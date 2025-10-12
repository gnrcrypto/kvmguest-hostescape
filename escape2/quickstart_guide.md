# KVM ESCAPE FRAMEWORK - COMPLETE PACKAGE
# ==========================================

## What You Have

This complete exploitation framework for KVM guest-to-host escape includes:

### Core Files

1. **kvm_probe_drv_enhanced.c** - Advanced kernel module
   - Extended memory access (GPA, HPA, MMIO)
   - Hypercall support (0-4 arguments, return value capture)
   - Shared buffers (64KB standard, 16MB large pool)
   - Address translation utilities
   - Batch operations

2. **kvm_escape_advanced.c** - Multi-vector exploitation tool
   - 8 different attack vectors
   - Comprehensive memory scanning
   - Race condition exploitation
   - Systematic approach

3. **address_space_attack.c** - Massive memory aliasing tool
   - Maps gigabytes of guest memory
   - Searches for GPA→HPA aliasing
   - Pattern spray attacks
   - Address space exploration

### Scripts

4. **build.sh** - Automated compilation and deployment
   - Compiles kernel module
   - Builds userspace tools
   - Loads module
   - Sets permissions

5. **attack.sh** - Interactive menu-driven attack system
   - Easy-to-use interface
   - Organized attack vectors
   - System information
   - Log monitoring

### Documentation

6. **README.md** - Comprehensive guide
   - Quick start instructions
   - Feature overview
   - Troubleshooting
   - Safety considerations

7. **EXPLOITATION_GUIDE.md** - Detailed technical documentation
   - Attack theory for each vector
   - Memory model explanation
   - Vulnerability patterns
   - Success indicators

## Quick Start (3 Steps)

### Step 1: Build Everything

```bash
./build.sh
```

This compiles and loads everything automatically.

### Step 2: Run Interactive Menu

```bash
./attack.sh
```

Choose option 1 (Quick scan) for fastest results.

### Step 3: Monitor Results

In another terminal:
```bash
sudo dmesg -w | grep -E "flag|FLAG"
```

## Target Configuration

```
Your Setup:
  Guest RAM: ~6GB (0x1000-0x17fffffff)
  
Target Addresses (Host Physical):
  Write Flag: 0x64279a8
  Read Flag:  0x695ee10
```

## Attack Strategy Overview

### Phase 1: Quick Wins (< 1 minute)

```bash
./attack.sh
# Select option 1: Quick scan
```

Tries the most likely vectors:
- Direct HPA access (Vector 1)
- Hypercall exploitation (Vector 3)
- EPT confusion (Vector 5)

### Phase 2: Address Space Aliasing (2-5 minutes)

```bash
./attack.sh
# Select option 2: Address space attack
```

or directly:
```bash
./address_space_attack
```

This maps massive amounts of memory looking for GPA→HPA aliasing.

### Phase 3: Comprehensive Scan (10-30 minutes)

```bash
./attack.sh
# Select option 3: All standard vectors
```

Runs all non-intensive vectors (1-6).

### Phase 4: Nuclear Option (Hours)

```bash
./attack.sh
# Select option 12: Full assault
```

Runs EVERYTHING including slow vectors.

## Understanding Your "Shared Address Space" Concept

You mentioned wanting to "initialize entire address space to be shared." Here's what we've implemented:

### 1. **Large Pool Allocation (IOCTL_ALLOC_LARGE_POOL)**
   - Allocates 16MB contiguous guest memory
   - All of it available for host hypercalls
   - GPA is stable and known

### 2. **Massive Memory Mapping (address_space_attack)**
   - Maps gigabytes of guest virtual memory
   - Converts each to GPA via virt_to_phys
   - Tracks all mappings
   - Searches for GPAs that alias to target HPAs

### 3. **Pattern Spray**
   - Writes unique patterns to all mapped memory
   - Issues hypercalls
   - Checks if host read our patterns (indicates shared access)

### The Theory

```
Normal Case:
  Guest GPA 0x1000000 → Host HPA 0x50000000 ✗ (not useful)

Exploit Case (what we're looking for):
  Guest GPA 0x64279a8 → Host HPA 0x64279a8 ✓ (direct access!)
  
  or
  
  Guest GPA 0x1000000 → Host HPA 0x64279a8 ✓ (EPT misconfiguration!)
```

By mapping tons of memory and checking all GPAs, we increase chances of finding such aliasing.

## Key Differences from Your Original Code

### Enhanced Driver

**Before:**
- Basic shared buffer (4KB)
- Simple hypercalls
- Limited memory operations

**After:**
- Large pools (16MB)
- Batch hypercalls
- Extended memory access (GPA, HPA, MMIO)
- Address probing
- Better logging

### Userspace Tools

**Before (kvm_prober.c):**
- Manual commands
- Single operations
- Limited automation

**After:**
- Multiple attack vectors
- Automated scanning
- Comprehensive memory mapping
- Interactive menu system

## How Each Vector Addresses Your Goal

### Vector 1: Direct HPA Access
- **Goal:** Directly access 0x64279a8 via ioremap
- **Theory:** Maybe ioremap(0x64279a8) gives us host memory
- **Likelihood:** Low, but instant to try

### Vector 2: MMIO Scanning
- **Goal:** Find MMIO region that's actually host RAM
- **Theory:** Misconfigured PCI BAR points to 0x64279a8
- **Likelihood:** Medium

### Vector 3: Hypercall Exploitation
- **Goal:** Convince host to copy from 0x64279a8 to our GPA
- **Theory:** Buggy hypercall handler interprets our GPA as HPA source
- **Likelihood:** High if custom hypercalls exist

### Vector 4: GPA Space Expansion
- **Goal:** Allocate at specific addresses to get target GPA
- **Theory:** If we can get GPA 0x64279a8, maybe it maps to HPA 0x64279a8
- **Likelihood:** Medium

### Vector 5: EPT Confusion
- **Goal:** Access out-of-bounds GPA that aliases to target HPA
- **Theory:** EPT has misconfigured entries
- **Likelihood:** Medium-High

### Vector 6-8: Other approaches
- Port I/O tricks
- Race conditions
- Brute force scanning

### Address Space Attack
- **Goal:** Map entire guest VA space, find any GPA→HPA aliasing
- **Theory:** With enough mappings, we'll find a collision
- **Likelihood:** Depends on total guest RAM vs target HPA

## What Makes This "Shared Address Space"

Traditional approach:
```
Allocate 1 buffer at GPA X
Hope X is useful
```

Your approach (what we implemented):
```
Allocate 1000s of buffers at GPAs X₁, X₂, X₃, ...
Map entire address space
Find which Xᵢ is useful
```

The `address_space_attack` tool does exactly this:
1. Allocates GB of memory in various chunk sizes
2. Maps all of it to GPAs
3. Tracks every (VA, GPA) pair
4. Searches for GPAs near target HPAs
5. Tests if reading these GPAs gives us host memory

## Success Scenarios

### Scenario 1: Identity Mapping
```
Guest GPA 0x64279a8 → Host HPA 0x64279a8
```
**Exploit:** Read GPA 0x64279a8 directly
**Vector:** 5 (EPT confusion), 9 (address space)

### Scenario 2: Hypercall Confusion
```
Hypercall(read, hpa=0x64279a8, dst_gpa=our_buffer)
Host mistakenly reads HPA and writes to our GPA
```
**Exploit:** Hypercall returns host data
**Vector:** 3 (hypercalls)

### Scenario 3: MMIO Aliasing
```
MMIO region 0xC0000000 actually maps to HPA 0x64279a8
```
**Exploit:** Read MMIO
**Vector:** 2 (MMIO scan)

### Scenario 4: Large Mapping Collision
```
We map 100 regions
One has GPA 0x64200000
Due to EPT bug, reads from here give data from HPA 0x64279a8
```
**Exploit:** Found via address space attack
**Vector:** 9 (address space)

## Monitoring Success

### Terminal 1: Run attack
```bash
./attack.sh
```

### Terminal 2: Watch for success
```bash
sudo dmesg -w | grep -i flag
```

### Terminal 3: System monitoring
```bash
watch -n 1 'free -h; echo ""; ps aux | grep kvm'
```

## If Nothing Works

### Check the Setup

1. **Verify kernel module:**
   ```bash
   lsmod | grep kvm_probe
   dmesg | tail -20
   ```

2. **Test basic functionality:**
   ```bash
   # Allocate shared buffer
   ./kvm_prober alloc_shared
   
   # Try simple hypercall
   ./kvm_prober hypercall 0 0 0 0 0
   ```

3. **Check guest RAM layout:**
   ```bash
   cat /proc/iomem | grep "System RAM"
   ```

4. **Verify target addresses are correct:**
   - Write flag: 0x64279a8
   - Read flag: 0x695ee10

### Advanced Debugging

1. **Enable more logging:**
   ```bash
   echo 8 > /proc/sys/kernel/printk
   sudo dmesg -w
   ```

2. **Test individual IOCTLs:**
   ```bash
   # Test GPA read
   ./kvm_prober readgpa 0x1000000 256
   
   # Test hypercall
   ./kvm_prober hypercall 0 0 0 0 0
   ```

3. **Check for crashes:**
   ```bash
   dmesg | grep -E "BUG|Oops|segfault"
   ```

## Expected Output on Success

```
[VECTOR 3] Hypercall-based Memory Access
=========================================

[*] Hypercall 101: read(hpa=0x64279a8, gpa=0x1f000000, size=256)
    Return: 256 (0x100)

[+] Shared buffer has data!

[0x00000001f000000]:
  0000: 66 6C 61 67 7B 73 75 70  65 72 5F 73 65 63 72 65 | flag{super_secre
  0010: 74 5F 68 6F 73 74 5F 6D  65 6D 6F 72 79 5F 72 65 | t_host_memory_re
  0020: 61 64 7D 00 00 00 00 00  00 00 00 00 00 00 00 00 | ad}.............

[!!!] FLAG PATTERN FOUND!
```

## Files Summary

```
kvm_escape_framework/
│
├── Core Components
│   ├── kvm_probe_drv_enhanced.c    [Kernel module - 900 lines]
│   ├── kvm_escape_advanced.c       [Multi-vector tool - 1000 lines]
│   └── address_space_attack.c      [Aliasing attack - 800 lines]
│
├── Scripts
│   ├── build.sh                     [Build automation - 100 lines]
│   └── attack.sh                    [Interactive menu - 600 lines]
│
├── Documentation
│   ├── README.md                    [Main guide - 400 lines]
│   ├── EXPLOITATION_GUIDE.md        [Technical details - 600 lines]
│   └── SUMMARY.md                   [This file - 400 lines]
│
└── Original (for reference)
    ├── kvm_probe_drv.c
    └── kvm_prober.c
```

## Final Checklist

- [ ] Run `./build.sh` successfully
- [ ] Verify `/dev/kvm_probe_dev` exists
- [ ] Run `./attack.sh` and try option 1
- [ ] Monitor dmesg in second terminal
- [ ] Try address_space_attack
- [ ] Check for flag patterns in output
- [ ] Review logs in /tmp/*.log

## Next Steps After Reading This

1. **Build:** `./build.sh`
2. **Run:** `./attack.sh`
3. **Choose:** Option 1 (quick scan)
4. **Observe:** Watch for flag patterns
5. **Iterate:** Try other vectors if needed

## Emergency Stop

If guest becomes unresponsive:
```bash
# In guest (if possible)
sudo rmmod kvm_probe_drv

# On host (via console)
# Force shutdown
```

## Contact / Questions

This is a comprehensive framework. If you're confused about any part:

1. Read `EXPLOITATION_GUIDE.md` for theory
2. Check `README.md` for usage
3. Look at source code comments
4. Test incrementally (don't run everything at once first time)

## Good Luck!

You now have a sophisticated, multi-vector KVM escape framework that implements your "shared address space" concept through massive memory mapping and comprehensive scanning.

The key innovation is mapping large amounts of memory and systematically searching for GPA→HPA aliasing, rather than hoping a single shared buffer at a random GPA will work.

Try the quick scan first, then address_space_attack, then escalate to comprehensive scans.

Watch dmesg constantly - that's where success will first appear!
