# KVM ESCAPE EXPLOITATION GUIDE
# ==============================

## Overview

This document details advanced techniques for escaping from a KVM guest to the host.
Target: Read/write host physical memory at specific flag addresses.

### Target Information

```
Guest RAM Regions (from /proc/iomem):
- 00001000-0009fbff : System RAM
- 00100000-7fff9fff : System RAM  
- 100000000-17fffffff : System RAM

Host Flag Addresses (HPA):
- Write Flag: 0x64279a8  
- Read Flag:  0x695ee10
```

## Attack Vectors

### VECTOR 1: Direct HPA Access via ioremap()

**Theory:**
In KVM, `ioremap()` in the guest kernel maps Guest Physical Addresses (GPA) to 
Guest Virtual Addresses (GVA). However, if EPT (Extended Page Tables) is 
misconfigured or if we can trigger a confused deputy situation, ioremap might
map Host Physical Addresses (HPA) directly.

**Strategy:**
1. Call ioremap() on the target HPA addresses
2. If successful, read/write through the mapped address
3. Look for:
   - EPT misconfigurations
   - MMIO regions that alias to host memory
   - PCI BAR mappings that point to host RAM

**Likelihood:** Low
**Why try:** Sometimes QEMU/KVM configurations expose certain physical ranges

**Implementation:**
```c
struct hpa_io_data data;
data.hpa = 0x64279a8;  // Target flag address
data.size = 256;
ioctl(fd, IOCTL_READ_HPA, &data);
```

---

### VECTOR 2: MMIO Address Space Scanning

**Theory:**
The physical address space has holes where MMIO devices are mapped. Some of
these regions might:
- Actually be backed by host RAM (misconfiguration)
- Provide DMA-like access to host memory
- Contain hypervisor control structures

**Strategy:**
1. Scan common MMIO ranges:
   - 0x80000000 - 0xFFFFFFFF (above 2GB)
   - 0xC0000000 - 0xDFFFFFFF (PCI config space)
   - 0xFEC00000 - 0xFEE00000 (APIC regions)

2. For each accessible region, check if:
   - Content looks like RAM (not 0x00 or 0xFF patterns)
   - Writes persist
   - Patterns match known host kernel structures

**Likelihood:** Medium
**Why try:** Misconfigurations in QEMU PCI device mappings are common

**Key Insight:**
If a PCI BAR is incorrectly mapped to host physical memory instead of
emulated device memory, we get direct host access!

---

### VECTOR 3: Hypercall Memory Operations

**Theory:**
KVM hypercalls allow the guest to request services from the host. Standard
hypercalls include:
- KVM_HC_VAPIC_POLL_IRQ (0)
- KVM_HC_MMU_OP (1)  
- KVM_HC_KICK_CPU (4)

Custom or buggy hypercall handlers might:
- Interpret GPA as HPA
- Have buffer overflow vulnerabilities
- Lack proper bounds checking

**Strategy:**
1. Allocate a shared buffer in guest memory
2. Get its GPA via virt_to_phys()
3. Issue hypercalls with arguments:
   - arg0 = target HPA (flag address)
   - arg1 = shared buffer GPA
   - arg2 = size
   
4. Try various hypercall numbers (0-255)
5. Check if host wrote data to our shared buffer

**Attack Scenarios:**

#### Scenario A: Hypercall Confused Deputy
```c
hypercall(nr=101,  // Custom "read memory" hypercall  
          arg0=0x64279a8,   // Host wants this as HPA
          arg1=shared_gpa,   // Guest buffer
          arg2=256)          // Size
```

If the host handler does:
```c
copy_from_host_memory(arg0, guest_buffer(arg1), arg2)
```
We win!

#### Scenario B: Integer Overflow
```c
hypercall(nr=1,  // MMU_OP
          arg0=0xFFFFFFFF64279a8,  // High bits might overflow
          arg1=shared_gpa,
          arg2=0xFFFFFFFFFFFFFF00)  // Large size wraps
```

**Likelihood:** High for custom hypercalls, Medium for standard
**Why try:** Most likely vector if custom hypercalls exist

---

### VECTOR 4: GPA Space Expansion

**Theory:**
Guest physical memory might not be contiguous. By allocating memory at
specific virtual addresses and checking the resulting GPA mapping, we might:
- Find GPAs that alias to interesting HPAs
- Discover memory regions beyond documented RAM
- Trigger EPT faults that the hypervisor mishandles

**Strategy:**
1. Use mmap() to allocate large regions
2. Use virt_to_phys() to find the GPA
3. Try to access GPAs near the flag addresses:
   - Direct GPA == HPA collision
   - GPA + offset == HPA tricks
   
4. Look for patterns:
```
GPA Range          | HPA Range
0x00000000-0x80000000 | 0x00000000-0x80000000 (identity map?)
0x100000000+       | Host RAM aliasing?
```

**Key Insight:**
If guest physical address 0x64279a8 happens to map to host physical
0x64279a8, we can access it directly!

**Likelihood:** Medium
**Why try:** Simple identity mapping bugs are surprisingly common

---

### VECTOR 5: EPT Confusion via Out-of-Bounds GPA Access

**Theory:**
Extended Page Tables (EPT) translate GPA → HPA. By accessing GPAs outside
the documented guest RAM ranges, we might:
- Trigger EPT violations that expose host memory
- Find unmapped regions that alias to host RAM
- Exploit EPT page table walking bugs

**Strategy:**
1. Access GPAs just beyond guest RAM:
   - GUEST_RAM_END_2 + 0x1000
   - GUEST_RAM_END_2 + 0x10000
   
2. Access GPAs that should be "holes":
   - 0x80000000 - 0xC0000000
   - 0xA0000 - 0xBFFFF (VGA hole)
   
3. Try the flag HPAs directly as GPAs:
   - Read GPA 0x64279a8
   - Maybe EPT misconfigured for identity mapping?

4. Use high bits:
   - GPA 0x8000000064279a8
   - Overflow/underflow in address translation?

**Likelihood:** Medium-High
**Why try:** EPT bugs are a major KVM vulnerability class

---

### VECTOR 6: PIO-triggered Memory Access

**Theory:**
I/O port operations (IN/OUT instructions) trap to the hypervisor. Some ports
trigger complex operations that might:
- DMA to/from host memory
- Access hypervisor data structures
- Have buffer overflow bugs

**Interesting Ports:**
```
0xCF8/0xCFC - PCI configuration space
0x510/0x511 - QEMU fw_cfg interface
0x3F8-0x3FF - Serial ports (COM1)
0x510       - fw_cfg selector (QEMU-specific)
```

**Strategy:**
1. Write specific values to port 0x510 (fw_cfg selector)
2. Read from port 0x511 (fw_cfg data)
3. Look for commands that:
   - Read arbitrary memory
   - Set DMA addresses
   - Modify hypervisor state

**Example Attack:**
```c
outl(0x510, FIRMWARE_CFG_MEMORY_MAP);  // Select memory map
inb(0x511);  // Might leak host addresses!
```

**Likelihood:** Low-Medium
**Why try:** QEMU fw_cfg has had vulnerabilities

---

### VECTOR 7: Race Conditions in Hypercall Handlers

**Theory:**
If multiple vCPUs make hypercalls simultaneously, race conditions in the
host hypercall handler might:
- Allow TOCTOU (Time-of-Check-Time-of-Use) bugs
- Corrupt shared data structures
- Bypass security checks

**Strategy:**
1. Create 4+ threads in guest
2. Each thread repeatedly calls the same hypercall
3. Use shared guest buffer as the target
4. Race conditions might cause:
   - Double-fetch vulnerabilities
   - Buffer confusion
   - State machine corruption

**Attack Pattern:**
```
Thread 1: hypercall(read, hpa=0x64279a8, gpa=buf, size=256)
Thread 2: hypercall(read, hpa=0x64279a8, gpa=buf, size=256)  
Thread 3: hypercall(write, hpa=buf_gpa, val=0xDEADBEEF)
Thread 4: hypercall(read, hpa=0x695ee10, gpa=buf, size=256)
```

Possible outcomes:
- Host reads from HPA, guest buffer gets data
- Race in address translation uses wrong translation
- Check-then-act pattern broken

**Likelihood:** Medium
**Why try:** Multi-core race conditions are hard to find/fix

---

### VECTOR 8: Systematic Memory Scanning

**Theory:**
Brute force scan the entire 32-bit physical address space looking for
accessible regions. When we find one, check if it:
- Contains interesting data (kernel structures)
- Is actually host memory
- Maps to our target addresses

**Strategy:**
```
For addr in 0x00000000 to 0xFFFFFFFF (4GB), step 16MB:
    Try ioremap(addr, 4KB)
    If accessible:
        Read content
        Check for kernel patterns:
            - Magic numbers
            - ASCII strings
            - Pointer patterns
            - Known structures
        If looks like host kernel:
            Map more memory around this region
            Search for flag strings
```

**Optimizations:**
- Skip known guest RAM regions
- Focus on likely MMIO holes
- Use kernel patterns to identify host memory

**Likelihood:** Low (time-consuming)
**Why try:** Last resort, might find unexpected mappings

---

## Exploitation Workflow

### Phase 1: Reconnaissance
```bash
# Build and load
./build.sh

# Check guest memory layout
cat /proc/iomem

# Get kernel info  
uname -a
cat /proc/cpuinfo
```

### Phase 2: Quick Wins (Fast Vectors)
```bash
# Try direct access first
./kvm_escape_advanced 1  # Vector 1: Direct HPA

# Try EPT confusion
./kvm_escape_advanced 5  # Vector 5: EPT tricks

# Try hypercalls
./kvm_escape_advanced 3  # Vector 3: Hypercalls
```

### Phase 3: Systematic Search
```bash
# MMIO scanning
./kvm_escape_advanced 2  # Vector 2: MMIO scan

# PIO probing
./kvm_escape_advanced 6  # Vector 6: Port I/O
```

### Phase 4: Advanced Techniques
```bash
# Race conditions (takes time)
./kvm_escape_advanced 7  # Vector 7: Races

# Full memory scan (very slow)
./kvm_escape_advanced 8  # Vector 8: Brute force
```

### Phase 5: Custom Exploitation

If none of the above work, analyze the specific KVM/QEMU setup:

1. Check QEMU command line:
   ```bash
   ps aux | grep qemu
   ```
   
2. Look for custom devices or weird configs

3. Review dmesg for hints about the hypervisor

4. Try kernel info leaks:
   ```bash
   cat /sys/kernel/debug/kvm/...  # If debugfs mounted
   ```

---

## Success Indicators

You've successfully escaped if you see:

```
[+] Read X bytes from HOST physical 0x64279a8
Address          | Hex Bytes                                        | ASCII
-----------------|--------------------------------------------------|------------------
0x0000000064279a8 | 66 6C 61 67 7B ... | flag{...
```

Or in kernel log:
```
[+] Hypercall returned host memory!
[+] Found flag pattern in buffer
```

---

## Debugging Tips

### Monitor kernel logs in realtime:
```bash
sudo dmesg -w
```

### Check for crashes:
```bash
sudo dmesg | grep "BUG\|Oops\|segfault"
```

### Verify device access:
```bash
ls -la /dev/kvm_probe_dev
# Should be: crw-rw-rw- 1 root root ...
```

### Test basic functionality:
```bash
# Allocate shared buffer
echo "alloc_shared" | sudo tee /proc/kvm_probe

# Check it worked
sudo cat /proc/kvm_probe
```

---

## Advanced: Understanding the Memory Model

```
+------------------+
|   Guest Process  |  <- User virtual addresses
+------------------+
        |
   [Guest Paging]
        |
        v  
+------------------+
|   Guest Kernel   |  <- Guest virtual addresses (GVA)
+------------------+
        |
   [Guest Paging]
        |
        v
+------------------+
|  Guest Physical  |  <- Guest physical addresses (GPA)
|   Memory (RAM)   |     0x0 - 0x180000000 in our case
+------------------+
        |
      [EPT]  <- This is where the magic happens!
        |
        v
+------------------+
|  Host Physical   |  <- Host physical addresses (HPA)
|   Memory (RAM)   |     Flag at 0x64279a8
+------------------+

Our goal: Find a way to make GPA translate to target HPA!
```

### EPT Entry Format (simplified):
```
Bits  | Function
------|------------------
0-2   | Read, Write, Execute permissions
12-51 | Host Physical Address (HPA)
52-63 | Reserved/Flags
```

If we can:
1. Corrupt an EPT entry
2. Find a misconfigured EPT entry
3. Exploit EPT walking logic

We can make any GPA map to any HPA!

---

## Notes on Custom Hypercalls

If the host has custom hypercalls (nr >= 100), analyze them:

```c
// Hypothetical buggy handler on host:
int handle_custom_hypercall(int nr, u64 a0, u64 a1, u64 a2, u64 a3) {
    if (nr == 101) {  // Read memory
        void *host_src = (void*)a0;      // BUG: No validation!
        void *guest_dst = gpa_to_hva(a1); // Translate guest addr
        size_t size = a2;
        
        memcpy(guest_dst, host_src, size);  // VULN: Direct read!
        return size;
    }
}
```

This would allow direct host memory reading!

---

## Conclusion

The key to KVM escape is finding a confused deputy - a situation where the
host hypervisor incorrectly interprets our guest-controlled data as host
addresses or performs unsafe operations.

Common vulnerability patterns:
1. **Address confusion**: GPA treated as HPA
2. **Integer overflows**: In address/size calculations  
3. **TOCTOU**: Race conditions in hypercall handlers
4. **Insufficient validation**: Bounds checking missing
5. **Configuration errors**: MMIO/PCI BAR mismap

Try all vectors systematically. Good luck!

For more information:
- KVM architecture: https://www.kernel.org/doc/Documentation/virt/kvm/
- EPT details: Intel SDM Volume 3, Chapter 28
- QEMU devices: https://www.qemu.org/docs/master/
