#!/bin/bash

# KVM Escape Exploitation Framework - Build Script
# ================================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║       KVM Escape Framework - Compilation & Deployment          ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running in guest
if [ ! -e "/dev/kvm" ]; then
    echo -e "${GREEN}[+] Running in guest VM (no /dev/kvm)${NC}"
else
    echo -e "${YELLOW}[!] Warning: /dev/kvm exists - might be running on host${NC}"
fi

# Create Makefile for kernel module
cat > Makefile << 'EOF'
obj-m += kvm_probe_drv.o
kvm_probe_drv-objs := kvm_probe_drv_enhanced.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f *.o *.ko *.mod.* .*.cmd modules.order Module.symvers
	rm -rf .tmp_versions

install:
	sudo rmmod kvm_probe_drv 2>/dev/null || true
	sudo insmod kvm_probe_drv.ko
	sudo chmod 666 /dev/kvm_probe_dev
	dmesg | tail -20

uninstall:
	sudo rmmod kvm_probe_drv 2>/dev/null || true
EOF

echo -e "${YELLOW}[*] Compiling kernel module...${NC}"

# Copy the enhanced driver to the expected filename
if [ -f "kvm_probe_drv_enhanced.c" ]; then
    echo -e "${GREEN}[+] Using enhanced driver${NC}"
else
    echo -e "${RED}[-] Enhanced driver not found!${NC}"
    exit 1
fi

# Build kernel module
make clean 2>/dev/null || true
make

if [ ! -f "kvm_probe_drv.ko" ]; then
    echo -e "${RED}[-] Kernel module compilation failed!${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Kernel module compiled successfully${NC}"

# Compile userspace tool
echo -e "${YELLOW}[*] Compiling exploitation tools...${NC}"

gcc -o kvm_escape_advanced kvm_escape_advanced.c -lpthread -Wall -Wextra

if [ ! -f "kvm_escape_advanced" ]; then
    echo -e "${RED}[-] Userspace tool compilation failed!${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Exploitation tools compiled successfully${NC}"

# Load kernel module
echo -e "${YELLOW}[*] Loading kernel module...${NC}"
sudo rmmod kvm_probe_drv 2>/dev/null || true
sudo insmod kvm_probe_drv.ko

if [ ! -c "/dev/kvm_probe_dev" ]; then
    echo -e "${RED}[-] Device node /dev/kvm_probe_dev not created!${NC}"
    exit 1
fi

sudo chmod 666 /dev/kvm_probe_dev
echo -e "${GREEN}[+] Kernel module loaded, device ready${NC}"

# Show kernel log
echo -e "${YELLOW}[*] Recent kernel logs:${NC}"
dmesg | tail -10

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                     BUILD SUCCESSFUL                           ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}[*] To run exploitation:${NC}"
echo "    ./kvm_escape_advanced           # Run all vectors"
echo "    ./kvm_escape_advanced <1-8>     # Run specific vector"
echo ""
echo -e "${YELLOW}[*] To view kernel logs:${NC}"
echo "    sudo dmesg -w"
echo ""
echo -e "${YELLOW}[*] To unload module:${NC}"
echo "    make uninstall"
echo ""
