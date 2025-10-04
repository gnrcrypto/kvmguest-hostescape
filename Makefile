# Makefile for KVM CTF Exploit Suite

# Kernel module build
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Module name
MODULE_NAME := kvm_probe_drv
obj-m += $(MODULE_NAME).o

# Userspace tools
PROBER := kvm_prober
DIRECT_EXPLOIT := kvm_direct_exploit

# Python exploits
PYTHON_EXPLOITS := comprehensive_kvm_exploit.py \
                   ivshmem_kvm_exploit.py \
                   hybrid_kvm_exploit.py

CC := gcc
CFLAGS := -Wall -O2

.PHONY: all clean install module userspace help test

all: module userspace

# Build kernel module
module:
	@echo "[*] Building kernel module..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Build userspace tools
userspace: $(PROBER) $(DIRECT_EXPLOIT)

$(PROBER): kvm_prober.c
	@echo "[*] Building kvm_prober..."
	$(CC) $(CFLAGS) -o $(PROBER) kvm_prober.c

$(DIRECT_EXPLOIT): kvm_direct_exploit.c
	@echo "[*] Building direct exploit..."
	$(CC) $(CFLAGS) -o $(DIRECT_EXPLOIT) kvm_direct_exploit.c

# Install everything
install: all
	@echo "[*] Installing kernel module..."
	sudo insmod $(MODULE_NAME).ko || true
	@echo "[*] Installing userspace tools..."
	sudo cp $(PROBER) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(PROBER)
	sudo cp $(DIRECT_EXPLOIT) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(DIRECT_EXPLOIT)
	@echo "[*] Making Python exploits executable..."
	chmod +x $(PYTHON_EXPLOITS)
	@echo "[*] Verifying device..."
	@ls -la /dev/kvm_probe* 2>/dev/null || echo "Warning: Device not found"
	@echo "[+] Installation complete!"

# Uninstall
uninstall:
	@echo "[*] Removing kernel module..."
	sudo rmmod $(MODULE_NAME) 2>/dev/null || true
	@echo "[*] Removing userspace tools..."
	sudo rm -f /usr/local/bin/$(PROBER)
	sudo rm -f /usr/local/bin/$(DIRECT_EXPLOIT)
	@echo "[+] Uninstallation complete!"

# Clean build artifacts
clean:
	@echo "[*] Cleaning build artifacts..."
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f $(PROBER) $(DIRECT_EXPLOIT)
	rm -f *.o *.ko *.mod.c *.mod *.order *.symvers
	rm -f .*.cmd
	rm -rf .tmp_versions
	@echo "[+] Clean complete!"

# Run quick test
test: install
	@echo "[*] Running quick test..."
	@echo "  - Testing device access..."
	@sudo $(PROBER) getkaslr || echo "KASLR detection failed (expected in some configs)"
	@echo "  - Testing GPA write..."
	@sudo $(PROBER) writegpa 1000 deadbeefcafebabe || echo "GPA write test failed"
	@echo "  - Testing GPA read..."
	@sudo $(PROBER) readgpa 1000 8 || echo "GPA read test failed"
	@echo "[+] Basic tests complete!"

# Run full exploit
exploit-python: install
	@echo "[*] Running Python hybrid exploit..."
	sudo python3 hybrid_kvm_exploit.py

exploit-c: install
	@echo "[*] Running C direct exploit..."
	sudo ./$(DIRECT_EXPLOIT)

# Quick exploit - tries all methods
exploit-all: install
	@echo "[*] Running all exploit methods..."
	@echo ""
	@echo "=== Method 1: Hybrid Python Exploit ==="
	@sudo python3 hybrid_kvm_exploit.py || true
	@echo ""
	@echo "=== Method 2: IVSHMEM-focused Exploit ==="
	@sudo python3 ivshmem_kvm_exploit.py || true
	@echo ""
	@echo "=== Method 3: Direct C Exploit ==="
	@sudo ./$(DIRECT_EXPLOIT) || true

# Show PCI devices and BARs
pci-info:
	@echo "[*] PCI Device Information:"
	@lspci -v | head -30
	@echo ""
	@echo "[*] Checking for IVSHMEM devices (vendor 1af4):"
	@lspci -d 1af4: || echo "No IVSHMEM devices found"
	@echo ""
	@echo "[*] BAR information for first 3 devices:"
	@for dev in /sys/bus/pci/devices/*/resource; do \
		echo "Device: $$(dirname $$dev | xargs basename)"; \
		head -3 $$dev 2>/dev/null; \
		echo ""; \
	done | head -20

# Show memory map
meminfo:
	@echo "[*] Memory Map (IOMEM):"
	@cat /proc/iomem | grep -i "virtio\|pci" || echo "No virtio/PCI regions found"
	@echo ""
	@echo "[*] Physical Memory Info:"
	@cat /proc/meminfo | grep -E "MemTotal|MemFree|MemAvailable"

# Check module status
status:
	@echo "[*] Module Status:"
	@lsmod | grep kvm_probe || echo "Module not loaded"
	@echo ""
	@echo "[*] Device Status:"
	@ls -la /dev/kvm_probe* 2>/dev/null || echo "Device not found"
	@echo ""
	@echo "[*] Kernel Messages (last 10):"
	@dmesg | grep kvm_probe | tail -10 || echo "No kernel messages"

# Help
help:
	@echo "KVM CTF Exploit Suite - Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  make all          - Build kernel module and userspace tools"
	@echo "  make module       - Build only kernel module"
	@echo "  make userspace    - Build only userspace tools"
	@echo "  make install      - Build and install everything"
	@echo "  make uninstall    - Remove module and tools"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make test         - Run basic functionality tests"
	@echo "  make exploit-all  - Run all exploit methods"
	@echo "  make pci-info     - Show PCI devices and BARs"
	@echo "  make meminfo      - Show memory map information"
	@echo "  make status       - Show module and device status"
	@echo ""
	@echo "Quick Start:"
	@echo "  1. make install          # Build and load everything"
	@echo "  2. make pci-info         # Check for IVSHMEM devices"
	@echo "  3. make exploit-all      # Run all exploits"
	@echo ""
	@echo "CTF Targets:"
	@echo "  Write Flag:  0x64279a8 = 0xdeadbeef41424344"
	@echo "  Read Flag:   0x695ee10"
	@echo "  RCE Flag:    /root/rce_flag"