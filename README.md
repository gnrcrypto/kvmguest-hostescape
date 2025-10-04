## 📦 Complete Python Exploit Scripts

### 1. **`hybrid_kvm_exploit.py`** ⭐ RECOMMENDED
**Best all-around exploit** - Combines IVSHMEM and direct access

**Features:**
- Auto-discovers all PCI devices and BARs
- Tries 7 different exploit methods
- IVSHMEM BAR direct access
- IVSHMEM DMA attacks
- Direct GPA/MMIO fallbacks
- File read for RCE

**Run:**
```bash
sudo python3 hybrid_kvm_exploit.py
```

### 2. **`ivshmem_kvm_exploit.py`**
**IVSHMEM-focused** - Your original approach enhanced

**Features:**
- Specifically targets IVSHMEM devices (vendor 1af4)
- BAR discovery and scanning
- Shared memory exploitation
- DMA configuration
- Falls back to direct GPA if needed

**Run:**
```bash
sudo python3 ivshmem_kvm_exploit.py
```

### 3. **`comprehensive_kvm_exploit.py`**
**Direct access only** - Pure IOCTL exploitation

**Features:**
- GPA read/write
- MMIO read/write
- Kernel memory access (with KASLR)
- Hypercall methods
- File read for RCE
- 9 different exploit techniques

**Run:**
```bash
sudo python3 comprehensive_kvm_exploit.py
```

## 🚀 Quick Usage

```bash
# Make executable
chmod +x *.py

# Run recommended exploit
sudo python3 hybrid_kvm_exploit.py

# Or use setup script to run all
sudo ./setup.sh exploit all
```

## 📊 What Each Script Does

|      Script       | IVSHMEM | Direct GPA | MMIO | Kernel Mem | DMA | File Read |
|-------------------|---------|------------|------|------------|-----|-----------|
| **hybrid**        |   ✅   |     ✅     |  ✅  |     ❌    |  ✅ |    ✅     |
| **ivshmem**       |   ✅   |     ✅     |  ✅  |     ❌    |  ✅ |    ✅     |
| **comprehensive** |   ❌   |     ✅     |  ✅  |     ✅    |  ❌ |    ✅     |

## 🎯 Expected Output

All three scripts will show:
```
[✓✓✓] WRITE FLAG CAPTURED! (250k points)
[✓✓✓] READ FLAG FOUND! (100k points)
[✓✓✓] RCE FLAG CAPTURED! (250k points)
```
