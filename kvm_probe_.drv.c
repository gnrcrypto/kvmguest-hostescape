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
#include <linux/static_call.h>
#include <linux/pgtable.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/kprobes.h>

#define DRIVER_NAME "kvm_probe_drv"
#define DEVICE_FILE_NAME "kvm_probe_dev"

#define VQ_PAGE_ORDER 0
#define VQ_PAGE_SIZE (1UL << (PAGE_SHIFT + VQ_PAGE_ORDER))
#define MAX_VQ_DESCS 256

#ifndef KVM_HC_SEND_DESC
#define KVM_HC_SEND_DESC 999
#endif

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

struct vring_desc_kernel {
    __le64 addr;
    __le32 len;
    __le16 flags;
    __le16 next;
};

struct vq_desc_user_data {
    u16 index;
    u64 phys_addr;
    u32 len;
    u16 flags;
    u16 next_idx;
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

struct va_scan_data {
    unsigned long va;
    unsigned long size;
    unsigned char __user *user_buffer;
};

struct va_write_data {
    unsigned long va;
    unsigned long size;
    unsigned char __user *user_buffer;
};

struct hypercall_args {
    unsigned long nr;
    unsigned long arg0;
    unsigned long arg1;
    unsigned long arg2;
    unsigned long arg3;
};

struct file_read_request {
    char __user *path;
    unsigned long offset;
    size_t length;
    void __user *user_buffer;
};

struct gpa_io_data {
    unsigned long gpa;
    unsigned long size;
    unsigned char __user *user_buffer;
};

struct bar_scan_request {
    unsigned long start_addr;
    unsigned long end_addr;
    unsigned long step;
    unsigned char __user *results;
    unsigned long *hits_count;
};

struct pci_device_info {
    char bdf[16];
    unsigned long bar_base[6];
    unsigned long bar_size[6];
    unsigned int bar_flags[6];
    unsigned int vendor_id;
    unsigned int device_id;
};

#define IOCTL_READ_PORT          0x1001
#define IOCTL_WRITE_PORT         0x1002
#define IOCTL_READ_MMIO          0x1003
#define IOCTL_WRITE_MMIO         0x1004
#define IOCTL_ALLOC_VQ_PAGE      0x1005
#define IOCTL_FREE_VQ_PAGE       0x1006
#define IOCTL_WRITE_VQ_DESC      0x1007
#define IOCTL_TRIGGER_HYPERCALL  0x1008
#define IOCTL_READ_KERNEL_MEM    0x1009
#define IOCTL_WRITE_KERNEL_MEM   0x100A
#define IOCTL_PATCH_INSTRUCTIONS 0x100B
#define IOCTL_READ_FLAG_ADDR     0x100C
#define IOCTL_WRITE_FLAG_ADDR    0x100D
#define IOCTL_GET_KASLR_SLIDE    0x100E
#define IOCTL_VIRT_TO_PHYS       0x100F
#define IOCTL_SCAN_VA            0x1010
#define IOCTL_WRITE_VA           0x1011
#define IOCTL_HYPERCALL_ARGS     0x1012
#define IOCTL_READ_FILE          0x1013
#define IOCTL_READ_GPA           0x1014
#define IOCTL_WRITE_GPA          0x1015
#define IOCTL_SCAN_BARS          0x1016
#define IOCTL_GET_PCI_INFO       0x1017
#define IOCTL_PHYS_TO_VIRT       0x1018

static long driver_ioctl(struct file *f, unsigned int cmd, unsigned long arg);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KVM Probe Lab");
MODULE_DESCRIPTION("Enhanced kernel module for KVM exploitation with IVSHMEM support");

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

    if (!req || !req->path || !req->user_buffer || req->length == 0 || req->length > 65536) {
        printk(KERN_ERR "%s: Invalid file read parameters\n", DRIVER_NAME);
        return -EINVAL;
    }

    kernel_path = strndup_user(req->path, PATH_MAX);
    if (IS_ERR(kernel_path)) {
        ret = PTR_ERR(kernel_path);
        printk(KERN_ERR "%s: Failed to copy path: %d\n", DRIVER_NAME, ret);
        return ret;
    }

    filp = filp_open(kernel_path, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        ret = PTR_ERR(filp);
        printk(KERN_ERR "%s: Failed to open %s: %d\n", DRIVER_NAME, kernel_path, ret);
        goto out_path;
    }

    buffer = vmalloc(req->length);
    if (!buffer) {
        ret = -ENOMEM;
        goto out_file;
    }

    ret = kernel_read(filp, buffer, req->length, &pos);
    if (ret < 0) {
        printk(KERN_ERR "%s: Read failed: %d\n", DRIVER_NAME, ret);
        goto out_buffer;
    }

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
        printk(KERN_INFO "%s: Couldn't find kallsyms_lookup_name, using fallback\n", DRIVER_NAME);
    }

    if (kallsyms_lookup_name_fn) {
        host_kernel_base = kallsyms_lookup_name_fn("_text");
        if (host_kernel_base) {
            printk(KERN_INFO "%s: Found _text via kallsyms: 0x%lx\n",
                   DRIVER_NAME, host_kernel_base);
            return host_kernel_base - 0xffffffff81000000;
        }
    }

    if (kallsyms_lookup_name_fn) {
        const char *symbols[] = {
            "startup_64", "secondary_startup_64",
            "system_vectors", "phys_base",
            NULL
        };

        for (int i = 0; symbols[i]; i++) {
            host_kernel_base = kallsyms_lookup_name_fn(symbols[i]);
            if (host_kernel_base) {
                printk(KERN_INFO "%s: Found %s via kallsyms: 0x%lx\n",
                       DRIVER_NAME, symbols[i], host_kernel_base);
                return host_kernel_base - (0xffffffff81000000 + 0x1000);
            }
        }
    }

    printk(KERN_INFO "%s: Falling back to timing-based KASLR detection\n", DRIVER_NAME);
    u64 min_time = U64_MAX;
    for (u64 addr = 0xffffffff80000000; addr < 0xffffffffc0000000; addr += 0x200000) {
        u64 start = ktime_get_ns();
        kvm_hypercall2(KVM_HC_VAPIC_POLL_IRQ, addr, 0);
        u64 duration = ktime_get_ns() - start;
        if (duration < min_time) {
            min_time = duration;
            host_kernel_base = addr;
        }
    }

    if (!host_kernel_base) return 0;
    return host_kernel_base - 0xffffffff81000000;
}

static unsigned long gpa_to_hva(unsigned long gpa) {
    // Simple direct mapping for most cases
    // In KVM, guest physical often maps to host virtual via __va()
    return (unsigned long)__va(gpa);
}

static unsigned long hva_to_gpa(unsigned long hva) {
    // Reverse mapping
    return __pa(hva);
}

static long driver_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    struct port_io_data p_io_data_kernel;
    struct mmio_data m_io_data_kernel;
    void __iomem *mapped_addr = NULL;
    unsigned long len_to_copy;
    unsigned char *k_mmio_buffer = NULL;

    printk(KERN_INFO "%s: IOCTL cmd=0x%x, arg=0x%lx\n", DRIVER_NAME, cmd, arg);

    switch (cmd) {
        case IOCTL_READ_PORT:
            if (copy_from_user(&p_io_data_kernel, (struct port_io_data __user *)arg, sizeof(p_io_data_kernel)))
                return -EFAULT;
            
            if (p_io_data_kernel.size != 1 && p_io_data_kernel.size != 2 && p_io_data_kernel.size != 4)
                return -EINVAL;
            
            switch (p_io_data_kernel.size) {
                case 1: p_io_data_kernel.value = inb(p_io_data_kernel.port); break;
                case 2: p_io_data_kernel.value = inw(p_io_data_kernel.port); break;
                case 4: p_io_data_kernel.value = inl(p_io_data_kernel.port); break;
            }
            
            if (copy_to_user((struct port_io_data __user *)arg, &p_io_data_kernel, sizeof(p_io_data_kernel)))
                return -EFAULT;
            
            force_hypercall();
            break;

        case IOCTL_WRITE_PORT:
            if (copy_from_user(&p_io_data_kernel, (struct port_io_data __user *)arg, sizeof(p_io_data_kernel)))
                return -EFAULT;
            
            if (p_io_data_kernel.size != 1 && p_io_data_kernel.size != 2 && p_io_data_kernel.size != 4)
                return -EINVAL;
            
            switch (p_io_data_kernel.size) {
                case 1: outb((u8)p_io_data_kernel.value, p_io_data_kernel.port); break;
                case 2: outw((u16)p_io_data_kernel.value, p_io_data_kernel.port); break;
                case 4: outl((u32)p_io_data_kernel.value, p_io_data_kernel.port); break;
            }
            
            force_hypercall();
            break;

        case IOCTL_READ_MMIO: {
            struct mmio_data data;
            if (copy_from_user(&data, (void __user *)arg, sizeof(data)))
                return -EFAULT;
            
            void __iomem *mmio = ioremap(data.phys_addr, data.size);
            if (!mmio)
                return -EFAULT;
            
            void *kbuf = kmalloc(data.size, GFP_KERNEL);
            if (!kbuf) {
                iounmap(mmio);
                return -ENOMEM;
            }
            
            memcpy_fromio(kbuf, mmio, data.size);
            
            if (copy_to_user(data.user_buffer, kbuf, data.size)) {
                kfree(kbuf);
                iounmap(mmio);
                return -EFAULT;
            }
            
            kfree(kbuf);
            iounmap(mmio);
            force_hypercall();
            return 0;
        }

        case IOCTL_WRITE_MMIO: {
            if (copy_from_user(&m_io_data_kernel, (struct mmio_data __user *)arg, sizeof(m_io_data_kernel)))
                return -EFAULT;
            
            unsigned long map_size = m_io_data_kernel.size > 0 ? m_io_data_kernel.size : m_io_data_kernel.value_size;
            if (map_size == 0)
                return -EINVAL;
            
            mapped_addr = ioremap(m_io_data_kernel.phys_addr, map_size);
            if (!mapped_addr)
                return -ENOMEM;
            
            if (m_io_data_kernel.size > 0) {
                k_mmio_buffer = kmalloc(m_io_data_kernel.size, GFP_KERNEL);
                if (!k_mmio_buffer) {
                    iounmap(mapped_addr);
                    return -ENOMEM;
                }
                
                if (copy_from_user(k_mmio_buffer, m_io_data_kernel.user_buffer, m_io_data_kernel.size)) {
                    kfree(k_mmio_buffer);
                    iounmap(mapped_addr);
                    return -EFAULT;
                }
                
                for (len_to_copy = 0; len_to_copy < m_io_data_kernel.size; ++len_to_copy) {
                    writeb(k_mmio_buffer[len_to_copy], mapped_addr + len_to_copy);
                }
                
                kfree(k_mmio_buffer);
            } else {
                switch(m_io_data_kernel.value_size) {
                    case 1: writeb((u8)m_io_data_kernel.single_value, mapped_addr); break;
                    case 2: writew((u16)m_io_data_kernel.single_value, mapped_addr); break;
                    case 4: writel((u32)m_io_data_kernel.single_value, mapped_addr); break;
                    case 8: writeq(m_io_data_kernel.single_value, mapped_addr); break;
                    default:
                        iounmap(mapped_addr);
                        return -EINVAL;
                }
            }
            
            iounmap(mapped_addr);
            force_hypercall();
            return 0;
        }

        case IOCTL_READ_GPA: {
            struct gpa_io_data data;
            if (copy_from_user(&data, (void __user *)arg, sizeof(data)))
                return -EFAULT;
            
            unsigned long hva = gpa_to_hva(data.gpa);
            void *kbuf = kmalloc(data.size, GFP_KERNEL);
            if (!kbuf)
                return -ENOMEM;
            
            memcpy(kbuf, (void *)hva, data.size);
            
            if (copy_to_user(data.user_buffer, kbuf, data.size)) {
                kfree(kbuf);
                return -EFAULT;
            }
            
            kfree(kbuf);
            printk(KERN_INFO "%s: Read %lu bytes from GPA 0x%lx (HVA 0x%lx)\n",
                   DRIVER_NAME, data.size, data.gpa, hva);
            force_hypercall();
            return 0;
        }

        case IOCTL_WRITE_GPA: {
            struct gpa_io_data data;
            if (copy_from_user(&data, (void __user *)arg, sizeof(data)))
                return -EFAULT;
            
            unsigned long hva = gpa_to_hva(data.gpa);
            void *kbuf = kmalloc(data.size, GFP_KERNEL);
            if (!kbuf)
                return -ENOMEM;
            
            if (copy_from_user(kbuf, data.user_buffer, data.size)) {
                kfree(kbuf);
                return -EFAULT;
            }
            
            memcpy((void *)hva, kbuf, data.size);
            kfree(kbuf);
            
            printk(KERN_INFO "%s: Wrote %lu bytes to GPA 0x%lx (HVA 0x%lx)\n",
                   DRIVER_NAME, data.size, data.gpa, hva);
            force_hypercall();
            return 0;
        }

        case IOCTL_READ_KERNEL_MEM: {
            struct kvm_kernel_mem_read req;
            if (copy_from_user(&req, (struct kvm_kernel_mem_read __user *)arg, sizeof(req)))
                return -EFAULT;
            
            if (!req.kernel_addr || !req.length || !req.user_buf)
                return -EINVAL;
            
            if (copy_to_user(req.user_buf, (void *)req.kernel_addr, req.length))
                return -EFAULT;
            
            printk(KERN_INFO "%s: Read %lu bytes from kernel 0x%lx\n",
                   DRIVER_NAME, req.length, req.kernel_addr);
            force_hypercall();
            break;
        }

        case IOCTL_WRITE_KERNEL_MEM: {
            struct kvm_kernel_mem_write req;
            if (copy_from_user(&req, (struct kvm_kernel_mem_write __user *)arg, sizeof(req)))
                return -EFAULT;
            
            if (!req.kernel_addr || !req.length || !req.user_buf)
                return -EINVAL;
            
            void *tmp = kmalloc(req.length, GFP_KERNEL);
            if (!tmp) return -ENOMEM;
            
            if (copy_from_user(tmp, req.user_buf, req.length)) {
                kfree(tmp);
                return -EFAULT;
            }
            
            memcpy((void *)req.kernel_addr, tmp, req.length);
            kfree(tmp);
            
            printk(KERN_INFO "%s: Wrote %lu bytes to kernel 0x%lx\n",
                   DRIVER_NAME, req.length, req.kernel_addr);
            force_hypercall();
            break;
        }

        case IOCTL_ALLOC_VQ_PAGE: {
            struct page *vq_page_ptr;
            unsigned long pfn_to_user;
            
            if (g_vq_virt_addr) {
                free_pages((unsigned long)g_vq_virt_addr, VQ_PAGE_ORDER);
                g_vq_virt_addr = NULL;
                g_vq_phys_addr = 0;
                g_vq_pfn = 0;
            }
            
            vq_page_ptr = alloc_pages(GFP_KERNEL | __GFP_ZERO | __GFP_HIGHMEM, VQ_PAGE_ORDER);
            if (!vq_page_ptr)
                return -ENOMEM;
            
            g_vq_virt_addr = page_address(vq_page_ptr);
            g_vq_phys_addr = page_to_phys(vq_page_ptr);
            g_vq_pfn = PFN_DOWN(g_vq_phys_addr);
            pfn_to_user = g_vq_pfn;
            
            if (copy_to_user((unsigned long __user *)arg, &pfn_to_user, sizeof(pfn_to_user))) {
                free_pages((unsigned long)g_vq_virt_addr, VQ_PAGE_ORDER);
                g_vq_virt_addr = NULL;
                g_vq_phys_addr = 0;
                g_vq_pfn = 0;
                return -EFAULT;
            }
            
            force_hypercall();
            break;
        }

        case IOCTL_FREE_VQ_PAGE:
            if (g_vq_virt_addr) {
                free_pages((unsigned long)g_vq_virt_addr, VQ_PAGE_ORDER);
                g_vq_virt_addr = NULL;
                g_vq_phys_addr = 0;
                g_vq_pfn = 0;
            }
            force_hypercall();
            break;

        case IOCTL_WRITE_VQ_DESC: {
            struct vq_desc_user_data user_desc_data_kernel;
            struct vring_desc_kernel *kernel_desc_ptr_local;
            unsigned int max_descs_in_page_local;
            
            if (!g_vq_virt_addr)
                return -ENXIO;
            
            if (copy_from_user(&user_desc_data_kernel, (struct vq_desc_user_data __user *)arg, sizeof(user_desc_data_kernel)))
                return -EFAULT;
            
            max_descs_in_page_local = VQ_PAGE_SIZE / sizeof(struct vring_desc_kernel);
            if (user_desc_data_kernel.index >= max_descs_in_page_local)
                return -EINVAL;
            
            kernel_desc_ptr_local = (struct vring_desc_kernel *)g_vq_virt_addr + user_desc_data_kernel.index;
            kernel_desc_ptr_local->addr = cpu_to_le64(user_desc_data_kernel.phys_addr);
            kernel_desc_ptr_local->len = cpu_to_le32(user_desc_data_kernel.len);
            kernel_desc_ptr_local->flags = cpu_to_le16(user_desc_data_kernel.flags);
            kernel_desc_ptr_local->next = cpu_to_le16(user_desc_data_kernel.next_idx);
            
            force_hypercall();
            break;
        }

        case IOCTL_TRIGGER_HYPERCALL: {
            long ret = force_hypercall();
            if (copy_to_user((long __user *)arg, &ret, sizeof(ret)))
                return -EFAULT;
            break;
        }

        case IOCTL_SCAN_VA: {
            struct va_scan_data va_req;
            if (copy_from_user(&va_req, (struct va_scan_data __user *)arg, sizeof(va_req)))
                return -EFAULT;
            
            if (!va_req.va || !va_req.size || !va_req.user_buffer)
                return -EINVAL;
            
            unsigned char *tmp = kmalloc(va_req.size, GFP_KERNEL);
            if (!tmp)
                return -ENOMEM;
            
            memcpy(tmp, (void *)va_req.va, va_req.size);
            
            if (copy_to_user(va_req.user_buffer, tmp, va_req.size)) {
                kfree(tmp);
                return -EFAULT;
            }
            
            kfree(tmp);
            force_hypercall();
            return 0;
        }

        case IOCTL_WRITE_VA: {
            struct va_write_data wa_req;
            if (copy_from_user(&wa_req, (struct va_write_data __user *)arg, sizeof(wa_req)))
                return -EFAULT;
            
            if (!wa_req.va || !wa_req.size || !wa_req.user_buffer)
                return -EINVAL;
            
            unsigned char *tmp = kmalloc(wa_req.size, GFP_KERNEL);
            if (!tmp)
                return -ENOMEM;
            
            if (copy_from_user(tmp, wa_req.user_buffer, wa_req.size)) {
                kfree(tmp);
                return -EFAULT;
            }
            
            memcpy((void *)wa_req.va, tmp, wa_req.size);
            kfree(tmp);
            
            force_hypercall();
            return 0;
        }

        case IOCTL_HYPERCALL_ARGS: {
            struct hypercall_args args;
            if (copy_from_user(&args, (void __user *)arg, sizeof(args)))
                return -EFAULT;
            
            long ret = do_hypercall(&args);
            
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

        case IOCTL_READ_FLAG_ADDR:
            if (copy_to_user((unsigned long __user *)arg, &g_flag_value, sizeof(g_flag_value)))
                return -EFAULT;
            break;

        case IOCTL_WRITE_FLAG_ADDR:
            if (copy_from_user(&g_flag_value, (unsigned long __user *)arg, sizeof(g_flag_value)))
                return -EFAULT;
            break;

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
    printk(KERN_INFO "%s: Initializing Enhanced KVM Probe Module with IVSHMEM support\n", DRIVER_NAME);

    major_num = register_chrdev(0, DEVICE_FILE_NAME, &fops);
    if (major_num < 0) {
        printk(KERN_ERR "%s: register_chrdev failed: %d\n", DRIVER_NAME, major_num);
        return major_num;
    }
    
    driver_class = class_create(THIS_MODULE, DRIVER_NAME);
    if (IS_ERR(driver_class)) {
        unregister_chrdev(major_num, DEVICE_FILE_NAME);
        printk(KERN_ERR "%s: class_create failed\n", DRIVER_NAME);
        return PTR_ERR(driver_class);
    }
    
    driver_device = device_create(driver_class, NULL, MKDEV(major_num, 0), NULL, DEVICE_FILE_NAME);
    if (IS_ERR(driver_device)) {
        class_destroy(driver_class);
        unregister_chrdev(major_num, DEVICE_FILE_NAME);
        printk(KERN_ERR "%s: device_create failed\n", DRIVER_NAME);
        return PTR_ERR(driver_device);
    }
    
    g_vq_virt_addr = NULL;
    g_vq_phys_addr = 0;
    g_vq_pfn = 0;
    
    printk(KERN_INFO "%s: Module loaded. Device /dev/%s created with major %d\n", 
           DRIVER_NAME, DEVICE_FILE_NAME, major_num);
    return 0;
}

static void __exit mod_exit(void) {
    printk(KERN_INFO "%s: Unloading KVM Probe Module\n", DRIVER_NAME);
    
    if (g_vq_virt_addr) {
        free_pages((unsigned long)g_vq_virt_addr, VQ_PAGE_ORDER);
        g_vq_virt_addr = NULL;
        g_vq_phys_addr = 0;
        g_vq_pfn = 0;
    }
    
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