/*
 *  linux/drivers/char/crash.c
 *
 *  Copyright (C) 2004, 2011, 2016  Dave Anderson <anderson@redhat.com>
 *  Copyright (C) 2004, 2011, 2016  Red Hat, Inc.
 *  Copyright (C) 2019 Serapheim Dimitropoulos <serapheim delphix com>
 */

/******************************************************************************
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *****************************************************************************/

#include <linux/module.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/miscdevice.h>
#include <linux/init.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/types.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/mmzone.h>

extern int page_is_ram(unsigned long);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)

#define CAN_WRITE_KERNEL	1

static inline long copy_from_kernel_nofault(void *dst, const void *src, size_t size)
{
	return probe_kernel_read(dst, src, size);
}

static inline long copy_to_kernel_nofault(void *dst, const void *src, size_t size)
{
	return probe_kernel_write(dst, src, size);
}

#endif

#ifdef CONFIG_S390
/*
 * For swapped prefix pages get bounce buffer using xlate_dev_mem_ptr()
 */
static inline void *map_virtual(u64 offset, struct page **pp)
{
	struct page *page;
	unsigned long pfn;
	void *vaddr;

	vaddr = xlate_dev_mem_ptr(offset);
	pfn = ((unsigned long) vaddr) >> PAGE_SHIFT;
	if ((unsigned long) vaddr != offset)
		page = pfn_to_page(pfn);
	else
		page = NULL;

	if (!page_is_ram(pfn)) {
		printk(KERN_INFO
		    "crash memory driver: !page_is_ram(pfn: %lx)\n", pfn);
		return NULL;
	}

	if (!pfn_valid(pfn)) {
		printk(KERN_INFO
		    "crash memory driver: invalid pfn: %lx )\n", pfn);
		return NULL;
	}

	*pp = page;
	return vaddr;
}

/*
 * Free bounce buffer if necessary
 */
static inline void unmap_virtual(struct page *page)
{
	void *vaddr;

	if (page) {
		/*
		 * Because for bounce buffers vaddr will never be 0
		 * unxlate_dev_mem_ptr() will always free the bounce buffer.
		 */
		vaddr = (void *)(page_to_pfn(page) << PAGE_SHIFT);
		unxlate_dev_mem_ptr(0, vaddr);
	}
}

#else  /* all architectures except s390x */

static inline void *
map_virtual(u64 offset, struct page **pp)
{
	struct page *page;
	unsigned long pfn;
	void *vaddr;

	pfn = (unsigned long)(offset >> PAGE_SHIFT);

#ifdef NOTDEF
	/*
	 *  page_is_ram() is typically not exported, but there may
	 *  be another architecture, kernel version, or distribution
	 *  specific mechanism that can be plugged in here if desired.
	 */
	if (!page_is_ram(pfn)) {
		printk(KERN_INFO
		    "crash memory driver: !page_is_ram(pfn: %lx)\n", pfn);
		return NULL;
	}
#endif

	if (!pfn_valid(pfn)) {
		printk(KERN_INFO
		    "crash memory driver: invalid pfn: %lx\n", pfn);
		return NULL;
	}

	page = pfn_to_page(pfn);

	vaddr = kmap(page);
	if (!vaddr) {
		printk(KERN_INFO
		    "crash memory driver: pfn: %lx kmap(page: %lx) failed\n", 
			pfn, (unsigned long)page);
		return NULL;
	}

	*pp = page;
	return (vaddr + (offset & (PAGE_SIZE-1)));
}

static inline void unmap_virtual(struct page *page) 
{ 
	kunmap(page);
}
#endif


#define CRASH_VERSION   "1.5"

/*
 *  These are the file operation functions that allow crash utility
 *  access to physical memory.
 */

static loff_t
crash_llseek(struct file * file, loff_t offset, int orig)
{
	switch (orig) {
	case 0:
		file->f_pos = offset;
		return file->f_pos;
	case 1:
		file->f_pos += offset;
		return file->f_pos;
	default:
		return -EINVAL;
	}
}

#ifdef CAN_WRITE_KERNEL

static ssize_t
crash_write(struct file *file, const char *buf, size_t count, loff_t *poff)
{
       void *vaddr;
       struct page *page;
       u64 offset;
       ssize_t written;
       char *buffer = file->private_data;

       offset = *poff;
       if (offset >> PAGE_SHIFT != (offset+count-1) >> PAGE_SHIFT)
               return -EINVAL;

       vaddr = map_virtual(offset, &page);
       if (!vaddr)
               return -EFAULT;

       /*
        * Use bounce buffer to bypass the CONFIG_HARDENED_USERCOPY
        * kernel text restriction.
        */
       if (copy_from_user(buffer, buf, count)) {
               unmap_virtual(page);
               return -EFAULT;
       }

       if (copy_to_kernel_nofault(vaddr, buffer, count)) {
               unmap_virtual(page);
               return -EFAULT;
       }
       unmap_virtual(page);

       written = count;
       *poff += written;
       return written;
}

#endif

/*
 *  Determine the page address for an address offset value,
 *  get a virtual address for it, and copy it out.
 *  Accesses must fit within a page.
 */
static ssize_t
crash_read(struct file *file, char *buf, size_t count, loff_t *poff)
{
	void *vaddr;
	struct page *page;
	u64 offset;
	ssize_t read;
	char *buffer = file->private_data;

	offset = *poff;
	if (offset >> PAGE_SHIFT != (offset+count-1) >> PAGE_SHIFT)
		return -EINVAL;

	vaddr = map_virtual(offset, &page);
	if (!vaddr)
		return -EFAULT;
	/*
	 * Use bounce buffer to bypass the CONFIG_HARDENED_USERCOPY
	 * kernel text restriction.
	 */
        if (copy_from_kernel_nofault(buffer, vaddr, count)) {
                unmap_virtual(page);
                return -EFAULT;
        }
	if (copy_to_user(buf, buffer, count)) {
		unmap_virtual(page);
		return -EFAULT;
	}
	unmap_virtual(page);

	read = count;
	*poff += read;
	return read;
}

static int
crash_open(struct inode * inode, struct file * filp)
{
	if (!capable(CAP_SYS_RAWIO))
		return -EPERM;

	filp->private_data = (void *)__get_free_page(GFP_KERNEL);
	if (!filp->private_data)
		return -ENOMEM;

	return 0;
}

static int
crash_release(struct inode *inode, struct file *filp)
{
	free_pages((unsigned long)filp->private_data, 0);
	return 0;
}

/*
 *  Note: This function is required for Linux 4.6 and later ARM64 kernels.
 *        For earler kernel versions, remove this CONFIG_ARM64 section.
 */
#ifdef CONFIG_ARM64

#define DEV_CRASH_ARCH_DATA _IOR('c', 1, long)

static long
crash_arch_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	extern u64 kimage_voffset;

	switch (cmd)
	{
	case DEV_CRASH_ARCH_DATA:
		return put_user(kimage_voffset, (unsigned long __user *)arg);
	default:
		return -EINVAL;
	}
}
#endif

static long 
crash_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
#ifdef DEV_CRASH_ARCH_DATA
	return crash_arch_ioctl(file, cmd, arg);
#else
	return -EINVAL;
#endif
}

static struct file_operations crash_fops = {
	.owner = THIS_MODULE,
	.llseek = crash_llseek,
	.read = crash_read,
#ifdef CAN_WRITE_KERNEL
	.write = crash_write,
#endif
	.unlocked_ioctl = crash_ioctl,
	.open = crash_open,
	.release = crash_release,
};

static struct miscdevice crash_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "crash",
	.fops = &crash_fops
};

static int __init
crash_init(void)
{
	int ret;

	ret = misc_register(&crash_dev);
	if (ret) {
		printk(KERN_ERR
		    "crash memory driver: cannot misc_register (MISC_DYNAMIC_MINOR)\n");
		goto out;
	}

	ret = 0;
	printk(KERN_INFO "crash memory driver: version %s\n", CRASH_VERSION);
out:
	return ret;
}

static void __exit
crash_cleanup_module(void)
{
	misc_deregister(&crash_dev);
}

module_init(crash_init);
module_exit(crash_cleanup_module);

MODULE_LICENSE("GPL");
