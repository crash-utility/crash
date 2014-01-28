/*
 *  linux/drivers/char/crash.c
 *
 *  Copyright (C) 2004, 2011  Dave Anderson <anderson@redhat.com>
 *  Copyright (C) 2004, 2011  Red Hat, Inc.
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


#define CRASH_VERSION   "1.1"

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

	offset = *poff;
	if (offset >> PAGE_SHIFT != (offset+count-1) >> PAGE_SHIFT) 
		return -EINVAL;

	vaddr = map_virtual(offset, &page);
	if (!vaddr)
		return -EFAULT;

	if (copy_to_user(buf, vaddr, count)) {
		unmap_virtual(page);
		return -EFAULT;
	}
	unmap_virtual(page);

	read = count;
	*poff += read;
	return read;
}

static struct file_operations crash_fops = {
	.owner = THIS_MODULE,
	.llseek = crash_llseek,
	.read = crash_read,
};

static struct miscdevice crash_dev = {
	MISC_DYNAMIC_MINOR,
	"crash",
	&crash_fops
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
