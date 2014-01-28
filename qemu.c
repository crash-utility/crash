/*
 * Derive kernel base from a QEMU saved VM file
 *
 * Copyright (C) 2009, 2010 Red Hat, Inc.
 * Written by Paolo Bonzini.
 *
 * Portions Copyright (C) 2009 David Anderson
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <assert.h>

#include "qemu-load.h"

#include "kvmdump.h"

/*
 * Some bits we need to access in the control registers and page tables.
 */

#define MSR_EFER_LMA	(1 << 10)
#define PG_PRESENT_MASK	(1 << 0)
#define PG_PSE_MASK	(1 << 7)
#define CR0_PG_MASK	(1 << 31)
#define CR4_PAE_MASK	(1 << 31)
#define CR4_PSE_MASK	(1 << 31)

static uint32_t
ldl (struct qemu_device_x86 *dx86, struct qemu_device_ram *dram, uint64_t addr)
{
	char buf[4096];
	if (dx86->a20_masked)
		addr &= ~(1LL<<20);
	if (!ram_read_phys_page (dram, buf, addr & ~0xfff))
		return 0;

	assert ((addr & 0xfff) <= 0xffc);
	return *(uint32_t *)(buf + (addr & 0xfff));
}

static uint64_t
ldq (struct qemu_device_x86 *dx86, struct qemu_device_ram *dram, uint64_t addr)
{
	char buf[4096];
	if (dx86->a20_masked)
		addr &= ~(1LL<<20);
	if (!ram_read_phys_page (dram, buf, addr & ~0xfff))
		return 0;

	assert ((addr & 0xfff) <= 0xff8);
	return *(uint64_t *)(buf + (addr & 0xfff));
}

/*
 * Messy x86 TLB fault logic, walking the page tables to find the physical
 * address corresponding to ADDR.  Taken from QEMU.
 */

static uint64_t
get_phys_page(struct qemu_device_x86 *dx86, struct qemu_device_ram *dram,
	      uint64_t addr)
{
	uint64_t pde_addr, pte_addr;
	uint64_t pte, paddr;
	uint32_t page_offset;
	int page_size;

	if ((dx86->cr4 & CR4_PAE_MASK) || (dx86->efer & MSR_EFER_LMA)) {
		uint64_t pdpe_addr;
		uint64_t pde, pdpe;

		if (dx86->cr4 & CR4_PAE_MASK)
			dprintf ("PAE active\n");
		if (dx86->efer & MSR_EFER_LMA) {
			uint64_t pml4e_addr, pml4e;
			int32_t sext;

			dprintf ("long mode active\n");

			/* test virtual address sign extension */
			sext = (int64_t) addr >> 47;
			if (sext != 0 && sext != -1)
				return -1;

			pml4e_addr = ((dx86->cr3 & ~0xfff)
				      + (((addr >> 39) & 0x1ff) << 3));
			pml4e = ldq (dx86, dram, pml4e_addr);
			if (!(pml4e & PG_PRESENT_MASK))
				return -1;
			dprintf ("PML4 page present\n");

			pdpe_addr = ((pml4e & ~0xfff)
				     + (((addr >> 30) & 0x1ff) << 3));
			pdpe = ldq (dx86, dram, pdpe_addr);
			if (!(pdpe & PG_PRESENT_MASK))
				return -1;
			dprintf ("PDPE page present\n");
		} else {
			dprintf ("long mode inactive\n");

			pdpe_addr = ((dx86->cr3 & ~0x1f)
				     + ((addr >> 27) & 0x18));
			pdpe = ldq (dx86, dram, pdpe_addr);
			if (!(pdpe & PG_PRESENT_MASK))
				return -1;
			dprintf ("PDPE page present\n");
		}

		pde_addr = (pdpe & ~0xfff) + (((addr >> 21) & 0x1ff) << 3);
		pde = ldq (dx86, dram, pde_addr);
		if (!(pde & PG_PRESENT_MASK))
			return -1;
		dprintf ("PDE page present\n");

		if (pde & PG_PSE_MASK) {
			/* 2 MB page */
			dprintf ("2MB page\n");

			page_size = 2048 * 1024;
			pte = pde & ~((page_size - 1) & ~0xfff);
		} else {
			/* 4 KB page */
			dprintf ("4 KB PAE page\n");

			pte_addr = ((pde & ~0xfff)
				    + (((addr >> 12) & 0x1ff) << 3));
			page_size = 4096;
			pte = ldq (dx86, dram, pte_addr);
			if (!(pte & PG_PRESENT_MASK))
				return -1;
			dprintf ("PTE page present\n");
		}

	} else {
		/* Not PAE.  */

		uint32_t pde;
		if (!(dx86->cr0 & CR0_PG_MASK)) {
			dprintf ("Paging inactive\n");

			pte = addr;
			page_size = 4096;
		} else {
			/* page directory entry */
			pde_addr = ((dx86->cr3 & ~0xfff)
				    + ((addr >> 20) & 0xffc));
			pde = ldl (dx86, dram, pde_addr);
			if (!(pde & PG_PRESENT_MASK))
				return -1;
			dprintf ("PDE page present\n");
			if ((pde & PG_PSE_MASK) && (dx86->cr4 & CR4_PSE_MASK)) {
				page_size = 4096 * 1024;
				pte = pde & ~((page_size - 1) & ~0xfff);
			} else {
				page_size = 4096;
				pte_addr = ((pde & ~0xfff)
					    + ((addr >> 10) & 0xffc));
				pte = ldl (dx86, dram, pte_addr);
				if (!(pte & PG_PRESENT_MASK))
					return -1;
				dprintf ("PTE page present\n");
			}
		}
	}

	page_offset = (addr & 0xfff) & (page_size - 1);
	paddr = (pte & ~0xfff) + page_offset;
	return paddr;
}

/*
 * I'm using the IDT base as a quick way to find the bottom of the
 * kernel memory.
 */
static uint64_t
get_idt_base(struct qemu_device_list *dl)
{
	struct qemu_device_x86 *dx86 = (struct qemu_device_x86 *)
		device_find_instance (dl, "cpu", 0);

	return dx86->idt.base;
}

static uint64_t
get_kernel_base(struct qemu_device_list *dl)
{
	int i;
	uint64_t kernel_base = -1;
	uint64_t base_vaddr, last, mask;
	struct qemu_device_x86 *dx86 = (struct qemu_device_x86 *)
		device_find_instance (dl, "cpu", 0);
	struct qemu_device_ram *dram = (struct qemu_device_ram *)
		device_find_instance (dl, "ram", 0);

	for (i = 30, last = -1; (kernel_base == -1) && (i >= 20); i--)
        {
                mask = ~((1LL << i) - 1);
                base_vaddr = dx86->idt.base & mask;
		if (base_vaddr == last)
			continue;
		if (base_vaddr < kvm->kvbase) {
			fprintf(stderr, 
			    "WARNING: IDT base contains: %llx\n         "
			    "cannot determine physical base address: defaulting to 0\n\n", 
				(unsigned long long)base_vaddr);
			return 0;
		}
		dprintf("get_kernel_base: %llx\n", (unsigned long long)base_vaddr);
                kernel_base = get_phys_page(dx86, dram, base_vaddr);
		last = base_vaddr;
        }

        if (kernel_base != -1) {
		dprintf("kvbase: %llx vaddr used: %llx physical: %llx\n",
			(unsigned long long)kvm->kvbase,
			(unsigned long long)base_vaddr,
			(unsigned long long)kernel_base);
		/*
		 *  Subtract the offset between the virtual address used
		 *  and the kernel's base virtual address.
		 */
                kernel_base -= (base_vaddr - kvm->kvbase);
        } else {
		dprintf("WARNING: cannot determine physical base address:"
			" defaulting to 0\n\n");
		kernel_base = 0;
		kvm->flags |= NO_PHYS_BASE;
	}

	return kernel_base;
}


#ifdef MAIN_FROM_TEST_C
int main (int argc, char **argv)
{
	struct qemu_device_list *dl;
	FILE *fp;

	if (argc != 2) {
		fprintf (stderr, "Usage: test SAVE-FILE\n");
		exit (1);
	}

	fp = fopen(argv[1], "r");
	if (!fp) {
		fprintf (stderr, "Error: %s\n", strerror (errno));
		exit (1);
	}

#ifdef HOST_32BIT
	dl = qemu_load (devices_x86_32, QEMU_FEATURE_CPU|QEMU_FEATURE_RAM, fp);
#else
	dl = qemu_load (devices_x86_64, QEMU_FEATURE_CPU|QEMU_FEATURE_RAM, fp);
#endif
	printf ("IDT at %llx\n", get_idt_base (dl));
	printf ("Physical kernel base at %llx\n", get_kernel_base (dl));
	device_list_free (dl);
	fclose (fp);
	exit (0);
}
#endif


/*
 *  crash utility adaptation
 */

#include "defs.h"

int 
qemu_init(char *filename)
{
	struct qemu_device_list *dl;
	struct qemu_device_ram *dram;
	uint64_t idt = 0;

	if (CRASHDEBUG(1))
		dump_qemu_header(kvm->ofp);

	rewind(kvm->vmp);

	if (kvm->flags & (MAPFILE|MAPFILE_APPENDED))
		return TRUE;

	please_wait("scanning KVM dumpfile");

	if (kvm->flags & KVMHOST_32)
		dl = qemu_load(devices_x86_32, 
			QEMU_FEATURE_CPU|QEMU_FEATURE_RAM, kvm->vmp);
	else
		dl = qemu_load(devices_x86_64, 
			QEMU_FEATURE_CPU|QEMU_FEATURE_RAM, kvm->vmp);

	please_wait_done();

	if (dl) {
		if (machine_type("X86_64")) {
			idt = get_idt_base(dl);
			kvm->mapinfo.phys_base = get_kernel_base(dl);
		}

		dram = (struct qemu_device_ram *) 
			device_find_instance (dl, "ram", 0);

		if (CRASHDEBUG(1)) {
			if (machine_type("X86_64")) {
				fprintf(kvm->ofp, "IDT: %llx\n", 
					(ulonglong)idt);
				fprintf(kvm->ofp, "physical kernel base: %llx\n", 
					(ulonglong)kvm->mapinfo.phys_base); 
			}
			fprintf(kvm->ofp, "last RAM offset: %llx\n", 
				(ulonglong)dram->last_ram_offset); 
		}

		device_list_free (dl);
	} else
		fclose(kvm->vmp);

	return dl ? TRUE : FALSE;
}
