/*
 * kaslr_helper - helper for kaslr offset calculation
 *
 * Copyright (c) 2011 FUJITSU LIMITED
 * Copyright (c) 2018 Red Hat Inc.
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
 *
 * Authors: HATAYAMA Daisuke <d.hatayama@jp.fujitsu.com>
 *          INDOH Takao <indou.takao@jp.fujitsu.com>
 *          Sergio Lopez <slp@redhat.com>
 */

#include "defs.h"
#include <elf.h>
#include <inttypes.h>

#ifdef X86_64
/*
 * Get address of vector0 interrupt handler (Devide Error) from Interrupt
 * Descriptor Table.
 */
static ulong
get_vec0_addr(ulong idtr)
{
	struct gate_struct64 {
		uint16_t offset_low;
		uint16_t segment;
		uint32_t ist : 3, zero0 : 5, type : 5, dpl : 2, p : 1;
		uint16_t offset_middle;
		uint32_t offset_high;
		uint32_t zero1;
	} __attribute__((packed)) gate;

	readmem(idtr, PHYSADDR, &gate, sizeof(gate), "idt_table", FAULT_ON_ERROR);

	return ((ulong)gate.offset_high << 32)
		+ ((ulong)gate.offset_middle << 16)
		+ gate.offset_low;
}

/*
 * Parse a string of [size[KMG] ]offset[KMG]
 * Import from Linux kernel(lib/cmdline.c)
 */
static ulong
memparse(char *ptr, char **retptr)
{
	char *endptr;

	unsigned long long ret = strtoull(ptr, &endptr, 0);

	switch (*endptr) {
	case 'E':
	case 'e':
		ret <<= 10;
	case 'P':
	case 'p':
		ret <<= 10;
	case 'T':
	case 't':
		ret <<= 10;
	case 'G':
	case 'g':
		ret <<= 10;
	case 'M':
	case 'm':
		ret <<= 10;
	case 'K':
	case 'k':
		ret <<= 10;
		endptr++;
	default:
		break;
	}

	if (retptr)
		*retptr = endptr;

	return ret;
}

/*
 * Find "elfcorehdr=" in the boot parameter of kernel and return the address
 * of elfcorehdr.
 */
static ulong
get_elfcorehdr(ulong kaslr_offset)
{
	char cmdline[BUFSIZE], *ptr;
	ulong cmdline_vaddr;
	ulong cmdline_paddr;
	ulong buf_vaddr, buf_paddr;
	char *end;
	ulong elfcorehdr_addr = 0, elfcorehdr_size = 0;
	int verbose = CRASHDEBUG(1)? 1: 0;

	cmdline_vaddr = st->saved_command_line_vmlinux + kaslr_offset;
	if (!kvtop(NULL, cmdline_vaddr, &cmdline_paddr, verbose))
		return 0;

	if (CRASHDEBUG(1)) {
		fprintf(fp, "cmdline vaddr=%lx\n", cmdline_vaddr);
		fprintf(fp, "cmdline paddr=%lx\n", cmdline_paddr);
	}

	if (!readmem(cmdline_paddr, PHYSADDR, &buf_vaddr, sizeof(ulong),
		     "saved_command_line", RETURN_ON_ERROR))
		return 0;

	if (!kvtop(NULL, buf_vaddr, &buf_paddr, verbose))
		return 0;

	if (CRASHDEBUG(1)) {
		fprintf(fp, "cmdline buffer vaddr=%lx\n", buf_vaddr);
		fprintf(fp, "cmdline buffer paddr=%lx\n", buf_paddr);
	}

	memset(cmdline, 0, BUFSIZE);
	if (!readmem(buf_paddr, PHYSADDR, cmdline, BUFSIZE,
		     "saved_command_line", RETURN_ON_ERROR))
		return 0;

	ptr = strstr(cmdline, "elfcorehdr=");
	if (!ptr)
		return 0;

	if (CRASHDEBUG(1))
		fprintf(fp, "2nd kernel detected\n");

	ptr += strlen("elfcorehdr=");
	elfcorehdr_addr = memparse(ptr, &end);
	if (*end == '@') {
		elfcorehdr_size = elfcorehdr_addr;
		elfcorehdr_addr = memparse(end + 1, &end);
	}

	if (CRASHDEBUG(1)) {
		fprintf(fp, "elfcorehdr_addr=%lx\n", elfcorehdr_addr);
		fprintf(fp, "elfcorehdr_size=%lx\n", elfcorehdr_size);
	}

	return elfcorehdr_addr;
}

 /*
  * Get vmcoreinfo from elfcorehdr.
  * Some codes are imported from Linux kernel(fs/proc/vmcore.c)
  */
static int
get_vmcoreinfo(ulong elfcorehdr, ulong *addr, int *len)
{
	unsigned char e_ident[EI_NIDENT];
	Elf64_Ehdr ehdr;
	Elf64_Phdr phdr;
	Elf64_Nhdr nhdr;
	ulong ptr;
	ulong nhdr_offset = 0;
	int i;

	if (!readmem(elfcorehdr, PHYSADDR, e_ident, EI_NIDENT,
		     "EI_NIDENT", RETURN_ON_ERROR))
		return FALSE;

	if (e_ident[EI_CLASS] != ELFCLASS64) {
		error(INFO, "Only ELFCLASS64 is supportd\n");
		return FALSE;
	}

	if (!readmem(elfcorehdr, PHYSADDR, &ehdr, sizeof(ehdr),
			"Elf64_Ehdr", RETURN_ON_ERROR))
		return FALSE;

	/* Sanity Check */
	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
		(ehdr.e_type != ET_CORE) ||
		ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
		ehdr.e_ident[EI_VERSION] != EV_CURRENT ||
		ehdr.e_version != EV_CURRENT ||
		ehdr.e_ehsize != sizeof(Elf64_Ehdr) ||
		ehdr.e_phentsize != sizeof(Elf64_Phdr) ||
		ehdr.e_phnum == 0) {
		error(INFO, "Invalid elf header\n");
		return FALSE;
	}

	ptr = elfcorehdr + ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		ulong offset;
		char name[16];

		if (!readmem(ptr, PHYSADDR, &phdr, sizeof(phdr),
				"Elf64_Phdr", RETURN_ON_ERROR))
			return FALSE;

		ptr += sizeof(phdr);
		if (phdr.p_type != PT_NOTE)
			continue;

		offset = phdr.p_offset;
		if (!readmem(offset, PHYSADDR, &nhdr, sizeof(nhdr),
				"Elf64_Nhdr", RETURN_ON_ERROR))
			return FALSE;

		offset += DIV_ROUND_UP(sizeof(Elf64_Nhdr), sizeof(Elf64_Word))*
			  sizeof(Elf64_Word);
		memset(name, 0, sizeof(name));
		if (!readmem(offset, PHYSADDR, name, sizeof(name),
				"Elf64_Nhdr name", RETURN_ON_ERROR))
			return FALSE;

		if(!strcmp(name, "VMCOREINFO")) {
			nhdr_offset = offset;
			break;
		}
	}

	if (!nhdr_offset)
		return FALSE;

	*addr = nhdr_offset +
		DIV_ROUND_UP(nhdr.n_namesz, sizeof(Elf64_Word))*
		sizeof(Elf64_Word);
	*len = nhdr.n_descsz;

	if (CRASHDEBUG(1)) {
		fprintf(fp, "vmcoreinfo addr=%lx\n", *addr);
		fprintf(fp, "vmcoreinfo len=%d\n", *len);
	}

	return TRUE;
}

static int
qemu_get_cr3_idtr(ulong *cr3, ulong *idtr)
{
	QEMUCPUState *cpustat;

	if (DISKDUMP_DUMPFILE()) {
		cpustat = diskdump_get_qemucpustate(0);
	} else if (KDUMP_DUMPFILE()) {
		cpustat = kdump_get_qemucpustate(0);
	} else {
		return FALSE;
	}

	if (!cpustat) {
		return FALSE;
	}

	*cr3 = cpustat->cr[3];
	*idtr = cpustat->idt.base;

	return TRUE;
}

/*
 * Check if current kaslr_offset/phys_base is for 1st kernel or 2nd kernel.
 * If we are in 2nd kernel, get kaslr_offset/phys_base from vmcoreinfo.
 *
 * 1. Get command line and try to retrieve "elfcorehdr=" boot parameter
 * 2. If "elfcorehdr=" is not found in command line, we are in 1st kernel.
 *    There is nothing to do.
 * 3. If "elfcorehdr=" is found, we are in 2nd kernel. Find vmcoreinfo
 *    using "elfcorehdr=" and retrieve kaslr_offset/phys_base from vmcoreinfo.
 */
static int
get_kaslr_offset_from_vmcoreinfo(ulong orig_kaslr_offset,
		                 ulong *kaslr_offset, ulong *phys_base)
{
	ulong elfcorehdr_addr = 0;
	ulong vmcoreinfo_addr;
	int vmcoreinfo_len;
	char *buf, *pos;
	int ret = FALSE;

	/* Find "elfcorehdr=" in the kernel boot parameter */
	elfcorehdr_addr = get_elfcorehdr(orig_kaslr_offset);
	if (!elfcorehdr_addr)
		return FALSE;

	/* Get vmcoreinfo from the address of "elfcorehdr=" */
	if (!get_vmcoreinfo(elfcorehdr_addr, &vmcoreinfo_addr, &vmcoreinfo_len))
		return FALSE;

	if (!vmcoreinfo_len)
		return FALSE;

	if (CRASHDEBUG(1))
		fprintf(fp, "Find vmcoreinfo in kdump memory\n");

	buf = GETBUF(vmcoreinfo_len);
	if (!readmem(vmcoreinfo_addr, PHYSADDR, buf, vmcoreinfo_len,
			"vmcoreinfo", RETURN_ON_ERROR))
		goto quit;

	/* Get phys_base form vmcoreinfo */
	pos = strstr(buf, "NUMBER(phys_base)=");
	if (!pos)
		goto quit;
	*phys_base  = strtoull(pos + strlen("NUMBER(phys_base)="), NULL, 0);

	/* Get kaslr_offset form vmcoreinfo */
	pos = strstr(buf, "KERNELOFFSET=");
	if (!pos)
		goto quit;
	*kaslr_offset = strtoull(pos + strlen("KERNELOFFSET="), NULL, 16);

	ret = TRUE;

quit:
	FREEBUF(buf);
	return ret;
}

/*
 * Calculate kaslr_offset and phys_base
 *
 * kaslr_offset:
 *   The difference between original address in System.map or vmlinux and
 *   actual address placed randomly by kaslr feature. To be more accurate,
 *   kaslr_offset = actual address  - original address
 *
 * phys_base:
 *   Physical address where the kerenel is placed. In other words, it's a
 *   physical address of __START_KERNEL_map. This is also decided randomly by
 *   kaslr.
 *
 * kaslr offset and phys_base are calculated as follows:
 *
 * kaslr_offset:
 * 1) Get IDTR and CR3 value from the dump header.
 * 2) Get a virtual address of IDT from IDTR value
 *    --- (A)
 * 3) Translate (A) to physical address using CR3, the upper 52 bits
 *    of which points a top of page table.
 *    --- (B)
 * 4) Get an address of vector0 (Devide Error) interrupt handler from
 *    IDT, which are pointed by (B).
 *    --- (C)
 * 5) Get an address of symbol "divide_error" form vmlinux
 *    --- (D)
 *
 * Now we have two addresses:
 * (C)-> Actual address of "divide_error"
 * (D)-> Original address of "divide_error" in the vmlinux
 *
 * kaslr_offset can be calculated by the difference between these two
 * value.
 *
 * phys_base;
 * 1) Get IDT virtual address from vmlinux
 *    --- (E)
 *
 * So phys_base can be calculated using relationship of directly mapped
 * address.
 *
 * phys_base =
 *   Physical address(B) -
 *   (Virtual address(E) + kaslr_offset - __START_KERNEL_map)
 *
 * Note that the address (A) cannot be used instead of (E) because (A) is
 * not direct map address, it's a fixed map address.
 *
 * This solution works in most every case, but does not work in the
 * following case.
 *
 * 1) If the dump is captured on early stage of kernel boot, IDTR points
 *    early IDT table(early_idts) instead of normal IDT(idt_table).
 * 2) If the dump is captured whle kdump is working, IDTR points
 *    IDT table of 2nd kernel, not 1st kernel.
 *
 * Current implementation does not support the case 1), need
 * enhancement in the future. For the case 2), get kaslr_offset and
 * phys_base as follows.
 *
 * 1) Get kaslr_offset and phys_base using the above solution.
 * 2) Get kernel boot parameter from "saved_command_line"
 * 3) If "elfcorehdr=" is not included in boot parameter, we are in the
 *    first kernel, nothing to do any more.
 * 4) If "elfcorehdr=" is included in boot parameter, we are in the 2nd
 *    kernel. Retrieve vmcoreinfo from address of "elfcorehdr=" and
 *    get kaslr_offset and phys_base from vmcoreinfo.
 */
#define PTI_USER_PGTABLE_BIT	PAGE_SHIFT
#define PTI_USER_PGTABLE_MASK	(1 << PTI_USER_PGTABLE_BIT)
#define CR3_PCID_MASK		0xFFFull
int
calc_kaslr_offset(ulong *kaslr_offset, ulong *phys_base)
{
	uint64_t cr3 = 0, idtr = 0, pgd = 0, idtr_paddr;
	ulong divide_error_vmcore;
	ulong kaslr_offset_kdump, phys_base_kdump;
	int ret = FALSE;
	int verbose = CRASHDEBUG(1)? 1: 0;

	if (!machine_type("X86_64"))
		return FALSE;

	if (SADUMP_DUMPFILE()) {
		if (!sadump_get_cr3_idtr(&cr3, &idtr))
			return FALSE;
	} else if (QEMU_MEM_DUMP_NO_VMCOREINFO()) {
		if (!qemu_get_cr3_idtr(&cr3, &idtr))
			return FALSE;
	} else if (VMSS_DUMPFILE()) {
		if (!vmware_vmss_get_cr3_idtr(&cr3, &idtr))
			return FALSE;
	} else
		return FALSE;

	if (st->pti_init_vmlinux || st->kaiser_init_vmlinux)
		pgd = cr3 & ~(CR3_PCID_MASK|PTI_USER_PGTABLE_MASK);
	else
		pgd = cr3 & ~CR3_PCID_MASK;

	/*
	 * Set up for kvtop.
	 *
	 * calc_kaslr_offset() is called before machdep_init(PRE_GDB), so some
	 * variables are not initialized yet. Set up them here to call kvtop().
	 *
	 * TODO: XEN and 5-level is not supported
	 */
	vt->kernel_pgd[0] = pgd;
	machdep->last_pgd_read = vt->kernel_pgd[0];
	machdep->machspec->physical_mask_shift = __PHYSICAL_MASK_SHIFT_2_6;
	machdep->machspec->pgdir_shift = PGDIR_SHIFT;
	machdep->machspec->ptrs_per_pgd = PTRS_PER_PGD;
	if (!readmem(pgd, PHYSADDR, machdep->pgd, PAGESIZE(),
			"pgd", RETURN_ON_ERROR))
		goto quit;

	/* Convert virtual address of IDT table to physical address */
	if (!kvtop(NULL, idtr, &idtr_paddr, verbose))
		goto quit;

	/* Now we can calculate kaslr_offset and phys_base */
	divide_error_vmcore = get_vec0_addr(idtr_paddr);
	*kaslr_offset = divide_error_vmcore - st->divide_error_vmlinux;
	*phys_base = idtr_paddr -
		(st->idt_table_vmlinux + *kaslr_offset - __START_KERNEL_map);

	if (CRASHDEBUG(1)) {
		fprintf(fp, "calc_kaslr_offset: idtr=%lx\n", idtr);
		fprintf(fp, "calc_kaslr_offset: pgd=%lx\n", pgd);
		fprintf(fp, "calc_kaslr_offset: idtr(phys)=%lx\n", idtr_paddr);
		fprintf(fp, "calc_kaslr_offset: divide_error(vmlinux): %lx\n",
			st->divide_error_vmlinux);
		fprintf(fp, "calc_kaslr_offset: divide_error(vmcore): %lx\n",
			divide_error_vmcore);
	}

	/*
	 * Check if current kaslr_offset/phys_base is for 1st kernel or 2nd
	 * kernel. If we are in 2nd kernel, get kaslr_offset/phys_base
	 * from vmcoreinfo
	 */
	if (get_kaslr_offset_from_vmcoreinfo(
		*kaslr_offset, &kaslr_offset_kdump, &phys_base_kdump)) {
		*kaslr_offset =  kaslr_offset_kdump;
		*phys_base =  phys_base_kdump;
	} else if (CRASHDEBUG(1)) {
		fprintf(fp, "kaslr_helper: failed to determine which kernel was running at crash,\n");
		fprintf(fp, "kaslr_helper: asssuming the kdump 1st kernel.\n");
	}

	if (CRASHDEBUG(1)) {
		fprintf(fp, "calc_kaslr_offset: kaslr_offset=%lx\n",
			*kaslr_offset);
		fprintf(fp, "calc_kaslr_offset: phys_base=%lx\n", *phys_base);
	}

	ret = TRUE;
quit:
	vt->kernel_pgd[0] = 0;
	machdep->last_pgd_read = 0;
	return ret;
}
#else
int
calc_kaslr_offset(ulong *kaslr_offset, ulong *phys_page)
{
	return FALSE;
}
#endif /* X86_64 */
