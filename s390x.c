/* s390.c - core analysis suite
 *
 * Copyright (C) 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002-2006, 2009-2014 David Anderson
 * Copyright (C) 2002-2006, 2009-2014 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2005, 2006, 2010-2013 Michael Holzheu, IBM Corporation
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
#ifdef S390X
#include <elf.h>
#include "defs.h"
#include "netdump.h"

#define S390X_WORD_SIZE   8

#define S390X_PAGE_BASE_MASK     (~((1ULL<<12)-1))

/* Flags used in entries of page dirs and page tables.
 */
#define S390X_PTE_FLAG_BITS     0xfffULL /* Page table entry flag bits */
#define S390X_PAGE_PRESENT      0x001ULL /* set: loaded in physical memory
                                          * clear: not loaded in physical mem */
#define S390X_PAGE_RO           0x200ULL /* HW read-only */
#define S390X_PAGE_INVALID      0x400ULL /* HW invalid */
#define S390X_PAGE_INVALID_MASK 0x601ULL /* for linux 2.6 */
#define S390X_PAGE_INVALID_NONE 0x401ULL /* for linux 2.6 */

/* bits 52, 55 must contain zeroes in a pte */
#define S390X_PTE_INVALID_MASK  0x900ULL
#define S390X_PTE_INVALID(x) ((x) & S390X_PTE_INVALID_MASK)

#define INT_STACK_SIZE    STACKSIZE() // can be 8192 or 16384
#define KERNEL_STACK_SIZE STACKSIZE() // can be 8192 or 16384

#define LOWCORE_SIZE 8192
#define VX_SA_SIZE (32 * 16)

#define S390X_PSW_MASK_PSTATE	0x0001000000000000UL

#define S390X_LC_VMCORE_INFO	0xe0c

/*
 * Flags for Region and Segment table entries.
 */
#define S390X_RTE_FLAG_BITS_FC0    0xfffULL
#define S390X_RTE_FLAG_BITS_FC1    0x7fffffffULL
#define S390X_RTE_TL           0x3ULL
#define S390X_RTE_TL_10        0x2ULL
#define S390X_RTE_TL_01        0x1ULL
#define S390X_RTE_TT           0xcULL
#define S390X_RTE_TT_10        0x8ULL
#define S390X_RTE_TT_01        0x4ULL
#define S390X_RTE_CR           0x10ULL
#define S390X_RTE_I            0x20ULL
#define S390X_RTE_TF           0xc0ULL
#define S390X_RTE_TF_10        0x80ULL
#define S390X_RTE_TF_01        0x40ULL
#define S390X_RTE_P            0x200ULL
#define S390X_RTE_FC           0x400ULL
#define S390X_RTE_F            0x800ULL
#define S390X_RTE_ACC          0xf000ULL
#define S390X_RTE_ACC_1000     0x8000ULL
#define S390X_RTE_ACC_0100     0x4000ULL
#define S390X_RTE_ACC_0010     0x2000ULL
#define S390X_RTE_ACC_0001     0x1000ULL
#define S390X_RTE_AV           0x10000ULL

#define S390X_STE_FLAG_BITS_FC0    0x7ffULL
#define S390X_STE_FLAG_BITS_FC1    0xfffffULL
#define S390X_STE_TT           0xcULL
#define S390X_STE_TT_10        0x8ULL
#define S390X_STE_TT_01        0x4ULL
#define S390X_STE_CS           0x10ULL
#define S390X_STE_I            0x20ULL
#define S390X_STE_P            0x200ULL
#define S390X_STE_FC           0x400ULL
#define S390X_STE_F            0x800ULL
#define S390X_STE_ACC          0xf000ULL
#define S390X_STE_ACC_1000     0x8000ULL
#define S390X_STE_ACC_0100     0x4000ULL
#define S390X_STE_ACC_0010     0x2000ULL
#define S390X_STE_ACC_0001     0x1000ULL
#define S390X_STE_AV           0x10000ULL

/*
 * S390x prstatus ELF Note
 */
struct s390x_nt_prstatus {
	uint8_t		pad1[32];
	uint32_t	pr_pid;
	uint8_t		pad2[76];
	uint64_t	psw[2];
	uint64_t	gprs[16];
	uint32_t	acrs[16];
	uint64_t	orig_gpr2;
	uint32_t	pr_fpvalid;
	uint8_t		pad3[4];
} __attribute__ ((packed));

/*
 * S390x floating point register ELF Note
 */
#ifndef NT_FPREGSET
#define NT_FPREGSET 0x2
#endif

struct s390x_nt_fpregset {
	uint32_t	fpc;
	uint32_t	pad;
	uint64_t	fprs[16];
} __attribute__ ((packed));

struct s390x_vxrs {
	uint64_t	low;
	uint64_t	high;
} __attribute__ ((packed));

/*
 * s390x CPU info
 */
struct s390x_cpu
{
	uint64_t	gprs[16];
	uint64_t	ctrs[16];
	uint32_t	acrs[16];
	uint64_t	fprs[16];
	uint32_t	fpc;
	uint64_t	psw[2];
	uint32_t	prefix;
	uint64_t	timer;
	uint64_t	todcmp;
	uint32_t	todpreg;
	uint64_t		vxrs_low[16];
	struct s390x_vxrs	vxrs_high[16];
};

/*
 * declarations of static functions
 */
static void s390x_print_lowcore(char*, struct bt_info*,int);
static int s390x_kvtop(struct task_context *, ulong, physaddr_t *, int);
static int s390x_uvtop(struct task_context *, ulong, physaddr_t *, int);
static int s390x_vtop(unsigned long, ulong, physaddr_t*, int);
static ulong s390x_vmalloc_start(void);
static int s390x_is_task_addr(ulong);
static int s390x_verify_symbol(const char *, ulong, char type);
static ulong s390x_get_task_pgd(ulong);
static int s390x_translate_pte(ulong, void *, ulonglong);
static ulong s390x_processor_speed(void);
static int s390x_eframe_search(struct bt_info *);
static void s390x_back_trace_cmd(struct bt_info *);
static void s390x_get_stack_frame(struct bt_info *, ulong *, ulong *);
static int s390x_dis_filter(ulong, char *, unsigned int);
static void s390x_cmd_mach(void);
static int s390x_get_smp_cpus(void);
static void s390x_display_machine_stats(void);
static void s390x_dump_line_number(ulong);
static struct line_number_hook s390x_line_number_hooks[];
static int s390x_is_uvaddr(ulong, struct task_context *);
static int s390x_get_kvaddr_ranges(struct vaddr_range *);
static int set_s390x_max_physmem_bits(void);

/*
 * struct lowcore name (old: "_lowcore", new: "lowcore")
 */
static char *lc_struct;

/*
 * Read a unsigned long value from address
 */
static unsigned long readmem_ul(unsigned long addr)
{
	unsigned long rc;

	readmem(addr, KVADDR, &rc, sizeof(rc), "readmem_ul", FAULT_ON_ERROR);
	return rc;
}

/*
 * Print hex data
 */
static void print_hex_buf(void *buf, int len, int cols, char *tag)
{
	int j, first = 1;

	for (j = 0; j < len; j += 8) {
		if (j % (cols * 8) == 0) {
			if (first)
				first = 0;
			else
				fprintf(fp, "\n");
			fprintf(fp, "%s", tag);
		}
		fprintf(fp, "%#018lx ", *((unsigned long *)(buf + j)));
	}
	if (len)
		fprintf(fp, "\n");
}

/*
 * Initialize member offsets
 */
static void s390x_offsets_init(void)
{
	if (STRUCT_EXISTS("lowcore"))
		lc_struct = "lowcore";
	else
		lc_struct = "_lowcore";

	if (MEMBER_EXISTS(lc_struct, "st_status_fixed_logout"))
		MEMBER_OFFSET_INIT(s390_lowcore_psw_save_area, lc_struct,
				   "st_status_fixed_logout");
	else
		MEMBER_OFFSET_INIT(s390_lowcore_psw_save_area, lc_struct,
				   "psw_save_area");
	if (!STRUCT_EXISTS("stack_frame")) {
		ASSIGN_OFFSET(s390_stack_frame_back_chain) = 0;
		ASSIGN_OFFSET(s390_stack_frame_r14) = 112;
		ASSIGN_SIZE(s390_stack_frame) = 160;
	} else {
		ASSIGN_OFFSET(s390_stack_frame_back_chain) =
			MEMBER_OFFSET("stack_frame", "back_chain");
		ASSIGN_OFFSET(s390_stack_frame_r14) =
			MEMBER_OFFSET("stack_frame", "gprs") + 8 * 8;
		ASSIGN_SIZE(s390_stack_frame) = STRUCT_SIZE("stack_frame");
	}
}

/*
 *  MAX_PHYSMEM_BITS is 42 on older kernels, and 46 on newer kernels.
 */
static int
set_s390x_max_physmem_bits(void)
{
	int array_len, dimension;
	char *string;

	if ((string = pc->read_vmcoreinfo("NUMBER(MAX_PHYSMEM_BITS)"))) {
		machdep->max_physmem_bits = atol(string);
		free(string);
		return TRUE;
	}

	machdep->max_physmem_bits = _MAX_PHYSMEM_BITS_OLD;

	if (!kernel_symbol_exists("mem_section"))
		return TRUE;

	/*
	 *  The mem_section was changed to be a pointer in 4.15, so it's 
	 *  guaranteed to be a newer kernel.
	 */
	if (get_symbol_type("mem_section", NULL, NULL) == TYPE_CODE_PTR) {
		machdep->max_physmem_bits = _MAX_PHYSMEM_BITS_NEW;
		return TRUE;
	}

	if (!(array_len = get_array_length("mem_section", &dimension, 0)))
		return FALSE;

	/*
	 * !CONFIG_SPARSEMEM_EXTREME
	 */
	if (dimension) {
		machdep->max_physmem_bits = _MAX_PHYSMEM_BITS_OLD;
		if (array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT()))
			return TRUE;

		machdep->max_physmem_bits = _MAX_PHYSMEM_BITS_NEW;
		if (array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT()))
			return TRUE;

		return FALSE;
	}

	/*
	 * CONFIG_SPARSEMEM_EXTREME
	 */
	machdep->max_physmem_bits = _MAX_PHYSMEM_BITS_OLD;
	if (array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT_EXTREME()))
		return TRUE;

	machdep->max_physmem_bits = _MAX_PHYSMEM_BITS_NEW;
	if (array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT_EXTREME()))
		return TRUE;

	return FALSE;
}

static struct s390x_cpu *s390x_cpu_vec;
static int s390x_cpu_cnt;
/*
 * Return s390x CPU data for backtrace
 */
static struct s390x_cpu *s390x_cpu_get(struct bt_info *bt)
{
	unsigned int cpu = bt->tc->processor;
	unsigned long lowcore_ptr, prefix;
	unsigned int i;

	lowcore_ptr = symbol_value("lowcore_ptr");
	readmem(lowcore_ptr + cpu * sizeof(long), KVADDR,
		&prefix, sizeof(long), "lowcore_ptr", FAULT_ON_ERROR);
	for (i = 0; i < s390x_cpu_cnt; i++) {
		if (s390x_cpu_vec[i].prefix == prefix)
			return &s390x_cpu_vec[i];
	}
	error(FATAL, "cannot determine CPU for task: %lx\n", bt->task);
	return NULL;
}

/*
 * ELF core dump fuctions for storing CPU data
 */
static void s390x_elf_nt_prstatus_add(struct s390x_cpu *cpu,
				      struct s390x_nt_prstatus *prstatus)
{
	memcpy(&cpu->psw, &prstatus->psw, sizeof(cpu->psw));
	memcpy(&cpu->gprs, &prstatus->gprs, sizeof(cpu->gprs));
	memcpy(&cpu->acrs, &prstatus->acrs, sizeof(cpu->acrs));
}

static void s390x_elf_nt_fpregset_add(struct s390x_cpu *cpu,
				      struct s390x_nt_fpregset *fpregset)
{
	memcpy(&cpu->fpc, &fpregset->fpc, sizeof(cpu->fpc));
	memcpy(&cpu->fprs, &fpregset->fprs, sizeof(cpu->fprs));
}

static void s390x_elf_nt_timer_add(struct s390x_cpu *cpu, void *desc)
{
	memcpy(&cpu->timer, desc, sizeof(cpu->timer));
}

static void s390x_elf_nt_todcmp_add(struct s390x_cpu *cpu, void *desc)
{
	memcpy(&cpu->todcmp, desc, sizeof(cpu->todcmp));
}

static void s390x_elf_nt_todpreg_add(struct s390x_cpu *cpu, void *desc)
{
	memcpy(&cpu->todpreg, desc, sizeof(cpu->todpreg));
}

static void s390x_elf_nt_ctrs_add(struct s390x_cpu *cpu, void *desc)
{
	memcpy(&cpu->ctrs, desc, sizeof(cpu->ctrs));
}

static void s390x_elf_nt_prefix_add(struct s390x_cpu *cpu, void *desc)
{
	memcpy(&cpu->prefix, desc, sizeof(cpu->prefix));
}

static void s390x_elf_nt_vxrs_low_add(struct s390x_cpu *cpu, void *desc)
{
	memcpy(&cpu->vxrs_low, desc, sizeof(cpu->vxrs_low));
}

static void s390x_elf_nt_vxrs_high_add(struct s390x_cpu *cpu, void *desc)
{
	memcpy(&cpu->vxrs_high, desc, sizeof(cpu->vxrs_high));
}

static void *get_elf_note_desc(Elf64_Nhdr *note)
{
	void *ptr = note;

	return ptr + roundup(sizeof(*note) + note->n_namesz, 4);
}

static void s390x_elf_note_add(int elf_cpu_nr, void *note_ptr)
{
	Elf64_Nhdr *note = note_ptr;
	struct s390x_cpu *cpu;
	void *desc;

	desc = get_elf_note_desc(note);
	if (elf_cpu_nr != s390x_cpu_cnt) {
		s390x_cpu_cnt++;
		s390x_cpu_vec = realloc(s390x_cpu_vec,
					s390x_cpu_cnt * sizeof(*s390x_cpu_vec));
		if (!s390x_cpu_vec)
			error(FATAL, "cannot malloc cpu space.");
	}
	cpu = &s390x_cpu_vec[s390x_cpu_cnt - 1];
	switch (note->n_type) {
	case NT_PRSTATUS:
		s390x_elf_nt_prstatus_add(cpu, desc);
		break;
	case NT_FPREGSET:
		s390x_elf_nt_fpregset_add(cpu, desc);
		break;
	case NT_S390_TIMER:
		s390x_elf_nt_timer_add(cpu, desc);
		break;
	case NT_S390_TODCMP:
		s390x_elf_nt_todcmp_add(cpu, desc);
		break;
	case NT_S390_TODPREG:
		s390x_elf_nt_todpreg_add(cpu, desc);
		break;
	case NT_S390_CTRS:
		s390x_elf_nt_ctrs_add(cpu, desc);
		break;
	case NT_S390_PREFIX:
		s390x_elf_nt_prefix_add(cpu, desc);
		break;
	case NT_S390_VXRS_LOW:
		s390x_elf_nt_vxrs_low_add(cpu, desc);
		break;
	case NT_S390_VXRS_HIGH:
		s390x_elf_nt_vxrs_high_add(cpu, desc);
		break;
	}
}

static void s390x_process_elf_notes(void *note_ptr, unsigned long size_note)
{
	Elf64_Nhdr *note = NULL;
	size_t tot, len;
	static int num_prstatus_notes = 0;

	for (tot = 0; tot < size_note; tot += len) {
		note = note_ptr + tot;

		if (note->n_type == NT_PRSTATUS)
			num_prstatus_notes++;

		machdep->dumpfile_init(num_prstatus_notes, note);

		len = sizeof(Elf64_Nhdr);
		len = roundup(len + note->n_namesz, 4);
		len = roundup(len + note->n_descsz, 4);
	}
}

static void s390x_check_live(void)
{
	unsigned long long live_magic;

	readmem(0, KVADDR, &live_magic, sizeof(live_magic), "live_magic",
		RETURN_ON_ERROR | QUIET);

	if (live_magic == 0x4c49564544554d50ULL)
		pc->flags2 |= LIVE_DUMP;
}

static char *
vmcoreinfo_read_string_s390x(const char *vmcoreinfo, const char *key)
{
	char *value_string = NULL;
	size_t value_length;
	char keybuf[128];
	char *p1, *p2;

	sprintf(keybuf, "%s=", key);

	if ((p1 = strstr(vmcoreinfo, keybuf))) {
		p2 = p1 + strlen(keybuf);
		p1 = strstr(p2, "\n");
		value_length = p1-p2;
		value_string = calloc(value_length + 1, sizeof(char));
		strncpy(value_string, p2, value_length);
		value_string[value_length] = NULLCHAR;
	}

	return value_string;
}

/*
 * Check the value in well-known lowcore location and process it as either
 * an explicit KASLR offset (early dump case) or as vmcoreinfo pointer to
 * read the relocated _stext symbol value (important for s390 and lkcd dump
 * formats).
 */
static void s390x_check_kaslr(void)
{
	char *_stext_string, *vmcoreinfo;
	Elf64_Nhdr note;
	char str[128];
	ulong addr;

	/* Read the value from well-known lowcore location*/
	if (!readmem(S390X_LC_VMCORE_INFO, PHYSADDR, &addr,
		    sizeof(addr), "s390x vmcoreinfo ptr",
		    QUIET|RETURN_ON_ERROR))
		return;
	if (addr == 0)
		return;
	/* Check for explicit kaslr offset flag */
	if (addr & 0x1UL) {
		/* Drop the last bit to get an offset value */
		addr &= ~(0x1UL);
		/* Make sure the offset is aligned by 0x1000 */
		if (addr && !(addr & 0xfff)) {
					kt->relocate = addr * (-1);
					kt->flags |= RELOC_SET;
					kt->flags2 |= KASLR;
		}
		return;
	}
	/* Use the addr value as vmcoreinfo pointer */
	if (!readmem(addr, PHYSADDR, &note,
		     sizeof(note), "Elf64_Nhdr vmcoreinfo",
		     QUIET|RETURN_ON_ERROR))
		return;
	memset(str, 0, sizeof(str));
	if (!readmem(addr + sizeof(note), PHYSADDR, str,
		     note.n_namesz, "VMCOREINFO",
		     QUIET|RETURN_ON_ERROR))
		return;
	if (memcmp(str, "VMCOREINFO", sizeof("VMCOREINFO")) != 0)
		return;
	if ((vmcoreinfo = malloc(note.n_descsz + 1)) == NULL) {
		error(INFO, "s390x_check_kaslr: cannot malloc vmcoreinfo buffer\n");
		return;
	}
	addr = addr + sizeof(note) + note.n_namesz + 1;
	if (!readmem(addr, PHYSADDR, vmcoreinfo,
		     note.n_descsz, "s390x vmcoreinfo",
		     QUIET|RETURN_ON_ERROR)) {
		free(vmcoreinfo);
		return;
	}
	vmcoreinfo[note.n_descsz] = NULLCHAR;
	/*
	 * Read relocated _stext symbol value and store it in the kernel_table
	 * for further processing within derive_kaslr_offset().
	 */
	if ((_stext_string = vmcoreinfo_read_string_s390x(vmcoreinfo,
							  "SYMBOL(_stext)"))) {
		kt->vmcoreinfo._stext_SYMBOL = htol(_stext_string,
						    RETURN_ON_ERROR, NULL);
		free(_stext_string);
	}
	free(vmcoreinfo);
}

/*
 *  Do all necessary machine-specific setup here.  This is called several
 *  times during initialization.
 */
void
s390x_init(int when)
{
	switch (when)
	{
	case SETUP_ENV:
		machdep->dumpfile_init = s390x_elf_note_add;
		machdep->process_elf_notes = s390x_process_elf_notes;
		break;
	case PRE_SYMTAB:
		machdep->verify_symbol = s390x_verify_symbol;
		if (pc->flags & KERNEL_DEBUG_QUERY)
			return;
		machdep->pagesize = memory_page_size();
		machdep->pageshift = ffs(machdep->pagesize) - 1;
		machdep->pageoffset = machdep->pagesize - 1;
		machdep->pagemask = ~((ulonglong)machdep->pageoffset);
		// machdep->stacksize = KERNEL_STACK_SIZE;
		if ((machdep->pgd = (char *)malloc(SEGMENT_TABLE_SIZE)) == NULL)
			error(FATAL, "cannot malloc pgd space.");
		machdep->pmd = machdep->pgd;
		if ((machdep->ptbl = (char *)malloc(PAGESIZE())) == NULL)
			error(FATAL, "cannot malloc ptbl space.");
		machdep->last_pgd_read = 0;
		machdep->last_pmd_read = 0;
		machdep->last_ptbl_read = 0;
		machdep->verify_paddr = generic_verify_paddr;
		machdep->get_kvaddr_ranges = s390x_get_kvaddr_ranges;
		machdep->ptrs_per_pgd = PTRS_PER_PGD;
		if (DUMPFILE() && !(kt->flags & RELOC_SET))
			s390x_check_kaslr();
		break;

	case PRE_GDB:
		machdep->kvbase = 0;
		machdep->identity_map_base = 0;
		machdep->is_kvaddr =  generic_is_kvaddr;
		machdep->is_uvaddr =  s390x_is_uvaddr;
		machdep->eframe_search = s390x_eframe_search;
		machdep->back_trace = s390x_back_trace_cmd;
		machdep->processor_speed = s390x_processor_speed;
		machdep->uvtop = s390x_uvtop;
		machdep->kvtop = s390x_kvtop;
		machdep->get_task_pgd = s390x_get_task_pgd;
		machdep->get_stack_frame = s390x_get_stack_frame;
		machdep->get_stackbase = generic_get_stackbase;
		machdep->get_stacktop = generic_get_stacktop;
		machdep->translate_pte = s390x_translate_pte;
		machdep->memory_size = generic_memory_size;
		machdep->is_task_addr = s390x_is_task_addr;
		machdep->dis_filter = s390x_dis_filter;
		machdep->cmd_mach = s390x_cmd_mach;
		machdep->get_smp_cpus = s390x_get_smp_cpus;
		machdep->line_number_hooks = s390x_line_number_hooks;
		machdep->value_to_symbol = generic_machdep_value_to_symbol;
		machdep->init_kernel_pgd = NULL;
		vt->flags |= COMMON_VADDR;
		s390x_check_live();
		break;

	case POST_GDB:
		if (symbol_exists("irq_desc"))
			ARRAY_LENGTH_INIT(machdep->nr_irqs, irq_desc,
				"irq_desc", NULL, 0);
		else if (kernel_symbol_exists("nr_irqs"))
			get_symbol_data("nr_irqs", sizeof(unsigned int),
				&machdep->nr_irqs);
		else
			machdep->nr_irqs = 0;

		machdep->vmalloc_start = s390x_vmalloc_start;
		machdep->dump_irq = generic_dump_irq;
		if (!machdep->hz)
			machdep->hz = HZ;
		machdep->section_size_bits = _SECTION_SIZE_BITS;
		if (!set_s390x_max_physmem_bits())
			error(WARNING, "cannot determine MAX_PHYSMEM_BITS\n");
		s390x_offsets_init();
		break;

	case POST_INIT:
		break;
	}
}

/*
 * Dump machine dependent information
 */
void
s390x_dump_machdep_table(ulong arg)
{
	int others; 
 
	others = 0;
	fprintf(fp, "              flags: %lx (", machdep->flags);
	if (machdep->flags & KSYMS_START)
		fprintf(fp, "%sKSYMS_START", others++ ? "|" : "");
	fprintf(fp, ")\n");

	fprintf(fp, "             kvbase: %lx\n", machdep->kvbase);
	fprintf(fp, "  identity_map_base: %lx\n", machdep->kvbase);
	fprintf(fp, "           pagesize: %d\n", machdep->pagesize);
	fprintf(fp, "          pageshift: %d\n", machdep->pageshift);
	fprintf(fp, "           pagemask: %llx\n", machdep->pagemask);
	fprintf(fp, "         pageoffset: %lx\n", machdep->pageoffset);
	fprintf(fp, "          stacksize: %ld\n", machdep->stacksize);
	fprintf(fp, "                 hz: %d\n", machdep->hz);
	fprintf(fp, "                mhz: %ld\n", machdep->mhz);
	fprintf(fp, "            memsize: %lld (0x%llx)\n", 
		(unsigned long long)machdep->memsize,
		(unsigned long long)machdep->memsize);
	fprintf(fp, "               bits: %d\n", machdep->bits);
	fprintf(fp, "            nr_irqs: %d\n", machdep->nr_irqs);
	fprintf(fp, "      eframe_search: s390x_eframe_search()\n");
	fprintf(fp, "         back_trace: s390x_back_trace_cmd()\n");
	fprintf(fp, "    processor_speed: s390x_processor_speed()\n");
	fprintf(fp, "              uvtop: s390x_uvtop()\n");
	fprintf(fp, "              kvtop: s390x_kvtop()\n");
	fprintf(fp, "       get_task_pgd: s390x_get_task_pgd()\n");
	fprintf(fp, "           dump_irq: generic_dump_irq()\n");
	fprintf(fp, "    get_stack_frame: s390x_get_stack_frame()\n");
	fprintf(fp, "      get_stackbase: generic_get_stackbase()\n");
	fprintf(fp, "       get_stacktop: generic_get_stacktop()\n");
	fprintf(fp, "      translate_pte: s390x_translate_pte()\n");
	fprintf(fp, "        memory_size: generic_memory_size()\n");
	fprintf(fp, "      vmalloc_start: s390x_vmalloc_start()\n");
	fprintf(fp, "       is_task_addr: s390x_is_task_addr()\n");
	fprintf(fp, "      verify_symbol: s390x_verify_symbol()\n");
	fprintf(fp, "         dis_filter: s390x_dis_filter()\n");
	fprintf(fp, "           cmd_mach: s390x_cmd_mach()\n");
	fprintf(fp, "       get_smp_cpus: s390x_get_smp_cpus()\n");
	fprintf(fp, "          is_kvaddr: generic_is_kvaddr()\n");
	fprintf(fp, "          is_uvaddr: s390x_is_uvaddr()\n");
	fprintf(fp, "       verify_paddr: generic_verify_paddr()\n");
	fprintf(fp, "  get_kvaddr_ranges: s390x_get_kvaddr_ranges()\n");
	fprintf(fp, "    init_kernel_pgd: NULL\n");
	fprintf(fp, "    value_to_symbol: generic_machdep_value_to_symbol()\n");
	fprintf(fp, "      dumpfile_init: s390x_elf_note_add()\n");
	fprintf(fp, "  process_elf_notes: s390x_process_elf_notes()\n");
	fprintf(fp, "  line_number_hooks: s390x_line_number_hooks\n");
	fprintf(fp, "      last_pgd_read: %lx\n", machdep->last_pgd_read);
	fprintf(fp, "      last_pmd_read: %lx\n", machdep->last_pmd_read);
	fprintf(fp, "     last_ptbl_read: %lx\n", machdep->last_ptbl_read);
	fprintf(fp, "                pgd: %lx\n", (ulong)machdep->pgd);
	fprintf(fp, "                pmd: %lx\n", (ulong)machdep->pmd);
	fprintf(fp, "               ptbl: %lx\n", (ulong)machdep->ptbl);
	fprintf(fp, "       ptrs_per_pgd: %d\n", machdep->ptrs_per_pgd);
	fprintf(fp, "   max_physmem_bits: %ld\n", machdep->max_physmem_bits);
	fprintf(fp, "  section_size_bits: %ld\n", machdep->section_size_bits);
	fprintf(fp, "           machspec: %lx\n", (ulong)machdep->machspec);
}

/*
 * Check if address is in context's address space
 */
static int 
s390x_is_uvaddr(ulong vaddr, struct task_context *tc)
{
	return IN_TASK_VMA(tc->task, vaddr);
}

/*
 *  Translates a user virtual address to its physical address
 */
static int
s390x_uvtop(struct task_context *tc, ulong vaddr, physaddr_t *paddr, int verbose)
{
	unsigned long pgd_base;
	readmem(tc->mm_struct + OFFSET(mm_struct_pgd), KVADDR,
		&pgd_base,sizeof(long), "pgd_base",FAULT_ON_ERROR);
	return s390x_vtop(pgd_base, vaddr, paddr, verbose);	
}

/*
 *  Translates a kernel virtual address to its physical address
 */
static int
s390x_kvtop(struct task_context *tc, ulong vaddr, physaddr_t *paddr, int verbose)
{
	unsigned long pgd_base;

	if (!IS_KVADDR(vaddr)){
		*paddr = 0;
		return FALSE;
	}

	if (!vt->vmalloc_start) {
	       *paddr = VTOP(vaddr);
	       return TRUE;
	}

	if (!IS_VMALLOC_ADDR(vaddr)) {
	       *paddr = VTOP(vaddr);
	       return TRUE;
	}

	pgd_base = (unsigned long)vt->kernel_pgd[0];
	return s390x_vtop(pgd_base, vaddr, paddr, verbose);	
}

/*
 * Check if page is mapped
 */
static inline int s390x_pte_present(unsigned long x){
	if(THIS_KERNEL_VERSION >= LINUX(2,6,0)){
		return !((x) & S390X_PAGE_INVALID) ||
			((x) & S390X_PAGE_INVALID_MASK) == S390X_PAGE_INVALID_NONE;
	} else {
		return ((x) & S390X_PAGE_PRESENT);
	}
}

/*
 * page table traversal functions 
 */

/* Print flags of Segment-Table entry with format control = 1 */
static void print_segment_entry_fc1(ulong val)
{
	fprintf(fp, "AV=%u; ACC=%u%u%u%u; F=%u; FC=%u; P=%u; I=%u; CS=%u; TT=%u%u\n",
		!!(val & S390X_STE_AV),
		!!(val & S390X_STE_ACC_1000),
		!!(val & S390X_STE_ACC_0100),
		!!(val & S390X_STE_ACC_0010),
		!!(val & S390X_STE_ACC_0001),
		!!(val & S390X_STE_F),
		!!(val & S390X_STE_FC),
		!!(val & S390X_STE_P),
		!!(val & S390X_STE_I),
		!!(val & S390X_STE_CS),
		!!(val & S390X_STE_TT_10),
		!!(val & S390X_STE_TT_01));
}

/* Print flags of Segment-Table entry with format control = 0 */
static void print_segment_entry_fc0(ulong val)
{
	fprintf(fp, "FC=%u; P=%u; I=%u; CS=%u; TT=%u%u\n",
		!!(val & S390X_STE_FC),
		!!(val & S390X_STE_P),
		!!(val & S390X_STE_I),
		!!(val & S390X_STE_CS),
		!!(val & S390X_STE_TT_10),
		!!(val & S390X_STE_TT_01));
}

/* Print flags of Region-Third-Table entry with format control = 1 */
static void print_region_third_entry_fc1(ulong val)
{
	fprintf(fp, "AV=%u; ACC=%u%u%u%u; F=%u; FC=%u; P=%u; I=%u; CR=%u; TT=%u%u\n",
		!!(val & S390X_RTE_AV),
		!!(val & S390X_RTE_ACC_1000),
		!!(val & S390X_RTE_ACC_0100),
		!!(val & S390X_RTE_ACC_0010),
		!!(val & S390X_RTE_ACC_0001),
		!!(val & S390X_RTE_F),
		!!(val & S390X_RTE_FC),
		!!(val & S390X_RTE_P),
		!!(val & S390X_RTE_I),
		!!(val & S390X_RTE_CR),
		!!(val & S390X_RTE_TT_10),
		!!(val & S390X_RTE_TT_01));
}

/* Print flags of Region-Third-Table entry with format control = 0 */
static void print_region_third_entry_fc0(ulong val)
{
	fprintf(fp, "FC=%u; P=%u; TF=%u%u; I=%u; CR=%u; TT=%u%u; TL=%u%u\n",
		!!(val & S390X_RTE_FC),
		!!(val & S390X_RTE_P),
		!!(val & S390X_RTE_TF_10),
		!!(val & S390X_RTE_TF_01),
		!!(val & S390X_RTE_I),
		!!(val & S390X_RTE_CR),
		!!(val & S390X_RTE_TT_10),
		!!(val & S390X_RTE_TT_01),
		!!(val & S390X_RTE_TL_10),
		!!(val & S390X_RTE_TL_01));
}

/* Print flags of Region-First/Second-Table entry */
static void print_region_first_second_entry(ulong val)
{
	fprintf(fp, "P=%u; TF=%u%u; I=%u; TT=%u%u; TL=%u%u\n",
		!!(val & S390X_RTE_P),
		!!(val & S390X_RTE_TF_10),
		!!(val & S390X_RTE_TF_01),
		!!(val & S390X_RTE_I),
		!!(val & S390X_RTE_TT_10),
		!!(val & S390X_RTE_TT_01),
		!!(val & S390X_RTE_TL_10),
		!!(val & S390X_RTE_TL_01));
}

/* Print the binary flags for Region or Segment table entry */
static void s390x_print_te_binary_flags(ulong val, int level)
{
	fprintf(fp, "       flags in binary : ");
	switch (level) {
	case 0:
		if (val & S390X_STE_FC)
			print_segment_entry_fc1(val);
		else
			print_segment_entry_fc0(val);
		break;
	case 1:
		if (val & S390X_RTE_FC)
			print_region_third_entry_fc1(val);
		else
			print_region_third_entry_fc0(val);
		break;
	case 2:
	case 3:
		print_region_first_second_entry(val);
		break;
	}
}

/* Region or segment table traversal function */
static ulong _kl_rsg_table_deref_s390x(ulong vaddr, ulong table,
				       int len, int level, int verbose)
{
	const char *name_vec[] = {"STE", "RTTE", "RSTE", "RFTE"};
	ulong offset, entry, flags, addr;
	int flags_prt_len;

	offset = ((vaddr >> (11*level + 20)) & 0x7ffULL) * 8;
	if (offset >= (len + 1)*4096)
		/* Offset is over the table limit. */
		return 0;
	addr = table + offset;
	readmem(addr, KVADDR, &entry, sizeof(entry), "entry", FAULT_ON_ERROR);
	if (verbose) {
		flags_prt_len = 3;
		if (entry & S390X_RTE_FC)
			if (level) {
				flags = entry & S390X_RTE_FLAG_BITS_FC1;
				flags_prt_len = 8;
			} else {
				flags = entry & S390X_STE_FLAG_BITS_FC1;
				flags_prt_len = 5;
			}
		else
			if (level)
				flags = entry & S390X_RTE_FLAG_BITS_FC0;
			else
				flags = entry & S390X_STE_FLAG_BITS_FC0;
		fprintf(fp, "%5s: %016lx => %016lx (flags = %0*lx)\n",
			name_vec[level], addr, entry, flags_prt_len, flags);
		s390x_print_te_binary_flags(entry, level);
	}
	/*
	 * Check if the segment table entry could be read and doesn't have
	 * any of the reserved bits set.
	 */
	if ((entry & S390X_RTE_TT) != (level << 2))
		return 0;
	/* Check if the region table entry has the invalid bit set. */
	if (entry & S390X_RTE_I)
		return 0;
	/* Region table entry is valid and well formed. */
	return entry;
}

/* Check for swap entry */
static int swap_entry(ulong entry)
{
	if (THIS_KERNEL_VERSION < LINUX(2,6,19)) {
		if ((entry & 0x601ULL) == 0x600ULL)
			return 1;
	} if (THIS_KERNEL_VERSION < LINUX(3,12,0)) {
		if ((entry & 0x403ULL) == 0x403ULL)
			return 1;
	} else {
		if ((entry & 0x603ULL) == 0x402ULL)
			return 1;
	}
	return 0;
}

/* Page table traversal function */
static ulong _kl_pg_table_deref_s390x(ulong vaddr, ulong table, int verbose)
{
	ulong offset, entry, addr;

	offset = ((vaddr >> 12) & 0xffULL) * 8;
	addr = table + offset;
	readmem(addr, KVADDR, &entry, sizeof(entry), "entry", FAULT_ON_ERROR);
	if (verbose) {
		fprintf(fp, "%5s: %016lx => %016lx (flags = %03llx)\n",
			"PTE", addr, entry, entry & S390X_PTE_FLAG_BITS);
		fprintf(fp, "       flags in binary : I=%u; P=%u\n",
			!!(entry & S390X_PAGE_INVALID), !!(entry & S390X_PAGE_RO));
		fprintf(fp, "%5s: %016llx\n", "PAGE", entry & ~S390X_PTE_FLAG_BITS);
	}
	/*
	 * Return zero if the page table entry has the reserved (0x800) or
	 * the invalid (0x400) bit set and it is not a swap entry.
	 */
	if ((entry & 0xc00ULL) && !swap_entry(entry))
		return 0;
	/* Page table entry is valid and well formed. */
	return entry;
}

/* lookup virtual address in page tables */
int s390x_vtop(ulong table, ulong vaddr, physaddr_t *phys_addr, int verbose)
{
	ulong entry, paddr;
	int level, len;

	if (verbose)
		fprintf(fp, "PAGE DIRECTORY: %016lx\n", table);

	*phys_addr = 0;
	/*
	 * Walk the region and segment tables.
	 * We assume that the table length field in the asce is set to the
	 * maximum value of 3 (which translates to a region first, region
	 * second, region third or segment table with 2048 entries) and that
	 * the addressing mode is 64 bit.
	 */
	len = 3;
	/* Read the first entry to find the number of page table levels. */
	readmem(table, KVADDR, &entry, sizeof(entry), "entry", FAULT_ON_ERROR);
	level = (entry & 0xcULL) >> 2;
	if ((level < 3) && (vaddr >> (31 + 11*level)) != 0ULL) {
		/* Address too big for the number of page table levels. */
		return FALSE;
	}
	while (level >= 0) {
		entry = _kl_rsg_table_deref_s390x(vaddr, table, len, level,
						  verbose);
		if (!entry)
			return FALSE;
		table = entry & ~0xfffULL;
		/* Check if this a 2GB page */
		if ((entry & 0x400ULL) && (level == 1)) {
			/* Add the 2GB frame offset & return the final value. */
			table &= ~0x7fffffffULL;
			*phys_addr = table + (vaddr & 0x7fffffffULL);
			return TRUE;
		}
		len = entry & 0x3ULL;
		level--;
	}

	/* Check if this is a large page. */
	if (entry & 0x400ULL) {
		/* Add the 1MB page offset and return the final value. */
		table &= ~0xfffffULL;
		*phys_addr = table + (vaddr & 0xfffffULL);
		return TRUE;
	}

	/* Get the page table entry */
	entry = _kl_pg_table_deref_s390x(vaddr, entry & ~0x7ffULL, verbose);
	if (!entry)
		return FALSE;

	/* For swap entries we have to return FALSE and phys_addr = PTE */
	if (swap_entry(entry)) {
		*phys_addr = entry;
		return FALSE;
	}

	/* Isolate the page origin from the page table entry. */
	paddr = entry & ~0xfffULL;

	/* Add the page offset and return the final value. */
	*phys_addr = paddr + (vaddr & 0xfffULL);

	return TRUE;
}

/*
 *  Determine where vmalloc'd memory starts.
 */
static ulong
s390x_vmalloc_start(void)
{
	unsigned long highmem_addr,high_memory;
	highmem_addr=symbol_value("high_memory");
       	readmem(highmem_addr, PHYSADDR, &high_memory,sizeof(long),
		"highmem",FAULT_ON_ERROR);
	return high_memory;
}

/*
 * Check if address can be a valid task_struct
 */
static int
s390x_is_task_addr(ulong task)
{
	if (tt->flags & THREAD_INFO)
		return IS_KVADDR(task);
	else
		return (IS_KVADDR(task) && (ALIGNED_STACK_OFFSET(task) == 0));
}

/*
 * return MHz - unfortunately it is not possible to get this on linux 
 *              for zSeries
 */
static ulong
s390x_processor_speed(void)
{
	return 0;
}

/*
 *  Accept or reject a symbol from the kernel namelist.
 */
static int
s390x_verify_symbol(const char *name, ulong value, char type)
{
	int i;

	if (CRASHDEBUG(8) && name && strlen(name))
		fprintf(fp, "%08lx %s\n", value, name);

	if (STREQ(name, "startup") || STREQ(name, "_stext"))
		machdep->flags |= KSYMS_START;

	if (!name || !strlen(name) || !(machdep->flags & KSYMS_START))
		return FALSE;

	if ((type == 'A') && STRNEQ(name, "__crc_"))
		return FALSE;

	if (STREQ(name, "Letext") || STREQ(name, "gcc2_compiled."))
		return FALSE;

        /* reject L2^B symbols */
	if (strstr(name, "L2\002") == name)
	    	return FALSE;

	if (STREQ(name, ".rodata"))
		return TRUE;

	/* throw away all symbols containing a '.' */
	for(i = 0; i < strlen(name);i++){
		if(name[i] == '.')
			return FALSE;
	}

	return TRUE;
}

/*
 *  Get the relevant page directory pointer from a task structure.
 */
static ulong
s390x_get_task_pgd(ulong task)
{
	return (error(FATAL, "s390x_get_task_pgd: TBD\n"));
}

/*
 *  Translate a PTE, returning TRUE if the page is present.
 *  If a physaddr pointer is passed in, don't print anything.
 */
static int
s390x_translate_pte(ulong pte, void *physaddr, ulonglong unused)
{
	char *arglist[MAXARGS];
	char buf[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char ptebuf[BUFSIZE];
	int c,len1,len2,len3;

	if(S390X_PTE_INVALID(pte)){
		fprintf(fp,"PTE is invalid\n");
		return FALSE;
	}

	if(physaddr)
		*((ulong *)physaddr) = pte & S390X_PAGE_BASE_MASK;

	if(!s390x_pte_present(pte)){
		swap_location(pte, buf);
		if ((c = parse_line(buf, arglist)) != 3)
			error(FATAL, "cannot determine swap location\n");

		sprintf(ptebuf, "%lx", pte);
		len1 = MAX(strlen(ptebuf), strlen("PTE"));
		len2 = MAX(strlen(arglist[0]), strlen("SWAP"));
		len3 = MAX(strlen(arglist[2]), strlen("OFFSET"));

		fprintf(fp, "%s  %s  %s\n",
			mkstring(ptebuf, len1, CENTER|LJUST, "PTE"),
			mkstring(buf2, len2, CENTER|LJUST, "SWAP"),
			mkstring(buf3, len3, CENTER|LJUST, "OFFSET"));

		sprintf(ptebuf, "%lx", pte);
		strcpy(buf2, arglist[0]);
		strcpy(buf3, arglist[2]);
		fprintf(fp, "%s  %s  %s\n",
			mkstring(ptebuf, len1, CENTER|RJUST, NULL),
			mkstring(buf2, len2, CENTER|RJUST, NULL),
			mkstring(buf3, len3, CENTER|RJUST, NULL));
		return FALSE;
	}
	fprintf(fp,"PTE      PHYSICAL  FLAGS\n");
	fprintf(fp,"%08lx %08llx",pte, pte & S390X_PAGE_BASE_MASK);
	fprintf(fp,"  (");
	if(pte & S390X_PAGE_INVALID)
		fprintf(fp,"INVALID ");
	if(pte & S390X_PAGE_RO)
		fprintf(fp,"PROTECTION");
	fprintf(fp,")");
	return TRUE;
}

/*
 *  Look for likely exception frames in a stack.
 */
static int 
s390x_eframe_search(struct bt_info *bt)
{
	if(bt->flags & BT_EFRAME_SEARCH2)
		return (error(FATAL, 
		    "Option '-E' is not implemented for this architecture\n"));
	else
		return (error(FATAL, 
		    "Option '-e' is not implemented for this architecture\n"));
}

#ifdef DEPRECATED
/*
 * returns cpu number of task
 */ 
static int 
s390x_cpu_of_task(unsigned long task)
{
	unsigned int cpu;

	if(VALID_MEMBER(task_struct_processor)){
		/* linux 2.4 */
		readmem(task + OFFSET(task_struct_processor),KVADDR,
                        &cpu, sizeof(cpu), "task_struct_processor", 
			FAULT_ON_ERROR);		
	} else {
		/* linux 2.6 */
		char thread_info[8192];
		unsigned long thread_info_addr;
		readmem(task + OFFSET(task_struct_thread_info),KVADDR,
                        &thread_info_addr, sizeof(thread_info_addr),
                        "thread info addr", FAULT_ON_ERROR);
		readmem(thread_info_addr,KVADDR,thread_info,sizeof(thread_info),
			"thread info", FAULT_ON_ERROR);
		cpu = *((int*) &thread_info[OFFSET(thread_info_cpu)]);
	}
	return cpu;
}
#endif

/*
 * returns true, if task of bt currently is executed by a cpu
 */ 
static int 
s390x_has_cpu(struct bt_info *bt)
{
	int cpu = bt->tc->processor;

	if (is_task_active(bt->task) && (kt->cpu_flags[cpu] & ONLINE_MAP))
		return TRUE;
	else
		return FALSE;
}

/*
 * read lowcore for cpu
 */
static void
s390x_get_lowcore(struct bt_info *bt, char* lowcore)
{
	unsigned long lowcore_array,lowcore_ptr;
	struct s390x_cpu *s390x_cpu;
	int cpu = bt->tc->processor;

	lowcore_array = symbol_value("lowcore_ptr");
	readmem(lowcore_array + cpu * S390X_WORD_SIZE,KVADDR,
		&lowcore_ptr, sizeof(long), "lowcore_ptr", FAULT_ON_ERROR);
	readmem(lowcore_ptr, KVADDR, lowcore, LOWCORE_SIZE, "lowcore", 
		FAULT_ON_ERROR);

	if (!s390x_cpu_vec)
		return;

	/* Copy register information to defined places in lowcore */
	s390x_cpu = s390x_cpu_get(bt);

	memcpy(lowcore + 4864, &s390x_cpu->psw, sizeof(s390x_cpu->psw));
	memcpy(lowcore + 4736, &s390x_cpu->gprs, sizeof(s390x_cpu->gprs));
	memcpy(lowcore + 4928, &s390x_cpu->acrs, sizeof(s390x_cpu->acrs));

	memcpy(lowcore + 4892, &s390x_cpu->fpc, sizeof(s390x_cpu->fpc));
	memcpy(lowcore + 4608, &s390x_cpu->fprs, sizeof(s390x_cpu->fprs));

	memcpy(lowcore + 4888, &s390x_cpu->prefix, sizeof(s390x_cpu->prefix));
	memcpy(lowcore + 4992, &s390x_cpu->ctrs, sizeof(s390x_cpu->ctrs));

	memcpy(lowcore + 4900, &s390x_cpu->todpreg, sizeof(s390x_cpu->todpreg));
	memcpy(lowcore + 4904, &s390x_cpu->timer, sizeof(s390x_cpu->timer));
	memcpy(lowcore + 4912, &s390x_cpu->todcmp, sizeof(s390x_cpu->todcmp));
}

/*
 * Copy VX registers out of s390x cpu
 */
static void vx_copy(void *buf, struct s390x_cpu *s390x_cpu)
{
	char *_buf = buf;
	int i;

	for (i = 0; i < 16; i++) {
		memcpy(&_buf[i * 16], &s390x_cpu->fprs[i], 8);
		memcpy(&_buf[i * 16 + 8], &s390x_cpu->vxrs_low[i], 8);
	}
	memcpy(&_buf[16 * 16], &s390x_cpu->vxrs_high[0], 16 * 16);
}

/*
 * Check if VX registers are available
 */
static int has_vx_regs(char *lowcore)
{
	unsigned long addr = *((uint64_t *)(lowcore + 0x11b0));

	if (addr == 0 || addr % 1024)
		return 0;
	return 1;
}

/*
 * Print vector registers for cpu
 */
static void
s390x_print_vx_sa(struct bt_info *bt, char *lc)
{
	char vx_sa[VX_SA_SIZE];
	uint64_t addr;

	if (!(bt->flags & BT_SHOW_ALL_REGS))
		return;
	if (!has_vx_regs(lc))
		return;
	if (!s390x_cpu_vec) {
		/* Pointer to save area */
		addr = *((uint64_t *)(lc + 0x11b0));
		readmem(addr, KVADDR, vx_sa, sizeof(vx_sa), "vx_sa",
			FAULT_ON_ERROR);
	} else {
		/* Get data from s390x cpu */
		vx_copy(vx_sa, s390x_cpu_get(bt));
	}
	fprintf(fp, "  -vector registers:\n");
	print_hex_buf(vx_sa, sizeof(vx_sa), 2, "     ");
}

/*
 * Get stack address for interrupt stack using the pcpu array
 */
static unsigned long get_int_stack_pcpu(char *stack_name, int cpu)
{
	unsigned long addr;

	addr = symbol_value("pcpu_devices") +
		cpu * STRUCT_SIZE("pcpu") + MEMBER_OFFSET("pcpu", stack_name);
	return readmem_ul(addr) + INT_STACK_SIZE;
}

/*
 * Get stack address for interrupt stack using the lowcore
 */
static unsigned long get_int_stack_lc(char *stack_name, char *lc)
{
	if (!MEMBER_EXISTS(lc_struct, stack_name))
		return 0;
	return roundup(ULONG(lc + MEMBER_OFFSET(lc_struct, stack_name)),
			     PAGESIZE());
}

/*
 * Read interrupt stack (either "async_stack" or "panic_stack");
 */
static void get_int_stack(char *stack_name, int cpu, char *lc,
			  unsigned long *start, unsigned long *end)
{
	unsigned long stack_addr;

	*start = *end = 0;
	if (strcmp(stack_name, "restart_stack") == 0) {
		stack_addr = symbol_value("restart_stack");
		stack_addr = readmem_ul(stack_addr);
	} else {
		if (symbol_exists("pcpu_devices") && MEMBER_EXISTS("pcpu", stack_name))
			stack_addr = get_int_stack_pcpu(stack_name, cpu);
		else
			stack_addr = get_int_stack_lc(stack_name, lc);
	}
	if (stack_addr == 0)
		return;
	*start = stack_addr - INT_STACK_SIZE;
	*end = stack_addr;
}

/*
 * Print hex data
 */
static void print_hex(unsigned long addr, int len, int cols)
{
	int j, first = 1;

	for (j = 0; j < len; j += 8) {
		if (j % (cols * 8) == 0) {
			if (!first)
				fprintf(fp, "\n");
			else
				first = 0;
			fprintf(fp, "    %016lx: ", addr + j);
		}
		fprintf(fp, " %016lx", readmem_ul(addr + j));
	}
	if (len)
		fprintf(fp, "\n");
}

/*
 * Print hexdump of stack frame data
 */
static void print_frame_data(unsigned long sp, unsigned long high)
{
	unsigned long next_sp, len = high - sp;

	next_sp = readmem_ul(sp + MEMBER_OFFSET("stack_frame", "back_chain"));
	if (next_sp == 0)
		len = MIN(len, SIZE(s390_stack_frame) + STRUCT_SIZE("pt_regs"));
	else
		len = MIN(len, next_sp - sp);
	print_hex(sp, len, 2);
}

/*
 * Do reference check and set flags
 */
static int bt_reference_check(struct bt_info *bt, unsigned long addr)
{
	if (!BT_REFERENCE_CHECK(bt))
		return 0;

	if (bt->ref->cmdflags & BT_REF_HEXVAL) {
		if (addr == bt->ref->hexval)
			bt->ref->cmdflags |= BT_REF_FOUND;
	} else {
		if (STREQ(closest_symbol(addr), bt->ref->str))
			bt->ref->cmdflags |= BT_REF_FOUND;
	}
	return 1;
}

/*
 * Print stack frame
 */
static void print_frame(struct bt_info *bt, int cnt, unsigned long sp,
			unsigned long r14)
{
	struct load_module *lm;
	char *sym;
	ulong offset;
	struct syment *symp;
	char *name_plus_offset;
	char buf[BUFSIZE];

	if (bt_reference_check(bt, r14))
		return;
	fprintf(fp, "%s#%d [%08lx] ", cnt < 10 ? " " : "", cnt, sp);
	sym = closest_symbol(r14);
	name_plus_offset = NULL;
	if (bt->flags & BT_SYMBOL_OFFSET) {
		symp = value_search(r14, &offset);
		if (symp && offset)
			name_plus_offset = value_to_symstr(r14, buf, bt->radix);
	}
	fprintf(fp, "%s at %lx", name_plus_offset ? name_plus_offset : sym, r14);
	if (module_symbol(r14, NULL, &lm, NULL, 0))
		fprintf(fp, " [%s]", lm->mod_name);
	fprintf(fp, "\n");
	if (bt->flags & BT_LINE_NUMBERS)
		s390x_dump_line_number(r14);
}

/*
 * Print pt_regs structure
 */
static void print_ptregs(struct bt_info *bt, unsigned long sp)
{
	unsigned long addr, psw_flags, psw_addr, offs;
	struct load_module *lm;
	char *sym;
	int i;

	addr = sp + MEMBER_OFFSET("pt_regs", "psw");
	psw_flags = readmem_ul(addr);
	psw_addr = readmem_ul(addr + sizeof(long));
	if (bt_reference_check(bt, psw_addr))
		return;

	fprintf(fp, " PSW:  %016lx %016lx ", psw_flags, psw_addr);
	if (psw_flags & S390X_PSW_MASK_PSTATE) {
		fprintf(fp, "(user space)\n");
	} else {
		sym = closest_symbol(psw_addr);
		offs = psw_addr - closest_symbol_value(psw_addr);
		if (module_symbol(psw_addr, NULL, &lm, NULL, 0))
			fprintf(fp, "(%s+%ld [%s])\n", sym, offs, lm->mod_name);
		else
			fprintf(fp, "(%s+%ld)\n", sym, offs);
	}

	addr = sp + MEMBER_OFFSET("pt_regs", "gprs");
	for (i = 0; i < 16; i++) {
		if (i != 0 && i % 4 == 0)
			fprintf(fp, "\n");
		if (i % 4 == 0) {
			if (i == 0)
				fprintf(fp, " GPRS: ");
			else
				fprintf(fp, "       ");
		}
		fprintf(fp, "%016lx ", readmem_ul(addr + i * sizeof(long)));
	}
	fprintf(fp, "\n");
}


/*
 * Print back trace for one stack
 */
static unsigned long show_trace(struct bt_info *bt, int cnt, unsigned long sp,
				unsigned long low, unsigned long high)
{
	unsigned long reg; 
	unsigned long psw_addr ATTRIBUTE_UNUSED;

	while (1) {
		if (sp < low || sp > high - SIZE(s390_stack_frame))
			return sp;
		reg = readmem_ul(sp + OFFSET(s390_stack_frame_r14));
		if (!s390x_has_cpu(bt))
			print_frame(bt, cnt++, sp, reg);
		if (bt->flags & BT_FULL)
			print_frame_data(sp, high);
		/* Follow the backchain. */
		while (1) {
			low = sp;
			sp = readmem_ul(sp +
					OFFSET(s390_stack_frame_back_chain));
			if (!sp) {
				sp = low;
				break;
			}
			if (sp <= low || sp > high - SIZE(s390_stack_frame))
				return sp;
			reg = readmem_ul(sp + OFFSET(s390_stack_frame_r14));
			print_frame(bt, cnt++, sp, reg);
			if (bt->flags & BT_FULL)
				print_frame_data(sp, high);
		}
		/* Zero backchain detected, check for interrupt frame. */
		sp += SIZE(s390_stack_frame);
		if (sp <= low || sp > high - STRUCT_SIZE("pt_regs"))
			return sp;
		/* Check for user PSW */
		reg = readmem_ul(sp + MEMBER_OFFSET("pt_regs", "psw"));
		if (reg & S390X_PSW_MASK_PSTATE) {
			print_ptregs(bt, sp);
			return sp;
		}
		/* Get new backchain from r15 */
		reg = readmem_ul(sp + MEMBER_OFFSET("pt_regs", "gprs") +
				 15 * sizeof(long));
		/* Get address of interrupted function */
		psw_addr = readmem_ul(sp + MEMBER_OFFSET("pt_regs", "psw") +
				      sizeof(long));
		/* Check for loop (kernel_thread_starter) of second zero bc */
		if (low == reg || reg == 0)
			return reg;
		print_ptregs(bt, sp);
		low = sp;
		sp = reg;
		cnt = 0;
	}
}

/*
 * Unroll a kernel stack
 */
static void s390x_back_trace_cmd(struct bt_info *bt)
{
	unsigned long low, high, sp = bt->stkptr;
	int cpu = bt->tc->processor, cnt = 0;
	char lowcore[LOWCORE_SIZE];
	unsigned long psw_flags;

	if (bt->hp && bt->hp->eip) {
		error(WARNING,
	        "instruction pointer argument ignored on this architecture!\n");
	}
	if (is_task_active(bt->task) && !(kt->cpu_flags[cpu] & ONLINE_MAP)) {
		fprintf(fp, " CPU offline\n");
		return;
	}

	/*
	 * Print lowcore and print interrupt stacks when task has cpu
	 */
	if (s390x_has_cpu(bt)) {
		s390x_get_lowcore(bt, lowcore);
		psw_flags = ULONG(lowcore + OFFSET(s390_lowcore_psw_save_area));

		if (psw_flags & S390X_PSW_MASK_PSTATE) {
			fprintf(fp,"Task runs in userspace\n");
			s390x_print_lowcore(lowcore,bt,0);
			s390x_print_vx_sa(bt, lowcore);
			return;
		}
		s390x_print_lowcore(lowcore,bt,1);
		s390x_print_vx_sa(bt, lowcore);
		fprintf(fp,"\n");
		if (symbol_exists("restart_stack")) {
			get_int_stack("restart_stack",
				      cpu, lowcore, &low, &high);
			sp = show_trace(bt, cnt, sp, low, high);
		}
		get_int_stack("panic_stack", cpu, lowcore, &low, &high);
		sp = show_trace(bt, cnt, sp, low, high);
		get_int_stack("async_stack", cpu, lowcore, &low, &high);
		sp = show_trace(bt, cnt, sp, low, high);
	}
	/*
	 * Print task stack
	 */
	if (THIS_KERNEL_VERSION >= LINUX(2, 6, 0)) {
		low = task_to_stackbase(bt->task);
	} else {
		low = bt->task;
	}
	high = low + KERNEL_STACK_SIZE;
	sp = show_trace(bt, cnt, sp, low, high);
}

/*
 * print lowcore info (psw and all registers)
 */
static void
s390x_print_lowcore(char* lc, struct bt_info *bt,int show_symbols)
{
	char* ptr;
	unsigned long tmp[4];

	ptr = lc + OFFSET(s390_lowcore_psw_save_area);
	tmp[0]=ULONG(ptr);
	tmp[1]=ULONG(ptr + S390X_WORD_SIZE);

	if(BT_REFERENCE_CHECK(bt)){
		if(bt->ref->cmdflags & BT_REF_HEXVAL){
			if(tmp[1] == bt->ref->hexval)
				bt->ref->cmdflags |= BT_REF_FOUND;
		} else {
			if(STREQ(closest_symbol(tmp[1]),bt->ref->str))
				bt->ref->cmdflags |= BT_REF_FOUND;
		}
		return;
	}
	fprintf(fp," LOWCORE INFO:\n");
	fprintf(fp,"  -psw      : %#018lx %#018lx\n", tmp[0], tmp[1]);
	if(show_symbols){
		fprintf(fp,"  -function : %s at %lx\n", 
			closest_symbol(tmp[1]), tmp[1]);
		if (bt->flags & BT_LINE_NUMBERS)
			s390x_dump_line_number(tmp[1]);
	}
	ptr = lc + MEMBER_OFFSET(lc_struct, "prefixreg_save_area");
	tmp[0] = UINT(ptr);
	fprintf(fp,"  -prefix   : %#010lx\n", tmp[0]);
	
	ptr = lc + MEMBER_OFFSET(lc_struct, "cpu_timer_save_area");
	tmp[0]=ULONG(ptr);
	fprintf(fp,"  -cpu timer: %#018lx\n", tmp[0]);

	ptr = lc + MEMBER_OFFSET(lc_struct, "clock_comp_save_area");
	/*
	 * Shift clock comparator by 8 because we got bit positions 0-55
	 * in byte 1 to 8. The first byte is always zero.
	 */
	tmp[0]=ULONG(ptr) << 8;
	fprintf(fp,"  -clock cmp: %#018lx\n", tmp[0]);

	fprintf(fp,"  -general registers:\n");
	ptr = lc + MEMBER_OFFSET(lc_struct, "gpregs_save_area");
	tmp[0]=ULONG(ptr);
	tmp[1]=ULONG(ptr + S390X_WORD_SIZE);
	tmp[2]=ULONG(ptr + 2 * S390X_WORD_SIZE);
	tmp[3]=ULONG(ptr + 3 * S390X_WORD_SIZE);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[0],tmp[1]);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[2],tmp[3]);
	tmp[0]=ULONG(ptr + 4 * S390X_WORD_SIZE);
	tmp[1]=ULONG(ptr + 5 * S390X_WORD_SIZE);
	tmp[2]=ULONG(ptr + 6 * S390X_WORD_SIZE);
	tmp[3]=ULONG(ptr + 7 * S390X_WORD_SIZE);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[0],tmp[1]);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[2],tmp[3]);
	tmp[0]=ULONG(ptr + 8 * S390X_WORD_SIZE);
	tmp[1]=ULONG(ptr + 9 * S390X_WORD_SIZE);
	tmp[2]=ULONG(ptr + 10* S390X_WORD_SIZE);
	tmp[3]=ULONG(ptr + 11* S390X_WORD_SIZE);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[0],tmp[1]);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[2],tmp[3]);
	tmp[0]=ULONG(ptr + 12* S390X_WORD_SIZE);
	tmp[1]=ULONG(ptr + 13* S390X_WORD_SIZE);
	tmp[2]=ULONG(ptr + 14* S390X_WORD_SIZE);
	tmp[3]=ULONG(ptr + 15* S390X_WORD_SIZE);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[0],tmp[1]);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[2],tmp[3]);

	fprintf(fp,"  -access registers:\n");
	ptr = lc + MEMBER_OFFSET(lc_struct, "access_regs_save_area");
	tmp[0]=UINT(ptr);
	tmp[1]=UINT(ptr + 4);
	tmp[2]=UINT(ptr + 2 * 4);
	tmp[3]=UINT(ptr + 3 * 4);
	fprintf(fp,"     %#010lx %#010lx %#010lx %#010lx\n", 
		tmp[0], tmp[1], tmp[2], tmp[3]);
	tmp[0]=UINT(ptr + 4 * 4);
	tmp[1]=UINT(ptr + 5 * 4);
	tmp[2]=UINT(ptr + 6 * 4);
	tmp[3]=UINT(ptr + 7 * 4);
	fprintf(fp,"     %#010lx %#010lx %#010lx %#010lx\n", 
		tmp[0], tmp[1], tmp[2], tmp[3]);
	tmp[0]=UINT(ptr + 8 * 4);
	tmp[1]=UINT(ptr + 9 * 4);
	tmp[2]=UINT(ptr + 10 * 4);
	tmp[3]=UINT(ptr + 11 * 4);
	fprintf(fp,"     %#010lx %#010lx %#010lx %#010lx\n", 
		tmp[0], tmp[1], tmp[2], tmp[3]);
	tmp[0]=UINT(ptr + 12 * 4);
	tmp[1]=UINT(ptr + 13 * 4);
	tmp[2]=UINT(ptr + 14 * 4);
	tmp[3]=UINT(ptr + 15 * 4);
	fprintf(fp,"     %#010lx %#010lx %#010lx %#010lx\n", 
		tmp[0], tmp[1], tmp[2], tmp[3]);

	fprintf(fp,"  -control registers:\n");
	ptr = lc + MEMBER_OFFSET(lc_struct, "cregs_save_area");
	tmp[0]=ULONG(ptr);
	tmp[1]=ULONG(ptr + S390X_WORD_SIZE);
	tmp[2]=ULONG(ptr + 2 * S390X_WORD_SIZE);
	tmp[3]=ULONG(ptr + 3 * S390X_WORD_SIZE);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[0],tmp[1]);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[2],tmp[3]);
	tmp[0]=ULONG(ptr + 4 * S390X_WORD_SIZE);
	tmp[1]=ULONG(ptr + 5 * S390X_WORD_SIZE);
	tmp[2]=ULONG(ptr + 6 * S390X_WORD_SIZE);
	tmp[3]=ULONG(ptr + 7 * S390X_WORD_SIZE);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[0],tmp[1]);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[2],tmp[3]);
	tmp[0]=ULONG(ptr + 8 * S390X_WORD_SIZE);
	tmp[1]=ULONG(ptr + 9 * S390X_WORD_SIZE);
	tmp[2]=ULONG(ptr + 10 * S390X_WORD_SIZE);
	tmp[3]=ULONG(ptr + 11 * S390X_WORD_SIZE);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[0],tmp[1]);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[2],tmp[3]);
	tmp[0]=ULONG(ptr + 12 * S390X_WORD_SIZE);
	tmp[1]=ULONG(ptr + 13 * S390X_WORD_SIZE);
	tmp[2]=ULONG(ptr + 14 * S390X_WORD_SIZE);
	tmp[3]=ULONG(ptr + 15 * S390X_WORD_SIZE);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[0],tmp[1]);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[2],tmp[3]);

	ptr = lc + MEMBER_OFFSET(lc_struct, "floating_pt_save_area");
	fprintf(fp,"  -floating point registers:\n");
	tmp[0]=ULONG(ptr);
	tmp[1]=ULONG(ptr +  S390X_WORD_SIZE);
	tmp[2]=ULONG(ptr + 2 * S390X_WORD_SIZE);
	tmp[3]=ULONG(ptr + 3 * S390X_WORD_SIZE);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[0],tmp[1]);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[2],tmp[3]);
	tmp[0]=ULONG(ptr + 4 * S390X_WORD_SIZE);
	tmp[1]=ULONG(ptr + 5 * S390X_WORD_SIZE);
	tmp[2]=ULONG(ptr + 6 * S390X_WORD_SIZE);
	tmp[3]=ULONG(ptr + 7 * S390X_WORD_SIZE);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[0],tmp[1]);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[2],tmp[3]);
	tmp[0]=ULONG(ptr + 8 * S390X_WORD_SIZE);
	tmp[1]=ULONG(ptr + 9 * S390X_WORD_SIZE);
	tmp[2]=ULONG(ptr + 10 * S390X_WORD_SIZE);
	tmp[3]=ULONG(ptr + 11 * S390X_WORD_SIZE);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[0],tmp[1]);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[2],tmp[3]);
	tmp[0]=ULONG(ptr + 12 * S390X_WORD_SIZE);
	tmp[1]=ULONG(ptr + 13 * S390X_WORD_SIZE);
	tmp[2]=ULONG(ptr + 14 * S390X_WORD_SIZE);
	tmp[3]=ULONG(ptr + 15 * S390X_WORD_SIZE);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[0],tmp[1]);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[2],tmp[3]);
}

/*
 *  Get a stack frame combination of pc and ra from the most relevent spot.
 */
static void
s390x_get_stack_frame(struct bt_info *bt, ulong *eip, ulong *esp)
{
	unsigned long ksp, r14;
	int r14_offset;
	char lowcore[LOWCORE_SIZE];

	if(s390x_has_cpu(bt))
		s390x_get_lowcore(bt, lowcore);

	/* get the stack pointer */
	if(esp){
		if (!LIVE() && s390x_has_cpu(bt)) {
			ksp = ULONG(lowcore + MEMBER_OFFSET(lc_struct,
				"gpregs_save_area") + (15 * S390X_WORD_SIZE));
		} else {
			readmem(bt->task + OFFSET(task_struct_thread_ksp), 
				KVADDR, &ksp, sizeof(void *),
				"thread_struct ksp", FAULT_ON_ERROR);
		}
		*esp = ksp;
	} else {
		/* for 'bt -S' */
		ksp=bt->hp->esp;
	}

	/* get the instruction address */
	if(!eip)
		return;

	if(s390x_has_cpu(bt) && esp){
		*eip = ULONG(lowcore + OFFSET(s390_lowcore_psw_save_area) +
			S390X_WORD_SIZE);
	} else {
		if(!STRUCT_EXISTS("stack_frame")){
			r14_offset = 112;
		} else {
			r14_offset = MEMBER_OFFSET("stack_frame","gprs") + 
						   8 * S390X_WORD_SIZE;
		}
		readmem(ksp + r14_offset,KVADDR,&r14,sizeof(void*),"eip",
			FAULT_ON_ERROR);
		*eip=r14; 
	}
}

/*
 *  Filter disassembly output if the output radix is not gdb's default 10
 */
static int 
s390x_dis_filter(ulong vaddr, char *inbuf, unsigned int output_radix)
{
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char *colon, *p1;
	int argc;
	char *argv[MAXARGS];
	ulong value;

	if (!inbuf) 
		return TRUE;
/*
 *  For some reason gdb can go off into the weeds translating text addresses,
 *  so this routine both fixes the references as well as imposing the current 
 *  output radix on the translations.
 */
	console("IN: %s", inbuf);

	colon = strstr(inbuf, ":");

	if (colon) {
		sprintf(buf1, "0x%lx <%s>", vaddr,
			value_to_symstr(vaddr, buf2, output_radix));
		sprintf(buf2, "%s%s", buf1, colon);
		strcpy(inbuf, buf2);
	}

	strcpy(buf1, inbuf);
	argc = parse_line(buf1, argv);

	if ((FIRSTCHAR(argv[argc-1]) == '<') && 
	    (LASTCHAR(argv[argc-1]) == '>')) {
		p1 = rindex(inbuf, '<');
		while ((p1 > inbuf) && 
		    !(STRNEQ(p1, " 0x") || STRNEQ(p1, "\t0x") || STRNEQ(p1, ",0x"))) 
			p1--;

		if (!(STRNEQ(p1, " 0x") || STRNEQ(p1, "\t0x") || STRNEQ(p1, ",0x"))) 
			return FALSE;
		p1++;

		if (!extract_hex(p1, &value, NULLCHAR, TRUE))
			return FALSE;

		sprintf(buf1, "0x%lx <%s>\n", value,
			value_to_symstr(value, buf2, output_radix));

		sprintf(p1, "%s", buf1);
	}

	console("    %s", inbuf);

	return TRUE;
}

/*
 *   Override smp_num_cpus if possible and necessary.
 */
int
s390x_get_smp_cpus(void)
{
	return MAX(get_cpus_online(), get_highest_cpu_online()+1);
}

/*
 *  Machine dependent command.
 */
void
s390x_cmd_mach(void)
{
	int c;

	while ((c = getopt(argcnt, args, "cm")) != EOF) {
		switch(c)
		{
		case 'c':
			fprintf(fp,"'-c' option is not implemented on this architecture\n");
			return;
		case 'm':
			fprintf(fp,"'-m' option is not implemented on this architecture\n");
			return;
		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	s390x_display_machine_stats();
}

/*
 *  "mach" command output.
 */
static void
s390x_display_machine_stats(void)
{
	struct new_utsname *uts;
	char buf[BUFSIZE];
	ulong mhz;

	uts = &kt->utsname;

	fprintf(fp, "       MACHINE TYPE: %s\n", uts->machine);
	fprintf(fp, "        MEMORY SIZE: %s\n", get_memory_size(buf));
	fprintf(fp, "               CPUS: %d\n", kt->cpus);
	fprintf(fp, "    PROCESSOR SPEED: ");
	if ((mhz = machdep->processor_speed()))
		fprintf(fp, "%ld Mhz\n", mhz);
	else
		fprintf(fp, "(unknown)\n");
	fprintf(fp, "                 HZ: %d\n", machdep->hz);
	fprintf(fp, "          PAGE SIZE: %d\n", PAGESIZE());
	// fprintf(fp, "      L1 CACHE SIZE: %d\n", l1_cache_size());
	fprintf(fp, "KERNEL VIRTUAL BASE: %lx\n", machdep->kvbase);
	fprintf(fp, "KERNEL VMALLOC BASE: %lx\n", vt->vmalloc_start);
	fprintf(fp, "  KERNEL STACK SIZE: %ld\n", STACKSIZE());

}

static const char *hook_files[] = {
	"arch/s390x/kernel/entry.S",
	"arch/s390x/kernel/head.S"
};

#define ENTRY_S      ((char **)&hook_files[0])
#define HEAD_S       ((char **)&hook_files[1])

static struct line_number_hook s390x_line_number_hooks[] = {
       {"startup",HEAD_S},
       {"_stext",HEAD_S},
       {"_pstart",HEAD_S},
       {"system_call",ENTRY_S},
       {"sysc_do_svc",ENTRY_S},
       {"sysc_do_restart",ENTRY_S},
       {"sysc_return",ENTRY_S},
       {"sysc_sigpending",ENTRY_S},
       {"sysc_restart",ENTRY_S},
       {"sysc_singlestep",ENTRY_S},
       {"sysc_tracesys",ENTRY_S},
       {"ret_from_fork",ENTRY_S},
       {"pgm_check_handler",ENTRY_S},
       {"io_int_handler",ENTRY_S},
       {"io_return",ENTRY_S},
       {"ext_int_handler",ENTRY_S},
       {"mcck_int_handler",ENTRY_S},
       {"mcck_return",ENTRY_S},
       {"restart_int_handler",ENTRY_S},
       {NULL, NULL}    /* list must be NULL-terminated */
};

static void
s390x_dump_line_number(ulong callpc)
{
	int retries;
	char buf[BUFSIZE], *p;

	retries = 0;
try_closest:
	get_line_number(callpc, buf, FALSE);

	if (strlen(buf)) {
		if (retries) {
			p = strstr(buf, ": ");
			if (p)
				*p = NULLCHAR;
		}
		fprintf(fp, "    %s\n", buf);
	} else {
		if (retries) {
			fprintf(fp, GDB_PATCHED() ?
			  "" : "    (cannot determine file and line number)\n");
		} else {
			retries++;
			callpc = closest_symbol_value(callpc);
			goto try_closest;
		}
	}
}

static int 
s390x_get_kvaddr_ranges(struct vaddr_range *vrp)
{
	int cnt;
	physaddr_t phys1, phys2;
	ulong pp1, pp2;

	cnt = 0;

	vrp[cnt].type = KVADDR_UNITY_MAP;
	vrp[cnt].start = machdep->kvbase;
	vrp[cnt++].end = vt->high_memory;

	vrp[cnt].type = KVADDR_VMALLOC;
	vrp[cnt].start = first_vmalloc_address();
	vrp[cnt++].end = last_vmalloc_address();

	phys1 = (physaddr_t)(0);
	phys2 = (physaddr_t)VTOP(vt->high_memory - PAGESIZE());
	if (phys_to_page(phys1, &pp1) && 
	    phys_to_page(phys2, &pp2) &&
	    (pp1 >= vrp[cnt-1].end)) {
		vrp[cnt].type = KVADDR_VMEMMAP;
		vrp[cnt].start = pp1;
		vrp[cnt++].end = pp2;
	}

	return cnt;
}
#endif  /* S390X */
