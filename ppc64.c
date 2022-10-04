/* ppc64.c -- core analysis suite
 *
 * Copyright (C) 2004-2015,2018 David Anderson
 * Copyright (C) 2004-2015,2018 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2004, 2006 Haren Myneni, IBM Corporation
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
#ifdef PPC64

#include "defs.h"
#include <endian.h>
#include <ctype.h>

static int ppc64_kvtop(struct task_context *, ulong, physaddr_t *, int);
static int ppc64_uvtop(struct task_context *, ulong, physaddr_t *, int);
static ulong ppc64_vmalloc_start(void);
static int ppc64_vmemmap_to_phys(ulong, physaddr_t *, int);
static int ppc64_is_task_addr(ulong);
static int ppc64_verify_symbol(const char *, ulong, char);
static ulong ppc64_get_task_pgd(ulong);
static int ppc64_translate_pte(ulong, void *, ulonglong);
static ulong ppc64_processor_speed(void);
static int ppc64_eframe_search(struct bt_info *);
static void ppc64_back_trace_cmd(struct bt_info *);
static void ppc64_back_trace(struct gnu_request *, struct bt_info *);
static void get_ppc64_frame(struct bt_info *, ulong *, ulong *);
static void ppc64_print_stack_entry(int,struct gnu_request *, 
	ulong, ulong, struct bt_info *);
static void ppc64_dump_irq(int);
static ulong ppc64_get_sp(ulong);
static void ppc64_get_stack_frame(struct bt_info *, ulong *, ulong *);
static int ppc64_dis_filter(ulong, char *, unsigned int);
static void ppc64_cmd_mach(void);
static int ppc64_get_smp_cpus(void);
static void ppc64_display_machine_stats(void);
static void ppc64_dump_line_number(ulong);
static struct line_number_hook ppc64_line_number_hooks[];
static ulong ppc64_get_stackbase(ulong);
static ulong ppc64_get_stacktop(ulong);
void ppc64_compiler_warning_stub(void);
static ulong ppc64_in_irqstack(ulong);
static enum emergency_stack_type ppc64_in_emergency_stack(int cpu, ulong addr,
							  bool verbose);
static void ppc64_set_bt_emergency_stack(enum emergency_stack_type type,
					 struct bt_info *bt);
static char * ppc64_check_eframe(struct ppc64_pt_regs *);
static void ppc64_print_eframe(char *, struct ppc64_pt_regs *, 
		struct bt_info *);
static void parse_cmdline_args(void);
static int ppc64_paca_percpu_offset_init(int);
static void ppc64_init_cpu_info(void);
static int ppc64_get_cpu_map(void);
static void ppc64_clear_machdep_cache(void);
static void ppc64_init_paca_info(void);
static void ppc64_vmemmap_init(void);
static int ppc64_get_kvaddr_ranges(struct vaddr_range *);
static uint get_ptetype(ulong pte);
static int is_hugepage(ulong pte);
static int is_hugepd(ulong pte);
static ulong hugepage_dir(ulong pte);
static ulong pgd_page_vaddr_l4(ulong pgd);
static ulong pud_page_vaddr_l4(ulong pud);
static ulong pmd_page_vaddr_l4(ulong pmd);
static int is_opal_context(ulong sp, ulong nip);
void opalmsg(void);

static int is_opal_context(ulong sp, ulong nip)
{
	uint64_t opal_start, opal_end;

	if (!(machdep->flags & OPAL_FW))
		return FALSE;

	opal_start = machdep->machspec->opal.base;
	opal_end   = opal_start + machdep->machspec->opal.size;

	if (((sp >= opal_start) && (sp < opal_end)) ||
	    ((nip >= opal_start) && (nip < opal_end)))
		return TRUE;

	return FALSE;
}

static inline int is_hugepage(ulong pte)
{
	if ((machdep->flags & BOOK3E) ||
		(THIS_KERNEL_VERSION < LINUX(3,10,0))) {
		/*
		 * hugepage support via hugepd for book3e and
		 * also kernel v3.9 & below.
		 */
		return 0;

	} else if (THIS_KERNEL_VERSION >= LINUX(4,5,0)) {
		/*
		 * leaf pte for huge page, if _PAGE_PTE is set.
		 */
		return !!(pte & _PAGE_PTE);

	} else { /* BOOK3S, kernel v3.10 - v4.4 */

		/*
		 * leaf pte for huge page, bottom two bits != 00
		 */
		return ((pte & HUGE_PTE_MASK) != 0x0);
	}
}

static inline int is_hugepd(ulong pte)
{
	if ((machdep->flags & BOOK3E) ||
		(THIS_KERNEL_VERSION < LINUX(3,10,0)))
		return ((pte & PD_HUGE) == 0x0);

	else if (THIS_KERNEL_VERSION >= LINUX(4,5,0)) {
		/*
		 * hugepd pointer, if _PAGE_PTE is not set and
		 * hugepd shift mask is set.
		 */
		return (!(pte & _PAGE_PTE) &&
			((pte & HUGEPD_SHIFT_MASK) != 0));

	} else { /* BOOK3S, kernel v3.10 - v4.4 */

		/*
		 * hugepd pointer, bottom two bits == 00 and next 4 bits
		 * indicate size of table
		 */
		return (((pte & HUGE_PTE_MASK) == 0x0) &&
			((pte & HUGEPD_SHIFT_MASK) != 0));
	}
}

static inline uint get_ptetype(ulong pte)
{
	uint pte_type = 0; /* 0: regular entry; 1: huge pte; 2: huge pd */

	if (is_hugepage(pte))
		pte_type = 1;
	else if (!(machdep->flags & RADIX_MMU) &&
	    (PAGESIZE() != PPC64_64K_PAGE_SIZE) && is_hugepd(pte))
		pte_type = 2;

	return pte_type;
}

static inline ulong hugepage_dir(ulong pte)
{
	if ((machdep->flags & BOOK3E) ||
		(THIS_KERNEL_VERSION < LINUX(3,10,0)))
		return (ulong)((pte & ~HUGEPD_SHIFT_MASK) | PD_HUGE);
	else if (machdep->flags & PHYS_ENTRY_L4)
		return PTOV(pte & ~HUGEPD_ADDR_MASK);
	else /* BOOK3S, kernel v3.10 - v4.4 */
		return (ulong)(pte & ~HUGEPD_SHIFT_MASK);
}

static inline ulong pgd_page_vaddr_l4(ulong pgd)
{
	ulong pgd_val;

	pgd_val = (pgd & ~machdep->machspec->pgd_masked_bits);
	if (machdep->flags & PHYS_ENTRY_L4) {
		/*
		 * physical address is stored starting from kernel v4.6
		 */
		pgd_val = PTOV(pgd_val);
	}

	return pgd_val;
}

static inline ulong pud_page_vaddr_l4(ulong pud)
{
	ulong pud_val;

	pud_val = (pud & ~machdep->machspec->pud_masked_bits);
	if (machdep->flags & PHYS_ENTRY_L4) {
		/*
		 * physical address is stored starting from kernel v4.6
		 */
		pud_val = PTOV(pud_val);
	}

	return pud_val;
}

static inline ulong pmd_page_vaddr_l4(ulong pmd)
{
	ulong pmd_val;

	pmd_val = (pmd & ~machdep->machspec->pmd_masked_bits);
	if (machdep->flags & PHYS_ENTRY_L4) {
		/*
		 * physical address is stored starting from kernel v4.6
		 */
		pmd_val = PTOV(pmd_val);
	}

	return pmd_val;
}

static int book3e_is_kvaddr(ulong addr)
{
	return (addr >= BOOK3E_VMBASE);
}


static int book3e_is_vmaddr(ulong addr)
{
	return (addr >= BOOK3E_VMBASE) && (addr < machdep->identity_map_base);
}

static int ppc64_is_vmaddr(ulong addr)
{
	return (vt->vmalloc_start && addr >= vt->vmalloc_start);
}

#define is_RHEL8() (strstr(kt->proc_version, ".el8."))

static int set_ppc64_max_physmem_bits(void)
{
	int dimension;
	char *string;

	if ((string = pc->read_vmcoreinfo("NUMBER(MAX_PHYSMEM_BITS)"))) {
		machdep->max_physmem_bits = atol(string);
		free(string);
		return 0;
	}

	get_array_length("mem_section", &dimension, 0);

	if ((machdep->flags & VMEMMAP) &&
	    (THIS_KERNEL_VERSION >= LINUX(4,20,0)) &&
	    !dimension && (machdep->pagesize == 65536)) {
		/*
		 * SPARSEMEM_VMEMMAP & SPARSEMEM_EXTREME configurations with
		 * 64K pagesize and v4.20 kernel or later.
		 */
		machdep->max_physmem_bits = _MAX_PHYSMEM_BITS_4_20;
	} else if ((machdep->flags & VMEMMAP) &&
	    ((THIS_KERNEL_VERSION >= LINUX(4,19,0)) || is_RHEL8())) {
		/* SPARSEMEM_VMEMMAP & v4.19 kernel or later, or RHEL8 */
		machdep->max_physmem_bits = _MAX_PHYSMEM_BITS_4_19;
	} else if (THIS_KERNEL_VERSION >= LINUX(3,7,0))
		machdep->max_physmem_bits = _MAX_PHYSMEM_BITS_3_7;
	else
		machdep->max_physmem_bits = _MAX_PHYSMEM_BITS;

	return 0;
}

struct machine_specific ppc64_machine_specific = { 
	.hwintrstack = NULL,
	.hwstackbuf = 0,
	.hwstacksize = 0,
	.pte_rpn_shift = PTE_RPN_SHIFT_DEFAULT,
	._page_pte = 0x0UL,
	._page_present = 0x1UL,
	._page_user = 0x2UL,
	._page_rw = 0x4UL,
	._page_guarded = 0x8UL,
	._page_coherent = 0x10UL,
	._page_no_cache = 0x20UL,
	._page_writethru = 0x40UL,
	._page_dirty = 0x80UL,
	._page_accessed = 0x100UL,
	.is_kvaddr = generic_is_kvaddr,
	.is_vmaddr = ppc64_is_vmaddr,
};

struct machine_specific book3e_machine_specific = {
	.hwintrstack = NULL,
	.hwstackbuf = 0,
	.hwstacksize = 0,
	.pte_rpn_shift = PTE_RPN_SHIFT_L4_BOOK3E_64K,
	._page_pte = 0x0UL,
	._page_present = 0x1UL,
	._page_user = 0xCUL,
	._page_rw = 0x30UL,
	._page_guarded = 0x100000UL,
	._page_coherent = 0x200000UL,
	._page_no_cache = 0x400000UL,
	._page_writethru = 0x800000UL,
	._page_dirty = 0x1000UL,
	._page_accessed = 0x40000UL,
	.is_kvaddr = book3e_is_kvaddr,
	.is_vmaddr = book3e_is_vmaddr,
};

#define SKIBOOT_BASE			0x30000000

/*
 *  Do all necessary machine-specific setup here.  This is called several
 *  times during initialization.
 */
void
ppc64_init(int when)
{
	struct machine_specific *ms;

#if defined(__x86_64__)
        if (ACTIVE())
                error(FATAL, "compiled for the PPC64 architecture\n");
#endif
	switch (when)
	{
	case SETUP_ENV:
		machdep->process_elf_notes = process_elf64_notes;
		break;

	case PRE_SYMTAB:
		machdep->machspec = &ppc64_machine_specific;
		machdep->verify_symbol = ppc64_verify_symbol;
		if (pc->flags & KERNEL_DEBUG_QUERY)
			return;
		machdep->stacksize = PPC64_STACK_SIZE;
		machdep->last_pgd_read = 0;
		machdep->last_pud_read = 0;
		machdep->last_pmd_read = 0;
		machdep->last_ptbl_read = 0;
		machdep->verify_paddr = generic_verify_paddr;
		machdep->ptrs_per_pgd = PTRS_PER_PGD;
		machdep->flags |= MACHDEP_BT_TEXT;
                if (machdep->cmdline_args[0])
                        parse_cmdline_args();
		 machdep->clear_machdep_cache = ppc64_clear_machdep_cache;
		break;

	case PRE_GDB:
		/*
                * Recently there were changes made to kexec tools
                * to support 64K page size. With those changes
                * vmcore file obtained from a kernel which supports
                * 64K page size cannot be analyzed using crash on a
                * machine running with kernel supporting 4K page size
                *
                * The following modifications are required in crash
                * tool to be in sync with kexec tools.
                *
                * Look if the following symbol exists. If yes then
                * the dump was taken with a kernel supporting 64k
                * page size. So change the page size accordingly.
                *
                * Also moved the following code block from
                * PRE_SYMTAB case here.
                */
		if (symbol_exists("interrupt_base_book3e")) {
			machdep->machspec = &book3e_machine_specific;
			machdep->flags |= BOOK3E;
			machdep->kvbase = BOOK3E_VMBASE;
		} else
			machdep->kvbase = symbol_value("_stext");

                if (symbol_exists("__hash_page_64K"))
                        machdep->pagesize = PPC64_64K_PAGE_SIZE;
                else
			machdep->pagesize = memory_page_size();
		machdep->pageshift = ffs(machdep->pagesize) - 1;
		machdep->pageoffset = machdep->pagesize - 1;
		machdep->pagemask = ~((ulonglong)machdep->pageoffset);
		if ((machdep->pgd = (char *)malloc(PAGESIZE())) == NULL)
			error(FATAL, "cannot malloc pgd space.");
		if ((machdep->pud = (char *)malloc(PAGESIZE())) == NULL)
			error(FATAL, "cannot malloc pud space.");
		if ((machdep->pmd = (char *)malloc(PAGESIZE())) == NULL)
			error(FATAL, "cannot malloc pmd space.");
		if ((machdep->ptbl = (char *)malloc(PAGESIZE())) == NULL)
			error(FATAL, "cannot malloc ptbl space.");

		machdep->identity_map_base = symbol_value("_stext"); 
                machdep->is_kvaddr = machdep->machspec->is_kvaddr; 
                machdep->is_uvaddr = generic_is_uvaddr;
	        machdep->eframe_search = ppc64_eframe_search;
	        machdep->back_trace = ppc64_back_trace_cmd;
	        machdep->processor_speed = ppc64_processor_speed;
	        machdep->uvtop = ppc64_uvtop;
	        machdep->kvtop = ppc64_kvtop;
	        machdep->get_task_pgd = ppc64_get_task_pgd;
		machdep->get_stack_frame = ppc64_get_stack_frame;
		machdep->get_stackbase = ppc64_get_stackbase;
		machdep->get_stacktop = ppc64_get_stacktop;
		machdep->translate_pte = ppc64_translate_pte;
		machdep->memory_size = generic_memory_size;
		machdep->is_task_addr = ppc64_is_task_addr;
		machdep->dis_filter = ppc64_dis_filter;
		machdep->cmd_mach = ppc64_cmd_mach;
		machdep->get_smp_cpus = ppc64_get_smp_cpus;
		machdep->line_number_hooks = ppc64_line_number_hooks;
		machdep->value_to_symbol = generic_machdep_value_to_symbol;
		machdep->get_kvaddr_ranges = ppc64_get_kvaddr_ranges;
		machdep->init_kernel_pgd = NULL;

		if (symbol_exists("vmemmap_populate")) {
			if (symbol_exists("vmemmap")) {
				readmem(symbol_value("vmemmap"), KVADDR,
					&machdep->machspec->vmemmap_base,
					sizeof(void *), "vmemmap", QUIET|FAULT_ON_ERROR);
			} else
				machdep->machspec->vmemmap_base =
					VMEMMAP_REGION_ID << REGION_SHIFT;

			machdep->flags |= VMEMMAP;
		}

		machdep->get_irq_affinity = generic_get_irq_affinity;
		machdep->show_interrupts = generic_show_interrupts;
		break;

	case POST_GDB:
		ms = machdep->machspec;

		if (!(machdep->flags & BOOK3E)) {
			/*
			 * To determine if the kernel was running on OPAL based platform,
			 * use struct opal, which is populated with relevant values.
			 */
			if (symbol_exists("opal")) {
				get_symbol_data("opal", sizeof(struct ppc64_opal), &(ms->opal));
				if (ms->opal.base == SKIBOOT_BASE)
					machdep->flags |= OPAL_FW;
			}

			/*
			 * On Power ISA 3.0 based server processors, a kernel can
			 * run with radix MMU or standard MMU. Set the flag,
			 * if it is radix MMU.
			 */
			if (symbol_exists("cur_cpu_spec") &&
			    MEMBER_EXISTS("cpu_spec", "mmu_features")) {
				ulong cur_cpu_spec;
				uint mmu_features, offset;

				get_symbol_data("cur_cpu_spec", sizeof(void *), &cur_cpu_spec);
				offset = MEMBER_OFFSET("cpu_spec", "mmu_features");
				readmem(cur_cpu_spec + offset, KVADDR, &mmu_features,
					sizeof(uint), "cpu mmu features", FAULT_ON_ERROR);
				machdep->flags |= (mmu_features & RADIX_MMU);
			}

			/*
			 * Starting with v3.14 we no longer use _PAGE_COHERENT
			 * bit as it is always set on hash64 and on platforms
			 * that cannot always set it, _PAGE_NO_CACHE and
			 * _PAGE_WRITETHRU  can be used to infer it.
			 */
			if (THIS_KERNEL_VERSION >= LINUX(3,14,0))
				ms->_page_coherent = 0x0UL;

			/*
			 * In kernel v4.5, _PAGE_PTE bit is introduced to
			 * distinguish PTEs from pointers.
			 */
			if (THIS_KERNEL_VERSION >= LINUX(4,5,0)) {
				ms->_page_pte = 0x1UL;
				ms->_page_present = 0x2UL;
				ms->_page_user = 0x4UL;
				ms->_page_rw = 0x8UL;
				ms->_page_guarded = 0x10UL;
			}

			/*
			 * Starting with kernel v4.6, to accommodate both
			 * radix and hash MMU modes in a single kernel,
			 * _PAGE_PTE & _PAGE_PRESENT page flags are changed.
			 * Also, page table entries store physical addresses.
			 */
			if (THIS_KERNEL_VERSION >= LINUX(4,6,0)) {
				ms->_page_pte = 0x1UL << 62;
				ms->_page_present = 0x1UL << 63;
				machdep->flags |= PHYS_ENTRY_L4;
			}

			if (THIS_KERNEL_VERSION >= LINUX(4,7,0)) {
				/*
				 * Starting with kernel v4.7 page table entries
				 * are always big endian on BOOK3S. Set this
				 * flag if kernel is not big endian.
				 */
				if (__BYTE_ORDER == __LITTLE_ENDIAN)
					machdep->flags |= SWAP_ENTRY_L4;
			}
		}

		if (!(machdep->flags & (VM_ORIG|VM_4_LEVEL))) {
			if (THIS_KERNEL_VERSION >= LINUX(2,6,14)) {
				machdep->flags |= VM_4_LEVEL;
			} else {
				machdep->flags |= VM_ORIG;
			}
		}
		if (machdep->flags & VM_ORIG) {
			/* pre-2.6.14 layout */
			free(machdep->pud);
			machdep->pud = NULL;
			machdep->ptrs_per_pgd = PTRS_PER_PGD;
		} else {
			/* 2.6.14 layout */
			if (machdep->pagesize == 65536) {
				/* 64K pagesize */
				if (machdep->flags & RADIX_MMU) {
					ms->l1_index_size = PTE_INDEX_SIZE_RADIX_64K;
					ms->l2_index_size = PMD_INDEX_SIZE_RADIX_64K;
					ms->l3_index_size = PUD_INDEX_SIZE_RADIX_64K;
					ms->l4_index_size = PGD_INDEX_SIZE_RADIX_64K;

				} else if (!(machdep->flags & BOOK3E) &&
				    (THIS_KERNEL_VERSION >= LINUX(4,6,0))) {
					ms->l1_index_size = PTE_INDEX_SIZE_L4_64K_3_10;

					if (THIS_KERNEL_VERSION >= LINUX(4,12,0)) {
						ms->l2_index_size = PMD_INDEX_SIZE_L4_64K_4_12;
						if (THIS_KERNEL_VERSION >= LINUX(4,17,0))
							ms->l3_index_size = PUD_INDEX_SIZE_L4_64K_4_17;
						else
							ms->l3_index_size = PUD_INDEX_SIZE_L4_64K_4_12;
						ms->l4_index_size = PGD_INDEX_SIZE_L4_64K_4_12;
					} else {
						ms->l2_index_size = PMD_INDEX_SIZE_L4_64K_4_6;
						ms->l3_index_size = PUD_INDEX_SIZE_L4_64K_4_6;
						ms->l4_index_size = PGD_INDEX_SIZE_L4_64K_3_10;
					}
				} else if (THIS_KERNEL_VERSION >= LINUX(3,10,0)) {
					ms->l1_index_size = PTE_INDEX_SIZE_L4_64K_3_10;
					ms->l2_index_size = PMD_INDEX_SIZE_L4_64K_3_10;
					ms->l3_index_size = PUD_INDEX_SIZE_L4_64K;
					ms->l4_index_size = PGD_INDEX_SIZE_L4_64K_3_10;

				} else {
					ms->l1_index_size = PTE_INDEX_SIZE_L4_64K;
					ms->l2_index_size = PMD_INDEX_SIZE_L4_64K;
					ms->l3_index_size = PUD_INDEX_SIZE_L4_64K;
					ms->l4_index_size = PGD_INDEX_SIZE_L4_64K;
				}

				if (!(machdep->flags & BOOK3E))
					ms->pte_rpn_shift = symbol_exists("demote_segment_4k") ?
						PTE_RPN_SHIFT_L4_64K_V2 : PTE_RPN_SHIFT_L4_64K_V1;

				if (!(machdep->flags & BOOK3E) &&
				    (THIS_KERNEL_VERSION >= LINUX(4,6,0))) {
					ms->pgd_masked_bits = PGD_MASKED_BITS_64K_4_6;
					ms->pud_masked_bits = PUD_MASKED_BITS_64K_4_6;
					ms->pmd_masked_bits = PMD_MASKED_BITS_64K_4_6;
				} else {
					ms->pgd_masked_bits = PGD_MASKED_BITS_64K;
					ms->pud_masked_bits = PUD_MASKED_BITS_64K;
					if ((machdep->flags & BOOK3E) &&
					    (THIS_KERNEL_VERSION >= LINUX(4,5,0)))
						ms->pmd_masked_bits = PMD_MASKED_BITS_BOOK3E_64K_4_5;
					else if (THIS_KERNEL_VERSION >= LINUX(3,11,0))
						ms->pmd_masked_bits = PMD_MASKED_BITS_64K_3_11;
					else
						ms->pmd_masked_bits = PMD_MASKED_BITS_64K;
				}
			} else {
				/* 4K pagesize */
				if (machdep->flags & RADIX_MMU) {
					ms->l1_index_size = PTE_INDEX_SIZE_RADIX_4K;
					ms->l2_index_size = PMD_INDEX_SIZE_RADIX_4K;
					ms->l3_index_size = PUD_INDEX_SIZE_RADIX_4K;
					ms->l4_index_size = PGD_INDEX_SIZE_RADIX_4K;

				} else {
					ms->l1_index_size = PTE_INDEX_SIZE_L4_4K;
					ms->l2_index_size = PMD_INDEX_SIZE_L4_4K;
					if (THIS_KERNEL_VERSION >= LINUX(3,7,0))
						ms->l3_index_size = PUD_INDEX_SIZE_L4_4K_3_7;
					else
						ms->l3_index_size = PUD_INDEX_SIZE_L4_4K;
					ms->l4_index_size = PGD_INDEX_SIZE_L4_4K;

					if (machdep->flags & BOOK3E)
						ms->pte_rpn_shift = PTE_RPN_SHIFT_L4_BOOK3E_4K;
					else
						ms->pte_rpn_shift = THIS_KERNEL_VERSION >= LINUX(4,5,0) ?
							PTE_RPN_SHIFT_L4_4K_4_5 : PTE_RPN_SHIFT_L4_4K;
				}

				ms->pgd_masked_bits = PGD_MASKED_BITS_4K;
				ms->pud_masked_bits = PUD_MASKED_BITS_4K;
				ms->pmd_masked_bits = PMD_MASKED_BITS_4K;
			}

			ms->pte_rpn_mask = PTE_RPN_MASK_DEFAULT;
			if (!(machdep->flags & BOOK3E)) {
				if (THIS_KERNEL_VERSION >= LINUX(4,6,0)) {
					ms->pte_rpn_mask = PTE_RPN_MASK_L4_4_6;
					ms->pte_rpn_shift = PTE_RPN_SHIFT_L4_4_6;
				}
				if (THIS_KERNEL_VERSION >= LINUX(4,7,0)) {
					ms->pgd_masked_bits = PGD_MASKED_BITS_4_7;
					ms->pud_masked_bits = PUD_MASKED_BITS_4_7;
					ms->pmd_masked_bits = PMD_MASKED_BITS_4_7;
				}
			}

			/* Compute ptrs per each level */
			ms->l1_shift = machdep->pageshift;
			ms->ptrs_per_l1 = (1 << ms->l1_index_size);
			ms->ptrs_per_l2 = (1 << ms->l2_index_size);
			ms->ptrs_per_l3 = (1 << ms->l3_index_size);
			ms->ptrs_per_l4 = (1 << ms->l4_index_size);
			machdep->ptrs_per_pgd = ms->ptrs_per_l4;

			/* Compute shifts */
			ms->l2_shift = ms->l1_shift + ms->l1_index_size;
			ms->l3_shift = ms->l2_shift + ms->l2_index_size;
			ms->l4_shift = ms->l3_shift + ms->l3_index_size;
		}

		if (machdep->flags & VMEMMAP)
			ppc64_vmemmap_init();

		machdep->section_size_bits = _SECTION_SIZE_BITS;
		set_ppc64_max_physmem_bits();

		ppc64_init_cpu_info();
		machdep->vmalloc_start = ppc64_vmalloc_start;
		MEMBER_OFFSET_INIT(thread_struct_pg_tables,
			"thread_struct", "pg_tables");

		STRUCT_SIZE_INIT(irqdesc, "irqdesc");
		STRUCT_SIZE_INIT(irq_desc_t, "irq_desc_t");
		if (INVALID_SIZE(irqdesc) && INVALID_SIZE(irq_desc_t))
			STRUCT_SIZE_INIT(irq_desc_t, "irq_desc");
		/* as of 2.3.x PPC uses the generic irq handlers */
		if (VALID_SIZE(irq_desc_t))
			machdep->dump_irq = generic_dump_irq;
		else {
			machdep->dump_irq = ppc64_dump_irq;
			MEMBER_OFFSET_INIT(irqdesc_action, "irqdesc", "action");
			MEMBER_OFFSET_INIT(irqdesc_ctl, "irqdesc", "ctl");
			MEMBER_OFFSET_INIT(irqdesc_level, "irqdesc", "level");
		}

		MEMBER_OFFSET_INIT(device_node_type, "device_node", "type");
		MEMBER_OFFSET_INIT(device_node_allnext,
			"device_node", "allnext");
		MEMBER_OFFSET_INIT(device_node_properties,
			"device_node", "properties");
		MEMBER_OFFSET_INIT(property_name, "property", "name");
		MEMBER_OFFSET_INIT(property_value, "property", "value");
		MEMBER_OFFSET_INIT(property_next, "property", "next");
		MEMBER_OFFSET_INIT(machdep_calls_setup_residual,
			"machdep_calls", "setup_residual");
		MEMBER_OFFSET_INIT(RESIDUAL_VitalProductData,
			"RESIDUAL", "VitalProductData");
		MEMBER_OFFSET_INIT(VPD_ProcessorHz, "VPD", "ProcessorHz");
		MEMBER_OFFSET_INIT(bd_info_bi_intfreq, "bd_info", "bi_intfreq");
		if (symbol_exists("irq_desc"))
			ARRAY_LENGTH_INIT(machdep->nr_irqs, irq_desc,
				"irq_desc", NULL, 0);
		else if (kernel_symbol_exists("nr_irqs"))
			get_symbol_data("nr_irqs", sizeof(unsigned int),
				&machdep->nr_irqs);
		else
			machdep->nr_irqs = 0;

		if (symbol_exists("paca") && 
			MEMBER_EXISTS("paca_struct", "xHrdIntStack")) {
			ulong paca_sym, offset;
			uint cpu, paca_size = STRUCT_SIZE("paca_struct");
			
			/*
			 * Get the HW Interrupt stack base and top values.
			 * Note that, this stack will be used to store frames
			 * when the CPU received IPI (only for 2.4 kernel). 
			 * Hence it is needed to retrieve IPI symbols
			 * (Ex: smp_message_recv, xics_ipi_action, and etc)
			 * and to get the top SP in the process's stack.
			 */
			offset = MEMBER_OFFSET("paca_struct", "xHrdIntStack");
			paca_sym  = symbol_value("paca");
			if (!(ms->hwintrstack = (ulong *)calloc(NR_CPUS, sizeof(ulong))))
				error(FATAL, "cannot malloc hwintrstack space.");
			for (cpu = 0; cpu < kt->cpus; cpu++)  {
				readmem(paca_sym + (paca_size * cpu) + offset, KVADDR,
					&ms->hwintrstack[cpu], sizeof(ulong),
					"PPC64 HW_intr_stack", FAULT_ON_ERROR);
			}
			ms->hwstacksize = 8 * machdep->pagesize;
			if ((ms->hwstackbuf = (char *)malloc(ms->hwstacksize)) == NULL)
				error(FATAL, "cannot malloc hwirqstack buffer space.");
		}

		ppc64_init_paca_info();

		if (!machdep->hz) {
			machdep->hz = HZ;
			if (THIS_KERNEL_VERSION >= LINUX(2,6,0))
				machdep->hz = 1000;
		}
		/*
		 * IRQ stacks are introduced in 2.6 and also configurable.
		 */
		if ((THIS_KERNEL_VERSION >= LINUX(2,6,0)) && 
			symbol_exists("hardirq_ctx"))
			ASSIGN_SIZE(irq_ctx) = STACKSIZE();

		break;

	case POST_INIT:
		break;

	case LOG_ONLY:
		machdep->identity_map_base = kt->vmcoreinfo._stext_SYMBOL;
		break;
	}
}

#ifndef KSYMS_START
#define KSYMS_START 1
#endif

static ulong 
ppc64_task_to_stackbase(ulong task)
{
	ulong stackbase;

	if (tt->flags & THREAD_INFO_IN_TASK) {
		readmem(task + OFFSET(task_struct_stack), KVADDR, &stackbase,
		    sizeof(void *), "task_struct.stack", FAULT_ON_ERROR);
		return stackbase;
	} else if (tt->flags & THREAD_INFO)
		return task_to_thread_info(task);
	else 
		return task;
}
static ulong 
ppc64_get_stackbase(ulong task)
{
	return ppc64_task_to_stackbase(task);
}

static ulong 
ppc64_get_stacktop(ulong task)
{
	return ppc64_task_to_stackbase(task) + STACKSIZE();
}

	
void
ppc64_dump_machdep_table(ulong arg)
{
	struct machine_specific *ms = machdep->machspec;
        int i, c, others; 
 
        others = 0;
        fprintf(fp, "              flags: %lx (", machdep->flags);
	if (machdep->flags & KSYMS_START)
		fprintf(fp, "%sKSYMS_START", others++ ? "|" : "");
	if (machdep->flags & MACHDEP_BT_TEXT)
		fprintf(fp, "%sMACHDEP_BT_TEXT", others++ ? "|" : "");
	if (machdep->flags & VM_ORIG)
		fprintf(fp, "%sVM_ORIG", others++ ? "|" : "");
	if (machdep->flags & VM_4_LEVEL)
		fprintf(fp, "%sVM_4_LEVEL", others++ ? "|" : "");
	if (machdep->flags & VMEMMAP)
		fprintf(fp, "%sVMEMMAP", others++ ? "|" : "");
	if (machdep->flags & VMEMMAP_AWARE)
		fprintf(fp, "%sVMEMMAP_AWARE", others++ ? "|" : "");
	if (machdep->flags & BOOK3E)
		fprintf(fp, "%sBOOK3E", others++ ? "|" : "");
	if (machdep->flags & PHYS_ENTRY_L4)
		fprintf(fp, "%sPHYS_ENTRY_L4", others++ ? "|" : "");
	if (machdep->flags & SWAP_ENTRY_L4)
		fprintf(fp, "%sSWAP_ENTRY_L4", others++ ? "|" : "");
	if (machdep->flags & RADIX_MMU)
		fprintf(fp, "%sRADIX_MMU", others++ ? "|" : "");
	if (machdep->flags & OPAL_FW)
		fprintf(fp, "%sOPAL_FW", others++ ? "|" : "");
        fprintf(fp, ")\n");

	fprintf(fp, "             kvbase: %lx\n", machdep->kvbase);
	fprintf(fp, "  identity_map_base: %lx\n", machdep->identity_map_base);
        fprintf(fp, "           pagesize: %d\n", machdep->pagesize);
        fprintf(fp, "          pageshift: %d\n", machdep->pageshift);
        fprintf(fp, "           pagemask: %llx\n", machdep->pagemask);
        fprintf(fp, "         pageoffset: %lx\n", machdep->pageoffset);
	fprintf(fp, "          stacksize: %ld\n", machdep->stacksize);
        fprintf(fp, "                 hz: %d\n", machdep->hz);
        fprintf(fp, "                mhz: %ld\n", machdep->mhz);
        fprintf(fp, "            memsize: %ld (0x%lx)\n", 
		machdep->memsize, machdep->memsize);
	fprintf(fp, "               bits: %d\n", machdep->bits);
	fprintf(fp, "            nr_irqs: %d\n", machdep->nr_irqs);
        fprintf(fp, "      eframe_search: ppc64_eframe_search()\n");
        fprintf(fp, "         back_trace: ppc64_back_trace_cmd()\n");
        fprintf(fp, "    processor_speed: ppc64_processor_speed()\n");
        fprintf(fp, "              uvtop: ppc64_uvtop()\n");
        fprintf(fp, "              kvtop: ppc64_kvtop()\n");
        fprintf(fp, "       get_task_pgd: ppc64_get_task_pgd()\n");
	fprintf(fp, "           dump_irq: ppc64_dump_irq()\n");
        fprintf(fp, "    get_stack_frame: ppc64_get_stack_frame()\n");
        fprintf(fp, "      get_stackbase: ppc64_get_stackbase()\n");
        fprintf(fp, "       get_stacktop: ppc64_get_stacktop()\n");
        fprintf(fp, "      translate_pte: ppc64_translate_pte()\n");
	fprintf(fp, "        memory_size: generic_memory_size()\n");
	fprintf(fp, "      vmalloc_start: ppc64_vmalloc_start()\n");
	fprintf(fp, "       is_task_addr: ppc64_is_task_addr()\n");
	fprintf(fp, "      verify_symbol: ppc64_verify_symbol()\n");
	fprintf(fp, "         dis_filter: ppc64_dis_filter()\n");
	fprintf(fp, "           cmd_mach: ppc64_cmd_mach()\n");
	fprintf(fp, "       get_smp_cpus: ppc64_get_smp_cpus()\n");
        fprintf(fp, "          is_kvaddr: %s\n", 
		machdep->is_kvaddr == book3e_is_kvaddr ? 
		"book3e_is_kvaddr()" : "generic_is_kvaddr()"); 
        fprintf(fp, "          is_uvaddr: generic_is_uvaddr()\n");
        fprintf(fp, "       verify_paddr: generic_verify_paddr()\n");
        fprintf(fp, "  get_kvaddr_ranges: ppc64_get_kvaddr_ranges()\n");
	fprintf(fp, "   get_irq_affinity: generic_get_irq_affinity()\n");
	fprintf(fp, "    show_interrupts: generic_show_interrupts()\n");
	fprintf(fp, " xendump_p2m_create: NULL\n");
	fprintf(fp, "xen_kdump_p2m_create: NULL\n");
        fprintf(fp, "  line_number_hooks: ppc64_line_number_hooks\n");
        fprintf(fp, "      last_pgd_read: %lx\n", machdep->last_pgd_read);
        fprintf(fp, "      last_pud_read: %lx\n", machdep->last_pud_read);
        fprintf(fp, "      last_pmd_read: %lx\n", machdep->last_pmd_read);
        fprintf(fp, "     last_ptbl_read: %lx\n", machdep->last_ptbl_read);
        fprintf(fp, "clear_machdep_cache: ppc64_clear_machdep_cache()\n");
        fprintf(fp, "                pgd: %lx\n", (ulong)machdep->pgd);
        fprintf(fp, "                pud: %lx\n", (ulong)machdep->pud);
        fprintf(fp, "                pmd: %lx\n", (ulong)machdep->pmd);
        fprintf(fp, "               ptbl: %lx\n", (ulong)machdep->ptbl);
	fprintf(fp, "       ptrs_per_pgd: %d\n", machdep->ptrs_per_pgd);
	fprintf(fp, "  section_size_bits: %ld\n", machdep->section_size_bits);
        fprintf(fp, "   max_physmem_bits: %ld\n", machdep->max_physmem_bits);
        fprintf(fp, "  sections_per_root: %ld\n", machdep->sections_per_root);
        for (i = 0; i < MAX_MACHDEP_ARGS; i++) {
                fprintf(fp, "    cmdline_args[%d]: %s\n",
                        i, machdep->cmdline_args[i] ?
                        machdep->cmdline_args[i] : "(unused)");
        }
	fprintf(fp, "           machspec: %lx\n", (ulong)ms);
	fprintf(fp, "            is_kvaddr: %s\n", 
		ms->is_kvaddr == book3e_is_kvaddr ?
		"book3e_is_kvaddr()" : "generic_is_kvaddr()");
	fprintf(fp, "            is_vmaddr: %s\n", 
		ms->is_vmaddr == book3e_is_vmaddr ?
		"book3e_is_vmaddr()" : "ppc64_is_vmaddr()");
	if (ms->hwintrstack) {
		fprintf(fp, "    hwintrstack[%d]: ", NR_CPUS);
		for (c = 0; c < NR_CPUS; c++) {
			fprintf(fp, "%s%016lx ",
				((c % 4) == 0) ? "\n  " : "",
				ms->hwintrstack[c]);
		}
	} else
		fprintf(fp, "          hwintrstack: (unused)");
	fprintf(fp, "\n");
	fprintf(fp, "           hwstackbuf: %lx\n", (ulong)ms->hwstackbuf);
	fprintf(fp, "          hwstacksize: %d\n", ms->hwstacksize);
	fprintf(fp, "        l4_index_size: %d\n", ms->l4_index_size);
	fprintf(fp, "        l3_index_size: %d\n", ms->l3_index_size);
	fprintf(fp, "        l2_index_size: %d\n", ms->l2_index_size);
	fprintf(fp, "        l1_index_size: %d\n", ms->l1_index_size);
	fprintf(fp, "          ptrs_per_l4: %d\n", ms->ptrs_per_l4);
	fprintf(fp, "          ptrs_per_l3: %d\n", ms->ptrs_per_l3);
	fprintf(fp, "          ptrs_per_l2: %d\n", ms->ptrs_per_l2);
	fprintf(fp, "          ptrs_per_l1: %d\n", ms->ptrs_per_l1);
	fprintf(fp, "             l4_shift: %d\n", ms->l4_shift);
	fprintf(fp, "             l3_shift: %d\n", ms->l3_shift);
	fprintf(fp, "             l2_shift: %d\n", ms->l2_shift);
	fprintf(fp, "             l1_shift: %d\n", ms->l1_shift);
	fprintf(fp, "         pte_rpn_mask: %lx\n", ms->pte_rpn_mask);
	fprintf(fp, "        pte_rpn_shift: %d\n", ms->pte_rpn_shift);
	fprintf(fp, "      pgd_masked_bits: %lx\n", ms->pgd_masked_bits);
	fprintf(fp, "      pud_masked_bits: %lx\n", ms->pud_masked_bits);
	fprintf(fp, "      pmd_masked_bits: %lx\n", ms->pmd_masked_bits);
	fprintf(fp, "         vmemmap_base: "); 
	if (ms->vmemmap_base)
		fprintf(fp, "%lx\n", ms->vmemmap_base);
	else
		fprintf(fp, "(unused)\n");
	if (ms->vmemmap_cnt) {
		fprintf(fp, "          vmemmap_cnt: %d\n", 
			ms->vmemmap_cnt);
		fprintf(fp, "        vmemmap_psize: %d\n", 
			ms->vmemmap_psize);
		for (i = 0; i < ms->vmemmap_cnt; i++) {
			fprintf(fp, 
			    "      vmemmap_list[%d]: virt: %lx  phys: %lx\n", i, 
				ms->vmemmap_list[i].virt,
				ms->vmemmap_list[i].phys);
		}
	} else {
		fprintf(fp, "          vmemmap_cnt: (unused)\n");
		fprintf(fp, "    vmemmap_page_size: (unused)\n");
		fprintf(fp, "       vmemmap_list[]: (unused)\n");
	}
}

/*
 * Virtual to physical memory translation. This function will be called
 * by both ppc64_kvtop and ppc64_uvtop.
 */
static int
ppc64_vtop(ulong vaddr, ulong *pgd, physaddr_t *paddr, int verbose)
{
	ulong *page_dir;
	ulong *page_middle;
	ulong *page_table;
	ulong pgd_pte, pmd_pte;
	ulong pte;

	if (verbose)
		fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)pgd);

	if (THIS_KERNEL_VERSION < LINUX(2,6,0)) 
		page_dir = (ulong *)((uint *)pgd + PGD_OFFSET_24(vaddr));
	else
		page_dir = (ulong *)((uint *)pgd + PGD_OFFSET(vaddr));

	FILL_PGD(PAGEBASE(pgd), KVADDR, PAGESIZE());
	pgd_pte = UINT(machdep->pgd + PAGEOFFSET(page_dir));

	if (verbose)
		fprintf(fp, "  PGD: %lx => %lx\n", (ulong)page_dir, pgd_pte);

	if (!pgd_pte)
		return FALSE;

	pgd_pte <<= PAGESHIFT();
	page_middle = (ulong *)((uint *)pgd_pte + PMD_OFFSET(vaddr));

	FILL_PMD(PTOV(PAGEBASE(pgd_pte)), KVADDR, PAGESIZE());
	pmd_pte = UINT(machdep->pmd + PAGEOFFSET(page_middle));

	if (verbose)
		fprintf(fp, "  PMD: %lx => %lx\n", (ulong)page_middle, pmd_pte);

	if (!(pmd_pte))
		return FALSE;

	if (THIS_KERNEL_VERSION < LINUX(2,6,0)) 
		pmd_pte <<= PAGESHIFT();
	else
		pmd_pte = ((pmd_pte << PAGESHIFT()) >> PMD_TO_PTEPAGE_SHIFT);

	page_table = (ulong *)pmd_pte + (BTOP(vaddr) & (PTRS_PER_PTE - 1));

	if (verbose)
		fprintf(fp, "  PMD: %lx => %lx\n",(ulong)page_middle,
			(ulong)page_table);

	FILL_PTBL(PTOV(PAGEBASE(pmd_pte)), KVADDR, PAGESIZE());
	pte = ULONG(machdep->ptbl + PAGEOFFSET(page_table));

	if (verbose)
		fprintf(fp, "  PTE: %lx => %lx\n", (ulong)page_table, pte);

	if (!(pte & _PAGE_PRESENT)) {
		if (pte && verbose) {
			fprintf(fp, "\n");
			ppc64_translate_pte(pte, 0, PTE_RPN_SHIFT_DEFAULT);
		}
		return FALSE;
	}

	if (!pte)
		return FALSE;

	*paddr = PAGEBASE(PTOB(pte >> PTE_RPN_SHIFT_DEFAULT)) + PAGEOFFSET(vaddr);

	if (verbose) {
		fprintf(fp, " PAGE: %lx\n\n", PAGEBASE(*paddr));
		ppc64_translate_pte(pte, 0, PTE_RPN_SHIFT_DEFAULT);
	}

	return TRUE;
}

/*
 * Virtual to physical memory translation. This function will be called
 * by both ppc64_kvtop and ppc64_uvtop.
 */
static int
ppc64_vtop_level4(ulong vaddr, ulong *level4, physaddr_t *paddr, int verbose)
{
	ulong *pgdir;
	ulong *page_upper;
	ulong *page_middle;
	ulong *page_table;
	ulong pgd_pte, pud_pte, pmd_pte;
	ulong pte;
	uint  pdshift;
	uint  hugepage_type = 0; /* 0: regular entry; 1: huge pte; 2: huge pd */
	uint  swap = !!(machdep->flags & SWAP_ENTRY_L4);

	if (verbose)
		fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)level4);

	pgdir = (ulong *)((ulong *)level4 + PGD_OFFSET_L4(vaddr));
	FILL_PGD(PAGEBASE(level4), KVADDR, PAGESIZE());
	pgd_pte = swap64(ULONG(machdep->pgd + PAGEOFFSET(pgdir)), swap);
	if (verbose)
		fprintf(fp, "  PGD: %lx => %lx\n", (ulong)pgdir, pgd_pte);
	if (!pgd_pte)
		return FALSE;

	hugepage_type = get_ptetype(pgd_pte);
	if (hugepage_type) {
		pte = pgd_pte;
		pdshift = machdep->machspec->l4_shift;
		goto out;
	}

	/* Sometimes we don't have level3 pagetable entries */
	if (machdep->machspec->l3_index_size != 0) {
		pgd_pte = pgd_page_vaddr_l4(pgd_pte);
		page_upper = (ulong *)((ulong *)pgd_pte + PUD_OFFSET_L4(vaddr));
		FILL_PUD(PAGEBASE(pgd_pte), KVADDR, PAGESIZE());
		pud_pte = swap64(ULONG(machdep->pud + PAGEOFFSET(page_upper)), swap);

		if (verbose)
			fprintf(fp, "  PUD: %lx => %lx\n", (ulong)page_upper, pud_pte);
		if (!pud_pte)
			return FALSE;

		hugepage_type = get_ptetype(pud_pte);
		if (hugepage_type) {
			pte = pud_pte;
			pdshift = machdep->machspec->l3_shift;
			goto out;
		}
	} else {
		pud_pte = pgd_pte;
	}

	pud_pte = pud_page_vaddr_l4(pud_pte);
	page_middle = (ulong *)((ulong *)pud_pte + PMD_OFFSET_L4(vaddr));
	FILL_PMD(PAGEBASE(pud_pte), KVADDR, PAGESIZE());
	pmd_pte = swap64(ULONG(machdep->pmd + PAGEOFFSET(page_middle)), swap);

	if (verbose)
		fprintf(fp, "  PMD: %lx => %lx\n", (ulong)page_middle, pmd_pte);

	if (!(pmd_pte))
		return FALSE;

	hugepage_type = get_ptetype(pmd_pte);
	if (hugepage_type) {
		pte = pmd_pte;
		pdshift = machdep->machspec->l2_shift;
		goto out;
	}

	pmd_pte = pmd_page_vaddr_l4(pmd_pte);
	page_table = (ulong *)(pmd_pte)
			 + (BTOP(vaddr) & (machdep->machspec->ptrs_per_l1 - 1));
	if (verbose)
		fprintf(fp, "  PMD: %lx => %lx\n",(ulong)page_middle,
			(ulong)page_table);

	FILL_PTBL(PAGEBASE(pmd_pte), KVADDR, PAGESIZE());
	pte = swap64(ULONG(machdep->ptbl + PAGEOFFSET(page_table)), swap);

	if (verbose)
		fprintf(fp, "  PTE: %lx => %lx\n", (ulong)page_table, pte);

	if (!(pte & _PAGE_PRESENT)) {
		if (pte && verbose) {
			fprintf(fp, "\n");
			ppc64_translate_pte(pte, 0, machdep->machspec->pte_rpn_shift);
		}
		return FALSE;
	}

	if (!pte)
		return FALSE;

out:
	if (hugepage_type) {
		if (hugepage_type == 2) {
			/* TODO: Calculate the offset within the huge page
			 * directory for this huge page to get corresponding
			 * physical address. In the current form, it may
			 * return the physical address of the first huge page
			 * in this directory for all the huge pages
			 * in this huge page directory.
			 */
			ulong hugepd = hugepage_dir(pte);

			readmem(hugepd, KVADDR, &pte, sizeof(pte),
                                "hugepd_entry", RETURN_ON_ERROR);

			if (verbose)
				fprintf(fp, "  HUGE PD: %lx => %lx\n", hugepd, pte);

			if (!pte)
				return FALSE;
		}

		*paddr = PAGEBASE(PTOB((pte & PTE_RPN_MASK) >> PTE_RPN_SHIFT))
				+ (vaddr & ((1UL << pdshift) - 1));
	} else {
		*paddr = PAGEBASE(PTOB((pte & PTE_RPN_MASK) >> PTE_RPN_SHIFT))
				+ PAGEOFFSET(vaddr);
	}

	if (verbose) {
		if (hugepage_type)
			fprintf(fp, " HUGE PAGE: %lx\n\n", PAGEBASE(*paddr));
		else
			fprintf(fp, " PAGE: %lx\n\n", PAGEBASE(*paddr));
		ppc64_translate_pte(pte, 0, machdep->machspec->pte_rpn_shift);
	}

	return TRUE;
}

/*
 *  Translates a user virtual address to its physical address.  cmd_vtop()
 *  sets the verbose flag so that the pte translation gets displayed; all
 *  other callers quietly accept the translation.
 *
 *  This routine can also take mapped kernel virtual addresses if the -u flag
 *  was passed to cmd_vtop().  If so, it makes the translation using the
 *  kernel-memory PGD entry instead of swapper_pg_dir.
 */

static int
ppc64_uvtop(struct task_context *tc, ulong vaddr, 
		physaddr_t *paddr, int verbose)
{
	ulong mm, active_mm;
	ulong *pgd;

        if (!tc)
		error(FATAL, "current context invalid\n");

        *paddr = 0;

	if (is_kernel_thread(tc->task) && IS_KVADDR(vaddr)) {
		if (VALID_MEMBER(thread_struct_pg_tables))
			pgd = (ulong *)machdep->get_task_pgd(tc->task);
		else {
			if (INVALID_MEMBER(task_struct_active_mm))
				error(FATAL, "no pg_tables or active_mm?\n");
	
			readmem(tc->task + OFFSET(task_struct_active_mm),
				KVADDR, &active_mm, sizeof(void *),
				"task active_mm contents", FAULT_ON_ERROR);

			if (!active_mm)
				error(FATAL,
				     "no active_mm for this kernel thread\n");

			readmem(active_mm + OFFSET(mm_struct_pgd),
				KVADDR, &pgd, sizeof(long),
				"mm_struct pgd", FAULT_ON_ERROR);
		}
	} else {
		if ((mm = task_mm(tc->task, TRUE)))
			pgd = ULONG_PTR(tt->mm_struct +
				OFFSET(mm_struct_pgd));
		else
			readmem(tc->mm_struct + OFFSET(mm_struct_pgd),
				KVADDR, &pgd, sizeof(long), "mm_struct pgd",
				FAULT_ON_ERROR);
	}

	if (machdep->flags & VM_4_LEVEL)
		return ppc64_vtop_level4(vaddr, pgd, paddr, verbose);
	else
		return ppc64_vtop(vaddr, pgd, paddr, verbose);
}

/*
 *  Translates a kernel virtual address to its physical address.  cmd_vtop()
 *  sets the verbose flag so that the pte translation gets displayed; all
 *  other callers quietly accept the translation.
 */
static int
ppc64_kvtop(struct task_context *tc, ulong kvaddr, 
	physaddr_t *paddr, int verbose)
{
        if (!IS_KVADDR(kvaddr))
                return FALSE;

	if ((machdep->flags & VMEMMAP) && 
	    (kvaddr >= machdep->machspec->vmemmap_base))
		return ppc64_vmemmap_to_phys(kvaddr, paddr, verbose);

	if (!vt->vmalloc_start) {
		*paddr = VTOP(kvaddr);
		return TRUE;
	}
	if (!IS_VMALLOC_ADDR(kvaddr)) {
		*paddr = VTOP(kvaddr);
		if (!verbose) 
			return TRUE;
	}

	if (machdep->flags & VM_4_LEVEL)
		return ppc64_vtop_level4(kvaddr, (ulong *)vt->kernel_pgd[0], paddr, verbose);
	else
		return ppc64_vtop(kvaddr, (ulong *)vt->kernel_pgd[0], paddr, verbose);
}

static void
ppc64_init_paca_info(void)
{
	struct machine_specific *ms = machdep->machspec;
	ulong *paca_ptr;
	int i;

	if (!(paca_ptr = (ulong *)calloc(kt->cpus, sizeof(ulong))))
		error(FATAL, "cannot malloc paca pointers space.\n");

	/* Get paca pointers for all CPUs. */
	if (symbol_exists("paca_ptrs")) {
		ulong paca_loc;

		readmem(symbol_value("paca_ptrs"), KVADDR, &paca_loc, sizeof(void *),
			"paca double pointer", RETURN_ON_ERROR);
		readmem(paca_loc, KVADDR, paca_ptr, sizeof(void *) * kt->cpus,
			"paca pointers", RETURN_ON_ERROR);
	} else if (symbol_exists("paca") &&
		   (get_symbol_type("paca", NULL, NULL) == TYPE_CODE_PTR)) {
		readmem(symbol_value("paca"), KVADDR, paca_ptr, sizeof(void *) * kt->cpus,
			"paca pointers", RETURN_ON_ERROR);
	} else {
		free(paca_ptr);
		return;
	}

	/* Initialize emergency stacks info. */
	if (MEMBER_EXISTS("paca_struct", "emergency_sp")) {
		ulong offset = MEMBER_OFFSET("paca_struct", "emergency_sp");

		if (!(ms->emergency_sp = (ulong *)calloc(kt->cpus, sizeof(ulong))))
			error(FATAL, "cannot malloc emergency stack space.\n");
		for (i = 0; i < kt->cpus; i++)
			readmem(paca_ptr[i] + offset, KVADDR, &ms->emergency_sp[i],
				sizeof(void *), "paca->emergency_sp",
				RETURN_ON_ERROR);
	}

	if (MEMBER_EXISTS("paca_struct", "nmi_emergency_sp")) {
		ulong offset = MEMBER_OFFSET("paca_struct", "nmi_emergency_sp");

		if (!(ms->nmi_emergency_sp = (ulong *)calloc(kt->cpus, sizeof(ulong))))
			error(FATAL, "cannot malloc NMI emergency stack space.\n");
		for (i = 0; i < kt->cpus; i++)
			readmem(paca_ptr[i] + offset, KVADDR, &ms->nmi_emergency_sp[i],
				sizeof(void *), "paca->nmi_emergency_sp",
				RETURN_ON_ERROR);
	}

	if (MEMBER_EXISTS("paca_struct", "mc_emergency_sp")) {
		ulong offset = MEMBER_OFFSET("paca_struct", "mc_emergency_sp");

		if (!(ms->mc_emergency_sp = (ulong *)calloc(kt->cpus, sizeof(ulong))))
			error(FATAL, "cannot malloc machine check emergency stack space.\n");
		for (i = 0; i < kt->cpus; i++)
			readmem(paca_ptr[i] + offset, KVADDR, &ms->mc_emergency_sp[i],
				sizeof(void *), "paca->mc_emergency_sp",
				RETURN_ON_ERROR);
	}

	free(paca_ptr);
}

/*
 *  Verify that the kernel has made the vmemmap list available,
 *  and if so, stash the relevant data required to make vtop
 *  translations.
 */
static
void ppc64_vmemmap_init(void)
{
	int i, psize, shift, cnt;
	struct list_data list_data, *ld;
	long backing_size, virt_addr_offset, phys_offset, list_offset;
	ulong *vmemmap_list;
	char *vmemmap_buf;
	struct machine_specific *ms;
	
	if (!(kernel_symbol_exists("vmemmap_list")) ||
	    !(kernel_symbol_exists("mmu_psize_defs")) ||
	    !(kernel_symbol_exists("mmu_vmemmap_psize")) ||
	    !STRUCT_EXISTS("vmemmap_backing") ||
	    !STRUCT_EXISTS("mmu_psize_def") ||
	    !MEMBER_EXISTS("mmu_psize_def", "shift") ||
	    !MEMBER_EXISTS("vmemmap_backing", "phys") ||
	    !MEMBER_EXISTS("vmemmap_backing", "virt_addr") ||
	    !MEMBER_EXISTS("vmemmap_backing", "list"))
		return;

	ms = machdep->machspec;

	backing_size = STRUCT_SIZE("vmemmap_backing");
	virt_addr_offset = MEMBER_OFFSET("vmemmap_backing", "virt_addr");
	phys_offset = MEMBER_OFFSET("vmemmap_backing", "phys");
	list_offset = MEMBER_OFFSET("vmemmap_backing", "list");

	if (!readmem(symbol_value("mmu_vmemmap_psize"),
	    KVADDR, &psize, sizeof(int), "mmu_vmemmap_psize", 
	    RETURN_ON_ERROR))
		return;
	if (!readmem(symbol_value("mmu_psize_defs") +
	    (STRUCT_SIZE("mmu_psize_def") * psize) +
	    MEMBER_OFFSET("mmu_psize_def", "shift"),
	    KVADDR, &shift, sizeof(int), "mmu_psize_def shift",
	    RETURN_ON_ERROR))
		return;

	ms->vmemmap_psize = 1 << shift;

        ld =  &list_data;
        BZERO(ld, sizeof(struct list_data));
	if (!readmem(symbol_value("vmemmap_list"),
	    KVADDR, &ld->start, sizeof(void *), "vmemmap_list",
	    RETURN_ON_ERROR))
		return;
        ld->end = symbol_value("vmemmap_list");
        ld->list_head_offset = list_offset;

        hq_open();
	cnt = do_list(ld);
        vmemmap_list = (ulong *)GETBUF(cnt * sizeof(ulong));
        cnt = retrieve_list(vmemmap_list, cnt);
	hq_close();

	if ((ms->vmemmap_list = (struct ppc64_vmemmap *)malloc(cnt *
	    sizeof(struct ppc64_vmemmap))) == NULL)
		error(FATAL, "cannot malloc vmemmap list space");

        vmemmap_buf = GETBUF(backing_size);
	for (i = 0; i < cnt; i++) {
		if (!readmem(vmemmap_list[i], KVADDR, vmemmap_buf, 
		   backing_size, "vmemmap_backing", RETURN_ON_ERROR)) {
			free(ms->vmemmap_list);
			goto out;
		}

		ms->vmemmap_list[i].phys = ULONG(vmemmap_buf + phys_offset);
		ms->vmemmap_list[i].virt = ULONG(vmemmap_buf + virt_addr_offset);

		if (ms->vmemmap_list[i].virt < ms->vmemmap_base)
			ms->vmemmap_base = ms->vmemmap_list[i].virt;
	}

	ms->vmemmap_cnt = cnt;
	machdep->flags |= VMEMMAP_AWARE;
	if (CRASHDEBUG(1))
		fprintf(fp, "ppc64_vmemmap_init: vmemmap base: %lx\n",
			ms->vmemmap_base);
out:
	FREEBUF(vmemmap_buf);
	FREEBUF(vmemmap_list);
}

/*
 *  If the vmemmap address translation information is stored in the kernel,
 *  make the translation. 
 */
static int
ppc64_vmemmap_to_phys(ulong kvaddr, physaddr_t *paddr, int verbose)
{
	int i;
	ulong offset;
	struct machine_specific *ms;

	if (!(machdep->flags & VMEMMAP_AWARE)) {
		/*
		 *  During runtime, just fail the command.
		 */
		if (vt->flags & VM_INIT)
			error(FATAL, "cannot translate vmemmap address: %lx\n",
				 kvaddr); 
		/*
		 *  During vm_init() initialization, print a warning message.
		 */
		error(WARNING, 
		    "cannot translate vmemmap kernel virtual addresses:\n"
		    "         commands requiring page structure contents"
		    " will fail\n\n");
	
		return FALSE;
	}

	ms = machdep->machspec;

	for (i = 0; i < ms->vmemmap_cnt; i++) {
		if ((kvaddr >= ms->vmemmap_list[i].virt) &&
		    (kvaddr < (ms->vmemmap_list[i].virt + ms->vmemmap_psize))) {
			offset = kvaddr - ms->vmemmap_list[i].virt;
			*paddr = ms->vmemmap_list[i].phys + offset;
			return TRUE;
		}
	}

	return FALSE;
}

/*
 *  Determine where vmalloc'd memory starts.
 */
static ulong
ppc64_vmalloc_start(void)
{
	return (first_vmalloc_address());
}

/*
 * 
 */
static int
ppc64_is_task_addr(ulong task)
{
	int i;

	if (tt->flags & THREAD_INFO)
		return IS_KVADDR(task);
	else if (IS_KVADDR(task) && (ALIGNED_STACK_OFFSET(task) == 0))
		return TRUE;

	for (i = 0; i < kt->cpus; i++)
		if (task == tt->idle_threads[i])
			return TRUE;

	return FALSE;
}


/*
 * 
 */
static ulong
ppc64_processor_speed(void)
{
        ulong res, value, ppc_md, md_setup_res;
        ulong prep_setup_res;
        ulong node, type, name, properties;
	char str_buf[32];
	uint len;
	ulong mhz = 0;

        if (machdep->mhz)
                return(machdep->mhz);

	if (symbol_exists("ppc_proc_freq")) {
		get_symbol_data("ppc_proc_freq", sizeof(ulong), &mhz);
		mhz /= 1000000;
		return (machdep->mhz = mhz);
	}

        if(symbol_exists("allnodes")) {
                get_symbol_data("allnodes", sizeof(void *), &node);
                while(node) {
                        readmem(node+OFFSET(device_node_type),
                                KVADDR, &type, sizeof(ulong), "node type",
                                FAULT_ON_ERROR);
                        if(type != 0) {
                                len = read_string(type, str_buf,
                                        sizeof(str_buf));

                                if(len && (strcasecmp(str_buf, "cpu") == 0))
                                        break;
                        }

                        readmem(node+OFFSET(device_node_allnext),
                                KVADDR, &node, sizeof(ulong), "node allnext",
                                FAULT_ON_ERROR);
                }
		
                /* now, if we found a CPU node, get the speed property */
                if(node) {
                        readmem(node+OFFSET(device_node_properties),
                                KVADDR, &properties, sizeof(ulong),
                                "node properties", FAULT_ON_ERROR);

                        while(properties) {
                                readmem(properties+OFFSET(property_name),
                                        KVADDR, &name,
                                        sizeof(ulong), "property name",
                                        FAULT_ON_ERROR);

                                len = read_string(name, str_buf,
                                        sizeof(str_buf));

                                if (len && (strcasecmp(str_buf,
                                    "clock-frequency") == 0)) {
                                        /* found the right cpu property */

                                        readmem(properties+
                                           OFFSET(property_value),
                                            KVADDR, &value, sizeof(ulong),
                                            "clock freqency pointer",
                                            FAULT_ON_ERROR);
                                        readmem(value, KVADDR, &mhz,
                                            sizeof(int),
                                            "clock frequency value",
                                            FAULT_ON_ERROR);
                                        mhz /= 1000000;
                                        break;
                                }
				else if(len && (strcasecmp(str_buf,
				    "ibm,extended-clock-frequency") == 0)){
					/* found the right cpu property */

					readmem(properties+
					    OFFSET(property_value),
					    KVADDR, &value, sizeof(ulong),
					    "clock freqency pointer",
					    FAULT_ON_ERROR);
					readmem(value, KVADDR, &mhz,
					    sizeof(ulong),
					    "clock frequency value",
					    FAULT_ON_ERROR);
					mhz /= 1000000;
					break;
                                }

                                /* keep looking */

                                readmem(properties+
                                    OFFSET(property_next),
                                    KVADDR, &properties, sizeof(ulong),
                                    "property next", FAULT_ON_ERROR);
                        }
                        if(!properties) {
                                /* didn't find the cpu speed for some reason */
				return (machdep->mhz = 0);
                        }
                }
	} 

	/* for machines w/o OF */
        /* untested, but in theory this should work on prep machines */

        if (symbol_exists("res") && !mhz) {
        	get_symbol_data("res", sizeof(void *), &res);

                if (symbol_exists("prep_setup_residual")) {
                	get_symbol_data("prep_setup_residual",
                        	sizeof(void *), &prep_setup_res);
                        get_symbol_data("ppc_md", sizeof(void *),
                        	&ppc_md);
                        readmem(ppc_md +
                        	OFFSET(machdep_calls_setup_residual),
                                KVADDR, &md_setup_res,
                                sizeof(ulong), "ppc_md setup_residual",
                                FAULT_ON_ERROR);

			if(prep_setup_res == md_setup_res) {
                        	/* PREP machine */
                                readmem(res+
                                	OFFSET(RESIDUAL_VitalProductData)+
                                        OFFSET(VPD_ProcessorHz),
                                        KVADDR, &mhz, sizeof(ulong),
                                        "res VitalProductData",
                                        FAULT_ON_ERROR);

                        	mhz = (mhz > 1024) ? mhz >> 20 : mhz;
                	}
		}

		if(!mhz) {
                        /* everything else seems to do this the same way... */
                        readmem(res +
                        	OFFSET(bd_info_bi_intfreq),
                                KVADDR, &mhz, sizeof(ulong),
                                "bd_info bi_intfreq", FAULT_ON_ERROR);

                	mhz /= 1000000;
        	}
	}
        /* else...well, we don't have OF, or a residual structure, so
         * just print unknown MHz
         */

        return (machdep->mhz = (ulong)mhz);
}


/*
 *  Accept or reject a symbol from the kernel namelist.
 */
static int
ppc64_verify_symbol(const char *name, ulong value, char type)
{
        if (CRASHDEBUG(8) && name && strlen(name))
                fprintf(fp, "%08lx %s\n", value, name);

        if (STREQ(name, "_start") || STREQ(name, "_stext"))
                machdep->flags |= KSYMS_START;

        return (name && strlen(name) && (machdep->flags & KSYMS_START) &&
                !STREQ(name, "Letext") && !STRNEQ(name, "__func__."));
}


/*
 *  Get the relevant page directory pointer from a task structure.
 */
static ulong
ppc64_get_task_pgd(ulong task)
{
        long offset;
        ulong pg_tables;

        offset = VALID_MEMBER(task_struct_thread) ?
                OFFSET(task_struct_thread) : OFFSET(task_struct_tss);

        if (INVALID_MEMBER(thread_struct_pg_tables))
                error(FATAL,
                   "pg_tables does not exist in this kernel's thread_struct\n");
        offset += OFFSET(thread_struct_pg_tables);

        readmem(task + offset, KVADDR, &pg_tables,
                sizeof(ulong), "task thread pg_tables", FAULT_ON_ERROR);

        return(pg_tables);
}


/*
 *  Translate a PTE, returning TRUE if the page is present.
 *  If a physaddr pointer is passed in, don't print anything.
 */
static int
ppc64_translate_pte(ulong pte, void *physaddr, ulonglong pte_rpn_shift)
{
        int c, len1, len2, len3, others, page_present;
        char buf[BUFSIZE];
        char buf2[BUFSIZE];
        char buf3[BUFSIZE];
        char ptebuf[BUFSIZE];
        char physbuf[BUFSIZE];
        char *arglist[MAXARGS];
        ulong paddr;

	if (STREQ(pc->curcmd, "pte"))
		pte_rpn_shift = machdep->machspec->pte_rpn_shift;
        paddr =  PTOB(pte >> pte_rpn_shift);
        page_present = !!(pte & _PAGE_PRESENT);

        if (physaddr) {
                *((ulong *)physaddr) = paddr;
                return page_present;
        }

        sprintf(ptebuf, "%lx", pte);
        len1 = MAX(strlen(ptebuf), strlen("PTE"));

        if (!page_present && pte) {
                swap_location(pte, buf);
                if ((c = parse_line(buf, arglist)) != 3)
                        error(FATAL, "cannot determine swap location\n");
                fprintf(fp, "%s  ", mkstring(buf2, len1, CENTER|LJUST, "PTE"));

                len2 = MAX(strlen(arglist[0]), strlen("SWAP"));
                len3 = MAX(strlen(arglist[2]), strlen("OFFSET"));

                fprintf(fp, "%s  %s\n",
                        mkstring(buf2, len2, CENTER|LJUST, "SWAP"),
                        mkstring(buf3, len3, CENTER|LJUST, "OFFSET"));

                strcpy(buf2, arglist[0]);
                strcpy(buf3, arglist[2]);
                fprintf(fp, "%s  %s  %s\n",
                        mkstring(ptebuf, len1, CENTER|RJUST, NULL),
                        mkstring(buf2, len2, CENTER|RJUST, NULL),
                        mkstring(buf3, len3, CENTER|RJUST, NULL));

                return page_present;
        }

        fprintf(fp, "%s  ", mkstring(buf, len1, CENTER|LJUST, "PTE"));
        sprintf(physbuf, "%lx", paddr);
        len2 = MAX(strlen(physbuf), strlen("PHYSICAL"));
        fprintf(fp, "%s  ", mkstring(buf, len2, CENTER|LJUST, "PHYSICAL"));

        fprintf(fp, "FLAGS\n");

        fprintf(fp, "%s  %s  ",
                mkstring(ptebuf, len1, CENTER|RJUST, NULL),
                mkstring(physbuf, len2, CENTER|RJUST, NULL));
        fprintf(fp, "(");
        others = 0;

        if (pte) {
                if (pte & _PAGE_PTE)
                        fprintf(fp, "%sPTE", others++ ? "|" : "");
                if (pte & _PAGE_PRESENT)
                        fprintf(fp, "%sPRESENT", others++ ? "|" : "");
                if (pte & _PAGE_USER)
                        fprintf(fp, "%sUSER", others++ ? "|" : "");
                if (pte & _PAGE_RW)
                        fprintf(fp, "%sRW", others++ ? "|" : "");
                if (pte & _PAGE_GUARDED)
                        fprintf(fp, "%sGUARDED", others++ ? "|" : "");
                if (pte & _PAGE_COHERENT)
                        fprintf(fp, "%sCOHERENT", others++ ? "|" : "");
                if (pte & _PAGE_NO_CACHE)
                        fprintf(fp, "%sNO_CACHE", others++ ? "|" : "");
                if (pte & _PAGE_WRITETHRU)
                        fprintf(fp, "%sWRITETHRU", others++ ? "|" : "");
                if (pte & _PAGE_DIRTY)
                        fprintf(fp, "%sDIRTY", others++ ? "|" : "");
                if (pte & _PAGE_ACCESSED)
                        fprintf(fp, "%sACCESSED", others++ ? "|" : "");
        } else
                fprintf(fp, "no mapping");

        fprintf(fp, ")\n");

        return page_present;
}

/*
 * The user specified SP could be in HW interrupt stack for tasks running on 
 * other CPUs. Hence, get the SP which is in process's stack.
 */
static ulong
ppc64_check_sp_in_HWintrstack(ulong sp, struct bt_info *bt)
{
	/*
	 * Since the seperate HW Interrupt stack is involved to store 
	 * IPI frames, printing all stack symbols or searching for exception 
	 * frames for running tasks on other CPUS is tricky. The simple 
	 * solution is - ignore HW intr stack and search in the process stack.
	 * Anyway the user will be interested only frames that are 
	 * involved before receiving CALL_FUNCTION_IPI.
	 * So, if the SP is not within the stack, read the top value 
	 * from the HW Interrupt stack which is the SP points to top 
	 * frame in the process's stack.
	 * 
	 * Note: HW Interrupt stack is used only in 2.4 kernel.
	 */
	if (machdep->machspec->hwintrstack && is_task_active(bt->task) &&
	    (bt->task != tt->panic_task)) {
		ulong newsp;

		readmem(machdep->machspec->hwintrstack[bt->tc->processor],
			KVADDR, &newsp, sizeof(ulong),
			"stack pointer", FAULT_ON_ERROR);
		if (INSTACK(newsp, bt))  
			sp = newsp;
	}

	return sp;
}

/*
 *  Look for likely exception frames in a stack.
 */
static int 
ppc64_eframe_search(struct bt_info *bt_in)
{
	ulong addr;
	struct bt_info bt_local, *bt;
	ulong *stack, *first, *last;
	ulong irqstack;
        char *mode;
	ulong eframe_addr;
	int c, cnt; 
	struct ppc64_pt_regs *regs;

	bt = bt_in;

	if (bt->flags & BT_EFRAME_SEARCH2) {
		if (!(tt->flags & IRQSTACKS)) {
			error(INFO, "This kernel does not have IRQ stacks\n");
			return 0;
		}

		BCOPY(bt_in, &bt_local, sizeof(struct bt_info));
		bt = &bt_local;
		bt->flags &= ~(ulonglong)BT_EFRAME_SEARCH2;

        	for (c = 0; c < NR_CPUS; c++) {
                	if (tt->hardirq_ctx[c]) {
				if ((bt->flags & BT_CPUMASK) && 
				    !(NUM_IN_BITMAP(bt->cpumask, c)))
					continue;
				bt->hp->esp = tt->hardirq_ctx[c];
				fprintf(fp, "CPU %d HARD IRQ STACK:\n", c);
				if ((cnt = ppc64_eframe_search(bt)))
					fprintf(fp, "\n");
				else
					fprintf(fp, "(none found)\n\n");
			}
		}
        	for (c = 0; c < NR_CPUS; c++) {
			if (tt->softirq_ctx[c]) {
				if ((bt->flags & BT_CPUMASK) && 
				    !(NUM_IN_BITMAP(bt->cpumask, c)))
					continue;
				bt->hp->esp = tt->softirq_ctx[c];
				fprintf(fp, "CPU %d SOFT IRQ STACK:\n", c);
				if ((cnt = ppc64_eframe_search(bt)))
					fprintf(fp, "\n");
				else
					fprintf(fp, "(none found)\n\n");
			}
		}

		return 0;
	}
	
	if (bt->hp && bt->hp->esp) {
		BCOPY(bt_in, &bt_local, sizeof(struct bt_info));
		bt = &bt_local;
		addr = bt->hp->esp;
		if ((irqstack = ppc64_in_irqstack(addr))) {
			bt->stackbase = irqstack;
			bt->stacktop = irqstack + STACKSIZE();
			alter_stackbuf(bt);
			addr = bt->stackbase +
				roundup(SIZE(thread_info), sizeof(ulong));
		} else if (!INSTACK(addr, bt)) {
			enum emergency_stack_type estype;

			if ((estype = ppc64_in_emergency_stack(bt->tc->processor, addr, false)))
				ppc64_set_bt_emergency_stack(estype, bt);

			/*
			 * If the user specified SP is in HW interrupt stack
			 * (only for tasks running on other CPUs and in 2.4
			 * kernel), get the top SP points to process's stack.
			 */
			addr = ppc64_check_sp_in_HWintrstack(addr, bt);
			if (!INSTACK(addr, bt))
				error(FATAL,
				"unrecognized stack address for this task: %lx\n", addr);
		}
	} else if (tt->flags & THREAD_INFO)
		addr = bt->stackbase +
			roundup(SIZE(thread_info), sizeof(ulong));

	else
		addr = bt->stackbase +
			roundup(SIZE(task_struct), sizeof(ulong));

	if (!INSTACK(addr, bt)) 
		return(0);

	stack = (ulong *)bt->stackbuf;
	first = stack + ((addr - bt->stackbase) / sizeof(ulong));
	last = stack + (((bt->stacktop - bt->stackbase) - SIZE(pt_regs)) /
		sizeof(ulong));
	
	for ( ; first <= last; first++) {
		char *efrm_str = NULL;
		eframe_addr = bt->stackbase + sizeof(ulong) * (first - stack);
		if (THIS_KERNEL_VERSION < LINUX(2,6,0)) {
			regs = (struct ppc64_pt_regs *)first;
			if (!IS_KVADDR(regs->gpr[1]) || !IS_KVADDR(regs->nip) 
				|| !is_kernel_text(regs->nip)) 
				if (!IS_UVADDR(regs->gpr[1], bt->tc) ||
					!IS_UVADDR(regs->nip, bt->tc)) 
					continue;
		} else {
			/*
			 * In 2.6 or later, 0x7265677368657265 is saved in the 
			 * stack (sp + 96) for the exception frame. Also, 
			 * pt_regs will be saved at sp + 112. 
			 * Hence, once we know the location of exception marker
			 * in the stack, pt_regs is saved at 
			 * <marker location> - 96 + 112. ==> first + 16. 
			 */
			if (*first == EXCP_FRAME_MARKER) {
				ulong *sp;
				/* 
				 * SP points to <marker location> - 96/8; 
				 */
				sp = (ulong *)(first - 12);
				if (!IS_KVADDR(*sp)) 
					if (!IS_UVADDR(*sp, bt->tc))
						continue;

				first = (ulong *)((char *)first + 16);
				regs = (struct ppc64_pt_regs *)first;
			} 
			else 
				continue;
		}
		
		if ((efrm_str = ppc64_check_eframe(regs)) != NULL) {
			if ((((regs)->msr) >> MSR_PR_LG) & 0x1) 
				mode = "USER-MODE";
			else
				mode = "KERNEL-MODE";
			fprintf(fp, "%s  %s EXCEPTION FRAME AT %lx:\n",	
				bt->flags & BT_EFRAME_SEARCH ? "\n" : "",
				mode, eframe_addr);
			ppc64_print_eframe(efrm_str, regs, bt);
		}
	}
	return 0;
}

static ulong 
ppc64_in_irqstack(ulong addr)
{
	int c;
	
	if (!(tt->flags & IRQSTACKS))
		return 0;

	for (c = 0; c < NR_CPUS; c++) {
                if (tt->hardirq_ctx[c]) {
			if ((addr >= tt->hardirq_ctx[c]) &&
			    (addr < (tt->hardirq_ctx[c] + SIZE(irq_ctx))))
				return(tt->hardirq_ctx[c]);
	
                }
                if (tt->softirq_ctx[c]) {
                       if ((addr >= tt->softirq_ctx[c]) &&
                           (addr < (tt->softirq_ctx[c] + SIZE(irq_ctx))))
                                return(tt->softirq_ctx[c]);
		}
	}

	return 0;
}

/*
 * Check if the CPU is running in any of its emergency stacks.
 * Returns
 *	NONE_STACK          : if input is invalid or addr is not within any emergency stack.
 *	EMERGENCY_STACK     : if the addr is within emergency stack.
 *	NMI_EMERGENCY_STACK : if the addr is within NMI emergency stack.
 *	MC_EMERGENCY_STACK  : if the addr is within machine check emergency stack.
 */
static enum emergency_stack_type
ppc64_in_emergency_stack(int cpu, ulong addr, bool verbose)
{
	struct machine_specific *ms = machdep->machspec;
	ulong base, top;

	if (cpu < 0  || cpu >= kt->cpus)
		return NONE_STACK;

	if (ms->emergency_sp && IS_KVADDR(ms->emergency_sp[cpu])) {
		top = ms->emergency_sp[cpu];
		base =  top - STACKSIZE();
		if (addr >= base && addr < top) {
			if (verbose)
				fprintf(fp, "---<Emergency Stack>---\n");
			return EMERGENCY_STACK;
		}
	}

	if (ms->nmi_emergency_sp && IS_KVADDR(ms->nmi_emergency_sp[cpu])) {
		top = ms->nmi_emergency_sp[cpu];
		base = top - STACKSIZE();
		if (addr >= base && addr < top) {
			if (verbose)
				fprintf(fp, "---<NMI Emergency Stack>---\n");
			return NMI_EMERGENCY_STACK;
		}
	}

	if (ms->mc_emergency_sp && IS_KVADDR(ms->mc_emergency_sp[cpu])) {
		top = ms->mc_emergency_sp[cpu];
		base =  top - STACKSIZE();
		if (addr >= base && addr < top) {
			if (verbose)
				fprintf(fp, "---<Machine Check Emergency Stack>---\n");
			return MC_EMERGENCY_STACK;
		}
	}

	return NONE_STACK;
}

static void
ppc64_set_bt_emergency_stack(enum emergency_stack_type type, struct bt_info *bt)
{
	struct machine_specific *ms = machdep->machspec;
	ulong top;

	switch (type) {
	case EMERGENCY_STACK:
		top = ms->emergency_sp[bt->tc->processor];
		break;
	case NMI_EMERGENCY_STACK:
		top = ms->nmi_emergency_sp[bt->tc->processor];
		break;
	case MC_EMERGENCY_STACK:
		top = ms->mc_emergency_sp[bt->tc->processor];
		break;
	default:
		top = 0;
		break;
	}

	if (top) {
		bt->stackbase = top - STACKSIZE();
		bt->stacktop = top;
		alter_stackbuf(bt);
	}
}

/*
 *  Unroll a kernel stack.
 */
static void
ppc64_back_trace_cmd(struct bt_info *bt)
{
	char buf[BUFSIZE];
	struct gnu_request *req;
	extern void print_stack_text_syms(struct bt_info *, ulong, ulong);

        bt->flags |= BT_EXCEPTION_FRAME;

        if (CRASHDEBUG(1) || bt->debug)
                fprintf(fp, " => PC: %lx (%s) FP: %lx \n",
                        bt->instptr, value_to_symstr(bt->instptr, buf, 0),
                        bt->stkptr);

        req = (struct gnu_request *)GETBUF(sizeof(struct gnu_request));
        req->command = GNU_STACK_TRACE;
        req->flags = GNU_RETURN_ON_ERROR;
        req->buf = GETBUF(BUFSIZE);
        req->debug = bt->debug;
        req->task = bt->task;

        req->pc = bt->instptr;
        req->sp = bt->stkptr;

	if (bt->flags &
	(BT_TEXT_SYMBOLS|BT_TEXT_SYMBOLS_PRINT|BT_TEXT_SYMBOLS_NOPRINT)) {
		if (!INSTACK(req->sp, bt))
			/*
			 * If the user specified SP is in HW interrupt stack
			 * (only for tasks running on other CPUs and in 2.4
			 * kernel), get the top SP points to process's stack.
			 */
			req->sp = ppc64_check_sp_in_HWintrstack(req->sp, bt);
		print_stack_text_syms(bt, req->sp, req->pc);
	} else {
				
        	if (bt->flags & BT_USE_GDB) {
                	strcpy(req->buf, "backtrace");
                	gdb_interface(req);
        	}
        	else
                	ppc64_back_trace(req, bt);
	}

        FREEBUF(req->buf);
        FREEBUF(req);
}


/*
 *  Unroll the kernel stack using a minimal amount of gdb services.
 *
 *  (Ref: 64-bit PowerPC ELF ABI Spplement; Ian Lance Taylor, Zembu Labs).
 *   A PPC64 stack frame looks like this:
 *
 *  High Address
 *   .-> Back Chain (etc...)
 *   |   FP reg save area
 *   |   GP reg save area
 *   |   Local var space
 *   |   Parameter save area    (SP+48)
 *   |   TOC save area          (SP+40)
 *   |   link editor doubleword (SP+32)
 *   |   compiler doubleword    (SP+24)
 *   |  LR save                 (SP+16)
 *   |   CR save                (SP+8)
 *   `- Back Chain       <-- sp (SP+0)
 *
 *   Note that the LR (ret addr) may not be saved in the current frame if
 *   no functions have been called from the current function.
 */
 /* HACK: put an initial lr in this var for find_trace().  It will be
  * cleared during the trace.  
  */
static void
ppc64_back_trace(struct gnu_request *req, struct bt_info *bt)
{
	enum emergency_stack_type estype;
	ulong newpc = 0, newsp, marker;
	int c = bt->tc->processor;
	ulong nmi_sp = 0;
	int eframe_found;
	int frame = 0;
	ulong lr = 0; /* hack...need to pass in initial lr reg */

	if (!INSTACK(req->sp, bt)) {
		ulong irqstack;
		struct machine_specific *ms = machdep->machspec;

		if ((irqstack = ppc64_in_irqstack(req->sp))) {
			bt->stackbase = irqstack;
			bt->stacktop = bt->stackbase + STACKSIZE();
			alter_stackbuf(bt);
		} else if ((estype = ppc64_in_emergency_stack(c, req->sp, true))) {
			if (estype == NMI_EMERGENCY_STACK)
				nmi_sp = req->sp;
			ppc64_set_bt_emergency_stack(estype, bt);
		} else if (ms->hwintrstack) {
			bt->stacktop = ms->hwintrstack[bt->tc->processor] +
				sizeof(ulong);
			bt->stackbase = ms->hwintrstack[bt->tc->processor] - 
				ms->hwstacksize + STACK_FRAME_OVERHEAD;
			bt->stackbuf = ms->hwstackbuf;
			alter_stackbuf(bt);
		} else {
			fprintf(fp, "cannot find the stack info.\n");
			return;
		}
	}
	
		
	while (INSTACK(req->sp, bt)) {
		newsp = *(ulong *)&bt->stackbuf[req->sp - bt->stackbase];
		if ((req->name = closest_symbol(req->pc)) == NULL) {
			if (CRASHDEBUG(1)) {
				error(FATAL,
				"ppc64_back_trace hit unknown symbol (%lx).\n",
					req->pc);
			}
		}

		bt->flags |= BT_SAVE_LASTSP;
		ppc64_print_stack_entry(frame, req, newsp, lr, bt);
		bt->flags &= ~(ulonglong)BT_SAVE_LASTSP;
		lr = 0;	
		if (IS_KVADDR(newsp)) {
			/*
			 * In 2.4, HW interrupt stack will be used to save
			 * smp_call_functions symbols. i.e, when the dumping 
			 * CPU is issued IPI call to freeze other CPUS, 
			 */
			if (INSTACK(newsp, bt) && (newsp + 16 > bt->stacktop))
				newsp = 
				*(ulong *)&bt->stackbuf[newsp - bt->stackbase];
			if (!INSTACK(newsp, bt)) {
				if ((estype = ppc64_in_emergency_stack(c, newsp, true))) {
					if (!nmi_sp && estype == NMI_EMERGENCY_STACK)
						nmi_sp = newsp;
					ppc64_set_bt_emergency_stack(estype, bt);
				} else {
					/*
					 * Switch HW interrupt stack or emergency stack
					 * to process's stack.
					 */
					bt->stackbase = GET_STACKBASE(bt->task);
					bt->stacktop = GET_STACKTOP(bt->task);
					alter_stackbuf(bt);
				}
			}
			if (IS_KVADDR(newsp) && INSTACK(newsp, bt))
				newpc = *(ulong *)&bt->stackbuf[newsp + 16 -
						bt->stackbase];
		}

		if (BT_REFERENCE_FOUND(bt))
			return;
		
		eframe_found =  FALSE;
		/*
		 * Is this frame an execption one?
		 * In 2.6, 0x7265677368657265 is saved and used
		 * to determine the execption frame.
		 */
		if (THIS_KERNEL_VERSION < LINUX(2,6,0)) {
			if (frame && (newsp - req->sp - STACK_FRAME_OVERHEAD) >=
				sizeof(struct ppc64_pt_regs))
				eframe_found = TRUE;
			else if (STREQ(req->name, ".ret_from_except")) 
				eframe_found = TRUE;
		} else if ((newsp - req->sp - STACK_FRAME_OVERHEAD) >= 
				sizeof(struct ppc64_pt_regs)) {
			 readmem(req->sp+0x60, KVADDR, &marker, 
				sizeof(ulong), "stack frame", FAULT_ON_ERROR);
		        if (marker == EXCP_FRAME_MARKER) 
				eframe_found = TRUE;
		}
		if (eframe_found) {
			char *efrm_str = NULL;
			struct ppc64_pt_regs regs;
			readmem(req->sp+STACK_FRAME_OVERHEAD, KVADDR, &regs,
				sizeof(struct ppc64_pt_regs),
				"exception frame", FAULT_ON_ERROR);

			efrm_str = ppc64_check_eframe(&regs);
			if (efrm_str) {
				ppc64_print_eframe(efrm_str, &regs, bt);
				lr = regs.link;
				newpc = regs.nip;
				newsp = regs.gpr[1];
			} 
		}

		/*
		 * NMI stack may not be re-entrant. In so, an SP in the NMI stack
		 * is likely to point back to an SP within the NMI stack, in case
		 * of a nested NMI.
		 */
		if (nmi_sp && nmi_sp == newsp) {
			fprintf(fp, "---<Nested NMI>---\n");
			break;
		}

		/*
		 * Some Linux 3.7 kernel threads have been seen to have
		 * their end-of-trace stack linkage pointer pointing
		 * back to itself (instead of NULL), which would cause
		 * an infinite loop at the .ret_from_kernel_thread frame.
		 */
		if (req->sp == newsp)
			break;

		req->pc = newpc;
		req->sp = newsp;
		frame++;
	}
}

static void
ppc64_display_full_frame(struct bt_info *bt, ulong nextsp, FILE *ofp)
{
        int i, u_idx;
        ulong *nip;
        ulong words, addr;
	char buf[BUFSIZE];

	if (!INSTACK(nextsp, bt)) 
		nextsp =  bt->stacktop;

        words = (nextsp - bt->frameptr) / sizeof(ulong);

        addr = bt->frameptr;
        u_idx = (bt->frameptr - bt->stackbase)/sizeof(ulong);
        for (i = 0; i < words; i++, u_idx++) {
              if (!(i & 1))
                        fprintf(ofp, "%s    %lx: ", i ? "\n" : "", addr);

                nip = (ulong *)(&bt->stackbuf[u_idx*sizeof(ulong)]);
                fprintf(ofp, "%s ", format_stack_entry(bt, buf, *nip, 0));
                addr += sizeof(ulong);
        }
        fprintf(ofp, "\n");
}

/*
 *  print one entry of a stack trace
 */
static void 
ppc64_print_stack_entry(int frame, 
		      struct gnu_request *req, 
		      ulong newsp,
		      ulong lr, 	
		      struct bt_info *bt)
{
	struct load_module *lm;
	char *lrname = NULL;
	ulong offset;
	struct syment *sp;
	char *name_plus_offset;
	char buf[BUFSIZE];

	if (BT_REFERENCE_CHECK(bt)) {
		switch (bt->ref->cmdflags & (BT_REF_SYMBOL|BT_REF_HEXVAL))
		{
		case BT_REF_SYMBOL:
			if (STREQ(req->name, bt->ref->str))
				bt->ref->cmdflags |= BT_REF_FOUND;
			break;

		case BT_REF_HEXVAL:
			if (bt->ref->hexval == req->pc)
				bt->ref->cmdflags |= BT_REF_FOUND;
			break;
		}
	} else {
		name_plus_offset = NULL;
		if (bt->flags & BT_SYMBOL_OFFSET) {
			sp = value_search(req->pc, &offset);
			if (sp && offset) 
				name_plus_offset = value_to_symstr(req->pc, buf, bt->radix);
		}
		
		fprintf(fp, "%s#%d [%lx] %s at %lx",
			frame < 10 ? " " : "", frame,
			req->sp, name_plus_offset ? name_plus_offset : req->name, 
			req->pc);
		if (module_symbol(req->pc, NULL, &lm, NULL, 0))
			fprintf(fp, " [%s]", lm->mod_name);
	
		if (req->ra) {
			/*
			 * Previous frame is an exception one. If the func 
			 * symbol for the current frame is same as with 
			 * the previous frame's LR value, print "(unreliable)".
			 */
			lrname = closest_symbol(req->ra);
			req->ra = 0;
			if (!lrname) {
				if (CRASHDEBUG(1)) 
					error(FATAL,
					"ppc64_back_trace hit unknown symbol (%lx).\n",
						req->ra);
				return;
			}
		}
		if (lr) {
			/*
			 * Link register value for an expection frame.
			 */
			if ((lrname = closest_symbol(lr)) == NULL) {
				if (CRASHDEBUG(1))
					error(FATAL,
					"ppc64_back_trace hit unknown symbol (%lx).\n",
					lr);
				return;
			}
			req->ra = lr;
		}
		if (!req->name || STREQ(req->name, lrname) ||
		    !is_kernel_text(req->pc))
			fprintf(fp, "  (unreliable)");
		
		fprintf(fp, "\n"); 
	}

	if (bt->flags & BT_SAVE_LASTSP)
		req->lastsp = req->sp;

	bt->frameptr = req->sp;
	if (bt->flags & BT_FULL) 
		if (IS_KVADDR(newsp))
			ppc64_display_full_frame(bt, newsp, fp);
	if (bt->flags & BT_LINE_NUMBERS)
		ppc64_dump_line_number(req->pc);
}

/*
 * Check whether the frame is exception one!
 */
static char *
ppc64_check_eframe(struct ppc64_pt_regs *regs)
{
	switch(regs->trap & ~0xF) {
	case 0x100:
		return("System Reset");
	case 0x200:
		return("Machine Check");
	case 0x300:
		return("Data Access");
	case 0x380:
		return("Data SLB Access");
	case 0x400:
		return("Instruction Access");
	case 0x480:
		return("Instruction SLB Access");
	case 0x500:
		return("Hardware Interrupt");
	case 0x600:
		return("Alignment");
	case 0x700:
		return("Program Check");
	case 0x800:
		return("FPU Unavailable");
	case 0x900:
		return("Decrementer");
	case 0x980:
		return("Hypervisor Decrementer");
	case 0xa00:
		return("Doorbell");
	case 0xb00:
		return("reserved");
	case 0xc00:
		return("System Call");
	case 0xd00:
		return("Single Step");
	case 0xe00:
		return("fp assist");
	case 0xe40:
		return("Emulation Assist");
	case 0xe60:
		return("HMI");
	case 0xe80:
		return("Hypervisor Doorbell");
	case 0xf00:
		return("Performance Monitor");
	case 0xf20:
		return("Altivec Unavailable");
	case 0x1300:    
		return("Instruction Breakpoint");
	case 0x1500:
		return("Denormalisation");
	case 0x1700:    
		return("Altivec Assist");
	}
	
	/* No exception frame exists */
	return NULL;
}

static void
ppc64_print_regs(struct ppc64_pt_regs *regs)
{
	int i;

        /* print out the gprs... */
        for (i=0; i<32; i++) {
                if (i && !(i % 3))
                        fprintf(fp, "\n");

                fprintf(fp, " R%d:%s %016lx   ", i,
                        ((i < 10) ? " " : ""), regs->gpr[i]);
		/*
		 * In 2.6, some stack frame contains only partial regs set.
		 * For the partial set, only 14 regs will be saved and trap 
		 * field will contain 1 in the least significant bit. 
		 */
		if ((i == 13) && (regs->trap & 1))
			break;
        }

        fprintf(fp, "\n");

        /* print out the rest of the registers */
        fprintf(fp, " NIP: %016lx   ", regs->nip);
        fprintf(fp, " MSR: %016lx    ", regs->msr);
        fprintf(fp, "OR3: %016lx\n", regs->orig_gpr3);
        fprintf(fp, " CTR: %016lx   ", regs->ctr);

        fprintf(fp, " LR:  %016lx    ", regs->link);
        fprintf(fp, "XER: %016lx\n", regs->xer);
        fprintf(fp, " CCR: %016lx   ", regs->ccr);
        fprintf(fp, " MQ:  %016lx    ", regs->mq);
        fprintf(fp, "DAR: %016lx\n", regs->dar);
        fprintf(fp, " DSISR: %016lx ", regs->dsisr);
        fprintf(fp, "    Syscall Result: %016lx\n", regs->result);
}

static void ppc64_print_nip_lr(struct ppc64_pt_regs *regs, int print_lr)
{
	char buf[BUFSIZE];
	char *sym_buf;

	sym_buf = value_to_symstr(regs->nip, buf, 0);
	if (sym_buf[0] != NULLCHAR)
		fprintf(fp, " [NIP  : %s]\n", sym_buf);

	if (print_lr) {
		sym_buf = value_to_symstr(regs->link, buf, 0);
		if (sym_buf[0] != NULLCHAR)
			fprintf(fp, " [LR   : %s]\n", sym_buf);
	}
}

/*
 * Print the exception frame information
 */
static void
ppc64_print_eframe(char *efrm_str, struct ppc64_pt_regs *regs,
			struct bt_info *bt)
{
	if (BT_REFERENCE_CHECK(bt))
		return;

	fprintf(fp, " %s [%lx] exception frame:\n", efrm_str, regs->trap);
	ppc64_print_regs(regs);
	ppc64_print_nip_lr(regs, 1);
}

/*
 * For vmcore typically saved with KDump or FADump, get SP and IP values
 * from the saved ptregs.
 */
static int
ppc64_vmcore_stack_frame(struct bt_info *bt_in, ulong *nip, ulong *ksp)
{
	struct ppc64_pt_regs *pt_regs;
	unsigned long unip;
	/*
	 * TRUE: task is running in a different context (userspace, OPAL..)
	 * FALSE: task is probably running in kernel space.
	 */
	int out_of_context = FALSE;

	pt_regs = (struct ppc64_pt_regs *)bt_in->machdep;
	if (!pt_regs || !pt_regs->gpr[1]) {
		if (bt_in->hp) {
			if (bt_in->hp->esp) {
				*ksp = bt_in->hp->esp;
				if (!bt_in->hp->eip) {
					if (IS_KVADDR(*ksp)) {
						readmem(*ksp+16, KVADDR, &unip, sizeof(ulong),
							"Regs NIP value", FAULT_ON_ERROR);
						*nip = unip;
					}
				} else
					*nip = bt_in->hp->eip;

			}
			return TRUE;
		}

		/*
		 * Not collected regs. May be the corresponding CPU not
		 * responded to an IPI in case of KDump OR f/w has not
		 * not provided the register info in case of FADump.
		 */
		fprintf(fp, "%0lx: GPR1 register value (SP) was not saved\n",
			bt_in->task);
		return FALSE;
	}

	*ksp = pt_regs->gpr[1];
	if (IS_KVADDR(*ksp)) {
		readmem(*ksp+16, KVADDR, &unip, sizeof(ulong), "Regs NIP value",
			FAULT_ON_ERROR);
		*nip = unip;
	} else {
		*nip = pt_regs->nip;
		if (IN_TASK_VMA(bt_in->task, *ksp)) {
			fprintf(fp, "%0lx: Task is running in user space\n",
				bt_in->task);
			out_of_context = TRUE;
		} else if (is_opal_context(*ksp, *nip)) {
			fprintf(fp, "%0lx: Task is running in OPAL (firmware) context\n",
				bt_in->task);
			out_of_context = TRUE;
		} else
			fprintf(fp, "%0lx: Invalid Stack Pointer %0lx\n",
				bt_in->task, *ksp);
	}

	if (bt_in->flags &&
	((BT_TEXT_SYMBOLS|BT_TEXT_SYMBOLS_PRINT|BT_TEXT_SYMBOLS_NOPRINT)))
		return TRUE;

	/*
	 * Print the collected regs for the active task
	 */
	ppc64_print_regs(pt_regs);

	if (out_of_context)
		return TRUE;
	if (!IS_KVADDR(*ksp))
		return FALSE;

	ppc64_print_nip_lr(pt_regs, (unip != pt_regs->link) ? 1 : 0);

	return TRUE;
}

/*
 *  Get the starting point for the active cpus in a diskdump/netdump.
 */
static int
ppc64_get_dumpfile_stack_frame(struct bt_info *bt_in, ulong *nip, ulong *ksp)
{
	int i, ret, panic_task;
	char *sym;
	ulong *up;
	struct bt_info bt_local, *bt;
	struct machine_specific *ms;
        ulong ur_nip = 0;
        ulong ur_ksp = 0;
	int check_hardirq, check_softirq;
	int check_intrstack = TRUE;
	struct ppc64_pt_regs *pt_regs;
	struct syment *sp;

	bt = &bt_local;
	BCOPY(bt_in, bt, sizeof(struct bt_info));
	ms = machdep->machspec;
	ur_nip = ur_ksp = 0;

	panic_task = tt->panic_task == bt->task ? TRUE : FALSE;

	check_hardirq = check_softirq = tt->flags & IRQSTACKS ? TRUE : FALSE;
	if (panic_task && bt->machdep) {
		pt_regs = (struct ppc64_pt_regs *)bt->machdep;
		ur_nip = pt_regs->nip;
		ur_ksp = pt_regs->gpr[1];
		/* Print the collected regs for panic task. */
		ppc64_print_regs(pt_regs);
		ppc64_print_nip_lr(pt_regs, 1);
	} else if ((pc->flags & KDUMP) ||
		   ((pc->flags & DISKDUMP) &&
		    (*diskdump_flags & KDUMP_CMPRS_LOCAL))) {
		/*
		 * For the KDump or FADump vmcore, use SP and IP values
		 * that are saved in ptregs.
		 */
		ret = ppc64_vmcore_stack_frame(bt_in, nip, ksp);
		if (ret)
			return TRUE;
	}

	if (bt->task != tt->panic_task) {
		char cpu_frozen = FALSE;
		/*
		 * Determine whether the CPU responded to an IPI.
		 * We captured the GPR1 register value in the
		 * platform_freeze_cpu() function.
		 */
		if ((sp = symbol_search("dump_header")) && 
		    !is_symbol_text(sp)) { /* Diskdump */
			ulong task_addr;
			/*
			 * The dump_header struct is specified in the module.
			 */
			ulong offset = roundup(STRUCT_SIZE("timespec") + 
				STRUCT_SIZE("new_utsname") + 52, 8);
			offset += sizeof(ulong) * bt->tc->processor;
			readmem(symbol_value("dump_header") + offset, KVADDR,
				&task_addr, sizeof(ulong), "Task Address",
				FAULT_ON_ERROR);
			if (task_addr) 
				cpu_frozen = TRUE;
		}
		if (!cpu_frozen && symbol_exists("cpus_frozen")) { /* Netdump */
			readmem(symbol_value("cpus_frozen") +
				sizeof(char) * bt->tc->processor, KVADDR,
				&cpu_frozen, sizeof(char), "CPU Frozen Value",
				FAULT_ON_ERROR);
		}
		ur_ksp = ppc64_get_sp(bt->task);
		if (IS_KVADDR(ur_ksp)) {
			/*
			 * Since we could not capture the NIP value, we do not
			 * know the top symbol name. Hence, move the SP to next
			 * frame.
			 */
			if (cpu_frozen) 
				readmem(ur_ksp, KVADDR, &ur_ksp, sizeof(ulong),
					"Stack Pointer", FAULT_ON_ERROR);
			else if (symbol_exists("platform_freeze_cpu"))
				fprintf(fp, 
				"%0lx: GPR1 register value (SP) was not saved\n",
					bt->task);
			if (IS_KVADDR(ur_ksp))
				/*
			 	 * Get the LR value stored in the stack frame.
			 	 */
				readmem(ur_ksp+16, KVADDR, &ur_nip,
					sizeof(ulong), "Regs NIP value",
					FAULT_ON_ERROR);
			*ksp = ur_ksp;
			*nip = ur_nip;
		} else {
			*ksp = ur_ksp; 
			fprintf(fp, "Could not find SP for task %0lx\n",
				bt->task);
		}
	}

	/*
	 * Check the process stack first. We are scanning stack for only
	 * panic task. Even though we have dumping CPU's regs, we will be
	 * looking for specific symbols to display trace from actual dump
	 * functions. If these symbols are not exists, consider the regs
	 * stored in the ELF header.
	 */
retry:

        for (i = 0, up = (ulong *)bt->stackbuf;
	     i < (bt->stacktop - bt->stackbase)/sizeof(ulong); i++, up++) {
                sym = closest_symbol(*up);

                if (STREQ(sym, ".netconsole_netdump") || 
			STREQ(sym, ".netpoll_start_netdump") ||
		 	STREQ(sym, ".start_disk_dump") ||
		 	STREQ(sym, "crash_kexec") ||
			STREQ(sym, "crash_fadump") ||
		 	STREQ(sym, "crash_ipi_callback") ||
		 	STREQ(sym, ".crash_kexec") ||
			STREQ(sym, ".crash_fadump") ||
		 	STREQ(sym, ".crash_ipi_callback") ||
			STREQ(sym, ".disk_dump")) {
                        *nip = *up;
                        *ksp = bt->stackbase + 
				((char *)(up) - 16 - bt->stackbuf);
			/*
			 * Check whether this symbol relates to a
			 * backtrace or not
			 */
			ur_ksp =  *(ulong *)&bt->stackbuf[(*ksp) - bt->stackbase];
			if (!INSTACK(ur_ksp, bt))
				continue;

                        return TRUE;
                }
	}

	bt->flags &= ~(BT_HARDIRQ|BT_SOFTIRQ);

	if (check_hardirq &&
	    (tt->hardirq_tasks[bt->tc->processor] == bt->tc->task)) {
		bt->stackbase = tt->hardirq_ctx[bt->tc->processor];
		bt->stacktop = bt->stackbase + STACKSIZE();
		alter_stackbuf(bt);
		bt->flags |= BT_HARDIRQ;
		check_hardirq = FALSE;
		goto retry;
	}

	if (check_softirq &&
		(tt->softirq_tasks[bt->tc->processor] == bt->tc->task)) {
		bt->stackbase = tt->softirq_ctx[bt->tc->processor];
		bt->stacktop = bt->stackbase + STACKSIZE();
		alter_stackbuf(bt);
		bt->flags |= BT_SOFTIRQ;
		check_softirq = FALSE;
		goto retry;
	} 

	if (check_intrstack && ms->hwintrstack) {
		bt->stacktop = ms->hwintrstack[bt->tc->processor] +
			sizeof(ulong);
		bt->stackbase = ms->hwintrstack[bt->tc->processor] -
			ms->hwstacksize + STACK_FRAME_OVERHEAD; 
		bt->stackbuf = ms->hwstackbuf;
		alter_stackbuf(bt);
		check_intrstack = FALSE;
		goto retry;
	}
	/*
	 *  We didn't find what we were looking for, so just use what was
	 *  passed in the ELF header.
	 */
	if (ur_nip && ur_ksp) {
		*nip = ur_nip;
		*ksp = ur_ksp;
		return TRUE;
	}

        console("ppc64_get_dumpfile_stack_frame: cannot find SP for panic task\n");
	return FALSE;
}



/*
 *  Get a stack frame combination of pc and ra from the most relevent spot.
 */
static void
ppc64_get_stack_frame(struct bt_info *bt, ulong *pcp, ulong *spp)
{
	ulong ksp, nip;
	
	nip = ksp = 0;

	if (DUMPFILE() && is_task_active(bt->task)) 
		ppc64_get_dumpfile_stack_frame(bt, &nip, &ksp);
	else
		get_ppc64_frame(bt, &nip, &ksp);

	if (pcp)
		*pcp = nip;
	if (spp)
		*spp = ksp;

}

static ulong
ppc64_get_sp(ulong task)
{
	ulong sp;

	if (tt->flags & THREAD_INFO)
		readmem(task + OFFSET(task_struct_thread_ksp), KVADDR,
			&sp, sizeof(void *),
			"thread_struct ksp", FAULT_ON_ERROR);
        else {
		ulong offset;
		offset = OFFSET_OPTION(task_struct_thread_ksp,
			task_struct_tss_ksp);
		readmem(task + offset, KVADDR, &sp, sizeof(void *),
			"task_struct ksp", FAULT_ON_ERROR);
        }
	return sp;
}


/*
 *  get the SP and PC values for idle tasks.
 */
static void
get_ppc64_frame(struct bt_info *bt, ulong *getpc, ulong *getsp)
{
	ulong ip;
	ulong sp;
	ulong *stack;
	ulong task;
	char *closest;
	struct ppc64_pt_regs regs;

	ip = 0;
	task = bt->task;
	stack = (ulong *)bt->stackbuf;

	sp = ppc64_get_sp(task);
	if (!INSTACK(sp, bt))
		goto out;
	readmem(sp+STACK_FRAME_OVERHEAD, KVADDR, &regs, 
		sizeof(struct ppc64_pt_regs),
		"PPC64 pt_regs", FAULT_ON_ERROR);
	ip = regs.nip; 
	closest = closest_symbol(ip);
	if (STREQ(closest, ".__switch_to") || STREQ(closest, "__switch_to")) {
		/* NOTE: _switch_to() calls _switch() which
		 * is asm.  _switch leaves pc == lr.
		 * Working through this frame is tricky,
		 * and this mess isn't going to help if we
		 * actually dumped here.  Most likely the
		 * analyzer is trying to backtrace a task.
		 * Need to skip 2 frames.
		 */
		sp = stack[(sp - bt->stackbase)/sizeof(ulong)];
		if (!INSTACK(sp, bt))
			goto out;
		sp = stack[(sp - bt->stackbase)/sizeof(ulong)];
		if (!INSTACK(sp+16, bt))
			goto out;
		ip = stack[(sp + 16 - bt->stackbase)/sizeof(ulong)];
	} 
out:
	*getsp = sp;
	*getpc = ip;
}

/*
 *  Do the work for cmd_irq().
 */
static void 
ppc64_dump_irq(int irq)
{
        ulong irq_desc_addr, addr;
        int level, others;
        ulong action, ctl, value;
        char typename[32];

        irq_desc_addr = symbol_value("irq_desc") + (SIZE(irqdesc) * irq);

        readmem(irq_desc_addr + OFFSET(irqdesc_level), KVADDR, &level,
                sizeof(int), "irq_desc entry", FAULT_ON_ERROR);
        readmem(irq_desc_addr + OFFSET(irqdesc_action), KVADDR, &action,
                sizeof(long), "irq_desc entry", FAULT_ON_ERROR);
        readmem(irq_desc_addr + OFFSET(irqdesc_ctl), KVADDR, &ctl,
                sizeof(long), "irq_desc entry", FAULT_ON_ERROR);

        fprintf(fp, "    IRQ: %d\n", irq);
        fprintf(fp, " STATUS: 0\n");
        fprintf(fp, "HANDLER: ");

        if (value_symbol(ctl)) {
                fprintf(fp, "%lx  ", ctl);
                pad_line(fp, VADDR_PRLEN == 8 ?
                        VADDR_PRLEN+2 : VADDR_PRLEN-6, ' ');
                fprintf(fp, "<%s>\n", value_symbol(ctl));
        } else
                fprintf(fp, "%lx\n", ctl);

        if(ctl) {
                /* typename */
                readmem(ctl + OFFSET(hw_interrupt_type_typename), KVADDR, &addr,
                        sizeof(ulong), "typename pointer", FAULT_ON_ERROR);

		fprintf(fp, "         typename: %08lx  ", addr);
                if (read_string(addr, typename, 32))
                        fprintf(fp, "\"%s\"\n", typename);
		else
			fprintf(fp, "\n");

                /* startup...I think this is always 0 */
                readmem(ctl + OFFSET(hw_interrupt_type_startup), KVADDR, &addr,
                        sizeof(ulong), "interrupt startup", FAULT_ON_ERROR);
                fprintf(fp, "          startup: ");
                if(value_symbol(addr)) {
                        fprintf(fp, "%08lx  <%s>\n", addr, value_symbol(addr));
                } else
                        fprintf(fp, "%lx\n", addr);

               /* shutdown...I think this is always 0 */
                readmem(ctl + OFFSET(hw_interrupt_type_shutdown), KVADDR, &addr,
                        sizeof(ulong), "interrupt shutdown", FAULT_ON_ERROR);
                fprintf(fp, "         shutdown: ");
                if(value_symbol(addr)) {
                        fprintf(fp, "%08lx  <%s>\n", addr, value_symbol(addr));
                } else
                        fprintf(fp, "%lx\n", addr);

                if (VALID_MEMBER(hw_interrupt_type_handle)) {
                        /* handle */
                        readmem(ctl + OFFSET(hw_interrupt_type_handle),
                                KVADDR, &addr, sizeof(ulong),
                                "interrupt handle", FAULT_ON_ERROR);
                        fprintf(fp, "           handle: ");
                        if(value_symbol(addr)) {
                                fprintf(fp, "%08lx  <%s>\n", addr,
                                        value_symbol(addr));
                        } else
                                fprintf(fp, "%lx\n", addr);
                }

                /* enable/disable */
                readmem(ctl + OFFSET(hw_interrupt_type_enable), KVADDR, &addr,
                        sizeof(ulong), "interrupt enable", FAULT_ON_ERROR);
                fprintf(fp, "           enable: ");
                if(value_symbol(addr)) {
                        fprintf(fp, "%08lx  <%s>\n", addr, value_symbol(addr));
                } else
                        fprintf(fp, "%lx\n", addr);

                readmem(ctl + OFFSET(hw_interrupt_type_disable), KVADDR, &addr,
                        sizeof(ulong), "interrupt disable", FAULT_ON_ERROR);
                fprintf(fp, "          disable: ");
                if(value_symbol(addr)) {
                        fprintf(fp, "%08lx  <%s>\n", addr, value_symbol(addr));
                } else
                        fprintf(fp, "0\n");
        }

        /* next, the action... and its submembers */
        if(!action)
                fprintf(fp, " ACTION: (none)\n");

        while(action) {
                fprintf(fp, " ACTION: %08lx\n", action);
               /* handler */
                readmem(action + OFFSET(irqaction_handler), KVADDR, &addr,
                        sizeof(ulong), "action handler", FAULT_ON_ERROR);
                fprintf(fp, "          handler: ");
                if(value_symbol(addr)) {
                        fprintf(fp, "%08lx  <%s>\n", addr, value_symbol(addr));
                } else
                        fprintf(fp, "0\n");

                /* flags */
                readmem(action + OFFSET(irqaction_flags), KVADDR, &value,
                        sizeof(ulong), "action flags", FAULT_ON_ERROR);
                fprintf(fp, "            flags: %lx  ", value);

                if (value) {
                        others = 0;
                        fprintf(fp, "(");

                        if (value & SA_INTERRUPT)
                                fprintf(fp,
                                        "%sSA_INTERRUPT",
                                        others++ ? "|" : "");
                        if (value & SA_PROBE)
                                fprintf(fp,
                                        "%sSA_PROBE",
                                        others++ ? "|" : "");
                        if (value & SA_SAMPLE_RANDOM)
                                fprintf(fp,
                                        "%sSA_SAMPLE_RANDOM",
                                        others++ ? "|" : "");
                        if (value & SA_SHIRQ)
                                fprintf(fp,
                                        "%sSA_SHIRQ",
                                        others++ ? "|" : "");
                        fprintf(fp, ")");
                        if (value & ~ACTION_FLAGS) {
                                fprintf(fp,
                                        "  (bits %lx not translated)",
                                        value & ~ACTION_FLAGS);
                        }
                }

                fprintf(fp, "\n");

                /* mask */
                readmem(action + OFFSET(irqaction_mask), KVADDR, &value,
                        sizeof(ulong), "action mask", FAULT_ON_ERROR);
                fprintf(fp, "             mask: %lx\n", value);

                /* name */
                readmem(action + OFFSET(irqaction_name), KVADDR, &addr,
                        sizeof(ulong), "action name", FAULT_ON_ERROR);

		fprintf(fp, "             name: %08lx  ", addr);
		if (read_string(addr, typename, 32))
                        fprintf(fp, "\"%s\"\n", typename);
		else
			fprintf(fp, "\n");

                /* dev_id */
                readmem(action + OFFSET(irqaction_dev_id), KVADDR, &value,
                        sizeof(ulong), "action dev_id", FAULT_ON_ERROR);
                fprintf(fp, "           dev_id: %08lx\n", value);

                /* next */
                readmem(action + OFFSET(irqaction_next), KVADDR, &value,
                        sizeof(ulong), "action next", FAULT_ON_ERROR);
                fprintf(fp, "             next: %lx\n", value);

                /* keep going if there are chained interrupts */
                action = value;
        }

        fprintf(fp, "  DEPTH: %x\n\n", level);
}

/*
 *  Filter disassembly output if the output radix is not gdb's default 10
 */
static int 
ppc64_dis_filter(ulong vaddr, char *inbuf, unsigned int output_radix)
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
 *  (on alpha -- not necessarily seen on ppc64) so this routine both fixes the 
 *  references as well as imposing the current output radix on the translations.
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
		while ((p1 > inbuf) && !(STRNEQ(p1, " 0x") || STRNEQ(p1, ",0x"))) 
			p1--;

		if (!(STRNEQ(p1, " 0x") || STRNEQ(p1, ",0x")))
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
ppc64_get_smp_cpus(void)
{
	return get_cpus_online();
}


/*
 * Definitions derived from OPAL. These need to track corresponding values in
 * https://github.com/open-power/skiboot/blob/master/include/mem-map.h
 */
#define SKIBOOT_CONSOLE_DUMP_START	0x31000000
#define SKIBOOT_CONSOLE_DUMP_SIZE	0x100000
#define ASCII_UNLIMITED ((ulong)(-1) >> 1)

void
opalmsg(void)
{
	struct memloc {
		uint8_t u8;
		uint16_t u16;
		uint32_t u32;
		uint64_t u64;
		uint64_t limit64;
	};
	int i, a;
	size_t typesz;
	void *location;
	char readtype[20];
	struct memloc mem;
	int displayed, per_line;
	int lost;
	ulong error_handle;
	long count = SKIBOOT_CONSOLE_DUMP_SIZE;
	ulonglong addr = SKIBOOT_CONSOLE_DUMP_START;

	if (!(machdep->flags & OPAL_FW))
		error(FATAL, "dump was not captured on OPAL based system");

	if (CRASHDEBUG(4))
		fprintf(fp, "<addr: %llx count: %ld (%s)>\n",
				addr, count, "PHYSADDR");

	BZERO(&mem, sizeof(struct memloc));
	lost = typesz = per_line = 0;
	location = NULL;

	/* ASCII */
	typesz = SIZEOF_8BIT;
	location = &mem.u8;
	sprintf(readtype, "ascii");
	per_line = 256;
	displayed = 0;

	error_handle = FAULT_ON_ERROR;

	for (i = a = 0; i < count; i++) {
		if (!readmem(addr, PHYSADDR, location, typesz,
					readtype, error_handle)) {
			addr += typesz;
			lost += 1;
			continue;
		}

		if (isprint(mem.u8)) {
			if ((a % per_line) == 0) {
				if (displayed && i)
					fprintf(fp, "\n");
			}
			fprintf(fp, "%c", mem.u8);
			displayed++;
			a++;
		} else {
			if (count == ASCII_UNLIMITED)
				return;
			a = 0;
		}

		addr += typesz;
	}

	if (lost != count)
		fprintf(fp, "\n");
}

static void ppc64_print_emergency_stack_info(void)
{
	struct machine_specific *ms = machdep->machspec;
	char buf[32];
	int i;

	fprintf(fp, "    EMERGENCY STACK: ");
	if (ms->emergency_sp) {
		fprintf(fp, "\n");
		for (i = 0; i < kt->cpus; i++) {
			sprintf(buf, "CPU %d", i);
			fprintf(fp, "%19s: %lx\n", buf, ms->emergency_sp[i]);
		}
	} else
		fprintf(fp, "(unused)\n");

	fprintf(fp, "NMI EMERGENCY STACK: ");
	if (ms->nmi_emergency_sp) {
		fprintf(fp, "\n");
		for (i = 0; i < kt->cpus; i++) {
			sprintf(buf, "CPU %d", i);
			fprintf(fp, "%19s: %lx\n", buf, ms->nmi_emergency_sp[i]);
		}
	} else
		fprintf(fp, "(unused)\n");

	fprintf(fp, " MC EMERGENCY STACK: ");
	if (ms->mc_emergency_sp) {
		fprintf(fp, "\n");
		for (i = 0; i < kt->cpus; i++) {
			sprintf(buf, "CPU %d", i);
			fprintf(fp, "%19s: %lx\n", buf, ms->mc_emergency_sp[i]);
		}
	} else
		fprintf(fp, "(unused)\n");
	fprintf(fp, "\n");
}

/*
 *  Machine dependent command.
 */
void
ppc64_cmd_mach(void)
{
        int c;

	while ((c = getopt(argcnt, args, "cmo")) != EOF) {
                switch(c)
                {
		case 'c':
		case 'm':
			fprintf(fp, "PPC64: '-%c' option is not supported\n", 
				c);
			break;
		case 'o':
			return opalmsg();
                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

        ppc64_display_machine_stats();
}

/*
 *  "mach" command output.
 */
static void
ppc64_display_machine_stats(void)
{
	int c;
        struct new_utsname *uts;
        char buf[BUFSIZE];
        ulong mhz;

        uts = &kt->utsname;

        fprintf(fp, "       MACHINE TYPE: %s\n", uts->machine);
        fprintf(fp, "        MEMORY SIZE: %s\n", get_memory_size(buf));
	fprintf(fp, "               CPUS: %d\n", get_cpus_to_display());
        fprintf(fp, "    PROCESSOR SPEED: ");
        if ((mhz = machdep->processor_speed()))
                fprintf(fp, "%ld Mhz\n", mhz);
        else
                fprintf(fp, "(unknown)\n");
        fprintf(fp, "                 HZ: %d\n", machdep->hz);
	fprintf(fp, "                MMU: %s\n", machdep->flags & RADIX_MMU
							? "RADIX" : "HASH");
        fprintf(fp, "          PAGE SIZE: %d\n", PAGESIZE());
//      fprintf(fp, "      L1 CACHE SIZE: %d\n", l1_cache_size());
        fprintf(fp, "KERNEL VIRTUAL BASE: %lx\n", machdep->kvbase);
        fprintf(fp, "KERNEL VMALLOC BASE: %lx\n", vt->vmalloc_start);
        fprintf(fp, "  KERNEL STACK SIZE: %ld\n", STACKSIZE());

	if (tt->flags & IRQSTACKS) {
		fprintf(fp, "HARD IRQ STACK SIZE: %ld\n", STACKSIZE());
		fprintf(fp, "    HARD IRQ STACKS:\n");
	
		for (c = 0; c < kt->cpus; c++) {
			if (!tt->hardirq_ctx[c])
				break;
			sprintf(buf, "CPU %d", c);
			fprintf(fp, "%19s: %lx\n", buf, tt->hardirq_ctx[c]);
		}

		fprintf(fp, "SOFT IRQ STACK SIZE: %ld\n", STACKSIZE());
		fprintf(fp, "    SOFT IRQ STACKS:\n");
		for (c = 0; c < kt->cpus; c++) {
			if (!tt->softirq_ctx)
				break;
			sprintf(buf, "CPU %d", c);
			fprintf(fp, "%19s: %lx\n", buf, tt->softirq_ctx[c]);
		}
	}

	ppc64_print_emergency_stack_info();
}

static const char *hook_files[] = {
        "arch/ppc64/kernel/entry.S",
        "arch/ppc64/kernel/head.S",
        "arch/ppc64/kernel/semaphore.c"
};

#define ENTRY_S      ((char **)&hook_files[0])
#define HEAD_S       ((char **)&hook_files[1])
#define SEMAPHORE_C  ((char **)&hook_files[2])

static struct line_number_hook ppc64_line_number_hooks[] = {

	{"DoSyscall", ENTRY_S},
	{"_switch", ENTRY_S},
	{"ret_from_syscall_1", ENTRY_S},
	{"ret_from_syscall_2", ENTRY_S},
	{"ret_from_fork", ENTRY_S},
	{"ret_from_except", ENTRY_S},
	{"do_signal_ret", ENTRY_S},
	{"ret_to_user_hook", ENTRY_S},
	{"enter_rtas", ENTRY_S},
	{"restore", ENTRY_S},
	{"do_bottom_half_ret", ENTRY_S},
	{"ret_to_user_hook", ENTRY_S},

	{"_stext", HEAD_S},
	{"_start", HEAD_S},
	{"__start", HEAD_S},
	{"__secondary_hold", HEAD_S},

        {"DataAccessCont", HEAD_S},
        {"DataAccess", HEAD_S},
        {"i0x300", HEAD_S},
        {"DataSegmentCont", HEAD_S},
        {"InstructionAccessCont", HEAD_S},
        {"InstructionAccess", HEAD_S},
        {"i0x400", HEAD_S},
        {"InstructionSegmentCont", HEAD_S},
        {"HardwareInterrupt", HEAD_S},
        {"do_IRQ_intercept", HEAD_S},
        {"i0x600", HEAD_S},
        {"ProgramCheck", HEAD_S},
        {"i0x700", HEAD_S},
        {"FPUnavailable", HEAD_S},
        {"i0x800", HEAD_S},
        {"Decrementer", HEAD_S},
        {"timer_interrupt_intercept", HEAD_S},
        {"SystemCall", HEAD_S},
        {"trap_0f_cont", HEAD_S},
        {"Trap_0f", HEAD_S},
        {"InstructionTLBMiss", HEAD_S},
        {"InstructionAddressInvalid", HEAD_S},
        {"DataLoadTLBMiss", HEAD_S},
        {"DataAddressInvalid", HEAD_S},
        {"DataStoreTLBMiss", HEAD_S},
        {"AltiVecUnavailable", HEAD_S},
        {"DataAccess", HEAD_S},
        {"InstructionAccess", HEAD_S},
        {"DataSegment", HEAD_S},
        {"InstructionSegment", HEAD_S},
        {"transfer_to_handler", HEAD_S},
        {"stack_ovf", HEAD_S},
        {"load_up_fpu", HEAD_S},
        {"KernelFP", HEAD_S},
        {"load_up_altivec", HEAD_S},
        {"KernelAltiVec", HEAD_S},
        {"giveup_altivec", HEAD_S},
        {"giveup_fpu", HEAD_S},
        {"relocate_kernel", HEAD_S},
        {"copy_and_flush", HEAD_S},
        {"fix_mem_constants", HEAD_S},
        {"apus_interrupt_entry", HEAD_S},
        {"__secondary_start_gemini", HEAD_S},
        {"__secondary_start_psurge", HEAD_S},
        {"__secondary_start_psurge2", HEAD_S},
        {"__secondary_start_psurge3", HEAD_S},
        {"__secondary_start_psurge99", HEAD_S},
        {"__secondary_start", HEAD_S},
        {"setup_common_caches", HEAD_S},
        {"setup_604_hid0", HEAD_S},
        {"setup_750_7400_hid0", HEAD_S},
        {"load_up_mmu", HEAD_S},
        {"start_here", HEAD_S},
        {"clear_bats", HEAD_S},
        {"flush_tlbs", HEAD_S},
        {"mmu_off", HEAD_S},
        {"initial_bats", HEAD_S},
        {"setup_disp_bat", HEAD_S},
        {"m8260_gorom", HEAD_S},
        {"sdata", HEAD_S},
        {"empty_zero_page", HEAD_S},
        {"swapper_pg_dir", HEAD_S},
        {"cmd_line", HEAD_S},
        {"intercept_table", HEAD_S},
        {"set_context", HEAD_S},

       {NULL, NULL}    /* list must be NULL-terminated */
};

static void
ppc64_dump_line_number(ulong callpc)
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
                if (retries)
                        fprintf(fp, GDB_PATCHED() ?
                          "" : "    (cannot determine file and line number)\n");
                else {
                        retries++;
                        callpc = closest_symbol_value(callpc);
                        goto try_closest;
                }
        }
}

void
ppc64_compiler_warning_stub(void)
{
        struct line_number_hook *lhp;

        lhp = &ppc64_line_number_hooks[0]; lhp++;
	ppc64_back_trace(NULL, NULL);
	ppc64_dump_line_number(0);
}

/*
 *  Force the VM address-range selection via:
 *
 *   --machdep vm=orig 
 *   --machdep vm=2.6.14
 */

void
parse_cmdline_args(void)
{
	int index, i, c;
	char *p;
	char buf[BUFSIZE];
	char *arglist[MAXARGS];
	int lines = 0;

	for (index = 0; index < MAX_MACHDEP_ARGS; index++) {

		if (!machdep->cmdline_args[index])
			break;
	
		if (!strstr(machdep->cmdline_args[index], "=")) {
			error(WARNING, "ignoring --machdep option: %s\n\n",
				machdep->cmdline_args[index]);
			continue;
	        }
	
		strcpy(buf, machdep->cmdline_args[index]);
	
		for (p = buf; *p; p++) {
			if (*p == ',')
				 *p = ' ';
		}
	
		c = parse_line(buf, arglist);
	
		for (i = 0; i < c; i++) {
			if (STRNEQ(arglist[i], "vm=")) {
				p = arglist[i] + strlen("vm=");
				if (strlen(p)) {
					if (STREQ(p, "orig")) {
						machdep->flags |= VM_ORIG;
						continue;
					} else if (STREQ(p, "2.6.14")) {
						machdep->flags |= VM_4_LEVEL;
						continue;
					}
				}
			}
	
			error(WARNING, "ignoring --machdep option: %s\n", arglist[i]);
			lines++;
		} 
	
		switch (machdep->flags & (VM_ORIG|VM_4_LEVEL))
		{
		case VM_ORIG:
			error(NOTE, "using original PPC64 VM address ranges\n");
			lines++;
			break;
	
		case VM_4_LEVEL:
			error(NOTE, "using 4-level pagetable PPC64 VM address ranges\n");
			lines++;
			break;
	
		case (VM_ORIG|VM_4_LEVEL):
			error(WARNING, "cannot set both vm=orig and vm=2.6.14\n");
			lines++;
			machdep->flags &= ~(VM_ORIG|VM_4_LEVEL);
			break;
		} 
	
		if (lines)
			fprintf(fp, "\n");
	}
}

/*
 * Initialize the per cpu data_offset values from paca structure.
 */
static int
ppc64_paca_percpu_offset_init(int map)
{
	int i, cpus, nr_paca;
	char *cpu_paca_buf;
	ulong data_offset;
	ulong paca;

	if (!symbol_exists("paca"))
		error(FATAL, "PPC64: Could not find 'paca' symbol\n");

	/*
	 * In v2.6.34 ppc64, the upstream commit 1426d5a3 (powerpc: Dynamically
	 * allocate pacas) now dynamically allocates the paca and have
	 * changed data type of 'paca' symbol from array to pointer. With this
	 * change in place crash utility fails to read vmcore generated for
	 * upstream kernel.
	 * Add a check for paca variable data type before accessing.
	 */
	if (get_symbol_type("paca", NULL, NULL) == TYPE_CODE_PTR)
		readmem(symbol_value("paca"), KVADDR, &paca, sizeof(ulong),
				"paca", FAULT_ON_ERROR);
	else
		paca = symbol_value("paca");

	if (!MEMBER_EXISTS("paca_struct", "data_offset"))
		return kt->cpus;
	
	STRUCT_SIZE_INIT(ppc64_paca, "paca_struct");
	data_offset = MEMBER_OFFSET("paca_struct", "data_offset");

	cpu_paca_buf = GETBUF(SIZE(ppc64_paca));

	if (!(nr_paca = get_array_length("paca", NULL, 0)))
		nr_paca = (kt->kernel_NR_CPUS ? kt->kernel_NR_CPUS : NR_CPUS);

	if (nr_paca > NR_CPUS) {
		error(WARNING, 
			"PPC64: Number of paca entries (%d) greater than NR_CPUS (%d)\n", 
			nr_paca, NR_CPUS);
		error(FATAL, "Recompile crash with larger NR_CPUS\n");
	}
	
	for (i = cpus = 0; i < nr_paca; i++) {
		/*
		 * CPU present or online or can exist in the system(possible)?
		 */
		if (!in_cpu_map(map, i))
			continue;

		readmem(paca + (i * SIZE(ppc64_paca)),
             		KVADDR, cpu_paca_buf, SIZE(ppc64_paca),
			"paca entry", FAULT_ON_ERROR);

		kt->__per_cpu_offset[i] = ULONG(cpu_paca_buf + data_offset);
		kt->flags |= PER_CPU_OFF;
		cpus++;
	}
	return cpus;
}

static int
ppc64_get_cpu_map(void)
{
	int map;

	if (cpu_map_addr("possible"))
		map = POSSIBLE_MAP;
	else if (cpu_map_addr("present"))
		map = PRESENT_MAP;
	else if (cpu_map_addr("online"))
		map = ONLINE_MAP;
	else if (cpu_map_addr("active"))
		map = ACTIVE_MAP;
	else {
		map = 0;
		error(FATAL,
			"PPC64: cannot find 'cpu_possible_map', "
			"'cpu_present_map', 'cpu_online_map' or 'cpu_active_map' symbols\n");
	}
	return map;
}

/*
 *  Updating any smp-related items that were possibly bypassed
 *  or improperly initialized in kernel_init().
 */
static void
ppc64_init_cpu_info(void)
{
	int i, map, cpus, nr_cpus;

	map = ppc64_get_cpu_map();
	/*
	 * starting from v2.6.36 we can not rely on paca structure to get
	 * per cpu data_offset. The upstream commit fc53b420 overwrites
	 * the paca pointer variable to point to static paca that contains
	 * valid data_offset only for crashing cpu.
	 *
	 * But the kernel v2.6.36 ppc64 introduces __per_cpu_offset symbol
	 * which was removed post v2.6.15 ppc64 and now we get the per cpu
	 * data_offset from __per_cpu_offset symbol during kernel_init()
	 * call. Hence for backward (pre-2.6.36) compatibility, call
	 * ppc64_paca_percpu_offset_init() only if symbol __per_cpu_offset
	 * does not exist.
	 */
	if (!symbol_exists("__per_cpu_offset"))
		cpus = ppc64_paca_percpu_offset_init(map);
	else {
		if (!(nr_cpus = get_array_length("__per_cpu_offset", NULL, 0)))
			nr_cpus = (kt->kernel_NR_CPUS ? kt->kernel_NR_CPUS :
							NR_CPUS);
		for (i = cpus = 0; i < nr_cpus; i++) {
			if (!in_cpu_map(map, i))
				continue;
			cpus++;
		}
	}
	switch (map)
	{
	case POSSIBLE_MAP:
		if (cpus > kt->cpus) {
			i = get_highest_cpu_online() + 1;
			if (i > kt->cpus)
				kt->cpus = i;
		}
		break;
	case ONLINE_MAP:
	case PRESENT_MAP:
		kt->cpus = cpus;
		break;
	}
	if (kt->cpus > 1)
		kt->flags |= SMP;
}

void
ppc64_clear_machdep_cache(void)
{
	if (machdep->last_pgd_read != vt->kernel_pgd[0])
		machdep->last_pgd_read = 0;
}

static int 
ppc64_get_kvaddr_ranges(struct vaddr_range *vrp)
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

	if (machdep->flags & VMEMMAP) {
 		phys1 = (physaddr_t)(0);
		phys2 = (physaddr_t)VTOP((vt->high_memory - PAGESIZE()));
		if (phys_to_page(phys1, &pp1) && 
	    	    phys_to_page(phys2, &pp2)) {
			vrp[cnt].type = KVADDR_VMEMMAP;
			vrp[cnt].start = pp1;
			vrp[cnt++].end = pp2;
		}
	}

	return cnt;
}
#endif /* PPC64 */ 
