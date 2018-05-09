/*
 * arm64.c - core analysis suite
 *
 * Copyright (C) 2012-2018 David Anderson
 * Copyright (C) 2012-2018 Red Hat, Inc. All rights reserved.
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

#ifdef ARM64

#include "defs.h"
#include <elf.h>
#include <endian.h>
#include <sys/ioctl.h>

#define NOT_IMPLEMENTED(X) error((X), "%s: function not implemented\n", __func__)

static struct machine_specific arm64_machine_specific = { 0 };
static int arm64_verify_symbol(const char *, ulong, char);
static void arm64_parse_cmdline_args(void);
static void arm64_calc_kimage_voffset(void);
static void arm64_calc_phys_offset(void);
static void arm64_calc_virtual_memory_ranges(void);
static int arm64_kdump_phys_base(ulong *);
static ulong arm64_processor_speed(void);
static void arm64_init_kernel_pgd(void);
static int arm64_kvtop(struct task_context *, ulong, physaddr_t *, int);
static int arm64_uvtop(struct task_context *, ulong, physaddr_t *, int);
static int arm64_vtop_2level_64k(ulong, ulong, physaddr_t *, int);
static int arm64_vtop_3level_64k(ulong, ulong, physaddr_t *, int);
static int arm64_vtop_3level_4k(ulong, ulong, physaddr_t *, int);
static int arm64_vtop_4level_4k(ulong, ulong, physaddr_t *, int);
static ulong arm64_get_task_pgd(ulong);
static void arm64_irq_stack_init(void);
static void arm64_stackframe_init(void);
static int arm64_eframe_search(struct bt_info *);
static int arm64_is_kernel_exception_frame(struct bt_info *, ulong);
static int arm64_in_exception_text(ulong);
static int arm64_in_exp_entry(ulong);
static void arm64_back_trace_cmd(struct bt_info *);
static void arm64_back_trace_cmd_v2(struct bt_info *);
static void arm64_print_text_symbols(struct bt_info *, struct arm64_stackframe *, FILE *);
static int arm64_print_stackframe_entry(struct bt_info *, int, struct arm64_stackframe *, FILE *);
static int arm64_print_stackframe_entry_v2(struct bt_info *, int, struct arm64_stackframe *, FILE *);
static void arm64_display_full_frame(struct bt_info *, ulong);
static void arm64_display_full_frame_v2(struct bt_info *, struct arm64_stackframe *, struct arm64_stackframe *);
static int arm64_unwind_frame(struct bt_info *, struct arm64_stackframe *);
static int arm64_unwind_frame_v2(struct bt_info *, struct arm64_stackframe *, FILE *);
static int arm64_get_dumpfile_stackframe(struct bt_info *, struct arm64_stackframe *);
static int arm64_in_kdump_text(struct bt_info *, struct arm64_stackframe *);
static int arm64_in_kdump_text_on_irq_stack(struct bt_info *);
static int arm64_switch_stack(struct bt_info *, struct arm64_stackframe *, FILE *);
static int arm64_get_stackframe(struct bt_info *, struct arm64_stackframe *);
static void arm64_get_stack_frame(struct bt_info *, ulong *, ulong *);
static void arm64_gen_hidden_frame(struct bt_info *bt, ulong, struct arm64_stackframe *);
static void arm64_print_exception_frame(struct bt_info *, ulong, int, FILE *);
static void arm64_do_bt_reference_check(struct bt_info *, ulong, char *);
static int arm64_translate_pte(ulong, void *, ulonglong);
static ulong arm64_vmalloc_start(void);
static int arm64_is_task_addr(ulong);
static int arm64_dis_filter(ulong, char *, unsigned int);
static void arm64_cmd_mach(void);
static void arm64_display_machine_stats(void);
static int arm64_get_smp_cpus(void);
static void arm64_clear_machdep_cache(void);
static int arm64_on_process_stack(struct bt_info *, ulong);
static int arm64_in_alternate_stack(int, ulong);
static int arm64_on_irq_stack(int, ulong);
static void arm64_set_irq_stack(struct bt_info *);
static void arm64_set_process_stack(struct bt_info *);
static int arm64_get_kvaddr_ranges(struct vaddr_range *);
static int arm64_get_crash_notes(void);
static void arm64_calc_VA_BITS(void);
static int arm64_is_uvaddr(ulong, struct task_context *);


/*
 * Do all necessary machine-specific setup here. This is called several times
 * during initialization.
 */
void
arm64_init(int when)
{
	ulong value;
	char *string;
	struct machine_specific *ms;

#if defined(__x86_64__)
	if (ACTIVE())
		error(FATAL, "compiled for the ARM64 architecture\n");
#endif

	switch (when) {
	case SETUP_ENV:
		machdep->process_elf_notes = process_elf64_notes;
		break;

	case PRE_SYMTAB:
		machdep->machspec = &arm64_machine_specific;
		machdep->verify_symbol = arm64_verify_symbol;
		if (pc->flags & KERNEL_DEBUG_QUERY)
			return;
		machdep->verify_paddr = generic_verify_paddr;
		if (machdep->cmdline_args[0])
			arm64_parse_cmdline_args();
		machdep->flags |= MACHDEP_BT_TEXT;

		ms = machdep->machspec;

		if (!ms->kimage_voffset && STREQ(pc->live_memsrc, "/dev/crash"))
			ioctl(pc->mfd, DEV_CRASH_ARCH_DATA, &ms->kimage_voffset);

		if (!ms->kimage_voffset &&
		    (string = pc->read_vmcoreinfo("NUMBER(kimage_voffset)"))) {
			ms->kimage_voffset = htol(string, QUIET, NULL);
			free(string);
		}

		if (ms->kimage_voffset) {
			machdep->flags |= NEW_VMEMMAP;

			/*
			 * Even if CONFIG_RANDOMIZE_BASE is not configured,
			 * derive_kaslr_offset() should work and set
			 * kt->relocate to 0
			 */
			if (!kt->relocate && !(kt->flags2 & (RELOC_AUTO|KASLR)))
				kt->flags2 |= (RELOC_AUTO|KASLR);
		}

		break;

	case PRE_GDB:
		if (kernel_symbol_exists("kimage_voffset"))
			machdep->flags |= NEW_VMEMMAP;

		if (!machdep->pagesize) {
			/*
			 * Kerneldoc Documentation/arm64/booting.txt describes
			 * the kernel image header flags field.
			 */
			value = machdep->machspec->kernel_flags;
			value = (value >> 1) & 3;

			switch(value)
			{
			case 0:
				break;
			case 1:
				machdep->pagesize = 4096;
				break;
			case 2:
				/* TODO: machdep->pagesize = 16384; */
				error(FATAL, "16K pages not supported.");
				break;
			case 3:
				machdep->pagesize = 65536;
				break;
			}

		}

		if (!machdep->pagesize &&
		    kernel_symbol_exists("swapper_pg_dir") &&
		    kernel_symbol_exists("idmap_pg_dir")) {
			if (kernel_symbol_exists("tramp_pg_dir"))
				value = symbol_value("tramp_pg_dir");
			else if (kernel_symbol_exists("reserved_ttbr0"))
				value = symbol_value("reserved_ttbr0");
			else
				value = symbol_value("swapper_pg_dir");

			value -= symbol_value("idmap_pg_dir");
			/*
			 * idmap_pg_dir is 2 pages prior to 4.1,
			 * and 3 pages thereafter.  Only 4K and 64K 
			 * page sizes are supported.
			 */
			switch (value)
			{
			case (4096 * 2):
			case (4096 * 3):
				machdep->pagesize = 4096;
				break;
			case (65536 * 2):
			case (65536 * 3):
				machdep->pagesize = 65536;
				break;
			}
		} else if (ACTIVE())
			machdep->pagesize = memory_page_size();   /* host */

		machdep->pageshift = ffs(machdep->pagesize) - 1;
		machdep->pageoffset = machdep->pagesize - 1;
		machdep->pagemask = ~((ulonglong)machdep->pageoffset);

		arm64_calc_VA_BITS();
		ms = machdep->machspec;
		ms->page_offset = ARM64_PAGE_OFFSET;
		machdep->identity_map_base = ARM64_PAGE_OFFSET;
		machdep->kvbase = ARM64_VA_START;
		ms->userspace_top = ARM64_USERSPACE_TOP;
		if (machdep->flags & NEW_VMEMMAP) {
			struct syment *sp;

			sp = kernel_symbol_search("_text");
			ms->kimage_text = (sp ? sp->value : 0);
			sp = kernel_symbol_search("_end");
			ms->kimage_end = (sp ? sp->value : 0);

			ms->modules_vaddr = ARM64_VA_START;
			if (kernel_symbol_exists("kasan_init"))
				ms->modules_vaddr += ARM64_KASAN_SHADOW_SIZE;
			ms->modules_end = ms->modules_vaddr
						+ ARM64_MODULES_VSIZE -1;

			ms->vmalloc_start_addr = ms->modules_end + 1;

			arm64_calc_kimage_voffset();
		} else {
			ms->modules_vaddr = ARM64_PAGE_OFFSET - MEGABYTES(64);
			ms->modules_end = ARM64_PAGE_OFFSET - 1;
			ms->vmalloc_start_addr = ARM64_VA_START;
		}
		ms->vmalloc_end = ARM64_VMALLOC_END;
		ms->vmemmap_vaddr = ARM64_VMEMMAP_VADDR;
		ms->vmemmap_end = ARM64_VMEMMAP_END;

		switch (machdep->pagesize)
		{
		case 4096:
			machdep->ptrs_per_pgd = PTRS_PER_PGD_L3_4K;
			if ((machdep->pgd = 
			    (char *)malloc(PTRS_PER_PGD_L3_4K * 8)) == NULL)
				error(FATAL, "cannot malloc pgd space.");
			if (machdep->machspec->VA_BITS > PGDIR_SHIFT_L4_4K) {
				machdep->flags |= VM_L4_4K;
				if ((machdep->pud =
				    (char *)malloc(PTRS_PER_PUD_L4_4K * 8))
				    == NULL)
					error(FATAL, "cannot malloc pud space.");
			} else {
				machdep->flags |= VM_L3_4K;
				machdep->pud = NULL;  /* not used */
			}
			if ((machdep->pmd = 
			    (char *)malloc(PTRS_PER_PMD_L3_4K * 8)) == NULL)
				error(FATAL, "cannot malloc pmd space.");
			if ((machdep->ptbl = 
			    (char *)malloc(PTRS_PER_PTE_L3_4K * 8)) == NULL)
				error(FATAL, "cannot malloc ptbl space.");
			break;

		case 65536:
			if (machdep->machspec->VA_BITS > PGDIR_SHIFT_L3_64K) {
				machdep->flags |= VM_L3_64K;
				machdep->ptrs_per_pgd = PTRS_PER_PGD_L3_64K;
				if ((machdep->pgd =
				    (char *)malloc(PTRS_PER_PGD_L3_64K * 8)) == NULL)
					error(FATAL, "cannot malloc pgd space.");
				if ((machdep->pmd =
				    (char *)malloc(PTRS_PER_PMD_L3_64K * 8)) == NULL)
					error(FATAL, "cannot malloc pmd space.");
				if ((machdep->ptbl =
				    (char *)malloc(PTRS_PER_PTE_L3_64K * 8)) == NULL)
					error(FATAL, "cannot malloc ptbl space.");
			} else {
				machdep->flags |= VM_L2_64K;
				machdep->ptrs_per_pgd = PTRS_PER_PGD_L2_64K;
				if ((machdep->pgd =
				    (char *)malloc(PTRS_PER_PGD_L2_64K * 8)) == NULL)
					error(FATAL, "cannot malloc pgd space.");
				if ((machdep->ptbl =
				    (char *)malloc(PTRS_PER_PTE_L2_64K * 8)) == NULL)
					error(FATAL, "cannot malloc ptbl space.");
				machdep->pmd = NULL;  /* not used */
			}
			machdep->pud = NULL;  /* not used */
			break;

		default:
			if (machdep->pagesize)
				error(FATAL, "invalid/unsupported page size: %d\n", 
					machdep->pagesize);
			else
				error(FATAL, "cannot determine page size\n");
		}

		machdep->last_pgd_read = 0;
		machdep->last_pud_read = 0;
		machdep->last_pmd_read = 0;
		machdep->last_ptbl_read = 0;
		machdep->clear_machdep_cache = arm64_clear_machdep_cache;

		machdep->stacksize = ARM64_STACK_SIZE;
		machdep->flags |= VMEMMAP;

		machdep->uvtop = arm64_uvtop;
		machdep->kvtop = arm64_kvtop;
		machdep->is_kvaddr = generic_is_kvaddr;
		machdep->is_uvaddr = arm64_is_uvaddr;
		machdep->eframe_search = arm64_eframe_search;
		machdep->back_trace = arm64_back_trace_cmd;
		machdep->in_alternate_stack = arm64_in_alternate_stack;
		machdep->processor_speed = arm64_processor_speed;
		machdep->get_task_pgd = arm64_get_task_pgd;
		machdep->get_stack_frame = arm64_get_stack_frame;
		machdep->get_stackbase = generic_get_stackbase;
		machdep->get_stacktop = generic_get_stacktop;
		machdep->translate_pte = arm64_translate_pte;
		machdep->memory_size = generic_memory_size;
		machdep->vmalloc_start = arm64_vmalloc_start;
		machdep->get_kvaddr_ranges = arm64_get_kvaddr_ranges;
		machdep->is_task_addr = arm64_is_task_addr;
		machdep->dis_filter = arm64_dis_filter;
		machdep->cmd_mach = arm64_cmd_mach;
		machdep->get_smp_cpus = arm64_get_smp_cpus;
		machdep->line_number_hooks = NULL;
		machdep->value_to_symbol = generic_machdep_value_to_symbol;
		machdep->dump_irq = generic_dump_irq;
		machdep->show_interrupts = generic_show_interrupts;
		machdep->get_irq_affinity = generic_get_irq_affinity;
		machdep->dumpfile_init = NULL;
		machdep->verify_line_number = NULL;
		machdep->init_kernel_pgd = arm64_init_kernel_pgd;

		/* use machdep parameters */
		arm64_calc_phys_offset();
	
		if (CRASHDEBUG(1)) {
			if (machdep->flags & NEW_VMEMMAP)
				fprintf(fp, "kimage_voffset: %lx\n", 
					machdep->machspec->kimage_voffset);
			fprintf(fp, "phys_offset: %lx\n", 
				machdep->machspec->phys_offset);
		}

		break;

	case POST_GDB:
		arm64_calc_virtual_memory_ranges();
		machdep->section_size_bits = _SECTION_SIZE_BITS;
		if (THIS_KERNEL_VERSION >= LINUX(3,17,0))
			machdep->max_physmem_bits = _MAX_PHYSMEM_BITS_3_17;
		else
			machdep->max_physmem_bits = _MAX_PHYSMEM_BITS;
		ms = machdep->machspec;

		if (THIS_KERNEL_VERSION >= LINUX(4,0,0)) {
			ms->__SWP_TYPE_BITS = 6;
			ms->__SWP_TYPE_SHIFT = 2;
			ms->__SWP_TYPE_MASK = ((1UL << ms->__SWP_TYPE_BITS) - 1);
			ms->__SWP_OFFSET_SHIFT = (ms->__SWP_TYPE_BITS + ms->__SWP_TYPE_SHIFT);
			ms->__SWP_OFFSET_BITS = 50;
			ms->__SWP_OFFSET_MASK = ((1UL << ms->__SWP_OFFSET_BITS) - 1);
			ms->PTE_PROT_NONE = (1UL << 58); 
			ms->PTE_FILE = 0;  /* unused */
		} else if (THIS_KERNEL_VERSION >= LINUX(3,13,0)) {
			ms->__SWP_TYPE_BITS = 6;
			ms->__SWP_TYPE_SHIFT = 3;
			ms->__SWP_TYPE_MASK = ((1UL << ms->__SWP_TYPE_BITS) - 1);
			ms->__SWP_OFFSET_SHIFT = (ms->__SWP_TYPE_BITS + ms->__SWP_TYPE_SHIFT);
			ms->__SWP_OFFSET_BITS = 49;
			ms->__SWP_OFFSET_MASK = ((1UL << ms->__SWP_OFFSET_BITS) - 1);
			ms->PTE_PROT_NONE = (1UL << 58); 
			ms->PTE_FILE = (1UL << 2);
		} else if (THIS_KERNEL_VERSION >= LINUX(3,11,0)) {
			ms->__SWP_TYPE_BITS = 6;
			ms->__SWP_TYPE_SHIFT = 4;
			ms->__SWP_TYPE_MASK = ((1UL << ms->__SWP_TYPE_BITS) - 1);
			ms->__SWP_OFFSET_SHIFT = (ms->__SWP_TYPE_BITS + ms->__SWP_TYPE_SHIFT);
			ms->__SWP_OFFSET_BITS = 0;  /* unused */ 
			ms->__SWP_OFFSET_MASK = 0;  /* unused */ 
			ms->PTE_PROT_NONE = (1UL << 2); 
			ms->PTE_FILE = (1UL << 3);
		} else {
			ms->__SWP_TYPE_BITS = 6;
			ms->__SWP_TYPE_SHIFT = 3;
			ms->__SWP_TYPE_MASK = ((1UL << ms->__SWP_TYPE_BITS) - 1);
			ms->__SWP_OFFSET_SHIFT = (ms->__SWP_TYPE_BITS + ms->__SWP_TYPE_SHIFT);
			ms->__SWP_OFFSET_BITS = 0;  /* unused */ 
			ms->__SWP_OFFSET_MASK = 0;  /* unused */
			ms->PTE_PROT_NONE = (1UL << 1); 
			ms->PTE_FILE = (1UL << 2);
		}

		if (symbol_exists("irq_desc"))
			ARRAY_LENGTH_INIT(machdep->nr_irqs, irq_desc,
				  "irq_desc", NULL, 0);
		else if (kernel_symbol_exists("nr_irqs"))
			get_symbol_data("nr_irqs", sizeof(unsigned int),
				&machdep->nr_irqs);

		if (!machdep->hz)
			machdep->hz = 100;

		arm64_irq_stack_init();
		arm64_stackframe_init();
		break;

	case POST_VM:
		/*
		 * crash_notes contains machine specific information about the
		 * crash. In particular, it contains CPU registers at the time
		 * of the crash. We need this information to extract correct
		 * backtraces from the panic task.
		 */
		if (!LIVE() && !arm64_get_crash_notes())
			error(WARNING, 
			    "cannot retrieve registers for active task%s\n\n",
				kt->cpus > 1 ? "s" : "");

		break;

	case LOG_ONLY:
		machdep->machspec = &arm64_machine_specific;
		arm64_calc_VA_BITS();
		arm64_calc_phys_offset();
		machdep->machspec->page_offset = ARM64_PAGE_OFFSET;
		break;
	}
}

/*
 * Accept or reject a symbol from the kernel namelist.
 */
static int
arm64_verify_symbol(const char *name, ulong value, char type)
{
	if (!name || !strlen(name))
		return FALSE;

	if ((type == 'A') && STREQ(name, "_kernel_flags_le"))
		machdep->machspec->kernel_flags = le64toh(value);

	if ((type == 'A') && STREQ(name, "_kernel_flags_le_hi32"))
		machdep->machspec->kernel_flags |= ((ulong)le32toh(value) << 32);

	if ((type == 'A') && STREQ(name, "_kernel_flags_le_lo32"))
		machdep->machspec->kernel_flags |= le32toh(value);

	if (((type == 'A') || (type == 'a')) && (highest_bit_long(value) != 63))
		return FALSE;

	if ((value == 0) && 
	    ((type == 'a') || (type == 'n') || (type == 'N') || (type == 'U')))
		return FALSE;

	if (STREQ(name, "$d") || STREQ(name, "$x"))
		return FALSE;
	
	if ((type == 'A') && STRNEQ(name, "__crc_"))
		return FALSE;

	if ((type == 'N') && strstr(name, "$d"))
		return FALSE;

	if (!(machdep->flags & KSYMS_START) && STREQ(name, "idmap_pg_dir"))
		machdep->flags |= KSYMS_START;

	return TRUE;
}


void
arm64_dump_machdep_table(ulong arg)
{
	const struct machine_specific *ms;
	int others, i;

	others = 0;
	fprintf(fp, "               flags: %lx (", machdep->flags);
	if (machdep->flags & KSYMS_START)
		fprintf(fp, "%sKSYMS_START", others++ ? "|" : "");
	if (machdep->flags & PHYS_OFFSET)
		fprintf(fp, "%sPHYS_OFFSET", others++ ? "|" : "");
	if (machdep->flags & VM_L2_64K)
		fprintf(fp, "%sVM_L2_64K", others++ ? "|" : "");
	if (machdep->flags & VM_L3_64K)
		fprintf(fp, "%sVM_L3_64K", others++ ? "|" : "");
	if (machdep->flags & VM_L3_4K)
		fprintf(fp, "%sVM_L3_4K", others++ ? "|" : "");
	if (machdep->flags & VM_L4_4K)
		fprintf(fp, "%sVM_L4_4K", others++ ? "|" : "");
	if (machdep->flags & VMEMMAP)
		fprintf(fp, "%sVMEMMAP", others++ ? "|" : "");
	if (machdep->flags & KDUMP_ENABLED)
		fprintf(fp, "%sKDUMP_ENABLED", others++ ? "|" : "");
	if (machdep->flags & IRQ_STACKS)
		fprintf(fp, "%sIRQ_STACKS", others++ ? "|" : "");
	if (machdep->flags & UNW_4_14)
		fprintf(fp, "%sUNW_4_14", others++ ? "|" : "");
	if (machdep->flags & MACHDEP_BT_TEXT)
		fprintf(fp, "%sMACHDEP_BT_TEXT", others++ ? "|" : "");
	if (machdep->flags & NEW_VMEMMAP)
		fprintf(fp, "%sNEW_VMEMMAP", others++ ? "|" : "");
	fprintf(fp, ")\n");

	fprintf(fp, "              kvbase: %lx\n", machdep->kvbase);
	fprintf(fp, "   identity_map_base: %lx\n", machdep->identity_map_base);
	fprintf(fp, "            pagesize: %d\n", machdep->pagesize);
	fprintf(fp, "           pageshift: %d\n", machdep->pageshift);
	fprintf(fp, "            pagemask: %lx\n", (ulong)machdep->pagemask);
	fprintf(fp, "          pageoffset: %lx\n", machdep->pageoffset);
	fprintf(fp, "           stacksize: %ld\n", machdep->stacksize);
	fprintf(fp, "                  hz: %d\n", machdep->hz);
	fprintf(fp, "                 mhz: %ld\n", machdep->mhz);
	fprintf(fp, "             memsize: %lld (0x%llx)\n",
		(ulonglong)machdep->memsize, (ulonglong)machdep->memsize);
	fprintf(fp, "                bits: %d\n", machdep->bits);
	fprintf(fp, "             nr_irqs: %d\n", machdep->nr_irqs);
	fprintf(fp, "       eframe_search: arm64_eframe_search()\n");
	fprintf(fp, "          back_trace: arm64_back_trace_cmd() (default: %s method)\n",
		kt->flags & USE_OPT_BT ? "optional" : "original");
	fprintf(fp, "  in_alternate_stack: arm64_in_alternate_stack()\n");
	fprintf(fp, "     processor_speed: arm64_processor_speed()\n");
	fprintf(fp, "               uvtop: arm64_uvtop()->%s()\n",
		machdep->flags & VM_L3_4K ? 
		"arm64_vtop_3level_4k" :
		machdep->flags & VM_L4_4K ?
		"arm64_vtop_4level_4k" :
		machdep->flags & VM_L3_64K ?
		"arm64_vtop_3level_64k" : "arm64_vtop_2level_64k");
	fprintf(fp, "               kvtop: arm64_kvtop()->%s()\n",
		machdep->flags & VM_L3_4K ? 
		"arm64_vtop_3level_4k" :
		machdep->flags & VM_L4_4K ?
		"arm64_vtop_4level_4k" :
		machdep->flags & VM_L3_64K ?
		"arm64_vtop_3level_64k" : "arm64_vtop_2level_64k");
	fprintf(fp, "        get_task_pgd: arm64_get_task_pgd()\n");
	fprintf(fp, "            dump_irq: generic_dump_irq()\n");
	fprintf(fp, "     get_stack_frame: arm64_get_stack_frame()\n");
	fprintf(fp, "       get_stackbase: generic_get_stackbase()\n");
	fprintf(fp, "        get_stacktop: generic_get_stacktop()\n");
	fprintf(fp, "       translate_pte: arm64_translate_pte()\n");
	fprintf(fp, "         memory_size: generic_memory_size()\n");
	fprintf(fp, "       vmalloc_start: arm64_vmalloc_start()\n");
	fprintf(fp, "   get_kvaddr_ranges: arm64_get_kvaddr_ranges()\n");
	fprintf(fp, "        is_task_addr: arm64_is_task_addr()\n");
	fprintf(fp, "       verify_symbol: arm64_verify_symbol()\n");
	fprintf(fp, "          dis_filter: arm64_dis_filter()\n");
	fprintf(fp, "            cmd_mach: arm64_cmd_mach()\n");
	fprintf(fp, "        get_smp_cpus: arm64_get_smp_cpus()\n");
	fprintf(fp, "           is_kvaddr: generic_is_kvaddr()\n");
	fprintf(fp, "           is_uvaddr: arm64_is_uvaddr()\n");
	fprintf(fp, "     value_to_symbol: generic_machdep_value_to_symbol()\n");
	fprintf(fp, "     init_kernel_pgd: arm64_init_kernel_pgd\n");
	fprintf(fp, "        verify_paddr: generic_verify_paddr()\n");
	fprintf(fp, "     show_interrupts: generic_show_interrupts()\n");
	fprintf(fp, "    get_irq_affinity: generic_get_irq_affinity()\n");
	fprintf(fp, "       dumpfile_init: (not used)\n");
	fprintf(fp, "   process_elf_notes: process_elf64_notes()\n");
	fprintf(fp, "  verify_line_number: (not used)\n");

	fprintf(fp, "  xendump_p2m_create: (n/a)\n");
	fprintf(fp, "xen_kdump_p2m_create: (n/a)\n");
        fprintf(fp, "  xendump_panic_task: (n/a)\n");
        fprintf(fp, "    get_xendump_regs: (n/a)\n");
	fprintf(fp, "   line_number_hooks: (not used)\n");
	fprintf(fp, "       last_pgd_read: %lx\n", machdep->last_pgd_read);
	fprintf(fp, "       last_pud_read: ");
	if ((PAGESIZE() == 65536) ||
	    ((PAGESIZE() == 4096) && !(machdep->flags & VM_L4_4K)))
		fprintf(fp, "(not used)\n");
	else
		fprintf(fp, "%lx\n", machdep->last_pud_read);
	fprintf(fp, "       last_pmd_read: ");
	if (PAGESIZE() == 65536)
		fprintf(fp, "(not used)\n");
	else
		fprintf(fp, "%lx\n", machdep->last_pmd_read);
	fprintf(fp, "      last_ptbl_read: %lx\n", machdep->last_ptbl_read);
	fprintf(fp, " clear_machdep_cache: arm64_clear_machdep_cache()\n");
	fprintf(fp, "                 pgd: %lx\n", (ulong)machdep->pgd);
	fprintf(fp, "                 pud: %lx\n", (ulong)machdep->pud);
	fprintf(fp, "                 pmd: %lx\n", (ulong)machdep->pmd);
	fprintf(fp, "                ptbl: %lx\n", (ulong)machdep->ptbl);
	fprintf(fp, "        ptrs_per_pgd: %d\n", machdep->ptrs_per_pgd);
	fprintf(fp, "   section_size_bits: %ld\n", machdep->section_size_bits);
	fprintf(fp, "    max_physmem_bits: %ld\n", machdep->max_physmem_bits);
	fprintf(fp, "   sections_per_root: %ld\n", machdep->sections_per_root);

	for (i = 0; i < MAX_MACHDEP_ARGS; i++) {
		fprintf(fp, "     cmdline_args[%d]: %s\n",
			i, machdep->cmdline_args[i] ?
			machdep->cmdline_args[i] : "(unused)");
	}

	ms = machdep->machspec;

	fprintf(fp, "            machspec: %lx\n", (ulong)ms);
	fprintf(fp, "               VA_BITS: %ld\n", ms->VA_BITS);
	fprintf(fp, "         userspace_top: %016lx\n", ms->userspace_top);
	fprintf(fp, "           page_offset: %016lx\n", ms->page_offset);
	fprintf(fp, "    vmalloc_start_addr: %016lx\n", ms->vmalloc_start_addr);
	fprintf(fp, "           vmalloc_end: %016lx\n", ms->vmalloc_end);
	fprintf(fp, "         modules_vaddr: %016lx\n", ms->modules_vaddr);
	fprintf(fp, "           modules_end: %016lx\n", ms->modules_end);
	fprintf(fp, "         vmemmap_vaddr: %016lx\n", ms->vmemmap_vaddr);
	fprintf(fp, "           vmemmap_end: %016lx\n", ms->vmemmap_end);
	if (machdep->flags & NEW_VMEMMAP) {
		fprintf(fp, "           kimage_text: %016lx\n", ms->kimage_text);
		fprintf(fp, "            kimage_end: %016lx\n", ms->kimage_end);
		fprintf(fp, "        kimage_voffset: %016lx\n", ms->kimage_voffset);
	}
	fprintf(fp, "           phys_offset: %lx\n", ms->phys_offset);
	fprintf(fp, "__exception_text_start: %lx\n", ms->__exception_text_start);
	fprintf(fp, "  __exception_text_end: %lx\n", ms->__exception_text_end);
	fprintf(fp, " __irqentry_text_start: %lx\n", ms->__irqentry_text_start);
	fprintf(fp, "   __irqentry_text_end: %lx\n", ms->__irqentry_text_end);
	fprintf(fp, "      exp_entry1_start: %lx\n", ms->exp_entry1_start);
	fprintf(fp, "        exp_entry1_end: %lx\n", ms->exp_entry1_end);
	fprintf(fp, "      exp_entry2_start: %lx\n", ms->exp_entry2_start);
	fprintf(fp, "        exp_entry2_end: %lx\n", ms->exp_entry2_end);
	fprintf(fp, "       panic_task_regs: %lx\n", (ulong)ms->panic_task_regs);
	fprintf(fp, "    user_eframe_offset: %ld\n", ms->user_eframe_offset);
	fprintf(fp, "    kern_eframe_offset: %ld\n", ms->kern_eframe_offset);
	fprintf(fp, "         PTE_PROT_NONE: %lx\n", ms->PTE_PROT_NONE);
	fprintf(fp, "              PTE_FILE: ");
	if (ms->PTE_FILE)
		fprintf(fp, "%lx\n", ms->PTE_FILE);
	else
		fprintf(fp, "(unused)\n");
        fprintf(fp, "       __SWP_TYPE_BITS: %ld\n", ms->__SWP_TYPE_BITS);
        fprintf(fp, "      __SWP_TYPE_SHIFT: %ld\n", ms->__SWP_TYPE_SHIFT);
        fprintf(fp, "       __SWP_TYPE_MASK: %lx\n", ms->__SWP_TYPE_MASK);
        fprintf(fp, "     __SWP_OFFSET_BITS: ");
	if (ms->__SWP_OFFSET_BITS)
        	fprintf(fp, "%ld\n", ms->__SWP_OFFSET_BITS);
	else
		fprintf(fp, "(unused)\n");
        fprintf(fp, "    __SWP_OFFSET_SHIFT: %ld\n", ms->__SWP_OFFSET_SHIFT);
	fprintf(fp, "     __SWP_OFFSET_MASK: ");
	if (ms->__SWP_OFFSET_MASK)
        	fprintf(fp, "%lx\n", ms->__SWP_OFFSET_MASK);
	else
		fprintf(fp, "(unused)\n");
	fprintf(fp, "   machine_kexec_start: %lx\n", ms->machine_kexec_start);
	fprintf(fp, "     machine_kexec_end: %lx\n", ms->machine_kexec_end);
	fprintf(fp, "     crash_kexec_start: %lx\n", ms->crash_kexec_start);
	fprintf(fp, "       crash_kexec_end: %lx\n", ms->crash_kexec_end);
	fprintf(fp, "  crash_save_cpu_start: %lx\n", ms->crash_save_cpu_start);
	fprintf(fp, "    crash_save_cpu_end: %lx\n", ms->crash_save_cpu_end);
	fprintf(fp, "          kernel_flags: %lx\n", ms->kernel_flags);
	fprintf(fp, "          irq_stackbuf: %lx\n", (ulong)ms->irq_stackbuf);
	if (machdep->flags & IRQ_STACKS) {
		fprintf(fp, "        irq_stack_size: %ld\n", ms->irq_stack_size);
		for (i = 0; i < kt->cpus; i++)
			fprintf(fp, "         irq_stacks[%d]: %lx\n", 
				i, ms->irq_stacks[i]);
	} else {
		fprintf(fp, "        irq_stack_size: (unused)\n");
		fprintf(fp, "            irq_stacks: (unused)\n");
	}
}

static int
arm64_parse_machdep_arg_l(char *argstring, char *param, ulong *value)
{
	int len;
	int megabytes = FALSE;
	char *p;

	len = strlen(param);
	if (!STRNEQ(argstring, param) || (argstring[len] != '='))
		return FALSE;

	if ((LASTCHAR(argstring) == 'm') ||
	    (LASTCHAR(argstring) == 'M')) {
		LASTCHAR(argstring) = NULLCHAR;
		megabytes = TRUE;
	}

	p = argstring + len + 1;
	if (strlen(p)) {
		int flags = RETURN_ON_ERROR | QUIET;
		int err = 0;

		if (megabytes) {
			*value = dtol(p, flags, &err);
			if (!err)
				*value = MEGABYTES(*value);
		} else {
			*value = htol(p, flags, &err);
		}

		if (!err)
			return TRUE;
	}

	return FALSE;
}

/*
 * Parse machine dependent command line arguments.
 *
 * Force the phys_offset address via:
 *
 *  --machdep phys_offset=<address>
 */
static void
arm64_parse_cmdline_args(void)
{
	int index, i, c;
	char *arglist[MAXARGS];
	char buf[BUFSIZE];
	char *p;

	for (index = 0; index < MAX_MACHDEP_ARGS; index++) {
		if (!machdep->cmdline_args[index])
			break;

		if (!strstr(machdep->cmdline_args[index], "=")) {
			error(WARNING, "ignoring --machdep option: %x\n",
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
			if (arm64_parse_machdep_arg_l(arglist[i], "phys_offset",
				&machdep->machspec->phys_offset)) {
				error(NOTE,
					"setting phys_offset to: 0x%lx\n\n",
					machdep->machspec->phys_offset);
				machdep->flags |= PHYS_OFFSET;
				continue;
			} else if (arm64_parse_machdep_arg_l(arglist[i], "kimage_voffset",
			        &machdep->machspec->kimage_voffset)) {
				error(NOTE,
					"setting kimage_voffset to: 0x%lx\n\n",
					machdep->machspec->kimage_voffset);
				continue;
			}

			error(WARNING, "ignoring --machdep option: %s\n",
				arglist[i]);
		}
	}
}

static void
arm64_calc_kimage_voffset(void)
{
	struct machine_specific *ms = machdep->machspec;
	ulong phys_addr;

	if (ms->kimage_voffset) /* vmcoreinfo, ioctl, or --machdep override */
		return;

	if (ACTIVE()) {
		char buf[BUFSIZE];
		char *p1;
		int errflag;
		FILE *iomem;

		if ((iomem = fopen("/proc/iomem", "r")) == NULL)
			return;

		errflag = 1;
		while (fgets(buf, BUFSIZE, iomem)) {
			if(strstr(buf, ": Kernel code")) {
				errflag = 0;
				break;
			}
			if (strstr(buf, ": System RAM")) {
				clean_line(buf);

				if (!(p1 = strstr(buf, "-")))
					continue;

				*p1 = NULLCHAR;

				phys_addr = htol(buf, RETURN_ON_ERROR | QUIET, NULL);
				if (phys_addr == BADADDR)
					continue;
			}
		}
		fclose(iomem);

		if (errflag)
			return;

	} else if (KDUMP_DUMPFILE())
		arm_kdump_phys_base(&phys_addr);  /* Get start address of first memory block */
	else {
		error(WARNING,
			"kimage_voffset cannot be determined from the dumpfile.\n");
		error(CONT,
			"Using default value of 0.  If this is not correct, then try\n");
		error(CONT,
			"using the command line option: --machdep kimage_voffset=<addr>\n");
		return;
	}

	ms->kimage_voffset = ms->vmalloc_start_addr - phys_addr;

	if ((kt->flags2 & KASLR) && (kt->flags & RELOC_SET))
		ms->kimage_voffset += (kt->relocate * -1);
}

static void
arm64_calc_phys_offset(void)
{
	struct machine_specific *ms = machdep->machspec;
	ulong phys_offset;

	if (machdep->flags & PHYS_OFFSET) /* --machdep override */
		return;

	/*
	 * Next determine suitable value for phys_offset. User can override this
	 * by passing valid '--machdep phys_offset=<addr>' option.
	 */
	ms->phys_offset = 0;

	if (ACTIVE()) {
		char buf[BUFSIZE];
		char *p1;
		int errflag;
		FILE *iomem;
		physaddr_t paddr;
		struct syment *sp;

		if ((machdep->flags & NEW_VMEMMAP) &&
		    ms->kimage_voffset && (sp = kernel_symbol_search("memstart_addr"))) {
			if (pc->flags & PROC_KCORE)
				paddr = KCORE_USE_VADDR;
			else
				paddr =	sp->value - machdep->machspec->kimage_voffset;
			if (READMEM(pc->mfd, &phys_offset, sizeof(phys_offset),
			    sp->value, paddr) > 0) {
				ms->phys_offset = phys_offset;
				return;
			}
		}

		if ((iomem = fopen("/proc/iomem", "r")) == NULL)
			return;

		/*
		 * Memory regions are sorted in ascending order. We take the
		 * first region which should be correct for most uses.
		 */
		errflag = 1;
		while (fgets(buf, BUFSIZE, iomem)) {
			if (strstr(buf, ": System RAM")) {
				clean_line(buf);
				errflag = 0;
				break;
			}
		}
		fclose(iomem);

		if (errflag)
			return;

		if (!(p1 = strstr(buf, "-")))
			return;

		*p1 = NULLCHAR;

		phys_offset = htol(buf, RETURN_ON_ERROR | QUIET, &errflag);
		if (errflag)
			return;

		ms->phys_offset = phys_offset;
	} else if (DISKDUMP_DUMPFILE() && diskdump_phys_base(&phys_offset)) {
		ms->phys_offset = phys_offset;
	} else if (KDUMP_DUMPFILE() && arm64_kdump_phys_base(&phys_offset)) {
		ms->phys_offset = phys_offset;
	} else {
		error(WARNING,
			"phys_offset cannot be determined from the dumpfile.\n");
		error(CONT,
			"Using default value of 0.  If this is not correct, then try\n");
		error(CONT,
			"using the command line option: --machdep phys_offset=<addr>\n");
	}

	if (CRASHDEBUG(1))
		fprintf(fp, "using %lx as phys_offset\n", ms->phys_offset);
}


/*
 *  Determine PHYS_OFFSET either by reading VMCOREINFO or the kernel
 *  symbol, otherwise borrow the 32-bit ARM functionality.
 */
static int
arm64_kdump_phys_base(ulong *phys_offset)
{
	char *string;
	struct syment *sp;
	physaddr_t paddr;

	if ((string = pc->read_vmcoreinfo("NUMBER(PHYS_OFFSET)"))) {
		*phys_offset = htol(string, QUIET, NULL);
		free(string);
		return TRUE;
	}

	if ((machdep->flags & NEW_VMEMMAP) &&
	    machdep->machspec->kimage_voffset &&
	    (sp = kernel_symbol_search("memstart_addr"))) {
		paddr =	sp->value - machdep->machspec->kimage_voffset;
		if (READMEM(-1, phys_offset, sizeof(*phys_offset),
		    sp->value, paddr) > 0)
			return TRUE;
	}

	return arm_kdump_phys_base(phys_offset);
}

static void
arm64_init_kernel_pgd(void)
{
	int i;
	ulong value;

	if (!kernel_symbol_exists("init_mm") ||
	    !readmem(symbol_value("init_mm") + OFFSET(mm_struct_pgd), KVADDR,
	    &value, sizeof(void *), "init_mm.pgd", RETURN_ON_ERROR)) {
		if (kernel_symbol_exists("swapper_pg_dir"))
			value = symbol_value("swapper_pg_dir");
		else {
			error(WARNING, "cannot determine kernel pgd location\n");
			return;
		}
	}

        for (i = 0; i < NR_CPUS; i++)
                vt->kernel_pgd[i] = value;
}

ulong
arm64_VTOP(ulong addr)
{
	if (machdep->flags & NEW_VMEMMAP) {
		if (addr >= machdep->machspec->page_offset)
			return machdep->machspec->phys_offset
				+ (addr - machdep->machspec->page_offset);
		else if (machdep->machspec->kimage_voffset)
			return addr - machdep->machspec->kimage_voffset;
		else /* no randomness */
			return machdep->machspec->phys_offset
				+ (addr - machdep->machspec->vmalloc_start_addr);
	} else {
		return machdep->machspec->phys_offset
			+ (addr - machdep->machspec->page_offset);
	}
}

static int
arm64_kvtop(struct task_context *tc, ulong kvaddr, physaddr_t *paddr, int verbose)
{
	ulong kernel_pgd;

	if (!IS_KVADDR(kvaddr))
		return FALSE;

	if (!vt->vmalloc_start) {
		*paddr = VTOP(kvaddr);
		return TRUE;
	}

	if (!IS_VMALLOC_ADDR(kvaddr)) {
		*paddr = VTOP(kvaddr);
		if (!verbose)
			return TRUE;
	}

	kernel_pgd = vt->kernel_pgd[0];
	*paddr = 0;

	switch (machdep->flags & (VM_L2_64K|VM_L3_64K|VM_L3_4K|VM_L4_4K))
	{
	case VM_L2_64K:
		return arm64_vtop_2level_64k(kernel_pgd, kvaddr, paddr, verbose);
	case VM_L3_64K:
		return arm64_vtop_3level_64k(kernel_pgd, kvaddr, paddr, verbose);
	case VM_L3_4K:
		return arm64_vtop_3level_4k(kernel_pgd, kvaddr, paddr, verbose);
	case VM_L4_4K:
		return arm64_vtop_4level_4k(kernel_pgd, kvaddr, paddr, verbose);
	default:
		return FALSE;
	}
}

static int
arm64_uvtop(struct task_context *tc, ulong uvaddr, physaddr_t *paddr, int verbose)
{
        ulong user_pgd;

        readmem(tc->mm_struct + OFFSET(mm_struct_pgd), KVADDR,
                &user_pgd, sizeof(long), "user pgd", FAULT_ON_ERROR);

	*paddr = 0;

	switch (machdep->flags & (VM_L2_64K|VM_L3_64K|VM_L3_4K|VM_L4_4K))
	{
	case VM_L2_64K:
		return arm64_vtop_2level_64k(user_pgd, uvaddr, paddr, verbose);
	case VM_L3_64K:
		return arm64_vtop_3level_64k(user_pgd, uvaddr, paddr, verbose);
	case VM_L3_4K:
		return arm64_vtop_3level_4k(user_pgd, uvaddr, paddr, verbose);
	case VM_L4_4K:
		return arm64_vtop_4level_4k(user_pgd, uvaddr, paddr, verbose);
	default:
		return FALSE;
	}
}

#define PMD_TYPE_MASK   3
#define PMD_TYPE_SECT   1
#define PMD_TYPE_TABLE  2
#define SECTION_PAGE_MASK_2MB    ((long)(~((MEGABYTES(2))-1)))
#define SECTION_PAGE_MASK_512MB  ((long)(~((MEGABYTES(512))-1)))

static int 
arm64_vtop_2level_64k(ulong pgd, ulong vaddr, physaddr_t *paddr, int verbose)
{
	ulong *pgd_base, *pgd_ptr, pgd_val;
	ulong *pte_base, *pte_ptr, pte_val;

        if (verbose)
                fprintf(fp, "PAGE DIRECTORY: %lx\n", pgd);

	pgd_base = (ulong *)pgd;
	FILL_PGD(pgd_base, KVADDR, PTRS_PER_PGD_L2_64K * sizeof(ulong));
	pgd_ptr = pgd_base + (((vaddr) >> PGDIR_SHIFT_L2_64K) & (PTRS_PER_PGD_L2_64K - 1));
        pgd_val = ULONG(machdep->pgd + PAGEOFFSET(pgd_ptr));
        if (verbose) 
                fprintf(fp, "   PGD: %lx => %lx\n", (ulong)pgd_ptr, pgd_val);
	if (!pgd_val)
		goto no_page;

	/* 
	 * #define __PAGETABLE_PUD_FOLDED 
	 * #define __PAGETABLE_PMD_FOLDED 
	 */

	if ((pgd_val & PMD_TYPE_MASK) == PMD_TYPE_SECT) {
		ulong sectionbase = (pgd_val & SECTION_PAGE_MASK_512MB) & PHYS_MASK;
		if (verbose) {
			fprintf(fp, "  PAGE: %lx  (512MB)\n\n", sectionbase);
			arm64_translate_pte(pgd_val, 0, 0);
		}
		*paddr = sectionbase + (vaddr & ~SECTION_PAGE_MASK_512MB);
		return TRUE;
	}

	pte_base = (ulong *)PTOV(pgd_val & PHYS_MASK & (s32)machdep->pagemask);
	FILL_PTBL(pte_base, KVADDR, PTRS_PER_PTE_L2_64K * sizeof(ulong));
	pte_ptr = pte_base + (((vaddr) >> machdep->pageshift) & (PTRS_PER_PTE_L2_64K - 1));
        pte_val = ULONG(machdep->ptbl + PAGEOFFSET(pte_ptr));
        if (verbose) 
                fprintf(fp, "   PTE: %lx => %lx\n", (ulong)pte_ptr, pte_val);
	if (!pte_val)
		goto no_page;

	if (pte_val & PTE_VALID) {
		*paddr = (PAGEBASE(pte_val) & PHYS_MASK) + PAGEOFFSET(vaddr);
		if (verbose) {
			fprintf(fp, "  PAGE: %lx\n\n", PAGEBASE(*paddr));
			arm64_translate_pte(pte_val, 0, 0);
		}
	} else {
		if (IS_UVADDR(vaddr, NULL))
			*paddr = pte_val;
		if (verbose) {
			fprintf(fp, "\n");
			arm64_translate_pte(pte_val, 0, 0);
		}
		goto no_page;
	}

	return TRUE;
no_page:
	return FALSE;
}

static int
arm64_vtop_3level_64k(ulong pgd, ulong vaddr, physaddr_t *paddr, int verbose)
{
	ulong *pgd_base, *pgd_ptr, pgd_val;
	ulong *pmd_base, *pmd_ptr, pmd_val;
	ulong *pte_base, *pte_ptr, pte_val;

        if (verbose)
                fprintf(fp, "PAGE DIRECTORY: %lx\n", pgd);

	pgd_base = (ulong *)pgd;
	FILL_PGD(pgd_base, KVADDR, PTRS_PER_PGD_L3_64K * sizeof(ulong));
	pgd_ptr = pgd_base + (((vaddr) >> PGDIR_SHIFT_L3_64K) & (PTRS_PER_PGD_L3_64K - 1));
        pgd_val = ULONG(machdep->pgd + PGDIR_OFFSET_L3_64K(pgd_ptr));
        if (verbose)
                fprintf(fp, "   PGD: %lx => %lx\n", (ulong)pgd_ptr, pgd_val);
	if (!pgd_val)
		goto no_page;

	/*
	 * #define __PAGETABLE_PUD_FOLDED
	 */

	pmd_base = (ulong *)PTOV(pgd_val & PHYS_MASK & (s32)machdep->pagemask);
	FILL_PMD(pmd_base, KVADDR, PTRS_PER_PMD_L3_64K * sizeof(ulong));
	pmd_ptr = pmd_base + (((vaddr) >> PMD_SHIFT_L3_64K) & (PTRS_PER_PMD_L3_64K - 1));
        pmd_val = ULONG(machdep->pmd + PAGEOFFSET(pmd_ptr));
        if (verbose)
                fprintf(fp, "   PMD: %lx => %lx\n", (ulong)pmd_ptr, pmd_val);
	if (!pmd_val)
		goto no_page;

	if ((pmd_val & PMD_TYPE_MASK) == PMD_TYPE_SECT) {
		ulong sectionbase = (pmd_val & SECTION_PAGE_MASK_512MB) & PHYS_MASK;
		if (verbose) {
			fprintf(fp, "  PAGE: %lx  (512MB)\n\n", sectionbase);
			arm64_translate_pte(pmd_val, 0, 0);
		}
		*paddr = sectionbase + (vaddr & ~SECTION_PAGE_MASK_512MB);
		return TRUE;
	}

	pte_base = (ulong *)PTOV(pmd_val & PHYS_MASK & (s32)machdep->pagemask);
	FILL_PTBL(pte_base, KVADDR, PTRS_PER_PTE_L3_64K * sizeof(ulong));
	pte_ptr = pte_base + (((vaddr) >> machdep->pageshift) & (PTRS_PER_PTE_L3_64K - 1));
        pte_val = ULONG(machdep->ptbl + PAGEOFFSET(pte_ptr));
        if (verbose)
                fprintf(fp, "   PTE: %lx => %lx\n", (ulong)pte_ptr, pte_val);
	if (!pte_val)
		goto no_page;

	if (pte_val & PTE_VALID) {
		*paddr = (PAGEBASE(pte_val) & PHYS_MASK) + PAGEOFFSET(vaddr);
		if (verbose) {
			fprintf(fp, "  PAGE: %lx\n\n", PAGEBASE(*paddr));
			arm64_translate_pte(pte_val, 0, 0);
		}
	} else {
		if (IS_UVADDR(vaddr, NULL))
			*paddr = pte_val;
		if (verbose) {
			fprintf(fp, "\n");
			arm64_translate_pte(pte_val, 0, 0);
		}
		goto no_page;
	}

	return TRUE;
no_page:
	return FALSE;
}

static int 
arm64_vtop_3level_4k(ulong pgd, ulong vaddr, physaddr_t *paddr, int verbose)
{
	ulong *pgd_base, *pgd_ptr, pgd_val;
	ulong *pmd_base, *pmd_ptr, pmd_val;
	ulong *pte_base, *pte_ptr, pte_val;

        if (verbose)
                fprintf(fp, "PAGE DIRECTORY: %lx\n", pgd);

	pgd_base = (ulong *)pgd;
	FILL_PGD(pgd_base, KVADDR, PTRS_PER_PGD_L3_4K * sizeof(ulong));
	pgd_ptr = pgd_base + (((vaddr) >> PGDIR_SHIFT_L3_4K) & (PTRS_PER_PGD_L3_4K - 1));
        pgd_val = ULONG(machdep->pgd + PAGEOFFSET(pgd_ptr));
        if (verbose) 
                fprintf(fp, "   PGD: %lx => %lx\n", (ulong)pgd_ptr, pgd_val);
	if (!pgd_val)
		goto no_page;

	/* 
	 * #define __PAGETABLE_PUD_FOLDED 
	 */

	pmd_base = (ulong *)PTOV(pgd_val & PHYS_MASK & (s32)machdep->pagemask);
	FILL_PMD(pmd_base, KVADDR, PTRS_PER_PMD_L3_4K * sizeof(ulong));
	pmd_ptr = pmd_base + (((vaddr) >> PMD_SHIFT_L3_4K) & (PTRS_PER_PMD_L3_4K - 1));
        pmd_val = ULONG(machdep->pmd + PAGEOFFSET(pmd_ptr));
        if (verbose) 
                fprintf(fp, "   PMD: %lx => %lx\n", (ulong)pmd_ptr, pmd_val);
	if (!pmd_val)
		goto no_page;

	if ((pmd_val & PMD_TYPE_MASK) == PMD_TYPE_SECT) {
		ulong sectionbase = (pmd_val & SECTION_PAGE_MASK_2MB) & PHYS_MASK;
		if (verbose) {
			fprintf(fp, "  PAGE: %lx  (2MB)\n\n", sectionbase);
			arm64_translate_pte(pmd_val, 0, 0);
		}
		*paddr = sectionbase + (vaddr & ~SECTION_PAGE_MASK_2MB);
		return TRUE;
	}

	pte_base = (ulong *)PTOV(pmd_val & PHYS_MASK & (s32)machdep->pagemask);
	FILL_PTBL(pte_base, KVADDR, PTRS_PER_PTE_L3_4K * sizeof(ulong));
	pte_ptr = pte_base + (((vaddr) >> machdep->pageshift) & (PTRS_PER_PTE_L3_4K - 1));
        pte_val = ULONG(machdep->ptbl + PAGEOFFSET(pte_ptr));
        if (verbose) 
                fprintf(fp, "   PTE: %lx => %lx\n", (ulong)pte_ptr, pte_val);
	if (!pte_val)
		goto no_page;

	if (pte_val & PTE_VALID) {
		*paddr = (PAGEBASE(pte_val) & PHYS_MASK) + PAGEOFFSET(vaddr);
		if (verbose) {
			fprintf(fp, "  PAGE: %lx\n\n", PAGEBASE(*paddr));
			arm64_translate_pte(pte_val, 0, 0);
		}
	} else {
		if (IS_UVADDR(vaddr, NULL))
			*paddr = pte_val;
		if (verbose) {
			fprintf(fp, "\n");
			arm64_translate_pte(pte_val, 0, 0);
		}
		goto no_page;
	}

	return TRUE;
no_page:
	return FALSE;
}

static int
arm64_vtop_4level_4k(ulong pgd, ulong vaddr, physaddr_t *paddr, int verbose)
{
	ulong *pgd_base, *pgd_ptr, pgd_val;
	ulong *pud_base, *pud_ptr, pud_val;
	ulong *pmd_base, *pmd_ptr, pmd_val;
	ulong *pte_base, *pte_ptr, pte_val;

        if (verbose)
                fprintf(fp, "PAGE DIRECTORY: %lx\n", pgd);

	pgd_base = (ulong *)pgd;
	FILL_PGD(pgd_base, KVADDR, PTRS_PER_PGD_L4_4K * sizeof(ulong));
	pgd_ptr = pgd_base + (((vaddr) >> PGDIR_SHIFT_L4_4K) & (PTRS_PER_PGD_L4_4K - 1));
        pgd_val = ULONG(machdep->pgd + PGDIR_OFFSET_48VA(pgd_ptr));
        if (verbose)
                fprintf(fp, "   PGD: %lx => %lx\n", (ulong)pgd_ptr, pgd_val);
	if (!pgd_val)
		goto no_page;

	pud_base = (ulong *)PTOV(pgd_val & PHYS_MASK & PGDIR_MASK_48VA);

	FILL_PUD(pud_base, KVADDR, PTRS_PER_PUD_L4_4K * sizeof(ulong));
	pud_ptr = pud_base + (((vaddr) >> PUD_SHIFT_L4_4K) & (PTRS_PER_PUD_L4_4K - 1));
        pud_val = ULONG(machdep->pud + PAGEOFFSET(pud_ptr));
        if (verbose)
                fprintf(fp, "   PUD: %lx => %lx\n", (ulong)pud_ptr, pud_val);
	if (!pud_val)
		goto no_page;

	pmd_base = (ulong *)PTOV(pud_val & PHYS_MASK & (s32)machdep->pagemask);
	FILL_PMD(pmd_base, KVADDR, PTRS_PER_PMD_L4_4K * sizeof(ulong));
	pmd_ptr = pmd_base + (((vaddr) >> PMD_SHIFT_L4_4K) & (PTRS_PER_PMD_L4_4K - 1));
        pmd_val = ULONG(machdep->pmd + PAGEOFFSET(pmd_ptr));
        if (verbose)
                fprintf(fp, "   PMD: %lx => %lx\n", (ulong)pmd_ptr, pmd_val);
	if (!pmd_val)
		goto no_page;

	if ((pmd_val & PMD_TYPE_MASK) == PMD_TYPE_SECT) {
		ulong sectionbase = (pmd_val & SECTION_PAGE_MASK_2MB) & PHYS_MASK;
		if (verbose) {
			fprintf(fp, "  PAGE: %lx  (2MB)\n\n", sectionbase);
			arm64_translate_pte(pmd_val, 0, 0);
		}
		*paddr = sectionbase + (vaddr & ~SECTION_PAGE_MASK_2MB);
		return TRUE;
	}

	pte_base = (ulong *)PTOV(pmd_val & PHYS_MASK & (s32)machdep->pagemask);
	FILL_PTBL(pte_base, KVADDR, PTRS_PER_PTE_L4_4K * sizeof(ulong));
	pte_ptr = pte_base + (((vaddr) >> machdep->pageshift) & (PTRS_PER_PTE_L4_4K - 1));
        pte_val = ULONG(machdep->ptbl + PAGEOFFSET(pte_ptr));
        if (verbose)
                fprintf(fp, "   PTE: %lx => %lx\n", (ulong)pte_ptr, pte_val);
	if (!pte_val)
		goto no_page;

	if (pte_val & PTE_VALID) {
		*paddr = (PAGEBASE(pte_val) & PHYS_MASK) + PAGEOFFSET(vaddr);
		if (verbose) {
			fprintf(fp, "  PAGE: %lx\n\n", PAGEBASE(*paddr));
			arm64_translate_pte(pte_val, 0, 0);
		}
	} else {
		if (IS_UVADDR(vaddr, NULL))
			*paddr = pte_val;
		if (verbose) {
			fprintf(fp, "\n");
			arm64_translate_pte(pte_val, 0, 0);
		}
		goto no_page;
	}

	return TRUE;
no_page:
	return FALSE;
}

static ulong 
arm64_get_task_pgd(ulong task)
{
	struct task_context *tc;
	ulong pgd;

	if ((tc = task_to_context(task)) &&
	    readmem(tc->mm_struct + OFFSET(mm_struct_pgd), KVADDR,
	    &pgd, sizeof(long), "user pgd", RETURN_ON_ERROR))
		return pgd;
	else
		return NO_TASK;
}

static ulong 
arm64_processor_speed(void) 
{
	return 0;
};

/*
 *  Gather IRQ stack values.
 */
static void
arm64_irq_stack_init(void)
{
	int i;
	struct syment *sp;
	struct gnu_request request, *req;
	struct machine_specific *ms = machdep->machspec;
	ulong p, sz;
	req = &request;

	if (symbol_exists("irq_stack") &&
	    (sp = per_cpu_symbol_search("irq_stack")) &&
	    get_symbol_type("irq_stack", NULL, req)) {
		/* before v4.14 or CONFIG_VMAP_STACK disabled */
		if (CRASHDEBUG(1)) {
			fprintf(fp, "irq_stack: \n");
			fprintf(fp, "  type: %s\n",
				(req->typecode == TYPE_CODE_ARRAY) ?
						"TYPE_CODE_ARRAY" : "other");
			fprintf(fp, "  target_typecode: %s\n",
				req->target_typecode == TYPE_CODE_INT ?
						"TYPE_CODE_INT" : "other");
			fprintf(fp, "  target_length: %ld\n",
						req->target_length);
			fprintf(fp, "  length: %ld\n", req->length);
		}

		if (!(ms->irq_stacks = (ulong *)malloc((size_t)(kt->cpus * sizeof(ulong)))))
			error(FATAL, "cannot malloc irq_stack addresses\n");
		ms->irq_stack_size = req->length;
		machdep->flags |= IRQ_STACKS;

		for (i = 0; i < kt->cpus; i++)
			ms->irq_stacks[i] = kt->__per_cpu_offset[i] + sp->value;
	} else if (symbol_exists("irq_stack_ptr") &&
	    (sp = per_cpu_symbol_search("irq_stack_ptr")) &&
	    get_symbol_type("irq_stack_ptr", NULL, req)) {
		/* v4.14 and later with CONFIG_VMAP_STACK enabled */
		if (CRASHDEBUG(1)) {
			fprintf(fp, "irq_stack_ptr: \n");
			fprintf(fp, "  type: %x, %s\n",
				(int)req->typecode,
				(req->typecode == TYPE_CODE_PTR) ?
						"TYPE_CODE_PTR" : "other");
			fprintf(fp, "  target_typecode: %x, %s\n",
				(int)req->target_typecode,
				req->target_typecode == TYPE_CODE_INT ?
						"TYPE_CODE_INT" : "other");
			fprintf(fp, "  target_length: %ld\n",
						req->target_length);
			fprintf(fp, "  length: %ld\n", req->length);
		}

		if (!(ms->irq_stacks = (ulong *)malloc((size_t)(kt->cpus * sizeof(ulong)))))
			error(FATAL, "cannot malloc irq_stack addresses\n");

		/*
		 *  Determining the IRQ_STACK_SIZE is tricky, but for now
		 *  4.14 kernel has:
		 *
		 *    #define IRQ_STACK_SIZE          THREAD_SIZE
		 *
		 *  and finding a solid usage of THREAD_SIZE is hard, but:   
		 *
		 *    union thread_union {
		 *            ... 
	         *            unsigned long stack[THREAD_SIZE/sizeof(long)];
		 *    };
		 */
		if (MEMBER_EXISTS("thread_union", "stack")) { 
			if ((sz = MEMBER_SIZE("thread_union", "stack")) > 0)
				ms->irq_stack_size = sz;
		} else
			ms->irq_stack_size = ARM64_IRQ_STACK_SIZE;

		machdep->flags |= IRQ_STACKS;

		for (i = 0; i < kt->cpus; i++) {
			p = kt->__per_cpu_offset[i] + sp->value;
			readmem(p, KVADDR, &(ms->irq_stacks[i]), sizeof(ulong),
			    "IRQ stack pointer", RETURN_ON_ERROR);
		}
	} 
}

/*
 *  Gather and verify all of the backtrace requirements.
 */
static void
arm64_stackframe_init(void)
{
	long task_struct_thread;
	long thread_struct_cpu_context;
	long context_sp, context_pc, context_fp;
	struct syment *sp1, *sp1n, *sp2, *sp2n, *sp3, *sp3n;

	STRUCT_SIZE_INIT(note_buf, "note_buf_t");
	STRUCT_SIZE_INIT(elf_prstatus, "elf_prstatus");
	MEMBER_OFFSET_INIT(elf_prstatus_pr_pid, "elf_prstatus", "pr_pid");
	MEMBER_OFFSET_INIT(elf_prstatus_pr_reg, "elf_prstatus", "pr_reg");

	if (MEMBER_EXISTS("pt_regs", "stackframe")) {
		machdep->machspec->user_eframe_offset = SIZE(pt_regs);
		machdep->machspec->kern_eframe_offset = SIZE(pt_regs) - 16;
	} else {
		machdep->machspec->user_eframe_offset = SIZE(pt_regs) + 16;
		machdep->machspec->kern_eframe_offset = SIZE(pt_regs);
	}

	machdep->machspec->__exception_text_start = 
		symbol_value("__exception_text_start");
	machdep->machspec->__exception_text_end = 
		symbol_value("__exception_text_end");
	if ((sp1 = kernel_symbol_search("__irqentry_text_start")) &&
	    (sp2 = kernel_symbol_search("__irqentry_text_end"))) {
		machdep->machspec->__irqentry_text_start = sp1->value; 
		machdep->machspec->__irqentry_text_end = sp2->value; 
	} 
	if ((sp1 = kernel_symbol_search("vectors")) &&
	    (sp1n = kernel_symbol_search("cpu_switch_to")) &&
	    (sp2 = kernel_symbol_search("ret_fast_syscall")) &&
	    (sp2n = kernel_symbol_search("sys_rt_sigreturn_wrapper"))) {
		machdep->machspec->exp_entry1_start = sp1->value;
		machdep->machspec->exp_entry1_end = sp1n->value;
		machdep->machspec->exp_entry2_start = sp2->value;
		machdep->machspec->exp_entry2_end = sp2n->value;
	}

	if ((sp1 = kernel_symbol_search("crash_kexec")) &&
	    (sp1n = next_symbol(NULL, sp1)) && 
	    (sp2 = kernel_symbol_search("crash_save_cpu")) &&
	    (sp2n = next_symbol(NULL, sp2)) &&
	    (sp3 = kernel_symbol_search("machine_kexec")) &&
	    (sp3n = next_symbol(NULL, sp3))) {
		machdep->machspec->crash_kexec_start = sp1->value;
		machdep->machspec->crash_kexec_end = sp1n->value;
		machdep->machspec->crash_save_cpu_start = sp2->value;
		machdep->machspec->crash_save_cpu_end = sp2n->value;
		machdep->machspec->machine_kexec_start = sp3->value;
		machdep->machspec->machine_kexec_end = sp3n->value;
		machdep->flags |= KDUMP_ENABLED;
	}

	task_struct_thread = MEMBER_OFFSET("task_struct", "thread");
	thread_struct_cpu_context = MEMBER_OFFSET("thread_struct", "cpu_context");

	if ((task_struct_thread == INVALID_OFFSET) ||
	    (thread_struct_cpu_context == INVALID_OFFSET)) {
		error(INFO, 
		    "cannot determine task_struct.thread.context offset\n");
		return;
	}

	/*
	 *  Pay for the convenience of using a hardcopy of a kernel structure.
	 */
	if (offsetof(struct arm64_stackframe, sp) != 
	    MEMBER_OFFSET("stackframe", "sp")) {
		if (CRASHDEBUG(1))
			error(INFO, "builtin stackframe.sp offset differs from kernel version\n");
	}
	if (offsetof(struct arm64_stackframe, fp) != 
	    MEMBER_OFFSET("stackframe", "fp")) {
		if (CRASHDEBUG(1))
			error(INFO, "builtin stackframe.fp offset differs from kernel version\n");
	}
	if (offsetof(struct arm64_stackframe, pc) != 
	    MEMBER_OFFSET("stackframe", "pc")) {
		if (CRASHDEBUG(1))
			error(INFO, "builtin stackframe.pc offset differs from kernel version\n");
	}
	if (!MEMBER_EXISTS("stackframe", "sp"))
		machdep->flags |= UNW_4_14;

	context_sp = MEMBER_OFFSET("cpu_context", "sp");
	context_fp = MEMBER_OFFSET("cpu_context", "fp");
	context_pc = MEMBER_OFFSET("cpu_context", "pc");
	if (context_sp == INVALID_OFFSET) {
		error(INFO, "cannot determine cpu_context.sp offset\n");
		return;
	}
	if (context_fp == INVALID_OFFSET) {
		error(INFO, "cannot determine cpu_context.fp offset\n");
		return;
	}
	if (context_pc == INVALID_OFFSET) {
		error(INFO, "cannot determine cpu_context.pc offset\n");
		return;
	}
	ASSIGN_OFFSET(task_struct_thread_context_sp) =
		task_struct_thread + thread_struct_cpu_context + context_sp;
	ASSIGN_OFFSET(task_struct_thread_context_fp) =
		task_struct_thread + thread_struct_cpu_context + context_fp;
	ASSIGN_OFFSET(task_struct_thread_context_pc) =
		task_struct_thread + thread_struct_cpu_context + context_pc;
}

#define KERNEL_MODE (1)
#define USER_MODE   (2)

#define USER_EFRAME_OFFSET (machdep->machspec->user_eframe_offset)
#define KERN_EFRAME_OFFSET (machdep->machspec->kern_eframe_offset)

/*
 * PSR bits
 */
#define PSR_MODE_EL0t   0x00000000
#define PSR_MODE_EL1t   0x00000004
#define PSR_MODE_EL1h   0x00000005
#define PSR_MODE_EL2t   0x00000008
#define PSR_MODE_EL2h   0x00000009
#define PSR_MODE_EL3t   0x0000000c
#define PSR_MODE_EL3h   0x0000000d
#define PSR_MODE_MASK   0x0000000f

/* Architecturally defined mapping between AArch32 and AArch64 registers */
#define compat_usr(x)   regs[(x)]
#define compat_fp       regs[11]
#define compat_sp       regs[13]
#define compat_lr       regs[14]

#define user_mode(ptregs) \
	(((ptregs)->pstate & PSR_MODE_MASK) == PSR_MODE_EL0t)

#define compat_user_mode(ptregs)  \
	(((ptregs)->pstate & (PSR_MODE32_BIT | PSR_MODE_MASK)) == \
	 (PSR_MODE32_BIT | PSR_MODE_EL0t))

#define user_stack_pointer(ptregs) \
	(!compat_user_mode(ptregs) ? (ptregs)->sp : (ptregs)->compat_sp)

#define user_frame_pointer(ptregs) \
	(!compat_user_mode(ptregs) ? (ptregs)->regs[29] : (ptregs)->compat_fp)

static int
arm64_is_kernel_exception_frame(struct bt_info *bt, ulong stkptr)
{
        struct arm64_pt_regs *regs;

        regs = (struct arm64_pt_regs *)&bt->stackbuf[(ulong)(STACK_OFFSET_TYPE(stkptr))];

	if (INSTACK(regs->sp, bt) && INSTACK(regs->regs[29], bt) && 
	    !(regs->pstate & (0xffffffff00000000ULL | PSR_MODE32_BIT)) &&
	    is_kernel_text(regs->pc) &&
	    is_kernel_text(regs->regs[30])) {
		switch (regs->pstate & PSR_MODE_MASK)
		{
		case PSR_MODE_EL1t:
		case PSR_MODE_EL1h:
		case PSR_MODE_EL2t:
		case PSR_MODE_EL2h:
			return TRUE;
		}
	}

	return FALSE;
}

static int 
arm64_eframe_search(struct bt_info *bt)
{
	int c;
	ulong ptr, count;
	struct machine_specific *ms;

	if (bt->flags & BT_EFRAME_SEARCH2) {
		if (!(machdep->flags & IRQ_STACKS)) 
			error(FATAL, "IRQ stacks do not exist in this kernel\n");

		ms = machdep->machspec;

		for (c = 0; c < kt->cpus; c++) {
			if ((bt->flags & BT_CPUMASK) && 
			    !(NUM_IN_BITMAP(bt->cpumask, c)))
				continue;

			fprintf(fp, "CPU %d IRQ STACK:", c);
			bt->stackbase = ms->irq_stacks[c];
			bt->stacktop = bt->stackbase + ms->irq_stack_size;
			alter_stackbuf(bt);
			count = 0;

			for (ptr = bt->stackbase; ptr < bt->stacktop - SIZE(pt_regs); ptr++) {
				if (arm64_is_kernel_exception_frame(bt, ptr)) {
					fprintf(fp, "%s\nKERNEL-MODE EXCEPTION FRAME AT: %lx\n", 
						count ? "" : "\n", ptr); 
					arm64_print_exception_frame(bt, ptr, KERNEL_MODE, fp);
					count++;
				}
			}

			if (count)
				fprintf(fp, "\n");
			else
				fprintf(fp, "(none found)\n\n");
		}

		return 0;
	}


	count = 0;
	for (ptr = bt->stackbase; ptr < bt->stacktop - SIZE(pt_regs); ptr++) {
		if (arm64_is_kernel_exception_frame(bt, ptr)) {
			fprintf(fp, "\nKERNEL-MODE EXCEPTION FRAME AT: %lx\n", ptr); 
			arm64_print_exception_frame(bt, ptr, KERNEL_MODE, fp);
			count++;
		}
	}

	if (is_kernel_thread(bt->tc->task))
		return count;

	ptr = bt->stacktop - USER_EFRAME_OFFSET;
	fprintf(fp, "%sUSER-MODE EXCEPTION FRAME AT: %lx\n", 
		count++ ? "\n" : "", ptr); 
	arm64_print_exception_frame(bt, ptr, USER_MODE, fp);

	return count;
}

static int
arm64_in_exception_text(ulong ptr)
{
	struct machine_specific *ms = machdep->machspec;

	if ((ptr >= ms->__exception_text_start) &&
	    (ptr < ms->__exception_text_end))
		return TRUE;

	if (ms->__irqentry_text_start && ms->__irqentry_text_end &&
	    ((ptr >= ms->__irqentry_text_start) && 
	    (ptr < ms->__irqentry_text_end)))
		return TRUE;

	return FALSE;
}

static int
arm64_in_exp_entry(ulong addr)
{
	struct machine_specific *ms;

	ms = machdep->machspec;
	if ((ms->exp_entry1_start <= addr) && (addr < ms->exp_entry1_end))
		return TRUE;
	if ((ms->exp_entry2_start <= addr) && (addr < ms->exp_entry2_end))
		return TRUE;
	return FALSE;
}

#define BACKTRACE_CONTINUE        (1)
#define BACKTRACE_COMPLETE_KERNEL (2)
#define BACKTRACE_COMPLETE_USER   (3)

static int 
arm64_print_stackframe_entry(struct bt_info *bt, int level, struct arm64_stackframe *frame, FILE *ofp)
{
	char *name, *name_plus_offset;
	ulong branch_pc, symbol_offset;
	struct syment *sp;
	struct load_module *lm;
	char buf[BUFSIZE];

        /*
         * if pc comes from a saved lr, it actually points to an instruction
         * after branch. To avoid any confusion, decrement pc by 4.
         * See, for example, "bl schedule" before ret_to_user().
         */
	branch_pc = frame->pc - 4;
        name = closest_symbol(branch_pc);
        name_plus_offset = NULL;

        if (bt->flags & BT_SYMBOL_OFFSET) {
               	sp = value_search(branch_pc, &symbol_offset);
               	if (sp && symbol_offset)
                       	name_plus_offset =
                               	value_to_symstr(branch_pc, buf, bt->radix);
        }

	if (!INSTACK(frame->fp, bt) && IN_TASK_VMA(bt->task, frame->fp))
		frame->fp = 0;

	if (bt->flags & BT_FULL) {
		if (level) 
			arm64_display_full_frame(bt, frame->fp);
		bt->frameptr = frame->fp;
	}

        fprintf(ofp, "%s#%d [%8lx] %s at %lx", level < 10 ? " " : "", level,
                frame->fp ? frame->fp : bt->stacktop - USER_EFRAME_OFFSET, 
		name_plus_offset ? name_plus_offset : name, branch_pc); 

	if (BT_REFERENCE_CHECK(bt)) {
		arm64_do_bt_reference_check(bt, frame->pc, closest_symbol(frame->pc));
		arm64_do_bt_reference_check(bt, branch_pc, name);
	}

	if (module_symbol(branch_pc, NULL, &lm, NULL, 0))
		fprintf(ofp, " [%s]", lm->mod_name);

	fprintf(ofp, "\n");

	if (bt->flags & BT_LINE_NUMBERS) {
		get_line_number(branch_pc, buf, FALSE);
		if (strlen(buf))
			fprintf(ofp, "    %s\n", buf);
	}

	if (STREQ(name, "start_kernel") || STREQ(name, "secondary_start_kernel") ||
	    STREQ(name, "kthread") || STREQ(name, "kthreadd"))
		return BACKTRACE_COMPLETE_KERNEL;

	return BACKTRACE_CONTINUE;
}

static int 
arm64_print_stackframe_entry_v2(struct bt_info *bt, int level, struct arm64_stackframe *frame, FILE *ofp)
{
	char *name, *name_plus_offset;
	ulong pc, symbol_offset;
	struct syment *sp;
	struct load_module *lm;
	char buf[BUFSIZE];

	/*
	 * if pc comes from a saved lr, it actually points to an instruction
	 * after branch. To avoid any confusion, decrement pc by 4.
	 * See, for example, "bl schedule" before ret_to_user().
	 */
	pc = frame->pc - 0x4;
	name = closest_symbol(pc);
        name_plus_offset = NULL;

        if (bt->flags & BT_SYMBOL_OFFSET) {
		sp = value_search(pc, &symbol_offset);
                if (sp && symbol_offset)
			name_plus_offset = value_to_symstr(pc, buf, bt->radix);
        }

	if (bt->flags & BT_USER_EFRAME)
		frame->fp = 0;

        fprintf(ofp, "%s#%d [%8lx] %s at %lx", level < 10 ? " " : "", level,
                frame->fp ? frame->fp : bt->stacktop - USER_EFRAME_OFFSET, 
		name_plus_offset ? name_plus_offset : name, pc);

	if (BT_REFERENCE_CHECK(bt))
		arm64_do_bt_reference_check(bt, pc, name);

	if (module_symbol(pc, NULL, &lm, NULL, 0))
		fprintf(ofp, " [%s]", lm->mod_name);

	fprintf(ofp, "\n");

	if (bt->flags & BT_LINE_NUMBERS) {
		get_line_number(pc, buf, FALSE);
		if (strlen(buf))
			fprintf(ofp, "    %s\n", buf);
	}

	if (STREQ(name, "start_kernel") ||
	    STREQ(name, "secondary_start_kernel") ||
	    STREQ(name, "kthread") || STREQ(name, "kthreadd"))
		return BACKTRACE_COMPLETE_KERNEL;

	return BACKTRACE_CONTINUE;
}

static void
arm64_display_full_frame(struct bt_info *bt, ulong sp)
{
	int i, u_idx;
	ulong *up;
	ulong words, addr;
	char buf[BUFSIZE];

	if (bt->frameptr == sp)
		return;

	if (INSTACK(bt->frameptr, bt)) {
		if (INSTACK(sp, bt)) {
			; /* normal case */
		} else {
			if (sp == 0)
				/* interrupt in user mode */
				sp = bt->stacktop - USER_EFRAME_OFFSET;
			else
				/* interrupt in kernel mode */
				sp = bt->stacktop;
		}
	} else { 
		/* This is a transition case from irq to process stack. */
		return;
	}

	words = (sp - bt->frameptr) / sizeof(ulong);

	addr = bt->frameptr;
	u_idx = (bt->frameptr - bt->stackbase)/sizeof(ulong);
	for (i = 0; i < words; i++, u_idx++) {
		if (!(i & 1)) 
			fprintf(fp, "%s    %lx: ", i ? "\n" : "", addr);

		up = (ulong *)(&bt->stackbuf[u_idx*sizeof(ulong)]);
		fprintf(fp, "%s ", format_stack_entry(bt, buf, *up, 0));

		addr += sizeof(ulong);
	}
	fprintf(fp, "\n");
}

static void
arm64_display_full_frame_v2(struct bt_info *bt, struct arm64_stackframe *cur,
						struct arm64_stackframe *next)
{
	struct machine_specific *ms;
	ulong next_fp, stackbase;
	char *stackbuf;
	int i, u_idx;
	ulong *up;
	ulong words, addr;
	char buf[BUFSIZE];

	stackbase = bt->stackbase;
	stackbuf = bt->stackbuf;
	ms = machdep->machspec;

	/* Calc next fp for dump */
	if (next->fp == 0)
		/* last stackframe on kernel tack */
		next_fp = bt->stacktop - 0x10;
	else if (!INSTACK(cur->sp, bt)) {
		/* We have just switched over stacks */
		next_fp = ms->irq_stacks[bt->tc->processor]
				+ ms->irq_stack_size - 0x10;

		/*
		 * We are already buffering a process stack.
		 * So use an old buffer for IRQ stack.
		 */
		stackbase = ms->irq_stacks[bt->tc->processor];
		stackbuf = ms->irq_stackbuf;
	} else
		next_fp = next->fp;

	if (CRASHDEBUG(1))
		fprintf(fp, "    frame <%016lx:%016lx>\n", cur->fp, next_fp);

	/* Check here because we want to see a debug message above. */
	if (!(bt->flags & BT_FULL))
		return;
	if (next_fp <= cur->fp)
		return;

	/* Dump */
	words = (next_fp - cur->fp) / sizeof(ulong);
	addr = cur->fp;
	u_idx = (cur->fp - stackbase)/sizeof(ulong);
	for (i = 0; i < words; i++, u_idx++) {
		if (!(i & 1)) 
			fprintf(fp, "%s    %lx: ", i ? "\n" : "", addr);

		up = (ulong *)(&stackbuf[u_idx*sizeof(ulong)]);
		fprintf(fp, "%s ", format_stack_entry(bt, buf, *up, 0));

		addr += sizeof(ulong);
	}
	fprintf(fp, "\n");

	if (stackbuf == ms->irq_stackbuf)
		FREEBUF(stackbuf);
}

static int 
arm64_unwind_frame(struct bt_info *bt, struct arm64_stackframe *frame)
{
	unsigned long high, low, fp;
	unsigned long stack_mask;
	unsigned long irq_stack_ptr, orig_sp;
	struct arm64_pt_regs *ptregs;
	struct machine_specific *ms;

	stack_mask = (unsigned long)(ARM64_STACK_SIZE) - 1;
	fp = frame->fp;

	low  = frame->sp;
	high = (low + stack_mask) & ~(stack_mask);

	if (fp < low || fp > high || fp & 0xf)
		return FALSE;

	frame->sp = fp + 0x10;
	frame->fp = GET_STACK_ULONG(fp);
	frame->pc = GET_STACK_ULONG(fp + 8);

	if ((frame->fp == 0) && (frame->pc == 0))
		return FALSE;

	if (!(machdep->flags & IRQ_STACKS))
		return TRUE;

	if (!(machdep->flags & IRQ_STACKS))
		return TRUE;

	if (machdep->flags & UNW_4_14) {
		if ((bt->flags & BT_IRQSTACK) &&
		    !arm64_on_irq_stack(bt->tc->processor, frame->fp)) {
			if (arm64_on_process_stack(bt, frame->fp)) {
				arm64_set_process_stack(bt);

				frame->sp = frame->fp - KERN_EFRAME_OFFSET;
				/*
				 * for switch_stack
				 * fp still points to irq stack
				 */
				bt->bptr = fp;
				/*
				 * for display_full_frame
				 * sp points to process stack
				 *
				 * If we want to see pt_regs,
				 * comment out the below.
				 * bt->frameptr = frame->sp;
				 */
			} else {
				/* irq -> user */
				return FALSE;
			}
		}

		return TRUE;
	}

	/*
	 * The kernel's manner of determining the end of the IRQ stack:
	 *
	 *  #define THREAD_SIZE        16384
	 *  #define THREAD_START_SP    (THREAD_SIZE - 16)
	 *  #define IRQ_STACK_START_SP THREAD_START_SP
	 *  #define IRQ_STACK_PTR(cpu) ((unsigned long)per_cpu(irq_stack, cpu) + IRQ_STACK_START_SP)
	 *  #define IRQ_STACK_TO_TASK_STACK(ptr) (*((unsigned long *)((ptr) - 0x08)))
	 *
	 *  irq_stack_ptr = IRQ_STACK_PTR(raw_smp_processor_id());
	 *  orig_sp = IRQ_STACK_TO_TASK_STACK(irq_stack_ptr);   (pt_regs pointer on process stack)
	 */
	ms = machdep->machspec;
	irq_stack_ptr = ms->irq_stacks[bt->tc->processor] + ms->irq_stack_size - 16;

	if (frame->sp == irq_stack_ptr) {
		orig_sp = GET_STACK_ULONG(irq_stack_ptr - 8);
		arm64_set_process_stack(bt);
		if (INSTACK(orig_sp, bt) && (INSTACK(frame->fp, bt) || (frame->fp == 0))) {
			ptregs = (struct arm64_pt_regs *)&bt->stackbuf[(ulong)(STACK_OFFSET_TYPE(orig_sp))];
			frame->sp = orig_sp;
			frame->pc = ptregs->pc;
			bt->bptr = fp;
			if (CRASHDEBUG(1))
				error(INFO,
				    "arm64_unwind_frame: switch stacks: fp: %lx sp: %lx  pc: %lx\n",
					frame->fp, frame->sp, frame->pc);
		} else {
			error(WARNING,
			    "arm64_unwind_frame: on IRQ stack: oriq_sp: %lx%s fp: %lx%s\n",
				orig_sp, INSTACK(orig_sp, bt) ? "" : " (?)",
				frame->fp, INSTACK(frame->fp, bt) ? "" : " (?)");
			return FALSE;
		}
	}

	return TRUE;
}

/*
 * The following figure shows how unwinding can be done.
 * Here we assume that the callstack order is:
 *    #(X-1)    ppc (previous PC)
 *    #X        cpc (current PC)
 * <  #(X+  1)  epc (Exception entry) >
 *    #(X+1/2)  npc (Next PC)
 *    #(X+2/3)  Npc (One before Next)
 *    #(X+3/4)  NNpc (One before 'Npc')
 * and unwind frames from #X to #(X+1).
 * When we add a faked frame for exception entry (exception frame)
 * as #(X+1), the next frame for npc will be recognized as #(x+2).
 *
 * (1)Normal stackframe:
 *     +------+
 *     | pfp  |
 *     | cpc  |
 * psp +      +
 *     |      |
 *     |      |
 * pfp +------+ <--- :prev stackframe = <pfp, psp, ppc>
 *     | cfp  |
 *     | npc  |
 * csp +      +
 *     |      |
 *     |      |
 * cfp +------+ <--- :curr stackframe = <cfp, csp, cpc>
 *     | nfp  |                             cfp = *pfp
 *     | Npc  |                             csp = pfp + 0x10
 * nsp +      +
 *     |      |
 *     |      |
 * nfp +------+ <--- :next stackframe = <nfp, nsp, npc>
 *     |      |
 *
 * (2)Exception on the same (IRQ or process) stack:
 *     +------+
 *     | pfp  |
 *     | cpc  |
 * psp +      +
 *     |      |
 *     |      |
 * pfp +------+ <--- :prev stackframe = <pfp, psp, ppc>
 *     | cfp  |
 *     | npc  |
 * csp +      +
 *     |      |
 *     |      |
 * cfp +------+ <--- :curr stackframe = <cfp, csp, cpc>
 *     | nfp  |
 *     | epc  |
 *     +      +
 *     |      |
 *     |      |       faked(*)
 * esp +------+ <--- :excp stackframe = <---, esp, epc
 *     |      |                           esp = nsp - sizeof(pt_regs)
 *     |      |
 *     | Npc  |            (*) If we didn't add this frame, the next frame
 *     | nfp  |                would be
 *     | nsp  |                    <nfp, nfp + 0x10, epc>
 *     | npc  |                and the frame below for npc would be lost.
 * nsp +      +
 *     |      |
 * nfp +------+ <--- :task stackframe = <nfp, nsp, npc>
 *     | Nfp  |
 *     | NNpc |
 * Nsp +      +
 *     |      |
 * Nfp +------+ <--- :task stackframe = <Nfp, Nsp, Npc>
 *     | NNfp |
 *
 * (3)Interrupt:
 *     +------+
 *     | cfp  |
 *     | ipc  |
 * csp +      +
 *     |      |
 *     |      |
 * cfp +------+ <--- :curr stackframe = <cfp, csp, cpc>
 *     | ifp  |
 *     | epc  |
 * isp +      +
 *     |      |
 *     |      |       (*)
 * ifp +------+ <--- :irq stackframe = <ifp, isp, epc>
 *     | nfp  |                            ifp == IRQ_STACK_PTR
 *     | esp  |            (*) Before the kernel enters an irq handler, frame
 * top +------+                pointer moves to the top of IRQ stack.
 *     IRQ stack               So we have to skip this frame in unwinding.
 *
 *                    faked
 * esp +------+ <--- :excp stackframe = <---, esp, epc>
 *     |      |                            esp = nsp - sizeof(pt_regs)
 *     |      |
 *     | Npc  |
 *     | nfp  |
 *     | nsp  |
 *     | npc  |
 * nsp +      +
 *     |      |
 * nfp +------+ <--- :task stackframe = <nfp, nsp, npc>
 *     | Nfp  |
 *     | NNpc |
 * Nsp +      +
 *     |      |
 * Nfp +------+ <--- :task stackframe = <Nfp, Nsp, Npc>
 *     | NNfp |
 */

static struct arm64_stackframe ext_frame;

static int
arm64_unwind_frame_v2(struct bt_info *bt, struct arm64_stackframe *frame,
								FILE *ofp)
{
	unsigned long high, low, fp;
	unsigned long stack_mask;
	unsigned long irq_stack_ptr;
	struct machine_specific *ms;

	stack_mask = (unsigned long)(ARM64_STACK_SIZE) - 1;
	fp = frame->fp;

	low  = frame->sp;
	high = (low + stack_mask) & ~(stack_mask);

	if (fp < low || fp > high || fp & 0xf)
		return FALSE;

	if (CRASHDEBUG(1))
		fprintf(ofp, "    cur fp:%016lx sp:%016lx pc:%016lx\n",
					frame->fp, frame->sp, frame->pc);

	if (ext_frame.pc) {
		/*
		 * The previous frame was a dummy for exception entry.
		 * So complement a missing (task) stackframe now.
		*/
		frame->fp = ext_frame.fp;
		frame->sp = ext_frame.sp;
		frame->pc = ext_frame.pc;

		ext_frame.pc = 0; /* back to normal unwinding */

		goto unwind_done;
	}

	frame->pc = GET_STACK_ULONG(fp + 8);
	if (!arm64_in_exp_entry(frame->pc)) {
		/* (1) Normal stack frame */

		frame->sp = fp + 0x10;
		frame->fp = GET_STACK_ULONG(fp);
	} else {
		/*
		 * We are in exception entry code, and so
		 *   - add a faked frame for exception entry, and
		 *   - prepare for a stackframe hidden by exception
		 */

		ext_frame.fp = GET_STACK_ULONG(fp);
		/*
		 * Note:
		 * In the following code, we determine a stack pointer for
		 * exception entry based on ext_frame.fp because we have
		 * no way to know a ext_frame.sp.
		 * Fortunately, this will work fine for most functions
		 * in the kernel.
		 */
		if (ext_frame.fp == 0) {
			/*
			 * (2)
			 * Either on process stack or on IRQ stack,
			 * the next frame is the last one on process stack.
			 */

			frame->sp = bt->stacktop
				    - sizeof(struct arm64_pt_regs) - 0x10;
			frame->fp = frame->sp;
		} else if (!arm64_on_irq_stack(bt->tc->processor, frame->sp)) {
			/*
			 * (2)
			 * We are on process stack. Just add a faked frame
			 */

			if (!arm64_on_irq_stack(bt->tc->processor, ext_frame.fp))
				frame->sp = ext_frame.fp
					    - sizeof(struct arm64_pt_regs);
			else {
				/*
				 * FIXME: very exceptional case
				 * We are already back on process stack, but
				 * a saved frame pointer indicates that we are
				 * on IRQ stack. Unfortunately this can happen
				 * when some functions are called after
				 * an irq handler is done because irq_exit()
				 * doesn't restore a frame pointer (x29).
				 * Those functions include
				 *    - do_notify_resume()
				 *    - trace_hardirqs_off()
				 *    - schedule()
				 *
				 * We have no perfect way to determine a true
				 * stack pointer value here.
				 * 0x20 is a stackframe size of schedule().
				 * Really ugly
				 */
				frame->sp = frame->fp + 0x20;
				fprintf(ofp, " (Next exception frame might be wrong)\n");
			}

			frame->fp = frame->sp;
		} else {
			/* We are on IRQ stack */

			ms = machdep->machspec;
			irq_stack_ptr = ms->irq_stacks[bt->tc->processor]
						+ ms->irq_stack_size - 0x20;
			if (ext_frame.fp != irq_stack_ptr) {
				/* (2) Just add a faked frame */

				frame->sp = ext_frame.fp
					    - sizeof(struct arm64_pt_regs);
				frame->fp = frame->sp;
			} else {
				/*
				 * (3)
				 * Switch from IRQ stack to process stack
				 */

				frame->sp = GET_STACK_ULONG(irq_stack_ptr + 8);
				frame->fp = frame->sp;

				/*
				 * Keep a buffer for a while until
				 * displaying the last frame on IRQ stack
				 * at next arm64_print_stackframe_entry_v2()
				 */
				if (bt->flags & BT_FULL)
					ms->irq_stackbuf = bt->stackbuf;

				arm64_set_process_stack(bt);
			}
		}

		/* prepare for a stackframe hidden by exception */
		arm64_gen_hidden_frame(bt, frame->sp, &ext_frame);
	}

unwind_done:
	if (CRASHDEBUG(1))
		fprintf(ofp, "    nxt fp:%016lx sp:%016lx pc:%016lx\n",
					frame->fp, frame->sp, frame->pc);

	return TRUE;
}

/*
 *  A layout of a stack frame in a function looks like:
 *
 *           stack grows to lower addresses.
 *             /|\
 *              |
 *           |      |
 *  new sp   +------+ <---
 *           |dyn   |   |
 *           | vars |   |
 *  new fp   +- - - +   |
 *           |old fp|   | a function's stack frame
 *           |old lr|   |
 *           |static|   |
 *           |  vars|   |
 *  old sp   +------+ <---
 *           |dyn   |
 *           | vars |
 *  old fp   +------+
 *           |      |
 *
 *  - On function entry, sp is decremented down to new fp.
 *
 *  - and old fp and sp are saved into this stack frame.
 *    "Static" local variables are allocated at the same time.
 *
 *  - Later on, "dynamic" local variables may be allocated on a stack.
 *    But those dynamic variables are rarely used in the kernel image,
 *    and, as a matter of fact, sp is equal to fp in almost all functions.
 *    (not 100% though.)
 *
 *  - Currently, sp is determined in arm64_unwind_frame() by
 *         sp = a callee's fp + 0x10
 *    where 0x10 stands for a saved area for fp and sp
 *
 *  - As you can see, however, this calculated sp still points to the top of
 *    callee's static local variables and doesn't match with a *real* sp.
 *
 *  - So, generally, dumping a stack from this calculated sp to the next frame's
 *    sp shows "callee's static local variables", old fp and sp.
 *
 *  Diagram and explanation courtesy of Takahiro Akashi
 */

static void 
arm64_back_trace_cmd(struct bt_info *bt)
{
	struct arm64_stackframe stackframe;
	int level;
	ulong exception_frame;
	FILE *ofp;

	if (bt->flags & BT_OPT_BACK_TRACE) {
		if (machdep->flags & UNW_4_14) {
			option_not_supported('o');
			return;
		}

		arm64_back_trace_cmd_v2(bt);
		return;
	}

	ofp = BT_REFERENCE_CHECK(bt) ? pc->nullfp : fp;

	/*
	 *  stackframes are created from 3 contiguous stack addresses:
	 *
	 *     x: contains stackframe.fp -- points to next triplet
	 *   x+8: contains stackframe.pc -- text return address
	 *  x+16: is the stackframe.sp address 
	 */

	if (bt->flags & BT_KDUMP_ADJUST) {
		if (arm64_on_irq_stack(bt->tc->processor, bt->bptr)) {
			arm64_set_irq_stack(bt);
			bt->flags |= BT_IRQSTACK;
		}
		stackframe.fp = GET_STACK_ULONG(bt->bptr - 8);
		stackframe.pc = GET_STACK_ULONG(bt->bptr);
		stackframe.sp = bt->bptr + 8;
		bt->frameptr = stackframe.sp;
	} else if (bt->hp && bt->hp->esp) {
		if (arm64_on_irq_stack(bt->tc->processor, bt->hp->esp)) {
			arm64_set_irq_stack(bt);
			bt->flags |= BT_IRQSTACK;
		}
		stackframe.fp = GET_STACK_ULONG(bt->hp->esp - 8);
		stackframe.pc = bt->hp->eip ? 
			bt->hp->eip : GET_STACK_ULONG(bt->hp->esp);
		stackframe.sp = bt->hp->esp + 8;
		bt->flags &= ~BT_REGS_NOT_FOUND;
	} else {
		if (arm64_on_irq_stack(bt->tc->processor, bt->frameptr)) {
			arm64_set_irq_stack(bt);
			bt->flags |= BT_IRQSTACK;
		}
		stackframe.sp = bt->stkptr;
		stackframe.pc = bt->instptr;
		stackframe.fp = bt->frameptr;
	}

	if (bt->flags & BT_TEXT_SYMBOLS) {
		arm64_print_text_symbols(bt, &stackframe, ofp);
                if (BT_REFERENCE_FOUND(bt)) {
                        print_task_header(fp, task_to_context(bt->task), 0);
			arm64_print_text_symbols(bt, &stackframe, fp);
                        fprintf(fp, "\n");
                }
		return;
        }

	if (bt->flags & BT_REGS_NOT_FOUND)
		return;

	if (!(bt->flags & BT_KDUMP_ADJUST)) {
		if (bt->flags & BT_USER_SPACE)
			goto complete_user;

		if (DUMPFILE() && is_task_active(bt->task)) {
			exception_frame = stackframe.fp - KERN_EFRAME_OFFSET;
			if (arm64_is_kernel_exception_frame(bt, exception_frame))
				arm64_print_exception_frame(bt, exception_frame, 
					KERNEL_MODE, ofp);
		}
	}

	level = exception_frame = 0;
	while (1) {
		bt->instptr = stackframe.pc;

		switch (arm64_print_stackframe_entry(bt, level, &stackframe, ofp))
		{
		case BACKTRACE_COMPLETE_KERNEL:
			return;
		case BACKTRACE_COMPLETE_USER:
			goto complete_user;
		case BACKTRACE_CONTINUE:
			break;
		}

		if (exception_frame) {
			arm64_print_exception_frame(bt, exception_frame, KERNEL_MODE, ofp);
			exception_frame = 0;
		}

		if (!arm64_unwind_frame(bt, &stackframe))
			break;

		if (arm64_in_exception_text(bt->instptr) && INSTACK(stackframe.fp, bt)) {
			if (!(bt->flags & BT_IRQSTACK) ||
			    ((stackframe.sp + SIZE(pt_regs)) < bt->stacktop)) {
				if (arm64_is_kernel_exception_frame(bt, stackframe.fp - KERN_EFRAME_OFFSET))
					exception_frame = stackframe.fp - KERN_EFRAME_OFFSET;
			}
		}

		if ((bt->flags & BT_IRQSTACK) &&
		    !arm64_on_irq_stack(bt->tc->processor, stackframe.fp)) {
			bt->flags &= ~BT_IRQSTACK;
			if (arm64_switch_stack(bt, &stackframe, ofp) == USER_MODE)
				break;
		}


		level++;
	}

	if (is_kernel_thread(bt->tc->task)) 
		return;

complete_user:
	exception_frame = bt->stacktop - USER_EFRAME_OFFSET;
	arm64_print_exception_frame(bt, exception_frame, USER_MODE, ofp);
	if ((bt->flags & (BT_USER_SPACE|BT_KDUMP_ADJUST)) == BT_USER_SPACE)
		fprintf(ofp, " #0 [user space]\n");
}

static void 
arm64_back_trace_cmd_v2(struct bt_info *bt)
{
	struct arm64_stackframe stackframe, cur_frame;
	int level, mode;
	ulong exception_frame;
	FILE *ofp;

	ofp = BT_REFERENCE_CHECK(bt) ? pc->nullfp : fp;

	/*
	 *  stackframes are created from 3 contiguous stack addresses:
	 *
	 *     x: contains stackframe.fp -- points to next triplet
	 *   x+8: contains stackframe.pc -- text return address
	 *  x+16: is the stackframe.sp address 
	 */

	if (bt->flags & BT_KDUMP_ADJUST) {
		if (arm64_on_irq_stack(bt->tc->processor, bt->bptr)) {
			arm64_set_irq_stack(bt);
			bt->flags |= BT_IRQSTACK;
		}
		stackframe.fp = GET_STACK_ULONG(bt->bptr);
		stackframe.pc = GET_STACK_ULONG(bt->bptr + 8);
		stackframe.sp = bt->bptr + 16;
		bt->frameptr = stackframe.fp;
	} else {
		if (arm64_on_irq_stack(bt->tc->processor, bt->frameptr)) {
			arm64_set_irq_stack(bt);
			bt->flags |= BT_IRQSTACK;
		}
		stackframe.sp = bt->stkptr;
		stackframe.pc = bt->instptr;
		stackframe.fp = bt->frameptr;
	}

	if (bt->flags & BT_TEXT_SYMBOLS) {
		arm64_print_text_symbols(bt, &stackframe, ofp);
                if (BT_REFERENCE_FOUND(bt)) {
                        print_task_header(fp, task_to_context(bt->task), 0);
			arm64_print_text_symbols(bt, &stackframe, fp);
                        fprintf(fp, "\n");
                }
		return;
        }

	if (bt->flags & BT_REGS_NOT_FOUND)
		return;

	if (!(bt->flags & BT_KDUMP_ADJUST)) {
		if (bt->flags & BT_USER_SPACE) {
user_space:
			exception_frame = bt->stacktop - USER_EFRAME_OFFSET;
			arm64_print_exception_frame(bt, exception_frame,
							USER_MODE, ofp);
//			fprintf(ofp, " #0 [user space]\n");

			return;
		}

		if (DUMPFILE() && is_task_active(bt->task)) {
			exception_frame = stackframe.fp - SIZE(pt_regs);
			if (arm64_is_kernel_exception_frame(bt, exception_frame))
				arm64_print_exception_frame(bt, exception_frame, 
					KERNEL_MODE, ofp);
		}
	}

	for (level = 0;; level++) {
		bt->instptr = stackframe.pc;

		/*
		 * Show one-line stackframe info
		 */
		if (arm64_print_stackframe_entry_v2(bt, level, &stackframe, ofp)
		    == BACKTRACE_COMPLETE_KERNEL)
			break;

		cur_frame = stackframe;
		if (!arm64_unwind_frame_v2(bt, &stackframe, ofp))
			break;

		/*
		 * Dump the contents of the current stackframe.
		 * We need to know the next stackframe to determine
		 * the dump range:
		 *    <cur_frame.fp:stackframe.fp>
		 */
		arm64_display_full_frame_v2(bt, &cur_frame, &stackframe);

		/*
		 * If we are in a normal stackframe, just continue,
		 * otherwise show an exception frame.
		 * Since exception entry code doesn't have a real
		 * stackframe, we fake a dummy frame here.
		 */
		if (!arm64_in_exp_entry(stackframe.pc))
			continue;

		if (!INSTACK(cur_frame.sp, bt))
			fprintf(ofp, "--- <IRQ stack> ---\n");

		arm64_print_stackframe_entry_v2(bt, ++level, &stackframe, ofp);
		if (bt->flags & BT_USER_EFRAME)
			goto user_space;
		cur_frame = stackframe;
		arm64_unwind_frame_v2(bt, &stackframe, ofp);

		/*
		 * and don't show the contenxts. Instead,
		 * show an exception frame below
		 */

		if (!INSTACK(cur_frame.sp, bt)) {
			/* This check is a safeguard. See unwind_frame().  */
			error(WARNING,
				"stack pointer for exception frame is wrong\n");
			return;
		}
		mode = (stackframe.pc < machdep->machspec->userspace_top) ?
				USER_MODE : KERNEL_MODE;
//		fprintf(ofp, "--- <Exception in %s> ---\n",
//				mode == KERNEL_MODE ? "kernel" : "user");
		arm64_print_exception_frame(bt, cur_frame.sp, mode, ofp);

		if (mode == USER_MODE)
			break;
	}
}

static void
arm64_print_text_symbols(struct bt_info *bt, struct arm64_stackframe *frame, FILE *ofp)
{
	int i;
	ulong *up;
	struct load_module *lm;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char *name;
	ulong start;

	if (bt->flags & BT_TEXT_SYMBOLS_ALL)
		start = bt->stackbase;
	else {
		start = frame->sp - 8;
		fprintf(ofp, "%sSTART: %s at %lx\n",
			space(VADDR_PRLEN > 8 ? 14 : 6),
			bt->flags & BT_SYMBOL_OFFSET ?
			value_to_symstr(frame->pc, buf2, bt->radix) :
			closest_symbol(frame->pc), frame->pc);
	}

	for (i = (start - bt->stackbase)/sizeof(ulong); i < LONGS_PER_STACK; i++) {
		up = (ulong *)(&bt->stackbuf[i*sizeof(ulong)]);
		if (is_kernel_text(*up)) {
			name = closest_symbol(*up);
			fprintf(ofp, "  %s[%s] %s at %lx",
				bt->flags & BT_ERROR_MASK ?
				"  " : "",
				mkstring(buf1, VADDR_PRLEN, 
				RJUST|LONG_HEX,
				MKSTR(bt->stackbase + 
				(i * sizeof(long)))),
				bt->flags & BT_SYMBOL_OFFSET ?
				value_to_symstr(*up, buf2, bt->radix) :
				name, *up);
			if (module_symbol(*up, NULL, &lm, NULL, 0))
				fprintf(ofp, " [%s]", lm->mod_name);
			fprintf(ofp, "\n");
			if (BT_REFERENCE_CHECK(bt))
				arm64_do_bt_reference_check(bt, *up, name);
		}
	}
}

static int
arm64_in_kdump_text(struct bt_info *bt, struct arm64_stackframe *frame)
{
	ulong *ptr, *start, *base;
	struct machine_specific *ms;
	ulong crash_kexec_frame;

	if (!(machdep->flags & KDUMP_ENABLED))
		return FALSE;

	base = (ulong *)&bt->stackbuf[(ulong)(STACK_OFFSET_TYPE(bt->stackbase))];
	if (bt->flags & BT_USER_SPACE)
		start = (ulong *)&bt->stackbuf[(ulong)(STACK_OFFSET_TYPE(bt->stacktop))];
	else {
		if (INSTACK(frame->fp, bt))
			start = (ulong *)&bt->stackbuf[(ulong)(STACK_OFFSET_TYPE(frame->fp))];
		else 
			start = (ulong *)&bt->stackbuf[(ulong)(STACK_OFFSET_TYPE(bt->stacktop))];
	}

	crash_kexec_frame = 0;
	ms = machdep->machspec;
	for (ptr = start - 8; ptr >= base; ptr--) {
		if (bt->flags & BT_OPT_BACK_TRACE) {
			if ((*ptr >= ms->crash_kexec_start) &&
			    (*ptr < ms->crash_kexec_end) &&
			    INSTACK(*(ptr - 1), bt)) {
				bt->bptr = ((ulong)(ptr - 1) - (ulong)base)
					   + task_to_stackbase(bt->tc->task);
				if (CRASHDEBUG(1))
					fprintf(fp, "%lx: %lx (crash_kexec)\n", bt->bptr, *ptr);
				return TRUE;
			}
			if ((*ptr >= ms->crash_save_cpu_start) &&
			    (*ptr < ms->crash_save_cpu_end) &&
			    INSTACK(*(ptr - 1), bt)) {
				bt->bptr = ((ulong)(ptr - 1) - (ulong)base)
					   + task_to_stackbase(bt->tc->task);
				if (CRASHDEBUG(1))
					fprintf(fp, "%lx: %lx (crash_save_cpu)\n", bt->bptr, *ptr);
				return TRUE;
			}
		} else {
			if ((*ptr >= ms->machine_kexec_start) && (*ptr < ms->machine_kexec_end)) {
				bt->bptr = ((ulong)ptr - (ulong)base)
					   + task_to_stackbase(bt->tc->task);
				if (CRASHDEBUG(1))
					fprintf(fp, "%lx: %lx (machine_kexec)\n", bt->bptr, *ptr);
				return TRUE;
			}
			if ((*ptr >= ms->crash_kexec_start) && (*ptr < ms->crash_kexec_end)) {
				/*
				 *  Stash the first crash_kexec frame in case the machine_kexec
				 *  frame is not found.
				 */
				if (!crash_kexec_frame) {
					crash_kexec_frame = ((ulong)ptr - (ulong)base)
						+ task_to_stackbase(bt->tc->task);
					if (CRASHDEBUG(1))
						fprintf(fp, "%lx: %lx (crash_kexec)\n", 
							bt->bptr, *ptr);
				}
				continue;
			}
			if ((*ptr >= ms->crash_save_cpu_start) && (*ptr < ms->crash_save_cpu_end)) {
				bt->bptr = ((ulong)ptr - (ulong)base)
					   + task_to_stackbase(bt->tc->task);
				if (CRASHDEBUG(1))
					fprintf(fp, "%lx: %lx (crash_save_cpu)\n", bt->bptr, *ptr);
				return TRUE;
			}
		}
	} 

	if (crash_kexec_frame) {
		bt->bptr = crash_kexec_frame;
		return TRUE;
	}

	return FALSE;
}

static int
arm64_in_kdump_text_on_irq_stack(struct bt_info *bt)
{
	int cpu;
	ulong stackbase;
	char *stackbuf;
	ulong *ptr, *start, *base;
	struct machine_specific *ms;

	if ((machdep->flags & (IRQ_STACKS|KDUMP_ENABLED)) != (IRQ_STACKS|KDUMP_ENABLED))
		return FALSE;

	ms = machdep->machspec;
	cpu = bt->tc->processor;
	stackbase = ms->irq_stacks[cpu];
	stackbuf = GETBUF(ms->irq_stack_size);

	if (!readmem(stackbase, KVADDR, stackbuf,
	    ms->irq_stack_size, "IRQ stack contents", RETURN_ON_ERROR)) {
		error(INFO, "read of IRQ stack at %lx failed\n", stackbase);
		FREEBUF(stackbuf);
		return FALSE;
	}

	base = (ulong *)stackbuf;
	start = (ulong *)(stackbuf + ms->irq_stack_size);

	for (ptr = start - 8; ptr >= base; ptr--) {
		if (bt->flags & BT_OPT_BACK_TRACE) {
			if ((*ptr >= ms->crash_kexec_start) &&
			    (*ptr < ms->crash_kexec_end) &&
			    INSTACK(*(ptr - 1), bt)) {
				bt->bptr = ((ulong)(ptr - 1) - (ulong)base) + stackbase;
				if (CRASHDEBUG(1))
					fprintf(fp, "%lx: %lx (crash_kexec on IRQ stack)\n", 
						bt->bptr, *ptr);
				FREEBUF(stackbuf);
				return TRUE;
			}
			if ((*ptr >= ms->crash_save_cpu_start) &&
			    (*ptr < ms->crash_save_cpu_end) &&
			    INSTACK(*(ptr - 1), bt)) {
				bt->bptr = ((ulong)(ptr - 1) - (ulong)base) + stackbase;
				if (CRASHDEBUG(1))
					fprintf(fp, "%lx: %lx (crash_save_cpu on IRQ stack)\n", 
						bt->bptr, *ptr);
				FREEBUF(stackbuf);
				return TRUE;
			}
		} else {
			if ((*ptr >= ms->crash_kexec_start) && (*ptr < ms->crash_kexec_end)) {
				bt->bptr = ((ulong)ptr - (ulong)base) + stackbase;
				if (CRASHDEBUG(1))
					fprintf(fp, "%lx: %lx (crash_kexec on IRQ stack)\n", 
						bt->bptr, *ptr);
				FREEBUF(stackbuf);
				return TRUE;
			}
			if ((*ptr >= ms->crash_save_cpu_start) && (*ptr < ms->crash_save_cpu_end)) {
				bt->bptr = ((ulong)ptr - (ulong)base) + stackbase;
				if (CRASHDEBUG(1))
					fprintf(fp, "%lx: %lx (crash_save_cpu on IRQ stack)\n", 
						bt->bptr, *ptr);
				FREEBUF(stackbuf);
				return TRUE;
			}
		}
	} 

	FREEBUF(stackbuf);
	return FALSE;
}

static int 
arm64_switch_stack(struct bt_info *bt, struct arm64_stackframe *frame, FILE *ofp)
{
	int i;
	ulong stacktop, words, addr;
	ulong *stackbuf;
	char buf[BUFSIZE];
	struct machine_specific *ms = machdep->machspec;

	if (bt->flags & BT_FULL) {
		stacktop = ms->irq_stacks[bt->tc->processor] + ms->irq_stack_size;
		words = (stacktop - bt->bptr) / sizeof(ulong);
		stackbuf = (ulong *)GETBUF(words * sizeof(ulong));
		readmem(bt->bptr, KVADDR, stackbuf, words * sizeof(long), 
			"top of IRQ stack", FAULT_ON_ERROR);

		addr = bt->bptr;
		for (i = 0; i < words; i++) {
			if (!(i & 1))
				fprintf(ofp, "%s    %lx: ", i ? "\n" : "", addr);
			fprintf(ofp, "%s ", format_stack_entry(bt, buf, stackbuf[i], 0));
			addr += sizeof(ulong);
		}
		fprintf(ofp, "\n");
		FREEBUF(stackbuf);
	}
	fprintf(ofp, "--- <IRQ stack> ---\n");

	if (frame->fp == 0)
		return USER_MODE;

	if (!(machdep->flags & UNW_4_14))
		arm64_print_exception_frame(bt, frame->sp, KERNEL_MODE, ofp);

	return KERNEL_MODE;
}

static int
arm64_get_dumpfile_stackframe(struct bt_info *bt, struct arm64_stackframe *frame)
{
	struct machine_specific *ms = machdep->machspec;
	struct arm64_pt_regs *ptregs;

	if (!ms->panic_task_regs ||
	    (!ms->panic_task_regs[bt->tc->processor].sp && 
	     !ms->panic_task_regs[bt->tc->processor].pc)) {
		bt->flags |= BT_REGS_NOT_FOUND;
		return FALSE;
	}

	ptregs = &ms->panic_task_regs[bt->tc->processor];
	frame->pc = ptregs->pc;
	if (user_mode(ptregs)) {
		frame->sp = user_stack_pointer(ptregs);
		frame->fp = user_frame_pointer(ptregs);
		if (is_kernel_text(frame->pc) ||
		    !in_user_stack(bt->tc->task, frame->sp)) {
			error(WARNING, 
			    "corrupt NT_PRSTATUS? pstate: 0x%lx, but no user frame found\n",
				ptregs->pstate);
			if (is_kernel_text(frame->pc) && 
			    INSTACK(frame->sp, bt) && INSTACK(frame->fp, bt))
				goto try_kernel;
			bt->flags |= BT_REGS_NOT_FOUND;
			return FALSE;
		}
		bt->flags |= BT_USER_SPACE;
	} else {
try_kernel:
		frame->sp = ptregs->sp;
		frame->fp = ptregs->regs[29];
	}

	if (arm64_in_kdump_text(bt, frame) || 
	    arm64_in_kdump_text_on_irq_stack(bt))
		bt->flags |= BT_KDUMP_ADJUST;

	return TRUE;
}

static int
arm64_get_stackframe(struct bt_info *bt, struct arm64_stackframe *frame) 
{
	if (!fill_task_struct(bt->task))
		return FALSE;

	frame->sp = ULONG(tt->task_struct + OFFSET(task_struct_thread_context_sp));
	frame->pc = ULONG(tt->task_struct + OFFSET(task_struct_thread_context_pc));
	frame->fp = ULONG(tt->task_struct + OFFSET(task_struct_thread_context_fp));

	return TRUE;
}

static void
arm64_get_stack_frame(struct bt_info *bt, ulong *pcp, ulong *spp)
{
	int ret;
	struct arm64_stackframe stackframe = { 0 };

	if (DUMPFILE() && is_task_active(bt->task))
		ret = arm64_get_dumpfile_stackframe(bt, &stackframe);
	else
		ret = arm64_get_stackframe(bt, &stackframe);

	if (!ret)
		error(WARNING, 
			"cannot determine starting stack frame for task %lx\n",
				bt->task);

	bt->frameptr = stackframe.fp;
	if (pcp)
		*pcp = stackframe.pc;
	if (spp)
		*spp = stackframe.sp;
}

static void
arm64_gen_hidden_frame(struct bt_info *bt, ulong sp,
					struct arm64_stackframe *frame)
{
	struct arm64_pt_regs *ptregs;

	if (IN_TASK_VMA(bt->task, sp)) {
		bt->flags |= BT_USER_EFRAME;
		return;
	}

	ptregs = (struct arm64_pt_regs *)
		 &bt->stackbuf[(ulong)(STACK_OFFSET_TYPE(sp))];

	frame->pc = ptregs->pc;
	frame->fp = ptregs->regs[29];
	frame->sp = ptregs->sp;
}

static void
arm64_print_exception_frame(struct bt_info *bt, ulong pt_regs, int mode, FILE *ofp)
{
	int i, r, rows, top_reg, is_64_bit;
	struct arm64_pt_regs *regs;
	struct syment *sp;
	ulong LR, SP, offset;
	char buf[BUFSIZE];

	if (CRASHDEBUG(1)) 
		fprintf(ofp, "pt_regs: %lx\n", pt_regs);

	regs = (struct arm64_pt_regs *)
	       &bt->stackbuf[(ulong)(STACK_OFFSET_TYPE(pt_regs))];

	if ((mode == USER_MODE) && (regs->pstate & PSR_MODE32_BIT)) {
		LR = regs->regs[14];
		SP = regs->regs[13];
		top_reg = 12;
		is_64_bit = FALSE;
		rows = 4;
	} else {
		LR = regs->regs[30];
		SP = regs->sp;
		top_reg = 29;
		is_64_bit = TRUE;
		rows = 3;
	}

	switch (mode) {
	case USER_MODE: 
		if (is_64_bit)
			fprintf(ofp, 
			    "     PC: %016lx   LR: %016lx   SP: %016lx\n    ",
				(ulong)regs->pc, LR, SP);
		else
			fprintf(ofp, 
			    "     PC: %08lx  LR: %08lx  SP: %08lx  PSTATE: %08lx\n    ",
				(ulong)regs->pc, LR, SP, (ulong)regs->pstate);
		break;

	case KERNEL_MODE:
		fprintf(ofp, "     PC: %016lx  ", (ulong)regs->pc);
		if (is_kernel_text(regs->pc) &&
		    (sp = value_search(regs->pc, &offset))) {
			fprintf(ofp, "[%s", sp->name);
			if (offset)
				fprintf(ofp, (*gdb_output_radix == 16) ?
				    "+0x%lx" : "+%ld", 
					offset);
			fprintf(ofp, "]\n");
		} else
			fprintf(ofp, "[unknown or invalid address]\n");

		fprintf(ofp, "     LR: %016lx  ", LR);
		if (is_kernel_text(LR) &&
		    (sp = value_search(LR, &offset))) {
			fprintf(ofp, "[%s", sp->name);
			if (offset)
				fprintf(ofp, (*gdb_output_radix == 16) ?
				    "+0x%lx" : "+%ld", 
					offset);
			fprintf(ofp, "]\n");
		} else
			fprintf(ofp, "[unknown or invalid address]\n");

		fprintf(ofp, "     SP: %016lx  PSTATE: %08lx\n    ", 
			SP, (ulong)regs->pstate);
		break;
	}

	for (i = top_reg, r = 1; i >= 0; r++, i--) {
		fprintf(ofp, "%sX%d: ", 
			i < 10 ? " " : "", i);
		fprintf(ofp, is_64_bit ? "%016lx" : "%08lx",
			(ulong)regs->regs[i]);
		if ((i == 0) && !is_64_bit)
			fprintf(ofp, "\n");
		else if ((i == 0) || ((r % rows) == 0))
			fprintf(ofp, "\n%s", 
				(i == 0) && (mode == KERNEL_MODE) ? "" : "    "); 
		else
			fprintf(ofp, "%s", is_64_bit ? "  " : " "); 
	}

	if (is_64_bit) {
		if (mode == USER_MODE) {
			fprintf(ofp, "ORIG_X0: %016lx  SYSCALLNO: %lx",
				(ulong)regs->orig_x0, (ulong)regs->syscallno);
			fprintf(ofp, "  PSTATE: %08lx\n", (ulong)regs->pstate);
		}
	}

	if (is_kernel_text(regs->pc) && (bt->flags & BT_LINE_NUMBERS)) {
		get_line_number(regs->pc, buf, FALSE);
		if (strlen(buf))
			fprintf(ofp, "    %s\n", buf);
	}

	if (BT_REFERENCE_CHECK(bt)) {
		arm64_do_bt_reference_check(bt, regs->pc, NULL);
		if ((sp = value_search(regs->pc, &offset))) 
			arm64_do_bt_reference_check(bt, 0, sp->name);
		arm64_do_bt_reference_check(bt, LR, NULL);
		arm64_do_bt_reference_check(bt, SP, NULL);
		arm64_do_bt_reference_check(bt, regs->pstate, NULL);
		for (i = 0; i <= top_reg; i++)
			arm64_do_bt_reference_check(bt, regs->regs[i], NULL);
		if (is_64_bit) {
			arm64_do_bt_reference_check(bt, regs->orig_x0, NULL);
			arm64_do_bt_reference_check(bt, regs->syscallno, NULL);
		}
	}
}

/*
 *  Check a frame for a requested reference.
 */
static void
arm64_do_bt_reference_check(struct bt_info *bt, ulong text, char *name)
{
	ulong offset;
	struct syment *sp = NULL;

	if (!name)
		sp = value_search(text, &offset); 
	else if (!text)
		sp = symbol_search(name);

        switch (bt->ref->cmdflags & (BT_REF_SYMBOL|BT_REF_HEXVAL))
        {
        case BT_REF_SYMBOL:
                if (name) {
			if (STREQ(name, bt->ref->str))
                        	bt->ref->cmdflags |= BT_REF_FOUND;
		} else {
			if (sp && !offset && STREQ(sp->name, bt->ref->str))
                        	bt->ref->cmdflags |= BT_REF_FOUND;
		}
                break;

        case BT_REF_HEXVAL:
                if (text) {
			if (bt->ref->hexval == text) 
                        	bt->ref->cmdflags |= BT_REF_FOUND;
		} else if (sp && (bt->ref->hexval == sp->value))
                       	bt->ref->cmdflags |= BT_REF_FOUND;
		else if (!name && !text && (bt->ref->hexval == 0))
			bt->ref->cmdflags |= BT_REF_FOUND;
                break;
        }
}

/*
 *  Translate a PTE, returning TRUE if the page is present.
 *  If a physaddr pointer is passed in, don't print anything.
 */
static int
arm64_translate_pte(ulong pte, void *physaddr, ulonglong unused)
{
	int c, others, len1, len2, len3;
	ulong paddr;
	char buf1[BUFSIZE];
        char buf2[BUFSIZE];
        char buf3[BUFSIZE];
	char ptebuf[BUFSIZE];
	char physbuf[BUFSIZE];
        char *arglist[MAXARGS];
	int page_present;

	paddr = pte & PHYS_MASK & (s32)machdep->pagemask;
       	page_present = pte & (PTE_VALID | machdep->machspec->PTE_PROT_NONE);

        if (physaddr) {
		*((ulong *)physaddr) = paddr;
		return page_present;
	}
        
	sprintf(ptebuf, "%lx", pte);
	len1 = MAX(strlen(ptebuf), strlen("PTE"));
	fprintf(fp, "%s  ", mkstring(buf1, len1, CENTER|LJUST, "PTE"));

        if (!page_present) { 
                swap_location(pte, buf1);
                if ((c = parse_line(buf1, arglist)) != 3)
                        error(FATAL, "cannot determine swap location\n");

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

        sprintf(physbuf, "%lx", paddr);
        len2 = MAX(strlen(physbuf), strlen("PHYSICAL"));
        fprintf(fp, "%s  ", mkstring(buf1, len2, CENTER|LJUST, "PHYSICAL"));

        fprintf(fp, "FLAGS\n");

        fprintf(fp, "%s  %s  ",
                mkstring(ptebuf, len1, CENTER|RJUST, NULL),
                mkstring(physbuf, len2, CENTER|RJUST, NULL));
        fprintf(fp, "(");
        others = 0;

	if (pte) {
		if (pte & PTE_VALID)
			fprintf(fp, "%sVALID", others++ ? "|" : "");
		if (pte & machdep->machspec->PTE_FILE)
			fprintf(fp, "%sFILE", others++ ? "|" : "");
		if (pte & machdep->machspec->PTE_PROT_NONE)
			fprintf(fp, "%sPROT_NONE", others++ ? "|" : "");
		if (pte & PTE_USER)
			fprintf(fp, "%sUSER", others++ ? "|" : "");
		if (pte & PTE_RDONLY)
			fprintf(fp, "%sRDONLY", others++ ? "|" : "");
		if (pte & PTE_SHARED)
			fprintf(fp, "%sSHARED", others++ ? "|" : "");
		if (pte & PTE_AF)
			fprintf(fp, "%sAF", others++ ? "|" : "");
		if (pte & PTE_NG)
			fprintf(fp, "%sNG", others++ ? "|" : "");
		if (pte & PTE_PXN)
			fprintf(fp, "%sPXN", others++ ? "|" : "");
		if (pte & PTE_UXN)
			fprintf(fp, "%sUXN", others++ ? "|" : "");
		if (pte & PTE_DIRTY)
			fprintf(fp, "%sDIRTY", others++ ? "|" : "");
		if (pte & PTE_SPECIAL)
			fprintf(fp, "%sSPECIAL", others++ ? "|" : "");
	} else {
                fprintf(fp, "no mapping");
        }

        fprintf(fp, ")\n");

	return (page_present);
}

static ulong
arm64_vmalloc_start(void)
{
	return machdep->machspec->vmalloc_start_addr;
}

/*
 *  Not so accurate since thread_info introduction.
 */
static int
arm64_is_task_addr(ulong task)
{
	if (tt->flags & THREAD_INFO)
		return IS_KVADDR(task);
	else
		return (IS_KVADDR(task) && (ALIGNED_STACK_OFFSET(task) == 0));
}

static ulong
PLT_veneer_to_kvaddr(ulong value)
{
	uint32_t insn;
	ulong addr = 0;
	int i;

	/*
	 * PLT veneer always looks:
         *   movn x16, #0x....
         *   movk x16, #0x...., lsl #16
         *   movk x16, #0x...., lsl #32
         *   br   x16
	 */
	for (i = 0; i < 4; i++) {
		if (!readmem(value + i * sizeof(insn), KVADDR, &insn,
		    sizeof(insn), "PLT veneer", RETURN_ON_ERROR)) {
			error(WARNING, "cannot read PLT veneer instruction at %lx\n", 
				value + i * sizeof(insn));
			return value;
		}
		switch (i) {
		case 0:
			if ((insn & 0xffe0001f) != 0x92800010)
				goto not_plt;
			addr = ~((ulong)(insn & 0x1fffe0) >> 5);
			break;
		case 1:
			if ((insn & 0xffe0001f) != 0xf2a00010)
				goto not_plt;
			addr &= 0xffffffff0000ffff;
			addr |= (ulong)(insn & 0x1fffe0) << (16 - 5);
			break;
		case 2:
			if ((insn & 0xffe0001f) != 0xf2c00010)
				goto not_plt;
			addr &= 0xffff0000ffffffff;
			addr |= (ulong)(insn & 0x1fffe0) << (32 - 5);
			break;
		case 3:
			if (insn != 0xd61f0200)
				goto not_plt;
			break;
		default:
			return value; /* to avoid any warnings */
		}
	}

	return addr;

not_plt:
	return value;
}

/*
 * Filter dissassembly output if the output radix is not gdb's default 10
 */
static int
arm64_dis_filter(ulong vaddr, char *inbuf, unsigned int output_radix)
{
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char *colon, *p1;
	int argc;
	char *argv[MAXARGS];
	ulong value;

	if (!inbuf)
		return TRUE;

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
		while ((p1 > inbuf) && !(STRNEQ(p1, " 0x") || STRNEQ(p1, "\t0x")))
			p1--;

		if (!(STRNEQ(p1, " 0x") || STRNEQ(p1, "\t0x")))
			return FALSE;
		p1++;

		if (!extract_hex(p1, &value, NULLCHAR, TRUE))
			return FALSE;

		sprintf(buf1, "0x%lx <%s>\n", value,
			value_to_symstr(value, buf2, output_radix));

		sprintf(p1, "%s", buf1);
	}

	if (IS_MODULE_VADDR(vaddr)) {
		ulong orig_value;

		p1 = &inbuf[strlen(inbuf)-1];
		strcpy(buf1, inbuf);
		argc = parse_line(buf1, argv);

		if ((STREQ(argv[argc-2], "b") || STREQ(argv[argc-2], "bl")) &&
		    extract_hex(argv[argc-1], &orig_value, NULLCHAR, TRUE)) {
			value = PLT_veneer_to_kvaddr(orig_value);
			sprintf(p1, " <%s%s>\n",
				value == orig_value ? "" : "plt:",
				value_to_symstr(value, buf2, output_radix));
		}
	}

	console("    %s", inbuf);

	return TRUE;
}

/*
 * Machine dependent command.
 */
static void
arm64_cmd_mach(void)
{
	int c;

	while ((c = getopt(argcnt, args, "cm")) != -1) {
		switch (c) {
		case 'c':
		case 'm':
			option_not_supported(c);
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	arm64_display_machine_stats();
}

static void
arm64_display_machine_stats(void)
{
	int i, pad;
	struct new_utsname *uts;
	char buf[BUFSIZE];
	ulong mhz;

	uts = &kt->utsname; 

	fprintf(fp, "       MACHINE TYPE: %s\n", uts->machine);
	fprintf(fp, "        MEMORY SIZE: %s\n", get_memory_size(buf));
	fprintf(fp, "               CPUS: %d\n", get_cpus_to_display());
	if ((mhz = machdep->processor_speed()))
		fprintf(fp, "    PROCESSOR SPEED: %ld Mhz\n", mhz);
	fprintf(fp, "                 HZ: %d\n", machdep->hz);
	fprintf(fp, "          PAGE SIZE: %d\n", PAGESIZE());
	fprintf(fp, "KERNEL VIRTUAL BASE: %lx\n", machdep->machspec->page_offset);
	fprintf(fp, "KERNEL VMALLOC BASE: %lx\n", machdep->machspec->vmalloc_start_addr);
	fprintf(fp, "KERNEL MODULES BASE: %lx\n", machdep->machspec->modules_vaddr);
        fprintf(fp, "KERNEL VMEMMAP BASE: %lx\n", machdep->machspec->vmemmap_vaddr);
	fprintf(fp, "  KERNEL STACK SIZE: %ld\n", STACKSIZE());
	if (machdep->machspec->irq_stack_size) {
		fprintf(fp, "     IRQ STACK SIZE: %ld\n", 
			machdep->machspec->irq_stack_size);
		fprintf(fp, "         IRQ STACKS:\n");
		for (i = 0; i < kt->cpus; i++) {
			pad = (i < 10) ? 3 : (i < 100) ? 2 : (i < 1000) ? 1 : 0; 
			fprintf(fp, "%s           CPU %d: %lx\n", space(pad), i, 
				machdep->machspec->irq_stacks[i]);
		}
	}
}

static int
arm64_get_smp_cpus(void)
{
	int cpus;
	
	if ((cpus = get_cpus_present()))
		return cpus;
	else
		return MAX(get_cpus_online(), get_highest_cpu_online()+1);
}


/*
 * Retrieve task registers for the time of the crash.
 */
static int
arm64_get_crash_notes(void)
{
	struct machine_specific *ms = machdep->machspec;
	ulong crash_notes;
	Elf64_Nhdr *note;
	ulong offset;
	char *buf, *p;
	ulong *notes_ptrs;
	ulong i;

	if (!symbol_exists("crash_notes"))
		return FALSE;

	crash_notes = symbol_value("crash_notes");

	notes_ptrs = (ulong *)GETBUF(kt->cpus*sizeof(notes_ptrs[0]));

	/*
	 * Read crash_notes for the first CPU. crash_notes are in standard ELF
	 * note format.
	 */
	if (!readmem(crash_notes, KVADDR, &notes_ptrs[kt->cpus-1], 
	    sizeof(notes_ptrs[kt->cpus-1]), "crash_notes", RETURN_ON_ERROR)) {
		error(WARNING, "cannot read crash_notes\n");
		FREEBUF(notes_ptrs);
		return FALSE;
	}

	if (symbol_exists("__per_cpu_offset")) {
		/* 
		 * Add __per_cpu_offset for each cpu to form the notes pointer.
		 */
		for (i = 0; i<kt->cpus; i++)
			notes_ptrs[i] = notes_ptrs[kt->cpus-1] + kt->__per_cpu_offset[i];	
	}

	buf = GETBUF(SIZE(note_buf));

	if (!(ms->panic_task_regs = calloc((size_t)kt->cpus, sizeof(struct arm64_pt_regs))))
		error(FATAL, "cannot calloc panic_task_regs space\n");
	
	for  (i = 0; i < kt->cpus; i++) {

		if (!readmem(notes_ptrs[i], KVADDR, buf, SIZE(note_buf), 
		    "note_buf_t", RETURN_ON_ERROR)) {
			error(WARNING, "failed to read note_buf_t\n");
			goto fail;
		}

		/*
		 * Do some sanity checks for this note before reading registers from it.
		 */
		note = (Elf64_Nhdr *)buf;
		p = buf + sizeof(Elf64_Nhdr);

		/*
		 * dumpfiles created with qemu won't have crash_notes, but there will
		 * be elf notes; dumpfiles created by kdump do not create notes for
		 * offline cpus.
		 */
		if (note->n_namesz == 0 && (DISKDUMP_DUMPFILE() || KDUMP_DUMPFILE())) {
			if (DISKDUMP_DUMPFILE())
				note = diskdump_get_prstatus_percpu(i);
			else if (KDUMP_DUMPFILE())
				note = netdump_get_prstatus_percpu(i);
			if (note) {
				/*
				 * SIZE(note_buf) accounts for a "final note", which is a
				 * trailing empty elf note header.
				 */
				long notesz = SIZE(note_buf) - sizeof(Elf64_Nhdr);

				if (sizeof(Elf64_Nhdr) + roundup(note->n_namesz, 4) +
				    note->n_descsz == notesz)
					BCOPY((char *)note, buf, notesz);
			} else {
				error(WARNING,
					"cannot find NT_PRSTATUS note for cpu: %d\n", i);
				continue;
			}
		}

		if (note->n_type != NT_PRSTATUS) {
			error(WARNING, "invalid note (n_type != NT_PRSTATUS)\n");
			goto fail;
		}
		if (p[0] != 'C' || p[1] != 'O' || p[2] != 'R' || p[3] != 'E') {
			error(WARNING, "invalid note (name != \"CORE\"\n");
			goto fail;
		}

		/*
		 * Find correct location of note data. This contains elf_prstatus
		 * structure which has registers etc. for the crashed task.
		 */
		offset = sizeof(Elf64_Nhdr);
		offset = roundup(offset + note->n_namesz, 4);
		p = buf + offset; /* start of elf_prstatus */

		BCOPY(p + OFFSET(elf_prstatus_pr_reg), &ms->panic_task_regs[i],
		      sizeof(struct arm64_pt_regs));
	}

	FREEBUF(buf);
	FREEBUF(notes_ptrs);
	return TRUE;

fail:
	FREEBUF(buf);
	FREEBUF(notes_ptrs);
	free(ms->panic_task_regs);
	ms->panic_task_regs = NULL;
	return FALSE;
}

static void
arm64_clear_machdep_cache(void) {
	/*
	 * TBD: probably not necessary...
	 */
	return;
}

static int
arm64_on_process_stack(struct bt_info *bt, ulong stkptr)
{
	ulong stackbase, stacktop;

	stackbase = GET_STACKBASE(bt->task);
	stacktop = GET_STACKTOP(bt->task);

	if ((stkptr >= stackbase) && (stkptr < stacktop))
		return TRUE;

	return FALSE;
}

static int
arm64_on_irq_stack(int cpu, ulong stkptr)
{
	return arm64_in_alternate_stack(cpu, stkptr);
}

static int
arm64_in_alternate_stack(int cpu, ulong stkptr)
{
	struct machine_specific *ms = machdep->machspec;

	if (!ms->irq_stack_size || (cpu >= kt->cpus))
		return FALSE;

	if ((stkptr >= ms->irq_stacks[cpu]) &&
	    (stkptr < (ms->irq_stacks[cpu] + ms->irq_stack_size)))
		return TRUE;

	return FALSE;
}

static void
arm64_set_irq_stack(struct bt_info *bt)
{
	struct machine_specific *ms = machdep->machspec;

	bt->stackbase = ms->irq_stacks[bt->tc->processor];
	bt->stacktop = bt->stackbase + ms->irq_stack_size;
	alter_stackbuf(bt);
}

static void
arm64_set_process_stack(struct bt_info *bt)
{
	bt->stackbase = GET_STACKBASE(bt->task);
	bt->stacktop = GET_STACKTOP(bt->task);
	alter_stackbuf(bt);
}


static int
compare_kvaddr(const void *v1, const void *v2)
{
        struct vaddr_range *r1, *r2;

        r1 = (struct vaddr_range *)v1;
        r2 = (struct vaddr_range *)v2;

        return (r1->start < r2->start ? -1 :
                r1->start == r2->start ? 0 : 1);
}

static int
arm64_get_kvaddr_ranges(struct vaddr_range *vrp)
{
	int cnt;

	cnt = 0;

	vrp[cnt].type = KVADDR_UNITY_MAP;
	vrp[cnt].start = machdep->machspec->page_offset;
	vrp[cnt++].end = vt->high_memory;

	vrp[cnt].type = KVADDR_VMALLOC;
	vrp[cnt].start = machdep->machspec->vmalloc_start_addr;
	vrp[cnt++].end = last_vmalloc_address();

	if (st->mods_installed) {
		vrp[cnt].type = KVADDR_MODULES;
		vrp[cnt].start = lowest_module_address();
		vrp[cnt++].end = roundup(highest_module_address(), 
			PAGESIZE());
	}

	if (machdep->flags & VMEMMAP) {
		vrp[cnt].type = KVADDR_VMEMMAP;
		vrp[cnt].start = machdep->machspec->vmemmap_vaddr;
		vrp[cnt++].end = vt->node_table[vt->numnodes-1].mem_map +
			(vt->node_table[vt->numnodes-1].size * SIZE(page));
	}

	qsort(vrp, cnt, sizeof(struct vaddr_range), compare_kvaddr);

	return cnt;
}

/*
 *  Include both vmalloc'd, module and vmemmap address space as VMALLOC space.
 */
int
arm64_IS_VMALLOC_ADDR(ulong vaddr)
{
	struct machine_specific *ms = machdep->machspec;
	
	if ((machdep->flags & NEW_VMEMMAP) &&
	    (vaddr >= machdep->machspec->kimage_text) &&
	    (vaddr <= machdep->machspec->kimage_end))
		return FALSE;

        return ((vaddr >= ms->vmalloc_start_addr && vaddr <= ms->vmalloc_end) ||
                ((machdep->flags & VMEMMAP) &&
                 (vaddr >= ms->vmemmap_vaddr && vaddr <= ms->vmemmap_end)) ||
                (vaddr >= ms->modules_vaddr && vaddr <= ms->modules_end));
}

static void 
arm64_calc_VA_BITS(void)
{
	int bitval;
	struct syment *sp;
	ulong value;
	char *string;

	if (!(sp = symbol_search("swapper_pg_dir")) &&
	    !(sp = symbol_search("idmap_pg_dir")) &&
	    !(sp = symbol_search("_text")) &&
	    !(sp = symbol_search("stext"))) { 
		for (sp = st->symtable; sp < st->symend; sp++) {
			if (highest_bit_long(sp->value) == 63)
				break;
		}
	}

	if (sp) 
		value = sp->value;
	else
		value = kt->vmcoreinfo.log_buf_SYMBOL;  /* crash --log */

	for (bitval = highest_bit_long(value); bitval; bitval--) {
		if ((value & (1UL << bitval)) == 0) {
			if (machdep->flags & NEW_VMEMMAP)
				machdep->machspec->VA_BITS = bitval + 1;
			else
				machdep->machspec->VA_BITS = bitval + 2;
			break;
		}
	}

	/*
	 *  Verify against dumpfiles that export VA_BITS in vmcoreinfo
	 */
        if ((string = pc->read_vmcoreinfo("NUMBER(VA_BITS)"))) {
                value = atol(string);
                free(string);
		if (machdep->machspec->VA_BITS != value)
			error(WARNING, "VA_BITS: calculated: %ld  vmcoreinfo: %ld\n",
				machdep->machspec->VA_BITS, value);
        }


	if (CRASHDEBUG(1))
		fprintf(fp, "VA_BITS: %ld\n", machdep->machspec->VA_BITS);

}

/*
 *  The size and end of the vmalloc range is dependent upon the kernel's
 *  VMEMMAP_SIZE value, and the vmemmap range is dependent upon the end
 *  of the vmalloc range as well as the VMEMMAP_SIZE:
 *
 *  #define VMEMMAP_SIZE    ALIGN((1UL << (VA_BITS - PAGE_SHIFT)) * sizeof(struct page), PUD_SIZE)
 *  #define VMALLOC_START   (UL(0xffffffffffffffff) << VA_BITS)
 *  #define VMALLOC_END     (PAGE_OFFSET - PUD_SIZE - VMEMMAP_SIZE - SZ_64K)
 *
 *  Since VMEMMAP_SIZE is dependent upon the size of a struct page,
 *  the two ranges cannot be determined until POST_GDB.
 */

#define ALIGN(x, a) __ALIGN_KERNEL((x), (a))
#define __ALIGN_KERNEL(x, a)            __ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)    (((x) + (mask)) & ~(mask))
#define SZ_64K                          0x00010000

static void
arm64_calc_virtual_memory_ranges(void)
{
	struct machine_specific *ms = machdep->machspec;
	ulong vmemmap_start, vmemmap_end, vmemmap_size;
	ulong vmalloc_end;
	ulong PUD_SIZE = UNINITIALIZED;

	if (THIS_KERNEL_VERSION < LINUX(3,17,0))  /* use original hardwired values */
		return;

	STRUCT_SIZE_INIT(page, "page");

        switch (machdep->flags & (VM_L2_64K|VM_L3_64K|VM_L3_4K|VM_L4_4K))
        {
        case VM_L2_64K:
        case VM_L3_64K:
		PUD_SIZE = PGDIR_SIZE_L2_64K;
		break;
        case VM_L3_4K:
		PUD_SIZE = PGDIR_SIZE_L3_4K;
        case VM_L4_4K:
		PUD_SIZE = PUD_SIZE_L4_4K;
		break;
        }

	if (machdep->flags & NEW_VMEMMAP)
#define STRUCT_PAGE_MAX_SHIFT   6
		vmemmap_size = 1UL << (ms->VA_BITS - machdep->pageshift - 1
						+ STRUCT_PAGE_MAX_SHIFT);
	else
		vmemmap_size = ALIGN((1UL << (ms->VA_BITS - machdep->pageshift)) * SIZE(page), PUD_SIZE);

	vmalloc_end = (ms->page_offset - PUD_SIZE - vmemmap_size - SZ_64K);

	if (machdep->flags & NEW_VMEMMAP) {
		vmemmap_start = ms->page_offset - vmemmap_size;
		vmemmap_end = ms->page_offset;
	} else {
		vmemmap_start = vmalloc_end + SZ_64K;
		vmemmap_end = vmemmap_start + vmemmap_size;
	}

	ms->vmalloc_end = vmalloc_end - 1;
	ms->vmemmap_vaddr = vmemmap_start;
	ms->vmemmap_end = vmemmap_end - 1;
}

static int
arm64_is_uvaddr(ulong addr, struct task_context *tc)
{
        return (addr < ARM64_USERSPACE_TOP);
}


ulong
arm64_swp_type(ulong pte)
{
	struct machine_specific *ms = machdep->machspec;

	pte >>= ms->__SWP_TYPE_SHIFT;
	pte &= ms->__SWP_TYPE_MASK;
	return pte;
}

ulong
arm64_swp_offset(ulong pte)
{
	struct machine_specific *ms = machdep->machspec;

	pte >>= ms->__SWP_OFFSET_SHIFT;
	if (ms->__SWP_OFFSET_MASK)
		pte &= ms->__SWP_OFFSET_MASK;
	return pte;
}

#endif  /* ARM64 */


