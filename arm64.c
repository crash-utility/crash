/*
 * arm64.c - core analysis suite
 *
 * Copyright (C) 2012-2014 David Anderson
 * Copyright (C) 2012-2014 Red Hat, Inc. All rights reserved.
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

#define NOT_IMPLEMENTED(X) error((X), "%s: function not implemented\n", __func__)

static struct machine_specific arm64_machine_specific = { 0 };
static int arm64_verify_symbol(const char *, ulong, char);
static void arm64_parse_cmdline_args(void);
static void arm64_calc_phys_offset(void);
static int arm64_kdump_phys_base(ulong *);
static ulong arm64_processor_speed(void);
static void arm64_init_kernel_pgd(void);
static int arm64_kvtop(struct task_context *, ulong, physaddr_t *, int);
static int arm64_uvtop(struct task_context *, ulong, physaddr_t *, int);
static int arm64_vtop_2level_64k(ulong, ulong, physaddr_t *, int);
static int arm64_vtop_3level_4k(ulong, ulong, physaddr_t *, int);
static ulong arm64_get_task_pgd(ulong);
static void arm64_stackframe_init(void);
static int arm64_eframe_search(struct bt_info *);
static int arm64_in_exception_text(ulong);
static void arm64_back_trace_cmd(struct bt_info *);
static int arm64_print_stackframe_entry(struct bt_info *, int, struct arm64_stackframe *);
static void arm64_display_full_frame(struct bt_info *, ulong);
static int arm64_unwind_frame(struct bt_info *, struct arm64_stackframe *);
static int arm64_get_dumpfile_stackframe(struct bt_info *, struct arm64_stackframe *);
static int arm64_get_stackframe(struct bt_info *, struct arm64_stackframe *);
static void arm64_get_stack_frame(struct bt_info *, ulong *, ulong *);
static void arm64_print_exception_frame(struct bt_info *, ulong, int);
static int arm64_translate_pte(ulong, void *, ulonglong);
static ulong arm64_vmalloc_start(void);
static int arm64_is_task_addr(ulong);
static int arm64_dis_filter(ulong, char *, unsigned int);
static void arm64_cmd_mach(void);
static void arm64_display_machine_stats(void);
static int arm64_get_smp_cpus(void);
static void arm64_clear_machdep_cache(void);
static int arm64_in_alternate_stack(int, ulong);
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

#if defined(__x86_64__)
	if (ACTIVE())
		error(FATAL, "compiled for the ARM64 architecture\n");
#endif

	switch (when) {
	case PRE_SYMTAB:
		machdep->machspec = &arm64_machine_specific;
		machdep->process_elf_notes = process_elf64_notes;
		machdep->verify_symbol = arm64_verify_symbol;
		if (pc->flags & KERNEL_DEBUG_QUERY)
			return;
		machdep->verify_paddr = generic_verify_paddr;
		if (machdep->cmdline_args[0])
			arm64_parse_cmdline_args();
		break;

	case PRE_GDB:
		if (kernel_symbol_exists("swapper_pg_dir") &&
		    kernel_symbol_exists("idmap_pg_dir")) {
			value = symbol_value("swapper_pg_dir") -
				symbol_value("idmap_pg_dir");
			machdep->pagesize = value / 2;
		} else
			machdep->pagesize = memory_page_size();   /* host */

		machdep->pageshift = ffs(machdep->pagesize) - 1;
		machdep->pageoffset = machdep->pagesize - 1;
		machdep->pagemask = ~((ulonglong)machdep->pageoffset);

		arm64_calc_VA_BITS();
		machdep->machspec->page_offset = ARM64_PAGE_OFFSET;
		machdep->identity_map_base = ARM64_PAGE_OFFSET;
		machdep->machspec->userspace_top = ARM64_USERSPACE_TOP;
		machdep->machspec->modules_vaddr = ARM64_MODULES_VADDR;
		machdep->machspec->modules_end = ARM64_MODULES_END;
		machdep->machspec->vmalloc_start_addr = ARM64_VMALLOC_START;
		machdep->machspec->vmalloc_end = ARM64_VMALLOC_END;
		machdep->kvbase = ARM64_VMALLOC_START;
		machdep->machspec->vmemmap_vaddr = ARM64_VMEMMAP_VADDR;
		machdep->machspec->vmemmap_end = ARM64_VMEMMAP_END;

		switch (machdep->pagesize)
		{
		case 4096:
			machdep->flags |= VM_L3_4K;
			machdep->ptrs_per_pgd = PTRS_PER_PGD_L3_4K;
			if ((machdep->pgd = 
			    (char *)malloc(PTRS_PER_PGD_L3_4K * 8)) == NULL)
				error(FATAL, "cannot malloc pgd space.");
			if ((machdep->pmd = 
			    (char *)malloc(PTRS_PER_PMD_L3_4K * 8)) == NULL)
				error(FATAL, "cannot malloc pmd space.");
			if ((machdep->ptbl = 
			    (char *)malloc(PTRS_PER_PTE_L3_4K * 8)) == NULL)
				error(FATAL, "cannot malloc ptbl space.");
			machdep->pud = NULL;  /* not used */
			break;

		case 65536:
			machdep->flags |= VM_L2_64K;
			machdep->ptrs_per_pgd = PTRS_PER_PGD_L2_64K;
			if ((machdep->pgd = 
			    (char *)malloc(PTRS_PER_PGD_L2_64K * 8)) == NULL)
				error(FATAL, "cannot malloc pgd space.");
			if ((machdep->ptbl = 
			    (char *)malloc(PTRS_PER_PTE_L2_64K * 8)) == NULL)
				error(FATAL, "cannot malloc ptbl space.");
			machdep->pmd = NULL;  /* not used */
			machdep->pud = NULL;  /* not used */
			break;

		default:
			error(FATAL, "invalid/unsupported page size: %d\n", 
				machdep->pagesize);
		}

		machdep->last_pud_read = 0;  /* not used */
		machdep->last_pgd_read = 0;
		machdep->last_pmd_read = 0;
		machdep->last_ptbl_read = 0;
		machdep->clear_machdep_cache = arm64_clear_machdep_cache;

		machdep->stacksize = ARM64_STACK_SIZE;
		machdep->flags |= VMEMMAP;

		arm64_calc_phys_offset();
		
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
		break;

	case POST_GDB:
		machdep->section_size_bits = _SECTION_SIZE_BITS;
		machdep->max_physmem_bits = _MAX_PHYSMEM_BITS;
		if (THIS_KERNEL_VERSION >= LINUX(3,10,0)) {
			machdep->machspec->pte_protnone = PTE_PROT_NONE_3_10;
			machdep->machspec->pte_file = PTE_FILE_3_10;
		} else {
			machdep->machspec->pte_protnone = PTE_PROT_NONE;
			machdep->machspec->pte_file = PTE_FILE;
		}

		if (symbol_exists("irq_desc"))
			ARRAY_LENGTH_INIT(machdep->nr_irqs, irq_desc,
				  "irq_desc", NULL, 0);
		else if (kernel_symbol_exists("nr_irqs"))
			get_symbol_data("nr_irqs", sizeof(unsigned int),
				&machdep->nr_irqs);

		if (!machdep->hz)
			machdep->hz = 100;

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
		error(FATAL, "crash --log not implemented on ARM64: TBD\n");
		/* machdep->identity_map_base = ARM64_PAGE_OFFSET; */
		arm64_calc_phys_offset();
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

	if ((value == 0) && 
	    ((type == 'a') || (type == 'n') || (type == 'N') || (type == 'U')))
		return FALSE;

	if (STREQ(name, "$d") || STREQ(name, "$x"))
		return FALSE;
	
	if ((type == 'A') && STRNEQ(name, "__crc_"))
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
	if (machdep->flags & VM_L3_4K)
		fprintf(fp, "%sVM_L3_4K", others++ ? "|" : "");
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
	fprintf(fp, "          back_trace: arm64_back_trace_cmd()\n");
	fprintf(fp, "  in_alternate_stack: arm64_in_alternate_stack()\n");
	fprintf(fp, "     processor_speed: arm64_processor_speed()\n");
	fprintf(fp, "               uvtop: arm64_uvtop()->%s()\n",
		machdep->flags & VM_L3_4K ? 
		"arm64_vtop_3level_4k" : "arm64_vtop_2level_64k");
	fprintf(fp, "               kvtop: arm64_kvtop()->%s()\n",
		machdep->flags & VM_L3_4K ? 
		"arm64_vtop_3level_4k" : "arm64_vtop_2level_64k");
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
	fprintf(fp, "       last_pud_read: (not used)\n");
	fprintf(fp, "       last_pgd_read: %lx\n", machdep->last_pgd_read);
	fprintf(fp, "       last_pmd_read: ");
	if (PAGESIZE() == 65536)
		fprintf(fp, "(not used)\n");
	else
		fprintf(fp, "%lx\n", machdep->last_pmd_read);
	fprintf(fp, "      last_ptbl_read: %lx\n", machdep->last_ptbl_read);
	fprintf(fp, " clear_machdep_cache: arm64_clear_machdep_cache()\n");
	fprintf(fp, "                 pgd: %lx\n", (ulong)machdep->pgd);
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
	fprintf(fp, "           phys_offset: %lx\n", ms->phys_offset);
	fprintf(fp, "__exception_text_start: %lx\n", ms->__exception_text_start);
	fprintf(fp, "  __exception_text_end: %lx\n", ms->__exception_text_end);
	fprintf(fp, "       panic_task_regs: %lx\n", (ulong)ms->panic_task_regs);
	fprintf(fp, "          pte_protnone: %lx\n", ms->pte_protnone);
	fprintf(fp, "              pte_file: %lx\n", ms->pte_file);
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
	int index, i, c, err;
	char *arglist[MAXARGS];
	char buf[BUFSIZE];
	char *p;
	ulong value = 0;

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
			err = 0;

			if (STRNEQ(arglist[i], "phys_offset=")) {
				int megabytes = FALSE;
				int flags = RETURN_ON_ERROR | QUIET;

				if ((LASTCHAR(arglist[i]) == 'm') ||
				    (LASTCHAR(arglist[i]) == 'M')) {
					LASTCHAR(arglist[i]) = NULLCHAR;
					megabytes = TRUE;
				}

				p = arglist[i] + strlen("phys_offset=");
				if (strlen(p)) {
					if (megabytes)
						value = dtol(p, flags, &err);
					else
						value = htol(p, flags, &err);
				}

				if (!err) {
					if (megabytes)
						value = MEGABYTES(value);

					machdep->machspec->phys_offset = value;

					error(NOTE,
					    "setting phys_offset to: 0x%lx\n\n",
						machdep->machspec->phys_offset);

					machdep->flags |= PHYS_OFFSET;
					continue;
				}
			}

			error(WARNING, "ignoring --machdep option: %s\n",
				arglist[i]);
		}
	}
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
		FILE *fp;

		if ((fp = fopen("/proc/iomem", "r")) == NULL)
			return;

		/*
		 * Memory regions are sorted in ascending order. We take the
		 * first region which should be correct for most uses.
		 */
		errflag = 1;
		while (fgets(buf, BUFSIZE, fp)) {
			if (strstr(buf, ": System RAM")) {
				clean_line(buf);
				errflag = 0;
				break;
			}
		}
		fclose(fp);

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
 *  Borrow the 32-bit ARM functionality.
 */
static int
arm64_kdump_phys_base(ulong *phys_offset)
{
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

	switch (machdep->flags & (VM_L2_64K|VM_L3_4K))
	{
	case VM_L2_64K:
		return arm64_vtop_2level_64k(kernel_pgd, kvaddr, paddr, verbose);
	case VM_L3_4K:
		return arm64_vtop_3level_4k(kernel_pgd, kvaddr, paddr, verbose);
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

	switch (machdep->flags & (VM_L2_64K|VM_L3_4K))
	{
	case VM_L2_64K:
		return arm64_vtop_2level_64k(user_pgd, uvaddr, paddr, verbose);
	case VM_L3_4K:
		return arm64_vtop_3level_4k(user_pgd, uvaddr, paddr, verbose);
	default:
		return FALSE;
	}
}

#define PMD_TYPE_MASK   3
#define PMD_TYPE_SECT   1
#define PMD_TYPE_TABLE  2
#define SECTION_PAGE_MASK_2MB    (~((MEGABYTES(2))-1))
#define SECTION_PAGE_MASK_512MB  (~((MEGABYTES(512))-1))

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
		ulong sectionbase = pgd_val & SECTION_PAGE_MASK_512MB;
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
		ulong sectionbase = pmd_val & SECTION_PAGE_MASK_2MB;
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
 *  Gather and verify all of the backtrace requirements.
 */
static void
arm64_stackframe_init(void)
{
	long task_struct_thread;
	long thread_struct_cpu_context;
	long context_sp, context_pc, context_fp;

	STRUCT_SIZE_INIT(note_buf, "note_buf_t");
	STRUCT_SIZE_INIT(elf_prstatus, "elf_prstatus");
	MEMBER_OFFSET_INIT(elf_prstatus_pr_pid, "elf_prstatus", "pr_pid");
	MEMBER_OFFSET_INIT(elf_prstatus_pr_reg, "elf_prstatus", "pr_reg");

	machdep->machspec->__exception_text_start = 
		symbol_value("__exception_text_start");
	machdep->machspec->__exception_text_end = 
		symbol_value("__exception_text_end");

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
		error(INFO, "builtin stackframe.sp offset incorrect!\n");
		return;
	}
	if (offsetof(struct arm64_stackframe, fp) != 
	    MEMBER_OFFSET("stackframe", "fp")) {
		error(INFO, "builtin stackframe.fp offset incorrect!\n");
		return;
	}
	if (offsetof(struct arm64_stackframe, pc) != 
	    MEMBER_OFFSET("stackframe", "pc")) {
		error(INFO, "builtin stackframe.pc offset incorrect!\n");
		return;
	}

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

#define USER_EFRAME_OFFSET (304)

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

static int arm64_eframe_search(struct bt_info *bt)
{
	ulong ptr, count;
        struct arm64_pt_regs *regs;

	count = 0;
	for (ptr = bt->stackbase; ptr < bt->stacktop - SIZE(pt_regs); ptr++) {
        	regs = (struct arm64_pt_regs *)&bt->stackbuf[(ulong)(STACK_OFFSET_TYPE(ptr))];

		if (INSTACK(regs->sp, bt) && INSTACK(regs->regs[29], bt) && 
		    !(regs->pstate & (0xffffffff00000000ULL | PSR_MODE32_BIT)) &&
		    is_kernel_text(regs->pc) &&
		    is_kernel_text(regs->regs[30])) {
			switch (regs->pstate & PSR_MODE_MASK)
			{
			case PSR_MODE_EL1t:
			case PSR_MODE_EL1h:
				fprintf(fp, 
				    "\nKERNEL-MODE EXCEPTION FRAME AT: %lx\n", ptr); 
				arm64_print_exception_frame(bt, ptr, KERNEL_MODE);
				count++;
				break;
			}
		}
	}

	if (is_kernel_thread(bt->tc->task))
		return count;

	ptr = bt->stacktop - USER_EFRAME_OFFSET;
	fprintf(fp, "%sUSER-MODE EXCEPTION FRAME AT: %lx\n", 
		count++ ? "\n" : "", ptr); 
	arm64_print_exception_frame(bt, ptr, USER_MODE);

	return count;
}

static int
arm64_in_exception_text(ulong ptr)
{
	struct machine_specific *ms = machdep->machspec;

        return((ptr >= ms->__exception_text_start) &&
               (ptr < ms->__exception_text_end));
}

#define BACKTRACE_CONTINUE        (1)
#define BACKTRACE_COMPLETE_KERNEL (2)
#define BACKTRACE_COMPLETE_USER   (3)

static int 
arm64_print_stackframe_entry(struct bt_info *bt, int level, struct arm64_stackframe *frame)
{
	char *name, *name_plus_offset;
	ulong symbol_offset;
	struct syment *sp;
	struct load_module *lm;
	char buf[BUFSIZE];

        name = closest_symbol(frame->pc);
        name_plus_offset = NULL;

        if (bt->flags & BT_SYMBOL_OFFSET) {
                sp = value_search(frame->pc, &symbol_offset);
                if (sp && symbol_offset)
                        name_plus_offset =
                                value_to_symstr(frame->pc, buf, bt->radix);
        }

	if (bt->flags & BT_FULL) {
		arm64_display_full_frame(bt, frame->sp);
		bt->frameptr = frame->sp;
	}

        fprintf(fp, "%s#%d [%8lx] %s at %lx", level < 10 ? " " : "", level,
                frame->sp, name_plus_offset ? name_plus_offset : name, frame->pc);

	if (module_symbol(frame->pc, NULL, &lm, NULL, 0))
		fprintf(fp, " [%s]", lm->mod_name);

	fprintf(fp, "\n");

	if (bt->flags & BT_LINE_NUMBERS) {
		get_line_number(frame->pc, buf, FALSE);
		if (strlen(buf))
			fprintf(fp, "    %s\n", buf);
	}

	if (STREQ(name, "start_kernel") || STREQ(name, "secondary_start_kernel") ||
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

	if (!INSTACK(sp, bt) || !INSTACK(bt->frameptr, bt))
		return;

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

static int arm64_unwind_frame(struct bt_info *bt, struct arm64_stackframe *frame)
{
	unsigned long high, low, fp;
	unsigned long stack_mask;
	
	stack_mask = (unsigned long)(ARM64_STACK_SIZE) - 1;
	fp = frame->fp;

	low  = frame->sp;
	high = (low + stack_mask) & ~(stack_mask);

	if (fp < low || fp > high || fp & 0xf)
		return FALSE;

	frame->sp = fp + 0x10;
	frame->fp = GET_STACK_ULONG(fp);
	frame->pc = GET_STACK_ULONG(fp + 8);

	return TRUE;
}

static void arm64_back_trace_cmd(struct bt_info *bt)
{
	struct arm64_stackframe stackframe;
	int level;
	ulong exception_frame;

	if (BT_REFERENCE_CHECK(bt))
		option_not_supported('R');

	if (bt->flags & BT_USER_SPACE) {
		fprintf(fp, "#0 [user space]\n");
		return;
	}

	stackframe.sp = bt->stkptr;
	stackframe.pc = bt->instptr;
	stackframe.fp = bt->frameptr;

	level = exception_frame = 0;
        while (1) {
		bt->instptr = stackframe.pc;

		switch (arm64_print_stackframe_entry(bt, level, &stackframe))
		{
		case BACKTRACE_COMPLETE_KERNEL:
			return;
		case BACKTRACE_COMPLETE_USER:
			goto complete_user;
		case BACKTRACE_CONTINUE:
			break;
		}

		if (exception_frame) {
			arm64_print_exception_frame(bt, exception_frame, 
				KERNEL_MODE);
			exception_frame = 0;
		}

                if (!arm64_unwind_frame(bt, &stackframe))
                        break;

        	if (arm64_in_exception_text(bt->instptr)) {
			if (stackframe.fp)
				exception_frame = stackframe.fp - SIZE(pt_regs);
		}

		level++;
        }

	if (is_kernel_thread(bt->tc->task)) 
		return;

complete_user:
	exception_frame = bt->stacktop - USER_EFRAME_OFFSET;
	arm64_print_exception_frame(bt, exception_frame, USER_MODE);
}

static int
arm64_get_dumpfile_stackframe(struct bt_info *bt, struct arm64_stackframe *frame)
{
	struct machine_specific *ms = machdep->machspec;
	struct arm64_pt_regs *ptregs;

	if (!ms->panic_task_regs)
		return FALSE;

	ptregs = &ms->panic_task_regs[bt->tc->processor];
	frame->sp = ptregs->sp;
	frame->pc = ptregs->pc;
	frame->fp = ptregs->regs[29];

	if (!is_kernel_text(frame->pc) && 
	    in_user_stack(bt->tc->task, frame->sp))
		bt->flags |= BT_USER_SPACE;

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
	struct arm64_stackframe stackframe;

	if (DUMPFILE() && is_task_active(bt->task))
		ret = arm64_get_dumpfile_stackframe(bt, &stackframe);
	else
		ret = arm64_get_stackframe(bt, &stackframe);

	if (!ret) {
		error(WARNING, 
			"cannot determine starting stack frame for task %lx\n",
				bt->task);
		return;
	}

	bt->frameptr = stackframe.fp;
	if (pcp)
		*pcp = stackframe.pc;
	if (spp)
		*spp = stackframe.sp;
}

static void
arm64_print_exception_frame(struct bt_info *bt, ulong pt_regs, int mode)
{
	int i, r, rows, top_reg, is_64_bit;
	struct arm64_pt_regs *regs;
	struct syment *sp;
	ulong LR, SP, offset;
	char buf[BUFSIZE];

	if (CRASHDEBUG(1))
		fprintf(fp, "pt_regs: %lx\n", pt_regs);

	regs = (struct arm64_pt_regs *)&bt->stackbuf[(ulong)(STACK_OFFSET_TYPE(pt_regs))];

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
			fprintf(fp, 
			    "     PC: %016lx   LR: %016lx   SP: %016lx\n    ",
				(ulong)regs->pc, LR, SP);
		else
			fprintf(fp, 
			    "     PC: %08lx  LR: %08lx  SP: %08lx  PSTATE: %08lx\n    ",
				(ulong)regs->pc, LR, SP, (ulong)regs->pstate);
		break;

	case KERNEL_MODE:
		fprintf(fp, "     PC: %016lx  ", (ulong)regs->pc);
		if (is_kernel_text(regs->pc) &&
		    (sp = value_search(regs->pc, &offset))) {
			fprintf(fp, "[%s", sp->name);
			if (offset)
				fprintf(fp, (*gdb_output_radix == 16) ?
				    "+0x%lx" : "+%ld", 
					offset);
			fprintf(fp, "]\n");
		} else
			fprintf(fp, "[unknown or invalid address]\n");

		fprintf(fp, "     LR: %016lx  ", LR);
		if (is_kernel_text(LR) &&
		    (sp = value_search(LR, &offset))) {
			fprintf(fp, "[%s", sp->name);
			if (offset)
				fprintf(fp, (*gdb_output_radix == 16) ?
				    "+0x%lx" : "+%ld", 
					offset);
			fprintf(fp, "]\n");
		} else
			fprintf(fp, "[unknown or invalid address]\n");

		fprintf(fp, "     SP: %016lx  PSTATE: %08lx\n    ", 
			SP, (ulong)regs->pstate);
		break;
	}

	for (i = top_reg, r = 1; i >= 0; r++, i--) {
		fprintf(fp, "%sX%d: ", 
			i < 10 ? " " : "", i);
		fprintf(fp, is_64_bit ? "%016lx" : "%08lx",
			(ulong)regs->regs[i]);
		if ((i == 0) || ((r % rows) == 0))
			fprintf(fp, "\n    ");
		else
			fprintf(fp, "%s", is_64_bit ? "  " : " "); 
	}

	if (is_64_bit) {
		fprintf(fp, "ORIG_X0: %016lx  SYSCALLNO: %lx",
			(ulong)regs->orig_x0, (ulong)regs->syscallno);
		if (mode == USER_MODE)
			fprintf(fp, "  PSTATE: %08lx", (ulong)regs->pstate);
		fprintf(fp, "\n");
	}

	if (is_kernel_text(regs->pc) && (bt->flags & BT_LINE_NUMBERS)) {
		get_line_number(regs->pc, buf, FALSE);
		if (strlen(buf))
			fprintf(fp, "    %s\n", buf);
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
       	page_present = pte & (PTE_VALID | machdep->machspec->pte_protnone);

        if (physaddr) {
		*((ulong *)physaddr) = paddr;
		return page_present;
	}
        
	sprintf(ptebuf, "%lx", pte);
	len1 = MAX(strlen(ptebuf), strlen("PTE"));
	fprintf(fp, "%s  ", mkstring(buf1, len1, CENTER|LJUST, "PTE"));

        if (!page_present && (pte & PTE_FILE)) {
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
		if (THIS_KERNEL_VERSION >= LINUX(3,10,0)) {
			if (pte & machdep->machspec->pte_file)
				fprintf(fp, "%sFILE", others++ ? "|" : "");
			if (pte & machdep->machspec->pte_protnone)
				fprintf(fp, "%sPROTNONE", others++ ? "|" : "");
		} else {
			if (pte & machdep->machspec->pte_protnone)
				fprintf(fp, "%sPROTNONE", others++ ? "|" : "");
			if (pte & machdep->machspec->pte_file)
				fprintf(fp, "%sFILE", others++ ? "|" : "");
		} 
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
		while ((p1 > inbuf) && !STRNEQ(p1, " 0x"))
			p1--;

		if (!STRNEQ(p1, " 0x"))
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
}

static int
arm64_get_smp_cpus(void)
{
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

	if (!(ms->panic_task_regs = malloc(kt->cpus * sizeof(struct arm64_pt_regs))))
		error(FATAL, "cannot malloc panic_task_regs space\n");
	
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
arm64_in_alternate_stack(int cpu, ulong stkptr)
{
	NOT_IMPLEMENTED(INFO);
	return FALSE;
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

	if (!(sp = symbol_search("swapper_pg_dir")) &&
	    !(sp = symbol_search("idmap_pg_dir")) &&
	    !(sp = symbol_search("_text")) &&
	    !(sp = symbol_search("stext"))) { 
		for (sp = st->symtable; sp < st->symend; sp++) {
			if (highest_bit_long(sp->value) == 63)
				break;
		}
	}

	for (bitval = highest_bit_long(sp->value); bitval; bitval--) {
		if ((sp->value & (1UL << bitval)) == 0) {
			machdep->machspec->VA_BITS = bitval + 2;
			break;
		}
	}

	if (CRASHDEBUG(1))
		fprintf(fp, "VA_BITS: %ld\n", machdep->machspec->VA_BITS);

}

static int
arm64_is_uvaddr(ulong addr, struct task_context *tc)
{
        return (addr < ARM64_USERSPACE_TOP);
}

#endif  /* ARM64 */

