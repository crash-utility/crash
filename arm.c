/*
 * arm.c - core analysis suite
 *
 * Authors:
 *   Thomas Fänge <thomas.fange@sonyericsson.com>
 *   Jan Karlsson <jan.karlsson@sonyericsson.com>
 *   Mika Westerberg <ext-mika.1.westerberg@nokia.com>
 *
 * Copyright (C) 2010-2011 Nokia Corporation
 * Copyright (C) 2010 Sony Ericsson. All rights reserved.
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

#ifdef ARM
#include <elf.h>

#include "defs.h"

static void arm_parse_cmdline_args(void);
static void arm_get_crash_notes(void);
static int arm_verify_symbol(const char *, ulong, char);
static int arm_is_module_addr(ulong);
static int arm_is_kvaddr(ulong);
static int arm_is_uvaddr(ulong, struct task_context *);
static int arm_in_exception_text(ulong);
static int arm_in_ret_from_syscall(ulong, int *);
static void arm_back_trace(struct bt_info *);
static void arm_back_trace_cmd(struct bt_info *);
static ulong arm_processor_speed(void);
static int arm_translate_pte(ulong, void *, ulonglong);
static int arm_vtop(ulong, ulong *, physaddr_t *, int);
static int arm_kvtop(struct task_context *, ulong, physaddr_t *, int);
static int arm_uvtop(struct task_context *, ulong, physaddr_t *, int);
static int arm_get_frame(struct bt_info *, ulong *, ulong *);
static int arm_get_dumpfile_stack_frame(struct bt_info *, ulong *, ulong *);
static void arm_get_stack_frame(struct bt_info *, ulong *, ulong *);
static void arm_dump_exception_stack(ulong, ulong);
static void arm_display_full_frame(struct bt_info *, ulong);
static ulong arm_vmalloc_start(void);
static int arm_is_task_addr(ulong);
static int arm_dis_filter(ulong, char *, unsigned int);
static int arm_eframe_search(struct bt_info *);
static ulong arm_get_task_pgd(ulong);
static void arm_cmd_mach(void);
static void arm_display_machine_stats(void);
static int arm_get_smp_cpus(void);
static void arm_init_machspec(void);

static struct line_number_hook arm_line_number_hooks[];
static struct machine_specific arm_machine_specific;

/**
 * struct arm_cpu_context_save - idle task registers
 *
 * This structure holds idle task registers. Only FP, SP, and PC are needed for
 * unwinding the stack.
 */
struct arm_cpu_context_save {
	ulong	fp;
	ulong	sp;
	ulong	pc;
};

/*
 * Holds registers during the crash.
 */
static struct arm_pt_regs *panic_task_regs;

#define PGDIR_SIZE() (4 * PAGESIZE())
#define PGDIR_OFFSET(X) (((ulong)(X)) & (PGDIR_SIZE() - 1))

#define _SECTION_PAGE_MASK	(~((MEGABYTES(1))-1))

#define PMD_TYPE_MASK   3
#define PMD_TYPE_SECT   2
#define PMD_TYPE_TABLE  1
#define PMD_TYPE_SECT_LPAE 1

static inline ulong *
pmd_page_addr(ulong pmd)
{
	ulong ptr;

	if (machdep->flags & PGTABLE_V2) {
		ptr = PAGEBASE(pmd);
	} else {
		ptr = pmd & ~(PTRS_PER_PTE * sizeof(void *) - 1);
		ptr += PTRS_PER_PTE * sizeof(void *);
	}

	return (ulong *)ptr;
}

/*
 * "Linux" PTE definitions.
 */
#define L_PTE_PRESENT		(1 << 0)
#define L_PTE_YOUNG		(1 << 1)
#define L_PTE_FILE		(1 << 2)
#define L_PTE_DIRTY		(1 << 6)
#define L_PTE_WRITE		(1 << 7)
#define L_PTE_RDONLY		L_PTE_WRITE
#define L_PTE_USER		(1 << 8)
#define L_PTE_EXEC		(1 << 9)
#define L_PTE_XN		L_PTE_EXEC
#define L_PTE_SHARED		(1 << 10)

#define pte_val(pte)		(pte)

#define pte_present(pte)	(pte_val(pte) & L_PTE_PRESENT)
#define pte_write(pte)		(pte_val(pte) & L_PTE_WRITE)
#define pte_rdonly(pte)		(pte_val(pte) & L_PTE_RDONLY)
#define pte_dirty(pte)		(pte_val(pte) & L_PTE_DIRTY)
#define pte_young(pte)		(pte_val(pte) & L_PTE_YOUNG)
#define pte_exec(pte)		(pte_val(pte) & L_PTE_EXEC)
#define pte_xn(pte)		(pte_val(pte) & L_PTE_XN)

/*
 * Following stuff is taken directly from the kernel sources. These are used in
 * dump_exception_stack() to format an exception stack entry.
 */
#define USR26_MODE	0x00000000
#define FIQ26_MODE	0x00000001
#define IRQ26_MODE	0x00000002
#define SVC26_MODE	0x00000003
#define USR_MODE	0x00000010
#define FIQ_MODE	0x00000011
#define IRQ_MODE	0x00000012
#define SVC_MODE	0x00000013
#define ABT_MODE	0x00000017
#define UND_MODE	0x0000001b
#define SYSTEM_MODE	0x0000001f
#define MODE32_BIT	0x00000010
#define MODE_MASK	0x0000001f
#define PSR_T_BIT	0x00000020
#define PSR_F_BIT	0x00000040
#define PSR_I_BIT	0x00000080
#define PSR_A_BIT	0x00000100
#define PSR_E_BIT	0x00000200
#define PSR_J_BIT	0x01000000
#define PSR_Q_BIT	0x08000000
#define PSR_V_BIT	0x10000000
#define PSR_C_BIT	0x20000000
#define PSR_Z_BIT	0x40000000
#define PSR_N_BIT	0x80000000

#define isa_mode(regs) \
	((((regs)->ARM_cpsr & PSR_J_BIT) >> 23) | \
	 (((regs)->ARM_cpsr & PSR_T_BIT) >> 5))

#define processor_mode(regs) \
	((regs)->ARM_cpsr & MODE_MASK)

#define interrupts_enabled(regs) \
	(!((regs)->ARM_cpsr & PSR_I_BIT))

#define fast_interrupts_enabled(regs) \
	(!((regs)->ARM_cpsr & PSR_F_BIT))

static const char *processor_modes[] = {
	"USER_26", "FIQ_26", "IRQ_26", "SVC_26", "UK4_26", "UK5_26",
	"UK6_26", "UK7_26" , "UK8_26", "UK9_26", "UK10_26", "UK11_26",
	"UK12_26", "UK13_26", "UK14_26", "UK15_26", "USER_32", "FIQ_32",
	"IRQ_32", "SVC_32", "UK4_32", "UK5_32", "UK6_32", "ABT_32",
	"UK8_32", "UK9_32", "UK10_32", "UND_32", "UK12_32", "UK13_32",
	"UK14_32", "SYS_32",
};

static const char *isa_modes[] = {
	"ARM" , "Thumb" , "Jazelle", "ThumbEE",
};

#define NOT_IMPLEMENTED() \
	error(FATAL, "%s: N/A\n", __func__)

/*
 * Do all necessary machine-specific setup here. This is called several times
 * during initialization.
 */
void
arm_init(int when)
{
	ulong vaddr;
	char *string;
	struct syment *sp;

#if defined(__i386__) || defined(__x86_64__)
	if (ACTIVE())
		error(FATAL, "compiled for the ARM architecture\n");
#endif

	switch (when) {
	case PRE_SYMTAB:
		machdep->verify_symbol = arm_verify_symbol;
		machdep->machspec = &arm_machine_specific;
		if (pc->flags & KERNEL_DEBUG_QUERY)
			return;
		machdep->pagesize = memory_page_size();
		machdep->pageshift = ffs(machdep->pagesize) - 1;
		machdep->pageoffset = machdep->pagesize - 1;
		machdep->pagemask = ~((ulonglong)machdep->pageoffset);
		machdep->stacksize = machdep->pagesize * 2;
		machdep->last_pgd_read = 0;
		machdep->last_pmd_read = 0;
		machdep->last_ptbl_read = 0;
		machdep->verify_paddr = generic_verify_paddr;
		machdep->ptrs_per_pgd = PTRS_PER_PGD;

		if (machdep->cmdline_args[0])
			arm_parse_cmdline_args();
		break;

	case PRE_GDB:
		if ((machdep->pgd = (char *)malloc(PGDIR_SIZE())) == NULL)
			error(FATAL, "cannot malloc pgd space.");
		if ((machdep->pmd = (char *)malloc(PMDSIZE())) == NULL)
			error(FATAL, "cannot malloc pmd space.");
		if ((machdep->ptbl = (char *)malloc(PAGESIZE())) == NULL)
			error(FATAL, "cannot malloc ptbl space.");

		/*
		 * LPAE requires an additional page for the PGD, 
		 * so PG_DIR_SIZE = 0x5000 for LPAE
		 */
		if ((string = pc->read_vmcoreinfo("CONFIG_ARM_LPAE"))) {
			machdep->flags |= PAE;
			free(string);
		} else if ((sp = next_symbol("swapper_pg_dir", NULL)) &&
		         (sp->value - symbol_value("swapper_pg_dir")) == 0x5000)
                         machdep->flags |= PAE;

		machdep->kvbase = symbol_value("_stext") & ~KVBASE_MASK;
		machdep->identity_map_base = machdep->kvbase;
		machdep->is_kvaddr = arm_is_kvaddr;
		machdep->is_uvaddr = arm_is_uvaddr;
		machdep->eframe_search = arm_eframe_search;
		machdep->back_trace = arm_back_trace_cmd;
		machdep->processor_speed = arm_processor_speed;
		machdep->uvtop = arm_uvtop;
		machdep->kvtop = arm_kvtop;
		machdep->get_task_pgd = arm_get_task_pgd;
		machdep->get_stack_frame = arm_get_stack_frame;
		machdep->get_stackbase = generic_get_stackbase;
		machdep->get_stacktop = generic_get_stacktop;
		machdep->translate_pte = arm_translate_pte;
		machdep->memory_size = generic_memory_size;
		machdep->vmalloc_start = arm_vmalloc_start;
		machdep->is_task_addr = arm_is_task_addr;
		machdep->dis_filter = arm_dis_filter;
		machdep->cmd_mach = arm_cmd_mach;
		machdep->get_smp_cpus = arm_get_smp_cpus;
		machdep->line_number_hooks = arm_line_number_hooks;
		machdep->value_to_symbol = generic_machdep_value_to_symbol;
		machdep->init_kernel_pgd = NULL;
		machdep->dump_irq = generic_dump_irq;
		machdep->show_interrupts = generic_show_interrupts;
		machdep->get_irq_affinity = generic_get_irq_affinity;

		arm_init_machspec();
		break;

	case POST_GDB:
		/*
		 * Starting from 2.6.38 hardware and Linux page tables
		 * were reordered. See also mainline kernel commit
		 * d30e45eeabe (ARM: pgtable: switch order of Linux vs
		 * hardware page tables).
		 */
		if (THIS_KERNEL_VERSION > LINUX(2,6,37) ||
		    STRUCT_EXISTS("pteval_t"))
			machdep->flags |= PGTABLE_V2;

		if (THIS_KERNEL_VERSION >= LINUX(3,3,0) ||
		    symbol_exists("idmap_pgd"))
			machdep->flags |= IDMAP_PGD;
		if (machdep->flags & PAE) {
			machdep->section_size_bits = _SECTION_SIZE_BITS_LPAE;
			machdep->max_physmem_bits = _MAX_PHYSMEM_BITS_LPAE;
		} else {
			machdep->section_size_bits = _SECTION_SIZE_BITS;
			machdep->max_physmem_bits = _MAX_PHYSMEM_BITS;
		}

		if (symbol_exists("irq_desc"))
			ARRAY_LENGTH_INIT(machdep->nr_irqs, irq_desc,
					  "irq_desc", NULL, 0);
		else if (kernel_symbol_exists("nr_irqs"))
			get_symbol_data("nr_irqs", sizeof(unsigned int),
				&machdep->nr_irqs);
		/*
		 * Registers for idle threads are saved in
		 * thread_info.cpu_context.
		 */
		STRUCT_SIZE_INIT(cpu_context_save, "cpu_context_save");
		MEMBER_OFFSET_INIT(cpu_context_save_r7,
			"cpu_context_save", "r7");
		MEMBER_OFFSET_INIT(cpu_context_save_fp,
			"cpu_context_save", "fp");
		MEMBER_OFFSET_INIT(cpu_context_save_sp,
			"cpu_context_save", "sp");
		MEMBER_OFFSET_INIT(cpu_context_save_pc,
			"cpu_context_save", "pc");
		MEMBER_OFFSET_INIT(thread_info_cpu_context,
			"thread_info", "cpu_context");

		/*
		 * We need to have information about note_buf_t which is used to
		 * hold ELF note containing registers and status of the thread
		 * that panic'd.
		 */
		STRUCT_SIZE_INIT(note_buf, "note_buf_t");

		STRUCT_SIZE_INIT(elf_prstatus, "elf_prstatus");
		MEMBER_OFFSET_INIT(elf_prstatus_pr_pid, "elf_prstatus",
				   "pr_pid");
		MEMBER_OFFSET_INIT(elf_prstatus_pr_reg, "elf_prstatus",
				   "pr_reg");
	
		if (!machdep->hz)
			machdep->hz = 100;
		break;

	case POST_VM:
		machdep->machspec->vmalloc_start_addr = vt->high_memory;
		/*
		 * Modules are placed in first vmalloc'd area. This is 16MB
		 * below PAGE_OFFSET.
		 */
		machdep->machspec->modules_end = machdep->kvbase - 1;
		vaddr = first_vmalloc_address();
		if (vaddr > machdep->machspec->modules_end)
			machdep->machspec->modules_vaddr = DEFAULT_MODULES_VADDR;
		else
			machdep->machspec->modules_vaddr = vaddr;

		/*
		 * crash_notes contains machine specific information about the
		 * crash. In particular, it contains CPU registers at the time
		 * of the crash. We need this information to extract correct
		 * backtraces from the panic task.
		 */
		if (!ACTIVE())
			arm_get_crash_notes();

		if (init_unwind_tables()) {
			if (CRASHDEBUG(1))
				fprintf(fp, "using unwind tables\n");
		} else {
			if (CRASHDEBUG(1))
				fprintf(fp, "using framepointers\n");
		}
		break;

	case LOG_ONLY:
		machdep->machspec = &arm_machine_specific;
		machdep->kvbase = kt->vmcoreinfo._stext_SYMBOL & 0xffff0000UL;
		arm_init_machspec();
		break;
	}
}

void
arm_dump_machdep_table(ulong arg)
{
	const struct machine_specific *ms;
	int others, i;

        others = 0;
        fprintf(fp, "              flags: %lx (", machdep->flags);
	if (machdep->flags & KSYMS_START)
		fprintf(fp, "%sKSYMS_START", others++ ? "|" : "");
	if (machdep->flags & PHYS_BASE)
		fprintf(fp, "%sPHYS_BASE", others++ ? "|" : "");
	if (machdep->flags & PGTABLE_V2)
		fprintf(fp, "%sPGTABLE_V2", others++ ? "|" : "");
	if (machdep->flags & IDMAP_PGD)
		fprintf(fp, "%sIDMAP_PGD", others++ ? "|" : "");
	if (machdep->flags & PAE)
		fprintf(fp, "%sPAE", others++ ? "|" : "");
        fprintf(fp, ")\n");

	fprintf(fp, "             kvbase: %lx\n", machdep->kvbase);
	fprintf(fp, "  identity_map_base: %lx\n", machdep->kvbase);
	fprintf(fp, "           pagesize: %d\n", machdep->pagesize);
	fprintf(fp, "          pageshift: %d\n", machdep->pageshift);
	fprintf(fp, "           pagemask: %lx\n", (ulong)machdep->pagemask);
	fprintf(fp, "         pageoffset: %lx\n", machdep->pageoffset);
	fprintf(fp, "          stacksize: %ld\n", machdep->stacksize);
	fprintf(fp, "                 hz: %d\n", machdep->hz);
	fprintf(fp, "                mhz: %ld\n", machdep->mhz);
	fprintf(fp, "            memsize: %lld (0x%llx)\n",
		machdep->memsize, machdep->memsize);
	fprintf(fp, "               bits: %d\n", machdep->bits);
	fprintf(fp, "            nr_irqs: %d\n", machdep->nr_irqs);
	fprintf(fp, "      eframe_search: arm_eframe_search()\n");
	fprintf(fp, "         back_trace: arm_back_trace_cmd()\n");
	fprintf(fp, "    processor_speed: arm_processor_speed()\n");
	fprintf(fp, "              uvtop: arm_uvtop()\n");
	fprintf(fp, "              kvtop: arm_kvtop()\n");
	fprintf(fp, "       get_task_pgd: arm_get_task_pgd()\n");
	fprintf(fp, "           dump_irq: generic_dump_irq()\n");
	fprintf(fp, "    get_stack_frame: arm_get_stack_frame()\n");
	fprintf(fp, "      get_stackbase: generic_get_stackbase()\n");
	fprintf(fp, "       get_stacktop: generic_get_stacktop()\n");
	fprintf(fp, "      translate_pte: arm_translate_pte()\n");
	fprintf(fp, "        memory_size: generic_memory_size()\n");
	fprintf(fp, "      vmalloc_start: arm_vmalloc_start()\n");
	fprintf(fp, "       is_task_addr: arm_is_task_addr()\n");
	fprintf(fp, "      verify_symbol: arm_verify_symbol()\n");
	fprintf(fp, "         dis_filter: arm_dis_filter()\n");
	fprintf(fp, "           cmd_mach: arm_cmd_mach()\n");
	fprintf(fp, "       get_smp_cpus: arm_get_smp_cpus()\n");
	fprintf(fp, "          is_kvaddr: arm_is_kvaddr()\n");
	fprintf(fp, "          is_uvaddr: arm_is_uvaddr()\n");
	fprintf(fp, "       verify_paddr: generic_verify_paddr()\n");
	fprintf(fp, "    show_interrupts: generic_show_interrupts()\n");
        fprintf(fp, "   get_irq_affinity: generic_get_irq_affinity()\n");

	fprintf(fp, " xendump_p2m_create: NULL\n");
	fprintf(fp, "xen_kdump_p2m_create: NULL\n");
	fprintf(fp, "  line_number_hooks: arm_line_number_hooks\n");
	fprintf(fp, "      last_pgd_read: %lx\n", machdep->last_pgd_read);
	fprintf(fp, "      last_pmd_read: %lx\n", machdep->last_pmd_read);
	fprintf(fp, "     last_ptbl_read: %lx\n", machdep->last_ptbl_read);
	fprintf(fp, "clear_machdep_cache: NULL\n");
	fprintf(fp, "                pgd: %lx\n", (ulong)machdep->pgd);
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

	ms = machdep->machspec;

	fprintf(fp, "           machspec: %lx\n", (ulong)ms);
	fprintf(fp, "          phys_base: %lx\n", ms->phys_base);
	fprintf(fp, " vmalloc_start_addr: %lx\n", ms->vmalloc_start_addr);
	fprintf(fp, "      modules_vaddr: %lx\n", ms->modules_vaddr);
	fprintf(fp, "        modules_end: %lx\n", ms->modules_end);
	fprintf(fp, "  kernel_text_start: %lx\n", ms->kernel_text_start);
	fprintf(fp, "    kernel_text_end: %lx\n", ms->kernel_text_end);
	fprintf(fp, "exception_text_start: %lx\n", ms->exception_text_start);
	fprintf(fp, " exception_text_end: %lx\n", ms->exception_text_end);
	fprintf(fp, "    crash_task_regs: %lx\n", (ulong)ms->crash_task_regs);
	fprintf(fp, "unwind_index_prel31: %d\n", ms->unwind_index_prel31);
}

/*
 * Parse machine dependent command line arguments.
 *
 * Force the phys_base address via:
 *
 *  --machdep phys_base=<address>
 */
static void
arm_parse_cmdline_args(void)
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

			if (STRNEQ(arglist[i], "phys_base=")) {
				int megabytes = FALSE;
				int flags = RETURN_ON_ERROR | QUIET;

				if ((LASTCHAR(arglist[i]) == 'm') ||
				    (LASTCHAR(arglist[i]) == 'M')) {
					LASTCHAR(arglist[i]) = NULLCHAR;
					megabytes = TRUE;
				}

				p = arglist[i] + strlen("phys_base=");
				if (strlen(p)) {
					if (megabytes)
						value = dtol(p, flags, &err);
					else
						value = htol(p, flags, &err);
				}

				if (!err) {
					if (megabytes)
						value = MEGABYTES(value);

					machdep->machspec->phys_base = value;

					error(NOTE,
						"setting phys_base to: 0x%lx\n",
						machdep->machspec->phys_base);

					machdep->flags |= PHYS_BASE;
					continue;
				}
			}

			error(WARNING, "ignoring --machdep option: %s\n",
				arglist[i]);
		}
	}
}

/*
 * Retrieve task registers for the time of the crash.
 */
static void
arm_get_crash_notes(void)
{
	struct machine_specific *ms = machdep->machspec;
	ulong crash_notes;
	Elf32_Nhdr *note;
	ulong offset;
	char *buf, *p;
	ulong *notes_ptrs;
	ulong i, found;

	if (!symbol_exists("crash_notes"))
		return;

	crash_notes = symbol_value("crash_notes");

	notes_ptrs = (ulong *)GETBUF(kt->cpus*sizeof(notes_ptrs[0]));

	/*
	 * Read crash_notes for the first CPU. crash_notes are in standard ELF
	 * note format.
	 */
	if (!readmem(crash_notes, KVADDR, &notes_ptrs[kt->cpus-1], 
	    sizeof(notes_ptrs[kt->cpus-1]), "crash_notes",
		     RETURN_ON_ERROR)) {
		error(WARNING, "cannot read crash_notes\n");
		FREEBUF(notes_ptrs);
		return;
	}

	if (symbol_exists("__per_cpu_offset")) {
		/* Add __per_cpu_offset for each cpu to form the pointer to the notes */
		for (i = 0; i<kt->cpus; i++)
			notes_ptrs[i] = notes_ptrs[kt->cpus-1] + kt->__per_cpu_offset[i];	
	}

	buf = GETBUF(SIZE(note_buf));

	if (!(panic_task_regs = calloc((size_t)kt->cpus, sizeof(*panic_task_regs))))
		error(FATAL, "cannot calloc panic_task_regs space\n");
	
	for  (i = found = 0; i<kt->cpus; i++) {
		if (!readmem(notes_ptrs[i], KVADDR, buf, SIZE(note_buf), "note_buf_t",
			     RETURN_ON_ERROR)) {
			error(WARNING, "cpu %d: cannot read NT_PRSTATUS note\n", i);
			continue;
		}

		/*
		 * Do some sanity checks for this note before reading registers from it.
		 */
		note = (Elf32_Nhdr *)buf;
		p = buf + sizeof(Elf32_Nhdr);

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
				long notesz = SIZE(note_buf) - sizeof(Elf32_Nhdr);

				if (sizeof(Elf32_Nhdr) + roundup(note->n_namesz, 4) +
				    note->n_descsz == notesz)
					BCOPY((char *)note, buf, notesz);
			} else {
				error(WARNING, "cpu %d: cannot find NT_PRSTATUS note\n", i);
				continue;
			}
		}
		/*
		 * Check the sanity of NT_PRSTATUS note only for each online cpu.
		 * If this cpu has invalid note, continue to find the crash notes
		 * for other online cpus.
		 */
		if (note->n_type != NT_PRSTATUS) {
			error(WARNING, "cpu %d: invalid NT_PRSTATUS note (n_type != NT_PRSTATUS)\n", i);
			continue;
		}

		if (!STRNEQ(p, "CORE")) {
			error(WARNING, "cpu %d: invalid NT_PRSTATUS note (name != \"CORE\")\n", i);
			continue;
		}

		/*
		 * Find correct location of note data. This contains elf_prstatus
		 * structure which has registers etc. for the crashed task.
		 */
		offset = sizeof(Elf32_Nhdr);
		offset = roundup(offset + note->n_namesz, 4);
		p = buf + offset; /* start of elf_prstatus */

		BCOPY(p + OFFSET(elf_prstatus_pr_reg), &panic_task_regs[i],
		      sizeof(panic_task_regs[i]));

		found++;
	}

	/*
	 * And finally we have the registers for the crashed task. This is
	 * used later on when dumping backtrace.
	 */
	ms->crash_task_regs = panic_task_regs;

	FREEBUF(buf);
	FREEBUF(notes_ptrs);
	if (!found) {
		free(panic_task_regs);
		ms->crash_task_regs = NULL;
	}
}

/*
 * Accept or reject a symbol from the kernel namelist.
 */
static int
arm_verify_symbol(const char *name, ulong value, char type)
{
	if (STREQ(name, "swapper_pg_dir"))
		machdep->flags |= KSYMS_START;

	if (!name || !strlen(name) || !(machdep->flags & KSYMS_START))
		return FALSE;

	if (STREQ(name, "$a") || STREQ(name, "$n") || STREQ(name, "$d"))
		return FALSE;

	if (STREQ(name, "PRRR") || STREQ(name, "NMRR"))
		return FALSE;

	if ((type == 'A') && STRNEQ(name, "__crc_"))
		return FALSE;

	if (CRASHDEBUG(8) && name && strlen(name))
		fprintf(fp, "%08lx %s\n", value, name);

	return TRUE;
}

static int
arm_is_module_addr(ulong vaddr)
{
	ulong modules_start;
	ulong modules_end = machdep->machspec->modules_end;

	if (!MODULES_VADDR) {
		/*
		 * In case we are still initializing, and vm_init() has not been
		 * called, we use defaults here which is 16MB below kernel start
		 * address.
		 */
		modules_start = DEFAULT_MODULES_VADDR;
	} else {
		modules_start = MODULES_VADDR;
	}

	return (vaddr >= modules_start && vaddr <= modules_end);
}

int
arm_is_vmalloc_addr(ulong vaddr)
{
	if (arm_is_module_addr(vaddr))
		return TRUE;

	if (!VMALLOC_START)
		return FALSE;

	return (vaddr >= VMALLOC_START);
}

/*
 * Check whether given address falls inside kernel address space (including
 * modules).
 */
static int
arm_is_kvaddr(ulong vaddr)
{
	if (arm_is_module_addr(vaddr))
		return TRUE;

	return (vaddr >= machdep->kvbase);
}

static int
arm_is_uvaddr(ulong vaddr, struct task_context *unused)
{
	if (arm_is_module_addr(vaddr))
		return FALSE;

	return (vaddr < machdep->kvbase);
}

/*
 * Returns TRUE if given pc is in exception area.
 */
static int
arm_in_exception_text(ulong pc)
{
	ulong exception_start = machdep->machspec->exception_text_start;
	ulong exception_end = machdep->machspec->exception_text_end;

	if (exception_start && exception_end)
		return (pc >= exception_start && pc < exception_end);

	return FALSE;
}

/*
 * Returns TRUE if given pc points to a return from syscall
 * entrypoint. In case the function returns TRUE and if offset is given,
 * it is filled with the offset that should be added to the SP to get
 * address of the exception frame where the user registers are.
 */
static int
arm_in_ret_from_syscall(ulong pc, int *offset)
{
	/*
	 * On fast syscall return path, the stack looks like:
	 *
	 * SP + 0	{r4, r5}
	 * SP + 8	user pt_regs
	 *
	 * The asm syscall handler pushes fifth and sixth registers
	 * onto the stack before calling the actual syscall handler.
	 *
	 * So in order to print out the user registers at the time
	 * the syscall was made, we need to adjust SP for 8.
	 */
	if (pc == symbol_value("ret_fast_syscall")) {
		if (offset)
			*offset = 8;
		return TRUE;
	}

	/*
	 * In case we are on the slow syscall path, the SP already
	 * points to the start of the user registers hence no
	 * adjustments needs to be done.
	 */
	if (pc == symbol_value("ret_slow_syscall")) {
		if (offset)
			*offset = 0;
		return TRUE;
	}

	return FALSE;
}

/*
 *  Unroll the kernel stack using a minimal amount of gdb services.
 */
static void
arm_back_trace(struct bt_info *bt)
{
	int n = 0;

	/*
	 * In case bt->machdep contains pointer to a full register set, we take
	 * FP from there.
	 */
	if (bt->machdep) {
		const struct arm_pt_regs *regs = bt->machdep;
		bt->frameptr = regs->ARM_fp;
	}

	/*
	 * Stack frame layout:
	 *             optionally saved caller registers (r4 - r10)
	 *             saved fp
	 *             saved sp
	 *             saved lr
	 *    frame => saved pc
	 *             optionally saved arguments (r0 - r3)
	 * saved sp => <next word>
	 *
	 * Functions start with the following code sequence:
	 *                  mov   ip, sp
	 *                  stmfd sp!, {r0 - r3} (optional)
	 * corrected pc =>  stmfd sp!, {..., fp, ip, lr, pc}
	 */
	while (bt->frameptr && INSTACK(bt->frameptr, bt)) {
		ulong from;
		ulong sp;

		/*
		 * We correct the PC to point to the actual instruction (current
		 * value is PC + 8).
		 */
		bt->instptr = GET_STACK_ULONG(bt->frameptr - 0);
		bt->instptr -= 8;

		/*
		 * Now get LR, saved SP and FP from the frame as well.
		 */
		from = GET_STACK_ULONG(bt->frameptr - 4);
		sp = GET_STACK_ULONG(bt->frameptr - 8);
		bt->frameptr = GET_STACK_ULONG(bt->frameptr - 12);

		arm_dump_backtrace_entry(bt, n++, from, sp);

		bt->stkptr = sp;
	}
}

/*
 * Unroll a kernel stack.
 */
static void
arm_back_trace_cmd(struct bt_info *bt)
{
	if (bt->flags & BT_REGS_NOT_FOUND)
		return;

	if (kt->flags & DWARF_UNWIND)
		unwind_backtrace(bt);
	else
		arm_back_trace(bt);
}

/*
 * Calculate and return the speed of the processor.
 */
static ulong
arm_processor_speed(void)
{
	/*
	 * For now, we don't support reading CPU speed.
	 */
	return 0;
}

/*
 * Translate a PTE, returning TRUE if the page is present. If a physaddr pointer
 * is passed in, don't print anything.
 */
static int
arm_translate_pte(ulong pte, void *physaddr, ulonglong lpae_pte)
{
	char ptebuf[BUFSIZE];
	char physbuf[BUFSIZE];
	char buf[BUFSIZE];
	int page_present;
	ulonglong paddr;
	int len1, len2, others;

	if (machdep->flags & PAE) {
		paddr = LPAE_PAGEBASE(lpae_pte);
		sprintf(ptebuf, "%llx", lpae_pte);
		pte = (ulong)lpae_pte;
	} else {
		paddr = PAGEBASE(pte);
		sprintf(ptebuf, "%lx", pte);
	}
	page_present = pte_present(pte);
	if (physaddr) {
		if (machdep->flags & PAE)
			*((ulonglong *)physaddr) = paddr;
		else
			*((ulong *)physaddr) = (ulong)paddr;
		return page_present;
	}

	len1 = MAX(strlen(ptebuf), strlen("PTE"));
	fprintf(fp, "%s  ", mkstring(buf, len1, CENTER | LJUST, "PTE"));

	if (!page_present && pte) {
		/* swap page, not handled yet */
		return page_present;
	}

	sprintf(physbuf, "%llx", paddr);
	len2 = MAX(strlen(physbuf), strlen("PHYSICAL"));
	fprintf(fp, "%s  ", mkstring(buf, len2, CENTER | LJUST, "PHYSICAL"));

	fprintf(fp, "FLAGS\n");
	fprintf(fp, "%s  %s  ",
		mkstring(ptebuf, len1, CENTER | RJUST, NULL),
		mkstring(physbuf, len2, CENTER | RJUST, NULL));

	fprintf(fp, "(");
	others = 0;

	if (pte) {
		if (pte_present(pte))
			fprintf(fp, "%sPRESENT", others++ ? "|" : "");
		if (pte_dirty(pte))
			fprintf(fp, "%sDIRTY", others++ ? "|" : "");
		if (pte_young(pte))
			fprintf(fp, "%sYOUNG", others++ ? "|" : "");
		if (machdep->flags & PGTABLE_V2) {
			if (!pte_rdonly(pte))
				fprintf(fp, "%sWRITE", others++ ? "|" : "");
			if (!pte_xn(pte))
				fprintf(fp, "%sEXEC", others++ ? "|" : "");
		} else {
			if (pte_write(pte))
				fprintf(fp, "%sWRITE", others++ ? "|" : "");
			if (pte_exec(pte))
				fprintf(fp, "%sEXEC", others++ ? "|" : "");
		}
	} else {
		fprintf(fp, "no mapping");
	}

	fprintf(fp, ")\n");

	return 0;
}

/*
 * Virtual to physical memory translation. This function will be called by both
 * arm_kvtop() and arm_uvtop().
 */
static int
arm_vtop(ulong vaddr, ulong *pgd, physaddr_t *paddr, int verbose)
{
	char buf[BUFSIZE];
	ulong *page_dir;
	ulong *page_middle;
	ulong *page_table;
	ulong pgd_pte;
	ulong pmd_pte;
	ulong pte;

	/*
	 * Page tables in ARM Linux
	 *
	 * In hardware PGD is 16k (having 4096 pointers to PTE) and PTE is 1k
	 * (containing 256 translations).
	 *
	 * Linux, however, wants to have PTEs as page sized entities. This means
	 * that in ARM Linux we have following setup (see also
	 * arch/arm/include/asm/pgtable.h)
	 *
	 * Before 2.6.38
	 *
	 *     PGD                   PTE
	 * +---------+
	 * |         | 0  ---->  +------------+
	 * +- - - - -+           | h/w pt 0   |
	 * |         | 4  ---->  +------------+ +1024
	 * +- - - - -+           | h/w pt 1   |
	 * .         .           +------------+ +2048
	 * .         .           | Linux pt 0 |
	 * .         .           +------------+ +3072
	 * |         | 4095      | Linux pt 1 |
	 * +---------+           +------------+ +4096
	 *
	 * Starting from 2.6.38
	 *
	 *     PGD                   PTE
	 * +---------+
	 * |         | 0  ---->  +------------+
	 * +- - - - -+           | Linux pt 0 |
	 * |         | 4  ---->  +------------+ +1024
	 * +- - - - -+           | Linux pt 1 |
	 * .         .           +------------+ +2048
	 * .         .           | h/w pt 0   |
	 * .         .           +------------+ +3072
	 * |         | 4095      | h/w pt 1   |
	 * +---------+           +------------+ +4096
	 *
	 * So in Linux implementation we have two hardware pointers to second
	 * level page tables. Depending on the kernel version, the "Linux" page
	 * tables either follow or precede the hardware tables.
	 *
	 * Linux PT entries contain bits that are not supported on hardware, for
	 * example "young" and "dirty" flags.
	 *
	 * Our translation scheme only uses Linux PTEs here.
	 */

	if (verbose)
		fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)pgd);

	/*
	 * pgd_offset(pgd, vaddr)
	 */
	page_dir = pgd + PGD_OFFSET(vaddr) * 2;

	/* The unity-mapped region is mapped using 1MB pages,
	 * hence 1-level translation if bit 20 is set; if we
	 * are 1MB apart physically, we move the page_dir in
	 * case bit 20 is set.
	 */
	if (((vaddr) >> (20)) & 1)
		page_dir = page_dir + 1;

	FILL_PGD(PAGEBASE(pgd), KVADDR, PGDIR_SIZE());
	pgd_pte = ULONG(machdep->pgd + PGDIR_OFFSET(page_dir));

	if (verbose)
		fprintf(fp, "  PGD: %s => %lx\n",
			mkstring(buf, VADDR_PRLEN, RJUST | LONG_HEX,
			MKSTR((ulong)page_dir)), pgd_pte);

	if (!pgd_pte)
		return FALSE;

	/*
	 * pmd_offset(pgd, vaddr)
	 *
	 * Here PMD is folded into a PGD.
	 */
	pmd_pte = pgd_pte;
	page_middle = page_dir;

	if (verbose)
		fprintf(fp, "  PMD: %s => %lx\n",
			mkstring(buf, VADDR_PRLEN, RJUST | LONG_HEX,
			MKSTR((ulong)page_middle)), pmd_pte);

	if ((pmd_pte & PMD_TYPE_MASK) == PMD_TYPE_SECT) {
		ulong sectionbase = pmd_pte & _SECTION_PAGE_MASK;

		if (verbose) {
			fprintf(fp, " PAGE: %s  (1MB)\n\n",
				mkstring(buf, VADDR_PRLEN, RJUST | LONG_HEX,
				MKSTR(sectionbase)));
		}
		*paddr = sectionbase + (vaddr & ~_SECTION_PAGE_MASK);
		return TRUE;
	}

	/*
	 * pte_offset_map(pmd, vaddr)
	 */
	page_table = pmd_page_addr(pmd_pte) + PTE_OFFSET(vaddr);

	FILL_PTBL(PAGEBASE(page_table), PHYSADDR, PAGESIZE());
	pte = ULONG(machdep->ptbl + PAGEOFFSET(page_table));

	if (verbose) {
		fprintf(fp, "  PTE: %s => %lx\n\n",
			mkstring(buf, VADDR_PRLEN, RJUST | LONG_HEX,
			MKSTR((ulong)page_table)), pte);
	}

	if (!pte_present(pte)) {
		if (pte && verbose) {
			fprintf(fp, "\n");
			arm_translate_pte(pte, 0, 0);
		}
		return FALSE;
	}

	*paddr = PAGEBASE(pte) + PAGEOFFSET(vaddr);

	if (verbose) {
		fprintf(fp, " PAGE: %s\n\n",
			mkstring(buf, VADDR_PRLEN, RJUST | LONG_HEX,
			MKSTR(PAGEBASE(pte))));
		arm_translate_pte(pte, 0, 0);
	}

	return TRUE;
}

/*
 * Virtual to physical memory translation when "CONFIG_ARM_LPAE=y".
 * This function will be called by both arm_kvtop() and arm_uvtop().
 */
static int
arm_lpae_vtop(ulong vaddr, ulong *pgd, physaddr_t *paddr, int verbose)
{
	char buf[BUFSIZE];
	physaddr_t page_dir;
	physaddr_t page_middle;
	physaddr_t page_table;
	pgd_t pgd_pmd;
	pmd_t pmd_pte;
	pte_t pte;

	if (IS_KVADDR(vaddr)) {
		if (!vt->vmalloc_start) {
			*paddr = LPAE_VTOP(vaddr);
			return TRUE;
		}

		if (!IS_VMALLOC_ADDR(vaddr)) {
			*paddr = LPAE_VTOP(vaddr);
			if (!verbose)
				return TRUE;
		}
	}

	if (verbose)
		fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)pgd);

	/*
	 * pgd_offset(pgd, vaddr)
	 */
	page_dir = LPAE_VTOP((ulong)pgd + LPAE_PGD_OFFSET(vaddr) * 8);
	FILL_PGD_LPAE(LPAE_VTOP(pgd), PHYSADDR, LPAE_PGDIR_SIZE());
	pgd_pmd = ULONGLONG(machdep->pgd + LPAE_PGDIR_OFFSET(page_dir));

	if (verbose)
		fprintf(fp, "  PGD: %8llx => %llx\n",
			(ulonglong)page_dir, pgd_pmd);

	if (!pgd_pmd)
		return FALSE;

	/*
	 * pmd_offset(pgd, vaddr)
	 */
	page_middle = LPAE_PAGEBASE(pgd_pmd) + LPAE_PMD_OFFSET(vaddr) * 8;
	FILL_PMD_LPAE(LPAE_PAGEBASE(pgd_pmd), PHYSADDR, LPAE_PMDIR_SIZE());
	pmd_pte = ULONGLONG(machdep->pmd + LPAE_PMDIR_OFFSET(page_middle));

	if (!pmd_pte)
		return FALSE;

	if ((pmd_pte & PMD_TYPE_MASK) == PMD_TYPE_SECT_LPAE) {
		ulonglong sectionbase = LPAE_PAGEBASE(pmd_pte)
			& LPAE_SECTION_PAGE_MASK;

		if (verbose)
			fprintf(fp, " PAGE: %8llx  (2MB)\n\n",
				(ulonglong)sectionbase);

		*paddr = sectionbase + (vaddr & ~LPAE_SECTION_PAGE_MASK);
		return TRUE;
	}
	/*
	 * pte_offset_map(pmd, vaddr)
	 */
	page_table = LPAE_PAGEBASE(pmd_pte) + PTE_OFFSET(vaddr) * 8;
	FILL_PTBL_LPAE(LPAE_PAGEBASE(pmd_pte), PHYSADDR, LPAE_PTEDIR_SIZE());
	pte = ULONGLONG(machdep->ptbl + LPAE_PTEDIR_OFFSET(page_table));

	if (verbose) {
		fprintf(fp, "  PTE: %8llx => %llx\n\n",
			(ulonglong)page_table, pte);
	}

	if (!pte_present(pte)) {
		if (pte && verbose) {
			fprintf(fp, "\n");
			arm_translate_pte(0, 0, pte);
		}
		return FALSE;
	}

	*paddr = LPAE_PAGEBASE(pte) + PAGEOFFSET(vaddr);

	if (verbose) {
		fprintf(fp, " PAGE: %s\n\n",
			mkstring(buf, VADDR_PRLEN, RJUST | LONG_HEX, 
			MKSTR(PAGEBASE(pte))));
		arm_translate_pte(0, 0, pte);
	}
	return TRUE;
}

/*
 * Translates a user virtual address to its physical address. cmd_vtop() sets
 * the verbose flag so that the pte translation gets displayed; all other
 * callers quietly accept the translation.
 */
static int
arm_uvtop(struct task_context *tc, ulong uvaddr, physaddr_t *paddr, int verbose)
{
	ulong *pgd;

	if (!tc)
		error(FATAL, "current context invalid\n");

	/*
	 * Before idmap_pgd was introduced with upstream commit 2c8951ab0c
	 * (ARM: idmap: use idmap_pgd when setting up mm for reboot), the
	 * panic task pgd was overwritten by soft reboot code, so we can't do
	 * any vtop translations.
	 */
	if (!(machdep->flags & IDMAP_PGD) && tc->task == tt->panic_task)
		error(FATAL, "panic task pgd is trashed by soft reboot code\n");

	*paddr = 0;

        if (is_kernel_thread(tc->task) && IS_KVADDR(uvaddr)) {
		ulong active_mm;

		readmem(tc->task + OFFSET(task_struct_active_mm),
			KVADDR, &active_mm, sizeof(void *),
			"task active_mm contents", FAULT_ON_ERROR);

		if (!active_mm)
			error(FATAL,
			     "no active_mm for this kernel thread\n");

		readmem(active_mm + OFFSET(mm_struct_pgd),
			KVADDR, &pgd, sizeof(long),
			"mm_struct pgd", FAULT_ON_ERROR);
	} else {
		ulong mm;

		mm = task_mm(tc->task, TRUE);
		if (mm)
			pgd = ULONG_PTR(tt->mm_struct + OFFSET(mm_struct_pgd));
		else
			readmem(tc->mm_struct + OFFSET(mm_struct_pgd),
				KVADDR, &pgd, sizeof(long), "mm_struct pgd",
				FAULT_ON_ERROR);
	}

	if (machdep->flags & PAE)
		return arm_lpae_vtop(uvaddr, pgd, paddr, verbose);

	return arm_vtop(uvaddr, pgd, paddr, verbose);
}

/*
 * Translates a kernel virtual address to its physical address. cmd_vtop() sets
 * the verbose flag so that the pte translation gets displayed; all other
 * callers quietly accept the translation.
 */
static int
arm_kvtop(struct task_context *tc, ulong kvaddr, physaddr_t *paddr, int verbose)
{
	if (!IS_KVADDR(kvaddr))
		return FALSE;

	if (machdep->flags & PAE)
		return arm_lpae_vtop(kvaddr, (ulong *)vt->kernel_pgd[0],
			paddr, verbose);


	if (!vt->vmalloc_start) {
		*paddr = VTOP(kvaddr);
		return TRUE;
	}

	if (!IS_VMALLOC_ADDR(kvaddr)) {
		*paddr = VTOP(kvaddr);
		if (!verbose)
			return TRUE;
	}


	return arm_vtop(kvaddr, (ulong *)vt->kernel_pgd[0], paddr, verbose);
}

/*
 * Get SP and PC values for idle tasks.
 */
static int
arm_get_frame(struct bt_info *bt, ulong *pcp, ulong *spp)
{
	const char *cpu_context;

	if (!bt->tc || !(tt->flags & THREAD_INFO))
		return FALSE;

	/*
	 * Update thread_info in tt.
	 */
	if (!fill_thread_info(bt->tc->thread_info))
		return FALSE;

	cpu_context = tt->thread_info + OFFSET(thread_info_cpu_context);

#define GET_REG(ptr, cp, off) ((*ptr) = (*((ulong *)((cp) + OFFSET(off)))))
	GET_REG(spp, cpu_context, cpu_context_save_sp);
	GET_REG(pcp, cpu_context, cpu_context_save_pc);

	/*
	 * Unwinding code needs FP (R7 for Thumb code) value also so we pass it
	 * with bt.
	 */
	if (*pcp & 1)
		GET_REG(&bt->frameptr, cpu_context, cpu_context_save_r7);
	else
		GET_REG(&bt->frameptr, cpu_context, cpu_context_save_fp);

	return TRUE;
}

/*
 * Get the starting point for the active cpu in a diskdump.
 */
static int
arm_get_dumpfile_stack_frame(struct bt_info *bt, ulong *nip, ulong *ksp)
{
	const struct machine_specific *ms = machdep->machspec;

	if (!ms->crash_task_regs ||
	    (!ms->crash_task_regs[bt->tc->processor].ARM_pc &&
	     !ms->crash_task_regs[bt->tc->processor].ARM_sp)) {
		bt->flags |= BT_REGS_NOT_FOUND;
		return FALSE;
	}

	/*
	 * We got registers for panic task from crash_notes. Just return them.
	 */
	*nip = ms->crash_task_regs[bt->tc->processor].ARM_pc;
	*ksp = ms->crash_task_regs[bt->tc->processor].ARM_sp;

	/*
	 * Also store pointer to all registers in case unwinding code needs
	 * to access LR.
	 */
	bt->machdep = &(ms->crash_task_regs[bt->tc->processor]);

	return TRUE;
}

/*
 * Get a stack frame combination of PC and SP from the most relevant spot.
 */
static void
arm_get_stack_frame(struct bt_info *bt, ulong *pcp, ulong *spp)
{
	ulong ip, sp;
	int ret;

	ip = sp = 0;
	bt->machdep = NULL;

	if (DUMPFILE() && is_task_active(bt->task))
		ret = arm_get_dumpfile_stack_frame(bt, &ip, &sp);
	else
		ret = arm_get_frame(bt, &ip, &sp);

	if (!ret)
		error(WARNING, "cannot determine starting stack frame for task %lx\n",
			bt->task);

	if (pcp)
		*pcp = ip;
	if (spp)
		*spp = sp;
}

/*
 * Prints out exception stack starting from start.
 */
void
arm_dump_exception_stack(ulong start, ulong end)
{
	struct arm_pt_regs regs;
	ulong flags;
	char buf[64];

	if (!readmem(start, KVADDR, &regs, sizeof(regs),
		     "exception regs", RETURN_ON_ERROR)) {
		error(WARNING, "failed to read exception registers\n");
		return;
	}

	fprintf(fp, "    pc : [<%08lx>]    lr : [<%08lx>]    psr: %08lx\n"
		"    sp : %08lx  ip : %08lx  fp : %08lx\n",
		regs.ARM_pc, regs.ARM_lr, regs.ARM_cpsr,
		regs.ARM_sp, regs.ARM_ip, regs.ARM_fp);
	fprintf(fp, "    r10: %08lx  r9 : %08lx  r8 : %08lx\n",
		regs.ARM_r10, regs.ARM_r9, regs.ARM_r8);
	fprintf(fp, "    r7 : %08lx  r6 : %08lx  r5 : %08lx  r4 : %08lx\n",
		regs.ARM_r7, regs.ARM_r6,
		regs.ARM_r5, regs.ARM_r4);
	fprintf(fp, "    r3 : %08lx  r2 : %08lx  r1 : %08lx  r0 : %08lx\n",
		regs.ARM_r3, regs.ARM_r2,
		regs.ARM_r1, regs.ARM_r0);

	flags = regs.ARM_cpsr;
	buf[0] = flags & PSR_N_BIT ? 'N' : 'n';
	buf[1] = flags & PSR_Z_BIT ? 'Z' : 'z';
	buf[2] = flags & PSR_C_BIT ? 'C' : 'c';
	buf[3] = flags & PSR_V_BIT ? 'V' : 'v';
	buf[4] = '\0';

	fprintf(fp, "    Flags: %s  IRQs o%s  FIQs o%s  Mode %s  ISA %s\n",
		buf, interrupts_enabled(&regs) ? "n" : "ff",
		fast_interrupts_enabled(&regs) ? "n" : "ff",
		processor_modes[processor_mode(&regs)],
		isa_modes[isa_mode(&regs)]);
}

static void
arm_display_full_frame(struct bt_info *bt, ulong sp)
{
	ulong words, addr;
	ulong *up;
	char buf[BUFSIZE];
	int i, u_idx;

	if (!INSTACK(sp, bt) || !INSTACK(bt->stkptr, bt))
		return;

	words = (sp - bt->stkptr) / sizeof(ulong);

	if (words == 0) {
		fprintf(fp, "    (no frame)\n");
		return;
	}

	addr = bt->stkptr;
	u_idx = (bt->stkptr - bt->stackbase) / sizeof(ulong);
	for (i = 0; i < words; i++, u_idx++) {
		if ((i % 4) == 0)
			fprintf(fp, "%s    %lx: ", i ? "\n" : "", addr);

		up = (ulong *)(&bt->stackbuf[u_idx * sizeof(ulong)]);
		fprintf(fp, "%s ", format_stack_entry(bt, buf, *up, 0));
		addr += sizeof(ulong);
	}
	fprintf(fp, "\n");
}

/*
 * Prints out a single stack frame. What is printed depends on flags passed in
 * with bt.
 *
 * What is expected when calling this function:
 *	bt->frameptr = current FP (or 0 if there is no such)
 *	bt->stkptr = current SP
 *	bt->instptr = current PC
 *
 *	from = LR
 *	sp = previous/saved SP
 */
void
arm_dump_backtrace_entry(struct bt_info *bt, int level, ulong from, ulong sp)
{
	struct load_module *lm;
	const char *name;
	int offset = 0;
	struct syment *symp;
	ulong symbol_offset;
	char *name_plus_offset;
	char buf[BUFSIZE];

	name = closest_symbol(bt->instptr);

	name_plus_offset = NULL;
	if (bt->flags & BT_SYMBOL_OFFSET) {
		symp = value_search(bt->instptr, &symbol_offset);

		if (symp && symbol_offset)
			name_plus_offset = 
				value_to_symstr(bt->instptr, buf, bt->radix);
	}

	if (module_symbol(bt->instptr, NULL, &lm, NULL, 0)) {
		fprintf(fp, "%s#%d [<%08lx>] (%s [%s]) from [<%08lx>]\n",
			level < 10 ? " " : "",
			level, bt->instptr, 
			name_plus_offset ? name_plus_offset : name,
			lm->mod_name, from);
	} else {
		fprintf(fp, "%s#%d [<%08lx>] (%s) from [<%08lx>]\n",
			level < 10 ? " " : "",
			level, bt->instptr, 
			name_plus_offset ? name_plus_offset : name, from);
	}

	if (bt->flags & BT_LINE_NUMBERS) {
		char buf[BUFSIZE];

		get_line_number(bt->instptr, buf, FALSE);
		if (strlen(buf))
			fprintf(fp, "    %s\n", buf);
	}

	if (arm_in_exception_text(bt->instptr)) {
		arm_dump_exception_stack(sp, sp + sizeof(struct arm_pt_regs));
	} else if (arm_in_ret_from_syscall(from, &offset)) {
		ulong nsp = sp + offset;

		arm_dump_exception_stack(nsp, nsp + sizeof(struct arm_pt_regs));
	}

	if (bt->flags & BT_FULL) {
		if (kt->flags & DWARF_UNWIND) {
			fprintf(fp, "    "
				"[PC: %08lx  LR: %08lx  SP: %08lx  SIZE: %ld]\n",
				bt->instptr, from, bt->stkptr, sp - bt->stkptr);
		} else {
			fprintf(fp, "    "
				"[PC: %08lx  LR: %08lx  SP: %08lx  FP: %08lx  "
				"SIZE: %ld]\n",
				bt->instptr, from, bt->stkptr, bt->frameptr,
				sp - bt->stkptr);
		}
		arm_display_full_frame(bt, sp);
	}
}

/*
 * Determine where vmalloc'd memory starts.
 */
static ulong
arm_vmalloc_start(void)
{
	machdep->machspec->vmalloc_start_addr = vt->high_memory;
	return vt->high_memory;
}

/*
 * Checks whether given task is valid task address.
 */
static int
arm_is_task_addr(ulong task)
{
	if (tt->flags & THREAD_INFO)
		return IS_KVADDR(task);

	return (IS_KVADDR(task) && ALIGNED_STACK_OFFSET(task) == 0);
}

/*
 * Filter dissassembly output if the output radix is not gdb's default 10
 */
static int
arm_dis_filter(ulong vaddr, char *inbuf, unsigned int output_radix)
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
 *  (on alpha -- not necessarily seen on arm) so this routine both fixes the
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
 * Look for likely exception frames in a stack.
 */
static int
arm_eframe_search(struct bt_info *bt)
{
	return (NOT_IMPLEMENTED());
}

/*
 * Get the relevant page directory pointer from a task structure.
 */
static ulong
arm_get_task_pgd(ulong task)
{
	return (NOT_IMPLEMENTED());
}

/*
 * Machine dependent command.
 */
static void
arm_cmd_mach(void)
{
	int c;

	while ((c = getopt(argcnt, args, "cm")) != -1) {
		switch (c) {
		case 'c':
		case 'm':
			fprintf(fp, "ARM: '-%c' option is not supported\n", c);
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	arm_display_machine_stats();
}

static void
arm_display_machine_stats(void)
{
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
	fprintf(fp, "          PAGE SIZE: %d\n", PAGESIZE());
	fprintf(fp, "KERNEL VIRTUAL BASE: %lx\n", machdep->kvbase);
	fprintf(fp, "KERNEL MODULES BASE: %lx\n", MODULES_VADDR);
	fprintf(fp, "KERNEL VMALLOC BASE: %lx\n", vt->vmalloc_start);
	fprintf(fp, "  KERNEL STACK SIZE: %ld\n", STACKSIZE());
}

static int
arm_get_smp_cpus(void)
{
	int cpus;
	
	if ((cpus = get_cpus_present()))
		return cpus;
	else
		return MAX(get_cpus_online(), get_highest_cpu_online()+1);
}

/*
 * Initialize ARM specific stuff.
 */
static void
arm_init_machspec(void)
{
	struct machine_specific *ms = machdep->machspec;
	ulong phys_base;

	if (symbol_exists("__exception_text_start") &&
	    symbol_exists("__exception_text_end")) {
		ms->exception_text_start = symbol_value("__exception_text_start");
		ms->exception_text_end = symbol_value("__exception_text_end");
	}

	if (symbol_exists("_stext") && symbol_exists("_etext")) {
		ms->kernel_text_start = symbol_value("_stext");
		ms->kernel_text_end = symbol_value("_etext");
	}

	if (CRASHDEBUG(1)) {
		fprintf(fp, "kernel text:    [%lx - %lx]\n",
			ms->kernel_text_start, ms->kernel_text_end);
		fprintf(fp, "exception text: [%lx - %lx]\n",
			ms->exception_text_start, ms->exception_text_end);
	}

	if (machdep->flags & PHYS_BASE) /* --machdep override */
		return;

	/*
	 * Next determine suitable value for phys_base. User can override this
	 * by passing valid '--machdep phys_base=<addr>' option.
	 */
	ms->phys_base = 0;

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

		phys_base = htol(buf, RETURN_ON_ERROR | QUIET, &errflag);
		if (errflag)
			return;

		ms->phys_base = phys_base;
	} else if (DISKDUMP_DUMPFILE() && diskdump_phys_base(&phys_base)) {
		ms->phys_base = phys_base;
	} else if (KDUMP_DUMPFILE() && arm_kdump_phys_base(&phys_base)) {
		ms->phys_base = phys_base;
	} else {
		error(WARNING,
			"phys_base cannot be determined from the dumpfile.\n"
			"Using default value of 0. If this is not correct,\n"
			"consider using '--machdep phys_base=<addr>'\n");
	}

	if (CRASHDEBUG(1))
		fprintf(fp, "using %lx as phys_base\n", ms->phys_base);
}

static const char *hook_files[] = {
	"arch/arm/kernel/entry-armv.S",
	"arch/arm/kernel/entry-common.S",
};

#define ENTRY_ARMV_S	((char **)&hook_files[0])
#define ENTRY_COMMON_S	((char **)&hook_files[1])

static struct line_number_hook arm_line_number_hooks[] = {
	{ "__dabt_svc", ENTRY_ARMV_S },
	{ "__irq_svc", ENTRY_ARMV_S },
	{ "__und_svc", ENTRY_ARMV_S },
	{ "__pabt_svc", ENTRY_ARMV_S },
	{ "__switch_to", ENTRY_ARMV_S },

	{ "ret_fast_syscall", ENTRY_COMMON_S },
	{ "ret_slow_syscall", ENTRY_COMMON_S },
	{ "ret_from_fork", ENTRY_COMMON_S },
	{ NULL, NULL },
};
#endif /* ARM */
