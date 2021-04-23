/* mips64.c - core analysis suite
 *
 * Copyright (C) 2021 Loongson Technology Co., Ltd.
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
#ifdef MIPS64

#include <elf.h>
#include "defs.h"

static void mips64_init_page_flags(void);
static int mips64_translate_pte(ulong pte, void *physaddr,
			ulonglong pte64);
static int mips64_pgd_vtop(ulong *pgd, ulong vaddr,
			physaddr_t *paddr, int verbose);
static int mips64_uvtop(struct task_context *tc, ulong vaddr,
			physaddr_t *paddr, int verbose);
static int mips64_kvtop(struct task_context *tc, ulong kvaddr,
			physaddr_t *paddr, int verbose);
static void mips64_cmd_mach(void);
static void mips64_display_machine_stats(void);
static void mips64_back_trace_cmd(struct bt_info *bt);
static void mips64_analyze_function(ulong start, ulong offset,
			struct mips64_unwind_frame *current,
			struct mips64_unwind_frame *previous);
static void mips64_dump_backtrace_entry(struct bt_info *bt,
			struct syment *sym, struct mips64_unwind_frame *current,
			struct mips64_unwind_frame *previous, int level);
static void mips64_dump_exception_stack(struct bt_info *bt, char *pt_regs);
static int mips64_is_exception_entry(struct syment *sym);
static void mips64_display_full_frame(struct bt_info *bt,
			struct mips64_unwind_frame *current,
			struct mips64_unwind_frame *previous);
static void mips64_stackframe_init(void);
static void mips64_get_stack_frame(struct bt_info *bt, ulong *pcp, ulong *spp);
static int mips64_get_dumpfile_stack_frame(struct bt_info *bt,
			ulong *nip, ulong *ksp);
static int mips64_get_frame(struct bt_info *bt, ulong *pcp, ulong *spp);
static int mips64_init_active_task_regs(void);
static int mips64_get_crash_notes(void);
static int mips64_get_elf_notes(void);

/*
 * 3 Levels paging       PAGE_SIZE=16KB
 *  PGD  |  PMD  |  PTE  |  OFFSET  |
 *  11   |  11   |  11   |    14    |
 */
/* From arch/mips/include/asm/pgtable{,-64}.h */
typedef struct { ulong pgd; } pgd_t;
typedef struct { ulong pmd; } pmd_t;
typedef struct { ulong pte; } pte_t;

#define PMD_ORDER	0
#define PTE_ORDER	0

#define PMD_SHIFT	(PAGESHIFT() + (PAGESHIFT() + PTE_ORDER - 3))
#define PMD_SIZE	(1UL << PMD_SHIFT)
#define PMD_MASK	(~(PMD_SIZE - 1))

#define PGDIR_SHIFT	(PMD_SHIFT + (PAGESHIFT() + PMD_ORDER - 3))
#define PGDIR_SIZE	(1UL << PGDIR_SHIFT)
#define PGDIR_MASK	(~(PGDIR_SIZE - 1))

#define PTRS_PER_PTE	(1UL << (PAGESHIFT() - 3))
#define PTRS_PER_PMD	PTRS_PER_PTE
#define PTRS_PER_PGD	PTRS_PER_PTE
#define USER_PTRS_PER_PGD	(0x80000000UL/PGDIR_SIZE)

#define pte_index(addr)	(((addr) >> PAGESHIFT()) & (PTRS_PER_PTE - 1))
#define pmd_index(addr)	(((addr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
#define pgd_index(addr)	(((addr) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))

#define MIPS64_CPU_RIXI	(1UL << 23)	/* CPU has TLB Read/eXec Inhibit */

/* From arch/mips/include/uapi/asm/reg.h */
#define MIPS64_EF_R0		0
#define MIPS64_EF_R29		29
#define MIPS64_EF_R31		31
#define MIPS64_EF_LO		32
#define MIPS64_EF_HI		33
#define MIPS64_EF_CP0_EPC	34
#define MIPS64_EF_CP0_BADVADDR	35
#define MIPS64_EF_CP0_STATUS	36
#define MIPS64_EF_CP0_CAUSE	37

static struct machine_specific mips64_machine_specific = { 0 };

/*
 * Holds registers during the crash.
 */
static struct mips64_register *panic_task_regs;

/*
 * 31                15 14    12 11 10  9  8  7  6  5  4  3  2  1  0
 * +-------------------+--------+--+--+--+--+--+--+--+--+--+--+--+--+
 * |       VPN         |    C   | D| V| G|RI|XI|SP|PN| H| M| A| W| P|
 * +-------------------+--------+--+--+--+--+--+--+--+--+--+--+--+--+
 */
static void
mips64_init_page_flags(void)
{
	ulong shift = 0;

	_PAGE_PRESENT = 1UL << shift++;
	_PAGE_WRITE = 1UL << shift++;
	_PAGE_ACCESSED = 1UL << shift++;
	_PAGE_MODIFIED = 1UL << shift++;
	_PAGE_HUGE = 1UL << shift++;
	_PAGE_PROTNONE = 1UL << shift++;

	if (THIS_KERNEL_VERSION >= LINUX(4,5,0))
		_PAGE_SPECIAL = 1UL << shift++;

	_PAGE_NO_EXEC = 1UL << shift++;
	_PAGE_NO_READ = _PAGE_READ = 1UL << shift++;
	_PAGE_GLOBAL = 1UL << shift++;
	_PAGE_VALID = 1UL << shift++;
	_PAGE_DIRTY = 1UL << shift++;

	_PFN_SHIFT =  PAGESHIFT() - 12 + shift + 3;
}

/*
 * Translate a PTE, returning TRUE if the page is present.
 * If a physaddr pointer is passed in, don't print anything.
 */
static int
mips64_translate_pte(ulong pte, void *physaddr, ulonglong pte64)
{
	char ptebuf[BUFSIZE];
	char physbuf[BUFSIZE];
	char buf[BUFSIZE];
	int page_present;
	int len1, len2, others;
	ulong paddr;

	paddr = PTOB(pte >> _PFN_SHIFT);
	page_present = !!(pte & _PAGE_PRESENT);

	if (physaddr) {
		*(ulong *)physaddr = paddr;
		return page_present;
	}

	sprintf(ptebuf, "%lx", pte);
	len1 = MAX(strlen(ptebuf), strlen("PTE"));
	fprintf(fp, "%s  ", mkstring(buf, len1, CENTER | LJUST, "PTE"));

	if (!page_present)
		return page_present;

	sprintf(physbuf, "%lx", paddr);
	len2 = MAX(strlen(physbuf), strlen("PHYSICAL"));
	fprintf(fp, "%s  ", mkstring(buf, len2, CENTER | LJUST, "PHYSICAL"));

	fprintf(fp, "FLAGS\n");
	fprintf(fp, "%s  %s  ",
		mkstring(ptebuf, len1, CENTER | RJUST, NULL),
		mkstring(physbuf, len2, CENTER | RJUST, NULL));

	fprintf(fp, "(");
	others = 0;

#define CHECK_PAGE_FLAG(flag)				\
	if ((_PAGE_##flag) && (pte & _PAGE_##flag))	\
		fprintf(fp, "%s" #flag, others++ ? "|" : "")

	if (pte) {
		CHECK_PAGE_FLAG(PRESENT);
		CHECK_PAGE_FLAG(WRITE);
		CHECK_PAGE_FLAG(ACCESSED);
		CHECK_PAGE_FLAG(MODIFIED);
		CHECK_PAGE_FLAG(HUGE);
		CHECK_PAGE_FLAG(PROTNONE);
		CHECK_PAGE_FLAG(SPECIAL);
		CHECK_PAGE_FLAG(NO_EXEC);
		CHECK_PAGE_FLAG(NO_READ);
		CHECK_PAGE_FLAG(READ);
		CHECK_PAGE_FLAG(GLOBAL);
		CHECK_PAGE_FLAG(VALID);
		CHECK_PAGE_FLAG(DIRTY);
	} else {
		fprintf(fp, "no mapping");
	}

	fprintf(fp, ")\n");

	return page_present;
}

/*
 * Virtual to physical memory translation. This function will be called
 * by both mips64_kvtop and mips64_uvtop.
 */
static int
mips64_pgd_vtop(ulong *pgd, ulong vaddr, physaddr_t *paddr, int verbose)
{
	ulong *pgd_ptr, pgd_val;
	ulong *pmd_ptr, pmd_val;
	ulong *pte_ptr, pte_val;

	if (verbose) {
		const char *segment;

		if (vaddr < 0x4000000000000000lu)
			segment = "xuseg";
		else if (vaddr < 0x8000000000000000lu)
			segment = "xsseg";
		else if (vaddr < 0xc000000000000000lu)
			segment = "xkphys";
		else if (vaddr < 0xffffffff80000000lu)
			segment = "xkseg";
		else if (vaddr < 0xffffffffa0000000lu)
			segment = "kseg0";
		else if (vaddr < 0xffffffffc0000000lu)
			segment = "kseg1";
		else if (vaddr < 0xffffffffe0000000lu)
			segment = "sseg";
		else
			segment = "kseg3";

		fprintf(fp, "SEGMENT: %s\n", segment);
	}

	if (IS_CKPHYS(vaddr) || IS_XKPHYS(vaddr)) {
		*paddr = VTOP(vaddr);
		return TRUE;
	}

	if (verbose)
		fprintf(fp, "PAGE DIRECTORY: %016lx\n", (ulong)pgd);

	pgd_ptr = pgd + pgd_index(vaddr);
	FILL_PGD(PAGEBASE(pgd), KVADDR, PAGESIZE());
	pgd_val = ULONG(machdep->pgd + PAGEOFFSET(pgd_ptr));
	if (verbose)
		fprintf(fp, "  PGD: %16lx => %16lx\n", (ulong)pgd_ptr, pgd_val);
	if (!pgd_val)
		goto no_page;

	pmd_ptr = (ulong *)(VTOP(pgd_val) + sizeof(pmd_t) * pmd_index(vaddr));
	FILL_PMD(PAGEBASE(pmd_ptr), PHYSADDR, PAGESIZE());
	pmd_val = ULONG(machdep->pmd + PAGEOFFSET(pmd_ptr));
	if (verbose)
		fprintf(fp, "  PMD: %016lx => %016lx\n", (ulong)pmd_ptr, pmd_val);
	if (!pmd_val)
		goto no_page;

	pte_ptr = (ulong *)(VTOP(pmd_val) + sizeof(pte_t) * pte_index(vaddr));
	FILL_PTBL(PAGEBASE(pte_ptr), PHYSADDR, PAGESIZE());
	pte_val = ULONG(machdep->ptbl + PAGEOFFSET(pte_ptr));
	if (verbose)
		fprintf(fp, "  PTE: %016lx => %016lx\n", (ulong)pte_ptr, pte_val);
	if (!pte_val)
		goto no_page;

	if (!(pte_val & _PAGE_PRESENT)) {
		if (verbose) {
			fprintf(fp, "\n");
			mips64_translate_pte((ulong)pte_val, 0, pte_val);
		}
		return FALSE;
	}

	*paddr = PTOB(pte_val >> _PFN_SHIFT) + PAGEOFFSET(vaddr);

	if (verbose) {
		fprintf(fp, " PAGE: %016lx\n\n", PAGEBASE(*paddr));
		mips64_translate_pte(pte_val, 0, 0);
	}

	return TRUE;
no_page:
	fprintf(fp, "invalid\n");
	return FALSE;
}

/* Translates a user virtual address to its physical address. cmd_vtop() sets
 * the verbose flag so that the pte translation gets displayed; all other
 * callers quietly accept the translation.
 */
static int
mips64_uvtop(struct task_context *tc, ulong vaddr, physaddr_t *paddr, int verbose)
{
	ulong mm, active_mm;
	ulong *pgd;

	if (!tc)
		error(FATAL, "current context invalid\n");

	*paddr = 0;

	if (is_kernel_thread(tc->task) && IS_KVADDR(vaddr)) {
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
		if ((mm = task_mm(tc->task, TRUE)))
			pgd = ULONG_PTR(tt->mm_struct + OFFSET(mm_struct_pgd));
		else
			readmem(tc->mm_struct + OFFSET(mm_struct_pgd),
			KVADDR, &pgd, sizeof(long), "mm_struct pgd",
			FAULT_ON_ERROR);
	}

	return mips64_pgd_vtop(pgd, vaddr, paddr, verbose);;
}

/* Translates a user virtual address to its physical address. cmd_vtop() sets
 * the verbose flag so that the pte translation gets displayed; all other
 * callers quietly accept the translation.
 */
static int
mips64_kvtop(struct task_context *tc, ulong kvaddr, physaddr_t *paddr, int verbose)
{
	if (!IS_KVADDR(kvaddr))
		return FALSE;

	if (!verbose) {
		if (IS_CKPHYS(kvaddr) || IS_XKPHYS(kvaddr)) {
			*paddr = VTOP(kvaddr);
			return TRUE;
		}
	}

	return mips64_pgd_vtop((ulong *)vt->kernel_pgd[0], kvaddr, paddr,
			     verbose);
}

/*
 * Machine dependent command.
 */
static void
mips64_cmd_mach(void)
{
	int c;

	while ((c = getopt(argcnt, args, "cmo")) != EOF) {
		switch (c) {
		case 'c':
		case 'm':
		case 'o':
			option_not_supported(c);
			break;
		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	mips64_display_machine_stats();
}

/*
 * "mach" command output.
 */
static void
mips64_display_machine_stats(void)
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
	fprintf(fp, "  KERNEL STACK SIZE: %ld\n", STACKSIZE());

}

/*
 * Unroll a kernel stack.
 */
static void
mips64_back_trace_cmd(struct bt_info *bt)
{
	struct mips64_unwind_frame current, previous;
	struct mips64_register *regs;
	struct mips64_pt_regs_main *mains;
	struct mips64_pt_regs_cp0 *cp0;
	char pt_regs[SIZE(pt_regs)];
	int level = 0;
	int invalid_ok = 1;

	if (bt->flags & BT_REGS_NOT_FOUND)
		return;

	previous.sp = previous.pc = previous.ra = 0;

	current.pc = bt->instptr;
	current.sp = bt->stkptr;
	current.ra = 0;

	if (!INSTACK(current.sp, bt))
		return;

	if (bt->machdep) {
		regs = bt->machdep;
		previous.pc = current.ra = regs->regs[MIPS64_EF_R31];
	}

	while (current.sp <= bt->stacktop - 32 - SIZE(pt_regs)) {
		struct syment *symbol = NULL;
		ulong offset;

		if (CRASHDEBUG(8))
			fprintf(fp, "level %d pc %#lx ra %#lx sp %lx\n",
				level, current.pc, current.ra, current.sp);

		if (!IS_KVADDR(current.pc) && !invalid_ok)
			return;

		symbol = value_search(current.pc, &offset);
		if (!symbol && !invalid_ok) {
			error(FATAL, "PC is unknown symbol (%lx)", current.pc);
			return;
		}
		invalid_ok = 0;

		/*
		 * If we get an address which points to the start of a
		 * function, then it could one of the following:
		 *
		 *  - we are dealing with a noreturn function.  The last call
		 *    from a noreturn function has an ra which points to the
		 *    start of the function after it.  This is common in the
		 *    oops callchain because of die() which is annotated as
		 *    noreturn.
		 *
		 *  - we have taken an exception at the start of this function.
		 *    In this case we already have the RA in current.ra.
		 *
		 *  - we are in one of these routines which appear with zero
		 *    offset in manually-constructed stack frames:
		 *
		 *    * ret_from_exception
		 *    * ret_from_irq
		 *    * ret_from_fork
		 *    * ret_from_kernel_thread
		 */
		if (symbol && !STRNEQ(symbol->name, "ret_from") && !offset &&
			!current.ra && current.sp < bt->stacktop - 32 - SIZE(pt_regs)) {
			if (CRASHDEBUG(8))
				fprintf(fp, "zero offset at %s, try previous symbol\n",
					symbol->name);

			symbol = value_search(current.pc - 4, &offset);
			if (!symbol) {
				error(FATAL, "PC is unknown symbol (%lx)", current.pc);
				return;
			}
		}

		if (symbol && mips64_is_exception_entry(symbol)) {

			mains = (struct mips64_pt_regs_main *) \
			       (pt_regs + OFFSET(pt_regs_regs));
			cp0 = (struct mips64_pt_regs_cp0 *) \
			      (pt_regs + OFFSET(pt_regs_cp0_badvaddr));

			GET_STACK_DATA(current.sp, pt_regs, sizeof(pt_regs));

			previous.ra = mains->regs[31];
			previous.sp = mains->regs[29];
			current.ra = cp0->cp0_epc;

			if (CRASHDEBUG(8))
				fprintf(fp, "exception pc %#lx ra %#lx sp %lx\n",
					previous.pc, previous.ra, previous.sp);

			/* The PC causing the exception may have been invalid */
			invalid_ok = 1;
		} else if (symbol) {
			mips64_analyze_function(symbol->value, offset, &current, &previous);
		} else {
			/*
			 * The current PC is invalid. Assume that the code
			 * jumped through a invalid pointer and that the SP has
			 * not been adjusted.
			 */
			previous.sp = current.sp;
		}

		mips64_dump_backtrace_entry(bt, symbol, &current, &previous, level++);

		current.pc = current.ra;
		current.sp = previous.sp;
		current.ra = previous.ra;

		if (CRASHDEBUG(8))
			fprintf(fp, "next %d pc %#lx ra %#lx sp %lx\n",
				level, current.pc, current.ra, current.sp);

		previous.sp = previous.pc = previous.ra = 0;
	}
}

static void
mips64_analyze_function(ulong start, ulong offset,
		      struct mips64_unwind_frame *current,
		      struct mips64_unwind_frame *previous)
{
	ulong i, reg;
	ulong rapos = 0;
	ulong spadjust = 0;
	uint32_t *funcbuf, *ip;

	if (CRASHDEBUG(8))
		fprintf(fp, "%s: start %#lx offset %#lx\n",
			__func__, start, offset);

	if (!offset) {
		previous->sp = current->sp;
		return;
	}

	ip = funcbuf = (uint32_t *)GETBUF(offset);
	if (!readmem(start, KVADDR, funcbuf, offset,
		     "mips64_analyze_function", RETURN_ON_ERROR)) {
		FREEBUF(funcbuf);
		error(WARNING, "Cannot read function at %16lx\n", start);
		return;
	}

	for (i = 0; i < offset; i += 4) {
		ulong insn = *ip & 0xffffffff;
		ulong high = (insn >> 16) & 0xffff;
		ulong low = insn & 0xffff;

		if (CRASHDEBUG(8))
			fprintf(fp, "insn @ %#lx = %#lx\n", start + i, insn);

		if (high == 0x27bd || high == 0x67bd) { /* ADDIU/DADDIU sp, sp, imm */
			if (!(low & 0x8000))
				break;

			spadjust += 0x10000 - low;
			if (CRASHDEBUG(8))
				fprintf(fp, "spadjust = %lu\n", spadjust);
		} else if (high == 0xafbf) { /* SW RA, imm(SP) */
			rapos = current->sp + low;
			if (CRASHDEBUG(8))
				fprintf(fp, "rapos %lx\n", rapos);
			break;
		} else if (high == 0xffbf) { /* SD RA, imm(SP) */
			rapos = current->sp + low;
			if (CRASHDEBUG(8))
				fprintf(fp, "rapos %lx\n", rapos);
			break;
		} else if ((insn & 0xffe08020) == 0xeba00020) { /* GSSQ reg, reg, offset(SP) */
			reg = (insn >> 16) & 0x1f;
			if (reg == 31) {
				low = ((((insn >> 6) & 0x1ff) ^ 0x100) - 0x100) << 4;
				rapos = current->sp + low;
				if (CRASHDEBUG(8))
					fprintf(fp, "rapos %lx\n", rapos);
				break;
			}
			reg = insn & 0x1f;
			if (reg == 31) {
				low = (((((insn >> 6) & 0x1ff) ^ 0x100) - 0x100) << 4) + 8;
				rapos = current->sp + low;
				if (CRASHDEBUG(8))
					fprintf(fp, "rapos %lx\n", rapos);
				break;
			}
		}

		ip++;
	}

	FREEBUF(funcbuf);

	previous->sp = current->sp + spadjust;

	if (rapos && !readmem(rapos, KVADDR, &current->ra,
			      sizeof(current->ra), "RA from stack",
			      RETURN_ON_ERROR)) {
		error(FATAL, "Cannot read RA from stack %lx", rapos);
		return;
	}
}

static void
mips64_dump_backtrace_entry(struct bt_info *bt, struct syment *sym,
			struct mips64_unwind_frame *current,
			struct mips64_unwind_frame *previous, int level)
{
	const char *name = sym ? sym->name : "(invalid)";
	struct load_module *lm;
	char *name_plus_offset = NULL;
	struct syment *symp;
	ulong symbol_offset;
	char buf[BUFSIZE];
	char pt_regs[SIZE(pt_regs)];

	if (bt->flags & BT_SYMBOL_OFFSET) {
		symp = value_search(current->pc, &symbol_offset);

		if (symp && symbol_offset)
			name_plus_offset =
				value_to_symstr(current->pc, buf, bt->radix);
	}

	fprintf(fp, "%s#%d [%016lx] %s at %016lx", level < 10 ? " " : "", level,
		current->sp, name_plus_offset ? name_plus_offset : name,
		current->pc);

	if (module_symbol(current->pc, NULL, &lm, NULL, 0))
		fprintf(fp, " [%s]", lm->mod_name);

	fprintf(fp, "\n");

	/*
	 * 'bt -l', get a line number associated with a current pc address.
	 */
	if (bt->flags & BT_LINE_NUMBERS) {
		get_line_number(current->pc, buf, FALSE);
		if (strlen(buf))
			fprintf(fp, "    %s\n", buf);
	}

	if (sym && mips64_is_exception_entry(sym)) {
		GET_STACK_DATA(current->sp, &pt_regs, SIZE(pt_regs));
		mips64_dump_exception_stack(bt, pt_regs);
	}

	/* bt -f */
	if (bt->flags & BT_FULL) {
		fprintf(fp, "    "
			"[PC: %016lx RA: %016lx SP: %016lx SIZE: %ld]\n",
			current->pc, current->ra, current->sp,
			previous->sp - current->sp);
		mips64_display_full_frame(bt, current, previous);
	}
}

static void
mips64_dump_exception_stack(struct bt_info *bt, char *pt_regs)
{
	struct mips64_pt_regs_main *mains;
	struct mips64_pt_regs_cp0 *cp0;
	int i;
	char buf[BUFSIZE];

	mains = (struct mips64_pt_regs_main *) (pt_regs + OFFSET(pt_regs_regs));
	cp0 = (struct mips64_pt_regs_cp0 *) \
		(pt_regs + OFFSET(pt_regs_cp0_badvaddr));

	for (i = 0; i < 32; i += 4) {
		fprintf(fp, "    $%2d   : %016lx %016lx %016lx %016lx\n",
			i, mains->regs[i], mains->regs[i+1],
			mains->regs[i+2], mains->regs[i+3]);
	}
	fprintf(fp, "    Hi    : %016lx\n", mains->hi);
	fprintf(fp, "    Lo    : %016lx\n", mains->lo);

	value_to_symstr(cp0->cp0_epc, buf, 16);
	fprintf(fp, "    epc   : %016lx %s\n", cp0->cp0_epc, buf);

	value_to_symstr(mains->regs[31], buf, 16);
	fprintf(fp, "    ra    : %016lx %s\n", mains->regs[31], buf);

	fprintf(fp, "    Status: %016lx\n", mains->cp0_status);
	fprintf(fp, "    Cause : %016lx\n", cp0->cp0_cause);
	fprintf(fp, "    BadVA : %016lx\n", cp0->cp0_badvaddr);
}

static int
mips64_is_exception_entry(struct syment *sym)
{
	return STREQ(sym->name, "ret_from_exception") ||
		STREQ(sym->name, "ret_from_irq") ||
		STREQ(sym->name, "work_resched") ||
		STREQ(sym->name, "handle_sys") ||
		STREQ(sym->name, "handle_sysn32") ||
		STREQ(sym->name, "handle_sys64");
}

/*
 * 'bt -f' commend output
 * Display all stack data contained in a frame
 */
static void
mips64_display_full_frame(struct bt_info *bt, struct mips64_unwind_frame *current,
			  struct mips64_unwind_frame *previous)
{
	int i, u_idx;
	ulong *up;
	ulong words, addr;
	char buf[BUFSIZE];

	if (previous->sp < current->sp)
		return;

	if (!(INSTACK(previous->sp, bt) && INSTACK(current->sp, bt)))
		return;

	words = (previous->sp - current->sp) / sizeof(ulong) + 1;
	addr = current->sp;
	u_idx = (current->sp - bt->stackbase) / sizeof(ulong);

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
mips64_stackframe_init(void)
{
	long task_struct_thread = MEMBER_OFFSET("task_struct", "thread");
	long thread_reg29 = MEMBER_OFFSET("thread_struct", "reg29");
	long thread_reg31 = MEMBER_OFFSET("thread_struct", "reg31");

	if ((task_struct_thread == INVALID_OFFSET) ||
	    (thread_reg29 == INVALID_OFFSET) ||
	    (thread_reg31 == INVALID_OFFSET)) {
		error(FATAL,
		      "cannot determine thread_struct offsets\n");
		return;
	}

	ASSIGN_OFFSET(task_struct_thread_reg29) =
		task_struct_thread + thread_reg29;
	ASSIGN_OFFSET(task_struct_thread_reg31) =
		task_struct_thread + thread_reg31;

	STRUCT_SIZE_INIT(pt_regs, "pt_regs");
	MEMBER_OFFSET_INIT(pt_regs_regs, "pt_regs", "regs");
	MEMBER_OFFSET_INIT(pt_regs_cp0_badvaddr, "pt_regs", "cp0_badvaddr");
}

/*
 * Get a stack frame combination of pc and ra from the most relevant spot.
 */
static void
mips64_get_stack_frame(struct bt_info *bt, ulong *pcp, ulong *spp)
{
	ulong ksp, nip;
	int ret = 0;

	nip = ksp = 0;
	bt->machdep = NULL;

	if (DUMPFILE() && is_task_active(bt->task))
		ret = mips64_get_dumpfile_stack_frame(bt, &nip, &ksp);
	else
		ret = mips64_get_frame(bt, &nip, &ksp);

	if (!ret)
		error(WARNING, "cannot determine starting stack frame for task %lx\n",
			bt->task);

	if (pcp)
		*pcp = nip;
	if (spp)
		*spp = ksp;
}

/*
 * Get the starting point for the active cpu in a diskdump.
 */
static int
mips64_get_dumpfile_stack_frame(struct bt_info *bt, ulong *nip, ulong *ksp)
{
	const struct machine_specific *ms = machdep->machspec;
	struct mips64_register *regs;
	ulong epc, r29;

	if (!ms->crash_task_regs) {
		bt->flags |= BT_REGS_NOT_FOUND;
		return FALSE;
	}

	/*
	 * We got registers for panic task from crash_notes. Just return them.
	 */
	regs = &ms->crash_task_regs[bt->tc->processor];
	epc = regs->regs[MIPS64_EF_CP0_EPC];
	r29 = regs->regs[MIPS64_EF_R29];

	if (!epc && !r29) {
		bt->flags |= BT_REGS_NOT_FOUND;
		return FALSE;
	}

	if (nip)
		*nip = epc;
	if (ksp)
		*ksp = r29;

	bt->machdep = regs;

	return TRUE;
}

/*
 * Do the work for mips64_get_stack_frame() for non-active tasks.
 * Get SP and PC values for idle tasks.
 */
static int
mips64_get_frame(struct bt_info *bt, ulong *pcp, ulong *spp)
{
	if (!bt->tc || !(tt->flags & THREAD_INFO))
		return FALSE;

	if (!readmem(bt->task + OFFSET(task_struct_thread_reg31),
		     KVADDR, pcp, sizeof(*pcp),
		     "thread_struct.regs31",
		     RETURN_ON_ERROR)) {
		return FALSE;
	}

	if (!readmem(bt->task + OFFSET(task_struct_thread_reg29),
		     KVADDR, spp, sizeof(*spp),
		     "thread_struct.regs29",
		     RETURN_ON_ERROR)) {
		return FALSE;
	}

	return TRUE;
}

static int
mips64_init_active_task_regs(void)
{
	int retval;

	retval = mips64_get_crash_notes();
	if (retval == TRUE)
		return retval;

	return mips64_get_elf_notes();
}

/*
 * Retrieve task registers for the time of the crash.
 */
static int
mips64_get_crash_notes(void)
{
	struct machine_specific *ms = machdep->machspec;
	ulong crash_notes;
	Elf64_Nhdr *note;
	ulong offset;
	char *buf, *p;
	ulong *notes_ptrs;
	ulong i;

	/*
	 * crash_notes contains per cpu memory for storing cpu states
	 * in case of system crash.
	 */
	if (!symbol_exists("crash_notes"))
		return FALSE;

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
		return FALSE;
	}

	if (symbol_exists("__per_cpu_offset")) {

		/*
		 * Add __per_cpu_offset for each cpu to form the pointer to the notes
		 */
		for (i = 0; i < kt->cpus; i++)
			notes_ptrs[i] = notes_ptrs[kt->cpus-1] + kt->__per_cpu_offset[i];
	}

	buf = GETBUF(SIZE(note_buf));

	if (!(panic_task_regs = calloc((size_t)kt->cpus, sizeof(*panic_task_regs))))
		error(FATAL, "cannot calloc panic_task_regs space\n");

	for (i = 0; i < kt->cpus; i++) {

		if (!readmem(notes_ptrs[i], KVADDR, buf, SIZE(note_buf), "note_buf_t",
			     RETURN_ON_ERROR)) {
			error(WARNING,
				"cannot find NT_PRSTATUS note for cpu: %d\n", i);
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

		/*
		 * Check the sanity of NT_PRSTATUS note only for each online cpu.
		 */
		if (note->n_type != NT_PRSTATUS) {
			error(WARNING, "invalid NT_PRSTATUS note (n_type != NT_PRSTATUS)\n");
			goto fail;
		}
		if (!STRNEQ(p, "CORE")) {
			error(WARNING, "invalid NT_PRSTATUS note (name != \"CORE\"\n");
			goto fail;
		}

		/*
		 * Find correct location of note data. This contains elf_prstatus
		 * structure which has registers etc. for the crashed task.
		 */
		offset = sizeof(Elf64_Nhdr);
		offset = roundup(offset + note->n_namesz, 4);
		p = buf + offset; /* start of elf_prstatus */

		BCOPY(p + OFFSET(elf_prstatus_pr_reg), &panic_task_regs[i],
		      sizeof(panic_task_regs[i]));
	}

	/*
	 * And finally we have the registers for the crashed task. This is
	 * used later on when dumping backtrace.
	 */
	ms->crash_task_regs = panic_task_regs;

	FREEBUF(buf);
	FREEBUF(notes_ptrs);
	return TRUE;

fail:
	FREEBUF(buf);
	FREEBUF(notes_ptrs);
	free(panic_task_regs);
	return FALSE;
}

static int
mips64_get_elf_notes(void)
{
	struct machine_specific *ms = machdep->machspec;
	int i;

	if (!DISKDUMP_DUMPFILE() && !KDUMP_DUMPFILE())
		return FALSE;

	panic_task_regs = calloc(kt->cpus, sizeof(*panic_task_regs));
	if (!panic_task_regs)
		error(FATAL, "cannot calloc panic_task_regs space\n");

	for (i = 0; i < kt->cpus; i++) {
		Elf64_Nhdr *note = NULL;
		size_t len;

		if (DISKDUMP_DUMPFILE())
			note = diskdump_get_prstatus_percpu(i);
		else if (KDUMP_DUMPFILE())
			note = netdump_get_prstatus_percpu(i);

		if (!note) {
			error(WARNING,
			      "cannot find NT_PRSTATUS note for cpu: %d\n", i);
			continue;
		}

		len = sizeof(Elf64_Nhdr);
		len = roundup(len + note->n_namesz, 4);

		BCOPY((char *)note + len + OFFSET(elf_prstatus_pr_reg),
		      &panic_task_regs[i], sizeof(panic_task_regs[i]));
	}

	ms->crash_task_regs = panic_task_regs;

	return TRUE;
}

/*
 * Accept or reject a symbol from the kernel namelist.
 */
static int
mips64_verify_symbol(const char *name, ulong value, char type)
{
	if (CRASHDEBUG(8) && name && strlen(name))
		fprintf(fp, "%08lx %s\n", value, name);

	if (STREQ(name, "_text") || STREQ(name, "_stext"))
		machdep->flags |= KSYMS_START;

	return (name && strlen(name) && (machdep->flags & KSYMS_START) &&
		!STRNEQ(name, "__func__.") && !STRNEQ(name, "__crc_"));
}

/*
 * Override smp_num_cpus if possible and necessary.
 */
static int
mips64_get_smp_cpus(void)
{
	return (get_cpus_online() > 0) ? get_cpus_online() : kt->cpus;
}

static ulong
mips64_get_page_size(void)
{
	return memory_page_size();
}

/*
 * Determine where vmalloc'd memory starts.
 */
static ulong
mips64_vmalloc_start(void)
{
	return first_vmalloc_address();
}

/*
 * Calculate and return the speed of the processor.
 */
static ulong
mips64_processor_speed(void)
{
	unsigned long cpu_hz1 = 0, cpu_hz2 = 0;

	if (machdep->mhz)
		return (machdep->mhz);

	if (symbol_exists("mips_cpu_frequency")) {
		get_symbol_data("mips_cpu_frequency", sizeof(int), &cpu_hz1);
		if (cpu_hz1)
			return(machdep->mhz = cpu_hz1/1000000);
	}

	if (symbol_exists("cpu_clock_freq")) {
		get_symbol_data("cpu_clock_freq", sizeof(int), &cpu_hz2);
		if (cpu_hz2)
			return(machdep->mhz = cpu_hz2/1000000);
	}

	return 0;
}

/*
 * Checks whether given task is valid task address.
 */
static int
mips64_is_task_addr(ulong task)
{
	if (tt->flags & THREAD_INFO)
		return IS_KVADDR(task);

	return (IS_KVADDR(task) && ALIGNED_STACK_OFFSET(task) == 0);
}

/*
 * "help -m/M" command output
 */
void
mips64_dump_machdep_table(ulong arg)
{
	int others = 0;

	fprintf(fp, "              flags: %lx (", machdep->flags);
	if (machdep->flags & KSYMS_START)
		fprintf(fp, "%sKSYMS_START", others++ ? "|" : "");
	fprintf(fp, ")\n");

	fprintf(fp, "             kvbase: %lx\n", machdep->kvbase);
	fprintf(fp, "  identity_map_base: %lx\n", machdep->identity_map_base);
	fprintf(fp, "           pagesize: %d\n", machdep->pagesize);
	fprintf(fp, "          pageshift: %d\n", machdep->pageshift);
	fprintf(fp, "           pagemask: %llx\n", machdep->pagemask);
	fprintf(fp, "         pageoffset: %lx\n", machdep->pageoffset);
	fprintf(fp, "        pgdir_shift: %d\n", PGDIR_SHIFT);
	fprintf(fp, "       ptrs_per_pgd: %lu\n", PTRS_PER_PGD);
	fprintf(fp, "       ptrs_per_pte: %ld\n", PTRS_PER_PTE);
	fprintf(fp, "          stacksize: %ld\n", machdep->stacksize);
	fprintf(fp, "                 hz: %d\n", machdep->hz);
	fprintf(fp, "            memsize: %ld (0x%lx)\n",
		machdep->memsize, machdep->memsize);
	fprintf(fp, "               bits: %d\n", machdep->bits);
	fprintf(fp, "         back_trace: mips64_back_trace_cmd()\n");
	fprintf(fp, "    processor_speed: mips64_processor_speed()\n");
	fprintf(fp, "              uvtop: mips64_uvtop()\n");
	fprintf(fp, "              kvtop: mips64_kvtop()\n");
	fprintf(fp, "    get_stack_frame: mips64_get_stack_frame()\n");
	fprintf(fp, "      get_stackbase: generic_get_stackbase()\n");
	fprintf(fp, "       get_stacktop: generic_get_stacktop()\n");
	fprintf(fp, "      translate_pte: mips64_translate_pte()\n");
	fprintf(fp, "        memory_size: generic_memory_size()\n");
	fprintf(fp, "      vmalloc_start: mips64_vmalloc_start()\n");
	fprintf(fp, "       is_task_addr: mips64_is_task_addr()\n");
	fprintf(fp, "      verify_symbol: mips64_verify_symbol()\n");
	fprintf(fp, "         dis_filter: generic_dis_filter()\n");
	fprintf(fp, "           dump_irq: generic_dump_irq()\n");
	fprintf(fp, "    show_interrupts: generic_show_interrupts()\n");
	fprintf(fp, "   get_irq_affinity: generic_get_irq_affinity()\n");
	fprintf(fp, "           cmd_mach: mips64_cmd_mach()\n");
	fprintf(fp, "       get_smp_cpus: mips64_get_smp_cpus()\n");
	fprintf(fp, "          is_kvaddr: generic_is_kvaddr()\n");
	fprintf(fp, "          is_uvaddr: generic_is_uvaddr()\n");
	fprintf(fp, "       verify_paddr: generic_verify_paddr()\n");
	fprintf(fp, "    init_kernel_pgd: NULL\n");
	fprintf(fp, "    value_to_symbol: generic_machdep_value_to_symbol()\n");
	fprintf(fp, "  line_number_hooks: NULL\n");
	fprintf(fp, "      last_pgd_read: %lx\n", machdep->last_pgd_read);
	fprintf(fp, "      last_pmd_read: %lx\n", machdep->last_pmd_read);
	fprintf(fp, "     last_ptbl_read: %lx\n", machdep->last_ptbl_read);
	fprintf(fp, "                pgd: %lx\n", (ulong)machdep->pgd);
	fprintf(fp, "                pmd: %lx\n", (ulong)machdep->pmd);
	fprintf(fp, "               ptbl: %lx\n", (ulong)machdep->ptbl);
	fprintf(fp, "  section_size_bits: %ld\n", machdep->section_size_bits);
	fprintf(fp, "   max_physmem_bits: %ld\n", machdep->max_physmem_bits);
	fprintf(fp, "  sections_per_root: %ld\n", machdep->sections_per_root);
	fprintf(fp, "           machspec: %lx\n", (ulong)machdep->machspec);
}

static void
pt_level_alloc(char **lvl, char *name)
{
	size_t sz = PAGESIZE();
	void *pointer = malloc(sz);

	if (!pointer)
	        error(FATAL, name);
	*lvl = pointer;
}

/*
 * Do all necessary machine-specific setup here. This is called several
 * times during initialization.
 */
void
mips64_init(int when)
{
	switch (when) {
	case SETUP_ENV:
		machdep->process_elf_notes = process_elf64_notes;
		break;

	case PRE_SYMTAB:
		machdep->verify_symbol = mips64_verify_symbol;
		machdep->machspec = &mips64_machine_specific;
		if (pc->flags & KERNEL_DEBUG_QUERY)
			return;
		machdep->last_pgd_read = 0;
		machdep->last_pmd_read = 0;
		machdep->last_ptbl_read = 0;
		machdep->verify_paddr = generic_verify_paddr;
		machdep->ptrs_per_pgd = PTRS_PER_PGD;
		break;

	case PRE_GDB:
		machdep->pagesize = mips64_get_page_size();
		machdep->pageshift = ffs(machdep->pagesize) - 1;
		machdep->pageoffset = machdep->pagesize - 1;
		machdep->pagemask = ~((ulonglong)machdep->pageoffset);
		if (machdep->pagesize >= 16384)
			machdep->stacksize = machdep->pagesize;
		else
			machdep->stacksize = machdep->pagesize * 2;

		pt_level_alloc(&machdep->pgd, "cannot malloc pgd space.");
		pt_level_alloc(&machdep->pmd, "cannot malloc pmd space.");
		pt_level_alloc(&machdep->ptbl, "cannot malloc ptbl space.");
		machdep->kvbase = 0x8000000000000000lu;
		machdep->identity_map_base = machdep->kvbase;
		machdep->is_kvaddr = generic_is_kvaddr;
		machdep->is_uvaddr = generic_is_uvaddr;
		machdep->uvtop = mips64_uvtop;
		machdep->kvtop = mips64_kvtop;
		machdep->cmd_mach = mips64_cmd_mach;
		machdep->back_trace = mips64_back_trace_cmd;
		machdep->get_stack_frame = mips64_get_stack_frame;
		machdep->vmalloc_start = mips64_vmalloc_start;
		machdep->processor_speed = mips64_processor_speed;
		machdep->get_stackbase = generic_get_stackbase;
		machdep->get_stacktop = generic_get_stacktop;
		machdep->translate_pte = mips64_translate_pte;
		machdep->memory_size = generic_memory_size;
		machdep->is_task_addr = mips64_is_task_addr;
		machdep->get_smp_cpus = mips64_get_smp_cpus;
		machdep->dis_filter = generic_dis_filter;
		machdep->dump_irq = generic_dump_irq;
		machdep->show_interrupts = generic_show_interrupts;
		machdep->get_irq_affinity = generic_get_irq_affinity;
		machdep->value_to_symbol = generic_machdep_value_to_symbol;
		machdep->init_kernel_pgd = NULL;
		break;

	case POST_GDB:
		mips64_init_page_flags();
		machdep->section_size_bits = _SECTION_SIZE_BITS;
		machdep->max_physmem_bits = _MAX_PHYSMEM_BITS;
		mips64_stackframe_init();
		if (!machdep->hz)
			machdep->hz = 250;

		if (symbol_exists("irq_desc"))
			ARRAY_LENGTH_INIT(machdep->nr_irqs, irq_desc,
					  "irq_desc", NULL, 0);
		else if (kernel_symbol_exists("nr_irqs"))
			get_symbol_data("nr_irqs", sizeof(unsigned int),
				&machdep->nr_irqs);

		MEMBER_OFFSET_INIT(elf_prstatus_pr_reg, "elf_prstatus",
				   "pr_reg");
		STRUCT_SIZE_INIT(note_buf, "note_buf_t");
		break;

	case POST_VM:
		/*
		 * crash_notes contains machine specific information about the
		 * crash. In particular, it contains CPU registers at the time
		 * of the crash. We need this information to extract correct
		 * backtraces from the panic task.
		 */
		if (!ACTIVE() && !mips64_init_active_task_regs())
			error(WARNING,
			    "cannot retrieve registers for active task%s\n\n",
				kt->cpus > 1 ? "s" : "");
		break;
	}
}

/*
 * 'help -r' command output
 */
void
mips64_display_regs_from_elf_notes(int cpu, FILE *ofp)
{
	const struct machine_specific *ms = machdep->machspec;
	struct mips64_register *regs;

	if (!ms->crash_task_regs) {
		error(INFO, "registers not collected for cpu %d\n", cpu);
		return;
	}

	regs = &ms->crash_task_regs[cpu];
	if (!regs->regs[MIPS64_EF_R29] && !regs->regs[MIPS64_EF_CP0_EPC]) {
		error(INFO, "registers not collected for cpu %d\n", cpu);
		return;
	}

	fprintf(ofp,
		"     R0: %016lx   R1: %016lx   R2: %016lx\n"
		"     R3: %016lx   R4: %016lx   R5: %016lx\n"
		"     R6: %016lx   R7: %016lx   R8: %016lx\n"
		"     R9: %016lx  R10: %016lx  R11: %016lx\n"
		"    R12: %016lx  R13: %016lx  R14: %016lx\n"
		"    R15: %016lx  R16: %016lx  R17: %016lx\n"
		"    R18: %016lx  R19: %016lx  R20: %016lx\n"
		"    R21: %016lx  R22: %016lx  R23: %016lx\n"
		"    R24: %016lx  R25: %016lx  R26: %016lx\n"
		"    R27: %016lx  R28: %016lx  R29: %016lx\n"
		"    R30: %016lx  R31: %016lx\n"
		"       LO: %016lx        HI: %016lx\n"
		"      EPC: %016lx  BADVADDR: %016lx\n"
		"   STATUS: %016lx     CAUSE: %016lx\n",
		regs->regs[MIPS64_EF_R0],
		regs->regs[MIPS64_EF_R0 + 1],
		regs->regs[MIPS64_EF_R0 + 2],
		regs->regs[MIPS64_EF_R0 + 3],
		regs->regs[MIPS64_EF_R0 + 4],
		regs->regs[MIPS64_EF_R0 + 5],
		regs->regs[MIPS64_EF_R0 + 6],
		regs->regs[MIPS64_EF_R0 + 7],
		regs->regs[MIPS64_EF_R0 + 8],
		regs->regs[MIPS64_EF_R0 + 9],
		regs->regs[MIPS64_EF_R0 + 10],
		regs->regs[MIPS64_EF_R0 + 11],
		regs->regs[MIPS64_EF_R0 + 12],
		regs->regs[MIPS64_EF_R0 + 13],
		regs->regs[MIPS64_EF_R0 + 14],
		regs->regs[MIPS64_EF_R0 + 15],
		regs->regs[MIPS64_EF_R0 + 16],
		regs->regs[MIPS64_EF_R0 + 17],
		regs->regs[MIPS64_EF_R0 + 18],
		regs->regs[MIPS64_EF_R0 + 19],
		regs->regs[MIPS64_EF_R0 + 20],
		regs->regs[MIPS64_EF_R0 + 21],
		regs->regs[MIPS64_EF_R0 + 22],
		regs->regs[MIPS64_EF_R0 + 23],
		regs->regs[MIPS64_EF_R0 + 24],
		regs->regs[MIPS64_EF_R0 + 25],
		regs->regs[MIPS64_EF_R0 + 26],
		regs->regs[MIPS64_EF_R0 + 27],
		regs->regs[MIPS64_EF_R0 + 28],
		regs->regs[MIPS64_EF_R0 + 29],
		regs->regs[MIPS64_EF_R0 + 30],
		regs->regs[MIPS64_EF_R0 + 31],
		regs->regs[MIPS64_EF_LO],
		regs->regs[MIPS64_EF_HI],
		regs->regs[MIPS64_EF_CP0_EPC],
		regs->regs[MIPS64_EF_CP0_BADVADDR],
		regs->regs[MIPS64_EF_CP0_STATUS],
		regs->regs[MIPS64_EF_CP0_CAUSE]);
}

#else /* !MIPS64 */

#include "defs.h"

void
mips64_display_regs_from_elf_notes(int cpu, FILE *ofp)
{
	return;
}

#endif /* !MIPS64 */
