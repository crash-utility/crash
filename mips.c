/*
 * mips.c - core analysis suite
 *
 * Copyright (C) 2015 Rabin Vincent <rabin rab in>
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

#ifdef MIPS

#include <elf.h>
#include "defs.h"

/* From arch/mips/asm/include/pgtable{,-32}.h */
typedef ulong pgd_t;
typedef ulong pte_t;

#define PTE_ORDER	0

#define PGD_T_LOG2	(__builtin_ffs(sizeof(pgd_t)) - 1)
#define PTE_T_LOG2	(__builtin_ffs(sizeof(pte_t)) - 1)

#define __PGD_ORDER	(32 - 3 * PAGESHIFT() + PGD_T_LOG2 + PTE_T_LOG2)
#define PGD_ORDER	(__PGD_ORDER >= 0 ? __PGD_ORDER : 0)
#define PGD_SIZE	(PAGESIZE() << PGD_ORDER)

#define PGDIR_SHIFT	(2 * PAGESHIFT() + PTE_ORDER - PTE_T_LOG2)
#define PGDIR_SIZE	(1UL << PGDIR_SHIFT)
#define PGDIR_MASK	(~(PGDIR_SIZE-1))

#define USER_PTRS_PER_PGD	(0x80000000UL/PGDIR_SIZE)

#define PTRS_PER_PGD	(USER_PTRS_PER_PGD * 2)
#define PTRS_PER_PTE	((PAGESIZE() << PTE_ORDER) / sizeof(pte_t))

#define pgd_index(address)	(((address) >> PGDIR_SHIFT) & (PTRS_PER_PGD-1))
#define pte_offset(address)						\
	(((address) >> PAGESHIFT()) & (PTRS_PER_PTE - 1))

#define MIPS_CPU_RIXI	0x00800000llu

#define MIPS32_EF_R0	6
#define MIPS32_EF_R29	35
#define MIPS32_EF_R31	37
#define MIPS32_EF_CPU0_EPC	40

static struct machine_specific mips_machine_specific = { 0 };

static void
mips_display_machine_stats(void)
{
        fprintf(fp, "          PAGE SIZE: %d\n", PAGESIZE());
	fprintf(fp, "\n");

#define PRINT_PAGE_FLAG(flag) 				\
	if (flag)					\
		fprintf(fp, "     %14s: %08lx\n", #flag, flag)

	PRINT_PAGE_FLAG(_PAGE_PRESENT);
	PRINT_PAGE_FLAG(_PAGE_READ);
	PRINT_PAGE_FLAG(_PAGE_WRITE);
	PRINT_PAGE_FLAG(_PAGE_ACCESSED);
	PRINT_PAGE_FLAG(_PAGE_MODIFIED);
	PRINT_PAGE_FLAG(_PAGE_GLOBAL);
	PRINT_PAGE_FLAG(_PAGE_VALID);
	PRINT_PAGE_FLAG(_PAGE_NO_READ);
	PRINT_PAGE_FLAG(_PAGE_NO_EXEC);
	PRINT_PAGE_FLAG(_PAGE_DIRTY);
}

static void
mips_cmd_mach(void)
{
        int c;

        while ((c = getopt(argcnt, args, "")) != EOF) {
                switch(c) {
                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

	mips_display_machine_stats();
}

#define PGDIR_OFFSET(X) (((ulong)(X)) & (PGD_SIZE - 1))

static void
mips_init_page_flags(void)
{
	ulong shift = 0;

	_PAGE_PRESENT = 1UL << shift++;

	if (THIS_KERNEL_VERSION >= LINUX(4,1,0)) {
		_PAGE_WRITE = 1UL << shift++;
		_PAGE_ACCESSED = 1UL << shift++;
		_PAGE_MODIFIED = 1UL << shift++;
		_PAGE_NO_EXEC = 1UL << shift++;
		_PAGE_READ = _PAGE_NO_READ = 1UL << shift++;
	} else {
		ulonglong cpu_options;
		int rixi;
		ulong addr;

		addr = symbol_value("cpu_data") +
		       MEMBER_OFFSET("cpuinfo_mips", "options");
		readmem(addr, KVADDR, &cpu_options, sizeof(cpu_options),
			"cpu_data[0].options", FAULT_ON_ERROR);

		rixi = cpu_options & MIPS_CPU_RIXI;

		if (!rixi)
			_PAGE_READ = 1UL << shift++;

		_PAGE_WRITE = 1UL << shift++;
		_PAGE_ACCESSED = 1UL << shift++;
		_PAGE_MODIFIED = 1UL << shift++;

		if (rixi) {
			_PAGE_NO_EXEC = 1UL << shift++;
			_PAGE_NO_READ = 1UL << shift++;
		}
	}

	_PAGE_GLOBAL = 1UL << shift++;
	_PAGE_VALID = 1UL << shift++;
	_PAGE_DIRTY = 1UL << shift++;

	_PFN_SHIFT = PAGESHIFT() - 12 + shift + 3;
}

static int
mips_translate_pte(ulong pte, void *physaddr, ulonglong pte64)
{
	char ptebuf[BUFSIZE];
	char physbuf[BUFSIZE];
	char buf[BUFSIZE];
	int present;
	ulong paddr;
	int len1, len2, others;

	present = pte & _PAGE_PRESENT;
	paddr = (pte >> _PFN_SHIFT) << PAGESHIFT();

	if (physaddr) {
		*(ulong *)physaddr = PAGEBASE(pte);
		return !!present;
	}

	sprintf(ptebuf, "%lx", pte);
	len1 = MAX(strlen(ptebuf), strlen("PTE"));
	fprintf(fp, "%s  ", mkstring(buf, len1, CENTER | LJUST, "PTE"));

	if (!present)
		return !!present;

	sprintf(physbuf, "%lx", paddr);
	len2 = MAX(strlen(physbuf), strlen("PHYSICAL"));
	fprintf(fp, "%s  ", mkstring(buf, len2, CENTER | LJUST, "PHYSICAL"));

	fprintf(fp, "FLAGS\n");
	fprintf(fp, "%s  %s  ",
		mkstring(ptebuf, len1, CENTER | RJUST, NULL),
		mkstring(physbuf, len2, CENTER | RJUST, NULL));

	fprintf(fp, "(");
	others = 0;

#define CHECK_PAGE_FLAG(flag) 				\
	if ((_PAGE_##flag) && (pte & _PAGE_##flag))	\
		fprintf(fp, "%s" #flag, others++ ? "|" : "")

	if (pte) {
		CHECK_PAGE_FLAG(PRESENT);
		CHECK_PAGE_FLAG(READ);
		CHECK_PAGE_FLAG(WRITE);
		CHECK_PAGE_FLAG(ACCESSED);
		CHECK_PAGE_FLAG(MODIFIED);
		CHECK_PAGE_FLAG(GLOBAL);
		CHECK_PAGE_FLAG(VALID);
		CHECK_PAGE_FLAG(NO_READ);
		CHECK_PAGE_FLAG(NO_EXEC);
		CHECK_PAGE_FLAG(DIRTY);
	} else {
		fprintf(fp, "no mapping");
	}

	fprintf(fp, ")\n");

	return !!present;
}

static int
mips_pgd_vtop(ulong *pgd, ulong vaddr, physaddr_t *paddr, int verbose)
{
	ulong invalid_pte_table = symbol_value("invalid_pte_table");
	ulong *page_dir;
	ulong pgd_pte, page_table;
	ulong pte;
	ulong pbase;

	if (verbose) {
		const char *segment;

		if (vaddr < 0x80000000lu)
			segment = "useg";
		else if (vaddr < 0xa0000000lu)
			segment = "kseg0";
		else if (vaddr < 0xc0000000lu)
			segment = "kseg1";
		else if (vaddr < 0xe0000000lu)
			segment = "ksseg";
		else
			segment = "kseg3";

		fprintf(fp, "SEGMENT: %s\n", segment);
	}

	if (vaddr >= 0x80000000lu && vaddr < 0xc0000000lu) {
		*paddr = VTOP(vaddr);
		return TRUE;
	}

	if (verbose)
		fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)pgd);

	page_dir = pgd + pgd_index(vaddr);

	FILL_PGD(PAGEBASE(pgd), KVADDR, PGD_SIZE);
	pgd_pte = ULONG(machdep->pgd + PGDIR_OFFSET(page_dir));

	if (verbose)
		fprintf(fp, "  PGD: %08lx => %lx\n", (ulong)page_dir, pgd_pte);

	if (pgd_pte == invalid_pte_table) {
		fprintf(fp, "invalid\n");
		return FALSE;
	}

	page_table = VTOP(pgd_pte) + sizeof(pte_t) * pte_offset(vaddr);

	FILL_PTBL(PAGEBASE(page_table), PHYSADDR, PAGESIZE());
	pte = ULONG(machdep->ptbl + PAGEOFFSET(page_table));
	if (verbose)
		fprintf(fp, "  PTE: %08lx => %08lx\n", page_table, pte);

	if (!(pte & _PAGE_PRESENT)) {
		if (verbose) {
			fprintf(fp, "\n");
			mips_translate_pte((ulong)pte, 0, pte);
		}
		return FALSE;
	}

	pbase = (pte >> _PFN_SHIFT) << PAGESHIFT();
	*paddr = pbase + PAGEOFFSET(vaddr);

	if (verbose) {
		fprintf(fp, " PAGE: %08lx\n\n", pbase);
		mips_translate_pte(pte, 0, 0);
	}

	return TRUE;
}

static int
mips_uvtop(struct task_context *tc, ulong vaddr, physaddr_t *paddr, int verbose)
{
	ulong *pgd;

	if (!tc)
		error(FATAL, "current context invalid\n");

        if (is_kernel_thread(tc->task) && IS_KVADDR(vaddr)) {
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

	return mips_pgd_vtop(pgd, vaddr, paddr, verbose);
}

static int
mips_kvtop(struct task_context *tc, ulong kvaddr, physaddr_t *paddr, int verbose)
{
	if (!IS_KVADDR(kvaddr))
		return FALSE;

	if (!verbose && !IS_VMALLOC_ADDR(kvaddr)) {
		*paddr = VTOP(kvaddr);
		return TRUE;
	}

	return mips_pgd_vtop((ulong *)vt->kernel_pgd[0], kvaddr, paddr,
			     verbose);
}

static void
mips_dump_exception_stack(struct bt_info *bt, char *pt_regs)
{
	struct mips_pt_regs_main *mains;
	struct mips_pt_regs_cp0 *cp0;
	int i;
	char buf[BUFSIZE];

	mains = (struct mips_pt_regs_main *) (pt_regs + OFFSET(pt_regs_regs));
	cp0 = (struct mips_pt_regs_cp0 *) \
	      (pt_regs + OFFSET(pt_regs_cp0_badvaddr));

	for (i = 0; i < 32; i += 4) {
		fprintf(fp, "    $%2d   : %08lx %08lx %08lx %08lx\n",
			i, mains->regs[i], mains->regs[i+1],
			mains->regs[i+2], mains->regs[i+3]);
	}
	fprintf(fp, "    Hi    : %08lx\n", mains->hi);
	fprintf(fp, "    Lo    : %08lx\n", mains->lo);

	value_to_symstr(cp0->cp0_epc, buf, 16);
	fprintf(fp, "    epc   : %08lx %s\n", cp0->cp0_epc, buf);

	value_to_symstr(mains->regs[31], buf, 16);
	fprintf(fp, "    ra    : %08lx %s\n", mains->regs[31], buf);

	fprintf(fp, "    Status: %08lx\n", mains->cp0_status);
	fprintf(fp, "    Cause : %08lx\n", cp0->cp0_cause);
	fprintf(fp, "    BadVA : %08lx\n", cp0->cp0_badvaddr);
}

struct mips_unwind_frame {
	ulong sp;
	ulong pc;
	ulong ra;
};

static void
mips_display_full_frame(struct bt_info *bt, struct mips_unwind_frame *current,
			struct mips_unwind_frame *previous)
{
	ulong words, addr;
	ulong *up;
	char buf[BUFSIZE];
	int i, u_idx;

	if (!INSTACK(previous->sp, bt) || !INSTACK(current->sp, bt))
		return;

	words = (previous->sp - current->sp) / sizeof(ulong);

	if (words == 0) {
		fprintf(fp, "    (no frame)\n");
		return;
	}

	addr = current->sp;
	u_idx = (current->sp - bt->stackbase) / sizeof(ulong);
	for (i = 0; i < words; i++, u_idx++) {
		if ((i % 4) == 0)
			fprintf(fp, "%s    %lx: ", i ? "\n" : "", addr);

		up = (ulong *)(&bt->stackbuf[u_idx * sizeof(ulong)]);
		fprintf(fp, "%s ", format_stack_entry(bt, buf, *up, 0));
		addr += sizeof(ulong);
	}
	fprintf(fp, "\n");
}

static int
mips_is_exception_entry(struct syment *sym)
{
	return STREQ(sym->name, "ret_from_exception") ||
	       STREQ(sym->name, "ret_from_irq") ||
	       STREQ(sym->name, "work_resched") ||
	       STREQ(sym->name, "handle_sys");
}

static void
mips_dump_backtrace_entry(struct bt_info *bt, struct syment *sym,
			  struct mips_unwind_frame *current,
			  struct mips_unwind_frame *previous, int level)
{
	const char *name = sym->name;
	struct load_module *lm;
	char *name_plus_offset;
	char buf[BUFSIZE];

	name_plus_offset = NULL;
	if (bt->flags & BT_SYMBOL_OFFSET) {
		struct syment *symp;
		ulong symbol_offset;

		symp = value_search(current->pc, &symbol_offset);

		if (symp && symbol_offset)
			name_plus_offset =
				value_to_symstr(current->pc, buf, bt->radix);
	}

	fprintf(fp, "%s#%d [%8lx] %s at %lx", level < 10 ? " " : "", level,
		current->sp, name_plus_offset ? name_plus_offset : name,
		current->pc);

	if (module_symbol(current->pc, NULL, &lm, NULL, 0))
		fprintf(fp, " [%s]", lm->mod_name);

	fprintf(fp, "\n");

	if (bt->flags & BT_LINE_NUMBERS) {
		char buf[BUFSIZE];

		get_line_number(current->pc, buf, FALSE);
		if (strlen(buf))
			fprintf(fp, "    %s\n", buf);
	}

	if (mips_is_exception_entry(sym)) {
		char pt_regs[SIZE(pt_regs)];

		GET_STACK_DATA(current->sp, &pt_regs, SIZE(pt_regs));
		mips_dump_exception_stack(bt, pt_regs);
	}

	if (bt->flags & BT_FULL) {
		fprintf(fp, "    "
			"[PC: %08lx RA: %08lx SP: %08lx SIZE: %ld]\n",
			current->pc, current->ra, current->sp,
			previous->sp - current->sp);
		mips_display_full_frame(bt, current, previous);
	}
}


static void
mips_analyze_function(ulong start, ulong offset,
		      struct mips_unwind_frame *current,
		      struct mips_unwind_frame *previous)
{
	ulong rapos = 0;
	ulong spadjust = 0;
	ulong *funcbuf, *ip;
	ulong i;

	if (CRASHDEBUG(8))
		fprintf(fp, "%s: start %#lx offset %#lx\n",
			__func__, start, offset);

	if (!offset) {
		previous->sp = current->sp;
		return;
	}

	ip = funcbuf = (ulong *)GETBUF(offset);
	if (!readmem(start, KVADDR, funcbuf, offset,
		     "mips_analyze_function", RETURN_ON_ERROR)) {
		FREEBUF(funcbuf);
		error(FATAL, "Cannot read function at %8x", start);
		return;
	}

	for (i = 0; i < offset; i += 4) {
		ulong insn = *ip;
		ulong high = (insn >> 16) & 0xffff;
		ulong low = insn & 0xffff;

		if (CRASHDEBUG(8))
			fprintf(fp, "insn @ %#lx = %#lx\n", start + i, insn);

		if (high == 0x27bd) { /* ADDIU sp, sp, imm */
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
mips_back_trace_cmd(struct bt_info *bt)
{
	struct mips_unwind_frame current, previous;
	int level = 0;

	previous.sp = previous.pc = previous.ra = 0;

	current.pc = bt->instptr;
	current.sp = bt->stkptr;
	current.ra = 0;

	if (bt->machdep) {
		struct mips_regset *regs = bt->machdep;
		previous.pc = current.ra = regs->regs[MIPS32_EF_R31];
	}

	while (INSTACK(current.sp, bt)) {
		struct syment *symbol;
		ulong offset;

		if (CRASHDEBUG(8))
			fprintf(fp, "level %d pc %#lx ra %#lx sp %lx\n",
				level, current.pc, current.ra, current.sp);

		if (!IS_KVADDR(current.pc))
			return;

		symbol = value_search(current.pc, &offset);
		if (!symbol) {
			error(FATAL, "PC is unknown symbol (%lx)", current.pc);
			return;
		}

		/*
		 * If we get an address which points to the start of a
		 * function, then it could one of the following:
		 *
		 *  - we are dealing with a noreturn function.  The last call
		 *    from a noreturn function has an an ra which points to the
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
		if (!current.ra && !offset && !STRNEQ(symbol->name, "ret_from")) {
			if (CRASHDEBUG(8))
				fprintf(fp, "zero offset at %s, try previous symbol\n",
					symbol->name);

			symbol = value_search(current.pc - 4, &offset);
			if (!symbol) {
				error(FATAL, "PC is unknown symbol (%lx)", current.pc);
				return;
			}
		}

		if (mips_is_exception_entry(symbol)) {
			struct mips_pt_regs_main *mains;
			struct mips_pt_regs_cp0 *cp0;
			char pt_regs[SIZE(pt_regs)];

			mains = (struct mips_pt_regs_main *) \
			       (pt_regs + OFFSET(pt_regs_regs));
			cp0 = (struct mips_pt_regs_cp0 *) \
			      (pt_regs + OFFSET(pt_regs_cp0_badvaddr));

			GET_STACK_DATA(current.sp, pt_regs, sizeof(pt_regs));

			previous.ra = mains->regs[31];
			previous.sp = mains->regs[29];
			current.ra = cp0->cp0_epc;

			if (CRASHDEBUG(8))
				fprintf(fp, "exception pc %#lx ra %#lx sp %lx\n",
					previous.pc, previous.ra, previous.sp);
		} else {
			mips_analyze_function(symbol->value, offset, &current, &previous);
		}

		mips_dump_backtrace_entry(bt, symbol, &current, &previous, level++);
		if (!current.ra)
			break;

		current.pc = current.ra;
		current.sp = previous.sp;
		current.ra = previous.ra;

		previous.sp = previous.pc = previous.ra = 0;
	}
}

static void
mips_dumpfile_stack_frame(struct bt_info *bt, ulong *nip, ulong *ksp)
{
	struct mips_regset *regs;

	regs = bt->machdep;
	if (!regs) {
		fprintf(fp, "0%lx: Register values not available\n",
			bt->task);
		return;
	}

	if (nip)
		*nip = regs->regs[MIPS32_EF_CPU0_EPC];
	if (ksp)
		*ksp = regs->regs[MIPS32_EF_R29];
}

static int
mips_get_frame(struct bt_info *bt, ulong *pcp, ulong *spp)
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

static void
mips_stackframe_init(void)
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

static void
mips_get_stack_frame(struct bt_info *bt, ulong *pcp, ulong *spp)
{
	*pcp = 0;
	*spp = 0;

	if (DUMPFILE() && is_task_active(bt->task))
		mips_dumpfile_stack_frame(bt, pcp, spp);
	else
		mips_get_frame(bt, pcp, spp);

}

static int
mips_eframe_search(struct bt_info *bt)
{
	return error(FATAL, "%s: not implemented\n", __func__);
}

static ulong
mips_get_task_pgd(ulong task)
{
	return error(FATAL, "%s: not implemented\n", __func__);
}

static int
mips_is_task_addr(ulong task)
{
	if (tt->flags & THREAD_INFO)
		return IS_KVADDR(task);

	return (IS_KVADDR(task) && ALIGNED_STACK_OFFSET(task) == 0);
}

static ulong
mips_processor_speed(void)
{
	return 0;
}

static int
mips_get_smp_cpus(void)
{
	return (get_cpus_online() > 0) ? get_cpus_online() : kt->cpus;
}

static ulong
mips_vmalloc_start(void)
{
	return first_vmalloc_address();
}

static int
mips_verify_symbol(const char *name, ulong value, char type)
{
	if (STREQ(name, "_text"))
		machdep->flags |= KSYMS_START;

	return (name && strlen(name) && (machdep->flags & KSYMS_START) &&
	        !STRNEQ(name, "__func__.") && !STRNEQ(name, "__crc_"));
}

void
mips_dump_machdep_table(ulong arg)
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
	fprintf(fp, "       ptrs_per_pte: %d\n", PTRS_PER_PTE);
	fprintf(fp, "          stacksize: %ld\n", machdep->stacksize);
	fprintf(fp, "            memsize: %lld (0x%llx)\n",
		machdep->memsize, machdep->memsize);
	fprintf(fp, "               bits: %d\n", machdep->bits);
	fprintf(fp, "            nr_irqs: %d\n", machdep->nr_irqs);
	fprintf(fp, "      eframe_search: mips_eframe_search()\n");
	fprintf(fp, "         back_trace: mips_back_trace_cmd()\n");
	fprintf(fp, "    processor_speed: mips_processor_speed()\n");
	fprintf(fp, "              uvtop: mips_uvtop()\n");
	fprintf(fp, "              kvtop: mips_kvtop()\n");
	fprintf(fp, "       get_task_pgd: mips_get_task_pgd()\n");
	fprintf(fp, "           dump_irq: generic_dump_irq()\n");
	fprintf(fp, "    show_interrupts: generic_show_interrupts()\n");
	fprintf(fp, "   get_irq_affinity: generic_get_irq_affinity()\n");
	fprintf(fp, "    get_stack_frame: mips_get_stack_frame()\n");
	fprintf(fp, "      get_stackbase: generic_get_stackbase()\n");
	fprintf(fp, "       get_stacktop: generic_get_stacktop()\n");
	fprintf(fp, "      translate_pte: mips_translate_pte()\n");
	fprintf(fp, "        memory_size: generic_memory_size()\n");
	fprintf(fp, "      vmalloc_start: mips_vmalloc_start()\n");
	fprintf(fp, "       is_task_addr: mips_is_task_addr()\n");
	fprintf(fp, "      verify_symbol: mips_verify_symbol()\n");
	fprintf(fp, "         dis_filter: generic_dis_filter()\n");
	fprintf(fp, "           cmd_mach: mips_cmd_mach()\n");
	fprintf(fp, "       get_smp_cpus: mips_get_smp_cpus()\n");
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

static ulong
mips_get_page_size(void)
{
	struct syment *spd, *next = NULL;

	spd = symbol_search("swapper_pg_dir");
	if (spd)
		next = next_symbol(NULL, spd);

	if (!spd || !next)
		return memory_page_size();

	return next->value - spd->value;
}

void
mips_init(int when)
{
#if defined(__i386__) || defined(__x86_64__)
	if (ACTIVE())
		error(FATAL, "compiled for the MIPS architecture\n");
#endif

	switch (when) {
	case SETUP_ENV:
		machdep->process_elf_notes = process_elf32_notes;
		break;

	case PRE_SYMTAB:
		machdep->verify_symbol = mips_verify_symbol;
		machdep->machspec = &mips_machine_specific;
		if (pc->flags & KERNEL_DEBUG_QUERY)
			return;
		machdep->last_pgd_read = 0;
		machdep->last_pmd_read = 0;
		machdep->last_ptbl_read = 0;
		machdep->verify_paddr = generic_verify_paddr;
		machdep->ptrs_per_pgd = PTRS_PER_PGD;
		break;

	case PRE_GDB:
		machdep->pagesize = mips_get_page_size();
		machdep->pageshift = ffs(machdep->pagesize) - 1;
		machdep->pageoffset = machdep->pagesize - 1;
		machdep->pagemask = ~((ulonglong)machdep->pageoffset);
		if (machdep->pagesize >= 16384)
			machdep->stacksize = machdep->pagesize;
		else
			machdep->stacksize = machdep->pagesize * 2;

		if ((machdep->pgd = malloc(PGD_SIZE)) == NULL)
			error(FATAL, "cannot malloc pgd space.");
		if ((machdep->ptbl = malloc(PAGESIZE())) == NULL)
			error(FATAL, "cannot malloc ptbl space.");

	        machdep->kvbase = 0x80000000;
		machdep->identity_map_base = machdep->kvbase;
                machdep->is_kvaddr = generic_is_kvaddr;
                machdep->is_uvaddr = generic_is_uvaddr;
	        machdep->uvtop = mips_uvtop;
	        machdep->kvtop = mips_kvtop;
		machdep->vmalloc_start = mips_vmalloc_start;
	        machdep->eframe_search = mips_eframe_search;
	        machdep->back_trace = mips_back_trace_cmd;
	        machdep->processor_speed = mips_processor_speed;
	        machdep->get_task_pgd = mips_get_task_pgd;
		machdep->get_stack_frame = mips_get_stack_frame;
		machdep->get_stackbase = generic_get_stackbase;
		machdep->get_stacktop = generic_get_stacktop;
		machdep->translate_pte = mips_translate_pte;
		machdep->memory_size = generic_memory_size;
		machdep->is_task_addr = mips_is_task_addr;
		machdep->dis_filter = generic_dis_filter;
		machdep->cmd_mach = mips_cmd_mach;
		machdep->get_smp_cpus = mips_get_smp_cpus;
		machdep->value_to_symbol = generic_machdep_value_to_symbol;
                machdep->init_kernel_pgd = NULL;
		break;
	case POST_GDB:
		mips_init_page_flags();
		machdep->dump_irq = generic_dump_irq;
		machdep->show_interrupts = generic_show_interrupts;
		machdep->get_irq_affinity = generic_get_irq_affinity;
		ARRAY_LENGTH_INIT(machdep->nr_irqs, irq_desc,
			"irq_desc", NULL, 0);
		mips_stackframe_init();
		break;
	}
}

#endif /* MIPS */
