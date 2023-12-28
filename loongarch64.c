/* loongarch64.c - core analysis suite
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

#ifdef LOONGARCH64

#include <elf.h>
#include "defs.h"

/* from arch/loongarch/include/asm/ptrace.h */
struct loongarch64_pt_regs {
	/* Saved main processor registers. */
	unsigned long regs[32];

	/* Saved special registers. */
	unsigned long csr_crmd;
	unsigned long csr_prmd;
	unsigned long csr_euen;
	unsigned long csr_ecfg;
	unsigned long csr_estat;
	unsigned long csr_epc;
	unsigned long csr_badvaddr;
	unsigned long orig_a0;
};

struct loongarch64_unwind_frame {
        unsigned long sp;
        unsigned long pc;
        unsigned long ra;
};

static int loongarch64_pgd_vtop(ulong *pgd, ulong vaddr,
			physaddr_t *paddr, int verbose);
static int loongarch64_uvtop(struct task_context *tc, ulong vaddr,
			physaddr_t *paddr, int verbose);
static int loongarch64_kvtop(struct task_context *tc, ulong kvaddr,
			physaddr_t *paddr, int verbose);
static int loongarch64_translate_pte(ulong pte, void *physaddr,
			ulonglong pte64);

/*
 * 3 Levels paging       PAGE_SIZE=16KB
 *  PGD  |  PMD  |  PTE  |  OFFSET  |
 *  11   |  11   |  11   |    14    |
 */
/* From arch/loongarch/include/asm/pgtable{,-64}.h */
typedef struct { ulong pgd; } pgd_t;
typedef struct { ulong pmd; } pmd_t;
typedef struct { ulong pte; } pte_t;

#define TASK_SIZE64	(1UL << 40)

#define PMD_SHIFT	(PAGESHIFT() + (PAGESHIFT() - 3))
#define PMD_SIZE	(1UL << PMD_SHIFT)
#define PMD_MASK	(~(PMD_SIZE - 1))

#define PGDIR_SHIFT	(PMD_SHIFT + (PAGESHIFT() - 3))
#define PGDIR_SIZE	(1UL << PGDIR_SHIFT)
#define PGDIR_MASK	(~(PGDIR_SIZE - 1))

#define PTRS_PER_PTE	(1UL << (PAGESHIFT() - 3))
#define PTRS_PER_PMD	PTRS_PER_PTE
#define PTRS_PER_PGD	PTRS_PER_PTE
#define USER_PTRS_PER_PGD	((TASK_SIZE64 / PGDIR_SIZE)?(TASK_SIZE64 / PGDIR_SIZE) : 1)

#define pte_index(addr)	(((addr) >> PAGESHIFT()) & (PTRS_PER_PTE - 1))
#define pmd_index(addr)	(((addr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
#define pgd_index(addr)	(((addr) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))

#define LOONGARCH64_CPU_RIXI	(1UL << 23)	/* CPU has TLB Read/eXec Inhibit */

static struct machine_specific loongarch64_machine_specific = { 0 };

/*
 * Check and print the flags on the page
 */
static void
check_page_flags(ulong pte)
{
#define CHECK_PAGE_FLAG(flag)				\
	if ((_PAGE_##flag) && (pte & _PAGE_##flag))	\
		fprintf(fp, "%s" #flag, others++ ? "|" : "")

	int others = 0;
	fprintf(fp, "(");

	if (pte) {
		CHECK_PAGE_FLAG(VALID);
		CHECK_PAGE_FLAG(DIRTY);
		CHECK_PAGE_FLAG(PLV);

		/* Determine whether it is a huge page format */
		if (pte & _PAGE_HGLOBAL) {
			CHECK_PAGE_FLAG(HUGE);
			CHECK_PAGE_FLAG(HGLOBAL);
		} else {
			CHECK_PAGE_FLAG(GLOBAL);
		}

		CHECK_PAGE_FLAG(PRESENT);
		CHECK_PAGE_FLAG(WRITE);
		CHECK_PAGE_FLAG(PROTNONE);
		CHECK_PAGE_FLAG(SPECIAL);
		CHECK_PAGE_FLAG(NO_READ);
		CHECK_PAGE_FLAG(NO_EXEC);
		CHECK_PAGE_FLAG(RPLV);
	} else {
		fprintf(fp, "no mapping");
	}

	fprintf(fp, ")\n");
}

/*
 * Translate a PTE, returning TRUE if the page is present.
 * If a physaddr pointer is passed in, don't print anything.
 */
static int
loongarch64_translate_pte(ulong pte, void *physaddr, ulonglong unused)
{
	char ptebuf[BUFSIZE];
	char physbuf[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char *arglist[MAXARGS];
	int page_present;
	int c, len1, len2, len3;
	ulong paddr;

	paddr = PTOB(pte >> _PFN_SHIFT);
	page_present = !!(pte & _PAGE_PRESENT);

	if (physaddr) {
		*(ulong *)physaddr = paddr;
		return page_present;
	}

	sprintf(ptebuf, "%lx", pte);
	len1 = MAX(strlen(ptebuf), strlen("PTE"));
	fprintf(fp, "%s  ", mkstring(buf1, len1, CENTER | LJUST, "PTE"));

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
	fprintf(fp, "%s  ", mkstring(buf1, len2, CENTER | LJUST, "PHYSICAL"));

	fprintf(fp, "FLAGS\n");
	fprintf(fp, "%s  %s  ",
		mkstring(ptebuf, len1, CENTER | RJUST, NULL),
		mkstring(physbuf, len2, CENTER | RJUST, NULL));

	check_page_flags(pte);

	return page_present;
}

/*
 * Identify and print the segment name to which the virtual address belongs
 */
static void
get_segment_name(ulong vaddr, int verbose)
{
	const char * segment;

	if (verbose) {
		if (vaddr < 0x4000000000000000lu)
			segment = "xuvrange";
		else if (vaddr < 0x8000000000000000lu)
			segment = "xsprange";
		else if (vaddr < 0xc000000000000000lu)
			segment = "xkprange";
		else
			segment = "xkvrange";

		fprintf(fp, "SEGMENT: %s\n", segment);
	}
}

/*
 * Virtual to physical memory translation. This function will be called
 * by both loongarch64_kvtop and loongarch64_uvtop.
 */
static int
loongarch64_pgd_vtop(ulong *pgd, ulong vaddr, physaddr_t *paddr, int verbose)
{
	ulong *pgd_ptr, pgd_val;
	ulong *pmd_ptr, pmd_val;
	ulong *pte_ptr, pte_val;

	get_segment_name(vaddr, verbose);

	if (IS_XKPRANGE(vaddr)) {
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
			loongarch64_translate_pte((ulong)pte_val, 0, pte_val);
		}
		return FALSE;
	}

	*paddr = PTOB(pte_val >> _PFN_SHIFT) + PAGEOFFSET(vaddr);

	if (verbose) {
		fprintf(fp, " PAGE: %016lx\n\n", PAGEBASE(*paddr));
		loongarch64_translate_pte(pte_val, 0, 0);
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
loongarch64_uvtop(struct task_context *tc, ulong vaddr, physaddr_t *paddr, int verbose)
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

	return loongarch64_pgd_vtop(pgd, vaddr, paddr, verbose);;
}

/* Translates a user virtual address to its physical address. cmd_vtop() sets
 * the verbose flag so that the pte translation gets displayed; all other
 * callers quietly accept the translation.
 */
static int
loongarch64_kvtop(struct task_context *tc, ulong kvaddr, physaddr_t *paddr, int verbose)
{
	if (!IS_KVADDR(kvaddr))
		return FALSE;

	if (!verbose) {
		if (IS_XKPRANGE(kvaddr)) {
			*paddr = VTOP(kvaddr);
			return TRUE;
		}
	}

	return loongarch64_pgd_vtop((ulong *)vt->kernel_pgd[0], kvaddr, paddr,
			     verbose);
}

/*
 * Accept or reject a symbol from the kernel namelist.
 */
static int
loongarch64_verify_symbol(const char *name, ulong value, char type)
{
	if (!strncmp(name, ".L", 2) || !strncmp(name, "L0", 2))
		return FALSE;

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
loongarch64_get_smp_cpus(void)
{
	return (get_cpus_online() > 0) ? get_cpus_online() : kt->cpus;
}

static ulong
loongarch64_get_page_size(void)
{
	return memory_page_size();
}

/*
 * Determine where vmalloc'd memory starts.
 */
static ulong
loongarch64_vmalloc_start(void)
{
	return 0;
}

/*
 * Calculate and return the speed of the processor.
 */
static ulong
loongarch64_processor_speed(void)
{
	unsigned long cpu_hz = 0;

	if (machdep->mhz)
		return (machdep->mhz);

	if (symbol_exists("cpu_clock_freq")) {
		get_symbol_data("cpu_clock_freq", sizeof(int), &cpu_hz);
		if (cpu_hz)
			return(machdep->mhz = cpu_hz/1000000);
	}

	return 0;
}

/*
 * Checks whether given task is valid task address.
 */
static int
loongarch64_is_task_addr(ulong task)
{
	if (tt->flags & THREAD_INFO)
		return IS_KVADDR(task);

	return (IS_KVADDR(task) && ALIGNED_STACK_OFFSET(task) == 0);
}

void
loongarch64_dump_machdep_table(ulong arg)
{
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

void
loongarch64_init(int when)
{
		switch (when) {
	case SETUP_ENV:
		machdep->process_elf_notes = process_elf64_notes;
		break;

	case PRE_SYMTAB:
		machdep->verify_symbol = loongarch64_verify_symbol;
		machdep->machspec = &loongarch64_machine_specific;
		if (pc->flags & KERNEL_DEBUG_QUERY)
			return;
		machdep->last_pgd_read = 0;
		machdep->last_pmd_read = 0;
		machdep->last_ptbl_read = 0;
		machdep->verify_paddr = generic_verify_paddr;
		machdep->ptrs_per_pgd = PTRS_PER_PGD;
		break;

	case PRE_GDB:
		machdep->pagesize = loongarch64_get_page_size();
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
		machdep->uvtop = loongarch64_uvtop;
		machdep->kvtop = loongarch64_kvtop;
		machdep->vmalloc_start = loongarch64_vmalloc_start;
		machdep->processor_speed = loongarch64_processor_speed;
		machdep->get_stackbase = generic_get_stackbase;
		machdep->get_stacktop = generic_get_stacktop;
		machdep->translate_pte = loongarch64_translate_pte;
		machdep->memory_size = generic_memory_size;
		machdep->is_task_addr = loongarch64_is_task_addr;
		machdep->get_smp_cpus = loongarch64_get_smp_cpus;
		machdep->dis_filter = generic_dis_filter;
		machdep->value_to_symbol = generic_machdep_value_to_symbol;
		machdep->init_kernel_pgd = NULL;
		break;

	case POST_GDB:
		machdep->section_size_bits = _SECTION_SIZE_BITS;
		machdep->max_physmem_bits = _MAX_PHYSMEM_BITS;

	case POST_VM:
		break;
	}
}

void
loongarch64_display_regs_from_elf_notes(int cpu, FILE *ofp)
{
}

#else /* !LOONGARCH64 */

#include "defs.h"

void
loongarch64_display_regs_from_elf_notes(int cpu, FILE *ofp)
{
       return;
}

#endif /* !LOONGARCH64 */
