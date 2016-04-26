/* sparc64.c - core analysis suite
 *
 * Copyright (C) 2016 Oracle Corporation
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
#ifdef SPARC64

#include "defs.h"
#include <stdio.h>
#include <elf.h>
#include <asm/ptrace.h>
#include <linux/const.h>

/* TT (Trap Type) is encoded into magic pt_regs field */
#define	MAGIC_TT_MASK		(0x1ff)

static const unsigned long not_valid_pte = ~0UL;
static struct machine_specific sparc64_machine_specific;
static unsigned long sparc64_ksp_offset;

static unsigned long
__va(unsigned long paddr)
{
	return paddr + PAGE_OFFSET;
}

static unsigned long
__pa(unsigned long vaddr)
{
	return vaddr - PAGE_OFFSET;
}

static void
sparc64_parse_cmdline_args(void)
{
}

/* This interface might not be required. */
static void
sparc64_clear_machdep_cache(void)
{
}

/*
 *  "mach" command output.
 */
static void
sparc64_display_machine_stats(void)
{
	int c;
	struct new_utsname *uts;
	char buf[BUFSIZE];
	ulong mhz;

	uts = &kt->utsname;

	fprintf(fp, "          MACHINE TYPE: %s\n", uts->machine);
	fprintf(fp, "           MEMORY SIZE: %s\n", get_memory_size(buf));
	fprintf(fp, "                  CPUS: %d\n", kt->cpus);
	fprintf(fp, "       PROCESSOR SPEED: ");
	if ((mhz = machdep->processor_speed()))
		fprintf(fp, "%ld Mhz\n", mhz);
	else
		fprintf(fp, "(unknown)\n");
	fprintf(fp, "                    HZ: %d\n", machdep->hz);
	fprintf(fp, "             PAGE SIZE: %ld\n", PAGE_SIZE);
	fprintf(fp, "   KERNEL VIRTUAL BASE: %lx\n", machdep->kvbase);
	fprintf(fp, "   KERNEL VMALLOC BASE: %lx\n", SPARC64_VMALLOC_START);
	fprintf(fp, "   KERNEL MODULES BASE: %lx\n", SPARC64_MODULES_VADDR);
	fprintf(fp, "     KERNEL STACK SIZE: %ld\n", STACKSIZE());

	fprintf(fp, "HARD IRQ STACK SIZE: %ld\n", THREAD_SIZE);
	fprintf(fp, "    HARD IRQ STACKS:\n");

	for (c = 0; c < kt->cpus; c++) {
		if (!tt->hardirq_ctx[c])
			continue;
		sprintf(buf, "CPU %d", c);
		fprintf(fp, "%19s: %lx\n", buf, tt->hardirq_ctx[c]);
	}

	fprintf(fp, "SOFT IRQ STACK SIZE: %ld\n", THREAD_SIZE);
	fprintf(fp, "    SOFT IRQ STACKS:\n");
	for (c = 0; c < kt->cpus; c++) {
		if (!tt->softirq_ctx[c])
			continue;
		sprintf(buf, "CPU %d", c);
		fprintf(fp, "%19s: %lx\n", buf, tt->softirq_ctx[c]);
	}
}

static void
sparc64_display_memmap(void)
{
	unsigned long iomem_resource;
	unsigned long resource;
	unsigned long start, end, nameptr;
	int size = STRUCT_SIZE("resource");
	char *buf;
	char name[32];

	buf = GETBUF(size);
	iomem_resource = symbol_value("iomem_resource");

	readmem(iomem_resource + MEMBER_OFFSET("resource", "child"), KVADDR,
		&resource, sizeof(resource), "iomem_resource", FAULT_ON_ERROR);

	fprintf(fp, "      PHYSICAL ADDRESS RANGE         TYPE\n");

	while (resource) {
		readmem(resource, KVADDR, buf, size, "resource",
			FAULT_ON_ERROR);
		start = ULONG(buf + MEMBER_OFFSET("resource", "start"));
		end = ULONG(buf + MEMBER_OFFSET("resource", "end"));
		nameptr = ULONG(buf + MEMBER_OFFSET("resource", "name"));

		readmem(nameptr, KVADDR, name, sizeof(name), "resource.name",
			FAULT_ON_ERROR);

		fprintf(fp, "%016lx - %016lx  %-32s\n", start, end, name);

		resource = ULONG(buf + MEMBER_OFFSET("resource", "sibling"));
	}
	FREEBUF(buf);
}

static void
sparc64_cmd_mach(void)
{
	int c;
	int mflag = 0;

	while ((c = getopt(argcnt, args, "cdmx")) != EOF) {
		switch (c) {
		case 'm':
			mflag++;
			sparc64_display_memmap();
			break;
		case 'c':
			fprintf(fp, "SPARC64: '-%c' option is not supported\n",
				c);
			return;
		case 'd':
		case 'x':
			/* Just ignore these */
			break;
		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (!mflag)
		sparc64_display_machine_stats();
}

struct sparc64_mem_ranges {
	unsigned long start;
	unsigned long end;
};

#define NR_PHYS_RANGES	(128)
static unsigned int nr_phys_ranges;
struct sparc64_mem_ranges phys_ranges[NR_PHYS_RANGES];

#define NR_IMAGE_RANGES (16)
static unsigned int nr_kimage_ranges;
struct sparc64_mem_ranges kimage_ranges[NR_IMAGE_RANGES];

/* There are three live cases:
 *  one) normal kernel
 *  two) --load-panic kernel
 *  and
 *  three) --load kernel
 * One and two can be treated the same because the kernel is physically
 * contiguous. Three isn't contiguous. The kernel is allocated in order
 * nine allocation pages. We don't handle case three yet.
 */

static int
sparc64_phys_live_valid(unsigned long paddr)
{
	unsigned int nr;
	int rc = FALSE;

	for (nr = 0; nr != nr_phys_ranges; nr++) {
		if (paddr >= phys_ranges[nr].start &&
			paddr < phys_ranges[nr].end) {
			rc = TRUE;
			break;
		}
	}
	return rc;
}

static int
sparc64_phys_kdump_valid(unsigned long paddr)
{
	return TRUE;
}

static int
sparc64_verify_paddr(unsigned long paddr)
{
	int rc;

	if (ACTIVE())
		rc = sparc64_phys_live_valid(paddr);
	else
		rc = sparc64_phys_kdump_valid(paddr);

	return rc;
}

static void
sparc6_phys_base_live_limits(void)
{
	if (nr_phys_ranges >= NR_PHYS_RANGES)
		error(FATAL, "sparc6_phys_base_live_limits: "
			"NR_PHYS_RANGES exceeded.\n");
	else if (nr_kimage_ranges >= NR_IMAGE_RANGES)
		error(FATAL, "sparc6_phys_base_live_limits: "
			"NR_IMAGE_RANGES exceeded.\n");
}

static void
sparc64_phys_base_live_valid(void)
{
	if (!nr_phys_ranges)
		error(FATAL, "No physical memory ranges.");
	else if (!nr_kimage_ranges)
		error(FATAL, "No vmlinux memory ranges.");
}

static void
sparc64_phys_base_live(void)
{
	char line[BUFSIZE];
	FILE *fp;

	fp = fopen("/proc/iomem", "r");
	if (fp == NULL)
		error(FATAL, "Can't open /proc/iomem. We can't proceed.");

	while (fgets(line, sizeof(line), fp) != 0) {
		unsigned long start, end;
		int count, consumed;
		char *ch;

		sparc6_phys_base_live_limits();
		count = sscanf(line, "%lx-%lx : %n", &start, &end, &consumed);
		if (count != 2)
			continue;
		ch = line + consumed;
		if (memcmp(ch, "System RAM\n", 11) == 0) {
			end = end + 1;
			phys_ranges[nr_phys_ranges].start = start;
			phys_ranges[nr_phys_ranges].end = end;
			nr_phys_ranges++;
		} else if ((memcmp(ch, "Kernel code\n", 12) == 0) ||
				(memcmp(ch, "Kernel data\n", 12) == 0) ||
				(memcmp(ch, "Kernel bss\n", 11) == 0)) {
			kimage_ranges[nr_kimage_ranges].start = start;
			kimage_ranges[nr_kimage_ranges].end = end;
			nr_kimage_ranges++;
		}
	}

	(void) fclose(fp);
	sparc64_phys_base_live_valid();
}

static void
sparc64_phys_base_kdump(void)
{
}

static void
sparc64_phys_base(void)
{
	if (ACTIVE())
		return sparc64_phys_base_live();
	else
		return sparc64_phys_base_kdump();
}

static unsigned long kva_start, kva_end;
static unsigned long kpa_start, kpa_end;

static void
sparc64_kimage_limits_live(void)
{
	kpa_start = kimage_ranges[0].start;
	kpa_end = kpa_start + (kva_end - kva_start);
}

static void
sparc64_kimage_limits_kdump(void)
{
	unsigned long phys_base;

	if (DISKDUMP_DUMPFILE()) {
		if (diskdump_phys_base(&phys_base)) {
			kpa_start = phys_base | (kva_start & 0xffff);
			kpa_end = kpa_start + (kva_end - kva_start);
			return;
		}
	}
	fprintf(stderr, "Can't determine phys_base\n");
}

static unsigned long
kimage_va_translate(unsigned long addr)
{
	unsigned long paddr = (addr - kva_start) + kpa_start;

	return paddr;
}

static int
kimage_va_range(unsigned long addr)
{
	if (addr >= kva_start && addr < kva_end)
		return TRUE;
	else
		return FALSE;
}

static void
sparc64_kimage_limits(void)
{
	kva_start = symbol_value("_stext");
	kva_end = symbol_value("_end");

	if (ACTIVE())
		sparc64_kimage_limits_live();
	else
		sparc64_kimage_limits_kdump();
}

static int
sparc64_is_linear_mapped(unsigned long vaddr)
{
	return (vaddr & PAGE_OFFSET) == PAGE_OFFSET;
}

static unsigned long
pte_to_pa(unsigned long pte)
{
	unsigned long paddr = pte & _PAGE_PFN_MASK;

	return paddr;
}

static unsigned long
fetch_page_table_level(unsigned long pte_kva, unsigned long vaddr,
		       unsigned int shift, unsigned int mask, const char *name,
		       int verbose)
{
	unsigned int pte_index = (vaddr >> shift) & mask;
	unsigned long page_table[PTES_PER_PAGE];
	unsigned long pte = 0UL;
	int rc;

	rc = readmem(pte_kva, KVADDR, page_table, sizeof(page_table),
		     (char *)name, RETURN_ON_ERROR);
	if (!rc)
		goto out;
	pte = page_table[pte_index];
	if (verbose)
		fprintf(fp,
			"%s(0x%.16lx) fetch of pte @index[0x%.4x]=0x%.16lx\n",
			name, pte_kva, pte_index, pte);
out:
	return pte;
}

static unsigned long
pmd_is_huge(unsigned long pmd, unsigned long vaddr, int verbose)
{
	unsigned long hpage_mask;
	unsigned long paddr = 0UL;

	if ((pmd & PAGE_PMD_HUGE) == 0UL)
		goto out;
	hpage_mask = ~((1UL << HPAGE_SHIFT) - 1UL);
	paddr = pte_to_pa(pmd) + (vaddr & ~hpage_mask);
	if (verbose)
		fprintf(fp, "Huge Page/THP pmd=0x%.16lx paddr=0x%.16lx\n",
			pmd, paddr);
out:
	return paddr;
}

static unsigned long
sparc64_page_table_walk(unsigned long pgd, unsigned long vaddr, int verbose)
{
	static const char *pgd_text = "pgd fetch";
	static const char *pud_text = "pud fetch";
	static const char *pmd_text = "pmd fetch";
	static const char *pte_text = "pte fetch";
	unsigned long kva = pgd;
	unsigned long paddr;
	unsigned long pte;

	if (!sparc64_is_linear_mapped(kva))
		error(FATAL,
			"sparc64_page_table_walk: pgd must be identity mapped"
			" but isn't (0xlx).", pgd);

	pte = fetch_page_table_level(kva, vaddr, PGDIR_SHIFT,
				     PTES_PER_PAGE_MASK, pgd_text, verbose);
	if (!pte)
		goto bad;
	kva = __va(pte);

	pte = fetch_page_table_level(kva, vaddr, PUD_SHIFT, PTES_PER_PAGE_MASK,
				     pud_text, verbose);
	if (!pte)
		goto bad;

	kva = __va(pte);
	pte = fetch_page_table_level(kva, vaddr, PMD_SHIFT,
				     PTES_PER_PAGE_MASK, pmd_text, verbose);
	if (!pte)
		goto bad;
	/* Check for a huge/THP page */
	paddr = pmd_is_huge(pte, vaddr, verbose);
	if (paddr)
		goto out;
	kva = __va(pte);
	pte = fetch_page_table_level(kva, vaddr, PAGE_SHIFT,
				     PTRS_PER_PTE - 1, pte_text, verbose);
	if ((pte & _PAGE_VALID) == 0UL)
		goto bad;
	paddr = pte_to_pa(pte);
	paddr = paddr | (vaddr & ~PAGE_MASK);
out:
	return paddr;
bad:
	return not_valid_pte;
}

static void
sparc64_init_kernel_pgd(void)
{
	int cpu, rc;
	ulong v;

	v = symbol_value("init_mm");
	rc = readmem(v + OFFSET(mm_struct_pgd), KVADDR, &v, sizeof(v),
		"init_mm.pgd", RETURN_ON_ERROR);
	if (!rc) {
		error(WARNING, "Can not determine pgd location.\n");
		goto out;
	}

	for (cpu = 0; cpu < NR_CPUS; cpu++)
		vt->kernel_pgd[cpu] = v;
out:
	return;
}

static int
sparc64_get_smp_cpus(void)
{
	int ncpu = MAX(get_cpus_online(), get_highest_cpu_online() + 1);

	return ncpu;
}

static ulong
sparc64_vmalloc_start(void)
{
	return SPARC64_VMALLOC_START;
}

int
sparc64_IS_VMALLOC_ADDR(ulong vaddr)
{
	return (vaddr >= SPARC64_VMALLOC_START) &&
		(vaddr < machdep->machspec->vmalloc_end);
}

static void
pt_clear_cache(void)
{
	machdep->last_pgd_read = 0UL;
	machdep->last_pud_read = 0UL;
	machdep->last_pmd_read = 0UL;
	machdep->last_ptbl_read = 0UL;
}

static void
pt_level_alloc(char **lvl, char *name)
{
	size_t sz = PAGE_SIZE;
	void *pointer = malloc(sz);

	if (!pointer)
		error(FATAL, name);
	*lvl = pointer;
}

static int
sparc64_verify_symbol(const char *name, unsigned long value, char type)
{
	return TRUE;
}

static int
sparc64_verify_line_number(unsigned long pc, unsigned long low,
			   unsigned long high)
{
	return TRUE;
}

static int
sparc64_dis_filter(ulong vaddr, char *inbuf, unsigned int radix)
{
	return FALSE;
}

struct eframe {
	struct sparc_stackf sf;
	struct pt_regs pr;
};

/* Need to handle hardirq and softirq stacks. */
static int
kstack_valid(struct bt_info *bt, unsigned long sp)
{
	unsigned long thread_info = SIZE(thread_info);
	unsigned long base = bt->stackbase + thread_info;
	unsigned long top = bt->stacktop - sizeof(struct eframe);
	int rc = FALSE;

	if (sp & (16U - 1))
		goto out;

	if ((sp >= base) && (sp <= top))
		rc = TRUE;
out:
	return rc;
}

static void
sparc64_print_eframe(struct bt_info *bt)
{
	struct eframe k_entry;
	struct pt_regs *regs = &k_entry.pr;
	unsigned long efp;
	unsigned int tt;
	int rc;
	struct reg_window window;
	unsigned long rw;

	efp = bt->stkptr + STACK_BIAS - TRACEREG_SZ - STACKFRAME_SZ;
	if (!kstack_valid(bt, efp))
		goto try_stacktop;

	rc = readmem(efp, KVADDR, &k_entry, sizeof(k_entry),
		     "Stack frame and pt_regs.", RETURN_ON_ERROR);
	if (rc && ((regs->magic & ~MAGIC_TT_MASK) == PT_REGS_MAGIC))
		goto print_frame;

try_stacktop:
	efp = bt->stacktop - sizeof(struct eframe);
	rc = readmem(efp, KVADDR, &k_entry, sizeof(k_entry),
		"Stack frame and pt_regs.", RETURN_ON_ERROR);
	if (!rc)
		goto out;
	/* Kernel thread or not in kernel any longer? */
	if ((regs->magic & ~MAGIC_TT_MASK) != PT_REGS_MAGIC)
		goto out;

print_frame:
	tt = regs->magic & MAGIC_TT_MASK;
	fprintf(fp, "TSTATE=0x%lx TT=0x%x TPC=0x%lx TNPC=0x%lx\n",
		regs->tstate, tt, regs->tpc, regs->tnpc);
	fprintf(fp, " g0=0x%.16lx  g1=0x%.16lx  g2=0x%.16lx\n",
		regs->u_regs[0],
		regs->u_regs[1],
		regs->u_regs[2]);
	fprintf(fp, " g3=0x%.16lx  g4=0x%.16lx  g5=0x%.16lx\n",
		regs->u_regs[3],
		regs->u_regs[4],
		regs->u_regs[5]);
#define	___INS	(8)
	fprintf(fp, " g6=0x%.16lx  g7=0x%.16lx\n",
		regs->u_regs[6],
		regs->u_regs[7]);
	fprintf(fp, " o0=0x%.16lx  o1=0x%.16lx  o2=0x%.16lx\n",
		regs->u_regs[___INS+0],
		regs->u_regs[___INS+1],
		regs->u_regs[___INS+2]);
	fprintf(fp, " o3=0x%.16lx  o4=0x%.16lx  o5=0x%.16lx\n",
		regs->u_regs[___INS+3],
		regs->u_regs[___INS+4],
		regs->u_regs[___INS+5]);
	fprintf(fp, " sp=0x%.16lx  ret_pc=0x%.16lx\n",
		regs->u_regs[___INS+6],
		regs->u_regs[___INS+7]);
#undef	___INS
	rw = bt->stkptr + STACK_BIAS;
	if (!kstack_valid(bt, rw))
		goto out;
	rc = readmem(rw, KVADDR, &window, sizeof(window),
		     "Register window.", RETURN_ON_ERROR);
	if (!rc)
		goto out;
	fprintf(fp, " l0=0x%.16lx  l1=0x%.16lx  l2=0x%.16lx\n",
		window.locals[0], window.locals[1], window.locals[2]);
	fprintf(fp, " l3=0x%.16lx  l4=0x%.16lx  l5=0x%.16lx\n",
		window.locals[3], window.locals[4], window.locals[5]);
	fprintf(fp, " l6=0x%.16lx  l7=0x%.16lx\n",
		window.locals[6], window.locals[7]);
	fprintf(fp, " i0=0x%.16lx  i1=0x%.16lx  i2=0x%.16lx\n",
		window.ins[0], window.ins[1], window.ins[2]);
	fprintf(fp, " i3=0x%.16lx  i4=0x%.16lx  i5=0x%.16lx\n",
		window.ins[3], window.ins[4], window.ins[5]);
	fprintf(fp, " i6=0x%.16lx  i7=0x%.16lx\n",
		window.ins[6], window.ins[7]);
out:
	return;
}

static int
sparc64_eframe_search(struct bt_info *bt)
{
	sparc64_print_eframe(bt);
	return 0;
}

static void
sparc64_print_frame(struct bt_info *bt, int cnt, unsigned long ip,
		    unsigned long ksp)
{
	char *symbol = closest_symbol(ip);

	fprintf(fp, "#%d [%lx] %s at %lx\n", cnt, ksp, symbol, ip);

	if (bt->flags & BT_LINE_NUMBERS) {
		char buf[BUFSIZE];

		get_line_number(ip, buf, FALSE);
		if (strlen(buf))
			fprintf(fp, "\t%s\n", buf);
	}
}

static void
sparc64_back_trace(struct bt_info *bt)
{
	unsigned long ip = bt->instptr;
	unsigned long ksp = bt->stkptr;
	struct reg_window window;
	int cnt = 0;
	int rc;

	do {
		if (!kstack_valid(bt, ksp + STACK_BIAS))
			break;
		rc = readmem(ksp + STACK_BIAS, KVADDR, &window, sizeof(window),
			"KSP window fetch.", RETURN_ON_ERROR);
		if (!rc)
			goto out;
		sparc64_print_frame(bt, cnt, ip, ksp);
		ksp = window.ins[6];
		ip = window.ins[7];
		cnt++;
	} while (cnt != 50);
	sparc64_print_eframe(bt);
out:
	return;
}

static ulong
sparc64_processor_speed(void)
{
	int cpu;
	unsigned long clock_tick;
	struct syment *sp;

	if (!MEMBER_EXISTS("cpuinfo_sparc", "clock_tick")) {
		error(WARNING, "sparc64 expects clock_tick\n");
		return 0UL;
	}

	sp = per_cpu_symbol_search("__cpu_data");
	if (!sp)
		return 0UL;
	for (cpu = 0; cpu < kt->cpus; cpu++) {
		if (!in_cpu_map(ONLINE, cpu))
			continue;
		if (!readmem(sp->value + kt->__per_cpu_offset[cpu] +
			     MEMBER_OFFSET("cpuinfo_sparc", "clock_tick"),
			     KVADDR, &clock_tick, sizeof(clock_tick),
			     "clock_tick", QUIET|RETURN_ON_ERROR))
			continue;
		return clock_tick/1000000;
	}
	return 0UL;
}

static ulong
sparc64_get_task_pgd(ulong task)
{
	struct task_context *tc = task_to_context(task);
	ulong pgd = NO_TASK;

	if (!tc)
		goto out;
	readmem(tc->mm_struct + OFFSET(mm_struct_pgd), KVADDR,
		&pgd, sizeof(unsigned long), "User pgd.", RETURN_ON_ERROR);
out:
	return pgd;
}

static int
sparc64_uvtop(struct task_context *tc, ulong va, physaddr_t *ppaddr,
	      int verbose)
{
	unsigned long pgd = sparc64_get_task_pgd(tc->task);
	unsigned long paddr;
	int rc = FALSE;

	if (pgd == NO_TASK)
		goto out;
	paddr = sparc64_page_table_walk(pgd, va, verbose);
	/* For now not_valid_pte skips checking for swap pte. */
	if (paddr == not_valid_pte) {
		*ppaddr = 0UL;
		goto out;
	}
	*ppaddr = paddr;
	rc = TRUE;
out:
	return rc;
}

static unsigned long
sparc64_vmalloc_translate(unsigned long vaddr, int verbose)
{
	unsigned long paddr = sparc64_page_table_walk(vt->kernel_pgd[0],
							vaddr, verbose);

	return paddr;
}

static unsigned long
sparc64_linear_translate(unsigned long vaddr)
{
	unsigned long paddr = __pa(vaddr);

	if (sparc64_verify_paddr(paddr) == FALSE)
		error(FATAL,
			"sparc64_linear_translate: This physical address"
			" (0x%lx) is invalid.", paddr);

	return paddr;
}

static int
sparc64_is_vmalloc_mapped(unsigned long vaddr)
{
	struct machine_specific *ms = &sparc64_machine_specific;
	int rc = 0;

	if ((vaddr >= SPARC64_MODULES_VADDR && vaddr < SPARC64_MODULES_END) ||
		(vaddr >= SPARC64_VMALLOC_START && vaddr < ms->vmalloc_end))
		rc = 1;
	return rc;
}

static int
sparc64_is_kvaddr(ulong vaddr)
{
	return kimage_va_range(vaddr) ||
	       sparc64_is_linear_mapped(vaddr) ||
	       sparc64_is_vmalloc_mapped(vaddr);
}

static int
sparc64_kvtop(struct task_context *tc, ulong vaddr, physaddr_t *paddr,
	      int verbose)
{
	unsigned long phys_addr;
	int rc = FALSE;

	if (kimage_va_range(vaddr)) {
		phys_addr = kimage_va_translate(vaddr);
	} else if (sparc64_is_vmalloc_mapped(vaddr)) {
		phys_addr = sparc64_vmalloc_translate(vaddr, verbose);
		if (phys_addr == not_valid_pte)
			goto out;
	} else if (sparc64_is_linear_mapped(vaddr)) {
		phys_addr = sparc64_linear_translate(vaddr);
	} else {
		error(WARNING,
		"This is an invalid kernel virtual address=0x%lx.",
			vaddr);
		goto out;
	}

	*paddr = phys_addr;
	rc = TRUE;
out:
	return rc;
}

static int
sparc64_is_task_addr(ulong task)
{
	int rc = FALSE;
	int cpu;

	if (sparc64_is_linear_mapped(task) || kimage_va_range(task))
		rc = TRUE;
	else {
		for (cpu = 0; cpu < kt->cpus; cpu++)
			if (task == tt->idle_threads[cpu]) {
				rc = TRUE;
				break;
			}
	}
	return rc;
}

static int
sparc64_is_uvaddr(ulong vaddr, struct task_context *tc)
{
	return vaddr < SPARC64_USERSPACE_TOP;
}

static const char
*pte_page_size(unsigned long pte)
{
	static const char *_4Mb = "4Mb";
	static const char *_64Kb = "64Kb";
	static const char *_8Kb = "8Kb";
	static const char *_ns = "Not Supported";
	const char *result;

	switch (pte & _PAGE_SZALL_4V) {
	case _PAGE_SZ8K_4V:
		result = _8Kb;
		break;
	case _PAGE_SZ64K_4V:
		result = _64Kb;
		break;
	case _PAGE_SZ4MB_4V:
		result = _4Mb;
		break;
	default:
		result = _ns;
	}
	return result;
}

static int
sparc64_translate_pte(unsigned long pte, void *physaddr, ulonglong unused)
{
	unsigned long paddr = pte_to_pa(pte);
	int rc = FALSE;
	int cnt = 0;

	/* Once again not handling swap pte.*/
	if ((pte & _PAGE_VALID) == 0UL)
		goto out;
	if (pte & _PAGE_NFO_4V)
		fprintf(fp, "%sNoFaultOn", cnt++ ? "|" : "");
	if (pte & _PAGE_MODIFIED_4V)
		fprintf(fp, "%sModified", cnt++ ? "|" : "");
	if (pte & _PAGE_ACCESSED_4V)
		fprintf(fp, "%sAccessed", cnt++ ? "|" : "");
	if (pte & _PAGE_READ_4V)
		fprintf(fp, "%sReadSoftware", cnt++ ? "|" : "");
	if (pte & _PAGE_WRITE_4V)
		fprintf(fp, "%sWriteSoftware", cnt++ ? "|" : "");
	if (pte & _PAGE_P_4V)
		fprintf(fp, "%sPriv", cnt++ ? "|" : "");
	if (pte & _PAGE_EXEC_4V)
		fprintf(fp, "%sExecute", cnt++ ? "|" : "");
	if (pte & _PAGE_W_4V)
		fprintf(fp, "%sWritable", cnt++ ? "|" : "");
	if (pte & _PAGE_PRESENT_4V)
		fprintf(fp, "%sPresent", cnt++ ? "|" : "");
	fprintf(fp, "|PageSize(%s)\n", pte_page_size(pte));
	if (physaddr)
		*(unsigned long *)physaddr = paddr;
	rc = TRUE;
out:
	return rc;
}

static void
sparc64_get_frame(struct bt_info *bt, unsigned long *r14, unsigned long *r15)
{
	unsigned long ksp_offset = sparc64_ksp_offset + bt->tc->thread_info;
	unsigned long ksp;
	int rc;

	/* We need thread_info's ksp. This is the stack for sleeping threads
	 * and captured during switch_to. The rest is fetchable from there.
	 */
	rc = readmem(ksp_offset, KVADDR, &ksp, sizeof(ksp), "KSP Fetch.",
		RETURN_ON_ERROR);
	if (!rc)
		goto out;
	*r14 = ksp;
	*r15 = symbol_value("switch_to_pc");
out:
	return;
}

static void
sparc64_get_dumpfile_stack_frame(struct bt_info *bt, unsigned long *psp,
				 unsigned long *ppc)
{
	unsigned long *pt_regs;

	pt_regs = (unsigned long *)bt->machdep;

	if (!pt_regs)
		fprintf(fp, "0%lx: registers not saved\n", bt->task);

	/* pt_regs can be unaligned */
	BCOPY(&pt_regs[30], psp, sizeof(ulong));
	BCOPY(&pt_regs[33], ppc, sizeof(ulong));
}

static void
sparc64_get_stack_frame(struct bt_info *bt, unsigned long *pcp,
			unsigned long *psp)
{
	unsigned long r14, r15;

	if (DUMPFILE() && is_task_active(bt->task))
		sparc64_get_dumpfile_stack_frame(bt, &r14, &r15);
	else
		sparc64_get_frame(bt, &r14, &r15);
	if (pcp)
		*pcp = r15;
	if (psp)
		*psp = r14;
}

static int
sparc64_get_kvaddr_ranges(struct vaddr_range *vrp)
{
	struct machine_specific *ms = &sparc64_machine_specific;

	vrp[0].type = KVADDR_UNITY_MAP;
	vrp[0].start = ms->page_offset;
	vrp[0].end = ~0ULL;
	vrp[1].type = KVADDR_VMALLOC;
	vrp[1].start = SPARC64_VMALLOC_START;
	vrp[1].end = ms->vmalloc_end;
	vrp[2].type = KVADDR_START_MAP;
	vrp[2].start = symbol_value("_start");
	vrp[2].end = symbol_value("_end");
	vrp[3].type = KVADDR_MODULES;
	vrp[3].start = SPARC64_MODULES_VADDR;
	vrp[3].end = SPARC64_MODULES_END;
	return 4;
}

static void
sparc64_get_crash_notes(void)
{
	unsigned long *notes_ptrs, size, crash_notes_address;
	int ret;

	if (!symbol_exists("crash_notes")) {
		error(WARNING, "Could not retrieve crash_notes.");
		goto out;
	}

	crash_notes_address = symbol_value("crash_notes");
	size = kt->cpus * sizeof(notes_ptrs[0]);
	notes_ptrs = (unsigned long *) GETBUF(size);
	ret = readmem(crash_notes_address, KVADDR, notes_ptrs, size,
		"crash_notes", RETURN_ON_ERROR);
	if (!ret)
		goto out2;
out2:
	FREEBUF(notes_ptrs);
out:
	return;
}

static void
sparc64_init_kstack_info(void)
{
	sparc64_ksp_offset = MEMBER_OFFSET("thread_info", "ksp");
}

static void
sparc64_init_irq_stacks(void)
{
	void *irq_stack;
	unsigned long stack_size;

	stack_size = get_array_length("hardirq_stack", NULL, 0) *
		     sizeof(unsigned long);
	irq_stack = malloc(stack_size);
	if (!irq_stack)
		error(FATAL, "malloc failure in sparc64_init_irq_stacks");

	get_symbol_data("hardirq_stack", stack_size, irq_stack);
	tt->hardirq_ctx = irq_stack;

	stack_size = get_array_length("softirq_stack", NULL, 0) *
		     sizeof(unsigned long);
	irq_stack = malloc(stack_size);
	if (!irq_stack)
		error(FATAL, "malloc failure in sparc64_init_irq_stacks");

	get_symbol_data("softirq_stack", stack_size, irq_stack);
	tt->softirq_ctx = irq_stack;
}

static void
sparc64_init_vmemmap_info(void)
{
	struct machine_specific *ms = &sparc64_machine_specific;
	unsigned long page_struct_size = STRUCT_SIZE("page");

	/*
	 * vmemmap memory is addressed as vmalloc memory, so we
	 * treat it as an etension of the latter.
	 */
	ms->vmalloc_end +=
		((1UL << (machdep->max_physmem_bits - PAGE_SHIFT)) *
		 page_struct_size);
}

static void
sparc64_init_cpu_info(void)
{
	unsigned long trap_block, per_cpu_base_offset, per_cpu_base;
	unsigned long trap_per_cpu;
	int cpu;

	if (!symbol_exists("trap_block"))
		error(FATAL, "sparc64 requires trap_block symbol.\n");

	trap_block = symbol_value("trap_block");
	if (!MEMBER_EXISTS("trap_per_cpu", "__per_cpu_base"))
		error(FATAL, "sparc64 requires __per_cpu_base.\n");
	trap_per_cpu = STRUCT_SIZE("trap_per_cpu");
	per_cpu_base_offset = MEMBER_OFFSET("trap_per_cpu", "__per_cpu_base");
	for (cpu = 0; cpu < NR_CPUS; cpu++,
		trap_block = trap_block + trap_per_cpu) {

		if (!in_cpu_map(POSSIBLE, cpu))
			continue;
		readmem(trap_block + per_cpu_base_offset, KVADDR,
			&per_cpu_base, sizeof(per_cpu_base),
			"sparc64: per_cpu_base", FAULT_ON_ERROR);
		kt->__per_cpu_offset[cpu] = per_cpu_base;
	}
}

void
sparc64_init(int when)
{
	struct machine_specific *ms = &sparc64_machine_specific;

	switch (when) {
	case SETUP_ENV:
		machdep->process_elf_notes = process_elf64_notes;
		break;
	case PRE_SYMTAB:
		machdep->machspec = ms;
		machdep->verify_paddr = sparc64_verify_paddr;
		machdep->verify_symbol = sparc64_verify_symbol;
		machdep->verify_line_number = sparc64_verify_line_number;

		if (pc->flags & KERNEL_DEBUG_QUERY)
			return;
		machdep->flags |= MACHDEP_BT_TEXT;
		if (machdep->cmdline_args[0])
			sparc64_parse_cmdline_args();
		break;

	case PRE_GDB:
		machdep->max_physmem_bits = _MAX_PHYSMEM_BITS;

		machdep->pagesize = memory_page_size();
		machdep->pageshift = ffs(machdep->pagesize) - 1;
		machdep->pageoffset = machdep->pagesize - 1;
		machdep->pagemask = ~((ulonglong) machdep->pageoffset);
		machdep->stacksize = machdep->pagesize * 2;

		machdep->eframe_search = sparc64_eframe_search;
		machdep->back_trace = sparc64_back_trace;
		machdep->processor_speed = sparc64_processor_speed;

		machdep->uvtop = sparc64_uvtop;
		machdep->kvtop = sparc64_kvtop;
		machdep->get_task_pgd = sparc64_get_task_pgd;

		machdep->dump_irq = generic_dump_irq;

		machdep->get_stack_frame = sparc64_get_stack_frame;
		machdep->get_stackbase = generic_get_stackbase;
		machdep->get_stacktop = generic_get_stacktop;
		machdep->translate_pte = sparc64_translate_pte;
		machdep->memory_size = generic_memory_size;

		machdep->vmalloc_start = sparc64_vmalloc_start;
		machdep->is_task_addr = sparc64_is_task_addr;
		machdep->is_kvaddr = sparc64_is_kvaddr;
		machdep->is_uvaddr = sparc64_is_uvaddr;
		machdep->dis_filter = sparc64_dis_filter;
		machdep->get_smp_cpus = sparc64_get_smp_cpus;
		machdep->clear_machdep_cache = sparc64_clear_machdep_cache;
		machdep->get_kvaddr_ranges = sparc64_get_kvaddr_ranges;
		machdep->cmd_mach = sparc64_cmd_mach;
		machdep->init_kernel_pgd = sparc64_init_kernel_pgd;
		machdep->value_to_symbol = generic_machdep_value_to_symbol;
		machdep->get_irq_affinity = generic_get_irq_affinity;
		machdep->show_interrupts = generic_show_interrupts;

		pt_level_alloc(&machdep->pgd, "Can't malloc pgd space.");
		pt_level_alloc(&machdep->pud, "Can't malloc pud space.");
		pt_level_alloc(&machdep->pmd, "Can't malloc pmd space.");
		pt_level_alloc(&machdep->ptbl, "Can't malloc ptbl space.");
		pt_clear_cache();
		sparc64_phys_base();
		sparc64_kimage_limits();
		break;

	case POST_GDB:
		get_symbol_data("PAGE_OFFSET", sizeof(unsigned long),
				&ms->page_offset);
		machdep->kvbase = symbol_value("_stext");
		machdep->identity_map_base = (ulong) PAGE_OFFSET;
		machdep->ptrs_per_pgd = PTRS_PER_PGD;
		get_symbol_data("VMALLOC_END", sizeof(unsigned long),
				&ms->vmalloc_end);
		machdep->section_size_bits = _SECTION_SIZE_BITS;
		if (kernel_symbol_exists("nr_irqs"))
			get_symbol_data("nr_irqs", sizeof(unsigned int),
			&machdep->nr_irqs);
		sparc64_init_vmemmap_info();
		sparc64_init_cpu_info();
		sparc64_init_kstack_info();
		sparc64_init_irq_stacks();
		break;
	case POST_VM:
		if (!ACTIVE())
			sparc64_get_crash_notes();
		break;
	case POST_INIT:
		break;

	case LOG_ONLY:
		machdep->machspec = ms;
		machdep->kvbase = kt->vmcoreinfo._stext_SYMBOL;
		break;
	}
}

void
sparc64_dump_machdep_table(ulong arg)
{
	int i, others;

	others = 0;
	fprintf(fp, "              flags: %lx (", machdep->flags);
	if (machdep->flags & MACHDEP_BT_TEXT)
		fprintf(fp, "%sMACHDEP_BT_TEXT", others++ ? "|" : "");
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
	fprintf(fp, "      eframe_search: sparc64_eframe_search()\n");
	fprintf(fp, "         back_trace: sparc64_back_trace()\n");
	fprintf(fp, "    processor_speed: sparc64_processor_speed()\n");
	fprintf(fp, "              uvtop: sparc64_uvtop()\n");
	fprintf(fp, "              kvtop: sparc64_kvtop()\n");
	fprintf(fp, "       get_task_pgd: sparc64_get_task_pgd()\n");
	fprintf(fp, "           dump_irq: generic_dump_irq()\n");
	fprintf(fp, "    get_stack_frame: sparc64_get_stack_frame()\n");
	fprintf(fp, "      get_stackbase: generic_get_stackbase()\n");
	fprintf(fp, "       get_stacktop: generic_get_stacktop()\n");
	fprintf(fp, "      translate_pte: sparc64_translate_pte()\n");
	fprintf(fp, "        memory_size: generic_memory_size()\n");
	fprintf(fp, "      vmalloc_start: sparc64_vmalloc_start()\n");
	fprintf(fp, "       is_task_addr: sparc64_is_task_addr()\n");
	fprintf(fp, "      verify_symbol: sparc64_verify_symbol()\n");
	fprintf(fp, "         dis_filter: sparc64_dis_filter()\n");
	fprintf(fp, "           cmd_mach: sparc64_cmd_mach()\n");
	fprintf(fp, "       get_smp_cpus: sparc64_get_smp_cpus()\n");
	fprintf(fp, "          is_kvaddr: sparc64_is_kvaddr()\n");
	fprintf(fp, "          is_uvaddr: sparc64_is_uvaddr()\n");
	fprintf(fp, "       verify_paddr: sparc64_verify_paddr()\n");
	fprintf(fp, "  get_kvaddr_ranges: sparc64_get_kvaddr_ranges()\n");
	fprintf(fp, "   get_irq_affinity: generic_get_irq_affinity()\n");
	fprintf(fp, "    show_interrupts: generic_show_interrupts()\n");
	fprintf(fp, " xendump_p2m_create: NULL\n");
	fprintf(fp, "xen_kdump_p2m_create: NULL\n");
	fprintf(fp, "  line_number_hooks: NULL\n");
	fprintf(fp, "      last_pgd_read: %lx\n", machdep->last_pgd_read);
	fprintf(fp, "      last_pmd_read: %lx\n", machdep->last_pmd_read);
	fprintf(fp, "     last_ptbl_read: %lx\n", machdep->last_ptbl_read);
	fprintf(fp, "clear_machdep_cache: sparc64_clear_machdep_cache()\n");
	fprintf(fp, "                pgd: %lx\n", (ulong)machdep->pgd);
	fprintf(fp, "                pmd: %lx\n", (ulong)machdep->pmd);
	fprintf(fp, "               ptbl: %lx\n", (ulong)machdep->ptbl);
	fprintf(fp, "       ptrs_per_pgd: %d\n", machdep->ptrs_per_pgd);
	fprintf(fp, "  section_size_bits: %ld\n", machdep->section_size_bits);
	fprintf(fp, "   max_physmem_bits: %ld\n", machdep->max_physmem_bits);
	fprintf(fp, "  sections_per_root: %ld\n", machdep->sections_per_root);
	for (i = 0; i < MAX_MACHDEP_ARGS; i++) {
		fprintf(fp, "    cmdline_args[%d]: %s\n", i,
			machdep->cmdline_args[i] ?
			machdep->cmdline_args[i] : "(unused)");
	}
	fprintf(fp, "           machspec: %lx\n", (ulong)machdep->machspec);
	fprintf(fp, "          page_offset: %lx\n",
		machdep->machspec->page_offset);
	fprintf(fp, "          vmalloc_end: %lx\n",
		machdep->machspec->vmalloc_end);
}

#endif /* SPARC64 */
