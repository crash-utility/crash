/* riscv64.c - core analysis suite
 *
 * Copyright (C) 2022 Alibaba Group Holding Limited.
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
#include "defs.h"
#ifdef RISCV64

#include <elf.h>
#include <math.h>

static ulong riscv64_get_page_size(void);
static int riscv64_vtop_3level_4k(ulong *pgd, ulong vaddr,
				   physaddr_t *paddr, int verbose);
static int riscv64_vtop_4level_4k(ulong *pgd, ulong vaddr,
				   physaddr_t *paddr, int verbose);
static int riscv64_vtop_5level_4k(ulong *pgd, ulong vaddr,
				   physaddr_t *paddr, int verbose);
static void riscv64_page_type_init(void);
static int riscv64_is_kvaddr(ulong vaddr);
static int riscv64_is_uvaddr(ulong vaddr, struct task_context *tc);
static int riscv64_uvtop(struct task_context *tc, ulong vaddr,
			  physaddr_t *paddr, int verbose);
static int riscv64_kvtop(struct task_context *tc, ulong kvaddr,
			  physaddr_t *paddr, int verbose);
static void riscv64_cmd_mach(void);
static void riscv64_irq_stack_init(void);
static void riscv64_overflow_stack_init(void);
static void riscv64_stackframe_init(void);
static void riscv64_back_trace_cmd(struct bt_info *bt);
static int riscv64_eframe_search(struct bt_info *bt);
static int riscv64_get_dumpfile_stack_frame(struct bt_info *bt,
					     ulong *nip, ulong *ksp);
static void riscv64_get_stack_frame(struct bt_info *bt, ulong *pcp,
				     ulong *spp);
static int riscv64_get_frame(struct bt_info *bt, ulong *pcp,
			      ulong *spp);
static void riscv64_display_full_frame(struct bt_info *bt,
				        struct riscv64_unwind_frame *current,
				        struct riscv64_unwind_frame *previous);
static int riscv64_translate_pte(ulong, void *, ulonglong);
static int riscv64_init_active_task_regs(void);
static int riscv64_get_crash_notes(void);
static int riscv64_get_elf_notes(void);
static void riscv64_get_va_range(struct machine_specific *ms);
static void riscv64_get_va_bits(struct machine_specific *ms);
static void riscv64_get_struct_page_size(struct machine_specific *ms);
static void riscv64_print_exception_frame(struct bt_info *, ulong , int );
static int riscv64_is_kernel_exception_frame(struct bt_info *, ulong );
static int riscv64_on_irq_stack(int , ulong);
static int riscv64_on_process_stack(struct bt_info *, ulong );
static void riscv64_set_process_stack(struct bt_info *);
static void riscv64_set_irq_stack(struct bt_info *);
static int riscv64_on_overflow_stack(int, ulong);
static void riscv64_set_overflow_stack(struct bt_info *);

#define REG_FMT 	"%016lx"
#define SZ_2G		0x80000000
#define USER_MODE	(0)
#define KERNEL_MODE	(1)

/*
 * Holds registers during the crash.
 */
static struct riscv64_register *panic_task_regs;

/* from arch/riscv/include/asm/stacktrace.h */
struct stackframe {
	ulong fp;
	ulong ra;
};

static struct machine_specific riscv64_machine_specific = {
	._page_present = (1 << 0),
	._page_read = (1 << 1),
	._page_write = (1 << 2),
	._page_exec = (1 << 3),
	._page_user = (1 << 4),
	._page_global = (1 << 5),
	._page_accessed = (1 << 6),
	._page_dirty = (1 << 7),
	._page_soft = (1 << 8),

	.va_bits = 0,
	.struct_page_size = 0,
};

static void
pt_level_alloc(char **lvl, char *name)
{
	size_t sz = PAGESIZE();
	void *pointer = malloc(sz);

	if (!pointer)
		error(FATAL, name);
	*lvl = pointer;
}

static ulong
riscv64_get_page_size(void)
{
	return memory_page_size();
}

static ulong
riscv64_vmalloc_start(void)
{
	return ((ulong)VMALLOC_START);
}

/* Get the size of struct page {} */
static void riscv64_get_struct_page_size(struct machine_specific *ms)
{
	char *string;

	string = pc->read_vmcoreinfo("SIZE(page)");
	if (string) {
		ms->struct_page_size = atol(string);
		free(string);
	}
}

/*
 * "mach" command output.
 */
static void
riscv64_display_machine_stats(void)
{
	struct new_utsname *uts;
	char buf[BUFSIZE];
	ulong mhz;

	uts = &kt->utsname;

	fprintf(fp, "		MACHINE TYPE: %s\n", uts->machine);
	fprintf(fp, "		 MEMORY SIZE: %s\n", get_memory_size(buf));
	fprintf(fp, "			CPUS: %d\n", get_cpus_to_display());
	fprintf(fp, "	     PROCESSOR SPEED: ");
	if ((mhz = machdep->processor_speed()))
		fprintf(fp, "%ld Mhz\n", mhz);
	else
		fprintf(fp, "(unknown)\n");
	fprintf(fp, "			  HZ: %d\n", machdep->hz);
	fprintf(fp, "		   PAGE SIZE: %d\n", PAGESIZE());
	fprintf(fp, "	   KERNEL STACK SIZE: %ld\n", STACKSIZE());
}

static void
riscv64_cmd_mach(void)
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

	riscv64_display_machine_stats();
}

/*
 * Accept or reject a symbol from the kernel namelist.
 */
static int
riscv64_verify_symbol(const char *name, ulong value, char type)
{
	if (CRASHDEBUG(8) && name && strlen(name))
		fprintf(fp, "%08lx %s\n", value, name);

	if (!(machdep->flags & KSYMS_START)) {
		if (STREQ(name, "_text") || STREQ(name, "_stext"))
			machdep->flags |= KSYMS_START;

		return (name && strlen(name) && !STRNEQ(name, "__func__.") &&
			!STRNEQ(name, "__crc_"));
	}

	return TRUE;
}

void
riscv64_dump_machdep_table(ulong arg)
{
	const struct machine_specific *ms = machdep->machspec;
	int others = 0, i = 0;

	fprintf(fp, "              flags: %lx (", machdep->flags);
	if (machdep->flags & KSYMS_START)
		fprintf(fp, "%sKSYMS_START", others++ ? "|" : "");
	if (machdep->flags & IRQ_STACKS)
		fprintf(fp, "%sIRQ_STACKS", others++ ? "|" : "");
	if (machdep->flags & OVERFLOW_STACKS)
		fprintf(fp, "%sOVERFLOW_STACKS", others++ ? "|" : "");
	fprintf(fp, ")\n");

	fprintf(fp, "             kvbase: %lx\n", machdep->kvbase);
	fprintf(fp, "  identity_map_base: %lx\n", machdep->identity_map_base);
	fprintf(fp, "           pagesize: %d\n", machdep->pagesize);
	fprintf(fp, "          pageshift: %d\n", machdep->pageshift);
	fprintf(fp, "           pagemask: %llx\n", machdep->pagemask);
	fprintf(fp, "         pageoffset: %lx\n", machdep->pageoffset);
	fprintf(fp, "        pgdir_shift: %ld\n", machdep->machspec->va_bits - 9);
	fprintf(fp, "       ptrs_per_pgd: %u\n", PTRS_PER_PGD);
	fprintf(fp, "       ptrs_per_pte: %d\n", PTRS_PER_PTE);
	fprintf(fp, "          stacksize: %ld\n", machdep->stacksize);
	fprintf(fp, "                 hz: %d\n", machdep->hz);
	fprintf(fp, "            memsize: %ld (0x%lx)\n",
		machdep->memsize, machdep->memsize);
	fprintf(fp, "               bits: %d\n", machdep->bits);
	fprintf(fp, "         back_trace: riscv64_back_trace_cmd()\n");
	fprintf(fp, "      eframe_search: riscv64_eframe_search()\n");
	fprintf(fp, "    processor_speed: riscv64_processor_speed()\n");
	fprintf(fp, "              uvtop: riscv64_uvtop()\n");
	fprintf(fp, "              kvtop: riscv64_kvtop()\n");
	fprintf(fp, "    get_stack_frame: riscv64_get_stack_frame()\n");
	fprintf(fp, "      get_stackbase: generic_get_stackbase()\n");
	fprintf(fp, "       get_stacktop: generic_get_stacktop()\n");
	fprintf(fp, "      translate_pte: riscv64_translate_pte()\n");
	fprintf(fp, "        memory_size: generic_memory_size()\n");
	fprintf(fp, "      vmalloc_start: riscv64_vmalloc_start()\n");
	fprintf(fp, "       is_task_addr: riscv64_is_task_addr()\n");
	fprintf(fp, "      verify_symbol: riscv64_verify_symbol()\n");
	fprintf(fp, "         dis_filter: generic_dis_filter()\n");
	fprintf(fp, "           dump_irq: generic_dump_irq()\n");
	fprintf(fp, "    show_interrupts: generic_show_interrupts()\n");
	fprintf(fp, "   get_irq_affinity: generic_get_irq_affinity()\n");
	fprintf(fp, "           cmd_mach: riscv64_cmd_mach()\n");
	fprintf(fp, "       get_smp_cpus: riscv64_get_smp_cpus()\n");
	fprintf(fp, "          is_kvaddr: riscv64_is_kvaddr()\n");
	fprintf(fp, "          is_uvaddr: riscv64_is_uvaddr()\n");
	fprintf(fp, "       verify_paddr: generic_verify_paddr()\n");
	fprintf(fp, "    init_kernel_pgd: NULL\n");
	fprintf(fp, "    value_to_symbol: generic_machdep_value_to_symbol()\n");
	fprintf(fp, "  line_number_hooks: NULL\n");
	fprintf(fp, "      last_pgd_read: %lx\n", machdep->last_pgd_read);
	fprintf(fp, "      last_p4d_read: %lx\n", machdep->machspec->last_p4d_read);
	fprintf(fp, "      last_pud_read: %lx\n", machdep->last_pud_read);
	fprintf(fp, "      last_pmd_read: %lx\n", machdep->last_pmd_read);
	fprintf(fp, "     last_ptbl_read: %lx\n", machdep->last_ptbl_read);
	fprintf(fp, "                pgd: %lx\n", (ulong)machdep->pgd);
	fprintf(fp, "                p4d: %lx\n", (ulong)machdep->machspec->p4d);
	fprintf(fp, "                pud: %lx\n", (ulong)machdep->pud);
	fprintf(fp, "                pmd: %lx\n", (ulong)machdep->pmd);
	fprintf(fp, "               ptbl: %lx\n", (ulong)machdep->ptbl);
	fprintf(fp, "  section_size_bits: %ld\n", machdep->section_size_bits);
	fprintf(fp, "   max_physmem_bits: %ld\n", machdep->max_physmem_bits);
	fprintf(fp, "  sections_per_root: %ld\n", machdep->sections_per_root);
	fprintf(fp, "           machspec: %lx\n", (ulong)machdep->machspec);
	if (machdep->flags & IRQ_STACKS) {
		fprintf(fp, "        irq_stack_size: %ld\n", ms->irq_stack_size);
		for (i = 0; i < kt->cpus; i++)
			fprintf(fp, "         irq_stacks[%d]: %lx\n",
				i, ms->irq_stacks[i]);
	} else {
		fprintf(fp, "        irq_stack_size: (unused)\n");
		fprintf(fp, "            irq_stacks: (unused)\n");
	}
	if (machdep->flags & OVERFLOW_STACKS) {
		fprintf(fp, "        overflow_stack_size: %ld\n", ms->overflow_stack_size);
		for (i = 0; i < kt->cpus; i++)
			fprintf(fp, "         overflow_stacks[%d]: %lx\n",
				i, ms->overflow_stacks[i]);
	} else {
		fprintf(fp, "        overflow_stack_size: (unused)\n");
		fprintf(fp, "            overflow_stacks: (unused)\n");
	}
}

static ulong
riscv64_processor_speed(void)
{
	/* TODO: */
	return 0;
}

static unsigned long riscv64_get_kernel_version(void)
{
	char *string;

	if (THIS_KERNEL_VERSION)
		return THIS_KERNEL_VERSION;

	if ((string = pc->read_vmcoreinfo("OSRELEASE"))) {
		parse_kernel_version(string);
		free(string);
	}
	return THIS_KERNEL_VERSION;
}

static void
riscv64_get_phys_ram_base(struct machine_specific *ms)
{
	unsigned long kernel_version = riscv64_get_kernel_version();

	/*
	 * phys_ram_base is defined in Linux kernel since 5.14.
	 */
	if (kernel_version >= LINUX(5,14,0)) {
		char *string;
		if ((string = pc->read_vmcoreinfo("NUMBER(phys_ram_base)"))) {
			ms->phys_base = atol(string);
			free(string);
		} else
			error(FATAL, "cannot read phys_ram_base\n");
	} else
		/*
		 * For qemu rv64 env and hardware platform, default phys base
		 * may different, eg,
		 *	hardware platform: 0x200000
		 *	qemu   rv64   env: 0x80200000
		 *
		 * But we only can set one default value, in this case, qemu
		 * rv64 env may can't work.
		 */
		ms->phys_base = 0x200000;
}

static void riscv64_get_va_bits(struct machine_specific *ms)
{
	unsigned long kernel_version = riscv64_get_kernel_version();

	/*
	 * VA_BITS is defined in Linux kernel since 5.17. So we use the
	 * default va bits 39 when Linux version < 5.17.
	 */
	if (kernel_version >= LINUX(5,17,0)) {
		char *string;
		if ((string = pc->read_vmcoreinfo("NUMBER(VA_BITS)"))) {
			ms->va_bits = atol(string);
			free(string);
		}
	} else
		ms->va_bits = 39;
}

static void riscv64_get_va_range(struct machine_specific *ms)
{
	unsigned long kernel_version = riscv64_get_kernel_version();
	char *string;

	if ((string = pc->read_vmcoreinfo("NUMBER(PAGE_OFFSET)"))) {
		ms->page_offset = htol(string, QUIET, NULL);
		free(string);
	} else
		goto error;

	if ((string = pc->read_vmcoreinfo("NUMBER(VMALLOC_START)"))) {
		ms->vmalloc_start_addr = htol(string, QUIET, NULL);
		free(string);
	} else
		goto error;

	if ((string = pc->read_vmcoreinfo("NUMBER(VMALLOC_END)"))) {
		ms->vmalloc_end = htol(string, QUIET, NULL);
                free(string);
	} else
		goto error;

	if ((string = pc->read_vmcoreinfo("NUMBER(VMEMMAP_START)"))) {
		ms->vmemmap_vaddr = htol(string, QUIET, NULL);
		free(string);
	} else
		goto error;

	if ((string = pc->read_vmcoreinfo("NUMBER(VMEMMAP_END)"))) {
		ms->vmemmap_end = htol(string, QUIET, NULL);
		free(string);
	} else
		goto error;

	if ((string = pc->read_vmcoreinfo("NUMBER(KERNEL_LINK_ADDR)"))) {
		ms->kernel_link_addr = htol(string, QUIET, NULL);
		free(string);
	} else
		goto error;

	if ((kt->flags2 & KASLR) && (kt->flags & RELOC_SET))
		ms->kernel_link_addr += (kt->relocate * -1);

	/*
	 * From Linux 5.13, the kernel mapping is moved to the last 2GB
	 * of the address space, modules use the 2GB memory range right
	 * before the kernel. Before Linux 5.13, modules area is embedded
	 * in vmalloc area.
	 *
	 */
	if (kernel_version >= LINUX(5,13,0)) {
		if ((string = pc->read_vmcoreinfo("NUMBER(MODULES_VADDR)"))) {
			ms->modules_vaddr = htol(string, QUIET, NULL);
			free(string);
		} else
			goto error;

		if ((string = pc->read_vmcoreinfo("NUMBER(MODULES_END)"))) {
			ms->modules_end = htol(string, QUIET, NULL);
			free(string);
		} else
			goto error;
	} else {
		ms->modules_vaddr = ms->vmalloc_start_addr;
		ms->modules_end = ms->vmalloc_end;
	}

	if (CRASHDEBUG(1)) {
		fprintf(fp, "vmemmap	: 0x%lx - 0x%lx\n",
			ms->vmemmap_vaddr, ms->vmemmap_end);
		fprintf(fp, "vmalloc	: 0x%lx - 0x%lx\n",
			ms->vmalloc_start_addr, ms->vmalloc_end);
		fprintf(fp, "mudules	: 0x%lx - 0x%lx\n",
			ms->modules_vaddr, ms->modules_end);
		fprintf(fp, "lowmem	: 0x%lx -\n", ms->page_offset);
		fprintf(fp, "kernel link addr	: 0x%lx\n",
			ms->kernel_link_addr);
	}
	return;
error:
	error(FATAL, "cannot get vm layout\n");
}

static void
riscv64_get_va_kernel_pa_offset(struct machine_specific *ms)
{
	unsigned long kernel_version = riscv64_get_kernel_version();

	/*
	 * Since Linux v6.4 phys_base is not the physical start of the kernel,
	 * trying to use "va_kernel_pa_offset" to determine the offset between
	 * kernel virtual and physical addresses.
	 */
	if (kernel_version >= LINUX(6,4,0)) {
		char *string;
		if ((string = pc->read_vmcoreinfo("NUMBER(va_kernel_pa_offset)"))) {
			ms->va_kernel_pa_offset = htol(string, QUIET, NULL);
			free(string);
		} else
			error(FATAL, "cannot read va_kernel_pa_offset\n");
	}
	else
		ms->va_kernel_pa_offset = ms->kernel_link_addr - ms->phys_base;
}

static int
riscv64_is_kvaddr(ulong vaddr)
{
	if (IS_VMALLOC_ADDR(vaddr))
		return TRUE;

	return (vaddr >= machdep->kvbase);
}

static int
riscv64_is_uvaddr(ulong vaddr, struct task_context *unused)
{
	if (IS_VMALLOC_ADDR(vaddr))
		return FALSE;

	return (vaddr < machdep->kvbase);
}

static int
riscv64_is_task_addr(ulong task)
{
	if (tt->flags & THREAD_INFO)
		return IS_KVADDR(task);

	return (IS_KVADDR(task) && ALIGNED_STACK_OFFSET(task) == 0);
}

static int
riscv64_get_smp_cpus(void)
{
	return (get_cpus_present() > 0) ? get_cpus_present() : kt->cpus;
}

/*
 *  Include both vmalloc'd and module address space as VMALLOC space.
 */
int
riscv64_IS_VMALLOC_ADDR(ulong vaddr)
{
	return ((vaddr >= VMALLOC_START && vaddr <= VMALLOC_END) ||
		(vaddr >= VMEMMAP_VADDR && vaddr <= VMEMMAP_END) ||
		(vaddr >= MODULES_VADDR && vaddr <= MODULES_END));
}

/*
 * Translate a PTE, returning TRUE if the page is present.
 * If a physaddr pointer is passed in, don't print anything.
 */
static int
riscv64_translate_pte(ulong pte, void *physaddr, ulonglong unused)
{
	char ptebuf[BUFSIZE];
	char physbuf[BUFSIZE];
	char buf[BUFSIZE];
	int page_present;
	int len1, len2, others;
	ulong paddr;

	paddr = PTOB(pte >> _PAGE_PFN_SHIFT);
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
		CHECK_PAGE_FLAG(READ);
		CHECK_PAGE_FLAG(WRITE);
		CHECK_PAGE_FLAG(EXEC);
		CHECK_PAGE_FLAG(USER);
		CHECK_PAGE_FLAG(GLOBAL);
		CHECK_PAGE_FLAG(ACCESSED);
		CHECK_PAGE_FLAG(DIRTY);
		CHECK_PAGE_FLAG(SOFT);
	} else {
		fprintf(fp, "no mapping");
	}

	fprintf(fp, ")\n");

	return page_present;
}

static void
riscv64_page_type_init(void)
{
	ulong va_bits = machdep->machspec->va_bits;

	/*
	 * For RISCV64 arch, any level of PTE may be a leaf PTE,
	 * so in addition to 4KiB pages,
	 * Sv39 supports 2 MiB megapages, 1 GiB gigapages;
	 * Sv48 supports 2 MiB megapages, 1 GiB gigapages, 512 GiB terapages;
	 * Sv57 supports 2 MiB megapages, 1 GiB gigapages, 512 GiB terapages, and 256 TiB petapages.
	 *
	 * refs to riscv-privileged spec.
	 *
	 * We just support 4KiB, 2MiB, 1GiB now.
	 */
	switch (machdep->pagesize)
	{
	case 0x1000:		// 4 KiB
		machdep->flags |= (va_bits == 57 ? VM_L5_4K :
				  (va_bits == 48 ? VM_L4_4K : VM_L3_4K));
		break;
	case 0x200000:		// 2 MiB
		/* TODO: */
	case 0x40000000: 	// 1 GiB
		/* TODO: */
	default:
		if (machdep->pagesize)
			error(FATAL, "invalid/unsupported page size: %d\n",
			      machdep->pagesize);
		else
			error(FATAL, "cannot determine page size\n");
	}
}

static int
riscv64_vtop_3level_4k(ulong *pgd, ulong vaddr, physaddr_t *paddr, int verbose)
{
	ulong *pgd_ptr, pgd_val;
	ulong pmd_val;
	ulong pte_val, pte_pfn;
	ulong pt_phys;

	/* PGD */
	pgd_ptr = pgd + pgd_index_l3_4k(vaddr);
	FILL_PGD(pgd, KVADDR, PAGESIZE());
	pgd_val = ULONG(machdep->pgd + PAGEOFFSET(pgd_ptr));
	if (verbose)
		fprintf(fp, "  PGD: %lx => %lx\n", (ulong)pgd_ptr, pgd_val);
	if (!pgd_val)
		goto no_page;
	pgd_val &= PTE_PFN_PROT_MASK;
	pt_phys = (pgd_val >> _PAGE_PFN_SHIFT) << PAGESHIFT();

	/* PMD */
	FILL_PMD(PAGEBASE(pt_phys), PHYSADDR, PAGESIZE());
	pmd_val = ULONG(machdep->pmd + PAGEOFFSET(sizeof(pmd_t) *
			pmd_index_l3_4k(vaddr)));
	if (verbose)
		fprintf(fp, "  PMD: %016lx => %016lx\n", pt_phys, pmd_val);
	if (!pmd_val)
		goto no_page;
	pmd_val &= PTE_PFN_PROT_MASK;
	pt_phys = (pmd_val >> _PAGE_PFN_SHIFT) << PAGESHIFT();

	/* PTE */
	FILL_PTBL(PAGEBASE(pt_phys), PHYSADDR, PAGESIZE());
	pte_val = ULONG(machdep->ptbl + PAGEOFFSET(sizeof(pte_t) *
			pte_index_l3_4k(vaddr)));
	if (verbose)
		fprintf(fp, "  PTE: %lx => %lx\n", pt_phys, pte_val);
	if (!pte_val)
		goto no_page;
	pte_val &= PTE_PFN_PROT_MASK;
	pte_pfn = pte_val >> _PAGE_PFN_SHIFT;

	if (!(pte_val & _PAGE_PRESENT)) {
		if (verbose) {
			fprintf(fp, "\n");
			riscv64_translate_pte((ulong)pte_val, 0, 0);
		}
		fprintf(fp, " PAGE: %016lx not present\n\n", PAGEBASE(*paddr));
		return FALSE;
	}

	*paddr = PTOB(pte_pfn) + PAGEOFFSET(vaddr);

	if (verbose) {
		fprintf(fp, " PAGE: %016lx\n\n", PAGEBASE(*paddr));
		riscv64_translate_pte(pte_val, 0, 0);
	}

	return TRUE;
no_page:
	fprintf(fp, "invalid\n");
	return FALSE;
}

/*
 * 'bt -f' command output
 * Display all stack data contained in a frame
 */
static void
riscv64_display_full_frame(struct bt_info *bt, struct riscv64_unwind_frame *current,
			  struct riscv64_unwind_frame *previous)
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


/*
 * Gather Overflow stack values.
 */
static void
riscv64_overflow_stack_init(void)
{
	int i;
	struct syment *sp;
	struct gnu_request request, *req;
	struct machine_specific *ms = machdep->machspec;
	req = &request;

	if (symbol_exists("overflow_stack") &&
	    (sp = per_cpu_symbol_search("overflow_stack")) &&
	    get_symbol_type("overflow_stack", NULL, req)) {
		if (CRASHDEBUG(1)) {
			fprintf(fp, "overflow_stack: \n");
			fprintf(fp, "  type: %x, %s\n",
				(int)req->typecode,
				(req->typecode == TYPE_CODE_ARRAY) ?
						"TYPE_CODE_ARRAY" : "other");
			fprintf(fp, "  target_typecode: %x, %s\n",
				(int)req->target_typecode,
				req->target_typecode == TYPE_CODE_INT ?
						"TYPE_CODE_INT" : "other");
			fprintf(fp, "  target_length: %ld\n",
						req->target_length);
			fprintf(fp, "  length: %ld\n", req->length);
		}

		if (!(ms->overflow_stacks = (ulong *)malloc((size_t)(kt->cpus * sizeof(ulong)))))
			error(FATAL, "cannot malloc overflow_stack addresses\n");

		ms->overflow_stack_size = RISCV64_OVERFLOW_STACK_SIZE;
		machdep->flags |= OVERFLOW_STACKS;

		for (i = 0; i < kt->cpus; i++)
			ms->overflow_stacks[i] = kt->__per_cpu_offset[i] + sp->value;
	}
}

/*
 * Gather IRQ stack values.
 */
static void
riscv64_irq_stack_init(void)
{
	int i;
	struct syment *sp;
	struct gnu_request request, *req;
	struct machine_specific *ms = machdep->machspec;
	ulong p, sz;
	req = &request;

	if (symbol_exists("irq_stack_ptr") &&
	    (sp = per_cpu_symbol_search("irq_stack_ptr")) &&
	    get_symbol_type("irq_stack_ptr", NULL, req)) {
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
		 * find IRQ_STACK_SIZE (i.e. THREAD_SIZE) via thread_union.stack
		 * or set STACKSIZE() as default.
		 */
		if (MEMBER_EXISTS("thread_union", "stack")) {
			if ((sz = MEMBER_SIZE("thread_union", "stack")) > 0)
				ms->irq_stack_size = sz;
		} else
			ms->irq_stack_size = machdep->stacksize;

		machdep->flags |= IRQ_STACKS;

		for (i = 0; i < kt->cpus; i++) {
			p = kt->__per_cpu_offset[i] + sp->value;
			if (CRASHDEBUG(1))
				fprintf(fp, " IRQ stack pointer[%d] is  %lx\n", i, p);
			readmem(p, KVADDR, &(ms->irq_stacks[i]), sizeof(ulong),
				"IRQ stack pointer", RETURN_ON_ERROR);
		}
	}
}

static int
riscv64_on_irq_stack(int cpu, ulong stkptr)
{
	struct machine_specific *ms = machdep->machspec;
	ulong * stacks = ms->irq_stacks;
	ulong stack_size = ms->irq_stack_size;

	if ((cpu >= kt->cpus) || (stacks == NULL) || !stack_size)
		return FALSE;

	if ((stkptr >= stacks[cpu]) &&
	    (stkptr < (stacks[cpu] + stack_size)))
		return TRUE;

	return FALSE;
}

static int
riscv64_on_overflow_stack(int cpu, ulong stkptr)
{
	struct machine_specific *ms = machdep->machspec;
	ulong * stacks = ms->overflow_stacks;
	ulong stack_size = ms->overflow_stack_size;

	if ((cpu >= kt->cpus) || (stacks == NULL) || !stack_size)
		return FALSE;

	if ((stkptr >= stacks[cpu]) &&
	    (stkptr < (stacks[cpu] + stack_size)))
		return TRUE;

	return FALSE;
}

static int
riscv64_on_process_stack(struct bt_info *bt, ulong stkptr)
{
	ulong stackbase, stacktop;

	stackbase = GET_STACKBASE(bt->task);
	stacktop = GET_STACKTOP(bt->task);

	if ((stkptr >= stackbase) && (stkptr < stacktop))
		return TRUE;

	return FALSE;
}

static void
riscv64_set_irq_stack(struct bt_info *bt)
{
	struct machine_specific *ms = machdep->machspec;

	bt->stackbase = ms->irq_stacks[bt->tc->processor];
	bt->stacktop = bt->stackbase + ms->irq_stack_size;
	alter_stackbuf(bt);
}

static void
riscv64_set_overflow_stack(struct bt_info *bt)
{
	struct machine_specific *ms = machdep->machspec;

	bt->stackbase = ms->overflow_stacks[bt->tc->processor];
	bt->stacktop = bt->stackbase + ms->overflow_stack_size;
	alter_stackbuf(bt);
}

static void
riscv64_set_process_stack(struct bt_info *bt)
{
	bt->stackbase = GET_STACKBASE(bt->task);
	bt->stacktop = GET_STACKTOP(bt->task);
	alter_stackbuf(bt);
}

static void
riscv64_stackframe_init(void)
{
	long task_struct_thread = MEMBER_OFFSET("task_struct", "thread");

	/* from arch/riscv/include/asm/processor.h */
	long thread_reg_ra = MEMBER_OFFSET("thread_struct", "ra");
	long thread_reg_sp = MEMBER_OFFSET("thread_struct", "sp");
	long thread_reg_fp = MEMBER_OFFSET("thread_struct", "s");

	if ((task_struct_thread == INVALID_OFFSET) ||
	    (thread_reg_ra == INVALID_OFFSET) ||
	    (thread_reg_sp == INVALID_OFFSET) ||
	    (thread_reg_fp == INVALID_OFFSET) )
		error(FATAL,
		      "cannot determine thread_struct offsets\n");

	ASSIGN_OFFSET(task_struct_thread_context_pc) =
		task_struct_thread + thread_reg_ra;
	ASSIGN_OFFSET(task_struct_thread_context_sp) =
		task_struct_thread + thread_reg_sp;
	ASSIGN_OFFSET(task_struct_thread_context_fp) =
		task_struct_thread + thread_reg_fp;
}

static void
riscv64_dump_backtrace_entry(struct bt_info *bt, struct syment *sym,
			     struct riscv64_unwind_frame *current,
			     struct riscv64_unwind_frame *previous, int level)
{
	const char *name = sym ? sym->name : "(invalid)";
	struct load_module *lm;
	char *name_plus_offset = NULL;
	struct syment *symp;
	ulong symbol_offset;
	char buf[BUFSIZE];

	if (bt->flags & BT_SYMBOL_OFFSET) {
		symp = value_search(current->pc, &symbol_offset);

		if (symp && symbol_offset)
			name_plus_offset =
				value_to_symstr(current->pc, buf, bt->radix);
	}

	fprintf(fp, "%s#%d [%016lx] %s at %016lx",
		level < 10 ? " " : "",
		level,
		current->sp,
		name_plus_offset ? name_plus_offset : name,
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

	/* bt -f */
	if (bt->flags & BT_FULL) {
		fprintf(fp, "    "
			"[PC: %016lx RA: %016lx SP: %016lx SIZE: %ld]\n",
			current->pc,
			previous->pc,
			current->sp,
			previous->sp - current->sp);
		riscv64_display_full_frame(bt, current, previous);
	}
}

/*
 * Unroll a kernel stack.
 */
static void
riscv64_back_trace_cmd(struct bt_info *bt)
{
	struct riscv64_unwind_frame current, previous;
	struct stackframe curr_frame;
	struct riscv64_register *regs, *irq_regs, *overflow_regs;
	int level = 0;

	if (bt->flags & BT_REGS_NOT_FOUND)
		return;

	regs = (struct riscv64_register *) bt->machdep;

	if (riscv64_on_irq_stack(bt->tc->processor, bt->frameptr)) {
		riscv64_set_irq_stack(bt);
		bt->flags |= BT_IRQSTACK;
	}

	if (riscv64_on_overflow_stack(bt->tc->processor, bt->frameptr)) {
		riscv64_set_overflow_stack(bt);
		bt->flags |= BT_OVERFLOW_STACK;
	}

	current.pc = bt->instptr;
	current.sp = bt->stkptr;
	current.fp = bt->frameptr;

	if (!INSTACK(current.sp, bt))
		return;

	for (;;) {
		struct syment *symbol = NULL;
		struct stackframe *frameptr;
		ulong low, high;
		ulong offset;

		if (CRASHDEBUG(8))
			fprintf(fp, "level %d pc %#lx sp %lx fp 0x%lx\n",
				level, current.pc, current.sp, current.fp);

		/* Validate frame pointer */
		low = current.sp + sizeof(struct stackframe);
		high = bt->stacktop;
		if (current.fp < low || current.fp > high || current.fp & 0x7) {
			if (CRASHDEBUG(8))
				fprintf(fp, "fp 0x%lx sp 0x%lx low 0x%lx high 0x%lx\n",
					current.fp, current.sp, low, high);
			return;
		}

		symbol = value_search(current.pc, &offset);
		if (!symbol)
			return;

		frameptr = (struct stackframe *)current.fp - 1;
		if (!readmem((ulong)frameptr, KVADDR, &curr_frame,
		    sizeof(curr_frame), "get stack frame", RETURN_ON_ERROR))
			return;

		/* correct PC and FP of the second frame when the first frame has no callee */

		if (regs && (regs->regs[RISCV64_REGS_EPC] == current.pc) && curr_frame.fp & 0x7){
			previous.pc = regs->regs[RISCV64_REGS_RA];
			previous.fp = curr_frame.ra;
		} else {
			previous.pc = curr_frame.ra;
			previous.fp = curr_frame.fp;
		}

		previous.sp = current.fp;

		riscv64_dump_backtrace_entry(bt, symbol, &current, &previous, level++);

		current.pc = previous.pc;
		current.fp = previous.fp;
		current.sp = previous.sp;

		/*
		 * When backtracing to do_irq(), find the original FP of do_irq()
		 * and then use the saved pt_regs in process stack to continue
		 */
		if ((bt->flags & BT_IRQSTACK) &&
		    !riscv64_on_irq_stack(bt->tc->processor, current.fp)){
			if (riscv64_on_process_stack(bt, current.fp)){

				frameptr = (struct stackframe *)current.fp - 1;

				if (!readmem((ulong)frameptr, KVADDR, &curr_frame,
				    sizeof(curr_frame), "get do_irq stack frame", RETURN_ON_ERROR))
					return;

				riscv64_set_process_stack(bt);

				irq_regs = (struct riscv64_register *)
					&bt->stackbuf[(ulong)(STACK_OFFSET_TYPE(curr_frame.fp))];

				current.pc = irq_regs->regs[RISCV64_REGS_EPC];
				current.fp = irq_regs->regs[RISCV64_REGS_FP];
				current.sp = irq_regs->regs[RISCV64_REGS_SP];

				bt->flags &= ~BT_IRQSTACK;
				riscv64_print_exception_frame(bt, curr_frame.fp, KERNEL_MODE);
				fprintf(fp, "--- <IRQ stack> ---\n");
			}
		}

		/*
		 * When backtracing to handle_kernel_stack_overflow()
		 * use pt_regs saved in overflow stack to continue
		 */
		if ((bt->flags & BT_OVERFLOW_STACK) &&
		    !riscv64_on_overflow_stack(bt->tc->processor, current.fp)) {

				overflow_regs = (struct riscv64_register *)
					&bt->stackbuf[(ulong)(STACK_OFFSET_TYPE(current.sp))];

				riscv64_print_exception_frame(bt, current.sp, KERNEL_MODE);

				current.pc = overflow_regs->regs[RISCV64_REGS_EPC];
				current.fp = overflow_regs->regs[RISCV64_REGS_FP];
				current.sp = overflow_regs->regs[RISCV64_REGS_SP];

				riscv64_set_process_stack(bt);

				bt->flags &= ~BT_OVERFLOW_STACK;
				fprintf(fp, "--- <OVERFLOW stack> ---\n");
		}

		if (CRASHDEBUG(8))
			fprintf(fp, "next %d pc %#lx sp %#lx fp %lx\n",
				level, current.pc, current.sp, current.fp);
	}
}

/*
 * Get a stack frame combination of pc and ra from the most relevant spot.
 */
static void
riscv64_get_stack_frame(struct bt_info *bt, ulong *pcp, ulong *spp)
{
	ulong ksp = 0, nip = 0;
	int ret = 0;

	if (DUMPFILE() && is_task_active(bt->task))
		ret = riscv64_get_dumpfile_stack_frame(bt, &nip, &ksp);
	else
		ret = riscv64_get_frame(bt, &nip, &ksp);

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
riscv64_get_dumpfile_stack_frame(struct bt_info *bt, ulong *nip, ulong *ksp)
{
	const struct machine_specific *ms = machdep->machspec;
	struct riscv64_register *regs;
	ulong epc, sp;

	if (!ms->crash_task_regs) {
		bt->flags |= BT_REGS_NOT_FOUND;
		return FALSE;
	}

	/*
	 * We got registers for panic task from crash_notes. Just return them.
	 */
	regs = &ms->crash_task_regs[bt->tc->processor];
	epc = regs->regs[RISCV64_REGS_EPC];
	sp = regs->regs[RISCV64_REGS_SP];

	/*
	 * Set stack frame ptr.
	 */
	bt->frameptr = regs->regs[RISCV64_REGS_FP];

	if (nip)
		*nip = epc;
	if (ksp)
		*ksp = sp;

	bt->machdep = regs;

	return TRUE;
}

/*
 * Do the work for riscv64_get_stack_frame() for non-active tasks.
 * Get SP and PC values for idle tasks.
 */
static int
riscv64_get_frame(struct bt_info *bt, ulong *pcp, ulong *spp)
{
	if (!bt->tc || !(tt->flags & THREAD_INFO))
		return FALSE;

	if (!readmem(bt->task + OFFSET(task_struct_thread_context_pc),
		     KVADDR, pcp, sizeof(*pcp),
		     "thread_struct.ra",
		     RETURN_ON_ERROR))
		return FALSE;

	if (!readmem(bt->task + OFFSET(task_struct_thread_context_sp),
		     KVADDR, spp, sizeof(*spp),
		     "thread_struct.sp",
		     RETURN_ON_ERROR))
		return FALSE;

	if (!readmem(bt->task + OFFSET(task_struct_thread_context_fp),
		     KVADDR, &bt->frameptr, sizeof(bt->frameptr),
		     "thread_struct.fp",
		     RETURN_ON_ERROR))
		return FALSE;

	return TRUE;
}

static int
riscv64_vtop_4level_4k(ulong *pgd, ulong vaddr, physaddr_t *paddr, int verbose)
{
	ulong *pgd_ptr, pgd_val;
	ulong pud_val;
	ulong pmd_val;
	ulong pte_val, pte_pfn;
	ulong pt_phys;

	/* PGD */
	pgd_ptr = pgd + pgd_index_l4_4k(vaddr);
	FILL_PGD(pgd, KVADDR, PAGESIZE());
	pgd_val = ULONG(machdep->pgd + PAGEOFFSET(pgd_ptr));
	if (verbose)
		fprintf(fp, "  PGD: %lx => %lx\n", (ulong)pgd_ptr, pgd_val);
	if (!pgd_val)
		goto no_page;
	pgd_val &= PTE_PFN_PROT_MASK;
	pt_phys = (pgd_val >> _PAGE_PFN_SHIFT) << PAGESHIFT();

	/* PUD */
	FILL_PUD(PAGEBASE(pt_phys), PHYSADDR, PAGESIZE());
	pud_val = ULONG(machdep->pud + PAGEOFFSET(sizeof(pud_t) *
			pud_index_l4_4k(vaddr)));
	if (verbose)
		fprintf(fp, "  PUD: %016lx => %016lx\n", pt_phys, pud_val);
	if (!pud_val)
		goto no_page;
	pud_val &= PTE_PFN_PROT_MASK;
	pt_phys = (pud_val >> _PAGE_PFN_SHIFT) << PAGESHIFT();

	/* PMD */
	FILL_PMD(PAGEBASE(pt_phys), PHYSADDR, PAGESIZE());
	pmd_val = ULONG(machdep->pmd + PAGEOFFSET(sizeof(pmd_t) *
			pmd_index_l4_4k(vaddr)));
	if (verbose)
		fprintf(fp, "  PMD: %016lx => %016lx\n", pt_phys, pmd_val);
	if (!pmd_val)
		goto no_page;
	pmd_val &= PTE_PFN_PROT_MASK;
	pt_phys = (pmd_val >> _PAGE_PFN_SHIFT) << PAGESHIFT();

	/* PTE */
	FILL_PTBL(PAGEBASE(pt_phys), PHYSADDR, PAGESIZE());
	pte_val = ULONG(machdep->ptbl + PAGEOFFSET(sizeof(pte_t) *
			pte_index_l4_4k(vaddr)));
	if (verbose)
		fprintf(fp, "  PTE: %lx => %lx\n", pt_phys, pte_val);
	if (!pte_val)
		goto no_page;
	pte_val &= PTE_PFN_PROT_MASK;
	pte_pfn = pte_val >> _PAGE_PFN_SHIFT;

	if (!(pte_val & _PAGE_PRESENT)) {
		if (verbose) {
			fprintf(fp, "\n");
			riscv64_translate_pte((ulong)pte_val, 0, 0);
		}
		fprintf(fp, " PAGE: %016lx not present\n\n", PAGEBASE(*paddr));
		return FALSE;
	}

	*paddr = PTOB(pte_pfn) + PAGEOFFSET(vaddr);

	if (verbose) {
		fprintf(fp, " PAGE: %016lx\n\n", PAGEBASE(*paddr));
		riscv64_translate_pte(pte_val, 0, 0);
	}

	return TRUE;
no_page:
	fprintf(fp, "invalid\n");
	return FALSE;
}

static int
riscv64_vtop_5level_4k(ulong *pgd, ulong vaddr, physaddr_t *paddr, int verbose)
{
	ulong *pgd_ptr, pgd_val;
	ulong p4d_val;
	ulong pud_val;
	ulong pmd_val;
	ulong pte_val, pte_pfn;
	ulong pt_phys;

	/* PGD */
	pgd_ptr = pgd + pgd_index_l5_4k(vaddr);
	FILL_PGD(pgd, KVADDR, PAGESIZE());
	pgd_val = ULONG(machdep->pgd + PAGEOFFSET(pgd_ptr));
	if (verbose)
		fprintf(fp, "  PGD: %lx => %lx\n", (ulong)pgd_ptr, pgd_val);
	if (!pgd_val)
		goto no_page;
	pgd_val &= PTE_PFN_PROT_MASK;
	pt_phys = (pgd_val >> _PAGE_PFN_SHIFT) << PAGESHIFT();

	/* P4D */
	FILL_P4D(PAGEBASE(pt_phys), PHYSADDR, PAGESIZE());
	p4d_val = ULONG(machdep->machspec->p4d + PAGEOFFSET(sizeof(p4d_t) *
			p4d_index_l5_4k(vaddr)));
	if (verbose)
		fprintf(fp, "  P4D: %016lx => %016lx\n", pt_phys, p4d_val);
	if (!p4d_val)
		goto no_page;
	p4d_val &= PTE_PFN_PROT_MASK;
	pt_phys = (p4d_val >> _PAGE_PFN_SHIFT) << PAGESHIFT();

	/* PUD */
	FILL_PUD(PAGEBASE(pt_phys), PHYSADDR, PAGESIZE());
	pud_val = ULONG(machdep->pud + PAGEOFFSET(sizeof(pud_t) *
			pud_index_l5_4k(vaddr)));
	if (verbose)
		fprintf(fp, "  PUD: %016lx => %016lx\n", pt_phys, pud_val);
	if (!pud_val)
		goto no_page;
	pud_val &= PTE_PFN_PROT_MASK;
	pt_phys = (pud_val >> _PAGE_PFN_SHIFT) << PAGESHIFT();

	/* PMD */
	FILL_PMD(PAGEBASE(pt_phys), PHYSADDR, PAGESIZE());
	pmd_val = ULONG(machdep->pmd + PAGEOFFSET(sizeof(pmd_t) *
			pmd_index_l4_4k(vaddr)));
	if (verbose)
		fprintf(fp, "  PMD: %016lx => %016lx\n", pt_phys, pmd_val);
	if (!pmd_val)
		goto no_page;
	pmd_val &= PTE_PFN_PROT_MASK;
	pt_phys = (pmd_val >> _PAGE_PFN_SHIFT) << PAGESHIFT();

	/* PTE */
	FILL_PTBL(PAGEBASE(pt_phys), PHYSADDR, PAGESIZE());
	pte_val = ULONG(machdep->ptbl + PAGEOFFSET(sizeof(pte_t) *
			pte_index_l4_4k(vaddr)));
	if (verbose)
		fprintf(fp, "  PTE: %lx => %lx\n", pt_phys, pte_val);
	if (!pte_val)
		goto no_page;
	pte_val &= PTE_PFN_PROT_MASK;
	pte_pfn = pte_val >> _PAGE_PFN_SHIFT;

	if (!(pte_val & _PAGE_PRESENT)) {
		if (verbose) {
			fprintf(fp, "\n");
			riscv64_translate_pte((ulong)pte_val, 0, 0);
		}
		printf("!_PAGE_PRESENT\n");
		return FALSE;
	}

	*paddr = PTOB(pte_pfn) + PAGEOFFSET(vaddr);

	if (verbose) {
		fprintf(fp, " PAGE: %016lx\n\n", PAGEBASE(*paddr));
		riscv64_translate_pte(pte_val, 0, 0);
	}

	return TRUE;
no_page:
	fprintf(fp, "invalid\n");
	return FALSE;
}

static int
riscv64_init_active_task_regs(void)
{
	int retval;

	retval = riscv64_get_crash_notes();
	if (retval == TRUE)
		return retval;

	return riscv64_get_elf_notes();
}

/*
 * Retrieve task registers for the time of the crash.
 */
static int
riscv64_get_crash_notes(void)
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
riscv64_get_elf_notes(void)
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
 * Translates a user virtual address to its physical address.
 */
static int
riscv64_uvtop(struct task_context *tc, ulong uvaddr, physaddr_t *paddr, int verbose)
{
	ulong mm, active_mm;
	ulong *pgd;

	if (!tc)
		error(FATAL, "current context invalid\n");

	*paddr = 0;

	if (is_kernel_thread(tc->task) && IS_KVADDR(uvaddr)) {
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

	switch (machdep->flags & VM_FLAGS)
	{
	case VM_L3_4K:
		return riscv64_vtop_3level_4k(pgd, uvaddr, paddr, verbose);
	case VM_L4_4K:
		return riscv64_vtop_4level_4k(pgd, uvaddr, paddr, verbose);
	case VM_L5_4K:
		return riscv64_vtop_5level_4k(pgd, uvaddr, paddr, verbose);
	default:
		return FALSE;
	}
}

static int
riscv64_kvtop(struct task_context *tc, ulong kvaddr, physaddr_t *paddr, int verbose)
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

	switch (machdep->flags & VM_FLAGS)
	{
	case VM_L3_4K:
		return riscv64_vtop_3level_4k((ulong *)kernel_pgd, kvaddr, paddr, verbose);
	case VM_L4_4K:
		return riscv64_vtop_4level_4k((ulong *)kernel_pgd, kvaddr, paddr, verbose);
	case VM_L5_4K:
		return riscv64_vtop_5level_4k((ulong *)kernel_pgd, kvaddr, paddr, verbose);
	default:
		return FALSE;
	}
}

void
riscv64_init(int when)
{
	switch (when) {
	case SETUP_ENV:
		machdep->process_elf_notes = process_elf64_notes;
		break;

	case PRE_SYMTAB:
		machdep->verify_symbol = riscv64_verify_symbol;
		machdep->machspec = &riscv64_machine_specific;
		if (pc->flags & KERNEL_DEBUG_QUERY)
			return;

		machdep->verify_paddr = generic_verify_paddr;
		machdep->ptrs_per_pgd = PTRS_PER_PGD;

		/*
		 * Even if CONFIG_RANDOMIZE_BASE is not configured,
		 * derive_kaslr_offset() should work and set
		 * kt->relocate to 0
		 */
		if (!kt->relocate && !(kt->flags2 & (RELOC_AUTO|KASLR)))
			kt->flags2 |= (RELOC_AUTO|KASLR);
		break;

	case PRE_GDB:
		machdep->pagesize = riscv64_get_page_size();
		machdep->pageshift = ffs(machdep->pagesize) - 1;
		machdep->pageoffset = machdep->pagesize - 1;
		machdep->pagemask = ~((ulonglong)machdep->pageoffset);
		machdep->stacksize = machdep->pagesize << THREAD_SIZE_ORDER;

		riscv64_get_phys_ram_base(machdep->machspec);
		riscv64_get_struct_page_size(machdep->machspec);
		riscv64_get_va_bits(machdep->machspec);
		riscv64_get_va_range(machdep->machspec);
		riscv64_get_va_kernel_pa_offset(machdep->machspec);

		pt_level_alloc(&machdep->pgd, "cannot malloc pgd space.");
		pt_level_alloc(&machdep->machspec->p4d, "cannot malloc p4d space.");
		pt_level_alloc(&machdep->pud, "cannot malloc pud space.");
		pt_level_alloc(&machdep->pmd, "cannot malloc pmd space.");
		pt_level_alloc(&machdep->ptbl, "cannot malloc ptbl space.");

		machdep->last_pgd_read = 0;
		machdep->machspec->last_p4d_read = 0;
		machdep->last_pud_read = 0;
		machdep->last_pmd_read = 0;
		machdep->last_ptbl_read = 0;

		machdep->kvbase = machdep->machspec->page_offset;
		machdep->identity_map_base = machdep->kvbase;
		machdep->is_kvaddr = riscv64_is_kvaddr;
		machdep->is_uvaddr = riscv64_is_uvaddr;
		machdep->uvtop = riscv64_uvtop;
		machdep->kvtop = riscv64_kvtop;
		machdep->cmd_mach = riscv64_cmd_mach;
		machdep->get_stack_frame = riscv64_get_stack_frame;
		machdep->back_trace = riscv64_back_trace_cmd;
		machdep->eframe_search = riscv64_eframe_search;

		machdep->vmalloc_start = riscv64_vmalloc_start;
		machdep->processor_speed = riscv64_processor_speed;
		machdep->get_stackbase = generic_get_stackbase;
		machdep->get_stacktop = generic_get_stacktop;
		machdep->translate_pte = riscv64_translate_pte;
		machdep->memory_size = generic_memory_size;
		machdep->is_task_addr = riscv64_is_task_addr;
		machdep->get_smp_cpus = riscv64_get_smp_cpus;
		machdep->value_to_symbol = generic_machdep_value_to_symbol;
		machdep->dis_filter = generic_dis_filter;
		machdep->dump_irq = generic_dump_irq;
		machdep->show_interrupts = generic_show_interrupts;
		machdep->get_irq_affinity = generic_get_irq_affinity;
		machdep->init_kernel_pgd = NULL; /* pgd set by symbol_value("swapper_pg_dir") */
		break;

	case POST_GDB:
		machdep->section_size_bits = _SECTION_SIZE_BITS;
		machdep->max_physmem_bits = _MAX_PHYSMEM_BITS;

		riscv64_irq_stack_init();
		riscv64_overflow_stack_init();
		riscv64_stackframe_init();
		riscv64_page_type_init();

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
		if (!ACTIVE() && !riscv64_init_active_task_regs())
			error(WARNING,
				"cannot retrieve registers for active task%s\n\n",
				kt->cpus > 1 ? "s" : "");
		break;
	}
}

/* bool pt_regs : pass 1 to dump pt_regs , pass 0 to dump user_regs_struct */
static void
riscv64_dump_pt_regs(struct riscv64_register *regs, FILE *ofp, bool pt_regs)
{

	/* Print riscv64 32 regs */
	fprintf(ofp,
		"epc : " REG_FMT " ra : " REG_FMT " sp : " REG_FMT "\n"
		" gp : " REG_FMT " tp : " REG_FMT " t0 : " REG_FMT "\n"
		" t1 : " REG_FMT " t2 : " REG_FMT " s0 : " REG_FMT "\n"
		" s1 : " REG_FMT " a0 : " REG_FMT " a1 : " REG_FMT "\n"
		" a2 : " REG_FMT " a3 : " REG_FMT " a4 : " REG_FMT "\n"
		" a5 : " REG_FMT " a6 : " REG_FMT " a7 : " REG_FMT "\n"
		" s2 : " REG_FMT " s3 : " REG_FMT " s4 : " REG_FMT "\n"
		" s5 : " REG_FMT " s6 : " REG_FMT " s7 : " REG_FMT "\n"
		" s8 : " REG_FMT " s9 : " REG_FMT " s10: " REG_FMT "\n"
		" s11: " REG_FMT " t3 : " REG_FMT " t4 : " REG_FMT "\n"
		" t5 : " REG_FMT " t6 : " REG_FMT "\n",
		regs->regs[0],  regs->regs[1],  regs->regs[2],
		regs->regs[3],  regs->regs[4],  regs->regs[5],
		regs->regs[6],  regs->regs[7],  regs->regs[8],
		regs->regs[9],  regs->regs[10], regs->regs[11],
		regs->regs[12], regs->regs[13], regs->regs[14],
		regs->regs[15], regs->regs[16], regs->regs[17],
		regs->regs[18], regs->regs[19], regs->regs[20],
		regs->regs[21], regs->regs[22], regs->regs[23],
		regs->regs[24], regs->regs[25], regs->regs[26],
		regs->regs[27], regs->regs[28], regs->regs[29],
		regs->regs[30], regs->regs[31]);

	if (pt_regs)
		fprintf(ofp,
		" status: " REG_FMT " badaddr: " REG_FMT "\n"
		"  cause: " REG_FMT " orig_a0: " REG_FMT "\n",
		regs->regs[32], regs->regs[33], regs->regs[34],
		regs->regs[35]);
}

/*
 * 'help -r' command output
 */
void
riscv64_display_regs_from_elf_notes(int cpu, FILE *ofp)
{
	const struct machine_specific *ms = machdep->machspec;
	struct riscv64_register *regs;

	if (!ms->crash_task_regs) {
		error(INFO, "registers not collected for cpu %d\n", cpu);
		return;
	}

	regs = &ms->crash_task_regs[cpu];
	if (!regs->regs[RISCV64_REGS_SP] && !regs->regs[RISCV64_REGS_EPC]) {
		error(INFO, "registers not collected for cpu %d\n", cpu);
		return;
	}

	riscv64_dump_pt_regs(regs, ofp, 0);
}

static void
riscv64_print_exception_frame(struct bt_info *bt, ulong ptr, int mode)
{

	struct syment *sp;
	ulong PC, RA, SP, offset;
	struct riscv64_register *regs;

	regs = (struct riscv64_register *)&bt->stackbuf[(ulong)(STACK_OFFSET_TYPE(ptr))];

	PC = regs->regs[RISCV64_REGS_EPC];
	RA = regs->regs[RISCV64_REGS_RA];
	SP = regs->regs[RISCV64_REGS_SP];

	switch (mode) {
	case USER_MODE:
		fprintf(fp,
		    "     PC: %016lx   RA: %016lx   SP: %016lx\n"
		    "     ORIG_A0: %016lx   SYSCALLNO: %016lx\n",
		    PC, RA, SP, regs->regs[35], regs->regs[17]);

		break;

	case KERNEL_MODE:
		fprintf(fp, "     PC: %016lx  ", PC);
		if (is_kernel_text(PC) && (sp = value_search(PC, &offset))) {
			fprintf(fp, "[%s", sp->name);
			if (offset)
				fprintf(fp, (*gdb_output_radix == 16) ?
					"+0x%lx" : "+%ld", offset);
			fprintf(fp, "]\n");
		} else
			fprintf(fp, "[unknown or invalid address]\n");

		fprintf(fp, "     RA: %016lx  ", RA);
		if (is_kernel_text(RA) && (sp = value_search(RA, &offset))) {
			fprintf(fp, "[%s", sp->name);
			if (offset)
				fprintf(fp, (*gdb_output_radix == 16) ?
					"+0x%lx" : "+%ld", offset);
			fprintf(fp, "]\n");
		} else
			fprintf(fp, "[unknown or invalid address]\n");

		fprintf(fp, "     SP: %016lx  CAUSE: %016lx\n",
			SP, regs->regs[RISCV64_REGS_CAUSE]);

		break;
	}

	riscv64_dump_pt_regs(regs, fp, 1);

}

static int
riscv64_is_kernel_exception_frame(struct bt_info *bt, ulong stkptr)
{
	struct riscv64_register *regs;

	if (stkptr > STACKSIZE() && !INSTACK(stkptr, bt)) {
		if (CRASHDEBUG(1))
			error(WARNING, "stkptr: %lx is outside the kernel stack range\n", stkptr);
		return FALSE;
	}

	regs = (struct riscv64_register *)&bt->stackbuf[(ulong)(STACK_OFFSET_TYPE(stkptr))];

	if (INSTACK(regs->regs[RISCV64_REGS_SP], bt) &&
	    INSTACK(regs->regs[RISCV64_REGS_FP], bt) &&
	    is_kernel_text(regs->regs[RISCV64_REGS_RA]) &&
	    is_kernel_text(regs->regs[RISCV64_REGS_EPC]) &&
	    ((regs->regs[RISCV64_REGS_STATUS] >> 8) & 0x1) && // sstatus.SPP != 0
	    !((regs->regs[RISCV64_REGS_CAUSE] >> 63) & 0x1 ) && // scause.Interrupt != 1
	    !(regs->regs[RISCV64_REGS_CAUSE] == 0x00000008UL)) { // scause != ecall from U-mode

		return TRUE;
	}

	return FALSE;
}

static int
riscv64_dump_kernel_eframes(struct bt_info *bt)
{
	ulong ptr;
	int count;

	/*
	 * use old_regs to avoid the identical contiguous kernel exception frames
	 * created by Linux handle_exception() path ending at riscv_crash_save_regs()
	 */
	struct riscv64_register *regs, *old_regs;

	count = 0;
	old_regs = NULL;

	for (ptr = bt->stackbase; ptr < bt->stacktop - SIZE(pt_regs); ptr++) {

		regs = (struct riscv64_register *)&bt->stackbuf[(ulong)(STACK_OFFSET_TYPE(ptr))];

		if (riscv64_is_kernel_exception_frame(bt, ptr)){
			if (!old_regs || (old_regs &&
			    memcmp(old_regs, regs, sizeof(struct riscv64_register))) != 0){
				old_regs = regs;
				fprintf(fp, "\nKERNEL-MODE EXCEPTION FRAME AT: %lx\n", ptr);
				riscv64_print_exception_frame(bt, ptr, KERNEL_MODE);
				count++;
			}
		}
	}

	return count;
}

static int
riscv64_eframe_search(struct bt_info *bt)
{
	ulong ptr;
	int count, c;
	struct machine_specific *ms = machdep->machspec;

	if (bt->flags & BT_EFRAME_SEARCH2) {
		if (!(machdep->flags & IRQ_STACKS))
			error(FATAL, "IRQ stacks do not exist in this kernel\n");

		for (c = 0; c < kt->cpus; c++) {
			if ((bt->flags & BT_CPUMASK) &&
			    !(NUM_IN_BITMAP(bt->cpumask, c)))
				continue;

			fprintf(fp, "CPU %d IRQ STACK: ", c);
			bt->stackbase = ms->irq_stacks[c];
			bt->stacktop = bt->stackbase + ms->irq_stack_size;
			alter_stackbuf(bt);

			count = riscv64_dump_kernel_eframes(bt);

			if (count)
				fprintf(fp, "\n");
			else
				fprintf(fp, "(none found)\n\n");
		}

		return 0;
	}

	count = riscv64_dump_kernel_eframes(bt);

	if (is_kernel_thread(bt->tc->task))
		return count;

	ptr = bt->stacktop - SIZE(pt_regs);
	fprintf(fp, "%sUSER-MODE EXCEPTION FRAME AT: %lx\n", count++ ? "\n" : "", ptr);
	riscv64_print_exception_frame(bt, ptr, USER_MODE);

	return count;
}

#else /* !RISCV64 */

void
riscv64_display_regs_from_elf_notes(int cpu, FILE *ofp)
{
	return;
}

#endif /* !RISCV64 */
