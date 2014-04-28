/* ppc.c - core analysis suite
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002-2007, 2010-2014 David Anderson
 * Copyright (C) 2002-2007, 2010-2014 Red Hat, Inc. All rights reserved.
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
#ifdef PPC
#include "defs.h"
#include <elf.h>


#define MAX_PLATFORM_LEN	32	/* length for platform string */

/* 
 *  This structure was copied from kernel source
 *  in include/asm-ppc/ptrace.h
 */
struct ppc_pt_regs {
        long gpr[32];
        long nip;
        long msr;
        long orig_gpr3;      /* Used for restarting system calls */
        long ctr;
        long link;
        long xer;
        long ccr;
        long mq;             /* 601 only (not used at present) */
                                /* Used on APUS to hold IPL value. */
        long trap;           /* Reason for being here */
        long dar;            /* Fault registers */
        long dsisr;
        long result;         /* Result of a system call */
};

static int ppc_kvtop(struct task_context *, ulong, physaddr_t *, int);
static int ppc_uvtop(struct task_context *, ulong, physaddr_t *, int);
static ulong ppc_vmalloc_start(void);
static int ppc_is_task_addr(ulong);
static int ppc_verify_symbol(const char *, ulong, char);
static ulong ppc_get_task_pgd(ulong);
static int ppc_translate_pte(ulong, void *, ulonglong);

static ulong ppc_processor_speed(void);
static int ppc_eframe_search(struct bt_info *);
static ulong ppc_in_irqstack(ulong);
static void ppc_back_trace_cmd(struct bt_info *);
static void ppc_back_trace(struct gnu_request *, struct bt_info *);
static void get_ppc_frame(struct bt_info *, ulong *, ulong *);
static void ppc_print_stack_entry(int,struct gnu_request *,
	ulong, ulong, struct bt_info *);
static char *ppc_check_eframe(struct ppc_pt_regs *);
static void ppc_print_eframe(char *, struct ppc_pt_regs *, struct bt_info *);
static void ppc_print_regs(struct ppc_pt_regs *);
static void ppc_display_full_frame(struct bt_info *, ulong, FILE *);
static void ppc_dump_irq(int);
static void ppc_get_stack_frame(struct bt_info *, ulong *, ulong *);
static int ppc_dis_filter(ulong, char *, unsigned int);
static void ppc_cmd_mach(void);
static int ppc_get_smp_cpus(void);
static void ppc_display_machine_stats(void);
static void ppc_dump_line_number(ulong);
static struct line_number_hook ppc_line_number_hooks[];


static struct machine_specific ppc_machine_specific = { 0 };
static int probe_default_platform(char *);
static int probe_ppc44x_platform(char *);
static int probe_ppce500_platform(char *);
static void ppc_probe_base_platform(void);

typedef int (*probe_func_t) (char *);

probe_func_t probe_platforms[] = {
	probe_ppc44x_platform,	/* 44x chipsets */
	probe_ppce500_platform, /* E500 chipsets */
	probe_default_platform, /* This should be at the end */
	NULL
};

/* Don't forget page flags definitions for each platform */
#define PLATFORM_PAGE_FLAGS_SETUP(PLT)		\
do {						\
	_PAGE_PRESENT = PLT##_PAGE_PRESENT;	\
	_PAGE_USER = PLT##_PAGE_USER;		\
	_PAGE_RW = PLT##_PAGE_RW;		\
	_PAGE_GUARDED = PLT##_PAGE_GUARDED;	\
	_PAGE_COHERENT = PLT##_PAGE_COHERENT;	\
	_PAGE_NO_CACHE = PLT##_PAGE_NO_CACHE;	\
	_PAGE_WRITETHRU = PLT##_PAGE_WRITETHRU;	\
	_PAGE_DIRTY = PLT##_PAGE_DIRTY;		\
	_PAGE_ACCESSED = PLT##_PAGE_ACCESSED;	\
	_PAGE_HWWRITE = PLT##_PAGE_HWWRITE;	\
	_PAGE_SHARED = PLT##_PAGE_SHARED;	\
} while (0)

static int
probe_ppc44x_platform(char *name)
{
	/* 44x include ppc440* and ppc470 */
	if (STRNEQ(name, "ppc440") || STREQ(name, "ppc470")) {
		PPC_PLATFORM = strdup(name);
		PLATFORM_PAGE_FLAGS_SETUP(PPC44x);

		return TRUE;
	}

	return FALSE;
}

struct fsl_booke_tlbcam {
#define NUM_TLBCAMS	(64)
#define LAST_TLBCAM	(0x40)
	uint index;
	struct {
		ulong start;
		ulong limit;
		physaddr_t phys;
	} tlbcamrange;
	struct {
		uint MAS0;
		uint MAS1;
		ulong MAS2;
		uint MAS3;
		uint MAS7;
	} tlbcam;
};

static int
fsl_booke_vtop(ulong vaddr, physaddr_t *paddr, int verbose)
{
	struct fsl_booke_tlbcam *fsl_mmu;
	int i, found;

	if (CRASHDEBUG(1))
		fprintf(fp, "[Searching tlbcam address mapping]\n");
	fsl_mmu = MMU_SPECIAL;
	for (i = 0, found = FALSE;;i++, fsl_mmu++) {
		if (vaddr >= fsl_mmu->tlbcamrange.start &&
		    vaddr < fsl_mmu->tlbcamrange.limit) {
			*paddr = fsl_mmu->tlbcamrange.phys +
				 (vaddr - fsl_mmu->tlbcamrange.start);
			found = TRUE;
			break;
		}
		if (fsl_mmu->index & LAST_TLBCAM)
			break;
	}
	if (found && verbose) {
		/* TLBCAM segment attributes */
		fprintf(fp, "\n  TLBCAM[%u]: MAS0     MAS1     MAS2     "
			"MAS3     MAS7\n",
			(fsl_mmu->index & ~LAST_TLBCAM));
		fprintf(fp, "             %-8x %-8x %-8lx %-8x %-8x\n",
			fsl_mmu->tlbcam.MAS0, fsl_mmu->tlbcam.MAS1,
			fsl_mmu->tlbcam.MAS2, fsl_mmu->tlbcam.MAS3,
			fsl_mmu->tlbcam.MAS7);
		/* TLBCAM range */
		fprintf(fp, "             VIRTUAL RANGE : %lx - %lx\n",
			fsl_mmu->tlbcamrange.start, fsl_mmu->tlbcamrange.limit);
		fprintf(fp, "             PHYSICAL RANGE: %llx - %llx\n",
			fsl_mmu->tlbcamrange.phys,
			fsl_mmu->tlbcamrange.phys + (fsl_mmu->tlbcamrange.limit
				- fsl_mmu->tlbcamrange.start));
		/* translated addr and its tlbcam's offset. */
		fprintf(fp, "  => VIRTUAL  PHYSICAL TLBCAM-OFFSET\n");
		fprintf(fp, "     %-8lx %-8llx %lu\n", vaddr, *paddr,
			vaddr - fsl_mmu->tlbcamrange.start);
	}
	if (CRASHDEBUG(1))
		fprintf(fp, "[tlbcam search end]\n");

	return found;
}

static void
fsl_booke_mmu_setup(void)
{
	struct fsl_booke_tlbcam *fsl_mmu;
	uint i, tlbcam_index;
	ulong tlbcam_addrs, TLBCAM;

	readmem(symbol_value("tlbcam_index"), KVADDR, &tlbcam_index,
		sizeof(uint), "tlbcam_index", FAULT_ON_ERROR);
	if (tlbcam_index != 0 && tlbcam_index < NUM_TLBCAMS) {
		fsl_mmu = calloc(tlbcam_index, sizeof(*fsl_mmu));
		if (!fsl_mmu) {
			error(FATAL, "fsl_mmu calloc() failed\n");
			return;
		}
		tlbcam_addrs = symbol_value("tlbcam_addrs");
		TLBCAM = symbol_value("TLBCAM");
		for (i = 0; i < tlbcam_index; i++) {
			fsl_mmu[i].index = i;
			readmem(tlbcam_addrs +
					i * sizeof(fsl_mmu[i].tlbcamrange),
				KVADDR, &fsl_mmu[i].tlbcamrange,
				sizeof(fsl_mmu[i].tlbcamrange), "tlbcam_addrs",
				FAULT_ON_ERROR);
			readmem(TLBCAM + i * sizeof(fsl_mmu[i].tlbcam), KVADDR,
				&fsl_mmu[i].tlbcam, sizeof(fsl_mmu[i].tlbcam),
				"TLBCAM", FAULT_ON_ERROR);
		}
		fsl_mmu[i - 1].index |= LAST_TLBCAM;
		MMU_SPECIAL = fsl_mmu;
		VTOP_SPECIAL = fsl_booke_vtop;
	} else
		error(INFO, "[%s]: can't setup tlbcam: tlbcam_index=%u\n",
			PPC_PLATFORM, tlbcam_index);
}

static int
probe_ppce500_platform(char *name)
{
	if (STRNEQ(name, "ppce500mc")) {
		PPC_PLATFORM = strdup(name);
		if (IS_PAE()) {
			PTE_RPN_SHIFT = BOOKE3E_PTE_RPN_SHIFT;
			PLATFORM_PAGE_FLAGS_SETUP(BOOK3E);
			/* Set special flag for book3e */
			_PAGE_K_RW = BOOK3E_PAGE_KERNEL_RW;
		} else
			PLATFORM_PAGE_FLAGS_SETUP(FSL_BOOKE);
		fsl_booke_mmu_setup();

		return TRUE;
	}
	return FALSE;
}

static int
probe_default_platform(char *name)
{
	if (IS_PAE()) {
		error(INFO, "platform \"%s\" 64bit PTE fall through\n", name);
		error(INFO, "vmalloc translation could not work!\n");
	}

	/* Use the default definitions */
	PPC_PLATFORM = strdup(name);
	PLATFORM_PAGE_FLAGS_SETUP(DEFAULT);

	return TRUE;
}

#undef PLATFORM_PAGE_FLAGS_SETUP

/*
 * Find the platform of the crashing system and set the
 * base_platform accordingly.
 */
void
ppc_probe_base_platform(void)
{
	probe_func_t probe;
	char platform_name[MAX_PLATFORM_LEN];
	ulong ptr;
	int i;

	if(!try_get_symbol_data("powerpc_base_platform", sizeof(ulong), &ptr) ||
		read_string(ptr, platform_name, MAX_PLATFORM_LEN - 1) == 0)
		/* Let us fallback to default definitions */
		strcpy(platform_name, "(unknown)");

	for (i = 0; probe_platforms[i] != NULL; i++) {
		probe = probe_platforms[i];
		if (probe(platform_name))
			break;
	}
}

/*
 *  Do all necessary machine-specific setup here.  This is called twice,
 *  before and after GDB has been initialized.
 */
void
ppc_init(int when)
{
	uint cpu_features;
	ulong cur_cpu_spec;
	struct datatype_member pte = {
		.name = "pte_t",
	};

	switch (when)
	{
	case SETUP_ENV:
		machdep->machspec = &ppc_machine_specific;
		machdep->process_elf_notes = process_elf32_notes;
		break;

	case PRE_SYMTAB:
		machdep->verify_symbol = ppc_verify_symbol;
                if (pc->flags & KERNEL_DEBUG_QUERY)
                        return;
                machdep->pagesize = memory_page_size();
                machdep->pageshift = ffs(machdep->pagesize) - 1;
                machdep->pageoffset = machdep->pagesize - 1;
                machdep->pagemask = ~((ulonglong)machdep->pageoffset);
		machdep->stacksize = PPC_STACK_SIZE;
                if ((machdep->pgd = (char *)malloc(PAGESIZE())) == NULL)
                        error(FATAL, "cannot malloc pgd space.");
                machdep->pmd = machdep->pgd;
                if ((machdep->ptbl = (char *)malloc(PAGESIZE())) == NULL)
                        error(FATAL, "cannot malloc ptbl space.");
                machdep->last_pgd_read = 0;
                machdep->last_pmd_read = 0;
                machdep->last_ptbl_read = 0;
		machdep->verify_paddr = generic_verify_paddr;
		break;

	case PRE_GDB:
	        machdep->kvbase = symbol_value("_stext");
		machdep->identity_map_base = machdep->kvbase;
                machdep->is_kvaddr = generic_is_kvaddr;
                machdep->is_uvaddr = generic_is_uvaddr;
	        machdep->eframe_search = ppc_eframe_search;
	        machdep->back_trace = ppc_back_trace_cmd;
	        machdep->processor_speed = ppc_processor_speed;
	        machdep->uvtop = ppc_uvtop;
	        machdep->kvtop = ppc_kvtop;
	        machdep->get_task_pgd = ppc_get_task_pgd;
		machdep->get_stack_frame = ppc_get_stack_frame;
		machdep->get_stackbase = generic_get_stackbase;
		machdep->get_stacktop = generic_get_stacktop;
		machdep->translate_pte = ppc_translate_pte;
		machdep->memory_size = generic_memory_size;
		machdep->is_task_addr = ppc_is_task_addr;
		machdep->dis_filter = ppc_dis_filter;
		machdep->cmd_mach = ppc_cmd_mach;
		machdep->get_smp_cpus = ppc_get_smp_cpus;
		machdep->line_number_hooks = ppc_line_number_hooks;
		machdep->value_to_symbol = generic_machdep_value_to_symbol;
                machdep->init_kernel_pgd = NULL;

		break;

	case POST_GDB:
		/* gdb interface got available, resolve PTE right now. */
		PTE_SIZE = DATATYPE_SIZE(&pte);
		if (PTE_SIZE < 0)
			error(FATAL,
			      "gdb could not handle \"pte_t\" size request\n");
		/* Check if we have 64bit PTE on 32bit system */
		if (PTE_SIZE == sizeof(ulonglong))
			machdep->flags |= PAE;
		/* Find the platform where we crashed */
		ppc_probe_base_platform();
		if (!PTE_RPN_SHIFT)
			PTE_RPN_SHIFT = PAGE_SHIFT;

		machdep->vmalloc_start = ppc_vmalloc_start;
		MEMBER_OFFSET_INIT(thread_struct_pg_tables, 
 			"thread_struct", "pg_tables");

		if (VALID_SIZE(irq_desc_t)) {
			/*
			 * Use generic irq handlers for recent kernels whose
			 * irq_desc_t have been initialized in kernel_init().
			 */
			machdep->dump_irq = generic_dump_irq;
			machdep->show_interrupts = generic_show_interrupts;
			machdep->get_irq_affinity = generic_get_irq_affinity;
		} else {
			machdep->dump_irq = ppc_dump_irq;
			STRUCT_SIZE_INIT(irqdesc, "irqdesc");
			STRUCT_SIZE_INIT(irq_desc_t, "irq_desc_t");
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
		else if (symbol_exists("nr_irqs"))
			get_symbol_data("nr_irqs", sizeof(int),
					&machdep->nr_irqs);
		else
			machdep->nr_irqs = 512; /* NR_IRQS (at least) */
		if (!machdep->hz) {
			machdep->hz = HZ;
			if (THIS_KERNEL_VERSION >= LINUX(2,6,0))
				machdep->hz = 1000;
		}
		if (symbol_exists("cur_cpu_spec")) {
			get_symbol_data("cur_cpu_spec", sizeof(void *), &cur_cpu_spec);
			readmem(cur_cpu_spec + MEMBER_OFFSET("cpu_spec", "cpu_user_features"), 
				KVADDR, &cpu_features, sizeof(uint), "cpu user features",
				FAULT_ON_ERROR);
			if (cpu_features & CPU_BOOKE)
				machdep->flags |= CPU_BOOKE;
		}
		else
			machdep->flags |= CPU_BOOKE;
		machdep->section_size_bits = _SECTION_SIZE_BITS;
		machdep->max_physmem_bits = _MAX_PHYSMEM_BITS;
		/*
		 * IRQ stacks are introduced in 2.6 and also configurable.
		 */
		if ((THIS_KERNEL_VERSION >= LINUX(2,6,0)) &&
			symbol_exists("hardirq_ctx"))
			STRUCT_SIZE_INIT(irq_ctx, "hardirq_ctx");

		STRUCT_SIZE_INIT(note_buf, "note_buf_t");
		STRUCT_SIZE_INIT(elf_prstatus, "elf_prstatus");
		break;

	case POST_INIT:
		break;

	case LOG_ONLY:
		machdep->kvbase = kt->vmcoreinfo._stext_SYMBOL;
		break;
	}
}

void
ppc_dump_machdep_table(ulong arg)
{
        int others; 
 
        others = 0;
	fprintf(fp, "           platform: %s\n", PPC_PLATFORM);
        fprintf(fp, "              flags: %lx (", machdep->flags);
	if (machdep->flags & KSYMS_START)
		fprintf(fp, "%sKSYMS_START", others++ ? "|" : "");
	if (machdep->flags & PAE)
		fprintf(fp, "%sPAE", others++ ? "|" : "");
	if (machdep->flags & CPU_BOOKE)
		fprintf(fp, "%sCPU_BOOKE", others++ ? "|" : "");
        fprintf(fp, ")\n");

	fprintf(fp, "             kvbase: %lx\n", machdep->kvbase);
	fprintf(fp, "  identity_map_base: %lx\n", machdep->identity_map_base);
        fprintf(fp, "           pagesize: %d\n", machdep->pagesize);
        fprintf(fp, "          pageshift: %d\n", machdep->pageshift);
        fprintf(fp, "           pagemask: %llx\n", machdep->pagemask);
        fprintf(fp, "         pageoffset: %lx\n", machdep->pageoffset);
	fprintf(fp, "        pgdir_shift: %d\n", PGDIR_SHIFT);
	fprintf(fp, "       ptrs_per_pgd: %d\n", PTRS_PER_PGD);
	fprintf(fp, "       ptrs_per_pte: %d\n", PTRS_PER_PTE);
	fprintf(fp, "           pte_size: %d\n", PTE_SIZE);
	fprintf(fp, "      pte_rpn_shift: %d\n", PTE_RPN_SHIFT);
	fprintf(fp, "          stacksize: %ld\n", machdep->stacksize);
        fprintf(fp, "                 hz: %d\n", machdep->hz);
        fprintf(fp, "                mhz: %ld\n", machdep->mhz);
        fprintf(fp, "            memsize: %lld (0x%llx)\n", 
		machdep->memsize, machdep->memsize);
	fprintf(fp, "               bits: %d\n", machdep->bits);
	fprintf(fp, "            nr_irqs: %d\n", machdep->nr_irqs);
        fprintf(fp, "      eframe_search: ppc_eframe_search()   [TBD]\n");
        fprintf(fp, "         back_trace: ppc_back_trace_cmd()\n");
        fprintf(fp, "    processor_speed: ppc_processor_speed()\n");
        fprintf(fp, "              uvtop: ppc_uvtop()\n");
        fprintf(fp, "              kvtop: ppc_kvtop()\n");
        fprintf(fp, "       get_task_pgd: ppc_get_task_pgd()\n");
	if (machdep->dump_irq == generic_dump_irq)
		fprintf(fp, "           dump_irq: generic_dump_irq()\n");
	else
		fprintf(fp, "           dump_irq: ppc_dump_irq()\n");
	fprintf(fp, "    show_interrupts: generic_show_interrupts()\n");
	fprintf(fp, "   get_irq_affinity: generic_get_irq_affinity()\n");
        fprintf(fp, "    get_stack_frame: ppc_get_stack_frame()\n");
        fprintf(fp, "      get_stackbase: generic_get_stackbase()\n");
        fprintf(fp, "       get_stacktop: generic_get_stacktop()\n");
        fprintf(fp, "      translate_pte: ppc_translate_pte()\n");
	fprintf(fp, "        memory_size: generic_memory_size()\n");
	fprintf(fp, "      vmalloc_start: ppc_vmalloc_start()\n");
	fprintf(fp, "       is_task_addr: ppc_is_task_addr()\n");
	fprintf(fp, "      verify_symbol: ppc_verify_symbol()\n");
	fprintf(fp, "         dis_filter: ppc_dis_filter()\n");
	fprintf(fp, "           cmd_mach: ppc_cmd_mach()\n");
	fprintf(fp, "       get_smp_cpus: ppc_get_smp_cpus()\n");
        fprintf(fp, "          is_kvaddr: generic_is_kvaddr()\n");
        fprintf(fp, "          is_uvaddr: generic_is_uvaddr()\n");
        fprintf(fp, "       verify_paddr: generic_verify_paddr()\n");
	fprintf(fp, "    init_kernel_pgd: NULL\n");
	fprintf(fp, "    value_to_symbol: generic_machdep_value_to_symbol()\n");
        fprintf(fp, "  line_number_hooks: ppc_line_number_hooks\n");
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

static ulonglong
ppc_pte_physaddr(ulonglong pte)
{
	pte = pte >> PTE_RPN_SHIFT;	/* pfn */
	pte = pte << PAGE_SHIFT;	/* physaddr */

	return pte;
}

static int
ppc_pgd_vtop(ulong *pgd, ulong vaddr, physaddr_t *paddr, int verbose)
{
	ulong *page_dir;
	ulong pgd_pte, page_table, pte_index;
	ulonglong pte;

	if (verbose)
		fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)pgd);

	page_dir = pgd + (vaddr >> PGDIR_SHIFT);

	/*
 	 * Size of a pgd could be more than a PAGE.
 	 * So use PAGEBASE(page_dir), instead of 
 	 * PAGEBASE(pgd) for FILL_PGD()
 	 */
        FILL_PGD(PAGEBASE((ulong)page_dir), KVADDR, PAGESIZE());
        pgd_pte = ULONG(machdep->pgd + PAGEOFFSET((ulong)page_dir));

	if (verbose)
		fprintf(fp, "  PGD: %lx => %lx\n", (ulong)page_dir, pgd_pte);

	if (!pgd_pte) {
		if (VTOP_SPECIAL)
			/*
			 * This ppc platform have special address mapping
			 * between vaddr and paddr which can not search from
			 * standard page table.
			 */
			return VTOP_SPECIAL(vaddr, paddr, verbose);
		goto no_page;
	}

	page_table = pgd_pte;
	if (IS_BOOKE())
		page_table = VTOP(page_table);

        FILL_PTBL(PAGEBASE((ulong)page_table), PHYSADDR, PAGESIZE());
	pte_index = (vaddr >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
	if (IS_PAE())
		pte = ULONGLONG(machdep->ptbl + PTE_SIZE * pte_index);

	else
	        pte = ULONG(machdep->ptbl + PTE_SIZE * pte_index);

	if (verbose) 
		fprintf(fp, "  PTE: %lx => %llx\n", pgd_pte, pte);

	if (!(pte & _PAGE_PRESENT)) { 
		if (pte && verbose) {
			fprintf(fp, "\n");
			ppc_translate_pte((ulong)pte, 0, pte);
		}
		goto no_page;
	}

	if (verbose) {
		fprintf(fp, " PAGE: %llx\n\n", PAGEBASE(ppc_pte_physaddr(pte)));
		ppc_translate_pte((ulong)pte, 0, pte);
	}

	*paddr = PAGEBASE(ppc_pte_physaddr(pte)) + PAGEOFFSET(vaddr);

	return TRUE;

no_page:
	return FALSE;

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
ppc_uvtop(struct task_context *tc, ulong vaddr, physaddr_t *paddr, int verbose)
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

	return ppc_pgd_vtop(pgd, vaddr, paddr, verbose);
}

/*
 * Translates a kernel virtual address to its physical address.  cmd_vtop()
 * sets the verbose flag so that the pte translation gets displayed; all
 * other callers quietly accept the translation.
 */
static int
ppc_kvtop(struct task_context *tc, ulong kvaddr, physaddr_t *paddr, int verbose)
{
	ulong *pgd;

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

	pgd = (ulong *)vt->kernel_pgd[0];
	return ppc_pgd_vtop(pgd, kvaddr, paddr, verbose);
}

/*
 *  Determine where vmalloc'd memory starts by looking at the first
 *  entry on the vmlist.
 */
static ulong
ppc_vmalloc_start(void)
{
	return (first_vmalloc_address());
}

/*
 *  PPC tasks are all stacksize-aligned, except when split from the stack.
 *  PPC also allows the idle_task to be non-page aligned, so we have to make
 *  an additional check through the idle_threads array.
 */
static int
ppc_is_task_addr(ulong task)
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
 *  According to kernel source, this should cover all the PPC variants out
 *  There, but since we can't test them all, YMMV.
 */
static ulong
ppc_processor_speed(void)
{
	ulong res, value, ppc_md, md_setup_res;
	ulong prep_setup_res;
	ulong node, type, name, properties;
	char str_buf[32];
	ulong len, mhz = 0;

	if (machdep->mhz)
		return(machdep->mhz);

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
					    sizeof(ulong), 
					    "clock frequency value",
                                            FAULT_ON_ERROR);
					mhz /= 1000000;
					break;
				} else if(len && (strcasecmp(str_buf,
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

	return (machdep->mhz = mhz);
}

/*
 *  Accept or reject a symbol from the kernel namelist.
 */
static int
ppc_verify_symbol(const char *name, ulong value, char type)
{
	if (CRASHDEBUG(8) && name && strlen(name))
		fprintf(fp, "%08lx %s\n", value, name);

	if (STREQ(name, "_start"))
		machdep->flags |= KSYMS_START;

	return (name && strlen(name) && (machdep->flags & KSYMS_START) &&
	        !STREQ(name, "Letext") && !STRNEQ(name, "__func__."));
}


/*
 *  Get the relevant page directory pointer from a task structure.
 */
static ulong
ppc_get_task_pgd(ulong task)
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
 *  Translate a PTE, returning TRUE if the page is _PAGE_PRESENT.
 *  If a physaddr pointer is passed in, don't print anything.
 */
static int
ppc_translate_pte(ulong pte32, void *physaddr, ulonglong pte64)
{
	int c, len1, len2, len3, others, page_present;
	char buf[BUFSIZE];
        char buf2[BUFSIZE];
        char buf3[BUFSIZE];
	char ptebuf[BUFSIZE];
	char physbuf[BUFSIZE];
        char *arglist[MAXARGS];
	ulonglong paddr;

	if (!IS_PAE())
		pte64 = pte32;

        paddr = PAGEBASE(ppc_pte_physaddr(pte64));
	page_present = (pte64 & _PAGE_PRESENT);

	if (physaddr) {
		*((ulong *)physaddr) = paddr;
		return page_present;
	}

	sprintf(ptebuf, "%llx", pte64);
	len1 = MAX(strlen(ptebuf), strlen("PTE"));
	fprintf(fp, "%s  ", mkstring(buf, len1, CENTER|LJUST, "PTE"));

        if (!page_present && pte64) {
                swap_location(pte64, buf);
                if ((c = parse_line(buf, arglist)) != 3)
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

	sprintf(physbuf, "%llx", paddr);
	len2 = MAX(strlen(physbuf), strlen("PHYSICAL"));
	fprintf(fp, "%s  ", mkstring(buf, len2, CENTER|LJUST, "PHYSICAL"));

	fprintf(fp, "FLAGS\n");

	fprintf(fp, "%s  %s  ",  
		mkstring(ptebuf, len1, CENTER|RJUST, NULL),
		mkstring(physbuf, len2, CENTER|RJUST, NULL)); 
	fprintf(fp, "(");
	others = 0;

	if (pte64) {
		if (_PAGE_PRESENT &&
		    (pte64 & _PAGE_PRESENT) == _PAGE_PRESENT)
			fprintf(fp, "%sPRESENT", others++ ? "|" : "");
		if (_PAGE_USER &&
		    (pte64 & _PAGE_USER) == _PAGE_USER)
			fprintf(fp, "%sUSER", others++ ? "|" : "");
		if (_PAGE_RW &&
		    (pte64 & _PAGE_RW) == _PAGE_RW)
			fprintf(fp, "%sRW", others++ ? "|" : "");
		if (_PAGE_K_RW &&
		    ((pte64 & _PAGE_K_RW) == _PAGE_K_RW))
			fprintf(fp, "%sK-RW", others++ ? "|" : "");
		if (_PAGE_GUARDED &&
		    (pte64 & _PAGE_GUARDED) == _PAGE_GUARDED)
			fprintf(fp, "%sGUARDED", others++ ? "|" : "");
		if (_PAGE_COHERENT &&
		    (pte64 & _PAGE_COHERENT) == _PAGE_COHERENT)
			fprintf(fp, "%sCOHERENT", others++ ? "|" : "");
		if (_PAGE_NO_CACHE &&
		    (pte64 & _PAGE_NO_CACHE) == _PAGE_NO_CACHE)
			fprintf(fp, "%sNO_CACHE", others++ ? "|" : "");
		if (_PAGE_WRITETHRU &&
		    (pte64 & _PAGE_WRITETHRU) == _PAGE_WRITETHRU)
			fprintf(fp, "%sWRITETHRU", others++ ? "|" : "");
		if (_PAGE_DIRTY &&
		    (pte64 & _PAGE_DIRTY) == _PAGE_DIRTY)
			fprintf(fp, "%sDIRTY", others++ ? "|" : "");
		if (_PAGE_ACCESSED &&
		    (pte64 & _PAGE_ACCESSED) == _PAGE_ACCESSED)
			fprintf(fp, "%sACCESSED", others++ ? "|" : "");
		if (_PAGE_HWWRITE &&
		    (pte64 & _PAGE_HWWRITE) == _PAGE_HWWRITE)
			fprintf(fp, "%sHWWRITE", others++ ? "|" : "");
	} else
		fprintf(fp, "no mapping");

	fprintf(fp, ")\n");

	return page_present;
}


/*
 *  Look for likely exception frames in a stack.
 */

static int 
ppc_eframe_search(struct bt_info *bt)
{
	return (error(FATAL, "ppc_eframe_search: function not written yet!\n"));
}

static ulong
ppc_in_irqstack(ulong addr)
{
	int c;

	if (!(tt->flags & IRQSTACKS))
		return 0;

	for (c = 0; c < kt->cpus; c++) {
		if (tt->hardirq_ctx[c]) {
			if ((addr >= tt->hardirq_ctx[c]) &&
			    (addr < (tt->hardirq_ctx[c] + SIZE(irq_ctx))))
				return tt->hardirq_ctx[c];
		}
		if (tt->softirq_ctx[c]) {
			if ((addr >= tt->softirq_ctx[c]) &&
			    (addr < (tt->softirq_ctx[c] + SIZE(irq_ctx))))
				return tt->softirq_ctx[c];
		}
	}

	return 0;
}

/*
 *  Unroll a kernel stack.
 */
static void
ppc_back_trace_cmd(struct bt_info *bt)
{
	char buf[BUFSIZE];
	struct gnu_request *req;

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

        if (bt->flags & BT_USE_GDB) {
                strcpy(req->buf, "backtrace");
                gdb_interface(req);
        }
        else
                ppc_back_trace(req, bt);

        FREEBUF(req->buf);
        FREEBUF(req);
}

/*
 *  Unroll the kernel stack using a minimal amount of gdb services.
 */
static void
ppc_back_trace(struct gnu_request *req, struct bt_info *bt)
{
	int frame = 0;
	ulong lr = 0;
	ulong newpc = 0, newsp, marker;
	int eframe_found;

	if (!INSTACK(req->sp, bt)) {
		ulong irqstack;

		if ((irqstack = ppc_in_irqstack(req->sp))) {
			bt->stackbase = irqstack;
			bt->stacktop = bt->stackbase + SIZE(irq_ctx);
			alter_stackbuf(bt);
		} else {
			if (CRASHDEBUG(1))
				fprintf(fp, "cannot find the stack info.\n");
			return;
		}
	}

	while (INSTACK(req->sp, bt)) {
		newsp = *(ulong *)&bt->stackbuf[req->sp - bt->stackbase];
		if (IS_KVADDR(newsp) && INSTACK(newsp, bt))
			newpc = *(ulong *)&bt->stackbuf[newsp +
							STACK_FRAME_LR_SAVE -
							bt->stackbase];
		if ((req->name = closest_symbol(req->pc)) == NULL) {
			error(FATAL, 
				"ppc_back_trace hit unknown symbol (%lx).\n",
				req->pc);
			break;
		}

		bt->flags |= BT_SAVE_LASTSP;
		ppc_print_stack_entry(frame, req, newsp, lr, bt);
		bt->flags &= ~(ulonglong)BT_SAVE_LASTSP;
		lr = 0;

		if (BT_REFERENCE_FOUND(bt))
			return;

		eframe_found = FALSE;
		/*
		 * Is this frame an execption one?
		 * In 2.6, 0x72656773 is saved and used
		 * to determine the execption frame.
		 */
		if (THIS_KERNEL_VERSION < LINUX(2,6,0)) {
			if (frame && (newsp - req->sp - STACK_FRAME_OVERHEAD >=
				sizeof(struct ppc_pt_regs)))
				/* there might be an exception frame here... */
				eframe_found = TRUE;
			/* also possible ones here... */
			else if(!IS_KVADDR(newsp) || (newsp < req->sp))
				eframe_found = TRUE;
			else if (STREQ(req->name, ".ret_from_except"))
				eframe_found = TRUE;
		} else if ((newsp - req->sp - STACK_FRAME_OVERHEAD) >=
				sizeof(struct ppc_pt_regs)){
			readmem(req->sp + STACK_FRAME_MARKER, KVADDR, &marker,
				sizeof(ulong), "frame marker", FAULT_ON_ERROR);
			if (marker == STACK_FRAME_REGS_MARKER)
				eframe_found = TRUE;
		}
		if (eframe_found) {
			char *efrm_str;
			struct ppc_pt_regs regs;

			readmem(req->sp + STACK_FRAME_OVERHEAD, KVADDR, &regs,
				sizeof(struct ppc_pt_regs),
				"exception frame", FAULT_ON_ERROR);
			efrm_str = ppc_check_eframe(&regs);
			if (efrm_str) {
				ppc_print_eframe(efrm_str, &regs, bt);
				lr = regs.link;
				newpc = regs.nip;
				newsp = regs.gpr[1];
			}
		}

		if (STREQ(req->name, "start_kernel"))
			break;

		req->pc = newpc;
		req->sp = newsp;
		frame++;
	}

	return;
}

static void
ppc_display_full_frame(struct bt_info *bt, ulong nextsp, FILE *ofp)
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
ppc_print_stack_entry(int frame, 
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
                	req->sp, name_plus_offset ? name_plus_offset : req->name, req->pc);
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
					"ppc_back_trace hit unknown symbol (%lx).\n",
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
					"ppc_back_trace hit unknown symbol (%lx).\n",
						lr);
				return;
			}
			if (req->pc != lr) {
				fprintf(fp, "\n [Link Register ] ");
				fprintf(fp, " [%lx] %s at %lx",
					req->sp, lrname, lr);
			}
			req->ra = lr;
		}
		if (!req->name || STREQ(req->name,lrname))
			fprintf(fp, "  (unreliable)");
		fprintf(fp, "\n");
	}

	if (bt->flags & BT_SAVE_LASTSP)
		req->lastsp = req->sp;

	bt->frameptr = req->sp;
	if (bt->flags & BT_FULL)
		if (IS_KVADDR(newsp))
			ppc_display_full_frame(bt, newsp, fp);
	if (bt->flags & BT_LINE_NUMBERS)
		ppc_dump_line_number(req->pc);
}

/*
 *  Check whether the frame is exception one!
 */
static char *
ppc_check_eframe(struct ppc_pt_regs *regs)
{
	switch(regs->trap & ~0xF) {
	case 0x200:
		return "machine check";
	case 0x300:
		return "address error (store)";
	case 0x400:
		return "instruction bus error";
	case 0x500:
		return "interrupt";
	case 0x600:
		return "alingment";
	case 0x700:
		return "breakpoint trap";
	case 0x800:
		return "fpu unavailable";
	case 0x900:
		return "decrementer";
	case 0xa00:
		return "reserved";
	case 0xb00:
		return "reserved";
	case 0xc00:
		return "syscall";
	case 0xd00:
		return "single-step/watch";
	case 0xe00:
		return "fp assist";
	}
	/* No exception frame exists */
	return NULL;
}

static void
ppc_print_regs(struct ppc_pt_regs *regs)
{
	int i;

	/* print out the gprs... */
	for(i=0; i<32; i++) {
		if(!(i % 4))
			fprintf(fp, "\n");

		fprintf(fp, "R%d:%s %08lx   ", i,
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
	fprintf(fp, "NIP: %08lx   ", regs->nip);
	fprintf(fp, "MSR: %08lx   ", regs->msr);
	fprintf(fp, "OR3: %08lx   ", regs->orig_gpr3);
	fprintf(fp, "CTR: %08lx\n", regs->ctr);

	fprintf(fp, "LR:  %08lx   ", regs->link);
	fprintf(fp, "XER: %08lx   ", regs->xer);
	fprintf(fp, "CCR: %08lx   ", regs->ccr);
	fprintf(fp, "MQ:  %08lx\n", regs->mq);
	fprintf(fp, "DAR: %08lx ", regs->dar);
	fprintf(fp, "DSISR: %08lx ", regs->dsisr);
	fprintf(fp, "       Syscall Result: %08lx\n", regs->result);
}

/*
 * Print the exception frame information
 */
static void
ppc_print_eframe(char *efrm_str, struct ppc_pt_regs *regs, struct bt_info *bt)
{
	if (BT_REFERENCE_CHECK(bt))
		return;

	fprintf(fp, " %s  [%lx] exception frame:", efrm_str, regs->trap);
	ppc_print_regs(regs);
	fprintf(fp, "\n");
}

static void
ppc_kdump_stack_frame(struct bt_info *bt, ulong *nip, ulong *ksp)
{
	struct ppc_pt_regs *pt_regs;
	unsigned long ip, sp;

	ip = sp = 0;

	pt_regs = (struct ppc_pt_regs*)bt->machdep;

	if (!pt_regs || !(pt_regs->gpr[1])) {
		fprintf(fp, "0%lx: GPR1 register value(SP) was not saved\n",
			bt->task);
		return;
	}

	sp = pt_regs->gpr[1];

	if (!IS_KVADDR(sp)) {
		if (IN_TASK_VMA(bt->task, *ksp))
			fprintf(fp, "%0lx: Task is running in user space\n",
				bt->task);
		else 
			fprintf(fp, "%0lx: Invalid Stack Pointer %0lx\n",
				bt->task, *ksp);
	}

	ip = pt_regs->nip;

	if(nip)
		*nip = ip;
	if (ksp)
		*ksp = sp;

	if (bt->flags && 
		((BT_TEXT_SYMBOLS | BT_TEXT_SYMBOLS_PRINT |
			BT_TEXT_SYMBOLS_NOPRINT))) 
		return;
	/*
	 * Print the collected regs for the active task
	 */
	ppc_print_regs(pt_regs);

	if (!IS_KVADDR(sp)) 
		return;
	
	fprintf(fp, " NIP [%016lx] %s\n", pt_regs->nip,
		closest_symbol(pt_regs->nip));
	fprintf(fp, " LR  [%016lx] %s\n", pt_regs->link,
			closest_symbol(pt_regs->link));

	fprintf(fp, "\n");

	return;
}	
	
static void
ppc_dumpfile_stack_frame(struct bt_info *bt, ulong *getpc, ulong *getsp)
{
	struct syment *sp;

	/* 
	 * For KDUMP and compressed KDUMP get the SP, PC from pt_regs 
	 * read from the Elf Note. 
	 */
	if (ELF_NOTES_VALID()) {
		ppc_kdump_stack_frame(bt, getpc, getsp);
		return;
	}
	
	if (getpc) {
		if (!(sp = next_symbol("crash_save_current_state", NULL)))
			*getpc = (symbol_value("crash_save_current_state")+16);
        	else
			*getpc = (sp->value - 4);
	}
}

/*
 *  Get a stack frame combination of pc and ra from the most relevent spot.
 */
static void
ppc_get_stack_frame(struct bt_info *bt, ulong *pcp, ulong *spp)
{
	if (DUMPFILE() && is_task_active(bt->task))
		ppc_dumpfile_stack_frame(bt, pcp, spp);
	else
		get_ppc_frame(bt, pcp, spp);

}

/*
 *  Do the work for ppc_get_stack_frame() for non-active tasks
 */
static void
get_ppc_frame(struct bt_info *bt, ulong *getpc, ulong *getsp)
{
	ulong ip;
	ulong sp;
	ulong *stack;
	ulong task;
	struct ppc_pt_regs regs;

	ip = 0;
	task = bt->task;
	stack = (ulong *)bt->stackbuf;

        if ((tt->flags & THREAD_INFO) && VALID_MEMBER(task_struct_thread_ksp)) 
                readmem(task + OFFSET(task_struct_thread_ksp), KVADDR,
                        &sp, sizeof(void *),
                        "thread_struct ksp", FAULT_ON_ERROR);
	else if (VALID_MEMBER(task_struct_tss_ksp)) 
                sp = stack[OFFSET(task_struct_tss_ksp)/sizeof(long)];
	else 
                sp = stack[OFFSET(task_struct_thread_ksp)/sizeof(long)];

	if (!INSTACK(sp, bt))
		goto out;

	readmem(sp + STACK_FRAME_OVERHEAD, KVADDR, &regs,
		sizeof(struct ppc_pt_regs),
		"PPC pt_regs", FAULT_ON_ERROR);
	ip = regs.nip;
	if (STREQ(closest_symbol(ip), "__switch_to")) {
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
		if (!INSTACK(sp + 4, bt))
			goto out;
		ip = stack[(sp + 4 - bt->stackbase)/sizeof(ulong)];
	}
out:
	if (DUMPFILE() && getsp && STREQ(closest_symbol(sp), "panic")) {
		*getsp = sp;
		return;
	}

	if (getsp)
		*getsp = sp;
	if (getpc)
		*getpc = ip;

}

/*
 *  Do the work for cmd_irq().
 */
static void ppc_dump_irq(int irq)
{
        ulong irq_desc_addr, addr;
        int level, others;
        ulong action, ctl, value;
	char typename[32];
	int len;

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
		len = read_string(addr, typename, 32);
		
		if(len)
			fprintf(fp, "         typename: %08lx  \"%s\"\n", 
				addr, typename);
		
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
		len = read_string(addr, typename, 32);
		
		if(len)
			fprintf(fp, "             name: %08lx  \"%s\"\n", 
				addr, typename);

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
ppc_dis_filter(ulong vaddr, char *inbuf, unsigned int output_radix)
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
 *  (on alpha -- not necessarily seen on ppc) so this routine both fixes the 
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
 *   Override smp_num_cpus if possible and necessary.
 */
int
ppc_get_smp_cpus(void)
{
	return (get_cpus_online() > 0) ? get_cpus_online() : kt->cpus;
}

/*
 *  Machine dependent command.
 */
void
ppc_cmd_mach(void)
{
        int c;

        while ((c = getopt(argcnt, args, "")) != EOF) {
                switch(c)
                {
                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

	ppc_display_machine_stats();
}

/*
 *  "mach" command output.
 */
static void
ppc_display_machine_stats(void)
{
	int c;
        struct new_utsname *uts;
        char buf[BUFSIZE];
        ulong mhz;

        uts = &kt->utsname;

        fprintf(fp, "       MACHINE TYPE: %s\n", uts->machine);
        fprintf(fp, "           PLATFORM: %s\n", PPC_PLATFORM);
        fprintf(fp, "        MEMORY SIZE: %s\n", get_memory_size(buf));
        fprintf(fp, "               CPUS: %d\n", kt->cpus);
        fprintf(fp, "    PROCESSOR SPEED: ");
        if ((mhz = machdep->processor_speed()))
                fprintf(fp, "%ld Mhz\n", mhz);
        else
                fprintf(fp, "(unknown)\n");
        fprintf(fp, "                 HZ: %d\n", machdep->hz);
        fprintf(fp, "          PAGE SIZE: %d\n", PAGESIZE());
//      fprintf(fp, "      L1 CACHE SIZE: %d\n", l1_cache_size());
        fprintf(fp, "KERNEL VIRTUAL BASE: %lx\n", machdep->kvbase);
        fprintf(fp, "KERNEL VMALLOC BASE: %lx\n", vt->vmalloc_start);
        fprintf(fp, "  KERNEL STACK SIZE: %ld\n", STACKSIZE());

	if (tt->flags & IRQSTACKS) {
		fprintf(fp, "HARD IRQ STACK SIZE: %ld\n", SIZE(irq_ctx));
		fprintf(fp, "    HARD IRQ STACKS:\n");

		for (c = 0; c < kt->cpus; c++) {
			if (!tt->hardirq_ctx[c])
				break;
			sprintf(buf, "CPU %d", c);
			fprintf(fp, "%19s: %lx\n", buf, tt->hardirq_ctx[c]);
		}

		fprintf(fp, "SOFT IRQ STACK SIZE: %ld\n", SIZE(irq_ctx));
		fprintf(fp, "    SOFT IRQ STACKS:\n");
		for (c = 0; c < kt->cpus; c++) {
			if (!tt->softirq_ctx[c])
				break;
			sprintf(buf, "CPU %d", c);
			fprintf(fp, "%19s: %lx\n", buf, tt->softirq_ctx[c]);
		}
	}
}


static const char *hook_files[] = {
        "arch/ppc/kernel/entry.S",
        "arch/ppc/kernel/head.S",
};

#define ENTRY_S      ((char **)&hook_files[0])
#define HEAD_S       ((char **)&hook_files[1])

static struct line_number_hook ppc_line_number_hooks[] = {
	{"DoSyscall", ENTRY_S},
	{"_switch", ENTRY_S},
	{"ret_from_syscall_1", ENTRY_S},
	{"ret_from_syscall_2", ENTRY_S},
	{"ret_from_fork", ENTRY_S},
	{"ret_from_intercept", ENTRY_S},
	{"ret_from_except", ENTRY_S},
	{"do_signal_ret", ENTRY_S},
	{"ret_to_user_hook", ENTRY_S},
	{"enter_rtas", ENTRY_S},
	{"restore", ENTRY_S},
	{"fake_interrupt", ENTRY_S},
	{"lost_irq_ret", ENTRY_S},
	{"do_bottom_half_ret", ENTRY_S},
	{"ret_to_user_hook", ENTRY_S},
	{"signal_return", ENTRY_S},

	{"_stext", HEAD_S},
	{"_start", HEAD_S},
	{"__start", HEAD_S},
	{"__after_mmu_off", HEAD_S},
	{"turn_on_mmu", HEAD_S},
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
ppc_dump_line_number(ulong callpc)
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

/*
 * Try to relocate NT_PRSTATUS notes according by in kernel crash_notes.
 * Function is only called from ppc's get_regs.
 */
static int
verify_crash_note_in_kernel(int cpu)
{
	int ret;
	Elf32_Nhdr *note32;
	ulong crash_notes_ptr;
	char *buf, *name;

	ret = TRUE;
	if (!readmem(symbol_value("crash_notes"), KVADDR, &crash_notes_ptr,
		     sizeof(ulong), "crash_notes", QUIET|RETURN_ON_ERROR) ||
	    !crash_notes_ptr)
		goto out;

	buf = GETBUF(SIZE(note_buf));
	if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF))
		crash_notes_ptr += kt->__per_cpu_offset[cpu];
	if (!readmem(crash_notes_ptr, KVADDR, buf, SIZE(note_buf),
		     "cpu crash_notes", QUIET|RETURN_ON_ERROR))
		goto freebuf;

	note32 = (Elf32_Nhdr *)buf;
	name = (char *)(note32 + 1);
	if (note32->n_type != NT_PRSTATUS ||
	    note32->n_namesz != strlen("CORE") + 1 ||
	    strncmp(name, "CORE", note32->n_namesz) ||
	    note32->n_descsz != SIZE(elf_prstatus))
		ret = FALSE;
freebuf:
	FREEBUF(buf);
out:
	return ret;
}

void
ppc_relocate_nt_prstatus_percpu(void **nt_prstatus_percpu,
				uint *num_prstatus_notes)
{
	static int relocated = FALSE;
	void **nt_ptr;
	int i, j, nrcpus;
	size_t size;

	/* relocation is possible only once */
	if (relocated == TRUE)
		return;
	relocated = TRUE;
	if (!symbol_exists("crash_notes") ||
	    !VALID_STRUCT(note_buf) || !VALID_STRUCT(elf_prstatus))
		return;

	size = NR_CPUS * sizeof(void *);
	nt_ptr = (void **)GETBUF(size);
	BCOPY(nt_prstatus_percpu, nt_ptr, size);
	BZERO(nt_prstatus_percpu, size);

	*num_prstatus_notes = 0;
	nrcpus = (kt->kernel_NR_CPUS ? kt->kernel_NR_CPUS : NR_CPUS);
	for (i = 0, j = 0; i < nrcpus; i++) {
		if (!in_cpu_map(ONLINE_MAP, i))
			continue;
		if (verify_crash_note_in_kernel(i))
			nt_prstatus_percpu[i] = nt_ptr[j++];
		else if (CRASHDEBUG(1))
			error(WARNING, "cpu#%d: crash_notes not saved\n", i);
		/* num_prstatus_notes is always equal to online cpus in ppc */
		(*num_prstatus_notes)++;
	}
	FREEBUF(nt_ptr);
}
#endif /* PPC */
