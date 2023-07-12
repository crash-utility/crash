/* ia64.c - core analysis suite
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002-2013 David Anderson
 * Copyright (C) 2002-2013 Red Hat, Inc. All rights reserved.
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
#ifdef IA64 
#include "defs.h"
#include "xen_hyper_defs.h"
#include <sys/prctl.h>

static int ia64_verify_symbol(const char *, ulong, char);
static int ia64_eframe_search(struct bt_info *);
static void ia64_back_trace_cmd(struct bt_info *);
static void ia64_old_unwind(struct bt_info *);
static void ia64_old_unwind_init(void);
static void try_old_unwind(struct bt_info *);
static void ia64_dump_irq(int);
static ulong ia64_processor_speed(void);
static int ia64_vtop_4l(ulong, physaddr_t *paddr, ulong *pgd, int, int);
static int ia64_vtop(ulong, physaddr_t *paddr, ulong *pgd, int, int);
static int ia64_uvtop(struct task_context *, ulong, physaddr_t *, int);
static int ia64_kvtop(struct task_context *, ulong, physaddr_t *, int);
static ulong ia64_get_task_pgd(ulong);
static ulong ia64_get_pc(struct bt_info *);
static ulong ia64_get_sp(struct bt_info *);
static ulong ia64_get_thread_ksp(ulong);
static void ia64_get_stack_frame(struct bt_info *, ulong *, ulong *);
static int ia64_translate_pte(ulong, void *, ulonglong);
static ulong ia64_vmalloc_start(void);
static int ia64_is_task_addr(ulong);
static int ia64_dis_filter(ulong, char *, unsigned int);
static void ia64_dump_switch_stack(ulong, ulong);
static void ia64_cmd_mach(void);
static int ia64_get_smp_cpus(void);
static void ia64_display_machine_stats(void);
static void ia64_display_cpu_data(unsigned int);
static void ia64_display_memmap(void);
static void ia64_create_memmap(void);
static ulong check_mem_limit(void);
static int ia64_verify_paddr(uint64_t);
static int ia64_available_memory(struct efi_memory_desc_t *);
static void ia64_post_init(void);
static ulong ia64_in_per_cpu_mca_stack(void);
static struct line_number_hook ia64_line_number_hooks[];
static ulong ia64_get_stackbase(ulong);
static ulong ia64_get_stacktop(ulong);
static void parse_cmdline_args(void);
static void ia64_calc_phys_start(void);
static int ia64_get_kvaddr_ranges(struct vaddr_range *);

struct unw_frame_info;
static void dump_unw_frame_info(struct unw_frame_info *);
static int old_unw_unwind(struct unw_frame_info *);
static void unw_init_from_blocked_task(struct unw_frame_info *, ulong);
static ulong ia64_rse_slot_num(ulong *);
static ulong *ia64_rse_skip_regs(ulong *, long);
static ulong *ia64_rse_rnat_addr(ulong *);
static ulong rse_read_reg(struct unw_frame_info *, int, int *);
static void rse_function_params(struct unw_frame_info *, char *);

static int ia64_vtop_4l_xen_wpt(ulong, physaddr_t *paddr, ulong *pgd, int, int);
static int ia64_vtop_xen_wpt(ulong, physaddr_t *paddr, ulong *pgd, int, int);
static int ia64_xen_kdump_p2m_create(struct xen_kdump_data *);
static int ia64_xendump_p2m_create(struct xendump_data *);
static void ia64_debug_dump_page(FILE *, char *, char *);
static char *ia64_xendump_load_page(ulong, struct xendump_data *);
static int ia64_xendump_page_index(ulong, struct xendump_data *);
static ulong ia64_xendump_panic_task(struct xendump_data *);
static void ia64_get_xendump_regs(struct xendump_data *, struct bt_info *, ulong *, ulong *);

static void ia64_init_hyper(int);

struct machine_specific ia64_machine_specific = { 0 };

void
ia64_init(int when)
{
	struct syment *sp, *spn;

	if (XEN_HYPER_MODE()) {
		ia64_init_hyper(when);
		return;
	}

        switch (when)
        {
	case SETUP_ENV:
#if defined(PR_SET_FPEMU) && defined(PR_FPEMU_NOPRINT)
		prctl(PR_SET_FPEMU, PR_FPEMU_NOPRINT, 0, 0, 0);
#endif
#if defined(PR_SET_UNALIGN) && defined(PR_UNALIGN_NOPRINT)
		prctl(PR_SET_UNALIGN, PR_UNALIGN_NOPRINT, 0, 0, 0);
#endif
		break;

        case PRE_SYMTAB:
                machdep->verify_symbol = ia64_verify_symbol;
		machdep->machspec = &ia64_machine_specific;
		if (pc->flags & KERNEL_DEBUG_QUERY)
			return;
                machdep->pagesize = memory_page_size();
                machdep->pageshift = ffs(machdep->pagesize) - 1;
                machdep->pageoffset = machdep->pagesize - 1;
                machdep->pagemask = ~(machdep->pageoffset);
		switch (machdep->pagesize)
		{
		case 4096:
			machdep->stacksize = (power(2, 3) * PAGESIZE());
			break;
		case 8192:
			machdep->stacksize = (power(2, 2) * PAGESIZE());
			break;
		case 16384:
			machdep->stacksize = (power(2, 1) * PAGESIZE());
			break;
		case 65536:
			machdep->stacksize = (power(2, 0) * PAGESIZE());
			break;
		default:
			machdep->stacksize = 32*1024;
			break;
		}
                if ((machdep->pgd = (char *)malloc(PAGESIZE())) == NULL)
                        error(FATAL, "cannot malloc pgd space.");
		if ((machdep->pud = (char *)malloc(PAGESIZE())) == NULL)
			error(FATAL, "cannot malloc pud space.");
                if ((machdep->pmd = (char *)malloc(PAGESIZE())) == NULL)
                        error(FATAL, "cannot malloc pmd space.");
                if ((machdep->ptbl = (char *)malloc(PAGESIZE())) == NULL)
                        error(FATAL, "cannot malloc ptbl space.");
                machdep->last_pgd_read = 0;
                machdep->last_pud_read = 0;
                machdep->last_pmd_read = 0;
                machdep->last_ptbl_read = 0;
		machdep->verify_paddr = ia64_verify_paddr;
		machdep->get_kvaddr_ranges = ia64_get_kvaddr_ranges;
		machdep->ptrs_per_pgd = PTRS_PER_PGD;
                machdep->machspec->phys_start = UNKNOWN_PHYS_START;
                if (machdep->cmdline_args[0]) 
			parse_cmdline_args();
		if (ACTIVE())
			machdep->flags |= DEVMEMRD;
                break;     

        case PRE_GDB:

		if (pc->flags & KERNEL_DEBUG_QUERY)
			return;
		
		/*
		 * Until the kernel core dump and va_server library code
		 * do the right thing with respect to the configured page size,
		 * try to recognize a fatal inequity between the compiled-in 
		 * page size and the page size used by the kernel.
		 */ 
		

		if ((sp = symbol_search("empty_zero_page")) &&
		    (spn = next_symbol(NULL, sp)) && 
		    ((spn->value - sp->value) != PAGESIZE())) 
			error(FATAL, 
	        "compiled-in page size: %d  (apparent) kernel page size: %ld\n",
				PAGESIZE(), spn->value - sp->value);

                machdep->kvbase = KERNEL_VMALLOC_BASE;
		machdep->identity_map_base = KERNEL_CACHED_BASE;
                machdep->is_kvaddr = generic_is_kvaddr;
                machdep->is_uvaddr = generic_is_uvaddr;
                machdep->eframe_search = ia64_eframe_search;
                machdep->back_trace = ia64_back_trace_cmd;
                machdep->processor_speed = ia64_processor_speed;
                machdep->uvtop = ia64_uvtop;
                machdep->kvtop = ia64_kvtop;
                machdep->get_task_pgd = ia64_get_task_pgd;
                machdep->dump_irq = ia64_dump_irq;
		machdep->get_stack_frame = ia64_get_stack_frame;
		machdep->get_stackbase = ia64_get_stackbase;
		machdep->get_stacktop = ia64_get_stacktop;
                machdep->translate_pte = ia64_translate_pte;
                machdep->memory_size = generic_memory_size;
                machdep->vmalloc_start = ia64_vmalloc_start;
                machdep->is_task_addr = ia64_is_task_addr;
                machdep->dis_filter = ia64_dis_filter;
		machdep->cmd_mach = ia64_cmd_mach;
		machdep->get_smp_cpus = ia64_get_smp_cpus;
		machdep->line_number_hooks = ia64_line_number_hooks;
		machdep->value_to_symbol = generic_machdep_value_to_symbol;
                machdep->init_kernel_pgd = NULL;
		machdep->get_irq_affinity = generic_get_irq_affinity;
		machdep->show_interrupts = generic_show_interrupts;

		if ((sp = symbol_search("_stext"))) {
			machdep->machspec->kernel_region = 
				VADDR_REGION(sp->value);
			machdep->machspec->kernel_start = sp->value;
		} else {
			machdep->machspec->kernel_region = KERNEL_CACHED_REGION;
			machdep->machspec->kernel_start = KERNEL_CACHED_BASE;
		}
        	if (machdep->machspec->kernel_region == KERNEL_VMALLOC_REGION) {
                	machdep->machspec->vmalloc_start = 
				machdep->machspec->kernel_start +
				GIGABYTES((ulong)(4));
			if (machdep->machspec->phys_start == UNKNOWN_PHYS_START)
				ia64_calc_phys_start();
		} else
               		machdep->machspec->vmalloc_start = KERNEL_VMALLOC_BASE;

		machdep->xen_kdump_p2m_create = ia64_xen_kdump_p2m_create;
		machdep->xendump_p2m_create = ia64_xendump_p2m_create;
		machdep->xendump_panic_task = ia64_xendump_panic_task;
		machdep->get_xendump_regs = ia64_get_xendump_regs;
                break;

        case POST_GDB:
		STRUCT_SIZE_INIT(cpuinfo_ia64, "cpuinfo_ia64");
		STRUCT_SIZE_INIT(switch_stack, "switch_stack");
		MEMBER_OFFSET_INIT(thread_struct_fph, "thread_struct", "fph");
		MEMBER_OFFSET_INIT(switch_stack_b0, "switch_stack", "b0");
		MEMBER_OFFSET_INIT(switch_stack_ar_bspstore,  
			"switch_stack", "ar_bspstore");
		MEMBER_OFFSET_INIT(switch_stack_ar_pfs,  
			"switch_stack", "ar_pfs");
		MEMBER_OFFSET_INIT(switch_stack_ar_rnat, 
			"switch_stack", "ar_rnat");
		MEMBER_OFFSET_INIT(switch_stack_pr, 
			"switch_stack", "pr");
        	MEMBER_OFFSET_INIT(cpuinfo_ia64_proc_freq, 
			"cpuinfo_ia64", "proc_freq");
        	MEMBER_OFFSET_INIT(cpuinfo_ia64_unimpl_va_mask,
			"cpuinfo_ia64", "unimpl_va_mask");
        	MEMBER_OFFSET_INIT(cpuinfo_ia64_unimpl_pa_mask, 
			"cpuinfo_ia64", "unimpl_pa_mask");
		if (kernel_symbol_exists("nr_irqs"))
			get_symbol_data("nr_irqs", sizeof(unsigned int),
				&machdep->nr_irqs);
		else if (symbol_exists("irq_desc"))
		        ARRAY_LENGTH_INIT(machdep->nr_irqs, irq_desc, 
				"irq_desc", NULL, 0);
		else if (symbol_exists("_irq_desc"))
			ARRAY_LENGTH_INIT(machdep->nr_irqs, irq_desc, 
				"_irq_desc", NULL, 0);
		if (!machdep->hz)
			machdep->hz = 1024;
		machdep->section_size_bits = _SECTION_SIZE_BITS;
		machdep->max_physmem_bits = _MAX_PHYSMEM_BITS;
		ia64_create_memmap();
                break;

	case POST_INIT:
		ia64_post_init();
		break;

	case LOG_ONLY:
		machdep->machspec = &ia64_machine_specific;
		machdep->machspec->kernel_start = kt->vmcoreinfo._stext_SYMBOL;
		machdep->machspec->kernel_region = 
			VADDR_REGION(kt->vmcoreinfo._stext_SYMBOL);
		if (machdep->machspec->kernel_region == KERNEL_VMALLOC_REGION) {
			machdep->machspec->vmalloc_start = 
				machdep->machspec->kernel_start +
				GIGABYTES((ulong)(4));
			ia64_calc_phys_start();
		}
		break;
	}
}

/*
 *  --machdep <addr> defaults to the physical start location.
 *
 *  Otherwise, it's got to be a "item=value" string, separated
 *  by commas if more than one is passed in.
 */

void
parse_cmdline_args(void)
{
	int index, i, c, errflag;
	char *p;
	char buf[BUFSIZE];
	char *arglist[MAXARGS];
	ulong value;
        struct machine_specific *ms;
	int vm_flag;

        ms = &ia64_machine_specific;
	vm_flag = 0;

	for (index = 0; index < MAX_MACHDEP_ARGS; index++) {

		if (!machdep->cmdline_args[index])
			break;

		if (!strstr(machdep->cmdline_args[index], "=")) {
			errflag = 0;
	        	value = htol(machdep->cmdline_args[index],
	                	RETURN_ON_ERROR|QUIET, &errflag);
			if (!errflag) {
	        		ms->phys_start = value;
				error(NOTE, "setting phys_start to: 0x%lx\n",
					ms->phys_start);
			} else
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
			errflag = 0;
	
			if (STRNEQ(arglist[i], "phys_start=")) {
				p = arglist[i] + strlen("phys_start=");
				if (strlen(p)) {
	        			value = htol(p, RETURN_ON_ERROR|QUIET, 
						&errflag);
					if (!errflag) {
	        				ms->phys_start = value;
						error(NOTE, 
						    "setting phys_start to: 0x%lx\n",
							ms->phys_start);
						continue;
					}
				}
			} else if (STRNEQ(arglist[i], "init_stack_size=")) {
				p = arglist[i] + strlen("init_stack_size=");
				if (strlen(p)) {
					value = stol(p, RETURN_ON_ERROR|QUIET, 
						&errflag);
					if (!errflag) {
						ms->ia64_init_stack_size = (int)value;
						error(NOTE, 
			    	    	      "setting init_stack_size to: 0x%x (%d)\n",
					    		ms->ia64_init_stack_size,
					    		ms->ia64_init_stack_size);
						continue;
					}
				}
			} else if (STRNEQ(arglist[i], "vm=")) {
				vm_flag++;
				p = arglist[i] + strlen("vm=");
				if (strlen(p)) {
					if (STREQ(p, "4l")) {
						machdep->flags |= VM_4_LEVEL;
						continue;
					}
				}
			}
	
			error(WARNING, "ignoring --machdep option: %s\n", arglist[i]);
		} 
	
		if (vm_flag) {
			switch (machdep->flags & (VM_4_LEVEL))
			{
				case VM_4_LEVEL:
					error(NOTE, "using 4-level pagetable\n");
					c++;
					break;
					
				default:
					error(WARNING, "invalid vm= option\n");
					c++;
					machdep->flags &= ~(VM_4_LEVEL);
					break;
			} 
		}
	
	
		if (c)
			fprintf(fp, "\n");
	}
}


int
ia64_in_init_stack(ulong addr)
{
	ulong init_stack_addr;

	if (!symbol_exists("ia64_init_stack"))
		return FALSE;

	/* 
	 *  ia64_init_stack could be aliased to region 5 
	 */
	init_stack_addr = ia64_VTOP(symbol_value("ia64_init_stack"));
	addr = ia64_VTOP(addr);
	if ((addr < init_stack_addr) ||
	    (addr >= (init_stack_addr+machdep->machspec->ia64_init_stack_size)))
		return FALSE;

	return TRUE;
}


static ulong
ia64_in_per_cpu_mca_stack(void)
{
	int plen, i;
	ulong flag;
	ulong vaddr, paddr, stackbase, stacktop;
	ulong *__per_cpu_mca;
	struct task_context *tc;

	tc = CURRENT_CONTEXT();

	if (STRNEQ(CURRENT_COMM(), "INIT"))
		flag = INIT;
	else if (STRNEQ(CURRENT_COMM(), "MCA"))
		flag = MCA;
	else
		return 0;

	if (!symbol_exists("__per_cpu_mca") ||
	    !(plen = get_array_length("__per_cpu_mca", NULL, 0)) ||
	    (plen < kt->cpus))
		return 0;

	vaddr = SWITCH_STACK_ADDR(CURRENT_TASK());
	if (VADDR_REGION(vaddr) != KERNEL_CACHED_REGION)
		return 0;
	paddr = ia64_VTOP(vaddr);

	__per_cpu_mca = (ulong *)GETBUF(sizeof(ulong) * kt->cpus);

	if (!readmem(symbol_value("__per_cpu_mca"), KVADDR, __per_cpu_mca,
	    sizeof(ulong) * kt->cpus, "__per_cpu_mca", RETURN_ON_ERROR|QUIET))
		return 0;

	if (CRASHDEBUG(1)) {
		for (i = 0; i < kt->cpus; i++) {
			fprintf(fp, "__per_cpu_mca[%d]: %lx\n", 
		 		i, __per_cpu_mca[i]);
		}
	}

	stackbase = __per_cpu_mca[tc->processor];
	stacktop = stackbase + (STACKSIZE() * 2);
	FREEBUF(__per_cpu_mca);

	if ((paddr >= stackbase) && (paddr < stacktop))
		return flag;
	else
		return 0;
}

void
ia64_dump_machdep_table(ulong arg)
{
        int i, others, verbose;
	struct machine_specific *ms;

	verbose = FALSE;
	ms = &ia64_machine_specific;

	if (arg) {
		switch (arg)
		{
		default:
		case 1:
			verbose = TRUE;
			break;

		case 2: 
			if (machdep->flags & NEW_UNWIND) {
				machdep->flags &= 
				        ~(NEW_UNWIND|NEW_UNW_V1|NEW_UNW_V2|NEW_UNW_V3);
				machdep->flags |= OLD_UNWIND;
                        	ms->unwind_init = ia64_old_unwind_init;
                        	ms->unwind = ia64_old_unwind;
                        	ms->dump_unwind_stats = NULL;
                        	ms->unwind_debug = NULL;
			} else {
				machdep->flags &= ~OLD_UNWIND;
				machdep->flags |= NEW_UNWIND;
				if (MEMBER_EXISTS("unw_frame_info", "pt")) {
					if (MEMBER_EXISTS("pt_regs", "ar_csd")) {
						machdep->flags |= NEW_UNW_V3;
                        			ms->unwind_init = unwind_init_v3;
                        			ms->unwind = unwind_v3;
                        			ms->unwind_debug = unwind_debug_v3;
                        			ms->dump_unwind_stats = 
							dump_unwind_stats_v3;
					} else {
						machdep->flags |= NEW_UNW_V2;
                        			ms->unwind_init = unwind_init_v2;
                        			ms->unwind = unwind_v2;
                        			ms->unwind_debug = unwind_debug_v2;
                        			ms->dump_unwind_stats = 
							dump_unwind_stats_v2;
					}
				} else {
					machdep->flags |= NEW_UNW_V1;
                        		ms->unwind_init = unwind_init_v1;
                        		ms->unwind = unwind_v1;
                        		ms->unwind_debug = unwind_debug_v1;
                        		ms->dump_unwind_stats = 
						dump_unwind_stats_v1;
				}
			}
			ms->unwind_init();
			return;

		case 3:
			if (machdep->flags & NEW_UNWIND) 
				ms->unwind_debug(arg);
			return;
		}
	}

        others = 0;
        fprintf(fp, "              flags: %lx (", machdep->flags);
        /* future flags tests here */
	if (machdep->flags & NEW_UNWIND)
		fprintf(fp, "%sNEW_UNWIND", others++ ? "|" : "");
	if (machdep->flags & NEW_UNW_V1)
		fprintf(fp, "%sNEW_UNW_V1", others++ ? "|" : "");
	if (machdep->flags & NEW_UNW_V2)
		fprintf(fp, "%sNEW_UNW_V2", others++ ? "|" : "");
	if (machdep->flags & NEW_UNW_V3)
		fprintf(fp, "%sNEW_UNW_V3", others++ ? "|" : "");
	if (machdep->flags & OLD_UNWIND)
		fprintf(fp, "%sOLD_UNWIND", others++ ? "|" : "");
	if (machdep->flags & UNW_OUT_OF_SYNC)
		fprintf(fp, "%sUNW_OUT_OF_SYNC", others++ ? "|" : "");
	if (machdep->flags & UNW_READ)
		fprintf(fp, "%sUNW_READ", others++ ? "|" : "");
	if (machdep->flags & UNW_PTREGS)
		fprintf(fp, "%sUNW_PTREGS", others++ ? "|" : "");
	if (machdep->flags & UNW_R0)
		fprintf(fp, "%sUNW_R0", others++ ? "|" : "");
	if (machdep->flags & MEM_LIMIT)
		fprintf(fp, "%sMEM_LIMIT", others++ ? "|" : "");
	if (machdep->flags & DEVMEMRD)
		fprintf(fp, "%sDEVMEMRD", others++ ? "|" : "");
	if (machdep->flags & INIT)
		fprintf(fp, "%sINIT", others++ ? "|" : "");
	if (machdep->flags & MCA)
		fprintf(fp, "%sMCA", others++ ? "|" : "");
	if (machdep->flags & VM_4_LEVEL)
		fprintf(fp, "%sVM_4_LEVEL", others++ ? "|" : "");
        fprintf(fp, ")\n");
        fprintf(fp, "             kvbase: %lx\n", machdep->kvbase);
	fprintf(fp, "  identity_map_base: %lx\n", machdep->identity_map_base);
        fprintf(fp, "           pagesize: %d\n", machdep->pagesize);
        fprintf(fp, "          pageshift: %d\n", machdep->pageshift);
        fprintf(fp, "           pagemask: %llx\n", machdep->pagemask);
        fprintf(fp, "         pageoffset: %lx\n", machdep->pageoffset);
        fprintf(fp, "          stacksize: %ld\n", machdep->stacksize);
        fprintf(fp, "                 hz: %d\n", machdep->hz);
        fprintf(fp, "                mhz: %d\n", machdep->hz);
        fprintf(fp, "            memsize: %ld (0x%lx)\n", 
		machdep->memsize, machdep->memsize);
	fprintf(fp, "               bits: %d\n", machdep->bits);
        fprintf(fp, "            nr_irqs: %d\n", machdep->nr_irqs);
        fprintf(fp, "      eframe_search: ia64_eframe_search()\n");
        fprintf(fp, "         back_trace: ia64_back_trace_cmd()\n");
        fprintf(fp, "get_processor_speed: ia64_processor_speed()\n");
        fprintf(fp, "              uvtop: ia64_uvtop()\n");
        fprintf(fp, "              kvtop: ia64_kvtop()\n");
        fprintf(fp, "       get_task_pgd: ia64_get_task_pgd()\n");
        fprintf(fp, "           dump_irq: ia64_dump_irq()\n");
	fprintf(fp, "    get_stack_frame: ia64_get_stack_frame()\n");
	fprintf(fp, "      get_stackbase: ia64_get_stackbase()\n");
	fprintf(fp, "       get_stacktop: ia64_get_stacktop()\n");
        fprintf(fp, "      translate_pte: ia64_translate_pte()\n");
        fprintf(fp, "        memory_size: generic_memory_size()\n");
        fprintf(fp, "      vmalloc_start: ia64_vmalloc_start()\n");
        fprintf(fp, "       is_task_addr: ia64_is_task_addr()\n");
        fprintf(fp, "      verify_symbol: ia64_verify_symbol()\n");
        fprintf(fp, "         dis_filter: ia64_dis_filter()\n");
        fprintf(fp, "           cmd_mach: ia64_cmd_mach()\n");
        fprintf(fp, "       get_smp_cpus: ia64_get_smp_cpus()\n");
	fprintf(fp, "  get_kvaddr_ranges: ia64_get_kvaddr_ranges()\n");
        fprintf(fp, "          is_kvaddr: generic_is_kvaddr()\n");
        fprintf(fp, "          is_uvaddr: generic_is_uvaddr()\n");
        fprintf(fp, "       verify_paddr: %s()\n",
		(machdep->verify_paddr == ia64_verify_paddr) ?
		"ia64_verify_paddr" : "generic_verify_paddr");
	fprintf(fp, "   get_irq_affinity: generic_get_irq_affinity()\n");
	fprintf(fp, "    show_interrupts: generic_show_interrupts()\n");
        fprintf(fp, "    init_kernel_pgd: NULL\n");
	fprintf(fp, "xen_kdump_p2m_create: ia64_xen_kdump_p2m_create()\n");
        fprintf(fp, " xendump_p2m_create: ia64_xendump_p2m_create()\n");
	fprintf(fp, " xendump_panic_task: ia64_xendump_panic_task()\n");
	fprintf(fp, "   get_xendump_regs: ia64_get_xendump_regs()\n");
	fprintf(fp, "    value_to_symbol: generic_machdep_value_to_symbol()\n");
        fprintf(fp, "  line_number_hooks: ia64_line_number_hooks\n");
        fprintf(fp, "      last_pgd_read: %lx\n", machdep->last_pgd_read);
        fprintf(fp, "      last_pud_read: %lx\n", machdep->last_pud_read);
        fprintf(fp, "      last_pmd_read: %lx\n", machdep->last_pmd_read);
        fprintf(fp, "     last_ptbl_read: %lx\n", machdep->last_ptbl_read);
        fprintf(fp, "                pgd: %lx\n", (ulong)machdep->pgd);
        fprintf(fp, "                pud: %lx\n", (ulong)machdep->pud);
        fprintf(fp, "                pmd: %lx\n", (ulong)machdep->pmd);
        fprintf(fp, "               ptbl: %lx\n", (ulong)machdep->ptbl);
	fprintf(fp, "       ptrs_per_pgd: %d\n", machdep->ptrs_per_pgd);
        for (i = 0; i < MAX_MACHDEP_ARGS; i++) {
                fprintf(fp, "    cmdline_args[%d]: %s\n",
                        i, machdep->cmdline_args[i] ?
                        machdep->cmdline_args[i] : "(unused)");
        }
        fprintf(fp, "  section_size_bits: %ld\n", machdep->section_size_bits);
        fprintf(fp, "   max_physmem_bits: %ld\n", machdep->max_physmem_bits);
        fprintf(fp, "  sections_per_root: %ld\n", machdep->sections_per_root);
        fprintf(fp, "           machspec: ia64_machine_specific\n");
	fprintf(fp, "                   cpu_data_address: %lx\n", 
			machdep->machspec->cpu_data_address);
	fprintf(fp, "                     unimpl_va_mask: %lx\n", 
		machdep->machspec->unimpl_va_mask);
	fprintf(fp, "                     unimpl_pa_mask: %lx\n",
		machdep->machspec->unimpl_pa_mask);
	fprintf(fp, "                                unw: %lx\n",
		(ulong)machdep->machspec->unw);
	fprintf(fp, "                  unw_tables_offset: %ld\n",
		machdep->machspec->unw_tables_offset);
	fprintf(fp, "            unw_kernel_table_offset: %ld %s\n",
		machdep->machspec->unw_kernel_table_offset,
		machdep->machspec->unw_kernel_table_offset ? "" : "(unused)");
	fprintf(fp, "                unw_pt_regs_offsets: %ld %s\n",
		machdep->machspec->unw_pt_regs_offsets,
		machdep->machspec->unw_pt_regs_offsets ? "" : "(unused)");
	fprintf(fp, "                       script_index: %d\n",
		machdep->machspec->script_index);
	fprintf(fp, "                       script_cache: %lx%s",
		(ulong)machdep->machspec->script_cache,
		machdep->flags & OLD_UNWIND ? "\n" : " ");
	if (machdep->flags & NEW_UNWIND)
		ms->dump_unwind_stats();
	if (!(machdep->flags & (NEW_UNWIND|OLD_UNWIND)))
		fprintf(fp, "\n");
	fprintf(fp, "                          mem_limit: %lx\n", 
		machdep->machspec->mem_limit);
	fprintf(fp, "                      kernel_region: %ld\n", 
		machdep->machspec->kernel_region);
	fprintf(fp, "                       kernel_start: %lx\n", 
		machdep->machspec->kernel_start);
	fprintf(fp, "                         phys_start: %lx (%lx)\n", 
		machdep->machspec->phys_start,
		machdep->machspec->phys_start & KERNEL_TR_PAGE_MASK);
	fprintf(fp, "                      vmalloc_start: %lx\n", 
		machdep->machspec->vmalloc_start);

	fprintf(fp, "                        ia64_memmap: %lx\n", 
		(ulong)machdep->machspec->ia64_memmap);
	fprintf(fp, "                    efi_memmap_size: %ld\n", 
		(ulong)machdep->machspec->efi_memmap_size);
	fprintf(fp, "                   efi_memdesc_size: %ld\n", 
		(ulong)machdep->machspec->efi_memdesc_size);

	fprintf(fp, "                        unwind_init: ");
	if (ms->unwind_init == unwind_init_v1)
		fprintf(fp, "unwind_init_v1()\n");
	else if (ms->unwind_init == unwind_init_v2)
		fprintf(fp, "unwind_init_v2()\n");
	else if (ms->unwind_init == unwind_init_v3)
		fprintf(fp, "unwind_init_v3()\n");
	else if (ms->unwind_init == ia64_old_unwind_init)
		fprintf(fp, "ia64_old_unwind_init()\n");
	else 
		fprintf(fp, "%lx\n", (ulong)ms->unwind_init);

	fprintf(fp, "                             unwind: ");
        if (ms->unwind == unwind_v1)
                fprintf(fp, "unwind_v1()\n");
        else if (ms->unwind == unwind_v2)
                fprintf(fp, "unwind_v2()\n");
        else if (ms->unwind == unwind_v3)
                fprintf(fp, "unwind_v3()\n");
	else if (ms->unwind == ia64_old_unwind)
		fprintf(fp, "ia64_old_unwind()\n");
        else
                fprintf(fp, "%lx\n", (ulong)ms->unwind);

	fprintf(fp, "                  dump_unwind_stats: ");
        if (ms->dump_unwind_stats == dump_unwind_stats_v1)
                fprintf(fp, "dump_unwind_stats_v1()\n");
        else if (ms->dump_unwind_stats == dump_unwind_stats_v2)
                fprintf(fp, "dump_unwind_stats_v2()\n");
        else if (ms->dump_unwind_stats == dump_unwind_stats_v3)
                fprintf(fp, "dump_unwind_stats_v3()\n");
        else
                fprintf(fp, "%lx\n", (ulong)ms->dump_unwind_stats);

	fprintf(fp, "                       unwind_debug: ");
        if (ms->unwind_debug == unwind_debug_v1)
                fprintf(fp, "unwind_debug_v1()\n");
        else if (ms->unwind_debug == unwind_debug_v2)
                fprintf(fp, "unwind_debug_v2()\n");
        else if (ms->unwind_debug == unwind_debug_v3)
                fprintf(fp, "unwind_debug_v3()\n");
        else
                fprintf(fp, "%lx\n", (ulong)ms->unwind_debug);

	fprintf(fp, "               ia64_init_stack_size: %d\n", 
		ms->ia64_init_stack_size);

	if (verbose)
		ia64_display_memmap();
}

/*
 *  Keep or reject a symbol from the namelist.
 */
static int
ia64_verify_symbol(const char *name, ulong value, char type)
{
	ulong region;

	if (!name || !strlen(name))
		return FALSE;

	if (XEN_HYPER_MODE() && STREQ(name, "__per_cpu_shift"))
		return TRUE;

        if (CRASHDEBUG(8))
                fprintf(fp, "%016lx %s\n", value, name);

//	if (STREQ(name, "phys_start") && type == 'A')
//		if (machdep->machspec->phys_start == UNKNOWN_PHYS_START)
//			machdep->machspec->phys_start = value;

	region = VADDR_REGION(value);

	return (((region == KERNEL_CACHED_REGION) ||
		 (region == KERNEL_VMALLOC_REGION)));
}


/*
 *   Look for likely exception frames in a stack.
 */
static int 
ia64_eframe_search(struct bt_info *bt)
{
	return(error(FATAL, 
	    "ia64_eframe_search: not available for this architecture\n"));
}


/*
 *  Unroll a kernel stack.
 */

#define BT_SWITCH_STACK BT_SYMBOLIC_ARGS

static void
ia64_back_trace_cmd(struct bt_info *bt)
{
	struct machine_specific *ms = &ia64_machine_specific;

	if (bt->flags & BT_SWITCH_STACK)
        	ia64_dump_switch_stack(bt->task, 0);

        if (machdep->flags & UNW_OUT_OF_SYNC) 
                error(FATAL,
                    "kernel and %s unwind data structures are out of sync\n",
                        pc->program_name);

	ms->unwind(bt);

	if (bt->flags & BT_UNWIND_ERROR) 
		try_old_unwind(bt);
}


/*
 *  Dump the IRQ table.
 */
static void
ia64_dump_irq(int irq)
{
	if (kernel_symbol_exists("sparse_irqs") ||
	    symbol_exists("irq_desc") || symbol_exists("_irq_desc") ||
	    kernel_symbol_exists("irq_desc_ptrs")) {
                machdep->dump_irq = generic_dump_irq;
                return(generic_dump_irq(irq));
        }

	error(FATAL, 
		"ia64_dump_irq: neither irq_desc or _irq_desc exist\n");
}


/*      
 *  Calculate and return the speed of the processor. 
 */
static ulong 
ia64_processor_speed(void)
{
	ulong mhz, proc_freq;
	int bootstrap_processor;

	if (machdep->mhz)
		return(machdep->mhz);

	mhz = 0;
	bootstrap_processor = 0;

	if (!machdep->machspec->cpu_data_address ||
	    !VALID_STRUCT(cpuinfo_ia64) ||
	    !VALID_MEMBER(cpuinfo_ia64_proc_freq))
		return (machdep->mhz = mhz);

	if (symbol_exists("bootstrap_processor"))
		get_symbol_data("bootstrap_processor", sizeof(int), 
			&bootstrap_processor);
	if (bootstrap_processor == -1)
		bootstrap_processor = 0;

        readmem(machdep->machspec->cpu_data_address + 
		OFFSET(cpuinfo_ia64_proc_freq),
        	KVADDR, &proc_freq, sizeof(ulong),
                "cpuinfo_ia64 proc_freq", FAULT_ON_ERROR);

	mhz = proc_freq/1000000;

	return (machdep->mhz = mhz);
}

/* Generic abstraction to translate user or kernel virtual
 * addresses to physical using a 4 level page table.
 */
static int
ia64_vtop_4l(ulong vaddr, physaddr_t *paddr, ulong *pgd, int verbose, int usr)
{
	ulong *page_dir;
	ulong *page_upper;
	ulong *page_middle;
	ulong *page_table;
	ulong pgd_pte;
	ulong pud_pte;
	ulong pmd_pte;
	ulong pte;
	ulong region, offset;

	if (usr) {
		region = VADDR_REGION(vaddr);
		offset = (vaddr >> PGDIR_SHIFT) & ((PTRS_PER_PGD >> 3) - 1);
		offset |= (region << (PAGESHIFT() - 6));
		page_dir = pgd + offset;
	} else {
		if (!(pgd = (ulong *)vt->kernel_pgd[0]))
			error(FATAL, "cannot determine kernel pgd pointer\n");
		page_dir = pgd + ((vaddr >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1));
	}

	if (verbose) 
		fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)pgd);

	FILL_PGD(PAGEBASE(pgd), KVADDR, PAGESIZE());
	pgd_pte = ULONG(machdep->pgd + PAGEOFFSET(page_dir));
	
        if (verbose) 
                fprintf(fp, "   PGD: %lx => %lx\n", (ulong)page_dir, pgd_pte);

        if (!(pgd_pte))
		return FALSE;
	
	offset = (vaddr >> PUD_SHIFT) & (PTRS_PER_PUD - 1);
	page_upper = (ulong *)(PTOV(pgd_pte & _PFN_MASK)) + offset; 
	
	FILL_PUD(PAGEBASE(page_upper), KVADDR, PAGESIZE());
	pud_pte = ULONG(machdep->pud + PAGEOFFSET(page_upper));
        
	if (verbose) 
                fprintf(fp, "   PUD: %lx => %lx\n", (ulong)page_upper, pud_pte);
        
	if (!(pud_pte))
		return FALSE;

	offset = (vaddr >> PMD_SHIFT) & (PTRS_PER_PMD - 1);
	page_middle = (ulong *)(PTOV(pud_pte & _PFN_MASK)) + offset; 

	FILL_PMD(PAGEBASE(page_middle), KVADDR, PAGESIZE());
	pmd_pte = ULONG(machdep->pmd + PAGEOFFSET(page_middle));

        if (verbose)
                fprintf(fp, "   PMD: %lx => %lx\n", (ulong)page_middle, pmd_pte);

        if (!(pmd_pte))
		return FALSE;

        offset = (vaddr >> PAGESHIFT()) & (PTRS_PER_PTE - 1);
        page_table = (ulong *)(PTOV(pmd_pte & _PFN_MASK)) + offset;

	FILL_PTBL(PAGEBASE(page_table), KVADDR, PAGESIZE());
	pte = ULONG(machdep->ptbl + PAGEOFFSET(page_table));

        if (verbose)
                fprintf(fp, "   PTE: %lx => %lx\n", (ulong)page_table, pte);

        if (!(pte & (_PAGE_P | _PAGE_PROTNONE))) {
		if (usr)
		  	*paddr = pte;
		if (pte && verbose) {
			fprintf(fp, "\n");
			ia64_translate_pte(pte, 0, 0);
		}
		return FALSE;
        }

        *paddr = (pte & _PFN_MASK) + PAGEOFFSET(vaddr);

        if (verbose) {
                fprintf(fp, "  PAGE: %lx\n\n", PAGEBASE(*paddr));
		ia64_translate_pte(pte, 0, 0);
	}

	return TRUE;
}

/* Generic abstraction to translate user or kernel virtual
 * addresses to physical using a 3 level page table.
 */
static int
ia64_vtop(ulong vaddr, physaddr_t *paddr, ulong *pgd, int verbose, int usr)
{
	ulong *page_dir;
	ulong *page_middle;
	ulong *page_table;
	ulong pgd_pte;
	ulong pmd_pte;
	ulong pte;
	ulong region, offset;

	if (usr) {
		region = VADDR_REGION(vaddr);
		offset = (vaddr >> PGDIR_SHIFT_3L) & ((PTRS_PER_PGD >> 3) - 1);
		offset |= (region << (PAGESHIFT() - 6));
		page_dir = pgd + offset;
	} else {
		if (!(pgd = (ulong *)vt->kernel_pgd[0]))
			error(FATAL, "cannot determine kernel pgd pointer\n");
		page_dir = pgd + ((vaddr >> PGDIR_SHIFT_3L) & (PTRS_PER_PGD - 1));
	}

	if (verbose)
		fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)pgd);
	
	FILL_PGD(PAGEBASE(pgd), KVADDR, PAGESIZE());
	pgd_pte = ULONG(machdep->pgd + PAGEOFFSET(page_dir));
	
        if (verbose) 
                fprintf(fp, "   PGD: %lx => %lx\n", (ulong)page_dir, pgd_pte);

        if (!(pgd_pte))
		return FALSE;

	offset = (vaddr >> PMD_SHIFT) & (PTRS_PER_PMD - 1);
	page_middle = (ulong *)(PTOV(pgd_pte & _PFN_MASK)) + offset; 

	FILL_PMD(PAGEBASE(page_middle), KVADDR, PAGESIZE());
	pmd_pte = ULONG(machdep->pmd + PAGEOFFSET(page_middle));

        if (verbose)
                fprintf(fp, "   PMD: %lx => %lx\n", (ulong)page_middle, pmd_pte);

        if (!(pmd_pte))
		return FALSE;

        offset = (vaddr >> PAGESHIFT()) & (PTRS_PER_PTE - 1);
        page_table = (ulong *)(PTOV(pmd_pte & _PFN_MASK)) + offset;

	FILL_PTBL(PAGEBASE(page_table), KVADDR, PAGESIZE());
	pte = ULONG(machdep->ptbl + PAGEOFFSET(page_table));

        if (verbose)
                fprintf(fp, "   PTE: %lx => %lx\n", (ulong)page_table, pte);

        if (!(pte & (_PAGE_P | _PAGE_PROTNONE))) {
		if (usr)
		  	*paddr = pte;
		if (pte && verbose) {
			fprintf(fp, "\n");
			ia64_translate_pte(pte, 0, 0);
		}
		return FALSE;
        }

        *paddr = (pte & _PFN_MASK) + PAGEOFFSET(vaddr);

        if (verbose) {
                fprintf(fp, "  PAGE: %lx\n\n", PAGEBASE(*paddr));
		ia64_translate_pte(pte, 0, 0);
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
 *  swapper_pg_dir, making it irrelevant in this processor's case.
 */
static int
ia64_uvtop(struct task_context *tc, ulong uvaddr, physaddr_t *paddr, int verbose)
{
	ulong mm;
	ulong *pgd;

	if (!tc)
		error(FATAL, "current context invalid\n");

	*paddr = 0;

	if (IS_KVADDR(uvaddr))
		return ia64_kvtop(tc, uvaddr, paddr, verbose);

	if ((mm = task_mm(tc->task, TRUE)))
        	pgd = ULONG_PTR(tt->mm_struct + OFFSET(mm_struct_pgd));
	else
		readmem(tc->mm_struct + OFFSET(mm_struct_pgd), KVADDR, &pgd,
			sizeof(long), "mm_struct pgd", FAULT_ON_ERROR);

	if (XEN() && (kt->xen_flags & WRITABLE_PAGE_TABLES)) {
                if (machdep->flags & VM_4_LEVEL)
                        return ia64_vtop_4l_xen_wpt(uvaddr, paddr, pgd, verbose, 1);
                else
                        return ia64_vtop_xen_wpt(uvaddr, paddr, pgd, verbose, 1);
	} else {
		if (machdep->flags & VM_4_LEVEL)
			return ia64_vtop_4l(uvaddr, paddr, pgd, verbose, 1);
		else
			return ia64_vtop(uvaddr, paddr, pgd, verbose, 1);
	}
	
}


/*
 *  Translates a kernel virtual address to its physical address.  cmd_vtop()
 *  sets the verbose flag so that the pte translation gets displayed; all
 *  other callers quietly accept the translation.
 */
static int
ia64_kvtop(struct task_context *tc, ulong kvaddr, physaddr_t *paddr, int verbose)
{
        ulong *pgd;

        if (!IS_KVADDR(kvaddr))
                return FALSE;

        if (!vt->vmalloc_start) {
                *paddr = ia64_VTOP(kvaddr);
                return TRUE;
        }

	switch (VADDR_REGION(kvaddr))
	{
	case KERNEL_UNCACHED_REGION:
		*paddr = kvaddr - KERNEL_UNCACHED_BASE;
		if (verbose)
			fprintf(fp, "[UNCACHED MEMORY]\n");
                return TRUE;

	case KERNEL_CACHED_REGION:
                *paddr = ia64_VTOP(kvaddr);
		if (verbose)
			fprintf(fp, "[MAPPED IN TRANSLATION REGISTER]\n");
                return TRUE;

	case KERNEL_VMALLOC_REGION:
		if (ia64_IS_VMALLOC_ADDR(kvaddr))
			break;
		if ((kvaddr < machdep->machspec->kernel_start) &&
		    (machdep->machspec->kernel_region == 
		    KERNEL_VMALLOC_REGION)) {
			*paddr = PADDR_NOT_AVAILABLE;
			return FALSE;
		}
                *paddr = ia64_VTOP(kvaddr);
		if (verbose)
			fprintf(fp, "[MAPPED IN TRANSLATION REGISTER]\n");
                return TRUE;
        }

        if (!(pgd = (ulong *)vt->kernel_pgd[0]))
		error(FATAL, "cannot determine kernel pgd pointer\n");

	if (XEN() && (kt->xen_flags & WRITABLE_PAGE_TABLES)) {
                if (machdep->flags & VM_4_LEVEL)
                        return ia64_vtop_4l_xen_wpt(kvaddr, paddr, pgd, verbose, 0);
                else
                        return ia64_vtop_xen_wpt(kvaddr, paddr, pgd, verbose, 0);
	} else {
		if (machdep->flags & VM_4_LEVEL)
			return ia64_vtop_4l(kvaddr, paddr, pgd, verbose, 0);
		else
			return ia64_vtop(kvaddr, paddr, pgd, verbose, 0);
	}

}

/*
 *  Even though thread_info structs are used in 2.6, they
 *  are not the stack base. (until further notice...)
 */
static ulong 
ia64_get_stackbase(ulong task)
{
	return (task);
}

static ulong 
ia64_get_stacktop(ulong task)
{
	return (ia64_get_stackbase(task) + STACKSIZE());
}


/*
 *  Get the relevant page directory pointer from a task structure.
 */
static ulong
ia64_get_task_pgd(ulong task)
{
	return (error(FATAL, "ia64_get_task_pgd: N/A\n"));
}

static void
ia64_get_stack_frame(struct bt_info *bt, ulong *pcp, ulong *spp)
{
        if (pcp)
                *pcp = ia64_get_pc(bt);
        if (spp)
                *spp = ia64_get_sp(bt);
}


/*
 *  Return the kernel switch_stack b0 value.
 */
static ulong
ia64_get_pc(struct bt_info *bt)
{
        ulong b0;

        readmem(SWITCH_STACK_ADDR(bt->task) + OFFSET(switch_stack_b0), KVADDR,
                &b0, sizeof(void *), "switch_stack b0", FAULT_ON_ERROR);

        return b0;
}


/*
 *  Return the kernel switch_stack ar_bspstore value. 
 *  If it's "bt -t" request, calculate the register backing store offset.
 */
static ulong
ia64_get_sp(struct bt_info *bt)
{
	ulong bspstore;

        readmem(SWITCH_STACK_ADDR(bt->task) + OFFSET(switch_stack_ar_bspstore), 
		KVADDR, &bspstore, sizeof(void *), "switch_stack ar_bspstore", 
		FAULT_ON_ERROR);

	if (bt->flags &
	    (BT_TEXT_SYMBOLS|BT_TEXT_SYMBOLS_PRINT|BT_TEXT_SYMBOLS_NOPRINT)) {
		bspstore = bt->task + SIZE(task_struct);
		if (tt->flags & THREAD_INFO)
			bspstore += SIZE(thread_info);
		bspstore = roundup(bspstore, sizeof(ulong));
	}

        return bspstore;
}

/*
 *  Get the ksp out of the task's thread_struct
 */
static ulong
ia64_get_thread_ksp(ulong task)
{
        ulong ksp;

	if (XEN_HYPER_MODE()) {
        	readmem(task + XEN_HYPER_OFFSET(vcpu_thread_ksp), KVADDR,
                	&ksp, sizeof(void *),
                	"vcpu thread ksp", FAULT_ON_ERROR);
	} else {
        	readmem(task + OFFSET(task_struct_thread_ksp), KVADDR,
                	&ksp, sizeof(void *),
                	"thread_struct ksp", FAULT_ON_ERROR);
	}

        return ksp;
}

/*
 *  Return the switch_stack structure address of a task.
 */ 
ulong
ia64_get_switch_stack(ulong task)
{
	ulong sw;
		
	if (LKCD_DUMPFILE() && (sw = get_lkcd_switch_stack(task)))
	    return sw;
	/*
	 * debug only: get panic switch_stack from the ELF header.
	 */
	if (CRASHDEBUG(3) && NETDUMP_DUMPFILE() && 
		(sw = get_netdump_switch_stack(task))) 
		return sw;

	if (DISKDUMP_DUMPFILE() && (sw = get_diskdump_switch_stack(task)))
		return sw;

	return (ia64_get_thread_ksp((ulong)(task)) + 16);
}

/*
 *  Translate a PTE, returning TRUE if the page is _PAGE_P.
 *  If a physaddr pointer is passed in, don't print anything.
 */
static int
ia64_translate_pte(ulong pte, void *physaddr, ulonglong unused)
{
	int c, len1, len2, len3, others, page_present;
	char buf[BUFSIZE];
        char buf2[BUFSIZE];
        char buf3[BUFSIZE];
	char ptebuf[BUFSIZE];
	char physbuf[BUFSIZE];
        char *arglist[MAXARGS];
	char *ptr;
	ulong paddr;

        paddr = pte & _PFN_MASK;
	page_present = !!(pte & (_PAGE_P | _PAGE_PROTNONE));

	if (physaddr) {
		*((ulong *)physaddr) = paddr;
		return page_present;
	}

	sprintf(ptebuf, "%lx", pte);
	len1 = MAX(strlen(ptebuf), strlen("PTE"));
	fprintf(fp, "%s  ", mkstring(buf, len1, CENTER|LJUST, "PTE"));

        if (!page_present && pte) {
                swap_location(pte, buf);
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
		if (pte & _PAGE_P)
			fprintf(fp, "%sP", others++ ? "|" : "");
		switch (pte & _PAGE_MA_MASK)
		{
		case _PAGE_MA_WB:
			ptr = "MA_WB"; 
			break;
		case _PAGE_MA_UC:
			ptr = "MA_UC"; 
			break;
		case _PAGE_MA_UCE:
			ptr = "MA_UCE"; 
			break;
		case _PAGE_MA_WC:
			ptr = "MA_WC"; 
			break;
		case _PAGE_MA_NAT:
			ptr = "MA_NAT"; 
			break;
		case (0x1 << 2):
			ptr = "MA_UC"; 
			break;
		default:
			ptr = "MA_RSV";
			break;
		}
		fprintf(fp, "%s%s", others++ ? "|" : "", ptr);
		switch (pte & _PAGE_PL_MASK)
		{
		case _PAGE_PL_0:
			ptr = "PL_0";
			break;
		case _PAGE_PL_1:
			ptr = "PL_1";
			break;
		case _PAGE_PL_2:
			ptr = "PL_2";
			break;
		case _PAGE_PL_3:
			ptr = "PL_3";
			break;
		}
		fprintf(fp, "%s%s", others++ ? "|" : "", ptr);
		switch (pte & _PAGE_AR_MASK)
		{
		case _PAGE_AR_R:
			ptr = "AR_R";
			break;
		case _PAGE_AR_RX:
			ptr = "AT_RX";
			break;
		case _PAGE_AR_RW:
			ptr = "AR_RW";
			break;
		case _PAGE_AR_RWX:
			ptr = "AR_RWX";
			break;
		case _PAGE_AR_R_RW:
			ptr = "AR_R_RW";
			break;
		case _PAGE_AR_RX_RWX:
			ptr = "AR_RX_RWX";
			break;
		case _PAGE_AR_RWX_RW:
			ptr = "AR_RWX_RW";
			break;
		case _PAGE_AR_X_RX:
			ptr = "AR_X_RX";
			break;
		}
		fprintf(fp, "%s%s", others++ ? "|" : "", ptr);
		if (pte & _PAGE_A)
			fprintf(fp, "%sA", others++ ? "|" : "");
		if (pte & _PAGE_D)
			fprintf(fp, "%sD", others++ ? "|" : "");
		if (pte & _PAGE_ED)
			fprintf(fp, "%sED", others++ ? "|" : "");
		if (pte & _PAGE_PROTNONE)
			fprintf(fp, "%sPROTNONE", others++ ? "|" : "");
	} else {
		fprintf(fp, "no mapping");
	}

	fprintf(fp, ")\n");

	return page_present;
}


/*
 *  Determine where vmalloc'd memory starts.
 */
static ulong
ia64_vmalloc_start(void)
{
	return machdep->machspec->vmalloc_start;
}


/*
 *  Verify that an address is a task_struct address.
 */
static int
ia64_is_task_addr(ulong task)
{
        int i;

        if (IS_KVADDR(task) && (ALIGNED_STACK_OFFSET(task) == 0))
                return TRUE;

        for (i = 0; i < kt->cpus; i++)
                if (task == tt->idle_threads[i])
                        return TRUE;

        return FALSE;
}


/*
 *  Filter disassembly output if the output radix is not gdb's default 10
 */
static int
ia64_dis_filter(ulong vaddr, char *inbuf, unsigned int output_radix)
{
        char buf1[BUFSIZE];
        char buf2[BUFSIZE];
        char *colon, *p1, *p2;
        int argc;
	int revise_bracket, stop_bit;
        char *argv[MAXARGS];
        ulong value;

        if (!inbuf)
                return TRUE;

/*
 *  For some reason gdb can go off into the weeds translating text addresses,
 *  (on alpha -- not necessarily seen on ia64) so this routine both fixes the
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

	revise_bracket = stop_bit = 0;
	if ((FIRSTCHAR(argv[argc-1]) == '<') &&
            (LASTCHAR(argv[argc-1]) == '>')) {
		revise_bracket = TRUE;
		stop_bit = FALSE;
	} else if ((FIRSTCHAR(argv[argc-1]) == '<') &&
            strstr(argv[argc-1], ">;;")) {
		revise_bracket = TRUE;
		stop_bit = TRUE;
	}

        if (revise_bracket) {
                p1 = rindex(inbuf, '<');
                while ((p1 > inbuf) && !STRNEQ(p1, "0x"))
                        p1--;

                if (!STRNEQ(p1, "0x"))
                        return FALSE;

                if (!extract_hex(p1, &value, NULLCHAR, TRUE))
                        return FALSE;

                sprintf(buf1, "0x%lx <%s>%s\n", value,
                        value_to_symstr(value, buf2, output_radix),
			stop_bit ? ";;" : "");

                sprintf(p1, "%s", buf1);

        } else if (STRNEQ(argv[argc-2], "br.call.") &&
		 STRNEQ(argv[argc-1], "b0=0x")) {
		/*  
		 *  Update module function calls of these formats:
	 	 *
		 *     br.call.sptk.many b0=0xa0000000003d5e40;;
		 *     br.call.sptk.many b0=0xa00000000001dfc0
		 *
		 *  to show a bracketed function name if the destination
		 *  address is a known symbol with no offset.
		 */
		if ((p1 = strstr(argv[argc-1], ";;")) &&
		    (p2 = strstr(inbuf, ";;\n"))) {
			*p1 = NULLCHAR;
			p1 = &argv[argc-1][3];

                	if (extract_hex(p1, &value, NULLCHAR, TRUE)) {
				sprintf(buf1, " <%s>;;\n",
					value_to_symstr(value, buf2, 
					output_radix));
				if (IS_MODULE_VADDR(value) &&
				    !strstr(buf2, "+"))
					sprintf(p2, "%s", buf1);
			} 
		} else {
			p1 = &argv[argc-1][3];
			p2 = &LASTCHAR(inbuf);
                	if (extract_hex(p1, &value, '\n', TRUE)) {
				sprintf(buf1, " <%s>\n",
					value_to_symstr(value, buf2, 
					output_radix));
				if (IS_MODULE_VADDR(value) &&
				    !strstr(buf2, "+"))
					sprintf(p2, "%s", buf1);
			}
		}
	}

        console("    %s", inbuf);

	return TRUE;
}

/*
 *  Format the pt_regs structure.
 */
enum pt_reg_names { 
		P_cr_ipsr, P_cr_iip, P_cr_ifs, 
		P_ar_unat, P_ar_pfs, P_ar_rsc, P_ar_rnat, P_ar_bspstore, 
		P_ar_ccv, P_ar_fpsr,
		P_pr, P_loadrs, 
		P_b0, P_b6, P_b7,
		P_r1, P_r2, P_r3, P_r8, P_r9, P_r10, P_r11, P_r12, P_r13,
	        P_r14, P_r15, P_r16, P_r17, P_r18, P_r19, P_r20, P_r21,
		P_r22, P_r23, P_r24, P_r25, P_r26, P_r27, P_r28, P_r29,
		P_r30, P_r31,
		P_f6_lo, P_f6_hi,
		P_f7_lo, P_f7_hi,
		P_f8_lo, P_f8_hi,
		P_f9_lo, P_f9_hi, 
		P_f10_lo, P_f10_hi, 
		P_f11_lo, P_f11_hi, 
		NUM_PT_REGS};
 
void
ia64_exception_frame(ulong addr, struct bt_info *bt)
{
	char buf[BUFSIZE], *p, *p1;
	int fval;
	ulong value1, value2;
	ulong eframe[NUM_PT_REGS];

	console("ia64_exception_frame: pt_regs: %lx\n", addr);

        if (bt->debug)
                CRASHDEBUG_RESTORE();
	CRASHDEBUG_SUSPEND(0);

        BZERO(&eframe, sizeof(ulong) * NUM_PT_REGS);

        open_tmpfile();
	if (XEN_HYPER_MODE())
        	dump_struct("cpu_user_regs", addr, RADIX(16));
	else
        	dump_struct("pt_regs", addr, RADIX(16));
        rewind(pc->tmpfile);

	fval = 0;
        while (fgets(buf, BUFSIZE, pc->tmpfile)) {

		if (strstr(buf, "f6 = ")) {
			fval = 6;
			continue;
		}
		if (strstr(buf, "f7 = ")) {
			fval = 7;
			continue;
		}
		if (strstr(buf, "f8 = ")) {
			fval = 8;
			continue;
		}
		if (strstr(buf, "f9 = ")) {
			fval = 9;
			continue;
		}

                if (strstr(buf, "f10 = ")) {
                        fval = 10;
                        continue;
                }

                if (strstr(buf, "f11 = ")) {
                        fval = 11;
                        continue;
                }

                if (!strstr(buf, "0x"))
                        continue;

		if (fval) {
			p = strstr(buf, "0x");
			if ((p1 = strstr(p, "}")))
				*p1 = NULLCHAR;
			extract_hex(p, &value1, ',', TRUE);
			p = strstr(buf, ",");
			extract_hex(p, &value2, NULLCHAR, FALSE);  
			switch (fval)
			{
			case 6:
				eframe[P_f6_lo] = value1;
				eframe[P_f6_hi] = value2;
				break;
			case 7:
				eframe[P_f7_lo] = value1;
				eframe[P_f7_hi] = value2;
				break;
			case 8:
				eframe[P_f8_lo] = value1;
				eframe[P_f8_hi] = value2;
				break;
			case 9:
				eframe[P_f9_lo] = value1;
				eframe[P_f9_hi] = value2;
				break;
                        case 10:
                                eframe[P_f10_lo] = value1;
                                eframe[P_f10_hi] = value2;
                                break;
                        case 11:
                                eframe[P_f11_lo] = value1;
                                eframe[P_f11_hi] = value2;
                                break;
			}
			fval = 0;
			continue;
		}
		
		strip_comma(clean_line(buf));
		p = strstr(buf, " = ");
		extract_hex(p, &value1, NULLCHAR, FALSE);

		if (strstr(buf, "cr_ipsr = ")) {
			eframe[P_cr_ipsr] = value1;
		}

		if (strstr(buf, "cr_iip = ")) {
			eframe[P_cr_iip] = value1;
		}

		if (strstr(buf, "cr_ifs = ")) {
			eframe[P_cr_ifs] = value1;
		}

		if (strstr(buf, "ar_unat = ")) {
			eframe[P_ar_unat] = value1;
		}

		if (strstr(buf, "ar_pfs = ")) {
			eframe[P_ar_pfs] = value1;
		}

		if (strstr(buf, "ar_rsc = ")) {
			eframe[P_ar_rsc] = value1;
		}

		if (strstr(buf, "ar_rnat = ")) {
			eframe[P_ar_rnat] = value1;
		}

		if (strstr(buf, "ar_bspstore = ")) {
			eframe[P_ar_bspstore] = value1;
		}

		if (strstr(buf, "ar_ccv = ")) {
			eframe[P_ar_ccv] = value1;
		}

                if (strstr(buf, "ar_fpsr = ")) {
                        eframe[P_ar_fpsr] = value1;
                }

                if (strstr(buf, "pr = ")) {
                        eframe[P_pr] = value1;
                }

                if (strstr(buf, "loadrs = ")) {
                        eframe[P_loadrs] = value1;
                }

                if (strstr(buf, "b0 = ")) {
                        eframe[P_b0] = value1;
                }

                if (strstr(buf, "b6 = ")) {
                        eframe[P_b6] = value1;
                }

                if (strstr(buf, "b7 = ")) {
                        eframe[P_b7] = value1;
                }

                if (strstr(buf, "r1 = ")) {
                        eframe[P_r1] = value1;
                }


                if (strstr(buf, "r2 = ")) {
                        eframe[P_r2] = value1;
                }


                if (strstr(buf, "r3 = ")) {
                        eframe[P_r3] = value1;
                }


                if (strstr(buf, "r8 = ")) {
                        eframe[P_r8] = value1;
                }


                if (strstr(buf, "r9 = ")) {
                        eframe[P_r9] = value1;
                }

                if (strstr(buf, "r10 = ")) {
                        eframe[P_r10] = value1;
                }


                if (strstr(buf, "r11 = ")) {
                        eframe[P_r11] = value1;
                }

                if (strstr(buf, "r12 = ")) {
                        eframe[P_r12] = value1;
                }

                if (strstr(buf, "r13 = ")) {
                        eframe[P_r13] = value1;
                }

                if (strstr(buf, "r14 = ")) {
                        eframe[P_r14] = value1;
                }

                if (strstr(buf, "r15 = ")) {
                        eframe[P_r15] = value1;
                }

                if (strstr(buf, "r16 = ")) {
                        eframe[P_r16] = value1;
                }

                if (strstr(buf, "r17 = ")) {
                        eframe[P_r17] = value1;
                }

                if (strstr(buf, "r18 = ")) {
                        eframe[P_r18] = value1;
                }

                if (strstr(buf, "r19 = ")) {
                        eframe[P_r19] = value1;
                }

                if (strstr(buf, "r20 = ")) {
                        eframe[P_r20] = value1;
                }

                if (strstr(buf, "r21 = ")) {
                        eframe[P_r21] = value1;
                }

                if (strstr(buf, "r22 = ")) {
                        eframe[P_r22] = value1;
                }

                if (strstr(buf, "r23 = ")) {
                        eframe[P_r23] = value1;
                }

                if (strstr(buf, "r24 = ")) {
                        eframe[P_r24] = value1;
                }

                if (strstr(buf, "r25 = ")) {
                        eframe[P_r25] = value1;
                }

                if (strstr(buf, "r26 = ")) {
                        eframe[P_r26] = value1;
                }

                if (strstr(buf, "r27 = ")) {
                        eframe[P_r27] = value1;
                }

                if (strstr(buf, "r28 = ")) {
                        eframe[P_r28] = value1;
                }

                if (strstr(buf, "r29 = ")) {
                        eframe[P_r29] = value1;
                }

                if (strstr(buf, "r30 = ")) {
                        eframe[P_r30] = value1;
                }

                if (strstr(buf, "r31 = ")) {
                        eframe[P_r31] = value1;
                }
	}

       	close_tmpfile(); 

	fprintf(fp, "  EFRAME: %lx\n", addr);

	if (bt->flags & BT_INCOMPLETE_USER_EFRAME) {
		fprintf(fp, 
    "  [exception frame incomplete -- check salinfo for complete context]\n");
		bt->flags &= ~BT_INCOMPLETE_USER_EFRAME;
	}

	fprintf(fp, "      B0: %016lx      CR_IIP: %016lx\n", 
		eframe[P_b0], eframe[P_cr_iip]);
/**
	if (is_kernel_text(eframe[P_cr_iip]))
        	fprintf(fp, "<%s>",
                	value_to_symstr(eframe[P_cr_iip], buf, 0));
	fprintf(fp, "\n");
**/
	fprintf(fp, " CR_IPSR: %016lx      CR_IFS: %016lx\n", 
		eframe[P_cr_ipsr], eframe[P_cr_ifs]);
	fprintf(fp, "  AR_PFS: %016lx      AR_RSC: %016lx\n", 
		eframe[P_ar_pfs], eframe[P_ar_rsc]);
	fprintf(fp, " AR_UNAT: %016lx     AR_RNAT: %016lx\n", 
		eframe[P_ar_unat], eframe[P_ar_rnat]);
        fprintf(fp, "  AR_CCV: %016lx     AR_FPSR: %016lx\n",
                eframe[P_ar_ccv], eframe[P_ar_fpsr]);
        fprintf(fp, "  LOADRS: %016lx AR_BSPSTORE: %016lx\n", 
		eframe[P_loadrs], eframe[P_ar_bspstore]);
        fprintf(fp, "      B6: %016lx          B7: %016lx\n", 
		eframe[P_b6], eframe[P_b7]);
        fprintf(fp, "      PR: %016lx          R1: %016lx\n", 
		eframe[P_pr], eframe[P_r1]);
        fprintf(fp, "      R2: %016lx          R3: %016lx\n", 
		eframe[P_r2], eframe[P_r3]);
        fprintf(fp, "      R8: %016lx          R9: %016lx\n", 
		eframe[P_r8], eframe[P_r9]);
        fprintf(fp, "     R10: %016lx         R11: %016lx\n", 
		eframe[P_r10], eframe[P_r11]);
        fprintf(fp, "     R12: %016lx         R13: %016lx\n", 
		eframe[P_r12], eframe[P_r13]);
        fprintf(fp, "     R14: %016lx         R15: %016lx\n", 
		eframe[P_r14], eframe[P_r15]);
        fprintf(fp, "     R16: %016lx         R17: %016lx\n", 
		eframe[P_r16], eframe[P_r17]);
        fprintf(fp, "     R18: %016lx         R19: %016lx\n", 
		eframe[P_r18], eframe[P_r19]);
        fprintf(fp, "     R20: %016lx         R21: %016lx\n", 
		eframe[P_r20], eframe[P_r21]);
        fprintf(fp, "     R22: %016lx         R23: %016lx\n", 
		eframe[P_r22], eframe[P_r23]);
        fprintf(fp, "     R24: %016lx         R25: %016lx\n", 
		eframe[P_r24], eframe[P_r25]);
        fprintf(fp, "     R26: %016lx         R27: %016lx\n", 
		eframe[P_r26], eframe[P_r27]);
        fprintf(fp, "     R28: %016lx         R29: %016lx\n", 
		eframe[P_r28], eframe[P_r29]);
        fprintf(fp, "     R30: %016lx         R31: %016lx\n", 
		eframe[P_r30], eframe[P_r31]);
	fprintf(fp, "      F6: %05lx%016lx  ",
		eframe[P_f6_hi], eframe[P_f6_lo]);
        fprintf(fp, "   F7: %05lx%016lx\n",
                eframe[P_f7_hi], eframe[P_f7_lo]);
        fprintf(fp, "      F8: %05lx%016lx  ",
                eframe[P_f8_hi], eframe[P_f8_lo]);
        fprintf(fp, "   F9: %05lx%016lx\n",
                eframe[P_f9_hi], eframe[P_f9_lo]);

	if (machdep->flags & NEW_UNW_V3) {
        	fprintf(fp, "     F10: %05lx%016lx  ",
                	eframe[P_f10_hi], eframe[P_f10_lo]);
        	fprintf(fp, "  F11: %05lx%016lx\n",
                	eframe[P_f11_hi], eframe[P_f11_lo]);
	}

	CRASHDEBUG_RESTORE();
        if (bt->debug)
                CRASHDEBUG_SUSPEND(bt->debug);
}

enum ss_reg_names { 
		S_caller_unat, S_ar_fpsr,
		S_f2_lo, S_f2_hi,
		S_f3_lo, S_f3_hi,
		S_f4_lo, S_f4_hi,
		S_f5_lo, S_f5_hi,
		S_f10_lo, S_f10_hi,
		S_f11_lo, S_f11_hi,
		S_f12_lo, S_f12_hi,
		S_f13_lo, S_f13_hi,
		S_f14_lo, S_f14_hi,
		S_f15_lo, S_f15_hi,
		S_f16_lo, S_f16_hi,
		S_f17_lo, S_f17_hi,
		S_f18_lo, S_f18_hi,
		S_f19_lo, S_f19_hi,
                S_f20_lo, S_f20_hi,
                S_f21_lo, S_f21_hi,
                S_f22_lo, S_f22_hi,
                S_f23_lo, S_f23_hi,
                S_f24_lo, S_f24_hi,
                S_f25_lo, S_f25_hi,
                S_f26_lo, S_f26_hi,
                S_f27_lo, S_f27_hi,
                S_f28_lo, S_f28_hi,
                S_f29_lo, S_f29_hi,
                S_f30_lo, S_f30_hi,
                S_f31_lo, S_f31_hi,
		S_r4, S_r5, S_r6, S_r7,
		S_b0, S_b1, S_b2, S_b3, S_b4, S_b5,
		S_ar_pfs, S_ar_lc, S_ar_unat, S_ar_rnat, S_ar_bspstore, S_pr,
                NUM_SS_REGS };


/*
 *  Format the switch_stack structure.
 */
static void
ia64_dump_switch_stack(ulong task, ulong flag)
{
	ulong addr;
        char buf[BUFSIZE], *p;
        int fval;
        ulong value1, value2;
        ulong ss[NUM_SS_REGS];

	addr = SWITCH_STACK_ADDR(task);

        BZERO(&ss, sizeof(ulong) * NUM_SS_REGS);

        open_tmpfile();
        dump_struct("switch_stack", addr, RADIX(16));
        rewind(pc->tmpfile);

        fval = 0;
        while (fgets(buf, BUFSIZE, pc->tmpfile)) {

		if (strstr(buf, "f2 = ")) {
			fval = 2;
			continue;
		}
		if (strstr(buf, "f3 = ")) {
			fval = 3;
			continue;
		}
		if (strstr(buf, "f4 = ")) {
			fval = 4;
			continue;
		}
		if (strstr(buf, "f5 = ")) {
			fval = 5;
			continue;
		}
		if (strstr(buf, "f10 = ")) {
			fval = 10;
			continue;
		}
		if (strstr(buf, "f11 = ")) {
			fval = 11;
			continue;
		}
		if (strstr(buf, "f12 = ")) {
			fval = 12;
			continue;
		}
		if (strstr(buf, "f13 = ")) {
			fval = 13;
			continue;
		}
		if (strstr(buf, "f14 = ")) {
			fval = 14;
			continue;
		}
		if (strstr(buf, "f15 = ")) {
			fval = 15;
			continue;
		}
		if (strstr(buf, "f16 = ")) {
			fval = 16;
			continue;
		}
		if (strstr(buf, "f17 = ")) {
			fval = 17;
			continue;
		}
		if (strstr(buf, "f18 = ")) {
			fval = 18;
			continue;
		}
		if (strstr(buf, "f19 = ")) {
			fval = 19;
			continue;
		}
		if (strstr(buf, "f20 = ")) {
			fval = 20;
			continue;
		}
		if (strstr(buf, "f21 = ")) {
			fval = 21;
			continue;
		}
		if (strstr(buf, "f22 = ")) {
			fval = 22;
			continue;
		}
		if (strstr(buf, "f23 = ")) {
			fval = 23;
			continue;
		}
		if (strstr(buf, "f24 = ")) {
			fval = 24;
			continue;
		}
		if (strstr(buf, "f25 = ")) {
			fval = 25;
			continue;
		}
		if (strstr(buf, "f26 = ")) {
			fval = 26;
			continue;
		}
		if (strstr(buf, "f27 = ")) {
			fval = 27;
			continue;
		}
		if (strstr(buf, "f28 = ")) {
			fval = 28;
			continue;
		}
		if (strstr(buf, "f29 = ")) {
			fval = 29;
			continue;
		}
                if (strstr(buf, "f30 = ")) {
                        fval = 30;
                        continue;
                }
                if (strstr(buf, "f31 = ")) {
                        fval = 31;
                        continue;
                }

                if (!strstr(buf, "0x"))
                        continue;

		if (fval) {
			p = strstr(buf, "0x");
			extract_hex(p, &value1, ',', TRUE);
			p = strstr(buf, ",");
			extract_hex(p, &value2, '}', FALSE);  
			switch (fval)
			{
			case 2:
				ss[S_f2_lo] = value1;
				ss[S_f2_hi] = value2;
				break;
			case 3:
				ss[S_f3_lo] = value1;
				ss[S_f3_hi] = value2;
				break;
			case 4:
				ss[S_f4_lo] = value1;
				ss[S_f4_hi] = value2;
				break;
			case 5:
				ss[S_f5_lo] = value1;
				ss[S_f5_hi] = value2;
				break;
                        case 10:
                                ss[S_f10_lo] = value1;
                                ss[S_f10_hi] = value2;
                                break;
                        case 11:
                                ss[S_f11_lo] = value1;
                                ss[S_f11_hi] = value2;
                                break;
                        case 12:
                                ss[S_f12_lo] = value1;
                                ss[S_f12_hi] = value2;
                                break;
                        case 13:
                                ss[S_f13_lo] = value1;
                                ss[S_f13_hi] = value2;
                                break;
                        case 14:
                                ss[S_f14_lo] = value1;
                                ss[S_f14_hi] = value2;
                                break;
                        case 15:
                                ss[S_f15_lo] = value1;
                                ss[S_f15_hi] = value2;
                                break;
                        case 16:
                                ss[S_f16_lo] = value1;
                                ss[S_f16_hi] = value2;
                                break;
                        case 17:
                                ss[S_f17_lo] = value1;
                                ss[S_f17_hi] = value2;
                                break;
                        case 18:
                                ss[S_f18_lo] = value1;
                                ss[S_f18_hi] = value2;
                                break;
                        case 19:
                                ss[S_f19_lo] = value1;
                                ss[S_f19_hi] = value2;
                                break;
                        case 20:
                                ss[S_f20_lo] = value1;
                                ss[S_f20_hi] = value2;
                                break;
                        case 21:
                                ss[S_f21_lo] = value1;
                                ss[S_f21_hi] = value2;
                                break;
                        case 22:
                                ss[S_f22_lo] = value1;
                                ss[S_f22_hi] = value2;
                                break;
                        case 23:
                                ss[S_f23_lo] = value1;
                                ss[S_f23_hi] = value2;
                                break;
                        case 24:
                                ss[S_f24_lo] = value1;
                                ss[S_f24_hi] = value2;
                                break;
                        case 25:
                                ss[S_f25_lo] = value1;
                                ss[S_f25_hi] = value2;
                                break;
                        case 26:
                                ss[S_f26_lo] = value1;
                                ss[S_f26_hi] = value2;
                                break;
                        case 27:
                                ss[S_f27_lo] = value1;
                                ss[S_f27_hi] = value2;
                                break;
                        case 28:
                                ss[S_f28_lo] = value1;
                                ss[S_f28_hi] = value2;
                                break;
                        case 29:
                                ss[S_f29_lo] = value1;
                                ss[S_f29_hi] = value2;
                                break;
                        case 30:
                                ss[S_f30_lo] = value1;
                                ss[S_f30_hi] = value2;
                                break;
                        case 31:
                                ss[S_f31_lo] = value1;
                                ss[S_f31_hi] = value2;
                                break;
			}
			fval = 0;
			continue;
		}
		
		strip_comma(clean_line(buf));
		p = strstr(buf, " = ");
		extract_hex(p, &value1, NULLCHAR, FALSE);

                if (strstr(buf, "caller_unat = ")) {
                        ss[S_caller_unat] = value1;
                }
                if (strstr(buf, "ar_fpsr = ")) {
                        ss[S_ar_fpsr] = value1;
                }
                if (strstr(buf, "r4 = ")) {
                        ss[S_r4] = value1;
                }
                if (strstr(buf, "r5 = ")) {
                        ss[S_r5] = value1;
                }
                if (strstr(buf, "r6 = ")) {
                        ss[S_r6] = value1;
                }
                if (strstr(buf, "r7 = ")) {
                        ss[S_r7] = value1;
                }
                if (strstr(buf, "b0 = ")) {
                        ss[S_b0] = value1;
                }
                if (strstr(buf, "b1 = ")) {
                        ss[S_b1] = value1;
                }
                if (strstr(buf, "b2 = ")) {
                        ss[S_b2] = value1;
                }
                if (strstr(buf, "b3 = ")) {
                        ss[S_b3] = value1;
                }
                if (strstr(buf, "b4 = ")) {
                        ss[S_b4] = value1;
                }
                if (strstr(buf, "b5 = ")) {
                        ss[S_b5] = value1;
                }
                if (strstr(buf, "ar_pfs = ")) {
                        ss[S_ar_pfs] = value1;
                }
                if (strstr(buf, "ar_lc = ")) {
                        ss[S_ar_lc] = value1;
                }
                if (strstr(buf, "ar_unat = ")) {
                        ss[S_ar_unat] = value1;
                }
                if (strstr(buf, "ar_rnat = ")) {
                        ss[S_ar_rnat] = value1;
                }
                if (strstr(buf, "ar_bspstore = ")) {
                        ss[S_ar_bspstore] = value1;
                }
                if (strstr(buf, "pr = ")) {
                        ss[S_pr] = value1;
                }
	}

	close_tmpfile();

	fprintf(fp, "SWITCH_STACK: %lx\n", addr);

        fprintf(fp, "      B0: %016lx          B1: %016lx\n",
		ss[S_b0], ss[S_b1]);
        fprintf(fp, "      B2: %016lx          B3: %016lx\n",
		ss[S_b2], ss[S_b3]);
        fprintf(fp, "      B4: %016lx          B5: %016lx\n",
		ss[S_b4], ss[S_b5]);

	fprintf(fp, "  AR_PFS: %016lx       AR_LC: %016lx\n",
		ss[S_ar_pfs], ss[S_ar_lc]);
	fprintf(fp, " AR_UNAT: %016lx     AR_RNAT: %016lx\n",
		ss[S_ar_unat], ss[S_ar_rnat]);
	fprintf(fp, "      PR: %016lx AR_BSPSTORE: %016lx\n",
		ss[S_pr], ss[S_ar_bspstore]);
	fprintf(fp, " AR_FPSR: %016lx CALLER_UNAT: %016lx\n",
		ss[S_ar_fpsr], ss[S_caller_unat]);

        fprintf(fp, "      R4: %016lx          R5: %016lx\n",
		ss[S_r4], ss[S_r5]);
        fprintf(fp, "      R6: %016lx          R7: %016lx\n",
		ss[S_r6], ss[S_r7]);

        fprintf(fp, "      F2: %05lx%016lx  ", ss[S_f2_hi], ss[S_f2_lo]);
        fprintf(fp, "   F3: %05lx%016lx\n", ss[S_f3_hi], ss[S_f3_lo]);
        fprintf(fp, "      F4: %05lx%016lx  ", ss[S_f4_hi], ss[S_f4_lo]);
        fprintf(fp, "   F5: %05lx%016lx\n", ss[S_f5_hi], ss[S_f5_lo]);
        fprintf(fp, "     F10: %05lx%016lx  ", ss[S_f10_hi], ss[S_f10_lo]);
        fprintf(fp, "  F11: %05lx%016lx\n", ss[S_f11_hi], ss[S_f11_lo]);
        fprintf(fp, "     F12: %05lx%016lx  ", ss[S_f12_hi], ss[S_f12_lo]);
        fprintf(fp, "  F13: %05lx%016lx\n", ss[S_f13_hi], ss[S_f13_lo]);
        fprintf(fp, "     F14: %05lx%016lx  ", ss[S_f14_hi], ss[S_f14_lo]);
        fprintf(fp, "  F15: %05lx%016lx\n", ss[S_f15_hi], ss[S_f15_lo]);
        fprintf(fp, "     F16: %05lx%016lx  ", ss[S_f16_hi], ss[S_f16_lo]);
        fprintf(fp, "  F17: %05lx%016lx\n", ss[S_f17_hi], ss[S_f17_lo]);
        fprintf(fp, "     F18: %05lx%016lx  ", ss[S_f18_hi], ss[S_f18_lo]);
        fprintf(fp, "  F19: %05lx%016lx\n", ss[S_f19_hi], ss[S_f19_lo]);
        fprintf(fp, "     F20: %05lx%016lx  ", ss[S_f20_hi], ss[S_f20_lo]);
        fprintf(fp, "  F21: %05lx%016lx\n", ss[S_f21_hi], ss[S_f21_lo]);
        fprintf(fp, "     F22: %05lx%016lx  ", ss[S_f22_hi], ss[S_f22_lo]);
        fprintf(fp, "  F23: %05lx%016lx\n", ss[S_f23_hi], ss[S_f23_lo]);
        fprintf(fp, "     F24: %05lx%016lx  ", ss[S_f24_hi], ss[S_f24_lo]);
        fprintf(fp, "  F25: %05lx%016lx\n", ss[S_f25_hi], ss[S_f25_lo]);
        fprintf(fp, "     F26: %05lx%016lx  ", ss[S_f26_hi], ss[S_f26_lo]);
        fprintf(fp, "  F27: %05lx%016lx\n", ss[S_f27_hi], ss[S_f27_lo]);
        fprintf(fp, "     F28: %05lx%016lx  ", ss[S_f28_hi], ss[S_f28_lo]);
        fprintf(fp, "  F29: %05lx%016lx\n", ss[S_f29_hi], ss[S_f29_lo]);
        fprintf(fp, "     F30: %05lx%016lx  ", ss[S_f30_hi], ss[S_f30_lo]);
        fprintf(fp, "  F31: %05lx%016lx\n", ss[S_f31_hi], ss[S_f31_lo]);
}

/*
 *   Override smp_num_cpus if possible and necessary.
 */
int
ia64_get_smp_cpus(void)
{
	int cpus;

	if ((cpus = get_cpus_online()))
		return MAX(cpus, get_highest_cpu_online()+1);
	else
		return kt->cpus;
}

/*
 *  Machine dependent command.
 */
void
ia64_cmd_mach(void)
{
        int c, cflag, mflag;
	unsigned int radix;

	cflag = mflag = radix = 0;

        while ((c = getopt(argcnt, args, "cmxd")) != EOF) {
                switch(c)
                {
		case 'c':
			cflag++;
			break;
		case 'm':
			mflag++;
			ia64_display_memmap();
			break;
		case 'x':
			if (radix == 10)
				error(FATAL,
					"-d and -x are mutually exclusive\n");
			radix = 16;
			break;
		case 'd':
			if (radix == 16)
				error(FATAL,
					"-d and -x are mutually exclusive\n");
			radix = 10;
			break;
                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

	if (cflag)
		ia64_display_cpu_data(radix);

	if (!cflag && !mflag)
		ia64_display_machine_stats();
}

/*
 *  "mach" command output.
 */
static void
ia64_display_machine_stats(void)
{
        struct new_utsname *uts;
        char buf[BUFSIZE];
        ulong mhz;

        uts = &kt->utsname;

        fprintf(fp, "              MACHINE TYPE: %s\n", uts->machine);
        fprintf(fp, "               MEMORY SIZE: %s\n", get_memory_size(buf));
        fprintf(fp, "                      CPUS: %d\n", kt->cpus);
	if (!STREQ(kt->hypervisor, "(undetermined)") &&
	    !STREQ(kt->hypervisor, "bare hardware"))
		fprintf(fp, "                HYPERVISOR: %s\n",  kt->hypervisor);
        fprintf(fp, "           PROCESSOR SPEED: ");
        if ((mhz = machdep->processor_speed()))
                fprintf(fp, "%ld Mhz\n", mhz);
        else
                fprintf(fp, "(unknown)\n");
        fprintf(fp, "                        HZ: %d\n", machdep->hz);
        fprintf(fp, "                 PAGE SIZE: %d\n", PAGESIZE());
//      fprintf(fp, "             L1 CACHE SIZE: %d\n", l1_cache_size());
        fprintf(fp, "         KERNEL STACK SIZE: %ld\n", STACKSIZE());
        fprintf(fp, "      KERNEL CACHED REGION: %lx\n",
		(ulong)KERNEL_CACHED_REGION << REGION_SHIFT);
        fprintf(fp, "    KERNEL UNCACHED REGION: %lx\n", 
		(ulong)KERNEL_UNCACHED_REGION << REGION_SHIFT);
        fprintf(fp, "     KERNEL VMALLOC REGION: %lx\n", 
		(ulong)KERNEL_VMALLOC_REGION << REGION_SHIFT);
	fprintf(fp, "    USER DATA/STACK REGION: %lx\n",
		(ulong)USER_STACK_REGION << REGION_SHIFT);
	fprintf(fp, "    USER DATA/STACK REGION: %lx\n",
		(ulong)USER_DATA_REGION << REGION_SHIFT);
	fprintf(fp, "          USER TEXT REGION: %lx\n",
		(ulong)USER_TEXT_REGION << REGION_SHIFT);
	fprintf(fp, " USER SHARED MEMORY REGION: %lx\n",
		(ulong)USER_SHMEM_REGION << REGION_SHIFT);
	fprintf(fp, "USER IA32 EMULATION REGION: %016lx\n",
		(ulong)USER_IA32_EMUL_REGION << REGION_SHIFT);
}

static void 
ia64_display_cpu_data(unsigned int radix)
{
        int cpu;
	ulong cpu_data;
	int array_location_known;
	struct syment *sp;

	if (!(cpu_data = machdep->machspec->cpu_data_address)) {
		error(FATAL, "cannot find cpuinfo_ia64 location\n");
		return;
	}

	array_location_known = per_cpu_symbol_search("per_cpu__cpu_info") ||
		symbol_exists("cpu_data") || symbol_exists("_cpu_data");

        for (cpu = 0; cpu < kt->cpus; cpu++) {
                fprintf(fp, "%sCPU %d: %s\n", cpu ? "\n" : "", cpu,
			array_location_known ? "" : "(boot)");
                dump_struct("cpuinfo_ia64", cpu_data, radix);

		if (!array_location_known)
			break;
		
		if ((sp = per_cpu_symbol_search("per_cpu__cpu_info"))) {
                       if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF))
                                cpu_data = sp->value + 
					kt->__per_cpu_offset[cpu+1];
                       else
				break;   /* we've already done cpu 0 */
		} else
			cpu_data += SIZE(cpuinfo_ia64);
        }
}


/*
 *  Dump the EFI memory map.  
 */
static void
ia64_display_memmap(void)
{
	int i, others;
	struct efi_memory_desc_t *desc;
        struct machine_specific *ms;
	char *map;

        ms = &ia64_machine_specific;
	map = ms->ia64_memmap;

	if (!map) { 
		check_mem_limit();
		error(FATAL, "efi_mmap not accessible\n");
	}

	fprintf(fp, 
	  "      PHYSICAL ADDRESS RANGE         TYPE / ATTRIBUTE / [ACCESS]\n");

        for (i = 0; i < ms->efi_memmap_size/ms->efi_memdesc_size; i++) {
		desc = (struct efi_memory_desc_t *)map;

		fprintf(fp, "%016lx - %016lx  ",
			desc->phys_addr, desc->phys_addr + 
			(desc->num_pages * (1 << EFI_PAGE_SHIFT)));

		switch (desc->type)
		{
		case EFI_RESERVED_TYPE:
			fprintf(fp, "%s", "RESERVED_TYPE"); break;
		case EFI_LOADER_CODE:  
			fprintf(fp, "%s", "LOADER_CODE"); break;
		case EFI_LOADER_DATA: 
			fprintf(fp, "%s", "LOADER_DATA"); break;
		case EFI_BOOT_SERVICES_CODE:    
			fprintf(fp, "%s", "BOOT_SERVICES_CODE"); break;
		case EFI_BOOT_SERVICES_DATA:   
			fprintf(fp, "%s", "BOOT_SERVICES_DATA"); break;
		case EFI_RUNTIME_SERVICES_CODE: 
			fprintf(fp, "%s", "RUNTIME_SERVICES_CODE"); break;
		case EFI_RUNTIME_SERVICES_DATA: 
			fprintf(fp, "%s", "RUNTIME_SERVICES_DATA"); break;
		case EFI_CONVENTIONAL_MEMORY: 
			fprintf(fp, "%s", "CONVENTIONAL_MEMORY"); break;
		case EFI_UNUSABLE_MEMORY:    
			fprintf(fp, "%s", "UNUSABLE_MEMORY"); break;
		case EFI_ACPI_RECLAIM_MEMORY: 
			fprintf(fp, "%s", "ACPI_RECLAIM_MEMORY"); break;
		case EFI_ACPI_MEMORY_NVS:    
			fprintf(fp, "%s", "ACPI_MEMORY_NVS"); break;
		case EFI_MEMORY_MAPPED_IO:  
			fprintf(fp, "%s", "MEMORY_MAPPED_IO"); break;
		case EFI_MEMORY_MAPPED_IO_PORT_SPACE:
			fprintf(fp, "%s", "MEMORY_MAPPED_IO_PORT_SPACE"); 
			break;
		case EFI_PAL_CODE:                  
			fprintf(fp, "%s", "PAL_CODE"); break;
		default:
			fprintf(fp, "%s", "(unknown type)"); break;
		}

		fprintf(fp, " ");
		others = 0;
		if (desc->attribute & EFI_MEMORY_UC)
			fprintf(fp, "%sUC", others++ ? "|" : "");
		if (desc->attribute & EFI_MEMORY_WC)
			fprintf(fp, "%sWC", others++ ? "|" : "");
		if (desc->attribute & EFI_MEMORY_WT)
			fprintf(fp, "%sWT", others++ ? "|" : "");
		if (desc->attribute & EFI_MEMORY_WB)
			fprintf(fp, "%sWB", others++ ? "|" : "");
		if (desc->attribute & EFI_MEMORY_WP)
			fprintf(fp, "%sWP", others++ ? "|" : "");
		if (desc->attribute & EFI_MEMORY_RP)
			fprintf(fp, "%sRP", others++ ? "|" : "");
		if (desc->attribute & EFI_MEMORY_XP)
			fprintf(fp, "%sXP", others++ ? "|" : "");
		if (desc->attribute & EFI_MEMORY_RUNTIME)
			fprintf(fp, "%sRUNTIME", others++ ? "|" : "");

		fprintf(fp, " %s", ia64_available_memory(desc) ? 
			"[available]" : "");

		switch (VADDR_REGION(desc->virt_addr))
		{
        	case KERNEL_UNCACHED_REGION:
			fprintf(fp, "[R6]\n");
			break;
        	case KERNEL_CACHED_REGION:
			fprintf(fp, "[R7]\n");
			break;
		default:
			fprintf(fp, "\n");
		}

		if (!CRASHDEBUG(1))
			goto next_desc;

		fprintf(fp, 
		    "physical: %016lx  %dk pages: %ld  virtual: %016lx\n",
			desc->phys_addr, (1 << EFI_PAGE_SHIFT)/1024, 
			desc->num_pages, desc->virt_addr);

		fprintf(fp, "type: ");
		switch (desc->type)
		{
		case EFI_RESERVED_TYPE:
			fprintf(fp, "%-27s", "RESERVED_TYPE"); break;
		case EFI_LOADER_CODE:  
			fprintf(fp, "%-27s", "LOADER_CODE"); break;
		case EFI_LOADER_DATA: 
			fprintf(fp, "%-27s", "LOADER_DATA"); break;
		case EFI_BOOT_SERVICES_CODE:    
			fprintf(fp, "%-27s", "BOOT_SERVICES_CODE"); break;
		case EFI_BOOT_SERVICES_DATA:   
			fprintf(fp, "%-27s", "BOOT_SERVICES_DATA"); break;
		case EFI_RUNTIME_SERVICES_CODE: 
			fprintf(fp, "%-27s", "RUNTIME_SERVICES_CODE"); break;
		case EFI_RUNTIME_SERVICES_DATA: 
			fprintf(fp, "%-27s", "RUNTIME_SERVICES_DATA"); break;
		case EFI_CONVENTIONAL_MEMORY: 
			fprintf(fp, "%-27s", "CONVENTIONAL_MEMORY"); break;
		case EFI_UNUSABLE_MEMORY:    
			fprintf(fp, "%-27s", "UNUSABLE_MEMORY"); break;
		case EFI_ACPI_RECLAIM_MEMORY: 
			fprintf(fp, "%-27s", "ACPI_RECLAIM_MEMORY"); break;
		case EFI_ACPI_MEMORY_NVS:    
			fprintf(fp, "%-27s", "ACPI_MEMORY_NVS"); break;
		case EFI_MEMORY_MAPPED_IO:  
			fprintf(fp, "%-27s", "MEMORY_MAPPED_IO"); break;
		case EFI_MEMORY_MAPPED_IO_PORT_SPACE:
			fprintf(fp, "%-27s", "MEMORY_MAPPED_IO_PORT_SPACE"); 
			break;
		case EFI_PAL_CODE:                  
			fprintf(fp, "%-27s", "PAL_CODE"); break;
		default:
			fprintf(fp, "%-27s", "(unknown type)"); break;
		}

		fprintf(fp, "  attribute: (");
		others = 0;
		if (desc->attribute & EFI_MEMORY_UC)
			fprintf(fp, "%sUC", others++ ? "|" : "");
		if (desc->attribute & EFI_MEMORY_WC)
			fprintf(fp, "%sWC", others++ ? "|" : "");
		if (desc->attribute & EFI_MEMORY_WT)
			fprintf(fp, "%sWT", others++ ? "|" : "");
		if (desc->attribute & EFI_MEMORY_WB)
			fprintf(fp, "%sWB", others++ ? "|" : "");
		if (desc->attribute & EFI_MEMORY_WP)
			fprintf(fp, "%sWP", others++ ? "|" : "");
		if (desc->attribute & EFI_MEMORY_RP)
			fprintf(fp, "%sRP", others++ ? "|" : "");
		if (desc->attribute & EFI_MEMORY_XP)
			fprintf(fp, "%sXP", others++ ? "|" : "");
		if (desc->attribute & EFI_MEMORY_RUNTIME)
			fprintf(fp, "%sRUNTIME", others++ ? "|" : "");
		fprintf(fp, ") %s\n", ia64_available_memory(desc) ? 
			"[available]" : "");

next_desc:
                map += ms->efi_memdesc_size;
        }
}

static int
ia64_available_memory(struct efi_memory_desc_t *desc)
{
	if (desc->attribute & EFI_MEMORY_WB) {
	        switch (desc->type) {
                case EFI_LOADER_CODE:
                case EFI_LOADER_DATA:
                case EFI_BOOT_SERVICES_CODE:
                case EFI_BOOT_SERVICES_DATA:
                case EFI_CONVENTIONAL_MEMORY:
                	return TRUE;
                }
        }
	return FALSE;
}

/*
 *  Make a copy of the memmap descriptor array.
 */
static void 
ia64_create_memmap(void)
{
        struct machine_specific *ms;
        uint64_t ia64_boot_param, efi_memmap;
	ulong num_physpages;
	char *memmap;

        ms = &ia64_machine_specific;
	ms->ia64_memmap = NULL;

        if (symbol_exists("num_physpages")) {
                get_symbol_data("num_physpages", sizeof(ulong), &num_physpages);
                machdep->memsize = num_physpages * PAGESIZE();
        }

	if (!symbol_exists("ia64_boot_param"))
		return;

	if ((ms->mem_limit = check_mem_limit()))
		machdep->flags |= MEM_LIMIT;

       	get_symbol_data("ia64_boot_param", sizeof(void *), &ia64_boot_param);

        if ((ms->mem_limit && (ia64_VTOP(ia64_boot_param) >= ms->mem_limit)) ||
            !readmem(ia64_boot_param+
	    MEMBER_OFFSET("ia64_boot_param", "efi_memmap"),
            KVADDR, &efi_memmap, sizeof(uint64_t), "efi_memmap", 
	    QUIET|RETURN_ON_ERROR)) {
		if (!XEN() || CRASHDEBUG(1))
			error(WARNING, "cannot read ia64_boot_param: " 
			    "memory verification will not be performed\n\n");
		return;
	}

        readmem(ia64_boot_param+MEMBER_OFFSET("ia64_boot_param",
                "efi_memmap_size"), KVADDR, &ms->efi_memmap_size,
                sizeof(uint64_t), "efi_memmap_size", FAULT_ON_ERROR);
        readmem(ia64_boot_param+MEMBER_OFFSET("ia64_boot_param",
                "efi_memdesc_size"), KVADDR, &ms->efi_memdesc_size,
                sizeof(uint64_t), "efi_memdesc_size", FAULT_ON_ERROR);

	if (!(memmap = (char *) malloc(ms->efi_memmap_size))) {
		error(WARNING, "cannot malloc ia64_memmap\n");
		return;
	}

	if ((ms->mem_limit && (efi_memmap >= ms->mem_limit)) ||
            !readmem(PTOV(efi_memmap), KVADDR, memmap,
	    ms->efi_memmap_size, "efi_mmap contents", 
	    QUIET|RETURN_ON_ERROR)) {
		if (!XEN() || (XEN() && CRASHDEBUG(1)))
			error(WARNING, "cannot read efi_mmap: " 
			    "EFI memory verification will not be performed\n\n");
		free(memmap);
		return;
	}

	ms->ia64_memmap = memmap;
}

/*
 *  Kernel pages may cross EFI memmap boundaries, so the system page is
 *  broken into EFI pages, and then each of them is verified.
 */
static int
ia64_verify_paddr(uint64_t paddr)
{
        int i, j, cnt, found, desc_count, desc_size;
        struct efi_memory_desc_t *desc;
        struct machine_specific *ms;
	uint64_t phys_end;
        char *map;
	int efi_pages;
	ulong efi_pagesize;

	/*
	 *  When kernel text and data are mapped in region 5,
	 *  and we're using the crash memory device driver,
         *  then the driver will gracefully fail the read attempt
 	 *  if the address is bogus.  
	 */
	if ((VADDR_REGION(paddr) == KERNEL_VMALLOC_REGION) && 
	    (pc->flags & MEMMOD)) 
		return TRUE;

        ms = &ia64_machine_specific;
        if (ms->ia64_memmap == NULL)
		return TRUE;

	desc_count = ms->efi_memmap_size/ms->efi_memdesc_size;
        desc_size = ms->efi_memdesc_size;

	efi_pagesize = (1 << EFI_PAGE_SHIFT);
	efi_pages = PAGESIZE() / efi_pagesize;
	paddr = PAGEBASE(paddr); 

	for (i = cnt = 0; i < efi_pages; i++, paddr += efi_pagesize) {
		map = ms->ia64_memmap;
	        for (j = found = 0; j < desc_count; j++) {
	                desc = (struct efi_memory_desc_t *)map;
	                if (ia64_available_memory(desc)) {
	                        phys_end = desc->phys_addr +
	                                (desc->num_pages * efi_pagesize);
	                        if ((paddr >= desc->phys_addr) &&
	                            ((paddr + efi_pagesize) <= phys_end)) {
	                                cnt++;
					found = TRUE;
				}
	                }
			if (found)  
				break;
	                map += desc_size;
	        }
	} 

	return (cnt == efi_pages);
}

/*
 *  Check whether a "mem=X" argument was entered on the boot command line.
 *  Note that the default setting of the kernel mem_limit is ~0UL.
 */
static ulong
check_mem_limit(void)
{
	ulong mem_limit;
        char *saved_command_line, *p1, *p2;
	int len;

        if (!symbol_exists("mem_limit")) 
		return 0;

        get_symbol_data("mem_limit", sizeof(ulong), &mem_limit);
        if (mem_limit == ~0UL) 
		return 0;

	mem_limit += 1;

	if (!symbol_exists("saved_command_line"))
		goto no_command_line;

	len = get_array_length("saved_command_line", 0, sizeof(char));
	if (!len)
		goto no_command_line;

	saved_command_line = GETBUF(len+1);
	if (!readmem(symbol_value("saved_command_line"), KVADDR, 
	    saved_command_line, len, "saved_command_line", RETURN_ON_ERROR))
		goto no_command_line;

	if (!(p1 = strstr(saved_command_line, "mem=")))
		goto no_command_line;

	p2 = p1;
	while (*p2 && !whitespace(*p2))
		p2++;
	*p2 = NULLCHAR;

	error(pc->flags & RUNTIME ? INFO : WARNING, 
		"boot command line argument: %s\n", p1);
	return mem_limit;

no_command_line:
	error(pc->flags & RUNTIME ? INFO : WARNING, 
		"boot command line memory limit: %lx\n", mem_limit);
	return mem_limit;
}


#ifndef _ASM_IA64_UNWIND_H
#define _ASM_IA64_UNWIND_H

/*
 * Copyright (C) 1999-2000 Hewlett-Packard Co
 * Copyright (C) 1999-2000 David Mosberger-Tang <davidm@hpl.hp.com>
 *
 * A simple API for unwinding kernel stacks.  This is used for
 * debugging and error reporting purposes.  The kernel doesn't need
 * full-blown stack unwinding with all the bells and whitles, so there
 * is not much point in implementing the full IA-64 unwind API (though
 * it would of course be possible to implement the kernel API on top
 * of it).
 */

struct task_struct;	/* forward declaration */
struct switch_stack;	/* forward declaration */

enum unw_application_register {
	UNW_AR_BSP,
	UNW_AR_BSPSTORE,
	UNW_AR_PFS,
	UNW_AR_RNAT,
	UNW_AR_UNAT,
	UNW_AR_LC,
	UNW_AR_EC,
	UNW_AR_FPSR,
	UNW_AR_RSC,
	UNW_AR_CCV
};

/*
 * The following declarations are private to the unwind
 * implementation:
 */

struct unw_stack {
	unsigned long limit;
	unsigned long top;
};

#define UNW_FLAG_INTERRUPT_FRAME	(1UL << 0)

/*
 * No user of this module should every access this structure directly
 * as it is subject to change.  It is declared here solely so we can
 * use automatic variables.
 */
struct unw_frame_info {
	struct unw_stack regstk;
	struct unw_stack memstk;
	unsigned int flags;
	short hint;
	short prev_script;
	unsigned long bsp;
	unsigned long sp;		/* stack pointer */
	unsigned long psp;		/* previous sp */
	unsigned long ip;		/* instruction pointer */
	unsigned long pr_val;		/* current predicates */
	unsigned long *cfm;

	struct task_struct *task;
	struct switch_stack *sw;

	/* preserved state: */
	unsigned long *pbsp;		/* previous bsp */
	unsigned long *bspstore;
	unsigned long *pfs;
	unsigned long *rnat;
	unsigned long *rp;
	unsigned long *pri_unat;
	unsigned long *unat;
	unsigned long *pr;
	unsigned long *lc;
	unsigned long *fpsr;
	struct unw_ireg {
		unsigned long *loc;
		struct unw_ireg_nat {
			int type : 3;		/* enum unw_nat_type */
			signed int off;		/* NaT word is at loc+nat.off */
		} nat;
	} r4, r5, r6, r7;
	unsigned long *b1, *b2, *b3, *b4, *b5;
	struct ia64_fpreg *f2, *f3, *f4, *f5, *fr[16];
};

#endif /* _ASM_UNWIND_H */

/*
 *  Perform any leftover pre-prompt machine-specific initialization tasks here.
 */
static void
ia64_post_init(void)
{
	struct machine_specific *ms;
	struct gnu_request req;
	struct syment *sp;
	ulong flag;

	ms = &ia64_machine_specific;

	if (symbol_exists("unw_init_frame_info")) {
		machdep->flags |= NEW_UNWIND;
		if (MEMBER_EXISTS("unw_frame_info", "pt")) {
			if (MEMBER_EXISTS("pt_regs", "ar_csd")) {
				machdep->flags |= NEW_UNW_V3;
				ms->unwind_init = unwind_init_v3;
				ms->unwind = unwind_v3;
				ms->unwind_debug = unwind_debug_v3;
				ms->dump_unwind_stats = dump_unwind_stats_v3;
			} else {
				machdep->flags |= NEW_UNW_V2;
				ms->unwind_init = unwind_init_v2;
				ms->unwind = unwind_v2;
				ms->unwind_debug = unwind_debug_v2;
				ms->dump_unwind_stats = dump_unwind_stats_v2;
			}
		} else {
			machdep->flags |= NEW_UNW_V1;
			ms->unwind_init = unwind_init_v1;
			ms->unwind = unwind_v1;
			ms->unwind_debug = unwind_debug_v1;
			ms->dump_unwind_stats = dump_unwind_stats_v1;
		}
	} else {
		machdep->flags |= OLD_UNWIND;
		ms->unwind_init = ia64_old_unwind_init;
		ms->unwind = ia64_old_unwind;
	}
	ms->unwind_init();

	if (!VALID_STRUCT(cpuinfo_ia64)) 
		error(WARNING, "cpuinfo_ia64 structure does not exist\n");
	else {
		if (symbol_exists("_cpu_data"))
			ms->cpu_data_address = symbol_value("_cpu_data");
		else if (symbol_exists("boot_cpu_data"))
			get_symbol_data("boot_cpu_data", sizeof(ulong), 
				&ms->cpu_data_address);
		else if (symbol_exists("cpu_data"))
			ms->cpu_data_address = symbol_value("cpu_data");
		else if ((sp = per_cpu_symbol_search("per_cpu__cpu_info")) ||
		         (sp = per_cpu_symbol_search("per_cpu__ia64_cpu_info"))) {
			if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF))
				ms->cpu_data_address = sp->value +
					kt->__per_cpu_offset[0];
				else
					ms->cpu_data_address = sp->value;
		} else {
			error(WARNING, "cannot find cpuinfo_ia64 location\n");
			ms->cpu_data_address = 0;
		}
	
	        if (ms->cpu_data_address) {
	            	if (VALID_MEMBER(cpuinfo_ia64_unimpl_va_mask))
	       			readmem(ms->cpu_data_address +
	                		OFFSET(cpuinfo_ia64_unimpl_va_mask),
	                		KVADDR, &ms->unimpl_va_mask, 
					sizeof(ulong),
	                		"unimpl_va_mask", FAULT_ON_ERROR);
	            	if (VALID_MEMBER(cpuinfo_ia64_unimpl_pa_mask))
	                        readmem(ms->cpu_data_address +
	                                OFFSET(cpuinfo_ia64_unimpl_pa_mask),
	                                KVADDR, &ms->unimpl_pa_mask, 
					sizeof(ulong),
	                                "unimpl_pa_mask", FAULT_ON_ERROR);
		}
	}

        if (symbol_exists("ia64_init_stack") && !ms->ia64_init_stack_size) { 
		get_symbol_type("ia64_init_stack", NULL, &req);
		ms->ia64_init_stack_size = req.length;
	}

	if (DUMPFILE() && ia64_in_init_stack(SWITCH_STACK_ADDR(CURRENT_TASK())))
		machdep->flags |= INIT;

	if (DUMPFILE() && (flag = ia64_in_per_cpu_mca_stack()))
		machdep->flags |= flag;
}

/*
 *  Try using the old unwind scheme if the new one fails,
 *  that is as long as the unw_frame_info structs are the
 *  same size.
 */
static void
try_old_unwind(struct bt_info *bt)
{
	if ((machdep->flags & NEW_UNWIND) &&
	     (STRUCT_SIZE("unw_frame_info") == sizeof(struct unw_frame_info))) {
		error(INFO, "unwind: trying old unwind mechanism\n");
		ia64_old_unwind(bt);
	}
}

/*
 *  Unwind the stack using the basic method used when CONFIG_IA64_NEW_UNWIND
 *  is not configured into the kernel.
 *
 *  NOTE: see kernel source: show_stack() and/or kdba_bt_stack()
 */

static void
ia64_old_unwind_init(void)
{
	long len;

        len = STRUCT_SIZE("unw_frame_info");
        if (len < 0) {
                error(WARNING, "cannot determine size of unw_frame_info\n");
                        machdep->flags |= UNW_OUT_OF_SYNC;
        } else if (len != sizeof(struct unw_frame_info)) {
                error(WARNING, "unw_frame_info size differs: %ld (local: %d)\n",
                        len, sizeof(struct unw_frame_info));
                        machdep->flags |= UNW_OUT_OF_SYNC;
        }

}

static int unw_debug;  /* debug fprintf indent */

static void
ia64_old_unwind(struct bt_info *bt)
{
        struct unw_frame_info unw_frame_info, *info;
	struct syment *sm;
	int frame;
	char *name;

	if (bt->debug)
		CRASHDEBUG_SUSPEND(bt->debug);

	if (CRASHDEBUG(1))
		unw_debug = 0;

	info = &unw_frame_info;
	unw_init_from_blocked_task(info, bt->task);
	frame = 0;

	do {
                if (info->ip == 0) 
                        break; 

		if (!IS_KVADDR(info->ip))
			break;

		if ((sm = value_search(info->ip, NULL)))
			name = sm->name;
		else
			name = "(unknown)";

		if (BT_REFERENCE_CHECK(bt)) {
                	switch (bt->ref->cmdflags & 
				(BT_REF_SYMBOL|BT_REF_HEXVAL))
                	{
                	case BT_REF_SYMBOL:
                        	if (STREQ(name, bt->ref->str)) {
                                	bt->ref->cmdflags |= BT_REF_FOUND;
					goto unwind_return;
				}
                        	break;

                	case BT_REF_HEXVAL:
                        	if (bt->ref->hexval == info->ip) {
                                	bt->ref->cmdflags |= BT_REF_FOUND;
					goto unwind_return;
				}
                        	break;   
                	}
		} else {

			fprintf(fp, "%s#%d [BSP:%lx] %s at %lx\n",
				frame >= 10 ? "" : " ", frame,
				info->bsp, name, info->ip);

			if (bt->flags & BT_FULL)
				rse_function_params(info, name);
			if (bt->flags & BT_LINE_NUMBERS)
				ia64_dump_line_number(info->ip);
		}

		frame++;

		if (CRASHDEBUG(1))
			unw_debug = 0;

		if (STREQ(name, "start_kernel"))
			break;

	} while (old_unw_unwind(info) >= 0);

unwind_return:

        if (!BT_REFERENCE_CHECK(bt) && !is_kernel_thread(bt->task))
        	ia64_exception_frame(bt->stacktop - SIZE(pt_regs), bt);

	if (bt->debug)
		CRASHDEBUG_RESTORE();
}

static unsigned long
ia64_rse_slot_num (unsigned long *addr)
{
        return (((unsigned long) addr) >> 3) & 0x3f;
}

/* 
 * Given a bsp address and a number of register locations, calculate a new 
 * bsp address, accounting for any intervening RNAT stores.
 */
static unsigned long *
ia64_rse_skip_regs (unsigned long *addr, long num_regs)
{
        long delta = ia64_rse_slot_num(addr) + num_regs;

	if (CRASHDEBUG(1)) {
		fprintf(fp, 
	    "%sia64_rse_skip_regs: ia64_rse_slot_num(%lx): %ld num_regs: %ld\n",
			space(unw_debug),
			(ulong)addr, ia64_rse_slot_num(addr), num_regs);
	}

        if (num_regs < 0)
                delta -= 0x3e;

	if (CRASHDEBUG(1)) {
		fprintf(fp, "%sia64_rse_skip_regs: delta: %ld return(%lx)",
			space(unw_debug), delta,
			(ulong)(addr + num_regs + delta/0x3f));
		if (addr > (addr + num_regs + delta/0x3f)) 
			fprintf(fp, "(-%ld)\n",
				addr - (addr + num_regs + delta/0x3f));
		else
			fprintf(fp, "(+%ld)\n",
				(addr + num_regs + delta/0x3f) - addr);
	}

        return(addr + num_regs + delta/0x3f);
}

/*
 * Returns the address of the RNAT slot that covers the slot at
 * address SLOT_ADDR.
 */
static unsigned long *
ia64_rse_rnat_addr (unsigned long *slot_addr)
{
        return (unsigned long *) ((unsigned long) slot_addr | (0x3f << 3));
}

/*
 *  Initialize the key fields in the unw_frame_info structure.
 *
 *  NOTE: see kernel source: unw_init_from_blocked_task()
 */
static void
unw_init_from_blocked_task(struct unw_frame_info *info, ulong task)
{
	ulong sw;
        ulong sol, limit, top;
	ulong ar_pfs, ar_bspstore, b0;

	sw = SWITCH_STACK_ADDR(task);
	BZERO(info, sizeof(struct unw_frame_info));

        readmem(sw + OFFSET(switch_stack_b0), KVADDR,
                &b0, sizeof(ulong), "switch_stack b0", FAULT_ON_ERROR);
        readmem(sw + OFFSET(switch_stack_ar_pfs), KVADDR,
                &ar_pfs, sizeof(ulong), "switch_stack ar_pfs", FAULT_ON_ERROR);
        readmem(sw + OFFSET(switch_stack_ar_bspstore), KVADDR,
                &ar_bspstore, sizeof(ulong), "switch_stack ar_bspstore", 
		FAULT_ON_ERROR);

        sol = (ar_pfs >> 7) & 0x7f; /* size of locals */

        limit = task + IA64_RBS_OFFSET;
        top = ar_bspstore;
        if ((top - task) >= IA64_STK_OFFSET)
                top = limit;

        if (CRASHDEBUG(1)) {
		unw_debug++;
                fprintf(fp, 
                    "unw_init_from_blocked_task: stack top: %lx sol: %ld\n",
			top, sol);
	}

        info->regstk.limit = limit;
        info->regstk.top   = top;
        info->sw = (struct switch_stack *)sw;
        info->bsp = (ulong)ia64_rse_skip_regs((ulong *)info->regstk.top, -sol);
        info->cfm = (ulong *)(sw + OFFSET(switch_stack_ar_pfs));
        info->ip = b0;

	if (CRASHDEBUG(1)) 
		dump_unw_frame_info(info);
}

/*
 *  Update the unw_frame_info structure based upon its current state.
 *  This routine works without enabling CONFIG_IA64_NEW_UNWIND because 
 *  gdb allocates two additional "local" register locations for each
 *  function, found at the end of the stored locals:
 *
 *      register "sol-1" (last local) = ar.pfs (gives us previous sol)
 *      register "sol-2" (2nd to last local = b0 to previous address
 *
 *  NOTE: see kernel source: unw_unwind() (#ifndef CONFIG_IA64_NEW_UNWIND)
 *  On entry, info->regstk.top should point to the register backing
 *  store for r32.
 */

static int
old_unw_unwind (struct unw_frame_info *info)
{
	unsigned long sol, cfm;
	int is_nat;

        if (!readmem((ulong)info->cfm, KVADDR, &cfm,
             sizeof(long), "info->cfm", QUIET|RETURN_ON_ERROR))
		return -1;

        sol = (cfm >> 7) & 0x7f;        /* size of locals */

	if (CRASHDEBUG(1)) {
		fprintf(fp, "old_unw_unwind: cfm: %lx  sol: %ld\n", cfm, sol);
		unw_debug++;
	}

       /*
         * In general, we would have to make use of unwind info to
         * unwind an IA-64 stack, but for now gcc uses a special
         * convention that makes this possible without full-fledged
         * unwind info.  Specifically, we expect "rp" in the second
         * last, and "ar.pfs" in the last local register, so the
         * number of locals in a frame must be at least two.  If it's
         * less than that, we reached the end of the C call stack.
         */
        if (sol < 2)
                return -1;

        info->ip = rse_read_reg(info, sol - 2, &is_nat);

	if (CRASHDEBUG(1))
		fprintf(fp, "old_unw_unwind: ip: %lx\n", info->ip);

        if (is_nat || (info->ip & (machdep->machspec->unimpl_va_mask | 0xf)))
                return -1;

        info->cfm = ia64_rse_skip_regs((ulong *)info->bsp, sol - 1);

        cfm = rse_read_reg(info, sol - 1, &is_nat);

	if (CRASHDEBUG(1))
		fprintf(fp, "old_unw_unwind: info->cfm: %lx => %lx\n", 
			(ulong)info->cfm, cfm);

        if (is_nat)
                return -1;

        sol = (cfm >> 7) & 0x7f;

        info->bsp = (ulong)ia64_rse_skip_regs((ulong *)info->bsp, -sol);

	if (CRASHDEBUG(1)) {
		fprintf(fp, "old_unw_unwind: next sol: %ld\n", sol);
		fprintf(fp, "old_unw_unwind: next bsp: %lx\n", info->bsp);
	}

	return 0;

#ifdef KERNEL_SOURCE
        unsigned long sol, cfm = *info->cfm;
        int is_nat;

        sol = (cfm >> 7) & 0x7f;        /* size of locals */

        /*
         * In general, we would have to make use of unwind info to
         * unwind an IA-64 stack, but for now gcc uses a special
         * convention that makes this possible without full-fledged
         * unwind info.  Specifically, we expect "rp" in the second
         * last, and "ar.pfs" in the last local register, so the
         * number of locals in a frame must be at least two.  If it's
         * less than that, we reached the end of the C call stack.
         */
        if (sol < 2)
                return -1;

        info->ip = rse_read_reg(info, sol - 2, &is_nat);
        if (is_nat || (info->ip & (my_cpu_data.unimpl_va_mask | 0xf)))
                /* reject let obviously bad addresses */
                return -1;

        info->cfm = ia64_rse_skip_regs((unsigned long *) info->bsp, sol - 1);
        cfm = rse_read_reg(info, sol - 1, &is_nat);
        if (is_nat)
                return -1;

        sol = (cfm >> 7) & 0x7f;

        info->bsp = (unsigned long) ia64_rse_skip_regs((unsigned long *) info->bsp, -sol);
        return 0;
#endif  /* KERNEL_SOURCE */
}


/*
 *  Retrieve a register value from the stack, returning its NAT attribute
 *  as well.
 *
 *  NOTE: see kernel source: read_reg()
 */
static ulong
rse_read_reg (struct unw_frame_info *info, int regnum, int *is_nat)
{
        ulong *addr, *rnat_addr, rnat;
	ulong regcontent;

	if (CRASHDEBUG(1)) {
		fprintf(fp, "%srse_read_reg: bsp: %lx\n", space(unw_debug),
			info->bsp);
		unw_debug++;
	}

        addr = ia64_rse_skip_regs((unsigned long *) info->bsp, regnum);

	if (CRASHDEBUG(1)) {
		unw_debug--;
		fprintf(fp, "%srse_read_reg: addr: %lx\n", 
			space(unw_debug), (ulong)addr);
	}

        if (((ulong)addr < info->regstk.limit) || 
	    ((ulong)addr >= info->regstk.top) || 
	    (((long)addr & 0x7) != 0)) {
                *is_nat = 1;

		if (CRASHDEBUG(1))
			fprintf(fp, 
		    "%srse_read_reg: is_nat: %d -- return 0xdeadbeefdeadbeef\n",
				space(unw_debug), *is_nat);

                return 0xdeadbeefdeadbeef;
        }

        rnat_addr = ia64_rse_rnat_addr(addr);

	if (CRASHDEBUG(1))
		fprintf(fp, "%srse_read_reg: rnat_addr: %lx\n", 
			space(unw_debug), (ulong)rnat_addr);

        if ((unsigned long) rnat_addr >= info->regstk.top) 
		readmem((ulong)(info->sw) + OFFSET(switch_stack_ar_rnat), 
			KVADDR, &rnat, sizeof(long), 
			"info->sw->ar_rnat", FAULT_ON_ERROR);
        else
		readmem((ulong)rnat_addr, KVADDR, &rnat, sizeof(long), 
			"rnat_addr", FAULT_ON_ERROR);

        *is_nat = (rnat & (1UL << ia64_rse_slot_num(addr))) != 0;

	if (CRASHDEBUG(1))
		fprintf(fp, "%srse_read_reg: rnat: %lx is_nat: %d\n",
			space(unw_debug), rnat, *is_nat);

	readmem((ulong)addr, KVADDR, &regcontent, sizeof(long), 
		"rse_read_reg addr", FAULT_ON_ERROR);

	if (CRASHDEBUG(1)) {
		char buf[BUFSIZE];

		fprintf(fp, "%srse_read_reg: addr: %lx => %lx ", 
			space(unw_debug), (ulong)addr, regcontent);
		if (is_kernel_text(regcontent))
			fprintf(fp, "(%s)", 
			    value_to_symstr(regcontent, buf, pc->output_radix));
		fprintf(fp, "\n");
	}

        return regcontent;
}

/*
 *  Display the arguments to a function, presuming that they are found at
 *  the beginning of the sol section.
 */

#define MAX_REGISTER_PARAMS (8)

static void 
rse_function_params(struct unw_frame_info *info, char *name)
{
	int i;
	int numargs, is_nat[MAX_REGISTER_PARAMS];
	char buf1[BUFSIZE], buf2[BUFSIZE], *p1, *p2;
	ulong arglist[MAX_REGISTER_PARAMS];

	numargs = MIN(get_function_numargs(info->ip), MAX_REGISTER_PARAMS);

	if (CRASHDEBUG(1))
		fprintf(fp, "rse_function_params: %s: %d args\n",
			name, numargs);

	switch (numargs)
	{
	case 0:
		fprintf(fp, "    (void)\n");
		return;

	case -1:
		return;

	default:
		break;
	}

	for (i = 0; i < numargs; i++) 
		arglist[i] = rse_read_reg(info, i, &is_nat[i]);

	sprintf(buf1, "    (");
	for (i = 0; i < numargs; i++) {
		p1 = &buf1[strlen(buf1)];
		if (is_nat[i])
			sprintf(buf2, "[NAT]");
		else {
			if ((p2 = value_symbol(arglist[i])))
				sprintf(buf2, "%s", p2);
			else
				sprintf(buf2, "%lx", arglist[i]);
		}
		sprintf(p1, "%s%s", i ? ", " : "", buf2);
		if (strlen(buf1) >= 80) 
			sprintf(p1, ",\n     %s", buf2);
	}
	strcat(buf1, ")\n");

	fprintf(fp, "%s", buf1);

}


static void 
dump_unw_frame_info(struct unw_frame_info *info)
{
	unw_debug++;

	fprintf(fp, "%sregstk.limit: %lx\n", 
		space(unw_debug), info->regstk.limit);
	fprintf(fp, "%s  regstk.top: %lx\n", 
		space(unw_debug), info->regstk.top);
	fprintf(fp, "%s          sw: %lx\n", 
		space(unw_debug), (ulong)info->sw);
	fprintf(fp, "%s         bsp: %lx\n", 
		space(unw_debug), info->bsp);
	fprintf(fp, "%s         cfm: %lx\n", 
		space(unw_debug), (ulong)info->cfm);
	fprintf(fp, "%s          ip: %lx\n", 
		space(unw_debug), info->ip);

	unw_debug--;
}

static const char *hook_files[] = {
        "arch/ia64/kernel/entry.S",
        "arch/ia64/kernel/head.S",
};

#define ENTRY_S      ((char **)&hook_files[0])
#define HEAD_S       ((char **)&hook_files[1])

static struct line_number_hook ia64_line_number_hooks[] = {
	{"ia64_execve", ENTRY_S},
	{"sys_clone2", ENTRY_S},
	{"sys_clone", ENTRY_S},
	{"ia64_switch_to", ENTRY_S},
	{"save_switch_stack", ENTRY_S},
	{"load_switch_stack", ENTRY_S},
	{"__ia64_syscall", ENTRY_S},
	{"invoke_syscall_trace", ENTRY_S},
	{"ia64_trace_syscall", ENTRY_S},
	{"ia64_ret_from_clone", ENTRY_S},
	{"ia64_ret_from_syscall", ENTRY_S},
	{"ia64_leave_kernel", ENTRY_S},
	{"handle_syscall_error", ENTRY_S},
	{"invoke_schedule_tail", ENTRY_S},
	{"invoke_schedule", ENTRY_S},
	{"handle_signal_delivery", ENTRY_S},
	{"sys_rt_sigsuspend", ENTRY_S},
	{"sys_rt_sigreturn", ENTRY_S},
	{"ia64_prepare_handle_unaligned", ENTRY_S},
	{"unw_init_running", ENTRY_S},

        {"_start", HEAD_S},
        {"ia64_save_debug_regs", HEAD_S},
        {"ia64_load_debug_regs", HEAD_S},
        {"__ia64_save_fpu", HEAD_S},
        {"__ia64_load_fpu", HEAD_S},
        {"__ia64_init_fpu", HEAD_S},
        {"ia64_switch_mode", HEAD_S},
        {"ia64_set_b1", HEAD_S},
        {"ia64_set_b2", HEAD_S},
        {"ia64_set_b3", HEAD_S},
        {"ia64_set_b4", HEAD_S},
        {"ia64_set_b5", HEAD_S},
        {"ia64_spinlock_contention", HEAD_S},

       {NULL, NULL}    /* list must be NULL-terminated */
};

void 
ia64_dump_line_number(ulong ip)
{
	int retries;
	char buf[BUFSIZE], *p;

        retries = 0;
try_closest:
	get_line_number(ip, buf, FALSE);

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
                        ip = closest_symbol_value(ip);
                        goto try_closest;
                }
        }
}

/*
 *  For now, just make it a region 7 address for all cases, ignoring the
 *  fact that it might be in a 2.6 kernel's non-unity mapped region.  XXX
 */
ulong
ia64_PTOV(ulong paddr)
{
	ulong vaddr;
	switch (machdep->machspec->kernel_region)
	{
	case KERNEL_VMALLOC_REGION:
//		error(FATAL, "ia64_PTOV: TBD for kernels loaded in region 5\n");
	default:
	case KERNEL_CACHED_REGION:
		vaddr = paddr + (ulong)(KERNEL_CACHED_BASE);
	}

	return vaddr;
}

/*
 *  Account for 2.6 kernel mapping in region 5.
 */
ulong
ia64_VTOP(ulong vaddr)
{
        struct machine_specific *ms;
	ulong paddr;

        ms = &ia64_machine_specific;

	switch (VADDR_REGION(vaddr)) 
	{
	case KERNEL_CACHED_REGION:
		paddr = vaddr - (ulong)(KERNEL_CACHED_BASE);
		break;

	case KERNEL_UNCACHED_REGION:
		paddr = vaddr - (ulong)(KERNEL_UNCACHED_BASE);
		break;

	/* 
	 *  Differentiate between a 2.6 kernel address in region 5 and 
	 *  a real vmalloc() address.  
	 */
	case KERNEL_VMALLOC_REGION:
	       /*
	 	* Real vmalloc() addresses should never be the subject 
	        * of a VTOP() translation.
	        */
		if (ia64_IS_VMALLOC_ADDR(vaddr) ||
        	    (ms->kernel_region != KERNEL_VMALLOC_REGION))
			return(error(FATAL, 
			    "ia64_VTOP(%lx): unexpected region 5 address\n",
				 vaddr));
	       /*
	 	*  If it's a region 5 kernel address, subtract the starting
		*  kernel virtual address, and then add the base physical page.
	 	*/
		paddr = vaddr - ms->kernel_start + 
			(ms->phys_start & KERNEL_TR_PAGE_MASK);
		break;

	default:
		return(error(FATAL, 
			"ia64_VTOP(%lx): invalid kernel address\n", vaddr));
	}

	return paddr;
}

/*
 *  vmalloc() starting address is either the traditional 0xa000000000000000 or
 *  bumped up in 2.6 to 0xa000000200000000.
 */
int
ia64_IS_VMALLOC_ADDR(ulong vaddr)
{
	return ((vaddr >= machdep->machspec->vmalloc_start) && 
        	(vaddr < (ulong)KERNEL_UNCACHED_BASE));
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
ia64_get_kvaddr_ranges(struct vaddr_range *vrp)
{
	int cnt;

	cnt = 0;

	vrp[cnt].type = KVADDR_UNITY_MAP;
	vrp[cnt].start = machdep->identity_map_base;
	vrp[cnt++].end = vt->high_memory;

	if (machdep->machspec->kernel_start != machdep->identity_map_base) {
		vrp[cnt].type = KVADDR_START_MAP;
		vrp[cnt].start = machdep->machspec->kernel_start;
		vrp[cnt++].end = kt->end;
	}

	vrp[cnt].type = KVADDR_VMALLOC;
	vrp[cnt].start = machdep->machspec->vmalloc_start;
	vrp[cnt++].end = (ulong)KERNEL_UNCACHED_REGION << REGION_SHIFT;

	if (VADDR_REGION(vt->node_table[0].mem_map) == KERNEL_VMALLOC_REGION) {
		vrp[cnt].type = KVADDR_VMEMMAP;
		vrp[cnt].start = vt->node_table[0].mem_map;
		vrp[cnt].end = vt->node_table[vt->numnodes-1].mem_map +
			(vt->node_table[vt->numnodes-1].size *  
			 SIZE(page));
		/*
		 * Prevent overlap with KVADDR_VMALLOC range.
		 */
		if (vrp[cnt].start > vrp[cnt-1].start)
			vrp[cnt-1].end = vrp[cnt].start;
		cnt++;
	}

	qsort(vrp, cnt, sizeof(struct vaddr_range), compare_kvaddr);

	return cnt;
}


/* Generic abstraction to translate user or kernel virtual
 * addresses to physical using a 4 level page table.
 */
static int
ia64_vtop_4l_xen_wpt(ulong vaddr, physaddr_t *paddr, ulong *pgd, int verbose, int usr)
{
	error(FATAL, "ia64_vtop_4l_xen_wpt: TBD\n");
	return FALSE;
#ifdef TBD
	ulong *page_dir;
	ulong *page_upper;
	ulong *page_middle;
	ulong *page_table;
	ulong pgd_pte;
	ulong pud_pte;
	ulong pmd_pte;
	ulong pte;
	ulong region, offset;


	if (usr) {
		region = VADDR_REGION(vaddr);
		offset = (vaddr >> PGDIR_SHIFT) & ((PTRS_PER_PGD >> 3) - 1);
		offset |= (region << (PAGESHIFT() - 6));
		page_dir = pgd + offset;
	} else {
		if (!(pgd = (ulong *)vt->kernel_pgd[0]))
			error(FATAL, "cannot determine kernel pgd pointer\n");
		page_dir = pgd + ((vaddr >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1));
	}

	if (verbose) 
		fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)pgd);

	FILL_PGD(PAGEBASE(pgd), KVADDR, PAGESIZE());
	pgd_pte = ULONG(machdep->pgd + PAGEOFFSET(page_dir));
	
        if (verbose) 
                fprintf(fp, "   PGD: %lx => %lx\n", (ulong)page_dir, pgd_pte);

        if (!(pgd_pte))
		return FALSE;
	
	offset = (vaddr >> PUD_SHIFT) & (PTRS_PER_PUD - 1);
	page_upper = (ulong *)(PTOV(pgd_pte & _PFN_MASK)) + offset; 
	
	FILL_PUD(PAGEBASE(page_upper), KVADDR, PAGESIZE());
	pud_pte = ULONG(machdep->pud + PAGEOFFSET(page_upper));
        
	if (verbose) 
                fprintf(fp, "   PUD: %lx => %lx\n", (ulong)page_upper, pud_pte);
        
	if (!(pud_pte))
		return FALSE;

	offset = (vaddr >> PMD_SHIFT) & (PTRS_PER_PMD - 1);
	page_middle = (ulong *)(PTOV(pud_pte & _PFN_MASK)) + offset; 

	FILL_PMD(PAGEBASE(page_middle), KVADDR, PAGESIZE());
	pmd_pte = ULONG(machdep->pmd + PAGEOFFSET(page_middle));

        if (verbose)
                fprintf(fp, "   PMD: %lx => %lx\n", (ulong)page_middle, pmd_pte);

        if (!(pmd_pte))
		return FALSE;

        offset = (vaddr >> PAGESHIFT()) & (PTRS_PER_PTE - 1);
        page_table = (ulong *)(PTOV(pmd_pte & _PFN_MASK)) + offset;

	FILL_PTBL(PAGEBASE(page_table), KVADDR, PAGESIZE());
	pte = ULONG(machdep->ptbl + PAGEOFFSET(page_table));

        if (verbose)
                fprintf(fp, "   PTE: %lx => %lx\n", (ulong)page_table, pte);

        if (!(pte & (_PAGE_P))) {
		if (usr)
		  	*paddr = pte;
		if (pte && verbose) {
			fprintf(fp, "\n");
			ia64_translate_pte(pte, 0, 0);
		}
		return FALSE;
        }

        *paddr = (pte & _PFN_MASK) + PAGEOFFSET(vaddr);

        if (verbose) {
                fprintf(fp, "  PAGE: %lx\n\n", PAGEBASE(*paddr));
		ia64_translate_pte(pte, 0, 0);
	}

	return TRUE;
#endif
}

/* Generic abstraction to translate user or kernel virtual
 * addresses to physical using a 3 level page table.
 */
static int
ia64_vtop_xen_wpt(ulong vaddr, physaddr_t *paddr, ulong *pgd, int verbose, int usr)
{
	error(FATAL, "ia64_vtop_xen_wpt: TBD\n");
	return FALSE;
#ifdef TBD
	ulong *page_dir;
	ulong *page_middle;
	ulong *page_table;
	ulong pgd_pte;
	ulong pmd_pte;
	ulong pte;
	ulong region, offset;


	if (usr) {
		region = VADDR_REGION(vaddr);
		offset = (vaddr >> PGDIR_SHIFT) & ((PTRS_PER_PGD >> 3) - 1);
		offset |= (region << (PAGESHIFT() - 6));
		page_dir = pgd + offset;
	} else {
		if (!(pgd = (ulong *)vt->kernel_pgd[0]))
			error(FATAL, "cannot determine kernel pgd pointer\n");
		page_dir = pgd + ((vaddr >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1));
	}

	if (verbose)
		fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)pgd);

	FILL_PGD(PAGEBASE(pgd), KVADDR, PAGESIZE());
	pgd_pte = ULONG(machdep->pgd + PAGEOFFSET(page_dir));
	
        if (verbose) 
                fprintf(fp, "   PGD: %lx => %lx\n", (ulong)page_dir, pgd_pte);

        if (!(pgd_pte))
		return FALSE;

	offset = (vaddr >> PMD_SHIFT) & (PTRS_PER_PMD - 1);
	page_middle = (ulong *)(PTOV(pgd_pte & _PFN_MASK)) + offset; 

	FILL_PMD(PAGEBASE(page_middle), KVADDR, PAGESIZE());
	pmd_pte = ULONG(machdep->pmd + PAGEOFFSET(page_middle));

        if (verbose)
                fprintf(fp, "   PMD: %lx => %lx\n", (ulong)page_middle, pmd_pte);

        if (!(pmd_pte))
		return FALSE;

        offset = (vaddr >> PAGESHIFT()) & (PTRS_PER_PTE - 1);
        page_table = (ulong *)(PTOV(pmd_pte & _PFN_MASK)) + offset;

	FILL_PTBL(PAGEBASE(page_table), KVADDR, PAGESIZE());
	pte = ULONG(machdep->ptbl + PAGEOFFSET(page_table));

        if (verbose)
                fprintf(fp, "   PTE: %lx => %lx\n", (ulong)page_table, pte);

        if (!(pte & (_PAGE_P))) {
		if (usr)
		  	*paddr = pte;
		if (pte && verbose) {
			fprintf(fp, "\n");
			ia64_translate_pte(pte, 0, 0);
		}
		return FALSE;
        }

        *paddr = (pte & _PFN_MASK) + PAGEOFFSET(vaddr);

        if (verbose) {
                fprintf(fp, "  PAGE: %lx\n\n", PAGEBASE(*paddr));
		ia64_translate_pte(pte, 0, 0);
	}

	return TRUE;
#endif
}

#include "netdump.h"
#include "xen_dom0.h"

/*
 *  Determine the relocatable physical address base.
 */
static void
ia64_calc_phys_start(void)
{
	FILE *iomem;
	int i, found, errflag;
	char buf[BUFSIZE];
	char *p1;
	ulong kernel_code_start;
	struct vmcore_data *vd;
	ulong phys_start, text_start;
	Elf64_Phdr *phdr = NULL;

	/*
	 *  Default to 64MB.
	 */
	machdep->machspec->phys_start = DEFAULT_PHYS_START;

	text_start = symbol_exists("_text") ? symbol_value("_text") : BADADDR;

	if (ACTIVE()) {
	        if ((iomem = fopen("/proc/iomem", "r")) == NULL)
	                return;
	
		errflag = 1;
	        while (fgets(buf, BUFSIZE, iomem)) {
			if (strstr(buf, ": Kernel code")) {
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
		else
			*p1 = NULLCHAR;
	
		errflag = 0;
		kernel_code_start = htol(buf, RETURN_ON_ERROR|QUIET, &errflag);
	        if (errflag)
			return;
	
		machdep->machspec->phys_start = kernel_code_start;
	
		if (CRASHDEBUG(1)) {
			if (text_start == BADADDR)
				fprintf(fp, "_text: (unknown)  ");
			else
				fprintf(fp, "_text: %lx  ", text_start);
			fprintf(fp, "Kernel code: %lx -> ", kernel_code_start);
			fprintf(fp, "phys_start: %lx\n\n", 
				machdep->machspec->phys_start);
		}

		return;
	}

	/*
	 *  Get relocation value from whatever dumpfile format is being used.
	 */

        if (DISKDUMP_DUMPFILE()) {
                if (diskdump_phys_base(&phys_start)) {
                        machdep->machspec->phys_start = phys_start;
			if (CRASHDEBUG(1))
				fprintf(fp, 
				    "compressed kdump: phys_start: %lx\n",
					phys_start);
		}
                return;
        } else if (LKCD_DUMPFILE()) {

		if (lkcd_get_kernel_start(&phys_start)) {
                        machdep->machspec->phys_start = phys_start;
			if (CRASHDEBUG(1))
				fprintf(fp,
				    "LKCD dump: phys_start: %lx\n",
					phys_start);
		}
	}

	if ((vd = get_kdump_vmcore_data())) {
		/*
		 *  There should be at most one region 5 region, and it
		 *  should be equal to "_text".  If not, take whatever
		 *  region 5 address comes first and hope for the best.
		 */
                for (i = found = 0; i < vd->num_pt_load_segments; i++) {
			phdr = vd->load64 + i;
			if (phdr->p_vaddr == text_start) {
				machdep->machspec->phys_start = phdr->p_paddr;
				found++;
				break;
			}
		}

                for (i = 0; !found && (i < vd->num_pt_load_segments); i++) {
			phdr = vd->load64 + i;
			if (VADDR_REGION(phdr->p_vaddr) == KERNEL_VMALLOC_REGION) {
				machdep->machspec->phys_start = phdr->p_paddr;
				found++;
				break;
			}
		}

		if (found && CRASHDEBUG(1)) {
			if (text_start == BADADDR)
				fprintf(fp, "_text: (unknown)  ");
			else
				fprintf(fp, "_text: %lx  ", text_start);
			fprintf(fp, "p_vaddr: %lx  p_paddr: %lx\n", 
				phdr->p_vaddr, phdr->p_paddr);
		}

		return;
	}
}

/*
 *  From the xen vmcore, create an index of mfns for each page that makes
 *  up the dom0 kernel's complete phys_to_machine_mapping[max_pfn] array.
 */
static int
ia64_xen_kdump_p2m_create(struct xen_kdump_data *xkd)
{
	/*
	 *  Temporarily read physical (machine) addresses from vmcore.
	 */
	pc->curcmd_flags |= XEN_MACHINE_ADDR;

	if (CRASHDEBUG(1)) {
		fprintf(fp, "readmem (temporary): force XEN_MACHINE_ADDR\n");
		fprintf(fp, "ia64_xen_kdump_p2m_create: p2m_mfn: %lx\n", xkd->p2m_mfn);
	}

	if ((xkd->p2m_mfn_frame_list = (ulong *)malloc(PAGESIZE())) == NULL)
		error(FATAL, "cannot malloc p2m_frame_list");

	if (!readmem(PTOB(xkd->p2m_mfn), PHYSADDR, xkd->p2m_mfn_frame_list, PAGESIZE(), 
	    "xen kdump p2m mfn page", RETURN_ON_ERROR))
		error(FATAL, "cannot read xen kdump p2m mfn page\n");

	xkd->p2m_frames = PAGESIZE()/sizeof(ulong);

	pc->curcmd_flags &= ~XEN_MACHINE_ADDR;
	if (CRASHDEBUG(1))
		fprintf(fp, "readmem (restore): p2m translation\n");

	return TRUE;
}

physaddr_t
ia64_xen_kdump_p2m(struct xen_kdump_data *xkd, physaddr_t pseudo)
{
	ulong pgd_idx, pte_idx;
	ulong pmd, pte;
	physaddr_t paddr;

	/*
	 *  Temporarily read physical (machine) addresses from vmcore.
	 */
	pc->curcmd_flags |= XEN_MACHINE_ADDR;
	if (CRASHDEBUG(1))
		fprintf(fp, "readmem (temporary): force XEN_MACHINE_ADDR\n");

	xkd->accesses += 2;

	pgd_idx = (pseudo >> PGDIR_SHIFT_3L) & (PTRS_PER_PGD - 1);
	pmd = xkd->p2m_mfn_frame_list[pgd_idx] & _PFN_MASK;
	if (!pmd) {
		paddr = P2M_FAILURE;
		goto out;
	}

	pmd += ((pseudo >> PMD_SHIFT) & (PTRS_PER_PMD - 1)) * sizeof(ulong);
	if (pmd != xkd->last_pmd_read) {
		if (!readmem(pmd, PHYSADDR, &pte, sizeof(ulong), 
		    "ia64_xen_kdump_p2m pmd", RETURN_ON_ERROR)) {
			xkd->last_pmd_read = BADADDR;
			xkd->last_mfn_read = BADADDR;
			paddr = P2M_FAILURE;
			goto out;
		}
		xkd->last_pmd_read = pmd;
	} else {
		pte = xkd->last_mfn_read;
		xkd->cache_hits++;
	}
	pte = pte & _PFN_MASK;
	if (!pte) {
		paddr = P2M_FAILURE;
		goto out;
	}

	if (pte != xkd->last_mfn_read) {
		if (!readmem(pte, PHYSADDR, xkd->page, PAGESIZE(), 
		    "ia64_xen_kdump_p2m pte page", RETURN_ON_ERROR)) {
			xkd->last_pmd_read = BADADDR;
			xkd->last_mfn_read = BADADDR;
			paddr = P2M_FAILURE;
			goto out;
		}
		xkd->last_mfn_read = pte;
	} else
		xkd->cache_hits++;

	pte_idx = (pseudo >> PAGESHIFT()) & (PTRS_PER_PTE - 1);
	paddr = *(((ulong *)xkd->page) + pte_idx);
	if (!(paddr & _PAGE_P)) {
		paddr = P2M_FAILURE;
		goto out;
	}
	paddr = (paddr & _PFN_MASK) | PAGEOFFSET(pseudo);

out:
	pc->curcmd_flags &= ~XEN_MACHINE_ADDR;
	if (CRASHDEBUG(1))
		fprintf(fp, "readmem (restore): p2m translation\n");

	return paddr;
}

#include "xendump.h"

/*
 *  Create an index of mfns for each page that makes up the
 *  kernel's complete phys_to_machine_mapping[max_pfn] array.
 */
static int
ia64_xendump_p2m_create(struct xendump_data *xd)
{
	if (!symbol_exists("phys_to_machine_mapping")) {
		xd->flags |= XC_CORE_NO_P2M;
		return TRUE;
	}

	error(FATAL, "ia64_xendump_p2m_create: TBD\n");

	/* dummy calls for clean "make [wW]arn" */
	ia64_debug_dump_page(NULL, NULL, NULL);
	ia64_xendump_load_page(0, xd);
	ia64_xendump_page_index(0, xd);
	ia64_xendump_panic_task(xd);  /* externally called */
	ia64_get_xendump_regs(xd, NULL, NULL, NULL);  /* externally called */

	return FALSE;
}

static void
ia64_debug_dump_page(FILE *ofp, char *page, char *name)
{
        int i;
        ulong *up;

        fprintf(ofp, "%s\n", name);

        up = (ulong *)page;
        for (i = 0; i < 1024; i++) {
                fprintf(ofp, "%016lx: %016lx %016lx\n",
                        (ulong)((i * 2) * sizeof(ulong)),
                        *up, *(up+1));
                up += 2;
        }
}

/*
 *  Find the page associate with the kvaddr, and read its contents
 *  into the passed-in buffer.
 */
static char *
ia64_xendump_load_page(ulong kvaddr, struct xendump_data *xd)
{
	error(FATAL, "ia64_xendump_load_page: TBD\n");

	return NULL;
}

/*
 *  Find the dumpfile page index associated with the kvaddr.
 */
static int
ia64_xendump_page_index(ulong kvaddr, struct xendump_data *xd)
{
	error(FATAL, "ia64_xendump_page_index: TBD\n");

	return 0;
}

static ulong
ia64_xendump_panic_task(struct xendump_data *xd)
{
	if (CRASHDEBUG(1))
		error(INFO, "ia64_xendump_panic_task: TBD\n");

	return NO_TASK;
}

static void
ia64_get_xendump_regs(struct xendump_data *xd, struct bt_info *bt, ulong *rip, ulong *rsp)
{
        machdep->get_stack_frame(bt, rip, rsp);

	if (is_task_active(bt->task) &&
            !(bt->flags & (BT_TEXT_SYMBOLS_ALL|BT_TEXT_SYMBOLS)) &&
	    STREQ(closest_symbol(*rip), "schedule"))
		error(INFO, 
		    "xendump: switch_stack possibly not saved -- try \"bt -t\"\n");
}

/* for XEN Hypervisor analysis */

static int
ia64_is_kvaddr_hyper(ulong addr)
{
	return (addr >= HYPERVISOR_VIRT_START && addr < HYPERVISOR_VIRT_END);
}

static int
ia64_kvtop_hyper(struct task_context *tc, ulong kvaddr, physaddr_t *paddr, int verbose)
{
	ulong virt_percpu_start, phys_percpu_start;
	ulong addr, dirp, entry;

	if (!IS_KVADDR(kvaddr))
		return FALSE;

	if (PERCPU_VIRT_ADDR(kvaddr)) {
		virt_percpu_start = symbol_value("__phys_per_cpu_start");
		phys_percpu_start = virt_percpu_start - DIRECTMAP_VIRT_START;
		*paddr = kvaddr - PERCPU_ADDR + phys_percpu_start;
		return TRUE;
	} else if (DIRECTMAP_VIRT_ADDR(kvaddr)) {
		*paddr = kvaddr - DIRECTMAP_VIRT_START;
		return TRUE;
	} else if (!FRAME_TABLE_VIRT_ADDR(kvaddr)) {
		return FALSE;
	}

	/* frametable virtual address */
	addr = kvaddr - xhmachdep->frame_table;

	dirp = symbol_value("frametable_pg_dir");
	dirp += ((addr >> PGDIR_SHIFT_3L) & (PTRS_PER_PGD - 1)) * sizeof(ulong);
	readmem(dirp, KVADDR, &entry, sizeof(ulong), 
		"frametable_pg_dir", FAULT_ON_ERROR);

	dirp = entry & _PFN_MASK;
	if (!dirp)
		return FALSE;
	dirp += ((addr >> PMD_SHIFT) & (PTRS_PER_PMD - 1)) * sizeof(ulong);
	readmem(dirp, PHYSADDR, &entry, sizeof(ulong), 
		"frametable pmd", FAULT_ON_ERROR);

	dirp = entry & _PFN_MASK;
	if (!dirp)
		return FALSE;
	dirp += ((addr >> PAGESHIFT()) & (PTRS_PER_PTE - 1)) * sizeof(ulong);
	readmem(dirp, PHYSADDR, &entry, sizeof(ulong), 
		"frametable pte", FAULT_ON_ERROR);

	if (!(entry & _PAGE_P))
		return FALSE;

	*paddr = (entry & _PFN_MASK) + (kvaddr & (PAGESIZE() - 1));
	return TRUE;
}

static void
ia64_post_init_hyper(void)
{
	struct machine_specific *ms;
	ulong frame_table;

	ms = &ia64_machine_specific;

	if (symbol_exists("unw_init_frame_info")) {
		machdep->flags |= NEW_UNWIND;
		if (MEMBER_EXISTS("unw_frame_info", "pt")) {
			if (MEMBER_EXISTS("cpu_user_regs", "ar_csd")) {
				machdep->flags |= NEW_UNW_V3;
				ms->unwind_init = unwind_init_v3;
				ms->unwind = unwind_v3;
				ms->unwind_debug = unwind_debug_v3;
				ms->dump_unwind_stats = dump_unwind_stats_v3;
			} else {
				machdep->flags |= NEW_UNW_V2;
				ms->unwind_init = unwind_init_v2;
				ms->unwind = unwind_v2;
				ms->unwind_debug = unwind_debug_v2;
				ms->dump_unwind_stats = dump_unwind_stats_v2;
			}
		} else {
			machdep->flags |= NEW_UNW_V1;
			ms->unwind_init = unwind_init_v1;
			ms->unwind = unwind_v1;
			ms->unwind_debug = unwind_debug_v1;
			ms->dump_unwind_stats = dump_unwind_stats_v1;
		}
	} else {
		machdep->flags |= OLD_UNWIND;
		ms->unwind_init = ia64_old_unwind_init;
		ms->unwind = ia64_old_unwind;
	}
	ms->unwind_init();

	if (symbol_exists("frame_table")) {
		frame_table = symbol_value("frame_table");
		readmem(frame_table, KVADDR, &xhmachdep->frame_table, sizeof(ulong),
			"frame_table virtual address", FAULT_ON_ERROR);
	} else {
		error(FATAL, "cannot find frame_table virtual address.");
	}
}

int
ia64_in_mca_stack_hyper(ulong addr, struct bt_info *bt)
{
	int plen, i;
	ulong paddr, stackbase, stacktop;
	ulong *__per_cpu_mca;
	struct xen_hyper_vcpu_context *vcc;

	vcc = xen_hyper_vcpu_to_vcpu_context(bt->task);
	if (!vcc)
		return 0;

	if (!symbol_exists("__per_cpu_mca") ||
	    !(plen = get_array_length("__per_cpu_mca", NULL, 0)) ||
	    (plen < xht->pcpus))
		return 0;

	if (!machdep->kvtop(NULL, addr, &paddr, 0))
		return 0;

	__per_cpu_mca = (ulong *)GETBUF(sizeof(ulong) * plen);

	if (!readmem(symbol_value("__per_cpu_mca"), KVADDR, __per_cpu_mca,
	    sizeof(ulong) * plen, "__per_cpu_mca", RETURN_ON_ERROR|QUIET))
		return 0;

	if (CRASHDEBUG(1)) {
		for (i = 0; i < plen; i++) {
			fprintf(fp, "__per_cpu_mca[%d]: %lx\n", 
		 		i, __per_cpu_mca[i]);
		}
	}

	stackbase = __per_cpu_mca[vcc->processor];
	stacktop = stackbase + (STACKSIZE() * 2);
	FREEBUF(__per_cpu_mca);

	if ((paddr >= stackbase) && (paddr < stacktop))
		return 1;
	else
		return 0;
}

static void
ia64_init_hyper(int when)
{
	struct syment *sp;

        switch (when)
        {
	case SETUP_ENV:
#if defined(PR_SET_FPEMU) && defined(PR_FPEMU_NOPRINT)
		prctl(PR_SET_FPEMU, PR_FPEMU_NOPRINT, 0, 0, 0);
#endif
#if defined(PR_SET_UNALIGN) && defined(PR_UNALIGN_NOPRINT)
		prctl(PR_SET_UNALIGN, PR_UNALIGN_NOPRINT, 0, 0, 0);
#endif
		break;

        case PRE_SYMTAB:
                machdep->verify_symbol = ia64_verify_symbol;
		machdep->machspec = &ia64_machine_specific;
		if (pc->flags & KERNEL_DEBUG_QUERY)
			return;
                machdep->pagesize = memory_page_size();
                machdep->pageshift = ffs(machdep->pagesize) - 1;
                machdep->pageoffset = machdep->pagesize - 1;
                machdep->pagemask = ~(machdep->pageoffset);
		switch (machdep->pagesize)
		{
		case 4096:
			machdep->stacksize = (power(2, 3) * PAGESIZE());
			break;
		case 8192:
			machdep->stacksize = (power(2, 2) * PAGESIZE());
			break;
		case 16384:
			machdep->stacksize = (power(2, 1) * PAGESIZE());
			break;
		case 65536:
			machdep->stacksize = (power(2, 0) * PAGESIZE());
			break;
		default:
			machdep->stacksize = 32*1024;
			break;
		}
                if ((machdep->pgd = (char *)malloc(PAGESIZE())) == NULL)
                        error(FATAL, "cannot malloc pgd space.");
		if ((machdep->pud = (char *)malloc(PAGESIZE())) == NULL)
			error(FATAL, "cannot malloc pud space.");
                if ((machdep->pmd = (char *)malloc(PAGESIZE())) == NULL)
                        error(FATAL, "cannot malloc pmd space.");
                if ((machdep->ptbl = (char *)malloc(PAGESIZE())) == NULL)
                        error(FATAL, "cannot malloc ptbl space.");
                machdep->last_pgd_read = 0;
                machdep->last_pud_read = 0;
                machdep->last_pmd_read = 0;
                machdep->last_ptbl_read = 0;
		machdep->verify_paddr = ia64_verify_paddr;
		machdep->ptrs_per_pgd = PTRS_PER_PGD;
                machdep->machspec->phys_start = UNKNOWN_PHYS_START;
		/* ODA: if need make hyper version
                if (machdep->cmdline_args[0]) 
			parse_cmdline_args(); */
                break;     

        case PRE_GDB:

		if (pc->flags & KERNEL_DEBUG_QUERY)
			return;
		
                machdep->kvbase = HYPERVISOR_VIRT_START;
		machdep->identity_map_base = HYPERVISOR_VIRT_START;
                machdep->is_kvaddr = ia64_is_kvaddr_hyper;
                machdep->is_uvaddr = generic_is_uvaddr;
                machdep->eframe_search = ia64_eframe_search;
                machdep->back_trace = ia64_back_trace_cmd;
                machdep->processor_speed = xen_hyper_ia64_processor_speed;
                machdep->uvtop = ia64_uvtop;
                machdep->kvtop = ia64_kvtop_hyper;
		machdep->get_stack_frame = ia64_get_stack_frame;
		machdep->get_stackbase = ia64_get_stackbase;
		machdep->get_stacktop = ia64_get_stacktop;
                machdep->translate_pte = ia64_translate_pte;
                machdep->memory_size = xen_hyper_ia64_memory_size;
                machdep->dis_filter = ia64_dis_filter;
		machdep->cmd_mach = ia64_cmd_mach;
		machdep->get_smp_cpus = xen_hyper_ia64_get_smp_cpus;
		machdep->line_number_hooks = ia64_line_number_hooks;
		machdep->value_to_symbol = generic_machdep_value_to_symbol;
                machdep->init_kernel_pgd = NULL;

		if ((sp = symbol_search("_stext"))) {
			machdep->machspec->kernel_region = 
				VADDR_REGION(sp->value);
			machdep->machspec->kernel_start = sp->value;
		} else {
//			machdep->machspec->kernel_region = KERNEL_CACHED_REGION;
//			machdep->machspec->kernel_start = KERNEL_CACHED_BASE;
		}

		/* machdep table for Xen Hypervisor */
		xhmachdep->pcpu_init = xen_hyper_ia64_pcpu_init;
                break;

        case POST_GDB:
		STRUCT_SIZE_INIT(switch_stack, "switch_stack");
		MEMBER_OFFSET_INIT(thread_struct_fph, "thread_struct", "fph");
		MEMBER_OFFSET_INIT(switch_stack_b0, "switch_stack", "b0");
		MEMBER_OFFSET_INIT(switch_stack_ar_bspstore,  
			"switch_stack", "ar_bspstore");
		MEMBER_OFFSET_INIT(switch_stack_ar_pfs,  
			"switch_stack", "ar_pfs");
		MEMBER_OFFSET_INIT(switch_stack_ar_rnat, 
			"switch_stack", "ar_rnat");
		MEMBER_OFFSET_INIT(switch_stack_pr, 
			"switch_stack", "pr");

		XEN_HYPER_STRUCT_SIZE_INIT(cpuinfo_ia64, "cpuinfo_ia64");
		XEN_HYPER_MEMBER_OFFSET_INIT(cpuinfo_ia64_proc_freq, "cpuinfo_ia64", "proc_freq");
		XEN_HYPER_MEMBER_OFFSET_INIT(cpuinfo_ia64_vendor, "cpuinfo_ia64", "vendor");
		if (symbol_exists("per_cpu__cpu_info")) {
			xht->cpu_data_address = symbol_value("per_cpu__cpu_info");
		}
		/* kakuma Can this be calculated? */
		if (!machdep->hz) {
			machdep->hz = XEN_HYPER_HZ;
		}
                break;

	case POST_INIT:
		ia64_post_init_hyper();
		break;
	}
}
#endif
