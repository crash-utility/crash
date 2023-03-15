/* x86_64.c -- core analysis suite
 *
 * Copyright (C) 2004-2019 David Anderson
 * Copyright (C) 2004-2019 Red Hat, Inc. All rights reserved.
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
#include "xen_hyper_defs.h"

#ifdef X86_64

static int x86_64_kvtop(struct task_context *, ulong, physaddr_t *, int);
static int x86_64_kvtop_xen_wpt(struct task_context *, ulong, physaddr_t *, int);
static int x86_64_uvtop(struct task_context *, ulong, physaddr_t *, int);
static int x86_64_uvtop_level4(struct task_context *, ulong, physaddr_t *, int);
static int x86_64_uvtop_level4_xen_wpt(struct task_context *, ulong, physaddr_t *, int);
static int x86_64_uvtop_level4_rhel4_xen_wpt(struct task_context *, ulong, physaddr_t *, int);
static ulong x86_64_vmalloc_start(void);
static int x86_64_is_task_addr(ulong);
static int x86_64_verify_symbol(const char *, ulong, char);
static int x86_64_verify_line_number(ulong, ulong, ulong);
static ulong x86_64_get_task_pgd(ulong);
static int x86_64_translate_pte(ulong, void *, ulonglong);
static ulong x86_64_processor_speed(void);
static int is_vsyscall_addr(ulong);
struct syment *x86_64_value_to_symbol(ulong, ulong *);
static int x86_64_eframe_search(struct bt_info *);
static int x86_64_eframe_verify(struct bt_info *, long, long, long, long, long, long);

#define EFRAME_PRINT  (0x1)
#define EFRAME_VERIFY (0x2)
#define EFRAME_CS     (0x4)
#define EFRAME_SEARCH (0x8)
static int x86_64_print_eframe_location(ulong, int, FILE *);
static void x86_64_back_trace_cmd(struct bt_info *);
static ulong x86_64_in_exception_stack(struct bt_info *, int *);
static ulong x86_64_in_irqstack(struct bt_info *);
static int x86_64_in_alternate_stack(int, ulong);
static ulong x86_64_in_kpti_entry_stack(int, ulong);
static ulong __schedule_frame_adjust(ulong, struct bt_info *);
static void x86_64_low_budget_back_trace_cmd(struct bt_info *);
static void x86_64_dwarf_back_trace_cmd(struct bt_info *);
static void x86_64_get_dumpfile_stack_frame(struct bt_info *, ulong *, ulong *);
static struct syment *x86_64_function_called_by(ulong);
static int is_direct_call_target(struct bt_info *);
static void get_x86_64_frame(struct bt_info *, ulong *, ulong *);
static ulong text_lock_function(char *, struct bt_info *, ulong);
static int x86_64_print_stack_entry(struct bt_info *, FILE *, int, int, ulong);
static void x86_64_display_full_frame(struct bt_info *, ulong, FILE *);
static void x86_64_do_bt_reference_check(struct bt_info *, ulong,char *);
static void x86_64_dump_irq(int);
static void x86_64_get_irq_affinity(int);
static void x86_64_show_interrupts(int, ulong *);
static char *x86_64_extract_idt_function(ulong *, char *, ulong *);
static ulong x86_64_get_pc(struct bt_info *);
static ulong x86_64_get_sp(struct bt_info *);
static void x86_64_get_stack_frame(struct bt_info *, ulong *, ulong *);
static int x86_64_dis_filter(ulong, char *, unsigned int);
static void x86_64_cmd_mach(void);
static int x86_64_get_smp_cpus(void);
static void x86_64_display_machine_stats(void);
static void x86_64_display_cpu_data(unsigned int);
static void x86_64_display_memmap(void);
static void x86_64_dump_line_number(ulong);
static struct line_number_hook x86_64_line_number_hooks[];
static void x86_64_calc_phys_base(void);
static int x86_64_is_module_addr(ulong);
static int x86_64_is_kvaddr(ulong);
static int x86_64_is_uvaddr(ulong, struct task_context *);
static int x86_64_is_page_ptr(ulong, physaddr_t *);
static ulong *x86_64_kpgd_offset(ulong, int, int);
static ulong x86_64_upgd_offset(struct task_context *, ulong, int, int);
static ulong x86_64_upgd_offset_legacy(struct task_context *, ulong, int, int);
static ulong x86_64_p4d_offset(ulong, ulong, int, int);
static ulong x86_64_pud_offset(ulong, ulong, int, int);
static ulong x86_64_pmd_offset(ulong, ulong, int, int);
static ulong x86_64_pte_offset(ulong, ulong, int, int);
void x86_64_compiler_warning_stub(void);
static void x86_64_init_kernel_pgd(void);
static void x86_64_cpu_pda_init(void);
static void x86_64_per_cpu_init(void);
static void x86_64_ist_init(void);
static void x86_64_l1tf_init(void);
static void x86_64_irq_stack_gap_init(void);
static void x86_64_entry_trampoline_init(void);
static void x86_64_post_init(void);
static void parse_cmdline_args(void);
static void x86_64_clear_machdep_cache(void);
static void x86_64_irq_eframe_link_init(void);
static ulong x86_64_irq_eframe_link(ulong, struct bt_info *, FILE *);
static ulong search_for_switch_to(ulong, ulong);
static void x86_64_thread_return_init(void);
static void x86_64_framepointer_init(void);
static void x86_64_ORC_init(void);
static int x86_64_virt_phys_base(void);
static int x86_64_xendump_p2m_create(struct xendump_data *);
static int x86_64_pvops_xendump_p2m_create(struct xendump_data *);
static int x86_64_pvops_xendump_p2m_l2_create(struct xendump_data *);
static int x86_64_pvops_xendump_p2m_l3_create(struct xendump_data *);
static char *x86_64_xendump_load_page(ulong, struct xendump_data *);
static int x86_64_xendump_page_index(ulong, struct xendump_data *);
static int x86_64_xen_kdump_p2m_create(struct xen_kdump_data *);
static char *x86_64_xen_kdump_load_page(ulong, char *);
static ulong x86_64_xen_kdump_page_mfn(ulong);
static void x86_64_debug_dump_page(FILE *, char *, char *);
static void x86_64_get_xendump_regs(struct xendump_data *, struct bt_info *, ulong *, ulong *);
static ulong x86_64_xendump_panic_task(struct xendump_data *);
static void x86_64_init_hyper(int);
static ulong x86_64_get_stackbase_hyper(ulong);
static ulong x86_64_get_stacktop_hyper(ulong);
static int x86_64_framesize_cache_resize(void);
static int x86_64_do_not_cache_framesize(struct syment *, ulong);
static int x86_64_framesize_cache_func(int, ulong, int *, int, struct syment *);
static ulong x86_64_get_framepointer(struct bt_info *, ulong);
int search_for_eframe_target_caller(struct bt_info *, ulong, int *);
static int x86_64_get_framesize(struct bt_info *, ulong, ulong, char *);
static void x86_64_framesize_debug(struct bt_info *);
static void x86_64_get_active_set(void);
static int x86_64_get_kvaddr_ranges(struct vaddr_range *);
static int x86_64_get_cpu_reg(int, int, const char *, int, void *);
static int x86_64_verify_paddr(uint64_t);
static void GART_init(void);
static void x86_64_exception_stacks_init(void);
static int in_START_KERNEL_map(ulong);
static ulong orc_ip(ulong);
static kernel_orc_entry *__orc_find(ulong, ulong, uint, ulong);
static kernel_orc_entry *orc_find(ulong);
static kernel_orc_entry *orc_module_find(ulong);
static ulong ip_table_to_vaddr(ulong);
static void orc_dump(ulong);

struct machine_specific x86_64_machine_specific = { 0 };

static const char *exception_functions_orig[];
static const char *exception_functions_5_8[];

/*
 *  Do all necessary machine-specific setup here.  This is called several
 *  times during initialization.
 */
void
x86_64_init(int when)
{
	int len, dim;
	char *string;

        if (XEN_HYPER_MODE()) {
                x86_64_init_hyper(when);
                return;
        }

	switch (when)
	{
	case SETUP_ENV:
		machdep->process_elf_notes = x86_process_elf_notes;
		machdep->is_page_ptr = x86_64_is_page_ptr;
		break;
	case PRE_SYMTAB:
		machdep->verify_symbol = x86_64_verify_symbol;
		machdep->verify_line_number = x86_64_verify_line_number;
                machdep->machspec = &x86_64_machine_specific;
                if (pc->flags & KERNEL_DEBUG_QUERY)
                        return;
                machdep->pagesize = memory_page_size();
                machdep->pageshift = ffs(machdep->pagesize) - 1;
                machdep->pageoffset = machdep->pagesize - 1;
                machdep->pagemask = ~((ulonglong)machdep->pageoffset);
		machdep->stacksize = machdep->pagesize * 2;
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
		machdep->verify_paddr = x86_64_verify_paddr;
		machdep->ptrs_per_pgd = PTRS_PER_PGD;
		machdep->flags |= MACHDEP_BT_TEXT;
		machdep->flags |= FRAMESIZE_DEBUG;
		machdep->machspec->irq_eframe_link = UNINITIALIZED;
		machdep->machspec->irq_stack_gap = UNINITIALIZED;
		machdep->get_kvaddr_ranges = x86_64_get_kvaddr_ranges;
		machdep->get_cpu_reg = x86_64_get_cpu_reg;
                if (machdep->cmdline_args[0])
                        parse_cmdline_args();
		if ((string = pc->read_vmcoreinfo("relocate"))) {
			kt->relocate = htol(string, QUIET, NULL);
                        kt->flags |= RELOC_SET;
                        kt->flags2 |= KASLR;
			free(string);
		}
		if ((string = pc->read_vmcoreinfo("NUMBER(KERNEL_IMAGE_SIZE)"))) {
			machdep->machspec->kernel_image_size = dtol(string, QUIET, NULL);
			free(string);
		}
		if ((string = pc->read_vmcoreinfo("NUMBER(sme_mask)"))) {
			machdep->machspec->sme_mask = dtol(string, QUIET, NULL);
			free(string);
		}
		if (SADUMP_DUMPFILE() || QEMU_MEM_DUMP_NO_VMCOREINFO() ||
		    VMSS_DUMPFILE())
			/* Need for calculation of kaslr_offset and phys_base */
			machdep->kvtop = x86_64_kvtop;
		break;

	case PRE_GDB:
		if (!(machdep->flags & VM_FLAGS)) {
			if (symbol_exists("xen_start_info")) {
				if (PVOPS())
					machdep->flags |= VM_2_6_11;
				else if (symbol_exists("low_pml4") && 
				    symbol_exists("swap_low_mappings"))
					machdep->flags |= VM_XEN_RHEL4;
				else
					machdep->flags |= VM_XEN;
			} else if (symbol_exists("boot_vmalloc_pgt"))
				machdep->flags |= VM_ORIG;
			else
				machdep->flags |= VM_2_6_11;
		}

		switch (machdep->flags & VM_FLAGS) 
		{
		case VM_ORIG:
		        /* pre-2.6.11 layout */
                        machdep->machspec->userspace_top = USERSPACE_TOP_ORIG;
                        machdep->machspec->page_offset = PAGE_OFFSET_ORIG;
                        machdep->machspec->vmalloc_start_addr = VMALLOC_START_ADDR_ORIG;
                        machdep->machspec->vmalloc_end = VMALLOC_END_ORIG;
                        machdep->machspec->modules_vaddr = MODULES_VADDR_ORIG;
                        machdep->machspec->modules_end = MODULES_END_ORIG;

			machdep->uvtop = x86_64_uvtop;
			machdep->machspec->physical_mask_shift = __PHYSICAL_MASK_SHIFT_2_6;
			machdep->machspec->pgdir_shift = PGDIR_SHIFT;
			machdep->machspec->ptrs_per_pgd = PTRS_PER_PGD;
			break;
		
		case VM_2_6_11:
			/* 2.6.11 layout */
			machdep->machspec->userspace_top = USERSPACE_TOP_2_6_11;
			machdep->machspec->vmalloc_start_addr = VMALLOC_START_ADDR_2_6_11;
			machdep->machspec->vmalloc_end = VMALLOC_END_2_6_11;
			machdep->machspec->modules_vaddr = MODULES_VADDR_2_6_11;
			machdep->machspec->modules_end = MODULES_END_2_6_11;

			/* 2.6.24 layout */
			machdep->machspec->vmemmap_vaddr = VMEMMAP_VADDR_2_6_24;
			machdep->machspec->vmemmap_end = VMEMMAP_END_2_6_24;
			if (symbol_exists("vmemmap_populate"))
				machdep->flags |= VMEMMAP;

			if (kernel_symbol_exists("end_pfn"))
				/* 2.6.11 layout */
				machdep->machspec->page_offset = PAGE_OFFSET_2_6_11;
			else
				/* 2.6.27 layout */
				machdep->machspec->page_offset = PAGE_OFFSET_2_6_27;

			machdep->uvtop = x86_64_uvtop_level4;
			machdep->machspec->physical_mask_shift = __PHYSICAL_MASK_SHIFT_2_6;
			machdep->machspec->pgdir_shift = PGDIR_SHIFT;
			machdep->machspec->ptrs_per_pgd = PTRS_PER_PGD;
			break;

                case VM_XEN:
                        /* Xen layout */
                        machdep->machspec->userspace_top = USERSPACE_TOP_XEN;
                        machdep->machspec->page_offset = PAGE_OFFSET_XEN;
                        machdep->machspec->vmalloc_start_addr = VMALLOC_START_ADDR_XEN;
                        machdep->machspec->vmalloc_end = VMALLOC_END_XEN;
                        machdep->machspec->modules_vaddr = MODULES_VADDR_XEN;
                        machdep->machspec->modules_end = MODULES_END_XEN;
			machdep->machspec->physical_mask_shift = __PHYSICAL_MASK_SHIFT_XEN;
			machdep->machspec->pgdir_shift = PGDIR_SHIFT;
			machdep->machspec->ptrs_per_pgd = PTRS_PER_PGD;
                        break;

		case VM_XEN_RHEL4:
			/* RHEL4 Xen layout */
                        machdep->machspec->userspace_top = USERSPACE_TOP_XEN_RHEL4;
                        machdep->machspec->page_offset = PAGE_OFFSET_XEN_RHEL4;
                        machdep->machspec->vmalloc_start_addr = VMALLOC_START_ADDR_XEN_RHEL4;
                        machdep->machspec->vmalloc_end = VMALLOC_END_XEN_RHEL4;
                        machdep->machspec->modules_vaddr = MODULES_VADDR_XEN_RHEL4;
                        machdep->machspec->modules_end = MODULES_END_XEN_RHEL4;
			machdep->machspec->physical_mask_shift = __PHYSICAL_MASK_SHIFT_XEN;
			machdep->machspec->pgdir_shift = PGDIR_SHIFT;
			machdep->machspec->ptrs_per_pgd = PTRS_PER_PGD;
			break;
		}
	        machdep->kvbase = (ulong)PAGE_OFFSET;
		machdep->identity_map_base = (ulong)PAGE_OFFSET;
                machdep->is_kvaddr = x86_64_is_kvaddr;
                machdep->is_uvaddr = x86_64_is_uvaddr;
	        machdep->eframe_search = x86_64_eframe_search;
	        machdep->back_trace = x86_64_low_budget_back_trace_cmd;
	        machdep->processor_speed = x86_64_processor_speed;
	        machdep->kvtop = x86_64_kvtop;
	        machdep->get_task_pgd = x86_64_get_task_pgd;
		machdep->get_stack_frame = x86_64_get_stack_frame;
		machdep->get_stackbase = generic_get_stackbase;
		machdep->get_stacktop = generic_get_stacktop;
		machdep->translate_pte = x86_64_translate_pte;
		machdep->memory_size = generic_memory_size;
		machdep->is_task_addr = x86_64_is_task_addr;
		machdep->dis_filter = x86_64_dis_filter;
		machdep->cmd_mach = x86_64_cmd_mach;
		machdep->get_smp_cpus = x86_64_get_smp_cpus;
		machdep->value_to_symbol = x86_64_value_to_symbol;
		machdep->init_kernel_pgd = x86_64_init_kernel_pgd;
		machdep->clear_machdep_cache = x86_64_clear_machdep_cache;
		machdep->xendump_p2m_create = x86_64_xendump_p2m_create;
		machdep->get_xendump_regs = x86_64_get_xendump_regs;
		machdep->xen_kdump_p2m_create = x86_64_xen_kdump_p2m_create;
		machdep->xendump_panic_task = x86_64_xendump_panic_task;
		if (symbol_exists("vgettimeofday"))
			machdep->machspec->vsyscall_page = 
				PAGEBASE(symbol_value("vgettimeofday"));
		x86_64_calc_phys_base();
		break;

	case POST_RELOC:
		/* Check for 5-level paging */
		if (!(machdep->flags & VM_5LEVEL)) {
			int l5_enabled = 0;
			if ((string = pc->read_vmcoreinfo("NUMBER(pgtable_l5_enabled)"))) {
				l5_enabled = atoi(string);
				free(string);
			} else if (kernel_symbol_exists("__pgtable_l5_enabled"))
				readmem(symbol_value("__pgtable_l5_enabled"), KVADDR,
					&l5_enabled, sizeof(int), "__pgtable_l5_enabled",
					QUIET|FAULT_ON_ERROR);

			if (l5_enabled)
				machdep->flags |= VM_5LEVEL;
		}

		if (machdep->flags & VM_5LEVEL) {
			machdep->machspec->userspace_top = USERSPACE_TOP_5LEVEL;
			machdep->machspec->page_offset = PAGE_OFFSET_5LEVEL;
			machdep->machspec->vmalloc_start_addr = VMALLOC_START_ADDR_5LEVEL;
			machdep->machspec->vmalloc_end = VMALLOC_END_5LEVEL;
			machdep->machspec->modules_vaddr = MODULES_VADDR_5LEVEL;
			machdep->machspec->modules_end = MODULES_END_5LEVEL;
			machdep->machspec->vmemmap_vaddr = VMEMMAP_VADDR_5LEVEL;
			machdep->machspec->vmemmap_end = VMEMMAP_END_5LEVEL;
			if (symbol_exists("vmemmap_populate"))
				machdep->flags |= VMEMMAP;
			machdep->machspec->physical_mask_shift = __PHYSICAL_MASK_SHIFT_5LEVEL;
			machdep->machspec->pgdir_shift = PGDIR_SHIFT_5LEVEL;
			machdep->machspec->ptrs_per_pgd = PTRS_PER_PGD_5LEVEL;
			if (!machdep->machspec->p4d) {
				if ((machdep->machspec->p4d = (char *)malloc(PAGESIZE())) == NULL)
					error(FATAL, "cannot malloc p4d space.");
				machdep->machspec->last_p4d_read = 0;
			}
			machdep->uvtop = x86_64_uvtop_level4;  /* 5-level is optional per-task */
			machdep->kvbase = (ulong)PAGE_OFFSET;
			machdep->identity_map_base = (ulong)PAGE_OFFSET;
		}

		/*
		 *  Check for CONFIG_RANDOMIZE_MEMORY, and set page_offset and
		 *  the virtual address ranges.
		 */
		if (kernel_symbol_exists("page_offset_base") &&
		    kernel_symbol_exists("vmalloc_base")) {
			machdep->flags |= RANDOMIZED;
			readmem(symbol_value("page_offset_base"), KVADDR,
				&machdep->machspec->page_offset, sizeof(ulong),
				"page_offset_base", QUIET|FAULT_ON_ERROR);
			machdep->kvbase = machdep->machspec->page_offset;
			machdep->identity_map_base = machdep->machspec->page_offset;

			readmem(symbol_value("vmalloc_base"), KVADDR,
					&machdep->machspec->vmalloc_start_addr,
					sizeof(ulong), "vmalloc_base", FAULT_ON_ERROR);
			if (machdep->flags & VM_5LEVEL)
				machdep->machspec->vmalloc_end =
					machdep->machspec->vmalloc_start_addr + TERABYTES(1280) - 1;
			else
				machdep->machspec->vmalloc_end =
					machdep->machspec->vmalloc_start_addr + TERABYTES(32) - 1;
			if (kernel_symbol_exists("vmemmap_base")) {
				readmem(symbol_value("vmemmap_base"), KVADDR,
					&machdep->machspec->vmemmap_vaddr, sizeof(ulong),
					"vmemmap_base", FAULT_ON_ERROR);
				machdep->machspec->vmemmap_end =
					machdep->machspec->vmemmap_vaddr +
					TERABYTES(1) - 1;
			} else {
				machdep->machspec->vmemmap_vaddr = VMEMMAP_VADDR_2_6_31;
				machdep->machspec->vmemmap_end = VMEMMAP_END_2_6_31;
			}
			machdep->machspec->modules_vaddr = __START_KERNEL_map +
				(machdep->machspec->kernel_image_size ?
				machdep->machspec->kernel_image_size : GIGABYTES(1));
			machdep->machspec->modules_end = MODULES_END_2_6_31;
		}
		break;

	case POST_GDB:
		if (!(machdep->flags & RANDOMIZED) &&
		    ((THIS_KERNEL_VERSION >= LINUX(4,19,5)) || 
		    ((THIS_KERNEL_VERSION >= LINUX(4,14,84)) && 
		     (THIS_KERNEL_VERSION < LINUX(4,15,0))))) {
			machdep->machspec->page_offset = machdep->flags & VM_5LEVEL ?
				PAGE_OFFSET_5LEVEL_4_20 : PAGE_OFFSET_4LEVEL_4_20;
			machdep->kvbase = machdep->machspec->page_offset; 
			machdep->identity_map_base = machdep->machspec->page_offset; 
		}
		/* 
		 * --machdep page_offset forced override 
		 */
		if (machdep->machspec->page_offset_force) {
			machdep->machspec->page_offset = machdep->machspec->page_offset_force;
			machdep->kvbase = machdep->machspec->page_offset; 
			machdep->identity_map_base = machdep->machspec->page_offset; 
		}
		if (THIS_KERNEL_VERSION >= LINUX(2,6,26) &&
		    THIS_KERNEL_VERSION < LINUX(2,6,31)) {
			machdep->machspec->modules_vaddr = MODULES_VADDR_2_6_26;
		}
		if (THIS_KERNEL_VERSION >= LINUX(2,6,27) &&
		    THIS_KERNEL_VERSION < LINUX(2,6,31)) {
			machdep->machspec->modules_end = MODULES_END_2_6_27;
		}
		if (THIS_KERNEL_VERSION >= LINUX(2,6,31)) {
			if (!(machdep->flags & RANDOMIZED)) {
				machdep->machspec->vmalloc_start_addr = VMALLOC_START_ADDR_2_6_31;
				machdep->machspec->vmalloc_end = VMALLOC_END_2_6_31;
				machdep->machspec->vmemmap_vaddr = VMEMMAP_VADDR_2_6_31;
				machdep->machspec->vmemmap_end = VMEMMAP_END_2_6_31;
				if (kt->flags2 & KASLR)
					machdep->machspec->modules_vaddr = __START_KERNEL_map + 
						(machdep->machspec->kernel_image_size ?
						machdep->machspec->kernel_image_size : GIGABYTES(1));
				else
					machdep->machspec->modules_vaddr = MODULES_VADDR_2_6_31;
				machdep->machspec->modules_end = MODULES_END_2_6_31;
			}
		}
		if (STRUCT_EXISTS("cpu_entry_area")) {
			machdep->machspec->cpu_entry_area_start = CPU_ENTRY_AREA_START;	
			machdep->machspec->cpu_entry_area_end = CPU_ENTRY_AREA_END;	
		}

                STRUCT_SIZE_INIT(cpuinfo_x86, "cpuinfo_x86");
		/* 
		 * Before 2.6.25 the structure was called gate_struct
		 */
		if (STRUCT_EXISTS("gate_desc"))
			STRUCT_SIZE_INIT(gate_struct, "gate_desc");
		else
			STRUCT_SIZE_INIT(gate_struct, "gate_struct");

		if (STRUCT_EXISTS("e820map")) {
			STRUCT_SIZE_INIT(e820map, "e820map");
			MEMBER_OFFSET_INIT(e820map_nr_map, "e820map", "nr_map");
		} else {
			STRUCT_SIZE_INIT(e820map, "e820_table");
			MEMBER_OFFSET_INIT(e820map_nr_map, "e820_table", "nr_entries");
		}
		if (STRUCT_EXISTS("e820entry")) {
			STRUCT_SIZE_INIT(e820entry, "e820entry");
			MEMBER_OFFSET_INIT(e820entry_addr, "e820entry", "addr");
			MEMBER_OFFSET_INIT(e820entry_size, "e820entry", "size");
			MEMBER_OFFSET_INIT(e820entry_type, "e820entry", "type");
		} else {
			STRUCT_SIZE_INIT(e820entry, "e820_entry");
			MEMBER_OFFSET_INIT(e820entry_addr, "e820_entry", "addr");
			MEMBER_OFFSET_INIT(e820entry_size, "e820_entry", "size");
			MEMBER_OFFSET_INIT(e820entry_type, "e820_entry", "type");
		}

		if (KVMDUMP_DUMPFILE())
			set_kvm_iohole(NULL);
		MEMBER_OFFSET_INIT(thread_struct_rip, "thread_struct", "rip");
		MEMBER_OFFSET_INIT(thread_struct_rsp, "thread_struct", "rsp");
		MEMBER_OFFSET_INIT(thread_struct_rsp0, "thread_struct", "rsp0");
		if (INVALID_MEMBER(thread_struct_rip))
			MEMBER_OFFSET_INIT(thread_struct_rip, "thread_struct", "ip");
		if (INVALID_MEMBER(thread_struct_rsp))
			MEMBER_OFFSET_INIT(thread_struct_rsp, "thread_struct", "sp");
		if (INVALID_MEMBER(thread_struct_rsp0))
			MEMBER_OFFSET_INIT(thread_struct_rsp0, "thread_struct", "sp0");
		STRUCT_SIZE_INIT(tss_struct, "tss_struct");
		MEMBER_OFFSET_INIT(tss_struct_ist, "tss_struct", "ist");
		if (INVALID_MEMBER(tss_struct_ist)) {
			long x86_tss_offset, ist_offset;
			x86_tss_offset = MEMBER_OFFSET("tss_struct", "x86_tss");
			ist_offset = MEMBER_OFFSET("x86_hw_tss", "ist");
			if ((x86_tss_offset != INVALID_OFFSET) &&
			    (ist_offset != INVALID_OFFSET))
				ASSIGN_OFFSET(tss_struct_ist) = x86_tss_offset + 
					ist_offset;
		}
		MEMBER_OFFSET_INIT(user_regs_struct_rip,
			"user_regs_struct", "rip");
		if (INVALID_MEMBER(user_regs_struct_rip))
			MEMBER_OFFSET_INIT(user_regs_struct_rip,
				"user_regs_struct", "ip");
		MEMBER_OFFSET_INIT(user_regs_struct_rsp,
			"user_regs_struct", "rsp");
		if (INVALID_MEMBER(user_regs_struct_rsp))
			MEMBER_OFFSET_INIT(user_regs_struct_rsp,
				"user_regs_struct", "sp");
		MEMBER_OFFSET_INIT(user_regs_struct_eflags,
			"user_regs_struct", "eflags");
		if (INVALID_MEMBER(user_regs_struct_eflags))
			MEMBER_OFFSET_INIT(user_regs_struct_eflags,
				"user_regs_struct", "flags");
		MEMBER_OFFSET_INIT(user_regs_struct_cs,
			"user_regs_struct", "cs");
		MEMBER_OFFSET_INIT(user_regs_struct_ss,
			"user_regs_struct", "ss");
		MEMBER_OFFSET_INIT(user_regs_struct_rax,
			"user_regs_struct", "rax");
		if (INVALID_MEMBER(user_regs_struct_rax))
			MEMBER_OFFSET_INIT(user_regs_struct_rax,
				"user_regs_struct", "ax");
		MEMBER_OFFSET_INIT(user_regs_struct_rbx,
			"user_regs_struct", "rbx");
		if (INVALID_MEMBER(user_regs_struct_rbx))
			MEMBER_OFFSET_INIT(user_regs_struct_rbx,
				"user_regs_struct", "bx");
		MEMBER_OFFSET_INIT(user_regs_struct_rcx,
			"user_regs_struct", "rcx");
		if (INVALID_MEMBER(user_regs_struct_rcx))
			MEMBER_OFFSET_INIT(user_regs_struct_rcx,
				"user_regs_struct", "cx");
		MEMBER_OFFSET_INIT(user_regs_struct_rdx,
			"user_regs_struct", "rdx");
		if (INVALID_MEMBER(user_regs_struct_rdx))
			MEMBER_OFFSET_INIT(user_regs_struct_rdx,
				"user_regs_struct", "dx");
		MEMBER_OFFSET_INIT(user_regs_struct_rsi,
			"user_regs_struct", "rsi");
		if (INVALID_MEMBER(user_regs_struct_rsi))
			MEMBER_OFFSET_INIT(user_regs_struct_rsi,
				"user_regs_struct", "si");
		MEMBER_OFFSET_INIT(user_regs_struct_rdi,
			"user_regs_struct", "rdi");
		if (INVALID_MEMBER(user_regs_struct_rdi))
			MEMBER_OFFSET_INIT(user_regs_struct_rdi,
				"user_regs_struct", "di");
		MEMBER_OFFSET_INIT(user_regs_struct_rbp,
			"user_regs_struct", "rbp");
		if (INVALID_MEMBER(user_regs_struct_rbp))
			MEMBER_OFFSET_INIT(user_regs_struct_rbp,
				"user_regs_struct", "bp");
		MEMBER_OFFSET_INIT(user_regs_struct_r8,
			"user_regs_struct", "r8");
		MEMBER_OFFSET_INIT(user_regs_struct_r9,
			"user_regs_struct", "r9");
		MEMBER_OFFSET_INIT(user_regs_struct_r10,
			"user_regs_struct", "r10");
		MEMBER_OFFSET_INIT(user_regs_struct_r11,
			"user_regs_struct", "r11");
		MEMBER_OFFSET_INIT(user_regs_struct_r12,
			"user_regs_struct", "r12");
		MEMBER_OFFSET_INIT(user_regs_struct_r13,
			"user_regs_struct", "r13");
		MEMBER_OFFSET_INIT(user_regs_struct_r14,
			"user_regs_struct", "r14");
		MEMBER_OFFSET_INIT(user_regs_struct_r15,
			"user_regs_struct", "r15");
		STRUCT_SIZE_INIT(user_regs_struct, "user_regs_struct");
		if (!VALID_STRUCT(user_regs_struct)) {
			/*  Use this hardwired version -- sometimes the
			 *  debuginfo doesn't pick this up even though
 			 *  it exists in the kernel; it shouldn't change.
 			 */
			struct x86_64_user_regs_struct {
				unsigned long r15, r14, r13, r12, bp, bx;
				unsigned long r11, r10, r9, r8, ax, cx, dx;
				unsigned long si, di, orig_ax, ip, cs;
				unsigned long flags, sp, ss, fs_base;
				unsigned long gs_base, ds, es, fs, gs;
			};
			ASSIGN_SIZE(user_regs_struct) = 
				sizeof(struct x86_64_user_regs_struct);
			ASSIGN_OFFSET(user_regs_struct_rip) =
				offsetof(struct x86_64_user_regs_struct, ip);
			ASSIGN_OFFSET(user_regs_struct_rsp) =
				offsetof(struct x86_64_user_regs_struct, sp);
			ASSIGN_OFFSET(user_regs_struct_eflags) =
				offsetof(struct x86_64_user_regs_struct, flags);
			ASSIGN_OFFSET(user_regs_struct_cs) =
				offsetof(struct x86_64_user_regs_struct, cs);
			ASSIGN_OFFSET(user_regs_struct_ss) =
				offsetof(struct x86_64_user_regs_struct, ss);
			ASSIGN_OFFSET(user_regs_struct_rax) =
				offsetof(struct x86_64_user_regs_struct, ax);
			ASSIGN_OFFSET(user_regs_struct_rbx) =
				offsetof(struct x86_64_user_regs_struct, bx);
			ASSIGN_OFFSET(user_regs_struct_rcx) =
				offsetof(struct x86_64_user_regs_struct, cx);
			ASSIGN_OFFSET(user_regs_struct_rdx) =
				offsetof(struct x86_64_user_regs_struct, dx);
			ASSIGN_OFFSET(user_regs_struct_rsi) =
				offsetof(struct x86_64_user_regs_struct, si);
			ASSIGN_OFFSET(user_regs_struct_rdi) =
				offsetof(struct x86_64_user_regs_struct, di);
			ASSIGN_OFFSET(user_regs_struct_rbp) =
				offsetof(struct x86_64_user_regs_struct, bp);
			ASSIGN_OFFSET(user_regs_struct_r8) =
				offsetof(struct x86_64_user_regs_struct, r8);
			ASSIGN_OFFSET(user_regs_struct_r9) =
				offsetof(struct x86_64_user_regs_struct, r9);
			ASSIGN_OFFSET(user_regs_struct_r10) =
				offsetof(struct x86_64_user_regs_struct, r10);
			ASSIGN_OFFSET(user_regs_struct_r11) =
				offsetof(struct x86_64_user_regs_struct, r11);
			ASSIGN_OFFSET(user_regs_struct_r12) =
				offsetof(struct x86_64_user_regs_struct, r12);
			ASSIGN_OFFSET(user_regs_struct_r13) =
				offsetof(struct x86_64_user_regs_struct, r13);
			ASSIGN_OFFSET(user_regs_struct_r14) =
				offsetof(struct x86_64_user_regs_struct, r14);
			ASSIGN_OFFSET(user_regs_struct_r15) =
				offsetof(struct x86_64_user_regs_struct, r15);
		}
		machdep->vmalloc_start = x86_64_vmalloc_start;
		vt->vmalloc_start = machdep->vmalloc_start();
		machdep->init_kernel_pgd();
		if (STRUCT_EXISTS("x8664_pda"))
			x86_64_cpu_pda_init();
		else
			x86_64_per_cpu_init();
		x86_64_ist_init();
		if (symbol_exists("repeat_nmi"))
			machdep->flags |= NESTED_NMI;
		machdep->in_alternate_stack = x86_64_in_alternate_stack;
                if ((machdep->machspec->irqstack = (char *)
		    malloc(machdep->machspec->stkinfo.isize)) == NULL)
                        error(FATAL, "cannot malloc irqstack space.");
		if (symbol_exists("irq_desc")) {
			if (LKCD_KERNTYPES())
				ARRAY_LENGTH_INIT_ALT(machdep->nr_irqs,
				    "irq_desc", "kernel_stat.irqs", NULL, 0);
			else
				ARRAY_LENGTH_INIT(machdep->nr_irqs, irq_desc,
					"irq_desc", NULL, 0);
		} else if (kernel_symbol_exists("nr_irqs"))
			get_symbol_data("nr_irqs", sizeof(unsigned int),
				&machdep->nr_irqs);
		else
			machdep->nr_irqs = 224; /* NR_IRQS (at least) */
		machdep->dump_irq = x86_64_dump_irq;
		machdep->get_irq_affinity = x86_64_get_irq_affinity;
		machdep->show_interrupts = x86_64_show_interrupts;
		if (THIS_KERNEL_VERSION < LINUX(2,6,24))
			machdep->line_number_hooks = x86_64_line_number_hooks;
		if (!machdep->hz) {
			machdep->hz = HZ;
			if (THIS_KERNEL_VERSION >= LINUX(2,6,0))
				machdep->hz = 1000;
		}
		machdep->section_size_bits = _SECTION_SIZE_BITS;
		if (!machdep->max_physmem_bits) {
			if ((string = pc->read_vmcoreinfo("NUMBER(MAX_PHYSMEM_BITS)"))) {
				machdep->max_physmem_bits = atol(string);
				free(string);
			} else if (machdep->flags & VM_5LEVEL)
				machdep->max_physmem_bits = 
					_MAX_PHYSMEM_BITS_5LEVEL;
			else if (THIS_KERNEL_VERSION >= LINUX(2,6,31))
				machdep->max_physmem_bits = 
					_MAX_PHYSMEM_BITS_2_6_31;
			else if (THIS_KERNEL_VERSION >= LINUX(2,6,26))
				machdep->max_physmem_bits = 
					_MAX_PHYSMEM_BITS_2_6_26;
			else {
				machdep->max_physmem_bits = _MAX_PHYSMEM_BITS;
				len = get_array_length("mem_section", &dim, 0);
				/*
				 * Check for patched MAX_PHYSMEM_BITS.
				 */
				if (((len > 32) && !dim) ||
				    ((len > 8192) && (dim == 1)))
					machdep->max_physmem_bits = 
						_MAX_PHYSMEM_BITS_2_6_26;
			}
		}

                if (XEN()) {
			if (kt->xen_flags & WRITABLE_PAGE_TABLES) {
				switch (machdep->flags & VM_FLAGS)
				{
				case VM_XEN: 
				case VM_2_6_11:
                        		machdep->uvtop = x86_64_uvtop_level4_xen_wpt;
					break;
				case VM_XEN_RHEL4:
                        		machdep->uvtop = x86_64_uvtop_level4_rhel4_xen_wpt;
					break;
				}
				machdep->machspec->physical_mask_shift = __PHYSICAL_MASK_SHIFT_XEN;
			} else {
				machdep->uvtop = x86_64_uvtop_level4;
			}
                        MEMBER_OFFSET_INIT(vcpu_guest_context_user_regs,
                                "vcpu_guest_context", "user_regs");
			ASSIGN_OFFSET(cpu_user_regs_rsp) = 
				MEMBER_OFFSET("cpu_user_regs", "ss") - sizeof(ulong);
			ASSIGN_OFFSET(cpu_user_regs_rip) = 
				MEMBER_OFFSET("cpu_user_regs", "cs") - sizeof(ulong);
                }
		x86_64_irq_eframe_link_init();
		x86_64_irq_stack_gap_init();
		x86_64_entry_trampoline_init();
		x86_64_framepointer_init();
		x86_64_ORC_init();
		x86_64_thread_return_init();
		x86_64_l1tf_init();

		if (THIS_KERNEL_VERSION >= LINUX(2,6,28))
			machdep->machspec->page_protnone = _PAGE_GLOBAL;
		else
			machdep->machspec->page_protnone = _PAGE_PSE;

		STRUCT_SIZE_INIT(note_buf, "note_buf_t");
		STRUCT_SIZE_INIT(elf_prstatus, "elf_prstatus");
		MEMBER_OFFSET_INIT(elf_prstatus_pr_reg, "elf_prstatus",
				   "pr_reg");
		STRUCT_SIZE_INIT(percpu_data, "percpu_data");

		GART_init();

		if (kernel_symbol_exists("asm_exc_divide_error"))
			machdep->machspec->exception_functions = (char **)exception_functions_5_8;
		else
			machdep->machspec->exception_functions = (char **)exception_functions_orig;

		break;

	case POST_VM:
                init_unwind_table();
		break;

	case POST_INIT:
		x86_64_post_init();
		x86_64_get_active_set();
		break;

	case LOG_ONLY:
                machdep->machspec = &x86_64_machine_specific;
		x86_64_calc_phys_base();
		break;
	}
}

void
x86_64_dump_machdep_table(ulong arg)
{
	int c, i, cpus;
        int others; 
        struct machine_specific *ms;

        ms = machdep->machspec;
 
        others = 0;
        fprintf(fp, "              flags: %lx (", machdep->flags);
	if (machdep->flags & KSYMS_START)
		fprintf(fp, "%sKSYMS_START", others++ ? "|" : "");
	if (machdep->flags & PT_REGS_INIT)
		fprintf(fp, "%sPT_REGS_INIT", others++ ? "|" : "");
	if (machdep->flags & MACHDEP_BT_TEXT)
		fprintf(fp, "%sMACHDEP_BT_TEXT", others++ ? "|" : "");
	if (machdep->flags & VM_ORIG)
		fprintf(fp, "%sVM_ORIG", others++ ? "|" : "");
	if (machdep->flags & VM_2_6_11)
		fprintf(fp, "%sVM_2_6_11", others++ ? "|" : "");
	if (machdep->flags & VM_XEN)
		fprintf(fp, "%sVM_XEN", others++ ? "|" : "");
	if (machdep->flags & VM_XEN_RHEL4)
		fprintf(fp, "%sVM_XEN_RHEL4", others++ ? "|" : "");
	if (machdep->flags & VM_5LEVEL)
		fprintf(fp, "%sVM_5LEVEL", others++ ? "|" : "");
	if (machdep->flags & VMEMMAP)
		fprintf(fp, "%sVMEMMAP", others++ ? "|" : "");
	if (machdep->flags & NO_TSS)
		fprintf(fp, "%sNO_TSS", others++ ? "|" : "");
	if (machdep->flags & SCHED_TEXT)
		fprintf(fp, "%sSCHED_TEXT", others++ ? "|" : "");
	if (machdep->flags & PHYS_BASE)
		fprintf(fp, "%sPHYS_BASE", others++ ? "|" : "");
	if (machdep->flags & FRAMESIZE_DEBUG)
		fprintf(fp, "%sFRAMESIZE_DEBUG", others++ ? "|" : "");
	if (machdep->flags & ORC)
		fprintf(fp, "%sORC", others++ ? "|" : "");
	if (machdep->flags & FRAMEPOINTER)
		fprintf(fp, "%sFRAMEPOINTER", others++ ? "|" : "");
	if (machdep->flags & GART_REGION)
		fprintf(fp, "%sGART_REGION", others++ ? "|" : "");
	if (machdep->flags & NESTED_NMI)
		fprintf(fp, "%sNESTED_NMI", others++ ? "|" : "");
	if (machdep->flags & RANDOMIZED)
		fprintf(fp, "%sRANDOMIZED", others++ ? "|" : "");
	if (machdep->flags & KPTI)
		fprintf(fp, "%sKPTI", others++ ? "|" : "");
	if (machdep->flags & L1TF)
		fprintf(fp, "%sL1TF", others++ ? "|" : "");
        fprintf(fp, ")\n");

	fprintf(fp, "             kvbase: %lx\n", machdep->kvbase);
	fprintf(fp, "  identity_map_base: %lx\n", machdep->kvbase);
        fprintf(fp, "           pagesize: %d\n", machdep->pagesize);
        fprintf(fp, "          pageshift: %d\n", machdep->pageshift);
        fprintf(fp, "           pagemask: %llx\n", machdep->pagemask);
        fprintf(fp, "         pageoffset: %lx\n", machdep->pageoffset);
	fprintf(fp, "          stacksize: %ld\n", machdep->stacksize);
        fprintf(fp, "                 hz: %d\n", machdep->hz);
        fprintf(fp, "                mhz: %ld\n", machdep->mhz);
        fprintf(fp, "            memsize: %llu (0x%llx)\n", 
		(ulonglong)machdep->memsize, (ulonglong)machdep->memsize);
	fprintf(fp, "               bits: %d\n", machdep->bits);
	fprintf(fp, "            nr_irqs: %d\n", machdep->nr_irqs);
        fprintf(fp, "      eframe_search: x86_64_eframe_search()\n");
	if (machdep->back_trace == x86_64_back_trace_cmd)
        	fprintf(fp, "         back_trace: x86_64_back_trace_cmd()\n");
	else if (machdep->back_trace == x86_64_low_budget_back_trace_cmd)
        	fprintf(fp, 
		   "         back_trace: x86_64_low_budget_back_trace_cmd() %s\n",
			kt->flags & DWARF_UNWIND ?
			"-> x86_64_dwarf_back_trace_cmd()" : "");
	else if (machdep->back_trace == x86_64_dwarf_back_trace_cmd)
        	fprintf(fp, 
		   "         back_trace: x86_64_dwarf_back_trace_cmd() %s\n",
			kt->flags & DWARF_UNWIND ? 
			"" : "->x86_64_low_budget_back_trace_cmd()");
	else
		fprintf(fp, "         back_trace: %lx\n",
			(ulong)machdep->back_trace);
        fprintf(fp, "    processor_speed: x86_64_processor_speed()\n");
	if (machdep->uvtop == x86_64_uvtop)
        	fprintf(fp, "              uvtop: x86_64_uvtop()\n");
	else if (machdep->uvtop == x86_64_uvtop_level4) {
        	fprintf(fp, "              uvtop: x86_64_uvtop_level4()");
		if (machdep->flags & VM_5LEVEL)
			fprintf(fp, " (uses 5-level page tables)");
		fprintf(fp, "\n");
	} else if (machdep->uvtop == x86_64_uvtop_level4_xen_wpt)
        	fprintf(fp, "              uvtop: x86_64_uvtop_level4_xen_wpt()\n");
	else if (machdep->uvtop == x86_64_uvtop_level4_rhel4_xen_wpt)
        	fprintf(fp, "              uvtop: x86_64_uvtop_level4_rhel4_xen_wpt()\n");
	else
        	fprintf(fp, "              uvtop: %lx\n", (ulong)machdep->uvtop);
        fprintf(fp, "              kvtop: x86_64_kvtop()");
	if (machdep->flags & VM_5LEVEL)
		fprintf(fp, " -> x86_64_kvtop_5level()");
	else if (XEN() && (kt->xen_flags & WRITABLE_PAGE_TABLES))
		fprintf(fp, " -> x86_64_kvtop_xen_wpt()");
	fprintf(fp, "\n");
        fprintf(fp, "       get_task_pgd: x86_64_get_task_pgd()\n");
	fprintf(fp, "           dump_irq: x86_64_dump_irq()\n");
	fprintf(fp, "   get_irq_affinity: x86_64_get_irq_affinity()\n");
	fprintf(fp, "    show_interrupts: x86_64_show_interrupts()\n");
        fprintf(fp, "    get_stack_frame: x86_64_get_stack_frame()\n");
        fprintf(fp, "      get_stackbase: generic_get_stackbase()\n");
        fprintf(fp, "       get_stacktop: generic_get_stacktop()\n");
        fprintf(fp, "      translate_pte: x86_64_translate_pte()\n");
	fprintf(fp, "        memory_size: generic_memory_size()\n");
	fprintf(fp, "      vmalloc_start: x86_64_vmalloc_start()\n");
	fprintf(fp, "       is_task_addr: x86_64_is_task_addr()\n");
	fprintf(fp, "      verify_symbol: x86_64_verify_symbol()\n");
	fprintf(fp, "         dis_filter: x86_64_dis_filter()\n");
	fprintf(fp, "           cmd_mach: x86_64_cmd_mach()\n");
	fprintf(fp, "       get_smp_cpus: x86_64_get_smp_cpus()\n");
        fprintf(fp, "          is_kvaddr: x86_64_is_kvaddr()\n");
        fprintf(fp, "          is_uvaddr: x86_64_is_uvaddr()\n");
        fprintf(fp, "        is_page_ptr: x86_64_is_page_ptr()\n");
        fprintf(fp, "       verify_paddr: x86_64_verify_paddr()\n");
        fprintf(fp, "  get_kvaddr_ranges: x86_64_get_kvaddr_ranges()\n");
	fprintf(fp, "        get_cpu_reg: x86_64_get_cpu_reg()\n");
        fprintf(fp, "    init_kernel_pgd: x86_64_init_kernel_pgd()\n");
        fprintf(fp, "clear_machdep_cache: x86_64_clear_machdep_cache()\n");
	fprintf(fp, " xendump_p2m_create: %s\n", PVOPS_XEN() ?
		"x86_64_pvops_xendump_p2m_create()" :
		"x86_64_xendump_p2m_create()");
	fprintf(fp, "   get_xendump_regs: x86_64_get_xendump_regs()\n");
	fprintf(fp, " xendump_panic_task: x86_64_xendump_panic_task()\n");
	fprintf(fp, "xen_kdump_p2m_create: x86_64_xen_kdump_p2m_create()\n");
	fprintf(fp, "  line_number_hooks: %s\n", machdep->line_number_hooks ?
		"x86_64_line_number_hooks" : "(unused)");
	fprintf(fp, " verify_line_number: x86_64_verify_line_number()\n");
        fprintf(fp, "    value_to_symbol: x86_64_value_to_symbol()\n");
        fprintf(fp, " in_alternate_stack: x86_64_in_alternate_stack()\n");
        fprintf(fp, "      last_pgd_read: %lx\n", machdep->last_pgd_read);
	fprintf(fp, "      last_pud_read: %lx\n", machdep->last_pud_read);
        fprintf(fp, "      last_pmd_read: %lx\n", machdep->last_pmd_read);
        fprintf(fp, "     last_ptbl_read: %lx\n", machdep->last_ptbl_read);
        fprintf(fp, "                pgd: %lx\n", (ulong)machdep->pgd);
	fprintf(fp, "                pud: %lx\n", (ulong)machdep->pud);
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

	fprintf(fp, "           machspec: %016lx\n", (ulong)machdep->machspec);
	fprintf(fp, "            userspace_top: %016lx\n", (ulong)ms->userspace_top);
	fprintf(fp, "              page_offset: %016lx\n", (ulong)ms->page_offset);
	fprintf(fp, "        page_offset_force: ");
	if (ms->page_offset_force)
		fprintf(fp, "%016lx\n", (ulong)ms->page_offset_force);
	else
		fprintf(fp, "(unused)\n");
	fprintf(fp, "       vmalloc_start_addr: %016lx\n", (ulong)ms->vmalloc_start_addr);
	fprintf(fp, "              vmalloc_end: %016lx\n", (ulong)ms->vmalloc_end);
	fprintf(fp, "            modules_vaddr: %016lx\n", (ulong)ms->modules_vaddr);
	fprintf(fp, "              modules_end: %016lx\n", (ulong)ms->modules_end);
	fprintf(fp, "            vmemmap_vaddr: %016lx %s\n", (ulong)ms->vmemmap_vaddr,
		machdep->flags & VMEMMAP ? "" : "(unused)");
	fprintf(fp, "              vmemmap_end: %016lx %s\n", (ulong)ms->vmemmap_end,
		machdep->flags & VMEMMAP ? "" : "(unused)");
	fprintf(fp, "                phys_base: %lx\n", (ulong)ms->phys_base);
	fprintf(fp, "        kernel_image_size: ");
	if (ms->kernel_image_size)
		fprintf(fp, "%lx (%ldMB)\n", ms->kernel_image_size,
			ms->kernel_image_size/MEGABYTES(1));
	else
		fprintf(fp, "(uninitialized)\n");
	fprintf(fp, "                 sme_mask: %lx\n", ms->sme_mask);
	fprintf(fp, "      physical_mask_shift: %ld\n", ms->physical_mask_shift);
	fprintf(fp, "              pgdir_shift: %ld\n", ms->pgdir_shift);
	fprintf(fp, "               GART_start: %lx\n", ms->GART_start);
	fprintf(fp, "                 GART_end: %lx\n", ms->GART_end);

	/* pml4 and upml is legacy for extension modules */
	if (ms->pml4) {
		fprintf(fp, "                     pml4: %lx\n", (ulong)ms->pml4);
		fprintf(fp, "           last_pml4_read: %lx\n", (ulong)ms->last_pml4_read);

	} else {
		fprintf(fp, "                     pml4: (unused)\n");
		fprintf(fp, "           last_pml4_read: (unused)\n");
	}

	if (ms->upml) {
		fprintf(fp, "                     upml: %lx\n", (ulong)ms->upml);
		fprintf(fp, "           last_upml_read: %lx\n", (ulong)ms->last_upml_read);
	} else {
		fprintf(fp, "                 GART_end: %lx\n", ms->GART_end);
		fprintf(fp, "                     upml: (unused)\n");
		fprintf(fp, "           last_upml_read: (unused)\n");
	}

	if (ms->p4d) {
		fprintf(fp, "                      p4d: %lx\n", (ulong)ms->p4d);
		fprintf(fp, "            last_p4d_read: %lx\n", (ulong)ms->last_p4d_read);
	} else {
		fprintf(fp, "                      p4d: (unused)\n");
		fprintf(fp, "            last_p4d_read: (unused)\n");
	}

	fprintf(fp, "                 ORC_data: %s", machdep->flags & ORC ? "\n" : "(unused)\n");
	if (machdep->flags & ORC) {
		fprintf(fp, "                    module_ORC: %s\n", ms->orc.module_ORC ? "TRUE" : "FALSE");
		fprintf(fp, "             lookup_num_blocks: %d\n", ms->orc.lookup_num_blocks);
		fprintf(fp, "         __start_orc_unwind_ip: %lx\n", ms->orc.__start_orc_unwind_ip);
		fprintf(fp, "          __stop_orc_unwind_ip: %lx\n", ms->orc.__stop_orc_unwind_ip);
		fprintf(fp, "            __start_orc_unwind: %lx\n", ms->orc.__start_orc_unwind);
		fprintf(fp, "             __stop_orc_unwind: %lx\n", ms->orc.__stop_orc_unwind);
		fprintf(fp, "                    orc_lookup: %lx\n", ms->orc.orc_lookup);
		fprintf(fp, "                      ip_entry: %lx\n", ms->orc.ip_entry);
		fprintf(fp, "                     orc_entry: %lx\n", ms->orc.orc_entry);
		fprintf(fp, "              kernel_orc_entry:\n");
		fprintf(fp, "                       sp_offset: %d\n", ms->orc.kernel_orc_entry.sp_offset);
		fprintf(fp, "                       bp_offset: %d\n", ms->orc.kernel_orc_entry.bp_offset);
		fprintf(fp, "                          sp_reg: %d\n", ms->orc.kernel_orc_entry.sp_reg);
		fprintf(fp, "                          bp_reg: %d\n", ms->orc.kernel_orc_entry.bp_reg);
		fprintf(fp, "                            type: %d\n", ms->orc.kernel_orc_entry.type);
		if (MEMBER_EXISTS("orc_entry", "end"))
			fprintf(fp, "                             end: %d\n", ms->orc.kernel_orc_entry.end);
		else
			fprintf(fp, "                             end: (n/a)\n");
	} 
	fprintf(fp, "                      pto: %s",
		machdep->flags & PT_REGS_INIT ? "\n" : "(uninitialized)\n");
	if (machdep->flags & PT_REGS_INIT) {
 	fprintf(fp, "                           r15: %ld\n", ms->pto.r15);
 	fprintf(fp, "                           r14: %ld\n", ms->pto.r14);
 	fprintf(fp, "                           r13: %ld\n", ms->pto.r13);
 	fprintf(fp, "                           r12: %ld\n", ms->pto.r12);
	fprintf(fp, "                           rbp: %ld\n", ms->pto.rbp);
	fprintf(fp, "                           rbx: %ld\n", ms->pto.rbx);
 	fprintf(fp, "                           r11: %ld\n", ms->pto.r11);
 	fprintf(fp, "                           r10: %ld\n", ms->pto.r10);
 	fprintf(fp, "                            r9: %ld\n", ms->pto.r9);
 	fprintf(fp, "                            r8: %ld\n", ms->pto.r8);
	fprintf(fp, "                           rax: %ld\n", ms->pto.rax);
	fprintf(fp, "                           rcx: %ld\n", ms->pto.rcx);
	fprintf(fp, "                           rdx: %ld\n", ms->pto.rdx);
	fprintf(fp, "                           rsi: %ld\n", ms->pto.rsi);
	fprintf(fp, "                           rdi: %ld\n", ms->pto.rdi);
	fprintf(fp, "                      orig_rax: %ld\n", ms->pto.orig_rax);
	fprintf(fp, "                           rip: %ld\n", ms->pto.rip);
	fprintf(fp, "                            cs: %ld\n", ms->pto.cs);
	fprintf(fp, "                        eflags: %ld\n", ms->pto.eflags);
	fprintf(fp, "                           rsp: %ld\n", ms->pto.rsp);
	fprintf(fp, "                            ss: %ld\n", ms->pto.ss);
	}

#define CPU_SPACES(C) \
   ((C) < 10 ? 3 : (C) < 100 ? 2 : (C) < 1000 ? 1 : 0)

	fprintf(fp, "%s            current[%d]:%s", 
		space(CPU_SPACES(kt->cpus)), kt->cpus,
		ms->current ? "\n   " : " (unused)\n");
	for (c = 0; ms->current && (c < kt->cpus); c++) { 
		if (c && !(c%4))
			fprintf(fp, "\n   ");
		fprintf(fp, "%016lx ", ms->current[c]);
	}
	if (ms->current)
		fprintf(fp, "\n");

	fprintf(fp, "%s      crash_nmi_rsp[%d]:%s", 
		space(CPU_SPACES(kt->cpus)), kt->cpus, 
		ms->crash_nmi_rsp ? "\n   " : " (unused)\n");
	for (c = 0; ms->crash_nmi_rsp && (c < kt->cpus); c++) { 
		if (c && !(c%4))
			fprintf(fp, "\n   ");
		fprintf(fp, "%016lx ", ms->crash_nmi_rsp[c]);
	}
	if (ms->crash_nmi_rsp)
		fprintf(fp, "\n");
	fprintf(fp, "            vsyscall_page: %lx\n", ms->vsyscall_page); 
	fprintf(fp, "            thread_return: %lx\n", ms->thread_return); 
	fprintf(fp, "            page_protnone: %lx\n", ms->page_protnone); 

	fprintf(fp, "                 irqstack: %lx\n", (ulong)ms->irqstack);
	fprintf(fp, "          irq_eframe_link: %ld\n", ms->irq_eframe_link);
	fprintf(fp, "            irq_stack_gap: %ld\n", ms->irq_stack_gap);
	fprintf(fp, "                  stkinfo: isize: %d\n", 
		ms->stkinfo.isize);
	fprintf(fp, "                           esize[%d]: %d,%d,%d,%d,%d,%d,%d%s\n", 
		MAX_EXCEPTION_STACKS,
		ms->stkinfo.esize[0], 
		ms->stkinfo.esize[1], 
		ms->stkinfo.esize[2], 
		ms->stkinfo.esize[3], 
		ms->stkinfo.esize[4], 
		ms->stkinfo.esize[5], 
		ms->stkinfo.esize[6], 
		machdep->flags & NO_TSS ? " (NO TSS) " : " ");

	fprintf(fp, "                           NMI_stack_index: %d\n", 
		ms->stkinfo.NMI_stack_index);
        fprintf(fp, "                           exception_stacks:\n");
        for (i = 0; i < MAX_EXCEPTION_STACKS; i++)
		fprintf(fp, "                             [%d]: %s\n", i, 
			ms->stkinfo.exception_stacks[i]);

	fprintf(fp, "                           ebase[%s][%d]:",
		arg ? "NR_CPUS" : "cpus", MAX_EXCEPTION_STACKS);
	cpus = arg ? NR_CPUS : kt->cpus;
	for (c = 0; c < cpus; c++) {
		fprintf(fp, "\n  %s[%d]: ", c < 10 ? " " : "", c);
		for (i = 0; i < MAX_EXCEPTION_STACKS; i++) { 
			fprintf(fp, "%016lx ", ms->stkinfo.ebase[c][i]);
			if (i == 3)
				fprintf(fp, "\n        ");
		}
	}
	fprintf(fp, "\n                           ibase[%s]:\n   ",
		arg ? "NR_CPUS" : "cpus");
	for (c = 0; c < cpus; c++) {
		if (c && !(c%4))
			fprintf(fp, "\n   ");
		fprintf(fp, "%016lx ", ms->stkinfo.ibase[c]);
	}
	fprintf(fp, "\n    kpti_entry_stack_size: ");
	if (ms->kpti_entry_stack_size)
		fprintf(fp, "%ld", ms->kpti_entry_stack_size);
	else
		fprintf(fp, "(unused)");
	fprintf(fp, "\n         kpti_entry_stack: ");
	if (machdep->flags & KPTI) {
		fprintf(fp, "(percpu: %lx):\n   ", ms->kpti_entry_stack);
		for (c = 0; c < cpus; c++) {
			if (c && !(c%4))
				fprintf(fp, "\n   ");
			fprintf(fp, "%016lx ", ms->kpti_entry_stack + kt->__per_cpu_offset[c]);
		}
		fprintf(fp, "\n");
	} else
		fprintf(fp, "(unused)\n");
	fprintf(fp, "     cpu_entry_area_start: ");
	if (ms->cpu_entry_area_start)
		fprintf(fp, "%016lx\n", (ulong)ms->cpu_entry_area_start);
	else
		fprintf(fp, "(unused)\n");
	fprintf(fp, "       cpu_entry_area_end: ");
	if (ms->cpu_entry_area_end)
		fprintf(fp, "%016lx\n", (ulong)ms->cpu_entry_area_end);
	else
		fprintf(fp, "(unused)\n");

	fprintf(fp, "      excpetion_functions: ");
	if (ms->exception_functions == (char **)exception_functions_5_8)
		fprintf(fp, "excpetion_functions_5_8\n");
	else
		fprintf(fp, "excpetion_functions_orig\n");
}

/*
 *  Gather the cpu_pda array info, updating any smp-related items that
 *  were possibly bypassed or improperly initialized in kernel_init().
 */
static void 
x86_64_cpu_pda_init(void)
{
	int i, cpus, nr_pda, cpunumber, _cpu_pda, _boot_cpu_pda;
	char *cpu_pda_buf;
	ulong level4_pgt, data_offset, cpu_pda_addr;
	struct syment *sp, *nsp;
	ulong offset, istacksize;

	_boot_cpu_pda = FALSE;
	level4_pgt = 0;

	STRUCT_SIZE_INIT(x8664_pda, "x8664_pda");
	MEMBER_OFFSET_INIT(x8664_pda_pcurrent, "x8664_pda", "pcurrent");
	MEMBER_OFFSET_INIT(x8664_pda_data_offset, "x8664_pda", "data_offset");
	MEMBER_OFFSET_INIT(x8664_pda_kernelstack, "x8664_pda", "kernelstack");
	MEMBER_OFFSET_INIT(x8664_pda_irqrsp, "x8664_pda", "irqrsp");
	MEMBER_OFFSET_INIT(x8664_pda_irqstackptr, "x8664_pda", "irqstackptr");
	MEMBER_OFFSET_INIT(x8664_pda_level4_pgt, "x8664_pda", "level4_pgt");
	MEMBER_OFFSET_INIT(x8664_pda_cpunumber, "x8664_pda", "cpunumber");
	MEMBER_OFFSET_INIT(x8664_pda_me, "x8664_pda", "me");

	cpu_pda_buf = GETBUF(SIZE(x8664_pda));

	if (LKCD_KERNTYPES()) {
		if (symbol_exists("_cpu_pda"))
			_cpu_pda = TRUE;
		else
 			_cpu_pda = FALSE;
		nr_pda = get_cpus_possible();
	} else {
		if (symbol_exists("_cpu_pda")) {
			if (!(nr_pda = get_array_length("_cpu_pda", NULL, 0)))
				nr_pda = NR_CPUS;
			_cpu_pda = TRUE;
		} else {
			if (!(nr_pda = get_array_length("cpu_pda", NULL, 0)))
				nr_pda = NR_CPUS;
			_cpu_pda = FALSE;
		}
	}
	if (_cpu_pda) {
		if (symbol_exists("_boot_cpu_pda"))
			_boot_cpu_pda = TRUE;
		else
			_boot_cpu_pda = FALSE;
	}

	if (DUMPFILE() &&
	    !(machdep->machspec->current = calloc(nr_pda, sizeof(ulong))))
		error(FATAL, "cannot calloc %d x86_64 current pointers!\n",
			nr_pda);

	for (i = cpus = 0; i < nr_pda; i++) {
		if (_cpu_pda) {
			if (_boot_cpu_pda) {
				if (!_CPU_PDA_READ2(i, cpu_pda_buf))
					break;
			} else {
				if (!_CPU_PDA_READ(i, cpu_pda_buf))
					break;
			}
		} else {
			if (!CPU_PDA_READ(i, cpu_pda_buf))
				break;
		}

		if (VALID_MEMBER(x8664_pda_level4_pgt)) {
			level4_pgt = ULONG(cpu_pda_buf + OFFSET(x8664_pda_level4_pgt));
			if (!VALID_LEVEL4_PGT_ADDR(level4_pgt))
				break;
		}
		cpunumber = INT(cpu_pda_buf + OFFSET(x8664_pda_cpunumber));
		if (cpunumber != cpus)
			break;
		cpus++;

		if (VALID_MEMBER(x8664_pda_data_offset)) {
			data_offset = ULONG(cpu_pda_buf + 
				OFFSET(x8664_pda_data_offset));
                        kt->__per_cpu_offset[i] = data_offset;
                        kt->flags |= PER_CPU_OFF;
		} else
			data_offset = 0;

		machdep->machspec->stkinfo.ibase[i] = ULONG(cpu_pda_buf + 
			OFFSET(x8664_pda_irqstackptr));
		if (DUMPFILE())
			machdep->machspec->current[i] = ULONG(cpu_pda_buf + 
				OFFSET(x8664_pda_pcurrent));

		if (CRASHDEBUG(2)) 
			fprintf(fp, 
			    "CPU%d: level4_pgt: %lx " 
			    "data_offset: %lx pcurrent: %lx\n",
				i, level4_pgt, data_offset, 
				DUMPFILE() ? machdep->machspec->current[i] : 0);
	}

	if (!LKCD_KERNTYPES() &&
	    (i = get_array_length("boot_cpu_stack", NULL, 0))) {
		istacksize = i;
	} else if ((sp = symbol_search("boot_cpu_stack")) &&
 	    (nsp = next_symbol(NULL, sp))) {
		istacksize = (nsp->value - sp->value) & ~(PAGESIZE()-1);
		if (istacksize != 16384)
			error(WARNING, 
			    "calculated irqstack size of %ld != 16K?\n\n",
				istacksize);
	} else 
		istacksize = 16384;

	machdep->machspec->stkinfo.isize = istacksize;

	/*
	 *  Adjust the kernel top-of-stack values down to their base.
	 */
	for (i = 0; i < NR_CPUS; i++) {
		if (machdep->machspec->stkinfo.ibase[i])
			machdep->machspec->stkinfo.ibase[i] -= (istacksize-64);
		else
			break;
	}

	/*
	 *  Sanity check cpu 0's IRQ stack, which should be located at
	 *  the address of &boot_cpu_stack[0].
	 */
	sp = value_search(machdep->machspec->stkinfo.ibase[0], &offset);
	nsp = symbol_search("boot_cpu_stack");
	if (!sp || offset || !nsp || (sp->value != nsp->value)) {
		if (symbol_exists("boot_cpu_stack")) {
			error(WARNING, 
		       "cpu 0 IRQ stack: %lx\n         boot_cpu_stack: %lx\n\n",
				machdep->machspec->stkinfo.ibase[0], 
				symbol_value("boot_cpu_stack"));
			if (!machdep->machspec->stkinfo.ibase[0])
				machdep->machspec->stkinfo.ibase[0] = 
					symbol_value("boot_cpu_stack");
		} else
			error(WARNING, 
	 	     "boot_cpu_stack: symbol does not exist in this kernel!\n");
	}

	kt->cpus = cpus;
	if (kt->cpus > 1)
		kt->flags |= SMP;

	verify_spinlock();

	FREEBUF(cpu_pda_buf);
}

static void
x86_64_per_cpu_init(void)
{
	int i, cpus, cpunumber;
	struct machine_specific *ms;
	struct syment *irq_sp, *curr_sp, *cpu_sp, *hardirq_stack_ptr_sp, *pcpu_sp;
	ulong hardirq_stack_ptr;
	ulong __per_cpu_load = 0;
	long hardirq_addr = 0, cpu_addr = 0, curr_addr = 0;

	ms = machdep->machspec;

	pcpu_sp = per_cpu_symbol_search("pcpu_hot");

	hardirq_stack_ptr_sp = per_cpu_symbol_search("hardirq_stack_ptr");
	irq_sp = per_cpu_symbol_search("per_cpu__irq_stack_union");
	cpu_sp = per_cpu_symbol_search("per_cpu__cpu_number");
	curr_sp = per_cpu_symbol_search("per_cpu__current_task");

	if (!(kt->flags & PER_CPU_OFF)) {
		/*
		 * Presume kernel is !CONFIG_SMP.
		 */
		if (irq_sp || (irq_sp = symbol_search("irq_stack_union"))) { 
			ms->stkinfo.ibase[0] = irq_sp->value;
			if ((ms->stkinfo.isize = 
		    	    MEMBER_SIZE("irq_stack_union", "irq_stack")) <= 0)
				ms->stkinfo.isize = 16384;
		}
		if (DUMPFILE() && curr_sp) {
			if (!(ms->current = calloc(kt->cpus, sizeof(ulong))))
				error(FATAL, 
			    	    "cannot calloc"
				    " %d x86_64 current pointers!\n",
					kt->cpus);
			get_symbol_data(curr_sp->name, sizeof(ulong),
				&ms->current[0]);
		}

		return;
	}

	if (!pcpu_sp && (!cpu_sp || (!irq_sp && !hardirq_stack_ptr_sp)))
		return;

	if (MEMBER_EXISTS("irq_stack_union", "irq_stack"))
		ms->stkinfo.isize = MEMBER_SIZE("irq_stack_union", "irq_stack");
	else if (MEMBER_EXISTS("irq_stack", "stack"))
		ms->stkinfo.isize = MEMBER_SIZE("irq_stack", "stack");
	else if (!ms->stkinfo.isize)
		ms->stkinfo.isize = 16384;

	if (kernel_symbol_exists("__per_cpu_load"))
		__per_cpu_load = symbol_value("__per_cpu_load");

	if (pcpu_sp) {
		hardirq_addr = pcpu_sp->value + MEMBER_OFFSET("pcpu_hot", "hardirq_stack_ptr");
		cpu_addr = pcpu_sp->value + MEMBER_OFFSET("pcpu_hot", "cpu_number");
		curr_addr = pcpu_sp->value + MEMBER_OFFSET("pcpu_hot", "current_task");
	} else {
		if (hardirq_stack_ptr_sp)
			hardirq_addr = hardirq_stack_ptr_sp->value;
		cpu_addr = cpu_sp->value;
		curr_addr = curr_sp->value;
	}

	for (i = cpus = 0; i < NR_CPUS; i++) {
		if (__per_cpu_load && kt->__per_cpu_offset[i] == __per_cpu_load)
			break;
		if (!readmem(cpu_addr + kt->__per_cpu_offset[i],
		    KVADDR, &cpunumber, sizeof(int),
		    "cpu number (per_cpu)", QUIET|RETURN_ON_ERROR))
			break;

		if (cpunumber != cpus)
			break;
		cpus++;

		if (pcpu_sp || hardirq_stack_ptr_sp) {
			if (!readmem(hardirq_addr + kt->__per_cpu_offset[i],
		    	    KVADDR, &hardirq_stack_ptr, sizeof(void *),
		    	    "hardirq_stack_ptr (per_cpu)", QUIET|RETURN_ON_ERROR))
				continue;
			if (hardirq_stack_ptr != PAGEBASE(hardirq_stack_ptr))
				hardirq_stack_ptr += 8;
			ms->stkinfo.ibase[i] = hardirq_stack_ptr - ms->stkinfo.isize;
		} else if (irq_sp)
			ms->stkinfo.ibase[i] = irq_sp->value + kt->__per_cpu_offset[i];
	}

	if (CRASHDEBUG(2))
		fprintf(fp, "x86_64_per_cpu_init: "
		    "setup_percpu areas: %d\n", cpus);

	if (cpus > 1)
		kt->flags |= SMP;

	if ((i = get_cpus_present()) && (!cpus || (i < cpus)))
		kt->cpus = get_highest_cpu_present() + 1;
	else
		kt->cpus = cpus;

	if (DUMPFILE() && (pcpu_sp || curr_sp)) {
		if ((ms->current = calloc(kt->cpus, sizeof(ulong))) == NULL)
			error(FATAL, 
			    "cannot calloc %d x86_64 current pointers!\n",
				kt->cpus);
		for (i = 0; i < kt->cpus; i++)
			if (!readmem(curr_addr + kt->__per_cpu_offset[i],
			    KVADDR, &ms->current[i], sizeof(ulong),
			    "current_task (per_cpu)", RETURN_ON_ERROR))
				continue;
	}

	verify_spinlock();
}

/*
 *  Gather the ist addresses for each CPU.
 */
static void 
x86_64_ist_init(void)
{
	int c, i, cpus, esize;
	ulong vaddr, offset;
	ulong init_tss;
	struct machine_specific *ms;
	struct syment *boot_sp, *tss_sp, *ist_sp;
	char *exc_stack_struct_name = NULL;

        ms = machdep->machspec;
	if (!(tss_sp = per_cpu_symbol_search("per_cpu__init_tss"))) {
		if (!(tss_sp = per_cpu_symbol_search("per_cpu__cpu_tss")))
			tss_sp = per_cpu_symbol_search("per_cpu__cpu_tss_rw");
	}
	ist_sp = per_cpu_symbol_search("per_cpu__orig_ist");

	x86_64_exception_stacks_init();

	if (!tss_sp && symbol_exists("init_tss")) {
		init_tss = symbol_value("init_tss");
	
		for (c = cpus = 0; c < NR_CPUS; c++) {
			vaddr = init_tss + (c * SIZE(tss_struct)) +
				OFFSET(tss_struct_ist); 
			readmem(vaddr, KVADDR, &ms->stkinfo.ebase[c][0], 
				sizeof(ulong) * MAX_EXCEPTION_STACKS, 
				"tss_struct ist array", FAULT_ON_ERROR);
			if (ms->stkinfo.ebase[c][0] == 0)
				break;
		}
	} else if (tss_sp) {
		for (c = 0; c < kt->cpus; c++) {
                	if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF)) {
				if (kt->__per_cpu_offset[c] == 0)
					break;
				vaddr = tss_sp->value + kt->__per_cpu_offset[c];
			} else 
				vaddr = tss_sp->value;

			vaddr += OFFSET(tss_struct_ist);

                        readmem(vaddr, KVADDR, &ms->stkinfo.ebase[c][0],
                                sizeof(ulong) * MAX_EXCEPTION_STACKS, 
				"tss_struct ist array", FAULT_ON_ERROR);

                        if (ms->stkinfo.ebase[c][0] == 0)
                                break;
		}

		if (ist_sp) {
			for (c = 0; c < kt->cpus; c++) {
				ulong estacks[MAX_EXCEPTION_STACKS];
				if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF)) {
					if (kt->__per_cpu_offset[c] == 0)
						break;
					vaddr = ist_sp->value + kt->__per_cpu_offset[c];
				} else 
					vaddr = ist_sp->value;
	
				readmem(vaddr, KVADDR, &estacks[0],
				    sizeof(ulong) * MAX_EXCEPTION_STACKS, 
				    "orig_ist array", FAULT_ON_ERROR);

				for (i = 0; i < MAX_EXCEPTION_STACKS; i++) {
					if (ms->stkinfo.ebase[c][i] && estacks[i] &&
					    (ms->stkinfo.ebase[c][i] != estacks[i]))
						error(WARNING, 
						    "cpu %d %s stack: init_tss: %lx orig_ist: %lx\n", c,  
							ms->stkinfo.exception_stacks[i],
							ms->stkinfo.ebase[c][i], estacks[i]);
					ms->stkinfo.ebase[c][i] = estacks[i];
				}
			}
		}
	} else if (!symbol_exists("boot_exception_stacks")) {
		machdep->flags |= NO_TSS;

		if (CRASHDEBUG(1))
			error(NOTE, "CONFIG_X86_NO_TSS\n");

		return;
	}

	if (MEMBER_EXISTS("cea_exception_stacks", "NMI_stack")) {
		/* The effective cpu entry area mapping with guard pages. */
		exc_stack_struct_name = "cea_exception_stacks";
	} else if (MEMBER_EXISTS("exception_stacks", "NMI_stack")) {
		/* The exception stacks' physical storage. No guard pages and no VC stack. */
		exc_stack_struct_name = "exception_stacks";
	}
	if (exc_stack_struct_name) {
                for (i = 0; i < MAX_EXCEPTION_STACKS; i++) {
			if (STREQ(ms->stkinfo.exception_stacks[i], "DEBUG"))
				ms->stkinfo.esize[i] = MEMBER_SIZE(exc_stack_struct_name, "DB_stack");
			else if (STREQ(ms->stkinfo.exception_stacks[i], "NMI"))
				ms->stkinfo.esize[i] = MEMBER_SIZE(exc_stack_struct_name, "NMI_stack");
			else if (STREQ(ms->stkinfo.exception_stacks[i], "DOUBLEFAULT"))
				ms->stkinfo.esize[i] = MEMBER_SIZE(exc_stack_struct_name, "DF_stack");
			else if (STREQ(ms->stkinfo.exception_stacks[i], "MCE"))
				ms->stkinfo.esize[i] = MEMBER_SIZE(exc_stack_struct_name, "MCE_stack");
			else if (STREQ(ms->stkinfo.exception_stacks[i], "VC"))
				ms->stkinfo.esize[i] = MEMBER_SIZE(exc_stack_struct_name, "VC_stack");
		}
		/*
		 *  Adjust the top-of-stack addresses down to the base stack address
		 *  and set stack page availabilituy flag.
		 */
		for (c = 0; c < kt->cpus; c++) {
			for (i = 0; i < MAX_EXCEPTION_STACKS; i++) {
				if (ms->stkinfo.ebase[c][i])
					ms->stkinfo.ebase[c][i] -= ms->stkinfo.esize[i];

				ms->stkinfo.available[c][i] = TRUE;
				/* VC stack can be unmapped if SEV-ES is disabled or not supported. */
				if (STREQ(ms->stkinfo.exception_stacks[i], "VC") &&
				    !accessible(ms->stkinfo.ebase[c][i]))
					ms->stkinfo.available[c][i] = FALSE;
			}
		}

		return;

	} else if (ms->stkinfo.ebase[0][0] && ms->stkinfo.ebase[0][1])
		esize = ms->stkinfo.ebase[0][1] - ms->stkinfo.ebase[0][0];
	else
		esize = 4096;

	/*
 	 *  Knowing the size, now adjust the top-of-stack addresses back down
	 *  to the base stack address.
	 */
        for (c = 0; c < kt->cpus; c++) {
                for (i = 0; i < MAX_EXCEPTION_STACKS; i++) {
                        if (ms->stkinfo.ebase[c][i] == 0) 
                                break;
			if ((THIS_KERNEL_VERSION >= LINUX(2,6,18)) &&
			    STREQ(ms->stkinfo.exception_stacks[i], "DEBUG"))
				ms->stkinfo.esize[i] = esize*2;
			else
				ms->stkinfo.esize[i] = esize;
			ms->stkinfo.ebase[c][i] -= ms->stkinfo.esize[i];
			ms->stkinfo.available[c][i] = TRUE;
		}
	}

	/*
	 *  Sanity check cpu 0's first exception stack, which should be
	 *  located at: &boot_exception_stacks[0]
	 */
        boot_sp = value_search(ms->stkinfo.ebase[0][0], &offset);
       	if (!boot_sp || offset || 
	    !STREQ(boot_sp->name, "boot_exception_stacks")) {
		if ((boot_sp = symbol_search("boot_exception_stacks"))) {
                	error(WARNING,
    "cpu 0 first exception stack: %lx\n         boot_exception_stacks: %lx\n\n",
                        	ms->stkinfo.ebase[0][0], boot_sp->value);
			if (!ms->stkinfo.ebase[0][0])
				ms->stkinfo.ebase[0][0] = boot_sp->value;
		} else if (STRUCT_EXISTS("x8664_pda"))
			error(WARNING, 
	      "boot_exception_stacks: symbol does not exist in this kernel!\n");
	}
}

/*
 *  Determine whether the unused gap at the top of the IRQ stack exists,
 *  and store its size (either 0 or 64 bytes).
 */
static void 
x86_64_irq_stack_gap_init(void)
{
	int c, cpus;
	struct syment *sp;
	ulong irq_stack_ptr;
	struct machine_specific *ms = machdep->machspec;
	
	if (ms->irq_stack_gap != UNINITIALIZED)
		return;

	if (THIS_KERNEL_VERSION >= LINUX(4,9,0)) {
		ms->irq_stack_gap = 0;
		return;
	}

	ms->irq_stack_gap = 64;

	/*
	 *  Check for backports of this commit:
	 *
	 *    commit 4950d6d48a0c43cc61d0bbb76fb10e0214b79c66
	 *    Author: Josh Poimboeuf <jpoimboe@redhat.com>
	 *    Date:   Thu Aug 18 10:59:08 2016 -0500
	 *
	 *        x86/dumpstack: Remove 64-byte gap at end of irq stack
	 */

	if (!(sp = per_cpu_symbol_search("per_cpu__irq_stack_ptr")))
		return;

	/*
	 *  CONFIG_SMP=n
	 */
	if (!(kt->flags & PER_CPU_OFF)) {
		get_symbol_data(sp->name, sizeof(ulong), &irq_stack_ptr);
		if ((irq_stack_ptr & 0xfff) == 0)
			ms->irq_stack_gap = 0;
		return;
	}

	/*
	 *  Check the per-cpu irq_stack_ptr of the first possible cpu.
	 */
	if (!cpu_map_addr("possible"))
		return;

	cpus = kt->kernel_NR_CPUS ? kt->kernel_NR_CPUS : NR_CPUS;
	for (c = 0; c < cpus; c++) {
		if (!in_cpu_map(POSSIBLE, c))
			continue;
		if (readmem(sp->value + kt->__per_cpu_offset[c],
		    KVADDR, &irq_stack_ptr, sizeof(void *), "irq_stack_ptr",
		    QUIET|RETURN_ON_ERROR)) {
			if ((irq_stack_ptr & 0xfff) == 0)
				ms->irq_stack_gap = 0;
			break;
		}
	}
}

/*
 *  Check kernel version and/or backport for L1TF
 */
static void
x86_64_l1tf_init(void)
{
	if (THIS_KERNEL_VERSION >= LINUX(4,18,1) ||
	    kernel_symbol_exists("l1tf_mitigation"))
		machdep->flags |= L1TF;
}

static void 
x86_64_post_init(void)
{ 
        int c, i, clues;
        struct machine_specific *ms;
	ulong *up;
	struct syment *spt, *spc;
	ulong offset;

	/*
	 *  Check whether each cpu was stopped by an NMI.
	 */
        ms = machdep->machspec;
	
	if (DUMPFILE() && 
	    (ms->crash_nmi_rsp = calloc(kt->cpus, sizeof(ulong))) == NULL)
		error(FATAL, "cannot calloc %d x86_64 NMI rsp values\n",
			kt->cpus);

        for (c = 0; DUMPFILE() && (c < kt->cpus); c++) {
                if (ms->stkinfo.ebase[c][NMI_STACK] == 0)
                        break;

                if (!readmem(ms->stkinfo.ebase[c][NMI_STACK], 
		    KVADDR, ms->irqstack,
		    ms->stkinfo.esize[NMI_STACK],
                    "NMI exception stack contents", 
		    RETURN_ON_ERROR|QUIET)) 
			continue;

       		for (i = clues = 0; i < (ms->stkinfo.esize[NMI_STACK])/sizeof(ulong); i++){
                	up = (ulong *)(&ms->irqstack[i*sizeof(ulong)]);

                	if (!is_kernel_text(*up) ||
                            !(spt = value_search(*up, &offset)))
				continue;

			if (STREQ(spt->name, "try_crashdump") ||
			    STREQ(spt->name, "die_nmi")) 
				clues++;

                    	if ((STREQ(spt->name, "nmi_watchdog_tick") ||
                     	     STREQ(spt->name, "default_do_nmi"))) {
                        	spc = x86_64_function_called_by((*up)-5);
                        	if (spc && STREQ(spc->name, "die_nmi"))
                                	clues += 2;
			}

			if (STREQ(spt->name, "crash_nmi_callback")) {
				up = (ulong *)(&ms->irqstack[ms->stkinfo.esize[NMI_STACK]]);
				up -= 2;
				ms->crash_nmi_rsp[c] = *up;
			}
		}

		if (clues >= 2) 
			kt->cpu_flags[c] |= NMI;
        }

	if (symbol_exists("__sched_text_start") && 
	    (symbol_value("__sched_text_start") == symbol_value("schedule")))
		machdep->flags |= SCHED_TEXT;
}

/*
 *  No x86_64 swapper_pg_dir; initialize the vt->kernel_pgd[NR_CPUS] array
 *  with the lazily-sync'd init_level4_pgt page address.  The level4 page
 *  could be taken from the per-cpu cpu_pda.level4_pgt pointer, but since
 *  the kernel pgd_offset_k() is defined as shown below, we'll derive
 *  the third-level pgd in the same manner:
 *   
 *   /@ This accesses the reference page table of the boot cpu.
 *      Other CPUs get synced lazily via the page fault handler. @/
 *
 *   static inline pgd_t *pgd_offset_k(unsigned long address)
 *   {
 *           unsigned long addr;
 *   
 *           addr = pml4_val(init_level4_pgt[pml4_index(address)]);
 *           addr &= PHYSICAL_PAGE_MASK;
 *           return __pgd_offset_k((pgd_t *)__va(addr), address);
 *   } 
 */ 
static void 
x86_64_init_kernel_pgd(void)
{
	int i;
	ulong kernel_pgt = 0;

	if (kernel_symbol_exists("init_level4_pgt"))
		kernel_pgt = symbol_value("init_level4_pgt");
	else if (kernel_symbol_exists("init_top_pgt"))
		kernel_pgt = symbol_value("init_top_pgt");
	else
		error(WARNING, "neither \"init_level4_pgt\" or \"init_top_pgt\" exist\n");

	for (i = 0; i < NR_CPUS; i++) 
		vt->kernel_pgd[i] = kernel_pgt;

	FILL_TOP_PGD();
}

/*
 *  x86_64 __pa() clone.
 */
ulong x86_64_VTOP(ulong vaddr) 
{
	if (vaddr >= __START_KERNEL_map)
		return ((vaddr) - (ulong)__START_KERNEL_map + machdep->machspec->phys_base);
	else
		return ((vaddr) - PAGE_OFFSET);
}

/*
 *  Include both vmalloc'd and module address space as VMALLOC space.
 */
int 
x86_64_IS_VMALLOC_ADDR(ulong vaddr)
{
	return ((vaddr >= VMALLOC_START && vaddr <= VMALLOC_END) ||
                ((machdep->flags & VMEMMAP) && 
		 (vaddr >= VMEMMAP_VADDR && vaddr <= VMEMMAP_END)) ||
                (vaddr >= MODULES_VADDR && vaddr <= MODULES_END) ||
		(vaddr >= VSYSCALL_START && vaddr < VSYSCALL_END) ||
		(machdep->machspec->cpu_entry_area_start && 
		 vaddr >= machdep->machspec->cpu_entry_area_start &&
		 vaddr <= machdep->machspec->cpu_entry_area_end) ||
		((machdep->flags & VM_5LEVEL) && vaddr > VMALLOC_END && vaddr < VMEMMAP_VADDR));
}

static int 
x86_64_is_module_addr(ulong vaddr)
{
	return (vaddr >= MODULES_VADDR && vaddr <= MODULES_END);
}

/*
 *  Refining this may cause more problems than just doing it this way.
 */
static int 
x86_64_is_kvaddr(ulong addr)
{
	if (machdep->flags & VM_XEN_RHEL4)
		return (addr >= VMALLOC_START);
	else
        	return (addr >= PAGE_OFFSET); 
}

static int 
x86_64_is_uvaddr(ulong addr, struct task_context *tc)
{
        return (addr < USERSPACE_TOP);
}

static int
x86_64_is_page_ptr(ulong addr, physaddr_t *phys)
{
	ulong pfn, nr;

	if (IS_SPARSEMEM() && (machdep->flags & VMEMMAP) &&
	    (addr >= VMEMMAP_VADDR && addr <= VMEMMAP_END) &&
	    !((addr - VMEMMAP_VADDR) % SIZE(page))) {

		pfn = (addr - VMEMMAP_VADDR) / SIZE(page);
		nr = pfn_to_section_nr(pfn);
		if (valid_section_nr(nr)) {
			if (phys)
				*phys = PTOB(pfn);
			return TRUE;
		}
	}
	return FALSE;
}

/*
 * Find the kernel pgd entry..
 * pgd = pgd_offset_k(addr);
 */
static ulong *
x86_64_kpgd_offset(ulong kvaddr, int verbose, int IS_XEN)
{
	ulong *pgd;

	FILL_TOP_PGD();
	pgd = ((ulong *)machdep->pgd) + pgd_index(kvaddr);
	if (verbose) {
		fprintf(fp, "PGD DIRECTORY: %lx\n", vt->kernel_pgd[0]);
		if (IS_XEN)
			fprintf(fp, "PAGE DIRECTORY: %lx [machine]\n", *pgd);
		else
			fprintf(fp, "PAGE DIRECTORY: %lx\n", *pgd & ~machdep->machspec->sme_mask);
	}

	return pgd;
}

/*
 * In x86 64 bit system, Linux uses the 4-level page table as the default both
 * in Kernel page tables and user page tables.
 *
 * But in some old versions(pre-2.6.11), the 3-level page table is used for
 * user page tables.
 *
 * So reuse the PUD and find the user pgd entry for this older version Linux..
 * pgd = pgd_offset(mm, address);
 */
static ulong
x86_64_upgd_offset_legacy(struct task_context *tc, ulong uvaddr, int verbose, int IS_XEN)
{
	ulong *pud;
	ulong pud_paddr;
	ulong pud_pte;

        if (task_mm(tc->task, TRUE))
                pud = ULONG_PTR(tt->mm_struct + OFFSET(mm_struct_pgd));
        else
                readmem(tc->mm_struct + OFFSET(mm_struct_pgd), KVADDR, &pud,
                        sizeof(long), "mm_struct pgd", FAULT_ON_ERROR);

        pud_paddr = x86_64_VTOP((ulong)pud);
        FILL_PUD(pud_paddr, PHYSADDR, PAGESIZE());
	pud = ((ulong *)pud_paddr) + pud_index(uvaddr);
	pud_pte = ULONG(machdep->pud + PAGEOFFSET(pud));
        if (verbose) {
		if (IS_XEN)
			fprintf(fp, "   PGD: %lx => %lx [machine]\n", (ulong)pud, pud_pte);
		else
			fprintf(fp, "   PGD: %lx => %lx\n",
				(ulong)pud, pud_pte & ~machdep->machspec->sme_mask);
        }

	return pud_pte;
}

/*
 * Find the user pgd entry..
 * pgd = pgd_offset(mm, address);
 */
static ulong
x86_64_upgd_offset(struct task_context *tc, ulong uvaddr, int verbose, int IS_XEN)
{
	ulong *pgd;
	ulong pgd_paddr;
	ulong pgd_pte;

	if (task_mm(tc->task, TRUE))
		pgd = ULONG_PTR(tt->mm_struct + OFFSET(mm_struct_pgd));
	else
		readmem(tc->mm_struct + OFFSET(mm_struct_pgd), KVADDR, &pgd,
				sizeof(long), "mm_struct pgd", FAULT_ON_ERROR);

	pgd_paddr = x86_64_VTOP((ulong)pgd);
	FILL_PGD(pgd_paddr, PHYSADDR, PAGESIZE());
	pgd = ((ulong *)pgd_paddr) + pgd_index(uvaddr);
	pgd_pte = ULONG(machdep->pgd + PAGEOFFSET(pgd));
        if (verbose) {
		if (IS_XEN)
			fprintf(fp, "   PGD: %lx => %lx [machine]\n", (ulong)pgd, pgd_pte);
		else
			fprintf(fp, "   PGD: %lx => %lx\n",
				(ulong)pgd, pgd_pte & ~machdep->machspec->sme_mask);
        }

	return pgd_pte;
}

/*
 * Find an entry in the fourth-level page table..
 * p4d = p4d_offset(pgd, address);
 */
static ulong
x86_64_p4d_offset(ulong pgd_pte, ulong vaddr, int verbose, int IS_XEN)
{
	ulong *p4d;
	ulong p4d_paddr;
	ulong p4d_pte;

	p4d_paddr = pgd_pte & PHYSICAL_PAGE_MASK;
	p4d_paddr &= ~machdep->machspec->sme_mask;
	FILL_P4D(p4d_paddr, PHYSADDR, PAGESIZE());
	p4d = ((ulong *)p4d_paddr) + p4d_index(vaddr);
	p4d_pte = ULONG(machdep->machspec->p4d + PAGEOFFSET(p4d));
	p4d_pte &= ~machdep->machspec->sme_mask;
        if (verbose) {
		if (IS_XEN)
			fprintf(fp, "   P4D: %lx => %lx [machine]\n", (ulong)p4d, p4d_pte);
		else
			fprintf(fp, "   P4D: %lx => %lx\n", (ulong)p4d, p4d_pte);
        }

	return p4d_pte;
}

/*
 * Find an entry in the third-level page table..
 * pud = pud_offset(pgd, address);
 */
static ulong
x86_64_pud_offset(ulong pgd_pte, ulong vaddr, int verbose, int IS_XEN)
{
	ulong *pud;
	ulong pud_paddr;
	ulong pud_pte;

	pud_paddr = pgd_pte & PHYSICAL_PAGE_MASK;
	pud_paddr &= ~machdep->machspec->sme_mask;

	if (IS_XEN) {
		pud_paddr = xen_m2p(pud_paddr);
		if (verbose)
			fprintf(fp, "	PGD: %lx\n", pud_paddr);
	}

	FILL_PUD(pud_paddr, PHYSADDR, PAGESIZE());
	pud = ((ulong *)pud_paddr) + pud_index(vaddr);
	pud_pte = ULONG(machdep->pud + PAGEOFFSET(pud));
	pud_pte &= ~machdep->machspec->sme_mask;
	if (verbose) {
		if (IS_XEN)
			fprintf(fp, "   PUD: %lx => %lx [machine]\n", (ulong)pud, pud_pte);
		else
			fprintf(fp, "   PUD: %lx => %lx\n", (ulong)pud, pud_pte);
        }

	return pud_pte;
}

/*
 * Find an entry in the middle page table..
 * pmd = pmd_offset(pud, address);
 */
static ulong
x86_64_pmd_offset(ulong pud_pte, ulong vaddr, int verbose, int IS_XEN)
{
	ulong *pmd;
	ulong pmd_paddr;
	ulong pmd_pte;

	pmd_paddr = pud_pte & PHYSICAL_PAGE_MASK;
	pmd_paddr &= ~machdep->machspec->sme_mask;

	if (IS_XEN) {
		pmd_paddr = xen_m2p(pmd_paddr);
		if (verbose)
			fprintf(fp, "	PUD: %lx\n", pmd_paddr);
	}

	FILL_PMD(pmd_paddr, PHYSADDR, PAGESIZE());
	pmd = ((ulong *)pmd_paddr) + pmd_index(vaddr);
	pmd_pte = ULONG(machdep->pmd + PAGEOFFSET(pmd));
	pmd_pte &= ~machdep->machspec->sme_mask;
        if (verbose) {
		if (IS_XEN)
			fprintf(fp, "   PMD: %lx => %lx [machine]\n", (ulong)pmd, pmd_pte);
		else
			fprintf(fp, "   PMD: %lx => %lx\n", (ulong)pmd, pmd_pte);
        }
	return pmd_pte;
}

/*
 * Find an entry in the pet page table..
 * pmd = pmd_offset(pud, address);
 */
static ulong
x86_64_pte_offset(ulong pmd_pte, ulong vaddr, int verbose, int IS_XEN)
{
	ulong *ptep;
	ulong pte_paddr;
	ulong pte;

	pte_paddr = pmd_pte & PHYSICAL_PAGE_MASK;
	pte_paddr &= ~machdep->machspec->sme_mask;

	if (IS_XEN) {
		pte_paddr = xen_m2p(pte_paddr);
		if (verbose)
			fprintf(fp, "   PMD: %lx\n", pte_paddr);
	}

	FILL_PTBL(pte_paddr, PHYSADDR, PAGESIZE());
	ptep = ((ulong *)pte_paddr) + pte_index(vaddr);
	pte = ULONG(machdep->ptbl + PAGEOFFSET(ptep));
	pte &= ~machdep->machspec->sme_mask;
	if (verbose) {
		if (IS_XEN)
			fprintf(fp, "   PTE: %lx => %lx [machine]\n", (ulong)ptep, pte);
		else
			fprintf(fp, "   PTE: %lx => %lx\n", (ulong)ptep, pte);
	}

	return pte;
}

/*
 *  Translates a user virtual address to its physical address.  cmd_vtop()
 *  sets the verbose flag so that the pte translation gets displayed; all
 *  other callers quietly accept the translation.
 *
 *  This routine can also take mapped kernel virtual addresses if the -u flag
 *  was passed to cmd_vtop(), just pass it to x86_64_kvtop().
 */

static int
x86_64_uvtop_level4(struct task_context *tc, ulong uvaddr, physaddr_t *paddr, int verbose)
{
	ulong pgd_pte;
	ulong pud_pte;
	ulong pmd_pte;
	ulong pte;
	physaddr_t physpage;

	if (!tc)
		error(FATAL, "current context invalid\n");

	*paddr = 0;

	if (IS_KVADDR(uvaddr))
		return x86_64_kvtop(tc, uvaddr, paddr, verbose);

        pgd_pte = x86_64_upgd_offset(tc, uvaddr, verbose, FALSE);
	if (!(pgd_pte & _PAGE_PRESENT))
		goto no_upage;

	/* If the VM is in 5-level page table */
	if (machdep->flags & VM_5LEVEL) {
		ulong p4d_pte;
		/*
		 *  p4d = p4d_offset(pgd, address);
		 */
		p4d_pte = x86_64_p4d_offset(pgd_pte, uvaddr, verbose, FALSE);
		if (!(p4d_pte & _PAGE_PRESENT))
			goto no_upage;
		/*
		 *  pud = pud_offset(p4d, address);
		 */
		pud_pte = x86_64_pud_offset(p4d_pte, uvaddr, verbose, FALSE);
	} else {
		/*
		 *  pud = pud_offset(pgd, address);
		 */
		pud_pte = x86_64_pud_offset(pgd_pte, uvaddr, verbose, FALSE);
	}

	if (!(pud_pte & _PAGE_PRESENT))
		goto no_upage;

	if (pud_pte & _PAGE_PSE) {
		if (verbose) {
			fprintf(fp, "  PAGE: %lx  (1GB)\n\n",
			       PAGEBASE(pud_pte) & PHYSICAL_PAGE_MASK);
			x86_64_translate_pte(pud_pte, 0, 0);
		}

		physpage = (PAGEBASE(pud_pte) & PHYSICAL_PAGE_MASK) +
			       (uvaddr & ~_1GB_PAGE_MASK);
		*paddr = physpage;
		return TRUE;
	}

	/*
         *  pmd = pmd_offset(pud, address);
	 */
	pmd_pte = x86_64_pmd_offset(pud_pte, uvaddr, verbose, FALSE);
	if (!(pmd_pte & (_PAGE_PRESENT | _PAGE_PROTNONE)))
		goto no_upage;
        if (pmd_pte & _PAGE_PSE) {
		if (verbose) {
                        fprintf(fp, "  PAGE: %lx  (2MB)\n\n", 
				PAGEBASE(pmd_pte) & PHYSICAL_PAGE_MASK);
                        x86_64_translate_pte(pmd_pte, 0, 0);
                }

                physpage = (PAGEBASE(pmd_pte) & PHYSICAL_PAGE_MASK) + 
			(uvaddr & ~_2MB_PAGE_MASK);
                *paddr = physpage;
                return TRUE;
        }

        /*
	 *  ptep = pte_offset_map(pmd, address);
	 *  pte = *ptep;
	 */
	pte = x86_64_pte_offset(pmd_pte, uvaddr, verbose, FALSE);
	if (!(pte & (_PAGE_PRESENT | _PAGE_PROTNONE))) {
		*paddr = pte;

		if (pte && verbose) {
			fprintf(fp, "\n");
			x86_64_translate_pte(pte, 0, 0);
		}
		goto no_upage;
	}

	*paddr = (PAGEBASE(pte) & PHYSICAL_PAGE_MASK) + PAGEOFFSET(uvaddr);

	if (verbose) {
		fprintf(fp, "  PAGE: %lx\n\n", 
			PAGEBASE(*paddr) & PHYSICAL_PAGE_MASK);
		x86_64_translate_pte(pte, 0, 0);
	}

	return TRUE;

no_upage:

	return FALSE;
}

static int
x86_64_uvtop_level4_xen_wpt(struct task_context *tc, ulong uvaddr, physaddr_t *paddr, int verbose)
{
	ulong pgd_pte;
	ulong pud_pte;
	ulong pmd_pte;
	ulong pseudo_pmd_pte;
	ulong pte;
	ulong pseudo_pte;
	physaddr_t physpage;
	char buf[BUFSIZE];

	if (!tc)
		error(FATAL, "current context invalid\n");

	*paddr = 0;

	if (IS_KVADDR(uvaddr))
		return x86_64_kvtop(tc, uvaddr, paddr, verbose);

	pgd_pte = x86_64_upgd_offset(tc, uvaddr, verbose, TRUE);
	if (!(pgd_pte & _PAGE_PRESENT))
		goto no_upage;

	pud_pte = x86_64_pud_offset(pgd_pte, uvaddr, verbose, TRUE);
	if (!(pud_pte & _PAGE_PRESENT))
		goto no_upage;

	/*
         *  pmd = pmd_offset(pud, address);
	 */
	pmd_pte = x86_64_pmd_offset(pud_pte, uvaddr, verbose, TRUE);
	if (!(pmd_pte & _PAGE_PRESENT))
		goto no_upage;
        if (pmd_pte & _PAGE_PSE) {
                if (verbose)
                        fprintf(fp, "  PAGE: %lx  (2MB) [machine]\n", 
				PAGEBASE(pmd_pte) & PHYSICAL_PAGE_MASK);

		pseudo_pmd_pte = xen_m2p(PAGEBASE(pmd_pte));

                if (pseudo_pmd_pte == XEN_MACHADDR_NOT_FOUND) {
                        if (verbose)
                                fprintf(fp, " PAGE: page not available\n");
                        *paddr = PADDR_NOT_AVAILABLE;
                        return FALSE;
                }

		pseudo_pmd_pte |= PAGEOFFSET(pmd_pte);

                if (verbose) {
                        fprintf(fp, " PAGE: %s  (2MB)\n\n",
                                mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX,
                                MKSTR(PAGEBASE(pseudo_pmd_pte) & 
				PHYSICAL_PAGE_MASK)));

                        x86_64_translate_pte(pseudo_pmd_pte, 0, 0);
                }

                physpage = (PAGEBASE(pseudo_pmd_pte) & PHYSICAL_PAGE_MASK) + 
			(uvaddr & ~_2MB_PAGE_MASK);

                *paddr = physpage;
                return TRUE;
        }

        /*
	 *  ptep = pte_offset_map(pmd, address);
	 *  pte = *ptep;
	 */
	pte = x86_64_pte_offset(pmd_pte, uvaddr, verbose, TRUE);
	if (!(pte & (_PAGE_PRESENT))) {
		*paddr = pte;

		if (pte && verbose) {
			fprintf(fp, "\n");
			x86_64_translate_pte(pte, 0, 0);
		}
		goto no_upage;
	}

	pseudo_pte = xen_m2p(pte & PHYSICAL_PAGE_MASK);
	if (verbose)
		fprintf(fp, "   PTE: %lx\n", pseudo_pte + PAGEOFFSET(pte));

	*paddr = (PAGEBASE(pseudo_pte) & PHYSICAL_PAGE_MASK) + PAGEOFFSET(uvaddr);

	if (verbose) {
		fprintf(fp, "  PAGE: %lx [machine]\n", 
			PAGEBASE(pte) & PHYSICAL_PAGE_MASK);
		fprintf(fp, "  PAGE: %lx\n\n", 
			PAGEBASE(*paddr) & PHYSICAL_PAGE_MASK);
		x86_64_translate_pte(pseudo_pte + PAGEOFFSET(pte), 0, 0);
	}

	return TRUE;

no_upage:

	return FALSE;
}

static int
x86_64_uvtop_level4_rhel4_xen_wpt(struct task_context *tc, ulong uvaddr, physaddr_t *paddr, int verbose)
{
	ulong pgd_pte;
	ulong pmd_pte;
	ulong pseudo_pmd_pte;
	ulong pte;
	ulong pseudo_pte;
	physaddr_t physpage;
	char buf[BUFSIZE];

	if (!tc)
		error(FATAL, "current context invalid\n");

	*paddr = 0;

	if (IS_KVADDR(uvaddr))
		return x86_64_kvtop(tc, uvaddr, paddr, verbose);

	pgd_pte = x86_64_upgd_offset_legacy(tc, uvaddr, verbose, TRUE);
	if (!(pgd_pte & _PAGE_PRESENT))
		goto no_upage;

	/*
         *  pmd = pmd_offset(pgd, address);
	 */
	pmd_pte = x86_64_pmd_offset(pgd_pte, uvaddr, verbose, TRUE);
	if (!(pmd_pte & _PAGE_PRESENT))
		goto no_upage;
        if (pmd_pte & _PAGE_PSE) {
                if (verbose)
                        fprintf(fp, "  PAGE: %lx  (2MB) [machine]\n", 
				PAGEBASE(pmd_pte) & PHYSICAL_PAGE_MASK);

		pseudo_pmd_pte = xen_m2p(PAGEBASE(pmd_pte));

                if (pseudo_pmd_pte == XEN_MACHADDR_NOT_FOUND) {
                        if (verbose)
                                fprintf(fp, " PAGE: page not available\n");
                        *paddr = PADDR_NOT_AVAILABLE;
                        return FALSE;
                }

		pseudo_pmd_pte |= PAGEOFFSET(pmd_pte);

                if (verbose) {
                        fprintf(fp, " PAGE: %s  (2MB)\n\n",
                                mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX,
                                MKSTR(PAGEBASE(pseudo_pmd_pte) & 
				PHYSICAL_PAGE_MASK)));

                        x86_64_translate_pte(pseudo_pmd_pte, 0, 0);
                }

                physpage = (PAGEBASE(pseudo_pmd_pte) & PHYSICAL_PAGE_MASK) + 
			(uvaddr & ~_2MB_PAGE_MASK);

                *paddr = physpage;
                return TRUE;
        }

        /*
	 *  ptep = pte_offset_map(pmd, address);
	 *  pte = *ptep;
	 */
	pte = x86_64_pte_offset(pmd_pte, uvaddr, verbose, TRUE);
	if (!(pte & (_PAGE_PRESENT))) {
		*paddr = pte;

		if (pte && verbose) {
			fprintf(fp, "\n");
			x86_64_translate_pte(pte, 0, 0);
		}
		goto no_upage;
	}
	
	pseudo_pte = xen_m2p(pte & PHYSICAL_PAGE_MASK);
	if (verbose)
		fprintf(fp, "   PTE: %lx\n", pseudo_pte + PAGEOFFSET(pte));

	*paddr = (PAGEBASE(pseudo_pte) & PHYSICAL_PAGE_MASK) + PAGEOFFSET(uvaddr);

	if (verbose) {
		fprintf(fp, "  PAGE: %lx [machine]\n", 
			PAGEBASE(pte) & PHYSICAL_PAGE_MASK);
		fprintf(fp, "  PAGE: %lx\n\n", 
			PAGEBASE(*paddr) & PHYSICAL_PAGE_MASK);
		x86_64_translate_pte(pseudo_pte + PAGEOFFSET(pte), 0, 0);
	}

	return TRUE;

no_upage:

	return FALSE;
}

static int
x86_64_uvtop(struct task_context *tc, ulong uvaddr, physaddr_t *paddr, int verbose)
{
	ulong pgd_pte;
	ulong pmd_pte;
        ulong pte;
        physaddr_t physpage;

        if (!tc)
                error(FATAL, "current context invalid\n");

        *paddr = 0;

        if (IS_KVADDR(uvaddr))
                return x86_64_kvtop(tc, uvaddr, paddr, verbose);

	/*
	 *  pgd = pgd_offset(mm, address);
	 */
	pgd_pte = x86_64_upgd_offset_legacy(tc, uvaddr, verbose, FALSE);
	if (!(pgd_pte & _PAGE_PRESENT))
		goto no_upage;

	/*
         *  pmd = pmd_offset(pgd, address);
	 */
	pmd_pte = x86_64_pmd_offset(pgd_pte, uvaddr, verbose, FALSE);
	if (!(pmd_pte & _PAGE_PRESENT))
		goto no_upage;
        if (pmd_pte & _PAGE_PSE) {
                if (verbose) {
                        fprintf(fp, "  PAGE: %lx  (2MB)\n\n", 
				PAGEBASE(pmd_pte) & PHYSICAL_PAGE_MASK);
                        x86_64_translate_pte(pmd_pte, 0, 0);
                }

                physpage = (PAGEBASE(pmd_pte) & PHYSICAL_PAGE_MASK) + 
			(uvaddr & ~_2MB_PAGE_MASK);
                *paddr = physpage;
                return TRUE;
        }

        /*
	 *  ptep = pte_offset_map(pmd, address);
         *  pte = *ptep;
	 */
	pte = x86_64_pte_offset(pmd_pte, uvaddr, verbose, FALSE);
        if (!(pte & (_PAGE_PRESENT))) {
		*paddr = pte;

                if (pte && verbose) {
                        fprintf(fp, "\n");
                        x86_64_translate_pte(pte, 0, 0);
                }
                goto no_upage;
        }

        *paddr = (PAGEBASE(pte) & PHYSICAL_PAGE_MASK) + PAGEOFFSET(uvaddr);

        if (verbose) {
                fprintf(fp, "  PAGE: %lx\n\n", 
			PAGEBASE(*paddr) & PHYSICAL_PAGE_MASK);
                x86_64_translate_pte(pte, 0, 0);
        }

	return TRUE;

no_upage:

	return FALSE;
}

/*
 *  Translates a kernel virtual address to its physical address.  cmd_vtop()
 *  sets the verbose flag so that the pte translation gets displayed; all
 *  other callers quietly accept the translation.
 */
static int
x86_64_kvtop(struct task_context *tc, ulong kvaddr, physaddr_t *paddr, int verbose)
{
	ulong *pgd;
	ulong pud_pte;
	ulong pmd_pte;
	ulong pte;
	physaddr_t physpage;

	if ((SADUMP_DUMPFILE() || QEMU_MEM_DUMP_NO_VMCOREINFO() || VMSS_DUMPFILE())
	    && !(machdep->flags & KSYMS_START)) {
		/*
		 * In the case of sadump, to calculate kaslr_offset and
		 * phys_base, kvtop is called during symtab_init(). In this
		 * stage phys_base is not initialized yet and x86_64_VTOP()
		 * does not work. Jump to the code of pagetable translation.
		 */
		pgd = x86_64_kpgd_offset(kvaddr, verbose, FALSE);
		goto start_vtop_with_pagetable;
	}

        if (!IS_KVADDR(kvaddr))
                return FALSE;

	if (XEN_HYPER_MODE()) {
		if (XEN_VIRT_ADDR(kvaddr)) {
			*paddr = kvaddr - XEN_VIRT_START + xen_phys_start();
			return TRUE;
		}
		if (DIRECTMAP_VIRT_ADDR(kvaddr)) {
			*paddr = kvaddr - DIRECTMAP_VIRT_START;
			return TRUE;
		}
		FILL_TOP_PGD_HYPER();
		pgd = ((ulong *)machdep->pgd) + pgd_index(kvaddr);
        	if (verbose) {
			fprintf(fp, "PGD DIRECTORY: %lx\n", vt->kernel_pgd[0]);
			fprintf(fp, "PAGE DIRECTORY: %lx\n", *pgd);
		}
	} else {
        	if (!vt->vmalloc_start) {
                	*paddr = x86_64_VTOP(kvaddr);
                	return TRUE;
        	}

        	if (!IS_VMALLOC_ADDR(kvaddr)) {
                	*paddr = x86_64_VTOP(kvaddr);
                	if (!verbose)
                        	return TRUE;
        	}

		if (XEN() && (kt->xen_flags & WRITABLE_PAGE_TABLES))
			return (x86_64_kvtop_xen_wpt(tc, kvaddr, paddr, verbose));

 		/*	
		 *  pgd = pgd_offset_k(addr);
		 */
		pgd = x86_64_kpgd_offset(kvaddr, verbose, FALSE);
	}

start_vtop_with_pagetable:
	if (!(*pgd & _PAGE_PRESENT))
		goto no_kpage;

	/* If the VM is in 5-level page table */
	if (machdep->flags & VM_5LEVEL) {
		ulong p4d_pte;
		/*
		 *  p4d = p4d_offset(pgd, address);
		 */
		p4d_pte = x86_64_p4d_offset(*pgd, kvaddr, verbose, FALSE);
		if (!(p4d_pte & _PAGE_PRESENT))
			goto no_kpage;
		/*
		 *  pud = pud_offset(p4d, address);
		 */
		pud_pte = x86_64_pud_offset(p4d_pte, kvaddr, verbose, FALSE);
	} else {
		pud_pte = x86_64_pud_offset(*pgd, kvaddr, verbose, FALSE);
	}

	if (!(pud_pte & _PAGE_PRESENT))
		goto no_kpage;

	if (pud_pte & _PAGE_PSE) {
		if (verbose) {
			fprintf(fp, "  PAGE: %lx  (1GB)\n\n",
			       PAGEBASE(pud_pte) & PHYSICAL_PAGE_MASK);
			x86_64_translate_pte(pud_pte, 0, 0);
		}

		physpage = (PAGEBASE(pud_pte) & PHYSICAL_PAGE_MASK) +
			       (kvaddr & ~_1GB_PAGE_MASK);
		*paddr = physpage;
		return TRUE;
	}

	/*
         *  pmd = pmd_offset(pud, address);
	 */
	pmd_pte = x86_64_pmd_offset(pud_pte, kvaddr, verbose, FALSE);
	if (!(pmd_pte & _PAGE_PRESENT))
		goto no_kpage;
	if (pmd_pte & _PAGE_PSE) {
		if (verbose) {
			fprintf(fp, "  PAGE: %lx  (2MB)\n\n", 
				PAGEBASE(pmd_pte) & PHYSICAL_PAGE_MASK);
                       	x86_64_translate_pte(pmd_pte, 0, 0);
                }

                physpage = (PAGEBASE(pmd_pte) & PHYSICAL_PAGE_MASK) + 
			(kvaddr & ~_2MB_PAGE_MASK);
                *paddr = physpage;
                return TRUE;
	}

	/*
	 *  ptep = pte_offset_map(pmd, addr);
	 *  pte = *ptep;
	 */
	pte = x86_64_pte_offset(pmd_pte, kvaddr, verbose, FALSE);
        if (!(pte & (_PAGE_PRESENT))) {
                if (pte && verbose) {
                        fprintf(fp, "\n");
                        x86_64_translate_pte(pte, 0, 0);
                }
                goto no_kpage;
        }

        *paddr = (PAGEBASE(pte) & PHYSICAL_PAGE_MASK) + PAGEOFFSET(kvaddr);

        if (verbose) {
                fprintf(fp, "  PAGE: %lx\n\n", 
			PAGEBASE(*paddr) & PHYSICAL_PAGE_MASK);
                x86_64_translate_pte(pte, 0, 0);
        }

        return TRUE;

no_kpage:
        return FALSE;
}

static int
x86_64_kvtop_xen_wpt(struct task_context *tc, ulong kvaddr, physaddr_t *paddr, int verbose)
{
        ulong *pgd;
	ulong pud_pte;
	ulong pmd_pte;
	ulong pseudo_pmd_pte;
	ulong pte;
	ulong pseudo_pte;
	physaddr_t physpage;
	char buf[BUFSIZE];

 	/*	
	 *  pgd = pgd_offset_k(addr);
	 */
	pgd = x86_64_kpgd_offset(kvaddr, verbose, TRUE);
	if (!(*pgd & _PAGE_PRESENT))
		goto no_kpage;

	pud_pte = x86_64_pud_offset(*pgd, kvaddr, verbose, TRUE);
	if (!(pud_pte & _PAGE_PRESENT))
		goto no_kpage;

	/*
	 *  pmd = pmd_offset(pgd, addr); 
	 */
	pmd_pte = x86_64_pmd_offset(pud_pte, kvaddr, verbose, TRUE);
	if (!(pmd_pte & _PAGE_PRESENT))
		goto no_kpage;
	if (pmd_pte & _PAGE_PSE) {
		if (verbose)
			fprintf(fp, "  PAGE: %lx  (2MB) [machine]\n", 
				PAGEBASE(pmd_pte) & PHYSICAL_PAGE_MASK);

                pseudo_pmd_pte = xen_m2p(PAGEBASE(pmd_pte));

                if (pseudo_pmd_pte == XEN_MACHADDR_NOT_FOUND) {
                        if (verbose)
                                fprintf(fp, " PAGE: page not available\n");
                        *paddr = PADDR_NOT_AVAILABLE;
                        return FALSE;
                }

                pseudo_pmd_pte |= PAGEOFFSET(pmd_pte);

                if (verbose) {
                        fprintf(fp, " PAGE: %s  (2MB)\n\n",
                                mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX,
                                MKSTR(PAGEBASE(pseudo_pmd_pte) &
                                PHYSICAL_PAGE_MASK)));

                        x86_64_translate_pte(pseudo_pmd_pte, 0, 0);
                }

                physpage = (PAGEBASE(pseudo_pmd_pte) & PHYSICAL_PAGE_MASK) +
                        (kvaddr & ~_2MB_PAGE_MASK);

                *paddr = physpage;
                return TRUE;
	}

	/*
	 *  ptep = pte_offset_map(pmd, addr);
	 *  pte = *ptep;
	 */
	pte = x86_64_pte_offset(pmd_pte, kvaddr, verbose, TRUE);
        if (!(pte & (_PAGE_PRESENT))) {
                if (pte && verbose) {
                        fprintf(fp, "\n");
                        x86_64_translate_pte(pte, 0, 0);
                }
                goto no_kpage;
        }

	pseudo_pte = xen_m2p(pte & PHYSICAL_PAGE_MASK);
	if (verbose)
                fprintf(fp, "   PTE: %lx\n", pseudo_pte + PAGEOFFSET(pte));

        *paddr = (PAGEBASE(pseudo_pte) & PHYSICAL_PAGE_MASK) + PAGEOFFSET(kvaddr);

        if (verbose) {
                fprintf(fp, "  PAGE: %lx [machine]\n", 
			PAGEBASE(pte) & PHYSICAL_PAGE_MASK);
                fprintf(fp, "  PAGE: %lx\n\n", 
			PAGEBASE(*paddr) & PHYSICAL_PAGE_MASK);
                x86_64_translate_pte(pseudo_pte + PAGEOFFSET(pte), 0, 0);
        }

        return TRUE;

no_kpage:
        return FALSE;
}


/*
 *  Determine where vmalloc'd memory starts.
 */
static ulong
x86_64_vmalloc_start(void)
{
	return ((ulong)VMALLOC_START);
}

/*
 *  thread_info implementation makes for less accurate results here.
 */
static int
x86_64_is_task_addr(ulong task)
{
        if (tt->flags & THREAD_INFO)
                return IS_KVADDR(task);
        else
                return (IS_KVADDR(task) && (ALIGNED_STACK_OFFSET(task) == 0));
}


/*
 *  easy enough...
 */
static ulong
x86_64_processor_speed(void)
{
        unsigned long cpu_khz = 0;

        if (machdep->mhz)
                return (machdep->mhz);

        if (symbol_exists("cpu_khz")) {
                get_symbol_data("cpu_khz", sizeof(int), &cpu_khz);
                if (cpu_khz)
                        return(machdep->mhz = cpu_khz/1000);
        }

        return 0;
}


/*
 *  Accept or reject a symbol from the kernel namelist.
 */
static int
x86_64_verify_symbol(const char *name, ulong value, char type)
{
	if (!name || !strlen(name))
		return FALSE;

	if (XEN_HYPER_MODE() && STREQ(name, "__per_cpu_shift"))
		return TRUE;

	if (!(machdep->flags & KSYMS_START)) {
		if (STREQ(name, "_text") || STREQ(name, "_stext")) {
			machdep->flags |= KSYMS_START;
			if (!st->first_ksymbol)
				st->first_ksymbol = value;
			return TRUE;
		} else if (STREQ(name, "__per_cpu_start")) {
			st->flags |= PERCPU_SYMS;
			return TRUE;
		} else if (st->flags & PERCPU_SYMS) {
			if (STRNEQ(name, "per_cpu") || 
			    STREQ(name, "__per_cpu_end"))
				return TRUE;
			if ((type == 'V') || (type == 'd') || (type == 'D'))
				return TRUE;
		}

		return FALSE;
	}

	return TRUE;
}


/*
 *  Prevent base kernel pc section ranges that end with a
 *  vsyscall address from being accepted for kernel module
 *  addresses.
 */
static int 
x86_64_verify_line_number(ulong pc, ulong low, ulong high)
{
	if (IS_MODULE_VADDR(pc) && 
	    !IS_MODULE_VADDR(low) && is_vsyscall_addr(high))
		return FALSE;

	return TRUE;
}

/*
 *  Get the relevant page directory pointer from a task structure.
 */
static ulong
x86_64_get_task_pgd(ulong task)
{
	return (error(FATAL, "x86_64_get_task_pgd: N/A\n"));
}


/*
 *  Translate a PTE, returning TRUE if the page is present.
 *  If a physaddr pointer is passed in, don't print anything.
 */
static int
x86_64_translate_pte(ulong pte, void *physaddr, ulonglong unused)
{
	int c, others, len1, len2, len3;
	ulong paddr;
	char buf[BUFSIZE];
        char buf2[BUFSIZE];
        char buf3[BUFSIZE];
	char ptebuf[BUFSIZE];
	char physbuf[BUFSIZE];
        char *arglist[MAXARGS];
	int page_present;

        paddr = pte & PHYSICAL_PAGE_MASK;
        page_present = pte & (_PAGE_PRESENT | _PAGE_PROTNONE);

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
		if (pte & _PAGE_PRESENT)
			fprintf(fp, "%sPRESENT", others++ ? "|" : "");
		if (pte & _PAGE_RW)
			fprintf(fp, "%sRW", others++ ? "|" : "");
		if (pte & _PAGE_USER)
			fprintf(fp, "%sUSER", others++ ? "|" : "");
		if (pte & _PAGE_PWT)
			fprintf(fp, "%sPWT", others++ ? "|" : "");
		if (pte & _PAGE_PCD)
			fprintf(fp, "%sPCD", others++ ? "|" : "");
		if (pte & _PAGE_ACCESSED)
			fprintf(fp, "%sACCESSED", others++ ? "|" : "");
		if (pte & _PAGE_DIRTY)
			fprintf(fp, "%sDIRTY", others++ ? "|" : "");
		if ((pte & _PAGE_PSE) && (pte & _PAGE_PRESENT))
			fprintf(fp, "%sPSE", others++ ? "|" : "");
		if ((pte & _PAGE_PROTNONE) && !(pte & _PAGE_PRESENT))
			fprintf(fp, "%sPROTNONE", others++ ? "|" : "");
		if (pte & _PAGE_GLOBAL)
			fprintf(fp, "%sGLOBAL", others++ ? "|" : "");
		if (pte & _PAGE_NX)
			fprintf(fp, "%sNX", others++ ? "|" : "");
	} else {
                fprintf(fp, "no mapping");
        }

        fprintf(fp, ")\n");

	return (page_present);
}


/*
 *  Look for likely exception frames in a stack.
 */
static int 
x86_64_eframe_search(struct bt_info *bt)
{
	int i, c, cnt, estack_index;
        ulong estack, irqstack, stacksize;
	ulong *up;
        struct machine_specific *ms;
	struct bt_info bt_local;

	if (bt->flags & BT_EFRAME_SEARCH2) {
		BCOPY(bt, &bt_local, sizeof(struct bt_info));
		bt->flags &= ~(ulonglong)BT_EFRAME_SEARCH2;

        	ms = machdep->machspec;

        	for (c = 0; c < kt->cpus; c++) {
			if ((bt->flags & BT_CPUMASK) && 
			    !(NUM_IN_BITMAP(bt->cpumask, c)))
				continue;
                	if (ms->stkinfo.ibase[c] == 0)
                        	break;
                        bt->hp->esp = ms->stkinfo.ibase[c];
                        fprintf(fp, "CPU %d IRQ STACK:", c);

			if (hide_offline_cpu(c)) {
				fprintf(fp, " [OFFLINE]\n\n");
				continue;
			} else
				fprintf(fp, "\n");

                        if ((cnt = x86_64_eframe_search(bt)))
				fprintf(fp, "\n");
			else
                                fprintf(fp, "(none found)\n\n");
                }

        	for (c = 0; c < kt->cpus; c++) {
			if ((bt->flags & BT_CPUMASK) && 
			    !(NUM_IN_BITMAP(bt->cpumask, c)))
				continue;
                	for (i = 0; i < MAX_EXCEPTION_STACKS; i++) {
				if (ms->stkinfo.ebase[c][i] == 0 ||
				    !ms->stkinfo.available[c][i])
                                	break;
                                bt->hp->esp = ms->stkinfo.ebase[c][i];
                                fprintf(fp, "CPU %d %s EXCEPTION STACK:",
					c, ms->stkinfo.exception_stacks[i]);

				if (hide_offline_cpu(c)) {
					fprintf(fp, " [OFFLINE]\n\n");
					continue;
				} else
					fprintf(fp, "\n");

                                if ((cnt = x86_64_eframe_search(bt)))
					fprintf(fp, "\n");
				else
                                        fprintf(fp, "(none found)\n\n");
                	}
        	}

		return 0;
        }

        if (bt->hp && bt->hp->esp) {
        	ms = machdep->machspec;
		bt->stkptr = bt->hp->esp;
		if ((estack = x86_64_in_exception_stack(bt, &estack_index))) {
			stacksize = ms->stkinfo.esize[estack_index];
			bt->stackbase = estack;
			bt->stacktop = estack + ms->stkinfo.esize[estack_index];
                	bt->stackbuf = ms->irqstack;
                	alter_stackbuf(bt);
		} else if ((irqstack = x86_64_in_irqstack(bt))) {
			stacksize = ms->stkinfo.isize;
			bt->stackbase = irqstack;
			bt->stacktop = irqstack + ms->stkinfo.isize;
                	bt->stackbuf = ms->irqstack;
                	alter_stackbuf(bt);
		} else if (!INSTACK(bt->stkptr, bt))
			error(FATAL, 
			    "unrecognized stack address for this task: %lx\n",
				bt->hp->esp);
	} 

	stacksize = bt->stacktop - bt->stackbase - SIZE(pt_regs);

	if (bt->stkptr)
		i = (bt->stkptr - bt->stackbase)/sizeof(ulong);
	else
		i = 0;

	for (cnt = 0; i <= stacksize/sizeof(ulong); i++) {
		up = (ulong *)(&bt->stackbuf[i*sizeof(ulong)]);

                if (x86_64_exception_frame(EFRAME_SEARCH|EFRAME_PRINT|
		    EFRAME_VERIFY, 0, (char *)up, bt, fp)) 
			cnt++;
	}

	return cnt;
}

static void
x86_64_display_full_frame(struct bt_info *bt, ulong rsp, FILE *ofp)
{
	int i, u_idx;
	ulong *up;
	ulong words, addr;
	char buf[BUFSIZE];

	if (rsp < bt->frameptr)
		return;

	if (!INSTACK(rsp, bt) || !INSTACK(bt->frameptr, bt))
		return;

        words = (rsp - bt->frameptr) / sizeof(ulong) + 1;

	addr = bt->frameptr;
	u_idx = (bt->frameptr - bt->stackbase)/sizeof(ulong);
	for (i = 0; i < words; i++, u_idx++) {
		if (!(i & 1)) 
			fprintf(ofp, "%s    %lx: ", i ? "\n" : "", addr);
		
		up = (ulong *)(&bt->stackbuf[u_idx*sizeof(ulong)]);
		fprintf(ofp, "%s ", format_stack_entry(bt, buf, *up, 0));
		addr += sizeof(ulong);
	}
	fprintf(ofp, "\n");
}

/*
 *  Check a frame for a requested reference.
 */
static void
x86_64_do_bt_reference_check(struct bt_info *bt, ulong text, char *name)
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
 *  Determine the function containing a .text.lock. reference.
 */
static ulong
text_lock_function(char *name, struct bt_info *bt, ulong locktext)
{
	int c, reterror, instr, arg;
	char buf[BUFSIZE];
	char *arglist[MAXARGS];
	char *p1;
	ulong locking_func;
	
	instr = arg = -1;
	locking_func = 0;

        open_tmpfile2();

	if (STREQ(name, ".text.lock.spinlock"))
        	sprintf(buf, "x/4i 0x%lx", locktext);
	else
        	sprintf(buf, "x/1i 0x%lx", locktext);

        if (!gdb_pass_through(buf, pc->tmpfile2, GNU_RETURN_ON_ERROR)) {
                close_tmpfile2();
                bt->flags |= BT_FRAMESIZE_DISABLE;
                return 0;
        }

        rewind(pc->tmpfile2);
        while (fgets(buf, BUFSIZE, pc->tmpfile2)) {
                c = parse_line(buf, arglist);

                if (instr == -1) {
                        /*
                         *  Check whether <function+offset> are
                         *  in the output string.
                         */
                        if (LASTCHAR(arglist[0]) == ':') {
                                instr = 1;
                                arg = 2;
                        } else {
                                instr = 2;
                                arg = 3;
                        }
                }

                if (c < (arg+1))
                        break;

		if (STREQ(arglist[instr], "jmpq") || STREQ(arglist[instr], "jmp")) {
                        p1 = arglist[arg];
                        reterror = 0;
                        locking_func = htol(p1, RETURN_ON_ERROR, &reterror);
                        if (reterror)
				locking_func = 0;
			break;
                }
	}
	close_tmpfile2();

	if (!locking_func)
                bt->flags |= BT_FRAMESIZE_DISABLE;

	return locking_func;

}

/*
 * As of 2.6.29, the handy check for the "error_exit:" label
 * no longer applies; it became an entry point that was jmp'd to 
 * after the exception handler was called.  Therefore, if the 
 * return address is an offset from any of these functions, 
 * then the exception frame should be checked for:
 *
 * .macro errorentry sym do_sym
 * errorentry invalid_TSS do_invalid_TSS
 * errorentry segment_not_present do_segment_not_present
 * errorentry alignment_check do_alignment_check
 * errorentry xen_stack_segment do_stack_segment
 * errorentry general_protection do_general_protection
 * errorentry page_fault do_page_fault
 *
 * .macro zeroentry sym do_sym
 * zeroentry divide_error do_divide_error
 * zeroentry overflow do_overflow
 * zeroentry bounds do_bounds
 * zeroentry invalid_op do_invalid_op
 * zeroentry device_not_available do_device_not_available
 * zeroentry coprocessor_segment_overrun do_coprocessor_segment_overrun
 * zeroentry spurious_interrupt_bug do_spurious_interrupt_bug
 * zeroentry coprocessor_error do_coprocessor_error
 * zeroentry simd_coprocessor_error do_simd_coprocessor_error
 * zeroentry xen_hypervisor_callback xen_do_hypervisor_callback
 * zeroentry xen_debug do_debug
 * zeroentry xen_int3 do_int3
*/
static const char *exception_functions_orig[] = {
	"invalid_TSS",
	"segment_not_present",
	"alignment_check",
	"xen_stack_segment",
	"general_protection",
	"page_fault",
	"divide_error",
	"overflow",
	"bounds",
	"invalid_op",
	"device_not_available",
	"coprocessor_segment_overrun",
	"spurious_interrupt_bug",
	"coprocessor_error",
	"simd_coprocessor_error",
	"xen_hypervisor_callback",
	"xen_debug",
	"xen_int3",
	"async_page_fault",
	NULL,
};

static const char *exception_functions_5_8[] = {
	"asm_exc_invalid_tss",
	"asm_exc_segment_not_present",
	"asm_exc_alignment_check",
	"asm_exc_general_protection",
	"asm_exc_page_fault",
	"asm_exc_divide_error",
	"asm_exc_overflow",
	"asm_exc_bounds",
	"asm_exc_invalid_op",
	"asm_exc_device_not_available",
	"asm_exc_coproc_segment_overrun",
	"asm_exc_spurious_interrupt_bug",
	"asm_exc_coprocessor_error",
	"asm_exc_simd_coprocessor_error",
	"asm_exc_debug",
	"xen_asm_exc_stack_segment",
	"xen_asm_exc_xen_hypervisor_callback",
	"xen_asm_exc_int3",
	NULL,
};

/*
 *  print one entry of a stack trace
 */
#define BACKTRACE_COMPLETE                   (1)
#define BACKTRACE_ENTRY_IGNORED              (2)
#define BACKTRACE_ENTRY_DISPLAYED            (3)
#define BACKTRACE_ENTRY_AND_EFRAME_DISPLAYED (4)

static int
x86_64_print_stack_entry(struct bt_info *bt, FILE *ofp, int level, 
	int stkindex, ulong text)
{
	ulong rsp, offset, locking_func;
	struct syment *sp, *spl;
	char *name, *name_plus_offset;
	int i, result; 
	long eframe_check;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	struct load_module *lm;

	eframe_check = -1;
	if (!(bt->flags & BT_SAVE_EFRAME_IP))
		bt->eframe_ip = 0;
	offset = 0;
	sp = value_search(text, &offset);
	if (!sp)
		return BACKTRACE_ENTRY_IGNORED;

	name = sp->name;

	if (offset && (bt->flags & BT_SYMBOL_OFFSET))
		name_plus_offset = value_to_symstr(text, buf2, bt->radix);
	else
		name_plus_offset = NULL;

	if (bt->flags & BT_TEXT_SYMBOLS) {
		if (bt->flags & BT_EXCEPTION_FRAME)
			rsp = bt->stkptr;
		else
			rsp = bt->stackbase + (stkindex * sizeof(long));
                fprintf(ofp, "  [%s] %s at %lx",
                	mkstring(buf1, VADDR_PRLEN, RJUST|LONG_HEX, MKSTR(rsp)),
			name_plus_offset ? name_plus_offset : name, text);
		if (module_symbol(text, NULL, &lm, NULL, 0))
			fprintf(ofp, " [%s]", lm->mod_name);
		fprintf(ofp, "\n");
		if (BT_REFERENCE_CHECK(bt))
			x86_64_do_bt_reference_check(bt, text, name);
		return BACKTRACE_ENTRY_DISPLAYED;
	}

	if (!offset && !(bt->flags & BT_EXCEPTION_FRAME) &&
	    !(bt->flags & BT_START)) { 
		if (STREQ(name, "child_rip")) {
			if (symbol_exists("kernel_thread"))
				name = "kernel_thread";
			else if (symbol_exists("arch_kernel_thread"))
				name = "arch_kernel_thread";
		}
		else if (!(bt->flags & BT_SCHEDULE)) {
			if (STREQ(name, "error_exit")) 
				eframe_check = 8;
			else {
				if (CRASHDEBUG(2))
					fprintf(ofp, 
		              "< ignoring text symbol with no offset: %s() >\n",
						sp->name);
				return BACKTRACE_ENTRY_IGNORED;
			}
		}
	}

	if ((THIS_KERNEL_VERSION >= LINUX(2,6,29)) && 
	    (eframe_check == -1) && offset && 
	    !(bt->flags & (BT_EXCEPTION_FRAME|BT_START|BT_SCHEDULE))) { 
		for (i = 0; machdep->machspec->exception_functions[i]; i++) {
			if (STREQ(name, machdep->machspec->exception_functions[i])) {
				eframe_check = 8;
				break;
			}
		}
		if (x86_64_in_irqstack(bt) && strstr(name, "_interrupt"))
			eframe_check = 0;
	}

	if (bt->flags & BT_SCHEDULE)
		name = "schedule";

        if (STREQ(name, "child_rip")) {
                if (symbol_exists("kernel_thread"))
                        name = "kernel_thread";
                else if (symbol_exists("arch_kernel_thread"))
                        name = "arch_kernel_thread";
		result = BACKTRACE_COMPLETE;
        } else if (STREQ(name, "cpu_idle") || 
	    STREQ(name, "system_call_fastpath"))
		result = BACKTRACE_COMPLETE;
	else
		result = BACKTRACE_ENTRY_DISPLAYED;

	if (bt->flags & BT_EXCEPTION_FRAME)
		rsp = bt->stkptr;
	else if (bt->flags & BT_START)
		rsp = bt->stkptr;
	else
		rsp = bt->stackbase + (stkindex * sizeof(long));

	if ((bt->flags & BT_FULL)) {
		if (bt->frameptr) 
			x86_64_display_full_frame(bt, rsp, ofp);
		bt->frameptr = rsp + sizeof(ulong);
	}

       	fprintf(ofp, "%s#%d [%8lx] %s at %lx", level < 10 ? " " : "", level,
		rsp, name_plus_offset ? name_plus_offset : name, text);

	if (STREQ(name, "tracesys"))
		fprintf(ofp, " (via system_call)");
	else if (STRNEQ(name, ".text.lock.")) {
		if ((locking_func = text_lock_function(name, bt, text)) &&
		    (spl = value_search(locking_func, &offset)))
			fprintf(ofp, " (via %s)", spl->name);
	}
	if (module_symbol(text, NULL, &lm, NULL, 0))
		fprintf(ofp, " [%s]", lm->mod_name);

	if (bt->flags & BT_FRAMESIZE_DISABLE)
		fprintf(ofp, " *");

	fprintf(ofp, "\n");

        if (bt->flags & BT_LINE_NUMBERS) {
                get_line_number(text, buf1, FALSE);
                if (strlen(buf1))
                        fprintf(ofp, "    %s\n", buf1);
	}

	if (eframe_check >= 0) {
		if (x86_64_exception_frame(EFRAME_PRINT|EFRAME_VERIFY, 
		    bt->stackbase + (stkindex*sizeof(long)) + eframe_check,
		    NULL, bt, ofp))
			result = BACKTRACE_ENTRY_AND_EFRAME_DISPLAYED;
	}

	if (BT_REFERENCE_CHECK(bt))
		x86_64_do_bt_reference_check(bt, text, name);

	bt->call_target = name;

	if (is_direct_call_target(bt)) {
		if (CRASHDEBUG(2))
			fprintf(ofp, "< enable BT_CHECK_CALLER for %s >\n", 
				bt->call_target);
		bt->flags |= BT_CHECK_CALLER;
	} else {
		if (CRASHDEBUG(2) && (bt->flags & BT_CHECK_CALLER))
			fprintf(ofp, "< disable BT_CHECK_CALLER for %s >\n", 
				bt->call_target);
		if (bt->flags & BT_CHECK_CALLER) {
			if (CRASHDEBUG(2))
			    	fprintf(ofp, "< set BT_NO_CHECK_CALLER >\n");
			bt->flags |= BT_NO_CHECK_CALLER;
		}
		bt->flags &= ~(ulonglong)BT_CHECK_CALLER;
	}

	return result;
}

/*
 *  Unroll a kernel stack.
 */
static void
x86_64_back_trace_cmd(struct bt_info *bt)
{
	error(FATAL, "x86_64_back_trace_cmd: TBD\n");
}



/*
 *  Determine whether the initial stack pointer is located in one of the
 *  exception stacks.
 */
static ulong
x86_64_in_exception_stack(struct bt_info *bt, int *estack_index) 
{
	int c, i;
	ulong rsp;
	ulong estack;
	struct machine_specific *ms;

	rsp = bt->stkptr;
	ms = machdep->machspec;
	estack = 0;

        for (c = 0; !estack && (c < kt->cpus); c++) {
		for (i = 0; i < MAX_EXCEPTION_STACKS; i++) {
			if (ms->stkinfo.ebase[c][i] == 0 ||
			    !ms->stkinfo.available[c][i])
				break;
			if ((rsp >= ms->stkinfo.ebase[c][i]) &&
			    (rsp < (ms->stkinfo.ebase[c][i] + 
			    ms->stkinfo.esize[i]))) {
				estack = ms->stkinfo.ebase[c][i]; 
				if (estack_index)
					*estack_index = i;
				if (CRASHDEBUG(1) && (c != bt->tc->processor)) 
					error(INFO, 
      		                      "task cpu: %d  exception stack cpu: %d\n",
						bt->tc->processor, c);
				break;
			}
		}
        }

	return estack;
}

/*
 *  Determine whether the current stack pointer is in a cpu's irqstack.
 */
static ulong
x86_64_in_irqstack(struct bt_info *bt) 
{
        int c;
        ulong rsp;
        ulong irqstack;
        struct machine_specific *ms;

        rsp = bt->stkptr;
        ms = machdep->machspec;
        irqstack = 0;

        for (c = 0; !irqstack && (c < kt->cpus); c++) {
                if (ms->stkinfo.ibase[c] == 0)
                 	break;
                if ((rsp >= ms->stkinfo.ibase[c]) &&
                    (rsp < (ms->stkinfo.ibase[c] + ms->stkinfo.isize))) {
                	irqstack = ms->stkinfo.ibase[c];
                        if (CRASHDEBUG(1) && (c != bt->tc->processor)) 
                                error(INFO, 
			          "task cpu: %d  IRQ stack cpu: %d\n",
                                	bt->tc->processor, c);
                        break;
                }
        }

        return irqstack;
}

static int 
x86_64_in_alternate_stack(int cpu, ulong rsp)
{
	int i;
	struct machine_specific *ms;

	if (cpu >= NR_CPUS)
		return FALSE;

	ms = machdep->machspec;

	if (ms->stkinfo.ibase[cpu] &&
	    (rsp >= ms->stkinfo.ibase[cpu]) &&
	    (rsp < (ms->stkinfo.ibase[cpu] + ms->stkinfo.isize)))
		return TRUE;

	for (i = 0; i < MAX_EXCEPTION_STACKS; i++) {
		if (ms->stkinfo.ebase[cpu][i] &&
		    (rsp >= ms->stkinfo.ebase[cpu][i]) &&
		    (rsp < (ms->stkinfo.ebase[cpu][i] + ms->stkinfo.esize[i])))
			return TRUE;
	}

	return FALSE;
}

static char *
x86_64_exception_RIP_message(struct bt_info *bt, ulong rip)
{
	physaddr_t phys;
	
	if (IS_VMALLOC_ADDR(rip) && 
	    machdep->kvtop(bt->tc, rip, &phys, 0))
		return ("no symbolic reference");
 
	return ("unknown or invalid address");
}

#define STACK_TRANSITION_ERRMSG_E_I_P \
"cannot transition from exception stack to IRQ stack to current process stack:\n    exception stack pointer: %lx\n          IRQ stack pointer: %lx\n      process stack pointer: %lx\n         current stack base: %lx\n" 
#define STACK_TRANSITION_ERRMSG_E_P \
"cannot transition from exception stack to current process stack:\n    exception stack pointer: %lx\n      process stack pointer: %lx\n         current stack base: %lx\n"
#define STACK_TRANSITION_ERRMSG_I_P \
"cannot transition from IRQ stack to current process stack:\n        IRQ stack pointer: %lx\n    process stack pointer: %lx\n       current stack base: %lx\n"

/*
 *  Low-budget back tracer -- dump text return addresses, following call chain
 *  when possible, along with any verifiable exception frames.
 */
static void
x86_64_low_budget_back_trace_cmd(struct bt_info *bt_in)
{
	int i, level, done, framesize, estack_index;
	ulong rsp, offset, stacktop;
	ulong *up;
	long cs;
	struct syment *sp, *spt;
	FILE *ofp;
	ulong estack, irqstack;
	ulong irq_eframe, kpti_eframe;
	struct bt_info bt_local, *bt;
	struct machine_specific *ms;
	ulong last_process_stack_eframe;
	ulong user_mode_eframe;
	char *rip_symbol;

        /*
         *  User may have made a run-time switch.
         */
	if (kt->flags & DWARF_UNWIND) {
		machdep->back_trace = x86_64_dwarf_back_trace_cmd;
		x86_64_dwarf_back_trace_cmd(bt_in);
		return;
	}

	bt = &bt_local;
	BCOPY(bt_in, bt, sizeof(struct bt_info));

	if (bt->flags & BT_FRAMESIZE_DEBUG) {
		x86_64_framesize_debug(bt);
		return;
	}

	level = 0;
	done = FALSE;
	irq_eframe = 0;
	last_process_stack_eframe = 0;
	bt->call_target = NULL;
	rsp = bt->stkptr;
	ms = machdep->machspec;

	if (BT_REFERENCE_CHECK(bt))
		ofp = pc->nullfp;
	else
		ofp = fp;

	/* If rsp is in user stack, the memory may not be included in vmcore, and
	 * we only output the register's value. So it's not necessary to check
	 * whether it can be accessible.
	 */
	if (!(bt->flags & BT_USER_SPACE) && (!rsp || !accessible(rsp))) {
		error(INFO, "cannot determine starting stack pointer\n");
		if (KVMDUMP_DUMPFILE())
			kvmdump_display_regs(bt->tc->processor, ofp);
		else if (ELF_NOTES_VALID() && DISKDUMP_DUMPFILE())
			diskdump_display_regs(bt->tc->processor, ofp);
		else if (SADUMP_DUMPFILE())
			sadump_display_regs(bt->tc->processor, ofp);
		else if (VMSS_DUMPFILE())
			vmware_vmss_display_regs(bt->tc->processor, ofp);
		return;
	}

        if (bt->flags & BT_TEXT_SYMBOLS) {
		if ((bt->flags & BT_USER_SPACE) &&
		    !(bt->flags & BT_TEXT_SYMBOLS_ALL))
			return;
		if (!(bt->flags & BT_TEXT_SYMBOLS_ALL))
                	fprintf(ofp, "%sSTART: %s%s at %lx\n",
                	    space(VADDR_PRLEN > 8 ? 14 : 6),
                	    closest_symbol(bt->instptr), 
			    STREQ(closest_symbol(bt->instptr), "thread_return") ?
			    " (schedule)" : "",
			    bt->instptr);
	} else if (bt->flags & BT_USER_SPACE) {
		fprintf(ofp, "    [exception RIP: user space]\n");
		if (KVMDUMP_DUMPFILE())
			kvmdump_display_regs(bt->tc->processor, ofp);
		else if (ELF_NOTES_VALID() && DISKDUMP_DUMPFILE())
			diskdump_display_regs(bt->tc->processor, ofp);
		else if (SADUMP_DUMPFILE())
			sadump_display_regs(bt->tc->processor, ofp);
		else if (VMSS_DUMPFILE())
			vmware_vmss_display_regs(bt->tc->processor, ofp);
		else if (pc->flags2 & QEMU_MEM_DUMP_ELF)
			display_regs_from_elf_notes(bt->tc->processor, ofp);
		return;
	} else if ((bt->flags & BT_KERNEL_SPACE) &&
		   (KVMDUMP_DUMPFILE() ||
		    (ELF_NOTES_VALID() && DISKDUMP_DUMPFILE()) ||
		    SADUMP_DUMPFILE() || (pc->flags2 & QEMU_MEM_DUMP_ELF) ||
		    VMSS_DUMPFILE())) {
		fprintf(ofp, "    [exception RIP: ");
		if ((sp = value_search(bt->instptr, &offset))) {
			fprintf(ofp, "%s", sp->name);
			if (offset)
				fprintf(ofp, (*gdb_output_radix == 16) ?
					"+0x%lx" : "+%ld", offset);
		} else
			fprintf(ofp, "%s", x86_64_exception_RIP_message(bt, bt->instptr));
		fprintf(ofp, "]\n");
		if (KVMDUMP_DUMPFILE())
			kvmdump_display_regs(bt->tc->processor, ofp);
		else if (ELF_NOTES_VALID() && DISKDUMP_DUMPFILE())
			diskdump_display_regs(bt->tc->processor, ofp);
		else if (SADUMP_DUMPFILE())
			sadump_display_regs(bt->tc->processor, ofp);
		else if (VMSS_DUMPFILE())
			vmware_vmss_display_regs(bt->tc->processor, ofp);
		else if (pc->flags2 & QEMU_MEM_DUMP_ELF)
			display_regs_from_elf_notes(bt->tc->processor, ofp);

        } else if (bt->flags & BT_START) {
                x86_64_print_stack_entry(bt, ofp, level,
                        0, bt->instptr);
		bt->flags &= ~BT_START;
		level++;
	}


        if ((estack = x86_64_in_exception_stack(bt, &estack_index))) {
in_exception_stack:
		bt->flags |= BT_EXCEPTION_STACK;
		/*
	 	 *  The stack buffer will have been loaded with the process
		 *  stack, so switch to the indicated exception stack.
		 */
                bt->stackbase = estack;
                bt->stacktop = estack + ms->stkinfo.esize[estack_index];
                bt->stackbuf = ms->irqstack;

                if (!readmem(bt->stackbase, KVADDR, bt->stackbuf,
                    bt->stacktop - bt->stackbase,
		    bt->hp && (bt->hp->esp == bt->stkptr) ? 
	 	    "irqstack contents via hook" : "irqstack contents", 
		    RETURN_ON_ERROR))
                    	error(FATAL, "read of exception stack at %lx failed\n",
                        	bt->stackbase);

		/*
	 	 *  If irq_eframe is set, we've jumped back here from the
		 *  IRQ stack dump below.  Do basically the same thing as if
		 *  had come from the processor stack, but presume that we
		 *  must have been in kernel mode, i.e., took an exception
	 	 *  while operating on an IRQ stack.  (untested)
		 */
                if (irq_eframe) {
                        bt->flags |= BT_EXCEPTION_FRAME;
                        i = (irq_eframe - bt->stackbase)/sizeof(ulong);
                        x86_64_print_stack_entry(bt, ofp, level, i, 
				bt->instptr);
                        bt->flags &= ~(ulonglong)BT_EXCEPTION_FRAME;
                        cs = x86_64_exception_frame(EFRAME_PRINT|EFRAME_CS, 0,
                        	bt->stackbuf + (irq_eframe - bt->stackbase), 
				bt, ofp);
                        rsp += SIZE(pt_regs);  /* guaranteed kernel mode */
			if (bt->eframe_ip && ((framesize = x86_64_get_framesize(bt, 
			    bt->eframe_ip, rsp, NULL)) >= 0))
				rsp += framesize;
                        level++;
                        irq_eframe = 0;
                }

		stacktop = bt->stacktop - SIZE(pt_regs);
		if ((machdep->flags & NESTED_NMI) && estack_index == NMI_STACK)
			stacktop -= 12*sizeof(ulong);

		bt->flags &= ~BT_FRAMESIZE_DISABLE;

        	for (i = (rsp - bt->stackbase)/sizeof(ulong);
	     	    !done && (rsp < stacktop); i++, rsp += sizeof(ulong)) {

			up = (ulong *)(&bt->stackbuf[i*sizeof(ulong)]);

			if (!is_kernel_text(*up))
		        	continue;

	                switch (x86_64_print_stack_entry(bt, ofp, level, i,*up))
	                {
	                case BACKTRACE_ENTRY_AND_EFRAME_DISPLAYED:
				rsp += SIZE(pt_regs);
				i += SIZE(pt_regs)/sizeof(ulong);
				if (!bt->eframe_ip) {
					level++;
					break;
				} /* else fall through */
	                case BACKTRACE_ENTRY_DISPLAYED:
	                        level++;
				if ((framesize = x86_64_get_framesize(bt, 
				    bt->eframe_ip ?  bt->eframe_ip : *up, rsp, NULL)) >= 0) {
					rsp += framesize;
					i += framesize/sizeof(ulong);
				}
	                        break;
	                case BACKTRACE_ENTRY_IGNORED:
	                        break;
	                case BACKTRACE_COMPLETE:
	                        done = TRUE;
	                        break;
	                }
		}

                cs = x86_64_exception_frame(EFRAME_PRINT|EFRAME_CS, 0, 
			bt->stackbuf + (stacktop - bt->stackbase),
			bt, ofp);

		if (!BT_REFERENCE_CHECK(bt))
			fprintf(fp, "--- <%s exception stack> ---\n",
				ms->stkinfo.exception_stacks[estack_index]);

		/*
		 * Find the CPU-saved, or handler-saved registers
		 */
		up = (ulong *)(&bt->stackbuf[bt->stacktop - bt->stackbase]);
		up -= 5;
		if ((machdep->flags & NESTED_NMI) &&
		    estack_index == NMI_STACK &&
		    bt->stkptr <= bt->stacktop - 17*sizeof(ulong)) {
			up -= 12;
			/* Copied and saved regs are swapped in pre-3.8 kernels */
			if (*up == symbol_value("repeat_nmi"))
				up += 5;
		}

		/* Registers (as saved by CPU):
		 *
		 *   up[4]	SS
		 *   up[3]	RSP
		 *   up[2]	RFLAGS
		 *   up[1]	CS
		 *   up[0]	RIP
		 */
		rsp = bt->stkptr = up[3];
		bt->instptr = up[0];
		if (cs & 3)
			done = TRUE;   /* user-mode exception */
		else
			done = FALSE;  /* kernel-mode exception */
		bt->frameptr = 0;

		/*
		 *  Print the return values from the estack end.
		 */
		if (!done) {
			bt->flags |= BT_START|BT_SAVE_EFRAME_IP;
			x86_64_print_stack_entry(bt, ofp, level,
				0, bt->instptr);
			bt->flags &= 
			    	~(BT_START|BT_SAVE_EFRAME_IP|BT_FRAMESIZE_DISABLE);

			/*
			 *  Protect against exception stack recursion.
			 */
			if (x86_64_in_exception_stack(bt, NULL) == estack) {
				fprintf(ofp, 
     				    "    [ %s exception stack recursion: "
				    "prior stack location overwritten ]\n",
					ms->stkinfo.exception_stacks[estack_index]);
				return;
			}

			level++;
			if ((framesize = x86_64_get_framesize(bt, bt->instptr, rsp, NULL)) >= 0)
				rsp += framesize;
		}
	}

	/*
	 *  IRQ stack entry always comes in via the process stack, regardless
	 *  whether it happened while running in user or kernel space.
	 */
        if (!done && (irqstack = x86_64_in_irqstack(bt))) {
		bt->flags |= BT_IRQSTACK;
		/*
		 *  Until coded otherwise, the stackbase will be pointing to
		 *  either the exception stack or, more likely, the process
		 *  stack base.  Switch it to the IRQ stack.
		 */
                bt->stackbase = irqstack;
                bt->stacktop = irqstack + ms->stkinfo.isize;
                bt->stackbuf = ms->irqstack;

                if (!readmem(bt->stackbase, KVADDR, 
	  	    bt->stackbuf, bt->stacktop - bt->stackbase,
                    bt->hp && (bt->hp->esp == bt_in->stkptr) ?
		    "irqstack contents via hook" : "irqstack contents", 
		    RETURN_ON_ERROR))
                    	error(FATAL, "read of IRQ stack at %lx failed\n",
				bt->stackbase);

		stacktop = bt->stacktop - ms->irq_stack_gap; 

		bt->flags &= ~BT_FRAMESIZE_DISABLE;

                for (i = (rsp - bt->stackbase)/sizeof(ulong);
                    !done && (rsp < stacktop); i++, rsp += sizeof(ulong)) {

                        up = (ulong *)(&bt->stackbuf[i*sizeof(ulong)]);

                        if (!is_kernel_text(*up))
                                continue;

                        switch (x86_64_print_stack_entry(bt, ofp, level, i,*up))
                        {
			case BACKTRACE_ENTRY_AND_EFRAME_DISPLAYED:
				rsp += SIZE(pt_regs);
				i += SIZE(pt_regs)/sizeof(ulong);
				if (!bt->eframe_ip) {
					level++;
					break;
				} /* else fall through */
                        case BACKTRACE_ENTRY_DISPLAYED:
                                level++;
				if ((framesize = x86_64_get_framesize(bt, 
				    bt->eframe_ip ? bt->eframe_ip : *up, rsp, NULL)) >= 0) {
					rsp += framesize;
					i += framesize/sizeof(ulong);
				}
                                break;
                        case BACKTRACE_ENTRY_IGNORED:
                                break;
                        case BACKTRACE_COMPLETE:
                                done = TRUE;
                                break;
                        }
                }

		if (!BT_REFERENCE_CHECK(bt))
                	fprintf(fp, "--- <IRQ stack> ---\n");

                /*
		 *  stack = (unsigned long *) (irqstack_end[-1]);
		 *  (where irqstack_end is 64 bytes below page end)
                 */
                up = (ulong *)(&bt->stackbuf[stacktop - bt->stackbase]);
                up -= 1;
                irq_eframe = rsp = bt->stkptr = x86_64_irq_eframe_link(*up, bt, ofp);
		up -= 1;
                bt->instptr = *up;
		/*
		 *  No exception frame when coming from do_softirq_own_stack
		 *  or call_softirq.
		 */
		if ((sp = value_search(bt->instptr, &offset)) && 
		    (STREQ(sp->name, "do_softirq_own_stack") || STREQ(sp->name, "call_softirq")))
			irq_eframe = 0;
                bt->frameptr = 0;
                done = FALSE;
        } else
		irq_eframe = 0;

        if (!done && (estack = x86_64_in_exception_stack(bt, &estack_index))) 
		goto in_exception_stack;

	if (!done && (bt->flags & (BT_EXCEPTION_STACK|BT_IRQSTACK))) {
		/*
		 *  Verify that the rsp pointer taken from either the
		 *  exception or IRQ stack points into the process stack.
		 */
		bt->stackbase = GET_STACKBASE(bt->tc->task);
		bt->stacktop = GET_STACKTOP(bt->tc->task);

		if (!INSTACK(rsp, bt)) {
			/*
			 *  If the exception occurred while on the KPTI entry trampoline stack,
			 *  just print the entry exception frame and bail out.
			 */
			if ((kpti_eframe = x86_64_in_kpti_entry_stack(bt->tc->processor, rsp))) {
				x86_64_exception_frame(EFRAME_PRINT, kpti_eframe, 0, bt, ofp);
				fprintf(fp, "--- <entry trampoline stack> ---\n");
				return;
			}

			switch (bt->flags & (BT_EXCEPTION_STACK|BT_IRQSTACK))
			{
			case (BT_EXCEPTION_STACK|BT_IRQSTACK):
				error(FATAL, STACK_TRANSITION_ERRMSG_E_I_P,
					bt_in->stkptr, bt->stkptr, rsp,
					bt->stackbase);

			case BT_EXCEPTION_STACK:
				if (in_user_stack(bt->tc->task, rsp)) {
					done = TRUE;
					break;
				}
				if (STREQ(closest_symbol(bt->instptr), 
				    "ia32_sysenter_target")) {
					/*
					 * RSP 0 from MSR_IA32_SYSENTER_ESP?
					 */
					if (rsp == 0)
						return;
					done = TRUE;
					break;
				}
				error(FATAL, STACK_TRANSITION_ERRMSG_E_P,
					bt_in->stkptr, rsp, bt->stackbase);

			case BT_IRQSTACK:
				error(FATAL, STACK_TRANSITION_ERRMSG_I_P,
					bt_in->stkptr, rsp, bt->stackbase);
			}
		}

		/*
	 	 *  Now fill the local stack buffer from the process stack.
	  	 */
               	if (!readmem(bt->stackbase, KVADDR, bt->stackbuf,
                    bt->stacktop - bt->stackbase, 
		    "irqstack contents", RETURN_ON_ERROR))
                	error(FATAL, "read of process stack at %lx failed\n",
				bt->stackbase);
	}

	/*
	 *  For a normally blocked task, hand-create the first level(s).
	 *  associated with __schedule() and/or schedule().
	 */
        if (!done && 
	    !(bt->flags & (BT_TEXT_SYMBOLS|BT_EXCEPTION_STACK|BT_IRQSTACK)) &&
            (rip_symbol = closest_symbol(bt->instptr)) &&
	    (STREQ(rip_symbol, "thread_return") || 
	     STREQ(rip_symbol, "schedule") || 
	     STREQ(rip_symbol, "__schedule"))) {
		if ((machdep->flags & ORC) && VALID_MEMBER(inactive_task_frame_ret_addr)) {
			/*
			 * %rsp should have the address of inactive_task_frame, so
			 * skip the registers before ret_addr to adjust rsp.
			 */
			if (CRASHDEBUG(1))
				fprintf(fp, "rsp: %lx rbp: %lx\n", rsp, bt->bptr);
			rsp += OFFSET(inactive_task_frame_ret_addr);
		} else {
			if (STREQ(rip_symbol, "__schedule")) {
				i = (rsp - bt->stackbase)/sizeof(ulong);
				x86_64_print_stack_entry(bt, ofp, level,
					i, bt->instptr);
				level++;
				rsp = __schedule_frame_adjust(rsp, bt);
				if (STREQ(closest_symbol(bt->instptr), "schedule"))
					bt->flags |= BT_SCHEDULE;
			} else
				bt->flags |= BT_SCHEDULE;

			if (bt->flags & BT_SCHEDULE) {
				i = (rsp - bt->stackbase)/sizeof(ulong);
				x86_64_print_stack_entry(bt, ofp, level,
					i, bt->instptr);
				bt->flags &= ~(ulonglong)BT_SCHEDULE;
				rsp += sizeof(ulong);
				level++;
			}
		}
	}

	/*
	 *  Dump the IRQ exception frame from the process stack.
	 *  If the CS register indicates a user exception frame,
	 *  then set done to TRUE to avoid the process stack walk-through.
	 *  Otherwise, bump up the rsp past the kernel-mode eframe.
	 */
        if (irq_eframe) {
                bt->flags |= BT_EXCEPTION_FRAME;
                i = (irq_eframe - bt->stackbase)/sizeof(ulong);
                if (symbol_exists("asm_common_interrupt")) {
			i -= 1;
			up = (ulong *)(&bt->stackbuf[i*sizeof(ulong)]);
			bt->instptr = *up;
                }
                x86_64_print_stack_entry(bt, ofp, level, i, bt->instptr);
                bt->flags &= ~(ulonglong)BT_EXCEPTION_FRAME;
                cs = x86_64_exception_frame(EFRAME_PRINT|EFRAME_CS, 0, 
			bt->stackbuf + (irq_eframe - bt->stackbase), bt, ofp);
		if (cs & 3)
			done = TRUE;   /* IRQ from user-mode */
		else {
			if (x86_64_print_eframe_location(rsp, level, ofp))
				level++;
			rsp += SIZE(pt_regs);
			irq_eframe = 0;
			bt->flags |= BT_EFRAME_TARGET;
			if (bt->eframe_ip && ((framesize = x86_64_get_framesize(bt, 
			    bt->eframe_ip, rsp, NULL)) >= 0))
				rsp += framesize;
			bt->flags &= ~BT_EFRAME_TARGET;
		}
		level++;
        }

	/*
	 *  Walk the process stack.  
	 */

	bt->flags &= ~BT_FRAMESIZE_DISABLE;

        for (i = (rsp - bt->stackbase)/sizeof(ulong);
	     !done && (rsp < bt->stacktop); i++, rsp += sizeof(ulong)) {

		up = (ulong *)(&bt->stackbuf[i*sizeof(ulong)]);

		if (!is_kernel_text(*up))
			continue;

		if ((bt->flags & BT_CHECK_CALLER)) {
			/*
			 *  A non-zero offset value from the value_search() 
			 *  lets us know if it's a real text return address.
			 */
			if (!(spt = value_search(*up, &offset)))
				continue;

			if (!offset && !(bt->flags & BT_FRAMESIZE_DISABLE))
				continue;

			/*
		         *  sp gets the syment of the function that the text 
			 *  routine above called before leaving its return 
			 *  address on the stack -- if it can be determined.
			 */
			sp = x86_64_function_called_by((*up)-5); 

			if (sp == NULL) {
				/* 
				 *  We were unable to get the called function.
				 *  If the text address had an offset, then
				 *  it must have made an indirect call, and
				 *  can't have called our target function.
				 */
				if (offset) {
					if (CRASHDEBUG(1))
						fprintf(ofp, 
                       "< ignoring %s() -- makes indirect call and NOT %s()>\n",
						    	spt->name, 
						    	bt->call_target);
					continue;
				}
			} else if ((machdep->flags & SCHED_TEXT) &&
				STREQ(bt->call_target, "schedule") &&
				STREQ(sp->name, "__sched_text_start")) {
				;  /*  bait and switch */
			} else if (!STREQ(sp->name, bt->call_target)) {
				/*
				 *  We got function called by the text routine,
			 	 *  but it's not our target function.
				 */
				if (CRASHDEBUG(2))
					fprintf(ofp, 
 		                "< ignoring %s() -- calls %s() and NOT %s()>\n",
						spt->name, sp->name, 
						bt->call_target);
				continue;
			}
		}

		switch (x86_64_print_stack_entry(bt, ofp, level, i,*up))
		{
		case BACKTRACE_ENTRY_AND_EFRAME_DISPLAYED:
			last_process_stack_eframe = rsp + 8;
			if (x86_64_print_eframe_location(last_process_stack_eframe, level, ofp))
				level++;
			rsp += SIZE(pt_regs);
			i += SIZE(pt_regs)/sizeof(ulong);
			if (!bt->eframe_ip) {
				level++;
				break;
			} /* else fall through */
		case BACKTRACE_ENTRY_DISPLAYED:
			level++;
			if ((framesize = x86_64_get_framesize(bt, 
			    bt->eframe_ip ? bt->eframe_ip : *up, rsp, (char *)up)) >= 0) {
				rsp += framesize;
				i += framesize/sizeof(ulong);
			}
			break;
		case BACKTRACE_ENTRY_IGNORED:	
			break;
		case BACKTRACE_COMPLETE:
			done = TRUE;
			break;
		}
        }

        if (!irq_eframe && !is_kernel_thread(bt->tc->task) &&
            (GET_STACKBASE(bt->tc->task) == bt->stackbase)) {
		user_mode_eframe = bt->stacktop - SIZE(pt_regs);
		if (last_process_stack_eframe < user_mode_eframe)
                	x86_64_exception_frame(EFRAME_PRINT, 0, bt->stackbuf +
                        	(bt->stacktop - bt->stackbase) - SIZE(pt_regs),
                        	bt, ofp);
	}

        if (bt->flags & BT_TEXT_SYMBOLS) {
        	if (BT_REFERENCE_FOUND(bt)) {
                	print_task_header(fp, task_to_context(bt->task), 0);
			BCOPY(bt_in, bt, sizeof(struct bt_info));
                	bt->ref = NULL;
                	machdep->back_trace(bt);
                	fprintf(fp, "\n");
        	}
	}
}

/*
 *  Use dwarf CFI encodings to correctly follow the call chain.
 */
static void
x86_64_dwarf_back_trace_cmd(struct bt_info *bt_in)
{
	int i, level, done, estack_index;
	ulong rsp, offset, stacktop;
	ulong *up;
	long cs;
	struct syment *sp;
	FILE *ofp;
	ulong estack, irqstack;
	ulong irq_eframe, kpti_eframe;
	struct bt_info bt_local, *bt;
	struct machine_specific *ms;
	ulong last_process_stack_eframe;
	ulong user_mode_eframe;

	/*
	 *  User may have made a run-time switch.
	 */
        if (!(kt->flags & DWARF_UNWIND)) {
                machdep->back_trace = x86_64_low_budget_back_trace_cmd;
                x86_64_low_budget_back_trace_cmd(bt_in);
                return;
        }

	bt = &bt_local;
	BCOPY(bt_in, bt, sizeof(struct bt_info));

        if (bt->flags & BT_FRAMESIZE_DEBUG) {
		dwarf_debug(bt);
		return;
	}

	level = 0;
	done = FALSE;
	irq_eframe = 0;
	last_process_stack_eframe = 0;
	bt->call_target = NULL;
	bt->bptr = 0;
	rsp = bt->stkptr;
	if (!rsp) {
		error(INFO, "cannot determine starting stack pointer\n");
		return;
	}
	ms = machdep->machspec;
	if (BT_REFERENCE_CHECK(bt))
		ofp = pc->nullfp;
	else
		ofp = fp;

        if (bt->flags & BT_TEXT_SYMBOLS) {
		if (!(bt->flags & BT_TEXT_SYMBOLS_ALL))
                	fprintf(ofp, "%sSTART: %s%s at %lx\n",
                	    space(VADDR_PRLEN > 8 ? 14 : 6),
                	    closest_symbol(bt->instptr), 
			    STREQ(closest_symbol(bt->instptr), "thread_return") ?
			    " (schedule)" : "",
			    bt->instptr);
        } else if (bt->flags & BT_START) {
                x86_64_print_stack_entry(bt, ofp, level,
                        0, bt->instptr);
		bt->flags &= ~BT_START;
		level++;
	}


        if ((estack = x86_64_in_exception_stack(bt, &estack_index))) {
in_exception_stack:
		bt->flags |= BT_EXCEPTION_STACK;
		/*
	 	 *  The stack buffer will have been loaded with the process
		 *  stack, so switch to the indicated exception stack.
		 */
                bt->stackbase = estack;
                bt->stacktop = estack + ms->stkinfo.esize[estack_index];
                bt->stackbuf = ms->irqstack;

                if (!readmem(bt->stackbase, KVADDR, bt->stackbuf,
                    bt->stacktop - bt->stackbase,
		    bt->hp && (bt->hp->esp == bt->stkptr) ? 
	 	    "irqstack contents via hook" : "irqstack contents", 
		    RETURN_ON_ERROR))
                    	error(FATAL, "read of exception stack at %lx failed\n",
                        	bt->stackbase);

		/*
	 	 *  If irq_eframe is set, we've jumped back here from the
		 *  IRQ stack dump below.  Do basically the same thing as if
		 *  had come from the processor stack, but presume that we
		 *  must have been in kernel mode, i.e., took an exception
	 	 *  while operating on an IRQ stack.  (untested)
		 */
                if (irq_eframe) {
                        bt->flags |= BT_EXCEPTION_FRAME;
                        i = (irq_eframe - bt->stackbase)/sizeof(ulong);
                        x86_64_print_stack_entry(bt, ofp, level, i, 
				bt->instptr);
                        bt->flags &= ~(ulonglong)BT_EXCEPTION_FRAME;
                        cs = x86_64_exception_frame(EFRAME_PRINT|EFRAME_CS, 0,
                        	bt->stackbuf + (irq_eframe - bt->stackbase), 
				bt, ofp);
                        rsp += SIZE(pt_regs);  /* guaranteed kernel mode */
                        level++;
                        irq_eframe = 0;
                }

		stacktop = bt->stacktop - SIZE(pt_regs);
		if ((machdep->flags & NESTED_NMI) &&
		    estack_index == NMI_STACK)
			stacktop -= 12*sizeof(ulong);

		if (!done) {
			level = dwarf_backtrace(bt, level, stacktop);
			done = TRUE;
		}

                cs = x86_64_exception_frame(EFRAME_PRINT|EFRAME_CS, 0, 
			bt->stackbuf + (stacktop - bt->stackbase),
			bt, ofp);

		if (!BT_REFERENCE_CHECK(bt))
			fprintf(fp, "--- <exception stack> ---\n");

		/*
		 * Find the CPU-saved, or handler-saved registers
		 */
		up = (ulong *)(&bt->stackbuf[bt->stacktop - bt->stackbase]);
		up -= 5;
		if ((machdep->flags & NESTED_NMI) &&
		    estack_index == NMI_STACK &&
		    bt->stkptr <= bt->stacktop - 17*sizeof(ulong)) {
			up -= 12;
			/* Copied and saved regs are swapped in pre-3.8 kernels */
			if (*up == symbol_value("repeat_nmi"))
				up += 5;
		}

		/* Registers (as saved by CPU):
		 *
		 *   up[4]	SS
		 *   up[3]	RSP
		 *   up[2]	RFLAGS
		 *   up[1]	CS
		 *   up[0]	RIP
		 */
		rsp = bt->stkptr = up[3];
		bt->instptr = up[0];
		if (cs & 3)
			done = TRUE;   /* user-mode exception */
		else
			done = FALSE;  /* kernel-mode exception */
		bt->frameptr = 0;

		/*
		 *  Print the return values from the estack end.
		 */
		if (!done) {
                	bt->flags |= BT_START;
                	x86_64_print_stack_entry(bt, ofp, level,
                        	0, bt->instptr);
                	bt->flags &= ~BT_START;
			level++;
		}
	}

	/*
	 *  IRQ stack entry always comes in via the process stack, regardless
	 *  whether it happened while running in user or kernel space.
	 */
        if (!done && (irqstack = x86_64_in_irqstack(bt))) {
		bt->flags |= BT_IRQSTACK;
		/*
		 *  Until coded otherwise, the stackbase will be pointing to
		 *  either the exception stack or, more likely, the process
		 *  stack base.  Switch it to the IRQ stack.
		 */
                bt->stackbase = irqstack;
                bt->stacktop = irqstack + ms->stkinfo.isize;
                bt->stackbuf = ms->irqstack;

                if (!readmem(bt->stackbase, KVADDR, 
	  	    bt->stackbuf, bt->stacktop - bt->stackbase,
                    bt->hp && (bt->hp->esp == bt_in->stkptr) ?
		    "irqstack contents via hook" : "irqstack contents", 
		    RETURN_ON_ERROR))
                    	error(FATAL, "read of IRQ stack at %lx failed\n",
				bt->stackbase);

		stacktop = bt->stacktop - ms->irq_stack_gap;

		if (!done) {
			level = dwarf_backtrace(bt, level, stacktop);
			done = TRUE;
		}

		if (!BT_REFERENCE_CHECK(bt))
                	fprintf(fp, "--- <IRQ stack> ---\n");

                /*
		 *  stack = (unsigned long *) (irqstack_end[-1]);
		 *  (where irqstack_end is 64 bytes below page end)
                 */
                up = (ulong *)(&bt->stackbuf[stacktop - bt->stackbase]);
                up -= 1;
                irq_eframe = rsp = bt->stkptr = (*up) - ms->irq_eframe_link;
		up -= 1;
                bt->instptr = *up;
                /*
                 *  No exception frame when coming from call_softirq.
                 */
                if ((sp = value_search(bt->instptr, &offset)) &&
                    STREQ(sp->name, "call_softirq"))
                        irq_eframe = 0;
                bt->frameptr = 0;
                done = FALSE;
        } else
		irq_eframe = 0;

        if (!done && (estack = x86_64_in_exception_stack(bt, &estack_index))) 
		goto in_exception_stack;

	if (!done && (bt->flags & (BT_EXCEPTION_STACK|BT_IRQSTACK))) {
		/*
		 *  Verify that the rsp pointer taken from either the
		 *  exception or IRQ stack points into the process stack.
		 */
		bt->stackbase = GET_STACKBASE(bt->tc->task);
		bt->stacktop = GET_STACKTOP(bt->tc->task);

		if (!INSTACK(rsp, bt)) {
			/*
			 *  If the exception occurred while on the KPTI entry trampoline stack,
			 *  just print the entry exception frame and bail out.
			 */
			if ((kpti_eframe = x86_64_in_kpti_entry_stack(bt->tc->processor, rsp))) {
				x86_64_exception_frame(EFRAME_PRINT, kpti_eframe, 0, bt, ofp);
				fprintf(fp, "--- <ENTRY TRAMPOLINE stack> ---\n");
				return;
			}

			switch (bt->flags & (BT_EXCEPTION_STACK|BT_IRQSTACK))
			{
			case (BT_EXCEPTION_STACK|BT_IRQSTACK):
				error(FATAL, STACK_TRANSITION_ERRMSG_E_I_P,
					bt_in->stkptr, bt->stkptr, rsp,
					bt->stackbase);

			case BT_EXCEPTION_STACK:
				error(FATAL, STACK_TRANSITION_ERRMSG_E_P,
					bt_in->stkptr, rsp, bt->stackbase);

			case BT_IRQSTACK:
				error(FATAL, STACK_TRANSITION_ERRMSG_I_P,
					bt_in->stkptr, rsp, bt->stackbase);
			}
		}

		/*
	 	 *  Now fill the local stack buffer from the process stack.
	  	 */
               	if (!readmem(bt->stackbase, KVADDR, bt->stackbuf,
                    bt->stacktop - bt->stackbase, 
		    "irqstack contents", RETURN_ON_ERROR))
                	error(FATAL, "read of process stack at %lx failed\n",
				bt->stackbase);
	}

	/*
	 *  Dump the IRQ exception frame from the process stack.
	 *  If the CS register indicates a user exception frame,
	 *  then set done to TRUE to avoid the process stack walk-through.
	 *  Otherwise, bump up the rsp past the kernel-mode eframe.
	 */
        if (irq_eframe) {
                bt->flags |= BT_EXCEPTION_FRAME;
		level = dwarf_print_stack_entry(bt, level);
                bt->flags &= ~(ulonglong)BT_EXCEPTION_FRAME;
                cs = x86_64_exception_frame(EFRAME_PRINT|EFRAME_CS, 0, 
			bt->stackbuf + (irq_eframe - bt->stackbase), bt, ofp);
		if (cs & 3)
			done = TRUE;   /* IRQ from user-mode */
		else {
			if (x86_64_print_eframe_location(rsp, level, ofp))
				level++;
			rsp += SIZE(pt_regs);
			irq_eframe = 0;
		}
		level++;
        }

	/*
	 *  Walk the process stack.  
	 */
	if (!done) {
		level = dwarf_backtrace(bt, level, bt->stacktop);
		done = TRUE;
	}

        if (!irq_eframe && !is_kernel_thread(bt->tc->task) &&
            (GET_STACKBASE(bt->tc->task) == bt->stackbase)) {
		user_mode_eframe = bt->stacktop - SIZE(pt_regs);
		if (last_process_stack_eframe < user_mode_eframe)
                	x86_64_exception_frame(EFRAME_PRINT, 0, bt->stackbuf +
                        	(bt->stacktop - bt->stackbase) - SIZE(pt_regs),
                        	bt, ofp);
	}

        if (bt->flags & BT_TEXT_SYMBOLS) {
        	if (BT_REFERENCE_FOUND(bt)) {
                	print_task_header(fp, task_to_context(bt->task), 0);
			BCOPY(bt_in, bt, sizeof(struct bt_info));
                	bt->ref = NULL;
                	machdep->back_trace(bt);
                	fprintf(fp, "\n");
        	}
	}
}

/*
 *  Functions that won't be called indirectly.
 *  Add more to this as they are discovered.
 */
static const char *direct_call_targets[] = {
        "schedule",
        "schedule_timeout",
	NULL
};

static int
is_direct_call_target(struct bt_info *bt)
{
	int i;

	if (!bt->call_target || (bt->flags & BT_NO_CHECK_CALLER))
		return FALSE;

	if (strstr(bt->call_target, "schedule") &&
	    is_task_active(bt->task))
		return FALSE;

	for (i = 0; direct_call_targets[i]; i++) {
		if (STREQ(direct_call_targets[i], bt->call_target)) 
			return TRUE;
	}

	return FALSE;
}

static struct syment *
x86_64_function_called_by(ulong rip)
{
	struct syment *sp;
	char buf[BUFSIZE], *p1;
	ulong value, offset;
	unsigned char byte;

	value = 0;
	sp = NULL;

        if (!readmem(rip, KVADDR, &byte, sizeof(unsigned char), "call byte",
            QUIET|RETURN_ON_ERROR)) 
		return sp;

        if (byte != 0xe8) 
		return sp;

        sprintf(buf, "x/i 0x%lx", rip);

        open_tmpfile2();
	if (gdb_pass_through(buf, pc->tmpfile2, GNU_RETURN_ON_ERROR)) {
	        rewind(pc->tmpfile2);
	        while (fgets(buf, BUFSIZE, pc->tmpfile2)) {
			if ((p1 = strstr(buf, " call")) || (p1 = strstr(buf, "\tcall"))) {
				if (extract_hex(p1, &value, NULLCHAR, TRUE)) 
					break;
			}
		}
	}
        close_tmpfile2();

	if (value)
		sp = value_search(value, &offset);

	/*
	 *  Functions that jmp to schedule() or schedule_timeout().
	 */
	if (sp) {
	    	if ((STREQ(sp->name, "schedule_timeout_interruptible") ||
	             STREQ(sp->name, "schedule_timeout_uninterruptible")))
			sp = symbol_search("schedule_timeout");

		if (STREQ(sp->name, "__cond_resched"))
			sp = symbol_search("schedule");
	}

	return sp;
}

/*
 *  Unroll the kernel stack using a minimal amount of gdb services.
 */
static void
x86_64_back_trace(struct gnu_request *req, struct bt_info *bt)
{
	error(FATAL, "x86_64_back_trace: unused\n");
}


/*
 *  Print exception frame information for x86_64.
 *
 *    Pid: 0, comm: swapper Not tainted 2.6.5-1.360phro.rootsmp
 *    RIP: 0010:[<ffffffff8010f534>] <ffffffff8010f534>{default_idle+36}
 *    RSP: 0018:ffffffff8048bfd8  EFLAGS: 00000246
 *    RAX: 0000000000000000 RBX: ffffffff8010f510 RCX: 0000000000000018
 *    RDX: 0000010001e37280 RSI: ffffffff803ac0a0 RDI: 000001007f43c400
 *    RBP: 0000000000000000 R08: ffffffff8048a000 R09: 0000000000000000
 *    R10: ffffffff80482188 R11: 0000000000000001 R12: 0000000000000000
 *    R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
 *    FS:  0000002a96e14fc0(0000) GS:ffffffff80481d80(0000) GS:0000000055578aa0
 *    CS:  0010 DS: 0018 ES: 0018 CR0: 000000008005003b
 *    CR2: 0000002a9556b000 CR3: 0000000000101000 CR4: 00000000000006e0
 *
 */

long
x86_64_exception_frame(ulong flags, ulong kvaddr, char *local,
	struct bt_info *bt, FILE *ofp)
{
        long rip, rsp, cs, ss, rflags, orig_rax, rbp; 
	long rax, rbx, rcx, rdx, rsi, rdi;
        long r8, r9, r10, r11, r12, r13, r14, r15;
	struct machine_specific *ms;
	struct syment *sp;
	ulong offset, verify_addr;
	char *pt_regs_buf;
	long verified;
	long err;
	char buf[BUFSIZE];

	if (flags & EFRAME_VERIFY) {
		if (kvaddr)
			verify_addr = kvaddr;
		else
			verify_addr = (local - bt->stackbuf) + bt->stackbase;

		if (!accessible(verify_addr) ||
		    !accessible(verify_addr + SIZE(pt_regs) - sizeof(long)))
			return FALSE;
	}

	ms = machdep->machspec;
	sp = NULL;

	if (!(machdep->flags & PT_REGS_INIT) || (flags == EFRAME_INIT)) {
		err = 0;
		err |= ((ms->pto.r15 = MEMBER_OFFSET("pt_regs", "r15")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.r14 = MEMBER_OFFSET("pt_regs", "r14")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.r13 = MEMBER_OFFSET("pt_regs", "r13")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.r12 = MEMBER_OFFSET("pt_regs", "r12")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.r11 = MEMBER_OFFSET("pt_regs", "r11")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.r10 = MEMBER_OFFSET("pt_regs", "r10")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.r9 = MEMBER_OFFSET("pt_regs", "r9")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.r8 = MEMBER_OFFSET("pt_regs", "r8")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.cs = MEMBER_OFFSET("pt_regs", "cs")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.ss = MEMBER_OFFSET("pt_regs", "ss")) == 
			INVALID_OFFSET);
		/*
		 *  x86/x86_64 merge changed traditional register names.
		 */
		if (((ms->pto.rbp = MEMBER_OFFSET("pt_regs", "rbp")) == 
		    INVALID_OFFSET) &&
		    ((ms->pto.rbp = MEMBER_OFFSET("pt_regs", "bp")) == 
		    INVALID_OFFSET))
			err++; 
		if (((ms->pto.rax = MEMBER_OFFSET("pt_regs", "rax")) == 
		    INVALID_OFFSET) &&
		    ((ms->pto.rax = MEMBER_OFFSET("pt_regs", "ax")) == 
		    INVALID_OFFSET))
			err++; 
		if (((ms->pto.rbx = MEMBER_OFFSET("pt_regs", "rbx")) == 
		    INVALID_OFFSET) &&
		    ((ms->pto.rbx = MEMBER_OFFSET("pt_regs", "bx")) == 
		    INVALID_OFFSET))
			err++; 
		if (((ms->pto.rcx = MEMBER_OFFSET("pt_regs", "rcx")) == 
		    INVALID_OFFSET) &&
		    ((ms->pto.rcx = MEMBER_OFFSET("pt_regs", "cx")) == 
		    INVALID_OFFSET))
			err++; 
		if (((ms->pto.rdx = MEMBER_OFFSET("pt_regs", "rdx")) == 
		    INVALID_OFFSET) &&
		    ((ms->pto.rdx = MEMBER_OFFSET("pt_regs", "dx")) == 
		    INVALID_OFFSET))
			err++; 
		if (((ms->pto.rsi = MEMBER_OFFSET("pt_regs", "rsi")) == 
		    INVALID_OFFSET) &&
		    ((ms->pto.rsi = MEMBER_OFFSET("pt_regs", "si")) == 
		    INVALID_OFFSET))
			err++; 
		if (((ms->pto.rdi = MEMBER_OFFSET("pt_regs", "rdi")) == 
		    INVALID_OFFSET) &&
		    ((ms->pto.rdi = MEMBER_OFFSET("pt_regs", "di")) == 
		    INVALID_OFFSET))
			err++; 
		if (((ms->pto.rip = MEMBER_OFFSET("pt_regs", "rip")) == 
		    INVALID_OFFSET) &&
		    ((ms->pto.rip = MEMBER_OFFSET("pt_regs", "ip")) == 
		    INVALID_OFFSET))
			err++; 
		if (((ms->pto.rsp = MEMBER_OFFSET("pt_regs", "rsp")) == 
		    INVALID_OFFSET) &&
		    ((ms->pto.rsp = MEMBER_OFFSET("pt_regs", "sp")) == 
		    INVALID_OFFSET))
			err++; 
		if (((ms->pto.eflags = MEMBER_OFFSET("pt_regs", "eflags")) == 
		    INVALID_OFFSET) &&
		    ((ms->pto.eflags = MEMBER_OFFSET("pt_regs", "flags")) == 
		    INVALID_OFFSET))
			err++; 
		if (((ms->pto.orig_rax = MEMBER_OFFSET("pt_regs", "orig_rax")) == 
		    INVALID_OFFSET) &&
		    ((ms->pto.orig_rax = MEMBER_OFFSET("pt_regs", "orig_ax")) == 
		    INVALID_OFFSET))
			err++; 

		if (err)
			error(WARNING, "pt_regs structure has changed\n");

		machdep->flags |= PT_REGS_INIT;

		if (flags == EFRAME_INIT)
			return err;
	}

	if (kvaddr) {
		pt_regs_buf = GETBUF(SIZE(pt_regs));
        	readmem(kvaddr, KVADDR, pt_regs_buf,
                	SIZE(pt_regs), "pt_regs", FAULT_ON_ERROR);
	} else
		pt_regs_buf = local;

	rip = ULONG(pt_regs_buf + ms->pto.rip);
	rsp = ULONG(pt_regs_buf + ms->pto.rsp);
	cs = ULONG(pt_regs_buf + ms->pto.cs);
	ss = ULONG(pt_regs_buf + ms->pto.ss);
	rflags = ULONG(pt_regs_buf + ms->pto.eflags);
	orig_rax = ULONG(pt_regs_buf + ms->pto.orig_rax);
	rbp = ULONG(pt_regs_buf + ms->pto.rbp);
	rax = ULONG(pt_regs_buf + ms->pto.rax);
	rbx = ULONG(pt_regs_buf + ms->pto.rbx);
	rcx = ULONG(pt_regs_buf + ms->pto.rcx);
	rdx = ULONG(pt_regs_buf + ms->pto.rdx);
	rsi = ULONG(pt_regs_buf + ms->pto.rsi);
	rdi = ULONG(pt_regs_buf + ms->pto.rdi);
	r8 = ULONG(pt_regs_buf + ms->pto.r8);
	r9 = ULONG(pt_regs_buf + ms->pto.r9);
	r10 = ULONG(pt_regs_buf + ms->pto.r10);
	r11 = ULONG(pt_regs_buf + ms->pto.r11);
	r12 = ULONG(pt_regs_buf + ms->pto.r12);
	r13 = ULONG(pt_regs_buf + ms->pto.r13);
	r14 = ULONG(pt_regs_buf + ms->pto.r14);
	r15 = ULONG(pt_regs_buf + ms->pto.r15);

        verified = x86_64_eframe_verify(bt, 
		kvaddr ? kvaddr : (local - bt->stackbuf) + bt->stackbase,
		cs, ss, rip, rsp, rflags);

	/*
	 *  If it's print-if-verified request, don't print bogus eframes.
	 */
        if (!verified && ((flags & (EFRAME_VERIFY|EFRAME_PRINT)) == 
	    (EFRAME_VERIFY|EFRAME_PRINT))) 
		flags &= ~EFRAME_PRINT;
 	else if (CRASHDEBUG(1) && verified && (flags != EFRAME_VERIFY)) 
		fprintf(ofp, "< exception frame at: %lx >\n", kvaddr ?
			kvaddr : (local - bt->stackbuf) + bt->stackbase);

	if (flags & EFRAME_PRINT) {
		if (flags & EFRAME_SEARCH) {
			fprintf(ofp, "\n  %s-MODE EXCEPTION FRAME AT: %lx\n",
				cs & 3 ? "USER" : "KERNEL", 
				kvaddr ?  kvaddr : 
				(local - bt->stackbuf) + bt->stackbase);
			if (!(cs & 3)) {
				fprintf(ofp, "    [exception RIP: ");
				if ((sp = value_search(rip, &offset))) {
					fprintf(ofp, "%s", sp->name);
					if (offset)
						fprintf(ofp, 
						    (*gdb_output_radix == 16) ? 
						    "+0x%lx" : "+%ld", 
						    offset);
				} else
					fprintf(ofp, "%s", 
						x86_64_exception_RIP_message(bt, rip));
				fprintf(ofp, "]\n");
			}
		} else if (!(cs & 3)) {
			fprintf(ofp, "    [exception RIP: ");
			if ((sp = value_search(rip, &offset))) {
                		fprintf(ofp, "%s", sp->name);
                		if (offset)
                        		fprintf(ofp, (*gdb_output_radix == 16) ? 
						"+0x%lx" : "+%ld", offset);
				bt->eframe_ip = rip;
			} else
				fprintf(ofp, "%s", x86_64_exception_RIP_message(bt, rip));
			fprintf(ofp, "]\n");
		}
		fprintf(ofp, "    RIP: %016lx  RSP: %016lx  RFLAGS: %08lx\n", 
			rip, rsp, rflags);
		fprintf(ofp, "    RAX: %016lx  RBX: %016lx  RCX: %016lx\n", 
			rax, rbx, rcx);
		fprintf(ofp, "    RDX: %016lx  RSI: %016lx  RDI: %016lx\n", 
	 		rdx, rsi, rdi);
		fprintf(ofp, "    RBP: %016lx   R8: %016lx   R9: %016lx\n", 
			rbp, r8, r9);
		fprintf(ofp, "    R10: %016lx  R11: %016lx  R12: %016lx\n", 
			r10, r11, r12);
		fprintf(ofp, "    R13: %016lx  R14: %016lx  R15: %016lx\n", 
			r13, r14, r15);
		fprintf(ofp, "    ORIG_RAX: %016lx  CS: %04lx  SS: %04lx\n", 
			orig_rax, cs, ss);

		if (!(cs & 3) && sp && (bt->flags & BT_LINE_NUMBERS)) {
			get_line_number(rip, buf, FALSE);
			if (strlen(buf))
				fprintf(ofp, "    %s\n", buf);
		}

		if (!verified && CRASHDEBUG((pc->flags & RUNTIME) ? 0 : 1))
			error(WARNING, "possibly bogus exception frame\n");
	}

        if ((flags & EFRAME_PRINT) && BT_REFERENCE_CHECK(bt)) {
                x86_64_do_bt_reference_check(bt, rip, NULL);
		if ((sp = value_search(rip, &offset))) 
			x86_64_do_bt_reference_check(bt, 0, sp->name);
                x86_64_do_bt_reference_check(bt, rsp, NULL);
                x86_64_do_bt_reference_check(bt, cs, NULL);
                x86_64_do_bt_reference_check(bt, ss, NULL);
                x86_64_do_bt_reference_check(bt, rflags, NULL);
                x86_64_do_bt_reference_check(bt, orig_rax, NULL);
                x86_64_do_bt_reference_check(bt, rbp, NULL);
                x86_64_do_bt_reference_check(bt, rax, NULL);
                x86_64_do_bt_reference_check(bt, rbx, NULL);
                x86_64_do_bt_reference_check(bt, rcx, NULL);
                x86_64_do_bt_reference_check(bt, rdx, NULL);
                x86_64_do_bt_reference_check(bt, rsi, NULL);
                x86_64_do_bt_reference_check(bt, rdi, NULL);
                x86_64_do_bt_reference_check(bt, r8, NULL);
                x86_64_do_bt_reference_check(bt, r9, NULL);
                x86_64_do_bt_reference_check(bt, r10, NULL);
                x86_64_do_bt_reference_check(bt, r11, NULL);
                x86_64_do_bt_reference_check(bt, r12, NULL);
                x86_64_do_bt_reference_check(bt, r13, NULL);
                x86_64_do_bt_reference_check(bt, r14, NULL);
                x86_64_do_bt_reference_check(bt, r15, NULL);
        }

	/* Remember the rip and rsp for unwinding the process stack */
	if (kt->flags & DWARF_UNWIND){
		bt->instptr = rip;
		bt->stkptr = rsp;
		bt->bptr = rbp;
	} else if (machdep->flags & ORC)
		bt->bptr = rbp;

	if (kvaddr)
		FREEBUF(pt_regs_buf);

	if (flags & EFRAME_CS)
		return cs;
	else if (flags & EFRAME_VERIFY)
		return verified;

	return 0;
}

static int 
x86_64_print_eframe_location(ulong eframe, int level, FILE *ofp)
{
	return FALSE;

#ifdef NOTDEF
	ulong rip;
	char *pt_regs_buf;
        struct machine_specific *ms;
        struct syment *sp;

        ms = machdep->machspec;

        pt_regs_buf = GETBUF(SIZE(pt_regs));
        if (!readmem(eframe, KVADDR, pt_regs_buf, SIZE(pt_regs), 
	    "pt_regs", RETURN_ON_ERROR|QUIET)) {
		FREEBUF(pt_regs_buf);
		return FALSE;
	}

        rip = ULONG(pt_regs_buf + ms->pto.rip);
	FREEBUF(pt_regs_buf);

        if (!(sp = value_search(rip, NULL)))
                return FALSE;

        fprintf(ofp, "%s#%d [%8lx] %s at %lx\n", level < 10 ? " " : "", level+1,
		eframe, sp->name, rip);

	return TRUE;
#endif
}

/*
 *  Check whether an RIP is in the FIXMAP vsyscall page.
 */
static int
is_vsyscall_addr(ulong rip)
{
	ulong page;

	if ((page = machdep->machspec->vsyscall_page))
		if ((rip >= page) && (rip < (page+PAGESIZE())))
			return TRUE;

	return FALSE;
}

struct syment *
x86_64_value_to_symbol(ulong vaddr, ulong *offset)
{
	struct syment *sp;

	if (is_vsyscall_addr(vaddr) && 
	    (sp = value_search_base_kernel(vaddr, offset))) 
		return sp;

	return generic_machdep_value_to_symbol(vaddr, offset);
}

/*
 *  Check that the verifiable registers contain reasonable data.
 */
#define RAZ_MASK 0xffffffffffc08028    /* return-as-zero bits */

static int 
x86_64_eframe_verify(struct bt_info *bt, long kvaddr, long cs, long ss,
	long rip, long rsp, long rflags)
{
	int estack;
	struct syment *sp;
	ulong offset, exception;
	physaddr_t phys;

	if ((rflags & RAZ_MASK) || !(rflags & 0x2))
		return FALSE;

        if ((cs == 0x10) && (ss == 0x18)) {
                if (is_kernel_text(rip) && IS_KVADDR(rsp))
                        return TRUE;

                if (x86_64_is_module_addr(rip) &&
		    IS_KVADDR(rsp) &&
		    (rsp == (kvaddr + SIZE(pt_regs))))
                        return TRUE;

		if (is_kernel_text(rip) && 
		    (bt->flags & BT_EXCEPTION_STACK) &&
		    in_user_stack(bt->tc->task, rsp))
                        return TRUE;

		if (is_kernel_text(rip) && !IS_KVADDR(rsp) &&
		    (bt->flags & BT_EFRAME_SEARCH) &&
		    x86_64_in_exception_stack(bt, NULL))
			return TRUE;

		if (is_kernel_text(rip) && 
		    x86_64_in_exception_stack(bt, &estack) &&
		    (estack <= 1))
			return TRUE;
		
		/*
		 * RSP may be 0 from MSR_IA32_SYSENTER_ESP.
		 */
		if (STREQ(closest_symbol(rip), "ia32_sysenter_target"))
			return TRUE;

		if ((rip == 0) && INSTACK(rsp, bt) &&
		    STREQ(bt->call_target, "ret_from_fork"))
			return TRUE;

		if (readmem(kvaddr - 8, KVADDR, &exception, sizeof(ulong), 
		    "exception type", RETURN_ON_ERROR|QUIET) &&
		    (sp = value_search(exception, &offset)) &&
		    STREQ(sp->name, "page_fault"))
			return TRUE;
			
		if ((kvaddr + SIZE(pt_regs)) == rsp)
			return TRUE;
	}

        if ((cs == 0x10) && kvaddr) {
                if (is_kernel_text(rip) && IS_KVADDR(rsp) &&
		    (rsp == (kvaddr + SIZE(pt_regs) + 8)))
                        return TRUE;
	}

        if ((cs == 0x10) && kvaddr) {
                if (is_kernel_text(rip) && IS_KVADDR(rsp) &&
		    (rsp == (kvaddr + SIZE(pt_regs))))
                        return TRUE;
	}

	if ((cs == 0x10) && kvaddr) {
                if (is_kernel_text(rip) && IS_KVADDR(rsp) &&
		    x86_64_in_exception_stack(bt, NULL))
			return TRUE;
	}

	if ((cs == 0x10) && kvaddr) {
                if (IS_KVADDR(rsp) && IS_VMALLOC_ADDR(rip) && 
		    machdep->kvtop(bt->tc, rip, &phys, 0))
			return TRUE;
	}

        if ((cs == 0x33) && (ss == 0x2b)) {
                if (IS_UVADDR(rip, bt->tc) && IS_UVADDR(rsp, bt->tc))
                        return TRUE;
                if (is_vsyscall_addr(rip) && IS_UVADDR(rsp, bt->tc))
                        return TRUE;
        }

        if (XEN() && ((cs == 0x33) || (cs == 0xe033)) && 
	    ((ss == 0x2b) || (ss == 0xe02b))) {
                if (IS_UVADDR(rip, bt->tc) && IS_UVADDR(rsp, bt->tc))
                        return TRUE;
        }

	if (XEN() && ((cs == 0x10000e030) || (cs == 0xe030)) && 
	    (ss == 0xe02b)) {
                if (is_kernel_text(rip) && IS_KVADDR(rsp))
                        return TRUE;
	}

	/* 
	 *  32-bit segments 
	 */
        if ((cs == 0x23) && (ss == 0x2b)) {
                if (IS_UVADDR(rip, bt->tc) && IS_UVADDR(rsp, bt->tc))
                        return TRUE;
        }

	return FALSE;
}

/*
 *  Get a stack frame combination of pc and ra from the most relevent spot.
 */
static void
x86_64_get_stack_frame(struct bt_info *bt, ulong *pcp, ulong *spp)
{
	if (bt->flags & BT_DUMPFILE_SEARCH)
		return x86_64_get_dumpfile_stack_frame(bt, pcp, spp);

	if (bt->flags & BT_SKIP_IDLE)
		bt->flags &= ~BT_SKIP_IDLE;

        if (pcp)
                *pcp = x86_64_get_pc(bt);
        if (spp)
                *spp = x86_64_get_sp(bt);
}

/*
 *  Get the starting point for the active cpus in a diskdump/netdump.
 */
static void
x86_64_get_dumpfile_stack_frame(struct bt_info *bt_in, ulong *rip, ulong *rsp) 
{
	int panic_task;
        int i, j, estack, panic, stage, in_nmi_stack;
        char *sym;
	struct syment *sp;
        ulong *up, *up2;
	struct bt_info bt_local, *bt;
        struct machine_specific *ms;
	char *user_regs;
	ulong ur_rip, ur_rsp;
	ulong halt_rip, halt_rsp;
	ulong crash_kexec_rip, crash_kexec_rsp;
	ulong call_function_rip, call_function_rsp;
	ulong sysrq_c_rip, sysrq_c_rsp;
	ulong notify_die_rip, notify_die_rsp;

#define STACKTOP_INDEX(BT) (((BT)->stacktop - (BT)->stackbase)/sizeof(ulong))

        bt = &bt_local;
        BCOPY(bt_in, bt, sizeof(struct bt_info));
        ms = machdep->machspec;
	ur_rip = ur_rsp = 0;
	halt_rip = halt_rsp = 0;
	crash_kexec_rip = crash_kexec_rsp = 0;
	call_function_rip = call_function_rsp = 0;
	notify_die_rsp = notify_die_rip = 0;
	sysrq_c_rip = sysrq_c_rsp = 0;
	in_nmi_stack = stage = 0;
	estack = -1;
	panic = FALSE;

	if (bt_in->flags & BT_SKIP_IDLE)
		bt_in->flags &= ~BT_SKIP_IDLE;

	panic_task = tt->panic_task == bt->task ? TRUE : FALSE;

	if (panic_task && bt->machdep) {
		user_regs = bt->machdep;

		if (x86_64_eframe_verify(bt, 
		    0,
		    ULONG(user_regs + OFFSET(user_regs_struct_cs)),
		    ULONG(user_regs + OFFSET(user_regs_struct_ss)),
		    ULONG(user_regs + OFFSET(user_regs_struct_rip)),
        	    ULONG(user_regs + OFFSET(user_regs_struct_rsp)),
		    ULONG(user_regs + OFFSET(user_regs_struct_eflags)))) {
			bt->stkptr = ULONG(user_regs + 
				OFFSET(user_regs_struct_rsp));
			if (x86_64_in_irqstack(bt)) {
				ur_rip = ULONG(user_regs + 
					OFFSET(user_regs_struct_rip));
				ur_rsp = ULONG(user_regs + 
					OFFSET(user_regs_struct_rsp));
				goto skip_stage;
			}
		}
	} else if (ELF_NOTES_VALID() && bt->machdep) {
		user_regs = bt->machdep;
		ur_rip = ULONG(user_regs +
			OFFSET(user_regs_struct_rip));
		ur_rsp = ULONG(user_regs +
			OFFSET(user_regs_struct_rsp));
	}

	/*
	 *  Check the process stack first.
	 */
next_stack:
        for (i = 0, up = (ulong *)bt->stackbuf; i < STACKTOP_INDEX(bt); i++, up++) {
                sym = closest_symbol(*up);
		if (XEN_CORE_DUMPFILE()) {
			if (STREQ(sym, "crash_kexec")) {
				sp = x86_64_function_called_by((*up)-5);
				if (sp && STREQ(sp->name, "machine_kexec")) {
					*rip = *up;
					*rsp = bt->stackbase + ((char *)(up) - bt->stackbuf);
					return;
				}
			}
			if (STREQ(sym, "xen_machine_kexec")) {
                       		*rip = *up;
                       		*rsp = bt->stackbase + ((char *)(up) - bt->stackbuf);
				return;
			}
		} else if (STREQ(sym, "netconsole_netdump") || 
		    STREQ(sym, "netpoll_start_netdump") ||
		    STREQ(sym, "start_disk_dump") ||
		    STREQ(sym, "disk_dump") ||
		    STREQ(sym, "crash_kexec") ||
		    STREQ(sym, "machine_kexec") ||
		    STREQ(sym, "try_crashdump")) {
			if (STREQ(sym, "crash_kexec")) {
				sp = x86_64_function_called_by((*up)-5);
				if (sp && STREQ(sp->name, "machine_kexec")) {
					*rip = *up;
					*rsp = bt->stackbase + ((char *)(up) - bt->stackbuf);
					return;
				}
			}
			/*
			 *  Use second instance of crash_kexec if it exists.
			 */
			if (!(bt->flags & BT_TEXT_SYMBOLS) && 
			    STREQ(sym, "crash_kexec") && !crash_kexec_rip) {
				crash_kexec_rip = *up;
				crash_kexec_rsp = bt->stackbase + ((char *)(up) - bt->stackbuf);
				continue;
			}
                       	*rip = *up;
                       	*rsp = bt->stackbase + ((char *)(up) - bt->stackbuf);
                       	return;
                }

                if ((estack >= 0) && 
                    (STREQ(sym, "nmi_watchdog_tick") ||
                     STREQ(sym, "default_do_nmi"))) {
			sp = x86_64_function_called_by((*up)-5);
			if (!sp || !STREQ(sp->name, "die_nmi")) 
				continue;
                        *rip = *up;
                        *rsp = bt->stackbase + ((char *)(up) - bt->stackbuf);
			bt_in->flags |= BT_START;
			*rip = symbol_value("die_nmi");
			*rsp = (*rsp) - (7*sizeof(ulong));
                        return;
                }

                if (STREQ(sym, "panic")) {
                        *rip = *up;
                        *rsp = bt->stackbase + ((char *)(up) - bt->stackbuf);
                        panic = TRUE;
                        continue;   /* keep looking for die */
                }

                if (STREQ(sym, "die")) {
                        *rip = *up;
                        *rsp = bt->stackbase + ((char *)(up) - bt->stackbuf);
			j = i;
			up2 = up;
                        for (j++, up2++; j < STACKTOP_INDEX(bt); j++, up2++) {
                                sym = closest_symbol(*up2);
                                if (STREQ(sym, "sysrq_handle_crash"))
                                        goto next_sysrq;
                        }
                        return;
                }

                if (STREQ(sym, "sysrq_handle_crash")) {
			j = i;
			up2 = up;
next_sysrq:
                        sysrq_c_rip = *up2;
                        sysrq_c_rsp = bt->stackbase + ((char *)(up2) - bt->stackbuf);
                        pc->flags |= SYSRQ;
                        for (j++, up2++; j < STACKTOP_INDEX(bt); j++, up2++) {
                                sym = closest_symbol(*up2);
                                if (STREQ(sym, "sysrq_handle_crash"))
                                        goto next_sysrq;
                        }
                }

                if (!panic_task && (stage > 0) && 
		    (STREQ(sym, "smp_call_function_interrupt") ||
		     STREQ(sym, "stop_this_cpu"))) {
			call_function_rip = *up;
			call_function_rsp = bt->stackbase + 
				((char *)(up) - bt->stackbuf);
                }

                if (!panic_task && STREQ(sym, "crash_nmi_callback")) {
                        *rip = *up;
                        *rsp = bt->stackbase + ((char *)(up) - bt->stackbuf);
			if ((bt->flags & BT_SKIP_IDLE) && is_idle_thread(bt->task))
				bt_in->flags |= BT_SKIP_IDLE;
                        return;
                }

		if (!panic_task && in_nmi_stack && 
		    (pc->flags2 & VMCOREINFO) && STREQ(sym, "notify_die")) { 
                        notify_die_rip = *up;
                        notify_die_rsp = bt->stackbase + ((char *)(up) - bt->stackbuf);
		}

		if (XEN_CORE_DUMPFILE() && !panic_task && (bt->tc->pid == 0) &&
		    (stage == 0) && STREQ(sym, "safe_halt")) {
			halt_rip = *up;
			halt_rsp = bt->stackbase + ((char *)(up) - bt->stackbuf);
		}

		if (XEN_CORE_DUMPFILE() && !panic_task && (bt->tc->pid == 0) &&
		    !halt_rip && (stage == 0) && STREQ(sym, "xen_idle")) {
			halt_rip = *up;
			halt_rsp = bt->stackbase + ((char *)(up) - bt->stackbuf);
		}

		if (!XEN_CORE_DUMPFILE() && !panic_task && (bt->tc->pid == 0) && 
		    !halt_rip && (stage == 0) && STREQ(sym, "cpu_idle")) { 
			halt_rip = *up;
			halt_rsp = bt->stackbase + ((char *)(up) - bt->stackbuf);
		}
	}

	if (panic) 
		return;

	if (crash_kexec_rip) {
		*rip = crash_kexec_rip;
		*rsp = crash_kexec_rsp;
		return;
	}

skip_stage:
	switch (stage) 
	{
	/*
         *  Now check the processor's interrupt stack.
         */
	case 0:
		bt->stackbase = ms->stkinfo.ibase[bt->tc->processor];
		bt->stacktop = ms->stkinfo.ibase[bt->tc->processor] + 
			ms->stkinfo.isize;
		console("x86_64_get_dumpfile_stack_frame: searching IRQ stack at %lx\n", 
			bt->stackbase);
		bt->stackbuf = ms->irqstack;
		alter_stackbuf(bt);
		stage = 1;
		goto next_stack;

        /*
         *  Check the exception stacks.
         */
	case 1:
		if (++estack == MAX_EXCEPTION_STACKS)
			break;
		bt->stackbase = ms->stkinfo.ebase[bt->tc->processor][estack];
		bt->stacktop = ms->stkinfo.ebase[bt->tc->processor][estack] +
                	ms->stkinfo.esize[estack];
		console("x86_64_get_dumpfile_stack_frame: searching %s estack at %lx\n", 
			ms->stkinfo.exception_stacks[estack], bt->stackbase);
		if (!(bt->stackbase && ms->stkinfo.available[bt->tc->processor][estack]))
			goto skip_stage;
		bt->stackbuf = ms->irqstack;
		alter_stackbuf(bt);
		in_nmi_stack = STREQ(ms->stkinfo.exception_stacks[estack], "NMI");
		goto next_stack;

	}

	if (sysrq_c_rip) {
		*rip = sysrq_c_rip;
		*rsp = sysrq_c_rsp;
		return;
	}

	if (notify_die_rip) {
		*rip = notify_die_rip;
		*rsp = notify_die_rsp;
		return;
	}

	/*
	 *  We didn't find what we were looking for, so just use what was
	 *  passed in from the ELF header.
	 */
	if (ur_rip && ur_rsp) {
        	*rip = ur_rip;
		*rsp = ur_rsp;
		if (is_kernel_text(ur_rip) &&
		    (INSTACK(ur_rsp, bt_in) ||
		     in_alternate_stack(bt->tc->processor, ur_rsp)))
			bt_in->flags |= BT_KERNEL_SPACE;
		if (!is_kernel_text(ur_rip) && in_user_stack(bt->tc->task, ur_rsp))
			bt_in->flags |= BT_USER_SPACE;
		return;
	}

	if (call_function_rip && call_function_rsp) {
		*rip = call_function_rip;
		*rsp = call_function_rsp;
		return;
	}

	if (halt_rip && halt_rsp) {
        	*rip = halt_rip;
		*rsp = halt_rsp;
		if (KVMDUMP_DUMPFILE() || SADUMP_DUMPFILE() ||
		    (VMSS_DUMPFILE() && vmware_vmss_valid_regs(bt)))
			bt_in->flags &= ~(ulonglong)BT_DUMPFILE_SEARCH;
		return;
	}

	/*
	 *  Use what was (already) saved in the panic task's 
	 *  registers found in the ELF header.
	 */ 
	if (bt->flags & BT_KDUMP_ELF_REGS) {
		user_regs = bt->machdep;
		ur_rip = ULONG(user_regs + OFFSET(user_regs_struct_rip));
		ur_rsp = ULONG(user_regs + OFFSET(user_regs_struct_rsp));
		if (!in_alternate_stack(bt->tc->processor, ur_rsp) && 
		    !stkptr_to_task(ur_rsp)) {
			if (CRASHDEBUG(1))
				error(INFO, 
				    "x86_64_get_dumpfile_stack_frame: "
				    "ELF mismatch: RSP: %lx task: %lx\n",
					ur_rsp, bt->task);
		} else {
			if (is_kernel_text(ur_rip) && (INSTACK(ur_rsp, bt_in) || 
			    in_alternate_stack(bt->tc->processor, ur_rsp)))
				bt_in->flags |= BT_KERNEL_SPACE;
			if (!is_kernel_text(ur_rip) && in_user_stack(bt->tc->task, ur_rsp))
				bt_in->flags |= BT_USER_SPACE;
			return;
		}
	}

	if (CRASHDEBUG(1)) 
        	error(INFO, 
		    "x86_64_get_dumpfile_stack_frame: cannot find anything useful (task: %lx)\n",
			bt->task);

        if (XEN_CORE_DUMPFILE() && !panic_task && is_task_active(bt->task) &&
            !(bt->flags & (BT_TEXT_SYMBOLS_ALL|BT_TEXT_SYMBOLS)))
                error(FATAL,
                    "starting backtrace locations of the active (non-crashing) "
                    "xen tasks\n    cannot be determined: try -t or -T options\n");

	bt->flags &= ~(ulonglong)BT_DUMPFILE_SEARCH;

        machdep->get_stack_frame(bt, rip, rsp);

	if (KVMDUMP_DUMPFILE() || SADUMP_DUMPFILE() ||
	    (VMSS_DUMPFILE() && vmware_vmss_valid_regs(bt)))
		bt_in->flags &= ~(ulonglong)BT_DUMPFILE_SEARCH;
}

/*
 *  Get the saved RSP from the task's thread_struct.
 */
static ulong
x86_64_get_sp(struct bt_info *bt)
{
        ulong offset, rsp;

        if (tt->flags & THREAD_INFO) {
                readmem(bt->task + OFFSET(task_struct_thread) +
			OFFSET(thread_struct_rsp), KVADDR,
                        &rsp, sizeof(void *),
                        "thread_struct rsp", FAULT_ON_ERROR);
		if ((machdep->flags & ORC) && VALID_MEMBER(inactive_task_frame_bp)) {
			readmem(rsp + OFFSET(inactive_task_frame_bp), KVADDR, &bt->bptr,
				sizeof(void *), "inactive_task_frame.bp", FAULT_ON_ERROR);
		}
                return rsp;
        }

        offset = OFFSET(task_struct_thread) + OFFSET(thread_struct_rsp); 

        return GET_STACK_ULONG(offset);
}

/*
 *  Get the saved PC from the task's thread_struct if it exists;
 *  otherwise just use the pre-determined thread_return value.
 */
static ulong
x86_64_get_pc(struct bt_info *bt)
{
        ulong offset, rip;

	if (INVALID_MEMBER(thread_struct_rip))
		return machdep->machspec->thread_return;

        if (tt->flags & THREAD_INFO) {
                readmem(bt->task + OFFSET(task_struct_thread) +
                        OFFSET(thread_struct_rip), KVADDR,
                        &rip, sizeof(void *),
                        "thread_struct rip", FAULT_ON_ERROR);
		if (rip)
			return rip;
		else
			return machdep->machspec->thread_return;
        }

        offset = OFFSET(task_struct_thread) + OFFSET(thread_struct_rip);

        return GET_STACK_ULONG(offset);
}


/*
 *  Do the work for x86_64_get_sp() and x86_64_get_pc().
 */
static void
get_x86_64_frame(struct bt_info *bt, ulong *getpc, ulong *getsp)
{
	error(FATAL, "get_x86_64_frame: TBD\n");
}

/*
 *  Do the work for cmd_irq().
 */
static void 
x86_64_dump_irq(int irq)
{
        if (symbol_exists("irq_desc") || 
	    kernel_symbol_exists("irq_desc_ptrs") ||
	    kernel_symbol_exists("irq_desc_tree")) {
                machdep->dump_irq = generic_dump_irq;
                return(generic_dump_irq(irq));
        }

        error(FATAL, 
	    "x86_64_dump_irq: irq_desc[] or irq_desc_tree do not exist?\n");
}

static void
x86_64_get_irq_affinity(int irq)
{
        if (symbol_exists("irq_desc") ||
	    kernel_symbol_exists("irq_desc_ptrs") ||
	    kernel_symbol_exists("irq_desc_tree")) {
                machdep->get_irq_affinity = generic_get_irq_affinity;
                return(generic_get_irq_affinity(irq));
        }

        error(FATAL,
	    "x86_64_get_irq_affinity: irq_desc[] or irq_desc_tree do not exist?\n");
}

static void
x86_64_show_interrupts(int irq, ulong *cpus)
{
        if (symbol_exists("irq_desc") ||
	    kernel_symbol_exists("irq_desc_ptrs") ||
	    kernel_symbol_exists("irq_desc_tree")) {
                machdep->show_interrupts = generic_show_interrupts;
                return(generic_show_interrupts(irq, cpus));
        }

        error(FATAL,
	    "x86_64_show_interrupts: irq_desc[] or irq_desc_tree do not exist?\n");
}

/* 
 *  Do the work for irq -d
 */
void 
x86_64_display_idt_table(void)
{
	int i;
	char *idt_table_buf;
	char buf[BUFSIZE];
	ulong *ip;

	if (INVALID_SIZE(gate_struct)) {
		option_not_supported('d');
		return;
	}
	idt_table_buf = GETBUF(SIZE(gate_struct) * 256);
        readmem(symbol_value("idt_table"), KVADDR, idt_table_buf, 
		SIZE(gate_struct) * 256, "idt_table", FAULT_ON_ERROR);
	ip = (ulong *)idt_table_buf;

	for (i = 0; i < 256; i++, ip += 2) {
                if (i < 10)
                        fprintf(fp, "  ");
                else if (i < 100)
                        fprintf(fp, " ");
                fprintf(fp, "[%d] %s\n",
                        i, x86_64_extract_idt_function(ip, buf, NULL));
	}

	FREEBUF(idt_table_buf);
}

static void
x86_64_exception_stacks_init(void)
{
        char *idt_table_buf;
        char buf[BUFSIZE];
	int i;
        ulong *ip, ist;
	long size;
	struct machine_specific *ms;

	ms = machdep->machspec;

	ms->stkinfo.NMI_stack_index = -1;
	for (i = 0; i < MAX_EXCEPTION_STACKS; i++)
		ms->stkinfo.exception_stacks[i] = "(unknown)";

	if (!kernel_symbol_exists("idt_table"))
		return;

        if (INVALID_SIZE(gate_struct))
                size = 16;
	else
		size = SIZE(gate_struct);

        idt_table_buf = GETBUF(size * 256);
        readmem(symbol_value("idt_table"), KVADDR, idt_table_buf,
                size * 256, "idt_table", FAULT_ON_ERROR);
        ip = (ulong *)idt_table_buf;

	if (CRASHDEBUG(1))
		fprintf(fp, "exception IST:\n");

	for (i = 0; i < 256; i++, ip += 2) {
		ist = ((*ip) >> 32) & 0x7;
		if (ist) {
                        x86_64_extract_idt_function(ip, buf, NULL);
			if (CRASHDEBUG(1))
				fprintf(fp, "  %ld: %s\n", ist, buf);
			if (strstr(buf, "nmi")) {
				ms->stkinfo.NMI_stack_index = ist-1; 
				ms->stkinfo.exception_stacks[ist-1] = "NMI";
			}
			if (strstr(buf, "debug"))
				ms->stkinfo.exception_stacks[ist-1] = "DEBUG";
			if (strstr(buf, "stack"))
				ms->stkinfo.exception_stacks[ist-1] = "STACKFAULT";
			if (strstr(buf, "double"))
				ms->stkinfo.exception_stacks[ist-1] = "DOUBLEFAULT";
			if (strstr(buf, "machine"))
				ms->stkinfo.exception_stacks[ist-1] = "MCE";
			if (strstr(buf, "vmm"))
				ms->stkinfo.exception_stacks[ist-1] = "VC";
		}
	}

	if (CRASHDEBUG(1)) {
		fprintf(fp, "exception stacks:\n");
		for (i = 0; i < MAX_EXCEPTION_STACKS; i++) 
			fprintf(fp, "  [%d]: %s\n", i, ms->stkinfo.exception_stacks[i]);
	}

	FREEBUF(idt_table_buf);
}


/*
 *  Extract the function name out of the IDT entry.
 */
static char *
x86_64_extract_idt_function(ulong *ip, char *buf, ulong *retaddr)
{
	ulong i1, i2, addr;
	char locbuf[BUFSIZE];
	physaddr_t phys;

	if (buf)
		BZERO(buf, BUFSIZE);

	i1 = *ip;
	i2 = *(ip+1);

	i2 <<= 32;
	addr = i2 & 0xffffffff00000000;
	addr |= (i1 & 0xffff);
	i1 >>= 32;
	addr |= (i1 & 0xffff0000);

	if (retaddr)
		*retaddr = addr;

	if (!buf)
		return NULL;

	value_to_symstr(addr, locbuf, 0);
	if (strlen(locbuf))
		sprintf(buf, "%s", locbuf);
	else {
		sprintf(buf, "%016lx", addr);
		if (kvtop(NULL, addr, &phys, 0)) {
			addr = machdep->kvbase + (ulong)phys;
			if (value_to_symstr(addr, locbuf, 0)) {
				strcat(buf, "  <");
				strcat(buf, locbuf);
				strcat(buf, ">");
			}
		}
	}

	return buf;
}

/*
 *  Filter disassembly output if the output radix is not gdb's default 10
 */
static int 
x86_64_dis_filter(ulong vaddr, char *inbuf, unsigned int output_radix)
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
 *  (on alpha -- not necessarily seen on x86_64) so this routine both fixes the 
 *  references as well as imposing the current output radix on the translations.
 */
	console(" IN: %s", inbuf);

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
	
	} else if ((STREQ(argv[argc-2], "callq") || (argv[argc-2][0] == 'j')) &&
	    hexadecimal(argv[argc-1], 0)) {
		/*
	 	 *  Update code of the form:
	 	 *
	 	 *    callq  <function-address>
		 *    jmp    <function-address>  
		 *    jCC    <function-address>  
	      	 *
	 	 *  to show a translated, bracketed, target.
	 	 */
		p1 = &LASTCHAR(inbuf);

		if (extract_hex(argv[argc-1], &value, NULLCHAR, TRUE)) {
			sprintf(buf1, " <%s>\n",
				value_to_symstr(value, buf2, output_radix));
			if (!strstr(buf1, "<>"))
				sprintf(p1, "%s", buf1);
		}
        }

	if (value_symbol(vaddr) &&
	    (strstr(inbuf, "nopl   0x0(%rax,%rax,1)") ||
	     strstr(inbuf, "data32 data32 data32 xchg %ax,%ax"))) {
		strip_line_end(inbuf);
		strcat(inbuf, " [FTRACE NOP]\n");
	}

	console("OUT: %s", inbuf);

	return TRUE;
}


/*
 *   Override smp_num_cpus if possible and necessary.
 */
int
x86_64_get_smp_cpus(void)
{
	int i, cpus, nr_pda, cpunumber, _cpu_pda, _boot_cpu_pda;
	char *cpu_pda_buf;
	ulong level4_pgt, cpu_pda_addr;
	struct syment *sp;
	ulong __per_cpu_load = 0, cpu_addr;

	if (!VALID_STRUCT(x8664_pda)) {

		if (!(kt->flags & PER_CPU_OFF))
			return 1;

		if ((sp = per_cpu_symbol_search("pcpu_hot")) &&
		    (cpu_addr = MEMBER_OFFSET("pcpu_hot", "cpu_number")) != INVALID_OFFSET)
			cpu_addr += sp->value;
		else if ((sp = per_cpu_symbol_search("per_cpu__cpu_number")))
			cpu_addr = sp->value;
		else
			return 1;

		if (kernel_symbol_exists("__per_cpu_load"))
			__per_cpu_load = symbol_value("__per_cpu_load");

		for (i = cpus = 0; i < NR_CPUS; i++) {
			if (__per_cpu_load && kt->__per_cpu_offset[i] == __per_cpu_load)
				break;
			if (!readmem(cpu_addr + kt->__per_cpu_offset[i],
			    KVADDR, &cpunumber, sizeof(int),
			    "cpu number (per_cpu)", QUIET|RETURN_ON_ERROR))
				break;
			if (cpunumber != cpus)
				break;
			cpus++;
		}

		if ((i = get_cpus_present()) && (!cpus || (i < cpus)))
			cpus = get_highest_cpu_present() + 1;

		return cpus;
	}

	_boot_cpu_pda = FALSE;
	cpu_pda_buf = GETBUF(SIZE(x8664_pda));

	if (LKCD_KERNTYPES()) {
		if (symbol_exists("_cpu_pda"))
 			_cpu_pda = TRUE;
		else
	 		_cpu_pda = FALSE;
		nr_pda = get_cpus_possible();
	} else {
		if (symbol_exists("_cpu_pda")) {
			if (!(nr_pda = get_array_length("_cpu_pda", NULL, 0)))
				nr_pda = NR_CPUS;
			_cpu_pda = TRUE;
		} else {
			if (!(nr_pda = get_array_length("cpu_pda", NULL, 0)))
				nr_pda = NR_CPUS;
			_cpu_pda = FALSE;
		}
	}
	if (_cpu_pda) {
		if (symbol_exists("_boot_cpu_pda"))
			_boot_cpu_pda = TRUE;
		else
			_boot_cpu_pda = FALSE;
	}
	for (i = cpus = 0; i < nr_pda; i++) {
		if (_cpu_pda) {
			if (_boot_cpu_pda) {
				if (!_CPU_PDA_READ2(i, cpu_pda_buf))
					break;
			} else {
				if (!_CPU_PDA_READ(i, cpu_pda_buf))
					break;
			}
		} else {
			if (!CPU_PDA_READ(i, cpu_pda_buf))
				break;
		}
		if (VALID_MEMBER(x8664_pda_level4_pgt)) {
			level4_pgt = ULONG(cpu_pda_buf + OFFSET(x8664_pda_level4_pgt));
			if (!VALID_LEVEL4_PGT_ADDR(level4_pgt))
				break;
		}
		cpunumber = INT(cpu_pda_buf + OFFSET(x8664_pda_cpunumber));
		if (cpunumber != cpus)
			break;
                cpus++;
	}

	FREEBUF(cpu_pda_buf);

	return cpus;
}

/*
 *  Machine dependent command.
 */
void
x86_64_cmd_mach(void)
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
                        x86_64_display_memmap();
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
		x86_64_display_cpu_data(radix);

	if (!cflag && !mflag)
        	x86_64_display_machine_stats();
}

/*
 *  "mach" command output.
 */
static void
x86_64_display_machine_stats(void)
{
	int i, c;
	struct new_utsname *uts;
	char buf[BUFSIZE];
	ulong mhz;

	uts = &kt->utsname;

	fprintf(fp, "          MACHINE TYPE: %s\n", uts->machine);
	fprintf(fp, "           MEMORY SIZE: %s\n", get_memory_size(buf));
	fprintf(fp, "                  CPUS: %d", kt->cpus);
	if (kt->cpus - get_cpus_to_display())
		fprintf(fp, " [OFFLINE: %d]\n",
			kt->cpus - get_cpus_to_display());
	else
		fprintf(fp, "\n");
	if (!STREQ(kt->hypervisor, "(undetermined)") &&
	    !STREQ(kt->hypervisor, "bare hardware"))
		fprintf(fp, "            HYPERVISOR: %s\n",  kt->hypervisor);
	fprintf(fp, "       PROCESSOR SPEED: ");
	if ((mhz = machdep->processor_speed()))
		fprintf(fp, "%ld Mhz\n", mhz);
	else
		fprintf(fp, "(unknown)\n");
	fprintf(fp, "                    HZ: %d\n", machdep->hz);
	fprintf(fp, "             PAGE SIZE: %d\n", PAGESIZE());
//	fprintf(fp, "         L1 CACHE SIZE: %d\n", l1_cache_size());
	fprintf(fp, "   KERNEL VIRTUAL BASE: %lx\n", machdep->kvbase);
	fprintf(fp, "   KERNEL VMALLOC BASE: %lx\n", vt->vmalloc_start);
	if (machdep->flags & VMEMMAP)
	fprintf(fp, "   KERNEL VMEMMAP BASE: %lx\n", machdep->machspec->vmemmap_vaddr);
	fprintf(fp, "      KERNEL START MAP: %lx\n", __START_KERNEL_map);
	fprintf(fp, "   KERNEL MODULES BASE: %lx\n", MODULES_VADDR);
	fprintf(fp, "     KERNEL STACK SIZE: %ld\n", STACKSIZE());

	fprintf(fp, "        IRQ STACK SIZE: %d\n", machdep->machspec->stkinfo.isize);
	fprintf(fp, "            IRQ STACKS:\n");
	for (c = 0; c < kt->cpus; c++) {
		sprintf(buf, "CPU %d", c);
		
		fprintf(fp, "%22s: %016lx",
			buf, machdep->machspec->stkinfo.ibase[c]);

		if (hide_offline_cpu(c))
			fprintf(fp, " [OFFLINE]\n");
		else
			fprintf(fp, "\n");
	}

	for (i = 0; i < MAX_EXCEPTION_STACKS; i++) {
		if (machdep->machspec->stkinfo.ebase[0][i] == 0)
			break;
		fprintf(fp, "%11s STACK SIZE: %d\n",
			machdep->machspec->stkinfo.exception_stacks[i],
			machdep->machspec->stkinfo.esize[i]);
		sprintf(buf, "%s STACKS:\n", machdep->machspec->stkinfo.exception_stacks[i]);
		fprintf(fp, "%24s", buf);
		for (c = 0; c < kt->cpus; c++) {
			if (machdep->machspec->stkinfo.ebase[c][i] == 0)
				break;
			sprintf(buf, "CPU %d", c);

			fprintf(fp, "%22s: %016lx",
				buf, machdep->machspec->stkinfo.ebase[c][i]);

			if (!machdep->machspec->stkinfo.available[c][i])
				fprintf(fp, " [unavailable]");

			if (hide_offline_cpu(c))
				fprintf(fp, " [OFFLINE]\n");
			else
				fprintf(fp, "\n");
		}
	}
}

/*
 *  "mach -c" 
 */
static void 
x86_64_display_cpu_data(unsigned int radix)
{
        int cpu, cpus, boot_cpu, _cpu_pda;
        ulong cpu_data;
	ulong cpu_pda, cpu_pda_addr;
	struct syment *per_cpu;

	boot_cpu = _cpu_pda = FALSE;
	cpu_data = cpu_pda = 0;
	cpus = 0;
	per_cpu = NULL;

	if (symbol_exists("cpu_data")) {
        	cpu_data = symbol_value("cpu_data");
		cpus = kt->cpus;
		boot_cpu = FALSE;
	} else if ((per_cpu = per_cpu_symbol_search("per_cpu__cpu_info"))) {
		cpus = kt->cpus;
		boot_cpu = FALSE;
	} else if (symbol_exists("boot_cpu_data")) {
        	cpu_data = symbol_value("boot_cpu_data");
		boot_cpu = TRUE;
		cpus = 1;
	}
	if (symbol_exists("_cpu_pda")) {
		cpu_pda = symbol_value("_cpu_pda");
		_cpu_pda = TRUE;
	} else if (symbol_exists("cpu_pda")) {
		cpu_pda = symbol_value("cpu_pda");
		_cpu_pda = FALSE;
	}

        for (cpu = 0; cpu < cpus; cpu++) {
		if (boot_cpu)
                	fprintf(fp, "BOOT CPU:\n");
		else {
			if (hide_offline_cpu(cpu)) {
				fprintf(fp, "%sCPU %d: [OFFLINE]\n", cpu ? "\n" : "", cpu);
				continue;
			} else
				fprintf(fp, "%sCPU %d:\n", cpu ? "\n" : "", cpu);
		}

		if (per_cpu)
			cpu_data = per_cpu->value + kt->__per_cpu_offset[cpu];

                dump_struct("cpuinfo_x86", cpu_data, radix);

		if (_cpu_pda) {
			readmem(cpu_pda, KVADDR, &cpu_pda_addr,
				sizeof(unsigned long), "_cpu_pda addr", FAULT_ON_ERROR);
			fprintf(fp, "\n");
			dump_struct("x8664_pda", cpu_pda_addr, radix);
			cpu_pda += sizeof(void *);
		} else if (VALID_STRUCT(x8664_pda)) {
			fprintf(fp, "\n");
			dump_struct("x8664_pda", cpu_pda, radix);
			cpu_pda += SIZE(x8664_pda);
		}

		if (!per_cpu)
			cpu_data += SIZE(cpuinfo_x86);
        }
}

/*
 *  "mach -m"
 */
static char *e820type[] = {
        "(invalid type)",
        "E820_RAM",
        "E820_RESERVED",
        "E820_ACPI",
        "E820_NVS",
	"E820_UNUSABLE",
};

static void
x86_64_display_memmap(void)
{
        ulong e820;
        int nr_map, i;
        char *buf, *e820entry_ptr;
        ulonglong addr, size;
        uint type;

	if (kernel_symbol_exists("e820")) {
		if (get_symbol_type("e820", NULL, NULL) == TYPE_CODE_PTR)
			get_symbol_data("e820", sizeof(void *), &e820);
		else
			e820 = symbol_value("e820");

	} else if (kernel_symbol_exists("e820_table"))
		get_symbol_data("e820_table", sizeof(void *), &e820);
	else
		error(FATAL, "neither e820 or e820_table symbols exist\n");

	if (CRASHDEBUG(1)) {
		if (STRUCT_EXISTS("e820map"))
			dump_struct("e820map", e820, RADIX(16));
		else if (STRUCT_EXISTS("e820_table"))
			dump_struct("e820_table", e820, RADIX(16));
	}
        buf = (char *)GETBUF(SIZE(e820map));

        readmem(e820, KVADDR, &buf[0], SIZE(e820map),
                "e820map", FAULT_ON_ERROR);

        nr_map = INT(buf + OFFSET(e820map_nr_map));

        fprintf(fp, "      PHYSICAL ADDRESS RANGE         TYPE\n");

        for (i = 0; i < nr_map; i++) {
                e820entry_ptr = buf + sizeof(int) + (SIZE(e820entry) * i);
                addr = ULONGLONG(e820entry_ptr + OFFSET(e820entry_addr));
                size = ULONGLONG(e820entry_ptr + OFFSET(e820entry_size));
                type = UINT(e820entry_ptr + OFFSET(e820entry_type));
		fprintf(fp, "%016llx - %016llx  ", addr, addr+size);
		if (type >= (sizeof(e820type)/sizeof(char *))) {
			if (type == 12)
				fprintf(fp, "E820_PRAM\n");
			else if (type == 128)
				fprintf(fp, "E820_RESERVED_KERN\n");
			else
				fprintf(fp, "type %d\n", type);
		} else
			fprintf(fp, "%s\n", e820type[type]);
        }
}


static const char *hook_files[] = {
        "arch/x86_64/kernel/entry.S",
        "arch/x86_64/kernel/head.S",
        "arch/x86_64/kernel/semaphore.c"
};

#define ENTRY_S      ((char **)&hook_files[0])
#define HEAD_S       ((char **)&hook_files[1])
#define SEMAPHORE_C  ((char **)&hook_files[2])

static struct line_number_hook x86_64_line_number_hooks[] = {
	{"ret_from_fork", ENTRY_S},
	{"system_call", ENTRY_S},
	{"int_ret_from_sys_call", ENTRY_S},
	{"ptregscall_common", ENTRY_S},
	{"stub_execve", ENTRY_S},
	{"stub_rt_sigreturn", ENTRY_S},
	{"common_interrupt", ENTRY_S},
	{"ret_from_intr", ENTRY_S},
	{"load_gs_index", ENTRY_S},
	{"arch_kernel_thread", ENTRY_S},
	{"execve", ENTRY_S},
	{"page_fault", ENTRY_S},
	{"coprocessor_error", ENTRY_S},
	{"simd_coprocessor_error", ENTRY_S},
	{"device_not_available", ENTRY_S},
	{"debug", ENTRY_S},
	{"nmi", ENTRY_S},
	{"int3", ENTRY_S},
	{"overflow", ENTRY_S},
	{"bounds", ENTRY_S},
	{"invalid_op", ENTRY_S},
	{"coprocessor_segment_overrun", ENTRY_S},
	{"reserved", ENTRY_S},
	{"double_fault", ENTRY_S},
	{"invalid_TSS", ENTRY_S},
	{"segment_not_present", ENTRY_S},
	{"stack_segment", ENTRY_S},
	{"general_protection", ENTRY_S},
	{"alignment_check", ENTRY_S},
	{"divide_error", ENTRY_S},
	{"spurious_interrupt_bug", ENTRY_S},
	{"machine_check", ENTRY_S},
	{"call_debug", ENTRY_S},

	{NULL, NULL}    /* list must be NULL-terminated */
};

static void
x86_64_dump_line_number(ulong callpc)
{
	error(FATAL, "x86_64_dump_line_number: TBD\n");
}

void
x86_64_compiler_warning_stub(void)
{
        struct line_number_hook *lhp;
        char **p ATTRIBUTE_UNUSED;

        lhp = &x86_64_line_number_hooks[0]; lhp++;
        p = ENTRY_S;
	x86_64_back_trace(NULL, NULL);
	get_x86_64_frame(NULL, NULL, NULL);
	x86_64_dump_line_number(0);
}

/*
 *  Force the VM address-range selection via:
 *
 *   --machdep vm=orig 
 *   --machdep vm=2.6.11
 *  
 *  Force the phys_base address via:
 *
 *   --machdep phys_base=<address>
 *
 *  Force the IRQ stack back-link via:
 *
 *   --machdep irq_eframe_link=<offset>
 *
 *  Force the IRQ stack gap size via:
 *
 *   --machdep irq_stack_gap=<size>
 *
 *  Force max_physmem_bits via:
 *
 *   --machdep max_physmem_bits=<count>
 */

void
parse_cmdline_args(void)
{
	int index, i, c, errflag;
	char *p;
	char buf[BUFSIZE];
	char *arglist[MAXARGS];
	int megabytes, gigabytes;
	int lines = 0;
	int vm_flag;
	ulong value;

	for (index = 0; index < MAX_MACHDEP_ARGS; index++) {

		if (!machdep->cmdline_args[index])
			break;

		if (!strstr(machdep->cmdline_args[index], "=")) {
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
	
		for (i = vm_flag = 0; i < c; i++) {
			errflag = 0;
	
			if (STRNEQ(arglist[i], "vm=")) {
				vm_flag++;
				p = arglist[i] + strlen("vm=");
				if (strlen(p)) {
					if (STREQ(p, "orig")) {
						machdep->flags |= VM_ORIG;
						continue;
					} else if (STREQ(p, "2.6.11")) {
						machdep->flags |= VM_2_6_11;
						continue;
					} else if (STREQ(p, "xen")) {
						machdep->flags |= VM_XEN;
						continue;
					} else if (STREQ(p, "xen-rhel4")) {
						machdep->flags |= VM_XEN_RHEL4;
						continue;
					} else if (STREQ(p, "5level")) {
						machdep->flags |= VM_5LEVEL;
						continue;
					}
				}
			} else if (STRNEQ(arglist[i], "phys_base=")) {
				megabytes = FALSE;
				if ((LASTCHAR(arglist[i]) == 'm') || 
				    (LASTCHAR(arglist[i]) == 'M')) {
					LASTCHAR(arglist[i]) = NULLCHAR;
					megabytes = TRUE;
				}
	                        p = arglist[i] + strlen("phys_base=");
	                        if (strlen(p)) {
					if (hexadecimal(p, 0) && !decimal(p, 0) &&
					    !STRNEQ(p, "0x") && !STRNEQ(p, "0X"))
						string_insert("0x", p);
					errno = 0;
					value = strtoull(p, NULL, 0);
	                                if (!errno) {
						if (megabytes)
							value = MEGABYTES(value);
	                                        machdep->machspec->phys_base = value;
	                                        error(NOTE,
	                                            "setting phys_base to: 0x%lx\n\n",
	                                                machdep->machspec->phys_base);
						machdep->flags |= PHYS_BASE;
	                                        continue;
	                                }
	                        }
			} else if (STRNEQ(arglist[i], "kernel_image_size=")) {
				megabytes = gigabytes = FALSE;
				if ((LASTCHAR(arglist[i]) == 'm') || 
				    (LASTCHAR(arglist[i]) == 'M')) {
					LASTCHAR(arglist[i]) = NULLCHAR;
					megabytes = TRUE;
				}
				if ((LASTCHAR(arglist[i]) == 'g') || 
				    (LASTCHAR(arglist[i]) == 'G')) {
					LASTCHAR(arglist[i]) = NULLCHAR;
					gigabytes = TRUE;
				}

	                        p = arglist[i] + strlen("kernel_image_size=");
	                        if (strlen(p)) {
					if (megabytes || gigabytes) {
	                                	value = dtol(p, RETURN_ON_ERROR|QUIET,
	                                        	&errflag);
					} else
	                                	value = htol(p, RETURN_ON_ERROR|QUIET,
	                                        	&errflag);
	                                if (!errflag) {
						if (megabytes)
							value = MEGABYTES(value);
						else if (gigabytes)
							value = GIGABYTES(value);
	                                        machdep->machspec->kernel_image_size = value;
	                                        error(NOTE,
	                                            "setting kernel_image_size to: 0x%lx\n\n",
	                                                machdep->machspec->kernel_image_size);
	                                        continue;
	                                }
	                        }
	                } else if (STRNEQ(arglist[i], "irq_eframe_link=")) {
	                        p = arglist[i] + strlen("irq_eframe_link=");
				if (strlen(p)) {
					value = stol(p, RETURN_ON_ERROR|QUIET, &errflag);
					if (!errflag) {
						machdep->machspec->irq_eframe_link = value;
						continue;
					}
				}
	                } else if (STRNEQ(arglist[i], "irq_stack_gap=")) {
	                        p = arglist[i] + strlen("irq_stack_gap=");
				if (strlen(p)) {
					value = stol(p, RETURN_ON_ERROR|QUIET, &errflag);
					if (!errflag) {
						machdep->machspec->irq_stack_gap = value;
						continue;
					}
				}
			} else if (STRNEQ(arglist[i], "max_physmem_bits=")) {
	                        p = arglist[i] + strlen("max_physmem_bits=");
				if (strlen(p)) {
					value = stol(p, RETURN_ON_ERROR|QUIET, &errflag);
					if (!errflag) {
						machdep->max_physmem_bits = value;
	                                        error(NOTE,
	                                            "setting max_physmem_bits to: %ld\n\n",
	                                                machdep->max_physmem_bits);
						continue;
					}
				}
			} else if (STRNEQ(arglist[i], "page_offset=")) {
				p = arglist[i] + strlen("page_offset=");
				if (strlen(p)) {
					value = htol(p, RETURN_ON_ERROR|QUIET, &errflag);

					if (!errflag) {
						machdep->machspec->page_offset_force = value;
						error(NOTE, "setting PAGE_OFFSET to: 0x%lx\n\n",
							machdep->machspec->page_offset_force);
						continue;
					}
				}
			}
	
			error(WARNING, "ignoring --machdep option: %s\n", arglist[i]);
			lines++;
		} 
	
		if (vm_flag) {
			switch (machdep->flags & VM_FLAGS)
			{
			case 0:
				break;
		
			case VM_ORIG:
				error(NOTE, "using original x86_64 VM address ranges\n");
				lines++;
				break;
		
			case VM_2_6_11:
				error(NOTE, "using 2.6.11 x86_64 VM address ranges\n");
				lines++;
				break;
		
			case VM_XEN:
				error(NOTE, "using xen x86_64 VM address ranges\n");
				lines++;
				break;
	
			case VM_XEN_RHEL4:
				error(NOTE, "using RHEL4 xen x86_64 VM address ranges\n");
				lines++;
				break;
		
			case VM_5LEVEL:
				error(NOTE, "using 5-level pagetable x86_64 VM address ranges\n");
				lines++;
				break;

			default:
				error(WARNING, "cannot set multiple vm values\n");
				lines++;
				machdep->flags &= ~VM_FLAGS;
				break;
			} 
		}
	
		if (lines)
			fprintf(fp, "\n");
	}
}

void
x86_64_clear_machdep_cache(void)
{
	if (machdep->last_pgd_read != vt->kernel_pgd[0])
		machdep->last_pgd_read = 0;
}

#define PUSH_RBP_MOV_RSP_RBP 0xe5894855

static void
x86_64_framepointer_init(void)
{
	unsigned int push_rbp_mov_rsp_rbp;
	int i, check;
	char *checkfuncs[] = {"sys_open", "sys_fork", "sys_read",
		"__x64_sys_open", "__x64_sys_fork", "__x64_sys_read",
		"do_futex", "do_fork", "_do_fork", "sys_write", 
		"vfs_read", "__schedule"};

	if (pc->flags & KERNEL_DEBUG_QUERY)
		return;

	for (i = check = 0; i < 12; i++) {
		if (!kernel_symbol_exists(checkfuncs[i]))
			continue;

		if (!readmem(symbol_value(checkfuncs[i]), KVADDR,
		    &push_rbp_mov_rsp_rbp, sizeof(uint),
		    "framepointer check", RETURN_ON_ERROR))
			return;

		if ((push_rbp_mov_rsp_rbp == 0x66666666) ||
		    (push_rbp_mov_rsp_rbp == 0x00441f0f)) {
			if (!readmem(symbol_value(checkfuncs[i]) + 5, 
			    KVADDR, &push_rbp_mov_rsp_rbp, sizeof(uint),
			    "framepointer check", RETURN_ON_ERROR))
				return;
		}

		if (push_rbp_mov_rsp_rbp == PUSH_RBP_MOV_RSP_RBP) {
			if (++check > 2) {
				machdep->flags |= FRAMEPOINTER;
				break;
			}
		}
        }
}

static void
x86_64_ORC_init(void)
{
	int i;
	char *ORC_symbols[] = {
		"lookup_num_blocks",
		"__start_orc_unwind_ip",
		"__stop_orc_unwind_ip",
		"__start_orc_unwind",
		"__stop_orc_unwind",
		"orc_lookup",
		NULL
	};
	struct ORC_data *orc;

	if (machdep->flags & FRAMEPOINTER)
		return;

	STRUCT_SIZE_INIT(orc_entry, "orc_entry");
	if (!VALID_STRUCT(orc_entry))
		return;

	if (!MEMBER_EXISTS("orc_entry", "sp_offset") || 
	    !MEMBER_EXISTS("orc_entry", "bp_offset") ||
	    !MEMBER_EXISTS("orc_entry", "sp_reg") ||
	    !MEMBER_EXISTS("orc_entry", "bp_reg") ||
	    !MEMBER_EXISTS("orc_entry", "type") ||
	    SIZE(orc_entry) != sizeof(kernel_orc_entry)) {
		error(WARNING, "ORC unwinder: orc_entry structure has changed\n");
		return;
	}

	for (i = 0; ORC_symbols[i]; i++) {
		if (!symbol_exists(ORC_symbols[i])) {
			error(WARNING, 
			    "ORC unwinder: %s does not exist in this kernel\n", 
				ORC_symbols[i]);
			return;
		}
	}

	orc = &machdep->machspec->orc;

	MEMBER_OFFSET_INIT(module_arch, "module", "arch");
	MEMBER_OFFSET_INIT(mod_arch_specific_num_orcs, "mod_arch_specific", "num_orcs");
	MEMBER_OFFSET_INIT(mod_arch_specific_orc_unwind_ip, "mod_arch_specific", "orc_unwind_ip");
	MEMBER_OFFSET_INIT(mod_arch_specific_orc_unwind, "mod_arch_specific", "orc_unwind");
	/*
	 *  Nice to have, but not required. 
	 */
	if (VALID_MEMBER(module_arch) &&
	    VALID_MEMBER(mod_arch_specific_num_orcs) &&
	    VALID_MEMBER(mod_arch_specific_orc_unwind_ip) &&
	    VALID_MEMBER(mod_arch_specific_orc_unwind)) {
		orc->module_ORC = TRUE;
	} else {
		orc->module_ORC = FALSE;
		error(WARNING, "ORC unwinder: module orc_entry structures have changed\n");
	}
		
	if (!readmem(symbol_value("lookup_num_blocks"), KVADDR, &orc->lookup_num_blocks, 
	    sizeof(unsigned int), "lookup_num_blocks", RETURN_ON_ERROR|QUIET)) {
		error(WARNING, "ORC unwinder: cannot read lookup_num_blocks\n"); 
		return;
	} 

	orc->__start_orc_unwind_ip = symbol_value("__start_orc_unwind_ip");
	orc->__stop_orc_unwind_ip = symbol_value("__stop_orc_unwind_ip");
	orc->__start_orc_unwind = symbol_value("__start_orc_unwind");
	orc->__stop_orc_unwind = symbol_value("__stop_orc_unwind");
	orc->orc_lookup = symbol_value("orc_lookup");

	MEMBER_OFFSET_INIT(inactive_task_frame_bp, "inactive_task_frame", "bp");
	MEMBER_OFFSET_INIT(inactive_task_frame_ret_addr, "inactive_task_frame", "ret_addr");

	machdep->flags |= ORC;
}


static ulong
search_for_switch_to(ulong start, ulong end)
{
	ulong max_instructions, address;
	char buf1[BUFSIZE];
	char search_string1[BUFSIZE];
	char search_string2[BUFSIZE];
	char search_string3[BUFSIZE];
	char search_string4[BUFSIZE];
	int found;

	max_instructions = end - start;
	found = FALSE;
	search_string1[0] = search_string2[0] = NULLCHAR;
	search_string3[0] = search_string4[0] = NULLCHAR;
	sprintf(buf1, "x/%ldi 0x%lx", max_instructions, start);

	if (symbol_exists("__switch_to")) {
		sprintf(search_string1,
			"callq  0x%lx", symbol_value("__switch_to"));
		sprintf(search_string2,
			"call   0x%lx", symbol_value("__switch_to"));
	}
	if (symbol_exists("__switch_to_asm")) {
		sprintf(search_string3, 
			"callq  0x%lx", symbol_value("__switch_to_asm"));
		sprintf(search_string4,
			"call   0x%lx", symbol_value("__switch_to_asm"));
	}

	open_tmpfile();

	if (!gdb_pass_through(buf1, pc->tmpfile, GNU_RETURN_ON_ERROR))
		return FALSE;

	rewind(pc->tmpfile);
	while (fgets(buf1, BUFSIZE, pc->tmpfile)) {
		if (found)
			break;
		if (strstr(buf1, "<__switch_to>"))
			found = TRUE;
		if (strlen(search_string1) && strstr(buf1, search_string1))
			found = TRUE;
		if (strlen(search_string2) && strstr(buf1, search_string2))
			found = TRUE;
		if (strlen(search_string3) && strstr(buf1, search_string3))
			found = TRUE;
		if (strlen(search_string4) && strstr(buf1, search_string4))
			found = TRUE;
	}
	close_tmpfile();

	if (found && extract_hex(buf1, &address, ':', TRUE))
		return address;

	return 0;
}

static void
x86_64_thread_return_init(void)
{
	struct syment *sp, *spn;
	ulong address;

	if ((sp = kernel_symbol_search("thread_return"))) {
		machdep->machspec->thread_return = sp->value;
		return;
	}

	if ((sp = kernel_symbol_search("schedule")) &&
	    (spn = next_symbol(NULL, sp)) &&
	    (address = search_for_switch_to(sp->value, spn->value))) {
		machdep->machspec->thread_return = address;
		return;
	}

	if ((sp = kernel_symbol_search("__schedule")) &&
	    (spn = next_symbol(NULL, sp)) &&
	    (address = search_for_switch_to(sp->value, spn->value))) {
		machdep->machspec->thread_return = address;
		return;
	}

	error(INFO, "cannot determine thread return address\n");
	machdep->machspec->thread_return = 
		(sp = kernel_symbol_search("schedule")) ?  sp->value : 0;
}

static void 
x86_64_irq_eframe_link_init(void)
{
	int c;
	struct syment *sp, *spn;
	char buf[BUFSIZE];
	char link_register[BUFSIZE];
        char *arglist[MAXARGS];

	if (machdep->machspec->irq_eframe_link == UNINITIALIZED)
		machdep->machspec->irq_eframe_link = 0;
	else
		return; 

	if (symbol_exists("asm_common_interrupt")) {
		if (symbol_exists("asm_call_on_stack"))
			machdep->machspec->irq_eframe_link = -64;
		else
			machdep->machspec->irq_eframe_link = -32;
		return;
	}

	if (THIS_KERNEL_VERSION < LINUX(2,6,9)) 
		return;

	if (!(sp = symbol_search("common_interrupt")) ||
	    !(spn = next_symbol(NULL, sp))) {
		return;
	}

	open_tmpfile();

        sprintf(buf, "disassemble 0x%lx, 0x%lx",
		sp->value, spn->value);

        if (!gdb_pass_through(buf, pc->tmpfile, GNU_RETURN_ON_ERROR))
		return;

	link_register[0] = NULLCHAR;

	rewind(pc->tmpfile);
        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
		if (STRNEQ(buf, "Dump of assembler code"))
			continue;
		if (!strstr(buf, sp->name))
			break;
		if ((c = parse_line(buf, arglist)) < 4)
			continue;
		if (strstr(arglist[2], "push"))
			strcpy(link_register, arglist[3]);
	}
	close_tmpfile();

	if (CRASHDEBUG(1)) 
		fprintf(fp, "IRQ stack link register: %s\n", 
		    strlen(link_register) ? 
			link_register : "undetermined");

	if (STREQ(link_register, "%rbp"))
		machdep->machspec->irq_eframe_link = 40;
	else if (THIS_KERNEL_VERSION >= LINUX(2,6,29)) 
		machdep->machspec->irq_eframe_link = 40;
}

/*
 *  Calculate and verify the IRQ exception frame location from the 
 *  stack reference at the top of the IRQ stack, possibly adjusting
 *  the ms->irq_eframe_link value.
 */
static ulong
x86_64_irq_eframe_link(ulong stkref, struct bt_info *bt, FILE *ofp)
{
	ulong irq_eframe;

	if (x86_64_exception_frame(EFRAME_VERIFY, stkref, 0, bt, ofp))
		return stkref;

	irq_eframe = stkref - machdep->machspec->irq_eframe_link;

	if (x86_64_exception_frame(EFRAME_VERIFY, irq_eframe, 0, bt, ofp))
		return irq_eframe;

	if (x86_64_exception_frame(EFRAME_VERIFY, irq_eframe+8, 0, bt, ofp)) {
		machdep->machspec->irq_eframe_link -= 8;
		return (irq_eframe + 8);
	}

	return irq_eframe;
}

#include "netdump.h"
#include "xen_dom0.h"

/*
 *  From the xen vmcore, create an index of mfns for each page that makes
 *  up the dom0 kernel's complete phys_to_machine_mapping[max_pfn] array.
 */

#define MAX_X86_64_FRAMES  (512)
#define MFNS_PER_FRAME     (PAGESIZE()/sizeof(ulong))

static int
x86_64_xen_kdump_p2m_create(struct xen_kdump_data *xkd)
{
        int i, j;
        ulong kvaddr;
        ulong *up;
        ulong frames;
        ulong frame_mfn[MAX_X86_64_FRAMES] = { 0 };
        int mfns[MAX_X86_64_FRAMES] = { 0 };
	struct syment *sp;

        /*
         *  Temporarily read physical (machine) addresses from vmcore.
         */
	pc->curcmd_flags |= XEN_MACHINE_ADDR;
	if (CRASHDEBUG(1))
		fprintf(fp, "readmem (temporary): force XEN_MACHINE_ADDR\n");

        if (xkd->flags & KDUMP_CR3)
                goto use_cr3;

        if (CRASHDEBUG(1))
                fprintf(fp, "x86_64_xen_kdump_p2m_create: p2m_mfn: %lx\n", 
			xkd->p2m_mfn);

	if (!readmem(PTOB(xkd->p2m_mfn), PHYSADDR, xkd->page, PAGESIZE(), 
	    "xen kdump p2m mfn page", RETURN_ON_ERROR))
		error(FATAL, "cannot read xen kdump p2m mfn page\n");

	if (CRASHDEBUG(2))
		x86_64_debug_dump_page(fp, xkd->page, "pfn_to_mfn_frame_list");

	for (i = 0, up = (ulong *)xkd->page; i < MAX_X86_64_FRAMES; i++, up++)
		frame_mfn[i] = *up;

	for (i = 0; i < MAX_X86_64_FRAMES; i++) {
		if (!frame_mfn[i])
			break;

        	if (!readmem(PTOB(frame_mfn[i]), PHYSADDR, xkd->page, 
		    PAGESIZE(), "xen kdump p2m mfn list page", RETURN_ON_ERROR))
                	error(FATAL, "cannot read xen kdump p2m mfn list page\n");

		for (j = 0, up = (ulong *)xkd->page; j < MFNS_PER_FRAME; j++, up++)
			if (*up)
				mfns[i]++;

		xkd->p2m_frames += mfns[i];
		
	        if (CRASHDEBUG(7))
			x86_64_debug_dump_page(fp, xkd->page, "pfn_to_mfn_frame_list page");
	}

        if (CRASHDEBUG(1))
		fprintf(fp, "p2m_frames: %d\n", xkd->p2m_frames);

        if ((xkd->p2m_mfn_frame_list = (ulong *)
	    malloc(xkd->p2m_frames * sizeof(ulong))) == NULL)
                error(FATAL, "cannot malloc p2m_frame_index_list");

	for (i = 0, frames = xkd->p2m_frames; frames; i++) {
        	if (!readmem(PTOB(frame_mfn[i]), PHYSADDR, 
		    &xkd->p2m_mfn_frame_list[i * MFNS_PER_FRAME], 
		    mfns[i] * sizeof(ulong), "xen kdump p2m mfn list page", 
		    RETURN_ON_ERROR))
                	error(FATAL, "cannot read xen kdump p2m mfn list page\n");

		frames -= mfns[i];
	}

	if (CRASHDEBUG(2)) {
		for (i = 0; i < xkd->p2m_frames; i++)
		    	fprintf(fp, "%lx ", xkd->p2m_mfn_frame_list[i]);
		fprintf(fp, "\n");
	}

	pc->curcmd_flags &= ~XEN_MACHINE_ADDR;
	if (CRASHDEBUG(1))
		fprintf(fp, "readmem (restore): p2m translation\n");

	return TRUE;

use_cr3:

        if (CRASHDEBUG(1))
                fprintf(fp, "x86_64_xen_kdump_p2m_create: cr3: %lx\n", xkd->cr3);

        if (!readmem(PTOB(xkd->cr3), PHYSADDR, machdep->pgd,
	    PAGESIZE(), "xen kdump cr3 page", RETURN_ON_ERROR))
                error(FATAL, "cannot read xen kdump cr3 page\n");

        if (CRASHDEBUG(7))
                x86_64_debug_dump_page(fp, machdep->pgd,
                        "contents of PML4 page:");

	/*
	 * kernel version <  2.6.27 => end_pfn
	 * kernel version >= 2.6.27 => max_pfn
	 */
	if ((sp = symbol_search("end_pfn")))
		kvaddr = sp->value;
	else
		kvaddr = symbol_value("max_pfn");

        if (!x86_64_xen_kdump_load_page(kvaddr, xkd->page))
                return FALSE;
        up = (ulong *)(xkd->page + PAGEOFFSET(kvaddr));

        xkd->p2m_frames = (*up/(PAGESIZE()/sizeof(ulong))) +
                ((*up%(PAGESIZE()/sizeof(ulong))) ? 1 : 0);

        if (CRASHDEBUG(1))
                fprintf(fp, "end_pfn at %lx: %lx (%ld) -> %d p2m_frames\n",
                        kvaddr, *up, *up, xkd->p2m_frames);

        if ((xkd->p2m_mfn_frame_list = (ulong *)
            malloc(xkd->p2m_frames * sizeof(ulong))) == NULL)
                error(FATAL, "cannot malloc p2m_frame_index_list");

        kvaddr = symbol_value("phys_to_machine_mapping");
        if (!x86_64_xen_kdump_load_page(kvaddr, xkd->page))
                return FALSE;
        up = (ulong *)(xkd->page + PAGEOFFSET(kvaddr));
        kvaddr = *up;
        if (CRASHDEBUG(1))
                fprintf(fp, "phys_to_machine_mapping: %lx\n", kvaddr);

        machdep->last_pud_read = BADADDR;
        machdep->last_pmd_read = BADADDR;
        machdep->last_ptbl_read = BADADDR;

        for (i = 0; i < xkd->p2m_frames; i++) {
                xkd->p2m_mfn_frame_list[i] = x86_64_xen_kdump_page_mfn(kvaddr);
                kvaddr += PAGESIZE();
        }

        if (CRASHDEBUG(1)) {
                for (i = 0; i < xkd->p2m_frames; i++)
                        fprintf(fp, "%lx ", xkd->p2m_mfn_frame_list[i]);
                fprintf(fp, "\n");
        }

	machdep->last_pud_read = 0;
        machdep->last_ptbl_read = 0;
        machdep->last_pmd_read = 0;
	pc->curcmd_flags &= ~XEN_MACHINE_ADDR;
	if (CRASHDEBUG(1))
		fprintf(fp, "readmem (restore): p2m translation\n");

        return TRUE;
}

static char *
x86_64_xen_kdump_load_page(ulong kvaddr, char *pgbuf)
{
	ulong mfn;
	ulong *pgd, *pud, *pmd, *ptep;

        pgd = ((ulong *)machdep->pgd) + pgd_index(kvaddr);
	mfn = ((*pgd) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

	if (CRASHDEBUG(3))
		fprintf(fp, 
		    "[%lx] pgd: %lx  mfn: %lx  pgd_index: %lx\n",
			kvaddr, *pgd, mfn, pgd_index(kvaddr));

        if (!readmem(PTOB(mfn), PHYSADDR, machdep->pud, PAGESIZE(),
            "xen kdump pud page", RETURN_ON_ERROR))
		error(FATAL, "cannot read/find pud page\n");

	machdep->last_pud_read = mfn;
        
        if (CRASHDEBUG(7))
		x86_64_debug_dump_page(fp, machdep->pud,
                	"contents of page upper directory page:");

        pud = ((ulong *)machdep->pud) + pud_index(kvaddr);
	mfn = ((*pud) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

	if (CRASHDEBUG(3))
		fprintf(fp, 
		    "[%lx] pud: %lx  mfn: %lx  pud_index: %lx\n",
			kvaddr, *pgd, mfn, pud_index(kvaddr));

	if (!readmem(PTOB(mfn), PHYSADDR, machdep->pmd, PAGESIZE(),
            "xen kdump pmd page", RETURN_ON_ERROR))
                error(FATAL, "cannot read/find pmd page\n");

	machdep->last_pmd_read = mfn;

        if (CRASHDEBUG(7)) 
		x86_64_debug_dump_page(fp, machdep->pmd, 
			"contents of page middle directory page:");

        pmd = ((ulong *)machdep->pmd) + pmd_index(kvaddr);
	mfn = ((*pmd) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

	if (CRASHDEBUG(3))
		fprintf(fp, 
		    "[%lx] pmd: %lx  mfn: %lx  pmd_index: %lx\n", 
			kvaddr, *pmd, mfn, pmd_index(kvaddr));

       if (!readmem(PTOB(mfn), PHYSADDR, machdep->ptbl, PAGESIZE(),
            "xen kdump page table page", RETURN_ON_ERROR))
                error(FATAL, "cannot read/find page table page\n");

	machdep->last_ptbl_read = mfn;

        if (CRASHDEBUG(7)) 
		x86_64_debug_dump_page(fp, machdep->ptbl, 
			"contents of page table page:");

        ptep = ((ulong *)machdep->ptbl) + pte_index(kvaddr);
	mfn = ((*ptep) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

	if (CRASHDEBUG(3))
		fprintf(fp, 
		    "[%lx] ptep: %lx  mfn: %lx  pte_index: %lx\n", 
			kvaddr, *ptep, mfn, pte_index(kvaddr));

       if (!readmem(PTOB(mfn), PHYSADDR, pgbuf, PAGESIZE(),
            "xen kdump page table page", RETURN_ON_ERROR))
                error(FATAL, "cannot read/find pte page\n");

        if (CRASHDEBUG(7)) 
		x86_64_debug_dump_page(fp, pgbuf, 
			"contents of page:");

	return pgbuf;
}

static ulong 
x86_64_xen_kdump_page_mfn(ulong kvaddr)
{
	ulong mfn;
	ulong *pgd, *pud, *pmd, *ptep;

        pgd = ((ulong *)machdep->pgd) + pgd_index(kvaddr);
	mfn = ((*pgd) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

        if ((mfn != machdep->last_pud_read) && 
	    !readmem(PTOB(mfn), PHYSADDR, machdep->pud, PAGESIZE(),
            "xen kdump pud entry", RETURN_ON_ERROR))
		error(FATAL, "cannot read/find pud page\n");
        machdep->last_pud_read = mfn;

        pud = ((ulong *)machdep->pud) + pud_index(kvaddr);
	mfn = ((*pud) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

        if ((mfn != machdep->last_pmd_read) &&
            !readmem(PTOB(mfn), PHYSADDR, machdep->pmd, PAGESIZE(),
            "xen kdump pmd entry", RETURN_ON_ERROR))
                error(FATAL, "cannot read/find pmd page\n");
        machdep->last_pmd_read = mfn;

        pmd = ((ulong *)machdep->pmd) + pmd_index(kvaddr);
	mfn = ((*pmd) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

        if ((mfn != machdep->last_ptbl_read) && 
            !readmem(PTOB(mfn), PHYSADDR, machdep->ptbl, PAGESIZE(),
            "xen kdump page table page", RETURN_ON_ERROR))
                error(FATAL, "cannot read/find page table page\n");
        machdep->last_ptbl_read = mfn;

        ptep = ((ulong *)machdep->ptbl) + pte_index(kvaddr);
	mfn = ((*ptep) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

	return mfn;
}

#include "xendump.h"

static int
in_START_KERNEL_map(ulong vaddr)
{
	if (machdep->machspec->kernel_image_size &&
	    ((vaddr >= __START_KERNEL_map) && 
	    (vaddr < (__START_KERNEL_map + machdep->machspec->kernel_image_size))))
		return TRUE;

	if ((vaddr >= __START_KERNEL_map) &&
	    (vaddr < highest_bss_symbol())) 
		return TRUE; 

	return FALSE;
}

/*
 *  Determine the physical address base for relocatable kernels.
 */
static void
x86_64_calc_phys_base(void)
{
	int i;
	FILE *iomem;
	char buf[BUFSIZE];
	char *p1;
	ulong phys_base, text_start, kernel_code_start;
	int errflag;
	struct vmcore_data *vd;
	static struct xendump_data *xd;
	Elf64_Phdr *phdr;

	if (machdep->flags & PHYS_BASE)     /* --machdep override */
		return;

	machdep->machspec->phys_base = 0;   /* default/traditional */

	if (pc->flags2 & GET_LOG) 
		text_start = BADADDR;
	else {
		if (!kernel_symbol_exists("phys_base"))
			return;
		if (!symbol_exists("_text"))
			return;
		else
			text_start = symbol_value("_text");
		if (REMOTE()) {
			phys_base = get_remote_phys_base(text_start, symbol_value("phys_base"));
			if (phys_base) {
				machdep->machspec->phys_base = phys_base;
				if (CRASHDEBUG(1)) {
					fprintf(fp, "_text: %lx  ", text_start);
					fprintf(fp, "phys_base: %lx\n\n",
						machdep->machspec->phys_base);
				}
				return;
			}
		}
	}

	/*
	 * Linux 4.10 exports it in VMCOREINFO (finally).
	 */
	if ((p1 = pc->read_vmcoreinfo("NUMBER(phys_base)"))) {
		if (*p1 == '-')
			machdep->machspec->phys_base = dtol(p1+1, QUIET, NULL) * -1;
		else
			machdep->machspec->phys_base = dtol(p1, QUIET, NULL);
		if (CRASHDEBUG(1))
			fprintf(fp, "VMCOREINFO: NUMBER(phys_base): %s -> %lx\n", 
				p1, machdep->machspec->phys_base);
		free(p1);
		return;
	}

	if (LOCAL_ACTIVE()) {
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
	
		machdep->machspec->phys_base = kernel_code_start -
			(text_start - __START_KERNEL_map);
	
		if (CRASHDEBUG(1)) {
			fprintf(fp, "_text: %lx  ", text_start);
			fprintf(fp, "Kernel code: %lx -> ", kernel_code_start);
			fprintf(fp, "phys_base: %lx\n\n", 
				machdep->machspec->phys_base);
		}

		return;
	}

	/*
	 *  Get relocation value from whatever dumpfile format is being used.
	 */

	if (QEMU_MEM_DUMP_NO_VMCOREINFO()) {
		if ((KDUMP_DUMPFILE() && kdump_phys_base(&phys_base)) ||
		    (DISKDUMP_DUMPFILE() && diskdump_phys_base(&phys_base)))
			machdep->machspec->phys_base = phys_base;

		if (!x86_64_virt_phys_base())
			error(WARNING,
				"cannot determine physical base address:"
				" defaulting to %lx\n\n",
				machdep->machspec->phys_base);
		return;
	}

	if (VMSS_DUMPFILE()) {
		if (vmware_vmss_phys_base(&phys_base)) {
			machdep->machspec->phys_base = phys_base;
			if (!x86_64_virt_phys_base())
				error(WARNING,
				    "cannot determine physical base address:"
				    " defaulting to %lx\n\n",
					machdep->machspec->phys_base);
			if (CRASHDEBUG(1))
				fprintf(fp, "compressed kdump: phys_base: %lx\n",
				    phys_base);
		}
		return;
	}

	if (DISKDUMP_DUMPFILE()) {
		if (diskdump_phys_base(&phys_base)) {
			machdep->machspec->phys_base = phys_base;
			if ((pc->flags2 & QEMU_MEM_DUMP_COMPRESSED) && 
			    !x86_64_virt_phys_base())
				error(WARNING,
				    "cannot determine physical base address:"
				    " defaulting to %lx\n\n",
					machdep->machspec->phys_base);
			if (CRASHDEBUG(1))
				fprintf(fp, "compressed kdump: phys_base: %lx\n",
					phys_base);
		}
		return;
	}

	if (KVMDUMP_DUMPFILE()) {
		if (kvmdump_phys_base(&phys_base)) {
			machdep->machspec->phys_base = phys_base;
			if (CRASHDEBUG(1))
				fprintf(fp, "kvmdump: phys_base: %lx\n",
					phys_base);
		} else {
			machdep->machspec->phys_base = phys_base;
			if (!x86_64_virt_phys_base())
				error(WARNING, 
				    "cannot determine physical base address:"
				    " defaulting to %lx\n\n", 
					phys_base);
		}
		return;
	}

	if (SADUMP_DUMPFILE()) {
		if (sadump_phys_base(&phys_base)) {
			machdep->machspec->phys_base = phys_base;
			if (CRASHDEBUG(1))
				fprintf(fp, "sadump: phys_base: %lx\n",
					phys_base);
		} else {
			machdep->machspec->phys_base = phys_base;
			if (!x86_64_virt_phys_base())
				error(WARNING,
				      "cannot determine physical base address:"
				      " defaulting to %lx\n\n",
				      phys_base);
		}
		return;
	}

	if ((vd = get_kdump_vmcore_data())) {
                for (i = 0; i < vd->num_pt_load_segments; i++) {
			phdr = vd->load64 + i;
			if ((phdr->p_vaddr >= __START_KERNEL_map) &&
			    (in_START_KERNEL_map(phdr->p_vaddr) || 
			    !(IS_VMALLOC_ADDR(phdr->p_vaddr)))) {

				machdep->machspec->phys_base = phdr->p_paddr - 
				    (phdr->p_vaddr & ~(__START_KERNEL_map));

				if (CRASHDEBUG(1)) {
					fprintf(fp, "p_vaddr: %lx p_paddr: %lx -> ",
						phdr->p_vaddr, phdr->p_paddr);
					fprintf(fp, "phys_base: %lx\n\n", 
						machdep->machspec->phys_base);
				}
				break;
			}
		}

		if ((pc->flags2 & QEMU_MEM_DUMP_ELF) && !x86_64_virt_phys_base())
			error(WARNING,
			    "cannot determine physical base address:"
			    " defaulting to %lx\n\n",
			      	machdep->machspec->phys_base);

		return;
	}

	if ((xd = get_xendump_data())) {
		if (text_start == __START_KERNEL_map) {
		       /* 
			*  Xen kernels are not relocable (yet) and don't have
			*  the "phys_base" entry point, so this is most likely 
			*  a xendump of a fully-virtualized relocatable kernel.
			*  No clues exist in the xendump header, so hardwire 
			*  phys_base to 2MB and hope for the best.
			*/
			machdep->machspec->phys_base = 0x200000;
			if (CRASHDEBUG(1))
				fprintf(fp, 
			    	    "default relocatable phys_base: %lx\n",
					machdep->machspec->phys_base);

		} else if (text_start > __START_KERNEL_map) {
			switch (xd->flags & (XC_CORE_ELF|XC_CORE_NO_P2M)) 	
			{
			/*
			 *  If this is a new ELF-style xendump with no
			 *  p2m information, then it also must be a
			 *  fully-virtualized relocatable kernel.  Again,
			 *  the xendump header is useless, and we don't
			 *  have /proc/iomem, so presume that the kernel 
			 *  code starts at 2MB.
			 */ 
			case (XC_CORE_ELF|XC_CORE_NO_P2M):
				machdep->machspec->phys_base = 0x200000 - 
					(text_start - __START_KERNEL_map);
				if (CRASHDEBUG(1))
					fprintf(fp, "default relocatable " 
			    	            "phys_base: %lx\n",
						machdep->machspec->phys_base);
				break;

			default:
				break;
			}
		}

		if (xd->xc_core.header.xch_magic == XC_CORE_MAGIC_HVM)
			x86_64_virt_phys_base();
	}
}

/*
 *  Verify, or possibly override, the xendump/kvmdump phys_base 
 *  calculation by trying to read linux_banner from a range of 
 *  typical physical offsets.
 */
static int
x86_64_virt_phys_base(void)
{
	char buf[BUFSIZE];
	struct syment *sp;
	ulong phys, linux_banner_phys;

	if (!(sp = symbol_search("linux_banner")) ||
	    !((sp->type == 'R') || (sp->type == 'r') ||
	    (sp->type == 'D')))
		return FALSE;

	linux_banner_phys = sp->value - __START_KERNEL_map;

	if (readmem(linux_banner_phys + machdep->machspec->phys_base,
	    PHYSADDR, buf, strlen("Linux version"), "linux_banner verify", 
	    QUIET|RETURN_ON_ERROR) && STRNEQ(buf, "Linux version"))
		return TRUE;

	for (phys = (ulong)(-MEGABYTES(32)); phys != 0xfffff00000; 
	     phys += MEGABYTES(1)) {
		if (readmem(linux_banner_phys + phys, PHYSADDR, buf,
		    strlen("Linux version"), "linux_banner search", 
		    QUIET|RETURN_ON_ERROR) && STRNEQ(buf, "Linux version")) {
			if (CRASHDEBUG(1))
				fprintf(fp,
				    "virtual dump phys_base: %lx %s\n", phys, 
					machdep->machspec->phys_base != phys ?
					"override" : "");
			machdep->machspec->phys_base = phys;
			return TRUE;
		}
	}

	return FALSE;
}

/*
 *  Create an index of mfns for each page that makes up the
 *  kernel's complete phys_to_machine_mapping[max_pfn] array.
 */
static int 
x86_64_xendump_p2m_create(struct xendump_data *xd)
{
	int i, idx;
	ulong mfn, kvaddr, ctrlreg[8], ctrlreg_offset;
	ulong *up;
	off_t offset; 
	struct syment *sp;

	/*
	 *  Check for pvops Xen kernel before presuming it's HVM.
	 */
	if (symbol_exists("pv_init_ops") &&
	    (symbol_exists("xen_patch") || symbol_exists("paravirt_patch_default")) &&
	    (xd->xc_core.header.xch_magic == XC_CORE_MAGIC))
		return x86_64_pvops_xendump_p2m_create(xd);

        if (!symbol_exists("phys_to_machine_mapping")) {
                xd->flags |= XC_CORE_NO_P2M;
                return TRUE;
        }

	if ((ctrlreg_offset = MEMBER_OFFSET("vcpu_guest_context", "ctrlreg")) ==
	     INVALID_OFFSET)
		error(FATAL, 
		    "cannot determine vcpu_guest_context.ctrlreg offset\n");
	else if (CRASHDEBUG(1))
		fprintf(xd->ofp, 
		    "MEMBER_OFFSET(vcpu_guest_context, ctrlreg): %ld\n",
			ctrlreg_offset);

	offset = xd->xc_core.header.xch_ctxt_offset +
		(off_t)ctrlreg_offset;

	if (lseek(xd->xfd, offset, SEEK_SET) == -1)
		error(FATAL, "cannot lseek to xch_ctxt_offset\n");

	if (read(xd->xfd, &ctrlreg, sizeof(ctrlreg)) !=
	    sizeof(ctrlreg))
		error(FATAL, "cannot read vcpu_guest_context ctrlreg[8]\n");

	for (i = 0; CRASHDEBUG(1) && (i < 8); i++)
		fprintf(xd->ofp, "ctrlreg[%d]: %lx\n", i, ctrlreg[i]);

	mfn = ctrlreg[3] >> PAGESHIFT();

	if (!xc_core_mfn_to_page(mfn, machdep->pgd))
		error(FATAL, "cannot read/find cr3 page\n");

	if (CRASHDEBUG(7)) 
		x86_64_debug_dump_page(xd->ofp, machdep->pgd,
						"contents of PGD page:");

	/*
	 * kernel version <  2.6.27 => end_pfn
	 * kernel version >= 2.6.27 => max_pfn
	 */
	if ((sp = symbol_search("end_pfn")))
		kvaddr = sp->value;
	else
		kvaddr = symbol_value("max_pfn");

	if (!x86_64_xendump_load_page(kvaddr, xd))
		return FALSE;

	up = (ulong *)(xd->page + PAGEOFFSET(kvaddr));
	if (CRASHDEBUG(1))
		fprintf(xd->ofp, "end pfn: %lx\n", *up);

	xd->xc_core.p2m_frames = (*up/(PAGESIZE()/sizeof(ulong))) +
                ((*up%(PAGESIZE()/sizeof(ulong))) ? 1 : 0);

	if ((xd->xc_core.p2m_frame_index_list = (ulong *)
	    malloc(xd->xc_core.p2m_frames * sizeof(ulong))) == NULL)
        	error(FATAL, "cannot malloc p2m_frame_list");

	kvaddr = symbol_value("phys_to_machine_mapping");
	if (!x86_64_xendump_load_page(kvaddr, xd))
		return FALSE;

	up = (ulong *)(xd->page + PAGEOFFSET(kvaddr));
	if (CRASHDEBUG(1))
		fprintf(fp, "phys_to_machine_mapping: %lx\n", *up);

	kvaddr = *up;
	machdep->last_ptbl_read = BADADDR;

	for (i = 0; i < xd->xc_core.p2m_frames; i++) {
		if ((idx = x86_64_xendump_page_index(kvaddr, xd)) == MFN_NOT_FOUND)
			return FALSE;
		xd->xc_core.p2m_frame_index_list[i] = idx; 
		kvaddr += PAGESIZE();
	}

	machdep->last_ptbl_read = 0;

	return TRUE;
}

static int 
x86_64_pvops_xendump_p2m_create(struct xendump_data *xd)
{
	int i;
	ulong mfn, kvaddr, ctrlreg[8], ctrlreg_offset;
	ulong *up;
	off_t offset; 
	struct syment *sp;

	if ((ctrlreg_offset = MEMBER_OFFSET("vcpu_guest_context", "ctrlreg")) ==
	     INVALID_OFFSET)
		error(FATAL, 
		    "cannot determine vcpu_guest_context.ctrlreg offset\n");
	else if (CRASHDEBUG(1))
		fprintf(xd->ofp, 
		    "MEMBER_OFFSET(vcpu_guest_context, ctrlreg): %ld\n",
			ctrlreg_offset);

	offset = xd->xc_core.header.xch_ctxt_offset +
		(off_t)ctrlreg_offset;

	if (lseek(xd->xfd, offset, SEEK_SET) == -1)
		error(FATAL, "cannot lseek to xch_ctxt_offset\n");

	if (read(xd->xfd, &ctrlreg, sizeof(ctrlreg)) !=
	    sizeof(ctrlreg))
		error(FATAL, "cannot read vcpu_guest_context ctrlreg[8]\n");

	for (i = 0; CRASHDEBUG(1) && (i < 8); i++)
		fprintf(xd->ofp, "ctrlreg[%d]: %lx\n", i, ctrlreg[i]);

	mfn = ctrlreg[3] >> PAGESHIFT();

	if (!xc_core_mfn_to_page(mfn, machdep->pgd))
		error(FATAL, "cannot read/find cr3 page\n");

	if (CRASHDEBUG(7)) 
		x86_64_debug_dump_page(xd->ofp, machdep->pgd,
			"contents of PGD page:");

	/*
	 * kernel version <  2.6.27 => end_pfn
	 * kernel version >= 2.6.27 => max_pfn
	 */
	if ((sp = symbol_search("end_pfn")))
		kvaddr = sp->value;
	else
		kvaddr = symbol_value("max_pfn");

	if (!x86_64_xendump_load_page(kvaddr, xd))
		return FALSE;

	up = (ulong *)(xd->page + PAGEOFFSET(kvaddr));
	if (CRASHDEBUG(1))
		fprintf(xd->ofp, "end pfn: %lx\n", *up);

	xd->xc_core.p2m_frames = (*up/(PAGESIZE()/sizeof(ulong))) +
                ((*up%(PAGESIZE()/sizeof(ulong))) ? 1 : 0);

	if ((xd->xc_core.p2m_frame_index_list = (ulong *)
	    malloc(xd->xc_core.p2m_frames * sizeof(ulong))) == NULL)
        	error(FATAL, "cannot malloc p2m_frame_list");

	if (symbol_exists("p2m_mid_missing"))
		return x86_64_pvops_xendump_p2m_l3_create(xd);
	else
		return x86_64_pvops_xendump_p2m_l2_create(xd);
}

static int x86_64_pvops_xendump_p2m_l2_create(struct xendump_data *xd)
{
	int i, idx, p;
	ulong kvaddr, *up;

	machdep->last_ptbl_read = BADADDR;

	kvaddr = symbol_value("p2m_top");

	for (p = 0; p < xd->xc_core.p2m_frames; p += XEN_PFNS_PER_PAGE) {
		if (!x86_64_xendump_load_page(kvaddr, xd))
			return FALSE;

		if (CRASHDEBUG(7))
 			x86_64_debug_dump_page(xd->ofp, xd->page,
                       		"contents of page:");

		up = (ulong *)(xd->page);

		for (i = 0; i < XEN_PFNS_PER_PAGE; i++, up++) {
			if ((p+i) >= xd->xc_core.p2m_frames)
				break;
			if ((idx = x86_64_xendump_page_index(*up, xd)) == MFN_NOT_FOUND)
				return FALSE;
			xd->xc_core.p2m_frame_index_list[p+i] = idx;
		}

		kvaddr += PAGESIZE();
	}

	machdep->last_ptbl_read = 0;

	return TRUE;
}

static int x86_64_pvops_xendump_p2m_l3_create(struct xendump_data *xd)
{
	int i, idx, j, p2m_frame, ret = FALSE;
	ulong kvaddr, *p2m_mid, p2m_mid_missing, p2m_missing, *p2m_top;

	p2m_top = NULL;
	machdep->last_ptbl_read = BADADDR;

	kvaddr = symbol_value("p2m_missing");

	if (!x86_64_xendump_load_page(kvaddr, xd))
		goto err;

	p2m_missing = *(ulong *)(xd->page + PAGEOFFSET(kvaddr));

	kvaddr = symbol_value("p2m_mid_missing");

	if (!x86_64_xendump_load_page(kvaddr, xd))
		goto err;

	p2m_mid_missing = *(ulong *)(xd->page + PAGEOFFSET(kvaddr));

	kvaddr = symbol_value("p2m_top");

	if (!x86_64_xendump_load_page(kvaddr, xd))
		goto err;

	kvaddr = *(ulong *)(xd->page + PAGEOFFSET(kvaddr));

	if (!x86_64_xendump_load_page(kvaddr, xd))
		goto err;

	if (CRASHDEBUG(7))
		x86_64_debug_dump_page(xd->ofp, xd->page,
					"contents of p2m_top page:");

	p2m_top = (ulong *)GETBUF(PAGESIZE());

	memcpy(p2m_top, xd->page, PAGESIZE());

	for (i = 0; i < XEN_P2M_TOP_PER_PAGE; ++i) {
		p2m_frame = i * XEN_P2M_MID_PER_PAGE;

		if (p2m_frame >= xd->xc_core.p2m_frames)
			break;

		if (p2m_top[i] == p2m_mid_missing)
			continue;

		if (!x86_64_xendump_load_page(p2m_top[i], xd))
			goto err;

		if (CRASHDEBUG(7))
			x86_64_debug_dump_page(xd->ofp, xd->page,
						"contents of p2m_mid page:");

		p2m_mid = (ulong *)xd->page;

		for (j = 0; j < XEN_P2M_MID_PER_PAGE; ++j, ++p2m_frame) {
			if (p2m_frame >= xd->xc_core.p2m_frames)
				break;

			if (p2m_mid[j] == p2m_missing)
				continue;

			idx = x86_64_xendump_page_index(p2m_mid[j], xd);

			if (idx == MFN_NOT_FOUND)
				goto err;

			xd->xc_core.p2m_frame_index_list[p2m_frame] = idx;
		}
	}

	machdep->last_ptbl_read = 0;

	ret = TRUE;

err:
	if (p2m_top)
		FREEBUF(p2m_top);

	return ret;
}

static void
x86_64_debug_dump_page(FILE *ofp, char *page, char *name)
{
	int i;
	ulong *up;

        fprintf(ofp, "%s\n", name);

        up = (ulong *)page;
        for (i = 0; i < 256; i++) {
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
x86_64_xendump_load_page(ulong kvaddr, struct xendump_data *xd)
{
	ulong mfn;
	ulong *pgd, *pud, *pmd, *ptep;

        pgd = ((ulong *)machdep->pgd) + pgd_index(kvaddr);
	mfn = ((*pgd) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

	if (CRASHDEBUG(3))
		fprintf(xd->ofp, 
		    "[%lx] pgd: %lx  mfn: %lx  pgd_index: %lx\n",
			kvaddr, *pgd, mfn, pgd_index(kvaddr));

	if (!xc_core_mfn_to_page(mfn, machdep->pud))
		error(FATAL, "cannot read/find pud page\n");

	machdep->last_pud_read = mfn;

        if (CRASHDEBUG(7))
		x86_64_debug_dump_page(xd->ofp, machdep->pud, 
                	"contents of page upper directory page:");

        pud = ((ulong *)machdep->pud) + pud_index(kvaddr);
	mfn = ((*pud) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

	if (CRASHDEBUG(3))
		fprintf(xd->ofp, 
		    "[%lx] pud: %lx  mfn: %lx  pud_index: %lx\n",
			kvaddr, *pud, mfn, pud_index(kvaddr));

        if (!xc_core_mfn_to_page(mfn, machdep->pmd))
                error(FATAL, "cannot read/find pmd page\n");

	machdep->last_pmd_read = mfn;

        if (CRASHDEBUG(7)) 
		x86_64_debug_dump_page(xd->ofp, machdep->pmd, 
			"contents of page middle directory page:");

        pmd = ((ulong *)machdep->pmd) + pmd_index(kvaddr);
	mfn = ((*pmd) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

	if (CRASHDEBUG(3))
		fprintf(xd->ofp, 
		    "[%lx] pmd: %lx  mfn: %lx  pmd_index: %lx\n", 
			kvaddr, *pmd, mfn, pmd_index(kvaddr));

        if (!xc_core_mfn_to_page(mfn, machdep->ptbl))
                error(FATAL, "cannot read/find page table page\n");

	machdep->last_ptbl_read = mfn;

        if (CRASHDEBUG(7)) 
		x86_64_debug_dump_page(xd->ofp, machdep->ptbl, 
			"contents of page table page:");

        ptep = ((ulong *)machdep->ptbl) + pte_index(kvaddr);
	mfn = ((*ptep) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

	if (CRASHDEBUG(3))
		fprintf(xd->ofp, 
		    "[%lx] ptep: %lx  mfn: %lx  pte_index: %lx\n", 
			kvaddr, *ptep, mfn, pte_index(kvaddr));

        if (!xc_core_mfn_to_page(mfn, xd->page))
                error(FATAL, "cannot read/find pte page\n");

        if (CRASHDEBUG(7)) 
		x86_64_debug_dump_page(xd->ofp, xd->page, 
			"contents of page:");

	return xd->page;
}

/*
 *  Find the dumpfile page index associated with the kvaddr.
 */
static int 
x86_64_xendump_page_index(ulong kvaddr, struct xendump_data *xd)
{
        int idx;
	ulong mfn;
	ulong *pgd, *pud, *pmd, *ptep;

        pgd = ((ulong *)machdep->pgd) + pgd_index(kvaddr);
	mfn = ((*pgd) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

        if ((mfn != machdep->last_pud_read) && 
	    !xc_core_mfn_to_page(mfn, machdep->pud))
		error(FATAL, "cannot read/find pud page\n");
        machdep->last_pud_read = mfn;

        pud = ((ulong *)machdep->pud) + pud_index(kvaddr);
	mfn = ((*pud) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

        if ((mfn != machdep->last_pmd_read) && 
            !xc_core_mfn_to_page(mfn, machdep->pmd))
                error(FATAL, "cannot read/find pmd page\n");

        machdep->last_pmd_read = mfn;

        pmd = ((ulong *)machdep->pmd) + pmd_index(kvaddr);
	mfn = ((*pmd) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

        if ((mfn != machdep->last_ptbl_read) && 
	    !xc_core_mfn_to_page(mfn, machdep->ptbl))
                error(FATAL, "cannot read/find page table page\n");
        machdep->last_ptbl_read = mfn;

        ptep = ((ulong *)machdep->ptbl) + pte_index(kvaddr);
	mfn = ((*ptep) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

        if ((idx = xc_core_mfn_to_page_index(mfn)) == MFN_NOT_FOUND)
                error(INFO, "cannot determine page index for %lx\n",
                        kvaddr);

	return idx;
}

/*
 *  Pull the rsp from the cpu_user_regs struct in the header
 *  turn it into a task, and match it with the active_set.
 *  Unfortunately, the registers in the vcpu_guest_context 
 *  are not necessarily those of the panic task, so for now
 *  let get_active_set_panic_task() get the right task.
 */
static ulong 
x86_64_xendump_panic_task(struct xendump_data *xd)
{
	int i;
	ulong rsp;
	off_t offset;
	ulong task;

	if (INVALID_MEMBER(vcpu_guest_context_user_regs) ||
	    INVALID_MEMBER(cpu_user_regs_esp))
		return NO_TASK;

        offset = xd->xc_core.header.xch_ctxt_offset +
                (off_t)OFFSET(vcpu_guest_context_user_regs) +
		(off_t)OFFSET(cpu_user_regs_rsp);

        if (lseek(xd->xfd, offset, SEEK_SET) == -1)
		return NO_TASK;

        if (read(xd->xfd, &rsp, sizeof(ulong)) != sizeof(ulong))
		return NO_TASK;

        if (IS_KVADDR(rsp) && (task = stkptr_to_task(rsp))) {

                for (i = 0; i < NR_CPUS; i++) {
                	if (task == tt->active_set[i]) {
                        	if (CRASHDEBUG(0))
                                	error(INFO,
                            "x86_64_xendump_panic_task: rsp: %lx -> task: %lx\n",
                                        	rsp, task);
                        	return task;
			}
		}               

               	error(WARNING,
		    "x86_64_xendump_panic_task: rsp: %lx -> task: %lx (not active)\n",
			rsp);
        }

	return NO_TASK;
}

/*
 *  Because of an off-by-one vcpu bug in early xc_domain_dumpcore()
 *  instantiations, the registers in the vcpu_guest_context are not 
 *  necessarily those of the panic task.  Furthermore, the rsp is
 *  seemingly unassociated with the task, presumably due a hypervisor
 *  callback, so only accept the contents if they retfer to the panic
 *  task's stack. 
 */
static void 
x86_64_get_xendump_regs(struct xendump_data *xd, struct bt_info *bt, ulong *rip, ulong *rsp)
{
	ulong task, xrip, xrsp;
	off_t offset;
	struct syment *sp;
	char *rip_symbol;
	int cpu;

        if (INVALID_MEMBER(vcpu_guest_context_user_regs) ||
            INVALID_MEMBER(cpu_user_regs_rip) ||
            INVALID_MEMBER(cpu_user_regs_rsp))
                goto generic;

        offset = xd->xc_core.header.xch_ctxt_offset +
                (off_t)OFFSET(vcpu_guest_context_user_regs) +
                (off_t)OFFSET(cpu_user_regs_rsp);
        if (lseek(xd->xfd, offset, SEEK_SET) == -1)
                goto generic;
        if (read(xd->xfd, &xrsp, sizeof(ulong)) != sizeof(ulong))
                goto generic;

        offset = xd->xc_core.header.xch_ctxt_offset +
                (off_t)OFFSET(vcpu_guest_context_user_regs) +
                (off_t)OFFSET(cpu_user_regs_rip);
        if (lseek(xd->xfd, offset, SEEK_SET) == -1)
                goto generic;
        if (read(xd->xfd, &xrip, sizeof(ulong)) != sizeof(ulong))
                goto generic;

	/*
	 *  This works -- comes from smp_send_stop call in panic.
	 *  But xendump_panic_hook() will forestall this function 
	 *  from being called (for now).
	 */
        if (IS_KVADDR(xrsp) && (task = stkptr_to_task(xrsp)) &&
	    (task == bt->task)) {
		if (CRASHDEBUG(1))
			fprintf(xd->ofp, 
		"hooks from vcpu_guest_context: rip: %lx rsp: %lx\n", xrip, xrsp);
		*rip = xrip;
		*rsp = xrsp;
		return;
	}

generic:

	machdep->get_stack_frame(bt, rip, rsp);

	/*
	 *  If this is an active task showing itself in schedule(), 
	 *  then the thread_struct rsp is stale.  It has to be coming 
	 *  from a callback via the interrupt stack.
	 */
	if (is_task_active(bt->task) && (rip_symbol = closest_symbol(*rip)) && 
	    (STREQ(rip_symbol, "thread_return") || STREQ(rip_symbol, "schedule"))) {
		cpu = bt->tc->processor;
		xrsp = machdep->machspec->stkinfo.ibase[cpu] + 
			machdep->machspec->stkinfo.isize - sizeof(ulong);

                while (readmem(xrsp, KVADDR, &xrip,
                    sizeof(ulong), "xendump rsp", RETURN_ON_ERROR)) {
        		if ((sp = value_search(xrip, (ulong *)&offset)) && 
			    STREQ(sp->name, "smp_really_stop_cpu") && offset) {
                                *rip = xrip;
                                *rsp = xrsp;
                                if (CRASHDEBUG(1))
                                        error(INFO,
                                            "switch thread_return to smp_call_function_interrupt\n");
                                break;
                        }
                        xrsp -= sizeof(ulong);
                        if (xrsp <= machdep->machspec->stkinfo.ibase[cpu])
                                break;
                }
	}
}

/* for XEN Hypervisor analysis */

static int 
x86_64_is_kvaddr_hyper(ulong addr)
{
        return (addr >= HYPERVISOR_VIRT_START && addr < HYPERVISOR_VIRT_END); 
}

static ulong
x86_64_get_stackbase_hyper(ulong task)
{
	struct xen_hyper_vcpu_context *vcc;
	struct xen_hyper_pcpu_context *pcc;
	ulong rsp0, base;

	/* task means vcpu here */
	vcc = xen_hyper_vcpu_to_vcpu_context(task);
	if (!vcc)
		error(FATAL, "invalid vcpu\n");

	pcc = xen_hyper_id_to_pcpu_context(vcc->processor);
	if (!pcc)
		error(FATAL, "invalid pcpu number\n");

	rsp0 = pcc->sp.rsp0;
	base = rsp0 & (~(STACKSIZE() - 1));
	return base;
}

static ulong
x86_64_get_stacktop_hyper(ulong task)
{
	return x86_64_get_stackbase_hyper(task) + STACKSIZE();
}

#define EXCEPTION_STACKSIZE_HYPER (1024UL)

static ulong
x86_64_in_exception_stack_hyper(ulong vcpu, ulong rsp)
{
	struct xen_hyper_vcpu_context *vcc;
	struct xen_hyper_pcpu_context *pcc;
	int i;
	ulong stackbase;

	vcc = xen_hyper_vcpu_to_vcpu_context(vcpu);
	if (!vcc)
		error(FATAL, "invalid vcpu\n");

	pcc = xen_hyper_id_to_pcpu_context(vcc->processor);
	if (!pcc)
		error(FATAL, "invalid pcpu number\n");

	for (i = 0; i < XEN_HYPER_TSS_IST_MAX; i++) {
		if (pcc->ist[i] == 0) {
			continue;
		}
		stackbase = pcc->ist[i] - EXCEPTION_STACKSIZE_HYPER;
		if ((rsp & ~(EXCEPTION_STACKSIZE_HYPER - 1)) == stackbase) {
			return stackbase;
		}
	}

	return 0;
}

static void
x86_64_get_stack_frame_hyper(struct bt_info *bt, ulong *pcp, ulong *spp)
{
	struct xen_hyper_vcpu_context *vcc;
        int pcpu;
        ulong *regs;
	ulong rsp, rip;

	/* task means vcpu here */
	vcc = xen_hyper_vcpu_to_vcpu_context(bt->task);
	if (!vcc)
		error(FATAL, "invalid vcpu\n");

	pcpu = vcc->processor;
	if (!xen_hyper_test_pcpu_id(pcpu)) {
		error(FATAL, "invalid pcpu number\n");
	}

	if (bt->flags & BT_TEXT_SYMBOLS_ALL) {
		if (spp)
			*spp = x86_64_get_stackbase_hyper(bt->task);
		if (pcp)
			*pcp = 0;
		bt->flags &= ~BT_TEXT_SYMBOLS_ALL;
		return;
	}

	regs = (ulong *)xen_hyper_id_to_dumpinfo_context(pcpu)->pr_reg_ptr;
	rsp = XEN_HYPER_X86_64_NOTE_RSP(regs);
	rip = XEN_HYPER_X86_64_NOTE_RIP(regs);

	if (spp) {
		if (x86_64_in_exception_stack_hyper(bt->task, rsp))
			*spp = rsp;
		else if (rsp < x86_64_get_stackbase_hyper(bt->task) ||
			rsp >= x86_64_get_stacktop_hyper(bt->task))
			*spp = x86_64_get_stackbase_hyper(bt->task);
		else
			*spp = rsp;
	}
	if (pcp) {
		if (is_kernel_text(rip))
			*pcp = rip;
		else
			*pcp = 0;
	}
}

static int
x86_64_print_stack_entry_hyper(struct bt_info *bt, FILE *ofp, int level, 
	int stkindex, ulong text)
{
	ulong rsp, offset;
	struct syment *sp;
	char *name, *name_plus_offset;
	int result; 
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];

	offset = 0;
	sp = value_search(text, &offset);
	if (!sp)
		return BACKTRACE_ENTRY_IGNORED;

	name = sp->name;

	if (offset && (bt->flags & BT_SYMBOL_OFFSET))
		name_plus_offset = value_to_symstr(text, buf2, bt->radix);
	else
		name_plus_offset = NULL;

	if (STREQ(name, "syscall_enter"))
		result = BACKTRACE_COMPLETE;
	else
		result = BACKTRACE_ENTRY_DISPLAYED;

	rsp = bt->stackbase + (stkindex * sizeof(long));

	if ((bt->flags & BT_FULL)) {
		if (bt->frameptr) 
			x86_64_display_full_frame(bt, rsp, ofp);
		bt->frameptr = rsp + sizeof(ulong);
	}

        fprintf(ofp, "%s#%d [%8lx] %s at %lx\n", level < 10 ? " " : "", level,
		rsp, name_plus_offset ? name_plus_offset : name, text);

        if (bt->flags & BT_LINE_NUMBERS) {
                get_line_number(text, buf1, FALSE);
                if (strlen(buf1))
                        fprintf(ofp, "    %s\n", buf1);
	}

	if (BT_REFERENCE_CHECK(bt))
		x86_64_do_bt_reference_check(bt, text, name);

	return result;
}

static void
x86_64_print_eframe_regs_hyper(struct bt_info *bt)
{
	ulong *up;
	ulong offset;
	struct syment *sp;


	up = (ulong *)(&bt->stackbuf[bt->stacktop - bt->stackbase]);
	up -= 21;

	fprintf(fp, "    [exception RIP: ");
	if ((sp = value_search(up[16], &offset))) {
               	fprintf(fp, "%s", sp->name);
              	if (offset)
               		fprintf(fp, (*gdb_output_radix == 16) ? 
					"+0x%lx" : "+%ld", offset);
	} else
       		fprintf(fp, "unknown or invalid address");
	fprintf(fp, "]\n");

	fprintf(fp, "    RIP: %016lx  RSP: %016lx  RFLAGS: %08lx\n", 
		up[16], up[19], up[18]);
	fprintf(fp, "    RAX: %016lx  RBX: %016lx  RCX: %016lx\n", 
		up[10], up[5], up[11]);
	fprintf(fp, "    RDX: %016lx  RSI: %016lx  RDI: %016lx\n", 
 		up[12], up[13], up[14]);
	fprintf(fp, "    RBP: %016lx   R8: %016lx   R9: %016lx\n", 
		up[4], up[9], up[8]);
	fprintf(fp, "    R10: %016lx  R11: %016lx  R12: %016lx\n", 
		up[7], up[6], up[3]);
	fprintf(fp, "    R13: %016lx  R14: %016lx  R15: %016lx\n", 
		up[2], up[1], up[0]);
	fprintf(fp, "    ORIG_RAX: %016lx  CS: %04lx  SS: %04lx\n", 
		up[15], up[17], up[20]);

	fprintf(fp, "--- <exception stack> ---\n");
}

/*
 *  simple back tracer for xen hypervisor
 *  irq stack does not exist. so relative easy.
 */
static void
x86_64_simple_back_trace_cmd_hyper(struct bt_info *bt_in)
{
	int i, level, done;
	ulong rsp, estack, stacktop;
	ulong *up;
	FILE *ofp;
	struct bt_info bt_local, *bt;
	char ebuf[EXCEPTION_STACKSIZE_HYPER];

	bt = &bt_local;
	BCOPY(bt_in, bt, sizeof(struct bt_info));

	if (bt->flags & BT_FRAMESIZE_DEBUG) {
		error(INFO, "-F not support\n");
		return;
	}

	level = 0;
	done = FALSE;
	bt->call_target = NULL;
	rsp = bt->stkptr;
	if (!rsp) {
		error(INFO, "cannot determine starting stack pointer\n");
		return;
	}
	if (BT_REFERENCE_CHECK(bt))
		ofp = pc->nullfp;
	else
		ofp = fp;

	while ((estack = x86_64_in_exception_stack_hyper(bt->task, rsp))) {
		bt->flags |= BT_EXCEPTION_STACK;
		bt->stackbase = estack;
		bt->stacktop = estack + EXCEPTION_STACKSIZE_HYPER;
		bt->stackbuf = ebuf;

		if (!readmem(bt->stackbase, KVADDR, bt->stackbuf,
		    bt->stacktop - bt->stackbase, "exception stack contents",
		    RETURN_ON_ERROR))
			error(FATAL, "read of exception stack at %lx failed\n",
				bt->stackbase);

		stacktop = bt->stacktop - 168;

        	for (i = (rsp - bt->stackbase)/sizeof(ulong);
		     !done && (rsp < stacktop); i++, rsp += sizeof(ulong)) {
	
			up = (ulong *)(&bt->stackbuf[i*sizeof(ulong)]);

			if (!is_kernel_text(*up))
				continue;

			switch (x86_64_print_stack_entry_hyper(bt, ofp, level, i,*up))
			{
			case BACKTRACE_ENTRY_DISPLAYED:
				level++;
				break;
			case BACKTRACE_ENTRY_IGNORED:	
				break;
			case BACKTRACE_COMPLETE:
				done = TRUE;
				break;
			}
        	}

		if (!BT_REFERENCE_CHECK(bt))
			x86_64_print_eframe_regs_hyper(bt);

		up = (ulong *)(&bt->stackbuf[bt->stacktop - bt->stackbase]);
		up -= 2;
		rsp = bt->stkptr = *up;
		up -= 3;
		bt->instptr = *up;
		done = FALSE;
		bt->frameptr = 0;
	}

	if (bt->flags & BT_EXCEPTION_STACK) {
		bt->flags &= ~BT_EXCEPTION_STACK;
		bt->stackbase = bt_in->stackbase;
		bt->stacktop = bt_in->stacktop;
		bt->stackbuf = bt_in->stackbuf;
	}

        for (i = (rsp - bt->stackbase)/sizeof(ulong);
	     !done && (rsp < bt->stacktop); i++, rsp += sizeof(ulong)) {

		up = (ulong *)(&bt->stackbuf[i*sizeof(ulong)]);

		if (!is_kernel_text(*up))
			continue;

		switch (x86_64_print_stack_entry_hyper(bt, ofp, level, i,*up))
		{
		case BACKTRACE_ENTRY_DISPLAYED:
			level++;
			break;
		case BACKTRACE_ENTRY_IGNORED:	
			break;
		case BACKTRACE_COMPLETE:
			done = TRUE;
			break;
		}
        }
}

static void
x86_64_init_hyper(int when)
{
	switch (when)
	{
	case PRE_SYMTAB:
		machdep->verify_symbol = x86_64_verify_symbol;
                machdep->machspec = &x86_64_machine_specific;
                if (pc->flags & KERNEL_DEBUG_QUERY)
                        return;
                machdep->pagesize = memory_page_size();
                machdep->pageshift = ffs(machdep->pagesize) - 1;
                machdep->pageoffset = machdep->pagesize - 1;
                machdep->pagemask = ~((ulonglong)machdep->pageoffset);
		machdep->stacksize = machdep->pagesize * 8;
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
		machdep->verify_paddr = generic_verify_paddr;
		machdep->ptrs_per_pgd = PTRS_PER_PGD;
                if (machdep->cmdline_args[0])
                        parse_cmdline_args();
		break;

	case PRE_GDB:
                machdep->machspec->page_offset = PAGE_OFFSET_XEN_HYPER;
	        machdep->kvbase = (ulong)HYPERVISOR_VIRT_START;
		machdep->identity_map_base = (ulong)PAGE_OFFSET_XEN_HYPER;
                machdep->is_kvaddr = x86_64_is_kvaddr_hyper;
                machdep->is_uvaddr = x86_64_is_uvaddr;
	        machdep->eframe_search = x86_64_eframe_search;
	        machdep->back_trace = x86_64_simple_back_trace_cmd_hyper;
	        machdep->processor_speed = x86_64_processor_speed;
	        machdep->kvtop = x86_64_kvtop;
	        machdep->get_task_pgd = x86_64_get_task_pgd;
		machdep->get_stack_frame = x86_64_get_stack_frame_hyper;
		machdep->get_stackbase = x86_64_get_stackbase_hyper;
		machdep->get_stacktop = x86_64_get_stacktop_hyper;
		machdep->translate_pte = x86_64_translate_pte;
		machdep->memory_size = xen_hyper_x86_memory_size;	/* KAK add */
		machdep->is_task_addr = x86_64_is_task_addr;
		machdep->dis_filter = x86_64_dis_filter;
		machdep->cmd_mach = x86_64_cmd_mach;
		machdep->get_smp_cpus = xen_hyper_x86_get_smp_cpus;	/* KAK add */
		machdep->line_number_hooks = x86_64_line_number_hooks;
		machdep->value_to_symbol = generic_machdep_value_to_symbol;
		machdep->init_kernel_pgd = x86_64_init_kernel_pgd;
		machdep->clear_machdep_cache = x86_64_clear_machdep_cache;

		/* machdep table for Xen Hypervisor */
		xhmachdep->pcpu_init = xen_hyper_x86_pcpu_init;
		break;

	case POST_GDB:
		XEN_HYPER_STRUCT_SIZE_INIT(cpuinfo_x86, "cpuinfo_x86");
		if (symbol_exists("per_cpu__tss_page")) {
			XEN_HYPER_STRUCT_SIZE_INIT(tss, "tss64");
			XEN_HYPER_ASSIGN_OFFSET(tss_rsp0) =
							MEMBER_OFFSET("tss64", "rsp0");
			XEN_HYPER_MEMBER_OFFSET_INIT(tss_ist, "tss64", "ist");
		} else {
			XEN_HYPER_STRUCT_SIZE_INIT(tss, "tss_struct");
			XEN_HYPER_MEMBER_OFFSET_INIT(tss_ist, "tss_struct", "ist");
			if (MEMBER_EXISTS("tss_struct", "__blh")) {
				XEN_HYPER_ASSIGN_OFFSET(tss_rsp0) =
					MEMBER_OFFSET("tss_struct", "__blh") +
								sizeof(short unsigned int);
			} else	{
				XEN_HYPER_ASSIGN_OFFSET(tss_rsp0) =
							MEMBER_OFFSET("tss_struct", "rsp0");
			}
		}
		if (symbol_exists("cpu_data")) {
			xht->cpu_data_address = symbol_value("cpu_data");
		}
/* KAK Can this be calculated? */
		if (!machdep->hz) {
			machdep->hz = XEN_HYPER_HZ;
		}
		break;

	case POST_INIT:
		break;
	}
}


struct framesize_cache {
        ulong textaddr;
        int framesize;
	int exception;
};

static struct framesize_cache *x86_64_framesize_cache = NULL;
static int framesize_cache_entries = 0;

#define FRAMESIZE_QUERY  (1)
#define FRAMESIZE_ENTER  (2)
#define FRAMESIZE_DUMP   (3)

#define FRAMESIZE_CACHE_INCR (50)

static int
x86_64_framesize_cache_resize(void)
{
	int i;
	struct framesize_cache *new_fc, *fc;

	if ((new_fc = realloc(x86_64_framesize_cache, 
		    (framesize_cache_entries+FRAMESIZE_CACHE_INCR) * 
		    sizeof(struct framesize_cache))) == NULL) {
			error(INFO, "cannot realloc x86_64_framesize_cache space!\n");
			return FALSE;
	} 

	fc = new_fc + framesize_cache_entries;
	for (i = framesize_cache_entries; 
	     i < (framesize_cache_entries+FRAMESIZE_CACHE_INCR); 
	     fc++, i++) {
		fc->textaddr = 0;
		fc->framesize = 0;
		fc->exception = 0;
	} 	

	x86_64_framesize_cache = new_fc;
	framesize_cache_entries += FRAMESIZE_CACHE_INCR;

	return TRUE;
}

ulong *x86_64_framesize_no_cache = NULL;
static int framesize_no_cache_entries = 0;
#define FRAMESIZE_NO_CACHE_INCR (10)

static int
x86_64_do_not_cache_framesize(struct syment *sp, ulong textaddr)
{
	int c, instr, arg;
	char buf[BUFSIZE];
	char *arglist[MAXARGS];
	ulong *new_fnc;

	if (x86_64_framesize_no_cache[framesize_no_cache_entries-1]) {
		if ((new_fnc = realloc(x86_64_framesize_no_cache,
		    (framesize_no_cache_entries+FRAMESIZE_NO_CACHE_INCR) *
		    sizeof(ulong))) == NULL) {
			error(INFO, "cannot realloc x86_64_framesize_no_cache space!\n");
			return FALSE;
		}
		x86_64_framesize_no_cache = new_fnc;
		for (c = framesize_no_cache_entries; 
		     c < framesize_no_cache_entries + FRAMESIZE_NO_CACHE_INCR; c++) 
			x86_64_framesize_no_cache[c] = 0;
		framesize_no_cache_entries += FRAMESIZE_NO_CACHE_INCR; 
	}

	for (c = 0; c < framesize_no_cache_entries; c++)
		if (x86_64_framesize_no_cache[c] == sp->value)
			return TRUE;

	if (!accessible(sp->value))
		return FALSE;

	sprintf(buf, "disassemble 0x%lx,0x%lx", sp->value, textaddr);

	open_tmpfile2();

	if (!gdb_pass_through(buf, pc->tmpfile2, GNU_RETURN_ON_ERROR)) {
		close_tmpfile2();
		return FALSE;
	}

	rewind(pc->tmpfile2);
	instr = arg = -1;
	while (fgets(buf, BUFSIZE, pc->tmpfile2)) {
		if (STRNEQ(buf, "Dump of assembler code"))
			continue;
		else if (STRNEQ(buf, "End of assembler dump."))
			break;
		else if ((c = parse_line(buf, arglist)) < 3)
			continue;

		if (instr == -1) {
			if (LASTCHAR(arglist[0]) == ':') {
                                instr = 1;
                                arg = 2;
                        } else {
                                instr = 2;
                                arg = 3;
                        }
		}

		if (STREQ(arglist[instr], "and") && 
		    STREQ(arglist[arg], "$0xfffffffffffffff0,%rsp")) {
			close_tmpfile2();
			for (c = 0; c < framesize_no_cache_entries; c++) {
				if (x86_64_framesize_no_cache[c] == 0) {
					x86_64_framesize_no_cache[c] = sp->value;
					break;
				}
			}
			return TRUE;
		}

		if (STREQ(arglist[instr], "callq") || STREQ(arglist[instr], "call"))
			break;
	}
	close_tmpfile2();

	return FALSE;
}

static int
x86_64_framesize_cache_func(int cmd, ulong textaddr, int *framesize, int exception, struct syment *sp)
{
	int i, n;
	struct framesize_cache *fc;
	char buf[BUFSIZE];

	if (!x86_64_framesize_cache) {
		framesize_cache_entries = FRAMESIZE_CACHE_INCR;
		if ((x86_64_framesize_cache = calloc(framesize_cache_entries,
		    sizeof(struct framesize_cache))) == NULL)
			error(FATAL, 
			    "cannot calloc x86_64_framesize_cache space!\n");
		framesize_no_cache_entries = FRAMESIZE_NO_CACHE_INCR;
		if ((x86_64_framesize_no_cache = calloc(framesize_no_cache_entries,
		    sizeof(ulong))) == NULL)
			error(FATAL, "cannot calloc x86_64_framesize_no_cache space!\n");
	}

	switch (cmd) 
	{
	case FRAMESIZE_QUERY:
		fc = &x86_64_framesize_cache[0];
		for (i = 0; i < framesize_cache_entries; i++, fc++) {
			if (fc->textaddr == textaddr) {
				if (fc->exception != exception)
					return FALSE;
				*framesize = fc->framesize;
				return TRUE;
			}
		}
		return FALSE;

	case FRAMESIZE_ENTER:
		if (sp && x86_64_do_not_cache_framesize(sp, textaddr))
			return *framesize;
retry:
		fc = &x86_64_framesize_cache[0];
		for (i = 0; i < framesize_cache_entries; i++, fc++) {
			if ((fc->textaddr == 0) ||
			    (fc->textaddr == textaddr)) {
				if (*framesize == -1) {
					fc->textaddr = 0;
					fc->framesize = 0;
					fc->exception = 0;
					for (n = i+1; n < framesize_cache_entries; 
					    i++, n++)
						x86_64_framesize_cache[i] = 
							x86_64_framesize_cache[n];
					return 0;
				}
				fc->textaddr = textaddr;
				fc->framesize = *framesize;
				fc->exception = exception;
				return fc->framesize;
			}
		}

		if (x86_64_framesize_cache_resize())
			goto retry;

		return *framesize;

	case FRAMESIZE_DUMP:
		fprintf(fp, "framesize_cache_entries:\n");
		fc = &x86_64_framesize_cache[0];
		for (i = 0; i < framesize_cache_entries; i++, fc++) {
			if (fc->textaddr == 0) {
				if (i < (framesize_cache_entries-1)) {
					fprintf(fp, "  [%d-%d]: (unused)\n",
						i, framesize_cache_entries-1);
				}
				break;
			}

			fprintf(fp, "  [%3d]: %lx %3d %s (%s)\n", i,
				fc->textaddr, fc->framesize,
				fc->exception ? "EX" : "CF",
				value_to_symstr(fc->textaddr, buf, 0));
		}

		fprintf(fp, "\nframesize_no_cache_entries:\n");
		for (i = 0; i < framesize_no_cache_entries; i++) {
			if (x86_64_framesize_no_cache[i])
				fprintf(fp, "  [%3d]: %lx (%s)\n", 
					i, x86_64_framesize_no_cache[i],
					value_to_symstr(x86_64_framesize_no_cache[i], buf, 0));
			else {
				fprintf(fp, "  [%d-%d]: (unused)\n", 
					i, framesize_no_cache_entries-1);
				break;
			}
		}

		break;
	}

	return TRUE;
}

ulong
x86_64_get_framepointer(struct bt_info *bt, ulong rsp)
{
	ulong stackptr, framepointer, retaddr;

	framepointer = 0;
	stackptr = rsp - sizeof(ulong);

	if (!INSTACK(stackptr, bt))
		return 0;

	if (!readmem(stackptr, KVADDR, &framepointer,
	    sizeof(ulong), "framepointer", RETURN_ON_ERROR|QUIET)) 
		return 0;

	if (!INSTACK(framepointer, bt)) 
		return 0;

	if (framepointer <= (rsp+sizeof(ulong)))
		return 0;

	if (!readmem(framepointer + sizeof(ulong), KVADDR, &retaddr,
	    sizeof(ulong), "return address", RETURN_ON_ERROR|QUIET)) 
		return 0;

	if (!is_kernel_text(retaddr))
		return 0;

	return framepointer;
}

int
search_for_eframe_target_caller(struct bt_info *bt, ulong stkptr, int *framesize)
{
	int i;
	ulong *up, offset, rsp;
	struct syment *sp1, *sp2;
	char *called_function;

	if ((sp1 = value_search(bt->eframe_ip, &offset)))
		called_function = sp1->name;
	else
		return FALSE;

	rsp = stkptr;

	for (i = (rsp - bt->stackbase)/sizeof(ulong);
	    rsp < bt->stacktop; i++, rsp += sizeof(ulong)) {

		up = (ulong *)(&bt->stackbuf[i*sizeof(ulong)]);

		if (!is_kernel_text(*up))
			continue;

		if (!(sp1 = value_search(*up, &offset)))
			continue;

		if (!offset && !(bt->flags & BT_FRAMESIZE_DISABLE))
			continue;

		/*
		 *  Get the syment of the function that the text 
		 *  routine above called before leaving its return 
		 *  address on the stack -- if it can be determined.
		 */
		if ((sp2 = x86_64_function_called_by((*up)-5))) {
			if (STREQ(sp2->name, called_function)) {
				if (CRASHDEBUG(1)) {
					fprintf(fp, 
					    "< %lx/%s rsp: %lx caller: %s >\n", 
						bt->eframe_ip, called_function, 
						stkptr, sp1->name);
				}
				*framesize = rsp - stkptr;
				return TRUE;
			}
		}
	}

	return FALSE;
}

#define BT_FRAMESIZE_IGNORE_MASK \
	(BT_OLD_BACK_TRACE|BT_TEXT_SYMBOLS|BT_TEXT_SYMBOLS_ALL|BT_FRAMESIZE_DISABLE)
 
static int
x86_64_get_framesize(struct bt_info *bt, ulong textaddr, ulong rsp, char *stack_ptr)
{
	int c, framesize, instr, arg, max;
	struct syment *sp;
	long max_instructions;
	ulong offset;
	char buf[BUFSIZE];
	char buf2[BUFSIZE];
	char *arglist[MAXARGS];
	ulong locking_func, textaddr_save, current, framepointer;
	char *p1, *p2;
	int reterror;
	int arg_exists;
	int exception;
	kernel_orc_entry *korc;

	if (!(bt->flags & BT_FRAMESIZE_DEBUG)) {
		if ((bt->flags & BT_FRAMESIZE_IGNORE_MASK) ||
		    (kt->flags & USE_OLD_BT))
			return 0;
	}

        if (!(sp = value_search(textaddr, &offset))) {
		if (!(bt->flags & BT_FRAMESIZE_DEBUG))
			bt->flags |= BT_FRAMESIZE_DISABLE;
                return 0;
	}

	exception = bt->eframe_ip == textaddr ? TRUE : FALSE;

	if ((bt->flags & BT_EFRAME_TARGET) &&
	    search_for_eframe_target_caller(bt, rsp, &framesize))
		return framesize;

	if (!(bt->flags & BT_FRAMESIZE_DEBUG) &&
	    x86_64_framesize_cache_func(FRAMESIZE_QUERY, textaddr, &framesize,
		exception, NULL)) {
		if (framesize == -1)
			bt->flags |= BT_FRAMESIZE_DISABLE;
		return framesize; 
	}

	/*
	 *  Bait and switch an incoming .text.lock address
	 *  with the containing function's address.
	 */
	if (STRNEQ(sp->name, ".text.lock.") &&
	    (locking_func = text_lock_function(sp->name, bt, textaddr))) {
        	if (!(sp = value_search(locking_func, &offset))) {
			bt->flags |= BT_FRAMESIZE_DISABLE;
			return 0;
		}
		textaddr_save = textaddr;
		textaddr = locking_func;
	} else
		textaddr_save = 0;

	/*
	 *  As of 2.6.29, "irq_entries_start" replaced the range of IRQ
	 *  entry points named IRQ0x00_interrupt through IRQ0x##_interrupt.
	 *  Each IRQ entry point in the list of non-symbolically-named 
	 *  entry stubs consists of a single pushq and a jmp.
	 */
	if (STREQ(sp->name, "irq_entries_start")) {
#define PUSH_IMM8 0x6a
		if (readmem(textaddr, KVADDR, &instr,
		    sizeof(short), "irq_entries_start instruction", 
		    QUIET|RETURN_ON_ERROR) &&
		    ((instr & 0xff) == PUSH_IMM8))
			framesize = 0;
		else 
			framesize = 8;
		return (x86_64_framesize_cache_func(FRAMESIZE_ENTER, textaddr, 
                	&framesize, exception, NULL));
	}

	if ((machdep->flags & FRAMEPOINTER) && 
	    rsp && !exception && !textaddr_save) {
		framepointer = x86_64_get_framepointer(bt, rsp);
		if (CRASHDEBUG(3)) {
			if (framepointer)
				fprintf(fp, 
				    " rsp: %lx framepointer: %lx -> %ld\n", 
					rsp, framepointer, framepointer - rsp);
			else
				fprintf(fp, 
				    " rsp: %lx framepointer: (unknown)\n", rsp);
		}
		if (framepointer) {
			framesize = framepointer - rsp;
			return (x86_64_framesize_cache_func(FRAMESIZE_ENTER, 
				textaddr, &framesize, 0, sp));
		}
	}

	if ((sp->value >= kt->init_begin) && (sp->value < kt->init_end))
		return 0;

	if ((machdep->flags & ORC) && (korc = orc_find(textaddr))) {
		if (CRASHDEBUG(1)) {
			fprintf(fp, 
			    "rsp: %lx textaddr: %lx -> spo: %d bpo: %d spr: %d bpr: %d type: %d",
				rsp, textaddr, korc->sp_offset, korc->bp_offset,
				korc->sp_reg, korc->bp_reg, korc->type);
			if (MEMBER_EXISTS("orc_entry", "end"))
				fprintf(fp, " end: %d", korc->end);
			fprintf(fp, "\n");
		}

		if (korc->type == ORC_TYPE_CALL) {
			ulong prev_sp = 0, prev_bp = 0;
			framesize = -1;

			if (korc->sp_reg == ORC_REG_SP) {
				framesize = (korc->sp_offset - 8);

				/* rsp points to a return address, so +8 to use sp_offset */
				prev_sp = (rsp + 8) + korc->sp_offset;
				if (CRASHDEBUG(1))
					fprintf(fp, "rsp: %lx prev_sp: %lx framesize: %d\n",
							rsp, prev_sp, framesize);
			} else if ((korc->sp_reg == ORC_REG_BP) && bt->bptr) {
				prev_sp = bt->bptr + korc->sp_offset;
				framesize = (prev_sp - (rsp + 8) - 8);
				if (CRASHDEBUG(1))
					fprintf(fp, "rsp: %lx rbp: %lx prev_sp: %lx framesize: %d\n",
							rsp, bt->bptr, prev_sp, framesize);
			}

			if ((korc->bp_reg == ORC_REG_PREV_SP) && prev_sp) {
				prev_bp = prev_sp + korc->bp_offset;
				if (stack_ptr && INSTACK(prev_bp, bt)) {
					bt->bptr = ULONG(stack_ptr + (prev_bp - rsp));
					if (CRASHDEBUG(1))
						fprintf(fp, "rsp: %lx prev_sp: %lx prev_bp: %lx -> %lx\n",
								rsp, prev_sp, prev_bp, bt->bptr);
				} else
					bt->bptr = 0;
			} else if ((korc->bp_reg != ORC_REG_UNDEFINED))
				bt->bptr = 0;

			if (framesize >= 0)
				/* Do not cache this, possibly it may be variable. */
				return framesize;
		}
	}

	framesize = max = 0;
        max_instructions = textaddr - sp->value; 
	instr = arg = -1;

        open_tmpfile2();

        sprintf(buf, "x/%ldi 0x%lx",
                max_instructions, sp->value);

        if (!gdb_pass_through(buf, pc->tmpfile2, GNU_RETURN_ON_ERROR)) {
        	close_tmpfile2();
		bt->flags |= BT_FRAMESIZE_DISABLE;
                return 0;
	}

        rewind(pc->tmpfile2);
        while (fgets(buf, BUFSIZE, pc->tmpfile2)) {
		strcpy(buf2, buf);

		if (CRASHDEBUG(3))
			fprintf(fp, "%s", buf2);

		c = parse_line(buf, arglist);

		if (instr == -1) {
			/*
			 *  Check whether <function+offset> are 
			 *  in the output string.
			 */
			if (LASTCHAR(arglist[0]) == ':') {
				instr = 1;
				arg = 2;
			} else { 
				instr = 2;
				arg = 3;
			}
		}

		if (c < (instr+1))
			continue;
		else if (c >= (arg+1))
			arg_exists = TRUE;
		else
			arg_exists = FALSE;

		reterror = 0;
		current =  htol(strip_ending_char(arglist[0], ':'), 
			RETURN_ON_ERROR, &reterror);
		if (reterror)
			continue;

		if (current > textaddr)
			break;
		else if ((current == textaddr) && !exception)
			break;

		if (STRNEQ(arglist[instr], "push")) {
			framesize += 8;
			if (CRASHDEBUG(2) || (bt->flags & BT_FRAMESIZE_DEBUG))
				fprintf(fp, "%s\t[framesize: %d]\n", 
					strip_linefeeds(buf2), framesize);
			max = framesize;
	 	} else if (STRNEQ(arglist[instr], "pop") || 
		    STRNEQ(arglist[instr], "leaveq")) {
			if (framesize > 0)
				framesize -= 8;
			if (CRASHDEBUG(2) || (bt->flags & BT_FRAMESIZE_DEBUG))
				fprintf(fp, "%s\t[framesize: %d]\n", 
					strip_linefeeds(buf2), framesize);
		} else if (arg_exists && STRNEQ(arglist[instr], "add") && 
			(p1 = strstr(arglist[arg], ",%rsp"))) {
			*p1 = NULLCHAR;
			p2 = arglist[arg];
			reterror = 0;
			offset =  htol(p2+1, RETURN_ON_ERROR, &reterror);
			if (reterror)
				continue;
			if (framesize > 0)
				framesize -= offset;
			if (CRASHDEBUG(2) || (bt->flags & BT_FRAMESIZE_DEBUG))
				fprintf(fp, "%s\t[framesize: %d]\n", 
					strip_linefeeds(buf2), framesize);
		} else if (arg_exists && STRNEQ(arglist[instr], "sub") && 
			(p1 = strstr(arglist[arg], ",%rsp"))) {
			*p1 = NULLCHAR;
			p2 = arglist[arg];
			reterror = 0;
			offset =  htol(p2+1, RETURN_ON_ERROR|QUIET, &reterror);
			if (reterror)
				continue;
			framesize += offset;
			max = framesize;
			if (CRASHDEBUG(2) || (bt->flags & BT_FRAMESIZE_DEBUG))
				fprintf(fp, "%s\t[framesize: %d]\n", 
					strip_linefeeds(buf2), framesize);
		} else if (STRNEQ(arglist[instr], "retq")) {
			if (!exception) {
				framesize = max;
				if (CRASHDEBUG(2) || (bt->flags & BT_FRAMESIZE_DEBUG))
					fprintf(fp, "%s\t[framesize restored to: %d]\n", 
						strip_linefeeds(buf2), max);
			}
		} else if (STRNEQ(arglist[instr], "retq_NOT_CHECKED")) {
			bt->flags |= BT_FRAMESIZE_DISABLE;
			framesize = -1;
			if (CRASHDEBUG(2) || (bt->flags & BT_FRAMESIZE_DEBUG))
				fprintf(fp, "%s\t[framesize: DISABLED]\n", 
					strip_linefeeds(buf2));
			break;
		} 
        }
        close_tmpfile2();

	if (textaddr_save)
		textaddr = textaddr_save;

	return (x86_64_framesize_cache_func(FRAMESIZE_ENTER, textaddr, 
		&framesize, exception, NULL));
}

static void 
x86_64_framesize_debug(struct bt_info *bt)
{
	int framesize;
	int exception;

	exception = (bt->flags & BT_EFRAME_SEARCH);

	switch (bt->hp->esp) 
	{
	case 1: /* "dump" */
		x86_64_framesize_cache_func(FRAMESIZE_DUMP, 0, NULL, 0, NULL);
		break;

	case 0:
		if (bt->hp->eip) {  /* clear one entry */
			framesize = -1;
			x86_64_framesize_cache_func(FRAMESIZE_ENTER, bt->hp->eip, 
				&framesize, exception, NULL);
		} else { /* clear all entries */
			BZERO(&x86_64_framesize_cache[0], 
			    sizeof(struct framesize_cache)*framesize_cache_entries);
			BZERO(&x86_64_framesize_no_cache[0], 
			    sizeof(ulong)*framesize_no_cache_entries);
			fprintf(fp, "framesize caches cleared\n");
		}
		break;

	case -1:
		if (!bt->hp->eip)
			error(INFO, "x86_64_framesize_debug: ignoring command\n");
		else
			x86_64_get_framesize(bt, bt->hp->eip, 0, NULL);
		break;

	case -3:
		machdep->flags |= FRAMEPOINTER;
		BZERO(&x86_64_framesize_cache[0], 
			sizeof(struct framesize_cache)*framesize_cache_entries);
		BZERO(&x86_64_framesize_no_cache[0], 
			sizeof(ulong)*framesize_no_cache_entries);
		fprintf(fp, 
			"framesize caches cleared and FRAMEPOINTER turned ON\n");
		break;

	case -4:
		machdep->flags &= ~FRAMEPOINTER;
		BZERO(&x86_64_framesize_cache[0], 
			sizeof(struct framesize_cache)*framesize_cache_entries);
		BZERO(&x86_64_framesize_no_cache[0], 
			sizeof(ulong)*framesize_no_cache_entries);
		fprintf(fp,
			"framesize caches cleared and FRAMEPOINTER turned OFF\n");
		break;

	case -5:
		if (!bt->hp->eip)
			error(INFO, "x86_64_framesize_debug: ignoring command (no ip)\n");
		else
			orc_dump(bt->hp->eip);
		break;

	default:
		if (bt->hp->esp > 1) {
			framesize = bt->hp->esp;
			if (bt->hp->eip)
				x86_64_framesize_cache_func(FRAMESIZE_ENTER, bt->hp->eip, 
					&framesize, exception, NULL);
		} else
			error(INFO, "x86_64_framesize_debug: ignoring command\n");
		break;
	}
}

/*
 *  The __schedule() framesize should only have to be calculated
 *  one time, but always verify that the previously-determined 
 *  framesize applies to this task, and if it doesn't, recalculate.
 *  Update the bt->instptr here, and return the new stack pointer.
 */
static ulong 
__schedule_frame_adjust(ulong rsp_in, struct bt_info *bt)
{
	int i, found;
	ulong rsp, *up;
	struct syment *sp;
	int framesize;

	if (!INSTACK(rsp_in, bt))
		error(FATAL, 
		    "invalid RSP: %lx  bt->stackbase/stacktop: %lx/%lx cpu: %d\n",
			rsp_in, bt->stackbase, bt->stacktop, bt->tc->processor);

	if (x86_64_framesize_cache_func(FRAMESIZE_QUERY, 
	    machdep->machspec->thread_return, &framesize, 0, NULL)) {
		rsp = rsp_in + framesize;
		i = (rsp - bt->stackbase)/sizeof(ulong);
		up = (ulong *)(&bt->stackbuf[i*sizeof(ulong)]);

		if (is_kernel_text_offset(*up) &&
		    (sp = x86_64_function_called_by((*up)-5)) &&
		    STREQ(sp->name, "__schedule")) {
			bt->instptr = *up;
			return (rsp);
		}
	}

	rsp = rsp_in;

	for (found = FALSE, i = (rsp - bt->stackbase)/sizeof(ulong);
	     rsp < bt->stacktop; i++, rsp += sizeof(ulong)) {
		up = (ulong *)(&bt->stackbuf[i*sizeof(ulong)]);

		if (!is_kernel_text_offset(*up))
			continue;

		if ((sp = x86_64_function_called_by((*up)-5)) &&
		    (STREQ(sp->name, "__schedule"))) {
			framesize = (int)(rsp - rsp_in);
			bt->instptr = *up;
			x86_64_framesize_cache_func(FRAMESIZE_ENTER, 
			    machdep->machspec->thread_return,
			    &framesize, 0, NULL);
			bt->instptr = *up;
			found = TRUE;
			break;
		}
	}

	if (CRASHDEBUG(1) && !found)
		error(INFO, "cannot determine __schedule() caller\n");

	return (found ? rsp : rsp_in);
}

static void
x86_64_get_active_set(void)
{
	int c;
	ulong current;
	struct task_context *actctx, *curctx;
        struct machine_specific *ms;

	if (ACTIVE())
		return;

	ms = machdep->machspec;
	if (!ms->current)
		return;

	if (CRASHDEBUG(1))
		fprintf(fp, "x86_64_get_active_set: runqueue vs. %s\n",
			VALID_STRUCT(x8664_pda) ? "x8664_pda" : "current_task");

	for (c = 0; c < kt->cpus; c++) {

		if (!tt->active_set[c])
			continue;

		current = ms->current[c];
		curctx = task_to_context(current);
		actctx = task_to_context(tt->active_set[c]);

		if (CRASHDEBUG(1))
			fprintf(fp, "  [%d]: %016lx %016lx %s%s\n",
				c, tt->active_set[c], current,
				curctx ? "" : "(invalid task)",
				curctx && (curctx->processor != c) ?
				"(wrong processor)" : "");

		if (!curctx || (curctx->processor != c))
			continue;

		if (tt->active_set[c] == current)
			continue;

		if (tt->active_set[c] == tt->panic_task)
			continue;

		if (stkptr_to_task(ms->crash_nmi_rsp[c]) == curctx->task)
			tt->active_set[c] = tt->panic_threads[c] = current;

		error(INFO, 
		    "inconsistent active task indications for CPU %d:\n", c);
		error(CONT, 
		    "   %srunqueue: %lx \"%s\" (default)\n",
			VALID_STRUCT(x8664_pda) ? "" : " ",
			actctx->task, actctx->comm);
		error(CONT,
		    "%s: %lx \"%s\" %s\n%s",
			VALID_STRUCT(x8664_pda) ? "  x8664_pda" : "current_task",			
			current, curctx->comm, 
			tt->active_set[c] == current ?  "(reassigned)" : "",
                        CRASHDEBUG(1) ? "" : "\n");
	}
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

/*
 *  Populate the vaddr_range array with a sorted list of
 *  kernel virtual address ranges.  The caller is responsible
 *  for ensuring that the array is large enough, so it should
 *  first call this function with a NULL vaddr_range pointer,
 *  which will return the count of kernel virtual address 
 *  space ranges.  
 */
static int
x86_64_get_kvaddr_ranges(struct vaddr_range *vrp)
{
	int cnt;
	ulong start;

	cnt = 0;

	vrp[cnt].type = KVADDR_UNITY_MAP;
	vrp[cnt].start = machdep->machspec->page_offset;
	vrp[cnt++].end = vt->high_memory;

	vrp[cnt].type = KVADDR_START_MAP;
	vrp[cnt].start = __START_KERNEL_map;
	vrp[cnt++].end = kt->end;

	vrp[cnt].type = KVADDR_VMALLOC;
	vrp[cnt].start = machdep->machspec->vmalloc_start_addr;
	vrp[cnt++].end = last_vmalloc_address();

	/*
	 *  Verify that these two regions stand alone.
	 */
	if (st->mods_installed) {
		start = lowest_module_address();

		if (!in_vmlist_segment(start)) {
			vrp[cnt].type = KVADDR_MODULES;
			vrp[cnt].start = start;
			vrp[cnt++].end = roundup(highest_module_address(), 
				PAGESIZE());
		}
	}

	if (machdep->flags & VMEMMAP) {
		start = machdep->machspec->vmemmap_vaddr;

		if (!in_vmlist_segment(start)) {
			vrp[cnt].type = KVADDR_VMEMMAP;
			vrp[cnt].start = start;
			vrp[cnt++].end = vt->node_table[vt->numnodes-1].mem_map +
				(vt->node_table[vt->numnodes-1].size * SIZE(page));
		}
	}

	qsort(vrp, cnt, sizeof(struct vaddr_range), compare_kvaddr);

	return cnt;
}

static int
x86_64_get_cpu_reg(int cpu, int regno, const char *name,
                   int size, void *value)
{
        if (regno >= LAST_REGNUM)
                return FALSE;

        if (VMSS_DUMPFILE())
                return vmware_vmss_get_cpu_reg(cpu, regno, name, size, value);

        return FALSE;
}

/*
 *  Determine the physical memory range reserved for GART.
 */
static void
GART_init(void)
{
	char resource[BUFSIZE];
	struct syment *sp;
	struct machine_specific *ms;

	if (!(sp = kernel_symbol_search("gart_resource")))
		return;

	STRUCT_SIZE_INIT(resource, "resource");
	MEMBER_OFFSET_INIT(resource_start, "resource", "start");
	MEMBER_OFFSET_INIT(resource_end, "resource", "end");

	if (VALID_STRUCT(resource) && 
	    VALID_MEMBER(resource_start) && 
	    VALID_MEMBER(resource_end)) {
		if (!readmem(sp->value, KVADDR, resource,
		    SIZE(resource), "GART resource", RETURN_ON_ERROR))
			return;
		ms = machdep->machspec;
		ms->GART_start = ULONG(resource + OFFSET(resource_start));
		ms->GART_end = ULONG(resource + OFFSET(resource_end)); 
		if (ms->GART_start && ms->GART_end) {
			machdep->flags |= GART_REGION;
			if (CRASHDEBUG(1))
				fprintf(fp, "GART address range: %lx - %lx\n", 
					ms->GART_start, ms->GART_end);
		}
	}
}

static int 
x86_64_verify_paddr(uint64_t paddr)
{
	struct machine_specific *ms;

	if (machdep->flags & GART_REGION) {
		ms = machdep->machspec;
		if (ms->GART_start && ms->GART_end &&
		    (paddr >= ms->GART_start) &&
		    (paddr <= ms->GART_end))
			return FALSE;
	}

	return TRUE;
}

static ulong 
orc_ip(ulong ip)
{
	int ip_entry;

	if (!readmem((ulong)ip, KVADDR, &ip_entry, sizeof(int), 
	    "orc_ip", QUIET|RETURN_ON_ERROR))
		return 0;

	return (ip + ip_entry); 
}

static kernel_orc_entry *
__orc_find(ulong ip_table_ptr, ulong u_table_ptr, uint num_entries, ulong ip)
{
	int index;
	int *first = (int *)ip_table_ptr;
	int *last = (int *)ip_table_ptr + num_entries - 1;
	int *mid = first, *found = first;
	int *ip_table = (int *)ip_table_ptr;
	struct ORC_data *orc = &machdep->machspec->orc;
	ulong vaddr;
	kernel_orc_entry *korc;

	if (CRASHDEBUG(2)) {
		int i, ip_entry;
		ulong ptr;
		ulong offset;
		struct syment *sp;

		fprintf(fp, "__orc_find:\n  ip: %lx  num_entries: %d\n", 
			ip, num_entries);

		for (i = 0; i < num_entries; i++) {
			ptr = ip_table_ptr + (i*4);
			if (!readmem((ulong)ptr, KVADDR, &ip_entry, sizeof(int), 
			    "ip entry", RETURN_ON_ERROR))
				return NULL;
			if (!(vaddr = orc_ip(ptr)))
				return NULL;
			fprintf(fp, "  orc_ip(%lx): %x -> %lx / ", ptr, ip_entry, vaddr); 
			if ((sp = value_search(vaddr, &offset))) {
				fprintf(fp, "%s+%ld -> ", sp->name, offset);
				fprintf(fp, "%lx\n", u_table_ptr + (i * SIZE(orc_entry)));
			} else
				fprintf(fp, "(unknown symbol value)\n");
		}
	}

	while (first <= last) {
		mid = first + ((last - first) / 2);

		if (!(vaddr = orc_ip((ulong)mid)))
			return NULL;

		if (vaddr <= ip) {
			found = mid;
			first = mid + 1;
		} else
			last = mid - 1;
	}

	index = found - ip_table;

	orc->ip_entry = (ulong)found;
	orc->orc_entry = u_table_ptr + (index * SIZE(orc_entry));
	if (!readmem(orc->orc_entry, KVADDR, &orc->kernel_orc_entry, 
	    sizeof(kernel_orc_entry), "kernel orc_entry", RETURN_ON_ERROR|QUIET)) 
		return NULL;

	korc = &orc->kernel_orc_entry;

	if (CRASHDEBUG(2)) {
		fprintf(fp, "  found: %lx  index: %d\n", (ulong)found, index);
                fprintf(fp, 
		    "  orc_entry: %lx  sp_offset: %d bp_offset: %d sp_reg: %d bp_reg: %d type: %d",
			orc->orc_entry, korc->sp_offset, korc->bp_offset, korc->sp_reg, korc->bp_reg, korc->type);
		if (MEMBER_EXISTS("orc_entry", "end"))
			fprintf(fp, " end: %d", korc->end); 
		fprintf(fp, "\n"); 
	}

	return korc;
}

#define LOOKUP_BLOCK_ORDER      8
#define LOOKUP_BLOCK_SIZE       (1 << LOOKUP_BLOCK_ORDER)
#define LOOKUP_START_IP         (unsigned long)kt->stext
#define LOOKUP_STOP_IP          (unsigned long)kt->etext

static kernel_orc_entry *
orc_find(ulong ip)
{
	unsigned int idx, start, stop;
	struct ORC_data *orc = &machdep->machspec->orc;

	if ((ip < LOOKUP_START_IP) || (ip >= LOOKUP_STOP_IP)) {
		if ((ip >= MODULES_VADDR) && (ip < MODULES_END))
			return orc_module_find(ip);
		error(WARNING, 
			"%lx: ip is outside kernel and module text ranges\n", ip);
		return NULL;
	}

	idx = (ip - LOOKUP_START_IP) / LOOKUP_BLOCK_SIZE;

	if (idx >= orc->lookup_num_blocks-1) {
		if (CRASHDEBUG(1)) {
			error(INFO, "bad lookup: idx: %u lookup_num_blocks: %u ip: %lx\n",
				idx, orc->lookup_num_blocks, ip);
		}
		return NULL;
	}

	if (!readmem(orc->orc_lookup + (sizeof(unsigned int) * idx), KVADDR,
	    &start, sizeof(unsigned int), "orc_lookup start", RETURN_ON_ERROR|QUIET)) {
		if (CRASHDEBUG(1))
			error(INFO, "cannot read \"start\" orc_lookup entry at %lx\n",
				orc->orc_lookup + (sizeof(unsigned int) * idx));
		return NULL;
	}
	if (!readmem(orc->orc_lookup + (sizeof(unsigned int) * (idx+1)), KVADDR,
	    &stop, sizeof(unsigned int), "orc_lookup stop", RETURN_ON_ERROR|QUIET)) {
		if (CRASHDEBUG(1))
			error(INFO, "cannot read \"stop\" orc_lookup entry at %lx\n",
				orc->orc_lookup + (sizeof(unsigned int) * (idx+1)));
		return NULL;
	}
	stop += 1;

	if (CRASHDEBUG(2)) {
		fprintf(fp, "orc_find:\n  ip: %lx  idx: %d\n", ip, idx);
		fprintf(fp, "  start = orc_lookup[%d]: %d\n"
			    "  stop = orc_lookup[%d] + 1: %d\n",
			idx, start, idx+1, stop);
		fprintf(fp, "  ip table start: %lx\n",
			orc->__start_orc_unwind_ip + (start * sizeof(int)));
		fprintf(fp, "  unwind table start: %lx\n",
			orc->__start_orc_unwind + (start * SIZE(orc_entry)));
	}

	if ((orc->__start_orc_unwind + (start * SIZE(orc_entry))) >= orc->__stop_orc_unwind) {
		if (CRASHDEBUG(1)) 
			error(INFO, 
			    "bad unwind lookup start: idx: %u num: %u start: %u stop: %u ip: %lx\n",
				idx, orc->lookup_num_blocks, start, stop, ip);
		return NULL;
	}
	if ((orc->__start_orc_unwind + (stop * SIZE(orc_entry))) > orc->__stop_orc_unwind) {
		if (CRASHDEBUG(1))
			error(INFO, 
			    "bad unwind lookup stop: idx: %u num: %u start: %u stop: %u ip: %lx\n",
				idx, orc->lookup_num_blocks, start, stop, ip);
		return NULL;
	}

	return __orc_find(orc->__start_orc_unwind_ip + (start * sizeof(int)),
		orc->__start_orc_unwind + (start * SIZE(orc_entry)), stop - start, ip);
}

static kernel_orc_entry *
orc_module_find(ulong ip)
{
	struct load_module *lm;
	uint num_orcs;
	ulong orc_unwind_ip, orc_unwind, module_arch;
	struct ORC_data *orc = &machdep->machspec->orc;

	if (!(orc->module_ORC) || !module_symbol(ip, NULL, &lm, NULL, 0))
		return NULL;

	module_arch = lm->module_struct + OFFSET(module_arch);

	if (!readmem(module_arch + OFFSET(mod_arch_specific_num_orcs), KVADDR, 
	    &num_orcs, sizeof(int), "module num_orcs", RETURN_ON_ERROR|QUIET)) 
		return NULL;
	if (!readmem(module_arch + OFFSET(mod_arch_specific_orc_unwind_ip), KVADDR, 
	    &orc_unwind_ip, sizeof(void *), "module orc_unwind_ip", RETURN_ON_ERROR|QUIET)) 
		return NULL;
	if (!readmem(module_arch + OFFSET(mod_arch_specific_orc_unwind), KVADDR, 
	    &orc_unwind, sizeof(void *), "module orc_unwind", RETURN_ON_ERROR|QUIET)) 
		return NULL;

	if (CRASHDEBUG(2)) {
		fprintf(fp, "orc_module_find:\n");
		fprintf(fp, "  num_orcs: %d orc_unwind_ip: %lx orc_unwind: %lx\n", 
			num_orcs, orc_unwind_ip, orc_unwind);
	}

	return __orc_find(orc_unwind_ip, orc_unwind, num_orcs, ip);
}

static ulong
ip_table_to_vaddr(ulong ip_table)
{
	int ip_entry;

	if (!readmem((ulong)ip_table, KVADDR, &ip_entry, sizeof(int), "ip entry", RETURN_ON_ERROR))
                error(FATAL, "ip_table_to_vaddr: cannot read ip_table: %lx\n", ip_table);

	return (ip_table + ip_entry);
}

static void
orc_dump(ulong ip)
{
	struct ORC_data *orc = &machdep->machspec->orc;
	kernel_orc_entry *korc;
	ulong vaddr, offset;
	struct syment *sp, *orig;

	fprintf(fp, "orc_dump: %lx / ", ip);
	if ((sp = value_search(ip, &offset)))
		fprintf(fp, "%s+%ld\n--------\n", sp->name, offset);
	else
		fprintf(fp, "(unresolved)\n--------\n");
	orig = sp;

	if (!orc_find(ip)) {
		fprintf(fp, "%lx: ip not found\n", ip);
		return;
	}

next_in_func:
	fprintf(fp, "ip: %lx -> %lx / ",  orc->ip_entry, 
		vaddr = ip_table_to_vaddr(orc->ip_entry));
	if ((sp = value_search(vaddr, &offset)))
		fprintf(fp, "%s+%ld -> ", sp->name, offset);
	else
		fprintf(fp, "(unresolved) -> ");
	if (!readmem(orc->orc_entry, KVADDR, &orc->kernel_orc_entry, sizeof(kernel_orc_entry),
	    "kernel orc_entry", RETURN_ON_ERROR)) 
		error(FATAL, "cannot read orc_entry\n");
	korc = &orc->kernel_orc_entry;
	fprintf(fp, "orc: %lx  spo: %d bpo: %d spr: %d bpr: %d type: %d",
			orc->orc_entry, korc->sp_offset, korc->bp_offset, korc->sp_reg, korc->bp_reg, korc->type);
	if (MEMBER_EXISTS("orc_entry", "end"))
		fprintf(fp, " end: %d", korc->end);
	fprintf(fp, "\n");

	orc->ip_entry += sizeof(int);
	orc->orc_entry += sizeof(kernel_orc_entry);
	vaddr = ip_table_to_vaddr(orc->ip_entry);
	if ((sp = value_search(vaddr, &offset)))
		if (sp == orig)
			goto next_in_func;
}

/*
 *  KPTI entry stack initialization.  May vary signficantly
 *  between upstream and distribution backports.
 */
static void 
x86_64_entry_trampoline_init(void)
{
	struct machine_specific *ms;
	struct syment *sp;

	ms = machdep->machspec;

	if (!kernel_symbol_exists("pti_init") &&
	    !kernel_symbol_exists("kaiser_init"))
		return;

	/*
	 *  4.15
	 */
	if (MEMBER_EXISTS("entry_stack", "words") && 
	    MEMBER_EXISTS("entry_stack_page", "stack") &&
	    (sp = per_cpu_symbol_search("per_cpu__entry_stack_storage"))) {
		ms->kpti_entry_stack = sp->value + MEMBER_OFFSET("entry_stack_page", "stack");
		ms->kpti_entry_stack_size = MEMBER_SIZE("entry_stack", "words");
		machdep->flags |= KPTI;
		return;
	}

	/* 
	 *  RHEL
	 */
	if (MEMBER_EXISTS("tss_struct", "stack")) {
		if (!(sp = per_cpu_symbol_search("per_cpu__init_tss")))
			sp = per_cpu_symbol_search("per_cpu__cpu_tss");
		ms->kpti_entry_stack = sp->value + MEMBER_OFFSET("tss_struct", "stack");
		ms->kpti_entry_stack_size = MEMBER_SIZE("tss_struct", "stack");
		machdep->flags |= KPTI;
		return;
	}
}

static ulong
x86_64_in_kpti_entry_stack(int cpu, ulong rsp)
{
	ulong stack_base, stack_end;
	struct machine_specific *ms;

	if (!(machdep->flags & KPTI))
		return 0;

	ms = machdep->machspec;

	if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF)) {
		if (kt->__per_cpu_offset[cpu] == 0)
			return 0;
		stack_base = ms->kpti_entry_stack + kt->__per_cpu_offset[cpu];
	} else
		stack_base = ms->kpti_entry_stack; 

	stack_end = stack_base + 
		(ms->kpti_entry_stack_size > 0 ? ms->kpti_entry_stack_size : 512);

	if ((rsp >= stack_base) && (rsp < stack_end))
		return(stack_end - SIZE(pt_regs));

	return 0;
}

/*
 *  Original:
 *
 *    #define SWP_TYPE(entry) (((entry) >> 1) & 0x3f)
 *    #define SWP_OFFSET(entry) ((entry) >> 8)
 *
 *  4.8:
 *    | OFFSET (14-63)  |  TYPE (9-13) |0|X|X|X| X| X|X|X|0|
 *
 *  l1tf:
 *    |     ...            | 11| 10|  9|8|7|6|5| 4| 3|2| 1|0| <- bit number
 *    |     ...            |SW3|SW2|SW1|G|L|D|A|CD|WT|U| W|P| <- bit names
 *    | TYPE (59-63) | ~OFFSET (9-58)  |0|0|X|X| X| X|X|SD|0| <- swp entry
 */


ulong 
x86_64_swp_type(ulong entry)
{
	if (machdep->flags & L1TF)
 		return(entry >> 59);

	if (THIS_KERNEL_VERSION >= LINUX(4,8,0))
 		return((entry >> 9) & 0x1f);
 
	return SWP_TYPE(entry);
}

ulong 
x86_64_swp_offset(ulong entry)
{
	if (machdep->flags & L1TF)
		return((~entry << 5) >> 14);

	if (THIS_KERNEL_VERSION >= LINUX(4,8,0))
 		return(entry >> 14);

	return SWP_OFFSET(entry);
}

#endif  /* X86_64 */ 
