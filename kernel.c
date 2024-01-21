/* kernel.c - core analysis suite
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002-2019 David Anderson
 * Copyright (C) 2002-2019 Red Hat, Inc. All rights reserved.
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
#include "xen_dom0.h"
#include <elf.h>
#include <libgen.h>
#include <ctype.h>
#include <stdbool.h>
#include "xendump.h"
#if defined(GDB_7_6) || defined(GDB_10_2)
#define __CONFIG_H__ 1
#include "config.h"
#endif
#include "bfd.h"

static void do_module_cmd(ulong, char *, ulong, char *, char *);
static void show_module_taint(void);
static char *find_module_objfile(char *, char *, char *);
static char *module_objfile_search(char *, char *, char *);
static char *get_loadavg(char *);
static void get_lkcd_regs(struct bt_info *, ulong *, ulong *);
static void dump_sys_call_table(char *, int);
static int get_NR_syscalls(int *);
static ulong get_irq_desc_addr(int);
static void display_cpu_affinity(ulong *);
static void display_bh_1(void);
static void display_bh_2(void);
static void display_bh_3(void);
static void display_bh_4(void);
static void dump_hrtimer_data(const ulong *cpus);
static void dump_hrtimer_clock_base(const void *, const int);
static void dump_hrtimer_base(const void *, const int);
static void dump_active_timers(const void *, ulonglong);
static int get_expires_len(const int, const ulong *, ulonglong, const int);
static void print_timer(const void *, ulonglong);
static ulonglong ktime_to_ns(const void *);
static void dump_timer_data(const ulong *cpus);
static void dump_timer_data_tvec_bases_v1(const ulong *cpus);
static void dump_timer_data_tvec_bases_v2(const ulong *cpus);
static void dump_timer_data_tvec_bases_v3(const ulong *cpus);
static void dump_timer_data_timer_bases(const ulong *cpus);
struct tv_range;
static void init_tv_ranges(struct tv_range *, int, int, int);
static int do_timer_list(ulong,int, ulong *, void *,ulong *, ulong *, struct tv_range *, ulong);
static int do_timer_list_v3(ulong, int, ulong *, void *,ulong *, ulong *, ulong, long);
struct timer_bases_data;
static int do_timer_list_v4(struct timer_bases_data *, ulong);
static int compare_timer_data(const void *, const void *);
static void panic_this_kernel(void);
static void dump_waitq(ulong, char *);
static void reinit_modules(void);
static int verify_modules(void);
static void verify_namelist(void);
static char *debug_kernel_version(char *);
static int restore_stack(struct bt_info *);
static ulong __xen_m2p(ulonglong, ulong);
static ulong __xen_pvops_m2p_l2(ulonglong, ulong);
static ulong __xen_pvops_m2p_l3(ulonglong, ulong);
static ulong __xen_pvops_m2p_hyper(ulonglong, ulong);
static ulong __xen_pvops_m2p_domU(ulonglong, ulong);
static int read_xc_p2m(ulonglong, void *, long);
static void read_p2m(ulong, int, void *);
static int search_mapping_page(ulong, ulong *, ulong *, ulong *);
static void read_in_kernel_config_err(int, char *);
static void BUG_bytes_init(void);
static int BUG_x86(void);
static int BUG_x86_64(void);
static void cpu_maps_init(void);
static void get_xtime(struct timespec *);
static char *log_from_idx(uint32_t, char *);
static uint32_t log_next(uint32_t, char *);
static void dump_log_entry(char *, int);
static void dump_variable_length_record_log(int);
static void hypervisor_init(void);
static void dump_log_legacy(void);
static void dump_variable_length_record(void);
static int is_livepatch(void);
static void show_kernel_taints(char *, int);
static void dump_dmi_info(void);
static void list_source_code(struct gnu_request *, int);
static void source_tree_init(void);
static ulong dump_audit_skb_queue(ulong);
static ulong __dump_audit(char *);
static void dump_audit(void);
static void dump_printk_safe_seq_buf(int);
static char *vmcoreinfo_read_string(const char *);
static void check_vmcoreinfo(void);
static int is_pvops_xen(void);
static int get_linux_banner_from_vmlinux(char *, size_t);

/*
 * popuplate the global kernel table (kt) with kernel version
 * information parsed from UTSNAME/OSRELEASE string
 */
void
parse_kernel_version(char *str)
{
	char *p1, *p2, separator;

	p1 = p2 = str;
	while (*p2 != '.' && *p2 != '\0')
		p2++;

	*p2 = NULLCHAR;
	kt->kernel_version[0] = atoi(p1);
	p1 = ++p2;
	while (*p2 != '.' && *p2 != '-' && *p2 != '\0')
		p2++;

	separator = *p2;
	*p2 = NULLCHAR;
	kt->kernel_version[1] = atoi(p1);

	if (separator == '.') {
		p1 = ++p2;
		while ((*p2 >= '0') && (*p2 <= '9'))
			p2++;

		*p2 = NULLCHAR;
		kt->kernel_version[2] = atoi(p1);
	}
}

/*
 *  Gather a few kernel basics.
 */
void
kernel_init()
{
	int i, c;
	char buf[BUFSIZE];
	struct syment *sp1, *sp2;
	char *rqstruct;
	char *rq_timestamp_name = NULL;
	char *irq_desc_type_name;	
	struct gnu_request req;

	if (pc->flags & KERNEL_DEBUG_QUERY)
		return;

        if (!(kt->cpu_flags = (ulong *)calloc(NR_CPUS, sizeof(ulong))))
                error(FATAL, "cannot malloc cpu_flags array");

	cpu_maps_init();

	kt->stext = symbol_value("_stext");
	kt->etext = symbol_value("_etext");
	get_text_init_space(); 
	if (symbol_exists("__init_begin")) {
		kt->init_begin = symbol_value("__init_begin");
		kt->init_end = symbol_value("__init_end");
	}
	kt->end = highest_bss_symbol();
	if ((sp1 = kernel_symbol_search("_end")) && (sp1->value > kt->end)) 
		kt->end = sp1->value;

	check_vmcoreinfo();
	
	/*
	 *  For the traditional (non-pv_ops) Xen architecture, default to writable 
         *  page tables unless:
	 *  
	 *  (1) it's an "xm save" CANONICAL_PAGE_TABLES dumpfile,  or
	 *  (2) the --shadow_page_tables option was explicitly entered.  
	 *
	 *  But if the "phys_to_maching_mapping" array does not exist, and 
         *  it's not an "xm save" canonical dumpfile, then we have no choice 
         *  but to presume shadow page tables.
	 */ 
	if (!PVOPS() && symbol_exists("xen_start_info")) {
		kt->flags |= ARCH_XEN;
		if (!(kt->xen_flags & (SHADOW_PAGE_TABLES|CANONICAL_PAGE_TABLES)))
			kt->xen_flags |= WRITABLE_PAGE_TABLES;
		if (symbol_exists("phys_to_machine_mapping"))
         		get_symbol_data("phys_to_machine_mapping", sizeof(ulong),
                       		&kt->phys_to_machine_mapping);
		else if (!(kt->xen_flags & CANONICAL_PAGE_TABLES)) {
			kt->xen_flags &= ~WRITABLE_PAGE_TABLES;
			kt->xen_flags |= SHADOW_PAGE_TABLES;
		}
		if (machine_type("X86"))
                	get_symbol_data("max_pfn", sizeof(ulong), &kt->p2m_table_size);
		if (machine_type("X86_64")) {
			/*
			 * kernel version <  2.6.27 => end_pfn
			 * kernel version >= 2.6.27 => max_pfn
			 */
			if (!try_get_symbol_data("end_pfn", sizeof(ulong), &kt->p2m_table_size))
				get_symbol_data("max_pfn", sizeof(ulong), &kt->p2m_table_size);
		}
                if ((kt->m2p_page = (char *)malloc(PAGESIZE())) == NULL)
                       	error(FATAL, "cannot malloc m2p page.");
	}

	if (is_pvops_xen()) {
		kt->flags |= ARCH_XEN | ARCH_PVOPS_XEN;
		kt->xen_flags |= WRITABLE_PAGE_TABLES;
		if (machine_type("X86"))
                	get_symbol_data("max_pfn", sizeof(ulong), &kt->p2m_table_size);
		if (machine_type("X86_64")) {
			if (!try_get_symbol_data("end_pfn", sizeof(ulong), &kt->p2m_table_size))
				get_symbol_data("max_pfn", sizeof(ulong), &kt->p2m_table_size);
		}
                if ((kt->m2p_page = (char *)malloc(PAGESIZE())) == NULL)
                       	error(FATAL, "cannot malloc m2p page.");

		if (symbol_exists("p2m_mid_missing")) {
			kt->pvops_xen.p2m_top_entries = XEN_P2M_TOP_PER_PAGE;
			get_symbol_data("p2m_top", sizeof(ulong),
						&kt->pvops_xen.p2m_top);
			get_symbol_data("p2m_mid_missing", sizeof(ulong),
						&kt->pvops_xen.p2m_mid_missing);
			get_symbol_data("p2m_missing", sizeof(ulong),
						&kt->pvops_xen.p2m_missing);
		} else if (!symbol_exists("xen_p2m_addr")) {
			kt->pvops_xen.p2m_top_entries = get_array_length("p2m_top", NULL, 0);
			kt->pvops_xen.p2m_top = symbol_value("p2m_top");
			kt->pvops_xen.p2m_missing = symbol_value("p2m_missing");
		}
	}

	if (symbol_exists("smp_num_cpus")) {
		kt->flags |= SMP;
		get_symbol_data("smp_num_cpus", sizeof(int), &kt->cpus);
		if (kt->cpus < 1 || kt->cpus > NR_CPUS)
			error(WARNING, 
			    "invalid value: smp_num_cpus: %d\n",
				kt->cpus);
	} else if (symbol_exists("__per_cpu_offset")) {
		kt->flags |= SMP;
		kt->cpus = 1;
	} else 
		kt->cpus = 1;

	if ((sp1 = symbol_search("__per_cpu_start")) &&
 	    (sp2 = symbol_search("__per_cpu_end")) &&
	    (sp1->type == 'A' || sp1->type == 'D') && 
	    (sp2->type == 'A' || sp2->type == 'D') &&
	    (sp2->value > sp1->value))
		kt->flags |= SMP|PER_CPU_OFF;
	
	MEMBER_OFFSET_INIT(timekeeper_xtime, "timekeeper", "xtime");
	MEMBER_OFFSET_INIT(timekeeper_xtime_sec, "timekeeper", "xtime_sec");
	get_xtime(&kt->date);
	if (CRASHDEBUG(1))
		fprintf(fp, "xtime timespec.tv_sec: %lx: %s\n", 
			kt->date.tv_sec, ctime_tz(&kt->date.tv_sec));
	if (kt->flags2 & GET_TIMESTAMP) {
		fprintf(fp, "%s\n\n", ctime_tz(&kt->date.tv_sec));
		clean_exit(0);
	}

	MEMBER_OFFSET_INIT(uts_namespace_name, "uts_namespace", "name");
	if (symbol_exists("system_utsname"))
        	readmem(symbol_value("system_utsname"), KVADDR, &kt->utsname,
                	sizeof(struct new_utsname), "system_utsname", 
			RETURN_ON_ERROR);
	else if (symbol_exists("init_uts_ns")) {
		long offset = sizeof(int);
		if (VALID_MEMBER(uts_namespace_name))
			offset = OFFSET(uts_namespace_name);

		readmem(symbol_value("init_uts_ns") + offset,
			KVADDR,  &kt->utsname, sizeof(struct new_utsname),
			"init_uts_ns", RETURN_ON_ERROR);
	} else
		error(INFO, "cannot access utsname information\n\n");

	if (CRASHDEBUG(1)) {
		fprintf(fp, "utsname:\n");
		fprintf(fp, "     sysname: %s\n", printable_string(kt->utsname.sysname) ? 
			kt->utsname.sysname : "(not printable)");
		fprintf(fp, "    nodename: %s\n", printable_string(kt->utsname.nodename) ? 
			kt->utsname.nodename : "(not printable)");
		fprintf(fp, "     release: %s\n", printable_string(kt->utsname.release) ? 
			kt->utsname.release : "(not printable)");
		fprintf(fp, "     version: %s\n", printable_string(kt->utsname.version) ? 
			kt->utsname.version : "(not printable)");
		fprintf(fp, "     machine: %s\n", printable_string(kt->utsname.machine) ? 
			kt->utsname.machine : "(not printable)");
		fprintf(fp, "  domainname: %s\n", printable_string(kt->utsname.domainname) ? 
			kt->utsname.domainname : "(not printable)");
	}

	strncpy(buf, kt->utsname.release, 65);
	if (buf[64])
		buf[64] = NULLCHAR;
	if (ascii_string(kt->utsname.release)) {
		parse_kernel_version(buf);

		if (CRASHDEBUG(1))
			fprintf(fp, "base kernel version: %d.%d.%d\n",
				kt->kernel_version[0],
				kt->kernel_version[1],
				kt->kernel_version[2]);
	} else
		error(INFO, "cannot determine base kernel version\n");


	verify_version();

	if (symbol_exists("__per_cpu_offset")) {
		if (LKCD_KERNTYPES())
			i = get_cpus_possible();
		else
			i = get_array_length("__per_cpu_offset", NULL, 0);
		get_symbol_data("__per_cpu_offset",
			sizeof(long)*((i && (i <= NR_CPUS)) ? i : NR_CPUS),
			&kt->__per_cpu_offset[0]);
                kt->flags |= PER_CPU_OFF;
	}

	MEMBER_OFFSET_INIT(percpu_counter_count, "percpu_counter", "count");
	MEMBER_OFFSET_INIT(percpu_counter_counters, "percpu_counter", "counters");
	STRUCT_SIZE_INIT(percpu_counter, "percpu_counter");

	if (STRUCT_EXISTS("runqueue")) {
		rqstruct = "runqueue";
		rq_timestamp_name = "timestamp_last_tick";
	} else if (STRUCT_EXISTS("rq")) {
		rqstruct = "rq";
		if (MEMBER_EXISTS("rq", "clock"))
			rq_timestamp_name = "clock";
		else if (MEMBER_EXISTS("rq", "most_recent_timestamp"))
			rq_timestamp_name = "most_recent_timestamp";
		else if (MEMBER_EXISTS("rq", "timestamp_last_tick"))
			rq_timestamp_name = "timestamp_last_tick";
	} else {
		rqstruct = NULL;
		error(FATAL, "neither runqueue nor rq structures exist\n");
	}

	MEMBER_OFFSET_INIT(runqueue_cpu, rqstruct, "cpu");
	/*
	 * 'cpu' does not exist in 'struct rq'.
	 */
	if (VALID_MEMBER(runqueue_cpu) &&
	    (get_array_length("runqueue.cpu", NULL, 0) > 0)) {
		MEMBER_OFFSET_INIT(cpu_s_curr, "cpu_s", "curr");
		MEMBER_OFFSET_INIT(cpu_s_idle, "cpu_s", "idle");
	 	STRUCT_SIZE_INIT(cpu_s, "cpu_s"); 
		kt->runq_siblings = get_array_length("runqueue.cpu", 
			NULL, 0);
		if (symbol_exists("__cpu_idx") &&
		    symbol_exists("__rq_idx")) {
			if (!(kt->__cpu_idx = (long *)
			    calloc(NR_CPUS, sizeof(long))))
				error(FATAL, "cannot malloc __cpu_idx array");
			if (!(kt->__rq_idx = (long *)
			    calloc(NR_CPUS, sizeof(long))))
				error(FATAL, "cannot malloc __rq_idx array");
			if (!readmem(symbol_value("__cpu_idx"), KVADDR, 
		            &kt->__cpu_idx[0], sizeof(long) * NR_CPUS,
                            "__cpu_idx[NR_CPUS]", RETURN_ON_ERROR))
				error(INFO, 
			            "cannot read __cpu_idx[NR_CPUS] array\n");
			if (!readmem(symbol_value("__rq_idx"), KVADDR, 
		            &kt->__rq_idx[0], sizeof(long) * NR_CPUS,
                            "__rq_idx[NR_CPUS]", RETURN_ON_ERROR))
				error(INFO, 
			           "cannot read __rq_idx[NR_CPUS] array\n");
		} else if (kt->runq_siblings > 1) 
			error(INFO, 
     	   "runq_siblings: %d: __cpu_idx and __rq_idx arrays don't exist?\n",
				kt->runq_siblings);
	} else {
		MEMBER_OFFSET_INIT(runqueue_idle, rqstruct, "idle");
		MEMBER_OFFSET_INIT(runqueue_curr, rqstruct, "curr");
		ASSIGN_OFFSET(runqueue_cpu) = INVALID_OFFSET;
	}
	MEMBER_OFFSET_INIT(runqueue_active, rqstruct, "active");
	MEMBER_OFFSET_INIT(runqueue_expired, rqstruct, "expired");
	MEMBER_OFFSET_INIT(runqueue_arrays, rqstruct, "arrays");
	MEMBER_OFFSET_INIT(rq_timestamp, rqstruct, rq_timestamp_name);
	MEMBER_OFFSET_INIT(prio_array_queue, "prio_array", "queue");
        MEMBER_OFFSET_INIT(prio_array_nr_active, "prio_array", "nr_active");
	STRUCT_SIZE_INIT(runqueue, rqstruct); 
	STRUCT_SIZE_INIT(prio_array, "prio_array"); 

	MEMBER_OFFSET_INIT(rq_cfs, "rq", "cfs");
	MEMBER_OFFSET_INIT(task_group_cfs_rq, "task_group", "cfs_rq");
	MEMBER_OFFSET_INIT(task_group_rt_rq, "task_group", "rt_rq");
	MEMBER_OFFSET_INIT(task_group_parent, "task_group", "parent");

       /*
        *  In 2.4, smp_send_stop() sets smp_num_cpus back to 1
        *  in some, but not all, architectures.  So if a count
        *  of 1 is found, be suspicious, and check the
        *  init_tasks[NR_CPUS] array (also intro'd in 2.4),
        *  for idle thread addresses.  For 2.2, prepare for the
     	*  eventuality by verifying the cpu count with the machine
	*  dependent count.
        */
        if ((kt->flags & SMP) && DUMPFILE() && (kt->cpus == 1)) {
                if (symbol_exists("init_tasks")) {
                        ulong init_tasks[NR_CPUS];
			int nr_cpus;

			BZERO(&init_tasks[0], sizeof(ulong) * NR_CPUS);

			nr_cpus = get_array_length("init_tasks", NULL, 0);
			if ((nr_cpus < 1) || (nr_cpus > NR_CPUS))
                                nr_cpus = NR_CPUS;

			get_idle_threads(&init_tasks[0], nr_cpus);

                        for (i = kt->cpus = 0; i < nr_cpus; i++)
                                if (init_tasks[i])
                                        kt->cpus++;
                } else 
			kt->cpus = machdep->get_smp_cpus();
	}

	if ((kt->flags & SMP) && ACTIVE() && (kt->cpus == 1) &&
	    (kt->flags & PER_CPU_OFF))
		kt->cpus = machdep->get_smp_cpus();

	if (kt->cpus_override && (c = atoi(kt->cpus_override))) {
		error(WARNING, "forcing cpu count to: %d\n\n", c);
		kt->cpus = c;
	}

	if (kt->cpus > NR_CPUS) {
		error(WARNING, 
       "%s number of cpus (%d) greater than compiled-in NR_CPUS (%d)\n",
			kt->cpus_override && atoi(kt->cpus_override) ? 
			"configured" : "calculated", kt->cpus, NR_CPUS);
		error(FATAL, "recompile crash with larger NR_CPUS\n");
	}

	hypervisor_init();

	STRUCT_SIZE_INIT(spinlock_t, "spinlock_t");
	verify_spinlock();

	if (STRUCT_EXISTS("atomic_t"))
		if (MEMBER_EXISTS("atomic_t", "counter"))
			MEMBER_OFFSET_INIT(atomic_t_counter,
					"atomic_t", "counter");

	STRUCT_SIZE_INIT(list_head, "list_head"); 
	MEMBER_OFFSET_INIT(list_head_next, "list_head", "next"); 
	MEMBER_OFFSET_INIT(list_head_prev, "list_head", "prev"); 
	if (OFFSET(list_head_next) != 0)
	    	error(WARNING, 
		    "list_head.next offset: %ld: list command may fail\n",
			OFFSET(list_head_next));

        MEMBER_OFFSET_INIT(hlist_node_next, "hlist_node", "next");
        MEMBER_OFFSET_INIT(hlist_node_pprev, "hlist_node", "pprev");
	STRUCT_SIZE_INIT(hlist_head, "hlist_head"); 
	STRUCT_SIZE_INIT(hlist_node, "hlist_node"); 

	if (STRUCT_EXISTS("irq_desc_t"))
		irq_desc_type_name = "irq_desc_t";
	else
		irq_desc_type_name = "irq_desc";

	STRUCT_SIZE_INIT(irq_desc_t, irq_desc_type_name);
	if (MEMBER_EXISTS(irq_desc_type_name, "irq_data"))
		MEMBER_OFFSET_INIT(irq_desc_t_irq_data, irq_desc_type_name, "irq_data");
	else
		MEMBER_OFFSET_INIT(irq_desc_t_affinity, irq_desc_type_name, "affinity");
	if (MEMBER_EXISTS(irq_desc_type_name, "kstat_irqs"))
		MEMBER_OFFSET_INIT(irq_desc_t_kstat_irqs, irq_desc_type_name, "kstat_irqs");
	MEMBER_OFFSET_INIT(irq_desc_t_name, irq_desc_type_name, "name");
	MEMBER_OFFSET_INIT(irq_desc_t_status, irq_desc_type_name, "status");
	if (MEMBER_EXISTS(irq_desc_type_name, "handler"))
		MEMBER_OFFSET_INIT(irq_desc_t_handler, irq_desc_type_name, "handler");
	else if (MEMBER_EXISTS(irq_desc_type_name, "chip"))
		MEMBER_OFFSET_INIT(irq_desc_t_chip, irq_desc_type_name, "chip");
	MEMBER_OFFSET_INIT(irq_desc_t_action, irq_desc_type_name, "action");
	MEMBER_OFFSET_INIT(irq_desc_t_depth, irq_desc_type_name, "depth");

	STRUCT_SIZE_INIT(kernel_stat, "kernel_stat");
	MEMBER_OFFSET_INIT(kernel_stat_irqs, "kernel_stat", "irqs");

	if (STRUCT_EXISTS("hw_interrupt_type")) {
		MEMBER_OFFSET_INIT(hw_interrupt_type_typename,
			"hw_interrupt_type", "typename");
		MEMBER_OFFSET_INIT(hw_interrupt_type_startup,
			"hw_interrupt_type", "startup");
		MEMBER_OFFSET_INIT(hw_interrupt_type_shutdown,
			"hw_interrupt_type", "shutdown");
		MEMBER_OFFSET_INIT(hw_interrupt_type_handle,
        	        "hw_interrupt_type", "handle");
		MEMBER_OFFSET_INIT(hw_interrupt_type_enable,
			"hw_interrupt_type", "enable");
		MEMBER_OFFSET_INIT(hw_interrupt_type_disable,
			"hw_interrupt_type", "disable");
		MEMBER_OFFSET_INIT(hw_interrupt_type_ack,
			"hw_interrupt_type", "ack");
		MEMBER_OFFSET_INIT(hw_interrupt_type_end,
			"hw_interrupt_type", "end");
		MEMBER_OFFSET_INIT(hw_interrupt_type_set_affinity,
			"hw_interrupt_type", "set_affinity");
	} else { /*
		  * On later kernels where hw_interrupt_type was replaced
		  * by irq_chip
		  */
		MEMBER_OFFSET_INIT(irq_chip_typename,
			"irq_chip", "name");
		MEMBER_OFFSET_INIT(irq_chip_startup,
			"irq_chip", "startup");
		MEMBER_OFFSET_INIT(irq_chip_shutdown,
			"irq_chip", "shutdown");
		MEMBER_OFFSET_INIT(irq_chip_enable,
			"irq_chip", "enable");
		MEMBER_OFFSET_INIT(irq_chip_disable,
			"irq_chip", "disable");
		MEMBER_OFFSET_INIT(irq_chip_ack,
			"irq_chip", "ack");
		MEMBER_OFFSET_INIT(irq_chip_mask,
			"irq_chip", "mask");
		MEMBER_OFFSET_INIT(irq_chip_mask_ack,
			"irq_chip", "mask_ack");
		MEMBER_OFFSET_INIT(irq_chip_unmask,
			"irq_chip", "unmask");
		MEMBER_OFFSET_INIT(irq_chip_eoi,
			"irq_chip", "eoi");
		MEMBER_OFFSET_INIT(irq_chip_end,
			"irq_chip", "end");
		MEMBER_OFFSET_INIT(irq_chip_set_affinity,
			"irq_chip", "set_affinity");
		MEMBER_OFFSET_INIT(irq_chip_retrigger,
			"irq_chip", "retrigger");
		MEMBER_OFFSET_INIT(irq_chip_set_type,
			"irq_chip", "set_type");
		MEMBER_OFFSET_INIT(irq_chip_set_wake,
			"irq_chip", "set_wake");
	}
	MEMBER_OFFSET_INIT(irqaction_handler, "irqaction", "handler");
	MEMBER_OFFSET_INIT(irqaction_flags, "irqaction", "flags");
	MEMBER_OFFSET_INIT(irqaction_mask, "irqaction", "mask");
	MEMBER_OFFSET_INIT(irqaction_name, "irqaction", "name");
	MEMBER_OFFSET_INIT(irqaction_dev_id, "irqaction", "dev_id");
	MEMBER_OFFSET_INIT(irqaction_next, "irqaction", "next");

	/* 6.5 and later: CONFIG_SPARSE_IRQ */
	if (kernel_symbol_exists("sparse_irqs"))
		kt->flags2 |= IRQ_DESC_TREE_MAPLE;
	else if (kernel_symbol_exists("irq_desc_tree")) {
		get_symbol_type("irq_desc_tree", NULL, &req);
		if (STREQ(req.type_tag_name, "xarray")) {
			kt->flags2 |= IRQ_DESC_TREE_XARRAY;
		} else {
			if (MEMBER_EXISTS("radix_tree_root", "xa_head"))
				kt->flags2 |= IRQ_DESC_TREE_XARRAY;
			else
				kt->flags2 |= IRQ_DESC_TREE_RADIX;
		}
	}
	STRUCT_SIZE_INIT(irq_data, "irq_data");
	if (VALID_STRUCT(irq_data)) {
		MEMBER_OFFSET_INIT(irq_data_irq, "irq_data", "irq");
		MEMBER_OFFSET_INIT(irq_data_chip, "irq_data", "chip");
		MEMBER_OFFSET_INIT(irq_data_affinity, "irq_data", "affinity");
		MEMBER_OFFSET_INIT(irq_desc_irq_data, "irq_desc", "irq_data");
	}

	STRUCT_SIZE_INIT(irq_common_data, "irq_common_data");
	if (VALID_STRUCT(irq_common_data)) {
		MEMBER_OFFSET_INIT(irq_common_data_affinity, "irq_common_data", "affinity");
		MEMBER_OFFSET_INIT(irq_desc_irq_common_data, "irq_desc", "irq_common_data");
	}

        STRUCT_SIZE_INIT(irq_cpustat_t, "irq_cpustat_t");
        MEMBER_OFFSET_INIT(irq_cpustat_t___softirq_active, 
                "irq_cpustat_t", "__softirq_active");
        MEMBER_OFFSET_INIT(irq_cpustat_t___softirq_mask, 
                "irq_cpustat_t", "__softirq_mask");

        STRUCT_SIZE_INIT(timer_list, "timer_list");
        MEMBER_OFFSET_INIT(timer_list_list, "timer_list", "list");
        MEMBER_OFFSET_INIT(timer_list_next, "timer_list", "next");
        MEMBER_OFFSET_INIT(timer_list_entry, "timer_list", "entry");
        MEMBER_OFFSET_INIT(timer_list_expires, "timer_list", "expires");
        MEMBER_OFFSET_INIT(timer_list_function, "timer_list", "function");
        STRUCT_SIZE_INIT(timer_vec_root, "timer_vec_root");
	if (VALID_STRUCT(timer_vec_root))
               	MEMBER_OFFSET_INIT(timer_vec_root_vec, 
			"timer_vec_root", "vec");
        STRUCT_SIZE_INIT(timer_vec, "timer_vec");
	if (VALID_STRUCT(timer_vec))
               	MEMBER_OFFSET_INIT(timer_vec_vec, "timer_vec", "vec");

	STRUCT_SIZE_INIT(tvec_root_s, "tvec_root_s");
        if (VALID_STRUCT(tvec_root_s)) {
               	STRUCT_SIZE_INIT(tvec_t_base_s, "tvec_t_base_s");
                MEMBER_OFFSET_INIT(tvec_t_base_s_tv1,
                        "tvec_t_base_s", "tv1");
	        MEMBER_OFFSET_INIT(tvec_root_s_vec, 
			"tvec_root_s", "vec");
	        STRUCT_SIZE_INIT(tvec_s, "tvec_s");
	        MEMBER_OFFSET_INIT(tvec_s_vec, "tvec_s", "vec");
	} else {
		STRUCT_SIZE_INIT(tvec_root_s, "tvec_root");
        	if (VALID_STRUCT(tvec_root_s)) {
               		STRUCT_SIZE_INIT(tvec_t_base_s, "tvec_base");
                	MEMBER_OFFSET_INIT(tvec_t_base_s_tv1,
                        	"tvec_base", "tv1");
	        	MEMBER_OFFSET_INIT(tvec_root_s_vec, 
				"tvec_root", "vec");
	        	STRUCT_SIZE_INIT(tvec_s, "tvec");
	        	MEMBER_OFFSET_INIT(tvec_s_vec, "tvec", "vec");
		}
	}

	if (per_cpu_symbol_search("timer_bases")) {
		kt->flags2 |= TIMER_BASES;
		MEMBER_OFFSET_INIT(timer_base_vectors, "timer_base", "vectors");
		STRUCT_SIZE_INIT(timer_base, "timer_base");
	} else if (per_cpu_symbol_search("per_cpu__tvec_bases")) {
		if (MEMBER_EXISTS("tvec_base", "migration_enabled"))
			kt->flags2 |= TVEC_BASES_V3;
		else
			kt->flags |= TVEC_BASES_V2;
	} else if (symbol_exists("tvec_bases"))
		kt->flags |= TVEC_BASES_V1;

        STRUCT_SIZE_INIT(__wait_queue, "__wait_queue");
	STRUCT_SIZE_INIT(wait_queue_entry, "wait_queue_entry");
	if (VALID_STRUCT(wait_queue_entry)) {
		MEMBER_OFFSET_INIT(wait_queue_entry_private,
			"wait_queue_entry", "private");
		MEMBER_OFFSET_INIT(wait_queue_head_head,
			"wait_queue_head", "head");
		MEMBER_OFFSET_INIT(wait_queue_entry_entry,
			"wait_queue_entry", "entry");
	} else if (VALID_STRUCT(__wait_queue)) {
		if (MEMBER_EXISTS("__wait_queue", "task"))
			MEMBER_OFFSET_INIT(__wait_queue_task,
				"__wait_queue", "task");
		else
			MEMBER_OFFSET_INIT(__wait_queue_task,
				"__wait_queue", "private");
                MEMBER_OFFSET_INIT(__wait_queue_head_task_list,
                        "__wait_queue_head", "task_list");
                MEMBER_OFFSET_INIT(__wait_queue_task_list,
                        "__wait_queue", "task_list");
        } else {
               	STRUCT_SIZE_INIT(wait_queue, "wait_queue");
		if (VALID_STRUCT(wait_queue)) {
               		MEMBER_OFFSET_INIT(wait_queue_task, 
				"wait_queue", "task");
               		MEMBER_OFFSET_INIT(wait_queue_next, 
				"wait_queue", "next");
		}
	}

	STRUCT_SIZE_INIT(pt_regs, "pt_regs");
	STRUCT_SIZE_INIT(softirq_state, "softirq_state");
	STRUCT_SIZE_INIT(softirq_action, "softirq_action");
	STRUCT_SIZE_INIT(desc_struct, "desc_struct");

	STRUCT_SIZE_INIT(char_device_struct, "char_device_struct");
	if (VALID_STRUCT(char_device_struct)) {
		MEMBER_OFFSET_INIT(char_device_struct_next,
			"char_device_struct", "next");
		MEMBER_OFFSET_INIT(char_device_struct_name,
			"char_device_struct", "name");
		MEMBER_OFFSET_INIT(char_device_struct_fops,
			"char_device_struct", "fops");
		MEMBER_OFFSET_INIT(char_device_struct_major,
			"char_device_struct", "major");
		MEMBER_OFFSET_INIT(char_device_struct_baseminor,
			"char_device_struct", "baseminor");
		MEMBER_OFFSET_INIT(char_device_struct_cdev,
			"char_device_struct", "cdev");
	}

	STRUCT_SIZE_INIT(cdev, "cdev");
	if (VALID_STRUCT(cdev)) 
		MEMBER_OFFSET_INIT(cdev_ops, "cdev", "ops");

	STRUCT_SIZE_INIT(probe, "probe");
	if (VALID_STRUCT(probe)) {
		MEMBER_OFFSET_INIT(probe_next, "probe", "next");
		MEMBER_OFFSET_INIT(probe_dev, "probe", "dev");
		MEMBER_OFFSET_INIT(probe_data, "probe", "data");
	}

	STRUCT_SIZE_INIT(kobj_map, "kobj_map");
	if (VALID_STRUCT(kobj_map)) 
		MEMBER_OFFSET_INIT(kobj_map_probes, "kobj_map", "probes");

	MEMBER_OFFSET_INIT(module_kallsyms_start, "module", 
		"kallsyms_start");

	STRUCT_SIZE_INIT(kallsyms_header, "kallsyms_header");

	if (VALID_MEMBER(module_kallsyms_start) &&
	    VALID_SIZE(kallsyms_header)) {
        	MEMBER_OFFSET_INIT(kallsyms_header_sections,
			"kallsyms_header", "sections");
        	MEMBER_OFFSET_INIT(kallsyms_header_section_off,
			"kallsyms_header", "section_off");
        	MEMBER_OFFSET_INIT(kallsyms_header_symbols,
			"kallsyms_header", "symbols");
        	MEMBER_OFFSET_INIT(kallsyms_header_symbol_off,
			"kallsyms_header", "symbol_off");
        	MEMBER_OFFSET_INIT(kallsyms_header_string_off,
			"kallsyms_header", "string_off");
        	MEMBER_OFFSET_INIT(kallsyms_symbol_section_off,
			"kallsyms_symbol", "section_off");
        	MEMBER_OFFSET_INIT(kallsyms_symbol_symbol_addr,
			"kallsyms_symbol", "symbol_addr");
        	MEMBER_OFFSET_INIT(kallsyms_symbol_name_off,
			"kallsyms_symbol", "name_off");
        	MEMBER_OFFSET_INIT(kallsyms_section_start,
			"kallsyms_section", "start");
        	MEMBER_OFFSET_INIT(kallsyms_section_size,
			"kallsyms_section", "size");
        	MEMBER_OFFSET_INIT(kallsyms_section_name_off,
			"kallsyms_section", "name_off");
		STRUCT_SIZE_INIT(kallsyms_symbol, "kallsyms_symbol");
		STRUCT_SIZE_INIT(kallsyms_section, "kallsyms_section");
			
		if (!(kt->flags & NO_KALLSYMS))
			kt->flags |= KALLSYMS_V1;
	}

	MEMBER_OFFSET_INIT(module_num_symtab, "module", "num_symtab");

	if (VALID_MEMBER(module_num_symtab)) {
		MEMBER_OFFSET_INIT(module_symtab, "module", "symtab");
		MEMBER_OFFSET_INIT(module_strtab, "module", "strtab");
			
		if (!(kt->flags & NO_KALLSYMS))
			kt->flags |= KALLSYMS_V2;
	}

	if (INVALID_MEMBER(module_num_symtab) && 
	    MEMBER_EXISTS("module", "core_kallsyms")) {
		ASSIGN_OFFSET(module_num_symtab) =
			MEMBER_OFFSET("module", "core_kallsyms") +
			MEMBER_OFFSET("mod_kallsyms", "num_symtab");
		ASSIGN_OFFSET(module_symtab) =
			MEMBER_OFFSET("module", "core_kallsyms") +
			MEMBER_OFFSET("mod_kallsyms", "symtab");
		ASSIGN_OFFSET(module_strtab) =
			MEMBER_OFFSET("module", "core_kallsyms") +
			MEMBER_OFFSET("mod_kallsyms", "strtab");

		if (!(kt->flags & NO_KALLSYMS))
			kt->flags |= KALLSYMS_V2;
	}

	if (!(kt->flags & DWARF_UNWIND))
		kt->flags |= NO_DWARF_UNWIND; 

	/* 
	 *  OpenVZ 
	 */
	if (kernel_symbol_exists("pcpu_info") && 
	    STRUCT_EXISTS("pcpu_info") && STRUCT_EXISTS("vcpu_struct")) {
		MEMBER_OFFSET_INIT(pcpu_info_vcpu, "pcpu_info", "vcpu");
		MEMBER_OFFSET_INIT(pcpu_info_idle, "pcpu_info", "idle");
		MEMBER_OFFSET_INIT(vcpu_struct_rq, "vcpu_struct", "rq");
		STRUCT_SIZE_INIT(pcpu_info, "pcpu_info");
		STRUCT_SIZE_INIT(vcpu_struct, "vcpu_struct");
		kt->flags |= ARCH_OPENVZ;
	}

	STRUCT_SIZE_INIT(mem_section, "mem_section");

	BUG_bytes_init();

	/*
	 *  for hrtimer
	 */
	STRUCT_SIZE_INIT(hrtimer_clock_base, "hrtimer_clock_base");
	if (VALID_STRUCT(hrtimer_clock_base)) {
		MEMBER_OFFSET_INIT(hrtimer_clock_base_offset, 
			"hrtimer_clock_base", "offset");
		MEMBER_OFFSET_INIT(hrtimer_clock_base_active, 
			"hrtimer_clock_base", "active");
		MEMBER_OFFSET_INIT(hrtimer_clock_base_first, 
			"hrtimer_clock_base", "first");
		MEMBER_OFFSET_INIT(hrtimer_clock_base_get_time, 
			"hrtimer_clock_base", "get_time");
	}

	STRUCT_SIZE_INIT(hrtimer_base, "hrtimer_base");
	if (VALID_STRUCT(hrtimer_base)) {
		MEMBER_OFFSET_INIT(hrtimer_base_first, 
			"hrtimer_base", "first");
		MEMBER_OFFSET_INIT(hrtimer_base_pending, 
			"hrtimer_base", "pending");
		MEMBER_OFFSET_INIT(hrtimer_base_get_time, 
			"hrtimer_base", "get_time");
	}

	MEMBER_OFFSET_INIT(hrtimer_cpu_base_clock_base, "hrtimer_cpu_base",
		"clock_base");

	MEMBER_OFFSET_INIT(hrtimer_node, "hrtimer", "node");
	MEMBER_OFFSET_INIT(hrtimer_list, "hrtimer", "list");
	MEMBER_OFFSET_INIT(hrtimer_expires, "hrtimer", "expires");
	if (INVALID_MEMBER(hrtimer_expires))
		MEMBER_OFFSET_INIT(hrtimer_expires, "hrtimer", "_expires");
	if (INVALID_MEMBER(hrtimer_expires)) {
		MEMBER_OFFSET_INIT(timerqueue_head_next, 
			"timerqueue_head", "next");
		MEMBER_OFFSET_INIT(timerqueue_node_expires, 
			"timerqueue_node", "expires");
		MEMBER_OFFSET_INIT(timerqueue_node_node, 
			"timerqueue_node", "node");
		if (INVALID_MEMBER(timerqueue_head_next)) {
			MEMBER_OFFSET_INIT(timerqueue_head_rb_root,
				"timerqueue_head", "rb_root");
			MEMBER_OFFSET_INIT(rb_root_cached_rb_leftmost,
				"rb_root_cached", "rb_leftmost");
		}
	}
	MEMBER_OFFSET_INIT(hrtimer_softexpires, "hrtimer", "_softexpires");
	MEMBER_OFFSET_INIT(hrtimer_function, "hrtimer", "function");

	MEMBER_OFFSET_INIT(ktime_t_tv64, "ktime", "tv64");
	if (INVALID_MEMBER(ktime_t_tv64))
		MEMBER_OFFSET_INIT(ktime_t_tv64, "ktime_t", "tv64");
	MEMBER_OFFSET_INIT(ktime_t_sec, "ktime", "sec");
	if (INVALID_MEMBER(ktime_t_sec))
		MEMBER_OFFSET_INIT(ktime_t_sec, "ktime_t", "sec");
	MEMBER_OFFSET_INIT(ktime_t_nsec, "ktime", "nsec");
	if (INVALID_MEMBER(ktime_t_nsec))
		MEMBER_OFFSET_INIT(ktime_t_nsec, "ktime_t", "nsec");

	if (kt->source_tree)
		source_tree_init();

	kt->flags &= ~PRE_KERNEL_INIT;
}

/*
 * Get cpu map address.  Types are: possible, online, present and active.
 * They exist as either:
 *
 *  (1) cpu_<type>_map symbols, or 
 *  (2) what is pointed to by cpu_<type>_mask
 */
ulong
cpu_map_addr(const char *type)
{
	char map_symbol[32];
	ulong addr;

	sprintf(map_symbol, "cpu_%s_map", type);
	if (kernel_symbol_exists(map_symbol))
		return symbol_value(map_symbol);

        sprintf(map_symbol, "cpu_%s_mask", type);
        if (kernel_symbol_exists(map_symbol)) {
        	get_symbol_data(map_symbol, sizeof(ulong), &addr);
        	return addr;
	}

	sprintf(map_symbol, "__cpu_%s_mask", type);
        if (kernel_symbol_exists(map_symbol))
		return symbol_value(map_symbol);

	return 0;
}

static char *
cpu_map_type(char *name)
{
	char map_symbol[32];

	sprintf(map_symbol, "cpu_%s_map", name);
	if (kernel_symbol_exists(map_symbol))
		return "map";

        sprintf(map_symbol, "cpu_%s_mask", name);
        if (kernel_symbol_exists(map_symbol))
		return "mask";

	sprintf(map_symbol, "__cpu_%s_map", name);
	if (kernel_symbol_exists(map_symbol))
		return "map";

        sprintf(map_symbol, "__cpu_%s_mask", name);
        if (kernel_symbol_exists(map_symbol))
		return "mask";

	return NULL;
}

/*
 * Get cpu map (possible, online, etc.) size
 */
static int
cpu_map_size(const char *type)
{
	int len;
	char map_symbol[32];
	struct gnu_request req;

        if (LKCD_KERNTYPES()) {
                if ((len = STRUCT_SIZE("cpumask_t")) < 0)
                        error(FATAL, "cannot determine type cpumask_t\n");
		return len;
	}

	sprintf(map_symbol, "cpu_%s_map", type);
	if (kernel_symbol_exists(map_symbol)) {
		len = get_symbol_type(map_symbol, NULL, &req) ==
                        TYPE_CODE_UNDEF ? sizeof(ulong) : req.length;
		return len;
	}

	len = STRUCT_SIZE("cpumask_t");
	if (len < 0)
		return sizeof(ulong);
	else
		return len;
}

/*
 *  If the cpu_present_map, cpu_online_map and cpu_possible_maps exist,
 *  set up the kt->cpu_flags[NR_CPUS] with their settings.
 */ 
static void
cpu_maps_init(void)
{
        int i, c, m, cpu, len;
        char *buf;
        ulong *maskptr, addr, error_handle;
	struct mapinfo {
		ulong cpu_flag;
		char *name;
	} mapinfo[] = {
		{ POSSIBLE_MAP, "possible" },
		{ PRESENT_MAP, "present" },
		{ ONLINE_MAP, "online" },
		{ ACTIVE_MAP, "active" },
	};

	if ((len = STRUCT_SIZE("cpumask_t")) < 0)
		len = sizeof(ulong);

	buf = GETBUF(len);

	for (m = 0; m < sizeof(mapinfo)/sizeof(struct mapinfo); m++) {
		if (!(addr = cpu_map_addr(mapinfo[m].name)))
			continue;

		error_handle = pc->flags & DEVMEM ? RETURN_ON_ERROR|QUIET : RETURN_ON_ERROR;
		if (!readmem(addr, KVADDR, buf, len,
		    mapinfo[m].name, error_handle)) {
			error(WARNING, "cannot read cpu_%s_map\n",
			      mapinfo[m].name);
			continue;
		}

		maskptr = (ulong *)buf;
		for (i = 0; i < (len/sizeof(ulong)); i++, maskptr++) {
			if (*maskptr == 0)
				continue;
			for (c = 0; c < BITS_PER_LONG; c++)
				if (*maskptr & (0x1UL << c)) {
					cpu = (i * BITS_PER_LONG) + c;
					if (cpu >= NR_CPUS) {
						error(WARNING, 
						    "cpu_%s_%s indicates more than"
						    " %d (NR_CPUS) cpus\n",
							mapinfo[m].name, 
							cpu_map_type(mapinfo[m].name), 
							NR_CPUS);
						break;
					}
					kt->cpu_flags[cpu] |= mapinfo[m].cpu_flag;
				}
		}

		if (CRASHDEBUG(1)) {
			fprintf(fp, "%scpu_%s_%s: cpus: ", 
				space(strlen("possible")-strlen(mapinfo[m].name)),
				mapinfo[m].name, cpu_map_type(mapinfo[m].name));
			for (i = c = 0; i < NR_CPUS; i++) {
				if (kt->cpu_flags[i] & mapinfo[m].cpu_flag) {
					fprintf(fp, "%d ", i);
					c++;
				}
			}
			fprintf(fp, "%s\n", c ? "" : "(none)");
		}

	}

	FREEBUF(buf);
}

/*
 *  Determine whether a cpu is in one of the cpu masks.
 */
int
in_cpu_map(int map, int cpu)
{
	if (cpu >= (kt->kernel_NR_CPUS ? kt->kernel_NR_CPUS : NR_CPUS)) {
		error(INFO, "in_cpu_map: invalid cpu: %d\n", cpu);
		return FALSE;
	}

	switch (map)
	{
	case POSSIBLE_MAP:
		if (!cpu_map_addr("possible")) {
			error(INFO, "cpu_possible_map does not exist\n");
			return FALSE;
		}
		return (kt->cpu_flags[cpu] & POSSIBLE_MAP);

	case PRESENT_MAP:
		if (!cpu_map_addr("present")) {
			error(INFO, "cpu_present_map does not exist\n");
			return FALSE;
		}
		return (kt->cpu_flags[cpu] & PRESENT_MAP);

	case ONLINE_MAP:
		if (!cpu_map_addr("online")) {
			error(INFO, "cpu_online_map does not exist\n");
			return FALSE;
		}
		return (kt->cpu_flags[cpu] & ONLINE_MAP);

	case ACTIVE_MAP:
		if (!cpu_map_addr("active")) {
			error(INFO, "cpu_active_map does not exist\n");
			return FALSE;
		}
		return (kt->cpu_flags[cpu] & ACTIVE_MAP);
	}

	return FALSE;
}


/*
 *  For lack of a better manner of verifying that the namelist and dumpfile
 *  (or live kernel) match up, verify that the Linux banner is where
 *  the namelist says it is.  Since this is common place to bail, extra
 *  debug statements are available.
 */
void
verify_version(void)
{
	char buf[BUFSIZE];
	ulong linux_banner;
        int argc, len;
        char *arglist[MAXARGS];
	char *p1, *p2;
	struct syment *sp;

	if (pc->flags & KERNEL_DEBUG_QUERY)
		return;

	BZERO(buf, BUFSIZE);

	if (!(sp = symbol_search("linux_banner")))
		error(FATAL, "linux_banner symbol does not exist?\n");
	else {
		switch (get_symbol_type("linux_banner", NULL, NULL))
		{
		case TYPE_CODE_ARRAY:
			linux_banner = sp->value;
			break;
		case TYPE_CODE_PTR:
			get_symbol_data("linux_banner", sizeof(ulong), &linux_banner);
			break;
		default:
			error(WARNING, "linux_banner is unknown type\n");
			linux_banner = sp->value;
			break;
		}
	}

	if (!IS_KVADDR(linux_banner))
		error(WARNING, "invalid linux_banner pointer: %lx\n", 
			linux_banner);

	if (!accessible(linux_banner)) 
		goto bad_match;

	if (!read_string(linux_banner, buf, BUFSIZE-1))
		error(WARNING, "cannot read linux_banner string\n");

	if (ACTIVE()) {
		len = strlen(kt->proc_version);
		if ((len > 0) && (strncmp(buf, kt->proc_version, len) != 0)) {
               		if (CRASHDEBUG(1)) {
                        	fprintf(fp, "/proc/version:\n%s\n", 
					kt->proc_version);
                        	fprintf(fp, "linux_banner:\n%s\n", buf);
                	}
			goto bad_match;
		} else if (CRASHDEBUG(1)) 
                       	fprintf(fp, "linux_banner:\n%s\n", buf);
	}

	if (DUMPFILE()) {
		if (!STRNEQ(buf, "Linux version")) {
                	if (CRASHDEBUG(1)) 
                        	fprintf(fp, "linux_banner:\n%s\n", buf);
			goto bad_match;
		}
		strcpy(kt->proc_version, strip_linefeeds(buf));
	}

	verify_namelist();

	if (strstr(kt->proc_version, "gcc version 3.3.3"))
		kt->flags |= GCC_3_3_3;
	if (strstr(kt->proc_version, "gcc version 3.3.2"))
		kt->flags |= GCC_3_3_2;
	else if (strstr(kt->proc_version, "gcc version 3.2.3"))
		kt->flags |= GCC_3_2_3;
	else if (strstr(kt->proc_version, "gcc version 3.2"))
		kt->flags |= GCC_3_2;
	else if (strstr(kt->proc_version, "gcc version 2.96"))
		kt->flags |= GCC_2_96;

	/*
	 *  Keeping the gcc version with #define's is getting out of hand.
	 */
	if ((p1 = strstr(kt->proc_version, "gcc version "))) {
		BZERO(buf, BUFSIZE);
		p1 += strlen("gcc version ");
		p2 = buf;
		while (((*p1 >= '0') && (*p1 <= '9')) || (*p1 == '.')) {
			if (*p1 == '.')
				*p2++ = ' ';
			else
				*p2++ = *p1;
			p1++;
		}
		argc = parse_line(buf, arglist);

		switch (argc)
		{
		case 0:
		case 1:
			break;
		case 2:
			kt->gcc_version[0] = atoi(arglist[0]);
			kt->gcc_version[1] = atoi(arglist[1]);
			break;
		default:
			kt->gcc_version[0] = atoi(arglist[0]);
			kt->gcc_version[1] = atoi(arglist[1]);		
			kt->gcc_version[2] = atoi(arglist[2]);
			break;
		}
	}

	if (CRASHDEBUG(1))
		gdb_readnow_warning();

	return;

bad_match:
	if (REMOTE())
		sprintf(buf, "%s:%s", pc->server, pc->server_memsrc);
	else
		sprintf(buf, "%s", ACTIVE() ? pc->live_memsrc : pc->dumpfile);

	error(INFO, "%s and %s do not match!\n",
		pc->system_map ? pc->system_map : 
		pc->namelist_debug ? pc->namelist_debug : pc->namelist, buf); 

	program_usage(SHORT_FORM);
}

/*
 *  Quick test to verify that we're not using a UP debug kernel on
 *  an SMP system.
 */
void
verify_spinlock(void)
{
	char buf[BUFSIZE];

	if ((kt->flags & SMP) && (SIZE(spinlock_t) == 0)) {
        	error(INFO,
           "debug data shows spinlock_t as an incomplete type (undefined),\n");
                fprintf(fp, "%sbut \"%s\" is an SMP kernel.\n",
                	space(strlen(pc->program_name)+2),
                        pc->namelist);
                if (CRASHDEBUG(1)) {
                        fprintf(fp, "\ngdb> ptype spinlock_t\n");
                        sprintf(buf, "ptype spinlock_t");
                        gdb_pass_through(buf, NULL, GNU_RETURN_ON_ERROR);
                }
                non_matching_kernel();
	}
}

/*
 *  Something doesn't jive.
 */
void
non_matching_kernel(void)
{
	int kernels = 0;

	if (pc->namelist)
		kernels++;
	if (pc->namelist_debug)
		kernels++;
	if (pc->debuginfo_file)
		kernels++;

	fprintf(fp, 
"\nErrors like the one above typically occur when the kernel%s and memory source\ndo not match.  These are the files being used:\n\n", kernels > 1 ? "s" : "");

        if (REMOTE()) {
                switch (pc->flags &
                        (NAMELIST_LOCAL|NAMELIST_UNLINKED|NAMELIST_SAVED))
                {
                case NAMELIST_UNLINKED:
                        fprintf(fp, "      KERNEL: %s  (temporary)\n",
                                pc->namelist);
                        break;

                case (NAMELIST_UNLINKED|NAMELIST_SAVED):
                        fprintf(fp, "      KERNEL: %s\n", pc->namelist);
                        break;

                case NAMELIST_LOCAL:
                        fprintf(fp, "      KERNEL: %s\n", pc->namelist);
                        break;
                }
        } else {
        	if (pc->system_map) {
                	fprintf(fp, "  SYSTEM MAP: %s\n", pc->system_map);
                	fprintf(fp, "DEBUG KERNEL: %s %s\n", pc->namelist,
                		debug_kernel_version(pc->namelist));
				
		} else
			fprintf(fp, "      KERNEL: %s\n", pc->namelist);
		if (pc->namelist_orig)
			fprintf(fp, "              (uncompressed from %s)\n",
				pc->namelist_orig);
	}

	if (pc->debuginfo_file) {
		fprintf(fp, "   DEBUGINFO: %s\n", pc->debuginfo_file);
		if (STREQ(pc->debuginfo_file, pc->namelist_debug) &&
		    pc->namelist_debug_orig)
			fprintf(fp, "              (uncompressed from %s)\n", 
				pc->namelist_debug_orig);
	} else if (pc->namelist_debug) {
		fprintf(fp, "DEBUG KERNEL: %s %s\n", pc->namelist_debug,
			debug_kernel_version(pc->namelist_debug));
		if (pc->namelist_debug_orig)
			fprintf(fp, "              (uncompressed from %s)\n", 
				pc->namelist_debug_orig);
	}

	if (dumpfile_is_split() || sadump_is_diskset() || is_ramdump_image())
        	fprintf(fp, "   DUMPFILES: ");
	else
        	fprintf(fp, "    DUMPFILE: ");
        if (ACTIVE()) {
                if (REMOTE_ACTIVE())
                        fprintf(fp, "%s@%s  (remote live system)\n",
                                pc->server_memsrc, pc->server);
                else 
                        fprintf(fp, "%s\n", pc->live_memsrc);
        } else {
                if (REMOTE_DUMPFILE())
                        fprintf(fp, "%s@%s  (remote dumpfile)\n",
                                pc->server_memsrc, pc->server);
		else if (REMOTE_PAUSED())
			fprintf(fp, "%s %s  (remote paused system)\n",
				pc->server_memsrc, pc->server);
                else {
                        if (dumpfile_is_split())
                                show_split_dumpfiles();
			else if (sadump_is_diskset())
				sadump_show_diskset();
			else if (is_ramdump_image())
                                show_ramdump_files();
                        else
                                fprintf(fp, "%s", pc->dumpfile);
                }
		if (LIVE())
			fprintf(fp, " [LIVE DUMP]");
        }

	fprintf(fp, "\n\n");

	if ((pc->flags & FINDKERNEL) && !(pc->system_map)) {
		fprintf(fp, 
		   "The kernel \"%s\" is most likely incorrect.\n",
			pc->namelist);
		fprintf(fp, 
         "Try a different kernel name, or use a System.map file argument.\n\n");
	}

	clean_exit(1);
}

/*
 *  Only two checks are made here: 
 *
 *    1. if the namelist is SMP and the memory source isn't, bail out.
 *    2. if the basic gcc versions differ, issue a warning only.
 */
static void
verify_namelist()
{
	int i;
	char command[BUFSIZE];
	char buffer[BUFSIZE/2];
	char buffer2[BUFSIZE/2];
	char buffer3[BUFSIZE/2];
	char buffer4[BUFSIZE/2];
	char buffer5[BUFSIZE*2];
	char *p1;
	FILE *pipe;
	int found;
	char *namelist;
	int namelist_smp;
	int target_smp;

	if (pc->flags & KERNEL_DEBUG_QUERY)
		return;

	/* the kerntypes may not match in terms of gcc version or SMP */
	if (LKCD_KERNTYPES())
		return;

	if (!strlen(kt->utsname.version))
		return;

	namelist = pc->namelist ? pc->namelist : pc->namelist_debug;
	target_smp = strstr(kt->utsname.version, " SMP ") ? TRUE : FALSE;
	namelist_smp = FALSE;

	if (get_linux_banner_from_vmlinux(buffer, sizeof(buffer)) &&
	    strstr(buffer, kt->proc_version)) {
		found = TRUE;
		goto found;
	}

        sprintf(command, "/usr/bin/strings %s", namelist);
        if ((pipe = popen(command, "r")) == NULL) {
                error(INFO, "%s: %s\n", namelist, strerror(errno));
                return;
        }

	found = FALSE;
	sprintf(buffer3, "(unknown)");
        while (fgets(buffer, (BUFSIZE/2)-1, pipe)) {
		if (!strstr(buffer, "Linux version 2.") &&
		    !strstr(buffer, "Linux version 3.") &&
		    !strstr(buffer, "Linux version 4.") &&
		    !strstr(buffer, "Linux version 5.") &&
		    !strstr(buffer, "Linux version 6."))
			continue;

                if (strstr(buffer, kt->proc_version)) {
                	found = TRUE;
			break;
		}

		if (strstr(buffer, " SMP ")) {
			namelist_smp = TRUE;
			strcpy(buffer2, buffer);
		}

		if ((p1 = strstr(buffer, "(gcc version "))) {
			p1 += strlen("(gcc version ");
			i = 0;
			while (*p1 != ' ') 
				buffer3[i++] = *p1++;
			buffer3[i] = NULLCHAR;
		}
        }
        pclose(pipe);

	if (!found && (p1 = strstr(kt->proc_version, "(gcc version "))) {
		p1 += strlen("(gcc version ");
		i = 0;
		while (*p1 != ' ') 
			buffer4[i++] = *p1++;
		buffer4[i] = NULLCHAR;
		if (!STREQ(buffer3, buffer4)) {
        		if (REMOTE())
                		sprintf(buffer, "%s:%s kernel", 
					pc->server, pc->server_memsrc);
        		else
                		sprintf(buffer, "%s kernel", ACTIVE() ? 
					"live system" : pc->dumpfile);
        		sprintf(buffer5, "  %s: %s\n  %s: %s\n\n",
                		namelist, buffer3,
                		buffer, buffer4);
        		error(WARNING, 
		           "kernels compiled by different gcc versions:\n%s",
				buffer5);
		}
	}

found:
	if (found) {
                if (CRASHDEBUG(1)) {
                	fprintf(fp, "verify_namelist:\n");
			fprintf(fp, "%s /proc/version:\n%s\n", 
				ACTIVE() ? "live memory" : "dumpfile",
				kt->proc_version);
			fprintf(fp, "%s:\n%s\n", namelist, buffer);
		}
		return;
	}

	if (!(pc->flags & SYSMAP_ARG)) 
		error(WARNING, 
		    "kernel version inconsistency between vmlinux and %s\n\n",
			ACTIVE() ? "live memory" : "dumpfile");
		 
        if (CRASHDEBUG(1)) {
		error(WARNING, 
		    "\ncannot find matching kernel version in %s file:\n\n",
			namelist);
			
               	fprintf(fp, "verify_namelist:\n");
                fprintf(fp, "%s /proc/version:\n%s\n", 
			ACTIVE() ? "live memory" : "dumpfile",
			kt->proc_version);
                fprintf(fp, "%s:\n%s\n", namelist, buffer2);
        }

	if (target_smp == namelist_smp)
		return;

        if (REMOTE())
                sprintf(buffer, "%s:%s", pc->server, pc->server_memsrc);
        else
                sprintf(buffer, "%s", ACTIVE() ? "live system" : pc->dumpfile);

	sprintf(buffer5, " %s is %s -- %s is %s\n",
                namelist, namelist_smp ? "SMP" : "not SMP",
                buffer, target_smp ? "SMP" : "not SMP");

	error(INFO, "incompatible arguments: %s%s",
		strlen(buffer5) > 48 ? "\n  " : "", buffer5);

        program_usage(SHORT_FORM);
}

/*
 *  Set up the gdb source code path.
 */
static void
source_tree_init(void)
{
	FILE *pipe;
	char command[BUFSIZE*2];
	char buf[BUFSIZE];

	if (!is_directory(kt->source_tree)) {
		error(INFO, "invalid --src argument: %s\n\n", 
			kt->source_tree);
		kt->source_tree = NULL;
		return;
	}

	sprintf(command, "/usr/bin/ls -d %s/arch/*/include/asm 2>/dev/null", 
		kt->source_tree);
	if ((pipe = popen(command, "r"))) {
		if (fgets(buf, BUFSIZE-1, pipe)) {
			sprintf(command, "directory %s", buf);
			gdb_pass_through(command, NULL, GNU_RETURN_ON_ERROR);
		} 
		pclose(pipe);
	} else
		error(INFO, "%s: %s\n", command, strerror(errno));

	sprintf(command, "directory %s", kt->source_tree);
	gdb_pass_through(command, NULL, GNU_RETURN_ON_ERROR);

}


static void
list_source_code(struct gnu_request *req, int count_entered)
{
	int argc, line, last, done, assembly;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE*2];
	char file[BUFSIZE];
        char *argv[MAXARGS];
	struct syment *sp;
	ulong remaining, offset;
	struct load_module *lm;
	char *p1;

	sp = value_search(req->addr, &offset);
	if (!sp || !is_symbol_text(sp))
		error(FATAL, "%lx: not a kernel text address\n", req->addr);

	if (module_symbol(req->addr, NULL, &lm, NULL, 0)) {
		if (!(lm->mod_flags & MOD_LOAD_SYMS))
			error(FATAL, "%s: module source code is not available\n", lm->mod_name);
		get_line_number(req->addr, buf1, FALSE);
	}

	sprintf(buf1, "list *0x%lx", req->addr);
	open_tmpfile();
	if (!gdb_pass_through(buf1, pc->tmpfile, GNU_RETURN_ON_ERROR)) {
		close_tmpfile();
		error(FATAL, "gdb command failed: %s\n", buf1);
	}

	done = FALSE;
	last = line = assembly = file[0] = 0;
	remaining = count_entered ? req->count : 0;

	rewind(pc->tmpfile);
	while (fgets(buf1, BUFSIZE, pc->tmpfile)) {
		strcpy(buf2, buf1);
		argc = parse_line(buf2, argv);
		if (!line && hexadecimal(argv[0], 0) && 
		    STREQ(argv[1], "is") && 
		    (STREQ(argv[2], "in") || STREQ(argv[2], "at"))) {
			/*
			 *  Don't bother continuing beyond the initial
			 *  list command if it's assembly language.
			 */
			if (STREQ(argv[2], "at"))
				assembly = TRUE;

			strip_beginning_char(argv[argc-1], '(');
			strip_ending_char(argv[argc-1], '.');
			strip_ending_char(argv[argc-1], ')');
			p1 = strstr_rightmost(argv[argc-1], ":");
			*p1 = NULLCHAR;
			strcpy(file, argv[argc-1]);
			line = atoi(p1+1);

			fprintf(pc->saved_fp, "FILE: %s\nLINE: %d\n\n", file, line);

			continue;
		} 

		/*
		 *  Check for 2 possible results of unavailable source.
		 */
		if ((argc == 3) &&
		    decimal(argv[0], 0) &&
		    STREQ(argv[1], "in") &&
		    STREQ(argv[2], file))
			error(FATAL, 
			    "%s: source code is not available\n\n", req->buf);

		sprintf(buf3, "%s: No such file or directory.", file);
		if (decimal(argv[0], 0) && strstr(buf1, buf3))
			error(FATAL, 
			    "%s: source code is not available\n\n", req->buf);

		if (decimal(argv[0], 0)) {
			if (count_entered && (last >= line)) {
				if (!remaining--) {
					done = TRUE;
					break;
				}
			}
			last = atoi(argv[0]);
			fprintf(pc->saved_fp, "%s%s", 
				last == line ? "* " : "  ", buf1);
		} else
			continue;

		if (!count_entered && (last > line) && 
		    STREQ(first_space(buf1), "\t}\n")) {
			done = TRUE;
			break;
		}
	}
	close_tmpfile();

	if (!line) {
		fprintf(fp, "FILE: (unknown)\nLINE: (unknown)\n\n");
		error(FATAL, "%s: source code is not available\n\n", req->buf);
	}

	if ((count_entered && !remaining) || (!count_entered && assembly)) {
		fprintf(fp, "\n");
		return;
	}

	/*
	 *  If the end of the containing function or a specified count
	 *  has not been reached, continue the listing until it has.
	 */
	while (!done) {
		open_tmpfile();
		if (!gdb_pass_through("list", fp, GNU_RETURN_ON_ERROR)) {
			close_tmpfile();
			return;
		}
		rewind(pc->tmpfile);
		while (fgets(buf1, BUFSIZE, pc->tmpfile)) {
			strcpy(buf2, buf1);
			argc = parse_line(buf2, argv);

			if (decimal(argv[0], 0))
				line = atoi(argv[0]);
			else
				continue;

			if (count_entered) {
				if (!remaining--) {
					done = TRUE;
					break;
				}
			}

			if (line == last) {
				done = TRUE;
				break;
			}
			last = line;

			fprintf(pc->saved_fp, "  %s", buf1);

			if (!count_entered && 
			    STREQ(first_space(buf1), "\t}\n")) {
				done = TRUE;
				break;
			}
		}
		close_tmpfile();
	}

	fprintf(fp, "\n");
}

/*
 *  From either a syment pointer, or a virtual address evaluated
 *  from a symbol name plus an offset value, determine whether 
 *  there are multiple symbols with the same name, or if it is
 *  determined to be an invalid expression of a text address.
 *
 *  If there are multiple text symbols with the same name, then 
 *  display a "duplicate text symbols found" message followed by
 *  a list of each symbol's information, and return FALSE.
 *
 *  If a symbol name plus and offset value evaluates to an address 
 *  that goes beyond the end of the text function, print an "invalid 
 *  expression" message, and return FALSE;
 * 
 *  If there is one text symbol and one or more data symbols with
 *  the same name, reset the incoming address based upon the 
 *  single text symbol, and return TRUE.
 *
 *  All of the remaining possibilities return TRUE without changing
 *  the incoming address:
 * 
 *   (1) if an evaluated address cannot be resolved to any symbol.
 *   (2) if an evaluated address argument did not contain a symbol name.
 *   (3) if there is only one possible symbol resolution.
 *   (4) if there are multiple data symbols.
 */
static int
resolve_text_symbol(char *arg, struct syment *sp_in, struct gnu_request *req, int radix)
{
	int text_symbols;
	struct syment *sp, *sp_orig, *first_text_sp, *sp_arg, *sp_addr;
	ulong offset, radix_flag;
	char buf[BUFSIZE];
	char *op;

	sp_arg = NULL;
	if (!sp_in && !IS_A_NUMBER(arg)) {
		strcpy(buf, arg);
		strip_beginning_char(buf, '(');
		strip_ending_char(buf, ')');
		clean_line(buf);
		if ((op = strpbrk(buf, "><+-&|*/%^"))) {
			*op = NULLCHAR;
			clean_line(buf);
			if ((sp = symbol_search(buf)) && is_symbol_text(sp)) {
				sp_arg = sp;
				text_symbols = 1;

				while ((sp = symbol_search_next(sp->name, sp))) {
					if (is_symbol_text(sp))
						text_symbols++;
				}

				if (text_symbols > 1) {
					sp_orig = sp_arg;
					goto duplicates;
				}
			}
		}
	}

	if (sp_in) {
		sp_orig = sp_in;
		offset = 0;
	} else if ((sp_orig = value_search(req->addr, &offset))) {
		if (!strstr(arg, sp_orig->name)) {
			if (sp_arg && (sp_orig != sp_arg)) {
				error(INFO, "invalid expression: %s evaluates to: %s+%lx\n", 
					arg, sp_orig->name, offset);
				return FALSE;
			}
			return TRUE;
		}
	} else {
		if (CRASHDEBUG(1))
			error(INFO, "%s: no text symbol found\n", arg);
		return TRUE;
	}

	if (symbol_name_count(sp_orig->name) <= 1)
		return TRUE;

	if (sp_arg) {
		sp_addr = value_search(req->addr, &offset);
		if (sp_arg != sp_addr) {
			if (STREQ(sp_arg->name, sp_addr->name)) {
				sp_orig = sp_arg;
				goto duplicates;
			}
			error(INFO, "invalid expression: %s evaluates to %s: %s+%lx\n", 
				arg, sp_addr->name, offset);
			return FALSE;
		}
	}

	text_symbols = 0;
	first_text_sp = NULL;
	sp = sp_orig;

	do {
		if (is_symbol_text(sp)) {
			if (!first_text_sp)
				first_text_sp = sp;
			text_symbols++;
		} 
	} while ((sp = symbol_search_next(sp->name, sp)));

	/*
	 *  If no text symbols for a symbol name exist, let it be...
	 */
	if (!text_symbols) {
		if (CRASHDEBUG(1))
			error(INFO, "%s: no text symbol found\n", arg);
		return TRUE;
	}

	/*
	 *  If only one symbol with the specified name is text,
	 *  reset the req->addr as appropriate in case a
	 *  lower-value data symbol was originally selected.
	 */
	if (text_symbols == 1) { 
		if (sp_in)
			req->addr = first_text_sp->value;
		else
			req->addr = first_text_sp->value + offset;
		return TRUE;
	}

duplicates:
	/*
	 *  Multiple text symbols with the same name exist.
	 *  Display them all and return FALSE.
	 */
	error(INFO, "%s: duplicate text symbols found:\n", arg);

	radix_flag = radix == 10 ? SHOW_DEC_OFFS : SHOW_HEX_OFFS;
	sp = sp_orig;

	do {
		if (is_symbol_text(sp)) {
			if (module_symbol(sp->value, NULL, NULL, NULL, 0))
				show_symbol(sp, 0, SHOW_LINENUM|SHOW_MODULE|radix_flag);
			else
				show_symbol(sp, 0, SHOW_LINENUM|radix_flag);
		}
	} while ((sp = symbol_search_next(sp->name, sp)));

	return FALSE;
}

static int
set_reverse_tmpfile_offset(struct gnu_request *req, ulong target)
{
	long index, *tmpfile_offsets;
	ulong curaddr;
	char buf[BUFSIZE];

	tmpfile_offsets = (long *)GETBUF(sizeof(long) * req->count);

	rewind(pc->tmpfile);
	index = 0;
        tmpfile_offsets[index] = ftell(pc->tmpfile);

	while (fgets(buf, BUFSIZE, pc->tmpfile)) {
		strip_beginning_whitespace(buf);
		if (STRNEQ(buf, "0x")) {
			extract_hex(buf, &curaddr, ':', TRUE);
			if (curaddr >= target)
				break;
		}
		index = (index+1) % req->count;
               	tmpfile_offsets[index] = ftell(pc->tmpfile);
	}

	if (((index+1) < req->count) && tmpfile_offsets[index+1]) 
		index++;
	else
		index = 0;

	if (fseek(pc->tmpfile, tmpfile_offsets[index], SEEK_SET) < 0) {
		FREEBUF(tmpfile_offsets);
		rewind(pc->tmpfile);
		return FALSE;
	}

	FREEBUF(tmpfile_offsets);

	return TRUE;
}


/*
 *  This routine disassembles text in one of four manners.  A starting
 *  address, an expression, or symbol must be entered.  Then:
 *
 *   1. if a count is appended, disassemble that many instructions starting
 *      at the target address.
 *   2. if a count is NOT entered, and the target address is the starting
 *      address of a function, disassemble the whole function.
 *   3. if the target address is other than the starting address of a 
 *      function, and no count argument is appended, then disassemble one 
 *      instruction. 
 *   4. If the -r option is used, disassemble all instructions in a routine
 *      up to and including the target address.
 *   5. If -u option, just pass the user address and count, ignoring any of
 *      the above.
 */

static char *dis_err = "gdb unable to disassemble kernel virtual address %lx\n";

void
cmd_dis(void)
{
	int c;
	int do_load_module_filter, do_machdep_filter, reverse, forward;
	int unfiltered, user_mode, count_entered, bug_bytes_entered, sources;
	unsigned int radix;
	ulong curaddr;
	ulong target;
	ulong count;
	ulong offset;
	ulong low, high;
	struct syment *sp;
	struct gnu_request *req;
	char *savename; 
	char *ret ATTRIBUTE_UNUSED;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char buf5[BUFSIZE];
	
	if ((argcnt == 2) && STREQ(args[1], "-b")) {
		fprintf(fp, "encoded bytes being skipped after ud2a: ");
		if (kt->BUG_bytes < 0)
			fprintf(fp, "undetermined\n");
		else
			fprintf(fp, "%d\n", kt->BUG_bytes);
		return;
	}

	reverse = forward = count_entered = bug_bytes_entered = sources = FALSE;
	sp = NULL;
	unfiltered = user_mode = do_machdep_filter = do_load_module_filter = 0;
	radix = 0;
	target = 0;

	req = (struct gnu_request *)GETBUF(sizeof(struct gnu_request));
	req->flags |= GNU_FROM_TTY_OFF|GNU_RETURN_ON_ERROR;
	req->count = 1;

        while ((c = getopt(argcnt, args, "dxhulsrfUb:B:")) != EOF) {
                switch(c)
		{
		case 'd':
			if (radix == 16)
				error(FATAL, 
				    "-d and -x are mutually exclusive\n");
			radix = 10;
			break;

		case 'x':
		case 'h':
			if (radix == 10)
				error(FATAL, 
				    "-d and -x are mutually exclusive\n");
			radix = 16;
			break;

		case 'U':
			unfiltered = TRUE;
			break;

		case 'u':
			if (sources)
				error(FATAL, 
					"-s can only be used with kernel addresses\n");
			user_mode = TRUE;
			break;

		case 'r':
			if (forward)
				error(FATAL, 
					"-r and -f are mutually exclusive\n");
			if (sources)
				error(FATAL, 
					"-r and -s are mutually exclusive\n");
			reverse = TRUE;
			break;

		case 'f':
			if (reverse)
				error(FATAL, 
					"-r and -f are mutually exclusive\n");
			if (sources)
				error(FATAL, 
					"-f and -s are mutually exclusive\n");
			forward = TRUE;
			break;

		case 'l':
			if (NO_LINE_NUMBERS())
				error(INFO, "line numbers are not available\n");
			else
				req->flags |= GNU_PRINT_LINE_NUMBERS;
			BZERO(buf4, BUFSIZE);
			break;

		case 's':
			if (reverse)
				error(FATAL, 
					"-r and -s are mutually exclusive\n");
			if (forward)
				error(FATAL, 
					"-f and -s are mutually exclusive\n");
			if (user_mode)
				error(FATAL, 
					"-s can only be used with kernel addresses\n");
			if (NO_LINE_NUMBERS())
				error(INFO, "line numbers are not available\n");
			sources = TRUE;
			break;

		case 'B':
		case 'b':
			kt->BUG_bytes = atoi(optarg);
			bug_bytes_entered = TRUE;
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (!radix)
		radix = pc->output_radix;

        if (args[optind]) {
                if (can_eval(args[optind])) {
			req->buf = args[optind];
                        req->addr = eval(args[optind], FAULT_ON_ERROR, NULL);
			if (!user_mode &&
			    !resolve_text_symbol(args[optind], NULL, req, radix)) {
				FREEBUF(req);
				return;
			}
                } else if (hexadecimal(args[optind], 0) && !symbol_exists(args[optind])) {
			req->buf = args[optind];
                        req->addr = htol(args[optind], FAULT_ON_ERROR, NULL);
			sp = value_search(req->addr, &offset);
			if (!user_mode && !sp) {
				error(WARNING, 
				    "%lx: no associated kernel symbol found\n",
					req->addr);
				unfiltered = TRUE;
			}
			if (!offset && sp && is_symbol_text(sp))
				req->flags |= GNU_FUNCTION_ONLY;
                } else if ((sp = symbol_search(args[optind]))) {
			req->buf = args[optind];
                        req->addr = sp->value;
			if (!resolve_text_symbol(args[optind], sp, req, radix)) {
				FREEBUF(req);
				return;
			}
			if (is_symbol_text(sp))
				req->flags |= GNU_FUNCTION_ONLY;
		} else {
                        fprintf(fp, "symbol not found: %s\n", args[optind]);
                        fprintf(fp, "possible alternatives:\n");
                        if (!symbol_query(args[optind], "  ", NULL))
                                fprintf(fp, "  (none found)\n");
			FREEBUF(req);
                        return;
                }

                if (args[++optind]) {
			if (forward)
				forward = FALSE;
			req->count = stol(args[optind], FAULT_ON_ERROR, NULL);
			req->flags &= ~GNU_FUNCTION_ONLY;
			if (!req->count)
				error(FATAL, "invalid count argument: 0\n"); 
			count_entered++;
		}

		if (sources) {
			list_source_code(req, count_entered);
			return;
		}

		if (unfiltered) {
                	sprintf(buf1, "x/%ldi 0x%lx",  
				req->count ? req->count : 1, req->addr);
        		gdb_pass_through(buf1, NULL, GNU_RETURN_ON_ERROR);
			return;
		}

		if (!user_mode && !IS_KVADDR(req->addr)) 
			error(FATAL, "%lx is not a kernel virtual address\n",
				req->addr);

		if (user_mode) {
                	sprintf(buf1, "x/%ldi 0x%lx",  
				req->count ? req->count : 1, req->addr);
			pc->curcmd_flags |= MEMTYPE_UVADDR;
        		gdb_pass_through(buf1, NULL, GNU_RETURN_ON_ERROR);
			return;
		}

		req->command = GNU_RESOLVE_TEXT_ADDR;
		gdb_interface(req);
		req->flags &= ~GNU_COMMAND_FAILED;

		if (reverse || forward || req->flags & GNU_FUNCTION_ONLY) {
			if (get_text_function_range(sp ? sp->value : req->addr,
			    &low, &high))
				req->addr2 = high;
			else if (sp) {
				savename = sp->name;
				if ((sp = next_symbol(NULL, sp)))
					req->addr2 = sp->value;
				else
					error(FATAL, 
				"unable to determine symbol after %s\n",
						savename);
			} else {
				if ((sp = value_search(req->addr, NULL))
				     && (sp = next_symbol(NULL, sp)))
					req->addr2 = sp->value;	
				else 
					error(FATAL, dis_err, req->addr);
			}
		}

		if (reverse || forward) {
			target = req->addr;
			if ((sp = value_search(target, NULL)) == NULL)
				error(FATAL, "cannot resolve address: %lx\n", target);

			req->addr = sp->value;
		} else
			count = 0;
		do_load_module_filter = module_symbol(req->addr, NULL, NULL, 
			NULL, *gdb_output_radix);

		do_machdep_filter = machdep->dis_filter(req->addr, NULL, radix);
		open_tmpfile();

		if (reverse)
			sprintf(buf5, "x/%ldi 0x%lx",
				(target - req->addr) ? target - req->addr : 1, 
				req->addr);
		else
			sprintf(buf5, "x/%ldi 0x%lx",
				count_entered && req->count ? req->count : 
				forward || req->flags & GNU_FUNCTION_ONLY ? 
				req->addr2 - req->addr : 1, 
				req->addr);
		gdb_pass_through(buf5, NULL, GNU_RETURN_ON_ERROR);

		if (req->flags & GNU_COMMAND_FAILED) {
			close_tmpfile();
			error(FATAL, dis_err, req->addr);
		}

		if (reverse && count_entered &&
		    set_reverse_tmpfile_offset(req, target))
			count_entered = FALSE;
		else
			rewind(pc->tmpfile);

		while (fgets(buf2, BUFSIZE, pc->tmpfile)) {

			if (STRNEQ(buf2, "=>"))
				shift_string_left(buf2, 2);

			strip_beginning_whitespace(buf2);

			if (do_load_module_filter)
				load_module_filter(buf2, LM_DIS_FILTER);

			if (STRNEQ(buf2, "0x"))
				extract_hex(buf2, &curaddr, ':', TRUE);

			if (forward) {
				if (curaddr < target)
					continue;
				else
					forward = FALSE;
			}

			if (!reverse)
				if (!count_entered && req->addr2 &&
				    (curaddr >= req->addr2))
					break;

			if (do_machdep_filter)
				machdep->dis_filter(curaddr, buf2, radix);

			if (req->flags & GNU_PRINT_LINE_NUMBERS) {
				get_line_number(curaddr, buf3,
					FALSE);
				if (!STREQ(buf3, buf4)) {
					print_verbatim(
					    pc->saved_fp, buf3);
					print_verbatim(
					    pc->saved_fp, "\n");
					strcpy(buf4, buf3);
				}
			}

			print_verbatim(pc->saved_fp, buf2); 
			if (reverse) {
				if (curaddr >= target) {
					if (LASTCHAR(clean_line(buf2)) != ':') 
						break;

					ret = fgets(buf2, BUFSIZE, pc->tmpfile);

					if (do_load_module_filter)
						load_module_filter(buf2, LM_DIS_FILTER);

					if (do_machdep_filter) 
						machdep->dis_filter(curaddr, buf2, radix);

					print_verbatim(pc->saved_fp, buf2);
					break;
				}
			}

			if (count_entered && LASTCHAR(clean_line(buf2)) != ':')
				if (++count == req->count)
					break;
		}
		close_tmpfile();
        }
        else if (bug_bytes_entered)
		return;
	else cmd_usage(pc->curcmd, SYNOPSIS);

	FREEBUF(req);
	return;
}

/*
 *  x86 and x86_64 kernels may have file/line-number encoding
 *  asm()'d in just after the "ud2a" instruction, which confuses
 *  the disassembler and the x86 backtracer.  Determine the 
 *  number of bytes to skip.
 */
static void
BUG_bytes_init(void)
{
	if (machine_type("X86"))
		kt->BUG_bytes = BUG_x86();
	else if (machine_type("X86_64"))
		kt->BUG_bytes = BUG_x86_64();
}

static int
BUG_x86(void)
{
	struct syment *sp, *spn;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char *arglist[MAXARGS];
	ulong vaddr, fileptr;
	int found;

	/*
	 *  Prior to 2.4.19, a call to do_BUG() preceded
	 *  the standalone ud2a instruction.
	 */ 
	if (THIS_KERNEL_VERSION < LINUX(2,4,19))
		return 0;

	/*
	 *  2.6.20 introduced __bug_table support for i386, 
	 *  but even if CONFIG_DEBUG_BUGVERBOSE is not configured,
	 *  the ud2a stands alone.
	 */
	if (THIS_KERNEL_VERSION >= LINUX(2,6,20))
		return 0;

	/*
	 *  For previous kernel versions, it may depend upon 
	 *  whether CONFIG_DEBUG_BUGVERBOSE was configured:
	 *
	 *   #ifdef CONFIG_DEBUG_BUGVERBOSE
	 *   #define BUG()                           \
	 *    __asm__ __volatile__(  "ud2\n"         \
	 *                           "\t.word %c0\n" \
	 *                           "\t.long %c1\n" \
	 *                            : : "i" (__LINE__), "i" (__FILE__))
	 *   #else
	 *   #define BUG() __asm__ __volatile__("ud2\n")
	 *   #endif
	 *
  	 *  But that's not necessarily true, since there are
	 *  pre-2.6.11 versions that force it like so:
	 *
         *   #if 1   /- Set to zero for a slightly smaller kernel -/
         *   #define BUG()                           \
         *    __asm__ __volatile__(  "ud2\n"         \
         *                           "\t.word %c0\n" \
         *                           "\t.long %c1\n" \
         *                            : : "i" (__LINE__), "i" (__FILE__))
         *   #else
         *   #define BUG() __asm__ __volatile__("ud2\n")
         *   #endif
	 */

	/*
	 *  This works if in-kernel config data is available.
	 */
	if ((THIS_KERNEL_VERSION >= LINUX(2,6,11)) &&
	    (kt->flags & BUGVERBOSE_OFF))
		return 0;

	/*
	 *  At this point, it's a pretty safe bet that it's configured,
	 *  but to be sure, disassemble a known BUG() caller and
	 *  verify that the encoding is there.
	 */

#define X86_BUG_BYTES (6)  /* sizeof(short) + sizeof(pointer) */

	if (!(sp = symbol_search("do_exit")) ||
	    !(spn = next_symbol(NULL, sp)))
		return X86_BUG_BYTES;

	sprintf(buf1, "x/%ldi 0x%lx", spn->value - sp->value, sp->value);

	found = FALSE;
	vaddr = 0;
	open_tmpfile();
	gdb_pass_through(buf1, pc->tmpfile, GNU_RETURN_ON_ERROR);
	rewind(pc->tmpfile);
	while (fgets(buf2, BUFSIZE, pc->tmpfile)) {
		if (parse_line(buf2, arglist) < 3)
			continue;

		if ((vaddr = htol(strip_ending_char(arglist[0], ':'), 
		    RETURN_ON_ERROR|QUIET, NULL)) >= spn->value)
			continue; 

		if (STREQ(arglist[2], "ud2a")) {
			found = TRUE;
			break;
		}
	}
	close_tmpfile();

        if (!found || !readmem(vaddr+4, KVADDR, &fileptr, sizeof(ulong),
            "BUG filename pointer", RETURN_ON_ERROR|QUIET))
		return X86_BUG_BYTES;

	if (!IS_KVADDR(fileptr)) {
		if (CRASHDEBUG(1))
			fprintf(fp, 
			    "no filename pointer: kt->BUG_bytes: 0\n");
		return 0;
	}

	if (!read_string(fileptr, buf1, BUFSIZE-1))
		error(WARNING, 
		    "cannot read BUG (ud2a) encoded filename address: %lx\n",
			fileptr);
	else if (CRASHDEBUG(1))
		fprintf(fp, "BUG bytes filename encoding: [%s]\n", buf1);

	return X86_BUG_BYTES;
}

static int
BUG_x86_64(void)
{
        /*
         *  2.6.20 introduced __bug_table support for x86_64,
         *  but even if CONFIG_DEBUG_BUGVERBOSE is not configured,
	 *  the ud2a stands alone.
         */
        if (THIS_KERNEL_VERSION >= LINUX(2,6,20))
                return 0;

	/*
	 *  The original bug_frame structure looks like this, which
	 *  causes the disassembler to go off into the weeds:
	 *
	 *    struct bug_frame { 
	 *        unsigned char ud2[2];          
	 *        char *filename;  
	 *        unsigned short line; 
	 *    } 
	 *  
	 *  In 2.6.13, fake push and ret instructions were encoded 
	 *  into the frame so that the disassembly would at least 
	 *  "work", although the two fake instructions show nonsensical
	 *  arguments:
	 *
	 *    struct bug_frame {
	 *        unsigned char ud2[2];
	 *        unsigned char push;
	 *        signed int filename;
	 *        unsigned char ret;
	 *        unsigned short line;
	 *    }
	 */  

	if (STRUCT_EXISTS("bug_frame"))
		return (int)(STRUCT_SIZE("bug_frame") - 2);

	return 0;
}


/*
 *  Callback from gdb disassembly code.
 */
int
kernel_BUG_encoding_bytes(void)
{
	return kt->BUG_bytes;
}

#ifdef NOT_USED
/*
 *  To avoid premature stoppage/extension of a dis <function> that includes
 *  one of the following x86/gcc 3.2 constant declarations, don't allow them
 *  to be considered the next text symbol.
 */
static struct syment *
next_text_symbol(struct syment *sp_in)
{
	return next_symbol(NULL, sp_in);
	struct syment *sp;

	sp = sp_in; 
	while ((sp = next_symbol(NULL, sp))) {
		if (STREQ(sp->name, "__constant_c_and_count_memset") ||
		    STREQ(sp->name, "__constant_copy_from_user") ||
	            STREQ(sp->name, "__constant_copy_from_user_nocheck") ||
	            STREQ(sp->name, "__constant_copy_to_user") ||
                    STREQ(sp->name, "__constant_copy_to_user_nocheck") ||
		    STREQ(sp->name, "__constant_memcpy") ||
		    STREQ(sp->name, "__constant_c_and_count_memset") ||
		    STREQ(sp->name, "__constant_c_x_memset") ||
		    STREQ(sp->name, "__constant_memcpy")) {
			continue;
		}
		break;
	}
	return sp;
}
#endif  /* NOT_USED */

/*
 *  Nothing to do.
 */
int
generic_dis_filter(ulong value, char *buf, unsigned int output_radix)
{
	return TRUE;
}

#define FRAMESIZE_DEBUG_MESSAGE \
"\nx86 usage: bt -D [size|clear|dump|seek|noseek|validate|novalidate] [-I eip]\n  If eip:  set its associated framesize to size.\n           \"validate/novalidate\" will turn on/off V bit for this eip entry.\n  If !eip: \"clear\" will clear the framesize cache and RA seek/noseek flags.\n           \"dump\" will dump the current framesize cache entries.\n           \"seek/noseek\" turns on/off RA seeking.\n           \"validate/novalidate\" turns on/off V bit for all current entries.\n\nx86_64 usage: bt -D [clear|dump|validate|framepointer|noframepointer] [-I rip]\n  If rip:  \"validate\" will verbosely recalculate the framesize without\n           framepointers (no stack reference).\n  If !rip: \"clear\" will clear the framesize cache.\n           \"dump\" will dump the current framesize cache entries.\n           \"framepointer/noframepointer\" toggle the FRAMEPOINTER flag and\n           clear the framesize cache."


/*
 *  Display a kernel stack backtrace.  Arguments may be any number pid or task
 *  values, or, if no arguments are given, the stack trace of the current 
 *  context will be displayed.  Alternatively:
 *
 *     -a  displays the stack traces of the active tasks on each CPU.
 *         (only applicable to crash dumps)
 *     -r  display raw stack data, consisting of a memory dump of the two
 *         pages of memory containing the task_union structure.
 *     -s  displays arguments symbolically.
 */

void
clone_bt_info(struct bt_info *orig, struct bt_info *new,
	      struct task_context *tc)
{
	BCOPY(orig, new, sizeof(*new));
	new->stackbuf = NULL;
	new->tc = tc;
	new->task = tc->task;
	new->stackbase = GET_STACKBASE(tc->task);
	new->stacktop = GET_STACKTOP(tc->task);
}

#define BT_SETUP(TC)                                          \
	clone_bt_info(&bt_setup, bt, (TC));         	      \
        if (refptr) {                                         \
		BZERO(&reference, sizeof(struct reference));  \
		bt->ref = &reference;                         \
        	bt->ref->str = refptr;                        \
	}

#define DO_TASK_BACKTRACE() 					\
	{							\
	BT_SETUP(tc);						\
	if (!BT_REFERENCE_CHECK(bt))				\
		print_task_header(fp, tc, subsequent++);	\
	back_trace(bt);						\
	}
 
#define DO_THREAD_GROUP_BACKTRACE()	 			\
	{							\
	tc = pid_to_context(tgid);				\
	BT_SETUP(tc);						\
	if (!BT_REFERENCE_CHECK(bt))				\
		print_task_header(fp, tc, subsequent++);	\
	if (setjmp(pc->foreach_loop_env)) {			\
		pc->flags &= ~IN_FOREACH;			\
		free_all_bufs();				\
	} else {						\
		pc->flags |= IN_FOREACH;			\
		back_trace(bt);					\
		pc->flags &= ~IN_FOREACH;			\
	}							\
	tc = FIRST_CONTEXT();					\
	for (i = 0; i < RUNNING_TASKS(); i++, tc++) {		\
		if (tc->pid == tgid) 				\
			continue;				\
		if (task_tgid(tc->task) != tgid)		\
			continue;				\
		BT_SETUP(tc);					\
		if (!BT_REFERENCE_CHECK(bt))			\
			print_task_header(fp, tc, subsequent++);\
		if (setjmp(pc->foreach_loop_env)) {		\
			pc->flags &= ~IN_FOREACH;		\
			free_all_bufs();			\
		} else {					\
			pc->flags |= IN_FOREACH;		\
			back_trace(bt);				\
			pc->flags &= ~IN_FOREACH;		\
		}						\
       	}							\
	pc->flags &= ~IN_FOREACH;				\
	}

void
cmd_bt(void)
{
	int i, c;
	ulong value, *cpus;
        struct task_context *tc;
	int subsequent, active, panic;
	struct stack_hook hook;
	struct bt_info bt_info, bt_setup, *bt;
	struct reference reference;
	char *refptr;
	ulong tgid, task;
	char arg_buf[BUFSIZE];

	tc = NULL;
	cpus = NULL;
	subsequent = active = panic = 0;
	hook.eip = hook.esp = 0;
	refptr = 0;
	bt = &bt_info;
	BZERO(bt, sizeof(struct bt_info));

	if (kt->flags & USE_OPT_BT)
		bt->flags |= BT_OPT_BACK_TRACE;

	while ((c = getopt(argcnt, args, "D:fFI:S:c:n:aAloreEgstTdxR:Ovp")) != EOF) {
                switch (c)
		{
		case 'f':
			bt->flags |= BT_FULL;
			break;

		case 'F':
			if (bt->flags & BT_FULL_SYM_SLAB)
				bt->flags |= BT_FULL_SYM_SLAB2;
			else
				bt->flags |= (BT_FULL|BT_FULL_SYM_SLAB);
			break;

		case 'o':
			if (!(machine_type("X86") || machine_type("X86_64") || machine_type("ARM64")) ||
			    XEN_HYPER_MODE())
				option_not_supported(c);
			bt->flags |= BT_OPT_BACK_TRACE;
			break;

		case 'O':
			if (!(machine_type("X86") || machine_type("X86_64") || machine_type("ARM64")) ||
			    XEN_HYPER_MODE()) 
				option_not_supported(c);
			else if (kt->flags & USE_OPT_BT) { 
				/* 
				 *  Make this setting idempotent across the use of
				 *  $HOME/.crashrc, ./.crashrc, and "-i input" files. 
				 *  If we've been here before during initialization,
				 *  leave it alone.
			 	 */
				if (pc->flags & INIT_IFILE) {
					error(INFO, "use %s bt method by default (already set)\n",
						machine_type("ARM64") ? "optional" : "old");
					return;
				}
				kt->flags &= ~USE_OPT_BT;
				error(INFO, "use %s bt method by default\n",
					machine_type("ARM64") ? "original" : "new");
			} else {
				kt->flags |= USE_OPT_BT;
				error(INFO, "use %s bt method by default\n",
					machine_type("ARM64") ? "optional" : "old");
			}
			return;

		case 'R':
			if (refptr) 
				error(INFO, "only one -R option allowed\n");
			else 
				refptr = optarg;
			break;
			
		case 'l':
			if (NO_LINE_NUMBERS())
				error(INFO, "line numbers are not available\n");
			else
				bt->flags |= BT_LINE_NUMBERS;
			break;

		case 'E':
			if (XEN_HYPER_MODE())
				option_not_supported(c);
			bt->flags |= BT_EFRAME_SEARCH|BT_EFRAME_SEARCH2;
			bt->hp = &hook;
			break;

		case 'e':
			if (XEN_HYPER_MODE())
				option_not_supported(c);
			bt->flags |= BT_EFRAME_SEARCH;
			break;

		case 'g':
#ifdef GDB_5_3
			bt->flags |= BT_USE_GDB;
#else
			bt->flags |= BT_THREAD_GROUP;
#endif
			break;

		case 'x':
			if (bt->radix == 10)
				error(FATAL,
					"-d and -x are mutually exclusive\n");
			bt->radix = 16;
			break;

		case 'd':
			if (bt->radix == 16)
				error(FATAL,
					"-d and -x are mutually exclusive\n");
			bt->radix = 10;
			break;

		case 'I':
			bt->hp = &hook;
			hook.eip = convert(optarg, FAULT_ON_ERROR, 
				NULL, NUM_HEX|NUM_EXPR);
			break;

		case 'D':
			if (STREQ(optarg, "seek")) {
				kt->flags |= RA_SEEK;
				kt->flags &= ~NO_RA_SEEK;
				return;
			} else if (STREQ(optarg, "noseek")) {
				kt->flags |= NO_RA_SEEK;
				kt->flags &= ~RA_SEEK;
				return;
			}
			bt->hp = &hook;
			bt->flags |= BT_FRAMESIZE_DEBUG;
			if (STREQ(optarg, "dump"))
				hook.esp = 1;
			else if (STRNEQ(optarg, "level-"))
				bt->debug = dtol(optarg+6, FAULT_ON_ERROR, NULL);
			else if (STREQ(optarg, "validate"))
				hook.esp = (ulong)-1;
			else if (STREQ(optarg, "novalidate"))
				hook.esp = (ulong)-2;
			else if (STREQ(optarg, "framepointer"))
				hook.esp = (ulong)-3;
			else if (STREQ(optarg, "noframepointer"))
				hook.esp = (ulong)-4;
			else if (STREQ(optarg, "orc"))
				hook.esp = (ulong)-5;
			else if (STREQ(optarg, "clear")) {
				kt->flags &= ~(RA_SEEK|NO_RA_SEEK);
				hook.esp = 0;
			} else if (*optarg == '-') {
				hook.esp = dtol(optarg+1, FAULT_ON_ERROR, NULL);
				hook.esp = (ulong)(0 - (long)hook.esp);
			} else if (STREQ(optarg, "dwarf") || STREQ(optarg, "cfi")) {
                        	if (!(kt->flags & DWARF_UNWIND_CAPABLE))
					return;
			} else
				hook.esp = dtol(optarg, FAULT_ON_ERROR, NULL);
			break;

		case 'S':
			bt->hp = &hook;
			hook.esp = htol(optarg, FAULT_ON_ERROR, NULL);
			if (!hook.esp)
				error(FATAL, 
				    "invalid stack address for this task: 0\n");
			break;

		case 'c':
			if (bt->flags & BT_CPUMASK) {
				error(INFO, "only one -c option allowed\n");
				argerrs++;
			} else {
				bt->flags |= BT_CPUMASK;				
				BZERO(arg_buf, BUFSIZE);
				strcpy(arg_buf, optarg);
				cpus = get_cpumask_buf();
			}
			break;

		case 'A':
			if (!machine_type("S390X"))
				option_not_supported(c);
			bt->flags |= BT_SHOW_ALL_REGS; /* FALLTHROUGH */
		case 'a':
			active++;
			break;

		case 'n':
			if ((machine_type("X86_64") || machine_type("ARM64")) &&
			    STREQ(optarg, "idle"))
				bt->flags |= BT_SKIP_IDLE;
			else
				option_not_supported(c);
			break;

		case 'r':
			bt->flags |= BT_RAW;
			break;

		case 's':
			bt->flags |= BT_SYMBOL_OFFSET;
			break;

		case 'T':
			bt->flags |= BT_TEXT_SYMBOLS_ALL;
		case 't':
			bt->flags |= BT_TEXT_SYMBOLS;
			break;

		case 'v':
			if (XEN_HYPER_MODE())
				option_not_supported(c);
			check_stack_overflow();
			return;
		case 'p':
			if (LIVE())
				error(FATAL,
				    "-p option not supported on a live system or live dump\n");
			if (!tt->panic_task)
				error(FATAL, "no panic task found!\n");
			panic++;
			break;

		default:
			argerrs++;
			if (optopt == 'D') {
				fprintf(fp, FRAMESIZE_DEBUG_MESSAGE);
				return;
			}
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (bt->flags & BT_FRAMESIZE_DEBUG) {
		if (machdep->flags & FRAMESIZE_DEBUG) {
			while (args[optind]) {
				if (!hook.eip)
                       			hook.eip = convert(args[optind], 
						FAULT_ON_ERROR, NULL, 
						NUM_HEX|NUM_EXPR);
				else {
					fprintf(fp, FRAMESIZE_DEBUG_MESSAGE);
					return;
				}
				optind++;
			}
			machdep->back_trace(bt);
			return;
		}
		error(FATAL, "framesize debug not available\n");
	}

	BCOPY(bt, &bt_setup, sizeof(struct bt_info));

	if (bt->flags & BT_EFRAME_SEARCH2) {
               	tc = CURRENT_CONTEXT();  /* borrow stack */
                BT_SETUP(tc);
		if (bt->flags & BT_CPUMASK) {
			make_cpumask(arg_buf, cpus, FAULT_ON_ERROR, NULL);
			bt->cpumask = cpus;
		}
                back_trace(bt);
                return;
	}

	if (XEN_HYPER_MODE()) {
#ifdef XEN_HYPERVISOR_ARCH
		/* "task" means vcpu for xen hypervisor */
		if (active) {
			for (c = 0; c < XEN_HYPER_MAX_CPUS(); c++) {
				if (!xen_hyper_test_pcpu_id(c))
					continue;
				fake_tc.task = xen_hyper_pcpu_to_active_vcpu(c);
				BT_SETUP(&fake_tc);
			        if (!BT_REFERENCE_CHECK(bt))
					xen_hyper_print_bt_header(fp, fake_tc.task, 
						subsequent++);
				back_trace(bt);
			}
		} else {
			if (args[optind]) {
				fake_tc.task = xen_hyper_pcpu_to_active_vcpu(
				    convert(args[optind], 0, NULL, NUM_DEC | NUM_HEX));
			} else {
				fake_tc.task = XEN_HYPER_VCPU_LAST_CONTEXT()->vcpu;
			}
			BT_SETUP(&fake_tc);
			if (!BT_REFERENCE_CHECK(bt))
				xen_hyper_print_bt_header(fp, fake_tc.task, 0);
			back_trace(bt);
		}
		return;
#else
		error(FATAL, XEN_HYPERVISOR_NOT_SUPPORTED);
#endif
	}

	if (bt->flags & BT_CPUMASK) {
		if (LIVE())
			error(FATAL, 
			    "-c option not supported on a live system or live dump\n");

		if (bt->flags & BT_THREAD_GROUP)
			error(FATAL, 
			    "-c option cannot be used with the -g option\n");

		make_cpumask(arg_buf, cpus, FAULT_ON_ERROR, NULL);

		for (i = 0; i < kt->cpus; i++) {
			if (NUM_IN_BITMAP(cpus, i)) {
				if (hide_offline_cpu(i)) {
					error(INFO, "%sCPU %d is OFFLINE.\n",
					      subsequent++ ? "\n" : "", i);
					continue;
				}

				if ((task = get_active_task(i)))
					tc = task_to_context(task);
				else
					error(FATAL, "cannot determine active task on cpu %ld\n", i);
				DO_TASK_BACKTRACE();
			}
		}
		FREEBUF(cpus);
		return;
	}

	if (active) {
		if (LIVE())
			error(FATAL, 
			    "-%c option not supported on a live system or live dump\n",
				bt->flags & BT_SHOW_ALL_REGS ? 'A' : 'a');

		if (bt->flags & BT_THREAD_GROUP)
			error(FATAL, 
			    "-a option cannot be used with the -g option\n");

		for (c = 0; c < NR_CPUS; c++) {
			if (setjmp(pc->foreach_loop_env)) {
				pc->flags &= ~IN_FOREACH;
				free_all_bufs();
				continue;
			}
			if ((tc = task_to_context(tt->panic_threads[c]))) {
				pc->flags |= IN_FOREACH;
				DO_TASK_BACKTRACE();
				pc->flags &= ~IN_FOREACH;
			}
		}

		return;
	}

	if (!args[optind]) {
		if (CURRENT_PID() && (bt->flags & BT_THREAD_GROUP)) {
			tgid = task_tgid(CURRENT_TASK());
			DO_THREAD_GROUP_BACKTRACE();
		} else {
			if (panic)
				tc = task_to_context(tt->panic_task);
			else
				tc = CURRENT_CONTEXT();
			DO_TASK_BACKTRACE();
		}
		return;
	}

	while (args[optind]) {
                switch (str_to_context(args[optind], &value, &tc))
                {
                case STR_PID:
                        for (tc = pid_to_context(value); tc; tc = tc->tc_next) {
				if (tc->pid && (bt->flags & BT_THREAD_GROUP)) {
					tgid = task_tgid(tc->task);
					DO_THREAD_GROUP_BACKTRACE();
					break;
				} else if (tc->tc_next) {
		                        if (setjmp(pc->foreach_loop_env)) {
						pc->flags &= ~IN_FOREACH;
						free_all_bufs();
						continue;
					}
					pc->flags |= IN_FOREACH;
					DO_TASK_BACKTRACE();
					pc->flags &= ~IN_FOREACH;
				} else 
					DO_TASK_BACKTRACE();
			}
			break;

                case STR_TASK:
			if (tc->pid && (bt->flags & BT_THREAD_GROUP)) {
				tgid = task_tgid(value);
				DO_THREAD_GROUP_BACKTRACE();
			} else
				DO_TASK_BACKTRACE();
			break;

                case STR_INVALID:
                        error(INFO, "%sinvalid task or pid value: %s\n",
                                subsequent++ ? "\n" : "", args[optind]);
                        break;
                }

		optind++;
	}
}

void
print_stack_text_syms(struct bt_info *bt, ulong esp, ulong eip)
{
	ulong next_sp, next_pc;
	int i;
	ulong *up;
	struct load_module *lm;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];

	if (bt->flags & BT_TEXT_SYMBOLS) {
		if (!(bt->flags & BT_TEXT_SYMBOLS_ALL))
			fprintf(fp, "%sSTART: %s at %lx\n",
				space(VADDR_PRLEN > 8 ? 14 : 6),
				bt->flags & BT_SYMBOL_OFFSET ?
				value_to_symstr(eip, buf2, bt->radix) :
		        	closest_symbol(eip), eip);
	}

	if (bt->hp) 
		bt->hp->eip = bt->hp->esp = 0;
	next_pc = next_sp = 0;

	for (i = (esp - bt->stackbase)/sizeof(ulong);
	     i < LONGS_PER_STACK; i++) {
		up = (ulong *)(&bt->stackbuf[i*sizeof(ulong)]);
		if (is_kernel_text_offset(*up)) {
			if (!next_pc) 
				next_pc = *up;
			else if (!next_sp) 
				next_sp = bt->stackbase + (i * sizeof(long));
		}
		if (is_kernel_text(*up) && (bt->flags & 
		    (BT_TEXT_SYMBOLS|BT_TEXT_SYMBOLS_PRINT))) { 
			if (bt->flags & (BT_ERROR_MASK|BT_TEXT_SYMBOLS)) {
                               	fprintf(fp, "  %s[%s] %s at %lx",
					bt->flags & BT_ERROR_MASK ?
					"  " : "",
					mkstring(buf1, VADDR_PRLEN, 
					RJUST|LONG_HEX,
                               		MKSTR(bt->stackbase + 
					(i * sizeof(long)))),
					bt->flags & BT_SYMBOL_OFFSET ?
					value_to_symstr(*up, buf2, bt->radix) :
					closest_symbol(*up), *up);
				if (module_symbol(*up, NULL, &lm, NULL, 0))
					fprintf(fp, " [%s]", lm->mod_name);
				fprintf(fp, "\n");
			} else
                               	fprintf(fp, "%lx: %s\n",
                                       	bt->stackbase + 
					(i * sizeof(long)),
                                       	value_to_symstr(*up, buf1, 0));
		}
	}

	if (bt->hp) {
		bt->hp->eip = next_pc;
		bt->hp->esp = next_sp;
	}
}

int
in_alternate_stack(int cpu, ulong address)
{
	if (cpu >= NR_CPUS)
		return FALSE;

	if (machdep->in_alternate_stack)
		if (machdep->in_alternate_stack(cpu, address))
			return TRUE;

	if (tt->flags & IRQSTACKS) {
		if (in_irq_ctx(BT_SOFTIRQ, cpu, address) ||
                    in_irq_ctx(BT_HARDIRQ, cpu, address))
			return TRUE;
	}

	return FALSE;
}

/*
 *  Gather the EIP, ESP and stack address for the target task, and passing 
 *  them on to the machine-specific back trace command.
 */
void
back_trace(struct bt_info *bt)
{
	int i;
	ulong *up;
	char buf[BUFSIZE];
	ulong eip, esp;
	struct bt_info btsave = { 0 };

	if (bt->flags & BT_RAW) {
		if (bt->hp && bt->hp->esp)
			esp = bt->hp->esp;
		else 
			esp = GET_STACKBASE(bt->task);
		raw_stack_dump(esp, STACKSIZE());
		return;
	}

	if (LIVE() && !(bt->flags & BT_EFRAME_SEARCH) && is_task_active(bt->task)) {

		if (BT_REFERENCE_CHECK(bt) ||
		    bt->flags & (BT_TEXT_SYMBOLS_PRINT|BT_TEXT_SYMBOLS_NOPRINT))
			return;

		if (!(bt->flags & 
		    (BT_KSTACKP|BT_TEXT_SYMBOLS|BT_TEXT_SYMBOLS_ALL)))
			fprintf(fp, "(active)\n");

		if (!(bt->flags & (BT_TEXT_SYMBOLS|BT_TEXT_SYMBOLS_ALL) || REMOTE_PAUSED()))
			return;
 	}

	if (bt->stackbase == 0) {
		fprintf(fp, "(no stack)\n");
		return;
	}

	fill_stackbuf(bt);

	if (CRASHDEBUG(4)) {
		for (i = 0, up = (ulong *)bt->stackbuf; 
		     i < LONGS_PER_STACK; i++, up++) {
			if (is_kernel_text(*up))
				fprintf(fp, "%lx: %s\n", 
					tt->flags & THREAD_INFO ?
					bt->tc->thread_info + 
					(i * sizeof(long)) :
					bt->task + (i * sizeof(long)),
					value_to_symstr(*up, buf, 0));
		}
	}

	if (BT_REFERENCE_CHECK(bt)) {
		if (can_eval(bt->ref->str)) {
			bt->ref->hexval = eval(bt->ref->str, 
				FAULT_ON_ERROR, NULL);
			bt->ref->cmdflags |= BT_REF_HEXVAL;
		} else if (hexadecimal(bt->ref->str, 0)) {
			bt->ref->hexval = htol(bt->ref->str, 
				FAULT_ON_ERROR, NULL);
			bt->ref->cmdflags |= BT_REF_HEXVAL;
		} else
			bt->ref->cmdflags |= BT_REF_SYMBOL;
	}

	if (bt->flags & BT_EFRAME_SEARCH) {
		machdep->eframe_search(bt); 
		return;
	}
	
	if (bt->hp) {
		if (bt->hp->esp && !INSTACK(bt->hp->esp, bt) &&
		    !in_alternate_stack(bt->tc->processor, bt->hp->esp))
			error(FATAL, 
		    	    "non-process stack address for this task: %lx\n"
			    "    (valid range: %lx - %lx)\n",
				bt->hp->esp, bt->stackbase, bt->stacktop);

		eip = bt->hp->eip;
		esp = bt->hp->esp;

		machdep->get_stack_frame(bt, eip ? NULL : &eip, 
			esp ? NULL : &esp);

		if (in_irq_ctx(BT_HARDIRQ, bt->tc->processor, esp)) {
			bt->stackbase = tt->hardirq_ctx[bt->tc->processor];
			bt->stacktop = bt->stackbase + STACKSIZE();
			alter_stackbuf(bt);
			bt->flags |= BT_HARDIRQ;
		} else if (in_irq_ctx(BT_SOFTIRQ, bt->tc->processor, esp)) {
			bt->stackbase = tt->softirq_ctx[bt->tc->processor];
			bt->stacktop = bt->stackbase + STACKSIZE();
			alter_stackbuf(bt);
			bt->flags |= BT_SOFTIRQ;
		}
        } else if (XEN_HYPER_MODE())
		machdep->get_stack_frame(bt, &eip, &esp);
	else if (NETDUMP_DUMPFILE())
                get_netdump_regs(bt, &eip, &esp);
	else if (KDUMP_DUMPFILE())
                get_kdump_regs(bt, &eip, &esp);
	else if (DISKDUMP_DUMPFILE())
                get_diskdump_regs(bt, &eip, &esp);
	else if (KVMDUMP_DUMPFILE())
                get_kvmdump_regs(bt, &eip, &esp);
        else if (LKCD_DUMPFILE())
                get_lkcd_regs(bt, &eip, &esp);
	else if (XENDUMP_DUMPFILE())
		get_xendump_regs(bt, &eip, &esp);
	else if (SADUMP_DUMPFILE())
		get_sadump_regs(bt, &eip, &esp);
	else if (VMSS_DUMPFILE())
		get_vmware_vmss_regs(bt, &eip, &esp);
        else if (REMOTE_PAUSED()) {
		if (!is_task_active(bt->task) || !get_remote_regs(bt, &eip, &esp))
			machdep->get_stack_frame(bt, &eip, &esp);
	} else
                machdep->get_stack_frame(bt, &eip, &esp);

	/* skip idle task stack */
	if (bt->flags & BT_SKIP_IDLE)
		return;

	if (bt->flags & BT_KSTACKP) {
		bt->stkptr = esp;
		return;
	}

	if (ACTIVE() && !INSTACK(esp, bt)) {
		if (!LOCAL_ACTIVE()) {
			error(INFO, "task no longer exists\n");
			return;
		}
		sprintf(buf, "/proc/%ld", bt->tc->pid); 
		if (!file_exists(buf, NULL))
			error(INFO, "task no longer exists\n");
		else 
			error(INFO, 
			    "invalid/stale stack pointer for this task: %lx\n", 
				esp);
		return;
	}

	if (bt->flags & 
	    (BT_TEXT_SYMBOLS|BT_TEXT_SYMBOLS_PRINT|BT_TEXT_SYMBOLS_NOPRINT)) {

		if (bt->flags & BT_TEXT_SYMBOLS_ALL) {
			esp = bt->stackbase + 
				((tt->flags & THREAD_INFO) ?
				SIZE(thread_info) : SIZE(task_struct));
			eip = 0;
		}

		if (machdep->flags & MACHDEP_BT_TEXT) {
			bt->instptr = eip;
			bt->stkptr = esp;
			machdep->back_trace(bt);
		} else
			print_stack_text_syms(bt, esp, eip);

		if (bt->flags & (BT_HARDIRQ|BT_SOFTIRQ)) {
			struct bt_info btloc;
			struct stack_hook stack_hook;

			BZERO(&btloc, sizeof(struct bt_info));
			BZERO(&stack_hook, sizeof(struct stack_hook));
			btloc.flags = bt->flags & ~(BT_HARDIRQ|BT_SOFTIRQ);
			btloc.hp = &stack_hook;
			btloc.tc = bt->tc;
			btloc.task = bt->task;
			btloc.stackbase = GET_STACKBASE(bt->task);
			btloc.stacktop = GET_STACKTOP(bt->task);

        		switch (bt->flags & (BT_HARDIRQ|BT_SOFTIRQ))
        		{
        		case BT_HARDIRQ:
				if (kernel_symbol_exists("hardirq_stack") &&
				    STRUCT_EXISTS("irq_stack")) {
					btloc.hp->eip = symbol_value("handle_irq");
					btloc.hp->esp = ULONG(bt->stackbuf);
				} else {
					btloc.hp->eip = symbol_value("do_IRQ");
					if (symbol_exists("__do_IRQ"))
						btloc.hp->esp = ULONG(bt->stackbuf +
					    		OFFSET(thread_info_previous_esp));
					else
						btloc.hp->esp = ULONG(bt->stackbuf +
					    		SIZE(irq_ctx) - (sizeof(char *)*2));
				}
				fprintf(fp, "--- <hard IRQ> ---\n");
				if (in_irq_ctx(BT_SOFTIRQ, bt->tc->processor, btloc.hp->esp)) {
					btloc.flags |= BT_SOFTIRQ;
					btloc.stackbase = tt->softirq_ctx[bt->tc->processor];
					btloc.stacktop = btloc.stackbase + STACKSIZE();
				}
                		break;

        		case BT_SOFTIRQ:
				btloc.hp->eip = symbol_value("do_softirq");
				if (kernel_symbol_exists("softirq_stack") &&
				    STRUCT_EXISTS("irq_stack")) {
					if (kernel_symbol_exists("do_softirq_own_stack"))
						btloc.hp->eip = symbol_value("do_softirq_own_stack");
					btloc.hp->esp = ULONG(bt->stackbuf);
				} else
					btloc.hp->esp = ULONG(bt->stackbuf +
						OFFSET(thread_info_previous_esp));
				fprintf(fp, "--- <soft IRQ> ---\n");
                		break;
        		}

			back_trace(&btloc);
		}
		
		return;
	}

	bt->instptr = eip;
	bt->stkptr = esp;

complete_trace:

	if (BT_REFERENCE_CHECK(bt))
		BCOPY(bt, &btsave, sizeof(struct bt_info));

	if (CRASHDEBUG(4))
		dump_bt_info(bt, "back_trace");

	machdep->back_trace(bt);

	if ((bt->flags & (BT_HARDIRQ|BT_SOFTIRQ)) && restore_stack(bt))  
		goto complete_trace;

	if (BT_REFERENCE_FOUND(bt)) {
#ifdef XEN_HYPERVISOR_ARCH
		if (XEN_HYPER_MODE())
			xen_hyper_print_bt_header(fp, bt->task, 0);
		else
			print_task_header(fp, task_to_context(bt->task), 0);
#else
		print_task_header(fp, task_to_context(bt->task), 0);
#endif /* XEN_HYPERVISOR_ARCH */

		BCOPY(&btsave, bt, sizeof(struct bt_info));
		bt->ref = NULL;
		machdep->back_trace(bt);
		fprintf(fp, "\n");
	}
}

/*
 *  Restore a bt_info to make the jump from an IRQ stack to the task's
 *  normal stack.
 */
static int 
restore_stack(struct bt_info *bt)
{
	ulonglong type;
	struct syment *sp;
	ulong retvaddr;

	bt->instptr = bt->stkptr = 0;
	type = 0;

	switch (bt->flags & (BT_HARDIRQ|BT_SOFTIRQ)) 
	{ 
	case BT_HARDIRQ:
		if (kernel_symbol_exists("hardirq_stack") &&
		    STRUCT_EXISTS("irq_stack")) {
			bt->instptr = symbol_value("handle_irq");
			bt->stkptr = ULONG(bt->stackbuf);
		} else {
			retvaddr = ULONG(bt->stackbuf +
				SIZE(irq_ctx) - sizeof(char *));
			if ((sp = value_search(retvaddr, NULL)) && 
				STREQ(sp->name, "do_IRQ"))
				bt->instptr = retvaddr; 
			else
				bt->instptr = symbol_value("do_IRQ");
			if (symbol_exists("__do_IRQ"))
				bt->stkptr = ULONG(bt->stackbuf +
					OFFSET(thread_info_previous_esp));
			else
				bt->stkptr = ULONG(bt->stackbuf + 
					SIZE(irq_ctx) - (sizeof(char *)*2));
		}
		type = BT_HARDIRQ;
		break;

	case BT_SOFTIRQ:
		if (kernel_symbol_exists("softirq_stack") &&
		    STRUCT_EXISTS("irq_stack")) {
			if (kernel_symbol_exists("do_softirq_own_stack"))
				bt->instptr = symbol_value("do_softirq_own_stack");
			else
				bt->instptr = symbol_value("do_softirq");
			bt->stkptr = ULONG(bt->stackbuf);
		} else {
			retvaddr = ULONG(bt->stackbuf +
				SIZE(irq_ctx) - sizeof(char *));
			if ((sp = value_search(retvaddr, NULL)) && 
				STREQ(sp->name, "do_softirq"))
				bt->instptr = retvaddr; 
			else
				bt->instptr = symbol_value("do_softirq");
	               	bt->stkptr = ULONG(bt->stackbuf +
	                       	OFFSET(thread_info_previous_esp));
		}
		type = BT_SOFTIRQ;
		break;
	}

	if ((type == BT_HARDIRQ) && bt->instptr &&
	    in_irq_ctx(BT_SOFTIRQ, bt->tc->processor, bt->stkptr)) {
		bt->flags &= ~BT_HARDIRQ; 
		bt->flags |= BT_SOFTIRQ; 
                bt->stackbase = tt->softirq_ctx[bt->tc->processor];
                bt->stacktop = bt->stackbase + STACKSIZE();
		if (!readmem(bt->stackbase, KVADDR, bt->stackbuf,
		    bt->stacktop - bt->stackbase, 
		    "restore softirq_ctx stack", RETURN_ON_ERROR)) {
			error(INFO, 
			    "read of softirq stack at %lx failed\n", 
				bt->stackbase);
			type = 0;
		}
	} else {
		bt->flags &= ~(BT_HARDIRQ|BT_SOFTIRQ); 
		bt->stackbase = GET_STACKBASE(bt->tc->task);
	        bt->stacktop = GET_STACKTOP(bt->tc->task);
	
	        if (!readmem(bt->stackbase, KVADDR, bt->stackbuf,
	            bt->stacktop - bt->stackbase, 
		    "restore_stack contents", RETURN_ON_ERROR)) {
	        	error(INFO, "restore_stack of stack at %lx failed\n", 
				bt->stackbase);
			type = 0;
		}
	
		if (!(bt->instptr && INSTACK(bt->stkptr, bt)))
			type = 0;
	}

	if (type) {
		if (!BT_REFERENCE_CHECK(bt))
		fprintf(fp, "--- %s ---\n", type == BT_HARDIRQ ? 
			"<hard IRQ>" : "<soft IRQ>");
		return TRUE;
	}

	return FALSE;
}


#define MAXHOOKS (100)

struct stack_hook *
gather_text_list(struct bt_info *bt) 
{
	int cnt;
	struct bt_info btloc;
	char buf[BUFSIZE], *p1;
	struct stack_hook *hooks;
	ulong esp, eip;
	FILE *savedfp;

	BCOPY(bt, &btloc, sizeof(struct bt_info));
	hooks = (struct stack_hook *)GETBUF(sizeof(struct stack_hook)*MAXHOOKS);
	cnt = 0;

	savedfp = fp;
        open_tmpfile2();
	fp = pc->tmpfile2;
        btloc.flags = BT_TEXT_SYMBOLS_PRINT;
        back_trace(&btloc);
        rewind(pc->tmpfile2);
        while (fgets(buf, BUFSIZE, pc->tmpfile2)) {
		if ((p1 = strstr(buf, ":"))) {
			esp = eip = 0;
                	*p1 = NULLCHAR;
			if (((esp = htol(buf, RETURN_ON_ERROR, NULL)) != BADADDR)
			    && INSTACK(esp, bt))
                                eip = GET_STACK_ULONG(esp);
			if (esp && eip) {
				hooks[cnt].esp = esp;
				hooks[cnt].eip = eip;
				if (++cnt == MAXHOOKS)
					break;
			}
		}
	}
	close_tmpfile2();
	fp = savedfp;

	if (cnt)
		return (bt->textlist = hooks);
	else {
		FREEBUF(hooks);
		return (bt->textlist = NULL);
	}
}

/*
 *  Debug routine most likely useful from above in back_trace()
 */
void
dump_bt_info(struct bt_info *bt, char *where)
{
	fprintf(fp, "[%lx] %s:\n", (ulong)bt, where);
	fprintf(fp, "        task: %lx\n", bt->task);
	fprintf(fp, "       flags: %llx\n", bt->flags);
	fprintf(fp, "     instptr: %lx\n", bt->instptr);
	fprintf(fp, "      stkptr: %lx\n", bt->stkptr);
	fprintf(fp, "        bptr: %lx\n", bt->bptr);
	fprintf(fp, "   stackbase: %lx\n", bt->stackbase);
	fprintf(fp, "    stacktop: %lx\n", bt->stacktop);
	fprintf(fp, "          tc: %lx ", (ulong)bt->tc);
	if (bt->tc)
		fprintf(fp, "(%ld, %lx)\n", bt->tc->pid, bt->tc->task);
	else
		fprintf(fp, "(unknown context)\n");
	fprintf(fp, "          hp: %lx\n", (ulong)bt->hp);
	fprintf(fp, "         ref: %lx\n", (ulong)bt->ref);
	fprintf(fp, "    stackbuf: %lx\n", (ulong)bt->stackbuf);
	fprintf(fp, "    textlist: %lx\n", (ulong)bt->textlist);
	fprintf(fp, "    frameptr: %lx\n", (ulong)bt->frameptr);
	fprintf(fp, " call_target: %s\n", bt->call_target ? 
		bt->call_target : "none");
	fprintf(fp, "   eframe_ip: %lx\n", bt->eframe_ip);
	fprintf(fp, "       debug: %lx\n", bt->debug);
	fprintf(fp, "       radix: %ld\n", bt->radix);
	fprintf(fp, "     cpumask: %lx\n", (ulong)bt->cpumask);
}

/*
 *  LKCD doesn't save state of the active tasks in the TSS, so poke around 
 *  the raw stack for some reasonable hooks.
 */
static void
get_lkcd_regs(struct bt_info *bt, ulong *eip, ulong *esp)
{
	int i;
	char *sym;
	ulong *up;
	ulong sysrq_eip, sysrq_esp;

	if (!is_task_active(bt->task)) {
		machdep->get_stack_frame(bt, eip, esp);
		return;
	}

	/* try to get it from the header */
	if (get_lkcd_regs_for_cpu(bt, eip, esp) == 0)
		return;

	/* if that fails: do guessing */
	sysrq_eip = sysrq_esp = 0;

	for (i = 0, up = (ulong *)bt->stackbuf; i < LONGS_PER_STACK; i++, up++){
		sym = closest_symbol(*up);
		if (STREQ(sym, "dump_execute") && INSTACK(*(up-1), bt)) {
			*eip = *up;
			*esp = *(up-1);
			return;
		}
                /* Begin 3PAR change -- required for our panic path */
		if (STREQ(sym, "dump_ipi") && INSTACK(*(up-1), bt)) {
			*eip = *up;
			*esp = *(up-1);
			return;
		}
		/* End 3PAR change */
                if (STREQ(sym, "panic") && INSTACK(*(up-1), bt)) {
                        *eip = *up;
                        *esp = *(up-1);
                        return;
                }
		/* Egenera */
                if (STREQ(sym, "netdump_ipi")) {
                        *eip = *up;
                        *esp = bt->task + 
				((char *)(up-1) - bt->stackbuf);
                        return;
                }
		if (STREQ(sym, "dump_execute")) {
                        *eip = *up;
                        *esp = bt->stackbase + 
				((char *)(up) - bt->stackbuf);
                        return;
		}
		if (STREQ(sym, "vmdump_nmi_callback")) {
                        *eip = *up;
                        *esp = bt->stackbase + 
				((char *)(up) - bt->stackbuf);
                        return;
		}
                if (STREQ(sym, "smp_stop_cpu_interrupt")) {
                        *eip = *up;
                        *esp = bt->task + 
				((char *)(up-1) - bt->stackbuf);
                        return;
                }
                if (STREQ(sym, "stop_this_cpu")) {
                        *eip = *up;
                        *esp = bt->task + 
				((char *)(up-1) - bt->stackbuf);
                        return;
                }
                if (SYSRQ_TASK(bt->task) &&
		    STREQ(sym, "smp_call_function_interrupt")) {
                        sysrq_eip = *up;
                        sysrq_esp = bt->task +
                                ((char *)(up-1) - bt->stackbuf);
                }
	}

	if (sysrq_eip) {
        	*eip = sysrq_eip;
        	*esp = sysrq_esp;
		return;
	}

	machdep->get_stack_frame(bt, eip, esp);
}


/*
 *  Store the head of the kernel module list for future use.
 *  Count the number of symbols defined by all modules in the system,
 *  and pass it on to store_module_symbols() to deal with.
 */
void
module_init(void)
{
	int i, c;
        ulong size, mod, mod_next;
	uint nsyms;
	ulong total, numksyms;
        char *modbuf, *kallsymsbuf;
	ulong kallsyms_header;
	struct syment *sp, *sp_array[10];
	struct kernel_list_head list;
	int modules_found;

	if (kernel_symbol_exists("module_list")) 
		kt->flags |= KMOD_V1;
	else if (kernel_symbol_exists("modules"))
		kt->flags |= KMOD_V2;
	else 
		error(WARNING, "cannot determine how modules are linked\n");

        if (kt->flags & NO_MODULE_ACCESS || !(kt->flags & (KMOD_V1|KMOD_V2))) {
                error(WARNING, "no kernel module access\n\n");
                kt->module_list = 0;
                kt->mods_installed = 0;
                return;
        }

	STRUCT_SIZE_INIT(module, "module");
        MEMBER_OFFSET_INIT(module_name, "module", "name");
        MEMBER_OFFSET_INIT(module_syms, "module", "syms");
	mod_next = nsyms = 0;

	switch (kt->flags & (KMOD_V1|KMOD_V2))
	{
	case KMOD_V1:
        	MEMBER_OFFSET_INIT(module_size_of_struct, "module", 
			"size_of_struct");
        	MEMBER_OFFSET_INIT(module_next, "module", "next");
        	MEMBER_OFFSET_INIT(module_nsyms, "module", "nsyms");
        	MEMBER_OFFSET_INIT(module_size, "module", "size");
        	MEMBER_OFFSET_INIT(module_flags, "module", "flags");

        	get_symbol_data("module_list", sizeof(ulong), &kt->module_list);
        	kt->kernel_module = symbol_value("kernel_module");
		break;	

	case KMOD_V2: 
		MEMBER_OFFSET_INIT(module_num_syms, "module", "num_syms");
		MEMBER_OFFSET_INIT(module_list, "module", "list");
        	MEMBER_OFFSET_INIT(module_gpl_syms, "module", "gpl_syms");
        	MEMBER_OFFSET_INIT(module_num_gpl_syms, "module", 
			"num_gpl_syms");

		if (MEMBER_EXISTS("module", "mem")) {	/* 6.4 and later */
			kt->flags2 |= KMOD_MEMORY;	/* MODULE_MEMORY() can be used. */

			MEMBER_OFFSET_INIT(module_mem, "module", "mem");
			MEMBER_OFFSET_INIT(module_memory_base, "module_memory", "base");
			MEMBER_OFFSET_INIT(module_memory_size, "module_memory", "size");
			STRUCT_SIZE_INIT(module_memory, "module_memory");

			if (CRASHDEBUG(1))
				error(INFO, "struct module_memory detected.\n");

			if (get_array_length("module.mem", NULL, 0) != MOD_MEM_NUM_TYPES)
				error(WARNING, "module memory types have changed!\n");

		} else if (MEMBER_EXISTS("module", "module_core")) {
			MEMBER_OFFSET_INIT(module_core_size, "module",
					   "core_size");
			MEMBER_OFFSET_INIT(module_init_size, "module",
					   "init_size");

			MEMBER_OFFSET_INIT(module_core_text_size, "module",
					   "core_text_size");
			MEMBER_OFFSET_INIT(module_init_text_size, "module",
					   "init_text_size");

			MEMBER_OFFSET_INIT(module_module_core, "module",
					   "module_core");
			MEMBER_OFFSET_INIT(module_module_init, "module",
					   "module_init");
		} else if (MEMBER_EXISTS("module", "module_core_rx")) {
			if (CRASHDEBUG(1))
				error(INFO, "PaX module layout detected.\n");
			kt->flags2 |= KMOD_PAX;

			MEMBER_OFFSET_INIT(module_core_size_rw, "module",
					   "core_size_rw");
			MEMBER_OFFSET_INIT(module_core_size_rx, "module",
					   "core_size_rx");

			MEMBER_OFFSET_INIT(module_init_size_rw, "module",
					   "init_size_rw");
			MEMBER_OFFSET_INIT(module_init_size_rx, "module",
					   "init_size_rx");

			MEMBER_OFFSET_INIT(module_module_core_rw, "module",
					   "module_core_rw");
			MEMBER_OFFSET_INIT(module_module_core_rx, "module",
					   "module_core_rx");

			MEMBER_OFFSET_INIT(module_module_init_rw, "module",
					   "module_init_rw");
			MEMBER_OFFSET_INIT(module_module_init_rx, "module",
					   "module_init_rx");
		} else if (MEMBER_EXISTS("module_layout", "base_rx")) {
			if (CRASHDEBUG(1))
				error(INFO, "PaX module layout detected.\n");
			kt->flags2 |= KMOD_PAX;

			ASSIGN_OFFSET(module_core_size_rw) =
				MEMBER_OFFSET("module", "core_layout") +
				MEMBER_OFFSET("module_layout", "size_rw");
			ASSIGN_OFFSET(module_core_size_rx) =
				MEMBER_OFFSET("module", "core_layout") +
				MEMBER_OFFSET("module_layout", "size_rx");

			ASSIGN_OFFSET(module_init_size_rw) =
				MEMBER_OFFSET("module", "init_layout") +
				MEMBER_OFFSET("module_layout", "size_rw");
			ASSIGN_OFFSET(module_init_size_rx) =
				MEMBER_OFFSET("module", "init_layout") +
				MEMBER_OFFSET("module_layout", "size_rx");

			ASSIGN_OFFSET(module_module_core_rw) =
				MEMBER_OFFSET("module", "core_layout") +
				MEMBER_OFFSET("module_layout", "base_rw");
			ASSIGN_OFFSET(module_module_core_rx) =
				MEMBER_OFFSET("module", "core_layout") +
				MEMBER_OFFSET("module_layout", "base_rx");

			ASSIGN_OFFSET(module_module_init_rw) =
				MEMBER_OFFSET("module", "init_layout") +
				MEMBER_OFFSET("module_layout", "base_rw");
			ASSIGN_OFFSET(module_module_init_rx) =
				MEMBER_OFFSET("module", "init_layout") +
				MEMBER_OFFSET("module_layout", "base_rx");
		} else {
			ASSIGN_OFFSET(module_core_size) =
				MEMBER_OFFSET("module", "core_layout") +
				MEMBER_OFFSET("module_layout", "size");
			ASSIGN_OFFSET(module_init_size) =
				MEMBER_OFFSET("module", "init_layout") +
				MEMBER_OFFSET("module_layout", "size");

			ASSIGN_OFFSET(module_core_text_size) =
				MEMBER_OFFSET("module", "core_layout") +
				MEMBER_OFFSET("module_layout", "text_size");
			ASSIGN_OFFSET(module_init_text_size) =
				MEMBER_OFFSET("module", "init_layout") +
				MEMBER_OFFSET("module_layout", "text_size");

			ASSIGN_OFFSET(module_module_core) =
				MEMBER_OFFSET("module", "core_layout") +
				MEMBER_OFFSET("module_layout", "base");
			ASSIGN_OFFSET(module_module_init) =
				MEMBER_OFFSET("module", "init_layout") +
				MEMBER_OFFSET("module_layout", "base");
		}

		MEMBER_OFFSET_INIT(module_percpu, "module", "percpu");

		/*
		 *  Make sure to pick the kernel "modules" list_head symbol,
		 *  not to be confused with the ia64/sn "modules[]" array.
		 *  The kernel modules list_head will either point to itself
		 *  (empty) or contain vmalloc'd module addresses; the ia64/sn
		 *  modules array contains a list of kmalloc'd addresses.
		 */
        	if ((c = get_syment_array("modules", sp_array, 10)) > 1) {
			modules_found = FALSE;
			for (i = 0; i < c; i++) {
				sp = sp_array[i];

				if (!readmem(sp->value, KVADDR, 
				    &list, sizeof(struct kernel_list_head), 
				    "modules list_head test", 
				    RETURN_ON_ERROR|QUIET)) 
					continue;

				if ((ulong)list.next == symbol_value("modules")) {
                			kt->mods_installed = 0;
					return;
				}

				if (IS_VMALLOC_ADDR((ulong)list.next) &&
				    IS_VMALLOC_ADDR((ulong)list.prev)) {
					kt->kernel_module = sp->value;
					kt->module_list = (ulong)list.next;
					modules_found = TRUE;
					break;
				}
			} 

			if (!modules_found) {
                        	error(WARNING,
          "cannot determine which of %d \"modules\" symbols is appropriate\n\n",
					c);
                       		kt->mods_installed = 0;
                        	kt->flags |= NO_MODULE_ACCESS;
				return;
			}
		} else {
        		get_symbol_data("modules", sizeof(ulong), 
				&kt->module_list);
			if (kt->module_list == symbol_value("modules")) {
                		kt->mods_installed = 0;
				return;
			}
        		kt->kernel_module = symbol_value("modules");
		}
		kt->module_list -= OFFSET(module_list);
		break;
	}

	total = kt->mods_installed = 0;

        modbuf = GETBUF(SIZE(module));
	kallsymsbuf = kt->flags & KALLSYMS_V1 ?
		GETBUF(SIZE(kallsyms_header)) : NULL;

	please_wait("gathering module symbol data");

        for (mod = kt->module_list; mod != kt->kernel_module; mod = mod_next) {
		if (CRASHDEBUG(3))
			fprintf(fp, "module: %lx\n", mod);

                if (!readmem(mod, KVADDR, modbuf, SIZE(module), 
		    "module struct", RETURN_ON_ERROR|QUIET)) {
                        error(WARNING,
                            "%scannot access vmalloc'd module memory\n\n",
				DUMPFILE() ? "\n" : "");
                        kt->mods_installed = 0;
                        kt->flags |= NO_MODULE_ACCESS;
                        FREEBUF(modbuf); 
			return;
		}

		switch (kt->flags & (KMOD_V1|KMOD_V2))
		{
		case KMOD_V1:
                	nsyms = UINT(modbuf + OFFSET(module_nsyms));
			break;
		case KMOD_V2: 
                	nsyms = UINT(modbuf + OFFSET(module_num_syms)) +
				UINT(modbuf + OFFSET(module_num_gpl_syms));
			break;
		}

		total += nsyms;
		total += 2;  /* store the module's start/ending addresses */
		total += 2;  /* and the init start/ending addresses */
		if (MODULE_MEMORY()) /* 7 regions at most -> 14, so needs +10 */
			total += 10;

		/*
		 *  If the module has kallsyms, set up to grab them as well.
		 */
		switch (kt->flags & (KALLSYMS_V1|KALLSYMS_V2))
		{
		case KALLSYMS_V1: 
			kallsyms_header = ULONG(modbuf +
				OFFSET(module_kallsyms_start));	
			if (kallsyms_header) {
	                	if (!readmem(kallsyms_header, KVADDR, 
				    kallsymsbuf, SIZE(kallsyms_header), 
				    "kallsyms_header", RETURN_ON_ERROR|QUIET)) {
	                        	error(WARNING,
                                      "%scannot access module kallsyms_header\n",
					    DUMPFILE() ? "\n" : "");
				} else {
					nsyms = UINT(kallsymsbuf +
				 	    OFFSET(kallsyms_header_symbols));
					total += nsyms; 
				}
			}
			break;

		case KALLSYMS_V2:
			if (THIS_KERNEL_VERSION >= LINUX(2,6,27)) {
				numksyms = UINT(modbuf + OFFSET(module_num_symtab));
				if (MODULE_MEMORY())
					/* check mem[MOD_TEXT].size only */
					size = UINT(modbuf + OFFSET(module_mem) + OFFSET(module_memory_size));
				else
					size = UINT(modbuf + MODULE_OFFSET2(module_core_size, rx));
			} else {
				numksyms = ULONG(modbuf + OFFSET(module_num_symtab));
				size = ULONG(modbuf + MODULE_OFFSET2(module_core_size, rx));
			}

			if (!size) {
				/*
				 *  Bail out here instead of a crashing with a 
				 *  getbuf(0) failure during storage later on.
				 */
				error(WARNING, 
				    "invalid kernel module size: 0\n");
					kt->mods_installed = 0;
					kt->flags |= NO_MODULE_ACCESS;
				FREEBUF(modbuf); 
				return;
			}

			total += numksyms; 
			break;
		}

		kt->mods_installed++;

		NEXT_MODULE(mod_next, modbuf);
	}

        FREEBUF(modbuf);
	if (kallsymsbuf)
		FREEBUF(kallsymsbuf);

	switch (kt->flags & (KMOD_V1|KMOD_V2))
	{
	case KMOD_V1:
		store_module_symbols_v1(total, kt->mods_installed);
		break;
	case KMOD_V2:
		if (MODULE_MEMORY())
			store_module_symbols_6_4(total, kt->mods_installed);
		else
			store_module_symbols_v2(total, kt->mods_installed);
		break;
	}

	please_wait_done();
}


/*
 *  Verify that the current set of modules jives with what's stored.
 */
static int
verify_modules(void)
{
	int i, t;
	int found, irregularities;
        ulong mod, mod_next, mod_base;
	long mod_size;
        char *modbuf, *module_name;
	ulong module_list, mod_name; 
	physaddr_t paddr;
	int mods_installed;
	struct load_module *lm;
	char buf[BUFSIZE];

	if (DUMPFILE() || !kt->module_list || (kt->flags & NO_MODULE_ACCESS))
		return TRUE;

	switch (kt->flags & (KMOD_V1|KMOD_V2))
	{
	case KMOD_V1:
        	get_symbol_data("module_list", sizeof(ulong), &module_list);
		break;
	case KMOD_V2:
                if (kt->module_list == symbol_value("modules")) {
			if (!kt->mods_installed)
				return TRUE;
                }
                get_symbol_data("modules", sizeof(ulong), &module_list);
                module_list -= OFFSET(module_list);
		break;
	}

	mods_installed = irregularities = 0;
	mod_base = mod_next = 0;
        modbuf = GETBUF(SIZE(module));

        for (mod = module_list; mod != kt->kernel_module; mod = mod_next) {

                if (!readmem(mod, KVADDR, modbuf, SIZE(module), 
		    "module struct", RETURN_ON_ERROR|QUIET)) {
                        error(WARNING,
                            "cannot access vmalloc'd module memory\n");
                        FREEBUF(modbuf);
                        return FALSE;
		}


                for (i = 0, found = FALSE; i < kt->mods_installed; i++) {
                        lm = &st->load_modules[i];
			if (!kvtop(NULL, lm->mod_base, &paddr, 0)) {
				irregularities++;
                                break;
			}

			switch (kt->flags & (KMOD_V1|KMOD_V2))
			{
			case KMOD_V1:
				mod_base = mod;
				break;
			case KMOD_V2:
				if (MODULE_MEMORY())
					/* mem[MOD_TEXT].base */
					mod_base = ULONG(modbuf + OFFSET(module_mem) +
							OFFSET(module_memory_base));
				else
					mod_base = ULONG(modbuf +
						MODULE_OFFSET2(module_module_core, rx));
				break;
			}

			if (lm->mod_base == mod_base) {
				switch (kt->flags & (KMOD_V1|KMOD_V2))
				{
				case KMOD_V1:
        				mod_name = ULONG(modbuf + 
						OFFSET(module_name));
					mod_size = LONG(modbuf + 
						OFFSET(module_size));
                			if (!read_string(mod_name, buf, 
					    BUFSIZE-1) || !STREQ(lm->mod_name, 
					    buf) || (mod_size != lm->mod_size)){
						irregularities++;
						goto irregularity;
					}
					break;
				case KMOD_V2:
        				module_name = modbuf + 
						OFFSET(module_name);
					if (MODULE_MEMORY()) {
						mod_size = 0;
						for_each_mod_mem_type(t) {
							if (t == MOD_INIT_TEXT)
								break;

							mod_size += UINT(modbuf + OFFSET(module_mem) +
									SIZE(module_memory) * t +
									OFFSET(module_memory_size));
						}
					} else if (THIS_KERNEL_VERSION >= LINUX(2,6,27))
						mod_size = UINT(modbuf +
							MODULE_OFFSET2(module_core_size, rx));
					else
						mod_size = ULONG(modbuf +
							MODULE_OFFSET2(module_core_size, rx));
                			if (strlen(module_name) < MAX_MOD_NAME)
                        			strcpy(buf, module_name);
                			else 
                        			strncpy(buf, module_name, 
							MAX_MOD_NAME-1);
					if (!STREQ(lm->mod_name, buf) ||
					    (mod_size != lm->mod_size)) {
						irregularities++;
						goto irregularity;
					}
					break;
				}
				found = TRUE;
irregularity:
				break;
			}
		}

		if (!found || irregularities) 
			return FALSE;

		mods_installed++;

		NEXT_MODULE(mod_next, modbuf);
	}

        FREEBUF(modbuf);

	if (mods_installed != kt->mods_installed) 
		return FALSE;

	return TRUE;
}


/*
 *  With no arguments, just dump basic data concerning each of the 
 *  currently-loaded modules.  The -s and -S arguments dynamically
 *  loads module symbols from its object file.
 */
#define LIST_MODULE_HDR               (0)
#define LIST_MODULE                   (1)
#define LOAD_ALL_MODULE_SYMBOLS       (2)
#define LOAD_SPECIFIED_MODULE_SYMBOLS (3)
#define DELETE_MODULE_SYMBOLS         (4)
#define DELETE_ALL_MODULE_SYMBOLS     (5)
#define REMOTE_MODULE_SAVE_MSG        (6)
#define REINIT_MODULES                (7)
#define LIST_ALL_MODULE_TAINT         (8)

void
cmd_mod(void)
{
	int c, ctmp;
	char *p, *objfile, *modref, *tree, *symlink;
	ulong flag, address;
	char buf[BUFSIZE];

	if (kt->flags & NO_MODULE_ACCESS)
		error(FATAL, "cannot access vmalloc'd module memory\n");

	if (!verify_modules()) {
 	 	error(NOTE, 
	             "modules have changed on this system -- reinitializing\n");
		reinit_modules();
	}

	if (!kt->mods_installed) {
		fprintf(fp, "no modules installed\n");
		return;
	}

	for (c = 1, p = NULL; c < argcnt; c++) {
		if (args[c][0] != '-')
			continue;

		if (STREQ(args[c], "-g")) {
			ctmp = c;
			pc->curcmd_flags |= MOD_SECTIONS;
			while (ctmp < argcnt) {
				args[ctmp] = args[ctmp+1];
				ctmp++;
			}
			argcnt--;
			c--;
		} else if (STREQ(args[c], "-r")) {
			ctmp = c;
			pc->curcmd_flags |= MOD_READNOW;
			while (ctmp < argcnt) {
				args[ctmp] = args[ctmp+1];
				ctmp++;
			}
			argcnt--;
			c--;
		} else {
			if ((p = strstr(args[c], "g"))) {
				pc->curcmd_flags |= MOD_SECTIONS;
				shift_string_left(p, 1);
			} 
			if ((p = strstr(args[c], "r"))) {
				pc->curcmd_flags |= MOD_READNOW;
				shift_string_left(p, 1);
			}
			/* if I've removed everything but the '-', toss it */
			if (STREQ(args[c], "-")) {
				ctmp = c;
				while (ctmp < argcnt) {
					args[ctmp] = args[ctmp+1];
					ctmp++;
				}
				argcnt--;
				c--;
			}
		}
	}

	if (pc->flags & READNOW)
		pc->curcmd_flags |= MOD_READNOW;

	modref = objfile = tree = symlink = NULL;
	address = 0;
	flag = LIST_MODULE_HDR;

        while ((c = getopt(argcnt, args, "Rd:Ds:Sot")) != EOF) {
                switch(c)
		{
                case 'R':
                        if (flag)
                                cmd_usage(pc->curcmd, SYNOPSIS);
                        flag = REINIT_MODULES;
                        break;

		case 'D':
			if (flag) 
				cmd_usage(pc->curcmd, SYNOPSIS);
			flag = DELETE_ALL_MODULE_SYMBOLS;
			break;

		case 'd':
                        if (flag)
                                cmd_usage(pc->curcmd, SYNOPSIS);
                        else
                                flag = DELETE_MODULE_SYMBOLS;

                        if (hexadecimal(optarg, 0) &&
                            (strlen(optarg) == VADDR_PRLEN)) {
                                address = htol(optarg, FAULT_ON_ERROR, NULL);
                                if (!is_module_address(address, buf))
                                        cmd_usage(pc->curcmd, SYNOPSIS);
				modref = buf;
                        } else if (is_module_name(optarg, &address, NULL))
                                modref = optarg;
                        else
                                cmd_usage(pc->curcmd, SYNOPSIS);
                        break;

                /*
                 *  Revert to using old-style add-symbol-file command
		 *  for KMOD_V2 kernels.
                 */
                case 'o':
			if (flag) 
				cmd_usage(pc->curcmd, SYNOPSIS);
			if (kt->flags & KMOD_V1)
				error(INFO, 
				    "-o option is not applicable to this kernel version\n");
                        st->flags |= USE_OLD_ADD_SYM;
			return;

		case 'S':
			if (flag) 
				cmd_usage(pc->curcmd, SYNOPSIS);
			else
				flag = LOAD_ALL_MODULE_SYMBOLS; 
			break;

		case 's':
                        if (flag)
				cmd_usage(pc->curcmd, SYNOPSIS);
			else
				flag = LOAD_SPECIFIED_MODULE_SYMBOLS;

			if (hexadecimal(optarg, 0) && 
			    (strlen(optarg) == VADDR_PRLEN)) {
				address = htol(optarg, FAULT_ON_ERROR, NULL);
				if (!is_module_address(address, buf))
					cmd_usage(pc->curcmd, SYNOPSIS);
				modref = buf;
			} else if (is_module_name(optarg, &address, NULL))
				modref = optarg;
			else
				cmd_usage(pc->curcmd, SYNOPSIS);
			break;

		case 't':
                        if (flag)
				cmd_usage(pc->curcmd, SYNOPSIS);
			else
				flag = LIST_ALL_MODULE_TAINT;
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (tree && (flag != LOAD_ALL_MODULE_SYMBOLS))
		argerrs++;

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (NO_MODULES()) {
                error(INFO, "no modules loaded in this kernel\n");
		if (flag != LIST_MODULE_HDR)
                	cmd_usage(pc->curcmd, SYNOPSIS);
		return;
	}

	switch (flag)
	{
	case LOAD_ALL_MODULE_SYMBOLS:
		switch (argcnt) 
		{
		case 3:
			if (is_directory(args[2]))
				tree = args[2];
			else {
                		error(INFO, "%s is not a directory\n", args[2]);
				cmd_usage(pc->curcmd, SYNOPSIS);
			}
			break;

		case 2:
			break;

		default:
			cmd_usage(pc->curcmd, SYNOPSIS);
		}
		break;

	case LOAD_SPECIFIED_MODULE_SYMBOLS:
		switch (argcnt)
		{
		case 4:
			objfile = args[3];
			if (!file_exists(objfile, NULL)) { 
				if (!(objfile = 
				    find_module_objfile(modref, objfile, tree)))
					error(FATAL, 
				    "%s: cannot find or load object file: %s\n",
						modref, args[3]);
			} 
			break;

		case 3:
                        if (!(objfile = find_module_objfile(modref,NULL,tree)))
                        	error(FATAL, 
                              "cannot find or load object file for %s module\n",
					modref);
			break;

		default:
			cmd_usage(pc->curcmd, SYNOPSIS);
		}

                if (!is_elf_file(objfile)) {
                        error(INFO, "%s: not an ELF format object file\n", 
				objfile);
                        cmd_usage(pc->curcmd, SYNOPSIS);
                }

		break;

	default:
		break;
	}

	if ((flag == LOAD_ALL_MODULE_SYMBOLS) &&
	    (tree || kt->module_tree)) {
		if (!tree)
			tree = kt->module_tree;
	}

	do_module_cmd(flag, modref, address, objfile, tree);

	if (symlink)
		FREEBUF(symlink);
}

int
check_specified_module_tree(char *module, char *gdb_buffer)
{
	char *p1, *treebuf;
	int retval;

	retval = FALSE;

	/*
	 *  Search for "/lib/modules" in the module name string
	 *  and insert "/usr/lib/debug" there.
	 */
	if (strstr(module, "/lib/modules")) {
		treebuf = GETBUF(strlen(module) + strlen("/usr/lib/debug") +
                        strlen(".debug") + 1);
		strcpy(treebuf, module);
		p1 = strstr(treebuf, "/lib/modules");
		shift_string_right(p1, strlen("/usr/lib/debug"));
		BCOPY("/usr/lib/debug", p1, strlen("/usr/lib/debug"));
		strcat(treebuf, ".debug");
		if (file_exists(treebuf, NULL)) {
			strcpy(gdb_buffer, treebuf);
			retval = TRUE;
		}
		FREEBUF(treebuf);
	}

	return retval;
}

static void
show_module_taint_4_10(void)
{
	int i, j, bx;
	struct load_module *lm;
	int maxnamelen;
	int found;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	struct syment *sp;
	ulong *taintsp, taints;
	bool tnt_mod;
	char tnt_true;
	int tnts_len;
	ulong tnts_addr;
	char *modbuf;

	if (INVALID_MEMBER(module_taints)) {
		MEMBER_OFFSET_INIT(module_taints, "module", "taints");
		STRUCT_SIZE_INIT(taint_flag, "taint_flag");
		MEMBER_OFFSET_INIT(tnt_true, "taint_flag", "true");
		if (INVALID_MEMBER(tnt_true))
			MEMBER_OFFSET_INIT(tnt_true, "taint_flag", "c_true");
		MEMBER_OFFSET_INIT(tnt_mod, "taint_flag", "module");
	}

	modbuf = GETBUF(SIZE(module));

	for (i = found = maxnamelen = 0; i < kt->mods_installed; i++) {
		lm = &st->load_modules[i];

		readmem(lm->module_struct, KVADDR, modbuf, SIZE(module),
			"module struct", FAULT_ON_ERROR);

		if (MEMBER_SIZE("module", "taints") == sizeof(ulong))
			taints = ULONG(modbuf + OFFSET(module_taints));
		else
			taints = UINT(modbuf + OFFSET(module_taints));

		if (taints) {
			found++;
			maxnamelen = strlen(lm->mod_name) > maxnamelen ?
				strlen(lm->mod_name) : maxnamelen;
		}
	}

	if (!found) {
		fprintf(fp, "no tainted modules\n");
		FREEBUF(modbuf);
		return;
	}

	tnts_len = get_array_length("taint_flags", NULL, 0);
	sp = symbol_search("taint_flags");
	tnts_addr = sp->value;

	fprintf(fp, "%s  %s\n",
			mkstring(buf2, maxnamelen, LJUST, "NAME"), "TAINTS");

	for (i = 0; i < st->mods_installed; i++) {

		lm = &st->load_modules[i];
		bx = 0;
		buf1[0] = '\0';

		readmem(lm->module_struct, KVADDR, modbuf, SIZE(module),
				"module struct", FAULT_ON_ERROR);

		if (MEMBER_SIZE("module", "taints") == sizeof(ulong))
			taints = ULONG(modbuf + OFFSET(module_taints));
		else
			taints = UINT(modbuf + OFFSET(module_taints));

		if (!taints)
			continue;
		taintsp = &taints;

		for (j = 0; j < tnts_len; j++) {
			readmem((tnts_addr + j * SIZE(taint_flag)) +
					OFFSET(tnt_mod),
					KVADDR, &tnt_mod, sizeof(bool),
					"tnt mod", FAULT_ON_ERROR);
			if (!tnt_mod)
				continue;
			if (NUM_IN_BITMAP(taintsp, j)) {
				readmem((tnts_addr + j * SIZE(taint_flag)) +
						OFFSET(tnt_true),
						KVADDR, &tnt_true, sizeof(char),
						"tnt true", FAULT_ON_ERROR);
				buf1[bx++] = tnt_true;
			}
		}

		buf1[bx++] = '\0';

		fprintf(fp, "%s  %s\n", mkstring(buf2, maxnamelen,
					LJUST, lm->mod_name), buf1);
	}

	FREEBUF(modbuf);
}

static void
show_module_taint(void)
{
	int i, j, bx;
	struct load_module *lm;
	int maxnamelen;
	int found;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	int gpgsig_ok, license_gplok;
	struct syment *sp;
	uint *taintsp, taints;
	uint8_t tnt_bit;
	char tnt_true, tnt_false;
	int tnts_exists, tnts_len;
	ulong tnts_addr;
	char *modbuf;

	if (VALID_STRUCT(taint_flag) ||
	    (kernel_symbol_exists("taint_flags") && STRUCT_EXISTS("taint_flag"))) {
		show_module_taint_4_10();
		return;
	}

	if (INVALID_MEMBER(module_taints) &&
	    INVALID_MEMBER(module_license_gplok)) {
		MEMBER_OFFSET_INIT(module_taints, "module", "taints");
		MEMBER_OFFSET_INIT(module_license_gplok, 
			"module", "license_gplok");
		MEMBER_OFFSET_INIT(module_gpgsig_ok, "module", "gpgsig_ok");
		STRUCT_SIZE_INIT(tnt, "tnt");
		MEMBER_OFFSET_INIT(tnt_bit, "tnt", "bit");
		MEMBER_OFFSET_INIT(tnt_true, "tnt", "true");
		MEMBER_OFFSET_INIT(tnt_false, "tnt", "false");
	}

	if (INVALID_MEMBER(module_taints) &&
	    INVALID_MEMBER(module_license_gplok))
		option_not_supported('t');

	modbuf = GETBUF(SIZE(module));

	for (i = found = maxnamelen = 0; i < kt->mods_installed; i++) {
		lm = &st->load_modules[i];

		readmem(lm->module_struct, KVADDR, modbuf, SIZE(module),
			"module struct", FAULT_ON_ERROR);

		taints = VALID_MEMBER(module_taints) ?
			UINT(modbuf + OFFSET(module_taints)) : 0;
		license_gplok = VALID_MEMBER(module_license_gplok) ? 
			INT(modbuf + OFFSET(module_license_gplok)) : 0;
		gpgsig_ok = VALID_MEMBER(module_gpgsig_ok) ?
			INT(modbuf + OFFSET(module_gpgsig_ok)) : 1;

		if (VALID_MEMBER(module_license_gplok) || taints || !gpgsig_ok) {
			found++;
			maxnamelen = strlen(lm->mod_name) > maxnamelen ?
				strlen(lm->mod_name) : maxnamelen;
		}
			
	}

	if (!found) {
		fprintf(fp, "no tainted modules\n");
		FREEBUF(modbuf);
		return;
	}

	if (VALID_STRUCT(tnt) && (sp = symbol_search("tnts"))) {
		tnts_exists = TRUE;
		tnts_len = get_array_length("tnts", NULL, 0);
		tnts_addr = sp->value;
	} else {
		tnts_exists = FALSE;
		tnts_len = 0;
		tnts_addr = 0;
	}

	fprintf(fp, "%s  %s\n",
		mkstring(buf2, maxnamelen, LJUST, "NAME"),
		VALID_MEMBER(module_taints) ? "TAINTS" : "LICENSE_GPLOK");

	for (i = 0; i < st->mods_installed; i++) {

		lm = &st->load_modules[i];
		bx = 0;
		buf1[0] = '\0';

		readmem(lm->module_struct, KVADDR, modbuf, SIZE(module),
			"module struct", FAULT_ON_ERROR);

		taints = VALID_MEMBER(module_taints) ?
			UINT(modbuf + OFFSET(module_taints)) : 0;
		license_gplok = VALID_MEMBER(module_license_gplok) ? 
			INT(modbuf + OFFSET(module_license_gplok)) : 0;
		gpgsig_ok = VALID_MEMBER(module_gpgsig_ok) ?
			INT(modbuf + OFFSET(module_gpgsig_ok)) : 1;

		if (INVALID_MEMBER(module_license_gplok)) {
			if (!taints && gpgsig_ok)
				continue;
		}

		if (tnts_exists && taints) {
			taintsp = &taints;
			for (j = 0; j < (tnts_len * SIZE(tnt)); j += SIZE(tnt)) {
				readmem((tnts_addr + j) + OFFSET(tnt_bit),
					KVADDR, &tnt_bit, sizeof(uint8_t), 
					"tnt bit", FAULT_ON_ERROR);

				if (NUM_IN_BITMAP(taintsp, tnt_bit)) {
					readmem((tnts_addr + j) + OFFSET(tnt_true),
						KVADDR, &tnt_true, sizeof(char), 
						"tnt true", FAULT_ON_ERROR);
					buf1[bx++] = tnt_true;
				} else {
					readmem((tnts_addr + j) + OFFSET(tnt_false),
						KVADDR, &tnt_false, sizeof(char), 
						"tnt false", FAULT_ON_ERROR);
					if (tnt_false != ' ' && tnt_false != '-' &&
					    tnt_false != 'G')
						buf1[bx++] = tnt_false;
				}

			}
		}

		if (VALID_MEMBER(module_gpgsig_ok) && !gpgsig_ok) {
			buf1[bx++] = '(';
			buf1[bx++] = 'U';
			buf1[bx++] = ')';
		}

		buf1[bx++] = '\0';

		if (tnts_exists)
			fprintf(fp, "%s  %s\n", mkstring(buf2, maxnamelen,
				LJUST, lm->mod_name), buf1);
		else
			fprintf(fp, "%s  %x%s\n", mkstring(buf2, maxnamelen,
				LJUST, lm->mod_name), 
				VALID_MEMBER(module_taints) ? 
				taints : license_gplok, buf1);
	}

	FREEBUF(modbuf);
}

/*
 *  Do the simple list work for cmd_mod().
 */

static void
do_module_cmd(ulong flag, char *modref, ulong address, 
	char *objfile, char *tree)
{
	int i, j;
	struct load_module *lm, *lmp;
	int maxnamelen;
	int maxsizelen;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];

	if (NO_MODULES())
		return;

	switch (flag)
	{
	case LIST_MODULE:
	case LIST_MODULE_HDR:
	 	maxnamelen = maxsizelen = 0;
		
		for (i = 0; i < kt->mods_installed; i++) {
			lm = &st->load_modules[i];
			maxnamelen = strlen(lm->mod_name) > maxnamelen ? 
				strlen(lm->mod_name) : maxnamelen;
	
	                sprintf(buf1, "%ld", lm->mod_size);
			maxsizelen = strlen(buf1) > maxsizelen ? 
				strlen(buf1) : maxsizelen;
	        }
	
		if (flag == LIST_MODULE_HDR) {
			fprintf(fp, "%s  %s  %s  %s  OBJECT FILE\n",
				mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, 
				"MODULE"),
				mkstring(buf2, maxnamelen, LJUST, "NAME"),
				mkstring(buf4, VADDR_PRLEN, CENTER|LJUST,
				MODULE_MEMORY() ? "TEXT_BASE" : "BASE"),
				mkstring(buf3, maxsizelen, RJUST, "SIZE"));
		}
	
		for (i = 0; i < kt->mods_installed; i++) {
			lm = &st->load_modules[i];
			if (!address || (lm->module_struct == address) ||
			    (lm->mod_base == address)) {
				fprintf(fp, "%s  ", mkstring(buf1, VADDR_PRLEN,
				    LONG_HEX|RJUST, MKSTR(lm->module_struct)));
				fprintf(fp, "%s  ", mkstring(buf2, maxnamelen, 
					LJUST, lm->mod_name));
				fprintf(fp, "%s  ", mkstring(buf4, VADDR_PRLEN,
				    LONG_HEX|RJUST, MKSTR(lm->mod_base)));
				fprintf(fp, "%s  ", mkstring(buf3, maxsizelen,
					RJUST|LONG_DEC, MKSTR(lm->mod_size)));
				// fprintf(fp, "%6ld  ", lm->mod_size);
		
				if (strlen(lm->mod_namelist))
					fprintf(fp, "%s %s", 
						lm->mod_namelist,
						lm->mod_flags & MOD_REMOTE ?
						" (temporary)" : "");  
				else {
					fprintf(fp, "(not loaded)");
					if (lm->mod_flags & MOD_KALLSYMS)
						fprintf(fp, 
					   "  [CONFIG_KALLSYMS]");
				}
		
				fprintf(fp, "\n");
			}
		}
		break;

	case REMOTE_MODULE_SAVE_MSG:
		if (!REMOTE())
			return;

                for (i = j = 0, lmp = NULL; i < kt->mods_installed; i++) {
                        lm = &st->load_modules[i];
			if (lm->mod_flags & MOD_REMOTE) {
				j++;
				lmp = lm;
			}
		}

		switch (j)
		{
		case 0:
			return;

		case 1:
			error(NOTE, 
 "\nTo save the %s module object locally,\n      enter: \"save %s\"\n",
				lmp->mod_name, lmp->mod_name);
			break;

		default:
			error(NOTE, 
"\nTo save all temporary remote module objects locally,\n      enter: \"save modules\"\n");
			fprintf(fp, 
 "      To save a single remote module object locally,\n      enter: \"save NAME\",\n"
 "      where \"NAME\" is one of the module names shown in the list above.\n");
			break;
		}
		break;
	
	case LOAD_SPECIFIED_MODULE_SYMBOLS:
		if (!load_module_symbols(modref, objfile, address)) 
			error(FATAL, "cannot load symbols from: %s\n", objfile);
		do_module_cmd(LIST_MODULE_HDR, 0, address, 0, NULL);
		do_module_cmd(REMOTE_MODULE_SAVE_MSG, 0, 0, 0, NULL);
		break;

	case LOAD_ALL_MODULE_SYMBOLS:
		for (i = j = 0; i < kt->mods_installed; i++) {
			lm = &st->load_modules[i];

			if (STREQ(lm->mod_name, "(unknown module)")) {
				error(INFO,
                          "cannot find object file for unknown module at %lx\n",
					lm->mod_base);
				continue;
			}

			modref = lm->mod_name;
			address = lm->mod_base;

			if ((objfile = find_module_objfile(modref,NULL,tree))) {
				if (!is_elf_file(objfile)) {
                        		error(INFO, 
			                  "%s: not an ELF format object file\n",
						objfile);
				} else if (!load_module_symbols(modref, 
					objfile, address))
					error(INFO, 
				           "cannot load symbols from: %s\n",
						objfile);
				do_module_cmd(j++ ? 
					LIST_MODULE : LIST_MODULE_HDR,
					0, address, 0, tree);
				FREEBUF(objfile);
			} else if ((lm->mod_flags & MOD_LOAD_SYMS) ||
			    strlen(lm->mod_namelist)) { 
				if (CRASHDEBUG(1))
                        		fprintf(fp, 
				      "%s: module symbols are already loaded\n",
                                		modref);
				do_module_cmd(j++ ? 
					LIST_MODULE : LIST_MODULE_HDR,
					0, address, 0, tree);
			} else
				error(INFO,
                              "cannot find or load object file for %s module\n",
					modref);
		}
		do_module_cmd(REMOTE_MODULE_SAVE_MSG, 0, 0, 0, tree);
		break;

	case DELETE_ALL_MODULE_SYMBOLS:
		delete_load_module(ALL_MODULES);
		break;

	case DELETE_MODULE_SYMBOLS:
		delete_load_module(address);
		break;

	case REINIT_MODULES:
		reinit_modules();
        	do_module_cmd(LIST_MODULE_HDR, NULL, 0, NULL, NULL);
		break;

	case LIST_ALL_MODULE_TAINT:
		show_module_taint();
		break;
	}
}

/*
 *  Reinitialize the current set of modules:
 *
 *   1. first clear out all references to the current set.
 *   2. call module_init() again.
 *   3. display the new set.
 */
static void
reinit_modules(void)
{
        delete_load_module(ALL_MODULES);
        st->mods_installed = 0;
        st->flags &= ~MODULE_SYMS;
        free(st->ext_module_symtable);
        free(st->load_modules);
        st->ext_module_symtable = NULL;
        st->load_modules = NULL;
        kt->mods_installed = 0;
	memset(st->mod_symname_hash, 0, sizeof(st->mod_symname_hash));

        module_init();
}


static char *
module_objfile_search(char *modref, char *filename, char *tree)
{
	char buf[BUFSIZE];
	char file[BUFSIZE];
	char dir[BUFSIZE];
	struct load_module *lm;
	char *retbuf;
	int initrd;
	struct syment *sp;
	char *p1, *p2;
	char *env;
	char *namelist;

	retbuf = NULL;
	initrd = FALSE;

	if (filename)
		strcpy(file, filename);
#ifdef MODULES_IN_CWD
       else {
		char *fileext[] = { "ko", "o"};
		int i;
		for (i = 0; i < 2; i++) {
			sprintf(file, "%s.%s", modref, fileext[i]);
			if (access(file, R_OK) == 0) {
				retbuf = GETBUF(strlen(file)+1);
				strcpy(retbuf, file);
				if (CRASHDEBUG(1))
					fprintf(fp, 
					    "find_module_objfile: [%s] file in cwd\n",
						retbuf);
				return retbuf;
			}
		}
	}
#else
	else 
		sprintf(file, "%s.o", modref);
#endif

	/*
	 *  Later versions of insmod create a symbol at the module's base
	 *  address.  Examples:
         *
         * __insmod_sunrpc_O/lib/modules/2.2.17/misc/sunrpc.o_M3A7EE300_V131601 
         * __insmod_lockd_O/lib/modules/2.2.17/fs/lockd.o_M3A7EE300_V131601  
         * __insmod_nfsd_O/lib/modules/2.2.17/fs/nfsd.o_M3A7EE300_V131601  
         * __insmod_nfs_O/lib/modules/2.2.17/fs/nfs.o_M3A7EE300_V131601
	 */
	if ((st->flags & INSMOD_BUILTIN) && !filename) {
		sprintf(buf, "__insmod_%s_O/", modref);
		if (symbol_query(buf, NULL, &sp) == 1) {
                        if (CRASHDEBUG(1))
                                fprintf(fp, "search: INSMOD_BUILTIN %s\n", sp->name);
			BZERO(buf, BUFSIZE);
			p1 = strstr(sp->name, "/");
			if ((p2 = strstr(sp->name, file)))
				p2 += strlen(file);
			if (p2) {
				strncpy(buf, p1, p2-p1); 	
                                if (!strstr(buf, "/lib/modules/")) {
					sprintf(dir, "/lib/%s.o", modref);
					if (STREQ(dir, buf))
						initrd = TRUE;
				} else if (REMOTE()) 
					strcpy(file, buf);
				else {
					retbuf = GETBUF(strlen(buf)+1);
					strcpy(retbuf, buf);
					if (CRASHDEBUG(1))
				    		fprintf(fp, 
					          "find_module_objfile: [%s]\n",
							retbuf);
					return retbuf;
				}
			}
		}
		if (is_module_name(modref, NULL, &lm) && 
		    (lm->mod_flags & MOD_INITRD)) {
			sprintf(dir, "/lib/%s.o", modref);
			initrd = TRUE;
		}
	}
        
	if (initrd) 
		error(NOTE, "%s: installed from initrd image\n", dir);

	if (REMOTE()) {
		retbuf = GETBUF(MAX_MOD_NAMELIST*2);

		if (!is_module_name(modref, NULL, &lm)) {
			error(INFO, "%s is not a module reference\n", modref);
			return NULL;
		}

        	if ((lm->mod_flags & MOD_LOAD_SYMS) &&
		    strlen(lm->mod_namelist)) {
			if (CRASHDEBUG(1))
				fprintf(fp, "redundant mod call: %s\n", 
					lm->mod_namelist);
			strcpy(retbuf, lm->mod_namelist);
			return retbuf;
		}

		if (find_remote_module_objfile(lm, file, retbuf))
			return retbuf;

		return NULL;
	}

	if (tree) {
		if (!(retbuf = search_directory_tree(tree, file, 1))) {
			switch (kt->flags & (KMOD_V1|KMOD_V2))
			{
			case KMOD_V2:
				sprintf(file, "%s.ko", modref);
				retbuf = search_directory_tree(tree, file, 1);
				if (!retbuf) {
					sprintf(file, "%s.ko.debug", modref);
					retbuf = search_directory_tree(tree, file, 1);
				}
			}
		}
		return retbuf;
	}

	sprintf(dir, "%s/%s", DEFAULT_REDHAT_DEBUG_LOCATION, 
		kt->utsname.release);
	if (!(retbuf = search_directory_tree(dir, file, 0))) {
		switch (kt->flags & (KMOD_V1|KMOD_V2))
		{
		case KMOD_V2:
			sprintf(file, "%s.ko", modref);
			retbuf = search_directory_tree(dir, file, 0);
			if (!retbuf) {
				sprintf(file, "%s.ko.debug", modref);
				retbuf = search_directory_tree(dir, file, 0);
			}
		}
	}

	if (!retbuf && (env = getenv("CRASH_MODULE_PATH"))) {
		sprintf(dir, "%s", env);
		if (!(retbuf = search_directory_tree(dir, file, 0))) {
			switch (kt->flags & (KMOD_V1|KMOD_V2))
			{
			case KMOD_V2:
				sprintf(file, "%s.ko", modref);
				retbuf = search_directory_tree(dir, file, 0);
				if (!retbuf) {
					sprintf(file, "%s.ko.debug", modref);
					retbuf = search_directory_tree(dir, file, 0);
				}
			}
		}
	}

	if (!retbuf) {
		sprintf(dir, "/lib/modules/%s/updates", kt->utsname.release);
		if (!(retbuf = search_directory_tree(dir, file, 0))) {
			switch (kt->flags & (KMOD_V1|KMOD_V2))
			{
			case KMOD_V2:
				sprintf(file, "%s.ko", modref);
				retbuf = search_directory_tree(dir, file, 0);
			}
		}
	}

	if (!retbuf) {
		sprintf(dir, "/lib/modules/%s", kt->utsname.release);
		if (!(retbuf = search_directory_tree(dir, file, 0))) {
			switch (kt->flags & (KMOD_V1|KMOD_V2))
			{
			case KMOD_V2:
				sprintf(file, "%s.ko", modref);
				retbuf = search_directory_tree(dir, file, 0);
			}
		}
	}

	if (!retbuf && !filename && !tree && kt->module_tree) {
		sprintf(dir, "%s", kt->module_tree);
		if (!(retbuf = search_directory_tree(dir, file, 0))) {
			switch (kt->flags & (KMOD_V1|KMOD_V2))
			{
			case KMOD_V2:
				sprintf(file, "%s.ko", modref);
				retbuf = search_directory_tree(dir, file, 0);
				if (!retbuf) {
					sprintf(file, "%s.ko.debug", modref);
					retbuf = search_directory_tree(dir, file, 0);
				}
			}
		}
	}

	/*
	 *  Check the directory tree where the vmlinux file is located.
	 */ 
	if (!retbuf && 
	    (namelist = realpath(pc->namelist_orig ? 
		pc->namelist_orig : pc->namelist, NULL))) {
		sprintf(dir, "%s", dirname(namelist));
		if (!(retbuf = search_directory_tree(dir, file, 0))) {
			switch (kt->flags & (KMOD_V1|KMOD_V2))
			{
			case KMOD_V2:
				sprintf(file, "%s.ko", modref);
				retbuf = search_directory_tree(dir, file, 0);
				if (!retbuf) {
					sprintf(file, "%s.ko.debug", modref);
					retbuf = search_directory_tree(dir, file, 0);
				}
			}
		}
		free(namelist);
	}

	if (!retbuf && is_livepatch()) {
		sprintf(file, "%s.ko", modref);
		sprintf(dir, "/usr/lib/kpatch/%s", kt->utsname.release);
		if (!(retbuf = search_directory_tree(dir, file, 0))) {
			sprintf(file, "%s.ko.debug", modref);
			sprintf(dir, "/usr/lib/debug/usr/lib/kpatch/%s", 
				kt->utsname.release);
			retbuf = search_directory_tree(dir, file, 0);
		}
	}

	return retbuf;
}

/*
 *  First look for a module based upon its reference name.
 *  If that fails, try replacing any underscores in the
 *  reference name with a dash.  
 *  If that fails, because of intermingled dashes and underscores, 
 *  try a regex expression.
 *
 *  Example: module name "dm_mod" comes from "dm-mod.ko" objfile
 *           module name "dm_region_hash" comes from "dm-region_hash.ko" objfile
 */
static char *
find_module_objfile(char *modref, char *filename, char *tree)
{
	char * retbuf;
	char tmpref[BUFSIZE];
	int i, c;

	retbuf = module_objfile_search(modref, filename, tree);

	if (!retbuf) {
		strncpy(tmpref, modref, BUFSIZE-1);
		for (c = 0; c < BUFSIZE && tmpref[c]; c++)
			if (tmpref[c] == '_')
				tmpref[c] = '-';
		retbuf = module_objfile_search(tmpref, filename, tree);
	}

	if (!retbuf && (count_chars(modref, '_') > 1)) {
		for (i = c = 0; modref[i]; i++) {
			if (modref[i] == '_') {
				tmpref[c++] = '[';
				tmpref[c++] = '_';
				tmpref[c++] = '-';
				tmpref[c++] = ']';
			} else
				tmpref[c++] = modref[i];
		} 
		tmpref[c] = NULLCHAR;
		retbuf = module_objfile_search(tmpref, filename, tree);
	}

	return retbuf;
}

/*
 * Try to load module symbols with name.
 */
int
load_module_symbols_helper(char *name)
{
	char *objfile;
	ulong address;

	if (is_module_name(name, &address, NULL) &&
		(objfile = find_module_objfile(name, NULL, NULL))) {
		do_module_cmd(LOAD_SPECIFIED_MODULE_SYMBOLS, name, address,
				objfile, NULL);
		return TRUE;
	}
	return FALSE;
}

/*
 *  Unlink any temporary remote module object files.
 */
void
unlink_module(struct load_module *load_module)
{
	int i;
	struct load_module *lm;

	if (load_module) {
		if (load_module->mod_flags & MOD_REMOTE)
			unlink(load_module->mod_namelist);
		return;
	}

        for (i = 0; i < kt->mods_installed; i++) {
                lm = &st->load_modules[i];
		if (lm->mod_flags & MOD_REMOTE) 
			unlink(lm->mod_namelist);
        }
}


/*
 *  Dump the kernel log_buf in chronological order.
 */

void
cmd_log(void)
{
	int c;
	int msg_flags;

	msg_flags = 0;

        while ((c = getopt(argcnt, args, "Ttdmasc")) != EOF) {
                switch(c)
                {
		case 'T':
			msg_flags |= SHOW_LOG_CTIME;
			break;
		case 't':
			msg_flags |= SHOW_LOG_TEXT;
			break;
		case 'd': 
			msg_flags |= SHOW_LOG_DICT;
			break;
                case 'm':
                        msg_flags |= SHOW_LOG_LEVEL;
                        break;
		case 'a':
			msg_flags |= SHOW_LOG_AUDIT;
			break;
		case 's':
			msg_flags |= SHOW_LOG_SAFE;
			break;
		case 'c':
			msg_flags |= SHOW_LOG_CALLER;
			break;
                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

	if (msg_flags & SHOW_LOG_CTIME && pc->flags & MINIMAL_MODE) {
		error(WARNING, "the option '-T' is not available in minimal mode\n");
		return;
	}

	if (msg_flags & SHOW_LOG_AUDIT) {
		dump_audit();
		return;
	}

	if (msg_flags & SHOW_LOG_SAFE) {
		dump_printk_safe_seq_buf(msg_flags);
		return;
	}

	dump_log(msg_flags);
	dump_printk_safe_seq_buf(msg_flags);
}


void 
dump_log(int msg_flags)
{
	int i, len, tmp, show_level;
	ulong log_buf, log_end;
	char *buf;
	char last;
	ulong index;
	struct syment *nsp;
	int log_wrap, loglevel, log_buf_len;

	if (kernel_symbol_exists("prb")) {
		dump_lockless_record_log(msg_flags);
		return;
	}

	if (kernel_symbol_exists("log_first_idx") && 
	    kernel_symbol_exists("log_next_idx")) {
		dump_variable_length_record_log(msg_flags);
		return;
	}

	if (msg_flags & SHOW_LOG_CTIME)
		option_not_supported('T');
	if (msg_flags & SHOW_LOG_DICT)
		option_not_supported('d');
	if ((msg_flags & SHOW_LOG_TEXT) && STREQ(pc->curcmd, "log"))
		option_not_supported('t');

	show_level = msg_flags & SHOW_LOG_LEVEL ? TRUE : FALSE;

	if (symbol_exists("log_buf_len")) {
		get_symbol_data("log_buf_len", sizeof(int), &log_buf_len);
		get_symbol_data("log_buf", sizeof(ulong), &log_buf);
	} else {
		if ((ARRAY_LENGTH(log_buf) == 0) &&
	            (get_array_length("log_buf", NULL, 0) == 0)) {
	                if ((nsp = next_symbol("log_buf", NULL)) == NULL)
	                        error(FATAL, 
				    "cannot determine length of log_buf\n");
	                builtin_array_length("log_buf", 
				(int)(nsp->value - symbol_value("log_buf")), 
				NULL);
		}
	
		log_buf_len = ARRAY_LENGTH(log_buf);
		log_buf = symbol_value("log_buf");
	}

	buf = GETBUF(log_buf_len);
	log_wrap = FALSE;
	last = 0;
	if ((len = get_symbol_length("log_end")) == sizeof(int)) {
		get_symbol_data("log_end", len, &tmp);
		log_end = (ulong)tmp;
	} else if (len == 0) {
		THIS_KERNEL_VERSION >= LINUX(2,6,25) ?
			get_symbol_data("log_end", sizeof(unsigned), &log_end) :
			get_symbol_data("log_end", sizeof(unsigned long), &log_end);
	} else
		get_symbol_data("log_end", len, &log_end);

	if (!readmem(log_buf, KVADDR, buf,
	    log_buf_len, "log_buf contents", RETURN_ON_ERROR|QUIET)) {
		error(WARNING, "\ncannot read log_buf contents\n");
		return;
	}

	if (log_end < log_buf_len)
		index = 0;
	else
		index = log_end & (log_buf_len - 1);

	if ((log_end < log_buf_len) && (index == 0) && (buf[index] == '<'))
		loglevel = TRUE;
	else
		loglevel = FALSE;

	if (index != 0)
		log_wrap = TRUE;

wrap_around:

	for (i = index; i < log_buf_len; i++) {
                if (loglevel && !show_level) {
                        switch (buf[i])
                        {
                        case '>':
                                loglevel = FALSE;
                                /* FALLTHROUGH */
                        case '<':
                        case '0':
                        case '1':
                        case '2':
                        case '3':
                        case '4':
                        case '5':
                        case '6':
                        case '7':
                                continue;

                        default:
                                loglevel = FALSE;
                                break;
                        }
                }

		if (buf[i]) {
                	fputc(ascii(buf[i]) ? buf[i] : '.', fp);
                	loglevel = buf[i] == '\n' ? TRUE : FALSE;
                	last = buf[i];
		}
	}

	if (log_wrap) {
		log_buf_len = index;
		index = 0;
		log_wrap = FALSE;
		goto wrap_around;
	}

	if (last != '\n')
		fprintf(fp, "\n");

	FREEBUF(buf);
}

/* 
 * get log record by index; idx must point to valid message.
 */
static char *
log_from_idx(uint32_t idx, char *logbuf)
{
	char *logptr;
	uint16_t msglen;

	logptr = logbuf + idx;

	/*
	 * A length == 0 record is the end of buffer marker. 
	 * Wrap around and return the message at the start of 
	 * the buffer.
	 */

	msglen = USHORT(logptr + OFFSET(log_len));
	if (!msglen)
		logptr = logbuf;

	return logptr;
}

/* 
 * get next record index; idx must point to valid message. 
 */
static uint32_t 
log_next(uint32_t idx, char *logbuf)
{
	char *logptr;
	uint16_t msglen;

	logptr = logbuf + idx;

	/*
	 * A length == 0 record is the end of buffer marker. Wrap around and
	 * read the message at the start of the buffer as *this* one, and
	 * return the one after that.
	 */

	msglen = USHORT(logptr + OFFSET(log_len));
	if (!msglen) {
		msglen = USHORT(logbuf + OFFSET(log_len));
		return msglen;
	}

        return idx + msglen;
}

static void
dump_log_entry(char *logptr, int msg_flags)
{
	int indent;
	char *msg, *p;
	uint16_t i, text_len, dict_len, level;
	uint64_t ts_nsec;
	ulonglong nanos; 
	ulong rem;
	char buf[BUFSIZE];
	int ilen;

	ilen = level = 0;
	text_len = USHORT(logptr + OFFSET(log_text_len));
	dict_len = USHORT(logptr + OFFSET(log_dict_len));
	if (VALID_MEMBER(log_level)) {
		/*
		 *  Initially a "u16 level", then a "u8 level:3"
		 */
		if (SIZE(log_level) == sizeof(short))
			level = USHORT(logptr + OFFSET(log_level));
		else
			level = UCHAR(logptr + OFFSET(log_level));
	} else {
		if (VALID_MEMBER(log_flags_level))
			level = UCHAR(logptr + OFFSET(log_flags_level));
		else if (msg_flags & SHOW_LOG_LEVEL)
			msg_flags &= ~SHOW_LOG_LEVEL;
	}
	ts_nsec = ULONGLONG(logptr + OFFSET(log_ts_nsec));

	msg = logptr + SIZE(log);

	if (CRASHDEBUG(1))
		fprintf(fp, 
		    "\nlog %lx -> msg: %lx ts_nsec: %lld flags/level: %x"
		    " text_len: %d dict_len: %d\n", 
			(ulong)logptr, (ulong)msg, (ulonglong)ts_nsec, 
			level, text_len, dict_len);

	if ((msg_flags & SHOW_LOG_TEXT) == 0) {
		nanos = (ulonglong)ts_nsec / (ulonglong)1000000000;
		rem = (ulonglong)ts_nsec % (ulonglong)1000000000;
		if (msg_flags & SHOW_LOG_CTIME) {
			time_t t = kt->boot_date.tv_sec + nanos;
			sprintf(buf, "[%s] ", ctime_tz(&t));
		}
		else
			sprintf(buf, "[%5lld.%06ld] ", nanos, rem/1000);
		ilen = strlen(buf);
		fprintf(fp, "%s", buf);
	}

	/*
	 * The PRINTK_CALLER id field was introduced with Linux-5.1 so if
	 * requested, Kernel version >= 5.1 and field exists print caller_id.
	 */
	if (msg_flags & SHOW_LOG_CALLER &&
			VALID_MEMBER(log_caller_id)) {
		const unsigned int cpuid = 0x80000000;
		char cbuf[PID_CHARS_MAX];
		unsigned int cid;

		/* Get id type, isolate just id value in cid for print */
		cid = UINT(logptr + OFFSET(log_caller_id));
		sprintf(cbuf, "%c%d", (cid & cpuid) ? 'C' : 'T', cid & ~cpuid);
		sprintf(buf, "[%*s] ", PID_CHARS_DEFAULT, cbuf);

		ilen += strlen(buf);
		fprintf(fp, "%s", buf);
	}

	level = LOG_LEVEL(level);

	if (msg_flags & SHOW_LOG_LEVEL) {
		sprintf(buf, "<%x>", level);
		ilen += strlen(buf);
		fprintf(fp, "%s", buf);
	}

	for (i = 0, p = msg; i < text_len; i++, p++) {
		if (*p == '\n')
			fprintf(fp, "\n%s", space(ilen));
		else if (isprint(*p) || isspace(*p)) 
			fputc(*p, fp);
		else
			fputc('.', fp);
	}
	
	if (dict_len & (msg_flags & SHOW_LOG_DICT)) {
		fprintf(fp, "\n");
		indent = TRUE;

		for (i = 0; i < dict_len; i++, p++) {
			if (indent) {
				fprintf(fp, "%s", space(ilen));
				indent = FALSE;
			}
			if (isprint(*p))
				fputc(*p, fp);
			else if (*p == NULLCHAR) {
				fputc('\n', fp);
				indent = TRUE;
			} else
				fputc('.', fp);
		}
	}
	fprintf(fp, "\n");
}

/* 
 *  Handle the variable-length-record log_buf.
 */
static void
dump_variable_length_record_log(int msg_flags)
{
	uint32_t idx, log_first_idx, log_next_idx, log_buf_len;
	ulong log_buf;
	char *logptr, *logbuf, *log_struct_name;

	if (INVALID_SIZE(log)) {
		if (STRUCT_EXISTS("printk_log")) {
			/*
			 * In kernel 3.11 the log structure name was renamed
			 * from log to printk_log.  See 62e32ac3505a0cab.
			 */
			log_struct_name = "printk_log";
			MEMBER_OFFSET_INIT(log_caller_id, "printk_log", "caller_id");
		} else 
			log_struct_name = "log";

		STRUCT_SIZE_INIT(log, log_struct_name);
		MEMBER_OFFSET_INIT(log_ts_nsec, log_struct_name, "ts_nsec");
		MEMBER_OFFSET_INIT(log_len, log_struct_name, "len");
		MEMBER_OFFSET_INIT(log_text_len, log_struct_name, "text_len");
		MEMBER_OFFSET_INIT(log_dict_len, log_struct_name, "dict_len");
		MEMBER_OFFSET_INIT(log_level, log_struct_name, "level");
		MEMBER_SIZE_INIT(log_level, log_struct_name, "level");
		MEMBER_OFFSET_INIT(log_flags_level, log_struct_name, "flags_level");
			
		/*
		 * If things change, don't kill a dumpfile session 
		 * searching for a panic message.
		 */
		if (INVALID_SIZE(log) ||
		    INVALID_MEMBER(log_ts_nsec) ||
		    INVALID_MEMBER(log_len) ||
		    INVALID_MEMBER(log_text_len) ||
		    INVALID_MEMBER(log_dict_len) ||
		    (INVALID_MEMBER(log_level) && INVALID_MEMBER(log_flags_level)) ||
		    !kernel_symbol_exists("log_buf_len") ||
		    !kernel_symbol_exists("log_buf")) {
			error(WARNING, "\nlog buf data structure(s) have changed\n");
			return;
		}
	}

	get_symbol_data("log_first_idx", sizeof(uint32_t), &log_first_idx);
	get_symbol_data("log_next_idx", sizeof(uint32_t), &log_next_idx);
	get_symbol_data("log_buf_len", sizeof(uint32_t), &log_buf_len);
	get_symbol_data("log_buf", sizeof(char *), &log_buf);

	if (CRASHDEBUG(1)) {
		fprintf(fp, "log_buf: %lx\n", (ulong)log_buf);
		fprintf(fp, "log_buf_len: %d\n", log_buf_len);
		fprintf(fp, "log_first_idx: %d\n", log_first_idx);
		fprintf(fp, "log_next_idx: %d\n", log_next_idx);
	}

	logbuf = GETBUF(log_buf_len);

	if (!readmem(log_buf, KVADDR, logbuf,
	    log_buf_len, "log_buf contents", RETURN_ON_ERROR|QUIET)) {
		error(WARNING, "\ncannot read log_buf contents\n");
		FREEBUF(logbuf);
		return;
	}

	hq_open();

	idx = log_first_idx;
	while (idx != log_next_idx) {
		logptr = log_from_idx(idx, logbuf);

		dump_log_entry(logptr, msg_flags);

		if (!hq_enter((ulong)logptr)) {
			error(INFO, "\nduplicate log_buf message pointer\n");
			break;
		}

		idx = log_next(idx, logbuf);

		if (idx >= log_buf_len) {
			if (log_first_idx > log_next_idx)
				idx = 0;
			else {
				error(INFO, "\ninvalid log_buf entry encountered\n");
				break;
			}
		}

		if (CRASHDEBUG(1) && (idx == log_next_idx))
			fprintf(fp, "\nfound log_next_idx OK\n");
	}

	hq_close();

	FREEBUF(logbuf);
}


/*
 *  Display general system info.
 */
void
cmd_sys(void)
{
        int c, cnt;
	ulong sflag;
	char buf[BUFSIZE];

	sflag = FALSE;

        while ((c = getopt(argcnt, args, "ctip:")) != EOF) {
                switch(c)
                {
		case 'p':
			if (STREQ(optarg, "anic"))
				panic_this_kernel();
			else
				argerrs++;
			break;

		case 'c':
			sflag = TRUE;
			break;

		case 't':
			show_kernel_taints(buf, VERBOSE);
			return;

		case 'i':
			dump_dmi_info();
			return;

                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

        if (!args[optind]) {
		if (sflag)
			dump_sys_call_table(NULL, 0);
		else
			display_sys_stats();
		return;
	}

	cnt = 0;
        do {
                if (sflag)
                        dump_sys_call_table(args[optind], cnt++);
		else if (STREQ(args[optind], "config"))
			read_in_kernel_config(IKCFG_READ);
                else
                        cmd_usage(pc->curcmd, SYNOPSIS);
                optind++;
        } while (args[optind]);
}

static int
is_kernel_tainted(void)
{
	ulong tainted_mask;
	int tainted;

	if (kernel_symbol_exists("tainted")) {
		get_symbol_data("tainted", sizeof(int), &tainted);
		if (tainted)
			return TRUE;
	} else if (kernel_symbol_exists("tainted_mask")) {
		get_symbol_data("tainted_mask", sizeof(ulong), &tainted_mask);
		if (tainted_mask)
			return TRUE;
	}
	return FALSE;
}

static int
is_livepatch(void)
{
	int i;
	struct load_module *lm;
	char buf[BUFSIZE];

	show_kernel_taints(buf, !VERBOSE);
	if (strstr(buf, "K"))  /* TAINT_LIVEPATCH */
		return TRUE;

	for (i = 0; i < st->mods_installed; i++) {
		lm = &st->load_modules[i];
		if (STREQ("kpatch", lm->mod_name))
			return TRUE;
	}

	return FALSE;
}

/*
 *  Display system stats at init-time or for the sys command.
 */
void
display_sys_stats(void)
{
        struct new_utsname *uts;
        char buf[BUFSIZE];
	ulong mhz;

	uts = &kt->utsname;

//	if (!(pc->flags & RUNTIME) && !DUMPFILE() && !GDB_PATCHED())
//		fprintf(fp, "\n");

        /*
         *  It's now safe to unlink the remote namelist.
         */
        if (pc->flags & UNLINK_NAMELIST) {
                unlink(pc->namelist);
                pc->flags &= ~UNLINK_NAMELIST;
                pc->flags |= NAMELIST_UNLINKED;
        }

	if (REMOTE()) {
		switch (pc->flags & 
			(NAMELIST_LOCAL|NAMELIST_UNLINKED|NAMELIST_SAVED))
		{
		case NAMELIST_UNLINKED:
			fprintf(fp, "      KERNEL: %s  (temporary)\n", 
				pc->namelist);
			break;

		case (NAMELIST_UNLINKED|NAMELIST_SAVED):
			fprintf(fp, "      KERNEL: %s\n", pc->namelist);
			break;

		case NAMELIST_LOCAL:
			fprintf(fp, "      KERNEL: %s\n", pc->namelist);
			break;
		}
	} else {
        	if (pc->system_map) {
			fprintf(fp, "  SYSTEM MAP: %s%s%s\n", pc->system_map,
				is_livepatch() ? "  [LIVEPATCH]" : "",
				is_kernel_tainted() ? "  [TAINTED]" : "");
			fprintf(fp, "DEBUG KERNEL: %s %s\n", 
					pc->namelist_orig ?
					pc->namelist_orig : pc->namelist,
					debug_kernel_version(pc->namelist));
		} else
			fprintf(fp, "      KERNEL: %s%s%s\n", pc->namelist_orig ?
				pc->namelist_orig : pc->namelist,
				is_livepatch() ? "  [LIVEPATCH]" : "",
				is_kernel_tainted() ? "  [TAINTED]" : "");
	}

	if (pc->debuginfo_file) { 
		if (STREQ(pc->debuginfo_file, pc->namelist_debug) && 
		     pc->namelist_debug_orig)
			fprintf(fp, "   DEBUGINFO: %s\n", 
				pc->namelist_debug_orig);
		else
			fprintf(fp, "   DEBUGINFO: %s\n", pc->debuginfo_file);
	} else if (pc->namelist_debug)
		fprintf(fp, "DEBUG KERNEL: %s %s\n", pc->namelist_debug_orig ? 
			pc->namelist_debug_orig : pc->namelist_debug,
			debug_kernel_version(pc->namelist_debug));

	/*
	 *  After the initial banner display, we no longer need the 
	 *  temporary namelist file(s).
	 */
	if (!(pc->flags & RUNTIME)) {
		if (pc->namelist_orig)
			unlink(pc->namelist);
		if (pc->namelist_debug_orig)
			unlink(pc->namelist_debug);
	}

	if (dumpfile_is_split() || sadump_is_diskset() || is_ramdump_image())
		fprintf(fp, "   DUMPFILES: ");
	else
		fprintf(fp, "    DUMPFILE: ");
        if (ACTIVE()) {
		if (REMOTE_ACTIVE()) 
			fprintf(fp, "%s@%s  (remote live system)\n",
			    	pc->server_memsrc, pc->server);
		else
                	fprintf(fp, "%s\n", pc->live_memsrc);
	} else {
		if (REMOTE_DUMPFILE())
                	fprintf(fp, "%s@%s  (remote dumpfile)", 
				pc->server_memsrc, pc->server);
		else if (REMOTE_PAUSED())
			fprintf(fp, "%s %s  (remote paused system)\n",
				pc->server_memsrc, pc->server);
		else {
			if (dumpfile_is_split())
				show_split_dumpfiles();
			else if (sadump_is_diskset())
				sadump_show_diskset();
			else if (is_ramdump_image())
				show_ramdump_files();
			else
                		fprintf(fp, "%s", pc->dumpfile);
		}

		if (LIVE())
			fprintf(fp, "  [LIVE DUMP]");

		if (NETDUMP_DUMPFILE() && is_partial_netdump())
			fprintf(fp, "  [PARTIAL DUMP]");

		if (KDUMP_DUMPFILE() && is_incomplete_dump())
			fprintf(fp, "  [INCOMPLETE]");

		if (DISKDUMP_DUMPFILE() && !dumpfile_is_split() &&
		    (is_partial_diskdump() || is_incomplete_dump() ||
		     is_excluded_vmemmap())) {
			fprintf(fp, " %s%s%s",
				is_partial_diskdump() ? 
				" [PARTIAL DUMP]" : "",
				is_incomplete_dump() ? 
				" [INCOMPLETE]" : "",
				is_excluded_vmemmap() ? 
				" [EXCLUDED VMEMMAP]" : "");

		}

		fprintf(fp, "\n");

		if (KVMDUMP_DUMPFILE() && pc->kvmdump_mapfile)
			fprintf(fp, "     MAPFILE: %s\n",
				pc->kvmdump_mapfile);
	}
	
	if (machine_type("PPC64"))
		fprintf(fp, "        CPUS: %d\n", get_cpus_to_display());
	else {
		fprintf(fp, "        CPUS: %d", kt->cpus);
		if (kt->cpus - get_cpus_to_display())
			fprintf(fp, " [OFFLINE: %d]", 
				kt->cpus - get_cpus_to_display());
		fprintf(fp, "\n");
	}

	if (ACTIVE())
		get_xtime(&kt->date);
        fprintf(fp, "        DATE: %s\n", ctime_tz(&kt->date.tv_sec));
        fprintf(fp, "      UPTIME: %s\n", get_uptime(buf, NULL)); 
        fprintf(fp, "LOAD AVERAGE: %s\n", get_loadavg(buf)); 
	fprintf(fp, "       TASKS: %ld\n", RUNNING_TASKS());
	fprintf(fp, "    NODENAME: %s\n", uts->nodename); 
        fprintf(fp, "     RELEASE: %s\n", uts->release); 
	fprintf(fp, "     VERSION: %s\n", uts->version); 
	fprintf(fp, "     MACHINE: %s  ", uts->machine);
	if ((mhz = machdep->processor_speed()))
		fprintf(fp, "(%ld Mhz)\n", mhz);
	else
		fprintf(fp, "(unknown Mhz)\n");
	fprintf(fp, "      MEMORY: %s\n", get_memory_size(buf));
#ifdef WHO_CARES
	fprintf(fp, "  DOMAINNAME: %s\n", uts->domainname);
#endif
	if (XENDUMP_DUMPFILE() && (kt->xen_flags & XEN_SUSPEND))
		return;

	if (DUMPFILE()) {
		fprintf(fp, "       PANIC: ");
		if (machdep->flags & HWRESET)
			fprintf(fp, "(HARDWARE RESET)\n");
		else if (machdep->flags & INIT)
			fprintf(fp, "(INIT)\n");
		else if (machdep->flags & MCA)
			fprintf(fp, "(MCA)\n");
		else {
        		strip_linefeeds(get_panicmsg(buf));
			fprintf(fp, "\"%s\"%s\n", buf, 
				strstr(buf, "Oops: ") ? 
				" (check log for details)" : "");
		}
	}
}

/*
 *  Get the kernel version from the debug kernel and store it here.
 */
static char *debug_kernel_version_string = NULL;

static char *
debug_kernel_version(char *namelist)
{
	FILE *pipe;
	int argc;
	char buf[BUFSIZE];
	char command[BUFSIZE];
	char *arglist[MAXARGS];

	if (debug_kernel_version_string)
		return debug_kernel_version_string;

        sprintf(command, "/usr/bin/strings %s", namelist);

        if ((pipe = popen(command, "r")) == NULL) { 
		debug_kernel_version_string = " ";
                return debug_kernel_version_string;
	}

	argc = 0;
        while (fgets(buf, BUFSIZE-1, pipe)) {
                if (!strstr(buf, "Linux version 2.") &&
		    !strstr(buf, "Linux version 3.") &&
		    !strstr(buf, "Linux version 4.") &&
		    !strstr(buf, "Linux version 5.") &&
		    !strstr(buf, "Linux version 6."))
                        continue;

		argc = parse_line(buf, arglist); 
		break;
        }
        pclose(pipe);

	if ((argc >= 3) && (debug_kernel_version_string = (char *) 
	    malloc(strlen(arglist[2])+3)))
		sprintf(debug_kernel_version_string, "(%s)", arglist[2]);
	else
		debug_kernel_version_string = " ";

	return debug_kernel_version_string;
}

/*
 *  Calculate and return the uptime.
 */
char *
get_uptime(char *buf, ulonglong *j64p)
{
	ulong jiffies, tmp1, tmp2;
	ulonglong jiffies_64, wrapped;

	if (symbol_exists("jiffies_64")) {
		get_symbol_data("jiffies_64", sizeof(ulonglong), &jiffies_64);
		if (THIS_KERNEL_VERSION >= LINUX(2,6,0)) {
			wrapped = (jiffies_64 & 0xffffffff00000000ULL);
			if (wrapped) {
				wrapped -= 0x100000000ULL;
				jiffies_64 &= 0x00000000ffffffffULL;
				jiffies_64 |= wrapped;
                		jiffies_64 += (ulonglong)(300*machdep->hz);
			} else {
				tmp1 = (ulong)(uint)(-300*machdep->hz);
				tmp2 = (ulong)jiffies_64;
				jiffies_64 = (ulonglong)(tmp2 - tmp1);
			}
		}
		if (buf)
			convert_time(jiffies_64, buf);
		if (j64p)
			*j64p = jiffies_64;
	} else {
		get_symbol_data("jiffies", sizeof(long), &jiffies);
		if (buf)
			convert_time((ulonglong)jiffies, buf);
		if (j64p)
			*j64p = (ulonglong)jiffies;
	}

	return buf;
}

#define FSHIFT          11              /* nr of bits of precision */
#define FIXED_1 (1<<FSHIFT)
#define LOAD_INT(x) ((x) >> FSHIFT)
#define LOAD_FRAC(x) LOAD_INT(((x) & (FIXED_1-1)) * 100)

static char *
get_loadavg(char *buf)
{
        int a, b, c;
	long avenrun[3];

        readmem(symbol_value("avenrun"), KVADDR, &avenrun[0],
                sizeof(long)*3, "avenrun array", FAULT_ON_ERROR);

        a = avenrun[0] + (FIXED_1/200);
        b = avenrun[1] + (FIXED_1/200);
        c = avenrun[2] + (FIXED_1/200);
        sprintf(buf, "%d.%02d, %d.%02d, %d.%02d",
                LOAD_INT(a), LOAD_FRAC(a),
                LOAD_INT(b), LOAD_FRAC(b),
                LOAD_INT(c), LOAD_FRAC(c));

	return buf;
}



/*
 *  Determine whether a string or value equates to a system call name or value.
 */
int
is_system_call(char *name, ulong value)
{
	int i;
        ulong *sys_call_table, *sct;
	char *sp;
        long size;
	int NR_syscalls;

	NR_syscalls = get_NR_syscalls(NULL);
        size = sizeof(void *) * NR_syscalls;
        sys_call_table = (ulong *)GETBUF(size);

        readmem(symbol_value("sys_call_table"), KVADDR, sys_call_table,
                size, "sys_call_table", FAULT_ON_ERROR);

	for (i = 0, sct = sys_call_table; i < NR_syscalls; i++, sct++) {
		if (name && (sp = value_symbol(*sct))) {
			if (STREQ(name, sp))
				return TRUE;
		} else if (value) {
			if (value == *sct)
				return TRUE;
		}
	}

        return FALSE;
}

char *sys_call_hdr = "NUM  SYSTEM CALL                FILE AND LINE NUMBER\n";

static void
dump_sys_call_table(char *spec, int cnt)
{
        int i, confirmed;
        char buf1[BUFSIZE], *scp;
        char buf2[BUFSIZE], *p;
	char buf3[BUFSIZE];
	char *arglist[MAXARGS];
	int argc, NR_syscalls;
	int number, printit, hdr_printed;
	struct syment *sp, *spn;
        long size;
#ifdef S390X
	unsigned int *sct, *sys_call_table, sys_ni_syscall, addr;
#else
	ulong *sys_call_table, *sct, sys_ni_syscall, addr;
#endif
	if (NO_LINE_NUMBERS())
		error(INFO, "line numbers are not available\n"); 

	NR_syscalls = get_NR_syscalls(&confirmed);
	if (CRASHDEBUG(1))
		fprintf(fp, "NR_syscalls: %d (%sconfirmed)\n", 
			NR_syscalls, confirmed ? "" : "not ");
        size = sizeof(addr) * NR_syscalls;
#ifdef S390X
        sys_call_table = (unsigned int *)GETBUF(size);
#else
        sys_call_table = (ulong *)GETBUF(size);
#endif

        readmem(symbol_value("sys_call_table"), KVADDR, sys_call_table,
                size, "sys_call_table", FAULT_ON_ERROR);

	sys_ni_syscall = symbol_value("sys_ni_syscall");

	if (spec)
		open_tmpfile();

	fprintf(fp, "%s", sys_call_hdr);

	get_build_directory(buf2);
        for (i = 0, sct = sys_call_table; i < NR_syscalls; i++, sct++) {
                if (!(scp = value_symbol(*sct))) {
			if (confirmed || CRASHDEBUG(1)) {
				fprintf(fp, (*gdb_output_radix == 16) ? 
					"%3x  " : "%3d  ", i);
				fprintf(fp, 
			    	    "invalid sys_call_table entry: %lx ", 
					(unsigned long)*sct);
				if (strlen(value_to_symstr(*sct, buf1, 0)))
					fprintf(fp, "(%s)\n", buf1);
				else
					fprintf(fp, "\n");
			}
			continue;
		}
		
		fprintf(fp, (*gdb_output_radix == 16) ? "%3x  " : "%3d  ", i);
  		if (sys_ni_syscall && *sct == sys_ni_syscall)
			fprintf(fp, "%-26s ", "sys_ni_syscall");
		else
			fprintf(fp, "%-26s ", scp);

		/*
		 *  For system call symbols whose first instruction is
		 *  an inline from a header file, the file/line-number is 
		 *  confusing.  For this command only, look for the first
	 	 *  instruction address in the system call that shows the
		 *  the actual source file containing the system call.
	  	 */
                sp = value_search(*sct, NULL);
                spn = next_symbol(NULL, sp);

		for (addr = *sct; sp && spn && (addr < spn->value); addr++) {
			BZERO(buf1, BUFSIZE);
			get_line_number(addr, buf1, FALSE);

			if (strstr(buf1, ".h: ") && strstr(buf1, "include/")) 
				continue;

			if (strstr(buf1, buf2)) {
                                p = buf1 + strlen(buf2);
                                fprintf(fp, "%s%s",
                                        strlen(buf1) ? ".." : "", p);
                                break;
                        }
		}

		fprintf(fp, "\n");
       	}

        if (spec) {
                rewind(pc->tmpfile);

		hdr_printed = cnt;
		if ((number = IS_A_NUMBER(spec))) 
                	sprintf(buf3, (*gdb_output_radix == 16) ?  "%lx" : "%ld",
                        	stol(spec, FAULT_ON_ERROR, NULL));

                while (fgets(buf1, BUFSIZE, pc->tmpfile)) {
			printit = FALSE;
			strcpy(buf2, buf1);
			argc = parse_line(buf2, arglist);
			if (argc < 2)
				continue;

			if (number && STREQ(arglist[0], buf3))
				printit = TRUE;
			else if (!number && strstr(arglist[1], spec))
				printit = TRUE;

			if (printit) {
				fprintf(pc->saved_fp, "%s%s", hdr_printed++ ? 
					"" : sys_call_hdr, buf1);
				if (number)
					break;
			}
                }

                close_tmpfile();
        }
}

/*
 *  Get the number of system calls in the sys_call_table, confirming
 *  the number only if the debuginfo data shows sys_call_table as an
 *  array.  Otherwise base it upon next symbol after it. 
 */
static int
get_NR_syscalls(int *confirmed)
{
       	ulong sys_call_table;
	struct syment *sp;
	int type, cnt;

	type = get_symbol_type("sys_call_table", NULL, NULL); 
	if ((type == TYPE_CODE_ARRAY) &&
	    (cnt = get_array_length("sys_call_table", NULL, 0))) {
		*confirmed = TRUE;
		return cnt;
	}

	*confirmed = FALSE;

	sys_call_table = symbol_value("sys_call_table");
	if (!(sp = next_symbol("sys_call_table", NULL)))
		return 256;

        while (sp->value == sys_call_table) {
                if (!(sp = next_symbol(sp->name, NULL)))
                        return 256;
        }

	if (machine_type("S390X"))
		cnt = (sp->value - sys_call_table)/sizeof(int);
	else
		cnt = (sp->value - sys_call_table)/sizeof(void *);

	return cnt;
}

/*
 *  "help -k" output
 */
void
dump_kernel_table(int verbose)
{
	int i, c, j, more, nr_cpus;
        struct new_utsname *uts;
        int others;

        others = 0;
	more = FALSE;
        uts = &kt->utsname;

        fprintf(fp, "         flags: %lx\n  (", kt->flags);
	if (kt->flags & NO_MODULE_ACCESS)
		fprintf(fp, "%sNO_MODULE_ACCESS", others++ ? "|" : "");
	if (kt->flags & TVEC_BASES_V1)
		fprintf(fp, "%sTVEC_BASES_V1", others++ ? "|" : "");
	if (kt->flags & TVEC_BASES_V2)
		fprintf(fp, "%sTVEC_BASES_V2", others++ ? "|" : "");
	if (kt->flags & GCC_2_96)
		fprintf(fp, "%sGCC_2_96", others++ ? "|" : "");
	if (kt->flags & GCC_3_2)
		fprintf(fp, "%sGCC_3_2", others++ ? "|" : "");
	if (kt->flags & GCC_3_2_3)
		fprintf(fp, "%sGCC_3_2_3", others++ ? "|" : "");
	if (kt->flags & GCC_3_3_2)
		fprintf(fp, "%sGCC_3_3_2", others++ ? "|" : "");
	if (kt->flags & GCC_3_3_3)
		fprintf(fp, "%sGCC_3_3_3", others++ ? "|" : "");
	if (kt->flags & RA_SEEK)
		fprintf(fp, "%sRA_SEEK", others++ ? "|" : "");
	if (kt->flags & NO_RA_SEEK)
		fprintf(fp, "%sNO_RA_SEEK", others++ ? "|" : "");
	if (kt->flags & KALLSYMS_V1)
		fprintf(fp, "%sKALLSYMS_V1", others++ ? "|" : "");
	if (kt->flags & NO_KALLSYMS)
		fprintf(fp, "%sNO_KALLSYMS", others++ ? "|" : "");
	if (kt->flags & PER_CPU_OFF)
		fprintf(fp, "%sPER_CPU_OFF", others++ ? "|" : "");
	if (kt->flags & SMP)
		fprintf(fp, "%sSMP", others++ ? "|" : "");
	if (kt->flags & KMOD_V1)
		fprintf(fp, "%sKMOD_V1", others++ ? "|" : "");
	if (kt->flags & KMOD_V2)
		fprintf(fp, "%sKMOD_V2", others++ ? "|" : "");
	if (kt->flags & KALLSYMS_V2)
		fprintf(fp, "%sKALLSYMS_V2", others++ ? "|" : "");
	if (kt->flags & USE_OPT_BT)
		fprintf(fp, "%sUSE_OPT_BT", others++ ? "|" : "");
	if (kt->flags & ARCH_XEN)
		fprintf(fp, "%sARCH_XEN", others++ ? "|" : "");
	if (kt->flags & ARCH_PVOPS_XEN)
		fprintf(fp, "%sARCH_PVOPS_XEN", others++ ? "|" : "");
	if (kt->flags & ARCH_OPENVZ)
		fprintf(fp, "%sARCH_OPENVZ", others++ ? "|" : "");
	if (kt->flags & ARCH_PVOPS)
		fprintf(fp, "%sARCH_PVOPS", others++ ? "|" : "");
	if (kt->flags & NO_IKCONFIG)
		fprintf(fp, "%sNO_IKCONFIG", others++ ? "|" : "");
	if (kt->flags & DWARF_UNWIND)
		fprintf(fp, "%sDWARF_UNWIND", others++ ? "|" : "");
	if (kt->flags & NO_DWARF_UNWIND)
		fprintf(fp, "%sNO_DWARF_UNWIND", others++ ? "|" : "");
	if (kt->flags & DWARF_UNWIND_MEMORY)
		fprintf(fp, "%sDWARF_UNWIND_MEMORY", others++ ? "|" : "");
	if (kt->flags & DWARF_UNWIND_EH_FRAME)
		fprintf(fp, "%sDWARF_UNWIND_EH_FRAME", others++ ? "|" : "");
	if (kt->flags & DWARF_UNWIND_MODULES)
		fprintf(fp, "%sDWARF_UNWIND_MODULES", others++ ? "|" : "");
	if (kt->flags & BUGVERBOSE_OFF)
		fprintf(fp, "%sBUGVERBOSE_OFF", others++ ? "|" : "");
	if (kt->flags & RELOC_SET)
		fprintf(fp, "%sRELOC_SET", others++ ? "|" : "");
	if (kt->flags & RELOC_FORCE)
		fprintf(fp, "%sRELOC_FORCE", others++ ? "|" : "");
	if (kt->flags & PRE_KERNEL_INIT)
		fprintf(fp, "%sPRE_KERNEL_INIT", others++ ? "|" : "");
	fprintf(fp, ")\n");

        others = 0;
        fprintf(fp, "        flags2: %llx %s", kt->flags2,
		kt->flags2 ? " \n  (" : " (unused");
	if (kt->flags2 & RELOC_AUTO)
		fprintf(fp, "%sRELOC_AUTO", others++ ? "|" : "");
	if (kt->flags2 & KASLR)
		fprintf(fp, "%sKASLR", others++ ? "|" : "");
	if (kt->flags2 & KASLR_CHECK)
		fprintf(fp, "%sKASLR_CHECK", others++ ? "|" : "");
	if (kt->flags2 & TVEC_BASES_V3)
		fprintf(fp, "%sTVEC_BASES_V3", others++ ? "|" : "");
	if (kt->flags2 & TIMER_BASES)
		fprintf(fp, "%sTIMER_BASES", others++ ? "|" : "");
	if (kt->flags2 & IRQ_DESC_TREE_RADIX)
		fprintf(fp, "%sIRQ_DESC_TREE_RADIX", others++ ? "|" : "");
	if (kt->flags2 & IRQ_DESC_TREE_XARRAY)
		fprintf(fp, "%sIRQ_DESC_TREE_XARRAY", others++ ? "|" : "");
	if (kt->flags2 & IRQ_DESC_TREE_MAPLE)
		fprintf(fp, "%sIRQ_DESC_TREE_MAPLE", others++ ? "|" : "");
	if (kt->flags2 & KMOD_PAX)
		fprintf(fp, "%sKMOD_PAX", others++ ? "|" : "");
	if (kt->flags2 & KMOD_MEMORY)
		fprintf(fp, "%sKMOD_MEMORY", others++ ? "|" : "");
	fprintf(fp, ")\n");

        fprintf(fp, "         stext: %lx\n", kt->stext);
        fprintf(fp, "         etext: %lx\n", kt->etext);
        fprintf(fp, "    stext_init: %lx\n", kt->stext_init);
        fprintf(fp, "    etext_init: %lx\n", kt->etext_init);
        fprintf(fp, "    init_begin: %lx\n", kt->init_begin);
        fprintf(fp, "      init_end: %lx\n", kt->init_end);
        fprintf(fp, "           end: %lx\n", kt->end);
        fprintf(fp, "          cpus: %d\n", kt->cpus);
        fprintf(fp, " cpus_override: %s\n", kt->cpus_override);
        fprintf(fp, "       NR_CPUS: %d (compiled-in to this version of %s)\n",
		NR_CPUS, pc->program_name); 
	fprintf(fp, "kernel_NR_CPUS: %d\n", kt->kernel_NR_CPUS);
        others = 0;
	fprintf(fp, "ikconfig_flags: %x (", kt->ikconfig_flags);
	if (kt->ikconfig_flags & IKCONFIG_AVAIL)
		fprintf(fp, "%sIKCONFIG_AVAIL", others++ ? "|" : "");
	if (kt->ikconfig_flags & IKCONFIG_LOADED)
		fprintf(fp, "%sIKCONFIG_LOADED", others++ ? "|" : "");
	if (!kt->ikconfig_flags)
		fprintf(fp, "unavailable");
	fprintf(fp, ")\n");
	fprintf(fp, " ikconfig_ents: %d\n", kt->ikconfig_ents);
	if (kt->display_bh == display_bh_1)
        	fprintf(fp, "    display_bh: display_bh_1()\n");
	else if (kt->display_bh == display_bh_2)
        	fprintf(fp, "    display_bh: display_bh_2()\n");
	else if (kt->display_bh == display_bh_3)
        	fprintf(fp, "    display_bh: display_bh_3()\n");
	else
        	fprintf(fp, "    display_bh: %lx\n", (ulong)kt->display_bh);
        fprintf(fp, "   highest_irq: ");
	if (kt->highest_irq)
		fprintf(fp, "%d\n", kt->highest_irq);
	else
		fprintf(fp, "(unused/undetermined)\n");
        fprintf(fp, "   module_list: %lx\n", kt->module_list);
        fprintf(fp, " kernel_module: %lx\n", kt->kernel_module);
	fprintf(fp, "mods_installed: %d\n", kt->mods_installed);
	fprintf(fp, "   module_tree: %s\n", kt->module_tree ? 
		kt->module_tree : "(not used)");
	fprintf(fp, "   source_tree: %s\n", kt->source_tree ? 
		kt->source_tree : "(not used)");
	if (!(pc->flags & KERNEL_DEBUG_QUERY) && ACTIVE()) 
		get_xtime(&kt->date);
        fprintf(fp, "          date: %s\n", ctime_tz(&kt->date.tv_sec));
        fprintf(fp, "     boot_date: %s\n", ctime_tz(&kt->boot_date.tv_sec));
        fprintf(fp, "  proc_version: %s\n", strip_linefeeds(kt->proc_version));
        fprintf(fp, "   new_utsname: \n");
        fprintf(fp, "      .sysname: %s\n", uts->sysname);
        fprintf(fp, "     .nodename: %s\n", uts->nodename);
        fprintf(fp, "      .release: %s\n", uts->release);
        fprintf(fp, "      .version: %s\n", uts->version);
        fprintf(fp, "      .machine: %s\n", uts->machine);
        fprintf(fp, "   .domainname: %s\n", uts->domainname);
	fprintf(fp, "kernel_version: %d.%d.%d\n", kt->kernel_version[0], 
		kt->kernel_version[1], kt->kernel_version[2]);
	fprintf(fp, "   gcc_version: %d.%d.%d\n", kt->gcc_version[0], 
		kt->gcc_version[1], kt->gcc_version[2]);
	fprintf(fp, "     BUG_bytes: %d\n", kt->BUG_bytes);
	fprintf(fp, "      relocate: %lx", kt->relocate);
	if (kt->flags2 & KASLR)
		fprintf(fp, "  (KASLR offset: %lx / %ldMB)", 
			kt->relocate * -1,
			(kt->relocate * -1) >> 20);
	fprintf(fp, "\n runq_siblings: %d\n", kt->runq_siblings);
	fprintf(fp, "  __rq_idx[NR_CPUS]: ");
	nr_cpus = kt->kernel_NR_CPUS ? kt->kernel_NR_CPUS : NR_CPUS;
	for (i = 0; i < nr_cpus; i++) {
		if (!(kt->__rq_idx)) {
			fprintf(fp, "(unused)");
			break;
		}
		fprintf(fp, "%ld ", kt->__rq_idx[i]);
		for (j = i, more = FALSE; j < nr_cpus; j++) {
			if (kt->__rq_idx[j])
				more = TRUE;
		}
		if (!more) {
			fprintf(fp, "...");
			break;
		}
	}
	fprintf(fp, "\n __cpu_idx[NR_CPUS]: ");
	for (i = 0; i < nr_cpus; i++) {
		if (!(kt->__cpu_idx)) {
			fprintf(fp, "(unused)");
			break;
		}
		fprintf(fp, "%ld ", kt->__cpu_idx[i]);
		for (j = i, more = FALSE; j < nr_cpus; j++) {
			if (kt->__cpu_idx[j])
				more = TRUE;
		}
		if (!more) {
			fprintf(fp, "...");
			break;
		}
	}
	fprintf(fp, "\n __per_cpu_offset[NR_CPUS]:");
	for (i = 0; i < nr_cpus; i++) {
		fprintf(fp, "%s%.*lx ", (i % 4) == 0 ? "\n    " : "",
			LONG_PRLEN, kt->__per_cpu_offset[i]);
		if ((i % 4) == 0) {
			for (j = i, more = FALSE; j < nr_cpus; j++) {
				if (kt->__per_cpu_offset[j] &&
				    (kt->__per_cpu_offset[j] != kt->__per_cpu_offset[i]))
					more = TRUE;
			}
		}
		if (!more) {
			fprintf(fp, "...");
			break;
		}

	}
	fprintf(fp, "\n cpu_flags[NR_CPUS]: ");
	for (i = 0; i < nr_cpus; i++) {
		if (!(kt->cpu_flags)) {
			fprintf(fp, "(unused)\n");
			goto no_cpu_flags;
		}
		fprintf(fp, "%lx ", kt->cpu_flags[i]);
		for (j = i, more = FALSE; j < nr_cpus; j++) {
			if (kt->cpu_flags[j])
				more = TRUE;
		}
		if (!more) {
			fprintf(fp, "...");
			break;
		}
	}
	fprintf(fp, "\n");
	fprintf(fp, "        possible cpus: ");
	if (cpu_map_addr("possible")) {
		for (i = c = 0; i < nr_cpus; i++) {
			if (kt->cpu_flags[i] & POSSIBLE_MAP) {
				fprintf(fp, "%d ", i);
				c++;
			}
		}
		fprintf(fp, "%s\n", c ? "" : "(none)");
	} else
		fprintf(fp, "(nonexistent)\n");
	fprintf(fp, "         present cpus: ");
	if (cpu_map_addr("present")) {
		for (i = c = 0; i < nr_cpus; i++) {
			if (kt->cpu_flags[i] & PRESENT_MAP) {
				fprintf(fp, "%d ", i);
				c++;
			}
		}
		fprintf(fp, "%s\n", c ? "" : "(none)");
	} else
		fprintf(fp, "(nonexistent)\n");
	fprintf(fp, "          online cpus: ");
	if (cpu_map_addr("online")) {
		for (i = c = 0; i < nr_cpus; i++) {
			if (kt->cpu_flags[i] & ONLINE_MAP) {
				fprintf(fp, "%d ", i);
				c++;
			}
		}
		fprintf(fp, "%s\n", c ? "" : "(none)");
	} else
		fprintf(fp, "(nonexistent)\n");
	fprintf(fp, "          active cpus: ");
	if (cpu_map_addr("active")) {
		for (i = c = 0; i < nr_cpus; i++) {
			if (kt->cpu_flags[i] & ACTIVE_MAP) {
				fprintf(fp, "%d ", i);
				c++;
			}
		}
		fprintf(fp, "%s\n", c ? "" : "(none)");
	} else
		fprintf(fp, "(nonexistent)\n");

no_cpu_flags:
	fprintf(fp, "    vmcoreinfo: \n");
	fprintf(fp, "      log_buf_SYMBOL: %lx\n", kt->vmcoreinfo.log_buf_SYMBOL);
	fprintf(fp, "      log_end_SYMBOL: %ld\n", kt->vmcoreinfo.log_end_SYMBOL);
	fprintf(fp, "  log_buf_len_SYMBOL: %ld\n", kt->vmcoreinfo.log_buf_len_SYMBOL);
	fprintf(fp, " logged_chars_SYMBOL: %ld\n", kt->vmcoreinfo.logged_chars_SYMBOL);
	fprintf(fp, "log_first_idx_SYMBOL: %ld\n", kt->vmcoreinfo.log_first_idx_SYMBOL);
	fprintf(fp, " log_next_idx_SYMBOL: %ld\n", kt->vmcoreinfo.log_next_idx_SYMBOL);
	fprintf(fp, "            log_SIZE: %ld\n", kt->vmcoreinfo.log_SIZE);
	fprintf(fp, "  log_ts_nsec_OFFSET: %ld\n", kt->vmcoreinfo.log_ts_nsec_OFFSET);
	fprintf(fp, "      log_len_OFFSET: %ld\n", kt->vmcoreinfo.log_len_OFFSET);
	fprintf(fp, " log_text_len_OFFSET: %ld\n", kt->vmcoreinfo.log_text_len_OFFSET);
	fprintf(fp, " log_dict_len_OFFSET: %ld\n", kt->vmcoreinfo.log_dict_len_OFFSET);
	fprintf(fp, "    phys_base_SYMBOL: %lx\n", kt->vmcoreinfo.phys_base_SYMBOL);
	fprintf(fp, "       _stext_SYMBOL: %lx\n", kt->vmcoreinfo._stext_SYMBOL);
        fprintf(fp, "    hypervisor: %s\n", kt->hypervisor); 

	others = 0;
	fprintf(fp, "     xen_flags: %lx (", kt->xen_flags);
        if (kt->xen_flags & WRITABLE_PAGE_TABLES)
                fprintf(fp, "%sWRITABLE_PAGE_TABLES", others++ ? "|" : "");
        if (kt->xen_flags & SHADOW_PAGE_TABLES)
                fprintf(fp, "%sSHADOW_PAGE_TABLES", others++ ? "|" : "");
        if (kt->xen_flags & CANONICAL_PAGE_TABLES)
                fprintf(fp, "%sCANONICAL_PAGE_TABLES", others++ ? "|" : "");
        if (kt->xen_flags & XEN_SUSPEND)
                fprintf(fp, "%sXEN_SUSPEND", others++ ? "|" : "");
	fprintf(fp, ")\n");
	fprintf(fp, "               m2p_page: %lx\n", (ulong)kt->m2p_page);
        fprintf(fp, "phys_to_machine_mapping: %lx\n", kt->phys_to_machine_mapping);
        fprintf(fp, "         p2m_table_size: %ld\n", kt->p2m_table_size);
	fprintf(fp, " p2m_mapping_cache[%d]: %s\n", P2M_MAPPING_CACHE,
		 verbose ? "" : "(use \"help -K\" to view cache contents)");
	for (i = 0; verbose && (i < P2M_MAPPING_CACHE); i++) {
		if (!kt->p2m_mapping_cache[i].mapping)
			continue;
		fprintf(fp, "       [%d] mapping: %lx pfn: ", i, kt->p2m_mapping_cache[i].mapping);
		if (PVOPS_XEN())
			fprintf(fp, "%lx ", kt->p2m_mapping_cache[i].pfn);
		else
			fprintf(fp, "n/a ");
		fprintf(fp, "start: %lx end: %lx (%ld mfns)\n",
			kt->p2m_mapping_cache[i].start,
			kt->p2m_mapping_cache[i].end,
			kt->p2m_mapping_cache[i].end -  kt->p2m_mapping_cache[i].start + 1);
        }
	fprintf(fp, "      last_mapping_read: %lx\n", kt->last_mapping_read);
	fprintf(fp, "        p2m_cache_index: %ld\n", kt->p2m_cache_index);
	fprintf(fp, "     p2m_pages_searched: %ld\n", kt->p2m_pages_searched);
	fprintf(fp, "     p2m_mfn_cache_hits: %ld ", kt->p2m_mfn_cache_hits);
	if (kt->p2m_pages_searched)
		fprintf(fp, "(%ld%%)\n", kt->p2m_mfn_cache_hits * 100 / kt->p2m_pages_searched);
	else
		fprintf(fp, "\n");
	fprintf(fp, "    p2m_page_cache_hits: %ld ", kt->p2m_page_cache_hits);
	if (kt->p2m_pages_searched)
		fprintf(fp, "(%ld%%)\n", kt->p2m_page_cache_hits * 100 / kt->p2m_pages_searched);
	else
		fprintf(fp, "\n");

	if (!symbol_exists("xen_p2m_addr")) {
		fprintf(fp, "              pvops_xen:\n");
		fprintf(fp, "                    p2m_top: %lx\n", kt->pvops_xen.p2m_top);
		fprintf(fp, "            p2m_top_entries: %d\n", kt->pvops_xen.p2m_top_entries);
		if (symbol_exists("p2m_mid_missing"))
			fprintf(fp, "            p2m_mid_missing: %lx\n", kt->pvops_xen.p2m_mid_missing);
		fprintf(fp, "                p2m_missing: %lx\n", kt->pvops_xen.p2m_missing);
	}
}

/*
 *  Set the context to the active task on a given cpu -- dumpfiles only.
 */
void
set_cpu(int cpu)
{
	ulong task;

	if (cpu >= kt->cpus)
		error(FATAL, "invalid cpu number: system has only %d cpu%s\n", 
			kt->cpus, kt->cpus > 1 ? "s" : "");

	if (hide_offline_cpu(cpu))
		error(FATAL, "invalid cpu number: cpu %d is OFFLINE\n", cpu);

	if ((task = get_active_task(cpu))) 
		set_context(task, NO_PID);
	else
		error(FATAL, "cannot determine active task on cpu %ld\n", cpu);

	show_context(CURRENT_CONTEXT());
}


/*
 *  Collect the irq_desc[] entry along with its associated handler and
 *  action structures.
 */

void
cmd_irq(void)
{
        int i, c;
	int nr_irqs;
	ulong *cpus;
	int show_intr, choose_cpu;
	char buf[15];
	char arg_buf[BUFSIZE];

	cpus = NULL;
	show_intr = 0;
	choose_cpu = 0;

        while ((c = getopt(argcnt, args, "dbuasc:")) != EOF) {
                switch(c)
                {
		case 'd':
			display_idt_table();
			return;

		case 'b':
			if (!kt->display_bh) {
			        if (symbol_exists("bh_base") &&
			            symbol_exists("bh_mask") &&
			            symbol_exists("bh_active"))
			                kt->display_bh = display_bh_1;
			        else if (symbol_exists("bh_base") &&
			            symbol_exists("softirq_state") &&
			            symbol_exists("softirq_vec"))
			                kt->display_bh = display_bh_2;
			        else if (symbol_exists("bh_base") &&
			            symbol_exists("irq_stat") &&
			            symbol_exists("softirq_vec") &&
				    VALID_MEMBER(irq_cpustat_t___softirq_active)
                        	    && VALID_MEMBER(irq_cpustat_t___softirq_mask))
			                kt->display_bh = display_bh_3;
				else if (get_symbol_type("softirq_vec", NULL, NULL) == 
				    TYPE_CODE_ARRAY)
			                kt->display_bh = display_bh_4;
				else
					error(FATAL, 
					    "bottom-half option not supported\n");
			}
			kt->display_bh();
			return;

		case 'u':
			pc->curcmd_flags |= IRQ_IN_USE;
			if (kernel_symbol_exists("no_irq_chip"))
				pc->curcmd_private = (ulonglong)symbol_value("no_irq_chip");
			else if (kernel_symbol_exists("no_irq_type"))
				pc->curcmd_private = (ulonglong)symbol_value("no_irq_type");
			else
				error(WARNING, 
       "irq: -u option ignored: \"no_irq_chip\" or \"no_irq_type\" symbols do not exist\n");
			break;

		case 'a':
			if (!machdep->get_irq_affinity)
				option_not_supported(c);

			if (INVALID_MEMBER(irq_data_affinity) &&
			    INVALID_MEMBER(irq_common_data_affinity) &&
			    INVALID_MEMBER(irq_desc_t_affinity))
				option_not_supported(c);

			if ((nr_irqs = machdep->nr_irqs) == 0)
				error(FATAL, "cannot determine number of IRQs\n");

			fprintf(fp, "IRQ NAME                 AFFINITY\n");
			for (i = 0; i < nr_irqs; i++)
				machdep->get_irq_affinity(i);

			return;

		case 's':
			if (!machdep->show_interrupts)
				option_not_supported(c);
			show_intr = 1;
			break;

		case 'c':
			if (choose_cpu) {
				error(INFO, "only one -c option allowed\n");
				argerrs++;
			} else {
				choose_cpu = 1;
				BZERO(arg_buf, BUFSIZE);
				strcpy(arg_buf, optarg);
			}
			break;

		default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

	if ((nr_irqs = machdep->nr_irqs) == 0)
		error(FATAL, "cannot determine number of IRQs\n");

	if (show_intr) {
		cpus = get_cpumask_buf();

		if (choose_cpu) {
			make_cpumask(arg_buf, cpus, FAULT_ON_ERROR, NULL);
		} else {
			for (i = 0; i < kt->cpus; i++)
				SET_BIT(cpus, i);
		}

		for (i = 0; i < kt->cpus; i++) {
			if (NUM_IN_BITMAP(cpus, i) && hide_offline_cpu(i))
				error(INFO, "CPU%d is OFFLINE.\n", i);
		}

		fprintf(fp, "     ");
		BZERO(buf, 15);

		for (i = 0; i < kt->cpus; i++) {
			if (hide_offline_cpu(i))
				continue;

			if (NUM_IN_BITMAP(cpus, i)) {
				sprintf(buf, "CPU%d", i);
				fprintf(fp, "%10s ", buf);
			}
		}
		fprintf(fp, "\n");

		for (i = 0; i < nr_irqs; i++)
			machdep->show_interrupts(i, cpus);

		if (choose_cpu)
			FREEBUF(cpus);
		return;
	}

	pc->curcmd_flags &= ~HEADER_PRINTED;

	if (!args[optind]) {
		for (i = 0; i < nr_irqs; i++)
			machdep->dump_irq(i);
		return;
	}

	pc->curcmd_flags &= ~IRQ_IN_USE;

	while (args[optind]) {
		i = dtoi(args[optind], FAULT_ON_ERROR, NULL);
		if (i >= nr_irqs)
			error(FATAL, "invalid IRQ value: %d  (%d max)\n", 
				i, nr_irqs-1);
		machdep->dump_irq(i);
		optind++;
	}
}

static ulong
get_irq_desc_addr(int irq)
{
	int c;
	ulong cnt, addr, ptr;
	long len;
	struct list_pair *lp;

	addr = 0;
	lp = NULL;

	if (!VALID_STRUCT(irq_desc_t))
		error(FATAL, "cannot determine size of irq_desc_t\n");
	len = SIZE(irq_desc_t);

        if (symbol_exists("irq_desc"))
		addr = symbol_value("irq_desc") + (len * irq);
        else if (symbol_exists("_irq_desc"))
		addr = symbol_value("_irq_desc") + (len * irq);
	else if (symbol_exists("irq_desc_ptrs")) {
		if (get_symbol_type("irq_desc_ptrs", NULL, NULL) == TYPE_CODE_PTR)
			get_symbol_data("irq_desc_ptrs", sizeof(void *), &ptr);
		else
			ptr = symbol_value("irq_desc_ptrs");
		ptr += (irq * sizeof(void *));
		readmem(ptr, KVADDR, &addr,
                        sizeof(void *), "irq_desc_ptrs entry",
                        FAULT_ON_ERROR);
	} else if (kt->flags2 & IRQ_DESC_TREE_MAPLE) {
		unsigned int i;

		if (kt->highest_irq && (irq > kt->highest_irq))
			return addr;

		cnt = do_maple_tree(symbol_value("sparse_irqs"), MAPLE_TREE_COUNT, NULL);

		len = sizeof(struct list_pair) * (cnt+1);
		lp = (struct list_pair *)GETBUF(len);
		lp[0].index = cnt; /* maxcount */

		cnt = do_maple_tree(symbol_value("sparse_irqs"), MAPLE_TREE_GATHER, lp);

		/*
		 * NOTE: We cannot use lp.index like Radix Tree or XArray because
		 * it's not an absolute index and just counter in Maple Tree.
		 */
		if (kt->highest_irq == 0) {
			readmem((ulong)lp[cnt-1].value +
					OFFSET(irq_desc_irq_data) + OFFSET(irq_data_irq),
				KVADDR, &kt->highest_irq, sizeof(int), "irq_data.irq",
				FAULT_ON_ERROR);
		}

		for (c = 0; c < cnt; c++) {
			readmem((ulong)lp[c].value +
					OFFSET(irq_desc_irq_data) + OFFSET(irq_data_irq),
				KVADDR, &i, sizeof(int), "irq_data.irq", FAULT_ON_ERROR);
			if (i == irq) {
				if (CRASHDEBUG(1))
					fprintf(fp, "index: %d value: %lx\n",
						i, (ulong)lp[c].value);
				addr = (ulong)lp[c].value;
				break;
			}
		}
		FREEBUF(lp);

	} else if (kt->flags2 & (IRQ_DESC_TREE_RADIX|IRQ_DESC_TREE_XARRAY)) {
		if (kt->highest_irq && (irq > kt->highest_irq))
			return addr;

		cnt = 0;
		switch (kt->flags2 & (IRQ_DESC_TREE_RADIX|IRQ_DESC_TREE_XARRAY))
		{
		case IRQ_DESC_TREE_RADIX:
			cnt = do_radix_tree(symbol_value("irq_desc_tree"),
				RADIX_TREE_COUNT, NULL);
			break;
		case IRQ_DESC_TREE_XARRAY:
			cnt = do_xarray(symbol_value("irq_desc_tree"),
				XARRAY_COUNT, NULL);
			break;
		}
		len = sizeof(struct list_pair) * (cnt+1);
		lp = (struct list_pair *)GETBUF(len);
		lp[0].index = cnt;

		switch (kt->flags2 & (IRQ_DESC_TREE_RADIX|IRQ_DESC_TREE_XARRAY))
		{
		case IRQ_DESC_TREE_RADIX:
			cnt = do_radix_tree(symbol_value("irq_desc_tree"),
				RADIX_TREE_GATHER, lp);
			break;
		case IRQ_DESC_TREE_XARRAY:
			cnt = do_xarray(symbol_value("irq_desc_tree"),
				XARRAY_GATHER, lp);
			break;
		}

		if (kt->highest_irq == 0)
			kt->highest_irq = lp[cnt-1].index;

		for (c = 0; c < cnt; c++) {
			if (lp[c].index == irq) {
				if (CRASHDEBUG(1))
					fprintf(fp, "index: %ld value: %lx\n",
						lp[c].index, (ulong)lp[c].value);
				addr = (ulong)lp[c].value;
				break;
			}
		}

		FREEBUF(lp);
	} else {
		error(FATAL,
		    "neither irq_desc, _irq_desc, irq_desc_ptrs, "
		    "irq_desc_tree or sparse_irqs symbols exist\n");
	}

	return addr;
}

static void
display_cpu_affinity(ulong *mask)
{
	int cpu, seq, start, count;

	seq = FALSE;
	start = 0;
	count = 0;

	for (cpu = 0; cpu < kt->cpus; ++cpu) {
		if (NUM_IN_BITMAP(mask, cpu)) {
			if (seq)
				continue;
			start = cpu;
			seq = TRUE;
		} else if (seq) {
			if (count)
				fprintf(fp, ",");
			if (start == cpu - 1)
				fprintf(fp, "%d", cpu - 1);
			else
				fprintf(fp, "%d-%d", start, cpu - 1);
			count++;
			seq = FALSE;
		}
	}

	if (seq) {
		if (count)
			fprintf(fp, ",");
		if (start == kt->cpus - 1)
			fprintf(fp, "%d", kt->cpus - 1);
		else
			fprintf(fp, "%d-%d", start, kt->cpus - 1);
	}
}

/*
 *  Do the work for cmd_irq().
 */
void
generic_dump_irq(int irq)
{
	ulong irq_desc_addr;
	char buf[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	int status, depth, others;
	ulong handler, action, value;
	ulong tmp1, tmp2;

	handler = UNINITIALIZED;
	action = 0;
	
	irq_desc_addr = get_irq_desc_addr(irq);
	if (!irq_desc_addr && symbol_exists("irq_desc_ptrs")) {
		if (!(pc->curcmd_flags & IRQ_IN_USE))
			fprintf(fp, "    IRQ: %d (unused)\n\n", irq);
		return;
	}

	if (irq_desc_addr) {
		if (VALID_MEMBER(irq_desc_t_status))
			readmem(irq_desc_addr + OFFSET(irq_desc_t_status), 
				KVADDR, &status, sizeof(int), "irq_desc status",
				FAULT_ON_ERROR);
		if (VALID_MEMBER(irq_desc_t_handler))
		        readmem(irq_desc_addr + OFFSET(irq_desc_t_handler), 
				KVADDR, &handler, sizeof(long), "irq_desc handler",
				FAULT_ON_ERROR);
		else if (VALID_MEMBER(irq_desc_t_chip))
		        readmem(irq_desc_addr + OFFSET(irq_desc_t_chip), KVADDR,
	        	        &handler, sizeof(long), "irq_desc chip",
				FAULT_ON_ERROR);
	        readmem(irq_desc_addr + OFFSET(irq_desc_t_action), KVADDR, 
			&action, sizeof(long), "irq_desc action", FAULT_ON_ERROR);
	        readmem(irq_desc_addr + OFFSET(irq_desc_t_depth), KVADDR, &depth,
	                sizeof(int), "irq_desc depth", FAULT_ON_ERROR);
	}

	if (!action && (handler == (ulong)pc->curcmd_private))
		return;

	if ((handler == UNINITIALIZED) && VALID_STRUCT(irq_data))
		goto irq_desc_format_v2;

	if (!irq_desc_addr) {
		if (!(pc->curcmd_flags & IRQ_IN_USE))
			fprintf(fp, "    IRQ: %d (unused)\n\n", irq);
		return;
	}

	fprintf(fp, "    IRQ: %d\n", irq);
	fprintf(fp, " STATUS: %x %s", status, status ? "(" : "");
	others = 0;
	if (status & IRQ_INPROGRESS) {
		fprintf(fp, "IRQ_INPROGRESS");
		others++;
	}
	if (status & IRQ_DISABLED)
		fprintf(fp, "%sIRQ_DISABLED", others++ ? "|" : "");
        if (status & IRQ_PENDING)
                fprintf(fp, "%sIRQ_PENDING", others++ ? "|" : "");
        if (status & IRQ_REPLAY)
                fprintf(fp, "%sIRQ_REPLAY", others++ ? "|" : "");
        if (status & IRQ_AUTODETECT)
                fprintf(fp, "%sIRQ_AUTODETECT", others++ ? "|" : "");
        if (status & IRQ_WAITING)
                fprintf(fp, "%sIRQ_WAITING", others++ ? "|" : "");
        if (status & IRQ_LEVEL)
                fprintf(fp, "%sIRQ_LEVEL", others++ ? "|" : "");
        if (status & IRQ_MASKED)
                fprintf(fp, "%sIRQ_MASKED", others++ ? "|" : "");
	fprintf(fp, "%s\n", status ? ")" : "");

	fprintf(fp, "HANDLER: ");
	if (value_symbol(handler)) {
		fprintf(fp, "%lx  ", handler);
		pad_line(fp, VADDR_PRLEN == 8 ? 
			VADDR_PRLEN+2 : VADDR_PRLEN-6, ' ');
		fprintf(fp, "<%s>\n", value_symbol(handler));
	} else
		fprintf(fp, "%lx\n", handler);

	if (handler) {
		if (VALID_MEMBER(hw_interrupt_type_typename))
	        	readmem(handler+OFFSET(hw_interrupt_type_typename),
				KVADDR,	&tmp1, sizeof(void *),
        	        	"hw_interrupt_type typename", FAULT_ON_ERROR);
		else if (VALID_MEMBER(irq_chip_typename))
	        	readmem(handler+OFFSET(irq_chip_typename),
				KVADDR,	&tmp1, sizeof(void *),
                		"hw_interrupt_type typename", FAULT_ON_ERROR);

	 	fprintf(fp, "         typename: %lx  ", tmp1);
		BZERO(buf, BUFSIZE);
        	if (read_string(tmp1, buf, BUFSIZE-1))
			fprintf(fp, "\"%s\"", buf);
		fprintf(fp, "\n");

		if (VALID_MEMBER(hw_interrupt_type_startup))
			readmem(handler+OFFSET(hw_interrupt_type_startup),
				KVADDR,	&tmp1, sizeof(void *),
				"hw_interrupt_type startup", FAULT_ON_ERROR);
		else if (VALID_MEMBER(irq_chip_startup))
			readmem(handler+OFFSET(irq_chip_startup),
				KVADDR,	&tmp1, sizeof(void *),
				"hw_interrupt_type startup", FAULT_ON_ERROR);
		fprintf(fp, "          startup: %lx  ", tmp1); 
		if (is_kernel_text(tmp1)) 
			fprintf(fp, "<%s>", value_to_symstr(tmp1, buf, 0));
		else if (readmem(tmp1, KVADDR, &tmp2,
                	sizeof(ulong), "startup indirection",
                        RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                            	fprintf(fp, "<%s>",
                                	value_to_symstr(tmp2, buf, 0));
		fprintf(fp, "\n");

		if (VALID_MEMBER(hw_interrupt_type_shutdown))
	                readmem(handler+OFFSET(hw_interrupt_type_shutdown),
				KVADDR, &tmp1, sizeof(void *),
	                        "hw_interrupt_type shutdown", FAULT_ON_ERROR);
		else if (VALID_MEMBER(irq_chip_shutdown))
	                readmem(handler+OFFSET(irq_chip_shutdown),
				KVADDR, &tmp1, sizeof(void *),
	                        "hw_interrupt_type shutdown", FAULT_ON_ERROR);

                fprintf(fp, "         shutdown: %lx  ", tmp1);
                if (is_kernel_text(tmp1))
                        fprintf(fp, "<%s>", value_to_symstr(tmp1, buf, 0));
                else if (readmem(tmp1, KVADDR, &tmp2,
                        sizeof(ulong), "shutdown indirection",
                        RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(tmp2, buf, 0));
                fprintf(fp, "\n");

		if (VALID_MEMBER(hw_interrupt_type_handle)) {
	                readmem(handler+OFFSET(hw_interrupt_type_handle), 
				KVADDR,
	                        &tmp1, sizeof(void *),
	                        "hw_interrupt_type handle", FAULT_ON_ERROR);
	                fprintf(fp, "           handle: %lx  ", tmp1);
	                if (is_kernel_text(tmp1))
	                        fprintf(fp, "<%s>", 
					value_to_symstr(tmp1, buf, 0));
	                else if (readmem(tmp1, KVADDR, &tmp2,
	                        sizeof(ulong), "handle indirection",
	                        RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
	                                fprintf(fp, "<%s>",
	                                        value_to_symstr(tmp2, buf, 0));
	                fprintf(fp, "\n");
		}

		if (VALID_MEMBER(hw_interrupt_type_enable))
	                readmem(handler+OFFSET(hw_interrupt_type_enable),
				KVADDR, &tmp1, sizeof(void *),
	                        "hw_interrupt_type enable", FAULT_ON_ERROR);
		else if (VALID_MEMBER(irq_chip_enable))
	                readmem(handler+OFFSET(irq_chip_enable),
				KVADDR, &tmp1, sizeof(void *),
	                        "hw_interrupt_type enable", FAULT_ON_ERROR);
                fprintf(fp, "           enable: %lx  ", tmp1);
                if (is_kernel_text(tmp1))
                        fprintf(fp, "<%s>", value_to_symstr(tmp1, buf, 0));
                else if (readmem(tmp1, KVADDR, &tmp2,
                        sizeof(ulong), "enable indirection",
                        RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(tmp2, buf, 0));
                fprintf(fp, "\n");

		if (VALID_MEMBER(hw_interrupt_type_disable))
	                readmem(handler+OFFSET(hw_interrupt_type_disable),
				KVADDR, &tmp1, sizeof(void *),
	                        "hw_interrupt_type disable", FAULT_ON_ERROR);
		else if (VALID_MEMBER(irq_chip_disable))
	                readmem(handler+OFFSET(irq_chip_disable),
				KVADDR, &tmp1, sizeof(void *),
	                        "hw_interrupt_type disable", FAULT_ON_ERROR);
                fprintf(fp, "          disable: %lx  ", tmp1);
                if (is_kernel_text(tmp1))
                        fprintf(fp, "<%s>", value_to_symstr(tmp1, buf, 0));
                else if (readmem(tmp1, KVADDR, &tmp2,
                        sizeof(ulong), "disable indirection",
                        RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(tmp2, buf, 0));
                fprintf(fp, "\n");

		if (VALID_MEMBER(hw_interrupt_type_ack)) {
                	readmem(handler+OFFSET(hw_interrupt_type_ack), KVADDR,
                        	&tmp1, sizeof(void *),
                        	"hw_interrupt_type ack", FAULT_ON_ERROR);
                	fprintf(fp, "              ack: %lx  ", tmp1);
                	if (is_kernel_text(tmp1))
                        	fprintf(fp, "<%s>", 
					value_to_symstr(tmp1, buf, 0));
                	else if (readmem(tmp1, KVADDR, &tmp2,
                        	sizeof(ulong), "ack indirection",
                        	RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                	fprintf(fp, "<%s>",
                                        	value_to_symstr(tmp2, buf, 0));
                	fprintf(fp, "\n");
		} else if (VALID_MEMBER(irq_chip_ack)) {
                	readmem(handler+OFFSET(irq_chip_ack), KVADDR,
                        	&tmp1, sizeof(void *),
                        	"irq_chip ack", FAULT_ON_ERROR);
                	fprintf(fp, "              ack: %lx  ", tmp1);
                	if (is_kernel_text(tmp1))
                        	fprintf(fp, "<%s>",
					value_to_symstr(tmp1, buf, 0));
                	else if (readmem(tmp1, KVADDR, &tmp2,
                        	sizeof(ulong), "ack indirection",
                        	RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                	fprintf(fp, "<%s>",
                                        	value_to_symstr(tmp2, buf, 0));
                	fprintf(fp, "\n");
		}

		if (VALID_MEMBER(irq_chip_mask)) {
			readmem(handler+OFFSET(irq_chip_mask), KVADDR,
				&tmp1, sizeof(void *),
				"irq_chip mask", FAULT_ON_ERROR);
                        fprintf(fp, "             mask: %lx  ", tmp1);
                        if (is_kernel_text(tmp1))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(tmp1, buf, 0));
                        else if (readmem(tmp1, KVADDR, &tmp2,
                                sizeof(ulong), "mask indirection",
                                RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                        fprintf(fp, "<%s>",
                                                value_to_symstr(tmp2, buf, 0));
                        fprintf(fp, "\n");
		}
		
		if (VALID_MEMBER(irq_chip_mask_ack)) {
			readmem(handler+OFFSET(irq_chip_mask_ack), KVADDR,
				&tmp1, sizeof(void *),
				"irq_chip mask_ack", FAULT_ON_ERROR);
                        fprintf(fp, "         mask_ack: %lx  ", tmp1);
                        if (is_kernel_text(tmp1))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(tmp1, buf, 0));
                        else if (readmem(tmp1, KVADDR, &tmp2,
                                sizeof(ulong), "mask_ack indirection",
                                RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                        fprintf(fp, "<%s>",
                                                value_to_symstr(tmp2, buf, 0));
                        fprintf(fp, "\n");
		}

		if (VALID_MEMBER(irq_chip_unmask)) {
			readmem(handler+OFFSET(irq_chip_unmask), KVADDR,
				&tmp1, sizeof(void *),
				"irq_chip unmask", FAULT_ON_ERROR);
                        fprintf(fp, "           unmask: %lx  ", tmp1);
                        if (is_kernel_text(tmp1))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(tmp1, buf, 0));
                        else if (readmem(tmp1, KVADDR, &tmp2,
                                sizeof(ulong), "unmask indirection",
                                RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                        fprintf(fp, "<%s>",
                                                value_to_symstr(tmp2, buf, 0));
                        fprintf(fp, "\n");
		}

		if (VALID_MEMBER(irq_chip_eoi)) {
			readmem(handler+OFFSET(irq_chip_eoi), KVADDR,
				&tmp1, sizeof(void *),
				"irq_chip eoi", FAULT_ON_ERROR);
                        fprintf(fp, "              eoi: %lx  ", tmp1);
                        if (is_kernel_text(tmp1))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(tmp1, buf, 0));
                        else if (readmem(tmp1, KVADDR, &tmp2,
                                sizeof(ulong), "eoi indirection",
                                RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                        fprintf(fp, "<%s>",
                                                value_to_symstr(tmp2, buf, 0));
                        fprintf(fp, "\n");
		}

		if (VALID_MEMBER(hw_interrupt_type_end)) {
                	readmem(handler+OFFSET(hw_interrupt_type_end), KVADDR,
                        	&tmp1, sizeof(void *),
                        	"hw_interrupt_type end", FAULT_ON_ERROR);
                        fprintf(fp, "              end: %lx  ", tmp1);
                        if (is_kernel_text(tmp1))
                                fprintf(fp, "<%s>", 
                                        value_to_symstr(tmp1, buf, 0));
                        else if (readmem(tmp1, KVADDR, &tmp2,
                                sizeof(ulong), "end indirection",
                                RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                        fprintf(fp, "<%s>",
                                                value_to_symstr(tmp2, buf, 0));
                        fprintf(fp, "\n");
		} else if (VALID_MEMBER(irq_chip_end)) {
                	readmem(handler+OFFSET(irq_chip_end), KVADDR,
                        	&tmp1, sizeof(void *),
                        	"irq_chip end", FAULT_ON_ERROR);
                        fprintf(fp, "              end: %lx  ", tmp1);
                        if (is_kernel_text(tmp1))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(tmp1, buf, 0));
                        else if (readmem(tmp1, KVADDR, &tmp2,
                                sizeof(ulong), "end indirection",
                                RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                        fprintf(fp, "<%s>",
                                                value_to_symstr(tmp2, buf, 0));
                        fprintf(fp, "\n");
		}

		if (VALID_MEMBER(hw_interrupt_type_set_affinity)) {
                	readmem(handler+OFFSET(hw_interrupt_type_set_affinity),
				KVADDR, &tmp1, sizeof(void *),
                        	"hw_interrupt_type set_affinity", 
				FAULT_ON_ERROR);
                        fprintf(fp, "     set_affinity: %lx  ", tmp1);
                        if (is_kernel_text(tmp1))
                                fprintf(fp, "<%s>", 
                                        value_to_symstr(tmp1, buf, 0));
                        else if (readmem(tmp1, KVADDR, &tmp2,
                                sizeof(ulong), "set_affinity indirection",
                                RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                        fprintf(fp, "<%s>",
                                                value_to_symstr(tmp2, buf, 0));
                        fprintf(fp, "\n");
		} else if (VALID_MEMBER(irq_chip_set_affinity)) {
                	readmem(handler+OFFSET(irq_chip_set_affinity),
				KVADDR, &tmp1, sizeof(void *),
                        	"irq_chip set_affinity",
				FAULT_ON_ERROR);
                        fprintf(fp, "     set_affinity: %lx  ", tmp1);
                        if (is_kernel_text(tmp1))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(tmp1, buf, 0));
                        else if (readmem(tmp1, KVADDR, &tmp2,
                                sizeof(ulong), "set_affinity indirection",
                                RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                        fprintf(fp, "<%s>",
                                                value_to_symstr(tmp2, buf, 0));
                        fprintf(fp, "\n");
		}
		if (VALID_MEMBER(irq_chip_retrigger)) {
			readmem(handler+OFFSET(irq_chip_retrigger), KVADDR,
				&tmp1, sizeof(void *),
				"irq_chip retrigger", FAULT_ON_ERROR);
                        fprintf(fp, "        retrigger: %lx  ", tmp1);
                        if (is_kernel_text(tmp1))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(tmp1, buf, 0));
                        else if (readmem(tmp1, KVADDR, &tmp2,
                                sizeof(ulong), "retrigger indirection",
                                RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                        fprintf(fp, "<%s>",
                                                value_to_symstr(tmp2, buf, 0));
                        fprintf(fp, "\n");
		}
		if (VALID_MEMBER(irq_chip_set_type)) {
			readmem(handler+OFFSET(irq_chip_set_type), KVADDR,
				&tmp1, sizeof(void *),
				"irq_chip set_type", FAULT_ON_ERROR);
                        fprintf(fp, "         set_type: %lx  ", tmp1);
                        if (is_kernel_text(tmp1))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(tmp1, buf, 0));
                        else if (readmem(tmp1, KVADDR, &tmp2,
                                sizeof(ulong), "set_type indirection",
                                RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                        fprintf(fp, "<%s>",
                                                value_to_symstr(tmp2, buf, 0));
                        fprintf(fp, "\n");
		}
		if (VALID_MEMBER(irq_chip_set_wake)) {
			readmem(handler+OFFSET(irq_chip_set_wake), KVADDR,
				&tmp1, sizeof(void *),
				"irq_chip set wake", FAULT_ON_ERROR);
                        fprintf(fp, "         set_wake: %lx  ", tmp1);
                        if (is_kernel_text(tmp1))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(tmp1, buf, 0));
                        else if (readmem(tmp1, KVADDR, &tmp2,
                                sizeof(ulong), "set_wake indirection",
                                RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                        fprintf(fp, "<%s>",
                                                value_to_symstr(tmp2, buf, 0));
                        fprintf(fp, "\n");
		}
	}

do_linked_action:

	fprintf(fp, " ACTION: ");
        if (value_symbol(action)) {
                fprintf(fp, "%lx  ", action);
                pad_line(fp, VADDR_PRLEN == 8 ? 
			VADDR_PRLEN+2 : VADDR_PRLEN-6, ' ');
                fprintf(fp, "<%s>\n", value_symbol(action));
        } else if (action)
                fprintf(fp, "%lx\n", action);
	else
		fprintf(fp, "(none)\n");


	if (action) {
                readmem(action+OFFSET(irqaction_handler), KVADDR,
                        &tmp1, sizeof(void *),
                        "irqaction handler", FAULT_ON_ERROR);
		fprintf(fp, "          handler: %lx  ", tmp1);
                if (is_kernel_text(tmp1))
                        fprintf(fp, "<%s>", value_to_symstr(tmp1, buf, 0));
                else if (readmem(tmp1, KVADDR, &tmp2,
                        sizeof(ulong), "handler indirection",
                        RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(tmp2, buf, 0));
                fprintf(fp, "\n");

                readmem(action+OFFSET(irqaction_flags), KVADDR,
                        &value, sizeof(void *),
                        "irqaction flags", FAULT_ON_ERROR);
                fprintf(fp, "            flags: %lx\n", value);

		if (VALID_MEMBER(irqaction_mask)) {
			readmem(action+OFFSET(irqaction_mask), KVADDR,
				&tmp1, sizeof(void *),
				"irqaction mask", FAULT_ON_ERROR);
			fprintf(fp, "             mask: %lx\n", tmp1);
		}

                readmem(action+OFFSET(irqaction_name), KVADDR,
                        &tmp1, sizeof(void *),
                        "irqaction name", FAULT_ON_ERROR);
                fprintf(fp, "             name: %lx  ", tmp1);
                BZERO(buf, BUFSIZE);
                if (read_string(tmp1, buf, BUFSIZE-1))
                        fprintf(fp, "\"%s\"", buf);
                fprintf(fp, "\n");

                readmem(action+OFFSET(irqaction_dev_id), KVADDR,
                        &tmp1, sizeof(void *),
                        "irqaction dev_id", FAULT_ON_ERROR);
                fprintf(fp, "           dev_id: %lx\n", tmp1);

                readmem(action+OFFSET(irqaction_next), KVADDR,
                        &action, sizeof(void *),
                        "irqaction dev_id", FAULT_ON_ERROR);
                fprintf(fp, "             next: %lx\n", action);
	}

	if (action) 
		goto do_linked_action;

	fprintf(fp, "  DEPTH: %d\n\n", depth);

	return;

irq_desc_format_v2:
	if (!(pc->curcmd_flags & HEADER_PRINTED)) {
		fprintf(fp, " IRQ  %s  %s  NAME\n",
			mkstring(buf1, VADDR_PRLEN, CENTER,
			"IRQ_DESC/_DATA"),
			mkstring(buf2, VADDR_PRLEN, CENTER,
			"IRQACTION"));
		
		pc->curcmd_flags |= HEADER_PRINTED;
	}
	if (!irq_desc_addr) {
		if (pc->curcmd_flags & IRQ_IN_USE)
			return;
	}
	fprintf(fp, "%s  %s  ", 
		mkstring(buf1, 4, CENTER|RJUST|INT_DEC, MKSTR((ulong)irq)),
		irq_desc_addr ?
		mkstring(buf2, MAX(VADDR_PRLEN, strlen("IRQ_DESC/_DATA")),
		CENTER|LONG_HEX, MKSTR(irq_desc_addr)) :
		mkstring(buf3,
                MAX(VADDR_PRLEN, strlen("IRQ_DESC/_DATA")),
                CENTER, "(unused)"));

do_linked_action_v2:

	fprintf(fp, "%s  ", action ?
		mkstring(buf1, MAX(VADDR_PRLEN, strlen("IRQACTION")),
		CENTER|LONG_HEX, MKSTR(action)) :
		mkstring(buf2, MAX(VADDR_PRLEN, strlen("IRQACTION")),
		CENTER, "(unused)"));

	if (action) {
		readmem(action+OFFSET(irqaction_name), KVADDR,
			&tmp1, sizeof(void *),
			"irqaction name", FAULT_ON_ERROR);
		if (read_string(tmp1, buf, BUFSIZE-1))
			fprintf(fp, "\"%s\"", buf);

                readmem(action+OFFSET(irqaction_next), KVADDR,
                        &action, sizeof(void *),
                        "irqaction next", FAULT_ON_ERROR);
		if (action) {
			fprintf(fp, "\n%s",
				space(4 + 2 + MAX(VADDR_PRLEN, 
				strlen("IRQ_DESC/_DATA")) + 2));
			goto do_linked_action_v2;
		}
	}
		

	fprintf(fp, "\n");
}

void
generic_get_irq_affinity(int irq)
{
	ulong irq_desc_addr;
	long len;
	ulong affinity_ptr;
	ulong *affinity;
	ulong tmp_addr;
	ulong action, name;
	char buf[BUFSIZE];
	char name_buf[BUFSIZE];

	affinity = NULL;

	irq_desc_addr = get_irq_desc_addr(irq);
	if (!irq_desc_addr)
		return;

	readmem(irq_desc_addr + OFFSET(irq_desc_t_action), KVADDR,
	        &action, sizeof(long), "irq_desc action", FAULT_ON_ERROR);

	if (!action)
		return;

	if ((len = STRUCT_SIZE("cpumask_t")) < 0)
		len = DIV_ROUND_UP(kt->cpus, BITS_PER_LONG) * sizeof(ulong);

	affinity = (ulong *)GETBUF(len);
	if (VALID_MEMBER(irq_common_data_affinity))
		tmp_addr = irq_desc_addr + OFFSET(irq_desc_irq_common_data)
				+ OFFSET(irq_common_data_affinity);
	else if (VALID_MEMBER(irq_data_affinity))
		tmp_addr = irq_desc_addr + \
			   OFFSET(irq_data_affinity);
	else
		tmp_addr = irq_desc_addr + \
			   OFFSET(irq_desc_t_affinity);

	if (symbol_exists("alloc_cpumask_var_node") ||
	    symbol_exists("alloc_cpumask_var")) /* pointer member */
		readmem(tmp_addr,KVADDR, &affinity_ptr, sizeof(ulong),
		        "irq_desc affinity", FAULT_ON_ERROR);
	else /* array member */
		affinity_ptr = tmp_addr;

	readmem(affinity_ptr, KVADDR, affinity, len,
	        "irq_desc affinity", FAULT_ON_ERROR);

	fprintf(fp, "%3d ", irq);

	BZERO(name_buf, BUFSIZE);

	while (action) {
		readmem(action+OFFSET(irqaction_name), KVADDR,
		        &name, sizeof(void *),
		        "irqaction name", FAULT_ON_ERROR);
		BZERO(buf, BUFSIZE);
		if (read_string(name, buf, BUFSIZE-1)) {
			if (strlen(name_buf) != 0)
				strcat(name_buf, ",");
			strcat(name_buf, buf);
		}

		readmem(action+OFFSET(irqaction_next), KVADDR,
		        &action, sizeof(void *),
		        "irqaction dev_id", FAULT_ON_ERROR);
	}

	fprintf(fp, "%-20s ", name_buf);
	display_cpu_affinity(affinity);
	fprintf(fp, "\n");

	FREEBUF(affinity);
}

void
generic_show_interrupts(int irq, ulong *cpus)
{
	int i;
	ulong irq_desc_addr;
	ulong handler, action, name;
	uint kstat_irq;
	uint kstat_irqs[kt->cpus];
	ulong kstat_irqs_ptr;
	struct syment *percpu_sp;
	ulong tmp, tmp1;
	char buf[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char name_buf[BUFSIZE];

	handler = UNINITIALIZED;

	irq_desc_addr = get_irq_desc_addr(irq);
	if (!irq_desc_addr)
		return;

	readmem(irq_desc_addr + OFFSET(irq_desc_t_action), KVADDR,
	        &action, sizeof(long), "irq_desc action", FAULT_ON_ERROR);

	if (!action)
		return;

	if (!symbol_exists("kstat_irqs_cpu")) { /* for RHEL5 or earlier */
		if (!(percpu_sp = per_cpu_symbol_search("kstat")))
			return;

		for (i = 0; i < kt->cpus; i++) {
			if (!(NUM_IN_BITMAP(cpus, i)))
				continue;

			tmp = percpu_sp->value + kt->__per_cpu_offset[i];
			readmem(tmp + OFFSET(kernel_stat_irqs) + sizeof(uint) * irq,
			        KVADDR, &kstat_irq, sizeof(uint),
			        "kernel_stat irqs", FAULT_ON_ERROR);
			kstat_irqs[i] = kstat_irq;
		}
	} else {
		readmem(irq_desc_addr + OFFSET(irq_desc_t_kstat_irqs),
		        KVADDR, &kstat_irqs_ptr, sizeof(long),
		        "irq_desc kstat_irqs", FAULT_ON_ERROR);
		if (THIS_KERNEL_VERSION > LINUX(2,6,37)) {
			for (i = 0; i < kt->cpus; i++) {
				if (!(NUM_IN_BITMAP(cpus, i)))
					continue;

				tmp = kstat_irqs_ptr + kt->__per_cpu_offset[i];
				readmem(tmp, KVADDR, &kstat_irq, sizeof(uint),
				        "kernel_stat irqs", FAULT_ON_ERROR);
				kstat_irqs[i] = kstat_irq;
			}
		} else
			readmem(kstat_irqs_ptr, KVADDR, kstat_irqs,
			        sizeof(kstat_irqs), "kstat_irqs",
			        FAULT_ON_ERROR);
	}
	if (VALID_MEMBER(irq_desc_t_handler))
		readmem(irq_desc_addr + OFFSET(irq_desc_t_handler),
		        KVADDR, &handler, sizeof(long), "irq_desc handler",
		        FAULT_ON_ERROR);
	else if (VALID_MEMBER(irq_desc_t_chip))
		readmem(irq_desc_addr + OFFSET(irq_desc_t_chip), KVADDR,
		        &handler, sizeof(long), "irq_desc chip",
		        FAULT_ON_ERROR);
	else if (VALID_MEMBER(irq_data_chip)) {
		tmp = irq_desc_addr + OFFSET(irq_data_chip);
		if (VALID_MEMBER(irq_desc_irq_data))
			tmp += OFFSET(irq_desc_irq_data);
		readmem(tmp, KVADDR, &handler, sizeof(long), "irq_data chip",
			FAULT_ON_ERROR);
	}

	fprintf(fp, "%3d: ", irq);

	for (i = 0; i < kt->cpus; i++) {
		if (hide_offline_cpu(i))
			continue;

		if (NUM_IN_BITMAP(cpus, i))
			fprintf(fp, "%10u ", kstat_irqs[i]);
	}

	if (handler != UNINITIALIZED) {
		if (VALID_MEMBER(hw_interrupt_type_typename)) {
			readmem(handler+OFFSET(hw_interrupt_type_typename),
			        KVADDR,	&tmp, sizeof(void *),
			        "hw_interrupt_type typename", FAULT_ON_ERROR);

			BZERO(buf, BUFSIZE);
			if (read_string(tmp, buf, BUFSIZE-1))
				fprintf(fp, "%14s", buf);
		}
		else if (VALID_MEMBER(irq_chip_typename)) {
			readmem(handler+OFFSET(irq_chip_typename),
			        KVADDR,	&tmp, sizeof(void *),
			        "hw_interrupt_type typename", FAULT_ON_ERROR);

			BZERO(buf, BUFSIZE);
			if (read_string(tmp, buf, BUFSIZE-1))
				fprintf(fp, "%8s", buf);
			BZERO(buf1, BUFSIZE);
			if (VALID_MEMBER(irq_desc_t_name))
				readmem(irq_desc_addr+OFFSET(irq_desc_t_name),
				        KVADDR,	&tmp1, sizeof(void *),
				        "irq_desc name", FAULT_ON_ERROR);
			if (read_string(tmp1, buf1, BUFSIZE-1))
				fprintf(fp, "-%-8s", buf1);
		}
	}

	BZERO(name_buf, BUFSIZE);

	while (action) {
		readmem(action+OFFSET(irqaction_name), KVADDR,
		        &name, sizeof(void *),
		        "irqaction name", FAULT_ON_ERROR);
		BZERO(buf2, BUFSIZE);
		if (read_string(name, buf2, BUFSIZE-1)) {
			if (strlen(name_buf) != 0)
				strcat(name_buf, ",");
			strcat(name_buf, buf2);
		}

		readmem(action+OFFSET(irqaction_next), KVADDR,
		        &action, sizeof(void *),
		        "irqaction dev_id", FAULT_ON_ERROR);
	}

	fprintf(fp, " %s\n", name_buf);
}

/*
 *  Dump the earlier 2.2 Linux version's bottom-half essentials.
 */
static void
display_bh_1(void)
{
        int i;
        ulong bh_mask, bh_active;
        ulong bh_base[32];
        char buf[BUFSIZE];

        get_symbol_data("bh_mask", sizeof(ulong), &bh_mask);
        get_symbol_data("bh_active", sizeof(ulong), &bh_active);
        readmem(symbol_value("bh_base"), KVADDR, bh_base, sizeof(void *) * 32,
                "bh_base[32]", FAULT_ON_ERROR);

        fprintf(fp, "BH_MASK   BH_ACTIVE\n");
        fprintf(fp, "%08lx  %08lx\n", bh_mask, bh_active);
        fprintf(fp, "\nBH_BASE   %s\n",
                mkstring(buf, VADDR_PRLEN, CENTER|LJUST, "FUNCTION"));
        for (i = 0; i < 32; i++) {
                if (!bh_base[i])
                        continue;
                fprintf(fp, "  %2d      %lx  <%s>\n", i, bh_base[i],
                        value_to_symstr(bh_base[i], buf, 0));
        }
}

/*
 *  Dump the 2.3-ish Linux version's bottom half essentials.  
 */
static void 
display_bh_2(void)
{
	int i;
        ulong bh_base[32];
	struct softirq_state {
        	uint32_t active;
        	uint32_t mask;
	} softirq_state; 
	struct softirq_action {
	        void    *action;
        	void    *data;
	} softirq_vec[32];
	char buf[BUFSIZE];

        readmem(symbol_value("bh_base"), KVADDR, bh_base, sizeof(void *) * 32,
                "bh_base[32]", FAULT_ON_ERROR);

        readmem(symbol_value("softirq_vec"), KVADDR, softirq_vec, 
		sizeof(struct softirq_action) * 32,
                "softirq_vec[32]", FAULT_ON_ERROR);

	fprintf(fp, "CPU    MASK     ACTIVE\n");
	
	for (i = 0; i < kt->cpus; i++) {
		readmem(symbol_value("softirq_state") + 
			(i * SIZE(softirq_state)), KVADDR,
			&softirq_state, sizeof(struct softirq_state),
			"softirq_state", FAULT_ON_ERROR);

		fprintf(fp, " %-2d  %08x  %08x\n", 
			i, softirq_state.mask,
			softirq_state.active);
	}

	fprintf(fp, "\nVEC  %s\n", 
		mkstring(buf, VADDR_PRLEN, CENTER|LJUST, "ACTION"));

	for (i = 0; i < 32; i++) {
		if (!softirq_vec[i].action)
			continue;

		fprintf(fp, " %-2d  %lx  <%s>\n", i, 
			(ulong)softirq_vec[i].action,
			value_to_symstr((ulong)softirq_vec[i].action, buf, 0));
	}

        fprintf(fp, "\nBH_BASE   %s\n", 
		mkstring(buf, VADDR_PRLEN, CENTER|LJUST, "FUNCTION"));
        for (i = 0; i < 32; i++) {
                if (!bh_base[i])
                        continue;
                fprintf(fp, "  %2d      %lx  <%s>\n", i, bh_base[i],
                        value_to_symstr(bh_base[i], buf, 0));
        }

}

/*
 *  Dump the 2.4 Linux version's bottom half essentials.  
 */
static void 
display_bh_3(void)
{
	int i;
        ulong bh_base[32];
	struct softirq_action {
	        void    *action;
        	void    *data;
	} softirq_vec[32];
	char buf[BUFSIZE];
	uint active, mask;
	ulong function;

        readmem(symbol_value("bh_base"), KVADDR, bh_base, sizeof(void *) * 32,
                "bh_base[32]", FAULT_ON_ERROR);

        readmem(symbol_value("softirq_vec"), KVADDR, softirq_vec, 
		sizeof(struct softirq_action) * 32,
                "softirq_vec[32]", FAULT_ON_ERROR);

	fprintf(fp, "CPU    MASK     ACTIVE\n");
	
	for (i = 0; i < kt->cpus; i++) {
		readmem(symbol_value("irq_stat") + 
			(i * SIZE(irq_cpustat_t)) +
			OFFSET(irq_cpustat_t___softirq_active), KVADDR,
			&active, sizeof(uint),
			"__softirq_active", FAULT_ON_ERROR);

                readmem(symbol_value("irq_stat") +
                        (i * SIZE(irq_cpustat_t)) +
                        OFFSET(irq_cpustat_t___softirq_mask), KVADDR,
                        &mask, sizeof(uint),
                        "__softirq_mask", FAULT_ON_ERROR);

		fprintf(fp, " %-2d  %08x  %08x\n", i, mask, active);
	}

	fprintf(fp, "\nVEC  %s\n", 
		mkstring(buf, VADDR_PRLEN, CENTER|LJUST, "ACTION"));

	for (i = 0; i < 32; i++) {
		if (!softirq_vec[i].action)
			continue;

		fprintf(fp, " %-2d  %lx  ", i, (ulong)softirq_vec[i].action);
		if (is_kernel_text((ulong)softirq_vec[i].action))
			fprintf(fp, "<%s>",
			    	value_to_symstr((ulong)softirq_vec[i].action, 
			    	buf, 0));
                else if (readmem((ulong)softirq_vec[i].action, KVADDR, 
			&function, sizeof(ulong), "action indirection",
                        RETURN_ON_ERROR|QUIET) && is_kernel_text(function))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(function, buf, 0));
		fprintf(fp, "\n");
	}

        fprintf(fp, "\nBH_BASE   %s\n", 
		mkstring(buf, VADDR_PRLEN, CENTER|LJUST, "FUNCTION"));
        for (i = 0; i < 32; i++) {
                if (!bh_base[i])
                        continue;
                fprintf(fp, "  %2d      %lx  ", i, bh_base[i]);
		if (is_kernel_text(bh_base[i]))
			fprintf(fp, "<%s>", 
				value_to_symstr(bh_base[i], buf, 0));
                else if (readmem(bh_base[i], KVADDR, &function,
                        sizeof(ulong), "bh_base indirection",
                        RETURN_ON_ERROR|QUIET) && is_kernel_text(function))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(function, buf, 0));
		fprintf(fp, "\n");
        }

}

/*
 *  Dump the 2.6 Linux version's bottom half essentials.  
 */
static void
display_bh_4(void)
{
	int i, len;
	char buf[BUFSIZE];
	char *array; 
	ulong *p;
	struct load_module *lm;

	if (!(len = get_array_length("softirq_vec", NULL, 0)))
		error(FATAL, "cannot determine softirq_vec array length\n");

	fprintf(fp, "SOFTIRQ_VEC %s\n",
		mkstring(buf, VADDR_PRLEN, CENTER|RJUST, "ACTION"));

	array = GETBUF(SIZE(softirq_action) * (len+1));
	
	readmem(symbol_value("softirq_vec"), KVADDR,
		array, SIZE(softirq_action) * len,
		"softirq_vec", FAULT_ON_ERROR);

	for (i = 0, p = (ulong *)array; i < len; i++, p++) {
		if (*p) {
			fprintf(fp, "    [%d]%s %s  <%s>",
				i, i < 10 ? space(4) : space(3),
				mkstring(buf, VADDR_PRLEN, 
				LONG_HEX|CENTER|RJUST, MKSTR(*p)),
				value_symbol(*p));
			if (module_symbol(*p, NULL, &lm, NULL, 0))
				fprintf(fp, "  [%s]", lm->mod_name);
			fprintf(fp, "\n");
		}
		if (SIZE(softirq_action) == (sizeof(void *)*2))
			p++;
	}

	FREEBUF(array);
}

/*
 *  Dump the entries in the old- and new-style timer queues in
 *  chronological order.
 */
void
cmd_timer(void)
{
        int c;
	int rflag;
	char *cpuspec;
	ulong *cpus = NULL;

	rflag = 0;

        while ((c = getopt(argcnt, args, "rC:")) != EOF) {
                switch(c)
                {
		case 'r':
			rflag = 1;
			break;

		case 'C':
			cpuspec = optarg;
			cpus = get_cpumask_buf();
			make_cpumask(cpuspec, cpus, FAULT_ON_ERROR, NULL);
			break;

                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

	if (rflag)
		dump_hrtimer_data(cpus);
	else
		dump_timer_data(cpus);

	if (cpus)
		FREEBUF(cpus);
}

static void
dump_hrtimer_data(const ulong *cpus)
{
	int i, j, k = 0;
	int hrtimer_max_clock_bases, max_hrtimer_bases;
	struct syment * hrtimer_bases;

	hrtimer_max_clock_bases = 0;
	max_hrtimer_bases = 0;

	/* 
	 * deside whether hrtimer is available and
	 * set hrtimer_max_clock_bases or max_hrtimer_bases.
	 * if both are not available, hrtimer is not available.
	 */
	if (VALID_STRUCT(hrtimer_clock_base)) {
		hrtimer_max_clock_bases = 2;
		if (symbol_exists("ktime_get_boottime"))
			hrtimer_max_clock_bases = MEMBER_SIZE("hrtimer_cpu_base", "clock_base") /
							SIZE(hrtimer_clock_base);
	} else if (VALID_STRUCT(hrtimer_base)) {
		max_hrtimer_bases = 2;
	} else
		option_not_supported('r');

	hrtimer_bases = per_cpu_symbol_search("hrtimer_bases");

	for (i = 0; i < kt->cpus; i++) {
		if (cpus && !NUM_IN_BITMAP(cpus, i))
			continue;

		if (k++)
			fprintf(fp, "\n");

		if (hide_offline_cpu(i)) {
			fprintf(fp, "CPU: %d  [OFFLINE]\n", i);
			continue;
		}

		fprintf(fp, "CPU: %d  ", i);
		if (VALID_STRUCT(hrtimer_clock_base)) {
			fprintf(fp, "HRTIMER_CPU_BASE: %lx\n",
				(ulong)(hrtimer_bases->value +
				kt->__per_cpu_offset[i]));

			for (j = 0; j < hrtimer_max_clock_bases; j++) {
				if (j)
					fprintf(fp, "\n");
				dump_hrtimer_clock_base(
					(void *)(hrtimer_bases->value) +
					kt->__per_cpu_offset[i], j);
			}
		} else {
			fprintf(fp, "\n");
			for (j = 0; j < max_hrtimer_bases; j++) {
				if (j)
					fprintf(fp, "\n");
				dump_hrtimer_base(
					(void *)(hrtimer_bases->value) +
					kt->__per_cpu_offset[i], j);
			}
		}
	}
}

static int expires_len = -1;
static int softexpires_len = -1;
static int tte_len = -1;

static void
dump_hrtimer_clock_base(const void *hrtimer_bases, const int num)
{
	void *base;
	ulonglong current_time, now;
	ulonglong offset;
	ulong get_time;
	char buf[BUFSIZE];

	base = (void *)hrtimer_bases + OFFSET(hrtimer_cpu_base_clock_base) +
		SIZE(hrtimer_clock_base) * num;
	readmem((ulong)(base + OFFSET(hrtimer_clock_base_get_time)), KVADDR,
		&get_time, sizeof(get_time), "hrtimer_clock_base get_time",
		FAULT_ON_ERROR);
	fprintf(fp, "  CLOCK: %d  HRTIMER_CLOCK_BASE: %lx  [%s]\n", num, 
		(ulong)base, value_to_symstr(get_time, buf, 0));

	/* get current time(uptime) */
	get_uptime(NULL, &current_time);

	offset = 0;
	if (VALID_MEMBER(hrtimer_clock_base_offset))
		offset = ktime_to_ns(base + OFFSET(hrtimer_clock_base_offset));
	now = current_time * (1000000000LL / machdep->hz) + offset;

	dump_active_timers(base, now);
}

static void
dump_hrtimer_base(const void *hrtimer_bases, const int num)
{
	void *base;
	ulonglong current_time, now;
	ulong get_time;
	char buf[BUFSIZE];
	
	base = (void *)hrtimer_bases + SIZE(hrtimer_base) * num;
	readmem((ulong)(base + OFFSET(hrtimer_base_get_time)), KVADDR,
		&get_time, sizeof(get_time), "hrtimer_base get_time",
		FAULT_ON_ERROR);
	fprintf(fp, "  CLOCK: %d  HRTIMER_BASE: %lx  [%s]\n", num, 
		(ulong)base, value_to_symstr(get_time, buf, 0));

	/* get current time(uptime) */
	get_uptime(NULL, &current_time);
	now = current_time * (1000000000LL / machdep->hz);

	dump_active_timers(base, now);
}

static void
dump_active_timers(const void *base, ulonglong now)
{
	int next, i, t;
	struct rb_node *curr;
	int timer_cnt;
	ulong *timer_list;
	void  *timer;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char buf5[BUFSIZE];

	next = 0;
	timer_list = 0;

	/* search hrtimers */
	hq_open();
	timer_cnt = 0;
next_one:
	i = 0;

	/* get the first node */
	if (VALID_MEMBER(hrtimer_base_pending))
		readmem((ulong)(base + OFFSET(hrtimer_base_pending) -
			OFFSET(hrtimer_list) + OFFSET(hrtimer_node)),
			KVADDR, &curr, sizeof(curr), "hrtimer_base pending",
			FAULT_ON_ERROR);
	else if (VALID_MEMBER(hrtimer_base_first))
		readmem((ulong)(base + OFFSET(hrtimer_base_first)),
			KVADDR, &curr, sizeof(curr), "hrtimer_base first",
			FAULT_ON_ERROR);
	else if (VALID_MEMBER(hrtimer_clock_base_first))
		readmem((ulong)(base + OFFSET(hrtimer_clock_base_first)),
			KVADDR,	&curr, sizeof(curr), "hrtimer_clock_base first",
			FAULT_ON_ERROR);
	else if (VALID_MEMBER(timerqueue_head_next))
		readmem((ulong)(base + OFFSET(hrtimer_clock_base_active) +
				OFFSET(timerqueue_head_next)),
			KVADDR, &curr, sizeof(curr), "hrtimer_clock base",
			FAULT_ON_ERROR);
	else
		readmem((ulong)(base + OFFSET(hrtimer_clock_base_active) +
				OFFSET(timerqueue_head_rb_root) +
				OFFSET(rb_root_cached_rb_leftmost)),
			KVADDR, &curr, sizeof(curr),
			"hrtimer_clock_base active", FAULT_ON_ERROR);

	while (curr && i < next) {
		curr = rb_next(curr);
		i++;
	}

	if (curr) {
		if (!hq_enter((ulong)curr)) {
			error(INFO, "duplicate rb_node: %lx\n", curr);
			return;
		}

		timer_cnt++;
		next++;
		goto next_one;
	}

	if (timer_cnt) {
		timer_list = (ulong *)GETBUF(timer_cnt * sizeof(long));
		timer_cnt = retrieve_list(timer_list, timer_cnt);
	}
	hq_close();

	if (!timer_cnt) {
		fprintf(fp, "  (empty)\n");
		return;
	}

	/* dump hrtimers */
	/* print header */
	expires_len = get_expires_len(timer_cnt, timer_list, 0, 0);
	if (expires_len < 7)
		expires_len = 7;
	softexpires_len = get_expires_len(timer_cnt, timer_list, 0, 1);
	tte_len = get_expires_len(timer_cnt, timer_list, now, 2);

	if (softexpires_len > -1) {
		if (softexpires_len < 11)
			softexpires_len = 11;
		fprintf(fp, "  %s\n", mkstring(buf1, softexpires_len, CENTER|RJUST,
			"CURRENT")); 
		sprintf(buf1, "%lld", now);
		fprintf(fp, "  %s\n", mkstring(buf1, softexpires_len, 
			CENTER|RJUST, NULL));
		fprintf(fp, "  %s  %s  %s  %s  %s\n",
			mkstring(buf1, softexpires_len, CENTER|RJUST, "SOFTEXPIRES"),
			mkstring(buf2, expires_len, CENTER|RJUST, "EXPIRES"),
			mkstring(buf5, tte_len, CENTER|RJUST, "TTE"),
			mkstring(buf3, VADDR_PRLEN, CENTER|LJUST, "HRTIMER"),
			mkstring(buf4, VADDR_PRLEN, CENTER|LJUST, "FUNCTION"));
	} else {
		fprintf(fp, "  %s\n", mkstring(buf1, expires_len, CENTER|RJUST, 
			"CURRENT"));
		sprintf(buf1, "%lld", now);
		fprintf(fp, "  %s\n", mkstring(buf1, expires_len, CENTER|RJUST, NULL));
		fprintf(fp, "  %s  %s  %s  %s\n",
			mkstring(buf1, expires_len, CENTER|RJUST, "EXPIRES"),
			mkstring(buf5, tte_len, CENTER|RJUST, "TTE"),
			mkstring(buf2, VADDR_PRLEN, CENTER|LJUST, "HRTIMER"),
			mkstring(buf3, VADDR_PRLEN, CENTER|LJUST, "FUNCTION"));
	}

	/* print timers */
	for (t = 0; t < timer_cnt; t++) {
		if (VALID_MEMBER(timerqueue_node_node))
			timer = (void *)(timer_list[t] -
				OFFSET(timerqueue_node_node) -
				OFFSET(hrtimer_node));
		else
			timer = (void *)(timer_list[t] - OFFSET(hrtimer_node));

		print_timer(timer, now);
	}
}

static int
get_expires_len(const int timer_cnt, const ulong *timer_list, ulonglong now, const int getsoft)
{
	void *last_timer;
	char buf[BUFSIZE];
	ulonglong softexpires, expires;
	int len;

	len = -1;

	if (!timer_cnt)
		return len;

	if (VALID_MEMBER(timerqueue_node_node))
		last_timer = (void *)(timer_list[timer_cnt - 1] -
			OFFSET(timerqueue_node_node) -
			OFFSET(hrtimer_node));
	else
		last_timer = (void *)(timer_list[timer_cnt -1] -
			OFFSET(hrtimer_node));

	if (getsoft == 1) {
		/* soft expires exist*/
		if (VALID_MEMBER(hrtimer_softexpires)) {
			softexpires = ktime_to_ns(last_timer + 
				OFFSET(hrtimer_softexpires));
			sprintf(buf, "%lld", softexpires);
			len = strlen(buf);
		}
	} else {
		if (VALID_MEMBER(hrtimer_expires))
			expires = ktime_to_ns(last_timer + OFFSET(hrtimer_expires));
		else
			expires = ktime_to_ns(last_timer + OFFSET(hrtimer_node) +
				OFFSET(timerqueue_node_expires));

		sprintf(buf, "%lld", getsoft ? expires - now : expires);
		len = strlen(buf);
	}

	return len;
}

/*
 * print hrtimer and its related information
 */
static void
print_timer(const void *timer, ulonglong now)
{
	ulonglong softexpires, expires, tte;
	
	ulong function;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];

	/* align information */
	fprintf(fp, "  ");

	if (!accessible((ulong)timer)) {
		fprintf(fp, "(destroyed timer)\n");
		return;
	}

	if (VALID_MEMBER(hrtimer_expires))
		expires = ktime_to_ns(timer + OFFSET(hrtimer_expires));
	else
		expires = ktime_to_ns(timer + OFFSET(hrtimer_node) +
			OFFSET(timerqueue_node_expires));

	if (VALID_MEMBER(hrtimer_softexpires)) {
		softexpires = ktime_to_ns(timer + OFFSET(hrtimer_softexpires));
		sprintf(buf1, "%lld-%lld", softexpires, expires);
	}

	if (VALID_MEMBER(hrtimer_softexpires)) {
		softexpires = ktime_to_ns(timer + OFFSET(hrtimer_softexpires));
		sprintf(buf1, "%lld", softexpires);
		fprintf(fp, "%s  ",
			mkstring(buf2, softexpires_len, CENTER|RJUST, buf1));
	}

	sprintf(buf1, "%lld", expires);
	fprintf(fp, "%s  ", mkstring(buf2, expires_len, CENTER|RJUST, buf1));

	tte = expires - now;
	fprintf(fp, "%s  ", mkstring(buf4, tte_len, SLONG_DEC|RJUST, MKSTR((ulong)tte)));

	fprintf(fp, "%lx  ", (ulong)timer);

	if (readmem((ulong)(timer + OFFSET(hrtimer_function)), KVADDR, &function,
		sizeof(function), "hrtimer function", QUIET|RETURN_ON_ERROR)) {
		fprintf(fp, "%lx  ", function);
		fprintf(fp ,"<%s>", value_to_symstr(function, buf3, 0));
	}

	fprintf(fp, "\n");
}

/*
 * convert ktime to ns, only need the address of ktime
 */
static ulonglong
ktime_to_ns(const void *ktime)
{
	ulonglong ns;

	ns = 0;

	if (!accessible((ulong)ktime)) 
		return ns;

	if (VALID_MEMBER(ktime_t_tv64)) {
		readmem((ulong)ktime + OFFSET(ktime_t_tv64), KVADDR, &ns,
			sizeof(ns), "ktime_t tv64", QUIET|RETURN_ON_ERROR);
	} else if (VALID_MEMBER(ktime_t_sec) && VALID_MEMBER(ktime_t_nsec)) {
		uint32_t sec, nsec;

		sec = 0;
		nsec = 0;

		readmem((ulong)ktime + OFFSET(ktime_t_sec), KVADDR, &sec,
			sizeof(sec), "ktime_t sec", QUIET|RETURN_ON_ERROR);

		readmem((ulong)ktime + OFFSET(ktime_t_nsec), KVADDR, &nsec,
			sizeof(nsec), "ktime_t nsec", QUIET|RETURN_ON_ERROR);

		ns = sec * 1000000000L + nsec;
	} else {
		readmem((ulong)ktime, KVADDR, &ns,
			sizeof(ns), "ktime_t", QUIET|RETURN_ON_ERROR);
	}

	return ns;
}

/*
 *  Display the pending timer queue entries, both the old and new-style.
 */
struct timer_data {
	ulong address; 
	ulong expires;
	ulong function;
	long tte;
};

struct tv_range {
        ulong base;
        ulong end;
};

#define TVN (6)

static void
dump_timer_data(const ulong *cpus)
{
	int i;
	ulong timer_active;
	struct timer_struct {
        	unsigned long expires;
        	void *fn;
	} timer_table[32];
	char buf[BUFSIZE];
	char buf1[BUFSIZE];
	char buf4[BUFSIZE];
        struct timer_struct *tp;
        ulong mask, highest, highest_tte, function;
	ulong jiffies, timer_jiffies;
	ulong *vec;
	long count;
        int vec_root_size, vec_size;
	struct timer_data *td;
	int flen, tlen, tdx, old_timers_exist;
        struct tv_range tv[TVN];

	if (kt->flags2 & TIMER_BASES) {
		dump_timer_data_timer_bases(cpus);
		return;
	} else if (kt->flags2 & TVEC_BASES_V3) {
		dump_timer_data_tvec_bases_v3(cpus);
		return;
	} else if (kt->flags & TVEC_BASES_V2) {
		dump_timer_data_tvec_bases_v2(cpus);
		return;
	} else if (kt->flags & TVEC_BASES_V1) {
		dump_timer_data_tvec_bases_v1(cpus);
		return;
	}
		
	BZERO(tv, sizeof(struct tv_range) * TVN);

	vec_root_size = (i = ARRAY_LENGTH(timer_vec_root_vec)) ?
		i : get_array_length("timer_vec_root.vec", 
			NULL, SIZE(list_head));
	vec_size = (i = ARRAY_LENGTH(timer_vec_vec)) ? 
		i : get_array_length("timer_vec.vec", NULL, SIZE(list_head));

	vec = (ulong *)GETBUF(SIZE(list_head) * MAX(vec_root_size, vec_size));

	if (symbol_exists("timer_active") && symbol_exists("timer_table")) {
		get_symbol_data("timer_active", sizeof(ulong), &timer_active);
        	readmem(symbol_value("timer_table"), KVADDR, &timer_table,
                	sizeof(struct timer_struct) * 32, "timer_table[32]", 
			FAULT_ON_ERROR);
		old_timers_exist = TRUE;
	} else
		old_timers_exist = FALSE;

	/*
 	 * Get rough count first, and then gather a bunch of timer_data
	 * structs to stuff in a sortable array.
	 */

	count = 0;
        for (mask = 1, tp = timer_table+0; old_timers_exist && mask; 
	     tp++, mask += mask) {
                if (mask > timer_active)
                        break;
                if (!(mask & timer_active))
                        continue;
		count++;
        }

	init_tv_ranges(tv, vec_root_size, vec_size, 0);

        count += do_timer_list(symbol_value("tv1") + OFFSET(timer_vec_root_vec),
		vec_root_size, vec, NULL, NULL, NULL, tv, 0);
        count += do_timer_list(symbol_value("tv2") + OFFSET(timer_vec_vec),
		vec_size, vec, NULL, NULL, NULL, tv, 0);
        count += do_timer_list(symbol_value("tv3") + OFFSET(timer_vec_vec),
		vec_size, vec, NULL, NULL, NULL, tv, 0);
        count += do_timer_list(symbol_value("tv4") + OFFSET(timer_vec_vec),
		vec_size, vec, NULL, NULL, NULL, tv, 0);
        count += do_timer_list(symbol_value("tv4") + OFFSET(timer_vec_vec),
		vec_size, vec, NULL, NULL, NULL, tv, 0);

	td = (struct timer_data *)
		GETBUF((count*2) * sizeof(struct timer_data));
	tdx = 0;

	get_symbol_data("jiffies", sizeof(ulong), &jiffies);
	get_symbol_data("timer_jiffies", sizeof(ulong), &timer_jiffies);
	if (old_timers_exist)
		get_symbol_data("timer_active", sizeof(ulong), &timer_active);

	highest = 0;
	highest_tte = 0;
        for (i = 0, mask = 1, tp = timer_table+0; old_timers_exist && mask; 
	     i++, tp++, mask += mask) {
                if (mask > timer_active) 
                        break;

                if (!(mask & timer_active)) 
                        continue;

		td[tdx].address = i;
		td[tdx].expires = tp->expires;
		td[tdx].function = (ulong)tp->fn;
		td[tdx].tte = tp->expires - jiffies;
		if (td[tdx].expires > highest)
			highest = td[tdx].expires;
		if (abs(td[tdx].tte) > highest_tte)
			highest_tte = abs(td[tdx].tte);
		tdx++;
        }

	do_timer_list(symbol_value("tv1") + OFFSET(timer_vec_root_vec),
		vec_root_size, vec, (void *)td, &highest, &highest_tte, tv, jiffies);
	do_timer_list(symbol_value("tv2") + OFFSET(timer_vec_vec),
		vec_size, vec, (void *)td, &highest, &highest_tte, tv, jiffies);
	do_timer_list(symbol_value("tv3") + OFFSET(timer_vec_vec),
		vec_size, vec, (void *)td, &highest, &highest_tte, tv, jiffies);
	do_timer_list(symbol_value("tv4") + OFFSET(timer_vec_vec),
		vec_size, vec, (void *)td, &highest, &highest_tte, tv, jiffies);
	tdx = do_timer_list(symbol_value("tv5") + OFFSET(timer_vec_vec),
		vec_size, vec, (void *)td, &highest, &highest_tte, tv, jiffies);

        qsort(td, tdx, sizeof(struct timer_data), compare_timer_data);

	/*
	 *  Because the jiffies values can fluctuate wildly from dump to
	 *  dump, try to use the appropriate amount of space...
	 */
	sprintf(buf, "%ld", highest); 
	flen = MAX(strlen(buf), strlen("JIFFIES"));
	fprintf(fp, "%s\n", mkstring(buf, flen, CENTER|LJUST, "JIFFIES"));
	fprintf(fp, "%s\n", mkstring(buf, flen, RJUST|LONG_DEC,MKSTR(jiffies)));

	/* +1 accounts possible "-" sign */
	sprintf(buf4, "%ld", highest_tte);
	tlen = MAX(strlen(buf4) + 1, strlen("TTE"));

	fprintf(fp, "%s  %s  TIMER_LIST/TABLE  FUNCTION\n",
		mkstring(buf, flen, CENTER|LJUST, "EXPIRES"),
		mkstring(buf4, tlen, CENTER|LJUST, "TTE"));

        for (i = 0; i < tdx; i++) {
        	fprintf(fp, "%s", 
		    mkstring(buf, flen, RJUST|LONG_DEC, MKSTR(td[i].expires)));

                fprintf(fp, "  %s",
                    mkstring(buf4, tlen, RJUST|SLONG_DEC, MKSTR(td[i].tte)));

		if (td[i].address < 32) {
                        sprintf(buf, "timer_table[%ld]", td[i].address);
                        fprintf(fp, "  %s  ",
                                mkstring(buf, 16, CENTER|LJUST, NULL));
		} else {
			mkstring(buf1, VADDR_PRLEN, RJUST|LONG_HEX, 
				MKSTR(td[i].address));
			fprintf(fp, "  %s  ", mkstring(buf, 16, CENTER, buf1));
		}
		
		if (is_kernel_text(td[i].function)) 
			fprintf(fp, "%s  <%s>\n",
				mkstring(buf1, VADDR_PRLEN, RJUST|LONG_HEX, 
				MKSTR(td[i].function)),
                        	value_to_symstr(td[i].function, buf, 0));
		else {
			fprintf(fp, "%s  ", 
				mkstring(buf1, VADDR_PRLEN, RJUST|LONG_HEX, 
				MKSTR(td[i].function)));
                	if (readmem(td[i].function, KVADDR, &function,
                            sizeof(ulong), "timer function",
                            RETURN_ON_ERROR|QUIET)) {
				if (is_kernel_text(function))
					fprintf(fp, "<%s>",
					    value_to_symstr(function, buf, 0));
			} 
			fprintf(fp, "\n");
		}
        }
}

/*
 *  Newer per-cpu timers, using "tvec_bases".
 */

static void
dump_timer_data_tvec_bases_v1(const ulong *cpus)
{
	int i, cpu, tdx, flen, tlen;
        struct timer_data *td;
        int vec_root_size, vec_size;
        struct tv_range tv[TVN];
	ulong *vec, jiffies, highest, highest_tte, function;
	long count;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];

	/*
         */
        vec_root_size = (i = ARRAY_LENGTH(tvec_root_s_vec)) ?
                i : get_array_length("tvec_root_s.vec", NULL, SIZE(list_head));
        vec_size = (i = ARRAY_LENGTH(tvec_s_vec)) ?
                i : get_array_length("tvec_s.vec", NULL, SIZE(list_head));
        vec = (ulong *)GETBUF(SIZE(list_head) * MAX(vec_root_size, vec_size));

	cpu = 0;

next_cpu:
	if (cpus && !NUM_IN_BITMAP(cpus, cpu)) {
		if (++cpu < kt->cpus)
			goto next_cpu;
		return;
	}

        count = 0;
        td = (struct timer_data *)NULL;

	BZERO(tv, sizeof(struct tv_range) * TVN);

        init_tv_ranges(tv, vec_root_size, vec_size, cpu);

        count += do_timer_list(tv[1].base + OFFSET(tvec_root_s_vec),
                vec_root_size, vec, NULL, NULL, NULL, tv, 0);
        count += do_timer_list(tv[2].base + OFFSET(tvec_s_vec),
                vec_size, vec, NULL, NULL, NULL, tv, 0);
        count += do_timer_list(tv[3].base + OFFSET(tvec_s_vec),
                vec_size, vec, NULL, NULL, NULL, tv, 0);
        count += do_timer_list(tv[4].base + OFFSET(tvec_s_vec),
                vec_size, vec, NULL, NULL, NULL, tv, 0);
        count += do_timer_list(tv[5].base + OFFSET(tvec_s_vec),
                vec_size, vec, NULL, NULL, NULL, tv, 0);

	if (count)
        	td = (struct timer_data *)
                	GETBUF((count*2) * sizeof(struct timer_data));
        tdx = 0;
	highest = 0;
	highest_tte = 0;

        get_symbol_data("jiffies", sizeof(ulong), &jiffies);

        do_timer_list(tv[1].base + OFFSET(tvec_root_s_vec),
                vec_root_size, vec, (void *)td, &highest, &highest_tte, tv, jiffies);
        do_timer_list(tv[2].base + OFFSET(tvec_s_vec),
                vec_size, vec, (void *)td, &highest, &highest_tte, tv, jiffies);
        do_timer_list(tv[3].base + OFFSET(tvec_s_vec),
                vec_size, vec, (void *)td, &highest, &highest_tte, tv, jiffies);
        do_timer_list(tv[4].base + OFFSET(tvec_s_vec),
                vec_size, vec, (void *)td, &highest, &highest_tte, tv, jiffies);
        tdx = do_timer_list(tv[5].base + OFFSET(tvec_s_vec),
                vec_size, vec, (void *)td, &highest, &highest_tte, tv, jiffies);

        qsort(td, tdx, sizeof(struct timer_data), compare_timer_data);

	fprintf(fp, "TVEC_BASES[%d]: %lx\n", cpu,
        	symbol_value("tvec_bases") + (SIZE(tvec_t_base_s) * cpu));
		
        sprintf(buf1, "%ld", highest);
        flen = MAX(strlen(buf1), strlen("JIFFIES"));
        fprintf(fp, "%s\n", mkstring(buf1,flen, CENTER|RJUST, "JIFFIES"));
        fprintf(fp, "%s\n", mkstring(buf1,flen, 
		RJUST|LONG_DEC,MKSTR(jiffies)));

        /* +1 accounts possible "-" sign */
        sprintf(buf4, "%ld", highest_tte);
        tlen = MAX(strlen(buf4) + 1, strlen("TTE"));

	fprintf(fp, "%s  %s  %s  %s\n",
		mkstring(buf1, flen, CENTER|RJUST, "EXPIRES"),
		mkstring(buf4, tlen, CENTER|RJUST, "TTE"),
		mkstring(buf2, VADDR_PRLEN, CENTER|LJUST, "TIMER_LIST"),
		mkstring(buf3, VADDR_PRLEN, CENTER|LJUST, "FUNCTION"));

        for (i = 0; i < tdx; i++) {
                fprintf(fp, "%s",
                    mkstring(buf1, flen, RJUST|LONG_DEC, MKSTR(td[i].expires)));

                fprintf(fp, "  %s",
                    mkstring(buf4, tlen, RJUST|SLONG_DEC, MKSTR(td[i].tte)));

                fprintf(fp, "  %s  ", mkstring(buf1, 
			MAX(VADDR_PRLEN, strlen("TIMER_LIST")), 
			RJUST|CENTER|LONG_HEX, MKSTR(td[i].address)));

                if (is_kernel_text(td[i].function)) {
                        fprintf(fp, "%s  <%s>\n",
				mkstring(buf2, VADDR_PRLEN, RJUST|LONG_HEX,
				MKSTR(td[i].function)),
                                value_to_symstr(td[i].function, buf1, 0));
                } else {
                        fprintf(fp, "%s  ", mkstring(buf1, VADDR_PRLEN, 
				RJUST|LONG_HEX, MKSTR(td[i].function)));
                        if (readmem(td[i].function, KVADDR, &function,
                            sizeof(ulong), "timer function",
                            RETURN_ON_ERROR|QUIET)) {
                                if (is_kernel_text(function))
                                        fprintf(fp, "<%s>",
                                            value_to_symstr(function, buf1, 0));
                        }
                        fprintf(fp, "\n");
                }
        }

	if (td)
		FREEBUF(td);

	if (++cpu < kt->cpus)
		goto next_cpu;
}

/*
 *  2.6 per-cpu timers, using "per_cpu__tvec_bases".
 */

static void
dump_timer_data_tvec_bases_v2(const ulong *cpus)
{
	int i, cpu, tdx, flen, tlen;
        struct timer_data *td;
        int vec_root_size, vec_size;
        struct tv_range tv[TVN];
	ulong *vec, jiffies, highest, highest_tte, function;
	ulong tvec_bases;
	long count;
	struct syment *sp;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];

        vec_root_size = (i = ARRAY_LENGTH(tvec_root_s_vec)) ?
                i : get_array_length("tvec_root_s.vec", NULL, SIZE(list_head));
	if (!vec_root_size && 
	    (i = get_array_length("tvec_root.vec", NULL, SIZE(list_head))))
		vec_root_size = i;
	if (!vec_root_size)
		error(FATAL, "cannot determine tvec_root.vec[] array size\n");

        vec_size = (i = ARRAY_LENGTH(tvec_s_vec)) ?
                i : get_array_length("tvec_s.vec", NULL, SIZE(list_head));
	if (!vec_size &&
	    (i = get_array_length("tvec.vec", NULL, SIZE(list_head))))
		vec_size = i;
	if (!vec_size)
		error(FATAL, "cannot determine tvec.vec[] array size\n");

        vec = (ulong *)GETBUF(SIZE(list_head) * MAX(vec_root_size, vec_size));
	cpu = 0;

next_cpu:
	if (cpus && !NUM_IN_BITMAP(cpus, cpu)) {
		if (++cpu < kt->cpus)
			goto next_cpu;
		return;
	}
	/*
	 * hide data of offline cpu and goto next cpu
	 */

	if (hide_offline_cpu(cpu)) {
	        fprintf(fp, "TVEC_BASES[%d]: [OFFLINE]\n", cpu);
		if (++cpu < kt->cpus)
			goto next_cpu;
		return;
	}


	count = 0;
	td = (struct timer_data *)NULL;

	BZERO(tv, sizeof(struct tv_range) * TVN);

        init_tv_ranges(tv, vec_root_size, vec_size, cpu);

        count += do_timer_list(tv[1].base + OFFSET(tvec_root_s_vec),
                vec_root_size, vec, NULL, NULL, NULL, tv, 0);
        count += do_timer_list(tv[2].base + OFFSET(tvec_s_vec),
                vec_size, vec, NULL, NULL, NULL, tv, 0);
        count += do_timer_list(tv[3].base + OFFSET(tvec_s_vec),
                vec_size, vec, NULL, NULL, NULL, tv, 0);
        count += do_timer_list(tv[4].base + OFFSET(tvec_s_vec),
                vec_size, vec, NULL, NULL, NULL, tv, 0);
        count += do_timer_list(tv[5].base + OFFSET(tvec_s_vec),
                vec_size, vec, NULL, NULL, NULL, tv, 0);

	if (count)
        	td = (struct timer_data *)
                	GETBUF((count*2) * sizeof(struct timer_data));
        tdx = 0;
	highest = 0;
	highest_tte = 0;

        get_symbol_data("jiffies", sizeof(ulong), &jiffies);

        do_timer_list(tv[1].base + OFFSET(tvec_root_s_vec),
                vec_root_size, vec, (void *)td, &highest, &highest_tte, tv, jiffies);
        do_timer_list(tv[2].base + OFFSET(tvec_s_vec),
                vec_size, vec, (void *)td, &highest, &highest_tte, tv, jiffies);
        do_timer_list(tv[3].base + OFFSET(tvec_s_vec),
                vec_size, vec, (void *)td, &highest, &highest_tte, tv, jiffies);
        do_timer_list(tv[4].base + OFFSET(tvec_s_vec),
                vec_size, vec, (void *)td, &highest, &highest_tte, tv, jiffies);
        tdx = do_timer_list(tv[5].base + OFFSET(tvec_s_vec),
                vec_size, vec, (void *)td, &highest, &highest_tte, tv, jiffies);

        qsort(td, tdx, sizeof(struct timer_data), compare_timer_data);

	sp = per_cpu_symbol_search("per_cpu__tvec_bases");
        if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF))
                tvec_bases = sp->value + kt->__per_cpu_offset[cpu];
        else
                tvec_bases =  sp->value;

	if (symbol_exists("boot_tvec_bases")) {
		readmem(tvec_bases, KVADDR, &tvec_bases, sizeof(void *),
                        "per-cpu tvec_bases", FAULT_ON_ERROR);
        }

        fprintf(fp, "TVEC_BASES[%d]: %lx\n", cpu, tvec_bases);
		
        sprintf(buf1, "%ld", highest);
        flen = MAX(strlen(buf1), strlen("JIFFIES"));
        fprintf(fp, "%s\n", mkstring(buf1,flen, CENTER|RJUST, "JIFFIES"));
        fprintf(fp, "%s\n", mkstring(buf1,flen, 
		RJUST|LONG_DEC,MKSTR(jiffies)));

        /* +1 accounts possible "-" sign */
        sprintf(buf4, "%ld", highest_tte);
        tlen = MAX(strlen(buf4) + 1, strlen("TTE"));

	fprintf(fp, "%s  %s  %s  %s\n",
		mkstring(buf1, flen, CENTER|RJUST, "EXPIRES"),
		mkstring(buf4, tlen, CENTER|RJUST, "TTE"),
		mkstring(buf2, VADDR_PRLEN, CENTER|LJUST, "TIMER_LIST"),
		mkstring(buf3, VADDR_PRLEN, CENTER|LJUST, "FUNCTION"));

        for (i = 0; i < tdx; i++) {
                fprintf(fp, "%s",
                    mkstring(buf1, flen, RJUST|LONG_DEC, MKSTR(td[i].expires)));

                fprintf(fp, "  %s",
                    mkstring(buf4, tlen, RJUST|SLONG_DEC, MKSTR(td[i].tte)));

                fprintf(fp, "  %s  ", mkstring(buf1, 
			MAX(VADDR_PRLEN, strlen("TIMER_LIST")), 
			RJUST|CENTER|LONG_HEX, MKSTR(td[i].address)));

                if (is_kernel_text(td[i].function)) {
                        fprintf(fp, "%s  <%s>\n",
				mkstring(buf2, VADDR_PRLEN, RJUST|LONG_HEX,
				MKSTR(td[i].function)),
                                value_to_symstr(td[i].function, buf1, 0));
                } else {
                        fprintf(fp, "%s  ", mkstring(buf1, VADDR_PRLEN, 
				RJUST|LONG_HEX, MKSTR(td[i].function)));
                        if (readmem(td[i].function, KVADDR, &function,
                            sizeof(ulong), "timer function",
                            RETURN_ON_ERROR|QUIET)) {
                                if (is_kernel_text(function))
                                        fprintf(fp, "<%s>",
                                            value_to_symstr(function, buf1, 0));
                        }
                        fprintf(fp, "\n");
                }
        }

	if (td)
		FREEBUF(td);

	if (++cpu < kt->cpus)
		goto next_cpu;
}

/*
 *  Linux 4.2 timers use new tvec_root, tvec and timer_list structures
 */
static void
dump_timer_data_tvec_bases_v3(const ulong *cpus)
{
	int i, cpu, tdx, flen, tlen;
	struct timer_data *td;
	int vec_root_size, vec_size;
	struct tv_range tv[TVN];
	ulong *vec, jiffies, highest, highest_tte, function;
	ulong tvec_bases;
	long count, head_size;
	struct syment *sp;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];

	vec_root_size = vec_size = 0;

	if (STREQ(MEMBER_TYPE_NAME("tvec_root", "vec"), "list_head"))
		/* for RHEL7.6 or later */
		head_size = SIZE(list_head);
	else
		head_size = SIZE(hlist_head);

	if ((i = get_array_length("tvec_root.vec", NULL, head_size)))
		vec_root_size = i;
	else
		error(FATAL, "cannot determine tvec_root.vec[] array size\n");

	if ((i = get_array_length("tvec.vec", NULL, head_size)))
		vec_size = i;
	else
		error(FATAL, "cannot determine tvec.vec[] array size\n");

	vec = (ulong *)GETBUF(head_size * MAX(vec_root_size, vec_size));
	cpu = 0;

next_cpu:
	if (cpus && !NUM_IN_BITMAP(cpus, cpu)) {
		if (++cpu < kt->cpus)
			goto next_cpu;
		return;
	}
	/*
	 * hide data of offline cpu and goto next cpu
	 */
	if (hide_offline_cpu(cpu)) {
	        fprintf(fp, "TVEC_BASES[%d]: [OFFLINE]\n", cpu);
		if (++cpu < kt->cpus)
			goto next_cpu;
		return;
	}

	count = 0;
	td = (struct timer_data *)NULL;

	BZERO(tv, sizeof(struct tv_range) * TVN);
	init_tv_ranges(tv, vec_root_size, vec_size, cpu);

	count += do_timer_list_v3(tv[1].base + OFFSET(tvec_root_s_vec),
		vec_root_size, vec, NULL, NULL, NULL, 0, head_size);
	count += do_timer_list_v3(tv[2].base + OFFSET(tvec_s_vec),
		vec_size, vec, NULL, NULL, NULL, 0, head_size);
	count += do_timer_list_v3(tv[3].base + OFFSET(tvec_s_vec),
		vec_size, vec, NULL, NULL, NULL, 0, head_size);
	count += do_timer_list_v3(tv[4].base + OFFSET(tvec_s_vec),
		vec_size, vec, NULL, NULL, NULL, 0, head_size);
	count += do_timer_list_v3(tv[5].base + OFFSET(tvec_s_vec),
		vec_size, vec, NULL, NULL, NULL, 0, head_size);

	if (count)
		td = (struct timer_data *)
			GETBUF((count*2) * sizeof(struct timer_data));
	tdx = 0;
	highest = 0;
	highest_tte = 0;

	get_symbol_data("jiffies", sizeof(ulong), &jiffies);

	do_timer_list_v3(tv[1].base + OFFSET(tvec_root_s_vec), vec_root_size,
		vec, (void *)td, &highest, &highest_tte, jiffies, head_size);
	do_timer_list_v3(tv[2].base + OFFSET(tvec_s_vec), vec_size,
		vec, (void *)td, &highest, &highest_tte, jiffies, head_size);
	do_timer_list_v3(tv[3].base + OFFSET(tvec_s_vec), vec_size,
		vec, (void *)td, &highest, &highest_tte, jiffies, head_size);
	do_timer_list_v3(tv[4].base + OFFSET(tvec_s_vec), vec_size,
		vec, (void *)td, &highest, &highest_tte, jiffies, head_size);
	tdx = do_timer_list_v3(tv[5].base + OFFSET(tvec_s_vec), vec_size,
		vec, (void *)td, &highest, &highest_tte, jiffies, head_size);

	qsort(td, tdx, sizeof(struct timer_data), compare_timer_data);

	sp = per_cpu_symbol_search("per_cpu__tvec_bases");
	if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF))
		tvec_bases = sp->value + kt->__per_cpu_offset[cpu];
	else
		tvec_bases =  sp->value;

	fprintf(fp, "TVEC_BASES[%d]: %lx\n", cpu, tvec_bases);

	sprintf(buf1, "%ld", highest);
	flen = MAX(strlen(buf1), strlen("JIFFIES"));
	fprintf(fp, "%s\n", mkstring(buf1,flen, CENTER|RJUST, "JIFFIES"));
	fprintf(fp, "%s\n", mkstring(buf1,flen, 
		RJUST|LONG_DEC,MKSTR(jiffies)));

	/* +1 accounts possible "-" sign */
	sprintf(buf4, "%ld", highest_tte);
	tlen = MAX(strlen(buf4) + 1, strlen("TTE"));

	fprintf(fp, "%s  %s  %s  %s\n",
		mkstring(buf1, flen, CENTER|RJUST, "EXPIRES"),
		mkstring(buf4, tlen, CENTER|RJUST, "TTE"),
		mkstring(buf2, VADDR_PRLEN, CENTER|LJUST, "TIMER_LIST"),
		mkstring(buf3, VADDR_PRLEN, CENTER|LJUST, "FUNCTION"));

	for (i = 0; i < tdx; i++) {
		fprintf(fp, "%s",
			mkstring(buf1, flen, RJUST|LONG_DEC, MKSTR(td[i].expires)));

		fprintf(fp, "  %s",
			mkstring(buf4, tlen, RJUST|SLONG_DEC, MKSTR(td[i].tte)));

		fprintf(fp, "  %s  ", mkstring(buf1, 
			MAX(VADDR_PRLEN, strlen("TIMER_LIST")), 
			RJUST|CENTER|LONG_HEX, MKSTR(td[i].address)));

		if (is_kernel_text(td[i].function)) {
			fprintf(fp, "%s  <%s>\n",
				mkstring(buf2, VADDR_PRLEN, RJUST|LONG_HEX,
				MKSTR(td[i].function)),
				value_to_symstr(td[i].function, buf1, 0));
		} else {
			fprintf(fp, "%s  ", mkstring(buf1, VADDR_PRLEN, 
				RJUST|LONG_HEX, MKSTR(td[i].function)));
			if (readmem(td[i].function, KVADDR, &function,
			    sizeof(ulong), "timer function",
			    RETURN_ON_ERROR|QUIET)) {
				if (is_kernel_text(function))
					fprintf(fp, "<%s>",
						value_to_symstr(function, buf1, 0));
			}
			fprintf(fp, "\n");
		}
	}

	if (td)
		FREEBUF(td);

	if (++cpu < kt->cpus)
		goto next_cpu;
}

/*
 *  The comparison function must return an integer less  than,
 *  equal  to,  or  greater than zero if the first argument is
 *  considered to be respectively  less  than,  equal  to,  or
 *  greater than the second.  If two members compare as equal,
 *  their order in the sorted array is undefined.
 */

static int
compare_timer_data(const void *v1, const void *v2)
{
        struct timer_data *t1, *t2;

        t1 = (struct timer_data *)v1;
        t2 = (struct timer_data *)v2;

	return (t1->expires < t2->expires ? -1 :
		t1->expires == t2->expires ? 0 : 1);
}

/*
 *  Create the address range for each of the timer vectors.
 */
static void
init_tv_ranges(struct tv_range *tv, int vec_root_size, int vec_size, int cpu)
{
	ulong tvec_bases;
	struct syment *sp;

	if (kt->flags & TVEC_BASES_V1) {
                tv[1].base = symbol_value("tvec_bases") +
			(SIZE(tvec_t_base_s) * cpu) +
			OFFSET(tvec_t_base_s_tv1);
                tv[1].end = tv[1].base + SIZE(tvec_root_s);

                tv[2].base = tv[1].end;
                tv[2].end = tv[2].base + SIZE(tvec_s);

                tv[3].base = tv[2].end;
                tv[3].end = tv[3].base + SIZE(tvec_s);

                tv[4].base = tv[3].end;
                tv[4].end = tv[4].base + SIZE(tvec_s);

                tv[5].base = tv[4].end;
                tv[5].end = tv[5].base + SIZE(tvec_s);
	} else if ((kt->flags & TVEC_BASES_V2) ||
		   (kt->flags2 & TVEC_BASES_V3)) {
		sp = per_cpu_symbol_search("per_cpu__tvec_bases");
		if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF))
			tvec_bases = sp->value + kt->__per_cpu_offset[cpu];
		else		
			tvec_bases =  sp->value;

		if (symbol_exists("boot_tvec_bases")) {
			readmem(tvec_bases, KVADDR, &tvec_bases, sizeof(void *), 
				"per-cpu tvec_bases", FAULT_ON_ERROR);
		}

                tv[1].base = tvec_bases +
                        OFFSET(tvec_t_base_s_tv1);
                tv[1].end = tv[1].base + SIZE(tvec_root_s);

                tv[2].base = tv[1].end;
                tv[2].end = tv[2].base + SIZE(tvec_s);

                tv[3].base = tv[2].end;
                tv[3].end = tv[3].base + SIZE(tvec_s);

                tv[4].base = tv[3].end;
                tv[4].end = tv[4].base + SIZE(tvec_s);

                tv[5].base = tv[4].end;
                tv[5].end = tv[5].base + SIZE(tvec_s);
	} else {
		tv[1].base = symbol_value("tv1");
	        tv[1].end = tv[1].base + SIZE(timer_vec_root);
	
	        tv[2].base = symbol_value("tv2");
	        tv[2].end = tv[2].base + SIZE(timer_vec);
	
	        tv[3].base = symbol_value("tv3");
	        tv[3].end = tv[3].base + SIZE(timer_vec);
	
	        tv[4].base = symbol_value("tv4");
	        tv[4].end = tv[4].base + SIZE(timer_vec);
	
	        tv[5].base = symbol_value("tv5");
	        tv[5].end = tv[5].base + SIZE(timer_vec);
	}
}

#define IN_TV_RANGE(vaddr) \
	((((vaddr) >= tv[1].base) && ((vaddr) < tv[1].end)) || \
	 (((vaddr) >= tv[2].base) && ((vaddr) < tv[2].end)) || \
	 (((vaddr) >= tv[3].base) && ((vaddr) < tv[3].end)) || \
	 (((vaddr) >= tv[4].base) && ((vaddr) < tv[4].end)) || \
	 (((vaddr) >= tv[5].base) && ((vaddr) < tv[5].end)))

/*
 *  Count, or stash, the entries of a linked timer_list -- depending
 *  upon the option value.
 */
static int
do_timer_list(ulong vec_kvaddr,
	      int size, 
	      ulong *vec, 
	      void *option, 
	      ulong *highest,
	      ulong *highest_tte,
	      struct tv_range *tv,
	      ulong jiffies)
{
	int i, t; 
	int count, tdx;
	ulong expires, function;
	struct timer_data *td;
	char *timer_list_buf;
	ulong *timer_list;
	int timer_cnt;
        struct list_data list_data, *ld;
	long sz;
	ulong offset = 0;

	tdx = 0;
	td = option ? (struct timer_data *)option : NULL;
	if (td) {
		while (td[tdx].function)
			tdx++;
	}

        if (VALID_MEMBER(timer_list_list))
		sz = SIZE(list_head) * size;
	else if (VALID_MEMBER(timer_list_entry))
		sz = SIZE(list_head) * size;
	else 
		sz = sizeof(ulong) * size;

        readmem(vec_kvaddr, KVADDR, vec, sz, "timer_list vec array",
                FAULT_ON_ERROR);

	if (VALID_MEMBER(timer_list_list)) {
		offset = OFFSET(timer_list_list);
		goto new_timer_list_format;
	}

	if (VALID_MEMBER(timer_list_entry)) {
		offset = OFFSET(timer_list_entry);
		goto new_timer_list_format;
	}

	if (VALID_MEMBER(timer_list_next))
		offset = OFFSET(timer_list_next);
	else
		error(FATAL, "no timer_list next, list, or entry members?\n");

	ld = &list_data;
	timer_list_buf = GETBUF(SIZE(timer_list));

        for (i = count = 0; i < size; i++) {
                if (vec[i]) {
			BZERO(ld, sizeof(struct list_data));
			ld->start = vec[i];
			ld->member_offset = offset;

			hq_open();
                	timer_cnt = do_list(ld);
			if (!timer_cnt) {
				hq_close();
				continue;
			}
                	timer_list = (ulong *)GETBUF(timer_cnt * sizeof(ulong));
                	timer_cnt = retrieve_list(timer_list, timer_cnt);
                	hq_close();

			for (t = 0; t < timer_cnt; t++) {
                                readmem(timer_list[t], KVADDR, timer_list_buf,
                                        SIZE(timer_list), "timer_list buffer",
                                        FAULT_ON_ERROR);

                                expires = ULONG(timer_list_buf +
                                        OFFSET(timer_list_expires));
                                function = ULONG(timer_list_buf +
                                        OFFSET(timer_list_function));

                                if (td) {
                                        td[tdx].address = timer_list[t];
                                        td[tdx].expires = expires;
                                        td[tdx].function = function;
                                        td[tdx].tte = expires - jiffies;
                                        if (highest && (expires > *highest))
                                                *highest = expires;
                                        if (highest_tte && (abs(td[tdx].tte) > *highest_tte))
                                                *highest_tte = abs(td[tdx].tte);
                                        tdx++;
                                }
			}
			FREEBUF(timer_list);
			count += timer_cnt;
        	}
	}

	FREEBUF(timer_list_buf);

	return(td ? tdx : count);

new_timer_list_format:

	ld = &list_data;
	timer_list_buf = GETBUF(SIZE(timer_list));

        for (i = count = 0; i < (size*2); i += 2, 
	     vec_kvaddr += SIZE(list_head)) {

		if (vec[i] == vec_kvaddr)
			continue;

                BZERO(ld, sizeof(struct list_data));
                ld->start = vec[i];
                ld->list_head_offset = offset;
		ld->end = vec_kvaddr;
		ld->flags = RETURN_ON_LIST_ERROR;

                hq_open();
		if ((timer_cnt = do_list(ld)) == -1) {
			/* Ignore chains with errors */
			error(INFO, 
	      	      "ignoring faulty timer list at index %d of timer array\n",
				i/2);
			continue; 
		}
                if (!timer_cnt)
                	continue;
                timer_list = (ulong *)GETBUF(timer_cnt * sizeof(ulong));
                timer_cnt = retrieve_list(timer_list, timer_cnt);
                hq_close();

                for (t = 0; t < timer_cnt; t++) {
			if (IN_TV_RANGE(timer_list[t]))
				break;

			count++;

                        readmem(timer_list[t], KVADDR, timer_list_buf,
                                SIZE(timer_list), "timer_list buffer",
                                FAULT_ON_ERROR);

                        expires = ULONG(timer_list_buf + 
				OFFSET(timer_list_expires));
                        function = ULONG(timer_list_buf +
                        	OFFSET(timer_list_function));

                        if (td) {
                                td[tdx].address = timer_list[t];
                                td[tdx].expires = expires;
                                td[tdx].function = function;
                                td[tdx].tte = expires - jiffies;
                                if (highest && (expires > *highest))
                                        *highest = expires;
                                if (highest_tte && (abs(td[tdx].tte) > *highest_tte))
                                        *highest_tte = abs(td[tdx].tte);
                                tdx++;
                        }
		}
		FREEBUF(timer_list);
	}

	FREEBUF(timer_list_buf);

	return(td ? tdx : count);
}

static int
do_timer_list_v3(ulong vec_kvaddr,
	      int size, 
	      ulong *vec, 
	      void *option, 
	      ulong *highest,
	      ulong *highest_tte,
	      ulong jiffies,
	      long head_size)
{
	int i, t; 
	int count, tdx;
	ulong expires, function;
	struct timer_data *td;
	char *timer_list_buf;
	ulong *timer_list;
	int timer_cnt;
	struct list_data list_data, *ld;

	tdx = 0;
	td = option ? (struct timer_data *)option : NULL;
	if (td) {
		while (td[tdx].function)
			tdx++;
	}

	readmem(vec_kvaddr, KVADDR, vec, head_size * size,
		"timer_list vec array", FAULT_ON_ERROR);

	ld = &list_data;
	timer_list_buf = GETBUF(SIZE(timer_list));

	for (i = count = 0; i < size; i++, vec_kvaddr += head_size) {

		if (head_size == SIZE(list_head)) {
			if (vec[i*2] == vec_kvaddr)
				continue;
		} else {
			if (vec[i] == 0)
				continue;
		}

		BZERO(ld, sizeof(struct list_data));
		ld->start = (head_size == SIZE(list_head)) ? vec[i*2] : vec[i];
		ld->list_head_offset = OFFSET(timer_list_entry);
		ld->end = vec_kvaddr;
		ld->flags = RETURN_ON_LIST_ERROR;

		hq_open();
		if ((timer_cnt = do_list(ld)) == -1) {
			/* Ignore chains with errors */
			error(INFO, 
		      "ignoring faulty timer list at index %d of timer array\n", i);
			continue; 
		}
		if (!timer_cnt) {
			hq_close();
			continue;
		}
		timer_list = (ulong *)GETBUF(timer_cnt * sizeof(ulong));
		timer_cnt = retrieve_list(timer_list, timer_cnt);
		hq_close();

		for (t = 0; t < timer_cnt; t++) {
			count++;

			readmem(timer_list[t], KVADDR, timer_list_buf,
				SIZE(timer_list), "timer_list buffer",
				FAULT_ON_ERROR);

			expires = ULONG(timer_list_buf + 
				OFFSET(timer_list_expires));
			function = ULONG(timer_list_buf +
				OFFSET(timer_list_function));

			if (td) {
				td[tdx].address = timer_list[t];
				td[tdx].expires = expires;
				td[tdx].function = function;
				td[tdx].tte = expires - jiffies;
				if (highest && (expires > *highest))
					*highest = expires;
				if (highest_tte && (abs(td[tdx].tte) > *highest_tte))
					*highest_tte = abs(td[tdx].tte);
				tdx++;
			}
		}
		FREEBUF(timer_list);
	}

	FREEBUF(timer_list_buf);

	return(td ? tdx : count);
}

#define TIMERS_CHUNK (100)

struct timer_bases_data {
	int total, cnt, num_vectors;
	ulong *vectors;
	ulong timer_base;
	struct timer_data *timers; 
};

static int
do_timer_list_v4(struct timer_bases_data *data, ulong jiffies)
{
	int i, t, timer_cnt, found;
	struct list_data list_data, *ld;
	ulong *timer_list;
	ulong expires, function;
	long oldsize;
	char *timer_list_buf;

	timer_list_buf = GETBUF(SIZE(timer_list));
	ld = &list_data;

	for (i = found = 0; i < data->num_vectors; i++) {
		if (data->vectors[i] == 0)
			continue;

		if (CRASHDEBUG(1))
			fprintf(fp, "%lx vectors[%d]: %lx\n", 
			    data->timer_base + OFFSET(timer_base_vectors) + (i * sizeof(void *)), 
				i, data->vectors[i]);

		BZERO(ld, sizeof(struct list_data));
		ld->start = data->vectors[i];
		ld->list_head_offset = OFFSET(timer_list_entry);
		ld->end = 0;
		ld->flags = RETURN_ON_LIST_ERROR;

		hq_open();
		if ((timer_cnt = do_list(ld)) == -1) {
			/* Ignore chains with errors */
			if (CRASHDEBUG(1))
				error(INFO, 
		"ignoring faulty timer_list in timer_base.vector[%d] list\n",
					i);
			hq_close();
			continue; 
		}
		if (!timer_cnt) {
			hq_close();
			continue;
		}

		timer_list = (ulong *)GETBUF(timer_cnt * sizeof(ulong));
		timer_cnt = retrieve_list(timer_list, timer_cnt);
		hq_close();

		for (t = 0; t < timer_cnt; t++) {
			if (CRASHDEBUG(1))
				fprintf(fp, "  %lx\n", timer_list[t]);

			if (!readmem(timer_list[t], KVADDR, timer_list_buf,
			    SIZE(timer_list), "timer_list buffer", QUIET|RETURN_ON_ERROR))
				continue;

			expires = ULONG(timer_list_buf + OFFSET(timer_list_expires));
			function = ULONG(timer_list_buf + OFFSET(timer_list_function));

			data->timers[data->cnt].address = timer_list[t];
			data->timers[data->cnt].expires = expires;
			data->timers[data->cnt].function = function;
			data->timers[data->cnt].tte = expires - jiffies;
			data->cnt++;

			if (data->cnt == data->total) {
				oldsize = data->total * sizeof(struct timer_data);
				RESIZEBUF(data->timers, oldsize, oldsize * 2);
				data->total *= 2;
			}

			found++;
	 	}

		FREEBUF(timer_list);

	}

	FREEBUF(timer_list_buf);

	return found;
}

/*
 *  Linux 4.8 timers use new timer_bases[][]
 */
static void
dump_timer_data_timer_bases(const ulong *cpus)
{
	int i, cpu, flen, tlen, base, nr_bases, found, display, j = 0;
	struct syment *sp;
	ulong timer_base, jiffies, function, highest_tte;
	struct timer_bases_data data;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf4[BUFSIZE];

	if (!(data.num_vectors = get_array_length("timer_base.vectors", NULL, 0)))
		error(FATAL, "cannot determine timer_base.vectors[] array size\n");
	data.vectors = (ulong *)GETBUF(data.num_vectors * sizeof(void *));
	data.timers = (struct timer_data *)GETBUF(sizeof(struct timer_data) * TIMERS_CHUNK);
	data.total = TIMERS_CHUNK;
	data.cnt = 0;

	nr_bases = kernel_symbol_exists("sysctl_timer_migration") ? 2 : 1;
	cpu = 0;

	get_symbol_data("jiffies", sizeof(ulong), &jiffies);
	sprintf(buf1, "%ld", jiffies);
	flen = MAX(strlen(buf1), strlen("JIFFIES"));
	fprintf(fp, "%s\n", mkstring(buf1, flen, LJUST, "JIFFIES"));
	fprintf(fp, "%s\n\n", mkstring(buf1, flen,
		RJUST|LONG_DEC,MKSTR(jiffies)));

next_cpu:
	if (cpus && !NUM_IN_BITMAP(cpus, cpu)) {
		if (++cpu < kt->cpus)
			goto next_cpu;
		goto done;
	}
	/*
	 * hide data of offline cpu and goto next cpu
	 */
	if (hide_offline_cpu(cpu)) {
		fprintf(fp, "TIMER_BASES[%d]: [OFFLINE]\n", cpu);
		if (++cpu < kt->cpus)
			goto next_cpu;
		goto done;
	}

	base = 0;

	sp = per_cpu_symbol_search("per_cpu__timer_bases");
	if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF))
		timer_base = sp->value + kt->__per_cpu_offset[cpu];
	else
		timer_base = sp->value;

	if (j++)
		fprintf(fp, "\n");
next_base:

	fprintf(fp, "TIMER_BASES[%d][%s]: %lx\n", cpu,  
		base == 0 ? "BASE_STD" : "BASE_DEF", timer_base);

	readmem(timer_base + OFFSET(timer_base_vectors), KVADDR, data.vectors, 
		data.num_vectors * sizeof(void *), "timer_base.vectors[]", FAULT_ON_ERROR); 
	data.cnt = 0;
	data.timer_base = timer_base;

	found = do_timer_list_v4(&data, jiffies);
	
	qsort(data.timers, found, sizeof(struct timer_data), compare_timer_data);

	highest_tte = 0;
	for (i = 0; i < found; i++) {
	    display = FALSE;

	    if (is_kernel_text(data.timers[i].function)) {
		display = TRUE;
	    } else {
		if (readmem(data.timers[i].function, KVADDR, &function,
		    sizeof(ulong), "timer function",
		    RETURN_ON_ERROR|QUIET) && is_kernel_text(function)) {
		    display = TRUE;
		} else {
                    if (LIVE())
			display = FALSE;
		    else
			display = TRUE;
		}
	    }

	    if (display) {
		if (abs(data.timers[i].tte) > highest_tte)
		    highest_tte = abs(data.timers[i].tte);
	    }
	}

	/* +1 accounts possible "-" sign */
	sprintf(buf4, "%ld", highest_tte);
	tlen = MAX(strlen(buf4) + 1, strlen("TTE"));

	fprintf(fp, "  %s     %s     TIMER_LIST     FUNCTION\n",
		mkstring(buf1, flen, LJUST, "EXPIRES"),
		mkstring(buf4, tlen, LJUST, "TTE"));

	for (i = 0; i < found; i++) {
		display = FALSE;

		if (is_kernel_text(data.timers[i].function)) {
			display = TRUE;
			function = data.timers[i].function;
		} else {
			if (readmem(data.timers[i].function, KVADDR, &function,
			    sizeof(ulong), "timer function",
			    RETURN_ON_ERROR|QUIET) && is_kernel_text(function))
				display = TRUE;
			else {
				if (LIVE()) {
					if (CRASHDEBUG(1))
						fprintf(fp, "(invalid/stale entry at %lx)\n", 
							data.timers[i].address);
					display = FALSE;
				} else {
					function = data.timers[i].function;
					display = TRUE;
				}
			}
		}

		if (display) {
			fprintf(fp, "  %s", 
				mkstring(buf1, flen, RJUST|LONG_DEC, MKSTR(data.timers[i].expires)));
			fprintf(fp, "  %s",
				mkstring(buf4, tlen, RJUST|SLONG_DEC, MKSTR(data.timers[i].tte)));
			mkstring(buf1, VADDR_PRLEN, RJUST|LONG_HEX, MKSTR(data.timers[i].address));
			fprintf(fp, "  %s  ", mkstring(buf2, 16, CENTER, buf1));
			fprintf(fp, "%s  <%s>\n",
				mkstring(buf1, VADDR_PRLEN, RJUST|LONG_HEX, 
				MKSTR(data.timers[i].function)),
				value_to_symstr(function, buf2, 0));
		}
	}

	if (!found)
		fprintf(fp, "  (none)\n");

	if ((nr_bases == 2) && (base == 0)) {
		base++;
		timer_base += SIZE(timer_base);
		goto next_base;
	}

	if (++cpu < kt->cpus)
		goto next_cpu;
done:
	FREEBUF(data.vectors);
	FREEBUF(data.timers);
}


/*
 *  Panic a live system by exploiting this code in do_exit():
 *
 *      if (!tsk->pid)
 *              panic("Attempted to kill the idle task!");
 *
 *  by writing a zero to this task's pid number.  If the write
 *  succeeds, the subsequent exit() call will invoke the panic.
 */
static void
panic_this_kernel(void)
{
	pid_t zero_pid = 0;

	if (!LOCAL_ACTIVE())
		error(FATAL, "cannot panic a dumpfile!\n");

	if (!(pc->flags & MFD_RDWR) || (pc->flags & MEMMOD))
		error(FATAL, "cannot write to %s\n", pc->live_memsrc);

	writemem(pid_to_task(pc->program_pid) + OFFSET(task_struct_pid), KVADDR,
		&zero_pid, sizeof(pid_t), "zero pid", FAULT_ON_ERROR);

	clean_exit(0);
}

/*
 *  Dump the list of entries on a wait queue, taking into account the two
 *  different definitions: wait_queue vs. __wait_queue (wait_queue_t).
 */
void
cmd_waitq(void)
{
	ulong q = 0;
	char *wq_name = NULL;		/* name of symbol which is a waitq */
	char *wq_struct = NULL;		/* struct containing the waitq */
	char *wq_member = NULL;		/* member of struct which is a waitq */
	int recd_address = 0;

	if (argcnt < 2 || argcnt > 3) {
		cmd_usage(pc->curcmd, SYNOPSIS);
	}

	if (IS_A_NUMBER(args[1])) {
		q = htol(args[1], FAULT_ON_ERROR, NULL);
		recd_address = 1;
	} else {
		/*
		 * We weren't given a number... see if it is the name of
		 * a symbol or and struct.member format.
		 */
		char *dot;

		dot = strstr(args[1], ".");
		if (dot == NULL) {
			wq_name = args[1];
			q = symbol_value(wq_name);
		} else {

			wq_struct = args[1];
			wq_member = dot+1;
			*dot = '\0';
			if (argcnt != 3) {
				fprintf(fp, "must supply an address for %s\n",
					wq_struct);
				return;
			}
			q = htol(args[2], FAULT_ON_ERROR, NULL);
			if (MEMBER_OFFSET(wq_struct, wq_member) == -1) {
				fprintf(fp, "%s is not a member of %s\n",
					wq_member, wq_struct);
				return;
			}
			q += MEMBER_OFFSET(wq_struct, wq_member);
		}
	}

	if (q != 0 && IS_KVADDR(q)) {
		/*
		 * If we weren't passed in an address and we're dealing
		 * with old style wait_queue, we must dereference the pointer
		 * and pass in the addr of the first elem on the queue.
		 * If we were supplied an address, assume the user knows
		 * what should be provided.
		 */
		if (!recd_address && VALID_STRUCT(wait_queue)) {
			ulong first_elem;
			readmem(q, KVADDR, &first_elem, sizeof(q),
				"wait queue pointer", FAULT_ON_ERROR);
			if (first_elem == 0) {
				fprintf(fp, "wait queue %lx is empty\n", q);
				return;
			} else {
				q = first_elem;
			}
		}
		dump_waitq(q, wq_name);
	}
}

static void
dump_waitq(ulong wq, char *wq_name)
{
	struct list_data list_data, *ld;
	ulong *wq_list;			/* addr of wait queue element */
	ulong next_offset;		/* next pointer of wq element */
	ulong task_offset = 0;		/* offset of task in wq element */
	int cnt;			/* # elems on Queue */
	int start_index = -1;		/* where to start in wq array */
	int i;

	ld = &list_data;
	BZERO(ld, sizeof(*ld));

	/*
	 * setup list depending on how the wait queues are organized.
	 */
	if (VALID_STRUCT(wait_queue)) {
		task_offset = OFFSET(wait_queue_task);
		next_offset = OFFSET(wait_queue_next);
		ld->end = wq;
		ld->start = wq;
		ld->member_offset = next_offset;
		ld->list_head_offset = task_offset;

		start_index = 0;
	} else if (VALID_STRUCT(__wait_queue)) {
		ulong task_list_offset;

                next_offset = OFFSET(list_head_next);
                task_offset = OFFSET(__wait_queue_task);
                task_list_offset = OFFSET(__wait_queue_head_task_list);
                ld->end = ld->start = wq + task_list_offset + next_offset;
                ld->list_head_offset = OFFSET(__wait_queue_task_list);
                ld->member_offset = next_offset;

		start_index = 1;
	} else if (VALID_STRUCT(wait_queue_entry)) {
		ulong head_offset;

		next_offset = OFFSET(list_head_next);
		task_offset = OFFSET(wait_queue_entry_private);
		head_offset = OFFSET(wait_queue_head_head);
		ld->end = ld->start = wq + head_offset + next_offset;
		ld->list_head_offset = OFFSET(wait_queue_entry_entry);
		ld->member_offset = next_offset;

		start_index = 1;
	} else {
		error(FATAL, "cannot determine wait queue structures\n");
	}

	hq_open();

	cnt = do_list(ld);
	if (cnt <= 1) {
		/*
		 * Due to the queueing of wait queues, list count returns
		 * an extra number of list entries:
		 * - in the case of a wait_queue_head_t, there is the
		 *   the list_entry in that structure;
		 * - in the case of a simple wait_queue, we have the
		 *   pointer back to the wait_queue head (see the
		 *   WAIT_QUEUE_HEAD macro in 2.2 systems).
		 */
		if (wq_name)
			fprintf(fp, "wait queue \"%s\" (%lx) is empty\n", 
				wq_name, wq);
		else
			fprintf(fp, "wait queue %lx is empty\n", wq);
		hq_close();
		return;
	}

	wq_list = (ulong *) GETBUF(cnt * sizeof(ulong));
	cnt = retrieve_list(wq_list, cnt);

	for (i = start_index; i < cnt; i++) {
		struct task_context *tc;
		ulong task;

		readmem(wq_list[i] + task_offset, KVADDR, &task,
			sizeof(void *), "wait_queue_t.task", FAULT_ON_ERROR);

		if ((tc = task_to_context(task)) || 
		    (tc = task_to_context(stkptr_to_task(task)))) {
			print_task_header(fp, tc, 0);
		} else {
			break;
		}
	}

	hq_close();
}

/*
 *  If active, clear the references to the last page tables read.
 */
void
clear_machdep_cache(void)
{
	if (ACTIVE()) {
		machdep->last_pgd_read = 0;
		machdep->last_pmd_read = 0;
		machdep->last_ptbl_read = 0;
		if (machdep->clear_machdep_cache)
			machdep->clear_machdep_cache();
	}
}

/*
 *  If it exists, return the number of cpus in the cpu_online_map.
 */
int
get_cpus_online()
{
	int i, len, online;
	char *buf;
	ulong *maskptr, addr;

	if (!(addr = cpu_map_addr("online")))
		return 0;

	len = cpu_map_size("online");
	buf = GETBUF(len);

	online = 0;

        if (readmem(addr, KVADDR, buf, len, 
	    "cpu_online_map", RETURN_ON_ERROR)) {

		maskptr = (ulong *)buf;
		for (i = 0; i < (len/sizeof(ulong)); i++, maskptr++)
			online += count_bits_long(*maskptr);

		if (CRASHDEBUG(1))
			error(INFO, "get_cpus_online: online: %d\n", online);
	}

	FREEBUF(buf);

	return online;
}

/*
 *  Check whether a cpu is offline
 */
int
check_offline_cpu(int cpu)
{
	if (!cpu_map_addr("online"))
		return FALSE;

	if (in_cpu_map(ONLINE_MAP, cpu))
		return FALSE;

	return TRUE;
}

/*
 *  Check whether the data related to the specified cpu should be hidden.
 */
int
hide_offline_cpu(int cpu)
{
	if (!(pc->flags2 & OFFLINE_HIDE))
		return FALSE;

	return check_offline_cpu(cpu);
}

/*
 *  If it exists, return the highest cpu number in the cpu_online_map.
 */
int
get_highest_cpu_online()
{
	int i, len;
	char *buf;
	ulong *maskptr, addr;
	int high, highest;

	if (!(addr = cpu_map_addr("online")))
		return -1;

	len = cpu_map_size("online");
	buf = GETBUF(len);
	highest = -1;

        if (readmem(addr, KVADDR, buf, len, 
	    "cpu_online_map", RETURN_ON_ERROR)) {

		maskptr = (ulong *)buf;
		for (i = 0; i < (len/sizeof(ulong)); i++, maskptr++) {
			if ((high = highest_bit_long(*maskptr)) < 0)
				continue;
			highest = high + (i * (sizeof(ulong)*8));
		}

		if (CRASHDEBUG(1))
			error(INFO, "get_highest_cpu_online: %d\n", highest);
	}

	FREEBUF(buf);

	return highest;
}

/*
 *  If it exists, return the number of cpus in the cpu_active_map.
 */
int
get_cpus_active()
{
	int i, len, active;
	char *buf;
	ulong *maskptr, addr;

	if (!(addr = cpu_map_addr("active")))
		return 0;

	len = cpu_map_size("active");
	buf = GETBUF(len);

	active = 0;

	if (readmem(addr, KVADDR, buf, len,
		"cpu_active_map", RETURN_ON_ERROR)) {

		maskptr = (ulong *)buf;
		for (i = 0; i < (len/sizeof(ulong)); i++, maskptr++)
			active += count_bits_long(*maskptr);

		if (CRASHDEBUG(1))
			error(INFO, "get_cpus_active: active: %d\n", active);
	}

	FREEBUF(buf);

	return active;
}

/*
 *  If it exists, return the number of cpus in the cpu_present_map.
 */
int
get_cpus_present()
{
	int i, len, present;
	char *buf;
	ulong *maskptr, addr;

	if (!(addr = cpu_map_addr("present"))) 
		return 0;

	len = cpu_map_size("present");
	buf = GETBUF(len);

	present = 0;

		if (readmem(addr, KVADDR, buf, len,
		    "cpu_present_map", RETURN_ON_ERROR)) {

		maskptr = (ulong *)buf;
		for (i = 0; i < (len/sizeof(ulong)); i++, maskptr++)
			present += count_bits_long(*maskptr);

		if (CRASHDEBUG(1))
			error(INFO, "get_cpus_present: present: %d\n", present);
	}

	FREEBUF(buf);

	return present;
}

/*
 *  If it exists, return the highest cpu number in the cpu_present_map.
 */
int
get_highest_cpu_present()
{
	int i, len;
	char *buf;
	ulong *maskptr, addr;
	int high, highest;

	if (!(addr = cpu_map_addr("present")))
		return -1;

	len = cpu_map_size("present");
	buf = GETBUF(len);
	highest = -1;

	if (readmem(addr, KVADDR, buf, len, 
	    "cpu_present_map", RETURN_ON_ERROR)) {

		maskptr = (ulong *)buf;
		for (i = 0; i < (len/sizeof(ulong)); i++, maskptr++) {
			if ((high = highest_bit_long(*maskptr)) < 0)
				continue;
			highest = high + (i * (sizeof(ulong)*8));
		}

		if (CRASHDEBUG(1))
			error(INFO, "get_highest_cpu_present: %d\n", highest);
	}

	FREEBUF(buf);

	return highest;
}

/*
 *  If it exists, return the number of cpus in the cpu_possible_map.
 */
int
get_cpus_possible()
{
	int i, len, possible;
	char *buf;
	ulong *maskptr, addr;

	if (!(addr = cpu_map_addr("possible")))
		return 0;

	len = cpu_map_size("possible");
	buf = GETBUF(len);

	possible = 0;

	if (readmem(addr, KVADDR, buf, len,
		"cpu_possible_map", RETURN_ON_ERROR)) {

		maskptr = (ulong *)buf;
		for (i = 0; i < (len/sizeof(ulong)); i++, maskptr++)
			possible += count_bits_long(*maskptr);

		if (CRASHDEBUG(1))
			error(INFO, "get_cpus_possible: possible: %d\n",
				possible);
	}

	FREEBUF(buf);

	return possible;
}

/*
 *  When displaying cpus, return the number of cpus online if possible, 
 *  otherwise kt->cpus.
 */
int
get_cpus_to_display(void)
{
	int online = get_cpus_online();

	return (online ? online : kt->cpus);
}

/*
 *  Xen machine-address to pseudo-physical-page translator.
 */ 
ulonglong
xen_m2p(ulonglong machine)
{
	ulong mfn, pfn;

	mfn = XEN_MACHINE_TO_MFN(machine);
	pfn = __xen_m2p(machine, mfn);

	if (pfn == XEN_MFN_NOT_FOUND) {
		if (CRASHDEBUG(1) && !STREQ(pc->curcmd, "search"))
			error(INFO, 
			    "xen_m2p: machine address %lx not found\n",
                           	 machine);
		return XEN_MACHADDR_NOT_FOUND;
	}

	return XEN_PFN_TO_PSEUDO(pfn);
}

static ulong
__xen_m2p(ulonglong machine, ulong mfn)
{
	ulong c, i, kmfn, mapping, p, pfn;
	ulong start, end;
	ulong *mp = (ulong *)kt->m2p_page;
	int memtype;

	if (XEN_CORE_DUMPFILE() && symbol_exists("xen_p2m_addr"))
		memtype = PHYSADDR;
	else
		memtype = KVADDR;

	/*
	 *  Check the FIFO cache first.
	 */
	for (c = 0; c < P2M_MAPPING_CACHE; c++) {
		if (kt->p2m_mapping_cache[c].mapping &&
		    ((mfn >= kt->p2m_mapping_cache[c].start) && 
		     (mfn <= kt->p2m_mapping_cache[c].end))) { 

			if (kt->p2m_mapping_cache[c].mapping != kt->last_mapping_read) {
				if (memtype == PHYSADDR)
					pc->curcmd_flags |= XEN_MACHINE_ADDR;

				read_p2m(c, memtype, mp);

				if (memtype == PHYSADDR)
					pc->curcmd_flags &= ~XEN_MACHINE_ADDR;
			} else
				kt->p2m_page_cache_hits++;

                	for (i = 0; i < XEN_PFNS_PER_PAGE; i++) {
				kmfn = (*(mp+i)) & ~XEN_FOREIGN_FRAME;
                        	if (kmfn == mfn) {
					p = P2M_MAPPING_PAGE_PFN(c);
					pfn = p + i;

                                	if (CRASHDEBUG(1))
                                    	    console("(cached) mfn: %lx (%llx) p: %ld"
                                        	" i: %ld pfn: %lx (%llx)\n",
						mfn, machine, p,
						i, pfn, XEN_PFN_TO_PSEUDO(pfn));
					kt->p2m_mfn_cache_hits++;

					return pfn;
				}
			}
			/*
			 *  Stale entry -- clear it out.
			 */
			kt->p2m_mapping_cache[c].mapping = 0;
		}
	}

	if (PVOPS_XEN()) {
		/*
		 *  The machine address was not cached, so search from the
		 *  beginning of the p2m tree/array, caching the contiguous
		 *  range containing the found machine address.
		 */
		if (symbol_exists("p2m_mid_missing"))
			pfn = __xen_pvops_m2p_l3(machine, mfn);
		else if (symbol_exists("xen_p2m_addr")) {
			if (XEN_CORE_DUMPFILE())
				pfn = __xen_pvops_m2p_hyper(machine, mfn);
			else
				pfn = __xen_pvops_m2p_domU(machine, mfn);
		} else
			pfn = __xen_pvops_m2p_l2(machine, mfn);

		if (pfn != XEN_MFN_NOT_FOUND)
			return pfn;
	} else {
		/*
		 *  The machine address was not cached, so search from the
		 *  beginning of the phys_to_machine_mapping array, caching
		 *  the contiguous range containing the found machine address.
		 */
		mapping = kt->phys_to_machine_mapping;

		for (p = 0; p < kt->p2m_table_size; p += XEN_PFNS_PER_PAGE) 
		{
			if (mapping != kt->last_mapping_read) {
				if (!readmem(mapping, KVADDR, mp, PAGESIZE(), 
			    	    "phys_to_machine_mapping page", 
				    RETURN_ON_ERROR))
					error(FATAL, 
				     	    "cannot access"
					    " phys_to_machine_mapping page\n");
				else
					kt->last_mapping_read = mapping;
			}
	
			kt->p2m_pages_searched++;
	
			if (search_mapping_page(mfn, &i, &start, &end)) {
				pfn = p + i;
				if (CRASHDEBUG(1))
				    console("pages: %d mfn: %lx (%llx) p: %ld"
					" i: %ld pfn: %lx (%llx)\n",
					(p/XEN_PFNS_PER_PAGE)+1, mfn, machine,
					p, i, pfn, XEN_PFN_TO_PSEUDO(pfn));
	
				c = kt->p2m_cache_index;
				kt->p2m_mapping_cache[c].start = start;
				kt->p2m_mapping_cache[c].end = end;
				kt->p2m_mapping_cache[c].mapping = mapping;
				kt->p2m_cache_index = (c+1) % P2M_MAPPING_CACHE;
	
				return pfn;
			}
	
			mapping += PAGESIZE();
		}
	}	

	if (CRASHDEBUG(1))
		console("machine address %llx not found\n", machine);
	
	return (XEN_MFN_NOT_FOUND);
}

static ulong
__xen_pvops_m2p_l2(ulonglong machine, ulong mfn)
{
	ulong c, e, end, i, mapping, p, p2m, pfn, start;

	for (e = p = 0, p2m = kt->pvops_xen.p2m_top;
	     e < kt->pvops_xen.p2m_top_entries;
	     e++, p += XEN_PFNS_PER_PAGE, p2m += sizeof(void *)) {

		if (!readmem(p2m, KVADDR, &mapping, sizeof(void *),
						"p2m_top", RETURN_ON_ERROR))
			error(FATAL, "cannot access p2m_top[] entry\n");

		if (mapping == kt->pvops_xen.p2m_missing)
			continue;

		if (mapping != kt->last_mapping_read) {
			if (!readmem(mapping, KVADDR, (void *)kt->m2p_page,
					PAGESIZE(), "p2m_top page", RETURN_ON_ERROR))
				error(FATAL, "cannot access p2m_top[] page\n");

			kt->last_mapping_read = mapping;
		}

		kt->p2m_pages_searched++;

		if (search_mapping_page(mfn, &i, &start, &end)) {
			pfn = p + i;
			if (CRASHDEBUG(1))
			    console("pages: %d mfn: %lx (%llx) p: %ld"
				" i: %ld pfn: %lx (%llx)\n",
				(p/XEN_PFNS_PER_PAGE)+1, mfn, machine,
				p, i, pfn, XEN_PFN_TO_PSEUDO(pfn));

			c = kt->p2m_cache_index;
			kt->p2m_mapping_cache[c].start = start;
			kt->p2m_mapping_cache[c].end = end;
			kt->p2m_mapping_cache[c].mapping = mapping;
			kt->p2m_mapping_cache[c].pfn = p;
			kt->p2m_cache_index = (c+1) % P2M_MAPPING_CACHE;

			return pfn;
		}
	}

	return XEN_MFN_NOT_FOUND;
}

static ulong
__xen_pvops_m2p_l3(ulonglong machine, ulong mfn)
{
	ulong c, end, i, j, k, mapping, p;
	ulong p2m_mid, p2m_top, pfn, start;

	p2m_top = kt->pvops_xen.p2m_top;

	for (i = 0; i < XEN_P2M_TOP_PER_PAGE; ++i, p2m_top += sizeof(void *)) {
		if (!readmem(p2m_top, KVADDR, &mapping,
				sizeof(void *), "p2m_top", RETURN_ON_ERROR))
			error(FATAL, "cannot access p2m_top[] entry\n");

		if (mapping == kt->pvops_xen.p2m_mid_missing)
			continue;

		p2m_mid = mapping;

		for (j = 0; j < XEN_P2M_MID_PER_PAGE; ++j, p2m_mid += sizeof(void *)) {
			if (!readmem(p2m_mid, KVADDR, &mapping,
					sizeof(void *), "p2m_mid", RETURN_ON_ERROR))
				error(FATAL, "cannot access p2m_mid[] entry\n");

			if (mapping == kt->pvops_xen.p2m_missing)
				continue;

			if (mapping != kt->last_mapping_read) {
				if (!readmem(mapping, KVADDR, (void *)kt->m2p_page,
						PAGESIZE(), "p2m_mid page", RETURN_ON_ERROR))
					error(FATAL, "cannot access p2m_mid[] page\n");

				kt->last_mapping_read = mapping;
			}

			if (!search_mapping_page(mfn, &k, &start, &end))
				continue;

			p = i * XEN_P2M_MID_PER_PAGE * XEN_P2M_PER_PAGE;
			p += j * XEN_P2M_PER_PAGE;
			pfn = p + k;

			if (CRASHDEBUG(1))
				console("pages: %d mfn: %lx (%llx) p: %ld"
					" i: %ld j: %ld k: %ld pfn: %lx (%llx)\n",
					(p / XEN_P2M_PER_PAGE) + 1, mfn, machine,
					p, i, j, k, pfn, XEN_PFN_TO_PSEUDO(pfn));

			c = kt->p2m_cache_index;
			kt->p2m_mapping_cache[c].start = start;
			kt->p2m_mapping_cache[c].end = end;
			kt->p2m_mapping_cache[c].mapping = mapping;
			kt->p2m_mapping_cache[c].pfn = p;
			kt->p2m_cache_index = (c + 1) % P2M_MAPPING_CACHE;

			return pfn;
		}
	}

	return XEN_MFN_NOT_FOUND;
}

static ulong
__xen_pvops_m2p_hyper(ulonglong machine, ulong mfn)
{
	ulong c, end, i, mapping, p, pfn, start;

	for (p = 0;
	     p < xkd->p2m_frames;
	     ++p) {

		mapping = PTOB(xkd->p2m_mfn_frame_list[p]);

		if (mapping != kt->last_mapping_read) {
			pc->curcmd_flags |= XEN_MACHINE_ADDR;
			if (!readmem(mapping, PHYSADDR, (void *)kt->m2p_page,
					PAGESIZE(), "p2m_mfn_frame_list page", RETURN_ON_ERROR))
				error(FATAL, "cannot access p2m_mfn_frame_list[] page\n");

			pc->curcmd_flags &= ~XEN_MACHINE_ADDR;
			kt->last_mapping_read = mapping;
		}

		kt->p2m_pages_searched++;

		if (search_mapping_page(mfn, &i, &start, &end)) {
			pfn = p * XEN_PFNS_PER_PAGE + i;
			if (CRASHDEBUG(1))
			    console("pages: %d mfn: %lx (%llx) p: %ld"
				" i: %ld pfn: %lx (%llx)\n", p + 1, mfn, machine,
				p, i, pfn, XEN_PFN_TO_PSEUDO(pfn));

			c = kt->p2m_cache_index;
			kt->p2m_mapping_cache[c].start = start;
			kt->p2m_mapping_cache[c].end = end;
			kt->p2m_mapping_cache[c].mapping = mapping;
			kt->p2m_mapping_cache[c].pfn = p * XEN_PFNS_PER_PAGE;
			kt->p2m_cache_index = (c+1) % P2M_MAPPING_CACHE;

			return pfn;
		}
	}

	return XEN_MFN_NOT_FOUND;
}

static void read_p2m(ulong cache_index, int memtype, void *buffer)
{
	/* 
	 *  Use special read function for PV domain p2m reading.
	 *  See the comments of read_xc_p2m().
	 */
	if (symbol_exists("xen_p2m_addr") && !XEN_CORE_DUMPFILE()) {
		if (!read_xc_p2m(kt->p2m_mapping_cache[cache_index].mapping, 
			buffer, PAGESIZE()))
			error(FATAL, "cannot access phys_to_machine_mapping page\n");
	} else if (!readmem(kt->p2m_mapping_cache[cache_index].mapping, memtype,
			buffer, PAGESIZE(), "phys_to_machine_mapping page (cached)",
			RETURN_ON_ERROR))
		error(FATAL, "cannot access phys_to_machine_mapping page\n");
	
	kt->last_mapping_read = kt->p2m_mapping_cache[cache_index].mapping;
}

/*
 *  PV domain p2m mapping info is stored in xd->xfd at xch_index_offset. It 
 *  is organized as struct xen_dumpcore_p2m and the pfns are progressively
 *  increased by 1 from 0.
 *
 *  This is a special p2m reading function for xen PV domain vmcores after
 *  kernel commit 054954eb051f35e74b75a566a96fe756015352c8 (xen: switch
 *  to linear virtual mapped sparse p2m list). It is invoked for reading
 *  p2m associate stuff by read_p2m().
 */
static int read_xc_p2m(ulonglong addr, void *buffer, long size)
{
	ulong i, new_p2m_buf_size;
	off_t offset;
	struct xen_dumpcore_p2m *new_p2m_buf;
	static struct xen_dumpcore_p2m *p2m_buf;
	static ulong p2m_buf_size = 0;

	if (size <= 0) {
		if ((CRASHDEBUG(1) && !STREQ(pc->curcmd, "search")) ||
			CRASHDEBUG(2))
			error(INFO, "invalid size request: %ld\n", size);
		return FALSE;
	}

	/* 
	 * We extract xen_dumpcore_p2m.gmfn and copy them into the 
	 * buffer. So, we need temporary p2m_buf whose size is 
	 * (size * (sizeof(struct xen_dumpcore_p2m) / sizeof(ulong)))
	 * to put xen_dumpcore_p2m structures read from xd->xfd.
	 */
	new_p2m_buf_size = size * (sizeof(struct xen_dumpcore_p2m) / sizeof(ulong));

	if (p2m_buf_size != new_p2m_buf_size) {
		p2m_buf_size = new_p2m_buf_size;

		new_p2m_buf = realloc(p2m_buf, p2m_buf_size);
		if (new_p2m_buf == NULL) {
			free(p2m_buf);
			error(FATAL, "cannot realloc p2m buffer\n");
		}
		p2m_buf = new_p2m_buf;
	}

	offset = addr * (sizeof(struct xen_dumpcore_p2m) / sizeof(ulong));
	offset += xd->xc_core.header.xch_index_offset;

	if (lseek(xd->xfd, offset, SEEK_SET) == -1)
		error(FATAL,
		    "cannot lseek to xch_index_offset offset 0x%lx\n", offset);
	if (read(xd->xfd, (void*)p2m_buf, p2m_buf_size) != p2m_buf_size)
		error(FATAL,
		    "cannot read from xch_index_offset offset 0x%lx\n", offset);

	for (i = 0; i < size / sizeof(ulong); i++)
		*((ulong *)buffer + i) = p2m_buf[i].gmfn;

	return TRUE;
}

static ulong
__xen_pvops_m2p_domU(ulonglong machine, ulong mfn)
{
	ulong c, end, i, mapping, p, pfn, start;

	/* 
	 * xch_nr_pages is the number of pages of p2m mapping. It is composed
	 * of struct xen_dumpcore_p2m. The stuff we want to copy into the mapping
	 * page is mfn whose type is unsigned long.
	 * So actual number of p2m pages should be:
	 *
	 * xch_nr_pages / (sizeof(struct xen_dumpcore_p2m) / sizeof(ulong))
	 */
	for (p = 0;
	     p < xd->xc_core.header.xch_nr_pages / 
		(sizeof(struct xen_dumpcore_p2m) / sizeof(ulong));
	     ++p) {

		mapping = p * PAGESIZE();

		if (mapping != kt->last_mapping_read) {
			if (!read_xc_p2m(mapping, (void *)kt->m2p_page, PAGESIZE()))
				error(FATAL, "cannot read the last mapping page\n");
			kt->last_mapping_read = mapping;
		}
		kt->p2m_pages_searched++;

		if (search_mapping_page(mfn, &i, &start, &end)) {
			pfn = p * XEN_PFNS_PER_PAGE + i;
			c = kt->p2m_cache_index;
			if (CRASHDEBUG (1))
				console("mfn: %lx (%llx) i: %ld pfn: %lx (%llx)\n",
					mfn, machine, i, pfn, XEN_PFN_TO_PSEUDO(pfn));

			kt->p2m_mapping_cache[c].start = start;
			kt->p2m_mapping_cache[c].end = end;
			kt->p2m_mapping_cache[c].mapping = mapping;
			kt->p2m_mapping_cache[c].pfn = p * XEN_PFNS_PER_PAGE;
			kt->p2m_cache_index = (c+1) % P2M_MAPPING_CACHE;
			
			return pfn;
		}
	}
	
	return XEN_MFN_NOT_FOUND;
}

/*
 *  Search for an mfn in the current mapping page, and if found, 
 *  determine the range of contiguous mfns that it's contained
 *  within (if any). 
 */
#define PREV_UP    0x1
#define NEXT_UP    0x2
#define PREV_DOWN  0x4
#define NEXT_DOWN  0x8

static int
search_mapping_page(ulong mfn, ulong *index, ulong *startptr, ulong *endptr)
{
	int n, found;
	ulong i, kmfn;
	ulong flags, start, end, next, prev, curr;
	ulong *mp;

	mp = (ulong *)kt->m2p_page;

	for (i = 0, found = FALSE; i < XEN_PFNS_PER_PAGE; i++) {
		kmfn = (*(mp+i)) & ~XEN_FOREIGN_FRAME;

		if (kmfn == mfn) {
			found = TRUE;
			*index = i;
			break;
		}
	}

	if (found) {
		flags = 0;
		next = prev = XEN_MFN_NOT_FOUND;
		start = end = kmfn;

		if (i)
			prev = (*(mp+(i-1))) & ~XEN_FOREIGN_FRAME;
		if ((i+1) != XEN_PFNS_PER_PAGE)
			next = (*(mp+(i+1))) & ~XEN_FOREIGN_FRAME;

		if (prev == (kmfn-1))
			flags |= PREV_UP;
		else if (prev == (kmfn+1))
			flags |= PREV_DOWN;

		if (next == (kmfn+1))
			flags |= NEXT_UP;
		else if (next == (kmfn-1))
			flags |= NEXT_DOWN;

		/*  Should be impossible, but just in case... */
		if ((flags & PREV_UP) && (flags & NEXT_DOWN))
			flags &= ~NEXT_DOWN;
		else if ((flags & PREV_DOWN) && (flags & NEXT_UP))
			flags &= ~NEXT_UP;

		if (flags & (PREV_UP|PREV_DOWN)) {
			start = prev;

			for (n = (i-2); n >= 0; n--) {
				curr = (*(mp+n)) & ~XEN_FOREIGN_FRAME;
				if (flags & PREV_UP) {
					if (curr == (start-1))
						start = curr;
				} else {
					if (curr == (start+1))
						start = curr;
				}
			}

		}

		if (flags & (NEXT_UP|NEXT_DOWN)) {
			end = next;

			for (n = (i+2); n < XEN_PFNS_PER_PAGE; n++) {
				curr = (*(mp+n)) & ~XEN_FOREIGN_FRAME;
				if (flags & NEXT_UP) {
					if (curr == (end+1))
						end = curr;
				} else {
					if (curr == (end-1))
						end = curr;
				}
			}


		}

		if (start > end) {
			curr = start;
			start = end;
			end = curr;	
		}

		*startptr = start;
		*endptr = end;

		if (CRASHDEBUG(2))
			fprintf(fp, "mfn: %lx -> start: %lx end: %lx (%ld mfns)\n", 
				mfn, start, end, end - start);
	}

	return found;
}

/*
 * IKCONFIG management.
 */
#define IKCONFIG_MAX		5000
static struct ikconfig_list {
	char *name;
	char *val;
} *ikconfig_all;

static int add_ikconfig_entry(char *line, struct ikconfig_list *ent)
{
	char *tokptr, *name, *val;

	name = strtok_r(line, "=", &tokptr);
	sscanf(name, "CONFIG_%s", name);
	val = strtok_r(NULL, "", &tokptr);

	if (!val) {
		if (CRASHDEBUG(2))
			error(WARNING, "invalid ikconfig entry: %s\n", line);
		return FALSE;
	}

	ent->name = strdup(name);
	ent->val = strdup(val);

	return TRUE;
}

static int setup_ikconfig(char *config)
{
	char *ent, *tokptr;
	struct ikconfig_list *new;

	ikconfig_all = calloc(1, sizeof(struct ikconfig_list) * IKCONFIG_MAX);
	if (!ikconfig_all) {
		error(WARNING, "cannot calloc for ikconfig entries.\n");
		return 0;
	}

	ent =  strtok_r(config, "\n", &tokptr);
	while (ent) {
		while (whitespace(*ent))
			ent++;

		if (STRNEQ(ent, "CONFIG_")) {
			if (add_ikconfig_entry(ent, &ikconfig_all[kt->ikconfig_ents]))
				kt->ikconfig_ents++;
			if (kt->ikconfig_ents == IKCONFIG_MAX) {
				error(WARNING, "ikconfig overflow.\n");
				return 1;
			}
		}
		ent = strtok_r(NULL, "\n", &tokptr);
	}
	if (kt->ikconfig_ents == 0) {
		free(ikconfig_all);
		return 0;
	}
	if ((new = realloc(ikconfig_all,
	    sizeof(struct ikconfig_list) * kt->ikconfig_ents)))
		ikconfig_all = new;

	return 1;
}

static void free_ikconfig(void)
{
	int i;

	for (i = 0; i < kt->ikconfig_ents; i++) {
		free(ikconfig_all[i].name);
		free(ikconfig_all[i].val);
	}
	free(ikconfig_all);
}

int get_kernel_config(char *conf_name, char **str)
{
	int i;
	int ret = IKCONFIG_N;
	char *name;

	if (!(kt->ikconfig_flags & IKCONFIG_AVAIL)) {
		error(WARNING, "CONFIG_IKCONFIG is not set\n");
		return ret;
	} else if (!(kt->ikconfig_flags & IKCONFIG_LOADED)) {
		read_in_kernel_config(IKCFG_SETUP);
		if (!(kt->ikconfig_flags & IKCONFIG_LOADED)) {
			error(WARNING, "IKCFG_SETUP failed\n");
			return ret;
		}
	}

	name = strdup(conf_name);
	if (!strncmp(name, "CONFIG_", strlen("CONFIG_")))
		sscanf(name, "CONFIG_%s", name);

	for (i = 0; i < kt->ikconfig_ents; i++) {
		if (STREQ(name, ikconfig_all[i].name)) {
			if (str)
				*str = ikconfig_all[i].val;
			if (STREQ(ikconfig_all[i].val, "y"))
				ret = IKCONFIG_Y;
			else if (STREQ(ikconfig_all[i].val, "m"))
				ret = IKCONFIG_M;
			else
				ret = IKCONFIG_STR;

			break;
		}
	}
	free(name);

	return ret;
}

/*
 *  Read the relevant IKCONFIG (In Kernel Config) data if available.
 */

static char *ikconfig[] = {
        "CONFIG_NR_CPUS",
        "CONFIG_PGTABLE_4",
        "CONFIG_HZ",
	"CONFIG_DEBUG_BUGVERBOSE",
	"CONFIG_DEBUG_INFO_REDUCED",
        NULL,
};

void
read_in_kernel_config(int command)
{
	struct syment *sp;
	int ii, jj, ret, end, found=0;
	unsigned long size, bufsz;
	uint64_t magic;
	char *pos, *ln, *buf, *head, *tail, *val, *uncomp;
	char line[512];
	z_stream stream;

	if ((kt->flags & NO_IKCONFIG) && !(pc->flags & RUNTIME))
		return;

	if ((sp = symbol_search("kernel_config_data")) == NULL) {
		if (command == IKCFG_READ)
			error(FATAL, 
			    "kernel_config_data does not exist in this kernel\n");
		else if (command == IKCFG_SETUP || command == IKCFG_FREE)
			error(WARNING, 
			    "kernel_config_data does not exist in this kernel\n");
		return;
	}
	
	/* We don't know how large IKCONFIG is, so we start with 
	 * 32k, if we can't find MAGIC_END assume we didn't read 
	 * enough, double it and try again.
	 */
	ii = 32;

again:
	size = ii * 1024;

	if ((buf = (char *)malloc(size)) == NULL) {
		error(WARNING, "cannot malloc IKCONFIG input buffer\n");
		return;
	}
	
        if (!readmem(sp->value, KVADDR, buf, size,
            "kernel_config_data", RETURN_ON_ERROR)) {
		error(WARNING, "cannot read kernel_config_data\n");
		goto out2;
	}
		
	/* Find the start */
	if (strstr(buf, MAGIC_START))
		head = buf + MAGIC_SIZE + 10; /* skip past MAGIC_START and gzip header */
	else {
		/*
		 *  Later versions put the magic number before the compressed data.
		 */
		if (readmem(sp->value - 8, KVADDR, &magic, 8,
            	    "kernel_config_data MAGIC_START", RETURN_ON_ERROR) &&
		    STRNEQ(&magic, MAGIC_START)) {
			head = buf + 10;
		} else {
			error(WARNING, "could not find MAGIC_START!\n");
			goto out2;
		}
	}

	tail = head;

	end = strlen(MAGIC_END);

	/* Find the end*/
	while (tail < (buf + (size - 1))) {
		
		if (strncmp(tail, MAGIC_END, end)==0) {
			found = 1;
			break;
		}
		tail++;
	}

	if (found) {
		bufsz = tail - head;
		size = 10 * bufsz;
		if ((uncomp = (char *)malloc(size)) == NULL) {
			error(WARNING, "cannot malloc IKCONFIG output buffer\n");
			goto out2;
		}
	} else {
		if (ii > 512) {
			error(WARNING, "could not find MAGIC_END!\n");
			goto out2;
		} else {
			free(buf);
			ii *= 2;
			goto again;
		}
	}


	/* initialize zlib */
	stream.next_in = (Bytef *)head;
	stream.avail_in = (uInt)bufsz;

	stream.next_out = (Bytef *)uncomp;
	stream.avail_out = (uInt)size;

	stream.zalloc = NULL;
	stream.zfree = NULL;
	stream.opaque = NULL;

	ret = inflateInit2(&stream, -MAX_WBITS);
	if (ret != Z_OK) {
		read_in_kernel_config_err(ret, "initialize");
		goto out1;
	}

	ret = inflate(&stream, Z_FINISH);

	if (ret != Z_STREAM_END) {
		inflateEnd(&stream);
		if (ret == Z_NEED_DICT || 
		   (ret == Z_BUF_ERROR && stream.avail_in == 0)) {
			read_in_kernel_config_err(Z_DATA_ERROR, "uncompress");
			goto out1;
		}
		read_in_kernel_config_err(ret, "uncompress");
		goto out1;
	}
	size = stream.total_out;

	ret = inflateEnd(&stream);

	pos = uncomp;

	if (command == IKCFG_INIT)
		kt->ikconfig_flags |= IKCONFIG_AVAIL;
	else if (command == IKCFG_SETUP) {
		if (!(kt->ikconfig_flags & IKCONFIG_LOADED)) {
			if (setup_ikconfig(pos)) {
				kt->ikconfig_flags |= IKCONFIG_LOADED;
				if (CRASHDEBUG(1))
					fprintf(fp,
					"ikconfig: %d valid configs.\n",
						kt->ikconfig_ents);
			} else
				error(WARNING, "IKCFG_SETUP failed\n\n");
		} else
			error(WARNING, 
				"IKCFG_SETUP: ikconfig data already loaded\n");
		goto out1;
	} else if (command == IKCFG_FREE) {
		if (kt->ikconfig_flags & IKCONFIG_LOADED) {
			free_ikconfig();
			kt->ikconfig_ents = 0;
			kt->ikconfig_flags &= ~IKCONFIG_LOADED;
		} else
			error(WARNING, "IKCFG_FREE: ikconfig data not loaded\n");
		goto out1;
	}

	do {
		ret = sscanf(pos, "%511[^\n]\n%n", line, &ii);
		if (ret > 0) {
			if ((command == IKCFG_READ) || CRASHDEBUG(8))
				fprintf(fp, "%s\n", line);

			pos += ii;

			ln = line;
				
			/* skip leading whitespace */
			while (whitespace(*ln))
				ln++;

			/* skip comments -- except when looking for "not set" */
			if (*ln == '#') {
				if (strstr(ln, "CONFIG_DEBUG_BUGVERBOSE") &&
				    strstr(ln, "not set"))
					kt->flags |= BUGVERBOSE_OFF;
				if (strstr(ln, "CONFIG_DEBUG_INFO_REDUCED"))
					if (CRASHDEBUG(1))
						error(INFO, "%s\n", ln);
				continue;
			}

			/* Find '=' */
			if ((head = strchr(ln, '=')) != NULL) {
				*head = '\0';
				val = head + 1;

				head--;

				/* skip trailing whitespace */
				while (whitespace(*head)) {
					*head = '\0';
					head--;
				}

				/* skip whitespace */
				while (whitespace(*val))
					val++;

			} else /* Bad line, skip it */
				continue;

			if (command != IKCFG_INIT)
				continue;

			for (jj = 0; ikconfig[jj]; jj++) {
				 if (STREQ(ln, ikconfig[jj])) {

					if (STREQ(ln, "CONFIG_NR_CPUS")) {
						kt->kernel_NR_CPUS = atoi(val);
						if (CRASHDEBUG(1)) 
							error(INFO, 
							    "CONFIG_NR_CPUS: %d\n",
								kt->kernel_NR_CPUS);

					} else if (STREQ(ln, "CONFIG_PGTABLE_4")) {
						machdep->flags |= VM_4_LEVEL;
						if (CRASHDEBUG(1))
							error(INFO, "CONFIG_PGTABLE_4\n");

					} else if (STREQ(ln, "CONFIG_HZ")) {
						machdep->hz = atoi(val);
						if (CRASHDEBUG(1))
							error(INFO, 
							    "CONFIG_HZ: %d\n",
								machdep->hz);

					} else if (STREQ(ln, "CONFIG_DEBUG_INFO_REDUCED")) {
						if (STREQ(val, "y")) {
							error(WARNING, 
							    "CONFIG_DEBUG_INFO_REDUCED=y\n");
							no_debugging_data(INFO);
						}
					}
				}
			}
		}
	} while (ret > 0);

out1:
	free(uncomp);
out2:
	free(buf);

	return;
}

static void
read_in_kernel_config_err(int e, char *msg)
{
	error(WARNING, "zlib could not %s\n", msg);
	switch (e) {
		case Z_OK:
			fprintf(fp, "Z_OK\n");
			break;

		case Z_STREAM_END:
			fprintf(fp, "Z_STREAM_END\n");
			break;

		case Z_NEED_DICT:
			fprintf(fp, "Z_NEED_DICT\n");
			break;
		
		case Z_ERRNO:
			fprintf(fp, "Z_ERNO\n");
			break;

		case Z_STREAM_ERROR:
			fprintf(fp, "Z_STREAM\n");
			break;

		case Z_DATA_ERROR: 
			fprintf(fp, "Z_DATA_ERROR\n");
			break;

		case Z_MEM_ERROR: /* out of memory */
			fprintf(fp, "Z_MEM_ERROR\n");
			break;

		case Z_BUF_ERROR: /* not enough room in output buf */
			fprintf(fp, "Z_BUF_ERROR\n");
			break;
		
		case Z_VERSION_ERROR:
			fprintf(fp, "Z_VERSION_ERROR\n");
			break;

		default: 
			fprintf(fp, "UNKNOWN ERROR: %d\n", e);
			break;
	}
}

/*
 *  With the evidence available, attempt to pre-determine whether
 *  this is a paravirt-capable kernel running as bare-metal, xen, 
 *  kvm, etc. 
 *
 *  NOTE: Only bare-metal pv_ops kernels are supported so far. 
 */
void
paravirt_init(void)
{
	/*
	 *  pv_init_ops appears to be (as of 2.6.27) an arch-common
	 *  symbol.  This may have to change.
	 */
	if (kernel_symbol_exists("pv_init_ops")) {
		if (CRASHDEBUG(1))
			error(INFO, "pv_init_ops exists: ARCH_PVOPS\n");
		kt->flags |= ARCH_PVOPS;
	}
	/*
	 * pv_init_ops moved to first entry in pv_ops as of 4.20-rc1
	 */
	if (kernel_symbol_exists("pv_ops")) {
		if (CRASHDEBUG(1))
			error(INFO, "pv_ops exists: ARCH_PVOPS\n");
		kt->flags |= ARCH_PVOPS;
	}
}

static int
is_pvops_xen(void)
{
	ulong addr;
	char *sym;

	if (!PVOPS())
		return FALSE;

	if (symbol_exists("pv_init_ops") &&
	    readmem(symbol_value("pv_init_ops"), KVADDR, &addr,
	    sizeof(void *), "pv_init_ops", RETURN_ON_ERROR) &&
	    (sym = value_symbol(addr)) &&
	    (STREQ(sym, "xen_patch") ||
	     STREQ(sym, "paravirt_patch_default")))
		return TRUE;

	if (machine_type("X86") || machine_type("X86_64")) {
		if (symbol_exists("xen_start_info") &&
		    readmem(symbol_value("xen_start_info"), KVADDR, &addr,
		    sizeof(void *), "xen_start_info", RETURN_ON_ERROR) &&
		    addr != 0)
			return TRUE;
	}

	if (machine_type("ARM") || machine_type("ARM64")) {
		if (symbol_exists("xen_vcpu_info") &&
		    readmem(symbol_value("xen_vcpu_info"), KVADDR, &addr,
		    sizeof(void *), "xen_vcpu_info", RETURN_ON_ERROR) &&
		    addr != 0)
			return TRUE;
	}

	return FALSE;
}

/*
 *  Get the kernel's xtime timespec from its relevant location.
 */
static void
get_xtime(struct timespec *date)
{
	struct syment *sp;
	uint64_t xtime_sec;

	if (VALID_MEMBER(timekeeper_xtime) &&
	    (sp = kernel_symbol_search("timekeeper"))) {
                readmem(sp->value + OFFSET(timekeeper_xtime), KVADDR, 
			date, sizeof(struct timespec),
                        "timekeeper xtime", RETURN_ON_ERROR);
	} else if (VALID_MEMBER(timekeeper_xtime_sec) &&
	    (sp = kernel_symbol_search("timekeeper"))) {
                readmem(sp->value + OFFSET(timekeeper_xtime_sec), KVADDR, 
			&xtime_sec, sizeof(uint64_t),
                        "timekeeper xtime_sec", RETURN_ON_ERROR);
		date->tv_sec = (__time_t)xtime_sec;
	} else if (VALID_MEMBER(timekeeper_xtime_sec) &&
	    (sp = kernel_symbol_search("shadow_timekeeper"))) {
                readmem(sp->value + OFFSET(timekeeper_xtime_sec), KVADDR, 
			&xtime_sec, sizeof(uint64_t),
                        "shadow_timekeeper xtime_sec", RETURN_ON_ERROR);
		date->tv_sec = (__time_t)xtime_sec;
	} else if (kernel_symbol_exists("xtime"))
		get_symbol_data("xtime", sizeof(struct timespec), date);
}


static void 
hypervisor_init(void)
{
	ulong x86_hyper, name, pv_init_ops, pv_ops;
	char buf[BUFSIZE], *p1;

	kt->hypervisor = "(undetermined)";
	BZERO(buf, BUFSIZE);

	if (kernel_symbol_exists("pv_info") && 
	    MEMBER_EXISTS("pv_info", "name") &&
	    readmem(symbol_value("pv_info") + MEMBER_OFFSET("pv_info", "name"), 
	    KVADDR, &name, sizeof(char *), "pv_info.name", 
	    QUIET|RETURN_ON_ERROR) && read_string(name, buf, BUFSIZE-1))
		kt->hypervisor = strdup(buf);
	else if (try_get_symbol_data("x86_hyper", sizeof(void *), &x86_hyper)) {
		if (!x86_hyper)
			kt->hypervisor = "bare hardware";
		else if (MEMBER_EXISTS("hypervisor_x86", "name") &&
	  	    readmem(x86_hyper + MEMBER_OFFSET("hypervisor_x86", "name"), 
		    KVADDR, &name, sizeof(char *), "x86_hyper->name", 
		    QUIET|RETURN_ON_ERROR) && read_string(name, buf, BUFSIZE-1))
			kt->hypervisor = strdup(buf);
	} else if (XENDUMP_DUMPFILE() || XEN()) 
		kt->hypervisor = "Xen";
	else if (KVMDUMP_DUMPFILE())
		kt->hypervisor = "KVM";
	else if (PVOPS() && symbol_exists("pv_init_ops") &&
	    readmem(symbol_value("pv_init_ops"), KVADDR, 
	    &pv_init_ops, sizeof(void *), "pv_init_ops", RETURN_ON_ERROR) &&
	    (p1 = value_symbol(pv_init_ops)) &&
	    STREQ(p1, "native_patch"))
		kt->hypervisor = "bare hardware";
	else if (PVOPS() && symbol_exists("pv_ops") &&
	    readmem(symbol_value("pv_ops"), KVADDR, 
	    &pv_ops, sizeof(void *), "pv_ops", RETURN_ON_ERROR) &&
	    (p1 = value_symbol(pv_ops)) &&
	    STREQ(p1, "native_patch"))
		kt->hypervisor = "bare hardware";

	if (CRASHDEBUG(1))
		fprintf(fp, "hypervisor: %s\n", kt->hypervisor);
}

/*
 *  Get and display the kernel log buffer using the vmcoreinfo
 *  data alone without the vmlinux file.
 */
void
get_log_from_vmcoreinfo(char *file)
{
	char *string;
	struct vmcoreinfo_data *vmc = &kt->vmcoreinfo;

	if (!(pc->flags2 & VMCOREINFO))
		error(FATAL, "%s: no VMCOREINFO section\n", file);

	vmc->log_SIZE = vmc->log_ts_nsec_OFFSET = vmc->log_len_OFFSET =
	vmc->log_text_len_OFFSET = vmc->log_dict_len_OFFSET = -1;

	if ((string = pc->read_vmcoreinfo("OSRELEASE"))) {
		if (CRASHDEBUG(1))
			fprintf(fp, "OSRELEASE: %s\n", string);

		parse_kernel_version(string);

		if (CRASHDEBUG(1))
			fprintf(fp, "base kernel version: %d.%d.%d\n",
				kt->kernel_version[0],
				kt->kernel_version[1],
				kt->kernel_version[2]);
		free(string);
	} else
		error(FATAL, "VMCOREINFO: cannot determine kernel version\n");

	if ((string = pc->read_vmcoreinfo("PAGESIZE"))) {
		machdep->pagesize = atoi(string);
		machdep->pageoffset = machdep->pagesize - 1;
		if (CRASHDEBUG(1))
			fprintf(fp, "PAGESIZE: %d\n", machdep->pagesize);
		free(string);
	} else
		error(FATAL, "VMCOREINFO: cannot determine page size\n");

	if ((string = pc->read_vmcoreinfo("SYMBOL(log_buf)"))) {
		vmc->log_buf_SYMBOL = htol(string, RETURN_ON_ERROR, NULL);
		if (CRASHDEBUG(1))
			fprintf(fp, "SYMBOL(log_buf): %lx\n", 
				vmc->log_buf_SYMBOL);
		free(string);
	}
	if ((string = pc->read_vmcoreinfo("SYMBOL(log_end)"))) {
		vmc->log_end_SYMBOL = htol(string, RETURN_ON_ERROR, NULL);
		if (CRASHDEBUG(1))
			fprintf(fp, "SYMBOL(log_end): %lx\n", 
				vmc->log_end_SYMBOL);
		free(string);
	} 
	if ((string = pc->read_vmcoreinfo("SYMBOL(log_buf_len)"))) {
		vmc->log_buf_len_SYMBOL = htol(string, RETURN_ON_ERROR, NULL);
		if (CRASHDEBUG(1))
			fprintf(fp, "SYMBOL(log_buf_len): %lx\n", 
				vmc->log_buf_len_SYMBOL);
		free(string);
	} 
	if ((string = pc->read_vmcoreinfo("SYMBOL(logged_chars)"))) {
		vmc->logged_chars_SYMBOL = htol(string, RETURN_ON_ERROR, NULL);
		if (CRASHDEBUG(1))
			fprintf(fp, "SYMBOL(logged_chars): %lx\n", 
				vmc->logged_chars_SYMBOL);
		free(string);
	} 
	if ((string = pc->read_vmcoreinfo("SYMBOL(log_first_idx)"))) {
		vmc->log_first_idx_SYMBOL = htol(string, RETURN_ON_ERROR, NULL);
		if (CRASHDEBUG(1))
			fprintf(fp, "SYMBOL(log_first_idx): %lx\n", 
				vmc->log_first_idx_SYMBOL);
		free(string);
	} 
	if ((string = pc->read_vmcoreinfo("SYMBOL(log_next_idx)"))) {
		vmc->log_next_idx_SYMBOL = htol(string, RETURN_ON_ERROR, NULL);
		if (CRASHDEBUG(1))
			fprintf(fp, "SYMBOL(log_next_idx): %lx\n", 
				vmc->log_next_idx_SYMBOL);
		free(string);
	} 
	if ((string = pc->read_vmcoreinfo("SYMBOL(phys_base)"))) {
		vmc->phys_base_SYMBOL = htol(string, RETURN_ON_ERROR, NULL);
		if (CRASHDEBUG(1))
			fprintf(fp, "SYMBOL(phys_base): %lx\n", 
				vmc->phys_base_SYMBOL);
		free(string);
	} 
	if ((string = pc->read_vmcoreinfo("SYMBOL(_stext)"))) {
		vmc->_stext_SYMBOL = htol(string, RETURN_ON_ERROR, NULL);
		if (CRASHDEBUG(1))
			fprintf(fp, "SYMBOL(_stext): %lx\n", 
				vmc->_stext_SYMBOL);
		free(string);
	} 
	if ((string = pc->read_vmcoreinfo("OFFSET(log.ts_nsec)"))) {
		vmc->log_ts_nsec_OFFSET = dtol(string, RETURN_ON_ERROR, NULL);
		if (CRASHDEBUG(1))
			fprintf(fp, "OFFSET(log.ts_nsec): %ld\n", 
				vmc->log_ts_nsec_OFFSET);
		free(string);
	} else if ((string = pc->read_vmcoreinfo("OFFSET(printk_log.ts_nsec)"))) {
		vmc->log_ts_nsec_OFFSET = dtol(string, RETURN_ON_ERROR, NULL);
		if (CRASHDEBUG(1))
			fprintf(fp, "OFFSET(printk_log.ts_nsec): %ld\n", 
				vmc->log_ts_nsec_OFFSET);
		free(string);
	}
	if ((string = pc->read_vmcoreinfo("OFFSET(log.len)"))) {
		vmc->log_len_OFFSET = dtol(string, RETURN_ON_ERROR, NULL);
		if (CRASHDEBUG(1))
			fprintf(fp, "OFFSET(log.len): %ld\n", 
				vmc->log_len_OFFSET);
		free(string);
	} else if ((string = pc->read_vmcoreinfo("OFFSET(printk_log.len)"))) {
		vmc->log_len_OFFSET = dtol(string, RETURN_ON_ERROR, NULL);
		if (CRASHDEBUG(1))
			fprintf(fp, "OFFSET(printk_log.len): %ld\n", 
				vmc->log_len_OFFSET);
		free(string);
	}
	if ((string = pc->read_vmcoreinfo("OFFSET(log.text_len)"))) {
		vmc->log_text_len_OFFSET = dtol(string, RETURN_ON_ERROR, NULL);
		if (CRASHDEBUG(1))
			fprintf(fp, "OFFSET(log.text_len): %ld\n", 
				vmc->log_text_len_OFFSET);
		free(string);
	} else if ((string = pc->read_vmcoreinfo("OFFSET(printk_log.text_len)"))) {
		vmc->log_text_len_OFFSET = dtol(string, RETURN_ON_ERROR, NULL);
		if (CRASHDEBUG(1))
			fprintf(fp, "OFFSET(printk_log.text_len): %ld\n", 
				vmc->log_text_len_OFFSET);
		free(string);
	}
	if ((string = pc->read_vmcoreinfo("OFFSET(log.dict_len)"))) {
		vmc->log_dict_len_OFFSET = dtol(string, RETURN_ON_ERROR, NULL);
		if (CRASHDEBUG(1))
			fprintf(fp, "OFFSET(log.dict_len): %ld\n", 
				vmc->log_dict_len_OFFSET);
		free(string);
	} else if ((string = pc->read_vmcoreinfo("OFFSET(printk_log.dict_len)"))) {
		vmc->log_dict_len_OFFSET = dtol(string, RETURN_ON_ERROR, NULL);
		if (CRASHDEBUG(1))
			fprintf(fp, "OFFSET(printk_log.dict_len): %ld\n", 
				vmc->log_dict_len_OFFSET);
		free(string);
	}
	if ((string = pc->read_vmcoreinfo("SIZE(log)"))) {
		vmc->log_SIZE = dtol(string, RETURN_ON_ERROR, NULL);
		if (CRASHDEBUG(1))
			fprintf(fp, "SIZE(log): %ld\n", vmc->log_SIZE);
		free(string);
	} else if ((string = pc->read_vmcoreinfo("SIZE(printk_log)"))) {
		vmc->log_SIZE = dtol(string, RETURN_ON_ERROR, NULL);
		if (CRASHDEBUG(1))
			fprintf(fp, "SIZE(printk_log): %ld\n", vmc->log_SIZE);
		free(string);
	}

	/*
	 *  The per-arch VTOP() macro must be functional.
	 */
	machdep_init(LOG_ONLY);

	if (vmc->log_buf_SYMBOL && vmc->log_buf_len_SYMBOL &&
	    vmc->log_first_idx_SYMBOL && vmc->log_next_idx_SYMBOL &&
            (vmc->log_SIZE > 0) &&
            (vmc->log_ts_nsec_OFFSET >= 0) &&
            (vmc->log_len_OFFSET >= 0) &&
            (vmc->log_text_len_OFFSET >= 0) &&
            (vmc->log_dict_len_OFFSET >= 0))
		dump_variable_length_record();
	else if (vmc->log_buf_SYMBOL && vmc->log_end_SYMBOL && 
	    vmc->log_buf_len_SYMBOL && vmc->logged_chars_SYMBOL)
		dump_log_legacy();
	else
		error(FATAL, "VMCOREINFO: no log buffer data\n");
}

static void
dump_log_legacy(void)
{
	int i;
        physaddr_t paddr;
        ulong long_value;
        uint int_value;
        ulong log_buf;
        uint log_end, log_buf_len, logged_chars, total;
	char *buf, *p;
	ulong index, bytes;
	struct vmcoreinfo_data *vmc;

	vmc = &kt->vmcoreinfo;
	log_buf = log_end = log_buf_len = logged_chars = 0;

	paddr = VTOP(vmc->log_buf_SYMBOL);
	if (readmem(paddr, PHYSADDR, &long_value, sizeof(ulong), 
	    "log_buf pointer", RETURN_ON_ERROR))
		log_buf = long_value;
	else
		error(FATAL, "cannot read log_buf value\n"); 
	if (CRASHDEBUG(1))
		fprintf(fp, "log_buf vaddr: %lx paddr: %llx => %lx\n", 
			vmc->log_buf_SYMBOL, (ulonglong)paddr, log_buf); 

	paddr = VTOP(vmc->log_end_SYMBOL);
	if (THIS_KERNEL_VERSION < LINUX(2,6,25)) {
		if (readmem(paddr, PHYSADDR, &long_value, sizeof(ulong),
		    "log_end (long)", RETURN_ON_ERROR))
			log_end = (uint)long_value;
		else
			error(FATAL, "cannot read log_end value\n"); 
	} else {
		if (readmem(paddr, PHYSADDR, &int_value, sizeof(uint),
		    "log_end (int)", RETURN_ON_ERROR))
			log_end = int_value;
		else
			error(FATAL, "cannot read log_end value\n"); 
	}
	if (CRASHDEBUG(1))
		fprintf(fp, "log_end vaddr: %lx paddr: %llx => %d\n", 
			vmc->log_end_SYMBOL, (ulonglong)paddr, log_end); 

	paddr = VTOP(vmc->log_buf_len_SYMBOL);
	if (readmem(paddr, PHYSADDR, &int_value, sizeof(uint),
	    "log_buf_len", RETURN_ON_ERROR))
		log_buf_len = int_value;
	else
		error(FATAL, "cannot read log_buf_len value\n"); 
	if (CRASHDEBUG(1))
		fprintf(fp, "log_buf_len vaddr: %lx paddr: %llx => %d\n", 
			vmc->log_buf_len_SYMBOL, (ulonglong)paddr, log_buf_len); 

	paddr = VTOP(vmc->logged_chars_SYMBOL);
	if (readmem(paddr, PHYSADDR, &int_value, sizeof(uint),
	    "logged_chars", RETURN_ON_ERROR))
		logged_chars = int_value;
	else
		error(FATAL, "cannot read logged_chars value\n"); 
	if (CRASHDEBUG(1))
		fprintf(fp, "logged_chars vaddr: %lx paddr: %llx => %d\n", 
			vmc->logged_chars_SYMBOL, (ulonglong)paddr, logged_chars); 

        if ((buf = calloc(sizeof(char), log_buf_len)) == NULL)
		error(FATAL, "cannot calloc log_buf_len (%d) bytes\n", 
			log_buf_len);

	paddr = VTOP(log_buf);

	if (log_end < log_buf_len) {
		bytes = log_end;
		if (!readmem(paddr, PHYSADDR, buf, bytes,
		    "log_buf", RETURN_ON_ERROR))
			error(FATAL, "cannot read log_buf\n");
		total = bytes;
	} else {
                index = log_end & (log_buf_len - 1);
		bytes = log_buf_len - index;
		if (!readmem(paddr + index, PHYSADDR, buf, bytes,
		    "log_buf + index", RETURN_ON_ERROR))
			error(FATAL, "cannot read log_buf\n");
		if (!readmem(paddr, PHYSADDR, buf + bytes, index,
		    "log_buf", RETURN_ON_ERROR))
			error(FATAL, "cannot read log_buf\n");
		total = log_buf_len;
	}

	for (i = 0, p = buf; i < total; i++, p++) {
		if (*p == NULLCHAR)
			fputc('\n', fp);
		else if (ascii(*p))
			fputc(*p, fp);
		else
			fputc('.', fp);
	}
}

static void
dump_variable_length_record(void)
{
        physaddr_t paddr;
	ulong long_value;
	uint32_t int_value;
	struct vmcoreinfo_data *vmc;
	ulong log_buf;
	uint32_t idx, log_buf_len, log_first_idx, log_next_idx;
	char *buf, *logptr;

	vmc = &kt->vmcoreinfo;
	log_buf = log_buf_len = log_first_idx = log_next_idx = 0;

	paddr = VTOP(vmc->log_buf_SYMBOL);
	if (readmem(paddr, PHYSADDR, &long_value, sizeof(ulong), 
	    "log_buf pointer", RETURN_ON_ERROR))
		log_buf = long_value;
	else
		error(FATAL, "cannot read log_buf value\n"); 
	if (CRASHDEBUG(1))
		fprintf(fp, "log_buf vaddr: %lx paddr: %llx => %lx\n", 
			vmc->log_buf_SYMBOL, (ulonglong)paddr, log_buf); 

	paddr = VTOP(vmc->log_buf_len_SYMBOL);
	if (readmem(paddr, PHYSADDR, &int_value, sizeof(uint),
	    "log_buf_len", RETURN_ON_ERROR))
		log_buf_len = int_value;
	else
		error(FATAL, "cannot read log_buf_len value\n"); 
	if (CRASHDEBUG(1))
		fprintf(fp, "log_buf_len vaddr: %lx paddr: %llx => %d\n", 
			vmc->log_buf_len_SYMBOL, (ulonglong)paddr, log_buf_len); 

	paddr = VTOP(vmc->log_first_idx_SYMBOL);
	if (readmem(paddr, PHYSADDR, &int_value, sizeof(uint),
	    "log_first_idx", RETURN_ON_ERROR))
		log_first_idx = int_value;
	else
		error(FATAL, "cannot read log_first_idx value\n"); 
	if (CRASHDEBUG(1))
		fprintf(fp, "log_first_idx vaddr: %lx paddr: %llx => %d\n", 
			vmc->log_first_idx_SYMBOL, (ulonglong)paddr, log_first_idx); 

	paddr = VTOP(vmc->log_next_idx_SYMBOL);
	if (readmem(paddr, PHYSADDR, &int_value, sizeof(uint),
	    "log_next_idx", RETURN_ON_ERROR))
		log_next_idx = int_value;
	else
		error(FATAL, "cannot read log_next_idx value\n"); 
	if (CRASHDEBUG(1))
		fprintf(fp, "log_next_idx vaddr: %lx paddr: %llx => %d\n", 
			vmc->log_next_idx_SYMBOL, (ulonglong)paddr, log_next_idx); 

	ASSIGN_SIZE(log)= vmc->log_SIZE;
	ASSIGN_OFFSET(log_ts_nsec) = vmc->log_ts_nsec_OFFSET;
	ASSIGN_OFFSET(log_len) = vmc->log_len_OFFSET;  
	ASSIGN_OFFSET(log_text_len) = vmc->log_text_len_OFFSET;
	ASSIGN_OFFSET(log_dict_len) = vmc->log_dict_len_OFFSET;

        if ((buf = calloc(sizeof(char), log_buf_len)) == NULL)
		error(FATAL, "cannot calloc log_buf_len (%d) bytes\n", 
			log_buf_len);

	paddr = VTOP(log_buf);

	if (!readmem(paddr, PHYSADDR, buf, log_buf_len,
	    "log_buf", RETURN_ON_ERROR))
		error(FATAL, "cannot read log_buf\n");

	hq_init();
	hq_open();

	idx = log_first_idx;
	while (idx != log_next_idx) {
		logptr = log_from_idx(idx, buf);

		dump_log_entry(logptr, 0);

		if (!hq_enter((ulong)logptr)) {
			error(INFO, "\nduplicate log_buf message pointer\n");
			break;
		}

		idx = log_next(idx, buf);

		if (idx >= log_buf_len) {
			error(INFO, "\ninvalid log_buf entry encountered\n");
			break;
		}

		if (CRASHDEBUG(1) && (idx == log_next_idx))
			fprintf(fp, "\nfound log_next_idx OK\n");
	}

	hq_close();
}

static void
show_kernel_taints(char *buf, int verbose)
{
	int i, bx;
	uint8_t tnt_bit;
	char tnt_true, tnt_false;
	int tnts_len = 0;
	ulong tnts_addr;
	ulong tainted_mask, *tainted_mask_ptr;
	int tainted;
	struct syment *sp = NULL;

	if (kernel_symbol_exists("tainted")) {
		get_symbol_data("tainted", sizeof(int), &tainted);
		if (verbose)
			fprintf(fp, "TAINTED: %x\n", tainted);
		return;
	} else if (VALID_STRUCT(tnt) ||
	    (kernel_symbol_exists("tnts") && STRUCT_EXISTS("tnt"))) {
		if (!VALID_STRUCT(tnt)) {
			STRUCT_SIZE_INIT(tnt, "tnt");
			MEMBER_OFFSET_INIT(tnt_bit, "tnt", "bit");
			MEMBER_OFFSET_INIT(tnt_true, "tnt", "true");
			MEMBER_OFFSET_INIT(tnt_false, "tnt", "false");
		}

		tnts_len = get_array_length("tnts", NULL, 0);
		sp = symbol_search("tnts");
	} else if (VALID_STRUCT(taint_flag) ||
	    (kernel_symbol_exists("taint_flags") && STRUCT_EXISTS("taint_flag"))) {
		if (!(VALID_STRUCT(taint_flag) &&
					VALID_MEMBER(tnt_true) && VALID_MEMBER(tnt_false))) {
			STRUCT_SIZE_INIT(taint_flag, "taint_flag");
			MEMBER_OFFSET_INIT(tnt_true, "taint_flag", "true");
			MEMBER_OFFSET_INIT(tnt_false, "taint_flag", "false");
			if (INVALID_MEMBER(tnt_true)) {
				MEMBER_OFFSET_INIT(tnt_true, "taint_flag", "c_true");
				MEMBER_OFFSET_INIT(tnt_false, "taint_flag", "c_false");
			}
		}

		if (!(pc->flags & RUNTIME)) {
			if (INVALID_MEMBER(tnt_true) || INVALID_MEMBER(tnt_false) ||
					!kernel_symbol_exists("tainted_mask"))
				return;
		}

		tnts_len = get_array_length("taint_flags", NULL, 0);
		sp = symbol_search("taint_flags");
	} else if (verbose)
		option_not_supported('t');

	tnts_addr = sp->value;
	get_symbol_data("tainted_mask", sizeof(ulong), &tainted_mask);
	tainted_mask_ptr = &tainted_mask;

	bx = 0;
	buf[0] = '\0';

	if (VALID_STRUCT(tnt)) {
		for (i = 0; i < (tnts_len * SIZE(tnt)); i += SIZE(tnt)) {
			readmem((tnts_addr + i) + OFFSET(tnt_bit),
				KVADDR, &tnt_bit, sizeof(uint8_t),
				"tnt bit", FAULT_ON_ERROR);

			if (NUM_IN_BITMAP(tainted_mask_ptr, tnt_bit)) {
				readmem((tnts_addr + i) + OFFSET(tnt_true),
					KVADDR, &tnt_true, sizeof(char),
					"tnt true", FAULT_ON_ERROR);
					buf[bx++] = tnt_true;
			} else {
				readmem((tnts_addr + i) + OFFSET(tnt_false),
					KVADDR, &tnt_false, sizeof(char),
					"tnt false", FAULT_ON_ERROR);
				if (tnt_false != ' ' && tnt_false != '-' &&
				    tnt_false != 'G')
					buf[bx++] = tnt_false;
			}
		}
	} else if (VALID_STRUCT(taint_flag)) {
		for (i = 0; i < tnts_len; i++) {
			if (NUM_IN_BITMAP(tainted_mask_ptr, i)) {
				readmem((tnts_addr + i * SIZE(taint_flag)) +
						OFFSET(tnt_true),
						KVADDR, &tnt_true, sizeof(char),
						"tnt true", FAULT_ON_ERROR);
				buf[bx++] = tnt_true;
			} else {
				readmem((tnts_addr + i * SIZE(taint_flag)) +
						OFFSET(tnt_false),
						KVADDR, &tnt_false, sizeof(char),
						"tnt false", FAULT_ON_ERROR);
				if (tnt_false != ' ' && tnt_false != '-' &&
						tnt_false != 'G')
					buf[bx++] = tnt_false;
			}
		}
	}

	buf[bx++] = '\0';

	if (verbose)
		fprintf(fp, "TAINTED_MASK: %lx  %s\n", tainted_mask, buf);
}

static void
dump_dmi_info(void)
{
	int i, array_len, len, maxlen;
	ulong dmi_ident_p, vaddr;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char *arglist[MAXARGS];

	if (!kernel_symbol_exists("dmi_ident"))
		error(FATAL, "dmi_ident does not exist in this kernel\n");

	dmi_ident_p = symbol_value("dmi_ident");
	array_len = get_array_length("dmi_ident", NULL, 0);
	maxlen = 0;

	open_tmpfile();

	if (dump_enumerator_list("dmi_field")) {
		rewind(pc->tmpfile);
		while (fgets(buf1, BUFSIZE, pc->tmpfile)) {
			if (!strstr(buf1, " = "))
				continue;
			if ((parse_line(buf1, arglist) != 3) ||
			    (atoi(arglist[2]) >= array_len))
				break;
			len = strlen(arglist[0]);
			if (len > maxlen)
				maxlen = len;
		}

		rewind(pc->tmpfile);
		while (fgets(buf1, BUFSIZE, pc->tmpfile)) {
			if (!strstr(buf1, " = "))
				continue;

			if ((parse_line(buf1, arglist) != 3) ||
			    ((i = atoi(arglist[2])) >= array_len))
				break;

			readmem(dmi_ident_p + (sizeof(void *) * i),
				KVADDR, &vaddr, sizeof(void *),
				"dmi_ident", FAULT_ON_ERROR);
			if (!vaddr)
				continue;

			read_string(vaddr, buf2, BUFSIZE-1);
			fprintf(pc->saved_fp, "  %s%s: %s\n", 
				space(maxlen - strlen(arglist[0])), arglist[0], buf2);
		}
	} else {
		for (i = 0; i < array_len; i++) {
			readmem(dmi_ident_p + (sizeof(void *) * i),
				KVADDR, &vaddr, sizeof(void *),
				"dmi_ident", FAULT_ON_ERROR);
			if (!vaddr)
				continue;
			read_string(vaddr, buf1, BUFSIZE-1);
			fprintf(pc->saved_fp, "  dmi_ident[%d]: %s\n", i, buf1);
		}
	} 

	close_tmpfile();
}

#define NLMSG_ALIGNTO 4
#define NLMSG_DATA(nlh) (nlh + roundup(SIZE(nlmsghdr), NLMSG_ALIGNTO))

static ulong
dump_audit_skb_queue(ulong audit_skb_queue)
{
	ulong skb_buff_head_next = 0, p;
	uint32_t qlen = 0;

	if (INVALID_SIZE(nlmsghdr)) {
		STRUCT_SIZE_INIT(nlmsghdr, "nlmsghdr");
		MEMBER_OFFSET_INIT(nlmsghdr_nlmsg_type, "nlmsghdr", "nlmsg_type");
		MEMBER_SIZE_INIT(nlmsghdr_nlmsg_type, "nlmsghdr", "nlmsg_type");
		MEMBER_OFFSET_INIT(sk_buff_head_next, "sk_buff_head", "next");
		MEMBER_OFFSET_INIT(sk_buff_head_qlen, "sk_buff_head", "qlen");
		MEMBER_SIZE_INIT(sk_buff_head_qlen, "sk_buff_head", "qlen");
		MEMBER_OFFSET_INIT(sk_buff_data, "sk_buff", "data");
		MEMBER_OFFSET_INIT(sk_buff_len, "sk_buff", "len");
		MEMBER_OFFSET_INIT(sk_buff_next, "sk_buff", "next");
		MEMBER_SIZE_INIT(sk_buff_len, "sk_buff", "len");
	}

	readmem(audit_skb_queue + OFFSET(sk_buff_head_qlen),
		KVADDR,
		&qlen,
		SIZE(sk_buff_head_qlen),
		"audit_skb_queue.qlen",
		FAULT_ON_ERROR);

	if (!qlen)
		return 0;

	readmem(audit_skb_queue + OFFSET(sk_buff_head_next),
		KVADDR,
		&skb_buff_head_next,
		sizeof(void *),
		"audit_skb_queue.next",
		FAULT_ON_ERROR);

	if (!skb_buff_head_next)
		error(FATAL, "audit_skb_queue.next: NULL\n");

	p = skb_buff_head_next;
	do {
		ulong data, data_len;
		uint len;
		uint16_t nlmsg_type;
		char *buf = NULL;

		if (CRASHDEBUG(2))
			fprintf(fp, "%#016lx\n", p);

		readmem(p + OFFSET(sk_buff_len),
			KVADDR,
			&len,
			SIZE(sk_buff_len),
			"sk_buff.len",
			FAULT_ON_ERROR);

		data_len = len - roundup(SIZE(nlmsghdr), NLMSG_ALIGNTO);

		readmem(p + OFFSET(sk_buff_data),
			KVADDR,
			&data,
			sizeof(void *),
			"sk_buff.data",
			FAULT_ON_ERROR);

		if (!data)
			error(FATAL, "sk_buff.data: NULL\n");

		readmem(data + OFFSET(nlmsghdr_nlmsg_type),
			KVADDR,
			&nlmsg_type,
			SIZE(nlmsghdr_nlmsg_type),
			"nlmsghdr.nlmsg_type",
			FAULT_ON_ERROR);

		buf = GETBUF(data_len + 1);
		readmem(NLMSG_DATA(data),
			KVADDR,
			buf,
			data_len,
			"sk_buff.data + sizeof(struct nlmsghdr)",
			FAULT_ON_ERROR);
		buf[data_len] = '\0';

		fprintf(fp, "type=%u %s\n", nlmsg_type, buf);
		FREEBUF(buf);

		readmem(p + OFFSET(sk_buff_next),
			KVADDR,
			&p,
			sizeof(void *),
			"skb_buff.next",
			FAULT_ON_ERROR);
	} while (p != audit_skb_queue);

	return qlen;
}

static ulong
__dump_audit(char *symname)
{
	if (symbol_exists(symname)) {
		if (CRASHDEBUG(1))
			fprintf(fp, "# %s:\n", symname);
		return dump_audit_skb_queue(symbol_value(symname));
	}
	return 0;
}

static void
dump_audit(void)
{
	ulong qlen = 0;

	if (symbol_exists("audit_skb_queue")) {
		qlen += __dump_audit("audit_skb_hold_queue");
		qlen += __dump_audit("audit_skb_queue");
	} else if (symbol_exists("audit_queue")) {
		qlen += __dump_audit("audit_hold_queue");
		qlen += __dump_audit("audit_retry_queue");
		qlen += __dump_audit("audit_queue");
	} else
		option_not_supported('a');

	if (!qlen)
		error(INFO, "kernel audit log is empty\n");
}

#define PRINTK_SAFE_SEQ_BUF_INDENT 2

static void
__dump_printk_safe_seq_buf(char *buf_name, int msg_flags)
{
	int cpu, buffer_size;
	char *buffer;
	ulong base_addr, len_addr, message_lost_addr, buffer_addr;
	bool show_header;

	show_header = msg_flags & SHOW_LOG_SAFE;

	if (!symbol_exists(buf_name)) {
		return;
	}

	base_addr = symbol_value(buf_name);
	len_addr = base_addr + OFFSET(printk_safe_seq_buf_len)
			+ OFFSET(atomic_t_counter);
	message_lost_addr = base_addr
			+ OFFSET(printk_safe_seq_buf_message_lost)
			+ OFFSET(atomic_t_counter);
	buffer_addr = base_addr + OFFSET(printk_safe_seq_buf_buffer);
	buffer_size = SIZE(printk_safe_seq_buf_buffer);
	buffer = GETBUF(buffer_size);

	if (show_header)
		fprintf(fp, "PRINTK_SAFE_SEQ_BUF: %s\n", buf_name);
	for (cpu = 0; cpu < kt->cpus; cpu++) {
		int len, message_lost;
		ulong per_cpu_offset;
		per_cpu_offset = kt->__per_cpu_offset[cpu];

		readmem(len_addr + per_cpu_offset, KVADDR, &len, sizeof(int),
			"printk_safe_seq_buf len", FAULT_ON_ERROR);

		if (show_header) {
			readmem(message_lost_addr + per_cpu_offset, KVADDR,
				&message_lost, sizeof(int),
				"printk_safe_seq_buf message_lost", FAULT_ON_ERROR);
			fprintf(fp, "CPU: %d  ADDR: %lx LEN: %d  MESSAGE_LOST: %d\n",
				cpu, base_addr + per_cpu_offset, len, message_lost);
		}

		if (len > 0) {
			int i, n, ilen;
			char *p;
			bool start_of_line;

			ilen = 0;
			if (show_header) {
				ilen = PRINTK_SAFE_SEQ_BUF_INDENT;
			} else {
				if (msg_flags & SHOW_LOG_TEXT)
					ilen = 0;
				else
					ilen = strlen(buf_name) + 3; // "[%s] "
			}
			if (msg_flags & SHOW_LOG_LEVEL)
				ilen += 3; // "<%c>"

			readmem(buffer_addr + per_cpu_offset, KVADDR,
				buffer, buffer_size,
				"printk_safe_seq_buf buffer", FAULT_ON_ERROR);

			start_of_line = true;
			n = (len <= buffer_size) ? len : buffer_size;
			for (i = 0, p = buffer; i < n; i++, p++) {
				bool sol = start_of_line;
				start_of_line = false;
				if (*p == 0x1) { //SOH
					i++; p++;

					if (!sol)
						fprintf(fp, "\n");

					if (show_header)
						fprintf(fp, "%s", space(PRINTK_SAFE_SEQ_BUF_INDENT));
					else if (!(msg_flags & SHOW_LOG_TEXT))
						fprintf(fp, "[%s] ", buf_name);

					if ((msg_flags & SHOW_LOG_LEVEL) && (i < n)) {
						switch (*p) {
						case '0' ... '7':
						case 'c':
							fprintf(fp, "<%c>", *p);
						}
					}

					continue;
				} else {
					if (sol)
						fprintf(fp, "%s", space(ilen));

					if (isprint(*p) || isspace(*p)) {
						fputc(*p, fp);
						if (*p == '\n')
							start_of_line = true;
					} else {
						fputc('.', fp);
					}
				}
			}
			if (!start_of_line)
				fputc('\n', fp);
			if (show_header)
				fputc('\n', fp);
		} else if (show_header) {
			fprintf(fp, "%s(empty)\n\n", space(PRINTK_SAFE_SEQ_BUF_INDENT));
		}
	}
	FREEBUF(buffer);
}

static void
dump_printk_safe_seq_buf(int msg_flags)
{
	if (!STRUCT_EXISTS("printk_safe_seq_buf"))
		return;

	if (INVALID_SIZE(printk_safe_seq_buf_buffer)) {
		MEMBER_OFFSET_INIT(printk_safe_seq_buf_len,
			"printk_safe_seq_buf", "len");
		MEMBER_OFFSET_INIT(printk_safe_seq_buf_message_lost,
			"printk_safe_seq_buf", "message_lost");
		MEMBER_OFFSET_INIT(printk_safe_seq_buf_buffer,
			"printk_safe_seq_buf", "buffer");

		if (!INVALID_MEMBER(printk_safe_seq_buf_buffer)) {
			MEMBER_SIZE_INIT(printk_safe_seq_buf_buffer,
				"printk_safe_seq_buf", "buffer");
		}
	}

	if (INVALID_MEMBER(printk_safe_seq_buf_len) ||
	    INVALID_MEMBER(printk_safe_seq_buf_message_lost) ||
	    INVALID_MEMBER(printk_safe_seq_buf_buffer) ||
	    INVALID_SIZE(printk_safe_seq_buf_buffer)) {
		if (msg_flags & SHOW_LOG_SAFE)
			error(INFO, "-s not supported with this kernel version\n");
		return;
	}

	__dump_printk_safe_seq_buf("nmi_print_seq", msg_flags);
	__dump_printk_safe_seq_buf("safe_print_seq", msg_flags);
}

/*
 * Reads a string value from the VMCOREINFO data stored in (live) memory.
 *
 * Returns a string (that has to be freed by the caller) that contains the
 * value for key or NULL if the key has not been found.
 */
static char *
vmcoreinfo_read_string(const char *key)
{
	char *buf, *value_string, *p1, *p2;
	size_t value_length;
	size_t vmcoreinfo_size;
	ulong vmcoreinfo_data;
	char keybuf[BUFSIZE];

	buf = value_string = NULL;

	switch (get_symbol_type("vmcoreinfo_data", NULL, NULL))
	{
	case TYPE_CODE_PTR:
		get_symbol_data("vmcoreinfo_data", sizeof(vmcoreinfo_data), &vmcoreinfo_data);
		break;
	case TYPE_CODE_ARRAY:
		vmcoreinfo_data = symbol_value("vmcoreinfo_data");
		break;
	default:
		return NULL;
	}

	get_symbol_data("vmcoreinfo_size", sizeof(vmcoreinfo_size), &vmcoreinfo_size);

	sprintf(keybuf, "%s=", key);

	if ((buf = malloc(vmcoreinfo_size+1)) == NULL) {
		error(INFO, "cannot malloc vmcoreinfo buffer\n");
		goto err;
	}

	if (!readmem(vmcoreinfo_data, KVADDR, buf, vmcoreinfo_size,
            "vmcoreinfo_data", RETURN_ON_ERROR|QUIET)) {
		error(INFO, "cannot read vmcoreinfo_data\n");
		goto err;
	}

	buf[vmcoreinfo_size] = '\n';

	if ((p1 = strstr(buf, keybuf))) {
		p2 = p1 + strlen(keybuf);
		p1 = strstr(p2, "\n");
		value_length = p1-p2;
		value_string = calloc(value_length+1, sizeof(char));
		strncpy(value_string, p2, value_length);
		value_string[value_length] = NULLCHAR;
	}
err:
	if (buf)
		free(buf);

	return value_string;
}

static void
check_vmcoreinfo(void)
{
	if (!kernel_symbol_exists("vmcoreinfo_data") ||
	    !kernel_symbol_exists("vmcoreinfo_size"))
		return;

	if (pc->read_vmcoreinfo == no_vmcoreinfo) {
		switch (get_symbol_type("vmcoreinfo_data", NULL, NULL))
		{
		case TYPE_CODE_PTR:
			pc->read_vmcoreinfo = vmcoreinfo_read_string;
			break;
		case TYPE_CODE_ARRAY:
			pc->read_vmcoreinfo = vmcoreinfo_read_string;
			break;
		}
	}
}

static
int get_linux_banner_from_vmlinux(char *buf, size_t size)
{
	struct bfd_section *sect;
	long offset;
	ulong start_rodata;

	if (kernel_symbol_exists(".rodata"))
		start_rodata = symbol_value(".rodata");
	else if (kernel_symbol_exists("__start_rodata"))
		start_rodata = symbol_value("__start_rodata");
	else
		return FALSE;

	sect = bfd_get_section_by_name(st->bfd, ".rodata");
	if (!sect)
		return FALSE;

	/*
	 * Although symbol_value() returns dynamic symbol value that
	 * is affected by kaslr, which is different from static symbol
	 * value in vmlinux file, but relative offset to linux_banner
	 * object in .rodata section is idential.
	 */
	offset = symbol_value("linux_banner") - start_rodata;

	if (!bfd_get_section_contents(st->bfd,
				      sect,
				      buf,
				      offset,
				      size))
		return FALSE;

	return TRUE;
}
