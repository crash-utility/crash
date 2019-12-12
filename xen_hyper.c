/*
 *  xen_hyper.c
 *
 *  Portions Copyright (C) 2006-2007 Fujitsu Limited
 *  Portions Copyright (C) 2006-2007 VA Linux Systems Japan K.K.
 *
 *  Authors: Itsuro Oda <oda@valinux.co.jp>
 *           Fumihiko Kakuma <kakuma@valinux.co.jp>
 *
 *  This file is part of Xencrash.
 *
 *  Xencrash is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  Xencrash is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Xencrash; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA.
 */

#include "defs.h"

#ifdef XEN_HYPERVISOR_ARCH
#include "xen_hyper_defs.h"

static void xen_hyper_schedule_init(void);

/*
 * Do initialization for Xen Hyper system here.
 */
void
xen_hyper_init(void)
{
	char *buf;
#if defined(X86) || defined(X86_64)
	long member_offset;
#endif

#ifdef X86_64
	xht->xen_virt_start = symbol_value("start");

	/*
	 * Xen virtual mapping is aligned to 1 GiB boundary.
	 * Image starts no more than 1 GiB below
	 * beginning of virtual address space.
	 */
	xht->xen_virt_start &= 0xffffffffc0000000;
#endif

	if (machine_type("X86_64") &&
	    symbol_exists("xen_phys_start") && !xen_phys_start())
		error(WARNING, 
	 	    "This hypervisor is relocatable; if initialization fails below, try\n"
                    "         using the \"--xen_phys_start <address>\" command line option.\n\n");

	if (symbol_exists("crashing_cpu")) {
		get_symbol_data("crashing_cpu", sizeof(xht->crashing_cpu),
			&xht->crashing_cpu);
	} else {
		xht->crashing_cpu = XEN_HYPER_PCPU_ID_INVALID;
	}
	machdep->get_smp_cpus();
	machdep->memory_size();

	if (symbol_exists("__per_cpu_offset")) {
		xht->flags |= XEN_HYPER_SMP;
		if((xht->__per_cpu_offset = malloc(sizeof(ulong) * XEN_HYPER_MAX_CPUS())) == NULL) {
			error(FATAL, "cannot malloc __per_cpu_offset space.\n");
		}
		if (!readmem(symbol_value("__per_cpu_offset"), KVADDR,
		xht->__per_cpu_offset, sizeof(ulong) * XEN_HYPER_MAX_CPUS(),
		"__per_cpu_offset", RETURN_ON_ERROR)) {
			error(FATAL, "cannot read __per_cpu_offset.\n");
		}
	}

#if defined(X86) || defined(X86_64)
	if (symbol_exists("__per_cpu_shift")) {
		xht->percpu_shift = (int)symbol_value("__per_cpu_shift");
	} else if (xen_major_version() >= 3 && xen_minor_version() >= 3) {
		xht->percpu_shift = 13;
	} else {
		xht->percpu_shift = 12;
	}
	member_offset = MEMBER_OFFSET("cpuinfo_x86", "x86_model_id");
	buf = GETBUF(XEN_HYPER_SIZE(cpuinfo_x86));	
	if (xen_hyper_test_pcpu_id(XEN_HYPER_CRASHING_CPU())) {
		xen_hyper_x86_fill_cpu_data(XEN_HYPER_CRASHING_CPU(), buf);
	} else {
		xen_hyper_x86_fill_cpu_data(xht->cpu_idxs[0], buf);
	}
	strncpy(xht->utsname.machine, (char *)(buf + member_offset),
		sizeof(xht->utsname.machine)-1);
	FREEBUF(buf);
#elif defined(IA64)
	buf = GETBUF(XEN_HYPER_SIZE(cpuinfo_ia64));
	if (xen_hyper_test_pcpu_id(XEN_HYPER_CRASHING_CPU())) {
		xen_hyper_ia64_fill_cpu_data(XEN_HYPER_CRASHING_CPU(), buf);
	} else {
		xen_hyper_ia64_fill_cpu_data(xht->cpu_idxs[0], buf);
	}
	strncpy(xht->utsname.machine, (char *)(buf + XEN_HYPER_OFFSET(cpuinfo_ia64_vendor)),
		sizeof(xht->utsname.machine)-1);
	FREEBUF(buf);
#endif

#ifndef IA64
	XEN_HYPER_STRUCT_SIZE_INIT(note_buf_t, "note_buf_t");
	XEN_HYPER_STRUCT_SIZE_INIT(crash_note_t, "crash_note_t");
	XEN_HYPER_MEMBER_OFFSET_INIT(crash_note_t_core, "crash_note_t", "core");
	XEN_HYPER_MEMBER_OFFSET_INIT(crash_note_t_xen, "crash_note_t", "xen");
	XEN_HYPER_MEMBER_OFFSET_INIT(crash_note_t_xen_regs, "crash_note_t", "xen_regs");
	XEN_HYPER_MEMBER_OFFSET_INIT(crash_note_t_xen_info, "crash_note_t", "xen_info");

	XEN_HYPER_STRUCT_SIZE_INIT(crash_note_core_t, "crash_note_core_t");
	XEN_HYPER_MEMBER_OFFSET_INIT(crash_note_core_t_note, "crash_note_core_t", "note");
	XEN_HYPER_MEMBER_OFFSET_INIT(crash_note_core_t_desc, "crash_note_core_t", "desc");

	XEN_HYPER_STRUCT_SIZE_INIT(crash_note_xen_t, "crash_note_xen_t");
	XEN_HYPER_MEMBER_OFFSET_INIT(crash_note_xen_t_note, "crash_note_xen_t", "note");
	XEN_HYPER_MEMBER_OFFSET_INIT(crash_note_xen_t_desc, "crash_note_xen_t", "desc");
	XEN_HYPER_STRUCT_SIZE_INIT(crash_note_xen_core_t, "crash_note_xen_core_t");
	XEN_HYPER_MEMBER_OFFSET_INIT(crash_note_xen_core_t_note, "crash_note_xen_core_t", "note");
	XEN_HYPER_MEMBER_OFFSET_INIT(crash_note_xen_core_t_desc, "crash_note_xen_core_t", "desc");
	XEN_HYPER_STRUCT_SIZE_INIT(crash_note_xen_info_t, "crash_note_xen_info_t");
	XEN_HYPER_MEMBER_OFFSET_INIT(crash_note_xen_info_t_note, "crash_note_xen_info_t", "note");
	XEN_HYPER_MEMBER_OFFSET_INIT(crash_note_xen_info_t_desc, "crash_note_xen_info_t", "desc");
	XEN_HYPER_STRUCT_SIZE_INIT(crash_xen_core_t, "crash_xen_core_t");
	XEN_HYPER_STRUCT_SIZE_INIT(crash_xen_info_t, "crash_xen_info_t");
	XEN_HYPER_STRUCT_SIZE_INIT(xen_crash_xen_regs_t, "xen_crash_xen_regs_t");

	XEN_HYPER_STRUCT_SIZE_INIT(ELF_Prstatus,"ELF_Prstatus");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_info, "ELF_Prstatus", "pr_info");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_cursig, "ELF_Prstatus", "pr_cursig");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_sigpend, "ELF_Prstatus", "pr_sigpend");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_sighold, "ELF_Prstatus", "pr_sighold");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_pid, "ELF_Prstatus", "pr_pid");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_ppid, "ELF_Prstatus", "pr_ppid");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_pgrp, "ELF_Prstatus", "pr_pgrp");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_sid, "ELF_Prstatus", "pr_sid");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_utime, "ELF_Prstatus", "pr_utime");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_stime, "ELF_Prstatus", "pr_stime");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_cutime, "ELF_Prstatus", "pr_cutime");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_cstime, "ELF_Prstatus", "pr_cstime");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_reg, "ELF_Prstatus", "pr_reg");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_fpvalid, "ELF_Prstatus", "pr_fpvalid");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Timeval_tv_sec, "ELF_Timeval", "tv_sec");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Timeval_tv_usec, "ELF_Timeval", "tv_usec");
	XEN_HYPER_STRUCT_SIZE_INIT(ELF_Signifo,"ELF_Signifo");
	XEN_HYPER_STRUCT_SIZE_INIT(ELF_Gregset,"ELF_Gregset");
	XEN_HYPER_STRUCT_SIZE_INIT(ELF_Timeval,"ELF_Timeval");
#endif
	XEN_HYPER_STRUCT_SIZE_INIT(domain, "domain");
	XEN_HYPER_STRUCT_SIZE_INIT(vcpu, "vcpu");
#ifndef IA64
	XEN_HYPER_STRUCT_SIZE_INIT(cpu_info, "cpu_info");
#endif
	XEN_HYPER_STRUCT_SIZE_INIT(cpu_user_regs, "cpu_user_regs");

	xht->idle_vcpu_size = get_array_length("idle_vcpu", NULL, 0);
	xht->idle_vcpu_array = (ulong *)malloc(xht->idle_vcpu_size * sizeof(ulong));
	if (xht->idle_vcpu_array == NULL) {
		error(FATAL, "cannot malloc idle_vcpu_array space.\n");
	}
	if (!readmem(symbol_value("idle_vcpu"), KVADDR, xht->idle_vcpu_array,
		xht->idle_vcpu_size * sizeof(ulong), "idle_vcpu_array",
		RETURN_ON_ERROR)) {
		error(FATAL, "cannot read idle_vcpu array.\n");
	}

	/*
	 * Do some initialization.
	 */
#ifndef IA64
	xen_hyper_dumpinfo_init();
#endif
	xhmachdep->pcpu_init();
	xen_hyper_domain_init();
	xen_hyper_vcpu_init();
	xen_hyper_misc_init();
	/*
	 * xen_hyper_post_init() have to be called after all initialize
	 * functions finished.
	 */
	xen_hyper_post_init();
}

/*
 * Do initialization for Domain of Xen Hyper system here.
 */
void
xen_hyper_domain_init(void)
{
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_domain_id, "domain", "domain_id");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_tot_pages, "domain", "tot_pages");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_max_pages, "domain", "max_pages");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_xenheap_pages, "domain", "xenheap_pages");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_shared_info, "domain", "shared_info");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_sched_priv, "domain", "sched_priv");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_next_in_list, "domain", "next_in_list");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_domain_flags, "domain", "domain_flags");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_evtchn, "domain", "evtchn");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_is_hvm, "domain", "is_hvm");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_guest_type, "domain", "guest_type");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_is_privileged, "domain", "is_privileged");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_debugger_attached, "domain", "debugger_attached");

	/*
	 * Will be removed in Xen 4.4 (hg ae9b223a675d),
	 * need to check that with XEN_HYPER_VALID_MEMBER() before using
	 */
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_is_polling, "domain", "is_polling");

	XEN_HYPER_MEMBER_OFFSET_INIT(domain_is_dying, "domain", "is_dying");
	/*
	 * With Xen 4.2.5 is_paused_by_controller changed to
	 * controller_pause_count.
	 */
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_is_paused_by_controller, "domain", "is_paused_by_controller");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_controller_pause_count, "domain", "controller_pause_count");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_is_shutting_down, "domain", "is_shutting_down");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_is_shut_down, "domain", "is_shut_down");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_vcpu, "domain", "vcpu");
	XEN_HYPER_MEMBER_SIZE_INIT(domain_vcpu, "domain", "vcpu");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_max_vcpus, "domain", "max_vcpus");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_arch, "domain", "arch");

	XEN_HYPER_STRUCT_SIZE_INIT(arch_shared_info, "arch_shared_info");
	XEN_HYPER_MEMBER_OFFSET_INIT(arch_shared_info_max_pfn, "arch_shared_info", "max_pfn");
	XEN_HYPER_MEMBER_OFFSET_INIT(arch_shared_info_pfn_to_mfn_frame_list_list, "arch_shared_info", "pfn_to_mfn_frame_list_list");
	XEN_HYPER_MEMBER_OFFSET_INIT(arch_shared_info_nmi_reason, "arch_shared_info", "nmi_reason");

	XEN_HYPER_STRUCT_SIZE_INIT(shared_info, "shared_info");
	XEN_HYPER_MEMBER_OFFSET_INIT(shared_info_vcpu_info, "shared_info", "vcpu_info");
	XEN_HYPER_MEMBER_OFFSET_INIT(shared_info_evtchn_pending, "shared_info", "evtchn_pending");
	XEN_HYPER_MEMBER_OFFSET_INIT(shared_info_evtchn_mask, "shared_info", "evtchn_mask");
	XEN_HYPER_MEMBER_OFFSET_INIT(shared_info_arch, "shared_info", "arch");

	XEN_HYPER_STRUCT_SIZE_INIT(arch_domain, "arch_domain");
#ifdef IA64
	XEN_HYPER_MEMBER_OFFSET_INIT(arch_domain_mm, "arch_domain", "mm");

	XEN_HYPER_STRUCT_SIZE_INIT(mm_struct, "mm_struct");
	XEN_HYPER_MEMBER_OFFSET_INIT(mm_struct_pgd, "mm_struct", "pgd");
#endif

	if((xhdt->domain_struct = malloc(XEN_HYPER_SIZE(domain))) == NULL) {
		error(FATAL, "cannot malloc domain struct space.\n");
	}
	if((xhdt->domain_struct_verify = malloc(XEN_HYPER_SIZE(domain))) == NULL) {
		error(FATAL, "cannot malloc domain struct space to verification.\n");
	}
	xen_hyper_refresh_domain_context_space();
	xhdt->flags |= XEN_HYPER_DOMAIN_F_INIT;
}

/*
 * Do initialization for vcpu of Xen Hyper system here.
 */
void
xen_hyper_vcpu_init(void)
{
	XEN_HYPER_STRUCT_SIZE_INIT(timer, "timer");
	XEN_HYPER_MEMBER_OFFSET_INIT(timer_expires, "timer", "expires");
	XEN_HYPER_MEMBER_OFFSET_INIT(timer_cpu, "timer", "cpu");
	XEN_HYPER_MEMBER_OFFSET_INIT(timer_function, "timer", "function");
	XEN_HYPER_MEMBER_OFFSET_INIT(timer_data, "timer", "data");
	XEN_HYPER_MEMBER_OFFSET_INIT(timer_heap_offset, "timer", "heap_offset");
	XEN_HYPER_MEMBER_OFFSET_INIT(timer_killed, "timer", "killed");

	XEN_HYPER_STRUCT_SIZE_INIT(vcpu_runstate_info, "vcpu_runstate_info");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_runstate_info_state, "vcpu_runstate_info", "state");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_runstate_info_state_entry_time, "vcpu_runstate_info", "state_entry_time");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_runstate_info_time, "vcpu_runstate_info", "time");

	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_vcpu_id, "vcpu", "vcpu_id");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_processor, "vcpu", "processor");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_vcpu_info, "vcpu", "vcpu_info");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_domain, "vcpu", "domain");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_next_in_list, "vcpu", "next_in_list");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_timer, "vcpu", "timer");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_sleep_tick, "vcpu", "sleep_tick");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_poll_timer, "vcpu", "poll_timer");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_sched_priv, "vcpu", "sched_priv");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_runstate, "vcpu", "runstate");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_runstate_guest, "vcpu", "runstate_guest");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_vcpu_flags, "vcpu", "vcpu_flags");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_pause_count, "vcpu", "pause_count");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_virq_to_evtchn, "vcpu", "virq_to_evtchn");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_cpu_affinity, "vcpu", "cpu_affinity");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_nmi_addr, "vcpu", "nmi_addr");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_vcpu_dirty_cpumask, "vcpu", "vcpu_dirty_cpumask");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_arch, "vcpu", "arch");

#ifdef IA64
	XEN_HYPER_ASSIGN_OFFSET(vcpu_thread_ksp) =
		MEMBER_OFFSET("vcpu", "arch") + MEMBER_OFFSET("arch_vcpu", "_thread") +
		MEMBER_OFFSET("thread_struct", "ksp");
#endif

	if((xhvct->vcpu_struct = malloc(XEN_HYPER_SIZE(vcpu))) == NULL) {
		error(FATAL, "cannot malloc vcpu struct space.\n");
	}
	if((xhvct->vcpu_struct_verify = malloc(XEN_HYPER_SIZE(vcpu))) == NULL) {
		error(FATAL, "cannot malloc vcpu struct space to verification.\n");
	}

	xen_hyper_refresh_vcpu_context_space();
	xhvct->flags |= XEN_HYPER_VCPU_F_INIT;
	xhvct->idle_vcpu = symbol_value("idle_vcpu");
}

/*
 * Do initialization for pcpu of Xen Hyper system here.
 */
#if defined(X86) || defined(X86_64)
void
xen_hyper_x86_pcpu_init(void)
{
	ulong cpu_info;
	ulong init_tss_base, init_tss;
	ulong sp;
	struct xen_hyper_pcpu_context *pcc;
	char *buf, *bp;
	int i, cpuid;
	int flag;

	XEN_HYPER_MEMBER_OFFSET_INIT(cpu_info_guest_cpu_user_regs, "cpu_info", "guest_cpu_user_regs");
	XEN_HYPER_MEMBER_OFFSET_INIT(cpu_info_processor_id, "cpu_info", "processor_id");
	XEN_HYPER_MEMBER_OFFSET_INIT(cpu_info_current_vcpu, "cpu_info", "current_vcpu");

	if((xhpct->pcpu_struct = malloc(XEN_HYPER_SIZE(cpu_info))) == NULL) {
		error(FATAL, "cannot malloc pcpu struct space.\n");
	}
	/* get physical cpu context */
	xen_hyper_alloc_pcpu_context_space(XEN_HYPER_MAX_CPUS());
	if (symbol_exists("per_cpu__init_tss")) {
		init_tss_base = symbol_value("per_cpu__init_tss");
		flag = TRUE;
	} else if (symbol_exists("per_cpu__tss_page")) {
			init_tss_base = symbol_value("per_cpu__tss_page");
			flag = TRUE;
	} else {
		init_tss_base = symbol_value("init_tss");
		flag = FALSE;
	}
	buf = GETBUF(XEN_HYPER_SIZE(tss));
	for_cpu_indexes(i, cpuid)
	{
		if (flag)
			init_tss = xen_hyper_per_cpu(init_tss_base, cpuid);
		else
			init_tss = init_tss_base +
				XEN_HYPER_SIZE(tss) * cpuid;
		if (!readmem(init_tss, KVADDR, buf,
			XEN_HYPER_SIZE(tss), "init_tss", RETURN_ON_ERROR)) {
			error(FATAL, "cannot read init_tss.\n");
		}
		if (machine_type("X86")) {
			sp = ULONG(buf + XEN_HYPER_OFFSET(tss_esp0));
		} else if (machine_type("X86_64")) {
			sp = ULONG(buf + XEN_HYPER_OFFSET(tss_rsp0));
		} else
			sp = 0;
		cpu_info = XEN_HYPER_GET_CPU_INFO(sp);
		if (CRASHDEBUG(1)) {
			fprintf(fp, "sp=%lx, cpu_info=%lx\n", sp, cpu_info);
		}
		if(!(bp = xen_hyper_read_pcpu(cpu_info))) {
			error(FATAL, "cannot read cpu_info.\n");
		}
		pcc = &xhpct->context_array[cpuid];
		xen_hyper_store_pcpu_context(pcc, cpu_info, bp);
		xen_hyper_store_pcpu_context_tss(pcc, init_tss, buf);
	}
	FREEBUF(buf);
}

#elif defined(IA64)
void
xen_hyper_ia64_pcpu_init(void)
{
	struct xen_hyper_pcpu_context *pcc;
	int i, cpuid;

	/* get physical cpu context */
	xen_hyper_alloc_pcpu_context_space(XEN_HYPER_MAX_CPUS());
	for_cpu_indexes(i, cpuid)
	{
		pcc = &xhpct->context_array[cpuid];
		pcc->processor_id = cpuid;
	}
}
#endif

/*
 * Do initialization for some miscellaneous thing
 * of Xen Hyper system here.
 */
void
xen_hyper_misc_init(void)
{
	XEN_HYPER_STRUCT_SIZE_INIT(schedule_data, "schedule_data");
	XEN_HYPER_MEMBER_OFFSET_INIT(schedule_data_schedule_lock, "schedule_data", "schedule_lock");
	XEN_HYPER_MEMBER_OFFSET_INIT(schedule_data_curr, "schedule_data", "curr");
	if (MEMBER_EXISTS("schedule_data", "idle"))
		XEN_HYPER_MEMBER_OFFSET_INIT(schedule_data_idle, "schedule_data", "idle");
	XEN_HYPER_MEMBER_OFFSET_INIT(schedule_data_sched_priv, "schedule_data", "sched_priv");
	XEN_HYPER_MEMBER_OFFSET_INIT(schedule_data_s_timer, "schedule_data", "s_timer");
	XEN_HYPER_MEMBER_OFFSET_INIT(schedule_data_tick, "schedule_data", "tick");

	XEN_HYPER_STRUCT_SIZE_INIT(scheduler, "scheduler");
	XEN_HYPER_MEMBER_OFFSET_INIT(scheduler_name, "scheduler", "name");
	XEN_HYPER_MEMBER_OFFSET_INIT(scheduler_opt_name, "scheduler", "opt_name");
	XEN_HYPER_MEMBER_OFFSET_INIT(scheduler_sched_id, "scheduler", "sched_id");
	XEN_HYPER_MEMBER_OFFSET_INIT(scheduler_init, "scheduler", "init");
	XEN_HYPER_MEMBER_OFFSET_INIT(scheduler_tick, "scheduler", "tick");
	XEN_HYPER_MEMBER_OFFSET_INIT(scheduler_init_vcpu, "scheduler", "init_vcpu");
	XEN_HYPER_MEMBER_OFFSET_INIT(scheduler_destroy_domain, "scheduler", "destroy_domain");
	XEN_HYPER_MEMBER_OFFSET_INIT(scheduler_sleep, "scheduler", "sleep");
	XEN_HYPER_MEMBER_OFFSET_INIT(scheduler_wake, "scheduler", "wake");
	XEN_HYPER_MEMBER_OFFSET_INIT(scheduler_set_affinity, "scheduler", "set_affinity");
	XEN_HYPER_MEMBER_OFFSET_INIT(scheduler_do_schedule, "scheduler", "do_schedule");
	XEN_HYPER_MEMBER_OFFSET_INIT(scheduler_adjust, "scheduler", "adjust");
	XEN_HYPER_MEMBER_OFFSET_INIT(scheduler_dump_settings, "scheduler", "dump_settings");
	XEN_HYPER_MEMBER_OFFSET_INIT(scheduler_dump_cpu_state, "scheduler", "dump_cpu_state");

	xen_hyper_schedule_init();
}

/*
 * Do initialization for scheduler of Xen Hyper system here.
 */
#define XEN_HYPER_SCHEDULER_NAME 1024

static int section_size(char *start_section, char *end_section)
{
	ulong sp_start, sp_end;

	sp_start = symbol_value(start_section);
	sp_end = symbol_value(end_section);

	return (sp_end - sp_start) / sizeof(long);
}

static void
xen_hyper_schedule_init(void)
{
	ulong addr, opt_sched, schedulers, opt_name;
	long scheduler_opt_name;
	long *schedulers_buf;
	int nr_schedulers;
	struct xen_hyper_sched_context *schc;
	char *buf;
	char opt_name_buf[XEN_HYPER_OPT_SCHED_SIZE];
	int i, cpuid, flag;
	char *sp_name;

	/* get scheduler information */
	if((xhscht->scheduler_struct =
	malloc(XEN_HYPER_SIZE(scheduler))) == NULL) {
		error(FATAL, "cannot malloc scheduler struct space.\n");
	}
	buf = GETBUF(XEN_HYPER_SCHEDULER_NAME);	
	scheduler_opt_name = XEN_HYPER_OFFSET(scheduler_opt_name);
	if (symbol_exists("ops")) {
		if (!readmem(symbol_value("ops") + scheduler_opt_name, KVADDR,
			&opt_sched, sizeof(ulong), "ops.opt_name",
			RETURN_ON_ERROR)) {
			error(FATAL, "cannot read ops.opt_name.\n");
		}
	} else {
		opt_sched = symbol_value("opt_sched");
	}
	if (!readmem(opt_sched, KVADDR, xhscht->opt_sched,
	XEN_HYPER_OPT_SCHED_SIZE, "opt_sched,", RETURN_ON_ERROR)) {
		error(FATAL, "cannot read opt_sched,.\n");
	}

	/* symbol exists since Xen 4.7 */
	if (symbol_exists("__start_schedulers_array")) {
		sp_name = "__start_schedulers_array";
		nr_schedulers = section_size("__start_schedulers_array",
					     "__end_schedulers_array");
	} else {
		sp_name = "schedulers";
		nr_schedulers = get_array_length("schedulers", 0, 0);
	}

	schedulers_buf = (long *)GETBUF(nr_schedulers * sizeof(long));
	schedulers = symbol_value(sp_name);
	addr = schedulers;
	while (xhscht->name == NULL) {
		if (!readmem(addr, KVADDR, schedulers_buf,
			     sizeof(long) * nr_schedulers,
			     "schedulers", RETURN_ON_ERROR)) {
			error(FATAL, "cannot read schedulers.\n");
		}
		for (i = 0; i < nr_schedulers; i++) {
			if (schedulers_buf[i] == 0) {
				error(FATAL, "schedule data not found.\n");
			}
			if (!readmem(schedulers_buf[i], KVADDR,
			xhscht->scheduler_struct, XEN_HYPER_SIZE(scheduler),
			"scheduler", RETURN_ON_ERROR)) {
				error(FATAL, "cannot read scheduler.\n");
			}
			opt_name = ULONG(xhscht->scheduler_struct +
				scheduler_opt_name);
			if (!readmem(opt_name, KVADDR, opt_name_buf,
			XEN_HYPER_OPT_SCHED_SIZE, "opt_name", RETURN_ON_ERROR)) {
				error(FATAL, "cannot read opt_name.\n");
			}
			if (strncmp(xhscht->opt_sched, opt_name_buf,
			XEN_HYPER_OPT_SCHED_SIZE))
				continue;
			xhscht->scheduler = schedulers_buf[i];
			xhscht->sched_id = INT(xhscht->scheduler_struct +
				XEN_HYPER_OFFSET(scheduler_sched_id));
			addr = ULONG(xhscht->scheduler_struct +
				XEN_HYPER_OFFSET(scheduler_name));
			if (!readmem(addr, KVADDR, buf, XEN_HYPER_SCHEDULER_NAME,
			"scheduler_name", RETURN_ON_ERROR)) {
				error(FATAL, "cannot read scheduler_name.\n");
			}
			if (strlen(buf) >= XEN_HYPER_SCHEDULER_NAME) {
				error(FATAL, "cannot read scheduler_name.\n");
			}
			if((xhscht->name = malloc(strlen(buf) + 1)) == NULL) {
				error(FATAL, "cannot malloc scheduler_name space.\n");
			}
			BZERO(xhscht->name, strlen(buf) + 1);
			BCOPY(buf, xhscht->name, strlen(buf));
			break;
		}
		addr += sizeof(long) * nr_schedulers;
	}
	FREEBUF(buf);
	FREEBUF(schedulers_buf);

	/* get schedule_data information */
	if((xhscht->sched_context_array =
	malloc(sizeof(struct xen_hyper_sched_context) * XEN_HYPER_MAX_CPUS())) == NULL) {
		error(FATAL, "cannot malloc xen_hyper_sched_context struct space.\n");
	}
	BZERO(xhscht->sched_context_array,
		sizeof(struct xen_hyper_sched_context) * XEN_HYPER_MAX_CPUS());
	buf = GETBUF(XEN_HYPER_SIZE(schedule_data));	
	if (symbol_exists("per_cpu__schedule_data")) {
		addr = symbol_value("per_cpu__schedule_data");
		flag = TRUE;
	} else {
		addr = symbol_value("schedule_data");
		flag = FALSE;
	}
	for_cpu_indexes(i, cpuid)
	{
		schc = &xhscht->sched_context_array[cpuid];
		if (flag) {
			schc->schedule_data =
				xen_hyper_per_cpu(addr, i);
		} else {
			schc->schedule_data = addr +
				XEN_HYPER_SIZE(schedule_data) * i;
		}
		if (!readmem(schc->schedule_data,
			KVADDR, buf, XEN_HYPER_SIZE(schedule_data),
		"schedule_data", RETURN_ON_ERROR)) {
			error(FATAL, "cannot read schedule_data.\n");
		}
		schc->cpu_id = cpuid;
		schc->curr = ULONG(buf + XEN_HYPER_OFFSET(schedule_data_curr));
		if (MEMBER_EXISTS("schedule_data", "idle"))
			schc->idle = ULONG(buf + XEN_HYPER_OFFSET(schedule_data_idle));
		else
			schc->idle = xht->idle_vcpu_array[cpuid];
		schc->sched_priv =
			ULONG(buf + XEN_HYPER_OFFSET(schedule_data_sched_priv));
		if (XEN_HYPER_VALID_MEMBER(schedule_data_tick))
			schc->tick = ULONG(buf + XEN_HYPER_OFFSET(schedule_data_tick));
	}
	FREEBUF(buf);
}

/*
 * This should be called after all initailize process finished.
 */
void
xen_hyper_post_init(void)
{
	struct xen_hyper_pcpu_context *pcc;
	int i, cpuid;

	/* set current vcpu to pcpu context */
	for_cpu_indexes(i, cpuid)
	{
		pcc = &xhpct->context_array[cpuid];
		if (!pcc->current_vcpu) {
			pcc->current_vcpu =
				xen_hyper_get_active_vcpu_from_pcpuid(cpuid);
		}
	}

	/* set pcpu last */
	if (!(xhpct->last =
		xen_hyper_id_to_pcpu_context(XEN_HYPER_CRASHING_CPU()))) {
		xhpct->last = &xhpct->context_array[xht->cpu_idxs[0]];
	}

	/* set vcpu last */
	if (xhpct->last) {
		xhvct->last =
			xen_hyper_vcpu_to_vcpu_context(xhpct->last->current_vcpu);
		/* set crashing vcpu */
		xht->crashing_vcc = xhvct->last;
	}
	if (!xhvct->last) {
		xhvct->last = xhvct->vcpu_context_arrays->context_array;
	}

	/* set domain last */
	if (xhvct->last) {
		xhdt->last =
			xen_hyper_domain_to_domain_context(xhvct->last->domain);
	}
	if (!xhdt->last) {
		xhdt->last = xhdt->context_array;
	}
}

/*
 * Do initialization for dump information here.
 */
void
xen_hyper_dumpinfo_init(void)
{
	Elf32_Nhdr *note;
	char *buf, *bp, *np, *upp;
	char *nccp, *xccp;
	ulong addr;
	long size;
	int i, cpuid, samp_cpuid;

	/*
	 * NOTE kakuma: It is not clear that what kind of
	 * a elf note format each one of the xen uses.
	 * So, we decide it confirming whether a symbol exists.
	 */
	if (STRUCT_EXISTS("note_buf_t"))
		xhdit->note_ver = XEN_HYPER_ELF_NOTE_V1;
	else if (STRUCT_EXISTS("crash_note_xen_t"))
		xhdit->note_ver = XEN_HYPER_ELF_NOTE_V2;
	else if (STRUCT_EXISTS("crash_xen_core_t")) {
		if (STRUCT_EXISTS("crash_note_xen_core_t"))
			xhdit->note_ver = XEN_HYPER_ELF_NOTE_V3;
		else
			xhdit->note_ver = XEN_HYPER_ELF_NOTE_V4;
	} else {
		error(WARNING, "found unsupported elf note format while checking of xen dumpinfo.\n");
		return;
	}
	if (!xen_hyper_test_pcpu_id(XEN_HYPER_CRASHING_CPU())) {
		error(WARNING, "crashing_cpu not found.\n");
		return;
	}

	/* allocate a context area */
	size = sizeof(struct xen_hyper_dumpinfo_context) * machdep->get_smp_cpus();
	if((xhdit->context_array = malloc(size)) == NULL) {
		error(FATAL, "cannot malloc dumpinfo table context space.\n");
	}
	BZERO(xhdit->context_array, size);
	size = sizeof(struct xen_hyper_dumpinfo_context_xen_core) * machdep->get_smp_cpus();
	if((xhdit->context_xen_core_array = malloc(size)) == NULL) {
		error(FATAL, "cannot malloc dumpinfo table context_xen_core_array space.\n");
	}
	BZERO(xhdit->context_xen_core_array, size);
	if (symbol_exists("per_cpu__crash_notes"))
		addr = symbol_value("per_cpu__crash_notes");
	else
		get_symbol_data("crash_notes", sizeof(ulong), &addr);
	for (i = 0; i < machdep->get_smp_cpus(); i++) {
		ulong addr_notes;

		if (symbol_exists("per_cpu__crash_notes"))
			addr_notes = xen_hyper_per_cpu(addr, i);
		else
			addr_notes = addr + i * STRUCT_SIZE("crash_note_range_t") +
					MEMBER_OFFSET("crash_note_range_t", "start");
		if (xhdit->note_ver == XEN_HYPER_ELF_NOTE_V4) {
			if (!readmem(addr_notes, KVADDR, &(xhdit->context_array[i].note),
			sizeof(ulong), "crash_notes", RETURN_ON_ERROR)) {
				error(WARNING, "cannot read crash_notes.\n");
				return;
			}
		} else {
			xhdit->context_array[i].note = addr_notes;
		}
	}

	if (xhdit->note_ver == XEN_HYPER_ELF_NOTE_V1) {
		xhdit->note_size = XEN_HYPER_SIZE(note_buf_t);
	} else if (xhdit->note_ver == XEN_HYPER_ELF_NOTE_V4) {
		xhdit->note_size = XEN_HYPER_ELF_NOTE_V4_NOTE_SIZE;
	} else {
		xhdit->note_size = XEN_HYPER_SIZE(crash_note_t);
	}

	/* read a sample note */
	buf = GETBUF(xhdit->note_size);
	if (xhdit->note_ver == XEN_HYPER_ELF_NOTE_V4)
		samp_cpuid = xht->cpu_idxs[0];
	else
		samp_cpuid = XEN_HYPER_CRASHING_CPU();
	xhdit->xen_info_cpu = samp_cpuid;
	if (!xen_hyper_fill_elf_notes(xhdit->context_array[samp_cpuid].note,
	buf, XEN_HYPER_ELF_NOTE_FILL_T_NOTE)) {
		error(FATAL, "cannot read crash_notes.\n");
	}
	bp = buf;

	/* Get elf format information for each version. */
	switch (xhdit->note_ver) {
	case XEN_HYPER_ELF_NOTE_V1:
		/* core data */
		note = (Elf32_Nhdr *)bp;
		np = bp + sizeof(Elf32_Nhdr);
		upp = np + note->n_namesz;
		upp = (char *)roundup((ulong)upp, 4);
		xhdit->core_offset = (Elf_Word)((ulong)upp - (ulong)note);
		note = (Elf32_Nhdr *)(upp + note->n_descsz);
		/* cr3 data */
		np = (char *)note + sizeof(Elf32_Nhdr);
		upp = np + note->n_namesz;
		upp = (char *)roundup((ulong)upp, 4);
		upp = upp + note->n_descsz;
		xhdit->core_size = upp - bp;
		break;
	case XEN_HYPER_ELF_NOTE_V2:
		/* core data */
		xhdit->core_offset = XEN_HYPER_OFFSET(crash_note_core_t_desc);
		xhdit->core_size = XEN_HYPER_SIZE(crash_note_core_t);
		/* xen core */
		xhdit->xen_info_offset = XEN_HYPER_OFFSET(crash_note_xen_t_desc);
		xhdit->xen_info_size = XEN_HYPER_SIZE(crash_note_xen_t);
		break;
	case XEN_HYPER_ELF_NOTE_V3:
		/* core data */
		xhdit->core_offset = XEN_HYPER_OFFSET(crash_note_core_t_desc);
		xhdit->core_size = XEN_HYPER_SIZE(crash_note_core_t);
		/* xen core */
		xhdit->xen_core_offset = XEN_HYPER_OFFSET(crash_note_xen_core_t_desc);
		xhdit->xen_core_size = XEN_HYPER_SIZE(crash_note_xen_core_t);
		/* xen info */
		xhdit->xen_info_offset = XEN_HYPER_OFFSET(crash_note_xen_info_t_desc);
		xhdit->xen_info_size = XEN_HYPER_SIZE(crash_note_xen_info_t);
		break;
	case XEN_HYPER_ELF_NOTE_V4:
		/* core data */
		note = (Elf32_Nhdr *)bp;
		np = bp + sizeof(Elf32_Nhdr);
		upp = np + note->n_namesz;
		upp = (char *)roundup((ulong)upp, 4);
		xhdit->core_offset = (Elf_Word)((ulong)upp - (ulong)note);
		upp = upp + note->n_descsz;
		xhdit->core_size = (Elf_Word)((ulong)upp - (ulong)note);
		if (XEN_HYPER_ELF_NOTE_V4_NOTE_SIZE < xhdit->core_size + 32) {
			error(WARNING, "note size is assumed on crash is incorrect.(core data)\n");
			return;
		}
		/* xen core */
		note = (Elf32_Nhdr *)upp;
		np = (char *)note + sizeof(Elf32_Nhdr);
		upp = np + note->n_namesz;
		upp = (char *)roundup((ulong)upp, 4);
		xhdit->xen_core_offset = (Elf_Word)((ulong)upp - (ulong)note);
		upp = upp + note->n_descsz;
		xhdit->xen_core_size = (Elf_Word)((ulong)upp - (ulong)note);
		if (XEN_HYPER_ELF_NOTE_V4_NOTE_SIZE <
		xhdit->core_size + xhdit->xen_core_size + 32) {
			error(WARNING, "note size is assumed on crash is incorrect.(xen core)\n");
			return;
		}
		/* xen info */
		note = (Elf32_Nhdr *)upp;
		np = (char *)note + sizeof(Elf32_Nhdr);
		upp = np + note->n_namesz;
		upp = (char *)roundup((ulong)upp, 4);
		xhdit->xen_info_offset = (Elf_Word)((ulong)upp - (ulong)note);
		upp = upp + note->n_descsz;
		xhdit->xen_info_size =  (Elf_Word)((ulong)upp - (ulong)note);
		if (XEN_HYPER_ELF_NOTE_V4_NOTE_SIZE <
		xhdit->core_size + xhdit->xen_core_size + xhdit->xen_info_size) {
			error(WARNING, "note size is assumed on crash is incorrect.(xen info)\n");
			return;
		}
		xhdit->note_size = xhdit->core_size + xhdit->xen_core_size + xhdit->xen_info_size;
		break;
	default:
		error(FATAL, "logic error in cheking elf note format occurs.\n");
	}

	/* fill xen info context. */
	if (xhdit->note_ver >= XEN_HYPER_ELF_NOTE_V3) {
		if((xhdit->crash_note_xen_info_ptr =
		malloc(xhdit->xen_info_size)) == NULL) {
			error(FATAL, "cannot malloc dumpinfo table "
				"crash_note_xen_info_ptr space.\n");
		}
		memcpy(xhdit->crash_note_xen_info_ptr,
			bp + xhdit->core_size + xhdit->xen_core_size,
			xhdit->xen_info_size);
		xhdit->context_xen_info.note =
			xhdit->context_array[samp_cpuid].note +
			xhdit->core_size + xhdit->xen_core_size;
		xhdit->context_xen_info.pcpu_id = samp_cpuid;
		xhdit->context_xen_info.crash_xen_info_ptr =
			xhdit->crash_note_xen_info_ptr + xhdit->xen_info_offset;
	}
		
	/* allocate note core */
	size = xhdit->core_size * XEN_HYPER_NR_PCPUS();
	if(!(xhdit->crash_note_core_array = malloc(size))) {
		error(FATAL, "cannot malloc crash_note_core_array space.\n");
	}
	nccp = xhdit->crash_note_core_array;
	BZERO(nccp, size);
	xccp = NULL;

	/* allocate xen core */
	if (xhdit->note_ver >= XEN_HYPER_ELF_NOTE_V2) {
		size = xhdit->xen_core_size * XEN_HYPER_NR_PCPUS();
		if(!(xhdit->crash_note_xen_core_array = malloc(size))) {
			error(FATAL, "cannot malloc dumpinfo table "
				"crash_note_xen_core_array space.\n");
		}
		xccp = xhdit->crash_note_xen_core_array;
		BZERO(xccp, size);
	}

	/* fill a context. */
	for_cpu_indexes(i, cpuid)
	{
		/* fill core context. */
		addr = xhdit->context_array[cpuid].note;
		if (!xen_hyper_fill_elf_notes(addr, nccp,
		XEN_HYPER_ELF_NOTE_FILL_T_CORE)) {
			error(FATAL, "cannot read elf note core.\n");
		}
		xhdit->context_array[cpuid].pcpu_id = cpuid;
		xhdit->context_array[cpuid].ELF_Prstatus_ptr =
			nccp + xhdit->core_offset;
		xhdit->context_array[cpuid].pr_reg_ptr =
			nccp + xhdit->core_offset +
			XEN_HYPER_OFFSET(ELF_Prstatus_pr_reg);

		/* Is there xen core data? */
		if (xhdit->note_ver < XEN_HYPER_ELF_NOTE_V2) {
			nccp += xhdit->core_size;
			continue;
		}
		if (xhdit->note_ver == XEN_HYPER_ELF_NOTE_V2 &&
		cpuid != samp_cpuid) {
			xccp += xhdit->xen_core_size;
			nccp += xhdit->core_size;
			continue;
		}

		/* fill xen core context, in case of more elf note V2. */
		xhdit->context_xen_core_array[cpuid].note =
			xhdit->context_array[cpuid].note +
			xhdit->core_size;
		xhdit->context_xen_core_array[cpuid].pcpu_id = cpuid;
		xhdit->context_xen_core_array[cpuid].crash_xen_core_ptr =
			xccp + xhdit->xen_core_offset;
		if (!xen_hyper_fill_elf_notes(xhdit->context_xen_core_array[cpuid].note,
		xccp, XEN_HYPER_ELF_NOTE_FILL_T_XEN_CORE)) {
			error(FATAL, "cannot read elf note xen core.\n");
		}
		xccp += xhdit->xen_core_size;
		nccp += xhdit->core_size;
	}

	FREEBUF(buf);
}

/*
 * Get dump information context from physical cpu id.
 */
struct xen_hyper_dumpinfo_context *
xen_hyper_id_to_dumpinfo_context(uint id)
{
	if (!xen_hyper_test_pcpu_id(id))
		return NULL;
	return &xhdit->context_array[id];
}

/*
 * Get dump information context from ELF Note address.
 */
struct xen_hyper_dumpinfo_context *
xen_hyper_note_to_dumpinfo_context(ulong note)
{
	int i;

	for (i = 0; i < XEN_HYPER_MAX_CPUS(); i++) {
		if (note == xhdit->context_array[i].note) {
			return &xhdit->context_array[i];
		}
	}
	return NULL;
}

/*
 * Fill ELF Notes header here.
 * This assume that variable note has a top address of an area for
 * specified type.
 */
char *
xen_hyper_fill_elf_notes(ulong note, char *note_buf, int type)
{
	long size;
	ulong rp = note;

	if (type == XEN_HYPER_ELF_NOTE_FILL_T_NOTE)
		size = xhdit->note_size;
	else if (type == XEN_HYPER_ELF_NOTE_FILL_T_CORE)
		size = xhdit->core_size;
	else if (type == XEN_HYPER_ELF_NOTE_FILL_T_XEN_CORE)
		size = xhdit->xen_core_size;
	else if (type == XEN_HYPER_ELF_NOTE_FILL_T_XEN_CORE_M)
		size = xhdit->core_size + xhdit->xen_core_size;
	else if (type == XEN_HYPER_ELF_NOTE_FILL_T_PRS)
		size = XEN_HYPER_SIZE(ELF_Prstatus);
	else if (type == XEN_HYPER_ELF_NOTE_FILL_T_XEN_REGS)
		size = XEN_HYPER_SIZE(xen_crash_xen_regs_t);
	else
		return NULL;

	if (!readmem(rp, KVADDR, note_buf, size,
		"note_buf_t or crash_note_t", RETURN_ON_ERROR)) {
		if (type == XEN_HYPER_ELF_NOTE_FILL_T_NOTE)
			error(WARNING, "cannot fill note_buf_t or crash_note_t.\n");
		else if (type == XEN_HYPER_ELF_NOTE_FILL_T_CORE)
			error(WARNING, "cannot fill note core.\n");
		else if (type == XEN_HYPER_ELF_NOTE_FILL_T_XEN_CORE)
			error(WARNING, "cannot fill note xen core.\n");
		else if (type == XEN_HYPER_ELF_NOTE_FILL_T_XEN_CORE_M)
			error(WARNING, "cannot fill note core & xen core.\n");
		else if (type == XEN_HYPER_ELF_NOTE_FILL_T_PRS)
			error(WARNING, "cannot fill ELF_Prstatus.\n");
		else if (type == XEN_HYPER_ELF_NOTE_FILL_T_XEN_REGS)
			error(WARNING, "cannot fill xen_crash_xen_regs_t.\n");
		return NULL;
	}
	return note_buf;
}



/*
 * Get domain status.
 */
ulong
xen_hyper_domain_state(struct xen_hyper_domain_context *dc)
{
	if (ACTIVE()) {
		if (xen_hyper_read_domain_verify(dc->domain) == NULL) {
			return XEN_HYPER_DOMF_ERROR;
		}
	}
	return dc->domain_flags;
}

/*
 * Allocate domain context space.
 */
void
xen_hyper_refresh_domain_context_space(void)
{
	char *domain_struct;
	ulong domain, next, dom_xen, dom_io, idle_vcpu;
	struct xen_hyper_domain_context *dc;
	struct xen_hyper_domain_context *dom0;
	int i;

	if ((xhdt->flags & XEN_HYPER_DOMAIN_F_INIT) && !ACTIVE()) {
		return;
	}

	XEN_HYPER_RUNNING_DOMAINS() = XEN_HYPER_NR_DOMAINS() =
		xen_hyper_get_domains();
	xen_hyper_alloc_domain_context_space(XEN_HYPER_NR_DOMAINS());

	dc = xhdt->context_array;

	/* restore an dom_io context. */
	get_symbol_data("dom_io", sizeof(dom_io), &dom_io);
	if ((domain_struct = xen_hyper_read_domain(dom_io)) == NULL) {
		error(FATAL, "cannot read dom_io.\n");
	}
	xen_hyper_store_domain_context(dc, dom_io, domain_struct);
	xhdt->dom_io = dc;
	dc++;

	/* restore an dom_xen context. */
	get_symbol_data("dom_xen", sizeof(dom_xen), &dom_xen);
	if ((domain_struct = xen_hyper_read_domain(dom_xen)) == NULL) {
		error(FATAL, "cannot read dom_xen.\n");
	}
	xen_hyper_store_domain_context(dc, dom_xen, domain_struct);
	xhdt->dom_xen = dc;
	dc++;

	/* restore an idle domain context. */
	for (i = 0; i < xht->idle_vcpu_size; i += XEN_HYPER_MAX_VIRT_CPUS) {
		idle_vcpu = xht->idle_vcpu_array[i];
		if (idle_vcpu == 0)
			break;
		if (!readmem(idle_vcpu + MEMBER_OFFSET("vcpu", "domain"),
			KVADDR, &domain, sizeof(domain), "domain", RETURN_ON_ERROR)) {
			error(FATAL, "cannot read domain member in vcpu.\n");
		}
		if (CRASHDEBUG(1)) {
			fprintf(fp, "idle_vcpu=%lx, domain=%lx\n", idle_vcpu, domain);
		}
		if ((domain_struct = xen_hyper_read_domain(domain)) == NULL) {
			error(FATAL, "cannot read idle domain.\n");
		}
		xen_hyper_store_domain_context(dc, domain, domain_struct);
		if (i == 0)
			xhdt->idle_domain = dc;
		dc++;
	}

	/* restore domain contexts from dom0 symbol. */
	xen_hyper_get_domain_next(XEN_HYPER_DOMAIN_READ_DOM0, &next);
	domain = next;
	dom0 = dc;
	while((domain_struct =
	xen_hyper_get_domain_next(XEN_HYPER_DOMAIN_READ_NEXT, &next)) != NULL) {
		xen_hyper_store_domain_context(dc, domain, domain_struct);
		domain = next;
		dc++;
	}
	xhdt->dom0 = dom0;
}

/*
 * Get number of domain.
 */
int
xen_hyper_get_domains(void)
{
	ulong domain, next_in_list;
	long domain_next_in_list;
	int i, j;

	if (!try_get_symbol_data("hardware_domain", sizeof(void *), &domain))
		get_symbol_data("dom0", sizeof(void *), &domain);

	domain_next_in_list = MEMBER_OFFSET("domain", "next_in_list");
	i = 0;
	while (domain != 0) {
		i++;
		next_in_list = domain + domain_next_in_list;
		if (!readmem(next_in_list, KVADDR, &domain, sizeof(void *),
			"domain.next_in_list", RETURN_ON_ERROR)) {
			error(FATAL, "cannot read domain.next_in_list.\n");
		}
	}
	i += 2;		/* for dom_io, dom_xen */
	/* for idle domains */
	for (j = 0; j < xht->idle_vcpu_size; j += XEN_HYPER_MAX_VIRT_CPUS) {
		if (xht->idle_vcpu_array[j])
			i++;
	}
	return i;
}

/*
 * Get next domain struct.
 * 	mod - XEN_HYPER_DOMAIN_READ_DOM0:start from dom0 symbol
 * 	    - XEN_HYPER_DOMAIN_READ_INIT:start from xhdt->context_array
 * 	    - XEN_HYPER_DOMAIN_READ_NEXT:next
 */
char *
xen_hyper_get_domain_next(int mod, ulong *next)
{
	static int idx = 0;

	char *domain_struct;
	struct xen_hyper_domain_context *dc;

	switch (mod) {
	case XEN_HYPER_DOMAIN_READ_DOM0:
		/* Case of search from dom0 symbol. */
		idx = 0;
		if (xhdt->dom0) {
			*next = xhdt->dom0->domain;
		} else {
			if (!try_get_symbol_data("hardware_domain", sizeof(void *), next))
				get_symbol_data("dom0", sizeof(void *), next);
		}
		return xhdt->domain_struct;
		break;
	case XEN_HYPER_DOMAIN_READ_INIT:
		/* Case of search from context_array. */
		if (xhdt->context_array && xhdt->context_array->domain) {
			idx = 1; 		/* this has a next index. */
			*next = xhdt->context_array->domain;
		} else {
			idx = 0;
			*next = 0;
			return NULL;
		}
		return xhdt->domain_struct;
		break;
	case XEN_HYPER_DOMAIN_READ_NEXT:
		break;
	default :
		error(FATAL, "xen_hyper_get_domain_next mod error: %d\n", mod);
		return NULL;
	}

	/* Finished search */
	if (!*next) {
		return NULL;
	}

	domain_struct = NULL;
	/* Is domain context array valid? */
	if (idx) {
		if ((domain_struct =
			xen_hyper_read_domain(*next)) == NULL) {
			error(FATAL, "cannot get next domain from domain context array.\n");
		}
		if (idx > XEN_HYPER_NR_DOMAINS()) {
			*next = 0;
		} else {
			dc = xhdt->context_array;
			dc += idx;
			*next = dc->domain;
			idx++;
		}
		return domain_struct;
	}

	/* Search from dom0 symbol. */
	if ((domain_struct =
		xen_hyper_read_domain(*next)) == NULL) {
		error(FATAL, "cannot get next domain from dom0 symbol.\n");
	}
	*next = ULONG(domain_struct + XEN_HYPER_OFFSET(domain_next_in_list));
	return domain_struct;
}

/*
 * from domain address to id.
 */
domid_t
xen_hyper_domain_to_id(ulong domain)
{
	struct xen_hyper_domain_context *dc;

	/* Is domain context array valid? */
	if (xhdt->context_array && xhdt->context_array->domain) {
		if ((dc = xen_hyper_domain_to_domain_context(domain)) == NULL) {
			return XEN_HYPER_DOMAIN_ID_INVALID;
		} else {
			return dc->domain_id;
		}
	} else {
		return XEN_HYPER_DOMAIN_ID_INVALID;
	}
}

/*
 * Get domain struct from id.
 */
char *
xen_hyper_id_to_domain_struct(domid_t id)
{
	char *domain_struct;
	struct xen_hyper_domain_context *dc;

	domain_struct = NULL;

	/* Is domain context array valid? */
	if (xhdt->context_array && xhdt->context_array->domain) {
		if ((dc = xen_hyper_id_to_domain_context(id)) == NULL) {
			return NULL;
		} else {
			if ((domain_struct =
				xen_hyper_read_domain(dc->domain)) == NULL) {
				error(FATAL, "cannot get domain from domain context array with id.\n");
			}
			return domain_struct;
		}
	} else {
		return NULL;
	}
}

/*
 * Get domain context from domain address.
 */
struct xen_hyper_domain_context *
xen_hyper_domain_to_domain_context(ulong domain)
{
	struct xen_hyper_domain_context *dc;
	int i;

	if (xhdt->context_array == NULL ||
		xhdt->context_array->domain == 0) {
		return NULL;
	}
	if (!domain) {
		return NULL;
	}
	for (i = 0, dc = xhdt->context_array; i < XEN_HYPER_NR_DOMAINS();
		i++, dc++) {
		if (domain == dc->domain) {
			return dc;
		}
	}
	return NULL;
}

/*
 * Get domain context from domain id.
 */
struct xen_hyper_domain_context *
xen_hyper_id_to_domain_context(domid_t id)
{
	struct xen_hyper_domain_context *dc;
	int i;

	if (xhdt->context_array == NULL ||
		xhdt->context_array->domain == 0) {
		return NULL;
	}
	if (id == XEN_HYPER_DOMAIN_ID_INVALID) {
		return NULL;
	}
	for (i = 0, dc = xhdt->context_array; i < XEN_HYPER_NR_DOMAINS();
		i++, dc++) {
		if (id == dc->domain_id) {
			return dc;
		}
	}
	return NULL;
}

/*
 * Store domain struct contents.
 */
struct xen_hyper_domain_context *
xen_hyper_store_domain_context(struct xen_hyper_domain_context *dc,
	       ulong domain, char *dp)
{
	char *vcpup;
	unsigned int max_vcpus;
	unsigned int i;

	dc->domain = domain;
	BCOPY((char *)(dp + XEN_HYPER_OFFSET(domain_domain_id)),
		&dc->domain_id, sizeof(domid_t));
	dc->tot_pages = UINT(dp + XEN_HYPER_OFFSET(domain_tot_pages));
	dc->max_pages = UINT(dp + XEN_HYPER_OFFSET(domain_max_pages));
	dc->xenheap_pages = UINT(dp + XEN_HYPER_OFFSET(domain_xenheap_pages));
	dc->shared_info = ULONG(dp + XEN_HYPER_OFFSET(domain_shared_info));
	dc->sched_priv = ULONG(dp + XEN_HYPER_OFFSET(domain_sched_priv));
	dc->next_in_list = ULONG(dp + XEN_HYPER_OFFSET(domain_next_in_list));
	if (XEN_HYPER_VALID_MEMBER(domain_domain_flags))
		dc->domain_flags = ULONG(dp + XEN_HYPER_OFFSET(domain_domain_flags));
	else if (XEN_HYPER_VALID_MEMBER(domain_is_shut_down)) {
		dc->domain_flags = 0;
                if (XEN_HYPER_VALID_MEMBER(domain_is_hvm) &&
                    *(dp + XEN_HYPER_OFFSET(domain_is_hvm))) {
			dc->domain_flags |= XEN_HYPER_DOMS_HVM;
		}
                if (XEN_HYPER_VALID_MEMBER(domain_guest_type) &&
                    *(dp + XEN_HYPER_OFFSET(domain_guest_type))) {
			/* For now PVH and HVM are the same for crash.
			 * and 0 is PV.
			 */
			dc->domain_flags |= XEN_HYPER_DOMS_HVM;
		}
		if (*(dp + XEN_HYPER_OFFSET(domain_is_privileged))) {
			dc->domain_flags |= XEN_HYPER_DOMS_privileged;
		}
		if (*(dp + XEN_HYPER_OFFSET(domain_debugger_attached))) {
			dc->domain_flags |= XEN_HYPER_DOMS_debugging;
		}
		if (XEN_HYPER_VALID_MEMBER(domain_is_polling) &&
				*(dp + XEN_HYPER_OFFSET(domain_is_polling))) {
			dc->domain_flags |= XEN_HYPER_DOMS_polling;
		}
		if (XEN_HYPER_VALID_MEMBER(domain_is_paused_by_controller) &&
			*(dp + XEN_HYPER_OFFSET(domain_is_paused_by_controller))) {
			dc->domain_flags |= XEN_HYPER_DOMS_ctrl_pause;
		}
		if (XEN_HYPER_VALID_MEMBER(domain_controller_pause_count) &&
			*(dp + XEN_HYPER_OFFSET(domain_controller_pause_count))) {
			dc->domain_flags |= XEN_HYPER_DOMS_ctrl_pause;
		}
		if (*(dp + XEN_HYPER_OFFSET(domain_is_dying))) {
			dc->domain_flags |= XEN_HYPER_DOMS_dying;
		}
		if (*(dp + XEN_HYPER_OFFSET(domain_is_shutting_down))) {
			dc->domain_flags |= XEN_HYPER_DOMS_shuttingdown;
		}
		if (*(dp + XEN_HYPER_OFFSET(domain_is_shut_down))) {
			dc->domain_flags |= XEN_HYPER_DOMS_shutdown;
		}
	} else {
		dc->domain_flags = XEN_HYPER_DOMF_ERROR;
	}
	dc->evtchn = ULONG(dp + XEN_HYPER_OFFSET(domain_evtchn));
	if (XEN_HYPER_VALID_MEMBER(domain_max_vcpus)) {
		max_vcpus = UINT(dp + XEN_HYPER_OFFSET(domain_max_vcpus));
	} else if (XEN_HYPER_VALID_SIZE(domain_vcpu)) {
		max_vcpus = XEN_HYPER_SIZE(domain_vcpu) / sizeof(void *);
	} else {
		max_vcpus = XEN_HYPER_MAX_VIRT_CPUS;
	}
	if (!(dc->vcpu = malloc(sizeof(ulong) * max_vcpus))) {
		error(FATAL, "cannot malloc vcpu array (%d VCPUs).",
		      max_vcpus);
	}
	if (MEMBER_TYPE("domain", "vcpu") == TYPE_CODE_ARRAY)
		vcpup = dp + XEN_HYPER_OFFSET(domain_vcpu);
	else {
		ulong vcpu_array = ULONG(dp + XEN_HYPER_OFFSET(domain_vcpu));
		if (vcpu_array && max_vcpus) {
			if (!(vcpup =
				malloc(max_vcpus * sizeof(void *)))) {
				error(FATAL, "cannot malloc VCPU array for domain %lx.",
					domain);
			}
			if (!readmem(vcpu_array, KVADDR,
				vcpup, max_vcpus * sizeof(void*),
				"VCPU array", RETURN_ON_ERROR)) {
				error(FATAL, "cannot read VCPU array for domain %lx.",
					domain);
			}
		} else {
			vcpup = NULL;
		}
	}
	if (vcpup) {
		for (i = 0; i < max_vcpus; i++) {
			dc->vcpu[i] = ULONG(vcpup + i*sizeof(void *));
			if (dc->vcpu[i])	XEN_HYPER_NR_VCPUS_IN_DOM(dc)++;
		}
		if (vcpup != dp + XEN_HYPER_OFFSET(domain_vcpu)) {
			free(vcpup);
		}
	}

	return dc;
}

/*
 * Read domain struct from domain context.
 */
char *
xen_hyper_read_domain_from_context(struct xen_hyper_domain_context *dc)
{
	return xen_hyper_fill_domain_struct(dc->domain, xhdt->domain_struct);
}

/*
 * Read domain struct.
 */
char *
xen_hyper_read_domain(ulong domain)
{
	return xen_hyper_fill_domain_struct(domain, xhdt->domain_struct);
}

/*
 * Read domain struct to verification.
 */
char *
xen_hyper_read_domain_verify(ulong domain)
{
	return xen_hyper_fill_domain_struct(domain, xhdt->domain_struct_verify);
}

/*
 * Fill domain struct.
 */
char *
xen_hyper_fill_domain_struct(ulong domain, char *domain_struct)
{
	if (!readmem(domain, KVADDR, domain_struct,
		XEN_HYPER_SIZE(domain), "fill_domain_struct",
	       	ACTIVE() ? (RETURN_ON_ERROR|QUIET) : RETURN_ON_ERROR)) {
		error(WARNING, "cannot fill domain struct.\n");
		return NULL;
	}
	return domain_struct;
}

/*
 * Allocate domain context space.
 */
void
xen_hyper_alloc_domain_context_space(int domains)
{
	if (xhdt->context_array == NULL) {
		if (!(xhdt->context_array =
			malloc(domains * sizeof(struct xen_hyper_domain_context)))) {
			error(FATAL, "cannot malloc context array (%d domains).",
				domains);
		}
		xhdt->context_array_cnt = domains;
	} else if (domains > xhdt->context_array_cnt) {
		struct xen_hyper_domain_context *dc;
		int i;
		for (dc = xhdt->context_array, i = 0;
		     i < xhdt->context_array_cnt; ++dc, ++i) {
			if (dc->vcpu)
				free(dc->vcpu);
		}
		if (!(xhdt->context_array =
			realloc(xhdt->context_array,
				domains * sizeof(struct xen_hyper_domain_context)))) {
			error(FATAL, "cannot realloc context array (%d domains).",
				domains);
		}
		xhdt->context_array_cnt = domains;
	}
	BZERO(xhdt->context_array,
		domains * sizeof(struct xen_hyper_domain_context));
}



/*
 * Get vcpu status.
 */
int
xen_hyper_vcpu_state(struct xen_hyper_vcpu_context *vcc)
{
	if (ACTIVE()) {
		if (xen_hyper_read_vcpu_verify(vcc->vcpu) == NULL) {
			return XEN_HYPER_RUNSTATE_ERROR;
		}
	}
	return vcc->state;
}

/*
 * Allocate vcpu context space.
 */
void
xen_hyper_refresh_vcpu_context_space(void)
{
	struct xen_hyper_domain_context *dc;
	struct xen_hyper_vcpu_context_array *vcca;
	struct xen_hyper_vcpu_context *vcc;
	int i, j;

	if ((xhvct->flags & XEN_HYPER_VCPU_F_INIT) && !ACTIVE()) {
		return;
	}

	xen_hyper_alloc_vcpu_context_arrays_space(XEN_HYPER_NR_DOMAINS());
	for (i = 0, xht->vcpus = 0, dc = xhdt->context_array,
	vcca = xhvct->vcpu_context_arrays;
	i < XEN_HYPER_NR_DOMAINS(); i++, dc++, vcca++) {
		dc->vcpu_context_array = vcca;
		xen_hyper_alloc_vcpu_context_space(vcca,
			XEN_HYPER_NR_VCPUS_IN_DOM(dc));
		for (j = 0, vcc = vcca->context_array;
		j < XEN_HYPER_NR_VCPUS_IN_DOM(dc); j++, vcc++) {
			xen_hyper_read_vcpu(dc->vcpu[j]);
			xen_hyper_store_vcpu_context(vcc, dc->vcpu[j],
				xhvct->vcpu_struct);	
		}
		if (dc == xhdt->idle_domain) {
			xhvct->idle_vcpu_context_array = vcca;
		}
		xht->vcpus += vcca->context_array_cnt;
	}
}

/*
 * Get vcpu context from vcpu address.
 */
struct xen_hyper_vcpu_context *
xen_hyper_vcpu_to_vcpu_context(ulong vcpu)
{
	struct xen_hyper_vcpu_context_array *vcca;
	struct xen_hyper_vcpu_context *vcc;
	int i, j;

	if (!vcpu) {
		return NULL;
	}
	for (i = 0, vcca = xhvct->vcpu_context_arrays;
		i < xhvct->vcpu_context_arrays_cnt; i++, vcca++) {
		for (j = 0, vcc = vcca->context_array;
			j < vcca->context_array_cnt; j++, vcc++) {
			if (vcpu == vcc->vcpu) {
				return vcc;
			}
		}
	}
	return NULL;
}

/*
 * Get vcpu context.
 */
struct xen_hyper_vcpu_context *
xen_hyper_id_to_vcpu_context(ulong domain, domid_t did, int vcid)
{
	struct xen_hyper_vcpu_context_array *vcca;
	struct xen_hyper_vcpu_context *vcc;
	int i;

	if (vcid == XEN_HYPER_VCPU_ID_INVALID) {
		return NULL;
	}
	if ((vcca = xen_hyper_domain_to_vcpu_context_array(domain))) {
		;
	} else if (!(vcca = xen_hyper_domid_to_vcpu_context_array(did))) {
		return NULL;
	}
	for (i = 0, vcc = vcca->context_array;
		i < vcca->context_array_cnt; i++, vcc++) {
		if (vcid == vcc->vcpu_id) {
			return vcc;
		}
	}
	return NULL;
}

/*
 * Get pointer of a vcpu context array from domain address.
 */
struct xen_hyper_vcpu_context_array *
xen_hyper_domain_to_vcpu_context_array(ulong domain)
{
	struct xen_hyper_domain_context *dc;

	if(!(dc = xen_hyper_domain_to_domain_context(domain))) {
		return NULL;
	}
	return dc->vcpu_context_array;
}

/*
 * Get pointer of a vcpu context array from domain id.
 */
struct xen_hyper_vcpu_context_array *
xen_hyper_domid_to_vcpu_context_array(domid_t id)
{
	struct xen_hyper_domain_context *dc;

	if (!(dc = xen_hyper_id_to_domain_context(id))) {
		return NULL;
	}
	return dc->vcpu_context_array;
}

/*
 * Store vcpu struct contents.
 */
struct xen_hyper_vcpu_context *
xen_hyper_store_vcpu_context(struct xen_hyper_vcpu_context *vcc,
       ulong vcpu, char *vcp)
{
	vcc->vcpu = vcpu;
	vcc->vcpu_id = INT(vcp + XEN_HYPER_OFFSET(vcpu_vcpu_id));
	vcc->processor = INT(vcp + XEN_HYPER_OFFSET(vcpu_processor));
	vcc->vcpu_info = ULONG(vcp + XEN_HYPER_OFFSET(vcpu_vcpu_info));
	vcc->domain = ULONG(vcp + XEN_HYPER_OFFSET(vcpu_domain));
	vcc->next_in_list = ULONG(vcp + XEN_HYPER_OFFSET(vcpu_next_in_list));
	if (XEN_HYPER_VALID_MEMBER(vcpu_sleep_tick))
		vcc->sleep_tick = ULONG(vcp + XEN_HYPER_OFFSET(vcpu_sleep_tick));
	vcc->sched_priv = ULONG(vcp + XEN_HYPER_OFFSET(vcpu_sched_priv));
	vcc->state = INT(vcp + XEN_HYPER_OFFSET(vcpu_runstate) +
		XEN_HYPER_OFFSET(vcpu_runstate_info_state));
	vcc->state_entry_time = ULONGLONG(vcp +
		XEN_HYPER_OFFSET(vcpu_runstate) +
		XEN_HYPER_OFFSET(vcpu_runstate_info_state_entry_time));
	vcc->runstate_guest = ULONG(vcp + XEN_HYPER_OFFSET(vcpu_runstate_guest));
	if (XEN_HYPER_VALID_MEMBER(vcpu_vcpu_flags))
		vcc->vcpu_flags = ULONG(vcp + XEN_HYPER_OFFSET(vcpu_vcpu_flags));
	else
		vcc->vcpu_flags = XEN_HYPER_VCPUF_ERROR;
	return vcc;
}

/*
 * Read vcpu struct from vcpu context.
 */
char *
xen_hyper_read_vcpu_from_context(struct xen_hyper_vcpu_context *vcc)
{
	return xen_hyper_fill_vcpu_struct(vcc->vcpu, xhvct->vcpu_struct);
}

/*
 * Read vcpu struct.
 */
char *
xen_hyper_read_vcpu(ulong vcpu)
{
	return xen_hyper_fill_vcpu_struct(vcpu, xhvct->vcpu_struct);
}

/*
 * Read vcpu struct to verification.
 */
char *
xen_hyper_read_vcpu_verify(ulong vcpu)
{
	return xen_hyper_fill_vcpu_struct(vcpu, xhvct->vcpu_struct_verify);
}

/*
 * Fill vcpu struct.
 */
char *
xen_hyper_fill_vcpu_struct(ulong vcpu, char *vcpu_struct)
{
	if (!readmem(vcpu, KVADDR, vcpu_struct,
		XEN_HYPER_SIZE(vcpu), "fill_vcpu_struct",
	       	ACTIVE() ? (RETURN_ON_ERROR|QUIET) : RETURN_ON_ERROR)) {
		error(WARNING, "cannot fill vcpu struct.\n");
		return NULL;
	}
	return vcpu_struct;
}

/*
 * Allocate vcpu context arrays space.
 */
void
xen_hyper_alloc_vcpu_context_arrays_space(int domains)
{
	struct xen_hyper_vcpu_context_array *vcca;

	if (xhvct->vcpu_context_arrays == NULL) {
		if (!(xhvct->vcpu_context_arrays =
			malloc(domains * sizeof(struct xen_hyper_vcpu_context_array)))) {
			error(FATAL, "cannot malloc context arrays (%d domains).",
				domains);
		}
		BZERO(xhvct->vcpu_context_arrays, domains * sizeof(struct xen_hyper_vcpu_context_array));
		xhvct->vcpu_context_arrays_cnt = domains;
	} else if (domains > xhvct->vcpu_context_arrays_cnt) {
		if (!(xhvct->vcpu_context_arrays =
			realloc(xhvct->vcpu_context_arrays,
				domains * sizeof(struct xen_hyper_vcpu_context_array)))) {
			error(FATAL, "cannot realloc context arrays (%d domains).",
				domains);
		}
		vcca = xhvct->vcpu_context_arrays + domains;
		BZERO(vcca, (domains - xhvct->vcpu_context_arrays_cnt) *
			sizeof(struct xen_hyper_vcpu_context_array));
		xhvct->vcpu_context_arrays_cnt = domains;
	}
}

/*
 * Allocate vcpu context space.
 */
void
xen_hyper_alloc_vcpu_context_space(struct xen_hyper_vcpu_context_array *vcca, int vcpus)
{
	if (!vcpus) {
		if (vcca->context_array != NULL) {
			free(vcca->context_array);
			vcca->context_array = NULL;
		}
		vcca->context_array_cnt = vcpus;
	} else if (vcca->context_array == NULL) {
		if (!(vcca->context_array =
			malloc(vcpus * sizeof(struct xen_hyper_vcpu_context)))) {
			error(FATAL, "cannot malloc context array (%d vcpus).",
				vcpus);
		}
		vcca->context_array_cnt = vcpus;
	} else if (vcpus > vcca->context_array_cnt) {
		if (!(vcca->context_array =
			realloc(vcca->context_array,
				vcpus * sizeof(struct xen_hyper_vcpu_context_array)))) {
			error(FATAL, "cannot realloc context array (%d vcpus).",
				vcpus);
		}
		vcca->context_array_cnt = vcpus;
	}
	vcca->context_array_valid = vcpus;
	BZERO(vcca->context_array, vcpus * sizeof(struct xen_hyper_vcpu_context));
}



/*
 * Get pcpu context from pcpu id.
 */
struct xen_hyper_pcpu_context *
xen_hyper_id_to_pcpu_context(uint id)
{
	if (xhpct->context_array == NULL) {
		return NULL;
	}
	if (!xen_hyper_test_pcpu_id(id)) {
		return NULL;
	}
	return &xhpct->context_array[id];
}

/*
 * Get pcpu context from pcpu address.
 */
struct xen_hyper_pcpu_context *
xen_hyper_pcpu_to_pcpu_context(ulong pcpu)
{
	struct xen_hyper_pcpu_context *pcc;
	int i;
	uint cpuid;

	if (xhpct->context_array == NULL) {
		return NULL;
	}
	if (!pcpu) {
		return NULL;
	}
	for_cpu_indexes(i, cpuid)
	{
		pcc = &xhpct->context_array[cpuid];
		if (pcpu == pcc->pcpu) {
			return pcc;
		}
	}
	return NULL;
}

/*
 * Store pcpu struct contents.
 */
struct xen_hyper_pcpu_context *
xen_hyper_store_pcpu_context(struct xen_hyper_pcpu_context *pcc,
       ulong pcpu, char *pcp)
{
	pcc->pcpu = pcpu;
	pcc->processor_id =
		UINT(pcp + XEN_HYPER_OFFSET(cpu_info_processor_id));
	pcc->guest_cpu_user_regs = (ulong)(pcpu +
			XEN_HYPER_OFFSET(cpu_info_guest_cpu_user_regs));
	pcc->current_vcpu =
		ULONG(pcp + XEN_HYPER_OFFSET(cpu_info_current_vcpu));
	return pcc;
}

/*
 * Store init_tss contents.
 */
struct xen_hyper_pcpu_context *
xen_hyper_store_pcpu_context_tss(struct xen_hyper_pcpu_context *pcc,
       ulong init_tss, char *tss)
{
	int i;
	uint64_t *ist_p;

	pcc->init_tss = init_tss;
	if (machine_type("X86")) {
		pcc->sp.esp0 = ULONG(tss + XEN_HYPER_OFFSET(tss_esp0));
	} else if (machine_type("X86_64")) {
		pcc->sp.rsp0 = ULONG(tss + XEN_HYPER_OFFSET(tss_rsp0));
		ist_p = (uint64_t *)(tss + XEN_HYPER_OFFSET(tss_ist));
		for (i = 0; i < XEN_HYPER_TSS_IST_MAX; i++, ist_p++) {
			pcc->ist[i] = ULONG(ist_p);
		}
	}
	return pcc;
}

/*
 * Read pcpu struct.
 */
char *
xen_hyper_read_pcpu(ulong pcpu)
{
	return xen_hyper_fill_pcpu_struct(pcpu, xhpct->pcpu_struct);
}

/*
 * Fill pcpu struct.
 */
char *
xen_hyper_fill_pcpu_struct(ulong pcpu, char *pcpu_struct)
{
	if (!readmem(pcpu, KVADDR, pcpu_struct,
		XEN_HYPER_SIZE(cpu_info), "fill_pcpu_struct",
	       	ACTIVE() ? (RETURN_ON_ERROR|QUIET) : RETURN_ON_ERROR)) {
		error(WARNING, "cannot fill pcpu_struct.\n");
		return NULL;
	}
	return pcpu_struct;
}

/*
 * Allocate pcpu context space.
 */
void
xen_hyper_alloc_pcpu_context_space(int pcpus)
{
	if (xhpct->context_array == NULL) {
		if (!(xhpct->context_array =
			malloc(pcpus * sizeof(struct xen_hyper_pcpu_context)))) {
			error(FATAL, "cannot malloc context array (%d pcpus).",
				pcpus);
		}
	}
	BZERO(xhpct->context_array, pcpus * sizeof(struct xen_hyper_pcpu_context));
}



/*
 * Fill cpu_data.
 */
char *
xen_hyper_x86_fill_cpu_data(int idx, char *cpuinfo_x86)
{
	ulong cpu_data;

	if (!xen_hyper_test_pcpu_id(idx) || !xht->cpu_data_address)
		return NULL;
	cpu_data = xht->cpu_data_address + XEN_HYPER_SIZE(cpuinfo_x86) * idx;
	if (!readmem(cpu_data, KVADDR, cpuinfo_x86, XEN_HYPER_SIZE(cpuinfo_x86),
		"cpu_data", RETURN_ON_ERROR)) {
		error(WARNING, "cannot read cpu_data.\n");
		return NULL;
	}
	return cpuinfo_x86;
}

char *
xen_hyper_ia64_fill_cpu_data(int idx, char *cpuinfo_ia64)
{
	ulong cpu_data;

	if (!xen_hyper_test_pcpu_id(idx) || !xht->cpu_data_address)
		return NULL;
	cpu_data = xen_hyper_per_cpu(xht->cpu_data_address, idx);
	if (!readmem(cpu_data, KVADDR, cpuinfo_ia64, XEN_HYPER_SIZE(cpuinfo_ia64),
		"cpu_data", RETURN_ON_ERROR)) {
		error(WARNING, "cannot read cpu_data.\n");
		return NULL;
	}
	return cpuinfo_ia64;
}

/*
 * Return whether vcpu is crashing.
 */
int
xen_hyper_is_vcpu_crash(struct xen_hyper_vcpu_context *vcc)
{
	if (vcc == xht->crashing_vcc)
		return TRUE;
	return FALSE;
}

/*
 * Test whether cpu for pcpu id exists.
 */
int
xen_hyper_test_pcpu_id(uint pcpu_id)
{
	ulong *cpumask = xht->cpumask;
	uint i, j;

	if (pcpu_id == XEN_HYPER_PCPU_ID_INVALID ||
	pcpu_id > XEN_HYPER_MAX_CPUS()) {
		return FALSE;
	}

	i = pcpu_id / (sizeof(ulong) * 8);
	j = pcpu_id % (sizeof(ulong) * 8);
	cpumask += i;
	if (*cpumask & (1UL << j)) {
		return TRUE;
	} else {
		return FALSE;
	}
}



/*
 *  Calculate and return the uptime.
 */
ulonglong
xen_hyper_get_uptime_hyper(void)
{
	ulong jiffies, tmp1, tmp2;
	ulonglong jiffies_64, wrapped;

	if (symbol_exists("jiffies_64")) {
		get_symbol_data("jiffies_64", sizeof(ulonglong), &jiffies_64);
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
	} else if (symbol_exists("jiffies")) {
		get_symbol_data("jiffies", sizeof(long), &jiffies);
		jiffies_64 = (ulonglong)jiffies;
	} else {
		jiffies_64 = 0;	/* hypervisor does not have uptime */
	}

	return jiffies_64;
}

/*
 * Get cpu informatin around.
 */
void
xen_hyper_get_cpu_info(void)
{
	ulong addr, init_begin, init_end;
	ulong *cpumask;
	uint *cpu_idx;
	int i, j, cpus;

	XEN_HYPER_STRUCT_SIZE_INIT(cpumask_t, "cpumask_t");

	if (symbol_exists("nr_cpu_ids"))
		get_symbol_data("nr_cpu_ids", sizeof(uint), &xht->max_cpus);
	else {
		init_begin = symbol_value("__init_begin");
		init_end = symbol_value("__init_end");
		addr = symbol_value("max_cpus");

		if (addr >= init_begin && addr < init_end)
			xht->max_cpus = XEN_HYPER_SIZE(cpumask_t) * 8;
		else {
			get_symbol_data("max_cpus", sizeof(xht->max_cpus), &xht->max_cpus);
			if (XEN_HYPER_SIZE(cpumask_t) * 8 > xht->max_cpus)
				xht->max_cpus = XEN_HYPER_SIZE(cpumask_t) * 8;
		}
	}

	if (xht->cpumask) {
		free(xht->cpumask);
	}
	if((xht->cpumask = malloc(XEN_HYPER_SIZE(cpumask_t))) == NULL) {
		error(FATAL, "cannot malloc cpumask space.\n");
	}
	addr = symbol_value("cpu_present_map");
	if (!readmem(addr, KVADDR, xht->cpumask,
		XEN_HYPER_SIZE(cpumask_t), "cpu_present_map", RETURN_ON_ERROR)) {
		error(FATAL, "cannot read cpu_present_map.\n");
	}
	if (xht->cpu_idxs) {
		free(xht->cpu_idxs);
	}
	if((xht->cpu_idxs = malloc(sizeof(uint) * XEN_HYPER_MAX_CPUS())) == NULL) {
		error(FATAL, "cannot malloc cpu_idxs space.\n");
	}
	memset(xht->cpu_idxs, 0xff, sizeof(uint) * XEN_HYPER_MAX_CPUS());

	for (i = cpus = 0, cpumask = xht->cpumask, cpu_idx = xht->cpu_idxs;
	i < (XEN_HYPER_SIZE(cpumask_t)/sizeof(ulong)); i++, cpumask++) {
		for (j = 0; j < sizeof(ulong) * 8; j++) {
			if (*cpumask & (1UL << j)) {
				*cpu_idx++ = i * sizeof(ulong) * 8 + j;
				cpus++;
			}
		}
	}
	xht->pcpus = cpus;
}

/*
 * Calculate the number of physical cpu for x86.
 */
int
xen_hyper_x86_get_smp_cpus(void)
{
	if (xht->pcpus) {
		return xht->pcpus;
	}
	xen_hyper_get_cpu_info();
	return xht->pcpus;
}

/*
 * Calculate used memory size for x86.
 */
uint64_t
xen_hyper_x86_memory_size(void)
{
	ulong vaddr;

	if (machdep->memsize) {
		return machdep->memsize;
	}
	vaddr = symbol_value("total_pages");
	if (!readmem(vaddr, KVADDR, &xht->total_pages, sizeof(xht->total_pages),
		"total_pages", RETURN_ON_ERROR)) {
		error(WARNING, "cannot read total_pages.\n");
	}
	xht->sys_pages = xht->total_pages;
	machdep->memsize = (uint64_t)(xht->sys_pages) * (uint64_t)(machdep->pagesize);
	return machdep->memsize;
}


/*
 * Calculate the number of physical cpu for ia64.
 */
int
xen_hyper_ia64_get_smp_cpus(void)
{
	return xen_hyper_x86_get_smp_cpus();
}

/*
 * Calculate used memory size for ia64.
 */
uint64_t
xen_hyper_ia64_memory_size(void)
{
	return xen_hyper_x86_memory_size();
}

/*      
 *  Calculate and return the speed of the processor. 
 */
ulong 
xen_hyper_ia64_processor_speed(void)
{
	ulong mhz, proc_freq;

	if (machdep->mhz)
		return(machdep->mhz);

	mhz = 0;

	if (!xht->cpu_data_address ||
	    !XEN_HYPER_VALID_STRUCT(cpuinfo_ia64) ||
	    XEN_HYPER_INVALID_MEMBER(cpuinfo_ia64_proc_freq))
		return (machdep->mhz = mhz);

        readmem(xen_hyper_per_cpu(xht->cpu_data_address, xht->cpu_idxs[0]) + 
		XEN_HYPER_OFFSET(cpuinfo_ia64_proc_freq),
        	KVADDR, &proc_freq, sizeof(ulong),
                "cpuinfo_ia64 proc_freq", FAULT_ON_ERROR);

	mhz = proc_freq/1000000;

	return (machdep->mhz = mhz);
}



/*
 * Print an aligned string with specified length.
 */
void
xen_hyper_fpr_indent(FILE *fp, int len, char *str1, char *str2, int flag)
{
	char buf[XEN_HYPER_CMD_BUFSIZE];
	int sl, r;
	char *s1, *s2;

	sl = strlen(str1);
	if (sl > len) {
		r = 0;
	} else {
		r = len - sl;
	}

	memset(buf, ' ', sizeof(buf));
	buf[r] =  '\0';
	if (flag & XEN_HYPER_PRI_L) {
		s1 = str1;
		s2 = buf;
	} else {
		s1 = buf;
		s2 = str1;
	}
	if (str2) {
		fprintf(fp, "%s%s%s", s1, s2, str2);
	} else {
		fprintf(fp, "%s%s", s1, s2);
	}
	if (flag & XEN_HYPER_PRI_LF) {
		fprintf(fp, "\n");
	}
}

ulong
xen_hyper_get_active_vcpu_from_pcpuid(ulong pcpuid)
{
	struct xen_hyper_pcpu_context *pcc;
	struct xen_hyper_vcpu_context_array *vcca;
	struct xen_hyper_vcpu_context *vcc;
	int i, j;

	if (!xen_hyper_test_pcpu_id(pcpuid))
		return 0;

	pcc = &xhpct->context_array[pcpuid];
	if (pcc->current_vcpu)
		return pcc->current_vcpu;

	for (i = 0, vcca = xhvct->vcpu_context_arrays;
		i < xhvct->vcpu_context_arrays_cnt; i++, vcca++) {
		for (j = 0, vcc = vcca->context_array;
			j < vcca->context_array_cnt; j++, vcc++) {
			if (vcc->processor == pcpuid && 
				vcc->state == XEN_HYPER_RUNSTATE_running) {
				return vcc->vcpu;
			}
		}
	}

	return 0;
}

ulong
xen_hyper_pcpu_to_active_vcpu(ulong pcpu)
{
	ulong vcpu;

	/* if pcpu is vcpu address, return it. */
	if (pcpu & (~(PAGESIZE() - 1))) {
		return pcpu;
	}

	if(!(vcpu = XEN_HYPER_CURR_VCPU(pcpu)))
		error(FATAL, "invalid pcpu id\n");
	return vcpu;
}

void
xen_hyper_print_bt_header(FILE *out, ulong vcpu, int newline)
{
	struct xen_hyper_vcpu_context *vcc;

	if (newline)
		fprintf(out, "\n");

	vcc = xen_hyper_vcpu_to_vcpu_context(vcpu);
	if (!vcc)
		error(FATAL, "invalid vcpu\n");
	fprintf(out, "PCPU: %2d  VCPU: %lx\n", vcc->processor, vcpu);
}
#endif
