/* task.c - core analysis suite
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002-2018 David Anderson
 * Copyright (C) 2002-2018 Red Hat, Inc. All rights reserved.
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

static ulong get_panic_context(void);
static int sort_by_pid(const void *, const void *);
static void show_ps(ulong, struct psinfo *);
static struct task_context *panic_search(void);
static void allocate_task_space(int);
static void refresh_fixed_task_table(void);
static void refresh_unlimited_task_table(void); 
static void refresh_pidhash_task_table(void);
static void refresh_pid_hash_task_table(void);
static void refresh_hlist_task_table(void);
static void refresh_hlist_task_table_v2(void);
static void refresh_hlist_task_table_v3(void);
static void refresh_active_task_table(void);
static int radix_tree_task_callback(ulong);
static void refresh_radix_tree_task_table(void);
static void refresh_xarray_task_table(void);
static struct task_context *add_context(ulong, char *);
static void refresh_context(ulong, ulong);
static ulong parent_of(ulong);
static void parent_list(ulong);
static void child_list(ulong);
static void initialize_task_state(void);
static void dump_task_states(void);
static void show_ps_data(ulong, struct task_context *, struct psinfo *);
static void show_task_times(struct task_context *, ulong);
static void show_task_args(struct task_context *);
static void show_task_rlimit(struct task_context *);
static void show_tgid_list(ulong);
static int compare_start_time(const void *, const void *);
static int start_time_timespec(void);
static ulonglong convert_start_time(ulonglong, ulonglong);
static ulong search_panic_task_by_cpu(char *);
static ulong search_panic_task_by_keywords(char *, int *);
static ulong get_log_panic_task(void);
static ulong get_dumpfile_panic_task(void);
static ulong get_active_set_panic_task(void);
static void populate_panic_threads(void);
static int verify_task(struct task_context *, int);
static ulong get_idle_task(int, char *);
static ulong get_curr_task(int, char *);
static long rq_idx(int);
static long cpu_idx(int);
static void dump_runq(void);
static void dump_on_rq_timestamp(void);
static void dump_on_rq_lag(void);
static void dump_on_rq_milliseconds(void);
static void dump_runqueues(void);
static void dump_prio_array(int, ulong, char *);
static void dump_task_runq_entry(struct task_context *, int);
static void print_group_header_fair(int, ulong, void *);
static void print_parent_task_group_fair(void *, int);
static int dump_tasks_in_lower_dequeued_cfs_rq(int, ulong, int, struct task_context *);
static int dump_tasks_in_cfs_rq(ulong);
static int dump_tasks_in_task_group_cfs_rq(int, ulong, int, struct task_context *);
static void dump_on_rq_tasks(void);
static void cfs_rq_offset_init(void);
static void task_group_offset_init(void);
static void dump_CFS_runqueues(void);
static void print_group_header_rt(ulong, void *);
static void print_parent_task_group_rt(void *, int);
static int dump_tasks_in_lower_dequeued_rt_rq(int, ulong, int);
static int dump_RT_prio_array(ulong, char *);
static void dump_tasks_in_task_group_rt_rq(int, ulong, int);
static char *get_task_group_name(ulong);
static void sort_task_group_info_array(void);
static void print_task_group_info_array(void);
static void reuse_task_group_info_array(void);
static void free_task_group_info_array(void);
static void fill_task_group_info_array(int, ulong, char *, int);
static void dump_tasks_by_task_group(void);
static void task_struct_member(struct task_context *,unsigned int, struct reference *);
static void signal_reference(struct task_context *, ulong, struct reference *);
static void do_sig_thread_group(ulong);
static void dump_signal_data(struct task_context *, ulong);
#define TASK_LEVEL         (0x1)
#define THREAD_GROUP_LEVEL (0x2)
#define TASK_INDENT        (0x4)
static int sigrt_minmax(int *, int *);
static void signame_list(void);
static void sigqueue_list(ulong);
static ulonglong task_signal(ulong, ulong*);
static ulonglong task_blocked(ulong);
static void translate_sigset(ulonglong);
static ulonglong sigaction_mask(ulong);
static int task_has_cpu(ulong, char *);
static int is_foreach_keyword(char *, int *);
static void foreach_cleanup(void *);
static void ps_cleanup(void *);
static char *task_pointer_string(struct task_context *, ulong, char *);
static int panic_context_adjusted(struct task_context *tc);
static void show_last_run(struct task_context *, struct psinfo *);
static void show_milliseconds(struct task_context *, struct psinfo *);
static char *translate_nanoseconds(ulonglong, char *);
static int sort_by_last_run(const void *arg1, const void *arg2);
static void sort_context_array_by_last_run(void);
static void show_ps_summary(ulong);
static void irqstacks_init(void);
static void parse_task_thread(int argcnt, char *arglist[], struct task_context *);
static void stack_overflow_check_init(void);
static int has_sched_policy(ulong, ulong);
static ulong task_policy(ulong);
static ulong sched_policy_bit_from_str(const char *);
static ulong make_sched_policy(const char *);

static struct sched_policy_info {
	ulong value;
	char *name;
} sched_policy_info[] = {
	{ SCHED_NORMAL,		"NORMAL" },
	{ SCHED_FIFO,		"FIFO" },
	{ SCHED_RR,		"RR" },
	{ SCHED_BATCH,		"BATCH" },
	{ SCHED_ISO,		"ISO" },
	{ SCHED_IDLE,		"IDLE" },
	{ SCHED_DEADLINE,	"DEADLINE" },
	{ ULONG_MAX,		NULL }
};

enum PANIC_TASK_FOUND_RESULT {
	FOUND_NO_PANIC_KEYWORD,
	FOUND_PANIC_KEYWORD,
	FOUND_PANIC_TASK
};

const char *panic_keywords[] = {
	"Unable to handle kernel",
	"BUG: unable to handle kernel",
	"Kernel BUG at",
	"kernel BUG at",
	"Bad mode in",
	"Oops",
	"Kernel panic",
	NULL,
};

/*
 *  Figure out how much space will be required to hold the task context
 *  data, malloc() it, and call refresh_task_table() to fill it up.
 *  Gather a few key offset and size values.  Lastly, get, and then set, 
 *  the initial context.
 */
void
task_init(void)
{
	long len;
	int dim, task_struct_size;
        struct syment *nsp;
	long tss_offset, thread_offset; 
	long eip_offset, esp_offset, ksp_offset;
	struct gnu_request req;
	ulong active_pid;

	if (!(tt->idle_threads = (ulong *)calloc(NR_CPUS, sizeof(ulong))))
		error(FATAL, "cannot malloc idle_threads array");
	if (DUMPFILE() &&
	    !(tt->panic_threads = (ulong *)calloc(NR_CPUS, sizeof(ulong))))
		error(FATAL, "cannot malloc panic_threads array");

        if (kernel_symbol_exists("nr_tasks")) {
		/*
		 *  Figure out what maximum NR_TASKS would be by getting the 
		 *  address of the next symbol after "task".
		 */
	        tt->task_start = symbol_value("task");
	        if ((nsp = next_symbol("task", NULL)) == NULL)
	        	error(FATAL, "cannot determine size of task table\n");

		tt->flags |= TASK_ARRAY_EXISTS;
		tt->task_end = nsp->value;
	        tt->max_tasks = (tt->task_end-tt->task_start) / sizeof(void *);
		allocate_task_space(tt->max_tasks);

		tss_offset = MEMBER_OFFSET_INIT(task_struct_tss,  
			"task_struct", "tss");
		eip_offset = MEMBER_OFFSET_INIT(thread_struct_eip, 
			"thread_struct", "eip");
		esp_offset = MEMBER_OFFSET_INIT(thread_struct_esp,
			"thread_struct", "esp");
		ksp_offset = MEMBER_OFFSET_INIT(thread_struct_ksp, 
			"thread_struct", "ksp");
	        ASSIGN_OFFSET(task_struct_tss_eip) = 
			(eip_offset == INVALID_OFFSET) ? 
			INVALID_OFFSET : tss_offset + eip_offset;
	        ASSIGN_OFFSET(task_struct_tss_esp) = 
			(esp_offset == INVALID_OFFSET) ?
			INVALID_OFFSET : tss_offset + esp_offset;
                ASSIGN_OFFSET(task_struct_tss_ksp) = 
			(ksp_offset == INVALID_OFFSET) ?
                        INVALID_OFFSET : tss_offset + ksp_offset;

		tt->flags |= TASK_REFRESH;
		tt->refresh_task_table = refresh_fixed_task_table;

                readmem(tt->task_start, KVADDR, &tt->idle_threads[0],
                	kt->cpus * sizeof(void *), "idle threads",
                        FAULT_ON_ERROR);
	} else {
		/*
		 *  Make the task table big enough to hold what's running.
		 *  It can be realloc'd later if it grows on a live system.
	         */
	        get_symbol_data("nr_threads", sizeof(int), &tt->nr_threads);
		tt->max_tasks = tt->nr_threads + NR_CPUS + TASK_SLUSH; 
		allocate_task_space(tt->max_tasks);
	
		thread_offset = MEMBER_OFFSET_INIT(task_struct_thread, 
			"task_struct", "thread");
		eip_offset = MEMBER_OFFSET_INIT(thread_struct_eip,
			"thread_struct", "eip");
		esp_offset = MEMBER_OFFSET_INIT(thread_struct_esp,
			"thread_struct", "esp");
		/*
		 *  Handle x86/x86_64 merger.
		 */
		if (eip_offset == INVALID_OFFSET)
			eip_offset = MEMBER_OFFSET_INIT(thread_struct_eip,
				"thread_struct", "ip");
		if (esp_offset == INVALID_OFFSET)
			esp_offset = MEMBER_OFFSET_INIT(thread_struct_esp,
				"thread_struct", "sp");
		ksp_offset = MEMBER_OFFSET_INIT(thread_struct_ksp,
			"thread_struct", "ksp");
	        ASSIGN_OFFSET(task_struct_thread_eip) = 
		    (eip_offset == INVALID_OFFSET) ? 
			INVALID_OFFSET : thread_offset + eip_offset;
	        ASSIGN_OFFSET(task_struct_thread_esp) = 
		    (esp_offset == INVALID_OFFSET) ?
			INVALID_OFFSET : thread_offset + esp_offset;
	        ASSIGN_OFFSET(task_struct_thread_ksp) = 
		    (ksp_offset == INVALID_OFFSET) ?
			INVALID_OFFSET : thread_offset + ksp_offset;
	
		tt->flags |= TASK_REFRESH;
		tt->refresh_task_table = refresh_unlimited_task_table;

		get_idle_threads(&tt->idle_threads[0], kt->cpus);
	}

	/*
	 * Handle CONFIG_THREAD_INFO_IN_TASK changes
	 */
	MEMBER_OFFSET_INIT(task_struct_stack, "task_struct", "stack");
	MEMBER_OFFSET_INIT(task_struct_thread_info, "task_struct", "thread_info");

	if (VALID_MEMBER(task_struct_thread_info)) {
		switch (MEMBER_TYPE("task_struct", "thread_info"))
		{
		case TYPE_CODE_PTR:
			break;
		case TYPE_CODE_STRUCT:
			tt->flags |= THREAD_INFO_IN_TASK;
			break;
		default:
			error(FATAL, 
			    "unexpected type code for task_struct.thread_info: %ld\n",
				MEMBER_TYPE("task_struct", "thread_info"));
			break;
		}
	} else if (VALID_MEMBER(task_struct_stack))
		MEMBER_OFFSET_INIT(task_struct_thread_info, "task_struct", "stack");

	MEMBER_OFFSET_INIT(task_struct_cpu, "task_struct", "cpu");

	if (VALID_MEMBER(task_struct_thread_info)) {
		if (tt->flags & THREAD_INFO_IN_TASK && VALID_MEMBER(task_struct_cpu)) {
			MEMBER_OFFSET_INIT(thread_info_flags, "thread_info", "flags");
			/* (unnecessary) reminders */
			ASSIGN_OFFSET(thread_info_task) = INVALID_OFFSET;
			ASSIGN_OFFSET(thread_info_cpu) = INVALID_OFFSET;
			ASSIGN_OFFSET(thread_info_previous_esp) = INVALID_OFFSET;
		} else {
			MEMBER_OFFSET_INIT(thread_info_task, "thread_info", "task"); 
			MEMBER_OFFSET_INIT(thread_info_cpu, "thread_info", "cpu");
			MEMBER_OFFSET_INIT(thread_info_flags, "thread_info", "flags");
			MEMBER_OFFSET_INIT(thread_info_previous_esp, "thread_info", 
				"previous_esp");
		}
		STRUCT_SIZE_INIT(thread_info, "thread_info");
		tt->flags |= THREAD_INFO;
	}

        MEMBER_OFFSET_INIT(task_struct_state, "task_struct", "state");
	MEMBER_SIZE_INIT(task_struct_state, "task_struct", "state");
	if (INVALID_MEMBER(task_struct_state)) {
		MEMBER_OFFSET_INIT(task_struct_state, "task_struct", "__state");
		MEMBER_SIZE_INIT(task_struct_state, "task_struct", "__state");
	}
        MEMBER_OFFSET_INIT(task_struct_exit_state, "task_struct", "exit_state");
        MEMBER_OFFSET_INIT(task_struct_pid, "task_struct", "pid");
        MEMBER_OFFSET_INIT(task_struct_comm, "task_struct", "comm");
        MEMBER_OFFSET_INIT(task_struct_next_task, "task_struct", "next_task");
        MEMBER_OFFSET_INIT(task_struct_processor, "task_struct", "processor");
        MEMBER_OFFSET_INIT(task_struct_p_pptr, "task_struct", "p_pptr");
        MEMBER_OFFSET_INIT(task_struct_parent, "task_struct", "parent");
	if (INVALID_MEMBER(task_struct_parent))
		MEMBER_OFFSET_INIT(task_struct_parent, "task_struct", 
			"real_parent");
        MEMBER_OFFSET_INIT(task_struct_has_cpu, "task_struct", "has_cpu");
        MEMBER_OFFSET_INIT(task_struct_cpus_runnable,  
		"task_struct", "cpus_runnable");
	MEMBER_OFFSET_INIT(task_struct_active_mm, "task_struct", "active_mm");
	MEMBER_OFFSET_INIT(task_struct_next_run, "task_struct", "next_run");
	MEMBER_OFFSET_INIT(task_struct_flags, "task_struct", "flags");
	MEMBER_SIZE_INIT(task_struct_flags, "task_struct", "flags");
	MEMBER_OFFSET_INIT(task_struct_policy, "task_struct", "policy");
	MEMBER_SIZE_INIT(task_struct_policy, "task_struct", "policy");
        MEMBER_OFFSET_INIT(task_struct_pidhash_next,
                "task_struct", "pidhash_next");
	MEMBER_OFFSET_INIT(task_struct_pgrp, "task_struct", "pgrp");
	MEMBER_OFFSET_INIT(task_struct_tgid, "task_struct", "tgid");
        MEMBER_OFFSET_INIT(task_struct_pids, "task_struct", "pids");
        MEMBER_OFFSET_INIT(task_struct_last_run, "task_struct", "last_run");
        MEMBER_OFFSET_INIT(task_struct_timestamp, "task_struct", "timestamp");
        MEMBER_OFFSET_INIT(task_struct_sched_info, "task_struct", "sched_info");
	if (VALID_MEMBER(task_struct_sched_info))
		MEMBER_OFFSET_INIT(sched_info_last_arrival, 
			"sched_info", "last_arrival");
	if (VALID_MEMBER(task_struct_last_run) || 
	    VALID_MEMBER(task_struct_timestamp) ||
	    VALID_MEMBER(sched_info_last_arrival)) {
		char buf[BUFSIZE];
	        strcpy(buf, "alias last ps -l");
        	alias_init(buf);
	}
	MEMBER_OFFSET_INIT(task_struct_pid_links, "task_struct", "pid_links");
	MEMBER_OFFSET_INIT(pid_link_pid, "pid_link", "pid");
	MEMBER_OFFSET_INIT(pid_hash_chain, "pid", "hash_chain");

	STRUCT_SIZE_INIT(pid_link, "pid_link");
	STRUCT_SIZE_INIT(upid, "upid");
	if (VALID_STRUCT(upid)) {
		MEMBER_OFFSET_INIT(upid_nr, "upid", "nr");
		MEMBER_OFFSET_INIT(upid_ns, "upid", "ns"); 
		MEMBER_OFFSET_INIT(upid_pid_chain, "upid", "pid_chain");
		MEMBER_OFFSET_INIT(pid_numbers, "pid", "numbers");
		ARRAY_LENGTH_INIT(len, pid_numbers, "pid.numbers", NULL, 0);
		MEMBER_OFFSET_INIT(pid_tasks, "pid", "tasks");
		tt->init_pid_ns = symbol_value("init_pid_ns");
	}

	MEMBER_OFFSET_INIT(pid_pid_chain, "pid", "pid_chain");

	STRUCT_SIZE_INIT(task_struct, "task_struct");

	if (kernel_symbol_exists("arch_task_struct_size") &&
	    readmem(symbol_value("arch_task_struct_size"), KVADDR,
	    &task_struct_size, sizeof(int),
	    "arch_task_struct_size", RETURN_ON_ERROR)) {
		ASSIGN_SIZE(task_struct) = task_struct_size;
		if (STRUCT_SIZE("task_struct") != SIZE(task_struct))
			add_to_downsized("task_struct");
		if (CRASHDEBUG(1))
			fprintf(fp, "downsize task_struct: %ld to %ld\n",
				STRUCT_SIZE("task_struct"),
				SIZE(task_struct));
	}

	MEMBER_OFFSET_INIT(task_struct_sig, "task_struct", "sig");
	MEMBER_OFFSET_INIT(task_struct_signal, "task_struct", "signal");
	MEMBER_OFFSET_INIT(task_struct_blocked, "task_struct", "blocked");
	MEMBER_OFFSET_INIT(task_struct_sigpending, "task_struct", "sigpending");
	MEMBER_OFFSET_INIT(task_struct_pending, "task_struct", "pending");
	MEMBER_OFFSET_INIT(task_struct_sigqueue, "task_struct", "sigqueue");
	MEMBER_OFFSET_INIT(task_struct_sighand, "task_struct", "sighand");
	 
	MEMBER_OFFSET_INIT(signal_struct_count, "signal_struct", "count");
	MEMBER_OFFSET_INIT(signal_struct_nr_threads, "signal_struct", "nr_threads");
	MEMBER_OFFSET_INIT(signal_struct_action, "signal_struct", "action");
	MEMBER_OFFSET_INIT(signal_struct_shared_pending, "signal_struct",
		"shared_pending");

	MEMBER_OFFSET_INIT(k_sigaction_sa, "k_sigaction", "sa");
	
	MEMBER_OFFSET_INIT(sigaction_sa_handler, "sigaction", "sa_handler");
	MEMBER_OFFSET_INIT(sigaction_sa_mask, "sigaction", "sa_mask");
	MEMBER_OFFSET_INIT(sigaction_sa_flags, "sigaction", "sa_flags");
	MEMBER_OFFSET_INIT(sigpending_head, "sigpending", "head");
	if (INVALID_MEMBER(sigpending_head))
		MEMBER_OFFSET_INIT(sigpending_list, "sigpending", "list");
	MEMBER_OFFSET_INIT(sigpending_signal, "sigpending", "signal");
	MEMBER_SIZE_INIT(sigpending_signal, "sigpending", "signal");

	STRUCT_SIZE_INIT(sigqueue, "sigqueue");
       	STRUCT_SIZE_INIT(signal_queue, "signal_queue");

	STRUCT_SIZE_INIT(sighand_struct, "sighand_struct");
	if (VALID_STRUCT(sighand_struct))
		MEMBER_OFFSET_INIT(sighand_struct_action, "sighand_struct", 
			"action");

        MEMBER_OFFSET_INIT(siginfo_si_signo, "siginfo", "si_signo");

	STRUCT_SIZE_INIT(signal_struct, "signal_struct");
	STRUCT_SIZE_INIT(k_sigaction, "k_sigaction");

        MEMBER_OFFSET_INIT(task_struct_start_time, "task_struct", "start_time");
        MEMBER_SIZE_INIT(task_struct_start_time, "task_struct", "start_time");
        MEMBER_SIZE_INIT(task_struct_utime, "task_struct", "utime");
        MEMBER_SIZE_INIT(task_struct_stime, "task_struct", "stime");
        MEMBER_OFFSET_INIT(task_struct_times, "task_struct", "times");
        MEMBER_OFFSET_INIT(tms_tms_utime, "tms", "tms_utime");
        MEMBER_OFFSET_INIT(tms_tms_stime, "tms", "tms_stime");
	MEMBER_OFFSET_INIT(task_struct_utime, "task_struct", "utime");
	MEMBER_OFFSET_INIT(task_struct_stime, "task_struct", "stime");

	STRUCT_SIZE_INIT(cputime_t, "cputime_t");

	if ((THIS_KERNEL_VERSION < LINUX(4,8,0)) &&
	    symbol_exists("cfq_slice_async")) {
		uint cfq_slice_async;

		get_symbol_data("cfq_slice_async", sizeof(int), 
			&cfq_slice_async);

		if (cfq_slice_async) {
			machdep->hz = cfq_slice_async * 25; 

			if (CRASHDEBUG(2))
				fprintf(fp, 
			    	    "cfq_slice_async exists: setting hz to %d\n", 
					machdep->hz);
		}
	} else if ((symbol_exists("dd_init_queue") &&
	    gdb_set_crash_scope(symbol_value("dd_init_queue"), "dd_init_queue")) ||
	    (symbol_exists("dd_init_sched") &&
	    gdb_set_crash_scope(symbol_value("dd_init_sched"), "dd_init_sched")) ||
	    (symbol_exists("deadline_init_queue") &&
	    gdb_set_crash_scope(symbol_value("deadline_init_queue"), "deadline_init_queue"))) {
		char buf[BUFSIZE];
		uint write_expire = 0;

		open_tmpfile();
		sprintf(buf, "printf \"%%d\", write_expire");
		if (gdb_pass_through(buf, pc->tmpfile, GNU_RETURN_ON_ERROR)) {
			rewind(pc->tmpfile);
			if (fgets(buf, BUFSIZE, pc->tmpfile))
				sscanf(buf, "%d", &write_expire);
		}
		close_tmpfile();

		if (write_expire) {
			machdep->hz = write_expire / 5;
			if (CRASHDEBUG(2))
				fprintf(fp, "write_expire exists: setting hz to %d\n",
					machdep->hz);
		}
		gdb_set_crash_scope(0, NULL);
	}

	if (VALID_MEMBER(runqueue_arrays)) 
		MEMBER_OFFSET_INIT(task_struct_run_list, "task_struct",
			"run_list");

	MEMBER_OFFSET_INIT(task_struct_rss_stat, "task_struct",
		"rss_stat");
	MEMBER_OFFSET_INIT(task_rss_stat_count, "task_rss_stat",
		"count");

        if ((tt->task_struct = (char *)malloc(SIZE(task_struct))) == NULL)
        	error(FATAL, "cannot malloc task_struct space.");

        if ((tt->mm_struct = (char *)malloc(SIZE(mm_struct))) == NULL)
        	error(FATAL, "cannot malloc mm_struct space.");

	if ((tt->flags & THREAD_INFO) &&
            ((tt->thread_info = (char *)malloc(SIZE(thread_info))) == NULL)) 
        	error(FATAL, "cannot malloc thread_info space.");

	STRUCT_SIZE_INIT(task_union, "task_union");
	STRUCT_SIZE_INIT(thread_union, "thread_union");

	if (VALID_SIZE(task_union) && (SIZE(task_union) != STACKSIZE())) {
		error(WARNING, "\nnon-standard stack size: %ld\n", 
			len = SIZE(task_union));
		machdep->stacksize = len;
	} else if (VALID_SIZE(thread_union) && 
	    	((len = SIZE(thread_union)) != STACKSIZE())) {
		machdep->stacksize = len;
	} else if (!VALID_SIZE(thread_union) && !VALID_SIZE(task_union)) {
		if (kernel_symbol_exists("__start_init_task") &&
		    kernel_symbol_exists("__end_init_task")) {
			len = symbol_value("__end_init_task");
			len -= symbol_value("__start_init_task");
			ASSIGN_SIZE(thread_union) = len;
			machdep->stacksize = len;
		}
	}

	MEMBER_OFFSET_INIT(pid_namespace_idr, "pid_namespace", "idr");
	MEMBER_OFFSET_INIT(idr_idr_rt, "idr", "idr_rt");

	if (symbol_exists("height_to_maxindex") ||
	    symbol_exists("height_to_maxnodes")) {
		int newver = symbol_exists("height_to_maxnodes");
		int tmp ATTRIBUTE_UNUSED;
		if (!newver) {
			if (LKCD_KERNTYPES())
				ARRAY_LENGTH_INIT_ALT(tmp, "height_to_maxindex",
					"radix_tree_preload.nodes", NULL, 0);
			else
				ARRAY_LENGTH_INIT(tmp, height_to_maxindex,
					"height_to_maxindex", NULL, 0);
		} else {
			if (LKCD_KERNTYPES())
				ARRAY_LENGTH_INIT_ALT(tmp, "height_to_maxnodes",
					"radix_tree_preload.nodes", NULL, 0);
			else
				ARRAY_LENGTH_INIT(tmp, height_to_maxnodes,
					"height_to_maxnodes", NULL, 0);
		}
		STRUCT_SIZE_INIT(radix_tree_root, "radix_tree_root");
		STRUCT_SIZE_INIT(radix_tree_node, "radix_tree_node");
		MEMBER_OFFSET_INIT(radix_tree_root_height,
			"radix_tree_root","height");
		MEMBER_OFFSET_INIT(radix_tree_root_rnode,
			"radix_tree_root","rnode");
		MEMBER_OFFSET_INIT(radix_tree_node_slots,
			"radix_tree_node","slots");
		MEMBER_OFFSET_INIT(radix_tree_node_height,
			"radix_tree_node","height");
		MEMBER_OFFSET_INIT(radix_tree_node_shift,
			"radix_tree_node","shift");
	}

	STRUCT_SIZE_INIT(xarray, "xarray");
	STRUCT_SIZE_INIT(xa_node, "xa_node");
	MEMBER_OFFSET_INIT(xarray_xa_head, "xarray","xa_head");
	MEMBER_OFFSET_INIT(xa_node_slots, "xa_node","slots");
	MEMBER_OFFSET_INIT(xa_node_shift, "xa_node","shift");

	if (symbol_exists("pidhash") && symbol_exists("pid_hash") &&
	    !symbol_exists("pidhash_shift"))
		error(FATAL, 
        "pidhash and pid_hash both exist -- cannot distinquish between them\n");

	if (VALID_MEMBER(pid_namespace_idr)) {
		STRUCT_SIZE_INIT(pid, "pid");
		if (STREQ(MEMBER_TYPE_NAME("idr", "idr_rt"), "xarray")) {
			tt->refresh_task_table = refresh_xarray_task_table;
			tt->pid_xarray = symbol_value("init_pid_ns") +
				OFFSET(pid_namespace_idr) + OFFSET(idr_idr_rt);
			tt->flags |= PID_XARRAY;
		} else if STREQ(MEMBER_TYPE_NAME("idr", "idr_rt"), "radix_tree_root") {
			if (MEMBER_EXISTS("radix_tree_root", "rnode")) {
				tt->refresh_task_table = refresh_radix_tree_task_table;
				tt->pid_radix_tree = symbol_value("init_pid_ns") +
					OFFSET(pid_namespace_idr) + OFFSET(idr_idr_rt);
				tt->flags |= PID_RADIX_TREE;
			} else if (MEMBER_EXISTS("radix_tree_root", "xa_head")) {
				tt->refresh_task_table = refresh_xarray_task_table;
				tt->pid_xarray = symbol_value("init_pid_ns") +
					OFFSET(pid_namespace_idr) + OFFSET(idr_idr_rt);
				tt->flags |= PID_XARRAY;
			}
		} else 
			error(FATAL, "unknown pid_namespace.idr type: %s\n",
				MEMBER_TYPE_NAME("idr", "idr_rt"));
	} else if (symbol_exists("pid_hash") && symbol_exists("pidhash_shift")) {
		int pidhash_shift;

	   	if (get_symbol_type("PIDTYPE_PID", NULL, &req) != 
		    TYPE_CODE_ENUM) 
			error(FATAL,
		           "cannot determine PIDTYPE_PID pid_hash dimension\n");

		get_symbol_data("pidhash_shift", sizeof(int), &pidhash_shift);
		tt->pidhash_len = 1 << pidhash_shift;
		get_symbol_data("pid_hash", sizeof(ulong), &tt->pidhash_addr);

		if (VALID_MEMBER(pid_link_pid) && VALID_MEMBER(pid_hash_chain)) {
			get_symbol_data("pid_hash", sizeof(ulong), &tt->pidhash_addr);
                	tt->refresh_task_table = refresh_pid_hash_task_table;
		} else {
                	tt->pidhash_addr = symbol_value("pid_hash");
			if (LKCD_KERNTYPES()) {
				if (VALID_STRUCT(pid_link)) {
					if (VALID_STRUCT(upid) && VALID_MEMBER(pid_numbers))
						tt->refresh_task_table =
							refresh_hlist_task_table_v3;
					else
						tt->refresh_task_table =
							refresh_hlist_task_table_v2;
 				} else
					tt->refresh_task_table =
						refresh_hlist_task_table;
				builtin_array_length("pid_hash",
					tt->pidhash_len, NULL);
			} else {
				if (!get_array_length("pid_hash", NULL,
				    sizeof(void *)) && VALID_STRUCT(pid_link)) {
					if (VALID_STRUCT(upid) && VALID_MEMBER(pid_numbers))
						tt->refresh_task_table =
							refresh_hlist_task_table_v3;
					else
						tt->refresh_task_table =
							refresh_hlist_task_table_v2;
				}
				else
                			tt->refresh_task_table =
						refresh_hlist_task_table;
			}
		}

                tt->flags |= PID_HASH;

	} else if (symbol_exists("pid_hash")) { 
	   	if (get_symbol_type("PIDTYPE_PGID", NULL, &req) != 
		    TYPE_CODE_ENUM) 
			error(FATAL,
		           "cannot determine PIDTYPE_PID pid_hash dimension\n");
		if (!(tt->pidhash_len = get_array_length("pid_hash",
                    &dim, SIZE(list_head))))
			error(FATAL, 
				"cannot determine pid_hash array dimensions\n");
                
                tt->pidhash_addr = symbol_value("pid_hash");
                tt->refresh_task_table = refresh_pid_hash_task_table;
                tt->flags |= PID_HASH;

        } else if (symbol_exists("pidhash")) {
                tt->pidhash_addr = symbol_value("pidhash");
                tt->pidhash_len = get_array_length("pidhash", NULL, 0);
                if (tt->pidhash_len == 0) {
                        if (!(nsp = next_symbol("pidhash", NULL)))
                                error(FATAL,
                                    "cannot determine pidhash length\n");
                        tt->pidhash_len =
                                (nsp->value-tt->pidhash_addr) / sizeof(void *);
                }
                if (ACTIVE())
                        tt->refresh_task_table = refresh_pidhash_task_table;
                tt->flags |= PIDHASH;
	}

	tt->pf_kthread = UNINITIALIZED;

	get_active_set();

	if (tt->flags & ACTIVE_ONLY)
		tt->refresh_task_table = refresh_active_task_table;

	tt->refresh_task_table(); 

	if (tt->flags & TASK_REFRESH_OFF) 
		tt->flags &= ~(TASK_REFRESH|TASK_REFRESH_OFF);

	/*
	 *  Get the IRQ stacks info if it's configured.
	 */
        if (VALID_STRUCT(irq_ctx))
		irqstacks_init();

	if (ACTIVE()) {
		active_pid = REMOTE() ? pc->server_pid :
			LOCAL_ACTIVE() ? pc->program_pid : 1;
		set_context(NO_TASK, active_pid);
		tt->this_task = pid_to_task(active_pid);
	}
	else {
		if (INVALID_SIZE(note_buf))
			STRUCT_SIZE_INIT(note_buf, "note_buf_t");

		if (KDUMP_DUMPFILE())
			map_cpus_to_prstatus();
		else if (ELF_NOTES_VALID() && DISKDUMP_DUMPFILE())
			map_cpus_to_prstatus_kdump_cmprs();
		please_wait("determining panic task");
		set_context(get_panic_context(), NO_PID);
		please_wait_done();
	}

	sort_context_array();
	sort_tgid_array();

	if (pc->flags & SILENT)
		initialize_task_state();

	stack_overflow_check_init();

	if (machdep->hz) {
		ulonglong uptime_jiffies;
		ulong  uptime_sec;

		get_uptime(NULL, &uptime_jiffies);
		uptime_sec = (uptime_jiffies)/(ulonglong)machdep->hz;
		kt->boot_date.tv_sec = kt->date.tv_sec - uptime_sec;
		kt->boot_date.tv_nsec = 0;
	}

	tt->flags |= TASK_INIT_DONE;
}

/*
 *  Store the pointers to the hard and soft irq_ctx arrays as well as
 *  the task pointers contained within each of them.
 */
static void
irqstacks_init(void)
{
	int i;
	char *thread_info_buf;
	struct syment *hard_sp, *soft_sp;
	ulong ptr, hardirq_next_sp = 0;

	if (!(tt->hardirq_ctx = (ulong *)calloc(NR_CPUS, sizeof(ulong))))
		error(FATAL, "cannot malloc hardirq_ctx space.");
	if (!(tt->hardirq_tasks = (ulong *)calloc(NR_CPUS, sizeof(ulong))))
		error(FATAL, "cannot malloc hardirq_tasks space.");
	if (!(tt->softirq_ctx = (ulong *)calloc(NR_CPUS, sizeof(ulong))))
		error(FATAL, "cannot malloc softirq_ctx space.");
	if (!(tt->softirq_tasks = (ulong *)calloc(NR_CPUS, sizeof(ulong))))
		error(FATAL, "cannot malloc softirq_tasks space.");

	thread_info_buf = GETBUF(SIZE(irq_ctx));

	if ((hard_sp = per_cpu_symbol_search("per_cpu__hardirq_ctx")) ||
	    (hard_sp = per_cpu_symbol_search("per_cpu__hardirq_stack"))) {
		if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF)) {
			for (i = 0; i < NR_CPUS; i++) {
				if (!kt->__per_cpu_offset[i])
					continue;
				ptr = hard_sp->value + kt->__per_cpu_offset[i];

				if (!readmem(ptr, KVADDR, &ptr,
					     sizeof(void *), "hardirq ctx",
					     RETURN_ON_ERROR)) {
					error(INFO, "cannot read hardirq_ctx[%d] at %lx\n",
					      i, ptr);
					continue;
				}
				tt->hardirq_ctx[i] = ptr;
			}
		} else 
			tt->hardirq_ctx[0] = hard_sp->value;
	} else if (symbol_exists("hardirq_ctx")) {
		i = get_array_length("hardirq_ctx", NULL, 0);
		get_symbol_data("hardirq_ctx",
			sizeof(long)*(i <= NR_CPUS ? i : NR_CPUS),
			&tt->hardirq_ctx[0]);
	} else 
		error(WARNING, "cannot determine hardirq_ctx addresses\n");

	/* TODO: Use multithreading to parallely update irq_tasks. */
	for (i = 0; i < NR_CPUS; i++) {
		if (!(tt->hardirq_ctx[i]))
			continue;

		if (!readmem(tt->hardirq_ctx[i], KVADDR, thread_info_buf, 
		    SIZE(irq_ctx), "hardirq thread_union", 
		    RETURN_ON_ERROR)) {
			error(INFO, "cannot read hardirq_ctx[%d] at %lx\n",
				i, tt->hardirq_ctx[i]);
			continue;
		}

		if (MEMBER_EXISTS("irq_ctx", "tinfo"))
			tt->hardirq_tasks[i] = 
				ULONG(thread_info_buf+OFFSET(thread_info_task));
		else {
			hardirq_next_sp = ULONG(thread_info_buf);
			tt->hardirq_tasks[i] = stkptr_to_task(hardirq_next_sp);
		}
	}

	if ((soft_sp = per_cpu_symbol_search("per_cpu__softirq_ctx")) ||
	    (soft_sp = per_cpu_symbol_search("per_cpu__softirq_stack"))) {
		if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF)) {
			for (i = 0; i < NR_CPUS; i++) {
				if (!kt->__per_cpu_offset[i])
					continue;
				ptr = soft_sp->value + kt->__per_cpu_offset[i];

				if (!readmem(ptr, KVADDR, &ptr,
					     sizeof(void *), "softirq ctx",
					     RETURN_ON_ERROR)) {
					error(INFO, "cannot read softirq_ctx[%d] at %lx\n",
					      i, ptr);
					continue;
				}
				tt->softirq_ctx[i] = ptr;
			}
		} else 
			 tt->softirq_ctx[0] = soft_sp->value;
	} else if (symbol_exists("softirq_ctx")) {
		i = get_array_length("softirq_ctx", NULL, 0);
		get_symbol_data("softirq_ctx",
			sizeof(long)*(i <= NR_CPUS ? i : NR_CPUS),
			&tt->softirq_ctx[0]);
	} else
		error(WARNING, "cannot determine softirq_ctx addresses\n");

        for (i = 0; i < NR_CPUS; i++) {
		if (!(tt->softirq_ctx[i]))
			continue;

		if (!readmem(tt->softirq_ctx[i], KVADDR, thread_info_buf,
		    SIZE(irq_ctx), "softirq thread_union",
		    RETURN_ON_ERROR)) {
			error(INFO, "cannot read softirq_ctx[%d] at %lx\n",
				i, tt->hardirq_ctx[i]);
			continue;
		}

		if (MEMBER_EXISTS("irq_ctx", "tinfo")) 
			tt->softirq_tasks[i] =
				ULONG(thread_info_buf+OFFSET(thread_info_task));
		else {
			tt->softirq_tasks[i] = stkptr_to_task(ULONG(thread_info_buf));
			/* Checking if softirq => hardirq nested stack */
			if ((tt->softirq_tasks[i] != NO_TASK) && hardirq_next_sp) {
				if ((tt->softirq_ctx[i] <= hardirq_next_sp) &&
				    (hardirq_next_sp < tt->softirq_ctx[i] + STACKSIZE()))
					tt->hardirq_tasks[i] = tt->softirq_tasks[i];
			}
		}
	}

        tt->flags |= IRQSTACKS;

	FREEBUF(thread_info_buf);

}

int
in_irq_ctx(ulonglong type, int cpu, ulong addr)
{
	if (!(tt->flags & IRQSTACKS))
		return FALSE;

	switch (type)
	{
	case BT_SOFTIRQ:
		if (tt->softirq_ctx[cpu] &&
		    (addr >= tt->softirq_ctx[cpu]) &&
		    (addr < (tt->softirq_ctx[cpu] + STACKSIZE())))
			return TRUE;
		break;

	case BT_HARDIRQ:
		if (tt->hardirq_ctx[cpu] &&
		    (addr >= tt->hardirq_ctx[cpu]) &&
		    (addr < (tt->hardirq_ctx[cpu] + STACKSIZE())))
			return TRUE;
		break;
	}

	return FALSE;
}

/*
 *  Allocate or re-allocated space for the task_context array and task list.
 */
static void
allocate_task_space(int cnt)
{
	if (tt->context_array == NULL) {
               if (!(tt->task_local = (void *)
                    malloc(cnt * sizeof(void *))))
                        error(FATAL,
                            "cannot malloc kernel task array (%d tasks)", cnt);

                if (!(tt->context_array = (struct task_context *)
                    malloc(cnt * sizeof(struct task_context))))
                        error(FATAL, "cannot malloc context array (%d tasks)",
                                cnt);
		if (!(tt->context_by_task = (struct task_context **)
                    malloc(cnt * sizeof(struct task_context*))))
                        error(FATAL, "cannot malloc context_by_task array (%d tasks)",
                                cnt);
		if (!(tt->tgid_array = (struct tgid_context *)
                    malloc(cnt * sizeof(struct tgid_context))))
                        error(FATAL, "cannot malloc tgid array (%d tasks)",
                                cnt);

	} else {
                if (!(tt->task_local = (void *)
		    realloc(tt->task_local, cnt * sizeof(void *)))) 
                        error(FATAL,
                            "%scannot realloc kernel task array (%d tasks)",
                            	(pc->flags & RUNTIME) ? "" : "\n", cnt);
                
                if (!(tt->context_array = (struct task_context *)
                    realloc(tt->context_array, 
		    cnt * sizeof(struct task_context)))) 
                        error(FATAL,
                            "%scannot realloc context array (%d tasks)",
	                	(pc->flags & RUNTIME) ? "" : "\n", cnt);

		 if (!(tt->context_by_task = (struct task_context **)
                    realloc(tt->context_by_task,
		    cnt * sizeof(struct task_context*))))
                        error(FATAL,
                            "%scannot realloc context_by_task array (%d tasks)",
                            	(pc->flags & RUNTIME) ? "" : "\n", cnt);

		 if (!(tt->tgid_array = (struct tgid_context *)
                    realloc(tt->tgid_array, 
		    cnt * sizeof(struct tgid_context)))) 
                        error(FATAL,
                            "%scannot realloc tgid array (%d tasks)",
	                	(pc->flags & RUNTIME) ? "" : "\n", cnt);
	}
}


/*
 *  This routine runs one time on dumpfiles, and constantly on live systems.
 *  It walks through the kernel task array looking for active tasks, and
 *  populates the local task table with their essential data.
 */
static void
refresh_fixed_task_table(void)
{
	int i;
	ulong *tlp;
	ulong curtask;
	ulong retries;
	ulong curpid;
	char *tp;

#define TASK_FREE(x)   ((x == 0) || (((ulong)(x) >= tt->task_start) && \
                       ((ulong)(x) < tt->task_end)))
#define TASK_IN_USE(x) (!TASK_FREE(x))

	if (DUMPFILE() && (tt->flags & TASK_INIT_DONE))
		return;

	if (DUMPFILE()) {
        	fprintf(fp, (pc->flags & SILENT) || !(pc->flags & TTY) ?
                        "" : "%splease wait... (gathering task table data)",
			GDB_PATCHED() ? "" : "\n");
		fflush(fp);
		if (!symbol_exists("panic_threads"))
			tt->flags |= POPULATE_PANIC;
	} 

	if (ACTIVE() && !(tt->flags & TASK_REFRESH))
		return;

	curpid = NO_PID;
	curtask = NO_TASK;

        /*
         *  The current task's task_context entry may change,
         *  or the task may not even exist anymore.
         */
	if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) {
		curtask = CURRENT_TASK();
		curpid = CURRENT_PID();
	}

	retries = 0;
retry:
        if (!readmem(tt->task_start, KVADDR, tt->task_local,
            tt->max_tasks * sizeof(void *), "kernel task array", 
	    RETURN_ON_ERROR))
        	error(FATAL, "cannot read kernel task array");

	clear_task_cache();

        for (i = 0, tlp = (ulong *)tt->task_local, tt->running_tasks = 0;
             i < tt->max_tasks; i++, tlp++) {
                if (TASK_IN_USE(*tlp)) {
                	if (!(tp = fill_task_struct(*tlp))) {
                        	if (DUMPFILE())
                                	continue;
                        	retries++;
                        	goto retry;
                	}

			add_context(*tlp, tp);
		}
        }

	if (DUMPFILE()) {
		fprintf(fp, (pc->flags & SILENT) || !(pc->flags & TTY) ? "" :
                        "\r                                                \r");
                fflush(fp);
	}

        if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) 
		refresh_context(curtask, curpid);

	tt->retries = MAX(tt->retries, retries);
}

/*
 *  Verify that a task_context's data makes sense enough to include
 *  in the task_context array.
 */
static int
verify_task(struct task_context *tc, int level)
{
	int i;
	ulong next_task;
	ulong readflag;

        readflag = ACTIVE() ? (RETURN_ON_ERROR|QUIET) : (RETURN_ON_ERROR);

	switch (level)
	{
	case 1:
        	if (!readmem(tc->task + OFFSET(task_struct_next_task),
	    	    KVADDR, &next_task, sizeof(void *), "next_task", readflag)) {
			return FALSE;
        	}
		if (!IS_TASK_ADDR(next_task))
			return FALSE;

		if (tc->processor & ~NO_PROC_ID)
			return FALSE;

		/* fall through */
	case 2:
		if (!IS_TASK_ADDR(tc->ptask))
			return FALSE;

		if ((tc->processor < 0) || (tc->processor >= NR_CPUS)) {
			for (i = 0; i < NR_CPUS; i++) {
				if (tc->task == tt->active_set[i]) {
					error(WARNING, 
			"active task %lx on cpu %d: corrupt cpu value: %u\n\n",
						tc->task, i, tc->processor);
					tc->processor = i;
					return TRUE;
				}
			}

			if (CRASHDEBUG(1))
				error(INFO, 
				    "verify_task: task: %lx invalid processor: %u",
					tc->task, tc->processor);
			return FALSE;
		}

		break;
	}

	return TRUE;
}

/*
 *  This routine runs one time on dumpfiles, and constantly on live systems.
 *  It walks through the kernel task array looking for active tasks, and
 *  populates the local task table with their essential data.
 */

#define MAX_UNLIMITED_TASK_RETRIES (500)

void
refresh_unlimited_task_table(void)
{
	int i;
	ulong *tlp;
	ulong curtask;
	ulong curpid;
	struct list_data list_data, *ld;
	ulong init_tasks[NR_CPUS];
	ulong retries;
	char *tp;
	int cnt;

	if (DUMPFILE() && (tt->flags & TASK_INIT_DONE))
		return;

        if (DUMPFILE()) {
                fprintf(fp, (pc->flags & SILENT) || !(pc->flags & TTY) ?
                        "" : "%splease wait... (gathering task table data)",
                        GDB_PATCHED() ? "" : "\n");
                fflush(fp);
		if (!symbol_exists("panic_threads"))
			tt->flags |= POPULATE_PANIC;
        } 

        if (ACTIVE() && !(tt->flags & TASK_REFRESH))
                return;

	curpid = NO_PID;
	curtask = NO_TASK;
	tp = NULL;

	/*
	 *  The current task's task_context entry may change,  
	 *  or the task may not even exist anymore.
	 */
        if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) {
                curtask = CURRENT_TASK();
                curpid = CURRENT_PID();
        }

	retries = 0;
retry:
	if (retries && DUMPFILE()) {
		if (tt->flags & PIDHASH) {
			error(WARNING, 
		      "\ncannot gather a stable task list -- trying pidhash\n");
			refresh_pidhash_task_table();
			return;
		}
		error(FATAL, "\ncannot gather a stable task list\n");
	}

	if ((retries == MAX_UNLIMITED_TASK_RETRIES) &&  
	    !(tt->flags & TASK_INIT_DONE)) 
		error(FATAL, "cannot gather a stable task list\n");

	/*
	 *  Populate the task_local array with a quick walk-through.
 	 *  If there's not enough room in the local array, realloc() it.
	 */
	ld = &list_data;
	BZERO(ld, sizeof(struct list_data));
	ld->flags |= RETURN_ON_LIST_ERROR;
	ld->start = symbol_value("init_task_union");
	ld->member_offset = OFFSET(task_struct_next_task);

	if (!hq_open()) {
		error(INFO, "cannot hash task_struct entries\n");
		if (!(tt->flags & TASK_INIT_DONE))
			clean_exit(1);
		error(INFO, "using stale task_structs\n");
		FREEBUF(tp);
		return;
	}

	if ((cnt = do_list(ld)) < 0) {
		retries++;
		goto retry;
	}

	if ((cnt+NR_CPUS+1) > tt->max_tasks) { 
		tt->max_tasks = cnt + NR_CPUS + TASK_SLUSH;
		allocate_task_space(tt->max_tasks);
		hq_close();
		if (!DUMPFILE())
			retries++;
		goto retry;
	}

	BZERO(tt->task_local, tt->max_tasks * sizeof(void *));
	cnt = retrieve_list((ulong *)tt->task_local, cnt);
	hq_close();

	/*
	 *  If SMP, add in the other idle tasks.
	 */
	if (kt->flags & SMP) {   
        	/*
         	 *  Now get the rest of the init_task[] entries, starting
		 *  at offset 1 since we've got the init_task already.
         	 */
		BZERO(&init_tasks[0], sizeof(ulong) * NR_CPUS);
		get_idle_threads(&init_tasks[0], kt->cpus);

		tlp = (ulong *)tt->task_local;
		tlp += cnt;

		for (i = 1; i < kt->cpus; i++) {
			if (init_tasks[i]) {
				*tlp = init_tasks[i];
				tlp++;
			}
	 	}
	}

	clear_task_cache();

        for (i = 0, tlp = (ulong *)tt->task_local, tt->running_tasks = 0;
             i < tt->max_tasks; i++, tlp++) {
		if (!(*tlp))
			continue;

		if (!IS_TASK_ADDR(*tlp)) {
			error(INFO, 
			    "\ninvalid task address in task list: %lx\n", *tlp);
			retries++;
			goto retry;
		}	
	
                if (!(tp = fill_task_struct(*tlp))) {
                     	if (DUMPFILE())
                        	continue;
                        retries++;
                        goto retry;
                }

		add_context(*tlp, tp);
	}

	if (DUMPFILE()) {
		fprintf(fp, (pc->flags & SILENT) || !(pc->flags & TTY) ? "" :
                        "\r                                                \r");
                fflush(fp);
	}

        if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) 
		refresh_context(curtask, curpid);

	tt->retries = MAX(tt->retries, retries);

}

/*
 *  This routine runs one time on dumpfiles, and constantly on live systems.
 *  It walks through the kernel pidhash array looking for active tasks, and
 *  populates the local task table with their essential data.
 *
 *  The following manner of refreshing the task table can be used for all
 *  kernels that have a pidhash[] array, whether or not they still 
 *  have a fixed task[] array or an unlimited list.
 */
static void
refresh_pidhash_task_table(void)
{
	int i;
	char *pidhash, *tp; 
	ulong *pp, next, pnext;
	int len, cnt;
        ulong curtask;
        ulong curpid;
        ulong retries;
	ulong *tlp;

        if (DUMPFILE() && (tt->flags & TASK_INIT_DONE))   /* impossible */
                return;

        if (DUMPFILE()) {                                 /* impossible */
                fprintf(fp, (pc->flags & SILENT) || !(pc->flags & TTY) ?
                        "" : "\rplease wait... (gathering task table data)");
                fflush(fp);
                if (!symbol_exists("panic_threads"))
                        tt->flags |= POPULATE_PANIC;
        }

        if (ACTIVE() && !(tt->flags & TASK_REFRESH))
                return;

	curpid = NO_PID;
	curtask = NO_TASK;

        /*
         *  The current task's task_context entry may change,
         *  or the task may not even exist anymore.
         */
        if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) {
                curtask = CURRENT_TASK();
                curpid = CURRENT_PID();
        }

	len = tt->pidhash_len;
	pidhash = GETBUF(len * sizeof(ulong));
        retries = 0;

retry_pidhash:
	if (retries && DUMPFILE())
		error(FATAL,"\ncannot gather a stable task list via pidhash\n");

        if ((retries == MAX_UNLIMITED_TASK_RETRIES) &&
            !(tt->flags & TASK_INIT_DONE)) 
                error(FATAL, 
	        "\ncannot gather a stable task list via pidhash (%d retries)\n",
			retries);

        if (!readmem(tt->pidhash_addr, KVADDR, pidhash, 
	    len * sizeof(ulong), "pidhash contents", RETURN_ON_ERROR)) 
		error(FATAL, "\ncannot read pidhash array\n");

        if (!hq_open()) {
                error(INFO, "cannot hash task_struct entries\n");
                if (!(tt->flags & TASK_INIT_DONE))
                        clean_exit(1);
                error(INFO, "using stale task_structs\n");
                FREEBUF(pidhash);
                return;
        }

	/*
	 *  Get the idle threads first. 
	 */
	cnt = 0;
	for (i = 0; i < kt->cpus; i++) {
		if (hq_enter(tt->idle_threads[i]))
			cnt++;
		else
			error(WARNING, "%sduplicate idle tasks?\n",
				DUMPFILE() ? "\n" : "");
	}

	/*
	 *  Then dump the pidhash contents.
	 */
	for (i = 0, pp = (ulong *)pidhash; i < len; i++, pp++) {
		if (!(*pp) || !IS_KVADDR(*pp))
			continue;
		/*
		 *  Mininum verification here -- make sure that a task address
		 *  and its pidhash_next entry (if any) both appear to be 
		 *  properly aligned before accepting the task.
		 */
		next = *pp;
		while (next) {
			if (!IS_TASK_ADDR(next)) {
                                error(INFO, 
				    "%sinvalid task address in pidhash: %lx\n",
                                        DUMPFILE() ? "\n" : "", next);
                                if (DUMPFILE()) 
                                        break;
                                hq_close();
                                retries++;
                                goto retry_pidhash;

			}

                        if (!readmem(next + OFFSET(task_struct_pidhash_next),
                            KVADDR, &pnext, sizeof(void *),
                            "pidhash_next entry", QUIET|RETURN_ON_ERROR)) {
                                error(INFO, "%scannot read from task: %lx\n",
                                        DUMPFILE() ? "\n" : "", next);
				if (DUMPFILE()) 
					break;
                                hq_close();
				retries++;
                                goto retry_pidhash;
                        }

			if (!hq_enter(next)) {
				error(INFO, 
				    "%sduplicate task in pidhash: %lx\n",
					DUMPFILE() ? "\n" : "", next);
				if (DUMPFILE())
					break;
				hq_close();
				retries++;
				goto retry_pidhash;
			}

			next = pnext;

			cnt++;
		}
	}

        if ((cnt+1) > tt->max_tasks) {
                tt->max_tasks = cnt + NR_CPUS + TASK_SLUSH;
		allocate_task_space(tt->max_tasks);
                hq_close();
		if (!DUMPFILE())
                	retries++;
                goto retry_pidhash;
        }

        BZERO(tt->task_local, tt->max_tasks * sizeof(void *));
        cnt = retrieve_list((ulong *)tt->task_local, cnt);

	hq_close();

	clear_task_cache();

        for (i = 0, tlp = (ulong *)tt->task_local, tt->running_tasks = 0;
             i < tt->max_tasks; i++, tlp++) {
		if (!(*tlp))
			continue;

		if (!IS_TASK_ADDR(*tlp)) {
			error(WARNING, 
		            "%sinvalid task address found in task list: %lx\n", 
				DUMPFILE() ? "\n" : "", *tlp);
			if (DUMPFILE()) 
				continue;
			retries++;
			goto retry_pidhash;
		}	
	
		if (!(tp = fill_task_struct(*tlp))) {
                        if (DUMPFILE())
                                continue;
                        retries++;
                        goto retry_pidhash;
                }

		add_context(*tlp, tp);
	}

        FREEBUF(pidhash);

	if (DUMPFILE()) {
		fprintf(fp, (pc->flags & SILENT) || !(pc->flags & TTY) ? "" :
                        "\r                                                \r");
                fflush(fp);
	}

        if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) 
		refresh_context(curtask, curpid);

	tt->retries = MAX(tt->retries, retries);
}


/*
 *  The following manner of refreshing the task table is used for all
 *  kernels that have a pid_hash[][] array.
 *
 *  This routine runs one time on dumpfiles, and constantly on live systems.
 *  It walks through the kernel pid_hash[PIDTYPE_PID] array looking for active
 *  tasks, and populates the local task table with their essential data.
 */

#define HASH_TO_TASK(X) ((ulong)(X) - (OFFSET(task_struct_pids) + \
                         OFFSET(pid_link_pid) + OFFSET(pid_hash_chain)))

#define TASK_TO_HASH(X) ((ulong)(X) + (OFFSET(task_struct_pids) + \
                         OFFSET(pid_link_pid) + OFFSET(pid_hash_chain)))

static void
refresh_pid_hash_task_table(void)
{
	int i;
	struct kernel_list_head *pid_hash, *pp, *kpp;
	char *tp; 
	ulong next, pnext;
	int len, cnt;
        ulong curtask;
        ulong curpid;
        ulong retries;
	ulong *tlp;

        if (DUMPFILE() && (tt->flags & TASK_INIT_DONE))   /* impossible */
                return;

        if (DUMPFILE()) {                                 /* impossible */
		please_wait("gathering task table data");
                if (!symbol_exists("panic_threads"))
                        tt->flags |= POPULATE_PANIC;
        }

        if (ACTIVE() && !(tt->flags & TASK_REFRESH))
                return;

	curpid = NO_PID;
	curtask = NO_TASK;

        /*
         *  The current task's task_context entry may change,
         *  or the task may not even exist anymore.
         */
        if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) {
                curtask = CURRENT_TASK();
                curpid = CURRENT_PID();
        }

	len = tt->pidhash_len;
	pid_hash = (struct kernel_list_head *)GETBUF(len * SIZE(list_head));
        retries = 0;

retry_pid_hash:
	if (retries && DUMPFILE())
		error(FATAL,
			"\ncannot gather a stable task list via pid_hash\n");

        if ((retries == MAX_UNLIMITED_TASK_RETRIES) &&
            !(tt->flags & TASK_INIT_DONE)) 
                error(FATAL, 
	       "\ncannot gather a stable task list via pid_hash (%d retries)\n",
			retries);

        if (!readmem(tt->pidhash_addr, KVADDR, pid_hash, 
	    len * SIZE(list_head), "pid_hash contents", RETURN_ON_ERROR)) 
		error(FATAL, "\ncannot read pid_hash array\n");

        if (!hq_open()) {
                error(INFO, "cannot hash task_struct entries\n");
                if (!(tt->flags & TASK_INIT_DONE))
                        clean_exit(1);
                error(INFO, "using stale task_structs\n");
                FREEBUF(pid_hash);
                return;
        }

	/*
	 *  Get the idle threads first. 
	 */
	cnt = 0;
	for (i = 0; i < kt->cpus; i++) {
		if (hq_enter(tt->idle_threads[i]))
			cnt++;
		else
			error(WARNING, "%sduplicate idle tasks?\n",
				DUMPFILE() ? "\n" : "");
	}

	for (i = 0; i < len; i++) {
		pp = &pid_hash[i];
		kpp = (struct kernel_list_head *)(tt->pidhash_addr + 
			i * SIZE(list_head));
		if (pp->next == kpp)
			continue;

		if (CRASHDEBUG(7))
		    console("%lx: pid_hash[%d]: %lx (%lx) %lx (%lx)\n", kpp, i,
			pp->next, HASH_TO_TASK(pp->next),
			pp->prev, HASH_TO_TASK(pp->prev));

		next = (ulong)HASH_TO_TASK(pp->next);
		while (next) {
                        if (!IS_TASK_ADDR(next)) {
                                error(INFO,
                                    "%sinvalid task address in pid_hash: %lx\n",
                                        DUMPFILE() ? "\n" : "", next);
                                if (DUMPFILE())
                                        break;
                                hq_close();
                                retries++;
                                goto retry_pid_hash;

                        }

                        if (!readmem(TASK_TO_HASH(next),
                            KVADDR, &pnext, sizeof(void *),
                            "pid_hash entry", QUIET|RETURN_ON_ERROR)) {
                                error(INFO, "%scannot read from task: %lx\n",
                                        DUMPFILE() ? "\n" : "", next);
                                if (DUMPFILE())
                                        break;
                                hq_close();
                                retries++;
                                goto retry_pid_hash;
                        }

                        if (!is_idle_thread(next) && !hq_enter(next)) {
                                error(INFO,
                                    "%sduplicate task in pid_hash: %lx\n",
                                        DUMPFILE() ? "\n" : "", next);
                                if (DUMPFILE())
                                        break;
                                hq_close();
                                retries++;
                                goto retry_pid_hash;
                        }

                        cnt++;

			if (pnext == (ulong)kpp) 
				break;

                        next = HASH_TO_TASK(pnext);
		}
	}

        BZERO(tt->task_local, tt->max_tasks * sizeof(void *));
        cnt = retrieve_list((ulong *)tt->task_local, cnt);

	hq_close();

	clear_task_cache();

        for (i = 0, tlp = (ulong *)tt->task_local, tt->running_tasks = 0;
             i < tt->max_tasks; i++, tlp++) {
		if (!(*tlp))
			continue;

		if (!IS_TASK_ADDR(*tlp)) {
			error(WARNING, 
		            "%sinvalid task address found in task list: %lx\n", 
				DUMPFILE() ? "\n" : "", *tlp);
			if (DUMPFILE()) 
				continue;
			retries++;
			goto retry_pid_hash;
		}	
	
		if (!(tp = fill_task_struct(*tlp))) {
                        if (DUMPFILE())
                                continue;
                        retries++;
                        goto retry_pid_hash;
                }

		add_context(*tlp, tp);
	}

        FREEBUF(pid_hash);

	please_wait_done();

        if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) 
		refresh_context(curtask, curpid);

	tt->retries = MAX(tt->retries, retries);
}

/*
 *  Adapt to yet another scheme, using later 2.6 hlist_head and hlist_nodes.
 */

#define HLIST_TO_TASK(X) ((ulong)(X) - (OFFSET(task_struct_pids) + \
                           OFFSET(pid_pid_chain)))

static void
refresh_hlist_task_table(void)
{
	int i;
	ulong *pid_hash;
	struct syment *sp;
	ulong pidhash_array;
	ulong kpp;
	char *tp; 
	ulong next, pnext, pprev;
	char *nodebuf;
	int plen, len, cnt;
	long value;
        ulong curtask;
        ulong curpid;
        ulong retries;
	ulong *tlp;

        if (DUMPFILE() && (tt->flags & TASK_INIT_DONE))   /* impossible */
                return;

        if (DUMPFILE()) {                                 /* impossible */
		please_wait("gathering task table data");
                if (!symbol_exists("panic_threads"))
                        tt->flags |= POPULATE_PANIC;
        }

        if (ACTIVE() && !(tt->flags & TASK_REFRESH))
                return;

	curpid = NO_PID;
	curtask = NO_TASK;

        /*
         *  The current task's task_context entry may change,
         *  or the task may not even exist anymore.
         */
        if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) {
                curtask = CURRENT_TASK();
                curpid = CURRENT_PID();
        }

	if (!(plen = get_array_length("pid_hash", NULL, sizeof(void *)))) {
		/*
		 *  Workaround for gcc omitting debuginfo data for pid_hash.
		 */
		if (enumerator_value("PIDTYPE_MAX", &value)) {
			if ((sp = next_symbol("pid_hash", NULL)) &&
		    	    (((sp->value - tt->pidhash_addr) / sizeof(void *)) < value))
				error(WARNING, "possible pid_hash array mis-handling\n");
			plen = (int)value;
		} else {
			error(WARNING, 
			    "cannot determine pid_hash array dimensions\n");
			plen = 1;
		}
	}

	pid_hash = (ulong *)GETBUF(plen * sizeof(void *));

        if (!readmem(tt->pidhash_addr, KVADDR, pid_hash, 
	    plen * SIZE(hlist_head), "pid_hash[] contents", RETURN_ON_ERROR)) 
		error(FATAL, "\ncannot read pid_hash array\n");

	if (CRASHDEBUG(7)) 
		for (i = 0; i < plen; i++)
			console("pid_hash[%d]: %lx\n", i, pid_hash[i]);

	/*
	 *  The zero'th (PIDTYPE_PID) entry is the hlist_head array
	 *  that we want.
	 */
	if (CRASHDEBUG(1)) {
		if (!enumerator_value("PIDTYPE_PID", &value))
			error(WARNING, 
			    "possible pid_hash array mis-handling: PIDTYPE_PID: (unknown)\n");
		else if (value != 0)
			error(WARNING, 
			    "possible pid_hash array mis-handling: PIDTYPE_PID: %d \n", 
				value);
	}

	pidhash_array = pid_hash[0];
	FREEBUF(pid_hash);

	len = tt->pidhash_len;
	pid_hash = (ulong *)GETBUF(len * SIZE(hlist_head));
	nodebuf = GETBUF(SIZE(hlist_node));
        retries = 0;

retry_pid_hash:
	if (retries && DUMPFILE())
		error(FATAL,
			"\ncannot gather a stable task list via pid_hash\n");

        if ((retries == MAX_UNLIMITED_TASK_RETRIES) &&
            !(tt->flags & TASK_INIT_DONE)) 
                error(FATAL, 
	       "\ncannot gather a stable task list via pid_hash (%d retries)\n",
			retries);

        if (!readmem(pidhash_array, KVADDR, pid_hash, 
	    len * SIZE(hlist_head), "pid_hash[0] contents", RETURN_ON_ERROR)) 
		error(FATAL, "\ncannot read pid_hash[0] array\n");

        if (!hq_open()) {
                error(INFO, "cannot hash task_struct entries\n");
                if (!(tt->flags & TASK_INIT_DONE))
                        clean_exit(1);
                error(INFO, "using stale task_structs\n");
                FREEBUF(pid_hash);
                return;
        }

	/*
	 *  Get the idle threads first. 
	 */
	cnt = 0;
	for (i = 0; i < kt->cpus; i++) {
		if (hq_enter(tt->idle_threads[i]))
			cnt++;
		else
			error(WARNING, "%sduplicate idle tasks?\n",
				DUMPFILE() ? "\n" : "");
	}

	for (i = 0; i < len; i++) {
		if (!pid_hash[i])
			continue;

        	if (!readmem(pid_hash[i], KVADDR, nodebuf, 
	    	    SIZE(hlist_node), "pid_hash node", RETURN_ON_ERROR|QUIET)) { 
			error(INFO, "\ncannot read pid_hash node\n");
                        if (DUMPFILE())
                                continue;
                        hq_close();
                        retries++;
                        goto retry_pid_hash;
		}

		kpp = pid_hash[i];
		next = (ulong)HLIST_TO_TASK(kpp);
		pnext = ULONG(nodebuf + OFFSET(hlist_node_next));
		pprev = ULONG(nodebuf + OFFSET(hlist_node_pprev));

		if (CRASHDEBUG(1)) 
			console("pid_hash[%d]: %lx task: %lx (node: %lx) next: %lx pprev: %lx\n",
				i, pid_hash[i], next, kpp, pnext, pprev);

		while (next) {
                        if (!IS_TASK_ADDR(next)) {
                                error(INFO,
                                    "%sinvalid task address in pid_hash: %lx\n",
                                        DUMPFILE() ? "\n" : "", next);
                                if (DUMPFILE())
                                        break;
                                hq_close();
                                retries++;
                                goto retry_pid_hash;

                        }

                        if (!is_idle_thread(next) && !hq_enter(next)) {
                                error(INFO,
                                    "%sduplicate task in pid_hash: %lx\n",
                                        DUMPFILE() ? "\n" : "", next);
                                if (DUMPFILE())
                                        break;
                                hq_close();
                                retries++;
                                goto retry_pid_hash;
                        }

                        cnt++;

			if (!pnext) 
				break;

                        if (!readmem((ulonglong)pnext, KVADDR, nodebuf,
                                SIZE(hlist_node), "task hlist_node", RETURN_ON_ERROR|QUIET)) {
                                error(INFO, "\ncannot read hlist_node from task\n");
                                if (DUMPFILE())
                                        break;
                                hq_close();
                                retries++;
                                goto retry_pid_hash;
                        }

			kpp = (ulong)pnext;
			next = (ulong)HLIST_TO_TASK(kpp);
			pnext = ULONG(nodebuf + OFFSET(hlist_node_next));
			pprev = ULONG(nodebuf + OFFSET(hlist_node_pprev));

			if (CRASHDEBUG(1)) 
				console("  chained task: %lx (node: %lx) next: %lx pprev: %lx\n",
					(ulong)HLIST_TO_TASK(kpp), kpp, pnext, pprev);
		}
	}

        if (cnt > tt->max_tasks) {
                tt->max_tasks = cnt + TASK_SLUSH;
                allocate_task_space(tt->max_tasks);
                hq_close();
                if (!DUMPFILE())
                        retries++;
                goto retry_pid_hash;
        }

        BZERO(tt->task_local, tt->max_tasks * sizeof(void *));
        cnt = retrieve_list((ulong *)tt->task_local, cnt);

	hq_close();

	clear_task_cache();

        for (i = 0, tlp = (ulong *)tt->task_local, tt->running_tasks = 0;
             i < tt->max_tasks; i++, tlp++) {
		if (!(*tlp))
			continue;

		if (!IS_TASK_ADDR(*tlp)) {
			error(WARNING, 
		            "%sinvalid task address found in task list: %lx\n", 
				DUMPFILE() ? "\n" : "", *tlp);
			if (DUMPFILE()) 
				continue;
			retries++;
			goto retry_pid_hash;
		}	
	
		if (!(tp = fill_task_struct(*tlp))) {
                        if (DUMPFILE())
                                continue;
                        retries++;
                        goto retry_pid_hash;
                }

		add_context(*tlp, tp);
	}

        FREEBUF(pid_hash);
	FREEBUF(nodebuf);

	please_wait_done();

        if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) 
		refresh_context(curtask, curpid);

	tt->retries = MAX(tt->retries, retries);
}

/*
 *  2.6.17 replaced:
 *    static struct hlist_head *pid_hash[PIDTYPE_MAX];
 *  with
 *     static struct hlist_head *pid_hash;
 */
static void
refresh_hlist_task_table_v2(void)
{
	int i;
	ulong *pid_hash;
	ulong pidhash_array;
	ulong kpp;
	char *tp; 
	ulong next, pnext, pprev;
	char *nodebuf;
	int len, cnt;
        ulong curtask;
        ulong curpid;
        ulong retries;
	ulong *tlp;

        if (DUMPFILE() && (tt->flags & TASK_INIT_DONE))   /* impossible */
                return;

        if (DUMPFILE()) {                                 /* impossible */
		please_wait("gathering task table data");
                if (!symbol_exists("panic_threads"))
                        tt->flags |= POPULATE_PANIC;
        }

        if (ACTIVE() && !(tt->flags & TASK_REFRESH))
                return;

	curpid = NO_PID;
	curtask = NO_TASK;

        /*
         *  The current task's task_context entry may change,
         *  or the task may not even exist anymore.
         */
        if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) {
                curtask = CURRENT_TASK();
                curpid = CURRENT_PID();
        }

	get_symbol_data("pid_hash", sizeof(void *), &pidhash_array);

	len = tt->pidhash_len;
	pid_hash = (ulong *)GETBUF(len * SIZE(hlist_head));
	nodebuf = GETBUF(SIZE(pid_link));
        retries = 0;

retry_pid_hash:
	if (retries && DUMPFILE())
		error(FATAL,
			"\ncannot gather a stable task list via pid_hash\n");

        if ((retries == MAX_UNLIMITED_TASK_RETRIES) &&
            !(tt->flags & TASK_INIT_DONE)) 
                error(FATAL, 
	       "\ncannot gather a stable task list via pid_hash (%d retries)\n",
			retries);

        if (!readmem(pidhash_array, KVADDR, pid_hash, 
	    len * SIZE(hlist_head), "pid_hash contents", RETURN_ON_ERROR)) 
		error(FATAL, "\ncannot read pid_hash array\n");

        if (!hq_open()) {
                error(INFO, "cannot hash task_struct entries\n");
                if (!(tt->flags & TASK_INIT_DONE))
                        clean_exit(1);
                error(INFO, "using stale task_structs\n");
                FREEBUF(pid_hash);
                return;
        }

	/*
	 *  Get the idle threads first. 
	 */
	cnt = 0;
	for (i = 0; i < kt->cpus; i++) {
		if (hq_enter(tt->idle_threads[i]))
			cnt++;
		else
			error(WARNING, "%sduplicate idle tasks?\n",
				DUMPFILE() ? "\n" : "");
	}

	for (i = 0; i < len; i++) {
		if (!pid_hash[i])
			continue;

        	if (!readmem(pid_hash[i], KVADDR, nodebuf, 
	    	    SIZE(pid_link), "pid_hash node pid_link", RETURN_ON_ERROR|QUIET)) { 
			error(INFO, "\ncannot read pid_hash node pid_link\n");
                        if (DUMPFILE())
                                continue;
                        hq_close();
                        retries++;
                        goto retry_pid_hash;
		}

		kpp = pid_hash[i];
		next = ULONG(nodebuf + OFFSET(pid_link_pid)); 
		if (next)
			next -= OFFSET(task_struct_pids);
		pnext = ULONG(nodebuf + OFFSET(hlist_node_next));
		pprev = ULONG(nodebuf + OFFSET(hlist_node_pprev));

		if (CRASHDEBUG(1)) 
			console("pid_hash[%d]: %lx task: %lx (node: %lx) next: %lx pprev: %lx\n",
				i, pid_hash[i], next, kpp, pnext, pprev);

		while (1) {
			if (next) {
                        	if (!IS_TASK_ADDR(next)) {
                                	error(INFO,
                                    	"%sinvalid task address in pid_hash: %lx\n",
                                        	DUMPFILE() ? "\n" : "", next);
                                	if (DUMPFILE())
                                        	break;
                                	hq_close();
                                	retries++;
                                	goto retry_pid_hash;

                        	}

                        	if (!is_idle_thread(next) && !hq_enter(next)) {
                                	error(INFO,
                                    	"%sduplicate task in pid_hash: %lx\n",
                                        	DUMPFILE() ? "\n" : "", next);
                                	if (DUMPFILE())
                                        	break;
                                	hq_close();
                                	retries++;
                                	goto retry_pid_hash;
                        	}

			}
                        cnt++;

			if (!pnext) 
				break;

                        if (!readmem((ulonglong)pnext, KVADDR, nodebuf,
                                SIZE(pid_link), "task hlist_node pid_link", RETURN_ON_ERROR|QUIET)) {
                                error(INFO, "\ncannot read hlist_node pid_link from node next\n");
                                if (DUMPFILE())
                                        break;
                                hq_close();
                                retries++;
                                goto retry_pid_hash;
                        }

			kpp = (ulong)pnext;
			next = ULONG(nodebuf + OFFSET(pid_link_pid));
			if (next)
				next -= OFFSET(task_struct_pids);
			pnext = ULONG(nodebuf + OFFSET(hlist_node_next));
			pprev = ULONG(nodebuf + OFFSET(hlist_node_pprev));

			if (CRASHDEBUG(1)) 
				console("  chained task: %lx (node: %lx) next: %lx pprev: %lx\n",
					next, kpp, pnext, pprev);
		}
	}

        if (cnt > tt->max_tasks) {
                tt->max_tasks = cnt + TASK_SLUSH;
                allocate_task_space(tt->max_tasks);
                hq_close();
                if (!DUMPFILE())
                        retries++;
                goto retry_pid_hash;
        }

        BZERO(tt->task_local, tt->max_tasks * sizeof(void *));
        cnt = retrieve_list((ulong *)tt->task_local, cnt);

	hq_close();

	clear_task_cache();

        for (i = 0, tlp = (ulong *)tt->task_local, tt->running_tasks = 0;
             i < tt->max_tasks; i++, tlp++) {
		if (!(*tlp))
			continue;

		if (!IS_TASK_ADDR(*tlp)) {
			error(WARNING, 
		            "%sinvalid task address found in task list: %lx\n", 
				DUMPFILE() ? "\n" : "", *tlp);
			if (DUMPFILE()) 
				continue;
			retries++;
			goto retry_pid_hash;
		}	
	
		if (!(tp = fill_task_struct(*tlp))) {
                        if (DUMPFILE())
                                continue;
                        retries++;
                        goto retry_pid_hash;
                }

		add_context(*tlp, tp);
	}

        FREEBUF(pid_hash);
	FREEBUF(nodebuf);

	please_wait_done();

        if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) 
		refresh_context(curtask, curpid);

	tt->retries = MAX(tt->retries, retries);
}


/*
 *  2.6.24: The pid_hash[] hlist_head entries were changed to point 
 *  to the hlist_node structure embedded in a upid structure. 
 */
static void
refresh_hlist_task_table_v3(void)
{
	int i;
	ulong *pid_hash;
	ulong pidhash_array;
	ulong kpp;
	char *tp; 
	ulong next, pnext, pprev;
	ulong upid;
	char *nodebuf;
	int len, cnt;
        ulong curtask;
        ulong curpid;
        ulong retries;
	ulong *tlp;
	uint upid_nr;
	ulong upid_ns;
	int chained;
	ulong pid;
	ulong pid_tasks_0;

        if (DUMPFILE() && (tt->flags & TASK_INIT_DONE))   /* impossible */
                return;

        if (DUMPFILE()) {                                 /* impossible */
		please_wait("gathering task table data");
                if (!symbol_exists("panic_threads"))
                        tt->flags |= POPULATE_PANIC;
        }

        if (ACTIVE() && !(tt->flags & TASK_REFRESH))
                return;

	curpid = NO_PID;
	curtask = NO_TASK;

        /*
         *  The current task's task_context entry may change,
         *  or the task may not even exist anymore.
         */
        if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) {
                curtask = CURRENT_TASK();
                curpid = CURRENT_PID();
        }

	get_symbol_data("pid_hash", sizeof(void *), &pidhash_array);

	len = tt->pidhash_len;
	pid_hash = (ulong *)GETBUF(len * SIZE(hlist_head));
	nodebuf = GETBUF(SIZE(upid));
        retries = 0;

retry_pid_hash:
	if (retries && DUMPFILE())
		error(FATAL,
			"\ncannot gather a stable task list via pid_hash\n");

        if ((retries == MAX_UNLIMITED_TASK_RETRIES) &&
            !(tt->flags & TASK_INIT_DONE)) 
                error(FATAL, 
	       "\ncannot gather a stable task list via pid_hash (%d retries)\n",
			retries);

        if (!readmem(pidhash_array, KVADDR, pid_hash, 
	    len * SIZE(hlist_head), "pid_hash contents", RETURN_ON_ERROR)) 
		error(FATAL, "\ncannot read pid_hash array\n");

        if (!hq_open()) {
                error(INFO, "cannot hash task_struct entries\n");
                if (!(tt->flags & TASK_INIT_DONE))
                        clean_exit(1);
                error(INFO, "using stale task_structs\n");
                FREEBUF(pid_hash);
                return;
        }

	/*
	 *  Get the idle threads first. 
	 */
	cnt = 0;
	for (i = 0; i < kt->cpus; i++) {
		if (!tt->idle_threads[i])
			continue;
		if (hq_enter(tt->idle_threads[i]))
			cnt++;
		else
			error(WARNING, "%sduplicate idle tasks?\n",
				DUMPFILE() ? "\n" : "");
	}

	for (i = 0; i < len; i++) {
		if (!pid_hash[i])
			continue;

		kpp = pid_hash[i];
		upid = pid_hash[i] - OFFSET(upid_pid_chain);
		chained = 0;
do_chained:
        	if (!readmem(upid, KVADDR, nodebuf, SIZE(upid), 
		    "pid_hash upid", RETURN_ON_ERROR|QUIET)) { 
			error(INFO, "\npid_hash[%d]: cannot read pid_hash upid\n", i);
                        if (DUMPFILE())
                                continue;
                        hq_close();
                        retries++;
                        goto retry_pid_hash;
		}

		pnext = ULONG(nodebuf + OFFSET(upid_pid_chain) + OFFSET(hlist_node_next));
		pprev = ULONG(nodebuf + OFFSET(upid_pid_chain) + OFFSET(hlist_node_pprev));
		upid_nr = UINT(nodebuf + OFFSET(upid_nr));
		upid_ns = ULONG(nodebuf + OFFSET(upid_ns));
		/*
		 *  Use init_pid_ns level 0 (PIDTYPE_PID).
		 */
		if (upid_ns != tt->init_pid_ns) {
			if (!accessible(upid_ns)) {
				error(INFO, 
				    "%spid_hash[%d]: invalid upid.ns: %lx\n",
					DUMPFILE() ? "\n" : "",
					i, upid_ns);
                             	continue;
			}
			goto chain_next;
		}

		pid = upid - OFFSET(pid_numbers);

		if (!readmem(pid + OFFSET(pid_tasks), KVADDR, &pid_tasks_0, 
		    sizeof(void *), "pid tasks", RETURN_ON_ERROR|QUIET)) {
                        error(INFO, "\npid_hash[%d]: cannot read pid.tasks[0]\n", i);
                        if (DUMPFILE())
                                continue;
                        hq_close();
                        retries++;
                        goto retry_pid_hash;
                }

		if (pid_tasks_0 == 0)
			goto chain_next;

		next = pid_tasks_0 - OFFSET(task_struct_pids);

		if (CRASHDEBUG(1)) {
			if (chained)
				console("                %lx upid: %lx nr: %d pid: %lx\n" 
				    "                pnext/pprev: %.*lx/%lx task: %lx\n",
				    kpp, upid, upid_nr, pid, VADDR_PRLEN, pnext, pprev, next);
			else
				console("pid_hash[%4d]: %lx upid: %lx nr: %d pid: %lx\n"
				    "                pnext/pprev: %.*lx/%lx task: %lx\n",
				    i, kpp, upid, upid_nr, pid, VADDR_PRLEN, pnext, pprev, next);
		}

		if (!IS_TASK_ADDR(next)) {
			error(INFO, "%spid_hash[%d]: invalid task address: %lx\n",
				DUMPFILE() ? "\n" : "", i, next);
			if (DUMPFILE())
				break;
 			hq_close();
 			retries++;
 			goto retry_pid_hash;
		}

		if (!is_idle_thread(next) && !hq_enter(next)) {
			error(INFO, "%spid_hash[%d]: duplicate task: %lx\n",
				DUMPFILE() ? "\n" : "", i, next);
			if (DUMPFILE())
				break;
			hq_close();
			retries++;
			goto retry_pid_hash;
		}

		cnt++;
chain_next:
		if (pnext) {
			if (chained >= tt->max_tasks) {
				error(INFO, 
				    "%spid_hash[%d]: corrupt/invalid upid chain\n",
					DUMPFILE() ? "\n" : "", i);
				continue;
			}
			kpp = pnext;
			upid = pnext - OFFSET(upid_pid_chain);
			chained++;
			goto do_chained;
		}
	}

        if (cnt > tt->max_tasks) {
                tt->max_tasks = cnt + TASK_SLUSH;
                allocate_task_space(tt->max_tasks);
                hq_close();
                if (!DUMPFILE())
                        retries++;
                goto retry_pid_hash;
        }

        BZERO(tt->task_local, tt->max_tasks * sizeof(void *));
        cnt = retrieve_list((ulong *)tt->task_local, cnt);

	hq_close();

	clear_task_cache();

        for (i = 0, tlp = (ulong *)tt->task_local, tt->running_tasks = 0;
             i < tt->max_tasks; i++, tlp++) {
		if (!(*tlp))
			continue;

		if (!IS_TASK_ADDR(*tlp)) {
			error(WARNING, 
		            "%sinvalid task address found in task list: %lx\n", 
				DUMPFILE() ? "\n" : "", *tlp);
			if (DUMPFILE()) 
				continue;
			retries++;
			goto retry_pid_hash;
		}	
	
		if (!(tp = fill_task_struct(*tlp))) {
                        if (DUMPFILE())
                                continue;
                        retries++;
                        goto retry_pid_hash;
                }

		add_context(*tlp, tp);
	}

        FREEBUF(pid_hash);
	FREEBUF(nodebuf);

	please_wait_done();

        if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) 
		refresh_context(curtask, curpid);

	tt->retries = MAX(tt->retries, retries);
}

/*
 *  Linux 4.15: pid_hash[] replaced by IDR/radix_tree
 */
static int
radix_tree_task_callback(ulong task)
{
	ulong *tlp;

	if (tt->callbacks < tt->max_tasks) {
		tlp = (ulong *)tt->task_local;
		tlp += tt->callbacks++;
		*tlp = task;
	}

	return TRUE;
}

static void
refresh_radix_tree_task_table(void)
{
	int i, cnt;
	ulong count, retries, next, curtask, curpid, upid_ns, pid_tasks_0, task;
	ulong *tlp;
	char *tp;
	struct list_pair rtp;
	char *pidbuf;

	if (DUMPFILE() && (tt->flags & TASK_INIT_DONE))   /* impossible */
		return;

	if (DUMPFILE()) {                                 /* impossible */
		please_wait("gathering task table data");
		if (!symbol_exists("panic_threads"))
			tt->flags |= POPULATE_PANIC;
	}

	if (ACTIVE() && !(tt->flags & TASK_REFRESH))
		return;

	curpid = NO_PID;
	curtask = NO_TASK;

	/*
	 *  The current task's task_context entry may change,
	 *  or the task may not even exist anymore.
	 */
	if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) {
		curtask = CURRENT_TASK();
		curpid = CURRENT_PID();
	}

	count = do_radix_tree(tt->pid_radix_tree, RADIX_TREE_COUNT, NULL);
	if (CRASHDEBUG(1))
		console("do_radix_tree: count: %ld\n", count);

	retries = 0;
	pidbuf = GETBUF(SIZE(pid));

retry_radix_tree:
	if (retries && DUMPFILE())
		error(FATAL,
			"\ncannot gather a stable task list via radix tree\n");

	if ((retries == MAX_UNLIMITED_TASK_RETRIES) &&
	    !(tt->flags & TASK_INIT_DONE))
		error(FATAL,
		    "\ncannot gather a stable task list via radix tree (%d retries)\n",
			retries);

	if (count > tt->max_tasks) {
		tt->max_tasks = count + TASK_SLUSH;
		allocate_task_space(tt->max_tasks);
	}

	BZERO(tt->task_local, tt->max_tasks * sizeof(void *));
	tt->callbacks = 0;
	rtp.index = 0;
	rtp.value = (void *)&radix_tree_task_callback;
	count = do_radix_tree(tt->pid_radix_tree, RADIX_TREE_DUMP_CB, &rtp);
	if (CRASHDEBUG(1))
		console("do_radix_tree: count: %ld  tt->callbacks: %d\n", count, tt->callbacks);

	if (count > tt->max_tasks) {
		retries++;
		goto retry_radix_tree;
	}

	if (!hq_open()) {
		error(INFO, "cannot hash task_struct entries\n");
		if (!(tt->flags & TASK_INIT_DONE))
			clean_exit(1);
		error(INFO, "using stale task_structs\n");
		return;
       }

	/*
	 *  Get the idle threads first.
	 */
	cnt = 0;
	for (i = 0; i < kt->cpus; i++) {
		if (!tt->idle_threads[i])
			continue;
		if (hq_enter(tt->idle_threads[i]))
			cnt++;
		else
			error(WARNING, "%sduplicate idle tasks?\n",
				DUMPFILE() ? "\n" : "");
	}

	for (i = 0; i < tt->max_tasks; i++) {
		tlp = (ulong *)tt->task_local;
		tlp += i;
		if ((next = *tlp) == 0)
			break;

		/*
		 *  Translate radix tree contents to PIDTYPE_PID task.
		 *  - the radix tree contents are struct pid pointers
		 *  - upid is contained in pid.numbers[0]
		 *  - upid.ns should point to init->init_pid_ns
		 *  - pid->tasks[0] is first hlist_node in task->pids[3]
		 *  - get task from address of task->pids[0]
		 */
		if (!readmem(next, KVADDR, pidbuf,
		    SIZE(pid), "pid", RETURN_ON_ERROR|QUIET)) {
			error(INFO, "\ncannot read pid struct from radix tree\n");
			if (DUMPFILE())
				continue;
			hq_close();
			retries++;
			goto retry_radix_tree;
		}

		upid_ns = ULONG(pidbuf + OFFSET(pid_numbers) + OFFSET(upid_ns));
		if (upid_ns != tt->init_pid_ns)
			continue;
		pid_tasks_0 = ULONG(pidbuf + OFFSET(pid_tasks));
		if (!pid_tasks_0)
			continue;
		if (VALID_MEMBER(task_struct_pids))
			task = pid_tasks_0 - OFFSET(task_struct_pids);
		else
			task = pid_tasks_0 - OFFSET(task_struct_pid_links);

		if (CRASHDEBUG(1))
			console("pid: %lx  ns: %lx  tasks[0]: %lx task: %lx\n",
				next, upid_ns, pid_tasks_0, task);

		if (is_idle_thread(task))
			continue;

		if (!IS_TASK_ADDR(task)) {
			error(INFO, "%s: IDR radix tree: invalid task address: %lx\n",
				DUMPFILE() ? "\n" : "", task);
			if (DUMPFILE())
				break;
			hq_close();
			retries++;
			goto retry_radix_tree;
		}

		if (!hq_enter(task)) {
			error(INFO, "%s: IDR radix tree: duplicate task: %lx\n",
				DUMPFILE() ? "\n" : "", task);
			if (DUMPFILE())
				break;
			hq_close();
			retries++;
			goto retry_radix_tree;
		}

		cnt++;
	}

	BZERO(tt->task_local, tt->max_tasks * sizeof(void *));
	cnt = retrieve_list((ulong *)tt->task_local, cnt);
	hq_close();

	clear_task_cache();

        for (i = 0, tlp = (ulong *)tt->task_local, tt->running_tasks = 0;
             i < tt->max_tasks; i++, tlp++) {
		if (!(*tlp))
			continue;

		if (!IS_TASK_ADDR(*tlp)) {
			error(WARNING,
		            "%sinvalid task address found in task list: %lx\n",
				DUMPFILE() ? "\n" : "", *tlp);
			if (DUMPFILE())
				continue;
			retries++;
			goto retry_radix_tree;
		}

		if (!(tp = fill_task_struct(*tlp))) {
			if (DUMPFILE())
				continue;
			retries++;
			goto retry_radix_tree;
		}

		add_context(*tlp, tp);
	}

	FREEBUF(pidbuf);

	please_wait_done();

	if (ACTIVE() && (tt->flags & TASK_INIT_DONE))
		refresh_context(curtask, curpid);

	tt->retries = MAX(tt->retries, retries);
}


/*
 *  Linux 4.20: pid_hash[] IDR changed from radix tree to xarray
 */
static int
xarray_task_callback(ulong task)
{
	ulong *tlp;

	if (tt->callbacks < tt->max_tasks) {
		tlp = (ulong *)tt->task_local;
		tlp += tt->callbacks++;
		*tlp = task;
	}

	return TRUE;
}

static void
refresh_xarray_task_table(void)
{
	int i, cnt;
	ulong count, retries, next, curtask, curpid, upid_ns, pid_tasks_0, task;
	ulong *tlp;
	char *tp;
	struct list_pair xp;
	char *pidbuf;
	long pid_size = SIZE(pid);

	if (DUMPFILE() && (tt->flags & TASK_INIT_DONE))   /* impossible */
		return;

	if (DUMPFILE()) {                                 /* impossible */
		please_wait("gathering task table data");
		if (!symbol_exists("panic_threads"))
			tt->flags |= POPULATE_PANIC;
	}

	if (ACTIVE() && !(tt->flags & TASK_REFRESH))
		return;

	curpid = NO_PID;
	curtask = NO_TASK;

	/*
	 *  The current task's task_context entry may change,
	 *  or the task may not even exist anymore.
	 */
	if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) {
		curtask = CURRENT_TASK();
		curpid = CURRENT_PID();
	}

	count = do_xarray(tt->pid_xarray, XARRAY_COUNT, NULL);
	if (CRASHDEBUG(1))
		console("xarray: count: %ld\n", count);

	/* 6.5: b69f0aeb0689 changed pid.numbers[1] to numbers[] */
	if (ARRAY_LENGTH(pid_numbers) == 0)
		pid_size += SIZE(upid);

	retries = 0;
	pidbuf = GETBUF(pid_size);

retry_xarray:
	if (retries && DUMPFILE())
		error(FATAL,
			"\ncannot gather a stable task list via xarray\n");

	if ((retries == MAX_UNLIMITED_TASK_RETRIES) &&
	    !(tt->flags & TASK_INIT_DONE))
		error(FATAL,
		    "\ncannot gather a stable task list via xarray (%d retries)\n",
			retries);

	if (count > tt->max_tasks) {
		tt->max_tasks = count + TASK_SLUSH;
		allocate_task_space(tt->max_tasks);
	}

	BZERO(tt->task_local, tt->max_tasks * sizeof(void *));
	tt->callbacks = 0;
	xp.index = 0;
	xp.value = (void *)&xarray_task_callback;
	count = do_xarray(tt->pid_xarray, XARRAY_DUMP_CB, &xp);
	if (CRASHDEBUG(1))
		console("do_xarray: count: %ld  tt->callbacks: %d\n", count, tt->callbacks);

	if (count > tt->max_tasks) {
		retries++;
		goto retry_xarray;
	}

	if (!hq_open()) {
		error(INFO, "cannot hash task_struct entries\n");
		if (!(tt->flags & TASK_INIT_DONE))
			clean_exit(1);
		error(INFO, "using stale task_structs\n");
		return;
       }

	/*
	 *  Get the idle threads first.
	 */
	cnt = 0;
	for (i = 0; i < kt->cpus; i++) {
		if (!tt->idle_threads[i])
			continue;
		if (hq_enter(tt->idle_threads[i]))
			cnt++;
		else
			error(WARNING, "%sduplicate idle tasks?\n",
				DUMPFILE() ? "\n" : "");
	}

	for (i = 0; i < tt->max_tasks; i++) {
		tlp = (ulong *)tt->task_local;
		tlp += i;
		if ((next = *tlp) == 0)
			break;

		/*
		 *  Translate xarray contents to PIDTYPE_PID task.
		 *  - the xarray contents are struct pid pointers
		 *  - upid is contained in pid.numbers[0]
		 *  - upid.ns should point to init->init_pid_ns
		 *  - pid->tasks[0] is first hlist_node in task->pids[3]
		 *  - get task from address of task->pids[0]
		 */
		if (!readmem(next, KVADDR, pidbuf,
		    pid_size, "pid", RETURN_ON_ERROR|QUIET)) {
			error(INFO, "\ncannot read pid struct from xarray\n");
			if (DUMPFILE())
				continue;
			hq_close();
			retries++;
			goto retry_xarray;
		}

		upid_ns = ULONG(pidbuf + OFFSET(pid_numbers) + OFFSET(upid_ns));
		if (upid_ns != tt->init_pid_ns)
			continue;
		pid_tasks_0 = ULONG(pidbuf + OFFSET(pid_tasks));
		if (!pid_tasks_0)
			continue;
		if (VALID_MEMBER(task_struct_pids))
			task = pid_tasks_0 - OFFSET(task_struct_pids);
		else
			task = pid_tasks_0 - OFFSET(task_struct_pid_links);

		if (CRASHDEBUG(1))
			console("pid: %lx  ns: %lx  tasks[0]: %lx task: %lx\n",
				next, upid_ns, pid_tasks_0, task);

		if (is_idle_thread(task))
			continue;

		if (!IS_TASK_ADDR(task)) {
			error(INFO, "%s: IDR xarray: invalid task address: %lx\n",
				DUMPFILE() ? "\n" : "", task);
			if (DUMPFILE())
				break;
			hq_close();
			retries++;
			goto retry_xarray;
		}

		if (!hq_enter(task)) {
			error(INFO, "%s: IDR xarray: duplicate task: %lx\n",
				DUMPFILE() ? "\n" : "", task);
			if (DUMPFILE())
				break;
			hq_close();
			retries++;
			goto retry_xarray;
		}

		cnt++;
	}

	BZERO(tt->task_local, tt->max_tasks * sizeof(void *));
	cnt = retrieve_list((ulong *)tt->task_local, cnt);
	hq_close();

	clear_task_cache();

        for (i = 0, tlp = (ulong *)tt->task_local, tt->running_tasks = 0;
             i < tt->max_tasks; i++, tlp++) {
		if (!(*tlp))
			continue;

		if (!IS_TASK_ADDR(*tlp)) {
			error(WARNING,
		            "%sinvalid task address found in task list: %lx\n",
				DUMPFILE() ? "\n" : "", *tlp);
			if (DUMPFILE())
				continue;
			retries++;
			goto retry_xarray;
		}

		if (!(tp = fill_task_struct(*tlp))) {
			if (DUMPFILE())
				continue;
			retries++;
			goto retry_xarray;
		}

		add_context(*tlp, tp);
	}

	FREEBUF(pidbuf);

	please_wait_done();

	if (ACTIVE() && (tt->flags & TASK_INIT_DONE))
		refresh_context(curtask, curpid);

	tt->retries = MAX(tt->retries, retries);
}

static void
refresh_active_task_table(void)
{
	int i;
	char *tp; 
	int cnt;
        ulong curtask;
        ulong curpid;
        ulong retries;
	ulong *tlp;

        if (DUMPFILE() && (tt->flags & TASK_INIT_DONE))   /* impossible */
                return;

        if (DUMPFILE()) { 
		please_wait("gathering task table data");
                if (!symbol_exists("panic_threads"))
                        tt->flags |= POPULATE_PANIC;
        }

        if (ACTIVE() && !(tt->flags & TASK_REFRESH))
                return;

	curtask = NO_TASK;
	curpid = NO_PID;
	retries = 0; 

	get_active_set();
       	/*
       	 *  The current task's task_context entry may change,
         *  or the task may not even exist anymore.
         */
       	if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) {
               	curtask = CURRENT_TASK();
               	curpid = CURRENT_PID();
       	}

retry_active:

        if (!hq_open()) {
                error(INFO, "cannot hash task_struct entries\n");
                if (!(tt->flags & TASK_INIT_DONE))
                        clean_exit(1);
                error(INFO, "using stale task_structs\n");
                return;
        }

	/*
	 *  Get the active tasks. 
	 */
	cnt = 0;
	for (i = 0; i < kt->cpus; i++) {
		if (hq_enter(tt->active_set[i]))
			cnt++;
		else
			error(WARNING, "%sduplicate active tasks?\n",
				DUMPFILE() ? "\n" : "");
	}

        BZERO(tt->task_local, tt->max_tasks * sizeof(void *));
        cnt = retrieve_list((ulong *)tt->task_local, cnt);

	hq_close();

	clear_task_cache();

        for (i = 0, tlp = (ulong *)tt->task_local, tt->running_tasks = 0;
             i < tt->max_tasks; i++, tlp++) {
		if (!(*tlp))
			continue;

		if (!IS_TASK_ADDR(*tlp)) {
			error(WARNING, 
		            "%sinvalid task address found in task list: %lx\n", 
				DUMPFILE() ? "\n" : "", *tlp);
			if (DUMPFILE()) 
				continue;
			retries++;
			goto retry_active;
		}	
	
		if (!(tp = fill_task_struct(*tlp))) {
                        if (DUMPFILE())
                                continue;
                        retries++;
                        goto retry_active;
                }

		if (!add_context(*tlp, tp) && DUMPFILE())
			error(WARNING, "corrupt/invalid active task: %lx\n",
				*tlp);
	}

	if (!tt->running_tasks) {
		if (DUMPFILE())
			error(FATAL, "cannot determine any active tasks!\n");
		retries++;
		goto retry_active;
	}

	please_wait_done();

        if (ACTIVE() && (tt->flags & TASK_INIT_DONE))
		refresh_context(curtask, curpid);

	tt->retries = MAX(tt->retries, retries);
}

/*
 *  Initialize and return a new task_context structure with data from a task.
 *  NULL is returned on error.
 */
static struct task_context *
add_context(ulong task, char *tp)
{
        pid_t *pid_addr, *tgid_addr;
        char *comm_addr;
        int *processor_addr;
        ulong *parent_addr;
        ulong *mm_addr;
        int has_cpu;
	int do_verify;
	struct task_context *tc;
	struct tgid_context *tg;

	processor_addr = NULL;

	if (tt->refresh_task_table == refresh_fixed_task_table)
		do_verify = 1;
	else if (tt->refresh_task_table == refresh_pid_hash_task_table)
		do_verify = 2;
	else if (tt->refresh_task_table == refresh_hlist_task_table)
		do_verify = 2;
	else if (tt->refresh_task_table == refresh_hlist_task_table_v2)
		do_verify = 2;
	else if (tt->refresh_task_table == refresh_hlist_task_table_v3)
		do_verify = 2;
	else if (tt->refresh_task_table == refresh_active_task_table)
		do_verify = 2;
	else
		do_verify = 0;

	tc = tt->context_array + tt->running_tasks;

        pid_addr = (pid_t *)(tp + OFFSET(task_struct_pid));
	tgid_addr = (pid_t *)(tp + OFFSET(task_struct_tgid));
        comm_addr = (char *)(tp + OFFSET(task_struct_comm));
	if (tt->flags & THREAD_INFO) {
		if (tt->flags & THREAD_INFO_IN_TASK) 
			tc->thread_info = task + OFFSET(task_struct_thread_info);
		else
			tc->thread_info = ULONG(tp + OFFSET(task_struct_thread_info));
		fill_thread_info(tc->thread_info);
		if (tt->flags & THREAD_INFO_IN_TASK && VALID_MEMBER(task_struct_cpu))
                	processor_addr = (int *) (tp + OFFSET(task_struct_cpu));
		else
			processor_addr = (int *) (tt->thread_info + 
				OFFSET(thread_info_cpu));
	} else if (VALID_MEMBER(task_struct_processor))
                processor_addr = (int *) (tp + OFFSET(task_struct_processor));
        else if (VALID_MEMBER(task_struct_cpu))
                processor_addr = (int *) (tp + OFFSET(task_struct_cpu));
	if (VALID_MEMBER(task_struct_p_pptr))
        	parent_addr = (ulong *)(tp + OFFSET(task_struct_p_pptr));
	else
        	parent_addr = (ulong *)(tp + OFFSET(task_struct_parent));
        mm_addr = (ulong *)(tp + OFFSET(task_struct_mm));
        has_cpu = task_has_cpu(task, tp);

        tc->pid = (ulong)(*pid_addr);
	strlcpy(tc->comm, comm_addr, TASK_COMM_LEN); 
	if (machine_type("SPARC64"))
		tc->processor = *(unsigned short *)processor_addr;
	else
		tc->processor = *processor_addr;
        tc->ptask = *parent_addr;
        tc->mm_struct = *mm_addr;
        tc->task = task;
        tc->tc_next = NULL;

	/*
	 *  Fill a tgid_context structure with the data from 
	 *  the incoming task.
	 */
	tg = tt->tgid_array + tt->running_tasks;
	tg->tgid = *tgid_addr;
	tg->task = task;
	tg->rss_cache = UNINITIALIZED;

        if (do_verify && !verify_task(tc, do_verify)) {
		error(INFO, "invalid task address: %lx\n", tc->task);
                BZERO(tc, sizeof(struct task_context));
                return NULL;
        }

        if (has_cpu && (tt->flags & POPULATE_PANIC))
                tt->panic_threads[tc->processor] = tc->task;

	tt->flags &= ~INDEXED_CONTEXTS;
	tt->running_tasks++;
	return tc;
}

/*
 *  The current context may have moved to a new spot in the task table
 *  or have exited since the last command.  If it still exists, reset its
 *  new position.  If it doesn't exist, set the context back to the initial
 *  crash context.  If necessary, complain and show the restored context.
 */
static void
refresh_context(ulong curtask, ulong curpid)
{
	ulong value, complain;
	struct task_context *tc;

	if (task_exists(curtask) && pid_exists(curpid)) {
                set_context(curtask, NO_PID);
        } else {
                set_context(tt->this_task, NO_PID);

                complain = TRUE;
                if (STREQ(args[0], "set") && (argcnt == 2) &&
                    IS_A_NUMBER(args[1])) {

	                switch (str_to_context(args[optind], &value, &tc))
	                {
	                case STR_PID:
	                case STR_TASK:
				complain = FALSE;
	                        break;
	                case STR_INVALID:
				complain = TRUE;
	                        break;
	                }
                }

                if (complain) {
                        error(INFO, "current context no longer exists -- "
                                    "restoring \"%s\" context:\n\n",
                        	pc->program_name);
                        show_context(CURRENT_CONTEXT());
			fprintf(fp, "\n");
                }
        }
}

static int
sort_by_task(const void *arg1, const void *arg2)
{
	const struct task_context *t1, *t2;

	t1 = *(const struct task_context **)arg1;
	t2 = *(const struct task_context **)arg2;

	if (t1->task == t2->task)
		return 0;

	return (t1->task < t2->task) ? -1 : 1;
}

/* sort context_by_task by task address */
static void
sort_context_by_task(void)
{
	int i;

	for (i = 0; i < tt->running_tasks; i++)
		tt->context_by_task[i] = &tt->context_array[i];
	qsort(tt->context_by_task, tt->running_tasks,
	      sizeof(*tt->context_by_task), sort_by_task);
	tt->flags |= INDEXED_CONTEXTS;
}

/*
 *  Sort the task_context array by PID number; for PID 0, sort by processor.
 */
void
sort_context_array(void)
{
        ulong curtask;

	curtask = CURRENT_TASK();
	qsort((void *)tt->context_array, (size_t)tt->running_tasks,
        	sizeof(struct task_context), sort_by_pid);
	set_context(curtask, NO_PID);

	sort_context_by_task();
}

static int
sort_by_pid(const void *arg1, const void *arg2)
{
	struct task_context *t1, *t2;

	t1 = (struct task_context *)arg1;
	t2 = (struct task_context *)arg2;

        if ((t1->pid == 0) && (t2->pid == 0))
                return (t1->processor < t2->processor ? -1 :
                        t1->processor == t2->processor ? 0 : 1);
        else
                return (t1->pid < t2->pid ? -1 :
                        t1->pid == t2->pid ? 0 : 1);
}


static int
sort_by_last_run(const void *arg1, const void *arg2)
{
	ulong task_last_run_stamp(ulong);
	struct task_context *t1, *t2;
	ulonglong lr1, lr2;

	t1 = (struct task_context *)arg1;
	t2 = (struct task_context *)arg2;

	lr1 = task_last_run(t1->task);
	lr2 = task_last_run(t2->task);
	
        return (lr2 < lr1 ? -1 :
        	lr2 == lr1 ? 0 : 1);
}

static void
sort_context_array_by_last_run(void)
{
        ulong curtask;

	curtask = CURRENT_TASK();
	qsort((void *)tt->context_array, (size_t)tt->running_tasks,
        	sizeof(struct task_context), sort_by_last_run);
	set_context(curtask, NO_PID);

	sort_context_by_task();
}

/*
 *  Set the tgid_context array by tgid number.
 */
void
sort_tgid_array(void)
{
	if (VALID_MEMBER(mm_struct_rss) || (!VALID_MEMBER(task_struct_rss_stat)))
		return;

	qsort((void *)tt->tgid_array, (size_t)tt->running_tasks,
		sizeof(struct tgid_context), sort_by_tgid);

	tt->last_tgid = tt->tgid_array;
}

int
sort_by_tgid(const void *arg1, const void *arg2)
{
	struct tgid_context *t1, *t2;

	t1 = (struct tgid_context *)arg1;
	t2 = (struct tgid_context *)arg2;

	return (t1->tgid < t2->tgid ? -1 :
		t1->tgid == t2->tgid ? 0 : 1);
}

/*
 *  Keep a stash of the last task_struct accessed.  Chances are it will
 *  be hit several times before the next task is accessed.
 */

char *
fill_task_struct(ulong task)
{
	if (XEN_HYPER_MODE())
		return NULL;

	if (!IS_LAST_TASK_READ(task)) { 
        	if (!readmem(task, KVADDR, tt->task_struct, 
	     		SIZE(task_struct), "fill_task_struct", 
	     		ACTIVE() ? (RETURN_ON_ERROR|QUIET) : RETURN_ON_ERROR)) {
			tt->last_task_read = 0;
			return NULL;
		}
	}

	tt->last_task_read = task;
	return(tt->task_struct);
}

/*
 *  Keep a stash of the last thread_info struct accessed.  Chances are it will
 *  be hit several times before the next task is accessed.
 */

char *
fill_thread_info(ulong thread_info)
{
        if (!IS_LAST_THREAD_INFO_READ(thread_info)) {
                if (!readmem(thread_info, KVADDR, tt->thread_info,
                        SIZE(thread_info), "fill_thread_info",
                        ACTIVE() ? (RETURN_ON_ERROR|QUIET) : RETURN_ON_ERROR)) {
                        tt->last_thread_info_read = 0;
                        return NULL;
                }
        }

        tt->last_thread_info_read = thread_info;
        return(tt->thread_info);
}
/*
 *  Used by back_trace(), copy the complete kernel stack into a local buffer
 *  and fill the task_struct buffer, dealing with possible future separation
 *  of task_struct and stack and/or cache coloring of stack top.
 */
void
fill_stackbuf(struct bt_info *bt)
{
	if (!bt->stackbuf) {
		bt->stackbuf = GETBUF(bt->stacktop - bt->stackbase);

        	if (!readmem(bt->stackbase, KVADDR, bt->stackbuf, 
	    	    bt->stacktop - bt->stackbase, 
		    "stack contents", RETURN_ON_ERROR))
                	error(FATAL, "read of stack at %lx failed\n", 
				bt->stackbase);
	} 

	if (XEN_HYPER_MODE())
		return;

	if (!IS_LAST_TASK_READ(bt->task)) {
		if (bt->stackbase == bt->task) {
			BCOPY(bt->stackbuf, tt->task_struct, SIZE(task_struct));
			tt->last_task_read = bt->task;
		} else
			fill_task_struct(bt->task);
	}
}

/*
 *  Keeping the task_struct info intact, alter the contents of the already
 *  allocated local copy of a kernel stack, for things like IRQ stacks or
 *  non-standard eframe searches.  The caller must change the stackbase
 *  and stacktop values.
 */
void
alter_stackbuf(struct bt_info *bt)
{
	if (!readmem(bt->stackbase, KVADDR, bt->stackbuf,
       	    bt->stacktop - bt->stackbase, "stack contents", RETURN_ON_ERROR))
        	error(FATAL, "read of stack at %lx failed\n", bt->stackbase);
}

/*
 *  In the same vein as fill_task_struct(), keep a stash of the mm_struct
 *  of a task.
 */

char *fill_mm_struct(ulong mm)
{
	if (!IS_LAST_MM_READ(mm)) {
        	if (!readmem(mm, KVADDR, tt->mm_struct,
             		SIZE(mm_struct), "fill_mm_struct",
             		ACTIVE() ? (RETURN_ON_ERROR|QUIET) : RETURN_ON_ERROR)) {
                	tt->last_mm_read = 0;
                	return NULL;
        	}
	}

        tt->last_mm_read = mm;
        return(tt->mm_struct);
}

/*
 *  If active, clear out references to the last task and mm_struct read.
 */
void
clear_task_cache(void)
{
        if (ACTIVE())
                tt->last_task_read = tt->last_mm_read = 0;
}

/*
 *  Shorthand command to dump the current context's task_struct, or if
 *  pid or task arguments are entered, the task_structs of the targets.
 *  References to structure members can be given to pare down the output,
 *  which are put in a comma-separated list.
 */
void
cmd_task(void)
{
	int c, tcnt, bogus;
	unsigned int radix;
	ulong value;
	struct reference *ref;
	struct task_context *tc;
	ulong *tasklist;
	char *memberlist;

	tasklist = (ulong *)GETBUF((MAXARGS+NR_CPUS)*sizeof(ulong));
	ref = (struct reference *)GETBUF(sizeof(struct reference));
	memberlist = GETBUF(BUFSIZE);
	ref->str = memberlist;
	radix = 0;

        while ((c = getopt(argcnt, args, "xdhR:")) != EOF) {
                switch(c)
		{
		case 'h':
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

		case 'R':
			if (strlen(ref->str))
				strcat(ref->str, ",");
			strcat(ref->str, optarg);
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	tcnt = bogus = 0;

        while (args[optind]) {
		if (IS_A_NUMBER(args[optind])) {
	                switch (str_to_context(args[optind], &value, &tc))
	                {
	                case STR_PID:
                                for (tc = pid_to_context(value); tc;
                                     tc = tc->tc_next)
                                        tasklist[tcnt++] = tc->task;
	                        break;
	
	                case STR_TASK:
				tasklist[tcnt++] = value;	
	                        break;
	
	                case STR_INVALID:
				bogus++;
	                        error(INFO, "invalid task or pid value: %s\n\n",
	                                args[optind]);
	                        break;
	                }
		} else if (strstr(args[optind], ",") ||
			MEMBER_EXISTS("task_struct", args[optind])) {
			if (strlen(ref->str))
				strcat(ref->str, ",");
			strcat(ref->str, args[optind]);
		} else if (strstr(args[optind], ".") || strstr(args[optind], "[")) {
			if (strlen(ref->str))
				strcat(ref->str, ",");
			strcat(ref->str, args[optind]);
		} else
                        error(INFO, 
			    "invalid task, pid, or task_struct member: %s\n\n",
                                args[optind]);
                optind++;
        }

	if (!tcnt && !bogus)
		tasklist[tcnt++] = CURRENT_TASK();

	for (c = 0; c < tcnt; c++) 
		do_task(tasklist[c], 0, strlen(ref->str) ? ref : NULL, radix);

}

/*
 *  Do the work for the task command.
 */
void
do_task(ulong task, ulong flags, struct reference *ref, unsigned int radix)
{
	struct task_context *tc;

	tc = task_to_context(task);

	if (ref) {
		print_task_header(fp, tc, 0);
		task_struct_member(tc, radix, ref);
	} else { 
		if (!(flags & FOREACH_TASK))
			print_task_header(fp, tc, 0);
		dump_struct("task_struct", task, radix);
		if (tt->flags & THREAD_INFO) {
			fprintf(fp, "\n");
			dump_struct("thread_info", tc->thread_info, radix);
		}
	}

	fprintf(fp, "\n");
}

/*
 *  Search the task_struct for the referenced field.
 */
static void
task_struct_member(struct task_context *tc, unsigned int radix, struct reference *ref)
{
	int i;
	int argcnt;
	char *arglist[MAXARGS];
	char *refcopy;
	struct datatype_member dm;

	if ((count_chars(ref->str, ',')+1) > MAXARGS) {
		error(INFO, 
		    	"too many -R arguments in comma-separated list!\n");
		return;
	}

	refcopy = GETBUF(strlen(ref->str)+1);
	strcpy(refcopy, ref->str);
	replace_string(refcopy, ",", ' ');

	argcnt = parse_line(refcopy, arglist);

        open_tmpfile();
        dump_struct("task_struct", tc->task, radix);
	if (tt->flags & THREAD_INFO)
		dump_struct("thread_info", tc->thread_info, radix);

	for (i = 0; i < argcnt; i++) {
		if (count_chars(arglist[i], '.') || count_chars(arglist[i], '[')) {
			dm.member = arglist[i];
			parse_for_member_extended(&dm, 0);
		} else {
			if (!MEMBER_EXISTS("task_struct", arglist[i]) &&
				!MEMBER_EXISTS("thread_info", arglist[i]))
				error(INFO, "%s: not a task_struct or "
					"thread_info member\n", arglist[i]);

			parse_task_thread(1, &arglist[i], tc);
		}
	}

	close_tmpfile();

	FREEBUF(refcopy);

}

static void 
parse_task_thread(int argcnt, char *arglist[], struct task_context *tc) {
	char buf[BUFSIZE];
	char lookfor1[BUFSIZE];
	char lookfor2[BUFSIZE];
	char lookfor3[BUFSIZE];
	int i, cnt, randomized;

        rewind(pc->tmpfile);

	BZERO(lookfor1, BUFSIZE);
	BZERO(lookfor2, BUFSIZE);
	BZERO(lookfor3, BUFSIZE);
	randomized = FALSE;

        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
		if (STREQ(buf, "  {\n"))
			randomized = TRUE;
		else if (randomized &&
			 (STREQ(buf, "  }, \n") || STREQ(buf, "  },\n")))
			randomized = FALSE;

		if (strlen(lookfor2)) {
			fprintf(pc->saved_fp, "%s", buf);
			if (STRNEQ(buf, lookfor2))
				BZERO(lookfor2, BUFSIZE);
			continue;
		}

		if (strlen(lookfor3)) {
			fprintf(pc->saved_fp, "%s", buf);
			if (strstr(buf, lookfor3))
				BZERO(lookfor3, BUFSIZE);
			continue;
		}

		for (i = 0; i < argcnt; i++) {
			BZERO(lookfor1, BUFSIZE);
			BZERO(lookfor2, BUFSIZE);
			BZERO(lookfor3, BUFSIZE);
			sprintf(lookfor1, "%s  %s = ", 
				randomized ? "  " : "", arglist[i]);
			if (STRNEQ(buf, lookfor1)) {
				fprintf(pc->saved_fp, "%s", buf);
				if (strstr(buf, "{{\n")) 
					sprintf(lookfor2, "%s    }},", 
						randomized ? "  " : "");
				else if (strstr(buf, " = {\n")) { 
					cnt = count_leading_spaces(buf);
					sprintf(lookfor2, "%s}", space(cnt));
				} else if (strstr(buf, "{"))
					sprintf(lookfor3, "},");
				break;
			}
		}
	}
}

static char *ps_exclusive = 
    "-a, -t, -c, -p, -g, -l, -m, -S, -r and -A flags are all mutually-exclusive\n";

static void
check_ps_exclusive(ulong flag, ulong thisflag)
{
	if (flag & (PS_EXCLUSIVE & ~thisflag))
		error(FATAL, ps_exclusive);
} 

/*
 *  Display ps-like data for all tasks, or as specified by pid, task, or
 *  command-name arguments.
 */
void
cmd_ps(void)
{
	int c, ac;
	ulong flag;
	ulong value;
	static struct psinfo psinfo;
	struct task_context *tc;
	char *cpuspec, *p;

	BZERO(&psinfo, sizeof(struct psinfo));
	cpuspec = NULL;
	flag = 0;

        while ((c = getopt(argcnt, args, "HASgstcpkuGlmarC:y:")) != EOF) {
                switch(c)
		{
		case 'k':
			if (flag & PS_USER)
                               error(FATAL,
                                   "-u and -k are mutually exclusive\n");
			flag |= PS_KERNEL;
			break;

		case 'u':
			if (flag & PS_KERNEL)
                               error(FATAL,
                                   "-u and -k are mutually exclusive\n");
			flag |= PS_USER;
			break;

		case 'G':
			if (flag & PS_GROUP) 
				break;
			else if (hq_open())
				flag |= PS_GROUP;
			else
				error(INFO, "cannot hash thread group tasks\n");
			break;
		/*
		 *  The a, t, c, p, g, l and r flags are all mutually-exclusive.
		 */
		case 'g':
			check_ps_exclusive(flag, PS_TGID_LIST);
			flag |= PS_TGID_LIST;
			break;

		case 'a':
			check_ps_exclusive(flag, PS_ARGV_ENVP);
			flag |= PS_ARGV_ENVP;
			break;

		case 't':
			check_ps_exclusive(flag, PS_TIMES);
			flag |= PS_TIMES;
			break;

		case 'c': 
			check_ps_exclusive(flag, PS_CHILD_LIST);
			flag |= PS_CHILD_LIST;
			break;

		case 'p':
			check_ps_exclusive(flag, PS_PPID_LIST);
			flag |= PS_PPID_LIST;
			break;

		case 'm':
			if (INVALID_MEMBER(task_struct_last_run) &&
			    INVALID_MEMBER(task_struct_timestamp) &&
			    INVALID_MEMBER(sched_info_last_arrival)) {
				error(INFO, 
                            "last-run timestamps do not exist in this kernel\n");
				argerrs++;
				break;
			}
			if (INVALID_MEMBER(rq_timestamp))
				option_not_supported(c);
			check_ps_exclusive(flag, PS_MSECS);
			flag |= PS_MSECS;
			break;
			
		case 'l':
			if (INVALID_MEMBER(task_struct_last_run) &&
			    INVALID_MEMBER(task_struct_timestamp) &&
			    INVALID_MEMBER(sched_info_last_arrival)) {
				error(INFO, 
                            "last-run timestamps do not exist in this kernel\n");
				argerrs++;
				break;
			}
			check_ps_exclusive(flag, PS_LAST_RUN);
			flag |= PS_LAST_RUN;
			break;

		case 's':
			flag |= PS_KSTACKP;
			break;

		case 'r':
			check_ps_exclusive(flag, PS_RLIMIT);
			flag |= PS_RLIMIT;
			break;

		case 'S':
			check_ps_exclusive(flag, PS_SUMMARY);
			flag |= PS_SUMMARY;
			break;

		case 'C':
			cpuspec = optarg;
			psinfo.cpus = get_cpumask_buf();
			make_cpumask(cpuspec, psinfo.cpus, FAULT_ON_ERROR, NULL);
			break;

		case 'y':
			flag |= PS_POLICY;
			psinfo.policy = make_sched_policy(optarg);
			break;

		case 'A':
			check_ps_exclusive(flag, PS_ACTIVE);
			flag |= PS_ACTIVE;
			break;

		case 'H':
			flag |= PS_NO_HEADER;
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (flag & (PS_LAST_RUN|PS_MSECS))
		sort_context_array_by_last_run();
	else if (psinfo.cpus) {
		error(INFO, "-C option is only applicable with -l and -m\n");
		goto bailout;
	}
	
	if (!args[optind]) {
		show_ps(PS_SHOW_ALL|flag, &psinfo);
		return;
	}

	if (flag & PS_SUMMARY)
		error(FATAL, "-S option takes no arguments\n");

	if (psinfo.cpus)
		error(INFO, 
			"-C option is not applicable with specified tasks\n");
	ac = 0;
	while (args[optind]) {
		if (IS_A_NUMBER(args[optind])) {
	                switch (str_to_context(args[optind], &value, &tc))
	                {
	                case STR_PID:
                                psinfo.pid[ac] = value;
                                psinfo.task[ac] = NO_TASK;
                                psinfo.type[ac] = PS_BY_PID;
                                flag |= PS_BY_PID;
	                        break;
	
	                case STR_TASK:
                                psinfo.task[ac] = value;
                                psinfo.pid[ac] = NO_PID;
                                psinfo.type[ac] = PS_BY_TASK;
                                flag |= PS_BY_TASK;
	                        break;
	
	                case STR_INVALID:
	                        error(INFO, "invalid task or pid value: %s\n\n",
	                                args[optind]);
	                        break;
	                }
			ac++;
		} else if (SINGLE_QUOTED_STRING(args[optind])) {
			/*
		 	 *  Regular expression is exclosed within "'" character.
		 	 *  The args[optind] string may not be modified, so a copy 
		 	 *  is duplicated.
		 	 */
			if (psinfo.regexs == MAX_PS_ARGS)
				error(INFO, "too many expressions specified!\n");
			else {
				p = strdup(&args[optind][1]);
				LASTCHAR(p) = NULLCHAR;
				
				if (regcomp(&psinfo.regex_data[psinfo.regexs].regex,
				    p, REG_EXTENDED|REG_NOSUB)) {
					error(INFO, 
					    "invalid regular expression: %s\n", p);
					free(p);
					goto bailout;
				}

				psinfo.regex_data[psinfo.regexs].pattern = p;
				if (psinfo.regexs++ == 0) {
					pc->cmd_cleanup_arg = (void *)&psinfo;
					pc->cmd_cleanup = ps_cleanup;
				}
				psinfo.type[ac] = PS_BY_REGEX;
				flag |= PS_BY_REGEX;
				ac++;
			}
			optind++;
			continue;
		} else {
			psinfo.pid[ac] = NO_PID;
			psinfo.task[ac] = NO_TASK;
			p = args[optind][0] == '\\' ? 
				&args[optind][1] : args[optind];
			strlcpy(psinfo.comm[ac], p, TASK_COMM_LEN);
			psinfo.type[ac] = PS_BY_CMD;
			flag |= PS_BY_CMD;
			ac++;
		}
		optind++;
	}

	psinfo.argc = ac;
	show_ps(flag, &psinfo);

bailout:
	ps_cleanup((void *)&psinfo);
}

/*
 *  Clean up regex buffers and pattern strings.
 */
static void 
ps_cleanup(void *arg)
{
	int i;
	struct psinfo *ps;

	pc->cmd_cleanup = NULL;
	pc->cmd_cleanup_arg = NULL;

	ps = (struct psinfo *)arg;

	for (i = 0; i < ps->regexs; i++) {
		regfree(&ps->regex_data[i].regex);
		free(ps->regex_data[i].pattern);
	}

	if (ps->cpus)
		FREEBUF(ps->cpus);
}

/*
 *  Do the work requested by cmd_ps().
 */
static void 
show_ps_data(ulong flag, struct task_context *tc, struct psinfo *psi)
{
	struct task_mem_usage task_mem_usage, *tm;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	ulong tgid;
	int task_active;

	if ((flag & PS_USER) && is_kernel_thread(tc->task))
		return;
	if ((flag & PS_KERNEL) && !is_kernel_thread(tc->task))
		return;
	if ((flag & PS_POLICY) && !has_sched_policy(tc->task, psi->policy))
		return;
	if (flag & PS_GROUP) {
		if (flag & (PS_LAST_RUN|PS_MSECS))
			error(FATAL, "-G not supported with -%c option\n",
				flag & PS_LAST_RUN ? 'l' : 'm');

		tgid = task_tgid(tc->task);
		if (tc->pid != tgid) {
			if (pc->curcmd_flags & TASK_SPECIFIED) {
				if (!(tc = tgid_to_context(tgid)))
					return;
				if (hq_entry_exists((ulong)tc))
					return;
				hq_enter((ulong)tc);
			} else
				return;
		} else {
			if (hq_entry_exists((ulong)tc))
				return;
			hq_enter((ulong)tc);
		}
	}

	if (flag & PS_PPID_LIST) {
		parent_list(tc->task);
		fprintf(fp, "\n");
		return;
	}
	if (flag & PS_CHILD_LIST) {
		child_list(tc->task);
		fprintf(fp, "\n");
		return;
	}
	if (flag & (PS_LAST_RUN)) {
		show_last_run(tc, psi);
		return;
	}
	if (flag & (PS_MSECS)) {
		show_milliseconds(tc, psi);
		return;
	}
	if (flag & PS_ARGV_ENVP) {
		show_task_args(tc);
		return;
	}
	if (flag & PS_RLIMIT) {
		show_task_rlimit(tc);
		return;
	}
	if (flag & PS_TGID_LIST) {
		show_tgid_list(tc->task);
		return;
	}

	tm = &task_mem_usage;
	get_task_mem_usage(tc->task, tm);

	task_active = is_task_active(tc->task);

	if ((flag & PS_ACTIVE) && (flag & PS_SHOW_ALL) && !task_active)
		return;

	if (task_active) {
		if (hide_offline_cpu(tc->processor))
			fprintf(fp, "- ");
		else
			fprintf(fp, "> ");
	} else
		fprintf(fp, "  ");

	fprintf(fp, "%7ld %7ld %3s  %s %3s",
		tc->pid, task_to_pid(tc->ptask),
		task_cpu(tc->processor, buf2, !VERBOSE),
		task_pointer_string(tc, flag & PS_KSTACKP, buf3),
		task_state_string(tc->task, buf1, !VERBOSE));
	pad_line(fp, strlen(buf1) > 3 ? 1 : 2, ' ');
	sprintf(buf1, "%.1f", tm->pct_physmem);
	if (strlen(buf1) == 3)
		mkstring(buf1, 4, CENTER|RJUST, NULL);
	fprintf(fp, "%s ", buf1);
	fprintf(fp, "%8ld ", (tm->total_vm * PAGESIZE())/1024);
	fprintf(fp, "%8ld  ", (tm->rss * PAGESIZE())/1024);
	if (is_kernel_thread(tc->task))
		fprintf(fp, "[%s]\n", tc->comm);
	else
		fprintf(fp, "%s\n", tc->comm);
}

static void
show_ps(ulong flag, struct psinfo *psi)
{
	int i, ac;
        struct task_context *tc;
	int print;
	char buf[BUFSIZE];

	if (!(flag & ((PS_EXCLUSIVE & ~PS_ACTIVE)|PS_NO_HEADER))) 
		fprintf(fp, 
		    "      PID    PPID  CPU %s  ST  %%MEM      VSZ      RSS  COMM\n",
			flag & PS_KSTACKP ?
			mkstring(buf, VADDR_PRLEN, CENTER|RJUST, "KSTACKP") :
			mkstring(buf, VADDR_PRLEN, CENTER, "TASK"));

	if (flag & PS_SHOW_ALL) {

		if (flag & PS_TIMES) {
			show_task_times(NULL, flag);
			return;
		}

		if (flag & PS_SUMMARY) {
			show_ps_summary(flag);
			return;
		}

		if (psi->cpus) {
			show_ps_data(flag, NULL, psi);
			return;
		}

		tc = FIRST_CONTEXT();
		for (i = 0; i < RUNNING_TASKS(); i++, tc++)
			show_ps_data(flag, tc, psi);
		
		return;
	}

	pc->curcmd_flags |= TASK_SPECIFIED;

	tc = FIRST_CONTEXT();
       	for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
		for (ac = 0; ac < psi->argc; ac++) {

			print = FALSE;

			switch(psi->type[ac])
			{
			case PS_BY_PID:
				if (tc->pid == psi->pid[ac])
					print = TRUE;
				break;

			case PS_BY_TASK:
				if ((tc->task == psi->task[ac]))
					print = TRUE;
				break;

			case PS_BY_CMD:
				if (STREQ(tc->comm, psi->comm[ac])) {
					if (flag & (PS_TGID_LIST|PS_GROUP)) {
						if (tc->pid == task_tgid(tc->task))
							print = TRUE;
						else
							print = FALSE;
					} else
						print = TRUE;
				}
				break;

			case PS_BY_REGEX:
				if (regexec(&psi->regex_data[ac].regex, 
				    tc->comm, 0, NULL, 0) == 0) {
					if (flag & (PS_TGID_LIST|PS_GROUP)) {
						if (tc->pid == task_tgid(tc->task))
							print = TRUE;
						else
							print = FALSE;
					} else
						print = TRUE;
				}
				break;
			}

			if (print) {
				if (flag & PS_TIMES) 
					show_task_times(tc, flag);
				else
					show_ps_data(flag, tc, psi);
			}
		}
	}
}

static void 
show_ps_summary(ulong flag)
{
	int i, s;
	struct task_context *tc;
	char buf[BUFSIZE];
#define MAX_STATES 20
	struct ps_state {
		long cnt;
		char string[3];
	} ps_state[MAX_STATES];

	if (flag & (PS_USER|PS_KERNEL|PS_GROUP))
		error(FATAL, "-S option cannot be used with other options\n");

	for (s = 0; s < MAX_STATES; s++)
		ps_state[s].cnt = 0;

	tc = FIRST_CONTEXT();
	for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
		task_state_string(tc->task, buf, !VERBOSE);
		for (s = 0; s < MAX_STATES; s++) {
			if (ps_state[s].cnt && 
			    STREQ(ps_state[s].string, buf)) {
				ps_state[s].cnt++;
				break;
			}
			if (ps_state[s].cnt == 0) {
				strcpy(ps_state[s].string, buf); 
				ps_state[s].cnt++;
				break;
			}
		}
	}
	for (s = 0; s < MAX_STATES; s++) {
		if (ps_state[s].cnt)
			fprintf(fp, 
			    "  %s: %ld\n", ps_state[s].string, ps_state[s].cnt);
	}
}


/*
 *  Display the task preceded by the last_run stamp and its
 *  current state.
 */
static void
show_last_run(struct task_context *tc, struct psinfo *psi)
{
	int i, c, others;
	struct task_context *tcp;
	char format[15];
	char buf[BUFSIZE];

	tcp = FIRST_CONTEXT();
	sprintf(buf, pc->output_radix == 10 ? "%lld" : "%llx", 
		task_last_run(tcp->task));
	c = strlen(buf);
	sprintf(format, "[%c%dll%c] ", '%', c, 
		pc->output_radix == 10 ? 'u' : 'x');

	if (psi && psi->cpus) {
		for (c = others = 0; c < kt->cpus; c++) {
			if (!NUM_IN_BITMAP(psi->cpus, c))
				continue;
			fprintf(fp, "%sCPU: %d",
				others++ ? "\n" : "", c);
			if (hide_offline_cpu(c)) {
				fprintf(fp, " [OFFLINE]\n");
				continue;
			} else
				fprintf(fp, "\n");

			tcp = FIRST_CONTEXT();
			for (i = 0; i < RUNNING_TASKS(); i++, tcp++) {
				if (tcp->processor != c)
					continue;
				fprintf(fp, format, task_last_run(tcp->task));
				fprintf(fp, "[%s]  ", 
					task_state_string(tcp->task, buf, !VERBOSE));
				print_task_header(fp, tcp, FALSE);
			}
		}
	} else if (tc) {
		fprintf(fp, format, task_last_run(tc->task));
		fprintf(fp, "[%s]  ", task_state_string(tc->task, buf, !VERBOSE));
		print_task_header(fp, tc, FALSE);
	} else {
		tcp = FIRST_CONTEXT();
		for (i = 0; i < RUNNING_TASKS(); i++, tcp++) {
			fprintf(fp, format, task_last_run(tcp->task));
			fprintf(fp, "[%s]  ", task_state_string(tcp->task, buf, !VERBOSE));
			print_task_header(fp, tcp, FALSE);
		}
	}
}

/*
 *  Translate a value in nanoseconds into a string showing days, 
 *  hours, minutes, seconds and milliseconds.
 */ 
static char *
translate_nanoseconds(ulonglong value, char *buf)
{
	ulong days, hours, mins, secs, ms;

	value = value / 1000000L;
	ms = value % 1000L;
	value = value / 1000L;	
	secs = value % 60L;
	value = value / 60L;
	mins = value % 60L;
	value = value / 60L;
	hours = value % 24L;
	value = value / 24L;
	days = value;

	sprintf(buf, "%ld %02ld:%02ld:%02ld.%03ld", 
		days, hours, mins, secs, ms);

	return buf;
}

/*
 *  Display the task preceded by a per-rq translation of the
 *  sched_info.last_arrival and its current state.
 */
static void
show_milliseconds(struct task_context *tc, struct psinfo *psi)
{
	int i, c, others, days, max_days;
	struct task_context *tcp;
	char format[15];
	char buf[BUFSIZE];
	struct syment *rq_sp;
	ulong runq;
	ulonglong rq_clock;
	long long delta;

	if (!(rq_sp = per_cpu_symbol_search("per_cpu__runqueues")))
		error(FATAL, "cannot determine per-cpu runqueue address\n");

	tcp = FIRST_CONTEXT();
	sprintf(buf, pc->output_radix == 10 ? "%lld" : "%llx", 
		task_last_run(tcp->task));
	c = strlen(buf);
	sprintf(format, "[%c%dll%c] ", '%', c, 
		pc->output_radix == 10 ? 'u' : 'x');

	if (psi && psi->cpus) {
		for (c = others = 0; c < kt->cpus; c++) {
			if (!NUM_IN_BITMAP(psi->cpus, c))
				continue;

			fprintf(fp, "%sCPU: %d",
				others++ ? "\n" : "", c);

			if (hide_offline_cpu(c)) {
				fprintf(fp, " [OFFLINE]\n");
				continue;
			} else
				fprintf(fp, "\n");

			if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF))
				runq = rq_sp->value + kt->__per_cpu_offset[c];
			else
				runq = rq_sp->value;
			readmem(runq + OFFSET(rq_timestamp), KVADDR, &rq_clock,
				sizeof(ulonglong), "per-cpu rq clock",
				FAULT_ON_ERROR);

			translate_nanoseconds(rq_clock, buf);
			max_days = first_space(buf) - buf;

			tcp = FIRST_CONTEXT();
			for (i = 0; i < RUNNING_TASKS(); i++, tcp++) {
				if (tcp->processor != c)
					continue;
				delta = rq_clock - task_last_run(tcp->task);
				if (delta < 0)
					delta = 0;
				translate_nanoseconds(delta, buf);
				days = first_space(buf) - buf;
				fprintf(fp, "[%s%s] ", space(max_days - days), 
					buf);
				fprintf(fp, "[%s]  ", 
					task_state_string(tcp->task, 
						buf, !VERBOSE));
				print_task_header(fp, tcp, FALSE);
			}
		}
	} else if (tc) {
		if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF))
			runq = rq_sp->value + kt->__per_cpu_offset[tc->processor];
		else
			runq = rq_sp->value;
		readmem(runq + OFFSET(rq_timestamp), KVADDR, &rq_clock,
			sizeof(ulonglong), "per-cpu rq clock",
			FAULT_ON_ERROR);
		translate_nanoseconds(rq_clock, buf);
		max_days = first_space(buf) - buf;
		delta = rq_clock - task_last_run(tc->task);
		if (delta < 0)
			delta = 0;
		translate_nanoseconds(delta, buf);
		days = first_space(buf) - buf;
		fprintf(fp, "[%s%s] ", space(max_days - days), buf);
		fprintf(fp, "[%s]  ", task_state_string(tc->task, buf, !VERBOSE));
		print_task_header(fp, tc, FALSE);
	} else {
		tcp = FIRST_CONTEXT();
		for (i = 0; i < RUNNING_TASKS(); i++, tcp++) {
			if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF))
				runq = rq_sp->value + 
					kt->__per_cpu_offset[tcp->processor];
			else
				runq = rq_sp->value;
			readmem(runq + OFFSET(rq_timestamp), KVADDR, &rq_clock,
				sizeof(ulonglong), "per-cpu rq clock",
				FAULT_ON_ERROR);
			delta = rq_clock - task_last_run(tcp->task);
			if (delta < 0)
				delta = 0;
			fprintf(fp, "[%s] ", translate_nanoseconds(delta, buf));
			fprintf(fp, "[%s]  ", task_state_string(tcp->task, buf, !VERBOSE));
			print_task_header(fp, tcp, FALSE);
		}
	}
}

static char *
read_arg_string(struct task_context *tc, char *buf, ulong start, ulong end)
{
	physaddr_t paddr;
	ulong uvaddr, size, cnt;
	char *bufptr;

	uvaddr = start;
	size = end - start;
	bufptr = buf;

	while (size > 0) {
		if (!uvtop(tc, uvaddr, &paddr, 0)) {
			error(INFO, "cannot access user stack address: %lx\n\n",
				uvaddr);
			return NULL;
		}

		cnt = PAGESIZE() - PAGEOFFSET(uvaddr);

		if (cnt > size)
			cnt = size;

		if (!readmem(paddr, PHYSADDR, bufptr, cnt,
		    "user stack contents", RETURN_ON_ERROR|QUIET)) {
			error(INFO, "cannot access user stack address: %lx\n\n",
				uvaddr);
			return NULL;
		}

		uvaddr += cnt;
		bufptr += cnt;
		size -= cnt;
	}

	return bufptr;
}

/*
 *  Show the argv and envp strings pointed to by mm_struct->arg_start 
 *  and mm_struct->env_start.  The user addresses need to broken up
 *  into physical on a page-per-page basis because we typically are
 *  not going to be working in the context of the target task. 
 */
static void
show_task_args(struct task_context *tc)
{
	ulong arg_start, arg_end, env_start, env_end;
	char *buf, *p1, *end;
	int c, d;

	print_task_header(fp, tc, 0);

        if (!tc || !tc->mm_struct) {     /* probably a kernel thread */
               	error(INFO, "no user stack\n\n");
                return;
	}

        if (!task_mm(tc->task, TRUE))
                return;

	if (INVALID_MEMBER(mm_struct_arg_start)) {
		MEMBER_OFFSET_INIT(mm_struct_arg_start, "mm_struct", "arg_start");
		MEMBER_OFFSET_INIT(mm_struct_arg_end, "mm_struct", "arg_end");
		MEMBER_OFFSET_INIT(mm_struct_env_start, "mm_struct", "env_start");
		MEMBER_OFFSET_INIT(mm_struct_env_end, "mm_struct", "env_end");
	}
	
	arg_start = ULONG(tt->mm_struct + OFFSET(mm_struct_arg_start));
	arg_end = ULONG(tt->mm_struct + OFFSET(mm_struct_arg_end));
	env_start = ULONG(tt->mm_struct + OFFSET(mm_struct_env_start));
	env_end = ULONG(tt->mm_struct + OFFSET(mm_struct_env_end));

	if (CRASHDEBUG(1)) {
		fprintf(fp, "arg_start: %lx arg_end: %lx (%ld)\n", 
			arg_start, arg_end, arg_end - arg_start);
		fprintf(fp, "env_start: %lx env_end: %lx (%ld)\n", 
			env_start, env_end, env_end - env_start);
	}

	buf = GETBUF(arg_end - arg_start + 1);
	end = read_arg_string(tc, buf, arg_start, arg_end);
	if (!end)
		goto bailout;

	fprintf(fp, "ARG: ");
	for (p1 = buf, c = 0; p1 < end; p1++) {
		if (*p1 == NULLCHAR) {
			if (c)
				fprintf(fp, " ");
			c = 0;
		} else {
			fprintf(fp, "%c", *p1);
			c++;
		}
	}

	FREEBUF(buf);

	buf = GETBUF(env_end - env_start + 1);
	end = read_arg_string(tc, buf, env_start, env_end);
	if (!end)
		goto bailout;

	fprintf(fp, "\nENV: ");
	for (p1 = buf, c = d = 0; p1 < end; p1++) {
		if (*p1 == NULLCHAR) {
			if (c)
				fprintf(fp, "\n");
			c = 0;
		} else {
			fprintf(fp, "%s%c", !c && (p1 != buf) ? "     " : "", *p1);
			c++, d++;
		}
	}
	fprintf(fp, "\n%s", d ? "" : "\n");

bailout:
	FREEBUF(buf);
}

char *rlim_names[] = {
	/* 0 */	 "CPU",  
	/* 1 */  "FSIZE",
	/* 2 */  "DATA",
	/* 3 */  "STACK",
	/* 4 */  "CORE",
	/* 5 */  "RSS",
	/* 6 */  "NPROC",
	/* 7 */  "NOFILE",
	/* 8 */  "MEMLOCK",
	/* 9 */  "AS",
	/* 10 */ "LOCKS",
	/* 11 */ "SIGPENDING",
	/* 12 */ "MSGQUEUE",
	/* 13 */ "NICE",
	/* 14 */ "RTPRIO",
	/* 15 */ "RTTIME",
	NULL,
};

#ifndef RLIM_INFINITY
#define RLIM_INFINITY (~0UL)
#endif

/*
 *  Show the current and maximum rlimit values.
 */
static void
show_task_rlimit(struct task_context *tc)
{
	int i, j, len1, len2, rlimit_index;
	int in_task_struct, in_signal_struct;
	char *rlimit_buffer;
	ulong *p1, rlim_addr;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];

	rlimit_index = 0;

	if (!VALID_MEMBER(task_struct_rlim) && !VALID_MEMBER(signal_struct_rlim)) {
		MEMBER_OFFSET_INIT(task_struct_rlim, "task_struct", "rlim");
		MEMBER_OFFSET_INIT(signal_struct_rlim, "signal_struct", "rlim");
		STRUCT_SIZE_INIT(rlimit, "rlimit");
		if (!VALID_MEMBER(task_struct_rlim) && 
	  	    !VALID_MEMBER(signal_struct_rlim))
			error(FATAL, "cannot determine rlimit array location\n");
	} else if (!VALID_STRUCT(rlimit))
		error(FATAL, "cannot determine rlimit structure definition\n");

	in_task_struct = in_signal_struct = FALSE;

	if (VALID_MEMBER(task_struct_rlim)) {
		rlimit_index = (i = ARRAY_LENGTH(task_struct_rlim)) ?
			i : get_array_length("task_struct.rlim", NULL, 0);
		in_task_struct = TRUE;
	} else if (VALID_MEMBER(signal_struct_rlim)) {
		if (!VALID_MEMBER(task_struct_signal))
			error(FATAL, "cannot determine rlimit array location\n");
		rlimit_index = (i = ARRAY_LENGTH(signal_struct_rlim)) ?
			i : get_array_length("signal_struct.rlim", NULL, 0);
		in_signal_struct = TRUE;
	}

	if (!rlimit_index)
		error(FATAL, "cannot determine rlimit array size\n");

	for (i = len1 = 0; i < rlimit_index; i++) {
		if (rlim_names[i] == NULL)
			continue;
		if ((j = strlen(rlim_names[i])) > len1)
			len1 = j;
	}
	len2 = strlen("(unlimited)");

	rlimit_buffer = GETBUF(rlimit_index * SIZE(rlimit));

	print_task_header(fp, tc, 0);

	fill_task_struct(tc->task);

	if (in_task_struct) {
		BCOPY(tt->task_struct + OFFSET(task_struct_rlim),
			rlimit_buffer, rlimit_index * SIZE(rlimit));
	} else if (in_signal_struct) {
		rlim_addr = ULONG(tt->task_struct + OFFSET(task_struct_signal));
        	if (!readmem(rlim_addr + OFFSET(signal_struct_rlim), 
		    KVADDR, rlimit_buffer, rlimit_index * SIZE(rlimit),
                    "signal_struct rlimit array", RETURN_ON_ERROR)) {
			FREEBUF(rlimit_buffer);
			return;
		}
	}
	
	fprintf(fp, "  %s   %s   %s\n",
		mkstring(buf1, len1, RJUST, "RLIMIT"),
		mkstring(buf2, len2, CENTER|RJUST, "CURRENT"),
		mkstring(buf3, len2, CENTER|RJUST, "MAXIMUM"));
		
	for (p1 = (ulong *)rlimit_buffer, i = 0; i < rlimit_index; i++) {
		fprintf(fp, "  %s   ", mkstring(buf1, len1, RJUST, 
			rlim_names[i] ? rlim_names[i] : "(unknown)"));
		if (*p1 == (ulong)RLIM_INFINITY)
			fprintf(fp, "(unlimited)   ");
		else
			fprintf(fp, "%s   ", mkstring(buf1, len2, 
				CENTER|LJUST|LONG_DEC, MKSTR(*p1)));
		p1++;
		if (*p1 == (ulong)RLIM_INFINITY)
			fprintf(fp, "(unlimited)\n");
		else
			fprintf(fp, "%s\n", mkstring(buf1, len2, 
				CENTER|LJUST|LONG_DEC, MKSTR(*p1)));
		p1++;
	}

	fprintf(fp, "\n");

	FREEBUF(rlimit_buffer);
}

/*
 *  Put either the task_struct address or kernel stack pointer into a string.
 *  If the kernel stack pointer is requested, piggy-back on top of the
 *  back trace code to avoid having to deal with machine dependencies,
 *  live active tasks, and dumpfile panic tasks.
 */
static char *
task_pointer_string(struct task_context *tc, ulong do_kstackp, char *buf)
{
	struct bt_info bt_info, *bt;
	char buf1[BUFSIZE];

	if (do_kstackp) {
		bt = &bt_info;
               	BZERO(bt, sizeof(struct bt_info));;

		if (is_task_active(tc->task)) {
			bt->stkptr = 0;
		} else if (VALID_MEMBER(task_struct_thread_esp)) {
        		readmem(tc->task + OFFSET(task_struct_thread_esp), 
				KVADDR, &bt->stkptr, sizeof(void *),
                		"thread_struct esp", FAULT_ON_ERROR);
		} else if (VALID_MEMBER(task_struct_thread_ksp)) {
        		readmem(tc->task + OFFSET(task_struct_thread_ksp), 
				KVADDR, &bt->stkptr, sizeof(void *),
                		"thread_struct ksp", FAULT_ON_ERROR);
		} else if (VALID_MEMBER(task_struct_thread_context_sp)) {
			readmem(tc->task + OFFSET(task_struct_thread_context_sp), 
				KVADDR, &bt->stkptr, sizeof(void *),
				"cpu_context sp", FAULT_ON_ERROR);
		} else {
			if ((bt->stackbase = GET_STACKBASE(tc->task))) {
				bt->stacktop = GET_STACKTOP(tc->task);
				bt->task = tc->task;
				bt->tc = tc;
				bt->flags |= BT_KSTACKP;
				back_trace(bt);
				if (bt->stackbuf)
					FREEBUF(bt->stackbuf);
			} else
				bt->stkptr = 0;
		}

		if (bt->stkptr)
			sprintf(buf, "%s",
				mkstring(buf1, VADDR_PRLEN,
					 CENTER|RJUST|LONG_HEX,
					 MKSTR(bt->stkptr)));
		else
			sprintf(buf, "%s",
			    mkstring(buf1, VADDR_PRLEN, CENTER|RJUST, "--"));
	} else 
		sprintf(buf, "%s",
			mkstring(buf1, VADDR_PRLEN,
				 CENTER|RJUST|LONG_HEX,
				 MKSTR(tc->task)));

	return buf;
}


/*
 *  Dump the task list ordered by start_time.
 */
struct kernel_timeval {
	unsigned int tv_sec;
    	unsigned int tv_usec;
};

struct task_start_time {
	struct task_context *tc;
        ulonglong start_time;
	ulong tms_utime;
	ulong tms_stime;
	struct timeval old_utime;
	struct timeval old_stime;
	struct kernel_timeval kutime;
	struct kernel_timeval kstime;
	ulonglong utime;
	ulonglong stime;
};

static void
show_task_times(struct task_context *tcp, ulong flags)
{
	int i, tasks, use_kernel_timeval, use_utime_stime;
	struct task_context *tc;
	struct task_start_time *task_start_times, *tsp;
	ulong jiffies, tgid;
	ulonglong jiffies_64;
	char buf1[BUFSIZE];

	task_start_times = (struct task_start_time *)
		GETBUF(RUNNING_TASKS() * sizeof(struct task_start_time));
 
	use_kernel_timeval = STRUCT_EXISTS("kernel_timeval");
	if (VALID_MEMBER(task_struct_utime) &&
	    (SIZE(task_struct_utime) == 
	    (BITS32() ? sizeof(uint32_t) : sizeof(uint64_t))))
		use_utime_stime = TRUE;
	else
		use_utime_stime = FALSE;
        get_symbol_data("jiffies", sizeof(long), &jiffies);
	if (symbol_exists("jiffies_64"))
		get_uptime(NULL, &jiffies_64);
	tsp = task_start_times;
	tc = tcp ? tcp : FIRST_CONTEXT();

        for (i = tasks = 0; i < RUNNING_TASKS(); i++, tc++) {

                if ((flags & PS_USER) && is_kernel_thread(tc->task))
                        continue;
                if ((flags & PS_KERNEL) && !is_kernel_thread(tc->task))
                        continue;
		if (flags & PS_GROUP) {
			tgid = task_tgid(tc->task);
			if (tc->pid != tgid) {
				if (tcp) {
					if (!(tc = tgid_to_context(tgid)))
						return;
				} else
					continue;
			}
			if (hq_entry_exists((ulong)tc))
				return;
			hq_enter((ulong)tc);
		}

		fill_task_struct(tc->task);
        	if (!tt->last_task_read) {
			if (tcp)
				return;
			continue;
		}

 		tsp->tc = tc;

		if (BITS32() && (SIZE(task_struct_start_time) == 8)) {
			if (start_time_timespec())
				tsp->start_time = 
					ULONG(tt->task_struct +
					OFFSET(task_struct_start_time));
			else
				tsp->start_time = 
					ULONGLONG(tt->task_struct +
					OFFSET(task_struct_start_time));
		} else {
			start_time_timespec();
			tsp->start_time = ULONG(tt->task_struct +
				OFFSET(task_struct_start_time));
		}

		if (VALID_MEMBER(task_struct_times)) {
			tsp->tms_utime = ULONG(tt->task_struct +
                        	OFFSET(task_struct_times) +
				OFFSET(tms_tms_utime));
                	tsp->tms_stime = ULONG(tt->task_struct +
                        	OFFSET(task_struct_times) +
                        	OFFSET(tms_tms_stime));
		} else if (VALID_MEMBER(task_struct_utime)) {
			if (use_utime_stime) {
				tsp->utime = ULONG(tt->task_struct +
					OFFSET(task_struct_utime));
				tsp->stime = ULONG(tt->task_struct +
					OFFSET(task_struct_stime));
			} else if (use_kernel_timeval) {
                                BCOPY(tt->task_struct +
                                        OFFSET(task_struct_utime), &tsp->kutime,
					sizeof(struct kernel_timeval));
                                BCOPY(tt->task_struct +
                                        OFFSET(task_struct_stime), &tsp->kstime,
					sizeof(struct kernel_timeval));
			} else if (VALID_STRUCT(cputime_t)) {
				/* since linux 2.6.11 */
				if (SIZE(cputime_t) == 8) {
					uint64_t utime_64, stime_64;
					BCOPY(tt->task_struct + 
						OFFSET(task_struct_utime), 
						&utime_64, 8);
					BCOPY(tt->task_struct + 
						OFFSET(task_struct_stime), 
						&stime_64, 8);
					/* convert from micro-sec. to sec. */
					tsp->old_utime.tv_sec = utime_64 / 1000000;
					tsp->old_stime.tv_sec = stime_64 / 1000000;
				} else {
					uint32_t utime_32, stime_32;
					BCOPY(tt->task_struct + 
						OFFSET(task_struct_utime), 
						&utime_32, 4);
					BCOPY(tt->task_struct + 
						OFFSET(task_struct_stime), 
						&stime_32, 4);
					tsp->old_utime.tv_sec = utime_32;
					tsp->old_stime.tv_sec = stime_32;
				}
			} else {
				BCOPY(tt->task_struct + 
					OFFSET(task_struct_utime), 
					&tsp->utime, sizeof(struct timeval));
				BCOPY(tt->task_struct + 
					OFFSET(task_struct_stime), 
					&tsp->stime, sizeof(struct timeval));
			}
		}

		tasks++;
		tsp++;

		if (tcp)
			break;
	}

	qsort((void *)task_start_times, (size_t)tasks, 
		sizeof(struct task_start_time), compare_start_time);

        for (i = 0, tsp = task_start_times; i < tasks; i++, tsp++) {
		print_task_header(fp, tsp->tc, 0);
		fprintf(fp, "    RUN TIME: %s\n", symbol_exists("jiffies_64") ? 
			convert_time(convert_start_time(tsp->start_time, jiffies_64), buf1) :
			convert_time(jiffies - tsp->start_time, buf1));
		fprintf(fp, "  START TIME: %llu\n", tsp->start_time); 
		if (VALID_MEMBER(task_struct_times)) {
			fprintf(fp, "   USER TIME: %ld\n", tsp->tms_utime);
			fprintf(fp, " SYSTEM TIME: %ld\n\n", tsp->tms_stime);
		} else if (VALID_MEMBER(task_struct_utime)) {
			if (use_utime_stime) {
				fprintf(fp, "       UTIME: %lld\n", 
					(ulonglong)tsp->utime);
				fprintf(fp, "       STIME: %lld\n\n", 
					(ulonglong)tsp->stime);
			} else if (use_kernel_timeval) {
				fprintf(fp, "   USER TIME: %d\n", 
					tsp->kutime.tv_sec);
				fprintf(fp, " SYSTEM TIME: %d\n\n", 
					tsp->kstime.tv_sec);
			} else {
				fprintf(fp, "   USER TIME: %ld\n", 
					tsp->old_utime.tv_sec);
				fprintf(fp, " SYSTEM TIME: %ld\n\n", 
					tsp->old_stime.tv_sec);
			}
		}
	}
	FREEBUF(task_start_times);
}

static int
start_time_timespec(void)
{
	switch(tt->flags & (TIMESPEC | NO_TIMESPEC | START_TIME_NSECS))
	{
	case TIMESPEC:
		return TRUE;
	case NO_TIMESPEC:
	case START_TIME_NSECS:
		return FALSE;
	default:
		break;
	}

	tt->flags |= NO_TIMESPEC;

	if (VALID_MEMBER(task_struct_start_time) &&
	    STREQ(MEMBER_TYPE_NAME("task_struct", "start_time"), "timespec")) {
			tt->flags &= ~NO_TIMESPEC;
			tt->flags |= TIMESPEC;
	}

	if ((tt->flags & NO_TIMESPEC) && (SIZE(task_struct_start_time) == 8)) {
		tt->flags &= ~NO_TIMESPEC;
		tt->flags |= START_TIME_NSECS;
	}

        return (tt->flags & TIMESPEC ? TRUE : FALSE);
}

static ulonglong
convert_start_time(ulonglong start_time, ulonglong current)
{
	ulong tmp1, tmp2;
	ulonglong wrapped;

        switch(tt->flags & (TIMESPEC | NO_TIMESPEC | START_TIME_NSECS))
        {
	case START_TIME_NSECS:
		start_time /= 1000000000ULL;  /* FALLTHROUGH */
        case TIMESPEC:
		if ((start_time * (ulonglong)machdep->hz) > current)
			return 0;
		else
                	return current - (start_time * (ulonglong)machdep->hz); 

        case NO_TIMESPEC:
                if (THIS_KERNEL_VERSION >= LINUX(2,6,0)) {
                        wrapped = (start_time & 0xffffffff00000000ULL);
                        if (wrapped) {
                                wrapped -= 0x100000000ULL;
                                start_time &= 0x00000000ffffffffULL;
                                start_time |= wrapped;
                                start_time += (ulonglong)(300*machdep->hz);
                        } else {
                                tmp1 = (ulong)(uint)(-300*machdep->hz);
                                tmp2 = (ulong)start_time;
                                start_time = (ulonglong)(tmp2 - tmp1);
                        }
                }
		break;

        default:
                break;
        }

	return start_time;
}

/*
 *  The comparison function must return an integer less  than,
 *  equal  to,  or  greater than zero if the first argument is
 *  considered to be respectively  less  than,  equal  to,  or
 *  greater than the second.  If two members compare as equal,
 *  their order in the sorted array is undefined.
 */

static int
compare_start_time(const void *v1, const void *v2)
{
        struct task_start_time *t1, *t2;

        t1 = (struct task_start_time *)v1;
        t2 = (struct task_start_time *)v2;

	return (t1->start_time < t2->start_time ? -1 :
		t1->start_time == t2->start_time ? 0 : 1);
}

static ulong
parent_of(ulong task)
{
	long offset;
	ulong parent;

        if (VALID_MEMBER(task_struct_parent))
                offset = OFFSET(task_struct_parent);
	else
                offset = OFFSET(task_struct_p_pptr);

	readmem(task+offset, KVADDR, &parent,
	    sizeof(void *), "task parent", FAULT_ON_ERROR);

	return parent;
}

/*
 *  Dump the parental hierarchy of a task.
 */
static void
parent_list(ulong task)
{
	int i, j, cnt;
        struct task_context *tc;
	char *buffer;
	long reserved;
	ulong *task_list, child, parent;

	reserved = 100 * sizeof(ulong);
	buffer = GETBUF(reserved);
	task_list = (ulong *)buffer;
	child = task_list[0] = task;
	parent = parent_of(child);
	cnt = 1;

	while (child != parent) {
		child = task_list[cnt++] = parent;
		parent = parent_of(child);
		if ((cnt * sizeof(ulong)) == reserved) {
			RESIZEBUF(buffer, reserved, reserved * 2);
			reserved *= 2;
			task_list = (ulong *)buffer;
		}
	}

	for (i = cnt-1, j = 0; i >= 0; i--, j++) {
		INDENT(j);
		tc = task_to_context(task_list[i]);
		if (tc)
			print_task_header(fp, tc, 0);
	}

	FREEBUF(task_list);
}

/*
 *  Dump the children of a task.
 */
static void
child_list(ulong task)
{
        int i;
	int cnt;
        struct task_context *tc;

	tc = task_to_context(task);
	print_task_header(fp, tc, 0);

        tc = FIRST_CONTEXT();
        for (i = cnt = 0; i < RUNNING_TASKS(); i++, tc++) {
                if (tc->ptask == task) {
			INDENT(2);
			print_task_header(fp, tc, 0);
			cnt++;
		}
	}

	if (!cnt)
		fprintf(fp, "  (no children)\n");
}

/*
 *  Dump the children of a task.
 */
static void
show_tgid_list(ulong task)
{
        int i;
        int cnt;
        struct task_context *tc;
	ulong tgid;

        tc = task_to_context(task);
	tgid = task_tgid(task);

	if (tc->pid != tgid) {
		if (pc->curcmd_flags & TASK_SPECIFIED) {
			if (!(tc = tgid_to_context(tgid)))
				return;
			task = tc->task;
		} else
			return;
	}

	if ((tc->pid == 0) && (pc->curcmd_flags & IDLE_TASK_SHOWN))
		return;

       	print_task_header(fp, tc, 0);

        tc = FIRST_CONTEXT();
        for (i = cnt = 0; i < RUNNING_TASKS(); i++, tc++) {
		if (tc->task == task)
			continue;

		if (task_tgid(tc->task)	== tgid) {
                        INDENT(2);
                        print_task_header(fp, tc, 0);
                        cnt++;
			if (tc->pid == 0)
				pc->curcmd_flags |= IDLE_TASK_SHOWN;
                }
        }

        if (!cnt)
                fprintf(fp, "  (no threads)\n");

	fprintf(fp, "\n");
}

/*
 * Return the first task found that belongs to a pid. 
 */
ulong
pid_to_task(ulong pid)
{
	int i;
	struct task_context *tc;

	tc = FIRST_CONTEXT();
        for (i = 0; i < RUNNING_TASKS(); i++, tc++) 
        	if (tc->pid == pid)
			return(tc->task);

	return((ulong)NULL);
}


/*
 *  Return the pid of a task.
 */
ulong
task_to_pid(ulong task)
{
        struct task_context *tc;

	tc = task_to_context(task);
	if (tc != NULL)
		return tc->pid;

        return(NO_PID);
}

/*
 *  Verify whether a task exists.
 */
int
task_exists(ulong task)
{
        int i;
        struct task_context *tc;

        tc = FIRST_CONTEXT();
        for (i = 0; i < RUNNING_TASKS(); i++, tc++) 
                if (tc->task == task)
                        return TRUE;
        
        return FALSE;
}

/*
 *  Return the task_context structure of a task.
 */
struct task_context *
task_to_context(ulong task)
{
	struct task_context key, *tc, **found;
	int i;

	/* Binary search the context_by_task array. */
	if (tt->flags & INDEXED_CONTEXTS) {
		key.task = task;
		tc = &key;
		found = bsearch(&tc, tt->context_by_task, tt->running_tasks,
				sizeof(*tt->context_by_task), sort_by_task);
		return found ? *found : NULL;
	}

        tc = FIRST_CONTEXT();
        for (i = 0; i < RUNNING_TASKS(); i++, tc++)
                if (tc->task == task)
                        return tc;

	return NULL;
}

/*
 *  Return a tgid's parent task_context structure.
 */
struct task_context *
tgid_to_context(ulong parent_tgid)
{
        int i;
        struct task_context *tc;
	ulong tgid;

        tc = FIRST_CONTEXT();
        for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
		tgid = task_tgid(tc->task);
		if ((tgid == parent_tgid) && (tgid == tc->pid))
                        return tc;
	}

        return NULL;
}


/*
 *  Return the task_context structure of the first task found with a pid,
 *  while linking all tasks that have that pid. 
 */
struct task_context *
pid_to_context(ulong pid)
{
        int i;
        struct task_context *tc, *firsttc, *lasttc;

        tc = FIRST_CONTEXT();
        firsttc = lasttc = NULL;

        for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
                if (tc->pid == pid) {
			if (!firsttc)
                        	firsttc = tc;
                        if (lasttc)
                                lasttc->tc_next = tc;
                        tc->tc_next = NULL;
                        lasttc = tc;
		}
	}

        return firsttc;
}


/*
 *  Verify whether a pid exists, and if found, linking all tasks having the pid.
 */
int
pid_exists(ulong pid)
{
        int i;
        struct task_context *tc, *lasttc;
	int count;

        tc = FIRST_CONTEXT();
	count = 0;
	lasttc = NULL;

        for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
                if (tc->pid == pid) {
                        count++;
			if (lasttc)
				lasttc->tc_next = tc;
			tc->tc_next = NULL;
			lasttc = tc;
		}
	}
        
        return(count);
}

/*
 *  Translate a stack pointer to a task, dealing with possible split.
 *  If that doesn't work, check the hardirq_stack and softirq_stack.
 *
 * TODO: This function can be optimized by getting min & max of the
 *       stack range in first pass and use these values against the
 *       given SP to decide whether or not to proceed with stack lookup.
 */
ulong
stkptr_to_task(ulong sp)
{
        int i, c;
        struct task_context *tc;
	struct bt_info bt_info, *bt;

	if (!sp)
		return NO_TASK;

	bt = &bt_info;
        tc = FIRST_CONTEXT();
        for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
        	bt->stackbase = GET_STACKBASE(tc->task);
        	bt->stacktop = GET_STACKTOP(tc->task);
		if (INSTACK(sp, bt)) 
			return tc->task;
	}

	if (!(tt->flags & IRQSTACKS))
        	return NO_TASK;

        bt = &bt_info;
        tc = FIRST_CONTEXT();
        for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
		for (c = 0; c < NR_CPUS; c++) {
			if (tt->hardirq_ctx[c]) {
				bt->stackbase = tt->hardirq_ctx[c];
				bt->stacktop = bt->stackbase + 
					SIZE(irq_ctx);
                		if (INSTACK(sp, bt) && 
				    (tt->hardirq_tasks[c] == tc->task)) 
                        		return tc->task;
			}
			if (tt->softirq_ctx[c]) {
                        	bt->stackbase = tt->softirq_ctx[c];
                        	bt->stacktop = bt->stackbase + 
					SIZE(irq_ctx);
                        	if (INSTACK(sp, bt) &&
				    (tt->softirq_tasks[c] == tc->task)) 
                                	return tc->task;
			}
		}
        }

	return NO_TASK;
}

/*
 *  Translate a task pointer to its thread_info.
 */
ulong
task_to_thread_info(ulong task)
{
	int i;
        struct task_context *tc;

	if (!(tt->flags & THREAD_INFO))
		error(FATAL, 
		   "task_to_thread_info: thread_info struct does not exist!\n");

        tc = FIRST_CONTEXT();
        for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
		if (tc->task == task)
			return tc->thread_info;
	}
	return(error(FATAL, "task does not exist: %lx\n", task));
}

/*
 *  Translate a task address to its stack base, dealing with potential split.
 */
ulong
task_to_stackbase(ulong task)
{
	ulong stackbase;

	if (tt->flags & THREAD_INFO_IN_TASK) {
		readmem(task + OFFSET(task_struct_stack), KVADDR, &stackbase,
		    sizeof(void *), "task_struct.stack", FAULT_ON_ERROR);
		return stackbase;
	} else if (tt->flags & THREAD_INFO)
		return task_to_thread_info(task);
	else
		return (task & ~(STACKSIZE()-1));
}

/*
 *  Try to translate a decimal or hexadecimal string into a task or pid,
 *  failing if no task or pid exists, or if there is ambiguity between
 *  the decimal and hexadecimal translations.  However, if the value could
 *  be a decimal PID and a hexadecimal PID of two different processes, then
 *  default to the decimal value. 
 *
 *  This was added in preparation for overlapping, zero-based, user and kernel
 *  virtual addresses on s390 and s390x, allowing for the entry of ambiguous
 *  decimal/hexadecimal task address values without the leading "0x".
 *  It should be used in lieu of "stol" when parsing for task/pid arguments.
 */
int 
str_to_context(char *string, ulong *value, struct task_context **tcp)
{
	ulong dvalue, hvalue;
	int found, type;
	char *s;
	struct task_context *tc_dp, *tc_dt, *tc_hp, *tc_ht;

	if (string == NULL) {
		error(INFO, "received NULL string\n");
		return STR_INVALID;
	}

	s = string;
        dvalue = hvalue = BADADDR;

        if (decimal(s, 0))
                dvalue = dtol(s, RETURN_ON_ERROR, NULL);

        if (hexadecimal(s, 0)) {
        	if (STRNEQ(s, "0x") || STRNEQ(s, "0X"))
                	s += 2;
		if (strlen(s) <= MAX_HEXADDR_STRLEN) 
                	hvalue = htol(s, RETURN_ON_ERROR, NULL);
	}

        found = 0;
        tc_dp = tc_dt = tc_hp = tc_ht = NULL;
	type = STR_INVALID;

	if (dvalue != BADADDR) {
		if ((tc_dp = pid_to_context(dvalue)))
			found++;
	        if ((tc_dt = task_to_context(dvalue)))
			found++;
	}
	
	if ((hvalue != BADADDR) && (dvalue != hvalue)) {
	        if ((tc_hp = pid_to_context(hvalue)))
			found++;
	        if ((tc_ht = task_to_context(hvalue)))
			found++;
	}

	switch (found) 
	{
	case 2: 
		if (tc_dp && tc_hp) {      
                	*tcp = tc_dp;      
                	*value = dvalue;   
                	type = STR_PID;
		}
		break;
		
	case 1: 
		if (tc_dp) {
			*tcp = tc_dp;
			*value = dvalue;
			type = STR_PID;
		}
	
		if (tc_dt) {
			*tcp = tc_dt;
			*value = dvalue;
			type = STR_TASK;
		}
	
		if (tc_hp) {
			*tcp = tc_hp;
			*value = hvalue;
			type = STR_PID;
		}
	
		if (tc_ht) {
			*tcp = tc_ht;
			*value = hvalue;
			type = STR_TASK;
		}
		break;
	}

	return type;
}


/*
 *  Return the task if the vaddr is part of a task's task_struct.
 */
ulong
vaddr_in_task_struct(ulong vaddr)
{
        int i;
        struct task_context *tc;

        tc = FIRST_CONTEXT();
        for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
		if ((vaddr >= tc->task) && 
		    (vaddr < (tc->task + SIZE(task_struct))))
                        return tc->task;
        }

	return NO_TASK;
}

/*
 *  Verify whether any task is running a command.
 */
int
comm_exists(char *s)
{
        int i, cnt;
        struct task_context *tc;
	char buf[TASK_COMM_LEN];

	strlcpy(buf, s, TASK_COMM_LEN);

        tc = FIRST_CONTEXT();
        for (i = cnt = 0; i < RUNNING_TASKS(); i++, tc++) 
		if (STREQ(tc->comm, buf))
                        cnt++;
        
        return cnt;
}

/*
 *  Set a new context.  If only a pid is passed, the first task found with
 *  that pid is selected.
 */
int
set_context(ulong task, ulong pid)
{
	int i;
	struct task_context *tc;
	int found;

	tc = FIRST_CONTEXT();

        for (i = 0, found = FALSE; i < RUNNING_TASKS(); i++, tc++) {
		if (task && (tc->task == task)) {
			found = TRUE;
			break;
		} else if (pid == tc->pid) {
			found = TRUE;
			break;
		}
        }

	if (found) {
		CURRENT_CONTEXT() = tc;
		return TRUE;
	} else {
		if (task) 
			error(INFO, "cannot set context for task: %lx\n", task);
		else 
			error(INFO, "cannot set context for pid: %d\n", pid);
		return FALSE;
	}
}

/*
 *  Check whether the panic was determined to be caused by a "sys -panic" 
 *  command.  If so, fix the task_context's pid despite what the task_struct
 *  says.
 */
#define CONTEXT_ADJUSTED      (1)
#define CONTEXT_ERRONEOUS     (2)

static int
panic_context_adjusted(struct task_context *tc)
{
        pid_t pgrp, tgid;
	char buf[BUFSIZE];

        if (!(DUMPFILE() && (tc == task_to_context(tt->panic_task)) &&
            (tc->pid == 0) && STRNEQ(tc->comm, pc->program_name) &&
            strstr(get_panicmsg(buf), "Attempted to kill the idle task")))
		return 0;

        if (INVALID_MEMBER(task_struct_pgrp) || 
	    INVALID_MEMBER(task_struct_tgid))
                return CONTEXT_ERRONEOUS;

        fill_task_struct(tc->task);

        pgrp = tt->last_task_read ?
                UINT(tt->task_struct + OFFSET(task_struct_pgrp)) : 0;
        tgid = tt->last_task_read ?
                UINT(tt->task_struct + OFFSET(task_struct_tgid)) : 0;

        if (pgrp && tgid && (pgrp == tgid) && !pid_exists((ulong)pgrp)) {
                tc->pid = (ulong)pgrp;
                return CONTEXT_ADJUSTED;
        }

        return CONTEXT_ERRONEOUS;
}

/*
 *  Display a task context.
 */

void
show_context(struct task_context *tc)
{
	char buf[BUFSIZE];
	char *p1;
	int adjusted, cnt, indent;

	adjusted = pc->flags & RUNTIME ? 0 : panic_context_adjusted(tc); 
	indent = pc->flags & RUNTIME ? 0 : 5;

	INDENT(indent);
	fprintf(fp, "    PID: %ld\n", tc->pid);
	INDENT(indent);
	fprintf(fp, "COMMAND: \"%s\"\n", tc->comm);
	INDENT(indent);
	fprintf(fp, "   TASK: %lx  ", tc->task);
	if ((machdep->flags & (INIT|MCA)) && (tc->pid == 0))
		cnt = comm_exists(tc->comm);
	else
		cnt = TASKS_PER_PID(tc->pid);
	if (cnt > 1)
		fprintf(fp, "(1 of %d)  ", cnt);
	if (tt->flags & THREAD_INFO)
		fprintf(fp, "[THREAD_INFO: %lx]", tc->thread_info);
	fprintf(fp, "\n");
	INDENT(indent);
	fprintf(fp, "    CPU: %s\n", task_cpu(tc->processor, buf, VERBOSE));
	INDENT(indent);
	fprintf(fp, "  STATE: %s ", 
		task_state_string(tc->task, buf, VERBOSE));
	if (is_task_active(tc->task)) {
		if (machdep->flags & HWRESET)
			fprintf(fp, "(HARDWARE RESET)");
		else if ((pc->flags & SYSRQ) && (tc->task == tt->panic_task))
			fprintf(fp, "(SYSRQ)");
		else if (machdep->flags & INIT)
			fprintf(fp, "(INIT)");
		else if ((machdep->flags & MCA) && (tc->task == tt->panic_task))
			fprintf(fp, "(MCA)");
		else if ((tc->processor >= 0) && 
		        (tc->processor < NR_CPUS) && 
			(kt->cpu_flags[tc->processor] & NMI))
			fprintf(fp, "(NMI)");
		else if ((tc->task == tt->panic_task) &&
			XENDUMP_DUMPFILE() && (kt->xen_flags & XEN_SUSPEND))
			fprintf(fp, "(SUSPEND)");
		else if ((tc->task == tt->panic_task) && !(pc->flags2 & SNAP))
			fprintf(fp, "(PANIC)");
		else
			fprintf(fp, "(ACTIVE)");
	}

	if (!(pc->flags & RUNTIME) && !ACTIVE() && 
	    (tt->flags & PANIC_TASK_NOT_FOUND) &&
	    !SYSRQ_TASK(tc->task)) {
		fprintf(fp, "\n"); INDENT(indent);
		if (machine_type("S390") || machine_type("S390X"))
			fprintf(fp, "   INFO: no panic task found");
		else if (tt->panic_processor >= 0)
			fprintf(fp,
			    "WARNING: reported panic task %lx not found",
				tt->panic_threads[tt->panic_processor]);
		else 
			fprintf(fp, "WARNING: panic task not found");
	}

	fprintf(fp, "\n");

	if (pc->flags & RUNTIME)
		return;

	/*
	 *  Dump any pre-first-prompt messages here.
	 */
	cnt = 0;

	if (pc->flags & NAMELIST_UNLINKED) {
		strcpy(buf, pc->namelist);
		if ((p1 = strstr(buf, "@")))
			*p1 = NULLCHAR;
		fprintf(fp, 
 "%sNOTE: To save the remote \"%s\" locally,\n      enter: \"save kernel\"\n",
			cnt++ ? "" : "\n", buf);
	}

	if (REMOTE_DUMPFILE())
		fprintf(fp, 
         "%sNOTE: To save the remote \"%s\" locally,\n      enter: \"save dumpfile\"\n",
			cnt++ ? "" : "\n", 
			basename(pc->server_memsrc));

	/*
	 *  If this panic was caused by a "sys -panic" command, issue the
	 *  proper warning message.
	 */
	switch (adjusted) 
	{
	case CONTEXT_ADJUSTED:
               	fprintf(fp,
          "%sNOTE: The \"%s\" task_struct will erroneously show a p_pid of 0\n",
                	cnt++ ? "" : "\n", tc->comm);
		break;

	case CONTEXT_ERRONEOUS:
              	fprintf(fp,
             "%sWARNING: The \"%s\" context will erroneously show a PID of 0\n",
               		cnt++ ? "" : "\n", tc->comm);
		break;
	}

	if (!(pc->flags & RUNTIME) && (tt->flags & ACTIVE_ONLY))
		error(WARNING, 
		    "\nonly the active tasks on each cpu are being tracked\n");
}


/*
 *  Translate a task_struct state value into a long (verbose), or short string,
 *  or if requested, just pass back the state value.
 */

#define TASK_STATE_UNINITIALIZED (-1)

static long _RUNNING_ = TASK_STATE_UNINITIALIZED;
static long _INTERRUPTIBLE_ = TASK_STATE_UNINITIALIZED;
static long _UNINTERRUPTIBLE_ = TASK_STATE_UNINITIALIZED;
static long _STOPPED_ = TASK_STATE_UNINITIALIZED;
static long _TRACING_STOPPED_ = TASK_STATE_UNINITIALIZED;
long _ZOMBIE_ = TASK_STATE_UNINITIALIZED;      /* also used by IS_ZOMBIE() */
static long _DEAD_ = TASK_STATE_UNINITIALIZED;
static long _SWAPPING_ = TASK_STATE_UNINITIALIZED;
static long _EXCLUSIVE_ = TASK_STATE_UNINITIALIZED;
static long _WAKEKILL_ = TASK_STATE_UNINITIALIZED;
static long _WAKING_ = TASK_STATE_UNINITIALIZED;
static long _NONINTERACTIVE_ = TASK_STATE_UNINITIALIZED;
static long _PARKED_ = TASK_STATE_UNINITIALIZED;
static long _NOLOAD_ = TASK_STATE_UNINITIALIZED;
static long _NEW_ = TASK_STATE_UNINITIALIZED;

#define valid_task_state(X) ((X) != TASK_STATE_UNINITIALIZED)

static void
dump_task_states(void)
{
	int hi, lo;

	fprintf(fp, "           RUNNING: %3ld (0x%lx)\n", 
		_RUNNING_, _RUNNING_);

	fprintf(fp, "     INTERRUPTIBLE: %3ld (0x%lx)\n", 
		_INTERRUPTIBLE_, _INTERRUPTIBLE_);

	fprintf(fp, "   UNINTERRUPTIBLE: %3ld (0x%lx)\n", 
		_UNINTERRUPTIBLE_, _UNINTERRUPTIBLE_);

	fprintf(fp, "           STOPPED: %3ld (0x%lx)\n", 
		_STOPPED_, _STOPPED_);

	if (valid_task_state(_TRACING_STOPPED_)) {
		if (count_bits_long(_TRACING_STOPPED_) > 1) {
			lo = lowest_bit_long(_TRACING_STOPPED_);
			hi = highest_bit_long(_TRACING_STOPPED_);
			fprintf(fp, 
			    "   TRACING_STOPPED: %3d and %d (0x%x and 0x%x)\n",
				1<<lo, 1<<hi, 1<<lo, 1<<hi);
		} else
			fprintf(fp, "   TRACING_STOPPED: %3ld (0x%lx)\n", 
				_TRACING_STOPPED_, _TRACING_STOPPED_);
	}

	fprintf(fp, "            ZOMBIE: %3ld (0x%lx)\n", 
		_ZOMBIE_, _ZOMBIE_);

	if (count_bits_long(_DEAD_) > 1) {
		lo = lowest_bit_long(_DEAD_);
		hi = highest_bit_long(_DEAD_);
		fprintf(fp, "              DEAD: %3d and %d (0x%x and 0x%x)\n", 
			1<<lo, 1<<hi, 1<<lo, 1<<hi); 
	} else
		fprintf(fp, "              DEAD: %3ld (0x%lx)\n", 
			_DEAD_, _DEAD_);

	if (valid_task_state(_NONINTERACTIVE_))
		fprintf(fp, "    NONINTERACTIVE: %3ld (0x%lx)\n", 
			_NONINTERACTIVE_, _NONINTERACTIVE_);

	if (valid_task_state(_SWAPPING_))
		fprintf(fp, "          SWAPPING: %3ld (0x%lx)\n", 
			_SWAPPING_, _SWAPPING_);

	if (valid_task_state(_EXCLUSIVE_))
		fprintf(fp, "         EXCLUSIVE: %3ld (0x%lx)\n", 
			_EXCLUSIVE_, _EXCLUSIVE_);

	if (valid_task_state(_WAKEKILL_) && valid_task_state(_WAKING_)) {
		if (_WAKEKILL_ < _WAKING_) {
			fprintf(fp, "          WAKEKILL: %3ld (0x%lx)\n", 
				_WAKEKILL_, _WAKEKILL_);
			fprintf(fp, "            WAKING: %3ld (0x%lx)\n", 
				_WAKING_, _WAKING_);
		} else {
			fprintf(fp, "            WAKING: %3ld (0x%lx)\n", 
				_WAKING_, _WAKING_);
			fprintf(fp, "          WAKEKILL: %3ld (0x%lx)\n", 
				_WAKEKILL_, _WAKEKILL_);
		}
	}

	if (valid_task_state(_PARKED_))
		fprintf(fp, "            PARKED: %3ld (0x%lx)\n", 
			_PARKED_, _PARKED_);

	if (valid_task_state(_NOLOAD_))
		fprintf(fp, "            NOLOAD: %3ld (0x%lx)\n", 
			_NOLOAD_, _NOLOAD_);

	if (valid_task_state(_NEW_))
		fprintf(fp, "               NEW: %3ld (0x%lx)\n",
			_NEW_, _NEW_);
}


/*
 *  Initialize the task state fields based upon the kernel's task_state_array
 *  string table.
 */
static void
initialize_task_state(void)
{
	int i, len;
	ulong bitpos;
	ulong str, task_state_array;
	char buf[BUFSIZE];

	if (!symbol_exists("task_state_array") ||
	    !readmem(task_state_array = symbol_value("task_state_array"),
            KVADDR, &str, sizeof(void *),
            "task_state_array", RETURN_ON_ERROR)) {
old_defaults:
		_RUNNING_ = 0;
		_INTERRUPTIBLE_ = 1;
		_UNINTERRUPTIBLE_ = 2;
		_ZOMBIE_ = 4;
		_STOPPED_ = 8;
		_SWAPPING_ = 16;
		_EXCLUSIVE_ = 32;
		return;
	}

	/*
	 *  If the later version of stat_nam[] array exists that contains 
	 *  WAKING, WAKEKILL and PARKED, use it instead of task_state_array[].
	 *  Available since kernel version 2.6.33 to 4.13.
	 */
	if (((len = get_array_length("stat_nam", NULL, 0)) > 0) &&
	    read_string(symbol_value("stat_nam"), buf, BUFSIZE-1) &&
	    ascii_string(buf) && (strlen(buf) > strlen("RSDTtZX"))) {
		for (i = 0; i < strlen(buf); i++) {
			switch (buf[i]) 
			{
			case 'R':
				_RUNNING_ = i;
				break;
			case 'S':
				_INTERRUPTIBLE_ = i;
				break;
			case 'D':
				_UNINTERRUPTIBLE_ = (1 << (i-1));
				break;
			case 'T':
				_STOPPED_ = (1 << (i-1));
				break;
			case 't':
				_TRACING_STOPPED_ = (1 << (i-1));
				break;
			case 'X':
				if (_DEAD_ == UNINITIALIZED)
					_DEAD_ = (1 << (i-1));
				else
					_DEAD_ |= (1 << (i-1));
				break;
			case 'Z':
				_ZOMBIE_ = (1 << (i-1));
				break;
			case 'x':
				if (_DEAD_ == UNINITIALIZED)
					_DEAD_ = (1 << (i-1));
				else
					_DEAD_ |= (1 << (i-1));
				break;
			case 'K':
				_WAKEKILL_ = (1 << (i-1));
				break;
			case 'W':
				_WAKING_ = (1 << (i-1));
				break;
			case 'P':
				_PARKED_ = (1 << (i-1));
				break;
			case 'N':
				_NOLOAD_ = (1 << (i-1));
				break;
			case 'n':
				_NEW_ = (1 << (i-1));
				break;
			}
		}

		goto done_states;
	} 
		
	if ((len = get_array_length("task_state_array", NULL, 0)) <= 0)
		goto old_defaults;
	bitpos = 0;
	for (i = 0; i < len; i++) {
		if (!read_string(str, buf, BUFSIZE-1))
			break;

		if (CRASHDEBUG(3)) 
			fprintf(fp, "%s%s[%d][%s]\n", bitpos ? "" : "\n", 
				i < 10 ? " " : "", i, buf);

		if (strstr(buf, "(running)"))
			_RUNNING_ = bitpos;
		else if (strstr(buf, "(sleeping)"))
			_INTERRUPTIBLE_ = bitpos;
		else if (strstr(buf, "(disk sleep)"))
			_UNINTERRUPTIBLE_ = bitpos;
		else if (strstr(buf, "(stopped)"))
			_STOPPED_ = bitpos;
		else if (strstr(buf, "(zombie)"))
			_ZOMBIE_ = bitpos;
		else if (strstr(buf, "(dead)")) {
			if (_DEAD_ == TASK_STATE_UNINITIALIZED)
				_DEAD_ = bitpos;
			else
				_DEAD_ |= bitpos;
		} else if (strstr(buf, "(swapping)"))  /* non-existent? */
			_SWAPPING_ = bitpos;
		else if (strstr(buf, "(tracing stop)")) {
			if (_TRACING_STOPPED_ == TASK_STATE_UNINITIALIZED)
				_TRACING_STOPPED_ = bitpos;
			else
				_TRACING_STOPPED_ |= bitpos;
		} else if (strstr(buf, "(wakekill)"))
			_WAKEKILL_ = bitpos;
		else if (strstr(buf, "(waking)"))
			_WAKING_ = bitpos;
		else if (strstr(buf, "(parked)"))
			_PARKED_ = bitpos;

		if (!bitpos)
			bitpos = 1;
		else
			bitpos = bitpos << 1;

		task_state_array += sizeof(void *);
		if (!readmem(task_state_array, KVADDR, &str, sizeof(void *),
              	    "task_state_array", RETURN_ON_ERROR))
			break;
	}

	if ((THIS_KERNEL_VERSION >= LINUX(2,6,16)) && 
	    (THIS_KERNEL_VERSION < LINUX(2,6,24))) {
		_NONINTERACTIVE_ = 64;
	}

	if (THIS_KERNEL_VERSION >= LINUX(4,14,0)) {
		if (valid_task_state(_PARKED_)) {
			bitpos = _PARKED_;
			_DEAD_ |= (bitpos << 1);    /* TASK_DEAD */
			_WAKEKILL_ = (bitpos << 2); /* TASK_WAKEKILL */
			_WAKING_ = (bitpos << 3);   /* TASK_WAKING */
			_NOLOAD_ = (bitpos << 4);   /* TASK_NOLOAD */
			_NEW_ = (bitpos << 5);      /* TASK_NEW */
		}
	} else if (THIS_KERNEL_VERSION >= LINUX(2,6,32)) {
		/*
	 	 * Account for states not listed in task_state_array[]
		 */
		if (count_bits_long(_DEAD_) == 1) {
			bitpos = 1<< lowest_bit_long(_DEAD_);
			_DEAD_ |= (bitpos<<1);    /* TASK_DEAD */
			_WAKEKILL_ = (bitpos<<2); /* TASK_WAKEKILL */
			_WAKING_ = (bitpos<<3);   /* TASK_WAKING */
		}
	}

done_states:
	if (CRASHDEBUG(3))
		dump_task_states();

	if (!valid_task_state(_RUNNING_) ||
	    !valid_task_state(_INTERRUPTIBLE_) ||
	    !valid_task_state(_UNINTERRUPTIBLE_) ||
	    !valid_task_state(_ZOMBIE_) ||
	    !valid_task_state(_STOPPED_)) {
		if (CRASHDEBUG(3))
			fprintf(fp, 
			    "initialize_task_state: using old defaults\n");
		goto old_defaults;
	}
}

/*
 *  Print multiple state strings if appropriate.
 */
static char *
task_state_string_verbose(ulong task, char *buf)
{
	long state, both;
	int count;

	state = task_state(task);

	buf[0] = NULLCHAR;
	count = 0;

	if (state == _RUNNING_) {
		sprintf(buf, "TASK_RUNNING");
		return buf;
	}

	if (state & _INTERRUPTIBLE_)
		sprintf(&buf[strlen(buf)], "%sTASK_INTERRUPTIBLE",
			count++ ? "|" : "");

	if (state & _UNINTERRUPTIBLE_)
		sprintf(&buf[strlen(buf)], "%sTASK_UNINTERRUPTIBLE",
			count++ ? "|" : "");

	if (state & _STOPPED_)
		sprintf(&buf[strlen(buf)], "%sTASK_STOPPED",
			count++ ? "|" : "");

	if (state & _TRACING_STOPPED_)
		sprintf(&buf[strlen(buf)], "%sTASK_TRACED",
			count++ ? "|" : "");

	if ((both = (state & _DEAD_))) {
		if (count_bits_long(both) > 1)
			sprintf(&buf[strlen(buf)], "%sEXIT_DEAD|TASK_DEAD",
				count++ ? "|" : "");
		else
			sprintf(&buf[strlen(buf)], "%sEXIT_DEAD",
				count++ ? "|" : "");
	}

	if (state & _ZOMBIE_)
		sprintf(&buf[strlen(buf)], "%sEXIT_ZOMBIE",
			count++ ? "|" : "");

	if (valid_task_state(_WAKING_) && (state & _WAKING_))
		sprintf(&buf[strlen(buf)], "%sTASK_WAKING",
			count++ ? "|" : "");

	if (valid_task_state(_WAKEKILL_) && (state & _WAKEKILL_))
		sprintf(&buf[strlen(buf)], "%sTASK_WAKEKILL",
			count++ ? "|" : "");

	if (valid_task_state(_NOLOAD_) && (state & _NOLOAD_))
		sprintf(&buf[strlen(buf)], "%sTASK_NOLOAD",
			count++ ? "|" : "");

	if (valid_task_state(_NEW_) && (state & _NEW_))
		sprintf(&buf[strlen(buf)], "%sTASK_NEW",
			count++ ? "|" : "");

	if (valid_task_state(_NONINTERACTIVE_) &&
	    (state & _NONINTERACTIVE_))
		sprintf(&buf[strlen(buf)], "%sTASK_NONINTERACTIVE",
			count++ ? "|" : "");

	if (state == _PARKED_) {
		sprintf(buf, "TASK_PARKED");
		return buf;
	}

	return buf;
}

char *
task_state_string(ulong task, char *buf, int verbose)
{
	long state;
	int exclusive;
	int valid, set;

	if (_RUNNING_ == TASK_STATE_UNINITIALIZED) 
		initialize_task_state();

	if (verbose)
		return task_state_string_verbose(task, buf);

	if (buf)
		sprintf(buf, verbose ? "(unknown)" : "??");

	state = task_state(task);

	set = valid = exclusive = 0;
	if (valid_task_state(_EXCLUSIVE_)) {
		exclusive = state & _EXCLUSIVE_;
		state &= ~(_EXCLUSIVE_);
	}

	if (state == _RUNNING_) {
		sprintf(buf, "RU"); 
		valid++;
	}

	if (state & _INTERRUPTIBLE_) { 
		sprintf(buf, "IN"); 
		valid++; 
		set++;
	}

	if (state & _UNINTERRUPTIBLE_) {
		if (valid_task_state(_NOLOAD_) &&
		    (state & _NOLOAD_))
			sprintf(buf, "ID");
		else
			sprintf(buf, "UN");
		valid++; 
		set++;
	}

	if (state & _ZOMBIE_) {
		sprintf(buf, "ZO"); 
		valid++; 
		set++;
	}

	if (state & _STOPPED_) {
		sprintf(buf, "ST"); 
		valid++; 
		set++;
	}

	if (valid_task_state(_TRACING_STOPPED_) &&
	    (state & _TRACING_STOPPED_)) {
		sprintf(buf, "TR"); 
		valid++; 
		set++;
	}

	if (state == _SWAPPING_) {
		sprintf(buf, "SW"); 
		valid++; 
		set++;
	}

	if ((state & _DEAD_) && !set) {
		sprintf(buf, "DE"); 
		valid++; 
		set++;
	}

	if (state == _PARKED_) {
		sprintf(buf, "PA"); 
		valid++;
	}

	if (state == _WAKING_) {
		sprintf(buf, "WA"); 
		valid++;
	}

	if (state == _NEW_) {
		sprintf(buf, "NE");
		valid++;
	}

	if (valid && exclusive) 
		strcat(buf, "EX");

	return buf;
}

/*
 *  Return a task's state and exit_state together.
 */
ulong
task_state(ulong task)
{
        ulong state, exit_state;

	fill_task_struct(task);

	if (!tt->last_task_read)
		return 0;

	if (SIZE(task_struct_state) == sizeof(ulong))
		state = ULONG(tt->task_struct + OFFSET(task_struct_state));
	else
		state = UINT(tt->task_struct + OFFSET(task_struct_state));
	exit_state = VALID_MEMBER(task_struct_exit_state) ?
		ULONG(tt->task_struct + OFFSET(task_struct_exit_state)) : 0;

        return (state | exit_state);
}

/*
 *  Return a task's flags.
 */
ulong
task_flags(ulong task)
{
	ulong flags;

	fill_task_struct(task);

	if (tt->last_task_read) {
		if (SIZE(task_struct_flags) == sizeof(unsigned int))
			flags = UINT(tt->task_struct +
				     OFFSET(task_struct_flags));
		else
			flags = ULONG(tt->task_struct +
				      OFFSET(task_struct_flags));
	} else
		flags = 0;

	return flags;
}

/*
 * Return task's policy as bitmask bit.
 */
static ulong
task_policy(ulong task)
{
	ulong policy = 0;

	fill_task_struct(task);

	if (!tt->last_task_read)
		return policy;

	if (SIZE(task_struct_policy) == sizeof(unsigned int))
		policy = 1 << UINT(tt->task_struct + OFFSET(task_struct_policy));
	else
		policy = 1 << ULONG(tt->task_struct + OFFSET(task_struct_policy));

	return policy;
}

/*
 *  Return a task's tgid.
 */
ulong
task_tgid(ulong task)
{
        uint tgid;

        fill_task_struct(task);

        tgid = tt->last_task_read ?
                 UINT(tt->task_struct + OFFSET(task_struct_tgid)) : 0;

        return (ulong)tgid;
}

ulonglong
task_last_run(ulong task)
{
        ulong last_run;
	ulonglong timestamp;

	timestamp = 0;
        fill_task_struct(task);

	if (VALID_MEMBER(task_struct_last_run)) {
        	last_run = tt->last_task_read ?  ULONG(tt->task_struct + 
			OFFSET(task_struct_last_run)) : 0;
		timestamp = (ulonglong)last_run;
	} else if (VALID_MEMBER(task_struct_timestamp))
        	timestamp = tt->last_task_read ?  ULONGLONG(tt->task_struct + 
			OFFSET(task_struct_timestamp)) : 0;
	else if (VALID_MEMBER(sched_info_last_arrival))
        	timestamp = tt->last_task_read ?  ULONGLONG(tt->task_struct + 
			OFFSET(task_struct_sched_info) + 
			OFFSET(sched_info_last_arrival)) : 0;
	
        return timestamp;
}

/*
 *  Return a task's mm_struct address.  If "fill" is set, the mm_struct
 *  cache is loaded.
 */
ulong
task_mm(ulong task, int fill)
{
	ulong mm_struct;

	fill_task_struct(task);

	if (!tt->last_task_read)
		return 0;

	mm_struct = ULONG(tt->task_struct + OFFSET(task_struct_mm));

	if (fill && mm_struct)
		fill_mm_struct(mm_struct);

	return mm_struct;
}

/*
 *  Translate a processor number into a string, taking NO_PROC_ID into account.
 */
char *
task_cpu(int processor, char *buf, int verbose)
{
	if (processor < NR_CPUS)
		sprintf(buf, "%d", processor);
	else
		sprintf(buf, verbose ? "(unknown)" : "?");

        return buf;
}

/*
 *  Check either the panic_threads[] array on a dump, or the has_cpu flag 
 *  of a task_struct on a live system.  Also account for deprecation of
 *  usage of has_cpu on non-SMP systems.
 */
int
is_task_active(ulong task)
{
	int has_cpu;

	if (LOCAL_ACTIVE() && (task == tt->this_task))
		return TRUE;
	if (DUMPFILE() && is_panic_thread(task))
		return TRUE;

        fill_task_struct(task);

	has_cpu = tt->last_task_read ?
		task_has_cpu(task, tt->task_struct) : 0;

	return(has_cpu);
}

/*
 *  Return true if a task is the panic_task or is contained within the 
 *  panic_threads[] array.
 */
int
is_panic_thread(ulong task)
{
	int i;

        if (DUMPFILE()) {
		if (tt->panic_task == task)
			return TRUE;

                for (i = 0; i < NR_CPUS; i++)
                        if (tt->panic_threads[i] == task)
                                return TRUE;
        }

	return FALSE;
}

/*
 *  Depending upon the kernel, check the task_struct's has_cpu or cpus_runnable 
 *  field if either exist, or the global runqueues[].curr via get_active_set()
 *  to determine whether a task is running on a cpu. 
 */
static int
task_has_cpu(ulong task, char *local_task) 
{
	int i, has_cpu;
	ulong cpus_runnable;

	if (DUMPFILE() && (task == tt->panic_task))  /* no need to continue */
		return TRUE;

	if (VALID_MEMBER(task_struct_has_cpu)) {
		if (local_task) 
			has_cpu = INT(local_task+OFFSET(task_struct_has_cpu));
		else if (!readmem((ulong)(task+OFFSET(task_struct_has_cpu)), 
			KVADDR, &has_cpu, sizeof(int), 
		    	"task_struct has_cpu", RETURN_ON_ERROR))
				has_cpu = FALSE;	
	} else if (VALID_MEMBER(task_struct_cpus_runnable)) {
                if (local_task) 
                        cpus_runnable = ULONG(local_task +
				OFFSET(task_struct_cpus_runnable));
		else if (!readmem((ulong)(task + 
			OFFSET(task_struct_cpus_runnable)),
                        KVADDR, &cpus_runnable, sizeof(ulong),
                        "task_struct cpus_runnable", RETURN_ON_ERROR))
                                cpus_runnable = ~0UL;
		has_cpu = (cpus_runnable != ~0UL);
	} else if (get_active_set()) {
                for (i = 0, has_cpu = FALSE; i < NR_CPUS; i++) {
                        if (task == tt->active_set[i]) {
				has_cpu = TRUE;
				break;
			}
		}
	} else
		error(FATAL, 
    "task_struct has no has_cpu, or cpus_runnable; runqueues[] not defined?\n");

	return has_cpu;
}


/*
 *  If a task is in the panic_threads array and has an associated panic_ksp
 *  array entry, return it.
 */
int
get_panic_ksp(struct bt_info *bt, ulong *ksp)
{
	int i;

	if (tt->flags & PANIC_KSP) {
        	for (i = 0; i < NR_CPUS; i++) {
        		if ((tt->panic_threads[i] == bt->task) && 
			     tt->panic_ksp[i] &&
			     INSTACK(tt->panic_ksp[i], bt)) {
				*ksp = tt->panic_ksp[i];
				return TRUE;
			}
		}
	}
	return FALSE;
}


/*
 *  Look for kcore's storage information for the system's panic state.
 *  If it's not there (somebody else's dump format?), look through all
 *  the stack traces or the log buffer for evidence of panic.
 */
static ulong
get_panic_context(void)
{
	int i;
        struct task_context *tc;
	ulong panic_threads_addr;
	ulong task;
	char *tp;

        for (i = 0; i < NR_CPUS; i++) {
                if (!(task = tt->active_set[i]))
			continue;

		if (!task_exists(task)) {
			error(WARNING, 
			  "active task %lx on cpu %d not found in PID hash\n\n",
				task, i);
			if ((tp = fill_task_struct(task)))
				add_context(task, tp);
		}
	}

	/* 
	 *  --no_panic command line option
	 */
	if (tt->flags & PANIC_TASK_NOT_FOUND) 
		goto use_task_0;

	tt->panic_processor = -1;
	task = NO_TASK;
        tc = FIRST_CONTEXT();

	if (symbol_exists("panic_threads") &&
	    symbol_exists("panicmsg") &&
	    symbol_exists("panic_processor")) {
		panic_threads_addr = symbol_value("panic_threads");
		get_symbol_data("panic_processor", sizeof(int), 
			&tt->panic_processor);
		get_symbol_data("panicmsg", sizeof(char *), &tt->panicmsg);
	
		if (!readmem(panic_threads_addr, KVADDR, tt->panic_threads,
		    sizeof(void *)*NR_CPUS, "panic_processor array", 
		    RETURN_ON_ERROR))
			goto use_task_0;
	
		task = tt->panic_threads[tt->panic_processor];

		if (symbol_exists("panic_ksp")) {
			if (!(tt->panic_ksp = (ulong *)
			     calloc(NR_CPUS, sizeof(void *))))
				error(FATAL, 
					"cannot malloc panic_ksp array.\n");
		    	readmem(symbol_value("panic_ksp"), KVADDR, 
			    tt->panic_ksp,
		            sizeof(void *)*NR_CPUS, "panic_ksp array", 
		            RETURN_ON_ERROR);
			tt->flags |= PANIC_KSP;
		}

		if (machdep->flags & HWRESET) {
			populate_panic_threads();
			task = tt->panic_threads[0];
		}
	}

	if (task && task_exists(task)) 
		return(tt->panic_task = task);

	if (task) 
		error(INFO, "reported panic task %lx does not exist!\n\n", 
			task);

	if ((tc = panic_search())) {
		tt->panic_processor = tc->processor;
		return(tt->panic_task = tc->task);
	}

use_task_0:

	if (CRASHDEBUG(1))
		error(INFO, "get_panic_context: panic task not found\n");

	tt->flags |= PANIC_TASK_NOT_FOUND;
	tc = FIRST_CONTEXT();
        return(tc->task);
}

/*
 *  Get the active task on a cpu -- from a dumpfile only.
 */
ulong
get_active_task(int cpu)
{
	int i;
	ulong task;
        struct task_context *tc;

	if (DUMPFILE() && (task = tt->panic_threads[cpu]))
		return task;

        tc = FIRST_CONTEXT();
        for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
                if ((tc->processor == cpu) && is_task_active(tc->task))
                	return(tc->task);
	}

	return NO_TASK;
}


/*
 *  Read the panic string.
 */
char *
get_panicmsg(char *buf)
{
	int msg_found;

        BZERO(buf, BUFSIZE);
	msg_found = FALSE;

	if (tt->panicmsg) {
		read_string(tt->panicmsg, buf, BUFSIZE-1);
		msg_found = TRUE;
	} else if (LKCD_DUMPFILE()) {
		get_lkcd_panicmsg(buf);
		msg_found = TRUE;
	}

        if (msg_found == TRUE)
                return(buf);

	open_tmpfile();
	dump_log(SHOW_LOG_TEXT);

	/*
	 *  First check for a SYSRQ-generated crash, and set the
	 *  active-task flag appropriately.  The message may or
	 *  may not be used as the panic message.
	 */
        rewind(pc->tmpfile);
        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
                if (strstr(buf, "SysRq : Crash") ||
		    strstr(buf, "SysRq : Trigger a crash")) {
			pc->flags |= SYSRQ;
			break;
		}
	}
	rewind(pc->tmpfile);
	while (!msg_found && fgets(buf, BUFSIZE, pc->tmpfile)) {
		if (strstr(buf, "general protection fault: ") ||
		    strstr(buf, "double fault: ") ||
		    strstr(buf, "divide error: ") ||
		    strstr(buf, "stack segment: ")) {
			msg_found = TRUE;
			break;
		}
	}
        rewind(pc->tmpfile);
        while (!msg_found && fgets(buf, BUFSIZE, pc->tmpfile)) {
                if (strstr(buf, "SysRq : Netdump") ||
		    strstr(buf, "SysRq : Crash") ||
		    strstr(buf, "SysRq : Trigger a crash")) {
			pc->flags |= SYSRQ;
                        msg_found = TRUE;
			break;
		}
        }
	rewind(pc->tmpfile);
	while (!msg_found && fgets(buf, BUFSIZE, pc->tmpfile)) {
	        if (strstr(buf, "Oops: ") ||
		    strstr(buf, "Kernel BUG at") ||
		    strstr(buf, "kernel BUG at") ||
		    strstr(buf, "Unable to handle kernel paging request") ||
		    strstr(buf, "Unable to handle kernel NULL pointer dereference") ||
		    strstr(buf, "BUG: unable to handle kernel "))
	        	msg_found = TRUE;
	}
        rewind(pc->tmpfile);
        while (!msg_found && fgets(buf, BUFSIZE, pc->tmpfile)) {
                if (strstr(buf, "sysrq") && 
		    symbol_exists("sysrq_pressed")) { 
			get_symbol_data("sysrq_pressed", sizeof(int), 
				&msg_found);
			break;
		}
        }
	rewind(pc->tmpfile);
	while (!msg_found && fgets(buf, BUFSIZE, pc->tmpfile)) {
		if (strstr(buf, "Kernel panic: ") ||
		    strstr(buf, "Kernel panic - ")) { 
			msg_found = TRUE;
			break;
		}
	}
	rewind(pc->tmpfile);
	while (!msg_found && fgets(buf, BUFSIZE, pc->tmpfile)) {
		if (strstr(buf, "[Hardware Error]: ")) {
			msg_found = TRUE;
			break;
		}
	}
	rewind(pc->tmpfile);
	while (!msg_found && fgets(buf, BUFSIZE, pc->tmpfile)) {
		if (strstr(buf, "Bad mode in ")) {
			msg_found = TRUE;
			break;
		}
	}

        close_tmpfile();

	if (!msg_found)
       		BZERO(buf, BUFSIZE);

	return(buf);
}

/*
 *  This command allows the running of a set of commands on any or all 
 *  tasks running on a system.  The target tasks may be designated by
 *  pid, task or command name.  The available command set is designated by 
 *  the FOREACH_xxx definitions below.  If a running command name string
 *  conflicts with a foreach command, the command name string may be
 *  prefixed with a \ character.
 */

void
cmd_foreach(void)
{
	int a, c, k, t, p;
	ulong value;
	static struct foreach_data foreach_data;
	struct foreach_data *fd;
	struct task_context *tc;
	char *p1;
	int key;

	BZERO(&foreach_data, sizeof(struct foreach_data));
	fd = &foreach_data;

        while ((c = getopt(argcnt, args, "R:vomlgersStTpukcfFxhdaGy:")) != EOF) {
                switch(c)
		{
		case 'R':
			fd->reference = optarg;
			break;

		case 'h':
		case 'x':
			fd->flags |= FOREACH_x_FLAG;
			break;

		case 'd':
			fd->flags |= FOREACH_d_FLAG;
			break;

		case 'v':
			fd->flags |= FOREACH_v_FLAG;
			break;

		case 'm':
			fd->flags |= FOREACH_m_FLAG;
			break;

		case 'l':
			fd->flags |= FOREACH_l_FLAG;
			break;

		case 'o':
                        fd->flags |= FOREACH_o_FLAG;
                        break;

		case 'g':
			fd->flags |= FOREACH_g_FLAG;
			break;

		case 'e':
			fd->flags |= FOREACH_e_FLAG;
			break;

		case 's':
			fd->flags |= FOREACH_s_FLAG;
			break;

		case 'S':
			fd->flags |= FOREACH_S_FLAG;
			break;

		case 'r':
			fd->flags |= FOREACH_r_FLAG;
			break;

		case 'T':
			fd->flags |= FOREACH_T_FLAG;
			break;

		case 't':
			fd->flags |= FOREACH_t_FLAG;
			break;

		case 'p':
			fd->flags |= FOREACH_p_FLAG;
			break;

                case 'u':
                        fd->flags |= FOREACH_u_FLAG;
                        break;

                case 'k':
                        fd->flags |= FOREACH_k_FLAG;
                        break;

		case 'c':
                        fd->flags |= FOREACH_c_FLAG;
                        break;

		case 'f':
			fd->flags |= FOREACH_f_FLAG;
			break;

		case 'F':
			if (fd->flags & FOREACH_F_FLAG)
				fd->flags |= FOREACH_F_FLAG2;
			else
				fd->flags |= FOREACH_F_FLAG;
			break;

		case 'a':
			fd->flags |= FOREACH_a_FLAG;
			break;

		case 'G':
			fd->flags |= FOREACH_G_FLAG;
			break;

		case 'y':
			fd->flags |= FOREACH_y_FLAG;
			fd->policy = make_sched_policy(optarg);
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs || !args[optind])
		cmd_usage(pc->curcmd, SYNOPSIS);

	a = c = k = t = p = 0;

	while (args[optind]) {
		/*
		 *  Once a keyword has been entered, then only accept
		 *  command arguments.
		 */
		if (k) {
			p1 = args[optind];
			goto command_argument;
		}

		/*
		 *  If it's a keyword, grab it and check no further.
		 */
                if (is_foreach_keyword(args[optind], &key)) {
			if (k == MAX_FOREACH_KEYWORDS)
				error(INFO, "too many keywords!\n");
			else 
                        	fd->keyword_array[k++] = key;
                        optind++;
                        continue;
                }

		/*
		 *  If it's a task pointer or pid, take it.
		 */
                if (IS_A_NUMBER(args[optind])) {
			if (STREQ(args[optind], "DE") && pid_exists(0xde)) {
				error(INFO, "ambiguous task-identifying argument: %s\n", args[optind]);
				error(CONT, "for a \"state\" argument, use: \\DE\n");
				error(CONT, "for a \"pid\" argument, use: 0xDE, 0xde, de or 222\n\n");
				cmd_usage(pc->curcmd, SYNOPSIS);
				return;
			}

			switch (str_to_context(args[optind], &value, &tc))
			{
			case STR_PID:
                                if (p == MAX_FOREACH_PIDS)
                                        error(INFO,
                                            "too many pids specified!\n");
                                else {
                                        fd->pid_array[p++] = value;
                                        fd->flags |= FOREACH_SPECIFIED;
                                }
				optind++;
				continue;

			case STR_TASK:
                                if (t == MAX_FOREACH_TASKS)
                                        error(INFO,
                                            "too many tasks specified!\n");
                                else {
                                        fd->task_array[t++] = value;
                                        fd->flags |= FOREACH_SPECIFIED;
                                }
				optind++;
				continue;

			case STR_INVALID:
				break;
			}
                }

		/*
		 *  Select all kernel threads.
		 */
		if (STREQ(args[optind], "kernel")) {
			if (fd->flags & FOREACH_USER)
				error(FATAL,
				   "user and kernel are mutually exclusive!\n");
			fd->flags |= FOREACH_KERNEL;
			optind++;
			continue;
		}

		if ((args[optind][0] == '\\') &&
		    STREQ(&args[optind][1], "DE"))
			shift_string_left(args[optind], 1);

		if (STREQ(args[optind], "RU") ||
		    STREQ(args[optind], "IN") ||
		    STREQ(args[optind], "UN") ||
		    STREQ(args[optind], "ST") ||
		    STREQ(args[optind], "TR") ||
		    STREQ(args[optind], "ZO") ||
		    STREQ(args[optind], "DE") ||
		    STREQ(args[optind], "PA") ||
		    STREQ(args[optind], "WA") ||
		    STREQ(args[optind], "ID") ||
		    STREQ(args[optind], "NE") ||
		    STREQ(args[optind], "SW")) {

			ulong state = TASK_STATE_UNINITIALIZED;

			if (fd->flags & FOREACH_STATE)
				error(FATAL, "only one task state allowed\n");

			if (STREQ(args[optind], "RU"))
				state = _RUNNING_;
			else if (STREQ(args[optind], "IN"))
				state = _INTERRUPTIBLE_;
			else if (STREQ(args[optind], "UN"))
				state = _UNINTERRUPTIBLE_;
			else if (STREQ(args[optind], "ST"))
				state = _STOPPED_;
			else if (STREQ(args[optind], "TR"))
				state = _TRACING_STOPPED_;
			else if (STREQ(args[optind], "ZO"))
				state = _ZOMBIE_;
			else if (STREQ(args[optind], "DE"))
				state = _DEAD_;
			else if (STREQ(args[optind], "SW"))
				state = _SWAPPING_;
			else if (STREQ(args[optind], "PA"))
				state = _PARKED_;
			else if (STREQ(args[optind], "WA"))
				state = _WAKING_;
			else if (STREQ(args[optind], "ID"))
				state = _UNINTERRUPTIBLE_|_NOLOAD_;
			else if (STREQ(args[optind], "NE"))
				state = _NEW_;

			if (state == TASK_STATE_UNINITIALIZED)
				error(FATAL, 
				    "invalid task state for this kernel: %s\n",
					args[optind]);

			fd->state = args[optind];
			fd->flags |= FOREACH_STATE;

			optind++;
			continue;
		}

		/*
		 *  Select only user threads.
		 */
                if (STREQ(args[optind], "user")) {
                        if (fd->flags & FOREACH_KERNEL)
                                error(FATAL, 
                                   "user and kernel are mutually exclusive!\n");
			fd->flags |= FOREACH_USER;
                        optind++;
                        continue;
                }

		/*
		 *  Select only user-space thread group leaders
		 */
		if (STREQ(args[optind], "gleader")) {
			if (fd->flags & FOREACH_KERNEL)
				error(FATAL,
					"gleader and kernel are mutually exclusive!\n");
			fd->flags |= (FOREACH_USER|FOREACH_GLEADER);
			optind++;
			continue;
		}

		/* 
		 *  Select only active tasks (dumpfile only)
	  	 */
                if (STREQ(args[optind], "active")) {
			if (!DUMPFILE())
				error(FATAL, 
				    "active option not allowed on live systems\n");
                        fd->flags |= FOREACH_ACTIVE;
                        optind++;
                        continue;
                }

		/*
		 *  Regular expression is exclosed within "'" character.
		 *  The args[optind] string may not be modified, so a copy 
		 *  is duplicated.
		 */
		if (SINGLE_QUOTED_STRING(args[optind])) {
			if (fd->regexs == MAX_REGEX_ARGS)
				error(INFO, "too many expressions specified!\n");
			else {
				p1 = strdup(&args[optind][1]);
				LASTCHAR(p1) = NULLCHAR;
				
				if (regcomp(&fd->regex_info[fd->regexs].regex, p1, 
				    REG_EXTENDED|REG_NOSUB)) {
					error(INFO, 
					    "invalid regular expression: %s\n", 
						p1);
					free(p1);
					goto bailout;
				}

				fd->regex_info[fd->regexs].pattern = p1;
				if (fd->regexs++ == 0) {
					pc->cmd_cleanup_arg = (void *)fd;
					pc->cmd_cleanup = foreach_cleanup;
				}
			}
			optind++;
			continue;
		}

		/*
	         *  If it's a command name, prefixed or otherwise, take it.
		 */
		p1 = (args[optind][0] == '\\') ? 
			&args[optind][1] : args[optind];

		if (comm_exists(p1)) {
			if (c == MAX_FOREACH_COMMS)
				error(INFO, "too many commands specified!\n");
			else {
				fd->comm_array[c++] = p1;
				fd->flags |= FOREACH_SPECIFIED;
			}
			optind++;
			continue;
		} 

command_argument:
		/*
	 	 *  If no keyword has been entered, we don't know what this
		 *  is -- most likely it's a bogus command specifier. We set
		 *  FOREACH_SPECIFIED in case it was a bad specifier and no
		 *  other task selectors exist -- which in turn would causes
		 *  the command to be erroneously run on all tasks.
	 	 */
		if (!k) {
			fd->flags |= FOREACH_SPECIFIED;
			error(INFO, "unknown argument: \"%s\"\n",
				args[optind]);
			optind++;
			continue;
		}

                /*  
                 *  Must be an command argument -- so store it and let
                 *  the command deal with it...
                 */
		if (a == MAX_FOREACH_ARGS)
			error(INFO, "too many arguments specified!\n");
		else
               		fd->arg_array[a++] = (ulong)p1;

		optind++;
	}

	fd->flags |= FOREACH_CMD;
	fd->pids = p;
	fd->keys = k;
	fd->comms = c;
	fd->tasks = t;
	fd->args = a;

	if (fd->keys)
		foreach(fd);
	else
		error(INFO, "no keywords specified\n");
bailout:
	foreach_cleanup((void *)fd);
}

/*
 *  Do the work for cmd_foreach().
 */
void
foreach(struct foreach_data *fd)
{
        int i, j, k, a;
        struct task_context *tc, *tgc;
	int specified;
	int doit;
	int subsequent;
	unsigned int radix;
	ulong cmdflags; 
	ulong tgid;
	struct reference reference, *ref;
	int print_header;
	struct bt_info bt_info, *bt;
	char buf[TASK_COMM_LEN];
	struct psinfo psinfo;

	/* 
	 *  Filter out any command/option issues.
	 */
	if (CRASHDEBUG(1)) {
		fprintf(fp, "        flags: %lx\n", fd->flags);
		fprintf(fp, "   task_array: %s", fd->tasks ? "" : "(none)");
                for (j = 0; j < fd->tasks; j++)
			fprintf(fp, "[%lx] ", fd->task_array[j]); 
		fprintf(fp, "\n");

		fprintf(fp, "    pid_array: %s", fd->pids ? "" : "(none)");
                for (j = 0; j < fd->pids; j++)
			fprintf(fp, "[%ld] ", fd->pid_array[j]); 
		fprintf(fp, "\n");

		fprintf(fp, "   comm_array: %s", fd->comms ? "" : "(none)");
                for (j = 0; j < fd->comms; j++)
			fprintf(fp, "[%s] ", fd->comm_array[j]); 
		fprintf(fp, "\n");

		fprintf(fp, "   regex_info: %s", fd->regexs ? "" : "(none)\n");
                for (j = 0; j < fd->regexs; j++) {
			fprintf(fp, "%s[%d] pattern: [%s] ", 
				j ? "               " : "",
				j, fd->regex_info[j].pattern); 
			fprintf(fp, "regex: [%lx]\n", 
				(ulong)&fd->regex_info[j].regex); 
		}
		fprintf(fp, "\n");

		fprintf(fp, "keyword_array: %s", fd->keys ? "" : "(none)");
        	for (k = 0; k < fd->keys; k++) 
			fprintf(fp, "[%d] ", fd->keyword_array[k]);
		fprintf(fp, "\n");

		fprintf(fp, "    arg_array: %s", fd->args ? "" : "(none)");
		for (a = 0; a < fd->args; a++)
                	fprintf(fp, "[%lx (%s)] ", 
				fd->arg_array[a],
				(char *)fd->arg_array[a]);
		fprintf(fp, "\n");
		fprintf(fp, "    reference: \"%s\"\n", 
			fd->reference ?  fd->reference : "");
	}

	print_header = TRUE;
	bt = NULL;

        for (k = 0; k < fd->keys; k++) {
        	switch(fd->keyword_array[k])
                {
                case FOREACH_NET:
			switch (fd->flags & (FOREACH_s_FLAG|FOREACH_S_FLAG))
			{
			case (FOREACH_s_FLAG|FOREACH_S_FLAG):
				error(WARNING, 
			     "net -s and -S options are mutually exclusive!\n");
				fd->flags = FOREACH_s_FLAG;
				break;

			case 0:
				error(WARNING, 
				    "net command requires -s or -S option\n\n");
				fd->flags |= FOREACH_s_FLAG;
				break;
			}
			if ((fd->flags & (FOREACH_x_FLAG|FOREACH_d_FLAG)) ==
			    (FOREACH_x_FLAG|FOREACH_d_FLAG))
				error(FATAL, 
				    "net: -x and -d options are mutually exclusive\n");
			break;

		case FOREACH_VTOP:
			if (!fd->args)
			    	error(FATAL,
				    "foreach command requires address argument\n");
			if (fd->reference)
				error(FATAL,
				    "vtop command does not support -R option\n");
                        if ((fd->flags & (FOREACH_u_FLAG|FOREACH_k_FLAG)) ==
				(FOREACH_u_FLAG|FOREACH_k_FLAG))
                                error(FATAL,
				    "vtop: -u and -k options are mutually exclusive\n");
			break;

		case FOREACH_VM:
			if ((fd->flags & (FOREACH_x_FLAG|FOREACH_d_FLAG)) ==
			    (FOREACH_x_FLAG|FOREACH_d_FLAG))
				error(FATAL, 
				    "vm: -x and -d options are mutually exclusive\n");
                        if (count_bits_long(fd->flags &
                            (FOREACH_i_FLAG|FOREACH_p_FLAG|
                             FOREACH_m_FLAG|FOREACH_v_FLAG)) > 1)
				error(FATAL,
				    "vm command accepts only one of -p, -m or -v flags\n");
			if (fd->reference) {
				if (fd->flags & FOREACH_i_FLAG)
					error(FATAL,
					    "vm: -i is not applicable to the -R option\n");
				if (fd->flags & FOREACH_m_FLAG)
					error(FATAL,
					    "vm: -m is not applicable to the -R option\n");
				if (fd->flags & FOREACH_v_FLAG)
					error(FATAL,
					    "vm: -v is not applicable to the -R option\n");
			}
			break;

		case FOREACH_BT:
			if ((fd->flags & (FOREACH_x_FLAG|FOREACH_d_FLAG)) ==
			    (FOREACH_x_FLAG|FOREACH_d_FLAG))
				error(FATAL, 
				    "bt: -x and -d options are mutually exclusive\n");

                        if ((fd->flags & FOREACH_l_FLAG) && NO_LINE_NUMBERS()) {
				error(INFO, "line numbers are not available\n");
				fd->flags &= ~FOREACH_l_FLAG;
			}
#ifndef GDB_5_3
                        if ((fd->flags & FOREACH_g_FLAG))
                                error(FATAL,
				    "bt -g option is not supported when issued from foreach\n");
#endif
			bt = &bt_info;
			break;

		case FOREACH_TASK:
			if ((fd->flags & (FOREACH_x_FLAG|FOREACH_d_FLAG)) ==
			    (FOREACH_x_FLAG|FOREACH_d_FLAG))
				error(FATAL, 
				    "task: -x and -d options are mutually exclusive\n");
                        if (count_bits_long(fd->flags & 
			    (FOREACH_x_FLAG|FOREACH_d_FLAG)) > 1)
                                error(FATAL,
				    "task command accepts -R member[,member],"
				    " and either -x or -d flags\n");
			break;

		case FOREACH_SET:
			if (fd->reference)
				error(FATAL,
				    "set command does not support -R option\n");
			break;

                case FOREACH_SIG:
			if (fd->flags & (FOREACH_l_FLAG|FOREACH_s_FLAG))
				error(FATAL,
				    "sig: -l and -s options are not applicable\n");
			if (fd->flags & FOREACH_g_FLAG) {
				if (!hq_open()) {
                			error(INFO, 
					   "cannot hash thread group tasks\n");
					fd->flags &= ~FOREACH_g_FLAG;
				} else
					print_header = FALSE;
			}
                        break;

                case FOREACH_PS:
			if (count_bits_long(fd->flags & FOREACH_PS_EXCLUSIVE) > 1)
				error(FATAL, ps_exclusive);
			if ((fd->flags & (FOREACH_l_FLAG|FOREACH_m_FLAG)) &&
			    (fd->flags & FOREACH_G_FLAG))
				error(FATAL, "-G not supported with -%c option\n",
					fd->flags & FOREACH_l_FLAG ? 'l' : 'm');

			BZERO(&psinfo, sizeof(struct psinfo));
			if (fd->flags & FOREACH_G_FLAG) {
				if (!hq_open()) {
					error(INFO, 
					   "cannot hash thread group tasks\n");
					fd->flags &= ~FOREACH_G_FLAG;
				}
			}
			if (fd->flags & (FOREACH_l_FLAG|FOREACH_m_FLAG))
				sort_context_array_by_last_run();
			if ((fd->flags & FOREACH_m_FLAG) && 
			    INVALID_MEMBER(rq_timestamp))
				option_not_supported('m');

			print_header = FALSE;
			break;

		case FOREACH_FILES:
			if (fd->flags & FOREACH_p_FLAG)
				error(FATAL,
				    "files command does not support -p option\n");
			break;

		case FOREACH_TEST:
			break;
		}
	}

	
	subsequent = FALSE;
	specified = (fd->tasks || fd->pids || fd->comms || fd->regexs ||
		(fd->flags & FOREACH_SPECIFIED));
	ref = &reference;

        tc = FIRST_CONTEXT();

        for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
		doit = FALSE;

		if ((fd->flags & FOREACH_ACTIVE) && !is_task_active(tc->task))
			continue;

		if ((fd->flags & FOREACH_USER) && is_kernel_thread(tc->task))
			continue;

		if ((fd->flags & FOREACH_GLEADER) && tc->pid != task_tgid(tc->task))
			continue;

		if ((fd->flags & FOREACH_KERNEL) && !is_kernel_thread(tc->task))
			continue;

		if ((fd->flags & FOREACH_STATE) &&
		    (!STRNEQ(task_state_string(tc->task, buf, 0), fd->state)))
			continue;

		if (specified) {
			for (j = 0; j < fd->tasks; j++) {
				if (fd->task_array[j] == tc->task) {
					doit = TRUE;
					break;
				}
			}
	
			for (j = 0; !doit && (j < fd->pids); j++) {
				if (fd->pid_array[j] == tc->pid) {
					doit = TRUE;
					break;
				}
			}
	
	 		for (j = 0; !doit && (j < fd->comms); j++) {
				strlcpy(buf, fd->comm_array[j], TASK_COMM_LEN);
				if (STREQ(buf, tc->comm)) {
					doit = TRUE;
					break;
				}
			}

			for (j = 0; !doit && (j < fd->regexs); j++) {
				if (regexec(&fd->regex_info[j].regex, 
				    tc->comm, 0, NULL, 0) == 0) {
					doit = TRUE;
					break;
				}
			}
		} else 
			doit = TRUE;

		if (!doit)
			continue;

		if (output_closed() || received_SIGINT()) {
			free_all_bufs();
			goto foreach_bailout;
		}

                if (setjmp(pc->foreach_loop_env)) {
			free_all_bufs();
                        continue;
		}
		pc->flags |= IN_FOREACH;

		if (fd->reference) {
			BZERO(ref, sizeof(struct reference));
			ref->str = fd->reference;
		} else if (print_header)
			print_task_header(fp, tc, subsequent++);

		for (k = 0; k < fd->keys; k++) {
			free_all_bufs();

			switch(fd->keyword_array[k])
			{
			case FOREACH_BT:
				pc->curcmd = "bt";
				BZERO(bt, sizeof(struct bt_info));;
				bt->task = tc->task;
				bt->tc = tc;
				bt->stackbase = GET_STACKBASE(tc->task);
				bt->stacktop = GET_STACKTOP(tc->task);
				if (fd->flags & FOREACH_r_FLAG)
					bt->flags |= BT_RAW;
				if (fd->flags & FOREACH_s_FLAG)
					bt->flags |= BT_SYMBOL_OFFSET;
				if (fd->flags & FOREACH_t_FLAG)
					bt->flags |= BT_TEXT_SYMBOLS;
				if (fd->flags & FOREACH_T_FLAG) {
					bt->flags |= BT_TEXT_SYMBOLS;
					bt->flags |= BT_TEXT_SYMBOLS_ALL;
				}
				if ((fd->flags & FOREACH_o_FLAG) ||
				    (kt->flags & USE_OPT_BT))
					bt->flags |= BT_OPT_BACK_TRACE;
                                if (fd->flags & FOREACH_e_FLAG)
                                        bt->flags |= BT_EFRAME_SEARCH;
#ifdef GDB_5_3
                                if (fd->flags & FOREACH_g_FLAG)
                                        bt->flags |= BT_USE_GDB;
#endif
                                if (fd->flags & FOREACH_l_FLAG) 
                                        bt->flags |= BT_LINE_NUMBERS;
                                if (fd->flags & FOREACH_f_FLAG) 
                                        bt->flags |= BT_FULL;
                                if (fd->flags & FOREACH_F_FLAG) 
                                        bt->flags |= (BT_FULL|BT_FULL_SYM_SLAB);
                                if (fd->flags & FOREACH_F_FLAG2) 
                                        bt->flags |= BT_FULL_SYM_SLAB2;
                                if (fd->flags & FOREACH_x_FLAG) 
					bt->radix = 16;
                                if (fd->flags & FOREACH_d_FLAG) 
					bt->radix = 10;
				if (fd->reference)
					bt->ref = ref;
				back_trace(bt); 
				break;

			case FOREACH_VM:
				pc->curcmd = "vm";
				cmdflags = 0;
				if (fd->flags & FOREACH_x_FLAG)
					cmdflags = PRINT_RADIX_16;
				else if (fd->flags & FOREACH_d_FLAG)
					cmdflags = PRINT_RADIX_10;
				if (fd->flags & FOREACH_i_FLAG)
					vm_area_dump(tc->task, 
					    PRINT_INODES, 0, NULL);
				else if (fd->flags & FOREACH_p_FLAG)
					vm_area_dump(tc->task, 
					    PHYSADDR, 0, 
					    fd->reference ? ref : NULL);
				else if (fd->flags & FOREACH_m_FLAG)
					vm_area_dump(tc->task, 
					    PRINT_MM_STRUCT|cmdflags, 0, NULL);
				else if (fd->flags & FOREACH_v_FLAG)
					vm_area_dump(tc->task, 
					    PRINT_VMA_STRUCTS|cmdflags, 0, NULL);
				else
					vm_area_dump(tc->task, 0, 0, 
					    fd->reference ? ref : NULL);
				break;

			case FOREACH_TASK:
				pc->curcmd = "task";
				if (fd->flags & FOREACH_x_FLAG)
					radix = 16;
				else if (fd->flags & FOREACH_d_FLAG)
					radix = 10;
				else
					radix = pc->output_radix;
				do_task(tc->task, FOREACH_TASK, 
					fd->reference ? ref : NULL, 
					radix);
				break;

                        case FOREACH_SIG:
				pc->curcmd = "sig";
				if (fd->flags & FOREACH_g_FLAG) {
					tgid = task_tgid(tc->task);	
					tgc = tgid_to_context(tgid);
					if (hq_enter(tgc->task))
						do_sig_thread_group(tgc->task);
				} else 
                                	do_sig(tc->task, FOREACH_SIG,
                                        	fd->reference ? ref : NULL);
                                break;

			case FOREACH_SET:
				pc->curcmd = "set";
				show_context(tc);
				break;

			case FOREACH_PS:
				pc->curcmd = "ps";
                                psinfo.task[0] = tc->task;
                                psinfo.pid[0] = NO_PID;
                                psinfo.type[0] = PS_BY_TASK;
				psinfo.argc = 1;
                                cmdflags = PS_BY_TASK;
				if (subsequent++)
					cmdflags |= PS_NO_HEADER;
				if (fd->flags & FOREACH_G_FLAG)
					cmdflags |= PS_GROUP;
				if (fd->flags & FOREACH_s_FLAG)
					cmdflags |= PS_KSTACKP;
				if (fd->flags & FOREACH_y_FLAG) {
					cmdflags |= PS_POLICY;
					psinfo.policy = fd->policy;
				}
				/*
				 * mutually exclusive flags
				 */ 
				if (fd->flags & FOREACH_a_FLAG)
					cmdflags |= PS_ARGV_ENVP;
				else if (fd->flags & FOREACH_c_FLAG)
					cmdflags |= PS_CHILD_LIST;
				else if (fd->flags & FOREACH_p_FLAG)
					cmdflags |= PS_PPID_LIST;
				else if (fd->flags & FOREACH_t_FLAG)
					cmdflags |= PS_TIMES;
				else if (fd->flags & FOREACH_l_FLAG)
					cmdflags |= PS_LAST_RUN;
				else if (fd->flags & FOREACH_m_FLAG)
					cmdflags |= PS_MSECS;
				else if (fd->flags & FOREACH_r_FLAG)
					cmdflags |= PS_RLIMIT;
				else if (fd->flags & FOREACH_g_FLAG)
					cmdflags |= PS_TGID_LIST;
				show_ps(cmdflags, &psinfo);
				break;

			case FOREACH_FILES:
				pc->curcmd = "files";
				cmdflags = 0;

				if (fd->flags & FOREACH_i_FLAG)
					cmdflags |= PRINT_INODES;
				if (fd->flags & FOREACH_c_FLAG)
					cmdflags |= PRINT_NRPAGES;

				open_files_dump(tc->task,
					cmdflags,
					fd->reference ? ref : NULL);
				break;

			case FOREACH_NET:
				pc->curcmd = "net";
				if (fd->flags & (FOREACH_s_FLAG|FOREACH_S_FLAG))
					dump_sockets_workhorse(tc->task,
						fd->flags, 
						fd->reference ? ref : NULL);
				break;

			case FOREACH_VTOP:
				pc->curcmd = "vtop";
				cmdflags = 0;
				if (fd->flags & FOREACH_c_FLAG)
					cmdflags |= USE_USER_PGD;
				if (fd->flags & FOREACH_u_FLAG)
					cmdflags |= UVADDR;
				if (fd->flags & FOREACH_k_FLAG)
					cmdflags |= KVADDR;

				for (a = 0; a < fd->args; a++) { 
					do_vtop(htol((char *)fd->arg_array[a], 
						FAULT_ON_ERROR, NULL), tc,
						cmdflags);
				}
				break;

			case FOREACH_TEST:
				pc->curcmd = "test";
				foreach_test(tc->task, 0);
				break;
			}

			pc->curcmd = "foreach";
		} 
	}

	/*
	 *  Post-process any commands requiring it.
	 */
        for (k = 0; k < fd->keys; k++) {
                switch(fd->keyword_array[k])
                {
		case FOREACH_SIG:
                        if (fd->flags & FOREACH_g_FLAG)
				hq_close();
			break;
		}
	}

foreach_bailout:

	pc->flags &= ~IN_FOREACH;
}

/*
 *  Clean up regex buffers and pattern strings.
 */
static void 
foreach_cleanup(void *arg)
{
	int i;
	struct foreach_data *fd;

	pc->cmd_cleanup = NULL;
	pc->cmd_cleanup_arg = NULL;

	fd = (struct foreach_data *)arg;

	for (i = 0; i < fd->regexs; i++) {
		regfree(&fd->regex_info[i].regex);
		free(fd->regex_info[i].pattern);
	}
}

/*
 *  The currently available set of foreach commands.
 */
static int
is_foreach_keyword(char *s, int *key)
{
	if (STREQ(args[optind], "bt")) {
		*key = FOREACH_BT;
		return TRUE;
	}

	if (STREQ(args[optind], "vm")) {
		*key = FOREACH_VM;
		return TRUE;
	}

        if (STREQ(args[optind], "task")) {
                *key = FOREACH_TASK;
                return TRUE;
        }

        if (STREQ(args[optind], "set")) {
                *key = FOREACH_SET;
                return TRUE;
        }

        if (STREQ(args[optind], "files")) {
                *key = FOREACH_FILES;
                return TRUE;
        }

	if (STREQ(args[optind], "net")) {
                *key = FOREACH_NET;
                return TRUE;
	}

        if (STREQ(args[optind], "vtop")) {
                *key = FOREACH_VTOP;
                return TRUE;
        }

        if (STREQ(args[optind], "sig")) {
                *key = FOREACH_SIG;
                return TRUE;
        }

        if (STREQ(args[optind], "test")) {
                *key = FOREACH_TEST;
                return TRUE;
        }

        if (STREQ(args[optind], "ps")) {
                *key = FOREACH_PS;
                return TRUE;
        }

	return FALSE;
}

/*
 *  Try the dumpfile-specific manner of finding the panic task first.  If
 *  that fails, find the panic task the hard way -- do a "foreach bt" in the 
 *  background, and look for the only one that has "panic" embedded in it.
 */
static struct task_context *
panic_search(void)
{
        struct foreach_data foreach_data, *fd;
	char *p1, *p2, *tp;
	ulong lasttask, dietask, found;
	char buf[BUFSIZE];
	struct task_context *tc;

	if ((lasttask = get_dumpfile_panic_task())) {
		found = TRUE;
		goto found_panic_task;
	}

	if (pc->flags2 & LIVE_DUMP)
		return NULL;

        BZERO(&foreach_data, sizeof(struct foreach_data));
        fd = &foreach_data;
	fd->keys = 1;
	fd->keyword_array[0] = FOREACH_BT; 
	if (machine_type("S390X"))
		fd->flags |= FOREACH_o_FLAG;
	else if (machine_type("ARM64"))
		fd->flags |= FOREACH_t_FLAG;
	else
		fd->flags |= (FOREACH_t_FLAG|FOREACH_o_FLAG);

	dietask = lasttask = NO_TASK;
	
	found = FALSE;

	open_tmpfile();

	foreach(fd);

        rewind(pc->tmpfile);

        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
		if ((p1 = strstr(buf, "  TASK: "))) {
			p1 += strlen("  TASK: ");
			p2 = p1;
			while (!whitespace(*p2))
				p2++;
			*p2 = NULLCHAR;
			lasttask = htol(p1, RETURN_ON_ERROR, NULL);
		}

		if (strstr(buf, " panic at ")) {
			found = TRUE;
			break;	
		}

		if (strstr(buf, " crash_kexec at ") ||
		    strstr(buf, " .crash_kexec at ")) {
			found = TRUE;
			break;	
		}

                if (strstr(buf, " die at ")) {
			switch (dietask)
			{
			case NO_TASK:
				dietask = lasttask;
				break;
			default:
				if (dietask != lasttask)
					dietask = NO_TASK+1;
				break;
			}
                }
	}

	close_tmpfile();

	pc->curcmd = pc->program_name;

	if (!found && (dietask > (NO_TASK+1)) && task_has_cpu(dietask, NULL)) {
		lasttask = dietask;
		found = TRUE;
	}

	if (dietask == (NO_TASK+1))
		error(WARNING, "multiple active tasks have called die\n\n");

	if (CRASHDEBUG(1) && found)
		error(INFO, "panic_search: %lx (via foreach bt)\n",
			lasttask);

	if (!found) {
		if (CRASHDEBUG(1))
			error(INFO, "panic_search: failed (via foreach bt)\n");
		if ((lasttask = get_log_panic_task()))
			found = TRUE;
	}

found_panic_task:
	populate_panic_threads();

	if (found) {
		if ((tc = task_to_context(lasttask)))
			return tc;

		/*
		 *  If the task list was corrupted, add this one in.
		 */
                if ((tp = fill_task_struct(lasttask))) {
			if ((tc = add_context(lasttask, tp)))
				return tc;
		}
	} 

	if (CRASHDEBUG(1))
		error(INFO, "panic_search: failed\n");

	return NULL;
}

static ulong
search_panic_task_by_cpu(char *buf)
{
	int crashing_cpu;
	char *p1, *p2;
	ulong task = NO_TASK;

	p1 = NULL;

	if ((p1 = strstr(buf, "CPU: ")))
		p1 += strlen("CPU: ");
	else if (STRNEQ(buf, "CPU "))
		p1 = buf + strlen("CPU ");

	if (p1) {
		p2 = p1;
		while (!whitespace(*p2) && (*p2 != '\n'))
			p2++;
		*p2 = NULLCHAR;
		crashing_cpu = dtol(p1, RETURN_ON_ERROR, NULL);
		if ((crashing_cpu >= 0) && in_cpu_map(ONLINE_MAP, crashing_cpu)) {
			task = tt->active_set[crashing_cpu];
			if (CRASHDEBUG(1))
				error(WARNING,
					"get_log_panic_task: active_set[%d]: %lx\n",
					crashing_cpu, tt->active_set[crashing_cpu]);
		}
	}
	return task;
}

static ulong
search_panic_task_by_keywords(char *buf, int *found_flag)
{
	char *p;
	int i = 0;
	ulong task;

	while (panic_keywords[i]) {
		if ((p = strstr(buf, panic_keywords[i]))) {
			if ((task = search_panic_task_by_cpu(p))) {
				*found_flag = FOUND_PANIC_TASK;
				return task;
			} else {
				*found_flag = FOUND_PANIC_KEYWORD;
				return NO_TASK;
			}
		}
		i++;
	}
	*found_flag = FOUND_NO_PANIC_KEYWORD;
	return NO_TASK;
}

/*
 *   Search for the panic task by seeking panic keywords from kernel log buffer.
 *   The panic keyword is generally followed by printing out the stack trace info
 *   of the panicking task.  We can determine the panic task by finding the first
 *   instance of "CPU: " or "CPU " following the panic keywords.
 */
static ulong
get_log_panic_task(void)
{
	int found_flag = FOUND_NO_PANIC_KEYWORD;
	int found_panic_keyword = FALSE;
	ulong task = NO_TASK;
	char buf[BUFSIZE];

	if (!get_active_set())
		goto fail;

	BZERO(buf, BUFSIZE);
	open_tmpfile();
	dump_log(SHOW_LOG_TEXT);
	rewind(pc->tmpfile);
	while (fgets(buf, BUFSIZE, pc->tmpfile)) {
		if (!found_panic_keyword) {
			task = search_panic_task_by_keywords(buf, &found_flag);
			switch (found_flag) {
				case FOUND_PANIC_TASK:
					goto found_panic_task;
				case FOUND_PANIC_KEYWORD:
					found_panic_keyword = TRUE;
					continue;
				default:
					continue;
			}
		} else {
			task = search_panic_task_by_cpu(buf);
			if (task)
				goto found_panic_task;
		}
	}

found_panic_task:
	close_tmpfile();
fail:
	if (CRASHDEBUG(1) && !task)
		 error(WARNING, "cannot determine the panic task from kernel log buffer\n");

	return task;
}

/*
 *   Get the panic task from the appropriate dumpfile handler.
 */
static ulong
get_dumpfile_panic_task(void)
{
	ulong task;

	if (NETDUMP_DUMPFILE()) {
		task = pc->flags & REM_NETDUMP ?
			tt->panic_task : get_netdump_panic_task();
		if (task) 
			return task;
	} else if (KDUMP_DUMPFILE()) {
                task = get_kdump_panic_task();
                if (task)
                        return task;
        } else if (DISKDUMP_DUMPFILE()) {
                task = get_diskdump_panic_task();
                if (task)
                        return task;
        } else if (KVMDUMP_DUMPFILE()) {
                task = get_kvmdump_panic_task();
                if (task)
                        return task;
	} else if (XENDUMP_DUMPFILE()) {
                task = get_xendump_panic_task();
                if (task)
                        return task;
        } else if (LKCD_DUMPFILE())
		return(get_lkcd_panic_task());

	if (pc->flags2 & LIVE_DUMP)
		return NO_TASK;

	if (get_active_set())
		return(get_active_set_panic_task());

	return NO_TASK;
}

/*
 *  If runqueues is defined in the kernel, get the panic threads from the
 *  active set.
 *
 *  If it's an LKCD dump, or for some other reason the active threads cannot
 *  be determined, do it the hard way.
 *
 *  NOTE: this function should be deprecated -- the work should have been
 *        done in the initial task table refresh.
 */
static void
populate_panic_threads(void)
{
	int i;
	int found;
        struct task_context *tc;

	if (get_active_set()) {
		for (i = 0; i < NR_CPUS; i++) 
			tt->panic_threads[i] = tt->active_set[i];
		return;
	}

	found = 0;
        if (!(machdep->flags & HWRESET)) {
		for (i = 0; i < kt->cpus; i++) {
			if (tt->panic_threads[i]) {
				if (++found == kt->cpus)
					return;
			}
		}
	}

        tc = FIRST_CONTEXT();
        for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
		if (task_has_cpu(tc->task, NULL) && 
		    (tc->processor >= 0) && 
		    (tc->processor < NR_CPUS)) {
			tt->panic_threads[tc->processor] = tc->task;
			found++;
		}
	}

	if (!found && !(kt->flags & SMP) &&
	    (LKCD_DUMPFILE() || NETDUMP_DUMPFILE() || 
	     KDUMP_DUMPFILE() || DISKDUMP_DUMPFILE() || KVMDUMP_DUMPFILE())) 
		tt->panic_threads[0] = get_dumpfile_panic_task();
}
	
/*
 *  Separate the foreach command's output on a task-by-task basis by
 *  displaying this header string.
 */
void
print_task_header(FILE *out, struct task_context *tc, int newline)
{
	char buf[BUFSIZE];
	char buf1[BUFSIZE];

        fprintf(out, "%sPID: %-7ld  TASK: %s  CPU: %-3s  COMMAND: \"%s\"\n",
		newline ? "\n" : "", tc->pid, 
		mkstring(buf1, VADDR_PRLEN, LJUST|LONG_HEX, MKSTR(tc->task)),
		task_cpu(tc->processor, buf, !VERBOSE), tc->comm);
}

/*
 *  "help -t" output
 */
void
dump_task_table(int verbose)
{
	int i, j, more, nr_cpus;
	struct task_context *tc;
	struct tgid_context *tg;
	char buf[BUFSIZE];
	int others, wrap, flen;

	tc = tt->current;
	others = 0;
	more = FALSE;

	fprintf(fp, "           current: %lx [%ld]\n",  (ulong)tt->current,
		(ulong)(tt->current - tt->context_array));
	if (tt->current) {
		fprintf(fp, "              .pid: %ld\n", tc->pid);
		fprintf(fp, "             .comm: \"%s\"\n", tc->comm);
		fprintf(fp, "             .task: %lx\n", tc->task);
		fprintf(fp, "      .thread_info: %lx\n", tc->thread_info);
		fprintf(fp, "        .processor: %d\n", tc->processor);
		fprintf(fp, "            .ptask: %lx\n", tc->ptask);
		fprintf(fp, "        .mm_struct: %lx\n", tc->mm_struct);
		fprintf(fp, "          .tc_next: %lx\n", (ulong)tc->tc_next);
	}
	fprintf(fp, "     context_array: %lx\n",  (ulong)tt->context_array);
	fprintf(fp, "   context_by_task: %lx\n",  (ulong)tt->context_by_task);
	fprintf(fp, "        tgid_array: %lx\n",  (ulong)tt->tgid_array);
	fprintf(fp, "     tgid_searches: %ld\n",  tt->tgid_searches);
	fprintf(fp, "   tgid_cache_hits: %ld (%ld%%)\n", tt->tgid_cache_hits,
		tt->tgid_searches ? 
		tt->tgid_cache_hits * 100 / tt->tgid_searches : 0);
	fprintf(fp, "         last_tgid: %lx\n",  (ulong)tt->last_tgid);
	fprintf(fp, "refresh_task_table: ");
	if (tt->refresh_task_table == refresh_fixed_task_table)
		fprintf(fp, "refresh_fixed_task_table()\n");
	else if (tt->refresh_task_table == refresh_unlimited_task_table)
		fprintf(fp, "refresh_unlimited_task_table()\n");
	else if (tt->refresh_task_table == refresh_pidhash_task_table)
		fprintf(fp, "refresh_pidhash_task_table()\n");
        else if (tt->refresh_task_table == refresh_pid_hash_task_table)
                fprintf(fp, "refresh_pid_hash_task_table()\n");
        else if (tt->refresh_task_table == refresh_hlist_task_table)
                fprintf(fp, "refresh_hlist_task_table()\n");
        else if (tt->refresh_task_table == refresh_hlist_task_table_v2)
                fprintf(fp, "refresh_hlist_task_table_v2()\n");
        else if (tt->refresh_task_table == refresh_hlist_task_table_v3)
                fprintf(fp, "refresh_hlist_task_table_v3()\n");
        else if (tt->refresh_task_table == refresh_active_task_table)
                fprintf(fp, "refresh_active_task_table()\n");
        else if (tt->refresh_task_table == refresh_radix_tree_task_table)
                fprintf(fp, "refresh_radix_tree_task_table()\n");
        else if (tt->refresh_task_table == refresh_xarray_task_table)
                fprintf(fp, "refresh_xarray_task_table()\n");
	else
		fprintf(fp, "%lx\n", (ulong)tt->refresh_task_table);

	buf[0] = NULLCHAR;
	fprintf(fp, "             flags: %lx  ",  tt->flags);
	sprintf(buf, "(");
	if (tt->flags & TASK_INIT_DONE)
		sprintf(&buf[strlen(buf)], 
			"%sTASK_INIT_DONE", others++ ? "|" : "");
        if (tt->flags & TASK_ARRAY_EXISTS)
                sprintf(&buf[strlen(buf)], 
			"%sTASK_ARRAY_EXISTS", others++ ? "|" : "");
        if (tt->flags & PANIC_TASK_NOT_FOUND)
                sprintf(&buf[strlen(buf)], 
			"%sPANIC_TASK_NOT_FOUND", others++ ? "|" : "");
        if (tt->flags & TASK_REFRESH)
                sprintf(&buf[strlen(buf)], 
			"%sTASK_REFRESH", others++ ? "|" : "");
        if (tt->flags & TASK_REFRESH_OFF)
                sprintf(&buf[strlen(buf)], 
			"%sTASK_REFRESH_OFF", others++ ? "|" : "");
        if (tt->flags & PANIC_KSP)
                sprintf(&buf[strlen(buf)], 
			"%sPANIC_KSP", others++ ? "|" : "");
       if (tt->flags & POPULATE_PANIC)
                sprintf(&buf[strlen(buf)],
                        "%sPOPULATE_PANIC", others++ ? "|" : "");
        if (tt->flags & ACTIVE_SET)
                sprintf(&buf[strlen(buf)], 
			"%sACTIVE_SET", others++ ? "|" : "");
        if (tt->flags & PIDHASH)
                sprintf(&buf[strlen(buf)], 
			"%sPIDHASH", others++ ? "|" : "");
        if (tt->flags & PID_HASH)
                sprintf(&buf[strlen(buf)], 
			"%sPID_HASH", others++ ? "|" : "");
	if (tt->flags & PID_RADIX_TREE)
		sprintf(&buf[strlen(buf)],
			"%sPID_RADIX_TREE", others++ ? "|" : "");
	if (tt->flags & PID_XARRAY)
		sprintf(&buf[strlen(buf)],
			"%sPID_XARRAY", others++ ? "|" : "");
        if (tt->flags & THREAD_INFO)
                sprintf(&buf[strlen(buf)], 
			"%sTHREAD_INFO", others++ ? "|" : "");
        if (tt->flags & THREAD_INFO_IN_TASK)
                sprintf(&buf[strlen(buf)], 
			"%sTHREAD_INFO_IN_TASK", others++ ? "|" : "");
        if (tt->flags & IRQSTACKS)
                sprintf(&buf[strlen(buf)], 
			"%sIRQSTACKS", others++ ? "|" : "");
        if (tt->flags & TIMESPEC)
                sprintf(&buf[strlen(buf)], 
			"%sTIMESPEC", others++ ? "|" : "");
        if (tt->flags & NO_TIMESPEC)
                sprintf(&buf[strlen(buf)], 
			"%sNO_TIMESPEC", others++ ? "|" : "");
        if (tt->flags & START_TIME_NSECS)
                sprintf(&buf[strlen(buf)], 
			"%sSTART_TIME_NSECS", others++ ? "|" : "");
        if (tt->flags & ACTIVE_ONLY)
                sprintf(&buf[strlen(buf)], 
			"%sACTIVE_ONLY", others++ ? "|" : "");
        if (tt->flags & INDEXED_CONTEXTS)
                sprintf(&buf[strlen(buf)], 
			"%sINDEXED_CONTEXTS", others++ ? "|" : "");
	sprintf(&buf[strlen(buf)], ")");

        if (strlen(buf) > 54)
                fprintf(fp, "\n%s\n", mkstring(buf, 80, CENTER|LJUST, NULL));
        else
                fprintf(fp, "%s\n", buf);

	fprintf(fp, "        task_start: %lx\n",  tt->task_start);
	fprintf(fp, "          task_end: %lx\n",  tt->task_end);
	fprintf(fp, "        task_local: %lx\n",  (ulong)tt->task_local);
	fprintf(fp, "         max_tasks: %d\n", tt->max_tasks);
	fprintf(fp, "    pid_radix_tree: %lx\n", tt->pid_radix_tree);
	fprintf(fp, "        pid_xarray: %lx\n", tt->pid_xarray);
	fprintf(fp, "         callbacks: %d\n", tt->callbacks);
	fprintf(fp, "        nr_threads: %d\n", tt->nr_threads);
	fprintf(fp, "     running_tasks: %ld\n", tt->running_tasks);
	fprintf(fp, "           retries: %ld\n", tt->retries);
        fprintf(fp, "          panicmsg: \"%s\"\n",
                strip_linefeeds(get_panicmsg(buf)));
        fprintf(fp, "   panic_processor: %d\n", tt->panic_processor);
        fprintf(fp, "        panic_task: %lx\n", tt->panic_task);
        fprintf(fp, "         this_task: %lx\n", tt->this_task);
        fprintf(fp, "       pidhash_len: %d\n", tt->pidhash_len);
        fprintf(fp, "      pidhash_addr: %lx\n", tt->pidhash_addr);
	fprintf(fp, "    last_task_read: %lx\n", tt->last_task_read);
	fprintf(fp, "      last_mm_read: %lx\n", tt->last_mm_read);
	fprintf(fp, "       task_struct: %lx\n", (ulong)tt->task_struct);
	fprintf(fp, "         mm_struct: %lx\n", (ulong)tt->mm_struct);
	fprintf(fp, "       init_pid_ns: %lx\n", tt->init_pid_ns);
	fprintf(fp, "         filepages: %ld\n", tt->filepages);
	fprintf(fp, "         anonpages: %ld\n", tt->anonpages);
	fprintf(fp, "        shmempages: %ld\n", tt->shmempages);
	fprintf(fp, "   stack_end_magic: %lx\n", tt->stack_end_magic);
	fprintf(fp, "        pf_kthread: %lx ", tt->pf_kthread);
	switch (tt->pf_kthread) 
	{
	case UNINITIALIZED:
		fprintf(fp, "(UNINITIALIZED)\n"); 
		break;
	case 0:
		fprintf(fp, "(n/a)\n"); 
		break;
	default:
		fprintf(fp, "(PF_KTHREAD)\n"); 
		break;
	}

	wrap = sizeof(void *) == SIZEOF_32BIT ? 8 : 4;
	flen = sizeof(void *) == SIZEOF_32BIT ? 8 : 16;

	nr_cpus = kt->kernel_NR_CPUS ? kt->kernel_NR_CPUS : NR_CPUS;


        fprintf(fp, "      idle_threads:");
        for (i = 0; i < nr_cpus; i++) {
		if (!tt->idle_threads) {
			fprintf(fp, " (unused)");
			break;
		}
                if ((i % wrap) == 0) {
                        fprintf(fp, "\n        ");
			for (j = i, more = FALSE; j < nr_cpus; j++) {
				if (tt->idle_threads[j]) {
					more = TRUE;
					break;
				}
			}
		}
                fprintf(fp, "%.*lx ", flen, tt->idle_threads[i]);
		if (!more) {
			fprintf(fp, "...");
			break;
		}
        }
        fprintf(fp, "\n");

	fprintf(fp, "        active_set:");
	for (i = 0; i < nr_cpus; i++) {
		if (!tt->active_set) {
			fprintf(fp, " (unused)");
			break;
		}
		if ((i % wrap) == 0) {
	        	fprintf(fp, "\n        ");
			for (j = i, more = FALSE; j < nr_cpus; j++) {
				if (tt->active_set[j]) {
					more = TRUE;
					break;
				}
			}
		}
	        fprintf(fp, "%.*lx ", flen, tt->active_set[i]);
		if (!more) {
			fprintf(fp, "...");
			break;
		}
	}
	fprintf(fp, "\n");

        fprintf(fp, "     panic_threads:");
        for (i = 0; i < nr_cpus; i++) {
		if (!tt->panic_threads) {
			fprintf(fp, " (unused)");
			break;
		}
                if ((i % wrap) == 0) {
                        fprintf(fp, "\n        ");
			for (j = i, more = FALSE; j < nr_cpus; j++) {
				if (tt->panic_threads[j]) {
					more = TRUE;
					break;
				}
			}
		}
               	fprintf(fp, "%.*lx ", flen, tt->panic_threads[i]); 
		if (!more) {
			fprintf(fp, "...");
			break;
		}
        }
        fprintf(fp, "\n");

        fprintf(fp, "         panic_ksp:");
        for (i = 0; i < nr_cpus; i++) {
		if (!tt->panic_ksp) {
			fprintf(fp, " (unused)");
			break;
		}
                if ((i % wrap) == 0) {
                        fprintf(fp, "\n        ");
			for (j = i, more = FALSE; j < nr_cpus; j++) {
				if (tt->panic_ksp[j]) {
					more = TRUE;
					break;
				}
			}
		}
                fprintf(fp, "%.*lx ", flen, tt->panic_ksp[i]);
		if (!more) {
			fprintf(fp, "...");
			break;
		}
        }
        fprintf(fp, "\n");

        fprintf(fp, "       hardirq_ctx:");
        for (i = 0; i < nr_cpus; i++) {
		if (!tt->hardirq_ctx) {
			fprintf(fp, " (unused)");
			break;
		}
                if ((i % wrap) == 0) {
                        fprintf(fp, "\n        ");
			for (j = i, more = FALSE; j < nr_cpus; j++) {
				if (tt->hardirq_ctx[j]) {
					more = TRUE;
					break;
				}
			}
		}
                fprintf(fp, "%.*lx ", flen, tt->hardirq_ctx[i]);
		if (!more) {
			fprintf(fp, "...");
			break;
		}
        }
        fprintf(fp, "\n");

        fprintf(fp, "     hardirq_tasks:");
        for (i = 0; i < nr_cpus; i++) {
		if (!tt->hardirq_tasks) {
			fprintf(fp, " (unused)");
			break;
		}
                if ((i % wrap) == 0) {
                        fprintf(fp, "\n        ");
			for (j = i, more = FALSE; j < nr_cpus; j++) {
				if (tt->hardirq_tasks[j]) {
					more = TRUE;
					break;
				}
			}
		}
                fprintf(fp, "%.*lx ", flen, tt->hardirq_tasks[i]);
		if (!more) {
			fprintf(fp, "...");
			break;
		}
        }
        fprintf(fp, "\n");

        fprintf(fp, "       softirq_ctx:");
        for (i = 0; i < nr_cpus; i++) {
		if (!tt->softirq_ctx) {
			fprintf(fp, " (unused)");
			break;
		}
                if ((i % wrap) == 0) {
                        fprintf(fp, "\n        ");
			for (j = i, more = FALSE; j < nr_cpus; j++) {
				if (tt->softirq_ctx[j]) {
					more = TRUE;
					break;
				}
			}
		}
                fprintf(fp, "%.*lx ", flen, tt->softirq_ctx[i]);
		if (!more) {
			fprintf(fp, "...");
			break;
		}
        }
        fprintf(fp, "\n");

        fprintf(fp, "     softirq_tasks:");
        for (i = 0; i < nr_cpus; i++) {
		if (!tt->softirq_tasks) {
			fprintf(fp, " (unused)");
			break;
		}
                if ((i % wrap) == 0) {
                        fprintf(fp, "\n        ");
			for (j = i, more = FALSE; j < nr_cpus; j++) {
				if (tt->softirq_tasks[j]) {
					more = TRUE;
					break;
				}
			}
		}
                fprintf(fp, "%.*lx ", flen, tt->softirq_tasks[i]);
		if (!more) {
			fprintf(fp, "...");
			break;
		}
        }
        fprintf(fp, "\n");
	dump_task_states();

	if (!verbose)
		return;

	if (tt->flags & THREAD_INFO)
		fprintf(fp, 
             "\nINDEX         TASK/THREAD_INFO           PID CPU     PTASK          MM_STRUCT     COMM\n");
	else
		fprintf(fp, 
			"\nINDEX   TASK    PID CPU PTASK   MM_STRUCT  COMM\n");
        tc = FIRST_CONTEXT();
        for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
		if (tt->flags & THREAD_INFO)
			fprintf(fp, 
			    "[%3d] %08lx/%08lx %5ld %d %08lx %016lx %s\n",
				i, tc->task, tc->thread_info, tc->pid, 
				tc->processor, tc->ptask, (ulong)tc->mm_struct,
				tc->comm); 
		else
			fprintf(fp, "[%3d] %08lx %5ld %d %08lx %08lx %s\n",
				i, tc->task, tc->pid, tc->processor, tc->ptask,
				(ulong)tc->mm_struct, tc->comm); 
	}

        fprintf(fp, "\nINDEX       TASK       TGID  (COMM)\n");
	for (i = 0; i < RUNNING_TASKS(); i++) {
		tg = &tt->tgid_array[i];
		tc = task_to_context(tg->task);
		fprintf(fp, "[%3d] %lx %ld (%s)\n", i, tg->task, tg->tgid, tc->comm);
	}

        fprintf(fp, "\nINDEX       TASK       (COMM)\n");
	for (i = 0; i < RUNNING_TASKS(); i++) {
		tc = tt->context_by_task[i];
		fprintf(fp, "[%3d] %lx (%s)\n", i, tc->task, tc->comm);
	}
}

/*
 *  Determine whether a task is a kernel thread.  This would seem easier than
 *  it looks, but on live systems it's easy to get faked out.
 */
int
is_kernel_thread(ulong task)
{
	struct task_context *tc;
	ulong mm;

        if (tt->pf_kthread == UNINITIALIZED) {
		if (THIS_KERNEL_VERSION >= LINUX(2,6,27)) {
			tt->pf_kthread = PF_KTHREAD;

			if ((tc = pid_to_context(0)) &&
			    !(task_flags(tc->task) & PF_KTHREAD)) {
				error(WARNING, "pid 0: PF_KTHREAD not set?\n");
				tt->pf_kthread = 0;
			}
			if ((tc = pid_to_context(1)) && 
			    task_mm(tc->task, FALSE) &&
			    (task_flags(tc->task) & PF_KTHREAD)) {
				error(WARNING, "pid 1: PF_KTHREAD set?\n");
				tt->pf_kthread = 0;
			}
		} else
			tt->pf_kthread = 0;
	}

	if (tt->pf_kthread)
		return (task_flags(task) & tt->pf_kthread ? TRUE : FALSE);

	tc = task_to_context(task);

	if ((tc->pid == 0) && !STREQ(tc->comm, pc->program_name))
		return TRUE;

        if (_ZOMBIE_ == TASK_STATE_UNINITIALIZED)
                initialize_task_state();

	if (IS_ZOMBIE(task) || IS_EXITING(task))
                return FALSE;

	/*
	 *  Check for shifting sands on a live system.
	 */
	mm = task_mm(task, TRUE);

	if (ACTIVE() && (mm != tc->mm_struct))
		return FALSE;

        /*
         *  Later version Linux kernel threads have no mm_struct at all.
	 *  Earlier version kernel threads point to common init_mm.
         */
        if (!tc->mm_struct) {
		if (IS_EXITING(task)) 
			return FALSE;

		if (!task_state(task) && !task_flags(task))
			return FALSE;

		return TRUE;
                
	} else if (tc->mm_struct == symbol_value("init_mm")) 
		return TRUE;

	return FALSE;
}

/*
 * Checks if task policy corresponds to given mask.
 */
static int
has_sched_policy(ulong task, ulong policy)
{
	return !!(task_policy(task) & policy);
}

/*
 * Converts sched policy name into mask bit.
 */
static ulong
sched_policy_bit_from_str(const char *policy_str)
{
	struct sched_policy_info *info = NULL;
	ulong policy = 0;
	int found = 0;
	char *upper = NULL;
	/*
	 * Once kernel gets more than 10 scheduling policies,
	 * sizes of these arrays should be adjusted
	 */
	char digit[2] = { 0, 0 };
	char hex[4] = { 0, 0, 0, 0 };

	upper = GETBUF(strlen(policy_str) + 1);
	upper_case(policy_str, upper);

	for (info = sched_policy_info; info->name; info++) {
		snprintf(digit, sizeof digit, "%lu", info->value);
		/*
		 * Not using %#lX format here since "0X" prefix
		 * is not prepended if 0 value is given
		 */
		snprintf(hex, sizeof hex, "0X%lX", info->value);
		if (strncmp(upper, info->name, strlen(info->name)) == 0 ||
			strncmp(upper, digit, sizeof digit) == 0 ||
			strncmp(upper, hex, sizeof hex) == 0) {
			policy = 1 << info->value;
			found = 1;
			break;
		}
	}

	FREEBUF(upper);

	if (!found)
		error(FATAL,
			"%s: invalid scheduling policy\n", policy_str);

	return policy;
}

/*
 * Converts sched policy string set into bitmask.
 */
static ulong
make_sched_policy(const char *policy_str)
{
	ulong policy = 0;
	char *iter = NULL;
	char *orig = NULL;
	char *cur = NULL;

	iter = STRDUPBUF(policy_str);
	orig = iter;

	while ((cur = strsep(&iter, ",")))
		policy |= sched_policy_bit_from_str(cur);

	FREEBUF(orig);

	return policy;
}

/*
 *  Gather an arry of pointers to the per-cpu idle tasks.  The tasklist
 *  argument must be at least the size of ulong[NR_CPUS].  There may be
 *  junk in everything after the first entry on a single CPU box, so the
 *  data gathered may be throttled by kt->cpus.
 */
void
get_idle_threads(ulong *tasklist, int nr_cpus)
{
	int i, cnt;
	ulong runq, runqaddr;
	char *runqbuf;
	struct syment *rq_sp;

	BZERO(tasklist, sizeof(ulong) * NR_CPUS);
	runqbuf = NULL;
	cnt = 0;

	if ((rq_sp = per_cpu_symbol_search("per_cpu__runqueues")) && 
	    VALID_MEMBER(runqueue_idle)) {
		runqbuf = GETBUF(SIZE(runqueue));
		for (i = 0; i < nr_cpus; i++) {
			if (machine_type("SPARC64") && 
			    cpu_map_addr("possible") &&
			    !(in_cpu_map(POSSIBLE, i)))
				continue;

			if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF))
				runq = rq_sp->value + kt->__per_cpu_offset[i];
			else
				runq = rq_sp->value;

			readmem(runq, KVADDR, runqbuf,
                        	SIZE(runqueue), "runqueues entry (per_cpu)",
                        	FAULT_ON_ERROR);		
			tasklist[i] = ULONG(runqbuf + OFFSET(runqueue_idle)); 
			if (IS_KVADDR(tasklist[i]))
				cnt++;
		}
	} else if (symbol_exists("runqueues") && VALID_MEMBER(runqueue_idle)) {
		runq = symbol_value("runqueues");
		runqbuf = GETBUF(SIZE(runqueue));
		for (i = 0; i < nr_cpus; i++, runq += SIZE(runqueue)) {
			readmem(runq, KVADDR, runqbuf,
                        	SIZE(runqueue), "runqueues entry (old)",
                        	FAULT_ON_ERROR);		
			tasklist[i] = ULONG(runqbuf + OFFSET(runqueue_idle)); 
			if (IS_KVADDR(tasklist[i]))
				cnt++;
		}
	} else if (symbol_exists("runqueues") && VALID_MEMBER(runqueue_cpu)) {
		runq = symbol_value("runqueues");
		runqbuf = GETBUF(SIZE(runqueue));

		for (i = 0; i < nr_cpus; i++) {
			runqaddr = runq + (SIZE(runqueue) * rq_idx(i));
			readmem(runqaddr, KVADDR, runqbuf,
                        	SIZE(runqueue), "runqueues entry",
                        	FAULT_ON_ERROR);		
			if ((tasklist[i] = get_idle_task(i, runqbuf)))
				cnt++;
		}
	} else if (symbol_exists("init_tasks")) {
                readmem(symbol_value("init_tasks"), KVADDR, tasklist,
                        sizeof(void *) * nr_cpus, "init_tasks array",
                        FAULT_ON_ERROR);
                if (IS_KVADDR(tasklist[0]))
			cnt++;
		else
                	BZERO(tasklist, sizeof(ulong) * NR_CPUS);
	} else if (OPENVZ()) {
		runq = symbol_value("pcpu_info");
		runqbuf = GETBUF(SIZE(pcpu_info));
		for (i = 0; i < nr_cpus; i++, runq += SIZE(pcpu_info)) {
			readmem(runq, KVADDR, runqbuf, SIZE(pcpu_info),
				"pcpu info", FAULT_ON_ERROR);
			tasklist[i] = ULONG(runqbuf + OFFSET(pcpu_info_idle));
			if (IS_KVADDR(tasklist[i]))
				cnt++;
		}
	}

	if (runqbuf)
		FREEBUF(runqbuf);

	if (!cnt) {
		error(INFO, 
     "cannot determine idle task addresses from init_tasks[] or runqueues[]\n");
		tasklist[0] = symbol_value("init_task_union");
	}
}

/*
 *  Emulate the kernel rq_idx() macro.
 */
static long
rq_idx(int cpu)
{
	if (kt->runq_siblings == 1)
		return cpu;
	else if (!(kt->__rq_idx))
		return 0;
	else
		return kt->__rq_idx[cpu];
}

/*
 *  Emulate the kernel cpu_idx() macro.
 */
static long
cpu_idx(int cpu)
{
        if (kt->runq_siblings == 1)
                return 0;
	else if (!(kt->__cpu_idx))
		return 0;
        else
                return kt->__cpu_idx[cpu];
}

/*
 *  Dig out the idle task data from a runqueue structure.
 */
static ulong 
get_idle_task(int cpu, char *runqbuf)
{
	ulong idle_task;

	idle_task = ULONG(runqbuf + OFFSET(runqueue_cpu) +
		(SIZE(cpu_s) * cpu_idx(cpu)) + OFFSET(cpu_s_idle));

	if (IS_KVADDR(idle_task)) 
		return idle_task;
	else { 
		if (cpu < kt->cpus)
			error(INFO, 
				"cannot determine idle task for cpu %d\n", cpu);
		return NO_TASK;
	}
}

/*
 *  Dig out the current task data from a runqueue structure.
 */
static ulong
get_curr_task(int cpu, char *runqbuf)
{
        ulong curr_task;

        curr_task = ULONG(runqbuf + OFFSET(runqueue_cpu) +
                (SIZE(cpu_s) * cpu_idx(cpu)) + OFFSET(cpu_s_curr));

        if (IS_KVADDR(curr_task)) 
                return curr_task;
        else 
                return NO_TASK;
}

/*
 *  On kernels with runqueue[] array, store the active set of tasks.
 */
int
get_active_set(void)
{
        int i, cnt;
        ulong runq, runqaddr;
        char *runqbuf;
	struct syment *rq_sp;

        if (tt->flags & ACTIVE_SET)
                return TRUE;

	runq = 0;
	rq_sp = per_cpu_symbol_search("per_cpu__runqueues");

	if (!rq_sp) {
		if (symbol_exists("runqueues"))
			runq = symbol_value("runqueues");
		else if (OPENVZ())
			runq = symbol_value("pcpu_info");
		else
			return FALSE;
	} else
		runq = rq_sp->value;

	if (!tt->active_set &&
	    !(tt->active_set = (ulong *)calloc(NR_CPUS, sizeof(ulong))))	
		error(FATAL, "cannot malloc active_set array");

        runqbuf = GETBUF(SIZE(runqueue));
	cnt = 0;

	if (OPENVZ()) {
		ulong vcpu_struct; 
		char *pcpu_info_buf, *vcpu_struct_buf;

		pcpu_info_buf   = GETBUF(SIZE(pcpu_info));
		vcpu_struct_buf = GETBUF(SIZE(vcpu_struct));

		for (i = 0; i < kt->cpus; i++, runq += SIZE(pcpu_info)) {
			readmem(runq, KVADDR, pcpu_info_buf, 
				SIZE(pcpu_info), "pcpu_info", FAULT_ON_ERROR);
			vcpu_struct= ULONG(pcpu_info_buf +
				OFFSET(pcpu_info_vcpu));
			readmem(vcpu_struct, KVADDR, vcpu_struct_buf, 
				SIZE(vcpu_struct), "pcpu_info->vcpu",
				FAULT_ON_ERROR);
			tt->active_set[i] = ULONG(vcpu_struct_buf +
				OFFSET(vcpu_struct_rq) + OFFSET(runqueue_curr));
			if (IS_KVADDR(tt->active_set[i]))
				cnt++;
		}
		FREEBUF(pcpu_info_buf);
		FREEBUF(vcpu_struct_buf);
	} else if (VALID_MEMBER(runqueue_curr) && rq_sp) {
               	for (i = 0; i < kt->cpus; i++) {
                        if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF))
                                runq = rq_sp->value + kt->__per_cpu_offset[i];
                        else
                                runq = rq_sp->value;

                        readmem(runq, KVADDR, runqbuf, SIZE(runqueue), 
				"active runqueues entry (per_cpu)",
                                FAULT_ON_ERROR);

	               	tt->active_set[i] = ULONG(runqbuf + 
				OFFSET(runqueue_curr));
			if (IS_KVADDR(tt->active_set[i]))
				cnt++;
		}
	} else if (VALID_MEMBER(runqueue_curr)) {
	        for (i = 0; i < MAX(kt->cpus, kt->kernel_NR_CPUS); i++, 
		    runq += SIZE(runqueue)) {
	                readmem(runq, KVADDR, runqbuf,
	                	SIZE(runqueue), "(old) runqueues curr",
	                        FAULT_ON_ERROR);
	               	tt->active_set[i] = ULONG(runqbuf + 
				OFFSET(runqueue_curr));
			if (IS_KVADDR(tt->active_set[i]))
				cnt++;
		}
        } else if (VALID_MEMBER(runqueue_cpu)) {
		for (i = 0; i < kt->cpus; i++) {
                        runqaddr = runq + (SIZE(runqueue) * rq_idx(i));
                        readmem(runqaddr, KVADDR, runqbuf,
                                SIZE(runqueue), "runqueues curr",
                                FAULT_ON_ERROR);
			if ((tt->active_set[i] = get_curr_task(i, runqbuf)))
				cnt++;
                }
	}

	if (cnt) {
		tt->flags |= ACTIVE_SET;
		return TRUE;
	} else {
		error(INFO, "get_active_set: no tasks found?\n");
		return FALSE;
	}
}

/*
 *  Clear the ACTIVE_SET flag on a live system, forcing a re-read of the
 *  runqueues[] array the next time get_active_set() is called above.
 */
void
clear_active_set(void)
{
        if (ACTIVE() && (tt->flags & TASK_REFRESH))
                tt->flags &= ~ACTIVE_SET;
}

#define RESOLVE_PANIC_AND_DIE_CALLERS()               		\
	if (xen_panic_task) {					\
                if (CRASHDEBUG(1))                              \
                        error(INFO,                             \
         "get_active_set_panic_task: %lx (xen_panic_event)\n",  \
                                xen_panic_task);		\
		return xen_panic_task;				\
	}							\
	if (crash_kexec_task) {					\
		if (CRASHDEBUG(1))				\
			error(INFO,				\
	    "get_active_set_panic_task: %lx (crash_kexec)\n",   \
				crash_kexec_task);	  	\
		return crash_kexec_task;			\
	}							\
	if (crash_fadump_task) {					\
		if (CRASHDEBUG(1))				\
			error(INFO,				\
	    "get_active_set_panic_task: %lx (crash_fadump)\n",   \
				crash_fadump_task);		\
		return crash_fadump_task;			\
	}							\
        if ((panic_task > (NO_TASK+1)) && !die_task) {		\
		if (CRASHDEBUG(1))				\
			fprintf(fp, 				\
		    "get_active_set_panic_task: %lx (panic)\n", \
				panic_task);			\
                return panic_task;                    		\
	}							\
                                                      		\
        if (panic_task && die_task) {                 		\
		if ((panic_task > (NO_TASK+1)) &&               \
		    (panic_task == die_task)) {                 \
		        if (CRASHDEBUG(1))			\
				fprintf(fp, 			\
		    "get_active_set_panic_task: %lx (panic)\n", \
					panic_task);		\
			return panic_task;			\
		}                                               \
                error(WARNING,                        		\
     "multiple active tasks have called die and/or panic\n\n"); \
		goto no_panic_task_found;			\
        }                                             		\
                                                      		\
        if (die_task > (NO_TASK+1)) {                 		\
		if (CRASHDEBUG(1))				\
			fprintf(fp, 				\
		    "get_active_set_panic_task: %lx (die)\n", 	\
				die_task);			\
                return die_task;                      		\
	}							\
        else if (die_task == (NO_TASK+1))             		\
                error(WARNING,                        		\
	"multiple active tasks have called die\n\n"); 

#define SEARCH_STACK_FOR_PANIC_DIE_AND_KEXEC_CALLERS()  \
	while (fgets(buf, BUFSIZE, pc->tmpfile)) {      \
                if (strstr(buf, " die+")) {             \
                        switch (die_task)               \
                        {                               \
                        case NO_TASK:                   \
                                die_task = task;        \
                                break;                  \
                        default:                        \
                                if (die_task != task)   \
                                        die_task = NO_TASK+1; \
                                break;                  \
                        }                               \
                }                                       \
                if (strstr(buf, " panic+")) {           \
                        switch (panic_task)             \
                        {                               \
                        case NO_TASK:                   \
                                panic_task = task;      \
				if (XENDUMP_DUMPFILE()) \
					xendump_panic_hook(buf); \
                                break;                  \
                        default:                        \
                                if (panic_task != task) \
                                        panic_task = NO_TASK+1; \
                                break;                  \
                        }                               \
                }                                       \
                if (strstr(buf, " crash_kexec+") ||     \
                    strstr(buf, " .crash_kexec+")) {    \
			crash_kexec_task = task;	\
                }                                       \
                if (strstr(buf, " .crash_fadump+"))     \
			crash_fadump_task = task;	\
                if (strstr(buf, " machine_kexec+") ||     \
                    strstr(buf, " .machine_kexec+")) {    \
			crash_kexec_task = task;	\
                }                                       \
                if (strstr(buf, " xen_panic_event+") || \
                    strstr(buf, " .xen_panic_event+")){ \
			xen_panic_task = task;	        \
			xendump_panic_hook(buf);	\
		}					\
                if (machine_type("IA64") && XENDUMP_DUMPFILE() && !xen_panic_task && \
                    strstr(buf, " sysrq_handle_crashdump+")) \
			xen_sysrq_task = task;	        \
	}

/*
 *  Search the active set tasks for instances of die or panic calls.
 */
static ulong
get_active_set_panic_task()
{
	int i, j, found;
	ulong task;
	char buf[BUFSIZE];
	ulong panic_task, die_task, crash_kexec_task, crash_fadump_task;
	ulong xen_panic_task;
	ulong xen_sysrq_task;

	panic_task = die_task = crash_kexec_task = xen_panic_task = NO_TASK;
	xen_sysrq_task = NO_TASK;
	crash_fadump_task = NO_TASK;

        for (i = 0; i < NR_CPUS; i++) {
                if (!(task = tt->active_set[i]) || !task_exists(task))
			continue;

        	open_tmpfile();
		raw_stack_dump(GET_STACKBASE(task), STACKSIZE());
        	rewind(pc->tmpfile);

		SEARCH_STACK_FOR_PANIC_DIE_AND_KEXEC_CALLERS();

		close_tmpfile();
        }

	RESOLVE_PANIC_AND_DIE_CALLERS();

	if (tt->flags & IRQSTACKS) {
		panic_task = die_task = NO_TASK;

	        for (i = 0; i < NR_CPUS; i++) {
			if (!(task = tt->hardirq_tasks[i]))
				continue;

			for (j = found = 0; j < NR_CPUS; j++) {
				if (task == tt->active_set[j]) {
					found++;
					break;
				}
			}

			if (!found)
				continue;

	        	open_tmpfile();
			raw_stack_dump(tt->hardirq_ctx[i], SIZE(thread_union));
	        	rewind(pc->tmpfile);
	
			SEARCH_STACK_FOR_PANIC_DIE_AND_KEXEC_CALLERS();

			close_tmpfile();
	        }

		RESOLVE_PANIC_AND_DIE_CALLERS();

		panic_task = die_task = NO_TASK;

	        for (i = 0; i < NR_CPUS; i++) {
			if (!(task = tt->softirq_tasks[i]))
				continue;

			for (j = found = 0; j < NR_CPUS; j++) {
				if (task == tt->active_set[j]) {
					found++;
					break;
				}
			}

			if (!found)
				continue;
	
	        	open_tmpfile();
			raw_stack_dump(tt->softirq_ctx[i], SIZE(thread_union));
	        	rewind(pc->tmpfile);
	
			SEARCH_STACK_FOR_PANIC_DIE_AND_KEXEC_CALLERS();

			close_tmpfile();
	        }

		RESOLVE_PANIC_AND_DIE_CALLERS();
	} 

	if (crash_kexec_task) {
		if (CRASHDEBUG(1))
			error(INFO,
		    "get_active_set_panic_task: %lx (crash_kexec)\n", 
				crash_kexec_task);
		return crash_kexec_task;
	}
	if (crash_fadump_task) {
		if (CRASHDEBUG(1))
			error(INFO,
		    "get_active_set_panic_task: %lx (crash_fadump)\n",
				crash_fadump_task);
		return crash_fadump_task;
	}

	if (xen_sysrq_task) {
		if (CRASHDEBUG(1))
			error(INFO,
		    "get_active_set_panic_task: %lx (sysrq_handle_crashdump)\n", 
				xen_sysrq_task);
		return xen_sysrq_task;
	}

no_panic_task_found:

	if (CRASHDEBUG(1)) 
		error(INFO,
		    "get_active_set_panic_task: failed\n");

	return NO_TASK;
}


/*
 *  Determine whether a task is one of the idle threads.
 */
int
is_idle_thread(ulong task)
{
	int i;

        for (i = 0; i < NR_CPUS; i++) 
		if (task == tt->idle_threads[i])
			return TRUE;

	return FALSE;
}


/*
 *  Dump the current run queue task list.  This command should be expanded
 *  to deal with timer queues, bottom halves, etc...
 */
void
cmd_runq(void)
{
        int c;
	char arg_buf[BUFSIZE];
	ulong *cpus = NULL;
	int sched_debug = 0;
	int dump_timestamp_flag = 0;
	int dump_lag_flag = 0;
	int dump_task_group_flag = 0;
	int dump_milliseconds_flag = 0;

        while ((c = getopt(argcnt, args, "dtTgmc:")) != EOF) {
                switch(c)
                {
		case 'd':
			sched_debug = 1;
			break;
		case 't':
			dump_timestamp_flag = 1;
			break;
		case 'T':
			dump_lag_flag = 1;
			break;
		case 'm':
			dump_milliseconds_flag = 1;
			break;
		case 'g':
			if ((INVALID_MEMBER(task_group_cfs_rq) &&
			     INVALID_MEMBER(task_group_rt_rq)) ||
			    INVALID_MEMBER(task_group_parent))
				option_not_supported(c);
			dump_task_group_flag = 1;
			break;
		case 'c':
			if (pc->curcmd_flags & CPUMASK) {
				error(INFO, "only one -c option allowed\n");
				argerrs++;
			} else {
				pc->curcmd_flags |= CPUMASK;
				BZERO(arg_buf, BUFSIZE);
				strcpy(arg_buf, optarg);
				cpus = get_cpumask_buf();
				make_cpumask(arg_buf, cpus, FAULT_ON_ERROR, NULL);
				pc->curcmd_private = (ulong)cpus;
			}
			break;
                default:
                        argerrs++;
                        break;
                }
        }


        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

	if (dump_timestamp_flag)
                dump_on_rq_timestamp();
	else if (dump_lag_flag)
		dump_on_rq_lag();
	else if (dump_milliseconds_flag)
                dump_on_rq_milliseconds();
	else if (sched_debug)
		dump_on_rq_tasks();
	else if (dump_task_group_flag)
		dump_tasks_by_task_group();
	else
		dump_runq();

	if (cpus)
		FREEBUF(cpus);
}

/*
 *  Displays the runqueue and active task timestamps of each cpu.
 */
static void
dump_on_rq_timestamp(void)
{
	ulong runq;
	char buf[BUFSIZE];
	char format[15];
	struct syment *rq_sp;
	struct task_context *tc;
	int cpu, len, indent;
	ulonglong timestamp;
	ulong *cpus;

	indent = runq = 0;
	cpus = pc->curcmd_flags & CPUMASK ? 
		(ulong *)(ulong)pc->curcmd_private : NULL;

	if (!(rq_sp = per_cpu_symbol_search("per_cpu__runqueues")))
		error(FATAL, "per-cpu runqueues do not exist\n");
	if (INVALID_MEMBER(rq_timestamp))
		option_not_supported('t');

	for (cpu = 0; cpu < kt->cpus; cpu++) {
		if (cpus && !NUM_IN_BITMAP(cpus, cpu))
			continue;

		if ((kt->flags & SMP) && (kt->flags &PER_CPU_OFF))
			runq = rq_sp->value + kt->__per_cpu_offset[cpu];
		else
			runq = rq_sp->value;

		readmem(runq + OFFSET(rq_timestamp), KVADDR, &timestamp,
			sizeof(ulonglong), "per-cpu rq timestamp",
			FAULT_ON_ERROR);

                sprintf(buf, pc->output_radix == 10 ? "%llu" : "%llx",
			timestamp);
		fprintf(fp, "%sCPU %d: ", cpu < 10 ? " " : "", cpu);

		if (hide_offline_cpu(cpu)) {
			fprintf(fp, "[OFFLINE]\n");
			continue;
		} else
			fprintf(fp, "%s\n", buf);

		len = strlen(buf);

		if ((tc = task_to_context(tt->active_set[cpu]))){
			if (cpu < 10)
				indent = 7;
			else if (cpu < 100)
				indent = 8;
			else if (cpu < 1000)
				indent = 9;
			if (cpu < 10)
				indent++;

			timestamp = task_last_run(tc->task);
			sprintf(format, "%c0%dll%c", '%', len,
				pc->output_radix == 10 ? 'u' : 'x');
			sprintf(buf, format, timestamp);
			fprintf(fp, "%s%s  PID: %-5ld  TASK: %lx  COMMAND: \"%s\"\n",
				space(indent), buf, tc->pid, tc->task, tc->comm);
		} else
			fprintf(fp, "\n"); 

	}
}

/*
 * Runqueue timestamp struct for dump_on_rq_lag().
 */
struct runq_ts_info {
	int cpu;
	ulonglong ts;
};

/*
 * Comparison function for dump_on_rq_lag().
 * Sorts runqueue timestamps in a descending order.
 */
static int
compare_runq_ts(const void *p1, const void *p2)
{
	const struct runq_ts_info *ts1 = p1;
	const struct runq_ts_info *ts2 = p2;

	if (ts1->ts > ts2->ts)
		return -1;

	if (ts1->ts < ts2->ts)
		return 1;

	return 0;
}

/*
 * Calculates integer log10
 */
static ulong
__log10ul(ulong x)
{
	ulong ret = 1;

	while (x > 9) {
		ret++;
		x /= 10;
	}

	return ret;
}

/*
 * Displays relative CPU lag.
 */
static void
dump_on_rq_lag(void)
{
	struct syment *rq_sp;
	int cpu;
	ulong runq;
	ulonglong timestamp;
	struct runq_ts_info runq_ts[kt->cpus];

	if (!(rq_sp = per_cpu_symbol_search("per_cpu__runqueues")))
		error(FATAL, "per-cpu runqueues do not exist\n");
	if (INVALID_MEMBER(rq_timestamp))
		option_not_supported('T');

	for (cpu = 0; cpu < kt->cpus; cpu++) {
		if ((kt->flags & SMP) && (kt->flags &PER_CPU_OFF))
			runq = rq_sp->value + kt->__per_cpu_offset[cpu];
		else
			runq = rq_sp->value;

		readmem(runq + OFFSET(rq_timestamp), KVADDR, &timestamp,
				sizeof(ulonglong), "per-cpu rq timestamp",
				FAULT_ON_ERROR);

		runq_ts[cpu].cpu = cpu;
		runq_ts[cpu].ts = timestamp;
	}

	qsort(runq_ts, (size_t)kt->cpus, sizeof(struct runq_ts_info), compare_runq_ts);

	for (cpu = 0; cpu < kt->cpus; cpu++) {
		fprintf(fp, "%sCPU %d: %.2lf secs\n",
			space(2 + __log10ul(kt->cpus) - __log10ul(runq_ts[cpu].cpu)),
			runq_ts[cpu].cpu,
			((double)runq_ts[0].ts - (double)runq_ts[cpu].ts) / 1000000000.0);
	}
}

/*
 *  Displays the runqueue and active task timestamps of each cpu.
 */
static void
dump_on_rq_milliseconds(void)
{
	ulong runq;
	char buf[BUFSIZE];
	struct syment *rq_sp;
	struct task_context *tc;
	int cpu, max_indent, indent, max_days, days;
	long long delta;
	ulonglong task_timestamp, rq_timestamp;
	ulong *cpus;

	if (!(rq_sp = per_cpu_symbol_search("per_cpu__runqueues")))
		error(FATAL, "per-cpu runqueues do not exist\n");
	if (INVALID_MEMBER(rq_timestamp))
		option_not_supported('m');

	if (kt->cpus < 10)
		max_indent = 1;
	else if (kt->cpus < 100)
		max_indent = 2;
	else if (kt->cpus < 1000)
		max_indent = 3;
	else
		max_indent = 4;

	max_days = days = 0;
	cpus = pc->curcmd_flags & CPUMASK ? 
		(ulong *)(ulong)pc->curcmd_private : NULL;

	for (cpu = 0; cpu < kt->cpus; cpu++) {
		if (cpus && !NUM_IN_BITMAP(cpus, cpu))
			continue;

		if ((kt->flags & SMP) && (kt->flags &PER_CPU_OFF))
			runq = rq_sp->value + kt->__per_cpu_offset[cpu];
		else
			runq = rq_sp->value;

		readmem(runq + OFFSET(rq_timestamp), KVADDR, &rq_timestamp,
			sizeof(ulonglong), "per-cpu rq timestamp",
			FAULT_ON_ERROR);

		if (!max_days) {
			translate_nanoseconds(rq_timestamp, buf);
			max_days = first_space(buf) - buf;
		}

		if (cpu < 10)
			indent = max_indent;
		else if (cpu < 100)
			indent = max_indent - 1;
		else if (cpu < 1000)
			indent = max_indent - 2;
		else
			indent = max_indent - 4;

		if (hide_offline_cpu(cpu)) {
			fprintf(fp, "%sCPU %d: [OFFLINE]\n", space(indent), cpu);
			continue;
		}

		if ((tc = task_to_context(tt->active_set[cpu])))
			task_timestamp = task_last_run(tc->task);
		else { 
			fprintf(fp, "%sCPU %d: [unknown]\n", space(indent), cpu);
			continue;
		}

		delta = rq_timestamp - task_timestamp;
		if (delta < 0)
			delta = 0;
		translate_nanoseconds(delta, buf);
		days = first_space(buf) - buf;

		fprintf(fp, 
		    "%sCPU %d: [%s%s]  PID: %-5ld  TASK: %lx  COMMAND: \"%s\"\n",
			space(indent), cpu, space(max_days - days), buf, tc->pid,
			tc->task, tc->comm);
	}
}

/*
 *  Dump the task run queue on behalf cmd_runq().
 */

static void
dump_runq(void)
{
	int i;
	ulong next, runqueue_head;
	long offs;
	int qlen, cnt;
	ulong *tlist;
	struct task_context *tc;

	if (VALID_MEMBER(rq_cfs)) {
		dump_CFS_runqueues();
		return;
	}
 
	if (VALID_MEMBER(runqueue_arrays)) {
		dump_runqueues();
		return;
	}

	offs = runqueue_head = 0;
	qlen = 1000;

start_again:
	tlist = (ulong *)GETBUF(qlen * sizeof(void *));

        if (symbol_exists("runqueue_head")) {
		next = runqueue_head = symbol_value("runqueue_head");
		offs = 0;
        } else if (VALID_MEMBER(task_struct_next_run)) {
		offs = OFFSET(task_struct_next_run);
		next = runqueue_head = symbol_value("init_task_union");
	} else
		error(FATAL, 
		    "cannot determine run queue structures\n");

	cnt = 0;
	do {
		if (cnt == qlen) {
			FREEBUF(tlist);
			qlen += 1000;
			goto start_again;
		} 

		tlist[cnt++] = next;

                readmem(next+offs, KVADDR, &next, sizeof(void *), 
			"run queue entry", FAULT_ON_ERROR);

		if (next == runqueue_head)
			break;
	} while (next);

	for (i = 0; i < cnt; i++) {
		if (tlist[i] == runqueue_head)
			continue;

		if (!(tc = task_to_context(VIRTPAGEBASE(tlist[i])))) {
			fprintf(fp, 
			    	"PID: ?      TASK: %lx  CPU: ?   COMMAND: ?\n",
					tlist[i]);
			continue;
		}

		if (!is_idle_thread(tc->task))
			print_task_header(fp, tc, 0);
	}
}

#define RUNQ_ACTIVE  (1)
#define RUNQ_EXPIRED (2)

static void
dump_runqueues(void)
{
	int cpu, displayed;
	ulong runq, offset;
	char *runqbuf;
	ulong active, expired, arrays;
	struct task_context *tc;
	struct syment *rq_sp;
	ulong *cpus;

	runq = 0;

        rq_sp = per_cpu_symbol_search("per_cpu__runqueues");
	if (!rq_sp) {
		if (symbol_exists("runqueues"))
			runq = symbol_value("runqueues");
		else
			error(FATAL, "cannot determine run queue structures\n"); 
        }

	get_active_set();
        runqbuf = GETBUF(SIZE(runqueue));
	cpus = pc->curcmd_flags & CPUMASK ? 
		(ulong *)(ulong)pc->curcmd_private : NULL;

	for (cpu = displayed = 0; cpu < kt->cpus; cpu++, runq += SIZE(runqueue)) {
		if (cpus && !NUM_IN_BITMAP(cpus, cpu))
			continue;

		if (rq_sp) {
			if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF))
				runq = rq_sp->value + kt->__per_cpu_offset[cpu];
			else
				runq = rq_sp->value;
		}

		fprintf(fp, "%sCPU %d ", displayed++ ? "\n" : "", cpu);

		if (hide_offline_cpu(cpu)) {
			fprintf(fp, "[OFFLINE]\n");
			continue;
		} else
			fprintf(fp, "RUNQUEUE: %lx\n", runq);

		fprintf(fp, "  CURRENT: ");
		if ((tc = task_to_context(tt->active_set[cpu])))
			fprintf(fp, "PID: %-5ld  TASK: %lx  COMMAND: \"%s\"\n",
				tc->pid, tc->task, tc->comm);
		else
			fprintf(fp, "%lx\n", tt->active_set[cpu]);

                readmem(runq, KVADDR, runqbuf, SIZE(runqueue), 
			"runqueues array entry", FAULT_ON_ERROR);
		active = ULONG(runqbuf + OFFSET(runqueue_active));
		expired = ULONG(runqbuf + OFFSET(runqueue_expired));
		arrays = runq + OFFSET(runqueue_arrays);

		console("active: %lx\n", active);
		console("expired: %lx\n", expired);
		console("arrays: %lx\n", arrays);

		offset = active == arrays ? OFFSET(runqueue_arrays) :
			OFFSET(runqueue_arrays) + SIZE(prio_array);
		offset = active - runq;
		dump_prio_array(RUNQ_ACTIVE, active, &runqbuf[offset]);

		offset = expired == arrays ? OFFSET(runqueue_arrays) :
			OFFSET(runqueue_arrays) + SIZE(prio_array);
		offset = expired - runq;
		dump_prio_array(RUNQ_EXPIRED, expired, &runqbuf[offset]);
	}
}

static void
dump_prio_array(int which, ulong k_prio_array, char *u_prio_array)
{
	int i, c, cnt, tot, nr_active;
	int qheads ATTRIBUTE_UNUSED;
	ulong offset, kvaddr, uvaddr;
	ulong list_head[2];
        struct list_data list_data, *ld;
	struct task_context *tc;
	ulong *tlist;

        qheads = (i = ARRAY_LENGTH(prio_array_queue)) ?
                i : get_array_length("prio_array.queue", NULL, SIZE(list_head));

	console("dump_prio_array[%d]: %lx %lx\n",
		which, k_prio_array, (ulong)u_prio_array);

	nr_active = INT(u_prio_array + OFFSET(prio_array_nr_active));
	console("nr_active: %d\n", nr_active);

	fprintf(fp, "  %s PRIO_ARRAY: %lx\n",  
		which == RUNQ_ACTIVE ? "ACTIVE" : "EXPIRED", k_prio_array);

	if (CRASHDEBUG(1))
		fprintf(fp, "nr_active: %d\n", nr_active);

	ld = &list_data;

	for (i = tot = 0; i < 140; i++) {
		offset =  OFFSET(prio_array_queue) + (i * SIZE(list_head));
		kvaddr = k_prio_array + offset;
		uvaddr = (ulong)u_prio_array + offset;
		BCOPY((char *)uvaddr, (char *)&list_head[0], sizeof(ulong)*2);

		if (CRASHDEBUG(1))
			fprintf(fp, "prio_array[%d] @ %lx => %lx/%lx %s\n", 
				i, kvaddr, list_head[0], list_head[1],
				(list_head[0] == list_head[1]) && 
				(list_head[0] == kvaddr) ? "(empty)" : "");

		if ((list_head[0] == kvaddr) && (list_head[1] == kvaddr))
			continue;

		console("[%d] %lx => %lx-%lx ", i, kvaddr, list_head[0],
			list_head[1]);

		fprintf(fp, "     [%3d] ", i);

		BZERO(ld, sizeof(struct list_data));
		ld->start = list_head[0];
		ld->list_head_offset = OFFSET(task_struct_run_list);
		ld->end = kvaddr;
		hq_open();
		cnt = do_list(ld);
		hq_close();
		console("%d entries\n", cnt);
        	tlist = (ulong *)GETBUF((cnt) * sizeof(ulong));
		cnt = retrieve_list(tlist, cnt);
		for (c = 0; c < cnt; c++) {
			if (!(tc = task_to_context(tlist[c])))
				continue;
			if (c)
				INDENT(11);
			fprintf(fp, "PID: %-5ld  TASK: %lx  COMMAND: \"%s\"\n",
				tc->pid, tc->task, tc->comm);
		}
		tot += cnt;
		FREEBUF(tlist);
	}

	if (!tot) {
		INDENT(5);
		fprintf(fp, "[no tasks queued]\n");
	}
}

#define MAX_GROUP_NUM 200
struct task_group_info {
	int use;
	int depth;
	char *name;
	ulong task_group;
	struct task_group_info *parent;
};

static struct task_group_info **tgi_array;
static int tgi_p = 0;
static int tgi_p_max = 0;

static void
sort_task_group_info_array(void)
{
	int i, j;
	struct task_group_info *tmp;

	for (i = 0; i < tgi_p - 1; i++) {
		for (j = 0; j < tgi_p - i - 1; j++) {
			if (tgi_array[j]->depth > tgi_array[j+1]->depth) {
				tmp = tgi_array[j+1];
				tgi_array[j+1] = tgi_array[j];
				tgi_array[j] = tmp;
			}
		}
	}
}

static void
print_task_group_info_array(void)
{
	int i;

	for (i = 0; i < tgi_p; i++) {
		fprintf(fp, "%d : use=%d, depth=%d, group=%lx, ", i,
			tgi_array[i]->use, tgi_array[i]->depth,
			tgi_array[i]->task_group);
		fprintf(fp, "name=%s, ",
			tgi_array[i]->name ? tgi_array[i]->name : "NULL");
		if (tgi_array[i]->parent)
			fprintf(fp, "parent=%lx",
				tgi_array[i]->parent->task_group);
		fprintf(fp, "\n");
	}
}

static void
free_task_group_info_array(void)
{
	int i;

	for (i = 0; i < tgi_p; i++) {
		if (tgi_array[i]->name)
			FREEBUF(tgi_array[i]->name);
		FREEBUF(tgi_array[i]);
	}
	tgi_p = 0;
	FREEBUF(tgi_array);
}

static void
reuse_task_group_info_array(void)
{
	int i;

	for (i = 0; i < tgi_p; i++) {
		if (tgi_array[i]->depth == 0)
			tgi_array[i]->use = 0;
		else
			tgi_array[i]->use = 1;
	}
}

static void
dump_task_runq_entry(struct task_context *tc, int current)
{
	int prio;

	readmem(tc->task + OFFSET(task_struct_prio), KVADDR, 
		&prio, sizeof(int), "task prio", FAULT_ON_ERROR);
	fprintf(fp, "[%3d] ", prio);
	fprintf(fp, "PID: %-5ld  TASK: %lx  COMMAND: \"%s\"",
		tc->pid, tc->task, tc->comm);
	if (current)
		fprintf(fp, " [CURRENT]\n");
	else
		fprintf(fp, "\n");
}

static void
print_group_header_fair(int depth, ulong cfs_rq, void *t)
{
	int throttled;
	struct task_group_info *tgi = (struct task_group_info *)t;

	INDENT(2 + 3 * depth);
	fprintf(fp, "TASK_GROUP: %lx  CFS_RQ: %lx ",
		tgi->task_group, cfs_rq);
	if (tgi->name)
		fprintf(fp, " <%s>", tgi->name);

	if (VALID_MEMBER(cfs_rq_throttled)) {
		readmem(cfs_rq + OFFSET(cfs_rq_throttled), KVADDR,
			&throttled, sizeof(int), "cfs_rq throttled",
			FAULT_ON_ERROR);
		if (throttled)
			fprintf(fp, " (THROTTLED)");
	}
	fprintf(fp, "\n");
}

static void
print_parent_task_group_fair(void *t, int cpu)
{
	struct task_group_info *tgi;
	ulong cfs_rq_c, cfs_rq_p;

	tgi = ((struct task_group_info *)t)->parent;
	if (tgi && tgi->use)
		print_parent_task_group_fair(tgi, cpu);
	else
		return;

	readmem(tgi->task_group + OFFSET(task_group_cfs_rq),
		KVADDR, &cfs_rq_c, sizeof(ulong),
		"task_group cfs_rq", FAULT_ON_ERROR);
	readmem(cfs_rq_c + cpu * sizeof(ulong), KVADDR, &cfs_rq_p,
		sizeof(ulong), "task_group cfs_rq", FAULT_ON_ERROR);

	print_group_header_fair(tgi->depth, cfs_rq_p, tgi);
	tgi->use = 0;
}

static int
dump_tasks_in_lower_dequeued_cfs_rq(int depth, ulong cfs_rq, int cpu,
	struct task_context *ctc)
{
	int i, total, nr_running;
	ulong group, cfs_rq_c, cfs_rq_p;

	total = 0;
	for (i = 0; i < tgi_p; i++) {
		if (tgi_array[i]->use == 0 || tgi_array[i]->depth - depth != 1)
			continue;

		readmem(cfs_rq + OFFSET(cfs_rq_tg), KVADDR, &group,
			sizeof(ulong), "cfs_rq tg", FAULT_ON_ERROR);
		if (group != tgi_array[i]->parent->task_group)
			continue;

		readmem(tgi_array[i]->task_group + OFFSET(task_group_cfs_rq),
			KVADDR, &cfs_rq_c, sizeof(ulong), "task_group cfs_rq",
			FAULT_ON_ERROR);
		readmem(cfs_rq_c + cpu * sizeof(ulong), KVADDR, &cfs_rq_p,
			sizeof(ulong), "task_group cfs_rq", FAULT_ON_ERROR);
		if (cfs_rq == cfs_rq_p)
			continue;

		readmem(cfs_rq_p + OFFSET(cfs_rq_nr_running), KVADDR,
			&nr_running, sizeof(int), "cfs_rq nr_running",
			FAULT_ON_ERROR);
		if (nr_running == 0) {
			total += dump_tasks_in_lower_dequeued_cfs_rq(depth + 1,
				cfs_rq_p, cpu, ctc);
			continue;
		}

		print_parent_task_group_fair(tgi_array[i], cpu);

		total++;
		total += dump_tasks_in_task_group_cfs_rq(depth + 1, cfs_rq_p, cpu, ctc);
	}

	return total;
}

static int
dump_tasks_in_cfs_rq(ulong cfs_rq)
{
	struct task_context *tc;
	struct rb_root *root;
	struct rb_node *node;
	ulong my_q, leftmost, curr, curr_my_q;
	int total;

	total = 0;

	if (VALID_MEMBER(sched_entity_my_q)) {
		readmem(cfs_rq + OFFSET(cfs_rq_curr), KVADDR, &curr, 
			sizeof(ulong), "curr", FAULT_ON_ERROR);
		if (curr) {
			readmem(curr + OFFSET(sched_entity_my_q), KVADDR, 
				&curr_my_q, sizeof(ulong), "curr->my_q", 
				FAULT_ON_ERROR);
			if (curr_my_q)
				total += dump_tasks_in_cfs_rq(curr_my_q);
		}
	}

	readmem(cfs_rq + OFFSET(cfs_rq_rb_leftmost), KVADDR, &leftmost,
		sizeof(ulong), "rb_leftmost", FAULT_ON_ERROR);
	root = (struct rb_root *)(cfs_rq + OFFSET(cfs_rq_tasks_timeline));

	for (node = rb_first(root); leftmost && node; node = rb_next(node)) {
		if (VALID_MEMBER(sched_entity_my_q)) {
			readmem((ulong)node - OFFSET(sched_entity_run_node)
				+ OFFSET(sched_entity_my_q), KVADDR, &my_q,
				sizeof(ulong), "my_q", FAULT_ON_ERROR);
			if (my_q) {
				total += dump_tasks_in_cfs_rq(my_q);
				continue;
			}
		}

		tc = task_to_context((ulong)node - OFFSET(task_struct_se) -
				     OFFSET(sched_entity_run_node));
		if (!tc)
			continue;
		if (hq_enter((ulong)tc)) {
			INDENT(5);
			dump_task_runq_entry(tc, 0);
		} else {
			error(WARNING, "duplicate CFS runqueue node: task %lx\n",
				tc->task);
			return total;
		}
		total++;
	}

	return total;
}

static int
dump_tasks_in_task_group_cfs_rq(int depth, ulong cfs_rq, int cpu,
	struct task_context *ctc)
{
	struct task_context *tc;
	struct rb_root *root;
	struct rb_node *node;
	ulong my_q, leftmost, curr, curr_my_q, tg;
	int total, i;

	total = 0;
	curr_my_q = curr = 0;

	if (depth) {
		readmem(cfs_rq + OFFSET(cfs_rq_tg), KVADDR,
			&tg, sizeof(ulong), "cfs_rq tg",
			FAULT_ON_ERROR);
		for (i = 0; i < tgi_p; i++) {
			if (tgi_array[i]->task_group == tg) {
				print_group_header_fair(depth,
					cfs_rq, tgi_array[i]);
				tgi_array[i]->use = 0;
				break;
			}
		}
	}

	if (VALID_MEMBER(sched_entity_my_q)) {
		readmem(cfs_rq + OFFSET(cfs_rq_curr), KVADDR, &curr,
			sizeof(ulong), "curr", FAULT_ON_ERROR);
		if (curr) {
			readmem(curr + OFFSET(sched_entity_my_q), KVADDR,
				&curr_my_q, sizeof(ulong), "curr->my_q",
				FAULT_ON_ERROR);
			if (curr_my_q) {
				total++;
				total += dump_tasks_in_task_group_cfs_rq(depth + 1,
					curr_my_q, cpu, ctc);
			}
		}
	}

	/*
	 *  check if "curr" is the task that is current running task
	 */
	if (!curr_my_q && ctc && (curr - OFFSET(task_struct_se)) == ctc->task) {
		/* curr is not in the rb tree, so let's print it here */
		total++;
		INDENT(5 + 3 * depth);
		dump_task_runq_entry(ctc, 1);
	}

	readmem(cfs_rq + OFFSET(cfs_rq_rb_leftmost), KVADDR, &leftmost,
		sizeof(ulong), "rb_leftmost", FAULT_ON_ERROR);
	root = (struct rb_root *)(cfs_rq + OFFSET(cfs_rq_tasks_timeline));

	for (node = rb_first(root); leftmost && node; node = rb_next(node)) {
		if (VALID_MEMBER(sched_entity_my_q)) {
			readmem((ulong)node - OFFSET(sched_entity_run_node)
				+ OFFSET(sched_entity_my_q), KVADDR, &my_q,
				sizeof(ulong), "my_q", FAULT_ON_ERROR);
			if (my_q) {
				total++;
				total += dump_tasks_in_task_group_cfs_rq(depth + 1,
					my_q, cpu, ctc);
				continue;
			}
		}

		tc = task_to_context((ulong)node - OFFSET(task_struct_se) -
				     OFFSET(sched_entity_run_node));
		if (!tc)
			continue;
		if (hq_enter((ulong)tc)) {
			INDENT(5 + 3 * depth);
			dump_task_runq_entry(tc, 0);
		} else {
			error(WARNING, "duplicate CFS runqueue node: task %lx\n",
				tc->task);
			return total;
		}
		total++;
	}

	total += dump_tasks_in_lower_dequeued_cfs_rq(depth, cfs_rq, cpu, ctc);

	if (!total) {
		INDENT(5 + 3 * depth);
		fprintf(fp, "[no tasks queued]\n");
	}
	return total;
}

static void
dump_on_rq_tasks(void)
{
	char buf[BUFSIZE];
	struct task_context *tc;
	int i, cpu, on_rq, tot;
	ulong *cpus;

	if (!VALID_MEMBER(task_struct_on_rq)) {
		MEMBER_OFFSET_INIT(task_struct_se, "task_struct", "se");
		STRUCT_SIZE_INIT(sched_entity, "sched_entity");
		MEMBER_OFFSET_INIT(sched_entity_on_rq, "sched_entity", "on_rq");
		MEMBER_OFFSET_INIT(task_struct_on_rq, "task_struct", "on_rq");
                MEMBER_OFFSET_INIT(task_struct_prio, "task_struct", "prio");
		if (INVALID_MEMBER(task_struct_on_rq)) {
			if (INVALID_MEMBER(task_struct_se) ||
			    INVALID_SIZE(sched_entity))
				option_not_supported('d');
		}
	}

	cpus = pc->curcmd_flags & CPUMASK ? 
		(ulong *)(ulong)pc->curcmd_private : NULL;

	for (cpu = 0; cpu < kt->cpus; cpu++) {
		if (cpus && !NUM_IN_BITMAP(cpus, cpu))
			continue;

                fprintf(fp, "%sCPU %d", cpu ? "\n" : "", cpu);

		if (hide_offline_cpu(cpu)) {
			fprintf(fp, " [OFFLINE]\n");
			continue;
		} else
			fprintf(fp, "\n");

		tc = FIRST_CONTEXT();
		tot = 0;

		for (i = 0; i < RUNNING_TASKS(); i++, tc++) {

			if (VALID_MEMBER(task_struct_on_rq)) {
				readmem(tc->task + OFFSET(task_struct_on_rq),
					KVADDR, &on_rq, sizeof(int),
					"task on_rq", FAULT_ON_ERROR);
			} else {
				readmem(tc->task + OFFSET(task_struct_se), KVADDR,
					buf, SIZE(sched_entity), "task se",
					FAULT_ON_ERROR);
				on_rq = INT(buf + OFFSET(sched_entity_on_rq));
			}

			if (!on_rq || tc->processor != cpu)
				continue;

			INDENT(5);
			dump_task_runq_entry(tc, 0);
			tot++;
		}

		if (!tot) {
			INDENT(5);
			fprintf(fp, "[no tasks queued]\n");
		}
	}
}

static void
cfs_rq_offset_init(void)
{
	if (!VALID_STRUCT(cfs_rq)) {
		STRUCT_SIZE_INIT(cfs_rq, "cfs_rq");
		STRUCT_SIZE_INIT(rt_rq, "rt_rq");
		MEMBER_OFFSET_INIT(rq_rt, "rq", "rt");
		MEMBER_OFFSET_INIT(rq_nr_running, "rq", "nr_running");
		MEMBER_OFFSET_INIT(task_struct_se, "task_struct", "se");
		STRUCT_SIZE_INIT(sched_entity, "sched_entity");
		MEMBER_OFFSET_INIT(sched_entity_run_node, "sched_entity", 
			"run_node");
		MEMBER_OFFSET_INIT(sched_entity_cfs_rq, "sched_entity", 
			"cfs_rq");
		MEMBER_OFFSET_INIT(sched_entity_my_q, "sched_entity", 
			"my_q");
		MEMBER_OFFSET_INIT(sched_rt_entity_my_q, "sched_rt_entity",
			"my_q");
		MEMBER_OFFSET_INIT(sched_entity_on_rq, "sched_entity", "on_rq");
		MEMBER_OFFSET_INIT(cfs_rq_tasks_timeline, "cfs_rq", 
			"tasks_timeline");
		MEMBER_OFFSET_INIT(cfs_rq_rb_leftmost, "cfs_rq", "rb_leftmost");
		if (INVALID_MEMBER(cfs_rq_rb_leftmost) && 
		    VALID_MEMBER(cfs_rq_tasks_timeline) &&
		    MEMBER_EXISTS("rb_root_cached", "rb_leftmost"))
			ASSIGN_OFFSET(cfs_rq_rb_leftmost) = OFFSET(cfs_rq_tasks_timeline) + 
				MEMBER_OFFSET("rb_root_cached", "rb_leftmost");
		MEMBER_OFFSET_INIT(cfs_rq_nr_running, "cfs_rq", "nr_running");
		MEMBER_OFFSET_INIT(cfs_rq_curr, "cfs_rq", "curr");
		MEMBER_OFFSET_INIT(rt_rq_active, "rt_rq", "active");
                MEMBER_OFFSET_INIT(task_struct_run_list, "task_struct",
                        "run_list");
		MEMBER_OFFSET_INIT(task_struct_on_rq, "task_struct", "on_rq");
                MEMBER_OFFSET_INIT(task_struct_prio, "task_struct",
                        "prio");
		MEMBER_OFFSET_INIT(task_struct_rt, "task_struct", "rt");
		MEMBER_OFFSET_INIT(sched_rt_entity_run_list, "sched_rt_entity", 
			"run_list");
		MEMBER_OFFSET_INIT(rt_prio_array_queue, "rt_prio_array", "queue");
	}
}

static void
task_group_offset_init(void)
{
	if (!VALID_STRUCT(task_group)) {
		STRUCT_SIZE_INIT(task_group, "task_group");
		MEMBER_OFFSET_INIT(rt_rq_rt_nr_running, "rt_rq", "rt_nr_running");
		MEMBER_OFFSET_INIT(cfs_rq_tg, "cfs_rq", "tg");
		MEMBER_OFFSET_INIT(rt_rq_tg, "rt_rq", "tg");
		MEMBER_OFFSET_INIT(rt_rq_highest_prio, "rt_rq", "highest_prio");
		MEMBER_OFFSET_INIT(task_group_css, "task_group", "css");
		MEMBER_OFFSET_INIT(cgroup_subsys_state_cgroup,
			"cgroup_subsys_state", "cgroup");

		MEMBER_OFFSET_INIT(cgroup_dentry, "cgroup", "dentry");
		MEMBER_OFFSET_INIT(cgroup_kn, "cgroup", "kn");
		MEMBER_OFFSET_INIT(kernfs_node_name, "kernfs_node", "name");
		MEMBER_OFFSET_INIT(kernfs_node_parent, "kernfs_node", "parent");

		MEMBER_OFFSET_INIT(task_group_siblings, "task_group", "siblings");
		MEMBER_OFFSET_INIT(task_group_children, "task_group", "children");

		MEMBER_OFFSET_INIT(task_group_cfs_bandwidth,
			"task_group", "cfs_bandwidth");
		MEMBER_OFFSET_INIT(cfs_rq_throttled, "cfs_rq",
			"throttled");

		MEMBER_OFFSET_INIT(task_group_rt_bandwidth,
			"task_group", "rt_bandwidth");
		MEMBER_OFFSET_INIT(rt_rq_rt_throttled, "rt_rq",
			"rt_throttled");
	}
}

static void
dump_CFS_runqueues(void)
{
	int cpu, tot, displayed;
	ulong runq, cfs_rq, prio_array;
	char *runqbuf, *cfs_rq_buf;
	ulong tasks_timeline ATTRIBUTE_UNUSED;
	struct task_context *tc;
	struct rb_root *root;
	struct syment *rq_sp, *init_sp;
	ulong *cpus;

	cfs_rq_offset_init();

	if (!(rq_sp = per_cpu_symbol_search("per_cpu__runqueues")))
		error(FATAL, "per-cpu runqueues do not exist\n");

        runqbuf = GETBUF(SIZE(runqueue));
	if ((init_sp = per_cpu_symbol_search("per_cpu__init_cfs_rq")))
		cfs_rq_buf = GETBUF(SIZE(cfs_rq));
	else
		cfs_rq_buf = NULL;

	get_active_set();
	cpus = pc->curcmd_flags & CPUMASK ? 
		(ulong *)(ulong)pc->curcmd_private : NULL;

        for (cpu = displayed = 0; cpu < kt->cpus; cpu++) {
		if (cpus && !NUM_IN_BITMAP(cpus, cpu))
			continue;
		
		if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF))
			runq = rq_sp->value + kt->__per_cpu_offset[cpu];
		else
			runq = rq_sp->value;

                fprintf(fp, "%sCPU %d ", displayed++ ? "\n" : "", cpu);

		if (hide_offline_cpu(cpu)) {
			fprintf(fp, "[OFFLINE]\n");
			continue;
		} else
			fprintf(fp, "RUNQUEUE: %lx\n", runq);

		fprintf(fp, "  CURRENT: ");
		if ((tc = task_to_context(tt->active_set[cpu])))
			fprintf(fp, "PID: %-5ld  TASK: %lx  COMMAND: \"%s\"\n",
				tc->pid, tc->task, tc->comm);
		else
			fprintf(fp, "%lx\n", tt->active_set[cpu]);

                readmem(runq, KVADDR, runqbuf, SIZE(runqueue),
                        "per-cpu rq", FAULT_ON_ERROR);

		if (cfs_rq_buf) {
			/*
		 	 *  Use default task group's cfs_rq on each cpu.
		 	 */
			if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF))
				cfs_rq = init_sp->value + kt->__per_cpu_offset[cpu];
			else
				cfs_rq = init_sp->value;

			readmem(cfs_rq, KVADDR, cfs_rq_buf, SIZE(cfs_rq),
				"per-cpu cfs_rq", FAULT_ON_ERROR);
			root = (struct rb_root *)(cfs_rq + 
				OFFSET(cfs_rq_tasks_timeline));
		} else {
			cfs_rq = runq + OFFSET(rq_cfs);
			root = (struct rb_root *)(runq + OFFSET(rq_cfs) + 
				OFFSET(cfs_rq_tasks_timeline));
		}

		prio_array = runq + OFFSET(rq_rt) + OFFSET(rt_rq_active);
		fprintf(fp, "  RT PRIO_ARRAY: %lx\n",  prio_array);

		tot = dump_RT_prio_array(prio_array,
			&runqbuf[OFFSET(rq_rt) + OFFSET(rt_rq_active)]);
		if (!tot) {
			INDENT(5);
			fprintf(fp, "[no tasks queued]\n");
		}

		fprintf(fp, "  CFS RB_ROOT: %lx\n", (ulong)root);

		hq_open();
		tot = dump_tasks_in_cfs_rq(cfs_rq);
		hq_close();

		if (!tot) {
			INDENT(5);
			fprintf(fp, "[no tasks queued]\n");
		}
	}

	FREEBUF(runqbuf);
	if (cfs_rq_buf)
		FREEBUF(cfs_rq_buf);
}

static void
print_group_header_rt(ulong rt_rq, void *t)
{
	int throttled;
	struct task_group_info *tgi = (struct task_group_info *)t;

	fprintf(fp, "TASK_GROUP: %lx  RT_RQ: %lx", tgi->task_group, rt_rq);
	if (tgi->name)
		fprintf(fp, " <%s>", tgi->name);

	if (VALID_MEMBER(task_group_rt_bandwidth)) {
		readmem(rt_rq + OFFSET(rt_rq_rt_throttled), KVADDR,
			&throttled, sizeof(int), "rt_rq rt_throttled",
			FAULT_ON_ERROR);
		if (throttled)
			fprintf(fp, " (THROTTLED)");
	}
	fprintf(fp, "\n");
}

static void
print_parent_task_group_rt(void *t, int cpu)
{
	int prio;
	struct task_group_info *tgi;
	ulong rt_rq_c, rt_rq_p;


	tgi = ((struct task_group_info *)t)->parent;
	if (tgi && tgi->use)
		print_parent_task_group_fair(tgi, cpu);
	else
		return;

	readmem(tgi->task_group + OFFSET(task_group_rt_rq),
		KVADDR, &rt_rq_c, sizeof(ulong),
		"task_group rt_rq", FAULT_ON_ERROR);
	readmem(rt_rq_c + cpu * sizeof(ulong), KVADDR, &rt_rq_p,
		sizeof(ulong), "task_group rt_rq", FAULT_ON_ERROR);

	readmem(rt_rq_p + OFFSET(rt_rq_highest_prio), KVADDR, &prio,
		sizeof(int), "rt_rq highest prio", FAULT_ON_ERROR);

	INDENT(-1 + 6 * tgi->depth);
	fprintf(fp, "[%3d] ", prio);
	print_group_header_rt(rt_rq_p, tgi);
	tgi->use = 0;
}

static int
dump_tasks_in_lower_dequeued_rt_rq(int depth, ulong rt_rq, int cpu)
{
	int i, prio, tot, delta, nr_running;
	ulong rt_rq_c, rt_rq_p, group;

	tot = 0;
	for (i = 0; i < tgi_p; i++) {
		delta = tgi_array[i]->depth - depth;
		if (delta > 1)
			break;

		if (tgi_array[i]->use == 0 || delta < 1)
			continue;

		readmem(rt_rq + OFFSET(rt_rq_tg), KVADDR, &group,
			sizeof(ulong), "rt_rq tg", FAULT_ON_ERROR);
		if (group != tgi_array[i]->parent->task_group)
			continue;

		readmem(tgi_array[i]->task_group + OFFSET(task_group_rt_rq),
			KVADDR, &rt_rq_c, sizeof(ulong), "task_group rt_rq",
			FAULT_ON_ERROR);
		readmem(rt_rq_c + cpu * sizeof(ulong), KVADDR, &rt_rq_p,
			sizeof(ulong), "task_group rt_rq", FAULT_ON_ERROR);
		if (rt_rq == rt_rq_p)
			continue;

		readmem(rt_rq_p + OFFSET(rt_rq_rt_nr_running), KVADDR,
			&nr_running, sizeof(int), "rt_rq rt_nr_running",
			FAULT_ON_ERROR);
		if (nr_running == 0) {
			tot += dump_tasks_in_lower_dequeued_rt_rq(depth + 1,
				rt_rq_p, cpu);
			continue;
		}

		print_parent_task_group_rt(tgi_array[i], cpu);

		readmem(rt_rq_p + OFFSET(rt_rq_highest_prio), KVADDR,
			&prio, sizeof(int), "rt_rq highest_prio",
			FAULT_ON_ERROR);
		INDENT(5 + 6 * depth);
		fprintf(fp, "[%3d] ", prio);
		tot++;
		dump_tasks_in_task_group_rt_rq(depth + 1, rt_rq_p, cpu);
	}

	return tot;
}

static int
dump_RT_prio_array(ulong k_prio_array, char *u_prio_array)
{
	int i, c, tot, cnt, qheads;
	ulong offset, kvaddr, uvaddr;
	ulong list_head[2];
        struct list_data list_data, *ld;
	struct task_context *tc;
	ulong my_q, task_addr;
	char *rt_rq_buf;

        qheads = (i = ARRAY_LENGTH(rt_prio_array_queue)) ?
                i : get_array_length("rt_prio_array.queue", NULL, SIZE(list_head));

	ld = &list_data;

	for (i = tot = 0; i < qheads; i++) {
		offset =  OFFSET(rt_prio_array_queue) + (i * SIZE(list_head));
		kvaddr = k_prio_array + offset;
		uvaddr = (ulong)u_prio_array + offset;
		BCOPY((char *)uvaddr, (char *)&list_head[0], sizeof(ulong)*2);

		if (CRASHDEBUG(1))
			fprintf(fp, "rt_prio_array[%d] @ %lx => %lx/%lx\n", 
				i, kvaddr, list_head[0], list_head[1]);

		if ((list_head[0] == kvaddr) && (list_head[1] == kvaddr))
			continue;

		BZERO(ld, sizeof(struct list_data));
		ld->start = list_head[0];
		ld->flags |= LIST_ALLOCATE;
		if (VALID_MEMBER(task_struct_rt) &&
		    VALID_MEMBER(sched_rt_entity_run_list))
			ld->list_head_offset = OFFSET(sched_rt_entity_run_list);
		else
			ld->list_head_offset = OFFSET(task_struct_run_list);
		ld->end = kvaddr;
		cnt = do_list(ld);
		for (c = 0; c < cnt; c++) {
			task_addr = ld->list_ptr[c];
			if (VALID_MEMBER(sched_rt_entity_my_q)) {
				readmem(ld->list_ptr[c] + OFFSET(sched_rt_entity_my_q),
					KVADDR, &my_q, sizeof(ulong), "my_q",
					FAULT_ON_ERROR);
				if (my_q) {
					rt_rq_buf = GETBUF(SIZE(rt_rq));
					readmem(my_q, KVADDR, rt_rq_buf,
						SIZE(rt_rq), "rt_rq",
						FAULT_ON_ERROR);

					tot += dump_RT_prio_array(
						my_q + OFFSET(rt_rq_active),
						&rt_rq_buf[OFFSET(rt_rq_active)]);
					FREEBUF(rt_rq_buf);
					continue;
				}
			}
			if (VALID_MEMBER(task_struct_rt))
				task_addr -= OFFSET(task_struct_rt);
			else
				task_addr -= OFFSET(task_struct_run_list);

			if (!(tc = task_to_context(task_addr)))
				continue;

			INDENT(5);
			fprintf(fp, "[%3d] ", i);
			fprintf(fp, "PID: %-5ld  TASK: %lx  COMMAND: \"%s\"\n",
				tc->pid, tc->task, tc->comm);
			tot++;
		}
		FREEBUF(ld->list_ptr);
	}

	return tot;
}

static void
dump_tasks_in_task_group_rt_rq(int depth, ulong rt_rq, int cpu)
{
	int i, c, tot, cnt, qheads;
	ulong offset, kvaddr, uvaddr;
	ulong list_head[2];
        struct list_data list_data, *ld;
	struct task_context *tc;
	ulong my_q, task_addr, tg, k_prio_array;
	char *rt_rq_buf, *u_prio_array;

	k_prio_array = rt_rq +  OFFSET(rt_rq_active);
	rt_rq_buf = GETBUF(SIZE(rt_rq));
	readmem(rt_rq, KVADDR, rt_rq_buf, SIZE(rt_rq), "rt_rq", FAULT_ON_ERROR);
	u_prio_array = &rt_rq_buf[OFFSET(rt_rq_active)];

	if (depth) {
		readmem(rt_rq + OFFSET(rt_rq_tg), KVADDR,
			&tg, sizeof(ulong), "rt_rq tg",
			FAULT_ON_ERROR);
		for (i = 0; i < tgi_p; i++) {
			if (tgi_array[i]->task_group == tg) {
				print_group_header_rt(rt_rq, tgi_array[i]);
				tgi_array[i]->use = 0;
				break;
			}
		}
	}

        qheads = (i = ARRAY_LENGTH(rt_prio_array_queue)) ?
                i : get_array_length("rt_prio_array.queue", NULL, SIZE(list_head));

	ld = &list_data;

	for (i = tot = 0; i < qheads; i++) {
		offset =  OFFSET(rt_prio_array_queue) + (i * SIZE(list_head));
		kvaddr = k_prio_array + offset;
		uvaddr = (ulong)u_prio_array + offset;
		BCOPY((char *)uvaddr, (char *)&list_head[0], sizeof(ulong)*2);

		if (CRASHDEBUG(1))
			fprintf(fp, "rt_prio_array[%d] @ %lx => %lx/%lx\n",
				i, kvaddr, list_head[0], list_head[1]);

		if ((list_head[0] == kvaddr) && (list_head[1] == kvaddr))
			continue;

		BZERO(ld, sizeof(struct list_data));
		ld->start = list_head[0];
		ld->flags |= LIST_ALLOCATE;
		if (VALID_MEMBER(task_struct_rt) &&
		    VALID_MEMBER(sched_rt_entity_run_list))
			ld->list_head_offset = OFFSET(sched_rt_entity_run_list);
		else
			ld->list_head_offset = OFFSET(task_struct_run_list);
		ld->end = kvaddr;
		cnt = do_list(ld);
		for (c = 0; c < cnt; c++) {
			task_addr = ld->list_ptr[c];
			if (INVALID_MEMBER(sched_rt_entity_my_q))
				goto is_task;

			readmem(ld->list_ptr[c] + OFFSET(sched_rt_entity_my_q),
				KVADDR, &my_q, sizeof(ulong), "my_q",
				FAULT_ON_ERROR);
			if (!my_q) {
				task_addr -= OFFSET(task_struct_rt);
				goto is_task;
			}

			INDENT(5 + 6 * depth);
			fprintf(fp, "[%3d] ", i);
			tot++;
			dump_tasks_in_task_group_rt_rq(depth + 1, my_q, cpu);
			continue;

is_task:
			if (!(tc = task_to_context(task_addr)))
				continue;

			INDENT(5 + 6 * depth);
			fprintf(fp, "[%3d] ", i);
			fprintf(fp, "PID: %-5ld  TASK: %lx  COMMAND: \"%s\"\n",
				tc->pid, tc->task, tc->comm);
			tot++;
		}
		FREEBUF(ld->list_ptr);
	}

	tot += dump_tasks_in_lower_dequeued_rt_rq(depth, rt_rq, cpu);

	if (!tot) {
		INDENT(5 + 6 * depth);
		fprintf(fp, "[no tasks queued]\n");
	}
	FREEBUF(rt_rq_buf);
}

static char *
get_task_group_name(ulong group)
{
	ulong cgroup, dentry, kernfs_node, parent, name;
	char *dentry_buf, *tmp;
	char buf[BUFSIZE];
	int len;

	tmp = NULL;
	readmem(group + OFFSET(task_group_css) + OFFSET(cgroup_subsys_state_cgroup),
		KVADDR, &cgroup, sizeof(ulong),
		"task_group css cgroup", FAULT_ON_ERROR);
	if (cgroup == 0)
		return NULL;

	if (VALID_MEMBER(cgroup_dentry)) {
		readmem(cgroup + OFFSET(cgroup_dentry), KVADDR, &dentry, sizeof(ulong),
			"cgroup dentry", FAULT_ON_ERROR);
		if (dentry == 0)
			return NULL;
	
		dentry_buf = GETBUF(SIZE(dentry));
		readmem(dentry, KVADDR, dentry_buf, SIZE(dentry),
			"dentry", FAULT_ON_ERROR);
		len = UINT(dentry_buf + OFFSET(dentry_d_name) + OFFSET(qstr_len));
		tmp = GETBUF(len + 1);
		name = ULONG(dentry_buf + OFFSET(dentry_d_name) + OFFSET(qstr_name));
		readmem(name, KVADDR, tmp, len, "qstr name", FAULT_ON_ERROR);
	
		FREEBUF(dentry_buf);
		return tmp;
	}

	/*
	 *  Emulate kernfs_name() and kernfs_name_locked()
	 */
	if (INVALID_MEMBER(cgroup_kn) || INVALID_MEMBER(kernfs_node_name) ||
	    INVALID_MEMBER(kernfs_node_parent))
		return NULL;

	readmem(cgroup + OFFSET(cgroup_kn), KVADDR, &kernfs_node, sizeof(ulong),
		"cgroup kn", FAULT_ON_ERROR);
	if (kernfs_node == 0)
		return NULL;

	readmem(kernfs_node + OFFSET(kernfs_node_parent), KVADDR, &parent, 
		sizeof(ulong), "kernfs_node parent", FAULT_ON_ERROR);
	if (!parent) {
		tmp = GETBUF(2);
		strcpy(tmp, "/");
		return tmp;
	}

	readmem(kernfs_node + OFFSET(kernfs_node_name), KVADDR, &name, 
		sizeof(ulong), "kernfs_node name", FAULT_ON_ERROR);
	if (!name || !read_string(name, buf, BUFSIZE-1))
		return NULL;

	tmp = GETBUF(strlen(buf)+1);
	strcpy(tmp, buf);

	return tmp;
}

static void
fill_task_group_info_array(int depth, ulong group, char *group_buf, int i)
{
	int d;
	ulong kvaddr, uvaddr, offset;
	ulong list_head[2], next;
	struct task_group_info **tgi_array_new;

	d = tgi_p;
	tgi_array[tgi_p] = (struct task_group_info *)
		GETBUF(sizeof(struct task_group_info));
	if (depth)
		tgi_array[tgi_p]->use = 1;
	else
		tgi_array[tgi_p]->use = 0;

	tgi_array[tgi_p]->depth = depth;
	tgi_array[tgi_p]->name = get_task_group_name(group);
	tgi_array[tgi_p]->task_group = group;
	if (i >= 0)
		tgi_array[tgi_p]->parent = tgi_array[i];
	else
		tgi_array[tgi_p]->parent = NULL;
	tgi_p++;

	if (tgi_p == tgi_p_max) {
		tgi_p_max += MAX_GROUP_NUM;
		tgi_array_new = (struct task_group_info **)
			GETBUF(sizeof(void *) * tgi_p_max);
		BCOPY(tgi_array, tgi_array_new, sizeof(void *) * tgi_p);
		FREEBUF(tgi_array);
		tgi_array = tgi_array_new;
	}

	offset = OFFSET(task_group_children);
	kvaddr = group + offset;
	uvaddr = (ulong)(group_buf + offset);
	BCOPY((char *)uvaddr, (char *)&list_head[0], sizeof(ulong)*2);

	if ((list_head[0] == kvaddr) && (list_head[1] == kvaddr))
		return;

	next = list_head[0];
	while (next != kvaddr) {
		group = next - OFFSET(task_group_siblings);
		readmem(group, KVADDR, group_buf, SIZE(task_group),
			"task_group", FAULT_ON_ERROR);
		next = ULONG(group_buf + OFFSET(task_group_siblings) +
			OFFSET(list_head_next));
		fill_task_group_info_array(depth + 1, group, group_buf, d);
	}
}

static void
dump_tasks_by_task_group(void)
{
	int cpu, displayed;
	ulong root_task_group, cfs_rq = 0, cfs_rq_p;
	ulong rt_rq = 0, rt_rq_p;
	char *buf;
	struct task_context *tc;
	char *task_group_name;
	ulong *cpus;

	cfs_rq_offset_init();
	task_group_offset_init();

	root_task_group = 0;
	task_group_name = NULL;
	if (symbol_exists("init_task_group")) {
		root_task_group = symbol_value("init_task_group");
		task_group_name = "INIT";
	} else if (symbol_exists("root_task_group")) {
		root_task_group = symbol_value("root_task_group");
		task_group_name = "ROOT";
	} else
		error(FATAL, "cannot determine root task_group\n");

	tgi_p_max = MAX_GROUP_NUM;
	tgi_array = (struct task_group_info **)GETBUF(sizeof(void *)
		* tgi_p_max);
	buf = GETBUF(SIZE(task_group));
	readmem(root_task_group, KVADDR, buf, SIZE(task_group),
		"task_group", FAULT_ON_ERROR);
	if (VALID_MEMBER(task_group_rt_rq))
		rt_rq = ULONG(buf + OFFSET(task_group_rt_rq));
	if (VALID_MEMBER(task_group_cfs_rq))
		cfs_rq = ULONG(buf + OFFSET(task_group_cfs_rq));

	fill_task_group_info_array(0, root_task_group, buf, -1);
	sort_task_group_info_array();
	if (CRASHDEBUG(1))
		print_task_group_info_array();

	get_active_set();

	cpus = pc->curcmd_flags & CPUMASK ? 
		(ulong *)(ulong)pc->curcmd_private : NULL;

	for (cpu = displayed = 0; cpu < kt->cpus; cpu++) {
		if (cpus && !NUM_IN_BITMAP(cpus, cpu))
			continue;

		if (rt_rq)
			readmem(rt_rq + cpu * sizeof(ulong), KVADDR,
				&rt_rq_p, sizeof(ulong), "task_group rt_rq",
				FAULT_ON_ERROR);
		if (cfs_rq)
			readmem(cfs_rq + cpu * sizeof(ulong), KVADDR,
				&cfs_rq_p, sizeof(ulong), "task_group cfs_rq",
				FAULT_ON_ERROR);
		fprintf(fp, "%sCPU %d", displayed++ ? "\n" : "", cpu);

		if (hide_offline_cpu(cpu)) {
			fprintf(fp, " [OFFLINE]\n");
			continue;
		} else
			fprintf(fp, "\n");

		fprintf(fp, "  CURRENT: ");
		if ((tc = task_to_context(tt->active_set[cpu])))
			fprintf(fp, "PID: %-5ld  TASK: %lx  COMMAND: \"%s\"\n",
				tc->pid, tc->task, tc->comm);
		else
			fprintf(fp, "%lx\n", tt->active_set[cpu]);

		if (rt_rq) {
			fprintf(fp, "  %s_TASK_GROUP: %lx  RT_RQ: %lx\n",
				task_group_name, root_task_group, rt_rq_p);
			reuse_task_group_info_array();
			dump_tasks_in_task_group_rt_rq(0, rt_rq_p, cpu);
		}

		if (cfs_rq) {
			fprintf(fp, "  %s_TASK_GROUP: %lx  CFS_RQ: %lx\n",
				task_group_name, root_task_group, cfs_rq_p);
			reuse_task_group_info_array();
			dump_tasks_in_task_group_cfs_rq(0, cfs_rq_p, cpu, tc);
		}
	}

	FREEBUF(buf);
	free_task_group_info_array();
}

#undef _NSIG
#define _NSIG           64
#define _NSIG_BPW       machdep->bits
#define _NSIG_WORDS     (_NSIG / _NSIG_BPW)

#undef SIGRTMIN
#define SIGRTMIN	32

static struct signame {
        char *name;
        char *altname;
} signame[_NSIG] = {
    /* 0 */   {NULL,         NULL},
    /* 1 */   {"SIGHUP",     NULL},
    /* 2 */   {"SIGINT",     NULL},
    /* 3 */   {"SIGQUIT",    NULL},
    /* 4 */   {"SIGILL",     NULL},
    /* 5 */   {"SIGTRAP",    NULL},
    /* 6 */   {"SIGABRT",    "SIGIOT"},
    /* 7 */   {"SIGBUS",     NULL},
    /* 8 */   {"SIGFPE",     NULL},
    /* 9 */   {"SIGKILL",    NULL},
    /* 10 */  {"SIGUSR1",    NULL},
    /* 11 */  {"SIGSEGV",    NULL},
    /* 12 */  {"SIGUSR2",    NULL},
    /* 13 */  {"SIGPIPE",    NULL},
    /* 14 */  {"SIGALRM",    NULL},
    /* 15 */  {"SIGTERM",    NULL},
    /* 16 */  {"SIGSTKFLT",  NULL},
    /* 17 */  {"SIGCHLD",    "SIGCLD"},
    /* 18 */  {"SIGCONT",    NULL},
    /* 19 */  {"SIGSTOP",    NULL},
    /* 20 */  {"SIGTSTP",    NULL},
    /* 21 */  {"SIGTTIN",    NULL},
    /* 22 */  {"SIGTTOU",    NULL},
    /* 23 */  {"SIGURG",     NULL},
    /* 24 */  {"SIGXCPU",    NULL},
    /* 25 */  {"SIGXFSZ",    NULL},
    /* 26 */  {"SIGVTALRM",  NULL},
    /* 27 */  {"SIGPROF",    NULL},
    /* 28 */  {"SIGWINCH",   NULL},
    /* 29 */  {"SIGIO",      "SIGPOLL"},
    /* 30 */  {"SIGPWR",     NULL},
    /* 31 */  {"SIGSYS",     "SIGUNUSED"},
              {NULL,         NULL},    /* Real time signals start here. */
};

static int
sigrt_minmax(int *min, int *max) 
{
	int sigrtmax, j;

	sigrtmax = THIS_KERNEL_VERSION < LINUX(2,5,0) ? 
		_NSIG - 1  : _NSIG;

	if (min && max) {
		j = sigrtmax-SIGRTMIN-1;
		*max = j / 2;
		*min = j - *max;
	}

	return sigrtmax;
}

static void
signame_list(void)
{
	int i, sigrtmax, j, min, max;

	sigrtmax = sigrt_minmax(&min, &max);
	j = 1;

        for (i = 1; i <= sigrtmax; i++) {
		if ((i == SIGRTMIN) || (i == sigrtmax)) {
			fprintf(fp, "[%d] %s", i, 
			    (i== SIGRTMIN) ? "SIGRTMIN" : "SIGRTMAX");
		} else if (i > SIGRTMIN) {
			if (j <= min){
				fprintf(fp, "[%d] %s%d", i , "SIGRTMIN+", j);
				j++;
			} else if (max >= 1) {
				fprintf(fp, "[%d] %s%d", i , "SIGRTMAX-",max);
				max--;
			}
		} else {
                	if (!signame[i].name)
                        	continue;

                	fprintf(fp, "%s[%d] %s", i < 10 ? " " : "", 
				i, signame[i].name);
			if (signame[i].altname)
				fprintf(fp, "/%s",  signame[i].altname);
		}
		fprintf(fp, "\n");
        }
}

/*
 *  Translate the bits in a signal set into their name strings.
 */
static void 
translate_sigset(ulonglong sigset)
{
	int sigrtmax, min, max, i, j, c, len;
	char buf[BUFSIZE];

	if (!sigset) {
		fprintf(fp, "(none)\n");
		return;
	}

	len = 0;
	sigrtmax= sigrt_minmax(&min, &max);
	j = 1;

        for (i = 1, c = 0; i <= sigrtmax; i++) {
		if (sigset & (ulonglong)1) {
			if (i == SIGRTMIN || i == sigrtmax)
				sprintf(buf, "%s%s", c++ ? " " : "", 
					(i==SIGRTMIN) ? "SIGRTMIN" : "SIGRTMAX");
			else if (i > SIGRTMIN) {
				if (j <= min)
					sprintf(buf, "%s%s%d", 
						c++ ? " " : "", "SIGRTMIN+", j);
				else if (max >= 1)
					sprintf(buf, "%s%s%d", 
						c++ ? " " : "", "SIGRTMAX-", max);
			} else
				sprintf(buf, "%s%s", c++ ? " " : "", 
					signame[i].name);

			if ((len + strlen(buf)) > 80) {
				shift_string_left(buf, 1);
				fprintf(fp,  "\n");
				len = 0;
			}

			len += strlen(buf);
			fprintf(fp, "%s", buf);
		}

		sigset >>= 1;
		if (i > SIGRTMIN) {
			if (j <= min) 
				j++;
			else if (max >= 1)
				max--;
		}	
	}
	fprintf(fp, "\n");
}

/*
 *  Machine dependent interface to modify signame struct contents.
 */
void modify_signame(int sig, char *name, char *altname)
{
	signame[sig].name = name;
	signame[sig].altname = altname;
}

/*
 *  Display all signal-handling data for a task.
 *
 *  Reference handling framework is here, but not used as of yet.
 */

void
cmd_sig(void)
{
	int c, tcnt, bogus;
	ulong value;
	ulonglong sigset;
	struct reference *ref;
	struct task_context *tc;
	ulong *tasklist;
	char *siglist;
	int thread_group = FALSE;

	tasklist = (ulong *)GETBUF((MAXARGS+NR_CPUS)*sizeof(ulong));
	ref = (struct reference *)GETBUF(sizeof(struct reference));
	siglist = GETBUF(BUFSIZE);
	ref->str = siglist;

        while ((c = getopt(argcnt, args, "lR:s:g")) != EOF) {
                switch(c)
		{
		case 's':
			sigset = htoll(optarg, FAULT_ON_ERROR, NULL);
			translate_sigset(sigset);
			return;

		case 'R':
			if (strlen(ref->str))
				strcat(ref->str, ",");
			strcat(ref->str, optarg);
			break;

		case 'l':
			signame_list();
			return;

		case 'g':
			pc->curcmd_flags |= TASK_SPECIFIED;
			thread_group = TRUE;
			break;
		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	tcnt = bogus = 0;

        while (args[optind]) {
		if (IS_A_NUMBER(args[optind])) {
	                switch (str_to_context(args[optind], &value, &tc))
	                {
	                case STR_PID:
                                for (tc = pid_to_context(value); tc;
                                     tc = tc->tc_next)
                                        tasklist[tcnt++] = tc->task;
	                        break;
	
	                case STR_TASK:
				tasklist[tcnt++] = value;
	                        break;
	
	                case STR_INVALID:
				bogus++;
	                        error(INFO, "invalid task or pid value: %s\n\n",
	                                args[optind]);
	                        break;
	                }
		} else if (strstr(args[optind], ",") ||
			MEMBER_EXISTS("task_struct", args[optind])) {
			if (strlen(ref->str))
				strcat(ref->str, ",");
			strcat(ref->str, args[optind]);
		} else
                        error(INFO, "invalid task or pid value: %s\n\n",
                                args[optind]);
                optind++;
        }

	if (!tcnt && !bogus)
		tasklist[tcnt++] = CURRENT_TASK();

	for (c = 0; c < tcnt; c++) {
		if (thread_group)
			do_sig_thread_group(tasklist[c]);
		else {
			do_sig(tasklist[c], 0, strlen(ref->str) ? ref : NULL);
			fprintf(fp, "\n");
		}
	}

}


/*
 *  Do the work for the "sig -g" command option, coming from sig or foreach.
 */
static void
do_sig_thread_group(ulong task)
{
        int i;
        int cnt;
        struct task_context *tc;
	ulong tgid;

        tc = task_to_context(task);
	tgid = task_tgid(task);

	if (tc->pid != tgid) {
		if (pc->curcmd_flags & TASK_SPECIFIED) {
			if (!(tc = tgid_to_context(tgid))) 
				return;
			task = tc->task;
		} else 
			return;
	}

	if ((tc->pid == 0) && (pc->curcmd_flags & IDLE_TASK_SHOWN))
		return;

       	print_task_header(fp, tc, 0);
	dump_signal_data(tc, THREAD_GROUP_LEVEL);
	fprintf(fp, "\n  ");
	print_task_header(fp, tc, 0);
	dump_signal_data(tc, TASK_LEVEL|TASK_INDENT);

	tc = FIRST_CONTEXT();
        for (i = cnt = 0; i < RUNNING_TASKS(); i++, tc++) {
		if (tc->task == task)
			continue;

		if (task_tgid(tc->task)	== tgid) {
			fprintf(fp, "\n  ");
                        print_task_header(fp, tc, 0);
			dump_signal_data(tc, TASK_LEVEL|TASK_INDENT);
                        cnt++;
			if (tc->pid == 0)
				pc->curcmd_flags |= IDLE_TASK_SHOWN;
                }
        }

	fprintf(fp, "\n");
}

/*
 *  Do the work for the sig command, coming from sig or foreach.
 */
void
do_sig(ulong task, ulong flags, struct reference *ref)
{
        struct task_context *tc;

        tc = task_to_context(task);

        if (ref)
                signal_reference(tc, flags, ref);
        else {
                if (!(flags & FOREACH_SIG))
                        print_task_header(fp, tc, 0);
                dump_signal_data(tc, TASK_LEVEL|THREAD_GROUP_LEVEL);
        }
}

/*
 *  Implementation for -R reference for the sig command.
 */
static void
signal_reference(struct task_context *tc, ulong flags, struct reference *ref)
{
	if (flags & FOREACH_SIG)
		error(FATAL, "sig: -R not supported yet\n");
	else
		error(FATAL, "-R not supported yet\n");
}

/*
 *  Dump all signal-handling data for a task.
 */
static void
dump_signal_data(struct task_context *tc, ulong flags)
{
	int i, sigrtmax, others, use_sighand;
	int translate, sigpending;
	uint ti_flags;
	ulonglong sigset, blocked, mask;
	ulong signal_struct, kaddr, handler, sa_flags, sigqueue;
	ulong sighand_struct;
	long size;
	char *signal_buf, *uaddr;
	ulong shared_pending, signal;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];

	sigpending = sigqueue = 0;
	sighand_struct = signal_struct = 0;

        if (VALID_STRUCT(sigqueue) && !VALID_MEMBER(sigqueue_next)) {
                MEMBER_OFFSET_INIT(sigqueue_next, "sigqueue", "next");
                MEMBER_OFFSET_INIT(sigqueue_list, "sigqueue", "list");
                MEMBER_OFFSET_INIT(sigqueue_info, "sigqueue", "info");
        } else if (!VALID_MEMBER(signal_queue_next)) {
                MEMBER_OFFSET_INIT(signal_queue_next, "signal_queue", "next");
                MEMBER_OFFSET_INIT(signal_queue_info, "signal_queue", "info");
        }

	sigset = task_signal(tc->task, 0);
	if (!tt->last_task_read)
		return;

	if (VALID_MEMBER(task_struct_sig))
		signal_struct = ULONG(tt->task_struct + 
			OFFSET(task_struct_sig));
	else if (VALID_MEMBER(task_struct_signal))
		signal_struct = ULONG(tt->task_struct + 
			OFFSET(task_struct_signal));

	size = MAX(SIZE(signal_struct), VALID_SIZE(signal_queue) ?  
		SIZE(signal_queue) : SIZE(sigqueue));
	if (VALID_SIZE(sighand_struct))
		size = MAX(size, SIZE(sighand_struct));
	signal_buf = GETBUF(size);

	if (signal_struct)
		readmem(signal_struct, KVADDR, signal_buf,
			SIZE(signal_struct), "signal_struct buffer",
			FAULT_ON_ERROR);

	/*
	 *  Signal dispositions (thread group level).
	 */
	if (flags & THREAD_GROUP_LEVEL) {
		if (flags & TASK_INDENT)
			INDENT(2);
		fprintf(fp, "SIGNAL_STRUCT: %lx  ", signal_struct);
		if (!signal_struct) {
			fprintf(fp, "\n");
			return;
		}
		if (VALID_MEMBER(signal_struct_count))
			fprintf(fp, "COUNT: %d\n",
				INT(signal_buf + OFFSET(signal_struct_count)));
		else if (VALID_MEMBER(signal_struct_nr_threads))
			fprintf(fp, "NR_THREADS: %d\n",
				INT(signal_buf + OFFSET(signal_struct_nr_threads)));
		else
			fprintf(fp, "\n");

		if (flags & TASK_INDENT)
			INDENT(2);
		fprintf(fp, " SIG %s %s %s %s\n",
			mkstring(buf1, VADDR_PRLEN == 8 ? 9 : VADDR_PRLEN, 
				CENTER, "SIGACTION"),
		mkstring(buf2, UVADDR_PRLEN, RJUST, "HANDLER"),
		mkstring(buf3, 16, CENTER, "MASK"),
		mkstring(buf4, VADDR_PRLEN, LJUST, "FLAGS"));

		if (VALID_MEMBER(task_struct_sighand)) {
			sighand_struct = ULONG(tt->task_struct +
	                        OFFSET(task_struct_sighand));
			readmem(sighand_struct, KVADDR, signal_buf,
				SIZE(sighand_struct), "sighand_struct buffer",
				FAULT_ON_ERROR);
			use_sighand = TRUE;
		} else
			use_sighand = FALSE;

		sigrtmax = sigrt_minmax(NULL, NULL);

	        for (i = 1; i <= sigrtmax; i++) {
			if (flags & TASK_INDENT)
				INDENT(2);

	                fprintf(fp, "%s[%d] ", i < 10 ? " " : "", i);
	
			if (use_sighand) {
				kaddr = sighand_struct + 
					OFFSET(sighand_struct_action) +
					((i-1) * SIZE(k_sigaction));
				uaddr = signal_buf + 
					OFFSET(sighand_struct_action) +
					((i-1) * SIZE(k_sigaction));
			} else {
				kaddr = signal_struct + 
					OFFSET(signal_struct_action) +
					((i-1) * SIZE(k_sigaction));
				uaddr = signal_buf + 
					OFFSET(signal_struct_action) +
					((i-1) * SIZE(k_sigaction));
			}
	
			handler = ULONG(uaddr + OFFSET(sigaction_sa_handler));
			switch ((long)handler)
			{
			case -1:
				mkstring(buf1, UVADDR_PRLEN, RJUST, "SIG_ERR");
				break;
			case 0:
				mkstring(buf1, UVADDR_PRLEN, RJUST, "SIG_DFL");
				break;
			case 1:
				mkstring(buf1, UVADDR_PRLEN, RJUST, "SIG_IGN");
				break;
			default:
				mkstring(buf1, UVADDR_PRLEN, RJUST|LONG_HEX,
	                                    MKSTR(handler));
				break;
			}
	
			mask = sigaction_mask((ulong)uaddr);
			sa_flags = ULONG(uaddr + OFFSET(sigaction_sa_flags));
	
			fprintf(fp, "%s%s %s %016llx %lx ",
				space(MINSPACE-1), 
				mkstring(buf2,
				UVADDR_PRLEN,LJUST|LONG_HEX,MKSTR(kaddr)),
				buf1,
				mask,
				sa_flags);
	
			if (sa_flags) {
				others = 0; translate = 1;
				if (sa_flags & SA_NOCLDSTOP)
					fprintf(fp, "%s%sSA_NOCLDSTOP",
						translate-- > 0 ? "(" : "",
						others++ ? "|" : "");
#ifdef SA_RESTORER
	                        if (sa_flags & SA_RESTORER)
	                                fprintf(fp, "%s%sSA_RESTORER",
	                                        translate-- > 0 ? "(" : "",
	                                        others++ ? "|" : "");
#endif
#ifdef SA_NOCLDWAIT
				if (sa_flags & SA_NOCLDWAIT)
					fprintf(fp, "%s%sSA_NOCLDWAIT", 
						translate-- > 0 ? "(" : "",
						others++ ? "|" : "");
#endif
				if (sa_flags & SA_SIGINFO)
					fprintf(fp, "%s%sSA_SIGINFO", 
						translate-- > 0 ? "(" : "",
						others++ ? "|" : "");
				if (sa_flags & SA_ONSTACK)
					fprintf(fp, "%s%sSA_ONSTACK", 
						translate-- > 0 ? "(" : "",
						others++ ? "|" : "");
				if (sa_flags & SA_RESTART)
					fprintf(fp, "%s%sSA_RESTART", 
						translate-- > 0 ? "(" : "",
						others++ ? "|" : "");
				if (sa_flags & SA_NODEFER)
					fprintf(fp, "%s%sSA_NODEFER", 
						translate-- > 0 ? "(" : "",
						others++ ? "|" : "");
				if (sa_flags & SA_RESETHAND)
					fprintf(fp, "%s%sSA_RESETHAND", 
						translate-- > 0 ? "(" : "",
						others++ ? "|" : "");
				if (translate < 1)
	                		fprintf(fp, ")");
			}
	
	                fprintf(fp, "\n");
	        }
	}
	
	if (flags & TASK_LEVEL) {
		/*
	 	* Pending signals (task level).
		*/
		if (VALID_MEMBER(task_struct_sigpending))
			sigpending = INT(tt->task_struct + 
				OFFSET(task_struct_sigpending));
		else if (VALID_MEMBER(thread_info_flags)) {
			fill_thread_info(tc->thread_info);
			ti_flags = UINT(tt->thread_info + OFFSET(thread_info_flags));
			sigpending = ti_flags & (1<<TIF_SIGPENDING);
		}
		if (flags & TASK_INDENT)
			INDENT(2);
		fprintf(fp, "SIGPENDING: %s\n", sigpending ? "yes" : "no");

		/*
	 	*  Blocked signals (task level).
	 	*/

		blocked = task_blocked(tc->task);
		if (flags & TASK_INDENT)
			INDENT(2);
		fprintf(fp, "   BLOCKED: %016llx\n", blocked);
		
		/*
	 	*  Pending queue (task level).
	 	*/
	
		if (flags & TASK_INDENT)
			INDENT(2);
		if (VALID_MEMBER(signal_struct_shared_pending)) {
			fprintf(fp, "PRIVATE_PENDING\n");
			if (flags & TASK_INDENT)
				INDENT(2);
		}
		fprintf(fp, "    SIGNAL: %016llx\n", sigset);

		if (VALID_MEMBER(task_struct_sigqueue)) 
			sigqueue = ULONG(tt->task_struct + 
				OFFSET(task_struct_sigqueue));
	
		else if (VALID_MEMBER(task_struct_pending)) 
			sigqueue = ULONG(tt->task_struct +
				OFFSET(task_struct_pending) +
				OFFSET_OPTION(sigpending_head, 
				sigpending_list));
	
		if (VALID_MEMBER(sigqueue_list) && empty_list(sigqueue))
			sigqueue = 0;

		if (flags & TASK_INDENT)
			INDENT(2);
		if (sigqueue) {
                	fprintf(fp, "  SIGQUEUE:  SIG  %s\n",
                        	mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "SIGINFO"));
		 	sigqueue_list(sigqueue);
		} else
                	fprintf(fp, "  SIGQUEUE: (empty)\n");
	}

	/*
	 *  Pending queue (thread group level).
	 */
	if ((flags & THREAD_GROUP_LEVEL) &&
	    VALID_MEMBER(signal_struct_shared_pending)) {

		fprintf(fp, "SHARED_PENDING\n");
		shared_pending = signal_struct + OFFSET(signal_struct_shared_pending);
		signal = shared_pending + OFFSET(sigpending_signal);
		readmem(signal, KVADDR, signal_buf,SIZE(sigpending_signal),
			"signal", FAULT_ON_ERROR);
		sigset = task_signal(0, (ulong*)signal_buf);
		if (flags & TASK_INDENT)
			INDENT(2);
		fprintf(fp, "    SIGNAL: %016llx\n", sigset);
                sigqueue = (shared_pending + 
			OFFSET_OPTION(sigpending_head, sigpending_list) + 
			OFFSET(list_head_next));
		readmem(sigqueue,KVADDR, signal_buf,
			SIZE(sigqueue), "sigqueue", FAULT_ON_ERROR);
		sigqueue = ULONG(signal_buf);

		if (VALID_MEMBER(sigqueue_list) && empty_list(sigqueue))
			sigqueue = 0;
		if (flags & TASK_INDENT)
			INDENT(2);
		if (sigqueue) {
               		fprintf(fp, "  SIGQUEUE:  SIG  %s\n",
                       		mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "SIGINFO"));
			 sigqueue_list(sigqueue);
		} else
               		fprintf(fp, "  SIGQUEUE: (empty)\n");
	}
	FREEBUF(signal_buf);
}

/*
 *  Dump a pending signal queue (private/shared).
 */

static void sigqueue_list(ulong sigqueue) {
        ulong sigqueue_save, next;
	int sig;
	char *signal_buf;
	long size;
        size = VALID_SIZE(signal_queue) ?  SIZE(signal_queue) : SIZE(sigqueue);
        signal_buf = GETBUF(size);

        sigqueue_save = sigqueue;
        while (sigqueue) {
        	readmem(sigqueue, KVADDR, signal_buf, 
			SIZE_OPTION(signal_queue, sigqueue), 
			"signal_queue/sigqueue", FAULT_ON_ERROR);

		if (VALID_MEMBER(signal_queue_next) && 
		    VALID_MEMBER(signal_queue_info)) {
                	next = ULONG(signal_buf + OFFSET(signal_queue_next));
                	sig = INT(signal_buf + OFFSET(signal_queue_info) +
				 OFFSET(siginfo_si_signo));
		} else {
			next = ULONG(signal_buf +
                        	OFFSET_OPTION(sigqueue_next, sigqueue_list));
                	sig = INT(signal_buf + OFFSET(sigqueue_info) + 
				OFFSET(siginfo_si_signo));
		}

		if (sigqueue_save == next)
			break;

                fprintf(fp, "             %3d  %lx\n",
                        sig, sigqueue +
			OFFSET_OPTION(signal_queue_info, sigqueue_info));

                sigqueue = next;
        }
	FREEBUF(signal_buf);

}

/*
 *  Return the current set of signals sent to a task, in the form of 
 *  a long long data type form that can be easily masked regardless
 *  of its size.
 */

static ulonglong 
task_signal(ulong task, ulong *signal)
{
	ulong *sigset_ptr;
	ulonglong sigset = 0;

	if (task) {
        	fill_task_struct(task);

	if (!tt->last_task_read) 
		return 0;

        if (VALID_MEMBER(sigpending_signal)) {
                sigset_ptr = (ulong *)(tt->task_struct +
                        OFFSET(task_struct_pending) +
                        OFFSET(sigpending_signal));
	} else if (VALID_MEMBER(task_struct_signal)) {
                sigset_ptr = (ulong *)(tt->task_struct +
                        OFFSET(task_struct_signal));
        } else
		return 0;
	} else if (signal) {
		sigset_ptr = signal;
	} else
		return 0;

	switch (_NSIG_WORDS)
	{
	case 1:
		sigset = (ulonglong)sigset_ptr[0];
		break;

	case 2:
		sigset = (ulonglong)(sigset_ptr[1]) << 32;
		sigset |= (ulonglong)(sigset_ptr[0]);
		break;
	}

	return sigset;
}

/*
 *  Return the current set of signals that a task has blocked, in the form
 *  of a long long data type form that can be easily masked regardless
 *  of its size.
 */

static ulonglong
task_blocked(ulong task)
{
        ulonglong sigset;
        ulong *sigset_ptr;

        fill_task_struct(task);

        if (!tt->last_task_read)
                return 0;

        sigset_ptr = (ulong *)(tt->task_struct + OFFSET(task_struct_blocked));

        sigset = (ulonglong)(sigset_ptr[1]) << 32;
        sigset |= (ulonglong)(sigset_ptr[0]);

	return sigset;
}

static ulonglong
sigaction_mask(ulong sigaction)
{
        ulonglong sigset;
        ulong *sigset_ptr;

	sigset = 0;
	sigset_ptr = (ulong *)(sigaction + OFFSET(sigaction_sa_mask));

        switch (_NSIG_WORDS)
        {
        case 1:
                sigset = (ulonglong)sigset_ptr[0];
                break;

        case 2:
                sigset = (ulonglong)(sigset_ptr[1]) << 32;
                sigset |= (ulonglong)(sigset_ptr[0]);
                break;
        }

        return sigset;
}

/*
 *  Deal with potential separation of task_struct and kernel stack.
 */
ulong 
generic_get_stackbase(ulong task)
{
	return task_to_stackbase(task);
}

ulong
generic_get_stacktop(ulong task)
{
        return task_to_stackbase(task) + STACKSIZE();
}

#define STACK_END_MAGIC 0x57AC6E9D

static void
stack_overflow_check_init(void)
{
	int pid;
	struct task_context *tc;
	ulong location, magic;

	if (!(tt->flags & THREAD_INFO))
		return;

	for (pid = 1; pid < 10; pid++) {
 		if (!(tc = pid_to_context(pid)))
			continue;

		if (tt->flags & THREAD_INFO_IN_TASK)
			location = task_to_stackbase(tc->task);
		else
			location = tc->thread_info + SIZE(thread_info);

		if (!readmem(location, KVADDR, &magic, sizeof(long), 
		    "stack magic", RETURN_ON_ERROR|QUIET))
			continue;

		if (magic == STACK_END_MAGIC) {
			tt->stack_end_magic = STACK_END_MAGIC;
			break;
		}
	}
}

/*
 *  Check thread_info.task and thread_info.cpu members, 
 *  and the STACK_END_MAGIC location.
 */
void 
check_stack_overflow(void)
{
	int i, overflow, cpu_size, cpu, total;
	char buf[BUFSIZE];
	ulong magic, task, stackbase, location;
	struct task_context *tc;

	if (!tt->stack_end_magic && 
	    INVALID_MEMBER(thread_info_task) && 
	    INVALID_MEMBER(thread_info_cpu))
		option_not_supported('v');

	cpu_size = VALID_MEMBER(thread_info_cpu) ? 
		MEMBER_SIZE("thread_info", "cpu") : 0;

	tc = FIRST_CONTEXT();
	for (i = total = 0; i < RUNNING_TASKS(); i++, tc++) {
		overflow = 0;

		if (tt->flags & THREAD_INFO_IN_TASK) {
			if (!readmem(task_to_stackbase(tc->task), KVADDR, &stackbase, 
			    sizeof(ulong), "stack overflow check", RETURN_ON_ERROR))
				continue;
			goto check_stack_end_magic;
		} else {
			if (!readmem(tc->thread_info, KVADDR, buf, 
			    SIZE(thread_info) + sizeof(ulong), 
			    "stack overflow check", RETURN_ON_ERROR))
				continue;
		}

		if (VALID_MEMBER(thread_info_task)) {
			task = ULONG(buf + OFFSET(thread_info_task));
			if (task != tc->task) {
				print_task_header(fp, tc, 0);
				fprintf(fp, 
				    "  possible stack overflow: thread_info.task: %lx != %lx\n",
					task, tc->task);
				overflow++; total++;
			}
		}

		if (VALID_MEMBER(thread_info_cpu)) {
			switch (cpu_size)
			{
			case 1:
				cpu = UCHAR(buf + OFFSET(thread_info_cpu));
				break;
			case 2:
				cpu = USHORT(buf + OFFSET(thread_info_cpu));
				break;
			case 4:
				cpu = UINT(buf + OFFSET(thread_info_cpu));
				break;
			default:
				cpu = 0;
				break;
			}
			if (cpu >= kt->cpus) {
				if (!overflow)
					print_task_header(fp, tc, 0);
				fprintf(fp, 
				    "  possible stack overflow: thread_info.cpu: %d >= %d\n",
					cpu, kt->cpus);
				overflow++; total++;
			}
		}

check_stack_end_magic:
		if (!tt->stack_end_magic)
			continue;

		if (tt->flags & THREAD_INFO_IN_TASK) 
			magic = stackbase;
		else
			magic = ULONG(buf + SIZE(thread_info));

		if (tc->pid == 0) {
			if (kernel_symbol_exists("init_task")) {
				if (tc->task == symbol_value("init_task"))
					continue;
			} else 
				continue;
		}

		if (magic != STACK_END_MAGIC) {
			if (!overflow)
				print_task_header(fp, tc, 0);

			if (tt->flags & THREAD_INFO_IN_TASK)
				location = task_to_stackbase(tc->task);
			else
				location = tc->thread_info + SIZE(thread_info);

			fprintf(fp, 
			    "  possible stack overflow: %lx: %lx != STACK_END_MAGIC\n",
				location, magic);
			overflow++, total++;
		}

		if (overflow)
			fprintf(fp, "\n");
	}

	if (!total)
		fprintf(fp, "No stack overflows detected\n");
}
