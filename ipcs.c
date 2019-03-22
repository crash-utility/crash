/* ipcs.c - provide information on ipc facilities
 *
 * Copyright (C) 2012 FUJITSU LIMITED
 * Auther: Qiao Nuohan <qiaonuohan@cn.fujitsu.com>
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

#include "defs.h"    /* From the crash source top-level directory */

#define SPECIFIED_NOTHING 0x0
#define SPECIFIED_ID      0x1
#define SPECIFIED_ADDR    0x2

#define IPCS_INIT  0x1
#define IDR_ORIG   0x2
#define IDR_RADIX  0x4
#define IDR_XARRAY 0x8

#define MAX_ID_SHIFT (sizeof(int)*8 - 1)
#define MAX_ID_BIT (1U << MAX_ID_SHIFT)
#define MAX_ID_MASK (MAX_ID_BIT - 1)

#define SHM_DEST   01000
#define SHM_LOCKED 02000

struct shm_info {
	ulong shmid_kernel;
	int key;
	int shmid;
	ulong rss;
	ulong swap;
	unsigned int uid;
	unsigned int perms;
	ulong bytes;
	ulong nattch;
	ulong shm_inode;
	int deleted;
};

struct sem_info {
	ulong sem_array;
	int key;
	int semid;
	unsigned int uid;
	unsigned int perms;
	ulong nsems;
	int deleted;
};

struct msg_info {
	ulong msg_queue;
	int key;
	int msgid;
	unsigned int uid;
	unsigned int perms;
	ulong bytes;
	ulong messages;
	int deleted;
};

struct ipcs_table {
	int idr_bits;
	ulong init_flags;
	ulong hugetlbfs_f_op_addr;
	ulong shm_f_op_addr;
	ulong shm_f_op_huge_addr;
	int use_shm_f_op;
	int seq_multiplier;
	int cnt;
	struct list_pair *lp;
};

/*
 * function declaration
 */

static int dump_shared_memory(int, ulong, int, ulong);
static int dump_semaphore_arrays(int, ulong, int, ulong);
static int dump_message_queues(int, ulong, int, ulong);
static int ipc_search_idr(ulong, int, ulong, int (*)(ulong, int, ulong, int, int), int);
static int ipc_search_array(ulong, int, ulong, int (*)(ulong, int, ulong, int, int), int);
static int dump_shm_info(ulong, int, ulong, int, int);
static int dump_sem_info(ulong, int, ulong, int, int);
static int dump_msg_info(ulong, int, ulong, int, int);
static void get_shm_info(struct shm_info *, ulong, int);
static void get_sem_info(struct sem_info *, ulong, int);
static void get_msg_info(struct msg_info *, ulong, int);
static void add_rss_swap(ulong, int, ulong *, ulong *);
static int is_file_hugepages(ulong);
static void gather_radix_tree_entries(ulong);
static void gather_xarray_entries(ulong);

/*
 * global data
 */
static struct ipcs_table ipcs_table = { 0 };

void
ipcs_init(void)
{
	if (ipcs_table.init_flags & IPCS_INIT) {
		return;
	}

	ipcs_table.init_flags |= IPCS_INIT;

	MEMBER_OFFSET_INIT(file_f_op, "file", "f_op");
	MEMBER_OFFSET_INIT(file_private_data, "file", "private_data");
	MEMBER_OFFSET_INIT(hstate_order, "hstate", "order");
	MEMBER_OFFSET_INIT(hugetlbfs_sb_info_hstate, "hugetlbfs_sb_info",
			"hstate");
	MEMBER_OFFSET_INIT(idr_layers, "idr", "layers");
	MEMBER_OFFSET_INIT(idr_layer_layer, "idr_layer", "layer");
	MEMBER_OFFSET_INIT(idr_layer_ary, "idr_layer", "ary");
	MEMBER_OFFSET_INIT(idr_top, "idr", "top");
	MEMBER_OFFSET_INIT(idr_cur, "idr", "cur");
	MEMBER_OFFSET_INIT(ipc_id_ary_p, "ipc_id_ary", "p");
	MEMBER_OFFSET_INIT(ipc_ids_entries, "ipc_ids", "entries");
	MEMBER_OFFSET_INIT(ipc_ids_max_id, "ipc_ids", "max_id");
	MEMBER_OFFSET_INIT(ipc_ids_in_use, "ipc_ids", "in_use");
	MEMBER_OFFSET_INIT(ipc_ids_ipcs_idr, "ipc_ids", "ipcs_idr");
	MEMBER_OFFSET_INIT(ipc_namespace_ids, "ipc_namespace", "ids");
	MEMBER_OFFSET_INIT(kern_ipc_perm_key, "kern_ipc_perm", "key");
	MEMBER_OFFSET_INIT(kern_ipc_perm_id, "kern_ipc_perm", "id");
	MEMBER_OFFSET_INIT(kern_ipc_perm_uid, "kern_ipc_perm", "uid");
	MEMBER_OFFSET_INIT(kern_ipc_perm_mode, "kern_ipc_perm", "mode");
	MEMBER_OFFSET_INIT(kern_ipc_perm_deleted, "kern_ipc_perm",
			"deleted");
	MEMBER_OFFSET_INIT(kern_ipc_perm_seq, "kern_ipc_perm", "seq");
	MEMBER_OFFSET_INIT(nsproxy_ipc_ns, "nsproxy", "ipc_ns");
	MEMBER_OFFSET_INIT(shmem_inode_info_vfs_inode, "shmem_inode_info",
			"vfs_inode");
	MEMBER_OFFSET_INIT(shmem_inode_info_swapped, "shmem_inode_info",
			"swapped");
	if (INVALID_MEMBER(shmem_inode_info_swapped))
		ANON_MEMBER_OFFSET_INIT(shmem_inode_info_swapped,
				"shmem_inode_info", "swapped");
	MEMBER_OFFSET_INIT(shm_file_data_file, "shm_file_data", "file");
	MEMBER_OFFSET_INIT(shmid_kernel_shm_perm, "shmid_kernel",
			"shm_perm");
	MEMBER_OFFSET_INIT(shmid_kernel_shm_segsz, "shmid_kernel",
			"shm_segsz");
	MEMBER_OFFSET_INIT(shmid_kernel_shm_nattch, "shmid_kernel",
			"shm_nattch");
	MEMBER_OFFSET_INIT(shmid_kernel_shm_file, "shmid_kernel",
			"shm_file");
	MEMBER_OFFSET_INIT(shmid_kernel_id, "shmid_kernel", "id");
	MEMBER_OFFSET_INIT(sem_array_sem_perm, "sem_array", "sem_perm");
	MEMBER_OFFSET_INIT(sem_array_sem_id, "sem_array", "sem_id");
	MEMBER_OFFSET_INIT(sem_array_sem_nsems, "sem_array", "sem_nsems");
	MEMBER_OFFSET_INIT(msg_queue_q_perm, "msg_queue", "q_perm");
	MEMBER_OFFSET_INIT(msg_queue_q_id, "msg_queue", "q_id");
	MEMBER_OFFSET_INIT(msg_queue_q_cbytes, "msg_queue", "q_cbytes");
	MEMBER_OFFSET_INIT(msg_queue_q_qnum, "msg_queue", "q_qnum");
	MEMBER_OFFSET_INIT(super_block_s_fs_info, "super_block",
			"s_fs_info");

	/*
	 * struct size
	 */
	STRUCT_SIZE_INIT(ipc_ids, "ipc_ids");
	STRUCT_SIZE_INIT(shmid_kernel, "shmid_kernel");
	STRUCT_SIZE_INIT(sem_array, "sem_array");
	STRUCT_SIZE_INIT(msg_queue, "msg_queue");
	STRUCT_SIZE_INIT(hstate, "hstate");

	if (symbol_exists("hugetlbfs_file_operations"))
		ipcs_table.hugetlbfs_f_op_addr =
			symbol_value("hugetlbfs_file_operations");
	if (symbol_exists("is_file_shm_hugepages")) {
		ipcs_table.use_shm_f_op = TRUE;
		ipcs_table.shm_f_op_addr =
			symbol_value("shm_file_operations");
		if (symbol_exists("shm_file_operations_huge")) {
			ipcs_table.shm_f_op_huge_addr =
				symbol_value("shm_file_operations_huge");
		} else {
			ipcs_table.shm_f_op_huge_addr = -1;
		}
	} else {
		ipcs_table.use_shm_f_op = FALSE;
		ipcs_table.shm_f_op_addr = -1;
		ipcs_table.shm_f_op_huge_addr = -1;
	}

	if (VALID_MEMBER(idr_layer_ary) && 
	    get_array_length("idr_layer.ary", NULL, 0) > 64)
		ipcs_table.idr_bits = 8;
	else if (BITS32())
		ipcs_table.idr_bits = 5;
	else if (BITS64())
		ipcs_table.idr_bits = 6;
	else
		error(FATAL, "machdep->bits is not 32 or 64");

	if (VALID_MEMBER(idr_idr_rt)) {
		if (STREQ(MEMBER_TYPE_NAME("idr", "idr_rt"), "xarray"))
			ipcs_table.init_flags |= IDR_XARRAY;
		else {
			if (MEMBER_EXISTS("radix_tree_root", "rnode"))
				ipcs_table.init_flags |= IDR_RADIX;
			else if (MEMBER_EXISTS("radix_tree_root", "xa_head"))
				ipcs_table.init_flags |= IDR_XARRAY;
		}
	} else
		ipcs_table.init_flags |= IDR_ORIG;

	ipcs_table.seq_multiplier = 32768;
}

/* 
 *  Arguments are passed to the command functions in the global args[argcnt]
 *  array.  See getopt(3) for info on dash arguments.  Check out defs.h and
 *  other crash commands for usage of the myriad of utility routines available
 *  to accomplish what your task.
 */
void
cmd_ipcs(void)
{
	int specified;
	char *specified_value[MAXARGS];
	int value_index;
	int c;
	int shm, sem, msg, verbose;
	int i;
	ulong value, task;
	int found;
	struct task_context *tc;
	char buf[BUFSIZE];

	value_index = 0;
	specified = SPECIFIED_NOTHING;
	shm = 0;
	sem = 0;
	msg = 0;
	verbose = 0;
	tc = NULL;
	
	while ((c = getopt(argcnt, args, "smMqn:")) != EOF) {
		switch(c) {
			case 's':
				sem = 1;
				break;
			case 'm':
				shm = 1;
				break;
			case 'M':
				shm = 1;
				verbose = 1;
				break;
			case 'q':
				msg = 1;
				break;
			case 'n':
				switch (str_to_context(optarg, &value, &tc)) {
		        	case STR_PID:
                        	case STR_TASK:
                               		break;
                        	case STR_INVALID:
                               		error(FATAL, "invalid task or pid value: %s\n",
                                        	optarg);
                               		break;
				}
				break;
			default:
				cmd_usage(pc->curcmd, SYNOPSIS);;
				return;
		}
	}

	while (args[optind]) {
		if (value_index >= MAXARGS)
			error(FATAL, "too many id/member specified\n");
		specified |= SPECIFIED_ID | SPECIFIED_ADDR;
		specified_value[value_index] = args[optind];
		stol(args[optind], FAULT_ON_ERROR, NULL);
		optind++;
		value_index++;
	}

	if (THIS_KERNEL_VERSION < LINUX(2,6,0))
		command_not_supported();

	ipcs_init();

	if (!shm && !sem && !msg)
		shm = sem = msg = 1;

	task = tc ? tc->task : pid_to_task(0);

	if (!value_index) {
		if (shm)
			dump_shared_memory(specified, 0, verbose, task);
		if (sem)
			dump_semaphore_arrays(specified, 0, 0, task);
		if (msg)
			dump_message_queues(specified, 0, 0, task);
	} else {
		open_tmpfile();
		i = 0;
		while (i < value_index) {
			found = 0;
			value = stol(specified_value[i], FAULT_ON_ERROR, NULL);
			if (shm)
				found += dump_shared_memory(specified,
					value, verbose, task);
			if (sem)
				found += dump_semaphore_arrays(specified,
					value, 0, task);
			if (msg)
				found += dump_message_queues(specified,
					value, 0, task);

			if (!found)
				fprintf(pc->saved_fp, "invalid id or address: %s\n\n",
					specified_value[i]);

			i++;
		}
		fflush(fp);
		rewind(fp);

		while (fgets(buf, BUFSIZE, fp))
			fprintf(pc->saved_fp, "%s", buf);

		close_tmpfile();
	}
}

static int
dump_shared_memory(int specified, ulong specified_value, int verbose, ulong task)
{
	ulong nsproxy_p, ipc_ns_p;
	ulong ipc_ids_p;
	int (*ipc_search)(ulong, int, ulong, int (*)(ulong, int, ulong, int, int), int);
	int (*dump_shm)(ulong, int, ulong, int, int);
	char buf0[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char buf5[BUFSIZE];
	char buf6[BUFSIZE];
	char buf7[BUFSIZE];

	if (!verbose && specified == SPECIFIED_NOTHING) {
		fprintf(fp, "%s %s %s %s %s %s %s %s\n",
			mkstring(buf0, VADDR_PRLEN<=12?12:VADDR_PRLEN,
				LJUST, "SHMID_KERNEL"),
			mkstring(buf1, 8, LJUST, "KEY"),
			mkstring(buf2, 10, LJUST, "SHMID"),
			mkstring(buf3, 5, LJUST, "UID"),
			mkstring(buf4, 5, LJUST, "PERMS"),
			mkstring(buf5, 10, LJUST, "BYTES"),
			mkstring(buf6, 6, LJUST, "NATTCH"),
			mkstring(buf7, 6, LJUST, "STATUS"));
	}

	dump_shm = dump_shm_info;

	if (VALID_MEMBER(kern_ipc_perm_id)) {
		ipc_search = ipc_search_idr;
	} else {
		ipc_search = ipc_search_array;
	}

	if (symbol_exists("shm_ids")) {
		ipc_ids_p = symbol_value("shm_ids");
	} else {
		readmem(task + OFFSET(task_struct_nsproxy), KVADDR,
			&nsproxy_p, sizeof(ulong), "task_struct.nsproxy",
			FAULT_ON_ERROR);
		if (!readmem(nsproxy_p + OFFSET(nsproxy_ipc_ns), KVADDR,
			&ipc_ns_p, sizeof(ulong), "nsproxy.ipc_ns",
			RETURN_ON_ERROR|QUIET))
			error(FATAL,
				"cannot determine ipc_namespace location!\n");

		if (MEMBER_SIZE("ipc_namespace","ids") == sizeof(ulong) * 3)
			readmem(ipc_ns_p + OFFSET(ipc_namespace_ids) +
				sizeof(ulong) * 2, KVADDR, &ipc_ids_p,
				sizeof(ulong), "ipc_namespace.ids[2]",
				FAULT_ON_ERROR);
		else
			ipc_ids_p = ipc_ns_p + OFFSET(ipc_namespace_ids) +
				2 * SIZE(ipc_ids);
	}

	if (ipc_search(ipc_ids_p, specified, specified_value, dump_shm, verbose)) {
		return 1;
	} else {
		if (verbose && specified == SPECIFIED_NOTHING) {
			fprintf(fp, "%s %s %s %s %s %s %s %s\n",
				mkstring(buf0, VADDR_PRLEN<=12?12:VADDR_PRLEN,
					LJUST, "SHMID_KERNEL"),
				mkstring(buf1, 8, LJUST, "KEY"),
				mkstring(buf2, 10, LJUST, "SHMID"),
				mkstring(buf3, 5, LJUST, "UID"),
				mkstring(buf4, 5, LJUST, "PERMS"),
				mkstring(buf5, 10, LJUST, "BYTES"),
				mkstring(buf6, 6, LJUST, "NATTCH"),
				mkstring(buf7, 6, LJUST, "STATUS"));
			fprintf(fp, "(none allocated)\n\n");
		}
		return 0;
	}
}

static int
dump_semaphore_arrays(int specified, ulong specified_value, int verbose, ulong task)
{
	ulong nsproxy_p, ipc_ns_p;
	ulong ipc_ids_p;
	int (*ipc_search)(ulong, int, ulong, int (*)(ulong, int, ulong, int, int), int);
	int (*dump_sem)(ulong, int, ulong, int, int);
	char buf0[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char buf5[BUFSIZE];

	if (specified == SPECIFIED_NOTHING) {
		fprintf(fp, "%s %s %s %s %s %s\n",
			mkstring(buf0, VADDR_PRLEN<=10?10:VADDR_PRLEN,
				LJUST, "SEM_ARRAY"),
			mkstring(buf1, 8, LJUST, "KEY"),
			mkstring(buf2, 10, LJUST, "SEMID"),
			mkstring(buf3, 5, LJUST, "UID"),
			mkstring(buf4, 5, LJUST, "PERMS"),
			mkstring(buf5, 10, LJUST, "NSEMS"));
	}

	dump_sem = dump_sem_info;
	
	if (VALID_MEMBER(kern_ipc_perm_id)) {
		ipc_search = ipc_search_idr;
	} else {
		ipc_search = ipc_search_array;
	}

	if (symbol_exists("sem_ids")) {
		ipc_ids_p = symbol_value("sem_ids");
	} else {
		readmem(task + OFFSET(task_struct_nsproxy), KVADDR,
			&nsproxy_p, sizeof(ulong), "task_struct.nsproxy",
			FAULT_ON_ERROR);
		
		if (!readmem(nsproxy_p + OFFSET(nsproxy_ipc_ns), KVADDR,
			&ipc_ns_p, sizeof(ulong), "nsproxy.ipc_ns",
			FAULT_ON_ERROR|QUIET))
			error(FATAL,
				"cannot determine ipc_namespace location!\n");

		if (MEMBER_SIZE("ipc_namespace","ids") == sizeof(ulong) * 3)
			readmem(ipc_ns_p + OFFSET(ipc_namespace_ids),
				KVADDR,	&ipc_ids_p, sizeof(ulong),
				"ipc_namespace.ids[2]",	FAULT_ON_ERROR);
		else
			ipc_ids_p = ipc_ns_p + OFFSET(ipc_namespace_ids);
	}

	return ipc_search(ipc_ids_p, specified, specified_value, dump_sem, verbose);
}

static int
dump_message_queues(int specified, ulong specified_value, int verbose, ulong task)
{
	ulong nsproxy_p, ipc_ns_p;
	ulong ipc_ids_p;
	int (*ipc_search)(ulong, int, ulong, int (*)(ulong, int, ulong, int, int), int);
	int (*dump_msg)(ulong, int, ulong, int, int);
	char buf0[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char buf5[BUFSIZE];
	char buf6[BUFSIZE];

	if (specified == SPECIFIED_NOTHING) {
		fprintf(fp, "%s %s %s %s %s %s %s\n",
			mkstring(buf0, VADDR_PRLEN<=10?10:VADDR_PRLEN,
				LJUST, "MSG_QUEUE"),
			mkstring(buf1, 8, LJUST, "KEY"),
			mkstring(buf2, 10, LJUST, "MSQID"),
			mkstring(buf3, 5, LJUST, "UID"),
			mkstring(buf4, 5, LJUST, "PERMS"),
			mkstring(buf5, 12, LJUST, "USED-BYTES"),
			mkstring(buf6, 12, LJUST, "MESSAGES"));
	}

	dump_msg = dump_msg_info;
	
	if (VALID_MEMBER(kern_ipc_perm_id)) {
		ipc_search = ipc_search_idr;
	} else {
		ipc_search = ipc_search_array;
	}

	if (symbol_exists("msg_ids")) {
		ipc_ids_p = symbol_value("msg_ids");
	} else {
		readmem(task + OFFSET(task_struct_nsproxy), KVADDR,
			&nsproxy_p, sizeof(ulong), "task_struct.nsproxy",
			FAULT_ON_ERROR);
		if (!readmem(nsproxy_p + OFFSET(nsproxy_ipc_ns), KVADDR,
			&ipc_ns_p, sizeof(ulong), "nsproxy.ipc_ns",
			FAULT_ON_ERROR|QUIET))
			error(FATAL,
				"cannot determine ipc_namespace location!\n");

		if (MEMBER_SIZE("ipc_namespace","ids") == sizeof(ulong) * 3)
			readmem(ipc_ns_p + OFFSET(ipc_namespace_ids) +
				sizeof(ulong), KVADDR, &ipc_ids_p,
				sizeof(ulong), "ipc_namespace.ids[2]",
				FAULT_ON_ERROR);
		else
			ipc_ids_p = ipc_ns_p + OFFSET(ipc_namespace_ids) +
				SIZE(ipc_ids);
	}

	return ipc_search(ipc_ids_p, specified, specified_value, dump_msg, verbose);
}

/*
 * if shared memory information is stored in an array, use this function.
 */
static int
ipc_search_array(ulong ipc_ids_p, int specified, ulong specified_value, int (*fn)(ulong, int, ulong, int, int), int verbose)
{
	ulong entries_p;
	int max_id, i;
	ulong *array;
	int found = 0;
	int allocated = 0;

	readmem(ipc_ids_p + OFFSET(ipc_ids_entries), KVADDR, &entries_p,
		sizeof(ulong), "ipc_ids.entries", FAULT_ON_ERROR);
	readmem(ipc_ids_p + OFFSET(ipc_ids_max_id), KVADDR, &max_id,
		sizeof(int), "ipc_ids.max_id", FAULT_ON_ERROR);

	if (max_id < 0) {
		if (specified == SPECIFIED_NOTHING && !verbose)
			fprintf(fp, "(none allocated)\n\n");
		return 0;
	}

	array = (ulong *)GETBUF(sizeof(ulong *) * (max_id + 1));
	if (VALID_MEMBER(ipc_id_ary_p))
		readmem(entries_p + OFFSET(ipc_id_ary_p), KVADDR, array,
			sizeof(ulong *) * (max_id + 1), "ipc_id_ary.p",
			FAULT_ON_ERROR);
	else
		readmem(entries_p, KVADDR, array, sizeof(ulong *)*(max_id+1),
				"ipc_id array", FAULT_ON_ERROR);

	for (i=0; i<=max_id; i++) {
		if (array[i] == 0)
			continue;
		if (fn(array[i], specified, specified_value, i, verbose)) {
			allocated++;
			found = 1;
			if (specified != SPECIFIED_NOTHING)
				break;
		}
	}

	if (specified == SPECIFIED_NOTHING && !verbose) {
		if (!allocated)
			fprintf(fp, "(none allocated)\n");
		fprintf(fp, "\n");
	}

	FREEBUF(array);

	if (found)
		return 1;
	else
		return 0;
}

/*
 * if shared memory information is stored by using idr, use this function to
 * get data.
 */
static int
ipc_search_idr(ulong ipc_ids_p, int specified, ulong specified_value, int (*fn)(ulong, int, ulong, int, int), int verbose)
{
	int i, in_use;
	ulong ipcs_idr_p;
	ulong ipc;
	int next_id, total;
	int found = 0;

	readmem(ipc_ids_p + OFFSET(ipc_ids_in_use), KVADDR, &in_use, 
		sizeof(int), "ipc_ids.in_use", FAULT_ON_ERROR);

	ipcs_idr_p = ipc_ids_p + OFFSET(ipc_ids_ipcs_idr);

	if (!in_use) {
		if (specified == SPECIFIED_NOTHING && !verbose)
			fprintf(fp, "(none allocated)\n\n");
		return 0;
	}

	if (VALID_MEMBER(idr_idr_rt)) {
		switch (ipcs_table.init_flags & (IDR_RADIX|IDR_XARRAY))
		{
		case IDR_RADIX: 
			gather_radix_tree_entries(ipcs_idr_p);
			break;
		case IDR_XARRAY:
			gather_xarray_entries(ipcs_idr_p);
			break;
		}

		for (i = 0; i < ipcs_table.cnt; i++) {
			ipc = (ulong)ipcs_table.lp[i].value;
			if (fn(ipc, specified, specified_value, UNUSED, verbose)) {
				found = 1;
				if (specified != SPECIFIED_NOTHING)
					break;
			}
		}

		if (ipcs_table.lp)
			FREEBUF(ipcs_table.lp);
	} else {
		for (total = 0, next_id = 0; total < in_use; next_id++) {
			ipc = idr_find(ipcs_idr_p, next_id);
			if (ipc == 0)
				continue;
			
			total++;
			if (fn(ipc, specified, specified_value, next_id, verbose)) {
				found = 1;
				if (specified != SPECIFIED_NOTHING)
					break;
			}
		}
	}
	
	if (!verbose && specified == SPECIFIED_NOTHING)
		fprintf(fp, "\n");

	if (found || specified == SPECIFIED_NOTHING)
		return 1;
	else
		return 0;
}

/*
 * search every idr_layer
 */
ulong
idr_find(ulong idp, int id)
{
	ulong idr_layer_p;
	int layer;
	int idr_layers;
	int n;
	int index;

	readmem(idp + OFFSET(idr_top), KVADDR, &idr_layer_p,
		sizeof(ulong), "idr.top", FAULT_ON_ERROR);

	if (!idr_layer_p)
		return 0;

	if (VALID_MEMBER(idr_layer_layer)) {
		readmem(idr_layer_p + OFFSET(idr_layer_layer), KVADDR,
			&layer,	sizeof(int), "idr_layer.layer",
			FAULT_ON_ERROR);
		n = (layer + 1) * ipcs_table.idr_bits;
	} else {
		readmem(idp + OFFSET(idr_layers), KVADDR, &idr_layers,
			sizeof(int), "idr.layers", FAULT_ON_ERROR);
		n = idr_layers * ipcs_table.idr_bits;
	}
	id &= MAX_ID_MASK;

	if (id >= (1 << n))
		return 0;

	while (n > 0 && idr_layer_p) {
		n -= ipcs_table.idr_bits;
		index = (id >> n) & ((1 << ipcs_table.idr_bits) - 1);
		readmem(idr_layer_p + OFFSET(idr_layer_ary) +
			sizeof(ulong) * index, KVADDR, &idr_layer_p,
			sizeof(ulong), "idr_layer.ary", FAULT_ON_ERROR);
	}
	
	return idr_layer_p;
}

/*
 * only specified is not SPECIFIED_NOTHIND, and the specified_value is found,
 * then return 1
 */
static int
dump_shm_info(ulong shp, int specified, ulong specified_value, int id, int verbose)
{
	struct shm_info shm_info;
	char buf[BUFSIZE];
	char buf0[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char buf5[BUFSIZE];
	char buf6[BUFSIZE];
	char buf7[BUFSIZE];

	get_shm_info(&shm_info, shp, id);
	
	if (shm_info.deleted)
		return 0;

	if (((specified & SPECIFIED_ID) && shm_info.shmid == specified_value) ||
		((specified & SPECIFIED_ADDR) && shm_info.shmid_kernel ==
		 specified_value) || specified == SPECIFIED_NOTHING) {
		if (verbose || specified != SPECIFIED_NOTHING) {
			fprintf(fp, "%s %s %s %s %s %s %s %s\n",
				mkstring(buf0, VADDR_PRLEN<=12?12:VADDR_PRLEN,
					LJUST, "SHMID_KERNEL"),
				mkstring(buf1, 8, LJUST, "KEY"),
				mkstring(buf2, 10, LJUST, "SHMID"),
				mkstring(buf3, 5, LJUST, "UID"),
				mkstring(buf4, 5, LJUST, "PERMS"),
				mkstring(buf5, 10, LJUST, "BYTES"),
				mkstring(buf6, 6, LJUST, "NATTCH"),
				mkstring(buf7, 6, LJUST, "STATUS"));
		}

		fprintf(fp, "%s %08x %-10d %-5d %-5o %-10ld %-6ld %-s %-s\n",
			mkstring(buf, VADDR_PRLEN <= 12 ? 12 : VADDR_PRLEN,
				LJUST|LONG_HEX,	(char *)shm_info.shmid_kernel),
			shm_info.key,
			shm_info.shmid,
			shm_info.uid,
			shm_info.perms & 0777,
			shm_info.bytes,
			shm_info.nattch,
			shm_info.perms & SHM_DEST ? "dest" : "",
			shm_info.perms & SHM_LOCKED ? "locked" : "");

		if (verbose) {
			fprintf(fp, "PAGES ALLOCATED/RESIDENT/SWAPPED: %ld/%ld/%ld\n",
				(shm_info.bytes+PAGESIZE()-1) >> PAGESHIFT(),
				shm_info.rss, shm_info.swap);
			fprintf(fp, "INODE: %lx\n", shm_info.shm_inode);
		}

		if (verbose || specified != SPECIFIED_NOTHING)
			fprintf(fp, "\n");

		return 1;
	} else
		return 0;
}

/*
 * only specified is not SPECIFIED_NOTHIND, and the specified_value is found,
 * then return 1
 */
static int
dump_sem_info(ulong shp, int specified, ulong specified_value, int id, int verbose)
{
	struct sem_info sem_info;
	char buf[BUFSIZE];
	char buf0[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char buf5[BUFSIZE];

	get_sem_info(&sem_info, shp, id);

	if (sem_info.deleted)
		return 0;

	if (((specified & SPECIFIED_ID) && sem_info.semid == specified_value) ||
		((specified & SPECIFIED_ADDR) && sem_info.sem_array ==
		 specified_value) || specified == SPECIFIED_NOTHING) {
		if (specified != SPECIFIED_NOTHING) {
			fprintf(fp, "%s %s %s %s %s %s\n",
				mkstring(buf0, VADDR_PRLEN<=10?10:VADDR_PRLEN,
					LJUST, "SEM_ARRAY"),
				mkstring(buf1, 8, LJUST, "KEY"),
				mkstring(buf2, 10, LJUST, "SEMID"),
				mkstring(buf3, 5, LJUST, "UID"),
				mkstring(buf4, 5, LJUST, "PERMS"),
				mkstring(buf5, 10, LJUST, "NSEMS"));
		}

		fprintf(fp, "%s %08x %-10d %-5d %-5o %-10ld\n",
			mkstring(buf, VADDR_PRLEN <= 10 ? 10 : VADDR_PRLEN,
				LJUST|LONG_HEX,	(char *)sem_info.sem_array),
			sem_info.key,
			sem_info.semid,
			sem_info.uid,
			sem_info.perms & 0777,
			sem_info.nsems);

		if (specified != SPECIFIED_NOTHING)
			fprintf(fp, "\n");

		return 1;
	} else
		return 0;
}

/*
 * only specified is not SPECIFIED_NOTHIND, and the specified_value is found,
 * then return 1
 */
static int
dump_msg_info(ulong shp, int specified, ulong specified_value, int id, int verbose)
{
	struct msg_info msg_info;
	char buf[BUFSIZE];
	char buf0[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char buf5[BUFSIZE];
	char buf6[BUFSIZE];

	get_msg_info(&msg_info, shp, id);

	if (msg_info.deleted)
		return 0;

	if (((specified & SPECIFIED_ID) && msg_info.msgid == specified_value) ||
		((specified & SPECIFIED_ADDR) && msg_info.msg_queue ==
		 specified_value) || specified == SPECIFIED_NOTHING) {
		if (specified != SPECIFIED_NOTHING) {
			fprintf(fp, "%s %s %s %s %s %s %s\n",
				mkstring(buf0, VADDR_PRLEN<=10?10:VADDR_PRLEN,
					LJUST, "MSG_QUEUE"),
				mkstring(buf1, 8, LJUST, "KEY"),
				mkstring(buf2, 10, LJUST, "MSQID"),
				mkstring(buf3, 5, LJUST, "UID"),
				mkstring(buf4, 5, LJUST, "PERMS"),
				mkstring(buf5, 12, LJUST, "USED-BYTES"),
				mkstring(buf6, 12, LJUST, "MESSAGES"));
		}

		fprintf(fp, "%s %08x %-10d %-5d %-5o %-12ld %-12ld\n",
			mkstring(buf, VADDR_PRLEN <= 10 ? 10 : VADDR_PRLEN,
				LJUST|LONG_HEX,	(char *)msg_info.msg_queue),
			msg_info.key,
			msg_info.msgid,
			msg_info.uid,
			msg_info.perms & 0777,
			msg_info.bytes,
			msg_info.messages);

		if (specified != SPECIFIED_NOTHING)
			fprintf(fp, "\n");

		return 1;
	} else
		return 0;
}

static void
get_shm_info(struct shm_info *shm_info, ulong shp, int id)
{
	char buf[BUFSIZE];
	ulong filep, dentryp, inodep;

	shm_info->shmid_kernel = shp - OFFSET(shmid_kernel_shm_perm);

	/*
	 * cache shmid_kernel
	 */
	readmem(shm_info->shmid_kernel, KVADDR, buf, SIZE(shmid_kernel),
		"shmid_kernel", FAULT_ON_ERROR);

	shm_info->key = INT(buf + OFFSET(shmid_kernel_shm_perm) +
			OFFSET(kern_ipc_perm_key));
	if (VALID_MEMBER(shmid_kernel_id))
		shm_info->shmid = INT(buf + OFFSET(shmid_kernel_id));
	else
		shm_info->shmid = INT(buf +
				OFFSET(shmid_kernel_shm_perm) +
				OFFSET(kern_ipc_perm_id));

	shm_info->uid = UINT(buf + OFFSET(shmid_kernel_shm_perm) +
			OFFSET(kern_ipc_perm_uid));

	if (BITS32())
		shm_info->perms = USHORT(buf +
				OFFSET(shmid_kernel_shm_perm) +
				OFFSET(kern_ipc_perm_mode));
	else
		shm_info->perms = UINT(buf +
				OFFSET(shmid_kernel_shm_perm) +
				OFFSET(kern_ipc_perm_mode));

	shm_info->bytes = ULONG(buf + OFFSET(shmid_kernel_shm_segsz));

	shm_info->nattch = ULONG(buf + OFFSET(shmid_kernel_shm_nattch));

	filep = ULONG(buf + OFFSET(shmid_kernel_shm_file));
	readmem(filep + OFFSET(file_f_dentry), KVADDR, &dentryp, sizeof(ulong),
		"file.f_dentry", FAULT_ON_ERROR);
	readmem(dentryp + OFFSET(dentry_d_inode), KVADDR, &inodep,
		sizeof(ulong), "dentry.d_inode", FAULT_ON_ERROR);
	/* 
	 * shm_inode here is the vfs_inode of struct shmem_inode_info
	 */
	shm_info->shm_inode = inodep;

	shm_info->rss = 0;
	shm_info->swap = 0;

	add_rss_swap(inodep, is_file_hugepages(filep), &shm_info->rss,
                 &shm_info->swap);

	shm_info->deleted = UCHAR(buf + OFFSET(shmid_kernel_shm_perm) +
				OFFSET(kern_ipc_perm_deleted));
}

static void
get_sem_info(struct sem_info *sem_info, ulong shp, int id)
{
	char buf[BUFSIZE];
	
	sem_info->sem_array = shp - OFFSET(sem_array_sem_perm);

	/*
	 * cache sem_array
	 */
	readmem(sem_info->sem_array, KVADDR, buf, SIZE(sem_array),
		"sem_array", FAULT_ON_ERROR);

	sem_info->key = INT(buf + OFFSET(sem_array_sem_perm) +
			OFFSET(kern_ipc_perm_key));

	if (VALID_MEMBER(sem_array_sem_id))
		sem_info->semid = INT(buf + OFFSET(sem_array_sem_id));
	else if (VALID_MEMBER(kern_ipc_perm_id))
		sem_info->semid = INT(buf + OFFSET(sem_array_sem_perm) +
				OFFSET(kern_ipc_perm_id));
	else {
		ulong seq;
		seq = ULONG(buf + OFFSET(sem_array_sem_perm) +
				OFFSET(kern_ipc_perm_seq));
		sem_info->semid = ipcs_table.seq_multiplier * seq + id;
	}

	sem_info->uid = UINT(buf + OFFSET(sem_array_sem_perm) +
			OFFSET(kern_ipc_perm_uid));

	if (BITS32())
		sem_info->perms = USHORT(buf +
				OFFSET(sem_array_sem_perm) +
				OFFSET(kern_ipc_perm_mode));
	else
		sem_info->perms = UINT(buf + OFFSET(sem_array_sem_perm) +
				OFFSET(kern_ipc_perm_mode));

	sem_info->nsems = ULONG(buf + OFFSET(sem_array_sem_nsems));

	sem_info->deleted = UCHAR(buf + OFFSET(sem_array_sem_perm) +
				OFFSET(kern_ipc_perm_deleted));
}

static void
get_msg_info(struct msg_info *msg_info, ulong shp, int id)
{
	char buf[BUFSIZE];

	msg_info->msg_queue = shp - OFFSET(msg_queue_q_perm);

	/*
	 * cache msg_queue
	 */
	readmem(msg_info->msg_queue, KVADDR, buf, SIZE(msg_queue),
		"msg_queue", FAULT_ON_ERROR);

	msg_info->key = INT(buf + OFFSET(msg_queue_q_perm) +
			OFFSET(kern_ipc_perm_key));

	if (VALID_MEMBER(msg_queue_q_id))
		msg_info->msgid = INT(buf + OFFSET(msg_queue_q_id));
	else if (VALID_MEMBER(kern_ipc_perm_id))
		msg_info->msgid = INT(buf + OFFSET(msg_queue_q_perm) +
				OFFSET(kern_ipc_perm_id));
	else {
		ulong seq;
		seq = ULONG(buf + OFFSET(msg_queue_q_perm) +
				OFFSET(kern_ipc_perm_seq));
		msg_info->msgid = ipcs_table.seq_multiplier * seq + id;
	}

	msg_info->uid = UINT(buf + OFFSET(msg_queue_q_perm) +
			OFFSET(kern_ipc_perm_uid));

	if (BITS32())
		msg_info->perms = USHORT(buf + OFFSET(msg_queue_q_perm) +
				OFFSET(kern_ipc_perm_mode));
	else
		msg_info->perms = UINT(buf + OFFSET(msg_queue_q_perm) +
				OFFSET(kern_ipc_perm_mode));

	msg_info->bytes = ULONG(buf + OFFSET(msg_queue_q_cbytes));

	msg_info->messages = ULONG(buf + OFFSET(msg_queue_q_qnum));
	
	msg_info->deleted = UCHAR(buf + OFFSET(msg_queue_q_perm) +
				OFFSET(kern_ipc_perm_deleted));
}

/*
 * get rss & swap related to every shared memory, and get the total number of rss
 * & swap
 */
static void
add_rss_swap(ulong inode_p, int hugepage, ulong *rss, ulong *swap)
{
	unsigned long mapping_p, nr_pages;

	readmem(inode_p + OFFSET(inode_i_mapping), KVADDR, &mapping_p,
		sizeof(ulong), "inode.i_mapping", FAULT_ON_ERROR);
	readmem(mapping_p + OFFSET(address_space_nrpages), KVADDR, &nr_pages,
		sizeof(ulong), "address_space.nrpages",
		FAULT_ON_ERROR);

	if (hugepage) {
		unsigned long pages_per_hugepage;
		if (VALID_SIZE(hstate)) {
			unsigned long i_sb_p, hsb_p, hstate_p;
			unsigned int order;

			readmem(inode_p + OFFSET(inode_i_sb), KVADDR, &i_sb_p,
				sizeof(ulong), "inode.i_sb",
				FAULT_ON_ERROR);
			readmem(i_sb_p + OFFSET(super_block_s_fs_info),
				KVADDR,	&hsb_p, sizeof(ulong),
				"super_block.s_fs_info", FAULT_ON_ERROR);
			readmem(hsb_p + OFFSET(hugetlbfs_sb_info_hstate),
				KVADDR,	&hstate_p, sizeof(ulong),
				"hugetlbfs_sb_info.hstate", FAULT_ON_ERROR);
			readmem(hstate_p + OFFSET(hstate_order), KVADDR,
				&order,	sizeof(uint), "hstate.order",
				FAULT_ON_ERROR);
			pages_per_hugepage = 1 << order;
		} else {
			unsigned long hpage_shift;
			/*
			 * HPAGE_SHIFT is 21 after commit 83a5101b
			 * (kernel > 2.6.24)
			 */
			if (THIS_KERNEL_VERSION > LINUX(2, 6, 24)) {
				hpage_shift = 21;
			} else {
				/*
				 * HPAGE_SHIFT:
				 *   x86(PAE): 21
				 *   x86(no PAE): 22
				 *   x86_64: 21
				 */
				if ((machine_type("X86") &&
					!(machdep->flags & PAE)))
					hpage_shift = 22;
				else
					hpage_shift = 21;
			}
			pages_per_hugepage = (1 << hpage_shift) / PAGESIZE();
		}
		*rss += pages_per_hugepage * nr_pages;
	} else {
		unsigned long swapped;

		*rss += nr_pages;
		readmem(inode_p - OFFSET(shmem_inode_info_vfs_inode) +
			OFFSET(shmem_inode_info_swapped), KVADDR,
			&swapped, sizeof(ulong), "shmem_inode_info.swapped",
			FAULT_ON_ERROR);
		*swap += swapped;
    }
}

static int
is_file_hugepages(ulong file_p)
{
	unsigned long f_op, sfd_p;

again:
	readmem(file_p + OFFSET(file_f_op), KVADDR, &f_op, sizeof(ulong),
		"file.f_op", FAULT_ON_ERROR);
	if (f_op == ipcs_table.hugetlbfs_f_op_addr)
		return 1;

	if (ipcs_table.use_shm_f_op) {
		if (ipcs_table.shm_f_op_huge_addr != -1) {
			if (f_op == ipcs_table.shm_f_op_huge_addr)
				return 1;
		} else {
			if (f_op == ipcs_table.shm_f_op_addr) {
				readmem(file_p +
					OFFSET(file_private_data),
					KVADDR,	&sfd_p, sizeof(ulong),
					"file.private_data", FAULT_ON_ERROR);
				readmem(sfd_p +
					OFFSET(shm_file_data_file),
					KVADDR,	&file_p, sizeof(ulong),
					"shm_file_data.file", FAULT_ON_ERROR);
				goto again;
			}
		}
	}

	return 0;
}

static void
gather_radix_tree_entries(ulong ipcs_idr_p)
{
	long len;

	ipcs_table.cnt = do_radix_tree(ipcs_idr_p, RADIX_TREE_COUNT, NULL);

	if (ipcs_table.cnt) {
		len = sizeof(struct list_pair) * (ipcs_table.cnt+1);
		ipcs_table.lp = (struct list_pair *)GETBUF(len);
		ipcs_table.lp[0].index = ipcs_table.cnt;
		ipcs_table.cnt = do_radix_tree(ipcs_idr_p, RADIX_TREE_GATHER, ipcs_table.lp);
	} else
		ipcs_table.lp = NULL;
}

static void
gather_xarray_entries(ulong ipcs_idr_p)
{
	long len;

	ipcs_table.cnt = do_xarray(ipcs_idr_p, XARRAY_COUNT, NULL);

	if (ipcs_table.cnt) {
		len = sizeof(struct list_pair) * (ipcs_table.cnt+1);
		ipcs_table.lp = (struct list_pair *)GETBUF(len);
		ipcs_table.lp[0].index = ipcs_table.cnt;
		ipcs_table.cnt = do_xarray(ipcs_idr_p, XARRAY_GATHER, ipcs_table.lp);
	} else
		ipcs_table.lp = NULL;
}

