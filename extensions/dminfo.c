/* dminfo.c - crash extension module for device-mapper analysis
 *
 * Copyright (C) 2005 NEC Corporation
 * Copyright (C) 2005 Red Hat, Inc. All rights reserved.
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

#include "defs.h"		/* From the crash source top-level directory */

void dminfo_init(void);
void dminfo_fini(void);

/*
 * Indices of size-offset array (Used by GET_xxx macros)
 *
 * DM_<struct name>_<member name>
 */
enum {
	DM_hash_cell_name_list = 0,
	DM_hash_cell_name,
	DM_hash_cell_md,

	DM_mapped_device_disk,
	DM_mapped_device_map,

	DM_gendisk_major,
	DM_gendisk_first_minor,
	DM_gendisk_disk_name,

	DM_dm_table_num_targets,
	DM_dm_table_targets,
	DM_dm_table_devices,

	DM_dm_target_type,
	DM_dm_target_begin,
	DM_dm_target_len,
	DM_dm_target_private,

	DM_dm_dev_count,
	DM_dm_dev_bdev,
	DM_dm_dev_name,

	DM_dm_io_md,
	DM_dm_io_bio,

	DM_target_type_name,

	DM_target_io_io,

	DM_block_device_bd_disk,

	DM_bio_bi_private,

	DM_bio_list_head,

	DM_linear_c_dev,
	DM_linear_c_start,

	DM_multipath_hw_handler,
	DM_multipath_nr_priority_groups,
	DM_multipath_priority_groups,
	DM_multipath_nr_valid_paths,
	DM_multipath_current_pg,
	DM_multipath_queue_if_no_path,
	DM_multipath_queue_size,

	DM_hw_handler_type,
	DM_hw_handler_type_name,

	DM_priority_group_ps,
	DM_priority_group_pg_num,
	DM_priority_group_bypassed,
	DM_priority_group_nr_pgpaths,
	DM_priority_group_pgpaths,

	DM_path_selector_type,
	DM_path_selector_type_name,

	DM_pgpath_fail_count,
	DM_pgpath_path,

	DM_path_dev,
	DM_path_is_active,

	DM_mirror_set_rh,
	DM_mirror_set_reads,
	DM_mirror_set_writes,
	DM_mirror_set_in_sync,
	DM_mirror_set_nr_mirrors,
	DM_mirror_set_mirror,

	DM_region_hash_log,
	DM_region_hash_quiesced_regions,
	DM_region_hash_recovered_regions,

	DM_dirty_log_type,
	DM_dirty_log_type_name,

	DM_mirror_error_count,
	DM_mirror_dev,
	DM_mirror_offset,

	DM_crypt_config_dev,
	DM_crypt_config_iv_mode,
	DM_crypt_config_tfm,
	DM_crypt_config_key_size,
	DM_crypt_config_key,

	DM_crypto_tfm_crt_u,
	DM_crypto_tfm___crt_alg,

	DM_crypto_alg_cra_name,

	DM_cipher_tfm_cit_mode,

	DM_stripe_c_stripes,
	DM_stripe_c_chunk_mask,
	DM_stripe_c_stripe,

	DM_stripe_dev,

	DM_dm_snapshot_origin,
	DM_dm_snapshot_cow,
	DM_dm_snapshot_chunk_size,
	DM_dm_snapshot_valid,
	DM_dm_snapshot_type,

	NR_DMINFO_MEMBER_TABLE_ENTRY
};

/* Size-offset array for structure's member */
static struct dminfo_member_entry {
	unsigned long offset;
	unsigned long size;
} mbr_ary[NR_DMINFO_MEMBER_TABLE_ENTRY];

/*
 * Macros to retrieve data of given structure's member
 *
 * Macros except for the MSG assume 'struct s' is at 'addr'
 */
#define MSG(msg, s, m) msg ": " s "." m

/* Initialize the size-offset array */
#define INIT_MBR_TABLE(s, m) \
	do { \
		if (!mbr_ary[DM_##s##_##m].size) { \
			mbr_ary[DM_##s##_##m].offset = MEMBER_OFFSET("struct " #s, #m); \
			mbr_ary[DM_##s##_##m].size   = MEMBER_SIZE("struct " #s, #m); \
		} \
	} while (0)

/*
 * Store the data of member m in ret.
 * Initialize the size-offset array for the member m if needed.
 */
#define GET_VALUE(addr, s, m, ret) \
	do { \
		INIT_MBR_TABLE(s, m); \
		if (sizeof(ret) < mbr_ary[DM_##s##_##m].size) \
			fprintf(fp, "%s\n", \
				MSG("ERROR: GET_VALUE size_check", #s, #m)); \
		readmem(addr + mbr_ary[DM_##s##_##m].offset, KVADDR, &ret, \
			mbr_ary[DM_##s##_##m].size, MSG("GET_VALUE", #s, #m), \
			FAULT_ON_ERROR);\
	} while (0)

/*
 * Store the address of member m in ret.
 * Initialize the size-offset array for the member m if needed.
 */
#define GET_ADDR(addr, s, m, ret) \
	do { \
		INIT_MBR_TABLE(s, m); \
		ret = addr + mbr_ary[DM_##s##_##m].offset; \
	} while (0)

/*
 * Store the string data of member m in ret.
 * Initialize the size-offset array for the member m if needed.
 */
#define GET_STR(addr, s, m, ret, len) \
	do { \
		INIT_MBR_TABLE(s, m); \
		if (!read_string(addr + mbr_ary[DM_##s##_##m].offset, ret, len - 1)) \
			fprintf(fp, "%s\n", MSG("ERROR: GET_STR", #s, #m)); \
	} while (0)

/*
 * Store the string data pointed by member m in ret.
 * Initialize the size-offset array for the member m if needed.
 */
#define GET_PTR_STR(addr, s, m, ret, len) \
	do { \
		unsigned long tmp; \
		INIT_MBR_TABLE(s, m); \
		readmem(addr + mbr_ary[DM_##s##_##m].offset, KVADDR, &tmp, \
			mbr_ary[DM_##s##_##m].size, MSG("GET_PTR_STR", #s, #m),\
			FAULT_ON_ERROR);\
		if (!read_string(tmp, ret, len - 1)) \
			fprintf(fp, "%s\n", MSG("ERROR: GET_PTR_STR", #s, #m));\
	} while (0)

/*
 * Utility function/macro to walk the list
 */
static unsigned long
get_next_from_list_head(unsigned long addr)
{
	unsigned long ret;

	readmem(addr + OFFSET(list_head_next), KVADDR, &ret, sizeof(void *),
		MSG("get_next_from_list_head", "list_head", "next"),
		FAULT_ON_ERROR);

	return ret;
}

#define list_for_each(next, head, last) \
	for (next = get_next_from_list_head(head), last = 0UL; \
		next && next != head && next != last; \
		last = next, next = get_next_from_list_head(next))

/*
 * device-mapper target analyzer
 *
 * device-mapper has various target driver: linear, mirror, multipath, etc.
 * Information specific to target is stored in its own way.
 * Target-specific analyzer is provided for each target driver for this reason.
 */
static struct dminfo_target_analyzer {
	struct dminfo_target_analyzer *next;
	char *target_name;
	int (*ready) (void);	/* returns true if analyzer is available */
	void (*show_table) (unsigned long);  /* display table info */
	void (*show_status) (unsigned long); /* display status info */
	void (*show_queue) (unsigned long);  /* display queued I/O info */
} analyzers_head;

static void
dminfo_register_target_analyzer(struct dminfo_target_analyzer *ta)
{
	ta->next = analyzers_head.next;
	analyzers_head.next = ta;
}

static struct
dminfo_target_analyzer *find_target_analyzer(char *target_type)
{
	struct dminfo_target_analyzer *ta;

	for (ta = analyzers_head.next; ta; ta = ta->next)
		if (!strcmp(ta->target_name, target_type))
			return ta;

	return NULL;
}

/*
 * zero target
 */
static int
zero_ready(void)
{
	return 1;
}

static void
zero_show_table(unsigned long target)
{
	unsigned long long start, len;

	/* Get target information */
	GET_VALUE(target, dm_target, begin, start);
	GET_VALUE(target, dm_target, len, len);

	fprintf(fp, "  begin:%llu len:%llu", start, len);
}

static void
zero_show_status(unsigned long target)
{
	/* zero target has no status */
	fprintf(fp, "  No status info");
}

static void
zero_show_queue(unsigned long target)
{
	/* zero target has no queue */
	fprintf(fp, "  No queue info");
}

static struct dminfo_target_analyzer zero_analyzer = {
	.target_name      = "zero",
	.ready            = zero_ready,
	.show_table       = zero_show_table,
	.show_status      = zero_show_status,
	.show_queue       = zero_show_queue
};

/*
 * error target
 */
static int
error_ready(void)
{
	return 1;
}

static void
error_show_table(unsigned long target)
{
	unsigned long long start, len;

	/* Get target information */
	GET_VALUE(target, dm_target, begin, start);
	GET_VALUE(target, dm_target, len, len);

	fprintf(fp, "  begin:%llu len:%llu", start, len);
}

static void
error_show_status(unsigned long target)
{
	/* error target has no status */
	fprintf(fp, "  No status info");
}

static void
error_show_queue(unsigned long target)
{
	/* error target has no queue */
	fprintf(fp, "  No queue info");
}

static struct dminfo_target_analyzer error_analyzer = {
	.target_name      = "error",
	.ready            = error_ready,
	.show_table       = error_show_table,
	.show_status      = error_show_status,
	.show_queue       = error_show_queue
};

/*
 * linear target
 */
static int
linear_ready(void)
{
	static int debuginfo = 0;

	if (debuginfo)
		return 1;

	if (STRUCT_EXISTS("struct linear_c")) {
		debuginfo = 1;
		return 1;
	} else
		fprintf(fp, "No such struct info: linear_c");

	return 0;
}

static void
linear_show_table(unsigned long target)
{
	unsigned long lc, dm_dev;
	unsigned long long start, len, offset;
	char devt[BUFSIZE];

	/* Get target information */
	GET_VALUE(target, dm_target, begin, start);
	GET_VALUE(target, dm_target, len, len);
	GET_VALUE(target, dm_target, private, lc);
	GET_VALUE(lc, linear_c, dev, dm_dev);
	GET_STR(dm_dev, dm_dev, name, devt, BUFSIZE);
	GET_VALUE(lc, linear_c, start, offset);

	fprintf(fp, "  begin:%llu len:%llu dev:%s offset:%llu",
		start, len, devt, offset);
}

static void
linear_show_status(unsigned long target)
{
	/* linear target has no status */
	fprintf(fp, "  No status info");
}

static void
linear_show_queue(unsigned long target)
{
	/* linear target has no I/O queue */
	fprintf(fp, "  No queue info");
}

static struct dminfo_target_analyzer linear_analyzer = {
	.target_name      = "linear",
	.ready            = linear_ready,
	.show_table       = linear_show_table,
	.show_status      = linear_show_status,
	.show_queue       = linear_show_queue
};

/*
 * mirror target
 */
static int
mirror_ready(void)
{
	static int debuginfo = 0;

	if (debuginfo)
		return 1;

	if (STRUCT_EXISTS("struct mirror_set")) {
		debuginfo = 1;
		return 1;
	} else
		fprintf(fp, "No such struct info: mirror_set");

	return 0;
}

static void
mirror_show_table(unsigned long target)
{
	unsigned int i, nr_mir;
	unsigned long ms, rh, log, log_type, mir_size, mir_head, mir, dm_dev;
	unsigned long long offset;
	char buf[BUFSIZE];

	/* Get the address of struct mirror_set */
	GET_VALUE(target, dm_target, private, ms);

	/* Get the log-type name of the mirror_set */
	GET_ADDR(ms, mirror_set, rh, rh);
	GET_VALUE(rh, region_hash, log, log);
	GET_VALUE(log, dirty_log, type, log_type);
	GET_PTR_STR(log_type, dirty_log_type, name, buf, BUFSIZE);
	fprintf(fp, "  log:%s", buf);

	/*
	 * Display information for each mirror disks.
	 *
	 * mir_head = mirror_set.mirror.
	 * This is the head of struct mirror array.
	 */
	fprintf(fp, " dev:");
	mir_size = STRUCT_SIZE("struct mirror");
	GET_ADDR(ms, mirror_set, mirror, mir_head);
	GET_VALUE(ms, mirror_set, nr_mirrors, nr_mir);
	for (i = 0; i < nr_mir; i++) {
		mir = mir_head + mir_size * i; /* Get next mirror */

		/* Get the devt of the mirror disk */
		GET_VALUE(mir, mirror, dev, dm_dev);
		GET_STR(dm_dev, dm_dev, name, buf, BUFSIZE);

		/* Get the offset of the mirror disk */
		GET_VALUE(mir, mirror, offset, offset);

		fprintf(fp, "%s(%llu)%s", buf, offset,
			i == nr_mir - 1 ? "" : ",");
	}
	if (i != nr_mir)
		fprintf(fp, " ERROR: dev are less than nr_mir:%d", nr_mir);
}

static void
mirror_show_status(unsigned long target)
{
	unsigned int i, nr_mir, synced, nr_error;
	unsigned long ms, mir_size, mir_head, mir, dm_dev;
	char buf[BUFSIZE];

	/* Get the address of struct mirror_set */
	GET_VALUE(target, dm_target, private, ms);

	/* Get the status info of the mirror_set */
	GET_VALUE(ms, mirror_set, in_sync, synced);
	fprintf(fp, "  in_sync:%d", synced);

	/*
	 * Display information for each mirror disks.
	 *
	 * mir_head = mirror_set.mirror.
	 * This is the head of struct mirror array.
	 */
	fprintf(fp, " dev:");
	mir_size = STRUCT_SIZE("struct mirror");
	GET_ADDR(ms, mirror_set, mirror, mir_head);
	GET_VALUE(ms, mirror_set, nr_mirrors, nr_mir);
	for (i = 0; i < nr_mir; i++) {
		mir = mir_head + mir_size * i; /* Get next mirror */

		/* Get the devt of the mirror disk */
		GET_VALUE(mir, mirror, dev, dm_dev);
		GET_STR(dm_dev, dm_dev, name, buf, BUFSIZE);

		/* Get the offset of the mirror disk */
		GET_VALUE(mir, mirror, error_count, nr_error);

		fprintf(fp, "%s(%c,%d)%s", buf, nr_error ? 'D' : 'A', nr_error,
			i == nr_mir - 1 ? "" : ",");
	}
	if (i != nr_mir)
		fprintf(fp, " ERROR: dev are less than nr_mir:%d", nr_mir);
}

static void
mirror_show_queue(unsigned long target)
{
	unsigned long ms, rlist, wlist, rhead, whead;
	unsigned long rh, quis_head, rcov_head, quis_next, rcov_next;

	/* Get the address of struct mirror_set */
	GET_VALUE(target, dm_target, private, ms);

	/* Get the address of queued I/O lists in struct mirror_set */
	GET_ADDR(ms, mirror_set, reads, rlist);
	GET_ADDR(ms, mirror_set, writes, wlist);

	/* Get the head of queued I/O lists */
	GET_VALUE(rlist, bio_list, head, rhead);
	GET_VALUE(wlist, bio_list, head, whead);
	fprintf(fp, "  %s", rhead ? "reads" : "(reads)");
	fprintf(fp, " %s", whead ? "writes" : "(writes)");

	/* Get the address of the struct region_hash */
	GET_ADDR(ms, mirror_set, rh, rh);

	/* Get the address of recover region lists in struct region_hash */
	GET_ADDR(rh, region_hash, quiesced_regions, quis_head);
	GET_ADDR(rh, region_hash, recovered_regions, rcov_head);

	/* Get the head of recover region lists */
	quis_next = get_next_from_list_head(quis_head);
	rcov_next = get_next_from_list_head(rcov_head);

	fprintf(fp, " %s", quis_next != quis_head ? "quiesced" : "(quiesced)");
	fprintf(fp, " %s", rcov_next != rcov_head ? "recovered" : "(recovered)");
}

static struct dminfo_target_analyzer mirror_analyzer = {
	.target_name      = "mirror",
	.ready            = mirror_ready,
	.show_table       = mirror_show_table,
	.show_status      = mirror_show_status,
	.show_queue       = mirror_show_queue
};

/*
 * multipath target
 */
static int
multipath_ready(void)
{
	static int debuginfo = 0;

	if (debuginfo)
		return 1;

	if (STRUCT_EXISTS("struct multipath")) {
		debuginfo = 1;
		return 1;
	} else
		fprintf(fp, "No such struct info: multipath");

	return 0;
}

static void
multipath_show_table(unsigned long target)
{
	int i, j;
	unsigned int queue_if_no_path, nr_pgs, pg_id, nr_paths;
	unsigned long mp, hwh, hwh_type, ps, ps_type, path, dm_dev;
	unsigned long pg_head, pg_next, pg_last;
	unsigned long path_head, path_next, path_last;
	char name[BUFSIZE];

	/* Get the address of struct multipath */
	GET_VALUE(target, dm_target, private, mp);

	/* Get features information */
	GET_VALUE(mp, multipath, queue_if_no_path, queue_if_no_path);

	/* Get the hardware-handler information */
	GET_ADDR(mp, multipath, hw_handler, hwh);
	GET_VALUE(hwh, hw_handler, type, hwh_type);
	if (hwh_type)
		GET_PTR_STR(hwh_type, hw_handler_type, name, name, BUFSIZE);
	else
		strcpy(name, "none");

	/* Get the number of priority groups */
	GET_VALUE(mp, multipath, nr_priority_groups, nr_pgs);

	fprintf(fp, "  queue_if_no_path:%d hwh:%s nr_pgs:%d\n",
		queue_if_no_path, name, nr_pgs);

	/* Display information for each priority group */
	fprintf(fp, "    %-2s  %-13s  %-8s  %s",
		"PG", "PATH_SELECTOR", "NR_PATHS", "PATHS");
	GET_ADDR(mp, multipath, priority_groups, pg_head);
	i = 0;
	list_for_each (pg_next, pg_head, pg_last) {
		/* pg_next == struct priority_group */

		/* Get the index of the priority group */
		GET_VALUE(pg_next, priority_group, pg_num, pg_id);

		/* Get the name of path selector */
		GET_ADDR(pg_next, priority_group, ps, ps);
		GET_VALUE(ps, path_selector, type, ps_type);
		GET_PTR_STR(ps_type, path_selector_type, name, name, BUFSIZE);

		/* Get the number of paths in the priority group */
		GET_VALUE(pg_next, priority_group, nr_pgpaths, nr_paths);

		fprintf(fp, "\n    %-2d  %-13s  %-8d ", pg_id, name, nr_paths);

		/* Display information for each path */
		GET_ADDR(pg_next, priority_group, pgpaths, path_head);
		j = 0;
		list_for_each (path_next, path_head, path_last) {
			/* path_next == struct pgpath */

			/* Get the devt of the pgpath */
			GET_ADDR(path_next, pgpath, path, path);
			GET_VALUE(path, path, dev, dm_dev);
			GET_STR(dm_dev, dm_dev, name, name, BUFSIZE);

			fprintf(fp, " %s", name);
			j++;
		}
		if (j != nr_paths)
			fprintf(fp, " ERROR: paths are less than nr_paths:%d",
				nr_paths);
		i++;
	}
	if (i != nr_pgs)
		fprintf(fp, " ERROR: pgs are less than nr_pgs:%d", nr_pgs);
}

static void
multipath_show_status(unsigned long target)
{
	int i, j;
	unsigned int queue_if_no_path, nr_pgs, pg_id, nr_paths;
	unsigned int bypassed_pg, path_active, nr_fails;
	unsigned long mp, hwh, hwh_type, cur_pg, path, dm_dev;
	unsigned long pg_head, pg_next, pg_last;
	unsigned long path_head, path_next, path_last;
	char buf[BUFSIZE], path_status;

	/* Get the address of struct multipath */
	GET_VALUE(target, dm_target, private, mp);

	/* Get features information */
	GET_VALUE(mp, multipath, queue_if_no_path, queue_if_no_path);

	/* Get the hardware-handler information */
	GET_ADDR(mp, multipath, hw_handler, hwh);
	GET_VALUE(hwh, hw_handler, type, hwh_type);
	if (hwh_type)
		GET_PTR_STR(hwh_type, hw_handler_type, name, buf, BUFSIZE);
	else
		strcpy(buf, "none");

	/* Get the number of priority groups */
	GET_VALUE(mp, multipath, nr_priority_groups, nr_pgs);

	fprintf(fp, "  queue_if_no_path:%d hwh:%s nr_pgs:%d\n",
		queue_if_no_path, buf, nr_pgs);

	/* Display information for each priority group */
	fprintf(fp, "    %-2s  %-9s  %-8s  %s",
		"PG", "PG_STATUS", "NR_PATHS", "PATHS");
	GET_ADDR(mp, multipath, priority_groups, pg_head);
	i = 0;
	list_for_each (pg_next, pg_head, pg_last) {
		/* pg_next == struct priority_group */

		/* Get the index of the priority group */
		GET_VALUE(pg_next, priority_group, pg_num, pg_id);

		/* Get the status of the priority group */
		GET_VALUE(pg_next, priority_group, bypassed, bypassed_pg);
		if (bypassed_pg)
			strcpy(buf, "disabled");
		else {
			GET_VALUE(mp, multipath, current_pg, cur_pg);
			if (pg_next == cur_pg)
				strcpy(buf, "active");
			else
				strcpy(buf, "enabled");
		}

		/* Get the number of paths in the priority group */
		GET_VALUE(pg_next, priority_group, nr_pgpaths, nr_paths);

		fprintf(fp, "\n    %-2d  %-9s  %-8d ", pg_id, buf, nr_paths);

		/* Display information for each path */
		GET_ADDR(pg_next, priority_group, pgpaths, path_head);
		j = 0;
		list_for_each (path_next, path_head, path_last) {
			/* path_next == struct pgpath */

			/* Get the devt of the pgpath */
			GET_ADDR(path_next, pgpath, path, path);
			GET_VALUE(path, path, dev, dm_dev);
			GET_STR(dm_dev, dm_dev, name, buf, BUFSIZE);

			/* Get the status of the path */
			GET_VALUE(path, path, is_active, path_active);
			GET_VALUE(path_next, pgpath, fail_count, nr_fails);
			path_status = path_active ? 'A' : 'F';

			fprintf(fp, " %s(%c,%u)", buf, path_status, nr_fails);
			j++;
		}
		if (j != nr_paths)
			fprintf(fp, " ERROR: paths are less than nr_paths:%d",
				nr_paths);
		i++;
	}
	if (i != nr_pgs)
		fprintf(fp, " ERROR: pgs are less than nr_pgs:%d", nr_pgs);
}

static void
multipath_show_queue(unsigned long target)
{
	unsigned int queue_size;
	unsigned long mp;

	/* Get the address of struct multipath */
	GET_VALUE(target, dm_target, private, mp);

	/* Get the size of queued I/Os in this 'target' */
	GET_VALUE(mp, multipath, queue_size, queue_size);

	fprintf(fp, "  queue_size:%d", queue_size);
}

static struct dminfo_target_analyzer multipath_analyzer = {
	.target_name      = "multipath",
	.ready            = multipath_ready,
	.show_table       = multipath_show_table,
	.show_status      = multipath_show_status,
	.show_queue       = multipath_show_queue
};

/*
 * crypt target
 */
static int
crypt_ready(void)
{
	static int debuginfo = 0;

	if (debuginfo)
		return 1;

	if (STRUCT_EXISTS("struct crypt_config")) {
		debuginfo = 1;
		return 1;
	} else
		fprintf(fp, "No such struct info: crypt_config");

	return 0;
}

#define DMINFO_CRYPTO_TFM_MODE_ECB 0x00000001
#define DMINFO_CRYPTO_TFM_MODE_CBC 0x00000002

static void
crypt_show_table(unsigned long target)
{
	int i, cit_mode, key_size;
	unsigned long cc, tfm, crt_alg, cipher, iv_mode, dm_dev;
	char buf[BUFSIZE], *chainmode;

	/* Get the address of struct crypt_config */
	GET_VALUE(target, dm_target, private, cc);

	/* Get the cipher name of the crypt_tfm */
	GET_VALUE(cc, crypt_config, tfm, tfm);
	GET_VALUE(tfm, crypto_tfm, __crt_alg, crt_alg);
	GET_STR(crt_alg, crypto_alg, cra_name, buf, BUFSIZE);
	fprintf(fp, "  type:%s", buf);

	/* Get the cit_mode of the crypt_tfm */
	GET_ADDR(tfm, crypto_tfm, crt_u, cipher);
	GET_VALUE(cipher, cipher_tfm, cit_mode, cit_mode);

	if (MEMBER_EXISTS("struct crypt_config", "iv_mode")) {
		if (cit_mode == DMINFO_CRYPTO_TFM_MODE_CBC)
			chainmode = "cbc";
		else if (cit_mode == DMINFO_CRYPTO_TFM_MODE_ECB) 
			chainmode = "ecb";
		else
			chainmode = "unknown";

		/* Get the iv_mode of the crypt_config */
		GET_VALUE(cc, crypt_config, iv_mode, iv_mode);
		if (iv_mode) {
			GET_PTR_STR(cc, crypt_config, iv_mode, buf, BUFSIZE);
			fprintf(fp, "-%s-%s", chainmode, buf);
		} else
			fprintf(fp, "-%s", chainmode);

	} else {
		/* Compatibility mode for old dm-crypt cipher strings */
		if (cit_mode == DMINFO_CRYPTO_TFM_MODE_CBC)
			chainmode = "plain";
		else if (cit_mode == DMINFO_CRYPTO_TFM_MODE_ECB) 
			chainmode = "ecb";
		else
			chainmode = "unknown";

		fprintf(fp, "-%s", chainmode);
	}

	/* Get the devt of the crypt_config */
	GET_VALUE(cc, crypt_config, dev, dm_dev);
	GET_STR(dm_dev, dm_dev, name, buf, BUFSIZE);
	fprintf(fp, " dev:%s", buf);

	/*
	 * Get the key of the crypt_config.
	 */
	GET_VALUE(cc, crypt_config, key_size, key_size);
	GET_STR(cc, crypt_config, key, buf, MIN(key_size + 1, BUFSIZE));
	fprintf(fp, " key:");
	for (i = 0; i < key_size; i++)
		fprintf(fp, "%02x", (unsigned char)buf[i]);
}

static void
crypt_show_status(unsigned long target)
{
	/* crypt target has no status */
	fprintf(fp, "  No status info");
}

static void
crypt_show_queue(unsigned long target)
{
	/* crypt target has no queue */
	fprintf(fp, "  No queue info");
}

static struct dminfo_target_analyzer crypt_analyzer = {
	.target_name      = "crypt",
	.ready            = crypt_ready,
	.show_table       = crypt_show_table,
	.show_status      = crypt_show_status,
	.show_queue       = crypt_show_queue
};

/*
 * stripe target
 */
static int
stripe_ready(void)
{
	static int debuginfo = 0;

	if (debuginfo)
		return 1;

	if (STRUCT_EXISTS("struct stripe_c")) {
		debuginfo = 1;
		return 1;
	} else
		fprintf(fp, "No such struct info: stripe_c");

	return 0;
}

static void
stripe_show_table(unsigned long target)
{
	unsigned int i, n_stripe;
	unsigned long sc, stripe_size, s, head, dm_dev;
	unsigned long long mask;
	char buf[BUFSIZE];

	/* Get the address of struct stripe_c */
	GET_VALUE(target, dm_target, private, sc);

	/* Get the chunk_size of the stripe_c */
	GET_VALUE(sc, stripe_c, chunk_mask, mask);
	fprintf(fp, "  chunk_size:%llu", mask + 1);

	/*
	 * Display the information of each stripe disks.
	 *
	 * head = stripe_c.stripe.
	 * This is the head of struct stripe array.
	 */
	stripe_size = STRUCT_SIZE("struct stripe");
	GET_ADDR(sc, stripe_c, stripe, head);
	GET_VALUE(sc, stripe_c, stripes, n_stripe);
	fprintf(fp, " dev:");
	for (i = 0; i < n_stripe; i++) {
		s = head + stripe_size * i; /* Get next stripe */

		/* Get the devt of the stripe disk */
		GET_VALUE(s, stripe, dev, dm_dev);
		GET_STR(dm_dev, dm_dev, name, buf, BUFSIZE);

		fprintf(fp, "%s%s", buf, i == n_stripe - 1 ? "" : ",");
	}
	if (i != n_stripe)
		fprintf(fp, " ERROR: dev are less than n_stripe:%d", n_stripe);
}

static void
stripe_show_status(unsigned long target)
{
	/* stripe target has no status */
	fprintf(fp, "  No status info");
}

static void
stripe_show_queue(unsigned long target)
{
	/* stripe target has no queue */
	fprintf(fp, "  No queue info");
}

static struct dminfo_target_analyzer stripe_analyzer = {
	.target_name      = "striped",
	.ready            = stripe_ready,
	.show_table       = stripe_show_table,
	.show_status      = stripe_show_status,
	.show_queue       = stripe_show_queue
};

/*
 * snapshot target
 */
static int
snapshot_ready(void)
{
	static int debuginfo = 0;

	if (debuginfo)
		return 1;

	if (STRUCT_EXISTS("struct dm_snapshot")) {
		debuginfo = 1;
		return 1;
	} else
		fprintf(fp, "No such struct info: dm_snapshot");

	return 0;
}

static void
snapshot_show_table(unsigned long target)
{
	unsigned long snap, orig_dev, cow_dev;
	unsigned long long chunk_size;
	char orig_name[BUFSIZE], cow_name[BUFSIZE], type;

	/* Get the address of struct dm_snapshot */
	GET_VALUE(target, dm_target, private, snap);

	/* Get snapshot parameters of the dm_snapshot */
	GET_VALUE(snap, dm_snapshot, origin, orig_dev);
	GET_STR(orig_dev, dm_dev, name, orig_name, BUFSIZE);
	GET_VALUE(snap, dm_snapshot, cow, cow_dev);
	GET_STR(cow_dev, dm_dev, name, cow_name, BUFSIZE);
	GET_VALUE(snap, dm_snapshot, type, type);
	GET_VALUE(snap, dm_snapshot, chunk_size, chunk_size);

	fprintf(fp, "  orig:%s cow:%s type:%c chunk_size:%llu",
		orig_name, cow_name, type, chunk_size);
}

static void
snapshot_show_status(unsigned long target)
{
	int valid;
	unsigned long snap;

	/* Get the address of struct dm_snapshot */
	GET_VALUE(target, dm_target, private, snap);

	/* Get snapshot parameters of the dm_snapshot */
	GET_VALUE(snap, dm_snapshot, valid, valid);

	fprintf(fp, "  vaild:%d", valid);
}

static void
snapshot_show_queue(unsigned long target)
{
	fprintf(fp, "  No queue info");
}

static struct dminfo_target_analyzer snapshot_analyzer = {
	.target_name      = "snapshot",
	.ready            = snapshot_ready,
	.show_table       = snapshot_show_table,
	.show_status      = snapshot_show_status,
	.show_queue       = snapshot_show_queue
};

/*
 * snapshot-origin target
 */
static int
origin_ready(void)
{
	return 1;
}

static void
origin_show_table(unsigned long target)
{
	unsigned long dm_dev;
	char buf[BUFSIZE];

	/* Get the name of the struct dm_dev */
	GET_VALUE(target, dm_target, private, dm_dev);
	GET_STR(dm_dev, dm_dev, name, buf, BUFSIZE);

	fprintf(fp, "  orig_dev:%s", buf);
}

static void
origin_show_status(unsigned long target)
{
	/* snapshot-origin target has no status */
	fprintf(fp, "  No status info");
}

static void
origin_show_queue(unsigned long target)
{
	/* snapshot-origin target has no queue */
	fprintf(fp, "  No queue info");
}

static struct dminfo_target_analyzer snapshot_origin_analyzer = {
	.target_name      = "snapshot-origin",
	.ready            = origin_ready,
	.show_table       = origin_show_table,
	.show_status      = origin_show_status,
	.show_queue       = origin_show_queue
};

/*
 * Core part of dminfo
 */
#define DMINFO_LIST   0
#define DMINFO_DEPS   1
#define DMINFO_TABLE  2
#define DMINFO_STATUS 3
#define DMINFO_QUEUE  4

static int
dm_core_ready(void)
{
	static int debuginfo = 0;

	if (debuginfo)
		return 1;

	if (STRUCT_EXISTS("struct hash_cell")) {
		debuginfo = 1;
		return 1;
	} else
		fprintf(fp, "No such struct info: hash_cell\n");

	return 0;
}

/* Display dependency information of the 'table' */
static void
dminfo_show_deps(unsigned long table)
{
	int major, minor, count;
	unsigned long head, next, last, dev, bdev;
	char buf[BUFSIZE];

	/* head = dm_table.devices */
	GET_ADDR(table, dm_table, devices, head);

	fprintf(fp, "  %-3s  %-3s  %-16s  %-5s  %s\n",
		"MAJ", "MIN", "GENDISK", "COUNT", "DEVNAME");

	list_for_each (next, head, last) {
		/* Get dependency information. (next == struct *dm_dev) */
		GET_VALUE(next, dm_dev, count, count);
		GET_VALUE(next, dm_dev, bdev, bdev);
		GET_VALUE(bdev, block_device, bd_disk, dev);
		GET_VALUE(dev, gendisk, major, major);
		GET_VALUE(dev, gendisk, first_minor, minor);
		GET_STR(dev, gendisk, disk_name, buf, BUFSIZE);

		fprintf(fp, "  %-3d  %-3d  %-16lx  %-5d  %s\n",
			major, minor, dev, count, buf);
	}
}

/*
 * Display target specific information in the 'table', if the target
 * analyzer is registered and available.
 */
static void
dminfo_show_details(unsigned long table, unsigned int num_targets, int info_type)
{
	unsigned int i;
	unsigned long head, target_size, target, target_type;
	struct dminfo_target_analyzer *ta;
	char buf[BUFSIZE];

	/*
	 * head = dm_table.targets.
	 * This is the head of struct dm_target array.
	 */
	GET_VALUE(table, dm_table, targets, head);
	target_size = STRUCT_SIZE("struct dm_target");

	fprintf(fp, "  %-16s  %-11s  %s\n",
		"TARGET", "TARGET_TYPE", "PRIVATE_DATA");

	for (i = 0; i < num_targets; i++, fprintf(fp, "\n")) {
		target = head + target_size * i; /* Get next target */

		/* Get target information */
		GET_VALUE(target, dm_target, type, target_type);
		GET_PTR_STR(target_type, target_type, name, buf, BUFSIZE);

		fprintf(fp, "  %-16lx  %-11s", target, buf);

		if (!(ta = find_target_analyzer(buf)) || !ta->ready
			|| !ta->ready())
			continue;

		switch (info_type) {
		case DMINFO_TABLE:
			if (ta->show_table)
				ta->show_table(target);
			break;
		case DMINFO_STATUS:
			if (ta->show_status)
				ta->show_status(target);
			break;
		case DMINFO_QUEUE:
			if (ta->show_queue)
				ta->show_queue(target);
			break;
		default:
			break;
		}
	}

	if (i != num_targets)
		fprintf(fp, " ERROR: targets are less than num_targets:%d",
			num_targets);
}

/*
 * Display lists (and detail information if specified) of existing
 * dm devices.
 */
static void
dminfo_show_list(int additional_info)
{
	int i, major, minor, array_len;
	unsigned int num_targets;
	unsigned long _name_buckets, head, next, last, md, dev, table;
	char buf[BUFSIZE];

	_name_buckets = symbol_value("_name_buckets");
	array_len = get_array_length("_name_buckets", NULL, 0);

	if (additional_info == DMINFO_LIST)
		fprintf(fp, "%-3s  %-3s  %-16s  %-16s  %-7s  %s\n",
			"MAJ", "MIN", "MAP_DEV", "DM_TABLE",
			"TARGETS", "MAPNAME");

	for (i = 0; i < array_len; i++) {
		/* head = _name_buckets[i] */
		head = _name_buckets + (i * SIZE(list_head));

		list_for_each (next, head, last) { /* next == hash_cell */
			/* Get device and table information */
			GET_PTR_STR(next, hash_cell, name, buf, BUFSIZE);
			GET_VALUE(next, hash_cell, md, md);
			GET_VALUE(md, mapped_device, disk, dev);
			GET_VALUE(dev, gendisk, major, major);
			GET_VALUE(dev, gendisk, first_minor, minor);
			GET_VALUE(md, mapped_device, map, table);
			GET_VALUE(table, dm_table, num_targets, num_targets);

			if (additional_info != DMINFO_LIST)
				fprintf(fp, "%-3s  %-3s  %-16s  %-16s  %-7s  %s\n",
					"MAJ", "MIN", "MAP_DEV", "DM_TABLE",
					"TARGETS", "MAPNAME");

			fprintf(fp, "%-3d  %-3d  %-16lx  %-16lx  %-7d  %s\n",
				major, minor, md, table, num_targets, buf);

			switch(additional_info) {
			case DMINFO_DEPS:
				dminfo_show_deps(table);
				break;
			case DMINFO_TABLE:
			case DMINFO_STATUS:
			case DMINFO_QUEUE:
				dminfo_show_details(table, num_targets,
					additional_info);
				break;
			default:
				break;
			}

			if (additional_info != DMINFO_LIST)
				fprintf(fp, "\n");
		}
	}
}

/*
 * Display the original bio information for the 'bio'.
 * If the 'bio' is for dm devices, the original bio information is pointed
 * by bio.bi_private as struct target_io.
 */
static void
dminfo_show_bio(unsigned long bio)
{
	int major, minor;
	unsigned long target_io, dm_io, dm_bio, md, dev;
	char buf[BUFSIZE];

	/* Get original bio and device information */
	GET_VALUE(bio, bio, bi_private, target_io);
	GET_VALUE(target_io, target_io, io, dm_io);
	GET_VALUE(dm_io, dm_io, bio, dm_bio);
	GET_VALUE(dm_io, dm_io, md, md);
	GET_VALUE(md, mapped_device, disk, dev);
	GET_VALUE(dev, gendisk, major, major);
	GET_VALUE(dev, gendisk, first_minor, minor);
	GET_STR(dev, gendisk, disk_name, buf, BUFSIZE);

	fprintf(fp, "%-16s  %-3s  %-3s  %-16s  %s\n",
		"DM_BIO_ADDRESS", "MAJ", "MIN", "MAP_DEV", "DEVNAME");
	fprintf(fp, "%-16lx  %-3d  %-3d  %-16lx  %s\n",
		dm_bio, major, minor, md, buf);
}

static void
cmd_dminfo(void)
{
	int c, additional_info = DMINFO_LIST;
	unsigned long bio;

	if (!dm_core_ready())
		return;

	/* Parse command line option */
	while ((c = getopt(argcnt, args, "b:dlqst")) != EOF) {
		switch(c)
		{
		case 'b':
			bio = stol(optarg, FAULT_ON_ERROR, NULL);
			dminfo_show_bio(bio);
			return;
		case 'd':
			additional_info = DMINFO_DEPS;
			break;
		case 'l':
			additional_info = DMINFO_LIST;
			break;
		case 'q':
			additional_info = DMINFO_QUEUE;
			break;
		case 's':
			additional_info = DMINFO_STATUS;
			break;
		case 't':
			additional_info = DMINFO_TABLE;
			break;
		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	dminfo_show_list(additional_info);
}

/*
 * dminfo help
 */
static char *help_dminfo[] = {
	"dminfo",				/* command name */
	"device mapper (dm) information",	/* short description */
	"[-b bio | -d | -l | -q | -s | -t]",	/* argument synopsis */
	"  This command displays information about device-mapper mapped ",
        "  devices (dm devices).",
        "  If no argument is entered, displays lists of existing dm devices.",
        "  It's same as -l option.",
	"",
	"    -b bio  displays the information of the dm device which the bio",
	"            is submitted in.  If the bio isn't for dm devices,",
	"            results will be error.",
	"        -d  displays dependency information for existing dm devices.",
	"        -l  displays lists of existing dm devices.",
	"        -q  displays queued I/O information for each target of",
	"            existing dm devices.",
	"        -s  displays status information for each target of existing",
	"            dm devices.",
	"        -t  displays table information for each target of existing",
	"            dm devices.",
	"",
	"EXAMPLE",
	"  Display lists of dm devices.  \"MAP_DEV\" is the address of the",
	"  struct mapped_device.  \"DM_TABLE\" is the address of the struct",
	"  dm_table.  \"TARGETS\" is the number of targets which are in",
	"  the struct dm_table.",
	"",
	"    %s> dminfo",
	"    MAJ  MIN  MAP_DEV           DM_TABLE          TARGETS  MAPNAME",
	"    253  8    c4866c80          c4866280          1        vg0-snap0",
	"    253  6    f6a04a80          f6a04580          1        vg0-lv0-real",
	"    253  0    c4840380          c4841880          1        mp0",
	"    253  5    f7c50c80          c488e480          1        via_cbeheddbdd",
	"    253  7    c4866a80          c4866380          1        vg0-snap0-cow",
	"    253  4    d441e280          c919ed80          1        dummy1",
	"    253  3    f5dc4280          cba81d80          1        dummy0",
	"    253  2    f7c53180          c4866180          1        vg0-lv0",
	"    253  1    f746d280          f746cd80          1        mp0p1",
	"",
	"  Display the dm device information which the bio is submitted in.",
	"  The bio (ceacee80) is a clone of the bio (ceacee00) which is",
	"  submitted in the dm-3 (dummy0).  And the bio (ceacee00) is a clone",
	"  of the bio (ceaced80) which is submitted in the dm-4 (dummy1), too.",
	"  The bio (ceaced80) is the original bio.",
	"",
	"    %s> dminfo -b ceacee80",
	"    DM_BIO_ADDRESS    MAJ  MIN  MAP_DEV           DEVNAME",
	"    ceacee00          253  3    f5dc4280          dm-3",
	"    crash> dminfo -b ceacee00",
	"    DM_BIO_ADDRESS    MAJ  MIN  MAP_DEV           DEVNAME",
	"    ceaced80          253  4    d441e280          dm-4",
	"    crash> dminfo -b ceaced80",
	"    dminfo: invalid kernel virtual address: 64  type: \"GET_VALUE: dm_io.bio\"",
	"",
	"  Display dependency information for each target.",
	"  The vg0-snap0 depends on thd dm-6 (vg0-lv0-real) and the dm-7",
	"  (vg0-snap0-cow)",
	"",
	"    %s> dminfo -d",
	"    MAJ  MIN  MAP_DEV           DM_TABLE          TARGETS  MAPNAME",
	"    253  8    c4866c80          c4866280          1        vg0-snap0",
	"      MAJ  MIN  GENDISK           COUNT  DEVNAME",
	"      253  7    c4866980          1      dm-7",
	"      253  6    f6a04280          1      dm-6",
	"",
	"    MAJ  MIN  MAP_DEV           DM_TABLE          TARGETS  MAPNAME",
	"    253  6    f6a04a80          f6a04580          1        vg0-lv0-real",
	"      MAJ  MIN  GENDISK           COUNT  DEVNAME",
	"      8    0    f7f24c80          1      sda",
	"",
	"    MAJ  MIN  MAP_DEV           DM_TABLE          TARGETS  MAPNAME",
	"    253  7    c4866a80          c4866380          1        vg0-snap0-cow",
	"      MAJ  MIN  GENDISK           COUNT  DEVNAME",
	"      8    0    f7f24c80          1      sda",
	"",
	"    MAJ  MIN  MAP_DEV           DM_TABLE          TARGETS  MAPNAME",
	"    253  2    f7c53180          c4866180          1        vg0-lv0",
	"      MAJ  MIN  GENDISK           COUNT  DEVNAME",
	"      253  6    f6a04280          1      dm-6",
	"",
	"  Display queued I/O information for each target.",
	"  The information is displayed under the \"PRIVATE_DATA\" column.",
	"",
	"    %s> dminfo -q",
	"    MAJ  MIN  MAP_DEV           DM_TABLE          TARGETS  MAPNAME",
	"    253  5    f7c50c80          c488e480          1        via_cbeheddbdd",
	"      TARGET            TARGET_TYPE  PRIVATE_DATA",
	"      f8961080          mirror       (reads) (writes) (quiesced) (recovered)",
	"",
	"      --------------------------------------------------------------",
	"       \"reads/writes\" are members of the struct mirror_set, and",
	"       \"quiesced/recovered\" are members of the struct region_hash.",
	"       If the list is empty, the member is bracketed by \"()\".",
	"      --------------------------------------------------------------",
	"",
	"    MAJ  MIN  MAP_DEV           DM_TABLE          TARGETS  MAPNAME",
	"    253  0    c4840380          c4841880          1        mp0",
	"      TARGET            TARGET_TYPE  PRIVATE_DATA",
	"      f8802080          multipath    queue_size:0",
	"",
	"    MAJ  MIN  MAP_DEV           DM_TABLE          TARGETS  MAPNAME",
	"    253  1    f746d280          f746cd80          1        mp0p1",
	"      TARGET            TARGET_TYPE  PRIVATE_DATA",
	"      f8821080          linear       No queue info",
	"",
	"  Display status information for each target.",
	"  The information is displayed under the \"PRIVATE_DATA\" column.",
	"",
	"    %s> dminfo -s",
	"    MAJ  MIN  MAP_DEV           DM_TABLE          TARGETS  MAPNAME",
	"    253  0    c4840380          c4841880          1        mp0",
	"      TARGET            TARGET_TYPE  PRIVATE_DATA",
	"      f8802080          multipath    queue_if_no_path:0 hwh:none nr_pgs:1",
	"        PG  PG_STATUS  NR_PATHS  PATHS",
	"        1   active     2         8:16(A,0) 8:32(A,0)",
	"",
	"      --------------------------------------------------------------",
	"       Format of \"PATHS\": <major>:<minor>(<status>,<fail_count>)",
	"         Status: A:active, F:faulty",
	"         Fail_count: the value of the struct pgpath.fail_count",
	"      --------------------------------------------------------------",
	"",
	"    MAJ  MIN  MAP_DEV           DM_TABLE          TARGETS  MAPNAME",
	"    253  5    f7c50c80          c488e480          1        via_cbeheddbdd",
	"      TARGET            TARGET_TYPE  PRIVATE_DATA",
	"      f8961080          mirror       in_sync:1 dev:8:16(A,0),8:32(A,0)",
	"",
	"      --------------------------------------------------------------",
	"       Format of \"dev\": <major>:<minor>(<status>,<error_count>)",
	"         Status: A:active, D:degraded",
	"         Error_count: the value of the struct mirror.error_count",
	"      --------------------------------------------------------------",
	"",
	"    MAJ  MIN  MAP_DEV           DM_TABLE          TARGETS  MAPNAME",
	"    253  1    f746d280          f746cd80          1        mp0p1",
	"      TARGET            TARGET_TYPE  PRIVATE_DATA",
	"      f8821080          linear       No status info",
	"",
	"  Display table information for each target.",
	"  The information is displayed under the \"PRIVATE_DATA\" column.",
	"",
	"    %s> dminfo -t",
	"    MAJ  MIN  MAP_DEV           DM_TABLE          TARGETS  MAPNAME",
	"    253  8    c4866c80          c4866280          1        vg0-snap0",
	"      TARGET            TARGET_TYPE  PRIVATE_DATA",
	"      f89b4080          snapshot     orig:253:6 cow:253:7 type:P chunk_size:16",
	"",
	"    MAJ  MIN  MAP_DEV           DM_TABLE          TARGETS  MAPNAME",
	"    253  6    f6a04a80          f6a04580          1        vg0-lv0-real",
	"      TARGET            TARGET_TYPE  PRIVATE_DATA",
	"      f890f080          linear       begin:0 len:204800 dev:8:5 offset:384",
	"",
	"    MAJ  MIN  MAP_DEV           DM_TABLE          TARGETS  MAPNAME",
	"    253  0    c4840380          c4841880          1        mp0",
	"      TARGET            TARGET_TYPE  PRIVATE_DATA",
	"      f8802080          multipath    queue_if_no_path:0 hwh:none nr_pgs:1",
	"        PG  PATH_SELECTOR  NR_PATHS  PATHS",
	"        1   round-robin    2         8:16 8:32",
	"",
	"    MAJ  MIN  MAP_DEV           DM_TABLE          TARGETS  MAPNAME",
	"    253  5    f7c50c80          c488e480          1        via_cbeheddbdd",
	"      TARGET            TARGET_TYPE  PRIVATE_DATA",
	"      f8961080          mirror       log:core dev:8:16(0),8:32(0)",
	"",
	"      --------------------------------------------------------------",
	"       Format of \"dev\": <major>:<minor>(<offset>)",
	"         Offset: the value of the struct mirror.offset",
	"      --------------------------------------------------------------",
	"",
	"    MAJ  MIN  MAP_DEV           DM_TABLE          TARGETS  MAPNAME",
	"    253  7    c4866a80          c4866380          1        vg0-snap0-cow",
	"      TARGET            TARGET_TYPE  PRIVATE_DATA",
	"      f899d080          linear       begin:0 len:8192 dev:8:5 offset:205184",
	"",
	"    MAJ  MIN  MAP_DEV           DM_TABLE          TARGETS  MAPNAME",
	"    253  2    f7c53180          c4866180          1        vg0-lv0",
	"      TARGET            TARGET_TYPE  PRIVATE_DATA",
	"      f8bbc080          snapshot-origin  orig_dev:253:6",
	"",
	"    MAJ  MIN  MAP_DEV           DM_TABLE          TARGETS  MAPNAME",
	"    253  1    f746d280          f746cd80          1        mp0p1",
	"      TARGET            TARGET_TYPE  PRIVATE_DATA",
	"      f8821080          linear       begin:0 len:2040192 dev:253:0 offset:63",
	NULL
};

/*
 * Registering command extension
 */

static struct command_table_entry command_table[] = {
	{"dminfo", cmd_dminfo, help_dminfo, 0},
	{NULL, NULL, NULL, 0},
};

void __attribute__((constructor))
dminfo_init(void)
{
	register_extension(command_table);

	dminfo_register_target_analyzer(&zero_analyzer);
	dminfo_register_target_analyzer(&error_analyzer);
	dminfo_register_target_analyzer(&linear_analyzer);
	dminfo_register_target_analyzer(&mirror_analyzer);
	dminfo_register_target_analyzer(&multipath_analyzer);
	dminfo_register_target_analyzer(&crypt_analyzer);
	dminfo_register_target_analyzer(&stripe_analyzer);
	dminfo_register_target_analyzer(&snapshot_analyzer);
	dminfo_register_target_analyzer(&snapshot_origin_analyzer);
}

void __attribute__((destructor))
dminfo_fini(void)
{
}
