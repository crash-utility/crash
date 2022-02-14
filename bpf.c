/* bpf.c - core analysis suite
 *
 * Copyright (C) 2018 David Anderson
 * Copyright (C) 2018 Red Hat, Inc. All rights reserved.
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

struct bpf_info {
	ulong status;
	ulong progs, maps;
	struct list_pair *proglist;
	struct list_pair *maplist;
	char *bpf_prog_buf;
	char *bpf_prog_aux_buf;
	char *bpf_map_buf;
	char *bytecode_buf;
	int bpf_prog_type_size;
	int bpf_map_map_type_size;
	int idr_type;
#define IDR_ORIG   (1)
#define IDR_RADIX  (2)
#define IDR_XARRAY (3)
	char prog_hdr1[81];
	char map_hdr1[81];
} bpf_info = { 
	.status = UNINITIALIZED,
};

static void do_bpf(ulong, ulong, ulong, int);
static void bpf_init(struct bpf_info *);
static int bpf_type_size_init(void);
static char *bpf_prog_type_string(int, char *);
static char *bpf_map_map_type_string(int, char *);
static char *bpf_prog_used_maps(int, char *);
static char *bpf_prog_tag_string(char *, char *);
static void bpf_prog_gpl_compatible(char *, ulong);

static void dump_xlated_plain(void *, unsigned int, int);
static void print_boot_time(unsigned long long, char *, unsigned int);

static int do_old_idr(int, ulong, struct list_pair *);
#define IDR_ORIG_INIT   (1)
#define IDR_ORIG_COUNT  (2)
#define IDR_ORIG_GATHER (3)

#define PROG_ID        (0x1)
#define MAP_ID         (0x2)
#define DUMP_STRUCT    (0x4)
#define JITED          (0x8)
#define XLATED        (0x10)
#define OPCODES       (0x20)
#define PROG_VERBOSE  (0x40)
#define MAP_VERBOSE   (0x80)

static int map_is_per_cpu(int type)
{

/* See the definition of bpf_map_type: include/uapi/linux/bpf.h */
#define BPF_MAP_TYPE_PERCPU_HASH (5UL)
#define BPF_MAP_TYPE_PERCPU_ARRAY (6UL)
#define BPF_MAP_TYPE_LRU_PERCPU_HASH (10UL)
#define BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE (21UL)

	return type == BPF_MAP_TYPE_PERCPU_HASH ||
	       type == BPF_MAP_TYPE_PERCPU_ARRAY ||
	       type == BPF_MAP_TYPE_LRU_PERCPU_HASH ||
	       type == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE;
}

static int map_is_fd_map(int type)
{

/* See the definition of bpf_map_type: include/uapi/linux/bpf.h */
#define BPF_MAP_TYPE_PROG_ARRAY (3UL)
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY (4UL)
#define BPF_MAP_TYPE_CGROUP_ARRAY (8UL)
#define BPF_MAP_TYPE_ARRAY_OF_MAPS (12UL)
#define BPF_MAP_TYPE_HASH_OF_MAPS (13UL)

	return type == BPF_MAP_TYPE_PROG_ARRAY ||
	       type == BPF_MAP_TYPE_PERF_EVENT_ARRAY ||
	       type == BPF_MAP_TYPE_CGROUP_ARRAY ||
	       type == BPF_MAP_TYPE_ARRAY_OF_MAPS ||
	       type == BPF_MAP_TYPE_HASH_OF_MAPS;

}

static ulong bpf_map_memory_size(int map_type, uint value_size,
				uint key_size, uint max_entries)
{
	ulong size;
	uint valsize;
	int cpus = 0;

	if (map_is_per_cpu(map_type)) {
		cpus = get_cpus_possible();
		if (!cpus) {
			error(WARNING, "cpu_possible_map does not exist, possible cpus: %d\n", cpus);
			return 0;
		}

		valsize = roundup(value_size, 8) * cpus;
	} else if (map_is_fd_map(map_type))
		valsize = sizeof(uint);
	else
		valsize = value_size;

	size = roundup((key_size + valsize), 8);

	return roundup((max_entries * size), PAGESIZE());
}

void
cmd_bpf(void)
{
	int c, radix;
	ulong flags, prog_id, map_id;

	flags = prog_id = map_id = radix = 0;

	while ((c = getopt(argcnt, args, "PMtTjsxdm:p:")) != EOF) {
		switch(c)
		{
		case 'j':
			flags |= JITED;
			break;
		case 'T':
			flags |= (XLATED|OPCODES);
			break;
		case 't':
			flags |= XLATED;
			break;
		case 'm':
			map_id = stol(optarg, FAULT_ON_ERROR, NULL);
			flags |= MAP_ID;
			break;
		case 'p':	
			prog_id = stol(optarg, FAULT_ON_ERROR, NULL);
			flags |= PROG_ID;
			break;
		case 's':
			flags |= DUMP_STRUCT;
			break;
		case 'P':
			flags |= PROG_VERBOSE;
			break;
		case 'M':
			flags |= MAP_VERBOSE;
			break;
		case 'x':
			if (radix == 10)
				error(FATAL, "-d and -x are mutually exclusive\n");
			radix = 16;
			break;
		case 'd':
			if (radix == 16)
				error(FATAL, "-d and -x are mutually exclusive\n");
			radix = 16;
			break;
		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	if ((flags & JITED) && !(flags & (PROG_ID|PROG_VERBOSE)))
		error(FATAL, "-j option only applicable with -p or -P\n");
	if ((flags & XLATED) && !(flags & (PROG_ID|PROG_VERBOSE)))
		error(FATAL, "-t option only applicable with -p or -P\n");
	if ((flags & DUMP_STRUCT) && !(flags & (PROG_ID|PROG_VERBOSE|MAP_ID|MAP_VERBOSE)))
		error(FATAL, "-s option requires either -p, -P, -m or -M\n");

	if (radix && !(flags & (PROG_ID|PROG_VERBOSE|MAP_ID|MAP_VERBOSE)))
		error(FATAL, "-%c option requires -s\n", radix == 10 ? 'd' : 'x');

	while (args[optind]) {
		error(FATAL, "invalid argument: %s\n", args[optind]);
		optind++;
	}

	do_bpf(flags, prog_id, map_id, radix);
}

static void
bpf_init(struct bpf_info *bpf)
{
	long len;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];

	switch (bpf->status)
	{
	case UNINITIALIZED:
		if (!kernel_symbol_exists("prog_idr") || 
		    !kernel_symbol_exists("map_idr")) {
			bpf->status = FALSE;
			command_not_supported();
		}
		
		STRUCT_SIZE_INIT(bpf_prog, "bpf_prog");
		STRUCT_SIZE_INIT(bpf_prog_aux, "bpf_prog_aux");
		STRUCT_SIZE_INIT(bpf_map, "bpf_map");
		STRUCT_SIZE_INIT(bpf_insn, "bpf_insn");
		MEMBER_OFFSET_INIT(bpf_prog_aux, "bpf_prog", "aux");
		MEMBER_OFFSET_INIT(bpf_prog_type, "bpf_prog", "type");
		MEMBER_OFFSET_INIT(bpf_prog_tag, "bpf_prog", "tag");
		MEMBER_OFFSET_INIT(bpf_prog_jited_len, "bpf_prog", "jited_len");
		MEMBER_OFFSET_INIT(bpf_prog_bpf_func, "bpf_prog", "bpf_func");
		MEMBER_OFFSET_INIT(bpf_prog_len, "bpf_prog", "len");
		MEMBER_OFFSET_INIT(bpf_prog_insnsi, "bpf_prog", "insnsi");
		MEMBER_OFFSET_INIT(bpf_map_map_type, "bpf_map", "map_type");
		MEMBER_OFFSET_INIT(bpf_map_map_flags, "bpf_map", "map_flags");
		MEMBER_OFFSET_INIT(bpf_prog_aux_used_maps, "bpf_prog_aux", "used_maps");
		MEMBER_OFFSET_INIT(bpf_prog_aux_used_map_cnt, "bpf_prog_aux", "used_map_cnt");
		if (!VALID_STRUCT(bpf_prog) || 
		    !VALID_STRUCT(bpf_prog_aux) ||
		    !VALID_STRUCT(bpf_map) ||
		    !VALID_STRUCT(bpf_insn) ||
		    INVALID_MEMBER(bpf_prog_aux) ||
		    INVALID_MEMBER(bpf_prog_type) ||
		    INVALID_MEMBER(bpf_prog_tag) ||
		    INVALID_MEMBER(bpf_prog_jited_len) ||
		    INVALID_MEMBER(bpf_prog_bpf_func) ||
		    INVALID_MEMBER(bpf_prog_len) ||
		    INVALID_MEMBER(bpf_prog_insnsi) ||
		    INVALID_MEMBER(bpf_map_map_flags) ||
		    INVALID_MEMBER(bpf_map_map_type) ||
		    INVALID_MEMBER(bpf_prog_aux_used_maps) ||
		    INVALID_MEMBER(bpf_prog_aux_used_map_cnt)) {
			bpf->status = FALSE;
			command_not_supported();
		}	
		/*
		 *  Not required for basic functionality
		 */
		MEMBER_OFFSET_INIT(bpf_prog_pages, "bpf_prog", "pages");
		MEMBER_OFFSET_INIT(bpf_prog_aux_load_time, "bpf_prog_aux", "load_time");
		MEMBER_OFFSET_INIT(bpf_prog_aux_user, "bpf_prog_aux", "user");
		MEMBER_OFFSET_INIT(bpf_prog_aux_name, "bpf_prog_aux", "name");
		MEMBER_OFFSET_INIT(bpf_map_key_size, "bpf_map", "key_size");
		MEMBER_OFFSET_INIT(bpf_map_value_size, "bpf_map", "value_size");
		MEMBER_OFFSET_INIT(bpf_map_max_entries, "bpf_map", "max_entries");
		MEMBER_OFFSET_INIT(bpf_map_pages, "bpf_map", "pages");
		MEMBER_OFFSET_INIT(bpf_map_name, "bpf_map", "name");
		MEMBER_OFFSET_INIT(bpf_map_user, "bpf_map", "user");
		MEMBER_OFFSET_INIT(user_struct_uid, "user_struct", "uid");

		/* Linux 5.3 */
		MEMBER_OFFSET_INIT(bpf_map_memory, "bpf_map", "memory");
		if (VALID_MEMBER(bpf_map_memory)) {
			MEMBER_OFFSET_INIT(bpf_map_memory_pages, "bpf_map_memory", "pages");
			MEMBER_OFFSET_INIT(bpf_map_memory_user, "bpf_map_memory", "user");
		}

		if (!bpf_type_size_init()) {
			bpf->status = FALSE;
			command_not_supported();
		}
		sprintf(bpf->prog_hdr1, "%s %s %s %s ",
			mkstring(buf1, 4, CENTER|LJUST, "ID"),
			mkstring(buf2, VADDR_PRLEN, CENTER|LJUST, "BPF_PROG"),
			mkstring(buf3, VADDR_PRLEN, CENTER|LJUST, "BPF_PROG_AUX"),
			mkstring(buf4, bpf->bpf_prog_type_size, CENTER|LJUST, "BPF_PROG_TYPE"));
		strcat(bpf->prog_hdr1, "      TAG        USED_MAPS");
		sprintf(bpf->map_hdr1, "%s %s %s MAP_FLAGS",
			mkstring(buf1, 4, CENTER|LJUST, "ID"),
			mkstring(buf2, VADDR_PRLEN, CENTER|LJUST, "BPF_MAP"),
			mkstring(buf3, bpf->bpf_map_map_type_size, CENTER|LJUST, "BPF_MAP_TYPE"));

		if (INVALID_MEMBER(idr_idr_rt)) {
			bpf->idr_type = IDR_ORIG;
			do_old_idr(IDR_ORIG_INIT, 0, NULL);
		} else if (STREQ(MEMBER_TYPE_NAME("idr", "idr_rt"), "radix_tree_root"))
			if (MEMBER_EXISTS("radix_tree_root", "rnode"))
				bpf->idr_type = IDR_RADIX;
			else if (MEMBER_EXISTS("radix_tree_root", "xa_head"))
				bpf->idr_type = IDR_XARRAY;
			else
				error(FATAL, "cannot determine IDR list type\n");
		else if (STREQ(MEMBER_TYPE_NAME("idr", "idr_rt"), "xarray"))
			bpf->idr_type = IDR_XARRAY;
		else
			error(FATAL, "cannot determine IDR list type\n");

		bpf->status = TRUE;
		break;

	case TRUE:
		break;

	case FALSE:
		command_not_supported();
	}

	switch (bpf->idr_type)
	{
	case IDR_ORIG:
		bpf->progs = do_old_idr(IDR_ORIG_COUNT, symbol_value("prog_idr"), NULL);
		break;
	case IDR_RADIX:
		bpf->progs = do_radix_tree(symbol_value("prog_idr") + OFFSET(idr_idr_rt),
			RADIX_TREE_COUNT, NULL);
		break;
	case IDR_XARRAY:
		bpf->progs = do_xarray(symbol_value("prog_idr") + OFFSET(idr_idr_rt),
			XARRAY_COUNT, NULL);
		break;
	}

	if (bpf->progs) {
		len = sizeof(struct list_pair) * (bpf->progs+1);
		bpf->proglist = (struct list_pair *)GETBUF(len);
		bpf->proglist[0].index = bpf->progs;

		switch (bpf->idr_type)
		{
		case IDR_ORIG:
			bpf->progs = do_old_idr(IDR_ORIG_GATHER, symbol_value("prog_idr"), bpf->proglist);
			break;
		case IDR_RADIX:
			bpf->progs = do_radix_tree(symbol_value("prog_idr") + OFFSET(idr_idr_rt),
				RADIX_TREE_GATHER, bpf->proglist);
			break;
		case IDR_XARRAY:
			bpf->progs = do_xarray(symbol_value("prog_idr") + OFFSET(idr_idr_rt),
				XARRAY_GATHER, bpf->proglist);
			break;
		}
	}

	switch (bpf->idr_type)
	{
	case IDR_ORIG:
		bpf->maps = do_old_idr(IDR_ORIG_COUNT, symbol_value("map_idr"), NULL);
		break;
	case IDR_RADIX:
		bpf->maps = do_radix_tree(symbol_value("map_idr") + OFFSET(idr_idr_rt), 
			RADIX_TREE_COUNT, NULL);
		break;
	case IDR_XARRAY:
		bpf->maps = do_xarray(symbol_value("map_idr") + OFFSET(idr_idr_rt), 
			XARRAY_COUNT, NULL);
		break;
	}

	if (bpf->maps) {
		len = sizeof(struct list_pair) * (bpf->maps+1);
		bpf->maplist = (struct list_pair *)GETBUF(len);
		bpf->maplist[0].index = bpf->maps;

		switch (bpf->idr_type)
		{
		case IDR_ORIG:
			bpf->maps = do_old_idr(IDR_ORIG_GATHER, symbol_value("map_idr"), bpf->maplist);
			break;
		case IDR_RADIX:
			bpf->maps = do_radix_tree(symbol_value("map_idr") + OFFSET(idr_idr_rt),
				RADIX_TREE_GATHER, bpf->maplist);
			break;
		case IDR_XARRAY:
			bpf->maps = do_xarray(symbol_value("map_idr") + OFFSET(idr_idr_rt),
				XARRAY_GATHER, bpf->maplist);
			break;
		}
	}

	bpf->bpf_prog_buf = GETBUF(SIZE(bpf_prog));
	bpf->bpf_prog_aux_buf = GETBUF(SIZE(bpf_prog_aux));
	bpf->bpf_map_buf = GETBUF(SIZE(bpf_map));
}

static void
do_bpf(ulong flags, ulong prog_id, ulong map_id, int radix)
{
	struct bpf_info *bpf;
	int i, c, found, entries, type;
	uint uid, map_pages, key_size = 0, value_size = 0, max_entries = 0;
	ulong bpf_prog_aux, bpf_func, end_func, addr, insnsi, user;
	ulong do_progs, do_maps;
	ulonglong load_time;
	char *symbol;
	ushort prog_pages;
	int jited_len, len;
	char *arglist[MAXARGS];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char buf5[BUFSIZE/2];
	
	bpf = &bpf_info;
	bpf->proglist = NULL;
	bpf->maplist = NULL;
	bpf->bpf_prog_buf = bpf->bpf_prog_aux_buf = bpf->bpf_map_buf = NULL;
	bpf->bytecode_buf = NULL;

	bpf_init(bpf);

	if (flags & PROG_ID) {
		for (i = found = 0; i < bpf->progs; i++) {
			if (prog_id == bpf->proglist[i].index) {
				found++;
				break;
			}
		}
		if (!found) {
			error(INFO, "invalid program ID: %ld\n", prog_id);
			goto bailout;
		}
	}

	if (flags & MAP_ID) {
		for (i = found = 0; i < bpf->maps; i++) {
			if (map_id == bpf->maplist[i].index) {
				found++;
				break;
			}
		}
		if (!found) {
			error(INFO, "invalid map ID: %ld\n", map_id);
			goto bailout;
		}
	}

	if (!(flags & (PROG_ID|PROG_VERBOSE|MAP_ID|MAP_VERBOSE)))
		do_progs = do_maps = TRUE;
	else {
		do_progs = do_maps = FALSE;
		if (flags & (PROG_ID|PROG_VERBOSE))
			do_progs = TRUE;
		if (flags & (MAP_ID|MAP_VERBOSE))
			do_maps = TRUE;
	}

	if (!do_progs)
		goto do_map_only;

	for (i = entries = 0; i < bpf->progs; i++) {
		if (bpf->proglist[i].value == 0) 
			continue;

		if (((flags & (PROG_ID|PROG_VERBOSE)) == PROG_ID) && 
		    (prog_id != bpf->proglist[i].index)) 
			continue;

		if (!readmem((ulong)bpf->proglist[i].value, KVADDR, bpf->bpf_prog_buf, 
		    SIZE(bpf_prog), "struct bpf_prog", RETURN_ON_ERROR))
			goto bailout;
		bpf_prog_aux = ULONG(bpf->bpf_prog_buf + OFFSET(bpf_prog_aux));
		if (!readmem(bpf_prog_aux, KVADDR, bpf->bpf_prog_aux_buf, 
		    SIZE(bpf_prog_aux), "struct bpf_prog_aux", RETURN_ON_ERROR))
			goto bailout;

		if (entries && (flags & PROG_VERBOSE))
			fprintf(fp, "\n%s\n", bpf->prog_hdr1);
		if (entries++ == 0)
			fprintf(fp, "%s\n", bpf->prog_hdr1);

		fprintf(fp, "%s %s %s ", 
			mkstring(buf1, 4, CENTER|LJUST|LONG_DEC, MKSTR(bpf->proglist[i].index)),
			mkstring(buf2, VADDR_PRLEN, CENTER|LJUST|LONG_HEX, MKSTR(bpf->proglist[i].value)),
			mkstring(buf3, VADDR_PRLEN, CENTER|LJUST|LONG_HEX, MKSTR(bpf_prog_aux)));
		type = INT(bpf->bpf_prog_buf + OFFSET(bpf_prog_type));
		fprintf(fp, "%s ", 
			mkstring(buf1, bpf->bpf_prog_type_size, CENTER|LJUST, bpf_prog_type_string(type, buf2)));
		fprintf(fp, "%s ", bpf_prog_tag_string(bpf->bpf_prog_buf + OFFSET(bpf_prog_tag), buf1));
		fprintf(fp, "%s ", 
			mkstring(buf1, strlen("USED_MAPS"), CENTER|LJUST, bpf_prog_used_maps(i, buf2)));
		fprintf(fp, "\n");

		if (flags & (PROG_ID|PROG_VERBOSE)) {
			jited_len = UINT(bpf->bpf_prog_buf + OFFSET(bpf_prog_jited_len));
			len = UINT(bpf->bpf_prog_buf + OFFSET(bpf_prog_len));
			len *= SIZE(bpf_insn);
			if (VALID_MEMBER(bpf_prog_pages)) {
				prog_pages = USHORT(bpf->bpf_prog_buf + OFFSET(bpf_prog_pages));
				prog_pages *= PAGESIZE();
			} else
				prog_pages = 0;

			fprintf(fp, "     XLATED: %d  JITED: %d  MEMLOCK: ", len, jited_len);
			if (VALID_MEMBER(bpf_prog_pages)) {
				fprintf(fp, "%d\n", prog_pages);
			} else
				fprintf(fp, "(unknown)\n");

			fprintf(fp, "     LOAD_TIME: ");
			if (VALID_MEMBER(bpf_prog_aux_load_time)) {
				load_time = ULONGLONG(bpf->bpf_prog_aux_buf + OFFSET(bpf_prog_aux_load_time));
				print_boot_time(load_time, buf5, BUFSIZE/2);
				fprintf(fp, "%s\n", buf5);
			} else
				fprintf(fp, "(unknown)\n");

			bpf_prog_gpl_compatible(buf1, (ulong)bpf->proglist[i].value);
			fprintf(fp, "     GPL_COMPATIBLE: %s", buf1);

			fprintf(fp, "  NAME: ");
			if (VALID_MEMBER(bpf_prog_aux_name)) {
				BCOPY(&bpf->bpf_prog_aux_buf[OFFSET(bpf_prog_aux_name)], buf1, 16);
				buf1[16] = NULLCHAR;
				if (strlen(buf1))
					fprintf(fp, "\"%s\"", buf1);
				else
					fprintf(fp, "(unused)");
			} else
				fprintf(fp, "(unknown)");

			fprintf(fp, "  UID: ");
			if (VALID_MEMBER(bpf_prog_aux_user) && VALID_MEMBER(user_struct_uid)) {
				user = ULONG(bpf->bpf_prog_aux_buf + OFFSET(bpf_prog_aux_user));
				if (readmem(user + OFFSET(user_struct_uid), KVADDR, &uid, sizeof(uint), 
				    "user_struct.uid", QUIET|RETURN_ON_ERROR))
					fprintf(fp, "%d\n", uid);
				else
					fprintf(fp, "(unknown)\n");
			} else
				fprintf(fp, "(unknown)\n");
		}

		if (flags & JITED) {
			fprintf(fp, "\n");
			jited_len = UINT(bpf->bpf_prog_buf + OFFSET(bpf_prog_jited_len));
			bpf_func = ULONG(bpf->bpf_prog_buf + OFFSET(bpf_prog_bpf_func));
			end_func = bpf_func + jited_len;

			if (jited_len) {
				open_tmpfile();
				pc->curcmd_private = (ulonglong)end_func;
				sprintf(buf1, "x/%di 0x%lx", jited_len, bpf_func);
				gdb_pass_through(buf1, NULL, GNU_RETURN_ON_ERROR);
				rewind(pc->tmpfile);
				while (fgets(buf1, BUFSIZE, pc->tmpfile)) {
					strcpy(buf2, strip_linefeeds(buf1));
					c = parse_line(buf1, arglist);
					if (STRNEQ(arglist[0], "0x") && 
					    (LASTCHAR(arglist[0]) == ':')) {
						addr = htol(strip_ending_char(arglist[0], ':'), 
							RETURN_ON_ERROR, NULL);
						if (addr >= end_func)
							break;
					}
					symbol = NULL;
					if ((c > 1) && IS_A_NUMBER(arglist[c-1])) {
						addr = htol(arglist[c-1], RETURN_ON_ERROR, NULL);
						symbol = value_to_symstr(addr, buf3, radix); 
						if (strlen(symbol)) {
							sprintf(buf4, "<%s>", symbol);
							symbol = buf4;
						}
					}
					fprintf(pc->saved_fp, "%s %s\n", buf2, symbol ? symbol : "");
				}
				pc->curcmd_private = 0;
				close_tmpfile();
			} else
				fprintf(fp, "(program not jited)\n");
		}

		if (flags & XLATED) {
			fprintf(fp, "\n");
			len = UINT(bpf->bpf_prog_buf + OFFSET(bpf_prog_len));
			insnsi = (ulong)bpf->proglist[i].value + OFFSET(bpf_prog_insnsi);
			bpf->bytecode_buf = GETBUF(len * SIZE(bpf_insn));
			if (CRASHDEBUG(1))
				fprintf(fp, "bytecode_buf: [%lx] len %d * size %ld = %ld  from: %lx\n", 
					(ulong)bpf->bytecode_buf,
					len, SIZE(bpf_insn), len * SIZE(bpf_insn), insnsi);
			if (!readmem(insnsi, KVADDR, bpf->bytecode_buf, len * SIZE(bpf_insn), 
			    "bpf_prog.insnsi contents", RETURN_ON_ERROR))
				goto bailout;
			dump_xlated_plain((void *)bpf->bytecode_buf, len * SIZE(bpf_insn), flags & OPCODES);
		}

		if (flags & DUMP_STRUCT) {
			fprintf(fp, "\n");
			dump_struct("bpf_prog", (ulong)bpf->proglist[i].value, radix);
			fprintf(fp, "\n");
			dump_struct("bpf_prog_aux", bpf_prog_aux, radix);
		}
	}

	if (!do_maps)
		goto bailout;
	else
		fprintf(fp, "\n");

do_map_only:

	for (i = entries = 0; i < bpf->maps; i++) {
		if (bpf->maplist[i].value == 0) 
			continue;

		if (((flags & (MAP_ID|MAP_VERBOSE)) == MAP_ID) && 
		    (map_id != bpf->maplist[i].index))
			continue;

		if (entries && (flags & MAP_VERBOSE))
			fprintf(fp, "\n%s\n", bpf->map_hdr1);
		if (entries++ == 0)
			fprintf(fp, "%s\n", bpf->map_hdr1);

		if (!readmem((ulong)bpf->maplist[i].value, KVADDR, bpf->bpf_map_buf, 
		    SIZE(bpf_map), "struct bpf_map", RETURN_ON_ERROR))
			goto bailout;

		fprintf(fp, "%s %s ", 
			mkstring(buf1, 4, CENTER|LJUST|LONG_DEC, MKSTR(bpf->maplist[i].index)),
			mkstring(buf2, VADDR_PRLEN, CENTER|LJUST|LONG_HEX, MKSTR(bpf->maplist[i].value)));
		type = INT(bpf->bpf_map_buf + OFFSET(bpf_map_map_type));
		fprintf(fp, "%s ", 
			mkstring(buf1, bpf->bpf_map_map_type_size, CENTER|LJUST, bpf_map_map_type_string(type, buf2)));
		fprintf(fp, " %08x ", UINT(bpf->bpf_map_buf + OFFSET(bpf_map_map_flags)));
		fprintf(fp, "\n");

		if (flags & (MAP_ID|MAP_VERBOSE)) {
			ulong msize = 0;

			fprintf(fp, "     KEY_SIZE: ");
			if (VALID_MEMBER(bpf_map_key_size)) {
				key_size = UINT(bpf->bpf_map_buf + OFFSET(bpf_map_key_size));
				fprintf(fp, "%d", key_size);
			} else
				fprintf(fp, "(unknown)");

			fprintf(fp, "  VALUE_SIZE: ");
			if (VALID_MEMBER(bpf_map_value_size)) {
				value_size = UINT(bpf->bpf_map_buf + OFFSET(bpf_map_value_size));
				fprintf(fp, "%d", value_size);
			} else
				fprintf(fp, "(unknown)");

			fprintf(fp, "  MAX_ENTRIES: ");
			if (VALID_MEMBER(bpf_map_max_entries)) {
				max_entries = UINT(bpf->bpf_map_buf + OFFSET(bpf_map_max_entries));
				fprintf(fp, "%d", max_entries);

			} else
				fprintf(fp, "(unknown)");

			fprintf(fp, "  MEMLOCK: ");
			if (VALID_MEMBER(bpf_map_memory) && VALID_MEMBER(bpf_map_memory_pages)) {
				map_pages = UINT(bpf->bpf_map_buf + OFFSET(bpf_map_memory)
						+ OFFSET(bpf_map_memory_pages));
				fprintf(fp, "%d\n", map_pages * PAGESIZE());
			} else if (VALID_MEMBER(bpf_map_pages)) {
				map_pages = UINT(bpf->bpf_map_buf + OFFSET(bpf_map_pages));
				fprintf(fp, "%d\n", map_pages * PAGESIZE());
			} else if ((msize = bpf_map_memory_size(type, value_size, key_size, max_entries)))
				fprintf(fp, "%ld\n", msize);
			else
				fprintf(fp, "(unknown)");

			fprintf(fp, "     NAME: ");
			if (VALID_MEMBER(bpf_map_name)) {
				BCOPY(&bpf->bpf_map_buf[OFFSET(bpf_map_name)], buf1, 16);
				buf1[17] = NULLCHAR;
				if (strlen(buf1))
					fprintf(fp, "\"%s\"", buf1);
				else
					fprintf(fp, "(unused)");
			} else
				fprintf(fp, "(unknown)\n");

			fprintf(fp, "  UID: ");
			if (VALID_MEMBER(bpf_map_memory) && VALID_MEMBER(bpf_map_memory_user))
				user = ULONG(bpf->bpf_map_buf + OFFSET(bpf_map_memory)
						+ OFFSET(bpf_map_memory_user));
			else if (VALID_MEMBER(bpf_map_user))
				user = ULONG(bpf->bpf_map_buf + OFFSET(bpf_map_user));
			else
				user = 0;

			if (user && VALID_MEMBER(user_struct_uid)) {
				if (readmem(user + OFFSET(user_struct_uid), KVADDR, &uid, sizeof(uint), 
				    "user_struct.uid", QUIET|RETURN_ON_ERROR))
					fprintf(fp, "%d\n", uid);
				else
					fprintf(fp, "(unknown)\n");
			} else
				fprintf(fp, "(unused)\n");
		}

		if (flags & DUMP_STRUCT) {
			fprintf(fp, "\n");
			dump_struct("bpf_map", (ulong)bpf->maplist[i].value, radix);
		}

	}

bailout:
	if (bpf->proglist)
		FREEBUF(bpf->proglist);
	if (bpf->maplist)
		FREEBUF(bpf->maplist);
	FREEBUF(bpf->bpf_prog_buf);
	FREEBUF(bpf->bpf_prog_aux_buf);
	FREEBUF(bpf->bpf_map_buf);
	if (bpf->bytecode_buf)
		FREEBUF(bpf->bytecode_buf);
}

static int 
bpf_type_size_init(void)
{
	int c ATTRIBUTE_UNUSED; 
	size_t max;
	char *arglist[MAXARGS];
	char buf[BUFSIZE];
	struct bpf_info *bpf = &bpf_info;

	open_tmpfile();
	if (dump_enumerator_list("bpf_prog_type")) {
		max = 0;
		rewind(pc->tmpfile);
		while (fgets(buf, BUFSIZE, pc->tmpfile)) {
			if (!strstr(buf, " = "))
				continue;
			c = parse_line(buf, arglist);
			if (CRASHDEBUG(1))
				fprintf(pc->saved_fp, "%s\n", arglist[0]);
			max = MAX(max, strlen(arglist[0]));
		}
		bpf->bpf_prog_type_size = max - strlen("BPF_PROG_TYPE_");
	} else {
		close_tmpfile();
		return FALSE;
	}
	/*
	 * Keep bpf program header at 80 columns
	 */
	bpf->bpf_prog_type_size = MIN(13, bpf->bpf_prog_type_size);
	close_tmpfile();

	open_tmpfile();
	if (dump_enumerator_list("bpf_map_type")) {
		max = 0;
		rewind(pc->tmpfile);
		while (fgets(buf, BUFSIZE, pc->tmpfile)) {
			if (!strstr(buf, " = "))
				continue;
			c = parse_line(buf, arglist);
			if (CRASHDEBUG(1))
				fprintf(pc->saved_fp, "%s\n", arglist[0]);
			max = MAX(max, strlen(arglist[0]));
		}
		bpf->bpf_map_map_type_size = max - strlen("BPF_PROG_TYPE_");
	} else {
		close_tmpfile();
		return FALSE;
	}
	close_tmpfile();

	return TRUE;
}

static char *
bpf_prog_type_string(int type, char *retbuf)
{
	char *p;	
	int c ATTRIBUTE_UNUSED; 
	char *arglist[MAXARGS];
	char buf[BUFSIZE];
	
	retbuf[0] = NULLCHAR;

	open_tmpfile();
	if (dump_enumerator_list("bpf_prog_type")) {
		rewind(pc->tmpfile);
		while (fgets(buf, BUFSIZE, pc->tmpfile)) {
			if (!strstr(buf, " = "))
				continue;
			c = parse_line(buf, arglist);
			if (atoi(arglist[2]) == type) {
				p = arglist[0];
				p += strlen("BPF_PROG_TYPE_");
				strcpy(retbuf, p);
				break;
			}
		}
	} 

	close_tmpfile();
	return retbuf;
}

static char *
bpf_map_map_type_string(int map_type, char *retbuf)
{
	char *p;	
	int c ATTRIBUTE_UNUSED; 
	char *arglist[MAXARGS];
	char buf[BUFSIZE];
	
	retbuf[0] = NULLCHAR;

	open_tmpfile();
	if (dump_enumerator_list("bpf_map_type")) {
		rewind(pc->tmpfile);
		while (fgets(buf, BUFSIZE, pc->tmpfile)) {
			if (!strstr(buf, " = "))
				continue;
			c = parse_line(buf, arglist);
			if (atoi(arglist[2]) == map_type) {
				p = arglist[0];
				p += strlen("BPF_MAP_TYPE_");
				strcpy(retbuf, p);
				break;
			}
		}
	} 

	close_tmpfile();
	return retbuf;
}

static char *
bpf_prog_used_maps(int idx, char *retbuf)
{
	int i, m, cnt;
	struct bpf_info *bpf = &bpf_info;
	uint used_map_cnt;
	ulong used_maps, map;

	retbuf[0] = NULLCHAR;

	used_map_cnt = UINT(bpf->bpf_prog_aux_buf + OFFSET(bpf_prog_aux_used_map_cnt));
	used_maps = ULONG(bpf->bpf_prog_aux_buf + OFFSET(bpf_prog_aux_used_maps));

	for (i = cnt = 0; i < used_map_cnt; i++) {
		if (!readmem(used_maps + (sizeof(ulong)*i), KVADDR, &map,
		    sizeof(ulong), "bpf_prog_aux.used_maps", RETURN_ON_ERROR))
			return retbuf;
		for (m = 0; m < bpf->maps; m++) {
			if (map == (ulong)bpf->maplist[m].value) {
				sprintf(&retbuf[strlen(retbuf)], "%s%ld", 
					strlen(retbuf) ? "," : "",
					bpf->maplist[m].index);
			}
		}
	}

	return retbuf;
}

static char *
bpf_prog_tag_string(char *tag, char *buf)
{
	int i;

	buf[0] = NULLCHAR;
	for (i = 0; i < 8; i++)
		sprintf(&buf[strlen(buf)], "%02x", (unsigned char)tag[i]);

	return buf;
}

static void
bpf_prog_gpl_compatible(char *retbuf, ulong bpf_prog)
{
	char buf[BUFSIZE];

	sprintf(retbuf, "(unknown)");

	open_tmpfile();
        sprintf(buf, "p (*(struct bpf_prog *)0x%lx).gpl_compatible", bpf_prog);
	gdb_pass_through(buf, NULL, GNU_RETURN_ON_ERROR);
	rewind(pc->tmpfile);
	while (fgets(buf, BUFSIZE, pc->tmpfile)) {
		if (strstr(buf, " = 1")) {
			sprintf(retbuf, "yes");
			break;
		} else if (strstr(buf, " = 0")) {
			sprintf(retbuf, "no");
			break;
		}
	}
	close_tmpfile();
}


// #include <linux/bpf_common.h>

/*
 *  Taken from: "/usr/include/linux/bpf_common.h"
 */

/*
 *  bpf_common.h
 */

/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __LINUX_BPF_COMMON_H__
#define __LINUX_BPF_COMMON_H__

/* Instruction classes */
#define BPF_CLASS(code) ((code) & 0x07)
#define		BPF_LD		0x00
#define		BPF_LDX		0x01
#define		BPF_ST		0x02
#define		BPF_STX		0x03
#define		BPF_ALU		0x04
#define		BPF_JMP		0x05
#define		BPF_RET		0x06
#define		BPF_MISC        0x07

/* ld/ldx fields */
#define BPF_SIZE(code)  ((code) & 0x18)
#define		BPF_W		0x00 /* 32-bit */
#define		BPF_H		0x08 /* 16-bit */
#define		BPF_B		0x10 /*  8-bit */
/* eBPF		BPF_DW		0x18    64-bit */
#define BPF_MODE(code)  ((code) & 0xe0)
#define		BPF_IMM		0x00
#define		BPF_ABS		0x20
#define		BPF_IND		0x40
#define		BPF_MEM		0x60
#define		BPF_LEN		0x80
#define		BPF_MSH		0xa0

/* alu/jmp fields */
#define BPF_OP(code)    ((code) & 0xf0)
#define		BPF_ADD		0x00
#define		BPF_SUB		0x10
#define		BPF_MUL		0x20
#define		BPF_DIV		0x30
#define		BPF_OR		0x40
#define		BPF_AND		0x50
#define		BPF_LSH		0x60
#define		BPF_RSH		0x70
#define		BPF_NEG		0x80
#define		BPF_MOD		0x90
#define		BPF_XOR		0xa0

#define		BPF_JA		0x00
#define		BPF_JEQ		0x10
#define		BPF_JGT		0x20
#define		BPF_JGE		0x30
#define		BPF_JSET        0x40
#define BPF_SRC(code)   ((code) & 0x08)
#define		BPF_K		0x00
#define		BPF_X		0x08

#ifndef BPF_MAXINSNS
#define BPF_MAXINSNS 4096
#endif

#endif /* __LINUX_BPF_COMMON_H__ */


/*
 *  Taken from: /usr/include/asm-generic/int-ll64.h
 */
typedef unsigned char __u8;
typedef __signed__ short __s16;
typedef __signed__ int __s32;

/*
 *  Taken from: "/usr/include/linux/bpf.h"
 */

/* Extended instruction set based on top of classic BPF */

/* instruction classes */
#define BPF_ALU64	0x07	/* alu mode in double word width */

/* ld/ldx fields */
#define BPF_DW		0x18	/* double word (64-bit) */
#define BPF_XADD	0xc0	/* exclusive add */

/* alu/jmp fields */
#define BPF_MOV		0xb0	/* mov reg to reg */
#define BPF_ARSH	0xc0	/* sign extending arithmetic shift right */

/* change endianness of a register */
#define BPF_END		0xd0	/* flags for endianness conversion: */
#define BPF_TO_LE	0x00	/* convert to little-endian */
#define BPF_TO_BE	0x08	/* convert to big-endian */
#define BPF_FROM_LE	BPF_TO_LE
#define BPF_FROM_BE	BPF_TO_BE

/* jmp encodings */
#define BPF_JNE		0x50	/* jump != */
#define BPF_JLT		0xa0	/* LT is unsigned, '<' */
#define BPF_JLE		0xb0	/* LE is unsigned, '<=' */
#define BPF_JSGT	0x60	/* SGT is signed '>', GT in x86 */
#define BPF_JSGE	0x70	/* SGE is signed '>=', GE in x86 */
#define BPF_JSLT	0xc0	/* SLT is signed, '<' */
#define BPF_JSLE	0xd0	/* SLE is signed, '<=' */
#define BPF_CALL	0x80	/* function call */
#define BPF_EXIT	0x90	/* function return */

/* Register numbers */
enum {
	BPF_REG_0 = 0,
	BPF_REG_1,
	BPF_REG_2,
	BPF_REG_3,
	BPF_REG_4,
	BPF_REG_5,
	BPF_REG_6,
	BPF_REG_7,
	BPF_REG_8,
	BPF_REG_9,
	BPF_REG_10,
	__MAX_BPF_REG,
};

struct bpf_insn {
        __u8    code;           /* opcode */
        __u8    dst_reg:4;      /* dest register */
        __u8    src_reg:4;      /* source register */
        __s16   off;            /* signed offset */
        __s32   imm;            /* signed immediate constant */
};

/* instruction classes */
#define BPF_ALU64       0x07    /* alu mode in double word width */

/* ld/ldx fields */
#define BPF_DW          0x18    /* double word (64-bit) */
#define BPF_XADD        0xc0    /* exclusive add */

/* alu/jmp fields */
#define BPF_MOV         0xb0    /* mov reg to reg */
#define BPF_ARSH        0xc0    /* sign extending arithmetic shift right */

/* change endianness of a register */
#define BPF_END         0xd0    /* flags for endianness conversion: */
#define BPF_TO_LE       0x00    /* convert to little-endian */
#define BPF_TO_BE       0x08    /* convert to big-endian */
#define BPF_FROM_LE     BPF_TO_LE
#define BPF_FROM_BE     BPF_TO_BE

/* when bpf_ldimm64->src_reg == BPF_PSEUDO_MAP_FD, bpf_ldimm64->imm == fd */
#define BPF_PSEUDO_MAP_FD       1

/* when bpf_call->src_reg == BPF_PSEUDO_CALL, bpf_call->imm == pc-relative
 * offset to another bpf function
 */
#define BPF_PSEUDO_CALL         1




static void fprint_hex(FILE *, void *, unsigned int, const char *);

/*
 *  Taken from: tools/bpf/bpftool/main.c
 */
void fprint_hex(FILE *f, void *arg, unsigned int n, const char *sep)
{
	unsigned char *data = arg;
	unsigned int i;

	for (i = 0; i < n; i++) {
		const char *pfx = "";

		if (!i)
			/* nothing */;
		else if (!(i % 16))
			fprintf(f, "\n");
		else if (!(i % 8))
			fprintf(f, "  ");
		else
			pfx = sep;

		fprintf(f, "%s%02hhx", i ? pfx : "", data[i]);
	}
}



static void
dump_bpf_insn(struct bpf_insn *insn)
{
	fprintf(fp, "          code: 0x%x / %d\n", insn->code, insn->code);
	fprintf(fp, "       dst_reg: 0x%x / %d\n", insn->dst_reg, insn->dst_reg);
	fprintf(fp, "       src_reg: 0x%x / %d\n", insn->src_reg, insn->src_reg);
	fprintf(fp, "           off: 0x%x / %d\n", insn->off, insn->off);
	fprintf(fp, "           imm: 0x%x / %d\n", insn->imm, insn->imm);
}

static void print_bpf_insn(struct bpf_insn *, int);

/*
 *  Adapted from: "tools/bpf/bpftool/prog.c"
 */
static void 
dump_xlated_plain(void *buf, unsigned int len, int opcodes)
{
	struct bpf_insn *insn = buf;
	int double_insn = FALSE;
	unsigned int i;

	for (i = 0; i < len / sizeof(*insn); i++) {
		if (double_insn) {
			double_insn = FALSE;
			continue;
		}

		double_insn = insn[i].code == (BPF_LD | BPF_IMM | BPF_DW);

		fprintf(fp, "% 4d: ", i);
		print_bpf_insn(insn + i, TRUE);

		if (opcodes) {
			fprintf(fp, "       ");
			fprint_hex(fp, insn + i, 8, " ");
			if (double_insn && i < len - 1) {
				fprintf(fp, " ");
				fprint_hex(fp, insn + i + 1, 8, " ");
			}
			fprintf(fp, "\n");
		}

		if (CRASHDEBUG(1))
			dump_bpf_insn(insn + i);
	}
}


/*
 *  Adapted from: kernel/bpf/disasm.c
 */

const char *const bpf_class_string[8] = {
	[BPF_LD]    = "ld",
	[BPF_LDX]   = "ldx",
	[BPF_ST]    = "st",
	[BPF_STX]   = "stx",
	[BPF_ALU]   = "alu",
	[BPF_JMP]   = "jmp",
	[BPF_RET]   = "BUG",
	[BPF_ALU64] = "alu64",
};

const char *const bpf_alu_string[16] = {
	[BPF_ADD >> 4]  = "+=",
	[BPF_SUB >> 4]  = "-=",
	[BPF_MUL >> 4]  = "*=",
	[BPF_DIV >> 4]  = "/=",
	[BPF_OR  >> 4]  = "|=",
	[BPF_AND >> 4]  = "&=",
	[BPF_LSH >> 4]  = "<<=",
	[BPF_RSH >> 4]  = ">>=",
	[BPF_NEG >> 4]  = "neg",
	[BPF_MOD >> 4]  = "%=",
	[BPF_XOR >> 4]  = "^=",
	[BPF_MOV >> 4]  = "=",
	[BPF_ARSH >> 4] = "s>>=",
	[BPF_END >> 4]  = "endian",
};

static const char *const bpf_ldst_string[] = {
	[BPF_W >> 3]  = "u32",
	[BPF_H >> 3]  = "u16",
	[BPF_B >> 3]  = "u8",
	[BPF_DW >> 3] = "u64",
};

static const char *const bpf_jmp_string[16] = {
	[BPF_JA >> 4]   = "jmp",
	[BPF_JEQ >> 4]  = "==",
	[BPF_JGT >> 4]  = ">",
	[BPF_JLT >> 4]  = "<",
	[BPF_JGE >> 4]  = ">=",
	[BPF_JLE >> 4]  = "<=",
	[BPF_JSET >> 4] = "&",
	[BPF_JNE >> 4]  = "!=",
	[BPF_JSGT >> 4] = "s>",
	[BPF_JSLT >> 4] = "s<",
	[BPF_JSGE >> 4] = "s>=",
	[BPF_JSLE >> 4] = "s<=",
	[BPF_CALL >> 4] = "call",
	[BPF_EXIT >> 4] = "exit",
};

typedef unsigned char u8;
typedef unsigned int u32;

static const char *__func_imm_name(const struct bpf_insn *insn,
                                   uint64_t full_imm, char *buff, size_t len)
{
	int m;
	struct bpf_info *bpf = &bpf_info;

	for (m = 0; m < bpf->maps; m++) {
		if (full_imm == (ulong)bpf->maplist[m].value) {
			sprintf(buff, "map[id:%ld]", 
				bpf->maplist[m].index);
			if (CRASHDEBUG(1))
				sprintf(&buff[strlen(buff)], " (%lx)",
					(ulong)bpf->maplist[m].value); 
			return buff;
		}
	}

	snprintf(buff, len, "0x%llx", (unsigned long long)full_imm);
	return buff;
}

static char *__func_get_name(const struct bpf_insn *insn,
                                   char *buff, size_t len)
{
	long __BPF_FUNC_MAX_ID;
	char func_id_str[BUFSIZE];
	ulong func_id_ptr;
	struct syment *sp;
	ulong offset;

	if (!enumerator_value("__BPF_FUNC_MAX_ID", &__BPF_FUNC_MAX_ID))
		return buff;

	if (insn->src_reg != BPF_PSEUDO_CALL &&
	    insn->imm >= 0 && insn->imm < __BPF_FUNC_MAX_ID) {
//              return func_id_str[insn->imm];
		if (!readmem(symbol_value("func_id_str") + (insn->imm * sizeof(void *)), 
		    KVADDR, &func_id_ptr, sizeof(void *), "func_id_str pointer", 
		    QUIET|RETURN_ON_ERROR))
			error(FATAL, "cannot read func_id_str[]");
		if (!read_string(func_id_ptr, func_id_str, BUFSIZE-1))
			error(FATAL, "cannot read func_id_str[] string");
		sprintf(buff, "%s", func_id_str);
		return buff;
	}

	if ((insn->src_reg != BPF_PSEUDO_CALL) &&
	    (sp = value_search(symbol_value("__bpf_call_base") + insn->imm, &offset)) && 
	    !offset)
		return(sp->name);

	if (insn->src_reg == BPF_PSEUDO_CALL)
		snprintf(buff, len, "%+d", insn->imm);

	return buff;
}


static void 
print_bpf_insn(struct bpf_insn *insn, int allow_ptr_leaks)
{
	__u8 class = BPF_CLASS(insn->code);

	if (class == BPF_ALU || class == BPF_ALU64) {
		if (BPF_OP(insn->code) == BPF_END) {
			if (class == BPF_ALU64)
				fprintf(fp, "BUG_alu64_%02x\n", insn->code);
			else
//				print_bpf_end_insn(verbose, env, insn);
				fprintf(fp, "(%02x) r%d = %s%d r%d\n", insn->code, insn->dst_reg,
					BPF_SRC(insn->code) == BPF_TO_BE ? "be" : "le",
					insn->imm, insn->dst_reg);

		} else if (BPF_OP(insn->code) == BPF_NEG) {
			fprintf(fp, "(%02x) r%d = %s-r%d\n",
				insn->code, insn->dst_reg,
				class == BPF_ALU ? "(u32) " : "",
				insn->dst_reg);
		} else if (BPF_SRC(insn->code) == BPF_X) {
			fprintf(fp, "(%02x) %sr%d %s %sr%d\n",
				insn->code, class == BPF_ALU ? "(u32) " : "",
				insn->dst_reg,
				bpf_alu_string[BPF_OP(insn->code) >> 4],
				class == BPF_ALU ? "(u32) " : "",
				insn->src_reg);
		} else {
			fprintf(fp, "(%02x) %sr%d %s %s%d\n",
				insn->code, class == BPF_ALU ? "(u32) " : "",
				insn->dst_reg,
				bpf_alu_string[BPF_OP(insn->code) >> 4],
				class == BPF_ALU ? "(u32) " : "",
				insn->imm);
		}
	} else if (class == BPF_STX) {
		if (BPF_MODE(insn->code) == BPF_MEM)
			fprintf(fp, "(%02x) *(%s *)(r%d %+d) = r%d\n",
				insn->code,
				bpf_ldst_string[BPF_SIZE(insn->code) >> 3],
				insn->dst_reg,
				insn->off, insn->src_reg);
		else if (BPF_MODE(insn->code) == BPF_XADD)
			fprintf(fp, "(%02x) lock *(%s *)(r%d %+d) += r%d\n",
				insn->code,
				bpf_ldst_string[BPF_SIZE(insn->code) >> 3],
				insn->dst_reg, insn->off,
				insn->src_reg);
		else
			fprintf(fp, "BUG_%02x\n", insn->code);
	} else if (class == BPF_ST) {
		if (BPF_MODE(insn->code) != BPF_MEM) {
			fprintf(fp, "BUG_st_%02x\n", insn->code);
			return;
		}
		fprintf(fp, "(%02x) *(%s *)(r%d %+d) = %d\n",
			insn->code,
			bpf_ldst_string[BPF_SIZE(insn->code) >> 3],
			insn->dst_reg,
			insn->off, insn->imm);
	} else if (class == BPF_LDX) {
		if (BPF_MODE(insn->code) != BPF_MEM) {
			fprintf(fp, "BUG_ldx_%02x\n", insn->code);
			return;
		}
		fprintf(fp, "(%02x) r%d = *(%s *)(r%d %+d)\n",
			insn->code, insn->dst_reg,
			bpf_ldst_string[BPF_SIZE(insn->code) >> 3],
			insn->src_reg, insn->off);
	} else if (class == BPF_LD) {
		if (BPF_MODE(insn->code) == BPF_ABS) {
			fprintf(fp, "(%02x) r0 = *(%s *)skb[%d]\n",
				insn->code,
				bpf_ldst_string[BPF_SIZE(insn->code) >> 3],
				insn->imm);
		} else if (BPF_MODE(insn->code) == BPF_IND) {
			fprintf(fp, "(%02x) r0 = *(%s *)skb[r%d + %d]\n",
				insn->code,
				bpf_ldst_string[BPF_SIZE(insn->code) >> 3],
				insn->src_reg, insn->imm);
		} else if (BPF_MODE(insn->code) == BPF_IMM &&
			   BPF_SIZE(insn->code) == BPF_DW) {
			/* At this point, we already made sure that the second
			 * part of the ldimm64 insn is accessible.
			 */
			uint64_t imm = ((uint64_t)(insn + 1)->imm << 32) | (u32)insn->imm;
			int map_ptr = insn->src_reg == BPF_PSEUDO_MAP_FD;
			char tmp[64];

			if (map_ptr && !allow_ptr_leaks)
				imm = 0;

			fprintf(fp, "(%02x) r%d = %s\n",
				insn->code, insn->dst_reg,
				__func_imm_name(insn, imm,
						tmp, sizeof(tmp)));
		} else {
			fprintf(fp, "BUG_ld_%02x\n", insn->code);
			return;
		}
	} else if (class == BPF_JMP) {
		u8 opcode = BPF_OP(insn->code);

		if (opcode == BPF_CALL) {
			char tmp[64];

			if (insn->src_reg == BPF_PSEUDO_CALL) {
				fprintf(fp, "(%02x) call pc%s\n",
					insn->code,
					__func_get_name(insn,
							tmp, sizeof(tmp)));
			} else {
				strcpy(tmp, "unknown");
				fprintf(fp, "(%02x) call %s#%d\n", insn->code,
					__func_get_name(insn,
							tmp, sizeof(tmp)),
					insn->imm);
			}
		} else if (insn->code == (BPF_JMP | BPF_JA)) {
			fprintf(fp, "(%02x) goto pc%+d\n",
				insn->code, insn->off);
		} else if (insn->code == (BPF_JMP | BPF_EXIT)) {
			fprintf(fp, "(%02x) exit\n", insn->code);
		} else if (BPF_SRC(insn->code) == BPF_X) {
			fprintf(fp, "(%02x) if r%d %s r%d goto pc%+d\n",
				insn->code, insn->dst_reg,
				bpf_jmp_string[BPF_OP(insn->code) >> 4],
				insn->src_reg, insn->off);
		} else {
			fprintf(fp, "(%02x) if r%d %s 0x%x goto pc%+d\n",
				insn->code, insn->dst_reg,
				bpf_jmp_string[BPF_OP(insn->code) >> 4],
				insn->imm, insn->off);
		}
	} else {
		fprintf(fp, "(%02x) %s\n",
			insn->code, bpf_class_string[class]);
	}
}

static void 
print_boot_time(unsigned long long nsecs, char *buf, unsigned int size)
{
#ifdef CLOCK_BOOTTIME
	struct timespec real_time_ts, boot_time_ts;
	time_t wallclock_secs;
	struct tm load_tm;

	buf[--size] = '\0';

	if (clock_gettime(CLOCK_REALTIME, &real_time_ts) ||
	    clock_gettime(CLOCK_BOOTTIME, &boot_time_ts)) {
		perror("Can't read clocks");
		snprintf(buf, size, "%llu", nsecs / 1000000000);
		return;
	}

	wallclock_secs = (real_time_ts.tv_sec - boot_time_ts.tv_sec) +
		nsecs / 1000000000;

	if (!localtime_r(&wallclock_secs, &load_tm)) {
		snprintf(buf, size, "%llu", nsecs / 1000000000);
		return;
	}

//	strftime(buf, size, "%b %d/%H:%M", &load_tm);
	strftime(buf, size, "%a %b %d %H:%M:%S %Y", &load_tm);
#else
	sprintf(buf, "(unknown)");
#endif
}

/*
 *  Borrow the old (pre-radix_tree) IDR facility code used by
 *  the ipcs command.
 */
static int
do_old_idr(int cmd, ulong idr, struct list_pair *lp)
{
	int i, max, cur, next_id, total = 0;
	ulong entry;

	switch (cmd)
	{
	case IDR_ORIG_INIT:
		ipcs_init();
		break;

	case IDR_ORIG_COUNT:
		readmem(idr + OFFSET(idr_cur), KVADDR, &cur, 
			sizeof(int), "idr.cur", FAULT_ON_ERROR);
		for (total = next_id = 0; next_id < cur; next_id++) {
			entry = idr_find(idr, next_id);
			if (entry == 0)
				continue;
			total++;
		}
		break;

	case IDR_ORIG_GATHER:
		max = lp[0].index;
		readmem(idr + OFFSET(idr_cur), KVADDR, &cur, 
			sizeof(int), "idr.cur", FAULT_ON_ERROR);
		for (i = total = next_id = 0; next_id < cur; next_id++) {
			entry = idr_find(idr, next_id);
			if (entry == 0)
				continue;
			total++;
			lp[i].index = next_id;
			lp[i].value = (void *)entry;
			if (++i == max)
				break;
		}
		break;
	}

	return total;
}
