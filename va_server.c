/* va_server.c - kernel crash dump file translation library
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002-2006, 2011, 2013 David Anderson
 * Copyright (C) 2002-2006, 2011, 2013 Red Hat, Inc. All rights reserved.
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
 *
 * 10/99, Dave Winchell, Initial release for kernel crash dump support.
 * 11/12/99, Dave Winchell, Add support for in memory dumps.
 */
#include <zlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "va_server.h"
#include <errno.h>
#include <sys/mman.h>
#include <signal.h>


struct map_hdr *vas_map_base = (struct map_hdr *)0;     /* base of tree */

#ifdef NOT_DEF
#define trunc_page(x)   ((void *)(((unsigned long)(x)) & ~((unsigned long)(page_size - 1))))
#define round_page(x)   trunc_page(((unsigned long)(x)) + ((unsigned long)(page_size - 1)))
#endif

u_long vas_base_va;
u_long vas_start_va;

FILE *vas_file_p;
char *zero_page;
int vas_version;

int read_map(char *crash_file);
void load_data(struct crash_map_entry *m);
int find_data(u_long va, u_long *buf, u_long *len, u_long *offset);
u_long vas_find_end(void);
int vas_free_memory(char *);
int vas_memory_used(void);
int vas_memory_dump(FILE *);
int mclx_page_size(void);
void set_vas_debug(ulong);

extern int monitor_memory(long *, long *, long *, long *);

int Page_Size;  
ulong vas_debug = 0;

extern void *malloc(size_t);

int va_server_init(char *crash_file, u_long *start, u_long *end, u_long *stride)
{
	Page_Size = getpagesize();  /* temporary setting until disk header is read */

	if(read_map(crash_file)) {
		if(va_server_init_v1(crash_file, start, end, stride))
			return -1;
		vas_version = 1;
		return 0;
	}
	
	vas_version = 2;
	zero_page = (char *)malloc(Page_Size);
	bzero((void *)zero_page, Page_Size);

	vas_base_va = vas_start_va = vas_map_base->map[0].start_va;

	if(start)
		*start = vas_start_va;
	if(end) {
		*end = vas_find_end();
	}
	if(stride)
		*stride = Page_Size;
	return 0;
}

int vas_lseek(u_long position, int whence)
{
	if(vas_version < 2)
		return vas_lseek_v1(position, whence);
	
	if(whence != SEEK_SET)
		return -1;

	vas_base_va = vas_start_va + position;
	return 0;
}

size_t vas_read(void *buf_in, size_t count)
{
	u_long len, offset, buf, va;
	u_long num, output, remaining;

	if(vas_version < 2)
		return vas_read_v1(buf_in, count);

	va = vas_base_va;
	remaining = count;
	output = (u_long)buf_in;

	while(remaining) {
		find_data(va, &buf, &len, &offset);
		num = (remaining > (len - offset)) ? (len - offset) : remaining;
		bcopy((const void *)(buf+offset), (void *)output, num);
		remaining -= num;
		va += num;
		output += num;
	}
	vas_base_va += count;
	return count;
}
size_t vas_write(void *buf_in, size_t count)
{
	u_long len, offset, buf, va;

	if(vas_version < 2)
		return vas_write_v1(buf_in, count);

	if(count != sizeof(u_long)) {
		printf("count %d not %d\n", (int)count, (int)sizeof(u_long));
		return -1;
	}
	va = vas_base_va;
	if(!find_data(va, &buf, &len, &offset))
	   *(u_long *)(buf+offset) = *(u_long *)buf_in;

	vas_base_va += count;
	return count;
}
void vas_free_data(u_long va)
{
	struct crash_map_entry *m, *last_m;

	if(vas_version < 2) {
		vas_free_data_v1(va);
		return;
	}

	m = last_m = vas_map_base->map;
	for(;m->start_va;) {
		if(m->start_va > va)
			break;
		last_m = m;
		m++;
	}
	if(last_m->exp_data) {
		free((void *)last_m->exp_data);
		last_m->exp_data = 0;
	}
}

u_long vas_find_end(void)
{
	struct crash_map_entry *m;
	u_long *sub_m;

	m = vas_map_base->map;
	for(;m->start_va;m++)
		;
	m--;
	load_data(m);
	sub_m = (u_long *)m->exp_data;
	for(;*sub_m; sub_m++)
		;
	sub_m--;
	return *sub_m;
}
int find_data(u_long va, u_long *buf, u_long *len, u_long *offset)
{
	u_long off;
	struct crash_map_entry *m, *last_m;
	u_long *sub_m, va_saved;
	char *data;
	int saved;

	m = last_m = vas_map_base->map;
	for(;m->start_va;) {
		if(m->start_va > va)
			break;
		last_m = m;
		m++;
	}
	load_data(last_m);
	sub_m = (u_long *)last_m->exp_data;
	data = last_m->exp_data + CRASH_SUB_MAP_PAGES*Page_Size;

	saved = 0;
	for(;*sub_m; sub_m++, data += Page_Size) {
		va_saved = *sub_m;
		if((va >= va_saved) && (va < (va_saved + Page_Size))) {
			saved = 1;
			break;
		}
		else if(va < va_saved)
			break;
	}
	off = va - (u_long)trunc_page(va);
	if(offset)
		*offset = off;
	if(len)
		*len = Page_Size;

	if (vas_debug && !saved)
		fprintf(stderr, "find_data: page containing %lx not saved\n", 
			(u_long)trunc_page(va));

	if(buf)
		*buf = saved ? (u_long)data : (u_long)zero_page;
	return (saved ^ 1);
}

void load_data(struct crash_map_entry *m)
{
	char *compr_buf;
	char *exp_buf;
	int ret, items;
	uLongf destLen;
	int retries;

	if(m->exp_data)
		goto out;
	ret = fseek(vas_file_p, (long)(m->start_blk * Page_Size),
		    SEEK_SET);

	if(ret == -1) {
		printf("load_data: unable to fseek, errno = %d\n", ferror(vas_file_p));
		clean_exit(1);
	}

	retries = 0;
load_data_retry1:

	compr_buf =  (char *)malloc(m->num_blks * Page_Size);
	if(!compr_buf) {
		if (retries++ == 0) {
			vas_free_memory("malloc failure: out of memory");
			goto load_data_retry1;
		}
		fprintf(stderr, "FATAL ERROR: malloc failure: out of memory\n");
		clean_exit(1);
	}
	items = fread((void *)compr_buf, sizeof(char), m->num_blks * Page_Size, vas_file_p);
	if(items != m->num_blks * Page_Size) {
		printf("unable to read blocks from errno = %d\n", ferror(vas_file_p));
		clean_exit(1);
	}
load_data_retry2:
	m->exp_data = exp_buf =
	    (char *)malloc((CRASH_SOURCE_PAGES+CRASH_SUB_MAP_PAGES) * Page_Size);
	if(!exp_buf) {
                if (retries++ == 0) {
			vas_free_memory("malloc failure: out of memory");
                        goto load_data_retry2;
                }
                fprintf(stderr, "FATAL ERROR: malloc failure: out of memory\n");
		clean_exit(1);
	}
	destLen = (uLongf)((CRASH_SOURCE_PAGES+CRASH_SUB_MAP_PAGES) * Page_Size);
	ret = uncompress((Bytef *)exp_buf, &destLen, (const Bytef *)compr_buf, (uLong)items);

	if(ret) {
		if(ret == Z_MEM_ERROR)
			printf("load_data, bad ret Z_MEM_ERROR from uncompress\n");
		else if(ret == Z_BUF_ERROR)
			printf("load_data, bad ret Z_BUF_ERROR from uncompress\n");
		else if(ret == Z_DATA_ERROR)
			printf("load_data, bad ret Z_DATA_ERROR from uncompress\n");
		else
			printf("load_data, bad ret %d from uncompress\n", ret);
		
		clean_exit(1);
	}
	free((void *)compr_buf);
  out:
	return;
}


int read_map(char *crash_file)
{
	struct crash_map_hdr *disk_hdr;
	int ret, items;
	struct map_hdr *hdr;

	vas_file_p = fopen(crash_file, "r");
	if(vas_file_p == (FILE *)0) {
		printf("read_maps: bad ret from fopen for %s: %s\n", crash_file, strerror(errno));
		return -1;
	}

	hdr = (struct map_hdr *)malloc(sizeof(struct map_hdr));
	if(!hdr) {
		printf("read_map: unable to malloc mem\n");
		return -1;
	}
	bzero((void *)hdr, sizeof(struct map_hdr));
	disk_hdr = (struct crash_map_hdr *)malloc(Page_Size);
	ret = fseek(vas_file_p, (long)0, SEEK_SET);
	if(ret == -1) {
		printf("va_server: unable to fseek, err = %d\n", ferror(vas_file_p));
		free(hdr);
		free(disk_hdr);
		return -1;
	}
	items = fread((void *)disk_hdr, 1, Page_Size, vas_file_p);
	if(items != Page_Size) {
		free(hdr);
		free(disk_hdr);
		return -1;
	}
	if(disk_hdr->magic[0] != CRASH_MAGIC) {
		free(hdr);
		free(disk_hdr);
		return -1;
	}
	ret = fseek(vas_file_p, (long)((disk_hdr->map_block) * disk_hdr->blk_size), SEEK_SET);

	if(ret == -1) {
		printf("va_server: unable to fseek, err = %d\n", ferror(vas_file_p));
		free(hdr);
		free(disk_hdr);
		return -1;
	}

	Page_Size = disk_hdr->blk_size;       /* over-ride PAGE_SIZE */
	hdr->blk_size = disk_hdr->blk_size;
	hdr->map = (struct crash_map_entry *)malloc(disk_hdr->map_blocks * disk_hdr->blk_size);

	items = fread((void *)hdr->map, hdr->blk_size, disk_hdr->map_blocks,
		      vas_file_p);
	if(items != disk_hdr->map_blocks) {
		printf("unable to read map entries, err = %d\n", errno);
		free(hdr);
		free(disk_hdr);
		return -1;
	}

	vas_map_base = hdr;
	free(disk_hdr);
	return 0;
}


int
vas_free_memory(char *s)
{
        struct crash_map_entry *m;
	long swap_usage;
	int blks;

        if (vas_version < 2) 
                return 0;

	if (s) {
        	fprintf(stderr, "\nWARNING: %s  ", s);

        	if (monitor_memory(NULL, NULL, NULL, &swap_usage))
        		fprintf(stderr, "(swap space usage: %ld%%)", 
				swap_usage);

		fprintf(stderr, 
     "\nWARNING: memory/swap exhaustion may cause this session to be killed\n");
	}

        for (blks = 0, m = vas_map_base->map; m->start_va; m++) {
		if (m->exp_data) {
			free((void *)m->exp_data);
			m->exp_data = 0;
			blks += m->num_blks;
		}
        }

	return blks;
}

int
vas_memory_used(void)
{
        struct crash_map_entry *m;
	int blks;

	if (vas_version < 2) 
		return 0;

        for (blks = 0, m = vas_map_base->map; m->start_va; m++) {
		if (m->exp_data)
			blks += m->num_blks;
        }

	return blks;
}

char *memory_dump_hdr_32 = "START_VA  EXP_DATA  START_BLK  NUM_BLKS\n";
char *memory_dump_fmt_32 = "%8lx  %8lx  %9d  %8d\n";
char *memory_dump_hdr_64 = \
    "    START_VA          EXP_DATA      START_BLK  NUM_BLKS\n";
char *memory_dump_fmt_64 = "%16lx  %16lx  %9d  %8d\n";

int
vas_memory_dump(FILE *fp)
{
        struct crash_map_entry *m;
	char *hdr, *fmt;
	int blks;

	if (vas_version < 2) {
		fprintf(fp, "%s\n", vas_version ? 
			"version 1: not supported" : "no dumpfile");
		return 0;
	}

	hdr = sizeof(long) == 4 ? memory_dump_hdr_32 : memory_dump_hdr_64;
	fmt = sizeof(long) == 4 ? memory_dump_fmt_32 : memory_dump_fmt_64;

	fprintf(fp, "%s", hdr);

        for (blks = 0, m = vas_map_base->map; m->start_va; m++) {
		fprintf(fp, fmt,
			m->start_va, m->exp_data, m->start_blk, m->num_blks); 
		if (m->exp_data)
			blks += m->num_blks;
        }

	fprintf(fp, "total blocks: %d\n", blks);

	return blks;
}

int
mclx_page_size(void)
{
	return (Page_Size);
}

void 
set_vas_debug(ulong value)
{
	vas_debug = value;
}
