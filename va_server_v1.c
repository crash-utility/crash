/* va_server_v1.c - kernel crash dump file translation library
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002, 2003, 2004, 2005 David Anderson
 * Copyright (C) 2002, 2003, 2004, 2005 Red Hat, Inc. All rights reserved.
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
 * 11/12/99, Dave Winchell, Preserve V1 interface.
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

struct map_hdr_v1 *vas_map_base_v1 = (struct map_hdr_v1 *)0;     /* base of tree */


#ifdef NOT_DEF
#define trunc_page(x)   ((void *)(((unsigned long)(x)) & ~((unsigned long)(page_size - 1))))
#define round_page(x)   trunc_page(((unsigned long)(x)) + ((unsigned long)(page_size - 1)))
#endif

extern u_long vas_base_va;
extern u_long vas_start_va;
u_long vas_end_va;

void find_data_v1(u_long va, u_long *buf, u_long *len, u_long *offset);
void load_data_v1(struct map_hdr_v1 *hdr, u_long index, u_long *buf, u_long *len);
struct map_hdr_v1 *find_header_v1(u_long va);
u_long vas_find_start_v1(void);
u_long vas_find_end_v1(void);
int read_maps_v1(char *crash_file);
int read_map_v1(int blk_pos);

extern int Page_Size;

extern FILE *vas_file_p;

extern void *malloc(size_t);


int va_server_init_v1(char *crash_file, u_long *start, u_long *end, u_long *stride)
{
	if(read_maps_v1(crash_file))
		return -1;

	vas_base_va = vas_start_va = vas_find_start_v1();
	vas_end_va = vas_find_end_v1();

	if(start)
		*start = vas_start_va;
	if(end)
		*end = vas_end_va;
	if(stride)
		*stride = vas_map_base_v1->va_per_entry;
	return 0;
}

int vas_lseek_v1(u_long position, int whence)
{
	if(whence != SEEK_SET)
		return -1;
	if(position > (vas_end_va - vas_start_va)) {
		printf("position 0x%lx beyond dump range of 0x%lx\n",
		       position, (vas_end_va - vas_start_va));
		return -1;
	}
	vas_base_va = vas_start_va + position;
	return 0;
}
size_t vas_read_v1(void *buf_in, size_t count)
{
	u_long len, offset, buf, va;
	u_long num, output, remaining;


	if(count > (vas_end_va - vas_base_va)) {
		printf("count 0x%lx greater than remaining dump of 0x%lx\n",
		       (ulong)count, (vas_end_va - vas_base_va));
		return -1;
	}
	va = vas_base_va;
	remaining = count;
	output = (u_long)buf_in;

	while(remaining) {
		find_data_v1(va, &buf, &len, &offset);
		num = (remaining > (len - offset)) ? (len - offset) : remaining;
		bcopy((const void *)(buf+offset), (void *)output, num);
		remaining -= num;
		va += num;
		output += num;
	}
	vas_base_va += count;
	return count;
}
size_t vas_write_v1(void *buf_in, size_t count)
{
	u_long len, offset, buf, va;

	if(count != sizeof(u_long)) {
		printf("count %d not %d\n", (int)count, (int)sizeof(u_long));
		return -1;
	}
	va = vas_base_va;
	find_data_v1(va, &buf, &len, &offset);
	*(u_long *)(buf+offset) = *(u_long *)buf_in;

	vas_base_va += count;
	return count;
}


void find_data_v1(u_long va, u_long *buf, u_long *len, u_long *offset)
{
	struct map_hdr_v1 *hdr;
	u_long index, off;

	hdr = find_header_v1(va);
	index = (va - hdr->start_va) / hdr->va_per_entry;
	off = (va - hdr->start_va) % hdr->va_per_entry;
	load_data_v1(hdr, index, buf, len);
	if(offset)
		*offset = off;
}
void vas_free_data_v1(u_long va)
{
	struct map_hdr_v1 *hdr;
	u_long index;

	hdr = find_header_v1(va);
	index = (va - hdr->start_va) / hdr->va_per_entry;

	if(hdr->map[index].exp_data) {
		free((void *)hdr->map[index].exp_data);
		hdr->map[index].exp_data = 0;
	}
}
void load_data_v1(struct map_hdr_v1 *hdr, u_long index, u_long *buf, u_long *len)
{
	char *compr_buf;
	char *exp_buf;
	int ret, items;
	uLongf destLen;

	if(hdr->map[index].exp_data)
		goto out;
	ret = fseek(vas_file_p, (long)((hdr->blk_offset + hdr->map[index].start_blk) * hdr->blk_size),
		    SEEK_SET);

	if(ret == -1) {
		printf("load_data: unable to fseek, errno = %d\n", ferror(vas_file_p));
		clean_exit(1);
	}
	compr_buf =  (char *)malloc(2*hdr->va_per_entry);
	if(!compr_buf) {
		printf("load_data: bad ret from malloc, errno = %d\n", ferror(vas_file_p));
		clean_exit(1);
	}
	items = fread((void *)compr_buf, sizeof(char), hdr->map[index].num_blks * hdr->blk_size, vas_file_p);
	if(items != hdr->map[index].num_blks * hdr->blk_size) {
		printf("unable to read blocks from errno = %d\n", ferror(vas_file_p));
		clean_exit(1);
	}
	hdr->map[index].exp_data = exp_buf =  (char *)malloc(hdr->va_per_entry);
	if(!exp_buf) {
		printf("load_data: bad ret from malloc, errno = %d\n", ferror(vas_file_p));
		clean_exit(1);
	}
	destLen = (uLongf)(2*hdr->va_per_entry);
	ret = uncompress((Bytef *)exp_buf, &destLen, (const Bytef *)compr_buf, (uLong)items);
	/*	if(destLen != hdr->va_per_entry) {
		 printf("uncompress error\n");
		 exit(1);
	}
	*/
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
	if(buf)
		*buf = (u_long)hdr->map[index].exp_data;
	if(len)
		*len = hdr->va_per_entry;
	return;
}

struct map_hdr_v1 *find_header_v1(u_long va)
{
	struct map_hdr_v1 *hdr;
	int found = 0;

	for(hdr = vas_map_base_v1; hdr; hdr = hdr->next)
		if((va >= hdr->start_va) && (va < hdr->end_va)) {
			found = 1;
			break;
		}
	if(found)
		return  hdr;
	else
		return (struct map_hdr_v1 *)0;
}
u_long vas_find_start_v1(void)
{
	struct map_hdr_v1 *hdr;
	u_long start;

	start = vas_map_base_v1->start_va;
	for(hdr = vas_map_base_v1; hdr; hdr = hdr->next)
		if(hdr->start_va < start)
			start = hdr->start_va;

	return start;
}
u_long vas_find_end_v1(void)
{
	struct map_hdr_v1 *hdr;
	u_long end;

	end = vas_map_base_v1->end_va;
	for(hdr = vas_map_base_v1; hdr; hdr = hdr->next)
		if(hdr->end_va > end)
			end = hdr->end_va;

	return end;
}
int read_maps_v1(char *crash_file)
{
	int *cur_entry_p, *cp;
	int ret, items, blk_pos;

	cur_entry_p = (int *)malloc(Page_Size);
	if(!cur_entry_p) {
		printf("read_maps: bad ret from malloc, errno = %d\n", ferror(vas_file_p));
		clean_exit(1);
	}
	bzero((void *)cur_entry_p, Page_Size);

	vas_file_p = fopen(crash_file, "r");
	if(vas_file_p == (FILE *)0) {
		printf("read_maps: bad ret from fopen for %s: %s\n", crash_file, strerror(errno));
		free(cur_entry_p);
		return -1;
	}
	ret = fseek(vas_file_p, (long)0, SEEK_SET);
	if(ret == -1) {
		printf("read_maps: unable to fseek in  %s, errno = %d\n", crash_file, ferror(vas_file_p));
		free(cur_entry_p);
		return -1;
	}	
	items = fread((void *)cur_entry_p, 1, Page_Size, vas_file_p);
	if(items != Page_Size) {
		printf("read_maps: unable to read header from %s, errno = %d\n", crash_file, ferror(vas_file_p));
		free(cur_entry_p);
		return -1;
	}
	ret = -1;
	cp = cur_entry_p;
	while ((blk_pos = *cp++)) {
		if (read_map_v1(blk_pos)) {
			free(cur_entry_p);
			return -1;
		}
		ret = 0;
	}

	free(cur_entry_p);
	return ret;
}




int read_map_v1(int blk_pos)
{
	struct crash_map_hdr_v1 *disk_hdr;
	int ret, items;
	struct map_hdr_v1 *hdr, *hdr1;
	extern int console(char *, ...);

	hdr = (struct map_hdr_v1 *)malloc(sizeof(struct map_hdr_v1));
	if(!hdr) {
		printf("read_map: unable to malloc mem\n");
		return -1;
	}
	bzero((void *)hdr, sizeof(struct map_hdr_v1));
	disk_hdr = (struct crash_map_hdr_v1 *)malloc(Page_Size);
	ret = fseek(vas_file_p, (long)(blk_pos*Page_Size), SEEK_SET);
	if(ret == -1) {
		console("va_server: unable to fseek, err = %d\n", ferror(vas_file_p));
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
		console("va_server: bad magic 0x%lx\n", disk_hdr->magic[0]);
		free(hdr);
		free(disk_hdr);
		return -1;
	}
	ret = fseek(vas_file_p, (long)((blk_pos + disk_hdr->map_block) * disk_hdr->blk_size), SEEK_SET);

	if(ret == -1) {
		printf("va_server: unable to fseek, err = %d\n", ferror(vas_file_p));
		free(hdr);
		free(disk_hdr);
		return -1;
	}

	hdr->map_entries = disk_hdr->map_entries;
	hdr->va_per_entry = disk_hdr->va_per_entry;
	hdr->blk_offset = blk_pos - CRASH_OFFSET_BLKS;
	hdr->blk_size = disk_hdr->blk_size;
	Page_Size = disk_hdr->blk_size;    /* over-ride PAGE_SIZE */

	hdr->map = (struct crash_map_entry_v1 *)malloc(hdr->map_entries *
							 sizeof(struct crash_map_entry_v1));
	items = fread((void *)hdr->map, sizeof(struct crash_map_entry_v1), hdr->map_entries,
		      vas_file_p);
	if(items != hdr->map_entries) {
		printf("unable to read map entries, err = %d\n", errno);
		free(hdr);
		free(disk_hdr);
		return -1;
	}

	hdr->start_va = hdr->map[0].start_va;
	hdr->end_va = hdr->start_va + hdr->map_entries * hdr->va_per_entry;

	if(!vas_map_base_v1) {
		vas_map_base_v1 = hdr;
		hdr->next = (struct map_hdr_v1 *)0;
	}
	else {
		hdr1 = vas_map_base_v1;
		while(hdr1->next)
			hdr1 = hdr1->next;
		hdr1->next = hdr;
		hdr->next = (struct map_hdr_v1 *)0;
	}

	free((void *)disk_hdr);
	return 0;

}




