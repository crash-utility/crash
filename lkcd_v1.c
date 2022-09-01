/* lkcd_v1.c - core analysis suite
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
 */

#define LKCD_COMMON
#include "defs.h"
#define CONFIG_VMDUMP
#include "lkcd_vmdump_v1.h"

static dump_header_t dump_header_v1 = { 0 };
static dump_page_t dump_page = { 0 };

/*
 *  Verify and initialize the LKCD environment, storing the common data
 *  in the global lkcd_environment structure.
 */
int
lkcd_dump_init_v1(FILE *fp, int fd)
{
	int i; 
	int eof;
	uint32_t pgcnt;
	dump_header_t *dh;
	dump_page_t *dp;

	lkcd->fd = fd;
	lkcd->fp = fp;

	lseek(lkcd->fd, 0, SEEK_SET);

	dh = &dump_header_v1;
	dp = &dump_page;

	if (read(lkcd->fd, dh, sizeof(dump_header_t)) !=
	    sizeof(dump_header_t))
		return FALSE;

        lkcd->dump_header = dh;
        lkcd->dump_page = dp;
	if (lkcd->debug) 
		dump_lkcd_environment(LKCD_DUMP_HEADER_ONLY);

        /*
         *  Allocate and clear the benchmark offsets, one per megabyte.
         */
        lkcd->page_size = dh->dh_page_size;
	lkcd->page_shift = ffs(lkcd->page_size) - 1;
	lkcd->bits = sizeof(long) * 8;
	lkcd->total_pages = dh->dh_num_pages;
        lkcd->benchmark_pages = (dh->dh_num_pages/LKCD_PAGES_PER_MEGABYTE())+1;
	lkcd->page_header_size = sizeof(dump_page_t);

	lkcd->zone_shift = ffs(ZONE_SIZE) - 1;
	lkcd->zone_mask = ~(ZONE_SIZE - 1);
	lkcd->num_zones = 0;
	lkcd->max_zones = 0;

	lkcd->get_dp_flags = get_dp_flags_v1;
	lkcd->get_dp_address = get_dp_address_v1;
	lkcd->get_dp_size = get_dp_size_v1;
	lkcd->compression = LKCD_DUMP_COMPRESS_RLE;

        lseek(lkcd->fd, LKCD_OFFSET_TO_FIRST_PAGE, SEEK_SET);

	for (pgcnt = 0, eof = FALSE; !eof; pgcnt++) {

		switch (lkcd_load_dump_page_header(dp, pgcnt))
		{
		case LKCD_DUMPFILE_OK:
		case LKCD_DUMPFILE_END:
			break;

		case LKCD_DUMPFILE_EOF:
			eof = TRUE;
			continue;
		}

		if (!(dp->dp_flags & (DUMP_COMPRESSED|DUMP_RAW|DUMP_END))) {
			lkcd_print("unknown page flag in dump: %lx\n",
				dp->dp_flags);
		}

		if (dp->dp_size > 4096) {
			lkcd_print("dp_size > 4096: %d\n", dp->dp_size);
			dump_lkcd_environment(LKCD_DUMP_PAGE_ONLY);
		}

		if (dp->dp_flags & DUMP_END) {
			lkcd_print("found DUMP_END\n");
			break;
		}

        	lseek(lkcd->fd, dp->dp_size, SEEK_CUR);

		if (!LKCD_DEBUG(1))
			break;
	}

        /*
         *  Allocate space for LKCD_CACHED_PAGES data pages plus one to
         *  contain a copy of the compressed data of the current page.
         */
	if ((lkcd->page_cache_buf = (char *)malloc
	    (dh->dh_page_size * (LKCD_CACHED_PAGES))) == NULL)
		return FALSE;

        /*
         *  Clear the page data areas.
         */
        lkcd_free_memory();
	for (i = 0; i < LKCD_CACHED_PAGES; i++) {
		lkcd->page_cache_hdr[i].pg_bufptr = 
			&lkcd->page_cache_buf[i * dh->dh_page_size];
	}

	if ((lkcd->compressed_page = (char *)malloc(dh->dh_page_size)) == NULL)
                return FALSE;

	if ((lkcd->page_hash = (struct page_hash_entry *)calloc
	    	(LKCD_PAGE_HASH, sizeof(struct page_hash_entry))) == NULL)
		return FALSE;

	lkcd->total_pages = eof || (pgcnt > dh->dh_num_pages) ? 
		pgcnt : dh->dh_num_pages;
	lkcd->panic_task = (ulong)dh->dh_current_task;
	lkcd->panic_string = (char *)&dh->dh_panic_string[0];
	if (!fp) 
		lkcd->flags |= LKCD_REMOTE;
	lkcd->flags |= LKCD_VALID;

	return TRUE;
}

/*
 *  Return the current page's dp_size.   
 */
uint32_t 
get_dp_size_v1(void)
{
        dump_page_t *dp;

        dp = (dump_page_t *)lkcd->dump_page;

	return(dp->dp_size);
}

/*
 *  Return the current page's dp_flags. 
 */
uint32_t
get_dp_flags_v1(void)
{
        dump_page_t *dp;

        dp = (dump_page_t *)lkcd->dump_page;

        return(dp->dp_flags);
}

/*
 *  Return the current page's dp_address.
 */
uint64_t
get_dp_address_v1(void)
{
        dump_page_t *dp;

        dp = (dump_page_t *)lkcd->dump_page;

        return(dp->dp_address);
}

/*
 *  console-only output for info regarding current page.
 */
void
dump_dump_page_v1(char *s, void *dpp)
{
        dump_page_t *dp;
        uint32_t flags;
        int others;

        console(s);

        dp = (dump_page_t *)dpp;
        others = 0;

        console("dp_address: %llx  ", dp->dp_address);
        console("dp_size: %ld  ", dp->dp_size);
        console("dp_flags: %lx  (", flags = dp->dp_flags);

        if (flags & DUMP_COMPRESSED)
                console("DUMP_COMPRESSED", others++);
        if (flags & DUMP_RAW)
                console("%sDUMP_RAW", others++ ? "|" : "");
        if (flags & DUMP_END)
                console("DUMP_END", others++ ? "|" : "");
        console(")\n");
}

/*
 *  help -S output, or as specified by arg.
 */
void
dump_lkcd_environment_v1(ulong arg)
{
	int others;
        dump_header_t *dh;
        dump_page_t *dp;

        dh = (dump_header_t *)lkcd->dump_header;
        dp = (dump_page_t *)lkcd->dump_page;

	if (arg == LKCD_DUMP_HEADER_ONLY)
		goto dump_header_only;
	if (arg == LKCD_DUMP_PAGE_ONLY)
		goto dump_page_only;

dump_header_only:

	lkcd_print("     dump_header:\n");
        lkcd_print(" dh_magic_number: %llx  ",
                        dh->dh_magic_number);
	if (dh->dh_magic_number == DUMP_MAGIC_NUMBER)
		lkcd_print("(DUMP_MAGIC_NUMBER)\n");
	else
		lkcd_print("(?)\n");
        lkcd_print("      dh_version: %d\n", dh->dh_version);
        lkcd_print("  dh_header_size: %d\n", dh->dh_header_size);
        lkcd_print("   dh_dump_level: %d\n", dh->dh_dump_level);
        lkcd_print("    dh_page_size: %d\n", dh->dh_page_size);
        lkcd_print("  dh_memory_size: %lld\n", dh->dh_memory_size);
        lkcd_print(" dh_memory_start: %llx\n", dh->dh_memory_start);
        lkcd_print("   dh_memory_end: %llx\n", dh->dh_memory_end);
       	lkcd_print("          dh_esp: %lx\n", dh->dh_esp);
        lkcd_print("          dh_eip: %lx\n", dh->dh_eip);
	lkcd_print("    dh_num_pages: %d\n", dh->dh_num_pages);
        lkcd_print(" dh_panic_string: %s%s", dh->dh_panic_string,
		dh && strstr(dh->dh_panic_string, "\n") ? "" : "\n");
        lkcd_print("         dh_time: %s\n",
                        strip_linefeeds(ctime(&(dh->dh_time.tv_sec))));

	lkcd_print("      dh_utsname:\n");
	lkcd_print("         sysname: %s\n", dh->dh_utsname.sysname);
	lkcd_print("        nodename: %s\n", dh->dh_utsname.nodename);
	lkcd_print("         release: %s\n", dh->dh_utsname.release);
	lkcd_print("         version: %s\n", dh->dh_utsname.version);
	lkcd_print("         machine: %s\n", dh->dh_utsname.machine);
	lkcd_print("      domainname: %s\n", dh->dh_utsname.domainname);

        lkcd_print(" dh_current_task: %lx\n", dh->dh_current_task);

	lkcd_print("         dh_regs:\n");
#ifdef PPC
	lkcd_print("             (PowerPC register display TBD)\n");
#endif
#ifdef X86
	lkcd_print("             ebx: %lx\n", dh->dh_regs.ebx);
	lkcd_print("             ecx: %lx\n", dh->dh_regs.ecx);
	lkcd_print("             edx: %lx\n", dh->dh_regs.edx);
	lkcd_print("             esi: %lx\n", dh->dh_regs.esi);
	lkcd_print("             edi: %lx\n", dh->dh_regs.edi);
	lkcd_print("             eax: %lx\n", dh->dh_regs.eax);
	lkcd_print("             xds: %x\n", dh->dh_regs.xds);
	lkcd_print("             xes: %x\n", dh->dh_regs.xes);
	lkcd_print("        orig_eax: %lx\n", dh->dh_regs.orig_eax);
	lkcd_print("             eip: %lx\n", dh->dh_regs.eip);
	lkcd_print("             xcs: %x\n", dh->dh_regs.xcs);
	lkcd_print("          eflags: %lx\n", dh->dh_regs.eflags);
	lkcd_print("             esp: %lx\n", dh->dh_regs.esp);
	lkcd_print("             xss: %x\n", dh->dh_regs.xss);
#endif

        if (arg == LKCD_DUMP_HEADER_ONLY)
                return;

dump_page_only:

	lkcd_print("       dump_page:\n");
        lkcd_print("      dp_address: %llx\n", dp->dp_address);
        lkcd_print("         dp_size: %ld\n", dp->dp_size);
        lkcd_print("        dp_flags: %lx  (", dp->dp_flags);
	others = 0;
        if (dp->dp_flags & DUMP_COMPRESSED)
                lkcd_print("DUMP_COMPRESSED", others++);
        if (dp->dp_flags & DUMP_RAW)
                lkcd_print("%sDUMP_RAW", others++ ? "|" : "");
        if (dp->dp_flags & DUMP_END)
                lkcd_print("DUMP_END", others++ ? "|" : "");
        lkcd_print(")\n");
}
