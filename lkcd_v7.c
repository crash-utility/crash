/* lkcd_v7.c - core analysis suite
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002 Silicon Graphics, Inc.
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
#include "lkcd_dump_v5.h"				/* REMIND */

static dump_header_t dump_header_v7 = { 0 };
static dump_page_t dump_page = { 0 };
static void mclx_cache_page_headers_v7(void);

/*
 *  Verify and initialize the LKCD environment, storing the common data
 *  in the global lkcd_environment structure.
 */
int
lkcd_dump_init_v7(FILE *fp, int fd, char *dumpfile)
{
	int i; 
	int eof;
	uint32_t pgcnt;
	dump_header_t *dh;
	dump_page_t *dp;
	int dump_index_size ATTRIBUTE_UNUSED;
	int dump_index_created ATTRIBUTE_UNUSED;
	static char dumpfile_index_name[128];
	int ifd ATTRIBUTE_UNUSED;

	lkcd->fd = fd;
	lkcd->fp = fp;
	dump_index_created = 0;

	lseek(lkcd->fd, 0, SEEK_SET);

	dh = &dump_header_v7;
	dp = &dump_page;

	if (read(lkcd->fd, dh, sizeof(dump_header_t)) !=
	    sizeof(dump_header_t))
		return FALSE;


        lkcd->dump_page = dp;
        lkcd->dump_header = dh;
	if (lkcd->debug) 
		dump_lkcd_environment(LKCD_DUMP_HEADER_ONLY);

#ifdef IA64
	if ( (fix_addr_v7(fd) == -1) )
	    return FALSE;
#endif

	/*
	 *  Allocate and clear the benchmark offsets, one per megabyte.
	 */
        lkcd->page_size = dh->dh_page_size;
	lkcd->page_shift = ffs(lkcd->page_size) - 1;
	lkcd->bits = sizeof(long) * 8;
        lkcd->benchmark_pages = (dh->dh_num_pages/LKCD_PAGES_PER_MEGABYTE())+1;
	lkcd->total_pages = dh->dh_num_pages;
	/* 
	 * REMIND: dh_memory_size should be in physical pages and seems to be wrong.
	 *         pad by two for now; 3DFE8 should be 40000.
	 */

	lkcd->memory_pages = dh->dh_memory_size;
	lkcd->page_offsets = 0;
	lkcd->ifd = -1;
	lkcd->dumpfile_index = NULL;

        /* Keep from getting unused warnings */
	dump_index_size = 0; 
	dump_index_created = 0;
	strcpy(dumpfile_index_name, dumpfile);
	ifd = 0;

#ifdef LKCD_INDEX_FILE
        if (dh->dh_memory_end < 0x1000000000LL) {
            lkcd->memory_pages = dh->dh_memory_end / lkcd->page_size + 1;
        } else {
            lkcd->memory_pages = (dh->dh_memory_size * (getpagesize()/lkcd->page_size)) * 2;
        }
	dump_index_size = (lkcd->memory_pages * sizeof(off_t));	
	lkcd->page_offsets = 0;
	strcpy(dumpfile_index_name, dumpfile);
	lkcd->dumpfile_index = strcat(dumpfile_index_name, ".index");
        ifd = open(lkcd->dumpfile_index, O_RDWR, 0644);
	if( ifd < 0 ) {
		int err;

		ifd = open(lkcd->dumpfile_index, (O_RDWR | O_CREAT), 0644);

		if (ifd > 0) {
			err = ftruncate(ifd, dump_index_size);
			if (err == -1) {
				lkcd->dumpfile_index = NULL;
				close(ifd);
				ifd = -1;
			} else {
				dump_index_created++;
			}	
		}
	}
	if (ifd >= 0) {
		/* MAP_SHARED so we can sync the file */
		lkcd->page_offsets = mmap( (void *)0, dump_index_size, (PROT_READ | PROT_WRITE), MAP_SHARED, ifd, (off_t)0);

		if (lkcd->page_offsets == MAP_FAILED) {
			close(ifd);
			ifd = -1;
			lkcd->dumpfile_index = NULL;
			lkcd->page_offsets = 0;
		}
	}
	lkcd->ifd = ifd;
#endif 

	lkcd->zone_shift = ffs(ZONE_SIZE) - 1;
	lkcd->zone_mask = ~(ZONE_SIZE - 1);
	lkcd->num_zones = 0;
	lkcd->max_zones = 0;
	lkcd->zoned_offsets = 0;

	lkcd->get_dp_flags = get_dp_flags_v7;
	lkcd->get_dp_address = get_dp_address_v7;
	lkcd->get_dp_size = get_dp_size_v7;
   	lkcd->compression = dh->dh_dump_compress; 
        lkcd->page_header_size = sizeof(dump_page_t);

        lseek(lkcd->fd, LKCD_OFFSET_TO_FIRST_PAGE, SEEK_SET);

	/*
	 * Read all of the pages and save the page offsets for lkcd_lseek().
	 */
	for (pgcnt = 0, eof = FALSE; !eof; pgcnt++) {

		switch (lkcd_load_dump_page_header(dp, pgcnt))
		{
		case LKCD_DUMPFILE_OK:
		case LKCD_DUMPFILE_END:
			break;
		
		case LKCD_DUMPFILE_EOF:
			lkcd_print("reached EOF\n");
			eof = TRUE;
			continue;
		}

		if (dp->dp_flags & 
              ~(DUMP_DH_COMPRESSED|DUMP_DH_RAW|DUMP_DH_END|LKCD_DUMP_MCLX_V0)) {
			lkcd_print("unknown page flag in dump: %lx\n",
				dp->dp_flags);
		}
		if (dp->dp_flags & (LKCD_DUMP_MCLX_V0|LKCD_DUMP_MCLX_V1))
			lkcd->flags |= LKCD_MCLX;

		if (dp->dp_size > 4096) {
			lkcd_print("dp_size > 4096: %d\n", dp->dp_size);
			dump_lkcd_environment(LKCD_DUMP_PAGE_ONLY);
		}

		if (dp->dp_flags & DUMP_DH_END) {
			lkcd_print("found DUMP_DH_END\n");
			break;
		}

        	lseek(lkcd->fd, dp->dp_size, SEEK_CUR);

		if (!LKCD_DEBUG(2)) 
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

	if (dh->dh_version & LKCD_DUMP_MCLX_V1) 
		mclx_cache_page_headers_v7();

        if (!fp)
                lkcd->flags |= LKCD_REMOTE;
	lkcd->flags |= LKCD_VALID;

	return TRUE;
}


/*
 *  Return the current page's dp_size.
 */
uint32_t 
get_dp_size_v7(void) 
{
        dump_page_t *dp;

        dp = (dump_page_t *)lkcd->dump_page;

        return(dp->dp_size);
}

/*
 *  Return the current page's dp_flags.
 */
uint32_t 
get_dp_flags_v7(void) 
{
        dump_page_t *dp;

        dp = (dump_page_t *)lkcd->dump_page;

        return(dp->dp_flags);
}

/*
 *  Return the current page's dp_address.
 */
uint64_t 
get_dp_address_v7(void)
{
        dump_page_t *dp;

        dp = (dump_page_t *)lkcd->dump_page;

        return(dp->dp_address);
}    

/*
 *  help -S output, or as specified by arg.
 */
void
dump_lkcd_environment_v7(ulong arg)
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
        lkcd_print(" dh_magic_number: ");
	lkcd_print(BITS32() ? "%llx  " : "%lx  ", dh->dh_magic_number);
        if (dh->dh_magic_number == DUMP_MAGIC_NUMBER)
                lkcd_print("(DUMP_MAGIC_NUMBER)\n");
        else if (dh->dh_magic_number == DUMP_MAGIC_LIVE)
                lkcd_print("(DUMP_MAGIC_LIVE)\n");
        else
                lkcd_print("(?)\n");
	others = 0;
	lkcd_print("      dh_version: ");
        lkcd_print(BITS32() ? "%lx (" : "%x (", dh->dh_version);
        switch (dh->dh_version & LKCD_DUMP_VERSION_NUMBER_MASK)
        {
        case LKCD_DUMP_V1:
                lkcd_print("%sLKCD_DUMP_V1", others++ ? "|" : "");
		break;
        case LKCD_DUMP_V2:
                lkcd_print("%sLKCD_DUMP_V2", others++ ? "|" : "");
		break;
        case LKCD_DUMP_V3:
                lkcd_print("%sLKCD_DUMP_V3", others++ ? "|" : "");
		break;
        case LKCD_DUMP_V5:
                lkcd_print("%sLKCD_DUMP_V5", others++ ? "|" : "");
		break;
        case LKCD_DUMP_V7:
                lkcd_print("%sLKCD_DUMP_V7", others++ ? "|" : "");
		break;
        case LKCD_DUMP_V8:
                lkcd_print("%sLKCD_DUMP_V8", others++ ? "|" : "");
		break;
        }
        if (dh->dh_version & LKCD_DUMP_MCLX_V0)
                lkcd_print("%sLKCD_DUMP_MCLX_V0", others++ ? "|" : "");
        if (dh->dh_version & LKCD_DUMP_MCLX_V1)
                lkcd_print("%sLKCD_DUMP_MCLX_V1", others++ ? "|" : "");
        lkcd_print(")\n");
	lkcd_print("  dh_header_size: ");
	lkcd_print(BITS32() ? "%ld\n" : "%d\n", dh->dh_header_size);
        lkcd_print("   dh_dump_level: ");
	lkcd_print(BITS32() ? "%lx  (" : "%x  (", dh->dh_dump_level);
	others = 0;
	if (dh->dh_dump_level & DUMP_LEVEL_HEADER)
                lkcd_print("%sDUMP_LEVEL_HEADER", others++ ? "|" : "");
	if (dh->dh_dump_level & DUMP_LEVEL_KERN)
                lkcd_print("%sDUMP_LEVEL_KERN", others++ ? "|" : "");
	if (dh->dh_dump_level & DUMP_LEVEL_USED)
                lkcd_print("%sDUMP_LEVEL_USED", others++ ? "|" : "");
	if (dh->dh_dump_level & DUMP_LEVEL_ALL)
                lkcd_print("%sDUMP_LEVEL_ALL", others++ ? "|" : "");
	lkcd_print(")\n");
        lkcd_print("    dh_page_size: ");
	lkcd_print(BITS32() ? "%ld\n" : "%d\n", dh->dh_page_size);
        lkcd_print("  dh_memory_size: ");
	lkcd_print(BITS32() ? "%lld\n" : "%ld\n", dh->dh_memory_size);
        lkcd_print(" dh_memory_start: ");
	lkcd_print(BITS32() ? "%llx\n" : "%lx\n", dh->dh_memory_start);
        lkcd_print("   dh_memory_end: ");
	lkcd_print(BITS32() ? "%llx\n" : "%lx\n", dh->dh_memory_end);
	lkcd_print("    dh_num_pages: ");
	lkcd_print(BITS32() ? "%ld\n" : "%d\n", dh->dh_num_pages);
        lkcd_print(" dh_panic_string: %s%s", dh->dh_panic_string,
		dh && strstr(dh->dh_panic_string, "\n") ? "" : "\n");
        lkcd_print("         dh_time: %s\n",
                        strip_linefeeds(ctime(&(dh->dh_time.tv_sec))));

	lkcd_print("dh_utsname_sysname: %s\n", dh->dh_utsname_sysname);
	lkcd_print("dh_utsname_nodename: %s\n", dh->dh_utsname_nodename);
	lkcd_print("dh_utsname_release: %s\n", dh->dh_utsname_release);
	lkcd_print("dh_utsname_version: %s\n", dh->dh_utsname_version);
	lkcd_print("dh_utsname_machine: %s\n", dh->dh_utsname_machine);
	lkcd_print("dh_utsname_domainname: %s\n", dh->dh_utsname_domainname);

        lkcd_print(" dh_current_task: %lx\n", dh->dh_current_task);

        lkcd_print(" dh_dump_compress: ");
	lkcd_print(BITS32() ? "%lx  (" : "%x  (", dh->dh_dump_compress);
	others = 0;
	if (dh->dh_dump_compress == DUMP_COMPRESS_NONE)
                lkcd_print("%sDUMP_COMPRESS_NONE", others++ ? "|" : "");
	if (dh->dh_dump_compress & DUMP_COMPRESS_RLE)
                lkcd_print("%sDUMP_COMPRESS_RLE", others++ ? "|" : "");
	if (dh->dh_dump_compress & DUMP_COMPRESS_GZIP)
                lkcd_print("%sDUMP_COMPRESS_GZIP", others++ ? "|" : "");
	lkcd_print(")\n");

        lkcd_print(" dh_dump_flags: ");
	others = 0;
	lkcd_print(BITS32() ? "%lx  (" : "%x  (", dh->dh_dump_flags);
	if (dh->dh_dump_flags & DUMP_FLAGS_NONDISRUPT)
                lkcd_print("%sDUMP_FLAGS_NONDISRUPT", others++ ? "|" : "");
	lkcd_print(")\n");

        lkcd_print(" dh_dump_device: ");
	lkcd_print(BITS32() ? "%lx\n" : "%x\n", dh->dh_dump_device);

        if (arg == LKCD_DUMP_HEADER_ONLY)
                return;

dump_page_only:

	lkcd_print("       dump_page:\n");
        lkcd_print("      dp_address: ");
	lkcd_print(BITS32() ? "%llx\n" : "%lx\n", dp->dp_address);
        lkcd_print("         dp_size: ");
	lkcd_print(BITS32() ? "%ld\n" : "%d\n", dp->dp_size);
        lkcd_print("        dp_flags: ");
	lkcd_print(BITS32() ? "%lx  (" : "%x  (", dp->dp_flags);

	others = 0;
        if (dp->dp_flags & DUMP_DH_COMPRESSED)
                lkcd_print("DUMP_DH_COMPRESSED", others++);
        if (dp->dp_flags & DUMP_DH_RAW)
                lkcd_print("%sDUMP_DH_RAW", others++ ? "|" : "");
        if (dp->dp_flags & DUMP_DH_END)
                lkcd_print("%sDUMP_DH_END", others++ ? "|" : "");
        if (dp->dp_flags & LKCD_DUMP_MCLX_V0)
                lkcd_print("%sLKCD_DUMP_MCLX_V0", others++ ? "|" : "");
        lkcd_print(")\n");
}

void
dump_dump_page_v7(char *s, void *dpp)
{
        dump_page_t *dp;
        uint32_t flags;
        int others;
 
        console(s);
 
        dp = (dump_page_t *)dpp;
        others = 0;

        console(BITS32() ? "dp_address: %llx " : "dp_address: %lx ",
                dp->dp_address);
        console("dp_size: %ld ", dp->dp_size);
        console("dp_flags: %lx (", flags = dp->dp_flags);

        if (flags & DUMP_DH_COMPRESSED)
                console("DUMP_DH_COMPRESSED", others++);
        if (flags & DUMP_DH_RAW)
                console("%sDUMP_DH_RAW", others++ ? "|" : "");
        if (flags & DUMP_DH_END)
                console("%sDUMP_DH_END", others++ ? "|" : "");
        if (flags & LKCD_DUMP_MCLX_V0)
                console("%sLKCD_DUMP_MCLX_V0", others++ ? "|" : "");
        console(")\n");
}


/*
 *  Read the MCLX-enhanced page header cache.  Verify the first one, which
 *  is a pointer to the page header for address 1MB, and take the rest at 
 *  blind faith.  Note that the page headers do not include the 64K dump
 *  header offset, which must be added to the values found.
 */
static void
mclx_cache_page_headers_v7(void)
{
	int i;
	uint64_t physaddr1, physaddr2, page_headers[MCLX_PAGE_HEADERS];
	dump_page_t dump_page, *dp;
	ulong granularity;

	if (LKCD_DEBUG(2))  /* dump headers have all been read */
		return;

	if (lkcd->total_pages > MEGABYTES(1))/* greater than 4G not supported */
		return;

        if (lseek(lkcd->fd, sizeof(dump_header_t), SEEK_SET) == -1)
		return;

        if (read(lkcd->fd, page_headers, MCLX_V1_PAGE_HEADER_CACHE) !=
            MCLX_V1_PAGE_HEADER_CACHE)
                return;

	dp = &dump_page;

	/*
	 *  Determine the granularity between offsets.
	 */
        if (lseek(lkcd->fd, page_headers[0] + LKCD_OFFSET_TO_FIRST_PAGE, 
	    SEEK_SET) == -1) 
		return;
        if (read(lkcd->fd, dp, lkcd->page_header_size) != 
	    lkcd->page_header_size) 
                return;
        physaddr1 = (dp->dp_address - lkcd->kvbase) << lkcd->page_shift;

        if (lseek(lkcd->fd, page_headers[1] + LKCD_OFFSET_TO_FIRST_PAGE,
            SEEK_SET) == -1)
                return;
        if (read(lkcd->fd, dp, lkcd->page_header_size) 
	    != lkcd->page_header_size)
                return;
        physaddr2 = (dp->dp_address - lkcd->kvbase) << lkcd->page_shift;

	if ((physaddr1 % MEGABYTES(1)) || (physaddr2 % MEGABYTES(1)) ||
	     (physaddr2 < physaddr1))
		return;

	granularity = physaddr2 - physaddr1;

	for (i = 0; i < (MCLX_PAGE_HEADERS-1); i++) {
		if (!page_headers[i])
			break;
		lkcd->curhdroffs = page_headers[i] + LKCD_OFFSET_TO_FIRST_PAGE;
		set_mb_benchmark((granularity * (i+1))/lkcd->page_size);
	}
}

