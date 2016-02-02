/* lkcd_common.c - core analysis suite
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002 Silicon Graphics, Inc. 
 * Copyright (C) 2002 Free Software Foundation, Inc.
 * Copyright (C) 2002-2005, 2007, 2009, 2011, 2013 David Anderson
 * Copyright (C) 2002-2005, 2007, 2009, 2011, 2013 Red Hat, Inc. All rights reserved.
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

/*
 *  lkcd_uncompress_RLE() is essentially LKCD's __cmpuncompress_page() rountine,
 *  adapted from ../cmd/lcrash/lib/libklib/arch/i386/kl_cmp.c:
 */

/*
 * arch/i386/cmp.c
 *
 * This file handles compression aspects of crash dump files
 * for i386 based systems.  Most of this is taken from the
 * IRIX compression code, with exceptions to how the index
 * is created, because the file format is different with Linux.
 *
 * Copyright 1999 Silicon Graphics, Inc. All rights reserved.
 */


/*
 *  This file has no knowledge of the dump_header_t, dump_header_asm_t or
 *  dump_page_t formats, so it gathers information from them via the version
 *  specific "_v1" or "_v2_v3" type routines.
 */

#define LKCD_COMMON
#include "defs.h"

static void dump_dump_page(char *, void *);
static int lkcd_uncompress_RLE(unsigned char *, unsigned char *,uint32_t,int *);
static int lkcd_uncompress_gzip(unsigned char *, ulong, unsigned char *, ulong);
static int hash_page(ulong);
static int page_is_cached(void);
static int page_is_hashed(long *);
static int cache_page(void);

struct lkcd_environment lkcd_environment = { 0 };
struct lkcd_environment *lkcd = &lkcd_environment;
static int uncompress_errloc;
static int uncompress_recover(unsigned char *, ulong, unsigned char *, ulong);

ulonglong 
fix_lkcd_address(ulonglong addr)
{
    int i; 
    ulong offset;

    for (i = 0; i < lkcd->fix_addr_num; i++) {
	if ( (addr >=lkcd->fix_addr[i].task) && 
		(addr < lkcd->fix_addr[i].task + STACKSIZE())){

	    offset = addr - lkcd->fix_addr[i].task;
	    addr = lkcd->fix_addr[i].saddr + offset;
	}
    }

    return addr;
}


/*
 *  Each version has its own dump initialization.
 */
int
lkcd_dump_init(FILE *fp, int fd, char *dumpfile)
{
	switch (lkcd->version)
	{
        case LKCD_DUMP_V1:
		return(lkcd_dump_init_v1(fp, fd));

        case LKCD_DUMP_V2:
        case LKCD_DUMP_V3:
		return(lkcd_dump_init_v2_v3(fp, fd));

        case LKCD_DUMP_V5:
        case LKCD_DUMP_V6:
		return(lkcd_dump_init_v5(fp, fd));

        case LKCD_DUMP_V7:
		return(lkcd_dump_init_v7(fp, fd, dumpfile));

        case LKCD_DUMP_V8:
        case LKCD_DUMP_V9:
		return(lkcd_dump_init_v8(fp, fd, dumpfile));

	default:
		return FALSE;
	}
}

/*
 *  Return the page size value recorded in the dump header.
 */
uint32_t
lkcd_page_size(void)
{
	return lkcd->page_size;
}


/*
 *  Return the panic task and panic string.
 */
unsigned long
get_lkcd_panic_task(void)
{
	return(lkcd->flags & (LKCD_VALID|LKCD_REMOTE) ? lkcd->panic_task : 0);
}

void
get_lkcd_panicmsg(char *buf)
{
	if (lkcd->flags & (LKCD_VALID|LKCD_REMOTE))
		strcpy(buf, lkcd->panic_string);
}

/*
 *  Called by remote_lkcd_dump_init() the local (!valid) lkcd_environment
 *  is used to store the panic task and panic message for use by the
 *  two routines above.
 */ 
void
set_remote_lkcd_panic_data(ulong task, char *buf)
{
	if (buf) {
		if (!(lkcd->panic_string = (char *)malloc(strlen(buf)+1))) {
			fprintf(stderr, 
			    "cannot malloc space for panic message!\n");
			clean_exit(1);
		}
		strcpy(lkcd->panic_string, buf);
	}

	if (task)
		lkcd->panic_task = task;

	lkcd->flags |= LKCD_REMOTE;
}

/*
 *  Does the magic number indicate an LKCD compressed dump?
 *  If so, set the version number for all future forays into the
 *  functions in this file.
 */
int
is_lkcd_compressed_dump(char *s)
{
        int tmpfd;
        uint64_t magic;
	uint32_t version;
	char errbuf[BUFSIZE];

        if ((tmpfd = open(s, O_RDONLY)) < 0) {
		strcpy(errbuf, s);
                perror(errbuf);
                return FALSE;
        }
        if (read(tmpfd, &magic, sizeof(uint64_t)) != sizeof(uint64_t)) {
                close(tmpfd);
                return FALSE;
        }
        if (read(tmpfd, &version, sizeof(uint32_t)) != sizeof(uint32_t)) {
                close(tmpfd);
                return FALSE;
        }

        close(tmpfd);

        if (!((magic == LKCD_DUMP_MAGIC_NUMBER) || 
	     (magic == LKCD_DUMP_MAGIC_LIVE)))
		return FALSE;

	switch (version & ~(LKCD_DUMP_MCLX_V0|LKCD_DUMP_MCLX_V1))
	{
	case LKCD_DUMP_V1:
		lkcd->version = LKCD_DUMP_V1;
		return TRUE;

	case LKCD_DUMP_V2:
	case LKCD_DUMP_V3:
		lkcd->version = LKCD_DUMP_V2;
		return TRUE;

	case LKCD_DUMP_V5:
	case LKCD_DUMP_V6:
		lkcd->version = LKCD_DUMP_V5;
		return TRUE;

	case LKCD_DUMP_V7:
		lkcd->version = LKCD_DUMP_V7;
		return TRUE;

	case LKCD_DUMP_V8:
	case LKCD_DUMP_V9:
	case LKCD_DUMP_V10:
		lkcd->version = LKCD_DUMP_V8;
		return TRUE;

	default:
		lkcd_print("unsupported LKCD dump version: %ld (%lx)\n", 
			version & ~(LKCD_DUMP_MCLX_V0|LKCD_DUMP_MCLX_V1), 
			version);
		return FALSE;
	}
}

/*
 *  console-only output for info regarding current page.
 */
static void
dump_dump_page(char *s, void *dp)
{
        switch (lkcd->version)
        {
        case LKCD_DUMP_V1:
                dump_dump_page_v1(s, dp);
		break;

        case LKCD_DUMP_V2:
        case LKCD_DUMP_V3:
                dump_dump_page_v2_v3(s, dp);
		break;

        case LKCD_DUMP_V5:
                dump_dump_page_v5(s, dp);
                break;

        case LKCD_DUMP_V7:
                dump_dump_page_v7(s, dp);
		break;

        case LKCD_DUMP_V8:
        case LKCD_DUMP_V9:
                dump_dump_page_v8(s, dp);
		break;
        }
}

/*
 *  help -S output, or as specified by arg.
 */
void
dump_lkcd_environment(ulong arg)
{
	int others;

	if (arg == LKCD_DUMP_HEADER_ONLY)
		goto dump_header_only;
	if (arg == LKCD_DUMP_PAGE_ONLY)
		goto dump_page_only;

	lkcd_print("              fd: %d\n", lkcd->fd);
	lkcd_print("              fp: %lx\n", lkcd->fp);
	lkcd_print("           debug: %ld\n", lkcd->debug);
	lkcd_print("           flags: %lx  (", lkcd->flags);
	others = 0;
	if (lkcd->flags & LKCD_VALID)
		lkcd_print("%sLKCD_VALID", others++ ? "|" : "");
	if (lkcd->flags & LKCD_REMOTE)
		lkcd_print("%sLKCD_REMOTE", others++ ? "|" : "");
	if (lkcd->flags & LKCD_NOHASH)
		lkcd_print("%sLKCD_NOHASH", others++ ? "|" : "");
        if (lkcd->flags & LKCD_MCLX)
                lkcd_print("%sLKCD_MCLX", others++ ? "|" : "");
        if (lkcd->flags & LKCD_BAD_DUMP)
                lkcd_print("%sLKCD_BAD_DUMP", others++ ? "|" : "");
	lkcd_print(")\n");

dump_header_only:
        switch (lkcd->version)
        {
        case LKCD_DUMP_V1:
                dump_lkcd_environment_v1(LKCD_DUMP_HEADER_ONLY);
                break;

        case LKCD_DUMP_V2:
        case LKCD_DUMP_V3:
                dump_lkcd_environment_v2_v3(LKCD_DUMP_HEADER_ONLY);
                break;

        case LKCD_DUMP_V5:
                dump_lkcd_environment_v5(LKCD_DUMP_HEADER_ONLY);
                break;

        case LKCD_DUMP_V7:
                dump_lkcd_environment_v7(LKCD_DUMP_HEADER_ONLY);
		break;

        case LKCD_DUMP_V8:
        case LKCD_DUMP_V9:
                dump_lkcd_environment_v8(LKCD_DUMP_HEADER_ONLY);
		break;
        }

        if (arg == LKCD_DUMP_HEADER_ONLY)
                return;

dump_page_only:
        switch (lkcd->version)
        {
        case LKCD_DUMP_V1:
                dump_lkcd_environment_v1(LKCD_DUMP_PAGE_ONLY);
                break;

        case LKCD_DUMP_V2:
        case LKCD_DUMP_V3:
                dump_lkcd_environment_v2_v3(LKCD_DUMP_PAGE_ONLY);
                break;

        case LKCD_DUMP_V5:
                dump_lkcd_environment_v5(LKCD_DUMP_PAGE_ONLY);
                break;

        case LKCD_DUMP_V7:
                dump_lkcd_environment_v7(LKCD_DUMP_PAGE_ONLY);
		break;

        case LKCD_DUMP_V8:
                dump_lkcd_environment_v8(LKCD_DUMP_PAGE_ONLY);
		break;
        }
	if (arg == LKCD_DUMP_PAGE_ONLY)
		return;

	lkcd_print("         version: %ld\n", lkcd->version);
	lkcd_print("       page_size: %ld\n", lkcd->page_size);
	lkcd_print("      page_shift: %d\n", lkcd->page_shift);
	lkcd_print("            bits: %d\n", lkcd->bits);
	lkcd_print("      panic_task: %lx\n", lkcd->panic_task);
	lkcd_print("    panic_string: %s%s", lkcd->panic_string,
		lkcd->panic_string && strstr(lkcd->panic_string, "\n") ? 
		"" : "\n");

	lkcd_print("     get_dp_size: ");
	if (lkcd->get_dp_size == get_dp_size_v1)
		lkcd_print("get_dp_size_v1()\n");
	else if (lkcd->get_dp_size == get_dp_size_v2_v3)
		lkcd_print("get_dp_size_v2_v3()\n");
        else if (lkcd->get_dp_size == get_dp_size_v5)
                lkcd_print("get_dp_size_v5()\n");
	else
		lkcd_print("%lx\n", lkcd->get_dp_size);

        lkcd_print("    get_dp_flags: ");
        if (lkcd->get_dp_flags == get_dp_flags_v1)
                lkcd_print("get_dp_flags_v1()\n");
        else if (lkcd->get_dp_flags == get_dp_flags_v2_v3)
                lkcd_print("get_dp_flags_v2_v3()\n");
        else if (lkcd->get_dp_flags == get_dp_flags_v5)
                lkcd_print("get_dp_flags_v5()\n");
        else
                lkcd_print("%lx\n", lkcd->get_dp_flags);

        lkcd_print("  get_dp_address: ");
        if (lkcd->get_dp_address == get_dp_address_v1)
                lkcd_print("get_dp_address_v1()\n");
        else if (lkcd->get_dp_address == get_dp_address_v2_v3)
                lkcd_print("get_dp_address_v2_v3()\n");
        else if (lkcd->get_dp_address == get_dp_address_v5)
                lkcd_print("get_dp_address_v5()\n");
        else
                lkcd_print("%lx\n", lkcd->get_dp_address);

	lkcd_print("     compression: ");
	lkcd_print(BITS32() ? "%lx  " : "%x  ", lkcd->compression);
	switch (lkcd->compression)
	{
	case LKCD_DUMP_COMPRESS_NONE:
		lkcd_print("(LKCD_DUMP_COMPRESS_NONE)\n");
		break;
	case LKCD_DUMP_COMPRESS_RLE:
		lkcd_print("(LKCD_DUMP_COMPRESS_RLE)\n");
		break;
	case LKCD_DUMP_COMPRESS_GZIP:
		lkcd_print("(LKCD_DUMP_COMPRESS_GZIP)\n");
		break;
	default:
		lkcd_print("(unknown)\n");
		break;
	}

	lkcd_print("page_header_size: %ld\n", lkcd->page_header_size);
	lkcd_print("          curpos: %ld\n", lkcd->curpos);
	lkcd_print("        curpaddr: ");
	lkcd_print(BITS32() ? "%llx\n" : "%lx\n", lkcd->curpaddr);
	lkcd_print("       curbufptr: %lx\n", lkcd->curbufptr);
	lkcd_print("      curhdroffs: %ld\n", lkcd->curhdroffs);
	lkcd_print("          kvbase: ");
	lkcd_print(BITS32() ? "%llx\n" : "%lx\n", lkcd->kvbase);
	lkcd_print("  page_cache_buf: %lx\n", lkcd->page_cache_buf);
	lkcd_print(" compressed_page: %lx\n", lkcd->compressed_page);
	lkcd_print("     evict_index: %d\n", lkcd->evict_index);
	lkcd_print("       evictions: %ld\n", lkcd->evictions);
	lkcd_print(" benchmark_pages: %ld\n", lkcd->benchmark_pages);
	lkcd_print(" benchmarks_done: %ld\n", lkcd->benchmarks_done);

	lkcd_memory_dump(lkcd->fp);
}

/*
 *  Set the shadow debug flag.
 */
void
set_lkcd_debug(ulong debug)
{
	lkcd->debug = debug;
}

/*
 *  Set no-hash flag bit.
 */
void 
set_lkcd_nohash(void)
{
	lkcd->flags |= LKCD_NOHASH; 
}

/*
 *  Set the file pointer for debug output.
 */
FILE *
set_lkcd_fp(FILE *fp)
{
	lkcd->fp = fp;
	return fp;
}

/*
 *  Return the number of pages cached.
 */
int
lkcd_memory_used(void)
{
	int i, pages;
        struct page_cache_hdr *sp;

        sp = &lkcd->page_cache_hdr[0];
        for (i = pages = 0; i < LKCD_CACHED_PAGES; i++, sp++) { 
		if (LKCD_VALID_PAGE(sp->pg_flags))
			pages++;
	}

	return pages;
}

/*
 *  Since the dumpfile pages are temporary tenants of a fixed page cache,
 *  this command doesn't do anything except clear the references. 
 */
int
lkcd_free_memory(void)
{
        int i, pages;
        struct page_cache_hdr *sp;

        sp = &lkcd->page_cache_hdr[0];
        for (i = pages = 0; i < LKCD_CACHED_PAGES; i++, sp++) {
                if (LKCD_VALID_PAGE(sp->pg_flags)) {
			sp->pg_addr = 0;
			sp->pg_hit_count = 0;
                        pages++;
		}
		sp->pg_flags = 0;
        }

        return pages;
}

/*
 *  Dump the page cache;
 */
int
lkcd_memory_dump(FILE *fp)
{
        int i, c, pages;
        struct page_cache_hdr *sp;
        struct page_hash_entry *phe;
	ulong pct_cached, pct_hashed;
	ulong pct_compressed, pct_raw;
	FILE *fpsave;
	char buf[BUFSIZE];
	int wrap;

	fpsave = lkcd->fp;
	lkcd->fp = fp;

        lkcd_print("     total_pages: %ld\n", lkcd->total_pages);
        pct_compressed = (lkcd->compressed*100) /
                (lkcd->hashed ? lkcd->hashed : 1);
        pct_raw = (lkcd->raw*100) /
                (lkcd->hashed ? lkcd->hashed : 1);
        lkcd_print("          hashed: %ld\n", lkcd->hashed);
        lkcd_print("      compressed: %ld (%ld%%)\n", 
		lkcd->compressed, pct_compressed);
        lkcd_print("             raw: %ld (%ld%%)\n", 
		lkcd->raw, pct_raw);
        pct_cached = (lkcd->cached_reads*100) /  
                (lkcd->total_reads ? lkcd->total_reads : 1);
        pct_hashed = (lkcd->hashed_reads*100) /
                (lkcd->total_reads ? lkcd->total_reads : 1); 
        lkcd_print("    cached_reads: %ld (%ld%%)\n", lkcd->cached_reads,
                pct_cached);
        lkcd_print("    hashed_reads: %ld (%ld%%)\n", lkcd->hashed_reads,
                pct_hashed);
        lkcd_print("     total_reads: %ld (hashed or cached: %ld%%) \n",
            lkcd->total_reads, pct_cached+pct_hashed);

        lkcd_print("page_hash[%2d]:\n", LKCD_PAGE_HASH);

	if (LKCD_DEBUG(1)) {
	        for (i = 0; i < LKCD_PAGE_HASH; i++) {
	                phe = &lkcd->page_hash[i];
	                if (!LKCD_VALID_PAGE(phe->pg_flags))
	                        continue;
	                lkcd_print("  [%2d]: ", i);
	                wrap = 0;
	                while (phe && LKCD_VALID_PAGE(phe->pg_flags)) {
				sprintf(buf, "%llx@", 
					(ulonglong)phe->pg_addr);
				sprintf(&buf[strlen(buf)],
	                        	"%llx,", (ulonglong)phe->pg_hdr_offset);
				lkcd_print("%18s", buf);

	                        phe = phe->next;
	                        if (phe && (++wrap == 3)) {
	                                lkcd_print("\n        ");
	                                wrap = 0;
	                        }
	                }
	                lkcd_print("\n");
	        }
	} else {
	        for (i = 0; i < LKCD_PAGE_HASH; i++) {
	                phe = &lkcd->page_hash[i];
	                if (!LKCD_VALID_PAGE(phe->pg_flags))
	                        continue;
	                lkcd_print("  [%2d]: ", i);
	                wrap = 0;
	                while (phe && LKCD_VALID_PAGE(phe->pg_flags)) {
				lkcd_print(BITS32() ? "%9llx," : "%9lx,",
					phe->pg_addr);
	                        phe = phe->next;
	                        if (phe && (++wrap == 7)) {
	                                lkcd_print("\n        ");
	                                wrap = 0;
	                        }
	                }
	                lkcd_print("\n");
	        }
	}

        lkcd_print("page_cache_hdr[%2d]:\n", LKCD_CACHED_PAGES);
	lkcd_print(" INDEX   PG_ADDR  PG_BUFPTR");
        lkcd_print(BITS32() ? " PG_HIT_COUNT\n" : "        PG_HIT_COUNT\n");

        sp = &lkcd->page_cache_hdr[0];
        for (i = pages = 0; i < LKCD_CACHED_PAGES; i++, sp++) {
                if (LKCD_VALID_PAGE(sp->pg_flags))
                        pages++;
		if (BITS32())
                	lkcd_print("  [%2d] %9llx  %lx        %ld\n",
			    i, sp->pg_addr, sp->pg_bufptr, sp->pg_hit_count);
		else
                	lkcd_print("  [%2d] %9lx  %lx  %ld\n",
			    i, sp->pg_addr, sp->pg_bufptr, sp->pg_hit_count);
        }

	if (lkcd->mb_hdr_offsets) {
		lkcd_print("mb_hdr_offsets[%3ld]: \n", lkcd->benchmark_pages);

		for (i = 0; i < lkcd->benchmark_pages; i += 8) {
			lkcd_print("  [%3d]", i);
			c = 0;
			while ((c < 8) && ((i+c) < lkcd->benchmark_pages)) {
				lkcd_print(" %8lx", lkcd->mb_hdr_offsets[i+c]);
				c++;
			}
			lkcd_print("\n");
		}
	} else {
		lkcd_print("  mb_hdr_offsets: NA\n");
	}

	if (lkcd->zones) {
		lkcd_print("       num_zones: %d / %d\n", lkcd->num_zones,
				lkcd->max_zones);
		lkcd_print("   zoned_offsets: %ld\n", lkcd->zoned_offsets);
	}

	lkcd_print("  dumpfile_index: %s\n", lkcd->dumpfile_index);
	lkcd_print("             ifd: %d\n", lkcd->ifd);
        lkcd_print("    memory_pages: %ld\n", lkcd->memory_pages);
        lkcd_print(" page_offset_max: %ld\n", lkcd->page_offset_max);
        lkcd_print("  page_index_max: %ld\n", lkcd->page_index_max);
        lkcd_print("    page_offsets: %lx\n", lkcd->page_offsets);

	lkcd->fp = fpsave;

        return pages;

}


/*
 *  The lkcd_lseek() routine does the bulk of the work setting things up 
 *  so that the subsequent lkcd_read() simply has to do a bcopy().

 *  Given a physical address, first determine:
 *
 *   (1) its page offset (lkcd->curpos).
 *   (2) its page address as specified in the dumpfile (lkcd->curpaddr).
 *
 *  If the page data is already cached, everything will be set up for the
 *  subsequent read when page_is_cached() returns.
 *
 *  If the page data is not cached, either of the following occurs:
 *
 *   (1) page_is_hashed() will check whether the page header offset is cached,
 *       and if so, will set up the page variable, and lseek to the header.
 *
 *  In either case above, the starting point for the page search is set up.
 *  Lastly, cache_page() stores the requested page's data.
 */

static int
save_offset(uint64_t paddr, off_t off)
{
	uint64_t zone, page;
	int ii, ret;
	int max_zones;
	struct physmem_zone *zones;

	ret = -1;
	zone = paddr & lkcd->zone_mask;

	page = (paddr & ~lkcd->zone_mask) >> lkcd->page_shift;

	if (lkcd->num_zones == 0) {
		lkcd->zones = malloc(ZONE_ALLOC * sizeof(struct physmem_zone));
		if (!lkcd->zones) {
			return -1; /* This should be fatal */
		}
		BZERO(lkcd->zones, ZONE_ALLOC * sizeof(struct physmem_zone));

		lkcd->max_zones = ZONE_ALLOC;

		lkcd->zones[0].start = zone;
		lkcd->zones[0].pages = malloc((ZONE_SIZE >> lkcd->page_shift) *
					sizeof(struct page_desc));
		if (!lkcd->zones[0].pages) {
			return -1; /* this should be fatal */
		}

		BZERO(lkcd->zones[0].pages, (ZONE_SIZE >> lkcd->page_shift) *
					sizeof(struct page_desc));
		lkcd->num_zones++;
	}

retry:
	/* find the zone */
	for (ii=0; ii < lkcd->num_zones; ii++) {
		if (lkcd->zones[ii].start == zone) {
			if (lkcd->zones[ii].pages[page].offset != 0) {
			   if (lkcd->zones[ii].pages[page].offset != off) {
				if (CRASHDEBUG(1) && !STREQ(pc->curcmd, "search"))
				    error(INFO, "LKCD: conflicting page: zone %lld, "
					"page %lld: %lld, %lld != %lld\n",
					(unsigned long long)zone, 
					(unsigned long long)page, 
					(unsigned long long)paddr, 
					(unsigned long long)off,
					(unsigned long long)lkcd->zones[ii].pages[page].offset);
				return -1;
			   }
			   ret = 0;
			} else {
			   lkcd->zones[ii].pages[page].offset = off;
			   ret = 1;
			}
			break;
		}
	}
	if (ii == lkcd->num_zones) {
		/* This is a new zone */
		if (lkcd->num_zones < lkcd->max_zones) {
			/* We have room for another one */
			lkcd->zones[ii].start = zone;
			lkcd->zones[ii].pages = malloc(
					(ZONE_SIZE >> lkcd->page_shift) *
					sizeof(struct page_desc));
			if (!lkcd->zones[ii].pages) {
				return -1; /* this should be fatal */
			}

			BZERO(lkcd->zones[ii].pages, 
					(ZONE_SIZE >> lkcd->page_shift) *
					sizeof(struct page_desc));
			lkcd->zones[ii].pages[page].offset = off;
			ret = 1;
			lkcd->num_zones++;
		} else {
			/* need to expand zone */
			max_zones = lkcd->max_zones * 2;
			zones = malloc(max_zones * sizeof(struct physmem_zone));
			if (!zones) {
				return -1; /* This should be fatal */
			}
			BZERO(zones, max_zones * sizeof(struct physmem_zone));
			memcpy(zones, lkcd->zones,
				lkcd->max_zones * sizeof(struct physmem_zone));
			free(lkcd->zones);

			lkcd->zones = zones;
			lkcd->max_zones = max_zones;
			goto retry;
		}
	}

	return ret;  /* 1 if the page is new */
}
		
static off_t
get_offset(uint64_t paddr)
{
	uint64_t zone, page;
	int ii;

	zone = paddr & lkcd->zone_mask;
	page = (paddr % ZONE_SIZE) >> lkcd->page_shift;

	if (lkcd->zones == 0) {
		return 0;
	}

	/* find the zone */
	for (ii=0; ii < lkcd->num_zones; ii++) {
		if (lkcd->zones[ii].start == zone) {
			return (lkcd->zones[ii].pages[page].offset);
		}
	}
	return 0;
}


#ifdef IA64

int
lkcd_get_kernel_start(ulong *addr)
{
	if (!addr)
		return 0;

	switch (lkcd->version)
	{
        case LKCD_DUMP_V8:
        case LKCD_DUMP_V9:
		return lkcd_get_kernel_start_v8(addr);

	default:
		return 0;
	}
}

#endif


int
lkcd_lseek(physaddr_t paddr)
{
	int err;
        int eof;
        void *dp;
        long page = 0;
	physaddr_t physaddr;
	int seeked_to_page = 0;
	off_t page_offset;

	dp = lkcd->dump_page;

	lkcd->curpos = paddr & ((physaddr_t)(lkcd->page_size-1));
        lkcd->curpaddr = paddr & ~((physaddr_t)(lkcd->page_size-1));

	if (page_is_cached()) 
		return TRUE;

	/* Faster than paging in lkcd->page_offsets[page] */
	if(page_is_hashed(&page)) {
		seeked_to_page = 1;
	}

	 /* Find the offset for this page, if known */
    if ((page_offset = get_offset(paddr)) > 0) {
	off_t seek_offset;
	seek_offset = lseek(lkcd->fd, page_offset, SEEK_SET);

	if (seek_offset == page_offset) {
	    seeked_to_page = 1;
	    page = 0; /* page doesn't make any sense */
	}
    }


    if (seeked_to_page) {
	err = lkcd_load_dump_page_header(dp, page);
	if (err == LKCD_DUMPFILE_OK) {
	    return(cache_page());
	}
    }	

    /* We have to grind through some more of the dump file */
    lseek(lkcd->fd, lkcd->page_offset_max, SEEK_SET);
    eof = FALSE;
    while (!eof) {
	switch (lkcd_load_dump_page_header(dp, page))
	{
	    case LKCD_DUMPFILE_OK:
		break;

	    case LKCD_DUMPFILE_EOF:
		eof = TRUE;
		continue;
	}

	physaddr = lkcd->get_dp_flags() & 
	    (LKCD_DUMP_MCLX_V0|LKCD_DUMP_MCLX_V1) ?
	    (lkcd->get_dp_address() - lkcd->kvbase) << lkcd->page_shift:
	    lkcd->get_dp_address() - lkcd->kvbase;

	if (physaddr == lkcd->curpaddr) {
	    return(cache_page());
	}
	lseek(lkcd->fd, lkcd->get_dp_size(), SEEK_CUR);
    }

	return FALSE;
}

/*
 *  Everything's been set up by the previous lkcd_lseek(), so all that has
 *  to be done is to read the uncompressed data into the user buffer:
 *
 *    lkcd->curbufptr points to the uncompressed page base.
 *    lkcd->curpos is the offset into the buffer.
 */
long 
lkcd_read(void *buf, long count)
{
	char *p;

	lkcd->total_reads++;

	p = lkcd->curbufptr + lkcd->curpos;
	
	BCOPY(p, buf, count);
	return count;
}

/*
 *  Check whether lkcd->curpaddr is already cached.  If it is, update
 *  lkcd->curbufptr to point to the page's uncompressed data.  
 */
static int
page_is_cached(void)
{
	int i;

	for (i = 0; i < LKCD_CACHED_PAGES; i++) {

		if (!LKCD_VALID_PAGE(lkcd->page_cache_hdr[i].pg_flags))
			continue;

		if (lkcd->page_cache_hdr[i].pg_addr == lkcd->curpaddr) {
			lkcd->page_cache_hdr[i].pg_hit_count++;
			lkcd->curbufptr = lkcd->page_cache_hdr[i].pg_bufptr;
			lkcd->cached_reads++;
			return TRUE;
		}
	}

	return FALSE;
}


/*
 *  For an incoming page:
 *  
 *   (1) If it's already hashed just return TRUE.
 *   (2) If the base page_hash_entry is unused, fill it up and return TRUE;
 *   (3) Otherwise, find the last page_hash_entry on the list, allocate and
 *       fill a new one, link it on the list, and return TRUE.
 *   (4) If the malloc fails, quietly return FALSE (with no harm done).
 */
static int
hash_page(ulong type)
{
	struct page_hash_entry *phe;
	int index;

        if (lkcd->flags & LKCD_NOHASH) {
                lkcd->flags &= ~LKCD_NOHASH;
		return FALSE;
	}

	index = LKCD_PAGE_HASH_INDEX(lkcd->curpaddr);

	for (phe = &lkcd->page_hash[index]; LKCD_VALID_PAGE(phe->pg_flags); 
	     phe = phe->next) {
		if (phe->pg_addr == lkcd->curpaddr)
			return TRUE;
		if (!phe->next)
			break;
	}

	if (LKCD_VALID_PAGE(phe->pg_flags)) {
		if ((phe->next = malloc
		    (sizeof(struct page_hash_entry))) == NULL)
			return FALSE;
		phe = phe->next;
	}

	phe->pg_flags |= LKCD_VALID;
	phe->pg_addr = lkcd->curpaddr;
	phe->pg_hdr_offset = lkcd->curhdroffs;
	phe->next = NULL;

	lkcd->hashed++;
	switch (type)
	{
	case LKCD_DUMP_COMPRESSED:
		lkcd->compressed++;
		break;
	case LKCD_DUMP_RAW:
		lkcd->raw++;
		break;
	}

	return TRUE;
}

/*
 *  Check whether a page is currently hashed, and if so, return the page
 *  number so that the subsequent search loop will find it immediately.
 */
static int
page_is_hashed(long *pp)
{
	struct page_hash_entry *phe;
	int index;

	index = LKCD_PAGE_HASH_INDEX(lkcd->curpaddr);

	for (phe = &lkcd->page_hash[index]; LKCD_VALID_PAGE(phe->pg_flags); 
	     phe = phe->next) {
		if (phe->pg_addr == lkcd->curpaddr) {
			*pp = (long)(lkcd->curpaddr >> lkcd->page_shift);
			lseek(lkcd->fd, phe->pg_hdr_offset, SEEK_SET);
			lkcd->hashed_reads++;
			return TRUE;
		}
		if (!phe->next)
			break;
	}

	return FALSE;

}

/*
 *  The caller stores the incoming page's page header offset in 
 *  lkcd->curhdroffs.
 */
int
set_mb_benchmark(ulong page)
{
	long mb;

	if ((mb = LKCD_PAGE_MEGABYTE(page)) >= lkcd->benchmark_pages)
		return FALSE;

        if (!lkcd->mb_hdr_offsets[mb]) {
        	lkcd->mb_hdr_offsets[mb] = lkcd->curhdroffs;
		lkcd->benchmarks_done++;
	}

	return TRUE;
}
	
/*
 *  Coming into this routine:
 *
 *   (1) lkcd->curpaddr points to the page address as specified in the dumpfile.
 *   (2) the dump_page header has been copied into lkcd->dump_page.
 *   (3) the file pointer is sitting at the beginning of the page data,
 *       be it compressed or otherwise.
 *   (4) lkcd->curhdroffs contains the file pointer to the incoming page's
 *       header offset.
 *
 *  If an empty page cache location is available, take it.  Otherwise, evict
 *  the entry indexed by evict_index, and then bump evict index.  The hit_count
 *  is only gathered for dump_lkcd_environment().
 *
 *  If the page is compressed, uncompress it into the selected page cache entry.
 *  If the page is raw, just copy it into the selected page cache entry.
 *  If all works OK, update lkcd->curbufptr to point to the page's uncompressed
 *  data.
 *
 */
static int
cache_page(void)
{
	int i;
	ulong type;
	int found, newsz;
	uint32_t rawsz;
	ssize_t bytes ATTRIBUTE_UNUSED;


        for (i = found = 0; i < LKCD_CACHED_PAGES; i++) {
                if (LKCD_VALID_PAGE(lkcd->page_cache_hdr[i].pg_flags))
                        continue;
		found = TRUE;
		break;
        }

	if (!found) {
                i = lkcd->evict_index;
		lkcd->page_cache_hdr[i].pg_hit_count = 0;
                lkcd->evict_index = (lkcd->evict_index+1) % LKCD_CACHED_PAGES;
                lkcd->evictions++;
	}

        lkcd->page_cache_hdr[i].pg_flags = 0;
        lkcd->page_cache_hdr[i].pg_addr = lkcd->curpaddr;
	lkcd->page_cache_hdr[i].pg_hit_count++;

	type = lkcd->get_dp_flags() & (LKCD_DUMP_COMPRESSED|LKCD_DUMP_RAW);

	switch (type)
	{
	case LKCD_DUMP_COMPRESSED:
		if (LKCD_DEBUG(2)) 
			dump_dump_page("cmp: ", lkcd->dump_page);
		
		newsz = 0;
		BZERO(lkcd->compressed_page, lkcd->page_size);
                bytes = read(lkcd->fd, lkcd->compressed_page, lkcd->get_dp_size());

		switch (lkcd->compression)
		{
		case LKCD_DUMP_COMPRESS_NONE:
			lkcd_print("dump_header: DUMP_COMPRESS_NONE and "
			          "dump_page: DUMP_COMPRESSED (?)\n");
			return FALSE;

		case LKCD_DUMP_COMPRESS_RLE:
			if (!lkcd_uncompress_RLE((unsigned char *)
			    lkcd->compressed_page,
			    (unsigned char *)lkcd->page_cache_hdr[i].pg_bufptr, 	
			    lkcd->get_dp_size(), &newsz) || 
			    (newsz != lkcd->page_size)) {
				lkcd_print("uncompress of page ");
				lkcd_print(BITS32() ? 
					"%llx failed!\n" : "%lx failed!\n",
					lkcd->get_dp_address());
				lkcd_print("newsz returned: %d\n", newsz);
				return FALSE;
			}
			break;

		case LKCD_DUMP_COMPRESS_GZIP:
			if (!lkcd_uncompress_gzip((unsigned char *)
			    lkcd->page_cache_hdr[i].pg_bufptr, lkcd->page_size,
			    (unsigned char *)lkcd->compressed_page, 
			    lkcd->get_dp_size())) {
                                lkcd_print("uncompress of page ");
                                lkcd_print(BITS32() ? 
                                        "%llx failed!\n" : "%lx failed!\n",
                                        lkcd->get_dp_address());
				return FALSE;
			}
			break;
		}

		break;

	case LKCD_DUMP_RAW:
		if (LKCD_DEBUG(2)) 
			dump_dump_page("raw: ", lkcd->dump_page);
		if ((rawsz = lkcd->get_dp_size()) == 0)
			BZERO(lkcd->page_cache_hdr[i].pg_bufptr, 
				lkcd->page_size);
		else if (rawsz == lkcd->page_size)
			bytes = read(lkcd->fd, lkcd->page_cache_hdr[i].pg_bufptr, 
				lkcd->page_size);
		else {
			lkcd_print("cache_page: "
		        	"invalid LKCD_DUMP_RAW dp_size\n");
			dump_lkcd_environment(LKCD_DUMP_PAGE_ONLY);
			return FALSE;
		}
		break;

	default:
		lkcd_print("cache_page: bogus page:\n");
		dump_lkcd_environment(LKCD_DUMP_PAGE_ONLY);
		return FALSE;
	}

        lkcd->page_cache_hdr[i].pg_flags |= LKCD_VALID;
	lkcd->curbufptr = lkcd->page_cache_hdr[i].pg_bufptr;

	hash_page(type);

	return TRUE;
}

/*
 *  Uncompress an RLE-encoded buffer.
 */
static int
lkcd_uncompress_RLE(unsigned char *cbuf, unsigned char *ucbuf, 
	       uint32_t blk_size, int *new_size)
{
        int i;
        unsigned char value, count, cur_byte;
        uint32_t ri, wi;

        /* initialize the read / write indices */
        ri = wi = 0;

        /* otherwise decompress using run length encoding */
        while(ri < blk_size) {
                cur_byte = cbuf[ri++];
                if (cur_byte == 0) {
                        count = cbuf[ri++];
                        if (count == 0) {
                                ucbuf[wi++] = 0;
                        } else {
                                value = cbuf[ri++];
                                for (i = 0; i <= count; i++) {
                                        ucbuf[wi++] = value;
                                }
                        }
                } else {
                        ucbuf[wi++] = cur_byte;
                }

                /* if our write index is beyond the page size, exit out */
                if (wi > /* PAGE_SIZE */ lkcd->page_size) {
			lkcd_print( 
           "Attempted to decompress beyond page boundaries: file corrupted!\n");
                        return (0);
                }
        }

        /* set return size to be equal to uncompressed size (in bytes) */
        *new_size = wi;

        return 1;
}

/* Returns the bit offset if it's able to correct, or negative if not */
static int
uncompress_recover(unsigned char *dest, ulong destlen,
    unsigned char *source, ulong sourcelen)
{
        int byte, bit;
        ulong retlen = destlen;
        int good_decomp = 0, good_rv = -1;

        /* Generate all single bit errors */
        if (sourcelen > 16384) {
                lkcd_print("uncompress_recover: sourcelen %ld too long\n",
                    sourcelen);
                return(-1);
        }
        for (byte = 0; byte < sourcelen; byte++) {
                for (bit = 0; bit < 8; bit++) {
                        source[byte] ^= (1 << bit);

                        if (uncompress(dest, &retlen, source, sourcelen) == Z_OK &&
                            retlen == destlen) {
                                good_decomp++;
                                lkcd_print("good for flipping byte %d bit %d\n",
                                    byte, bit);
                                good_rv = bit + byte * 8;
                        }

                        /* Put it back */
                        source[byte] ^= (1 << bit);
                }
        }
        if (good_decomp == 0) {
                lkcd_print("Could not correct gzip errors.\n");
                return -2;
        } else if (good_decomp > 1) {
                lkcd_print("Too many valid gzip decompressions: %d.\n", good_decomp);
                return -3;
        } else {
                source[good_rv >> 8] ^= 1 << (good_rv % 8);
                uncompress(dest, &retlen, source, sourcelen);
                source[good_rv >> 8] ^= 1 << (good_rv % 8);
                return good_rv;
        }
}


/*
 *  Uncompress a gzip'd buffer.
 *
 *  Returns FALSE on error.  If set, then
 *    a non-negative value of uncompress_errloc indicates the location of
 *    a single-bit error, and the data may be used.
 */
static int 
lkcd_uncompress_gzip(unsigned char *dest, ulong destlen, 
	unsigned char *source, ulong sourcelen)
{
        ulong retlen = destlen;
        int rc = FALSE;

	switch (uncompress(dest, &retlen, source, sourcelen)) 
	{
	case Z_OK:
		if (retlen == destlen) {
                        rc = TRUE;
                        break;
		}

		lkcd_print("uncompress: returned length not page size: %ld\n",
				retlen);
                rc = FALSE;
                break;

	case Z_MEM_ERROR:
		lkcd_print("uncompress: Z_MEM_ERROR (not enough memory)\n");
                rc = FALSE;
                break;

	case Z_BUF_ERROR:
		lkcd_print("uncompress: "
			"Z_BUF_ERROR (not enough room in output buffer)\n");
                rc = FALSE;
                break;

	case Z_DATA_ERROR:
		lkcd_print("uncompress: Z_DATA_ERROR (input data corrupted)\n");
                rc = FALSE;
                break;
        default:
                rc = FALSE;
                break;
	}

        if (rc == FALSE) {
                uncompress_errloc =
                    uncompress_recover(dest, destlen, source, sourcelen);
        }
	return rc;
}


/*
 *  Generic print routine to handle integral and remote daemon usage of
 */
void 
lkcd_print(char *fmt, ...)
{
	char buf[BUFSIZE];
	va_list ap;

        if (!fmt || !strlen(fmt))
                return;

        va_start(ap, fmt);
        (void)vsnprintf(buf, BUFSIZE, fmt, ap);
        va_end(ap);

	if (lkcd->fp)
		fprintf(lkcd->fp, "%s", buf);
	else
		console(buf);
}

/*
 *  Try to read the current dump page header, reporting back either
 *  LKCD_DUMPFILE_EOF, LKCD_DUMPFILE_END or LKCD_DUMPFILE_OK.  The header's
 *  file pointer position is saved in lkcd->curhdroffs.  If the page is
 *  an even megabyte, save its offset.
 */
int
lkcd_load_dump_page_header(void *dp, ulong page)
{
	uint32_t dp_flags;
	uint64_t dp_address, physaddr;
	off_t page_offset;
	int ret;


	/* This is wasted effort */
        page_offset = lkcd->curhdroffs = lseek(lkcd->fd, 0, SEEK_CUR);

        if (read(lkcd->fd, dp, lkcd->page_header_size) != 
	    lkcd->page_header_size) {
		if (page > lkcd->total_pages) 
			lkcd_dumpfile_complaint(page, lkcd->total_pages, 
				LKCD_DUMPFILE_EOF);
                return LKCD_DUMPFILE_EOF;
	}

	dp_flags = lkcd->get_dp_flags();
	dp_address = lkcd->get_dp_address();

        if (dp_flags & LKCD_DUMP_END) {
                return LKCD_DUMPFILE_END;
        }

	if ((lkcd->flags & LKCD_VALID) && (page > lkcd->total_pages)) 
		lkcd->total_pages = page;

#ifdef X86
	/*
	 *  Ugly leftover from very early x86 LKCD versions which used 
	 *  the kernel unity-mapped virtual address as the dp_address.
	 */
        if ((page == 0) && !(lkcd->flags & LKCD_VALID) && 
	    (lkcd->version == LKCD_DUMP_V1) && 
	    (dp_address == 0xc0000000)) 
        	lkcd->kvbase = dp_address;
#endif

	physaddr = dp_flags & (LKCD_DUMP_MCLX_V0|LKCD_DUMP_MCLX_V1) ?
		(dp_address - lkcd->kvbase) << lkcd->page_shift : 
        	dp_address - lkcd->kvbase;


	if ((ret = save_offset(physaddr, page_offset)) < 0) {
	    return LKCD_DUMPFILE_EOF; /* really an error */
	} 

	lkcd->zoned_offsets += ret;  /* return = 0 if already known */

	if (page_offset > lkcd->page_offset_max) {
	    /* doesn't this mean I have to re-read this dp? */
	    lkcd->page_offset_max = page_offset;
	}


	return LKCD_DUMPFILE_OK;
}

/*
 *  Register a complaint one time, if appropriate.
 */
void
lkcd_dumpfile_complaint(uint32_t realpages, uint32_t dh_num_pages, int retval)
{
	if (lkcd->flags & LKCD_BAD_DUMP)
		return;
	
	lkcd->flags |= LKCD_BAD_DUMP;

	if (realpages > dh_num_pages) {
		lkcd_print(
"\n\nWARNING: This dumpfile contains more pages than the amount indicated\n"
"         in the dumpfile header.  This is indicative of a failure during\n"
"         the post-panic creation of the dumpfile on the dump device.\n\n");
	}

	if (realpages < dh_num_pages) {
		lkcd_print(
"\n\nWARNING: This dumpfile contains fewer pages than the amount indicated\n"
"         in the dumpfile header.  This is indicative of a failure during\n"
"         the creation of the dumpfile during boot.\n\n");
	}
}

int
get_lkcd_regs_for_cpu(struct bt_info *bt, ulong *eip, ulong *esp)
{
	switch (lkcd->version) {
	case LKCD_DUMP_V8:
	case LKCD_DUMP_V9:
		return get_lkcd_regs_for_cpu_v8(bt, eip, esp);
	default:
		return -1;
	}
}

