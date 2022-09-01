/* lkcd_v2_v3.c - core analysis suite
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
#include "lkcd_vmdump_v2_v3.h"

static dump_header_t dump_header_v2_v3 = { 0 };
static dump_page_t dump_page = { 0 };
static dump_header_asm_t dump_header_asm = { 0 };
static void mclx_cache_page_headers_v3(void);

/*
 *  Verify and initialize the LKCD environment, storing the common data
 *  in the global lkcd_environment structure.
 */
int
lkcd_dump_init_v2_v3(FILE *fp, int fd)
{
	int i; 
	int eof;
	uint32_t pgcnt;
	dump_header_t *dh;
	dump_header_asm_t *dha;
	dump_page_t *dp;

	lkcd->fd = fd;
	lkcd->fp = fp;

	lseek(lkcd->fd, 0, SEEK_SET);

	dh = &dump_header_v2_v3;
	dha = &dump_header_asm;
	dp = &dump_page;

	if (read(lkcd->fd, dh, sizeof(dump_header_t)) !=
	    sizeof(dump_header_t))
		return FALSE;

	if (dh->dh_version & LKCD_DUMP_MCLX_V1) 
		lseek(lkcd->fd, MCLX_V1_PAGE_HEADER_CACHE, SEEK_CUR);

        if (read(lkcd->fd, dha, sizeof(dump_header_asm_t)) !=
            sizeof(dump_header_asm_t))
                return FALSE;

        lkcd->dump_page = dp;
        lkcd->dump_header = dh;
	lkcd->dump_header_asm = dha;
	if (lkcd->debug) 
		dump_lkcd_environment(LKCD_DUMP_HEADER_ONLY);

	/*
	 *  Allocate and clear the benchmark offsets, one per megabyte.
	 */
        lkcd->page_size = dh->dh_page_size;
	lkcd->page_shift = ffs(lkcd->page_size) - 1;
	lkcd->bits = sizeof(long) * 8;
        lkcd->benchmark_pages = (dh->dh_num_pages/LKCD_PAGES_PER_MEGABYTE())+1;
	lkcd->total_pages = dh->dh_num_pages;

	lkcd->zone_shift = ffs(ZONE_SIZE) - 1;
	lkcd->zone_mask = ~(ZONE_SIZE - 1);
	lkcd->num_zones = 0;
	lkcd->max_zones = 0;
	lkcd->zoned_offsets = 0;

	lkcd->get_dp_flags = get_dp_flags_v2_v3;
	lkcd->get_dp_address = get_dp_address_v2_v3;
	lkcd->get_dp_size = get_dp_size_v2_v3;
	lkcd->compression = LKCD_DUMP_COMPRESS_RLE;
        lkcd->page_header_size = sizeof(dump_page_t);

        lseek(lkcd->fd, LKCD_OFFSET_TO_FIRST_PAGE, SEEK_SET);

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
                    ~(DUMP_COMPRESSED|DUMP_RAW|DUMP_END|LKCD_DUMP_MCLX_V0)) {
			lkcd_print("unknown page flag in dump: %lx\n",
				dp->dp_flags);
		}
		if (dp->dp_flags & (LKCD_DUMP_MCLX_V0|LKCD_DUMP_MCLX_V1))
			lkcd->flags |= LKCD_MCLX;

		if (dp->dp_size > 4096) {
			lkcd_print("dp_size > 4096: %d\n", dp->dp_size);
			dump_lkcd_environment(LKCD_DUMP_PAGE_ONLY);
		}

		if (dp->dp_flags & DUMP_END) {
			lkcd_print("found DUMP_END\n");
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
		mclx_cache_page_headers_v3();

        if (!fp)
                lkcd->flags |= LKCD_REMOTE;
	lkcd->flags |= LKCD_VALID;

	return TRUE;
}

/*
 *  Return the current page's dp_size. 
 */
uint32_t 
get_dp_size_v2_v3(void)
{
        dump_page_t *dp;

        dp = (dump_page_t *)lkcd->dump_page;

        return(dp->dp_size);
}

/*
 *  Return the current page's dp_flags.
 */
uint32_t
get_dp_flags_v2_v3(void)
{
        dump_page_t *dp;

        dp = (dump_page_t *)lkcd->dump_page;

        return(dp->dp_flags);
}

/*
 *  Return the current page's dp_address.
 */
uint64_t
get_dp_address_v2_v3(void)
{
        dump_page_t *dp;

        dp = (dump_page_t *)lkcd->dump_page;

        return(dp->dp_address);
}

void
dump_dump_page_v2_v3(char *s, void *dpp)
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

        if (flags & DUMP_COMPRESSED)
                console("DUMP_COMPRESSED", others++);
        if (flags & DUMP_RAW)
                console("%sDUMP_RAW", others++ ? "|" : "");
        if (flags & DUMP_END)
                console("%sDUMP_END", others++ ? "|" : "");
	if (flags & LKCD_DUMP_MCLX_V0)
                console("%sLKCD_DUMP_MCLX_V0", others++ ? "|" : "");
        console(")\n");
}


/*
 *  help -S output, or as specified by arg.
 */
void
dump_lkcd_environment_v2_v3(ulong arg)
{
	int others;
        dump_header_t *dh;
	dump_header_asm_t *dha;
        dump_page_t *dp;

        dh = (dump_header_t *)lkcd->dump_header;
	dha = (dump_header_asm_t *)lkcd->dump_header_asm;
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
        if (dh->dh_dump_level & DUMP_HEADER)
                lkcd_print("%sDUMP_HEADER", others++ ? "|" : "");
        if (dh->dh_dump_level & DUMP_KERN)
                lkcd_print("%sDUMP_KERN", others++ ? "|" : "");
        if (dh->dh_dump_level & DUMP_USED)
                lkcd_print("%sDUMP_USED", others++ ? "|" : "");
        if (dh->dh_dump_level & DUMP_ALL)
                lkcd_print("%sDUMP_ALL", others++ ? "|" : "");
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

	lkcd_print("      dh_utsname:\n");
	lkcd_print("         sysname: %s\n", dh->dh_utsname.sysname);
	lkcd_print("        nodename: %s\n", dh->dh_utsname.nodename);
	lkcd_print("         release: %s\n", dh->dh_utsname.release);
	lkcd_print("         version: %s\n", dh->dh_utsname.version);
	lkcd_print("         machine: %s\n", dh->dh_utsname.machine);
	lkcd_print("      domainname: %s\n", dh->dh_utsname.domainname);

        lkcd_print(" dh_current_task: %lx\n", dh->dh_current_task);

	lkcd_print("dha_magic_number: ");
	lkcd_print(BITS32() ? "%llx  " : "%lx  ", dha->dha_magic_number);
        if (dha->dha_magic_number == DUMP_ASM_MAGIC_NUMBER)
                lkcd_print("(DUMP_ASM_MAGIC_NUMBER)\n");
        else
                lkcd_print("(?)\n");
	lkcd_print("     dha_version: ");
	lkcd_print(BITS32() ? "%ld\n" : "%d\n", dha->dha_version);
	lkcd_print(" dha_header_size: ");
	lkcd_print(BITS32() ? "%ld\n" : "%d\n", dha->dha_header_size);
#ifdef X86 
        lkcd_print("         dha_esp: %lx\n", dha->dha_esp);
        lkcd_print("         dha_eip: %lx\n", dha->dha_eip);
#endif
#if defined PPC || ALPHA || IA64
	/* TBD */
#endif
	lkcd_print("        dha_regs:\n");
#ifdef PPC
	lkcd_print("             (PowerPC register display TBD)\n");
#endif
#ifdef IA64
	lkcd_print("             (IA64 register display TBD)\n");
#endif
#ifdef X86
	lkcd_print("             ebx: %lx\n", dha->dha_regs.ebx);
	lkcd_print("             ecx: %lx\n", dha->dha_regs.ecx);
	lkcd_print("             edx: %lx\n", dha->dha_regs.edx);
	lkcd_print("             esi: %lx\n", dha->dha_regs.esi);
	lkcd_print("             edi: %lx\n", dha->dha_regs.edi);
	lkcd_print("             eax: %lx\n", dha->dha_regs.eax);
	lkcd_print("             xds: %x\n", dha->dha_regs.xds);
	lkcd_print("             xes: %x\n", dha->dha_regs.xes);
	lkcd_print("        orig_eax: %lx\n", dha->dha_regs.orig_eax);
	lkcd_print("             eip: %lx\n", dha->dha_regs.eip);
	lkcd_print("             xcs: %x\n", dha->dha_regs.xcs);
	lkcd_print("          eflags: %lx\n", dha->dha_regs.eflags);
	lkcd_print("             esp: %lx\n", dha->dha_regs.esp);
	lkcd_print("             xss: %x\n", dha->dha_regs.xss);
#endif
#ifdef ALPHA
	lkcd_print("              r0: %lx\n", dha->dha_regs.r0);
	lkcd_print("              r1: %lx\n", dha->dha_regs.r1);
	lkcd_print("              r2: %lx\n", dha->dha_regs.r2);
	lkcd_print("              r3: %lx\n", dha->dha_regs.r3);
	lkcd_print("              r4: %lx\n", dha->dha_regs.r4);
	lkcd_print("              r5: %lx\n", dha->dha_regs.r5);
	lkcd_print("              r6: %lx\n", dha->dha_regs.r6);
	lkcd_print("              r7: %lx\n", dha->dha_regs.r7);
	lkcd_print("              r8: %lx\n", dha->dha_regs.r8);
	lkcd_print("             r19: %lx\n", dha->dha_regs.r19);
	lkcd_print("             r20: %lx\n", dha->dha_regs.r20);
	lkcd_print("             r21: %lx\n", dha->dha_regs.r21);
	lkcd_print("             r22: %lx\n", dha->dha_regs.r22);
	lkcd_print("             r23: %lx\n", dha->dha_regs.r23);
	lkcd_print("             r24: %lx\n", dha->dha_regs.r24);
	lkcd_print("             r25: %lx\n", dha->dha_regs.r25);
	lkcd_print("             r26: %lx\n", dha->dha_regs.r26);
	lkcd_print("             r27: %lx\n", dha->dha_regs.r27);
	lkcd_print("             r28: %lx\n", dha->dha_regs.r28);
	lkcd_print("             hae: %lx\n", dha->dha_regs.hae);
	lkcd_print("         trap_a0: %lx\n", dha->dha_regs.trap_a0);
	lkcd_print("         trap_a1: %lx\n", dha->dha_regs.trap_a1);
	lkcd_print("         trap_a2: %lx\n", dha->dha_regs.trap_a2);
	lkcd_print("              ps: %lx\n", dha->dha_regs.ps);
	lkcd_print("              pc: %lx\n", dha->dha_regs.pc);
	lkcd_print("              gp: %lx\n", dha->dha_regs.gp);
	lkcd_print("             r16: %lx\n", dha->dha_regs.r16);
	lkcd_print("             r17: %lx\n", dha->dha_regs.r17);
	lkcd_print("             r18: %lx\n", dha->dha_regs.r18);
#endif

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
        if (dp->dp_flags & DUMP_COMPRESSED)
                lkcd_print("DUMP_COMPRESSED", others++);
        if (dp->dp_flags & DUMP_RAW)
                lkcd_print("%sDUMP_RAW", others++ ? "|" : "");
        if (dp->dp_flags & DUMP_END)
                lkcd_print("%sDUMP_END", others++ ? "|" : "");
        if (dp->dp_flags & LKCD_DUMP_MCLX_V0)
                lkcd_print("%sLKCD_DUMP_MCLX_V0", others++ ? "|" : "");
        lkcd_print(")\n");
}

/*
 *  Read the MCLX-enhanced page header cache.  Verify the first one, which
 *  is a pointer to the page header for address 1MB, and take the rest at 
 *  blind faith.  Note that the page headers do not include the 64K dump
 *  header offset, which must be added to the values found.
 */
static void
mclx_cache_page_headers_v3(void)
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
        if (read(lkcd->fd, dp, lkcd->page_header_size) != 
	    lkcd->page_header_size)
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
