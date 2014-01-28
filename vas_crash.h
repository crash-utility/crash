/* vas_crash.h - kernel crash dump file format (on swap)
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002, 2003, 2004, 2005, 2006 David Anderson
 * Copyright (C) 2002, 2003, 2004, 2005, 2006 Red Hat, Inc. All rights reserved.
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

#include <sys/types.h>
//#include <asm/page.h>

void save_core(void);


/*  struct crash_map_hdr located at byte offset 0 */
/* on-disk formats */

#define trunc_page(x)   ((void *)(((unsigned long)(x)) & ~((unsigned long)(Page_Size - 1))))
#define round_page(x)   trunc_page(((unsigned long)(x)) + ((unsigned long)(Page_Size - 1)))

#define CRASH_MAGIC 0x9a8bccdd
#define CRASH_SOURCE_PAGES 128
#define CRASH_SUB_MAP_BYTES ((u_long)round_page((CRASH_SOURCE_PAGES+1)*sizeof(u_long)))
#define CRASH_SUB_MAP_PAGES (CRASH_SUB_MAP_BYTES / Page_Size)
#define CRASH_UNCOMPR_BUF_PAGES (CRASH_SOURCE_PAGES + CRASH_SUB_MAP_PAGES)
#define CRASH_COMPR_BUF_PAGES (CRASH_UNCOMPR_BUF_PAGES + (CRASH_UNCOMPR_BUF_PAGES/4))
#define CRASH_COMPESS_PRIME_PAGES (2*CRASH_COMPR_BUF_PAGES)
#define CRASH_ZALLOC_PAGES 16*5*2   /* 2 to handle crash in crash */
#define CRASH_LOW_WATER_PAGES 100

#define HP_BIOS_HIGH_PAGES_USED 2000

#define CRASH_MARK_RESERVED(addr) (set_bit(PG_reserved,&mem_map[MAP_NR(addr)].flags))
#define CRASH_CLEAR_RESERVED(addr) (clear_bit(PG_reserved,&mem_map[MAP_NR(addr)].flags))

#ifdef NOT_DEF
typedef int boolean_t;
#endif

#define TRUE 1
#define FALSE 0



/* mem structure */

struct mem_crash_map_hdr {
      long magic[4];                 /* identify crash dump */
      u_long map;                    /* location of map */
      u_long map_pages;
      u_long data_pages;
      u_long compr_units;
};
struct mem_crash_map_entry {
      u_long src_va;                 /* source start of larger non-contig block */
                                     /* a src_va of -1 means that the dest_page_va
				      *	is the location of the next map page */
      u_long dest_page_va;           /* dest of this sub block */
      u_long check_sum;              /* check_sum for dest data */
};


/* file structure */

struct crash_map_hdr {
      long magic[4];                 /* identify crash dump */
      int blk_size;                  /* block size for this device */
      int map_block;                 /* location of map */
      int map_blocks;                /* number of blocks for map */
};
struct crash_map_entry {
      u_long start_va;               /* virtual address */
      char *exp_data;                /* expanded data in memory */
      int start_blk;                 /* device location */
      int num_blks;
};

#define CRASH_OFFSET_BLKS 100
#define CRASH_MAGIC 0x9a8bccdd
struct crash_map_hdr_v1 {
      long magic[4];                 /* identify crash dump */
      int blk_size;                  /* block size for this device */
      int map_block;                 /* location of map */
      int map_blocks;                /* number of blocks for map */
      int map_entries;
      u_long va_per_entry;           /* va covered by each map_entry */
      u_long bytes_not_dumped;       /* ran out of swap space */
      int total_blocks;              /* CRASH_OFFSET_BLKS + header + map + data */
};
struct crash_map_entry_v1 {
      u_long start_va;               /* virtual address */
      char *exp_data;                /* expanded data in memory */
      int start_blk;                 /* device location */
      int num_blks;
      int chk_sum;                   /* check sum */
};
