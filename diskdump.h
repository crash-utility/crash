/* 
 * diskdump.h
 *
 * Copyright (C) 2004, 2005, 2006  David Anderson
 * Copyright (C) 2004, 2005, 2006  Red Hat, Inc. All rights reserved.
 * Copyright (C) 2005  FUJITSU LIMITED
 * Copyright (C) 2005  NEC Corporation
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

#include <elf.h>

#define divideup(x, y)	(((x) + ((y) - 1)) / (y))
#define round(x, y)	(((x) / (y)) * (y))

#define DUMP_PARTITION_SIGNATURE	"diskdump"
#define SIG_LEN (sizeof(DUMP_PARTITION_SIGNATURE) - 1)
#define DISK_DUMP_SIGNATURE		"DISKDUMP"
#define KDUMP_SIGNATURE			"KDUMP   "

#define DUMP_HEADER_COMPLETED	0
#define DUMP_HEADER_INCOMPLETED 1
#define DUMP_HEADER_COMPRESSED  8

struct disk_dump_header {
	char			signature[SIG_LEN];	/* = "DISKDUMP" */
	int			header_version; /* Dump header version */
	struct new_utsname	utsname;	/* copy of system_utsname */
	struct timeval		timestamp;	/* Time stamp */
	unsigned int		status; 	/* Above flags */
	int			block_size;	/* Size of a block in byte */
	int			sub_hdr_size;	/* Size of arch dependent
						   header in blocks */
	unsigned int		bitmap_blocks;	/* Size of Memory bitmap in
						   block */
	unsigned int		max_mapnr;	/* = max_mapnr, OBSOLETE!
						   32bit only, full 64bit
						   in sub header. */
	unsigned int		total_ram_blocks;/* Number of blocks should be
						   written */
	unsigned int		device_blocks;	/* Number of total blocks in
						 * the dump device */
	unsigned int		written_blocks; /* Number of written blocks */
	unsigned int		current_cpu;	/* CPU# which handles dump */
	int			nr_cpus;	/* Number of CPUs */
	struct task_struct	*tasks[0];
};

struct disk_dump_sub_header {
	long		elf_regs;
};

struct kdump_sub_header {
	unsigned long	phys_base;
	int		dump_level;         /* header_version 1 and later */
	int		split;              /* header_version 2 and later */
	unsigned long	start_pfn;          /* header_version 2 and later,
					       OBSOLETE! 32bit only, full 64bit
					       in start_pfn_64. */
	unsigned long	end_pfn;            /* header_version 2 and later,
					       OBSOLETE! 32bit only, full 64bit
					       in end_pfn_64. */
	off_t		offset_vmcoreinfo;  /* header_version 3 and later */
	unsigned long	size_vmcoreinfo;    /* header_version 3 and later */
	off_t		offset_note;        /* header_version 4 and later */
	unsigned long	size_note;          /* header_version 4 and later */
	off_t		offset_eraseinfo;   /* header_version 5 and later */
	unsigned long	size_eraseinfo;     /* header_version 5 and later */
	unsigned long long start_pfn_64;    /* header_version 6 and later */
	unsigned long long end_pfn_64;      /* header_version 6 and later */
	unsigned long long max_mapnr_64;    /* header_version 6 and later */
};

/* page flags */
#define DUMP_DH_COMPRESSED_ZLIB    0x1   /* page is compressed with zlib */
#define DUMP_DH_COMPRESSED_LZO     0x2   /* page is compressed with lzo */
#define DUMP_DH_COMPRESSED_SNAPPY  0x4   /* page is compressed with snappy */
#define DUMP_DH_COMPRESSED_INCOMPLETE  0x8   /* dumpfile is incomplete */
#define DUMP_DH_EXCLUDED_VMEMMAP   0x10  /* unused vmemmap pages are excluded */
#define DUMP_DH_COMPRESSED_ZSTD    0x20  /* page is compressed with zstd */

/* descriptor of each page for vmcore */
typedef struct page_desc {
	off_t			offset;		/* the offset of the page data*/
	unsigned int		size;		/* the size of this dump page */
	unsigned int		flags;		/* flags */
	unsigned long long	page_flags;	/* page flags */
} page_desc_t;

#define DISKDUMP_CACHED_PAGES	(16)
#define PAGE_VALID		(0x1)	/* flags */
#define DISKDUMP_VALID_PAGE(flags)	((flags) & PAGE_VALID)

