/* ibm_common.h - core analysis suite
 *
 * Copyright (C) 2001, 2002 Mission Critical Linux, Inc.
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

/*
 *  header file for zgetdump
 *    Copyright (C) 2001 IBM Deutschland Entwicklung GmbH, IBM Corporation
 *    Author(s): Despina Papadopoulou
 */

/* This header file holds the architecture specific crash dump header */
#ifndef _ZGETDUMP_H
#define _ZGETDUMP_H

/* definitions (this has to match with vmdump.h of lcrash */

#define DUMP_MAGIC_S390     0xa8190173618f23fdULL  /* s390 magic number     */
#define S390_DUMP_HEADER_SIZE     4096
#define DUMP_ASM_MAGIC_NUMBER     0xdeaddeadULL    /* magic number            */

/*
 * Structure: s390_dump_header_t
 *  Function: This is the header dumped at the top of every valid s390 crash
 *            dump.
 */

typedef struct _s390_dump_header_s {
        /* the dump magic number -- unique to verify dump is valid */
        uint64_t             dh_magic_number;                    /* 0x000 */

        /* the version number of this dump */
        uint32_t             dh_version;                         /* 0x008 */

        /* the size of this header (in case we can't read it) */
        uint32_t             dh_header_size;                     /* 0x00c */ 

        /* the level of this dump (just a header?) */
        uint32_t             dh_dump_level;                      /* 0x010 */

        /* the size of a Linux memory page (4K, 8K, 16K, etc.) */
        uint32_t             dh_page_size;                       /* 0x014 */

        /* the size of all physical memory */
        uint64_t             dh_memory_size;                     /* 0x018 */

        /* the start of physical memory */
        uint64_t             dh_memory_start;                    /* 0x020 */

        /* the end of physical memory */
        uint64_t             dh_memory_end;                      /* 0x028 */

        /* the number of pages in this dump specifically */
        uint32_t             dh_num_pages;                       /* 0x030 */

        /* ensure that dh_tod and dh_cpu_id are 8 byte aligned */
        uint32_t             dh_pad;                             /* 0x034 */
	
        /* the time of the dump generation using stck */
        uint64_t             dh_tod;                             /* 0x038 */

        /* cpu id */
        uint64_t             dh_cpu_id;                          /* 0x040 */

	/* arch */
	uint32_t             dh_arch;                            /* 0x048 */

	/* volume number */
	uint32_t             dh_volnr;                           /* 0x04c */

	/* build arch */
	uint32_t             dh_build_arch;                      /* 0x050 */

        /* fill up to 4096 byte */
        unsigned char        end_pad[0x1000-0x054];              /* 0x054 */

} __attribute__((packed))  s390_dump_header_t;

/*
 * Structure: s390_dump_end_marker_t
 *  Function: This end marker should be at the end of every valid s390 crash
 *            dump.
 */

typedef struct _s390_dump_end_marker_{
        char end_string[8];
        unsigned long long end_time;
} __attribute__((packed)) s390_dump_end_marker_t; 

#endif /* _ASM_VMDUMP_H */
