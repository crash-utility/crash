/* lkcd_vmdump_v1.h - core analysis suite
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
 */


/*
 * Kernel header file for Linux crash dumps.
 *
 * Created by: Matt Robinson (yakker@sgi.com)
 *
 * Copyright 1999 Silicon Graphics, Inc. All rights reserved.
 * 
 */

/* This header file includes all structure definitions for crash dumps. */
#ifndef _VMDUMP_H
#define _VMDUMP_H

/* necessary header files */
#ifndef MCLX
#include <linux/utsname.h>              /* for utsname structure            */
#endif
#ifndef IA64
typedef unsigned int u32;
#include <asm/ptrace.h>                 /* for pt_regs                      */
#endif

/* necessary header definitions in all cases */
#define DUMP_KIOBUF_NUMBER  0xdeadbeef  /* special number for kiobuf maps   */

#ifdef CONFIG_VMDUMP
/* size of a dump header page */
#define DUMP_PAGE_SZ        64 * 1024  /* size of dump page buffer          */

/* standard header definitions */
#define DUMP_MAGIC_NUMBER   0xa8190173618f23edULL  /* dump magic number     */
#define DUMP_VERSION_NUMBER 0x1         /* dump version number              */
#define DUMP_PANIC_LEN      0x100       /* dump panic string length         */

/* dump flags -- add as necessary */
#define DUMP_RAW            0x1         /* raw page (no compression)        */
#define DUMP_COMPRESSED     0x2         /* page is compressed               */
#define DUMP_END            0x4         /* end marker on a full dump        */

/* dump types - type specific stuff added later for page typing */
#define DUMP_NONE           0           /* no dumping at all -- just bail   */
#define DUMP_HEADER         1           /* kernel dump header only          */
#define DUMP_KERN           2           /* dump header and kernel pages     */
#define DUMP_USED           3           /* dump header, kernel/user pages   */
#define DUMP_ALL            4           /* dump header, all memory pages    */

/*
 * Structure: dump_header_t
 *  Function: This is the header dumped at the top of every valid crash
 *            dump.  
 *            easy reassembly of each crash dump page.  The address bits
 *            are split to make things easier for 64-bit/32-bit system
 *            conversions.
 */
typedef struct _dump_header_s {
	/* the dump magic number -- unique to verify dump is valid */
	uint64_t             dh_magic_number;

	/* the version number of this dump */
	uint32_t             dh_version;

	/* the size of this header (in case we can't read it) */
	uint32_t             dh_header_size;

	/* the level of this dump (just a header?) */
	uint32_t             dh_dump_level;

	/* the size of a Linux memory page (4K, 8K, 16K, etc.) */
	uint32_t             dh_page_size;

	/* the size of all physical memory */
	uint64_t             dh_memory_size;

	/* the start of physical memory */
	uint64_t             dh_memory_start;

	/* the end of physical memory */
	uint64_t             dh_memory_end;

	/* the esp for i386 systems -- MOVE LATER */
	uint32_t             dh_esp;

	/* the eip for i386 systems -- MOVE LATER */
	uint32_t             dh_eip;

	/* the number of pages in this dump specifically */
	uint32_t             dh_num_pages;

	/* the panic string, if available */
	char                 dh_panic_string[DUMP_PANIC_LEN];

	/* the time of the system crash */
	struct timeval       dh_time;

	/* the utsname (uname) information */
	struct new_utsname   dh_utsname;

	/* the dump registers */
#if !defined(IA64) && !defined(S390) && !defined(S390X) && !defined(ARM64) && !defined(RISCV64)
	struct pt_regs       dh_regs;
#endif

	/* the address of the current task */
	struct task_struct  *dh_current_task;

} dump_header_t;

/*
 * Structure: dump_page_t
 *  Function: To act as the header associated to each physical page of
 *            memory saved in the system crash dump.  This allows for
 *            easy reassembly of each crash dump page.  The address bits
 *            are split to make things easier for 64-bit/32-bit system
 *            conversions.
 */
typedef struct _dump_page_s {
    
	/* the address of this dump page */
	uint64_t             dp_address;

	/* the size of this dump page */
	uint32_t             dp_size;

	/* flags (currently DUMP_COMPRESSED, DUMP_RAW or DUMP_END) */
	uint32_t             dp_flags;
} dump_page_t;

#endif /* CONFIG_VMDUMP */

#ifdef __KERNEL__
extern void dump_init(uint64_t, uint64_t);
extern void dump_open(char *);
extern void dump_execute(char *, struct pt_regs *);
#endif

#endif /* _VMDUMP_H */
