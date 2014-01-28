/* lkcd_dump_v5.h - core analysis suite
 *
 * Copyright (C) 2001, 2002 Mission Critical Linux, Inc.
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
 * Copyright 1999 Silicon Graphics, Inc. All rights reserved.
 *
 * vmdump.h to dump.h by: Matt D. Robinson (yakker@sourceforge.net)
 * Copyright 2001 Matt D. Robinson.  All rights reserved.
 *
 * Most of this is the same old stuff from vmdump.h, except now we're
 * actually a stand-alone driver plugged into the block layer interface,
 * with the exception that we now allow for compression modes externally
 * loaded (e.g., someone can come up with their own).
 */

/* This header file includes all structure definitions for crash dumps. */
#ifndef _DUMP_H
#define _DUMP_H

//#include <linux/list.h>

/* define TRUE and FALSE for use in our dump modules */
#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef MCLX                   

/* 
 *  MCLX NOTE: the architecture-specific headers are being ignored until
 *  deemed necessary; crash has never used them functionally, and only
 *  referencing them in the dump_sgi_environment() helper routines.
 */

/* necessary header files */
#include <asm/dump.h>                   /* for architecture-specific header */
#endif

#define UTSNAME_ENTRY_SZ 65

/* necessary header definitions in all cases */
#define DUMP_KIOBUF_NUMBER  0xdeadbeef  /* special number for kiobuf maps   */

/* size of a dump header page */
#define DUMP_PAGE_SZ        64 * 1024  /* size of dump page buffer          */

/* header definitions for s390 dump */
#define DUMP_MAGIC_S390     0xa8190173618f23fdULL  /* s390 magic number     */
#define S390_DUMP_HEADER_SIZE     4096

/* standard header definitions */
#define DUMP_MAGIC_NUMBER   0xa8190173618f23edULL  /* dump magic number     */
#define DUMP_MAGIC_LIVE     0xa8190173618f23cdULL  /* live magic number     */
#define DUMP_VERSION_NUMBER   0x5       /* dump version number              */
#define DUMP_PANIC_LEN        0x100     /* dump panic string length         */

/* dump levels - type specific stuff added later -- add as necessary */
#define DUMP_LEVEL_NONE        0x0      /* no dumping at all -- just bail   */
#define DUMP_LEVEL_HEADER      0x1      /* kernel dump header only          */
#define DUMP_LEVEL_KERN        0x2      /* dump header and kernel pages     */
#define DUMP_LEVEL_USED        0x4      /* dump header, kernel/user pages   */
#define DUMP_LEVEL_ALL         0x8      /* dump header, all memory pages    */

/* dump compression options -- add as necessary */
#define DUMP_COMPRESS_NONE     0x0      /* don't compress this dump         */
#define DUMP_COMPRESS_RLE      0x1      /* use RLE compression              */
#define DUMP_COMPRESS_GZIP     0x2      /* use GZIP compression             */

/* dump flags - any dump-type specific flags -- add as necessary */
#define DUMP_FLAGS_NONE        0x0      /* no flags are set for this dump   */
#define DUMP_FLAGS_NONDISRUPT  0x1      /* try to keep running after dump   */

/* dump header flags -- add as necessary */
#define DUMP_DH_FLAGS_NONE     0x0      /* no flags set (error condition!)  */
#define DUMP_DH_RAW            0x1      /* raw page (no compression)        */
#define DUMP_DH_COMPRESSED     0x2      /* page is compressed               */
#define DUMP_DH_END            0x4      /* end marker on a full dump        */

/* names for various dump tunables (they are now all read-only) */
#define DUMP_ROOT_NAME         "sys/dump"
#define DUMP_DEVICE_NAME       "dump_device"
#define DUMP_COMPRESS_NAME     "dump_compress"
#define DUMP_LEVEL_NAME        "dump_level"
#define DUMP_FLAGS_NAME        "dump_flags"

/* page size for gzip compression -- buffered beyond PAGE_SIZE slightly */
#define DUMP_DPC_PAGE_SIZE     (PAGE_SIZE + 512)

/* dump ioctl() control options */
#define DIOSDUMPDEV		1       /* set the dump device              */
#define DIOGDUMPDEV		2       /* get the dump device              */
#define DIOSDUMPLEVEL		3       /* set the dump level               */
#define DIOGDUMPLEVEL		4       /* get the dump level               */
#define DIOSDUMPFLAGS		5       /* set the dump flag parameters     */
#define DIOGDUMPFLAGS		6       /* get the dump flag parameters     */
#define DIOSDUMPCOMPRESS	7       /* set the dump compress level      */
#define DIOGDUMPCOMPRESS	8       /* get the dump compress level      */

/* the major number used for the dumping device */
#ifndef DUMP_MAJOR
#define DUMP_MAJOR              227
#endif

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

	/* the number of pages in this dump specifically */
	uint32_t             dh_num_pages;

	/* the panic string, if available */
	char                 dh_panic_string[DUMP_PANIC_LEN];

	/* the time of the system crash */
	struct timeval       dh_time;

	/* the NEW utsname (uname) information -- in character form */
	/* we do this so we don't have to include utsname.h         */
	/* plus it helps us be more architecture independent        */
	/* now maybe one day soon they'll make the [65] a #define!  */
	char                 dh_utsname_sysname[65];
	char                 dh_utsname_nodename[65];
	char                 dh_utsname_release[65];
	char                 dh_utsname_version[65];
	char                 dh_utsname_machine[65];
	char                 dh_utsname_domainname[65];

	/* the address of current task (OLD = task_struct *, NEW = void *) */
	void                *dh_current_task;

	/* what type of compression we're using in this dump (if any) */
	uint32_t             dh_dump_compress;

	/* any additional flags */
	uint32_t             dh_dump_flags;

	/* any additional flags */
	uint32_t             dh_dump_device;

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

/*
 * This structure contains information needed for the lkcdutils
 * package (particularly lcrash) to determine what information is
 * associated to this kernel, specifically.
 */
typedef struct lkcdinfo_s {
	int             arch;
	int             ptrsz;
	int             byte_order;
	int             linux_release;
	int             page_shift;
	int             page_size;
	uint64_t        page_mask;
	uint64_t        page_offset;
	int             stack_offset;
} lkcdinfo_t;

#ifdef __KERNEL__

/*
 * Structure: dump_compress_t
 *  Function: This is what an individual compression mechanism can use
 *            to plug in their own compression techniques.  It's always
 *            best to build these as individual modules so that people
 *            can put in whatever they want.
 */
typedef struct dump_compress_s {
	/* the list_head structure for list storage */
	struct list_head list;

	/* the type of compression to use (DUMP_COMPRESS_XXX) */
        int compress_type;

	/* the compression function to call */
        int (*compress_func)(char *, int, char *, int);
} dump_compress_t;

extern int dump_init(void);
extern void dump_execute(char *, struct pt_regs *);
extern int page_is_ram(unsigned long);

#endif /* __KERNEL__ */

#endif /* _DUMP_H */
