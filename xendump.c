/* 
 * xendump.c 
 * 
 * Copyright (C) 2006-2011, 2013-2014 David Anderson
 * Copyright (C) 2006-2011, 2013-2014 Red Hat, Inc. All rights reserved.
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

#include "defs.h"
#include "xendump.h"

static struct xendump_data xendump_data = { 0 };
struct xendump_data *xd = &xendump_data;

static int xc_save_verify(char *);
static int xc_core_verify(char *, char *);
static int xc_save_read(void *, int, ulong, physaddr_t);
static int xc_core_read(void *, int, ulong, physaddr_t);
static int xc_core_mfns(ulong, FILE *);

static void poc_store(ulong, off_t);
static off_t poc_get(ulong, int *);

static void xen_dump_vmconfig(FILE *);

static void xc_core_create_pfn_tables(void);
static ulong xc_core_pfn_to_page_index(ulong);
static int xc_core_pfn_valid(ulong);

static void xendump_print(char *fmt, ...);

static int xc_core_elf_verify(char *, char *);
static void xc_core_elf_dump(void);
static char *xc_core_elf_mfn_to_page(ulong, char *);
static int xc_core_elf_mfn_to_page_index(ulong);
static ulong xc_core_elf_pfn_valid(ulong);
static ulong xc_core_elf_pfn_to_page_index(ulong);
static void xc_core_dump_Elf32_Ehdr(Elf32_Ehdr *);
static void xc_core_dump_Elf64_Ehdr(Elf64_Ehdr *);
static void xc_core_dump_Elf32_Shdr(Elf32_Off offset, int);
static void xc_core_dump_Elf64_Shdr(Elf64_Off offset, int);
static char *xc_core_strtab(uint32_t, char *);
static void xc_core_dump_elfnote(off_t, size_t, int);
static void xc_core_elf_pfn_init(void);

#define ELFSTORE 1
#define ELFREAD  0

/*
 *  Determine whether a file is a xendump creation, and if TRUE,
 *  initialize the xendump_data structure.
 */
int
is_xendump(char *file)
{
	int verified;
	char buf[BUFSIZE];

        if ((xd->xfd = open(file, O_RDWR)) < 0) {
                if ((xd->xfd = open(file, O_RDONLY)) < 0) {
                        sprintf(buf, "%s: open", file);
                        perror(buf);
                        return FALSE;
                }
        }

	if (read(xd->xfd, buf, BUFSIZE) != BUFSIZE) 
		return FALSE;

        if (machine_type("X86") || machine_type("X86_64"))
                xd->page_size = 4096;
	else if (machine_type("IA64") && !machdep->pagesize)
		xd->page_size = 16384;
	else 
                xd->page_size = machdep->pagesize;

	verified = xc_save_verify(buf) || xc_core_verify(file, buf);

	if (!verified)
		close(xd->xfd);

	return (verified);
}

/*
 *  Verify whether the dump was created by the xc_domain_dumpcore()
 *  library function in libxc/xc_core.c.
 */
static int
xc_core_verify(char *file, char *buf)
{
	struct xc_core_header *xcp;

	xcp = (struct xc_core_header *)buf;

	if (xc_core_elf_verify(file, buf))
		return TRUE;

	if ((xcp->xch_magic != XC_CORE_MAGIC) && 
	    (xcp->xch_magic != XC_CORE_MAGIC_HVM))
		return FALSE;

	if (!xcp->xch_nr_vcpus) {
		error(INFO, 
		    "faulty xc_core dump file header: xch_nr_vcpus is 0\n\n");

        	fprintf(stderr, "         xch_magic: %x\n", xcp->xch_magic);
        	fprintf(stderr, "      xch_nr_vcpus: %d\n", xcp->xch_nr_vcpus);
        	fprintf(stderr, "      xch_nr_pages: %d\n", xcp->xch_nr_pages);
        	fprintf(stderr, "   xch_ctxt_offset: %d\n", xcp->xch_ctxt_offset);
        	fprintf(stderr, "  xch_index_offset: %d\n", xcp->xch_index_offset);
        	fprintf(stderr, "  xch_pages_offset: %d\n\n", xcp->xch_pages_offset);

		clean_exit(1);
	}

	xd->xc_core.header.xch_magic = xcp->xch_magic;
	xd->xc_core.header.xch_nr_vcpus = xcp->xch_nr_vcpus;
	xd->xc_core.header.xch_nr_pages = xcp->xch_nr_pages;
	xd->xc_core.header.xch_ctxt_offset = (off_t)xcp->xch_ctxt_offset;
	xd->xc_core.header.xch_index_offset = (off_t)xcp->xch_index_offset;
	xd->xc_core.header.xch_pages_offset = (off_t)xcp->xch_pages_offset;

        xd->flags |= (XENDUMP_LOCAL | XC_CORE_ORIG | XC_CORE_P2M_CREATE);

	if (xc_core_mfns(XC_CORE_64BIT_HOST, stderr))
		xd->flags |= XC_CORE_64BIT_HOST;

	if (!xd->page_size)
		error(FATAL,
		    "unknown page size: use -p <pagesize> command line option\n");

	if (!(xd->page = (char *)malloc(xd->page_size)))
		error(FATAL, "cannot malloc page space.");

        if (!(xd->poc = (struct pfn_offset_cache *)calloc
            (PFN_TO_OFFSET_CACHE_ENTRIES,
            sizeof(struct pfn_offset_cache))))
                error(FATAL, "cannot malloc pfn_offset_cache\n");
	xd->last_pfn = ~(0UL);

	if (CRASHDEBUG(1)) 
                xendump_memory_dump(stderr);

	return TRUE;
}

/*
 *  Do the work for read_xendump() for the XC_CORE dumpfile format.
 */
static int
xc_core_read(void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
        ulong pfn, page_index;
	off_t offset;
	int redundant;

	if (xd->flags & (XC_CORE_P2M_CREATE|XC_CORE_PFN_CREATE))
		xc_core_create_pfn_tables();

        pfn = (ulong)BTOP(paddr);

        if ((offset = poc_get(pfn, &redundant))) {
                if (!redundant) {
                        if (lseek(xd->xfd, offset, SEEK_SET) == -1)
                                return SEEK_ERROR;
                        if (read(xd->xfd, xd->page, xd->page_size) != 
			    xd->page_size)
                                return READ_ERROR;
			xd->last_pfn = pfn;
                }

                BCOPY(xd->page + PAGEOFFSET(paddr), bufptr, cnt);
                return cnt;
        }

	if ((page_index = xc_core_pfn_to_page_index(pfn)) == 
	    PFN_NOT_FOUND)
		return READ_ERROR;

	offset = xd->xc_core.header.xch_pages_offset +
		((off_t)(page_index) * (off_t)xd->page_size);

	if (lseek(xd->xfd, offset, SEEK_SET) == -1) 
 		return SEEK_ERROR;

	if (read(xd->xfd, xd->page, xd->page_size) != xd->page_size)
		return READ_ERROR;

	poc_store(pfn, offset);

	BCOPY(xd->page + PAGEOFFSET(paddr), bufptr, cnt);

	return cnt;
}

/*
 *  Verify whether the dumpfile was created by the "xm save" facility.
 *  This gets started by the "save" function in XendCheckpoint.py, and
 *  then by xc_save.c, with the work done in the xc_linux_save() library
 *  function in libxc/xc_linux_save.c.
 */

#define MAX_BATCH_SIZE  1024
/*
 *  Number of P2M entries in a page.
 */
#define ULPP (xd->page_size/sizeof(unsigned long))
/*
 *  Number of P2M entries in the pfn_to_mfn_frame_list.
 */
#define P2M_FL_ENTRIES  (((xd->xc_save.nr_pfns)+ULPP-1)/ULPP)
/*
 *  Size in bytes of the pfn_to_mfn_frame_list.
 */
#define P2M_FL_SIZE     ((P2M_FL_ENTRIES)*sizeof(unsigned long))

#define XTAB  (0xf<<28) /* invalid page */
#define LTAB_MASK XTAB

static int
xc_save_verify(char *buf)
{
	int i, batch_count, done_batch, *intptr;
	ulong flags, *ulongptr;
	ulong batch_index, total_pages_read;
	ulong N;

	if (!STRNEQ(buf, XC_SAVE_SIGNATURE))
		return FALSE;

	if (lseek(xd->xfd, strlen(XC_SAVE_SIGNATURE), SEEK_SET) == -1)
		return FALSE;

	flags = XC_SAVE;

	if (CRASHDEBUG(1)) {
		fprintf(stderr, "\"%s\"\n", buf); 
		fprintf(stderr, "endian: %d %s\n", __BYTE_ORDER, 
		    __BYTE_ORDER == __BIG_ENDIAN ? "__BIG_ENDIAN" :
		    (__BYTE_ORDER == __LITTLE_ENDIAN ? 
		    "__LITTLE_ENDIAN" : "???"));
	}
		  
	/*
	 *  size of vmconfig data structure (big-endian)
	 */
	if (read(xd->xfd, buf, sizeof(int)) != sizeof(int))
		return FALSE;

	intptr = (int *)buf;

	if (CRASHDEBUG(1) && BYTE_SWAP_REQUIRED(__BIG_ENDIAN)) {
		fprintf(stderr, "byte-swap required for this:\n");
		for (i = 0; i < sizeof(int); i++) 
			fprintf(stderr, "[%x]", buf[i] & 0xff);
		fprintf(stderr, ": %x -> ", *intptr);
	}
	
	xd->xc_save.vmconfig_size = swab32(*intptr);

	if (CRASHDEBUG(1))
		fprintf(stderr, "%x\n", xd->xc_save.vmconfig_size);

	if (!(xd->xc_save.vmconfig_buf = (char *)malloc
	    (xd->xc_save.vmconfig_size)))
		error(FATAL, "cannot malloc xc_save vmconfig space.");

	if (!xd->page_size)
		error(FATAL, 
		    "unknown page size: use -p <pagesize> command line option\n");

	if (!(xd->page = (char *)malloc(xd->page_size)))
		error(FATAL, "cannot malloc page space.");

	if (!(xd->poc = (struct pfn_offset_cache *)calloc
	    (PFN_TO_OFFSET_CACHE_ENTRIES, 
	    sizeof(struct pfn_offset_cache))))
		error(FATAL, "cannot malloc pfn_offset_cache\n");
	xd->last_pfn = ~(0UL);

	if (!(xd->xc_save.region_pfn_type = (ulong *)calloc
	    (MAX_BATCH_SIZE, sizeof(ulong))))
		error(FATAL, "cannot malloc region_pfn_type\n");

	if (read(xd->xfd, xd->xc_save.vmconfig_buf, 
	    xd->xc_save.vmconfig_size) != xd->xc_save.vmconfig_size)
		goto xc_save_bailout;

	/*
	 *  nr_pfns (native byte order)
	 */
	if (read(xd->xfd, buf, sizeof(ulong)) != sizeof(ulong))
		goto xc_save_bailout;

	ulongptr = (ulong *)buf;

	if (CRASHDEBUG(1)) {
		for (i = 0; i < sizeof(ulong); i++)
			fprintf(stderr, "[%x]", buf[i] & 0xff);
		fprintf(stderr, ": %lx (nr_pfns)\n", *ulongptr);
	}

	xd->xc_save.nr_pfns = *ulongptr;

	if (machine_type("IA64"))
		goto xc_save_ia64;

    	/* 
	 *  Get a local copy of the live_P2M_frame_list 
	 */
	if (!(xd->xc_save.p2m_frame_list = (unsigned long *)malloc(P2M_FL_SIZE))) 
        	error(FATAL, "cannot allocate p2m_frame_list array");

	if (!(xd->xc_save.batch_offsets = (off_t *)calloc((size_t)P2M_FL_ENTRIES, 
	    sizeof(off_t))))
        	error(FATAL, "cannot allocate batch_offsets array");

	xd->xc_save.batch_count = P2M_FL_ENTRIES;
		
	if (read(xd->xfd, xd->xc_save.p2m_frame_list, P2M_FL_SIZE) != 
	    P2M_FL_SIZE)
		goto xc_save_bailout;

	if (CRASHDEBUG(1))
		fprintf(stderr, "pre-batch file pointer: %lld\n", 
			(ulonglong)lseek(xd->xfd, 0L, SEEK_CUR));

	/*
	 *  ...
	 *  int batch_count
	 *  ulong region pfn_type[batch_count]
	 *  page 0
	 *  page 1
	 *  ...
	 *  page batch_count-1
	 *  (repeat)
	 */

	total_pages_read = 0;
	batch_index = 0;
	done_batch = FALSE;

	while (!done_batch) {

		xd->xc_save.batch_offsets[batch_index] = (off_t)
			lseek(xd->xfd, 0L, SEEK_CUR);

		if (read(xd->xfd, &batch_count, sizeof(int)) != sizeof(int))
			goto xc_save_bailout;

		if (CRASHDEBUG(1))
			fprintf(stderr, "batch[%ld]: %d ", 
				batch_index, batch_count); 

		batch_index++;

		if (batch_index >= P2M_FL_ENTRIES) {
			fprintf(stderr, "more than %ld batches encountered?\n",
				P2M_FL_ENTRIES);
			goto xc_save_bailout;
		}

	 	switch (batch_count)
	 	{
	 	case 0:
			if (CRASHDEBUG(1)) {
	 		    fprintf(stderr, 
			        ": Batch work is done: %ld pages read (P2M_FL_ENTRIES: %ld)\n", 
				    total_pages_read, P2M_FL_ENTRIES);
			}
			done_batch = TRUE;
			continue;

	 	case -1:
			if (CRASHDEBUG(1))
	 			fprintf(stderr, ": Entering page verify mode\n");
			continue;

	 	default:
	 		if (batch_count > MAX_BATCH_SIZE) {
				if (CRASHDEBUG(1))
	             		    fprintf(stderr, 
					": Max batch size exceeded. Giving up.\n");
				done_batch = TRUE;
				continue;
	 		}
			if (CRASHDEBUG(1))
	 			fprintf(stderr, "\n");
			break;
		}

		if (read(xd->xfd, xd->xc_save.region_pfn_type, batch_count * sizeof(ulong)) != 
	    	    batch_count * sizeof(ulong))
			goto xc_save_bailout;

		for (i = 0; i < batch_count; i++) {
			unsigned long pagetype;
			unsigned long pfn;
	
	            	pfn = xd->xc_save.region_pfn_type[i] & ~LTAB_MASK;
	            	pagetype = xd->xc_save.region_pfn_type[i] & LTAB_MASK;
	
		        if (pagetype == XTAB) 
			    /* a bogus/unmapped page: skip it */
	                	continue;
	
	            	if (pfn > xd->xc_save.nr_pfns) {
				if (CRASHDEBUG(1))
	                	    fprintf(stderr, 
				 	"batch_count: %d pfn %ld out of range",
						batch_count, pfn);
	            	}

			if (lseek(xd->xfd, xd->page_size, SEEK_CUR) == -1)
				goto xc_save_bailout;
	
			total_pages_read++;
		}
	}	

	/* 
	 *  Get the list of PFNs that are not in the psuedo-phys map 
	 */
	if (read(xd->xfd, &xd->xc_save.pfns_not, 
	    sizeof(xd->xc_save.pfns_not)) != sizeof(xd->xc_save.pfns_not))
		goto xc_save_bailout;

	if (CRASHDEBUG(1))
		fprintf(stderr, "PFNs not in pseudo-phys map: %d\n", 
			xd->xc_save.pfns_not);

	if ((total_pages_read + xd->xc_save.pfns_not) != 
	    xd->xc_save.nr_pfns)
		error(WARNING, 
		    "nr_pfns: %ld != (total pages: %ld + pages not saved: %d)\n",
			xd->xc_save.nr_pfns, total_pages_read, 
			xd->xc_save.pfns_not);

	xd->xc_save.pfns_not_offset = lseek(xd->xfd, 0L, SEEK_CUR);

	if (lseek(xd->xfd, sizeof(ulong) * xd->xc_save.pfns_not, SEEK_CUR) == -1)
		goto xc_save_bailout;

	xd->xc_save.vcpu_ctxt_offset = lseek(xd->xfd, 0L, SEEK_CUR);

	lseek(xd->xfd, 0, SEEK_END);
	lseek(xd->xfd,  -((off_t)(xd->page_size)), SEEK_CUR);

	xd->xc_save.shared_info_page_offset = lseek(xd->xfd, 0L, SEEK_CUR);

	xd->flags |= (XENDUMP_LOCAL | flags);
	kt->xen_flags |= (CANONICAL_PAGE_TABLES|XEN_SUSPEND);

	if (CRASHDEBUG(1))
		xendump_memory_dump(stderr);

	return TRUE;

xc_save_ia64:

	/*
	 *  Completely different format for ia64:
         *
         *    ...
         *    pfn #
         *    page data
         *    pfn #
         *    page data
         *    ...
	 */
	free(xd->poc); 
	xd->poc = NULL;
	free(xd->xc_save.region_pfn_type); 
	xd->xc_save.region_pfn_type = NULL;

	if (!(xd->xc_save.ia64_page_offsets = 
	    (ulong *)calloc(xd->xc_save.nr_pfns, sizeof(off_t)))) 
        	error(FATAL, "cannot allocate ia64_page_offsets array");

        /*
         *  version
         */
        if (read(xd->xfd, buf, sizeof(ulong)) != sizeof(ulong))
                goto xc_save_bailout;

	xd->xc_save.ia64_version = *((ulong *)buf);

	if (CRASHDEBUG(1))
		fprintf(stderr, "ia64 version: %lx\n", 
			xd->xc_save.ia64_version);

	/*
	 *  xen_domctl_arch_setup structure
	 */
        if (read(xd->xfd, buf, sizeof(xen_domctl_arch_setup_t)) != 
	    sizeof(xen_domctl_arch_setup_t))
                goto xc_save_bailout;

	if (CRASHDEBUG(1)) {
		xen_domctl_arch_setup_t *setup = 
			(xen_domctl_arch_setup_t *)buf;

		fprintf(stderr, "xen_domctl_arch_setup:\n");
		fprintf(stderr, "        flags: %lx\n", (ulong)setup->flags);
		fprintf(stderr, "           bp: %lx\n", (ulong)setup->bp);
		fprintf(stderr, "       maxmem: %lx\n", (ulong)setup->maxmem);
		fprintf(stderr, "       xsi_va: %lx\n", (ulong)setup->xsi_va);
		fprintf(stderr, "hypercall_imm: %x\n", setup->hypercall_imm);
	}

	for (i = N = 0; i < xd->xc_save.nr_pfns; i++) {
        	if (read(xd->xfd, &N, sizeof(N)) != sizeof(N))
                	goto xc_save_bailout;

		if (N < xd->xc_save.nr_pfns)
			xd->xc_save.ia64_page_offsets[N] = 
				lseek(xd->xfd, 0, SEEK_CUR);
		else
			error(WARNING, 	
			    "[%d]: pfn of %lx (0x%lx) in ia64 canonical page list exceeds %ld\n",	
				i, N, N, xd->xc_save.nr_pfns);

		if (CRASHDEBUG(1)) {
			if ((i < 10) || (N >= (xd->xc_save.nr_pfns-10))) 
				fprintf(stderr, "[%d]: %ld\n%s", i, N,
					i == 9 ? "...\n" : "");	
		}

		if ((N+1) >= xd->xc_save.nr_pfns)
			break;

		if (lseek(xd->xfd, xd->page_size, SEEK_CUR) == -1)
                	goto xc_save_bailout;
	}

	if (CRASHDEBUG(1)) {
		for (i = N = 0; i < xd->xc_save.nr_pfns; i++) {
			if (!xd->xc_save.ia64_page_offsets[i])
				N++;
		}
		fprintf(stderr, "%ld out of %ld pfns not dumped\n",
			N,  xd->xc_save.nr_pfns);
	}

	xd->flags |= (XENDUMP_LOCAL | flags | XC_SAVE_IA64);
	kt->xen_flags |= (CANONICAL_PAGE_TABLES|XEN_SUSPEND);

	if (CRASHDEBUG(1))
		xendump_memory_dump(stderr);

	return TRUE;

xc_save_bailout:

	error(INFO, 
	    "xc_save_verify: \"LinuxGuestRecord\" file handling/format error\n");

	if (xd->xc_save.p2m_frame_list) {
		free(xd->xc_save.p2m_frame_list);
		xd->xc_save.p2m_frame_list = NULL;
	}
	if (xd->xc_save.batch_offsets) {
		free(xd->xc_save.batch_offsets);
		xd->xc_save.batch_offsets = NULL;
	}
	if (xd->xc_save.vmconfig_buf) {
		free(xd->xc_save.vmconfig_buf);
		xd->xc_save.vmconfig_buf = NULL;
	}
	if (xd->page) {
		free(xd->page);
		xd->page = NULL;
	}

	return FALSE;
}

/*
 *  Do the work for read_xendump() for the XC_SAVE dumpfile format.
 */
static int
xc_save_read(void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	int b, i, redundant;
	ulong reqpfn;
	int batch_count;
	off_t file_offset;

	reqpfn = (ulong)BTOP(paddr);

	if (CRASHDEBUG(8))
	    fprintf(xd->ofp, 
	        "xc_save_read(bufptr: %lx cnt: %d addr: %lx paddr: %llx (%ld, 0x%lx)\n",
		    (ulong)bufptr, cnt, addr, (ulonglong)paddr, reqpfn, reqpfn);

	if (xd->flags & XC_SAVE_IA64) {
                if (reqpfn >= xd->xc_save.nr_pfns) {
			if (CRASHDEBUG(1))
                            	fprintf(xd->ofp,
				    "xc_save_read: pfn %lx too large: nr_pfns: %lx\n",
					reqpfn, xd->xc_save.nr_pfns);
			return SEEK_ERROR;
		}

        	file_offset = xd->xc_save.ia64_page_offsets[reqpfn];
		if (!file_offset) {
			if (CRASHDEBUG(1))
                            	fprintf(xd->ofp,
				    "xc_save_read: pfn %lx not stored in xendump\n",
					reqpfn);
			return SEEK_ERROR;
		}	

       		if (reqpfn != xd->last_pfn) {
	        	if (lseek(xd->xfd, file_offset, SEEK_SET) == -1)
				return SEEK_ERROR;
	
			if (read(xd->xfd, xd->page, xd->page_size) != xd->page_size)
	               		return READ_ERROR;
		} else {
                	xd->redundant++;
			xd->cache_hits++;
		}

		xd->accesses++;
		xd->last_pfn = reqpfn;

                BCOPY(xd->page + PAGEOFFSET(paddr), bufptr, cnt);
                return cnt;
	}

	if ((file_offset = poc_get(reqpfn, &redundant))) {
		if (!redundant) {
        		if (lseek(xd->xfd, file_offset, SEEK_SET) == -1)
				return SEEK_ERROR;
			if (read(xd->xfd, xd->page, xd->page_size) != xd->page_size)
                		return READ_ERROR;
			xd->last_pfn = reqpfn;
		} else if (CRASHDEBUG(1))
			console("READ %ld (0x%lx) skipped!\n", reqpfn, reqpfn);

		BCOPY(xd->page + PAGEOFFSET(paddr), bufptr, cnt);
                return cnt;
	}

        /*
         *  ...
         *  int batch_count
         *  ulong region pfn_type[batch_count]
         *  page 0
         *  page 1
         *  ...
         *  page batch_count-1
         *  (repeat)
         */
	for (b = 0; b < xd->xc_save.batch_count; b++) {

		if (lseek(xd->xfd, xd->xc_save.batch_offsets[b], SEEK_SET) == -1)
			return SEEK_ERROR;

		if (CRASHDEBUG(8))
		    fprintf(xd->ofp, "check batch[%d]: offset: %llx\n",
			b, (ulonglong)xd->xc_save.batch_offsets[b]);

                if (read(xd->xfd, &batch_count, sizeof(int)) != sizeof(int))
                        return READ_ERROR;

                switch (batch_count)
                {
                case 0:
                        if (CRASHDEBUG(1) && !STREQ(pc->curcmd, "search")) {
                            	fprintf(xd->ofp,
                                    "batch[%d]: has count of zero -- bailing out on pfn %ld\n",
					 b, reqpfn);
                        }
			return READ_ERROR;

                case -1:
			return READ_ERROR;

                default:
			if (CRASHDEBUG(8))
		    	    fprintf(xd->ofp, 
				"batch[%d]: offset: %llx batch count: %d\n",
				    b, (ulonglong)xd->xc_save.batch_offsets[b], 
				    batch_count);
                        break;
                }

                if (read(xd->xfd, xd->xc_save.region_pfn_type, batch_count * sizeof(ulong)) !=
                    batch_count * sizeof(ulong))
                        return READ_ERROR;

                for (i = 0; i < batch_count; i++) {
                        unsigned long pagetype;
                        unsigned long pfn;

                        pfn = xd->xc_save.region_pfn_type[i] & ~LTAB_MASK;
                        pagetype = xd->xc_save.region_pfn_type[i] & LTAB_MASK;

                        if (pagetype == XTAB)
                            /* a bogus/unmapped page: skip it */
                                continue;

                        if (pfn > xd->xc_save.nr_pfns) {
                                if (CRASHDEBUG(1))
                                    fprintf(stderr,
                                        "batch_count: %d pfn %ld out of range",
                                                batch_count, pfn);
                        }

			if (pfn == reqpfn) {
				file_offset = lseek(xd->xfd, 0, SEEK_CUR);
				poc_store(pfn, file_offset);

				if (read(xd->xfd, xd->page, xd->page_size) != 
				    xd->page_size)
                			return READ_ERROR;

				BCOPY(xd->page + PAGEOFFSET(paddr), bufptr, cnt);
				return cnt;
			}

                        if (lseek(xd->xfd, xd->page_size, SEEK_CUR) == -1)
                                return SEEK_ERROR;
                }
	}

	return READ_ERROR;
}

/*
 *  Stash a pfn's offset.  If they're all in use, put it in the
 *  least-used slot that's closest to the beginning of the array.
 */
static void
poc_store(ulong pfn, off_t file_offset)
{
	int i;
	struct pfn_offset_cache *poc, *plow;
	ulong curlow;

	curlow = ~(0UL);
	plow = NULL;
	poc = xd->poc;

        for (i = 0; i < PFN_TO_OFFSET_CACHE_ENTRIES; i++, poc++) {
		if (poc->cnt == 0) {
			poc->cnt = 1;
			poc->pfn = pfn;
			poc->file_offset = file_offset;
			xd->last_pfn = pfn;
			return;
		}

		if (poc->cnt < curlow) {
			curlow = poc->cnt;
			plow = poc;
		}
	}

	plow->cnt = 1;
	plow->pfn = pfn;
	plow->file_offset = file_offset;
	xd->last_pfn = pfn;
}

/*
 *  Check whether a pfn's offset has been cached.
 */
static off_t
poc_get(ulong pfn, int *redundant)
{
	int i;
	struct pfn_offset_cache *poc;

	xd->accesses++;

	if (pfn == xd->last_pfn) {
		xd->redundant++;
		*redundant = TRUE;
		return 1;
	} else
		*redundant = FALSE;

	poc = xd->poc;

        for (i = 0; i < PFN_TO_OFFSET_CACHE_ENTRIES; i++, poc++) {
		if (poc->cnt && (poc->pfn == pfn)) {
			poc->cnt++;
			xd->cache_hits++;
			return poc->file_offset;
		}
	}

	return 0;
}


/*
 *  Perform any post-dumpfile determination stuff here.
 */
int
xendump_init(char *unused, FILE *fptr)
{
        if (!XENDUMP_VALID())
                return FALSE;

        xd->ofp = fptr;
        return TRUE;
}

int
read_xendump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	if (pc->curcmd_flags & XEN_MACHINE_ADDR)
		return READ_ERROR;

	switch (xd->flags & (XC_SAVE|XC_CORE_ORIG|XC_CORE_ELF))
	{
	case XC_SAVE:
		return xc_save_read(bufptr, cnt, addr, paddr);

	case XC_CORE_ORIG:
	case XC_CORE_ELF:
		return xc_core_read(bufptr, cnt, addr, paddr);

	default:
        	return READ_ERROR;
	}
}

int
read_xendump_hyper(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
        ulong pfn, page_index;
        off_t offset;

        pfn = (ulong)BTOP(paddr);

	/* ODA: pfn == mfn !!! */
        if ((page_index = xc_core_mfn_to_page_index(pfn)) == PFN_NOT_FOUND)
                return READ_ERROR;

        offset = xd->xc_core.header.xch_pages_offset +
                ((off_t)(page_index) * (off_t)xd->page_size);

        if (lseek(xd->xfd, offset, SEEK_SET) == -1)
                return SEEK_ERROR;

        if (read(xd->xfd, xd->page, xd->page_size) != xd->page_size)
                return READ_ERROR;

        BCOPY(xd->page + PAGEOFFSET(paddr), bufptr, cnt);

        return cnt;
}

int
write_xendump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
        return WRITE_ERROR;
}

uint
xendump_page_size(void)
{
        if (!XENDUMP_VALID())
                return 0;

        return xd->page_size;
}

/*
 *  xendump_free_memory(), and xendump_memory_used()
 *  are debug only, and typically unnecessary to implement.
 */
int
xendump_free_memory(void)
{
        return 0;
}

int
xendump_memory_used(void)
{
        return 0;
}

/*
 *  This function is dump-type independent, used here to
 *  to dump the xendump_data structure contents.
 */
int
xendump_memory_dump(FILE *fp)
{
	int i, linefeed, used, others;
	ulong *ulongptr;
	Elf32_Off offset32;
	Elf64_Off offset64;
	FILE *fpsave;

	fprintf(fp, "        flags: %lx (", xd->flags);
	others = 0;
	if (xd->flags & XENDUMP_LOCAL)
		fprintf(fp, "%sXENDUMP_LOCAL", others++ ? "|" : "");
	if (xd->flags & XC_SAVE)
		fprintf(fp, "%sXC_SAVE", others++ ? "|" : "");
	if (xd->flags & XC_CORE_ORIG)
		fprintf(fp, "%sXC_CORE_ORIG", others++ ? "|" : "");
	if (xd->flags & XC_CORE_ELF)
		fprintf(fp, "%sXC_CORE_ELF", others++ ? "|" : "");
	if (xd->flags & XC_CORE_P2M_CREATE)
		fprintf(fp, "%sXC_CORE_P2M_CREATE", others++ ? "|" : "");
	if (xd->flags & XC_CORE_PFN_CREATE)
		fprintf(fp, "%sXC_CORE_PFN_CREATE", others++ ? "|" : "");
	if (xd->flags & XC_CORE_NO_P2M)
		fprintf(fp, "%sXC_CORE_NO_P2M", others++ ? "|" : "");
	if (xd->flags & XC_SAVE_IA64)
		fprintf(fp, "%sXC_SAVE_IA64", others++ ? "|" : "");
	if (xd->flags & XC_CORE_64BIT_HOST)
		fprintf(fp, "%sXC_CORE_64BIT_HOST", others++ ? "|" : "");
	fprintf(fp, ")\n");
	fprintf(fp, "          xfd: %d\n", xd->xfd);
	fprintf(fp, "    page_size: %d\n", xd->page_size);
	fprintf(fp, "          ofp: %lx\n", (ulong)xd->ofp);
	fprintf(fp, "         page: %lx\n", (ulong)xd->page);
	fprintf(fp, "     panic_pc: %lx\n", xd->panic_pc);
	fprintf(fp, "     panic_sp: %lx\n", xd->panic_sp);
	fprintf(fp, "     accesses: %ld\n", (ulong)xd->accesses);
	fprintf(fp, "   cache_hits: %ld ", (ulong)xd->cache_hits);
	if (xd->accesses)
 		fprintf(fp, "(%ld%%)\n", xd->cache_hits * 100 / xd->accesses);
	else
		fprintf(fp, "\n");
	fprintf(fp, "     last_pfn: %ld\n", xd->last_pfn);
	fprintf(fp, "    redundant: %ld ", (ulong)xd->redundant);
	if (xd->accesses)
 		fprintf(fp, "(%ld%%)\n", xd->redundant * 100 / xd->accesses);
	else
		fprintf(fp, "\n");
	for (i = used = 0; i < PFN_TO_OFFSET_CACHE_ENTRIES; i++) 
		if (xd->poc && xd->poc[i].cnt)
			used++;
	if (xd->poc)
		fprintf(fp, "    poc[%d]: %lx %s", PFN_TO_OFFSET_CACHE_ENTRIES, 
		(ulong)xd->poc, xd->poc ? "" : "(none)");
	else
		fprintf(fp, "       poc[0]: (unused)\n");
	for (i = 0; i < PFN_TO_OFFSET_CACHE_ENTRIES; i++) {
		if (!xd->poc)
			break;
		if (!xd->poc[i].cnt) {
			if (!i)
				fprintf(fp, "(none used)\n");
			break;
		} else if (!i)
			fprintf(fp, "(%d used)\n", used);
		if (CRASHDEBUG(2))
			fprintf(fp, 
		  	    "  [%d]: pfn: %ld (0x%lx) count: %ld file_offset: %llx\n",
			    	i,
			    	xd->poc[i].pfn,
				xd->poc[i].pfn,
				xd->poc[i].cnt,
				(ulonglong)xd->poc[i].file_offset);
	}
	if (!xd->poc)
		fprintf(fp, "\n");

	fprintf(fp, "\n      xc_save:\n");
	fprintf(fp, "                  nr_pfns: %ld (0x%lx)\n", 
		xd->xc_save.nr_pfns, xd->xc_save.nr_pfns); 
	fprintf(fp, "            vmconfig_size: %d (0x%x)\n", xd->xc_save.vmconfig_size, 
		xd->xc_save.vmconfig_size);
	fprintf(fp, "             vmconfig_buf: %lx\n", (ulong)xd->xc_save.vmconfig_buf);
	if (xd->flags & XC_SAVE) 
		xen_dump_vmconfig(fp);
	fprintf(fp, "           p2m_frame_list: %lx ", (ulong)xd->xc_save.p2m_frame_list);
	if ((xd->flags & XC_SAVE) && xd->xc_save.p2m_frame_list) {
		fprintf(fp, "\n");
		ulongptr = xd->xc_save.p2m_frame_list;
		for (i = 0; i < P2M_FL_ENTRIES; i++, ulongptr++)
			fprintf(fp, "%ld ", *ulongptr);
		fprintf(fp, "\n");
	} else
		fprintf(fp, "(none)\n");
	fprintf(fp, "                 pfns_not: %d\n", xd->xc_save.pfns_not);
	fprintf(fp, "          pfns_not_offset: %lld\n", 
		(ulonglong)xd->xc_save.pfns_not_offset);
	fprintf(fp, "         vcpu_ctxt_offset: %lld\n", 
		(ulonglong)xd->xc_save.vcpu_ctxt_offset);
	fprintf(fp, "  shared_info_page_offset: %lld\n", 
		(ulonglong)xd->xc_save.shared_info_page_offset);
	fprintf(fp, "          region_pfn_type: %lx\n", (ulong)xd->xc_save.region_pfn_type);
	fprintf(fp, "              batch_count: %ld\n", (ulong)xd->xc_save.batch_count);
	fprintf(fp, "            batch_offsets: %lx %s\n", 
		(ulong)xd->xc_save.batch_offsets, 
		xd->xc_save.batch_offsets ? "" : "(none)");
	for (i = linefeed = 0; i < xd->xc_save.batch_count; i++) {
		fprintf(fp, "[%d]: %llx ", i, 
			(ulonglong)xd->xc_save.batch_offsets[i]);
		if (((i+1)%4) == 0) {
			fprintf(fp, "\n");
			linefeed = FALSE;
		} else
			linefeed = TRUE;
	}
	if (linefeed)
		fprintf(fp, "\n");
	fprintf(fp, "             ia64_version: %ld\n", (ulong)xd->xc_save.ia64_version);
	fprintf(fp, "        ia64_page_offsets: %lx ", (ulong)xd->xc_save.ia64_page_offsets);
	if (xd->xc_save.ia64_page_offsets)
		fprintf(fp, "(%ld entries)\n\n", xd->xc_save.nr_pfns);
	else
		fprintf(fp, "(none)\n\n");	

	fprintf(fp, "      xc_core:\n");
	fprintf(fp, "                   header:\n");
	fprintf(fp, "                xch_magic: %x ", 
		xd->xc_core.header.xch_magic);
	if (xd->xc_core.header.xch_magic == XC_CORE_MAGIC)
		fprintf(fp, "(XC_CORE_MAGIC)\n");
	else if (xd->xc_core.header.xch_magic == XC_CORE_MAGIC_HVM)
		fprintf(fp, "(XC_CORE_MAGIC_HVM)\n");
	else
		fprintf(fp, "(unknown)\n");
	fprintf(fp, "             xch_nr_vcpus: %d\n", 
		xd->xc_core.header.xch_nr_vcpus);
	fprintf(fp, "             xch_nr_pages: %d (0x%x)\n",
		xd->xc_core.header.xch_nr_pages,
		xd->xc_core.header.xch_nr_pages);
	fprintf(fp, "          xch_ctxt_offset: %llu (0x%llx)\n",
		(ulonglong)xd->xc_core.header.xch_ctxt_offset,
		(ulonglong)xd->xc_core.header.xch_ctxt_offset);
	fprintf(fp, "         xch_index_offset: %llu (0x%llx)\n",
		(ulonglong)xd->xc_core.header.xch_index_offset,
		(ulonglong)xd->xc_core.header.xch_index_offset);
	fprintf(fp, "         xch_pages_offset: %llu (0x%llx)\n",
		(ulonglong)xd->xc_core.header.xch_pages_offset,
		(ulonglong)xd->xc_core.header.xch_pages_offset);

	fprintf(fp, "                elf_class: %s\n", xd->xc_core.elf_class == ELFCLASS64 ? "ELFCLASS64" :
		xd->xc_core.elf_class == ELFCLASS32 ? "ELFCLASS32" : "n/a");
	fprintf(fp, "        elf_strtab_offset: %lld (0x%llx)\n", 
		(ulonglong)xd->xc_core.elf_strtab_offset,
		(ulonglong)xd->xc_core.elf_strtab_offset);
	fprintf(fp, "           format_version: %016llx\n", 
		(ulonglong)xd->xc_core.format_version);
	fprintf(fp, "       shared_info_offset: %lld (0x%llx)\n", 
		(ulonglong)xd->xc_core.shared_info_offset,
		(ulonglong)xd->xc_core.shared_info_offset);
	if (machine_type("IA64"))
		fprintf(fp, "  ia64_mapped_regs_offset: %lld (0x%llx)\n", 
			(ulonglong)xd->xc_core.ia64_mapped_regs_offset,
			(ulonglong)xd->xc_core.ia64_mapped_regs_offset);
	fprintf(fp, "       elf_index_pfn[%d]: %s", INDEX_PFN_COUNT,
		xd->xc_core.elf_class ? "\n" : "(none used)\n");
	if (xd->xc_core.elf_class) {
		for (i = 0; i < INDEX_PFN_COUNT; i++) {
			fprintf(fp, "%ld:%ld ", 
			    xd->xc_core.elf_index_pfn[i].index,
			    xd->xc_core.elf_index_pfn[i].pfn);
		}
		fprintf(fp, "\n");
	}
	fprintf(fp, "               last_batch:\n");
	fprintf(fp, "                    index: %ld (%ld - %ld)\n", 
		xd->xc_core.last_batch.index,
		xd->xc_core.last_batch.start, xd->xc_core.last_batch.end);
	fprintf(fp, "                 accesses: %ld\n", 
		xd->xc_core.last_batch.accesses);
	fprintf(fp, "               duplicates: %ld ", 
		xd->xc_core.last_batch.duplicates);
        if (xd->xc_core.last_batch.accesses)
                fprintf(fp, "(%ld%%)\n", 
			xd->xc_core.last_batch.duplicates * 100 / 
			xd->xc_core.last_batch.accesses);
        else
                fprintf(fp, "\n");

	fprintf(fp, "                    elf32: %lx\n", (ulong)xd->xc_core.elf32);
	fprintf(fp, "                    elf64: %lx\n", (ulong)xd->xc_core.elf64);

	fprintf(fp, "               p2m_frames: %d\n", 
		xd->xc_core.p2m_frames);
	fprintf(fp, "     p2m_frame_index_list: %s\n",
		(xd->flags & (XC_CORE_NO_P2M|XC_SAVE)) ? "(not used)" : "");
	for (i = 0; i < xd->xc_core.p2m_frames; i++) {
		fprintf(fp, "%ld ", 
			xd->xc_core.p2m_frame_index_list[i]);
	}
	fprintf(fp, xd->xc_core.p2m_frames ? "\n" : "");

	if ((xd->flags & XC_CORE_ORIG) && CRASHDEBUG(8))
		xc_core_mfns(XENDUMP_LOCAL, fp);

        switch (xd->xc_core.elf_class)
        {
        case ELFCLASS32:
		fpsave = xd->ofp;
		xd->ofp = fp;
		xc_core_elf_dump();
		offset32 = xd->xc_core.elf32->e_shoff;
		for (i = 0; i < xd->xc_core.elf32->e_shnum; i++) {
			xc_core_dump_Elf32_Shdr(offset32, ELFREAD);
			offset32 += xd->xc_core.elf32->e_shentsize;
		}
		xendump_print("\n");
		xd->ofp = fpsave;
                break;

        case ELFCLASS64:
		fpsave = xd->ofp;
		xd->ofp = fp;
		xc_core_elf_dump();
		offset64 = xd->xc_core.elf64->e_shoff;
		for (i = 0; i < xd->xc_core.elf64->e_shnum; i++) {
			xc_core_dump_Elf64_Shdr(offset64, ELFREAD);
			offset64 += xd->xc_core.elf64->e_shentsize;
		}
		xendump_print("\n");
		xd->ofp = fpsave;
		break;
	}

	return 0;
}

static void
xen_dump_vmconfig(FILE *fp)
{
	int i, opens, closes;
	char *p;

	opens = closes = 0;
	p = xd->xc_save.vmconfig_buf;
	for (i = 0; i < xd->xc_save.vmconfig_size; i++, p++) {
		if (ascii(*p))
			fprintf(fp, "%c", *p);
		else
			fprintf(fp, "<%x>", *p);

		if (*p == '(')
			opens++;
		else if (*p == ')')
			closes++;
	}
	fprintf(fp, "\n");

	if (opens != closes)
		error(WARNING, "invalid vmconfig contents?\n");
}

/*
 *  Looking at the active set, try to determine who panicked, 
 *  or who was the "suspend" kernel thread. 
 */
ulong get_xendump_panic_task(void)
{
	int i;
	ulong task;
	struct task_context *tc;

	switch (xd->flags & (XC_CORE_ORIG|XC_CORE_ELF|XC_SAVE))
	{
	case XC_CORE_ORIG:
	case XC_CORE_ELF:
		if (machdep->xendump_panic_task)
			return (machdep->xendump_panic_task((void *)xd));
		break;

	case XC_SAVE:
        	for (i = 0; i < NR_CPUS; i++) {
                	if (!(task = tt->active_set[i]))
                        	continue;
			tc = task_to_context(task);
			if (is_kernel_thread(task) &&
			    STREQ(tc->comm, "suspend")) 
				return tc->task;
        	}
		break;
	}

	return NO_TASK;
}

/*
 *  Figure out the back trace hooks.
 */
void get_xendump_regs(struct bt_info *bt, ulong *pc, ulong *sp)
{
	int i;
	ulong *up;

	if ((tt->panic_task == bt->task) &&
	    (xd->panic_pc && xd->panic_sp)) {
		*pc = xd->panic_pc;
		*sp = xd->panic_sp;
		return;
	}

	switch (xd->flags & (XC_CORE_ORIG|XC_CORE_ELF|XC_SAVE))
	{
	case XC_CORE_ORIG:
	case XC_CORE_ELF:
		if (machdep->get_xendump_regs)
			return (machdep->get_xendump_regs(xd, bt, pc, sp));
		break;

	case XC_SAVE:
		if (tt->panic_task != bt->task) 
			break;

                for (i = 0, up = (ulong *)bt->stackbuf;
                     i < LONGS_PER_STACK; i++, up++) {
                        if (is_kernel_text(*up) &&
		       	    (STREQ(closest_symbol(*up), 
			    "__do_suspend"))) {
				*pc = *up;
				*sp = tt->flags & THREAD_INFO ?
                               		bt->tc->thread_info +
                                        (i * sizeof(long)) :
                                        bt->task + 
					(i * sizeof(long));
				xd->panic_pc = *pc;
				xd->panic_sp = *sp;
				return;
			}
		}
	}

	machdep->get_stack_frame(bt, pc, sp);
}

/*
 *  Farm out most of the work to the proper architecture to create
 *  the p2m table.  For ELF core dumps, create the index;pfn table. 
 */
static void 
xc_core_create_pfn_tables(void)
{
        if (xd->flags & XC_CORE_P2M_CREATE) {
		if (!machdep->xendump_p2m_create)
			error(FATAL, 
			    "xen xc_core dumpfiles not supported on this architecture");
	
		if (!machdep->xendump_p2m_create((void *)xd))
			error(FATAL,
			    "cannot create xen pfn-to-mfn mapping\n");
	}

	if (xd->flags & XC_CORE_PFN_CREATE)
		xc_core_elf_pfn_init();

	xd->flags &= ~(XC_CORE_P2M_CREATE|XC_CORE_PFN_CREATE);

	if (CRASHDEBUG(1))
		xendump_memory_dump(xd->ofp);
}

/*
 *  Find the page index containing the mfn, and read the
 *  machine page into the buffer.
 */
char *
xc_core_mfn_to_page(ulong mfn, char *pgbuf)
{
	int i, b, idx, done;
	ulong tmp[MAX_BATCH_SIZE];
	off_t offset;
	size_t size;
	uint nr_pages;

	if (xd->flags & XC_CORE_ELF)
		return xc_core_elf_mfn_to_page(mfn, pgbuf);

        if (lseek(xd->xfd, xd->xc_core.header.xch_index_offset,
            SEEK_SET) == -1) {
                error(INFO, "cannot lseek to page index\n");
		return NULL;
	}

	nr_pages = xd->xc_core.header.xch_nr_pages;
	if (xd->flags & XC_CORE_64BIT_HOST)
		nr_pages *= 2;

        for (b = 0, idx = -1, done = FALSE; 
	     !done && (b < nr_pages); b += MAX_BATCH_SIZE) {
		size = sizeof(ulong) * MIN(MAX_BATCH_SIZE, nr_pages - b);
                if (read(xd->xfd, tmp, size) != size) {
                        error(INFO, "cannot read index page %d\n", b);
			return NULL;
		}

                for (i = 0; i < MAX_BATCH_SIZE; i++) {
			if ((b+i) >= nr_pages) {
				done = TRUE;
				break;
			}
                        if (tmp[i] == mfn) {
                                idx = i+b;
                                if (CRASHDEBUG(4))
                                        fprintf(xd->ofp,
                                            "page: found mfn 0x%lx (%ld) at index %d\n",
                                                mfn, mfn, idx);
				done = TRUE;
                        }
                }
	}

	if (idx == -1) {
                error(INFO, "cannot find mfn %ld (0x%lx) in page index\n",
			mfn, mfn);
		return NULL;
	}

        if (lseek(xd->xfd, xd->xc_core.header.xch_pages_offset,
            SEEK_SET) == -1) {
                error(INFO, "cannot lseek to xch_pages_offset\n");
		return NULL;
	}

        offset = (off_t)(idx) * (off_t)xd->page_size;

        if (lseek(xd->xfd, offset, SEEK_CUR) == -1) {
                error(INFO, "cannot lseek to mfn-specified page\n");
		return NULL;
	}

        if (read(xd->xfd, pgbuf, xd->page_size) != xd->page_size) {
                error(INFO, "cannot read mfn-specified page\n");
		return NULL;
	}

	return pgbuf;
}

/*
 *  Find the page index containing the mfn, and read the
 *  machine page into the buffer.
 */
static char *
xc_core_elf_mfn_to_page(ulong mfn, char *pgbuf)
{
	int i, b, idx, done;
	off_t offset;
	size_t size;
	uint nr_pages;
	ulong tmp;
	struct xen_dumpcore_p2m p2m_batch[MAX_BATCH_SIZE];

        offset = xd->xc_core.header.xch_index_offset;
	nr_pages = xd->xc_core.header.xch_nr_pages;

        if (lseek(xd->xfd, offset, SEEK_SET) == -1)
                error(FATAL, "cannot lseek to page index\n");

        for (b = 0, idx = -1, done = FALSE; 
	     !done && (b < nr_pages); b += MAX_BATCH_SIZE) {
		size = sizeof(struct xen_dumpcore_p2m) *
			MIN(MAX_BATCH_SIZE, nr_pages - b);
                if (read(xd->xfd, &p2m_batch[0], size) != size) {
                        error(INFO, "cannot read index page %d\n", b);
			return NULL;
		}

                for (i = 0; i < MAX_BATCH_SIZE; i++) {
			if ((b+i) >= nr_pages) {
				done = TRUE;
				break;
			}

			tmp = (ulong)p2m_batch[i].gmfn;

                        if (tmp == mfn) {
                                idx = i+b;
                                if (CRASHDEBUG(4))
                                        fprintf(xd->ofp,
                                            "page: found mfn 0x%lx (%ld) at index %d\n",
                                                mfn, mfn, idx);
				done = TRUE;
                        }
                }
	}

	if (idx == -1) {
                error(INFO, "cannot find mfn %ld (0x%lx) in page index\n",
			mfn, mfn);
		return NULL;
	}

        if (lseek(xd->xfd, xd->xc_core.header.xch_pages_offset,
            SEEK_SET) == -1)
                error(FATAL, "cannot lseek to xch_pages_offset\n");

        offset = (off_t)(idx) * (off_t)xd->page_size;

        if (lseek(xd->xfd, offset, SEEK_CUR) == -1) {
                error(INFO, "cannot lseek to mfn-specified page\n");
		return NULL;
	}

        if (read(xd->xfd, pgbuf, xd->page_size) != xd->page_size) {
                error(INFO, "cannot read mfn-specified page\n");
		return NULL;
	}

	return pgbuf;
}


/*
 *  Find and return the page index containing the mfn.
 */
int 
xc_core_mfn_to_page_index(ulong mfn)
{
        int i, b;
        ulong tmp[MAX_BATCH_SIZE];
	uint nr_pages;
	size_t size;

	if (xd->flags & XC_CORE_ELF)
		return xc_core_elf_mfn_to_page_index(mfn);

        if (lseek(xd->xfd, xd->xc_core.header.xch_index_offset,
            SEEK_SET) == -1) {
                error(INFO, "cannot lseek to page index\n");
                return MFN_NOT_FOUND;
        }

	nr_pages = xd->xc_core.header.xch_nr_pages;
	if (xd->flags & XC_CORE_64BIT_HOST)
                nr_pages *= 2;

        for (b = 0; b < nr_pages; b += MAX_BATCH_SIZE) {
		size = sizeof(ulong) * MIN(MAX_BATCH_SIZE, nr_pages - b);
                if (read(xd->xfd, tmp, size) != size) {
                        error(INFO, "cannot read index page %d\n", b);
			return MFN_NOT_FOUND;
		}

		for (i = 0; i < MAX_BATCH_SIZE; i++) {
			if ((b+i) >= nr_pages)
				break;
			
                	if (tmp[i] == mfn) {
				if (CRASHDEBUG(4))
                        		fprintf(xd->ofp, 
				            "index: batch: %d found mfn %ld (0x%lx) at index %d\n",
                                		b/MAX_BATCH_SIZE, mfn, mfn, i+b);
                        	return (i+b);
                	}
		}
        }

        return MFN_NOT_FOUND;
}

/*
 *  Find and return the page index containing the mfn.
 */
static int
xc_core_elf_mfn_to_page_index(ulong mfn)
{
        int i, b;
	off_t offset;
	size_t size;
	uint nr_pages;
        ulong tmp;
        struct xen_dumpcore_p2m p2m_batch[MAX_BATCH_SIZE];

        offset = xd->xc_core.header.xch_index_offset;
	nr_pages = xd->xc_core.header.xch_nr_pages;

        if (lseek(xd->xfd, offset, SEEK_SET) == -1)
                error(FATAL, "cannot lseek to page index\n");

        for (b = 0; b < nr_pages; b += MAX_BATCH_SIZE) {
		size = sizeof(struct xen_dumpcore_p2m) *
			MIN(MAX_BATCH_SIZE, nr_pages - b);
                if (read(xd->xfd, &p2m_batch[0], size) != size) {
                        error(INFO, "cannot read index page %d\n", b);
			return MFN_NOT_FOUND;
		}

		for (i = 0; i < MAX_BATCH_SIZE; i++) {
			if ((b+i) >= nr_pages)
				break;
			
			tmp = (ulong)p2m_batch[i].gmfn;

                	if (tmp == mfn) {
				if (CRASHDEBUG(4))
                        		fprintf(xd->ofp, 
				            "index: batch: %d found mfn %ld (0x%lx) at index %d\n",
                                		b/MAX_BATCH_SIZE, mfn, mfn, i+b);
                        	return (i+b);
                	}
		}
        }

        return MFN_NOT_FOUND;
}


/*
 *  XC_CORE mfn-related utility function.
 */
static int
xc_core_mfns(ulong arg, FILE *ofp)
{
        int i, b;
	uint nr_pages;
        ulong tmp[MAX_BATCH_SIZE];
        ulonglong tmp64[MAX_BATCH_SIZE];
	size_t size;

        if (lseek(xd->xfd, xd->xc_core.header.xch_index_offset,
            SEEK_SET) == -1) {
                error(INFO, "cannot lseek to page index\n");
		return FALSE;
        }

	switch (arg)
	{
	case XC_CORE_64BIT_HOST:
		/*
		 *  Determine whether this is a 32-bit guest xendump that
		 *  was taken on a 64-bit xen host.
	         */
		if (machine_type("X86_64") || machine_type("IA64"))
			return FALSE;
check_next_4:
	        if (read(xd->xfd, tmp, sizeof(ulong) * 4) != (4 * sizeof(ulong))) {
			error(INFO, "cannot read index pages\n");
			return FALSE;
	        }

		if ((tmp[0] == 0xffffffff) || (tmp[1] == 0xffffffff) ||
		    (tmp[2] == 0xffffffff) || (tmp[3] == 0xffffffff) ||
		    (!tmp[0] && !tmp[1]) || (!tmp[2] && !tmp[3]))
			goto check_next_4;

		if (CRASHDEBUG(2))
			fprintf(ofp, "mfns: %08lx %08lx %08lx %08lx\n", 
					tmp[0], tmp[1], tmp[2], tmp[3]);

		if (tmp[0] && !tmp[1] && tmp[2] && !tmp[3])
			return TRUE;
		else
			return FALSE;

	case XENDUMP_LOCAL:
		if (BITS64() || (xd->flags & XC_CORE_64BIT_HOST))
			goto show_64bit_mfns;

		fprintf(ofp, "xch_index_offset mfn list:\n");

		nr_pages = xd->xc_core.header.xch_nr_pages;

	        for (b = 0; b < nr_pages; b += MAX_BATCH_SIZE) {
			size = sizeof(ulong) *
				MIN(MAX_BATCH_SIZE, nr_pages - b);
	                if (read(xd->xfd, tmp, size) != size) {
	                        error(INFO, "cannot read index page %d\n", b);
	                        return FALSE;
	                }
	
			if (b) fprintf(ofp, "\n");

	                for (i = 0; i < MAX_BATCH_SIZE; i++) {
				if ((b+i) >= nr_pages)
					break;
				if ((i%8) == 0)
					fprintf(ofp, "%s[%d]:", 
						i ? "\n" : "", b+i);
				if (tmp[i] == 0xffffffff)
					fprintf(ofp, " INVALID");
				else
					fprintf(ofp, " %lx", tmp[i]);
			}
		}

		fprintf(ofp, "\nxch_nr_pages: %d\n", 
			xd->xc_core.header.xch_nr_pages);
		return TRUE;

show_64bit_mfns:
		fprintf(ofp, "xch_index_offset mfn list: %s\n",
			BITS32() ? "(64-bit mfns)" : "");

		nr_pages = xd->xc_core.header.xch_nr_pages;

	        for (b = 0; b < nr_pages; b += MAX_BATCH_SIZE) {
			size = sizeof(ulonglong) *
				MIN(MAX_BATCH_SIZE, nr_pages - b);
			if (read(xd->xfd, tmp64, size) != size) {
	                        error(INFO, "cannot read index page %d\n", b);
	                        return FALSE;
	                }
	
			if (b) fprintf(ofp, "\n");

	                for (i = 0; i < MAX_BATCH_SIZE; i++) {
				if ((b+i) >= nr_pages)
					break;
				if ((i%8) == 0)
					fprintf(ofp, "%s[%d]:", 
						i ? "\n" : "", b+i);
				if (tmp64[i] == 0xffffffffffffffffULL)
					fprintf(ofp, " INVALID");
				else
					fprintf(ofp, " %llx", tmp64[i]);
			}
		}

		fprintf(ofp, "\nxch_nr_pages: %d\n", nr_pages);
		return TRUE;

	default:
		return FALSE;
	}
}

/*
 *  Given a normal kernel pfn, determine the page index in the dumpfile.
 *
 *  -  First determine which of the pages making up the 
 *     phys_to_machine_mapping[] array would contain the pfn.
 *  -  From the phys_to_machine_mapping page, determine the mfn.
 *  -  Find the mfn in the dumpfile page index.
 */
#define PFNS_PER_PAGE  (xd->page_size/sizeof(unsigned long))

static ulong
xc_core_pfn_to_page_index(ulong pfn)
{
	ulong idx, p2m_idx, mfn_idx;
	ulong *up, mfn;
	off_t offset;

	/*
	 *  This function does not apply when there's no p2m
	 *  mapping and/or if this is an ELF format dumpfile.
	 */
	switch (xd->flags & (XC_CORE_NO_P2M|XC_CORE_ELF))
	{
	case (XC_CORE_NO_P2M|XC_CORE_ELF):
		return xc_core_elf_pfn_valid(pfn);

	case XC_CORE_NO_P2M:
		return(xc_core_pfn_valid(pfn) ? pfn : PFN_NOT_FOUND);
	
	case XC_CORE_ELF:
		return xc_core_elf_pfn_to_page_index(pfn);
	}

	idx = pfn/PFNS_PER_PAGE;

	if (idx >= xd->xc_core.p2m_frames) {
		error(INFO, "pfn: %lx is too large for dumpfile\n", 
			pfn);
		return PFN_NOT_FOUND;
	}

	p2m_idx = xd->xc_core.p2m_frame_index_list[idx];

	if (lseek(xd->xfd, xd->xc_core.header.xch_pages_offset,
            SEEK_SET) == -1) {
                error(INFO, "cannot lseek to xch_pages_offset\n");
                return PFN_NOT_FOUND;
        }

        offset = (off_t)(p2m_idx) * (off_t)xd->page_size;

        if (lseek(xd->xfd, offset, SEEK_CUR) == -1) {
                error(INFO, "cannot lseek to pfn-specified page\n");
                return PFN_NOT_FOUND;
        }

        if (read(xd->xfd, xd->page, xd->page_size) != xd->page_size) {
                error(INFO, "cannot read pfn-specified page\n");
                return PFN_NOT_FOUND;
        }

	up = (ulong *)xd->page;
	up += (pfn%PFNS_PER_PAGE);

	mfn = *up;

	if ((mfn_idx = xc_core_mfn_to_page_index(mfn)) == MFN_NOT_FOUND) {
		if (!STREQ(pc->curcmd, "search"))	
			error(INFO, "cannot find mfn in page index\n");
		return PFN_NOT_FOUND;
	}

	return mfn_idx;
}


/*
 *  Search the .xen_p2m array for the target pfn, starting at a 
 *  higher batch if appropriate.  This presumes that the pfns
 *  are laid out in ascending order.
 */
static ulong
xc_core_elf_pfn_to_page_index(ulong pfn)
{
        int i, b, start_index;
	off_t offset;
	size_t size;
	uint nr_pages;
        ulong tmp;
        struct xen_dumpcore_p2m p2m_batch[MAX_BATCH_SIZE];

        offset = xd->xc_core.header.xch_index_offset;
	nr_pages = xd->xc_core.header.xch_nr_pages;

	/*
	 *  Initialize the start_index.
	 */
	xd->xc_core.last_batch.accesses++;
	start_index = 0;

	if ((pfn >= xd->xc_core.last_batch.start) &&
	    (pfn <= xd->xc_core.last_batch.end)) {
		xd->xc_core.last_batch.duplicates++;
		start_index = xd->xc_core.last_batch.index;
	} else {
		for (i = 0; i <= INDEX_PFN_COUNT; i++) {
			if ((i == INDEX_PFN_COUNT) ||
			    (pfn < xd->xc_core.elf_index_pfn[i].pfn)) {
				if (--i < 0)
					i = 0;
				start_index = xd->xc_core.elf_index_pfn[i].index;
				break;
			}
		}
	}

	offset += (start_index * sizeof(struct xen_dumpcore_p2m));
        if (lseek(xd->xfd, offset, SEEK_SET) == -1)
                error(FATAL, "cannot lseek to page index\n");

        for (b = start_index; b < nr_pages; b += MAX_BATCH_SIZE) {
		size = sizeof(struct xen_dumpcore_p2m) *
			MIN(MAX_BATCH_SIZE, nr_pages - b);
                if (read(xd->xfd, &p2m_batch[0], size) != size) {
                        error(INFO, "cannot read index page %d\n", b);
			return PFN_NOT_FOUND;
		}

		for (i = 0; i < MAX_BATCH_SIZE; i++) {
			if ((b+i) >= nr_pages)
				break;
			
			tmp = (ulong)p2m_batch[i].pfn;

                	if (tmp == pfn) {
				if (CRASHDEBUG(4))
                        		fprintf(xd->ofp, 
				            "index: batch: %d found pfn %ld (0x%lx) at index %d\n",
                                		b/MAX_BATCH_SIZE, pfn, pfn, i+b);

				if ((b+MAX_BATCH_SIZE) < nr_pages) {
					xd->xc_core.last_batch.index = b;
					xd->xc_core.last_batch.start = p2m_batch[0].pfn;
					xd->xc_core.last_batch.end = p2m_batch[MAX_BATCH_SIZE-1].pfn;
				}

                        	return (i+b);
                	}
		}
        }

        return PFN_NOT_FOUND;
}

/*
 *  In xendumps containing INVALID_MFN markers in the page index,
 *  return the validity of the pfn.
 */
static int 
xc_core_pfn_valid(ulong pfn)
{
	ulong mfn;
	off_t offset;

	if (pfn >= (ulong)xd->xc_core.header.xch_nr_pages)
		return FALSE;

        offset = xd->xc_core.header.xch_index_offset;

	if (xd->flags & XC_CORE_64BIT_HOST)
		offset += (off_t)(pfn * sizeof(ulonglong));
	else
		offset += (off_t)(pfn * sizeof(ulong));

	/*
	 *  The lseek and read should never fail, so report 
	 *  any errors unconditionally.
	 */
	if (lseek(xd->xfd, offset, SEEK_SET) == -1) {
		error(INFO, 
		    "xendump: cannot lseek to page index for pfn %lx\n", 
			pfn);
		return FALSE;
	}

	if (read(xd->xfd, &mfn, sizeof(ulong)) != sizeof(ulong)) {
		error(INFO, 
		    "xendump: cannot read index page for pfn %lx\n", 
			pfn);
		return FALSE;
	}

	/*
	 *  If it's an invalid mfn, let the caller decide whether
	 *  to display an error message (unless debugging).
	 */
	if (mfn == INVALID_MFN) {
		if (CRASHDEBUG(1) && !STREQ(pc->curcmd, "search"))
			error(INFO, 
		    	    "xendump: pfn %lx contains INVALID_MFN\n", 
				pfn);
		return FALSE;
	} 

	return TRUE;
}

/*
 *  Return the index into the .xen_pfn array containing the pfn.
 *  If not found, return PFN_NOT_FOUND.
 */
static ulong
xc_core_elf_pfn_valid(ulong pfn)
{
        int i, b, start_index;
	off_t offset;
	size_t size;
	uint nr_pages;
        ulong tmp;
        uint64_t pfn_batch[MAX_BATCH_SIZE];

        offset = xd->xc_core.header.xch_index_offset;
	nr_pages = xd->xc_core.header.xch_nr_pages;

	/*
	 *  Initialize the start_index.
	 */
	xd->xc_core.last_batch.accesses++;
	start_index = 0;

	if ((pfn >= xd->xc_core.last_batch.start) &&
	    (pfn <= xd->xc_core.last_batch.end)) {
		xd->xc_core.last_batch.duplicates++;
		start_index = xd->xc_core.last_batch.index;
	} else {
		for (i = 0; i <= INDEX_PFN_COUNT; i++) {
			if ((i == INDEX_PFN_COUNT) ||
			    (pfn < xd->xc_core.elf_index_pfn[i].pfn)) {
				if (--i < 0)
					i = 0;
				start_index = xd->xc_core.elf_index_pfn[i].index;
				break;
			}
		}
	}

	offset += (start_index * sizeof(uint64_t));
        if (lseek(xd->xfd, offset, SEEK_SET) == -1)
                error(FATAL, "cannot lseek to page index\n");

        for (b = start_index; b < nr_pages; b += MAX_BATCH_SIZE) {
		size = sizeof(uint64_t) * MIN(MAX_BATCH_SIZE, nr_pages - b);
                if (read(xd->xfd, &pfn_batch[0], size) != size) {
                        error(INFO, "cannot read index page %d\n", b);
			return PFN_NOT_FOUND;
		}

		for (i = 0; i < MAX_BATCH_SIZE; i++) {
			if ((b+i) >= nr_pages)
				break;
			
			tmp = (ulong)pfn_batch[i];

                	if (tmp == pfn) {
				if (CRASHDEBUG(4))
                        		fprintf(xd->ofp, 
				            "index: batch: %d found pfn %ld (0x%lx) at index %d\n",
                                		b/MAX_BATCH_SIZE, pfn, pfn, i+b);

				if ((b+MAX_BATCH_SIZE) < nr_pages) {
					xd->xc_core.last_batch.index = b;
					xd->xc_core.last_batch.start = (ulong)pfn_batch[0];
					xd->xc_core.last_batch.end = (ulong)pfn_batch[MAX_BATCH_SIZE-1];
				}

                        	return (i+b);
                	}
		}
        }

        return PFN_NOT_FOUND;
}

/*
 *  Store the panic task's stack hooks from where it was found
 *  in get_active_set_panic_task().
 */
void
xendump_panic_hook(char *stack)
{
	int i, err, argc;
	char *arglist[MAXARGS];
	char buf[BUFSIZE];
	ulong value, *sp;

	if (machine_type("IA64"))  /* needs switch_stack address */
		return;

	strcpy(buf, stack);

        argc = parse_line(buf, arglist);

	if ((value = htol(strip_ending_char(arglist[0], ':'), 
	    RETURN_ON_ERROR, &err)) == BADADDR)
		return;
	for (sp = (ulong *)value, i = 1; i < argc; i++, sp++) {
		if (strstr(arglist[i], "xen_panic_event")) {
			if (!readmem((ulong)sp, KVADDR, &value,
			    sizeof(ulong), "xen_panic_event address",
                            RETURN_ON_ERROR))
				return;

			xd->panic_sp = (ulong)sp;
			xd->panic_pc = value;
		} else if (strstr(arglist[i], "panic") && !xd->panic_sp) {
                        if (!readmem((ulong)sp, KVADDR, &value,
                            sizeof(ulong), "xen_panic_event address",
                            RETURN_ON_ERROR))
                                return;

			xd->panic_sp = (ulong)sp;
			xd->panic_pc = value;
		}
	}
}

static void
xendump_print(char *fmt, ...)
{
        char buf[BUFSIZE];
        va_list ap;

        if (!fmt || !strlen(fmt))
                return;

        va_start(ap, fmt);
        (void)vsnprintf(buf, BUFSIZE, fmt, ap);
        va_end(ap);

        if (xd->ofp)
                fprintf(xd->ofp, "%s", buf);
        else if (!XENDUMP_VALID() && CRASHDEBUG(7))
		fprintf(stderr, "%s", buf);
                
}

/*
 *  Support for xc_core ELF dumpfile format.
 */
static int
xc_core_elf_verify(char *file, char *buf)
{
	int i;
	Elf32_Ehdr *elf32;
	Elf64_Ehdr *elf64;
	Elf32_Off offset32;
	Elf64_Off offset64;
	char *eheader;
	int swap;

	eheader = buf;

	if (!STRNEQ(eheader, ELFMAG) || eheader[EI_VERSION] != EV_CURRENT)
		goto bailout;

	swap = (((eheader[EI_DATA] == ELFDATA2LSB) && 
	     (__BYTE_ORDER == __BIG_ENDIAN)) ||
	    ((eheader[EI_DATA] == ELFDATA2MSB) && 
	     (__BYTE_ORDER == __LITTLE_ENDIAN)));

	elf32 = (Elf32_Ehdr *)buf;
	elf64 = (Elf64_Ehdr *)buf;

        if ((elf32->e_ident[EI_CLASS] == ELFCLASS32) &&
	    (swap16(elf32->e_type, swap) == ET_CORE) &&
	    (swap32(elf32->e_version, swap) == EV_CURRENT) &&
	    (swap16(elf32->e_shnum, swap) > 0)) {
		switch (swap16(elf32->e_machine, swap))
		{
		case EM_386:
			if (machine_type_mismatch(file, "X86", NULL, 0))
				goto bailout;
			break;

		default:
			if (machine_type_mismatch(file, "(unknown)", NULL, 0))
				goto bailout;
			break;
		}

		if (endian_mismatch(file, elf32->e_ident[EI_DATA], 0))
			goto bailout;

		xd->xc_core.elf_class = ELFCLASS32;
        	if ((xd->xc_core.elf32 = (Elf32_Ehdr *)malloc(sizeof(Elf32_Ehdr))) == NULL) {
                	fprintf(stderr, "cannot malloc ELF header buffer\n");
                	clean_exit(1);
		}
		BCOPY(buf, xd->xc_core.elf32, sizeof(Elf32_Ehdr));

	} else if ((elf64->e_ident[EI_CLASS] == ELFCLASS64) &&
	    (swap16(elf64->e_type, swap) == ET_CORE) &&
	    (swap32(elf64->e_version, swap) == EV_CURRENT) &&
	    (swap16(elf64->e_shnum, swap) > 0)) { 
		switch (swap16(elf64->e_machine, swap))
		{
		case EM_IA_64:
			if (machine_type_mismatch(file, "IA64", NULL, 0))
				goto bailout;
			break;

		case EM_X86_64:
			if (machine_type_mismatch(file, "X86_64", "X86", 0))
				goto bailout;
			break;

		case EM_386:
			if (machine_type_mismatch(file, "X86", NULL, 0))
				goto bailout;
			break;

		case EM_ARM:
			if (machine_type_mismatch(file, "ARM", NULL, 0))
				goto bailout;
			break;

		case EM_AARCH64:
			if (machine_type_mismatch(file, "ARM64", NULL, 0))
				goto bailout;
			break;

		default:
			if (machine_type_mismatch(file, "(unknown)", NULL, 0))
				goto bailout;
		}

		if (endian_mismatch(file, elf64->e_ident[EI_DATA], 0))
			goto bailout;

		xd->xc_core.elf_class = ELFCLASS64;
        	if ((xd->xc_core.elf64 = (Elf64_Ehdr *)malloc(sizeof(Elf64_Ehdr))) == NULL) {
                	fprintf(stderr, "cannot malloc ELF header buffer\n");
                	clean_exit(1);
		}
		BCOPY(buf, xd->xc_core.elf64, sizeof(Elf64_Ehdr));

	} else {
		if (CRASHDEBUG(1))
			error(INFO, "%s: not a xen ELF core file\n", file);
		goto bailout;
	}

	xc_core_elf_dump();

	switch (xd->xc_core.elf_class)
	{
	case ELFCLASS32:
                offset32 = xd->xc_core.elf32->e_shoff;
		for (i = 0; i < xd->xc_core.elf32->e_shnum; i++) {
			xc_core_dump_Elf32_Shdr(offset32, ELFSTORE);
			offset32 += xd->xc_core.elf32->e_shentsize;
		}
		xendump_print("\n");
		break;

	case ELFCLASS64:
                offset64 = xd->xc_core.elf64->e_shoff;
		for (i = 0; i < xd->xc_core.elf64->e_shnum; i++) {
			xc_core_dump_Elf64_Shdr(offset64, ELFSTORE);
			offset64 += xd->xc_core.elf64->e_shentsize;
		}
		xendump_print("\n");
		break;
	}

        xd->flags |= (XENDUMP_LOCAL | XC_CORE_ELF);

	if (!xd->page_size)
		error(FATAL,
		    "unknown page size: use -p <pagesize> command line option\n");

	if (!(xd->page = (char *)malloc(xd->page_size)))
		error(FATAL, "cannot malloc page space.");

        if (!(xd->poc = (struct pfn_offset_cache *)calloc
            (PFN_TO_OFFSET_CACHE_ENTRIES,
            sizeof(struct pfn_offset_cache))))
                error(FATAL, "cannot malloc pfn_offset_cache\n");
	xd->last_pfn = ~(0UL);

	for (i = 0; i < INDEX_PFN_COUNT; i++)
        	xd->xc_core.elf_index_pfn[i].pfn = ~0UL;

	if (CRASHDEBUG(1)) 
                xendump_memory_dump(fp);

	return TRUE;

bailout:
	return FALSE;
}

/*
 *  Dump the relevant ELF header. 
 */
static void
xc_core_elf_dump(void)
{
	switch (xd->xc_core.elf_class)
	{
	case ELFCLASS32:
		xc_core_dump_Elf32_Ehdr(xd->xc_core.elf32);
		break;
	case ELFCLASS64:
		xc_core_dump_Elf64_Ehdr(xd->xc_core.elf64);
		break;
	}
}


/*
 *  Dump the 32-bit ELF header, and grab a pointer to the strtab section.
 */
static void 
xc_core_dump_Elf32_Ehdr(Elf32_Ehdr *elf)
{
	char buf[BUFSIZE];
	Elf32_Off offset32;
	Elf32_Shdr shdr;

	BZERO(buf, BUFSIZE);
	BCOPY(elf->e_ident, buf, SELFMAG); 
	xendump_print("\nElf32_Ehdr:\n");
	xendump_print("                e_ident: \\%o%s\n", buf[0], 
		&buf[1]);
	xendump_print("      e_ident[EI_CLASS]: %d ", elf->e_ident[EI_CLASS]);
	switch (elf->e_ident[EI_CLASS])
	{
	case ELFCLASSNONE:
		xendump_print("(ELFCLASSNONE)");
		break;
	case ELFCLASS32:
		xendump_print("(ELFCLASS32)\n");
		break;
	case ELFCLASS64:
		xendump_print("(ELFCLASS64)\n");
		break;
	case ELFCLASSNUM:
		xendump_print("(ELFCLASSNUM)\n");
		break;
	default:
		xendump_print("(?)\n");
		break;
	}
	xendump_print("       e_ident[EI_DATA]: %d ", elf->e_ident[EI_DATA]);
	switch (elf->e_ident[EI_DATA])
	{
	case ELFDATANONE:
		xendump_print("(ELFDATANONE)\n");
		break;
	case ELFDATA2LSB: 
		xendump_print("(ELFDATA2LSB)\n");
		break;
	case ELFDATA2MSB:
		xendump_print("(ELFDATA2MSB)\n");
		break;
	case ELFDATANUM:
		xendump_print("(ELFDATANUM)\n");
		break;
        default:
                xendump_print("(?)\n");
	}
	xendump_print("    e_ident[EI_VERSION]: %d ", 
		elf->e_ident[EI_VERSION]);
	if (elf->e_ident[EI_VERSION] == EV_CURRENT)
		xendump_print("(EV_CURRENT)\n");
	else
		xendump_print("(?)\n");
	xendump_print("      e_ident[EI_OSABI]: %d ", elf->e_ident[EI_OSABI]);
	switch (elf->e_ident[EI_OSABI])
	{
	case ELFOSABI_SYSV:   
		xendump_print("(ELFOSABI_SYSV)\n");
		break;
	case ELFOSABI_HPUX:    
		xendump_print("(ELFOSABI_HPUX)\n");
		break;
	case ELFOSABI_ARM:      
		xendump_print("(ELFOSABI_ARM)\n");
		break;
	case ELFOSABI_STANDALONE:
		xendump_print("(ELFOSABI_STANDALONE)\n");
		break;
        default:
                xendump_print("(?)\n");
	}
	xendump_print(" e_ident[EI_ABIVERSION]: %d\n", 
		elf->e_ident[EI_ABIVERSION]);

	xendump_print("                 e_type: %d ", elf->e_type);
	switch (elf->e_type)
	{
	case ET_NONE:
		xendump_print("(ET_NONE)\n");
		break;
	case ET_REL:
		xendump_print("(ET_REL)\n");
		break;
	case ET_EXEC:
		xendump_print("(ET_EXEC)\n");
		break;
	case ET_DYN:
		xendump_print("(ET_DYN)\n");
		break;
	case ET_CORE:
		xendump_print("(ET_CORE)\n");
		break;
	case ET_NUM:
		xendump_print("(ET_NUM)\n");
		break;
	case ET_LOOS:
		xendump_print("(ET_LOOS)\n");
		break;
	case ET_HIOS:
		xendump_print("(ET_HIOS)\n");
		break;
	case ET_LOPROC:
		xendump_print("(ET_LOPROC)\n");
		break;
	case ET_HIPROC:
		xendump_print("(ET_HIPROC)\n");
		break;
	default:
		xendump_print("(?)\n");
	}

        xendump_print("              e_machine: %d ", elf->e_machine);
	switch (elf->e_machine) 
	{
	case EM_386:
		xendump_print("(EM_386)\n");
		break;
	default:
		xendump_print("(unsupported)\n");
		break;
	}

        xendump_print("              e_version: %ld ", (ulong)elf->e_version);
	xendump_print("%s\n", elf->e_version == EV_CURRENT ? 
		"(EV_CURRENT)" : "");

        xendump_print("                e_entry: %lx\n", (ulong)elf->e_entry);
        xendump_print("                e_phoff: %lx\n", (ulong)elf->e_phoff);
        xendump_print("                e_shoff: %lx\n", (ulong)elf->e_shoff);
        xendump_print("                e_flags: %lx\n", (ulong)elf->e_flags);
        xendump_print("               e_ehsize: %x\n", elf->e_ehsize);
        xendump_print("            e_phentsize: %x\n", elf->e_phentsize);
        xendump_print("                e_phnum: %x\n", elf->e_phnum);
        xendump_print("            e_shentsize: %x\n", elf->e_shentsize);
        xendump_print("                e_shnum: %x\n", elf->e_shnum);
        xendump_print("             e_shstrndx: %x\n", elf->e_shstrndx);

	/* Determine the strtab location. */
	
	offset32 = elf->e_shoff +
		(elf->e_shstrndx * elf->e_shentsize);

        if (lseek(xd->xfd, offset32, SEEK_SET) != offset32)
                error(FATAL, 
		    "xc_core_dump_Elf32_Ehdr: cannot seek to strtab Elf32_Shdr\n");
        if (read(xd->xfd, &shdr, sizeof(Elf32_Shdr)) != sizeof(Elf32_Shdr))
                error(FATAL, 
		    "xc_core_dump_Elf32_Ehdr: cannot read strtab Elf32_Shdr\n");

	xd->xc_core.elf_strtab_offset = (ulonglong)shdr.sh_offset;
}

/*
 *  Dump the 64-bit ELF header, and grab a pointer to the strtab section.
 */
static void 
xc_core_dump_Elf64_Ehdr(Elf64_Ehdr *elf)
{
	char buf[BUFSIZE];
        Elf64_Off offset64;
        Elf64_Shdr shdr;

	BZERO(buf, BUFSIZE);
	BCOPY(elf->e_ident, buf, SELFMAG); 
	xendump_print("\nElf64_Ehdr:\n");
	xendump_print("                e_ident: \\%o%s\n", buf[0], 
		&buf[1]);
	xendump_print("      e_ident[EI_CLASS]: %d ", elf->e_ident[EI_CLASS]);
	switch (elf->e_ident[EI_CLASS])
	{
	case ELFCLASSNONE:
		xendump_print("(ELFCLASSNONE)");
		break;
	case ELFCLASS32:
		xendump_print("(ELFCLASS32)\n");
		break;
	case ELFCLASS64:
		xendump_print("(ELFCLASS64)\n");
		break;
	case ELFCLASSNUM:
		xendump_print("(ELFCLASSNUM)\n");
		break;
	default:
		xendump_print("(?)\n");
		break;
	}
	xendump_print("       e_ident[EI_DATA]: %d ", elf->e_ident[EI_DATA]);
	switch (elf->e_ident[EI_DATA])
	{
	case ELFDATANONE:
		xendump_print("(ELFDATANONE)\n");
		break;
	case ELFDATA2LSB: 
		xendump_print("(ELFDATA2LSB)\n");
		break;
	case ELFDATA2MSB:
		xendump_print("(ELFDATA2MSB)\n");
		break;
	case ELFDATANUM:
		xendump_print("(ELFDATANUM)\n");
		break;
        default:
                xendump_print("(?)\n");
	}
	xendump_print("    e_ident[EI_VERSION]: %d ", 
		elf->e_ident[EI_VERSION]);
	if (elf->e_ident[EI_VERSION] == EV_CURRENT)
		xendump_print("(EV_CURRENT)\n");
	else
		xendump_print("(?)\n");
	xendump_print("      e_ident[EI_OSABI]: %d ", elf->e_ident[EI_OSABI]);
	switch (elf->e_ident[EI_OSABI])
	{
	case ELFOSABI_SYSV:   
		xendump_print("(ELFOSABI_SYSV)\n");
		break;
	case ELFOSABI_HPUX:    
		xendump_print("(ELFOSABI_HPUX)\n");
		break;
	case ELFOSABI_ARM:      
		xendump_print("(ELFOSABI_ARM)\n");
		break;
	case ELFOSABI_STANDALONE:
		xendump_print("(ELFOSABI_STANDALONE)\n");
		break;
        default:
                xendump_print("(?)\n");
	}
	xendump_print(" e_ident[EI_ABIVERSION]: %d\n", 
		elf->e_ident[EI_ABIVERSION]);

	xendump_print("                 e_type: %d ", elf->e_type);
	switch (elf->e_type)
	{
	case ET_NONE:
		xendump_print("(ET_NONE)\n");
		break;
	case ET_REL:
		xendump_print("(ET_REL)\n");
		break;
	case ET_EXEC:
		xendump_print("(ET_EXEC)\n");
		break;
	case ET_DYN:
		xendump_print("(ET_DYN)\n");
		break;
	case ET_CORE:
		xendump_print("(ET_CORE)\n");
		break;
	case ET_NUM:
		xendump_print("(ET_NUM)\n");
		break;
	case ET_LOOS:
		xendump_print("(ET_LOOS)\n");
		break;
	case ET_HIOS:
		xendump_print("(ET_HIOS)\n");
		break;
	case ET_LOPROC:
		xendump_print("(ET_LOPROC)\n");
		break;
	case ET_HIPROC:
		xendump_print("(ET_HIPROC)\n");
		break;
	default:
		xendump_print("(?)\n");
	}

        xendump_print("              e_machine: %d ", elf->e_machine);
        switch (elf->e_machine)
        {
	case EM_386:
		xendump_print("(EM_386)\n");
		break;
        case EM_IA_64:
                xendump_print("(EM_IA_64)\n");
                break;
        case EM_PPC64:
                xendump_print("(EM_PPC64)\n");
                break;
        case EM_X86_64:
                xendump_print("(EM_X86_64)\n");
                break;
        default:
                xendump_print("(unsupported)\n");
                break;
        }

        xendump_print("              e_version: %ld ", (ulong)elf->e_version);
	xendump_print("%s\n", elf->e_version == EV_CURRENT ? 
		"(EV_CURRENT)" : "");

        xendump_print("                e_entry: %lx\n", (ulong)elf->e_entry);
        xendump_print("                e_phoff: %lx\n", (ulong)elf->e_phoff);
        xendump_print("                e_shoff: %lx\n", (ulong)elf->e_shoff);
        xendump_print("                e_flags: %lx\n", (ulong)elf->e_flags);
        xendump_print("               e_ehsize: %x\n", elf->e_ehsize);
        xendump_print("            e_phentsize: %x\n", elf->e_phentsize);
        xendump_print("                e_phnum: %x\n", elf->e_phnum);
        xendump_print("            e_shentsize: %x\n", elf->e_shentsize);
        xendump_print("                e_shnum: %x\n", elf->e_shnum);
        xendump_print("             e_shstrndx: %x\n", elf->e_shstrndx);

	/* Determine the strtab location. */

	offset64 = elf->e_shoff +
		(elf->e_shstrndx * elf->e_shentsize);

        if (lseek(xd->xfd, offset64, SEEK_SET) != offset64)
                error(FATAL, 
		    "xc_core_dump_Elf64_Ehdr: cannot seek to strtab Elf32_Shdr\n");
        if (read(xd->xfd, &shdr, sizeof(Elf32_Shdr)) != sizeof(Elf32_Shdr))
                error(FATAL, 
		    "xc_core_dump_Elf64_Ehdr:  cannot read strtab Elf32_Shdr\n");

	xd->xc_core.elf_strtab_offset = (ulonglong)shdr.sh_offset;
}

/*
 *  Dump each 32-bit section header and the data that they reference.
 */
static void 
xc_core_dump_Elf32_Shdr(Elf32_Off offset, int store)
{
	Elf32_Shdr shdr;
	char name[BUFSIZE];
	int i;
	char c;

	if (lseek(xd->xfd, offset, SEEK_SET) != offset)
		error(FATAL, 
		    "xc_core_dump_Elf32_Shdr: cannot seek to Elf32_Shdr\n");
	if (read(xd->xfd, &shdr, sizeof(Elf32_Shdr)) != sizeof(Elf32_Shdr)) 
		error(FATAL, 
		    "xc_core_dump_Elf32_Shdr: cannot read Elf32_Shdr\n");

	xendump_print("\nElf32_Shdr:\n");
	xendump_print("                sh_name: %lx ", shdr.sh_name);
	xendump_print("\"%s\"\n", xc_core_strtab(shdr.sh_name, name));
	xendump_print("                sh_type: %lx ", shdr.sh_type);
	switch (shdr.sh_type)
	{
	case SHT_NULL:
		xendump_print("(SHT_NULL)\n");
		break;
	case SHT_PROGBITS:
		xendump_print("(SHT_PROGBITS)\n");
		break;
	case SHT_STRTAB:
		xendump_print("(SHT_STRTAB)\n");
		break;
	case SHT_NOTE:
		xendump_print("(SHT_NOTE)\n");
		break;
	default:
		xendump_print("\n");
		break;
	}
	xendump_print("               sh_flags: %lx\n", shdr.sh_flags);
	xendump_print("                sh_addr: %lx\n", shdr.sh_addr);
	xendump_print("              sh_offset: %lx\n", shdr.sh_offset);
	xendump_print("                sh_size: %lx\n", shdr.sh_size);
	xendump_print("                sh_link: %lx\n", shdr.sh_link);
	xendump_print("                sh_info: %lx\n", shdr.sh_info);
	xendump_print("           sh_addralign: %lx\n", shdr.sh_addralign);
	xendump_print("             sh_entsize: %lx\n", shdr.sh_entsize);

	if (STREQ(name, ".shstrtab")) {
		if (lseek(xd->xfd, xd->xc_core.elf_strtab_offset, SEEK_SET) != 
		    xd->xc_core.elf_strtab_offset)
			error(FATAL,
			    "xc_core_dump_Elf32_Shdr: cannot seek to strtab data\n");

		xendump_print("                         ");
		for (i = 0; i < shdr.sh_size; i++) {
			if (read(xd->xfd, &c, sizeof(char)) != sizeof(char)) 
				error(FATAL, 
				    "xc_core_dump_Elf32_Shdr: cannot read strtab data\n");
			if (i && !c)
				xendump_print("\n                         ");
			else
				xendump_print("%c", c);
		}
        }

	if (STREQ(name, ".note.Xen"))
		xc_core_dump_elfnote((off_t)shdr.sh_offset, 
			(size_t)shdr.sh_size, store);

	if (!store)
		return;

	if (STREQ(name, ".xen_prstatus"))
		xd->xc_core.header.xch_ctxt_offset =
			(off_t)shdr.sh_offset;

	if (STREQ(name, ".xen_shared_info"))
		xd->xc_core.shared_info_offset = (off_t)shdr.sh_offset;

	if (STREQ(name, ".xen_pfn")) {
		xd->xc_core.header.xch_index_offset =
			(off_t)shdr.sh_offset;
		xd->flags |= (XC_CORE_NO_P2M|XC_CORE_PFN_CREATE);
	}

	if (STREQ(name, ".xen_p2m")) {
		xd->xc_core.header.xch_index_offset =
			(off_t)shdr.sh_offset;
		xd->flags |= XC_CORE_PFN_CREATE;
	}

	if (STREQ(name, ".xen_pages"))
		xd->xc_core.header.xch_pages_offset =
			(off_t)shdr.sh_offset;

	if (STREQ(name, ".xen_ia64_mapped_regs"))
		xd->xc_core.ia64_mapped_regs_offset = 
			(off_t)shdr.sh_offset;
}

/*
 *  Dump each 64-bit section header and the data that they reference.
 */
static void 
xc_core_dump_Elf64_Shdr(Elf64_Off offset, int store)
{
	Elf64_Shdr shdr;
	char name[BUFSIZE];
	int i;
	char c;

	if (lseek(xd->xfd, offset, SEEK_SET) != offset)
		error(FATAL, 
		    "xc_core_dump_Elf64_Shdr: cannot seek to Elf64_Shdr\n");
	if (read(xd->xfd, &shdr, sizeof(Elf64_Shdr)) != sizeof(Elf64_Shdr))
		error(FATAL, 
		    "xc_core_dump_Elf64_Shdr: cannot read Elf64_Shdr\n");

	xendump_print("\nElf64_Shdr:\n");
	xendump_print("                sh_name: %x ", shdr.sh_name);
	xendump_print("\"%s\"\n", xc_core_strtab(shdr.sh_name, name));
	xendump_print("                sh_type: %x ", shdr.sh_type);
	switch (shdr.sh_type)
	{
	case SHT_NULL:
		xendump_print("(SHT_NULL)\n");
		break;
	case SHT_PROGBITS:
		xendump_print("(SHT_PROGBITS)\n");
		break;
	case SHT_STRTAB:
		xendump_print("(SHT_STRTAB)\n");
		break;
	case SHT_NOTE:
		xendump_print("(SHT_NOTE)\n");
		break;
	default:
		xendump_print("\n");
		break;
	}
	xendump_print("               sh_flags: %lx\n", shdr.sh_flags);
	xendump_print("                sh_addr: %lx\n", shdr.sh_addr);
	xendump_print("              sh_offset: %lx\n", shdr.sh_offset);
	xendump_print("                sh_size: %lx\n", shdr.sh_size);
	xendump_print("                sh_link: %x\n", shdr.sh_link);
	xendump_print("                sh_info: %x\n", shdr.sh_info);
	xendump_print("           sh_addralign: %lx\n", shdr.sh_addralign);
	xendump_print("             sh_entsize: %lx\n", shdr.sh_entsize);

	if (STREQ(name, ".shstrtab")) {
		if (lseek(xd->xfd, xd->xc_core.elf_strtab_offset, SEEK_SET) != 
		    xd->xc_core.elf_strtab_offset)
			error(FATAL,
			    "xc_core_dump_Elf64_Shdr: cannot seek to strtab data\n");

		xendump_print("                         ");
		for (i = 0; i < shdr.sh_size; i++) {
			if (read(xd->xfd, &c, sizeof(char)) != sizeof(char)) 
				error(FATAL, 
				    "xc_core_dump_Elf64_Shdr: cannot read strtab data\n");
			if (i && !c)
				xendump_print("\n                         ");
			else
				xendump_print("%c", c);
		}
	}

	if (STREQ(name, ".note.Xen"))
		xc_core_dump_elfnote((off_t)shdr.sh_offset, 
			(size_t)shdr.sh_size, store);

	if (!store)
		return;

	if (STREQ(name, ".xen_prstatus"))
		xd->xc_core.header.xch_ctxt_offset =
			(off_t)shdr.sh_offset;

	if (STREQ(name, ".xen_shared_info"))
		xd->xc_core.shared_info_offset = (off_t)shdr.sh_offset;

	if (STREQ(name, ".xen_pfn")) {
		xd->xc_core.header.xch_index_offset =
			(off_t)shdr.sh_offset;
		xd->flags |= (XC_CORE_NO_P2M|XC_CORE_PFN_CREATE);
	}

	if (STREQ(name, ".xen_p2m")) {
		xd->xc_core.header.xch_index_offset =
			(off_t)shdr.sh_offset;
		xd->flags |= XC_CORE_PFN_CREATE;
	}

	if (STREQ(name, ".xen_pages"))
		xd->xc_core.header.xch_pages_offset =
			(off_t)shdr.sh_offset;

	if (STREQ(name, ".xen_ia64_mapped_regs"))
		xd->xc_core.ia64_mapped_regs_offset = 
			(off_t)shdr.sh_offset;
}

/*
 *  Return the string found at the specified index into
 *  the dumpfile's strtab.
 */
static char *
xc_core_strtab(uint32_t index, char *buf)
{
	off_t offset;
	int i;

	offset = xd->xc_core.elf_strtab_offset + index;

	if (lseek(xd->xfd, offset, SEEK_SET) != offset)
		error(FATAL, 
		    "xc_core_strtab: cannot seek to Elf64_Shdr\n");

	BZERO(buf, BUFSIZE);
	i = 0;

	while (read(xd->xfd, &buf[i], sizeof(char)) == sizeof(char)) {
		if (buf[i] == NULLCHAR)
			break;
		i++;
	}

	return buf;
}


/*
 *  Dump the array of elfnote structures, storing relevant info
 *  when requested during initialization.  This function is 
 *  common to both 32-bit and 64-bit ELF files.
 */
static void 
xc_core_dump_elfnote(off_t sh_offset, size_t sh_size, int store)
{
	int i, lf, index;
	char *notes_buffer;
	struct elfnote *elfnote;
	ulonglong *data;
	struct xen_dumpcore_elfnote_header_desc *elfnote_header;
	struct xen_dumpcore_elfnote_format_version_desc *format_version;

	elfnote_header = NULL;
	format_version = NULL;

        if (!(notes_buffer = (char *)malloc(sh_size)))
                error(FATAL, "cannot malloc notes space.");

	if (lseek(xd->xfd, sh_offset, SEEK_SET) != sh_offset)
		error(FATAL, 
		    "xc_core_dump_elfnote: cannot seek to sh_offset\n");

        if (read(xd->xfd, notes_buffer, sh_size) != sh_size)
                error(FATAL,
                    "xc_core_dump_elfnote: cannot read elfnote data\n");

	for (index = 0; index < sh_size; ) {
		elfnote = (struct elfnote *)&notes_buffer[index];
		xendump_print("                 namesz: %d\n", elfnote->namesz);
		xendump_print("                  descz: %d\n", elfnote->descsz);
		xendump_print("                   type: %x ", elfnote->type);
		switch (elfnote->type) 
		{
		case XEN_ELFNOTE_DUMPCORE_NONE:           
			xendump_print("(XEN_ELFNOTE_DUMPCORE_NONE)\n");
			break;
		case XEN_ELFNOTE_DUMPCORE_HEADER:
			xendump_print("(XEN_ELFNOTE_DUMPCORE_HEADER)\n");
			elfnote_header = (struct xen_dumpcore_elfnote_header_desc *)
				(elfnote+1);
			break;
		case XEN_ELFNOTE_DUMPCORE_XEN_VERSION:   
			xendump_print("(XEN_ELFNOTE_DUMPCORE_XEN_VERSION)\n");
			break;
		case XEN_ELFNOTE_DUMPCORE_FORMAT_VERSION:
			xendump_print("(XEN_ELFNOTE_DUMPCORE_FORMAT_VERSION)\n");
			format_version = (struct xen_dumpcore_elfnote_format_version_desc *)
				(elfnote+1);
			break;
		default:
			xendump_print("(unknown)\n");
			break;
		}
		xendump_print("                   name: %s\n", elfnote->name);

		data = (ulonglong *)(elfnote+1);
		for (i = lf = 0; i < elfnote->descsz/sizeof(ulonglong); i++) {
			if (((i%2)==0)) {
				xendump_print("%s                         ",
					i ? "\n" : "");
				lf++;
			} else
				lf = 0;
			xendump_print("%016llx ", *data++);
                }
		if (!elfnote->descsz)
			xendump_print("                         (empty)");
		xendump_print("\n");

		index += sizeof(struct elfnote) + elfnote->descsz;
	}

	if (!store) {
		free(notes_buffer);
		return;
	}

	if (elfnote_header) {
		xd->xc_core.header.xch_magic = elfnote_header->xch_magic;
		xd->xc_core.header.xch_nr_vcpus = elfnote_header->xch_nr_vcpus;
		xd->xc_core.header.xch_nr_pages = elfnote_header->xch_nr_pages;
		xd->page_size = elfnote_header->xch_page_size;
	}

	if (format_version) {
		switch (format_version->version)
		{
		case FORMAT_VERSION_0000000000000001:
			break;
		default:
			error(WARNING, 
			    "unsupported xen dump-core format version: %016llx\n",
				format_version->version);
		}
		xd->xc_core.format_version = format_version->version;
	}

	free(notes_buffer);
}

/*
 *  Initialize the batching list for the .xen_p2m or .xen_pfn
 *  arrays.
 */
static void 
xc_core_elf_pfn_init(void)
{
	int i, c, chunk;
	off_t offset;
	struct xen_dumpcore_p2m p2m;
	uint64_t pfn;

	switch (xd->flags & (XC_CORE_ELF|XC_CORE_NO_P2M)) 
	{
	case (XC_CORE_ELF|XC_CORE_NO_P2M):
		chunk = xd->xc_core.header.xch_nr_pages/INDEX_PFN_COUNT;

		for (i = c = 0; i < INDEX_PFN_COUNT; i++, c += chunk) {
			offset = xd->xc_core.header.xch_index_offset +
				(off_t)(c * sizeof(uint64_t));

	        	if (lseek(xd->xfd, offset, SEEK_SET) == -1)
	                	error(FATAL, 
				    "cannot lseek to page index %d\n", c);
			if (read(xd->xfd, &pfn, sizeof(uint64_t)) != 
			    sizeof(uint64_t))
	                	error(FATAL, 
				    "cannot read page index %d\n", c);

			xd->xc_core.elf_index_pfn[i].index = c;
			xd->xc_core.elf_index_pfn[i].pfn = (ulong)pfn;
		}
		break;

	case XC_CORE_ELF:
		chunk = xd->xc_core.header.xch_nr_pages/INDEX_PFN_COUNT;
	
		for (i = c = 0; i < INDEX_PFN_COUNT; i++, c += chunk) {
			offset = xd->xc_core.header.xch_index_offset +
				(off_t)(c * sizeof(struct xen_dumpcore_p2m));

	        	if (lseek(xd->xfd, offset, SEEK_SET) == -1)
	                	error(FATAL, 
				    "cannot lseek to page index %d\n", c);
			if (read(xd->xfd, &p2m, sizeof(struct xen_dumpcore_p2m)) !=
				sizeof(struct xen_dumpcore_p2m))
	                	error(FATAL, 
				    "cannot read page index %d\n", c);
	
			xd->xc_core.elf_index_pfn[i].index = c;
			xd->xc_core.elf_index_pfn[i].pfn = (ulong)p2m.pfn;
		}
		break;
	}
}

struct xendump_data *
get_xendump_data(void)
{
	return (XENDUMP_VALID() ? xd : NULL);
}
