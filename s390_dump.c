/* s390_dump.c - core analysis suite
 *
 * Copyright (C) 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002, 2003, 2004, 2005, 2006 David Anderson
 * Copyright (C) 2002, 2003, 2004, 2005, 2006 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2005 Michael Holzheu, IBM Corporation
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
//#include <asm/page.h>
#include "ibm_common.h"

static FILE * s390_file;

int 
is_s390_dump(char *file) 
{
	FILE* fh;
	long long int magic;
	size_t items ATTRIBUTE_UNUSED;
	int rc;

	fh = fopen(file,"r");
	if (fh == NULL) {
		error(INFO, "is_s390_dump: cannot open %s: %s\n", file);
		return FALSE;
	}
	items = fread(&magic, sizeof(magic), 1,fh);
	if(magic == 0xa8190173618f23fdLL)
		rc = TRUE;
	else
		rc = FALSE;
	fclose(fh);
	return rc;
}

FILE*
s390_dump_init(char *file)
{
        if ((s390_file = fopen(file, "r+")) == NULL) {
		if ((s390_file = fopen(file, "r")) == NULL)
			return NULL;
	}

	return s390_file;
}

int
read_s390_dumpfile(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	paddr += S390_DUMP_HEADER_SIZE;

        if (fseek(s390_file, (ulong)paddr, SEEK_SET) != 0) 
		return SEEK_ERROR;

        if (fread(bufptr, 1 , cnt, s390_file) != cnt) 
		return READ_ERROR;

	return 0;
}

int
write_s390_dumpfile(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	return WRITE_ERROR;
}

#define S390_PAGE_SHIFT   12
#define S390_PAGE_SIZE    (1UL << S390_PAGE_SHIFT)

uint
s390_page_size(void)
{
	return S390_PAGE_SIZE;
}

int 
s390_memory_used(void)
{
	return 0;
}

int 
s390_free_memory(void)
{
	return 0;
}

int 
s390_memory_dump(FILE *fp)
{
	return 0;
}

ulong 
get_s390_panic_task(void)
{
	return BADVAL;
}

void 
get_s390_panicmsg(char *buf)
{
	return;
}
