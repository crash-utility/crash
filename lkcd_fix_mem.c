/* lkcd_fix_mem.c
 *
 * Copyright (C) 2004 Hewlett-Packard Development Company, L.P.
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

#ifdef IA64

#define LKCD_COMMON
#include "defs.h"
#include "lkcd_dump_v8.h"

static int fix_addr(dump_header_asm_t *); 
    
int
fix_addr_v8(dump_header_asm_t *dha)
{
    fix_addr(dha);

    return 0;
}

int
fix_addr_v7(int fd)
{
    static dump_header_asm_t dump_header_asm_v7 = { 0 };
    dump_header_asm_t *dha;
    dha = &dump_header_asm_v7;
    
    if (read(lkcd->fd, dha, sizeof(dump_header_asm_t)) !=
	    sizeof(dump_header_asm_t))
	return -1;

    fix_addr(dha);
    
    return 0;
}

static int
fix_addr(dump_header_asm_t *dha)  
{
    lkcd->dump_header_asm = dha;
    

    if (dha->dha_magic_number == DUMP_ASM_MAGIC_NUMBER && dha->dha_version > 3) {
	int num;
	int i = 0;

	num = dha->dha_smp_num_cpus;
    

	lkcd->fix_addr_num = 0;
	if (num && (lkcd->fix_addr = malloc(num * sizeof(struct fix_addrs)))) {
	    while (i < num) {
		if (dha->dha_stack[i] && dha->dha_smp_current_task[i]) {
		    lkcd->fix_addr[i].task = (ulong)dha->dha_smp_current_task[i];
		    lkcd->fix_addr[i].saddr = (ulong)dha->dha_stack[i]; 
		    lkcd->fix_addr[i].sw = (ulong)dha->dha_stack_ptr[i];
		    /* remember the highest non-zero entry */
		    lkcd->fix_addr_num = i + 1;
		} else {
		    lkcd->fix_addr[i].task = (ulong)0;
		}
		i++;
	    }
	}
    }

    return 0;
}

ulong
get_lkcd_switch_stack(ulong task)
{
	int i;

	if (lkcd->fix_addr_num == 0)
		return 0;

	for (i = 0; i < lkcd->fix_addr_num; i++) {
		if (task == lkcd->fix_addr[i].task) {
		    return lkcd->fix_addr[i].sw;
		}
	}
	return 0;
}

int lkcd_get_kernel_start_v8(ulong *addr)
{
	if (!addr)
		return 0;

	*addr = ((dump_header_asm_t *)lkcd->dump_header_asm)->dha_kernel_addr;

	return 1;
}

#endif // IA64
