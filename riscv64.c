/* riscv64.c - core analysis suite
 *
 * Copyright (C) 2022 Alibaba Group Holding Limited.
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
#ifdef RISCV64

#include <elf.h>

void
riscv64_dump_machdep_table(ulong arg)
{
}

/*
 *  Include both vmalloc'd and module address space as VMALLOC space.
 */
int
riscv64_IS_VMALLOC_ADDR(ulong vaddr)
{
	return ((vaddr >= VMALLOC_START && vaddr <= VMALLOC_END) ||
		(vaddr >= VMEMMAP_VADDR && vaddr <= VMEMMAP_END) ||
		(vaddr >= MODULES_VADDR && vaddr <= MODULES_END));
}

void
riscv64_init(int when)
{
}

void
riscv64_display_regs_from_elf_notes(int cpu, FILE *ofp)
{
}

#else /* !RISCV64 */

void
riscv64_display_regs_from_elf_notes(int cpu, FILE *ofp)
{
	return;
}

#endif /* !RISCV64 */
