/* mips64.c - core analysis suite
 *
 * Copyright (C) 2021 Loongson Technology Co., Ltd.
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
#ifdef MIPS64

#include <elf.h>
#include "defs.h"

void
mips64_dump_machdep_table(ulong arg)
{
}

void
mips64_init(int when)
{
}

void
mips64_display_regs_from_elf_notes(int cpu, FILE *ofp)
{
}

#else /* !MIPS64 */

#include "defs.h"

void
mips64_display_regs_from_elf_notes(int cpu, FILE *ofp)
{
	return;
}

#endif /* !MIPS64 */
