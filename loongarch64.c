/* loongarch64.c - core analysis suite
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

#ifdef LOONGARCH64

#include <elf.h>
#include "defs.h"

/* from arch/loongarch/include/asm/ptrace.h */
struct loongarch64_pt_regs {
	/* Saved main processor registers. */
	unsigned long regs[32];

	/* Saved special registers. */
	unsigned long csr_crmd;
	unsigned long csr_prmd;
	unsigned long csr_euen;
	unsigned long csr_ecfg;
	unsigned long csr_estat;
	unsigned long csr_epc;
	unsigned long csr_badvaddr;
	unsigned long orig_a0;
};

struct loongarch64_unwind_frame {
        unsigned long sp;
        unsigned long pc;
        unsigned long ra;
};

void
loongarch64_dump_machdep_table(ulong arg)
{
}

void
loongarch64_init(int when)
{
}

void
loongarch64_display_regs_from_elf_notes(int cpu, FILE *ofp)
{
}

#else /* !LOONGARCH64 */

#include "defs.h"

void
loongarch64_display_regs_from_elf_notes(int cpu, FILE *ofp)
{
       return;
}

#endif /* !LOONGARCH64 */
