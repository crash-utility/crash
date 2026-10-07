/* lkcd_x86_64_pt_regs.h - core analysis suite
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
 *  The LKCD dump headers embed the host kernel's "struct pt_regs", which is
 *  normally picked up from <asm/ptrace.h>.  When the X86_64 target is built
 *  on a non-x86_64 host, that header describes the host architecture and does
 *  not export an x86_64 "struct pt_regs" at all, so the definition below is
 *  used instead.  It is a verbatim copy of "struct pt_regs" from
 *  arch/x86/include/uapi/asm/ptrace.h, which keeps the LKCD dump
 *  header layout identical to a native x86_64 build.
 */

#ifndef _LKCD_X86_64_PT_REGS_H
#define _LKCD_X86_64_PT_REGS_H

struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
	unsigned long orig_rax;
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags;
	unsigned long rsp;
	unsigned long ss;
};

#endif /* _LKCD_X86_64_PT_REGS_H */
