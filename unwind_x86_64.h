/*
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

#define CONFIG_64BIT 1
#define NULL ((void *)0)

typedef unsigned long size_t;
typedef unsigned char u8;
typedef signed short s16;
typedef unsigned short u16;
typedef signed int s32;
typedef unsigned int u32;
typedef unsigned long long u64;

struct pt_regs {
        unsigned long r15;
        unsigned long r14;
        unsigned long r13;
        unsigned long r12;
        unsigned long rbp;
        unsigned long rbx;
/* arguments: non interrupts/non tracing syscalls only save upto here*/
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
/* end of arguments */
/* cpu exception frame or undefined */
        unsigned long rip;
        unsigned long cs;
        unsigned long eflags;
        unsigned long rsp;
        unsigned long ss;
/* top of stack page */
};

struct unwind_frame_info
{
        struct pt_regs regs;
};

extern int unwind(struct unwind_frame_info *, int);
extern void init_unwind_table(void);
extern void free_unwind_table(void);

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#define BUILD_BUG_ON_ZERO(e) (sizeof(struct { int:-!!(e); }))
#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))
#define get_unaligned(ptr) (*(ptr))
//#define __get_user(x,ptr)  __get_user_nocheck((x),(ptr),sizeof(*(ptr)))
#define THREAD_ORDER 1
#define THREAD_SIZE  (PAGE_SIZE << THREAD_ORDER)

#define UNW_PC(frame)        (frame)->regs.rip
#define UNW_SP(frame)        (frame)->regs.rsp
#ifdef CONFIG_FRAME_POINTER
	#define UNW_FP(frame)        (frame)->regs.rbp
	#define FRAME_RETADDR_OFFSET 8
	#define FRAME_LINK_OFFSET    0
	#define STACK_BOTTOM(tsk)    (((tsk)->thread.rsp0 - 1) & ~(THREAD_SIZE - 1))
	#define STACK_TOP(tsk)       ((tsk)->thread.rsp0)
#endif


#define EXTRA_INFO(f) { BUILD_BUG_ON_ZERO(offsetof(struct unwind_frame_info, f) % FIELD_SIZEOF(struct unwind_frame_info, f)) + offsetof(struct unwind_frame_info, f)/ FIELD_SIZEOF(struct unwind_frame_info, f), FIELD_SIZEOF(struct unwind_frame_info, f) }

#define PTREGS_INFO(f) EXTRA_INFO(regs.f)

#define UNW_REGISTER_INFO \
	PTREGS_INFO(rax),\
	PTREGS_INFO(rdx),\
	PTREGS_INFO(rcx),\
	PTREGS_INFO(rbx), \
	PTREGS_INFO(rsi), \
	PTREGS_INFO(rdi), \
	PTREGS_INFO(rbp), \
	PTREGS_INFO(rsp), \
	PTREGS_INFO(r8), \
	PTREGS_INFO(r9), \
	PTREGS_INFO(r10),\
	PTREGS_INFO(r11), \
	PTREGS_INFO(r12), \
	PTREGS_INFO(r13), \
	PTREGS_INFO(r14), \
	PTREGS_INFO(r15), \
	PTREGS_INFO(rip)

