/*
 * Copyright (C) 1999-2000 Hewlett-Packard Co
 * Copyright (C) 1999-2000 David Mosberger-Tang <davidm@hpl.hp.com>
 */
/*
 * Copyright (C) 1998, 1999 Hewlett-Packard Co
 * Copyright (C) 1998, 1999 David Mosberger-Tang <davidm@hpl.hp.com>
 */

/*
 *  unwind.h
 *
 *  Copyright (C) 2002, 2003, 2004, 2005 David Anderson
 *  Copyright (C) 2002, 2003, 2004, 2005 Red Hat, Inc. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  Adapted from:
 *
 *    include/asm-ia64/fpu.h  (kernel-2.4.18-6.23)
 *    include/asm-ia64/unwind.h  (kernel-2.4.18-6.23)
 */

#ifndef _ASM_IA64_FPU_H
#define _ASM_IA64_FPU_H

struct ia64_fpreg {
        union {
                unsigned long bits[2];
        } u;
} __attribute__ ((aligned (16)));

#endif /* _ASM_IA64_FPU_H */

#ifndef _ASM_IA64_UNWIND_H
#define _ASM_IA64_UNWIND_H

/*
 * A simple API for unwinding kernel stacks.  This is used for
 * debugging and error reporting purposes.  The kernel doesn't need
 * full-blown stack unwinding with all the bells and whitles, so there
 * is not much point in implementing the full IA-64 unwind API (though
 * it would of course be possible to implement the kernel API on top
 * of it).
 */

struct task_struct;	/* forward declaration */
struct switch_stack;	/* forward declaration */

enum unw_application_register {
	UNW_AR_BSP,
	UNW_AR_BSPSTORE,
	UNW_AR_PFS,
	UNW_AR_RNAT,
	UNW_AR_UNAT,
	UNW_AR_LC,
	UNW_AR_EC,
	UNW_AR_FPSR,
	UNW_AR_RSC,
	UNW_AR_CCV,
        UNW_AR_CSD,
        UNW_AR_SSD
};

/*
 * The following declarations are private to the unwind
 * implementation:
 */

struct unw_stack {
	unsigned long limit;
	unsigned long top;
};

#define UNW_FLAG_INTERRUPT_FRAME	(1UL << 0)

/*
 * No user of this module should every access this structure directly
 * as it is subject to change.  It is declared here solely so we can
 * use automatic variables.
 */
struct unw_frame_info {
	struct unw_stack regstk;
	struct unw_stack memstk;
	unsigned int flags;
	short hint;
	short prev_script;

	/* current frame info: */
	unsigned long bsp;		/* backing store pointer value */
	unsigned long sp;		/* stack pointer value */
	unsigned long psp;		/* previous sp value */
	unsigned long ip;		/* instruction pointer value */
	unsigned long pr;		/* current predicate values */
	unsigned long *cfm_loc;		/* cfm save location (or NULL) */
#if defined(UNWIND_V2) || defined(UNWIND_V3)
	unsigned long pt;		/* struct pt_regs location */
#endif

	struct task_struct *task;
	struct switch_stack *sw;

	/* preserved state: */
	unsigned long *bsp_loc;		/* previous bsp save location */
	unsigned long *bspstore_loc;
	unsigned long *pfs_loc;
	unsigned long *rnat_loc;
	unsigned long *rp_loc;
	unsigned long *pri_unat_loc;
	unsigned long *unat_loc;
	unsigned long *pr_loc;
	unsigned long *lc_loc;
	unsigned long *fpsr_loc;
	struct unw_ireg {
		unsigned long *loc;
		struct unw_ireg_nat {
			long type : 3;			/* enum unw_nat_type */
			signed long off : 61;		/* NaT word is at loc+nat.off */
		} nat;
	} r4, r5, r6, r7;
	unsigned long *b1_loc, *b2_loc, *b3_loc, *b4_loc, *b5_loc;
	struct ia64_fpreg *f2_loc, *f3_loc, *f4_loc, *f5_loc, *fr_loc[16];
};

/*
 * The official API follows below:
 */

/*
 * Initialize unwind support.
 */
extern void unw_init (void);
extern void unw_create_gate_table (void);

extern void *unw_add_unwind_table (const char *name, unsigned long segment_base, unsigned long gp,
				   const void *table_start, const void *table_end);

extern void unw_remove_unwind_table (void *handle);

/*
 * Prepare to unwind blocked task t.
 */
#ifndef REDHAT
extern void unw_init_from_blocked_task (struct unw_frame_info *info, struct task_struct *t);

extern void unw_init_frame_info (struct unw_frame_info *info, struct task_struct *t,
				 struct switch_stack *sw);
#endif /* !REDHAT */

/*
 * Prepare to unwind the currently running thread.
 */
extern void unw_init_running (void (*callback)(struct unw_frame_info *info, void *arg), void *arg);

/*
 * Unwind to previous to frame.  Returns 0 if successful, negative
 * number in case of an error.
 */
#ifndef REDHAT
extern int unw_unwind (struct unw_frame_info *info);
#endif /* !REDHAT */

/*
 * Unwind until the return pointer is in user-land (or until an error
 * occurs).  Returns 0 if successful, negative number in case of
 * error.
 */
extern int unw_unwind_to_user (struct unw_frame_info *info);

#define unw_is_intr_frame(info)	(((info)->flags & UNW_FLAG_INTERRUPT_FRAME) != 0)

static inline int
unw_get_ip (struct unw_frame_info *info, unsigned long *valp)
{
	*valp = (info)->ip;
	return 0;
}

static inline int
unw_get_sp (struct unw_frame_info *info, unsigned long *valp)
{
	*valp = (info)->sp;
	return 0;
}

static inline int
unw_get_psp (struct unw_frame_info *info, unsigned long *valp)
{
	*valp = (info)->psp;
	return 0;
}

static inline int
unw_get_bsp (struct unw_frame_info *info, unsigned long *valp)
{
	*valp = (info)->bsp;
	return 0;
}

static inline int
unw_get_cfm (struct unw_frame_info *info, unsigned long *valp)
{
	*valp = *(info)->cfm_loc;
	return 0;
}

static inline int
unw_set_cfm (struct unw_frame_info *info, unsigned long val)
{
	*(info)->cfm_loc = val;
	return 0;
}

static inline int
unw_get_rp (struct unw_frame_info *info, unsigned long *val)
{
	if (!info->rp_loc)
		return -1;
	*val = *info->rp_loc;
	return 0;
}

#ifdef UNWIND_V1
extern int unw_access_gr_v1 (struct unw_frame_info *, int, unsigned long *, char *, int);
extern int unw_access_br_v1 (struct unw_frame_info *, int, unsigned long *, int);
extern int unw_access_fr_v1 (struct unw_frame_info *, int, struct ia64_fpreg *, int);
extern int unw_access_ar_v1 (struct unw_frame_info *, int, unsigned long *, int);
extern int unw_access_pr_v1 (struct unw_frame_info *, unsigned long *, int);

#define unw_access_gr unw_access_gr_v1
#define unw_access_br unw_access_br_v1
#define unw_access_fr unw_access_fr_v1
#define unw_access_ar unw_access_ar_v1
#define unw_access_pr unw_access_pr_v1
#endif

#ifdef UNWIND_V2
extern int unw_access_gr_v2 (struct unw_frame_info *, int, unsigned long *, char *, int);
extern int unw_access_br_v2 (struct unw_frame_info *, int, unsigned long *, int);
extern int unw_access_fr_v2 (struct unw_frame_info *, int, struct ia64_fpreg *, int);
extern int unw_access_ar_v2 (struct unw_frame_info *, int, unsigned long *, int);
extern int unw_access_pr_v2 (struct unw_frame_info *, unsigned long *, int);

#define unw_access_gr unw_access_gr_v2
#define unw_access_br unw_access_br_v2
#define unw_access_fr unw_access_fr_v2
#define unw_access_ar unw_access_ar_v2
#define unw_access_pr unw_access_pr_v2
#endif

#ifdef UNWIND_V3
extern int unw_access_gr_v3 (struct unw_frame_info *, int, unsigned long *, char *, int);
extern int unw_access_br_v3 (struct unw_frame_info *, int, unsigned long *, int);
extern int unw_access_fr_v3 (struct unw_frame_info *, int, struct ia64_fpreg *, int);
extern int unw_access_ar_v3 (struct unw_frame_info *, int, unsigned long *, int);
extern int unw_access_pr_v3 (struct unw_frame_info *, unsigned long *, int);

#define unw_access_gr unw_access_gr_v3
#define unw_access_br unw_access_br_v3
#define unw_access_fr unw_access_fr_v3
#define unw_access_ar unw_access_ar_v3
#define unw_access_pr unw_access_pr_v3
#endif

static inline int
unw_set_gr (struct unw_frame_info *i, int n, unsigned long v, char nat)
{
	return unw_access_gr(i, n, &v, &nat, 1);
}

static inline int
unw_set_br (struct unw_frame_info *i, int n, unsigned long v)
{
	return unw_access_br(i, n, &v, 1);
}

static inline int
unw_set_fr (struct unw_frame_info *i, int n, struct ia64_fpreg v)
{
	return unw_access_fr(i, n, &v, 1);
}

static inline int
unw_set_ar (struct unw_frame_info *i, int n, unsigned long v)
{
	return unw_access_ar(i, n, &v, 1);
}

static inline int
unw_set_pr (struct unw_frame_info *i, unsigned long v)
{
	return unw_access_pr(i, &v, 1);
}

#define unw_get_gr(i,n,v,nat)	unw_access_gr(i,n,v,nat,0)
#define unw_get_br(i,n,v)	unw_access_br(i,n,v,0)
#define unw_get_fr(i,n,v)	unw_access_fr(i,n,v,0)
#define unw_get_ar(i,n,v)	unw_access_ar(i,n,v,0)
#define unw_get_pr(i,v)		unw_access_pr(i,v,0)

#ifdef UNWIND_V1

struct switch_stack {
	unsigned long caller_unat;	/* user NaT collection register (preserved) */
	unsigned long ar_fpsr;		/* floating-point status register */

	struct ia64_fpreg f2;		/* preserved */
	struct ia64_fpreg f3;		/* preserved */
	struct ia64_fpreg f4;		/* preserved */
	struct ia64_fpreg f5;		/* preserved */

	struct ia64_fpreg f10;		/* scratch, but untouched by kernel */
	struct ia64_fpreg f11;		/* scratch, but untouched by kernel */
	struct ia64_fpreg f12;		/* scratch, but untouched by kernel */
	struct ia64_fpreg f13;		/* scratch, but untouched by kernel */
	struct ia64_fpreg f14;		/* scratch, but untouched by kernel */
	struct ia64_fpreg f15;		/* scratch, but untouched by kernel */
	struct ia64_fpreg f16;		/* preserved */
	struct ia64_fpreg f17;		/* preserved */
	struct ia64_fpreg f18;		/* preserved */
	struct ia64_fpreg f19;		/* preserved */
	struct ia64_fpreg f20;		/* preserved */
	struct ia64_fpreg f21;		/* preserved */
	struct ia64_fpreg f22;		/* preserved */
	struct ia64_fpreg f23;		/* preserved */
	struct ia64_fpreg f24;		/* preserved */
	struct ia64_fpreg f25;		/* preserved */
	struct ia64_fpreg f26;		/* preserved */
	struct ia64_fpreg f27;		/* preserved */
	struct ia64_fpreg f28;		/* preserved */
	struct ia64_fpreg f29;		/* preserved */
	struct ia64_fpreg f30;		/* preserved */
	struct ia64_fpreg f31;		/* preserved */

	unsigned long r4;		/* preserved */
	unsigned long r5;		/* preserved */
	unsigned long r6;		/* preserved */
	unsigned long r7;		/* preserved */

	unsigned long b0;		/* so we can force a direct return in copy_thread */
	unsigned long b1;
	unsigned long b2;
	unsigned long b3;
	unsigned long b4;
	unsigned long b5;

	unsigned long ar_pfs;		/* previous function state */
	unsigned long ar_lc;		/* loop counter (preserved) */
	unsigned long ar_unat;		/* NaT bits for r4-r7 */
	unsigned long ar_rnat;		/* RSE NaT collection register */
	unsigned long ar_bspstore;	/* RSE dirty base (preserved) */
	unsigned long pr;		/* 64 predicate registers (1 bit each) */
};
struct pt_regs {
	/* The following registers are saved by SAVE_MIN: */

	unsigned long cr_ipsr;		/* interrupted task's psr */
	unsigned long cr_iip;		/* interrupted task's instruction pointer */
	unsigned long cr_ifs;		/* interrupted task's function state */

	unsigned long ar_unat;		/* interrupted task's NaT register (preserved) */
	unsigned long ar_pfs;		/* prev function state  */
	unsigned long ar_rsc;		/* RSE configuration */
	/* The following two are valid only if cr_ipsr.cpl > 0: */
	unsigned long ar_rnat;		/* RSE NaT */
	unsigned long ar_bspstore;	/* RSE bspstore */

	unsigned long pr;		/* 64 predicate registers (1 bit each) */
	unsigned long b6;		/* scratch */
	unsigned long loadrs;		/* size of dirty partition << 16 */

	unsigned long r1;		/* the gp pointer */
	unsigned long r2;		/* scratch */
	unsigned long r3;		/* scratch */
	unsigned long r12;		/* interrupted task's memory stack pointer */
	unsigned long r13;		/* thread pointer */
	unsigned long r14;		/* scratch */
	unsigned long r15;		/* scratch */

	unsigned long r8;		/* scratch (return value register 0) */
	unsigned long r9;		/* scratch (return value register 1) */
	unsigned long r10;		/* scratch (return value register 2) */
	unsigned long r11;		/* scratch (return value register 3) */

	/* The following registers are saved by SAVE_REST: */

	unsigned long r16;		/* scratch */
	unsigned long r17;		/* scratch */
	unsigned long r18;		/* scratch */
	unsigned long r19;		/* scratch */
	unsigned long r20;		/* scratch */
	unsigned long r21;		/* scratch */
	unsigned long r22;		/* scratch */
	unsigned long r23;		/* scratch */
	unsigned long r24;		/* scratch */
	unsigned long r25;		/* scratch */
	unsigned long r26;		/* scratch */
	unsigned long r27;		/* scratch */
	unsigned long r28;		/* scratch */
	unsigned long r29;		/* scratch */
	unsigned long r30;		/* scratch */
	unsigned long r31;		/* scratch */

	unsigned long ar_ccv;		/* compare/exchange value (scratch) */
	unsigned long ar_fpsr;		/* floating point status (preserved) */

	unsigned long b0;		/* return pointer (bp) */
	unsigned long b7;		/* scratch */
	/*
	 * Floating point registers that the kernel considers
	 * scratch:
	 */
	struct ia64_fpreg f6;		/* scratch */
	struct ia64_fpreg f7;		/* scratch */
	struct ia64_fpreg f8;		/* scratch */
	struct ia64_fpreg f9;		/* scratch */
};
#endif  /* UNWIND_V1 */

#ifdef UNWIND_V2

struct switch_stack {
	unsigned long caller_unat;	/* user NaT collection register (preserved) */
	unsigned long ar_fpsr;		/* floating-point status register */

	struct ia64_fpreg f2;		/* preserved */
	struct ia64_fpreg f3;		/* preserved */
	struct ia64_fpreg f4;		/* preserved */
	struct ia64_fpreg f5;		/* preserved */

	struct ia64_fpreg f10;		/* scratch, but untouched by kernel */
	struct ia64_fpreg f11;		/* scratch, but untouched by kernel */
	struct ia64_fpreg f12;		/* scratch, but untouched by kernel */
	struct ia64_fpreg f13;		/* scratch, but untouched by kernel */
	struct ia64_fpreg f14;		/* scratch, but untouched by kernel */
	struct ia64_fpreg f15;		/* scratch, but untouched by kernel */
	struct ia64_fpreg f16;		/* preserved */
	struct ia64_fpreg f17;		/* preserved */
	struct ia64_fpreg f18;		/* preserved */
	struct ia64_fpreg f19;		/* preserved */
	struct ia64_fpreg f20;		/* preserved */
	struct ia64_fpreg f21;		/* preserved */
	struct ia64_fpreg f22;		/* preserved */
	struct ia64_fpreg f23;		/* preserved */
	struct ia64_fpreg f24;		/* preserved */
	struct ia64_fpreg f25;		/* preserved */
	struct ia64_fpreg f26;		/* preserved */
	struct ia64_fpreg f27;		/* preserved */
	struct ia64_fpreg f28;		/* preserved */
	struct ia64_fpreg f29;		/* preserved */
	struct ia64_fpreg f30;		/* preserved */
	struct ia64_fpreg f31;		/* preserved */

	unsigned long r4;		/* preserved */
	unsigned long r5;		/* preserved */
	unsigned long r6;		/* preserved */
	unsigned long r7;		/* preserved */

	unsigned long b0;		/* so we can force a direct return in copy_thread */
	unsigned long b1;
	unsigned long b2;
	unsigned long b3;
	unsigned long b4;
	unsigned long b5;

	unsigned long ar_pfs;		/* previous function state */
	unsigned long ar_lc;		/* loop counter (preserved) */
	unsigned long ar_unat;		/* NaT bits for r4-r7 */
	unsigned long ar_rnat;		/* RSE NaT collection register */
	unsigned long ar_bspstore;	/* RSE dirty base (preserved) */
	unsigned long pr;		/* 64 predicate registers (1 bit each) */
};
struct pt_regs {
	/* The following registers are saved by SAVE_MIN: */

	unsigned long cr_ipsr;		/* interrupted task's psr */
	unsigned long cr_iip;		/* interrupted task's instruction pointer */
	unsigned long cr_ifs;		/* interrupted task's function state */

	unsigned long ar_unat;		/* interrupted task's NaT register (preserved) */
	unsigned long ar_pfs;		/* prev function state  */
	unsigned long ar_rsc;		/* RSE configuration */
	/* The following two are valid only if cr_ipsr.cpl > 0: */
	unsigned long ar_rnat;		/* RSE NaT */
	unsigned long ar_bspstore;	/* RSE bspstore */

	unsigned long pr;		/* 64 predicate registers (1 bit each) */
	unsigned long b6;		/* scratch */
	unsigned long loadrs;		/* size of dirty partition << 16 */

	unsigned long r1;		/* the gp pointer */
	unsigned long r2;		/* scratch */
	unsigned long r3;		/* scratch */
	unsigned long r12;		/* interrupted task's memory stack pointer */
	unsigned long r13;		/* thread pointer */
	unsigned long r14;		/* scratch */
	unsigned long r15;		/* scratch */

	unsigned long r8;		/* scratch (return value register 0) */
	unsigned long r9;		/* scratch (return value register 1) */
	unsigned long r10;		/* scratch (return value register 2) */
	unsigned long r11;		/* scratch (return value register 3) */

	/* The following registers are saved by SAVE_REST: */

	unsigned long r16;		/* scratch */
	unsigned long r17;		/* scratch */
	unsigned long r18;		/* scratch */
	unsigned long r19;		/* scratch */
	unsigned long r20;		/* scratch */
	unsigned long r21;		/* scratch */
	unsigned long r22;		/* scratch */
	unsigned long r23;		/* scratch */
	unsigned long r24;		/* scratch */
	unsigned long r25;		/* scratch */
	unsigned long r26;		/* scratch */
	unsigned long r27;		/* scratch */
	unsigned long r28;		/* scratch */
	unsigned long r29;		/* scratch */
	unsigned long r30;		/* scratch */
	unsigned long r31;		/* scratch */

	unsigned long ar_ccv;		/* compare/exchange value (scratch) */
	unsigned long ar_fpsr;		/* floating point status (preserved) */

	unsigned long b0;		/* return pointer (bp) */
	unsigned long b7;		/* scratch */
	/*
	 * Floating point registers that the kernel considers
	 * scratch:
	 */
	struct ia64_fpreg f6;		/* scratch */
	struct ia64_fpreg f7;		/* scratch */
	struct ia64_fpreg f8;		/* scratch */
	struct ia64_fpreg f9;		/* scratch */
};
#endif /* UNWIND_V2 */

#ifdef UNWIND_V3
struct pt_regs {
	/* The following registers are saved by SAVE_MIN: */
	unsigned long b6;		/* scratch */
	unsigned long b7;		/* scratch */

	unsigned long ar_csd;           /* used by cmp8xchg16 (scratch) */
	unsigned long ar_ssd;           /* reserved for future use (scratch) */

	unsigned long r8;		/* scratch (return value register 0) */
	unsigned long r9;		/* scratch (return value register 1) */
	unsigned long r10;		/* scratch (return value register 2) */
	unsigned long r11;		/* scratch (return value register 3) */

	unsigned long cr_ipsr;		/* interrupted task's psr */
	unsigned long cr_iip;		/* interrupted task's instruction pointer */
	unsigned long cr_ifs;		/* interrupted task's function state */

	unsigned long ar_unat;		/* interrupted task's NaT register (preserved) */
	unsigned long ar_pfs;		/* prev function state  */
	unsigned long ar_rsc;		/* RSE configuration */
	/* The following two are valid only if cr_ipsr.cpl > 0: */
	unsigned long ar_rnat;		/* RSE NaT */
	unsigned long ar_bspstore;	/* RSE bspstore */

	unsigned long pr;		/* 64 predicate registers (1 bit each) */
	unsigned long b0;		/* return pointer (bp) */
	unsigned long loadrs;		/* size of dirty partition << 16 */

	unsigned long r1;		/* the gp pointer */
	unsigned long r12;		/* interrupted task's memory stack pointer */
	unsigned long r13;		/* thread pointer */

	unsigned long ar_fpsr;		/* floating point status (preserved) */
	unsigned long r15;		/* scratch */

	/* The remaining registers are NOT saved for system calls.  */

	unsigned long r14;		/* scratch */
	unsigned long r2;		/* scratch */
	unsigned long r3;		/* scratch */

	/* The following registers are saved by SAVE_REST: */
	unsigned long r16;		/* scratch */
	unsigned long r17;		/* scratch */
	unsigned long r18;		/* scratch */
	unsigned long r19;		/* scratch */
	unsigned long r20;		/* scratch */
	unsigned long r21;		/* scratch */
	unsigned long r22;		/* scratch */
	unsigned long r23;		/* scratch */
	unsigned long r24;		/* scratch */
	unsigned long r25;		/* scratch */
	unsigned long r26;		/* scratch */
	unsigned long r27;		/* scratch */
	unsigned long r28;		/* scratch */
	unsigned long r29;		/* scratch */
	unsigned long r30;		/* scratch */
	unsigned long r31;		/* scratch */

	unsigned long ar_ccv;		/* compare/exchange value (scratch) */

	/*
	 * Floating point registers that the kernel considers scratch:
	 */
	struct ia64_fpreg f6;		/* scratch */
	struct ia64_fpreg f7;		/* scratch */
	struct ia64_fpreg f8;		/* scratch */
	struct ia64_fpreg f9;		/* scratch */
	struct ia64_fpreg f10;		/* scratch */
	struct ia64_fpreg f11;		/* scratch */
};

/*
 * This structure contains the addition registers that need to
 * preserved across a context switch.  This generally consists of
 * "preserved" registers.
 */
struct switch_stack {
	unsigned long caller_unat;	/* user NaT collection register (preserved) */
	unsigned long ar_fpsr;		/* floating-point status register */

	struct ia64_fpreg f2;		/* preserved */
	struct ia64_fpreg f3;		/* preserved */
	struct ia64_fpreg f4;		/* preserved */
	struct ia64_fpreg f5;		/* preserved */

	struct ia64_fpreg f12;		/* scratch, but untouched by kernel */
	struct ia64_fpreg f13;		/* scratch, but untouched by kernel */
	struct ia64_fpreg f14;		/* scratch, but untouched by kernel */
	struct ia64_fpreg f15;		/* scratch, but untouched by kernel */
	struct ia64_fpreg f16;		/* preserved */
	struct ia64_fpreg f17;		/* preserved */
	struct ia64_fpreg f18;		/* preserved */
	struct ia64_fpreg f19;		/* preserved */
	struct ia64_fpreg f20;		/* preserved */
	struct ia64_fpreg f21;		/* preserved */
	struct ia64_fpreg f22;		/* preserved */
	struct ia64_fpreg f23;		/* preserved */
	struct ia64_fpreg f24;		/* preserved */
	struct ia64_fpreg f25;		/* preserved */
	struct ia64_fpreg f26;		/* preserved */
	struct ia64_fpreg f27;		/* preserved */
	struct ia64_fpreg f28;		/* preserved */
	struct ia64_fpreg f29;		/* preserved */
	struct ia64_fpreg f30;		/* preserved */
	struct ia64_fpreg f31;		/* preserved */

	unsigned long r4;		/* preserved */
	unsigned long r5;		/* preserved */
	unsigned long r6;		/* preserved */
	unsigned long r7;		/* preserved */

	unsigned long b0;		/* so we can force a direct return in copy_thread */
	unsigned long b1;
	unsigned long b2;
	unsigned long b3;
	unsigned long b4;
	unsigned long b5;

	unsigned long ar_pfs;		/* previous function state */
	unsigned long ar_lc;		/* loop counter (preserved) */
	unsigned long ar_unat;		/* NaT bits for r4-r7 */
	unsigned long ar_rnat;		/* RSE NaT collection register */
	unsigned long ar_bspstore;	/* RSE dirty base (preserved) */
	unsigned long pr;		/* 64 predicate registers (1 bit each) */
};
#endif /* UNWIND_V3 */
#endif /* _ASM_UNWIND_H */
