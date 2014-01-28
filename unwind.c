/*
 *  Copyright (C) 1999-2002 Hewlett-Packard Co
 *        David Mosberger-Tang <davidm@hpl.hp.com>
 */

/*
 *  unwind.c
 *
 *  Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2009, 2010, 2012 David Anderson
 *  Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2009, 2010, 2012 Red Hat, Inc. All rights reserved.
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
 *    arch/ia64/kernel/unwind.c  (kernel-2.4.18-6.23)
 */

#ifdef IA64

/*
 *  WARNING: unw_frame_info, pt_regs and switch_stack have been 
 *  copied to unwind.h, under the UNWIND_V[123] sections; this is
 *  done to rectify the need for this user-land code to use the same
 *  data structures that the target kernel is using.
 *
 *  Basically it's a juggling match to keep the unw_frame_info,
 *  switch_stack and pt_regs structures in a "known" state -- as defined by
 *  the UNWIND_V[123] definitions used in the unwind.h header file -- and 
 *  then passed to the 3 compile lines of unwind.c to create the three
 *  unwind_v[123].o object files.
 */

/*
 *  2004-09-14 J. Nomura    Added OS_INIT handling
 */

/* #include <asm/ptrace.h>  can't include this -- it's changing over time! */

#include "defs.h"
#include "xen_hyper_defs.h"

typedef unsigned char u8;
typedef unsigned long long u64;
#undef PAGE_SIZE
#define PAGE_SIZE PAGESIZE()
#define GATE_ADDR (0xa000000000000000 + PAGE_SIZE)
#define CLEAR_SCRIPT_CACHE (TRUE)

#define _ASM_IA64_FPU_H
#include "unwind.h"
#include "unwind_i.h"
#include "rse.h"

static struct unw_reg_state *alloc_reg_state(void);
static void free_reg_state(struct unw_reg_state *);
static void rse_function_params(struct bt_info *bt, struct unw_frame_info *, char *);
static int load_unw_table(int);
static void verify_unw_member(char *, long);
static void verify_common_struct(char *, long);
static void dump_unwind_table(struct unw_table *);
static int unw_init_from_blocked_task(struct unw_frame_info *, 
	struct bt_info *);
static void unw_init_from_interruption(struct unw_frame_info *,
	struct bt_info *, ulong, ulong);
static int unw_switch_from_osinit_v1(struct unw_frame_info *,
	struct bt_info *);
static int unw_switch_from_osinit_v2(struct unw_frame_info *,
	struct bt_info *);
static int unw_switch_from_osinit_v3(struct unw_frame_info *,
	struct bt_info *, char *);
static unsigned long get_init_stack_ulong(unsigned long addr);
static void unw_init_frame_info(struct unw_frame_info *, 
	struct bt_info *, ulong);
static int find_save_locs(struct unw_frame_info *);
static int unw_unwind(struct unw_frame_info *);
static void run_script(struct unw_script *, struct unw_frame_info *);
static struct unw_script *script_lookup(struct unw_frame_info *);
static struct unw_script *script_new(unsigned long);
static void script_finalize(struct unw_script *, struct unw_state_record *);
static void script_emit(struct unw_script *, struct unw_insn);
static void emit_nat_info(struct unw_state_record *, int, struct unw_script *);
static struct unw_script *build_script(struct unw_frame_info *);
static struct unw_table_entry *lookup(struct unw_table *, unsigned long);
static void compile_reg(struct unw_state_record *, int, struct unw_script *);
static void compile_reg_v2(struct unw_state_record *, int, struct unw_script *);

#define UNW_LOG_CACHE_SIZE      7   /* each unw_script is ~256 bytes in size */
#define UNW_CACHE_SIZE          (1 << UNW_LOG_CACHE_SIZE)

#define UNW_LOG_HASH_SIZE       (UNW_LOG_CACHE_SIZE + 1)
#define UNW_HASH_SIZE           (1 << UNW_LOG_HASH_SIZE)

#define UNW_DEBUG 0
#define UNW_STATS 0 

#define p5              5
#define pNonSys         p5      /* complement of pSys */

# define STAT(x...)

#define struct_offset(str,fld)  ((char *)&((str *)NULL)->fld - (char *) 0)

#undef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)


/*
 *  Local snapshot of kernel's "unw" table, minus the spinlock_t and anything
 *  after the kernel_table.  This allows the unmodified porting of the kernel
 *  code pieces that reference "unw.xxx" directly.
 *
 *  The 2.6 kernel introduced a new pt_regs_offsets[32] array positioned in 
 *  between the preg_index array and the kernel_table members.  
 */
#ifdef REDHAT
static struct unw {
#else
static struct {
	spinlock_t lock;			/* spinlock for unwind data */
#endif  /* !REDHAT */
	/* list of unwind tables (one per load-module) */
	struct unw_table *tables;

	/* table of registers that prologues can save 
           (and order in which they're saved): */
	unsigned char save_order[8];

	/* maps a preserved register index (preg_index) to corresponding 
           switch_stack offset: */
	unsigned short sw_off[sizeof(struct unw_frame_info) / 8];

	unsigned short lru_head;	/* index of lead-recently used script */
	unsigned short lru_tail;	/* index of most-recently used script */

	/* index into unw_frame_info for preserved register i */
	unsigned short preg_index[UNW_NUM_REGS];

	/* unwind table for the kernel: */
	struct unw_table kernel_table;

#ifndef REDHAT
	/* unwind table describing the gate page (kernel code that is mapped
	   into user space): */
	size_t gate_table_size;
	unsigned long *gate_table;

	/* hash table that maps instruction pointer to script index: */
	unsigned short hash[UNW_HASH_SIZE];

	/* script cache: */
	struct unw_script cache[UNW_CACHE_SIZE];
# if UNW_DEBUG
	const char *preg_name[UNW_NUM_REGS];
# endif
# if UNW_STATS
	struct {
		struct {
			int lookups;
			int hinted_hits;
			int normal_hits;
			int collision_chain_traversals;
		} cache;
		struct {
			unsigned long build_time;
			unsigned long run_time;
			unsigned long parse_time;
			int builds;
			int news;
			int collisions;
			int runs;
		} script;
		struct {
			unsigned long init_time;
			unsigned long unwind_time;
			int inits;
			int unwinds;
		} api;
	} stat;
# endif
#endif /* !REDHAT */
} unw = { 0 };

static short pt_regs_offsets[32] = { 0 };

static struct unw_reg_state *
alloc_reg_state(void)
{
	return((struct unw_reg_state *) GETBUF(sizeof(struct unw_reg_state)));
}

static void
free_reg_state(struct unw_reg_state *rs) 
{
	FREEBUF(rs);
}

static struct unw_labeled_state *
alloc_labeled_state(void)
{
	return((struct unw_labeled_state *) 
		GETBUF(sizeof(struct unw_labeled_state)));
}

static void
free_labeled_state(struct unw_labeled_state *ls)
{
	FREEBUF(ls);
}

typedef unsigned long unw_word;

/* Unwind accessors.  */

static inline unsigned long
pt_regs_off_v2 (unsigned long reg)
{
        short off = -1;

        if (reg < 32)
                off = pt_regs_offsets[reg];

        if (off < 0) {
		if (reg > 0)
                	error(INFO, "unwind: bad scratch reg r%lu\n", reg);
                off = 0;
        }
        return (unsigned long) off;
}

/*
 * Returns offset of rREG in struct pt_regs.
 */
static inline unsigned long
pt_regs_off (unsigned long reg)
{
	unsigned long off =0;

	if (machdep->flags & UNW_PTREGS)
		return pt_regs_off_v2(reg);

	if (reg >= 1 && reg <= 3)
		off = struct_offset(struct pt_regs, r1) + 8*(reg - 1);
	else if (reg <= 11)
		off = struct_offset(struct pt_regs, r8) + 8*(reg - 8);
	else if (reg <= 15)
		off = struct_offset(struct pt_regs, r12) + 8*(reg - 12);
	else if (reg <= 31)
		off = struct_offset(struct pt_regs, r16) + 8*(reg - 16);
	else if (reg > 0)
		error(INFO, "unwind: bad scratch reg r%lu\n", reg);
	return off;
}

#ifdef UNWIND_V1
static inline struct pt_regs *
get_scratch_regs (struct unw_frame_info *info)
{
	struct pt_regs *pt_unused = NULL;

	error(INFO, "get_scratch_regs: should not be here!\n");

	return pt_unused;
}
#endif
#ifdef UNWIND_V2
static inline struct pt_regs *
get_scratch_regs (struct unw_frame_info *info)
{
	if (!info->pt) {
		/* This should not happen with valid unwind info.  */
		error(INFO, 
		    "get_scratch_regs: bad unwind info: resetting info->pt\n");
		if (info->flags & UNW_FLAG_INTERRUPT_FRAME)
			info->pt = (unsigned long)((struct pt_regs *) 
				info->psp - 1);
		else
			info->pt = info->sp - 16;
	}
	return (struct pt_regs *) info->pt;
}
#endif
#ifdef UNWIND_V3
static inline struct pt_regs *
get_scratch_regs (struct unw_frame_info *info)
{
        if (!info->pt) {
                /* This should not happen with valid unwind info.  */
                error(INFO,
                    "get_scratch_regs: bad unwind info: resetting info->pt\n");
                if (info->flags & UNW_FLAG_INTERRUPT_FRAME)
                        info->pt = (unsigned long)((struct pt_regs *)
                                info->psp - 1);
                else
                        info->pt = info->sp - 16;
        }
        return (struct pt_regs *) info->pt;
}
#endif


int
#ifdef UNWIND_V1
unw_access_gr_v1 (struct unw_frame_info *info, int regnum, unsigned long *val, char *nat, int write)
#endif
#ifdef UNWIND_V2
unw_access_gr_v2 (struct unw_frame_info *info, int regnum, unsigned long *val, char *nat, int write)
#endif
#ifdef UNWIND_V3
unw_access_gr_v3 (struct unw_frame_info *info, int regnum, unsigned long *val, char *nat, int write)
#endif
{
	unsigned long *addr, *nat_addr, nat_mask = 0, dummy_nat;
	struct unw_ireg *ireg;
	struct pt_regs *pt;
	struct bt_info *bt = (struct bt_info *)info->task;

	if ((unsigned) regnum - 1 >= 127) {
		error(INFO, "unwind: trying to access non-existent r%u\n", 
			regnum);
		return -1;
	}

	if (regnum < 32) {
		if (regnum >= 4 && regnum <= 7) {
			/* access a preserved register */
			ireg = &info->r4 + (regnum - 4);
			addr = ireg->loc;
			if (addr) {
				nat_addr = addr + ireg->nat.off;
				switch (ireg->nat.type) {
				      case UNW_NAT_VAL:
					/* simulate getf.sig/setf.sig */
					if (write) {
						if (*nat) {
							/* write NaTVal and be done with it */
							addr[0] = 0;
							addr[1] = 0x1fffe;
							return 0;
						}
						addr[1] = 0x1003e;
					} else {
						if (addr[0] == 0 && addr[1] == 0x1ffe) {
							/* return NaT and be done with it */
							*val = 0;
							*nat = 1;
							return 0;
						}
					}
					/* fall through */
				      case UNW_NAT_NONE:
					dummy_nat = 0;
					nat_addr = &dummy_nat;
					break;

				      case UNW_NAT_MEMSTK:
					nat_mask = (1UL << ((long) addr & 0x1f8)/8);
					break;

				      case UNW_NAT_REGSTK:
					nat_addr = ia64_rse_rnat_addr(addr);
					if ((unsigned long) addr < info->regstk.limit
					    || (unsigned long) addr >= info->regstk.top)
					{
						error(INFO, 
						 "unwind: %p outside of regstk "
							"[0x%lx-0x%lx)\n", (void *) addr,
							info->regstk.limit,
							info->regstk.top);
						return -1;
					}
					if ((unsigned long) nat_addr >= info->regstk.top)
						nat_addr = &info->sw->ar_rnat;
					nat_mask = (1UL << ia64_rse_slot_num(addr));
					break;
				}
			} else {
				addr = &info->sw->r4 + (regnum - 4);
				nat_addr = &info->sw->ar_unat;
				nat_mask = (1UL << ((long) addr & 0x1f8)/8);
			}
		} else {
			/* access a scratch register */
			if (machdep->flags & UNW_PTREGS) {
				pt = get_scratch_regs(info);
				addr = (unsigned long *) ((unsigned long)pt + pt_regs_off(regnum));
			} else {
				if (info->flags & UNW_FLAG_INTERRUPT_FRAME)
					pt = (struct pt_regs *) info->psp - 1;
				else
					pt = (struct pt_regs *) info->sp - 1;
				addr = (unsigned long *) ((long) pt + pt_regs_off(regnum));
			}

			if (info->pri_unat_loc)
				nat_addr = info->pri_unat_loc;
			else
				nat_addr = &info->sw->ar_unat;
			nat_mask = (1UL << ((long) addr & 0x1f8)/8);
		}
	} else {
		/* access a stacked register */
		addr = ia64_rse_skip_regs((unsigned long *) info->bsp, regnum - 32);
		nat_addr = ia64_rse_rnat_addr(addr);
		if ((unsigned long) addr < info->regstk.limit
		    || (unsigned long) addr >= info->regstk.top)
		{
			error(INFO, "unwind: ignoring attempt to access register outside of rbs\n");
			return -1;
		}
		if ((unsigned long) nat_addr >= info->regstk.top)
			nat_addr = &info->sw->ar_rnat;
		nat_mask = (1UL << ia64_rse_slot_num(addr));
	}

	if (write) {
		*addr = *val;
		if (*nat)
			*nat_addr |= nat_mask;
		else
			*nat_addr &= ~nat_mask;
	} else {
		if ((IA64_GET_STACK_ULONG(nat_addr) & nat_mask) == 0) {
			*val = IA64_GET_STACK_ULONG(addr);
			*nat = 0;
		} else {
			*val = 0;	/* if register is a NaT, *addr may contain kernel data! */
			*nat = 1;
		}
	}
	return 0;
}

int
#ifdef UNWIND_V1
unw_access_br_v1 (struct unw_frame_info *info, int regnum, unsigned long *val, int write)
#endif
#ifdef UNWIND_V2
unw_access_br_v2 (struct unw_frame_info *info, int regnum, unsigned long *val, int write)
#endif
#ifdef UNWIND_V3
unw_access_br_v3 (struct unw_frame_info *info, int regnum, unsigned long *val, int write)
#endif
{
	unsigned long *addr;
	struct pt_regs *pt;
        struct bt_info *bt = (struct bt_info *)info->task;

	if (info->flags & UNW_FLAG_INTERRUPT_FRAME)
		pt = (struct pt_regs *) info->psp - 1;
	else
		pt = (struct pt_regs *) info->sp - 1;
	switch (regnum) {
		/* scratch: */
	      case 0: addr = &pt->b0; break;
	      case 6: addr = &pt->b6; break;
	      case 7: addr = &pt->b7; break;

		/* preserved: */
	      case 1: case 2: case 3: case 4: case 5:
		addr = *(&info->b1_loc + (regnum - 1));
		if (!addr)
			addr = &info->sw->b1 + (regnum - 1);
		break;

	      default:
		error(INFO, "unwind: trying to access non-existent b%u\n", 
			regnum);
		return -1;
	}
	if (write)
		*addr = *val;
	else
		*val = IA64_GET_STACK_ULONG(addr);
	return 0;
}

#ifdef UNWIND_V1
int
unw_access_fr_v1 (struct unw_frame_info *info, int regnum, struct ia64_fpreg *val, int write)
{
	struct ia64_fpreg *addr = 0;
	struct pt_regs *pt;
        struct bt_info *bt = (struct bt_info *)info->task;

	if ((unsigned) (regnum - 2) >= 126) {
		error(INFO, "unwind: trying to access non-existent f%u\n", 
			regnum);
		return -1;
	}

	if (info->flags & UNW_FLAG_INTERRUPT_FRAME)
		pt = (struct pt_regs *) info->psp - 1;
	else
		pt = (struct pt_regs *) info->sp - 1;

	if (regnum <= 5) {
                addr = *(&info->f2_loc + (regnum - 2));
		if (!addr)
			addr = &info->sw->f2 + (regnum - 2);
	} else if (regnum <= 15) {
		if (regnum <= 9)
			addr = &pt->f6  + (regnum - 6);
		else
			addr = &info->sw->f10 + (regnum - 10);
	} else if (regnum <= 31) {
		addr = info->fr_loc[regnum - 16];
		if (!addr)
			addr = &info->sw->f16 + (regnum - 16);
	} else {
#ifdef REDHAT
		struct bt_info *bt = (struct bt_info *)info->task;
		addr = (struct ia64_fpreg *)
			(bt->task + OFFSET(task_struct_thread) +
			OFFSET(thread_struct_fph) +
			((regnum - 32) * sizeof(struct ia64_fpreg)));
#else
		struct task_struct *t = info->task;

		if (write)
			ia64_sync_fph(t);
		else
			ia64_flush_fph(t);
		addr = t->thread.fph + (regnum - 32);
#endif
	}

	if (write)
		*addr = *val;
	else
		GET_STACK_DATA(addr, val, sizeof(struct ia64_fpreg));
	return 0;
}
#endif

#ifdef UNWIND_V2
int
unw_access_fr_v2 (struct unw_frame_info *info, int regnum, struct ia64_fpreg *val, int write)
{
        struct ia64_fpreg *addr = 0;
        struct pt_regs *pt;
        struct bt_info *bt = (struct bt_info *)info->task;

        if ((unsigned) (regnum - 2) >= 126) {
		error(INFO, "unwind: trying to access non-existent f%u\n", 
			regnum);
                return -1;
        }

        if (regnum <= 5) {
                addr = *(&info->f2_loc + (regnum - 2));
                if (!addr)
                        addr = &info->sw->f2 + (regnum - 2);
        } else if (regnum <= 15) {
                if (regnum <= 11) {
                        pt = get_scratch_regs(info);
                        addr = &pt->f6  + (regnum - 6);
                }
                else
                        addr = &info->sw->f12 + (regnum - 12);
        } else if (regnum <= 31) {
                addr = info->fr_loc[regnum - 16];
                if (!addr)
                        addr = &info->sw->f16 + (regnum - 16);
        } else {
#ifdef REDHAT
                struct bt_info *bt = (struct bt_info *)info->task;
                addr = (struct ia64_fpreg *)
                        (bt->task + OFFSET(task_struct_thread) +
                        OFFSET(thread_struct_fph) +
                        ((regnum - 32) * sizeof(struct ia64_fpreg)));
#else
                struct task_struct *t = info->task;

                if (write)
                        ia64_sync_fph(t);
                else
                        ia64_flush_fph(t);
                addr = t->thread.fph + (regnum - 32);
#endif
        }

        if (write)
                *addr = *val;
        else
		GET_STACK_DATA(addr, val, sizeof(struct ia64_fpreg));

	return 0;
}
#endif

#ifdef UNWIND_V3
int
unw_access_fr_v3 (struct unw_frame_info *info, int regnum, struct ia64_fpreg *val, int write)
{
        struct ia64_fpreg *addr = 0;
        struct pt_regs *pt;
        struct bt_info *bt = (struct bt_info *)info->task;

        if ((unsigned) (regnum - 2) >= 126) {
		error(INFO, "unwind: trying to access non-existent f%u\n", 
			regnum);
                return -1;
        }

        if (regnum <= 5) {
                addr = *(&info->f2_loc + (regnum - 2));
                if (!addr)
                        addr = &info->sw->f2 + (regnum - 2);
        } else if (regnum <= 15) {
                if (regnum <= 11) {
                        pt = get_scratch_regs(info);
                        addr = &pt->f6  + (regnum - 6);
                }
                else
                        addr = &info->sw->f12 + (regnum - 12);
        } else if (regnum <= 31) {
                addr = info->fr_loc[regnum - 16];
                if (!addr)
                        addr = &info->sw->f16 + (regnum - 16);
        } else {
#ifdef REDHAT
                struct bt_info *bt = (struct bt_info *)info->task;
                addr = (struct ia64_fpreg *)
                        (bt->task + OFFSET(task_struct_thread) +
                        OFFSET(thread_struct_fph) +
                        ((regnum - 32) * sizeof(struct ia64_fpreg)));
#else
                struct task_struct *t = info->task;

                if (write)
                        ia64_sync_fph(t);
                else
                        ia64_flush_fph(t);
                addr = t->thread.fph + (regnum - 32);
#endif
        }

        if (write)
                *addr = *val;
        else
		GET_STACK_DATA(addr, val, sizeof(struct ia64_fpreg));

	return 0;
}
#endif

int
#ifdef UNWIND_V1
unw_access_ar_v1 (struct unw_frame_info *info, int regnum, unsigned long *val, int write)
#endif
#ifdef UNWIND_V2
unw_access_ar_v2 (struct unw_frame_info *info, int regnum, unsigned long *val, int write)
#endif
#ifdef UNWIND_V3
unw_access_ar_v3 (struct unw_frame_info *info, int regnum, unsigned long *val, int write)
#endif
{
	unsigned long *addr;
	struct pt_regs *pt;
        struct bt_info *bt = (struct bt_info *)info->task;

	if (info->flags & UNW_FLAG_INTERRUPT_FRAME)
		pt = (struct pt_regs *) info->psp - 1;
	else
		pt = (struct pt_regs *) info->sp - 1;

	switch (regnum) {
	      case UNW_AR_BSP:
		addr = info->bsp_loc;
		if (!addr)
			addr = &info->sw->ar_bspstore;
		break;

	      case UNW_AR_BSPSTORE:
		addr = info->bspstore_loc;
		if (!addr)
			addr = &info->sw->ar_bspstore;
		break;

	      case UNW_AR_PFS:
		addr = info->pfs_loc;
		if (!addr)
			addr = &info->sw->ar_pfs;
		break;

	      case UNW_AR_RNAT:
		addr = info->rnat_loc;
		if (!addr)
			addr = &info->sw->ar_rnat;
		break;

	      case UNW_AR_UNAT:
		addr = info->unat_loc;
		if (!addr)
			addr = &info->sw->ar_unat;
		break;

	      case UNW_AR_LC:
		addr = info->lc_loc;
		if (!addr)
			addr = &info->sw->ar_lc;
		break;

	      case UNW_AR_EC:
		if (!info->cfm_loc)
			return -1;
		if (write)
			*info->cfm_loc =
				(*info->cfm_loc & ~(0x3fUL << 52)) | ((*val & 0x3f) << 52);
		else
			*val = (IA64_GET_STACK_ULONG(info->cfm_loc) >> 52) & 0x3f;
		return 0;

	      case UNW_AR_FPSR:
		addr = info->fpsr_loc;
		if (!addr)
			addr = &info->sw->ar_fpsr;
		break;

	      case UNW_AR_RSC:
		if (machdep->flags & UNW_PTREGS)
                	pt = get_scratch_regs(info);
		addr = &pt->ar_rsc;
		break;

	      case UNW_AR_CCV:
		if (machdep->flags & UNW_PTREGS)
                	pt = get_scratch_regs(info);
		addr = &pt->ar_ccv;
		break;

#if defined(UNWIND_V3)
              case UNW_AR_CSD:
		if (machdep->flags & UNW_PTREGS)
                	pt = get_scratch_regs(info);
                addr = &pt->ar_csd;
                break;

              case UNW_AR_SSD:
		if (machdep->flags & UNW_PTREGS)
                	pt = get_scratch_regs(info);
                addr = &pt->ar_ssd;
                break;
#endif

	      default:
		error(INFO, "unwind: trying to access non-existent ar%u\n", 
			regnum);
		return -1;
	}

	if (write)
		*addr = *val;
	else
		*val = IA64_GET_STACK_ULONG(addr);
	return 0;
}

int
#ifdef UNWIND_V1
unw_access_pr_v1 (struct unw_frame_info *info, unsigned long *val, int write)
#endif
#ifdef UNWIND_V2
unw_access_pr_v2 (struct unw_frame_info *info, unsigned long *val, int write)
#endif
#ifdef UNWIND_V3
unw_access_pr_v3 (struct unw_frame_info *info, unsigned long *val, int write)
#endif
{
	unsigned long *addr;
        struct bt_info *bt = (struct bt_info *)info->task;

	addr = info->pr_loc;
	if (!addr)
		addr = &info->sw->pr;

	if (write)
		*addr = *val;
	else
		*val = IA64_GET_STACK_ULONG(addr);
	return 0;
}


/* Routines to manipulate the state stack.  */

static inline void
push (struct unw_state_record *sr)
{
	struct unw_reg_state *rs;

	rs = alloc_reg_state();
	if (!rs) {
		error(INFO, "unwind: cannot stack reg state!\n");
		return;
	}
	memcpy(rs, &sr->curr, sizeof(*rs));
	sr->curr.next = rs;
}

static void
pop (struct unw_state_record *sr)
{
	struct unw_reg_state *rs = sr->curr.next;

	if (!rs) {
		error(INFO, "unwind: stack underflow!\n");
		return;
	}
	memcpy(&sr->curr, rs, sizeof(*rs));
	free_reg_state(rs);
}

/* Make a copy of the state stack.  Non-recursive to avoid stack overflows.  */
static struct unw_reg_state *
dup_state_stack (struct unw_reg_state *rs)
{
	struct unw_reg_state *copy, *prev = NULL, *first = NULL;

	while (rs) {
		copy = alloc_reg_state();
		if (!copy) {
			error(INFO, "unwind.dup_state_stack: out of memory\n");
			return NULL;
		}
		memcpy(copy, rs, sizeof(*copy));
		if (first)
			prev->next = copy;
		else
			first = copy;
		rs = rs->next;
		prev = copy;
	}
	return first;
}

/* Free all stacked register states (but not RS itself).  */
static void
free_state_stack (struct unw_reg_state *rs)
{
	struct unw_reg_state *p, *next;

	for (p = rs->next; p != NULL; p = next) {
		next = p->next;
		free_reg_state(p);
	}
	rs->next = NULL;
}

/* Routines to manipulate the state stack.  */

static enum unw_register_index __attribute__((const))
decode_abreg (unsigned char abreg, int memory)
{
	switch (abreg) {
	      case 0x04 ... 0x07: return UNW_REG_R4 + (abreg - 0x04);
	      case 0x22 ... 0x25: return UNW_REG_F2 + (abreg - 0x22);
	      case 0x30 ... 0x3f: return UNW_REG_F16 + (abreg - 0x30);
	      case 0x41 ... 0x45: return UNW_REG_B1 + (abreg - 0x41);
	      case 0x60: return UNW_REG_PR;
	      case 0x61: return UNW_REG_PSP;
	      case 0x62: return memory ? UNW_REG_PRI_UNAT_MEM : UNW_REG_PRI_UNAT_GR;
	      case 0x63: return UNW_REG_RP;
	      case 0x64: return UNW_REG_BSP;
	      case 0x65: return UNW_REG_BSPSTORE;
	      case 0x66: return UNW_REG_RNAT;
	      case 0x67: return UNW_REG_UNAT;
	      case 0x68: return UNW_REG_FPSR;
	      case 0x69: return UNW_REG_PFS;
	      case 0x6a: return UNW_REG_LC;
	      default:
		break;
	}
	error(INFO, "unwind: bad abreg=0x%x\n", abreg);
	return UNW_REG_LC;
}

static void
set_reg (struct unw_reg_info *reg, enum unw_where where, int when, unsigned long val)
{
	reg->val = val;
	reg->where = where;
	if (reg->when == UNW_WHEN_NEVER)
		reg->when = when;
}

static void
alloc_spill_area (unsigned long *offp, unsigned long regsize,
		  struct unw_reg_info *lo, struct unw_reg_info *hi)
{
	struct unw_reg_info *reg;

	for (reg = hi; reg >= lo; --reg) {
		if (reg->where == UNW_WHERE_SPILL_HOME) {
			reg->where = UNW_WHERE_PSPREL;
			*offp -= regsize;
			reg->val = *offp;
#ifndef KERNEL_FIX
			reg->val = 0x10 - *offp;
			*offp += regsize;
#endif
		}
	}
}

static inline void
spill_next_when (struct unw_reg_info **regp, struct unw_reg_info *lim, unw_word t)
{
	struct unw_reg_info *reg;

	for (reg = *regp; reg <= lim; ++reg) {
		if (reg->where == UNW_WHERE_SPILL_HOME) {
			reg->when = t;
			*regp = reg + 1;
			return;
		}
	}
	error(INFO, "unwind: excess spill!\n");
}

static inline void
finish_prologue (struct unw_state_record *sr)
{
	struct unw_reg_info *reg;
	unsigned long off;
	int i;

	/*
	 * First, resolve implicit register save locations (see Section "11.4.2.3 Rules
	 * for Using Unwind Descriptors", rule 3):
	 */
	for (i = 0; i < (int) sizeof(unw.save_order)/sizeof(unw.save_order[0]); ++i) {
		reg = sr->curr.reg + unw.save_order[i];
		if (reg->where == UNW_WHERE_GR_SAVE) {
			reg->where = UNW_WHERE_GR;
			reg->val = sr->gr_save_loc++;
		}
	}

	/*
	 * Next, compute when the fp, general, and branch registers get
	 * saved.  This must come before alloc_spill_area() because
	 * we need to know which registers are spilled to their home
	 * locations.
	 */
	if (sr->imask) {
		unsigned char kind, mask = 0, *cp = sr->imask;
		unsigned long t;
		static const unsigned char limit[3] = {
			UNW_REG_F31, UNW_REG_R7, UNW_REG_B5
		};
		struct unw_reg_info *(regs[3]);

		regs[0] = sr->curr.reg + UNW_REG_F2;
		regs[1] = sr->curr.reg + UNW_REG_R4;
		regs[2] = sr->curr.reg + UNW_REG_B1;

		for (t = 0; t < sr->region_len; ++t) {
			if ((t & 3) == 0)
				mask = *cp++;
			kind = (mask >> 2*(3-(t & 3))) & 3;
			if (kind > 0)
				spill_next_when(&regs[kind - 1], sr->curr.reg + limit[kind - 1],
						sr->region_start + t);
		}
	}
	/*
	 * Next, lay out the memory stack spill area:
	 */
	if (sr->any_spills) {
		off = sr->spill_offset;
		alloc_spill_area(&off, 16, sr->curr.reg + UNW_REG_F2, sr->curr.reg + UNW_REG_F31);
		alloc_spill_area(&off,  8, sr->curr.reg + UNW_REG_B1, sr->curr.reg + UNW_REG_B5);
		alloc_spill_area(&off,  8, sr->curr.reg + UNW_REG_R4, sr->curr.reg + UNW_REG_R7);
	}
}

/*
 * Region header descriptors.
 */

static void
desc_prologue (int body, unw_word rlen, unsigned char mask, unsigned char grsave,
	       struct unw_state_record *sr)
{
	int i;

	if (!(sr->in_body || sr->first_region))
		finish_prologue(sr);
	sr->first_region = 0;

	/* check if we're done: */
	if (sr->when_target < sr->region_start + sr->region_len) {
		sr->done = 1;
		return;
	}

	for (i = 0; i < sr->epilogue_count; ++i)
		pop(sr);
	sr->epilogue_count = 0;
	sr->epilogue_start = UNW_WHEN_NEVER;

	if (!body)
		push(sr);

	sr->region_start += sr->region_len;
	sr->region_len = rlen;
	sr->in_body = body;

	if (!body) {
		for (i = 0; i < 4; ++i) {
			if (mask & 0x8)
				set_reg(sr->curr.reg + unw.save_order[i], UNW_WHERE_GR,
					sr->region_start + sr->region_len - 1, grsave++);
			mask <<= 1;
		}
		sr->gr_save_loc = grsave;
		sr->any_spills = 0;
		sr->imask = 0;
		sr->spill_offset = 0x10;	/* default to psp+16 */
	}
}

/*
 * Prologue descriptors.
 */

static inline void
desc_abi (unsigned char abi, unsigned char context, struct unw_state_record *sr)
{
	console("desc_abi: abi: 0x%x context: %c\n", abi, context); 
	if (((abi == 0) || (abi == 3)) && context == 'i') 
		sr->flags |= UNW_FLAG_INTERRUPT_FRAME;
	else
		error(INFO, "unwind: ignoring unwabi(abi=0x%x,context=0x%x)\n", abi, context);
}

static inline void
desc_br_gr (unsigned char brmask, unsigned char gr, struct unw_state_record *sr)
{
	int i;

	for (i = 0; i < 5; ++i) {
		if (brmask & 1)
			set_reg(sr->curr.reg + UNW_REG_B1 + i, UNW_WHERE_GR,
				sr->region_start + sr->region_len - 1, gr++);
		brmask >>= 1;
	}
}

static inline void
desc_br_mem (unsigned char brmask, struct unw_state_record *sr)
{
	int i;

	for (i = 0; i < 5; ++i) {
		if (brmask & 1) {
			set_reg(sr->curr.reg + UNW_REG_B1 + i, UNW_WHERE_SPILL_HOME,
				sr->region_start + sr->region_len - 1, 0);
			sr->any_spills = 1;
		}
		brmask >>= 1;
	}
}

static inline void
desc_frgr_mem (unsigned char grmask, unw_word frmask, struct unw_state_record *sr)
{
	int i;

	for (i = 0; i < 4; ++i) {
		if ((grmask & 1) != 0) {
			set_reg(sr->curr.reg + UNW_REG_R4 + i, UNW_WHERE_SPILL_HOME,
				sr->region_start + sr->region_len - 1, 0);
			sr->any_spills = 1;
		}
		grmask >>= 1;
	}
        for (i = 0; i < 20; ++i) {
                if ((frmask & 1) != 0) {
                        int base = (i < 4) ? UNW_REG_F2 : UNW_REG_F16 - 4;
                        set_reg(sr->curr.reg + base + i, UNW_WHERE_SPILL_HOME,
                                sr->region_start + sr->region_len - 1, 0);
                        sr->any_spills = 1;
                }
                frmask >>= 1;
        }
#ifndef KERNEL_FIX
	for (i = 0; i < 20; ++i) {
		if ((frmask & 1) != 0) {
			set_reg(sr->curr.reg + UNW_REG_F2 + i, UNW_WHERE_SPILL_HOME,
				sr->region_start + sr->region_len - 1, 0);
			sr->any_spills = 1;
		}
		frmask >>= 1;
	}
#endif
}

static inline void
desc_fr_mem (unsigned char frmask, struct unw_state_record *sr)
{
	int i;

	for (i = 0; i < 4; ++i) {
		if ((frmask & 1) != 0) {
			set_reg(sr->curr.reg + UNW_REG_F2 + i, UNW_WHERE_SPILL_HOME,
				sr->region_start + sr->region_len - 1, 0);
			sr->any_spills = 1;
		}
		frmask >>= 1;
	}
}

static inline void
desc_gr_gr (unsigned char grmask, unsigned char gr, struct unw_state_record *sr)
{
	int i;

	for (i = 0; i < 4; ++i) {
		if ((grmask & 1) != 0)
			set_reg(sr->curr.reg + UNW_REG_R4 + i, UNW_WHERE_GR,
				sr->region_start + sr->region_len - 1, gr++);
		grmask >>= 1;
	}
}

static inline void
desc_gr_mem (unsigned char grmask, struct unw_state_record *sr)
{
	int i;

	for (i = 0; i < 4; ++i) {
		if ((grmask & 1) != 0) {
			set_reg(sr->curr.reg + UNW_REG_R4 + i, UNW_WHERE_SPILL_HOME,
				sr->region_start + sr->region_len - 1, 0);
			sr->any_spills = 1;
		}
		grmask >>= 1;
	}
}

static inline void
desc_mem_stack_f (unw_word t, unw_word size, struct unw_state_record *sr)
{
	set_reg(sr->curr.reg + UNW_REG_PSP, UNW_WHERE_NONE,
		sr->region_start + MIN((int)t, sr->region_len - 1), 16*size);
}

static inline void
desc_mem_stack_v (unw_word t, struct unw_state_record *sr)
{
	sr->curr.reg[UNW_REG_PSP].when = sr->region_start + MIN((int)t, sr->region_len - 1);
}

static inline void
desc_reg_gr (unsigned char reg, unsigned char dst, struct unw_state_record *sr)
{
	set_reg(sr->curr.reg + reg, UNW_WHERE_GR, sr->region_start + sr->region_len - 1, dst);
}

static inline void
desc_reg_psprel (unsigned char reg, unw_word pspoff, struct unw_state_record *sr)
{
	set_reg(sr->curr.reg + reg, UNW_WHERE_PSPREL, sr->region_start + sr->region_len - 1,
		0x10 - 4*pspoff);
}

static inline void
desc_reg_sprel (unsigned char reg, unw_word spoff, struct unw_state_record *sr)
{
	set_reg(sr->curr.reg + reg, UNW_WHERE_SPREL, sr->region_start + sr->region_len - 1,
		4*spoff);
}

static inline void
desc_rp_br (unsigned char dst, struct unw_state_record *sr)
{
	sr->return_link_reg = dst;
}

static inline void
desc_reg_when (unsigned char regnum, unw_word t, struct unw_state_record *sr)
{
	struct unw_reg_info *reg = sr->curr.reg + regnum;

	if (reg->where == UNW_WHERE_NONE)
		reg->where = UNW_WHERE_GR_SAVE;
	reg->when = sr->region_start + MIN((int)t, sr->region_len - 1);
}

static inline void
desc_spill_base (unw_word pspoff, struct unw_state_record *sr)
{
	sr->spill_offset = 0x10 - 4*pspoff;
}

static inline unsigned char *
desc_spill_mask (unsigned char *imaskp, struct unw_state_record *sr)
{
	sr->imask = imaskp;
	return imaskp + (2*sr->region_len + 7)/8;
}

/*
 * Body descriptors.
 */
static inline void
desc_epilogue (unw_word t, unw_word ecount, struct unw_state_record *sr)
{
	sr->epilogue_start = sr->region_start + sr->region_len - 1 - t;
	sr->epilogue_count = ecount + 1;
}

static inline void
desc_copy_state (unw_word label, struct unw_state_record *sr)
{
	struct unw_labeled_state *ls;

	for (ls = sr->labeled_states; ls; ls = ls->next) {
		if (ls->label == label) {
			free_state_stack(&sr->curr);
			memcpy(&sr->curr, &ls->saved_state, sizeof(sr->curr));
			sr->curr.next = dup_state_stack(ls->saved_state.next);
			return;
		}
	}
	error(INFO, "unwind: failed to find state labeled 0x%lx\n", label);
}

static inline void
desc_label_state (unw_word label, struct unw_state_record *sr)
{
	struct unw_labeled_state *ls;

	ls = alloc_labeled_state();
	if (!ls) {
		error(INFO, "unwind.desc_label_state(): out of memory\n");
		return;
	}
	ls->label = label;
	memcpy(&ls->saved_state, &sr->curr, sizeof(ls->saved_state));
	ls->saved_state.next = dup_state_stack(sr->curr.next);

	/* insert into list of labeled states: */
	ls->next = sr->labeled_states;
	sr->labeled_states = ls;
}

/*
 * General descriptors.
 */

static inline int
desc_is_active (unsigned char qp, unw_word t, struct unw_state_record *sr)
{
	if (sr->when_target <= sr->region_start + MIN((int)t, sr->region_len - 1))
		return 0;
	if (qp > 0) {
		if ((sr->pr_val & (1UL << qp)) == 0)
			return 0;
		sr->pr_mask |= (1UL << qp);
	}
	return 1;
}

static inline void
desc_restore_p (unsigned char qp, unw_word t, unsigned char abreg, struct unw_state_record *sr)
{
	struct unw_reg_info *r;

	if (!desc_is_active(qp, t, sr))
		return;

	r = sr->curr.reg + decode_abreg(abreg, 0);
	r->where = UNW_WHERE_NONE;
	r->when = UNW_WHEN_NEVER;
	r->val = 0;
}

static inline void
desc_spill_reg_p (unsigned char qp, unw_word t, unsigned char abreg, unsigned char x,
		     unsigned char ytreg, struct unw_state_record *sr)
{
	enum unw_where where = UNW_WHERE_GR;
	struct unw_reg_info *r;

	if (!desc_is_active(qp, t, sr))
		return;

	if (x)
		where = UNW_WHERE_BR;
	else if (ytreg & 0x80)
		where = UNW_WHERE_FR;

	r = sr->curr.reg + decode_abreg(abreg, 0);
	r->where = where;
	r->when = sr->region_start + MIN((int)t, sr->region_len - 1);
	r->val = (ytreg & 0x7f);
}

static inline void
desc_spill_psprel_p (unsigned char qp, unw_word t, unsigned char abreg, unw_word pspoff,
		     struct unw_state_record *sr)
{
	struct unw_reg_info *r;

	if (!desc_is_active(qp, t, sr))
		return;

	r = sr->curr.reg + decode_abreg(abreg, 1);
	r->where = UNW_WHERE_PSPREL;
	r->when = sr->region_start + MIN((int)t, sr->region_len - 1);
	r->val = 0x10 - 4*pspoff;
}

static inline void
desc_spill_sprel_p (unsigned char qp, unw_word t, unsigned char abreg, unw_word spoff,
		       struct unw_state_record *sr)
{
	struct unw_reg_info *r;

	if (!desc_is_active(qp, t, sr))
		return;

	r = sr->curr.reg + decode_abreg(abreg, 1);
	r->where = UNW_WHERE_SPREL;
	r->when = sr->region_start + MIN((int)t, sr->region_len - 1);
	r->val = 4*spoff;
}

#define UNW_DEC_BAD_CODE(code)			error(INFO, "unwind: unknown code 0x%02x\n", code);

/*
 * region headers:
 */
#define UNW_DEC_PROLOGUE_GR(fmt,r,m,gr,arg)	desc_prologue(0,r,m,gr,arg)
#define UNW_DEC_PROLOGUE(fmt,b,r,arg)		desc_prologue(b,r,0,32,arg)
/*
 * prologue descriptors:
 */
#define UNW_DEC_ABI(fmt,a,c,arg)		desc_abi(a,c,arg)
#define UNW_DEC_BR_GR(fmt,b,g,arg)		desc_br_gr(b,g,arg)
#define UNW_DEC_BR_MEM(fmt,b,arg)		desc_br_mem(b,arg)
#define UNW_DEC_FRGR_MEM(fmt,g,f,arg)		desc_frgr_mem(g,f,arg)
#define UNW_DEC_FR_MEM(fmt,f,arg)		desc_fr_mem(f,arg)
#define UNW_DEC_GR_GR(fmt,m,g,arg)		desc_gr_gr(m,g,arg)
#define UNW_DEC_GR_MEM(fmt,m,arg)		desc_gr_mem(m,arg)
#define UNW_DEC_MEM_STACK_F(fmt,t,s,arg)	desc_mem_stack_f(t,s,arg)
#define UNW_DEC_MEM_STACK_V(fmt,t,arg)		desc_mem_stack_v(t,arg)
#define UNW_DEC_REG_GR(fmt,r,d,arg)		desc_reg_gr(r,d,arg)
#define UNW_DEC_REG_PSPREL(fmt,r,o,arg)		desc_reg_psprel(r,o,arg)
#define UNW_DEC_REG_SPREL(fmt,r,o,arg)		desc_reg_sprel(r,o,arg)
#define UNW_DEC_REG_WHEN(fmt,r,t,arg)		desc_reg_when(r,t,arg)
#define UNW_DEC_PRIUNAT_WHEN_GR(fmt,t,arg)	desc_reg_when(UNW_REG_PRI_UNAT_GR,t,arg)
#define UNW_DEC_PRIUNAT_WHEN_MEM(fmt,t,arg)	desc_reg_when(UNW_REG_PRI_UNAT_MEM,t,arg)
#define UNW_DEC_PRIUNAT_GR(fmt,r,arg)		desc_reg_gr(UNW_REG_PRI_UNAT_GR,r,arg)
#define UNW_DEC_PRIUNAT_PSPREL(fmt,o,arg)	desc_reg_psprel(UNW_REG_PRI_UNAT_MEM,o,arg)
#define UNW_DEC_PRIUNAT_SPREL(fmt,o,arg)	desc_reg_sprel(UNW_REG_PRI_UNAT_MEM,o,arg)
#define UNW_DEC_RP_BR(fmt,d,arg)		desc_rp_br(d,arg)
#define UNW_DEC_SPILL_BASE(fmt,o,arg)		desc_spill_base(o,arg)
#define UNW_DEC_SPILL_MASK(fmt,m,arg)		(m = desc_spill_mask(m,arg))
/*
 * body descriptors:
 */
#define UNW_DEC_EPILOGUE(fmt,t,c,arg)		desc_epilogue(t,c,arg)
#define UNW_DEC_COPY_STATE(fmt,l,arg)		desc_copy_state(l,arg)
#define UNW_DEC_LABEL_STATE(fmt,l,arg)		desc_label_state(l,arg)
/*
 * general unwind descriptors:
 */
#define UNW_DEC_SPILL_REG_P(f,p,t,a,x,y,arg)	desc_spill_reg_p(p,t,a,x,y,arg)
#define UNW_DEC_SPILL_REG(f,t,a,x,y,arg)	desc_spill_reg_p(0,t,a,x,y,arg)
#define UNW_DEC_SPILL_PSPREL_P(f,p,t,a,o,arg)	desc_spill_psprel_p(p,t,a,o,arg)
#define UNW_DEC_SPILL_PSPREL(f,t,a,o,arg)	desc_spill_psprel_p(0,t,a,o,arg)
#define UNW_DEC_SPILL_SPREL_P(f,p,t,a,o,arg)	desc_spill_sprel_p(p,t,a,o,arg)
#define UNW_DEC_SPILL_SPREL(f,t,a,o,arg)	desc_spill_sprel_p(0,t,a,o,arg)
#define UNW_DEC_RESTORE_P(f,p,t,a,arg)		desc_restore_p(p,t,a,arg)
#define UNW_DEC_RESTORE(f,t,a,arg)		desc_restore_p(0,t,a,arg)

#include "unwind_decoder.c"

/*
 *  Run a sanity check on the common structure usage, and do an initial
 *  read of the unw table.  If anything fails, the UNW_OUT_OF_SYNC flag 
 *  will be set and backtraces not allowed.
 */
void
#ifdef UNWIND_V1
unwind_init_v1(void)
#endif
#ifdef UNWIND_V2
unwind_init_v2(void)
#endif
#ifdef UNWIND_V3
unwind_init_v3(void)
#endif
{
	int len;
	struct gnu_request request, *req;

	req = &request;

	if (LKCD_KERNTYPES()) {
		if ((len = STRUCT_SIZE("unw")) == 0) {
			error(WARNING,
			"cannot determine unw.tables offset; no struct unw\n");
			machdep->flags |= UNW_OUT_OF_SYNC;
			return;
		}
		machdep->machspec->unw_tables_offset =
			MEMBER_OFFSET("unw", "tables");
		if (MEMBER_EXISTS("unw", "r0"))
			machdep->flags |= UNW_R0;
		/*
		 * no verification of save_order, sw_off, preg_index as
		 * we're purely depending on the structure definition.
		 */
		if (MEMBER_EXISTS("unw", "pt_regs_offsets")) {
			machdep->machspec->unw_pt_regs_offsets =
				MEMBER_OFFSET("unw", "pt_regs_offsets") -
				machdep->machspec->unw_tables_offset;
			machdep->machspec->unw_kernel_table_offset =
				MEMBER_OFFSET("unw", "kernel_table") -
				machdep->machspec->unw_tables_offset;
			machdep->flags |= UNW_PTREGS;
		}
		if (!load_unw_table(CLEAR_SCRIPT_CACHE)) {
			error(WARNING,
				"unwind_init: cannot read kernel unw table\n");
			machdep->flags |= UNW_OUT_OF_SYNC;
		}
		machdep->machspec->unw = (void *)&unw;
		/* fall to common structure size verifications */
		goto verify;
	}

        if (get_symbol_type("unw", "tables", req) == TYPE_CODE_UNDEF) {
		/*
		 *  KLUDGE ALERT:
		 *  If unw.tables cannot be ascertained by gdb, try unw.save_order,
		 *  given that it is the field just after unw.tables.
		 */
		if (get_symbol_type("unw", "save_order", req) == TYPE_CODE_UNDEF) {
			error(WARNING, "cannot determine unw.tables offset\n");
			machdep->flags |= UNW_OUT_OF_SYNC;
		} else
	        	req->member_offset -= BITS_PER_BYTE * sizeof(void *);

		if (CRASHDEBUG(1))
			error(WARNING, "using unw.save_order to determine unw.tables\n");
	}

	if (!(machdep->flags & UNW_OUT_OF_SYNC)) {
		machdep->machspec->unw_tables_offset =
			 req->member_offset/BITS_PER_BYTE;

		if (get_symbol_type("unw", "r0", req) != TYPE_CODE_UNDEF) 
			machdep->flags |= UNW_R0;

		verify_unw_member("save_order", 
			struct_offset(struct unw, save_order));
		verify_unw_member("sw_off", struct_offset(struct unw, sw_off));
		verify_unw_member("preg_index", 
			struct_offset(struct unw, preg_index));

        	if (get_symbol_type("unw", "pt_regs_offsets", req) 
			== TYPE_CODE_ARRAY) {
			machdep->machspec->unw_pt_regs_offsets =
				req->member_offset/BITS_PER_BYTE -
				machdep->machspec->unw_tables_offset;
		    	get_symbol_type("unw", "kernel_table", req);
			machdep->machspec->unw_kernel_table_offset =
				req->member_offset/BITS_PER_BYTE -
				machdep->machspec->unw_tables_offset;
			machdep->flags |= UNW_PTREGS;
		} else
			verify_unw_member("kernel_table", 
				struct_offset(struct unw, kernel_table));

		if (!load_unw_table(CLEAR_SCRIPT_CACHE)) {
        		error(WARNING, "unwind_init: cannot read kernel unw table\n");
                	machdep->flags |= UNW_OUT_OF_SYNC;
		}

		machdep->machspec->unw = (void *)&unw;
	}
verify:	
	verify_common_struct("unw_frame_info", sizeof(struct unw_frame_info));
	verify_common_struct("unw_table", sizeof(struct unw_table));
	verify_common_struct("unw_table_entry", sizeof(struct unw_table_entry));
	verify_common_struct("unw_state_record", 
		sizeof(struct unw_state_record));
	verify_common_struct("unw_labeled_state", 
		sizeof(struct unw_labeled_state));
	verify_common_struct("unw_reg_info", sizeof(struct unw_reg_info));
	verify_common_struct("unw_insn", sizeof(struct unw_insn));
}

/*
 *  Check whether the unw fields used in this port exist at the same
 *  offset as the local version of the structure.
 */
static void
verify_unw_member(char *member, long loffs) 
{
	struct gnu_request request, *req;
	long koffs;

	req = &request;

        if (get_symbol_type("unw", member, req) == TYPE_CODE_UNDEF) {
                error(WARNING, "cannot determine unw.%s offset\n", member);
                machdep->flags |= UNW_OUT_OF_SYNC;
        } else {
                koffs = (req->member_offset/BITS_PER_BYTE) -
                	machdep->machspec->unw_tables_offset;
		if (machdep->flags & UNW_R0)
			koffs -= sizeof(unsigned long);
                if (koffs != loffs) {
                        error(WARNING, 
			    "unw.%s offset differs: %ld (local: %d)\n",
				member, koffs, loffs);
                        machdep->flags |= UNW_OUT_OF_SYNC;
                } else if (CRASHDEBUG(3)) 
                        error(INFO, 
			    "unw.%s offset OK: %ld (local: %d)\n",
				member, koffs, loffs);
        }
}

/*
 *  Check whether the sizes of common local/kernel structures match.
 */
static void
verify_common_struct(char *structname, long loclen)
{
	long len;

        len = STRUCT_SIZE(structname);
        if (len < 0) {
                error(WARNING, "cannot determine size of %s\n", structname);
                machdep->flags |= UNW_OUT_OF_SYNC;
        } else if (len != loclen) {
                error(WARNING, "%s size differs: %ld (local: %d)\n",
			structname, len, loclen);
                machdep->flags |= UNW_OUT_OF_SYNC;
        }
}

/*
 *  Do a one-time read of the useful part of the kernel's unw table into the 
 *  truncated local version, followed by a one-time read of the kernel's 
 *  unw_table_entry array into a permanently allocated location.  The
 *  script cache is cleared only if requested.  
 */
static int
load_unw_table(int clear_cache)
{
	int i;
	size_t len;
	struct machine_specific *ms;
	struct unw_table_entry *kernel_unw_table_entry_array;

	if (machdep->flags & UNW_OUT_OF_SYNC) 
		return FALSE;

	ms = machdep->machspec;

	if (clear_cache) {
		if (!ms->script_cache) {
			len = sizeof(struct unw_script) * UNW_CACHE_SIZE;
			if ((ms->script_cache = 
	    		    (struct unw_script *)malloc(len)) == NULL) {
				error(WARNING, 
					"cannot malloc unw_script cache\n");
				return FALSE;
			}
		}
		
                for (i = 0; i < UNW_CACHE_SIZE; i++)
                        BZERO((void *)&ms->script_cache[i], 
				sizeof(struct unw_script));
                ms->script_index = 0;
	}

	if (machdep->flags & UNW_READ)
		return TRUE;

	if (machdep->flags & UNW_R0) {
		struct unw *unw_temp, *up;

		unw_temp = (struct unw *)GETBUF(sizeof(struct unw) * 2);
		up = unw_temp;

		if (!readmem(symbol_value("unw")+ms->unw_tables_offset, 
	    	    KVADDR, up, 
		    sizeof(struct unw) + sizeof(struct unw_table *), 
		    "unw", RETURN_ON_ERROR|QUIET)) 
			return FALSE;

		unw.tables = up->tables;

		/*
		 *  Bump the "up" pointer by 8 to account for the 
	 	 *  "r0" member that comes after the "tables" member.
		 */
		up = (struct unw *)(((unsigned long)unw_temp) + 
			sizeof(struct unw_table *));

		for (i = 0; i < 8; i++)
			unw.save_order[i] = up->save_order[i];
		for (i = 0; i < (sizeof(struct unw_frame_info) / 8); i++)
			unw.sw_off[i] = up->sw_off[i];
		unw.lru_head = up->lru_head;	
		unw.lru_tail = up->lru_tail;	
		for (i = 0; i < UNW_NUM_REGS; i++)
			unw.preg_index[i] = up->preg_index[i];
		BCOPY(&up->kernel_table, &unw.kernel_table, 
			sizeof(struct unw_table));

		FREEBUF(unw_temp);
	} else {
		if (!readmem(symbol_value("unw")+ms->unw_tables_offset, 
	    	    KVADDR, &unw, sizeof(struct unw), "unw", RETURN_ON_ERROR|QUIET)) 
			return FALSE;
	}

	if (machdep->flags & UNW_PTREGS) {
		if (!readmem(symbol_value("unw")+ms->unw_kernel_table_offset+
			machdep->machspec->unw_tables_offset, 
	    		KVADDR, &unw.kernel_table, sizeof(struct unw_table), 
			"unw.kernel_table", RETURN_ON_ERROR|QUIET)) 
			return FALSE;
		if (!readmem(symbol_value("unw")+ms->unw_pt_regs_offsets+
			machdep->machspec->unw_tables_offset, 
	    		KVADDR, &pt_regs_offsets, sizeof(pt_regs_offsets), 
			"unw.pt_regs_offsets", RETURN_ON_ERROR|QUIET)) 
			return FALSE;
	}

	len = unw.kernel_table.length * sizeof(struct unw_table_entry);

	if ((kernel_unw_table_entry_array = 
	    (struct unw_table_entry *)malloc(len)) == NULL) {
		error(WARNING, 
		    "cannot malloc kernel unw.kernel_table array (len: %d)\n",
			len);
		return FALSE;
	}

	if (!readmem((ulong)unw.kernel_table.array, 
	    KVADDR, kernel_unw_table_entry_array, len, 
	    "kernel unw_table_entry array", RETURN_ON_ERROR|QUIET)) { 
		error(WARNING, "cannot read kernel unw.kernel_table array\n");
		return FALSE;
	}

	/*
	 *  Bait and switch for the kernel array only.
	 */
	unw.kernel_table.array = kernel_unw_table_entry_array;
	
	machdep->flags |= UNW_READ;
	return TRUE;
}

/*
 *  The main back trace loop.  If we get interrupted in the midst of an
 *  operation, unw_in_progress will left TRUE, and the next time we come
 *  here, the script_cache will be cleared.
 */
void
#ifdef UNWIND_V1
unwind_v1(struct bt_info *bt)
#endif
#ifdef UNWIND_V2
unwind_v2(struct bt_info *bt)
#endif
#ifdef UNWIND_V3
unwind_v3(struct bt_info *bt)
#endif
{
	struct unw_frame_info unw_frame_info, *info;
        unsigned long ip, sp, bsp;
        struct syment *sm;
	struct pt_regs *pt;
        int frame;
        char *name, *name_plus_offset;
	ulong offset;
	struct load_module *lm;
	static int unw_in_progress = FALSE;
	char buf[BUFSIZE];

	if (bt->debug)
		CRASHDEBUG_SUSPEND(bt->debug);

	if (!load_unw_table(unw_in_progress ? CLEAR_SCRIPT_CACHE : 0))
		error(FATAL, "unwind: cannot read kernel unw table\n");

	unw_in_progress = TRUE;

        info = &unw_frame_info;

        if (!unw_init_from_blocked_task(info, bt)) 
		goto unwind_return;

        frame = 0;

        do {
restart:
                unw_get_ip(info, &ip);
                unw_get_sp(info, &sp);
                unw_get_bsp(info, &bsp);

		if (XEN_HYPER_MODE()) {
			if (!IS_KVADDR(ip))
				break;
		} else {
                	if (ip < GATE_ADDR + PAGE_SIZE)
                       		break;
		}

		name_plus_offset = NULL;
                if ((sm = value_search(ip, &offset))) {
                        name = sm->name;
			if ((bt->flags & BT_SYMBOL_OFFSET) && offset)
				name_plus_offset = value_to_symstr(ip, buf, bt->radix);
                } else
                        name = "(unknown)";

                if (BT_REFERENCE_CHECK(bt)) {
                        switch (bt->ref->cmdflags &
                                (BT_REF_SYMBOL|BT_REF_HEXVAL))
                        {
                        case BT_REF_SYMBOL:
                                if (STREQ(name, bt->ref->str)) {
                                        bt->ref->cmdflags |= BT_REF_FOUND;
                                        goto unwind_return;
                                }
                                break;

                        case BT_REF_HEXVAL:
                                if (bt->ref->hexval == ip) {
                                        bt->ref->cmdflags |= BT_REF_FOUND;
                                        goto unwind_return;
                                }
                                break;
                        }
                } else {
                        fprintf(fp, "%s#%d [BSP:%lx] %s at %lx",
                                frame >= 10 ? "" : " ", frame,
                                bsp, name_plus_offset ? name_plus_offset : name, ip);
			if (module_symbol(ip, NULL, &lm, NULL, 0))
				fprintf(fp, " [%s]", lm->mod_name);
			fprintf(fp, "\n");

			if (bt->flags & BT_FULL)
                        	rse_function_params(bt, info, name);
                        if (bt->flags & BT_LINE_NUMBERS)
                                ia64_dump_line_number(ip);

		        if (info->flags & UNW_FLAG_INTERRUPT_FRAME) {
				pt = (struct pt_regs *)info->psp - 1;
                		ia64_exception_frame((ulong)pt, bt);
			} 
		}

		if (STREQ(name, "start_kernel") || 
		    STREQ(name, "start_secondary") ||
		    STREQ(name, "start_kernel_thread"))
                        break;

		/* 
		 * "init_handler_platform" indicates that this task was
		 * interrupted by INIT and its stack was switched. 
		 */
		if (STREQ(name, "init_handler_platform")) {
			unw_switch_from_osinit_v1(info, bt);
			frame++;
			goto restart;
		}

		/*
		 * In some cases, init_handler_platform is inlined into
		 * ia64_init_handler.  
		 */
		if (STREQ(name, "ia64_init_handler")) {
			if (symbol_exists("ia64_mca_modify_original_stack")) {
				/*
				 * 2.6.14 or later kernels no longer keep
				 * minstate info in pt_regs/switch_stack.
				 * unw_switch_from_osinit_v3() will try
				 * to find the interrupted task and restart
				 * backtrace itself.
				 */
				if (unw_switch_from_osinit_v3(info, bt, "INIT") == FALSE)
					break;
			} else {
				if (unw_switch_from_osinit_v2(info, bt) == FALSE)
					break;
				frame++;
				goto restart;
			}
		}

		if (STREQ(name, "ia64_mca_handler") &&
		    symbol_exists("ia64_mca_modify_original_stack"))
			if (unw_switch_from_osinit_v3(info, bt, "MCA") == FALSE)
				break;

                frame++;

        } while (unw_unwind(info) >= 0);

unwind_return:
	if (bt->flags & BT_UNWIND_ERROR) 
		load_unw_table(CLEAR_SCRIPT_CACHE);
	if (bt->debug)
		CRASHDEBUG_RESTORE();

	unw_in_progress = FALSE;
}

void
#ifdef UNWIND_V1
dump_unwind_stats_v1(void)
#endif
#ifdef UNWIND_V2
dump_unwind_stats_v2(void)
#endif
#ifdef UNWIND_V3
dump_unwind_stats_v3(void)
#endif
{
	int i;
	struct machine_specific *ms;
	char buf[BUFSIZE];

	if (machdep->flags & UNW_OUT_OF_SYNC) {
		fprintf(fp, "\n");
		return;
	}

        ms = machdep->machspec;

	fprintf(fp, " %2ld%% (%ld of %ld)\n",
	        ms->script_cache_fills ?
                (ms->script_cache_hits * 100)/ms->script_cache_fills : 0, 
		ms->script_cache_hits, ms->script_cache_fills);

	for (i = 0; i < UNW_CACHE_SIZE; i++) {
		if (ms->script_cache[i].ip)
			fprintf(fp, "              [%3d]: %lx %s\n", 
			    i, ms->script_cache[i].ip, 
			    value_to_symstr(ms->script_cache[i].ip, buf, 0));
	}
}

int
#ifdef UNWIND_V1
unwind_debug_v1(ulong arg)
#endif
#ifdef UNWIND_V2
unwind_debug_v2(ulong arg)
#endif
#ifdef UNWIND_V3
unwind_debug_v3(ulong arg)
#endif
{
	struct unw_table *table, *target;
	struct unw_table unw_table_buf;

	target = (struct unw_table *)arg;
        table = unw.tables;

        do {
                if (!readmem((ulong)table, KVADDR, &unw_table_buf,
                    sizeof(struct unw_table), "module unw_table",
                    RETURN_ON_ERROR))
                        break;

		switch (arg)
		{
		case 3:
			dump_unwind_table(table);
			break;
		default:
			if (table == target)
				dump_unwind_table(table);
			break;
		}

                table = &unw_table_buf;
		table = table->next;
		
        } while (table);

	return TRUE;
}

static void
dump_unwind_table(struct unw_table *table)
{
	struct unw_table unw_table_buf, *tbl;

	readmem((ulong)table, KVADDR, &unw_table_buf,
        	sizeof(struct unw_table), "module unw_table",
                RETURN_ON_ERROR);
	tbl = &unw_table_buf;
	dump_struct("unw_table", (ulong)table, RADIX(16));
}

static unsigned long 
get_init_stack_ulong(unsigned long addr) 
{
        unsigned long tmp;

        readmem(addr, KVADDR, &tmp, sizeof(unsigned long),
                "get_init_stack_ulong", FAULT_ON_ERROR);

        return tmp;
}

static int
unw_init_from_blocked_task(struct unw_frame_info *info, struct bt_info *bt)
{
	ulong sw;

	sw = SWITCH_STACK_ADDR(bt->task);
	if (XEN_HYPER_MODE()) {
		if (!INSTACK(sw, bt) && !ia64_in_mca_stack_hyper(sw, bt))
			return FALSE;
	} else {
		if (!INSTACK(sw, bt) && !ia64_in_init_stack(sw))
			return FALSE;
	}

        unw_init_frame_info(info, bt, sw);
	return TRUE;
}

/*
 * unw_init_from_interruption
 *   Initialize frame info from specified pt_regs/switch_stack.
 *
 *   Similar to unw_init_frame_info() except that:
 *     - do not use readmem to access stack
 *       (because stack may be modified by unw_init_from_saved_regs)
 *     - use ar.ifs and ar.iip instead of ar.pfs and b0, respectively
 *     - use sof(size-of-frame) of ar.ifs to caluculate bsp,
 *       instead of sol(size-of-local) of ar.pfs
 *       (because of cover instruction in kernel minstate save macro)
 */
static void
unw_init_from_interruption(struct unw_frame_info *info, struct bt_info *bt, ulong pt, ulong sw)
{
//	unsigned long rbslimit, rbstop, stklimit, stktop, sof, ar_pfs;
	unsigned long rbslimit, rbstop, stklimit, stktop, sof;
	ulong t;

	t = bt->task;

	memset(info, 0, sizeof(*info));

	rbslimit = (unsigned long) t + IA64_RBS_OFFSET;
	rbstop = IA64_GET_STACK_ULONG(sw + OFFSET(switch_stack_ar_bspstore));
	if (rbstop - (unsigned long) t >= IA64_STK_OFFSET)
		rbstop = rbslimit;

	stklimit = (unsigned long) t + IA64_STK_OFFSET;
	stktop   = IA64_GET_STACK_ULONG(pt + offsetof(struct pt_regs, r12));
	if (stktop <= rbstop)
		stktop = rbstop;

	info->regstk.limit = rbslimit;
	info->regstk.top   = rbstop;
	info->memstk.limit = stklimit;
	info->memstk.top   = stktop;
	info->task = (struct task_struct *)bt;
	info->sw  = (struct switch_stack *)sw;
	info->sp = info->psp = stktop;
	info->pr = IA64_GET_STACK_ULONG(sw + OFFSET(switch_stack_pr));

	info->cfm_loc = (unsigned long *) (pt + offsetof(struct pt_regs, cr_ifs));
	info->unat_loc = (unsigned long *) (pt + offsetof(struct pt_regs, ar_unat));
	info->pfs_loc = (unsigned long *) (pt + offsetof(struct pt_regs, ar_pfs));
	/* register stack is covered */
	sof = IA64_GET_STACK_ULONG(info->cfm_loc) & 0x7f;
	info->bsp = (unsigned long)
		ia64_rse_skip_regs((unsigned long *) info->regstk.top, -sof);
	/* interrupted ip is saved in iip */
	info->ip = IA64_GET_STACK_ULONG(pt + offsetof(struct pt_regs, cr_iip));
#if defined(UNWIND_V2) || defined(UNWIND_V3)
	info->pt = pt;
#endif

	find_save_locs(info);
}

/*
 * unw_switch_from_osinit
 *   switch back to interrupted context
 *
 *   assumption: init_handler_platform() has 3 arguments,
 *               2nd arg is pt_regs and 3rd arg is switch_stack.
 */
static int
unw_switch_from_osinit_v1(struct unw_frame_info *info, struct bt_info *bt)
{
	unsigned long pt, sw;
	char is_nat;

	/* pt_regs is the 2nd argument of init_handler_platform */
	if (unw_get_gr(info, 33, &pt, &is_nat)) {
		fprintf(fp, "gr 33 get error\n");
		return FALSE;
	}
	/* switch_stack is the 3rd argument of init_handler_platform */
	if (unw_get_gr(info, 34, &sw, &is_nat)) {
		fprintf(fp, "gr 33 get error\n");
		return FALSE;
	}

	unw_init_from_interruption(info, bt, pt, sw);
	ia64_exception_frame(pt, bt);

	return TRUE;
}

static int
unw_switch_from_osinit_v2(struct unw_frame_info *info, struct bt_info *bt)
{
	unsigned long pt, sw;
	char is_nat;

	/* pt_regs is the 1st argument of ia64_init_handler */
	if (unw_get_gr(info, 32, &pt, &is_nat)) {
		fprintf(fp, "gr 32 get error\n");

		return FALSE;
	}
	/* switch_stack is the 2nd argument of ia64_init_handler */
	if (unw_get_gr(info, 33, &sw, &is_nat)) {
		fprintf(fp, "gr 33 get error\n");
		return FALSE;
	}

	/* Fix me! */
	sw = info->psp + 16;
	pt = sw + STRUCT_SIZE("switch_stack");

	unw_init_from_interruption(info, bt, pt, sw);
	ia64_exception_frame(pt, bt);

	return TRUE;
}

/* CPL (current privilege level) is 2-bit field */
#define IA64_PSR_CPL0_BIT	32
#define IA64_PSR_CPL_MASK	(3UL << IA64_PSR_CPL0_BIT)

static int
user_mode(struct bt_info *bt, unsigned long pt)
{
	unsigned long cr_ipsr;

	cr_ipsr = IA64_GET_STACK_ULONG(pt + offsetof(struct pt_regs, cr_ipsr));
	if (cr_ipsr & IA64_PSR_CPL_MASK)
		return 1;
	return 0;
}

/*
 * Cope with INIT/MCA stack for the kernel 2.6.14 or later
 *
 * Returns FALSE if no more unwinding is needed.
 */
#define ALIGN16(x) ((x)&~15)
static int
unw_switch_from_osinit_v3(struct unw_frame_info *info, struct bt_info *bt,
			  char *type)
{
	unsigned long pt, sw, sos, pid;
	char *p, *q;
	struct task_context *tc = NULL;
	struct bt_info clone_bt;
	unsigned long kr_current, offset_kr;

	/*
	 *    The structure of INIT/MCA stack
	 *
	 *    +---------------------------+ <-------- IA64_STK_OFFSET
	 *    |          pt_regs          |
	 *    +---------------------------+
	 *    |        switch_stack       |
	 *    +---------------------------+
	 *    |        SAL/OS state       |
	 *    +---------------------------+
	 *    |    16 byte scratch area   |
	 *    +---------------------------+ <-------- SP at start of C handler
	 *    |           .....           |
	 *    +---------------------------+
	 *    | RBS for MCA/INIT handler  |
	 *    +---------------------------+
	 *    | struct task for MCA/INIT  |
	 *    +---------------------------+ <-------- bt->task
	 */
	pt = ALIGN16(bt->task + IA64_STK_OFFSET - STRUCT_SIZE("pt_regs"));
	sw = ALIGN16(pt - STRUCT_SIZE("switch_stack"));
	sos = ALIGN16(sw - STRUCT_SIZE("ia64_sal_os_state"));

	/*
	 * 1. Try to find interrupted task from comm
	 *
	 *    comm format of INIT/MCA task:
	 *       - "<type> <pid>"
	 *       - "<type> <comm> <processor>"
	 *    where "<type>" is either "INIT" or "MCA".
	 *    The latter form is chosen if PID is 0.
	 * 
	 *    See ia64_mca_modify_comm() in arch/ia64/kernel/mca.c
	 */
	if (!bt->tc || !bt->tc->comm)
		goto find_exframe;

	/*
	 * If comm is "INIT" or "MCA", it means original stack is not modified.
	 */
	if (STREQ(bt->tc->comm, type)) {
		/* Get pid using ia64_sal_os_state */
		pid = 0;
		offset_kr = MEMBER_OFFSET("ia64_sal_os_state",
		                          "prev_IA64_KR_CURRENT");
		readmem(sos + offset_kr, KVADDR, &kr_current, sizeof(ulong),
		        "ia64_sal_os_state prev_IA64_KR_CURRENT",
		        FAULT_ON_ERROR);
		readmem(kr_current + OFFSET(task_struct_pid), KVADDR, &pid,
		        sizeof(pid_t), "task_struct pid", FAULT_ON_ERROR);

		if (pid)
			tc = pid_to_context(pid);
		else {
			tc = pid_to_context(0);
			while (tc) {
				if (tc != bt->tc &&
					tc->processor == bt->tc->processor)
					break;
				tc = tc->tc_next;
			}
		}

		if (tc) {
			/* Clone bt_info and do backtrace */
			clone_bt_info(bt, &clone_bt, tc);
			if (!BT_REFERENCE_CHECK(&clone_bt)) {
				fprintf(fp, "(%s) INTERRUPTED TASK\n", type);
				print_task_header(fp, tc, 0);
			}
			if (!user_mode(bt, pt))
				goto find_exframe;
			else if (!BT_REFERENCE_CHECK(bt)) {
				fprintf(fp, " #0 [interrupted in user space]\n");
				/* at least show the incomplete exception frame */
				bt->flags |= BT_INCOMPLETE_USER_EFRAME;
				ia64_exception_frame(pt, bt);
			}
		}
		return FALSE;
	}

	if ((p = strstr(bt->tc->comm, type))) {
		p += strlen(type);
		if (*p != ' ')
			goto find_exframe;
		if ((q = strchr(++p, ' '))) {
			/* 
			 *  "<type> <comm> <processor>" 
			 *
			 *  We came from one of the PID 0 swapper tasks,
			 *  so just find the one with the same cpu as 
			 *  the passed-in INIT/MCA task.
			 */
			tc = pid_to_context(0);
			while (tc) {
				if (tc != bt->tc &&
				    tc->processor == bt->tc->processor)
					break;
				tc = tc->tc_next;
			}
		} else if (sscanf(p, "%lu", &pid) > 0)
			/* "<type> <pid>" */
			tc = pid_to_context(pid);
	}

	if (tc) {
		/* Clone bt_info and do backtrace */
		clone_bt_info(bt, &clone_bt, tc);
		if (!BT_REFERENCE_CHECK(&clone_bt)) {
			fprintf(fp, "(%s) INTERRUPTED TASK\n", type);
			print_task_header(fp, tc, 0);
		}
		if (!user_mode(bt, pt))
			back_trace(&clone_bt);
		else if (!BT_REFERENCE_CHECK(bt)) {
			fprintf(fp, " #0 [interrupted in user space]\n");
			/* at least show the incomplete exception frame */
			bt->flags |= BT_INCOMPLETE_USER_EFRAME;
			ia64_exception_frame(pt, bt);
		}
		return FALSE;
	}

	/* task matching with INIT/MCA task's comm is not found */

find_exframe:
	/*
	 * 2. If step 1 doesn't work, try best to find exception frame
	 */
	unw_init_from_interruption(info, bt, pt, sw);
	if (!BT_REFERENCE_CHECK(bt))
		ia64_exception_frame(pt, bt);

	return TRUE;
}

static void
unw_init_frame_info (struct unw_frame_info *info, struct bt_info *bt, ulong sw)
{
	unsigned long rbslimit, rbstop, stklimit, stktop, sol, ar_pfs;
	ulong t;

	t = bt->task;

	/*
	 * Subtle stuff here: we _could_ unwind through the
	 * switch_stack frame but we don't want to do that because it
	 * would be slow as each preserved register would have to be
	 * processed.  Instead, what we do here is zero out the frame
	 * info and start the unwind process at the function that
	 * created the switch_stack frame.  When a preserved value in
	 * switch_stack needs to be accessed, run_script() will
	 * initialize the appropriate pointer on demand.
	 */
	memset(info, 0, sizeof(*info));

	rbslimit = (unsigned long) t + IA64_RBS_OFFSET;
        readmem(sw + OFFSET(switch_stack_ar_bspstore), KVADDR,
                &rbstop, sizeof(ulong), "switch_stack ar_bspstore",
		FAULT_ON_ERROR);
	if (rbstop - (unsigned long) t >= IA64_STK_OFFSET)
		rbstop = rbslimit;

	stklimit = (unsigned long) t + IA64_STK_OFFSET;
	stktop   = (unsigned long) sw - 16;
	if (stktop <= rbstop)
		stktop = rbstop;

	info->regstk.limit = rbslimit;
	info->regstk.top   = rbstop;
	info->memstk.limit = stklimit;
	info->memstk.top   = stktop;
	info->task = (struct task_struct *)bt;
	info->sw  = (struct switch_stack *)sw;
	info->sp = info->psp = (unsigned long) (sw + SIZE(switch_stack)) - 16;
        info->cfm_loc = (ulong *)(sw + OFFSET(switch_stack_ar_pfs));
    	ar_pfs = IA64_GET_STACK_ULONG(info->cfm_loc); 
	sol = (ar_pfs >> 7) & 0x7f;
	info->bsp = (unsigned long) 
		ia64_rse_skip_regs((unsigned long *) info->regstk.top, -sol);
        info->ip = IA64_GET_STACK_ULONG(sw + OFFSET(switch_stack_b0)); 
        info->pr = IA64_GET_STACK_ULONG(sw + OFFSET(switch_stack_pr)); 

	find_save_locs(info);
}

/*
 *  Display the arguments to a function, presuming that they are found at
 *  the beginning of the sol section.
 */

#define MAX_REGISTER_PARAMS (8)

static void 
rse_function_params(struct bt_info *bt, struct unw_frame_info *info, char *name)
{
	int i;
	int numargs; 
	char is_nat[MAX_REGISTER_PARAMS];
	int retval[MAX_REGISTER_PARAMS];
	char buf1[BUFSIZE], buf2[BUFSIZE], buf3[BUFSIZE], *p1;
	ulong arglist[MAX_REGISTER_PARAMS];
	ulong ip;

	if (GDB_PATCHED())
        	return;

        unw_get_ip(info, &ip);

	numargs = MIN(get_function_numargs(ip), MAX_REGISTER_PARAMS);

	if (CRASHDEBUG(1))
		fprintf(fp, "rse_function_params: %s: %d args\n",
			name, numargs);

	switch (numargs)
	{
	case 0:
		fprintf(fp, "    (void)\n");
		return;

	case -1:
		return;

	default:
		break;
	}

	for (i = 0; i < numargs; i++) {
		arglist[i] = is_nat[i] = retval[i] = 0;
		retval[i] = unw_get_gr(info, 32+i, &arglist[i], &is_nat[i]);
	}

	sprintf(buf1, "    (");
	for (i = 0; i < numargs; i++) {
		p1 = &buf1[strlen(buf1)];
		if (retval[i] != 0)
			sprintf(buf2, "unknown");
		if (is_nat[i])
			sprintf(buf2, "[NAT]");
		else { 
			if (bt->flags & BT_FULL_SYM_SLAB)
				sprintf(buf2, "%s", 
					format_stack_entry(bt, buf3, 
					arglist[i], kt->end));
			else
				sprintf(buf2, "%lx", arglist[i]);
		}
		
		sprintf(p1, "%s%s", i ? ", " : "", buf2);
		if (strlen(buf1) >= 80) 
			sprintf(p1, ",\n     %s", buf2);
	}
	strcat(buf1, ")\n");

	fprintf(fp, "%s", buf1);
}

static int
find_save_locs (struct unw_frame_info *info)
{
	struct unw_script *scr;

	if ((info->ip & (machdep->machspec->unimpl_va_mask | 0xf)) ||
	    IS_UVADDR(info->ip, NULL)) {
		info->rp_loc = 0;
		return -1;
	}
		
        scr = script_lookup(info);
        if (!scr) {
        	scr = build_script(info);
        	if (!scr) {
			error(INFO, 
			    "failed to build unwind script for ip %lx\n",
				info->ip);
                	return -1;
        	}
	}

	run_script(scr, info);

	return 0;
}

static int
unw_unwind (struct unw_frame_info *info)
{
	unsigned long prev_ip, prev_sp, prev_bsp;
	unsigned long ip, pr, num_regs;
	int retval;
	struct bt_info *bt = (struct bt_info *)info->task;

	prev_ip = info->ip;
	prev_sp = info->sp;
	prev_bsp = info->bsp;

	/* restore the ip */
	if (!info->rp_loc) {
		error(INFO, 
		    "unwind: failed to locate return link (ip=0x%lx)!\n",
		       	info->ip);
		return -1;
	}
	ip = info->ip = IA64_GET_STACK_ULONG(info->rp_loc);
	if (ip < GATE_ADDR + PAGE_SIZE) {
		/*
		 * We don't have unwind info for the gate page, 
		 * so we consider that part
		 * of user-space for the purpose of unwinding.
		 */
		console("unwind: reached user-space (ip=0x%lx)\n", ip);
		return -1;
	}

	/* restore the cfm: */
	if (!info->pfs_loc) {
		error(INFO, "unwind: failed to locate ar.pfs!\n");
		return -1;
	}
	info->cfm_loc = info->pfs_loc;

	/* restore the bsp: */
	pr = info->pr;
	num_regs = 0;
	if ((info->flags & UNW_FLAG_INTERRUPT_FRAME)) {
#ifdef UNWIND_V1
		if ((pr & (1UL << pNonSys)) != 0)
			num_regs = IA64_GET_STACK_ULONG(info->cfm_loc) & 0x7f;		/* size of frame */
		info->pfs_loc =
			(unsigned long *) (info->sp + 16 + struct_offset(struct pt_regs, ar_pfs));
#endif
#ifdef UNWIND_V2
                info->pt = info->sp + 16;
                if ((pr & (1UL << pNonSys)) != 0)
                        num_regs = IA64_GET_STACK_ULONG(info->cfm_loc) & 0x7f;               /* size of frame */
                info->pfs_loc =
                        (unsigned long *) (info->pt + offsetof(struct pt_regs, ar_pfs));
#endif
#ifdef UNWIND_V3
                info->pt = info->sp + 16;
                if ((pr & (1UL << pNonSys)) != 0)
                        num_regs = IA64_GET_STACK_ULONG(info->cfm_loc) & 0x7f;               /* size of frame */
                info->pfs_loc =
                        (unsigned long *) (info->pt + offsetof(struct pt_regs, ar_pfs));
#endif
	} else
		num_regs = (IA64_GET_STACK_ULONG(info->cfm_loc) >> 7) & 0x7f;	/* size of locals */
	info->bsp = (unsigned long) ia64_rse_skip_regs((unsigned long *) info->bsp, -num_regs);
	if (info->bsp < info->regstk.limit || info->bsp > info->regstk.top) {
		error(INFO, "unwind: bsp (0x%lx) out of range [0x%lx-0x%lx]\n",
			info->bsp, info->regstk.limit, info->regstk.top);
		return -1;
	}

	/* restore the sp: */
	info->sp = info->psp;
	if ((info->sp < info->memstk.top || info->sp > info->memstk.limit)
		&& !ia64_in_init_stack(info->sp)) {
		error(INFO, "unwind: sp (0x%lx) out of range [0x%lx-0x%lx]\n",
			info->sp, info->memstk.top, info->memstk.limit);
		return -1;
	}

	if (info->ip == prev_ip && info->sp == prev_sp && info->bsp == prev_bsp) {
		error(INFO, 
	     "unwind: ip, sp, bsp remain unchanged; stopping here (ip=0x%lx)\n",
	    		ip);
		return -1;
	}

	/* as we unwind, the saved ar.unat becomes the primary unat: */
	info->pri_unat_loc = info->unat_loc;

	/* finally, restore the predicates: */
	unw_get_pr(info, &info->pr);

	retval = find_save_locs(info);
	return retval;
}

/*
 * Apply the unwinding actions represented by OPS and update SR to
 * reflect the state that existed upon entry to the function that this
 * unwinder represents.
 */
static void
run_script (struct unw_script *script, struct unw_frame_info *state)
{
	struct unw_insn *ip, *limit, next_insn;
	unsigned long opc, dst, val, off;
	unsigned long *s = (unsigned long *) state;
	struct bt_info *bt = (struct bt_info *)state->task;

	state->flags = script->flags;
	ip = script->insn;
	limit = script->insn + script->count;
	next_insn = *ip;

	while (ip++ < limit) {
		opc = next_insn.opc;
		dst = next_insn.dst;
		val = next_insn.val;
		next_insn = *ip;

	  redo:
		switch (opc) {
		      case UNW_INSN_ADD:
			s[dst] += val;
			break;

		      case UNW_INSN_MOVE2:
			if (!s[val])
				goto lazy_init;
			s[dst+1] = s[val+1];
			s[dst] = s[val];
			break;

		      case UNW_INSN_MOVE:
			if (!s[val])
				goto lazy_init;
			s[dst] = s[val];
			break;

#if defined(UNWIND_V2) || defined(UNWIND_V3)
		      case UNW_INSN_MOVE_SCRATCH:
			if (state->pt) {
				s[dst] = (unsigned long) get_scratch_regs(state) + val;
			} else {
				s[dst] = 0;
			}
			break;
#endif

		      case UNW_INSN_MOVE_STACKED:
			s[dst] = (unsigned long) ia64_rse_skip_regs((unsigned long *)state->bsp,
								    val);
			break;

		      case UNW_INSN_ADD_PSP:
			s[dst] = state->psp + val;
			break;

		      case UNW_INSN_ADD_SP:
			s[dst] = state->sp + val;
			break;

		      case UNW_INSN_SETNAT_MEMSTK:
			if (!state->pri_unat_loc)
				state->pri_unat_loc = &state->sw->ar_unat;
			/* register off. is a multiple of 8, so the least 3 bits (type) are 0 */
			s[dst+1] = ((unsigned long)(state->pri_unat_loc) - s[dst]) | UNW_NAT_MEMSTK;
			break;

		      case UNW_INSN_SETNAT_TYPE:
			s[dst+1] = val;
			break;

		      case UNW_INSN_LOAD:
#if UNW_DEBUG
			if ((s[val] & (local_cpu_data->unimpl_va_mask | 0x7)) != 0
			    || s[val] < TASK_SIZE)
			{
				debug(1, "unwind: rejecting bad psp=0x%lx\n", s[val]);
				break;
			}
#endif
			s[dst] = IA64_GET_STACK_ULONG(s[val]);
			break;
		}
	}
	return;

  lazy_init:
	off = unw.sw_off[val];
	s[val] = (unsigned long) state->sw + off;
	if (off >= struct_offset(struct switch_stack, r4)
	    && off <= struct_offset(struct switch_stack, r7))
		/*
		 * We're initializing a general register: init NaT info, too.  Note that
		 * the offset is a multiple of 8 which gives us the 3 bits needed for
		 * the type field.
		 */
		s[val+1] = (struct_offset(struct switch_stack, ar_unat) - off) | UNW_NAT_MEMSTK;
	goto redo;
}

/*
 *  Don't bother with the kernel's script hashing scheme -- we're not worried 
 *  about lookup speed.
 */
static struct unw_script *
script_lookup(struct unw_frame_info *info)
{
	int i;
        struct unw_script *script;
        unsigned long ip, pr;
	struct machine_specific *ms;

	ms = machdep->machspec;
	ms->script_cache_fills++;

        ip = info->ip;
        pr = info->pr;

	for (i = 0; i < UNW_CACHE_SIZE; i++) {
		script = &ms->script_cache[i];
		if (!script->ip)
			break;
        	if ((ip == script->ip) && 
		    (((pr ^ script->pr_val) & script->pr_mask) == 0)) {
			ms->script_cache_hits++;
                	return script;
		}
	}

	return NULL;
}

static struct unw_script *
script_new(unsigned long ip)
{
	struct unw_script *script;
	struct machine_specific *ms;

	ms = machdep->machspec;

	script = &ms->script_cache[ms->script_index];
	BZERO(script, sizeof(struct unw_script));
	ms->script_index++;
	ms->script_index %= UNW_CACHE_SIZE;

	script->ip = ip;	

        return script;
}

static void
script_finalize (struct unw_script *script, struct unw_state_record *sr)
{
        script->pr_mask = sr->pr_mask;
        script->pr_val = sr->pr_val;
}

static void
script_emit(struct unw_script *script, struct unw_insn insn)
{
        if (script->count >= UNW_MAX_SCRIPT_LEN) {
                error(INFO, 
		    "unwind: script exceeds maximum size of %u instructions!\n",
                        UNW_MAX_SCRIPT_LEN);
                return;
        }
        script->insn[script->count++] = insn;
}


static void
emit_nat_info(struct unw_state_record *sr, int i, struct unw_script *script)
{
	struct unw_reg_info *r = sr->curr.reg + i;
	enum unw_insn_opcode opc;
	struct unw_insn insn;
	unsigned long val = 0;

	switch (r->where) {
	      case UNW_WHERE_GR:
		if (r->val >= 32) {
			/* register got spilled to a stacked register */
			opc = UNW_INSN_SETNAT_TYPE;
			val = UNW_NAT_REGSTK;
		} else
			/* register got spilled to a scratch register */
			opc = UNW_INSN_SETNAT_MEMSTK;
		break;

	      case UNW_WHERE_FR:
		opc = UNW_INSN_SETNAT_TYPE;
		val = UNW_NAT_VAL;
		break;

	      case UNW_WHERE_BR:
		opc = UNW_INSN_SETNAT_TYPE;
		val = UNW_NAT_NONE;
		break;

	      case UNW_WHERE_PSPREL:
	      case UNW_WHERE_SPREL:
		opc = UNW_INSN_SETNAT_MEMSTK;
		break;

	      default:
		error(INFO, 
		    "unwind: don't know how to emit nat info for where = %u\n", 
			r->where);
		return;
	}
	insn.opc = opc;
	insn.dst = unw.preg_index[i];
	insn.val = val;
	script_emit(script, insn);
}

/*
 * Build an unwind script that unwinds from state OLD_STATE to the
 * entrypoint of the function that called OLD_STATE.
 */
#define UNWIND_INFO_BUFSIZE (3000)  /* absurdly large static buffer that */ 
                                    /* should avoid need for GETBUF() */
static struct unw_script *
build_script (struct unw_frame_info *info)
{
	const struct unw_table_entry *e = 0;
	struct unw_script *script = 0;
	struct unw_labeled_state *ls, *next;
	unsigned long ip = info->ip;
	struct unw_state_record sr;
	struct unw_table *table;
	struct unw_reg_info *r;
	struct unw_insn insn;
	u8 *dp, *desc_end;
	u64 hdr;
	int i;
	struct unw_table unw_table_buf;
	char unwind_info_buf[UNWIND_INFO_BUFSIZE];
	struct bt_info *bt = (struct bt_info *)info->task;

	/* build state record */
	memset(&sr, 0, sizeof(sr));
	for (r = sr.curr.reg; r < sr.curr.reg + UNW_NUM_REGS; ++r)
		r->when = UNW_WHEN_NEVER;
	sr.pr_val = info->pr;

	script = script_new(ip);
	if (!script) {
		error(INFO, "failed to create a new unwind script\n");
		return 0;
	}

	/*
	 *  The kernel table is embedded and guaranteed to be the first
         *  one on the list.
	 */
	table = &unw.kernel_table;
	if (ip >= table->start && ip < table->end) 
		e = lookup(table, ip - table->segment_base);

	/*
	 *  If not found, walk through the module list.
	 */
	while (!e && table->next) {
                if (!readmem((ulong)table->next, KVADDR, &unw_table_buf, 
		    sizeof(struct unw_table), "module unw_table",
                    RETURN_ON_ERROR))
			break;
		table = &unw_table_buf;
        	if (ip >= table->start && ip < table->end)
                	e = lookup(table, ip - table->segment_base);
	}

	if (!e) {
		/* no info, return default unwinder (leaf proc, no mem stack, 
		   no saved regs)  */
		if (CRASHDEBUG(2)) 
			error(INFO, "unwind: no unwind info for ip %lx\n", ip);
		bt->flags |= BT_UNWIND_ERROR;
		sr.curr.reg[UNW_REG_RP].where = UNW_WHERE_BR;
		sr.curr.reg[UNW_REG_RP].when = -1;
		sr.curr.reg[UNW_REG_RP].val = 0;
		compile_reg(&sr, UNW_REG_RP, script);
		script_finalize(script, &sr);
		return script;
	}

	sr.when_target = 
		(3*((ip & ~0xfUL) - (table->segment_base + e->start_offset))/16
	        + (ip & 0xfUL));
#ifdef REDHAT
        readmem((ulong)(table->segment_base + e->info_offset), KVADDR, 
		unwind_info_buf, UNWIND_INFO_BUFSIZE, "unwind info", 
		FAULT_ON_ERROR);
	hdr = *(u64 *)unwind_info_buf;
	if (((UNW_LENGTH(hdr)*8)+8) > UNWIND_INFO_BUFSIZE) 
		error(FATAL, 
	      "absurdly large unwind_info: %d (redefine UNWIND_INFO_BUFSIZE)\n",
			(UNW_LENGTH(hdr)*8)+8);
	dp = (u8 *)(unwind_info_buf + 8);
	desc_end = dp + 8*UNW_LENGTH(hdr);
#else
	hdr = *(u64 *) (table->segment_base + e->info_offset);
	dp =   (u8 *)  (table->segment_base + e->info_offset + 8);
	desc_end = dp + 8*UNW_LENGTH(hdr);
#endif

	while (!sr.done && dp < desc_end)
		dp = unw_decode(dp, sr.in_body, &sr);

	if (sr.when_target > sr.epilogue_start) {
		/*
		 * sp has been restored and all values on the memory stack below
		 * psp also have been restored.
		 */
		sr.curr.reg[UNW_REG_PSP].val = 0;
		sr.curr.reg[UNW_REG_PSP].where = UNW_WHERE_NONE;
		sr.curr.reg[UNW_REG_PSP].when = UNW_WHEN_NEVER;
		for (r = sr.curr.reg; r < sr.curr.reg + UNW_NUM_REGS; ++r)
			if ((r->where == UNW_WHERE_PSPREL && r->val <= 0x10)
			    || r->where == UNW_WHERE_SPREL)
			{
				r->val = 0;
				r->where = UNW_WHERE_NONE;
				r->when = UNW_WHEN_NEVER;
			}
	}

	script->flags = sr.flags;

	/*
	 * If RP did't get saved, generate entry for the return link
	 * register.
	 */
	if (sr.curr.reg[UNW_REG_RP].when >= sr.when_target) {
		sr.curr.reg[UNW_REG_RP].where = UNW_WHERE_BR;
		sr.curr.reg[UNW_REG_RP].when = -1;
		sr.curr.reg[UNW_REG_RP].val = sr.return_link_reg;
	}

	/* translate state record into unwinder instructions: */

	/*
	 * First, set psp if we're dealing with a fixed-size frame;
	 * subsequent instructions may depend on this value.
	 */
	if (sr.when_target > sr.curr.reg[UNW_REG_PSP].when
	    && (sr.curr.reg[UNW_REG_PSP].where == UNW_WHERE_NONE)
	    && sr.curr.reg[UNW_REG_PSP].val != 0) {
		/* new psp is sp plus frame size */
		insn.opc = UNW_INSN_ADD;
		insn.dst = struct_offset(struct unw_frame_info, psp)/8;
		insn.val = sr.curr.reg[UNW_REG_PSP].val;	/* frame size */
		script_emit(script, insn);
	}

	/* determine where the primary UNaT is: */
	if (sr.when_target < sr.curr.reg[UNW_REG_PRI_UNAT_GR].when)
		i = UNW_REG_PRI_UNAT_MEM;
	else if (sr.when_target < sr.curr.reg[UNW_REG_PRI_UNAT_MEM].when)
		i = UNW_REG_PRI_UNAT_GR;
	else if (sr.curr.reg[UNW_REG_PRI_UNAT_MEM].when > 
	    sr.curr.reg[UNW_REG_PRI_UNAT_GR].when)
		i = UNW_REG_PRI_UNAT_MEM;
	else
		i = UNW_REG_PRI_UNAT_GR;

	compile_reg(&sr, i, script);

	for (i = UNW_REG_BSP; i < UNW_NUM_REGS; ++i)
		compile_reg(&sr, i, script);

	/* free labeled register states & stack: */

	for (ls = sr.labeled_states; ls; ls = next) {
		next = ls->next;
		free_state_stack(&ls->saved_state);
		free_labeled_state(ls);
	}
	free_state_stack(&sr.curr);

	script_finalize(script, &sr);
	return script;
}


static struct unw_table_entry *
lookup(struct unw_table *table, unsigned long rel_ip)
{
	struct unw_table_entry *e = 0;
	unsigned long lo, hi, mid;
	struct unw_table_entry *array, *loc_array;
	static struct unw_table_entry e_returned;

	if (table == &unw.kernel_table) {
		array = (struct unw_table_entry *)table->array;
		loc_array = NULL;
	} else {
        	loc_array = (struct unw_table_entry *) 
		    	GETBUF(table->length * sizeof(struct unw_table_entry));
	        if (!readmem((ulong)table->array, KVADDR, loc_array, 
		    table->length * sizeof(struct unw_table_entry),
	            "module unw_table_entry array", RETURN_ON_ERROR|QUIET)) {
			if (IS_MODULE_VADDR(table->segment_base + rel_ip))
	                	error(WARNING, 
		    	          "cannot read module unw_table_entry array\n");
	                return 0;
	        }
		array = loc_array;
	}

	/* do a binary search for right entry: */
	for (lo = 0, hi = table->length; lo < hi; ) {
		mid = (lo + hi) / 2;
		e = &array[mid];
		if (rel_ip < e->start_offset)
			hi = mid;
		else if (rel_ip >= e->end_offset)
			lo = mid + 1;
		else
			break;
	}

	/*
	 *  Return a pointer to a static copy of "e" if found, and
         *  give back the module buffer if used.
	 */
	if (e) {
		BCOPY(e, &e_returned, sizeof(struct unw_table_entry));
		e = &e_returned;
	}
	if (loc_array)
		FREEBUF(loc_array);

	if (rel_ip < e->start_offset || rel_ip >= e->end_offset)
		return NULL;

	return e;
}

static void
compile_reg (struct unw_state_record *sr, int i, struct unw_script *script)
{
	struct unw_reg_info *r = sr->curr.reg + i;
	enum unw_insn_opcode opc;
	unsigned long val, rval;
	struct unw_insn insn;
	long need_nat_info;

	if (machdep->flags & UNW_PTREGS) {
		compile_reg_v2(sr, i, script);
		return;
	}

	if (r->where == UNW_WHERE_NONE || r->when >= sr->when_target)
		return;

	opc = UNW_INSN_MOVE;
	val = rval = r->val;
	need_nat_info = (i >= UNW_REG_R4 && i <= UNW_REG_R7);

	switch (r->where) {
	      case UNW_WHERE_GR:
		if (rval >= 32) {
			opc = UNW_INSN_MOVE_STACKED;
			val = rval - 32;
		} else if (rval >= 4 && rval <= 7) {
			if (need_nat_info) {
				opc = UNW_INSN_MOVE2;
				need_nat_info = 0;
			}
			val = unw.preg_index[UNW_REG_R4 + (rval - 4)];
		} else {
			opc = UNW_INSN_ADD_SP;
			val = -SIZE(pt_regs) + pt_regs_off(rval);
		}
		break;

	      case UNW_WHERE_FR:
		if (rval <= 5)
			val = unw.preg_index[UNW_REG_F2  + (rval -  2)];
		else if (rval >= 16 && rval <= 31)
			val = unw.preg_index[UNW_REG_F16 + (rval - 16)];
		else {
			opc = UNW_INSN_ADD_SP;
			val = -SIZE(pt_regs);
			if (rval <= 9)
				val += struct_offset(struct pt_regs, f6) + 16*(rval - 6);
			else
				error(INFO,
				    "unwind: kernel may not touch f%lu\n", 
				    	rval);
		}
		break;

	      case UNW_WHERE_BR:
		if (rval >= 1 && rval <= 5)
			val = unw.preg_index[UNW_REG_B1 + (rval - 1)];
		else {
			opc = UNW_INSN_ADD_SP;
			val = -SIZE(pt_regs);
			if (rval == 0)
				val += struct_offset(struct pt_regs, b0);
			else if (rval == 6)
				val += struct_offset(struct pt_regs, b6);
			else
				val += struct_offset(struct pt_regs, b7);
		}
		break;

	      case UNW_WHERE_SPREL:
		opc = UNW_INSN_ADD_SP;
		break;

	      case UNW_WHERE_PSPREL:
		opc = UNW_INSN_ADD_PSP;
		break;

	      default:
		error(INFO, 
		    "unwind: register %u has unexpected `where' value of %u\n",
		   	 i, r->where);
		break;
	}
	insn.opc = opc;
	insn.dst = unw.preg_index[i];
	insn.val = val;
	script_emit(script, insn);
	if (need_nat_info)
		emit_nat_info(sr, i, script);

	if (i == UNW_REG_PSP) {
		/*
		 * info->psp must contain the _value_ of the previous
		 * sp, not it's save location.  We get this by
		 * dereferencing the value we just stored in
		 * info->psp:
		 */
		insn.opc = UNW_INSN_LOAD;
		insn.dst = insn.val = unw.preg_index[UNW_REG_PSP];
		script_emit(script, insn);
	}
}

static void
compile_reg_v2 (struct unw_state_record *sr, int i, struct unw_script *script)
{
	struct unw_reg_info *r = sr->curr.reg + i;
	enum unw_insn_opcode opc;
	unsigned long val, rval;
	struct unw_insn insn;
	long need_nat_info;

	if (r->where == UNW_WHERE_NONE || r->when >= sr->when_target)
		return;

	opc = UNW_INSN_MOVE;
	val = rval = r->val;
	need_nat_info = (i >= UNW_REG_R4 && i <= UNW_REG_R7);

	switch (r->where) {
	      case UNW_WHERE_GR:
		if (rval >= 32) {
			opc = UNW_INSN_MOVE_STACKED;
			val = rval - 32;
		} else if (rval >= 4 && rval <= 7) {
			if (need_nat_info) {
				opc = UNW_INSN_MOVE2;
				need_nat_info = 0;
			}
			val = unw.preg_index[UNW_REG_R4 + (rval - 4)];
		} else {
			/* register got spilled to a scratch register */
			opc = UNW_INSN_MOVE_SCRATCH;
			val = pt_regs_off(rval);
		}
		break;

	      case UNW_WHERE_FR:
		if (rval <= 5)
			val = unw.preg_index[UNW_REG_F2  + (rval -  2)];
		else if (rval >= 16 && rval <= 31)
			val = unw.preg_index[UNW_REG_F16 + (rval - 16)];
		else {
			opc = UNW_INSN_MOVE_SCRATCH;
			if (rval <= 11)
				val = offsetof(struct pt_regs, f6) + 16*(rval - 6);
			else
				error(INFO, 
				   "compile_reg: kernel may not touch f%lu\n",
					rval);
		}
		break;

	      case UNW_WHERE_BR:
		if (rval >= 1 && rval <= 5)
			val = unw.preg_index[UNW_REG_B1 + (rval - 1)];
		else {
			opc = UNW_INSN_MOVE_SCRATCH;
			if (rval == 0)
				val = offsetof(struct pt_regs, b0);
			else if (rval == 6)
				val = offsetof(struct pt_regs, b6);
			else
				val = offsetof(struct pt_regs, b7);
		}
		break;

	      case UNW_WHERE_SPREL:
		opc = UNW_INSN_ADD_SP;
		break;

	      case UNW_WHERE_PSPREL:
		opc = UNW_INSN_ADD_PSP;
		break;

	      default:
		error(INFO, 
	        "compile_reg: register %u has unexpected `where' value of %u\n",
			   i, r->where);
		break;
	}
	insn.opc = opc;
	insn.dst = unw.preg_index[i];
	insn.val = val;
	script_emit(script, insn);
	if (need_nat_info)
		emit_nat_info(sr, i, script);

	if (i == UNW_REG_PSP) {
		/*
		 * info->psp must contain the _value_ of the previous
		 * sp, not it's save location.  We get this by
		 * dereferencing the value we just stored in
		 * info->psp:
		 */
		insn.opc = UNW_INSN_LOAD;
		insn.dst = insn.val = unw.preg_index[UNW_REG_PSP];
		script_emit(script, insn);
	}
}

#endif /* IA64 */
