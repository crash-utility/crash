/* x86.c - core analysis suite
 *
 * Portions Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002-2014,2017-2018 David Anderson
 * Copyright (C) 2002-2014,2017-2018 Red Hat, Inc. All rights reserved.
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

#ifdef X86
/*
 *                     NOTICE OF APPRECIATION
 *
 *  The stack-trace related code in this file is an extension of the stack 
 *  trace code from the Mach in-kernel debugger "ddb".  Sincere thanks to 
 *  the author(s).
 *
 */

/*
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie the
 * rights to redistribute these changes.
 */
#include "defs.h"
#include "xen_hyper_defs.h"

#ifndef MCLX

#include <sys/param.h>
#include <sys/systm.h>

#include <machine/cpu.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <ddb/ddb.h>

#include <ddb/db_access.h>
#include <ddb/db_sym.h>
#include <ddb/db_variables.h>

/*
 * Machine register set.
 */
struct db_variable db_regs[] = {
	"cs",	&ddb_regs.tf_cs,  FCN_NULL,
	"ds",	&ddb_regs.tf_ds,  FCN_NULL,
	"es",	&ddb_regs.tf_es,  FCN_NULL,
#if 0
	"fs",	&ddb_regs.tf_fs,  FCN_NULL,
	"gs",	&ddb_regs.tf_gs,  FCN_NULL,
#endif
	"ss",	&ddb_regs.tf_ss,  FCN_NULL,
	"eax",	&ddb_regs.tf_eax, FCN_NULL,
	"ecx",	&ddb_regs.tf_ecx, FCN_NULL,
	"edx",	&ddb_regs.tf_edx, FCN_NULL,
	"ebx",	&ddb_regs.tf_ebx, FCN_NULL,
	"esp",	&ddb_regs.tf_esp, FCN_NULL,
	"ebp",	&ddb_regs.tf_ebp, FCN_NULL,
	"esi",	&ddb_regs.tf_esi, FCN_NULL,
	"edi",	&ddb_regs.tf_edi, FCN_NULL,
	"eip",	&ddb_regs.tf_eip, FCN_NULL,
	"efl",	&ddb_regs.tf_eflags, FCN_NULL,
};
struct db_variable *db_eregs = db_regs + sizeof(db_regs)/sizeof(db_regs[0]);
#else

typedef int             db_strategy_t;  /* search strategy */

#define DB_STGY_ANY     0                       /* anything goes */
#define DB_STGY_XTRN    1                       /* only external symbols */
#define DB_STGY_PROC    2                       /* only procedures */

typedef ulong           db_addr_t;      /* address - unsigned */
typedef int             db_expr_t;      /* expression - signed */

/*
 * Symbol representation is specific to the symtab style:
 * BSD compilers use dbx' nlist, other compilers might use
 * a different one
 */
typedef char *          db_sym_t;       /* opaque handle on symbols */
#define DB_SYM_NULL     ((db_sym_t)0)

typedef uint            boolean_t;

#endif /* !MCLX */

/*
 * Stack trace.
 */
#ifdef MCLX
static db_expr_t db_get_value(db_addr_t, int, boolean_t, struct bt_info *);
#define INKERNEL(va) (machdep->kvtop(CURRENT_CONTEXT(), va, &phys, 0))
#else
#define	INKERNEL(va)	(((vm_offset_t)(va)) >= USRSTACK)
#endif

struct i386_frame {
	struct i386_frame	*f_frame;
	int			f_retaddr;
	int			f_arg0;
};

#ifdef MCLX
#define NORMAL              0
#define IDT_DIRECT_ENTRY    1
#define IDT_JMP_ERROR_CODE  2
#define RET_FROM_INTR       3
#define SIGNAL_RETURN       4
#else
#define NORMAL		0
#define	TRAP		1
#define	INTERRUPT	2
#define	SYSCALL		3
#endif

#ifndef MCLX
typedef vm_offset_t     db_addr_t;
#endif

#ifdef MCLX
struct eframe {
        int eframe_found;
	int eframe_type;
        ulong eframe_addr;
	ulong jmp_error_code_eip;
};

static void db_nextframe(struct i386_frame **, db_addr_t *, struct eframe *,
	struct bt_info *);
static int dump_eframe(struct eframe *, int, struct bt_info *);
static int eframe_numargs(ulong eip, struct bt_info *);
static int check_for_eframe(char *, struct bt_info *);
static void x86_user_eframe(struct bt_info *);
static ulong x86_next_eframe(ulong addr, struct bt_info *bt);
static void x86_cmd_mach(void);
static int x86_get_smp_cpus(void);
static void x86_display_machine_stats(void);
static void x86_display_cpu_data(unsigned int);
static void x86_display_memmap(void);
static int x86_omit_frame_pointer(void);
static void x86_back_trace_cmd(struct bt_info *);
static int is_rodata_text(ulong);
static int mach_CRASHDEBUG(ulong);
static db_sym_t db_search_symbol(db_addr_t, db_strategy_t,db_expr_t *);
static void db_symbol_values(db_sym_t, char **, db_expr_t *);
static int db_sym_numargs(db_sym_t, int *, char **);
static void x86_dump_line_number(ulong);
static void x86_clear_machdep_cache(void);
static void x86_parse_cmdline_args(void);

static ulong mach_debug = 0;

static int
mach_CRASHDEBUG(ulong dval)
{
        if (CRASHDEBUG(dval))
                return TRUE;

        return (mach_debug >= dval);
}


#else
static void db_nextframe(struct i386_frame **, db_addr_t *);
#endif
#ifdef MCLX
static int db_numargs(struct i386_frame *, struct bt_info *bt);
static void db_print_stack_entry(char *, int, char **, int *, 
	    db_addr_t, struct bt_info *, struct eframe *, int, 
	    struct i386_frame *);
#else
static void db_print_stack_entry (char *, int, char **, int *, db_addr_t);
#endif

/*
 * Figure out how many arguments were passed into the frame at "fp".
 */
static int
db_numargs(fp, bt)
	struct i386_frame *fp;
	struct bt_info *bt;
{
	int	*argp;
	int	inst;
	int	args;

	argp = (int *)db_get_value((int)&fp->f_retaddr, 4, FALSE, bt);
	/*
	 * etext is wrong for LKMs.  We should attempt to interpret
	 * the instruction at the return address in all cases.  This
	 * may require better fault handling.
	 */
#ifdef MCLX
	if (!is_kernel_text((ulong)argp)) {
#else
	if (argp < (int *)btext || argp >= (int *)etext) {
#endif
		args = 5;
	} else {
		inst = db_get_value((int)argp, 4, FALSE, bt);
		if ((inst & 0xff) == 0x59)	/* popl %ecx */
			args = 1;
		else if ((inst & 0xffff) == 0xc483)	/* addl $Ibs, %esp */
			args = ((inst >> 16) & 0xff) / 4;
		else
			args = 5;
	}
	return (args);
}

#ifdef MCLX
static int
eframe_numargs(ulong eip, struct bt_info *bt)
{
        int     inst;
        int     args;

	if (!is_kernel_text(eip)) 
		args = 5;
	else {
                inst = db_get_value((int)eip, 4, FALSE, bt);
                if ((inst & 0xff) == 0x59)      /* popl %ecx */
                        args = 1;
                else if ((inst & 0xffff) == 0xc483)     /* addl $Ibs, %esp */
                        args = ((inst >> 16) & 0xff) / 4;
                else
                        args = 5;
        }

	return args;
}
#endif

static void
#ifdef MCLX
db_print_stack_entry(name, narg, argnp, argp, callpc, bt, ep, fnum, frame)
#else
db_print_stack_entry(name, narg, argnp, argp, callpc)
#endif
	char *name;
	int narg;
	char **argnp;
	int *argp;
	db_addr_t callpc;
#ifdef MCLX
	struct bt_info *bt;
	struct eframe *ep;
	int fnum;
	struct i386_frame *frame;
#endif
{
#ifdef MCLX
	int i;
	db_expr_t arg;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char *sp;

	if (!name) {
		if (IS_MODULE_VADDR(callpc) &&
		    module_symbol(callpc, NULL, NULL, buf1, *gdb_output_radix)) {
			sprintf(buf2, "(%s)", buf1);
			name = buf2;
		}
		else
			name = "(unknown module)";
	}

	if (strstr(name, "_MODULE_START_")) {
		sprintf(buf3, "(%s module)", name + strlen("_MODULE_START_"));
		name = buf3;
	}

	if (BT_REFERENCE_CHECK(bt)) {
		switch (bt->ref->cmdflags & (BT_REF_SYMBOL|BT_REF_HEXVAL))
		{
		case BT_REF_SYMBOL: 
			if (ep->eframe_found && ep->jmp_error_code_eip) {
			       if (STREQ(closest_symbol(ep->jmp_error_code_eip),
			    	   bt->ref->str) || 
				   STREQ(closest_symbol(callpc), bt->ref->str))
					bt->ref->cmdflags |= BT_REF_FOUND;
			} else if (STREQ(name, bt->ref->str))
				bt->ref->cmdflags |= BT_REF_FOUND;
			break;

		case BT_REF_HEXVAL: 
			if (ep->eframe_found && ep->jmp_error_code_eip &&
			    (bt->ref->hexval == ep->jmp_error_code_eip))
				bt->ref->cmdflags |= BT_REF_FOUND;   
			else if (bt->ref->hexval == callpc)
				bt->ref->cmdflags |= BT_REF_FOUND;
			break;
		}

		return;

	} else {
		fprintf(fp, "%s#%d [%08lx] ", 
			fnum < 10 ? " " : "", fnum, (ulong)frame);

		if (ep->eframe_found && ep->jmp_error_code_eip)
        		fprintf(fp, "%s (via %s)",
				closest_symbol(callpc),
                		closest_symbol(ep->jmp_error_code_eip));
		else
		fprintf(fp, "%s", name);

        	fprintf(fp, " at %lx\n", callpc);
	}

	if (ep->eframe_found) 
		goto done_entry;

	if (STREQ(name, "L6"))
		goto done_entry;

        fprintf(fp, "    (");

	if ((i = get_function_numargs(callpc)) >= 0)
		narg = i;

        while (narg) {
                if (argnp)
                        fprintf(fp, "%s=", *argnp++);

		arg = db_get_value((int)argp, 4, FALSE, bt);

		if ((sp = value_symbol(arg)))
			fprintf(fp, "%s", sp);
		else if ((bt->flags & BT_SYMBOLIC_ARGS) &&
		    strlen(value_to_symstr(arg, buf1, 0)))
			fprintf(fp, "%s", buf1);
		else
			fprintf(fp, "%x", arg);
		
                argp++;
                if (--narg != 0)
                        fprintf(fp, ", ");
        }

	if (i == 0)
		fprintf(fp, "void");

        fprintf(fp, ")\n");
done_entry:
	if (bt->flags & BT_LINE_NUMBERS) 
		x86_dump_line_number(callpc);

	return;

#else
	db_printf("%s(", name);
	while (narg) {
		if (argnp)
			db_printf("%s=", *argnp++);
		db_printf("%r", db_get_value((int)argp, 4, FALSE, bt));
		argp++;
		if (--narg != 0)
			db_printf(",");
  	}
	db_printf(") at ");
	db_printsym(callpc, DB_STGY_PROC);
	db_printf("\n");
	return;
#endif
}

#ifdef MCLX
static db_sym_t
db_search_symbol(db_addr_t val, db_strategy_t strategy, db_expr_t *offp) 
{
	struct syment *sp;
	ulong offset;

	if ((sp = value_search(val, &offset))) {
		*offp = (db_expr_t)offset;
		return(sp->name);
	} else
		return DB_SYM_NULL;
}

/*
 * Return name and value of a symbol
 */
static void
db_symbol_values(db_sym_t sym, char **namep, db_expr_t *valuep)
{
	struct syment   *sp;

        if (sym == DB_SYM_NULL) {
                *namep = 0;
                return;
        }

        if ((sp = symbol_search(sym)) == NULL) {
		error(INFO, "db_symbol_values: cannot find symbol: %s\n", sym);
                *namep = 0;
		return;
	}

	*namep = sp->name;
	if (valuep)
		*valuep = sp->value;

#ifndef MCLX
        X_db_symbol_values(db_last_symtab, sym, namep, &value);

        if (db_symbol_is_ambiguous(sym))
                *namep = db_qualify(sym, db_last_symtab->name);
        if (valuep)
                *valuep = value;
#endif
}

static unsigned db_extend[] = { /* table for sign-extending */
        0,
        0xFFFFFF80U,
        0xFFFF8000U,
        0xFF800000U
};

static db_expr_t
db_get_value(addr, size, is_signed, bt)
        db_addr_t        addr;
        int     	 size;
        boolean_t        is_signed;
	struct bt_info * bt;
{
        char            data[sizeof(int)];
        db_expr_t 	value;
        int    		i;

#ifndef MCLX
        db_read_bytes(addr, size, data);
#else
	BZERO(data, sizeof(int));
	if (INSTACK(addr, bt)) {
		if (size == sizeof(ulong)) 
			return (db_expr_t)GET_STACK_ULONG(addr); 
		else
			GET_STACK_DATA(addr, data, size);
	} else {
		if (!readmem(addr, KVADDR, &value, size, "db_get_value", 
	    	     RETURN_ON_ERROR))
			error(FATAL, "db_get_value: read error: address: %lx\n",
				 addr);
	}
#endif

        value = 0;
#if     BYTE_MSF
        for (i = 0; i < size; i++)
#else   /* BYTE_LSF */
        for (i = size - 1; i >= 0; i--)
#endif
        {
            value = (value << 8) + (data[i] & 0xFF);
        }

        if (size < 4) {
            if (is_signed && (value & db_extend[size]) != 0)
                value |= db_extend[size];
        }
        return (value);
}

static int
db_sym_numargs(db_sym_t sym, int *nargp, char **argnames)
{
        return FALSE;
}

#endif

/*
 * Figure out the next frame up in the call stack.
 */
#ifdef MCLX
static void
db_nextframe(fp, ip, ep, bt)
        struct i386_frame **fp;            /* in/out */
        db_addr_t          *ip;            /* out */
	struct eframe      *ep;
	struct bt_info     *bt;
#else
static void
db_nextframe(fp, ip)
	struct i386_frame **fp;		/* in/out */
	db_addr_t	*ip;		/* out */
#endif
{
	int eip, ebp;
	db_expr_t offset;
	char *sym, *name;
#ifdef MCLX
	static int last_ebp;
	static int last_eip;
	struct syment *sp;
#endif

	eip = db_get_value((int) &(*fp)->f_retaddr, 4, FALSE, bt);
	ebp = db_get_value((int) &(*fp)->f_frame, 4, FALSE, bt);

	/*
	 * Figure out frame type, presuming normal.
	 */
	BZERO(ep, sizeof(struct eframe));
	ep->eframe_type = NORMAL;

	sym = db_search_symbol(eip, DB_STGY_ANY, &offset);
	db_symbol_values(sym, &name, NULL);
	if (name != NULL) {
		ep->eframe_type = check_for_eframe(name, bt);
#ifndef MCLX
		if (!strcmp(name, "calltrap")) {
			frame_type = TRAP;
		} else if (!strncmp(name, "Xresume", 7)) {
			frame_type = INTERRUPT;
		} else if (!strcmp(name, "_Xsyscall")) {
			frame_type = SYSCALL;
		}
#endif
	}

	switch (ep->eframe_type)
	{
	case NORMAL:
                ep->eframe_found = FALSE;
                break;

	case IDT_DIRECT_ENTRY:
	case RET_FROM_INTR:
	case SIGNAL_RETURN:
                ep->eframe_found = TRUE;
                ep->eframe_addr = x86_next_eframe(last_ebp + sizeof(ulong)*2,
                    bt);
		break;

	case IDT_JMP_ERROR_CODE:
                ep->eframe_found = TRUE;
                ep->eframe_addr = x86_next_eframe(last_ebp + sizeof(ulong) * 4,
                    bt);
		if ((sp = x86_jmp_error_code(last_eip))) 
			ep->jmp_error_code_eip = sp->value;
                break;

	default:
		error(FATAL, "unknown exception frame type?\n");

	}

        *ip = (db_addr_t) eip;
        *fp = (struct i386_frame *) ebp;
        last_ebp = ebp;
	last_eip = eip;

	return;

#ifndef MCLX
	db_print_stack_entry(name, 0, 0, 0, eip);

	/*
	 * Point to base of trapframe which is just above the
	 * current frame.
	 */
	tf = (struct trapframe *) ((int)*fp + 8);

	esp = (ISPL(tf->tf_cs) == SEL_UPL) ?  tf->tf_esp : (int)&tf->tf_esp;
	switch (frame_type) {
	case TRAP:
		if (INKERNEL((int) tf)) {
			eip = tf->tf_eip;
			ebp = tf->tf_ebp;
			db_printf(
		    "--- trap %#r, eip = %#r, esp = %#r, ebp = %#r ---\n",
			    tf->tf_trapno, eip, esp, ebp);
		}
		break;
	case SYSCALL:
		if (INKERNEL((int) tf)) {
			eip = tf->tf_eip;
			ebp = tf->tf_ebp;
			db_printf(
		    "--- syscall %#r, eip = %#r, esp = %#r, ebp = %#r ---\n",
			    tf->tf_eax, eip, esp, ebp);
		}
		break;
	case INTERRUPT:
		tf = (struct trapframe *)((int)*fp + 16);
		if (INKERNEL((int) tf)) {
			eip = tf->tf_eip;
			ebp = tf->tf_ebp;
			db_printf(
		    "--- interrupt, eip = %#r, esp = %#r, ebp = %#r ---\n",
			    eip, esp, ebp);
		}
		break;
	default:
		break;
	}

	*ip = (db_addr_t) eip;
	*fp = (struct i386_frame *) ebp;
#endif
}

#ifdef MCLX
void
x86_back_trace_cmd(struct bt_info *bt)
#else
ulong
db_stack_trace_cmd(addr, have_addr, count, modif, task, flags)
	db_expr_t addr;
	boolean_t have_addr;
	db_expr_t count;
	char *modif;
	ulong task;
	ulong flags;
#endif  /* MCLX */
{
	struct i386_frame *frame;
	int *argp;
	db_addr_t callpc;
	boolean_t first;
#ifdef MCLX
	db_expr_t addr;
        boolean_t have_addr;
        db_expr_t count;
        char *modif;
	db_addr_t last_callpc;
	ulong lastframe;
	physaddr_t phys;
	int frame_number;
	int forced;
	struct eframe eframe, *ep;
	char dbuf[BUFSIZE];

	if (!(bt->flags & BT_USER_SPACE) && 
	    (!bt->stkptr || !accessible(bt->stkptr))) {
		error(INFO, "cannot determine starting stack pointer\n");
		if (KVMDUMP_DUMPFILE())
			kvmdump_display_regs(bt->tc->processor, fp);
		else if (ELF_NOTES_VALID() && DISKDUMP_DUMPFILE())
			diskdump_display_regs(bt->tc->processor, fp);
		else if (SADUMP_DUMPFILE())
			sadump_display_regs(bt->tc->processor, fp);
		return;
	}

	if (bt->flags & BT_USER_SPACE) {
		if (KVMDUMP_DUMPFILE())
			kvmdump_display_regs(bt->tc->processor, fp);
		else if (ELF_NOTES_VALID() && DISKDUMP_DUMPFILE())
			diskdump_display_regs(bt->tc->processor, fp);
		else if (SADUMP_DUMPFILE())
			sadump_display_regs(bt->tc->processor, fp);
		fprintf(fp, " #0 [user space]\n");
		return;
	} else if ((bt->flags & BT_KERNEL_SPACE)) {
		if (KVMDUMP_DUMPFILE())
			kvmdump_display_regs(bt->tc->processor, fp);
		else if (ELF_NOTES_VALID() && DISKDUMP_DUMPFILE())
			diskdump_display_regs(bt->tc->processor, fp);
		else if (SADUMP_DUMPFILE())
			sadump_display_regs(bt->tc->processor, fp);
	}

	addr = bt->stkptr;
	have_addr = TRUE;
	count = 50;
	modif = (char *)bt->instptr;
        mach_debug = bt->debug;

        if ((machdep->flags & OMIT_FRAME_PTR) || 
	    bt->debug || 
	    (bt->flags & BT_FRAMESIZE_DEBUG) ||
	    !(bt->flags & BT_OLD_BACK_TRACE)) {
		bt->flags &= ~BT_OLD_BACK_TRACE;
                lkcd_x86_back_trace(bt, 0, fp);
                return;
        }

        if (mach_CRASHDEBUG(2)) {
        	fprintf(fp, "--> stkptr: %lx instptr: %lx (%s)\n",
			bt->stkptr, bt->instptr, closest_symbol(bt->instptr));
	}
#endif

	if (count == -1)
		count = 65535;

	if (!have_addr) {
#ifndef MCLX
		frame = (struct i386_frame *)ddb_regs.tf_ebp;
		if (frame == NULL)
			frame = (struct i386_frame *)(ddb_regs.tf_esp - 4);
		callpc = (db_addr_t)ddb_regs.tf_eip;
#endif
	} else {
		frame = (struct i386_frame *)addr;
		lastframe = (ulong)frame;
		ep = &eframe;
		BZERO(ep, sizeof(struct eframe));
		ep->eframe_found = FALSE;

		callpc = (db_addr_t)db_get_value((int)&frame->f_retaddr, 4, 
			FALSE, bt);
		if (modif) {
			frame_number = 0;
			forced = TRUE;
			callpc = (db_addr_t)modif;
		}
		else {
			frame_number = 1;
			forced = FALSE;
			if (!is_kernel_text(callpc))
				error(INFO, 
				   "callpc from stack is not a text address\n");
		}
	}

	first = TRUE;
	while (count--) {
		struct i386_frame *actframe;
		int		narg;
		char *	name;
		db_expr_t	offset;
		db_sym_t	sym;
#define MAXNARG	16
		char	*argnames[MAXNARG], **argnp = NULL;

		sym = db_search_symbol(callpc, DB_STGY_ANY, &offset);
		db_symbol_values(sym, &name, NULL);

		/*
		 * Attempt to determine a (possibly fake) frame that gives
		 * the caller's pc.  It may differ from `frame' if the
		 * current function never sets up a standard frame or hasn't
		 * set one up yet or has just discarded one.  The last two
		 * cases can be guessed fairly reliably for code generated
		 * by gcc.  The first case is too much trouble to handle in
		 * general because the amount of junk on the stack depends
		 * on the pc (the special handling of "calltrap", etc. in
		 * db_nextframe() works because the `next' pc is special).
		 */
		actframe = frame;
		if (first && !have_addr) {
#ifdef MCLX
			error(FATAL, "cannot handle \"!have_addr\" path #2\n");
#else
			int instr;

			instr = db_get_value(callpc, 4, FALSE);
			if ((instr & 0x00ffffff) == 0x00e58955) {
				/* pushl %ebp; movl %esp, %ebp */
				actframe = (struct i386_frame *)
					   (ddb_regs.tf_esp - 4);
			} else if ((instr & 0x0000ffff) == 0x0000e589) {
				/* movl %esp, %ebp */
				actframe = (struct i386_frame *)
					   ddb_regs.tf_esp;
				if (ddb_regs.tf_ebp == 0) {
					/* Fake the caller's frame better. */
					frame = actframe;
				}
			} else if ((instr & 0x000000ff) == 0x000000c3) {
				/* ret */
				actframe = (struct i386_frame *)
					   (ddb_regs.tf_esp - 4);
			} else if (offset == 0) {
				/* Probably a symbol in assembler code. */
				actframe = (struct i386_frame *)
					   (ddb_regs.tf_esp - 4);
			}
#endif
		}
		first = FALSE;

		argp = &actframe->f_arg0;
		narg = MAXNARG;
		if (sym != NULL && db_sym_numargs(sym, &narg, argnames)) {
			argnp = argnames;
		} else {
			narg = db_numargs(frame, bt);
		}

#ifdef MCLX
		if (is_kernel_text(callpc) || IS_MODULE_VADDR(callpc)) {
                        if (mach_CRASHDEBUG(2))
                                fprintf(fp, 
				    "--> (1) lastframe: %lx => frame: %lx\n",
                                        lastframe, (ulong)frame);

			db_print_stack_entry(name, narg, argnp, argp, callpc, 
				bt, ep, frame_number++, frame);

			if (STREQ(closest_symbol(callpc), "start_secondary"))
				break;

			if (BT_REFERENCE_FOUND(bt))
				return;

			if ((ulong)frame < lastframe) {
				break;
			}
			if (INSTACK(frame, bt) && 
			    ((ulong)frame > lastframe))
				lastframe = (ulong)frame;

		} else {
			if (!(forced && frame_number == 1)) {
				if (is_kernel_data(callpc)) {
                        		if (mach_CRASHDEBUG(2))
                                		fprintf(fp, 
					 "--> break(1): callpc %lx is data?\n",
                                        		callpc);
					if (!is_rodata_text(callpc))
						break;
				}

                                if (mach_CRASHDEBUG(2))
                                        fprintf(fp,
                                       "--> (2) lastframe: %lx => frame: %lx\n",
                                                lastframe, (ulong)frame);

				db_print_stack_entry(name, narg, argnp, 
					argp, callpc, bt, ep,
					frame_number++, frame); 

				if (BT_REFERENCE_FOUND(bt))
					return;

                        	if ((ulong)frame < lastframe) {
                                	break;
				}
                        	if (INSTACK(frame, bt) &&
				    ((ulong)frame > lastframe))
                                	lastframe = (ulong)frame;
			}
		}
		if (!INSTACK(frame, bt)) {
			if (mach_CRASHDEBUG(2))
				fprintf(fp, 
			    "--> break: !INSTACK(frame: %lx, task: %lx)\n",
					(ulong)frame, bt->task);
			break;
		}
#else
		db_print_stack_entry(name, narg, argnp, argp, callpc);
#endif

		if (actframe != frame) {
			/* `frame' belongs to caller. */
			callpc = (db_addr_t)
			    db_get_value((int)&actframe->f_retaddr, 4, 
				FALSE, bt);
			continue;
		}

                if (ep->eframe_found) 
			frame_number = dump_eframe(ep, frame_number, bt);

		last_callpc = callpc;

skip_frame:
		db_nextframe(&frame, &callpc, ep, bt);

		if (mach_CRASHDEBUG(2)) {
			fprintf(fp, 
			    "--> db_nextframe: frame: %lx  callpc: %lx [%s]\n", 
				(ulong)frame, callpc, 
				value_to_symstr(callpc, dbuf,0));
			if (callpc == last_callpc)
				fprintf(fp, "last callpc == callpc!\n");
		}

		if ((callpc == last_callpc) &&
		     STREQ(closest_symbol(callpc), "smp_stop_cpu_interrupt"))
			goto skip_frame;

		if (INSTACK(frame, bt) && 
		    ((ulong)frame < lastframe))
			if (mach_CRASHDEBUG(2))
				fprintf(fp, 
				     "--> frame pointer reversion?\n");

		if (INKERNEL((int) callpc) && !INKERNEL((int) frame)) {
			sym = db_search_symbol(callpc, DB_STGY_ANY, &offset);
			db_symbol_values(sym, &name, NULL);

                	if (is_kernel_data(callpc)) {
                        	if (mach_CRASHDEBUG(2))
                                	fprintf(fp,
				          "--> break(2): callpc %lx is data?\n",
                                        	callpc);
				if (!is_rodata_text(callpc))
					break;
                	}

                        if (mach_CRASHDEBUG(2))
                               fprintf(fp, 
				    "--> (3) lastframe: %lx => frame: %lx\n",
                                        lastframe, (ulong)frame);

			db_print_stack_entry(name, 0, 0, 0, callpc, bt, ep,
				frame_number++, frame);

			if (BT_REFERENCE_FOUND(bt))
				return;

			if ((ulong)frame < lastframe) {
				if (STREQ(closest_symbol(callpc), "reschedule"))
					x86_user_eframe(bt);
				break;
			}

                        if (INSTACK(frame, bt) &&
			    ((ulong)frame > lastframe))
                        	lastframe = (ulong)frame;
	
			if (mach_CRASHDEBUG(2)) 
				fprintf(fp, 
         "--> break: INKERNEL(callpc: %lx [%s]) && !INKERNEL(frame: %lx)\n",
				    callpc, value_to_symstr(callpc, dbuf, 0), 
				    (ulong)frame);
			break;
		}
		if (!INKERNEL((int) frame)) {
			if (mach_CRASHDEBUG(2))
				fprintf(fp, 
				    "--> break: !INKERNEL(frame: %lx)\n", 
					(ulong)frame);
			break;
		}
	}

	if (mach_CRASHDEBUG(2)) {
		fprintf(fp, "--> returning lastframe: %lx\n", lastframe);
	}

        if (ep->eframe_found) 
       		frame_number = dump_eframe(ep, frame_number, bt);

#ifndef MCLX
	return(lastframe);
#endif
}

/*
 *  The remainder of this file was generated at MCL to segregate 
 *  x86-specific needs.
 */
static int x86_uvtop(struct task_context *, ulong, physaddr_t *, int);
static int x86_kvtop(struct task_context *, ulong, physaddr_t *, int);
static int x86_uvtop_PAE(struct task_context *, ulong, physaddr_t *, int);
static int x86_kvtop_PAE(struct task_context *, ulong, physaddr_t *, int);
static int x86_uvtop_xen_wpt(struct task_context *, ulong, physaddr_t *, int);
static int x86_kvtop_xen_wpt(struct task_context *, ulong, physaddr_t *, int);
static int x86_uvtop_xen_wpt_PAE(struct task_context *, ulong, physaddr_t *, int);
static int x86_kvtop_xen_wpt_PAE(struct task_context *, ulong, physaddr_t *, int);
static int x86_kvtop_remap(ulong, physaddr_t *);
static ulong x86_get_task_pgd(ulong);
static ulong x86_processor_speed(void);
static ulong x86_get_pc(struct bt_info *);
static ulong x86_get_sp(struct bt_info *);
static void x86_get_stack_frame(struct bt_info *, ulong *, ulong *);
static int x86_translate_pte(ulong, void *, ulonglong);
static uint64_t x86_memory_size(void);
static ulong x86_vmalloc_start(void);
static ulong *read_idt_table(int);
static void eframe_init(void);
static int remap_init(void);
#define READ_IDT_INIT     1
#define READ_IDT_RUNTIME  2
static char *extract_idt_function(ulong *, char *, ulong *);
static int x86_is_task_addr(ulong);
static int x86_verify_symbol(const char *, ulong, char);
static int x86_eframe_search(struct bt_info *);
static ulong x86_in_irqstack(ulong);
static int x86_dis_filter(ulong, char *, unsigned int);
static struct line_number_hook x86_line_number_hooks[];
static int x86_is_uvaddr(ulong, struct task_context *);
static void x86_init_kernel_pgd(void);
static ulong xen_m2p_nonPAE(ulong);
static int x86_xendump_p2m_create(struct xendump_data *);
static int x86_pvops_xendump_p2m_create(struct xendump_data *);
static int x86_pvops_xendump_p2m_l2_create(struct xendump_data *);
static int x86_pvops_xendump_p2m_l3_create(struct xendump_data *);
static void x86_debug_dump_page(FILE *, char *, char *);
static int x86_xen_kdump_p2m_create(struct xen_kdump_data *);
static char *x86_xen_kdump_load_page(ulong, char *);
static char *x86_xen_kdump_load_page_PAE(ulong, char *);
static ulong x86_xen_kdump_page_mfn(ulong);
static ulong x86_xen_kdump_page_mfn_PAE(ulong);
static ulong x86_xendump_panic_task(struct xendump_data *);
static void x86_get_xendump_regs(struct xendump_data *, struct bt_info *, ulong *, ulong *);
static char *x86_xendump_load_page(ulong, char *);
static char *x86_xendump_load_page_PAE(ulong, char *);
static int x86_xendump_page_index(ulong);
static int x86_xendump_page_index_PAE(ulong);
static void x86_init_hyper(int);
static ulong x86_get_stackbase_hyper(ulong);
static ulong x86_get_stacktop_hyper(ulong);

int INT_EFRAME_SS = 14;
int INT_EFRAME_ESP = 13;
int INT_EFRAME_EFLAGS = 12;   /* CS lcall7 */
int INT_EFRAME_CS = 11;       /* EIP lcall7 */
int INT_EFRAME_EIP = 10;      /* EFLAGS lcall7 */
int INT_EFRAME_ERR = 9;
int INT_EFRAME_ES = 8;
int INT_EFRAME_DS = 7;
int INT_EFRAME_EAX = 6;
int INT_EFRAME_EBP = 5;
int INT_EFRAME_EDI = 4;
int INT_EFRAME_ESI = 3;
int INT_EFRAME_EDX = 2;
int INT_EFRAME_ECX = 1;
int INT_EFRAME_EBX = 0;
int INT_EFRAME_GS = -1;

#define MAX_USER_EFRAME_SIZE   (17)
#define KERNEL_EFRAME_SIZE (INT_EFRAME_EFLAGS+1)

#define EFRAME_USER   (1)
#define EFRAME_KERNEL (2)

#define DPL_BITS   (0x3)

static int
dump_eframe(struct eframe *ep, int frame_number, struct bt_info *bt)
{
	int i;
	char buf[BUFSIZE], *sp;
	ulong int_eframe[MAX_USER_EFRAME_SIZE];
	int eframe_type, args;
	ulong value, *argp;

	eframe_type = 0;

	if (STACK_OFFSET_TYPE(ep->eframe_addr) > STACKSIZE()) 
		return(frame_number);

	GET_STACK_DATA(ep->eframe_addr, (char *)int_eframe,
		SIZE(pt_regs));	

	if (int_eframe[INT_EFRAME_CS] & DPL_BITS) {
		if (!INSTACK(ep->eframe_addr + 
		    SIZE(pt_regs) - 1, bt))
			return(frame_number);
	/* error(FATAL, "read of exception frame would go beyond stack\n"); */
		eframe_type = EFRAME_USER;
	} else {
                if (!INSTACK(ep->eframe_addr + 
		    (KERNEL_EFRAME_SIZE*sizeof(ulong)) - 1, bt))
			return(frame_number);
        /* error(FATAL, "read of exception frame would go beyond stack\n"); */
                eframe_type = EFRAME_KERNEL;
	}

	x86_dump_eframe_common(bt, int_eframe, (eframe_type == EFRAME_KERNEL));

	if (bt->flags & BT_EFRAME_SEARCH)
		return 0;

	if (eframe_type == EFRAME_USER)
		return(frame_number);

	if (BT_REFERENCE_CHECK(bt)) 
		return(++frame_number);

	/*
	 *  The exception occurred while executing in kernel mode.
	 *  Pull out the EIP from the exception frame and display 
         *  the frame line.  Then figure out whether it's possible to 
	 *  show any arguments.
	 */
	fprintf(fp, "%s#%d [%08lx] %s at %08lx\n",
		frame_number < 10 ?  " " : "",
		frame_number,
		int_eframe[INT_EFRAME_EBP],
		value_to_symstr(int_eframe[INT_EFRAME_EIP], buf, 0),
		int_eframe[INT_EFRAME_EIP]);

	frame_number++;

	if ((sp = closest_symbol(int_eframe[INT_EFRAME_EIP])) == NULL)
		return(frame_number);

	value = symbol_value(sp);
        argp = (ulong *)(int_eframe[INT_EFRAME_EBP] + (sizeof(long)*2));
	args = is_system_call(NULL, value) ? 
		4 : eframe_numargs(int_eframe[INT_EFRAME_EIP], bt);
	
	fprintf(fp, "    (");
	for (i = 0; i < args; i++, argp++) {
		if (INSTACK(argp, bt)) 
			value = GET_STACK_ULONG((ulong)argp);
	        else /* impossible! */ 
        		readmem((ulong)argp, KVADDR, &value,
                		sizeof(ulong), "syscall arg", FAULT_ON_ERROR);
					
		if (i)
			fprintf(fp, ", ");

		if ((sp = value_symbol(value)))
		        fprintf(fp, "%s", sp);
		else if ((bt->flags & BT_SYMBOLIC_ARGS) &&
		        strlen(value_to_symstr(value, buf, 0)))
		       	fprintf(fp, "%s", buf);
		else
		        fprintf(fp, "%lx", value);
	}
	fprintf(fp, ")\n");

	if (bt->flags & BT_LINE_NUMBERS) 
		x86_dump_line_number(int_eframe[INT_EFRAME_EIP]);

	return(frame_number);
}

/*
 *  Dump an exception frame, coming from either source of stack trace code.
 *  (i.e., -fomit-frame-pointer or not)
 */
void
x86_dump_eframe_common(struct bt_info *bt, ulong *int_eframe, int kernel)
{
	struct syment *sp;
	ulong offset;

	if (bt && BT_REFERENCE_CHECK(bt)) {  
		if (!(bt->ref->cmdflags & BT_REF_HEXVAL)) 
			return;

		if ((int_eframe[INT_EFRAME_EAX] == bt->ref->hexval) ||
		    (int_eframe[INT_EFRAME_EBX] == bt->ref->hexval) || 
		    (int_eframe[INT_EFRAME_ECX] == bt->ref->hexval) || 
		    (int_eframe[INT_EFRAME_EDX] == bt->ref->hexval) || 
		    (int_eframe[INT_EFRAME_EBP] == bt->ref->hexval) || 
		    (int_eframe[INT_EFRAME_ESI] == bt->ref->hexval) || 
		    (int_eframe[INT_EFRAME_EDI] == bt->ref->hexval) || 
		    ((short)int_eframe[INT_EFRAME_ES] == 
				(short)bt->ref->hexval) || 
		    ((short)int_eframe[INT_EFRAME_DS] == 
				(short)bt->ref->hexval) || 
		    ((short)int_eframe[INT_EFRAME_CS] ==
                                (short)bt->ref->hexval) ||
		    (int_eframe[INT_EFRAME_EIP] == bt->ref->hexval) || 
		    (int_eframe[INT_EFRAME_ERR] == bt->ref->hexval) || 
		    (int_eframe[INT_EFRAME_EFLAGS] == bt->ref->hexval))
			bt->ref->cmdflags |= BT_REF_FOUND;

		if (!kernel) {
			if ((int_eframe[INT_EFRAME_ESP] == bt->ref->hexval) ||
		            ((short)int_eframe[INT_EFRAME_SS] == 
			    (short)bt->ref->hexval))
				bt->ref->cmdflags |= BT_REF_FOUND;
		}

		return;
	}

	if (kernel) {
		if (bt && (bt->flags & BT_EFRAME_SEARCH)) {
			fprintf(fp, "    [exception EIP: ");
			if ((sp = value_search(int_eframe[INT_EFRAME_EIP], 
			    &offset))) {
				fprintf(fp, "%s", sp->name);
				if (offset)
					fprintf(fp, 
					    (*gdb_output_radix == 16) ? 
					    "+0x%lx" : "+%ld", 
					    offset);
			} else 
				fprintf(fp, 
					"unknown or invalid address");
			fprintf(fp, "]\n");
		}
	    	fprintf(fp, 
  	    "    EAX: %08lx  EBX: %08lx  ECX: %08lx  EDX: %08lx  EBP: %08lx \n",
			int_eframe[INT_EFRAME_EAX],
			int_eframe[INT_EFRAME_EBX],
			int_eframe[INT_EFRAME_ECX],
			int_eframe[INT_EFRAME_EDX],
			int_eframe[INT_EFRAME_EBP]);
	} else
                fprintf(fp, 
		    "    EAX: %08lx  EBX: %08lx  ECX: %08lx  EDX: %08lx \n",
                        int_eframe[INT_EFRAME_EAX],
                        int_eframe[INT_EFRAME_EBX],
                        int_eframe[INT_EFRAME_ECX],
                        int_eframe[INT_EFRAME_EDX]);

        fprintf(fp, 
		"    DS:  %04x      ESI: %08lx  ES:  %04x      EDI: %08lx",
                (short)int_eframe[INT_EFRAME_DS],
                int_eframe[INT_EFRAME_ESI],
                (short)int_eframe[INT_EFRAME_ES],
                int_eframe[INT_EFRAME_EDI]);
	if (kernel && (INT_EFRAME_GS != -1))
		fprintf(fp, "  GS:  %04x", (short)int_eframe[INT_EFRAME_GS]);
	fprintf(fp, "\n");

	if (!kernel) {
		fprintf(fp, "    SS:  %04x      ESP: %08lx  EBP: %08lx",
			(short)int_eframe[INT_EFRAME_SS],
			int_eframe[INT_EFRAME_ESP],
                        int_eframe[INT_EFRAME_EBP]);
		if (INT_EFRAME_GS != -1)
			fprintf(fp, "  GS:  %04x", (short)int_eframe[INT_EFRAME_GS]);
		fprintf(fp, "\n");
	}

	fprintf(fp, 
	    "    CS:  %04x      EIP: %08lx  ERR: %08lx  EFLAGS: %08lx \n",
                (short)int_eframe[INT_EFRAME_CS],
                int_eframe[INT_EFRAME_EIP],
                int_eframe[INT_EFRAME_ERR],
                int_eframe[INT_EFRAME_EFLAGS]);
}

/*
 *  Catch a few functions that show up as rodata but really are
 *  functions.
 */
int
is_rodata_text(ulong callpc)
{
	struct syment *sp;

	if (!is_rodata(callpc, &sp))
		return FALSE;

	if (strstr(sp->name, "interrupt") || strstr(sp->name, "call_"))
		return TRUE;

	return FALSE;
}


static int 
check_for_eframe(char *name, struct bt_info *bt)
{
        int i;
        ulong *ip;
        char buf[BUFSIZE];

        ip = read_idt_table(READ_IDT_RUNTIME);

        for (i = 0; i < 256; i++, ip += 2) {
		if (STREQ(name, extract_idt_function(ip, buf, NULL))) 
			return IDT_DIRECT_ENTRY;
	}

	if (STREQ(name, "ret_from_intr") || 
	    STREQ(name, "call_call_function_interrupt") ||
	    STREQ(name, "call_reschedule_interrupt") ||
	    STREQ(name, "call_invalidate_interrupt"))
		return RET_FROM_INTR;

        if (STREQ(name, "error_code"))
        	return IDT_JMP_ERROR_CODE;

	if (STREQ(name, "signal_return"))
		return SIGNAL_RETURN;

	return FALSE;
}

/*
 *  Return the syment of the function that did the "jmp error_code".
 */
struct syment * 
x86_jmp_error_code(ulong callpc)
{
	struct syment *sp;

	if (!(sp = value_search(callpc, NULL)) || !STRNEQ(sp->name, "do_"))
		return NULL;

	return (symbol_search(sp->name + strlen("do_")));
}

static const char *hook_files[] = {
	"arch/i386/kernel/entry.S",
	"arch/i386/kernel/head.S",
	"arch/i386/kernel/semaphore.c"
};

#define ENTRY_S      ((char **)&hook_files[0])
#define HEAD_S       ((char **)&hook_files[1])
#define SEMAPHORE_C  ((char **)&hook_files[2])

static struct line_number_hook x86_line_number_hooks[] = {
	{"lcall7", ENTRY_S},                   
	{"lcall27", ENTRY_S},                       
	{"ret_from_fork", ENTRY_S},                       
	{"system_call", ENTRY_S},                       
	{"ret_from_sys_call", ENTRY_S},                       
	{"ret_from_intr", ENTRY_S},                       
	{"divide_error", ENTRY_S},                       
	{"coprocessor_error", ENTRY_S},                       
	{"simd_coprocessor_error", ENTRY_S},                       
	{"device_not_available", ENTRY_S},                       
	{"debug", ENTRY_S},                       
	{"nmi", ENTRY_S},                       
	{"int3", ENTRY_S},                       
	{"overflow", ENTRY_S},                       
	{"bounds", ENTRY_S},                       
	{"invalid_op", ENTRY_S},                       
	{"coprocessor_segment_overrun", ENTRY_S},                       
	{"double_fault", ENTRY_S},                       
	{"invalid_TSS", ENTRY_S},                       
	{"segment_not_present", ENTRY_S},                       
	{"stack_segment", ENTRY_S},                       
	{"general_protection", ENTRY_S},                       
	{"alignment_check", ENTRY_S},                       
	{"page_fault", ENTRY_S},                       
	{"machine_check", ENTRY_S},                       
	{"spurious_interrupt_bug", ENTRY_S},                       
	{"v86_signal_return", ENTRY_S},                       
	{"tracesys", ENTRY_S},                       
	{"tracesys_exit", ENTRY_S},                       
	{"badsys", ENTRY_S},                       
	{"ret_from_exception", ENTRY_S},                       
	{"reschedule", ENTRY_S},                       
	{"error_code", ENTRY_S},                       
	{"device_not_available_emulate", ENTRY_S},                       
	{"restore_all", ENTRY_S},                       
	{"signal_return", ENTRY_S},                       

        {"L6", HEAD_S},                       
	{"_text", HEAD_S},                       
        {"startup_32", HEAD_S},                       
        {"checkCPUtype", HEAD_S},                       
        {"is486", HEAD_S},                       
        {"is386", HEAD_S},                       
        {"ready", HEAD_S},                       
        {"check_x87", HEAD_S},                       
        {"setup_idt", HEAD_S},                       
        {"rp_sidt", HEAD_S},                       
        {"stack_start", HEAD_S},                       
        {"int_msg", HEAD_S},                       
        {"ignore_int", HEAD_S},                       
        {"idt_descr", HEAD_S},                       
        {"idt", HEAD_S},                       
        {"gdt_descr", HEAD_S},                       
        {"gdt", HEAD_S},                       
        {"swapper_pg_dir", HEAD_S},                       
        {"pg0", HEAD_S},                       
        {"pg1", HEAD_S},                       
        {"empty_zero_page", HEAD_S},                       

	{"__down_failed", SEMAPHORE_C},                 
	{"__down_failed_interruptible", SEMAPHORE_C},                 
	{"__down_failed_trylock", SEMAPHORE_C},                 
	{"__up_wakeup", SEMAPHORE_C},                 
	{"__write_lock_failed", SEMAPHORE_C},                 
	{"__read_lock_failed", SEMAPHORE_C},                 

	{NULL, NULL}    /* list must be NULL-terminated */
};


static void
x86_dump_line_number(ulong callpc)
{
	int retries;
	char buf[BUFSIZE], *p;

        retries = 0;
try_closest:
	get_line_number(callpc, buf, FALSE);

        if (strlen(buf)) {
                if (retries) {
                        p = strstr(buf, ": ");
			if (p)
				*p = NULLCHAR;
                }
                fprintf(fp, "    %s\n", buf);
        } else {
                if (retries) {
                        fprintf(fp, GDB_PATCHED() ? 
			  "" : "    (cannot determine file and line number)\n");
                } else {
                        retries++;
                        callpc = closest_symbol_value(callpc);
                        goto try_closest;
                }
        }
}

/*
 *   Look for likely exception frames in a stack.
 */

struct x86_pt_regs {
	ulong reg_value[MAX_USER_EFRAME_SIZE];
};

/*
 * Searches from addr within the stackframe defined by bt
 * for the next set of bytes that matches an exception frame pattern.
 * Returns either the address of the frame or 0.
 */
static ulong
x86_next_eframe(ulong addr, struct bt_info *bt)
{
	ulong *first, *last;
	struct x86_pt_regs *pt;
	ulong *stack;
        ulong rv;

	stack = (ulong *)bt->stackbuf;

        if (!INSTACK(addr, bt)) {
                return(0);
        }

        rv = 0;
	first = stack + ((addr - bt->stackbase) / sizeof(ulong));
	last = stack +
	   (((bt->stacktop - bt->stackbase) - SIZE(pt_regs)) / sizeof(ulong));

        for ( ; first <= last; first++) {
                pt = (struct x86_pt_regs *)first;

		/* check for kernel exception frame */

		if (((short)pt->reg_value[INT_EFRAME_CS] == 0x10) &&
		    ((short)pt->reg_value[INT_EFRAME_DS] == 0x18) &&
                    ((short)pt->reg_value[INT_EFRAME_ES] == 0x18) &&
		    IS_KVADDR(pt->reg_value[INT_EFRAME_EIP])) {
			if (!(machdep->flags & OMIT_FRAME_PTR) && 
			    !INSTACK(pt->reg_value[INT_EFRAME_EBP], bt)) 
				continue;
                        rv = bt->stackbase + sizeof(ulong) * (first - stack);
                        break;
		}

                if (((short)pt->reg_value[INT_EFRAME_CS] == 0x60) &&
                    ((short)pt->reg_value[INT_EFRAME_DS] == 0x68) &&
                    ((short)pt->reg_value[INT_EFRAME_ES] == 0x68) &&
                    IS_KVADDR(pt->reg_value[INT_EFRAME_EIP])) {
			if (!(machdep->flags & OMIT_FRAME_PTR) && 
			    !INSTACK(pt->reg_value[INT_EFRAME_EBP], bt)) 
				continue;
                        rv = bt->stackbase + sizeof(ulong) * (first - stack);
                        break;
                }

                if (((short)pt->reg_value[INT_EFRAME_CS] == 0x60) &&
                    ((short)pt->reg_value[INT_EFRAME_DS] == 0x7b) &&
                    ((short)pt->reg_value[INT_EFRAME_ES] == 0x7b) &&
                    IS_KVADDR(pt->reg_value[INT_EFRAME_EIP])) {
                        if (!(machdep->flags & OMIT_FRAME_PTR) &&
                            !INSTACK(pt->reg_value[INT_EFRAME_EBP], bt))
                                continue;
                        rv = bt->stackbase + sizeof(ulong) * (first - stack);
                        break;
                }

                if (XEN() && ((short)pt->reg_value[INT_EFRAME_CS] == 0x61) &&
                    ((short)pt->reg_value[INT_EFRAME_DS] == 0x7b) &&
                    ((short)pt->reg_value[INT_EFRAME_ES] == 0x7b) &&
                    IS_KVADDR(pt->reg_value[INT_EFRAME_EIP])) {
                        if (!(machdep->flags & OMIT_FRAME_PTR) &&
                            !INSTACK(pt->reg_value[INT_EFRAME_EBP], bt))
                                continue;
                        rv = bt->stackbase + sizeof(ulong) * (first - stack);
                        break;
                }

		/* check for user exception frame */

		if (((short)pt->reg_value[INT_EFRAME_CS] == 0x23) &&
		    ((short)pt->reg_value[INT_EFRAME_DS] == 0x2b) &&
		    ((short)pt->reg_value[INT_EFRAME_ES] == 0x2b) &&
		    ((short)pt->reg_value[INT_EFRAME_SS] == 0x2b) &&
		    IS_UVADDR(pt->reg_value[INT_EFRAME_EIP], bt->tc) &&
		    IS_UVADDR(pt->reg_value[INT_EFRAME_ESP], bt->tc)) {
                        rv = bt->stackbase + sizeof(ulong) * (first - stack);
                        break;
		}

                if (((short)pt->reg_value[INT_EFRAME_CS] == 0x73) &&
                    ((short)pt->reg_value[INT_EFRAME_DS] == 0x7b) &&
                    ((short)pt->reg_value[INT_EFRAME_ES] == 0x7b) &&
                    ((short)pt->reg_value[INT_EFRAME_SS] == 0x7b) &&
                    IS_UVADDR(pt->reg_value[INT_EFRAME_EIP], bt->tc) &&
                    IS_UVADDR(pt->reg_value[INT_EFRAME_ESP], bt->tc)) {
                        rv = bt->stackbase + sizeof(ulong) * (first - stack);
                        break;
                }

		/*
		 *  2.6 kernels using sysenter_entry instead of system_call
		 *  have a funky trampoline EIP address.
		 */
                if (((short)pt->reg_value[INT_EFRAME_CS] == 0x73) &&
                    ((short)pt->reg_value[INT_EFRAME_DS] == 0x7b) &&
                    ((short)pt->reg_value[INT_EFRAME_ES] == 0x7b) &&
                    ((short)pt->reg_value[INT_EFRAME_SS] == 0x7b) &&
                    (pt->reg_value[INT_EFRAME_EFLAGS] == 0x246) &&
                    IS_UVADDR(pt->reg_value[INT_EFRAME_ESP], bt->tc)) {
                        rv = bt->stackbase + sizeof(ulong) * (first - stack);
                        break;
                }
        }
        return(rv);
}

static int 
x86_eframe_search(struct bt_info *bt_in)
{
	ulong addr;
	struct x86_pt_regs *pt;
	struct eframe eframe, *ep;
	struct bt_info bt_local, *bt;
	ulong flagsave;
	ulong irqstack;
        short cs;
        char *mode, *ibuf;
	int c, cnt;

	bt = bt_in;
	ibuf = NULL;
	cnt = 0;

	if (bt->flags & BT_EFRAME_SEARCH2) {
		if (!(tt->flags & IRQSTACKS)) {
			error(FATAL, "this kernel does not have IRQ stacks\n");
			return 0;
		}

		BCOPY(bt_in, &bt_local, sizeof(struct bt_info));
		bt = &bt_local;
		bt->flags &= ~(ulonglong)BT_EFRAME_SEARCH2;

        	for (c = 0; c < NR_CPUS; c++) {
                	if (tt->hardirq_ctx[c]) {
				if ((bt->flags & BT_CPUMASK) && 
				    !(NUM_IN_BITMAP(bt->cpumask, c)))
					continue;
				bt->hp->esp = tt->hardirq_ctx[c];
				fprintf(fp, "CPU %d HARD IRQ STACK:\n", c);
				if ((cnt = x86_eframe_search(bt)))
					fprintf(fp, "\n");
				else
					fprintf(fp, "(none found)\n\n");
			}
		}
        	for (c = 0; c < NR_CPUS; c++) {
			if (tt->softirq_ctx[c]) {
				if ((bt->flags & BT_CPUMASK) && 
				    !(NUM_IN_BITMAP(bt->cpumask, c)))
					continue;
				bt->hp->esp = tt->softirq_ctx[c];
				fprintf(fp, "CPU %d SOFT IRQ STACK:\n", c);
				if ((cnt = x86_eframe_search(bt)))
					fprintf(fp, "\n");
				else
					fprintf(fp, "(none found)\n\n");
			}
		}

		return 0;
	}

	if (bt->hp && bt->hp->esp) {
		BCOPY(bt_in, &bt_local, sizeof(struct bt_info));
		bt = &bt_local;
		addr = bt->hp->esp;
		if ((irqstack = x86_in_irqstack(addr))) {
                	bt->stackbase = irqstack;
                	bt->stacktop = irqstack + SIZE(irq_ctx);
			if (SIZE(irq_ctx) > STACKSIZE()) {
				ibuf = (char *)GETBUF(SIZE(irq_ctx));
				bt->stackbuf = ibuf;
			}
			alter_stackbuf(bt);
		} else if (!INSTACK(addr, bt))
                        error(FATAL,
                            "unrecognized stack address for this task: %lx\n",
                                bt->hp->esp);
	} else if (tt->flags & THREAD_INFO)
        	addr = bt->stackbase + 
			roundup(SIZE(thread_info), sizeof(ulong));
	else
        	addr = bt->stackbase + 
			roundup(SIZE(task_struct), sizeof(ulong));

	ep = &eframe;
	BZERO(ep, sizeof(struct eframe));

        while ((addr = x86_next_eframe(addr, bt)) != 0) {
		cnt++;
		if (bt->flags & BT_EFRAME_COUNT) {
			addr += 4;
			continue;
		}
                pt = (struct x86_pt_regs *) (bt->stackbuf
                    + (addr - bt->stackbase));
                ep->eframe_addr = addr;
                cs = pt->reg_value[INT_EFRAME_CS];
                if ((cs == 0x23) || (cs == 0x73)) {
                        mode = "USER-MODE";
                } else if ((cs == 0x10) || (cs == 0x60)) {
                        mode = "KERNEL-MODE";
		} else if (XEN() && (cs == 0x61)) {
                        mode = "KERNEL-MODE";
                } else {
                        mode = "UNKNOWN-MODE";
                }
                fprintf(fp, "%s  %s EXCEPTION FRAME AT %lx:\n",
	            bt->flags & BT_EFRAME_SEARCH ? "\n" : "",
		    mode, ep->eframe_addr);
		flagsave = bt->flags;
		bt->flags |= BT_EFRAME_SEARCH;
                dump_eframe(ep, 0, bt);
		bt->flags = flagsave;
                addr += 4;
        }

	if (ibuf)
		FREEBUF(ibuf);

	return cnt;
}

static ulong 
x86_in_irqstack(ulong addr)
{
	int c;

	if (!(tt->flags & IRQSTACKS))
		return 0;
	
	for (c = 0; c < NR_CPUS; c++) {
                if (tt->hardirq_ctx[c]) {
			if ((addr >= tt->hardirq_ctx[c]) &&
			    (addr < (tt->hardirq_ctx[c] + SIZE(irq_ctx))))
				return(tt->hardirq_ctx[c]);
	
                }
                if (tt->softirq_ctx[c]) {
                       if ((addr >= tt->softirq_ctx[c]) &&
                           (addr < (tt->softirq_ctx[c] + SIZE(irq_ctx))))
                                return(tt->softirq_ctx[c]);
		}
	}

	return 0;
}

/*
 *  Dump the kernel-entry user-mode exception frame.
 */
static void
x86_user_eframe(struct bt_info *bt)
{
        struct eframe eframe, *ep;
	struct x86_pt_regs x86_pt_regs, *pt;
	ulong pt_regs_addr;

	pt_regs_addr = USER_EFRAME_ADDR(bt->task);
	readmem(pt_regs_addr, KVADDR, &x86_pt_regs, sizeof(struct x86_pt_regs),
		"x86 pt_regs", FAULT_ON_ERROR);

        pt = &x86_pt_regs;
        if (((short)pt->reg_value[INT_EFRAME_CS] == 0x23) &&
            ((short)pt->reg_value[INT_EFRAME_DS] == 0x2b) &&
            ((short)pt->reg_value[INT_EFRAME_ES] == 0x2b) &&
            ((short)pt->reg_value[INT_EFRAME_SS] == 0x2b) &&
            IS_UVADDR(pt->reg_value[INT_EFRAME_EIP], bt->tc) &&
            IS_UVADDR(pt->reg_value[INT_EFRAME_ESP], bt->tc) &&
            IS_UVADDR(pt->reg_value[INT_EFRAME_EBP], bt->tc)) {
                ep = &eframe;
                BZERO(ep, sizeof(struct eframe));
                ep->eframe_addr = pt_regs_addr;
		bt->flags |= BT_EFRAME_SEARCH;
                dump_eframe(ep, 0, bt);
		bt->flags &= ~(ulonglong)BT_EFRAME_SEARCH;
	}

}

/*
 *  Do all necessary machine-specific setup here.  This is called three times,
 *  during symbol table initialization, and before and after GDB has been 
 *  initialized.
 */

struct machine_specific x86_machine_specific = { 0 };

static int PGDIR_SHIFT;
static int PTRS_PER_PTE;
static int PTRS_PER_PGD;

void
x86_init(int when)
{
	struct syment *sp, *spn;

	if (XEN_HYPER_MODE()) {
		x86_init_hyper(when);
		return;
	}

	switch (when)
	{
	case SETUP_ENV:
		machdep->process_elf_notes = x86_process_elf_notes;
		break;
	case PRE_SYMTAB:
		machdep->verify_symbol = x86_verify_symbol;
                if (pc->flags & KERNEL_DEBUG_QUERY)
                        return;
                machdep->pagesize = memory_page_size();
                machdep->pageshift = ffs(machdep->pagesize) - 1;
                machdep->pageoffset = machdep->pagesize - 1;
                machdep->pagemask = ~((ulonglong)machdep->pageoffset);
		machdep->stacksize = machdep->pagesize * 2;
        	if ((machdep->pgd = (char *)malloc(PAGESIZE())) == NULL)
                	error(FATAL, "cannot malloc pgd space.");
                if ((machdep->pmd = (char *)malloc(PAGESIZE())) == NULL)
                        error(FATAL, "cannot malloc pmd space.");
        	if ((machdep->ptbl = (char *)malloc(PAGESIZE())) == NULL)
                	error(FATAL, "cannot malloc ptbl space.");
		machdep->last_pgd_read = 0;
		machdep->last_pmd_read = 0;
		machdep->last_ptbl_read = 0;
		machdep->machspec = &x86_machine_specific;
		machdep->verify_paddr = generic_verify_paddr;
		x86_parse_cmdline_args();
		break;

	case PRE_GDB:
		if (symbol_exists("pae_pgd_cachep") ||
		    ((sp = symbol_search("pkmap_count")) && 
		    (spn = next_symbol(NULL, sp)) &&
		    (((spn->value - sp->value)/sizeof(int)) == 512))) {
                	machdep->flags |= PAE;
			PGDIR_SHIFT = PGDIR_SHIFT_3LEVEL;
			PTRS_PER_PTE = PTRS_PER_PTE_3LEVEL;
			PTRS_PER_PGD = PTRS_PER_PGD_3LEVEL;
                        machdep->uvtop = x86_uvtop_PAE;
                        machdep->kvtop = x86_kvtop_PAE;
		} else {
			PGDIR_SHIFT = PGDIR_SHIFT_2LEVEL;
                        PTRS_PER_PTE = PTRS_PER_PTE_2LEVEL;
                        PTRS_PER_PGD = PTRS_PER_PGD_2LEVEL;
                	machdep->uvtop = x86_uvtop;
                	machdep->kvtop = x86_kvtop;
			free(machdep->pmd);
			machdep->pmd = machdep->pgd;   
		}
		machdep->ptrs_per_pgd = PTRS_PER_PGD;
		if (!machdep->kvbase) {
			if (kernel_symbol_exists("module_kaslr_mutex"))
				machdep->kvbase = 0xc0000000;
			else
				machdep->kvbase = symbol_value("_stext") & ~KVBASE_MASK;  
		}
		if (machdep->kvbase & 0x80000000) 
                	machdep->is_uvaddr = generic_is_uvaddr;
		else {
			vt->flags |= COMMON_VADDR;
                	machdep->is_uvaddr = x86_is_uvaddr;
		}
		machdep->identity_map_base = machdep->kvbase;
                machdep->is_kvaddr = generic_is_kvaddr;
	        machdep->eframe_search = x86_eframe_search;
	        machdep->back_trace = x86_back_trace_cmd;
	        machdep->processor_speed = x86_processor_speed;
	        machdep->get_task_pgd = x86_get_task_pgd;
		machdep->dump_irq = generic_dump_irq;
		machdep->get_irq_affinity = generic_get_irq_affinity;
		machdep->show_interrupts = generic_show_interrupts;
		machdep->get_stack_frame = x86_get_stack_frame;
		machdep->get_stackbase = generic_get_stackbase;
		machdep->get_stacktop = generic_get_stacktop;
		machdep->translate_pte = x86_translate_pte;
		machdep->memory_size = x86_memory_size;
		machdep->vmalloc_start = x86_vmalloc_start;
		machdep->is_task_addr = x86_is_task_addr;
		machdep->dis_filter = x86_dis_filter;
		machdep->cmd_mach = x86_cmd_mach;
		machdep->get_smp_cpus = x86_get_smp_cpus;
		machdep->flags |= FRAMESIZE_DEBUG;
		machdep->value_to_symbol = generic_machdep_value_to_symbol;
		machdep->init_kernel_pgd = x86_init_kernel_pgd;
		machdep->xendump_p2m_create = x86_xendump_p2m_create;
		machdep->xen_kdump_p2m_create = x86_xen_kdump_p2m_create;
		machdep->xendump_panic_task = x86_xendump_panic_task;
		machdep->get_xendump_regs = x86_get_xendump_regs;
		machdep->clear_machdep_cache = x86_clear_machdep_cache;
		break;

	case POST_GDB:
		if (x86_omit_frame_pointer())
			machdep->flags |= OMIT_FRAME_PTR;
		STRUCT_SIZE_INIT(user_regs_struct, "user_regs_struct");
		if (MEMBER_EXISTS("user_regs_struct", "ebp"))
			MEMBER_OFFSET_INIT(user_regs_struct_ebp,
				"user_regs_struct", "ebp");
		else
			MEMBER_OFFSET_INIT(user_regs_struct_ebp,
				"user_regs_struct", "bp");
		if (MEMBER_EXISTS("user_regs_struct", "esp"))
			MEMBER_OFFSET_INIT(user_regs_struct_esp,
				"user_regs_struct", "esp");
		else
			MEMBER_OFFSET_INIT(user_regs_struct_esp,
				"user_regs_struct", "sp");
		if (MEMBER_EXISTS("user_regs_struct", "eip"))
			MEMBER_OFFSET_INIT(user_regs_struct_eip,
				"user_regs_struct", "eip");
		else
			MEMBER_OFFSET_INIT(user_regs_struct_eip,
				"user_regs_struct", "ip");
		if (MEMBER_EXISTS("user_regs_struct", "eax"))
			MEMBER_OFFSET_INIT(user_regs_struct_eax,
				"user_regs_struct", "eax");
		else
			MEMBER_OFFSET_INIT(user_regs_struct_eax,
				"user_regs_struct", "ax");
		if (MEMBER_EXISTS("user_regs_struct", "ebx"))
			MEMBER_OFFSET_INIT(user_regs_struct_ebx,
				"user_regs_struct", "ebx");
		else
			MEMBER_OFFSET_INIT(user_regs_struct_ebx,
				"user_regs_struct", "bx");
		if (MEMBER_EXISTS("user_regs_struct", "ecx"))
			MEMBER_OFFSET_INIT(user_regs_struct_ecx,
				"user_regs_struct", "ecx");
		else
			MEMBER_OFFSET_INIT(user_regs_struct_ecx,
				"user_regs_struct", "cx");
		if (MEMBER_EXISTS("user_regs_struct", "edx"))
			MEMBER_OFFSET_INIT(user_regs_struct_edx,
				"user_regs_struct", "edx");
		else
			MEMBER_OFFSET_INIT(user_regs_struct_edx,
				"user_regs_struct", "dx");
		if (MEMBER_EXISTS("user_regs_struct", "esi"))
			MEMBER_OFFSET_INIT(user_regs_struct_esi,
				"user_regs_struct", "esi");
		else
			MEMBER_OFFSET_INIT(user_regs_struct_esi,
				"user_regs_struct", "si");
		if (MEMBER_EXISTS("user_regs_struct", "edi"))
			MEMBER_OFFSET_INIT(user_regs_struct_edi,
				"user_regs_struct", "edi");
		else
			MEMBER_OFFSET_INIT(user_regs_struct_edi,
				"user_regs_struct", "di");
		if (MEMBER_EXISTS("user_regs_struct", "eflags"))
			MEMBER_OFFSET_INIT(user_regs_struct_eflags,
				"user_regs_struct", "eflags");
		else
			MEMBER_OFFSET_INIT(user_regs_struct_eflags,
				"user_regs_struct", "flags");
		MEMBER_OFFSET_INIT(user_regs_struct_cs,
			"user_regs_struct", "cs");
		MEMBER_OFFSET_INIT(user_regs_struct_ds,
			"user_regs_struct", "ds");
		MEMBER_OFFSET_INIT(user_regs_struct_es,
			"user_regs_struct", "es");
		MEMBER_OFFSET_INIT(user_regs_struct_fs,
			"user_regs_struct", "fs");
		MEMBER_OFFSET_INIT(user_regs_struct_gs,
			"user_regs_struct", "gs");
		MEMBER_OFFSET_INIT(user_regs_struct_ss,
			"user_regs_struct", "ss");
		if (!VALID_STRUCT(user_regs_struct)) {
			/*  Use this hardwired version -- sometimes the 
			 *  debuginfo doesn't pick this up even though
			 *  it exists in the kernel; it shouldn't change.
			 */
			struct x86_user_regs_struct {
			        long ebx, ecx, edx, esi, edi, ebp, eax;
			        unsigned short ds, __ds, es, __es;
			        unsigned short fs, __fs, gs, __gs;
			        long orig_eax, eip;
			        unsigned short cs, __cs;
			        long eflags, esp;
			        unsigned short ss, __ss;
			};
			ASSIGN_SIZE(user_regs_struct) = 
				sizeof(struct x86_user_regs_struct);
			ASSIGN_OFFSET(user_regs_struct_ebp) =
				offsetof(struct x86_user_regs_struct, ebp);
			ASSIGN_OFFSET(user_regs_struct_esp) =
				offsetof(struct x86_user_regs_struct, esp);
			ASSIGN_OFFSET(user_regs_struct_eip) =
				offsetof(struct x86_user_regs_struct, eip);
			ASSIGN_OFFSET(user_regs_struct_eax) =
				offsetof(struct x86_user_regs_struct, eax);
			ASSIGN_OFFSET(user_regs_struct_ebx) =
				offsetof(struct x86_user_regs_struct, ebx);
			ASSIGN_OFFSET(user_regs_struct_ecx) =
				offsetof(struct x86_user_regs_struct, ecx);
			ASSIGN_OFFSET(user_regs_struct_edx) =
				offsetof(struct x86_user_regs_struct, edx);
			ASSIGN_OFFSET(user_regs_struct_esi) =
				offsetof(struct x86_user_regs_struct, esi);
			ASSIGN_OFFSET(user_regs_struct_edi) =
				offsetof(struct x86_user_regs_struct, edi);
			ASSIGN_OFFSET(user_regs_struct_eflags) =
				offsetof(struct x86_user_regs_struct, eflags);
			ASSIGN_OFFSET(user_regs_struct_cs) =
				offsetof(struct x86_user_regs_struct, cs);
			ASSIGN_OFFSET(user_regs_struct_ds) =
				offsetof(struct x86_user_regs_struct, ds);
			ASSIGN_OFFSET(user_regs_struct_es) =
				offsetof(struct x86_user_regs_struct, es);
			ASSIGN_OFFSET(user_regs_struct_fs) =
				offsetof(struct x86_user_regs_struct, fs);
			ASSIGN_OFFSET(user_regs_struct_gs) =
				offsetof(struct x86_user_regs_struct, gs);
			ASSIGN_OFFSET(user_regs_struct_ss) =
				offsetof(struct x86_user_regs_struct, ss);
		}
		MEMBER_OFFSET_INIT(thread_struct_cr3, "thread_struct", "cr3");
		STRUCT_SIZE_INIT(cpuinfo_x86, "cpuinfo_x86");
		STRUCT_SIZE_INIT(irq_ctx, "irq_ctx");
		if (STRUCT_EXISTS("e820map")) {
			STRUCT_SIZE_INIT(e820map, "e820map");
			MEMBER_OFFSET_INIT(e820map_nr_map, "e820map", "nr_map");
		} else {
			STRUCT_SIZE_INIT(e820map, "e820_table");
			MEMBER_OFFSET_INIT(e820map_nr_map, "e820_table", "nr_entries");
		}
		if (STRUCT_EXISTS("e820entry")) {
			STRUCT_SIZE_INIT(e820entry, "e820entry");
			MEMBER_OFFSET_INIT(e820entry_addr, "e820entry", "addr");
			MEMBER_OFFSET_INIT(e820entry_size, "e820entry", "size");
			MEMBER_OFFSET_INIT(e820entry_type, "e820entry", "type");
		} else {
			STRUCT_SIZE_INIT(e820entry, "e820_entry");
			MEMBER_OFFSET_INIT(e820entry_addr, "e820_entry", "addr");
			MEMBER_OFFSET_INIT(e820entry_size, "e820_entry", "size");
			MEMBER_OFFSET_INIT(e820entry_type, "e820_entry", "type");
		}
		if (!VALID_STRUCT(irq_ctx))
			STRUCT_SIZE_INIT(irq_ctx, "irq_stack");
		if (KVMDUMP_DUMPFILE())
			set_kvm_iohole(NULL);
		if (symbol_exists("irq_desc"))
			ARRAY_LENGTH_INIT(machdep->nr_irqs, irq_desc,
				"irq_desc", NULL, 0);
		else if (kernel_symbol_exists("nr_irqs"))
			get_symbol_data("nr_irqs", sizeof(unsigned int),
				&machdep->nr_irqs);
		else
			machdep->nr_irqs = 224;  /* NR_IRQS */
		if (!machdep->hz) {
			machdep->hz = HZ;
			if (THIS_KERNEL_VERSION >= LINUX(2,6,0))
				machdep->hz = 1000;
		}

		if (machdep->flags & PAE) {
			if (THIS_KERNEL_VERSION < LINUX(2,6,26))
				machdep->section_size_bits =
					_SECTION_SIZE_BITS_PAE_ORIG;
			else
				machdep->section_size_bits =
					_SECTION_SIZE_BITS_PAE_2_6_26;
			machdep->max_physmem_bits = _MAX_PHYSMEM_BITS_PAE;
		} else {
			machdep->section_size_bits = _SECTION_SIZE_BITS;
			machdep->max_physmem_bits = _MAX_PHYSMEM_BITS;
		}

		if (XEN() && (kt->xen_flags & WRITABLE_PAGE_TABLES)) {
			if (machdep->flags & PAE) 
                        	machdep->uvtop = x86_uvtop_xen_wpt_PAE;
			else
                        	machdep->uvtop = x86_uvtop_xen_wpt;
		} 

		if (XEN()) {
			MEMBER_OFFSET_INIT(vcpu_guest_context_user_regs,
				"vcpu_guest_context", "user_regs");
			MEMBER_OFFSET_INIT(cpu_user_regs_esp,
				"cpu_user_regs", "esp");
			MEMBER_OFFSET_INIT(cpu_user_regs_eip,
				"cpu_user_regs", "eip");
		}

		if (THIS_KERNEL_VERSION < LINUX(2,6,24))
			machdep->line_number_hooks = x86_line_number_hooks;

		eframe_init();

		if (THIS_KERNEL_VERSION >= LINUX(2,6,28))
			machdep->machspec->page_protnone = _PAGE_GLOBAL;
		else
			machdep->machspec->page_protnone = _PAGE_PSE;

		STRUCT_SIZE_INIT(note_buf, "note_buf_t");
		STRUCT_SIZE_INIT(elf_prstatus, "elf_prstatus");
		MEMBER_OFFSET_INIT(elf_prstatus_pr_reg, "elf_prstatus",
				   "pr_reg");
		STRUCT_SIZE_INIT(percpu_data, "percpu_data");

		if (!remap_init())
			machdep->machspec->max_numnodes = -1;

		MEMBER_OFFSET_INIT(inactive_task_frame_ret_addr, 
			"inactive_task_frame", "ret_addr");
		break;

	case POST_INIT:
		read_idt_table(READ_IDT_INIT); 
		break;

	case LOG_ONLY:
		machdep->kvbase = kt->vmcoreinfo._stext_SYMBOL & ~KVBASE_MASK;
		break;
	}
}

/*
 *  Handle non-default (c0000000) values of CONFIG_PAGE_OFFSET 
 *  with "--machdep page_offset=<address>"
 */
static void
x86_parse_cmdline_args(void)
{
	int index, i, c, err;
	char *arglist[MAXARGS];
	char buf[BUFSIZE];
	char *p;
	ulong value = 0;

	for (index = 0; index < MAX_MACHDEP_ARGS; index++) {
		if (!machdep->cmdline_args[index])
			break;

		if (!strstr(machdep->cmdline_args[index], "=")) {
			error(WARNING, "ignoring --machdep option: %x\n",
				machdep->cmdline_args[index]);
			continue;
		}

		strcpy(buf, machdep->cmdline_args[index]);

		for (p = buf; *p; p++) {
			if (*p == ',')
				*p = ' ';
		}

		c = parse_line(buf, arglist);

		for (i = 0; i < c; i++) {
			err = 0;

			if (STRNEQ(arglist[i], "page_offset=")) {
				int flags = RETURN_ON_ERROR | QUIET;

				p = arglist[i] + strlen("page_offset=");
				if (strlen(p))
					value = htol(p, flags, &err);

				if (!err) {
					machdep->kvbase = value;

					error(NOTE, "setting PAGE_OFFSET to: 0x%lx\n\n",
						machdep->kvbase);
					continue;
				}
			}

			error(WARNING, "ignoring --machdep option: %s\n",
				arglist[i]);
		}
	}
}

/*
 *  Account for addition of pt_regs.xgs field in 2.6.20+ kernels.
 */
static void
eframe_init(void)
{
	if (INVALID_SIZE(pt_regs)) {
		if (THIS_KERNEL_VERSION < LINUX(2,6,20))
			ASSIGN_SIZE(pt_regs) = (MAX_USER_EFRAME_SIZE-2)*sizeof(ulong);
		else {
			ASSIGN_SIZE(pt_regs) = MAX_USER_EFRAME_SIZE*sizeof(ulong);
			INT_EFRAME_SS = 15;
			INT_EFRAME_ESP = 14;
			INT_EFRAME_EFLAGS = 13;
			INT_EFRAME_CS = 12;
			INT_EFRAME_EIP = 11;
			INT_EFRAME_ERR = 10;
			INT_EFRAME_GS = 9;
		}
		return;
	}

	if (MEMBER_EXISTS("pt_regs", "esp")) {
		INT_EFRAME_SS = MEMBER_OFFSET("pt_regs", "xss") / 4; 
		INT_EFRAME_ESP = MEMBER_OFFSET("pt_regs", "esp") / 4;
		INT_EFRAME_EFLAGS = MEMBER_OFFSET("pt_regs", "eflags") / 4;
		INT_EFRAME_CS = MEMBER_OFFSET("pt_regs", "xcs") / 4;
		INT_EFRAME_EIP = MEMBER_OFFSET("pt_regs", "eip") / 4;
		INT_EFRAME_ERR = MEMBER_OFFSET("pt_regs", "orig_eax") / 4;
		if ((INT_EFRAME_GS = MEMBER_OFFSET("pt_regs", "xgs")) != -1)
			INT_EFRAME_GS /= 4;
		INT_EFRAME_ES = MEMBER_OFFSET("pt_regs", "xes") / 4;
		INT_EFRAME_DS = MEMBER_OFFSET("pt_regs", "xds") / 4;
		INT_EFRAME_EAX = MEMBER_OFFSET("pt_regs", "eax") / 4;
		INT_EFRAME_EBP = MEMBER_OFFSET("pt_regs", "ebp") / 4;
		INT_EFRAME_EDI = MEMBER_OFFSET("pt_regs", "edi") / 4;
		INT_EFRAME_ESI = MEMBER_OFFSET("pt_regs", "esi") / 4;
		INT_EFRAME_EDX = MEMBER_OFFSET("pt_regs", "edx") / 4;
		INT_EFRAME_ECX = MEMBER_OFFSET("pt_regs", "ecx") / 4;
		INT_EFRAME_EBX = MEMBER_OFFSET("pt_regs", "ebx") / 4;
	} else {
		INT_EFRAME_SS = MEMBER_OFFSET("pt_regs", "ss") / 4; 
		INT_EFRAME_ESP = MEMBER_OFFSET("pt_regs", "sp") / 4;
		INT_EFRAME_EFLAGS = MEMBER_OFFSET("pt_regs", "flags") / 4;
		INT_EFRAME_CS = MEMBER_OFFSET("pt_regs", "cs") / 4;
		INT_EFRAME_EIP = MEMBER_OFFSET("pt_regs", "ip") / 4;
		INT_EFRAME_ERR = MEMBER_OFFSET("pt_regs", "orig_ax") / 4;
		if ((INT_EFRAME_GS = MEMBER_OFFSET("pt_regs", "gs")) != -1)
			INT_EFRAME_GS /= 4;
		INT_EFRAME_ES = MEMBER_OFFSET("pt_regs", "es") / 4;
		INT_EFRAME_DS = MEMBER_OFFSET("pt_regs", "ds") / 4;
		INT_EFRAME_EAX = MEMBER_OFFSET("pt_regs", "ax") / 4;
		INT_EFRAME_EBP = MEMBER_OFFSET("pt_regs", "bp") / 4;
		INT_EFRAME_EDI = MEMBER_OFFSET("pt_regs", "di") / 4;
		INT_EFRAME_ESI = MEMBER_OFFSET("pt_regs", "si") / 4;
		INT_EFRAME_EDX = MEMBER_OFFSET("pt_regs", "dx") / 4;
		INT_EFRAME_ECX = MEMBER_OFFSET("pt_regs", "cx") / 4;
		INT_EFRAME_EBX = MEMBER_OFFSET("pt_regs", "bx") / 4;
	}
}

/*
 *  Locate regions remapped by the remap allocator
 */
static int
remap_init(void)
{
	ulong start_vaddr, end_vaddr, start_pfn;
	int max_numnodes;
	struct machine_specific *ms;
	struct syment *sp;

	if (! (sp = symbol_search("node_remap_start_vaddr")) )
		return FALSE;
	start_vaddr = sp->value;

	if (! (sp = symbol_search("node_remap_end_vaddr")) )
		return FALSE;
	end_vaddr = sp->value;

	if (! (sp = symbol_search("node_remap_start_pfn")) )
		return FALSE;
	start_pfn = sp->value;

	max_numnodes = get_array_length("node_remap_start_pfn", NULL,
					sizeof(ulong));
	if (max_numnodes < 1)
		max_numnodes = 1;

	ms = machdep->machspec;
	ms->remap_start_vaddr = calloc(3 * max_numnodes, sizeof(ulong));
	if (!ms->remap_start_vaddr)
		error(FATAL, "cannot malloc remap array");
	ms->remap_end_vaddr = ms->remap_start_vaddr + max_numnodes;
	ms->remap_start_pfn = ms->remap_end_vaddr + max_numnodes;

	readmem(start_vaddr, KVADDR, ms->remap_start_vaddr,
		max_numnodes * sizeof(ulong), "node_remap_start_vaddr",
		FAULT_ON_ERROR);
	readmem(end_vaddr, KVADDR, ms->remap_end_vaddr,
		max_numnodes * sizeof(ulong), "node_remap_end_vaddr",
		FAULT_ON_ERROR);
	readmem(start_pfn, KVADDR, ms->remap_start_pfn,
		max_numnodes * sizeof(ulong), "node_remap_end_vaddr",
		FAULT_ON_ERROR);
	ms->max_numnodes = max_numnodes;

	return TRUE;
}

static int
x86_kvtop_remap(ulong kvaddr, physaddr_t *paddr)
{
	struct machine_specific *ms;
	int i;

	ms = machdep->machspec;

	/* ms->max_numnodes is -1 when unused. */
	
	for (i = 0; i < ms->max_numnodes; ++i) {
		if (kvaddr >= ms->remap_start_vaddr[i] &&
		    kvaddr < ms->remap_end_vaddr[i]) {
			*paddr = PTOB(ms->remap_start_pfn[i]) +
				kvaddr - ms->remap_start_vaddr[i];
			return TRUE;
		}
	}
	return FALSE;
}

/*
 *  Needs to be done this way because of potential 4G/4G split.
 */
static int 
x86_is_uvaddr(ulong vaddr, struct task_context *tc)
{
	return IN_TASK_VMA(tc->task, vaddr);
}

/*
 *  Translates a user virtual address to its physical address.  cmd_vtop()
 *  sets the verbose flag so that the pte translation gets displayed; all
 *  other callers quietly accept the translation.
 *
 *  This routine can also take mapped kernel virtual addresses if the -u flag
 *  was passed to cmd_vtop().  If so, it makes the translation using the
 *  kernel-memory PGD entry instead of swapper_pg_dir.
 */

#define _4MB_PAGE_MASK       (~((MEGABYTES(4))-1))
#define _2MB_PAGE_MASK       (~((MEGABYTES(2))-1))

static int
x86_uvtop(struct task_context *tc, ulong vaddr, physaddr_t *paddr, int verbose)
{
	ulong mm, active_mm;
	ulong *pgd;
	ulong *page_dir;
	ulong *page_middle;
	ulong *page_table;
	ulong pgd_pte;
	ulong pmd_pte;
	ulong pte;
	char buf[BUFSIZE];

	if (!tc)
		error(FATAL, "current context invalid\n");

	*paddr = 0;

        if (is_kernel_thread(tc->task) && IS_KVADDR(vaddr)) { 
	    	if (VALID_MEMBER(thread_struct_cr3)) 
                	pgd = (ulong *)machdep->get_task_pgd(tc->task);
		else {
			if (INVALID_MEMBER(task_struct_active_mm))
				error(FATAL, "no cr3 or active_mm?\n");

                	readmem(tc->task + OFFSET(task_struct_active_mm), 
				KVADDR, &active_mm, sizeof(void *),
                        	"task active_mm contents", FAULT_ON_ERROR);

			if (!active_mm)
				error(FATAL, 
				     "no active_mm for this kernel thread\n");

			readmem(active_mm + OFFSET(mm_struct_pgd), 
				KVADDR, &pgd, sizeof(long), 
				"mm_struct pgd", FAULT_ON_ERROR);
		}
        } else {
		if ((mm = task_mm(tc->task, TRUE)))
			pgd = ULONG_PTR(tt->mm_struct + 
				OFFSET(mm_struct_pgd));
		else
			readmem(tc->mm_struct + OFFSET(mm_struct_pgd), 
				KVADDR, &pgd, sizeof(long), "mm_struct pgd", 
				FAULT_ON_ERROR);
	}

	if (verbose) 
		fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)pgd);

	page_dir = pgd + (vaddr >> PGDIR_SHIFT);

	FILL_PGD(NONPAE_PAGEBASE(pgd), KVADDR, PAGESIZE());
	pgd_pte = ULONG(machdep->pgd + PAGEOFFSET(page_dir));

	if (verbose)
		fprintf(fp, "  PGD: %s => %lx\n", 
			mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX, 
			MKSTR((ulong)page_dir)),
			pgd_pte);

	if (!(pgd_pte & (_PAGE_PRESENT | _PAGE_PROTNONE)))
		goto no_upage;

        if (pgd_pte & _PAGE_4M) {
                if (verbose) {
                        fprintf(fp, " PAGE: %s  (4MB)\n\n", 
				mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX, 
				MKSTR(NONPAE_PAGEBASE(pgd_pte))));
			x86_translate_pte(pgd_pte, 0, 0);
		}

		*paddr = NONPAE_PAGEBASE(pgd_pte) + (vaddr & ~_4MB_PAGE_MASK);
                return TRUE;
        }

	page_middle = page_dir;

	FILL_PMD(NONPAE_PAGEBASE(page_middle), KVADDR, PAGESIZE());
	pmd_pte = ULONG(machdep->pmd + PAGEOFFSET(page_middle));

	if (verbose)
		fprintf(fp, "  PMD: %s => %lx\n", 
		        mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX,
                        MKSTR((ulong)page_middle)),
			pmd_pte);

	if (!pmd_pte)
		goto no_upage;

#ifdef PTES_IN_LOWMEM
	page_table = (ulong *)(PTOV(NONPAE_PAGEBASE(pmd_pte)) + 
		((vaddr>>10) & ((PTRS_PER_PTE-1)<<2)));

	FILL_PTBL(NONPAE_PAGEBASE(page_table), KVADDR, PAGESIZE());
	pte = ULONG(machdep->ptbl + PAGEOFFSET(page_table));
#else
        page_table = (ulong *)((NONPAE_PAGEBASE(pmd_pte)) +
                ((vaddr>>10) & ((PTRS_PER_PTE-1)<<2)));

        FILL_PTBL(NONPAE_PAGEBASE(page_table), PHYSADDR, PAGESIZE());
        pte = ULONG(machdep->ptbl + PAGEOFFSET(page_table));
#endif

        if (verbose) 
                fprintf(fp, "  PTE: %s => %lx\n", 
			mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX,
                        MKSTR((ulong)page_table)), pte);

	if (!(pte & (_PAGE_PRESENT | _PAGE_PROTNONE))) {
		*paddr = pte;

		if (pte && verbose) {
			fprintf(fp, "\n");
			x86_translate_pte(pte, 0, 0);
		}
		
		goto no_upage;
	}

	*paddr = NONPAE_PAGEBASE(pte) + PAGEOFFSET(vaddr);

        if (verbose) {
                fprintf(fp, " PAGE: %s\n\n", 
			mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX, 
			MKSTR(NONPAE_PAGEBASE(pte))));
		x86_translate_pte(pte, 0, 0);
	}

	return TRUE;

no_upage:
	return FALSE;
}

static int
x86_uvtop_xen_wpt(struct task_context *tc, ulong vaddr, physaddr_t *paddr, int verbose)
{
	ulong mm, active_mm;
	ulong *pgd;
	ulong *page_dir;
	ulong *page_middle;
	ulong *machine_page_table, *pseudo_page_table;
	ulong pgd_pte, pseudo_pgd_pte;
	ulong pmd_pte;
	ulong machine_pte, pseudo_pte;
	char buf[BUFSIZE];

	if (!tc)
		error(FATAL, "current context invalid\n");

	*paddr = 0;

        if (is_kernel_thread(tc->task) && IS_KVADDR(vaddr)) { 
	    	if (VALID_MEMBER(thread_struct_cr3)) 
                	pgd = (ulong *)machdep->get_task_pgd(tc->task);
		else {
			if (INVALID_MEMBER(task_struct_active_mm))
				error(FATAL, "no cr3 or active_mm?\n");

                	readmem(tc->task + OFFSET(task_struct_active_mm), 
				KVADDR, &active_mm, sizeof(void *),
                        	"task active_mm contents", FAULT_ON_ERROR);

			if (!active_mm)
				error(FATAL, 
				     "no active_mm for this kernel thread\n");

			readmem(active_mm + OFFSET(mm_struct_pgd), 
				KVADDR, &pgd, sizeof(long), 
				"mm_struct pgd", FAULT_ON_ERROR);
		}
        } else {
		if ((mm = task_mm(tc->task, TRUE)))
			pgd = ULONG_PTR(tt->mm_struct + 
				OFFSET(mm_struct_pgd));
		else
			readmem(tc->mm_struct + OFFSET(mm_struct_pgd), 
				KVADDR, &pgd, sizeof(long), "mm_struct pgd", 
				FAULT_ON_ERROR);
	}

	if (verbose) 
		fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)pgd);

	page_dir = pgd + (vaddr >> PGDIR_SHIFT);

	FILL_PGD(NONPAE_PAGEBASE(pgd), KVADDR, PAGESIZE());
	pgd_pte = ULONG(machdep->pgd + PAGEOFFSET(page_dir));

	if (verbose)
		fprintf(fp, "  PGD: %s => %lx\n", 
			mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX, 
			MKSTR((ulong)page_dir)),
			pgd_pte);

	if (!pgd_pte)
		goto no_upage;

        if (pgd_pte & _PAGE_4M) {
                if (verbose) 
                        fprintf(fp, " PAGE: %s  (4MB) [machine]\n", 
				mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX, 
				MKSTR(NONPAE_PAGEBASE(pgd_pte))));

		pseudo_pgd_pte = xen_m2p_nonPAE(NONPAE_PAGEBASE(pgd_pte));

                if (pseudo_pgd_pte == XEN_MFN_NOT_FOUND) {
                        if (verbose)
                                fprintf(fp, " PAGE: page not available\n");
                        *paddr = PADDR_NOT_AVAILABLE;
                        return FALSE;
                }

		pseudo_pgd_pte |= PAGEOFFSET(pgd_pte);

		if (verbose) {
			fprintf(fp, " PAGE: %s  (4MB)\n\n", 
				mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX,
                        	MKSTR(NONPAE_PAGEBASE(pseudo_pgd_pte))));

			x86_translate_pte(pseudo_pgd_pte, 0, 0);
		}

		*paddr = NONPAE_PAGEBASE(pseudo_pgd_pte) + 
			(vaddr & ~_4MB_PAGE_MASK);

		return TRUE;
        }

	page_middle = page_dir;

	FILL_PMD(NONPAE_PAGEBASE(page_middle), KVADDR, PAGESIZE());
	pmd_pte = ULONG(machdep->pmd + PAGEOFFSET(page_middle));

	if (verbose)
		fprintf(fp, "  PMD: %s => %lx\n", 
		        mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX,
                        MKSTR((ulong)page_middle)),
			pmd_pte);

	if (!pmd_pte)
		goto no_upage;

        machine_page_table = (ulong *)((NONPAE_PAGEBASE(pmd_pte)) +
                ((vaddr>>10) & ((PTRS_PER_PTE-1)<<2)));

        pseudo_page_table = (ulong *)
                xen_m2p_nonPAE(NONPAE_PAGEBASE(machine_page_table));

        FILL_PTBL(NONPAE_PAGEBASE(pseudo_page_table), PHYSADDR, PAGESIZE());
        machine_pte = ULONG(machdep->ptbl + PAGEOFFSET(machine_page_table));

        if (verbose) {
                fprintf(fp, "  PTE: %s [machine]\n", 
			mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX,
                        MKSTR((ulong)machine_page_table)));

                fprintf(fp, "  PTE: %s => %lx\n",
                        mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX,
                        MKSTR((ulong)pseudo_page_table +
                        PAGEOFFSET(machine_page_table))), machine_pte);
	}

	if (!(machine_pte & (_PAGE_PRESENT | _PAGE_PROTNONE))) {
		*paddr = machine_pte;

		if (machine_pte && verbose) {
			fprintf(fp, "\n");
			x86_translate_pte(machine_pte, 0, 0);
		}
		
		goto no_upage;
	}

        pseudo_pte = xen_m2p_nonPAE(NONPAE_PAGEBASE(machine_pte));
        pseudo_pte |= PAGEOFFSET(machine_pte);

	*paddr = NONPAE_PAGEBASE(pseudo_pte) + PAGEOFFSET(vaddr);

        if (verbose) {
                fprintf(fp, " PAGE: %s [machine]\n", 
			mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX, 
			MKSTR(NONPAE_PAGEBASE(machine_pte))));

                fprintf(fp, " PAGE: %s\n\n",
                        mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX,
                        MKSTR(NONPAE_PAGEBASE(pseudo_pte))));

                x86_translate_pte(pseudo_pte, 0, 0);
	}

	return TRUE;

no_upage:
	return FALSE;
}

static int
x86_uvtop_PAE(struct task_context *tc, ulong vaddr, physaddr_t *paddr, int verbose)
{
	ulong mm, active_mm;
	ulonglong *pgd;
	ulonglong page_dir_entry;
	ulonglong page_middle;
	ulonglong page_middle_entry;
	ulonglong page_table;
	ulonglong page_table_entry;
	ulonglong physpage;
	ulonglong ull;
	ulong offset;
	char buf[BUFSIZE];

	if (!tc)
		error(FATAL, "current context invalid\n");

	*paddr = 0;

        if (is_kernel_thread(tc->task) && IS_KVADDR(vaddr)) { 
	    	if (VALID_MEMBER(thread_struct_cr3)) 
                	pgd = (ulonglong *)machdep->get_task_pgd(tc->task);
		else {
			if (INVALID_MEMBER(task_struct_active_mm))
				error(FATAL, "no cr3 or active_mm?\n");

                	readmem(tc->task + OFFSET(task_struct_active_mm), 
				KVADDR, &active_mm, sizeof(void *),
                        	"task active_mm contents", FAULT_ON_ERROR);

			if (!active_mm)
				error(FATAL, 
				     "no active_mm for this kernel thread\n");

			readmem(active_mm + OFFSET(mm_struct_pgd), 
				KVADDR, &pgd, sizeof(long), 
				"mm_struct pgd", FAULT_ON_ERROR);
		}
        } else {
		if ((mm = task_mm(tc->task, TRUE)))
			pgd = (ulonglong *)(ULONG_PTR(tt->mm_struct + 
				OFFSET(mm_struct_pgd)));
		else
			readmem(tc->mm_struct + OFFSET(mm_struct_pgd), 
				KVADDR, &pgd, sizeof(long), "mm_struct pgd", 
				FAULT_ON_ERROR);
	}

	if (verbose) 
		fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)pgd);

	FILL_PGD(pgd, KVADDR, PTRS_PER_PGD * sizeof(ulonglong));

	offset = ((vaddr >> PGDIR_SHIFT) & (PTRS_PER_PGD-1)) * 
		sizeof(ulonglong);

	page_dir_entry = *((ulonglong *)&machdep->pgd[offset]);

	if (verbose)
		fprintf(fp, "  PGD: %s => %llx\n", 
			mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX, 
			MKSTR((ulong)pgd + offset)), 
			page_dir_entry);

	if (!(page_dir_entry & _PAGE_PRESENT)) {
		goto no_upage;
	}

	page_middle = PAE_PAGEBASE(page_dir_entry);

	FILL_PMD_PAE(page_middle, PHYSADDR, PAGESIZE());

	offset = ((vaddr >> PMD_SHIFT) & (PTRS_PER_PMD-1)) * sizeof(ulonglong);

        page_middle_entry = *((ulonglong *)&machdep->pmd[offset]);

        if (verbose) {
		ull = page_middle + offset;
                fprintf(fp, "  PMD: %s => %llx\n", 
			mkstring(buf, VADDR_PRLEN, RJUST|LONGLONG_HEX, 
			MKSTR(&ull)), 
			page_middle_entry);
	}

        if (!(page_middle_entry & (_PAGE_PRESENT | _PAGE_PROTNONE))) {
                goto no_upage;
        }

        if (page_middle_entry & _PAGE_PSE) {
                if (verbose) {
			ull = PAE_PAGEBASE(page_middle_entry);
                        fprintf(fp, " PAGE: %s  (2MB)\n\n",
				mkstring(buf, VADDR_PRLEN, RJUST|LONGLONG_HEX,
                        	MKSTR(&ull)));
                        x86_translate_pte(0, 0, page_middle_entry);
                }

                physpage = PAE_PAGEBASE(page_middle_entry) +
                        (vaddr & ~_2MB_PAGE_MASK);
                *paddr = physpage;

                return TRUE;
        }

        page_table = PAE_PAGEBASE(page_middle_entry);

        FILL_PTBL_PAE(page_table, PHYSADDR, PAGESIZE());

	offset = ((vaddr >> PAGESHIFT()) & (PTRS_PER_PTE-1)) * 
		sizeof(ulonglong);

        page_table_entry = *((ulonglong *)&machdep->ptbl[offset]);

        if (verbose) {
		ull = page_table + offset;
                fprintf(fp, "  PTE: %s => %llx\n", 
			mkstring(buf, VADDR_PRLEN, RJUST|LONGLONG_HEX, 
			MKSTR(&ull)), page_table_entry);
	}

        if (!(page_table_entry & (_PAGE_PRESENT | _PAGE_PROTNONE))) {
                *paddr = page_table_entry;

                if (page_table_entry && verbose) {
                        fprintf(fp, "\n");
                        x86_translate_pte(0, 0, page_table_entry);
                }

                goto no_upage;
        }

	physpage = PAE_PAGEBASE(page_table_entry) + PAGEOFFSET(vaddr);

        *paddr = physpage;

        if (verbose) {
                ull = PAE_PAGEBASE(page_table_entry);
                fprintf(fp, " PAGE: %s\n\n",
                        mkstring(buf, VADDR_PRLEN, RJUST|LONGLONG_HEX,
                        MKSTR(&ull)));
                x86_translate_pte(0, 0, page_table_entry);
        }

        return TRUE;

no_upage:
	return FALSE;
}

static int
x86_uvtop_xen_wpt_PAE(struct task_context *tc, ulong vaddr, physaddr_t *paddr, int verbose)
{
	ulong mm, active_mm;
	ulonglong *pgd;
	ulonglong page_dir_entry;
	ulonglong page_middle, pseudo_page_middle;
	ulonglong page_middle_entry;
	ulonglong page_table, pseudo_page_table;
	ulonglong page_table_entry, pte;
	ulonglong physpage, pseudo_physpage;
	ulonglong ull;
	ulong offset;
	char buf[BUFSIZE];

	if (!tc)
		error(FATAL, "current context invalid\n");

	*paddr = 0;

        if (is_kernel_thread(tc->task) && IS_KVADDR(vaddr)) { 
	    	if (VALID_MEMBER(thread_struct_cr3)) 
                	pgd = (ulonglong *)machdep->get_task_pgd(tc->task);
		else {
			if (INVALID_MEMBER(task_struct_active_mm))
				error(FATAL, "no cr3 or active_mm?\n");

                	readmem(tc->task + OFFSET(task_struct_active_mm), 
				KVADDR, &active_mm, sizeof(void *),
                        	"task active_mm contents", FAULT_ON_ERROR);

			if (!active_mm)
				error(FATAL, 
				     "no active_mm for this kernel thread\n");

			readmem(active_mm + OFFSET(mm_struct_pgd), 
				KVADDR, &pgd, sizeof(long), 
				"mm_struct pgd", FAULT_ON_ERROR);
		}
        } else {
		if ((mm = task_mm(tc->task, TRUE)))
			pgd = (ulonglong *)(ULONG_PTR(tt->mm_struct + 
				OFFSET(mm_struct_pgd)));
		else
			readmem(tc->mm_struct + OFFSET(mm_struct_pgd), 
				KVADDR, &pgd, sizeof(long), "mm_struct pgd", 
				FAULT_ON_ERROR);
	}

	if (verbose) 
		fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)pgd);

	FILL_PGD(pgd, KVADDR, PTRS_PER_PGD * sizeof(ulonglong));

	offset = ((vaddr >> PGDIR_SHIFT) & (PTRS_PER_PGD-1)) * 
		sizeof(ulonglong);

	page_dir_entry = *((ulonglong *)&machdep->pgd[offset]);

	if (verbose)
		fprintf(fp, "  PGD: %s => %llx [machine]\n", 
			mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX, 
			MKSTR((ulong)pgd + offset)), 
			page_dir_entry);

	if (!(page_dir_entry & _PAGE_PRESENT)) {
		goto no_upage;
	}

	page_middle = PAE_PAGEBASE(page_dir_entry);
	pseudo_page_middle = xen_m2p(page_middle); 

        if (verbose)
                fprintf(fp, "  PGD: %s => %llx\n",
                        mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX,
                        MKSTR((ulong)pgd + offset)),
                        pseudo_page_middle | PAGEOFFSET(page_dir_entry) |
                        (page_dir_entry & _PAGE_NX));

	FILL_PMD_PAE(pseudo_page_middle, PHYSADDR, PAGESIZE());

	offset = ((vaddr >> PMD_SHIFT) & (PTRS_PER_PMD-1)) * sizeof(ulonglong);

        page_middle_entry = *((ulonglong *)&machdep->pmd[offset]);

        if (verbose) {
		ull = page_middle + offset;
                fprintf(fp, "  PMD: %s => %llx [machine]\n", 
			mkstring(buf, VADDR_PRLEN, RJUST|LONGLONG_HEX, 
			MKSTR(&ull)), 
			page_middle_entry);
	}

        if (!(page_middle_entry & _PAGE_PRESENT)) {
                goto no_upage;
        }

        if (page_middle_entry & _PAGE_PSE) {
		error(FATAL, "_PAGE_PSE in an mfn not supported\n");  /* XXX */
                if (verbose) {
			ull = PAE_PAGEBASE(page_middle_entry);
                        fprintf(fp, " PAGE: %s  (2MB)\n\n",
				mkstring(buf, VADDR_PRLEN, RJUST|LONGLONG_HEX,
                        	MKSTR(&ull)));
                        x86_translate_pte(0, 0, page_middle_entry);
                }

                physpage = PAE_PAGEBASE(page_middle_entry) +
                        (vaddr & ~_2MB_PAGE_MASK);
                *paddr = physpage;

                return TRUE;
        }

        page_table = PAE_PAGEBASE(page_middle_entry);
	pseudo_page_table = xen_m2p(page_table); 

        if (verbose) {
                ull = page_middle + offset;
                fprintf(fp, "  PMD: %s => %llx\n",
                        mkstring(buf, VADDR_PRLEN, RJUST|LONGLONG_HEX,
                        MKSTR(&ull)),
                        pseudo_page_table | PAGEOFFSET(page_middle_entry) |
                        (page_middle_entry & _PAGE_NX));
        }

        FILL_PTBL_PAE(pseudo_page_table, PHYSADDR, PAGESIZE());

	offset = ((vaddr >> PAGESHIFT()) & (PTRS_PER_PTE-1)) * 
		sizeof(ulonglong);

        page_table_entry = *((ulonglong *)&machdep->ptbl[offset]);

        if (verbose) {
		ull = page_table + offset;
                fprintf(fp, "  PTE: %s => %llx [machine]\n", 
			mkstring(buf, VADDR_PRLEN, RJUST|LONGLONG_HEX, 
			MKSTR(&ull)), page_table_entry);
	}

        if (!(page_table_entry & (_PAGE_PRESENT | _PAGE_PROTNONE))) {
                *paddr = page_table_entry;

                if (page_table_entry && verbose) {
                        fprintf(fp, "\n");
                        x86_translate_pte(0, 0, page_table_entry);
                }

                goto no_upage;
        }

	physpage = PAE_PAGEBASE(page_table_entry) + PAGEOFFSET(vaddr);
	pseudo_physpage = xen_m2p(physpage); 

        if (verbose) {
                ull = page_table + offset;
                fprintf(fp, "  PTE: %s => %llx\n",
                        mkstring(buf, VADDR_PRLEN, RJUST|LONGLONG_HEX,
                        MKSTR(&ull)),
                        pseudo_physpage | PAGEOFFSET(page_table_entry) |
                        (page_table_entry & _PAGE_NX));
        }

        *paddr = pseudo_physpage + PAGEOFFSET(vaddr);

        if (verbose) {
		physpage = PAE_PAGEBASE(physpage);
                fprintf(fp, " PAGE: %s [machine]\n", 
			mkstring(buf, VADDR_PRLEN, RJUST|LONGLONG_HEX, 
			MKSTR(&physpage)));
		
                fprintf(fp, " PAGE: %s\n\n",
                        mkstring(buf, VADDR_PRLEN, RJUST|LONGLONG_HEX,
                        MKSTR(&pseudo_physpage)));

		pte = pseudo_physpage | PAGEOFFSET(page_table_entry) |
			(page_table_entry & _PAGE_NX);

                x86_translate_pte(0, 0, pte);
        }

        return TRUE;

no_upage:
	return FALSE;
}

/*
 *  Translates a kernel virtual address to its physical address.  cmd_vtop()
 *  sets the verbose flag so that the pte translation gets displayed; all
 *  other callers quietly accept the translation.
 */

static int
x86_kvtop(struct task_context *tc, ulong kvaddr, physaddr_t *paddr, int verbose)
{
	ulong *pgd;
	ulong *page_dir;
	ulong *page_middle;
	ulong *page_table;
        ulong pgd_pte;
        ulong pmd_pte;
        ulong pte;
	char buf[BUFSIZE];

	if (!IS_KVADDR(kvaddr))
		return FALSE;

	if (XEN_HYPER_MODE()) {
		if (DIRECTMAP_VIRT_ADDR(kvaddr)) {
			*paddr = kvaddr - DIRECTMAP_VIRT_START;
			return TRUE;
		}
		pgd = (ulong *)symbol_value("idle_pg_table_l2");
	} else {
		if (x86_kvtop_remap(kvaddr, paddr)) {
			if (!verbose)
				return TRUE;
		} else if (!vt->vmalloc_start) {
			*paddr = VTOP(kvaddr);
			return TRUE;
		} else if (!IS_VMALLOC_ADDR(kvaddr)) { 
			*paddr = VTOP(kvaddr);
			if (!verbose)
				return TRUE;
		}

		if (XEN() && (kt->xen_flags & WRITABLE_PAGE_TABLES))
			return (x86_kvtop_xen_wpt(tc, kvaddr, paddr, verbose));

		pgd = (ulong *)vt->kernel_pgd[0];
	}

	if (verbose) 
		fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)pgd);

	page_dir = pgd + (kvaddr >> PGDIR_SHIFT);

        FILL_PGD(NONPAE_PAGEBASE(pgd), KVADDR, PAGESIZE());
        pgd_pte = ULONG(machdep->pgd + PAGEOFFSET(page_dir));

	if (verbose)
		fprintf(fp, "  PGD: %s => %lx\n", 
			mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX, 
			MKSTR((ulong)page_dir)), pgd_pte);

	if (!pgd_pte)
		goto no_kpage;

	if (pgd_pte & _PAGE_4M) {
		if (verbose) {
			fprintf(fp, " PAGE: %s  (4MB)\n\n", 
				mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX,
                        	MKSTR(NONPAE_PAGEBASE(pgd_pte))));
			x86_translate_pte(pgd_pte, 0, 0);
		}

		*paddr = NONPAE_PAGEBASE(pgd_pte) + (kvaddr & ~_4MB_PAGE_MASK);

		return TRUE;
	} 

	page_middle = page_dir;

        FILL_PMD(NONPAE_PAGEBASE(page_middle), KVADDR, PAGESIZE());
        pmd_pte = ULONG(machdep->pmd + PAGEOFFSET(page_middle));

	if (verbose)
		fprintf(fp, "  PMD: %s => %lx\n", 
			mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX, 
			MKSTR((ulong)page_middle)), pmd_pte);

	if (!pmd_pte)
		goto no_kpage;

#ifdef PTES_IN_LOWMEM
	page_table = (ulong *)(PTOV(NONPAE_PAGEBASE(pmd_pte)) + 
		((kvaddr>>10) & ((PTRS_PER_PTE-1)<<2)));
	
        FILL_PTBL(NONPAE_PAGEBASE(page_table), KVADDR, PAGESIZE());
        pte = ULONG(machdep->ptbl + PAGEOFFSET(page_table));
#else
        page_table = (ulong *)((NONPAE_PAGEBASE(pmd_pte)) +
                ((kvaddr>>10) & ((PTRS_PER_PTE-1)<<2)));

        FILL_PTBL(NONPAE_PAGEBASE(page_table), PHYSADDR, PAGESIZE());
        pte = ULONG(machdep->ptbl + PAGEOFFSET(page_table));
#endif

        if (verbose) 
                fprintf(fp, "  PTE: %s => %lx\n", 
			mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX, 
			MKSTR((ulong)page_table)), pte);

	if (!(pte & (_PAGE_PRESENT | _PAGE_PROTNONE))) {
		if (pte && verbose) {
			fprintf(fp, "\n");
			x86_translate_pte(pte, 0, 0);
		}
		goto no_kpage;
	}

	if (verbose) {
		fprintf(fp, " PAGE: %s\n\n", 
			mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX, 
			MKSTR(NONPAE_PAGEBASE(pte))));
		x86_translate_pte(pte, 0, 0);
	}

	*paddr = NONPAE_PAGEBASE(pte) + PAGEOFFSET(kvaddr);

	return TRUE;

no_kpage:
	return FALSE;
}

static int
x86_kvtop_xen_wpt(struct task_context *tc, ulong kvaddr, physaddr_t *paddr, int verbose)
{
	ulong *pgd;
	ulong *page_dir;
	ulong *page_middle;
	ulong *machine_page_table, *pseudo_page_table;
        ulong pgd_pte, pseudo_pgd_pte;
        ulong pmd_pte;
        ulong machine_pte, pseudo_pte;
	char buf[BUFSIZE];

	pgd = (ulong *)vt->kernel_pgd[0];

	if (verbose) 
		fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)pgd);

	page_dir = pgd + (kvaddr >> PGDIR_SHIFT);

        FILL_PGD(NONPAE_PAGEBASE(pgd), KVADDR, PAGESIZE());
        pgd_pte = ULONG(machdep->pgd + PAGEOFFSET(page_dir));

	if (verbose)
		fprintf(fp, "  PGD: %s => %lx\n", 
			mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX, 
			MKSTR((ulong)page_dir)), pgd_pte);

	if (!pgd_pte)
		goto no_kpage;

	if (pgd_pte & _PAGE_4M) {
		if (verbose)
			fprintf(fp, " PAGE: %s  (4MB) [machine]\n", 
				mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX,
                        	MKSTR(NONPAE_PAGEBASE(pgd_pte))));

		pseudo_pgd_pte = xen_m2p_nonPAE(NONPAE_PAGEBASE(pgd_pte));

		if (pseudo_pgd_pte == XEN_MFN_NOT_FOUND) {
			if (verbose)
				fprintf(fp, " PAGE: page not available\n");
			*paddr = PADDR_NOT_AVAILABLE;
			return FALSE;
		}

		pseudo_pgd_pte |= PAGEOFFSET(pgd_pte);

		if (verbose) {
			fprintf(fp, " PAGE: %s  (4MB)\n\n", 
				mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX,
                        	MKSTR(NONPAE_PAGEBASE(pseudo_pgd_pte))));

			x86_translate_pte(pseudo_pgd_pte, 0, 0);
		}

		*paddr = NONPAE_PAGEBASE(pseudo_pgd_pte) + 
			(kvaddr & ~_4MB_PAGE_MASK);

		return TRUE;
	} 

	page_middle = page_dir;

        FILL_PMD(NONPAE_PAGEBASE(page_middle), KVADDR, PAGESIZE());
        pmd_pte = ULONG(machdep->pmd + PAGEOFFSET(page_middle));

	if (verbose)
		fprintf(fp, "  PMD: %s => %lx\n", 
			mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX, 
			MKSTR((ulong)page_middle)), pmd_pte);

	if (!pmd_pte)
		goto no_kpage;

        machine_page_table = (ulong *)((NONPAE_PAGEBASE(pmd_pte)) +
                ((kvaddr>>10) & ((PTRS_PER_PTE-1)<<2)));

	pseudo_page_table = (ulong *)
		xen_m2p_nonPAE(NONPAE_PAGEBASE(machine_page_table));

        FILL_PTBL(NONPAE_PAGEBASE(pseudo_page_table), PHYSADDR, PAGESIZE());
        machine_pte = ULONG(machdep->ptbl + PAGEOFFSET(machine_page_table));

        if (verbose) {
                fprintf(fp, "  PTE: %s [machine]\n", 
			mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX, 
			MKSTR((ulong)machine_page_table)));

                fprintf(fp, "  PTE: %s => %lx\n", 
			mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX,
                        MKSTR((ulong)pseudo_page_table + 
			PAGEOFFSET(machine_page_table))), machine_pte);
	}

	if (!(machine_pte & (_PAGE_PRESENT | _PAGE_PROTNONE))) {
		if (machine_pte && verbose) {
			fprintf(fp, "\n");
			x86_translate_pte(machine_pte, 0, 0);
		}
		goto no_kpage;
	}

	pseudo_pte = xen_m2p_nonPAE(NONPAE_PAGEBASE(machine_pte));
	pseudo_pte |= PAGEOFFSET(machine_pte);

	if (verbose) {
		fprintf(fp, " PAGE: %s [machine]\n", 
			mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX, 
			MKSTR(NONPAE_PAGEBASE(machine_pte))));

		fprintf(fp, " PAGE: %s\n\n", 
			mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX, 
			MKSTR(NONPAE_PAGEBASE(pseudo_pte))));

		x86_translate_pte(pseudo_pte, 0, 0);
	}

	*paddr = NONPAE_PAGEBASE(pseudo_pte) + PAGEOFFSET(kvaddr);

	return TRUE;

no_kpage:
	return FALSE;
}


static int
x86_kvtop_PAE(struct task_context *tc, ulong kvaddr, physaddr_t *paddr, int verbose)
{
	ulonglong *pgd;
        ulonglong page_dir_entry;
        ulonglong page_middle;
        ulonglong page_middle_entry;
        ulonglong page_table;
        ulonglong page_table_entry;
        ulonglong physpage;
	ulonglong ull;
	char buf[BUFSIZE];
        ulong offset;
	

	if (!IS_KVADDR(kvaddr))
		return FALSE;

	if (XEN_HYPER_MODE()) {
		if (DIRECTMAP_VIRT_ADDR(kvaddr)) {
			*paddr = kvaddr - DIRECTMAP_VIRT_START;
			return TRUE;
		}
		if (symbol_exists("idle_pg_table_l3"))
			pgd = (ulonglong *)symbol_value("idle_pg_table_l3");
		else
			pgd = (ulonglong *)symbol_value("idle_pg_table");
	} else {
		if (x86_kvtop_remap(kvaddr, paddr)) {
			if (!verbose)
				return TRUE;
		} else if (!vt->vmalloc_start) {
			*paddr = VTOP(kvaddr);
			return TRUE;
		} else if (!IS_VMALLOC_ADDR(kvaddr)) { 
			*paddr = VTOP(kvaddr);
			if (!verbose)
				return TRUE;
		}

	        if (XEN() && (kt->xen_flags & WRITABLE_PAGE_TABLES))
	       	        return (x86_kvtop_xen_wpt_PAE(tc, kvaddr, paddr, verbose));

		pgd = (ulonglong *)vt->kernel_pgd[0];
	}

	if (verbose) 
		fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)pgd);

	FILL_PGD(pgd, KVADDR, PTRS_PER_PGD * sizeof(ulonglong));

	offset = ((kvaddr >> PGDIR_SHIFT) & (PTRS_PER_PGD-1)) * 
		sizeof(ulonglong);

	page_dir_entry = *((ulonglong *)&machdep->pgd[offset]);

	if (verbose)
		fprintf(fp, "  PGD: %s => %llx\n", 
                        mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX,
                        MKSTR((ulong)pgd + offset)),
                        page_dir_entry);

	if (!(page_dir_entry & _PAGE_PRESENT)) {
		goto no_kpage;
	}

	page_middle = PAE_PAGEBASE(page_dir_entry);

	FILL_PMD_PAE(page_middle, PHYSADDR, PAGESIZE());

	offset = ((kvaddr >> PMD_SHIFT) & (PTRS_PER_PMD-1)) * sizeof(ulonglong);

        page_middle_entry = *((ulonglong *)&machdep->pmd[offset]);

        if (verbose) {
                ull = page_middle + offset;
                fprintf(fp, "  PMD: %s => %llx\n",
                        mkstring(buf, VADDR_PRLEN, RJUST|LONGLONG_HEX,
                        MKSTR(&ull)),
                        page_middle_entry);
	}

        if (!(page_middle_entry & _PAGE_PRESENT)) {
                goto no_kpage;
        }

        if (page_middle_entry & _PAGE_PSE) {
                if (verbose) {
                        ull = PAE_PAGEBASE(page_middle_entry);
                        fprintf(fp, " PAGE: %s  (2MB)\n\n",
                                mkstring(buf, VADDR_PRLEN, RJUST|LONGLONG_HEX,
                                MKSTR(&ull)));
                        x86_translate_pte(0, 0, page_middle_entry);
                }

		physpage = PAE_PAGEBASE(page_middle_entry) +
			(kvaddr & ~_2MB_PAGE_MASK);
                *paddr = physpage;


                return TRUE;
        }

        page_table = PAE_PAGEBASE(page_middle_entry);

        FILL_PTBL_PAE(page_table, PHYSADDR, PAGESIZE());

	offset = ((kvaddr >> PAGESHIFT()) & (PTRS_PER_PTE-1)) * 
		sizeof(ulonglong);

        page_table_entry = *((ulonglong *)&machdep->ptbl[offset]);

        if (verbose) {
                ull = page_table + offset;
                fprintf(fp, "  PTE: %s => %llx\n",
                        mkstring(buf, VADDR_PRLEN, RJUST|LONGLONG_HEX,
                        MKSTR(&ull)), page_table_entry);
	}

        if (!(page_table_entry & (_PAGE_PRESENT | _PAGE_PROTNONE))) {
                if (page_table_entry && verbose) {
                        fprintf(fp, "\n");
                        x86_translate_pte(0, 0, page_table_entry);
                }

                goto no_kpage;
        }

	physpage = PAE_PAGEBASE(page_table_entry) + PAGEOFFSET(kvaddr);

        *paddr = physpage;

        if (verbose) {
		ull = PAE_PAGEBASE(page_table_entry);
                fprintf(fp, " PAGE: %s\n\n",
                        mkstring(buf, VADDR_PRLEN, RJUST|LONGLONG_HEX,
                        MKSTR(&ull)));
                x86_translate_pte(0, 0, page_table_entry);
        }

        return TRUE;

no_kpage:
	return FALSE;
}

static int
x86_kvtop_xen_wpt_PAE(struct task_context *tc, ulong kvaddr, physaddr_t *paddr, int verbose)
{
	ulonglong *pgd;
        ulonglong page_dir_entry;
        ulonglong page_middle, pseudo_page_middle;
        ulonglong page_middle_entry;
        ulonglong page_table, pseudo_page_table;
        ulonglong page_table_entry, pte;
        ulonglong physpage, pseudo_physpage;
        ulonglong ull;
        ulong offset;
	char buf[BUFSIZE];

        pgd = (ulonglong *)vt->kernel_pgd[0];

        if (verbose)
                fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)pgd);

        FILL_PGD(pgd, KVADDR, PTRS_PER_PGD * sizeof(ulonglong));

        offset = ((kvaddr >> PGDIR_SHIFT) & (PTRS_PER_PGD-1)) *
                sizeof(ulonglong);

        page_dir_entry = *((ulonglong *)&machdep->pgd[offset]);

        if (verbose)
                fprintf(fp, "  PGD: %s => %llx [machine]\n",
                        mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX,
                        MKSTR((ulong)pgd + offset)),
                        page_dir_entry);

        if (!(page_dir_entry & _PAGE_PRESENT)) {
                goto no_kpage;
        }

        page_middle = PAE_PAGEBASE(page_dir_entry);
	pseudo_page_middle = xen_m2p(page_middle); 

        if (verbose)
                fprintf(fp, "  PGD: %s => %llx\n",
                        mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX,
                        MKSTR((ulong)pgd + offset)),
			pseudo_page_middle | PAGEOFFSET(page_dir_entry) |
			(page_dir_entry & _PAGE_NX));

	FILL_PMD_PAE(pseudo_page_middle, PHYSADDR, PAGESIZE());

	offset = ((kvaddr >> PMD_SHIFT) & (PTRS_PER_PMD-1)) * sizeof(ulonglong);

        page_middle_entry = *((ulonglong *)&machdep->pmd[offset]);

        if (verbose) {
                ull = page_middle + offset;
                fprintf(fp, "  PMD: %s => %llx [machine]\n",
                        mkstring(buf, VADDR_PRLEN, RJUST|LONGLONG_HEX,
                        MKSTR(&ull)),
                        page_middle_entry);
	}

        if (!(page_middle_entry & _PAGE_PRESENT)) {
                goto no_kpage;
        }

        if (page_middle_entry & _PAGE_PSE) {
		error(FATAL, "_PAGE_PSE in an mfn not supported\n");  /* XXX */
                if (verbose) {
                        ull = PAE_PAGEBASE(page_middle_entry);
                        fprintf(fp, " PAGE: %s  (2MB)\n\n",
                                mkstring(buf, VADDR_PRLEN, RJUST|LONGLONG_HEX,
                                MKSTR(&ull)));
                        x86_translate_pte(0, 0, page_middle_entry);
                }

		physpage = PAE_PAGEBASE(page_middle_entry) +
			(kvaddr & ~_2MB_PAGE_MASK);
                *paddr = physpage;


                return TRUE;
        }

        page_table = PAE_PAGEBASE(page_middle_entry);
	pseudo_page_table = xen_m2p(page_table); 

        if (verbose) {
                ull = page_middle + offset;
                fprintf(fp, "  PMD: %s => %llx\n",
                        mkstring(buf, VADDR_PRLEN, RJUST|LONGLONG_HEX,
                        MKSTR(&ull)),
                        pseudo_page_table | PAGEOFFSET(page_middle_entry) | 
			(page_middle_entry & _PAGE_NX));
        }

        FILL_PTBL_PAE(pseudo_page_table, PHYSADDR, PAGESIZE());

	offset = ((kvaddr >> PAGESHIFT()) & (PTRS_PER_PTE-1)) * 
		sizeof(ulonglong);

        page_table_entry = *((ulonglong *)&machdep->ptbl[offset]);

        if (verbose) {
                ull = page_table + offset;
                fprintf(fp, "  PTE: %s => %llx [machine]\n",
                        mkstring(buf, VADDR_PRLEN, RJUST|LONGLONG_HEX,
                        MKSTR(&ull)), page_table_entry);
	}

        if (!(page_table_entry & (_PAGE_PRESENT | _PAGE_PROTNONE))) {
                if (page_table_entry && verbose) {
                        fprintf(fp, "\n");
                        x86_translate_pte(0, 0, page_table_entry);
                }

                goto no_kpage;
        }

	physpage = PAE_PAGEBASE(page_table_entry) + PAGEOFFSET(kvaddr);
	pseudo_physpage = xen_m2p(physpage); 

        if (verbose) {
                ull = page_table + offset;
                fprintf(fp, "  PTE: %s => %llx\n",
                        mkstring(buf, VADDR_PRLEN, RJUST|LONGLONG_HEX,
                        MKSTR(&ull)), 
			pseudo_physpage | PAGEOFFSET(page_table_entry) |
			(page_table_entry & _PAGE_NX));
        }

        *paddr = pseudo_physpage + PAGEOFFSET(kvaddr);

        if (verbose) {
		physpage = PAE_PAGEBASE(physpage);
                fprintf(fp, " PAGE: %s [machine]\n",
                        mkstring(buf, VADDR_PRLEN, RJUST|LONGLONG_HEX,
                        MKSTR(&physpage)));

                fprintf(fp, " PAGE: %s\n\n",
                        mkstring(buf, VADDR_PRLEN, RJUST|LONGLONG_HEX,
                        MKSTR(&pseudo_physpage)));

		pte = pseudo_physpage | PAGEOFFSET(page_table_entry) |
			(page_table_entry & _PAGE_NX);

		x86_translate_pte(0, 0, pte);
        }

        return TRUE;

no_kpage:
	return FALSE;
}

void
x86_clear_machdep_cache(void)
{
        machdep->machspec->last_pmd_read_PAE = 0;
        machdep->machspec->last_ptbl_read_PAE = 0;
}

/*
 *  Get the relevant page directory pointer from a task structure.
 */
static ulong
x86_get_task_pgd(ulong task)
{
	long offset;
	ulong cr3;

	offset = OFFSET_OPTION(task_struct_thread, task_struct_tss);

	if (INVALID_MEMBER(thread_struct_cr3))
		error(FATAL, 
		    "cr3 does not exist in this kernel's thread_struct\n"); 

	offset += OFFSET(thread_struct_cr3);

        readmem(task + offset, KVADDR, &cr3,
                sizeof(ulong), "task thread cr3", FAULT_ON_ERROR);

	return(PTOV(cr3));
}

/*
 *  Calculate and return the speed of the processor.
 */
ulong
x86_processor_speed(void)
{
	unsigned long cpu_hz, cpu_khz;

	if (machdep->mhz)
		return (machdep->mhz);

	if (symbol_exists("cpu_hz")) {
		get_symbol_data("cpu_hz", sizeof(long), &cpu_hz);
		if (cpu_hz)
			return (machdep->mhz = cpu_hz/1000000);
	}
	if (symbol_exists("cpu_khz")) {
		get_symbol_data("cpu_khz", sizeof(long), &cpu_khz);
		if (cpu_khz)
			return(machdep->mhz = cpu_khz/1000);
	}

	return 0;
}

void
x86_dump_machdep_table(ulong arg)
{
        int others;
	ulong xen_wpt;
	char buf[BUFSIZE];
	struct machine_specific *ms;
	int i, max_numnodes;

	switch (arg) {
	default:
		break;
	}

        others = 0;
        fprintf(fp, "              flags: %lx (", machdep->flags);
        if (machdep->flags & KSYMS_START)
                fprintf(fp, "%sKSYMS_START", others++ ? "|" : "");
        if (machdep->flags & PAE)
                fprintf(fp, "%sPAE", others++ ? "|" : "");
        if (machdep->flags & OMIT_FRAME_PTR)
                fprintf(fp, "%sOMIT_FRAME_PTR", others++ ? "|" : "");
        if (machdep->flags & FRAMESIZE_DEBUG)
                fprintf(fp, "%sFRAMESIZE_DEBUG", others++ ? "|" : "");
        fprintf(fp, ")\n");
        fprintf(fp, "             kvbase: %lx\n", machdep->kvbase);
	fprintf(fp, "  identity_map_base: %lx\n", machdep->identity_map_base);
	fprintf(fp, "           pagesize: %d\n", machdep->pagesize);
	fprintf(fp, "          pageshift: %d\n", machdep->pageshift);
	fprintf(fp, "           pagemask: %llx\n", machdep->pagemask);
	fprintf(fp, "         pageoffset: %lx\n", machdep->pageoffset);
	fprintf(fp, "          stacksize: %ld\n", machdep->stacksize);
        fprintf(fp, "                 hz: %d\n", machdep->hz);
        fprintf(fp, "                mhz: %ld\n", machdep->mhz);
        fprintf(fp, "            memsize: %lld (0x%llx)\n", 
		machdep->memsize, machdep->memsize);
	fprintf(fp, "               bits: %d\n", machdep->bits);
	fprintf(fp, "            nr_irqs: %d\n", machdep->nr_irqs);
        fprintf(fp, "      eframe_search: x86_eframe_search()\n");
        fprintf(fp, "         back_trace: x86_back_trace_cmd()\n");
        fprintf(fp, "get_processor_speed: x86_processor_speed()\n");
	xen_wpt = XEN() && (kt->xen_flags & WRITABLE_PAGE_TABLES);
	if (machdep->flags & PAE) {
        	fprintf(fp, "              uvtop: %s()\n", 
			xen_wpt ?  "x86_uvtop_xen_wpt_PAE" : "x86_uvtop_PAE");
        	fprintf(fp, "              kvtop: x86_kvtop_PAE()%s\n",
			xen_wpt ? " -> x86_kvtop_xen_wpt_PAE()" : "");
	} else {
        	fprintf(fp, "              uvtop: %s()\n", 
			xen_wpt ?  "x86_uvtop_xen_wpt" : "x86_uvtop");
        	fprintf(fp, "              kvtop: x86_kvtop()%s\n",
			xen_wpt ? " -> x86_kvtop_xen_wpt()" : "");
	}
        fprintf(fp, "       get_task_pgd: x86_get_task_pgd()\n");
	fprintf(fp, "           dump_irq: generic_dump_irq()\n");
	fprintf(fp, "   get_irq_affinity: generic_get_irq_affinity()\n");
	fprintf(fp, "    show_interrupts: generic_show_interrupts()\n");
	fprintf(fp, "    get_stack_frame: x86_get_stack_frame()\n");
	fprintf(fp, "      get_stackbase: generic_get_stackbase()\n");
	fprintf(fp, "       get_stacktop: generic_get_stacktop()\n");
	fprintf(fp, "      translate_pte: x86_translate_pte()\n");
	fprintf(fp, "        memory_size: x86_memory_size()\n");
	fprintf(fp, "      vmalloc_start: x86_vmalloc_start()\n");
	fprintf(fp, "       is_task_addr: x86_is_task_addr()\n");
	fprintf(fp, "      verify_symbol: x86_verify_symbol()\n");
	fprintf(fp, "         dis_filter: x86_dis_filter()\n");
	fprintf(fp, "           cmd_mach: x86_cmd_mach()\n");
	fprintf(fp, "       get_smp_cpus: x86_get_smp_cpus()\n");
	fprintf(fp, "          is_kvaddr: generic_is_kvaddr()\n");
	fprintf(fp, "          is_uvaddr: %s\n", COMMON_VADDR_SPACE() ?
                        "x86_is_uvaddr()" : "generic_is_uvaddr()");
	fprintf(fp, "       verify_paddr: generic_verify_paddr()\n");
        fprintf(fp, "    init_kernel_pgd: x86_init_kernel_pgd()\n");
	fprintf(fp, "    value_to_symbol: %s\n",
		machdep->value_to_symbol == generic_machdep_value_to_symbol ?
		"generic_machdep_value_to_symbol()" :
		"x86_is_entry_tramp_address()");
	fprintf(fp, "  line_number_hooks: %s\n", machdep->line_number_hooks ? 
		"x86_line_number_hooks" : "(not used)");
	fprintf(fp, "      last_pgd_read: %lx\n", machdep->last_pgd_read);
	fprintf(fp, "      last_pmd_read: %lx\n", machdep->last_pmd_read);
	fprintf(fp, "     last_ptbl_read: %lx\n", machdep->last_ptbl_read);
	fprintf(fp, "                pgd: %lx\n", (ulong)machdep->pgd);
	fprintf(fp, "                pmd: %lx\n", (ulong)machdep->pmd);
	fprintf(fp, "               ptbl: %lx\n", (ulong)machdep->ptbl);
	fprintf(fp, "       ptrs_per_pgd: %d\n", machdep->ptrs_per_pgd);
	fprintf(fp, "  section_size_bits: %ld\n", machdep->section_size_bits);
        fprintf(fp, "   max_physmem_bits: %ld\n", machdep->max_physmem_bits);
        fprintf(fp, "  sections_per_root: %ld\n", machdep->sections_per_root);
	fprintf(fp, " xendump_p2m_create: x86_xendump_p2m_create()\n");
	fprintf(fp, " xendump_p2m_create: %s\n", PVOPS_XEN() ?
		"x86_pvops_xendump_p2m_create()" : "x86_xendump_p2m_create()");
	fprintf(fp, " xendump_panic_task: x86_xendump_panic_task()\n");
	fprintf(fp, "   get_xendump_regs: x86_get_xendump_regs()\n");
	fprintf(fp, "xen_kdump_p2m_create: x86_xen_kdump_p2m_create()\n");
	fprintf(fp, "clear_machdep_cache: x86_clear_machdep_cache()\n");
	fprintf(fp, "   INT_EFRAME_[reg]:\n");
	fprintf(fp, "%s %d\n", 
		mkstring(buf, 21, RJUST, "SS: "), INT_EFRAME_SS);
	fprintf(fp, "%s %d\n", 
		mkstring(buf, 21, RJUST, "ESP: "), INT_EFRAME_ESP);
	fprintf(fp, "%s %d\n", 
		mkstring(buf, 21, RJUST, "EFLAGS: "), INT_EFRAME_EFLAGS);
	fprintf(fp, "%s %d\n", 
		mkstring(buf, 21, RJUST, "CS: "), INT_EFRAME_CS);
	fprintf(fp, "%s %d\n", 
		mkstring(buf, 21, RJUST, "IP: "), INT_EFRAME_EIP);
	fprintf(fp, "%s %d\n", 
		mkstring(buf, 21, RJUST, "ERR: "), INT_EFRAME_ERR);
	fprintf(fp, "%s %d\n", 
		mkstring(buf, 21, RJUST, "ES: "), INT_EFRAME_ES);
	fprintf(fp, "%s %d\n", 
		mkstring(buf, 21, RJUST, "DS: "), INT_EFRAME_DS);
	fprintf(fp, "%s %d\n", 
		mkstring(buf, 21, RJUST, "EAX: "), INT_EFRAME_EAX);
	fprintf(fp, "%s %d\n", 
		mkstring(buf, 21, RJUST, "EBP: "), INT_EFRAME_EBP);
	fprintf(fp, "%s %d\n", 
		mkstring(buf, 21, RJUST, "EDI: "), INT_EFRAME_EDI);
	fprintf(fp, "%s %d\n", 
		mkstring(buf, 21, RJUST, "ESI: "), INT_EFRAME_ESI);
	fprintf(fp, "%s %d\n", 
		mkstring(buf, 21, RJUST, "EDX: "), INT_EFRAME_EDX);
	fprintf(fp, "%s %d\n", 
		mkstring(buf, 21, RJUST, "ECX: "), INT_EFRAME_ECX);
	fprintf(fp, "%s %d\n", 
		mkstring(buf, 21, RJUST, "EBX: "), INT_EFRAME_EBX);
	fprintf(fp, "%s %d\n", 
		mkstring(buf, 21, RJUST, "GS: "), INT_EFRAME_GS);

        fprintf(fp, "           machspec: x86_machine_specific\n");
	fprintf(fp, "                     idt_table: %lx\n",
		(ulong)machdep->machspec->idt_table); 
	fprintf(fp, "             entry_tramp_start: %lx\n",
		machdep->machspec->entry_tramp_start);
	fprintf(fp, "               entry_tramp_end: %lx\n",
		machdep->machspec->entry_tramp_end);
	fprintf(fp, "        entry_tramp_start_phys: %llx\n",
		machdep->machspec->entry_tramp_start_phys);
	fprintf(fp, "             last_pmd_read_PAE: %llx\n",
		machdep->machspec->last_pmd_read_PAE);
	fprintf(fp, "            last_ptbl_read_PAE: %llx\n",
		machdep->machspec->last_ptbl_read_PAE);
	fprintf(fp, "                 page_protnone: %lx\n",
		machdep->machspec->page_protnone);

	ms = machdep->machspec;
	max_numnodes = ms->max_numnodes;
	fprintf(fp, "                  MAX_NUMNODES: ");
	if (max_numnodes < 0) {
		fprintf(fp, "(unused)\n");
	} else {
		fprintf(fp, "%d\n", max_numnodes);

		fprintf(fp, "             remap_start_vaddr:");
		for (i = 0; i < max_numnodes; ++i) {
			if ((i % 8) == 0)
				fprintf(fp, "\n        ");
			fprintf(fp, "%08lx ", ms->remap_start_vaddr[i]);
		}
		fprintf(fp, "\n");

		fprintf(fp, "               remap_end_vaddr:");
		for (i = 0; i < max_numnodes; ++i) {
			if ((i % 8) == 0)
				fprintf(fp, "\n        ");
			fprintf(fp, "%08lx ", ms->remap_end_vaddr[i]);
		}
		fprintf(fp, "\n");

		fprintf(fp, "               remap_start_pfn:");
		for (i = 0; i < max_numnodes; ++i) {
			if ((i % 8) == 0)
				fprintf(fp, "\n        ");
			fprintf(fp, "%08lx ", ms->remap_start_pfn[i]);
		}
		fprintf(fp, "\n");
	}
}

/*
 *  Get a stack frame combination of pc and ra from the most relevent spot.
 */
static void
x86_get_stack_frame(struct bt_info *bt, ulong *pcp, ulong *spp)
{
	if (pcp)  
		*pcp = x86_get_pc(bt);
	if (spp)
		*spp = x86_get_sp(bt);
}

/*
 *  Get the saved PC from a user-space copy of the kernel stack.
 */
static ulong 
x86_get_pc(struct bt_info *bt)
{
	ulong offset;
	ulong eip, inactive_task_frame;

	if (tt->flags & THREAD_INFO) {
		if (VALID_MEMBER(task_struct_thread_eip))
			readmem(bt->task + OFFSET(task_struct_thread_eip), KVADDR,
				&eip, sizeof(void *), 
				"thread_struct eip", FAULT_ON_ERROR);
		else if (VALID_MEMBER(inactive_task_frame_ret_addr)) {
			readmem(bt->task + OFFSET(task_struct_thread_esp), KVADDR,
				&inactive_task_frame, sizeof(void *),
				"task_struct.inactive_task_frame", FAULT_ON_ERROR);
			readmem(inactive_task_frame + OFFSET(inactive_task_frame_ret_addr), 
				KVADDR, &eip, sizeof(void *),
				"inactive_task_frame.ret_addr", FAULT_ON_ERROR);
		} else
			error(FATAL, "cannot determine ip address\n");
		return eip;
	}

	offset = OFFSET_OPTION(task_struct_thread_eip, task_struct_tss_eip);
	
	return GET_STACK_ULONG(offset);
}

/*
 *  Get the saved SP from a user-space copy of the kernel stack if it
 *  cannot be found in the panic_ksp array.
 */
static ulong 
x86_get_sp(struct bt_info *bt)
{
	ulong offset, ksp;

	if (get_panic_ksp(bt, &ksp))
		return ksp;

	if (tt->flags & THREAD_INFO) {
                readmem(bt->task + OFFSET(task_struct_thread_esp), KVADDR,
                        &ksp, sizeof(void *),
                        "thread_struct esp", FAULT_ON_ERROR);
		if (VALID_MEMBER(inactive_task_frame_ret_addr))
			ksp += OFFSET(inactive_task_frame_ret_addr);
                return ksp;
	} 

	offset = OFFSET_OPTION(task_struct_thread_esp, task_struct_tss_esp);

	return GET_STACK_ULONG(offset);
}


/*
 *  Translate a PTE, returning TRUE if the page is _PAGE_PRESENT.
 *  If a physaddr pointer is passed in, don't print anything.
 */
static int
x86_translate_pte(ulong pte, void *physaddr, ulonglong pae_pte)
{
	int c, len1, len2, len3, others, page_present;
	char buf[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char ptebuf[BUFSIZE];
	char physbuf[BUFSIZE];
	char *arglist[MAXARGS];
	ulonglong paddr;
	int nx_bit_set;

	nx_bit_set = FALSE;

	if (machdep->flags & PAE) {
        	paddr = PAE_PAGEBASE(pae_pte);
		sprintf(ptebuf, "%llx", pae_pte);
		if (pae_pte & _PAGE_NX)
			nx_bit_set = TRUE;
		pte = (ulong)pae_pte;
	} else { 
        	paddr = NONPAE_PAGEBASE(pte);
		sprintf(ptebuf, "%lx", pte);
	}

	page_present = (pte & (_PAGE_PRESENT|_PAGE_PROTNONE));

	if (physaddr) {
		if (machdep->flags & PAE) 
			*((ulonglong *)physaddr) = paddr;
		else
			*((ulong *)physaddr) = (ulong)paddr;
		return page_present;
	}

	len1 = MAX(strlen(ptebuf), strlen("PTE"));
	fprintf(fp, "%s  ", mkstring(buf, len1, CENTER|LJUST, "PTE"));

	if (!page_present && pte) {
		swap_location(machdep->flags & PAE ? pae_pte : pte, buf);
		if ((c = parse_line(buf, arglist)) != 3)
			error(FATAL, "cannot determine swap location\n");

		len2 = MAX(strlen(arglist[0]), strlen("SWAP"));
		len3 = MAX(strlen(arglist[2]), strlen("OFFSET"));

		fprintf(fp, "%s  %s\n", 
			mkstring(buf2, len2, CENTER|LJUST, "SWAP"),
			mkstring(buf3, len3, CENTER|LJUST, "OFFSET"));

		strcpy(buf2, arglist[0]);
		strcpy(buf3, arglist[2]);
		fprintf(fp, "%s  %s  %s\n",
                	mkstring(ptebuf, len1, CENTER|RJUST, NULL),
                	mkstring(buf2, len2, CENTER|RJUST, NULL),
                	mkstring(buf3, len3, CENTER|RJUST, NULL));

		return page_present;
	}

	sprintf(physbuf, "%llx", paddr);
	len2 = MAX(strlen(physbuf), strlen("PHYSICAL"));
	fprintf(fp, "%s  ", mkstring(buf, len2, CENTER|LJUST, "PHYSICAL"));

	fprintf(fp, "FLAGS\n");

	fprintf(fp, "%s  %s  ",  
		mkstring(ptebuf, len1, CENTER|RJUST, NULL),
		mkstring(physbuf, len2, CENTER|RJUST, NULL)); 
	fprintf(fp, "(");
	others = 0;

	if (pte) {
		if (pte & _PAGE_PRESENT)
			fprintf(fp, "%sPRESENT", others++ ? "|" : "");
		if (pte & _PAGE_RW)
			fprintf(fp, "%sRW", others++ ? "|" : "");
		if (pte & _PAGE_USER)
			fprintf(fp, "%sUSER", others++ ? "|" : "");
		if (pte & _PAGE_PWT)
			fprintf(fp, "%sPWT", others++ ? "|" : "");
		if (pte & _PAGE_PCD)
			fprintf(fp, "%sPCD", others++ ? "|" : "");
		if (pte & _PAGE_ACCESSED)
			fprintf(fp, "%sACCESSED", others++ ? "|" : "");
		if (pte & _PAGE_DIRTY)
			fprintf(fp, "%sDIRTY", others++ ? "|" : "");
		if ((pte & _PAGE_PSE) && (pte && _PAGE_PRESENT))
			fprintf(fp, "%sPSE", others++ ? "|" : "");
		if (pte & _PAGE_GLOBAL)
			fprintf(fp, "%sGLOBAL", others++ ? "|" : "");
		if (pte & _PAGE_PROTNONE && !(pte && _PAGE_PRESENT))
			fprintf(fp, "%sPROTNONE", others++ ? "|" : "");
		if (nx_bit_set)
			fprintf(fp, "%sNX", others++ ? "|" : "");
	} else { 
		fprintf(fp, "no mapping");
	}

	fprintf(fp, ")\n");

	return page_present;
}


/*
 *  For the time being, walk through the kernel page directory looking
 *  for the 4MB PTEs.  Zones might make this common code in the future.
 */

static uint64_t
x86_memory_size(void)
{
	int i, j;
        ulong *pp;
        ulong kpgd[PTRS_PER_PGD];
        uint64_t vm_total;
        uint64_t pgd_total;

	if (machdep->memsize)
		return machdep->memsize;

	if (!(machdep->flags & PAE)) {	
	        readmem(vt->kernel_pgd[0], KVADDR, kpgd, 
		    sizeof(ulong) * PTRS_PER_PGD,
	            "kernel page directory", FAULT_ON_ERROR);
	
	        for (i = j = 0, pp = &kpgd[0]; i < PTRS_PER_PGD; i++, pp++) {
	                if ((*pp & (_PAGE_PRESENT|_PAGE_4M)) ==
	                    (_PAGE_PRESENT|_PAGE_4M) ) {
	                        j++;
	                }
	        }
	        pgd_total = (uint64_t)j * (uint64_t)(MEGABYTES(4));
	} else
		pgd_total = 0;

       /*
	*  Use the memory node data (or its equivalent) if it's larger than
        *  the page directory total.
        */
	vm_total = total_node_memory();

	machdep->memsize = MAX(pgd_total, vm_total);

	return (machdep->memsize);
}

/*
 *  Determine where vmalloc'd memory starts.
 */
static ulong
x86_vmalloc_start(void)
{
	return (first_vmalloc_address());
}


/*
 *  Do the work for cmd_irq() -d option.
 */
void
x86_display_idt_table(void)
{
	int i;
	ulong *ip;
	char buf[BUFSIZE];

        ip = read_idt_table(READ_IDT_RUNTIME);

	for (i = 0; i < 256; i++, ip += 2) { 
		if (i < 10)
			fprintf(fp, "  ");
		else if (i < 100)
			fprintf(fp, " ");
		fprintf(fp, "[%d] %s\n", 
			i, extract_idt_function(ip, buf, NULL));
	}
}

/*
 *  Extract the function name out of the IDT entry.
 */
static char *
extract_idt_function(ulong *ip, char *buf, ulong *retaddr)
{
	ulong i1, i2, addr;
	char locbuf[BUFSIZE];
	physaddr_t phys;

	if (buf)
		BZERO(buf, BUFSIZE);

	i1 = *ip;
	i2 = *(ip+1);

	i1 &= 0x0000ffff;
	i2 &= 0xffff0000;

	addr = i1 | i2;
	if (retaddr)
		*retaddr = addr;

	if (!buf)
		return NULL;

	value_to_symstr(addr, locbuf, 0);
	if (strlen(locbuf))
		sprintf(buf, "%s", locbuf);
	else {
		sprintf(buf, "%08lx", addr);
		if (kvtop(NULL, addr, &phys, 0)) {
			addr = machdep->kvbase + (ulong)phys;
			if (value_to_symstr(addr, locbuf, 0)) {
				strcat(buf, "  <");
				strcat(buf, locbuf);
				strcat(buf, ">");
			}
		}
	}

	return buf;
}

/*
 *  Read the IDT table into a (hopefully) malloc'd buffer.
 */
static ulong *
read_idt_table(int flag)
{
	ulong *idt, addr, offset;
	physaddr_t phys;
	long desc_struct_size;
	struct syment *sp;
	struct machine_specific *ms;

	idt = NULL;
	ms = machdep->machspec;

	if (ms->idt_table)
		return ms->idt_table;

	desc_struct_size = SIZE(desc_struct) * 256;

	switch (flag)
	{
	case READ_IDT_INIT:
		if (!symbol_exists("idt_table"))
			return NULL;

       		if (!(idt = (ulong *)malloc(desc_struct_size))) {
			error(WARNING, "cannot malloc idt_table\n\n");
			return NULL;
		}

		if (!readmem(symbol_value("idt_table"), KVADDR, idt,
                    desc_struct_size, "idt_table", RETURN_ON_ERROR)) {
			error(WARNING, "cannot read idt_table\n\n");
			return NULL;
		}

               	ms->idt_table = idt;

		addr = 0;
		extract_idt_function(idt, NULL, &addr);

		if (addr) { 
			if (symbol_exists("__entry_tramp_start") &&
			    symbol_exists("__entry_tramp_end") &&
			    symbol_exists("__start___entry_text")) {
				ms->entry_tramp_start = 
					symbol_value("__start___entry_text");
				ms->entry_tramp_end = ms->entry_tramp_start +
					(symbol_value("__entry_tramp_end") -
					symbol_value("__entry_tramp_start"));
				ms->entry_tramp_start_phys = 0;
				machdep->value_to_symbol =
					x86_is_entry_tramp_address;
			} else if (!(sp = value_search(addr, &offset))) {
				addr = VIRTPAGEBASE(addr);
				if (kvtop(NULL, addr, &phys, 0) &&
				    (sp = value_search(PTOV(phys), &offset)) &&
				    STREQ(sp->name, "entry_tramp_start")) {
					ms->entry_tramp_start = 
						addr;
					ms->entry_tramp_start_phys = phys;
					ms->entry_tramp_end = addr + 
				 	    (symbol_value("entry_tramp_end") -
					    symbol_value("entry_tramp_start")); 
					machdep->value_to_symbol =
						x86_is_entry_tramp_address;
				}
			} 
		}
		break;

        case READ_IDT_RUNTIME:
		if (!symbol_exists("idt_table"))
			error(FATAL, 
			    "idt_table does not exist on this architecture\n");

		idt = (ulong *)GETBUF(desc_struct_size);
                readmem(symbol_value("idt_table"), KVADDR, idt,
                        desc_struct_size, "idt_table", FAULT_ON_ERROR);
                break;
	}

	return idt;
}

/* 
 *  If the address fits in the entry_tramp_start page, find the syment
 *  associated with it.
 */
struct syment *
x86_is_entry_tramp_address(ulong vaddr, ulong *retoffset)
{
	struct syment *sp;
	struct machine_specific *ms;
	ulong addr, offset;

	ms = machdep->machspec;

	if (!ms->entry_tramp_start ||
	    !((vaddr >= ms->entry_tramp_start) &&
	    (vaddr <= ms->entry_tramp_end))) 
		return NULL;

	/*
	 *  Check new vs. old style handling of entry_tramp addresses:
	 *
	 *   - The old way requires creation of the real symbol address from
	 *     the entry_tramp address passed in.
	 *   - The new way just uses the absolute (A) symbols that are built 
         *     in using the entry_tramp addresses, w/no phys address required.
	 */
	if (ms->entry_tramp_start_phys)  /* old */
		addr = machdep->kvbase + (ulong)ms->entry_tramp_start_phys + 
			PAGEOFFSET(vaddr);
	else                             /* new */
		addr = vaddr;

	if ((sp = value_search_base_kernel(addr, &offset))) {
		if (retoffset)
			*retoffset = offset;
		if (CRASHDEBUG(4))
  			console("x86_is_entry_tramp_address: %lx: %s %lx+%ld\n",
				vaddr, sp->name, sp->value, offset); 
		if (STREQ(sp->name, "entry_tramp_start"))
			sp++;
	}

	return sp;
}


/*
 *  X86 tasks are all stacksize-aligned, except when split from the stack.
 */
static int
x86_is_task_addr(ulong task)
{
	if (tt->flags & THREAD_INFO)
		return IS_KVADDR(task);
	else
		return (IS_KVADDR(task) && (ALIGNED_STACK_OFFSET(task) == 0));
}


/*
 *  Keep or reject a symbol from the namelist.
 */
static int
x86_verify_symbol(const char *name, ulong value, char type)
{
	if (XEN_HYPER_MODE() && STREQ(name, "__per_cpu_shift"))
		return TRUE;

	if (CRASHDEBUG(8) && name && strlen(name))
		fprintf(fp, "%08lx %s\n", value, name);

	if (STREQ(name, "_text") || STREQ(name, "_stext"))
		machdep->flags |= KSYMS_START;

	if (!name || !strlen(name) || !(machdep->flags & KSYMS_START))
		return FALSE;

	if ((type == 'A') && STRNEQ(name, "__crc_"))
		return FALSE;

        if (STREQ(name, "Letext") || STREQ(name, "gcc2_compiled."))
		return FALSE;

	return TRUE;
}

/*
 *  Filter disassembly output if the output radix is not gdb's default 10
 */
static int 
x86_dis_filter(ulong vaddr, char *inbuf, unsigned int output_radix)
{
        char buf1[BUFSIZE];
        char buf2[BUFSIZE];
        char *colon, *p1;
        int argc;
        char *argv[MAXARGS];
        ulong value;

	if (!inbuf) 
		return TRUE;
/*
 *  For some reason gdb can go off into the weeds translating text addresses,
 *  (on alpha -- not necessarily seen on x86) so this routine both fixes the 
 *  references as well as imposing the current output radix on the translations.
 */
	if (CRASHDEBUG(1))
		console("IN: %s", inbuf);

	colon = (inbuf[0] != ' ') ? strstr(inbuf, ":") : NULL;

	if (colon) {
		sprintf(buf1, "0x%lx <%s>", vaddr,
			value_to_symstr(vaddr, buf2, output_radix));
		sprintf(buf2, "%s%s", buf1, colon);
		strcpy(inbuf, buf2);
	}

	strcpy(buf1, inbuf);
	argc = parse_line(buf1, argv);

	if ((FIRSTCHAR(argv[argc-1]) == '<') && 
	    (LASTCHAR(argv[argc-1]) == '>')) {
		p1 = rindex(inbuf, '<');
		while ((p1 > inbuf) && !STRNEQ(p1, " 0x")) 
			p1--;

		if (!STRNEQ(p1, " 0x"))
			return FALSE;
		p1++;

		if (!extract_hex(p1, &value, NULLCHAR, TRUE))
			return FALSE;

		sprintf(buf1, "0x%lx <%s>\n", value,	
			value_to_symstr(value, buf2, output_radix));

		sprintf(p1, "%s", buf1);
	} else if (STREQ(argv[argc-2], "call") && 
	    hexadecimal(argv[argc-1], 0)) {
		/* 
		 *  Update module code of the form:
		 *
		 *    call   0xe081e1e0
		 *
		 *  to show a bracketed direct call target.
		 */
		p1 = &LASTCHAR(inbuf);

                if (extract_hex(argv[argc-1], &value, NULLCHAR, TRUE)) {
                	sprintf(buf1, " <%s>\n",
				value_to_symstr(value, buf2,
                                output_radix));
                        if (IS_MODULE_VADDR(value) &&
                            !strstr(buf2, "+"))
                                sprintf(p1, "%s", buf1);
		}
	} 
	else if (STREQ(argv[2], "ud2a"))
		pc->curcmd_flags |= UD2A_INSTRUCTION;
	else if (STREQ(argv[2], "(bad)"))
		pc->curcmd_flags |= BAD_INSTRUCTION;

	if (CRASHDEBUG(1))
		console("    %s", inbuf);

	return TRUE;
}


/*
 *   Override smp_num_cpus if possible and necessary.
 */
int
x86_get_smp_cpus(void)
{
	int count, cpucount;

	if ((count = get_cpus_online()) == 0) {
		count = kt->cpus;

		if (symbol_exists("cpucount")) {
			get_symbol_data("cpucount", sizeof(int), &cpucount);
			cpucount++;
			count = MAX(cpucount, kt->cpus);
		} 
	}

	if (XEN() && (count == 1) && symbol_exists("cpu_present_map")) {
        	ulong cpu_present_map;

        	get_symbol_data("cpu_present_map", sizeof(ulong), 
			&cpu_present_map);

        	cpucount = count_bits_long(cpu_present_map);
		count = MAX(cpucount, kt->cpus);
	}

	if (KVMDUMP_DUMPFILE() && (count < get_cpus_present()))
		return(get_highest_cpu_present()+1);

	return MAX(count, get_highest_cpu_online()+1);
}


/*
 *  Machine dependent command.
 */
void
x86_cmd_mach(void)
{
        int c, cflag, mflag;
	unsigned int radix;

	cflag = mflag = radix = 0;

        while ((c = getopt(argcnt, args, "cmxd")) != EOF) {
                switch(c)
                {
		case 'c':
			cflag++;
			break;			

                case 'm':
			mflag++;
                        x86_display_memmap();
                        break;

		case 'x':
			if (radix == 10)
				error(FATAL,
					"-d and -x are mutually exclusive\n");
			radix = 16;
			break;

		case 'd':
			if (radix == 16)
				error(FATAL,
					"-d and -x are mutually exclusive\n");
			radix = 10;
		break;

                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

	if (cflag)
		x86_display_cpu_data(radix);

	if (!cflag && !mflag)
		x86_display_machine_stats();
}

/*
 *  "mach" command output.
 */
static void
x86_display_machine_stats(void)
{
	int c;
        struct new_utsname *uts;
	char buf[BUFSIZE];
	ulong mhz;

        uts = &kt->utsname;

        fprintf(fp, "       MACHINE TYPE: %s\n", uts->machine);
        fprintf(fp, "        MEMORY SIZE: %s\n", get_memory_size(buf));
	fprintf(fp, "               CPUS: %d\n", kt->cpus);
	if (!STREQ(kt->hypervisor, "(undetermined)") &&
	    !STREQ(kt->hypervisor, "bare hardware"))
		fprintf(fp, "         HYPERVISOR: %s\n",  kt->hypervisor);
	fprintf(fp, "    PROCESSOR SPEED: ");
	if ((mhz = machdep->processor_speed())) 
		fprintf(fp, "%ld Mhz\n", mhz);
	else
		fprintf(fp, "(unknown)\n");
	fprintf(fp, "                 HZ: %d\n", machdep->hz);
	fprintf(fp, "          PAGE SIZE: %d\n", PAGESIZE());
//	fprintf(fp, "      L1 CACHE SIZE: %d\n", l1_cache_size());
	fprintf(fp, "KERNEL VIRTUAL BASE: %lx\n", machdep->kvbase);
	fprintf(fp, "KERNEL VMALLOC BASE: %lx\n", vt->vmalloc_start);
	fprintf(fp, "  KERNEL STACK SIZE: %ld\n", STACKSIZE());

	if (tt->flags & IRQSTACKS) {
		fprintf(fp, "HARD IRQ STACK SIZE: %ld\n", STACKSIZE());
		fprintf(fp, "    HARD IRQ STACKS:\n");
	
		for (c = 0; c < kt->cpus; c++) {
			if (!tt->hardirq_ctx[c])
				break;
			sprintf(buf, "CPU %d", c);
			fprintf(fp, "%19s: %lx\n", buf, tt->hardirq_ctx[c]);
		}

		fprintf(fp, "SOFT IRQ STACK SIZE: %ld\n", STACKSIZE());
		fprintf(fp, "    SOFT IRQ STACKS:\n");
		for (c = 0; c < kt->cpus; c++) {
			if (!tt->softirq_ctx)
				break;
			sprintf(buf, "CPU %d", c);
			fprintf(fp, "%19s: %lx\n", buf, tt->softirq_ctx[c]);
		}
	}
}

static void
x86_display_cpu_data(unsigned int radix)
{
	int cpu;
	ulong cpu_data = 0;
	
	if (symbol_exists("cpu_data"))
		cpu_data = symbol_value("cpu_data");
	else if (symbol_exists("boot_cpu_data"))
		cpu_data = symbol_value("boot_cpu_data");

	for (cpu = 0; cpu < kt->cpus; cpu++) {
		fprintf(fp, "%sCPU %d:\n", cpu ? "\n" : "", cpu);
		dump_struct("cpuinfo_x86", cpu_data, radix);	
		cpu_data += SIZE(cpuinfo_x86);
	}
}

static char *e820type[] = {
	"(invalid type)",
	"E820_RAM",
	"E820_RESERVED",
	"E820_ACPI",
	"E820_NVS",
	"E820_UNUSABLE",
};

static void
x86_display_memmap(void)
{
        ulong e820;
        int nr_map, i;
        char *buf, *e820entry_ptr;
        ulonglong addr, size;
        uint type;

	if (kernel_symbol_exists("e820")) {
		if (get_symbol_type("e820", NULL, NULL) == TYPE_CODE_PTR)
			get_symbol_data("e820", sizeof(void *), &e820);
		else
			e820 = symbol_value("e820");

	} else if (kernel_symbol_exists("e820_table"))
		get_symbol_data("e820_table", sizeof(void *), &e820);
	else
		error(FATAL, "neither e820 or e820_table symbols exist\n");

	if (CRASHDEBUG(1)) {
		if (STRUCT_EXISTS("e820map"))
			dump_struct("e820map", e820, RADIX(16));
		else if (STRUCT_EXISTS("e820_table"))
			dump_struct("e820_table", e820, RADIX(16));
	}
        buf = (char *)GETBUF(SIZE(e820map));

        readmem(e820, KVADDR, &buf[0], SIZE(e820map),
                "e820map", FAULT_ON_ERROR);

        nr_map = INT(buf + OFFSET(e820map_nr_map));

        fprintf(fp, "      PHYSICAL ADDRESS RANGE         TYPE\n");

        for (i = 0; i < nr_map; i++) {
                e820entry_ptr = buf + sizeof(int) + (SIZE(e820entry) * i);
                addr = ULONGLONG(e820entry_ptr + OFFSET(e820entry_addr));
                size = ULONGLONG(e820entry_ptr + OFFSET(e820entry_size));
                type = UINT(e820entry_ptr + OFFSET(e820entry_type));
		fprintf(fp, "%016llx - %016llx  ", addr, addr+size);
		if (type >= (sizeof(e820type)/sizeof(char *))) {
			if (type == 12)
				fprintf(fp, "E820_PRAM\n");
			else if (type == 128)
				fprintf(fp, "E820_RESERVED_KERN\n");
			else
				fprintf(fp, "type %d\n", type);
		} else
			fprintf(fp, "%s\n", e820type[type]);
        }
}

/*
 *  Check a few functions to determine whether the kernel was built
 *  with the -fomit-frame-pointer flag.
 */
#define PUSH_BP_MOV_ESP_BP 0xe58955
#define PUSH_BP_CLR_EAX_MOV_ESP_BP 0xe589c03155ULL

static int
x86_omit_frame_pointer(void)
{
	ulonglong push_bp_mov_esp_bp;
        int i;
        char *checkfuncs[] = {"sys_open", "sys_fork", "sys_read"};

	if (pc->flags & KERNEL_DEBUG_QUERY)
		return FALSE;

        for (i = 0; i < 2; i++) {
                if (!readmem(symbol_value(checkfuncs[i]), KVADDR,
                    &push_bp_mov_esp_bp, sizeof(ulonglong),
                    "x86_omit_frame_pointer", RETURN_ON_ERROR))
                        return TRUE;
                if (!(((push_bp_mov_esp_bp & 0x0000ffffffULL) == 
		    PUSH_BP_MOV_ESP_BP) ||
                    ((push_bp_mov_esp_bp & 0xffffffffffULL) ==
                    PUSH_BP_CLR_EAX_MOV_ESP_BP)))
                        return TRUE;
        }

	return FALSE;
}

/*
 *  Disassemble an address and determine whether the instruction calls
 *  a function; if so, return a pointer to the name of the called function.
 */
char *
x86_function_called_by(ulong eip)
{
	struct syment *sp;
	char buf[BUFSIZE], *p1, *p2, *funcname;
	ulong value, offset;
	unsigned char byte;

	funcname = NULL;
	
        if (!readmem(eip, KVADDR, &byte, sizeof(unsigned char), "call byte",
            RETURN_ON_ERROR)) 
		return funcname;
        if (byte != 0xe8) 
		return funcname;

        sprintf(buf, "x/i 0x%lx", eip);

        open_tmpfile2();
        if (gdb_pass_through(buf, pc->tmpfile2, GNU_RETURN_ON_ERROR)) {
	        rewind(pc->tmpfile2);
	        while (fgets(buf, BUFSIZE, pc->tmpfile2)) {
			if ((p1 = strstr(buf, "call   "))) {
				p1 += strlen("call   ");
				if ((p2 = strstr(p1, " <"))) {
					p2 += strlen(" <");
					if ((p1 = strstr(p2, ">")))
						*p1 = NULLCHAR;
					if ((sp = symbol_search(p2)))
						funcname = sp->name;
				} else if ((p2 = strstr(p1, "0x"))) {
					if (!extract_hex(strip_linefeeds(p2),
					    &value, NULLCHAR, TRUE))
						continue;
					if ((sp = value_search(value, &offset))
					    && !offset)
						funcname = sp->name;
				} 
			}
	        }
	}
        close_tmpfile2();

	return funcname;
}

struct syment *
x86_text_lock_jmp(ulong eip, ulong *offset)
{
	int i, c;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
        char *arglist[MAXARGS];
	struct syment *sp;
	ulong value;
	
        sprintf(buf1, "x/10i 0x%lx", eip);
	buf2[0] = NULLCHAR;
	value = 0;

        open_tmpfile2();
        if (gdb_pass_through(buf1, pc->tmpfile2, GNU_RETURN_ON_ERROR)) {
                rewind(pc->tmpfile2);
                while (fgets(buf1, BUFSIZE, pc->tmpfile2)) {
			if (!(c = parse_line(buf1, arglist)))
				continue;
			for (i = 0; i < c; i++) {
				if (STREQ(arglist[i], "jmp") && ((i+1)<c)) {
					strcpy(buf2, arglist[i+1]);
					goto done;
				}
			}
                }
        }
done:
        close_tmpfile2();

	if (strlen(buf2)) {
		value = htol(buf2, RETURN_ON_ERROR, NULL);
		if (value == BADADDR)
			return NULL;
	}

        return ((sp = value_search(value, offset))); 
}

static void
x86_init_kernel_pgd(void)
{
        int i;
	ulong value = 0;

	if (XEN()) { 
		if (PVOPS_XEN())
     			value = symbol_value("swapper_pg_dir");
		else
			get_symbol_data("swapper_pg_dir", sizeof(ulong), &value);
	} else
     		value = symbol_value("swapper_pg_dir");

       	for (i = 0; i < NR_CPUS; i++)
       		vt->kernel_pgd[i] = value;

}

static ulong
xen_m2p_nonPAE(ulong machine)
{
	ulonglong pseudo;

	pseudo = xen_m2p((ulonglong)machine);

	if (pseudo == XEN_MACHADDR_NOT_FOUND)
		return XEN_MFN_NOT_FOUND;

	return ((ulong)pseudo);
}

#include "netdump.h"
#include "xen_dom0.h"

/*
 *  From the xen vmcore, create an index of mfns for each page that makes 
 *  up the dom0 kernel's complete phys_to_machine_mapping[max_pfn] array.
 */

#define MAX_X86_FRAMES  (16)    
#define MFNS_PER_FRAME  (PAGESIZE()/sizeof(ulong))

static int 
x86_xen_kdump_p2m_create(struct xen_kdump_data *xkd)
{
	int i, j;
	ulong kvaddr;
	ulong *up;
	ulonglong *ulp;
	ulong frames;
	ulong frame_mfn[MAX_X86_FRAMES] = { 0 };
	int mfns[MAX_X86_FRAMES] = { 0 };

	/*
	 *  Temporarily read physical (machine) addresses from vmcore.
	 */ 
	pc->curcmd_flags |= XEN_MACHINE_ADDR;
	if (CRASHDEBUG(1)) 
		fprintf(fp, "readmem (temporary): force XEN_MACHINE_ADDR\n");

	if (xkd->flags & KDUMP_CR3)
		goto use_cr3;

        xkd->p2m_frames = 0;

	if (CRASHDEBUG(1))
		fprintf(fp, "x86_xen_kdump_p2m_create: p2m_mfn: %lx\n",
			xkd->p2m_mfn);

	if (!readmem(PTOB(xkd->p2m_mfn), PHYSADDR, xkd->page, PAGESIZE(), 
	    "xen kdump p2m mfn page", RETURN_ON_ERROR))
		error(FATAL, "cannot read xen kdump p2m mfn page\n");

	if (CRASHDEBUG(1)) {
		up = (ulong *)xkd->page;
		for (i = 0; i < 4; i++) {
                	fprintf(fp, "%08lx: %08lx %08lx %08lx %08lx\n",
                        	(ulong)((i * 4) * sizeof(ulong)),
                        	*up, *(up+1), *(up+2), *(up+3));
                        up += 4;
		}
		fprintf(fp, "\n");
	}

	for (i = 0, up = (ulong *)xkd->page; i < MAX_X86_FRAMES; i++, up++)
		frame_mfn[i] = *up;

	for (i = 0; i < MAX_X86_FRAMES; i++) {
		if (!frame_mfn[i])
			break;

        	if (!readmem(PTOB(frame_mfn[i]), PHYSADDR, xkd->page, 
		    PAGESIZE(), "xen kdump p2m mfn list page", RETURN_ON_ERROR))
                	error(FATAL, "cannot read xen kdump p2m mfn list page\n");

		for (j = 0, up = (ulong *)xkd->page; j < MFNS_PER_FRAME; j++, up++)
			if (*up)
				mfns[i]++;

		xkd->p2m_frames += mfns[i];
		
	        if (CRASHDEBUG(7)) {
	                up = (ulong *)xkd->page;
	                for (j = 0; j < 256; j++) {
	                        fprintf(fp, "%08lx: %08lx %08lx %08lx %08lx\n",
	                                (ulong)((j * 4) * sizeof(ulong)),
	                                *up, *(up+1), *(up+2), *(up+3));
	                        up += 4;
	                }
	        }
	}

        if (CRASHDEBUG(1))
		fprintf(fp, "p2m_frames: %d\n", xkd->p2m_frames);

        if ((xkd->p2m_mfn_frame_list = (ulong *)
	    malloc(xkd->p2m_frames * sizeof(ulong))) == NULL)
                error(FATAL, "cannot malloc p2m_frame_index_list");

	for (i = 0, frames = xkd->p2m_frames; frames; i++) {
        	if (!readmem(PTOB(frame_mfn[i]), PHYSADDR, 
		    &xkd->p2m_mfn_frame_list[i * MFNS_PER_FRAME], 
		    mfns[i] * sizeof(ulong), "xen kdump p2m mfn list page", 
		    RETURN_ON_ERROR))
                	error(FATAL, "cannot read xen kdump p2m mfn list page\n");

		frames -= mfns[i];
	}

        if (CRASHDEBUG(2)) {
                for (i = 0; i < xkd->p2m_frames; i++)
                        fprintf(fp, "%lx ", xkd->p2m_mfn_frame_list[i]);
                fprintf(fp, "\n");
        }

	pc->curcmd_flags &= ~XEN_MACHINE_ADDR;
	if (CRASHDEBUG(1)) 
		fprintf(fp, "readmem (restore): p2m translation\n");

	return TRUE;

use_cr3:
	if (CRASHDEBUG(1))
		fprintf(fp, "x86_xen_kdump_p2m_create: cr3: %lx\n", xkd->cr3);

	if (!readmem(PTOB(xkd->cr3), PHYSADDR, machdep->pgd, PAGESIZE(), 
	    "xen kdump cr3 page", RETURN_ON_ERROR))
		error(FATAL, "cannot read xen kdump cr3 page\n");

	if (CRASHDEBUG(7)) {
		fprintf(fp, "contents of page directory page:\n");	

		if (machdep->flags & PAE) {
			ulp = (ulonglong *)machdep->pgd;
			fprintf(fp, 
			    "%016llx %016llx %016llx %016llx\n",
				*ulp, *(ulp+1), *(ulp+2), *(ulp+3));
		} else {
			up = (ulong *)machdep->pgd;
			for (i = 0; i < 256; i++) {
				fprintf(fp, 
				    "%08lx: %08lx %08lx %08lx %08lx\n", 
					(ulong)((i * 4) * sizeof(ulong)),
					*up, *(up+1), *(up+2), *(up+3));
				up += 4;
			}
		}
	}

	kvaddr = symbol_value("max_pfn");
        if (!x86_xen_kdump_load_page(kvaddr, xkd->page))
                return FALSE;
	up = (ulong *)(xkd->page + PAGEOFFSET(kvaddr));

        xkd->p2m_frames = (*up/(PAGESIZE()/sizeof(ulong))) +
		((*up%(PAGESIZE()/sizeof(ulong))) ? 1 : 0);

        if (CRASHDEBUG(1))
                fprintf(fp, "max_pfn at %lx: %lx (%ld) -> %d p2m_frames\n", 
			kvaddr, *up, *up, xkd->p2m_frames);

        if ((xkd->p2m_mfn_frame_list = (ulong *)
            malloc(xkd->p2m_frames * sizeof(ulong))) == NULL)
                error(FATAL, "cannot malloc p2m_frame_index_list");

        kvaddr = symbol_value("phys_to_machine_mapping");
        if (!x86_xen_kdump_load_page(kvaddr, xkd->page))
                return FALSE;
        up = (ulong *)(xkd->page + PAGEOFFSET(kvaddr));
        kvaddr = *up;
        if (CRASHDEBUG(1))
                fprintf(fp, "phys_to_machine_mapping: %lx\n", kvaddr);

        if (CRASHDEBUG(7)) {
                fprintf(fp, "contents of first phys_to_machine_mapping page:\n");
        	if (!x86_xen_kdump_load_page(kvaddr, xkd->page))
			error(INFO, 
			    "cannot read first phys_to_machine_mapping page\n");

                 up = (ulong *)xkd->page;
                 for (i = 0; i < 256; i++) {
                         fprintf(fp, "%08lx: %08lx %08lx %08lx %08lx\n",
                         	(ulong)((i * 4) * sizeof(ulong)),
                         	*up, *(up+1), *(up+2), *(up+3));
                         up += 4;
                 }
        }

        machdep->last_ptbl_read = BADADDR;
        machdep->last_pmd_read = BADADDR;
        machdep->last_pgd_read = BADADDR;

        for (i = 0; i < xkd->p2m_frames; i++) {
                xkd->p2m_mfn_frame_list[i] = x86_xen_kdump_page_mfn(kvaddr);
                kvaddr += PAGESIZE();
        }

        if (CRASHDEBUG(1)) {
        	for (i = 0; i < xkd->p2m_frames; i++)
			fprintf(fp, "%lx ", xkd->p2m_mfn_frame_list[i]);
		fprintf(fp, "\n");
	}

        machdep->last_ptbl_read = 0;
        machdep->last_pmd_read = 0;
        machdep->last_pgd_read = 0;
	pc->curcmd_flags &= ~XEN_MACHINE_ADDR;
	if (CRASHDEBUG(1)) 
		fprintf(fp, "readmem (restore): p2m translation\n");

	return TRUE;
}

/*
 *  Find the page associate with the kvaddr, and read its contents
 *  into the passed-in buffer.
 */
static char *
x86_xen_kdump_load_page(ulong kvaddr, char *pgbuf)
{
        ulong *entry;
        ulong *up;
        ulong mfn;

        if (machdep->flags & PAE)
                return x86_xen_kdump_load_page_PAE(kvaddr, pgbuf);

        up = (ulong *)machdep->pgd;
        entry = up + (kvaddr >> PGDIR_SHIFT);
        mfn = (*entry) >> PAGESHIFT();

	if (!readmem(PTOB(mfn), PHYSADDR, pgbuf, PAGESIZE(), 
	    "xen kdump pgd entry", RETURN_ON_ERROR)) {
                error(INFO, "cannot read/find pgd entry from cr3 page\n");
		return NULL;
	}

        up = (ulong *)pgbuf;
        entry = up + ((kvaddr >> 12) & (PTRS_PER_PTE-1));
        mfn = (*entry) >> PAGESHIFT();

	if (!readmem(PTOB(mfn), PHYSADDR, pgbuf, PAGESIZE(), 
	    "xen page table page", RETURN_ON_ERROR)) {
                error(INFO, "cannot read/find page table page\n");
		return NULL;
	}

	return pgbuf;
}

static char *
x86_xen_kdump_load_page_PAE(ulong kvaddr, char *pgbuf)
{
	ulonglong *entry;
	ulonglong *up;
	ulong mfn;

        up = (ulonglong *)machdep->pgd;
        entry = up + (kvaddr >> PGDIR_SHIFT);
        mfn = (ulong)((*entry) >> PAGESHIFT());

	if (!readmem(PTOB(mfn), PHYSADDR, pgbuf, PAGESIZE(), 
	    "xen kdump pgd entry", RETURN_ON_ERROR)) {
                error(INFO, "cannot read/find pgd entry from cr3 page\n");
                return NULL;
        }

        up = (ulonglong *)pgbuf;
        entry = up + ((kvaddr >> PMD_SHIFT) & (PTRS_PER_PMD-1));
        mfn = (ulong)((*entry) >> PAGESHIFT());

	if (!readmem(PTOB(mfn), PHYSADDR, pgbuf, PAGESIZE(), 
	    "xen kdump pmd entry", RETURN_ON_ERROR)) {
                error(INFO, "cannot read/find pmd entry from pgd\n");
                return NULL;
        }

        up = (ulonglong *)pgbuf;
        entry = up + ((kvaddr >> PAGESHIFT()) & (PTRS_PER_PTE-1));
        mfn = (ulong)((*entry) >> PAGESHIFT());

	if (!readmem(PTOB(mfn), PHYSADDR, pgbuf, PAGESIZE(), 
	    "xen kdump page table page", RETURN_ON_ERROR)) {
                error(INFO, "cannot read/find page table page from pmd\n");
                return NULL;
        }

	return pgbuf;
}

/*
 *  Return the mfn value associated with a virtual address.
 */
static ulong 
x86_xen_kdump_page_mfn(ulong kvaddr)
{
        ulong *entry;
        ulong *up;
        ulong mfn;

        if (machdep->flags & PAE)
                return x86_xen_kdump_page_mfn_PAE(kvaddr);

        up = (ulong *)machdep->pgd;
        entry = up + (kvaddr >> PGDIR_SHIFT);
        mfn = (*entry) >> PAGESHIFT();

	if ((mfn != machdep->last_ptbl_read) && 
	    !readmem(PTOB(mfn), PHYSADDR, machdep->ptbl, PAGESIZE(), 
	    "xen kdump pgd entry", RETURN_ON_ERROR))
                error(FATAL, 
		    "cannot read/find pgd entry from cr3 page (mfn: %lx)\n", 
			mfn);
	machdep->last_ptbl_read = mfn;

        up = (ulong *)machdep->ptbl;
        entry = up + ((kvaddr >> 12) & (PTRS_PER_PTE-1));
        mfn = (*entry) >> PAGESHIFT();

	return mfn;
}

static ulong
x86_xen_kdump_page_mfn_PAE(ulong kvaddr)
{
	ulonglong *entry;
	ulonglong *up;
	ulong mfn;

        up = (ulonglong *)machdep->pgd;
        entry = up + (kvaddr >> PGDIR_SHIFT);
        mfn = (ulong)((*entry) >> PAGESHIFT());

	if ((mfn != machdep->last_pmd_read) &&
	    !readmem(PTOB(mfn), PHYSADDR, machdep->pmd, PAGESIZE(), 
	    "xen kdump pgd entry", RETURN_ON_ERROR))
                error(FATAL, 
		    "cannot read/find pgd entry from cr3 page (mfn: %lx)\n",
			mfn);
	machdep->last_pmd_read = mfn;

        up = (ulonglong *)machdep->pmd;
        entry = up + ((kvaddr >> PMD_SHIFT) & (PTRS_PER_PMD-1));
        mfn = (ulong)((*entry) >> PAGESHIFT());

	if ((mfn != machdep->last_ptbl_read) &&
	    !readmem(PTOB(mfn), PHYSADDR, machdep->ptbl, PAGESIZE(), 
	    "xen kdump pmd entry", RETURN_ON_ERROR))
                error(FATAL, 
		    "cannot read/find pmd entry from pgd (mfn: %lx)\n",
			mfn);
	machdep->last_ptbl_read = mfn;

        up = (ulonglong *)machdep->ptbl;
        entry = up + ((kvaddr >> PAGESHIFT()) & (PTRS_PER_PTE-1));
        mfn = (ulong)((*entry) >> PAGESHIFT());

	return mfn;
}

#include "xendump.h"

/*
 *  Create an index of mfns for each page that makes up the
 *  kernel's complete phys_to_machine_mapping[max_pfn] array.
 */
static int 
x86_xendump_p2m_create(struct xendump_data *xd)
{
	int i, idx;
	ulong mfn, kvaddr, ctrlreg[8], ctrlreg_offset;
	ulong *up;
	ulonglong *ulp;
	off_t offset; 

	/*
	 *  Check for pvops Xen kernel before presuming it's HVM.
	 */
	if (symbol_exists("pv_init_ops") &&
	    (symbol_exists("xen_patch") || symbol_exists("paravirt_patch_default")) &&
	    (xd->xc_core.header.xch_magic == XC_CORE_MAGIC))
		return x86_pvops_xendump_p2m_create(xd);

        if (!symbol_exists("phys_to_machine_mapping")) {
                xd->flags |= XC_CORE_NO_P2M;
                return TRUE;
        }

	if ((ctrlreg_offset = MEMBER_OFFSET("vcpu_guest_context", "ctrlreg")) ==
	     INVALID_OFFSET)
		error(FATAL, 
		    "cannot determine vcpu_guest_context.ctrlreg offset\n");
	else if (CRASHDEBUG(1))
		fprintf(xd->ofp, 
		    "MEMBER_OFFSET(vcpu_guest_context, ctrlreg): %ld\n",
			ctrlreg_offset);

	offset = xd->xc_core.header.xch_ctxt_offset +
		(off_t)ctrlreg_offset;

	if (lseek(xd->xfd, offset, SEEK_SET) == -1)
		error(FATAL, "cannot lseek to xch_ctxt_offset\n");

	if (read(xd->xfd, &ctrlreg, sizeof(ctrlreg)) !=
	    sizeof(ctrlreg))
		error(FATAL, "cannot read vcpu_guest_context ctrlreg[8]\n");

	mfn = (ctrlreg[3] >> PAGESHIFT()) | (ctrlreg[3] << (BITS()-PAGESHIFT()));

	for (i = 0; CRASHDEBUG(1) && (i < 8); i++) {
		fprintf(xd->ofp, "ctrlreg[%d]: %lx", i, ctrlreg[i]);
		if (i == 3)
			fprintf(xd->ofp, " -> mfn: %lx", mfn);
		fprintf(xd->ofp, "\n");
	}

	if (!xc_core_mfn_to_page(mfn, machdep->pgd))
		error(FATAL, "cannot read/find cr3 page\n");

	machdep->last_pgd_read = mfn;

	if (CRASHDEBUG(1)) {
		fprintf(xd->ofp, "contents of page directory page:\n");	

		if (machdep->flags & PAE) {
			ulp = (ulonglong *)machdep->pgd;
			fprintf(xd->ofp, 
			    "%016llx %016llx %016llx %016llx\n",
				*ulp, *(ulp+1), *(ulp+2), *(ulp+3));
		} else {
			up = (ulong *)machdep->pgd;
			for (i = 0; i < 256; i++) {
				fprintf(xd->ofp, 
				    "%08lx: %08lx %08lx %08lx %08lx\n", 
					(ulong)((i * 4) * sizeof(ulong)),
					*up, *(up+1), *(up+2), *(up+3));
				up += 4;
			}
		}
	}

	kvaddr = symbol_value("max_pfn");
	if (!x86_xendump_load_page(kvaddr, xd->page))
		return FALSE;
	up = (ulong *)(xd->page + PAGEOFFSET(kvaddr));
	if (CRASHDEBUG(1))
		fprintf(xd->ofp, "max_pfn: %lx\n", *up);

        xd->xc_core.p2m_frames = (*up/(PAGESIZE()/sizeof(ulong))) +
                ((*up%(PAGESIZE()/sizeof(ulong))) ? 1 : 0);

	if ((xd->xc_core.p2m_frame_index_list = (ulong *)
	    malloc(xd->xc_core.p2m_frames * sizeof(int))) == NULL)
        	error(FATAL, "cannot malloc p2m_frame_index_list");

	kvaddr = symbol_value("phys_to_machine_mapping");
	if (!x86_xendump_load_page(kvaddr, xd->page))
		return FALSE;
	up = (ulong *)(xd->page + PAGEOFFSET(kvaddr));
	if (CRASHDEBUG(1))
		fprintf(fp, "phys_to_machine_mapping: %lx\n", *up);

	kvaddr = *up;
	machdep->last_ptbl_read = BADADDR;
	machdep->last_pmd_read = BADADDR;

	for (i = 0; i < xd->xc_core.p2m_frames; i++) {
		if ((idx = x86_xendump_page_index(kvaddr)) == MFN_NOT_FOUND)
			return FALSE;
		xd->xc_core.p2m_frame_index_list[i] = idx; 
		kvaddr += PAGESIZE();
	}

	machdep->last_ptbl_read = 0;
	machdep->last_pmd_read = 0;

	return TRUE;
}

static int 
x86_pvops_xendump_p2m_create(struct xendump_data *xd)
{
	int i;
	ulong mfn, kvaddr, ctrlreg[8], ctrlreg_offset;
	ulong *up;
	ulonglong *ulp;
	off_t offset; 

	if ((ctrlreg_offset = MEMBER_OFFSET("vcpu_guest_context", "ctrlreg")) ==
	     INVALID_OFFSET)
		error(FATAL, 
		    "cannot determine vcpu_guest_context.ctrlreg offset\n");
	else if (CRASHDEBUG(1))
		fprintf(xd->ofp, 
		    "MEMBER_OFFSET(vcpu_guest_context, ctrlreg): %ld\n",
			ctrlreg_offset);

	offset = xd->xc_core.header.xch_ctxt_offset +
		(off_t)ctrlreg_offset;

	if (lseek(xd->xfd, offset, SEEK_SET) == -1)
		error(FATAL, "cannot lseek to xch_ctxt_offset\n");

	if (read(xd->xfd, &ctrlreg, sizeof(ctrlreg)) !=
	    sizeof(ctrlreg))
		error(FATAL, "cannot read vcpu_guest_context ctrlreg[8]\n");

	mfn = (ctrlreg[3] >> PAGESHIFT()) | (ctrlreg[3] << (BITS()-PAGESHIFT()));

	for (i = 0; CRASHDEBUG(1) && (i < 8); i++) {
		fprintf(xd->ofp, "ctrlreg[%d]: %lx", i, ctrlreg[i]);
		if (i == 3)
			fprintf(xd->ofp, " -> mfn: %lx", mfn);
		fprintf(xd->ofp, "\n");
	}

	if (!xc_core_mfn_to_page(mfn, machdep->pgd))
		error(FATAL, "cannot read/find cr3 page\n");

	machdep->last_pgd_read = mfn;

	if (CRASHDEBUG(1)) {
		fprintf(xd->ofp, "contents of page directory page:\n");	

		if (machdep->flags & PAE) {
			ulp = (ulonglong *)machdep->pgd;
			fprintf(xd->ofp, 
			    "%016llx %016llx %016llx %016llx\n",
				*ulp, *(ulp+1), *(ulp+2), *(ulp+3));
		} else {
			up = (ulong *)machdep->pgd;
			for (i = 0; i < 256; i++) {
				fprintf(xd->ofp, 
				    "%08lx: %08lx %08lx %08lx %08lx\n", 
					(ulong)((i * 4) * sizeof(ulong)),
					*up, *(up+1), *(up+2), *(up+3));
				up += 4;
			}
		}
	}

	kvaddr = symbol_value("max_pfn");
	if (!x86_xendump_load_page(kvaddr, xd->page))
		return FALSE;
	up = (ulong *)(xd->page + PAGEOFFSET(kvaddr));
	if (CRASHDEBUG(1))
		fprintf(xd->ofp, "max_pfn: %lx\n", *up);

        xd->xc_core.p2m_frames = (*up/(PAGESIZE()/sizeof(ulong))) +
                ((*up%(PAGESIZE()/sizeof(ulong))) ? 1 : 0);

	if ((xd->xc_core.p2m_frame_index_list = (ulong *)
	    malloc(xd->xc_core.p2m_frames * sizeof(int))) == NULL)
        	error(FATAL, "cannot malloc p2m_frame_index_list");

	if (symbol_exists("p2m_mid_missing"))
		return x86_pvops_xendump_p2m_l3_create(xd);
	else
		return x86_pvops_xendump_p2m_l2_create(xd);
}

static int x86_pvops_xendump_p2m_l2_create(struct xendump_data *xd)
{
	int i, idx, p;
	ulong kvaddr, *up;

	machdep->last_ptbl_read = BADADDR;
	machdep->last_pmd_read = BADADDR;

	kvaddr = symbol_value("p2m_top");

	for (p = 0; p < xd->xc_core.p2m_frames; p += XEN_PFNS_PER_PAGE) {
		if (!x86_xendump_load_page(kvaddr, xd->page))
			return FALSE;

		if (CRASHDEBUG(7))
 			x86_debug_dump_page(xd->ofp, xd->page,
                       		"contents of page:");

		up = (ulong *)(xd->page);

		for (i = 0; i < XEN_PFNS_PER_PAGE; i++, up++) {
			if ((p+i) >= xd->xc_core.p2m_frames)
				break;
			if ((idx = x86_xendump_page_index(*up)) == MFN_NOT_FOUND)
				return FALSE;
			xd->xc_core.p2m_frame_index_list[p+i] = idx;
		}

		kvaddr += PAGESIZE();
	}

	machdep->last_ptbl_read = 0;
	machdep->last_pmd_read = 0;

	return TRUE;
}

static int x86_pvops_xendump_p2m_l3_create(struct xendump_data *xd)
{
	int i, idx, j, p2m_frame, ret = FALSE;
	ulong kvaddr, *p2m_mid, p2m_mid_missing, p2m_missing, *p2m_top;

	p2m_top = NULL;
	machdep->last_ptbl_read = BADADDR;
	machdep->last_pmd_read = BADADDR;

	kvaddr = symbol_value("p2m_missing");

	if (!x86_xendump_load_page(kvaddr, xd->page))
		goto err;

	p2m_missing = *(ulong *)(xd->page + PAGEOFFSET(kvaddr));

	kvaddr = symbol_value("p2m_mid_missing");

	if (!x86_xendump_load_page(kvaddr, xd->page))
		goto err;

	p2m_mid_missing = *(ulong *)(xd->page + PAGEOFFSET(kvaddr));

	kvaddr = symbol_value("p2m_top");

	if (!x86_xendump_load_page(kvaddr, xd->page))
		goto err;

	kvaddr = *(ulong *)(xd->page + PAGEOFFSET(kvaddr));

	if (!x86_xendump_load_page(kvaddr, xd->page))
		goto err;

	if (CRASHDEBUG(7))
		x86_debug_dump_page(xd->ofp, xd->page,
					"contents of p2m_top page:");

	p2m_top = (ulong *)GETBUF(PAGESIZE());

	memcpy(p2m_top, xd->page, PAGESIZE());

	for (i = 0; i < XEN_P2M_TOP_PER_PAGE; ++i) {
		p2m_frame = i * XEN_P2M_MID_PER_PAGE;

		if (p2m_frame >= xd->xc_core.p2m_frames)
			break;

		if (p2m_top[i] == p2m_mid_missing)
			continue;

		if (!x86_xendump_load_page(p2m_top[i], xd->page))
			goto err;

		if (CRASHDEBUG(7))
			x86_debug_dump_page(xd->ofp, xd->page,
						"contents of p2m_mid page:");

		p2m_mid = (ulong *)xd->page;

		for (j = 0; j < XEN_P2M_MID_PER_PAGE; ++j, ++p2m_frame) {
			if (p2m_frame >= xd->xc_core.p2m_frames)
				break;

			if (p2m_mid[j] == p2m_missing)
				continue;

			idx = x86_xendump_page_index(p2m_mid[j]);

			if (idx == MFN_NOT_FOUND)
				goto err;

			xd->xc_core.p2m_frame_index_list[p2m_frame] = idx;
		}
	}

	machdep->last_ptbl_read = 0;
	machdep->last_pmd_read = 0;

	ret = TRUE;

err:
	if (p2m_top)
		FREEBUF(p2m_top);

	return ret;
}

static void
x86_debug_dump_page(FILE *ofp, char *page, char *name)
{
        int i;
        ulong *up;

        fprintf(ofp, "%s\n", name);

        up = (ulong *)page;
        for (i = 0; i < 256; i++) {
                fprintf(ofp, "%016lx: %08lx %08lx %08lx %08lx\n",
                        (ulong)((i * 4) * sizeof(ulong)),
                        *up, *(up+1), *(up+2), *(up+3));
                up += 4;
        }
}

/*
 *  Find the page associate with the kvaddr, and read its contents
 *  into the passed-in buffer.
 */
static char *
x86_xendump_load_page(ulong kvaddr, char *pgbuf)
{
	ulong *entry;
	ulong *up;
	ulong mfn;

	if (machdep->flags & PAE)
		return x86_xendump_load_page_PAE(kvaddr, pgbuf);

        up = (ulong *)machdep->pgd;
        entry = up + (kvaddr >> PGDIR_SHIFT);
        mfn = (*entry) >> PAGESHIFT();

        if (!xc_core_mfn_to_page(mfn, pgbuf)) {
                error(INFO, "cannot read/find pgd entry from cr3 page\n");
		return NULL;
	}

        up = (ulong *)pgbuf;
        entry = up + ((kvaddr >> 12) & (PTRS_PER_PTE-1));
        mfn = (*entry) >> PAGESHIFT();

        if (!xc_core_mfn_to_page(mfn, pgbuf)) {
                error(INFO, "cannot read/find page table page\n");
		return NULL;
	}

	return pgbuf;
}

static char *
x86_xendump_load_page_PAE(ulong kvaddr, char *pgbuf)
{
	ulonglong *entry;
	ulonglong *up;
	ulong mfn;

        up = (ulonglong *)machdep->pgd;
        entry = up + (kvaddr >> PGDIR_SHIFT);
        mfn = (ulong)((*entry) >> PAGESHIFT());

        if (!xc_core_mfn_to_page(mfn, pgbuf)) {
                error(INFO, "cannot read/find pgd entry from cr3 page\n");
                return NULL;
        }

        up = (ulonglong *)pgbuf;
        entry = up + ((kvaddr >> PMD_SHIFT) & (PTRS_PER_PMD-1));
        mfn = (ulong)((*entry) >> PAGESHIFT());

        if (!xc_core_mfn_to_page(mfn, pgbuf)) {
                error(INFO, "cannot read/find pmd entry from pgd\n");
                return NULL;
        }

        up = (ulonglong *)pgbuf;
        entry = up + ((kvaddr >> PAGESHIFT()) & (PTRS_PER_PTE-1));
        mfn = (ulong)((*entry) >> PAGESHIFT());

        if (!xc_core_mfn_to_page(mfn, pgbuf)) {
                error(INFO, "cannot read/find page table page from pmd\n");
                return NULL;
        }

	return pgbuf;
}

/*
 *  Find the dumpfile page index associated with the kvaddr.
 */
static int 
x86_xendump_page_index(ulong kvaddr)
{
	int idx;
        ulong *entry;
        ulong *up;
        ulong mfn;

	if (machdep->flags & PAE)
		return x86_xendump_page_index_PAE(kvaddr);

        up = (ulong *)machdep->pgd;
        entry = up + (kvaddr >> PGDIR_SHIFT);
        mfn = (*entry) >> PAGESHIFT();
	if ((mfn != machdep->last_ptbl_read) && 
            !xc_core_mfn_to_page(mfn, machdep->ptbl)) {
                error(INFO, "cannot read/find pgd entry from cr3 page\n");
		return MFN_NOT_FOUND;
	}
	machdep->last_ptbl_read = mfn;

        up = (ulong *)machdep->ptbl;
        entry = up + ((kvaddr>>12) & (PTRS_PER_PTE-1));
        mfn = (*entry) >> PAGESHIFT();
	if ((idx = xc_core_mfn_to_page_index(mfn)) == MFN_NOT_FOUND)
                error(INFO, "cannot determine page index for %lx\n", 
			kvaddr);

	return idx;
}

static int 
x86_xendump_page_index_PAE(ulong kvaddr)
{
	int idx;
        ulonglong *entry;
        ulonglong *up;
        ulong mfn;

        up = (ulonglong *)machdep->pgd;
        entry = up + (kvaddr >> PGDIR_SHIFT);
        mfn = (ulong)((*entry) >> PAGESHIFT());
	if ((mfn != machdep->last_pmd_read) &&
	    !xc_core_mfn_to_page(mfn, machdep->pmd)) {
                error(INFO, "cannot read/find pgd entry from cr3 page\n");
		return MFN_NOT_FOUND;
	}
	machdep->last_pmd_read = mfn;

        up = (ulonglong *)machdep->pmd;
        entry = up + ((kvaddr >> PMD_SHIFT) & (PTRS_PER_PMD-1));
        mfn = (ulong)((*entry) >> PAGESHIFT());
        if ((mfn != machdep->last_ptbl_read) &&
	    !xc_core_mfn_to_page(mfn, machdep->ptbl)) {
                error(INFO, "cannot read/find pmd entry from pgd\n");
                return MFN_NOT_FOUND;
        }
	machdep->last_ptbl_read = mfn;

        up = (ulonglong *)machdep->ptbl;
        entry = up + ((kvaddr >> PAGESHIFT()) & (PTRS_PER_PTE-1));
        mfn = (ulong)((*entry) >> PAGESHIFT());
	if ((idx = xc_core_mfn_to_page_index(mfn)) == MFN_NOT_FOUND)
                error(INFO, "cannot determine page index for %lx\n", 
			kvaddr);

	return idx;
}

/*
 *  Pull the esp from the cpu_user_regs struct in the header
 *  turn it into a task, and match it with the active_set.
 *  Unfortunately, the registers in the vcpu_guest_context 
 *  are not necessarily those of the panic task, so for now
 *  let get_active_set_panic_task() get the right task.
 */
static ulong 
x86_xendump_panic_task(struct xendump_data *xd)
{
	return NO_TASK;

#ifdef TO_BE_REVISITED
	int i;
	ulong esp;
	off_t offset;
	ulong task;


	if (INVALID_MEMBER(vcpu_guest_context_user_regs) ||
	    INVALID_MEMBER(cpu_user_regs_esp))
		return NO_TASK;

        offset = xd->xc_core.header.xch_ctxt_offset +
                (off_t)OFFSET(vcpu_guest_context_user_regs) +
		(off_t)OFFSET(cpu_user_regs_esp);

        if (lseek(xd->xfd, offset, SEEK_SET) == -1)
		return NO_TASK;

        if (read(xd->xfd, &esp, sizeof(ulong)) != sizeof(ulong))
		return NO_TASK;

        if (IS_KVADDR(esp) && (task = stkptr_to_task(esp))) {

                for (i = 0; i < NR_CPUS; i++) {
                	if (task == tt->active_set[i]) {
                        	if (CRASHDEBUG(0))
                                	error(INFO,
                            "x86_xendump_panic_task: esp: %lx -> task: %lx\n",
                                        	esp, task);
                        	return task;
			}
		}               

               	error(WARNING,
		    "x86_xendump_panic_task: esp: %lx -> task: %lx (not active)\n",
			esp);
        }

	return NO_TASK;
#endif
}

/*
 *  Because of an off-by-one vcpu bug in early xc_domain_dumpcore()
 *  instantiations, the registers in the vcpu_guest_context are not 
 *  necessarily those of the panic task.  If not, the eip/esp will be
 *  in stop_this_cpu, as a result of the IP interrupt in panic(),
 *  but the trace is strange because it comes out of the hypervisor
 *  at least if the vcpu had been idle.
 */
static void 
x86_get_xendump_regs(struct xendump_data *xd, struct bt_info *bt, ulong *eip, ulong *esp)
{
	ulong task, xeip, xesp;
	off_t offset;

        if (INVALID_MEMBER(vcpu_guest_context_user_regs) ||
            INVALID_MEMBER(cpu_user_regs_eip) ||
            INVALID_MEMBER(cpu_user_regs_esp))
                goto generic;

        offset = xd->xc_core.header.xch_ctxt_offset +
                (off_t)OFFSET(vcpu_guest_context_user_regs) +
                (off_t)OFFSET(cpu_user_regs_esp);
        if (lseek(xd->xfd, offset, SEEK_SET) == -1)
                goto generic;
        if (read(xd->xfd, &xesp, sizeof(ulong)) != sizeof(ulong))
                goto generic;

        offset = xd->xc_core.header.xch_ctxt_offset +
                (off_t)OFFSET(vcpu_guest_context_user_regs) +
                (off_t)OFFSET(cpu_user_regs_eip);
        if (lseek(xd->xfd, offset, SEEK_SET) == -1)
                goto generic;
        if (read(xd->xfd, &xeip, sizeof(ulong)) != sizeof(ulong))
                goto generic;

        if (IS_KVADDR(xesp) && (task = stkptr_to_task(xesp)) &&
	    (task == bt->task)) {
		if (CRASHDEBUG(1))
			fprintf(xd->ofp, 
		"hooks from vcpu_guest_context: eip: %lx esp: %lx\n", xeip, xesp);
		*eip = xeip;
		*esp = xesp;
		return;
	}

generic:
	return machdep->get_stack_frame(bt, eip, esp);
}

/* for Xen Hypervisor analysis */

static int
x86_xenhyper_is_kvaddr(ulong addr)
{
	if (machdep->flags & PAE) {
		return (addr >= HYPERVISOR_VIRT_START_PAE);
	}
	return (addr >= HYPERVISOR_VIRT_START);
}

static ulong
x86_get_stackbase_hyper(ulong task)
{
	struct xen_hyper_vcpu_context *vcc;
	int pcpu;
	ulong init_tss;
	ulong esp, base;
	char *buf;

	/* task means vcpu here */
	vcc = xen_hyper_vcpu_to_vcpu_context(task);
	if (!vcc)
		error(FATAL, "invalid vcpu\n");

	pcpu = vcc->processor;
	if (!xen_hyper_test_pcpu_id(pcpu)) {
		error(FATAL, "invalid pcpu number\n");
	}

	if (symbol_exists("init_tss")) {
		init_tss = symbol_value("init_tss");
		init_tss += XEN_HYPER_SIZE(tss) * pcpu;
	} else {
		init_tss = symbol_value("per_cpu__init_tss");
		init_tss = xen_hyper_per_cpu(init_tss, pcpu);
	}
	
	buf = GETBUF(XEN_HYPER_SIZE(tss));
	if (!readmem(init_tss, KVADDR, buf,
			XEN_HYPER_SIZE(tss), "init_tss", RETURN_ON_ERROR)) {
		error(FATAL, "cannot read init_tss.\n");
	}
	esp = ULONG(buf + XEN_HYPER_OFFSET(tss_esp0));
	FREEBUF(buf);
	base = esp & (~(STACKSIZE() - 1));

	return base;
}

static ulong
x86_get_stacktop_hyper(ulong task)
{
	return x86_get_stackbase_hyper(task) + STACKSIZE();
}

static void
x86_get_stack_frame_hyper(struct bt_info *bt, ulong *pcp, ulong *spp)
{
	struct xen_hyper_vcpu_context *vcc;
	int pcpu;
	ulong *regs;
	ulong esp, eip;

	/* task means vcpu here */
	vcc = xen_hyper_vcpu_to_vcpu_context(bt->task);
	if (!vcc)
		error(FATAL, "invalid vcpu\n");

	pcpu = vcc->processor;
	if (!xen_hyper_test_pcpu_id(pcpu)) {
		error(FATAL, "invalid pcpu number\n");
	}

	if (bt->flags & BT_TEXT_SYMBOLS_ALL) {
		if (spp)
			*spp = x86_get_stackbase_hyper(bt->task);
		if (pcp)
			*pcp = 0;
		bt->flags &= ~BT_TEXT_SYMBOLS_ALL;
		return;
	}

	regs = (ulong *)xen_hyper_id_to_dumpinfo_context(pcpu)->pr_reg_ptr;
	esp = XEN_HYPER_X86_NOTE_ESP(regs);
	eip = XEN_HYPER_X86_NOTE_EIP(regs);

	if (spp) {
		if (esp < x86_get_stackbase_hyper(bt->task) ||
			esp >= x86_get_stacktop_hyper(bt->task))
			*spp = x86_get_stackbase_hyper(bt->task);
		else
			*spp = esp;
	}
	if (pcp) {
		if (is_kernel_text(eip))
			*pcp = eip;
		else
			*pcp = 0;
	}
}

static void
x86_init_hyper(int when)
{
	switch (when)
	{
	case PRE_SYMTAB:
		machdep->verify_symbol = x86_verify_symbol;
                if (pc->flags & KERNEL_DEBUG_QUERY)
                        return;
                machdep->pagesize = memory_page_size();
                machdep->pageshift = ffs(machdep->pagesize) - 1;
                machdep->pageoffset = machdep->pagesize - 1;
                machdep->pagemask = ~((ulonglong)machdep->pageoffset);
		machdep->stacksize = machdep->pagesize * 4; /* ODA: magic num */
        	if ((machdep->pgd = (char *)malloc(PAGESIZE())) == NULL)
                	error(FATAL, "cannot malloc pgd space.");
                if ((machdep->pmd = (char *)malloc(PAGESIZE())) == NULL)
                        error(FATAL, "cannot malloc pmd space.");
        	if ((machdep->ptbl = (char *)malloc(PAGESIZE())) == NULL)
                	error(FATAL, "cannot malloc ptbl space.");
		machdep->last_pgd_read = 0;
		machdep->last_pmd_read = 0;
		machdep->last_ptbl_read = 0;
		machdep->machspec = &x86_machine_specific; /* some members used */
		break;

	case PRE_GDB:
		if (symbol_exists("create_pae_xen_mappings") ||
		    symbol_exists("idle_pg_table_l3")) {
                	machdep->flags |= PAE;
			PGDIR_SHIFT = PGDIR_SHIFT_3LEVEL;
			PTRS_PER_PTE = PTRS_PER_PTE_3LEVEL;
			PTRS_PER_PGD = PTRS_PER_PGD_3LEVEL;
                        machdep->kvtop = x86_kvtop_PAE;
			machdep->kvbase = HYPERVISOR_VIRT_START_PAE;
		} else {
			PGDIR_SHIFT = PGDIR_SHIFT_2LEVEL;
                        PTRS_PER_PTE = PTRS_PER_PTE_2LEVEL;
                        PTRS_PER_PGD = PTRS_PER_PGD_2LEVEL;
                	machdep->kvtop = x86_kvtop;
			free(machdep->pmd);
			machdep->pmd = machdep->pgd;   
			machdep->kvbase = HYPERVISOR_VIRT_START;
		}
		machdep->ptrs_per_pgd = PTRS_PER_PGD;
		machdep->identity_map_base = DIRECTMAP_VIRT_START;
                machdep->is_kvaddr = x86_xenhyper_is_kvaddr;
	        machdep->eframe_search = x86_eframe_search;
	        machdep->back_trace = x86_back_trace_cmd;
	        machdep->processor_speed = x86_processor_speed;		/* ODA: check */
		machdep->dump_irq = generic_dump_irq; 			/* ODA: check */
		machdep->get_stack_frame = x86_get_stack_frame_hyper;
		machdep->get_stackbase = x86_get_stackbase_hyper;
		machdep->get_stacktop = x86_get_stacktop_hyper;
		machdep->translate_pte = x86_translate_pte;
		machdep->memory_size = xen_hyper_x86_memory_size;
		machdep->dis_filter = x86_dis_filter;
//		machdep->cmd_mach = x86_cmd_mach;			/* ODA: check */
		machdep->get_smp_cpus = xen_hyper_x86_get_smp_cpus;
//		machdep->line_number_hooks = x86_line_number_hooks;	/* ODA: check */
		machdep->flags |= FRAMESIZE_DEBUG;			/* ODA: check */
		machdep->value_to_symbol = generic_machdep_value_to_symbol;
		machdep->clear_machdep_cache = x86_clear_machdep_cache;

		/* machdep table for Xen Hypervisor */
		xhmachdep->pcpu_init = xen_hyper_x86_pcpu_init;
		break;

	case POST_GDB:
#if 0	/* ODA: need this ? */
		if (x86_omit_frame_pointer()) {
			machdep->flags |= OMIT_FRAME_PTR;
#endif
		XEN_HYPER_STRUCT_SIZE_INIT(cpu_time, "cpu_time");
		XEN_HYPER_STRUCT_SIZE_INIT(cpuinfo_x86, "cpuinfo_x86");
		XEN_HYPER_STRUCT_SIZE_INIT(tss, "tss_struct");
		XEN_HYPER_MEMBER_OFFSET_INIT(tss_esp0, "tss_struct", "esp0");
		XEN_HYPER_MEMBER_OFFSET_INIT(cpu_time_local_tsc_stamp, "cpu_time", "local_tsc_stamp");
		XEN_HYPER_MEMBER_OFFSET_INIT(cpu_time_stime_local_stamp, "cpu_time", "stime_local_stamp");
		XEN_HYPER_MEMBER_OFFSET_INIT(cpu_time_stime_master_stamp, "cpu_time", "stime_master_stamp");
		XEN_HYPER_MEMBER_OFFSET_INIT(cpu_time_tsc_scale, "cpu_time", "tsc_scale");
		XEN_HYPER_MEMBER_OFFSET_INIT(cpu_time_calibration_timer, "cpu_time", "calibration_timer");
		if (symbol_exists("cpu_data")) {
			xht->cpu_data_address = symbol_value("cpu_data");
		}
/* KAK Can this be calculated? */
		if (!machdep->hz) {
			machdep->hz = XEN_HYPER_HZ;
		}
		break;

	case POST_INIT:
		break;
	}
}

#endif /* X86 */
