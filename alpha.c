/* alpha.c - core analysis suite
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002-2006, 2010-2013 David Anderson
 * Copyright (C) 2002-2006, 2010-2013 Red Hat, Inc. All rights reserved.
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
 *
 */ 
#ifdef ALPHA
#include "defs.h"

static void alpha_back_trace(struct gnu_request *, struct bt_info *);
static int alpha_trace_status(struct gnu_request *, struct bt_info *);
static void alpha_exception_frame(ulong, ulong, 
	struct gnu_request *, struct bt_info *);
static void alpha_frame_offset(struct gnu_request *, ulong);
static int alpha_backtrace_resync(struct gnu_request *, ulong,
	struct bt_info *);
static void alpha_print_stack_entry(struct gnu_request *, ulong, 
	char *, ulong, struct bt_info *);
static int alpha_resync_speculate(struct gnu_request *, ulong,struct bt_info *);
static int alpha_dis_filter(ulong, char *, unsigned int);
static void dis_address_translation(ulong, char *, unsigned int);
static void alpha_cmd_mach(void);
static int alpha_get_smp_cpus(void);
static void alpha_display_machine_stats(void);
static void alpha_dump_line_number(char *, ulong);
static void display_hwrpb(unsigned int);
static void alpha_post_init(void);
static struct line_number_hook alpha_line_number_hooks[];


#define ALPHA_CONTINUE_TRACE     (1)
#define ALPHA_END_OF_TRACE       (2)
#define ALPHA_EXCEPTION_FRAME    (3)
#define ALPHA_SYSCALL_FRAME      (4)
#define ALPHA_MM_FAULT           (5)
#define ALPHA_INTERRUPT_PENDING  (6)
#define ALPHA_RESCHEDULE         (7)
#define ALPHA_DOWN_FAILED        (8)
#define ALPHA_RET_FROM_SMP_FORK  (9)
#define ALPHA_SIGNAL_RETURN     (10)
#define ALPHA_STRACE            (11)

static int alpha_eframe_search(struct bt_info *);
static int alpha_uvtop(struct task_context *, ulong, physaddr_t *, int);
static int alpha_kvtop(struct task_context *, ulong, physaddr_t *, int);
static void alpha_back_trace_cmd(struct bt_info *);
static ulong alpha_get_task_pgd(ulong task);
static ulong alpha_processor_speed(void);
static void alpha_dump_irq(int);
static void alpha_get_stack_frame(struct bt_info *, ulong *, ulong *);
static void get_alpha_frame(struct bt_info *, ulong *, ulong *);
static int verify_user_eframe(struct bt_info *, ulong, ulong);
static int alpha_translate_pte(ulong, void *, ulonglong);
static uint64_t alpha_memory_size(void);
static ulong alpha_vmalloc_start(void);
static int alpha_is_task_addr(ulong);
static int alpha_verify_symbol(const char *, ulong, char);

struct percpu_data {
	ulong halt_PC;
	ulong halt_ra;
	ulong halt_pv;
};
#define GET_HALT_PC  0x1
#define GET_HALT_RA  0x2
#define GET_HALT_PV  0x3
static ulong get_percpu_data(int, ulong, struct percpu_data *);

/*
 *  Do all necessary machine-specific setup here.  This is called three times,
 *  before symbol table initialization, and before and after GDB has been 
 *  initialized.
 */
void
alpha_init(int when)
{
	int tmp;

	switch (when)
	{
	case PRE_SYMTAB:
		machdep->verify_symbol = alpha_verify_symbol;
                if (pc->flags & KERNEL_DEBUG_QUERY)
                        return;
                machdep->pagesize = memory_page_size();
                machdep->pageshift = ffs(machdep->pagesize) - 1;
                machdep->pageoffset = machdep->pagesize - 1;
                machdep->pagemask = ~(machdep->pageoffset);
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
		machdep->verify_paddr = generic_verify_paddr;
		machdep->ptrs_per_pgd = PTRS_PER_PGD;
		break;
		
	case PRE_GDB:
	        switch (symbol_value("_stext") & KSEG_BASE)
	        {
	        case KSEG_BASE:
	                machdep->kvbase = KSEG_BASE;
	                break;
	
	        case KSEG_BASE_48_BIT:
	                machdep->kvbase = KSEG_BASE_48_BIT;
	                break;
	
	        default:
	                error(FATAL, 
			    "cannot determine KSEG base from _stext: %lx\n",
	                        symbol_value("_stext"));
	        }

		machdep->identity_map_base = machdep->kvbase;
		machdep->is_kvaddr = generic_is_kvaddr;
                machdep->is_uvaddr = generic_is_uvaddr;
	        machdep->eframe_search = alpha_eframe_search;
	        machdep->back_trace = alpha_back_trace_cmd;
	        machdep->processor_speed = alpha_processor_speed;
	        machdep->uvtop = alpha_uvtop;
	        machdep->kvtop = alpha_kvtop;
	        machdep->get_task_pgd = alpha_get_task_pgd;
		if (symbol_exists("irq_desc"))
			machdep->dump_irq = generic_dump_irq;
		else
			machdep->dump_irq = alpha_dump_irq;
		machdep->get_stack_frame = alpha_get_stack_frame;
		machdep->get_stackbase = generic_get_stackbase;
		machdep->get_stacktop = generic_get_stacktop;
		machdep->translate_pte = alpha_translate_pte;
		machdep->memory_size = alpha_memory_size;
		machdep->vmalloc_start = alpha_vmalloc_start;
		machdep->is_task_addr = alpha_is_task_addr;
		if (symbol_exists("console_crash")) {
			get_symbol_data("console_crash", sizeof(int), &tmp);
			if (tmp)
				machdep->flags |= HWRESET;
		}
		machdep->dis_filter = alpha_dis_filter;
		machdep->cmd_mach = alpha_cmd_mach;
		machdep->get_smp_cpus = alpha_get_smp_cpus;
		machdep->line_number_hooks = alpha_line_number_hooks;
		machdep->value_to_symbol = generic_machdep_value_to_symbol;
                machdep->init_kernel_pgd = NULL;
		break;

	case POST_GDB:
		MEMBER_OFFSET_INIT(thread_struct_ptbr, 
			"thread_struct", "ptbr");
		MEMBER_OFFSET_INIT(hwrpb_struct_cycle_freq, 
			"hwrpb_struct", "cycle_freq");
		MEMBER_OFFSET_INIT(hwrpb_struct_processor_offset,
			"hwrpb_struct", "processor_offset");
		MEMBER_OFFSET_INIT(hwrpb_struct_processor_size,
			"hwrpb_struct", "processor_size");
		MEMBER_OFFSET_INIT(percpu_struct_halt_PC,
			"percpu_struct", "halt_PC");
		MEMBER_OFFSET_INIT(percpu_struct_halt_ra, 
			"percpu_struct", "halt_ra");
                MEMBER_OFFSET_INIT(percpu_struct_halt_pv,
                        "percpu_struct", "halt_pv");
		MEMBER_OFFSET_INIT(switch_stack_r26,
			"switch_stack", "r26");
        	if (symbol_exists("irq_action"))
			ARRAY_LENGTH_INIT(machdep->nr_irqs, irq_action, 
				"irq_action", NULL, 0);
        	else if (symbol_exists("irq_desc"))
                	ARRAY_LENGTH_INIT(machdep->nr_irqs, irq_desc, 
				"irq_desc", NULL, 0);
        	else
                	machdep->nr_irqs = 0;
		if (!machdep->hz)
			machdep->hz = HZ;
		break;

	case POST_INIT:
		alpha_post_init();
		break;
	}
}

/*
 *  Unroll a kernel stack.
 */
static void
alpha_back_trace_cmd(struct bt_info *bt)
{
	char buf[BUFSIZE];
	struct gnu_request *req;

        bt->flags |= BT_EXCEPTION_FRAME;

        if (CRASHDEBUG(1) || bt->debug)
                fprintf(fp, " => PC: %lx (%s) FP: %lx \n",
                        bt->instptr, value_to_symstr(bt->instptr, buf, 0),
			bt->stkptr );

        req = (struct gnu_request *)GETBUF(sizeof(struct gnu_request));
        req->command = GNU_STACK_TRACE;
        req->flags = GNU_RETURN_ON_ERROR;
        req->buf = GETBUF(BUFSIZE);
        req->debug = bt->debug;
        req->task = bt->task;

        req->pc = bt->instptr;
        req->sp = bt->stkptr;

        if (bt->flags & BT_USE_GDB) {
                strcpy(req->buf, "backtrace");
                gdb_interface(req);
        }
        else
                alpha_back_trace(req, bt);

        FREEBUF(req->buf);
        FREEBUF(req);
}


/*
 *  Unroll the kernel stack.
 */

#define ALPHA_BACKTRACE_SPECULATE(X) 				        \
{									\
        speculate_location = X;				                \
							                \
        if (bt->flags & BT_SPECULATE)					\
                return;							\
									\
        BZERO(btloc, sizeof(struct bt_info));                           \
	btloc->task = req->task;                                        \
	btloc->tc = bt->tc;                                             \
	btloc->stackbase = bt->stackbase;                               \
	btloc->stacktop = bt->stacktop;                                 \
	btloc->flags = BT_TEXT_SYMBOLS_NOPRINT;                         \
        hook.eip = 0; 					                \
	hook.esp = req->lastsp ? req->lastsp + sizeof(long) : 0;        \
	btloc->hp = &hook;                                              \
									\
        back_trace(btloc);	                                        \
									\
        if (hook.esp && hook.eip) {					\
                req->hookp = &hook;					\
                if (alpha_resync_speculate(req, bt->flags, bt)) {	\
                        req->pc = hook.eip;				\
                        req->sp = hook.esp;				\
                        continue; 					\
                }							\
		goto show_remaining_text;			        \
        }								\
	goto show_remaining_text;					\
}								


static void
alpha_back_trace(struct gnu_request *req, struct bt_info *bt)
{
	char buf[BUFSIZE];
        int frame;
	int done;
	int status;
        struct stack_hook hook;
	int eframe_same_pc_ra_function;
	int speculate_location;
	struct bt_info bt_info, *btloc;

	frame = 0;
	req->curframe = 0;
	btloc = &bt_info;

	if (!IS_KVADDR(req->pc)) {
		if (BT_REFERENCE_CHECK(bt))
			return;

		if ((machdep->flags & HWRESET) && is_task_active(req->task)) {
			fprintf(fp, "(hardware reset while in user space)\n");
			return;
		}
		
		fprintf(fp, "invalid pc: %lx\n", req->pc); 

        	alpha_exception_frame(USER_EFRAME_ADDR(req->task),  
			BT_USER_EFRAME, req, bt);

		return;
	}


        for (done = FALSE; !done && (frame < 100); frame++) {

		speculate_location = 0;

		if ((req->name = closest_symbol(req->pc)) == NULL) {
			req->ra = req->pc = 0;
                        if (alpha_backtrace_resync(req, 
			    bt->flags | BT_FROM_CALLFRAME, bt)) 
                       		continue; 

			if (BT_REFERENCE_FOUND(bt))
				return;

			ALPHA_BACKTRACE_SPECULATE(1);
		}

                if (!INSTACK(req->sp, bt))
                        break;

		if (!is_kernel_text(req->pc)) 
			ALPHA_BACKTRACE_SPECULATE(2);

		alpha_print_stack_entry(req, req->pc, req->name,
			bt->flags | BT_SAVE_LASTSP, bt);

		if (BT_REFERENCE_FOUND(bt))
			return;

		switch (status = alpha_trace_status(req, bt))
		{
		case ALPHA_CONTINUE_TRACE:
			alpha_frame_offset(req, 0);
			if (!req->value) {
				done = TRUE;
				break;
			}
			req->prevpc = req->pc;
			req->pc = GET_STACK_ULONG(req->sp);
			req->prevsp = req->sp;
                        req->sp += req->value;
			break;

		case ALPHA_END_OF_TRACE:
			done = TRUE;
			break;

		case ALPHA_STRACE:
                        alpha_exception_frame(req->sp, 
				BT_USER_EFRAME|BT_STRACE, req, bt);
                        done = TRUE;
			break;

		case ALPHA_RET_FROM_SMP_FORK:
                        alpha_exception_frame(USER_EFRAME_ADDR(req->task), 
				BT_USER_EFRAME|BT_RET_FROM_SMP_FORK, req, bt);
			done = TRUE;
			break;

                case ALPHA_DOWN_FAILED:
                        frame++;
                        alpha_print_stack_entry(req,
                                req->pc, closest_symbol(req->pc),
                                bt->flags | BT_SAVE_LASTSP, bt);

			if (BT_REFERENCE_FOUND(bt))
				return;

                        alpha_frame_offset(req, 0);
                        if (!req->value) {
                                done = TRUE;
                                break;
                        }
                        req->prevpc = req->pc;
			req->pc = GET_STACK_ULONG(req->sp);
                        req->prevsp = req->sp;
                        req->sp += req->value;
                        break;

                case ALPHA_RESCHEDULE:
                        alpha_exception_frame(USER_EFRAME_ADDR(req->task),
                                BT_USER_EFRAME|BT_RESCHEDULE, req, bt);
                        done = TRUE;
                        break;

		case ALPHA_MM_FAULT:
                        alpha_exception_frame(req->sp, bt->flags, req, bt);

                        if (!IS_KVADDR(req->pc)) {
				done = TRUE;
                                break;
			}

                        alpha_frame_offset(req, 0);
                        if (!req->value) {
                                done = TRUE;
                                break;
                        }

                        frame++;
			alpha_print_stack_entry(req,
				req->pc, closest_symbol(req->pc), 
				bt->flags | BT_SAVE_LASTSP, bt);

			if (BT_REFERENCE_FOUND(bt))
				return;

                        if (!IS_KVADDR(req->pc)) {
                                done = TRUE;
				break;
			}

			req->prevpc = req->pc;
			req->pc = GET_STACK_ULONG(req->sp);
			req->prevsp = req->sp;
                        req->sp += req->value;
                        break;

		case ALPHA_SYSCALL_FRAME:
			req->sp = verify_user_eframe(bt, req->task, req->sp) ?
				req->sp : USER_EFRAME_ADDR(req->task);

                        alpha_exception_frame(req->sp, bt->flags, req, bt);

			if (!IS_KVADDR(req->pc)) {
				done = TRUE;
				break;
			}

			alpha_frame_offset(req, 0);
                        if (!req->value) {
                                done = TRUE;
                                break;
                        }
			req->prevpc = req->pc;
			req->pc = GET_STACK_ULONG(req->sp);
			req->prevsp = req->sp;
                        req->sp += req->value;
                        break;

		case ALPHA_SIGNAL_RETURN:
                        alpha_exception_frame(USER_EFRAME_ADDR(req->task),
                                bt->flags, req, bt);
			done = TRUE;
			break;

		case ALPHA_EXCEPTION_FRAME:
			alpha_frame_offset(req, 0);
                        if (!req->value) {
				fprintf(fp, 
                       "ALPHA EXCEPTION FRAME w/no frame offset for %lx (%s)\n",
					req->pc, 
					value_to_symstr(req->pc, buf, 0));
                                done = TRUE;
                                break;
                        }

			alpha_exception_frame(req->sp + req->value, 
				bt->flags, req, bt);

			if (!IS_KVADDR(req->pc)) {
                                done = TRUE;
                                break;
			}

			alpha_frame_offset(req, 0);

                        if (!req->value) {
                                fprintf(fp,
                       "ALPHA EXCEPTION FRAME w/no frame offset for %lx (%s)\n",
                                        req->pc, 
					value_to_symstr(req->pc, buf, 0));
                                done = TRUE;
                                break;
                        }
			
			eframe_same_pc_ra_function = 
				SAME_FUNCTION(req->pc, req->ra);
	
			frame++;
			alpha_print_stack_entry(req, req->pc,
				closest_symbol(req->pc), 
				bt->flags | BT_SAVE_LASTSP, bt);

			if (BT_REFERENCE_FOUND(bt))
				return;

			if (!IS_KVADDR(req->pc)) {
				done = TRUE;
				break;
			}

			if (STREQ(closest_symbol(req->pc), 
			    "ret_from_reschedule")) {
                        	alpha_exception_frame(
				    USER_EFRAME_ADDR(req->task), 
				    BT_USER_EFRAME|BT_RESCHEDULE, req, bt);
                        	done = TRUE;
				break;
			}

			req->prevpc = req->pc;
			req->pc = GET_STACK_ULONG(req->sp);

			if (!is_kernel_text(req->pc)) {
				if (alpha_backtrace_resync(req, 
				    bt->flags | BT_FROM_EXCEPTION, bt))
					break;

				if (BT_REFERENCE_FOUND(bt))
					return;

				ALPHA_BACKTRACE_SPECULATE(3);
			}

			if (!eframe_same_pc_ra_function && 
			    (req->pc != req->ra)) {
				req->pc = req->ra;
				break;
			}

			req->prevsp = req->sp;
                        req->sp += req->value;
			break;

		case ALPHA_INTERRUPT_PENDING:
			alpha_frame_offset(req, 0);
                        if (!req->value) {
				req->prevpc = req->pc;
                                req->pc = req->addr;
				req->prevsp = req->sp;
				req->sp = req->frame;
                        } else {
				req->prevpc = req->pc;
				req->pc = GET_STACK_ULONG(req->sp);
				req->prevsp = req->sp;
                        	req->sp += req->value;
			}
			break;
		}
        }

	return;

show_remaining_text:

	if (BT_REFERENCE_CHECK(bt))
		return;

        BZERO(btloc, sizeof(struct bt_info));                         
        btloc->task = req->task;                                       
	btloc->tc = bt->tc;
	btloc->stackbase = bt->stackbase;
	btloc->stacktop = bt->stacktop;
        btloc->flags = BT_TEXT_SYMBOLS_NOPRINT;                        
        hook.esp = req->lastsp + sizeof(long);
        btloc->hp = &hook; 
        back_trace(btloc);

        if (hook.eip) {
       		fprintf(fp,
"NOTE: cannot resolve trace from this point -- remaining text symbols on stack:\n");
		btloc->flags = BT_TEXT_SYMBOLS_PRINT|BT_ERROR_MASK;
        	hook.esp = req->lastsp + sizeof(long);
        	back_trace(btloc);
	} else 
       		fprintf(fp, 
"NOTE: cannot resolve trace from this point -- no remaining text symbols\n");

	if (CRASHDEBUG(1))
		fprintf(fp, "speculate_location: %d\n", speculate_location);

	alpha_exception_frame(USER_EFRAME_ADDR(req->task), 
		BT_USER_EFRAME, req, bt);
}

/*
 *  print one entry of a stack trace
 */
static void 
alpha_print_stack_entry(struct gnu_request *req, 
			ulong callpc, 	
			char *name, 
			ulong flags,
			struct bt_info *bt)
{
	struct load_module *lm;

	if (BT_REFERENCE_CHECK(bt)) {
                switch (bt->ref->cmdflags & (BT_REF_SYMBOL|BT_REF_HEXVAL))
                {
                case BT_REF_SYMBOL:
			if (STREQ(name, bt->ref->str) ||
			    (STREQ(name, "strace") && 
			    STREQ(bt->ref->str, "entSys"))) {
				bt->ref->cmdflags |= BT_REF_FOUND;
			} 
			break;

		case BT_REF_HEXVAL:
			if (bt->ref->hexval == callpc)
				bt->ref->cmdflags |= BT_REF_FOUND;
			break;
		}
	} else {
		fprintf(fp, "%s#%d [%lx] %s at %lx",
        		req->curframe < 10 ? " " : "", req->curframe, req->sp,
			STREQ(name, "strace") ?  "strace (via entSys)" : name, 
			callpc);
		if (module_symbol(callpc, NULL, &lm, NULL, 0))
			fprintf(fp, " [%s]", lm->mod_name);
		fprintf(fp, "\n");
	}

	if (!(flags & BT_SPECULATE))
		req->curframe++;

	if (flags & BT_SAVE_LASTSP)
		req->lastsp = req->sp;

	if (BT_REFERENCE_CHECK(bt))
		return;

	if (flags & BT_LINE_NUMBERS) 
		alpha_dump_line_number(name, callpc);
}

static const char *hook_files[] = {
        "arch/alpha/kernel/entry.S",
        "arch/alpha/kernel/head.S",
	"init/main.c",
        "arch/alpha/kernel/smp.c",
};

#define ENTRY_S      ((char **)&hook_files[0])
#define HEAD_S       ((char **)&hook_files[1])
#define MAIN_C       ((char **)&hook_files[2])
#define SMP_C        ((char **)&hook_files[3])

static struct line_number_hook alpha_line_number_hooks[] = {
	{"entInt", ENTRY_S},
	{"entMM", ENTRY_S},
	{"entArith", ENTRY_S},
	{"entIF", ENTRY_S},
	{"entDbg", ENTRY_S},
	{"kernel_clone", ENTRY_S},
	{"kernel_thread", ENTRY_S},
	{"__kernel_execve", ENTRY_S},
	{"do_switch_stack", ENTRY_S},
	{"undo_switch_stack", ENTRY_S},
	{"entUna", ENTRY_S},
	{"entUnaUser", ENTRY_S},
	{"sys_fork", ENTRY_S},
	{"sys_clone", ENTRY_S},
	{"sys_vfork", ENTRY_S},
	{"alpha_switch_to", ENTRY_S},
	{"entSys", ENTRY_S},
	{"ret_from_sys_call", ENTRY_S},
	{"ret_from_reschedule", ENTRY_S},
	{"restore_all", ENTRY_S},
	{"strace", ENTRY_S},
	{"strace_success", ENTRY_S},
	{"strace_error", ENTRY_S},
	{"syscall_error", ENTRY_S},
	{"ret_success", ENTRY_S},
	{"signal_return", ENTRY_S},
	{"ret_from_fork", ENTRY_S},
	{"reschedule", ENTRY_S},
	{"sys_sigreturn", ENTRY_S},
	{"sys_rt_sigreturn", ENTRY_S},
	{"sys_sigsuspend", ENTRY_S},
	{"sys_rt_sigsuspend", ENTRY_S},
	{"ret_from_smpfork", ENTRY_S},

	{"_stext", HEAD_S},
	{"__start", HEAD_S},
	{"__smp_callin", HEAD_S},
	{"cserve_ena", HEAD_S},
	{"cserve_dis", HEAD_S},
	{"halt", HEAD_S},

	{"start_kernel", MAIN_C},

	{"smp_callin", SMP_C},

       {NULL, NULL}    /* list must be NULL-terminated */
};

static void
alpha_dump_line_number(char *name, ulong callpc)
{
        char buf[BUFSIZE], *p;
        int retries;

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
		if (retries)
			fprintf(fp, GDB_PATCHED() ? 
			  "" : "    (cannot determine file and line number)\n");
		else {
			retries++;
			callpc = closest_symbol_value(callpc);
			goto try_closest;
		}
	}
}


/*
 *  Look for the frame size storage at the beginning of a function.
 *  If it's not obvious, try gdb.
 *
 *  For future reference, here's where the numbers come from:
 *
 *    0xfffffc00003217e8 <schedule+8>:        subq    sp,0x50,sp
 *    fffffc00003217e8:  43ca153e
 *    010000 11110 01010000 1 0101001 11110
 *    
 *    0xfffffc0000321668 <schedule_timeout+8>:        subq    sp,0x60,sp
 *    fffffc0000321668:  43cc153e
 *    010000 11110 01100000 1 0101001 11110
 *    
 *    0xfffffc000035d028 <do_select+8>:       subq    sp,0x70,sp
 *    fffffc000035d028:  43ce153e
 *    010000 11110 01110000 1 0101001 11110
 *    
 *    0100 0011 110x xxxx xxx1 0101 0011 1110
 *    1111 1111 111x xxxx xxx1 1111 1111 1111
 *    0000 0000 0001 1111 1110 0000 0000 0000
 *       f    f    e    0    1    f    f    f  instruction mask
 *       0    0    1    f    e    0    0    0  offset
 *    
 *    stq     ra,0(sp)
 *    fffffc000035d034:  b75e0000
 */

static void
alpha_frame_offset(struct gnu_request *req, ulong alt_pc)
{
	uint *ip, ival;
	ulong value;

	req->value = value = 0;

	if (alt_pc && !is_kernel_text(alt_pc))
		error(FATAL, 
		    "trying to get frame offset of non-text address: %lx\n",
			alt_pc);
	else if (!alt_pc && !is_kernel_text(req->pc))
                error(FATAL, 
                    "trying to get frame offset of non-text address: %lx\n",
                        req->pc);

	ip = alt_pc ? (int *)closest_symbol_value(alt_pc) :
		      (int *)closest_symbol_value(req->pc);
	if (!ip)
		goto use_gdb;

	ival = 0;

 	/*  
	 *  Don't go any farther than "stq ra,0(sp)" (0xb75e0000)
	 */
	while (ival != 0xb75e0000) {
		readmem((ulong)ip, KVADDR, &ival, sizeof(uint),
			"text value", FAULT_ON_ERROR);

		if ((ival & 0xffe01fff) == 0x43c0153e) {
			value = (ival & 0x1fe000) >> 13;
			break;
		}
		ip++;
	}

	if (value) {
		req->value = value;
		return;
	}

use_gdb:
#ifndef GDB_5_3
{
	static int gdb_frame_offset_warnings = 10;

	if (gdb_frame_offset_warnings-- > 0)
		error(WARNING, 
	        "GNU_ALPHA_FRAME_OFFSET functionality not ported to gdb\n");
}
#endif
	req->command = GNU_ALPHA_FRAME_OFFSET;
	if (alt_pc) {
		ulong pc_save;
        	pc_save = req->pc; 
        	req->pc = alt_pc;
        	gdb_interface(req);
        	req->pc = pc_save;
	} else
        	gdb_interface(req);
}

/*
 *  Look for key routines that either mean the trace has ended or has
 *  bumped into an exception frame.
 */
int
alpha_trace_status(struct gnu_request *req, struct bt_info *bt)
{
	ulong value;
	char *func;
	ulong frame;

	req->addr = 0;
	func = req->name;
	frame = req->sp;

	if (STREQ(func, "start_kernel") || 
	    STREQ(func, "smp_callin") ||
	    STREQ(func, "kernel_thread") ||
	    STREQ(func, "__kernel_thread"))
		return ALPHA_END_OF_TRACE;

	if (STREQ(func, "ret_from_smp_fork") ||
	    STREQ(func, "ret_from_smpfork"))
		return ALPHA_RET_FROM_SMP_FORK;

	if (STREQ(func, "entSys")) 
		return ALPHA_SYSCALL_FRAME;

	if (STREQ(func, "entMM")) {
		req->sp += 56;       /* see entMM in entry.S */
		return ALPHA_MM_FAULT;
	}

	if (STREQ(func, "do_entInt")) 
		return ALPHA_EXCEPTION_FRAME;

	if (STREQ(func, "do_entArith")) 
                return ALPHA_EXCEPTION_FRAME;

        if (STREQ(func, "do_entIF")) 
                return ALPHA_EXCEPTION_FRAME;

        if (STREQ(func, "do_entDbg")) 
                return ALPHA_EXCEPTION_FRAME;

	if (STREQ(func, "handle_bottom_half"))
                return ALPHA_EXCEPTION_FRAME;

	if (STREQ(func, "handle_softirq"))
                return ALPHA_EXCEPTION_FRAME;

	if (STREQ(func, "reschedule"))
		return ALPHA_RESCHEDULE;

	if (STREQ(func, "ret_from_reschedule")) 
		return ALPHA_RESCHEDULE;

	if (STREQ(func, "signal_return"))
		return ALPHA_SIGNAL_RETURN;

	if (STREQ(func, "strace"))
		return ALPHA_STRACE;

        if (STREQ(func, "__down_failed") ||
            STREQ(func, "__down_failed_interruptible")) {
		readmem(req->sp + 144, KVADDR, &req->pc, sizeof(ulong),
			"__down_failed r26", FAULT_ON_ERROR);
		req->sp += 160;
                return ALPHA_DOWN_FAILED;
	}

	value = GET_STACK_ULONG(frame);

	if (STREQ(closest_symbol(value), "do_entInt") ||
	    STREQ(closest_symbol(value), "do_entArith") ||
	    STREQ(closest_symbol(value), "do_entIF") ||
	    STREQ(closest_symbol(value), "do_entDbg")) {
		req->addr = value;
		req->frame = 0;

		while (INSTACK(frame, bt)) {
			frame += sizeof(ulong);
			value = GET_STACK_ULONG(frame);
			if (STREQ(closest_symbol(value), "ret_from_sys_call")) {
				alpha_frame_offset(req, req->addr);
				/* req->frame = frame + req->value; XXX */
				break;
			}
		}
		return ALPHA_INTERRUPT_PENDING;
	}

	return ALPHA_CONTINUE_TRACE;
}

/*
 *  Redo the gdb pt_regs structure output.
 */
enum regnames { _r0_, _r1_, _r2_, _r3_, _r4_, _r5_, _r6_, _r7_, _r8_, 
		_r19_, _r20_, _r21_, _r22_, _r23_, _r24_, _r25_, _r26_, 
		_r27_, _r28_, _hae_, _trap_a0_, _trap_a1_, _trap_a2_, 
        	_ps_, _pc_, _gp_, _r16_, _r17_, _r18_, NUMREGS};

struct alpha_eframe {
	char regs[30][30];
	ulong value[29];
};

static void
alpha_exception_frame(ulong addr, 
	              ulong flags, 
		      struct gnu_request *req,
		      struct bt_info *bt)
{
	int i, j;
	char buf[BUFSIZE];
	ulong value; 
	physaddr_t paddr;
	struct alpha_eframe eframe;

	if (CRASHDEBUG(4))
		fprintf(fp, "alpha_exception_frame: %lx\n", addr);

	if (flags & BT_SPECULATE) {
		req->pc = 0;
		fprintf(fp, "ALPHA EXCEPTION FRAME\n");
		return;
	}

	BZERO(&eframe, sizeof(struct alpha_eframe));

        open_tmpfile();
	dump_struct("pt_regs", addr, RADIX(16));
        rewind(pc->tmpfile);
        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
		strip_comma(clean_line(buf));
		if (!strstr(buf, "0x"))
			continue;

		extract_hex(buf, &value, NULLCHAR, TRUE);
		if (CRASHDEBUG(4))
			fprintf(pc->saved_fp, "<%s> %lx\n", buf, value);

		if (STRNEQ(buf, "r0 = ")) {
			sprintf(eframe.regs[_r0_], "  V0/R0: %016lx", value);
			eframe.value[_r0_] = value;
		}
		if (STRNEQ(buf, "r1 = ")) {
			sprintf(eframe.regs[_r1_], "  T0/R1: %016lx", value);
			eframe.value[_r1_] = value;
		}
		if (STRNEQ(buf, "r2 = ")) {
			sprintf(eframe.regs[_r2_], "  T1/R2: %016lx", value);
			eframe.value[_r2_] = value;
		}
		if (STRNEQ(buf, "r3 = ")) {
			sprintf(eframe.regs[_r3_], "  T2/R3: %016lx", value);
			eframe.value[_r3_] = value;
		}
		if (STRNEQ(buf, "r4 = ")) {
			sprintf(eframe.regs[_r4_], "  T3/R4: %016lx", value);
			eframe.value[_r4_] = value;
		}
		if (STRNEQ(buf, "r5 = ")) {
			sprintf(eframe.regs[_r5_], "  T4/R5: %016lx", value);
			eframe.value[_r5_] = value;
		}
		if (STRNEQ(buf, "r6 = ")) {
			sprintf(eframe.regs[_r6_], "  T5/R6: %016lx", value);
			eframe.value[_r6_] = value;
		}
		if (STRNEQ(buf, "r7 = ")) {
			sprintf(eframe.regs[_r7_], "  T6/R7: %016lx", value);
			eframe.value[_r7_] = value;
		}
		if (STRNEQ(buf, "r8 = ")) {
			sprintf(eframe.regs[_r8_], "  T7/R8: %016lx", value);
			eframe.value[_r8_] = value;
		}
		if (STRNEQ(buf, "r19 = ")) {
			sprintf(eframe.regs[_r19_], " A3/R19: %016lx", value);
			eframe.value[_r19_] = value;
		}
		if (STRNEQ(buf, "r20 = ")) {
			sprintf(eframe.regs[_r20_], " A4/R20: %016lx", value);
			eframe.value[_r20_] = value;
		}
		if (STRNEQ(buf, "r21 = ")) {
			sprintf(eframe.regs[_r21_], " A5/R21: %016lx", value);
			eframe.value[_r21_] = value;
		}
		if (STRNEQ(buf, "r22 = ")) {
			sprintf(eframe.regs[_r22_], " T8/R22: %016lx", value);
			eframe.value[_r22_] = value;
		}
		if (STRNEQ(buf, "r23 = ")) {
			sprintf(eframe.regs[_r23_], " T9/R23: %016lx", value);
			eframe.value[_r23_] = value;
		}
		if (STRNEQ(buf, "r24 = ")) {
			sprintf(eframe.regs[_r24_], "T10/R24: %016lx", value);
			eframe.value[_r24_] = value;
		}
		if (STRNEQ(buf, "r25 = ")) {
			sprintf(eframe.regs[_r25_], "T11/R25: %016lx", value);
			eframe.value[_r25_] = value;
		}
		if (STRNEQ(buf, "r26 = ")) {
			sprintf(eframe.regs[_r26_], " RA/R26: %016lx", value);
			eframe.value[_r26_] = value;
		}
		if (STRNEQ(buf, "r27 = ")) {
			sprintf(eframe.regs[_r27_], "T12/R27: %016lx", value);
			eframe.value[_r27_] = value;
		}
		if (STRNEQ(buf, "r28 = ")) {
			sprintf(eframe.regs[_r28_], " AT/R28: %016lx", value);
			eframe.value[_r28_] = value;
		}
		if (STRNEQ(buf, "hae = ")) {
			sprintf(eframe.regs[_hae_], "    HAE: %016lx", value);
			eframe.value[_hae_] = value;
		}
		if (STRNEQ(buf, "trap_a0 = ")) {
			sprintf(eframe.regs[_trap_a0_], "TRAP_A0: %016lx", 
				value);
			eframe.value[_trap_a0_] = value;
		}
		if (STRNEQ(buf, "trap_a1 = ")) {
			sprintf(eframe.regs[_trap_a1_], "TRAP_A1: %016lx", 
				value);
			eframe.value[_trap_a1_] = value;
		}
		if (STRNEQ(buf, "trap_a2 = ")) {
			sprintf(eframe.regs[_trap_a2_], "TRAP_A2: %016lx", 
				value);
			eframe.value[_trap_a2_] = value;
		}
		if (STRNEQ(buf, "ps = ")) {
			sprintf(eframe.regs[_ps_], "     PS: %016lx", value);
			eframe.value[_ps_] = value;
		}
		if (STRNEQ(buf, "pc = ")) {
			sprintf(eframe.regs[_pc_], "     PC: %016lx", value);
			eframe.value[_pc_] = value;
		}
		if (STRNEQ(buf, "gp = ")) {
			sprintf(eframe.regs[_gp_], " GP/R29: %016lx", value);
			eframe.value[_gp_] = value;
		}
		if (STRNEQ(buf, "r16 = ")) {
			sprintf(eframe.regs[_r16_], " A0/R16: %016lx", value);
			eframe.value[_r16_] = value;
		}
		if (STRNEQ(buf, "r17 = ")) {
			sprintf(eframe.regs[_r17_], " A1/R17: %016lx", value);
			eframe.value[_r17_] = value;
		}
		if (STRNEQ(buf, "r18 =")) {
			sprintf(eframe.regs[_r18_], " A2/R18: %016lx", value);
			eframe.value[_r18_] = value;
		}
	}
        close_tmpfile();

	if ((flags & BT_EXCEPTION_FRAME) && !BT_REFERENCE_CHECK(bt)) {
dump_eframe:
		fprintf(fp, " EFRAME: %lx  ", addr);
		fprintf(fp, "%s\n", eframe.regs[_r24_]);

		for (i = 0; i < (((NUMREGS+1)/2)-1); i++) {
			fprintf(fp, "%s  ", eframe.regs[i]);
			pad_line(fp, 21 - strlen(eframe.regs[i]), ' ');
			j = i+((NUMREGS+1)/2);
			fprintf(fp, "%s", eframe.regs[j]);
			if (((j == _pc_) || (j == _r26_)) && 
			    is_kernel_text(eframe.value[j]))
				fprintf(fp, "  <%s>", 
				    value_to_symstr(eframe.value[j], buf, 0));
			fprintf(fp, "\n");
		}
	}

	req->ra = eframe.value[_r26_];
	req->pc = eframe.value[_pc_];
	req->sp = addr + (29 * sizeof(ulong));

	if (flags & BT_USER_EFRAME) {
		flags &= ~BT_USER_EFRAME;
		if (!BT_REFERENCE_CHECK(bt) && (eframe.value[_ps_] == 8) &&
		    (((uvtop(task_to_context(req->task), req->pc, &paddr, 0) || 
	             (volatile ulong)paddr) &&
		    (uvtop(task_to_context(req->task), req->ra, &paddr, 0) ||
		     (volatile ulong)paddr)) ||
		     (IS_ZOMBIE(req->task) || IS_EXITING(req->task)))) {
			if (!(flags & 
			     (BT_RESCHEDULE|BT_RET_FROM_SMP_FORK|BT_STRACE)))
				fprintf(fp, 
				    "NOTE: kernel-entry exception frame:\n");
			goto dump_eframe;
		} 
	}
}

/*
 *   Look for likely exception frames in a stack.
 */
struct alpha_pt_regs {
	ulong reg_value[NUMREGS];
};

static int
alpha_eframe_search(struct bt_info *bt)
{
        ulong *first, *last;
	ulong eframe;
	struct alpha_pt_regs *pt;
	struct gnu_request *req;   /* needed for alpha_exception_frame */
	ulong *stack;
	int cnt;

	stack = (ulong *)bt->stackbuf;
        req = (struct gnu_request *)GETBUF(sizeof(struct gnu_request));
        req->task = bt->task;

        first = stack +
           (roundup(SIZE(task_struct), sizeof(ulong)) / sizeof(ulong));
        last = stack +
           (((bt->stacktop - bt->stackbase) - SIZE(pt_regs)) / sizeof(ulong));

        for (cnt = 0; first <= last; first++) {
		pt = (struct alpha_pt_regs *)first;

		/* check for kernel exception frame */

		if (!(pt->reg_value[_ps_] & 0xfffffffffffffff8) &&
		    (is_kernel_text(pt->reg_value[_pc_]) ||
		     IS_MODULE_VADDR(pt->reg_value[_pc_])) &&
		    (is_kernel_text(pt->reg_value[_r26_]) ||
		     IS_MODULE_VADDR(pt->reg_value[_r26_])) &&
                    IS_KVADDR(pt->reg_value[_gp_])) {
			cnt++;
			if (bt->flags & BT_EFRAME_COUNT) 
				continue;
			fprintf(fp, "\nKERNEL-MODE EXCEPTION FRAME:\n");
			eframe = bt->task + ((ulong)first - (ulong)stack);
			alpha_exception_frame(eframe, BT_EXCEPTION_FRAME, 
				req, bt);
			continue;
		}

		/* check for user exception frame */

                if ((pt->reg_value[_ps_] == 0x8) &&
		    ((IN_TASK_VMA(bt->task, pt->reg_value[_pc_]) &&
                    IN_TASK_VMA(bt->task, pt->reg_value[_r26_]) &&
                    IS_UVADDR(pt->reg_value[_gp_], bt->tc)) ||
		    ((first == last) && 
			(IS_ZOMBIE(bt->task) || IS_EXITING(bt->task))))) {
			cnt++;
			if (bt->flags & BT_EFRAME_COUNT) 
				continue;
			fprintf(fp, "\nUSER-MODE EXCEPTION FRAME:\n");
			eframe = bt->task + ((ulong)first - (ulong)stack);
			alpha_exception_frame(eframe, BT_EXCEPTION_FRAME, 
				req, bt);
		}
        }

	FREEBUF(req);

	return cnt;
}

/*
 *  Before dumping a nonsensical exception frame, give it a quick test.
 */
static int
verify_user_eframe(struct bt_info *bt, ulong task, ulong sp)
{
	struct alpha_pt_regs ptbuf, *pt;

	readmem(sp, KVADDR, &ptbuf, sizeof(struct alpha_pt_regs),
		"pt_regs", FAULT_ON_ERROR);

	pt = &ptbuf;

        if ((pt->reg_value[_ps_] == 0x8) &&
            ((IN_TASK_VMA(task, pt->reg_value[_pc_]) &&
            IN_TASK_VMA(task, pt->reg_value[_r26_]) &&
            IS_UVADDR(pt->reg_value[_gp_], bt->tc)) ||
            ((pt == (struct alpha_pt_regs *)USER_EFRAME_ADDR(task)) && 
	    (IS_ZOMBIE(task) || IS_EXITING(task))))) {
		return TRUE;
        }

	return FALSE;
}

/*
 *  Try to resync the stack location when there is no valid stack frame,
 *  typically just above an exception frame.  Use the req->ra value from the 
 *  exception frame as the new starting req->pc.  Then walk up the stack until 
 *  a text routine that calls the newly-assigned pc is found -- that stack 
 *  location then becomes the new req->sp.  
 *
 *  If we're not coming from an exception frame, req-ra and req->pc will be 
 *  purposely zeroed out.  In that case, use the prevsp value to find the 
 *  first pc that called the last frame's pc.
 *
 *  Add any other repeatable "special-case" frames to the beginning of this 
 *  routine (ex. debug_spin_lock).  Last ditch -- at the end of this routine, 
 *  speculate what might have happened (possibly in the background) -- and 
 *  if it looks good, run with it.
 */
static int
alpha_backtrace_resync(struct gnu_request *req, ulong flags, struct bt_info *bt)
{
	char addr[BUFSIZE];
	char buf[BUFSIZE];
	char lookfor1[BUFSIZE];
	char lookfor2[BUFSIZE];
	ulong newpc;
	ulong *stkp; 
	ulong *stkp_newpc, *stkp_next;
	ulong value;
	int found;
	char *name;
	int exception;

	if (CRASHDEBUG(1))
		fprintf(fp, 
		    "RESYNC1: [%lx-%d] ra: %lx pc: %lx sp: %lx\n",
                        flags, req->curframe, req->ra, req->pc, req->sp);

	if (!req->ra && !req->pc) {
		req->ra = req->prevpc;
		exception = FALSE;
	} else
		exception = TRUE;

	if (!IS_KVADDR(req->ra)) 
		return FALSE;

	name = closest_symbol(req->ra);
	sprintf(lookfor1, "<%s>", name);
	sprintf(lookfor2, "<%s+", name);

        if (CRASHDEBUG(1))
                fprintf(fp, "RESYNC2: exception: %s lookfor: %s or %s\n",
                        exception ? "TRUE" : "FALSE",
			lookfor1, lookfor2);

	/*
	 *  This is common when a non-panicking active CPU is spinning
         *  in debug_spin_lock().  The next pc is offset by 0x30 from
         *  the top of the exception frame, and the next sp is equal
	 *  to the frame offset of debug_spin_lock().  I can't explain it...
	 */ 
	if ((flags & BT_FROM_EXCEPTION) && STREQ(name, "debug_spin_lock")) {
		alpha_print_stack_entry(req, req->ra, 
			closest_symbol(req->ra), flags, bt);

		if (BT_REFERENCE_FOUND(bt)) 
			return FALSE;
		
		alpha_frame_offset(req, req->ra);
		stkp = (ulong *)(req->sp + 0x30);
		value = GET_STACK_ULONG(stkp);
		if (!is_kernel_text(value)) {
			req->sp = req->prevsp;
			return FALSE;
		}
		req->pc = value;
		req->sp += req->value;
		return TRUE;
	}

	/*
	 *  If the ra is a system call, then all we should have to do is
	 *  find the next reference to entSys on the stack, and set the
	 *  sp to that value.
	 */
        if (is_system_call(name, 0)) {
		/* stkp = (ulong *)req->sp; */
		stkp = (ulong *)req->prevsp;

        	for (stkp++; INSTACK(stkp, bt); stkp++) {
			value = GET_STACK_ULONG(stkp);

			if (IS_KVADDR(value) && is_kernel_text(value)) {
				if (STREQ(closest_symbol(value), "entSys")) {
					req->pc = value;
					req->sp = USER_EFRAME_ADDR(req->task);
					return TRUE;
				}
			}
		}
	}

	/*
	 *  Just find the next location containing text. (?)
	 */
        if (STREQ(name, "do_coredump")) {
                stkp = (ulong *)(req->sp + sizeof(long));
                for (stkp++; INSTACK(stkp, bt); stkp++) {
			value = GET_STACK_ULONG(stkp);

                        if (IS_KVADDR(value) && is_kernel_text(value)) {
                                req->pc = req->ra;
                                req->sp = (ulong)stkp;
                                return TRUE;
                        }
                }
	}

	if (flags & BT_SPECULATE)
		return FALSE;

	if (CRASHDEBUG(1)) {
		fprintf(fp, "RESYNC3: prevsp: %lx  ra: %lx name: %s\n", 
			req->prevsp, req->ra, name);
		fprintf(fp, "RESYNC3: prevpc: %lx\n", req->prevpc); 
	}

	stkp_newpc = stkp_next = 0;
	newpc = 0;
	found = FALSE;
	if (exception) {
		newpc = req->ra;
		stkp = (ulong *)req->sp;
	} else 
		stkp = (ulong *)req->prevsp;

	if (CRASHDEBUG(1))
		fprintf(fp, "RESYNC4: stkp: %lx  newpc: %lx\n",
			(ulong)stkp, newpc);

	for (stkp++; INSTACK(stkp, bt); stkp++) {
		value = GET_STACK_ULONG(stkp);
		/*
		 *  First find the new pc on the stack.
		 */
		if (!found) {
			if (!exception && is_kernel_text(value)) {
				found = TRUE;
			} else if (value == newpc) {
				found = TRUE;
				stkp_newpc = stkp;
				continue;
			}
		}

		if (!IS_KVADDR(value))
			continue;

		if (is_kernel_text(value)) {
			if (!stkp_next)
				stkp_next = stkp;
			if (CRASHDEBUG(2)) {
				fprintf(fp, 
				    "RESYNC6: disassemble %lx (%s)\n",
					value - sizeof(uint),
					value_to_symstr(value - sizeof(uint),
					buf, 0));
			}
			req->command = GNU_DISASSEMBLE;
			req->addr = value - sizeof(uint);
			sprintf(addr, "0x%lx", req->addr);
			open_tmpfile();
			req->fp = pc->tmpfile;
			gdb_interface(req);
			rewind(pc->tmpfile);
			while (fgets(buf, BUFSIZE, pc->tmpfile)) {
				clean_line(buf);
                                if (STRNEQ(buf, "Dump of") ||
                                    STRNEQ(buf, "End of"))
                                        continue;

                                if (STRNEQ(buf, addr)) {
					if (LASTCHAR(buf) == ':') {
						fgets(buf, BUFSIZE, 
							pc->tmpfile);
						clean_line(buf);
					}
					if (CRASHDEBUG(2) && 
					    (strstr(buf, "jsr") 
					    || strstr(buf, "bsr"))) 
						fprintf(pc->saved_fp, "%s\n",
							buf);
					if ((strstr(buf, "jsr") ||
					     strstr(buf, "bsr")) &&
					    (strstr(buf, lookfor1) ||
					     strstr(buf, lookfor2))) {
						if (exception) {
							req->pc = newpc;
							req->sp = (ulong)stkp;
						} else 
							req->pc = req->addr;
						close_tmpfile();
						return TRUE;
					}
				}
			}
			close_tmpfile();
		}
	}

	if (CRASHDEBUG(1)) {
		fprintf(fp, "RESYNC9: [%d] name: %s pc: %lx ra: %lx\n",
			req->curframe, name, req->pc, req->ra);
		fprintf(fp, "RESYNC9: sp: %lx lastsp: %lx\n",
			req->sp, req->lastsp);
		fprintf(fp, "RESYNC9: prevpc: %lx prevsp: %lx\n",
			req->prevpc, req->prevsp);
	}

	/*
	 *  At this point, all we can do is speculate based upon 
	 *  past experiences...
	 */
	return (alpha_resync_speculate(req, flags, bt));
}

/*
 *  Try one level of speculation.  If it works, fine -- if not, give up.
 */
static int
alpha_resync_speculate(struct gnu_request *req, ulong flags, struct bt_info *bt)
{
	ulong *stkp;
	ulong value;
	ulong found_sp, found_ra;
        struct stack_hook hook;
	struct bt_info bt_info, *btloc;
	char buf[BUFSIZE];
	int kernel_thread;
	int looks_good;

	if (flags & BT_SPECULATE)   /* already been here on this trace... */
		return FALSE;

	if (pc->tmpfile)
		return FALSE;

        found_ra = found_sp = 0;
	kernel_thread = is_kernel_thread(req->task);

	/*
	 *  Add "known" possibilities here.
	 */
	switch (flags & (BT_FROM_EXCEPTION|BT_FROM_CALLFRAME))
	{
	case BT_FROM_EXCEPTION:
        	if (STREQ(closest_symbol(req->prevpc), "read_lock") ||
                    STREQ(closest_symbol(req->ra), "do_select") ||
                    STREQ(closest_symbol(req->ra), "schedule")) {
			stkp = (ulong *)req->sp;
			for (stkp++; INSTACK(stkp, bt); stkp++) {
				value = GET_STACK_ULONG(stkp);
	
				if (found_ra) {
					if (is_kernel_text_offset(value)) {
						found_sp = (ulong)stkp;
						break;
					}
					continue;
				}
	
				if (value == req->ra) 
					found_ra = value; 
			}
		}
		break;

	case BT_FROM_CALLFRAME:
                if (STREQ(closest_symbol(req->ra), "sys_read")) {
			value = GET_STACK_ULONG(req->prevsp - 32);
                        if (STREQ(closest_symbol(value), "entSys")) {
                                found_ra = value;
                                found_sp = req->prevsp - 32;
                        }
                } else if (STREQ(closest_symbol(req->ra), "exit_autofs4_fs")) {
                        stkp = (ulong *)req->sp;
                        for (stkp++; INSTACK(stkp, bt); stkp++) {
				value = GET_STACK_ULONG(stkp);

                                if (found_ra && (value != found_ra)) {
                                        if (is_kernel_text_offset(value)) {
                                                found_sp = (ulong)stkp;
                                                break;
                                        }
                                        continue;
                                }

				if (is_kernel_text_offset(value)) 
					found_ra = value;
                        }
		}

		break;

	default:
		if (req->hookp &&
		    STREQ(closest_symbol(req->prevpc), "filemap_nopage") &&
	            !STREQ(closest_symbol(req->hookp->eip), "do_no_page")) {
			found_ra = found_sp = 0;
			stkp = (ulong *)req->prevsp;
                        for (stkp++; INSTACK(stkp, bt); stkp++) {
				value = GET_STACK_ULONG(stkp);

                                if (found_ra && (value != found_ra)) {
                                        if (is_kernel_text_offset(value)) {
                                                found_sp = (ulong)stkp;
                                                break;
                                        }
                                        continue;
                                }

                                if (is_kernel_text_offset(value) &&
				    STREQ(closest_symbol(value), "do_no_page")) 
                                        found_ra = value;
                        }
			if (found_ra && found_sp) {
                        	req->hookp->eip = found_ra;
                        	req->hookp->esp = found_sp;
				return TRUE;
			}
		}
		
                if (req->hookp) {
                        found_ra = req->hookp->eip;
                        found_sp = req->hookp->esp;
                }

		break;
	}

	if (found_ra && found_sp) {
		looks_good = FALSE;
		hook.esp = found_sp;
		hook.eip = found_ra;

		if (CRASHDEBUG(1))
			fprintf(pc->saved_fp, 
			    "----- RESYNC SPECULATE START -----\n");

		open_tmpfile();
		btloc = &bt_info;
		BZERO(btloc, sizeof(struct bt_info));
		btloc->task = req->task;
		btloc->tc = bt->tc;
		btloc->stackbase = bt->stackbase;
		btloc->stacktop = bt->stacktop;
		btloc->flags = BT_SPECULATE;
		btloc->hp = &hook;
        	back_trace(btloc);
        	rewind(pc->tmpfile);
        	while (fgets(buf, BUFSIZE, pc->tmpfile)) {
			if (CRASHDEBUG(1))
				fprintf(pc->saved_fp, "%s", buf);

                        if (strstr(buf, "NOTE: cannot resolve")) {
                                looks_good = FALSE;
                                break;
                        }

			if (strstr(buf, "ALPHA EXCEPTION FRAME")) {
				looks_good = TRUE;
				break;
			}

			if (kernel_thread) {
				if (strstr(buf, " kernel_thread ") ||
				    strstr(buf, " __kernel_thread ") ||
				    strstr(buf, " start_kernel ") ||
				    strstr(buf, " smp_callin ")) {
					looks_good = TRUE;
					break;
				}
			}
		}
		close_tmpfile();

		if (CRASHDEBUG(1))
			fprintf(pc->saved_fp, 
			    "----- RESYNC SPECULATE DONE ------\n");

		if (looks_good) {
                	req->pc = found_ra;
                	req->sp = found_sp;
			return TRUE;
		}
	}

	return FALSE;
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

static int
alpha_uvtop(struct task_context *tc, ulong vaddr, physaddr_t *paddr, int verbose)
{
	ulong mm;
	ulong *pgd;
	ulong *page_dir;
	ulong *page_middle;
	ulong *page_table;
	ulong pgd_pte;
	ulong pmd_pte;
	ulong pte;

        if (!tc)
                error(FATAL, "current context invalid\n");

	*paddr = 0;

        if (is_kernel_thread(tc->task) && IS_KVADDR(vaddr)) {
		pgd = (ulong *)machdep->get_task_pgd(tc->task);
	} else {
		if (!tc->mm_struct)
			pgd = (ulong *)machdep->get_task_pgd(tc->task);
		else {
                	if ((mm = task_mm(tc->task, TRUE)))
                        	pgd = ULONG_PTR(tt->mm_struct +
                                	OFFSET(mm_struct_pgd));
			else
				readmem(tc->mm_struct + OFFSET(mm_struct_pgd), 
					KVADDR, &pgd, sizeof(long), 
					"mm_struct pgd", FAULT_ON_ERROR);
		}
	}

	if (verbose) 
		fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)pgd);

	page_dir = pgd + ((vaddr >> PGDIR_SHIFT) & (PTRS_PER_PAGE - 1));

	FILL_PGD(PAGEBASE(pgd), KVADDR, PAGESIZE());
	pgd_pte = ULONG(machdep->pgd + PAGEOFFSET(page_dir));

	if (verbose)
		fprintf(fp, "  PGD: %lx => %lx\n", (ulong)page_dir, pgd_pte);

	if (!(pgd_pte & _PAGE_VALID))
		goto no_upage;

	page_middle = (ulong *)
		(PTOV((pgd_pte & _PFN_MASK) >> (32-PAGESHIFT()))) + 
	  	((vaddr >> PMD_SHIFT) & (PTRS_PER_PAGE - 1));

	FILL_PMD(PAGEBASE(page_middle), KVADDR, PAGESIZE());
	pmd_pte = ULONG(machdep->pmd + PAGEOFFSET(page_middle));

	if (verbose)
		fprintf(fp, "  PMD: %lx => %lx\n", (ulong)page_middle, pmd_pte);

	if (!(pmd_pte & _PAGE_VALID))
		goto no_upage;

	page_table = (ulong *)
		(PTOV((pmd_pte & _PFN_MASK) >> (32-PAGESHIFT()))) +
     		(BTOP(vaddr) & (PTRS_PER_PAGE - 1));
	
	FILL_PTBL(PAGEBASE(page_table), KVADDR, PAGESIZE());
	pte = ULONG(machdep->ptbl + PAGEOFFSET(page_table));

        if (verbose) 
                fprintf(fp, "  PTE: %lx => %lx\n", (ulong)page_table, pte);

	if (!(pte & (_PAGE_VALID))) {
		*paddr = pte;
		if (pte && verbose) {
			fprintf(fp, "\n");
			alpha_translate_pte(pte, 0, 0);
		}
		goto no_upage;
	}

	*paddr = ((pte & _PFN_MASK) >> (32-PAGESHIFT())) + PAGEOFFSET(vaddr);

        if (verbose) {
                fprintf(fp, " PAGE: %lx\n\n", PAGEBASE(*paddr));
		alpha_translate_pte(pte, 0, 0);
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
alpha_kvtop(struct task_context *tc, ulong kvaddr, physaddr_t *paddr, int verbose)
{
	ulong *pgd;
	ulong *page_dir;
	ulong *page_middle;
	ulong *page_table;
        ulong pgd_pte;
        ulong pmd_pte;
        ulong pte;

	if (!IS_KVADDR(kvaddr))
		return FALSE;

	if (!vt->vmalloc_start) {         /* presume KSEG this early */
		*paddr = VTOP(kvaddr);
		return TRUE;
	}

	if (!IS_VMALLOC_ADDR(kvaddr)) { 
		*paddr = VTOP(kvaddr);
		return TRUE;
	}

	pgd = (ulong *)vt->kernel_pgd[0];

	if (verbose) 
		fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)pgd);

	page_dir = pgd + ((kvaddr >> PGDIR_SHIFT) & (PTRS_PER_PAGE - 1));

        FILL_PGD(PAGEBASE(pgd), KVADDR, PAGESIZE());
        pgd_pte = ULONG(machdep->pgd + PAGEOFFSET(page_dir));

	if (verbose)
		fprintf(fp, "  PGD: %lx => %lx\n", (ulong)page_dir, pgd_pte);

	if (!(pgd_pte & _PAGE_VALID))
		goto no_kpage;

	page_middle = (ulong *)
		(PTOV((pgd_pte & _PFN_MASK) >> (32-PAGESHIFT()))) + 
	  	((kvaddr >> PMD_SHIFT) & (PTRS_PER_PAGE - 1));

        FILL_PMD(PAGEBASE(page_middle), KVADDR, PAGESIZE());
        pmd_pte = ULONG(machdep->pmd + PAGEOFFSET(page_middle));

	if (verbose)
		fprintf(fp, "  PMD: %lx => %lx\n", (ulong)page_middle, pmd_pte);

	if (!(pmd_pte & _PAGE_VALID))
		goto no_kpage;

	page_table = (ulong *)
		(PTOV((pmd_pte & _PFN_MASK) >> (32-PAGESHIFT()))) +
     		(BTOP(kvaddr) & (PTRS_PER_PAGE - 1));
	
        FILL_PTBL(PAGEBASE(page_table), KVADDR, PAGESIZE());
        pte = ULONG(machdep->ptbl + PAGEOFFSET(page_table));

        if (verbose) 
                fprintf(fp, "  PTE: %lx => %lx\n", (ulong)page_table, pte);

	if (!(pte & (_PAGE_VALID))) {
		if (pte && verbose) {
			fprintf(fp, "\n");
			alpha_translate_pte(pte, 0, 0);
		}
		goto no_kpage;
	}

	*paddr = ((pte & _PFN_MASK) >> (32-PAGESHIFT())) + PAGEOFFSET(kvaddr);

        if (verbose) {
                fprintf(fp, " PAGE: %lx\n\n", PAGEBASE(*paddr));
		alpha_translate_pte(pte, 0, 0);
	}

	return TRUE;

no_kpage:
	return FALSE;
}


/*
 *  Get the relevant page directory pointer from a task structure.
 */
static ulong
alpha_get_task_pgd(ulong task)
{
	long offset;
	ulong ptbr;

	offset = OFFSET_OPTION(task_struct_thread, task_struct_tss);

	offset += OFFSET(thread_struct_ptbr);

        readmem(task + offset, KVADDR, &ptbr,
                sizeof(ulong), "task thread ptbr", FAULT_ON_ERROR);

	return(PTOV(PTOB(ptbr)));
}

/*
 *  Calculate and return the speed of the processor.
 */
static ulong
alpha_processor_speed(void)
{
	ulong hwrpb;
	long offset;
	long cycle_freq;
	ulong mhz;

	if (machdep->mhz)
		return machdep->mhz;

	mhz = 0;

	get_symbol_data("hwrpb", sizeof(void *), &hwrpb);
	offset = OFFSET(hwrpb_struct_cycle_freq);

	if (!hwrpb || (offset == -1) || 
	    !readmem(hwrpb+offset, KVADDR, &cycle_freq,
            sizeof(ulong), "hwrpb cycle_freq", RETURN_ON_ERROR))
		return (machdep->mhz = mhz);

	mhz = cycle_freq/1000000;

	return (machdep->mhz = mhz);
}

void
alpha_dump_machdep_table(ulong arg)
{
	int others;

	others = 0;
	fprintf(fp, "              flags: %lx (", machdep->flags);
        if (machdep->flags & HWRESET)
                fprintf(fp, "%sHWRESET", others++ ? "|" : "");
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
        fprintf(fp, "            memsize: %ld (0x%lx)\n", 
		machdep->memsize, machdep->memsize);
	fprintf(fp, "               bits: %d\n", machdep->bits);
	fprintf(fp, "            nr_irqs: %d\n", machdep->nr_irqs);
        fprintf(fp, "      eframe_search: alpha_eframe_search()\n");
        fprintf(fp, "         back_trace: alpha_back_trace_cmd()\n");
        fprintf(fp, "    processor_speed: alpha_processor_speed()\n");
        fprintf(fp, "              uvtop: alpha_uvtop()\n");
        fprintf(fp, "              kvtop: alpha_uvtop()\n");
        fprintf(fp, "       get_task_pgd: alpha_get_task_pgd()\n");
	if (machdep->dump_irq == generic_dump_irq)
		fprintf(fp, "           dump_irq: generic_dump_irq()\n");
	else
		fprintf(fp, "           dump_irq: alpha_dump_irq()\n");
	fprintf(fp, "    get_stack_frame: alpha_get_stack_frame()\n");
	fprintf(fp, "      get_stackbase: generic_get_stackbase()\n");
	fprintf(fp, "       get_stacktop: generic_get_stacktop()\n");
        fprintf(fp, "      translate_pte: alpha_translate_pte()\n");
	fprintf(fp, "        memory_size: alpha_get_memory_size()\n");
	fprintf(fp, "      vmalloc_start: alpha_get_vmalloc_start()\n");
	fprintf(fp, "       is_task_addr: alpha_is_task_addr()\n");
	fprintf(fp, "      verify_symbol: alpha_verify_symbol()\n");
	fprintf(fp, "         dis_filter: alpha_dis_filter()\n");
	fprintf(fp, "           cmd_mach: alpha_cmd_mach()\n");
	fprintf(fp, "       get_smp_cpus: alpha_get_smp_cpus()\n");
        fprintf(fp, "          is_kvaddr: generic_is_kvaddr()\n");
        fprintf(fp, "          is_uvaddr: generic_is_uvaddr()\n");
        fprintf(fp, "       verify_paddr: generic_verify_paddr()\n");
	fprintf(fp, "    init_kernel_pgd: NULL\n");
	fprintf(fp, "    value_to_symbol: generic_machdep_value_to_symbol()\n");
	fprintf(fp, "  line_number_hooks: alpha_line_number_hooks\n");
        fprintf(fp, "      last_pgd_read: %lx\n", machdep->last_pgd_read);
        fprintf(fp, "      last_pmd_read: %lx\n", machdep->last_pmd_read);
        fprintf(fp, "     last_ptbl_read: %lx\n", machdep->last_ptbl_read);
        fprintf(fp, "                pgd: %lx\n", (ulong)machdep->pgd);
        fprintf(fp, "                pmd: %lx\n", (ulong)machdep->pmd);
        fprintf(fp, "               ptbl: %lx\n", (ulong)machdep->ptbl);
	fprintf(fp, "       ptrs_per_pgd: %d\n", machdep->ptrs_per_pgd);
        fprintf(fp, "           machspec: %lx\n", (ulong)machdep->machspec);
}

/*
 *  Fix up jsr's to show the right target.
 *
 *  If a value is passed with no buf, then cmd_dis is fishing for whether
 *  the GP can be calculated from the first couple of instructions of the
 *  target routine:
 *
 *    0xfffffc0000349fa0 <sys_read>:  	      ldah    gp,35(t12)
 *    0xfffffc0000349fa4 <sys_read+4>:        lda     gp,6216(gp)
 *
 *  If a buf pointer is passed, then check whether the t12 register
 *  is being set up as an offset from gp, then calculate the target address:
 *
 *    0xfffffc000042c364 <start_tty+228>:     ldq     t12,-29336(gp)
 *    0xfffffc000042c368 <start_tty+232>:     
 *       jsr ra,(t12),0xfffffc0000429dc0 <decr_console+96>
 * 
 *  If the next instruction is a jsr ra,(t12), then correct the bracketed 
 *  target address translation.
 *  
 */

#define LDAH_GP_T12  (0x27bb0000)
#define LDA_GP_GP    (0x23bd0000)
#define LDQ_T12_GP   (0xa77d0000)   
#define JSR_RA_T12   (0x6b5b0000)

#define OPCODE_OPERAND_MASK  (0xffff0000)
#define OPCODE_MEM_DISP_MASK (0x0000ffff)

static struct instruction_data {
	uint inst[2];
	short mem_disp[2];
	ulong gp;
	ulong target;
	char *curfunc;
} instruction_data = { {0} };

static int
alpha_dis_filter(ulong vaddr, char *buf, unsigned int output_radix)
{
	struct syment *sp;
	struct instruction_data *id;
	char buf2[BUFSIZE], *p1;

	id = &instruction_data;

	if (!buf) {
		BZERO(id, sizeof(struct instruction_data));

		if (!(sp = value_search(vaddr, NULL)))   
			return FALSE;

		readmem(sp->value, KVADDR, &id->inst[0], 
			sizeof(uint) * 2, "two instructions", FAULT_ON_ERROR);

		if (((id->inst[0] & OPCODE_OPERAND_MASK) == LDAH_GP_T12) &&
		    ((id->inst[1] & OPCODE_OPERAND_MASK) == LDA_GP_GP)) {
			id->mem_disp[0] = (short)(id->inst[0] & 
				OPCODE_MEM_DISP_MASK);
			id->mem_disp[1] = (short)(id->inst[1] & 
				OPCODE_MEM_DISP_MASK);
			id->gp = sp->value + (65536*id->mem_disp[0]) +
				id->mem_disp[1];
			id->curfunc = sp->name;

			if (CRASHDEBUG(1))
                            console("%s: ldah(%d) and lda(%d) gp: %lx\n",
                                id->curfunc,
                                id->mem_disp[0], id->mem_disp[1],
                                id->gp);

			return TRUE;
		} 
                               /* send all lines through the generic */
		return TRUE;   /* dis_address_translation() filter */
	}

	dis_address_translation(vaddr, buf, output_radix);

	if (!id->gp || !(sp = value_search(vaddr, NULL)) || 
	    !STREQ(id->curfunc, sp->name)) {
		BZERO(id, sizeof(struct instruction_data));
		return FALSE;
	}

        readmem(vaddr, KVADDR, &id->inst[0],
        	sizeof(uint), "one instruction", FAULT_ON_ERROR);
        
	if ((id->inst[0] & OPCODE_OPERAND_MASK) == JSR_RA_T12) {

		if (!id->target || !strstr(buf, "jsr\tra,(t12)") ||
		    !strstr(buf, "<"))
			return FALSE;

		p1 = strstr(strstr(buf, "jsr"), "0x");
		sprintf(p1, "0x%lx <%s>%s", 
			id->target,
			value_to_symstr(id->target, buf2, output_radix),
			CRASHDEBUG(1) ? "  [PATCHED]\n" : "\n");
		return TRUE;
	}

	if ((id->inst[0] & OPCODE_OPERAND_MASK) == LDQ_T12_GP) {
		id->mem_disp[0] = (short)(id->inst[0] & OPCODE_MEM_DISP_MASK);
        	readmem(id->gp + id->mem_disp[0], KVADDR, &id->target,
                	sizeof(ulong), "jsr target", FAULT_ON_ERROR);
	} else
		id->target = 0;

	return TRUE;
}

/*
 *  For some reason gdb can go off into the weeds translating text addresses,
 *  so this routine both fixes the references as well as imposing the current
 *  output radix on the translations.
 */
static void
dis_address_translation(ulong vaddr, char *inbuf, unsigned int output_radix)
{
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char *colon, *p1;
	int argc;
	char *argv[MAXARGS];
	ulong value;

	console("IN: %s", inbuf);

	colon = strstr(inbuf, ":");

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
		while ((p1 > inbuf) && (*p1 != ',')) 
			p1--;

		if (!STRNEQ(p1, ",0x"))
			return;
		p1++;

		if (!extract_hex(p1, &value, NULLCHAR, TRUE))
			return;

		sprintf(buf1, "0x%lx <%s>\n", value,	
			value_to_symstr(value, buf2, output_radix));

		sprintf(p1, "%s", buf1);
	}

	console("    %s", inbuf);
}


/*
 *  If we're generically-inclined, call generic_dump_irq().  Otherwise
 *  dump the IRQ table the old-fashioned way.
 */
static void
alpha_dump_irq(int irq)
{
	ulong action;
	ulong value;
        char *arglist[MAXARGS];
	int argc, others;
	char buf[BUFSIZE];

	if (symbol_exists("irq_desc")) {
		machdep->dump_irq = generic_dump_irq;
		return(generic_dump_irq(irq));
	}

	action = symbol_value("irq_action") + (sizeof(void *) * irq);

        readmem(action, KVADDR, &action,
                sizeof(void *), "irq_action pointer", FAULT_ON_ERROR);

	if (!action) {
		fprintf(fp, "    IRQ: %d\n", irq);
		fprintf(fp, "handler:\n"); 
		fprintf(fp, "  flags: \n");
		fprintf(fp, "   mask: \n");
		fprintf(fp, "   name: \n");
		fprintf(fp, " dev_id: \n");
		fprintf(fp, "   next: \n\n");
		return;	
	}

        fprintf(fp, "    IRQ: %d\n", irq);

	open_tmpfile();

do_linked_action:
	dump_struct("irqaction", action, RADIX(16));
	action = 0;
        rewind(pc->tmpfile);
        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
		strip_comma(buf);
		argc = parse_line(buf, arglist);
		if (STREQ(arglist[0], "struct") || STREQ(buf, "};"))
			continue;

                if (STREQ(arglist[0], "handler")) {
                        fprintf(pc->saved_fp, "handler: %s  ",
                        	strip_hex(arglist[2]));
			if (argc == 4)
                        	fprintf(pc->saved_fp, "%s", arglist[3]);
			fprintf(pc->saved_fp, "\n");
                }
                if (STREQ(arglist[0], "flags")) {
			value = htol(strip_comma(arglist[2]), 
				FAULT_ON_ERROR, NULL);
                        fprintf(pc->saved_fp, 
				"  flags: %lx  ", value);
				
			if (value) {
				others = 0;
				fprintf(pc->saved_fp, "(");
	
				if (value & SA_INTERRUPT)
					fprintf(pc->saved_fp,
					    "%sSA_INTERRUPT",
						others++ ? "|" : "");
				if (value & SA_PROBE)
                                        fprintf(pc->saved_fp,
                                            "%sSA_PROBE",
                                                others++ ? "|" : "");
				if (value & SA_SAMPLE_RANDOM)
                                         fprintf(pc->saved_fp,
                                             "%sSA_SAMPLE_RANDOM",
                                                 others++ ? "|" : "");
				if (value & SA_SHIRQ)
                                         fprintf(pc->saved_fp,
                                             "%sSA_SHIRQ",
                                                 others++ ? "|" : "");
				fprintf(pc->saved_fp, ")");
				if (value & ~ACTION_FLAGS) {
					fprintf(pc->saved_fp,
					    "  (bits %lx not translated)",
						value & ~ACTION_FLAGS);
				}
			} 

			fprintf(pc->saved_fp, "\n");

		}
                if (STREQ(arglist[0], "mask")) {
			value = htol(strip_comma(arglist[2]), 
				FAULT_ON_ERROR, NULL);
                        fprintf(pc->saved_fp,
                        	"   mask: %lx\n", value);
		}
		if (STREQ(arglist[0], "name")) {
                        fprintf(pc->saved_fp, "   name: %s  ",
                        	strip_hex(arglist[2]));
			if (argc == 4)
				fprintf(pc->saved_fp, "\"%s\"", arglist[3]);
                        fprintf(pc->saved_fp, "\n");
                }
		if (STREQ(arglist[0], "dev_id")) {
                        value = htol(strip_comma(arglist[2]), 
				FAULT_ON_ERROR, NULL);
                        fprintf(pc->saved_fp,
                                " dev_id: %lx\n", value);
                }
		if (STREQ(arglist[0], "next")) {
                        value = htol(strip_comma(arglist[2]), 
				FAULT_ON_ERROR, NULL);
                        fprintf(pc->saved_fp,
                                "   next: %s\n",
                                	strip_hex(arglist[2]));
			if (value)
				action = value;
                }
	}
	close_tmpfile();

	fprintf(fp, "\n");

        if (action)
                goto do_linked_action;
}

/*
 *  Get a stack frame combination of pc and ra from the most relevent spot.
 */
static void
alpha_get_stack_frame(struct bt_info *bt, ulong *pcp, ulong *spp)
{
        struct syment *sp;
        ulong ksp;
	ulong ip;

	if (pcp) {
	        if (DUMPFILE() && is_panic_thread(bt->task)) {
			sp = next_symbol("crash_save_current_state", NULL);	

	                if (HWRESET_TASK(bt->task))
	                        ip = get_percpu_data(0, GET_HALT_PC, 0);
			else if (sp) 
	                        ip = sp->value - 4;
			else
	                       	ip = symbol_value("crash_save_current_state") 
					+ 16;
	        } else 
	        	get_alpha_frame(bt, &ip, NULL);

        	*pcp = ip;
	}

	if (spp) {
		ip = 0;
       		if (!get_panic_ksp(bt, &ksp))
                	get_alpha_frame(bt, 
				HWRESET_TASK(bt->task) ? &ip : NULL, &ksp);

        	if (!INSTACK(ksp, bt)) 
                	error(FATAL, 
			    "cannot determine starting stack address\n", 
				bt->task);

		*spp = ksp;
		if (ip)
			*pcp = ip;
	}
}

/*
 *  Do the work formerly done by alpha_get_sp() and alpha_get_pc().
 */
static void
get_alpha_frame(struct bt_info *bt, ulong *getpc, ulong *getsp)
{
	int i;
	ulong ip;
	ulong r26;
	ulong ksp, sp;
	ulong *spp;
	ulong percpu_ra;
	ulong percpu_pv;
	struct percpu_data percpu_data;
	char buf[BUFSIZE];
	ulong task;
	ulong *stack;

	task = bt->task;
	stack = (ulong *)bt->stackbuf;

	if (tt->flags & THREAD_INFO) { /* pcb.ksp is 1st word in thread_info */
		readmem(bt->tc->thread_info, KVADDR, &ksp, sizeof(ulong),
                	"thread_info pcb ksp", FAULT_ON_ERROR);
		sp = ksp;
	} else if (VALID_MEMBER(task_struct_tss_ksp))
                ksp = sp = stack[OFFSET(task_struct_tss_ksp)/sizeof(long)];
	else 
                ksp = sp = stack[OFFSET(task_struct_thread_ksp)/sizeof(long)];

	ip = 0;
	percpu_ra = percpu_pv = 0;
	spp = &stack[(sp - task)/sizeof(long)];

        if (DUMPFILE() && getsp) { 
		if (HWRESET_TASK(task)) {
			if (INSTACK(sp, bt)) {
				*getsp = sp;
				return;
			} else {
				get_percpu_data(0, 0, &percpu_data);
				percpu_ra = percpu_data.halt_ra;
				percpu_pv = percpu_data.halt_pv;
				spp = &stack[roundup(SIZE(task_struct), 
					sizeof(ulong)) / sizeof(ulong)];
			}
		}

            	if (!percpu_ra && (STREQ(closest_symbol(*spp), "panic") ||
                    STREQ(closest_symbol(*spp), "handle_ipi"))) {
                	*getsp = sp;
                	return;
		}
        }

percpu_retry:

	if (CRASHDEBUG(1) && percpu_ra) {
		fprintf(fp, "get_alpha_frame: look for %lx (%s)\n",
			percpu_ra, value_to_symstr(percpu_ra, buf, 0));
	}

	for (i = 0, spp++; spp < &stack[LONGS_PER_STACK]; spp++,i++) {

		if (CRASHDEBUG(1) && (percpu_ra || percpu_pv) && 
		    is_kernel_text(*spp)) {
			fprintf(fp, "%lx: %lx (%s)\n", 
				((ulong)spp - (ulong)stack) + task,
				*spp, value_to_symstr(*spp, buf, 0)); 
		}

                if (percpu_ra) {
                        if (*spp == percpu_ra) {
				*getsp = ((ulong)spp - (ulong)stack) + task;
				return;
			}
                        continue;
                } else if (percpu_pv) {
                        if (*spp == percpu_pv) {
                                *getsp = ((ulong)spp - (ulong)stack) + task;
				if (getpc)
					*getpc = percpu_pv;
                                return;
                        }
                        continue;
		}

		if (!INSTACK(*spp, bt))
			continue;

		if (is_kernel_text(*(spp+1))) {
			sp = *spp;
			ip = *(spp+1);
			break;
		}
	}

	if (percpu_ra) {
		percpu_ra = 0;

		error(INFO,
            "cannot find return address (percpu_ra) in HARDWARE RESET stack\n");
		error(INFO,
         "looking for procedure address (percpu_pv) in HARDWARE RESET stack\n");

        	if (CRASHDEBUG(1)) {
                	fprintf(fp, "get_alpha_frame: look for %lx (%s)\n",
                        	percpu_pv, value_to_symstr(percpu_pv, buf, 0));
        	}
		spp = &stack[roundup(SIZE(task_struct), 
			sizeof(ulong)) / sizeof(ulong)];

		goto percpu_retry;
	}

	if (percpu_pv) {
		error(INFO,
         "cannot find procedure address (percpu_pv) in HARDWARE RESET stack\n");
	}

	/*
	 *  Check for a forked task that has not yet run in user space.
	 */
	if (!ip) {
                if (INSTACK(ksp + OFFSET(switch_stack_r26), bt)) {
                        readmem(ksp + OFFSET(switch_stack_r26), KVADDR, 
				&r26, sizeof(ulong),
                                "ret_from_smp_fork check", FAULT_ON_ERROR);
                        if (STREQ(closest_symbol(r26), "ret_from_smp_fork") ||
			    STREQ(closest_symbol(r26), "ret_from_smpfork")) {
				ip = r26;
				sp = ksp;
			}
		}

	}

	if (getsp)
		*getsp = sp;
	if (getpc)
		*getpc = ip;

}

/*
 *  Fill the percpu_data structure with information from the 
 *  hwrpb/percpu_data structures for a given CPU.  If requested,
 *  return one of the specified entries.
 */
static ulong
get_percpu_data(int cpu, ulong flag, struct percpu_data *pd)
{
        ulong hwrpb, halt_ra, halt_PC, halt_pv;
        unsigned long processor_offset, processor_size;

        get_symbol_data("hwrpb", sizeof(void *), &hwrpb);

        readmem(hwrpb+OFFSET(hwrpb_struct_processor_offset), KVADDR,
                &processor_offset, sizeof(ulong),
                "hwrpb processor_offset", FAULT_ON_ERROR);

        readmem(hwrpb+OFFSET(hwrpb_struct_processor_size), KVADDR,
                &processor_size, sizeof(ulong),
                "hwrpb processor_size", FAULT_ON_ERROR);

        readmem(hwrpb + processor_offset + (cpu * processor_size) +
                OFFSET(percpu_struct_halt_PC),
                KVADDR, &halt_PC, sizeof(ulong),
                "percpu halt_PC", FAULT_ON_ERROR);

        readmem(hwrpb + processor_offset + (cpu * processor_size) +
                OFFSET(percpu_struct_halt_ra),
                KVADDR, &halt_ra, sizeof(ulong),
                "percpu halt_ra", FAULT_ON_ERROR);

        readmem(hwrpb + processor_offset + (cpu * processor_size) +
                OFFSET(percpu_struct_halt_pv),
                KVADDR, &halt_pv, sizeof(ulong),
                "percpu halt_pv", FAULT_ON_ERROR);

	if (pd) {
		pd->halt_PC = halt_PC;
		pd->halt_ra = halt_ra;
		pd->halt_pv = halt_pv;
	}

	switch (flag)
	{
	case GET_HALT_PC:
		return halt_PC;
		
	case GET_HALT_RA:
		return halt_ra;

	case GET_HALT_PV:
		return halt_pv;

	default:
		return 0;
	}
}

/*
 *  Translate a PTE, returning TRUE if the page is _PAGE_VALID or _PAGE_PRESENT,
 *  whichever is appropriate for the machine type.  If a physaddr pointer is
 *  passed in, don't print anything.
 */
static int
alpha_translate_pte(ulong pte, void *physaddr, ulonglong unused)
{
	int c, len1, len2, len3, others, page_present;
	char buf[BUFSIZE];
        char buf2[BUFSIZE];
        char buf3[BUFSIZE];
	char ptebuf[BUFSIZE];
	char physbuf[BUFSIZE];
        char *arglist[MAXARGS];
	physaddr_t paddr;

        paddr = PTOB(pte >> 32);
	page_present = (pte & _PAGE_VALID);

	if (physaddr) {
		*((ulong *)physaddr) = paddr;
		return page_present;
	}

	sprintf(ptebuf, "%lx", pte);
	len1 = MAX(strlen(ptebuf), strlen("PTE"));
	fprintf(fp, "%s  ", mkstring(buf, len1, CENTER|LJUST, "PTE"));

        if (!page_present && pte) {
                swap_location(pte, buf);
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
		if (pte & _PAGE_VALID)
			fprintf(fp, "%sVALID", others++ ? "|" : "");
		if (pte & _PAGE_FOR)
			fprintf(fp, "%sFOR", others++ ? "|" : "");
		if (pte & _PAGE_FOW)
			fprintf(fp, "%sFOW", others++ ? "|" : "");
		if (pte & _PAGE_FOE)
			fprintf(fp, "%sFOE", others++ ? "|" : "");
		if (pte & _PAGE_ASM)
			fprintf(fp, "%sASM", others++ ? "|" : "");
		if (pte & _PAGE_KRE)
			fprintf(fp, "%sKRE", others++ ? "|" : "");
		if (pte & _PAGE_URE)
			fprintf(fp, "%sURE", others++ ? "|" : "");
		if (pte & _PAGE_KWE)
			fprintf(fp, "%sKWE", others++ ? "|" : "");
		if (pte & _PAGE_UWE)
			fprintf(fp, "%sUWE", others++ ? "|" : "");
		if (pte & _PAGE_DIRTY)
			fprintf(fp, "%sDIRTY", others++ ? "|" : "");
		if (pte & _PAGE_ACCESSED)
			fprintf(fp, "%sACCESSED", others++ ? "|" : "");
	} else {
		fprintf(fp, "no mapping");
	}

	fprintf(fp, ")\n");

	return page_present;
}


/*
 *  This is currently not machine-dependent, but eventually I'd prefer to use
 *  the HWPCB for the real physical memory size.
 */
static uint64_t
alpha_memory_size(void)
{
	return (generic_memory_size());
}

/*
 *  Determine where vmalloc'd memory starts.
 */
static ulong
alpha_vmalloc_start(void)
{
	return VMALLOC_START;
}

/*
 *  ALPHA tasks are all stacksize-aligned.
 */
static int
alpha_is_task_addr(ulong task)
{
        return (IS_KVADDR(task) && (ALIGNED_STACK_OFFSET(task) == 0));
}

/*
 *  Keep or reject a symbol from the kernel namelist.
 */
int
alpha_verify_symbol(const char *name, ulong value, char type)
{
        if (CRASHDEBUG(8) && name && strlen(name))
                fprintf(fp, "%016lx %s\n", value, name);

	return (name && strlen(name) && (value > MIN_SYMBOL_VALUE));
}

/*
 *   Override smp_num_cpus if possible and necessary.
 */
int
alpha_get_smp_cpus(void)
{
	int cpus;

        if ((cpus = get_cpus_online()))
                return cpus;
        else
        	return kt->cpus;
}

/*
 *  Machine dependent command.
 */
void
alpha_cmd_mach(void)
{
        int c, cflag;
	unsigned int radix;

	cflag = radix = 0;

        while ((c = getopt(argcnt, args, "cxd")) != EOF) {
                switch(c)
                {
		case 'c':
			cflag++;
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
		display_hwrpb(radix);
	else
		alpha_display_machine_stats();
}

/*
 *  "mach" command output.
 */
static void
alpha_display_machine_stats(void)
{
        struct new_utsname *uts;
        char buf[BUFSIZE];
        ulong mhz;

        uts = &kt->utsname;

        fprintf(fp, "       MACHINE TYPE: %s\n", uts->machine);
        fprintf(fp, "        MEMORY SIZE: %s\n", get_memory_size(buf));
        fprintf(fp, "               CPUS: %d\n", kt->cpus);
        fprintf(fp, "    PROCESSOR SPEED: ");
        if ((mhz = machdep->processor_speed()))
                fprintf(fp, "%ld Mhz\n", mhz);
        else
                fprintf(fp, "(unknown)\n");
        fprintf(fp, "                 HZ: %d\n", machdep->hz);
        fprintf(fp, "          PAGE SIZE: %d\n", PAGESIZE());
        fprintf(fp, "      L1 CACHE SIZE: %d\n", l1_cache_size());
        fprintf(fp, "KERNEL VIRTUAL BASE: %lx\n", machdep->kvbase);
        fprintf(fp, "KERNEL VMALLOC BASE: %lx\n", vt->vmalloc_start);
        fprintf(fp, "  KERNEL STACK SIZE: %ld\n", STACKSIZE());
}

/*
 *  Display the hwrpb_struct and each percpu_struct.
 */
static void
display_hwrpb(unsigned int radix)
{
	int cpu;
	ulong hwrpb, percpu;
        ulong processor_offset, processor_size;
	
        get_symbol_data("hwrpb", sizeof(void *), &hwrpb);

        readmem(hwrpb+OFFSET(hwrpb_struct_processor_offset), KVADDR,
                &processor_offset, sizeof(ulong),
                "hwrpb processor_offset", FAULT_ON_ERROR);
        readmem(hwrpb+OFFSET(hwrpb_struct_processor_size), KVADDR,
                &processor_size, sizeof(ulong),
                "hwrpb processor_size", FAULT_ON_ERROR);

	fprintf(fp, "HWRPB:\n");
	dump_struct("hwrpb_struct", hwrpb, radix);

	for (cpu = 0; cpu < kt->cpus; cpu++) {
		fprintf(fp, "\nCPU %d:\n", cpu); 
		percpu = hwrpb + processor_offset + (processor_size * cpu);
		dump_struct("percpu_struct", percpu, radix);
	}
}

/*
 *  Perform any leftover pre-prompt machine-specific initialization tasks here.
 */
static void
alpha_post_init(void)
{
	modify_signame(7, "SIGEMT", NULL);
	modify_signame(10, "SIGBUS", NULL);
	modify_signame(12, "SIGSYS", NULL);
	modify_signame(16, "SIGURG", NULL);
	modify_signame(17, "SIGSTOP", NULL);
	modify_signame(18, "SIGTSTP", NULL);
	modify_signame(19, "SIGCONT", NULL);
	modify_signame(20, "SIGCHLD", NULL);
	modify_signame(23, "SIGIO", "SIGPOLL");
	modify_signame(29, "SIGINFO", "SIGPWR");
	modify_signame(30, "SIGUSR1", NULL);
	modify_signame(31, "SIGUSR2", NULL);
}


#endif /* ALPHA */
