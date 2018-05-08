/*
 * Copyright 1999 Silicon Graphics, Inc. All rights reserved.
 */

/* 
 *  lkcd_x86_trace.c
 *
 *  Copyright (C) 2002-2012, 2017-2018 David Anderson
 *  Copyright (C) 2002-2012, 2017-2018 Red Hat, Inc. All rights reserved.
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
 *  Adapted as noted from the following LKCD files:
 *
 *    lkcdutils-4.1/lcrash/arch/i386/lib/dis.c
 *    lkcdutils-4.1/lcrash/arch/i386/lib/trace.c
 *    lkcdutils-4.1/libutil/kl_queue.c
 */


#ifdef X86
#ifdef REDHAT

#include "lkcd_x86_trace.h"

#undef XEN_HYPER_MODE
static int XEN_HYPER_MODE(void) { return (pc->flags & XEN_HYPER) != 0; }

static void *kl_alloc_block(int, int);
static void kl_free_block(void *);
static void GET_BLOCK(kaddr_t, unsigned, void *);
static void kl_get_kaddr(kaddr_t, void *);
static char *kl_funcname(kaddr_t);
static kaddr_t kl_funcaddr(kaddr_t);
static syment_t *kl_lkup_symaddr(kaddr_t);
static k_error_t kl_get_task_struct(kaddr_t, int, void *);
static kaddr_t kl_kernelstack(kaddr_t);
static kaddr_t get_call_pc(kaddr_t);
static kaddr_t get_call_pc_v2(kaddr_t);
static int get_jmp_instr(kaddr_t, kaddr_t, kaddr_t *, char *, char **);
static int is_push(unsigned int);
static int is_pop(unsigned int);
static int get_framesize(kaddr_t, struct bt_info *);
static int cache_framesize(int, kaddr_t funcaddr, int *, void **);
struct framesize_cache;
static int framesize_modify(struct framesize_cache *);
struct framesize_mods;
static int compiler_matches(struct framesize_mods *);
static sframe_t *alloc_sframe(trace_t *, int);
static void free_sframes(trace_t *);
static void free_trace_rec(trace_t *);
static void clean_trace_rec(trace_t *);
static int setup_trace_rec(kaddr_t, kaddr_t, int, trace_t *);
static int valid_ra(kaddr_t);
static int valid_ra_function(kaddr_t, char *);
static int eframe_incr(kaddr_t, char *);
static int find_trace(kaddr_t, kaddr_t, kaddr_t, kaddr_t, trace_t *, int);
static void dump_stack_frame(trace_t *, sframe_t *, FILE *);
static void print_trace(trace_t *, int, FILE *);
static int eframe_type(uaddr_t *);
static char *funcname_display(char *, ulong, struct bt_info *, char *);
static void print_eframe(FILE *, uaddr_t *);
static void trace_banner(FILE *);
static void print_kaddr(kaddr_t, FILE *, int);
int do_text_list(kaddr_t, int, FILE *);
int print_traces(struct bt_info *, int, int, FILE *);
static int get_instr_info(kaddr_t, instr_rec_t *);
static instr_rec_t *get_instr_stream(kaddr_t, int, int);
static void free_instr_stream(instr_rec_t *);
static trace_t *alloc_trace_rec(int);
static void kl_enqueue(element_t**, element_t*);
static element_t *kl_dequeue(element_t**);
static void handle_trace_error(struct bt_info *, int, FILE *);
static int verify_back_trace(struct bt_info *);
static int recoverable(struct bt_info *, FILE *);
static void fill_instr_cache(kaddr_t, char *);
static void do_bt_reference_check(struct bt_info *, sframe_t *);
static void print_stack_entry(struct bt_info *, int, ulong, ulong, char *,
			      sframe_t *, FILE *);
static struct syment *eframe_label(char *, ulong);
static int dump_framesize_cache(FILE *, struct framesize_cache *);
static int modify_framesize_cache_entry(FILE *, ulong, int);
static int framesize_debug(struct bt_info *, FILE *);
static int kernel_entry_from_user_space(sframe_t *, struct bt_info *);

k_error_t klib_error = 0;

static void *
kl_alloc_block(int size, int flags)
{
	return ((void *)GETBUF(size));
}

static void
kl_free_block(void *blk)
{
        if (blk) 
		FREEBUF(blk);
}

static void 
GET_BLOCK(kaddr_t addr, unsigned size, void *buffer) 
{
	KL_ERROR = 0;
	if (!readmem(addr, KVADDR, (void *)buffer, (ulong)size,
	    "GET_BLOCK", RETURN_ON_ERROR|QUIET)) {
		console("GET_BLOCK: %lx (%d/0x%x)\n", addr, size, size);
		KL_ERROR = KLE_INVALID_READ;
	}
}

static void
kl_get_kaddr(kaddr_t addr, void *bp)
{
	KL_ERROR = 0;
	GET_BLOCK(addr, 4, bp);
}

static char *
kl_funcname(kaddr_t pc)
{
        struct syment *sp;
	char *buf, *name;
	struct load_module *lm;

	if ((sp = value_search(pc, NULL))) {
		if (STREQ(sp->name, "_stext") &&
	            (sp->value == (sp+1)->value))
			sp++;
		switch (sp->type)
		{
		case 'r':
			if (strstr(sp->name, "_interrupt") ||
			    STREQ(sp->name, "call_do_IRQ"))
				return sp->name;
			break;
		case 't':
		case 'T':
			return sp->name;
		}
		if (is_kernel_text(pc))
			return sp->name;
	}

        if (IS_MODULE_VADDR(pc)) {
		buf = GETBUF(BUFSIZE); 
		name = &buf[BUFSIZE/2];
            	if (module_symbol(pc, NULL, NULL, buf, output_radix)) {
                        sprintf(name, "(%s)", buf);
                        return name;
       		} else {
			FREEBUF(buf);
			return "(unknown module)";
		}
	}

	if ((lm = init_module_function(pc))) 
		return ("init_module");
 
       	return NULL;
}

static kaddr_t
kl_funcaddr(kaddr_t pc)
{
	struct syment *sp;
	struct load_module *lm;

        if ((sp = value_search(pc, NULL))) {
                switch (sp->type)
                {
                case 'r':
                        if (strstr(sp->name, "_interrupt") ||
                            STREQ(sp->name, "call_do_IRQ"))
                                return sp->value;
                        break;
                case 't':
                case 'T':
                        return sp->value;
                }
                if (is_kernel_text(pc))
                        return sp->value;
        }

	if ((lm = init_module_function(pc)))
		return lm->mod_init_module_ptr;

        return((kaddr_t)NULL);
}

static struct syment init_module_syment = {
	.name = "init_module",
	.type = 't',
};

static syment_t *
kl_lkup_symaddr(kaddr_t addr)
{
        struct syment *sp;
	struct load_module *lm;

        if ((sp = value_search(addr, NULL)))
		return sp;

	if ((lm = init_module_function(addr))) {
		init_module_syment.value = lm->mod_init_module_ptr;
		return &init_module_syment;
	}

	return NULL;
}

static k_error_t
kl_get_task_struct(kaddr_t value, int mode, void *tsp)
{
	KL_ERROR = 0;

	if (value == tt->last_task_read)
		BCOPY(tt->task_struct, tsp, TASK_STRUCT_SZ);
	else
        	GET_BLOCK(value, TASK_STRUCT_SZ, tsp);

        return KL_ERROR;
}

static kaddr_t
kl_kernelstack(kaddr_t task)
{
        kaddr_t saddr;

	return (saddr = (task + KSTACK_SIZE));
}

static void
print_kaddr(kaddr_t kaddr, FILE *ofp, int flag)
{
	fprintf(ofp, "%lx", (ulong)kaddr);
}
#endif  /* REDHAT */

/*
 *  lkcdutils-4.1/lcrash/arch/i386/lib/trace.c
 */

#ifndef REDHAT
/*
 * Copyright 1999 Silicon Graphics, Inc. All rights reserved.
 */
#include <lcrash.h>
#include <asm/lc_dis.h>
#include <strings.h>
#endif  /* !REDHAT */

/*
 * get_call_pc()
 */
kaddr_t
get_call_pc(kaddr_t ra)
{
	kaddr_t addr = 0;
	instr_rec_t *irp;

	if (!(irp = get_instr_stream(ra, 1, 0))) {
		return((kaddr_t)NULL);
	}
	if (!irp->prev) {
		free_instr_stream(irp);
		return((kaddr_t)NULL);
	}
	if ((irp->prev->opcode == 0x00e8) || (irp->prev->opcode == 0xff02)) {
		addr = irp->prev->addr;
	}
	free_instr_stream(irp);

	/*
	 *  If the old LKCD code fails, try disassembling...
	 */
	if (!addr)
		return get_call_pc_v2(ra);

	return(addr);
}

kaddr_t
get_call_pc_v2(kaddr_t ra)
{
	int c ATTRIBUTE_UNUSED; 
	int line, len;
	kaddr_t addr, addr2;
	ulong offset;
	struct syment *sp;
	char *arglist[MAXARGS];
	char buf[BUFSIZE];

	if ((sp = value_search(ra, &offset))) {
		if (offset == 0)
			return 0;
	} else
		return 0;

	addr = 0;

	for (len = 2; len < 8; len++) {
		open_tmpfile2();
		sprintf(buf, "x/2i 0x%x", ra - len);
		if (!gdb_pass_through(buf, pc->tmpfile2, GNU_RETURN_ON_ERROR)) {
			close_tmpfile2();
			return 0;
		}
	
		rewind(pc->tmpfile2);
		line = 1;
		while (fgets(buf, BUFSIZE, pc->tmpfile2)) {
			c = parse_line(buf, arglist);
			if ((line == 1) && !STREQ(arglist[2], "call"))
				break;
			if (line == 2) {
				addr2 = (kaddr_t)htol(arglist[0], RETURN_ON_ERROR|QUIET, 0);
				if (addr2 == ra) {
					addr = ra - len;
					break;
				}
			}
			line++;
		}

		close_tmpfile2();

		if (addr) {
			if (CRASHDEBUG(1)) {
				fprintf(fp, "get_call_pc_v2(ra: %x) -> %x -> ", ra, addr); 
				if (value_to_symstr(addr, buf, 0))
					fprintf(fp, "%s", buf);
				fprintf(fp, "\n");
			}
			break;
		}
	}

	return addr;
}

/*
 * get_jmp_instr()
 */
int
get_jmp_instr(kaddr_t addr, kaddr_t isp, kaddr_t *caddr, char *fname, 
	      char **cfname)
{
	kaddr_t a;
	int offset;
	instr_rec_t *irp;

	if (!(irp = get_instr_stream(addr, 1, 0))) {
		return(1);
	}
	if (!irp->prev) {
		free_instr_stream(irp);
		return(1);
	}
	irp = irp->prev;
	if (!(irp->opcode == 0x00e8) && !(irp->opcode == 0xff02)) {
		free_instr_stream(irp);
		return(1);
	}

	/* Check for the easiest case first...
	 */
	if (irp->opcode == 0xe8) {
		a = irp->operand[0].op_addr;
		if ((*cfname = kl_funcname(a))) {
			*caddr = a;
		}
	} else if (irp->opcode == 0xff02) {
		switch (irp->modrm) {
			case 0x14:
				if (irp->sib == 0x85) {
					kl_get_kaddr(addr - 4, &a);
					if (KL_ERROR) {
						free_instr_stream(irp);
						return(1);
					}
					if (strstr(fname, "system_call")) {
						GET_BLOCK(isp + 28, 4, &offset);
						a += (offset * 4);
						kl_get_kaddr(a, &a);
						if ((*cfname = 
							kl_funcname(a))) {
							*caddr = a;
						}
					}
				}
				break;

			case 0xc2: /* EAX */
			case 0xca: /* ECX */
			case 0xd2: /* EDX */
			case 0xda: /* EBX */
			case 0xea: /* EBP */
			case 0xf2: /* ESI */
			case 0xfa: /* EDI */
				break;
		} 
	}
	free_instr_stream(irp);
	return(0);
}

/* 
 * is_push()
 */
int
is_push(unsigned int opcode)
{
	switch(opcode) {
		case 0x0006:
		case 0x000e:
		case 0x0016:
		case 0x001e:
		case 0x0050:
		case 0x0051:
		case 0x0052:
		case 0x0053:
		case 0x0054:
		case 0x0055:
		case 0x0056:
		case 0x0057:
		case 0x0068:
		case 0x006a:
		case 0x009c:
		case 0x0fa0:
		case 0x0fa8:
		case 0xff06:
			return(1);
		case 0x0060:
			return(2);
	}
	return(0);
}

/* 
 * is_pop()
 */
int
is_pop(unsigned int opcode)
{
	switch(opcode) {
		case 0x0007:
		case 0x0017:
		case 0x001f:
		case 0x0058:
		case 0x0059:
		case 0x005a:
		case 0x005b:
		case 0x005c:
		case 0x005d:
		case 0x005e:
		case 0x005f:
		case 0x008f:
		case 0x009d:
		case 0x0fa1:
		case 0x0fa9:
			return(1);
		case 0x0061:
			return(2);
	}
	return(0);
}

#ifdef REDHAT

#define FRAMESIZE_VALIDATE (0x1)

struct framesize_cache {
	kaddr_t pc;
	int flags;
	int frmsize;
	int bp_adjust;
};
#define FRAMESIZE_CACHE (200)

static struct framesize_cache framesize_cache[FRAMESIZE_CACHE] = {{0}};
static struct framesize_cache framesize_cache_empty = {0};

#define FSZ_QUERY     (1)
#define FSZ_VALIDATE  (2)
#define FSZ_ENTER     (3)

#define FRAMESIZE_CACHE_QUERY(pc,szp) cache_framesize(FSZ_QUERY, pc, szp, NULL)
#define FRAMESIZE_CACHE_ENTER(pc,szp) cache_framesize(FSZ_ENTER, pc, szp, NULL)
#define FRAMESIZE_CACHE_VALIDATE(pc,fcpp) cache_framesize(FSZ_VALIDATE, pc, NULL, fcpp)

static int
cache_framesize(int cmd, kaddr_t funcaddr, int *fsize, void **ptr)
{
	int i;
	static ulong last_cleared = 0;

retry:
	for (i = 0; i < FRAMESIZE_CACHE; i++) {
		if (framesize_cache[i].pc == funcaddr) { 
			switch (cmd)
			{
			case FSZ_VALIDATE:
				*ptr = &framesize_cache[i];
				return TRUE;

			case FSZ_QUERY:
				*fsize = framesize_cache[i].frmsize;
				return TRUE;

			case FSZ_ENTER:
				*fsize = framesize_cache[i].frmsize;
				return TRUE;
			}
		}
		
		/*
		 *  The entry does not exist.
		 *
		 *  If FSZ_QUERY or FSZ_VALIDATE, return their 
		 *  no-such-entry indications.
		 *
		 *  Otherwise, load up the entry with the new data, and
		 *  and modify it with known kludgery.
		 */
		if (framesize_cache[i].pc == 0) {
			switch (cmd)
			{
			case FSZ_QUERY:
				return FALSE;

			case FSZ_VALIDATE:
				*ptr = &framesize_cache_empty;
				return FALSE;

			case FSZ_ENTER:
				framesize_cache[i].pc = funcaddr;
				framesize_cache[i].frmsize = *fsize;
				framesize_cache[i].bp_adjust = 0;
				framesize_modify(&framesize_cache[i]);
				*fsize = framesize_cache[i].frmsize;
				return TRUE;
			} 
		}
	}

	console("framesize_cache is full\n");

	/*
 	 *  No place to put it, or it doesn't exist.
	 */
	switch (cmd)
	{
	case FSZ_VALIDATE:
		*ptr = &framesize_cache_empty;
		return FALSE;

	case FSZ_QUERY:
		return FALSE;

	case FSZ_ENTER:
		BZERO(&framesize_cache[last_cleared % FRAMESIZE_CACHE], 
			sizeof(struct framesize_cache));
		last_cleared++;
		goto retry;
	}

	return FALSE; /* can't get here -- for compiler happiness */
}

/*
 *  More kludgery for compiler oddities.
 */
#define COMPILER_VERSION_MASK  (1)   /* deprecated -- usable up to 3.3.3 */
#define COMPILER_VERSION_EQUAL (2)
#define COMPILER_VERSION_START (3)
#define COMPILER_VERSION_RANGE (4)

struct framesize_mods {
	char *funcname;
	char *called_function;
	ulong compiler_flag;
	ulong compiler1;
	ulong compiler2;
	int pre_adjust;
	int post_adjust;
} framesize_mods[] = {
	{ "do_select", "schedule_timeout", 
		COMPILER_VERSION_START, GCC(3,3,2), 0, 0, 0 },
	{ "svc_recv", "schedule_timeout", 
		COMPILER_VERSION_START, GCC(3,3,2), 0, 0, 0 },
	{ "__down_interruptible", "schedule", 
		COMPILER_VERSION_START, GCC(3,3,2), 0, 0, 0 },
	{ "netconsole_netdump", NULL, 
	       	COMPILER_VERSION_START, GCC(3,3,2), 0, 0, -28 },
	{ "generic_file_write", NULL, 
		COMPILER_VERSION_EQUAL, GCC(2,96,0), 0, 0, 20 },  
	{ "block_prepare_write", NULL, 
		COMPILER_VERSION_EQUAL, GCC(2,96,0), 0, 0, 72 }, 
	{ "receive_chars", NULL, 
		COMPILER_VERSION_EQUAL, GCC(2,96,0), 0, 0, 48 },
	{ "default_idle", NULL, 
		COMPILER_VERSION_START, GCC(2,96,0), 0, -4, 0 },
	{ "hidinput_hid_event", NULL, 
		COMPILER_VERSION_START, GCC(4,1,2), 0, 0, 28 },
 	{ NULL, NULL, 0, 0, 0, 0, 0 },
};

static int
framesize_modify(struct framesize_cache *fc)
{
        char *funcname;
        struct framesize_mods *fmp;

        if (!(funcname = kl_funcname(fc->pc)))
                return FALSE;

	if (fc->frmsize < 0) {
		if (CRASHDEBUG(1))
			error(INFO, 
			    "bogus framesize: %d for pc: %lx (%s)\n",
				fc->frmsize, fc->pc, funcname);
		fc->frmsize = 0;
	}

        for (fmp = &framesize_mods[0]; fmp->funcname; fmp++) {
                if (STREQ(funcname, fmp->funcname) &&
                    compiler_matches(fmp))
                        break;
        }

	if (!fmp->funcname)
		return FALSE;

	if (fmp->pre_adjust) 
		fc->frmsize += fmp->pre_adjust;

        if (fmp->post_adjust) 
		fc->bp_adjust = fmp->post_adjust;

	if (fmp->called_function) {
		if (STREQ(fmp->called_function,x86_function_called_by(fc->pc)))
			fc->flags |= FRAMESIZE_VALIDATE;
	}

	return TRUE;
}

static int
compiler_matches(struct framesize_mods *fmp)
{
	switch (fmp->compiler_flag)
	{
	case COMPILER_VERSION_MASK:
		if (fmp->compiler1 & (kt->flags & GCC_VERSION_DEPRECATED))
			return TRUE;
		break;

	case COMPILER_VERSION_EQUAL:
		if (THIS_GCC_VERSION == fmp->compiler1)
			return TRUE;
		break;

	case COMPILER_VERSION_START:
		if (THIS_GCC_VERSION >= fmp->compiler1)
			return TRUE;
		break;

	case COMPILER_VERSION_RANGE:
		if ((THIS_GCC_VERSION >= fmp->compiler1) &&
		    (THIS_GCC_VERSION <= fmp->compiler2))
			return TRUE;
		break;
	}

	return FALSE;
}


static int
dump_framesize_cache(FILE *ofp, struct framesize_cache *fcp)
{
        int i, count;
        struct syment *sp, *spm;
	ulong offset;
	int once;

        for (i = once = count = 0; i < FRAMESIZE_CACHE; i++) {
		if (framesize_cache[i].pc == 0)
			break;

		count++;

		if (fcp && (fcp != &framesize_cache[i]))
			continue;

		if (!once) {
			fprintf(ofp, 
			    "RET ADDR   FSZ  BPA  V  FUNCTION\n");
			once++;
		}

		fprintf(ofp, "%8x %4d %4d  %s  ",
			framesize_cache[i].pc,
			framesize_cache[i].frmsize,
			framesize_cache[i].bp_adjust,
			framesize_cache[i].flags & FRAMESIZE_VALIDATE ?
			"V" : "-");	
        	if ((sp = value_search(framesize_cache[i].pc, &offset)) ||
		    (spm = kl_lkup_symaddr(framesize_cache[i].pc))) {
			if (sp) 
				fprintf(ofp, "(%s+", sp->name);
			else {
				fprintf(ofp, "(%s+", spm->name);
		    		offset = framesize_cache[i].pc - spm->value;
			}
			switch (pc->output_radix)
			{
			case 10:
				fprintf(ofp, "%ld)", offset);
				break;
			default:
			case 16:
				fprintf(ofp, "%lx)", offset);
				break;
			}
		} 
		fprintf(ofp, "\n");
		if (fcp)
			return 0;
	}

	if (!count)
		fprintf(ofp, "framesize cache emtpy\n");

	if (kt->flags & RA_SEEK)
		fprintf(ofp, "RA_SEEK: ON\n");
	if (kt->flags & NO_RA_SEEK)
		fprintf(ofp, "NO_RA_SEEK: ON\n");

	return count;
}

static int
modify_framesize_cache_entry(FILE *ofp, ulong eip, int framesize)
{
        int i, found, all_cleared;

        for (i = found = all_cleared = 0; i < FRAMESIZE_CACHE; i++) {
		if (!eip) {
			switch (framesize)
			{
			case -1:
				framesize_cache[i].flags |= FRAMESIZE_VALIDATE;
				break;
			case -2:
				framesize_cache[i].flags &= ~FRAMESIZE_VALIDATE;
				break;
			default:
				framesize_cache[i].pc = 0;
				framesize_cache[i].frmsize = 0;
				framesize_cache[i].flags = 0;
				all_cleared = TRUE;
				break;
			}
			continue;
		}

		if (framesize_cache[i].pc == 0)
			break;

                if (framesize_cache[i].pc == eip) {
			found++;

			switch (framesize)
			{
			case -1:
				framesize_cache[i].flags |= FRAMESIZE_VALIDATE;
				break;
			case -2:
				framesize_cache[i].flags &= ~FRAMESIZE_VALIDATE;
				break;
			default:
				framesize_cache[i].frmsize = framesize;
				break;
			}

			dump_framesize_cache(ofp, &framesize_cache[i]);

			return TRUE;
		}
        }

	if (eip && !found)
		fprintf(ofp, "eip: %lx not found in framesize cache\n", eip);

	if (all_cleared)
		fprintf(ofp, "framesize cache cleared\n");

	return FALSE;
}

/*
 *  If eip, look for it and replace its frmsize with the passed-in value.
 *  If no eip, frmsize of zero means clear the cache, non-zero displays it.
 */
static int 
framesize_debug(struct bt_info *bt, FILE *ofp)
{
	ulong eip; 
	int frmsize;

	eip = bt->hp->eip;
        frmsize = (int)bt->hp->esp;

	if (!eip) {
		switch (frmsize)
		{
		case 0:
		case -1:
		case -2:
			return modify_framesize_cache_entry(ofp, 0, frmsize);
		default:
			return dump_framesize_cache(ofp, NULL);
		}
	}

	return modify_framesize_cache_entry(ofp, eip, frmsize);
}

#endif /* REDHAT */

/*
#define FRMSIZE_DBG 1
#define FRMSIZE2_DBG 1
*/

/*
 * get_framesize()
 */
int
#ifdef REDHAT
get_framesize(kaddr_t pc, struct bt_info *bt)
#else
get_framesize(kaddr_t pc)
#endif
{
	int size, ret, frmsize = 0;
	kaddr_t addr;
	instr_rec_t irp;
        syment_t *sp;
#ifdef REDHAT
	int check_IRQ_stack_switch = 0;
	syment_t *jmpsp, *trampsp;
	ulong offset;
	int frmsize_restore = 0;
	int last_add = 0;

	if (FRAMESIZE_CACHE_QUERY(pc, &frmsize)) 
		return frmsize;

	frmsize = 0;
#endif

	if (!(sp = kl_lkup_symaddr(pc))) {
		return(0);
	}
#ifdef REDHAT
	if (STREQ(sp->name, "do_IRQ") && (tt->flags & IRQSTACKS)) 
		check_IRQ_stack_switch++;

        if (STREQ(sp->name, "stext_lock") || STRNEQ(sp->name, ".text.lock.")) {
		jmpsp = x86_text_lock_jmp(pc, &offset);
		if (jmpsp) {
			console("get_framesize: stext_lock %lx => %s\n", 
				pc, jmpsp->name);
			pc = jmpsp->value + offset;
			sp = jmpsp;
		}
	}

	if ((trampsp = x86_is_entry_tramp_address(pc, &offset))) {
		if (STREQ(sp->name, "system_call"))
			return 0;
                pc = trampsp->value + offset;
	}
#endif
#ifdef FRMSIZE_DBG
	fprintf(stderr, "get_framesize(): pc=0x%x (0x%x:%s)\n", 
		pc, sp->s_addr, sp->s_name);
#endif
	addr = sp->s_addr;
	while (addr <= pc) {
		bzero(&irp, sizeof(irp));
		irp.aflag = 1;
		irp.dflag = 1;
		if (!(size = get_instr_info(addr, &irp))) {
			fprintf(stderr, "ZERO SIZE!!\n");
			return(-1);
		}
		if (size != irp.size) {
			fprintf(stderr, "SIZE DOES NOT MATCH!!\n");
		}
#ifdef REDHAT
		/*
	 	 * Account for do_IRQ() stack switch.
		 */
		if (check_IRQ_stack_switch && (irp.opcode == 0xff02) && 
		    (irp.operand[0].op_reg == 0x7))
			break;
		/*
		 *  Account for embedded "ret" instructions screwing up
		 *  the frame size calculation.
		 */
		if (irp.opcode == 0xc3) {
			frmsize += frmsize_restore;
			frmsize_restore = 0;
			last_add = FALSE;
		} else if ((irp.opcode == 0x8300) &&
			(irp.operand[0].op_reg == R_eSP)) {
			frmsize_restore += irp.operand[1].op_addr;
			last_add = TRUE;
                } else if ((irp.opcode == 0x8100) &&
                        (irp.operand[0].op_reg == R_eSP)) {
                        frmsize_restore += irp.operand[1].op_addr;
                        last_add = TRUE;
		} else if ((ret = is_pop(irp.opcode))) {
			if (ret == 2)
				frmsize_restore += (8 * 4);
			else
				frmsize_restore += 4;
			last_add = FALSE;
		} else {
			if (last_add) 
				last_add = FALSE;
			else 
				frmsize_restore = 0;
		}
#endif /* REDHAT */
#ifdef REDHAT
		if ((irp.opcode == 0x8300) || (irp.opcode == 0x8100)) {
#else
		if (irp.opcode == 0x8300) {
#endif
			/* e.g., addl   $0x8,%esp */ 
			if (irp.operand[0].op_reg == R_eSP) {
				frmsize -= irp.operand[1].op_addr;
#ifdef FRMSIZE_DBG
				fprintf(stderr, "    addl  --> 0x%x: -%d\n", 
					addr, irp.operand[1].op_addr);
#endif
			}
		} else if ((irp.opcode == 0x8305) || (irp.opcode == 0x8105)) {
			/* e.g., subl   $0x40,%esp */
			if (irp.operand[0].op_reg == R_eSP) {
				frmsize += irp.operand[1].op_addr;
#ifdef FRMSIZE_DBG
				fprintf(stderr, "    subl  --> 0x%x: +%d\n", 
					addr, irp.operand[1].op_addr);
#endif
			}
		} else if ((ret = is_push(irp.opcode))) {
			if (ret == 2) {
				frmsize += (8 * 4);
#ifdef FRMSIZE_DBG
				fprintf(stderr, "   pusha  --> 0x%x: +%d\n",
					addr, (8 * 4));
#endif
			} else {
				frmsize += 4; 
#ifdef FRMSIZE_DBG
				fprintf(stderr, "   pushl  --> 0x%x: +%d\n" ,
					addr, 4);
#endif
			}
		} else if ((ret = is_pop(irp.opcode))) {
			if (ret == 2) {
				frmsize -= (8 * 4);
#ifdef FRMSIZE_DBG
				fprintf(stderr, "    popa  --> 0x%x: -%d\n", 
					addr, (8 * 4));
#endif
			} else {
				frmsize -= 4;
#ifdef FRMSIZE_DBG
				fprintf(stderr, "    popl  --> 0x%x: -%d\n", 
					addr, 4);
#endif
			}
#ifdef FRMSIZE2_DBG
		} else {
			fprintf(stderr, "              0x%x: opcode=0x%x\n", 
				addr, irp.opcode);
#endif
		}
		addr += size;
	}
#ifdef REDHAT
	/*
	 *  Account for fact that schedule may not "call" anybody, plus
	 *  the difference between gcc 3.2 and earlier compilers.
	 */
	if (STREQ(kl_funcname(pc), "schedule") && 
	    !(bt->flags & BT_CONTEXT_SWITCH)) 
		frmsize -= THIS_GCC_VERSION == GCC(3,2,0) ? 4 : 8;

        FRAMESIZE_CACHE_ENTER(pc, &frmsize);
#endif
	return(frmsize);
}

#ifndef REDHAT
/*
 * print_pc()
 */
void
print_pc(kaddr_t addr, FILE *ofp)
{
	int offset = 0;
	syment_t *sp;

	if ((sp = kl_lkup_symaddr(addr))) {
		offset = addr - sp->s_addr;
	}

	/* Print out address
	 */
	fprintf(ofp, "0x%x", addr);

	/* Print out symbol name
	 */
	if (sp) {
		if (offset) {
			fprintf(ofp, " <%s+%d>", sp->s_name, offset);
		} else {
			fprintf(ofp, " <%s>", sp->s_name);
		}
	}
}
#endif  /* !REDHAT */

/*
 * alloc_sframe() -- Allocate a stack frame record
 */
sframe_t *
alloc_sframe(trace_t *trace, int flags)
{
        sframe_t *f;

	if (flags & C_PERM) {
        	f = (sframe_t *)kl_alloc_block(sizeof(sframe_t), K_PERM);
	} else {
        	f = (sframe_t *)kl_alloc_block(sizeof(sframe_t), K_TEMP);
	}
        if (!f) {
                return((sframe_t *)NULL);
        }
        f->level = trace->nframes;
        return(f);
}

/*
 * free_sframes() -- Free all stack frames allocated to a trace record.
 */
void
free_sframes(trace_t *t)
{
        sframe_t *sf;

        t->nframes = 0;
        sf = t->frame;
        while(t->frame) {
                sf = (sframe_t *)kl_dequeue((element_t **)&t->frame);
                if (sf->srcfile) {
                        kl_free_block((void *)sf->srcfile);
                }
                kl_free_block((void *)sf);
        }
	t->frame = (sframe_t *)NULL;
}

/*
 * alloc_trace_rec() -- Allocate stack trace header
 */
trace_t *
alloc_trace_rec(int flags)
{
        trace_t *t;

	if (flags & C_PERM) {
		t = (trace_t *)kl_alloc_block(sizeof(trace_t), K_PERM);
	} else {
		t = (trace_t *)kl_alloc_block(sizeof(trace_t), K_TEMP);
	}
        return(t);
}

/*
 * free_trace_rec() -- Free memory associated with stack trace header
 */
void
free_trace_rec(trace_t *t)
{
        int i;

        if (t->tsp) {
                kl_free_block(t->tsp);
        }
        for (i = 0; i < STACK_SEGMENTS; i++) {
                if (t->stack[i].ptr) {
                        kl_free_block((void *)t->stack[i].ptr);
                }
        }
        free_sframes(t);
        kl_free_block((void *)t);
}

/*
 * clean_trace_rec() -- Clean up stack trace record without releasing
 *                      any of the allocated memory (except sframes).
 */
void
clean_trace_rec(trace_t *t)
{
	int i;

	t->flags = 0;
	t->task = 0;
	if (t->tsp) {
		kl_free_block(t->tsp);
		t->tsp = 0;
	}
	t->stackcnt = 0;
	for (i = 0; i < STACK_SEGMENTS; i++) {
		if (t->stack[i].ptr) {
			t->stack[i].type = 0;
			t->stack[i].size = 0;
			t->stack[i].addr = (kaddr_t)NULL;
			kl_free_block((void *)t->stack[i].ptr);
			t->stack[i].ptr = (uaddr_t *)NULL;
		}
	}
	free_sframes(t);
}

/* 
 * setup_trace_rec()
 */
int
setup_trace_rec(kaddr_t saddr, kaddr_t task, int flag, trace_t *trace)
{
	int aflag = K_TEMP;

#ifdef REDHAT
	KL_ERROR = 0;
#else
	kl_reset_error();
#endif

	if (flag & C_PERM) {
		aflag = K_PERM;
	}
	if (task) {
		trace->tsp = kl_alloc_block(TASK_STRUCT_SZ, aflag);
		if (kl_get_task_struct(task, 2, trace->tsp)) {
			kl_free_block(trace->tsp);
			trace->tsp = NULL;
			return(1);
		}
	}
	trace->stack[0].type = S_KERNELSTACK;
	trace->stack[0].size = STACK_SIZE;

	/* Get the base address of the stack
	 */
	trace->stack[0].addr = saddr - trace->stack[0].size;
	trace->stack[0].ptr = kl_alloc_block(STACK_SIZE, aflag);
	if (KL_ERROR) {
		clean_trace_rec(trace);
		return(1);
	}
#ifdef REDHAT
	BCOPY(trace->bt->stackbuf, trace->stack[0].ptr, STACK_SIZE);
#else
	GET_BLOCK(trace->stack[0].addr, STACK_SIZE, trace->stack[0].ptr);
#endif
	if (KL_ERROR) {
		clean_trace_rec(trace);
		return(1);
	}
	return(0);
}

/*
 * valid_ra()
 */
int
valid_ra(kaddr_t ra)
{
	kaddr_t pc;

	if ((ra < KL_PAGE_OFFSET) || !kl_funcaddr(ra)) 
		return(0);

	if ((pc = get_call_pc(ra))) 
		return(1);
	
	return(0);
}

/*
 * valid_ra_function() 
 *
 *  Same as above, but ensure that it calls the funcname passed in.
 */
int
valid_ra_function(kaddr_t ra, char *funcname)
{
        kaddr_t pc;

        if ((ra < KL_PAGE_OFFSET) || !kl_funcaddr(ra)) 
                return(0);

        if (!(pc = get_call_pc(ra))) 
                return(0);

	if (STREQ(x86_function_called_by(ra-5), funcname)) 
		return(1);

        return(0);
}

#ifndef REDHAT
#include <asm/segment.h>
#endif
#define KERNEL_EFRAME		0
#define USER_EFRAME		1
#define KERNEL_EFRAME_SZ	13	/* no ss and esp */
#define USER_EFRAME_SZ		15

#ifdef REDHAT
#undef __KERNEL_CS
#undef __KERNEL_DS
#undef __USER_CS
#undef __USER_DS

#define __KERNEL_CS     0x10
#define __KERNEL_DS     0x18

#define __USER_CS       0x23
#define __USER_DS       0x2B
#endif

/* 
 * Check if the exception frame is of kernel or user type 
 * Is checking only DS and CS values sufficient ?
 */

int eframe_type(uaddr_t *int_eframe)
{
	ushort xcs, xds;

	xcs = (ushort)(int_eframe[INT_EFRAME_CS] & 0xffff);
	xds = (ushort)(int_eframe[INT_EFRAME_DS] & 0xffff);

	if ((xcs == __KERNEL_CS) && (xds == __KERNEL_DS))
		return KERNEL_EFRAME;
#ifdef REDHAT
	else if ((xcs == 0x60) && (xds == 0x68))
		return KERNEL_EFRAME;
	else if ((xcs == 0x60) && (xds == 0x7b))
		return KERNEL_EFRAME;
	else if (XEN() && (xcs == 0x61) && (xds == 0x7b))
		return KERNEL_EFRAME;
#endif
	else if ((xcs == __USER_CS) && (xds == __USER_DS))
		return USER_EFRAME;
#ifdef REDHAT
	else if ((xcs == 0x73) && (xds == 0x7b))
		return USER_EFRAME;
#endif
	return -1;
}

void print_eframe(FILE *ofp, uaddr_t *regs)
{
	int type = eframe_type(regs);

#ifdef REDHAT
	x86_dump_eframe_common(NULL, (ulong *)regs, (type == KERNEL_EFRAME));
#else
	fprintf(ofp, "   ebx: %08lx   ecx: %08lx   edx: %08lx   esi: %08lx\n",
			regs->ebx, regs->ecx, regs->edx, regs->esi);
	fprintf(ofp, "   edi: %08lx   ebp: %08lx   eax: %08lx   ds:  %04x\n",
			regs->edi, regs->ebp, regs->eax, regs->xds & 0xffff);
	fprintf(ofp, "   es:  %04x       eip: %08lx   cs:  %04x       eflags: %08lx\n",
		       regs->xes & 0xffff, regs->eip, regs->xcs & 0xffff, regs->eflags);	
	if (type == USER_EFRAME)
		fprintf(ofp, "   esp: %08lx   ss:  %04x\n", regs->esp, regs->xss);
#endif
}

#ifdef REDHAT
#define SEEK_VALID_RA() 	                       \
{						       \
	while (!valid_ra(ra)) {                        \
        	if ((bp + 4) < bt->stacktop) {         \
                	bp += 4;                       \
                        ra = GET_STACK_ULONG(bp + 4);  \
                } else                                 \
                	break;                         \
	}				               \
}

#define SEEK_VALID_RA_FUNCTION(F)                      \
{                                                      \
        while (!valid_ra_function(ra, (F))) {          \
                if ((bp + 4) < bt->stacktop) {         \
                        bp += 4;                       \
                        ra = GET_STACK_ULONG(bp + 4);  \
                } else                                 \
                        break;                         \
        }                                              \
}
#endif

/*
 *  Determine how much to increment the stack pointer to find the 
 *  exception frame associated with a generic "error_code" or "nmi" 
 *  exception.
 *
 *  The incoming addr is that of the call to the generic error_code 
 *  or nmi exception handler function.  Until later 2.6 kernels, the next
 *  instruction had always been an "addl $8,%esp".  However, with later 
 *  2.6 kernels, that esp adjustment is no long valid, and there will be 
 *  an immediate "jmp" instruction.  Returns 4 or 12, whichever is appropriate. 
 *  Cache the value the first time, and allow for future changes or additions.
 */

#define NMI_ADJ         (0)
#define ERROR_CODE_ADJ  (1)
#define EFRAME_ADJUSTS  (ERROR_CODE_ADJ+1)

static int eframe_adjust[EFRAME_ADJUSTS] = { 0 };

static int
eframe_incr(kaddr_t addr, char *funcname)
{
	instr_rec_t irp;
	kaddr_t next;
	int size, adj, val;

	if (STRNEQ(funcname, "nmi")) {
		adj = NMI_ADJ;
		val = eframe_adjust[NMI_ADJ];
	} else if (strstr(funcname, "error_code")) {
		adj = ERROR_CODE_ADJ;
		val = eframe_adjust[ERROR_CODE_ADJ];
	} else { 
		adj = -1;
		val = 0;
		error(INFO, 
		    "unexpected exception frame marker: %lx (%s)\n",
			addr, funcname);
	}

	if (val) {
		console("eframe_incr(%lx, %s): eframe_adjust[%d]: %d\n", 
			addr, funcname, adj, val);
		return val;
	}
		
	console("eframe_incr(%lx, %s): TBD:\n", addr, funcname);

	bzero(&irp, sizeof(irp));
	irp.aflag = 1;
	irp.dflag = 1;
	if (!(size = get_instr_info(addr, &irp))) {
		if (CRASHDEBUG(1))
			error(INFO, 
			    "eframe_incr(%lx, %s): get_instr_info(%lx) failed\n", 
				addr, funcname, addr);			
		return((THIS_KERNEL_VERSION > LINUX(2,6,9)) ? 4 : 12);
	}
	console("  addr: %lx size: %d  opcode: 0x%x insn: \"%s\"\n", 
		addr, size, irp.opcode, irp.opcodep->name);

	next = addr + size;
	bzero(&irp, sizeof(irp));
	irp.aflag = 1;
	irp.dflag = 1;
	if (!(size = get_instr_info(next, &irp))) {
		if (CRASHDEBUG(1))
			error(INFO,
			    "eframe_incr(%lx, %s): get_instr_info(%lx) failed\n",
				addr, funcname, next);
		return((THIS_KERNEL_VERSION > LINUX(2,6,9)) ? 4 : 12);
	}
	console("  next: %lx size: %d  opcode: 0x%x insn: \"%s\"\n",
		next, size, irp.opcode, irp.opcodep->name);

	if (STREQ(irp.opcodep->name, "jmp") || STREQ(irp.opcodep->name, "nop"))
		val = 4;
	else
		val = 12;

	if (adj >= 0)
		eframe_adjust[adj] = val;

	return val;
}

static int 
xen_top_of_stack(struct bt_info *bt, char *funcname)
{
	ulong stkptr, contents;

	for (stkptr = bt->stacktop-4; stkptr > bt->stackbase; stkptr--) {
		contents = GET_STACK_ULONG(stkptr);
		if (kl_funcname(contents) == funcname)
			return TRUE;
		if (valid_ra(contents))
			break;
	}

	return FALSE;
}

static char *
xen_funcname(struct bt_info *bt, ulong pc) 
{
	char *funcname = kl_funcname(pc);

	if (xen_top_of_stack(bt, funcname) &&
	    (pc >= symbol_value("hypercall")) &&
	    (pc < symbol_value("ret_from_intr")))
		return "hypercall";

	return funcname;
}

static int
userspace_return(kaddr_t frame, struct bt_info *bt)
{
	ulong esp0, eframe_addr; 
	uint32_t *stkptr, *eframeptr;
	
	if (INVALID_MEMBER(task_struct_thread) ||
	    (((esp0 = MEMBER_OFFSET("thread_struct", "esp0")) < 0) &&
             ((esp0 = MEMBER_OFFSET("thread_struct", "sp0")) < 0)))
		eframe_addr = bt->stacktop - SIZE(pt_regs);
	else
		eframe_addr = ULONG(tt->task_struct + 
			OFFSET(task_struct_thread) + esp0) - SIZE(pt_regs);

	if (!INSTACK(eframe_addr, bt))
		return FALSE;

	stkptr = (uint32_t *)(bt->stackbuf + ((ulong)frame - bt->stackbase));
	eframeptr = (uint32_t *)(bt->stackbuf + (eframe_addr - bt->stackbase));

	while (stkptr < eframeptr) {
		if (is_kernel_text_offset(*stkptr))
			return FALSE;
		stkptr++;
	}

	return TRUE;
}

/*
 * find_trace()
 *
 *   Given a starting pc (start_cp), starting stack pointer (start_sp), 
 *   and stack address, check to see if a valid trace is possible. A
 *   trace is considered valid if no errors are encountered (bad PC,
 *   bad SP, etc.) Certain errors are tolorated however. For example,
 *   if the current stack frame is an exception frame (e.g., VEC_*),
 *   go ahead and return success -- even if PC and SP obtained from
 *   the exception frame are bad (a partial trace is better than no
 *   trace)..
 *
 *   Return zero if no valid trace was found. Otherwise, return the
 *   number of frames found. If the C_ALL flag is passed in, then
 *   return a trace even if it is a subtrace of a trace that was
 *   previously found.
 *
 *   Parameters:
 *
 *   start_pc       starting program counter
 *   start_sp       starting stack pointer
 *   check_pc       if non-NULL, check to see if check_pc/check_sp
 *   check_sp       are a sub-trace of trace beginning with spc/ssp
 *   trace          structure containing all trace related info (frames,
 *                  pages, page/frame counts, etc.
 *   flags
 */
int
find_trace(
	kaddr_t start_pc, 
	kaddr_t start_sp, 
	kaddr_t check_pc, 
	kaddr_t check_sp,
	trace_t *trace, 
	int flags)
{
	int curstkidx = 0, frame_size, frame_type;
	kaddr_t sp, pc, ra, bp, sbase, saddr, func_addr;
	sframe_t *curframe;
	char *func_name;
	uaddr_t *sbp, *asp;	
#ifdef REDHAT
	struct syment *sp1;
	ulong offset;
	int flag;
	int interrupted_system_call = FALSE;
	struct bt_info *bt = trace->bt;
	uaddr_t *pt;

	curframe = NULL;
#endif
	sbp = trace->stack[curstkidx].ptr;
	sbase = trace->stack[curstkidx].addr;
	saddr = sbase + trace->stack[curstkidx].size;
#ifdef REDHAT
	bp = start_sp + get_framesize(start_pc, bt); 
#else
	bp = start_sp + get_framesize(start_pc); 
#endif
	if (KL_ERROR || (bp < sbase) || (bp >= saddr)) {
		return(0);
	}
	pc = start_pc;
	sp = start_sp;
	func_name = kl_funcname(pc);
#ifdef REDHAT
	if (STREQ(func_name, "context_switch"))
		bt->flags |= BT_CONTEXT_SWITCH;
#endif

	while (pc) {

		/* LOOP TRAP! Make sure we are not just looping on the
		 * same frame forever.
		 */
		if ((trace->nframes > 1) &&
			(curframe->funcname == curframe->prev->funcname) &&
				(curframe->sp == curframe->prev->sp)) {
			curframe->error = 1;
#ifdef REDHAT
			bt->flags |= BT_LOOP_TRAP; 
#endif
			return(trace->nframes);
		} 
#ifdef REDHAT
		/*
		 *  If we wrap back to a lower stack location, we're cooked.
		 */
                if ((trace->nframes > 1) &&
                        (curframe->sp < curframe->prev->sp)) {
                        curframe->error = 1;
                        bt->flags |= BT_WRAP_TRAP;
                        return(trace->nframes);
                }
#endif

		/* Allocate space for a stack frame rec 
		 */
		curframe = alloc_sframe(trace, flags);
		if (!(func_addr = kl_funcaddr(pc))) {
			curframe->error = KLE_BAD_PC;
			UPDATE_FRAME(0, pc, 0, 0, 0, 0, 0, 0, 0, 0);
			return(trace->nframes);
		}

		/* Check to see if check_pc/check_sp points to a sub-trace
		 * of spc/ssp. If it does then don't return a trace (unless 
		 * C_ALL). Make sure we free the curframe block since we 
		 * wont be linking it in to the trace rec.
		 */
		if (check_pc && ((pc == check_pc) && (sp == check_sp))) {
			kl_free_block((void *)curframe);
			if (flags & C_ALL) {
				return(trace->nframes);
			} else {
				return(0);
			}
		}
		asp = (uaddr_t*)((uaddr_t)sbp + (STACK_SIZE - (saddr - sp)));

#ifdef REDHAT
		if (XEN_HYPER_MODE()) {
			func_name = xen_funcname(bt, pc);
			if (STREQ(func_name, "idle_loop") || STREQ(func_name, "hypercall")
				|| STREQ(func_name, "process_softirqs")
				|| STREQ(func_name, "tracing_off")
				|| STREQ(func_name, "page_fault")
				|| STREQ(func_name, "handle_exception")
				|| xen_top_of_stack(bt, func_name)) {
				UPDATE_FRAME(func_name, pc, 0, sp, bp, asp, 0, 0, bp - sp, 0);
				return(trace->nframes);
			}
		} else if (STREQ(closest_symbol(pc), "cpu_idle")) {
			func_name = kl_funcname(pc);
			UPDATE_FRAME(func_name, pc, 0, sp, bp, asp, 0, 0, bp - sp, 0);
			return(trace->nframes);
		}

		ra = GET_STACK_ULONG(bp + 4);
		/*
	  	 *  HACK: The get_framesize() function can return the proper
		 *  value -- as verified by disassembling the function -- but 
		 *  in rare circumstances there's more to the stack frame than 
		 *  meets the eye.  Until I can figure out why, extra space
		 *  can be added here for any "known" anomolies.  gcc version
		 *  restrictions are also added rather than assuming anything.
		 *  See framesize_modify() for kludgery. 
		 */
		if (!valid_ra(ra)) {
			char *funcname;
			struct framesize_cache *fcp;

			funcname = kl_funcname(pc);

			FRAMESIZE_CACHE_VALIDATE(pc, (void **)&fcp);
			bp += fcp->bp_adjust;

       			ra = GET_STACK_ULONG(bp + 4);

			/*
			 *  This anomoly would be caught by the recovery
			 *  speculation, but since we know it's an issue
			 *  just catch it here first.
			 */
			if (STREQ(funcname, "schedule") &&
			    (THIS_GCC_VERSION >= GCC(3,2,3))) {
				SEEK_VALID_RA();
			/* 
			 *  else FRAMESIZE_VALIDATE has been turned on
			 */
			} else if (fcp->flags & FRAMESIZE_VALIDATE) {
				SEEK_VALID_RA_FUNCTION(funcname);
			/*
			 *  Generic speculation continues the search for
			 *  a valid RA at a higher stack address.	
			 */
                        } else if ((bt->flags & BT_SPECULATE) &&
			    !STREQ(funcname, "context_switch") &&
			    !STREQ(funcname, "die") &&
		            !(bt->frameptr && ((bp+4) < bt->frameptr))) 
				SEEK_VALID_RA();
		}
#else
		kl_get_kaddr(bp + 4, &ra);
#endif
		

		/* Make sure that the ra we have is a valid one. If not
		 * then back up in the frame, word by word, until we find 
		 * one that is good.
		 */
		if (!valid_ra(ra)) {
			int i;

			i = ((bp - sp + 8) / 4);
			while (i) {
				bp -= 4;
#ifdef REDHAT
				ra = GET_STACK_ULONG(bp + 4);
#else
				kl_get_kaddr(bp + 4, &ra);
#endif
				if (valid_ra(ra)) {
					break;
				}
				i--;
			}
			if (i == 0)  {
#ifdef REDHAT
				if (interrupted_system_call) {
        				if ((sp1 = x86_is_entry_tramp_address
					    (pc, &offset)))
                				pc = sp1->value + offset;
					flag = EX_FRAME;
				} else {
					if (!XEN_HYPER_MODE() &&
					    !is_kernel_thread(bt->task) &&
					    (bt->stacktop == machdep->get_stacktop(bt->task))) {
					    	if (((ulong)(bp+4) + SIZE(pt_regs)) > bt->stacktop)
							flag = INCOMPLETE_EX_FRAME;
						else if ((sp1 = eframe_label(NULL, pc)) &&
					    	    	STREQ(sp1->name, "system_call"))
							flag = EX_FRAME|SET_EX_FRAME_ADDR;
						else if (STREQ(closest_symbol(pc), "ret_from_fork"))
							flag = EX_FRAME|SET_EX_FRAME_ADDR;
						else if (userspace_return(bp, bt))
							flag = EX_FRAME|SET_EX_FRAME_ADDR;
						else {
							curframe->error = KLE_BAD_RA;
							flag = 0;
						}
					} else {
						curframe->error = KLE_BAD_RA;
						flag = 0;
					}
				}
#else
				curframe->error = KLE_BAD_RA;
#endif
				UPDATE_FRAME(func_name, pc, ra, sp, 
					bp + 4, asp, 0, 0, 0, flag);

				return(trace->nframes);
			}
		} 

		UPDATE_FRAME(func_name, pc, ra, sp, bp + 4, asp, 0, 0, 0, 0);
		curframe->frame_size = curframe->fp - curframe->sp + 4;

		/* Gather starting information for the next frame
		 */
		pc = get_call_pc(ra);
#ifdef USE_FRAMEPTRS
		kl_get_kaddr(bp, &bp);
		if (KL_ERROR) {
			curframe->error = 2;
			return(trace->nframes);
		}
#else 
		/* It's possible for get_framesize() to return a size
		 * that is larger than the actual frame size (because
		 * all it does is count the push, pop, addl, and subl
		 * instructions that effect the SP). If we are real near
		 * the top of the stack, this might cause bp to overflow.
		 * This will be fixed above, but we need to bring bp 
		 * back into the legal range so we don't crap out
		 * before we can get to it...
		 */
#ifdef REDHAT
		frame_size = get_framesize(pc, bt);
		interrupted_system_call = FALSE;
#else
		frame_size = get_framesize(pc);
#endif
		if ((curframe->fp + frame_size) >= saddr) {
			bp = saddr - 4;
		} else {
			bp = curframe->fp + frame_size;
		}
#endif
		func_name = kl_funcname(pc);
		if (func_name && !XEN_HYPER_MODE()) {
			if (strstr(func_name, "kernel_thread")) {
				ra = 0;
				bp = saddr - 4;
				asp = (uaddr_t*)
					((uaddr_t)sbp + (STACK_SIZE - 12));
				curframe = alloc_sframe(trace, flags);
				UPDATE_FRAME(func_name, pc, 
					ra, sp, bp, asp, 0, 0, 16, 0);
				return(trace->nframes);
			} else if (strstr(func_name, "is386")) {
				ra = 0;
				bp = sp = saddr - 4;
				asp = curframe->asp;
				curframe = alloc_sframe(trace, flags);
				UPDATE_FRAME(func_name, pc, 
					ra, sp, bp, asp, 0, 0, 0, 0);
				return(trace->nframes);
			} else if (STREQ(func_name, "ret_from_fork")) {
				ra = 0;
				bp = sp = saddr - 4;
				asp = curframe->asp;
				curframe = alloc_sframe(trace, flags);
				UPDATE_FRAME(func_name, pc, 
					ra, sp, bp, asp, 0, 0, 0, EX_FRAME|SET_EX_FRAME_ADDR);
				return(trace->nframes);
#ifdef REDHAT
                        } else if (STREQ(func_name, "cpu_idle") ||
				STREQ(func_name, "cpu_startup_entry") ||
				STREQ(func_name, "start_secondary")) {
                                ra = 0;
                                bp = sp = saddr - 4;
                                asp = curframe->asp;
                                curframe = alloc_sframe(trace, flags);
                                UPDATE_FRAME(func_name, pc,
                                        ra, sp, bp, asp, 0, 0, 0, 0);
                                return(trace->nframes);

			} else if (strstr(func_name, "system_call") ||
				strstr(func_name, "sysenter_past_esp") ||
				eframe_label(func_name, pc) ||
				strstr(func_name, "syscall_call") ||
				strstr(func_name, "signal_return") ||
				strstr(func_name, "reschedule") ||
				kernel_entry_from_user_space(curframe, bt)) {
#else
			} else if (strstr(func_name, "system_call")) {
#endif
				/* 
				 * user exception frame, kernel stack ends 
				 * here.
				 */
				bp = saddr - 4;
				sp = curframe->fp + 4;
#ifdef REDHAT
				ra = GET_STACK_ULONG(bp-16);
#else
				kl_get_kaddr(bp-16, &ra);	
#endif
				curframe = alloc_sframe(trace, flags);
				asp = (uaddr_t*)((uaddr_t)sbp + 
					(STACK_SIZE - (saddr - sp)));
				UPDATE_FRAME(func_name, pc, ra, sp, bp, 
					asp, 0, 0, (bp - sp + 4), EX_FRAME);
				return(trace->nframes);
#ifdef REDHAT
			} else if (strstr(func_name, "error_code") 
				|| STREQ(func_name, "nmi_stack_correct")
				|| STREQ(func_name, "nmi")) {
#else
			} else if (strstr(func_name, "error_code")) {
#endif
				/* an exception frame */
				sp = curframe->fp + eframe_incr(pc, func_name);

				bp = sp + (KERNEL_EFRAME_SZ-1)*4;
				asp = (uaddr_t*)((uaddr_t)sbp + (STACK_SIZE - 
							(saddr - sp)));
				curframe = alloc_sframe(trace, flags);
				ra = asp[INT_EFRAME_EIP];
				frame_type = eframe_type(asp);
				UPDATE_FRAME(func_name, pc, ra, sp, bp, asp, 
						0, 0, (bp - sp + 4), EX_FRAME);

				/* prepare for next kernel frame, if present */
				if (frame_type == KERNEL_EFRAME) {
					pc = asp[INT_EFRAME_EIP];
					sp = curframe->fp+4;
#ifdef REDHAT
					bp = sp + get_framesize(pc, bt);
#else
					bp = sp + get_framesize(pc);
#endif
					func_name = kl_funcname(pc);
					continue;	
				} else {
					return(trace->nframes);
				}
			} else if (is_task_active(bt->task) && 
				(strstr(func_name, "call_do_IRQ") ||
				strstr(func_name, "common_interrupt") ||
				strstr(func_name, "reboot_interrupt") ||
				strstr(func_name, "call_function_interrupt"))) {
				/* Interrupt frame */
				sp = curframe->fp + 4;
				asp = (uaddr_t*)((uaddr_t)sbp + (STACK_SIZE - 
						(saddr - sp)));
				frame_type = eframe_type(asp);
				if (frame_type == KERNEL_EFRAME)
					bp = curframe->fp+(KERNEL_EFRAME_SZ-1)*4;
				else 
					bp = curframe->fp+(USER_EFRAME_SZ-1)*4;
				curframe = alloc_sframe(trace, flags);
				ra = asp[INT_EFRAME_EIP];
				UPDATE_FRAME(func_name, pc, ra, sp, bp + 4, asp,
			       	0, 0, curframe->fp - curframe->sp+4, EX_FRAME);

				/* prepare for next kernel frame, if present */
				if (frame_type == KERNEL_EFRAME) {
					sp = curframe->fp + 4;
					pc = asp[INT_EFRAME_EIP];
#ifdef REDHAT
					bp = sp + get_framesize(pc, bt);
#else
					bp = sp + get_framesize(pc);
#endif
					func_name = kl_funcname(pc);
#ifdef REDHAT
					/* interrupted system_call entry */
					if (STREQ(func_name, "system_call")) 
						interrupted_system_call = TRUE;
#endif
					continue;
				} else {
					return trace->nframes;
				}
			}
		}
		if (func_name && XEN_HYPER_MODE()) {
			if (STREQ(func_name, "continue_nmi") ||
			    STREQ(func_name, "vmx_asm_vmexit_handler") ||
			    STREQ(func_name, "common_interrupt") ||
			    STREQ(func_name, "handle_nmi_mce") ||
			    STREQ(func_name, "deferred_nmi")) {
				/* Interrupt frame */
				sp = curframe->fp + 4;
				asp = (uaddr_t*)((uaddr_t)sbp + (STACK_SIZE - 
						(saddr - sp)));
				bp = curframe->fp + (12 * 4);
				curframe = alloc_sframe(trace, flags);
				ra = *(asp + 9);
				UPDATE_FRAME(func_name, pc, ra, sp, bp + 4, asp,
			       	0, 0, curframe->fp - curframe->sp+4, 12 * 4);

				/* contunue next frame */
				pc = ra;
				sp = curframe->fp + 4;
				bp = sp + get_framesize(pc, bt);
				func_name = kl_funcname(pc);
				if (!func_name)
					return trace->nframes;
				continue;
			}
		}

		/*
		 *  Check for hypervisor_callback from user-space.
		 */
                if ((bt->flags & BT_XEN_STOP_THIS_CPU) && bt->tc->mm_struct &&
                    STREQ(kl_funcname(curframe->pc), "hypervisor_callback")) {
                	pt = curframe->asp+1;
                        if (eframe_type(pt) == USER_EFRAME) {
				if (program_context.debug >= 1)  /* pc above */
                        		error(INFO, 
					    "hypervisor_callback from user space\n");
                                curframe->asp++;
                                curframe->flag |= EX_FRAME;
                                return(trace->nframes);
                        }
                }

		/* Make sure our next frame pointer is valid (in the stack).
		 */
		if ((bp < sbase) || (bp >= saddr)) {
			curframe->error = 3;
			return(trace->nframes);
		}
		sp = curframe->fp + 4;
	}
	return(trace->nframes);
}

static int 
kernel_entry_from_user_space(sframe_t *curframe, struct bt_info *bt)
{
	ulong stack_segment;

	if (is_kernel_thread(bt->tc->task))
		return FALSE;

	stack_segment = GET_STACK_ULONG(curframe->fp + 4 + SIZE(pt_regs) - sizeof(kaddr_t));

	if ((curframe->fp + 4 + SIZE(pt_regs)) == GET_STACKTOP(bt->task)) {
		if ((stack_segment == 0x7b) || (stack_segment == 0x2b))
			return TRUE;
	}

	if ((curframe->fp + 4 + SIZE(pt_regs) + 8) == GET_STACKTOP(bt->task)) {
		if ((stack_segment == 0x7b) || (stack_segment == 0x2b))
			return TRUE;
	}

	if (userspace_return(curframe->fp+4, bt))
		return TRUE;
	else
		return FALSE;
}

#ifndef REDHAT
/*
 * pc_offset()
 */
int
pc_offset(kaddr_t pc) 
{
	kaddr_t func_addr;

	if ((func_addr = kl_funcaddr(pc))) {
		return(pc - func_addr);
	}
	return(-1);
}
#endif /* !REDHAT */

/*
 * dump_stack_frame()
 */
void
dump_stack_frame(trace_t *trace, sframe_t *curframe, FILE *ofp)
{
	int i, first_time = 1;
	kaddr_t sp;
	uaddr_t *asp;
	char buf[BUFSIZE];

	sp = curframe->sp;
	asp = curframe->asp;

	for (i = 0; i < curframe->frame_size / 4; i++) {
		if (!(i % 4)) {
			if (first_time) {
				first_time = 0;
#ifdef REDHAT
				fprintf(ofp, "    %x: %s  ", sp, 
					format_stack_entry(trace->bt, buf, *asp++, 0));
#else
				fprintf(ofp, "   %x: %08x  ", sp, *asp++);
#endif
			} else {
#ifdef REDHAT
				fprintf(ofp, "\n    %x: ", sp);
#else
				fprintf(ofp, "\n   %x: ", sp);
#endif
				fprintf(ofp, "%s  ", 
					format_stack_entry(trace->bt, buf, *asp++, 0));
			}
			sp += 16;
		} else  {
			fprintf(ofp, "%s  ", 
				format_stack_entry(trace->bt, buf, *asp++, 0));
		}
	}
	if (curframe->frame_size) {
#ifdef REDHAT
		fprintf(ofp, "\n");
#else
		fprintf(ofp, "\n\n");
#endif
	}
}

/*
 *  eframe_address()
 */
static uaddr_t *
eframe_address(sframe_t *frmp, struct bt_info *bt)
{
	ulong esp0, pt;

	if (!(frmp->flag & SET_EX_FRAME_ADDR) ||
	    INVALID_MEMBER(task_struct_thread) || 
	    (((esp0 = MEMBER_OFFSET("thread_struct", "esp0")) < 0) &&
	     ((esp0 = MEMBER_OFFSET("thread_struct", "sp0")) < 0)))
		return frmp->asp;
	/*  
	 * Work required in rarely-seen SET_EX_FRAME_ADDR circumstances.
	 */
	pt = ULONG(tt->task_struct + OFFSET(task_struct_thread) + esp0) 
	    	- SIZE(pt_regs);

	if (!INSTACK(pt, bt))
		return frmp->asp;

	return ((uint32_t *)(bt->stackbuf + (pt - bt->stackbase)));
}


/*
 * print_trace()
 */
void
print_trace(trace_t *trace, int flags, FILE *ofp)
{
	sframe_t *frmp;
#ifdef REDHAT
	kaddr_t fp = 0;
	kaddr_t last_fp ATTRIBUTE_UNUSED;
	kaddr_t last_pc, next_fp, next_pc;
	struct bt_info *bt;

	bt = trace->bt;
	last_fp = last_pc = next_fp = next_pc = 0;
#else
	int offset;
#endif

	if ((frmp = trace->frame)) {
		do {
#ifdef REDHAT
			if (trace->bt->flags & BT_LOOP_TRAP) {
				if (frmp->prev && frmp->error &&
				    (frmp->pc == frmp->prev->pc) &&
				    (frmp->fp == frmp->prev->fp))
					goto print_trace_error;
			}

			if ((trace->bt->flags & BT_WRAP_TRAP) && frmp->error) 
				goto print_trace_error;

			/*
			 *  We're guaranteed to run into an error when unwinding
			 *  a hard or soft IRQ stack, so just bail with success.
			 */
			if ((frmp->next != trace->frame) && frmp->next->error &&
				(bt->flags & (BT_LOOP_TRAP|BT_WRAP_TRAP)) &&
				(bt->flags & (BT_HARDIRQ|BT_SOFTIRQ))) 
				return;

			if ((frmp->level == 0) && (bt->flags & BT_XEN_STOP_THIS_CPU)) {
				print_stack_entry(trace->bt, 0, trace->bt->stkptr,
				symbol_value("stop_this_cpu"), 
				value_symbol(symbol_value("stop_this_cpu")),
				frmp, ofp);
			}

			print_stack_entry(trace->bt, (trace->bt->flags & 
				(BT_BUMP_FRAME_LEVEL|BT_XEN_STOP_THIS_CPU)) ?
                                frmp->level + 1 : frmp->level,
				fp ? (ulong)fp : trace->bt->stkptr,
				(ulong)frmp->pc, frmp->funcname, frmp, ofp);

			if (trace->bt->flags & BT_LOOP_TRAP) {
				last_fp = fp ? (ulong)fp : trace->bt->stkptr;
				last_pc = frmp->pc;
			}

			fp = frmp->fp;
#else
			fprintf(ofp, "%2d %s", frmp->level, frmp->funcname);
			offset = pc_offset(frmp->pc);
			if (offset > 0) {
				fprintf(ofp, "+%d", offset);
			} else if (offset < 0) {
				fprintf(ofp, "+<ERROR>");
			}
			fprintf(ofp, " [0x%x]\n", frmp->pc);
#endif
			if (frmp->flag & EX_FRAME) {
				if (CRASHDEBUG(1))
					fprintf(ofp, 
					    " EXCEPTION FRAME: %lx\n", 
						(unsigned long)frmp->sp);
				print_eframe(ofp, eframe_address(frmp, bt));
			}
#ifdef REDHAT
			if (CRASHDEBUG(1) && (frmp->flag & INCOMPLETE_EX_FRAME)) {
				fprintf(ofp, " INCOMPLETE EXCEPTION FRAME:\n");
				fprintf(ofp,
				    "    user stacktop: %lx  frame #%d: %lx  (+pt_regs: %lx)\n",
					bt->stacktop, frmp->level, (ulong)frmp->fp,
					(ulong)frmp->fp + SIZE(pt_regs));
			}

			if (trace->bt->flags & BT_FULL) {
                                fprintf(ofp, "    [RA: %x  SP: %x  FP: %x  "
                                        "SIZE: %d]\n", frmp->ra, frmp->sp,
                                        frmp->fp, frmp->frame_size);
                                dump_stack_frame(trace, frmp, ofp);
			}
#else
			if (flags & C_FULL) {
				fprintf(ofp, "\n");
				fprintf(ofp, "   RA=0x%x, SP=0x%x, FP=0x%x, "
					"SIZE=%d\n\n", frmp->ra, frmp->sp, 
					frmp->fp, frmp->frame_size);
#ifdef FRMSIZE_DBG
				fprintf(ofp, "\n  FRAMESIZE=%d\n\n",
#ifdef REDHAT
					get_framesize(frmp->pc, bt));
#else
					get_framesize(frmp->pc));
#endif
#endif
				dump_stack_frame(trace, frmp, ofp);
			}
#endif /* !REDHAT */
			if (frmp->error) {
#ifdef REDHAT
print_trace_error:
				KL_ERROR = KLE_PRINT_TRACE_ERROR;
				if (CRASHDEBUG(1) || trace->bt->debug)
					fprintf(ofp, 
					    "TRACE ERROR: 0x%llx %llx\n",
                                       	    	frmp->error, trace->bt->flags);
				if (trace->bt->flags & BT_WRAP_TRAP)
					return;
#else
				fprintf(ofp, "TRACE ERROR: 0x%llx\n", 
					frmp->error);
#endif
			}
			frmp = frmp->next;
		} while (frmp != trace->frame);
	}
}

/* 
 * trace_banner()
 */
void
trace_banner(FILE *ofp)
{
	fprintf(ofp, "===================================================="
			"============\n");
}

/*
 * task_trace()
 */
int
#ifdef REDHAT
lkcd_x86_back_trace(struct bt_info *bt, int flags, FILE *ofp)
#else
task_trace(kaddr_t task, int flags, FILE *ofp)
#endif
{
	void *tsp;
	kaddr_t saddr, eip, esp;
	ulong contents;
	trace_t *trace;

#ifdef REDHAT
	int nframes = 0;
	kaddr_t task = bt->task;
	KL_ERROR = 0;
	tsp = NULL;

	if (bt->flags & BT_FRAMESIZE_DEBUG) 
		return(framesize_debug(bt, ofp));

	if (kt->flags & RA_SEEK)
		bt->flags |= BT_SPECULATE;

	if (XENDUMP_DUMPFILE() && XEN() && is_task_active(bt->task) && 
    	    STREQ(kl_funcname(bt->instptr), "stop_this_cpu")) {
		/*
		 *  bt->instptr of "stop_this_cpu" is not a return
		 *  address -- replace it with the actual return
		 *  address found at the bt->stkptr location.
		 */
		if (readmem((ulong)bt->stkptr, KVADDR, &eip,
                    sizeof(ulong), "xendump eip", RETURN_ON_ERROR))
			bt->instptr = eip;
		bt->flags |= BT_XEN_STOP_THIS_CPU;
		if (CRASHDEBUG(1))
			error(INFO, "replacing stop_this_cpu with %s\n",
				kl_funcname(bt->instptr));
	}

	if (XENDUMP_DUMPFILE() && XEN() && is_idle_thread(bt->task) &&
	    is_task_active(bt->task) && 
	    !(kt->xen_flags & XEN_SUSPEND) &&
    	    STREQ(kl_funcname(bt->instptr), "schedule")) {
		/*
		 *  This is an invalid (stale) schedule reference
		 *  left in the task->thread.  Move down the stack 
		 *  until the smp_call_function_interrupt return 
		 *  address is found.
		 */
		saddr = bt->stkptr;
		while (readmem(saddr, KVADDR, &eip,
                    sizeof(ulong), "xendump esp", RETURN_ON_ERROR)) {
			if (STREQ(kl_funcname(eip), "smp_call_function_interrupt")) {
				bt->instptr = eip;
				bt->stkptr = saddr;
				bt->flags |= BT_XEN_STOP_THIS_CPU;
				if (CRASHDEBUG(1))
					error(INFO,
					    "switch schedule to smp_call_function_interrupt\n");
				break;
			}
			saddr -= sizeof(void *);
			if (saddr <= bt->stackbase)
				break;
		}
	}

        if (XENDUMP_DUMPFILE() && XEN() && is_idle_thread(bt->task) &&
            is_task_active(bt->task) &&
            (kt->xen_flags & XEN_SUSPEND) &&
            STREQ(kl_funcname(bt->instptr), "schedule")) {
		int framesize = 0;
                /*
                 *  This is an invalid (stale) schedule reference
                 *  left in the task->thread.  Move down the stack
                 *  until the hypercall_page() return address is
                 *  found, and fix up its framesize as we go.
                 */
                saddr = bt->stacktop;
                while (readmem(saddr, KVADDR, &eip,
                    sizeof(ulong), "xendump esp", RETURN_ON_ERROR)) {

                        if (STREQ(kl_funcname(eip), "xen_idle")) 
				framesize += sizeof(ulong);
			else if (framesize)
				framesize += sizeof(ulong);

                        if (STREQ(kl_funcname(eip), "hypercall_page")) {
				int framesize = 24;
                                bt->instptr = eip;
                                bt->stkptr = saddr;
                                if (CRASHDEBUG(1))
                                        error(INFO,
                                            "switch schedule to hypercall_page (framesize: %d)\n",
						framesize);
				FRAMESIZE_CACHE_ENTER(eip, &framesize);
                                break;
                        }
                        saddr -= sizeof(void *);
                        if (saddr <= bt->stackbase)
                                break;
                }
        }

	if (XENDUMP_DUMPFILE() && XEN() && !is_idle_thread(bt->task) &&
	    is_task_active(bt->task) && 
    	    STREQ(kl_funcname(bt->instptr), "schedule")) {
		/*
		 *  This is an invalid (stale) schedule reference
		 *  left in the task->thread.  Move down the stack 
		 *  until the smp_call_function_interrupt return 
		 *  address is found.
		 */
		saddr = bt->stacktop;
		while (readmem(saddr, KVADDR, &eip,
                    sizeof(ulong), "xendump esp", RETURN_ON_ERROR)) {
			if (STREQ(kl_funcname(eip), "smp_call_function_interrupt")) {
				bt->instptr = eip;
				bt->stkptr = saddr;
				bt->flags |= BT_XEN_STOP_THIS_CPU;
				if (CRASHDEBUG(1))
					error(INFO,
					    "switch schedule to smp_call_function_interrupt\n");
				break;
			}
			saddr -= sizeof(void *);
			if (saddr <= bt->stackbase)
				break;
		}
	}

	if (STREQ(kl_funcname(bt->instptr), "crash_kexec") ||
	    STREQ(kl_funcname(bt->instptr), "crash_nmi_callback")) {
		if (readmem(bt->stkptr-4, KVADDR, &contents, sizeof(ulong), 
		    "stkptr-4 contents", RETURN_ON_ERROR|QUIET) &&
		    (contents == bt->instptr))
			bt->stkptr -= 4;
	}

	if (!verify_back_trace(bt) && !recoverable(bt, ofp) && 
	    !BT_REFERENCE_CHECK(bt))
		error(INFO, "cannot resolve stack trace:\n");

        if (BT_REFERENCE_CHECK(bt)) 
		return(0);
#endif

	if (!XEN_HYPER_MODE()) {
	        if (!(tsp = kl_alloc_block(TASK_STRUCT_SZ, K_TEMP))) {
			return(1);
		}
		if (kl_get_task_struct(task, 2, tsp)) {
			kl_free_block(tsp);
			return(1);
		}
	}
	trace = (trace_t *)alloc_trace_rec(C_TEMP);
	if (!trace) {
#ifdef REDHAT
		error(INFO, "Could not alloc trace rec!\n");
#else
		fprintf(KL_ERRORFP, "Could not alloc trace rec!\n");
#endif
		return(1);
	} else {
#ifdef REDHAT
		saddr = kl_kernelstack(bt->stackbase);
       		eip = bt->instptr;
        	esp = bt->stkptr;
		trace->bt = bt;
#else
		saddr = kl_kernelstack(task);
		if (kl_smp_dumptask(task)) {
			eip = kl_dumpeip(task);
			esp = kl_dumpesp(task);
		} else {
			if (LINUX_2_2_X(KL_LINUX_RELEASE)) {
				eip = KL_UINT(K_PTR(tsp, "task_struct", "tss"), 
					"thread_struct", "eip");
				esp = KL_UINT(K_PTR(tsp, "task_struct", "tss"), 
				"thread_struct", "esp");
			} else {
				eip = KL_UINT(
					K_PTR(tsp, "task_struct", "thread"), 
					"thread_struct", "eip");
				esp = KL_UINT(
				K_PTR(tsp, "task_struct", "thread"), 
					"thread_struct", "esp");
			}
		}
#endif
		if (esp < KL_PAGE_OFFSET || eip < KL_PAGE_OFFSET) {
#ifdef REDHAT
			error(INFO, "Task in user space -- no backtrace\n");
#else
			fprintf(KL_ERRORFP, "Task in user space, No backtrace\n");
#endif
			return 1;
		}
		setup_trace_rec(saddr, 0, 0, trace);
		if (KL_ERROR) {
#ifdef REDHAT
			error(INFO, "Error setting up trace rec!\n");
#else
			fprintf(KL_ERRORFP, "Error setting up trace rec!\n");
#endif
			free_trace_rec(trace);
			return(1);
		}
#ifdef REDHAT
		nframes = find_trace(eip, esp, 0, 0, trace, 0);
#else
		find_trace(eip, esp, 0, 0, trace, 0);
		trace_banner(ofp);
		fprintf(ofp, "STACK TRACE FOR TASK: 0x%x", task);

		if (KL_TYPEINFO()) {
			fprintf(ofp, "(%s)\n\n", 
				(char *)K_PTR(tsp, "task_struct", "comm"));	
		} else {
			fprintf(ofp, "(%s)\n\n", 
				(char *)K_PTR(tsp, "task_struct", "comm"));
		}
#endif
		print_trace(trace, flags, ofp);
	}
	if (!XEN_HYPER_MODE())
		kl_free_block(tsp);

	free_trace_rec(trace);
#ifdef REDHAT
	if (KL_ERROR == KLE_PRINT_TRACE_ERROR) {
		handle_trace_error(bt, nframes, ofp);
		return(1);
	}
#endif
	return(0);
}

#ifdef REDHAT
/*
 *  Run find_trace() and check for any errors encountered.
 */
static int
verify_back_trace(struct bt_info *bt)
{
        void *tsp;
        kaddr_t saddr, eip, esp;
	int errcnt;
        trace_t *trace;
        sframe_t *frmp;

	errcnt = 0;
        KL_ERROR = 0;
	tsp = NULL;

	if (!XEN_HYPER_MODE()) {
	        if (!(tsp = kl_alloc_block(TASK_STRUCT_SZ, K_TEMP))) 
	                return FALSE;
	        
	        if (kl_get_task_struct(bt->task, 2, tsp)) {
	                kl_free_block(tsp);
	                return FALSE;
	        }
	}

        trace = (trace_t *)alloc_trace_rec(C_TEMP);
	if (!trace) 
		return FALSE;

	saddr = kl_kernelstack(bt->stackbase);

       	eip = bt->instptr;
        esp = bt->stkptr;
	trace->bt = bt;
	if (esp < KL_PAGE_OFFSET || eip < KL_PAGE_OFFSET) 
		return FALSE;
	
	setup_trace_rec(saddr, 0, 0, trace);
	if (KL_ERROR) {
		free_trace_rec(trace);
		return FALSE;
	}

	find_trace(eip, esp, 0, 0, trace, 0);

        if ((frmp = trace->frame)) {
                do {
			if (frmp->error) {
				/*
				 *  We're guaranteed to run into an error when
			         *  unwinding and IRQ stack, so bail out without
				 *  reporting the error.
				 */
				if ((bt->flags & (BT_HARDIRQ|BT_SOFTIRQ)) &&
				    (bt->flags & (BT_LOOP_TRAP|BT_WRAP_TRAP))) 
					break;
				
				errcnt++;
				if (!(bt->flags & BT_SPECULATE) && 
				    !bt->frameptr)
					bt->frameptr = frmp->fp;
			}
		        if (BT_REFERENCE_CHECK(bt))
				do_bt_reference_check(bt, frmp);
        		frmp = frmp->next;
                } while (frmp != trace->frame);
	}

	if (!XEN_HYPER_MODE())
		kl_free_block(tsp);

	free_trace_rec(trace);
        return (errcnt ? FALSE : TRUE);
}

/*
 *  Check a frame for a requested reference.
 */
static void
do_bt_reference_check(struct bt_info *bt, sframe_t *frmp)
{
        int type;
        struct syment *sp;

        sp = frmp->prev && STREQ(frmp->funcname, "error_code") ?
	    	x86_jmp_error_code((ulong)frmp->prev->pc) : NULL;

        switch (bt->ref->cmdflags & (BT_REF_SYMBOL|BT_REF_HEXVAL))
        {
        case BT_REF_SYMBOL:
                if (STREQ(kl_funcname(frmp->pc), bt->ref->str) || 
		    (sp && STREQ(sp->name, bt->ref->str)))
                        bt->ref->cmdflags |= BT_REF_FOUND;
                break;

        case BT_REF_HEXVAL:
                if ((bt->ref->hexval == frmp->pc) ||
		    (sp && (bt->ref->hexval == sp->value))) 
                        bt->ref->cmdflags |= BT_REF_FOUND;
                if (frmp->flag & EX_FRAME) {
			type = eframe_type(frmp->asp);
			x86_dump_eframe_common(bt, (ulong *)frmp->asp, 
				(type == KERNEL_EFRAME));
		}
                break;
        }
}

/*
 *  This function is a repository for "known" find_trace() failures that
 *  can be "fixed" on the fly.
 *
 *  Currently the routine only deals with BT_LOOP_TRAP/BT_WRAP_TRAP errors
 *  where get_framesize() leaves the bp in an invalid location, where
 *  where schedule() coming from schedule_timeout() is interrupted by a 
 *  false return address in between, those where the cpu_idle() trail
 *  cannot be followed, and where the functions called by kernel_thread()
 *  can't find their way back to kernel_thread().  As new fixable trace
 *  instances are discovered, add them in.
 *
 *  NOTE: the schedule() BT_LOOP_TRAP may have been subsequently fixed
 *  by the get_framesize() adjustment for schedule(), but it's worth
 *  keeping it around if a new schedule framesize anomoly pops up in
 *  the future.
 */
static int
recoverable(struct bt_info *bt, FILE *ofp)
{
        ulong esp, eip;
	sframe_t sframe;
        struct stack_hook *hp;
        struct bt_info btloc;
	ulong kernel_thread; 
	int calls_schedule;

	if (!(kt->flags & NO_RA_SEEK)) {
	        BCOPY(bt, &btloc, sizeof(struct bt_info));
		btloc.flags &= ~(ulonglong)BT_ERROR_MASK;
		btloc.flags |= BT_SPECULATE;
	        if (verify_back_trace(&btloc)) {
			bt->flags &= ~(ulonglong)BT_ERROR_MASK;
			bt->flags |= BT_SPECULATE;
			if (CRASHDEBUG(1) || bt->debug)
				error(INFO, 
					"recovered back trace with RA seek\n");
			return TRUE;
		}
	}

	if (!gather_text_list(bt) || 
	    !STREQ(kl_funcname(bt->instptr), "schedule"))
		return FALSE; 

	if (!is_idle_thread(bt->task) && !(bt->flags & BT_ERROR_MASK))
		return FALSE; 

        esp = eip = 0;
	calls_schedule = FALSE;
	kernel_thread = 0;

	for (hp = bt->textlist;	hp->esp; hp++) {
		if (STREQ(kl_funcname(hp->eip), "kernel_thread")) {
			kernel_thread = hp->eip;
			continue;
		}
		
		if (!calls_schedule && 
		    STREQ(x86_function_called_by(hp->eip-5), "schedule")) 
			calls_schedule = TRUE;

		if (STREQ(kl_funcname(hp->eip), "schedule_timeout")) {
			esp = hp->esp;
			eip = hp->eip;
			break;
		}

		if (STREQ(kl_funcname(hp->eip), "cpu_idle") && 
		    (bt->tc->pid == 0)) {
			esp = hp->esp;
			eip = hp->eip;
			bt->flags |= BT_CPU_IDLE;
			for ( ; BT_REFERENCE_CHECK(bt) && hp->esp; hp++) {
				if (STREQ(kl_funcname(hp->eip), "rest_init") ||
				    STREQ(kl_funcname(hp->eip), 
			            "start_kernel")) {
					BZERO(&sframe, sizeof(sframe_t));
					sframe.pc = hp->eip;
					do_bt_reference_check(bt, &sframe);
				} 
			}
			break;
		}
	}

        BCOPY(bt, &btloc, sizeof(struct bt_info));
	btloc.flags &= ~(ulonglong)BT_ERROR_MASK;

	if (esp && eip) {
                btloc.instptr = eip;
                btloc.stkptr = esp;
                if (verify_back_trace(&btloc)) {
			if (CRASHDEBUG(1) || bt->debug)
				error(INFO, "recovered stack trace:\n");
			if (!BT_REFERENCE_CHECK(bt))
                       		fprintf(ofp, " #0 [%08lx] %s at %lx\n",
                               		bt->stkptr, 
					kl_funcname(bt->instptr),
                               		bt->instptr);
			bt->instptr = eip;
			bt->stkptr = esp;
			bt->flags &= ~(ulonglong)BT_ERROR_MASK;
			bt->flags |= BT_BUMP_FRAME_LEVEL;
			FREEBUF(bt->textlist);
			return TRUE;
		}

		if (bt->flags & BT_CPU_IDLE) {
			if (CRASHDEBUG(1) || bt->debug)
				error(INFO, "recovered stack trace:\n");
			return TRUE;
		}
	}

	if (kernel_thread && calls_schedule && is_kernel_thread(bt->tc->task)) {
		if (CRASHDEBUG(1) || bt->debug)
			error(INFO, "recovered stack trace:\n");
		if (BT_REFERENCE_CHECK(bt)) {
                       	BZERO(&sframe, sizeof(sframe_t));
                        sframe.pc = kernel_thread;
                        do_bt_reference_check(bt, &sframe);
		}
		bt->flags |= BT_KERNEL_THREAD;
		return TRUE;
	}

	return FALSE;
}

/*
 *  If a trace is recoverable from this point finish it here.  Otherwise,
 *  if a back trace fails and is unrecoverable, dump the text symbols along
 *  with any possible exception frames that can be found on the stack. 
 */
static void
handle_trace_error(struct bt_info *bt, int nframes, FILE *ofp)
{
	int cnt, level;
	struct stack_hook *hp;

	if (CRASHDEBUG(2) || (bt->debug >= 2)) {
		for (hp = bt->textlist; hp->esp; hp++) {
			char *func;
			if ((func = x86_function_called_by(hp->eip-5)))
				fprintf(ofp, "%lx %s calls %s\n", hp->eip, 
					kl_funcname(hp->eip), func);
		}
	}

	if (bt->flags & BT_CPU_IDLE) {
		for (hp = bt->textlist, level = 2; hp->esp; hp++) {
			if (STREQ(kl_funcname(hp->eip), "rest_init") ||
                            STREQ(kl_funcname(hp->eip), "start_kernel")) 
				print_stack_entry(bt, level++, hp->esp, 
					hp->eip, kl_funcname(hp->eip), 
					NULL, ofp);
		}
		FREEBUF(bt->textlist);
		return;
	}

	if (bt->flags & BT_KERNEL_THREAD) {
		for (hp = bt->textlist; hp->esp; hp++) {
			if (STREQ(kl_funcname(hp->eip), "kernel_thread")) 
				print_stack_entry(bt, nframes-1, hp->esp, 
					hp->eip, "kernel_thread", NULL, ofp);
		}
		FREEBUF(bt->textlist);
		return;
	}

	error(INFO, "text symbols on stack:\n");
        bt->flags |= BT_TEXT_SYMBOLS_PRINT|BT_ERROR_MASK;
        back_trace(bt);

	if (!XEN_HYPER_MODE()) {
		bt->flags = BT_EFRAME_COUNT;
		if ((cnt = machdep->eframe_search(bt))) {
			error(INFO, "possible exception frame%s:\n", 
				cnt > 1 ? "s" : "");
			bt->flags &= ~(ulonglong)BT_EFRAME_COUNT;
			machdep->eframe_search(bt); 
		}
	}
}

/*
 *  Print a stack entry, and its line number if requested.
 */
static void
print_stack_entry(struct bt_info *bt, int level, ulong esp, ulong eip, 
		  char *funcname, sframe_t *frmp, FILE *ofp)
{
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	struct syment *sp;
	struct load_module *lm;

	if (frmp && frmp->prev && STREQ(frmp->funcname, "error_code") &&
	    (sp = x86_jmp_error_code((ulong)frmp->prev->pc)))
		sprintf(buf1, " (via %s)", sp->name);
	else if (frmp && (STREQ(frmp->funcname, "stext_lock") ||
		STRNEQ(frmp->funcname, ".text.lock")) &&
                (sp = x86_text_lock_jmp(eip, NULL)))
		sprintf(buf1, " (via %s)", sp->name);
	else
		buf1[0] = NULLCHAR;

	if ((sp = eframe_label(funcname, eip))) 
		funcname = sp->name;

	fprintf(ofp, "%s#%d [%8lx] %s%s at %lx",
                level < 10 ? " " : "", level, esp, 
		funcname_display(funcname, eip, bt, buf2), 
		strlen(buf1) ? buf1 : "", eip);
	if (module_symbol(eip, NULL, &lm, NULL, 0))
		fprintf(ofp, " [%s]", lm->mod_name);
	fprintf(ofp, "\n");

        if (bt->flags & BT_LINE_NUMBERS) {
                get_line_number(eip, buf1, FALSE);
                if (strlen(buf1))
                	fprintf(ofp, "    %s\n", buf1);
        }
}

/*
 *  The new process accounting stuff installs a label between system_call and 
 *  ret_from_sys_call, confusing the code that recognizes exception frame 
 *  symbols.  This function has been put in place to catch that anomoly, as 
 *  well as serving as a template for any future labels that get placed in the
 *  kernel entry point code.  It returns the syment of the "real" kernel entry
 *  point.  
 */

#define EFRAME_LABELS 10
static struct eframe_labels {
	int init;
	ulong syscall_labels[EFRAME_LABELS];
	struct syment *syscall;
	struct syment *syscall_end;
	ulong tracesys_labels[EFRAME_LABELS];
	struct syment *tracesys;
	struct syment *tracesys_exit;
	ulong sysenter_labels[EFRAME_LABELS];
	struct syment *sysenter;
	struct syment *sysenter_end;
} eframe_labels = { 0 };

static struct syment *
eframe_label(char *funcname, ulong eip)
{
	int i;
	struct eframe_labels *efp;
	struct syment *sp;

	if (XEN_HYPER_MODE())
		return NULL;	/* ODA: need support ? */

	efp = &eframe_labels;

	if (!efp->init) {
		if (!(efp->syscall = symbol_search("system_call"))) {
			if (CRASHDEBUG(1))
				error(WARNING, 
					"\"system_call\" symbol does not exist\n");
		}
		if ((sp = symbol_search("ret_from_sys_call")))
			efp->syscall_end = sp;
		else if ((sp = symbol_search("syscall_badsys")))
			efp->syscall_end = sp;
		else {
			if (CRASHDEBUG(1)) 
				error(WARNING, 
        "neither \"ret_from_sys_call\" nor \"syscall_badsys\" symbols exist\n");
		}

		if (efp->syscall) {
                	efp->tracesys = symbol_search("tracesys");
			efp->tracesys_exit = symbol_search("tracesys_exit");
		}

		if ((efp->sysenter = symbol_search("sysenter_entry")) ||
		    (efp->sysenter = symbol_search("ia32_sysenter_target"))) {
                	if ((sp = symbol_search("sysexit_ret_end_marker")))
                        	efp->sysenter_end = sp;
			else if (THIS_KERNEL_VERSION >= LINUX(2,6,32)) {
				if ((sp = symbol_search("sysexit_audit")) ||
				    (sp = symbol_search("sysenter_exit")))
                        		efp->sysenter_end = 
						next_symbol(NULL, sp);
				else error(WARNING, 
					"cannot determine end of %s function\n",
						efp->sysenter->name);
                	} else if ((sp = symbol_search("system_call")))
                        	efp->sysenter_end = sp;
			else
				error(WARNING, 
      "neither \"sysexit_ret_end_marker\" nor \"system_call\" symbols exist\n");
		}

		efp->init = TRUE;
	}

	/*
	 *  First search for the currently-known system_call labels.
	 */

	for (i = 0; (i < EFRAME_LABELS) && efp->syscall_labels[i]; i++) {
		if (efp->syscall_labels[i] == eip) 
			return efp->syscall; 
	}

        for (i = 0; (i < EFRAME_LABELS) && efp->tracesys_labels[i]; i++) {
                if (efp->tracesys_labels[i] == eip)
                        return efp->syscall;
        }

	for (i = 0; (i < EFRAME_LABELS) && efp->sysenter_labels[i]; i++) {
		if (efp->sysenter_labels[i] == eip) 
			return efp->sysenter; 
	}

	/*
	 *  If the eip fits in any of the label arrays, try to store it,  
	 *  but always return the real function it's referencing.
	 */
	if (efp->syscall && efp->syscall_end) {
		if (((eip >= efp->syscall->value) && 
		     (eip < efp->syscall_end->value))) {
			for (i = 0; i < EFRAME_LABELS; i++)
				if (!efp->syscall_labels[i])
					efp->syscall_labels[i] = eip;
			return efp->syscall;
		} 
	}

        if (efp->tracesys && efp->tracesys_exit) {
                if (((eip >= efp->tracesys->value) &&
                     (eip < efp->tracesys_exit->value))) {
                        for (i = 0; i < EFRAME_LABELS; i++)
                                if (!efp->tracesys_labels[i])
                                        efp->tracesys_labels[i] = eip;
                        return efp->syscall;
                }
        }

        if (efp->sysenter && efp->sysenter_end) {
                if (((eip >= efp->sysenter->value) &&
                     (eip < efp->sysenter_end->value))) {
                        for (i = 0; i < EFRAME_LABELS; i++)
                                if (!efp->sysenter_labels[i])
                                        efp->sysenter_labels[i] = eip;
                        return efp->sysenter;
                }
        }

	return NULL;
}

/*
 *  If it makes sense to display a different function/label name
 *  in a stack entry, it can be done here.  Unlike eframe_label(),
 *  this routine won't cause the passed-in function name pointer
 *  to be changed -- this is strictly for display purposes only.
 */
static char *
funcname_display(char *funcname, ulong eip, struct bt_info *bt, char *buf)
{
	struct syment *sp;
	ulong offset;

	if (bt->flags & BT_SYMBOL_OFFSET) {
		sp = value_search(eip, &offset);
		if (sp && offset)
			return value_to_symstr(eip, buf, bt->radix);
	}

        if (STREQ(funcname, "nmi_stack_correct") &&
            (sp = symbol_search("nmi"))) 
                return sp->name;

	return funcname;
}


/*
 *  Cache 2k starting from the passed-in text address.  This sits on top
 *  of the instrbuf 256-byte cache, but we don't want to extend its size
 *  because we can run off the end of a module segment -- if this routine
 *  does so, it's benign.  Tests of "foreach bt" result in more than an
 *  80% cache-hit rate.
 */
#define TEXT_BLOCK_SIZE (2048)

static void
fill_instr_cache(kaddr_t pc, char *buf)
{
	static kaddr_t last_block = 0;
	static char block[TEXT_BLOCK_SIZE];
	ulong offset;

	if ((pc >= last_block) && ((pc+256) < (last_block+TEXT_BLOCK_SIZE))) {
		offset = pc - last_block;
	} else {
        	if (readmem(pc, KVADDR, block, TEXT_BLOCK_SIZE,
               	    "fill_instr_cache", RETURN_ON_ERROR|QUIET)) {
			last_block = pc;
			offset = 0;
		} else {
			GET_BLOCK(pc, 256, block);
			last_block = 0;
			offset = 0;
		} 
	}

	BCOPY(&block[offset], buf, 256);
}
#endif

/*
 * print_traces()
 *
 *   Output a list of all valid code addresses contained in a stack
 *   along with their function name and stack location.
 */
int
#ifdef REDHAT
print_traces(struct bt_info *bt, int level, int flags, FILE *ofp)
#else
print_traces(kaddr_t saddr, int level, int flags, FILE *ofp)
#endif
{
	int nfrms;
	char *fname, *cfname;
	uaddr_t *wordp, *stackp;
	trace_t *trace;
	kaddr_t addr, isp, caddr, sbase;
#ifdef REDHAT
	kaddr_t saddr = bt->stkptr;
#endif
	
	stackp = (uaddr_t*)kl_alloc_block(STACK_SIZE, K_TEMP);
	sbase = saddr - STACK_SIZE;
	GET_BLOCK(sbase, STACK_SIZE, stackp);
	if (KL_ERROR) {
		kl_free_block(stackp);
		return(1);
	}

	if (!(trace = (trace_t *)alloc_trace_rec(K_TEMP))) {
#ifdef REDHAT
		error(INFO, "Could not alloc trace rec!\n");
#else
		fprintf(KL_ERRORFP, "Could not alloc trace rec!\n");
#endif
		kl_free_block(stackp);
		return(1);
	}
	setup_trace_rec(saddr, 0, 0, trace);
#ifdef REDHAT
	trace->bt = bt;
#endif

	wordp = stackp;
	while(wordp < (stackp + (STACK_SIZE / 4))) {
		if ((addr =  (kaddr_t)(*(uaddr_t*)wordp))) {

			/* check to see if this is a valid code address
			 */
			if ((fname = kl_funcname(addr))) {
				/* Now use the instruction to back up and
				 * see if this RA was saved after a call.
				 * If it was, then try to determine what 
				 * function was called. At the very least,
				 * only print out info for true return
				 * addresses (coming right after a call
				 * instruction -- even if we can't tell
				 * what function was called).
				 */
				isp = sbase + 
					(((uaddr_t)wordp) - ((uaddr_t)stackp));

				cfname = (char *)NULL;
				caddr = 0;
				if (get_jmp_instr(addr, isp, 
						&caddr, fname, &cfname)) {
					wordp++;
					continue;
				}

				/* We have found a valid jump address. Now, 
				 * try and get a backtrace.
				 */
				nfrms = find_trace(addr, isp, 0, 0, trace, 0);
				if (nfrms) {
					if ((nfrms >= level) &&
						 (!trace->frame->prev->error ||
							(flags & C_ALL))) {
						fprintf(ofp, "\nPC=");
						print_kaddr(addr, ofp, 0);
						fprintf(ofp, "  SP=");
						print_kaddr(isp, ofp, 0);
						fprintf(ofp, "  SADDR=");
						print_kaddr(saddr, ofp, 0);
						fprintf(ofp, "\n");
						trace_banner(ofp);
						print_trace(trace, flags, ofp);
						trace_banner(ofp);
					}
					free_sframes(trace);
				}
			}
			wordp++;
		} else {
			wordp++;
		}
	}
	kl_free_block(stackp);
	return(0);
}

/*
 * do_list()
 *
 *   Output a list of all valid code addresses contained in a stack
 *   along with their function name and stack location.
 */
int
#ifdef REDHAT
do_text_list(kaddr_t saddr, int size, FILE *ofp)
#else
do_list(kaddr_t saddr, int size, FILE *ofp)
#endif
{
	char *fname, *cfname;
	uaddr_t *wordp, *stackp;
	kaddr_t addr, isp, caddr, sbase;
	
	stackp = (uaddr_t*)kl_alloc_block(size, K_TEMP);
	sbase = saddr - size;
	GET_BLOCK(sbase, size, stackp);
	if (KL_ERROR) {
		kl_free_block(stackp);
		return(1);
	}

	wordp = stackp;
	while(wordp < (stackp + (size / 4))) {
		if ((addr =  (kaddr_t)(*(uaddr_t*)wordp))) {

			/* check to see if this is a valid code address
			 */
			if ((fname = kl_funcname(addr))) {
				/* Now use the instruction to back up and
				 * see if this RA was saved after a call.
				 * If it was, then try to determine what 
				 * function was called. At the very least,
				 * only print out info for true return
				 * addresses (coming right after a call
				 * instruction -- even if we can't tell
				 * what function was called).
				 */
				isp = sbase + 
					(((uaddr_t)wordp) - ((uaddr_t)stackp));

				cfname = (char *)NULL;
				caddr = 0;
				if (get_jmp_instr(addr, isp, 
						&caddr, fname, &cfname)) {
					wordp++;
					continue;
				}
				fprintf(ofp, "0x%x -- 0x%x (%s)",
						isp, addr, fname);
				if (cfname) {
					fprintf(ofp, " --> 0x%x (%s)\n",
						caddr, cfname);
				} else {
					fprintf(ofp, "\n");
				}
			}
			wordp++;
		} else {
			wordp++;
		}
	}
	kl_free_block(stackp);
	return(0);
}

#ifndef REDHAT
/*
 * add_frame()
 */
int
add_frame(trace_t *trace, kaddr_t fp, kaddr_t ra)
{
	sframe_t *cf, *sf;

	/* Check to make sure that sp is from the stack in the trace
	 * record.
	 *
	 * XXX -- todo
	 */
	sf = (sframe_t *)alloc_sframe(trace, C_PERM);
	sf->fp = fp;
	sf->ra = ra;
	if ((cf = trace->frame)) {
		do {
			if (cf->fp && (sf->fp < cf->fp)) {
				if (cf->next == cf) {
					cf->prev = sf;
					sf->next = cf;
					cf->next = sf;
					sf->prev = cf;
					trace->frame = sf;
				} else {
					cf->prev->next = sf;
					sf->prev = cf->prev;
					cf->prev = sf;
					sf->next = cf;
				}
				return(0);
			}
			cf = cf->next;
		} while (cf != trace->frame);
		cf = 0;
	} 
	if (!cf) {
		kl_enqueue((element_t **)&trace->frame, (element_t *)sf);
	}
	return(1);
}

/*
 * finish_trace()
 */
void
finish_trace(trace_t *trace)
{
	int level = 0, curstkidx = 0;
	uaddr_t *sbp;
	kaddr_t sbase, saddr;
	sframe_t *sf;

	sbp = trace->stack[curstkidx].ptr;
        sbase = trace->stack[curstkidx].addr;
        saddr = sbase + trace->stack[curstkidx].size;

	if ((sf = trace->frame)) {
		do {
			if (!sf->pc) {
				if (sf != trace->frame) {
					sf->sp = sf->prev->fp + 4;
					sf->pc = get_call_pc(sf->prev->ra);
				}
				if (!sf->pc) {
					sf = sf->next;
					continue;
				}
			}
			sf->level = level++;
			sf->frame_size = sf->fp - sf->sp + 4;
			sf->funcname = kl_funcname(sf->pc);
			sf->asp = (uaddr_t*)((uaddr_t)sbp + 
				(STACK_SIZE - (saddr - sf->sp)));
			sf = sf->next;
		} while (sf != trace->frame);

		if (level > 0) {
			sf = (sframe_t *)alloc_sframe(trace, C_PERM);
			sf->level = level;
			sf->sp = trace->frame->prev->fp + 4;
			sf->pc = get_call_pc(trace->frame->prev->ra);
			sf->funcname = kl_funcname(sf->pc);
			if (sf->funcname && 
					strstr(sf->funcname, "kernel_thread")) {
				sf->ra = 0;
				sf->fp = saddr - 4;
				sf->asp = (uaddr_t*)((uaddr_t)sbp + 
					(STACK_SIZE - 12));
			} else {
				sf->fp = saddr - 20;
				kl_get_kaddr(sf->fp, &sf->ra);
				sf->asp = (uaddr_t*)((uaddr_t)sbp + 
					(STACK_SIZE - (saddr - sf->sp)));
			}
			sf->frame_size = sf->fp - sf->sp + 4;
			kl_enqueue((element_t **)&trace->frame, 
				(element_t *)sf);
		}
	}
}

/*
 * dumptask_trace()
 */
int
dumptask_trace(
	kaddr_t curtask, 
	dump_header_asm_t *dha, 
	int flags, 
	FILE *ofp)
{
	kaddr_t eip, esp, saddr;
	void *tsp;
	trace_t *trace;
	int i;

	for (i = 0; i < dha->dha_smp_num_cpus; i++) {
		if (curtask == (kaddr_t)dha->dha_smp_current_task[i]) {
			eip = dha->dha_smp_regs[i].eip;
			esp = dha->dha_smp_regs[i].esp;
			break;
		}
	}

	tsp = kl_alloc_block(TASK_STRUCT_SZ, K_TEMP);
	if (!tsp) {
		return(1);
	}
	if (kl_get_task_struct(curtask, 2, tsp)) {
		kl_free_block(tsp);
		return(1);
	}
	if (!(trace = alloc_trace_rec(K_TEMP))) {
		fprintf(KL_ERRORFP, "Could not alloc trace rec!\n");
	} else {
		saddr = kl_kernelstack(curtask);
		setup_trace_rec(saddr, 0, 0, trace);
		find_trace(eip, esp, 0, 0, trace, 0);
		trace_banner(ofp);
		fprintf(ofp, "STACK TRACE FOR TASK: 0x%"FMTPTR"x (%s)\n\n",
			curtask, (char*)K_PTR(tsp, "task_struct", "comm"));
		print_trace(trace, flags, ofp);
		trace_banner(ofp);
		free_trace_rec(trace);
	}
	return(0);
}
#endif  /* !REDHAT */


/*
 *  lkcdutils-4.1/lcrash/arch/i386/lib/dis.c
 */

/*
 * Copyright 1999 Silicon Graphics, Inc. All rights reserved.
 */
#ifndef REDHAT
#include <lcrash.h>
#include <asm/lc_dis.h>
#include <strings.h>
#endif /* !REDHAT */

static int instr_buf_init = 1;
static instr_buf_t instrbuf;
static unsigned char *codeptr;

/* Forward declarations for local functions 
 */
static int seg_prefix(int);
static int op_e(int, int, instr_rec_t *);

static opcode_rec_t op_386[] = {

	/* 0x00 */
	{ "addb", Eb, Gb },	
	{ "addS", Ev, Gv },	
	{ "addb", Gb, Eb },	
	{ "addS", Gv, Ev },	
	{ "addb", AL, Ib },	
	{ "addS", eAX, Iv },	
	{ "pushS", es },		
	{ "popS", es },		

	/* 0x08 */	
	{ "orb", Eb, Gb },	
	{ "orS", Ev, Gv },	
	{ "orb", Gb, Eb },	
	{ "orS", Gv, Ev },	
	{ "orb", AL, Ib },	
	{ "orS", eAX, Iv },	
	{ "pushS", cs },		
	{ "(bad)", BAD },

	/* 0x10 */
	{ "adcb", Eb, Gb },
	{ "adcS", Ev, Gv },
	{ "adcb", Gb, Eb },
	{ "adcS", Gv, Ev },
	{ "adcb", AL, Ib },
	{ "adcS", eAX, Iv },
	{ "pushS", ss },
	{ "popS", ss },

	/* 0x18 */
	{ "sbbb", Eb, Gb },
	{ "sbbS", Ev, Gv },
	{ "sbbb", Gb, Eb },
	{ "sbbS", Gv, Ev },
	{ "sbbb", AL, Ib },
	{ "sbbS", eAX, Iv },
	{ "pushS", ds },
	{ "popS", ds },

	/* 0x20 */
	{ "andb", Eb, Gb },
	{ "andS", Ev, Gv },
	{ "andb", Gb, Eb },
	{ "andS", Gv, Ev },
	{ "andb", AL, Ib },
	{ "andS", eAX, Iv },      
	{ "(bad)", BAD },     /* SEG ES prefix */
	{ "daa", NONE },

	/* 0x28 */
	{ "subb", Eb, Gb },
	{ "subS", Ev, Gv },
	{ "subb", Gb, Eb },
	{ "subS", Gv, Ev },
	{ "subb", AL, Ib },
	{ "subS", eAX, Iv },
	{ "(bad)", BAD },      /* SEG CS prefix */
	{ "das", NONE },

	/* 0x30 */
	{ "xorb", Eb, Gb },
	{ "xorS", Ev, Gv },
	{ "xorb", Gb, Eb },
	{ "xorS", Gv, Ev },
	{ "xorb", AL, Ib },
	{ "xorS", eAX, Iv },
	{ "(bad)", BAD },      /* SEG SS prefix */
	{ "aaa", NONE },

	/* 0x38 */
	{ "cmpb", Eb, Gb },
	{ "cmpS", Ev, Gv },
	{ "cmpb", Gb, Eb },
	{ "cmpS", Gv, Ev },
	{ "cmpb", AL, Ib },
	{ "cmpS", eAX, Iv },
	{ "(bad)", BAD },	/* SEG DS previx */
	{ "aas", NONE },

	/* 0x40 */
	{ "incS", eAX },
	{ "incS", eCX },
	{ "incS", eDX },
	{ "incS", eBX },
	{ "incS", eSP },
	{ "incS", eBP },
	{ "incS", eSI },
	{ "incS", eDI },

	/* 0x48 */
	{ "decS", eAX },
	{ "decS", eCX },
	{ "decS", eDX },
	{ "decS", eBX },
	{ "decS", eSP },
	{ "decS", eBP },
	{ "decS", eSI },
	{ "decS", eDI },

	/* 0x50 */
	{ "pushS", eAX },
	{ "pushS", eCX },
	{ "pushS", eDX },
	{ "pushS", eBX },
	{ "pushS", eSP },
	{ "pushS", eBP },
	{ "pushS", eSI },
	{ "pushS", eDI },

	/* 0x58 */
	{ "popS", eAX },
	{ "popS", eCX },
	{ "popS", eDX },
	{ "popS", eBX },
	{ "popS", eSP },
	{ "popS", eBP },
	{ "popS", eSI },
	{ "popS", eDI },

	/* 0x60 */
	{ "pusha", NONE },
	{ "popa", NONE },
	{ "boundS", Gv, Ma },
	{ "arpl", Ew, Gw },
	{ "(bad)", BAD }, 	/* seg fs */
	{ "(bad)", BAD },	/* seg gs */
	{ "(bad)", BAD },	/* op size prefix */
	{ "(bad)", BAD },	/* adr size prefix */

	/* 0x68 */
	{ "pushS", Iv },         
	{ "imulS", Gv, Ev, Iv },
	{ "pushS", sIb },   /* push of byte really pushes 2 or 4 bytes */
	{ "imulS", Gv, Ev, Ib },
	{ "insb", Yb, indirDX },
	{ "insS", Yv, indirDX },
	{ "outsb", indirDX, Xb },
	{ "outsS", indirDX, Xv },

	/* 0x70 */
	{ "jo", Jb },
	{ "jno", Jb },
	{ "jb", Jb },
	{ "jae", Jb },
	{ "je", Jb },
	{ "jne", Jb },
	{ "jbe", Jb },
	{ "ja", Jb },

	/* 0x78 */
	{ "js", Jb },
	{ "jns", Jb },
	{ "jp", Jb },
	{ "jnp", Jb },
	{ "jl", Jb },
	{ "jnl", Jb },
	{ "jle", Jb },
	{ "jg", Jb },

	/* 0x80 */
	{ GRP1b },
	{ GRP1S },
	{ "(bad)", BAD },
	{ GRP1Ss },
	{ "testb", Eb, Gb },
	{ "testS", Ev, Gv },
	{ "xchgb", Eb, Gb },
	{ "xchgS", Ev, Gv },

	/* 0x88 */
	{ "movb", Eb, Gb },
	{ "movS", Ev, Gv },
	{ "movb", Gb, Eb },
	{ "movS", Gv, Ev },
	{ "movw", Ew, Sw },
	{ "leaS", Gv, M },
	{ "movw", Sw, Ew },
	{ "popS", Ev },

	/* 0x90 */
	{ "nop", NONE },
	{ "xchgS", eCX, eAX },
	{ "xchgS", eDX, eAX },
	{ "xchgS", eBX, eAX },
	{ "xchgS", eSP, eAX },
	{ "xchgS", eBP, eAX },
	{ "xchgS", eSI, eAX },
	{ "xchgS", eDI, eAX },

	/* 0x98 */
	{ "cWtS", NONE },
	{ "cStd", NONE },
	{ "lcall", Ap },
	{ "(bad)", BAD }, 	/* fwait */
	{ "pushf", NONE },
	{ "popf", NONE },
	{ "sahf", NONE },
	{ "lahf", NONE },

	/* 0xa0 */
	{ "movb", AL, Ob },
	{ "movS", eAX, Ov },
	{ "movb", Ob, AL },
	{ "movS", Ov, eAX },
	{ "movsb", Yb, Xb },
	{ "movsS", Yv, Xv },
	{ "cmpsb", Yb, Xb },
	{ "cmpsS", Yv, Xv },

	/* 0xa8 */
	{ "testb", AL, Ib },
	{ "testS", eAX, Iv },
	{ "stosb", Yb, AL },
	{ "stosS", Yv, eAX },
	{ "lodsb", AL, Xb },
	{ "lodsS", eAX, Xv },
	{ "scasb", AL, Yb },
	{ "scasS", eAX, Yv },

	/* 0xb0 */
	{ "movb", AL, Ib },
	{ "movb", CL, Ib },
	{ "movb", DL, Ib },
	{ "movb", BL, Ib },
	{ "movb", AH, Ib },
	{ "movb", CH, Ib },
	{ "movb", DH, Ib },
	{ "movb", BH, Ib },

	/* 0xb8 */
	{ "movS", eAX, Iv },
	{ "movS", eCX, Iv },
	{ "movS", eDX, Iv },
	{ "movS", eBX, Iv },
	{ "movS", eSP, Iv },
	{ "movS", eBP, Iv },
	{ "movS", eSI, Iv },
	{ "movS", eDI, Iv },

	/* 0xc0 */
	{ GRP2b },
	{ GRP2S },
	{ "ret", Iw },
	{ "ret", NONE },
	{ "lesS", Gv, Mp },
	{ "ldsS", Gv, Mp },
	{ "movb", Eb, Ib },
	{ "movS", Ev, Iv },

	/* 0xc8 */
	{ "enter", Iw, Ib },
	{ "leave", NONE },
	{ "lret", Iw },
	{ "lret", NONE },
	{ "int3", NONE },
	{ "int", Ib },
	{ "into", NONE },
	{ "iret", NONE },

	/* 0xd0 */
	{ GRP2b_one },
	{ GRP2S_one },
	{ GRP2b_cl },
	{ GRP2S_cl },
	{ "aam", Ib },
	{ "aad", Ib },
	{ "(bad)", BAD },
	{ "xlat", NONE },

	/* 0xd8 */
	{ FLOAT, NONE },
	{ FLOAT, NONE },
	{ FLOAT, NONE },
	{ FLOAT, NONE },
	{ FLOAT, NONE },
	{ FLOAT, NONE },
	{ FLOAT, NONE },
	{ FLOAT, NONE },

	/* 0xe0 */
	{ "loopne", Jb },
	{ "loope", Jb },
	{ "loop", Jb },
	{ "jCcxz", Jb },
	{ "inb", AL, Ib },
	{ "inS", eAX, Ib },
	{ "outb", Ib, AL },
	{ "outS", Ib, eAX },

	/* 0xe8 */
	{ "call", Av },
	{ "jmp", Jv },
	{ "ljmp", Ap },
	{ "jmp", Jb },
	{ "inb", AL, indirDX },
	{ "inS", eAX, indirDX },
	{ "outb", indirDX, AL },
	{ "outS", indirDX, eAX },

	/* 0xf0 */
	{ "(bad)", BAD },                  /* lock prefix */
	{ "(bad)", BAD },
	{ "(bad)", BAD },                  /* repne */
	{ "(bad)", BAD },                  /* repz */
	{ "hlt", NONE },
	{ "cmc", NONE },
	{ GRP3b },
	{ GRP3S },

	/* 0xf8 */
	{ "clc", NONE },
	{ "stc", NONE },
	{ "cli", NONE },
	{ "sti", NONE },
	{ "cld", NONE },
	{ "std", NONE },
	{ GRP4 },
	{ GRP5 },
};

static opcode_rec_t op_386_twobyte[] = {

	/* 0x00 */
	{ GRP6 },
	{ GRP7 },
	{ "larS", Gv, Ew },
	{ "lslS", Gv, Ew },  
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "clts", NONE },
	{ "(bad)", BAD },

	/* 0x08 */
	{ "invd", NONE },
	{ "wbinvd", NONE },
	{ "(bad)", BAD },
	{ "ud2a", NONE },  
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },

	/* 0x10 */
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },

	/* 0x18 */
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },

	/* 0x20 */
	/* these are all backward in appendix A of the intel book */
	{ "movl", Rd, Cd },
	{ "movl", Rd, Dd },
	{ "movl", Cd, Rd },
	{ "movl", Dd, Rd },  
	{ "movl", Rd, Td },
	{ "(bad)", BAD },
	{ "movl", Td, Rd },
	{ "(bad)", BAD },

	/* 0x28 */
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },

	/* 0x30 */
	{ "wrmsr", NONE },  
	{ "rdtsc", NONE },  
	{ "rdmsr", NONE },  
	{ "rdpmc", NONE },  
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },

	/* 0x38 */
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },

	/* 0x40 */
	{ "cmovo", Gv,Ev }, 
	{ "cmovno", Gv,Ev }, 
	{ "cmovb", Gv,Ev }, 
	{ "cmovae", Gv,Ev },
	{ "cmove", Gv,Ev }, 
	{ "cmovne", Gv,Ev }, 
	{ "cmovbe", Gv,Ev }, 
	{ "cmova", Gv,Ev },

	/* 0x48 */
	{ "cmovs", Gv,Ev }, 
	{ "cmovns", Gv,Ev }, 
	{ "cmovp", Gv,Ev }, 
	{ "cmovnp", Gv,Ev },
	{ "cmovl", Gv,Ev }, 
	{ "cmovge", Gv,Ev }, 
	{ "cmovle", Gv,Ev }, 
	{ "cmovg", Gv,Ev },  

	/* 0x50 */
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },

	/* 0x58 */
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },

	/* 0x60 */
	{ "punpcklbw", MX, EM },
	{ "punpcklwd", MX, EM },
	{ "punpckldq", MX, EM },
	{ "packsswb", MX, EM },
	{ "pcmpgtb", MX, EM },
	{ "pcmpgtw", MX, EM },
	{ "pcmpgtd", MX, EM },
	{ "packuswb", MX, EM },

	/* 0x68 */
	{ "punpckhbw", MX, EM },
	{ "punpckhwd", MX, EM },
	{ "punpckhdq", MX, EM },
	{ "packssdw", MX, EM },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "movd", MX, Ev },
	{ "movq", MX, EM },

	/* 0x70 */
	{ "(bad)", BAD },
	{ GRP10 },
	{ GRP11 },
	{ GRP12 },
	{ "pcmpeqb", MX, EM },
	{ "pcmpeqw", MX, EM },
	{ "pcmpeqd", MX, EM },
	{ "emms" , NONE },

	/* 0x78 */
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "movd", Ev, MX },
	{ "movq", EM, MX },

	/* 0x80 */
	{ "jo", Jv },
	{ "jno", Jv },
	{ "jb", Jv },
	{ "jae", Jv },  
	{ "je", Jv },
	{ "jne", Jv },
	{ "jbe", Jv },
	{ "ja", Jv },  

	/* 0x88 */
	{ "js", Jv },
	{ "jns", Jv },
	{ "jp", Jv },
	{ "jnp", Jv },  
	{ "jl", Jv },
	{ "jge", Jv },
	{ "jle", Jv },
	{ "jg", Jv },  

	/* 0x90 */
	{ "seto", Eb },
	{ "setno", Eb },
	{ "setb", Eb },
	{ "setae", Eb },
	{ "sete", Eb },
	{ "setne", Eb },
	{ "setbe", Eb },
	{ "seta", Eb },

	/* 0x98 */
	{ "sets", Eb },
	{ "setns", Eb },
	{ "setp", Eb },
	{ "setnp", Eb },
	{ "setl", Eb },
	{ "setge", Eb },
	{ "setle", Eb },
	{ "setg", Eb },  

	/* 0xa0 */
	{ "pushS", fs },
	{ "popS", fs },
	{ "cpuid", NONE },
	{ "btS", Ev, Gv },  
	{ "shldS", Ev, Gv, Ib },
	{ "shldS", Ev, Gv, CL },
	{ "(bad)", BAD },
	{ "(bad)", BAD },

	/* 0xa8 */
	{ "pushS", gs },
	{ "popS", gs },
	{ "rsm", NONE },
	{ "btsS", Ev, Gv },  
	{ "shrdS", Ev, Gv, Ib },
	{ "shrdS", Ev, Gv, CL },
	{ "(bad)", BAD },
	{ "imulS", Gv, Ev },  

	/* 0xb0 */
	{ "cmpxchgb", Eb, Gb },
	{ "cmpxchgS", Ev, Gv },
	{ "lssS", Gv, Mp },	/* 386 lists only Mp */
	{ "btrS", Ev, Gv },  
	{ "lfsS", Gv, Mp },	/* 386 lists only Mp */
	{ "lgsS", Gv, Mp },	/* 386 lists only Mp */
	{ "movzbS", Gv, Eb },
	{ "movzwS", Gv, Ew },  

	/* 0xb8 */
	{ "ud2b", NONE },
	{ "(bad)", BAD },
	{ GRP8 },
	{ "btcS", Ev, Gv },  
	{ "bsfS", Gv, Ev },
	{ "bsrS", Gv, Ev },
	{ "movsbS", Gv, Eb },
	{ "movswS", Gv, Ew },  

	/* 0xc0 */
	{ "xaddb", Eb, Gb },
	{ "xaddS", Ev, Gv },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ GRP9 },  

	/* 0xc8 */
	{ "bswap", eAX },
	{ "bswap", eCX },
	{ "bswap", eDX },
	{ "bswap", eBX },
	{ "bswap", eSP },
	{ "bswap", eBP },
	{ "bswap", eSI },
	{ "bswap", eDI },

	/* 0xd0 */
	{ "(bad)", BAD },
	{ "psrlw", MX, EM },
	{ "psrld", MX, EM },
	{ "psrlq", MX, EM },
	{ "(bad)", BAD },
	{ "pmullw", MX, EM },
	{ "(bad)", BAD },
	{ "(bad)", BAD },

	/* 0xd8 */
	{ "psubusb", MX, EM },
	{ "psubusw", MX, EM },
	{ "(bad)", BAD },
	{ "pand", MX, EM },
	{ "paddusb", MX, EM },
	{ "paddusw", MX, EM },
	{ "(bad)", BAD },
	{ "pandn", MX, EM },

	/* 0xe0 */
	{ "(bad)", BAD },
	{ "psraw", MX, EM },
	{ "psrad", MX, EM },
	{ "(bad)", BAD },
	{ "(bad)", BAD },
	{ "pmulhw", MX, EM },
	{ "(bad)", BAD },
	{ "(bad)", BAD },

	/* 0xe8 */
	{ "psubsb", MX, EM },
	{ "psubsw", MX, EM },
	{ "(bad)", BAD },
	{ "por", MX, EM },
	{ "paddsb", MX, EM },
	{ "paddsw", MX, EM },
	{ "(bad)", BAD },
	{ "pxor", MX, EM },

	/* 0xf0 */
	{ "(bad)", BAD },
	{ "psllw", MX, EM },
	{ "pslld", MX, EM },
	{ "psllq", MX, EM },
	{ "(bad)", BAD },
	{ "pmaddwd", MX, EM },
	{ "(bad)", BAD },
	{ "(bad)", BAD },

	/* 0xf8 */
	{ "psubb", MX, EM },
	{ "psubw", MX, EM },
	{ "psubd", MX, EM },
	{ "(bad)", BAD },
	{ "paddb", MX, EM },
	{ "paddw", MX, EM },
	{ "paddd", MX, EM },
	{ "(bad)", BAD },
};

static opcode_rec_t grps[][8] = {
	/* GRP1b */
	{
		{ "addb", Eb, Ib },
		{ "orb", Eb, Ib },
		{ "adcb", Eb, Ib },
		{ "sbbb", Eb, Ib },
		{ "andb", Eb, Ib },
		{ "subb", Eb, Ib },
		{ "xorb", Eb, Ib },
		{ "cmpb", Eb, Ib }
	},
	/* GRP1S */
	{
		{ "addS", Ev, Iv },
		{ "orS", Ev, Iv },
		{ "adcS", Ev, Iv },
		{ "sbbS", Ev, Iv },
		{ "andS", Ev, Iv },
		{ "subS", Ev, Iv },
		{ "xorS", Ev, Iv },
		{ "cmpS", Ev, Iv }
	},
	/* GRP1Ss */
	{
		{ "addS", Ev, sIb },
		{ "orS", Ev, sIb },
		{ "adcS", Ev, sIb },
		{ "sbbS", Ev, sIb },
		{ "andS", Ev, sIb },
		{ "subS", Ev, sIb },
		{ "xorS", Ev, sIb },
		{ "cmpS", Ev, sIb }
	},
	/* GRP2b */
	{
		{ "rolb", Eb, Ib },
		{ "rorb", Eb, Ib },
		{ "rclb", Eb, Ib },
		{ "rcrb", Eb, Ib },
		{ "shlb", Eb, Ib },
		{ "shrb", Eb, Ib },
		{ "(bad)", BAD },
		{ "sarb", Eb, Ib },
	},
	/* GRP2S */
	{
		{ "rolS", Ev, Ib },
		{ "rorS", Ev, Ib },
		{ "rclS", Ev, Ib },
		{ "rcrS", Ev, Ib },
		{ "shlS", Ev, Ib },
		{ "shrS", Ev, Ib },
		{ "(bad)", BAD },
		{ "sarS", Ev, Ib },
	},
	/* GRP2b_one */
	{
		{ "rolb", Eb },
		{ "rorb", Eb },
		{ "rclb", Eb },
		{ "rcrb", Eb },
		{ "shlb", Eb },
		{ "shrb", Eb },
		{ "(bad)", BAD },
		{ "sarb", Eb },
	},
	/* GRP2S_one */
	{
		{ "rolS", Ev },
		{ "rorS", Ev },
		{ "rclS", Ev },
		{ "rcrS", Ev },
		{ "shlS", Ev },
		{ "shrS", Ev },
		{ "(bad)", BAD },
		{ "sarS", Ev },
	},
	/* GRP2b_cl */
	{
		{ "rolb", Eb, CL },
		{ "rorb", Eb, CL },
		{ "rclb", Eb, CL },
		{ "rcrb", Eb, CL },
		{ "shlb", Eb, CL },
		{ "shrb", Eb, CL },
		{ "(bad)", BAD },
		{ "sarb", Eb, CL },
	},
	/* GRP2S_cl */
	{
		{ "rolS", Ev, CL },
		{ "rorS", Ev, CL },
		{ "rclS", Ev, CL },
		{ "rcrS", Ev, CL },
		{ "shlS", Ev, CL },
		{ "shrS", Ev, CL },
		{ "(bad)", BAD },
		{ "sarS", Ev, CL }
	},
	/* GRP3b */
	{
		{ "testb", Eb, Ib },
		{ "(bad)", Eb },
		{ "notb", Eb },
		{ "negb", Eb },
		{ "mulb", AL, Eb },
		{ "imulb", AL, Eb },
		{ "divb", AL, Eb },
		{ "idivb", AL, Eb }
	},
	/* GRP3S */
	{
		{ "testS", Ev, Iv },
		{ "(bad)", BAD },
		{ "notS", Ev },
		{ "negS", Ev },
		{ "mulS", eAX, Ev },
		{ "imulS", eAX, Ev },
		{ "divS", eAX, Ev },
		{ "idivS", eAX, Ev },
	},
	/* GRP4 */
	{
		{ "incb", Eb },
		{ "decb", Eb },
		{ "(bad)", BAD },
		{ "(bad)", BAD },
		{ "(bad)", BAD },
		{ "(bad)", BAD },
		{ "(bad)", BAD },
		{ "(bad)", BAD },
	},
	/* GRP5 */
	{
		{ "incS", Ev },
		{ "decS", Ev },
		{ "call", indirEv },
		{ "lcall", indirEv },
		{ "jmp", indirEv },
		{ "ljmp", indirEv },
		{ "pushS", Ev },
		{ "(bad)", BAD },
	},
	/* GRP6 */
	{
		{ "sldt", Ew },
		{ "str", Ew },
		{ "lldt", Ew },
		{ "ltr", Ew },
		{ "verr", Ew },
		{ "verw", Ew },
		{ "(bad)", BAD },
		{ "(bad)", BAD }
	},
	/* GRP7 */
	{
		{ "sgdt", Ew },
		{ "sidt", Ew },
		{ "lgdt", Ew },
		{ "lidt", Ew },
		{ "smsw", Ew },
		{ "(bad)", BAD },
		{ "lmsw", Ew },
		{ "invlpg", Ew },
	},
	/* GRP8 */
	{
		{ "(bad)", BAD },
		{ "(bad)", BAD },
		{ "(bad)", BAD },
		{ "(bad)", BAD },
		{ "btS", Ev, Ib },
		{ "btsS", Ev, Ib },
		{ "btrS", Ev, Ib },
		{ "btcS", Ev, Ib },
	},
	/* GRP9 */
	{
		{ "(bad)", BAD },
		{ "cmpxchg8b", Ev },
		{ "(bad)", BAD },
		{ "(bad)", BAD },
		{ "(bad)", BAD },
		{ "(bad)", BAD },
		{ "(bad)", BAD },
		{ "(bad)", BAD },
	},
	/* GRP10 */
	{
		{ "(bad)", BAD },
		{ "(bad)", BAD },
		{ "psrlw", MS, Ib },
		{ "(bad)", BAD },
		{ "psraw", MS, Ib },
		{ "(bad)", BAD },
		{ "psllw", MS, Ib },
		{ "(bad)", BAD },
	},
	/* GRP11 */
	{
		{ "(bad)", BAD },
		{ "(bad)", BAD },
		{ "psrld", MS, Ib },
		{ "(bad)", BAD },
		{ "psrad", MS, Ib },
		{ "(bad)", BAD },
		{ "pslld", MS, Ib },
		{ "(bad)", BAD },
	},
	/* GRP12 */
	{
		{ "(bad)", BAD },
		{ "(bad)", BAD },
		{ "psrlq", MS, Ib },
		{ "(bad)", BAD },
		{ "(bad)", BAD },
		{ "(bad)", BAD },
		{ "psllq", MS, Ib },
		{ "(bad)", BAD },
	}
};

static opcode_rec_t float_grps[][8] = {
	/* d8 */
	{
		{ "fadd",   ST, STi },
		{ "fmul",   ST, STi },
		{ "fcom",   STi },
		{ "fcomp",  STi },
		{ "fsub",   ST, STi },
		{ "fsubr",  ST, STi },
		{ "fdiv",   ST, STi },
		{ "fdivr",  ST, STi },
	},
	/* d9 */
	{
		{ "fld",    STi },
		{ "fxch",   STi },
		{ FGRPd9_2 },
		{ "(bad)" },
		{ FGRPd9_4 },
		{ FGRPd9_5 },
		{ FGRPd9_6 },
		{ FGRPd9_7 },
	},
	/* da */
	{
		{ "fcmovb", ST, STi },
		{ "fcmove", ST, STi },
		{ "fcmovbe",ST, STi },
		{ "fcmovu", ST, STi },
		{ "(bad)" },
		{ FGRPda_5 },
		{ "(bad)" },
		{ "(bad)" },
		},
	/* db */
	{
		{ "fcmovnb",ST, STi },
		{ "fcmovne",ST, STi },
		{ "fcmovnbe",ST, STi },
		{ "fcmovnu",ST, STi },
		{ FGRPdb_4 },
		{ "fucomi", ST, STi },
		{ "fcomi",  ST, STi },
		{ "(bad)" },
	},
	/* dc */
	{
		{ "fadd",   STi, ST },
		{ "fmul",   STi, ST },
		{ "(bad)" },
		{ "(bad)" },
		{ "fsub",   STi, ST },
		{ "fsubr",  STi, ST },
		{ "fdiv",   STi, ST },
		{ "fdivr",  STi, ST },
	},
	/* dd */
	{
		{ "ffree",  STi },
		{ "(bad)" },
		{ "fst",    STi },
		{ "fstp",   STi },
		{ "fucom",  STi },
		{ "fucomp", STi },
		{ "(bad)" },
		{ "(bad)" },
	},
	/* de */
	{
		{ "faddp",  STi, ST },
		{ "fmulp",  STi, ST },
		{ "(bad)" },
		{ FGRPde_3 },
		{ "fsubp",  STi, ST },
		{ "fsubrp", STi, ST },
		{ "fdivp",  STi, ST },
		{ "fdivrp", STi, ST },
	},
	/* df */
	{
		{ "(bad)" },
		{ "(bad)" },
		{ "(bad)" },
		{ "(bad)" },
		{ FGRPdf_4 },
		{ "fucomip",ST, STi },
		{ "fcomip", ST, STi },
		{ "(bad)" },
	},
};

static char *fgrps[][8] = {
	/* d9_2  0 */
	{
	"fnop","(bad)","(bad)","(bad)","(bad)","(bad)","(bad)","(bad)",
	},
	/* d9_4  1 */
	{
	"fchs","fabs","(bad)","(bad)","ftst","fxam","(bad)","(bad)",
	},
	/* d9_5  2 */
	{
	"fld1","fldl2t","fldl2e","fldpi","fldlg2","fldln2","fldz","(bad)",
	},
	/* d9_6  3 */
	{
	"f2xm1","fyl2x","fptan","fpatan","fxtract","fprem1","fdecstp","fincstp",
	},
	/* d9_7  4 */
	{
	"fprem","fyl2xp1","fsqrt","fsincos","frndint","fscale","fsin","fcos",
	},
	/* da_5  5 */
	{
	"(bad)","fucompp","(bad)","(bad)","(bad)","(bad)","(bad)","(bad)",
	},
	/* db_4  6 */
	{
	"feni(287 only)","fdisi(287 only)","fNclex","fNinit",
	"fNsetpm(287 only)","(bad)","(bad)","(bad)",
	},
	/* de_3  7 */
	{
	"(bad)","fcompp","(bad)","(bad)","(bad)","(bad)","(bad)","(bad)",
	},
	/* df_4  8 */
	{
	"fNstsw","(bad)","(bad)","(bad)","(bad)","(bad)","(bad)","(bad)",
	},
};

static char *float_mem[] = {
	/* 0xd8 */
	"fadds","fmuls","fcoms","fcomps","fsubs","fsubrs","fdivs","fdivrs",
	/* 0xd9 */
	"flds","(bad)","fsts","fstps","fldenv","fldcw","fNstenv","fNstcw",
	/* 0xda */
	"fiaddl","fimull","ficoml","ficompl","fisubl","fisubrl","fidivl",
	"fidivrl",
	/* 0xdb */
	"fildl","(bad)","fistl","fistpl","(bad)","fldt","(bad)","fstpt",
	/* 0xdc */
	"faddl","fmull","fcoml","fcompl","fsubl","fsubrl","fdivl","fdivrl",
	/* 0xdd */
	"fldl","(bad)","fstl","fstpl","frstor","(bad)","fNsave","fNstsw",
	/* 0xde */
	"fiadd","fimul","ficom","ficomp","fisub","fisubr","fidiv","fidivr",
	/* 0xdf */
	"fild","(bad)","fist","fistp","fbld","fildll","fbstp","fistpll",
};

static const unsigned char onebyte_has_modrm[256] = {
	/* 00 */ 1,1,1,1,0,0,0,0,1,1,1,1,0,0,0,0,
	/* 10 */ 1,1,1,1,0,0,0,0,1,1,1,1,0,0,0,0,
	/* 20 */ 1,1,1,1,0,0,0,0,1,1,1,1,0,0,0,0,
	/* 30 */ 1,1,1,1,0,0,0,0,1,1,1,1,0,0,0,0,
	/* 40 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	/* 50 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	/* 60 */ 0,0,1,1,0,0,0,0,0,1,0,1,0,0,0,0,
	/* 70 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	/* 80 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	/* 90 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	/* a0 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	/* b0 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	/* c0 */ 1,1,0,0,1,1,1,1,0,0,0,0,0,0,0,0,
	/* d0 */ 1,1,1,1,0,0,0,0,1,1,1,1,1,1,1,1,
	/* e0 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	/* f0 */ 0,0,0,0,0,0,1,1,0,0,0,0,0,0,1,1
};

static const unsigned char twobyte_has_modrm[256] = {
	/* 00 */ 1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0, /* 0f */
	/* 10 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 1f */
	/* 20 */ 1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0, /* 2f */
	/* 30 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 3f */
	/* 40 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 4f */
	/* 50 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 5f */
	/* 60 */ 1,1,1,1,1,1,1,1,1,1,1,1,0,0,1,1, /* 6f */
	/* 70 */ 0,1,1,1,1,1,1,0,0,0,0,0,0,0,1,1, /* 7f */
	/* 80 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 8f */
	/* 90 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 9f */
	/* a0 */ 0,0,0,1,1,1,1,1,0,0,0,1,1,1,1,1, /* af */
	/* b0 */ 1,1,1,1,1,1,1,1,0,0,1,1,1,1,1,1, /* bf */
	/* c0 */ 1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0, /* cf */
	/* d0 */ 0,1,1,1,0,1,0,0,1,1,0,1,1,1,0,1, /* df */
	/* e0 */ 0,1,1,0,0,1,0,0,1,1,0,1,1,1,0,1, /* ef */
	/* f0 */ 0,1,1,1,0,1,0,0,1,1,1,0,1,1,1,0  /* ff */
};

#ifdef NOT_USED
static int reg_num[] = {
	0, 1, 2, 3, 4, 5, 6, 7,
	0, 1, 2, 3, 4, 5, 6, 7,
	0, 1, 2, 3, 4, 5, 6, 7,
};
#endif

#ifndef REDHAT
static char *reg_name[] = {
	"%eax","%ecx","%edx","%ebx","%esp","%ebp","%esi","%edi",
	"%ax","%cx","%dx","%bx","%sp","%bp","%si","%di",
	"%al","%cl","%dl","%bl","%ah","%ch","%dh","%bh",
	"%es","%cs","%ss","%ds","%fs","%gs",
	"bx+si","bx+di","bp+si","bp+di",
};
#endif  /* !REDHAT */
static int reg_32[] = {
	R_eAX, R_eCX, R_eDX, R_eBX, R_eSP, R_eBP, R_eSI, R_eDI,
};
static int reg_16[] = {
	R_AX, R_CX, R_DX, R_BX, R_SP, R_BP, R_SI, R_DI,
};
static int reg_8[] = {
	R_AL, R_CL, R_DL, R_BL, R_AH, R_CH, R_DH, R_BH,
};
static int reg_seg[] = {
	R_ES, R_CS, R_SS, R_DS, R_FS, R_GS, R_BAD, R_BAD,
};
static int reg_index[] = {
	R_BX_SI, R_BX_DI, R_BP_SI, R_BP_DI, R_SI, R_DI, R_BP, R_BX,
};

#ifndef REDHAT
static char *optype_name[] = {
	"NONE","A","C","D","E","M_indirE","F","G","I","sI","J","M",
	"O","P","Q","R","S","T","V","W","X","Y","MMX","EM","MS","GRP",
	"REG",
};
static char *opmods[] = {
	"NONE","a","b","c","d","dg","p","pi",
	"ps","q","s","ss","si","v","w",
};

static char *reg_opname[] = {
	"eAX","eCX","eDX","eBX","eSP","eBP","eSI","eDI",
	"AX","CX","DX","BX","SP","BP","SI","DI",
	"AL","CL","DL","BL","AH","CH","DH","BH",
	"ES","CS","SS","DS","FS","GS",
};

static void
printaddr(kaddr_t addr, int flag, FILE *ofp)
{
	int offset = 0;
	syment_t *sp;

	if ((sp = kl_lkup_symaddr(addr))) {
		offset = addr - sp->s_addr;
	}

	/* Print out address
	 */
	fprintf(ofp, "0x%x", addr);

	/* Print out symbol name
	 */
	if (sp) {
		if (offset) {
			fprintf(ofp, " <%s+%d>",
				sp->s_name, offset);
		} else {
			fprintf(ofp, " <%s>", sp->s_name);
		}
	}

	/* Line things up properly for current function
	 */
	if (flag) {
		if (offset == 0) {
			fprintf(ofp, ":       ");
		} else if (offset < 10) {
			fprintf(ofp, ":     ");
		} else if (offset < 100) {
			fprintf(ofp, ":    ");
		} else if (offset < 1000) {
			fprintf(ofp, ":   ");
		} else if (offset < 10000) {
			fprintf(ofp, ":  ");
		} else {
			fprintf(ofp, ": ");
		}
	}
}

static void
print_optype(int m, int t, FILE *ofp)
{
	if (m >= M_BAD) {
		fprintf(ofp, "BAD");
	} else if (m == M_REG) {
		if (t >= R_BAD) {
			fprintf(ofp, "REG_BAD");
		} else {
			fprintf(ofp, "%s", reg_opname[t]);
		}
	} else {
		if (t == T_NONE) {
			fprintf(ofp, "%s", optype_name[m]);
		} else if (t >= T_BAD) {
			fprintf(ofp, "%s(bad)", optype_name[m]);
		} else {
			fprintf(ofp, "%s%s", optype_name[m], opmods[t]);
		}
	}
}
#endif  /* !REDHAT */

static void
get_modrm_info(unsigned char modr, int *mod_rm, int *reg_op)
{
	*mod_rm = ((modr >> 6) << 3) | (modr & 7);
	*reg_op = (modr >> 3) & 7; 
}

static int
is_prefix(unsigned char c)
{
	int prefix = 0;

	switch(c) {
		case 0xf3:
			prefix = PREFIX_REPZ;
			break;
		case 0xf2:
			prefix = PREFIX_REPNZ;
			break;
		case 0xf0:
			prefix = PREFIX_LOCK;
			break;
		case 0x2e:
			prefix = PREFIX_CS;
			break;
		case 0x36:
			prefix = PREFIX_SS;
			break;
		case 0x3e:
			prefix = PREFIX_DS;
			break;
		case 0x26:
			prefix = PREFIX_ES;
			break;
		case 0x64:
			prefix = PREFIX_FS;
			break;
		case 0x65:
			prefix = PREFIX_GS;
			break;
		case 0x66:
			prefix = PREFIX_DATA;
			break;
		case 0x67:
			prefix = PREFIX_ADR;
			break;
		case 0x9b:
			prefix = PREFIX_FWAIT;
			break;
	}
	return(prefix);
}

static int
get_modrm_reg16(int mod_rm, int opdata, instr_rec_t *irp)
{
	int reg, mod;

	mod = irp->modrm >> 6;
	switch (mod_rm) {
		case 0x6:
			break;

		default:
			reg = mod_rm - (mod * 8);
			return(reg_index[reg]);
	}
	return(R_BAD);
}

static int
get_modrm_reg32(int mod_rm, int opdata, instr_rec_t *irp)
{
	int reg;

	switch (mod_rm) {
		case 0x0:
		case 0x1:
		case 0x2:
		case 0x3:
		case 0x6:
		case 0x7:
			return(mod_rm);
		case 0x18:
		case 0x19:
		case 0x1a:
		case 0x1b:
		case 0x1c:
		case 0x1d:
		case 0x1e:
		case 0x1f:
			reg = mod_rm - 0x18;
			switch (opdata) {
				case T_b:
					return(reg_8[reg]);
				case T_w:
					return(reg_16[reg]);
				case T_v:
					if (irp->dflag) {
						return(reg_32[reg]);
					} else {
						return(reg_16[reg]);
					}
			}
	}
	return(R_BAD);
}

#ifndef REDHAT
static void
print_instrname(char *name, instr_rec_t *irp, FILE *ofp)
{
	char *cp, *np, name_str[100];

	strncpy (name_str, name, 100);
	np = name;
	cp = name_str;
	while (*np) {
		if (*np == 'C') {		/* For jcxz/jecxz */
			if (irp->aflag) {
				*cp++ = 'e';
			}
		} else if (*np == 'N') {
			if ((irp->prefixes & PREFIX_FWAIT) == 0) {
				*cp++ = 'n';
			}
		} else if (*np == 'S') {
			/* operand size flag 
			 */
			if (irp->dflag) {
				*cp++ = 'l';
			} else {
				*cp++ = 'w';
			}
		} else if (*np == 'W') {
			/* operand size flag for cwtl, cbtw 
			 */
			if (irp->dflag) {
				*cp++ = 'w';
			} else {
				*cp++ = 'b';
			}
		} else {
			*cp++ = *np;
		}
		np++;
	}
	while(*cp) {
		*cp++ = ' ';
	}
	*cp = 0;
	fprintf(ofp, "%s", name_str);
}
#endif  /* !REDHAT */

static void
op_a(int opnum, int opdata, instr_rec_t *irp)
{
	int offset;
	kaddr_t pc;

	pc = instrbuf.addr + (instrbuf.ptr - instrbuf.buf);
	switch(opdata) {
		case T_p:
			if (irp->aflag) {
				irp->operand[opnum].op_addr = 
					*(uint32_t*)codeptr;
				codeptr += 4; 
			} else {
				irp->operand[opnum].op_addr = 
					*(uint16_t*)codeptr;
				codeptr += 2;
			}
			irp->operand[opnum].op_seg = *(uint16_t*)codeptr;
			irp->operand[opnum].op_type = O_LPTR;
			codeptr += 2;
			break;
		case T_v:
			if (irp->aflag) {
				offset = *(int*)codeptr;
				irp->operand[opnum].op_addr = pc + offset + 5;
				codeptr += 4;
			} else {
				offset = *(short*)codeptr;
				irp->operand[opnum].op_addr = pc + offset + 3;
				codeptr += 2;
			}
			irp->operand[opnum].op_type = O_ADDR;
			break;
		default:
			break;
	}
}

static void
op_c(int opnum, int opdata, instr_rec_t *irp)
{
	int reg;

	reg = (irp->modrm  >> 3) & 7;
	irp->operand[opnum].op_type = (O_REG|O_CR);
	irp->operand[opnum].op_reg = reg;

}

static void
op_d(int opnum, int opdata, instr_rec_t *irp)
{
	int reg;

	reg = (irp->modrm  >> 3) & 7;
	irp->operand[opnum].op_type = (O_REG|O_DB);
	irp->operand[opnum].op_reg = reg;

}

static void
op_indir_e(int opnum, int opdata, instr_rec_t *irp)
{
	op_e(opnum, opdata, irp);
	irp->operand[opnum].op_type |= O_INDIR;
}

static void
get_modrm_data16(int opnum, int opdata, instr_rec_t *irp)
{
	int mod ATTRIBUTE_UNUSED;
	int reg, mod_rm, reg_op;

	get_modrm_info(irp->modrm, &mod_rm, &reg_op);
	mod = irp->modrm >> 6;
	switch(mod_rm) {
		case 0:
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
		case 7:
			reg = get_modrm_reg16(mod_rm, opdata, irp);
			irp->operand[opnum].op_reg = reg;
			irp->operand[opnum].op_type = (O_REG|O_BASE);
			break;

		case 6:
			/* 16-bit displacement */
			irp->operand[opnum].op_type = O_DISP;
			irp->operand[opnum].op_disp = *(uint16_t*)codeptr;
			codeptr += 2;
			break;
		case 8:
			/* disp8[BX+SI] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_BX_SI;
			irp->operand[opnum].op_disp = *(signed char*)codeptr;
			codeptr++;
			break;
		case 9:
			/* disp8[BX+DI] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_BX_DI;
			irp->operand[opnum].op_disp = *(signed char*)codeptr;
			codeptr++;
			break;
		case 10:
			/* disp8[BP+SI] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_BP_SI;
			irp->operand[opnum].op_disp = *(signed char*)codeptr;
			codeptr++;
			break;

		case 11:
			/* disp8[BP+DI] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_BP_DI;
			irp->operand[opnum].op_disp = *(signed char*)codeptr;
			codeptr++;
			break;

		case 12:
			/* disp8[SI] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_SI;
			irp->operand[opnum].op_disp = *(signed char*)codeptr;
			codeptr++;
			break;

		case 13:
			/* disp8[DI] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_DI;
			irp->operand[opnum].op_disp = *(signed char*)codeptr;
			codeptr++;
			break;

		case 14:
			/* disp8[BP] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_BP;
			irp->operand[opnum].op_disp = *(signed char*)codeptr;
			codeptr++;
			break;

		case 15:
			/* disp8[BX] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_BX;
			irp->operand[opnum].op_disp = *(signed char*)codeptr;
			codeptr++;
			break;

		case 16:
			/* disp16[BX+SI] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_BX_SI;
			irp->operand[opnum].op_disp = *(short*)codeptr;
			codeptr += 2;
			break;

		case 17:
			/* disp16[BX+DI] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_BX_DI;
			irp->operand[opnum].op_disp = *(short*)codeptr;
			codeptr += 2;
			break;

		case 18:
			/* disp16[BP+SI] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_BP_SI;
			irp->operand[opnum].op_disp = *(short*)codeptr;
			codeptr += 2;
			break;

		case 19:
			/* disp16[BP+DI] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_BP_DI;
			irp->operand[opnum].op_disp = *(short*)codeptr;
			codeptr += 2;
			break;

		case 20:
			/* disp16[SI] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_SI;
			irp->operand[opnum].op_disp = *(short*)codeptr;
			codeptr += 2;
			break;

		case 21:
			/* disp16[DI] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_DI;
			irp->operand[opnum].op_disp = *(short*)codeptr;
			codeptr += 2;
			break;

		case 22:
			/* disp16[BP] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_BP;
			irp->operand[opnum].op_disp = *(short*)codeptr;
			codeptr += 2;
			break;

		case 23:
			/* disp16[BX] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_BX;
			irp->operand[opnum].op_disp = *(short*)codeptr;
			codeptr += 2;
			break;
	}
}

static void
get_modrm_data32(int opnum, int opdata, instr_rec_t *irp)
{
	int mod ATTRIBUTE_UNUSED;
	int reg, mod_rm, reg_op;

	get_modrm_info(irp->modrm, &mod_rm, &reg_op);
	mod = irp->modrm >> 6;
	switch(mod_rm) {
		case 0:
		case 1:
		case 2:
		case 3:
		case 6:
		case 7:
			reg = get_modrm_reg32(mod_rm, opdata, irp);
			irp->operand[opnum].op_reg = reg;
			irp->operand[opnum].op_type = (O_REG|O_BASE);
			break;

		case 5:
			/* 32-bit displacement */
			irp->operand[opnum].op_type = O_DISP;
			irp->operand[opnum].op_disp = *(kaddr_t*)codeptr;
			codeptr += 4;
			break;
		case 8:
			/* disp8[EAX] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_eAX;
			irp->operand[opnum].op_disp = *(signed char*)codeptr;
			codeptr++;
			break;
		case 9:
			/* disp8[ECX] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_eCX;
			irp->operand[opnum].op_disp = *(signed char*)codeptr;
			codeptr++;
			break;
		case 10:
			/* disp8[EDX] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_eDX;
			irp->operand[opnum].op_disp = *(signed char*)codeptr;
			codeptr++;
			break;

		case 11:
			/* disp8[EBX] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_eBX;
			irp->operand[opnum].op_disp = *(signed char*)codeptr;
			codeptr++;
			break;

		case 13:
			/* disp8[EBP] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_eBP;
			irp->operand[opnum].op_disp = *(signed char*)codeptr;
			codeptr++;
			break;

		case 14:
			/* disp8[ESI] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_eSI;
			irp->operand[opnum].op_disp = *(signed char*)codeptr;
			codeptr++;
			break;
		case 15:
			/* disp8[EDI] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_eDI;
			irp->operand[opnum].op_disp = *(signed char*)codeptr;
			codeptr++;
			break;

		case 16:
			/* disp32[EAX] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_eAX;
			irp->operand[opnum].op_disp = *(int*)codeptr;
			codeptr += 4;
			break;

		case 17:
			/* disp32[ECX] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_eCX;
			irp->operand[opnum].op_disp = *(int*)codeptr;
			codeptr += 4;
			break;

		case 18:
			/* disp32[EDX] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_eDX;
			irp->operand[opnum].op_disp = *(int*)codeptr;
			codeptr += 4;
			break;

		case 19:
			/* disp32[EBX] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_eBX;
			irp->operand[opnum].op_disp = *(int*)codeptr;
			codeptr += 4;
			break;

		case  4: /* [..][..] (SIB) */
		case 12: /* disp8[..][..] (SIB) */
		case 20: { /* disp32[..][..] (SIB) */
			int rm ATTRIBUTE_UNUSED;
			int s, i, b, mod, havebase;

			s = (irp->sib >> 6) & 3;
			i = (irp->sib >> 3) & 7;
			b = irp->sib & 7;
			mod = irp->modrm >> 6;
			rm = irp->modrm & 7;
			havebase = 1;
			switch (mod) {
				case 0:
					if (b == 5) {
						havebase = 0;
						irp->operand[opnum].op_disp =
							*(int*)codeptr;
						irp->operand[opnum].op_type = 
							O_DISP;
						codeptr += 4;
					}
					break;
				case 1:
					irp->operand[opnum].op_disp = 
						*(signed char*) codeptr; 
					codeptr++;
					irp->operand[opnum].op_type = O_DISP;
					break;
				case 2:
					irp->operand[opnum].op_disp =
						*(int*)codeptr;
					codeptr += 4;
					irp->operand[opnum].op_type = O_DISP;
					break;
			}
			if (havebase) {
				irp->operand[opnum].op_base = b;
				irp->operand[opnum].op_type |= O_BASE;
			}
			if (i != 4) {
				irp->operand[opnum].op_index = i;
				irp->operand[opnum].op_type |= O_INDEX;
			}
			if (s) {
				irp->operand[opnum].op_scale = s;
				irp->operand[opnum].op_type |= O_SCALE;
			}
			break;
		}
		case 21:
			/* disp32[EBP] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_eBP;
			irp->operand[opnum].op_disp = *(int*)codeptr;
			codeptr += 4;
			break;
		case 22:
			/* disp32[ESI] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_eSI;
			irp->operand[opnum].op_disp = *(int*)codeptr;
			codeptr += 4;
			break;
		case 23:
			/* disp32[EDI] */
			irp->operand[opnum].op_type = (O_REG|O_DISP);
			irp->operand[opnum].op_reg = R_eDI;
			irp->operand[opnum].op_disp = *(int*)codeptr;
			codeptr += 4;
			break;
	}
}

static int
op_e(int opnum, int opdata, instr_rec_t *irp)
{
	int reg, mod, mod_rm, reg_op;

	get_modrm_info(irp->modrm, &mod_rm, &reg_op);
	mod = irp->modrm >> 6;

	if (mod == 3) {
		/* ((mod_rm >= 24) && (mod_rm <=31)) */
		if (opdata == T_NONE) {
			return(1);
		}
		if (irp->aflag) {
			reg = get_modrm_reg32(mod_rm, opdata, irp); 
		} else {
			reg = get_modrm_reg16(mod_rm, opdata, irp); 
		}
		irp->operand[opnum].op_type = O_REG;
		irp->operand[opnum].op_reg = reg;
		if ((reg = R_BAD)) {
			return(1);
		} else {
			return(0);
		}
	}
	if (irp->aflag) {
		get_modrm_data32(opnum, opdata, irp);
	} else {
		get_modrm_data16(opnum, opdata, irp);
	}
	if (seg_prefix(irp->prefixes)) {
		irp->operand[opnum].op_type |= O_SEG;
		irp->operand[opnum].op_seg = seg_prefix(irp->prefixes);
	}
	return(0);
}

static int
op_g(int opnum, int opdata, instr_rec_t *irp)
{
	int reg, mod_rm, reg_op;

	get_modrm_info(irp->modrm, &mod_rm, &reg_op);
	irp->operand[opnum].op_type = O_REG;
	if ((reg_op < 0) || (reg_op >= 8)){
		irp->operand[opnum].op_reg = R_BAD;
		return(1);
	}
	switch(opdata) {
		case T_b:
			reg = reg_8[reg_op];
			break;
		case T_w:
			reg = reg_16[reg_op];
			break;
		case T_d:
			reg = reg_32[reg_op];
			break;
		case T_v:
			if (irp->dflag) {
				reg = reg_32[reg_op];
			} else {
				reg = reg_16[reg_op];
			}
			break;
		default:	
			irp->operand[opnum].op_reg = R_BAD;
			return(1);
	}
	irp->operand[opnum].op_reg = reg;
	return(0);
}

static void
op_i(int opnum, int opdata, instr_rec_t *irp)
{
	irp->operand[opnum].op_type = O_IMMEDIATE;
	switch (opdata) {
		case T_b:
			irp->operand[opnum].op_addr = *(unsigned char*)codeptr;
			codeptr++;
			break;
		case T_w:
			irp->operand[opnum].op_addr = *(uint16_t*)codeptr;
			codeptr += 2;
			break;
		case T_v:
			if (irp->dflag) {
				irp->operand[opnum].op_addr = 
					*(uint32_t*)codeptr;
				codeptr += 4;
			} else {
				irp->operand[opnum].op_addr = 
					*(uint16_t*)codeptr;
				codeptr += 2;
			}
			break;
	}
}

static void
op_s(int opnum, int opdata, instr_rec_t *irp)
{
	int reg;

	reg = (irp->modrm >> 3) & 7;
	irp->operand[opnum].op_reg = reg_seg[reg];
	irp->operand[opnum].op_type = O_REG;
}

static void
op_si(int opnum, int opdata, instr_rec_t *irp)
{
	int val;

	irp->operand[opnum].op_type = O_IMMEDIATE;
	switch (opdata) {
		case T_b:
			val = *(signed char*)codeptr++;
			irp->operand[opnum].op_addr = val;
			break;
		case T_v:
			if (irp->dflag) {
				irp->operand[opnum].op_addr = *(int*)codeptr;
				codeptr += 4;
			} else {
				val = *(short*)codeptr;
				irp->operand[opnum].op_addr = val;
				codeptr += 2;
			}
			break;
		case T_w:
			val = *(short*)codeptr;
			irp->operand[opnum].op_addr = val;
			codeptr += 2;
			break;
	}
}

static void
op_j(int opnum, int opdata, instr_rec_t *irp)
{
	kaddr_t pc;

	pc = instrbuf.addr + (instrbuf.ptr - instrbuf.buf);
	pc += (codeptr - instrbuf.ptr);
	switch (opdata) {
		case T_b:
			pc++; 
			pc += *(signed char *)codeptr++;
			break;
		case T_v:
			if (irp->dflag) {
				/* 32-bit */
				pc += 4;
				pc += *(int*)codeptr;
				codeptr += 4;
			} else {
				/* 16-bit */
				pc += 2;
				pc += *(short*)codeptr;
				codeptr += 2;
			}
			break;
	}
	irp->operand[opnum].op_type = O_ADDR;
	irp->operand[opnum].op_addr = pc;
}

static void
op_m(int opnum, int opdata, instr_rec_t *irp)
{
	op_e(opnum, 0, irp); 
}

static void
op_o(int opnum, int opdata, instr_rec_t *irp)
{
	if (irp->aflag) {
		irp->operand[opnum].op_addr = *(uint32_t*)codeptr;
		codeptr += 4;
	} else {
		irp->operand[opnum].op_addr = *(uint16_t*)codeptr;
		codeptr += 2;
	}
	irp->operand[opnum].op_type = O_OFF;
}

static void
op_r(int opnum, int opdata, instr_rec_t *irp)
{
	int rm;
	rm = irp->modrm & 7;
	switch (opdata) {
		case T_d:
			irp->operand[opnum].op_reg = reg_32[rm];
			break;
		case T_w:
			irp->operand[opnum].op_reg = reg_16[rm];
			break;
	}
	irp->operand[opnum].op_type = O_REG;
}

static void
op_x(int opnum, int opdata, instr_rec_t *irp)
{
	irp->operand[opnum].op_seg = R_DS;
	if (irp->aflag) {
		irp->operand[opnum].op_reg = R_eSI;
	} else {
		irp->operand[opnum].op_reg = R_SI;
	}
	irp->operand[opnum].op_type = O_SEG;
}

static void
op_y(int opnum, int opdata, instr_rec_t *irp)
{
	irp->operand[opnum].op_seg = R_ES;
	if (irp->aflag) {
		irp->operand[opnum].op_reg = R_eDI;
	} else {
		irp->operand[opnum].op_reg = R_DI;
	}
	irp->operand[opnum].op_type = O_SEG;
}

static void
get_operand_info(int opnum, instr_rec_t *irp)
{
	int opcode, opdata;

	opcode = opdata = 0;

	switch(opnum) {
		case 0:
			opcode = irp->opcodep->Op1;
			opdata = irp->opcodep->opdata1;
			break;
		case 1:
			opcode = irp->opcodep->Op2;
			opdata = irp->opcodep->opdata2;
			break;
		case 2:
			opcode = irp->opcodep->Op3;
			opdata = irp->opcodep->opdata3;
			break;
	}
	switch (opcode) {
		case M_A:
			op_a(opnum, opdata, irp);
			break;

		case M_C:
			op_c(opnum, opdata, irp);
			break;

		case M_D:
			op_d(opnum, opdata, irp);
			break;

		case M_E:
			op_e(opnum, opdata, irp);
			break;

		case M_indirE:
			op_indir_e(opnum, opdata, irp);
			break;

		case M_G:
			op_g(opnum, opdata, irp);
			break;

		case M_I:
			op_i(opnum, opdata, irp);
			break;

		case M_sI:
			op_si(opnum, opdata, irp);
			break;

		case M_J: 
			op_j(opnum, opdata, irp);
			break;

		case M_M: 
			op_m(opnum, opdata, irp);
			break;

		case M_O:
			op_o(opnum, opdata, irp);
			break;

		case M_R:
			op_r(opnum, opdata, irp);
			break;

		case M_S:
			op_s(opnum, opdata, irp);
			break;

		case M_X:
			op_x(opnum, opdata, irp);
			break;

		case M_Y:
			op_y(opnum, opdata, irp);
			break;

		case M_REG:
		case M_indirREG:
			irp->operand[opnum].op_type = O_REG;
			if (opdata >= R_AX) {
				irp->operand[opnum].op_reg = opdata;
			} else {
				if (irp->dflag) {
					irp->operand[opnum].op_reg = 
						reg_32[opdata];
				} else {
					irp->operand[opnum].op_reg = 
						reg_16[opdata];
				}
			}
			if (opcode == M_indirREG) {
				/* The O_BASE gets the right results */
				irp->operand[opnum].op_type |= O_BASE;
			}
			break;
	}
}

/* Temporary opcode_rec_s struct that we keep around for the times
 * when we have to construct a special case instruction (e.g. some
 * floating point instructions).
 */
static opcode_rec_t tempop;
static char fwait_name[] = "fwait";

int
get_instr_info(kaddr_t pc, instr_rec_t *irp)
{
	int opcode, size = 0, p, prefixes = 0;
	unsigned char modrm = 0;
	opcode_rec_t *op;

	if (instr_buf_init) {
		bzero(&instrbuf, sizeof(instrbuf));
		instr_buf_init = 0;
	}

	/* Check to see instrbuf is valid and if there are enough 
	 * bytes in our instruction cache to cover the worst case 
	 * scenario for this pc.
	 */
	if (!instrbuf.addr || (pc < instrbuf.addr) || 
			(pc > (instrbuf.addr + instrbuf.size - 15))) { 
		instrbuf.addr = pc;
		instrbuf.size = 256;
#ifdef REDHAT
		fill_instr_cache(pc, (char *)instrbuf.buf);
#else
		GET_BLOCK(pc, 256, instrbuf.buf);
#endif
		if (KL_ERROR) {
			return(0);
		}
	} 

	/* Make sure that the instruction pointer points to the 
	 * right byte in the buffer.
	 */
	instrbuf.ptr = instrbuf.buf + (pc - instrbuf.addr);
	codeptr = instrbuf.ptr;
	irp->addr = pc;

	/* Check for prefixes 
	 */
	while((p = is_prefix(*codeptr))) {
		prefixes |= p;
		codeptr++;
		if ((prefixes & PREFIX_FWAIT) && 
			((*codeptr < 0xd8) || (*codeptr > 0xdf))) {

			/* If there is an fwait prefix that is not
			 * followed by a float instruction, we need to
			 * create a special instruction record so that
			 * the "fwait" gets printed out.
			 */
			bzero(&tempop, sizeof(tempop));
			tempop.name = fwait_name;
			irp->opcodep = &tempop;
			size = ((unsigned)codeptr - (unsigned)instrbuf.ptr);
			instrbuf.ptr = codeptr;
			irp->size = size;
			return(size);
		}
	}
	if (prefixes & PREFIX_DATA) {
		irp->dflag ^= 1;
	}
	if (prefixes & PREFIX_ADR) {
		irp->aflag ^= 1;
	}

	/* Check for one or two byte opcode, capture the opcode and
	 * check for a ModR/M byte.
	 */
	if (*codeptr == 0x0f) {
		opcode = *((unsigned short*)codeptr);
		codeptr++;
		op = &op_386_twobyte[*codeptr];
		if(twobyte_has_modrm[*codeptr]) {
			codeptr++;
			modrm = *codeptr++;
		} else {
			codeptr++;
		}
		if (STREQ(op->name, "ud2a")) 
			codeptr += kt->BUG_bytes;
	} else {
		opcode = *codeptr;
		op = &op_386[*codeptr];
		if(onebyte_has_modrm[*codeptr]) {
			codeptr++;
			modrm = *codeptr++;
		} else {
			codeptr++;
		}
	}
	/* See if the get_op bits from the modrm are needed to determine
	 * the actual instruction.
	 */
	if (op->Op1 == M_GRP) {
		op = &grps[op->opdata1][(modrm & 0x38) >> 3];

		/* Put something unique in opcode
		 */
		opcode = ((opcode << 8)|((modrm & 0x38) >> 3));
	} else if (op->Op1 == M_FLOAT) {
		int mod, rm, reg;

		mod = modrm >> 6;
		rm = modrm & 7;
		reg = (modrm >> 3) & 7; 
		bzero(&tempop, sizeof(tempop));
		if (mod != 3) {
			tempop.name = float_mem[(opcode - 0xd8) * 8 + reg];
			tempop.Op1 = M_E;
			tempop.opdata1 = T_v;
			op = &tempop;
		} else {
			op = &float_grps[opcode - 0xd8][reg];
			if (op->Op1 == M_FGRP) {
				tempop.name = fgrps[op->opdata1][rm];
				/* instruction fnstsw is only one with 
				 * strange arg 
				 */
				if ((opcode == 0xdf) && (*codeptr == 0xe0)) {
					irp->operand[1].op_type = O_REG;
					irp->operand[1].op_reg = R_eAX;
				}				
				op = &tempop;
			} 
		}
	}
	irp->opcodep = op;
	irp->opcode = opcode;
	irp->modrm = modrm; 
	irp->prefixes = prefixes; 

	/* Check to see if this is a bad instruction (per a table entry)
	 */
	if (op->opdata1 == T_BAD) {
		/* Back off the modrm if we grabbed one and return
		 * from here.
		 */
		if (modrm) {
			codeptr--;
			size = ((unsigned)codeptr - (unsigned)instrbuf.ptr);
			instrbuf.ptr = codeptr;
			irp->size = size;
			return(size);
		}
	}

	/* Check to see if there is an SIB byte.
	 */
	if (((modrm & 0xc0) != 0xc0) && ((modrm & 7) == 4)) {
		/* There is an SIB byte
		 */
		irp->sib = *codeptr++;
		irp->have_sib = 1;
	}

	/* Gather information on operands 
	 */
	if (op->Op1 && (op->Op1 != M_BAD)) {
		get_operand_info(0, irp);
	}
	if (op->Op2 && (op->Op2 != M_BAD)) {
		get_operand_info(1, irp);
	}
	if (op->Op3 && (op->Op3 != M_BAD)) {
		get_operand_info(2, irp);
	}

	/* Determine total instruction size and adjust instrbuf ptr
	 */
	size = ((unsigned)codeptr - (unsigned)instrbuf.ptr);
	instrbuf.ptr = codeptr;
	irp->size = size;
	return(size);
}

static int
seg_prefix(int prefixes) {
	if (prefixes & PREFIX_CS) {
		return(R_CS);
	} else if (prefixes & PREFIX_DS) {
		return(R_DS);
	} else if (prefixes & PREFIX_SS) {
		return(R_SS);
	} else if (prefixes & PREFIX_ES) {
		return(R_ES);
	} else if (prefixes & PREFIX_FS) {
		return(R_FS);
	} else if (prefixes & PREFIX_GS) {
		return(R_GS);
	} 
	return(0);
}

#ifdef NOT_USED
static void
print_seg_prefix(instr_rec_t *irp, FILE *ofp)
{
	if (irp->prefixes & PREFIX_CS) {
		fprintf(ofp, "%%cs:");
	}
	if (irp->prefixes & PREFIX_DS) {
		fprintf(ofp, "%%ds:");
	}
	if (irp->prefixes & PREFIX_SS) {
		fprintf(ofp, "%%ss:");
	}
	if (irp->prefixes & PREFIX_ES) {
		fprintf(ofp, "%%es:");
	}
	if (irp->prefixes & PREFIX_FS) {
		fprintf(ofp, "%%fs:");
	}
	if (irp->prefixes & PREFIX_GS) {
		fprintf(ofp, "%%gs:");
	}
}
#endif

#ifndef REDHAT
static int
print_prefixes(instr_rec_t *irp, FILE *ofp)
{
	int cnt = 0;

	if (irp->prefixes & PREFIX_REPZ) {
		fprintf(ofp, "repz ");
		cnt++;
	}
	if (irp->prefixes & PREFIX_REPNZ) {
		fprintf(ofp, "repnz ");
		cnt++;
	}
	if (irp->prefixes & PREFIX_LOCK) {
		fprintf(ofp, "lock ");
		cnt++;
	}
	if (irp->prefixes & PREFIX_ADR) {
		if (irp->aflag) {
			fprintf(ofp, "addr32 ");
		} else {
			fprintf(ofp, "addr16 ");
		}
		cnt++;
	}
	return(cnt);
}

static void
print_sib_value(int opnum, instr_rec_t *irp, FILE *ofp)
{
	if (irp->operand[opnum].op_type & O_REG) {
		if (irp->operand[opnum].op_type & O_BASE) {
			fprintf(ofp, "(%s)", 
				reg_name[irp->operand[opnum].op_reg]);
		} else {
			fprintf(ofp, "%s", 
				reg_name[irp->operand[opnum].op_reg]);
		}
		return;
	} else if (irp->operand[opnum].op_type & O_IMMEDIATE) {
		fprintf(ofp, "$0x%x", irp->operand[opnum].op_addr);
		return;
	}
	fprintf(ofp, "(");
	if (irp->operand[opnum].op_type & O_BASE) {
		fprintf(ofp, "%s,", reg_name[irp->operand[opnum].op_base]);
	} else {
		fprintf(ofp, ",");
	}
	if (irp->operand[opnum].op_type & O_INDEX) {
		fprintf(ofp, "%s,", reg_name[irp->operand[opnum].op_index]);
	} 
	fprintf(ofp, "%d)", (1 << irp->operand[opnum].op_scale));
}

static void
print_opvalue(int opnum, instr_rec_t *irp, FILE *ofp)
{
	if (irp->operand[opnum].op_type & O_REG) {
		if (irp->operand[opnum].op_type & (O_BASE|O_DISP)) {
			fprintf(ofp, "(%s)", 
				reg_name[irp->operand[opnum].op_reg]);
		} else {
			fprintf(ofp, "%s", 
				reg_name[irp->operand[opnum].op_reg]);
		}
	} else if (irp->operand[opnum].op_type & O_IMMEDIATE) {
		fprintf(ofp, "$0x%x", irp->operand[opnum].op_addr);
	} else if (irp->operand[opnum].op_type & O_ADDR) {
		/* jump or call address */
		printaddr(irp->operand[opnum].op_addr, 0, ofp);
	} else if (irp->operand[opnum].op_type & O_OFF) {
		fprintf(ofp, "0x%x", irp->operand[opnum].op_addr);
	}
}

int
print_instr(kaddr_t pc, FILE *ofp, int flag)
{
	int p = 0, i, j, size, print_comma = 0;
	instr_rec_t irp;
	opcode_rec_t *op;

	bzero(&irp, sizeof(irp));
	/* XXX -- For now, make aflag and dflag equal to one.  Should get
	 * this from some sort of configuration struct (set via 
	 * initialization)
	 */
	irp.aflag = 1;
	irp.dflag = 1;
	size = get_instr_info(pc, &irp);
	op = irp.opcodep;
	if (!op) {
		fprintf(ofp, "BAD INSTR (pc=0x%x)\n", pc);
		return(0);
	}
	printaddr(pc, 1, ofp);
	if (flag) {
		fprintf(ofp, "0x%04x  ", irp.opcode);
	}
	if (irp.prefixes) {
		p = print_prefixes(&irp, ofp);
	}
	print_instrname(op->name, &irp, ofp);
	/* HACK! but necessary to match i386-dis.c output for fwait.
	 */
	if (!strcmp(op->name, "fwait")) {
		fprintf(ofp, "\n");
		return(irp.size);
	}
	if (p || (strlen(op->name) >= 7)) {
		fprintf(ofp, " ");
	} else {
		for (i = 0; i < (7 - strlen(op->name)); i++) {
			fprintf(ofp, " ");
		}
	}
	for (j = 0; j < 3; j++) {
		if (irp.opcode == 0xc8) {
			i = j;
		} else {
			i = 2 - j;
		}
		if(irp.operand[i].op_type) {
			if (print_comma) {
				fprintf(ofp, ",");
			}
			if (irp.operand[i].op_type & O_LPTR) {
				fprintf(ofp, "0x%x,0x%x",
					irp.operand[i].op_seg,
					irp.operand[i].op_addr);
				print_comma++;
				continue;
			}
			if (irp.operand[i].op_type & O_CR) {
				fprintf(ofp, "%%cr%d", irp.operand[i].op_reg);
				print_comma++;
				continue;
			}
			if (irp.operand[i].op_type & O_DB) {
				fprintf(ofp, "%%db%d", irp.operand[i].op_reg);
				print_comma++;
				continue;
			}
			if (irp.operand[i].op_type & O_SEG) {
				fprintf(ofp, "%s:(%s)", 
					reg_name[irp.operand[i].op_seg],
					reg_name[irp.operand[i].op_reg]);
				print_comma++;
				continue;
			}
			if (irp.operand[i].op_type & O_INDIR) {
				fprintf(ofp, "*");
			}
			if (irp.operand[i].op_type & O_DISP) {
				fprintf(ofp, "0x%x", irp.operand[i].op_disp);
			}
			if (irp.have_sib) {
				print_sib_value(i, &irp, ofp);
			} else {
				print_opvalue(i, &irp, ofp);
			}
			print_comma++;
		}
	}
	if (flag) {
		fprintf(ofp, "  (%d %s)\n", 
			irp.size, (irp.size > 1) ? "bytes" : "byte"); 
	} else {
		fprintf(ofp, "\n");
	}
	return(irp.size);
}

void
list_instructions(FILE *ofp)
{
	int i, j, print_comma = 0;

	fprintf(ofp, "ONE BYTE INSTRUCTIONS:\n\n");
	for(i = 0; i < 256; i++) {
		fprintf(ofp, "0x%04x  %s", i, op_386[i].name);
		for (j = 0; j < (10 - strlen(op_386[i].name)); j++) {
			fprintf(ofp, " ");
		}
		if (op_386[i].Op1) {
			print_optype(op_386[i].Op1, op_386[i].opdata1, ofp);
			print_comma++;
		}
		if (op_386[i].Op2) {
			if (print_comma) {
				fprintf(ofp, ",");
			}
			print_optype(op_386[i].Op2, op_386[i].opdata2, ofp);
			print_comma++;
		}
		if (op_386[i].Op3) {
			if (print_comma) {
				fprintf(ofp, ",");
			}
			print_optype(op_386[i].Op3, op_386[i].opdata3, ofp);
		}
		fprintf(ofp, "\n");
		
	}

	fprintf(ofp, "\nTWO BYTE INSTRUCTIONS:\n\n");
	for(i = 0; i < 256; i++) {
		fprintf(ofp, "0x0f%02x  %s", i, op_386_twobyte[i].name);
		for (j = 0; j < (10 - strlen(op_386_twobyte[i].name)); j++) {
			fprintf(ofp, " ");
		}
		if (op_386_twobyte[i].Op1) {
			print_optype(op_386_twobyte[i].Op1, 
				op_386_twobyte[i].opdata1, ofp);
			print_comma++;
		}
		if (op_386_twobyte[i].Op2) {
			if (print_comma) {
				fprintf(ofp, ",");
			}
			print_optype(op_386_twobyte[i].Op2, 
				op_386_twobyte[i].opdata2, ofp);
			print_comma++;
		}
		if (op_386_twobyte[i].Op3) {
			if (print_comma) {
				fprintf(ofp, ",");
			}
			print_optype(op_386_twobyte[i].Op3, 
				op_386_twobyte[i].opdata3, ofp);
		}
		fprintf(ofp, "\n");
	}
}
#endif  /* !REDHAT */

void
free_instr_stream(instr_rec_t *irp)
{
	instr_rec_t *ptr;

	if(irp) {
		while (irp->prev) {
			irp = irp->prev;
		}
		while (irp) {
			ptr = irp;
			irp = irp->next;
			kl_free_block(ptr);
		}
	}
}

instr_rec_t *
get_instr_stream(kaddr_t pc, int bcount, int acount)
{
	int size, count = 0;
	kaddr_t addr, start_addr, end_addr;
        syment_t *sp1, *sp2;
#ifdef REDHAT
	syment_t *sp, *sp_next, *sp_next_next;
	ulong offset;
#endif
	instr_rec_t *fst = (instr_rec_t *)NULL, *lst, *ptr, *cur;

#ifdef REDHAT
	cur = NULL;
	if ((sp = x86_is_entry_tramp_address(pc, &offset))) 
        	pc = sp->value + offset;
#endif
	if (!(sp1 = kl_lkup_symaddr(pc))) {
		return((instr_rec_t *)NULL);
	}
	start_addr = sp1->s_addr;
	if (pc <= (sp1->s_addr + (bcount * 15))) {
		if ((sp2 = kl_lkup_symaddr(sp1->s_addr - 4))) {
			start_addr = sp2->s_addr;
		}
	} 
#ifdef REDHAT
	sp_next = next_symbol(NULL, sp1);
	if (!sp_next)
		return((instr_rec_t *)NULL);
	sp_next_next = next_symbol(NULL, sp_next);

        if (pc > (sp_next->s_addr - (acount * 15))) {
                if (sp_next_next) {
                        end_addr = sp_next_next->s_addr;
                } else {
                        end_addr = sp_next->s_addr;
                }
        } else {
                end_addr = sp_next->s_addr;
        }
#else
	if (pc > (sp1->s_next->s_addr - (acount * 15))) {
		if (sp1->s_next->s_next) {
			end_addr = sp1->s_next->s_next->s_addr;
		} else {
			end_addr = sp1->s_next->s_addr;
		}
	} else {
		end_addr = sp1->s_next->s_addr;
	}
#endif
	addr = start_addr;
	while (addr <= pc) {
		if (addr >= end_addr) {
			/* We've gone too far (beyond the end of this
			 * function) The pc most likely was not valid
			 * (it pointed into the middle of an instruction).
			 */
			free_instr_stream(cur);
			return((instr_rec_t *)NULL);
		}
		if (count <= bcount) {
			/* Allocate another record
			 */
			cur = (instr_rec_t *)
				kl_alloc_block(sizeof(instr_rec_t), K_TEMP);
			count++;
			cur->aflag = cur->dflag = 1;
			if ((ptr = fst)) {
				while (ptr->next) {
					ptr = ptr->next;
				}
				ptr->next = cur;
				cur->prev = ptr;
			} else {
				fst = cur; 
			}
		} else {
			/* Pull the last record to the front of the list
			 */
			ptr = fst;
			if (ptr->next) {
				fst = ptr->next;
				fst->prev = (instr_rec_t *)NULL;
				cur->next = ptr;
			}
			bzero(ptr, sizeof(*ptr));
			ptr->aflag = ptr->dflag = 1;
			if (ptr != fst) {
				ptr->prev = cur;
			}
			cur = ptr;

		}
		size = get_instr_info(addr, cur);
		if (size == 0) {
			free_instr_stream(cur);
			return((instr_rec_t *)NULL);
		}
		addr += size;
	}
	if (acount) {
		lst = cur;
		for (count = 0; count < acount; count++) {
			ptr = (instr_rec_t *) 
				kl_alloc_block(sizeof(instr_rec_t), K_TEMP);
			ptr->aflag = ptr->dflag = 1;
			size = get_instr_info(addr, ptr);
			if (size == 0) {
				kl_free_block(ptr);
				return(cur);
			}
			lst->next = ptr;
			ptr->prev = lst;
			lst = ptr;
			addr += size;
		}
	}
	return(cur);
}

#ifndef REDHAT
/*
 * print_instr_stream()
 */
kaddr_t
print_instr_stream(kaddr_t value, int bcount, int acount, int flags, FILE *ofp)
{
	kaddr_t v = value;
	instr_rec_t *cur_irp, *irp;

	if ((cur_irp = get_instr_stream(v, bcount, acount))) {
		irp = cur_irp;

		/* Walk back to the start of the stream and then
		 * print out all instructions in the stream.
		 */
		while (irp->prev) {
			irp = irp->prev;
		}
		while (irp) {
			if (flags & C_FULL) {
				print_instr(irp->addr, ofp, 1);
			} else {
				print_instr(irp->addr, ofp, 0);
			}
			if (irp->addr >= value) {
				v += irp->size;
			}
			irp = irp->next;
		}
		free_instr_stream(cur_irp);
	}
	return(v);
}

/*
 * dump_instr() -- architecture specific instruction dump routine
 */
void
dump_instr(kaddr_t addr, uint64_t count, int flags, FILE *ofp)
{
	fprintf(ofp, "This operation not supported for i386 architecture.\n");
}
#endif  /* !REDHAT */

/*
 *   lkcdutils-4.1/libutil/kl_queue.c
 */

/*
 * Copyright 2002 Silicon Graphics, Inc. All rights reserved.
 */
#ifndef REDHAT
#include <kl_lib.h>
#endif

/* 
 * kl_enqueue() -- Add a new element to the tail of doubly linked list.
 */
void
kl_enqueue(element_t **list, element_t *new)
{
	element_t *head;

	/* 
	 * If there aren't any elements on the list, then make new element the 
	 * head of the list and make it point to itself (next and prev).
	 */
	if (!(head = *list)) {
		new->next = new;
		new->prev = new;
		*list = new;
	} else {
		head->prev->next = new;
		new->prev = head->prev;
		new->next = head;
		head->prev = new;
	}
}

/* 
 * kl_dequeue() -- Remove an element from the head of doubly linked list.
 */
element_t *
kl_dequeue(element_t **list)
{
	element_t *head;

	/* If there's nothing queued up, just return 
	 */
	if (!*list) {
		return((element_t *)NULL);
	}

	head = *list;

	/* If there is only one element on list, just remove it 
	 */
	if (head->next == head) {
		*list = (element_t *)NULL;
	} else {
		head->next->prev = head->prev;
		head->prev->next = head->next;
		*list = head->next;
	}
	head->next = 0;
	return(head);
}

#ifndef REDHAT
/*
 * kl_findqueue()
 */
int
kl_findqueue(element_t **list, element_t *item)
{
	element_t *e;

	/* If there's nothing queued up, just return 
	 */
	if (!*list) {
		return(0);
	}

	e = *list;

	/* Check to see if there is only one element on the list. 
	 */
	if (e->next == e) {
		if (e != item) {
			return(0);
		}
	} else {
		/* Now walk linked list looking for item
		 */
		while(1) {
			if (e == item) {
				break;
			} else if (e->next == *list) {
				return(0);
			}
			e = e->next;
		}
	}
	return(1);
}

/*
 * kl_findlist_queue()
 */
int
kl_findlist_queue(list_of_ptrs_t **list,  list_of_ptrs_t *item, 
		  int (*compare)(void *,void *))
{
	list_of_ptrs_t *e;

	/* If there's nothing queued up, just return 
	 */
	if (!*list) {
		return(0);
	}

	e = *list;

	/* Check to see if there is only one element on the list. 
	 */
	if (((element_t *)e)->next == (element_t *)e) {
		if (compare(e,item)) {
			return(0);
		}
	} else {
		/* Now walk linked list looking for item
		 */
		while(1) {
			if (!compare(e,item)) {
				break;
			} else if (((element_t *)e)->next == 
						(element_t *)*list) {
				return(0);
			}
			e = (list_of_ptrs_t *)((element_t *)e)->next;
		}
	}
	return(1);
}

/* 
 * kl_remqueue() -- Remove specified element from doubly linked list.
 */
void
kl_remqueue(element_t **list, element_t *item)
{
	/* Check to see if item is first on the list
	 */
	if (*list == item) {
		if (item->next == item) {
			*list = (element_t *)NULL;
			return;
		} else {
			*list = item->next;
		}
	}

	/* Remove item from list
	 */
	item->next->prev = item->prev;
	item->prev->next = item->next;
}

#endif  /* !REDHAT */
#endif  /* X86 */
