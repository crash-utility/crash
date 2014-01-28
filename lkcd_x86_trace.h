/*
 * Copyright 1999 Silicon Graphics, Inc. All rights reserved.
 */

/*
 *  lkcd_x86_trace.h
 *
 *  Copyright (C) 2002, 2003, 2004, 2005, 2010 David Anderson
 *  Copyright (C) 2002, 2003, 2004, 2005, 2010 Red Hat, Inc. All rights reserved.
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
 *     lkcdutils-4.1/libklib/include/asm-i386/kl_types.h
 *     lkcdutils-4.1/lcrash/include/lc_command.h
 *     lkcdutils-4.1/libklib/include/klib.h
 *     lkcdutils-4.1/lcrash/include/asm-i386/lc_dis.h
 *     lkcdutils-4.1/lcrash/include/asm-i386/lc_trace.h
 *     lkcdutils-4.1/libutil/kl_queue.h
 *     lkcdutils-4.1/libklib/include/kl_error.h
 */

#ifdef REDHAT

#include "defs.h"

#define TASK_STRUCT_SZ  (SIZE(task_struct))
#define KL_PAGE_OFFSET  (machdep->kvbase)
#define LINUX_2_2_X(KL_LINUX_RELEASE) (VALID_MEMBER(task_struct_tss))
#define KLE_PRINT_TRACE_ERROR  KLE_INVALID_KERNELSTACK

typedef struct syment syment_t;

#define s_addr value
#define s_name name

typedef uint32_t kaddr_t; 

extern int INT_EFRAME_SS;
extern int INT_EFRAME_ESP;
extern int INT_EFRAME_EFLAGS;
extern int INT_EFRAME_CS;
extern int INT_EFRAME_EIP;
extern int INT_EFRAME_ERR;
extern int INT_EFRAME_ES;
extern int INT_EFRAME_DS;
extern int INT_EFRAME_EAX;
extern int INT_EFRAME_EBP;
extern int INT_EFRAME_EDI;
extern int INT_EFRAME_ESI;
extern int INT_EFRAME_EDX;
extern int INT_EFRAME_ECX;
extern int INT_EFRAME_EBX;
extern int INT_EFRAME_GS;

extern ulong int_eframe[];

#endif  /* REDHAT */


/*
 *  lkcdutils-4.1/libklib/include/asm-i386/kl_types.h
 */
typedef uint32_t        uaddr_t;
typedef uint64_t        k_error_t;

/*
 *  lkcdutils-4.1/lcrash/include/lc_command.h
 */
#define C_ALL           0x00000004   /* All elements */
#define C_PERM          0x00000008   /* Allocate perminant blocks */
#define C_TEMP                   0   /* For completeness */
#define C_FULL          0x00000010   /* Full output */

/*
 *  lkcdutils-4.1/libklib/include/klib.h
 */
#define K_TEMP          1
#define K_PERM          2

/*
 *  lkcdutils-4.1/lcrash/include/asm-i386/lc_dis.h
 */

/* Buffer to hold a cache of instruction bytes...we have to make sure
 * that there are AT LEAST 15 unread bytes in the buffer at all times,
 * as this is the maximum number of bytest that can belong to a single
 * instruction.
 *
 * Copyright 1999 Silicon Graphics, Inc. All rights reserved.
 */

typedef struct instr_buf_s {
	kaddr_t 	addr;
	int		size;
	unsigned char  *ptr;	
	unsigned char	buf[256];
} instr_buf_t;

typedef struct opcode_rec_s {
	char    *name;
	int     Op1;
	int     opdata1;
	int     Op2;
	int     opdata2;
	int     Op3;
	int     opdata3;
} opcode_rec_t;

typedef struct op_s {
	int             op_type;
	int		op_seg;
	int		op_reg;
	int		op_disp;
	int		op_base;
	int		op_index;
	int		op_scale;
	kaddr_t         op_addr;
} op_t; 

typedef struct instr_rec_s {
	struct instr_rec_s	*next;
	struct instr_rec_s	*prev;
	kaddr_t			 addr;	    /* start address of instruction */ 
	opcode_rec_t    	*opcodep;
	int		 	 size;
	int		 	 aflag; 
	int		 	 dflag;
	unsigned int     	 prefixes;
	unsigned int     	 opcode;
	unsigned char    	 modrm;
	unsigned char    	 sib;
	int		 	 have_sib; /* needed because sib can be zero */
	op_t             	 operand[3];
} instr_rec_t;

/* Addressing methods
 */
#define M_NONE    	 0
#define M_A       	 1
#define M_C       	 2
#define M_D	  	 3
#define M_E	  	 4
#define M_indirE  	 5
#define M_F	  	 6
#define M_G	  	 7
#define M_I	  	 8
#define M_sI	  	 9
#define M_J	 	10
#define M_M	 	11
#define M_O	 	12
#define M_P	 	13
#define M_Q	 	14
#define M_R	 	15
#define M_S	 	16
#define M_T	 	17
#define M_V	 	18
#define M_W	 	19
#define M_X	 	20
#define M_Y	 	21
#define M_MMX    	22
#define M_EM     	23
#define M_MS     	24
#define M_GRP    	25
#define M_REG    	26
#define M_indirREG    	27
#define M_FLOAT		28
#define M_FGRP		29
#define M_BAD    	30  /* Must be last on list */

/* Operand data types
 */
#define T_NONE    	 0
#define T_a	  	 1
#define T_b	  	 2
#define T_c    	  	 3
#define T_d       	 4
#define T_dq      	 5
#define T_p       	 6
#define T_pi      	 7
#define T_ps      	 8
#define T_q       	 9
#define T_s      	10
#define T_ss     	11
#define T_si     	12
#define T_v      	13
#define T_w      	14
#define T_BAD    	15	/* Must be last in list */

/* Register operand types
 */
#define R_eAX 	  	 0
#define R_eCX 	  	 1
#define R_eDX 	  	 2
#define R_eBX 	  	 3
#define R_eSP 	  	 4
#define R_eBP 	  	 5
#define R_eSI 	  	 6
#define R_eDI 	  	 7
#define R_AX 	  	 8
#define R_CX 	  	 9
#define R_DX 	 	10
#define R_BX 	 	11
#define R_SP 	 	12
#define R_BP 	 	13
#define R_SI 	 	14
#define R_DI 	 	15
#define R_AL 	 	16
#define R_CL 	 	17
#define R_DL 	 	18
#define R_BL 	 	19
#define R_AH 	 	20
#define R_CH 	 	21
#define R_DH 	 	22
#define R_BH 	 	23
#define R_ES 	 	24
#define R_CS 	 	25
#define R_SS 	 	26
#define R_DS 	 	27
#define R_FS 	 	28
#define R_GS 	 	29
#define R_BX_SI		30
#define R_BX_DI		31
#define R_BP_SI		32
#define R_BP_DI		33
#define R_BAD 	 	34	/* Must be last on list */

/* Operand codes
 */
#define BAD 	M_BAD, T_BAD
#define NONE 	M_NONE, T_NONE
#define Ap 	M_A, T_p
#define Av 	M_A, T_v
#define Cd 	M_C, T_d
#define Dd	M_D, T_d
#define Dx 	M_D, T_x
#define Td 	M_T, T_d
#define Eb 	M_E, T_b
#define indirEb M_indirE, T_b
#define Ev 	M_E, T_v
#define indirEv M_indirE, T_v
#define Ew	M_E, T_w
#define Gb 	M_G, T_b
#define Gv 	M_G, T_v
#define Gw 	M_G, T_w
#define Ib 	M_I, T_b
#define sIb 	M_sI, T_b
#define Iv 	M_I, T_v
#define sIv 	M_sI, T_v
#define Iw 	M_I, T_w
#define sIw 	M_sI, T_w
#define Jb 	M_J, T_b
#define Jp 	M_J, T_p
#define Jv 	M_J, T_v
#define M  	M_M, T_NONE
#define Ma 	M_M, T_a
#define Mp 	M_M, T_p
#define Ob 	M_O, T_b
#define Ov 	M_O, T_v
#define Pq 	M_P, T_q
#define Qq 	M_Q, T_q
#define Qd 	M_Q, T_d
#define Rw 	M_R, T_w
#define Rd 	M_R, T_d
#define Sw 	M_S, T_w
#define Vq 	M_V, T_q
#define Vss 	M_V, T_ss
#define Wq 	M_W, T_q
#define Wss 	M_W, T_ss
#define Xb 	M_X, T_b
#define Xv 	M_X, T_v
#define Yb 	M_Y, T_b
#define Yv 	M_Y, T_v

/* 32-bit */
#define eAX 	M_REG, R_eAX
#define eBX 	M_REG, R_eBX
#define eCX 	M_REG, R_eCX
#define eDX 	M_REG, R_eDX
#define eSP 	M_REG, R_eSP
#define eBP 	M_REG, R_eBP
#define eSI 	M_REG, R_eSI
#define eDI 	M_REG, R_eDI

/* 16-bit */
#define AX 	M_REG, R_AX
#define BX 	M_REG, R_BX
#define CX 	M_REG, R_CX
#define DX 	M_REG, R_DX
#define indirDX	M_indirREG, R_DX
#define DX 	M_REG, R_DX
#define BP 	M_REG, R_BP
#define SI 	M_REG, R_SI
#define DI 	M_REG, R_DI
#define SP 	M_REG, R_SP

/* 8-bit */
#define AH 	M_REG, R_AH
#define AL 	M_REG, R_AL
#define BH 	M_REG, R_BH
#define BL 	M_REG, R_BL
#define CH 	M_REG, R_CH
#define CL 	M_REG, R_CL
#define DH 	M_REG, R_DH
#define DL 	M_REG, R_DL

/* Segment Registers */
#define cs 	M_REG, R_CS
#define ds 	M_REG, R_DS
#define ss 	M_REG, R_SS
#define es 	M_REG, R_ES
#define fs 	M_REG, R_FS
#define gs 	M_REG, R_GS

#define MX 	M_MMX, T_NONE
#define EM 	M_EM, T_NONE
#define MS 	M_MS, T_NONE

#define GRP1b "GRP1b", M_GRP, 0
#define GRP1S "GRP1S", M_GRP, 1
#define GRP1Ss "GRP1Ss", M_GRP, 2
#define GRP2b "GRP2b", M_GRP, 3
#define GRP2S "GRP2S", M_GRP, 4
#define GRP2b_one "GRP2b_one", M_GRP, 5
#define GRP2S_one "GRP2S_one", M_GRP, 6
#define GRP2b_cl "GRP2b_cl", M_GRP, 7
#define GRP2S_cl "GRP2S_cl", M_GRP, 8
#define GRP3b "GRP3b", M_GRP, 9
#define GRP3S "GRP3S", M_GRP, 10
#define GRP4  "GRP4", M_GRP, 11
#define GRP5  "GRP5", M_GRP, 12
#define GRP6  "GRP6", M_GRP, 13
#define GRP7 "GRP7",  M_GRP, 14
#define GRP8 "GRP8", M_GRP, 15
#define GRP9 "GRP9", M_GRP, 16
#define GRP10 "GRP10", M_GRP, 17
#define GRP11 "GRP11", M_GRP, 18
#define GRP12 "GRP12", M_GRP, 19

#define FLOAT 	"FLOAT", M_FLOAT, T_NONE

#define ST 	M_FLOAT, T_NONE
#define STi 	M_FLOAT, T_NONE

#define FGRPd9_2 "FGRPd9_2", M_FGRP, 0
#define FGRPd9_4 "FGRPd9_4", M_FGRP, 1
#define FGRPd9_5 "FGRPd9_5", M_FGRP, 2
#define FGRPd9_6 "FGRPd9_6", M_FGRP, 3
#define FGRPd9_7 "FGRPd9_7", M_FGRP, 4
#define FGRPda_5 "FGRPda_5", M_FGRP, 5
#define FGRPdb_4 "FGRPdb_4", M_FGRP, 6
#define FGRPde_3 "FGRPde_3", M_FGRP, 7
#define FGRPdf_4 "FGRPdf_4", M_FGRP, 8

#define PREFIX_REPZ 	0x0001
#define PREFIX_REPNZ 	0x0002
#define PREFIX_LOCK 	0x0004
#define PREFIX_CS 	0x0008
#define PREFIX_SS       0x0010
#define PREFIX_DS 	0x0020
#define PREFIX_ES 	0x0040
#define PREFIX_FS 	0x0080
#define PREFIX_GS 	0x0100
#define PREFIX_DATA 	0x0200
#define PREFIX_ADR 	0x0400
#define PREFIX_FWAIT 	0x0800

/* Operand types
 */
#define O_REG	  	0x0001
#define O_IMMEDIATE  	0x0002
#define O_ADDR  	0x0004
#define O_OFF  		0x0008
#define O_DISP   	0x0010
#define O_BASE   	0x0020
#define O_INDEX   	0x0040
#define O_SCALE         0x0080
#define O_INDIR         0x0100
#define O_SEG           0x0200
#define O_CR            0x0400
#define O_DB            0x0800
#define O_LPTR          0x1000

#ifndef REDHAT
/* Function prototypes
 */
int get_instr_info(	
	kaddr_t 	/* pc */, 
	instr_rec_t * 	/* pointer to instr_rec_s struct */);

instr_rec_t *get_instr_stream(
	kaddr_t 	/* program counter */, 
	int 		/* before count */, 
	int 		/* after count */);

void free_instr_stream(
	instr_rec_t *);
#endif /* !REDHAT */

/* 
 *  lkcdutils-4.1/lcrash/include/asm-i386/lc_trace.h
 */

/*
 * Copyright 1999 Silicon Graphics, Inc. All rights reserved.
 */
#define STACK_SEGMENTS	1
#ifdef REDHAT
#define STACK_SIZE   (STACKSIZE())
#define KSTACK_SIZE  (STACKSIZE())
#else  /* REDHAT */
#define STACK_SIZE	0x2000
#endif /* !REDHAT */

#ifdef NOT
#define INCLUDE_REGINFO 1
#endif

#ifdef INCLUDE_REGINFO

#define NUM_REGS	8	
#define REGVAL_UNKNOWN  0
#define REGVAL_VALID    1
#define REGVAL_BAD      2  /* Value loaded into register before it was saved */

/* Register record
 */
typedef struct reg_rec {
	uint32_t			state;
	uint32_t			value;
} reg_rec_t;
#endif

/* Stack frame
 */
typedef struct sframe_rec {
	struct sframe_rec      *next;
	struct sframe_rec      *prev;
	int			flag;
	int			level;
	char		       *funcname;
	char		       *srcfile;
	int			line_no;
	kaddr_t			pc;
	kaddr_t			ra;
	kaddr_t			sp;
	kaddr_t			fp;
	uint32_t	       *asp;
	int			frame_size;
	int			ptr;
	uint64_t		error;
#ifdef INCLUDE_REGINFO
	reg_rec_t		regs[NUM_REGS];
#endif
} sframe_t;

/* flag field of sframe_t */
#define EX_FRAME	0x1	/* this frame is an interrupt or exception 
				   frame, pt_regs field of sframe_t is valid 
				   in this case */
#define INCOMPLETE_EX_FRAME  0x2
#define SET_EX_FRAME_ADDR    0x4

/* Stack segment structure
 */
struct stack_s {
	int			type;
	uint32_t		size;
	kaddr_t			addr;
	uint32_t	       *ptr;
};

/* Stack trace header
 */
typedef struct trace_rec {
	int			flags;
	kaddr_t			task;
	struct task_struct     *tsp;
	struct stack_s		stack[STACK_SEGMENTS];
	int			stackcnt;
	sframe_t	       *frame;
	int			nframes;
#ifdef REDHAT
	struct bt_info	       *bt;
#endif
} trace_t;

#define TF_TRACEREC_VALID  0x01 /* The trace_rec_s has been setup already!   */
#define TF_SUPPRESS_HEADER 0x02 /* Suppress header output from trace cmds    */

/* Stack types 
 */
#define S_USERSTACK	0
#define S_KERNELSTACK	1

/* Stack frame updating macro
 */
#define UPDATE_FRAME(FUNCNAME, PC, RA, SP, FP, ASP, SRCNAME, LINE_NO, SIZE, FLAG) \
        curframe->funcname = FUNCNAME; \
        curframe->pc = PC; \
        curframe->sp = SP; \
        curframe->ra = RA; \
        curframe->fp = FP; \
        curframe->asp = ASP; \
        curframe->srcfile = SRCNAME; \
        curframe->line_no = LINE_NO; \
        curframe->frame_size = SIZE; \
        curframe->ptr = curstkidx; \
        kl_enqueue((element_t **)&trace->frame, (element_t *)curframe); \
        trace->nframes++; \
	curframe->flag |= FLAG; \

#ifndef REDHAT
/* Function prototypes
 */
void print_pc(
	kaddr_t 	/* PC */, 
	FILE *		/* output file pointer */);

trace_t *alloc_trace_rec(
	int 		/* flag */);

int setup_trace_rec(kaddr_t, kaddr_t, int, trace_t *);
int find_trace(kaddr_t, kaddr_t, kaddr_t, kaddr_t, trace_t *, int);
void trace_banner(FILE *);
int print_traces(kaddr_t, int, int, FILE *);
void print_trace(trace_t *, int, FILE *);
void free_trace_rec(trace_t *t);
int task_trace(kaddr_t, int, FILE *);
int do_list(kaddr_t, int, FILE *);
void live_vmdump(int, int);
int do_report(int, FILE *);
void stab_type_banner(FILE *, int);
void ktype_banner(FILE *, int);
void print_stab_type(stab_type_t *, int, FILE *);
void print_ktype(kltype_t *, int, FILE *);
void walk_ktype(kltype_t *, int, FILE *);
int list_stab_types(int, FILE *);
int list_ktypes(int, FILE *);
void structlist(FILE *);
int walk_structs(char *, char *, int, kaddr_t, int, FILE *);
sframe_t *alloc_sframe(trace_t *, int);
int add_frame(trace_t *, kaddr_t, kaddr_t);
void finish_trace(trace_t *);
int dumptask_trace(kaddr_t, dump_header_asm_t *, int, FILE *);
#endif  /* !REDHAT */


/*
 *  lkcdutils-4.1/libutil/kl_queue.h
 */

/*
 * Copyright 1999 Silicon Graphics, Inc. All rights reserved.
 */

#ifndef _KL_QUEUE_H
#define _KL_QUEUE_H

/* List element header
 */
typedef struct element_s {
	struct element_s    *next;
	struct element_s    *prev;
} element_t;

/* Some useful macros
 */
#define ENQUEUE(list, elem) \
	kl_enqueue((element_t **)list, (element_t *)elem)
#define DEQUEUE(list) kl_dequeue((element_t **)list)
#define FINDQUEUE(list, elem) \
	kl_findqueue((element_t **)list, (element_t *)elem)
#define REMQUEUE(list, elem) kl_remqueue((element_t **)list, (element_t *)elem)

typedef struct list_of_ptrs {
	element_t		elem;
	unsigned long long 	val64;
} list_of_ptrs_t;

#define FINDLIST_QUEUE(list, elem, compare) \
	kl_findlist_queue((list_of_ptrs_t **)list, \
		(list_of_ptrs_t *)elem, compare)

#ifndef REDHAT
/** 
 ** Function prototypes
 **/

/* Add a new element to the tail of a doubly linked list.
 */
void kl_enqueue(
	element_t**	/* ptr to head of list */, 
	element_t*	/* ptr to element to add to the list */);

/* Remove an element from the head of a doubly linked list. A pointer 
 * to the element will be returned. In the event that the list is 
 * empty, a NULL pointer will be returned.
 */
element_t *kl_dequeue(
	element_t**	/* ptr to list head (first item removed) */);

/* Checks to see if a particular element is in a list. If it is, a 
 * value of one (1) will be returned. Otherwise, a value of zero (0) 
 * will be returned.
 */
int kl_findqueue(
	element_t**	/* ptr to head of list */, 
	element_t*	/* ptr to element to find on list */);

/* Walks through a list of pointers to queues and looks for a 
 * particular list.
 */
int kl_findlist_queue(
	list_of_ptrs_t** 	/* ptr to list of lists */,  
	list_of_ptrs_t* 	/* ptr to list to look for */,
	int(*)(void *, void *)	/* ptr to compare function */);

/* Remove specified element from doubly linked list.
 */
void kl_remqueue(
	element_t**		/* ptr to head of list */, 
	element_t*		/* ptr to element to remove from list */);
#endif  /* !REDHAT */

#endif /* _KL_QUEUE_H */


/*
 *  lkcdutils-4.1/libklib/include/kl_error.h
 */

/*
 * kl_error.h
 *
 * Copyright 1999 Silicon Graphics, Inc. All rights reserved.
 */

/**
 ** This header file contains basic definitions and declarations
 ** for the KLIB error handling facility.
 **
 **/

#ifndef __KL_ERROR_H
#define __KL_ERROR_H

/* Error Classes
 */
#define KLEC_APP        0
#define KLEC_KLIB       1
#define KLEC_MEM	2
#define KLEC_SYM	3
#define KLEC_KERN	4

#define KLEC_CLASS_MASK 0x00000000ff000000
#define KLEC_CLASS_SHIFT 24
#define KLEC_ECODE_MASK 0x0000000000ffffff
#define KLEC_TYPE_MASK  0xffffffff00000000
#define KLEC_TYPE_SHIFT 32
#define KLEC_CLASS(e) ((e & KLEC_CLASS_MASK) >> KLEC_CLASS_SHIFT)
#define KLEC_ECODE(e) (e & KLEC_ECODE_MASK)
#define KLEC_TYPE(e) ((e & KLEC_TYPE_MASK) >> KLEC_TYPE_SHIFT)

extern uint64_t klib_error;
void kl_reset_error(void);
void kl_print_error(void);

/** 
 ** Some macros for accessing data in klib_error 
 **/
#define KLIB_ERROR		klib_error
#define KL_ERROR 		klib_error
#define KL_ERRORVAL 		klib_errorval
#define KL_ERRORFP 		stderr

/* Error codes
 *
 * There are basically two types of error codes -- with each type
 * residing in a single word in a two word error code value. The lower
 * 32-bits contains an error class and code that represents exactly 
 * WHAT error occurred (e.g., non-numeric text in a numeric value 
 * entered by a user, bad virtual address, etc.). 
 * 
 * The upper 32-bits represents what type of data was being referenced 
 * when the error occurred (e.g., bad proc struct). Having two tiers of 
 * error codes makes it easier to generate useful and specific error 
 * messages. Note that is possible to have situations where one or the 
 * other type of error codes is not set. This is OK as long as at least 
 * one type s set.
 */

/** General klib error codes
 **/
#define KLE_KLIB (KLEC_KLIB << KLEC_CLASS_SHIFT)
#define KLE_NO_MEMORY				(KLE_KLIB|1)
#define KLE_OPEN_ERROR				(KLE_KLIB|2)
#define KLE_ZERO_BLOCK 				(KLE_KLIB|3)  
#define KLE_INVALID_VALUE 			(KLE_KLIB|4)  
#define KLE_NULL_BUFF 				(KLE_KLIB|5)  
#define KLE_ZERO_SIZE 				(KLE_KLIB|6)  
#define KLE_ACTIVE 				(KLE_KLIB|7)  


#define KLE_MISC_ERROR 				(KLE_KLIB|97)
#define KLE_NOT_SUPPORTED 			(KLE_KLIB|98)  
#define KLE_UNKNOWN_ERROR 			(KLE_KLIB|99)  

/** memory error codes
 **/
#define KLE_MEM (KLEC_MEM << KLEC_CLASS_SHIFT)
#define KLE_BAD_MAP_FILE			(KLE_MEM|1)
#define KLE_BAD_DUMP	  			(KLE_MEM|2)
#define KLE_BAD_DUMPTYPE			(KLE_MEM|3)
#define KLE_INVALID_LSEEK 			(KLE_MEM|4) 
#define KLE_INVALID_READ 			(KLE_MEM|5) 
#define KLE_BAD_MEMINFO 			(KLE_MEM|6) 
#define KLE_INVALID_PADDR 			(KLE_MEM|7)  
#define KLE_INVALID_VADDR 			(KLE_MEM|8)  
#define KLE_INVALID_VADDR_ALIGN 		(KLE_MEM|9)  
#define KLE_INVALID_MAPPING 		        (KLE_MEM|10)  
#define KLE_CMP_ERROR 		        	(KLE_MEM|11)  
#define KLE_INVALID_DUMP_MAGIC 		        (KLE_MEM|12)  
#define KLE_KERNEL_MAGIC_MISMATCH               (KLE_MEM|13)
#define KLE_NO_END_SYMBOL                       (KLE_MEM|14)
#define KLE_INVALID_DUMP_HEADER			(KLE_MEM|15)
#define KLE_DUMP_INDEX_CREATION			(KLE_MEM|16)
#define KLE_DUMP_HEADER_ONLY			(KLE_MEM|17)

/** symbol error codes
 **/
#define KLE_SYM (KLEC_SYM << KLEC_CLASS_SHIFT)
#define KLE_NO_SYMTAB                     	(KLE_SYM|1)
#define KLE_NO_SYMBOLS                     	(KLE_SYM|2)
#define KLE_INVALID_TYPE                        (KLE_SYM|3)
#define KLE_NO_MODULE_LIST                      (KLE_SYM|4)

/** kernel data error codes
 **/
#define KLE_KERN (KLEC_KERN << KLEC_CLASS_SHIFT)
#define KLE_INVALID_KERNELSTACK 		(KLE_KERN|1)  
#define KLE_INVALID_STRUCT_SIZE 		(KLE_KERN|2)  
#define KLE_BEFORE_RAM_OFFSET	 		(KLE_KERN|3)  
#define KLE_AFTER_MAXPFN 			(KLE_KERN|4)  
#define KLE_AFTER_PHYSMEM  			(KLE_KERN|5)  
#define KLE_AFTER_MAXMEM 			(KLE_KERN|6)  
#define KLE_PHYSMEM_NOT_INSTALLED 		(KLE_KERN|7)  
#define KLE_NO_DEFTASK	 			(KLE_KERN|8)  
#define KLE_PID_NOT_FOUND 			(KLE_KERN|9)  
#define KLE_DEFTASK_NOT_ON_CPU 			(KLE_KERN|10)  
#define KLE_NO_CURCPU 				(KLE_KERN|11)  
#define KLE_NO_CPU 				(KLE_KERN|12)  
#define KLE_SIG_ERROR 				(KLE_KERN|13)  

/** Error codes that indicate what type of data was bad. These are
 ** placed in the upper 32-bits of klib_error.
 **/
#define KLE_BAD_TASK_STRUCT    	(((uint64_t)1)<<32)
#define KLE_BAD_SYMNAME         (((uint64_t)2)<<32)
#define KLE_BAD_SYMADDR         (((uint64_t)3)<<32)
#define KLE_BAD_FUNCADDR        (((uint64_t)4)<<32)
#define KLE_BAD_STRUCT          (((uint64_t)5)<<32)
#define KLE_BAD_FIELD           (((uint64_t)6)<<32)
#define KLE_BAD_PC              (((uint64_t)7)<<32)
#define KLE_BAD_RA              (((uint64_t)8)<<32)
#define KLE_BAD_SP              (((uint64_t)9)<<32)
#define KLE_BAD_EP              (((uint64_t)10)<<32)
#define KLE_BAD_SADDR           (((uint64_t)11)<<32)
#define KLE_BAD_KERNELSTACK     (((uint64_t)12)<<32)
#define KLE_BAD_LINENO          (((uint64_t)13)<<32)
#define KLE_MAP_FILE          	(((uint64_t)14)<<32)
#define KLE_DUMP          	(((uint64_t)15)<<32)
#define KLE_BAD_STRING          (((uint64_t)16)<<32)

#endif /* __KL_ERROR_H */

