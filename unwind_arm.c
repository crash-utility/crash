/*
 * Stack unwinding support for ARM
 *
 * This code is derived from the kernel source:
 * arch/arm/kernel/unwind.c
 * Copyright (C) 2008 ARM Limited
 *
 * Created by: Mika Westerberg <ext-mika.1.westerberg@nokia.com>
 * Copyright (C) 2010 Nokia Corporation
 *
 * For more information about ARM unwind tables see "Exception handling ABI for
 * the ARM architecture" document at:
 *
 * http://infocenter.arm.com/help/topic/com.arm.doc.subset.swdev.abi/index.html
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

#ifdef ARM

#include "defs.h"

/**
 * struct unwind_idx - index table entry
 * @addr: prel31 offset to the start of the function
 * @insn: index table entry.
 *
 * @insn can be encoded as follows:
 *     1. if bit31 is clear this points to the start of the EHT entry
 *        (prel31 offset)
 *     2. if bit31 is set, this contains the EHT entry itself
 *     3. if 0x1, cannot unwind.
 */
struct unwind_idx {
	ulong	addr;
	ulong	insn;
};

/**
 * struct unwind_table - per-module unwind table
 * @idx: pointer to the star of the unwind table
 * @start: pointer to the start of the index table
 * @end: pointer to the last element +1 of the index table
 * @begin_addr: start address which this table covers
 * @end_addr: end address which this table covers
 * @kv_base: kernel virtual address of the start of the index table
 *
 * Kernel stores per-module unwind tables in this format. There can be more than
 * one table per module as we have different ELF sections in the module.
 */
struct unwind_table {
	struct unwind_idx	*idx;
	struct unwind_idx	*start;
	struct unwind_idx	*end;
	ulong			begin_addr;
	ulong			end_addr;
	ulong			kv_base;
};

/*
 * Unwind table pointers to master kernel table and for modules.
 */
static struct unwind_table	*kernel_unwind_table;
static struct unwind_table	*module_unwind_tables;

struct unwind_ctrl_block {
	ulong	vrs[16];
	ulong	insn;
	ulong	insn_kvaddr;
	int	entries;
	int	byte;
};

struct stackframe {
	ulong	fp;
	ulong	sp;
	ulong	lr;
	ulong	pc;
};

enum regs {
	R7 = 7,
	FP = 11,
	SP = 13,
	LR = 14,
	PC = 15,
};

static int init_kernel_unwind_table(void);
static int read_module_unwind_table(struct unwind_table *, ulong);
static int init_module_unwind_tables(void);
static int unwind_get_insn(struct unwind_ctrl_block *);
static ulong unwind_get_byte(struct unwind_ctrl_block *);
static ulong get_value_from_stack(ulong *);
static int unwind_exec_insn(struct unwind_ctrl_block *);
static int is_core_kernel_text(ulong);
static struct unwind_table *search_table(ulong);
static struct unwind_idx *search_index(const struct unwind_table *, ulong);
static ulong prel31_to_addr(ulong, ulong);
static void index_prel31_to_addr(struct unwind_table *);
static int unwind_frame(struct stackframe *, ulong);

/*
 * Function reads in-memory kernel and module unwind tables and makes
 * local copy of them for unwinding. If unwinding tables cannot be found, this
 * function returns FALSE, otherwise TRUE.
 */
int
init_unwind_tables(void)
{
	if (!symbol_exists("__start_unwind_idx") ||
	    !symbol_exists("__stop_unwind_idx") ||
	    !symbol_exists("__start_unwind_tab") ||
	    !symbol_exists("__stop_unwind_tab") ||
	    !symbol_exists("unwind_tables")) {
		return FALSE;
	}

	if (!init_kernel_unwind_table()) {
		error(WARNING,
		      "UNWIND: failed to initialize kernel unwind table\n");
		return FALSE;
	}

	/*
	 * Initialize symbols for per-module unwind tables. Actually there are
	 * several tables per module (one per code section).
	 */
	STRUCT_SIZE_INIT(unwind_table, "unwind_table");
	MEMBER_OFFSET_INIT(unwind_table_list, "unwind_table", "list");
	MEMBER_OFFSET_INIT(unwind_table_start, "unwind_table", "start");
	MEMBER_OFFSET_INIT(unwind_table_stop, "unwind_table", "stop");
	MEMBER_OFFSET_INIT(unwind_table_begin_addr, "unwind_table",
			   "begin_addr");
	MEMBER_OFFSET_INIT(unwind_table_end_addr, "unwind_table", "end_addr");

	STRUCT_SIZE_INIT(unwind_idx, "unwind_idx");
	MEMBER_OFFSET_INIT(unwind_idx_addr, "unwind_idx", "addr");
	MEMBER_OFFSET_INIT(unwind_idx_insn, "unwind_idx", "insn");

	if (!init_module_unwind_tables()) {
		error(WARNING,
		      "UNWIND: failed to initialize module unwind tables\n");
	}

	/*
	 * We abuse DWARF_UNWIND flag a little here as ARM unwinding tables are
	 * not in DWARF format but we can use the flags to indicate that we have
	 * unwind tables support ready.
	 */
	kt->flags |= DWARF_UNWIND_CAPABLE;
	kt->flags |= DWARF_UNWIND;

	return TRUE;
}

/*
 * Allocate and fill master kernel unwind table.
 */
static int
init_kernel_unwind_table(void)
{
	ulong idx_start, idx_end, idx_size;

	kernel_unwind_table = calloc(sizeof(*kernel_unwind_table), 1);
	if (!kernel_unwind_table)
		return FALSE;

	idx_start = symbol_value("__start_unwind_idx");
	idx_end = symbol_value("__stop_unwind_idx");
	idx_size = idx_end - idx_start;

	kernel_unwind_table->idx = calloc(idx_size, 1);
	if (!kernel_unwind_table->idx)
		goto fail;

	/* now read in the index table */
	if (!readmem(idx_start, KVADDR, kernel_unwind_table->idx, idx_size,
		     "master kernel unwind table", RETURN_ON_ERROR)) {
		free(kernel_unwind_table->idx);
		goto fail;
	}

	/*
	 * Kernel versions before v3.2 (specifically, before commit
	 * de66a979012db "ARM: 7187/1: fix unwinding for XIP kernels")
	 * converted the prel31 offsets in the unwind index table to absolute
	 * addresses on startup.  Newer kernels don't perform this conversion,
	 * and have a slightly more involved search algorithm.
	 *
	 * We always just use the older search method (a straightforward binary
	 * search) and convert the index table offsets ourselves if we detect
	 * that the kernel didn't do it.
	 */
	machdep->machspec->unwind_index_prel31 = !is_kernel_text(kernel_unwind_table->idx[0].addr);

	kernel_unwind_table->start = kernel_unwind_table->idx;
	kernel_unwind_table->end = (struct unwind_idx *)
		((char *)kernel_unwind_table->idx + idx_size);
	kernel_unwind_table->begin_addr = kernel_unwind_table->start->addr;
	kernel_unwind_table->end_addr = (kernel_unwind_table->end - 1)->addr;
	kernel_unwind_table->kv_base = idx_start;

	if (machdep->machspec->unwind_index_prel31)
		index_prel31_to_addr(kernel_unwind_table);

	if (CRASHDEBUG(1)) {
		fprintf(fp, "UNWIND: master kernel table start\n");
		fprintf(fp, "UNWIND: size      : %ld\n", idx_size);
		fprintf(fp, "UNWIND: start     : %p\n", kernel_unwind_table->start);
		fprintf(fp, "UNWIND: end       : %p\n", kernel_unwind_table->end);
		fprintf(fp, "UNWIND: begin_addr: 0x%lx\n",
			kernel_unwind_table->begin_addr);
		fprintf(fp, "UNWIND: begin_addr: 0x%lx\n",
			kernel_unwind_table->end_addr);
		fprintf(fp, "UNWIND: master kernel table end\n");
	}

	return TRUE;

fail:
	free(kernel_unwind_table);
	return FALSE;
}


/*
 * Read single module unwind table from addr.
 */
static int
read_module_unwind_table(struct unwind_table *tbl, ulong addr)
{
	ulong idx_start, idx_stop, idx_size;
	char *buf;

	buf = GETBUF(SIZE(unwind_table));

	/*
	 * First read in the unwind table for this module. It then contains
	 * pointers to the index table which we will read later.
	 */
	if (!readmem(addr, KVADDR, buf, SIZE(unwind_table),
		     "module unwind table", RETURN_ON_ERROR)) {
		error(WARNING, "UNWIND: cannot read unwind table\n");
		goto fail;
	}

#define TABLE_VALUE(b, offs) (*((ulong *)((b) + OFFSET(offs))))

	idx_start = TABLE_VALUE(buf, unwind_table_start);
	idx_stop = TABLE_VALUE(buf, unwind_table_stop);
	idx_size = idx_stop - idx_start;

	/*
	 * We know the size of the index table. Allocate memory for
	 * the table and read the contents from the kernel memory.
	 */
	tbl->idx = calloc(idx_size, 1);
	if (!tbl->idx)
		goto fail;

	if (!readmem(idx_start, KVADDR, tbl->idx, idx_size,
		     "module unwind index table", RETURN_ON_ERROR)) {
		free(tbl->idx);
		goto fail;
	}

	tbl->start = &tbl->idx[0];
	tbl->end = (struct unwind_idx *)((char *)tbl->start + idx_size);
	tbl->begin_addr = TABLE_VALUE(buf, unwind_table_begin_addr);
	tbl->end_addr = TABLE_VALUE(buf, unwind_table_end_addr);
	tbl->kv_base = idx_start;

	if (machdep->machspec->unwind_index_prel31)
		index_prel31_to_addr(tbl);

	if (CRASHDEBUG(1)) {
		fprintf(fp, "UNWIND: module table start\n");
		fprintf(fp, "UNWIND: start     : %p\n", tbl->start);
		fprintf(fp, "UNWIND: end       : %p\n", tbl->end);
		fprintf(fp, "UNWIND: begin_addr: 0x%lx\n", tbl->begin_addr);
		fprintf(fp, "UNWIND: begin_addr: 0x%lx\n", tbl->end_addr);
		fprintf(fp, "UNWIND: module table end\n");
	}

	FREEBUF(buf);
	return TRUE;

fail:
	FREEBUF(buf);
	return FALSE;
}

/*
 * Allocate and fill per-module unwind tables.
 */
static int
init_module_unwind_tables(void)
{
	ulong head = symbol_value("unwind_tables");
	struct unwind_table *tbl;
	struct list_data ld;
	ulong *table_list;
	int cnt, i, n;

	BZERO(&ld, sizeof(ld));
	ld.start = head;
	ld.member_offset = OFFSET(unwind_table_list);
	ld.flags = RETURN_ON_LIST_ERROR;

	if (CRASHDEBUG(1))
		ld.flags |= VERBOSE;

	/*
	 * Iterate through unwind table list and store start address of each
	 * table in table_list.
	 */
	hq_open();
	cnt = do_list(&ld);
	if (cnt == -1) {
		error(WARNING, "UNWIND: failed to gather unwind_table list\n");
		hq_close();
		return FALSE;
	}
	table_list = (ulong *)GETBUF(cnt * sizeof(ulong));
	cnt = retrieve_list(table_list, cnt);
	hq_close();

	module_unwind_tables = calloc(sizeof(struct unwind_table), cnt);
	if (!module_unwind_tables) {
		error(WARNING,
		      "UNWIND: failed to allocate memory for (%d tables)\n",
		      cnt);
		FREEBUF(table_list);
		return FALSE;
	}

	/* we skip the first address as it is just head pointer */
	for (i = 1, n = 0; i < cnt; i++, n++) {
		tbl = &module_unwind_tables[n];
		if (!read_module_unwind_table(tbl, table_list[i]))
			goto fail;
	}

	/* just in case, zero the last entry (again) */
	BZERO(&module_unwind_tables[n], sizeof(module_unwind_tables[n]));

	FREEBUF(table_list);
	return TRUE;

fail:
	FREEBUF(table_list);

	while (--n >= 0) {
		tbl = &module_unwind_tables[n];
		free(tbl->idx);
	}

	free(module_unwind_tables);
	module_unwind_tables = NULL;
	return FALSE;
}

/*
 * Read next unwind instruction pointed by ctrl->insn_kvaddr into
 * ctrl->insn. As a side-effect, increase the ctrl->insn_kvaddr to
 * point to the next instruction.
 */
static int
unwind_get_insn(struct unwind_ctrl_block *ctrl)
{
	if (readmem(ctrl->insn_kvaddr, KVADDR, &ctrl->insn, sizeof(ctrl->insn),
		    "unwind insn", RETURN_ON_ERROR)) {
		ctrl->insn_kvaddr += sizeof(ctrl->insn);
		return TRUE;
	}
	return FALSE;
}

/*
 * Return next insn byte from ctl or 0 in case of failure. As a side-effect,
 * changes ctrl according the next byte.
 */
static ulong
unwind_get_byte(struct unwind_ctrl_block *ctrl)
{
	ulong ret;

	if (ctrl->entries <= 0) {
		error(WARNING, "UNWIND: corrupt unwind entry\n");
		return 0;
	}

	ret = (ctrl->insn >> (ctrl->byte * 8)) & 0xff;

	if (!ctrl->byte && --ctrl->entries > 0) {
		if (!unwind_get_insn(ctrl))
			return 0;
		ctrl->byte = 3;
	} else {
		ctrl->byte--;
	}

	return ret;
}

/*
 * Gets one value from stack pointed by vsp.
 */
static ulong
get_value_from_stack(ulong *vsp)
{
	ulong val;

	/*
	 * We just read the value from kernel memory instead of peeking it from
	 * the bt->stack.
	 */
	if (!readmem((ulong)vsp, KVADDR, &val, sizeof(val),
		"unwind stack value", RETURN_ON_ERROR)) {
		error(FATAL, "unwind: failed to read value from stack\n");
	}

	return val;
}

/*
 * Execute the next unwind instruction.
 */
static int
unwind_exec_insn(struct unwind_ctrl_block *ctrl)
{
	ulong insn = unwind_get_byte(ctrl);

	if ((insn & 0xc0) == 0) {
		/*
		 * 00xx xxxx: vsp = vsp + (xx xxx << 2) + 4
		 *
		 * Note that it seems that there is a typo in the spec and this
		 * is corrected in kernel.
		 */
		ctrl->vrs[SP] += ((insn & 0x3f) << 2) + 4;
	} else if ((insn & 0xc0) == 0x40) {
		/* 00xx xxxx: vsp = vsp + (xx xxx << 2) + 4 */
		ctrl->vrs[SP] -= ((insn & 0x3f) << 2) + 4;
	} else if ((insn & 0xf0) == 0x80) {
		/*
		 * Pop up to 12 integer registers under masks
		 * {r15-r12}, {r11-r4}.
		 */
		ulong mask;
		ulong *vsp = (ulong *)ctrl->vrs[SP];
		int load_sp, reg = 4;

		insn = (insn << 8) | unwind_get_byte(ctrl);
		mask = insn & 0x0fff;
		if (mask == 0) {
			error(WARNING, "UNWIND: refuse to unwind\n");
			return FALSE;
		}

		/* pop {r4-r15} according to mask */
		load_sp = mask & (1 << (13 - 4));
		while (mask) {
			if (mask & 1)
				ctrl->vrs[reg] = get_value_from_stack(vsp++);
			mask >>= 1;
			reg++;
		}
		if (!load_sp)
			ctrl->vrs[SP] = (ulong)vsp;
	} else if ((insn & 0xf0) == 0x90 &&
		   (insn & 0x0d) != 0x0d) {
		/* 1001 nnnn: set vsp = r[nnnn] */
		ctrl->vrs[SP] = ctrl->vrs[insn & 0x0f];
	} else if ((insn & 0xf0) == 0xa0) {
		/*
		 * 1010 0nnn: pop r4-r[4+nnn]
		 * 1010 1nnn: pop r4-r[4+nnn], r14
		 */
		ulong *vsp = (ulong *)ctrl->vrs[SP];
		int reg;

		for (reg = 4; reg <= 4 + (insn & 7); reg++)
			ctrl->vrs[reg] = get_value_from_stack(vsp++);

		if (insn & 0x80)
			ctrl->vrs[14] = get_value_from_stack(vsp++);

		ctrl->vrs[SP] = (ulong)vsp;
	} else if (insn == 0xb0) {
		/* 1011 0000: finish */
		if (ctrl->vrs[PC] == 0)
			ctrl->vrs[PC] = ctrl->vrs[LR];
		/* no further processing */
		ctrl->entries = 0;
	} else if (insn == 0xb1) {
		/* 1011 0001 xxxx yyyy: spare */
		ulong mask = unwind_get_byte(ctrl);
		ulong *vsp = (ulong *)ctrl->vrs[SP];
		int reg = 0;

		if (mask == 0 || mask & 0xf0) {
			error(WARNING, "UNWIND: spare error\n");
			return FALSE;
		}

		/* pop r0-r3 according to mask */
		while (mask) {
			if (mask & 1)
				ctrl->vrs[reg] = get_value_from_stack(vsp++);
			mask >>= 1;
			reg++;
		}
		ctrl->vrs[SP] = (ulong)vsp;
	} else if (insn == 0xb2) {
		/* 1011 0010 uleb128: vsp = vsp + 0x204 (uleb128 << 2) */
		ulong uleb128 = unwind_get_byte(ctrl);

		ctrl->vrs[SP] += 0x204 + (uleb128 << 2);
	} else {
		error(WARNING, "UNWIND: unhandled instruction: %02lx\n", insn);
		return FALSE;
	}

	return TRUE;
}

static int
is_core_kernel_text(ulong pc)
{
	ulong text_start = machdep->machspec->kernel_text_start;
	ulong text_end = machdep->machspec->kernel_text_end;

	if (text_start && text_end)
		return (pc >= text_start && pc <= text_end);

	return FALSE;
}

static struct unwind_table *
search_table(ulong ip)
{
	/*
	 * First check if this address is in the master kernel unwind table or
	 * some of the module unwind tables.
	 */
	if (is_core_kernel_text(ip)) {
		return kernel_unwind_table;
	} else if (module_unwind_tables) {
		struct unwind_table *tbl;

		for (tbl = &module_unwind_tables[0]; tbl->idx; tbl++) {
			if (ip >= tbl->begin_addr && ip < tbl->end_addr)
				return tbl;
		}
	}

	return NULL;
}

static struct unwind_idx *
search_index(const struct unwind_table *tbl, ulong ip)
{
	struct unwind_idx *start = tbl->start;
	struct unwind_idx *end = tbl->end;

	/*
	 * Do a binary search for the addresses in the index table.
	 * Addresses are guaranteed to be sorted in ascending order.
	 */
	while (start < end - 1) {
		struct unwind_idx *mid = start + ((end - start + 1) >> 1);

		if (ip < mid->addr)
			end = mid;
		else
			start = mid;
	}

	return start;
}
/*
 * Convert a prel31 symbol to an absolute kernel virtual address.
 */
static ulong
prel31_to_addr(ulong addr, ulong insn)
{
	/* sign extend to 32 bits */
	long offset = ((long)insn << 1) >> 1;
	return addr + offset;
}

static void
index_prel31_to_addr(struct unwind_table *tbl)
{
	struct unwind_idx *idx = tbl->start;
	ulong kvaddr = tbl->kv_base;

	for (; idx < tbl->end; idx++, kvaddr += sizeof(struct unwind_idx))
		idx->addr = prel31_to_addr(kvaddr, idx->addr);
}

static int
unwind_frame(struct stackframe *frame, ulong stacktop)
{
	const struct unwind_table *tbl;
	struct unwind_ctrl_block ctrl;
	struct unwind_idx *idx;
	ulong low, high;
	int fpindex = FP;

	low = frame->sp;
	high = stacktop;

	if (!is_kernel_text(frame->pc))
		return FALSE;

	/* Thumb needs R7 instead of FP */
	if (frame->pc & 1)
		fpindex = R7;

	tbl = search_table(frame->pc);
	if (!tbl) {
		error(WARNING, "UNWIND: cannot find unwind table for %lx\n",
		      frame->pc);
		return FALSE;
	}
	idx = search_index(tbl, frame->pc);

	ctrl.vrs[fpindex] = frame->fp;
	ctrl.vrs[SP] = frame->sp;
	ctrl.vrs[LR] = frame->lr;
	ctrl.vrs[PC] = 0;

	if (CRASHDEBUG(5)) {
		fprintf(fp, "UNWIND: >frame: FP=%lx\n", ctrl.vrs[fpindex]);
		fprintf(fp, "UNWIND: >frame: SP=%lx\n", ctrl.vrs[SP]);
		fprintf(fp, "UNWIND: >frame: LR=%lx\n", ctrl.vrs[LR]);
		fprintf(fp, "UNWIND: >frame: PC=%lx\n", ctrl.vrs[PC]);
	}

	if (idx->insn == 1) {
		/* can't unwind */
		return FALSE;
	} else if ((idx->insn & 0x80000000) == 0) {
		/* insn contains prel31 offset to the EHT entry */

		/*
		 * Calculate a byte offset for idx->insn from the
		 * start of our copy of the index table. This offset
		 * is used to get a kernel virtual address of the
		 * unwind index entry (idx_kvaddr).
		 */
		ulong idx_offset = (ulong)&idx->insn - (ulong)tbl->start;
		ulong idx_kvaddr = tbl->kv_base + idx_offset;

		/*
		 * Now compute a kernel virtual address for the EHT
		 * entry by adding prel31 offset (idx->insn) to the
		 * unwind index entry address (idx_kvaddr) and read
		 * the EHT entry.
		 */
		ctrl.insn_kvaddr = prel31_to_addr(idx_kvaddr, idx->insn);
		if (!unwind_get_insn(&ctrl))
			return FALSE;
	} else if ((idx->insn & 0xff000000) == 0x80000000) {
		/* EHT entry is encoded in the insn itself */
		ctrl.insn = idx->insn;
	} else {
		error(WARNING, "UNWIND: unsupported instruction %lx\n",
		      idx->insn);
		return FALSE;
	}

	/* check the personality routine */
	if ((ctrl.insn & 0xff000000) == 0x80000000) {
		/* personality routine 0 */
		ctrl.byte = 2;
		ctrl.entries = 1;
	} else if ((ctrl.insn & 0xff000000) == 0x81000000) {
		/* personality routine 1 */
		ctrl.byte = 1;
		ctrl.entries = 1 + ((ctrl.insn & 0x00ff0000) >> 16);
	} else {
		error(WARNING, "UNWIND: unsupported personality routine\n");
		return FALSE;
	}

	/* now, execute the instructions */
	while (ctrl.entries > 0) {
		if (!unwind_exec_insn(&ctrl)) {
			error(WARNING, "UNWIND: failed to exec instruction\n");
			return FALSE;
		}

		if (ctrl.vrs[SP] < low || ctrl.vrs[SP] >= high)
			return FALSE;
	}

	if (ctrl.vrs[PC] == 0)
		ctrl.vrs[PC] = ctrl.vrs[LR];

	if (frame->pc == ctrl.vrs[PC])
		return FALSE;

	frame->fp = ctrl.vrs[fpindex];
	frame->sp = ctrl.vrs[SP];
	frame->lr = ctrl.vrs[LR];
	frame->pc = ctrl.vrs[PC];

	if (CRASHDEBUG(5)) {
		fprintf(fp, "UNWIND: <frame: FP=%lx\n", ctrl.vrs[fpindex]);
		fprintf(fp, "UNWIND: <frame: SP=%lx\n", ctrl.vrs[SP]);
		fprintf(fp, "UNWIND: <frame: LR=%lx\n", ctrl.vrs[LR]);
		fprintf(fp, "UNWIND: <frame: PC=%lx\n", ctrl.vrs[PC]);
	}

	return TRUE;
}

void
unwind_backtrace(struct bt_info *bt)
{
	struct stackframe frame;
	int n = 0;

	BZERO(&frame, sizeof(frame));
	frame.fp = bt->frameptr;
	frame.sp = bt->stkptr;
	frame.pc = bt->instptr;

	/*
	 * In case bt->machdep contains pointer to a full register set, we take
	 * LR from there.
	 */
	if (bt->machdep) {
		const struct arm_pt_regs *regs = bt->machdep;
		frame.fp = regs->ARM_fp;
		frame.lr = regs->ARM_lr;
	}

	while (IS_KVADDR(bt->instptr)) {
		if (!unwind_frame(&frame, bt->stacktop))
			break;

		arm_dump_backtrace_entry(bt, n++, frame.lr, frame.sp);

		bt->instptr = frame.pc;
		bt->stkptr = frame.sp;
	}
}
#endif /* ARM */
