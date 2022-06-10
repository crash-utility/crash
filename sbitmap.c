/* sbitmap.c
 *
 * Copyright (C) 2022 YADRO. All rights reserved
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

#include "defs.h"

#define SBQ_WAIT_QUEUES 8

/* sbitmap_queue struct context */
struct sbitmap_queue_context {
	ulong sb_addr;
	ulong alloc_hint;
	unsigned int wake_batch;
	int wake_index;
	ulong ws_addr;
	int ws_active;
	bool round_robin;
	unsigned int min_shallow_depth;

};

struct sbitmapq_data {
#define SBITMAPQ_DATA_FLAG_STRUCT_NAME    (VERBOSE << 1)
#define SBITMAPQ_DATA_FLAG_STRUCT_MEMBER  (VERBOSE << 2)
#define SBITMAPQ_DATA_FLAG_ARRAY_ADDR     (VERBOSE << 3)
#define SBITMAPQ_DATA_FLAG_ARRAY_OF_POINTS (VERBOSE << 4)
	ulong flags;
	int radix;
	/* sbitmap_queue info */
	ulong addr;
	/* data array info */
	ulong data_addr;
	char *data_name;
	int data_size;
};

#define SB_FLAG_INIT   0x01

static uint sb_flags = 0;


#define BIT(nr)			(1UL << (nr))

static inline unsigned long min(unsigned long a, unsigned long b)
{
	return (a < b) ? a : b;
}

static unsigned long __last_word_mask(unsigned long nbits)
{
	return ~0UL >> (-(nbits) & (BITS_PER_LONG - 1));
}

static unsigned long bitmap_hweight_long(unsigned long w)
{
	return sizeof(w) == 4 ? hweight32(w) : hweight64(w);
}

static unsigned long bitmap_weight(unsigned long bitmap, unsigned int bits)
{
	unsigned long w = 0;

	w += bitmap_hweight_long(bitmap);
	if (bits % BITS_PER_LONG)
		w += bitmap_hweight_long(bitmap & __last_word_mask(bits));

	return w;
}

static inline unsigned int __map_depth(const struct sbitmap_context *sc, int index)
{
       if (index == sc->map_nr - 1)
               return sc->depth - (index << sc->shift);
       return 1U << sc->shift;
}

static unsigned int __sbitmap_weight(const struct sbitmap_context *sc, bool set)
{
	const ulong sbitmap_word_size = SIZE(sbitmap_word);
	const ulong w_word_off = OFFSET(sbitmap_word_word);

	unsigned int weight = 0;
	ulong addr = sc->map_addr;
	ulong depth, word, cleared;
	char *sbitmap_word_buf;
	int i;

	sbitmap_word_buf = GETBUF(sbitmap_word_size);

	for (i = 0; i < sc->map_nr; i++) {
		if (!readmem(addr, KVADDR, sbitmap_word_buf, sbitmap_word_size, "sbitmap_word", RETURN_ON_ERROR)) {
			FREEBUF(sbitmap_word_buf);
			error(FATAL, "cannot read sbitmap_word\n");
		}

		depth = __map_depth(sc, i);

		if (set) {
			word = ULONG(sbitmap_word_buf + w_word_off);
			weight += bitmap_weight(word, depth);
		} else {
			if (VALID_MEMBER(sbitmap_word_cleared))
				cleared = ULONG(sbitmap_word_buf + OFFSET(sbitmap_word_cleared));
			else
				cleared = 0;
			weight += bitmap_weight(cleared, depth);
		}

		addr += sbitmap_word_size;
	}

	FREEBUF(sbitmap_word_buf);

	return weight;
}

static unsigned int sbitmap_weight(const struct sbitmap_context *sc)
{
	return __sbitmap_weight(sc, true);
}

static unsigned int sbitmap_cleared(const struct sbitmap_context *sc)
{
	if (VALID_MEMBER(sbitmap_word_cleared)) /* 5.0 and later */
		return __sbitmap_weight(sc, false);

	return 0;
}

static void sbitmap_emit_byte(unsigned int offset, uint8_t byte)
{
	if ((offset &0xf) == 0) {
		if (offset != 0)
			fputc('\n', fp);
		fprintf(fp, "%08x:", offset);
	}
	if ((offset & 0x1) == 0)
		fputc(' ', fp);
	fprintf(fp, "%02x", byte);
}

static void sbitmap_bitmap_show(const struct sbitmap_context *sc)
{
	const ulong sbitmap_word_size = SIZE(sbitmap_word);
	const ulong w_word_off = OFFSET(sbitmap_word_word);

	uint8_t byte = 0;
	unsigned int byte_bits = 0;
	unsigned int offset = 0;
	ulong addr = sc->map_addr;
	char *sbitmap_word_buf;
	int i;

	sbitmap_word_buf = GETBUF(sbitmap_word_size);

	for (i = 0; i < sc->map_nr; i++) {
		unsigned long word, cleared, word_bits;

		if (!readmem(addr, KVADDR, sbitmap_word_buf, sbitmap_word_size, "sbitmap_word", RETURN_ON_ERROR)) {
			FREEBUF(sbitmap_word_buf);
			error(FATAL, "cannot read sbitmap_word\n");
		}

		word = ULONG(sbitmap_word_buf + w_word_off);
		if (VALID_MEMBER(sbitmap_word_cleared))
			cleared = ULONG(sbitmap_word_buf + OFFSET(sbitmap_word_cleared));
		else
			cleared = 0;
		word_bits = __map_depth(sc, i);

		word &= ~cleared;

		while (word_bits > 0) {
			unsigned int bits = min(8 - byte_bits, word_bits);

			byte |= (word & (BIT(bits) - 1)) << byte_bits;
			byte_bits += bits;
			if (byte_bits == 8) {
				sbitmap_emit_byte(offset, byte);
				byte = 0;
				byte_bits = 0;
				offset++;
			}
			word >>= bits;
			word_bits -= bits;
		}

		addr += sbitmap_word_size;
	}
	if (byte_bits) {
		sbitmap_emit_byte(offset, byte);
		offset++;
	}
	if (offset)
		fputc('\n', fp);

	FREEBUF(sbitmap_word_buf);
}

static unsigned long sbitmap_find_next_bit(unsigned long word,
		unsigned long size, unsigned long offset)
{
	if (size > BITS_PER_LONG)
		error(FATAL, "%s: word size isn't correct\n", __func__);

	for (; offset < size; offset++)
		if (word & (1UL << offset))
			return offset;

	return size;
}

static void __sbitmap_for_each_set(const struct sbitmap_context *sc,
		unsigned int start, sbitmap_for_each_fn fn, void *data)
{
	const ulong sbitmap_word_size = SIZE(sbitmap_word);
	const ulong w_word_off = OFFSET(sbitmap_word_word);

	unsigned int index;
	unsigned int nr;
	unsigned int scanned = 0;
	char *sbitmap_word_buf;

	sbitmap_word_buf = GETBUF(sbitmap_word_size);

	if (start >= sc->map_nr)
		start = 0;

	index = start >> sc->shift;
	nr = start & ((1U << sc->shift) - 1U);

	while (scanned < sc->depth) {
		unsigned long w_addr = sc->map_addr + (sbitmap_word_size * index);
		unsigned long w_word, w_cleared;
		unsigned long word, depth;

		if (!readmem(w_addr, KVADDR, sbitmap_word_buf, sbitmap_word_size, "sbitmap_word", RETURN_ON_ERROR)) {
			FREEBUF(sbitmap_word_buf);
			error(FATAL, "cannot read sbitmap_word\n");
		}

		w_word = ULONG(sbitmap_word_buf + w_word_off);
		if (VALID_MEMBER(sbitmap_word_cleared))
			w_cleared = ULONG(sbitmap_word_buf + OFFSET(sbitmap_word_cleared));
		else
			w_cleared = 0;

		depth = min(__map_depth(sc, index) - nr, sc->depth - scanned);

		scanned += depth;
		word = w_word & ~w_cleared;
		if (!word)
			goto next;

		/*
		 * On the first iteration of the outer loop, we need to add the
		 * bit offset back to the size of the word for find_next_bit().
		 * On all other iterations, nr is zero, so this is a noop.
		 */
		depth += nr;
		while (1) {
			nr = sbitmap_find_next_bit(word, depth, nr);
			if (nr >= depth)
				break;
			if (!fn((index << sc->shift) + nr, data))
				goto exit;

			nr++;
		}
next:
		nr = 0;
		if (++index >= sc->map_nr)
			index = 0;
	}

exit:
	FREEBUF(sbitmap_word_buf);
}

void sbitmap_for_each_set(const struct sbitmap_context *sc,
		sbitmap_for_each_fn fn, void *data)
{
	__sbitmap_for_each_set(sc, 0, fn, data);
}

static void sbitmap_queue_show(const struct sbitmap_queue_context *sqc,
		const struct sbitmap_context *sc)
{
	ulong alloc_hint_addr = 0;
	int cpus = get_cpus_possible();
	int sbq_wait_state_size, wait_cnt_off, wait_off, list_head_off;
	char *sbq_wait_state_buf;
	bool first;
	int i;

	fprintf(fp, "depth = %u\n", sc->depth);
	fprintf(fp, "busy = %u\n", sbitmap_weight(sc) - sbitmap_cleared(sc));
	if (VALID_MEMBER(sbitmap_word_cleared)) /* 5.0 and later */
		fprintf(fp, "cleared = %u\n", sbitmap_cleared(sc));
	fprintf(fp, "bits_per_word = %u\n", 1U << sc->shift);
	fprintf(fp, "map_nr = %u\n", sc->map_nr);

	if (VALID_MEMBER(sbitmap_queue_alloc_hint))
		alloc_hint_addr = sqc->alloc_hint;
	else if (VALID_MEMBER(sbitmap_alloc_hint)) /* 5.13 and later */
		alloc_hint_addr = sc->alloc_hint;

	fputs("alloc_hint = {", fp);
	first = true;
	for (i = 0; i < cpus; i++) {
		ulong ptr;
		int val;

		if (!first)
			fprintf(fp, ", ");
		first = false;

		ptr = kt->__per_cpu_offset[i] + alloc_hint_addr;
		readmem(ptr, KVADDR, &val, sizeof(val), "alloc_hint", FAULT_ON_ERROR);

		fprintf(fp, "%u", val);
	}
	fputs("}\n", fp);

	fprintf(fp, "wake_batch = %u\n", sqc->wake_batch);
	fprintf(fp, "wake_index = %d\n", sqc->wake_index);
	if (VALID_MEMBER(sbitmap_queue_ws_active)) /* 5.0 and later */
		fprintf(fp, "ws_active = %d\n", sqc->ws_active);

	sbq_wait_state_size = SIZE(sbq_wait_state);
	wait_cnt_off = OFFSET(sbq_wait_state_wait_cnt);
	wait_off = OFFSET(sbq_wait_state_wait);
	if (VALID_MEMBER(wait_queue_head_head)) /* 4.13 and later */
		list_head_off = OFFSET(wait_queue_head_head);
	else
		list_head_off = OFFSET(__wait_queue_head_task_list);

	sbq_wait_state_buf = GETBUF(sbq_wait_state_size);

	fputs("ws = {\n", fp);
	for (i = 0; i < SBQ_WAIT_QUEUES; i++) {
		ulong ws_addr = sqc->ws_addr + (sbq_wait_state_size * i);
		struct kernel_list_head *lh;
		ulong wait_cnt;

		if (!readmem(ws_addr, KVADDR, sbq_wait_state_buf, sbq_wait_state_size, "sbq_wait_state", RETURN_ON_ERROR)) {
			FREEBUF(sbq_wait_state_buf);
			error(FATAL, "cannot read sbq_wait_state\n");
		}

		wait_cnt = INT(sbq_wait_state_buf + wait_cnt_off);
		lh = (struct kernel_list_head *)(sbq_wait_state_buf + wait_off + list_head_off);

		fprintf(fp, "\t{ .wait_cnt = %lu, .wait = %s },\n",
			wait_cnt, (lh->next == lh->prev) ? "inactive" : "active");
	}
	fputs("}\n", fp);

	FREEBUF(sbq_wait_state_buf);

	if (VALID_MEMBER(sbitmap_queue_round_robin))
		fprintf(fp, "round_robin = %d\n", sqc->round_robin);
	else if (VALID_MEMBER(sbitmap_round_robin)) /* 5.13 and later */
		fprintf(fp, "round_robin = %d\n", sc->round_robin);

	if (VALID_MEMBER(sbitmap_queue_min_shallow_depth)) /* 4.18 and later */
		fprintf(fp, "min_shallow_depth = %u\n", sqc->min_shallow_depth);
}

static void sbitmap_queue_context_load(ulong addr, struct sbitmap_queue_context *sqc)
{
	char *sbitmap_queue_buf;

	sqc->sb_addr = addr + OFFSET(sbitmap_queue_sb);

	sbitmap_queue_buf = GETBUF(SIZE(sbitmap_queue));
	if (!readmem(addr, KVADDR, sbitmap_queue_buf, SIZE(sbitmap_queue), "sbitmap_queue", RETURN_ON_ERROR)) {
		FREEBUF(sbitmap_queue_buf);
		error(FATAL, "cannot read sbitmap_queue\n");
	}

	if (VALID_MEMBER(sbitmap_queue_alloc_hint))
		sqc->alloc_hint = ULONG(sbitmap_queue_buf + OFFSET(sbitmap_queue_alloc_hint));
	sqc->wake_batch = UINT(sbitmap_queue_buf + OFFSET(sbitmap_queue_wake_batch));
	sqc->wake_index = INT(sbitmap_queue_buf + OFFSET(sbitmap_queue_wake_index));
	sqc->ws_addr = ULONG(sbitmap_queue_buf + OFFSET(sbitmap_queue_ws));
	if (VALID_MEMBER(sbitmap_queue_ws_active))
		sqc->ws_active = INT(sbitmap_queue_buf + OFFSET(sbitmap_queue_ws_active));
	if (VALID_MEMBER(sbitmap_queue_round_robin))
		sqc->round_robin = BOOL(sbitmap_queue_buf + OFFSET(sbitmap_queue_round_robin));
	if (VALID_MEMBER(sbitmap_queue_min_shallow_depth))
		sqc->min_shallow_depth = UINT(sbitmap_queue_buf + OFFSET(sbitmap_queue_min_shallow_depth));

	FREEBUF(sbitmap_queue_buf);
}

void sbitmap_context_load(ulong addr, struct sbitmap_context *sc)
{
	char *sbitmap_buf;

	sbitmap_buf = GETBUF(SIZE(sbitmap));
	if (!readmem(addr, KVADDR, sbitmap_buf, SIZE(sbitmap), "sbitmap", RETURN_ON_ERROR)) {
		FREEBUF(sbitmap_buf);
		error(FATAL, "cannot read sbitmap\n");
	}

	sc->depth = UINT(sbitmap_buf + OFFSET(sbitmap_depth));
	sc->shift = UINT(sbitmap_buf + OFFSET(sbitmap_shift));
	sc->map_nr = UINT(sbitmap_buf + OFFSET(sbitmap_map_nr));
	sc->map_addr = ULONG(sbitmap_buf + OFFSET(sbitmap_map));
	if (VALID_MEMBER(sbitmap_alloc_hint))
		sc->alloc_hint = ULONG(sbitmap_buf + OFFSET(sbitmap_alloc_hint));
	if (VALID_MEMBER(sbitmap_round_robin))
		sc->round_robin = BOOL(sbitmap_buf + OFFSET(sbitmap_round_robin));

	FREEBUF(sbitmap_buf);
}

static bool for_each_func(unsigned int idx, void *p)
{
	struct sbitmapq_ops *ops = p;
	ulong addr = ops->addr + (ops->size * idx);

	return ops->fn(idx, addr, ops->p);
}

void sbitmapq_for_each_set(ulong addr, struct sbitmapq_ops *ops)
{
	struct sbitmap_queue_context sqc = {0};
	struct sbitmap_context sc = {0};

	sbitmap_queue_context_load(addr, &sqc);
	sbitmap_context_load(sqc.sb_addr, &sc);

	sbitmap_for_each_set(&sc, for_each_func, ops);
}

static void dump_struct_members(const char *s, ulong addr, unsigned radix)
{
	int i, argc;
	char *p1, *p2;
	char *structname, *members;
	char *arglist[MAXARGS];

	structname = GETBUF(strlen(s) + 1);
	members = GETBUF(strlen(s) + 1);

	strcpy(structname, s);
	p1 = strstr(structname, ".") + 1;

	p2 = strstr(s, ".") + 1;
	strcpy(members, p2);
	replace_string(members, ",", ' ');
	argc = parse_line(members, arglist);

	for (i = 0; i < argc; i++) {
		*p1 = NULLCHAR;
		strcat(structname, arglist[i]);
		dump_struct_member(structname, addr, radix);
	}

	FREEBUF(structname);
	FREEBUF(members);
}

static bool sbitmap_data_print(unsigned int idx, ulong addr, void *p)
{
	const struct sbitmapq_data *sd = p;
	bool verbose = !!(sd->flags & VERBOSE);
	bool members = !!(sd->flags & SBITMAPQ_DATA_FLAG_STRUCT_MEMBER);
	bool points = !!(sd->flags & SBITMAPQ_DATA_FLAG_ARRAY_OF_POINTS);

	if (verbose) {
		fprintf(fp, "%d (0x%08lx):\n", idx, addr);

		if (points) {
			ulong p_addr;

			if (!readmem(addr, KVADDR, &p_addr, sizeof(void *),
					"read point of data", RETURN_ON_ERROR)) {
				error(INFO, "Failed to read the point of data: 0x%08lx\n", addr);
				return false;
			}
			addr = p_addr;
		}

		if (members)
			dump_struct_members(sd->data_name, addr, sd->radix);
		else
			dump_struct(sd->data_name, addr, sd->radix);
	} else
		fprintf(fp, "%d: 0x%08lx\n", idx, addr);

	return true;
}

static void sbitmap_queue_data_dump(struct sbitmapq_data *sd)
{
	struct sbitmapq_ops ops = {
		.addr = sd->data_addr,
		.size = (sd->flags & SBITMAPQ_DATA_FLAG_ARRAY_OF_POINTS) ? sizeof(void *) : sd->data_size,
		.fn = sbitmap_data_print,
		.p = sd
	};

	sbitmapq_for_each_set(sd->addr, &ops);
}

static void sbitmap_queue_dump(const struct sbitmapq_data *sd)
{
	struct sbitmap_queue_context sqc ={0};
	struct sbitmap_context sc = {0};

	sbitmap_queue_context_load(sd->addr, &sqc);
	sbitmap_context_load(sqc.sb_addr, &sc);

	sbitmap_queue_show(&sqc, &sc);
	fputc('\n', fp);
	sbitmap_bitmap_show(&sc);
}

void sbitmapq_init(void)
{
	if (sb_flags & SB_FLAG_INIT)
		return;

	STRUCT_SIZE_INIT(sbitmap_word, "sbitmap_word");
	STRUCT_SIZE_INIT(sbitmap, "sbitmap");
	STRUCT_SIZE_INIT(sbitmap_queue, "sbitmap_queue");
	STRUCT_SIZE_INIT(sbq_wait_state, "sbq_wait_state");

	/* sbitmap was abstracted out by commit 88459642cba4 on Linux 4.9. */
	if (INVALID_SIZE(sbitmap))
		command_not_supported();

	MEMBER_OFFSET_INIT(sbitmap_word_depth, "sbitmap_word", "depth");
	MEMBER_OFFSET_INIT(sbitmap_word_word, "sbitmap_word", "word");
	MEMBER_OFFSET_INIT(sbitmap_word_cleared, "sbitmap_word", "cleared");

	MEMBER_OFFSET_INIT(sbitmap_depth, "sbitmap", "depth");
	MEMBER_OFFSET_INIT(sbitmap_shift, "sbitmap", "shift");
	MEMBER_OFFSET_INIT(sbitmap_map_nr, "sbitmap", "map_nr");
	MEMBER_OFFSET_INIT(sbitmap_map, "sbitmap", "map");
	MEMBER_OFFSET_INIT(sbitmap_alloc_hint, "sbitmap", "alloc_hint");
	MEMBER_OFFSET_INIT(sbitmap_round_robin, "sbitmap", "round_robin");

	MEMBER_OFFSET_INIT(sbitmap_queue_sb, "sbitmap_queue", "sb");
	MEMBER_OFFSET_INIT(sbitmap_queue_alloc_hint, "sbitmap_queue", "alloc_hint");
	MEMBER_OFFSET_INIT(sbitmap_queue_wake_batch, "sbitmap_queue", "wake_batch");
	MEMBER_OFFSET_INIT(sbitmap_queue_wake_index, "sbitmap_queue", "wake_index");
	MEMBER_OFFSET_INIT(sbitmap_queue_ws, "sbitmap_queue", "ws");
	MEMBER_OFFSET_INIT(sbitmap_queue_ws_active, "sbitmap_queue", "ws_active");
	MEMBER_OFFSET_INIT(sbitmap_queue_round_robin, "sbitmap_queue", "round_robin");
	MEMBER_OFFSET_INIT(sbitmap_queue_min_shallow_depth, "sbitmap_queue", "min_shallow_depth");

	MEMBER_OFFSET_INIT(sbq_wait_state_wait_cnt, "sbq_wait_state", "wait_cnt");
	MEMBER_OFFSET_INIT(sbq_wait_state_wait, "sbq_wait_state", "wait");

	sb_flags |= SB_FLAG_INIT;
}

static char *__get_struct_name(const char *s)
{
	char *name, *p;

	name = GETBUF(strlen(s) + 1);
	strcpy(name, s);

	p = strstr(name, ".");
	*p = NULLCHAR;

	return name;
}

void cmd_sbitmapq(void)
{
	struct sbitmapq_data sd = {0};
	int c;

	while ((c = getopt(argcnt, args, "s:a:pxdv")) != EOF) {
		switch (c) {
		case 's':
			if (sd.flags & SBITMAPQ_DATA_FLAG_STRUCT_NAME)
				error(FATAL, "-s option (%s) already entered\n", sd.data_name);

			sd.data_name = optarg;
			sd.flags |= SBITMAPQ_DATA_FLAG_STRUCT_NAME;

			break;

		case 'a':
			if (sd.flags & SBITMAPQ_DATA_FLAG_ARRAY_ADDR)
				error(FATAL, "-a option (0x%lx) already entered\n", sd.data_addr);
			else if (!IS_A_NUMBER(optarg))
				error(FATAL, "invalid -a option: %s\n", optarg);

			sd.data_addr = htol(optarg, FAULT_ON_ERROR, NULL);
			if (!IS_KVADDR(sd.data_addr))
				error(FATAL, "invalid kernel virtual address: %s\n", optarg);
			sd.flags |= SBITMAPQ_DATA_FLAG_ARRAY_ADDR;

			break;

		case 'p':
			sd.flags |= SBITMAPQ_DATA_FLAG_ARRAY_OF_POINTS;
			break;

		case 'v':
			sd.flags |= VERBOSE;
			break;

		case 'x':
			if (sd.radix == 10)
				error(FATAL, "-d and -x are mutually exclusive\n");
			sd.radix = 16;
			break;

		case 'd':
			if (sd.radix == 16)
				error(FATAL, "-d and -x are mutually exclusive\n");
			sd.radix = 10;
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (!args[optind]) {
		error(INFO, "command argument is required\n");
		cmd_usage(pc->curcmd, SYNOPSIS);
	} else if (args[optind] && args[optind + 1]) {
		error(INFO, "too many arguments\n");
		cmd_usage(pc->curcmd, SYNOPSIS);
	} else if (!IS_A_NUMBER(args[optind])) {
		error(FATAL, "invalid command argument: %s\n", args[optind]);
	}

	sd.addr = htol(args[optind], FAULT_ON_ERROR, NULL);
	if (!IS_KVADDR(sd.addr))
		error(FATAL, "invalid kernel virtual address: %s\n", args[optind]);

	if ((sd.flags & SBITMAPQ_DATA_FLAG_STRUCT_NAME) &&
			!(sd.flags & SBITMAPQ_DATA_FLAG_ARRAY_ADDR)) {
		error(INFO, "-s option requires -a option\n");
		cmd_usage(pc->curcmd, SYNOPSIS);
	} else if ((sd.flags & SBITMAPQ_DATA_FLAG_ARRAY_ADDR) &&
			!(sd.flags & SBITMAPQ_DATA_FLAG_STRUCT_NAME)) {
		error(INFO, "-a option is used with -s option only\n");
		cmd_usage(pc->curcmd, SYNOPSIS);
	}

	if ((sd.flags & SBITMAPQ_DATA_FLAG_ARRAY_OF_POINTS) &&
			!(sd.flags & SBITMAPQ_DATA_FLAG_ARRAY_ADDR)) {
		error(INFO, "-p option requires -a option\n");
		cmd_usage(pc->curcmd, SYNOPSIS);
	}

	if (sd.flags & SBITMAPQ_DATA_FLAG_STRUCT_NAME) {
		if (count_chars(sd.data_name, '.') > 0)
			sd.flags |= SBITMAPQ_DATA_FLAG_STRUCT_MEMBER;

		if (sd.flags & SBITMAPQ_DATA_FLAG_STRUCT_MEMBER) {
			char *data_name = __get_struct_name(sd.data_name);
			sd.data_size = STRUCT_SIZE(data_name);
			FREEBUF(data_name);
		} else
			sd.data_size = STRUCT_SIZE(sd.data_name);

		if (sd.data_size <= 0)
			error(FATAL, "invalid data structure reference: %s\n", sd.data_name);
	}

	sbitmapq_init();

	if (sd.flags & SBITMAPQ_DATA_FLAG_STRUCT_NAME)
		sbitmap_queue_data_dump(&sd);
	else
		sbitmap_queue_dump(&sd);
}
