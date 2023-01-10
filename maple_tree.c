// SPDX-License-Identifier: GPL-2.0+
/*
 * Maple Tree implementation
 * Copyright (c) 2018-2022 Oracle Corporation
 * Authors: Liam R. Howlett <Liam.Howlett@oracle.com>
 * 	    Matthew Wilcox <willy@infradead.org>
 *
 * The following are copied and modified from lib/maple_tree.c
 */

#include "maple_tree.h"
#include "defs.h"

unsigned char *mt_slots = NULL;
unsigned char *mt_pivots = NULL;
ulong mt_max[4] = {0};

#define MAPLE_BUFSIZE			512

static inline ulong mte_to_node(ulong maple_enode_entry)
{
	return maple_enode_entry & ~MAPLE_NODE_MASK;
}

static inline enum maple_type mte_node_type(ulong maple_enode_entry)
{
	return (maple_enode_entry >> MAPLE_NODE_TYPE_SHIFT) &
		MAPLE_NODE_TYPE_MASK;
}

static inline ulong mt_slot(void **slots, unsigned char offset)
{
	return (ulong)slots[offset];
}

static inline bool ma_is_leaf(const enum maple_type type)
{
	return type < maple_range_64;
}

/*************** For cmd_tree ********************/

struct do_maple_tree_info {
	ulong maxcount;
	ulong count;
	void *data;
};

struct maple_tree_ops {
	void (*entry)(ulong node, ulong slot, const char *path,
		      ulong index, void *private);
	void *private;
	bool is_td;
};

static const char spaces[] = "                                ";

static void do_mt_range64(ulong, ulong, ulong, uint, char *, ulong *,
			  struct maple_tree_ops *);
static void do_mt_arange64(ulong, ulong, ulong, uint, char *, ulong *,
			   struct maple_tree_ops *);
static void do_mt_entry(ulong, ulong, ulong, uint, uint, char *, ulong *,
			struct maple_tree_ops *);
static void do_mt_node(ulong, ulong, ulong, uint, char *, ulong *,
		       struct maple_tree_ops *);
struct req_entry *fill_member_offsets(char *);
void dump_struct_members_fast(struct req_entry *, int, ulong);
void dump_struct_members_for_tree(struct tree_data *, int, ulong);

static void mt_dump_range(ulong min, ulong max, uint depth)
{
	if (min == max)
		fprintf(fp, "%.*s%lu: ", depth * 2, spaces, min);
	else
		fprintf(fp, "%.*s%lu-%lu: ", depth * 2, spaces, min, max);
}

static inline bool mt_is_reserved(ulong entry)
{
       return (entry < MAPLE_RESERVED_RANGE) && xa_is_internal(entry);
}

static inline bool mte_is_leaf(ulong maple_enode_entry)
{
       return ma_is_leaf(mte_node_type(maple_enode_entry));
}

static uint mt_height(char *mt_buf)
{
	return (UINT(mt_buf + OFFSET(maple_tree_ma_flags)) &
		MT_FLAGS_HEIGHT_MASK)
	       >> MT_FLAGS_HEIGHT_OFFSET;
}

static void dump_mt_range64(char *mr64_buf)
{
	int i;

	fprintf(fp, " contents: ");
	for (i = 0; i < mt_slots[maple_range_64] - 1; i++)
		fprintf(fp, "%p %lu ",
			VOID_PTR(mr64_buf + OFFSET(maple_range_64_slot)
				 + sizeof(void *) * i),
			ULONG(mr64_buf + OFFSET(maple_range_64_pivot)
			      + sizeof(ulong) * i));
	fprintf(fp, "%p\n", VOID_PTR(mr64_buf + OFFSET(maple_range_64_slot)
				     + sizeof(void *) * i));
}

static void dump_mt_arange64(char *ma64_buf)
{
	int i;

	fprintf(fp, " contents: ");
	for (i = 0; i < mt_slots[maple_arange_64]; i++)
		fprintf(fp, "%lu ", ULONG(ma64_buf + OFFSET(maple_arange_64_gap)
					  + sizeof(ulong) * i));

	fprintf(fp, "| %02X %02X| ",
		UCHAR(ma64_buf + OFFSET(maple_arange_64_meta) +
		      OFFSET(maple_metadata_end)),
		UCHAR(ma64_buf + OFFSET(maple_arange_64_meta) +
		      OFFSET(maple_metadata_gap)));

	for (i = 0; i < mt_slots[maple_arange_64] - 1; i++)
		fprintf(fp, "%p %lu ",
			VOID_PTR(ma64_buf + OFFSET(maple_arange_64_slot) +
				 sizeof(void *) * i),
			ULONG(ma64_buf + OFFSET(maple_arange_64_pivot) +
			      sizeof(ulong) * i));
	fprintf(fp, "%p\n", VOID_PTR(ma64_buf + OFFSET(maple_arange_64_slot) +
				     sizeof(void *) * i));
}

static void dump_mt_entry(ulong entry, ulong min, ulong max, uint depth)
{
	mt_dump_range(min, max, depth);

	if (xa_is_value(entry))
		fprintf(fp, "value %ld (0x%lx) [0x%lx]\n", xa_to_value(entry),
			xa_to_value(entry), entry);
	else if (xa_is_zero(entry))
		fprintf(fp, "zero (%ld)\n", xa_to_internal(entry));
	else if (mt_is_reserved(entry))
		fprintf(fp, "UNKNOWN ENTRY (0x%lx)\n", entry);
	else
		fprintf(fp, "0x%lx\n", entry);
}

static void dump_mt_node(ulong maple_node, char *node_data, uint type,
			 ulong min, ulong max, uint depth)
{
	mt_dump_range(min, max, depth);

	fprintf(fp, "node 0x%lx depth %d type %d parent %p",
		maple_node, depth, type,
		maple_node ? VOID_PTR(node_data + OFFSET(maple_node_parent)) :
			     NULL);
}

static void do_mt_range64(ulong entry, ulong min, ulong max,
			  uint depth, char *path, ulong *global_index,
			  struct maple_tree_ops *ops)
{
	ulong maple_node_m_node = mte_to_node(entry);
	char node_buf[MAPLE_BUFSIZE];
	bool leaf = mte_is_leaf(entry);
	ulong first = min, last;
	int i;
	int len = strlen(path);
	struct tree_data *td = ops->is_td ? (struct tree_data *)ops->private : NULL;
	char *mr64_buf;

	if (SIZE(maple_node) > MAPLE_BUFSIZE)
		error(FATAL, "MAPLE_BUFSIZE should be larger than maple_node struct");

	readmem(maple_node_m_node, KVADDR, node_buf, SIZE(maple_node),
		"mt_dump_range64 read maple_node", FAULT_ON_ERROR);

	mr64_buf = node_buf + OFFSET(maple_node_mr64);

	if (td && td->flags & TREE_STRUCT_VERBOSE) {
		dump_mt_range64(mr64_buf);
	}

	for (i = 0; i < mt_slots[maple_range_64]; i++) {
		last = max;

		if (i < (mt_slots[maple_range_64] - 1))
			last = ULONG(mr64_buf + OFFSET(maple_range_64_pivot) +
				     sizeof(ulong) * i);

		else if (!VOID_PTR(mr64_buf + OFFSET(maple_range_64_slot) +
			  sizeof(void *) * i) &&
			 max != mt_max[mte_node_type(entry)])
			break;
		if (last == 0 && i > 0)
			break;
		if (leaf)
			do_mt_entry(mt_slot((void **)(mr64_buf +
						      OFFSET(maple_range_64_slot)), i),
				    first, last, depth + 1, i, path, global_index, ops);
		else if (VOID_PTR(mr64_buf + OFFSET(maple_range_64_slot) +
				  sizeof(void *) * i)) {
			sprintf(path + len, "/%d", i);
			do_mt_node(mt_slot((void **)(mr64_buf +
						     OFFSET(maple_range_64_slot)), i),
				   first, last, depth + 1, path, global_index, ops);
		}

		if (last == max)
			break;
		if (last > max) {
			fprintf(fp, "node %p last (%lu) > max (%lu) at pivot %d!\n",
				mr64_buf, last, max, i);
			break;
		}
		first = last + 1;
	}
}

static void do_mt_arange64(ulong entry, ulong min, ulong max,
			   uint depth, char *path, ulong *global_index,
			   struct maple_tree_ops *ops)
{
	ulong maple_node_m_node = mte_to_node(entry);
	char node_buf[MAPLE_BUFSIZE];
	bool leaf = mte_is_leaf(entry);
	ulong first = min, last;
	int i;
	int len = strlen(path);
	struct tree_data *td = ops->is_td ? (struct tree_data *)ops->private : NULL;
	char *ma64_buf;

	if (SIZE(maple_node) > MAPLE_BUFSIZE)
		error(FATAL, "MAPLE_BUFSIZE should be larger than maple_node struct");

	readmem(maple_node_m_node, KVADDR, node_buf, SIZE(maple_node),
		"mt_dump_arange64 read maple_node", FAULT_ON_ERROR);

	ma64_buf = node_buf + OFFSET(maple_node_ma64);

	if (td && td->flags & TREE_STRUCT_VERBOSE) {
		dump_mt_arange64(ma64_buf);
	}

	for (i = 0; i < mt_slots[maple_arange_64]; i++) {
		last = max;

		if (i < (mt_slots[maple_arange_64] - 1))
			last = ULONG(ma64_buf + OFFSET(maple_arange_64_pivot) +
				     sizeof(ulong) * i);
		else if (!VOID_PTR(ma64_buf + OFFSET(maple_arange_64_slot) +
				   sizeof(void *) * i))
			break;
		if (last == 0 && i > 0)
			break;

		if (leaf)
			do_mt_entry(mt_slot((void **)(ma64_buf +
						      OFFSET(maple_arange_64_slot)), i),
				    first, last, depth + 1, i, path, global_index, ops);
		else if (VOID_PTR(ma64_buf + OFFSET(maple_arange_64_slot) +
				  sizeof(void *) * i)) {
			sprintf(path + len, "/%d", i);
			do_mt_node(mt_slot((void **)(ma64_buf +
						     OFFSET(maple_arange_64_slot)), i),
				   first, last, depth + 1, path, global_index, ops);
		}

		if (last == max)
			break;
		if (last > max) {
			fprintf(fp, "node %p last (%lu) > max (%lu) at pivot %d!\n",
				ma64_buf, last, max, i);
			break;
		}
		first = last + 1;
	}
}

static void do_mt_entry(ulong entry, ulong min, ulong max, uint depth,
			uint index, char *path, ulong *global_index,
			struct maple_tree_ops *ops)
{
	int print_radix = 0, i;
	static struct req_entry **e = NULL;
	struct tree_data *td = ops->is_td ? (struct tree_data *)ops->private : NULL;

	if (ops->entry)
		ops->entry(entry, entry, path, max, ops->private);

	if (!td)
		return;

	if (!td->count && td->structname_args) {
		/*
		 * Retrieve all members' info only once (count == 0)
		 * After last iteration all memory will be freed up
		 */
		e = (struct req_entry **)GETBUF(sizeof(*e) * td->structname_args);
		for (i = 0; i < td->structname_args; i++)
			e[i] = fill_member_offsets(td->structname[i]);
	}

	td->count++;

	if (td->flags & TREE_STRUCT_VERBOSE) {
		dump_mt_entry(entry, min, max, depth);
	} else if (td->flags & VERBOSE && entry)
		fprintf(fp, "%lx\n", entry);
	if (td->flags & TREE_POSITION_DISPLAY && entry)
		fprintf(fp, "  index: %ld  position: %s/%u\n",
			++(*global_index), path, index);

	if (td->structname) {
		if (td->flags & TREE_STRUCT_RADIX_10)
			print_radix = 10;
		else if (td->flags & TREE_STRUCT_RADIX_16)
			print_radix = 16;
		else
			print_radix = 0;

		for (i = 0; i < td->structname_args; i++) {
			switch (count_chars(td->structname[i], '.')) {
			case 0:
				dump_struct(td->structname[i], entry, print_radix);
				break;
			default:
				if (td->flags & TREE_PARSE_MEMBER)
					dump_struct_members_for_tree(td, i, entry);
				else if (td->flags & TREE_READ_MEMBER)
					dump_struct_members_fast(e[i], print_radix, entry);
			}
		}
	}

	if (e)
		FREEBUF(e);
}

static void do_mt_node(ulong entry, ulong min, ulong max,
		       uint depth, char *path, ulong *global_index,
		       struct maple_tree_ops *ops)
{
	ulong maple_node = mte_to_node(entry);
	uint type = mte_node_type(entry);
	uint i;
	char node_buf[MAPLE_BUFSIZE];
	struct tree_data *td = ops->is_td ? (struct tree_data *)ops->private : NULL;

	if (SIZE(maple_node) > MAPLE_BUFSIZE)
		error(FATAL, "MAPLE_BUFSIZE should be larger than maple_node struct");

	readmem(maple_node, KVADDR, node_buf, SIZE(maple_node),
		"mt_dump_node read maple_node", FAULT_ON_ERROR);

	if (td && td->flags & TREE_STRUCT_VERBOSE) {
		dump_mt_node(maple_node, node_buf, type, min, max, depth);
	}

	switch (type) {
	case maple_dense:
		for (i = 0; i < mt_slots[maple_dense]; i++) {
			if (min + i > max)
				fprintf(fp, "OUT OF RANGE: ");
			do_mt_entry(mt_slot((void **)(node_buf + OFFSET(maple_node_slot)), i),
				    min + i, min + i, depth, i, path, global_index, ops);
		}
		break;
	case maple_leaf_64:
	case maple_range_64:
		do_mt_range64(entry, min, max, depth, path, global_index, ops);
		break;
	case maple_arange_64:
		do_mt_arange64(entry, min, max, depth, path, global_index, ops);
		break;
	default:
		fprintf(fp, " UNKNOWN TYPE\n");
	}
}

static int do_maple_tree_traverse(ulong ptr, int is_root,
				  struct maple_tree_ops *ops)
{
	char path[BUFSIZE] = {0};
	char tree_buf[MAPLE_BUFSIZE];
	ulong entry;
	struct tree_data *td = ops->is_td ? (struct tree_data *)ops->private : NULL;
	ulong global_index = 0;

	if (SIZE(maple_tree) > MAPLE_BUFSIZE)
		error(FATAL, "MAPLE_BUFSIZE should be larger than maple_tree struct");

	if (!is_root) {
		strcpy(path, "direct");
		do_mt_node(ptr, 0, mt_max[mte_node_type(ptr)],
			   0, path, &global_index, ops);
	} else {
		readmem(ptr, KVADDR, tree_buf, SIZE(maple_tree),
			"mt_dump read maple_tree", FAULT_ON_ERROR);
		entry = ULONG(tree_buf + OFFSET(maple_tree_ma_root));

		if (td && td->flags & TREE_STRUCT_VERBOSE) {
			fprintf(fp, "maple_tree(%lx) flags %X, height %u root 0x%lx\n\n",
				ptr, UINT(tree_buf + OFFSET(maple_tree_ma_flags)),
				mt_height(tree_buf), entry);
		}

		if (!xa_is_node(entry))
			do_mt_entry(entry, 0, 0, 0, 0, path, &global_index, ops);
		else if (entry) {
			strcpy(path, "root");
			do_mt_node(entry, 0, mt_max[mte_node_type(entry)], 0,
				   path, &global_index, ops);
		}
	}
	return 0;
}

int do_mptree(struct tree_data *td)
{
	struct maple_tree_ops ops = {
		.entry		= NULL,
		.private	= td,
		.is_td		= true,
	};

	int is_root = !(td->flags & TREE_NODE_POINTER);

	do_maple_tree_traverse(td->start, is_root, &ops);

	return 0;
}

/************* For do_maple_tree *****************/
static void do_maple_tree_count(ulong node, ulong slot, const char *path,
				ulong index, void *private)
{
	struct do_maple_tree_info *info = private;
	info->count++;
}

static void do_maple_tree_search(ulong node, ulong slot, const char *path,
				 ulong index, void *private)
{
	struct do_maple_tree_info *info = private;
	struct list_pair *lp = info->data;

	if (lp->index == index) {
		lp->value = (void *)slot;
		info->count = 1;
	}
}

static void do_maple_tree_dump(ulong node, ulong slot, const char *path,
			       ulong index, void *private)
{
	struct do_maple_tree_info *info = private;
	fprintf(fp, "[%lu] %lx\n", index, slot);
	info->count++;
}

static void do_maple_tree_gather(ulong node, ulong slot, const char *path,
				 ulong index, void *private)
{
	struct do_maple_tree_info *info = private;
	struct list_pair *lp = info->data;

	if (info->maxcount) {
		lp[info->count].index = index;
		lp[info->count].value = (void *)slot;

		info->count++;
		info->maxcount--;
	}
}

static void do_maple_tree_dump_cb(ulong node, ulong slot, const char *path,
				  ulong index, void *private)
{
	struct do_maple_tree_info *info = private;
	struct list_pair *lp = info->data;
	int (*cb)(ulong) = lp->value;

	/* Caller defined operation */
	if (!cb(slot)) {
		error(FATAL, "do_maple_tree: callback "
		      "operation failed: entry: %ld  item: %lx\n",
		      info->count, slot);
	}
	info->count++;
}

/*
 *  do_maple_tree argument usage:
 *
 *    root: Address of a maple_tree_root structure
 *
 *    flag: MAPLE_TREE_COUNT - Return the number of entries in the tree.
 *          MAPLE_TREE_SEARCH - Search for an entry at lp->index; if found,
 *            store the entry in lp->value and return a count of 1; otherwise
 *            return a count of 0.
 *          MAPLE_TREE_DUMP - Dump all existing index/value pairs.
 *          MAPLE_TREE_GATHER - Store all existing index/value pairs in the
 *            passed-in array of list_pair structs starting at lp,
 *            returning the count of entries stored; the caller can/should
 *            limit the number of returned entries by putting the array size
 *            (max count) in the lp->index field of the first structure
 *            in the passed-in array.
 *          MAPLE_TREE_DUMP_CB - Similar with MAPLE_TREE_DUMP, but for each
 *            maple tree entry, a user defined callback at lp->value will
 *            be invoked.
 *
 *     lp: Unused by MAPLE_TREE_COUNT and MAPLE_TREE_DUMP.
 *          A pointer to a list_pair structure for MAPLE_TREE_SEARCH.
 *          A pointer to an array of list_pair structures for
 *          MAPLE_TREE_GATHER; the dimension (max count) of the array may
 *          be stored in the index field of the first structure to avoid
 *          any chance of an overrun.
 *          For MAPLE_TREE_DUMP_CB, the lp->value must be initialized as a
 *          callback function.  The callback prototype must be: int (*)(ulong);
 */
ulong
do_maple_tree(ulong root, int flag, struct list_pair *lp)
{
	struct do_maple_tree_info info = {
		.count		= 0,
		.data		= lp,
	};
	struct maple_tree_ops ops = {
		.private	= &info,
		.is_td		= false,
	};

	switch (flag)
	{
	case MAPLE_TREE_COUNT:
		ops.entry = do_maple_tree_count;
		break;

	case MAPLE_TREE_SEARCH:
		ops.entry = do_maple_tree_search;
		break;

	case MAPLE_TREE_DUMP:
		ops.entry = do_maple_tree_dump;
		break;

	case MAPLE_TREE_GATHER:
		if (!(info.maxcount = lp->index))
			info.maxcount = (ulong)(-1);   /* caller beware */

		ops.entry = do_maple_tree_gather;
		break;

	case MAPLE_TREE_DUMP_CB:
		if (lp->value == NULL) {
			error(FATAL, "do_maple_tree: need set callback function");
		}
		ops.entry = do_maple_tree_dump_cb;
		break;

	default:
		error(FATAL, "do_maple_tree: invalid flag: %lx\n", flag);
	}

	do_maple_tree_traverse(root, true, &ops);
	return info.count;
}

/***********************************************/
void maple_init(void)
{
	int array_len;

	STRUCT_SIZE_INIT(maple_tree, "maple_tree");
	STRUCT_SIZE_INIT(maple_node, "maple_node");

	MEMBER_OFFSET_INIT(maple_tree_ma_root, "maple_tree", "ma_root");
	MEMBER_OFFSET_INIT(maple_tree_ma_flags, "maple_tree", "ma_flags");

	MEMBER_OFFSET_INIT(maple_node_parent, "maple_node", "parent");
	MEMBER_OFFSET_INIT(maple_node_ma64, "maple_node", "ma64");
	MEMBER_OFFSET_INIT(maple_node_mr64, "maple_node", "mr64");
	MEMBER_OFFSET_INIT(maple_node_slot, "maple_node", "slot");

	MEMBER_OFFSET_INIT(maple_arange_64_pivot, "maple_arange_64", "pivot");
	MEMBER_OFFSET_INIT(maple_arange_64_slot, "maple_arange_64", "slot");
	MEMBER_OFFSET_INIT(maple_arange_64_gap, "maple_arange_64", "gap");
	MEMBER_OFFSET_INIT(maple_arange_64_meta, "maple_arange_64", "meta");

	MEMBER_OFFSET_INIT(maple_range_64_pivot, "maple_range_64", "pivot");
	MEMBER_OFFSET_INIT(maple_range_64_slot, "maple_range_64", "slot");

	MEMBER_OFFSET_INIT(maple_metadata_end, "maple_metadata", "end");
	MEMBER_OFFSET_INIT(maple_metadata_gap, "maple_metadata", "gap");

	array_len = get_array_length("mt_slots", NULL, sizeof(char));
	mt_slots = calloc(array_len, sizeof(char));
	readmem(symbol_value("mt_slots"), KVADDR, mt_slots,
		array_len * sizeof(char), "maple_init read mt_slots",
		RETURN_ON_ERROR);

	array_len = get_array_length("mt_pivots", NULL, sizeof(char));
	mt_pivots = calloc(array_len, sizeof(char));
	readmem(symbol_value("mt_pivots"), KVADDR, mt_pivots,
		array_len * sizeof(char), "maple_init read mt_pivots",
		RETURN_ON_ERROR);

	mt_max[maple_dense]           = mt_slots[maple_dense];
	mt_max[maple_leaf_64]         = ULONG_MAX;
	mt_max[maple_range_64]        = ULONG_MAX;
	mt_max[maple_arange_64]       = ULONG_MAX;
}
