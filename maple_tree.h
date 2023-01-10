/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef _MAPLE_TREE_H
#define _MAPLE_TREE_H
/*
 * Maple Tree - An RCU-safe adaptive tree for storing ranges
 * Copyright (c) 2018-2022 Oracle
 * Authors:     Liam R. Howlett <Liam.Howlett@Oracle.com>
 *              Matthew Wilcox <willy@infradead.org>
 *
 * eXtensible Arrays
 * Copyright (c) 2017 Microsoft Corporation
 * Author: Matthew Wilcox <willy@infradead.org>
 *
 * See Documentation/core-api/xarray.rst for how to use the XArray.
 */
#include <stdbool.h>
#include <limits.h>
#include <sys/types.h>

/*
 * The following are copied and modified from include/linux/maple_tree.h
 */

enum maple_type {
	maple_dense,
	maple_leaf_64,
	maple_range_64,
	maple_arange_64,
};

#define MAPLE_NODE_MASK		255UL

#define MT_FLAGS_HEIGHT_OFFSET	0x02
#define MT_FLAGS_HEIGHT_MASK	0x7C

#define MAPLE_NODE_TYPE_MASK	0x0F
#define MAPLE_NODE_TYPE_SHIFT	0x03

#define MAPLE_RESERVED_RANGE	4096

/*
 * The following are copied and modified from include/linux/xarray.h
 */

#define XA_ZERO_ENTRY		xa_mk_internal(257)

static inline ulong xa_mk_internal(ulong v)
{
	return (v << 2) | 2;
}

static inline bool xa_is_internal(ulong entry)
{
	return (entry & 3) == 2;
}

static inline bool xa_is_node(ulong entry)
{
	return xa_is_internal(entry) && entry > 4096;
}

static inline bool xa_is_value(ulong entry)
{
	return entry & 1;
}

static inline bool xa_is_zero(ulong entry)
{
	return entry == XA_ZERO_ENTRY;
}

static inline unsigned long xa_to_internal(ulong entry)
{
	return entry >> 2;
}

static inline unsigned long xa_to_value(ulong entry)
{
	return entry >> 1;
}

#endif /* _MAPLE_TREE_H */
