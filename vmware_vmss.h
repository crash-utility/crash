/*
 * vmware_vmss.h
 *
 * Copyright (c) 2015 VMware, Inc.
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
 * Author: Dyno Hongjun Fu <hfu@vmware.com>
 */

#define CPTDUMP_OLD_MAGIC_NUMBER       0xbed0bed0
#define CPTDUMP_MAGIC_NUMBER           0xbed2bed2
#define CPTDUMP_PARTIAL_MAGIC_NUMBER   0xbed3bed3

#define CPTDUMP_RESTORED_MAGIC_NUMBER  0xbad1bad1
#define CPTDUMP_NORESTORE_MAGIC_NUMBER 0xbad2bad2
/*
 * Poor man's bit fields
 * TAG: | NAMELEN | NINDX | VALSIZE |
 * bits |15      8|7     6|5       0|
 * size |    8    |   2   |    6    |
 */
#define TAG_NAMELEN_MASK   0xFF
#define TAG_NAMELEN_OFFSET    8
#define TAG_NINDX_MASK      0x3
#define TAG_NINDX_OFFSET      6
#define TAG_VALSIZE_MASK   0x3F
#define TAG_VALSIZE_OFFSET    0
#define TAG_SIZE              2

/*
 * The value size has two special values to indicate blocks and compressed
 * blocks.
 */
#define TAG_ISBLOCK TAG_VALSIZE_MASK
#define TAG_ISBLOCK_COMPRESSED (TAG_VALSIZE_MASK-1)

#define MAKE_TAG(_nl, _nidx, _nb) \
        (((_nl)  & TAG_NAMELEN_MASK) << TAG_NAMELEN_OFFSET | \
        ((_nidx) & TAG_NINDX_MASK)   << TAG_NINDX_OFFSET   | \
        ((_nb)   & TAG_VALSIZE_MASK) << TAG_VALSIZE_OFFSET)

#define TAG_NAMELEN(_tag) (((_tag) >> TAG_NAMELEN_OFFSET) & TAG_NAMELEN_MASK)
#define TAG_NINDX(_tag)   (((_tag) >> TAG_NINDX_OFFSET)   & TAG_NINDX_MASK)
#define TAG_VALSIZE(_tag) (((_tag) >> TAG_VALSIZE_OFFSET) & TAG_VALSIZE_MASK)

#define NULL_TAG MAKE_TAG(0, 0, 0)
#define NO_INDEX (-1)

/*
 * TRUE iff it's a (optionally compressed) block
 */
#define IS_BLOCK_TAG(_tag)   (TAG_VALSIZE(_tag) == TAG_ISBLOCK || \
                              TAG_VALSIZE(_tag) == TAG_ISBLOCK_COMPRESSED)

/*
 * TRUE iff it's a compressed block.
 */
#define IS_BLOCK_COMPRESSED_TAG(_tag) (TAG_VALSIZE(_tag) == TAG_ISBLOCK_COMPRESSED)

struct cptdumpheader {
	uint32_t	id;
	uint32_t	version;
	uint32_t	numgroups;
};
typedef struct cptdumpheader	cptdumpheader;


#define MAX_LENGTH	64
struct cptgroupdesc {
	char		name[MAX_LENGTH];
	uint64_t	position;
	uint64_t	size;
};
typedef struct cptgroupdesc	cptgroupdesc;

struct memregion {
   uint32_t startpagenum;
   uint32_t startppn;
   uint32_t size;
};
typedef struct memregion	memregion;

#define MAX_REGIONS	3
struct vmssdata {
	int32_t	cpt64bit;
	FILE	*dfp;
	/* about the memory */
	uint32_t	alignmask;
	uint32_t	regionscount;
        memregion	regions[MAX_REGIONS];
	uint64_t	memoffset;
	uint64_t	memsize;
};
typedef struct vmssdata vmssdata;

#define DEBUG_PARSE_PRINT(x)		\
do {					\
	if (CRASHDEBUG(1)) {		\
		fprintf x;		\
	}				\
} while(0)

