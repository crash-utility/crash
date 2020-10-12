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

#define VMW_GPREGS_SIZE (128)
#define VMW_CR64_SIZE (72)
#define VMW_IDTR_SIZE (10)
struct vmssregs64 {
	/* read from vmss */
	uint64_t	rax;
	uint64_t	rcx;
	uint64_t	rdx;
	uint64_t	rbx;
	uint64_t	rbp;
	uint64_t	rsp;
	uint64_t	rsi;
	uint64_t	rdi;
	uint64_t	r8;
	uint64_t	r9;
	uint64_t	r10;
	uint64_t	r11;
	uint64_t	r12;
	uint64_t	r13;
	uint64_t	r14;
	uint64_t	r15;
	/* manually managed */
	uint64_t	idtr;
	uint64_t	cr[VMW_CR64_SIZE / 8];
	uint64_t	rip;
	uint64_t	rflags;
};
typedef struct vmssregs64 vmssregs64;

#define REGS_PRESENT_RAX    1<<0
#define REGS_PRESENT_RCX    1<<1
#define REGS_PRESENT_RDX    1<<2
#define REGS_PRESENT_RBX    1<<3
#define REGS_PRESENT_RBP    1<<4
#define REGS_PRESENT_RSP    1<<5
#define REGS_PRESENT_RSI    1<<6
#define REGS_PRESENT_RDI    1<<7
#define REGS_PRESENT_R8     1<<8
#define REGS_PRESENT_R9     1<<9
#define REGS_PRESENT_R10    1<<10
#define REGS_PRESENT_R11    1<<11
#define REGS_PRESENT_R12    1<<12
#define REGS_PRESENT_R13    1<<13
#define REGS_PRESENT_R14    1<<14
#define REGS_PRESENT_R15    1<<15
#define REGS_PRESENT_IDTR   1<<16
#define REGS_PRESENT_CR0    1<<17
#define REGS_PRESENT_CR1    1<<18
#define REGS_PRESENT_CR2    1<<19
#define REGS_PRESENT_CR3    1<<20
#define REGS_PRESENT_CR4    1<<21
#define REGS_PRESENT_RIP    1<<22
#define REGS_PRESENT_RFLAGS 1<<23
#define REGS_PRESENT_GPREGS 65535
#define REGS_PRESENT_CRS    4063232
#define REGS_PRESENT_ALL    16777215

#define MAX_REGIONS	3
struct vmssdata {
	int32_t	cpt64bit;
	FILE	*dfp;
	char	*filename;
	/* about the memory */
	uint32_t	alignmask;
	uint32_t	regionscount;
        memregion	regions[MAX_REGIONS];
	uint64_t	memoffset;
	uint64_t	memsize;
	ulong		phys_base;
	int		separate_vmem;
	uint32_t	*vcpu_regs;
	uint64_t	num_vcpus;
	vmssregs64	**regs64;
};
typedef struct vmssdata vmssdata;

/* VMware only supports X86/X86_64 virtual machines. */
#define VMW_PAGE_SIZE (4096)
#define VMW_PAGE_SHIFT (12)

#define MAX_BLOCK_DUMP (128)

extern vmssdata vmss;

#define DEBUG_PARSE_PRINT(x)		\
do {					\
	if (CRASHDEBUG(1)) {		\
		fprintf x;		\
	}				\
} while(0)

