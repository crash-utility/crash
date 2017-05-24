/* 
 * xendump.h
 *
 * Copyright (C) 2006, 2007, 2009, 2010, 2014 David Anderson
 * Copyright (C) 2006, 2007, 2009, 2010, 2014 Red Hat, Inc. All rights reserved.
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
#include <endian.h>
#include <elf.h>

#define XC_SAVE_SIGNATURE  "LinuxGuestRecord"
#define XC_CORE_MAGIC      0xF00FEBED
#define XC_CORE_MAGIC_HVM  0xF00FEBEE

/*
 *  From xenctrl.h, but probably not on most host machines.
 */
typedef struct xc_core_header {
    unsigned int xch_magic;
    unsigned int xch_nr_vcpus;
    unsigned int xch_nr_pages;
    unsigned int xch_ctxt_offset;
    unsigned int xch_index_offset;
    unsigned int xch_pages_offset;
} xc_core_header_t;

/*
 *  Based upon the original xensource xc_core_header struct above, 
 *  but with unsigned long offset values so that it can be used
 *  with the original dumpfile format and new ELF-style format.
 */
struct xen_core_header {
    unsigned int xch_magic;
    unsigned int xch_nr_vcpus;
    unsigned int xch_nr_pages;
    off_t xch_ctxt_offset;
    off_t xch_index_offset;
    off_t xch_pages_offset;
};

struct pfn_offset_cache {
	off_t file_offset;
	ulong pfn;
	ulong cnt;
};
#define PFN_TO_OFFSET_CACHE_ENTRIES  (5000)

struct elf_index_pfn {
	ulong index;
	ulong pfn;
};
#define INDEX_PFN_COUNT (128)

struct last_batch {
	ulong index;
	ulong start;
	ulong end;
	ulong accesses;
	ulong duplicates; 
};

struct xendump_data {
        ulong flags;       /* XENDUMP_LOCAL, plus anything else... */
	int xfd;
	int pc_next;
	uint page_size;
	FILE *ofp;
	char *page;
	ulong accesses;
	ulong cache_hits;
	ulong redundant;
	ulong last_pfn;
	struct pfn_offset_cache *poc;

	struct xc_core_data {
		int p2m_frames;
		ulong *p2m_frame_index_list;
		struct xen_core_header header;
		int elf_class;
		uint64_t format_version;
		off_t elf_strtab_offset;
		off_t shared_info_offset;
		off_t ia64_mapped_regs_offset;
		struct elf_index_pfn elf_index_pfn[INDEX_PFN_COUNT];
		struct last_batch last_batch;
		Elf32_Ehdr *elf32;
		Elf64_Ehdr *elf64;
	} xc_core;

	struct xc_save_data {
		ulong nr_pfns;
		int vmconfig_size;
		char *vmconfig_buf;
		ulong *p2m_frame_list;
		uint pfns_not;
		off_t pfns_not_offset;
		off_t vcpu_ctxt_offset;
		off_t shared_info_page_offset;
		off_t *batch_offsets;
		ulong batch_count;
		ulong *region_pfn_type;
		ulong ia64_version;
		ulong *ia64_page_offsets;
	} xc_save;

	ulong panic_pc;
	ulong panic_sp;
};

#define XC_SAVE            (XENDUMP_LOCAL << 1)
#define XC_CORE_ORIG       (XENDUMP_LOCAL << 2)
#define XC_CORE_P2M_CREATE (XENDUMP_LOCAL << 3)
#define XC_CORE_PFN_CREATE (XENDUMP_LOCAL << 4)
#define XC_CORE_NO_P2M     (XENDUMP_LOCAL << 5)
#define XC_SAVE_IA64       (XENDUMP_LOCAL << 6)
#define XC_CORE_64BIT_HOST (XENDUMP_LOCAL << 7)
#define XC_CORE_ELF        (XENDUMP_LOCAL << 8)

#define MACHINE_BYTE_ORDER()  \
        (machine_type("X86") || \
         machine_type("X86_64") || \
         machine_type("IA64") ? __LITTLE_ENDIAN : __BIG_ENDIAN)

#define BYTE_SWAP_REQUIRED(endian) (endian != MACHINE_BYTE_ORDER())

static inline uint32_t
swab32(uint32_t x)
{
        return (((x & 0x000000ffU) << 24) |
                ((x & 0x0000ff00U) <<  8) |
                ((x & 0x00ff0000U) >>  8) |
                ((x & 0xff000000U) >> 24));
}

#define MFN_NOT_FOUND (-1)
#define PFN_NOT_FOUND (-1)

#define INVALID_MFN (~0UL)

/*
 *  ia64 "xm save" format is completely different than the others.
 */
typedef struct xen_domctl_arch_setup {
    uint64_t flags;      /* XEN_DOMAINSETUP_* */
/* #ifdef __ia64__ */
    uint64_t bp;            /* mpaddr of boot param area */
    uint64_t maxmem;        /* Highest memory address for MDT.  */
    uint64_t xsi_va;        /* Xen shared_info area virtual address.  */
    uint32_t hypercall_imm; /* Break imm for Xen hypercalls.  */
/* #endif */
} xen_domctl_arch_setup_t;

/*
 *  xc_core ELF note, which differs from the standard Elf[32|64]_Nhdr
 *  structure by the additional name field.
 */
struct elfnote {
	uint32_t namesz; 
	uint32_t descsz;
	uint32_t type;
	char name[4]; 
};

#define XEN_ELFNOTE_DUMPCORE_NONE            0x2000000
#define XEN_ELFNOTE_DUMPCORE_HEADER          0x2000001
#define XEN_ELFNOTE_DUMPCORE_XEN_VERSION     0x2000002
#define XEN_ELFNOTE_DUMPCORE_FORMAT_VERSION  0x2000003

struct xen_dumpcore_elfnote_header_desc {
	uint64_t xch_magic;
	uint64_t xch_nr_vcpus;
	uint64_t xch_nr_pages;
	uint64_t xch_page_size;
}; 

#define FORMAT_VERSION_0000000000000001 0x0000000000000001ULL

struct xen_dumpcore_elfnote_format_version_desc {
	uint64_t version;
}; 

struct xen_dumpcore_p2m {
	uint64_t pfn;
	uint64_t gmfn; 
};

extern struct xendump_data *xd;
