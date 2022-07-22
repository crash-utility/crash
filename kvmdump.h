/* 
 * kvmdump.h
 *
 * Copyright (C) 2009, 2010 David Anderson
 * Copyright (C) 2009, 2010 Red Hat, Inc. All rights reserved.
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

struct mapinfo_trailer {
	uint64_t map_start_offset;
	uint64_t phys_base;
	uint32_t cpu_version_id;
	uint32_t ram_version_id;
	uint64_t checksum;
	uint64_t magic;
};

struct register_set {
	uint32_t cs;
	uint32_t ss;
	uint32_t ds;
	uint32_t es;
	uint32_t fs;
	uint32_t gs;
	uint64_t ip;
	uint64_t flags;
	uint64_t regs[16];
};

#define REGS_MAGIC    (0xfeedbeefdeadbabeULL)
#define MAPFILE_MAGIC (0xfeedbabedeadbeefULL)
#define CHKSUM_SIZE   (4096)

#define KVMDUMP_CACHED_PAGES 32

struct kvmdump_data {
	ulong flags;
	FILE *ofp;
	FILE *vmp;
	int mapfd;
	int vmfd;
	struct mapinfo_trailer mapinfo;
        /* page cache */
        struct kvm_page_cache_hdr {
                uint64_t paddr;
               	char *bufptr;
        } page_cache[KVMDUMP_CACHED_PAGES];
	union {
		char *curbufptr;
		unsigned char compressed;
	} un;
        int evict_index;    
	ulong accesses;
	ulong hit_count;
	ulong compresses;
	uint64_t kvbase;
	ulong *debug;
	uint64_t cpu_devices;
	struct register_set *registers;
	uint64_t iohole;
};

#define TMPFILE              (0x2)
#define MAPFILE              (0x4)
#define MAPFILE_FOUND        (0x8)
#define MAPFILE_APPENDED    (0x10)
#define NO_PHYS_BASE        (0x20)
#define KVMHOST_32          (0x40)
#define KVMHOST_64          (0x80)
#define REGS_FROM_DUMPFILE (0x100)
#define REGS_FROM_MAPFILE  (0x200)
#define REGS_NOT_AVAIL     (0x400)

extern struct kvmdump_data *kvm;

#undef dprintf
#define dprintf(x...)   do { if (*(kvm->debug)) fprintf(kvm->ofp, x); } while (0)

int store_mapfile_offset(uint64_t, off_t *);
int load_mapfile_offset(uint64_t, off_t *);

struct qemu_device_x86;
int kvmdump_regs_store(uint32_t, struct qemu_device_x86 *);
#define KVMDUMP_REGS_START   (NR_CPUS+1)
#define KVMDUMP_REGS_END     (NR_CPUS+2)

#define UPPER_32_BITS    (0xffffffff00000000ULL)

enum CPU_REG {
	R_EAX,
	R_ECX,
	R_EDX,
	R_EBX,
	R_ESP,
	R_EBP,
	R_ESI,
	R_EDI,
	R_GP_MAX,
};

