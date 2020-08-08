/* netdump.h
 *
 * Copyright (C) 2002-2009, 2017-2018 David Anderson
 * Copyright (C) 2002-2009, 2017-2018 Red Hat, Inc. All rights reserved.
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
 * Author: David Anderson
 */

#include <elf.h>
#include "vmcore.h"

#define MIN_NETDUMP_ELF32_HEADER_SIZE \
        sizeof(Elf32_Ehdr)+sizeof(Elf32_Phdr)+sizeof(Elf32_Phdr)
#define MIN_NETDUMP_ELF64_HEADER_SIZE \
        sizeof(Elf64_Ehdr)+sizeof(Elf64_Phdr)+sizeof(Elf64_Phdr)
#define MIN_NETDUMP_ELF_HEADER_SIZE \
        MAX(MIN_NETDUMP_ELF32_HEADER_SIZE, MIN_NETDUMP_ELF64_HEADER_SIZE)

#define NETDUMP_ELF_HEADER_SPARE_SIZE 128
/*
 * "Safe" size, as in covering the ELF header and the first two program headers
 * plus any "padding" in-between, like section headers.
 */
#define SAFE_NETDUMP_ELF_HEADER_SIZE \
	(MIN_NETDUMP_ELF_HEADER_SIZE+NETDUMP_ELF_HEADER_SPARE_SIZE)

#define NT_TASKSTRUCT 4
#define NT_DISKDUMP   0x70000001

#ifdef NOTDEF
/*
 *  Note: Based upon the original, abandoned, proposal for
 *  its contents -- keep around for potential future use.
 */
#ifndef NT_KDUMPINFO
#define NT_KDUMPINFO 7
#endif

#endif  /* NOTDEF */

struct pt_load_segment {
	off_t file_offset;
	physaddr_t phys_start;
	physaddr_t phys_end;
	physaddr_t zero_fill;
};

struct vmcore_data {
	ulong flags;
	int ndfd;
	FILE *ofp;
	uint header_size;
	char *elf_header;
	uint num_pt_load_segments;
	struct pt_load_segment *pt_load_segments;
        Elf32_Ehdr *elf32;
        Elf32_Phdr *notes32;
        Elf32_Phdr *load32;
        Elf64_Ehdr *elf64;
        Elf64_Phdr *notes64;
        Elf64_Phdr *load64;
        Elf64_Shdr *sect0_64;
        void *nt_prstatus;
        void *nt_prpsinfo;
        void *nt_taskstruct;
	ulong task_struct;
	uint page_size;
	ulong switch_stack;
	uint num_prstatus_notes;
	void *nt_prstatus_percpu[NR_CPUS];
	void *vmcoreinfo;
	uint size_vmcoreinfo;
/* Backup Region, first 640K of System RAM. */
#define KEXEC_BACKUP_SRC_END	0x0009ffff
	uint num_qemu_notes;
	void *nt_qemu_percpu[NR_CPUS];
	ulonglong backup_src_start;
	ulong backup_src_size;
	ulonglong backup_offset;
	ulong arch_data;
#define arch_data1 arch_data
	ulong phys_base;
	ulong arch_data2;
	void *nt_vmcoredd_array[NR_DEVICE_DUMPS];
	uint  num_vmcoredd_notes;
};

#define DUMP_ELF_INCOMPLETE  0x1   /* dumpfile is incomplete */

/*
 * S390 CPU timer ELF note
 */
#ifndef NT_S390_TIMER
#define NT_S390_TIMER 0x301
#endif

/*
 * S390 TOD clock comparator ELF note
 */
#ifndef NT_S390_TODCMP
#define NT_S390_TODCMP 0x302
#endif

/*
 * S390 TOD programmable register ELF note
 */
#ifndef NT_S390_TODPREG
#define NT_S390_TODPREG 0x303
#endif

/*
 * S390 control registers ELF note
 */
#ifndef NT_S390_CTRS
#define NT_S390_CTRS 0x304
#endif

/*
 * S390 prefix ELF note
 */
#ifndef NT_S390_PREFIX
#define NT_S390_PREFIX 0x305
#endif

/*
 * S390 vector registers 0-15 upper half note (16 * u64)
 */
#ifndef NT_S390_VXRS_LOW
#define NT_S390_VXRS_LOW 0x309
#endif

/*
 * S390 vector registers 16-31 note (16 * u128)
 */
#ifndef NT_S390_VXRS_HIGH
#define NT_S390_VXRS_HIGH 0x30a
#endif

#define MAX_KCORE_ELF_HEADER_SIZE (32768)

struct proc_kcore_data {
	uint flags;
	uint segments;
	char *elf_header;
	size_t header_size;
	Elf64_Phdr *load64;
	Elf64_Phdr *notes64;
	Elf32_Phdr *load32;
	Elf32_Phdr *notes32;
	void *vmcoreinfo;
	uint size_vmcoreinfo;
};
