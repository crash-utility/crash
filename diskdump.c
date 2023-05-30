/* 
 * diskdump.c 
 * 
 * The diskdump module optionally creates either ELF vmcore 
 * dumpfiles, or compressed dumpfiles derived from the LKCD format.
 * In the case of ELF vmcore files, since they are identical to 
 * netdump dumpfiles, the facilities in netdump.c are used.  For
 * compressed dumpfiles, the facilities in this file are used.
 *
 * Copyright (C) 2004-2015 David Anderson
 * Copyright (C) 2004-2015 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2005  FUJITSU LIMITED
 * Copyright (C) 2005  NEC Corporation
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
#include "diskdump.h"
#include "xen_dom0.h"
#include "vmcore.h"

#define BITMAP_SECT_LEN	4096

struct diskdump_data {
	char *filename;
	ulong flags;       /* DISKDUMP_LOCAL, plus anything else... */
        int dfd;           /* dumpfile file descriptor */
        FILE *ofp;         /* fprintf(dd->ofp, "xxx"); */
	int machine_type;  /* machine type identifier */

	/* header */
	struct disk_dump_header		*header;
	struct disk_dump_sub_header	*sub_header;
	struct kdump_sub_header		*sub_header_kdump;

	unsigned long long	max_mapnr;	/* 64bit max_mapnr */

	size_t	data_offset;
	int	block_size;
	int	block_shift;
	char	*bitmap;
	off_t	bitmap_len;
	char	*dumpable_bitmap;
	int	byte, bit;
	char	*compressed_page;	/* copy of compressed page data */
	char	*curbufptr;		/* ptr to uncompressed page buffer */
	unsigned char *notes_buf;	/* copy of elf notes */
	void	**nt_prstatus_percpu;
	uint	num_prstatus_notes;
	void	**nt_qemu_percpu;
	void	**nt_qemucs_percpu;
	uint	num_qemu_notes;
	void	**nt_vmcoredd_array;
	uint	num_vmcoredd_notes;

	/* page cache */
	struct page_cache_hdr {		/* header for each cached page */
		uint32_t pg_flags;
		uint64_t pg_addr;
		char *pg_bufptr;
		ulong pg_hit_count;
	} page_cache_hdr[DISKDUMP_CACHED_PAGES];
	char	*page_cache_buf;	/* base of cached buffer pages */
	int	evict_index;		/* next page to evict */
	ulong	evictions;		/* total evictions done */
	ulong	cached_reads;
	ulong  *valid_pages;
	int     max_sect_len;           /* highest bucket of valid_pages */
	ulong   accesses;
	ulong	snapshot_task;
};

static struct diskdump_data diskdump_data = { 0 };
static struct diskdump_data *dd = &diskdump_data;

ulong *diskdump_flags = &diskdump_data.flags;

static int __diskdump_memory_dump(FILE *);
static void dump_vmcoreinfo(FILE *);
static void dump_note_offsets(FILE *);
static char *vmcoreinfo_read_string(const char *);
static void diskdump_get_osrelease(void);
static int valid_note_address(unsigned char *);

/* For split dumpfile */
static struct diskdump_data **dd_list = NULL;
static int num_dd = 0;
static int num_dumpfiles = 0;

int dumpfile_is_split(void)
{
	return KDUMP_SPLIT();
}

int have_crash_notes(int cpu)
{
	ulong crash_notes, notes_ptr;
	char *buf, *p;
	Elf64_Nhdr *note = NULL;

	if (!readmem(symbol_value("crash_notes"), KVADDR, &crash_notes,
		     sizeof(crash_notes), "crash_notes", RETURN_ON_ERROR)) {
		error(WARNING, "cannot read \"crash_notes\"\n");
		return FALSE;
	}

	if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF))
		notes_ptr = crash_notes + kt->__per_cpu_offset[cpu];
	else
		notes_ptr = crash_notes;

	buf = GETBUF(SIZE(note_buf));

	if (!readmem(notes_ptr, KVADDR, buf,
		     SIZE(note_buf), "note_buf_t", RETURN_ON_ERROR)) {
		error(WARNING, "cpu %d: cannot read NT_PRSTATUS note\n", cpu);
		return FALSE;
	}

	note = (Elf64_Nhdr *)buf;
	p = buf + sizeof(Elf64_Nhdr);

	if (note->n_type != NT_PRSTATUS) {
		error(WARNING, "cpu %d: invalid NT_PRSTATUS note (n_type != NT_PRSTATUS)\n", cpu);
		return FALSE;
	}

	if (!STRNEQ(p, "CORE")) {
		error(WARNING, "cpu %d: invalid NT_PRSTATUS note (name != \"CORE\")\n", cpu);
		return FALSE;
	}

	return TRUE;
}

void
map_cpus_to_prstatus_kdump_cmprs(void)
{
	void **nt_ptr;
	int online, i, j, nrcpus;
	size_t size;
	int crash_notes_exists;

	if (pc->flags2 & QEMU_MEM_DUMP_COMPRESSED)  /* notes exist for all cpus */
		goto resize_note_pointers;

	if (!(online = get_cpus_online()) || (online == kt->cpus))
		goto resize_note_pointers;

	if (CRASHDEBUG(1))
		error(INFO,
		    "cpus: %d online: %d NT_PRSTATUS notes: %d (remapping)\n",
			kt->cpus, online, dd->num_prstatus_notes);

	size = NR_CPUS * sizeof(void *);

	nt_ptr = (void **)GETBUF(size);
	BCOPY(dd->nt_prstatus_percpu, nt_ptr, size);
	BZERO(dd->nt_prstatus_percpu, size);

	/*
	 *  Re-populate the array with the notes mapping to online cpus
	 */
	nrcpus = (kt->kernel_NR_CPUS ? kt->kernel_NR_CPUS : NR_CPUS);
	crash_notes_exists = kernel_symbol_exists("crash_notes");

	for (i = 0, j = 0; i < nrcpus; i++) {
		if (in_cpu_map(ONLINE_MAP, i) && (!crash_notes_exists || have_crash_notes(i))) {
			dd->nt_prstatus_percpu[i] = nt_ptr[j++];
			dd->num_prstatus_notes = 
				MAX(dd->num_prstatus_notes, i+1);
		}
	}

	FREEBUF(nt_ptr);

resize_note_pointers:
	/*
	 *  For architectures that only utilize the note pointers
	 *  within this file, resize the arrays accordingly.
	 */
	if (machine_type("X86_64") || machine_type("X86") || 
	    machine_type("ARM64")) {
		if ((dd->nt_prstatus_percpu = realloc(dd->nt_prstatus_percpu, 
		    dd->num_prstatus_notes * sizeof(void *))) == NULL)
			error(FATAL, 
			    "compressed kdump: cannot realloc NT_PRSTATUS note pointers\n");
		if (dd->num_qemu_notes) {
			if  ((dd->nt_qemu_percpu = realloc(dd->nt_qemu_percpu, 
		    	    dd->num_qemu_notes * sizeof(void *))) == NULL)
				error(FATAL, 
				    "compressed kdump: cannot realloc QEMU note pointers\n");
			if  ((dd->nt_qemucs_percpu = realloc(dd->nt_qemucs_percpu,
			    dd->num_qemu_notes * sizeof(void *))) == NULL)
				error(FATAL,
				    "compressed kdump: cannot realloc QEMU note pointers\n");
		} else {
			free(dd->nt_qemu_percpu);
			free(dd->nt_qemucs_percpu);
		}
	}
}

static void 
add_diskdump_data(char* name)
{
#define DDL_SIZE 16
	int i;
	int sz = sizeof(void *);
	struct diskdump_data *ddp;

	if (dd_list == NULL) {
		dd_list = calloc(DDL_SIZE, sz);
		num_dd = DDL_SIZE;
	} else {
		for (i = 0; i < num_dumpfiles; i++) {
			ddp = dd_list[i];
                	if (same_file(ddp->filename, name))
				error(FATAL, 
				    "split dumpfiles are identical:\n"
				    "  %s\n  %s\n",
					ddp->filename, name);
			if (memcmp(ddp->header, dd->header,
			    sizeof(struct disk_dump_header)))
				error(FATAL, 
				    "split dumpfiles derived from different vmcores:\n"
				    "  %s\n  %s\n",
					ddp->filename, name);
		}
	}

	if (num_dumpfiles == num_dd) {
		/* expand list */
		struct diskdump_data **tmp;
		tmp = calloc(num_dd*2, sz);
		memcpy(tmp, dd_list, sz*num_dd);
		free(dd_list);
		dd_list = tmp;
		num_dd *= 2;
	}

	dd_list[num_dumpfiles] = dd;
	dd->flags |= DUMPFILE_SPLIT;
	dd->filename = name;

	if (CRASHDEBUG(1))
		fprintf(fp, "%s: start_pfn=%llu, end_pfn=%llu\n", name,
			dd->sub_header_kdump->start_pfn_64,
			dd->sub_header_kdump->end_pfn_64);
}

static void 
clean_diskdump_data(void)
{
	int i;

	if (dd_list == NULL)
		return;

	for (i=1; i<num_dumpfiles; i++)
		free(dd_list[i]); /* NOTE: dd_list[0] is static dd */

	free(dd_list);
	dd_list = NULL;
	num_dumpfiles = 0;
	dd = &diskdump_data;
}

static inline int 
get_bit(char *map, unsigned long byte, int bit)
{
	return map[byte] & (1<<bit);
}

static inline int 
page_is_ram(unsigned long nr)
{
	return get_bit(dd->bitmap, nr >> 3, nr & 7);
}

static inline int 
page_is_dumpable(unsigned long nr)
{
	return dd->dumpable_bitmap[nr>>3] & (1 << (nr & 7));
}

static inline int 
dump_is_partial(const struct disk_dump_header *header)
{
	return header->bitmap_blocks >=
	    divideup(divideup(dd->max_mapnr, 8), dd->block_size) * 2;
}

static int 
open_dump_file(char *file)
{
	int fd;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		error(INFO, "diskdump / compressed kdump: unable to open dump file %s\n", file);
		return FALSE;
	}

	if (KDUMP_SPLIT())
		dd = calloc(1, sizeof(*dd));

	dd->dfd = fd;
	return TRUE;
}

void
process_elf32_notes(void *note_buf, unsigned long size_note)
{
	Elf32_Nhdr *nt;
	size_t index, len = 0;
	int num = 0;
	int vmcoredd_num = 0;
	int qemu_num = 0;

	for (index = 0; index < size_note; index += len) {
		nt = note_buf + index;

		if (nt->n_type == NT_PRSTATUS) {
			dd->nt_prstatus_percpu[num] = nt;
			num++;
		}
		len = sizeof(Elf32_Nhdr);
		if (STRNEQ((char *)nt + len, "QEMU")) {
			ulong *ptr =
			    (ulong *)((char *)nt + sizeof(Elf32_Nhdr) + nt->n_namesz);
			dd->nt_qemucs_percpu[qemu_num] =
			    (ulong *)roundup((ulong) ptr, 4);
			dd->nt_qemu_percpu[qemu_num] = nt;
			qemu_num++;
		}
		if (nt->n_type == NT_XEN_KDUMP_CR3 ||
		    nt->n_type == XEN_ELFNOTE_CRASH_INFO) {
			void *data = (char*)(nt + 1) +
				roundup(nt->n_namesz, 4);
			process_xen_note(nt->n_type, data, nt->n_descsz);
		}

		if (nt->n_type == NT_VMCOREDD &&
		    vmcoredd_num < NR_DEVICE_DUMPS) {
			dd->nt_vmcoredd_array[vmcoredd_num] = nt;
			vmcoredd_num++;
		}

		len = roundup(len + nt->n_namesz, 4);
		len = roundup(len + nt->n_descsz, 4);
	}

	if (num > 0) {
		pc->flags2 |= ELF_NOTES;
		dd->num_prstatus_notes = num;
	}

	if (qemu_num > 0) {
		pc->flags2 |= QEMU_MEM_DUMP_COMPRESSED;
		dd->num_qemu_notes = qemu_num;
	}
	if (vmcoredd_num > 0)
		dd->num_vmcoredd_notes = vmcoredd_num;

	return;
}

void
process_elf64_notes(void *note_buf, unsigned long size_note)
{
	Elf64_Nhdr *nt;
	size_t index, len = 0;
	int num = 0;
	int vmcoredd_num = 0;
	int qemu_num = 0;

	for (index = 0; index < size_note; index += len) {
		nt = note_buf + index;

		if (nt->n_type == NT_PRSTATUS) {
			dd->nt_prstatus_percpu[num] = nt;
			num++;
		}
		if ((nt->n_type == NT_TASKSTRUCT) && 
		    (STRNEQ((char *)nt + sizeof(Elf64_Nhdr), "SNAP"))) {
			pc->flags2 |= (LIVE_DUMP|SNAP);
			dd->snapshot_task = 
			    *((ulong *)((char *)nt + sizeof(Elf64_Nhdr) + nt->n_namesz));
		}
		len = sizeof(Elf64_Nhdr);
		if (STRNEQ((char *)nt + len, "QEMU")) {
			ulong *ptr =
			    (ulong *)((char *)nt + sizeof(Elf64_Nhdr) + nt->n_namesz);
			dd->nt_qemucs_percpu[qemu_num] =
			    (ulong *)roundup((ulong) ptr, 4);
			dd->nt_qemu_percpu[qemu_num] = nt;
			qemu_num++;
		}
		if (nt->n_type == NT_XEN_KDUMP_CR3 ||
		    nt->n_type == XEN_ELFNOTE_CRASH_INFO) {
			void *data = (char*)(nt + 1) +
				roundup(nt->n_namesz, 4);
			process_xen_note(nt->n_type, data, nt->n_descsz);
		}

		if (nt->n_type == NT_VMCOREDD &&
		    vmcoredd_num < NR_DEVICE_DUMPS) {
			dd->nt_vmcoredd_array[vmcoredd_num] = nt;
			vmcoredd_num++;
		}

		len = roundup(len + nt->n_namesz, 4);
		len = roundup(len + nt->n_descsz, 4);
	}

	if (num > 0) {
		pc->flags2 |= ELF_NOTES;
		dd->num_prstatus_notes = num;
	}

	if (qemu_num > 0) {
		pc->flags2 |= QEMU_MEM_DUMP_COMPRESSED;
		dd->num_qemu_notes = qemu_num;
	}
	if (vmcoredd_num > 0)
		dd->num_vmcoredd_notes = vmcoredd_num;

	return;
}

void 
x86_process_elf_notes(void *note_ptr, unsigned long size_note)
{
	if (machine_type("X86_64"))
		process_elf64_notes(note_ptr, size_note);
	else if (machine_type("X86"))
		process_elf32_notes(note_ptr, size_note);
}

#if defined(__i386__) && (defined(ARM) || defined(MIPS))
/*
 * The kdump_sub_header member offsets are different when the crash 
 * binary is built natively on an ARM host vs. when built with  
 * "make target=ARM" on an x86/x86_64 host.  This is because the
 * off_t structure members will be aligned on an 8-byte boundary when
 * compiled as an ARM binary -- which will be reflected in the 
 * kdump_sub_header in a compressed ARM kdump.  
 *
 * When crash is compiled as an x86 binary, these are the 
 * structure's offsets:
 * 
 * struct kdump_sub_header {
 * [0]     unsigned long   phys_base;
 * [4]     int             dump_level;         /  header_version 1 and later  /
 * [8]     int             split;              /  header_version 2 and later  /
 * [12]    unsigned long   start_pfn;          /  header_version 2 and later  /
 * [16]    unsigned long   end_pfn;            /  header_version 2 and later  /
 * [20]    off_t           offset_vmcoreinfo;  /  header_version 3 and later  /
 * [28]    unsigned long   size_vmcoreinfo;    /  header_version 3 and later  /
 * [32]    off_t           offset_note;        /  header_version 4 and later  /
 * [40]    unsigned long   size_note;          /  header_version 4 and later  /
 * [44]    off_t           offset_eraseinfo;   /  header_version 5 and later  /
 * [52]    unsigned long   size_eraseinfo;     /  header_version 5 and later  /
 * [56]    unsigned long long   start_pfn_64;  /  header_version 6 and later  /
 * [64]    unsigned long long   end_pfn_64;    /  header_version 6 and later  /
 * [72]    unsigned long long   max_mapnr_64;  /  header_version 6 and later  /
 * };
 * 
 * But when compiled on an ARM processor, each 64-bit "off_t" would be pushed
 * up to an 8-byte boundary:
 * 
 * struct kdump_sub_header {
 * [0]     unsigned long   phys_base;
 * [4]     int             dump_level;         /  header_version 1 and later  /
 * [8]     int             split;              /  header_version 2 and later  /
 * [12]    unsigned long   start_pfn;          /  header_version 2 and later  /
 * [16]    unsigned long   end_pfn;            /  header_version 2 and later  /
 * [24]    off_t           offset_vmcoreinfo;  /  header_version 3 and later  /
 * [32]    unsigned long   size_vmcoreinfo;    /  header_version 3 and later  /
 * [40]    off_t           offset_note;        /  header_version 4 and later  /
 * [48]    unsigned long   size_note;          /  header_version 4 and later  /
 * [56]    off_t           offset_eraseinfo;   /  header_version 5 and later  /
 * [64]    unsigned long   size_eraseinfo;     /  header_version 5 and later  /
 * [72]    unsigned long long   start_pfn_64;  /  header_version 6 and later  /
 * [80]    unsigned long long   end_pfn_64;    /  header_version 6 and later  /
 * [88]    unsigned long long   max_mapnr_64;  /  header_version 6 and later  /
 * };
 * 
 */

struct kdump_sub_header_ARM_target {
        unsigned long   phys_base;
        int             dump_level;         /* header_version 1 and later */
        int             split;              /* header_version 2 and later */
        unsigned long   start_pfn;          /* header_version 2 and later */
        unsigned long   end_pfn;            /* header_version 2 and later */
	int		pad1;
        off_t           offset_vmcoreinfo;  /* header_version 3 and later */
        unsigned long   size_vmcoreinfo;    /* header_version 3 and later */
	int 		pad2;	
        off_t           offset_note;        /* header_version 4 and later */
        unsigned long   size_note;          /* header_version 4 and later */
	int 		pad3;	
        off_t           offset_eraseinfo;   /* header_version 5 and later */
        unsigned long   size_eraseinfo;     /* header_version 5 and later */
	int		pad4;
	unsigned long long start_pfn_64;    /* header_version 6 and later */
	unsigned long long end_pfn_64;      /* header_version 6 and later */
	unsigned long long max_mapnr_64;    /* header_version 6 and later */
};

static void
arm_kdump_header_adjust(int header_version)
{
	struct kdump_sub_header *kdsh;
	struct kdump_sub_header_ARM_target *kdsh_ARM_target;

	kdsh = dd->sub_header_kdump;
	kdsh_ARM_target = (struct kdump_sub_header_ARM_target *)kdsh;

	if (header_version >= 3) {
		kdsh->offset_vmcoreinfo = kdsh_ARM_target->offset_vmcoreinfo; 
		kdsh->size_vmcoreinfo = kdsh_ARM_target->size_vmcoreinfo;
	}
	if (header_version >= 4) {
		kdsh->offset_note = kdsh_ARM_target->offset_note;
		kdsh->size_note = kdsh_ARM_target->size_note;
	}
	if (header_version >= 5) {
		kdsh->offset_eraseinfo = kdsh_ARM_target->offset_eraseinfo;
		kdsh->size_eraseinfo = kdsh_ARM_target->size_eraseinfo;
	}
	if (header_version >= 6) {
		kdsh->start_pfn_64 = kdsh_ARM_target->start_pfn_64;
		kdsh->end_pfn_64 = kdsh_ARM_target->end_pfn_64;
		kdsh->max_mapnr_64 = kdsh_ARM_target->max_mapnr_64;
	} else {
		kdsh->start_pfn_64 = kdsh_ARM_target->start_pfn;
		kdsh->end_pfn_64 = kdsh_ARM_target->end_pfn;
		kdsh->max_mapnr_64 = dd->max_mapnr;
	}
}
#endif  /* __i386__ && (ARM || MIPS) */

/*
 * Read page descriptor.
 */
static int
read_pd(int fd, off_t offset, page_desc_t *pd)
{
	int ret;

	if (FLAT_FORMAT()) {
		if (!read_flattened_format(fd, offset, pd, sizeof(*pd)))
			return READ_ERROR;
	} else {
		if (offset < 0) {
			if (CRASHDEBUG(8))
				fprintf(fp, "read_pd: invalid offset: %lx\n", offset);
			return SEEK_ERROR;
		}
		if ((ret = pread(fd, pd, sizeof(*pd), offset)) != sizeof(*pd)) {
			if (ret == -1 && CRASHDEBUG(8))
				fprintf(fp, "read_pd: pread error: %s\n", strerror(errno));
			return READ_ERROR;
		}
	}

	return 0;
}

static int 
read_dump_header(char *file)
{
	struct disk_dump_header *header = NULL;
	struct disk_dump_sub_header *sub_header = NULL;
	struct kdump_sub_header *sub_header_kdump = NULL;
	size_t size;
	off_t bitmap_len;
	int block_size = (int)sysconf(_SC_PAGESIZE);
	off_t offset;
	const off_t failed = (off_t)-1;
	ulong pfn;
	int i, j, max_sect_len;
	int is_split = 0;
	ulonglong tmp, *bitmap;

	if (block_size < 0)
		return FALSE;

restart:
	if ((header = realloc(header, block_size)) == NULL)
		error(FATAL, "diskdump / compressed kdump: cannot malloc block_size buffer\n");

	if (FLAT_FORMAT()) {
		if (!read_flattened_format(dd->dfd, 0, header, block_size)) {
			error(FATAL, "diskdump / compressed kdump: cannot read header\n");
			goto err;
		}
	} else {
		if (lseek(dd->dfd, 0, SEEK_SET) == failed) {
			if (CRASHDEBUG(1))
				error(INFO, "diskdump / compressed kdump: cannot lseek dump header\n");
			goto err;
		}
		if (read(dd->dfd, header, block_size) < block_size) {
			if (CRASHDEBUG(1))
				error(INFO, "diskdump / compressed kdump: cannot read dump header\n");
			goto err;
		}
	}

	/* validate dump header */
	if (!memcmp(header->signature, DISK_DUMP_SIGNATURE,
				sizeof(header->signature))) {
		dd->flags |= DISKDUMP_LOCAL;
	} else if (!memcmp(header->signature, KDUMP_SIGNATURE,
				sizeof(header->signature))) {
		dd->flags |= KDUMP_CMPRS_LOCAL;
		if (header->header_version >= 1)
			dd->flags |= ERROR_EXCLUDED;
	} else {
		if (CRASHDEBUG(1))
			error(INFO, 
			    "diskdump / compressed kdump: dump does not have panic dump header\n");
		goto err;
	}

	if (CRASHDEBUG(1))
		fprintf(fp, "%s: header->utsname.machine: %s\n", 
			DISKDUMP_VALID() ? "diskdump" : "compressed kdump",
			header->utsname.machine);

	if (STRNEQ(header->utsname.machine, "i686") &&
	    machine_type_mismatch(file, "X86", NULL, 0))
		goto err;
	else if (STRNEQ(header->utsname.machine, "x86_64") &&
	    machine_type_mismatch(file, "X86_64", NULL, 0))
		goto err;
	else if (STRNEQ(header->utsname.machine, "ia64") &&
	    machine_type_mismatch(file, "IA64", NULL, 0))
		goto err;
	else if (STREQ(header->utsname.machine, "ppc") &&
	    machine_type_mismatch(file, "PPC", NULL, 0))
		goto err;
	else if (STRNEQ(header->utsname.machine, "ppc64") &&
	    machine_type_mismatch(file, "PPC64", NULL, 0))
		goto err;
	else if (STRNEQ(header->utsname.machine, "arm") &&
	    machine_type_mismatch(file, "ARM", NULL, 0))
		goto err;
	else if (STREQ(header->utsname.machine, "mips") &&
	    machine_type_mismatch(file, "MIPS", NULL, 0))
		goto err;
	else if (STRNEQ(header->utsname.machine, "mips64") &&
	    machine_type_mismatch(file, "MIPS64", NULL, 0))
		goto err;
	else if (STRNEQ(header->utsname.machine, "s390x") &&
	    machine_type_mismatch(file, "S390X", NULL, 0))
		goto err;
	else if (STRNEQ(header->utsname.machine, "aarch64") &&
	    machine_type_mismatch(file, "ARM64", NULL, 0))
		goto err;
	else if (STRNEQ(header->utsname.machine, "riscv64") &&
	    machine_type_mismatch(file, "RISCV64", NULL, 0))
		goto err;

	if (header->block_size != block_size) {
		block_size = header->block_size;
		if (CRASHDEBUG(1))
			fprintf(fp, 
			    "retrying with different block/page size: %d\n", 
				header->block_size);
		goto restart;
	}
	dd->block_size  = header->block_size;
	dd->block_shift = ffs(header->block_size) - 1;

	if ((DISKDUMP_VALID() &&
             (sizeof(*header) + sizeof(void *) * header->nr_cpus > block_size)) ||
             header->nr_cpus <= 0) {
                error(WARNING, "%s: invalid nr_cpus value: %d\n",
                        DISKDUMP_VALID() ? "diskdump" : "compressed kdump",
                        header->nr_cpus);
		if (!machine_type("S390") && !machine_type("S390X") &&
		    !machine_type("X86") && !machine_type("X86_64")) {
			if (DISKDUMP_VALID())
				goto err;
		}
        }

	/* read sub header */
	offset = (off_t)block_size;

	if (DISKDUMP_VALID()) {
		if ((sub_header = malloc(block_size)) == NULL)
			error(FATAL, "diskdump: cannot malloc sub_header buffer\n");

		if (FLAT_FORMAT()) {
			if (!read_flattened_format(dd->dfd, offset, sub_header, block_size)) {
				error(INFO, "diskdump: cannot read dump sub header\n");
				goto err;
			}
		} else {
			if (lseek(dd->dfd, offset, SEEK_SET) == failed) {
				error(INFO, "diskdump: cannot lseek dump sub header\n");
				goto err;
			}
			if (read(dd->dfd, sub_header, block_size) < block_size) {
				error(INFO, "diskdump: cannot read dump sub header\n");
				goto err;
			}
		}
		dd->sub_header = sub_header;

		/* the 64bit max_mapnr only exists in sub-header of compressed
		 * kdump file, if it's not a compressed kdump file, we have to
		 * use the old 32bit max_mapnr in dumpfile header.
		 * max_mapnr may be truncated here.
		 */
		dd->max_mapnr = header->max_mapnr;
	} else if (KDUMP_CMPRS_VALID()) {
		if ((sub_header_kdump = malloc(block_size)) == NULL)
			error(FATAL, "compressed kdump: cannot malloc sub_header_kdump buffer\n");

		if (FLAT_FORMAT()) {
			if (!read_flattened_format(dd->dfd, offset, sub_header_kdump, block_size)) {
				error(INFO, "compressed kdump: cannot read dump sub header\n");
				goto err;
			}
		} else {
			if (lseek(dd->dfd, offset, SEEK_SET) == failed) {
				error(INFO, "compressed kdump: cannot lseek dump sub header\n");
				goto err;
			}
			if (read(dd->dfd, sub_header_kdump, block_size) < block_size) {
				error(INFO, "compressed kdump: cannot read dump sub header\n");
				goto err;
			}
		}
		dd->sub_header_kdump = sub_header_kdump;

#if defined(__i386__) && (defined(ARM) || defined(MIPS))
		arm_kdump_header_adjust(header->header_version);
#endif
		/* use 64bit max_mapnr in compressed kdump file sub-header */
		if (header->header_version >= 6)
			dd->max_mapnr = dd->sub_header_kdump->max_mapnr_64;
		else {
			dd->sub_header_kdump->start_pfn_64
				= dd->sub_header_kdump->start_pfn;
			dd->sub_header_kdump->end_pfn_64
				= dd->sub_header_kdump->end_pfn;
		}
	}

	if (header->header_version < 6)
		dd->max_mapnr = header->max_mapnr;

	/* read memory bitmap */
	bitmap_len = (off_t)block_size * header->bitmap_blocks;
	dd->bitmap_len = bitmap_len;

	offset = (off_t)block_size * (1 + header->sub_hdr_size);

	dd->dumpable_bitmap = calloc(bitmap_len, 1);

	if (CRASHDEBUG(8))
		fprintf(fp, "%s: memory bitmap offset: %llx\n",
			DISKDUMP_VALID() ? "diskdump" : "compressed kdump",
			(ulonglong)offset);

	if (FLAT_FORMAT()) {
		if ((dd->bitmap = malloc(bitmap_len)) == NULL)
			error(FATAL, "%s: cannot malloc bitmap buffer\n",
				DISKDUMP_VALID() ? "diskdump" : "compressed kdump");

		if (!read_flattened_format(dd->dfd, offset, dd->bitmap, bitmap_len)) {
			error(INFO, "%s: cannot read memory bitmap\n",
				DISKDUMP_VALID() ? "diskdump" : "compressed kdump");
			goto err;
		}
	} else {
		dd->bitmap = mmap(NULL, bitmap_len, PROT_READ,
					MAP_SHARED, dd->dfd, offset);
		if (dd->bitmap == MAP_FAILED)
			error(FATAL, "%s: cannot mmap bitmap buffer\n",
				DISKDUMP_VALID() ? "diskdump" : "compressed kdump");

		madvise(dd->bitmap, bitmap_len, MADV_WILLNEED);
	}

	if (dump_is_partial(header))
		memcpy(dd->dumpable_bitmap, dd->bitmap + bitmap_len/2,
		       bitmap_len/2);
	else
		memcpy(dd->dumpable_bitmap, dd->bitmap, bitmap_len);

	dd->data_offset
		= (1UL + header->sub_hdr_size + header->bitmap_blocks)
		* header->block_size;

	dd->header = header;

	if (machine_type("ARM"))
		dd->machine_type = EM_ARM;
	else if (machine_type("MIPS") || machine_type("MIPS64"))
		dd->machine_type = EM_MIPS;
	else if (machine_type("X86"))
		dd->machine_type = EM_386;
	else if (machine_type("X86_64"))
		dd->machine_type = EM_X86_64;
	else if (machine_type("IA64"))
		dd->machine_type = EM_IA_64;
	else if (machine_type("PPC"))
		dd->machine_type = EM_PPC;
	else if (machine_type("PPC64"))
		dd->machine_type = EM_PPC64;
	else if (machine_type("S390X"))
		dd->machine_type = EM_S390;
	else if (machine_type("ARM64"))
		dd->machine_type = EM_AARCH64;
	else if (machine_type("SPARC64"))
		dd->machine_type = EM_SPARCV9;
	else if (machine_type("RISCV64"))
		dd->machine_type = EM_RISCV;
	else {
		error(INFO, "%s: unsupported machine type: %s\n", 
			DISKDUMP_VALID() ? "diskdump" : "compressed kdump",
			MACHINE_TYPE);
		goto err;
	}

	/* process elf notes data */
	if (KDUMP_CMPRS_VALID() && !(dd->flags & NO_ELF_NOTES) &&
		(dd->header->header_version >= 4) &&
		(sub_header_kdump->offset_note) &&
		(sub_header_kdump->size_note) && (machdep->process_elf_notes)) {
		size = sub_header_kdump->size_note;
		offset = sub_header_kdump->offset_note;

		if ((dd->notes_buf = malloc(size)) == NULL)
			error(FATAL, "compressed kdump: cannot malloc notes"
				" buffer\n");

		if ((dd->nt_prstatus_percpu = malloc(NR_CPUS * sizeof(void *))) == NULL)
			error(FATAL, "compressed kdump: cannot malloc pointer"
				" to NT_PRSTATUS notes\n");

		if ((dd->nt_qemu_percpu = malloc(NR_CPUS * sizeof(void *))) == NULL)
			error(FATAL, "qemu mem dump compressed: cannot malloc pointer"
				" to QEMU notes\n");

		if ((dd->nt_qemucs_percpu = malloc(NR_CPUS * sizeof(void *))) == NULL)
			error(FATAL, "qemu mem dump compressed: cannot malloc pointer"
				" to QEMUCS notes\n");

		if ((dd->nt_vmcoredd_array = malloc(NR_DEVICE_DUMPS * sizeof(void *))) == NULL)
			error(FATAL, "compressed kdump: cannot malloc array for "
				     "vmcore device dump notes\n");

		if (FLAT_FORMAT()) {
			if (!read_flattened_format(dd->dfd, offset, dd->notes_buf, size)) {
				error(INFO, "compressed kdump: cannot read notes data"
					"\n");
				goto err;
			}
		} else {
			if (lseek(dd->dfd, offset, SEEK_SET) == failed) {
				error(INFO, "compressed kdump: cannot lseek notes data\n");
				goto err;
			}
			if (read(dd->dfd, dd->notes_buf, size) < size) {
				error(INFO, "compressed kdump: cannot read notes data"
					"\n");
				goto err;
			}
		}

		machdep->process_elf_notes(dd->notes_buf, size);
	}

	/* Check if dump file contains erasesinfo data */
	if (KDUMP_CMPRS_VALID() && (dd->header->header_version >= 5) &&
		(sub_header_kdump->offset_eraseinfo) &&
		(sub_header_kdump->size_eraseinfo))
		pc->flags2 |= ERASEINFO_DATA;

	if (KDUMP_CMPRS_VALID() && (dd->header->header_version >= 3) &&
		dd->sub_header_kdump->offset_vmcoreinfo &&
		dd->sub_header_kdump->size_vmcoreinfo)
		pc->flags2 |= VMCOREINFO;

	if (KDUMP_CMPRS_VALID() && 
	    (dd->header->status & DUMP_DH_COMPRESSED_INCOMPLETE))
		pc->flags2 |= INCOMPLETE_DUMP;

	if (KDUMP_CMPRS_VALID() && 
	    (dd->header->status & DUMP_DH_EXCLUDED_VMEMMAP))
		pc->flags2 |= EXCLUDED_VMEMMAP;

	/* For split dumpfile */
	if (KDUMP_CMPRS_VALID()) {
		is_split = ((dd->header->header_version >= 2) &&
		            (sub_header_kdump->split));

		if ((is_split && (num_dumpfiles != 0) && (dd_list == NULL))||
		    (!is_split && (num_dumpfiles != 0))) {
			clean_diskdump_data();
			goto err;
		}

		if (is_split)
			add_diskdump_data(file);

		num_dumpfiles++;
	}

	if (!is_split) {
		max_sect_len = divideup(dd->max_mapnr, BITMAP_SECT_LEN);
		pfn = 0;
		dd->filename = file;
	}
	else {
		unsigned long long start = sub_header_kdump->start_pfn_64;
		unsigned long long end = sub_header_kdump->end_pfn_64;
		max_sect_len = divideup(end - start + 1, BITMAP_SECT_LEN);
		pfn = start;
	}

	dd->valid_pages = calloc(sizeof(ulong), max_sect_len + 1);
	dd->max_sect_len = max_sect_len;

	/* It is safe to convert it to (ulonglong *). */
	bitmap = (ulonglong *)dd->dumpable_bitmap;
	for (i = 1; i < max_sect_len + 1; i++) {
		dd->valid_pages[i] = dd->valid_pages[i - 1];
		for (j = 0; j < BITMAP_SECT_LEN; j += 64, pfn += 64) {
			tmp = bitmap[pfn >> 6];
			if (tmp)
				dd->valid_pages[i] += hweight64(tmp);
		}
	}

        return TRUE;

err:
	free(header);
	if (sub_header)
		free(sub_header);
	if (sub_header_kdump)
		free(sub_header_kdump);
	if (dd->bitmap) {
		if (FLAT_FORMAT())
			free(dd->bitmap);
		else
			munmap(dd->bitmap, dd->bitmap_len);
	}
	if (dd->dumpable_bitmap)
		free(dd->dumpable_bitmap);
	if (dd->notes_buf)
		free(dd->notes_buf);
	if (dd->nt_prstatus_percpu)
		free(dd->nt_prstatus_percpu);
	if (dd->nt_qemu_percpu)
		free(dd->nt_qemu_percpu);
	if (dd->nt_qemucs_percpu)
		free(dd->nt_qemucs_percpu);
	if (dd->nt_vmcoredd_array)
		free(dd->nt_vmcoredd_array);

	dd->flags &= ~(DISKDUMP_LOCAL|KDUMP_CMPRS_LOCAL);
	pc->flags2 &= ~ELF_NOTES;
	return FALSE;
}

static ulong
pfn_to_pos(ulong pfn)
{
	ulong desc_pos, j, valid;
	ulong p1, p2;

	if (KDUMP_SPLIT()) {
		p1 = pfn - dd->sub_header_kdump->start_pfn_64;
		p2 = round(p1, BITMAP_SECT_LEN)
			+ dd->sub_header_kdump->start_pfn_64;
	}
	else {
		p1 = pfn; 
		p2 = round(pfn, BITMAP_SECT_LEN); 
	}

	valid = dd->valid_pages[p1 / BITMAP_SECT_LEN];

	for (j = p2, desc_pos = valid; j <= pfn; j++)
			if (page_is_dumpable(j))
				desc_pos++;

	return desc_pos;
}


/*
 *  Determine whether a file is a diskdump creation, and if TRUE,
 *  initialize the diskdump_data structure based upon the contents
 *  of the diskdump header data.
 */
int
is_diskdump(char *file)
{
	int sz, i;

	if (!open_dump_file(file) || !read_dump_header(file))
		return FALSE;

	sz = dd->block_size * (DISKDUMP_CACHED_PAGES);
	if ((dd->page_cache_buf = malloc(sz)) == NULL)
		error(FATAL, "%s: cannot malloc compressed page_cache_buf\n",
			DISKDUMP_VALID() ? "diskdump" : "compressed kdump");

	for (i = 0; i < DISKDUMP_CACHED_PAGES; i++)
		dd->page_cache_hdr[i].pg_bufptr =
			&dd->page_cache_buf[i * dd->block_size];

	if ((dd->compressed_page = (char *)malloc(dd->block_size)) == NULL)
		error(FATAL, "%s: cannot malloc compressed page space\n",
			DISKDUMP_VALID() ? "diskdump" : "compressed kdump");

	if (CRASHDEBUG(1))
		__diskdump_memory_dump(fp);

	if (pc->flags2 & GET_OSRELEASE) 
		diskdump_get_osrelease();

#ifdef LZO
	if (lzo_init() == LZO_E_OK)
		dd->flags |= LZO_SUPPORTED;
#endif

#ifdef SNAPPY
	dd->flags |= SNAPPY_SUPPORTED;
#endif
#ifdef ZSTD
	dd->flags |= ZSTD_SUPPORTED;
#endif

	pc->read_vmcoreinfo = vmcoreinfo_read_string;

	if ((pc->flags2 & GET_LOG) && KDUMP_CMPRS_VALID()) {
		pc->dfd = dd->dfd;
		pc->readmem = read_diskdump;
		pc->flags |= DISKDUMP;
		get_log_from_vmcoreinfo(file);
	}

	return TRUE;
}

/*
 *  Perform any post-dumpfile determination stuff here.
 *  At a minimum
 */
int
diskdump_init(char *unused, FILE *fptr)
{
	if (!DISKDUMP_VALID() && !KDUMP_CMPRS_VALID())
		return FALSE;

	dd->ofp = fptr;
	return TRUE;
}

/*
 *  Get the relocational offset from the sub header of kdump.
 */
int
diskdump_phys_base(unsigned long *phys_base)
{
	if (KDUMP_CMPRS_VALID()) {
		*phys_base = dd->sub_header_kdump->phys_base;
		return TRUE;
	}

	return FALSE;
}

int
diskdump_set_phys_base(unsigned long phys_base)
{
	if (diskdump_kaslr_check()) {
		dd->sub_header_kdump->phys_base = phys_base;
		return TRUE;
	}

	return FALSE;
}

/*
 *  Check whether paddr is already cached.
 */
static int
page_is_cached(physaddr_t paddr)
{
	int i;
	struct page_cache_hdr *pgc;

	dd->accesses++;

	for (i = 0; i < DISKDUMP_CACHED_PAGES; i++) {

		pgc = &dd->page_cache_hdr[i];

		if (!DISKDUMP_VALID_PAGE(pgc->pg_flags))
			continue;

		if (pgc->pg_addr == paddr) {
			pgc->pg_hit_count++;
			dd->curbufptr = pgc->pg_bufptr;
			dd->cached_reads++;
			return TRUE;
		}
	}
	return FALSE;
}

/*
 * Translate physical address in paddr to PFN number. This means normally that
 * we just shift paddr by some constant. Some architectures need special
 * handling for this, however.
 */
static ulong
paddr_to_pfn(physaddr_t paddr)
{
#ifdef ARM
	/*
	 * In ARM, PFN 0 means first page in kernel direct-mapped view.
	 * This is also first page in mem_map as well.
	 */
	return (paddr - machdep->machspec->phys_base) >> dd->block_shift;
#else
	return paddr >> dd->block_shift;
#endif
}

/*
 *  Cache the page's data.
 *
 *  If an empty page cache location is available, take it.  Otherwise, evict
 *  the entry indexed by evict_index, and then bump evict index.  The hit_count
 *  is only gathered for dump_diskdump_environment().
 *
 *  If the page is compressed, uncompress it into the selected page cache entry.
 *  If the page is raw, just copy it into the selected page cache entry.
 *  If all works OK, update diskdump->curbufptr to point to the page's
 *  uncompressed data.
 */
static int
cache_page(physaddr_t paddr)
{
	int i, ret;
	int found;
	ulong pfn;
	ulong desc_pos;
	off_t seek_offset;
	page_desc_t pd;
	const int block_size = dd->block_size;
	ulong retlen;
#ifdef ZSTD
	static ZSTD_DCtx *dctx = NULL;
#endif

	for (i = found = 0; i < DISKDUMP_CACHED_PAGES; i++) {
		if (DISKDUMP_VALID_PAGE(dd->page_cache_hdr[i].pg_flags))
			continue;
		found = TRUE;
		break;
	}

	if (!found) {
		i = dd->evict_index;
		dd->page_cache_hdr[i].pg_hit_count = 0;
		dd->evict_index =
			(dd->evict_index+1) % DISKDUMP_CACHED_PAGES;
		dd->evictions++;
	}

	dd->page_cache_hdr[i].pg_flags = 0;
	dd->page_cache_hdr[i].pg_addr = paddr;
	dd->page_cache_hdr[i].pg_hit_count++;

	/* find page descriptor */
	pfn = paddr_to_pfn(paddr);
	desc_pos = pfn_to_pos(pfn);
	seek_offset = dd->data_offset
			+ (off_t)(desc_pos - 1)*sizeof(page_desc_t);

	/* read page descriptor */
	ret = read_pd(dd->dfd, seek_offset, &pd);
	if (ret)
		return ret;

	/* sanity check */
	if (pd.size > block_size)
		return READ_ERROR;

	/* read page data */
	if (FLAT_FORMAT()) {
		if (!read_flattened_format(dd->dfd, pd.offset, dd->compressed_page, pd.size))
			return READ_ERROR;
	} else if (0 == pd.offset) {
		/*
		 *  First check whether zero_excluded has been set.
		 */
		if (*diskdump_flags & ZERO_EXCLUDED) {
			if (CRASHDEBUG(8))
				fprintf(fp, 
			    	    "read_diskdump/cache_page: zero-fill: "
				    "paddr/pfn: %llx/%lx\n", 
					(ulonglong)paddr, pfn);
			memset(dd->compressed_page, 0, dd->block_size);
		} else {
			if (CRASHDEBUG(8))
				fprintf(fp,
					"read_diskdump/cache_page: "
					"descriptor with zero offset found at "
					"paddr/pfn/pos: %llx/%lx/%lx\n",
					(ulonglong)paddr, pfn, desc_pos);
			return PAGE_INCOMPLETE;
		}
	} else {
		if (pd.offset < 0) {
			if (CRASHDEBUG(8))
				fprintf(fp, "read_diskdump/cache_page: invalid offset: %lx\n",
					pd.offset);
			return SEEK_ERROR;
		}
		if ((ret = pread(dd->dfd, dd->compressed_page, pd.size, pd.offset)) != pd.size) {
			if (ret == -1 && CRASHDEBUG(8))
				fprintf(fp, "read_diskdump/cache_page: pread error: %s\n",
					strerror(errno));
			return READ_ERROR;
		}
	}

	if (pd.flags & DUMP_DH_COMPRESSED_ZLIB) {
		retlen = block_size;
		ret = uncompress((unsigned char *)dd->page_cache_hdr[i].pg_bufptr,
		                 &retlen,
		                 (unsigned char *)dd->compressed_page,
		                 pd.size);
		if ((ret != Z_OK) || (retlen != block_size)) {
			error(INFO, "%s: uncompress failed: %d\n", 
				DISKDUMP_VALID() ? "diskdump" : "compressed kdump",
				ret);
			return READ_ERROR;
		}
	} else if (pd.flags & DUMP_DH_COMPRESSED_LZO) {

		if (!(dd->flags & LZO_SUPPORTED)) {
			error(INFO, "%s: uncompress failed: no lzo compression support\n",
			      DISKDUMP_VALID() ? "diskdump" : "compressed kdump");
			return READ_ERROR;
		}

#ifdef LZO
		retlen = block_size;
		ret = lzo1x_decompress_safe((unsigned char *)dd->compressed_page,
					    pd.size,
					    (unsigned char *)dd->page_cache_hdr[i].pg_bufptr,
					    &retlen,
					    LZO1X_MEM_DECOMPRESS);
		if ((ret != LZO_E_OK) || (retlen != block_size)) {
			error(INFO, "%s: uncompress failed: %d\n", 
				DISKDUMP_VALID() ? "diskdump" : "compressed kdump",
				ret);
			return READ_ERROR;
		}
#endif
	} else if (pd.flags & DUMP_DH_COMPRESSED_SNAPPY) {

		if (!(dd->flags & SNAPPY_SUPPORTED)) {
			error(INFO, "%s: uncompress failed: no snappy compression support\n",
			      DISKDUMP_VALID() ? "diskdump" : "compressed kdump");
			return READ_ERROR;
		}

#ifdef SNAPPY
		ret = snappy_uncompressed_length((char *)dd->compressed_page,
						 pd.size, (size_t *)&retlen);
		if (ret != SNAPPY_OK) {
			error(INFO, "%s: uncompress failed: %d\n",
			      DISKDUMP_VALID() ? "diskdump" : "compressed kdump",
			      ret);
			return READ_ERROR;
		}

		ret = snappy_uncompress((char *)dd->compressed_page, pd.size,
					(char *)dd->page_cache_hdr[i].pg_bufptr,
					(size_t *)&retlen);
		if ((ret != SNAPPY_OK) || (retlen != block_size)) {
			error(INFO, "%s: uncompress failed: %d\n", 
			      DISKDUMP_VALID() ? "diskdump" : "compressed kdump",
			      ret);
			return READ_ERROR;
		}
#endif
	} else if (pd.flags & DUMP_DH_COMPRESSED_ZSTD) {

		if (!(dd->flags & ZSTD_SUPPORTED)) {
			error(INFO, "%s: uncompess failed: no zstd compression support\n",
				DISKDUMP_VALID() ? "diskdump" : "compressed kdump");
			return READ_ERROR;
		}
#ifdef ZSTD
		if (!dctx) {
			dctx = ZSTD_createDCtx();
			if (!dctx) {
				error(INFO, "%s: uncompess failed: cannot create ZSTD_DCtx\n",
					DISKDUMP_VALID() ? "diskdump" : "compressed kdump");
				return READ_ERROR;
			}
		}

		retlen = ZSTD_decompressDCtx(dctx,
				dd->page_cache_hdr[i].pg_bufptr, block_size,
				dd->compressed_page, pd.size);
		if (ZSTD_isError(retlen) || (retlen != block_size)) {
			error(INFO, "%s: uncompress failed: %d (%s)\n",
				DISKDUMP_VALID() ? "diskdump" : "compressed kdump",
				retlen, ZSTD_getErrorName(retlen));
			return READ_ERROR;
		}
#endif
	} else
		memcpy(dd->page_cache_hdr[i].pg_bufptr,
		       dd->compressed_page, block_size);

	dd->page_cache_hdr[i].pg_flags |= PAGE_VALID;
	dd->curbufptr = dd->page_cache_hdr[i].pg_bufptr;

	return TRUE;
}

/*
 *  Read from a diskdump-created dumpfile.
 */
int
read_diskdump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	int ret;
	physaddr_t curpaddr;
	ulong pfn, page_offset;
	physaddr_t paddr_in = paddr;

	if (XEN_CORE_DUMPFILE() && !XEN_HYPER_MODE()) {
		if ((paddr = xen_kdump_p2m(paddr)) == P2M_FAILURE) {
			if (CRASHDEBUG(8))
				fprintf(fp, "read_diskdump: xen_kdump_p2m(%llx): "
					"P2M_FAILURE\n", (ulonglong)paddr_in);
			return READ_ERROR;
		}
		if (CRASHDEBUG(8))
			fprintf(fp, "read_diskdump: xen_kdump_p2m(%llx): %llx\n",
				(ulonglong)paddr_in, (ulonglong)paddr);
	}

	pfn = paddr_to_pfn(paddr);

	if (KDUMP_SPLIT()) {
		/* Find proper dd */
		int i;
		unsigned long long start_pfn;
		unsigned long long end_pfn;

		for (i=0; i<num_dumpfiles; i++) {
			start_pfn = dd_list[i]->sub_header_kdump->start_pfn_64;
			end_pfn = dd_list[i]->sub_header_kdump->end_pfn_64;
			if ((pfn >= start_pfn) && (pfn < end_pfn))	{
				dd = dd_list[i];
				break;
			}
		}

		if (i == num_dumpfiles) {
			if (CRASHDEBUG(8))
				fprintf(fp, "read_diskdump: SEEK_ERROR: "
				    "paddr/pfn %llx/%lx beyond last dumpfile\n",
					(ulonglong)paddr, pfn);
			return SEEK_ERROR;
		}
	}

	curpaddr = paddr & ~((physaddr_t)(dd->block_size-1));
	page_offset = paddr & ((physaddr_t)(dd->block_size-1));

	if ((pfn >= dd->max_mapnr) || !page_is_ram(pfn)) {
		if (CRASHDEBUG(8)) {
			fprintf(fp, "read_diskdump: SEEK_ERROR: "
			    "paddr/pfn: %llx/%lx ",
				(ulonglong)paddr, pfn);
			if (pfn >= dd->max_mapnr)
				fprintf(fp, "max_mapnr: %llx\n",
					dd->max_mapnr);
			else
				fprintf(fp, "!page_is_ram\n");
		}

		return SEEK_ERROR;
	}

	if (!page_is_dumpable(pfn)) {
		if ((dd->flags & (ZERO_EXCLUDED|ERROR_EXCLUDED)) ==
		    ERROR_EXCLUDED) {
			if (CRASHDEBUG(8))
				fprintf(fp, "read_diskdump: PAGE_EXCLUDED: "
			    	    "paddr/pfn: %llx/%lx\n",
					(ulonglong)paddr, pfn);
			return PAGE_EXCLUDED;
		}
		if (CRASHDEBUG(8))
			fprintf(fp, "read_diskdump: zero-fill: "
		    	    "paddr/pfn: %llx/%lx\n",
				(ulonglong)paddr, pfn);
		memset(bufptr, 0, cnt);
		return cnt;
	}

	if (!page_is_cached(curpaddr)) {
		if (CRASHDEBUG(8))
			fprintf(fp, "read_diskdump: paddr/pfn: %llx/%lx"
			    " -> cache physical page: %llx\n",
				(ulonglong)paddr, pfn, (ulonglong)curpaddr);

		if ((ret = cache_page(curpaddr)) < 0) {
			if (CRASHDEBUG(8))
				fprintf(fp, "read_diskdump: " 
				    "%s: cannot cache page: %llx\n",
					ret == SEEK_ERROR ?  
					"SEEK_ERROR" : "READ_ERROR",
					(ulonglong)curpaddr);
			return ret;
		}
	} else if (CRASHDEBUG(8))
		fprintf(fp, "read_diskdump: paddr/pfn: %llx/%lx"
		    " -> physical page is cached: %llx\n", 
			(ulonglong)paddr, pfn, (ulonglong)curpaddr);
	
	memcpy(bufptr, dd->curbufptr + page_offset, cnt);
	return cnt;
}

/*
 *  Write to a diskdump-created dumpfile.
 */
int
write_diskdump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	return 0;
}

ulong
get_diskdump_panic_task(void)
{
	int i;

	if ((!DISKDUMP_VALID() && !KDUMP_CMPRS_VALID())
	    || !get_active_set())
		return NO_TASK;

	if (pc->flags2 & SNAP)
		return (task_exists(dd->snapshot_task) ? dd->snapshot_task : NO_TASK);

	if (DISKDUMP_VALID())
		return (ulong)dd->header->tasks[dd->header->current_cpu];

	if (KDUMP_CMPRS_VALID()) {
		if (kernel_symbol_exists("crashing_cpu") &&
		    cpu_map_addr("online")) {
			get_symbol_data("crashing_cpu", sizeof(int), &i);
			if ((i >= 0) && in_cpu_map(ONLINE_MAP, i)) {
				if (CRASHDEBUG(1))
					error(INFO, "get_diskdump_panic_task: "
					    "active_set[%d]: %lx\n", 
						i, tt->active_set[i]);
				return (tt->active_set[i]);
			}
		}
	}

	return NO_TASK;
}

extern void get_netdump_regs_x86(struct bt_info *, ulong *, ulong *);
extern void get_netdump_regs_x86_64(struct bt_info *, ulong *, ulong *);

static void
get_diskdump_regs_32(struct bt_info *bt, ulong *eip, ulong *esp)
{
	Elf32_Nhdr *note;
	int len;

	if (KDUMP_CMPRS_VALID() &&
		(bt->task == tt->panic_task || 
		(is_task_active(bt->task) && dd->num_prstatus_notes > 1))) {
		note  = (Elf32_Nhdr*) dd->nt_prstatus_percpu[bt->tc->processor];
		if (!note)
			error(FATAL,
				    "cannot determine NT_PRSTATUS ELF note "
				    "for %s task: %lx\n",
					(bt->task == tt->panic_task) ?
					"panic" : "active", bt->task);
		len = sizeof(Elf32_Nhdr);
		len = roundup(len + note->n_namesz, 4);
		bt->machdep = (void *)((char *)note + len +
			MEMBER_OFFSET("elf_prstatus", "pr_reg"));
	}

	machdep->get_stack_frame(bt, eip, esp);
}

static void
get_diskdump_regs_ppc(struct bt_info *bt, ulong *eip, ulong *esp)
{
	if (KDUMP_CMPRS_VALID())
		ppc_relocate_nt_prstatus_percpu(dd->nt_prstatus_percpu,
						&dd->num_prstatus_notes);

	get_diskdump_regs_32(bt, eip, esp);
}

static void
get_diskdump_regs_ppc64(struct bt_info *bt, ulong *eip, ulong *esp)
{
	int cpu;
	Elf64_Nhdr *note;
	size_t len;

	if ((bt->task == tt->panic_task) && DISKDUMP_VALID())
		bt->machdep = &dd->sub_header->elf_regs;
	else if (KDUMP_CMPRS_VALID() &&
		(bt->task == tt->panic_task ||
		(is_task_active(bt->task) && dd->num_prstatus_notes > 1))) {
		cpu = bt->tc->processor;
		if (dd->nt_prstatus_percpu[cpu] == NULL) {
			if(CRASHDEBUG(1))
				error(INFO,
				      "registers not collected for cpu %d\n",
				      cpu);
		} else {
			note = (Elf64_Nhdr *)
				dd->nt_prstatus_percpu[cpu];
			len = sizeof(Elf64_Nhdr);
			len = roundup(len + note->n_namesz, 4);
			bt->machdep = (void *)((char *)note + len +
				MEMBER_OFFSET("elf_prstatus", "pr_reg"));
		}
	}

	machdep->get_stack_frame(bt, eip, esp);
}

static void
get_diskdump_regs_arm(struct bt_info *bt, ulong *eip, ulong *esp)
{
	machdep->get_stack_frame(bt, eip, esp);
}

static void
get_diskdump_regs_arm64(struct bt_info *bt, ulong *eip, ulong *esp)
{
	machdep->get_stack_frame(bt, eip, esp);
}

static void
get_diskdump_regs_mips(struct bt_info *bt, ulong *eip, ulong *esp)
{
	machdep->get_stack_frame(bt, eip, esp);
}

static void
get_diskdump_regs_riscv64(struct bt_info *bt, ulong *eip, ulong *esp)
{
	machdep->get_stack_frame(bt, eip, esp);
}

static void
get_diskdump_regs_sparc64(struct bt_info *bt, ulong *eip, ulong *esp)
{
	Elf64_Nhdr *note;
	int len;

	if (KDUMP_CMPRS_VALID() &&
		(bt->task == tt->panic_task ||
		(is_task_active(bt->task) && dd->num_prstatus_notes > 1))) {
		note  = (Elf64_Nhdr *)dd->nt_prstatus_percpu[bt->tc->processor];
		if (!note)
			error(FATAL,
				    "cannot determine NT_PRSTATUS ELF note "
				    "for %s task: %lx\n",
					(bt->task == tt->panic_task) ?
					"panic" : "active", bt->task);
		len = sizeof(Elf64_Nhdr);
		len = roundup(len + note->n_namesz, 4);
		bt->machdep = (void *)((char *)note + len +
			MEMBER_OFFSET("elf_prstatus", "pr_reg"));
	}

	machdep->get_stack_frame(bt, eip, esp);
}

/*
 *  Send the request to the proper architecture hander.
 */

void
get_diskdump_regs(struct bt_info *bt, ulong *eip, ulong *esp)
{
	switch (dd->machine_type) 
	{
	case EM_ARM:
		get_diskdump_regs_arm(bt, eip, esp);
		break;

	case EM_MIPS:
		return get_diskdump_regs_mips(bt, eip, esp);
		break;

	case EM_386:
		return get_netdump_regs_x86(bt, eip, esp);
		break;

	case EM_IA_64:
	       /* For normal backtraces, this information will be obtained
		* frome the switch_stack structure, which is pointed to by
		* the thread.ksp field of the task_struct. But it's still
		* needed by the "bt -t" option.
		*/
		machdep->get_stack_frame(bt, eip, esp);
		break;

	case EM_PPC:
		return get_diskdump_regs_ppc(bt, eip, esp);
		break;

	case EM_PPC64:
		return get_diskdump_regs_ppc64(bt, eip, esp);
		break;

	case EM_X86_64:
		return get_netdump_regs_x86_64(bt, eip, esp);
		break;

	case EM_S390:
		return machdep->get_stack_frame(bt, eip, esp);
		break;

	case EM_AARCH64:
		get_diskdump_regs_arm64(bt, eip, esp);
		break;

	case EM_SPARCV9:
		get_diskdump_regs_sparc64(bt, eip, esp);
		break;

	case EM_RISCV:
		get_diskdump_regs_riscv64(bt, eip, esp);
		break;

	default:
		error(FATAL, "%s: unsupported machine type: %s\n",
			DISKDUMP_VALID() ? "diskdump" : "compressed kdump",
			MACHINE_TYPE);
	}
}

/*
 *  Return the processor page size.
 */
uint
diskdump_page_size(void)
{
	if (!DISKDUMP_VALID() && !KDUMP_CMPRS_VALID())
		return 0;

	return dd->header->block_size;
}

/*
 *  diskdump_free_memory(), and diskdump_memory_used() 
 *  are debug only, and probably unnecessary to implement.
 */
int
diskdump_free_memory(void)
{
        return 0;
}

int 
diskdump_memory_used(void)
{
        return 0;
}

static void 
dump_vmcoreinfo(FILE *fp)
{
	char *buf = NULL;
	unsigned long i = 0;
	unsigned long size_vmcoreinfo = dd->sub_header_kdump->size_vmcoreinfo;
	off_t offset = dd->sub_header_kdump->offset_vmcoreinfo;
	const off_t failed = (off_t)-1;

	if ((buf = malloc(size_vmcoreinfo)) == NULL) {
		error(FATAL, "compressed kdump: cannot malloc vmcoreinfo"
				" buffer\n");
	}

	if (FLAT_FORMAT()) {
		if (!read_flattened_format(dd->dfd, offset, buf, size_vmcoreinfo)) {
			error(INFO, "compressed kdump: cannot read vmcoreinfo data\n");
			goto err;
		}
	} else {
		if (lseek(dd->dfd, offset, SEEK_SET) == failed) {
			error(INFO, "compressed kdump: cannot lseek dump vmcoreinfo\n");
			goto err;
		}
		if (read(dd->dfd, buf, size_vmcoreinfo) < size_vmcoreinfo) {
			error(INFO, "compressed kdump: cannot read vmcoreinfo data\n");
			goto err;
		}
	}

	fprintf(fp, "                      ");
	for (i = 0; i < size_vmcoreinfo; i++) {
		fprintf(fp, "%c", buf[i]);
		if ((buf[i] == '\n') && ((i+1) != size_vmcoreinfo))
			fprintf(fp, "                      ");
	}
	if (buf[i-1] != '\n')
		fprintf(fp, "\n");
err:
	if (buf)
		free(buf);
	return;
}

static void 
dump_eraseinfo(FILE *fp)
{
	char *buf = NULL;
	unsigned long i = 0;
	unsigned long size_eraseinfo = dd->sub_header_kdump->size_eraseinfo;
	off_t offset = dd->sub_header_kdump->offset_eraseinfo;
	const off_t failed = (off_t)-1;

	if ((buf = malloc(size_eraseinfo)) == NULL) {
		error(FATAL, "compressed kdump: cannot malloc eraseinfo"
				" buffer\n");
	}

	if (FLAT_FORMAT()) {
		if (!read_flattened_format(dd->dfd, offset, buf, size_eraseinfo)) {
			error(INFO, "compressed kdump: cannot read eraseinfo data\n");
			goto err;
		}
	} else {
		if (lseek(dd->dfd, offset, SEEK_SET) == failed) {
			error(INFO, "compressed kdump: cannot lseek dump eraseinfo\n");
			goto err;
		}
		if (read(dd->dfd, buf, size_eraseinfo) < size_eraseinfo) {
			error(INFO, "compressed kdump: cannot read eraseinfo data\n");
			goto err;
		}
	}

	fprintf(fp, "                      ");
	for (i = 0; i < size_eraseinfo; i++) {
		fprintf(fp, "%c", buf[i]);
		if (buf[i] == '\n')
			fprintf(fp, "                      ");
	}
	if (buf[i - 1] != '\n')
		fprintf(fp, "\n");
err:
	if (buf)
		free(buf);
	return;
}

static void
dump_note_offsets(FILE *fp)
{
	struct kdump_sub_header *sub_header_kdump = dd->sub_header_kdump;
	size_t size;
	off_t offset;
	Elf32_Nhdr *note32 = NULL;
	Elf64_Nhdr *note64 = NULL;
	size_t tot, len = 0;
	int qemu, cnt;

	if (KDUMP_CMPRS_VALID() && !(dd->flags & NO_ELF_NOTES) &&
	    (dd->header->header_version >= 4) &&
	    (sub_header_kdump->offset_note) &&
	    (sub_header_kdump->size_note) && (machdep->process_elf_notes)) {
		size = sub_header_kdump->size_note;
		offset = sub_header_kdump->offset_note;

		fprintf(fp, "        NOTE offsets: ");
		for (tot = cnt = 0; tot < size; tot += len) {
			qemu = FALSE;
			if (machine_type("X86_64") || machine_type("S390X") ||
			    machine_type("ARM64") || machine_type("PPC64") ||
			    machine_type("SPARC64") || machine_type("MIPS64") ||
			    machine_type("RISCV64")) {
				note64 = (void *)dd->notes_buf + tot;
				len = sizeof(Elf64_Nhdr);
				if (STRNEQ((char *)note64 + len, "QEMU"))
					qemu = TRUE;
				len = roundup(len + note64->n_namesz, 4);
				len = roundup(len + note64->n_descsz, 4);

				if (note64->n_type == NT_PRSTATUS) {
					fprintf(fp, "%s%lx (NT_PRSTATUS)\n",
						tot ? space(22) : "",
						(ulong)(offset + tot));
					cnt++;
				} 
				if (qemu) {
					fprintf(fp, "%s%lx (QEMU)\n",
						tot ? space(22) : "",
						(ulong)(offset + tot));
					cnt++;
				}

			} else if (machine_type("X86") || machine_type("PPC")) {
				note32 = (void *)dd->notes_buf + tot;
				len = sizeof(Elf32_Nhdr);
				if (STRNEQ((char *)note32 + len, "QEMU"))
					qemu = TRUE;
				len = roundup(len + note32->n_namesz, 4);
				len = roundup(len + note32->n_descsz, 4);

				if (note32->n_type == NT_PRSTATUS) {
					fprintf(fp, "%s%lx (NT_PRSTATUS)\n",
						tot ? space(22) : "",
						(ulong)(offset + tot));
					cnt++;
				}
				if (qemu) {
					fprintf(fp, "%s%lx (QEMU)\n",
						tot ? space(22) : "",
						(ulong)(offset + tot));
					cnt++;
				}
			}
		}
		if (!cnt)
			fprintf(fp, "\n");
	}
}

/*
 *  This function is dump-type independent, and could be used
 *  to dump the diskdump_data structure contents and perhaps
 *  the diskdump header data.
 */
int
__diskdump_memory_dump(FILE *fp)
{
	int i, others, dump_level;
	struct disk_dump_header *dh;
	struct disk_dump_sub_header *dsh;
	struct kdump_sub_header *kdsh;
	ulong *tasks;

	if (FLAT_FORMAT())
		dump_flat_header(fp);

        fprintf(fp, "diskdump_data: \n");
	fprintf(fp, "          filename: %s\n", dd->filename);
        fprintf(fp, "             flags: %lx (", dd->flags);
        others = 0;
        if (dd->flags & DISKDUMP_LOCAL)
                fprintf(fp, "%sDISKDUMP_LOCAL", others++ ? "|" : "");
        if (dd->flags & KDUMP_CMPRS_LOCAL)
                fprintf(fp, "%sKDUMP_CMPRS_LOCAL", others++ ? "|" : "");
        if (dd->flags & ERROR_EXCLUDED)
                fprintf(fp, "%sERROR_EXCLUDED", others++ ? "|" : "");
        if (dd->flags & ZERO_EXCLUDED)
                fprintf(fp, "%sZERO_EXCLUDED", others++ ? "|" : "");
	if (dd->flags & NO_ELF_NOTES)
		fprintf(fp, "%sNO_ELF_NOTES", others++ ? "|" : "");
	if (dd->flags & LZO_SUPPORTED)
		fprintf(fp, "%sLZO_SUPPORTED", others++ ? "|" : "");
	if (dd->flags & SNAPPY_SUPPORTED)
		fprintf(fp, "%sSNAPPY_SUPPORTED", others++ ? "|" : "");
	if (dd->flags & ZSTD_SUPPORTED)
		fprintf(fp, "%sZSTD_SUPPORTED", others++ ? "|" : "");
        fprintf(fp, ") %s\n", FLAT_FORMAT() ? "[FLAT]" : "");
        fprintf(fp, "               dfd: %d\n", dd->dfd);
        fprintf(fp, "               ofp: %lx\n", (ulong)dd->ofp);
        fprintf(fp, "      machine_type: %d ", dd->machine_type);
	switch (dd->machine_type)
	{
	case EM_ARM:
		fprintf(fp, "(EM_ARM)\n"); break;
	case EM_MIPS:
		fprintf(fp, "(EM_MIPS)\n"); break;
	case EM_386:
		fprintf(fp, "(EM_386)\n"); break;
	case EM_X86_64:
		fprintf(fp, "(EM_X86_64)\n"); break;
	case EM_IA_64:
		fprintf(fp, "(EM_IA_64)\n"); break;
	case EM_PPC:
		fprintf(fp, "(EM_PPC)\n"); break;
	case EM_PPC64:
		fprintf(fp, "(EM_PPC64)\n"); break;
	case EM_S390:
		fprintf(fp, "(EM_S390)\n"); break;
	case EM_AARCH64:
		fprintf(fp, "(EM_AARCH64)\n"); break;
	case EM_SPARCV9:
		fprintf(fp, "(EM_SPARCV9)\n"); break;
	default:
		fprintf(fp, "(unknown)\n"); break;
	}

        fprintf(fp, "\n            header: %lx\n", (ulong)dd->header);
	dh = dd->header;
	fprintf(fp, "           signature: \"");
	for (i = 0; i < SIG_LEN; i++)
		if (dh->signature[i])
			fprintf(fp, "%c", dh->signature[i]);
	fprintf(fp, "\"\n");
	fprintf(fp, "      header_version: %d\n", dh->header_version);
	fprintf(fp, "             utsname:\n");
	fprintf(fp, "               sysname: %s\n", dh->utsname.sysname);
	fprintf(fp, "              nodename: %s\n", dh->utsname.nodename);
	fprintf(fp, "               release: %s\n", dh->utsname.release);
	fprintf(fp, "               version: %s\n", dh->utsname.version);
	fprintf(fp, "               machine: %s\n", dh->utsname.machine);
	fprintf(fp, "            domainname: %s\n", dh->utsname.domainname);
	fprintf(fp, "           timestamp:\n");
	fprintf(fp, "                tv_sec: %lx\n", dh->timestamp.tv_sec);
	fprintf(fp, "               tv_usec: %lx\n", dh->timestamp.tv_usec);
	fprintf(fp, "              status: %x (", dh->status);
	switch (dd->flags & (DISKDUMP_LOCAL|KDUMP_CMPRS_LOCAL))
	{
        case DISKDUMP_LOCAL:
		if (dh->status == DUMP_HEADER_COMPLETED)
			fprintf(fp, "DUMP_HEADER_COMPLETED");
		else if (dh->status == DUMP_HEADER_INCOMPLETED)
			fprintf(fp, "DUMP_HEADER_INCOMPLETED");
		else if (dh->status == DUMP_HEADER_COMPRESSED)
			fprintf(fp, "DUMP_HEADER_COMPRESSED");
		break;
	case KDUMP_CMPRS_LOCAL:
		if (dh->status & DUMP_DH_COMPRESSED_ZLIB)
			fprintf(fp, "DUMP_DH_COMPRESSED_ZLIB");
		if (dh->status & DUMP_DH_COMPRESSED_LZO)
			fprintf(fp, "DUMP_DH_COMPRESSED_LZO");
		if (dh->status & DUMP_DH_COMPRESSED_SNAPPY)
			fprintf(fp, "DUMP_DH_COMPRESSED_SNAPPY");
		if (dh->status & DUMP_DH_COMPRESSED_ZSTD)
			fprintf(fp, "DUMP_DH_COMPRESSED_ZSTD");
		if (dh->status & DUMP_DH_COMPRESSED_INCOMPLETE)
			fprintf(fp, "DUMP_DH_COMPRESSED_INCOMPLETE");
		if (dh->status & DUMP_DH_EXCLUDED_VMEMMAP)
			fprintf(fp, "DUMP_DH_EXCLUDED_VMEMMAP");
		break;
	}
	fprintf(fp, ")\n");
	fprintf(fp, "          block_size: %d\n", dh->block_size);
	fprintf(fp, "        sub_hdr_size: %d\n", dh->sub_hdr_size);
	fprintf(fp, "       bitmap_blocks: %u\n", dh->bitmap_blocks);
	fprintf(fp, "           max_mapnr: %u\n", dh->max_mapnr);
	fprintf(fp, "    total_ram_blocks: %u\n", dh->total_ram_blocks);
	fprintf(fp, "       device_blocks: %u\n", dh->device_blocks);
	fprintf(fp, "      written_blocks: %u\n", dh->written_blocks);
	fprintf(fp, "         current_cpu: %u\n", dh->current_cpu);
	fprintf(fp, "             nr_cpus: %d\n", dh->nr_cpus);
	tasks = (ulong *)&dh->tasks[0];
	fprintf(fp, "      tasks[nr_cpus]: %lx\n", *tasks);
	for (tasks++, i = 1; i < dh->nr_cpus; i++) {
		fprintf(fp, "                      %lx\n", *tasks);
		tasks++;
	}
        fprintf(fp, "\n");
	fprintf(fp, "        sub_header: %lx ", (ulong)dd->sub_header);
	if ((dsh = dd->sub_header)) {
		fprintf(fp, "\n            elf_regs: %lx\n", 
			(ulong)&dsh->elf_regs);
		fprintf(fp, "          dump_level: ");
		if ((pc->flags & RUNTIME) && 
		    ((dump_level = get_dump_level()) >= 0)) {
			fprintf(fp, "%d (0x%x) %s", dump_level, dump_level, 
				dump_level ? "(" : "");

#define DUMP_EXCLUDE_CACHE 0x00000001   /* Exclude LRU & SwapCache pages*/
#define DUMP_EXCLUDE_CLEAN 0x00000002   /* Exclude all-zero pages */
#define DUMP_EXCLUDE_FREE  0x00000004   /* Exclude free pages */
#define DUMP_EXCLUDE_ANON  0x00000008   /* Exclude Anon pages */
#define DUMP_SAVE_PRIVATE  0x00000010   /* Save private pages */

		        others = 0;
        		if (dump_level & DUMP_EXCLUDE_CACHE)
                		fprintf(fp, "%sDUMP_EXCLUDE_CACHE", 
					others++ ? "|" : "");
        		if (dump_level & DUMP_EXCLUDE_CLEAN)
                		fprintf(fp, "%sDUMP_EXCLUDE_CLEAN", 
					others++ ? "|" : "");
        		if (dump_level & DUMP_EXCLUDE_FREE)
                		fprintf(fp, "%sDUMP_EXCLUDE_FREE", 
					others++ ? "|" : "");
        		if (dump_level & DUMP_EXCLUDE_ANON)
                		fprintf(fp, "%sDUMP_EXCLUDE_ANON", 
					others++ ? "|" : "");
        		if (dump_level & DUMP_SAVE_PRIVATE)
                		fprintf(fp, "%sDUMP_SAVE_PRIVATE", 
					others++ ? "|" : "");
			fprintf(fp, "%s\n\n", dump_level ? ")" : "");
		} else
			fprintf(fp, "%s\n\n", pc->flags & RUNTIME ? 
				"(unknown)" : "(undetermined)");

	} else
        	fprintf(fp, "(n/a)\n\n");

	fprintf(fp, "  sub_header_kdump: %lx ", (ulong)dd->sub_header_kdump);
	if ((kdsh = dd->sub_header_kdump)) {
		fprintf(fp, "\n           phys_base: %lx\n", 
			(ulong)kdsh->phys_base);
		fprintf(fp, "          dump_level: ");
		if ((dump_level = get_dump_level()) >= 0) {
			fprintf(fp, "%d (0x%x) %s", dump_level, dump_level, 
				dump_level ? "(" : "");

#define DL_EXCLUDE_ZERO         (0x001) /* Exclude Pages filled with Zeros */
#define DL_EXCLUDE_CACHE        (0x002) /* Exclude Cache Pages without Private Pages */
#define DL_EXCLUDE_CACHE_PRI    (0x004) /* Exclude Cache Pages with Private Pages */
#define DL_EXCLUDE_USER_DATA    (0x008) /* Exclude UserProcessData Pages */
#define DL_EXCLUDE_FREE         (0x010) /* Exclude Free Pages */

			others = 0;
        		if (dump_level & DL_EXCLUDE_ZERO)
                		fprintf(fp, "%sDUMP_EXCLUDE_ZERO", 
					others++ ? "|" : "");
        		if (dump_level & DL_EXCLUDE_CACHE)
                		fprintf(fp, "%sDUMP_EXCLUDE_CACHE", 
					others++ ? "|" : "");
        		if (dump_level & DL_EXCLUDE_CACHE_PRI)
                		fprintf(fp, "%sDUMP_EXCLUDE_CACHE_PRI", 
					others++ ? "|" : "");
        		if (dump_level & DL_EXCLUDE_USER_DATA)
                		fprintf(fp, "%sDUMP_EXCLUDE_USER_DATA", 
					others++ ? "|" : "");
        		if (dump_level & DL_EXCLUDE_FREE)
                		fprintf(fp, "%sDUMP_EXCLUDE_FREE", 
					others++ ? "|" : "");
			others = 0;

			fprintf(fp, "%s\n", dump_level ? ")" : "");
		} else
			fprintf(fp, "(unknown)\n");

		if (dh->header_version >= 2) {
			fprintf(fp, "               split: %d\n", kdsh->split);
			fprintf(fp, "           start_pfn: ");
			if (KDUMP_SPLIT())
				fprintf(fp, "%ld (0x%lx)\n", 
					kdsh->start_pfn, kdsh->start_pfn);
			else
				fprintf(fp, "(unused)\n");
			fprintf(fp, "             end_pfn: ");
			if (KDUMP_SPLIT())
				fprintf(fp, "%ld (0x%lx)\n", 
					kdsh->end_pfn, kdsh->end_pfn);
			else
				fprintf(fp, "(unused)\n");
		}
		if (dh->header_version >= 3) {
			fprintf(fp, "   offset_vmcoreinfo: %llu (0x%llx)\n",
				(ulonglong)dd->sub_header_kdump->offset_vmcoreinfo,
				(ulonglong)dd->sub_header_kdump->offset_vmcoreinfo);
			fprintf(fp, "     size_vmcoreinfo: %lu (0x%lx)\n",
				dd->sub_header_kdump->size_vmcoreinfo,
				dd->sub_header_kdump->size_vmcoreinfo);
			if (dd->sub_header_kdump->offset_vmcoreinfo &&
				dd->sub_header_kdump->size_vmcoreinfo) {
				dump_vmcoreinfo(fp);
			}
		}
		if (dh->header_version >= 4) {
			fprintf(fp, "         offset_note: %llu (0x%llx)\n",
				(ulonglong)dd->sub_header_kdump->offset_note,
				(ulonglong)dd->sub_header_kdump->offset_note);
			fprintf(fp, "           size_note: %lu (0x%lx)\n",
				dd->sub_header_kdump->size_note,
				dd->sub_header_kdump->size_note);
			fprintf(fp, "           notes_buf: %lx\n",
				(ulong)dd->notes_buf);
			fprintf(fp, "  num_vmcoredd_notes: %d\n",
				dd->num_vmcoredd_notes);
			for (i = 0; i < dd->num_vmcoredd_notes; i++) {
				fprintf(fp, "            notes[%d]: %lx %s\n",
					i, (ulong)dd->nt_vmcoredd_array[i],
					dd->nt_vmcoredd_array[i] ? "(NT_VMCOREDD)" : "");
				display_vmcoredd_note(dd->nt_vmcoredd_array[i], fp);
			}

			fprintf(fp, "  num_prstatus_notes: %d\n",
				dd->num_prstatus_notes);
			for (i = 0; i < dd->num_prstatus_notes; i++) {
				fprintf(fp, "            notes[%d]: %lx %s\n",
					i, (ulong)dd->nt_prstatus_percpu[i],
					dd->nt_prstatus_percpu[i] ? "(NT_PRSTATUS)" : ""); 
				display_ELF_note(dd->machine_type, PRSTATUS_NOTE,
					 dd->nt_prstatus_percpu[i], fp);
			}
			fprintf(fp, "       snapshot_task: %lx %s\n", dd->snapshot_task, 
				dd->snapshot_task ? "(NT_TASKSTRUCT)" : "");
			fprintf(fp, "      num_qemu_notes: %d\n",
				dd->num_qemu_notes);
			for (i = 0; i < dd->num_qemu_notes; i++) {
				fprintf(fp, "            notes[%d]: %lx (QEMUCPUState)\n",
					i, (ulong)dd->nt_qemu_percpu[i]);
				display_ELF_note(dd->machine_type, QEMU_NOTE,
					dd->nt_qemu_percpu[i], fp);
			}
			dump_note_offsets(fp);
		}
		if (dh->header_version >= 5) {
			fprintf(fp, "    offset_eraseinfo: %llu (0x%llx)\n",
				(ulonglong)dd->sub_header_kdump->offset_eraseinfo,
				(ulonglong)dd->sub_header_kdump->offset_eraseinfo);
			fprintf(fp, "      size_eraseinfo: %lu (0x%lx)\n",
				dd->sub_header_kdump->size_eraseinfo,
				dd->sub_header_kdump->size_eraseinfo);
			if (dd->sub_header_kdump->offset_eraseinfo &&
				dd->sub_header_kdump->size_eraseinfo) {
				dump_eraseinfo(fp);
			}
		}
		if (dh->header_version >= 6) {
			fprintf(fp, "        start_pfn_64: ");
			if (KDUMP_SPLIT())
				fprintf(fp, "%lld (0x%llx)\n",
					kdsh->start_pfn_64, kdsh->start_pfn_64);
			else
				fprintf(fp, "(unused)\n");
			fprintf(fp, "          end_pfn_64: ");
			if (KDUMP_SPLIT())
				fprintf(fp, "%lld (0x%llx)\n",
					kdsh->end_pfn_64, kdsh->end_pfn_64);
			else
				fprintf(fp, "(unused)\n");

			fprintf(fp, "        max_mapnr_64: %llu (0x%llx)\n",
				kdsh->max_mapnr_64, kdsh->max_mapnr_64);
		}
		fprintf(fp, "\n");
	} else
        	fprintf(fp, "(n/a)\n\n");

	fprintf(fp, "       data_offset: %lx\n", (ulong)dd->data_offset);
	fprintf(fp, "        block_size: %d\n", dd->block_size);
	fprintf(fp, "       block_shift: %d\n", dd->block_shift);
	fprintf(fp, "            bitmap: %lx\n", (ulong)dd->bitmap);
	fprintf(fp, "        bitmap_len: %lld\n", (ulonglong)dd->bitmap_len);
	fprintf(fp, "         max_mapnr: %lld (0x%llx)\n", dd->max_mapnr, dd->max_mapnr);
	fprintf(fp, "   dumpable_bitmap: %lx\n", (ulong)dd->dumpable_bitmap);
	fprintf(fp, "              byte: %d\n", dd->byte);
	fprintf(fp, "               bit: %d\n", dd->bit);
	fprintf(fp, "   compressed_page: %lx\n", (ulong)dd->compressed_page);
	fprintf(fp, "         curbufptr: %lx\n\n", (ulong)dd->curbufptr);

	for (i = 0; i < DISKDUMP_CACHED_PAGES; i++) {
		fprintf(fp, "%spage_cache_hdr[%d]:\n", i < 10 ? " " : "", i);
		fprintf(fp, "            pg_flags: %x (", dd->page_cache_hdr[i].pg_flags);
		others = 0;
		if (dd->page_cache_hdr[i].pg_flags & PAGE_VALID)
                	fprintf(fp, "%sPAGE_VALID", others++ ? "|" : "");
		fprintf(fp, ")\n");
		fprintf(fp, "             pg_addr: %llx\n", (ulonglong)dd->page_cache_hdr[i].pg_addr);
		fprintf(fp, "           pg_bufptr: %lx\n", (ulong)dd->page_cache_hdr[i].pg_bufptr);
		fprintf(fp, "        pg_hit_count: %ld\n", dd->page_cache_hdr[i].pg_hit_count);
	}

	fprintf(fp, "\n    page_cache_buf: %lx\n", (ulong)dd->page_cache_buf);
	fprintf(fp, "       evict_index: %d\n", dd->evict_index);
	fprintf(fp, "         evictions: %ld\n", dd->evictions);
	fprintf(fp, "          accesses: %ld\n", dd->accesses);
	fprintf(fp, "      cached_reads: %ld ", dd->cached_reads);
	if (dd->accesses)
		fprintf(fp, "(%ld%%)\n",
			dd->cached_reads * 100 / dd->accesses);
	else
		fprintf(fp, "\n");
	fprintf(fp, "       valid_pages: %lx\n", (ulong)dd->valid_pages);
	fprintf(fp, " total_valid_pages: %ld\n", dd->valid_pages[dd->max_sect_len]);

	return 0;
}

/*
 * Wrapper of __diskdump_memory_dump()
 */
int
diskdump_memory_dump(FILE *fp)
{
	int i;

	if (KDUMP_SPLIT() && (dd_list != NULL))
		for (i = 0; i < num_dumpfiles; i++) {
			dd = dd_list[i];
			__diskdump_memory_dump(fp);
			fprintf(fp, "\n");
		}
	else
		__diskdump_memory_dump(fp);

	return 0;
}


/*
 *  Get the switch_stack address of the passed-in task.  
 */
ulong
get_diskdump_switch_stack(ulong task)
{
	return 0;
}

/*
 *  Versions of disk_dump that support it contain the "dump_level" symbol.
 *  Version 1 and later compressed kdump dumpfiles contain the dump level
 *  in an additional field of the sub_header_kdump structure.
 */
int
get_dump_level(void)
{
	int dump_level;

	if (DISKDUMP_VALID()) {
		if (symbol_exists("dump_level") &&
		    readmem(symbol_value("dump_level"), KVADDR, &dump_level,
		    sizeof(dump_level), "dump_level", QUIET|RETURN_ON_ERROR))
                 	return dump_level;
	} else if (KDUMP_CMPRS_VALID()) {
		if (dd->header->header_version >= 1)
			return dd->sub_header_kdump->dump_level;
	}

	return -1;
}

/*
 *  Used by the "sys" command to display [PARTIAL DUMP] 
 *  after the dumpfile name.
 */
int 
is_partial_diskdump(void) 
{
	return (get_dump_level() > 0 ? TRUE : FALSE);
}

/*
 *  Used by "sys" command to dump multiple split dumpfiles.
 */
void
show_split_dumpfiles(void)
{
	int i;
	struct diskdump_data *ddp;
	struct disk_dump_header *dh;

        for (i = 0; i < num_dumpfiles; i++) {
        	ddp = dd_list[i];
		dh = ddp->header;
		fprintf(fp, "%s%s%s%s%s", 
			i ? "              " : "", 
			ddp->filename, 
			is_partial_diskdump() ? " [PARTIAL DUMP]" : "",
			dh->status & DUMP_DH_COMPRESSED_INCOMPLETE ? 
			" [INCOMPLETE]" : "",
			dh->status & DUMP_DH_EXCLUDED_VMEMMAP ? 
			" [EXCLUDED VMEMMAP]" : "");
		if ((i+1) < num_dumpfiles)
			fprintf(fp, "\n");
	}
}

void *
diskdump_get_prstatus_percpu(int cpu)
{
	int online;

	if ((cpu < 0) || (cpu >= dd->num_prstatus_notes))
		return NULL;

	/*
	 * If no cpu mapping was done, then there must be
	 * a one-to-one relationship between the number
	 * of online cpus and the number of notes.
	 */
        if ((online = get_cpus_online()) && 
	    (online == kt->cpus) &&
	    (online != dd->num_prstatus_notes))
                return NULL;

	return dd->nt_prstatus_percpu[cpu];
}

/*
 * Reads a string value from VMCOREINFO.
 *
 * Returns a string (that has to be freed by the caller) that contains the
 * value for key or NULL if the key has not been found.
 */
static char *
vmcoreinfo_read_string(const char *key)
{
	char *buf, *value_string, *p1, *p2;
	size_t value_length;
	ulong size_vmcoreinfo;
	off_t offset;
	char keybuf[BUFSIZE];
	const off_t failed = (off_t)-1;

	if (dd->header->header_version < 3)
		return NULL;

	buf = value_string = NULL;
	size_vmcoreinfo = dd->sub_header_kdump->size_vmcoreinfo;
	offset = dd->sub_header_kdump->offset_vmcoreinfo;
	sprintf(keybuf, "%s=", key);

	if ((buf = malloc(size_vmcoreinfo+1)) == NULL) {
		error(INFO, "compressed kdump: cannot malloc vmcoreinfo"
			    " buffer\n");
		goto err;
	}

	if (FLAT_FORMAT()) {
		if (!read_flattened_format(dd->dfd, offset, buf, size_vmcoreinfo)) {
			error(INFO, "compressed kdump: cannot read vmcoreinfo data\n");
			goto err;
		}
	} else {
		if (lseek(dd->dfd, offset, SEEK_SET) == failed) {
			error(INFO, "compressed kdump: cannot lseek dump vmcoreinfo\n");
			goto err;
		}
		if (read(dd->dfd, buf, size_vmcoreinfo) < size_vmcoreinfo) {
			error(INFO, "compressed kdump: cannot read vmcoreinfo data\n");
			goto err;
		}
	}

	buf[size_vmcoreinfo] = '\n';

	if ((p1 = strstr(buf, keybuf))) {
		p2 = p1 + strlen(keybuf);
		p1 = strstr(p2, "\n");
		value_length = p1-p2;
		value_string = calloc(value_length+1, sizeof(char));
		strncpy(value_string, p2, value_length);
		value_string[value_length] = NULLCHAR;
	}
err:
	if (buf)
		free(buf);

	return value_string;
}

static void
diskdump_get_osrelease(void)
{
	char *string;

	if ((string = vmcoreinfo_read_string("OSRELEASE"))) {
		fprintf(fp, "%s\n", string);
		free(string);
	}
	else
		pc->flags2 &= ~GET_OSRELEASE;
}

static int
valid_note_address(unsigned char *offset)
{
	if (offset > (dd->notes_buf + dd->sub_header_kdump->size_note))
		return FALSE;
	
	return TRUE;
}

void
diskdump_display_regs(int cpu, FILE *ofp)
{
	Elf32_Nhdr *note32;
	Elf64_Nhdr *note64;
	char *user_regs;
	size_t len;

	if ((cpu < 0) || (cpu >= dd->num_prstatus_notes) ||
	    (dd->nt_prstatus_percpu[cpu] == NULL)) {
		error(INFO, "registers not collected for cpu %d\n", cpu);
                return;
	}

	if (machine_type("X86_64")) {
		note64 = dd->nt_prstatus_percpu[cpu];
		len = sizeof(Elf64_Nhdr);
		len = roundup(len + note64->n_namesz, 4);
		len = roundup(len + note64->n_descsz, 4);
		if (!valid_note_address((unsigned char *)note64 + len)) {
			error(INFO, "invalid NT_PRSTATUS note for cpu %d\n", cpu);
			return;
		}
		user_regs = (char *)note64 + len - SIZE(user_regs_struct) - sizeof(long);
		fprintf(ofp,
		    "    RIP: %016llx  RSP: %016llx  RFLAGS: %08llx\n"
		    "    RAX: %016llx  RBX: %016llx  RCX: %016llx\n"
		    "    RDX: %016llx  RSI: %016llx  RDI: %016llx\n"
		    "    RBP: %016llx   R8: %016llx   R9: %016llx\n"
		    "    R10: %016llx  R11: %016llx  R12: %016llx\n"
		    "    R13: %016llx  R14: %016llx  R15: %016llx\n"
		    "    CS: %04x  SS: %04x\n",
		    ULONGLONG(user_regs + OFFSET(user_regs_struct_rip)),
		    ULONGLONG(user_regs + OFFSET(user_regs_struct_rsp)),
		    ULONGLONG(user_regs + OFFSET(user_regs_struct_eflags)),
		    ULONGLONG(user_regs + OFFSET(user_regs_struct_rax)),
		    ULONGLONG(user_regs + OFFSET(user_regs_struct_rbx)),
		    ULONGLONG(user_regs + OFFSET(user_regs_struct_rcx)),
		    ULONGLONG(user_regs + OFFSET(user_regs_struct_rdx)),
		    ULONGLONG(user_regs + OFFSET(user_regs_struct_rsi)),
		    ULONGLONG(user_regs + OFFSET(user_regs_struct_rdi)),
		    ULONGLONG(user_regs + OFFSET(user_regs_struct_rbp)),
		    ULONGLONG(user_regs + OFFSET(user_regs_struct_r8)),
		    ULONGLONG(user_regs + OFFSET(user_regs_struct_r9)),
		    ULONGLONG(user_regs + OFFSET(user_regs_struct_r10)),
		    ULONGLONG(user_regs + OFFSET(user_regs_struct_r11)),
		    ULONGLONG(user_regs + OFFSET(user_regs_struct_r12)),
		    ULONGLONG(user_regs + OFFSET(user_regs_struct_r13)),
		    ULONGLONG(user_regs + OFFSET(user_regs_struct_r14)),
		    ULONGLONG(user_regs + OFFSET(user_regs_struct_r15)),
		    USHORT(user_regs + OFFSET(user_regs_struct_cs)),
		    USHORT(user_regs + OFFSET(user_regs_struct_ss))
		);
	}

	if (machine_type("PPC64")) {
		struct ppc64_elf_prstatus *prs;
		struct ppc64_pt_regs *pr;

		note64 = dd->nt_prstatus_percpu[cpu];
		len = sizeof(Elf64_Nhdr);
		len = roundup(len + note64->n_namesz, 4);
		len = roundup(len + note64->n_descsz, 4);
		if (!valid_note_address((unsigned char *)note64 + len)) {
			error(INFO, "invalid NT_PRSTATUS note for cpu %d\n", cpu);
			return;
		}

		prs = (struct ppc64_elf_prstatus *)
			((char *)note64 + sizeof(Elf64_Nhdr) + note64->n_namesz);
		prs = (struct ppc64_elf_prstatus *)roundup((ulong)prs, 4);
		pr = &prs->pr_reg;

		fprintf(ofp, 
			"     R0: %016lx   R1: %016lx   R2: %016lx\n"
			"     R3: %016lx   R4: %016lx   R5: %016lx\n"
			"     R6: %016lx   R7: %016lx   R8: %016lx\n"
			"     R9: %016lx  R10: %016lx  R11: %016lx\n"
			"    R12: %016lx  R13: %016lx  R14: %016lx\n"
			"    R15: %016lx  R16: %016lx  R16: %016lx\n"
			"    R18: %016lx  R19: %016lx  R20: %016lx\n"
			"    R21: %016lx  R22: %016lx  R23: %016lx\n"
			"    R24: %016lx  R25: %016lx  R26: %016lx\n"
			"    R27: %016lx  R28: %016lx  R29: %016lx\n"
			"    R30: %016lx  R31: %016lx\n"
			"      NIP: %016lx     MSR: %016lx\n"
			"    OGPR3: %016lx     CTR: %016lx\n"  
			"     LINK: %016lx     XER: %016lx\n"
			"      CCR: %016lx      MQ: %016lx\n"
			"     TRAP: %016lx     DAR: %016lx\n"
			"    DSISR: %016lx  RESULT: %016lx\n",
			pr->gpr[0], pr->gpr[1], pr->gpr[2],
			pr->gpr[3], pr->gpr[4], pr->gpr[5],
			pr->gpr[6], pr->gpr[7], pr->gpr[8],
			pr->gpr[9], pr->gpr[10], pr->gpr[11],
			pr->gpr[12], pr->gpr[13], pr->gpr[14],
			pr->gpr[15], pr->gpr[16], pr->gpr[17],
			pr->gpr[18], pr->gpr[19], pr->gpr[20],
			pr->gpr[21], pr->gpr[22], pr->gpr[23],
			pr->gpr[24], pr->gpr[25], pr->gpr[26],
			pr->gpr[27], pr->gpr[28], pr->gpr[29],
			pr->gpr[30], pr->gpr[31],
			pr->nip, pr->msr, 
			pr->orig_gpr3, pr->ctr,
			pr->link, pr->xer,
			pr->ccr, pr->mq,
			pr->trap,  pr->dar, 
			pr->dsisr, pr->result);
	}

	if (machine_type("ARM64")) {
		note64 = dd->nt_prstatus_percpu[cpu];
		len = sizeof(Elf64_Nhdr);
		len = roundup(len + note64->n_namesz, 4);
		len = roundup(len + note64->n_descsz, 4);
		if (!valid_note_address((unsigned char *)note64 + len)) {
			error(INFO, "invalid NT_PRSTATUS note for cpu %d\n", cpu);
			return;
		}
		user_regs = (char *)note64 + len - SIZE(elf_prstatus) + OFFSET(elf_prstatus_pr_reg);
		fprintf(ofp,
			"    X0: %016lx   X1: %016lx   X2: %016lx\n"
			"    X3: %016lx   X4: %016lx   X5: %016lx\n"
			"    X6: %016lx   X7: %016lx   X8: %016lx\n"
			"    X9: %016lx  X10: %016lx  X11: %016lx\n"
			"   X12: %016lx  X13: %016lx  X14: %016lx\n"
			"   X15: %016lx  X16: %016lx  X17: %016lx\n"
			"   X18: %016lx  X19: %016lx  X20: %016lx\n"
			"   X21: %016lx  X22: %016lx  X23: %016lx\n"
			"   X24: %016lx  X25: %016lx  X26: %016lx\n"
			"   X27: %016lx  X28: %016lx  X29: %016lx\n"
			"    LR: %016lx   SP: %016lx   PC: %016lx\n"
			"   PSTATE: %08lx   FPVALID: %08x\n", 
			ULONG(user_regs + sizeof(ulong) * 0),
			ULONG(user_regs + sizeof(ulong) * 1),
			ULONG(user_regs + sizeof(ulong) * 2),
			ULONG(user_regs + sizeof(ulong) * 3),
			ULONG(user_regs + sizeof(ulong) * 4),
			ULONG(user_regs + sizeof(ulong) * 5),
			ULONG(user_regs + sizeof(ulong) * 6),
			ULONG(user_regs + sizeof(ulong) * 7),
			ULONG(user_regs + sizeof(ulong) * 8),
			ULONG(user_regs + sizeof(ulong) * 9),
			ULONG(user_regs + sizeof(ulong) * 10),
			ULONG(user_regs + sizeof(ulong) * 11),
			ULONG(user_regs + sizeof(ulong) * 12),
			ULONG(user_regs + sizeof(ulong) * 13),
			ULONG(user_regs + sizeof(ulong) * 14),
			ULONG(user_regs + sizeof(ulong) * 15),
			ULONG(user_regs + sizeof(ulong) * 16),
			ULONG(user_regs + sizeof(ulong) * 17),
			ULONG(user_regs + sizeof(ulong) * 18),
			ULONG(user_regs + sizeof(ulong) * 19),
			ULONG(user_regs + sizeof(ulong) * 20),
			ULONG(user_regs + sizeof(ulong) * 21),
			ULONG(user_regs + sizeof(ulong) * 22),
			ULONG(user_regs + sizeof(ulong) * 23),
			ULONG(user_regs + sizeof(ulong) * 24),
			ULONG(user_regs + sizeof(ulong) * 25),
			ULONG(user_regs + sizeof(ulong) * 26),
			ULONG(user_regs + sizeof(ulong) * 27),
			ULONG(user_regs + sizeof(ulong) * 28),
			ULONG(user_regs + sizeof(ulong) * 29),
			ULONG(user_regs + sizeof(ulong) * 30),
			ULONG(user_regs + sizeof(ulong) * 31),
			ULONG(user_regs + sizeof(ulong) * 32),
			ULONG(user_regs + sizeof(ulong) * 33),
			UINT(user_regs + sizeof(ulong) * 34));
	}

	if (machine_type("X86")) {
		note32 = dd->nt_prstatus_percpu[cpu];
		len = sizeof(Elf32_Nhdr);
		len = roundup(len + note32->n_namesz, 4);
		len = roundup(len + note32->n_descsz, 4);
		user_regs = (char *)note32 + len - SIZE(user_regs_struct) - sizeof(int);
		if (!valid_note_address((unsigned char *)note32 + len)) {
			error(INFO, "invalid NT_PRSTATUS note for cpu %d\n", cpu);
			return;
		}
		fprintf(ofp,
		    "    EAX: %08x  EBX: %08x  ECX: %08x  EDX: %08x\n"
		    "    ESP: %08x  EIP: %08x  ESI: %08x  EDI: %08x\n"
		    "    CS: %04x       DS: %04x       ES: %04x       FS: %04x\n"
		    "    GS: %04x       SS: %04x\n"
		    "    EBP: %08x  EFLAGS: %08x\n",
		    UINT(user_regs + OFFSET(user_regs_struct_eax)),
		    UINT(user_regs + OFFSET(user_regs_struct_ebx)),
		    UINT(user_regs + OFFSET(user_regs_struct_ecx)),
		    UINT(user_regs + OFFSET(user_regs_struct_edx)),
		    UINT(user_regs + OFFSET(user_regs_struct_esp)),
		    UINT(user_regs + OFFSET(user_regs_struct_eip)),
		    UINT(user_regs + OFFSET(user_regs_struct_esi)),
		    UINT(user_regs + OFFSET(user_regs_struct_edi)),
		    USHORT(user_regs + OFFSET(user_regs_struct_cs)),
		    USHORT(user_regs + OFFSET(user_regs_struct_ds)),
		    USHORT(user_regs + OFFSET(user_regs_struct_es)),
		    USHORT(user_regs + OFFSET(user_regs_struct_fs)),
		    USHORT(user_regs + OFFSET(user_regs_struct_gs)),
		    USHORT(user_regs + OFFSET(user_regs_struct_ss)),
		    UINT(user_regs + OFFSET(user_regs_struct_ebp)),
		    UINT(user_regs + OFFSET(user_regs_struct_eflags))
		);
	}

	if (machine_type("MIPS"))
		mips_display_regs_from_elf_notes(cpu, ofp);

	if (machine_type("MIPS64"))
		mips64_display_regs_from_elf_notes(cpu, ofp);
}

void
dump_registers_for_compressed_kdump(void)
{
	int c;

	if (!KDUMP_CMPRS_VALID() || (dd->header->header_version < 4) ||
	    !(machine_type("X86") || machine_type("X86_64") ||
	      machine_type("ARM64") || machine_type("PPC64") ||
	      machine_type("MIPS") || machine_type("MIPS64") ||
	      machine_type("RISCV64")))
		error(FATAL, "-r option not supported for this dumpfile\n");

	if (machine_type("ARM64") && (kt->cpus != dd->num_prstatus_notes))
		fprintf(fp, "NOTE: cpus: %d  NT_PRSTATUS notes: %d  "
			"(note-to-cpu mapping is questionable)\n\n", 
			kt->cpus, dd->num_prstatus_notes);

	for (c = 0; c < kt->cpus; c++) {
		if (hide_offline_cpu(c)) {
			fprintf(fp, "%sCPU %d: [OFFLINE]\n", c ? "\n" : "", c);
			continue;
		} else
			fprintf(fp, "%sCPU %d:\n", c ? "\n" : "", c);
		diskdump_display_regs(c, fp);
	}
}

int
diskdump_kaslr_check()
{
	if (!QEMU_MEM_DUMP_NO_VMCOREINFO())
		return FALSE;

	if (dd->num_qemu_notes)
		return TRUE;

	return FALSE;
}

int
diskdump_get_nr_cpus(void)
{
        if (dd->num_prstatus_notes)
                return dd->num_prstatus_notes;
        else if (dd->num_qemu_notes)
                return dd->num_qemu_notes;
        else if (dd->num_vmcoredd_notes)
                return dd->num_vmcoredd_notes;
        else if (dd->header->nr_cpus)
                return dd->header->nr_cpus;

        return 1;
}

#ifdef X86_64
QEMUCPUState *
diskdump_get_qemucpustate(int cpu)
{
        if (cpu >= dd->num_qemu_notes) {
                if (CRASHDEBUG(1))
                        error(INFO,
                            "Invalid index for QEMU Note: %d (>= %d)\n",
                            cpu, dd->num_qemu_notes);
                return NULL;
        }

        if (dd->machine_type != EM_X86_64) {
                if (CRASHDEBUG(1))
                        error(INFO, "Only x86_64 64bit is supported.\n");
                return NULL;
        }

        return (QEMUCPUState *)dd->nt_qemucs_percpu[cpu];
}
#endif

/*
 * extract hardware specific device dumps from coredump.
 */
void
diskdump_device_dump_extract(int index, char *outfile, FILE *ofp)
{
	ulonglong offset;

	if (!dd->num_vmcoredd_notes)
		error(FATAL, "no device dumps found in this dumpfile\n");
	else if (index >= dd->num_vmcoredd_notes)
		error(FATAL, "no device dump found at index: %d", index);

	offset = dd->sub_header_kdump->offset_note +
		 ((unsigned char *)dd->nt_vmcoredd_array[index] -
		  dd->notes_buf);

	devdump_extract(dd->nt_vmcoredd_array[index], offset, outfile, ofp);
}

/*
 * list all hardware specific device dumps present in coredump.
 */
void
diskdump_device_dump_info(FILE *ofp)
{
	ulonglong offset;
	char buf[BUFSIZE];
	ulong i;

	if (!dd->num_vmcoredd_notes)
		error(FATAL, "no device dumps found in this dumpfile\n");

	fprintf(fp, "%s ", mkstring(buf, strlen("INDEX"), LJUST, "INDEX"));
	fprintf(fp, " %s ", mkstring(buf, LONG_LONG_PRLEN, LJUST, "OFFSET"));
	fprintf(fp, "  %s ", mkstring(buf, LONG_PRLEN, LJUST, "SIZE"));
	fprintf(fp, "NAME\n");

	for (i = 0; i < dd->num_vmcoredd_notes; i++) {
		fprintf(fp, "%s  ", mkstring(buf, strlen("INDEX"), CENTER | INT_DEC, MKSTR(i)));
		offset = dd->sub_header_kdump->offset_note +
			 ((unsigned char *)dd->nt_vmcoredd_array[i] -
			  dd->notes_buf);
		devdump_info(dd->nt_vmcoredd_array[i], offset, ofp);
	}
}

static void
zram_init(void)
{
	MEMBER_OFFSET_INIT(zram_mempoll, "zram", "mem_pool");
	MEMBER_OFFSET_INIT(zram_compressor, "zram", "compressor");
	MEMBER_OFFSET_INIT(zram_table_flag, "zram_table_entry", "flags");
	if (INVALID_MEMBER(zram_table_flag))
		MEMBER_OFFSET_INIT(zram_table_flag, "zram_table_entry", "value");
	STRUCT_SIZE_INIT(zram_table_entry, "zram_table_entry");
}

static unsigned char *
zram_object_addr(ulong pool, ulong handle, unsigned char *zram_buf)
{
	ulong obj, off, class, page, zspage;
	struct zspage zspage_s;
	physaddr_t paddr;
	unsigned int obj_idx, class_idx, size;
	ulong pages[2], sizes[2];

	readmem(handle, KVADDR, &obj, sizeof(void *), "zram entry", FAULT_ON_ERROR);
	obj >>= OBJ_TAG_BITS;
	phys_to_page(PTOB(obj >> OBJ_INDEX_BITS), &page);
	obj_idx = (obj & OBJ_INDEX_MASK);

	readmem(page + OFFSET(page_private), KVADDR, &zspage,
			sizeof(void *), "page_private", FAULT_ON_ERROR);
	readmem(zspage, KVADDR, &zspage_s, sizeof(struct zspage), "zspage", FAULT_ON_ERROR);

	class_idx = zspage_s.class;
	if (zspage_s.magic != ZSPAGE_MAGIC)
		error(FATAL, "zspage magic incorrect: %x\n", zspage_s.magic);

	class = pool + OFFSET(zspoll_size_class);
	class += (class_idx * sizeof(void *));
	readmem(class, KVADDR, &class, sizeof(void *), "size_class", FAULT_ON_ERROR);
	readmem(class + OFFSET(size_class_size), KVADDR,
			&size, sizeof(unsigned int), "size of class_size", FAULT_ON_ERROR);
	off = (size * obj_idx) & (~machdep->pagemask);
	if (off + size <= PAGESIZE()) {
		if (!is_page_ptr(page, &paddr)) {
			error(WARNING, "zspage: %lx: not a page pointer\n", page);
			return NULL;
		}
		readmem(paddr + off, PHYSADDR, zram_buf, size, "zram buffer", FAULT_ON_ERROR);
		goto out;
	}

	pages[0] = page;
	readmem(page + OFFSET(page_freelist), KVADDR, &pages[1],
			sizeof(void *), "page_freelist", FAULT_ON_ERROR);
	sizes[0] = PAGESIZE() - off;
	sizes[1] = size - sizes[0];
	if (!is_page_ptr(pages[0], &paddr)) {
		error(WARNING, "pages[0]: %lx: not a page pointer\n", pages[0]);
		return NULL;
	}

	readmem(paddr + off, PHYSADDR, zram_buf, sizes[0], "zram buffer[0]", FAULT_ON_ERROR);
	if (!is_page_ptr(pages[1], &paddr)) {
		error(WARNING, "pages[1]: %lx: not a page pointer\n", pages[1]);
		return NULL;
	}

	readmem(paddr, PHYSADDR, zram_buf + sizes[0], sizes[1], "zram buffer[1]", FAULT_ON_ERROR);

out:
	readmem(page, KVADDR, &obj, sizeof(void *), "page flags", FAULT_ON_ERROR);
	if (!(obj & (1<<10))) { //PG_OwnerPriv1 flag
		return (zram_buf + ZS_HANDLE_SIZE);
	}

	return zram_buf;
}

static unsigned char *
lookup_swap_cache(ulonglong pte_val, unsigned char *zram_buf)
{
	ulonglong swp_offset;
	ulong swp_type, swp_space, page;
	struct list_pair lp;
	physaddr_t paddr;
	static int is_xarray = -1;

	if (is_xarray < 0) {
		is_xarray = STREQ(MEMBER_TYPE_NAME("address_space", "i_pages"), "xarray");
	}

	swp_type = __swp_type(pte_val);
	if (THIS_KERNEL_VERSION >= LINUX(2,6,0)) {
		swp_offset = (ulonglong)__swp_offset(pte_val);
	} else {
		swp_offset = (ulonglong)SWP_OFFSET(pte_val);
	}

	if (!symbol_exists("swapper_spaces"))
		return NULL;
	swp_space = symbol_value("swapper_spaces");
	swp_space += swp_type * sizeof(void *);

	readmem(swp_space, KVADDR, &swp_space, sizeof(void *),
			"swp_spaces", FAULT_ON_ERROR);
	swp_space += (swp_offset >> SWAP_ADDRESS_SPACE_SHIFT) * SIZE(address_space);

	lp.index = swp_offset;
	if ((is_xarray ? do_xarray : do_radix_tree)(swp_space, RADIX_TREE_SEARCH, &lp)) {
		readmem((ulong)lp.value, KVADDR, &page, sizeof(void *),
				"swap_cache page", FAULT_ON_ERROR);
		if (!is_page_ptr(page, &paddr)) {
			error(WARNING, "radix page: %lx: not a page pointer\n", lp.value);
			return NULL;
		}
		readmem(paddr, PHYSADDR, zram_buf, PAGESIZE(), "zram buffer", FAULT_ON_ERROR);
		return zram_buf;
	}
	return NULL;
}

static int get_disk_name_private_data(ulonglong pte_val, ulonglong vaddr,
				       char *name, ulong *private_data)
{
	ulong swap_info, bdev, bd_disk;

	if (!symbol_exists("swap_info"))
		return FALSE;

	swap_info = symbol_value("swap_info");

	swap_info_init();
	if (vt->flags & SWAPINFO_V2) {
		swap_info += (__swp_type(pte_val) * sizeof(void *));
		readmem(swap_info, KVADDR, &swap_info,
				sizeof(void *), "swap_info", FAULT_ON_ERROR);
	} else {
		swap_info += (SIZE(swap_info_struct) * __swp_type(pte_val));
	}

	readmem(swap_info + OFFSET(swap_info_struct_bdev), KVADDR, &bdev,
			sizeof(void *), "swap_info_struct_bdev", FAULT_ON_ERROR);
	readmem(bdev + OFFSET(block_device_bd_disk), KVADDR, &bd_disk,
			sizeof(void *), "block_device_bd_disk", FAULT_ON_ERROR);
	if (name)
		readmem(bd_disk + OFFSET(gendisk_disk_name), KVADDR, name,
			strlen("zram"), "gendisk_disk_name", FAULT_ON_ERROR);
	if (private_data)
		readmem(bd_disk + OFFSET(gendisk_private_data), KVADDR,
			private_data, sizeof(void *), "gendisk_private_data",
			FAULT_ON_ERROR);

	return TRUE;
}

ulong readswap(ulonglong pte_val, char *buf, ulong len, ulonglong vaddr)
{
	char name[32] = {0};

	if (!get_disk_name_private_data(pte_val, vaddr, name, NULL))
		return 0;

	if (!strncmp(name, "zram", 4)) {
		return try_zram_decompress(pte_val, (unsigned char *)buf, len, vaddr);
	} else {
		if (CRASHDEBUG(2))
			error(WARNING, "this page has been swapped to %s\n", name);
		return 0;
	}
}

ulong (*decompressor)(unsigned char *in_addr, ulong in_size, unsigned char *out_addr,
			ulong *out_size, void *other/* NOT USED */);
/*
 * If userspace address was swapped out to zram, this function is called to decompress the object.
 * try_zram_decompress returns decompressed page data and data length
 */
ulong
try_zram_decompress(ulonglong pte_val, unsigned char *buf, ulong len, ulonglong vaddr)
{
	char name[32] = {0};
	ulonglong swp_offset;
	unsigned char *obj_addr = NULL;
	unsigned char *zram_buf = NULL;
	unsigned char *outbuf = NULL;
	ulong zram, zram_table_entry, sector, index, entry, flags, size,
		outsize, off;

	if (INVALID_MEMBER(zram_compressor)) {
		zram_init();
		if (INVALID_MEMBER(zram_compressor)) {
			error(WARNING,
			      "Some pages are swapped out to zram. "
			      "Please run mod -s zram.\n");
			return 0;
		}
	}

	if (CRASHDEBUG(2))
		error(WARNING, "this page has swapped to zram\n");

	if (!get_disk_name_private_data(pte_val, vaddr, NULL, &zram))
		return 0;

	readmem(zram + OFFSET(zram_compressor), KVADDR, name,
		sizeof(name), "zram compressor", FAULT_ON_ERROR);
	if (STREQ(name, "lzo")) {
#ifdef LZO
		if (!(dd->flags & LZO_SUPPORTED)) {
			if (lzo_init() == LZO_E_OK)
				dd->flags |= LZO_SUPPORTED;
			else
				return 0;
		}
		decompressor = (void *)lzo1x_decompress_safe;
#else
		error(WARNING,
		      "zram decompress error: this executable needs to be built"
		      " with lzo library\n");
		return 0;
#endif
	} else { /* todo: support more compressor */
		error(WARNING, "only the lzo compressor is supported\n");
		return 0;
	}

	if (THIS_KERNEL_VERSION >= LINUX(2, 6, 0)) {
		swp_offset = (ulonglong)__swp_offset(pte_val);
	} else {
		swp_offset = (ulonglong)SWP_OFFSET(pte_val);
	}

	zram_buf = (unsigned char *)GETBUF(PAGESIZE());
	/* lookup page from swap cache */
	off = PAGEOFFSET(vaddr);
	obj_addr = lookup_swap_cache(pte_val, zram_buf);
	if (obj_addr != NULL) {
		memcpy(buf, obj_addr + off, len);
		goto out;
	}

	sector = swp_offset << (PAGESHIFT() - 9);
	index = sector >> SECTORS_PER_PAGE_SHIFT;
	readmem(zram, KVADDR, &zram_table_entry,
		sizeof(void *), "zram_table_entry", FAULT_ON_ERROR);
	zram_table_entry += (index * SIZE(zram_table_entry));
	readmem(zram_table_entry, KVADDR, &entry,
		sizeof(void *), "entry of table", FAULT_ON_ERROR);
	readmem(zram_table_entry + OFFSET(zram_table_flag), KVADDR, &flags,
		sizeof(void *), "zram_table_flag", FAULT_ON_ERROR);
	if (!entry || (flags & ZRAM_FLAG_SAME_BIT)) {
		memset(buf, entry, len);
		goto out;
	}
	size = flags & (ZRAM_FLAG_SHIFT -1);
	if (size == 0) {
		len = 0;
		goto out;
	}

	readmem(zram + OFFSET(zram_mempoll), KVADDR, &zram,
		sizeof(void *), "zram_mempoll", FAULT_ON_ERROR);

	obj_addr = zram_object_addr(zram, entry, zram_buf);
	if (obj_addr == NULL) {
		len = 0;
		goto out;
	}

	if (size == PAGESIZE()) {
		memcpy(buf, obj_addr + off, len);
	} else {
		outbuf = (unsigned char *)GETBUF(PAGESIZE());
		outsize = PAGESIZE();
		if (!decompressor(obj_addr, size, outbuf, &outsize, NULL))
			memcpy(buf, outbuf + off, len);
		else {
			error(WARNING, "zram decompress error\n");
			len = 0;
		}
		FREEBUF(outbuf);
	}

out:
	if (len && CRASHDEBUG(2))
		error(INFO, "%lx: zram decompress success\n", vaddr);
	FREEBUF(zram_buf);
	return len;
}
