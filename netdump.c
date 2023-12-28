/* netdump.c 
 *
 * Copyright (C) 2002-2019 David Anderson
 * Copyright (C) 2002-2019 Red Hat, Inc. All rights reserved.
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

#define _LARGEFILE64_SOURCE 1  /* stat64() */

#include "defs.h"
#include "netdump.h"
#include "sadump.h"
#include "xen_dom0.h"

static struct vmcore_data vmcore_data = { 0 };
static struct vmcore_data *nd = &vmcore_data;
static struct proc_kcore_data proc_kcore_data = { 0 };
static struct proc_kcore_data *pkd = &proc_kcore_data;
static void netdump_print(char *, ...);
static size_t resize_elf_header(int, char *, char **, char **, ulong);
static void dump_Elf32_Ehdr(Elf32_Ehdr *);
static void dump_Elf32_Phdr(Elf32_Phdr *, int);
static size_t dump_Elf32_Nhdr(Elf32_Off offset, int);
static void dump_Elf64_Ehdr(Elf64_Ehdr *);
static void dump_Elf64_Phdr(Elf64_Phdr *, int);
static void dump_Elf64_Shdr(Elf64_Shdr *shdr);
static size_t dump_Elf64_Nhdr(Elf64_Off offset, int);
static void get_netdump_regs_32(struct bt_info *, ulong *, ulong *);
static void get_netdump_regs_ppc(struct bt_info *, ulong *, ulong *);
static void get_netdump_regs_ppc64(struct bt_info *, ulong *, ulong *);
static void get_netdump_regs_arm(struct bt_info *, ulong *, ulong *);
static void get_netdump_regs_arm64(struct bt_info *, ulong *, ulong *);
static void get_netdump_regs_mips(struct bt_info *, ulong *, ulong *);
static void get_netdump_regs_riscv(struct bt_info *, ulong *, ulong *);
static void get_netdump_regs_loongarch64(struct bt_info *, ulong *, ulong *);
static void check_dumpfile_size(char *);
static int proc_kcore_init_32(FILE *, int);
static int proc_kcore_init_64(FILE *, int);
static char *get_regs_from_note(char *, ulong *, ulong *);
static void kdump_get_osrelease(void);
static char *vmcoreinfo_read_string(const char *);


#define ELFSTORE 1
#define ELFREAD  0

#define MIN_PAGE_SIZE (4096)

/* 
 * Architectures that have configurable page sizes,
 * can differ from the host machine's page size.
 */
#define READ_PAGESIZE_FROM_VMCOREINFO() \
	(machine_type("IA64") || machine_type("PPC64") || machine_type("PPC") || machine_type("ARM64"))


/*
 * kdump installs NT_PRSTATUS elf notes only to the cpus
 * that were online during dumping.  Hence we call into
 * this function after reading the cpu map from the kernel,
 * to remap the NT_PRSTATUS notes only to the online cpus.
 */
void 
map_cpus_to_prstatus(void)
{
	void **nt_ptr;
	int online, i, j, nrcpus;
	size_t size;

	if (pc->flags2 & QEMU_MEM_DUMP_ELF)  /* notes exist for all cpus */
		return;

	if (!(online = get_cpus_online()) || (online == kt->cpus))
		return;

	if (CRASHDEBUG(1))
		error(INFO, 
		    "cpus: %d online: %d NT_PRSTATUS notes: %d (remapping)\n",
			kt->cpus, online, nd->num_prstatus_notes);

	size = NR_CPUS * sizeof(void *);

	nt_ptr = (void **)GETBUF(size);
	BCOPY(nd->nt_prstatus_percpu, nt_ptr, size);
	BZERO(nd->nt_prstatus_percpu, size);

	/*
	 *  Re-populate the array with the notes mapping to online cpus
	 */
	nrcpus = (kt->kernel_NR_CPUS ? kt->kernel_NR_CPUS : NR_CPUS);

	for (i = 0, j = 0; i < nrcpus; i++) {
		if (in_cpu_map(ONLINE_MAP, i) && machdep->is_cpu_prstatus_valid(i)) {
			nd->nt_prstatus_percpu[i] = nt_ptr[j++];
			nd->num_prstatus_notes =
				MAX(nd->num_prstatus_notes, i+1);
		}
	}

	FREEBUF(nt_ptr);
}

/*
 *  Determine whether a file is a netdump/diskdump/kdump creation, 
 *  and if TRUE, initialize the vmcore_data structure.
 */
int 
is_netdump(char *file, ulong source_query) 
{
        int i, fd, swap;
	Elf32_Ehdr *elf32;
	Elf32_Phdr *load32;
	Elf64_Ehdr *elf64;
	Elf64_Phdr *load64;
	char *eheader, *sect0;
	char buf[BUFSIZE];
	ssize_t size;
	size_t len, tot;
        Elf32_Off offset32;
        Elf64_Off offset64;
	ulong format;

	if ((fd = open(file, O_RDWR)) < 0) {
        	if ((fd = open(file, O_RDONLY)) < 0) {
                        sprintf(buf, "%s: open", file);
                        perror(buf);
                        return FALSE;
		}
	}

	size = SAFE_NETDUMP_ELF_HEADER_SIZE;
        if ((eheader = (char *)malloc(size)) == NULL) {
                fprintf(stderr, "cannot malloc ELF header buffer\n");
                clean_exit(1);
        }

	if (FLAT_FORMAT()) {
		if (!read_flattened_format(fd, 0, eheader, size))
			goto bailout;
	} else {
		size = read(fd, eheader, size);
		if (size < 0) {
			sprintf(buf, "%s: ELF header read", file);
			perror(buf);
			goto bailout;
		} else if (size < MIN_NETDUMP_ELF_HEADER_SIZE) {
			fprintf(stderr, "%s: file too small!\n", file);
			goto bailout;
		}
	}

	load32 = NULL;
	load64 = NULL;
	format = 0;
	elf32 = (Elf32_Ehdr *)&eheader[0];
	elf64 = (Elf64_Ehdr *)&eheader[0];

  	/* 
	 *  Verify the ELF header, and determine the dumpfile format.
	 * 
	 *  For now, kdump vmcores differ from netdump/diskdump like so:
	 *
 	 *   1. The first kdump PT_LOAD segment is packed just after
	 *      the ELF header, whereas netdump/diskdump page-align 
	 *      the first PT_LOAD segment.
	 *   2. Each kdump PT_LOAD segment has a p_align field of zero,
	 *      whereas netdump/diskdump have their p_align fields set
	 *      to the system page-size. 
	 *
	 *  If either kdump difference is seen, presume kdump -- this
	 *  is obviously subject to change.
	 */

	if (!STRNEQ(eheader, ELFMAG) || eheader[EI_VERSION] != EV_CURRENT)
		goto bailout;

	swap = (((eheader[EI_DATA] == ELFDATA2LSB) && 
	     (__BYTE_ORDER == __BIG_ENDIAN)) ||
	    ((eheader[EI_DATA] == ELFDATA2MSB) && 
	     (__BYTE_ORDER == __LITTLE_ENDIAN)));

        if ((elf32->e_ident[EI_CLASS] == ELFCLASS32) &&
	    (swap16(elf32->e_type, swap) == ET_CORE) &&
	    (swap32(elf32->e_version, swap) == EV_CURRENT) &&
	    (swap16(elf32->e_phnum, swap) >= 2)) {
		switch (swap16(elf32->e_machine, swap))
		{
		case EM_386:
			if (machine_type_mismatch(file, "X86", NULL, 
			    source_query))
				goto bailout;
			break;

		case EM_ARM:
			if (machine_type_mismatch(file, "ARM", NULL,
			    source_query))
				goto bailout;
			break;

		case EM_PPC:
			if (machine_type_mismatch(file, "PPC", NULL,
			    source_query))
				goto bailout;
			break;

		case EM_MIPS:
			if (machine_type_mismatch(file, "MIPS", NULL,
			    source_query))
				goto bailout;
			break;

		default:
			if (machine_type_mismatch(file, "(unknown)", NULL,
			    source_query))
				goto bailout;
		}

		if (endian_mismatch(file, elf32->e_ident[EI_DATA], 
		    source_query))
			goto bailout;

		if (elf32->e_phoff != sizeof(Elf32_Ehdr)) {
			if (CRASHDEBUG(1))
				error(WARNING, "%s: first PHdr not following "
					"EHdr (PHdr offset = %u)\n", file,
					elf32->e_phoff);
			/* it's okay as long as we've read enough data */
			if (elf32->e_phoff > size - 2 * sizeof(Elf32_Phdr)) {
				error(WARNING, "%s: PHdr to far into file!\n",
					file);
				goto bailout;
			}
		}

		/* skip the NOTE program header */
		load32 = (Elf32_Phdr *)
			&eheader[elf32->e_phoff+sizeof(Elf32_Phdr)];

		if ((load32->p_offset & (MIN_PAGE_SIZE-1)) ||
		    (load32->p_align == 0))
			format = KDUMP_ELF32;
		else
			format = NETDUMP_ELF32;
	} else if ((elf64->e_ident[EI_CLASS] == ELFCLASS64) &&
	    (swap16(elf64->e_type, swap) == ET_CORE) &&
	    (swap32(elf64->e_version, swap) == EV_CURRENT) &&
	    (swap16(elf64->e_phnum, swap) >= 2)) { 
		switch (swap16(elf64->e_machine, swap))
		{
		case EM_IA_64:
			if (machine_type_mismatch(file, "IA64", NULL, 
			    source_query))
				goto bailout;
			break;

		case EM_PPC64:
			if (machine_type_mismatch(file, "PPC64", NULL, 
			    source_query))
				goto bailout;
			break;

		case EM_X86_64:
			if (machine_type_mismatch(file, "X86_64", NULL,
			    source_query))
				goto bailout;
			break;

		case EM_S390:
			if (machine_type_mismatch(file, "S390X", NULL,
			    source_query))
				goto bailout;
			break;

		case EM_386:
			if (machine_type_mismatch(file, "X86", NULL,
			    source_query))
				goto bailout;
			break;

		case EM_ARM:
			if (machine_type_mismatch(file, "ARM", NULL,
			    source_query))
				goto bailout;
			break;

		case EM_AARCH64:
			if (machine_type_mismatch(file, "ARM64", NULL,
			    source_query))
				goto bailout;
			break;

		case EM_MIPS:
			if (machine_type_mismatch(file, "MIPS", "MIPS64",
			    source_query))
				goto bailout;
			break;

		case EM_RISCV:
			if (machine_type_mismatch(file, "RISCV64", NULL,
			    source_query))
				goto bailout;
			break;

		case EM_LOONGARCH:
			if (machine_type_mismatch(file, "LOONGARCH64", NULL,
			    source_query))
				goto bailout;
			break;

		default:
			if (machine_type_mismatch(file, "(unknown)", NULL,
			    source_query))
				goto bailout;
		}

		if (endian_mismatch(file, elf64->e_ident[EI_DATA], 
		    source_query))
			goto bailout;

		if (elf64->e_phoff != sizeof(Elf64_Ehdr)) {
			if (CRASHDEBUG(1))
				error(WARNING, "%s: first PHdr not following "
					"EHdr (PHdr offset = %u)\n", file,
					elf64->e_phoff);
			/* it's okay as long as we've read enough data */
			if (elf64->e_phoff > size - 2 * sizeof(Elf64_Phdr)) {
				error(WARNING, "%s: PHdr to far into file!\n",
					file);
				goto bailout;
			}
		}

		/* skip the NOTE program header */
		load64 = (Elf64_Phdr *)
			&eheader[elf64->e_phoff+sizeof(Elf64_Phdr)];

		if ((load64->p_offset & (MIN_PAGE_SIZE-1)) ||
		    (load64->p_align == 0))
			format = KDUMP_ELF64;
		else
			format = NETDUMP_ELF64;
	} else {
		if (CRASHDEBUG(2))
			error(INFO, "%s: not a %s ELF dumpfile\n",
				file, source_query == NETDUMP_LOCAL ?
				"netdump" : "kdump");
			
			
		goto bailout;
	}

	if (source_query == KCORE_LOCAL) {
		close(fd);
		return TRUE;
	}

	switch (format)
	{
	case NETDUMP_ELF32:
	case NETDUMP_ELF64:
		if (source_query & (NETDUMP_LOCAL|NETDUMP_REMOTE))
			break;
		else
			goto bailout;

	case KDUMP_ELF32:
	case KDUMP_ELF64:
		if (source_query & KDUMP_LOCAL)
			break;
		else
			goto bailout;
	}

	sect0 = NULL;
	if (!(size = resize_elf_header(fd, file, &eheader, &sect0, format)))
		goto bailout;

	nd->ndfd = fd;
	nd->elf_header = eheader;
	nd->flags = format | source_query;

	switch (format)
	{
	case NETDUMP_ELF32:
	case KDUMP_ELF32:
		nd->header_size = size;
        	nd->elf32 = (Elf32_Ehdr *)&nd->elf_header[0];
		nd->num_pt_load_segments = nd->elf32->e_phnum - 1;
		if ((nd->pt_load_segments = (struct pt_load_segment *)
		    malloc(sizeof(struct pt_load_segment) *
		    nd->num_pt_load_segments)) == NULL) {
			fprintf(stderr, "cannot malloc PT_LOAD segment buffers\n");
			clean_exit(1);
		}
		nd->notes32 = (Elf32_Phdr *)
		    &nd->elf_header[nd->elf32->e_phoff];
		nd->load32 = nd->notes32 + 1;
		if (format == NETDUMP_ELF32)
			nd->page_size = (uint)nd->load32->p_align;
                dump_Elf32_Ehdr(nd->elf32);
                dump_Elf32_Phdr(nd->notes32, ELFREAD);
		for (i = 0; i < nd->num_pt_load_segments; i++) 
                	dump_Elf32_Phdr(nd->load32 + i, ELFSTORE+i);
        	offset32 = nd->notes32->p_offset;
                for (tot = 0; tot < nd->notes32->p_filesz; tot += len) {
                        if (!(len = dump_Elf32_Nhdr(offset32, ELFSTORE)))
				break;
                        offset32 += len;
                }
		break;

	case NETDUMP_ELF64:
	case KDUMP_ELF64:
                nd->header_size = size;
                nd->elf64 = (Elf64_Ehdr *)&nd->elf_header[0];

		/*
		 * Extended Numbering support
		 * See include/uapi/linux/elf.h and elf(5) for more information
		 */
		if (nd->elf64->e_phnum == PN_XNUM) {
			nd->sect0_64 = (Elf64_Shdr *)sect0;
			nd->num_pt_load_segments = nd->sect0_64->sh_info - 1;
		} else
			nd->num_pt_load_segments = nd->elf64->e_phnum - 1;

                if ((nd->pt_load_segments = (struct pt_load_segment *)
                    malloc(sizeof(struct pt_load_segment) *
                    nd->num_pt_load_segments)) == NULL) {
                        fprintf(stderr, "cannot malloc PT_LOAD segment buffers\n");
                        clean_exit(1);
                }
		nd->notes64 = (Elf64_Phdr *)
		    &nd->elf_header[nd->elf64->e_phoff];
		nd->load64 = nd->notes64 + 1;
		if (format == NETDUMP_ELF64)
			nd->page_size = (uint)nd->load64->p_align;
                dump_Elf64_Ehdr(nd->elf64);
                dump_Elf64_Phdr(nd->notes64, ELFREAD);
		for (i = 0; i < nd->num_pt_load_segments; i++)
                	dump_Elf64_Phdr(nd->load64 + i, ELFSTORE+i);
                offset64 = nd->notes64->p_offset;
                for (tot = 0; tot < nd->notes64->p_filesz; tot += len) {
                        if (!(len = dump_Elf64_Nhdr(offset64, ELFSTORE)))
				break;
                        offset64 += len;
                }
		break;
	}

	if (CRASHDEBUG(1))
		netdump_memory_dump(fp);

	pc->read_vmcoreinfo = vmcoreinfo_read_string;

	if ((source_query == KDUMP_LOCAL) && 
	    (pc->flags2 & GET_OSRELEASE))
		kdump_get_osrelease();

	if ((source_query == KDUMP_LOCAL) && 
	    (pc->flags2 & GET_LOG)) {
		pc->dfd = nd->ndfd;
		pc->readmem = read_kdump;
		nd->flags |= KDUMP_LOCAL;
		pc->flags |= KDUMP;
		get_log_from_vmcoreinfo(file);
	}

	return nd->header_size;

bailout:
	close(fd);
	free(eheader);
	return FALSE;
}

/*
 *  Search through all PT_LOAD segments to determine the
 *  file offset where the physical memory segment(s) start
 *  in the vmcore, and consider everything prior to that as
 *  header contents.
 */

static size_t
resize_elf_header(int fd, char *file, char **eheader_ptr, char **sect0_ptr,
		ulong format)
{
	int i;
	char buf[BUFSIZE];
	char *eheader;
	Elf32_Ehdr *elf32;
	Elf32_Phdr *load32;
	Elf64_Ehdr *elf64;
	Elf64_Phdr *load64;
	Elf32_Off p_offset32;
	Elf64_Off p_offset64;
	size_t header_size;
	uint num_pt_load_segments;

	eheader = *eheader_ptr;
	header_size = num_pt_load_segments = 0;
	elf32 = (Elf32_Ehdr *)&eheader[0];
	elf64 = (Elf64_Ehdr *)&eheader[0];

	switch (format)
	{
	case NETDUMP_ELF32:
	case KDUMP_ELF32:
		num_pt_load_segments = elf32->e_phnum - 1;
		header_size = MAX(sizeof(Elf32_Ehdr), elf32->e_phoff) +
			(sizeof(Elf32_Phdr) * (num_pt_load_segments + 1));
		break;

	case NETDUMP_ELF64:
	case KDUMP_ELF64:
		/*
		 * Extended Numbering support
		 * See include/uapi/linux/elf.h and elf(5) for more information
		 */
		if (elf64->e_phnum == PN_XNUM) {
			Elf64_Shdr *shdr64;

			shdr64 = (Elf64_Shdr *)malloc(sizeof(*shdr64));
			if (!shdr64) {
				fprintf(stderr,
				    "cannot malloc a section header buffer\n");
				return 0;
			}
			if (FLAT_FORMAT()) {
				if (!read_flattened_format(fd, elf64->e_shoff,
				    shdr64, elf64->e_shentsize))
					return 0;
			} else {
				if (lseek(fd, elf64->e_shoff, SEEK_SET) !=
				    elf64->e_shoff) {
					sprintf(buf, "%s: section header lseek",
						file);
					perror(buf);
					return 0;
				}
				if (read(fd, shdr64, elf64->e_shentsize) !=
				    elf64->e_shentsize) {
					sprintf(buf, "%s: section header read",
						file);
					perror(buf);
					return 0;
				}
			}
			num_pt_load_segments = shdr64->sh_info - 1;
			*sect0_ptr = (char *)shdr64;
		} else
			num_pt_load_segments = elf64->e_phnum - 1;

		header_size = MAX(sizeof(Elf64_Ehdr), elf64->e_phoff) +
			(sizeof(Elf64_Phdr) * (num_pt_load_segments + 1));
		break;
	}

	if ((eheader = (char *)realloc(eheader, header_size)) == NULL) {
		fprintf(stderr, "cannot realloc interim ELF header buffer\n");
		clean_exit(1);
	} else
		*eheader_ptr = eheader;

	elf32 = (Elf32_Ehdr *)&eheader[0];
	elf64 = (Elf64_Ehdr *)&eheader[0];

	if (FLAT_FORMAT()) {
		if (!read_flattened_format(fd, 0, eheader, header_size))
			return 0;
	} else {
		if (lseek(fd, 0, SEEK_SET) != 0) {
			sprintf(buf, "%s: lseek", file);
			perror(buf);
			return 0;
		}
		if (read(fd, eheader, header_size) != header_size) {
			sprintf(buf, "%s: ELF header read", file);
			perror(buf);
			return 0;
		}
	}

	switch (format)
	{
	case NETDUMP_ELF32:
	case KDUMP_ELF32:
		load32 = (Elf32_Phdr *)&eheader[elf32->e_phoff+sizeof(Elf32_Phdr)];
		p_offset32 = load32->p_offset;
		for (i = 0; i < num_pt_load_segments; i++, load32 += 1) {
			if (load32->p_offset && 
			    (p_offset32 > load32->p_offset))
				p_offset32 = load32->p_offset;
		}
		header_size = (size_t)p_offset32;
		break;

	case NETDUMP_ELF64:
	case KDUMP_ELF64:
		load64 = (Elf64_Phdr *)&eheader[elf64->e_phoff+sizeof(Elf64_Phdr)];
		p_offset64 = load64->p_offset;
		for (i = 0; i < num_pt_load_segments; i++, load64 += 1) {
			if (load64->p_offset &&
			    (p_offset64 > load64->p_offset))
				p_offset64 = load64->p_offset;
		}
		header_size = (size_t)p_offset64;
		break;
	}

	if ((eheader = (char *)realloc(eheader, header_size)) == NULL) {
		perror("realloc");
		fprintf(stderr, "cannot realloc resized ELF header buffer\n");
		clean_exit(1);
	} else
		*eheader_ptr = eheader;

	if (FLAT_FORMAT()) {
		if (!read_flattened_format(fd, 0, eheader, header_size))
			return 0;
	} else {
		if (lseek(fd, 0, SEEK_SET) != 0) {
			sprintf(buf, "%s: lseek", file);
			perror(buf);
			return 0;
		}
		if (read(fd, eheader, header_size) != header_size) {
			sprintf(buf, "%s: ELF header read", file);
			perror(buf);
			return 0;
		}
	}

	return header_size;
}

/*
 *  Return the e_version number of an ELF file
 *  (or -1 if its not readable ELF file)
 */
int
file_elf_version(char *file)
{
	int fd, size;
	Elf32_Ehdr *elf32;
	Elf64_Ehdr *elf64;
	char header[MIN_NETDUMP_ELF_HEADER_SIZE];
	char buf[BUFSIZE];

	if ((fd = open(file, O_RDONLY)) < 0) {
		sprintf(buf, "%s: open", file);
		perror(buf);
		return -1;
	}

	size = MIN_NETDUMP_ELF_HEADER_SIZE;
        if (read(fd, header, size) != size) {
                sprintf(buf, "%s: read", file);
                perror(buf);
		close(fd);
		return -1;
	}
	close(fd);

	elf32 = (Elf32_Ehdr *)&header[0];
	elf64 = (Elf64_Ehdr *)&header[0];

        if (STRNEQ(elf32->e_ident, ELFMAG) &&
	    (elf32->e_ident[EI_CLASS] == ELFCLASS32) &&
  	    (elf32->e_ident[EI_DATA] == ELFDATA2LSB) &&
    	    (elf32->e_ident[EI_VERSION] == EV_CURRENT)) {
		return (elf32->e_version);
	} else if (STRNEQ(elf64->e_ident, ELFMAG) &&
	    (elf64->e_ident[EI_CLASS] == ELFCLASS64) &&
	    (elf64->e_ident[EI_VERSION] == EV_CURRENT)) {
		return (elf64->e_version);
	} 
	
	return -1;
}

/* 
 *  Check whether any PT_LOAD segment goes beyond the file size.
 */
static void
check_dumpfile_size(char *file)
{
	int i;
	struct stat64 stat;
	struct pt_load_segment *pls;
	uint64_t segment_end;

	if (is_ramdump_image())
		return;

	if (stat64(file, &stat) < 0)
		return;

	if (S_ISBLK(stat.st_mode)) {
		error(NOTE, "%s: No dump complete check for block devices\n",
		      file);
		return;
	}
	for (i = 0; i < nd->num_pt_load_segments; i++) {
		pls = &nd->pt_load_segments[i];

		segment_end = pls->file_offset + 
			(pls->phys_end - pls->phys_start);

		if (segment_end > stat.st_size) {
			error(WARNING, "%s: may be truncated or incomplete\n"
				"         PT_LOAD p_offset: %lld\n"
				"                 p_filesz: %lld\n"
				"           bytes required: %lld\n"
				"            dumpfile size: %lld\n\n",
				file, pls->file_offset, 
				pls->phys_end - pls->phys_start,  
				segment_end, stat.st_size);
			return;
		}
	}
}

/*
 *  Perform any post-dumpfile determination stuff here.
 */
int
netdump_init(char *unused, FILE *fptr)
{
	if (!VMCORE_VALID())
		return FALSE;

	machdep->is_cpu_prstatus_valid = diskdump_is_cpu_prstatus_valid;
	nd->ofp = fptr;

	check_dumpfile_size(pc->dumpfile);

        return TRUE;
}

/*
 *  Read from a netdump-created dumpfile.
 */
int
read_netdump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	off_t offset;
	ssize_t read_ret;
	struct pt_load_segment *pls;
	int i;

	offset = 0;

	/*
	 *  The Elf32_Phdr has 32-bit fields for p_paddr, p_filesz and
	 *  p_memsz, so for now, multiple PT_LOAD segment support is
	 *  restricted to 64-bit machines for netdump/diskdump vmcores.
	 *  However, kexec/kdump has introduced the optional use of a
         *  64-bit ELF header for 32-bit processors.
	 */ 
        switch (DUMPFILE_FORMAT(nd->flags))
	{
	case NETDUMP_ELF32:
		offset = (off_t)paddr + (off_t)nd->header_size;
		break;

	case NETDUMP_ELF64:
	case KDUMP_ELF32:
	case KDUMP_ELF64:
		if (nd->num_pt_load_segments == 1) {
			offset = (off_t)paddr + (off_t)nd->header_size -
				(off_t)nd->pt_load_segments[0].phys_start;
			break;
		}

		for (i = offset = 0; i < nd->num_pt_load_segments; i++) {
			pls = &nd->pt_load_segments[i];
			if ((paddr >= pls->phys_start) &&
			    (paddr < pls->phys_end)) {
				offset = (off_t)(paddr - pls->phys_start) +
					pls->file_offset;
				break;
			}
			if (pls->zero_fill && (paddr >= pls->phys_end) &&
			    (paddr < pls->zero_fill)) {
				memset(bufptr, 0, cnt);
				if (CRASHDEBUG(8))
					fprintf(fp, "read_netdump: zero-fill: "
					    "addr: %lx paddr: %llx cnt: %d\n",
						addr, (ulonglong)paddr, cnt);
                		return cnt;
			}
		}
	
		if (!offset) {
			if (CRASHDEBUG(8))
				fprintf(fp, "read_netdump: READ_ERROR: "
				    "offset not found for paddr: %llx\n",
					(ulonglong)paddr);
	                return READ_ERROR;
		}
		
		break;
	}	

	if (CRASHDEBUG(8))
		fprintf(fp, "read_netdump: addr: %lx paddr: %llx cnt: %d offset: %llx\n",
			addr, (ulonglong)paddr, cnt, (ulonglong)offset);

	if (FLAT_FORMAT()) {
		if (!read_flattened_format(nd->ndfd, offset, bufptr, cnt)) {
			if (CRASHDEBUG(8))
				fprintf(fp, "read_netdump: READ_ERROR: "
				    "read_flattened_format failed for offset:"
				    " %llx\n",
					(ulonglong)offset);
			return READ_ERROR;
		}
	} else {
		if (lseek(nd->ndfd, offset, SEEK_SET) == -1) {
			if (CRASHDEBUG(8))
				fprintf(fp, "read_netdump: SEEK_ERROR: "
				    "offset: %llx\n", (ulonglong)offset);
			return SEEK_ERROR;
		}

		read_ret = read(nd->ndfd, bufptr, cnt);
		if (read_ret != cnt) {
			/*
			 *  First check whether zero_excluded has been set.
			 */
			if ((read_ret >= 0) &&
			    (*diskdump_flags & ZERO_EXCLUDED)) {
				if (CRASHDEBUG(8))
					fprintf(fp, "read_netdump: zero-fill: "
					    "addr: %lx paddr: %llx cnt: %d\n",
						addr + read_ret, 
						(ulonglong)paddr + read_ret, 
						cnt - (int)read_ret);
				bufptr += read_ret;
				bzero(bufptr, cnt - read_ret);
				return cnt;
			}
			if (CRASHDEBUG(8))
				fprintf(fp, "read_netdump: READ_ERROR: "
				    "offset: %llx\n", (ulonglong)offset);
			return READ_ERROR;
		}
	}

        return cnt;
}

/*
 *  Write to a netdump-created dumpfile.  Note that cmd_wr() does not
 *  allow writes to dumpfiles, so you can't get here from there.
 *  But, if it would ever be helpful, here it is...
 */
int
write_netdump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	off_t offset;
	struct pt_load_segment *pls;
	int i;

	offset = 0;

        switch (DUMPFILE_FORMAT(nd->flags))
	{
	case NETDUMP_ELF32:
		offset = (off_t)paddr + (off_t)nd->header_size;
		break;

	case NETDUMP_ELF64:
	case KDUMP_ELF32:
	case KDUMP_ELF64:
		if (nd->num_pt_load_segments == 1) {
			offset = (off_t)paddr + (off_t)nd->header_size;
			break;
		}

		for (i = offset = 0; i < nd->num_pt_load_segments; i++) {
			pls = &nd->pt_load_segments[i];
			if ((paddr >= pls->phys_start) &&
			    (paddr < pls->phys_end)) {
				offset = (off_t)(paddr - pls->phys_start) +
					pls->file_offset;
				break;
			}
		}
	
		if (!offset) 
	                return READ_ERROR;
		
		break;
	}	

        if (lseek(nd->ndfd, offset, SEEK_SET) == -1)
                return SEEK_ERROR;

        if (write(nd->ndfd, bufptr, cnt) != cnt)
                return READ_ERROR;

        return cnt;
}

/*
 *  Set the file pointer for debug output.
 */
FILE *
set_netdump_fp(FILE *fp)
{
	if (!VMCORE_VALID())
		return NULL;

	nd->ofp = fp;
	return fp;
}

/*
 *  Generic print routine to handle integral and remote daemon output.
 */
static void
netdump_print(char *fmt, ...)
{
        char buf[BUFSIZE];
        va_list ap;

        if (!fmt || !strlen(fmt) || !VMCORE_VALID())
                return;

        va_start(ap, fmt);
        (void)vsnprintf(buf, BUFSIZE, fmt, ap);
        va_end(ap);

        if (nd->ofp)
                fprintf(nd->ofp, "%s", buf);
        else
                console(buf);
}

uint 
netdump_page_size(void)
{
	if (!VMCORE_VALID())
		return 0;

	return nd->page_size;
}

int 
netdump_free_memory(void)
{
	return (VMCORE_VALID() ? 0 : 0);
}

int netdump_memory_used(void)
{
	return (VMCORE_VALID() ? 0 : 0);
}

/*
 *  The netdump server will eventually use the NT_TASKSTRUCT section
 *  to pass the task address.  Until such time, look at the ebp of the
 *  user_regs_struct, which is located at the end of the NT_PRSTATUS
 *  elf_prstatus structure, minus one integer:
 *
 *    struct elf_prstatus
 *    {
 *    	...
 *            elf_gregset_t pr_reg;   (maps to user_regs_struct) 
 *            int pr_fpvalid;        
 *    };
 *
 *  If it's a kernel stack address who's adjusted task_struct value is
 *  equal to one of the active set tasks, we'll presume it's legit. 
 *
 */
ulong 
get_netdump_panic_task(void)
{
#ifdef DAEMON
	return nd->task_struct;
#else
	int i, crashing_cpu;
        size_t len;
	char *user_regs;
	ulong ebp, esp, task;

	if (!VMCORE_VALID() || !get_active_set())
		goto panic_task_undetermined;

	if (nd->task_struct) {
		if (CRASHDEBUG(1))
			error(INFO, 
			    "get_netdump_panic_task: NT_TASKSTRUCT: %lx\n", 
				nd->task_struct);
		return nd->task_struct;
	}

        switch (DUMPFILE_FORMAT(nd->flags))
        {
        case NETDUMP_ELF32:
        case NETDUMP_ELF64:
		crashing_cpu = -1;
		break;

        case KDUMP_ELF32:
        case KDUMP_ELF64:
		crashing_cpu = -1;
		if (kernel_symbol_exists("crashing_cpu")) {
			get_symbol_data("crashing_cpu", sizeof(int), &i);
			if ((i >= 0) && in_cpu_map(ONLINE_MAP, i)) {
				crashing_cpu = i;
				if (CRASHDEBUG(1))
					error(INFO, 
		  "get_netdump_panic_task: active_set[crashing_cpu: %d]: %lx\n",
						crashing_cpu,
						tt->active_set[crashing_cpu]);
			}
		}

		if ((nd->num_prstatus_notes > 1) && (crashing_cpu == -1))
			goto panic_task_undetermined;
		break;

	default:
		crashing_cpu = -1;
		break;
	}

        if (nd->elf32 && (nd->elf32->e_machine == EM_386)) {
		Elf32_Nhdr *note32 = NULL;

                if (nd->num_prstatus_notes > 1) {
			if (crashing_cpu != -1)
				note32 = (Elf32_Nhdr *)
					nd->nt_prstatus_percpu[crashing_cpu];
                } else
                        note32 = (Elf32_Nhdr *)nd->nt_prstatus;

		if (!note32)
			goto panic_task_undetermined;

	        len = sizeof(Elf32_Nhdr);
	        len = roundup(len + note32->n_namesz, 4);
	        len = roundup(len + note32->n_descsz, 4);
		
		user_regs = ((char *)note32 + len)
			- SIZE(user_regs_struct) - sizeof(int);
		ebp = ULONG(user_regs + OFFSET(user_regs_struct_ebp));
		esp = ULONG(user_regs + OFFSET(user_regs_struct_esp));
check_ebp_esp:
		if (CRASHDEBUG(1)) 
			error(INFO, 
			    "get_netdump_panic_task: NT_PRSTATUS esp: %lx ebp: %lx\n",
				esp, ebp);
		if (IS_KVADDR(esp)) {
			task = stkptr_to_task(esp);
			if (CRASHDEBUG(1))
				error(INFO, 
			    "get_netdump_panic_task: esp: %lx -> task: %lx\n",
					esp, task);
			for (i = 0; task && (i < NR_CPUS); i++) {
				if (task == tt->active_set[i]) 
					return task;
			} 
		}
                if (IS_KVADDR(ebp)) {
                        task = stkptr_to_task(ebp);
			if (CRASHDEBUG(1))
				error(INFO, 
			    "get_netdump_panic_task: ebp: %lx -> task: %lx\n",
					ebp, task);
                        for (i = 0; task && (i < NR_CPUS); i++) {
                                if (task == tt->active_set[i]) 
                                      return task;
                        }
                }
	} else if (nd->elf64) {
		Elf64_Nhdr *note64 = NULL;

                if (nd->num_prstatus_notes > 1) {
			if (crashing_cpu != -1)
				note64 = (Elf64_Nhdr *)
					nd->nt_prstatus_percpu[crashing_cpu];
                } else
                        note64 = (Elf64_Nhdr *)nd->nt_prstatus;

		if (!note64)
			goto panic_task_undetermined;

	        len = sizeof(Elf64_Nhdr);
	        len = roundup(len + note64->n_namesz, 4);
		user_regs = (char *)((char *)note64 + len +
			MEMBER_OFFSET("elf_prstatus", "pr_reg"));

		if (nd->elf64->e_machine == EM_386) {
                	ebp = ULONG(user_regs + OFFSET(user_regs_struct_ebp));
                	esp = ULONG(user_regs + OFFSET(user_regs_struct_esp));
			goto check_ebp_esp;
		}

		if (nd->elf64->e_machine == EM_PPC64) {
			/*
			 * Get the GPR1 register value.
			 */
			esp = *(ulong *)((char *)user_regs + 8);
			if (CRASHDEBUG(1)) 
				error(INFO, 
			    	"get_netdump_panic_task: NT_PRSTATUS esp: %lx\n", esp);
			if (IS_KVADDR(esp)) {
				task = stkptr_to_task(esp);
				if (CRASHDEBUG(1))
					error(INFO, 
			    		"get_netdump_panic_task: esp: %lx -> task: %lx\n",
						esp, task);
				for (i = 0; task && (i < NR_CPUS); i++) {
					if (task == tt->active_set[i]) 
						return task;
				}
			}
		}

		if (nd->elf64->e_machine == EM_X86_64) {
			if ((crashing_cpu != -1) && (crashing_cpu <= kt->cpus))
				return (tt->active_set[crashing_cpu]);
		}
	} 

panic_task_undetermined:

	if (CRASHDEBUG(1))
		error(INFO, "get_netdump_panic_task: failed\n");

	return NO_TASK;
#endif
}

/*
 *  Get the switch_stack address of the passed-in task.  Currently only
 *  the panicking task reports its switch-stack address.
 */
ulong 
get_netdump_switch_stack(ulong task)
{
#ifdef DAEMON
	if (nd->task_struct == task)
		return nd->switch_stack;
	return 0;
#else
	if (!VMCORE_VALID() || !get_active_set())
		return 0;

	if (nd->task_struct == task)
		return nd->switch_stack;

	return 0;
#endif
}

int
netdump_memory_dump(FILE *fp)
{
	int i, others, wrap, flen;
	size_t len, tot;
	FILE *fpsave;
	Elf32_Off offset32;
	Elf32_Off offset64;
	struct pt_load_segment *pls;

	if (!VMCORE_VALID())
		return FALSE;

	fpsave = nd->ofp;
	nd->ofp = fp;

	if (FLAT_FORMAT())
		dump_flat_header(nd->ofp);

	netdump_print("vmcore_data: \n");
	netdump_print("                  flags: %lx (", nd->flags);
	others = 0;
	if (nd->flags & NETDUMP_LOCAL)
		netdump_print("%sNETDUMP_LOCAL", others++ ? "|" : "");
	if (nd->flags & KDUMP_LOCAL)
		netdump_print("%sKDUMP_LOCAL", others++ ? "|" : "");
	if (nd->flags & NETDUMP_REMOTE)
		netdump_print("%sNETDUMP_REMOTE", others++ ? "|" : "");
	if (nd->flags & NETDUMP_ELF32)
		netdump_print("%sNETDUMP_ELF32", others++ ? "|" : "");
	if (nd->flags & NETDUMP_ELF64)
		netdump_print("%sNETDUMP_ELF64", others++ ? "|" : "");
	if (nd->flags & KDUMP_ELF32)
		netdump_print("%sKDUMP_ELF32", others++ ? "|" : "");
	if (nd->flags & KDUMP_ELF64)
		netdump_print("%sKDUMP_ELF64", others++ ? "|" : "");
	if (nd->flags & PARTIAL_DUMP)
		netdump_print("%sPARTIAL_DUMP", others++ ? "|" : "");
	if (nd->flags & QEMU_MEM_DUMP_KDUMP_BACKUP)
		netdump_print("%sQEMU_MEM_DUMP_KDUMP_BACKUP", others++ ? "|" : "");
	netdump_print(") %s\n", FLAT_FORMAT() ? "[FLAT]" : "");
	if ((pc->flags & RUNTIME) && symbol_exists("dump_level")) {
		int dump_level;
                if (readmem(symbol_value("dump_level"), KVADDR, &dump_level,
                    sizeof(dump_level), "dump_level", QUIET|RETURN_ON_ERROR)) {
			netdump_print("             dump_level: %d (0x%x) %s", 
				dump_level, dump_level, 
				dump_level > 0 ? "(" : "");

#define DUMP_EXCLUDE_CACHE 0x00000001   /* Exclude LRU & SwapCache pages*/
#define DUMP_EXCLUDE_CLEAN 0x00000002   /* Exclude all-zero pages */
#define DUMP_EXCLUDE_FREE  0x00000004   /* Exclude free pages */
#define DUMP_EXCLUDE_ANON  0x00000008   /* Exclude Anon pages */
#define DUMP_SAVE_PRIVATE  0x00000010   /* Save private pages */

		        others = 0;
        		if (dump_level & DUMP_EXCLUDE_CACHE)
                		netdump_print("%sDUMP_EXCLUDE_CACHE", 
					others++ ? "|" : "");
        		if (dump_level & DUMP_EXCLUDE_CLEAN)
                		netdump_print("%sDUMP_EXCLUDE_CLEAN", 
					others++ ? "|" : "");
        		if (dump_level & DUMP_EXCLUDE_FREE)
                		netdump_print("%sDUMP_EXCLUDE_FREE", 
					others++ ? "|" : "");
        		if (dump_level & DUMP_EXCLUDE_ANON)
                		netdump_print("%sDUMP_EXCLUDE_ANON", 
					others++ ? "|" : "");
        		if (dump_level & DUMP_SAVE_PRIVATE)
                		netdump_print("%sDUMP_SAVE_PRIVATE", 
					others++ ? "|" : "");
			netdump_print("%s\n", dump_level > 0 ? ")" : "");
		} else
			netdump_print("             dump_level: (unknown)\n");
	} else if (!(pc->flags & RUNTIME) && symbol_exists("dump_level"))
		netdump_print("             dump_level: (undetermined)\n");

	netdump_print("                   ndfd: %d\n", nd->ndfd);
	netdump_print("                    ofp: %lx\n", nd->ofp);
	netdump_print("            header_size: %d\n", nd->header_size);
	netdump_print("   num_pt_load_segments: %d\n", nd->num_pt_load_segments);
	for (i = 0; i < nd->num_pt_load_segments; i++) {
		pls = &nd->pt_load_segments[i];
		netdump_print("     pt_load_segment[%d]:\n", i);
		netdump_print("            file_offset: %lx\n", 
			pls->file_offset);
		netdump_print("             phys_start: %llx\n", 
			pls->phys_start);
		netdump_print("               phys_end: %llx\n", 
			pls->phys_end);
		netdump_print("              zero_fill: %llx\n", 
			pls->zero_fill);
	}
	netdump_print("             elf_header: %lx\n", nd->elf_header);
	netdump_print("                  elf32: %lx\n", nd->elf32);
	netdump_print("                notes32: %lx\n", nd->notes32);
	netdump_print("                 load32: %lx\n", nd->load32);
	netdump_print("                  elf64: %lx\n", nd->elf64);
	netdump_print("                notes64: %lx\n", nd->notes64);
	netdump_print("                 load64: %lx\n", nd->load64);
	netdump_print("               sect0_64: %lx\n", nd->sect0_64);
	netdump_print("            nt_prstatus: %lx\n", nd->nt_prstatus);
	netdump_print("            nt_prpsinfo: %lx\n", nd->nt_prpsinfo);
	netdump_print("          nt_taskstruct: %lx\n", nd->nt_taskstruct);
	netdump_print("            task_struct: %lx\n", nd->task_struct);
	netdump_print("             arch_data1: ");
	if (nd->arch_data1) {
		if (machine_type("X86_64"))
			netdump_print("%lx (relocate)\n", nd->arch_data1);
		else if (machine_type("ARM64"))
			netdump_print("%lx (kimage_voffset)\n", nd->arch_data1);
	} else
		netdump_print("(unused)\n");
	netdump_print("             arch_data2: ");
	if (nd->arch_data2) {
		if (machine_type("ARM64"))
			netdump_print("%016lx\n"
			    "                         CONFIG_ARM64_VA_BITS: %ld\n"
			    "                         VA_BITS_ACTUAL: %lld\n", 
				nd->arch_data2, nd->arch_data2 & 0xffffffff,
				((ulonglong)nd->arch_data2 >> 32));
		else
			netdump_print("%016lx (?)\n", nd->arch_data2);
	} else
		netdump_print("(unused)\n");
	netdump_print("           switch_stack: %lx\n", nd->switch_stack);
	netdump_print("              page_size: %d\n", nd->page_size);
	dump_xen_kdump_data(fp);
	netdump_print("     num_prstatus_notes: %d\n", nd->num_prstatus_notes);
	netdump_print("         num_qemu_notes: %d\n", nd->num_qemu_notes);
	netdump_print("             vmcoreinfo: %lx\n", (ulong)nd->vmcoreinfo);
	netdump_print("        size_vmcoreinfo: %d\n", nd->size_vmcoreinfo);
	netdump_print("     nt_prstatus_percpu: ");
        wrap = sizeof(void *) == SIZEOF_32BIT ? 8 : 4;
        flen = sizeof(void *) == SIZEOF_32BIT ? 8 : 16;
	if (nd->num_prstatus_notes == 1)
                netdump_print("%.*lx\n", flen, nd->nt_prstatus_percpu[0]);
	else {
        	for (i = 0; i < nd->num_prstatus_notes; i++) {
                	if ((i % wrap) == 0)
                        	netdump_print("\n        ");
                	netdump_print("%.*lx ", flen, 
				nd->nt_prstatus_percpu[i]);
        	}
	}
	netdump_print("\n");
	netdump_print("         nt_qemu_percpu: ");
	if (nd->num_qemu_notes == 1)
		netdump_print("%.*lx\n", flen, nd->nt_qemu_percpu[0]);
	else {
	       	for (i = 0; i < nd->num_qemu_notes; i++) {
                	if ((i % wrap) == 0)
                        	netdump_print("\n        ");
                	netdump_print("%.*lx ", flen, 
				nd->nt_qemu_percpu[i]);
        	}
	}
	netdump_print("\n");
	netdump_print("       backup_src_start: %llx\n", nd->backup_src_start);
	netdump_print("        backup_src_size: %lx\n", nd->backup_src_size);
	netdump_print("          backup_offset: %llx\n", nd->backup_offset);
	netdump_print("\n");

        switch (DUMPFILE_FORMAT(nd->flags))
	{
	case NETDUMP_ELF32:
	case KDUMP_ELF32:
		dump_Elf32_Ehdr(nd->elf32);
		dump_Elf32_Phdr(nd->notes32, ELFREAD);
                for (i = 0; i < nd->num_pt_load_segments; i++) 
			dump_Elf32_Phdr(nd->load32 + i, ELFREAD);
        	offset32 = nd->notes32->p_offset;
        	for (tot = 0; tot < nd->notes32->p_filesz; tot += len) {
                	if (!(len = dump_Elf32_Nhdr(offset32, ELFREAD)))
				break;
			offset32 += len;
        	}
		break;

	case NETDUMP_ELF64:
	case KDUMP_ELF64:
		dump_Elf64_Ehdr(nd->elf64);
		dump_Elf64_Phdr(nd->notes64, ELFREAD);
                for (i = 0; i < nd->num_pt_load_segments; i++)
			dump_Elf64_Phdr(nd->load64 + i, ELFREAD);
		if (nd->sect0_64)
			dump_Elf64_Shdr(nd->sect0_64);
        	offset64 = nd->notes64->p_offset;
        	for (tot = 0; tot < nd->notes64->p_filesz; tot += len) {
                	if (!(len = dump_Elf64_Nhdr(offset64, ELFREAD)))
				break;
                	offset64 += len;
        	}
		break;
	}

	dump_ramdump_data();

	nd->ofp = fpsave;
        return TRUE;
}

/* 
 *  Dump an ELF file header.
 */
static void 
dump_Elf32_Ehdr(Elf32_Ehdr *elf)
{
	char buf[BUFSIZE];

	BZERO(buf, BUFSIZE);
	BCOPY(elf->e_ident, buf, SELFMAG); 
	netdump_print("Elf32_Ehdr:\n");
	netdump_print("                e_ident: \\%o%s\n", buf[0], 
		&buf[1]);
	netdump_print("      e_ident[EI_CLASS]: %d ", elf->e_ident[EI_CLASS]);
	switch (elf->e_ident[EI_CLASS])
	{
	case ELFCLASSNONE:
		netdump_print("(ELFCLASSNONE)");
		break;
	case ELFCLASS32:
		netdump_print("(ELFCLASS32)\n");
		break;
	case ELFCLASS64:
		netdump_print("(ELFCLASS64)\n");
		break;
	case ELFCLASSNUM:
		netdump_print("(ELFCLASSNUM)\n");
		break;
	default:
		netdump_print("(?)\n");
		break;
	}
	netdump_print("       e_ident[EI_DATA]: %d ", elf->e_ident[EI_DATA]);
	switch (elf->e_ident[EI_DATA])
	{
	case ELFDATANONE:
		netdump_print("(ELFDATANONE)\n");
		break;
	case ELFDATA2LSB: 
		netdump_print("(ELFDATA2LSB)\n");
		break;
	case ELFDATA2MSB:
		netdump_print("(ELFDATA2MSB)\n");
		break;
	case ELFDATANUM:
		netdump_print("(ELFDATANUM)\n");
		break;
        default:
                netdump_print("(?)\n");
	}
	netdump_print("    e_ident[EI_VERSION]: %d ", 
		elf->e_ident[EI_VERSION]);
	if (elf->e_ident[EI_VERSION] == EV_CURRENT)
		netdump_print("(EV_CURRENT)\n");
	else
		netdump_print("(?)\n");
	netdump_print("      e_ident[EI_OSABI]: %d ", elf->e_ident[EI_OSABI]);
	switch (elf->e_ident[EI_OSABI])
	{
	case ELFOSABI_SYSV:   
		netdump_print("(ELFOSABI_SYSV)\n");
		break;
	case ELFOSABI_HPUX:    
		netdump_print("(ELFOSABI_HPUX)\n");
		break;
	case ELFOSABI_ARM:      
		netdump_print("(ELFOSABI_ARM)\n");
		break;
	case ELFOSABI_STANDALONE:
		netdump_print("(ELFOSABI_STANDALONE)\n");
		break;
	case ELFOSABI_LINUX:
		netdump_print("(ELFOSABI_LINUX)\n");
		break;
        default:
                netdump_print("(?)\n");
	}
	netdump_print(" e_ident[EI_ABIVERSION]: %d\n", 
		elf->e_ident[EI_ABIVERSION]);

	netdump_print("                 e_type: %d ", elf->e_type);
	switch (elf->e_type)
	{
	case ET_NONE:
		netdump_print("(ET_NONE)\n");
		break;
	case ET_REL:
		netdump_print("(ET_REL)\n");
		break;
	case ET_EXEC:
		netdump_print("(ET_EXEC)\n");
		break;
	case ET_DYN:
		netdump_print("(ET_DYN)\n");
		break;
	case ET_CORE:
		netdump_print("(ET_CORE)\n");
		break;
	case ET_NUM:
		netdump_print("(ET_NUM)\n");
		break;
	case ET_LOOS:
		netdump_print("(ET_LOOS)\n");
		break;
	case ET_HIOS:
		netdump_print("(ET_HIOS)\n");
		break;
	case ET_LOPROC:
		netdump_print("(ET_LOPROC)\n");
		break;
	case ET_HIPROC:
		netdump_print("(ET_HIPROC)\n");
		break;
	default:
		netdump_print("(?)\n");
	}

        netdump_print("              e_machine: %d ", elf->e_machine);
	switch (elf->e_machine) 
	{
	case EM_ARM:
		netdump_print("(EM_ARM)\n");
		break;
	case EM_386:
		netdump_print("(EM_386)\n");
		break;
	case EM_MIPS:
		netdump_print("(EM_MIPS)\n");
		break;
	case EM_LOONGARCH:
		netdump_print("(EM_LOONGARCH)\n");
		break;
	default:
		netdump_print("(unsupported)\n");
		break;
	}

        netdump_print("              e_version: %ld ", elf->e_version);
	netdump_print("%s\n", elf->e_version == EV_CURRENT ? 
		"(EV_CURRENT)" : "");

        netdump_print("                e_entry: %lx\n", elf->e_entry);
        netdump_print("                e_phoff: %lx\n", elf->e_phoff);
        netdump_print("                e_shoff: %lx\n", elf->e_shoff);
        netdump_print("                e_flags: %lx\n", elf->e_flags);
	if ((elf->e_flags & DUMP_ELF_INCOMPLETE) && 
	    (DUMPFILE_FORMAT(nd->flags) == KDUMP_ELF32))
		pc->flags2 |= INCOMPLETE_DUMP;
        netdump_print("               e_ehsize: %x\n", elf->e_ehsize);
        netdump_print("            e_phentsize: %x\n", elf->e_phentsize);
        netdump_print("                e_phnum: %x\n", elf->e_phnum);
        netdump_print("            e_shentsize: %x\n", elf->e_shentsize);
        netdump_print("                e_shnum: %x\n", elf->e_shnum);
        netdump_print("             e_shstrndx: %x\n", elf->e_shstrndx);
}

static void 
dump_Elf64_Ehdr(Elf64_Ehdr *elf)
{
	char buf[BUFSIZE];

	BZERO(buf, BUFSIZE);
	BCOPY(elf->e_ident, buf, SELFMAG); 
	netdump_print("Elf64_Ehdr:\n");
	netdump_print("                e_ident: \\%o%s\n", buf[0], 
		&buf[1]);
	netdump_print("      e_ident[EI_CLASS]: %d ", elf->e_ident[EI_CLASS]);
	switch (elf->e_ident[EI_CLASS])
	{
	case ELFCLASSNONE:
		netdump_print("(ELFCLASSNONE)");
		break;
	case ELFCLASS32:
		netdump_print("(ELFCLASS32)\n");
		break;
	case ELFCLASS64:
		netdump_print("(ELFCLASS64)\n");
		break;
	case ELFCLASSNUM:
		netdump_print("(ELFCLASSNUM)\n");
		break;
	default:
		netdump_print("(?)\n");
		break;
	}
	netdump_print("       e_ident[EI_DATA]: %d ", elf->e_ident[EI_DATA]);
	switch (elf->e_ident[EI_DATA])
	{
	case ELFDATANONE:
		netdump_print("(ELFDATANONE)\n");
		break;
	case ELFDATA2LSB: 
		netdump_print("(ELFDATA2LSB)\n");
		break;
	case ELFDATA2MSB:
		netdump_print("(ELFDATA2MSB)\n");
		break;
	case ELFDATANUM:
		netdump_print("(ELFDATANUM)\n");
		break;
        default:
                netdump_print("(?)\n");
	}
	netdump_print("    e_ident[EI_VERSION]: %d ", 
		elf->e_ident[EI_VERSION]);
	if (elf->e_ident[EI_VERSION] == EV_CURRENT)
		netdump_print("(EV_CURRENT)\n");
	else
		netdump_print("(?)\n");
	netdump_print("      e_ident[EI_OSABI]: %d ", elf->e_ident[EI_OSABI]);
	switch (elf->e_ident[EI_OSABI])
	{
	case ELFOSABI_SYSV:   
		netdump_print("(ELFOSABI_SYSV)\n");
		break;
	case ELFOSABI_HPUX:    
		netdump_print("(ELFOSABI_HPUX)\n");
		break;
	case ELFOSABI_ARM:      
		netdump_print("(ELFOSABI_ARM)\n");
		break;
	case ELFOSABI_STANDALONE:
		netdump_print("(ELFOSABI_STANDALONE)\n");
		break;
	case ELFOSABI_LINUX:
		netdump_print("(ELFOSABI_LINUX)\n");
		break;
        default:
                netdump_print("(?)\n");
	}
	netdump_print(" e_ident[EI_ABIVERSION]: %d\n", 
		elf->e_ident[EI_ABIVERSION]);

	netdump_print("                 e_type: %d ", elf->e_type);
	switch (elf->e_type)
	{
	case ET_NONE:
		netdump_print("(ET_NONE)\n");
		break;
	case ET_REL:
		netdump_print("(ET_REL)\n");
		break;
	case ET_EXEC:
		netdump_print("(ET_EXEC)\n");
		break;
	case ET_DYN:
		netdump_print("(ET_DYN)\n");
		break;
	case ET_CORE:
		netdump_print("(ET_CORE)\n");
		break;
	case ET_NUM:
		netdump_print("(ET_NUM)\n");
		break;
	case ET_LOOS:
		netdump_print("(ET_LOOS)\n");
		break;
	case ET_HIOS:
		netdump_print("(ET_HIOS)\n");
		break;
	case ET_LOPROC:
		netdump_print("(ET_LOPROC)\n");
		break;
	case ET_HIPROC:
		netdump_print("(ET_HIPROC)\n");
		break;
	default:
		netdump_print("(?)\n");
	}

        netdump_print("              e_machine: %d ", elf->e_machine);
        switch (elf->e_machine)
        {
	case EM_386:
		netdump_print("(EM_386)\n");
		break;
        case EM_IA_64:
                netdump_print("(EM_IA_64)\n");
                break;
        case EM_PPC64:
                netdump_print("(EM_PPC64)\n");
                break;
        case EM_X86_64:
                netdump_print("(EM_X86_64)\n");
                break;
	case EM_S390:
                netdump_print("(EM_S390)\n");
                break;
	case EM_ARM:
                netdump_print("(EM_ARM)\n");
                break;
	case EM_AARCH64:
                netdump_print("(EM_AARCH64)\n");
                break;
	case EM_LOONGARCH:
		netdump_print("(EM_LOONGARCH)\n");
		break;
        default:
                netdump_print("(unsupported)\n");
                break;
        }

        netdump_print("              e_version: %ld ", elf->e_version);
	netdump_print("%s\n", elf->e_version == EV_CURRENT ? 
		"(EV_CURRENT)" : "");

        netdump_print("                e_entry: %lx\n", elf->e_entry);
        netdump_print("                e_phoff: %lx\n", elf->e_phoff);
        netdump_print("                e_shoff: %lx\n", elf->e_shoff);
        netdump_print("                e_flags: %lx\n", elf->e_flags);
	if ((elf->e_flags & DUMP_ELF_INCOMPLETE) && 
	    (DUMPFILE_FORMAT(nd->flags) == KDUMP_ELF64))
		pc->flags2 |= INCOMPLETE_DUMP;
        netdump_print("               e_ehsize: %x\n", elf->e_ehsize);
        netdump_print("            e_phentsize: %x\n", elf->e_phentsize);
        netdump_print("                e_phnum: %x\n", elf->e_phnum);
        netdump_print("            e_shentsize: %x\n", elf->e_shentsize);
        netdump_print("                e_shnum: %x\n", elf->e_shnum);
        netdump_print("             e_shstrndx: %x\n", elf->e_shstrndx);
}

/*
 *  Dump a program segment header 
 */
static void
dump_Elf32_Phdr(Elf32_Phdr *prog, int store_pt_load_data)
{
	int others;
	struct pt_load_segment *pls;

        if ((char *)prog > (nd->elf_header + nd->header_size))
		error(FATAL,
		    "Elf32_Phdr pointer: %lx  ELF header end: %lx\n\n",
			(char *)prog, nd->elf_header + nd->header_size);

	if (store_pt_load_data) 
		pls = &nd->pt_load_segments[store_pt_load_data-1];
	else
		pls = NULL;

	netdump_print("Elf32_Phdr:\n");
	netdump_print("                 p_type: %lx ", prog->p_type);
	switch (prog->p_type)
	{
	case PT_NULL: 
		netdump_print("(PT_NULL)\n");
		break;
	case PT_LOAD:
		netdump_print("(PT_LOAD)\n");
		break;
	case PT_DYNAMIC: 
		netdump_print("(PT_DYNAMIC)\n");
		break;
	case PT_INTERP: 
		netdump_print("(PT_INTERP)\n");
		break;
	case PT_NOTE:  
		netdump_print("(PT_NOTE)\n");
		break;
	case PT_SHLIB: 
		netdump_print("(PT_SHLIB)\n");
		break;
	case PT_PHDR:  
		netdump_print("(PT_PHDR)\n");
		break;
	case PT_NUM:
		netdump_print("(PT_NUM)\n");
		break;
	case PT_LOOS:
		netdump_print("(PT_LOOS)\n");
		break;
	case PT_HIOS:
		netdump_print("(PT_HIOS)\n");
		break;
	case PT_LOPROC:
		netdump_print("(PT_LOPROC)\n");
		break;
	case PT_HIPROC:
		netdump_print("(PT_HIPROC)\n");
		break;
	default:
		netdump_print("(?)\n");
	}

	netdump_print("               p_offset: %ld (%lx)\n", prog->p_offset, 
		prog->p_offset);
	if (store_pt_load_data)
		pls->file_offset = prog->p_offset;
	netdump_print("                p_vaddr: %lx\n", prog->p_vaddr);
	netdump_print("                p_paddr: %lx\n", prog->p_paddr);
	if (store_pt_load_data)
		pls->phys_start = prog->p_paddr; 
	netdump_print("               p_filesz: %lu (%lx)\n", prog->p_filesz, 
		prog->p_filesz);
	if (store_pt_load_data) {
		pls->phys_end = pls->phys_start + prog->p_filesz;
		pls->zero_fill = (prog->p_filesz == prog->p_memsz) ? 
			0 : pls->phys_start + prog->p_memsz;
	}
	netdump_print("                p_memsz: %lu (%lx)\n", prog->p_memsz,
		prog->p_memsz);
	netdump_print("                p_flags: %lx (", prog->p_flags);
	others = 0;
	if (prog->p_flags & PF_X)
		netdump_print("PF_X", others++);
	if (prog->p_flags & PF_W)
		netdump_print("%sPF_W", others++ ? "|" : "");
	if (prog->p_flags & PF_R)
		netdump_print("%sPF_R", others++ ? "|" : "");
	netdump_print(")\n");
	netdump_print("                p_align: %ld\n", prog->p_align);
}

static void 
dump_Elf64_Phdr(Elf64_Phdr *prog, int store_pt_load_data)
{
	int others;
	struct pt_load_segment *pls;

	if (store_pt_load_data)
		pls = &nd->pt_load_segments[store_pt_load_data-1];
	else
		pls = NULL;

        if ((char *)prog > (nd->elf_header + nd->header_size))
		error(FATAL,
		    "Elf64_Phdr pointer: %lx  ELF header end: %lx\n\n",
			(char *)prog, nd->elf_header + nd->header_size);

	netdump_print("Elf64_Phdr:\n");
	netdump_print("                 p_type: %lx ", prog->p_type);
	switch (prog->p_type)
	{
	case PT_NULL: 
		netdump_print("(PT_NULL)\n");
		break;
	case PT_LOAD:
		netdump_print("(PT_LOAD)\n");
		break;
	case PT_DYNAMIC: 
		netdump_print("(PT_DYNAMIC)\n");
		break;
	case PT_INTERP: 
		netdump_print("(PT_INTERP)\n");
		break;
	case PT_NOTE:  
		netdump_print("(PT_NOTE)\n");
		break;
	case PT_SHLIB: 
		netdump_print("(PT_SHLIB)\n");
		break;
	case PT_PHDR:  
		netdump_print("(PT_PHDR)\n");
		break;
	case PT_NUM:
		netdump_print("(PT_NUM)\n");
		break;
	case PT_LOOS:
		netdump_print("(PT_LOOS)\n");
		break;
	case PT_HIOS:
		netdump_print("(PT_HIOS)\n");
		break;
	case PT_LOPROC:
		netdump_print("(PT_LOPROC)\n");
		break;
	case PT_HIPROC:
		netdump_print("(PT_HIPROC)\n");
		break;
	default:
		netdump_print("(?)\n");
	}

	netdump_print("               p_offset: %lld (%llx)\n", prog->p_offset, 
		prog->p_offset);
	if (store_pt_load_data)
		pls->file_offset = prog->p_offset;
	netdump_print("                p_vaddr: %llx\n", prog->p_vaddr);
	netdump_print("                p_paddr: %llx\n", prog->p_paddr);
	if (store_pt_load_data)
		pls->phys_start = prog->p_paddr; 
	netdump_print("               p_filesz: %llu (%llx)\n", prog->p_filesz, 
		prog->p_filesz);
	if (store_pt_load_data) {
		pls->phys_end = pls->phys_start + prog->p_filesz;
		pls->zero_fill = (prog->p_filesz == prog->p_memsz) ?
			0 : pls->phys_start + prog->p_memsz;
	}
	netdump_print("                p_memsz: %llu (%llx)\n", prog->p_memsz,
		prog->p_memsz);
	netdump_print("                p_flags: %lx (", prog->p_flags);
	others = 0;
	if (prog->p_flags & PF_X)
		netdump_print("PF_X", others++);
	if (prog->p_flags & PF_W)
		netdump_print("%sPF_W", others++ ? "|" : "");
	if (prog->p_flags & PF_R)
		netdump_print("%sPF_R", others++ ? "|" : "");
	netdump_print(")\n");
	netdump_print("                p_align: %lld\n", prog->p_align);
}

static void
dump_Elf64_Shdr(Elf64_Shdr *shdr)
{
	netdump_print("Elf64_Shdr:\n");
	netdump_print("                sh_name: %x\n", shdr->sh_name);
	netdump_print("                sh_type: %x ", shdr->sh_type);
	switch (shdr->sh_type)
	{
	case SHT_NULL:
		netdump_print("(SHT_NULL)\n");
		break;
	default:
		netdump_print("\n");
		break;
	}
	netdump_print("               sh_flags: %lx\n", shdr->sh_flags);
	netdump_print("                sh_addr: %lx\n", shdr->sh_addr);
	netdump_print("              sh_offset: %lx\n", shdr->sh_offset);
	netdump_print("                sh_size: %lx\n", shdr->sh_size);
	netdump_print("                sh_link: %x\n", shdr->sh_link);
	netdump_print("                sh_info: %x (%u)\n", shdr->sh_info,
		shdr->sh_info);
	netdump_print("           sh_addralign: %lx\n", shdr->sh_addralign);
	netdump_print("             sh_entsize: %lx\n", shdr->sh_entsize);
}

/*
 * VMCOREINFO
 *
 * This is a ELF note intented for makedumpfile that is exported by the
 * kernel that crashes and presented as ELF note to the /proc/vmcore
 * of the panic kernel.
 */

#define VMCOREINFO_NOTE_NAME        "VMCOREINFO"
#define VMCOREINFO_NOTE_NAME_BYTES  (sizeof(VMCOREINFO_NOTE_NAME))

/*
 * Reads a string value from VMCOREINFO.
 *
 * Returns a string (that has to be freed by the caller) that contains the
 * value for key or NULL if the key has not been found.
 */
static char *
vmcoreinfo_read_string(const char *key)
{
	int i, j, end;
	size_t value_length;
	size_t key_length = strlen(key);
	char *vmcoreinfo;
	uint size_vmcoreinfo;
	char *value = NULL;

	/*
	 *  Borrow this function for ELF vmcores created by the snap.so
	 *  extension module, where arch-specific data may be passed in 
	 *  the NT_TASKSTRUCT note.
	 */
	if ((pc->flags2 & SNAP)) {
		if (STREQ(key, "NUMBER(kimage_voffset)") && nd->arch_data1) {
			value = calloc(VADDR_PRLEN+1, sizeof(char));
			sprintf(value, "%lx", nd->arch_data1);
			if (nd->arch_data2 == 0)
				pc->read_vmcoreinfo = no_vmcoreinfo;
			return value;
		}
		if (STREQ(key, "NUMBER(VA_BITS)") && nd->arch_data2) {
			value = calloc(VADDR_PRLEN+1, sizeof(char));
			sprintf(value, "%ld", nd->arch_data2 & 0xffffffff);
			return value;
		}
		if ((STREQ(key, "NUMBER(TCR_EL1_T1SZ)") ||
		     STREQ(key, "NUMBER(tcr_el1_t1sz)")) && nd->arch_data2) {
			value = calloc(VADDR_PRLEN+1, sizeof(char));
			sprintf(value, "%lld", ((ulonglong)nd->arch_data2 >> 32) & 0xffffffff);
			pc->read_vmcoreinfo = no_vmcoreinfo;
			return value;
		}
		if (STREQ(key, "relocate") && nd->arch_data1) {
			value = calloc(VADDR_PRLEN+1, sizeof(char));
			sprintf(value, "%lx", nd->arch_data1);
			pc->read_vmcoreinfo = no_vmcoreinfo;
			return value;
		}
		return NULL;
	}

	if (nd->vmcoreinfo) {
		vmcoreinfo = (char *)nd->vmcoreinfo;
		size_vmcoreinfo = nd->size_vmcoreinfo;
	} else if (ACTIVE() && pkd->vmcoreinfo) {
		vmcoreinfo = (char *)pkd->vmcoreinfo;
		size_vmcoreinfo = pkd->size_vmcoreinfo;
	} else {
		vmcoreinfo = NULL;
		size_vmcoreinfo = 0;
	}

	if (!vmcoreinfo)
		return NULL;

	/* the '+ 1' is the equal sign */
	for (i = 0; i < (int)(size_vmcoreinfo - key_length + 1); i++) {
		/*
		 * We must also check if we're at the beginning of VMCOREINFO
		 * or the separating newline is there, and of course if we 
		 * have a equal sign after the key.
		 */
		if ((strncmp(vmcoreinfo+i, key, key_length) == 0) &&
		    (i == 0 || vmcoreinfo[i-1] == '\n') &&
		    (vmcoreinfo[i+key_length] == '=')) {

			end = -1;

			/* Found -- search for the next newline. */
			for (j = i + key_length + 1; 
			     j < size_vmcoreinfo; j++) {
				if (vmcoreinfo[j] == '\n') {
					end = j;
					break;
				}
			}

			/* 
			 * If we didn't find an end, we assume it's the end 
			 * of VMCOREINFO data. 
			 */
			if (end == -1) {
				/* Point after the end. */
				end = size_vmcoreinfo + 1;
			}

			value_length = end - (1+ i + key_length);
			value = calloc(value_length+1, sizeof(char));
			if (value)
				strncpy(value, vmcoreinfo + i + key_length + 1, 
					value_length);
			break;
		}
	}

	return value;
}

/*
 * Reads an integer value from VMCOREINFO.
 */
static long
vmcoreinfo_read_integer(const char *key, long default_value)
{
	char *string;
	long retval = default_value;

	string = vmcoreinfo_read_string(key);
	if (string) {
		retval = atol(string);
		free(string);
	}

	return retval;
}

void
display_vmcoredd_note(void *ptr, FILE *ofp)
{
	int sp;
	unsigned int dump_size;
	struct vmcoredd_header *vh;

	sp = VMCORE_VALID() ? 25 : 22;
	vh = (struct vmcoredd_header *)ptr;

	dump_size = vh->n_descsz - VMCOREDD_MAX_NAME_BYTES;
	fprintf(ofp, "%sname: \"%s\"\n", space(sp), vh->dump_name);
	fprintf(ofp, "%ssize: %u\n", space(sp), dump_size);
}

/*
 *  Dump a note section header -- the actual data is defined by netdump
 */

static size_t 
dump_Elf32_Nhdr(Elf32_Off offset, int store)
{
	int i, lf;
	Elf32_Nhdr *note;
	size_t len;
	char buf[BUFSIZE];
	char *ptr;
	ulong *uptr;
	int xen_core, vmcoreinfo, vmcoreinfo_xen, eraseinfo, qemuinfo;
	uint64_t remaining, notesize;

	note = (Elf32_Nhdr *)((char *)nd->elf32 + offset);

        BZERO(buf, BUFSIZE);
	xen_core = vmcoreinfo = eraseinfo = qemuinfo = FALSE;
        ptr = (char *)note + sizeof(Elf32_Nhdr);

	if (ptr > (nd->elf_header + nd->header_size)) {
		error(WARNING, 
	    	    "Elf32_Nhdr pointer: %lx ELF header end: %lx\n",
			(char *)note, nd->elf_header + nd->header_size);
		return 0;
	} else
		remaining = (uint64_t)((nd->elf_header + nd->header_size) - ptr);

	notesize = (uint64_t)note->n_namesz + (uint64_t)note->n_descsz;

	if ((note->n_namesz == 0) || !remaining || (notesize > remaining)) {
		error(WARNING, 
		    "possibly corrupt Elf32_Nhdr: "
		    "n_namesz: %ld n_descsz: %ld n_type: %lx\n%s",
			note->n_namesz, note->n_descsz, note->n_type,
			note->n_namesz || note->n_descsz || !remaining ? 
			"\n" : "");
		if (note->n_namesz || note->n_descsz || !remaining)
			return 0;
	}

        netdump_print("Elf32_Nhdr:\n");
        netdump_print("               n_namesz: %ld ", note->n_namesz);

        BCOPY(ptr, buf, note->n_namesz);
        netdump_print("(\"%s\")\n", buf);

        netdump_print("               n_descsz: %ld\n", note->n_descsz);
        netdump_print("                 n_type: %lx ", note->n_type);
	switch (note->n_type)
	{
	case NT_PRSTATUS:
		netdump_print("(NT_PRSTATUS)\n");
		if (store) { 
			if (!nd->nt_prstatus)
				nd->nt_prstatus = (void *)note;
			for (i = 0; i < NR_CPUS; i++) {
				if (!nd->nt_prstatus_percpu[i]) {
					nd->nt_prstatus_percpu[i] = (void *)note;
					nd->num_prstatus_notes++;
					break;
				}
			}
		}
		if (machine_type("PPC") && (nd->num_prstatus_notes > 0))
			pc->flags2 |= ELF_NOTES;
		break;
	case NT_PRPSINFO:
		netdump_print("(NT_PRPSINFO)\n");
		if (store)
			nd->nt_prpsinfo = (void *)note;
		break;
	case NT_TASKSTRUCT:
		netdump_print("(NT_TASKSTRUCT)\n");
		if (store) {
			nd->nt_taskstruct = (void *)note;
			nd->task_struct = *((ulong *)(ptr + note->n_namesz));
		}
		break;
        case NT_DISKDUMP:
                netdump_print("(NT_DISKDUMP)\n");
		uptr = (ulong *)(ptr + note->n_namesz);
		if (*uptr && store)
			nd->flags |= PARTIAL_DUMP;
		break;
#ifdef NOTDEF
	/*
	 *  Note: Based upon the original, abandoned, proposal for
	 *  its contents -- keep around for potential future use.
	 */
	case NT_KDUMPINFO:
		netdump_print("(NT_KDUMPINFO)\n");
		if (store) {
			uptr = (note->n_namesz == 5) ?
				(ulong *)(ptr + ((note->n_namesz + 3) & ~3)) :
				(ulong *)(ptr + note->n_namesz);
			nd->page_size = (uint)(1 << *uptr);
			uptr++;
			nd->task_struct = *uptr;
		}
		break;
#endif
	case NT_VMCOREDD:
		netdump_print("(NT_VMCOREDD)\n");
		if (store) {
			for (i = 0; i < NR_DEVICE_DUMPS; i++) {
				if (!nd->nt_vmcoredd_array[i]) {
					nd->nt_vmcoredd_array[i] = (void *)note;
					nd->num_vmcoredd_notes++;
					break;
				}
			}
		}
		break;
	default:
		xen_core = STRNEQ(buf, "XEN CORE") || STRNEQ(buf, "Xen");
		if (STRNEQ(buf, "VMCOREINFO_XEN"))
			vmcoreinfo_xen = TRUE;
		else
			vmcoreinfo = STRNEQ(buf, "VMCOREINFO");
		eraseinfo = STRNEQ(buf, "ERASEINFO");
		qemuinfo = STRNEQ(buf, "QEMU");
		if (xen_core) {
			netdump_print("(unknown Xen n_type)\n"); 
			if (store)
				error(WARNING, "unknown Xen n_type: %lx\n\n", 
					note->n_type);
		} else if (vmcoreinfo) {
			netdump_print("(unused)\n");
			nd->vmcoreinfo = (char *)(ptr + note->n_namesz + 1);
			nd->size_vmcoreinfo = note->n_descsz;
			if (READ_PAGESIZE_FROM_VMCOREINFO() && store)
				nd->page_size = (uint)
					vmcoreinfo_read_integer("PAGESIZE", 0);
			pc->flags2 |= VMCOREINFO;
		} else if (eraseinfo) {
			netdump_print("(unused)\n");
			if (note->n_descsz)
				pc->flags2 |= ERASEINFO_DATA;
		} else if (qemuinfo) {
			pc->flags2 |= QEMU_MEM_DUMP_ELF;
			netdump_print("(QEMUCPUState)\n");
		} else if (vmcoreinfo_xen)
			netdump_print("(unused)\n");
		else
			netdump_print("(?)\n");
		break;

	case NT_XEN_KDUMP_CR3: 
                netdump_print("(NT_XEN_KDUMP_CR3) [obsolete]\n");
		/* FALL THROUGH */

	case XEN_ELFNOTE_CRASH_INFO:
		/*
		 *  x86 and x86_64: p2m mfn appended to crash_xen_info_t structure
		 */
		if (note->n_type == XEN_ELFNOTE_CRASH_INFO)
                	netdump_print("(XEN_ELFNOTE_CRASH_INFO)\n");
		xen_core = TRUE;
		if (store)
			process_xen_note(note->n_type,
					 ptr + roundup(note->n_namesz, 4),
					 note->n_descsz);
		break;

	case XEN_ELFNOTE_CRASH_REGS:
      		/* 
		 *  x86 and x86_64: cr0, cr2, cr3, cr4 
		 */
		xen_core = TRUE;	
               	netdump_print("(XEN_ELFNOTE_CRASH_REGS)\n");
		break;
	}

	uptr = (ulong *)(ptr + note->n_namesz);

	/*
	 * kdumps are off-by-1, because their n_namesz is 5 for "CORE".
 	 */
	if ((nd->flags & KDUMP_ELF32) && (note->n_namesz == 5))
		uptr = (ulong *)(ptr + ((note->n_namesz + 3) & ~3));

	if (xen_core)
		uptr = (ulong *)roundup((ulong)uptr, 4);

	if (store && qemuinfo) {
		for(i = 0; i < NR_CPUS; i++) {
			if (!nd->nt_qemu_percpu[i]) {
				nd->nt_qemu_percpu[i] = (void *)uptr;
				nd->num_qemu_notes++;
				break;
			}
		}
	}

	if (vmcoreinfo || eraseinfo || vmcoreinfo_xen) {
                netdump_print("                         ");
                ptr += note->n_namesz + 1;
                for (i = 0; i < note->n_descsz; i++, ptr++) {
                        netdump_print("%c", *ptr);
                        if (*ptr == '\n')
                                netdump_print("                         ");
                }
                lf = 0;
	} else if (note->n_type == NT_VMCOREDD) {
		if (nd->ofp)
			display_vmcoredd_note(note, nd->ofp);
	} else {
		if (nd->ofp && !XEN_CORE_DUMPFILE() && !(pc->flags2 & LIVE_DUMP)) {
			if (machine_type("X86")) {
				if (note->n_type == NT_PRSTATUS)
					display_ELF_note(EM_386, PRSTATUS_NOTE, note, nd->ofp);
				else if (qemuinfo)
					display_ELF_note(EM_386, QEMU_NOTE, note, nd->ofp);
			}
		}
		for (i = lf = 0; i < note->n_descsz/sizeof(ulong); i++) {
			if (((i%4)==0)) {
				netdump_print("%s                         ", 
					i ? "\n" : "");
				lf++;
			} else
				lf = 0;
			netdump_print("%08lx ", *uptr++);
		}
	}
	if (!lf || (note->n_type == NT_TASKSTRUCT) ||
	    (note->n_type == NT_DISKDUMP) || xen_core)
		netdump_print("\n");

  	len = sizeof(Elf32_Nhdr);
  	len = roundup(len + note->n_namesz, 4);
  	len = roundup(len + note->n_descsz, 4);

	return len;
}


static size_t 
dump_Elf64_Nhdr(Elf64_Off offset, int store)
{
	int i = 0, lf = 0;
	Elf64_Nhdr *note;
	size_t len;
	char buf[BUFSIZE];
	char *ptr;
	ulonglong *uptr;
	int *iptr;
	int xen_core, vmcoreinfo, vmcoreinfo_xen, eraseinfo, qemuinfo;
	uint64_t remaining, notesize;

	note = (Elf64_Nhdr *)((char *)nd->elf64 + offset);

        BZERO(buf, BUFSIZE);
        ptr = (char *)note + sizeof(Elf64_Nhdr);
	xen_core = vmcoreinfo = vmcoreinfo_xen = eraseinfo = qemuinfo = FALSE;

	if (ptr > (nd->elf_header + nd->header_size)) {
		error(WARNING, 
	    	    "Elf64_Nhdr pointer: %lx  ELF header end: %lx\n\n",
			(char *)note, nd->elf_header + nd->header_size);
		return 0;
	} else
		remaining = (uint64_t)((nd->elf_header + nd->header_size) - ptr);

	notesize = (uint64_t)note->n_namesz + (uint64_t)note->n_descsz;

	if ((note->n_namesz == 0) || !remaining || (notesize > remaining)) {
		error(WARNING, 
		    "possibly corrupt Elf64_Nhdr: "
		    "n_namesz: %ld n_descsz: %ld n_type: %lx\n%s",
			note->n_namesz, note->n_descsz, note->n_type,
			note->n_namesz || note->n_descsz || !remaining ? 
			"\n" : "");
		if (note->n_namesz || note->n_descsz || !remaining)
			return 0;
	}

        netdump_print("Elf64_Nhdr:\n");
        netdump_print("               n_namesz: %ld ", note->n_namesz);

        BCOPY(ptr, buf, note->n_namesz);
        netdump_print("(\"%s\")\n", buf);

        netdump_print("               n_descsz: %ld\n", note->n_descsz);
        netdump_print("                 n_type: %lx ", note->n_type);
	switch (note->n_type)
	{
	case NT_PRSTATUS:
		netdump_print("(NT_PRSTATUS)\n");
		if (store) {
			if (!nd->nt_prstatus)
				nd->nt_prstatus = (void *)note;
			for (i = 0; i < NR_CPUS; i++) {
				if (!nd->nt_prstatus_percpu[i]) {
					nd->nt_prstatus_percpu[i] = (void *)note;
					nd->num_prstatus_notes++;
					break;
				}
			}
		}
		break;
	case NT_PRPSINFO:
		netdump_print("(NT_PRPSINFO)\n");
		if (store)
			nd->nt_prpsinfo = (void *)note;
		break;
	case NT_FPREGSET:
		netdump_print("(NT_FPREGSET)\n");
		break;
	case NT_S390_TIMER:
		netdump_print("(NT_S390_TIMER)\n");
		break;
	case NT_S390_TODCMP:
		netdump_print("(NT_S390_TODCMP)\n");
		break;
	case NT_S390_TODPREG:
		netdump_print("(NT_S390_TODPREG)\n");
		break;
	case NT_S390_CTRS:
		netdump_print("(NT_S390_CTRS)\n");
		break;
	case NT_S390_PREFIX:
		netdump_print("(NT_S390_PREFIX)\n");
		break;
	case NT_S390_VXRS_LOW:
		netdump_print("(NT_S390_VXRS_LOW)\n");
		break;
	case NT_S390_VXRS_HIGH:
		netdump_print("(NT_S390_VXRS_HIGH)\n");
		break;
	case NT_TASKSTRUCT:
		netdump_print("(NT_TASKSTRUCT)\n");
		if (STRNEQ(buf, "SNAP"))
			pc->flags2 |= (LIVE_DUMP|SNAP);
		if (store) {
			nd->nt_taskstruct = (void *)note;
			nd->task_struct = *((ulong *)(ptr + note->n_namesz));
			if (pc->flags2 & SNAP) {
				if (note->n_descsz >= 16)
					nd->arch_data1 = *((ulong *)
						(ptr + note->n_namesz + sizeof(ulong)));
				if (note->n_descsz >= 24)
					nd->arch_data2 = *((ulong *)
						(ptr + note->n_namesz + sizeof(ulong) + sizeof(ulong)));
			} else if (machine_type("IA64"))
				nd->switch_stack = *((ulong *)
					(ptr + note->n_namesz + sizeof(ulong)));
		}
		break;
        case NT_DISKDUMP:
                netdump_print("(NT_DISKDUMP)\n");
		iptr = (int *)(ptr + note->n_namesz);
		if (*iptr && store)
			nd->flags |= PARTIAL_DUMP;
		if (note->n_descsz < sizeof(ulonglong))
			netdump_print("                         %08x", *iptr);
		break;
#ifdef NOTDEF
	/*
	 *  Note: Based upon the original, abandoned, proposal for
	 *  its contents -- keep around for potential future use.
	 */
        case NT_KDUMPINFO:
                netdump_print("(NT_KDUMPINFO)\n");
		if (store) {
			uint32_t *u32ptr;

			if (nd->elf64->e_machine == EM_386) {
				u32ptr = (note->n_namesz == 5) ?
				    (uint *)(ptr + ((note->n_namesz + 3) & ~3)) :
	                            (uint *)(ptr + note->n_namesz);
				nd->page_size = 1 << *u32ptr;
				u32ptr++;
				nd->task_struct = *u32ptr;
			} else {
	                       	uptr = (note->n_namesz == 5) ?
				    (ulonglong *)(ptr + ((note->n_namesz + 3) & ~3)) :
	                            (ulonglong *)(ptr + note->n_namesz);
				nd->page_size = (uint)(1 << *uptr);
				uptr++;
				nd->task_struct = *uptr;
			}
		}
                break;
#endif
	case NT_VMCOREDD:
		netdump_print("(NT_VMCOREDD)\n");
		if (store) {
			for (i = 0; i < NR_DEVICE_DUMPS; i++) {
				if (!nd->nt_vmcoredd_array[i]) {
					nd->nt_vmcoredd_array[i] = (void *)note;
					nd->num_vmcoredd_notes++;
					break;
				}
			}
		}
		break;
	default:
		xen_core = STRNEQ(buf, "XEN CORE") || STRNEQ(buf, "Xen");
		if (STRNEQ(buf, "VMCOREINFO_XEN"))
			vmcoreinfo_xen = TRUE;
		else
			vmcoreinfo = STRNEQ(buf, "VMCOREINFO");
		eraseinfo = STRNEQ(buf, "ERASEINFO");
		qemuinfo = STRNEQ(buf, "QEMU");
                if (xen_core) {
                        netdump_print("(unknown Xen n_type)\n");
			if (store)
                        	error(WARNING, 
				    "unknown Xen n_type: %lx\n\n", note->n_type);
		} else if (vmcoreinfo) {
                        netdump_print("(unused)\n");

			nd->vmcoreinfo = (char *)nd->elf64 + offset +
				(sizeof(Elf64_Nhdr) +
				((note->n_namesz + 3) & ~3));
			nd->size_vmcoreinfo = note->n_descsz;

			if (READ_PAGESIZE_FROM_VMCOREINFO() && store)
				nd->page_size = (uint)
					vmcoreinfo_read_integer("PAGESIZE", 0);
			pc->flags2 |= VMCOREINFO;
		} else if (eraseinfo) {
			netdump_print("(unused)\n");
			if (note->n_descsz)
				pc->flags2 |= ERASEINFO_DATA;
		} else if (qemuinfo) {
			pc->flags2 |= QEMU_MEM_DUMP_ELF;
			netdump_print("(QEMUCPUState)\n");
		} else if (vmcoreinfo_xen)
			netdump_print("(unused)\n");
                else
                        netdump_print("(?)\n");
                break;

	case NT_XEN_KDUMP_CR3: 
                netdump_print("(NT_XEN_KDUMP_CR3) [obsolete]\n");
		/* FALL THROUGH */

	case XEN_ELFNOTE_CRASH_INFO:
		/*
		 *  x86 and x86_64: p2m mfn appended to crash_xen_info_t structure
		 */
		if (note->n_type == XEN_ELFNOTE_CRASH_INFO)
                	netdump_print("(XEN_ELFNOTE_CRASH_INFO)\n");
		xen_core = TRUE;
		if (store)
			process_xen_note(note->n_type,
					 ptr + roundup(note->n_namesz, 4),
					 note->n_descsz);
                break;

        case XEN_ELFNOTE_CRASH_REGS:
      		/* 
		 *  x86 and x86_64: cr0, cr2, cr3, cr4 
		 */
                xen_core = TRUE;
                netdump_print("(XEN_ELFNOTE_CRASH_REGS)\n");
                break;
	}

	if (machine_type("S390X")) {
		if (store)
			machdep->dumpfile_init(nd->num_prstatus_notes, note);

		uptr = (ulonglong *)
	    	    ((void *)note + roundup(sizeof(*note) + note->n_namesz, 4));
	} else {
		uptr = (ulonglong *)(ptr + note->n_namesz);
	
		/*
		 * kdumps are off-by-1, because their n_namesz is 5 for "CORE".
		 */
		if ((nd->flags & KDUMP_ELF64) && (note->n_namesz == 5))
			uptr = (ulonglong *)(ptr + ((note->n_namesz + 3) & ~3));
	
		if (xen_core)
			uptr = (ulonglong *)roundup((ulong)uptr, 4);
	}

	if (store && qemuinfo) {
		for(i=0; i<NR_CPUS; i++) {
			if (!nd->nt_qemu_percpu[i]) {
				nd->nt_qemu_percpu[i] = (void *)uptr;
				nd->num_qemu_notes++;
				break;
			}
		}
	}

	if (note->n_type == NT_VMCOREDD) {
		if (nd->ofp)
			display_vmcoredd_note(note, nd->ofp);
	} else if (BITS32() && (xen_core || (note->n_type == NT_PRSTATUS) || qemuinfo)) {
		if (nd->ofp && !XEN_CORE_DUMPFILE() && !(pc->flags2 & LIVE_DUMP)) {
			if (machine_type("X86")) { 
				if (note->n_type == NT_PRSTATUS)
					display_ELF_note(EM_386, PRSTATUS_NOTE, note, nd->ofp);
				else if (qemuinfo)
					display_ELF_note(EM_386, QEMU_NOTE, note, nd->ofp);
			}
		}

		iptr = (int *)uptr;
		for (i = lf = 0; i < note->n_descsz/sizeof(ulong); i++) {
			if (((i%4)==0)) {
				netdump_print("%s                         ", 
					i ? "\n" : "");
				lf++;
			} else
				lf = 0;
			netdump_print("%08lx ", *iptr++);
		}
	} else if (vmcoreinfo || eraseinfo || vmcoreinfo_xen) {
		netdump_print("                         ");
		ptr += note->n_namesz + 1;
		for (i = 0; i < note->n_descsz; i++, ptr++) {
			netdump_print("%c", *ptr);
			if (*ptr == '\n')
				netdump_print("                         ");
		}
		lf = 0;
	} else if (note->n_descsz == 4) {
		i = 0; lf = 1;
		iptr = (int *)uptr;
		netdump_print("                         %08lx\n", *iptr); 
	} else {
		if (nd->ofp && !XEN_CORE_DUMPFILE() && !(pc->flags2 & LIVE_DUMP)) {
			if (machine_type("X86_64")) {
				if (note->n_type == NT_PRSTATUS)
					display_ELF_note(EM_X86_64, PRSTATUS_NOTE, note, nd->ofp);
				else if (qemuinfo)
					display_ELF_note(EM_X86_64, QEMU_NOTE, note, nd->ofp);
			}
			if (machine_type("PPC64") && (note->n_type == NT_PRSTATUS))
				display_ELF_note(EM_PPC64, PRSTATUS_NOTE, note, nd->ofp);
			if (machine_type("ARM64") && (note->n_type == NT_PRSTATUS))
				display_ELF_note(EM_AARCH64, PRSTATUS_NOTE, note, nd->ofp);
			if (machine_type("RISCV64") && (note->n_type == NT_PRSTATUS))
				display_ELF_note(EM_RISCV, PRSTATUS_NOTE, note, nd->ofp);
		}
		for (i = lf = 0; i < note->n_descsz/sizeof(ulonglong); i++) {
			if (((i%2)==0)) {
				netdump_print("%s                         ", 
					i ? "\n" : "");
				lf++;
			} else
				lf = 0;
			netdump_print("%016llx ", *uptr++);
		}
	}
	if (!lf)
		netdump_print("\n");
	else if (i && (i&1))
		netdump_print("\n");

  	len = sizeof(Elf64_Nhdr);
  	len = roundup(len + note->n_namesz, 4);
  	len = roundup(len + note->n_descsz, 4);

	return len;
}

void *
netdump_get_prstatus_percpu(int cpu)
{
	int online;

	if ((cpu < 0) || (cpu >= nd->num_prstatus_notes))
		return NULL;

	/*
	 * If no cpu mapping was done, then there must be
	 * a one-to-one relationship between the number
	 * of online cpus and the number of notes.
	 */
	if ((online = get_cpus_online()) &&
	    (online == kt->cpus) &&
	    (online != nd->num_prstatus_notes))
		return NULL;

	return nd->nt_prstatus_percpu[cpu];
}

/*
 *  Send the request to the proper architecture hander.
 */
void
get_netdump_regs(struct bt_info *bt, ulong *eip, ulong *esp)
{
	int e_machine;

        if (nd->elf32)
        	e_machine = nd->elf32->e_machine;
        else if (nd->elf64)
       		e_machine = nd->elf64->e_machine;
        else
        	e_machine = EM_NONE;

        switch (e_machine) 
	{
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
		return get_netdump_regs_ppc(bt, eip, esp);
		break;

	case EM_PPC64:
		return get_netdump_regs_ppc64(bt, eip, esp);
		break;

	case EM_X86_64:
		return get_netdump_regs_x86_64(bt, eip, esp);
		break;

	case EM_S390:
		machdep->get_stack_frame(bt, eip, esp);
		break;

	case EM_ARM:
		return get_netdump_regs_arm(bt, eip, esp);
		break;

	case EM_AARCH64:
		return get_netdump_regs_arm64(bt, eip, esp);
		break;

	case EM_MIPS:
		return get_netdump_regs_mips(bt, eip, esp);
		break;

	case EM_RISCV:
		get_netdump_regs_riscv(bt, eip, esp);
		break;
	case EM_LOONGARCH:
		return get_netdump_regs_loongarch64(bt, eip, esp);
		break;

	default:
		error(FATAL, 
		   "support for ELF machine type %d not available\n",
			e_machine);  
	}
}

/* 
 * get regs from elf note, and return the address of user_regs. 
 */
static char * 
get_regs_from_note(char *note, ulong *ip, ulong *sp)
{
	Elf32_Nhdr *note32;
	Elf64_Nhdr *note64;
	size_t len;
	char *user_regs;
	long offset_sp, offset_ip;

	if (machine_type("X86_64")) {
		note64 = (Elf64_Nhdr *)note;
		len = sizeof(Elf64_Nhdr);
		len = roundup(len + note64->n_namesz, 4);
		len = roundup(len + note64->n_descsz, 4);
		offset_sp = OFFSET(user_regs_struct_rsp);
		offset_ip = OFFSET(user_regs_struct_rip);
	} else if (machine_type("X86")) {
		note32 = (Elf32_Nhdr *)note;
		len = sizeof(Elf32_Nhdr);
		len = roundup(len + note32->n_namesz, 4);
		len = roundup(len + note32->n_descsz, 4);
		offset_sp = OFFSET(user_regs_struct_esp);
		offset_ip = OFFSET(user_regs_struct_eip);
	} else
		return NULL;

	user_regs = note + len - SIZE(user_regs_struct) - sizeof(long);
	*sp = ULONG(user_regs + offset_sp);
	*ip = ULONG(user_regs + offset_ip);

	return user_regs;
}

void
display_regs_from_elf_notes(int cpu, FILE *ofp)
{
	Elf32_Nhdr *note32;
	Elf64_Nhdr *note64;
	size_t len;
	char *user_regs;
	int c, skipped_count;

	/*
	 * Kdump NT_PRSTATUS notes are only related to online cpus, 
	 * so offline cpus should be skipped.
	 */
	if (pc->flags2 & QEMU_MEM_DUMP_ELF)
		skipped_count = 0;
	else {
		for (c = skipped_count = 0; c < cpu; c++) {
			if (check_offline_cpu(c))
				skipped_count++;
		}
	}

	if ((cpu - skipped_count) >= nd->num_prstatus_notes &&
	     !machine_type("MIPS")) {
		error(INFO, "registers not collected for cpu %d\n", cpu);
		return;
	}

	if (machine_type("X86_64")) {
		if (nd->num_prstatus_notes > 1)
                	note64 = (Elf64_Nhdr *)
				nd->nt_prstatus_percpu[cpu];
		else
                	note64 = (Elf64_Nhdr *)nd->nt_prstatus;
		len = sizeof(Elf64_Nhdr);
		len = roundup(len + note64->n_namesz, 4);
		len = roundup(len + note64->n_descsz, 4);
		user_regs = ((char *)note64) + len - SIZE(user_regs_struct) - sizeof(long);

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
	} else if (machine_type("X86")) {
		if (nd->num_prstatus_notes > 1)
                	note32 = (Elf32_Nhdr *)
				nd->nt_prstatus_percpu[cpu];
		else
                	note32 = (Elf32_Nhdr *)nd->nt_prstatus;
		len = sizeof(Elf32_Nhdr);
		len = roundup(len + note32->n_namesz, 4);
		len = roundup(len + note32->n_descsz, 4);
		user_regs = ((char *)note32) + len - SIZE(user_regs_struct) - sizeof(long);

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
	} else if (machine_type("PPC64")) {
		struct ppc64_elf_prstatus *prs;
		struct ppc64_pt_regs *pr;

		if (nd->num_prstatus_notes > 1)
			note64 = (Elf64_Nhdr *)nd->nt_prstatus_percpu[cpu];
		else
			note64 = (Elf64_Nhdr *)nd->nt_prstatus;

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
	} else if (machine_type("ARM64")) {
		if (nd->num_prstatus_notes > 1)
                	note64 = (Elf64_Nhdr *)
				nd->nt_prstatus_percpu[cpu];
		else
                	note64 = (Elf64_Nhdr *)nd->nt_prstatus;
		len = sizeof(Elf64_Nhdr);
		len = roundup(len + note64->n_namesz, 4);
		len = roundup(len + note64->n_descsz, 4);
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
	} else if (machine_type("MIPS")) {
		mips_display_regs_from_elf_notes(cpu, ofp);
	} else if (machine_type("MIPS64")) {
		mips64_display_regs_from_elf_notes(cpu, ofp);
	} else if (machine_type("RISCV64")) {
		riscv64_display_regs_from_elf_notes(cpu, ofp);
	} else if (machine_type("LOONGARCH64")) {
		loongarch64_display_regs_from_elf_notes(cpu, ofp);
	}
}

void
dump_registers_for_elf_dumpfiles(void)
{
        int c;

        if (!(machine_type("X86") || machine_type("X86_64") || 
	    machine_type("ARM64") || machine_type("PPC64") ||
	    machine_type("MIPS") || machine_type("MIPS64") ||
	    machine_type("RISCV64") || machine_type("LOONGARCH64")))
                error(FATAL, "-r option not supported for this dumpfile\n");

	if (NETDUMP_DUMPFILE()) {
                display_regs_from_elf_notes(0, fp);
		return;
	}

        for (c = 0; c < kt->cpus; c++) {
		if (check_offline_cpu(c)) {
			fprintf(fp, "%sCPU %d: [OFFLINE]\n", c ? "\n" : "", c);
			continue;
		}

                fprintf(fp, "%sCPU %d:\n", c ? "\n" : "", c);
                display_regs_from_elf_notes(c, fp);
        }
}

struct x86_64_user_regs_struct {
        unsigned long r15,r14,r13,r12,rbp,rbx,r11,r10;
        unsigned long r9,r8,rax,rcx,rdx,rsi,rdi,orig_rax;
        unsigned long rip,cs,eflags;
        unsigned long rsp,ss;
        unsigned long fs_base, gs_base;
        unsigned long ds,es,fs,gs;
};

struct x86_64_prstatus {
	int si_signo;
	int si_code;
	int si_errno;
	short cursig;
	unsigned long sigpend;
	unsigned long sighold;
	int pid;
	int ppid;
	int pgrp;
	int sid;
	struct timeval utime;
	struct timeval stime;
	struct timeval cutime;
	struct timeval cstime;
	struct x86_64_user_regs_struct regs;
	int fpvalid;
};

static void
display_prstatus_x86_64(void *note_ptr, FILE *ofp)
{
	struct x86_64_prstatus *pr;
	Elf64_Nhdr *note;
	int sp;

	note = (Elf64_Nhdr *)note_ptr;
	pr = (struct x86_64_prstatus *)(
		(char *)note + sizeof(Elf64_Nhdr) + note->n_namesz);
	pr = (struct x86_64_prstatus *)roundup((ulong)pr, 4);
	sp = nd->num_prstatus_notes ? 25 : 22;

	fprintf(ofp,
		"%ssi.signo: %d  si.code: %d  si.errno: %d\n"
		"%scursig: %d  sigpend: %lx  sighold: %lx\n"
		"%spid: %d  ppid: %d  pgrp: %d  sid:%d\n"
		"%sutime: %01lld.%06d  stime: %01lld.%06d\n"
		"%scutime: %01lld.%06d  cstime: %01lld.%06d\n"
		"%sORIG_RAX: %lx  fpvalid: %d\n"
		"%s     R15: %016lx  R14: %016lx\n"
		"%s     R13: %016lx  R12: %016lx\n"
		"%s     RBP: %016lx  RBX: %016lx\n"
		"%s     R11: %016lx  R10: %016lx\n"
		"%s      R9: %016lx   R8: %016lx\n"
		"%s     RAX: %016lx  RCX: %016lx\n"
		"%s     RDX: %016lx  RSI: %016lx\n"
		"%s     RDI: %016lx  RIP: %016lx\n"
		"%s  RFLAGS: %016lx  RSP: %016lx\n"
		"%s FS_BASE: %016lx\n"
		"%s GS_BASE: %016lx\n"
		"%s      CS: %04lx  SS: %04lx  DS: %04lx\n"
		"%s      ES: %04lx  FS: %04lx  GS: %04lx\n",
		space(sp), pr->si_signo, pr->si_code, pr->si_errno,
		space(sp), pr->cursig, pr->sigpend, pr->sighold,
		space(sp), pr->pid, pr->ppid, pr->pgrp, pr->sid,
		space(sp), (long long)pr->utime.tv_sec, (int)pr->utime.tv_usec,
		(long long)pr->stime.tv_sec, (int)pr->stime.tv_usec,
		space(sp), (long long)pr->cutime.tv_sec, (int)pr->cutime.tv_usec,
		(long long)pr->cstime.tv_sec, (int)pr->cstime.tv_usec,
		space(sp), pr->regs.orig_rax, pr->fpvalid,
		space(sp), pr->regs.r15, pr->regs.r14,
		space(sp), pr->regs.r13, pr->regs.r12,
		space(sp), pr->regs.rbp, pr->regs.rbx,
		space(sp), pr->regs.r11, pr->regs.r10,
		space(sp), pr->regs.r9, pr->regs.r8,
		space(sp), pr->regs.rax, pr->regs.rcx,
		space(sp), pr->regs.rdx, pr->regs.rsi,
		space(sp), pr->regs.rdi, pr->regs.rip,
		space(sp), pr->regs.eflags, pr->regs.rsp,
		space(sp), pr->regs.fs_base,
		space(sp), pr->regs.gs_base,
		space(sp), pr->regs.cs, pr->regs.ss, pr->regs.ds,
		space(sp), pr->regs.es, pr->regs.fs, pr->regs.gs);
}

struct x86_user_regs_struct {
	unsigned long ebx,ecx,edx,esi,edi,ebp,eax;
	unsigned long ds,es,fs,gs,orig_eax;
	unsigned long eip,cs,eflags;
	unsigned long esp,ss;
};

struct x86_prstatus {
	int si_signo;
	int si_code;
	int si_errno;
	short cursig;
	unsigned long sigpend;
	unsigned long sighold;
	int pid;
	int ppid;
	int pgrp;
	int sid;
	struct timeval utime;
	struct timeval stime;
	struct timeval cutime;
	struct timeval cstime;
	struct x86_user_regs_struct regs;
	int fpvalid;
};

static void
display_prstatus_x86(void *note_ptr, FILE *ofp)
{
	struct x86_prstatus *pr;
	Elf32_Nhdr *note;
	int sp;

	note = (Elf32_Nhdr *)note_ptr;
	pr = (struct x86_prstatus *)(
		(char *)note + sizeof(Elf32_Nhdr) + note->n_namesz);
	pr = (struct x86_prstatus *)roundup((ulong)pr, 4);
	sp = nd->num_prstatus_notes ? 25 : 22;

	fprintf(ofp,
		"%ssi.signo: %d  si.code: %d  si.errno: %d\n"
		"%scursig: %d  sigpend: %lx  sighold : %lx\n"
		"%spid: %d  ppid: %d  pgrp: %d  sid: %d\n"
		"%sutime: %01lld.%06d  stime: %01lld.%06d\n"
		"%scutime: %01lld.%06d  cstime: %01lld.%06d\n"
		"%sORIG_EAX: %lx  fpvalid: %d\n"
		"%s     EBX: %08lx  ECX: %08lx\n"
		"%s     EDX: %08lx  ESI: %08lx\n"
		"%s     EDI: %08lx  EBP: %08lx\n"
		"%s     EAX: %08lx  EIP: %08lx\n"
		"%s  EFLAGS: %08lx  ESP: %08lx\n"
		"%s      DS: %04lx  ES: %04lx  FS: %04lx\n"
		"%s      GS: %04lx  CS: %04lx  SS: %04lx\n",
		space(sp), pr->si_signo, pr->si_code, pr->si_errno,
		space(sp), pr->cursig, pr->sigpend, pr->sighold,
		space(sp), pr->pid, pr->ppid, pr->pgrp, pr->sid,
		space(sp), (long long)pr->utime.tv_sec, (int)pr->utime.tv_usec,
		(long long)pr->stime.tv_sec, (int)pr->stime.tv_usec,
		space(sp), (long long)pr->cutime.tv_sec, (int)pr->cutime.tv_usec,
		(long long)pr->cstime.tv_sec, (int)pr->cstime.tv_usec,
		space(sp), pr->regs.orig_eax, pr->fpvalid,
		space(sp), pr->regs.ebx, pr->regs.ecx,
		space(sp), pr->regs.edx, pr->regs.esi,
		space(sp), pr->regs.edi, pr->regs.ebp,
		space(sp), pr->regs.eax, pr->regs.eip,
		space(sp), pr->regs.eflags, pr->regs.esp,
		space(sp), pr->regs.ds, pr->regs.es, pr->regs.fs,
		space(sp), pr->regs.gs, pr->regs.cs, pr->regs.ss);
}

static void
display_qemu_x86_64(void *note_ptr, FILE *ofp)
{
	int i, sp;
	Elf64_Nhdr *note;
	QEMUCPUState *ptr;
	QEMUCPUSegment *seg;
	char *seg_names[] = {"CS", "DS", "ES", "FS", "GS", "SS", "LDT", "TR",
			     "GDT", "IDT"};

	note = (Elf64_Nhdr *)note_ptr;
	ptr = (QEMUCPUState *)(
		(char *)note + sizeof(Elf64_Nhdr) + note->n_namesz);
	ptr = (QEMUCPUState *)roundup((ulong)ptr, 4);
	seg = &(ptr->cs);
	sp = VMCORE_VALID()? 25 : 22;

	fprintf(ofp,
		"%sversion: %d  size: %d\n"
		"%sRAX: %016llx     RBX: %016llx\n"
		"%sRCX: %016llx     RDX: %016llx\n"
		"%sRSI: %016llx     RDI: %016llx\n"
		"%sRSP: %016llx     RBP: %016llx\n"
		"%sRIP: %016llx  RFLAGS: %016llx\n"
		"%s R8: %016llx      R9: %016llx\n"
		"%sR10: %016llx     R11: %016llx\n"
		"%sR12: %016llx     R13: %016llx\n"
		"%sR14: %016llx     R15: %016llx\n",
		space(sp), ptr->version, ptr->size,
		space(sp), (ulonglong)ptr->rax, (ulonglong)ptr->rbx,
		space(sp), (ulonglong)ptr->rcx, (ulonglong)ptr->rdx,
		space(sp), (ulonglong)ptr->rsi, (ulonglong)ptr->rdi,
		space(sp), (ulonglong)ptr->rsp, (ulonglong)ptr->rbp,
		space(sp), (ulonglong)ptr->rip, (ulonglong)ptr->rflags,
		space(sp), (ulonglong)ptr->r8, (ulonglong)ptr->r9,
		space(sp), (ulonglong)ptr->r10, (ulonglong)ptr->r11,
		space(sp), (ulonglong)ptr->r12, (ulonglong)ptr->r13,
		space(sp), (ulonglong)ptr->r14, (ulonglong)ptr->r15);

	for (i = 0; i < sizeof(seg_names)/sizeof(seg_names[0]); i++) {
		fprintf(ofp, "%s%s", space(sp), strlen(seg_names[i]) > 2 ? "" : " ");
		fprintf(ofp, 
			"%s: "
			"selector: %04x  limit: %08x  flags: %08x\n"
			"%spad: %08x   base: %016llx\n",
			seg_names[i],
			seg->selector, seg->limit, seg->flags,
			space(sp+5), seg->pad, (ulonglong)seg->base);
		seg++;
	}

	fprintf(ofp,
		"%sCR0: %016llx  CR1: %016llx\n"
		"%sCR2: %016llx  CR3: %016llx\n"
		"%sCR4: %016llx\n",
		space(sp), (ulonglong)ptr->cr[0], (ulonglong)ptr->cr[1], 
		space(sp), (ulonglong)ptr->cr[2], (ulonglong)ptr->cr[3],
		space(sp), (ulonglong)ptr->cr[4]);
}

static void
display_qemu_x86(void *note_ptr, FILE *ofp)
{
	int i, sp;
	Elf32_Nhdr *note;
	QEMUCPUState *ptr;
	QEMUCPUSegment *seg;
	char *seg_names[] = {"CS", "DS", "ES", "FS", "GS", "SS", "LDT", "TR",
			     "GDT", "IDT"};

	note = (Elf32_Nhdr *)note_ptr;
	ptr = (QEMUCPUState *)(
		(char *)note + sizeof(Elf32_Nhdr) + note->n_namesz);
	ptr = (QEMUCPUState *)roundup((ulong)ptr, 4);
	seg = &(ptr->cs);
	sp = VMCORE_VALID()? 25 : 22;

	fprintf(ofp,
		"%sversion: %d  size: %d\n"
		"%sEAX: %016llx     EBX: %016llx\n"
		"%sECX: %016llx     EDX: %016llx\n"
		"%sESI: %016llx     EDI: %016llx\n"
		"%sESP: %016llx     EBP: %016llx\n"
		"%sEIP: %016llx  EFLAGS: %016llx\n",
		space(sp), ptr->version, ptr->size,
		space(sp), (ulonglong)ptr->rax, (ulonglong)ptr->rbx, 
		space(sp), (ulonglong)ptr->rcx, (ulonglong)ptr->rdx, 
		space(sp), (ulonglong)ptr->rsi, (ulonglong)ptr->rdi,
		space(sp), (ulonglong)ptr->rsp, (ulonglong)ptr->rbp,
		space(sp), (ulonglong)ptr->rip, (ulonglong)ptr->rflags);

	for(i = 0; i < sizeof(seg_names)/sizeof(seg_names[0]); i++) {
		fprintf(ofp, "%s%s", space(sp), strlen(seg_names[i]) > 2 ? "" : " ");
		fprintf(ofp,
			"%s: "
			"selector: %04x  limit: %08x  flags: %08x\n"
			"%spad: %08x   base: %016llx\n",
			seg_names[i],
			seg->selector, seg->limit, seg->flags,
			space(sp+5),
			seg->pad, (ulonglong)seg->base);
		seg++;
	}

	fprintf(ofp,
		"%sCR0: %016llx  CR1: %016llx\n"
		"%sCR2: %016llx  CR3: %016llx\n"
		"%sCR4: %016llx\n",
		space(sp), (ulonglong)ptr->cr[0], (ulonglong)ptr->cr[1],
		space(sp), (ulonglong)ptr->cr[2], (ulonglong)ptr->cr[3],
		space(sp), (ulonglong)ptr->cr[4]);
}

static void
display_prstatus_ppc64(void *note_ptr, FILE *ofp)
{
	struct ppc64_elf_prstatus *pr;
	Elf64_Nhdr *note;
	int sp;

	note = (Elf64_Nhdr *)note_ptr;
	pr = (struct ppc64_elf_prstatus *)(
		(char *)note + sizeof(Elf64_Nhdr) + note->n_namesz);
	pr = (struct ppc64_elf_prstatus *)roundup((ulong)pr, 4);
	sp = nd->num_prstatus_notes ? 25 : 22;

	fprintf(ofp,
		"%ssi.signo: %d  si.code: %d  si.errno: %d\n"
		"%scursig: %d  sigpend: %lx  sighold: %lx\n"
		"%spid: %d  ppid: %d  pgrp: %d  sid:%d\n"
		"%sutime: %01lld.%06d  stime: %01lld.%06d\n"
		"%scutime: %01lld.%06d  cstime: %01lld.%06d\n"
		"%s R0: %016lx   R1: %016lx   R2: %016lx\n"
		"%s R3: %016lx   R4: %016lx   R5: %016lx\n"
		"%s R6: %016lx   R7: %016lx   R8: %016lx\n"
		"%s R9: %016lx  R10: %016lx  R11: %016lx\n"
		"%sR12: %016lx  R13: %016lx  R14: %016lx\n"
		"%sR15: %016lx  R16: %016lx  R16: %016lx\n"
		"%sR18: %016lx  R19: %016lx  R20: %016lx\n"
		"%sR21: %016lx  R22: %016lx  R23: %016lx\n"
		"%sR24: %016lx  R25: %016lx  R26: %016lx\n"
		"%sR27: %016lx  R28: %016lx  R29: %016lx\n"
		"%sR30: %016lx  R31: %016lx\n"
		"%s  NIP: %016lx     MSR: %016lx\n"
		"%sOGPR3: %016lx     CTR: %016lx\n"  
		"%s LINK: %016lx     XER: %016lx\n"
		"%s  CCR: %016lx      MQ: %016lx\n"
		"%s TRAP: %016lx     DAR: %016lx\n"
		"%sDSISR: %016lx  RESULT: %016lx\n",
		space(sp), pr->pr_info.si_signo, pr->pr_info.si_code, pr->pr_info.si_errno,
		space(sp), pr->pr_cursig, pr->pr_sigpend, pr->pr_sighold,
		space(sp), pr->pr_pid, pr->pr_ppid, pr->pr_pgrp, pr->pr_sid,
		space(sp), (long long)pr->pr_utime.tv_sec, (int)pr->pr_utime.tv_usec,
		(long long)pr->pr_stime.tv_sec, (int)pr->pr_stime.tv_usec,
		space(sp), (long long)pr->pr_cutime.tv_sec, (int)pr->pr_cutime.tv_usec,
		(long long)pr->pr_cstime.tv_sec, (int)pr->pr_cstime.tv_usec,
		space(sp), pr->pr_reg.gpr[0], pr->pr_reg.gpr[1], pr->pr_reg.gpr[2],
		space(sp), pr->pr_reg.gpr[3], pr->pr_reg.gpr[4], pr->pr_reg.gpr[5],
		space(sp), pr->pr_reg.gpr[6], pr->pr_reg.gpr[7], pr->pr_reg.gpr[8],
		space(sp), pr->pr_reg.gpr[9], pr->pr_reg.gpr[10], pr->pr_reg.gpr[11],
		space(sp), pr->pr_reg.gpr[12], pr->pr_reg.gpr[13], pr->pr_reg.gpr[14],
		space(sp), pr->pr_reg.gpr[15], pr->pr_reg.gpr[16], pr->pr_reg.gpr[17],
		space(sp), pr->pr_reg.gpr[18], pr->pr_reg.gpr[19], pr->pr_reg.gpr[20],
		space(sp), pr->pr_reg.gpr[21], pr->pr_reg.gpr[22], pr->pr_reg.gpr[23],
		space(sp), pr->pr_reg.gpr[24], pr->pr_reg.gpr[25], pr->pr_reg.gpr[26],
		space(sp), pr->pr_reg.gpr[27], pr->pr_reg.gpr[28], pr->pr_reg.gpr[29],
		space(sp), pr->pr_reg.gpr[30], pr->pr_reg.gpr[31],
		space(sp), pr->pr_reg.nip, pr->pr_reg.msr, 
		space(sp), pr->pr_reg.orig_gpr3, pr->pr_reg.ctr,
		space(sp), pr->pr_reg.link, pr->pr_reg.xer,
		space(sp), pr->pr_reg.ccr, pr->pr_reg.mq,
		space(sp), pr->pr_reg.trap,  pr->pr_reg.dar, 
		space(sp), pr->pr_reg.dsisr, pr->pr_reg.result);
}

struct arm64_elf_siginfo {
    int si_signo;
    int si_code;
    int si_errno;
};

struct arm64_elf_prstatus {
    struct arm64_elf_siginfo pr_info;
    short pr_cursig;
    unsigned long pr_sigpend;
    unsigned long pr_sighold;
    pid_t pr_pid;
    pid_t pr_ppid;
    pid_t pr_pgrp;
    pid_t pr_sid;
    struct timeval pr_utime;
    struct timeval pr_stime;
    struct timeval pr_cutime;
    struct timeval pr_cstime;
/*  arm64_elf_gregset_t pr_reg; -> typedef unsigned long [34] arm64_elf_gregset_t */
    unsigned long pr_reg[34];
    int pr_fpvalid;
};

/*
  Note that the ARM64 elf_gregset_t includes the 31 numbered registers
  plus the sp, pc and pstate:

  typedef unsigned long [34] elf_gregset_t;

  struct pt_regs {
      union {
          struct user_pt_regs user_regs;
          struct {
              u64 regs[31];
              u64 sp;
              u64 pc;
              u64 pstate;
          };
      };
      u64 orig_x0;
      u64 syscallno;
  }
*/

static void
display_prstatus_arm64(void *note_ptr, FILE *ofp)
{
	struct arm64_elf_prstatus *pr;
	Elf64_Nhdr *note;
	int sp;

	note = (Elf64_Nhdr *)note_ptr;
	pr = (struct arm64_elf_prstatus *)(
		(char *)note + sizeof(Elf64_Nhdr) + note->n_namesz);
	pr = (struct arm64_elf_prstatus *)roundup((ulong)pr, 4);
	sp = nd->num_prstatus_notes ? 25 : 22;

	fprintf(ofp,
		"%ssi.signo: %d  si.code: %d  si.errno: %d\n"
		"%scursig: %d  sigpend: %lx  sighold: %lx\n"
		"%spid: %d  ppid: %d  pgrp: %d  sid:%d\n"
		"%sutime: %01lld.%06d  stime: %01lld.%06d\n"
		"%scutime: %01lld.%06d  cstime: %01lld.%06d\n",
		space(sp), pr->pr_info.si_signo, pr->pr_info.si_code, pr->pr_info.si_errno,
		space(sp), pr->pr_cursig, pr->pr_sigpend, pr->pr_sighold,
		space(sp), pr->pr_pid, pr->pr_ppid, pr->pr_pgrp, pr->pr_sid,
		space(sp), (long long)pr->pr_utime.tv_sec, (int)pr->pr_utime.tv_usec,
		(long long)pr->pr_stime.tv_sec, (int)pr->pr_stime.tv_usec,
		space(sp), (long long)pr->pr_cutime.tv_sec, (int)pr->pr_cutime.tv_usec,
		(long long)pr->pr_cstime.tv_sec, (int)pr->pr_cstime.tv_usec);
	fprintf(ofp,
		"%s X0: %016lx   X1: %016lx   X2: %016lx\n"
		"%s X3: %016lx   X4: %016lx   X5: %016lx\n"
		"%s X6: %016lx   X7: %016lx   X8: %016lx\n"
		"%s X9: %016lx  X10: %016lx  X11: %016lx\n"
		"%sX12: %016lx  X13: %016lx  X14: %016lx\n"
		"%sX15: %016lx  X16: %016lx  X17: %016lx\n"
		"%sX18: %016lx  X19: %016lx  X20: %016lx\n"
		"%sX21: %016lx  X22: %016lx  X23: %016lx\n"
		"%sX24: %016lx  X25: %016lx  X26: %016lx\n"
		"%sX27: %016lx  X28: %016lx  X29: %016lx\n"
		"%s LR: %016lx   SP: %016lx   PC: %016lx\n"
		"%sPSTATE: %08lx   FPVALID: %08x\n", 
		space(sp), pr->pr_reg[0], pr->pr_reg[1], pr->pr_reg[2],
		space(sp), pr->pr_reg[3], pr->pr_reg[4], pr->pr_reg[5],
		space(sp), pr->pr_reg[6], pr->pr_reg[7], pr->pr_reg[8],
		space(sp), pr->pr_reg[9], pr->pr_reg[10], pr->pr_reg[11],
		space(sp), pr->pr_reg[12], pr->pr_reg[13], pr->pr_reg[14],
		space(sp), pr->pr_reg[15], pr->pr_reg[16], pr->pr_reg[17],
		space(sp), pr->pr_reg[18], pr->pr_reg[19], pr->pr_reg[20],
		space(sp), pr->pr_reg[21], pr->pr_reg[22], pr->pr_reg[23],
		space(sp), pr->pr_reg[24], pr->pr_reg[25], pr->pr_reg[26],
		space(sp), pr->pr_reg[27], pr->pr_reg[28], pr->pr_reg[29],
		space(sp), pr->pr_reg[30], pr->pr_reg[31], pr->pr_reg[32],
		space(sp), pr->pr_reg[33], pr->pr_fpvalid);
}

struct riscv64_elf_siginfo {
    int si_signo;
    int si_code;
    int si_errno;
};

struct riscv64_elf_prstatus {
    struct riscv64_elf_siginfo pr_info;
    short pr_cursig;
    unsigned long pr_sigpend;
    unsigned long pr_sighold;
    pid_t pr_pid;
    pid_t pr_ppid;
    pid_t pr_pgrp;
    pid_t pr_sid;
    struct timeval pr_utime;
    struct timeval pr_stime;
    struct timeval pr_cutime;
    struct timeval pr_cstime;
/*  elf_gregset_t pr_reg; => typedef struct user_regs_struct elf_gregset_t; */
    unsigned long pr_reg[32];
    int pr_fpvalid;
};

static void
display_prstatus_riscv64(void *note_ptr, FILE *ofp)
{
	struct riscv64_elf_prstatus *pr;
	Elf64_Nhdr *note;
	int sp;

	note = (Elf64_Nhdr *)note_ptr;
	pr = (struct riscv64_elf_prstatus *)(
		(char *)note + sizeof(Elf64_Nhdr) + note->n_namesz);
	pr = (struct riscv64_elf_prstatus *)roundup((ulong)pr, 4);
	sp = nd->num_prstatus_notes ? 25 : 22;

	fprintf(ofp,
		"%ssi.signo: %d  si.code: %d  si.errno: %d\n"
		"%scursig: %d  sigpend: %lx  sighold: %lx\n"
		"%spid: %d  ppid: %d  pgrp: %d  sid:%d\n"
		"%sutime: %01lld.%06d  stime: %01lld.%06d\n"
		"%scutime: %01lld.%06d  cstime: %01lld.%06d\n",
		space(sp), pr->pr_info.si_signo, pr->pr_info.si_code, pr->pr_info.si_errno,
		space(sp), pr->pr_cursig, pr->pr_sigpend, pr->pr_sighold,
		space(sp), pr->pr_pid, pr->pr_ppid, pr->pr_pgrp, pr->pr_sid,
		space(sp), (long long)pr->pr_utime.tv_sec, (int)pr->pr_utime.tv_usec,
		(long long)pr->pr_stime.tv_sec, (int)pr->pr_stime.tv_usec,
		space(sp), (long long)pr->pr_cutime.tv_sec, (int)pr->pr_cutime.tv_usec,
		(long long)pr->pr_cstime.tv_sec, (int)pr->pr_cstime.tv_usec);
	fprintf(ofp,
		"%sepc: %016lx   ra: %016lx   sp: %016lx\n"
		"%s gp: %016lx   tp: %016lx   t0: %016lx\n"
		"%s t1: %016lx   t2: %016lx   s0: %016lx\n"
		"%s s1: %016lx   a0: %016lx   a1: %016lx\n"
		"%s a2: %016lx   a3: %016lx   a4: %016lx\n"
		"%s a5: %016lx   a6: %016lx   a7: %016lx\n"
		"%s s2: %016lx   s3: %016lx   s4: %016lx\n"
		"%s s5: %016lx   s6: %016lx   s7: %016lx\n"
		"%s s8: %016lx   s9: %016lx  s10: %016lx\n"
		"%ss11: %016lx   t3: %016lx   t4: %016lx\n"
		"%s t5: %016lx   t6: %016lx\n",
		space(sp), pr->pr_reg[0], pr->pr_reg[1], pr->pr_reg[2],
		space(sp), pr->pr_reg[3], pr->pr_reg[4], pr->pr_reg[5],
		space(sp), pr->pr_reg[6], pr->pr_reg[7], pr->pr_reg[8],
		space(sp), pr->pr_reg[9], pr->pr_reg[10], pr->pr_reg[11],
		space(sp), pr->pr_reg[12], pr->pr_reg[13], pr->pr_reg[14],
		space(sp), pr->pr_reg[15], pr->pr_reg[16], pr->pr_reg[17],
		space(sp), pr->pr_reg[18], pr->pr_reg[19], pr->pr_reg[20],
		space(sp), pr->pr_reg[21], pr->pr_reg[22], pr->pr_reg[23],
		space(sp), pr->pr_reg[24], pr->pr_reg[25], pr->pr_reg[26],
		space(sp), pr->pr_reg[27], pr->pr_reg[28], pr->pr_reg[29],
		space(sp), pr->pr_reg[30], pr->pr_reg[31]);
}

void
display_ELF_note(int machine, int type, void *note, FILE *ofp)
{
	if (note == NULL)
		return;

	switch (machine)
	{
	case EM_386:
		switch (type)
		{
		case PRSTATUS_NOTE:
			display_prstatus_x86(note, ofp);
			break;
		case QEMU_NOTE:
			display_qemu_x86(note, ofp);
			break;
		}
		break;

	case EM_X86_64:
		switch (type)
		{
		case PRSTATUS_NOTE:
			display_prstatus_x86_64(note, ofp);
			break;
		case QEMU_NOTE:
			display_qemu_x86_64(note, ofp);
			break;
		}
		break;

	case EM_PPC64:
		switch (type)
		{
		case PRSTATUS_NOTE:
			display_prstatus_ppc64(note, ofp);
			break;
		}
		break;

	case EM_AARCH64:
		switch (type)
		{
		case PRSTATUS_NOTE:
			display_prstatus_arm64(note, ofp);
			break;
		}
		break;
	case EM_RISCV:
		switch (type)
		{
		case PRSTATUS_NOTE:
			display_prstatus_riscv64(note, ofp);
			break;
		}
		break;

	default:
		return;
	}
}

void 
get_netdump_regs_x86_64(struct bt_info *bt, ulong *ripp, ulong *rspp)
{
        Elf64_Nhdr *note;
        size_t len;
        char *user_regs;
	ulong regs_size, rsp_offset, rip_offset;
	ulong rip, rsp;

        if (is_task_active(bt->task)) 
                bt->flags |= BT_DUMPFILE_SEARCH;

	if (((NETDUMP_DUMPFILE() || KDUMP_DUMPFILE()) &&
   	      VALID_STRUCT(user_regs_struct) && 
	      ((bt->task == tt->panic_task) || (pc->flags2 & QEMU_MEM_DUMP_ELF))) ||
	      (KDUMP_DUMPFILE() && (kt->flags & DWARF_UNWIND) && 
	      (bt->flags & BT_DUMPFILE_SEARCH))) {
		if (nd->num_prstatus_notes > 1)
                	note = (Elf64_Nhdr *)
				nd->nt_prstatus_percpu[bt->tc->processor];
		else
                	note = (Elf64_Nhdr *)nd->nt_prstatus;

		if (!note)
			goto no_nt_prstatus_exists;

                len = sizeof(Elf64_Nhdr);
                len = roundup(len + note->n_namesz, 4);
                len = roundup(len + note->n_descsz, 4);

		regs_size = VALID_STRUCT(user_regs_struct) ?
			SIZE(user_regs_struct) : 
			sizeof(struct x86_64_user_regs_struct);
		rsp_offset = VALID_MEMBER(user_regs_struct_rsp) ?
			OFFSET(user_regs_struct_rsp) : 
			offsetof(struct x86_64_user_regs_struct, rsp);
		rip_offset = VALID_MEMBER(user_regs_struct_rip) ?
			OFFSET(user_regs_struct_rip) :
                        offsetof(struct x86_64_user_regs_struct, rip);

                user_regs = ((char *)note + len) - regs_size - sizeof(long);
		rsp = ULONG(user_regs + rsp_offset);
		rip = ULONG(user_regs + rip_offset);

		if (INSTACK(rsp, bt) || 
		    in_alternate_stack(bt->tc->processor, rsp)) {
			if (CRASHDEBUG(1))
				netdump_print("ELF prstatus rsp: %lx rip: %lx\n", 
					rsp, rip);

			if (KDUMP_DUMPFILE()) {
				*rspp = rsp;
				*ripp = rip;

				if (*ripp && *rspp)
					bt->flags |= BT_KDUMP_ELF_REGS;
			}
			
			bt->machdep = (void *)user_regs;
		}
	}

	if (ELF_NOTES_VALID() && 
	    (bt->flags & BT_DUMPFILE_SEARCH) && DISKDUMP_DUMPFILE() && 
	    (note = (Elf64_Nhdr *)
	     diskdump_get_prstatus_percpu(bt->tc->processor))) {

		if (!note)
			goto no_nt_prstatus_exists;

		user_regs = get_regs_from_note((char *)note, &rip, &rsp);

		if (INSTACK(rsp, bt) || 
		    in_alternate_stack(bt->tc->processor, rsp)) {
			if (CRASHDEBUG(1))
				netdump_print("ELF prstatus rsp: %lx rip: %lx\n",
					rsp, rip);

			*rspp = rsp;
			*ripp = rip;

			if (*ripp && *rspp)
				bt->flags |= BT_KDUMP_ELF_REGS;

			bt->machdep = (void *)user_regs;
		}
	}

no_nt_prstatus_exists:
        machdep->get_stack_frame(bt, ripp, rspp);
}

/*
 *  Netdump doesn't save state of the active tasks in the TSS, so poke around
 *  the raw stack for some reasonable hooks.
 */

void
get_netdump_regs_x86(struct bt_info *bt, ulong *eip, ulong *esp)
{
	int i, search, panic, panic_task, altered;
	char *sym;
	ulong *up;
	ulong ipintr_eip, ipintr_esp, ipintr_func;
	ulong halt_eip, halt_esp, panic_eip, panic_esp;
	int check_hardirq, check_softirq;
	ulong stackbase, stacktop;
	Elf32_Nhdr *note;
	char *user_regs ATTRIBUTE_UNUSED;
	ulong ip, sp;

	if (!is_task_active(bt->task)) {
		machdep->get_stack_frame(bt, eip, esp);
		return;
	}

	panic_task = tt->panic_task == bt->task ? TRUE : FALSE;

	ipintr_eip = ipintr_esp = ipintr_func = panic = altered = 0;
	halt_eip = halt_esp = panic_eip = panic_esp = 0;
	check_hardirq = check_softirq = tt->flags & IRQSTACKS ? TRUE : FALSE;
	search = ((bt->flags & BT_TEXT_SYMBOLS) && (tt->flags & TASK_INIT_DONE))
		|| (machdep->flags & OMIT_FRAME_PTR);
	stackbase = bt->stackbase;
	stacktop = bt->stacktop;
retry:
	for (i = 0, up = (ulong *)bt->stackbuf; i < LONGS_PER_STACK; i++, up++){
		sym = closest_symbol(*up);

		if (XEN_CORE_DUMPFILE()) {
			if (STREQ(sym, "xen_machine_kexec")) {
				*eip = *up;
				*esp = bt->stackbase + ((char *)(up+1) - bt->stackbuf);
				return;
			}
			if (STREQ(sym, "crash_kexec")) {
                        	halt_eip = *up;
				halt_esp = bt->stackbase + ((char *)(up+1) - bt->stackbuf);
			}
		} else if (STREQ(sym, "netconsole_netdump") || 
		    STREQ(sym, "netpoll_start_netdump") ||
		    STREQ(sym, "start_disk_dump") ||
		    (STREQ(sym, "crash_kexec") && !KVMDUMP_DUMPFILE()) ||
		    STREQ(sym, "disk_dump")) {
crash_kexec:
			*eip = *up;
			*esp = search ?
			    bt->stackbase + ((char *)(up+1) - bt->stackbuf) :
				*(up-1);
			return;
		}

                if (STREQ(sym, "panic")) {
                        *eip = *up;
                        *esp = search ?
			    bt->stackbase + ((char *)(up+1) - bt->stackbuf) :
				*(up-1);
			panic_eip = *eip;
			panic_esp = *esp;
			panic = TRUE;
                        continue;   /* keep looking for die */
                }

                if (STREQ(sym, "die")) {
                        *eip = *up;
                        *esp = search ? 
			    bt->stackbase + ((char *)(up+1) - bt->stackbuf) :
				*(up-1);
                        for (i++, up++; i < LONGS_PER_STACK; i++, up++) {
                                sym = closest_symbol(*up);
                                if (STREQ(sym, "sysrq_handle_crash"))
                                        goto next_sysrq;
                        }
                        return;
                }

                if (STREQ(sym, "sysrq_handle_crash")) {
next_sysrq:
                        *eip = *up;
			*esp = bt->stackbase + ((char *)(up+4) - bt->stackbuf);
			pc->flags |= SYSRQ;
			for (i++, up++; i < LONGS_PER_STACK; i++, up++) {
				sym = closest_symbol(*up);
				if (STREQ(sym, "crash_kexec") && !KVMDUMP_DUMPFILE())
					goto crash_kexec;
				if (STREQ(sym, "sysrq_handle_crash")) 
					goto next_sysrq; 
			}
			if (!panic)
				return;
                }

		/* 
		 *  Obsolete -- replaced by sysrq_handle_crash 
		 */
                if (STREQ(sym, "sysrq_handle_netdump")) {
                        *eip = *up;
                        *esp = search ?
                            bt->stackbase + ((char *)(up+1) - bt->stackbuf) :
                                *(up-1);
                        pc->flags |= SYSRQ;
                        return;
                }

                if (STREQ(sym, "crash_nmi_callback")) {
                        *eip = *up;
                        *esp = search ?
                            bt->stackbase + ((char *)(up+1) - bt->stackbuf) :
                                *(up-1);
                        return;
                }

                if (STREQ(sym, "stop_this_cpu")) {
                        *eip = *up;
                        *esp = search ?
                            bt->stackbase + ((char *)(up+1) - bt->stackbuf) :
                                *(up-1);
                        return;
                }

                if (STREQ(sym, "smp_call_function_interrupt")) {
			if (ipintr_eip && IS_VMALLOC_ADDR(ipintr_func) &&
		  	    IS_KERNEL_STATIC_TEXT(*(up - 2)))
				continue;
                        ipintr_eip = *up;
                        ipintr_esp = search ?
			    bt->stackbase + ((char *)(up+1) - bt->stackbuf) :
			    bt->stackbase + ((char *)(up-1) - bt->stackbuf);
			ipintr_func = *(up - 2);
                }

                if (XEN_CORE_DUMPFILE() && !panic_task && (bt->tc->pid == 0) &&
                    STREQ(sym, "safe_halt")) {
                        halt_eip = *up;
			halt_esp = bt->stackbase + ((char *)(up+1) - bt->stackbuf);
                }

                if (XEN_CORE_DUMPFILE() && !panic_task && (bt->tc->pid == 0) &&
                    !halt_eip && STREQ(sym, "xen_idle")) {
                        halt_eip = *up;
			halt_esp = bt->stackbase + ((char *)(up+1) - bt->stackbuf);
                }
	}

	if (panic) {
		*eip = panic_eip;
		*esp = panic_esp;
		return;
	}

	if (ipintr_eip) {
        	*eip = ipintr_eip;
        	*esp = ipintr_esp;
		return;
	}

	if (halt_eip && halt_esp) {
        	*eip = halt_eip;
        	*esp = halt_esp;
		return;
	}

	bt->flags &= ~(BT_HARDIRQ|BT_SOFTIRQ);

	if (check_hardirq &&
	    (tt->hardirq_tasks[bt->tc->processor] == bt->tc->task)) {
		bt->stackbase = tt->hardirq_ctx[bt->tc->processor];
		bt->stacktop = bt->stackbase + STACKSIZE();
		alter_stackbuf(bt);
		bt->flags |= BT_HARDIRQ;
		check_hardirq = FALSE;
		altered = TRUE;
		goto retry;
	}

        if (check_softirq &&
            (tt->softirq_tasks[bt->tc->processor] == bt->tc->task)) {
                bt->stackbase = tt->softirq_ctx[bt->tc->processor];
                bt->stacktop = bt->stackbase + STACKSIZE();
		alter_stackbuf(bt);
		bt->flags |= BT_SOFTIRQ;
                check_softirq = FALSE;
		altered = TRUE;
                goto retry;
        }

	if (ELF_NOTES_VALID() && DISKDUMP_DUMPFILE() &&
	    (note = (Elf32_Nhdr *)
	     diskdump_get_prstatus_percpu(bt->tc->processor))) {
		user_regs = get_regs_from_note((char *)note, &ip, &sp);
		if (is_kernel_text(ip) &&
		    (((sp >= GET_STACKBASE(bt->task)) &&
		      (sp < GET_STACKTOP(bt->task))) ||
		    in_alternate_stack(bt->tc->processor, sp))) {
			bt->flags |= BT_KERNEL_SPACE;
			*eip = ip;
			*esp = sp;
			return;
		}

		if (!is_kernel_text(ip) && in_user_stack(bt->tc->task, sp)) {
			bt->flags |= BT_USER_SPACE;
			*eip = ip;
			*esp = sp;
			return;
		}
	}

	if (CRASHDEBUG(1))
		error(INFO, 
    "get_netdump_regs_x86: cannot find anything useful (task: %lx)\n", bt->task);

	if (altered) {
                bt->stackbase = stackbase;
                bt->stacktop = stacktop;
		alter_stackbuf(bt);
	}

        if (XEN_CORE_DUMPFILE() && !panic_task && is_task_active(bt->task) &&
	    !(bt->flags & (BT_TEXT_SYMBOLS_ALL|BT_TEXT_SYMBOLS)))
		error(FATAL, 
		    "starting backtrace locations of the active (non-crashing) "
		    "xen tasks\n    cannot be determined: try -t or -T options\n");
 
	if (KVMDUMP_DUMPFILE() || SADUMP_DUMPFILE())
		bt->flags &= ~(ulonglong)BT_DUMPFILE_SEARCH;

	machdep->get_stack_frame(bt, eip, esp);
}

static void
get_netdump_regs_32(struct bt_info *bt, ulong *eip, ulong *esp)
{
	Elf32_Nhdr *note;
	size_t len;

	if ((bt->task == tt->panic_task) ||
		(is_task_active(bt->task) && nd->num_prstatus_notes)) {
		/*	
		 * Registers are saved during the dump process for the 
		 * panic task. Whereas in kdump, regs are captured for all 
		 * CPUs if they responded to an IPI.
		 */
                if (nd->num_prstatus_notes > 1) {
			if (!nd->nt_prstatus_percpu[bt->tc->processor])
				error(FATAL, 
		          	    "cannot determine NT_PRSTATUS ELF note "
				    "for %s task: %lx\n", 
					(bt->task == tt->panic_task) ?
					"panic" : "active", bt->task);	
                        note = (Elf32_Nhdr *)
                                nd->nt_prstatus_percpu[bt->tc->processor];
		} else
			note = (Elf32_Nhdr *)nd->nt_prstatus;

		if (!note)
			goto no_nt_prstatus_exists;

		len = sizeof(Elf32_Nhdr);
		len = roundup(len + note->n_namesz, 4);
		bt->machdep = (void *)((char *)note + len + 
			MEMBER_OFFSET("elf_prstatus", "pr_reg"));
	}

no_nt_prstatus_exists:
	machdep->get_stack_frame(bt, eip, esp);
}

static void
get_netdump_regs_ppc(struct bt_info *bt, ulong *eip, ulong *esp)
{
	ppc_relocate_nt_prstatus_percpu(nd->nt_prstatus_percpu,
					&nd->num_prstatus_notes);

	get_netdump_regs_32(bt, eip, esp);
}

static void
get_netdump_regs_ppc64(struct bt_info *bt, ulong *eip, ulong *esp)
{
	Elf64_Nhdr *note;
	size_t len;

	if ((bt->task == tt->panic_task) ||
		(is_task_active(bt->task) && nd->num_prstatus_notes > 1)) {
		/*	
		 * Registers are saved during the dump process for the 
		 * panic task. Whereas in kdump, regs are captured for all 
		 * CPUs if they responded to an IPI.
		 */
                if (nd->num_prstatus_notes > 1) {
			if (!nd->nt_prstatus_percpu[bt->tc->processor])
				error(FATAL, 
		          	    "cannot determine NT_PRSTATUS ELF note "
				    "for %s task: %lx\n", 
					(bt->task == tt->panic_task) ?
					"panic" : "active", bt->task);	
                        note = (Elf64_Nhdr *)
                                nd->nt_prstatus_percpu[bt->tc->processor];
		} else
			note = (Elf64_Nhdr *)nd->nt_prstatus;

		if (!note)
			goto no_nt_prstatus_exists;

		len = sizeof(Elf64_Nhdr);
		len = roundup(len + note->n_namesz, 4);
		bt->machdep = (void *)((char *)note + len + 
			MEMBER_OFFSET("elf_prstatus", "pr_reg"));
	}

no_nt_prstatus_exists:
	machdep->get_stack_frame(bt, eip, esp);
}

static void
get_netdump_regs_arm(struct bt_info *bt, ulong *eip, ulong *esp)
{
	machdep->get_stack_frame(bt, eip, esp);
}

static void
get_netdump_regs_arm64(struct bt_info *bt, ulong *eip, ulong *esp)
{
	machdep->get_stack_frame(bt, eip, esp);
}

static void
get_netdump_regs_mips(struct bt_info *bt, ulong *eip, ulong *esp)
{
	machdep->get_stack_frame(bt, eip, esp);
}

static void
get_netdump_regs_riscv(struct bt_info *bt, ulong *eip, ulong *esp)
{
	machdep->get_stack_frame(bt, eip, esp);
}

static void
get_netdump_regs_loongarch64(struct bt_info *bt, ulong *eip, ulong *esp)
{
	machdep->get_stack_frame(bt, eip, esp);
}

int 
is_partial_netdump(void)
{
	return (nd->flags & PARTIAL_DUMP ? TRUE : FALSE);
}


/*
 *  kexec/kdump generated vmcore files are similar enough in
 *  nature to netdump/diskdump such that most vmcore access
 *  functionality may be borrowed from the equivalent netdump
 *  function.  If not, re-work them here.
 */
int
is_kdump(char *file, ulong source_query)
{
        return is_netdump(file, source_query);
}

int
kdump_init(char *unused, FILE *fptr)
{
	return netdump_init(unused, fptr);
}

ulong 
get_kdump_panic_task(void)
{
	return get_netdump_panic_task();
}

int
read_kdump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	physaddr_t paddr_in = paddr;

	if ((nd->flags & QEMU_MEM_DUMP_KDUMP_BACKUP) &&
	    (paddr >= nd->backup_src_start) &&
	    (paddr < nd->backup_src_start + nd->backup_src_size)) {

		paddr += nd->backup_offset - nd->backup_src_start;

		if (CRASHDEBUG(1))
			error(INFO,
			    "qemu_mem_dump: kdump backup region: %#llx => %#llx\n",
			    paddr_in, paddr);
	}

	if (XEN_CORE_DUMPFILE() && !XEN_HYPER_MODE()) {
		if ((paddr = xen_kdump_p2m(paddr)) == P2M_FAILURE) {
			if (CRASHDEBUG(8)) 
				fprintf(fp, "read_kdump: xen_kdump_p2m(%llx): "
					"P2M_FAILURE\n", (ulonglong)paddr_in);
			return READ_ERROR;
		}
		if (CRASHDEBUG(8))
			fprintf(fp, "read_kdump: xen_kdump_p2m(%llx): %llx\n",
				(ulonglong)paddr_in, (ulonglong)paddr);
	}

	return read_netdump(fd, bufptr, cnt, addr, paddr);
}

int
write_kdump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	return write_netdump(fd, bufptr, cnt, addr, paddr);
}

void
get_kdump_regs(struct bt_info *bt, ulong *eip, ulong *esp)
{
	get_netdump_regs(bt, eip, esp);
}

uint
kdump_page_size(void)
{
        uint pagesz;

        if (!VMCORE_VALID())
                return 0;

	if (!(pagesz = nd->page_size))
                pagesz = (uint)getpagesize();

        return pagesz;
}

int 
kdump_free_memory(void)
{
	return netdump_free_memory();
}

int 
kdump_memory_used(void)
{
	return netdump_memory_used();
}

int 
kdump_memory_dump(FILE *fp)
{
	return netdump_memory_dump(fp);
}

struct vmcore_data *
get_kdump_vmcore_data(void)
{
	if (!VMCORE_VALID() || !KDUMP_DUMPFILE())
		return NULL;

	return &vmcore_data;
}

/*
 *  The following set of functions are not used by the crash
 *  source code, but are available to extension modules for
 *  gathering register sets from ELF NT_PRSTATUS note sections.
 *
 *  Contributed by: Sharyathi Nagesh (sharyath@in.ibm.com)
 */

static void *get_ppc_regs_from_elf_notes(struct task_context *);
static void *get_ppc64_regs_from_elf_notes(struct task_context *);
static void *get_x86_regs_from_elf_notes(struct task_context *);
static void *get_x86_64_regs_from_elf_notes(struct task_context *);
static void *get_arm_regs_from_elf_notes(struct task_context *);

int get_netdump_arch(void)
{
	int e_machine;

	if (nd->elf32)
		e_machine = nd->elf32->e_machine;
	else if (nd->elf64)
		e_machine = nd->elf64->e_machine;
	else
		e_machine = EM_NONE;

	return e_machine;
}

int 
exist_regs_in_elf_notes(struct task_context *tc)
{
	if ((tc->task == tt->panic_task) ||
	    (is_task_active(tc->task) && (nd->num_prstatus_notes > 1) &&
	     (tc->processor < nd->num_prstatus_notes)))
		return TRUE;
	else
		return FALSE;
}

void * 
get_regs_from_elf_notes(struct task_context *tc)
{
	int e_machine = get_netdump_arch();

	switch (e_machine)
	{
	case EM_386:
	case EM_PPC:
	case EM_PPC64:
	case EM_X86_64:
	case EM_ARM:
		break;
	case EM_AARCH64:
		error(FATAL, 
			"get_regs_from_elf_notes: ARM64 support TBD\n");
	default:
		error(FATAL,
		      "support for ELF machine type %d not available\n",
		      e_machine);
	}

	if (!exist_regs_in_elf_notes(tc))
		error(FATAL, "cannot determine register set "
		      "for active task: %lx comm: \"%s\"\n",
		      tc->task, tc->comm);

	switch(e_machine)
	{
	case EM_386:
		return get_x86_regs_from_elf_notes(tc);
	case EM_PPC:
		return get_ppc_regs_from_elf_notes(tc);
	case EM_PPC64:
		return get_ppc64_regs_from_elf_notes(tc);
	case EM_X86_64:
		return get_x86_64_regs_from_elf_notes(tc);
	case EM_ARM:
		return get_arm_regs_from_elf_notes(tc);
	case EM_AARCH64:
		break;  /* TBD */
	}

	return NULL;
}

static void * 
get_x86_regs_from_elf_notes(struct task_context *tc)
{
	Elf32_Nhdr *note_32;
	Elf64_Nhdr *note_64;
	void *note;
	size_t len;
	void *pt_regs;

	len = 0;
	pt_regs = NULL;

	if (nd->num_prstatus_notes > 1)
		note = (void *)nd->nt_prstatus_percpu[tc->processor];
	else
		note = (void *)nd->nt_prstatus;

	if (!note)
		goto no_nt_prstatus_exists;

	if (nd->elf32) {
		note_32 = (Elf32_Nhdr *)note;
		len = sizeof(Elf32_Nhdr);
		len = roundup(len + note_32->n_namesz, 4);
	} else if (nd->elf64) {
		note_64 = (Elf64_Nhdr *)note;
		len = sizeof(Elf64_Nhdr);
		len = roundup(len + note_64->n_namesz, 4);
	}

	pt_regs = (void *)((char *)note + len +
			   MEMBER_OFFSET("elf_prstatus", "pr_reg"));
	/* NEED TO BE FIXED: Hack to get the proper alignment */
	pt_regs +=4;

no_nt_prstatus_exists:
	return pt_regs;

}

static void * 
get_x86_64_regs_from_elf_notes(struct task_context *tc)
{
	Elf64_Nhdr *note;
	size_t len;
	void *pt_regs;

	pt_regs = NULL;

	if (nd->num_prstatus_notes > 1)
		note = (Elf64_Nhdr *)nd->nt_prstatus_percpu[tc->processor];
	else
		note = (Elf64_Nhdr *)nd->nt_prstatus;

	if (!note)
		goto no_nt_prstatus_exists;

	len = sizeof(Elf64_Nhdr);
	len = roundup(len + note->n_namesz, 4);
	pt_regs = (void *)((char *)note + len +
			   MEMBER_OFFSET("elf_prstatus", "pr_reg"));

no_nt_prstatus_exists:
	return pt_regs;
}

static void * 
get_ppc_regs_from_elf_notes(struct task_context *tc)
{
	Elf32_Nhdr *note;
	size_t len;
	void *pt_regs;
	extern struct vmcore_data *nd;

	pt_regs = NULL;

	/*
	 * Registers are always saved during the dump process for the
	 * panic task.  Kdump also captures registers for all CPUs if
	 * they responded to an IPI.
	 */
	if (nd->num_prstatus_notes > 1) {
		note = (Elf32_Nhdr *)nd->nt_prstatus_percpu[tc->processor];
	} else
		note = (Elf32_Nhdr *)nd->nt_prstatus;

	if (!note)
		goto no_nt_prstatus_exists;

	len = sizeof(Elf32_Nhdr);
	len = roundup(len + note->n_namesz, 4);
	pt_regs = (void *)((char *)note + len +
			   MEMBER_OFFSET("elf_prstatus", "pr_reg"));

no_nt_prstatus_exists:
	return pt_regs;
}

static void * 
get_ppc64_regs_from_elf_notes(struct task_context *tc)
{
	Elf64_Nhdr *note;
	size_t len;
	void *pt_regs;
	extern struct vmcore_data *nd;

	pt_regs = NULL;

	/*
	 * Registers are always saved during the dump process for the
	 * panic task.  Kdump also captures registers for all CPUs if
	 * they responded to an IPI.
	 */
	if (nd->num_prstatus_notes > 1) {
		note = (Elf64_Nhdr *)nd->nt_prstatus_percpu[tc->processor];
	} else
		note = (Elf64_Nhdr *)nd->nt_prstatus;

	if (!note)
		goto no_nt_prstatus_exists;

	len = sizeof(Elf64_Nhdr);
	len = roundup(len + note->n_namesz, 4);
	pt_regs = (void *)((char *)note + len +
			   MEMBER_OFFSET("elf_prstatus", "pr_reg"));

no_nt_prstatus_exists:
	return pt_regs;
}

int
kdump_phys_base(ulong *phys_base)
{
	if (!kdump_kaslr_check())
		return FALSE;

	*phys_base = nd->phys_base;

	return TRUE;
}

int
kdump_set_phys_base(ulong phys_base)
{
	if (!kdump_kaslr_check())
		return FALSE;

	nd->phys_base = phys_base;

	return TRUE;
}

/*
 * In case of ARM we need to determine correct PHYS_OFFSET from the kdump file.
 * This is done by taking lowest physical address (LMA) from given load
 * segments. Normally this is the right one.
 *
 * Alternative would be to store phys_base in VMCOREINFO but current kernel
 * kdump doesn't do that yet.
 */
int arm_kdump_phys_base(ulong *phys_base)
{
	struct pt_load_segment *pls;
	ulong paddr = ULONG_MAX;
	int i;

	for (i = 0; i < nd->num_pt_load_segments; i++) {
		pls = &nd->pt_load_segments[i];
		if (pls->phys_start < paddr)
			paddr = pls->phys_start;
	}

	if (paddr != ULONG_MAX) {
		*phys_base = paddr;
		return TRUE;
	}
	return FALSE;
}

/*
 * physical memory size, calculated by given load segments
 */
int
arm_kdump_phys_end(ulong *phys_end)
{
	struct pt_load_segment *pls;
	ulong paddr = 0;
	int i;

	for (i = 0; i < nd->num_pt_load_segments; i++) {
		pls = &nd->pt_load_segments[i];
		if (pls->phys_end > paddr)
			paddr = pls->phys_end;
	}

	if (paddr != 0) {
		*phys_end = paddr;
		return TRUE;
	}
	return FALSE;
}

static void *
get_arm_regs_from_elf_notes(struct task_context *tc)
{
	Elf32_Nhdr *note_32;
	Elf64_Nhdr *note_64;
	void *note;
	size_t len;
	void *pt_regs;

	len = 0;
	pt_regs = NULL;

	if (nd->num_prstatus_notes > 1)
		note = (void *)nd->nt_prstatus_percpu[tc->processor];
	else
		note = (void *)nd->nt_prstatus;

	if (!note)
		goto no_nt_prstatus_exists;

	if (nd->elf32) {
		note_32 = (Elf32_Nhdr *)note;
		len = sizeof(Elf32_Nhdr);
		len = roundup(len + note_32->n_namesz, 4);
	} else if (nd->elf64) {
		note_64 = (Elf64_Nhdr *)note;
		len = sizeof(Elf64_Nhdr);
		len = roundup(len + note_64->n_namesz, 4);
	}

	pt_regs = (void *)((char *)note + len +
			   MEMBER_OFFSET("elf_prstatus", "pr_reg"));

no_nt_prstatus_exists:
	return pt_regs;
}

/*
 *  Read from /proc/kcore.
 */
int
read_proc_kcore(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr) 
{
	int i, ret;
	size_t readcnt;
	ulong kvaddr;
	Elf32_Phdr *lp32;
	Elf64_Phdr *lp64;
	off_t offset;

	if (paddr != KCORE_USE_VADDR) {
		if (!machdep->verify_paddr(paddr)) {
			if (CRASHDEBUG(1))
				error(INFO, "verify_paddr(%lx) failed\n", paddr);
			return READ_ERROR;
		}
	}

	/*
	 *  Unless specified otherwise, turn the physical address into 
	 *  a unity-mapped kernel virtual address, which should work 
	 *  for 64-bit architectures, and for lowmem access for 32-bit
	 *  architectures.
	 */
	if (paddr == KCORE_USE_VADDR)
		kvaddr = addr;
	else
		kvaddr =  PTOV((ulong)paddr);

	offset = UNINITIALIZED;
	readcnt = cnt;

	switch (pkd->flags & (KCORE_ELF32|KCORE_ELF64)) 
	{
	case KCORE_ELF32:
		for (i = 0; i < pkd->segments; i++) {
			lp32 = pkd->load32 + i;
			if ((kvaddr >= lp32->p_vaddr) &&
			    (kvaddr < (lp32->p_vaddr + lp32->p_memsz))) {
				offset = (off_t)(kvaddr - lp32->p_vaddr) + 
					(off_t)lp32->p_offset;
				break;
			}
		}
		/*
		 *  If it's not accessible via unity-mapping, check whether
		 *  it's a request for a vmalloc address that can be found 
                 *  in the header.
		 */
		if (pc->curcmd_flags & MEMTYPE_KVADDR)
			pc->curcmd_flags &= ~MEMTYPE_KVADDR;
		else
			break;

		for (i = 0; i < pkd->segments; i++) {
			lp32 = pkd->load32 + i;
			if ((addr >= lp32->p_vaddr) &&
			    (addr < (lp32->p_vaddr + lp32->p_memsz))) {
				offset = (off_t)(addr - lp32->p_vaddr) + 
					(off_t)lp32->p_offset;
				break;
			}
		}

		break;

	case KCORE_ELF64:
		/*
		 *  If KASLR, the PAGE_OFFSET may be unknown early on, so try
		 *  the (hopefully) mapped kernel address first.
		 */
		if (!(pc->flags & RUNTIME) &&
		    (pc->curcmd_flags & MEMTYPE_KVADDR) && (kvaddr != addr)) {
			pc->curcmd_flags &= ~MEMTYPE_KVADDR;
			for (i = 0; i < pkd->segments; i++) {
				lp64 = pkd->load64 + i;
				if ((addr >= lp64->p_vaddr) &&
				    (addr < (lp64->p_vaddr + lp64->p_memsz))) {
					offset = (off_t)(addr - lp64->p_vaddr) + 
						(off_t)lp64->p_offset;
					break;
				}
			}
			if (offset != UNINITIALIZED)
				break;
		}

		for (i = 0; i < pkd->segments; i++) {
			lp64 = pkd->load64 + i;
			if ((kvaddr >= lp64->p_vaddr) &&
			    (kvaddr < (lp64->p_vaddr + lp64->p_memsz))) {
				offset = (off_t)(kvaddr - lp64->p_vaddr) + 
					(off_t)lp64->p_offset;
				break;
			}
		}

		break;
	}

	if (offset == UNINITIALIZED)
		return SEEK_ERROR;

	if (offset < 0) {
		if (CRASHDEBUG(8))
			fprintf(fp, "read_proc_kcore: invalid offset: %lx\n", offset);
		return SEEK_ERROR;
	}
	if ((ret = pread(fd, bufptr, readcnt, offset)) != readcnt) {
		if (ret == -1 && CRASHDEBUG(8))
			fprintf(fp, "read_proc_kcore: pread error: %s\n", strerror(errno));
		return READ_ERROR;
	}

	return cnt;
}

/*
 *  place holder -- cannot write to /proc/kcore
 */
int
write_proc_kcore(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	error(FATAL, "cannot write to /proc/kcore\n");
	return FALSE;
}

int
is_proc_kcore(char *file, ulong source_query)
{
	if (STREQ(file, "/proc/kcore") || same_file(file, "/proc/kcore")) {
		if (!is_netdump(file, source_query))
			error(FATAL, 
			    "cannot translate the ELF header of /proc/kcore\n");
		pkd->flags |= KCORE_LOCAL;
		return TRUE;
	} else
		return FALSE;
}

int
proc_kcore_init(FILE *fp, int kcore_fd)
{
	if (pkd->flags & (KCORE_ELF32|KCORE_ELF64))
		return TRUE;

	if (BITS32())
		return proc_kcore_init_32(fp, kcore_fd);
	else 
		return proc_kcore_init_64(fp, kcore_fd);
}

static int
proc_kcore_init_32(FILE *fp, int kcore_fd)
{
	int fd;
	Elf32_Ehdr *elf32;
	Elf32_Phdr *load32;
	Elf32_Phdr *notes32;
	char eheader[MAX_KCORE_ELF_HEADER_SIZE];
	char buf[BUFSIZE];
	size_t load_size, notes_size;

	if (kcore_fd == UNUSED) {
		if ((fd = open("/proc/kcore", O_RDONLY)) < 0) {
			error(INFO, "/proc/kcore: %s\n", strerror(errno));
			return FALSE;
		}
	} else
		fd = kcore_fd;

	if (read(fd, eheader, MAX_KCORE_ELF_HEADER_SIZE) != MAX_KCORE_ELF_HEADER_SIZE) {
		sprintf(buf, "/proc/kcore: read");
		perror(buf);
		goto bailout;
	}

	if (lseek(fd, 0, SEEK_SET) != 0) {
		sprintf(buf, "/proc/kcore: lseek");
		perror(buf);
		goto bailout;
	}

	if (fd != kcore_fd)
		close(fd);

	elf32 = (Elf32_Ehdr *)&eheader[0];
	if (elf32->e_phoff > sizeof(eheader) - 2 * sizeof(Elf32_Phdr)) {
		error(INFO, "/proc/kcore: ELF program header offset too big!\n");
		return FALSE;
	}
	notes32 = (Elf32_Phdr *)&eheader[elf32->e_phoff];
	load32 = notes32 + 1;

	pkd->segments = elf32->e_phnum - 1;

	notes_size = load_size = 0;
	if (notes32->p_type == PT_NOTE)
		notes_size = notes32->p_offset + notes32->p_filesz;
	if (notes32->p_type == PT_LOAD)
		load_size = (ulong)(load32+(elf32->e_phnum)) - (ulong)elf32;
	pkd->header_size = MAX(notes_size, load_size);
	if (!pkd->header_size)
		pkd->header_size = MAX_KCORE_ELF_HEADER_SIZE;

	if ((pkd->elf_header = (char *)malloc(pkd->header_size)) == NULL) {
		error(INFO, "/proc/kcore: cannot malloc ELF header buffer\n");
		clean_exit(1);
	}

	BCOPY(&eheader[0], &pkd->elf_header[0], pkd->header_size);	
	pkd->notes32 = (Elf32_Phdr *)&pkd->elf_header[elf32->e_phoff];
	pkd->load32 = pkd->notes32 + 1;
	pkd->flags |= KCORE_ELF32;
	
	kcore_memory_dump(CRASHDEBUG(1) ? fp : pc->nullfp);

	return TRUE;

bailout:
	if (fd != kcore_fd)
		close(fd);
	return FALSE;
}

static int
proc_kcore_init_64(FILE *fp, int kcore_fd)
{
	int fd;
	Elf64_Ehdr *elf64;
	Elf64_Phdr *load64;
	Elf64_Phdr *notes64;
	char eheader[MAX_KCORE_ELF_HEADER_SIZE];
	char buf[BUFSIZE];
	size_t load_size, notes_size;

	if (kcore_fd == UNUSED) {
		if ((fd = open("/proc/kcore", O_RDONLY)) < 0) {
			error(INFO, "/proc/kcore: %s\n", strerror(errno));
			return FALSE;
		}
	} else
		fd = kcore_fd;

	if (read(fd, eheader, MAX_KCORE_ELF_HEADER_SIZE) != MAX_KCORE_ELF_HEADER_SIZE) {
		sprintf(buf, "/proc/kcore: read");
		perror(buf);
		goto bailout;
	}

	if (lseek(fd, 0, SEEK_SET) != 0) {
		sprintf(buf, "/proc/kcore: lseek");
		perror(buf);
		goto bailout;
	}

	if (fd != kcore_fd)
		close(fd);

	elf64 = (Elf64_Ehdr *)&eheader[0];
	if (elf64->e_phoff > sizeof(eheader) - 2 * sizeof(Elf64_Phdr)) {
		error(INFO, "/proc/kcore: ELF program header offset too big!\n");
		return FALSE;
	}
	notes64 = (Elf64_Phdr *)&eheader[elf64->e_phoff];
	load64 = notes64 + 1;

	pkd->segments = elf64->e_phnum - 1;

	notes_size = load_size = 0;
	if (notes64->p_type == PT_NOTE)
		notes_size = notes64->p_offset + notes64->p_filesz;
	if (notes64->p_type == PT_LOAD)
		load_size = (ulong)(load64+(elf64->e_phnum)) - (ulong)elf64;

	pkd->header_size = MAX(notes_size, load_size);
	if (!pkd->header_size)
		pkd->header_size = MAX_KCORE_ELF_HEADER_SIZE;

	if ((pkd->elf_header = (char *)malloc(pkd->header_size)) == NULL) {
		error(INFO, "/proc/kcore: cannot malloc ELF header buffer\n");
		clean_exit(1);
	}

	BCOPY(&eheader[0], &pkd->elf_header[0], pkd->header_size);	
	pkd->notes64 = (Elf64_Phdr *)&pkd->elf_header[elf64->e_phoff];
	pkd->load64 = pkd->notes64 + 1;
	pkd->flags |= KCORE_ELF64;
	
	kcore_memory_dump(CRASHDEBUG(1) ? fp : pc->nullfp);

	return TRUE;

bailout:
	if (fd != kcore_fd)
		close(fd);
	return FALSE;
}

int
kcore_memory_dump(FILE *ofp)
{
	int i, others;
	Elf32_Phdr *ph32;
	Elf64_Phdr *ph64;
	Elf32_Nhdr *note32;
	Elf64_Nhdr *note64;
	size_t tot, len;
	char *name, *ptr, buf[BUFSIZE];

	fprintf(ofp, "proc_kcore_data:\n");
	fprintf(ofp, "           flags: %x (", pkd->flags);
	others = 0;
	if (pkd->flags & KCORE_LOCAL)
		fprintf(ofp, "%sKCORE_LOCAL", others++ ? "|" : "");
	if (pkd->flags & KCORE_ELF32)
		fprintf(ofp, "%sKCORE_ELF32", others++ ? "|" : "");
	if (pkd->flags & KCORE_ELF64)
		fprintf(ofp, "%sKCORE_ELF64", others++ ? "|" : "");
	fprintf(ofp, ")\n");
	fprintf(ofp, "        segments: %d\n",
		pkd->segments);
	fprintf(ofp, "      elf_header: %lx\n", (ulong)pkd->elf_header);
	fprintf(ofp, "     header_size: %ld\n", (ulong)pkd->header_size);
	fprintf(ofp, "         notes64: %lx\n", (ulong)pkd->notes64);
	fprintf(ofp, "          load64: %lx\n", (ulong)pkd->load64);
	fprintf(ofp, "         notes32: %lx\n", (ulong)pkd->notes32);
	fprintf(ofp, "          load32: %lx\n", (ulong)pkd->load32);
	fprintf(ofp, "      vmcoreinfo: %lx\n", (ulong)pkd->vmcoreinfo);
	fprintf(ofp, " size_vmcoreinfo: %d\n\n", pkd->size_vmcoreinfo); 

	if (pkd->flags & KCORE_ELF32) {
		ph32 = pkd->notes32;

		fprintf(ofp, "  Elf32_Phdr:\n");
		fprintf(ofp, "        p_type: %x ", ph32->p_type);
		switch (ph32->p_type)
		{
		case PT_NOTE:
			fprintf(ofp, "(PT_NOTE)\n");
			break;
		case PT_LOAD:
			fprintf(ofp, "(PT_LOAD)\n");
			break;
		default:
			fprintf(ofp, "(unknown)\n");
			break;
		}
		fprintf(ofp, "       p_flags: %x\n", ph32->p_flags);
		fprintf(ofp, "      p_offset: %x\n", ph32->p_offset);
		fprintf(ofp, "       p_vaddr: %x\n", ph32->p_vaddr);
		fprintf(ofp, "       p_paddr: %x\n", ph32->p_paddr);
		fprintf(ofp, "      p_filesz: %d\n", ph32->p_filesz);
		fprintf(ofp, "       p_memsz: %d\n", ph32->p_memsz);
		fprintf(ofp, "       p_align: %d\n", ph32->p_align);
		fprintf(ofp, "\n");

		for (i = 0; i < pkd->segments; i++) {
			ph32 = pkd->load32 + i;
	
			fprintf(ofp, "  Elf32_Phdr:\n");
			fprintf(ofp, "        p_type: %x ", ph32->p_type);
			switch (ph32->p_type)
			{
			case PT_NOTE:
				fprintf(ofp, "(PT_NOTE)\n");
				break;
			case PT_LOAD:
				fprintf(ofp, "(PT_LOAD)\n");
				break;
			default:
				fprintf(ofp, "(unknown)\n");
				break;
			}
			fprintf(ofp, "       p_flags: %x\n", ph32->p_flags);
			fprintf(ofp, "      p_offset: %x\n", ph32->p_offset);
			fprintf(ofp, "       p_vaddr: %x\n", ph32->p_vaddr);
			fprintf(ofp, "       p_paddr: %x\n", ph32->p_paddr);
			fprintf(ofp, "      p_filesz: %d\n", ph32->p_filesz);
			fprintf(ofp, "       p_memsz: %d\n", ph32->p_memsz);
			fprintf(ofp, "       p_align: %d\n", ph32->p_align);
			fprintf(ofp, "\n");
		}

		note32 = (Elf32_Nhdr *)(pkd->elf_header + pkd->notes32->p_offset);

                for (tot = 0; tot < pkd->notes32->p_filesz; tot += len) {
			name = (char *)((ulong)note32 + sizeof(Elf32_Nhdr));
			snprintf(buf, note32->n_namesz, "%s", name);

			fprintf(ofp, "  Elf32_Nhdr:\n");
			fprintf(ofp, "      n_namesz: %d (\"%s\")\n", note32->n_namesz, buf);
			fprintf(ofp, "      n_descsz: %d\n", note32->n_descsz);
			fprintf(ofp, "        n_type: %d ", note32->n_type);
			switch (note32->n_type)
			{
			case NT_PRSTATUS:
				fprintf(ofp, "(NT_PRSTATUS)\n");
				break;
			case NT_PRPSINFO:
				fprintf(ofp, "(NT_PRPSINFO)\n");
				break;
			case NT_TASKSTRUCT:
				fprintf(ofp, "(NT_TASKSTRUCT)\n");
				break;
			default:
				fprintf(ofp, "(unknown)\n");
				if (STRNEQ(name, "VMCOREINFO")) {
					ptr = (char *)note32 +
						sizeof(Elf32_Nhdr) +
						note32->n_namesz + 1; 
					pkd->vmcoreinfo = (void *)ptr;
					pkd->size_vmcoreinfo = note32->n_descsz;
					pc->read_vmcoreinfo = vmcoreinfo_read_string;
					fprintf(ofp, "\n      ");
					for (i = 0; i < note32->n_descsz; i++, ptr++) {
						fprintf(ofp, "%c%s", *ptr,
							*ptr == '\n' ?  "      " : "");
					}
				}
				break;
			}

			fprintf(ofp, "\n");

			len = sizeof(Elf32_Nhdr);
			len = roundup(len + note32->n_namesz, 4);
			len = roundup(len + note32->n_descsz, 4);
			note32 = (Elf32_Nhdr *)((ulong)note32 + len);
		}
	} 

	if (pkd->flags & KCORE_ELF64) {
		ph64 = pkd->notes64;

		fprintf(ofp, "  Elf64_Phdr:\n");
		fprintf(ofp, "        p_type: %x ", ph64->p_type);
		switch (ph64->p_type)
		{
		case PT_NOTE:
			fprintf(ofp, "(PT_NOTE)\n");
			break;
		case PT_LOAD:
			fprintf(ofp, "(PT_LOAD)\n");
			break;
		default:
			fprintf(ofp, "(unknown)\n");
			break;
		}
		fprintf(ofp, "       p_flags: %x\n", ph64->p_flags);
		fprintf(ofp, "      p_offset: %llx\n", (ulonglong)ph64->p_offset);
		fprintf(ofp, "       p_vaddr: %llx\n", (ulonglong)ph64->p_vaddr);
		fprintf(ofp, "       p_paddr: %llx\n", (ulonglong)ph64->p_paddr);
		fprintf(ofp, "      p_filesz: %lld\n", (ulonglong)ph64->p_filesz);
		fprintf(ofp, "       p_memsz: %lld\n", (ulonglong)ph64->p_memsz);
		fprintf(ofp, "       p_align: %lld\n", (ulonglong)ph64->p_align);
		fprintf(ofp, "\n");

		for (i = 0; i < pkd->segments; i++) {
			ph64 = pkd->load64 + i;
	
			fprintf(ofp, "  Elf64_Phdr:\n");
			fprintf(ofp, "        p_type: %x ", ph64->p_type);
			switch (ph64->p_type)
			{
			case PT_NOTE:
				fprintf(ofp, "(PT_NOTE)\n");
				break;
			case PT_LOAD:
				fprintf(ofp, "(PT_LOAD)\n");
				break;
			default:
				fprintf(ofp, "(unknown)\n");
				break;
			}
			fprintf(ofp, "       p_flags: %x\n", ph64->p_flags);
			fprintf(ofp, "      p_offset: %llx\n", (ulonglong)ph64->p_offset);
			fprintf(ofp, "       p_vaddr: %llx\n", (ulonglong)ph64->p_vaddr);
			fprintf(ofp, "       p_paddr: %llx\n", (ulonglong)ph64->p_paddr);
			fprintf(ofp, "      p_filesz: %lld\n", (ulonglong)ph64->p_filesz);
			fprintf(ofp, "       p_memsz: %lld\n", (ulonglong)ph64->p_memsz);
			fprintf(ofp, "       p_align: %lld\n", (ulonglong)ph64->p_align);
			fprintf(ofp, "\n");
		}

		note64 = (Elf64_Nhdr *)(pkd->elf_header + pkd->notes64->p_offset);

                for (tot = 0; tot < pkd->notes64->p_filesz; tot += len) {
			name = (char *)((ulong)note64 + sizeof(Elf64_Nhdr));
			snprintf(buf, note64->n_namesz, "%s", name);

			fprintf(ofp, "  Elf64_Nhdr:\n");
			fprintf(ofp, "      n_namesz: %d (\"%s\")\n", note64->n_namesz, buf);
			fprintf(ofp, "      n_descsz: %d\n", note64->n_descsz);
			fprintf(ofp, "        n_type: %d ", note64->n_type);
			switch (note64->n_type)
			{
			case NT_PRSTATUS:
				fprintf(ofp, "(NT_PRSTATUS)\n");
				break;
			case NT_PRPSINFO:
				fprintf(ofp, "(NT_PRPSINFO)\n");
				break;
			case NT_TASKSTRUCT:
				fprintf(ofp, "(NT_TASKSTRUCT)\n");
				break;
			default:
				fprintf(ofp, "(unknown)\n");
				if (STRNEQ(name, "VMCOREINFO")) {
					ptr = (char *)note64 +
						sizeof(Elf64_Nhdr) +
						note64->n_namesz + 1; 
					pkd->vmcoreinfo = (void *)ptr;
					pkd->size_vmcoreinfo = note64->n_descsz;
					pc->read_vmcoreinfo = vmcoreinfo_read_string;
					fprintf(ofp, "\n      ");
					for (i = 0; i < note64->n_descsz; i++, ptr++) {
						fprintf(ofp, "%c%s", *ptr,
							*ptr == '\n' ?  "      " : "");
					}
				}
				break;
			}

			fprintf(ofp, "\n");

			len = sizeof(Elf64_Nhdr);
			len = roundup(len + note64->n_namesz, 4);
			len = roundup(len + note64->n_descsz, 4);
			note64 = (Elf64_Nhdr *)((ulong)note64 + len);
		}
	}

	return TRUE;
}

static void
kdump_get_osrelease(void)
{
	char *string;

	if ((string = vmcoreinfo_read_string("OSRELEASE"))) {
		fprintf(fp, "%s\n", string);
		free(string);
	} else 
		pc->flags2 &= ~GET_OSRELEASE;
}

void
dump_registers_for_qemu_mem_dump(void)
{
	int i;
	QEMUCPUState *ptr;
	FILE *fpsave;

	fpsave = nd->ofp;
	nd->ofp = fp;

	for (i = 0; i < nd->num_qemu_notes; i++) {
		ptr = (QEMUCPUState *)nd->nt_qemu_percpu[i];

		if (i)
			netdump_print("\n");

		if (hide_offline_cpu(i)) {
			netdump_print("CPU %d: [OFFLINE]\n", i);
			continue;
		} else
			netdump_print("CPU %d:\n", i);

		if (CRASHDEBUG(1))
			netdump_print("  version:%d  size:%d\n",
				ptr->version, ptr->size);
		netdump_print("  RAX: %016llx  RBX: %016llx  RCX: %016llx\n",
			ptr->rax, ptr->rbx, ptr->rcx);
		netdump_print("  RDX: %016llx  RSI: %016llx  RDI:%016llx\n",
			ptr->rdx, ptr->rsi, ptr->rdi);
		netdump_print("  RSP: %016llx  RBP: %016llx  ",
			ptr->rsp, ptr->rbp);
	
		if (DUMPFILE_FORMAT(nd->flags) == KDUMP_ELF64) {
			netdump_print(" R8: %016llx\n",
				ptr->r8);
			netdump_print("   R9: %016llx  R10: %016llx  R11: %016llx\n",
				ptr->r9, ptr->r10, ptr->r11);
			netdump_print("  R12: %016llx  R13: %016llx  R14: %016llx\n",
				ptr->r12, ptr->r13, ptr->r14);
			netdump_print("  R15: %016llx",
				ptr->r15);
		} else
                        netdump_print("\n");

		netdump_print("  RIP: %016llx  RFLAGS: %08llx\n",
			ptr->rip, ptr->rflags);
		netdump_print("   CS: selector: %04lx  limit: %08lx  flags: %08lx\n\
       pad: %08lx   base: %016llx\n",
			ptr->cs.selector, ptr->cs.limit, ptr->cs.flags,
			ptr->cs.pad, ptr->cs.base);
		netdump_print("   DS: selector: %04lx  limit: %08lx  flags: %08lx\n\
       pad: %08lx   base: %016llx\n",
			ptr->ds.selector, ptr->ds.limit, ptr->ds.flags,
			ptr->ds.pad, ptr->ds.base);
		netdump_print("   ES: selector: %04lx  limit: %08lx  flags: %08lx\n\
       pad: %08lx   base: %016llx\n",
			ptr->es.selector, ptr->es.limit, ptr->es.flags,
			ptr->es.pad, ptr->es.base);
		netdump_print("   FS: selector: %04lx  limit: %08lx  flags: %08lx\n\
       pad: %08lx   base: %016llx\n",
			ptr->fs.selector, ptr->fs.limit, ptr->fs.flags,
			ptr->fs.pad, ptr->fs.base);
		netdump_print("   GS: selector: %04lx  limit: %08lx  flags: %08lx\n\
       pad: %08lx   base: %016llx\n",
			ptr->gs.selector, ptr->gs.limit, ptr->gs.flags,
			ptr->gs.pad, ptr->gs.base);
		netdump_print("   SS: selector: %04lx  limit: %08lx  flags: %08lx\n\
       pad: %08lx   base: %016llx\n",
			ptr->ss.selector, ptr->ss.limit, ptr->ss.flags,
			ptr->ss.pad, ptr->ss.base);
		netdump_print("  LDT: selector: %04lx  limit: %08lx  flags: %08lx\n\
       pad: %08lx   base: %016llx\n",
			ptr->ldt.selector, ptr->ldt.limit, ptr->ldt.flags,
			ptr->ldt.pad, ptr->ldt.base);
		netdump_print("   TR: selector: %04lx  limit: %08lx  flags: %08lx\n\
       pad: %08lx   base: %016llx\n",
			ptr->tr.selector, ptr->tr.limit, ptr->tr.flags,
			ptr->tr.pad, ptr->tr.base);
		netdump_print("  GDT: selector: %04lx  limit: %08lx  flags: %08lx\n\
       pad: %08lx   base: %016llx\n",
			ptr->gdt.selector, ptr->gdt.limit, ptr->gdt.flags,
			ptr->gdt.pad, ptr->gdt.base);
		netdump_print("  IDT: selector: %04lx  limit: %08lx  flags: %08lx\n\
       pad: %08lx   base: %016llx\n",
			ptr->idt.selector, ptr->idt.limit, ptr->idt.flags,
			ptr->idt.pad, ptr->idt.base);
		netdump_print("  CR0: %016llx  CR1: %016llx  CR2: %016llx\n",
			ptr->cr[0], ptr->cr[1], ptr->cr[2]);
		netdump_print("  CR3: %016llx  CR4: %016llx\n",
			ptr->cr[3], ptr->cr[4]);
	}

	nd->ofp = fpsave;
}

/* 
 * kdump saves the first 640kB physical memory for BIOS to use the
 * range on boot of 2nd kernel. Read request to the 640k should be 
 * translated to the back up region. This function searches kexec
 * resources for the backup region.
 */
void
kdump_backup_region_init(void)
{
	char buf[BUFSIZE];
	ulong i, total, kexec_crash_image_p, elfcorehdr_p;
	Elf32_Off e_phoff32;
	Elf64_Off e_phoff64;
	uint16_t e_phnum, e_phentsize;
	ulonglong backup_offset;
	ulonglong backup_src_start;
	ulong backup_src_size;
	int kimage_segment_len;
	size_t bufsize;
	struct vmcore_data *vd;
	struct sadump_data *sd;
	int is_32_bit;  
	char typename[BUFSIZE];

	e_phoff32 = e_phoff64 = 0;
	vd = NULL;
	sd = NULL;

	if (SADUMP_DUMPFILE()) {
		sd = get_sadump_data();
		is_32_bit = FALSE;
		sprintf(typename, "sadump");
	} else if (pc->flags2 & QEMU_MEM_DUMP_ELF) {
		vd = get_kdump_vmcore_data();
		if (vd->flags & KDUMP_ELF32)
			is_32_bit = TRUE;
		else
			is_32_bit = FALSE;
		sprintf(typename, "qemu mem dump");
	} else
		return;

	if (symbol_exists("kexec_crash_image")) {
		if (!readmem(symbol_value("kexec_crash_image"), KVADDR,
			     &kexec_crash_image_p, sizeof(ulong),
			     "kexec backup region: kexec_crash_image",
			     QUIET|RETURN_ON_ERROR))
			goto error;
	} else
		kexec_crash_image_p = 0;

	if (!kexec_crash_image_p) {
		if (CRASHDEBUG(1))
			error(INFO, "%s: kexec_crash_image not loaded\n", typename);
		return;
	}

	kimage_segment_len = get_array_length("kimage.segment", NULL,
					      STRUCT_SIZE("kexec_segment"));

	if (!readmem(kexec_crash_image_p + MEMBER_OFFSET("kimage", "segment"),
		     KVADDR, buf, MEMBER_SIZE("kimage", "segment"),
		     "kexec backup region: kexec_crash_image->segment",
		     QUIET|RETURN_ON_ERROR))
		goto error;

	elfcorehdr_p = 0;
	for (i = 0; i < kimage_segment_len; ++i) {
		char e_ident[EI_NIDENT];
		ulong mem;

		mem = ULONG(buf + i * STRUCT_SIZE("kexec_segment") +
			    MEMBER_OFFSET("kexec_segment", "mem"));
		if (!mem)
			continue;

		if (!readmem(mem, PHYSADDR, e_ident, SELFMAG,
			     "elfcorehdr: e_ident",
			     QUIET|RETURN_ON_ERROR))
			goto error;

		if (strncmp(ELFMAG, e_ident, SELFMAG) == 0) {
			elfcorehdr_p = mem;
			break;
		}
	}
	if (!elfcorehdr_p) {
		if (CRASHDEBUG(1))
			error(INFO,
	"%s: elfcorehdr not found in segments of kexec_crash_image\n", typename);
		goto error;
	}
	
	if (is_32_bit) {
		if (!readmem(elfcorehdr_p, PHYSADDR, buf, STRUCT_SIZE("elf32_hdr"),
			"elfcorehdr", QUIET|RETURN_ON_ERROR))
			goto error;

		e_phnum = USHORT(buf + MEMBER_OFFSET("elf32_hdr", "e_phnum"));
		e_phentsize = USHORT(buf + MEMBER_OFFSET("elf32_hdr", "e_phentsize"));
		e_phoff32 = ULONG(buf + MEMBER_OFFSET("elf32_hdr", "e_phoff"));
	} else {
		if (!readmem(elfcorehdr_p, PHYSADDR, buf, STRUCT_SIZE("elf64_hdr"),
			    "elfcorehdr", QUIET|RETURN_ON_ERROR))
			goto error;

		e_phnum = USHORT(buf + MEMBER_OFFSET("elf64_hdr", "e_phnum"));
		e_phentsize = USHORT(buf + MEMBER_OFFSET("elf64_hdr", "e_phentsize"));
		e_phoff64 = ULONG(buf + MEMBER_OFFSET("elf64_hdr", "e_phoff"));
	}

	backup_src_start = backup_src_size = backup_offset = 0;

	for (i = 0; i < e_phnum; ++i) {
		uint32_t p_type;
		Elf32_Off p_offset32;
		Elf64_Off p_offset64;
		Elf32_Addr p_paddr32;
		Elf64_Addr p_paddr64;
		uint32_t p_memsz32;
		uint64_t p_memsz64;

		if (is_32_bit) {
			if (!readmem(elfcorehdr_p + e_phoff32 + i * e_phentsize,
				    PHYSADDR, buf, e_phentsize,
				    "elfcorehdr: program header",
				    QUIET|RETURN_ON_ERROR))
				goto error;

			p_type = UINT(buf+MEMBER_OFFSET("elf32_phdr","p_type"));
			p_offset32 = ULONG(buf+MEMBER_OFFSET("elf32_phdr","p_offset"));
			p_paddr32 = ULONG(buf+MEMBER_OFFSET("elf32_phdr","p_paddr"));
			p_memsz32 = ULONG(buf+MEMBER_OFFSET("elf32_phdr","p_memsz"));
		} else {
			if (!readmem(elfcorehdr_p + e_phoff64 + i * e_phentsize,
				    PHYSADDR, buf, e_phentsize,
				    "elfcorehdr: program header",
				    QUIET|RETURN_ON_ERROR))
				goto error;

			p_type = UINT(buf+MEMBER_OFFSET("elf64_phdr","p_type"));
			p_offset64 = ULONG(buf+MEMBER_OFFSET("elf64_phdr","p_offset"));
			p_paddr64 = ULONG(buf+MEMBER_OFFSET("elf64_phdr","p_paddr"));
			p_memsz64 = ULONG(buf+MEMBER_OFFSET("elf64_phdr","p_memsz"));
		}

		/*
		 * kexec marks backup region PT_LOAD by assigning
		 * backup region address in p_offset, and p_addr in
		 * p_offsets for other PT_LOAD entries.
		 */
		if (is_32_bit) {
			if (p_type == PT_LOAD &&
			    p_paddr32 <= KEXEC_BACKUP_SRC_END &&
			    p_paddr32 != p_offset32) {

				backup_src_start = p_paddr32;
				backup_src_size = p_memsz32;
				backup_offset = p_offset32;

				if (CRASHDEBUG(1))
					error(INFO,
				"%s: kexec backup region found: "
				"START: %#016llx SIZE: %#016lx OFFSET: %#016llx\n",
				typename, backup_src_start, backup_src_size, backup_offset);

				break;
			}
		} else {
			if (p_type == PT_LOAD &&
			    p_paddr64 <= KEXEC_BACKUP_SRC_END &&
			    p_paddr64 != p_offset64) {

				backup_src_start = p_paddr64;
				backup_src_size = p_memsz64;
				backup_offset = p_offset64;

				if (CRASHDEBUG(1))
					error(INFO,
				"%s: kexec backup region found: "
				"START: %#016llx SIZE: %#016lx OFFSET: %#016llx\n",
				typename, backup_src_start, backup_src_size, backup_offset);

				break;
			}
		}
	}

	if (!backup_offset) {
		if (CRASHDEBUG(1))
	error(WARNING, "%s: backup region not found in elfcorehdr\n", typename);
		return;
	}

	bufsize = BUFSIZE;
	for (total = 0; total < backup_src_size; total += bufsize) {
		char backup_buf[BUFSIZE];
		int j;

		if (backup_src_size - total < BUFSIZE)
			bufsize = backup_src_size - total;

		if (!readmem(backup_offset + total, PHYSADDR, backup_buf,
			     bufsize, "backup source", QUIET|RETURN_ON_ERROR))
			goto error;

		/*
		 * We're assuming the backup region is initialized
		 * with 0 filled if kdump has not run.
		 */
		for (j = 0; j < bufsize; ++j) {
			if (backup_buf[j]) {

				if (SADUMP_DUMPFILE()) {
					sd->flags |= SADUMP_KDUMP_BACKUP;
					sd->backup_src_start = backup_src_start;
					sd->backup_src_size = backup_src_size;
					sd->backup_offset = backup_offset;
				} else if (pc->flags2 & QEMU_MEM_DUMP_ELF) {
					vd->flags |= QEMU_MEM_DUMP_KDUMP_BACKUP;
					vd->backup_src_start = backup_src_start;
					vd->backup_src_size = backup_src_size;
					vd->backup_offset = backup_offset;
				}

				if (CRASHDEBUG(1))
error(INFO, "%s: backup region is used: %llx\n", typename, backup_offset + total + j);

				return;
			}
		}
	}

	if (CRASHDEBUG(1))
		error(INFO, "%s: kexec backup region not used\n", typename);

	return;

error:
	error(WARNING, "failed to init kexec backup region\n");
}

int
kdump_kaslr_check(void)
{
	if (!QEMU_MEM_DUMP_NO_VMCOREINFO())
		return FALSE;

	/* If vmcore has QEMU note, need to calculate kaslr offset */
	if (nd->num_qemu_notes)
		return TRUE;
	else
		return FALSE;
}

int
kdump_get_nr_cpus(void)
{
        if (nd->num_prstatus_notes)
                return nd->num_prstatus_notes;
        else if (nd->num_qemu_notes)
                return nd->num_qemu_notes;
        else if (nd->num_vmcoredd_notes)
                return nd->num_vmcoredd_notes;

        return 1;
}

QEMUCPUState *
kdump_get_qemucpustate(int cpu)
{
	if (cpu >= nd->num_qemu_notes) {
		if (CRASHDEBUG(1))
			error(INFO,
			    "Invalid index for QEMU Note: %d (>= %d)\n",
			    cpu, nd->num_qemu_notes);
		return NULL;
	}

	if (!nd->elf64 || (nd->elf64->e_machine != EM_X86_64)) {
		if (CRASHDEBUG(1))
			error(INFO, "Only x86_64 64bit is supported.\n");
		return NULL;
	}

	return (QEMUCPUState *)nd->nt_qemu_percpu[cpu];
}

static void *
get_kdump_device_dump_offset(void)
{
	void *elf_base = NULL;

	if (DUMPFILE_FORMAT(nd->flags) == KDUMP_ELF64)
		elf_base = (void *)nd->elf64;
	else if (DUMPFILE_FORMAT(nd->flags) == KDUMP_ELF32)
		elf_base = (void *)nd->elf32;
	else
		error(FATAL, "no device dumps found in this dumpfile\n");

	return elf_base;
}

/*
 * extract hardware specific device dumps from coredump.
 */
void
kdump_device_dump_extract(int index, char *outfile, FILE *ofp)
{
	ulonglong offset;
	void *elf_base;

	if (!nd->num_vmcoredd_notes)
		error(FATAL, "no device dumps found in this dumpfile\n");
	else if (index >= nd->num_vmcoredd_notes)
		error(FATAL, "no device dump found at index: %d", index);

	elf_base = get_kdump_device_dump_offset();

	offset = nd->nt_vmcoredd_array[index] - elf_base;

	devdump_extract(nd->nt_vmcoredd_array[index], offset, outfile, ofp);
}

/*
 * list all hardware specific device dumps present in coredump.
 */
void kdump_device_dump_info(FILE *ofp)
{
	ulonglong offset;
	char buf[BUFSIZE];
	void *elf_base;
	ulong i;

	if (!nd->num_vmcoredd_notes)
		error(FATAL, "no device dumps found in this dumpfile\n");

	fprintf(fp, "%s ", mkstring(buf, strlen("INDEX"), LJUST, "INDEX"));
	fprintf(fp, " %s ", mkstring(buf, LONG_LONG_PRLEN, LJUST, "OFFSET"));
	fprintf(fp, "  %s ", mkstring(buf, LONG_PRLEN, LJUST, "SIZE"));
	fprintf(fp, "NAME\n");

	elf_base = get_kdump_device_dump_offset();

	for (i = 0; i < nd->num_vmcoredd_notes; i++) {
		fprintf(fp, "%s  ", mkstring(buf, strlen("INDEX"), CENTER | INT_DEC, MKSTR(i)));
		offset = nd->nt_vmcoredd_array[i] - elf_base;
		devdump_info(nd->nt_vmcoredd_array[i], offset, ofp);
	}
}
