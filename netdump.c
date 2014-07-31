/* netdump.c 
 *
 * Copyright (C) 2002-2014 David Anderson
 * Copyright (C) 2002-2014 Red Hat, Inc. All rights reserved.
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

static struct vmcore_data vmcore_data = { 0 };
static struct vmcore_data *nd = &vmcore_data;
static struct xen_kdump_data xen_kdump_data = { 0 };
static struct proc_kcore_data proc_kcore_data = { 0 };
static struct proc_kcore_data *pkd = &proc_kcore_data;
static void netdump_print(char *, ...);
static void dump_Elf32_Ehdr(Elf32_Ehdr *);
static void dump_Elf32_Phdr(Elf32_Phdr *, int);
static size_t dump_Elf32_Nhdr(Elf32_Off offset, int);
static void dump_Elf64_Ehdr(Elf64_Ehdr *);
static void dump_Elf64_Phdr(Elf64_Phdr *, int);
static size_t dump_Elf64_Nhdr(Elf64_Off offset, int);
static void get_netdump_regs_ppc(struct bt_info *, ulong *, ulong *);
static void get_netdump_regs_ppc64(struct bt_info *, ulong *, ulong *);
static void get_netdump_regs_arm(struct bt_info *, ulong *, ulong *);
static void get_netdump_regs_arm64(struct bt_info *, ulong *, ulong *);
static physaddr_t xen_kdump_p2m(physaddr_t);
static void check_dumpfile_size(char *);
static int proc_kcore_init_32(FILE *fp);
static int proc_kcore_init_64(FILE *fp);
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
		if (in_cpu_map(ONLINE_MAP, i))
			nd->nt_prstatus_percpu[i] = nt_ptr[j++];
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
	char eheader[MIN_NETDUMP_ELF_HEADER_SIZE];
	char buf[BUFSIZE];
	size_t size, len, tot;
        Elf32_Off offset32;
        Elf64_Off offset64;
	ulong tmp_flags;
	char *tmp_elf_header;

	if ((fd = open(file, O_RDWR)) < 0) {
        	if ((fd = open(file, O_RDONLY)) < 0) {
                        sprintf(buf, "%s: open", file);
                        perror(buf);
                        return FALSE;
		}
	}

	size = MIN_NETDUMP_ELF_HEADER_SIZE;

	if (FLAT_FORMAT()) {
		if (!read_flattened_format(fd, 0, eheader, size))
			goto bailout;
	} else {
		if (read(fd, eheader, size) != size) {
			sprintf(buf, "%s: read", file);
			perror(buf);
			goto bailout;
		}
	}

	load32 = NULL;
	load64 = NULL;
	tmp_flags = 0;
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

		default:
			if (machine_type_mismatch(file, "(unknown)", NULL,
			    source_query))
				goto bailout;
		}

		if (endian_mismatch(file, elf32->e_ident[EI_DATA], 
		    source_query))
			goto bailout;

                load32 = (Elf32_Phdr *)
                        &eheader[sizeof(Elf32_Ehdr)+sizeof(Elf32_Phdr)];
                size = (size_t)load32->p_offset;

		if ((load32->p_offset & (MIN_PAGE_SIZE-1)) ||
		    (load32->p_align == 0))
                	tmp_flags |= KDUMP_ELF32;
		else
                	tmp_flags |= NETDUMP_ELF32;
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

		default:
			if (machine_type_mismatch(file, "(unknown)", NULL,
			    source_query))
				goto bailout;
		}

		if (endian_mismatch(file, elf64->e_ident[EI_DATA], 
		    source_query))
			goto bailout;

                load64 = (Elf64_Phdr *)
                        &eheader[sizeof(Elf64_Ehdr)+sizeof(Elf64_Phdr)];
                size = (size_t)load64->p_offset;
		if ((load64->p_offset & (MIN_PAGE_SIZE-1)) ||
		    (load64->p_align == 0))
                	tmp_flags |= KDUMP_ELF64;
		else
                	tmp_flags |= NETDUMP_ELF64;
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

	switch (DUMPFILE_FORMAT(tmp_flags))
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

	if ((tmp_elf_header = (char *)malloc(size)) == NULL) {
		fprintf(stderr, "cannot malloc ELF header buffer\n");
		clean_exit(1);
	}

	if (FLAT_FORMAT()) {
		if (!read_flattened_format(fd, 0, tmp_elf_header, size)) {
			free(tmp_elf_header);
			goto bailout;
		}
	} else {
		if (lseek(fd, 0, SEEK_SET) != 0) {
			sprintf(buf, "%s: lseek", file);
			perror(buf);
			goto bailout;
		}
		if (read(fd, tmp_elf_header, size) != size) {
			sprintf(buf, "%s: read", file);
			perror(buf);
			free(tmp_elf_header);
			goto bailout;
		}
	}

	nd->ndfd = fd;
	nd->elf_header = tmp_elf_header;
	nd->flags = tmp_flags;
	nd->flags |= source_query;

	switch (DUMPFILE_FORMAT(nd->flags))
	{
	case NETDUMP_ELF32:
	case KDUMP_ELF32:
		nd->header_size = load32->p_offset;
        	nd->elf32 = (Elf32_Ehdr *)&nd->elf_header[0];
		nd->num_pt_load_segments = nd->elf32->e_phnum - 1;
		if ((nd->pt_load_segments = (struct pt_load_segment *)
		    malloc(sizeof(struct pt_load_segment) *
		    nd->num_pt_load_segments)) == NULL) {
			fprintf(stderr, "cannot malloc PT_LOAD segment buffers\n");
			clean_exit(1);
		}
        	nd->notes32 = (Elf32_Phdr *)
		    &nd->elf_header[sizeof(Elf32_Ehdr)];
        	nd->load32 = (Elf32_Phdr *)
		    &nd->elf_header[sizeof(Elf32_Ehdr)+sizeof(Elf32_Phdr)];
		if (DUMPFILE_FORMAT(nd->flags) == NETDUMP_ELF32)
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
                nd->header_size = load64->p_offset;
                nd->elf64 = (Elf64_Ehdr *)&nd->elf_header[0];
		nd->num_pt_load_segments = nd->elf64->e_phnum - 1;
                if ((nd->pt_load_segments = (struct pt_load_segment *)
                    malloc(sizeof(struct pt_load_segment) *
                    nd->num_pt_load_segments)) == NULL) {
                        fprintf(stderr, "cannot malloc PT_LOAD segment buffers\n");
                        clean_exit(1);
                }
                nd->notes64 = (Elf64_Phdr *)
                    &nd->elf_header[sizeof(Elf64_Ehdr)];
                nd->load64 = (Elf64_Phdr *)
                    &nd->elf_header[sizeof(Elf64_Ehdr)+sizeof(Elf64_Phdr)];
		if (DUMPFILE_FORMAT(nd->flags) == NETDUMP_ELF64)
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
	return FALSE;
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
		if (read(nd->ndfd, bufptr, cnt) != cnt) {
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
	netdump_print("            nt_prstatus: %lx\n", nd->nt_prstatus);
	netdump_print("            nt_prpsinfo: %lx\n", nd->nt_prpsinfo);
	netdump_print("          nt_taskstruct: %lx\n", nd->nt_taskstruct);
	netdump_print("            task_struct: %lx\n", nd->task_struct);
	netdump_print("              page_size: %d\n", nd->page_size);
	netdump_print("           switch_stack: %lx\n", nd->switch_stack);
	netdump_print("         xen_kdump_data: %s\n",
		XEN_CORE_DUMPFILE() ? " " : "(unused)");
	if (XEN_CORE_DUMPFILE()) {
		netdump_print("                    flags: %lx (", nd->xen_kdump_data->flags);
		others = 0;
        	if (nd->xen_kdump_data->flags & KDUMP_P2M_INIT)
                	netdump_print("%sKDUMP_P2M_INIT", others++ ? "|" : "");
        	if (nd->xen_kdump_data->flags & KDUMP_CR3)
                	netdump_print("%sKDUMP_CR3", others++ ? "|" : "");
        	if (nd->xen_kdump_data->flags & KDUMP_MFN_LIST)
                	netdump_print("%sKDUMP_MFN_LIST", others++ ? "|" : "");
		netdump_print(")\n");
		netdump_print("                  p2m_mfn: %lx\n", 
			nd->xen_kdump_data->p2m_mfn);
		netdump_print("                      cr3: %lx\n", 
			nd->xen_kdump_data->cr3);
		netdump_print("            last_mfn_read: %lx\n", 
			nd->xen_kdump_data->last_mfn_read);
		netdump_print("            last_pmd_read: %lx\n", 
			nd->xen_kdump_data->last_pmd_read);
		netdump_print("                     page: %lx\n", 
			nd->xen_kdump_data->page);
		netdump_print("                 accesses: %ld\n", 
			nd->xen_kdump_data->accesses);
		netdump_print("               cache_hits: %ld ", 
			nd->xen_kdump_data->cache_hits);
      		if (nd->xen_kdump_data->accesses)
                	netdump_print("(%ld%%)", 
			    nd->xen_kdump_data->cache_hits * 100 / nd->xen_kdump_data->accesses);
		netdump_print("\n               p2m_frames: %d\n", 
			nd->xen_kdump_data->p2m_frames);
		netdump_print("           xen_phys_start: %lx\n", 
			nd->xen_kdump_data->xen_phys_start);
		netdump_print("        xen_major_version: %d\n", 
			nd->xen_kdump_data->xen_major_version);
		netdump_print("        xen_minor_version: %d\n", 
			nd->xen_kdump_data->xen_minor_version);
		netdump_print("       p2m_mfn_frame_list: %lx\n", 
			nd->xen_kdump_data->p2m_mfn_frame_list);
		for (i = 0; i < nd->xen_kdump_data->p2m_frames; i++)
			netdump_print("%lx ", 
				nd->xen_kdump_data->p2m_mfn_frame_list[i]);
		if (i) netdump_print("\n");
	}
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
	char *vmcoreinfo = (char *)nd->vmcoreinfo;
	char *value = NULL;

	if (!nd->vmcoreinfo)
		return NULL;

	/* the '+ 1' is the equal sign */
	for (i = 0; i < (nd->size_vmcoreinfo - key_length + 1); i++) {
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
			     j < nd->size_vmcoreinfo; j++) {
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
				end = nd->size_vmcoreinfo + 1;
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

/*
 *  Dump a note section header -- the actual data is defined by netdump
 */

static size_t 
dump_Elf32_Nhdr(Elf32_Off offset, int store)
{
	int i, lf, words;
	Elf32_Nhdr *note;
	size_t len;
	char buf[BUFSIZE];
	char *ptr;
	ulong *uptr;
	int xen_core, vmcoreinfo, eraseinfo, qemuinfo;
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
			nd->switch_stack = *((ulong *)
				(ptr + note->n_namesz + sizeof(ulong)));
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
	default:
		xen_core = STRNEQ(buf, "XEN CORE") || STRNEQ(buf, "Xen");
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
		} else
			netdump_print("(?)\n");

		if (qemuinfo)
			pc->flags2 |= QEMU_MEM_DUMP;
		break;

	case NT_XEN_KDUMP_CR3: 
                netdump_print("(NT_XEN_KDUMP_CR3) [obsolete]\n");
		if (store)
			error(WARNING, 
			    "obsolete Xen n_type: %lx (NT_XEN_KDUMP_CR3)\n\n", 
				note->n_type);
		/* FALL THROUGH */

	case XEN_ELFNOTE_CRASH_INFO:
		/*
		 *  x86 and x86_64: p2m mfn appended to crash_xen_info_t structure
		 */
		if (note->n_type == XEN_ELFNOTE_CRASH_INFO)
                	netdump_print("(XEN_ELFNOTE_CRASH_INFO)\n");
		xen_core = TRUE;
		if (store) { 
			pc->flags |= XEN_CORE;
			nd->xen_kdump_data = &xen_kdump_data;
			nd->xen_kdump_data->last_mfn_read = UNINITIALIZED;
			nd->xen_kdump_data->last_pmd_read = UNINITIALIZED;

			if ((note->n_type == NT_XEN_KDUMP_CR3) &&
			    ((note->n_descsz/sizeof(ulong)) == 1)) {
				nd->xen_kdump_data->flags |= KDUMP_CR3;
				/*
				 *  Use the first cr3 found.
				 */
				if (!nd->xen_kdump_data->cr3) {
					uptr = (ulong *)(ptr + note->n_namesz);
					uptr = (ulong *)roundup((ulong)uptr, 4);
					nd->xen_kdump_data->cr3 = *uptr;
				}
			} else {
				nd->xen_kdump_data->flags |= KDUMP_MFN_LIST;
				uptr = (ulong *)(ptr + note->n_namesz);
				uptr = (ulong *)roundup((ulong)uptr, 4);
				words = note->n_descsz/sizeof(ulong);
				/*
				 *  If already set, overridden with --pfm_mfn
				 */
				if (!nd->xen_kdump_data->p2m_mfn)
					nd->xen_kdump_data->p2m_mfn = *(uptr+(words-1));
				if (words > 9 && !nd->xen_kdump_data->xen_phys_start)
					nd->xen_kdump_data->xen_phys_start = *(uptr+(words-2));
				nd->xen_kdump_data->xen_major_version = *uptr;
				nd->xen_kdump_data->xen_minor_version = *(uptr+1);
			}
		}
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
		for(i=0; i<NR_CPUS; i++) {
			if (!nd->nt_qemu_percpu[i]) {
				nd->nt_qemu_percpu[i] = (void *)uptr;
				nd->num_qemu_notes++;
				break;
			}
		}
	}

	if (vmcoreinfo || eraseinfo) {
                netdump_print("                         ");
                ptr += note->n_namesz + 1;
                for (i = 0; i < note->n_descsz; i++, ptr++) {
                        netdump_print("%c", *ptr);
                        if (*ptr == '\n')
                                netdump_print("                         ");
                }
                lf = 0;
	} else {
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
	int i, lf, words;
	Elf64_Nhdr *note;
	size_t len;
	char buf[BUFSIZE];
	char *ptr;
	ulonglong *uptr;
	int *iptr;
	ulong *up;
	int xen_core, vmcoreinfo, eraseinfo, qemuinfo;
	uint64_t remaining, notesize;

	note = (Elf64_Nhdr *)((char *)nd->elf64 + offset);

        BZERO(buf, BUFSIZE);
        ptr = (char *)note + sizeof(Elf64_Nhdr);
	xen_core = vmcoreinfo = eraseinfo = qemuinfo = FALSE;

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
	case NT_TASKSTRUCT:
		netdump_print("(NT_TASKSTRUCT)\n");
		if (STRNEQ(buf, "SNAP"))
			pc->flags2 |= LIVE_DUMP;
		if (store) {
			nd->nt_taskstruct = (void *)note;
			nd->task_struct = *((ulong *)(ptr + note->n_namesz));
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
	default:
		xen_core = STRNEQ(buf, "XEN CORE") || STRNEQ(buf, "Xen");
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
                } else
                        netdump_print("(?)\n");

		if (qemuinfo)
			pc->flags2 |= QEMU_MEM_DUMP;
                break;

	case NT_XEN_KDUMP_CR3: 
                netdump_print("(NT_XEN_KDUMP_CR3) [obsolete]\n");
               	if (store)
                	error(WARNING,
                            "obsolete Xen n_type: %lx (NT_XEN_KDUMP_CR3)\n\n",
                                note->n_type);
		/* FALL THROUGH */

	case XEN_ELFNOTE_CRASH_INFO:
		/*
		 *  x86 and x86_64: p2m mfn appended to crash_xen_info_t structure
		 */
		if (note->n_type == XEN_ELFNOTE_CRASH_INFO)
                	netdump_print("(XEN_ELFNOTE_CRASH_INFO)\n");
		xen_core = TRUE;
		if (store) {
			pc->flags |= XEN_CORE;
			nd->xen_kdump_data = &xen_kdump_data;
			nd->xen_kdump_data->last_mfn_read = UNINITIALIZED;
			nd->xen_kdump_data->last_pmd_read = UNINITIALIZED;

			if ((note->n_type == NT_XEN_KDUMP_CR3) &&
			    ((note->n_descsz/sizeof(ulong)) == 1)) {
				nd->xen_kdump_data->flags |= KDUMP_CR3;
	                        /*
	                         *  Use the first cr3 found.
	                         */
	                        if (!nd->xen_kdump_data->cr3) {
					up = (ulong *)(ptr + note->n_namesz);
	                                up = (ulong *)roundup((ulong)up, 4);
	                                nd->xen_kdump_data->cr3 = *up;
	                        }
			} else {
				nd->xen_kdump_data->flags |= KDUMP_MFN_LIST;
				up = (ulong *)(ptr + note->n_namesz);
	                        up = (ulong *)roundup((ulong)up, 4);
				words = note->n_descsz/sizeof(ulong);
				/*
				 *  If already set, overridden with --p2m_mfn
				 */
	                        if (!nd->xen_kdump_data->p2m_mfn)
	                        	nd->xen_kdump_data->p2m_mfn = *(up+(words-1));
				if (words > 9 && !nd->xen_kdump_data->xen_phys_start)
					nd->xen_kdump_data->xen_phys_start = *(up+(words-2));
				nd->xen_kdump_data->xen_major_version = *up;
				nd->xen_kdump_data->xen_minor_version = *(up+1);
			}
		}
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

	if (BITS32() && (xen_core || (note->n_type == NT_PRSTATUS))) {
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
	} else if (vmcoreinfo || eraseinfo) {
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

static void
display_regs_from_elf_notes(int cpu)
{
	Elf32_Nhdr *note32;
	Elf64_Nhdr *note64;
	size_t len;
	char *user_regs;

	if (cpu >= nd->num_prstatus_notes) {
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

		fprintf(fp,
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

		fprintf(fp,
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
	} else if (machine_type("ARM64")) {
		if (nd->num_prstatus_notes > 1)
                	note64 = (Elf64_Nhdr *)
				nd->nt_prstatus_percpu[cpu];
		else
                	note64 = (Elf64_Nhdr *)nd->nt_prstatus;
		len = sizeof(Elf64_Nhdr);
		len = roundup(len + note64->n_namesz, 4);
		len = roundup(len + note64->n_descsz, 4);
//		user_regs = ((char *)note64) + len - SIZE(user_regs_struct) - sizeof(long);
		fprintf(fp, "display_regs_from_elf_notes: ARM64 register dump TBD\n");
	}
}

void
dump_registers_for_elf_dumpfiles(void)
{
        int c;

        if (!(machine_type("X86") || machine_type("X86_64") || machine_type("ARM64")))
                error(FATAL, "-r option not supported for this dumpfile\n");

	if (NETDUMP_DUMPFILE()) {
                display_regs_from_elf_notes(0);
		return;
	}

        for (c = 0; c < kt->cpus; c++) {
                fprintf(fp, "%sCPU %d:\n", c ? "\n" : "", c);
                display_regs_from_elf_notes(c);
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
   	      VALID_STRUCT(user_regs_struct) && (bt->task == tt->panic_task)) ||
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
get_netdump_regs_ppc(struct bt_info *bt, ulong *eip, ulong *esp)
{
	Elf32_Nhdr *note;
	size_t len;

	ppc_relocate_nt_prstatus_percpu(nd->nt_prstatus_percpu,
					&nd->num_prstatus_notes);

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
	    	if (!(nd->xen_kdump_data->flags & KDUMP_P2M_INIT)) {
        		if (!machdep->xen_kdump_p2m_create)
                		error(FATAL,
                            "xen kdump dumpfiles not supported on this architecture\n");

			if ((nd->xen_kdump_data->page = 
			    (char *)malloc(PAGESIZE())) == NULL)
				error(FATAL,
				    "cannot malloc xen kdump data page\n");

			if (!machdep->xen_kdump_p2m_create(nd->xen_kdump_data))
                		error(FATAL,
                    	    "cannot create xen kdump pfn-to-mfn mapping\n");

        		nd->xen_kdump_data->flags |= KDUMP_P2M_INIT;
		}

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

/*
 *  Translate a xen domain's pseudo-physical address into the
 *  xen machine address.  Since there's no compression involved,
 *  just the last phys_to_machine_mapping[] page read is cached, 
 *  which essentially caches 1024 p2m translations. 
 */
static physaddr_t 
xen_kdump_p2m(physaddr_t pseudo)
{
	ulong pfn, mfn_frame; 
	ulong *mfnptr;
	ulong mfn_idx, frame_idx;
	physaddr_t paddr;
	struct xen_kdump_data *xkd = nd->xen_kdump_data;

	if (pc->curcmd_flags & XEN_MACHINE_ADDR)
		return pseudo;

#ifdef IA64
	return ia64_xen_kdump_p2m(xkd, pseudo);
#endif

	xkd->accesses++;

	pfn = (ulong)BTOP(pseudo);
	mfn_idx = pfn / (PAGESIZE()/sizeof(ulong));
	frame_idx = pfn % (PAGESIZE()/sizeof(ulong));
	if (mfn_idx >= xkd->p2m_frames) {
		if (CRASHDEBUG(8))
			fprintf(fp, "xen_kdump_p2m: paddr/pfn: %llx/%lx: "
			    "mfn_idx nonexistent\n",
				(ulonglong)pseudo, pfn);
		return P2M_FAILURE;
	}
	mfn_frame = xkd->p2m_mfn_frame_list[mfn_idx];

	if (mfn_frame == xkd->last_mfn_read)
		xkd->cache_hits++;
	else {
		if (CRASHDEBUG(8))
			fprintf(fp, "xen_kdump_p2m: paddr/pfn: %llx/%lx: "
			    "read mfn_frame: %llx\n",
				(ulonglong)pseudo, pfn, PTOB(mfn_frame));
		if (read_netdump(0, xkd->page, PAGESIZE(), 0, 
		    (physaddr_t)PTOB(mfn_frame)) != PAGESIZE())
			return P2M_FAILURE;
	}

	xkd->last_mfn_read = mfn_frame;

	mfnptr = ((ulong *)(xkd->page)) + frame_idx;
	paddr = (physaddr_t)PTOB((ulonglong)(*mfnptr));  
	paddr |= PAGEOFFSET(pseudo);

	if (CRASHDEBUG(7))
		fprintf(fp, 
		    "xen_kdump_p2m(%llx): mfn_idx: %ld frame_idx: %ld"
		    " mfn_frame: %lx mfn: %lx => %llx\n",
			(ulonglong)pseudo, mfn_idx, frame_idx, 
			mfn_frame, *mfnptr, (ulonglong)paddr);
	
	return paddr;
}

struct vmcore_data *
get_kdump_vmcore_data(void)
{
	if (!VMCORE_VALID() || !KDUMP_DUMPFILE())
		return NULL;

	return &vmcore_data;
}

/*
 *  Override the dom0 p2m mfn in the XEN_ELFNOTE_CRASH_INFO note
 *  in order to initiate a crash session of a guest kernel.
 */
void
xen_kdump_p2m_mfn(char *arg)
{
	ulong value;
	int errflag;

	errflag = 0;
	value = htol(arg, RETURN_ON_ERROR|QUIET, &errflag);
	if (!errflag) {
		xen_kdump_data.p2m_mfn = value;
		if (CRASHDEBUG(1))
			error(INFO, 
			    "xen_kdump_data.p2m_mfn override: %lx\n",  
				value); 
	} else 
		error(WARNING, "invalid p2m_mfn argument: %s\n", arg);
}

/*
 *  Fujitsu dom0/HV sadump-generated dumpfile, which requires
 *  the --p2m_mfn command line argument.
 */
int
is_sadump_xen(void)
{
	if (xen_kdump_data.p2m_mfn) {
		if (!XEN_CORE_DUMPFILE()) {
			pc->flags |= XEN_CORE;
			nd->xen_kdump_data = &xen_kdump_data;
			nd->xen_kdump_data->last_mfn_read = UNINITIALIZED;
			nd->xen_kdump_data->last_pmd_read = UNINITIALIZED;
			nd->xen_kdump_data->flags |= KDUMP_MFN_LIST;
		}
		return TRUE;
	}

	return FALSE;
}

void
set_xen_phys_start(char *arg)
{
	ulong value;
	int errflag = 0;

	value = htol(arg, RETURN_ON_ERROR|QUIET, &errflag);
	if (!errflag)
		xen_kdump_data.xen_phys_start = value;
	else 
		error(WARNING, "invalid xen_phys_start argument: %s\n", arg);
}

ulong
xen_phys_start(void)
{
	return nd->xen_kdump_data->xen_phys_start;
}

int
xen_major_version(void)
{
	return nd->xen_kdump_data->xen_major_version;
}

int
xen_minor_version(void)
{
	return nd->xen_kdump_data->xen_minor_version;
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
	int i; 
	size_t readcnt;
	ulong kvaddr;
	Elf32_Phdr *lp32;
	Elf64_Phdr *lp64;
	off_t offset;

	if (!machdep->verify_paddr(paddr)) {
		if (CRASHDEBUG(1))
			error(INFO, "verify_paddr(%lx) failed\n", paddr);
		return READ_ERROR;
	}

	/*
	 *  Turn the physical address into a unity-mapped kernel 
	 *  virtual address, which should work for 64-bit architectures,
	 *  and for lowmem access for 32-bit architectures.
	 */
	offset = UNINITIALIZED;
	if (machine_type("ARM64"))
		kvaddr =  PTOV((ulong)paddr);
	else
		kvaddr = (ulong)paddr | machdep->kvbase;
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

        if (lseek(fd, offset, SEEK_SET) != offset)
		perror("lseek");

	if (read(fd, bufptr, readcnt) != readcnt)
		return READ_ERROR;

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
proc_kcore_init(FILE *fp)
{
	if (BITS32())
		return proc_kcore_init_32(fp);
	else 
		return proc_kcore_init_64(fp);
}

static int
proc_kcore_init_32(FILE *fp)
{
	Elf32_Ehdr *elf32;
	Elf32_Phdr *load32;
	char eheader[MAX_KCORE_ELF_HEADER_SIZE];
	char buf[BUFSIZE];
	size_t size;

	size = MAX_KCORE_ELF_HEADER_SIZE;

	if (read(pc->mfd, eheader, size) != size) {
		sprintf(buf, "/proc/kcore: read");
		perror(buf);
		goto bailout;
	}

	if (lseek(pc->mfd, 0, SEEK_SET) != 0) {
		sprintf(buf, "/proc/kcore: lseek");
		perror(buf);
		goto bailout;
	}

	elf32 = (Elf32_Ehdr *)&eheader[0];
	load32 = (Elf32_Phdr *)&eheader[sizeof(Elf32_Ehdr)+sizeof(Elf32_Phdr)];

	pkd->segments = elf32->e_phnum - 1;

	size = (ulong)(load32+(elf32->e_phnum)) - (ulong)elf32;
	if ((pkd->elf_header = (char *)malloc(size)) == NULL) {
		error(INFO, "/proc/kcore: cannot malloc ELF header buffer\n");
		clean_exit(1);
	}

	BCOPY(&eheader[0], &pkd->elf_header[0], size);	
	pkd->elf32 = (Elf32_Ehdr *)pkd->elf_header;
	pkd->load32 = (Elf32_Phdr *)
		&pkd->elf_header[sizeof(Elf32_Ehdr)+sizeof(Elf32_Phdr)];
	pkd->flags |= KCORE_ELF32;
	
	if (CRASHDEBUG(1))
		kcore_memory_dump(fp);

	return TRUE;
bailout:
	return FALSE;
}

static int
proc_kcore_init_64(FILE *fp)
{
	Elf64_Ehdr *elf64;
	Elf64_Phdr *load64;
	char eheader[MAX_KCORE_ELF_HEADER_SIZE];
	char buf[BUFSIZE];
	size_t size;

	size = MAX_KCORE_ELF_HEADER_SIZE;

	if (read(pc->mfd, eheader, size) != size) {
		sprintf(buf, "/proc/kcore: read");
		perror(buf);
		goto bailout;
	}

	if (lseek(pc->mfd, 0, SEEK_SET) != 0) {
		sprintf(buf, "/proc/kcore: lseek");
		perror(buf);
		goto bailout;
	}

	elf64 = (Elf64_Ehdr *)&eheader[0];
	load64 = (Elf64_Phdr *)&eheader[sizeof(Elf64_Ehdr)+sizeof(Elf64_Phdr)];

	pkd->segments = elf64->e_phnum - 1;

	size = (ulong)(load64+(elf64->e_phnum)) - (ulong)elf64;
	if ((pkd->elf_header = (char *)malloc(size)) == NULL) {
		error(INFO, "/proc/kcore: cannot malloc ELF header buffer\n");
		clean_exit(1);
	}

	BCOPY(&eheader[0], &pkd->elf_header[0], size);	
	pkd->elf64 = (Elf64_Ehdr *)pkd->elf_header;
	pkd->load64 = (Elf64_Phdr *)
		&pkd->elf_header[sizeof(Elf64_Ehdr)+sizeof(Elf64_Phdr)];
	pkd->flags |= KCORE_ELF64;
	
	if (CRASHDEBUG(1))
		kcore_memory_dump(fp);

	return TRUE;
bailout:
	return FALSE;
}

int
kcore_memory_dump(FILE *ofp)
{
	int i, others;
	Elf32_Phdr *lp32;
	Elf64_Phdr *lp64;

	if (!(pkd->flags & KCORE_LOCAL))
		return FALSE;

	fprintf(ofp, "proc_kcore_data:\n");
	fprintf(ofp, "       flags: %lx (", nd->flags);
	others = 0;
	if (pkd->flags & KCORE_LOCAL)
		fprintf(ofp, "%sKCORE_LOCAL", others++ ? "|" : "");
	if (pkd->flags & KCORE_ELF32)
		fprintf(ofp, "%sKCORE_ELF32", others++ ? "|" : "");
	if (pkd->flags & KCORE_ELF64)
		fprintf(ofp, "%sKCORE_ELF64", others++ ? "|" : "");
	fprintf(ofp, ")\n");
	fprintf(ofp, "    segments: %d\n",
		pkd->segments);
	fprintf(ofp, "  elf_header: %lx\n", (ulong)pkd->elf_header);
	fprintf(ofp, "       elf64: %lx\n", (ulong)pkd->elf64);
	fprintf(ofp, "      load64: %lx\n", (ulong)pkd->load64);
	fprintf(ofp, "       elf32: %lx\n", (ulong)pkd->elf32);
	fprintf(ofp, "      load32: %lx\n\n", (ulong)pkd->load32);

	for (i = 0; i < pkd->segments; i++) {
		if (pkd->flags & KCORE_ELF32)
			break;

		lp64 = pkd->load64 + i;

		fprintf(ofp, "  Elf64_Phdr:\n");
		fprintf(ofp, "        p_type: %x\n", lp64->p_type);
		fprintf(ofp, "       p_flags: %x\n", lp64->p_flags);
		fprintf(ofp, "      p_offset: %llx\n", (ulonglong)lp64->p_offset);
		fprintf(ofp, "       p_vaddr: %llx\n", (ulonglong)lp64->p_vaddr);
		fprintf(ofp, "       p_paddr: %llx\n", (ulonglong)lp64->p_paddr);
		fprintf(ofp, "      p_filesz: %llx\n", (ulonglong)lp64->p_filesz);
		fprintf(ofp, "       p_memsz: %llx\n", (ulonglong)lp64->p_memsz);
		fprintf(ofp, "       p_align: %lld\n", (ulonglong)lp64->p_align);
		fprintf(ofp, "\n");
	}

	for (i = 0; i < pkd->segments; i++) {
		if (pkd->flags & KCORE_ELF64)
			break;

		lp32 = pkd->load32 + i;

		fprintf(ofp, "  Elf32_Phdr:\n");
		fprintf(ofp, "        p_type: %x\n", lp32->p_type);
		fprintf(ofp, "       p_flags: %x\n", lp32->p_flags);
		fprintf(ofp, "      p_offset: %x\n", lp32->p_offset);
		fprintf(ofp, "       p_vaddr: %x\n", lp32->p_vaddr);
		fprintf(ofp, "       p_paddr: %x\n", lp32->p_paddr);
		fprintf(ofp, "      p_filesz: %x\n", lp32->p_filesz);
		fprintf(ofp, "       p_memsz: %x\n", lp32->p_memsz);
		fprintf(ofp, "       p_align: %d\n", lp32->p_align);
		fprintf(ofp, "\n");
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

	for (i=0; i<nd->num_qemu_notes; i++) {
		ptr = (QEMUCPUState *)nd->nt_qemu_percpu[i];

		if (i)
			netdump_print("\n");
		netdump_print("CPU %d:\n", i);

		if (CRASHDEBUG(1))
			netdump_print("  version:%08lx      size:%08lx\n",
				ptr->version, ptr->size);
		netdump_print("  rax:%016llx  rbx:%016llx  rcx:%016llx\n",
			ptr->rax, ptr->rbx, ptr->rcx);
		netdump_print("  rdx:%016llx  rsi:%016llx  rdi:%016llx\n",
			ptr->rdx, ptr->rsi, ptr->rdi);
		netdump_print("  rsp:%016llx  rbp:%016llx  ",
			ptr->rsp, ptr->rbp);
	
		if (DUMPFILE_FORMAT(nd->flags) == KDUMP_ELF64) {
			netdump_print(" r8:%016llx\n",
				ptr->r8);
			netdump_print("   r9:%016llx  r10:%016llx  r11:%016llx\n",
				ptr->r9, ptr->r10, ptr->r11);
			netdump_print("  r12:%016llx  r13:%016llx  r14:%016llx\n",
				ptr->r12, ptr->r13, ptr->r14);
			netdump_print("  r15:%016llx",
				ptr->r15);
		} else
                        netdump_print("\n");

		netdump_print("  rip:%016llx  rflags:%08llx\n",
			ptr->rip, ptr->rflags);
		netdump_print("  cs:\n    selector:%08lx  limit:%08lx  flags:%08lx\n\
    pad:%08lx  base:%016llx\n",
			ptr->cs.selector, ptr->cs.limit, ptr->cs.flags,
			ptr->cs.pad, ptr->cs.base);
		netdump_print("  ds:\n    selector:%08lx  limit:%08lx  flags:%08lx\n\
    pad:%08lx  base:%016llx\n",
			ptr->ds.selector, ptr->ds.limit, ptr->ds.flags,
			ptr->ds.pad, ptr->ds.base);
		netdump_print("  es:\n    selector:%08lx  limit:%08lx  flags:%08lx\n\
    pad:%08lx  base:%016llx\n",
			ptr->es.selector, ptr->es.limit, ptr->es.flags,
			ptr->es.pad, ptr->es.base);
		netdump_print("  fs:\n    selector:%08lx  limit:%08lx  flags:%08lx\n\
    pad:%08lx  base:%016llx\n",
			ptr->fs.selector, ptr->fs.limit, ptr->fs.flags,
			ptr->fs.pad, ptr->fs.base);
		netdump_print("  gs:\n    selector:%08lx  limit:%08lx  flags:%08lx\n\
    pad:%08lx  base:%016llx\n",
			ptr->gs.selector, ptr->gs.limit, ptr->gs.flags,
			ptr->gs.pad, ptr->gs.base);
		netdump_print("  ss:\n    selector:%08lx  limit:%08lx  flags:%08lx\n\
    pad:%08lx  base:%016llx\n",
			ptr->ss.selector, ptr->ss.limit, ptr->ss.flags,
			ptr->ss.pad, ptr->ss.base);
		netdump_print("  ldt:\n    selector:%08lx  limit:%08lx  flags:%08lx\n\
    pad:%08lx  base:%016llx\n",
			ptr->ldt.selector, ptr->ldt.limit, ptr->ldt.flags,
			ptr->ldt.pad, ptr->ldt.base);
		netdump_print("  tr:\n    selector:%08lx  limit:%08lx  flags:%08lx\n\
    pad:%08lx  base:%016llx\n",
			ptr->tr.selector, ptr->tr.limit, ptr->tr.flags,
			ptr->tr.pad, ptr->tr.base);
		netdump_print("  gdt:\n    selector:%08lx  limit:%08lx  flags:%08lx\n\
    pad:%08lx  base:%016llx\n",
			ptr->gdt.selector, ptr->gdt.limit, ptr->gdt.flags,
			ptr->gdt.pad, ptr->gdt.base);
		netdump_print("  idt:\n    selector:%08lx  limit:%08lx  flags:%08lx\n\
    pad:%08lx  base:%016llx\n",
			ptr->idt.selector, ptr->idt.limit, ptr->idt.flags,
			ptr->idt.pad, ptr->idt.base);
		netdump_print("  cr[0]:%016llx  cr[1]:%016llx  cr[2]:%016llx\n",
			ptr->cr[0], ptr->cr[1], ptr->cr[2]);
		netdump_print("  cr[3]:%016llx  cr[4]:%016llx\n",
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
	} else if (pc->flags2 & QEMU_MEM_DUMP) {
		vd = get_kdump_vmcore_data();
		if (vd->flags & KDUMP_ELF32)
			is_32_bit = TRUE;
		else
			is_32_bit = FALSE;
		sprintf(typename, "qemu mem dump");
	} else
		return;

	if (!readmem(symbol_value("kexec_crash_image"), KVADDR,
		     &kexec_crash_image_p, sizeof(ulong),
		     "kexec backup region: kexec_crash_image",
		     QUIET|RETURN_ON_ERROR))
		goto error;

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
				} else if (pc->flags2 & QEMU_MEM_DUMP) {
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
