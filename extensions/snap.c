/* snap.c - capture live memory into a kdump or netdump dumpfile
 *
 * Copyright (C) 2009, 2013, 2014, 2017 David Anderson
 * Copyright (C) 2009, 2013, 2014, 2017 Red Hat, Inc. All rights reserved.
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
#include <sys/time.h>
#include <linux/types.h>
#include <elf.h>

void snap_init(void);
void snap_fini(void);

void cmd_snap(void);     
char *help_snap[];

static struct command_table_entry command_table[] = {
	{ "snap", cmd_snap, help_snap, 0 },    
	{ NULL }                               
};

static char *generate_elf_header(int, int, char *);
static int verify_paddr(physaddr_t);
static void init_ram_segments(void);
static int print_progress(const char *, ulong);

#if defined(X86) || defined(X86_64) || defined(IA64) || defined(PPC64) || defined(ARM64)
int supported = TRUE;
#else
int supported = FALSE;
#endif

void __attribute__((constructor)) 
snap_init(void) /* Register the command set. */
{ 
        register_extension(command_table);
}
 
void __attribute__((destructor))
snap_fini(void) 
{ 
}


/* 
 *  Just pass in an unused filename.
 */
void
cmd_snap(void)
{
        int c, fd, n;
	physaddr_t paddr;
	size_t offset;
	char *buf;
	char *filename;
	struct node_table *nt;
	int type;
	char *elf_header;
	Elf64_Phdr *load;
	int load_index;

	if (!supported)
		error(FATAL, "command not supported on the %s architecture\n",
			pc->machine_type);

	filename = NULL;
	buf = GETBUF(PAGESIZE()); 
	type = KDUMP_ELF64;

        while ((c = getopt(argcnt, args, "n")) != EOF) {
                switch(c)
                {
		case 'n':
			if (machine_type("X86_64"))
				option_not_supported('n');
			else
				type = NETDUMP_ELF64;
			break;
                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs || !args[optind])
                cmd_usage(pc->curcmd, SYNOPSIS);

	while (args[optind]) {
		if (filename)
                	cmd_usage(pc->curcmd, SYNOPSIS);

		if (file_exists(args[optind], NULL))
			error(FATAL, "%s: file already exists\n", args[optind]);
		else if ((fd = open(args[optind], O_RDWR|O_CREAT, 0644)) < 0)
			error(FATAL, args[optind]);

		filename = args[optind];
		optind++;
	}

	if (!filename)
                cmd_usage(pc->curcmd, SYNOPSIS);

	init_ram_segments();

	if (!(elf_header = generate_elf_header(type, fd, filename)))
		error(FATAL, "cannot generate ELF header\n");

	load = (Elf64_Phdr *)(elf_header + sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr));
	load_index = machine_type("X86_64") || machine_type("IA64") ? 1 : 0;

	for (n = 0; n < vt->numnodes; n++) {
		nt = &vt->node_table[n];
		paddr = nt->start_paddr;
		offset = load[load_index + n].p_offset;

		for (c = 0; c < nt->size; c++, paddr += PAGESIZE()) {
			if (!verify_paddr(paddr))
				continue;
			if (!readmem(paddr, PHYSADDR, &buf[0], PAGESIZE(), 
			    "memory page", QUIET|RETURN_ON_ERROR))
				continue;

			lseek(fd, (off_t)(paddr + offset - nt->start_paddr), SEEK_SET);
			if (write(fd, &buf[0], PAGESIZE()) != PAGESIZE())
				error(FATAL, "write to dumpfile failed\n");

			if (!print_progress(filename, BTOP(paddr)))
				return;
		}
	}

        fprintf(stderr, "\r%s: [100%%] ", filename);
	fprintf(fp, "\n");
	sprintf(buf, "/bin/ls -l %s\n", filename);
	system(buf);

	FREEBUF(elf_header);
	FREEBUF(buf);
}


char *help_snap[] = {
        "snap",                     /* command name */
        "take a memory snapshot",   /* short description */
        "[-n] dumpfile",            /* filename */
 
        "  This command takes a snapshot of physical memory and creates an ELF vmcore.",
	"  The default vmcore is a kdump-style dumpfile.  Supported on x86, x86_64,",
	"  ia64 and ppc64 architectures only.",
	" ",
	"    -n  create a netdump-style vmcore (n/a on x86_64).",
        NULL
};

/*
 *  Architecture-specific and -generic ELF header data borrowed from the
 *  netdump.h file in the netdump package, modified slightly to also create
 *  a kdump-style vmcore.
 */ 

/******************************************************************************
 *                       Elf core dumping                                     *
 ******************************************************************************/

/*
 *  Host-platform independent data 
 */
#define ELF_PRARGSZ	(80)	/* Number of chars for args */
struct elf_prpsinfo_64
{
        char    pr_state;       /* numeric process state */
        char    pr_sname;       /* char for pr_state */
        char    pr_zomb;        /* zombie */
        char    pr_nice;        /* nice val */
        __u64   pr_flag;        /* flags */
        __u32   pr_uid;
        __u32   pr_gid;
        __u32   pr_pid, pr_ppid, pr_pgrp, pr_sid;
        /* Lots missing */
        char    pr_fname[16];   /* filename of executable */
        char    pr_psargs[ELF_PRARGSZ]; /* initial part of arg list */
};

/*
 *  i386 specific 
 */
struct user_regs_struct_i386 {
        __u32 ebx, ecx, edx, esi, edi, ebp, eax;
        __u16 ds, __ds, es, __es;
        __u16 fs, __fs, gs, __gs;
        __u32 orig_eax, eip;
        __u16 cs, __cs;
        __u32 eflags, esp;
        __u16 ss, __ss;
};

#define ELF_NGREG_I386 (sizeof (struct user_regs_struct_i386) / sizeof(__u32))
typedef __u32 elf_gregset_i386_t[ELF_NGREG_I386];

struct elf_prstatus_i386 {
	char pad[72];
	elf_gregset_i386_t pr_reg;	/* GP registers */
	__u32 pr_fpvalid;		/* True if math co-processor being used.  */
};

/* 
 *  x86_64 specific
 */
struct user_regs_struct_x86_64 {
        __u64 r15,r14,r13,r12,rbp,rbx,r11,r10;
        __u64 r9,r8,rax,rcx,rdx,rsi,rdi,orig_rax;
        __u64 rip,cs,eflags;
        __u64 rsp,ss;
        __u64 fs_base, gs_base;
        __u64 ds,es,fs,gs;
};

#define ELF_NGREG_X86_64 (sizeof (struct user_regs_struct_x86_64) / sizeof(__u64))
typedef __u64 elf_gregset_x86_64_t[ELF_NGREG_X86_64];

struct elf_prstatus_x86_64 {
        char pad[112];
        elf_gregset_x86_64_t pr_reg;      /* GP registers */
        __u32 pr_fpvalid;         	  /* True if math co-processor being used.  */
};

/*
 *  ppc64 specific
 */ 
struct user_regs_struct_ppc64 {
        __u64 gpr[32];
	__u64 nip;
	__u64 msr;
	__u64 orig_gpr3;
	__u64 ctr;
	__u64 link;
        __u64 xer;
	__u64 ccr;
	__u64 softe;
	__u64 trap;
	__u64 dar;
	__u64 dsisr;
	__u64 result;
};

#define ELF_NGREG_PPC64 (sizeof (struct user_regs_struct_ppc64) / sizeof(__u64))
typedef __u64 elf_gregset_ppc64_t[ELF_NGREG_PPC64];

struct elf_prstatus_ppc64 {
        char pad[112];
        elf_gregset_ppc64_t pr_reg;       /* GP registers */
        __u32 pr_fpvalid;         	  /* True if math co-processor being used.  */
};

/*
 *  ia64 specific
 */ 
struct _ia64_fpreg {
        union {
                __u64 bits[2];
        } u;
} __attribute__ ((aligned (16)));

struct user_regs_struct_ia64 {
	/* The following registers are saved by SAVE_MIN: */
	__u64 b6;		/* scratch */
	__u64 b7;		/* scratch */

	__u64 ar_csd;           /* used by cmp8xchg16 (scratch) */
	__u64 ar_ssd;           /* reserved for future use (scratch) */

	__u64 r8;		/* scratch (return value register 0) */
	__u64 r9;		/* scratch (return value register 1) */
	__u64 r10;		/* scratch (return value register 2) */
	__u64 r11;		/* scratch (return value register 3) */

	__u64 cr_ipsr;		/* interrupted task's psr */
	__u64 cr_iip;		/* interrupted task's instruction pointer */
	__u64 cr_ifs;		/* interrupted task's function state */

	__u64 ar_unat;		/* interrupted task's NaT register (preserved) */
	__u64 ar_pfs;		/* prev function state  */
	__u64 ar_rsc;		/* RSE configuration */
	/* The following two are valid only if cr_ipsr.cpl > 0: */
	__u64 ar_rnat;		/* RSE NaT */
	__u64 ar_bspstore;	/* RSE bspstore */

	__u64 pr;		/* 64 predicate registers (1 bit each) */
	__u64 b0;		/* return pointer (bp) */
	__u64 loadrs;		/* size of dirty partition << 16 */

	__u64 r1;		/* the gp pointer */
	__u64 r12;		/* interrupted task's memory stack pointer */
	__u64 r13;		/* thread pointer */

	__u64 ar_fpsr;		/* floating point status (preserved) */
	__u64 r15;		/* scratch */

	/* The remaining registers are NOT saved for system calls.  */

	__u64 r14;		/* scratch */
	__u64 r2;		/* scratch */
	__u64 r3;		/* scratch */

	/* The following registers are saved by SAVE_REST: */
	__u64 r16;		/* scratch */
	__u64 r17;		/* scratch */
	__u64 r18;		/* scratch */
	__u64 r19;		/* scratch */
	__u64 r20;		/* scratch */
	__u64 r21;		/* scratch */
	__u64 r22;		/* scratch */
	__u64 r23;		/* scratch */
	__u64 r24;		/* scratch */
	__u64 r25;		/* scratch */
	__u64 r26;		/* scratch */
	__u64 r27;		/* scratch */
	__u64 r28;		/* scratch */
	__u64 r29;		/* scratch */
	__u64 r30;		/* scratch */
	__u64 r31;		/* scratch */

	__u64 ar_ccv;		/* compare/exchange value (scratch) */

	/*
	 * Floating point registers that the kernel considers scratch:
	 */
	struct _ia64_fpreg f6;		/* scratch */
	struct _ia64_fpreg f7;		/* scratch */
	struct _ia64_fpreg f8;		/* scratch */
	struct _ia64_fpreg f9;		/* scratch */
	struct _ia64_fpreg f10;		/* scratch */
	struct _ia64_fpreg f11;		/* scratch */
};

#define ELF_NGREG_IA64 (sizeof (struct user_regs_struct_ia64) / sizeof(__u64))
typedef __u64 elf_gregset_ia64_t[ELF_NGREG_IA64];

struct elf_prstatus_ia64 {
        char pad[112];
        elf_gregset_ia64_t pr_reg;       /* GP registers */
        __u32 pr_fpvalid;         	  /* True if math co-processor being used.  */
};

/*
 *  arm64 specific
 */

struct user_pt_regs_arm64 {
        __u64           regs[31];
        __u64           sp;
        __u64           pc;
        __u64           pstate;
};

#define ELF_NGREG_ARM64 (sizeof (struct user_pt_regs_arm64) / sizeof(elf_greg_t))
#ifndef elf_greg_t
typedef unsigned long elf_greg_t;
#endif
typedef elf_greg_t elf_gregset_arm64_t[ELF_NGREG_ARM64];

struct elf_prstatus_arm64 {
        char pad[112];
	elf_gregset_arm64_t pr_reg;
	int pr_fpvalid;
};


union prstatus {
	struct elf_prstatus_i386 x86; 
	struct elf_prstatus_x86_64 x86_64; 
	struct elf_prstatus_ppc64 ppc64;
	struct elf_prstatus_ia64 ia64;
	struct elf_prstatus_arm64 arm64;
};

static size_t
dump_elf_note(char *buf, Elf64_Word type, char *name, char *desc, int d_len)
{
	Elf64_Nhdr *note;
	size_t len;

	note = (Elf64_Nhdr *)buf;
	note->n_namesz = strlen(name);
	note->n_descsz = d_len;
	note->n_type = type;
	len = sizeof(Elf64_Nhdr);

	memcpy(buf + len, name, note->n_namesz);
	len = roundup(len + note->n_namesz, 4);

	memcpy(buf + len, desc, note->n_descsz);
	len = roundup(len + note->n_descsz, 4);

	return len;
}

char *
generate_elf_header(int type, int fd, char *filename)
{
	int i, n;
	char *buffer, *ptr;
	Elf64_Ehdr *elf;
	Elf64_Phdr *notes;
	Elf64_Phdr *load;
	size_t offset, len, l_offset;
	size_t data_offset;
	struct elf_prpsinfo_64 prpsinfo;
	union prstatus prstatus;
	int prstatus_len;
	ushort e_machine;
	int num_segments;
	struct node_table *nt;
	struct SNAP_info {
		ulonglong task_struct;
		ulonglong arch_data1;
		ulonglong arch_data2;
	} SNAP_info;

	num_segments = vt->numnodes;

	if (machine_type("X86_64")) {
		e_machine = EM_X86_64;
		prstatus_len = sizeof(prstatus.x86_64);
		num_segments += 1;  /* mapped kernel section for phys_base */
	} else if (machine_type("X86")) {
		e_machine = EM_386;
		prstatus_len = sizeof(prstatus.x86);
	} else if (machine_type("IA64")) {
		e_machine = EM_IA_64;
		prstatus_len = sizeof(prstatus.ia64);
		num_segments += 1;  /* mapped kernel section for phys_start */
	} else if (machine_type("PPC64")) {
		e_machine = EM_PPC64;
		prstatus_len = sizeof(prstatus.ppc64);
	} else if (machine_type("ARM64")) {
		e_machine = EM_AARCH64;
		prstatus_len = sizeof(prstatus.arm64);
	} else
		return NULL;

	/* should be enought for the notes + roundup + two blocks */
	buffer = (char *)GETBUF(sizeof(Elf64_Ehdr) +
		num_segments * sizeof(Elf64_Phdr) + PAGESIZE() * 2);
	offset = 0;
	ptr = buffer;

	/* Elf header */
	elf = (Elf64_Ehdr *)ptr;
	memcpy(elf->e_ident, ELFMAG, SELFMAG);
	elf->e_ident[EI_CLASS] = ELFCLASS64;
#if __BYTE_ORDER == __BIG_ENDIAN
	elf->e_ident[EI_DATA] = ELFDATA2MSB;
#else
	elf->e_ident[EI_DATA] = ELFDATA2LSB;
#endif
	elf->e_ident[EI_VERSION] = EV_CURRENT;
	elf->e_ident[EI_OSABI] = ELFOSABI_SYSV;
	elf->e_ident[EI_ABIVERSION] = 0;
	memset(elf->e_ident+EI_PAD, 0, EI_NIDENT-EI_PAD);

	elf->e_type = ET_CORE;
	elf->e_machine = e_machine;
	elf->e_version = EV_CURRENT;
	elf->e_entry = 0;
	elf->e_phoff = sizeof(Elf64_Ehdr);
	elf->e_shoff = 0;
	elf->e_flags = 0;
	elf->e_ehsize = sizeof(Elf64_Ehdr);
	elf->e_phentsize = sizeof(Elf64_Phdr);
	elf->e_phnum = 1 + num_segments;
	elf->e_shentsize = 0;
	elf->e_shnum = 0;
	elf->e_shstrndx = 0;

	offset += sizeof(Elf64_Ehdr);
	ptr += sizeof(Elf64_Ehdr);

	/* PT_NOTE */
	notes = (Elf64_Phdr *)ptr;
	notes->p_type = PT_NOTE;
	notes->p_offset = 0; /* TO BE FILLED IN */
	notes->p_vaddr = 0;
	notes->p_paddr = 0;
	notes->p_filesz = 0; /* TO BE FILLED IN */
	notes->p_memsz = 0;
	notes->p_flags = 0;
	notes->p_align = 0;

	offset += sizeof(Elf64_Phdr);
	ptr += sizeof(Elf64_Phdr);

	/* PT_LOAD */
	load = (Elf64_Phdr *)ptr;
	for (i = n = 0; i < num_segments; i++) {
		load[i].p_type = PT_LOAD;
		load[i].p_offset = 0; /* TO BE FILLED IN */

		switch (e_machine)
		{
		case EM_X86_64:
			nt = &vt->node_table[n];
			if (i == 0) {
#ifdef X86_64
				load[i].p_vaddr = __START_KERNEL_map;
				load[i].p_paddr = machdep->machspec->phys_base;
#endif
				load[i].p_filesz = 0;
				load[i].p_memsz = load[i].p_filesz;
			} else {
				load[i].p_vaddr = PTOV(nt->start_paddr);
				load[i].p_paddr = nt->start_paddr;
				load[i].p_filesz = nt->size * PAGESIZE();
				load[i].p_memsz = load[i].p_filesz;
				n++;
			}
			load[i].p_flags = PF_R | PF_W | PF_X;
			load[i].p_align = 0;
			break;

		case EM_386:
			nt = &vt->node_table[n++];
			load[i].p_vaddr = 0;
			load[i].p_paddr = nt->start_paddr;
			load[i].p_filesz = nt->size * PAGESIZE();
			load[i].p_memsz = load[i].p_filesz;
			load[i].p_flags = PF_R | PF_W | PF_X;
			load[i].p_align = (type == NETDUMP_ELF64) ? PAGESIZE() : 0;
			break;

		case EM_IA_64:
			nt = &vt->node_table[n];
			if (i == 0) {
#ifdef IA64
				load[i].p_vaddr = machdep->machspec->kernel_start;
				load[i].p_paddr = machdep->machspec->phys_start;
#endif
				load[i].p_filesz = 0;
				load[i].p_memsz = load[i].p_filesz;
			} else {
				load[i].p_vaddr = PTOV(nt->start_paddr);
				load[i].p_paddr = nt->start_paddr;
				load[i].p_filesz = nt->size * PAGESIZE();
 				load[i].p_memsz = load[i].p_filesz;
				n++;
			}
			load[i].p_flags = PF_R | PF_W | PF_X;
			load[i].p_align = (type == NETDUMP_ELF64) ? PAGESIZE() : 0;
			break;

		case EM_PPC64:
			nt = &vt->node_table[n++];
			load[i].p_vaddr = PTOV(nt->start_paddr);
			load[i].p_paddr = nt->start_paddr;
			load[i].p_filesz = nt->size * PAGESIZE();
			load[i].p_memsz = load[i].p_filesz;
			load[i].p_flags = PF_R | PF_W | PF_X;
			load[i].p_align = (type == NETDUMP_ELF64) ? PAGESIZE() : 0;
			break;

		case EM_AARCH64:
			nt = &vt->node_table[n++];
			load[i].p_vaddr = PTOV(nt->start_paddr);
			load[i].p_paddr = nt->start_paddr;
			load[i].p_filesz = nt->size * PAGESIZE();
			load[i].p_memsz = load[i].p_filesz;
			load[i].p_flags = PF_R | PF_W | PF_X;
			load[i].p_align = (type == NETDUMP_ELF64) ? PAGESIZE() : 0;
			break;
		}

//		l_offset += load[i].p_filesz;
		offset += sizeof(Elf64_Phdr);
		ptr += sizeof(Elf64_Phdr);
	}
	notes->p_offset = offset;

	/* NT_PRSTATUS note */
	memset(&prstatus, 0, sizeof(prstatus));
	len = dump_elf_note(ptr, NT_PRSTATUS, "CORE",
		(char *)&prstatus, prstatus_len);
	offset += len;
	ptr += len;
	notes->p_filesz += len;

	/* NT_PRPSINFO note */
	memset(&prpsinfo, 0, sizeof(struct elf_prpsinfo_64));
	prpsinfo.pr_state = 0;
	prpsinfo.pr_sname = 'R';
	prpsinfo.pr_zomb = 0;
	strcpy(prpsinfo.pr_fname, "vmlinux");

	len = dump_elf_note(ptr, NT_PRPSINFO, "CORE",
		(char *)&prpsinfo, sizeof(prpsinfo));

	offset += len;
	ptr += len;
	notes->p_filesz += len;

  	/* NT_TASKSTRUCT note */
	SNAP_info.task_struct = CURRENT_TASK();
#ifdef X86_64
	SNAP_info.arch_data1 = kt->relocate;
	SNAP_info.arch_data2 = 0;
#elif ARM64
	SNAP_info.arch_data1 = machdep->machspec->kimage_voffset;
	SNAP_info.arch_data2 = (machdep->machspec->VA_BITS_ACTUAL << 32) | 
				machdep->machspec->CONFIG_ARM64_VA_BITS;
#else
	SNAP_info.arch_data1 = 0;
	SNAP_info.arch_data2 = 0;
#endif
	len = dump_elf_note (ptr, NT_TASKSTRUCT, "SNAP",
		(char *)&SNAP_info, sizeof(struct SNAP_info));
	offset += len;
	ptr += len;
	notes->p_filesz += len;

	if (type == NETDUMP_ELF64)
		offset = roundup (offset, PAGESIZE());

	l_offset = offset;
	for (i = 0; i < num_segments; i++) {
		load[i].p_offset = l_offset;
		l_offset += load[i].p_filesz;
	}
	data_offset = offset;

	while (offset > 0) {
		len = write(fd, buffer + (data_offset - offset), offset);
		if (len < 0) {
			perror(filename);
			FREEBUF(buffer);
			return NULL;
		}

		offset -= len;
	}

	return buffer;
}

struct ram_segments {
	physaddr_t start;
	physaddr_t end;
};

static struct ram_segments *ram_segments = NULL;
static int nr_segments = 0;

static void
init_ram_segments(void)
{
	int i, errflag;
        FILE *iomem; 
	char buf[BUFSIZE], *p1, *p2;
	physaddr_t start, end;

	if ((iomem = fopen("/proc/iomem", "r")) == NULL)
		goto fail_iomem;

	while (fgets(buf, BUFSIZE, iomem)) {
		if (strstr(buf, "System RAM")) {
			console(buf);
			nr_segments++;
		}
	}
	if (!nr_segments)
		goto fail_iomem;

	ram_segments = (struct ram_segments *)
		GETBUF(sizeof(struct ram_segments) * nr_segments);

	rewind(iomem);
	i = 0;
	while (fgets(buf, BUFSIZE, iomem)) {
		if (strstr(buf, "System RAM")) {
			if (!(p1 = strstr(buf, ":")))
				goto fail_iomem;
			*p1 = NULLCHAR;
			clean_line(buf);
			if (strstr(buf, " "))
				goto fail_iomem;
			p1 = buf;
			if (!(p2 = strstr(buf, "-")))
				goto fail_iomem;
			*p2 = NULLCHAR;
			p2++;
			errflag = 0;
			start = htoll(p1, RETURN_ON_ERROR|QUIET, &errflag);
			end = htoll(p2, RETURN_ON_ERROR|QUIET, &errflag);
			if (errflag)
				goto fail_iomem;
			ram_segments[i].start = PHYSPAGEBASE(start);
			if (PAGEOFFSET(start))
				ram_segments[i].start += PAGESIZE();
			ram_segments[i].end = PHYSPAGEBASE(end);
			if (PAGEOFFSET(end) == (PAGESIZE()-1))
				ram_segments[i].end += PAGESIZE();
			console("ram_segments[%d]: %016llx %016llx [%s-%s]\n", i,
				(ulonglong)ram_segments[i].start, 
				(ulonglong)ram_segments[i].end, p1, p2);
			i++;
		}
	}

	fclose(iomem);
	return;

fail_iomem:
	fclose(iomem);
	nr_segments = 0;
	if (ram_segments)
		FREEBUF(ram_segments);

	return; 
}

static int
verify_paddr(physaddr_t paddr)
{
	int i, ok;

	if (!machdep->verify_paddr(paddr))
		return FALSE;

	if (!nr_segments)
		return TRUE;

	for (i = ok = 0; i < nr_segments; i++) {
		if ((paddr >= ram_segments[i].start) &&
		    (paddr < ram_segments[i].end)) {
			ok++;
			break;
		}
	}

	/*
	 *  Pre-2.6.13 x86_64 /proc/iomem was restricted to 4GB,
	 *  so just accept it.
	 */
	if ((paddr >= 0x100000000ULL) &&
	    machine_type("X86_64") &&
	    (THIS_KERNEL_VERSION < LINUX(2,6,13)))
		ok++;

	if (!ok) {
		if (CRASHDEBUG(1))
			console("reject: %llx\n", (ulonglong)paddr);
		return FALSE;
	}
	
	return TRUE;
}

/*
 *  Borrowed from makedumpfile, prints a percentage-done value 
 *  once per second. 
 */
static int
print_progress(const char *filename, ulong current)
{
        int n, progress;
        time_t tm;
	struct node_table *nt;
        static time_t last_time = 0;
	static ulong total_pages = 0;
	static ulong written_pages = 0;

	if (!total_pages) {
        	for (n = 0; n < vt->numnodes; n++) {
                	nt = &vt->node_table[n];
                	total_pages += nt->size;
        	}
	}

	if (received_SIGINT()) {
		fprintf(stderr, "\n\n");
		return FALSE;
	}

        if (++written_pages < total_pages) {
                tm = time(NULL);
                if (tm - last_time < 1)
                        return TRUE;
                last_time = tm;
                progress = written_pages * 100 / total_pages;
        } else
                progress = 100;

        fprintf(stderr, "\r%s: [%2d%%] ", filename, progress);

	return TRUE;
}
