/*
 * ramdump.c - core analysis suite
 *
 * Copyright (c) 2014  Broadcom Corporation
 *                     Oza Pawandeep <oza@broadcom.com>
 *                     Vikram Prakash <vikramp@broadcom.com>
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
 * Author: Oza Pawandeep <oza@broadcom.com>
 */

#define _LARGEFILE64_SOURCE 1  /* stat64() */
#include "defs.h"
#include <elf.h>

struct ramdump_def {
	char *path;
	int rfd;
	ulonglong start_paddr;
	ulonglong end_paddr;
};

static struct ramdump_def *ramdump;
static int nodes;
static char *user_elf = NULL;
static char elf_default[] = "/var/tmp/ramdump_elf_XXXXXX";

static void alloc_elf_header(Elf64_Ehdr *ehdr, ushort e_machine)
{
	memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
	ehdr->e_ident[EI_CLASS] = ELFCLASS64;
	ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr->e_ident[EI_VERSION] = EV_CURRENT;
	ehdr->e_ident[EI_OSABI] = ELFOSABI_LINUX;
	ehdr->e_ident[EI_ABIVERSION] = 0;
	memset(ehdr->e_ident+EI_PAD, 0,
		EI_NIDENT-EI_PAD);
	ehdr->e_type = ET_CORE;
	ehdr->e_machine = e_machine;
	ehdr->e_version = EV_CURRENT;
	ehdr->e_entry = 0;
	ehdr->e_phoff = sizeof(Elf64_Ehdr);
	ehdr->e_shoff = 0;
	ehdr->e_flags = 0;
	ehdr->e_ehsize = sizeof(Elf64_Ehdr);
	ehdr->e_phentsize = sizeof(Elf64_Phdr);
	ehdr->e_phnum = 1 + nodes;
	ehdr->e_shentsize = 0;
	ehdr->e_shnum = 0;
	ehdr->e_shstrndx = 0;
}

static void alloc_program_headers(Elf64_Phdr *phdr)
{
	unsigned int i;

	for (i = 0; i < nodes; i++) {
		phdr[i].p_type = PT_LOAD;
		phdr[i].p_filesz = ramdump[i].end_paddr + 1 - ramdump[i].start_paddr;
		phdr[i].p_memsz = phdr[i].p_filesz;
		phdr[i].p_vaddr = 0;
		phdr[i].p_paddr = ramdump[i].start_paddr;
		phdr[i].p_flags = PF_R | PF_W | PF_X;
		phdr[i].p_align = 0;
	}
}

static char *write_elf(Elf64_Phdr *load, Elf64_Ehdr *e_head, size_t data_offset)
{
#define CPY_BUF_SZ 4096
	int fd1, fd2, i, err = 1;
	char *buf;
	char *out_elf;
	size_t offset;
	ssize_t rd, len;

	buf = (char *)malloc(CPY_BUF_SZ);

	offset = data_offset;

	if (user_elf) {
		fd2 = open(user_elf, O_CREAT|O_RDWR, S_IRUSR|S_IWUSR);
		if (fd2 < 0) {
			error(INFO, "%s open error, %s\n",
				user_elf, strerror(errno));
			goto end1;
		}
		out_elf = user_elf;
	} else {
		fd2 = mkstemp(elf_default);
		if (fd2 < 0) {
			error(INFO, "%s open error, %s\n",
				elf_default, strerror(errno));
			goto end1;
		}
		out_elf = elf_default;
		pc->flags2 |= RAMDUMP;
	}

	if (user_elf) {
		sprintf(buf, "creating ELF dumpfile: %s", out_elf);
		please_wait(buf);
	} else if (CRASHDEBUG(1))
		fprintf(fp, "creating temporary ELF header: %s\n\n",
			elf_default);

	while (offset > 0) {
		len = write(fd2, e_head + (data_offset - offset), offset);
		if (len < 0) {
			error(INFO, "ramdump write error, %s\n",
				strerror(errno));
			goto end;
		}
		offset -= len;
	}

	if (user_elf) {
		for (i = 0; i < nodes; i++) {
			offset = load[i].p_offset;

			fd1 = open(ramdump[i].path, O_RDONLY, S_IRUSR);
			if (fd1 < 0) {
				error(INFO, "%s open error, %s\n",
					ramdump[i].path, strerror(errno));
				goto end;
			}

			lseek(fd2, (off_t)offset, SEEK_SET);
			while ((rd = read(fd1, buf, CPY_BUF_SZ)) > 0) {
				if (write(fd2, buf, rd) != rd) {
					error(INFO, "%s write error, %s\n",
						ramdump[i].path,
						strerror(errno));
					close(fd1);
					goto end;
				}
			}
			close(fd1);
		}
		please_wait_done();
	}

	err = 0;
end:
	close(fd2);
end1:
	free(buf);
	return err ? NULL : out_elf;
}

static void alloc_notes(Elf64_Phdr *notes)
{
	/* Nothing filled in as of now */
	notes->p_type = PT_NOTE;
	notes->p_offset = 0;
	notes->p_vaddr = 0;
	notes->p_paddr = 0;
	notes->p_filesz = 0;
	notes->p_memsz = 0;
	notes->p_flags = 0;
	notes->p_align = 0;
}

char *ramdump_to_elf(void)
{
	int i;
	char *ptr, *e_file = NULL;
	ushort e_machine = 0;
	size_t offset, data_offset;
	size_t l_offset;
	Elf64_Phdr *notes, *load;
	Elf64_Ehdr *e_head;

	if (machine_type("ARM"))
		e_machine = EM_ARM;
	else if (machine_type("ARM64"))
		e_machine = EM_AARCH64;
	else if (machine_type("MIPS") || machine_type("MIPS64"))
		e_machine = EM_MIPS;
	else if (machine_type("X86_64"))
		e_machine = EM_X86_64;
	else
		error(FATAL, "ramdump: unsupported machine type: %s\n", 
			MACHINE_TYPE);

	e_head = (Elf64_Ehdr *)malloc(sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr) +
		(nodes * sizeof(Elf64_Phdr)) + (CPY_BUF_SZ * 2));
	ptr = (char *)e_head;
	offset = 0;

	alloc_elf_header(e_head, e_machine);

	ptr += sizeof(Elf64_Ehdr);
	offset += sizeof(Elf64_Ehdr);

	notes = (Elf64_Phdr *)ptr;

	alloc_notes(notes);

	offset += sizeof(Elf64_Phdr);
	ptr += sizeof(Elf64_Phdr);

	load = (Elf64_Phdr *)ptr;

	alloc_program_headers(load);

	offset += sizeof(Elf64_Phdr) * nodes;
	ptr += sizeof(Elf64_Phdr) * nodes;

	/* Empty note */
	notes->p_offset = offset;

	l_offset = offset;

	data_offset = offset;

	for (i = 0; i < nodes; i++) {
		load[i].p_offset = l_offset;
		l_offset += load[i].p_filesz;
	}

	e_file = write_elf(load, e_head, data_offset);

	free(e_head);
	return e_file;
}

#define PREFIX(ptr, pat)				\
	(strncmp((ptr), (pat), sizeof(pat)-1) ?	 0 :	\
			((ptr) += sizeof(pat)-1, 1))

int is_ramdump(char *p)
{
	char *x = NULL, *y = NULL, *pat;
	size_t len;
	char *pattern;
	struct stat64 st;
	int is_live;
	int err = 0;

	is_live = PREFIX(p, "live:");

	if (nodes || !strchr(p, '@'))
		return 0;

	len = strlen(p);
	pattern = (char *)malloc(len + 1);
	strlcpy(pattern, p, len + 1);

	pat = pattern;
	while ((pat = strtok_r(pat, ",", &x))) {
		if ((pat = strtok_r(pat, "@", &y))) {
			nodes++;
			ramdump = realloc(ramdump,
				sizeof(struct ramdump_def) * nodes);
			if (!ramdump)
				error(FATAL, "realloc failure\n");
			ramdump[nodes - 1].path = pat;
			pat = strtok_r(NULL, "@", &y);
			ramdump[nodes - 1].start_paddr =
				htoll(pat, RETURN_ON_ERROR, &err);
			if (err == TRUE)
				error(FATAL, "Invalid ramdump address\n");
			if ((ramdump[nodes - 1].rfd =
				open(ramdump[nodes - 1].path, O_RDONLY)) < 0)
					error(FATAL,
						"ramdump %s open failed:%s\n",
						ramdump[nodes - 1].path,
						strerror(errno));
			if (fstat64(ramdump[nodes - 1].rfd, &st) < 0)
				error(FATAL, "ramdump stat failed\n");
			ramdump[nodes - 1].end_paddr =
				ramdump[nodes - 1].start_paddr + st.st_size - 1;
		}

		pat = NULL;
	}

	if (nodes && is_live) {
		pc->flags |= LIVE_SYSTEM;
		pc->dumpfile = ramdump[0].path;
		pc->live_memsrc = pc->dumpfile;
	}
	return nodes;
}

void ramdump_elf_output_file(char *opt)
{
	user_elf = opt;
}

void ramdump_cleanup(void)
{
	if (!user_elf)
		unlink(elf_default);
}

int
read_ramdump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	off_t offset;
	int i, found;
	struct ramdump_def *r = &ramdump[0];

	offset = 0;

	for (i = found = 0; i < nodes; i++) {
		r = &ramdump[i];

		if ((paddr >= r->start_paddr) &&
		    (paddr <= r->end_paddr)) {
			offset = (off_t)paddr - (off_t)r->start_paddr;
			found++;
			break;
		}
	}

	if (!found) {
		if (CRASHDEBUG(8))
			fprintf(fp, "read_ramdump: READ_ERROR: "
		    	    "offset not found for paddr: %llx\n",
				(ulonglong)paddr);
		return READ_ERROR;
	}

	if (CRASHDEBUG(8))
		fprintf(fp,
		"read_ramdump: addr: %lx paddr: %llx cnt: %d offset: %llx\n",
			addr, (ulonglong)paddr, cnt, (ulonglong)offset);

	if (lseek(r->rfd, offset, SEEK_SET) == -1) {
		if (CRASHDEBUG(8))
			fprintf(fp, "read_ramdump: SEEK_ERROR: "
				"offset: %llx\n", (ulonglong)offset);
		return SEEK_ERROR;
	}

	if (read(r->rfd, bufptr, cnt) != cnt) {
		if (CRASHDEBUG(8))
			fprintf(fp, "read_ramdump: READ_ERROR: "
				"offset: %llx\n", (ulonglong)offset);
		return READ_ERROR;
	}

        return cnt;
}

void
show_ramdump_files(void)
{
	int i;

	fprintf(fp, "%s [temporary ELF header]\n", elf_default);
	for (i = 0; i < nodes; i++) {
		fprintf(fp, "%s              %s", 
			i ? "\n" : "", ramdump[i].path);
	}
}

void
dump_ramdump_data()
{
	int i;

	if (!user_elf && !is_ramdump_image())
		return;

	fprintf(fp, "\nramdump data:\n");

	fprintf(fp, "               user_elf: %s\n", 
		user_elf ? user_elf : "(unused)");
	fprintf(fp, "            elf_default: %s\n", 
		user_elf ? "(unused)" : elf_default);
	fprintf(fp, "                  nodes: %d\n", nodes);

	for (i = 0; i < nodes; i++) {
	fprintf(fp, "             ramdump[%d]:\n", i);
		fprintf(fp, "                     path: %s\n", 
			ramdump[i].path);
		fprintf(fp, "                      rfd: %d\n", 
			ramdump[i].rfd);
		fprintf(fp, "              start_paddr: %llx\n", 
			(ulonglong)ramdump[i].start_paddr);
		fprintf(fp, "                end_paddr: %llx\n", 
			(ulonglong)ramdump[i].end_paddr);
	}

	fprintf(fp, "\n");
}

int
is_ramdump_image(void)
{
	return (pc->flags2 & RAMDUMP ? TRUE : FALSE);
}
