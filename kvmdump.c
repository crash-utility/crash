/*
 * kvmdump.c
 *
 * Copyright (C) 2009, 2010, 2011 David Anderson
 * Copyright (C) 2009, 2010, 2011 Red Hat, Inc. All rights reserved.
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
#include "kvmdump.h"

static struct kvmdump_data kvmdump_data = { 0 };  
struct kvmdump_data *kvm = &kvmdump_data;
static int cache_page(physaddr_t);
static int kvmdump_mapfile_exists(void);
static off_t mapfile_offset(uint64_t);
static void kvmdump_mapfile_create(char *);
static void kvmdump_mapfile_append(void);
static char *mapfile_in_use(void);
static void write_mapfile_registers(void);
static void write_mapfile_trailer(void);
static void read_mapfile_trailer(void);
static void read_mapfile_registers(void);

#define RAM_OFFSET_COMPRESSED (~(off_t)255)
#define QEMU_COMPRESSED       ((WRITE_ERROR)-1)
#define CACHE_UNUSED          (1ULL)

int 
is_kvmdump(char *filename)
{
	int i;
	ulong *ptr;
	off_t eof;
	ulonglong csum;
	struct mapinfo_trailer trailer;
	char buf[CHKSUM_SIZE];

	if (!is_qemu_vm_file(filename))
		return FALSE;

	if (lseek(kvm->vmfd, 0, SEEK_SET) < 0) {
		error(INFO, "%s: read: %s\n", filename, strerror(errno));
		return FALSE;
	}
	if (read(kvm->vmfd, buf, CHKSUM_SIZE) != CHKSUM_SIZE) {
		error(INFO, "%s: read: %s\n", filename, strerror(errno));
		return FALSE;
        }

	ptr = (ulong *)&buf[0];	
	for (i = csum = 0; i < (CHKSUM_SIZE/sizeof(ulong)); i++, ptr++)
		csum += *ptr;

	eof = lseek(kvm->vmfd, 0, SEEK_END);
	if (lseek(kvm->vmfd, eof - sizeof(trailer), SEEK_SET) < 0) {
		error(INFO, "%s: lseek: %s\n", filename, strerror(errno));
		return FALSE;
	} 
	if (read(kvm->vmfd, &trailer, sizeof(trailer)) != sizeof(trailer)) {
		error(INFO, "%s: read: %s\n", filename, strerror(errno));
		return FALSE;
	}
	if (trailer.magic == MAPFILE_MAGIC) {
		kvm->mapinfo.map_start_offset = trailer.map_start_offset;
		kvm->flags |= MAPFILE_APPENDED;
	}

	kvm->mapinfo.checksum = csum;

	return TRUE;
}

int 
kvmdump_init(char *filename, FILE *fptr)
{
	int i, page_size;
        struct command_table_entry *cp;
	char *cachebuf;
	FILE *tmpfp;

	if (!machine_type("X86") && !machine_type("X86_64")) {
		error(FATAL, 
		    "invalid or unsupported host architecture for KVM: %s\n",
			MACHINE_TYPE);
		return FALSE;
	}

	kvm->ofp = fptr;
	kvm->debug = &pc->debug;
	page_size = memory_page_size();

#ifdef X86_64
	kvm->kvbase = __START_KERNEL_map;
#endif

	switch (kvm->flags & (TMPFILE|MAPFILE|MAPFILE_APPENDED))
	{
	case MAPFILE_APPENDED:
		kvm->mapfd = kvm->vmfd;
		break;

	case MAPFILE|MAPFILE_APPENDED:
	case MAPFILE:
		break;

	default:
		if (kvmdump_mapfile_exists())
			break;

		if ((tmpfp = tmpfile()) == NULL) 
			error(FATAL, 
			    "cannot create tmpfile for KVM file offsets: %s\n", 
				strerror(errno));

		kvm->mapfd = fileno(tmpfp);
		kvm->flags |= TMPFILE;
		break;
	}

        if ((cachebuf = calloc(1, KVMDUMP_CACHED_PAGES * page_size)) == NULL)
                error(FATAL, "%s: cannot malloc KVM page_cache_buf\n");

	for (i = 0; i < KVMDUMP_CACHED_PAGES; i++) {
		kvm->page_cache[i].paddr = CACHE_UNUSED;
		kvm->page_cache[i].bufptr = cachebuf + (i * page_size);
	}

	kvmdump_regs_store(KVMDUMP_REGS_START, NULL);

	if (qemu_init(filename)) {
		switch (kvm->flags & (TMPFILE|MAPFILE|MAPFILE_APPENDED))
		{
		case TMPFILE:
			kvmdump_regs_store(KVMDUMP_REGS_END, NULL);
			write_mapfile_trailer();
			break;

		case MAPFILE:
		case MAPFILE_APPENDED:
		case MAPFILE|MAPFILE_APPENDED:
			read_mapfile_trailer();
			kvmdump_regs_store(KVMDUMP_REGS_END, NULL);
			break;
		}

		for (cp = pc->cmd_table; cp->name; cp++) {
			if (STREQ(cp->name, "map")) {
				cp->flags &= ~HIDDEN_COMMAND;
				break;
			}
		}

		kvm->flags |= KVMDUMP_LOCAL; 
		return TRUE;
	} else 
		return FALSE;
}

int 
read_kvmdump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	switch (cache_page(PHYSPAGEBASE(paddr)))
	{
	case READ_ERROR:
		return READ_ERROR;

	case SEEK_ERROR:
		return SEEK_ERROR;

	case QEMU_COMPRESSED:
		memset(bufptr, kvm->un.compressed, cnt);
		break;

	default:
		memcpy(bufptr, kvm->un.curbufptr + PAGEOFFSET(paddr), cnt);
		break;
	}

	return cnt;
}


int 
write_kvmdump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	return SEEK_ERROR;
}

/*
 *  kvmdump_free_memory(), and kvmdump_memory_used()
 *  are debug only, and typically unnecessary to implement.
 */
int 
kvmdump_free_memory(void)
{
	return 0;
}

int 
kvmdump_memory_used(void)
{
	return 0;
}

/*
 *  This function is dump-type independent, used here to
 *  to dump the kvmdump_data structure contents.
 */
int 
kvmdump_memory_dump(FILE *ofp)
{
	int i, others;
	struct mapinfo_trailer trailer;
	off_t eof;

	fprintf(ofp, "            flags: %lx (", kvm->flags);
	others = 0;
	if (kvm->flags & KVMDUMP_LOCAL)
		fprintf(ofp, "%sKVMDUMP_LOCAL", others++ ? "|" : "");
	if (kvm->flags & TMPFILE)
		fprintf(ofp, "%sTMPFILE", others++ ? "|" : "");
	if (kvm->flags & MAPFILE)
		fprintf(ofp, "%sMAPFILE", others++ ? "|" : "");
	if (kvm->flags & MAPFILE_FOUND)
		fprintf(ofp, "%sMAPFILE_FOUND", others++ ? "|" : "");
	if (kvm->flags & MAPFILE_APPENDED)
		fprintf(ofp, "%sMAPFILE_APPENDED", others++ ? "|" : "");
	if (kvm->flags & NO_PHYS_BASE)
		fprintf(ofp, "%sNO_PHYS_BASE", others++ ? "|" : "");
	if (kvm->flags & KVMHOST_32)
		fprintf(ofp, "%sKVMHOST_32", others++ ? "|" : "");
	if (kvm->flags & KVMHOST_64)
		fprintf(ofp, "%sKVMHOST_64", others++ ? "|" : "");
	if (kvm->flags & REGS_FROM_MAPFILE)
		fprintf(ofp, "%sREGS_FROM_MAPFILE", others++ ? "|" : "");
	if (kvm->flags & REGS_FROM_DUMPFILE)
		fprintf(ofp, "%sREGS_FROM_DUMPFILE", others++ ? "|" : "");
	if (kvm->flags & REGS_NOT_AVAIL)
		fprintf(ofp, "%sREGS_NOT_AVAIL", others++ ? "|" : "");
	fprintf(ofp, ")\n");

	fprintf(ofp, "            mapfd: %d\n", kvm->mapfd);
	fprintf(ofp, "             vmfd: %d\n", kvm->vmfd);
	fprintf(ofp, "              vmp: %lx (fd: %d)\n", (ulong)kvm->vmp, 
		fileno(kvm->vmp));
	fprintf(ofp, "              ofp: %lx\n", (ulong)kvm->ofp);
	fprintf(ofp, "            debug: %lx\n", (ulong)kvm->debug);
	if (machine_type("X86_64"))
        	fprintf(ofp, "           kvbase: %llx\n", (ulonglong)kvm->kvbase);
	else
        	fprintf(ofp, "           kvbase: (unused)\n");
	fprintf(ofp, "          mapinfo:\n");
        fprintf(ofp, "              magic: %llx %s\n", (ulonglong)kvm->mapinfo.magic,
		kvm->mapinfo.magic == MAPFILE_MAGIC ?  "(MAPFILE_MAGIC)" : "");
        fprintf(ofp, "          phys_base: %llx %s\n", (ulonglong)kvm->mapinfo.phys_base,
		machine_type("X86") ? "(unused)" : "");
        fprintf(ofp, "     cpu_version_id: %ld\n", (ulong)kvm->mapinfo.cpu_version_id);
        fprintf(ofp, "     ram_version_id: %ld\n", (ulong)kvm->mapinfo.ram_version_id);
        fprintf(ofp, "   map_start_offset: %llx\n", (ulonglong)kvm->mapinfo.map_start_offset);
        fprintf(ofp, "           checksum: %llx\n", (ulonglong)kvm->mapinfo.checksum);

	fprintf(ofp, "        curbufptr: %lx\n", (ulong)kvm->un.curbufptr);
	fprintf(ofp, "      evict_index: %d\n", kvm->evict_index);
	fprintf(ofp, "         accesses: %ld\n", kvm->accesses);
	fprintf(ofp, "        hit_count: %ld ", kvm->hit_count);
	if (kvm->accesses)
		fprintf(ofp, "(%ld%%)\n",
			kvm->hit_count * 100 / kvm->accesses);
	else
		fprintf(ofp, "\n");
	fprintf(ofp, "       compresses: %ld ", kvm->compresses);
	if (kvm->accesses)
		fprintf(ofp, "(%ld%%)\n",
			kvm->compresses * 100 / kvm->accesses);
	else
		fprintf(ofp, "\n");

	for (i = 0; i < KVMDUMP_CACHED_PAGES; i++) {
		if (kvm->page_cache[i].paddr == CACHE_UNUSED)
			fprintf(ofp, "   %spage_cache[%d]: CACHE_UNUSED\n", 
				i < 10 ? " " : "", i);
		else
			fprintf(ofp, 
			    "   %spage_cache[%d]: bufptr: %lx  addr: %llx\n",
				i < 10 ? " " : "", i,
				(ulong)kvm->page_cache[i].bufptr,
				(ulonglong)kvm->page_cache[i].paddr);
	}

	fprintf(ofp, "      cpu_devices: %ld\n", kvm->cpu_devices);
	fprintf(ofp, "           iohole: %llx (%llx - %llx)\n", 
		(ulonglong)kvm->iohole, 0x100000000ULL - kvm->iohole,
		0x100000000ULL);

	fprintf(ofp, "        registers: %s\n",
		kvm->registers ? "" : "(not used)");
	for (i = 0; i < kvm->cpu_devices; i++) {
		fprintf(ofp, "  CPU %d:\n", i);
		kvmdump_display_regs(i, ofp);
	}
	fprintf(ofp, "\n");

	dump_qemu_header(ofp);

	fprintf(ofp, "\n%s: mapinfo trailer:\n\n", mapfile_in_use());

	eof = lseek(kvm->mapfd, 0, SEEK_END);
	if (lseek(kvm->mapfd, eof - sizeof(trailer), SEEK_SET) < 0)
		error(FATAL, "%s: lseek: %s\n", mapfile_in_use(), 
			strerror(errno));
	if (read(kvm->mapfd, &trailer, sizeof(trailer)) != sizeof(trailer))
		error(FATAL, "%s: read: %s\n", mapfile_in_use(), 
			strerror(errno));

	fprintf(ofp, "             magic: %llx %s\n", (ulonglong)trailer.magic,
		trailer.magic == MAPFILE_MAGIC ? "(MAPFILE_MAGIC)" : "");
	fprintf(ofp, "         phys_base: %llx %s\n", (ulonglong)trailer.phys_base,
		machine_type("X86") ? "(unused)" : "");
	fprintf(ofp, "    cpu_version_id: %ld\n", (ulong)trailer.cpu_version_id);
	fprintf(ofp, "    ram_version_id: %ld\n", (ulong)trailer.ram_version_id);
        fprintf(ofp, "  map_start_offset: %llx\n", (ulonglong)trailer.map_start_offset);
	fprintf(ofp, "          checksum: %llx\n\n", (ulonglong)trailer.checksum);

	return TRUE;
}

void
kvmdump_display_regs(int cpu, FILE *ofp)
{
	struct register_set *rp;

	if (cpu >= kvm->cpu_devices) {
		error(INFO, "registers not collected for cpu %d\n", cpu);
		return;
	}

	rp = &kvm->registers[cpu];

	if (machine_type("X86_64")) {
		fprintf(ofp, 
		    "    RIP: %016llx  RSP: %016llx  RFLAGS: %08llx\n"
		    "    RAX: %016llx  RBX: %016llx  RCX: %016llx\n"
		    "    RDX: %016llx  RSI: %016llx  RDI: %016llx\n"
		    "    RBP: %016llx   R8: %016llx   R9: %016llx\n"
		    "    R10: %016llx  R11: %016llx  R12: %016llx\n"
		    "    R13: %016llx  R14: %016llx  R15: %016llx\n"
		    "    CS: %04x  SS: %04x\n",
			(ulonglong)rp->ip,
			(ulonglong)rp->regs[R_ESP],
			(ulonglong)rp->flags,
			(ulonglong)rp->regs[R_EAX], 
			(ulonglong)rp->regs[R_EBX],
			(ulonglong)rp->regs[R_ECX], 
			(ulonglong)rp->regs[R_EDX],
			(ulonglong)rp->regs[R_ESI],
			(ulonglong)rp->regs[R_EDI],
			(ulonglong)rp->regs[R_EBP],
			(ulonglong)rp->regs[8], 
			(ulonglong)rp->regs[9],
			(ulonglong)rp->regs[10], 
			(ulonglong)rp->regs[11],
			(ulonglong)rp->regs[12], 
			(ulonglong)rp->regs[13],
			(ulonglong)rp->regs[14], 
			(ulonglong)rp->regs[15],
			rp->cs,
			rp->ss);
	}

	if (machine_type("X86")) {
		fprintf(ofp,
		    "    EAX: %08llx  EBX: %08llx  ECX: %08llx  EDX: %08llx\n"
		    "    DS:  %04x      ESI: %08llx  ES:  %04x      EDI: %08llx\n"
		    "    SS:  %04x      ESP: %08llx  EBP: %08llx  GS:  %04x\n"
		    "    CS:  %04x      EIP: %08llx  EFLAGS: %08llx\n",
			(ulonglong)rp->regs[R_EAX], 
			(ulonglong)rp->regs[R_EBX],
			(ulonglong)rp->regs[R_ECX], 
			(ulonglong)rp->regs[R_EDX],
			rp->ds,
			(ulonglong)rp->regs[R_ESI], 
			rp->ds,
			(ulonglong)rp->regs[R_EDI],
			rp->ss,
			(ulonglong)rp->regs[R_ESP], 
			(ulonglong)rp->regs[R_EBP],
			rp->gs,
			rp->cs,
			(ulonglong)rp->ip,
			(ulonglong)rp->flags);
	}
}

void 
get_kvmdump_regs(struct bt_info *bt, ulong *ipp, ulong *spp)
{
	ulong ip, sp;
	struct register_set *rp;

	ip = sp = 0;

	if (!is_task_active(bt->task)) {
		machdep->get_stack_frame(bt, ipp, spp);
		return;
	}

	bt->flags |= BT_DUMPFILE_SEARCH;
	if (machine_type("X86_64"))
		machdep->get_stack_frame(bt, ipp, spp);
	else if (machine_type("X86"))
		get_netdump_regs_x86(bt, ipp, spp);
	if (bt->flags & BT_DUMPFILE_SEARCH)
		return;

	if ((kvm->registers == NULL) ||
	    (bt->tc->processor >= kvm->cpu_devices))
		return;

	rp = &kvm->registers[bt->tc->processor];
	ip = (ulong)rp->ip;
	sp = (ulong)rp->regs[R_ESP];
	if (is_kernel_text(ip) &&
	    (((sp >= GET_STACKBASE(bt->task)) &&
	      (sp < GET_STACKTOP(bt->task))) ||
	    in_alternate_stack(bt->tc->processor, sp))) {
		*ipp = ip; 
		*spp = sp;
		bt->flags |= BT_KERNEL_SPACE;
		return;
	}

	if (!is_kernel_text(ip) && 
	    in_user_stack(bt->tc->task, sp))
		bt->flags |= BT_USER_SPACE;
}


ulong
get_kvmdump_panic_task(void)
{
	int i;
	struct bt_info *bt;
	ulong panic_task, task, rip, rsp;
	char *sym;

	if (machine_type("X86") || !get_active_set())
		return NO_TASK;

	bt = (struct bt_info *)GETBUF(sizeof(struct bt_info));

	for (i = 0, panic_task = NO_TASK; i < NR_CPUS; i++) {
		if (!(task = tt->active_set[i]) ||
		    !(bt->tc = task_to_context(task)))
			continue;

		bt->task = task;
		bt->stackbase = GET_STACKBASE(task);
		bt->stacktop = GET_STACKTOP(task);
		if (!bt->stackbuf)
                	bt->stackbuf = GETBUF(bt->stacktop - bt->stackbase);
		alter_stackbuf(bt);

		bt->flags |= BT_DUMPFILE_SEARCH;
		machdep->get_stack_frame(bt, &rip, &rsp);
		if (!(bt->flags & BT_DUMPFILE_SEARCH))
			continue;

		sym = closest_symbol(rip);
		if (STREQ(sym, "panic") ||
		    STREQ(sym, "die") ||
		    STREQ(sym, "die_nmi") ||
		    STREQ(sym, "sysrq_handle_crash")) {
			if (CRASHDEBUG(1))
				fprintf(fp, "get_kvmdump_panic_task: %lx\n", 
					task);
			panic_task = task;
			break;
		}
	}

	if (bt->stackbuf)
		FREEBUF(bt->stackbuf);
	FREEBUF(bt);

	return panic_task;
}

int
kvmdump_phys_base(unsigned long *phys_base)
{
        if (KVMDUMP_VALID()) {
		if (CRASHDEBUG(1) && (kvm->mapinfo.cpu_version_id > 9)) 
			error(NOTE, 
			    "KVM/QEMU CPU_SAVE_VERSION %d is greater than"
			    " supported version 9\n\n",
				kvm->mapinfo.cpu_version_id);

                *phys_base = kvm->mapinfo.phys_base;

		return (kvm->flags & NO_PHYS_BASE ? FALSE : TRUE);
        }

        return FALSE;
}

static int
cache_page(physaddr_t paddr)
{
	int idx, err;
	struct kvm_page_cache_hdr *pgc;
	size_t page_size;
	off_t offset;

	kvm->accesses++;

	for (idx = 0; idx < KVMDUMP_CACHED_PAGES; idx++) {
		pgc = &kvm->page_cache[idx];

		if (pgc->paddr == CACHE_UNUSED)
			continue;

		if (pgc->paddr == paddr) {
			kvm->hit_count++;
			kvm->un.curbufptr = pgc->bufptr;
			return idx;
		}
	}

	if ((err = load_mapfile_offset(paddr, &offset)) < 0)
		return err;

        if ((offset & RAM_OFFSET_COMPRESSED) == RAM_OFFSET_COMPRESSED) {
                kvm->un.compressed = (unsigned char)(offset & 255);
		kvm->compresses++;
		return QEMU_COMPRESSED;
	}

	idx = kvm->evict_index;
	pgc = &kvm->page_cache[idx];
        page_size = memory_page_size();

	if (lseek(kvm->vmfd, offset, SEEK_SET) < 0) {
		pgc->paddr = CACHE_UNUSED;
		return SEEK_ERROR;
	}
	if (read(kvm->vmfd, pgc->bufptr, page_size) != page_size) {
		pgc->paddr = CACHE_UNUSED;
		return READ_ERROR;
	}

	kvm->evict_index = (idx+1) % KVMDUMP_CACHED_PAGES;

	pgc->paddr = paddr;
	kvm->un.curbufptr = pgc->bufptr;

	return idx;
}

static off_t 
mapfile_offset(uint64_t physaddr)
{
	off_t offset = 0;

	switch (kvm->flags & (TMPFILE|MAPFILE|MAPFILE_APPENDED))
	{
	case TMPFILE:
	case TMPFILE|MAPFILE_APPENDED:
	case MAPFILE:
	case MAPFILE|MAPFILE_APPENDED:
		offset = (off_t)(((((uint64_t)physaddr/(uint64_t)4096)) 
			* sizeof(off_t))); 
		break;
	
	case MAPFILE_APPENDED:
		offset = (off_t)(((((uint64_t)physaddr/(uint64_t)4096)) 
			* sizeof(off_t)) + kvm->mapinfo.map_start_offset); 
                break;
	}

	return offset;
}

int 
store_mapfile_offset(uint64_t physaddr, off_t *entry_ptr)
{
        if (lseek(kvm->mapfd, mapfile_offset(physaddr), SEEK_SET) < 0) {
		error(INFO, "store_mapfile_offset: "
	    	    "lseek error: physaddr: %llx  %s offset: %llx\n", 
			(unsigned long long)physaddr, mapfile_in_use(),
			(unsigned long long)mapfile_offset(physaddr));
		return SEEK_ERROR;
	}

        if (write(kvm->mapfd, entry_ptr, sizeof(off_t)) != sizeof(off_t)) {
		error(INFO, "store_mapfile_offset: "
	    	    "write error: physaddr: %llx  %s offset: %llx\n", 
			(unsigned long long)physaddr, mapfile_in_use(),
			(unsigned long long)mapfile_offset(physaddr));
		return WRITE_ERROR;
	}
	
	return 0;
}

int 
load_mapfile_offset(uint64_t physaddr, off_t *entry_ptr)
{
	uint64_t kvm_addr = physaddr;

	switch (kvm->iohole)
	{
	case 0x20000000ULL:
		if (physaddr >= 0xe0000000ULL) {
			if (physaddr < 0x100000000ULL)
				return SEEK_ERROR;   /* In 512MB I/O hole */
			kvm_addr -= kvm->iohole;
		}
		break;

	case 0x40000000ULL:
		if (physaddr >= 0xc0000000ULL) {
			if (physaddr < 0x100000000ULL)
				return SEEK_ERROR;   /* In 1GB I/O hole */
			kvm_addr -= kvm->iohole;
		}
		break;
	}
 
	if (lseek(kvm->mapfd, mapfile_offset(kvm_addr), SEEK_SET) < 0) {
		if (CRASHDEBUG(1))
			error(INFO, "load_mapfile_offset: "
		    	    "lseek error: physical: %llx  %s offset: %llx\n", 
				(unsigned long long)physaddr, mapfile_in_use(),
				(unsigned long long)mapfile_offset(kvm_addr));
		return SEEK_ERROR;
	}

	if (read(kvm->mapfd, entry_ptr, sizeof(off_t)) != sizeof(off_t)) {
		if (CRASHDEBUG(1)) 
			error(INFO, "load_mapfile_offset: "
		    	    "read error: physical: %llx  %s offset: %llx\n", 
				(unsigned long long)physaddr, mapfile_in_use(),
				(unsigned long long)mapfile_offset(kvm_addr));
		return READ_ERROR;
	}

	return 0;
}

static void
kvmdump_mapfile_create(char *filename)
{
	int fdmem, n;
	off_t offset;
	char buf[4096];

	if (kvm->flags & MAPFILE) {
		error(INFO, "%s: mapfile in use\n", pc->kvmdump_mapfile);
		return;
	}

	if (file_exists(filename, NULL)) {
		error(INFO, 
		    "%s: file already exists!\n", filename);
		return;
	}

	if ((fdmem = open(filename, O_CREAT|O_RDWR, 0644)) < 0) {
		error(INFO, "%s: open: %s\n", filename, strerror(errno));
		return;
	}

	offset = kvm->mapinfo.map_start_offset;

	if (lseek(kvm->mapfd, offset, SEEK_SET) < 0) {
		error(INFO, "%s: leek: %s\n", 
			mapfile_in_use(), strerror(errno));
		return;
	}

	while ((n = read(kvm->mapfd, buf, 4096)) > 0) {
		if (write(fdmem, buf, n) != n) {
			error(INFO, "%s: write: %s\n", filename, 
				strerror(errno));
			break;
		}
	}

	close(fdmem);

	fprintf(fp, "MAP FILE CREATED: %s\n", filename);
}

static void
kvmdump_mapfile_append(void)
{
	int n, fdcore; 
	ulong round_bytes;
	struct stat statbuf;
	uint64_t map_start_offset;
	off_t eof, orig_dumpfile_size;
	char buf[4096];

	if (kvm->flags & MAPFILE_APPENDED)
		error(FATAL, "mapfile already appended to %s\n",
			pc->dumpfile);

	if (access(pc->dumpfile, W_OK) != 0)
		error(FATAL, 
		    "%s: cannot append map information to this file\n",
			pc->dumpfile);

	if (stat(pc->dumpfile, &statbuf) < 0)
		error(FATAL, "%s: stat: %s\n",
			pc->dumpfile, strerror(errno));

	round_bytes = (sizeof(uint64_t) - (statbuf.st_size % sizeof(uint64_t)))
		% sizeof(uint64_t);

	if ((fdcore = open(pc->dumpfile, O_WRONLY)) < 0)
		error(FATAL, "%s: open: %s\n", 
			pc->dumpfile, strerror(errno));

	if ((orig_dumpfile_size = lseek(fdcore, 0, SEEK_END)) < 0) {
		error(INFO, "%s: lseek: %s\n", pc->dumpfile, strerror(errno));
		goto bailout1;
	}

	if (round_bytes) {
		BZERO(buf, round_bytes);

		if (write(fdcore, buf, round_bytes) != round_bytes) {
			error(INFO, "%s: write: %s\n", 
				pc->dumpfile, strerror(errno));
			goto bailout2;
		}

	}

	map_start_offset = orig_dumpfile_size + round_bytes;

	if (lseek(kvm->mapfd, 0, SEEK_SET) != 0) {
		error(INFO, "%s: lseek: %s\n", 
			mapfile_in_use(), strerror(errno));
		goto bailout2;
	}

	while ((n = read(kvm->mapfd, buf, 4096)) > 0) {
		if (write(fdcore, buf, n) != n) {
			error(INFO, "%s: write: %s\n", pc->dumpfile, 
				strerror(errno));
			goto bailout2;
		}
	}

	/*
	 *  Overwrite the map_start_offset value in the trailer to reflect
	 *  its location in the appended-to dumpfile.
	 */
        eof = lseek(fdcore, 0, SEEK_END);
        if (lseek(fdcore, eof - sizeof(struct mapinfo_trailer), SEEK_SET) < 0) {
		error(INFO, "%s: write: %s\n", pc->dumpfile, strerror(errno));
		goto bailout2;
	}
	if (write(fdcore, &map_start_offset, sizeof(uint64_t)) != sizeof(uint64_t)) { 
		error(INFO, "%s: write: %s\n", pc->dumpfile, strerror(errno));
		goto bailout2;
	}

	close(fdcore);

	kvm->flags |= MAPFILE_APPENDED;
	fprintf(fp, "MAP FILE APPENDED TO: %s\n", pc->dumpfile);

	return;

bailout2:
	if (ftruncate(fdcore, (off_t)orig_dumpfile_size) < 0)
		error(INFO, "%s: ftruncate: %s\n", 
			pc->dumpfile, strerror(errno));
bailout1:
	close(fdcore);
	error(INFO, "failed to append map to %s\n", pc->dumpfile);
}

int 
is_kvmdump_mapfile(char *filename)
{
	int fd;
	struct mapinfo_trailer trailer;
	off_t eof;

        if ((fd = open(filename, O_RDONLY)) < 0) {
                error(INFO, "%s: open: %s\n", filename, strerror(errno));
                return FALSE;
        }

	if ((eof = lseek(fd, 0, SEEK_END)) == -1)
		goto bailout;

	if (lseek(fd, eof - sizeof(trailer), SEEK_SET) < 0) {
                error(INFO, "%s: lseek: %s\n", filename, strerror(errno));
		goto bailout;
	}

        if (read(fd, &trailer, sizeof(trailer)) != sizeof(trailer)) {
                error(INFO, "%s: read: %s\n", filename, strerror(errno));
		goto bailout;
        }

	if (trailer.magic == MAPFILE_MAGIC) {
		if (pc->dumpfile && (trailer.checksum != kvm->mapinfo.checksum)) {
			error(kvm->flags & MAPFILE_FOUND ? INFO : FATAL,
			    "checksum mismatch between %s and %s\n\n",
				pc->dumpfile, filename);
			goto bailout;
		}
		kvm->mapfd = fd;
		kvm->flags |= MAPFILE;
		return TRUE;
	} 

bailout:
	close(fd);
	return FALSE;
}

static int
kvmdump_mapfile_exists(void)
{
	char *filename;
	struct stat stat;

	if (!(filename = malloc(strlen(pc->dumpfile) + strlen(".map") + 10))) 
		return FALSE;

	sprintf(filename, "%s.map", pc->dumpfile);

	if (!file_exists(filename, &stat) || !S_ISREG(stat.st_mode)) {
		free(filename);
		return FALSE;
	}

	if (is_kvmdump_mapfile(filename)) {
		pc->kvmdump_mapfile = filename;
		kvm->flags |= MAPFILE_FOUND;
		return TRUE;
	}

	free(filename);
	return FALSE;
}

void
cmd_map(void)
{
	int c;
	int append, file, specified;
	char *mapfile;

	append = file = specified = 0;
	mapfile = NULL;

        while ((c = getopt(argcnt, args, "af")) != EOF) {
                switch(c)
		{
		case 'a':
			append++;
			break;
		case 'f':
			file++;
			break;
		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

        while (args[optind]) {
		if (!mapfile) {
			mapfile = args[optind];	
			specified++;
		} else
			cmd_usage(pc->curcmd, SYNOPSIS);
		optind++;
	}

	if (file && !specified) {
		mapfile = GETBUF(strlen(pc->dumpfile)+10);
		sprintf(mapfile, "%s.map", pc->dumpfile);
	}

	if (append)
		kvmdump_mapfile_append();

	if (file) {
		kvmdump_mapfile_create(mapfile);
		if (!specified)
			FREEBUF(mapfile);
	}

	if (!file && !append)
		fprintf(fp, "MAP FILE IN USE: %s\n", mapfile_in_use());
}

static char *
mapfile_in_use(void)
{
	char *name;

	switch (kvm->flags & (TMPFILE|MAPFILE|MAPFILE_APPENDED))
	{
	default:
	case TMPFILE:
	case TMPFILE|MAPFILE_APPENDED:
		name = "(tmpfile)";
		break;
	case MAPFILE:
	case MAPFILE|MAPFILE_APPENDED:
		name = pc->kvmdump_mapfile;
		break;
	case MAPFILE_APPENDED:
		name = pc->dumpfile;
		break;
	}

	return name;
}

static void
write_mapfile_trailer(void)
{
	if (kvm->cpu_devices)
		write_mapfile_registers();

        kvm->mapinfo.magic = MAPFILE_MAGIC;

        if (lseek(kvm->mapfd, 0, SEEK_END) < 0)
		error(FATAL, "%s: lseek: %s\n", mapfile_in_use(), strerror(errno));

	if (write(kvm->mapfd, &kvm->mapinfo, sizeof(struct mapinfo_trailer)) 
	    != sizeof(struct mapinfo_trailer))
		error(FATAL, "%s: write: %s\n", mapfile_in_use(), strerror(errno));
}

static void
write_mapfile_registers(void)
{
	size_t regs_size;
	uint64_t magic;

        if (lseek(kvm->mapfd, 0, SEEK_END) < 0)
		error(FATAL, "%s: lseek: %s\n", mapfile_in_use(), strerror(errno));

	regs_size = sizeof(struct register_set) * kvm->cpu_devices;
	if (write(kvm->mapfd, &kvm->registers[0], regs_size) != regs_size)
		error(FATAL, "%s: write: %s\n", mapfile_in_use(), strerror(errno));

	if (write(kvm->mapfd, &kvm->cpu_devices, sizeof(uint64_t)) != sizeof(uint64_t))
		error(FATAL, "%s: write: %s\n", mapfile_in_use(), strerror(errno));

	magic = REGS_MAGIC;
	if (write(kvm->mapfd, &magic, sizeof(uint64_t)) != sizeof(uint64_t))
		error(FATAL, "%s: write: %s\n", mapfile_in_use(), strerror(errno));
}

static void
read_mapfile_trailer(void)
{
	off_t eof;
	struct mapinfo_trailer trailer;

	if ((eof = lseek(kvm->mapfd, 0, SEEK_END)) < 0)
		error(FATAL, "%s: lseek: %s\n", 
			mapfile_in_use(), strerror(errno));

	if (lseek(kvm->mapfd, eof - sizeof(trailer), SEEK_SET) < 0)
		error(FATAL, "%s: lseek: %s\n", 
			mapfile_in_use(), strerror(errno));

	if (read(kvm->mapfd, &trailer, sizeof(trailer)) != sizeof(trailer))
		error(FATAL, "%s: read: %s\n", 
			mapfile_in_use(), strerror(errno));

	if (kvm->mapinfo.checksum != trailer.checksum)
		error(FATAL, "checksum mismatch between %s and %s\n",
			pc->dumpfile, mapfile_in_use());

	kvm->mapinfo = trailer;

	read_mapfile_registers();
}

static void
read_mapfile_registers(void)
{
	size_t regs_size;
	uint64_t ncpus, magic;
	off_t offset;

	if ((offset = lseek(kvm->mapfd, 0, SEEK_END)) < 0)
		error(FATAL, "%s: lseek: %s\n", 
			mapfile_in_use(), strerror(errno));

	offset -= sizeof(struct mapinfo_trailer) + 
		sizeof(magic) + sizeof(ncpus);

        if (lseek(kvm->mapfd, offset, SEEK_SET) < 0)
                error(FATAL, "%s: lseek: %s\n",
                        mapfile_in_use(), strerror(errno));

	if (read(kvm->mapfd, &ncpus, sizeof(uint64_t)) != sizeof(uint64_t))
		error(FATAL, "%s: read: %s\n", 
			mapfile_in_use(), strerror(errno));

	if (read(kvm->mapfd, &magic, sizeof(uint64_t)) != sizeof(uint64_t))
		error(FATAL, "%s: read: %s\n", 
			mapfile_in_use(), strerror(errno));

	if ((magic != REGS_MAGIC) || (ncpus >= NR_CPUS)) {
		kvm->flags |= REGS_NOT_AVAIL;
		return;
	}

	regs_size = sizeof(struct register_set) * ncpus;
	offset -= regs_size;
        if (lseek(kvm->mapfd, offset, SEEK_SET) < 0)
                error(FATAL, "%s: lseek: %s\n",
                        mapfile_in_use(), strerror(errno));

	if (read(kvm->mapfd, &kvm->registers[0], regs_size) != regs_size)
		error(FATAL, "%s: read: %s\n", 
			mapfile_in_use(), strerror(errno));

	kvm->cpu_devices = ncpus;
	kvm->flags |= REGS_FROM_MAPFILE;
}

void
set_kvmhost_type(char *host)
{
	if (!machine_type("X86")) {
		error(INFO, 
		    "--kvmhost is only applicable to the X86 architecture\n");
		return;
	}

	if (STREQ(host, "32")) {
		kvm->flags &= ~KVMHOST_64;
		kvm->flags |= KVMHOST_32;
	} else if (STREQ(host, "64")) {
		kvm->flags &= ~KVMHOST_32;
		kvm->flags |= KVMHOST_64;
	} else
		error(INFO, "invalid --kvmhost argument: %s\n", host);
}

/*
 *  set_kvm_iohole() is called from main() with a command line argument,
 *  or from the x86/x86_64_init functions for assistance in determining
 *  the I/O hole size.
 */
void
set_kvm_iohole(char *optarg)
{
#define DEFAULT_IOHOLE() \
	((kvm->mapinfo.cpu_version_id <= 9) ? 0x40000000 : 0x20000000)
#define E820_RAM 1

	if (optarg) {
		ulong flags;
		ulonglong iohole;
		char *arg;
	
		flags = LONG_LONG;
		if (IS_A_NUMBER(&LASTCHAR(optarg)))
			flags |= HEX_BIAS;
	
		arg = strdup(optarg);
	
		if (!calculate(arg, NULL, &iohole, flags))
			error(FATAL, 
			    "invalid --kvm_iohole argument: %s\n", optarg);
	
		free(arg);
	
		/*
		 *  Only 512MB or 1GB have been used to date.
		 */
		if ((iohole != 0x20000000ULL) && (iohole != 0x40000000ULL))
			error(WARNING, "questionable --kvmio argument: %s\n", 
				optarg);

		kvm->iohole = iohole;

	} else {
	        int nr_map, i;
	        char *buf, *e820entry;
	        ulonglong addr, size, ending_addr;
	        uint type;

		if (kvm->iohole)
			return;   /* set by command line option below */

		kvm->iohole = DEFAULT_IOHOLE();

		if (!symbol_exists("e820"))
			return;

	        buf = (char *)GETBUF(SIZE(e820map));
	        if (!readmem(symbol_value("e820"), KVADDR, &buf[0], 
		    SIZE(e820map), "e820map", RETURN_ON_ERROR|QUIET)) {
			FREEBUF(buf);
			return;
		}

		nr_map = INT(buf + OFFSET(e820map_nr_map));

		for (i = 0; i < nr_map; i++) {
                	e820entry = buf + sizeof(int) + (SIZE(e820entry) * i);
                	addr = ULONGLONG(e820entry + OFFSET(e820entry_addr));
			size = ULONGLONG(e820entry + OFFSET(e820entry_size));
                	type = UINT(e820entry + OFFSET(e820entry_type));

			if (type != E820_RAM)
				continue;
			if (addr >= 0x100000000ULL)
				break;
			
			ending_addr = addr + size;
			if ((ending_addr > 0xc0000000ULL) && 
			    (ending_addr <= 0xe0000000ULL)) {
				kvm->iohole = 0x20000000ULL;
				break;
			}
        	}

		FREEBUF(buf);
	}
}

#include "qemu-load.h"

int
kvmdump_regs_store(uint32_t cpu, struct qemu_device_x86 *dx86)
{
	struct register_set *rp;
	int retval;

	retval = TRUE;

	switch (cpu)
	{
	case KVMDUMP_REGS_START:
		if ((kvm->registers = 
		    calloc(NR_CPUS, sizeof(struct register_set))) == NULL)
			error(FATAL, "kvmdump_regs_store: "
				"cannot malloc KVM register_set array\n");
		kvm->cpu_devices = 0;
		break;

	case KVMDUMP_REGS_END:
		if (kvm->cpu_devices == 0) {
			free(kvm->registers);
			kvm->registers = NULL;
		} else if ((kvm->registers = realloc(kvm->registers, 
		    	sizeof(struct register_set) * kvm->cpu_devices)) == NULL) 
			error(FATAL, "kvmdump_regs_store: "
				"cannot realloc KVM registers array\n");
		break;

	default:
		if (cpu >= NR_CPUS) {
			if (machine_type("X86") && 
		    	    !(kvm->flags & (KVMHOST_32|KVMHOST_64)))
				return FALSE;
			break;
		}

		rp = &kvm->registers[cpu];
		rp->ip = dx86->eip;
		rp->flags = dx86->eflags;
		rp->cs = dx86->cs.selector;
		rp->ss = dx86->ss.selector;
		rp->ds = dx86->ds.selector;
		rp->es = dx86->es.selector;
		rp->fs = dx86->fs.selector;
		rp->gs = dx86->gs.selector;
		BCOPY(dx86->regs, rp->regs, 16*sizeof(uint64_t));
		kvm->cpu_devices = cpu+1;
		kvm->flags |= REGS_FROM_DUMPFILE;

		if (machine_type("X86_64") || 
		    (kvm->flags & (KVMHOST_32|KVMHOST_64)))
			break;

		if ((rp->regs[R_EAX] & UPPER_32_BITS) ||
		    (rp->regs[R_EBX] & UPPER_32_BITS) ||
		    (rp->regs[R_ECX] & UPPER_32_BITS) ||
		    (rp->regs[R_EDX] & UPPER_32_BITS) ||
		    (rp->regs[R_ESI] & UPPER_32_BITS) ||
		    (rp->regs[R_EDI] & UPPER_32_BITS) ||
		    (rp->regs[R_ESP] & UPPER_32_BITS) ||
		    (rp->regs[R_EBP] & UPPER_32_BITS) ||
		    (rp->ip & UPPER_32_BITS))
			retval = FALSE;

		break;
	}

	return retval;
}

int 
get_kvm_register_set(int cpu, struct kvm_register_set *krs)
{
	struct register_set *rs = &kvm->registers[cpu];

	if (!krs)
		return FALSE;

	if (machine_type("X86") || machine_type("X86_64")) {
		krs->x86.cs = rs->cs;
		krs->x86.ss = rs->ss;
		krs->x86.ds = rs->ds;
		krs->x86.es = rs->es;
		krs->x86.fs = rs->fs;
		krs->x86.gs = rs->gs;
		krs->x86.ip = rs->ip;
		krs->x86.flags = rs->flags;
		krs->x86.regs[0] = rs->regs[0];
		krs->x86.regs[1] = rs->regs[1];
		krs->x86.regs[2] = rs->regs[2];
		krs->x86.regs[3] = rs->regs[3];
		krs->x86.regs[4] = rs->regs[4];
		krs->x86.regs[5] = rs->regs[5];
		krs->x86.regs[6] = rs->regs[6];
		krs->x86.regs[7] = rs->regs[7];
		krs->x86.regs[8] = rs->regs[8];
		krs->x86.regs[9] = rs->regs[9];
		krs->x86.regs[10] = rs->regs[10];
		krs->x86.regs[11] = rs->regs[11];
		krs->x86.regs[12] = rs->regs[12];
		krs->x86.regs[13] = rs->regs[13];
		krs->x86.regs[14] = rs->regs[14];
		krs->x86.regs[15] = rs->regs[15];
	
		return TRUE;
	}

	return FALSE;
}
