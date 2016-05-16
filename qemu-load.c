/*
 * Qemu save VM loader
 *
 * Copyright (C) 2009, 2010, 2011 Red Hat, Inc.
 * Written by Paolo Bonzini.
 *
 * Portions Copyright (C) 2009 David Anderson
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

#define _GNU_SOURCE
#include "qemu-load.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>

#include "kvmdump.h"

struct qemu_device *
device_alloc (struct qemu_device_list *dl, size_t sz,
	     struct qemu_device_vtbl *vtbl,
             uint32_t section_id, uint32_t instance_id, uint32_t version_id)
{
	struct qemu_device *d = calloc (1, sz);
	d->vtbl = vtbl;
	d->list = dl;
	d->section_id = section_id;
	d->instance_id = instance_id;
	d->version_id = version_id;

	if (!dl->head)
		dl->head = dl->tail = d;
	else {
		dl->tail->next = d;
		d->prev = dl->tail;
		dl->tail = d;
	}
	return d;
}

struct qemu_device *
device_find (struct qemu_device_list *dl, uint32_t section_id)
{
	struct qemu_device *d;
	d = dl->head;
	while (d && d->section_id != section_id)
		d = d->next;

	return d;
}

struct qemu_device *
device_find_instance (struct qemu_device_list *dl, const char *name,
		      uint32_t instance_id)
{
	struct qemu_device *d;
	d = dl->head;
	while (d && (strcmp (d->vtbl->name, name) || d->instance_id != instance_id))
		d = d->next;

	return d;
}

void
device_free (struct qemu_device *d)
{
	struct qemu_device_list *dl = d->list;
	if (d->prev)
		d->prev->next = d->next;
	else
		dl->head = d->next;
	if (d->next)
		d->next->prev = d->prev;
	else
		dl->tail = d->prev;

	d->prev = d->next = NULL;
	if (d->vtbl->free)
		d->vtbl->free (d, dl);
}

void
device_list_free (struct qemu_device_list *l)
{
	if (!l)
		return;

	while (l->head)
		device_free (l->head);
}


/* File access.  */

static inline uint16_t
get_be16 (FILE *fp)
{
	uint8_t a = getc (fp);
	uint8_t b = getc (fp);
	return (a << 8) | b;
}

static inline uint16_t
get_le16 (FILE *fp)
{
	uint8_t b = getc (fp);
	uint8_t a = getc (fp);
	return (a << 8) | b;
}

static inline uint32_t
get_be32 (FILE *fp)
{
	uint16_t a = get_be16 (fp);
	uint16_t b = get_be16 (fp);
	return (a << 16) | b;
}

static inline uint32_t
get_le32 (FILE *fp)
{
	uint16_t b = get_le16 (fp);
	uint16_t a = get_le16 (fp);
	return (a << 16) | b;
}

static inline uint64_t
get_be64 (FILE *fp)
{
	uint32_t a = get_be32 (fp);
	uint32_t b = get_be32 (fp);
	return ((uint64_t)a << 32) | b;
}

static inline uint64_t
get_le64 (FILE *fp)
{
	uint32_t b = get_le32 (fp);
	uint32_t a = get_le32 (fp);
	return ((uint64_t)a << 32) | b;
}

static inline void
get_qemu128 (FILE *fp, union qemu_uint128_t *result)
{
	result->i[1] = get_le32 (fp);
	result->i[0] = get_le32 (fp);
	result->i[3] = get_le32 (fp);
	result->i[2] = get_le32 (fp);
}




/* RAM loader.  */

#define RAM_SAVE_FLAG_FULL	0x01
#define RAM_SAVE_FLAG_COMPRESS	0x02
#define RAM_SAVE_FLAG_MEM_SIZE	0x04
#define RAM_SAVE_FLAG_PAGE	0x08
#define RAM_SAVE_FLAG_EOS	0x10
#define RAM_SAVE_FLAG_CONTINUE	0x20
#define RAM_SAVE_ADDR_MASK	(~4095LL)

#define RAM_OFFSET_COMPRESSED	(~(off_t)255)

static void
ram_alloc (struct qemu_device_ram *dram, uint64_t size)
{
//	size_t old_npages = dram->offsets ? 0 : dram->last_ram_offset / 4096;
//	size_t new_npages = size / 4096;
//	assert (size <= SIZE_MAX);
//	if (dram->offsets)
//		dram->offsets = realloc (dram->offsets,
//					 new_npages * sizeof (off_t));
//	else
//		dram->offsets = malloc (new_npages * sizeof (off_t));
//
//	assert (dram->offsets);
//	while (old_npages < new_npages)
//		dram->offsets[old_npages++] = RAM_OFFSET_COMPRESSED | 0;

	dram->last_ram_offset = size;
}

#ifndef ATTRIBUTE_UNUSED
#define ATTRIBUTE_UNUSED __attribute__ ((__unused__))
#endif

static int
get_string (FILE *fp, char *name)
{
	size_t items ATTRIBUTE_UNUSED;
	int sz = (uint8_t) getc (fp);
	if (sz == EOF)
		return -1;
	items = fread (name, sz, 1, fp);
	name[sz] = 0;
	return sz;
}
static int
get_string_len (FILE *fp, char *name, uint32_t sz)
{
	size_t items ATTRIBUTE_UNUSED;
	if (sz == EOF)
		return -1;
	items = fread (name, sz, 1, fp);
	name[sz] = 0;
	return sz;
}

static void
ram_read_blocks (FILE *fp, uint64_t size)
{
	char name[257];
	/* The RAM block table is a list of block names followed by
	   their sizes.  Read it until the sizes sum up to SIZE bytes.  */
	while (size) {
		get_string (fp, name);
		size -= get_be64 (fp);
	}
}

static uint32_t
ram_load (struct qemu_device *d, FILE *fp, enum qemu_save_section sec)
{
	char name[257];
	struct qemu_device_ram *dram = (struct qemu_device_ram *)d;
	uint64_t header;
	static int pc_ram = 0;

	for (;;) {
		uint64_t addr;
		off_t entry;

		header = get_be64 (fp);
		if (feof (fp) || ferror (fp))
			return 0;
		if (header & RAM_SAVE_FLAG_EOS)
			break;

		assert (!(header & RAM_SAVE_FLAG_FULL));

		addr = header & RAM_SAVE_ADDR_MASK;

		if (header & RAM_SAVE_FLAG_MEM_SIZE) {
			ram_alloc (dram, addr);
			if (d->version_id >= 4)
				ram_read_blocks(fp, addr);
			continue;
		}

		if (d->version_id >= 4 && !(header & RAM_SAVE_FLAG_CONTINUE)) {
			get_string(fp, name);
			if (strcmp(name, "pc.ram") == 0)
				pc_ram = 1;
			else
				pc_ram = 0;
		}

		if (header & RAM_SAVE_FLAG_COMPRESS) {
			entry = RAM_OFFSET_COMPRESSED | getc(fp);
			if ((d->version_id == 3) || 
			    (d->version_id >= 4 && pc_ram))
				store_mapfile_offset(addr, &entry);
		}
		else if (header & RAM_SAVE_FLAG_PAGE) {
			entry = ftell(fp);
			if ((d->version_id == 3) || 
			    (d->version_id >= 4 && pc_ram))
				store_mapfile_offset(addr, &entry);
			fseek (fp, 4096, SEEK_CUR);
		}
	}

	dram->fp = fp;
	return QEMU_FEATURE_RAM;
}

static void
ram_free (struct qemu_device *d, struct qemu_device_list *dl)
{
	struct qemu_device_ram *dram = (struct qemu_device_ram *)d;
	free (dram->offsets);
}

int
ram_read_phys_page (struct qemu_device_ram *dram, void *buf, uint64_t addr)
{
	off_t ofs;
	ssize_t bytes ATTRIBUTE_UNUSED;

        if (addr >= dram->last_ram_offset)
                return false;
        assert ((addr & 0xfff) == 0);
//	ofs = dram->offsets[addr / 4096];
	if (load_mapfile_offset(addr, &ofs) < 0)
		return 0;
	if ((ofs & RAM_OFFSET_COMPRESSED) == RAM_OFFSET_COMPRESSED)
		memset (buf, ofs & 255, 4096);
	else
	        bytes = pread (fileno (dram->fp), buf, 4096, ofs);
	return true;
}

static struct qemu_device *
ram_init_load (struct qemu_device_list *dl,
	       uint32_t section_id, uint32_t instance_id,
	       uint32_t version_id, bool live, FILE *fp)
{
	static struct qemu_device_vtbl ram = {
		"ram", 
		ram_load, 
		ram_free
	};

	assert (version_id == 3 || version_id == 4);
	kvm->mapinfo.ram_version_id = version_id;
	return device_alloc (dl, sizeof (struct qemu_device_ram),
			     &ram, section_id, instance_id, version_id);
}


#define BLK_MIG_FLAG_EOS 2

static uint32_t
block_load (struct qemu_device *d, FILE *fp, enum qemu_save_section sec)
{
	uint64_t header;

	header = get_be64 (fp);
	assert (header == BLK_MIG_FLAG_EOS);
	return 0;
}

static struct qemu_device *
block_init_load (struct qemu_device_list *dl,
		 uint32_t section_id, uint32_t instance_id,
		 uint32_t version_id, bool live, FILE *fp)
{
	static struct qemu_device_vtbl block = {
		"block",
		block_load, 
		NULL
	};

	return device_alloc (dl, sizeof (struct qemu_device),
			     &block, section_id, instance_id, version_id);
}

/* RHEL5 marker.  */

static uint32_t
rhel5_marker_load (struct qemu_device *d, FILE *fp, enum qemu_save_section sec)
{
	return 0;
}

static struct qemu_device *
rhel5_marker_init_load (struct qemu_device_list *dl,
		      uint32_t section_id, uint32_t instance_id,
		      uint32_t version_id, bool live, FILE *fp)
{
	static struct qemu_device_vtbl rhel5_marker = {
		"__rhel5",
		rhel5_marker_load, 
		NULL
	};

	assert (!live);
	return device_alloc (dl, sizeof (struct qemu_device),
			     &rhel5_marker, section_id, instance_id,
			     version_id);
}



/* cpu_common loader.  */

struct qemu_device_cpu_common {
	struct qemu_device	base;
	uint32_t		halted;
	uint32_t		irq;
};

static uint32_t
cpu_common_load (struct qemu_device *d, FILE *fp, enum qemu_save_section sec)
{
	struct qemu_device_cpu_common *cpu = (struct qemu_device_cpu_common *)d;
	cpu->halted = get_be32 (fp);
	cpu->irq = get_be32 (fp);
	return 0;
}

static struct qemu_device *
cpu_common_init_load (struct qemu_device_list *dl,
		      uint32_t section_id, uint32_t instance_id,
		      uint32_t version_id, bool live, FILE *fp)
{
	static struct qemu_device_vtbl cpu_common = {
		"cpu_common",
		cpu_common_load, 
		NULL
	};

	assert (!live);
	return device_alloc (dl, sizeof (struct qemu_device_cpu_common),
			     &cpu_common, section_id, instance_id, version_id);
}



/* CPU loader.  */

static inline uint64_t
get_be_long (FILE *fp, int size)
{
	uint32_t a = size == 32 ? 0 : get_be32 (fp);
	uint32_t b = get_be32 (fp);
	return ((uint64_t)a << 32) | b;
}

static inline void
get_be_fp80 (FILE *fp, union qemu_fpu_reg *result)
{
	result->mmx = get_be64 (fp);
	result->bytes[9] = getc (fp);
	result->bytes[8] = getc (fp);
}

static void
cpu_load_seg (FILE *fp, struct qemu_x86_seg *seg, int size)
{
	seg->selector = get_be32 (fp);
	seg->base = get_be_long (fp, size);
	seg->limit = get_be32 (fp);
	seg->flags = get_be32 (fp);
}

static bool
v12_has_xsave_state(FILE *fp)
{
	char name[257];
	bool ret = true;
	long offset = ftell(fp); // save offset

        /*
	 * peek into byte stream to check for APIC vmstate
	 */
	if (getc(fp) == QEMU_VM_SECTION_FULL) {
		get_be32(fp); // skip section id
		get_string(fp, name);
		if (strcmp(name, "apic") == 0)
			ret = false;
	}
	fseek(fp, offset, SEEK_SET); // restore offset

	return ret;
}

static uint32_t
cpu_load (struct qemu_device *d, FILE *fp, int size)
{
	struct qemu_device_x86 *dx86 = (struct qemu_device_x86 *)d;
	uint32_t qemu_hflags = 0, qemu_hflags2 = 0;
	int nregs;
	uint32_t version_id = dx86->dev_base.version_id;
	uint32_t rhel5_version_id;
	int i;
	off_t restart;

	struct qemu_device *drhel5;
	struct qemu_device_cpu_common *dcpu;

	if (kvm->flags & KVMHOST_32)
		size = 32;
	restart = ftello(fp);
retry:
	nregs = size == 32 ? 8 : 16;
	drhel5 = device_find_instance (d->list, "__rhel5", 0);
	if (drhel5 || (version_id >= 7 && version_id <= 9)) {
		rhel5_version_id = version_id;
		version_id = 7;
	} else {
		rhel5_version_id = 0;
	       	version_id = dx86->dev_base.version_id;
	}

	dprintf("cpu_load: rhel5_version_id: %d (effective) version_id: %d\n",
		rhel5_version_id, version_id);

	dcpu = (struct qemu_device_cpu_common *)
		device_find_instance (d->list, "cpu_common", d->instance_id);
	if (dcpu) {
		dx86->halted = dcpu->halted;
		dx86->irq = dcpu->irq;
//		device_free ((struct qemu_device *) dcpu);
	}

	for (i = 0; i < nregs; i++)
		dx86->regs[i] = get_be_long (fp, size);

	dx86->eip = get_be_long (fp, size);
	dx86->eflags = get_be_long (fp, size);
	qemu_hflags = get_be32 (fp);
	dx86->fpucw = get_be16 (fp);
	dx86->fpusw = get_be16 (fp);
	dx86->fpu_free = get_be16 (fp);

	if (get_be16 (fp))
		for (i = 0; i < 8; i++)
			dx86->st[i].mmx = get_be64 (fp);
	else
		for (i = 0; i < 8; i++)
			get_be_fp80 (fp, &dx86->st[i]);

	cpu_load_seg (fp, &dx86->es, size);
	cpu_load_seg (fp, &dx86->cs, size);
	cpu_load_seg (fp, &dx86->ss, size);
	cpu_load_seg (fp, &dx86->ds, size);
	cpu_load_seg (fp, &dx86->fs, size);
	cpu_load_seg (fp, &dx86->gs, size);
	cpu_load_seg (fp, &dx86->ldt, size);
	cpu_load_seg (fp, &dx86->tr, size);
	cpu_load_seg (fp, &dx86->gdt, size);
	cpu_load_seg (fp, &dx86->idt, size);

	dx86->sysenter.cs = get_be32 (fp);
	dx86->sysenter.esp = get_be_long (fp, version_id <= 6 ? 32 : size);
	dx86->sysenter.eip = get_be_long (fp, version_id <= 6 ? 32 : size);

	dx86->cr0 = get_be_long (fp, size);
	dx86->cr2 = get_be_long (fp, size);
	dx86->cr3 = get_be_long (fp, size);
	dx86->cr4 = get_be_long (fp, size);
	for (i = 0; i < 8; i++)
		dx86->dr[i] = get_be_long (fp, size);

	dx86->a20_masked = get_be32 (fp) != 0xffffffff;
	dx86->mxcsr = get_be32 (fp);

	for (i = 0; i < nregs; i++)
		get_qemu128 (fp, &dx86->xmm[i]);

	if (size == 64) {
		dx86->efer = get_be64 (fp);
		dx86->star = get_be64 (fp);
		dx86->lstar = get_be64 (fp);
		dx86->cstar = get_be64 (fp);
		dx86->fmask = get_be64 (fp);
		dx86->kernel_gs_base = get_be64 (fp);
	}

	dx86->smbase = get_be32 (fp);

	dx86->soft_mmu = qemu_hflags	& (1 << 2);
	dx86->smm = qemu_hflags		& (1 << 19);

	if (version_id == 4)
		goto store;

	dx86->pat = get_be64 (fp);
	qemu_hflags2 = get_be32 (fp);
	dx86->global_if = qemu_hflags2	& (1 << 0);
	dx86->in_nmi = qemu_hflags2	& (1 << 2);

	if (version_id < 6)
		dx86->halted = get_be32 (fp);

	dx86->svm.hsave = get_be64 (fp);
	dx86->svm.vmcb = get_be64 (fp);
	dx86->svm.tsc_offset = get_be64 (fp);
	dx86->svm.in_vmm = qemu_hflags	& (1 << 21);
	dx86->svm.guest_if_mask = qemu_hflags2 & (1 << 1);
	dx86->svm.guest_intr_masking = qemu_hflags2 & (1 << 3);
	dx86->svm.intercept_mask = get_be64 (fp);
	dx86->svm.cr_read_mask = get_be16 (fp);
	dx86->svm.cr_write_mask = get_be16 (fp);
	dx86->svm.dr_read_mask = get_be16 (fp);
	dx86->svm.dr_write_mask = get_be16 (fp);
	dx86->svm.exception_intercept_mask = get_be32 (fp);
	dx86->cr8 = getc (fp);

	if (version_id >= 8) {
		for (i = 0; i < 11; i++)
			dx86->fixed_mtrr[i] = get_be64 (fp);
		dx86->deftype_mtrr = get_be64 (fp);
		for (i = 0; i < 8; i++) {
			dx86->variable_mtrr[i].base = get_be64 (fp);
			dx86->variable_mtrr[i].mask = get_be64 (fp);
		}
	}

	/* This was present only when KVM was enabled up to v8.
	 * Furthermore, it changed format in v9.  */
	if (version_id >= 9) {
		int32_t pending_irq = (int32_t) get_be32 (fp);
		if (pending_irq >= 0 && pending_irq <= 255)
			dx86->kvm.int_bitmap[pending_irq / 64] |=
				(uint64_t)1 << (pending_irq & 63);

		dx86->kvm.mp_state = get_be32 (fp);
		dx86->kvm.tsc = get_be64 (fp);
	}

	else if (d->list->features & QEMU_FEATURE_KVM) {
		for (i = 0; i < 4; i++)
			dx86->kvm.int_bitmap[i] = get_be64 (fp);
		dx86->kvm.tsc = get_be64 (fp);
		if (version_id >= 5)
			dx86->kvm.mp_state = get_be32 (fp);
	}

	if (version_id >= 11) {
		dx86->kvm.exception_injected = get_be32 (fp);
	}
	if (rhel5_version_id >= 8) {
		dx86->kvm.system_time_msr = get_be64 (fp);
		dx86->kvm.wall_clock_msr = get_be64 (fp);
	}
	if (version_id >= 11 || rhel5_version_id >= 9) {
		dx86->kvm.soft_interrupt = getc (fp);
		dx86->kvm.nmi_injected = getc (fp);
		dx86->kvm.nmi_pending = getc (fp);
		dx86->kvm.has_error_code = getc (fp);
		dx86->kvm.sipi_vector = get_be32 (fp);
	}

	if (version_id >= 10) {
		dx86->mce.mcg_cap = get_be64 (fp);
		dx86->mce.mcg_status = get_be64 (fp);
		dx86->mce.mcg_ctl = get_be64 (fp);
		for (i = 0; i < 10 * 4; i++)
			dx86->mce.mce_banks[i] = get_be64 (fp);
	}

	if (version_id >= 11) {
		dx86->tsc_aux = get_be64 (fp);
		dx86->kvm.system_time_msr = get_be64 (fp);
		dx86->kvm.wall_clock_msr = get_be64 (fp);
	}

	if (version_id >= 12 && v12_has_xsave_state(fp)) {
		dx86->xcr0 = get_be64 (fp);
		dx86->xstate_bv = get_be64 (fp);

		for (i = 0; i < nregs; i++)
			get_qemu128 (fp, &dx86->ymmh_regs[i]);
	}

store:
	if (!kvmdump_regs_store(d->instance_id, dx86)) {
		size = 32;
		kvm->flags |= KVMHOST_32;
		fseeko(fp, restart, SEEK_SET);
		dprintf("cpu_load: invalid registers: retry with 32-bit host\n");
		goto retry;
	}

	if (dcpu)
		device_free ((struct qemu_device *) dcpu);

	return QEMU_FEATURE_CPU;
}

static uint32_t
cpu_load_32 (struct qemu_device *d, FILE *fp, enum qemu_save_section sec)
{
	return cpu_load (d, fp, 32);
}

static struct qemu_device *
cpu_init_load_32 (struct qemu_device_list *dl,
		  uint32_t section_id, uint32_t instance_id,
		  uint32_t version_id, bool live, FILE *fp)
{
	struct qemu_device_x86 *dx86;
	static struct qemu_device_vtbl cpu = {
		"cpu",
		cpu_load_32,
		NULL
	};

	assert (!live);
//	assert (version_id >= 4 && version_id <= 9);
	assert (version_id >= 4 && version_id <= 12);
	kvm->mapinfo.cpu_version_id = version_id;
	dx86 = (struct qemu_device_x86 *)
		device_alloc (dl, sizeof (struct qemu_device_x86),
			      &cpu, section_id, instance_id, version_id);
	return (struct qemu_device *) dx86;
}

static uint32_t
cpu_load_64 (struct qemu_device *d, FILE *fp, enum qemu_save_section sec)
{
	return cpu_load (d, fp, 64);
}

static struct qemu_device *
cpu_init_load_64 (struct qemu_device_list *dl,
		  uint32_t section_id, uint32_t instance_id,
		  uint32_t version_id, bool live, FILE *fp)
{
	struct qemu_device_x86 *dx86;
	static struct qemu_device_vtbl cpu = {
		"cpu",
		cpu_load_64, 
		NULL
	};

	assert (!live);
//	assert (version_id >= 4 && version_id <= 9);
	assert (version_id >= 4 && version_id <= 12);
	kvm->mapinfo.cpu_version_id = version_id;
	dx86 = (struct qemu_device_x86 *)
		device_alloc (dl, sizeof (struct qemu_device_x86),
			      &cpu, section_id, instance_id, version_id);
	return (struct qemu_device *) dx86;
}


/* IOAPIC loader.  */

static uint32_t
apic_load (struct qemu_device *d, FILE *fp, enum qemu_save_section sec)
{
	switch (d->version_id) {
	case 1: fseek (fp, 173, SEEK_CUR); break;
	case 2:
	case 3: fseek (fp, 181, SEEK_CUR); break;
	}

	return 0;
}

static struct qemu_device *
apic_init_load (struct qemu_device_list *dl,
		       uint32_t section_id, uint32_t instance_id,
		       uint32_t version_id, bool live, FILE *fp)
{
	static struct qemu_device_vtbl apic = {
		"apic",
		apic_load, 
		NULL
	};

	assert (!live);
	return device_alloc (dl, sizeof (struct qemu_device),
			     &apic, section_id, instance_id, version_id);
}



/* timer loader.  */

static uint32_t
timer_load (struct qemu_device *d, FILE *fp, enum qemu_save_section sec)
{
	fseek (fp, 24, SEEK_CUR);
	return QEMU_FEATURE_TIMER;
}

static struct qemu_device *
timer_init_load (struct qemu_device_list *dl,
		       uint32_t section_id, uint32_t instance_id,
		       uint32_t version_id, bool live, FILE *fp)
{
	static struct qemu_device_vtbl timer = {
		"timer",
		timer_load, 
		NULL
	};

	assert (!live);
	return device_alloc (dl, sizeof (struct qemu_device),
			     &timer, section_id, instance_id, version_id);
}


/* kvmclock loader.  */

static uint32_t
kvmclock_load (struct qemu_device *d, FILE *fp, enum qemu_save_section sec)
{
	fseek (fp, 8, SEEK_CUR);
	return QEMU_FEATURE_KVM;
}

static struct qemu_device *
kvmclock_init_load (struct qemu_device_list *dl,
		       uint32_t section_id, uint32_t instance_id,
		       uint32_t version_id, bool live, FILE *fp)
{
	static struct qemu_device_vtbl kvmclock = {
		"kvmclock",
		kvmclock_load, 
		NULL
	};

	assert (!live);
	return device_alloc (dl, sizeof (struct qemu_device),
			     &kvmclock, section_id, instance_id, version_id);
}


/* kvm-tpr-opt loader.  */

static uint32_t
kvm_tpr_opt_load (struct qemu_device *d, FILE *fp, enum qemu_save_section sec)
{
	fseek (fp, 144, SEEK_CUR);
	return QEMU_FEATURE_KVM;
}

static struct qemu_device *
kvm_tpr_opt_init_load (struct qemu_device_list *dl,
		       uint32_t section_id, uint32_t instance_id,
		       uint32_t version_id, bool live, FILE *fp)
{
	static struct qemu_device_vtbl kvm_tpr_opt = {
		"kvm-tpr-opt",
		kvm_tpr_opt_load, 
		NULL
	};

	assert (!live);
	return device_alloc (dl, sizeof (struct qemu_device),
			     &kvm_tpr_opt, section_id, instance_id, version_id);
}


/* Putting it together.  */

const struct qemu_device_loader devices_x86_64[] = {
	{ "__rhel5", rhel5_marker_init_load },
	{ "cpu_common", cpu_common_init_load },
	{ "kvm-tpr-opt", kvm_tpr_opt_init_load },
	{ "kvmclock", kvmclock_init_load },
	{ "cpu", cpu_init_load_64 },
	{ "apic", apic_init_load },
	{ "block", block_init_load },
	{ "ram", ram_init_load },
	{ "timer", timer_init_load },
	{ NULL, NULL }
};

const struct qemu_device_loader devices_x86_32[] = {
	{ "__rhel5", rhel5_marker_init_load },
	{ "cpu_common", cpu_common_init_load },
	{ "kvm-tpr-opt", kvm_tpr_opt_init_load },
	{ "kvmclock", kvmclock_init_load },
	{ "cpu", cpu_init_load_32 },
	{ "apic", apic_init_load },
	{ "block", block_init_load },
	{ "ram", ram_init_load },
	{ "timer", timer_init_load },
	{ NULL, NULL }
};


#define QEMU_VM_FILE_MAGIC	0x5145564D
#define LIBVIRT_QEMU_VM_FILE_MAGIC	0x4c696276

struct libvirt_header {
	char		magic[16];
	uint32_t	version;
	uint32_t	xml_length;
	uint32_t	was_running;
	uint32_t	padding[16];
};

static long device_search(const struct qemu_device_loader *, FILE *);

static struct qemu_device *
device_get (const struct qemu_device_loader *devices,
	    struct qemu_device_list *dl, enum qemu_save_section sec, FILE *fp)
{
	char name[257];
	uint32_t section_id, instance_id, version_id;
//	bool live;
	const struct qemu_device_loader *devp;
	long next_device_offset;

next_device:
	devp = devices;
	if (sec == QEMU_VM_SUBSECTION) {
		get_string(fp, name);
		goto search_device;
	}
	section_id = get_be32 (fp);
	if (sec != QEMU_VM_SECTION_START &&
	    sec != QEMU_VM_SECTION_FULL)
		return device_find (dl, section_id);

	get_string(fp, name);

	instance_id = get_be32 (fp);
	version_id = get_be32 (fp);

	while (devp->name && strcmp (devp->name, name))
		devp++;
	if (!devp->name) {
search_device:
		dprintf("device_get: unknown/unsupported: \"%s\"\n", name);
		if ((next_device_offset = device_search(devices, fp))) {
			fseek(fp, next_device_offset, SEEK_CUR);
			sec = getc(fp);
			if (sec == QEMU_VM_EOF)
				return NULL;
			goto next_device;
		}
		return NULL;
	}

	return devp->init_load (dl, section_id, instance_id, version_id,
				   sec == QEMU_VM_SECTION_START, fp);
}

struct qemu_device_list *
qemu_load (const struct qemu_device_loader *devices, uint32_t required_features,
	   FILE *fp)
{
	struct qemu_device_list *result = NULL;
	struct qemu_device *last = NULL;;
	size_t items ATTRIBUTE_UNUSED;
	uint32_t footerSecId ATTRIBUTE_UNUSED;
	char name[257];

	switch (get_be32 (fp)) {
	case QEMU_VM_FILE_MAGIC:
		break;

	case LIBVIRT_QEMU_VM_FILE_MAGIC: {
		struct libvirt_header header;
		memcpy (header.magic, "Libv", 4);
		items = fread (&header.magic[4], sizeof (header) - 4, 1, fp);
		if (memcmp ("LibvirtQemudSave", header.magic, 16))
			goto fail;

		fseek (fp, header.xml_length, SEEK_CUR);
		if (get_be32 (fp) != QEMU_VM_FILE_MAGIC)
			goto fail;
		break;
	}

	default:
		goto fail;
	}

	if (get_be32 (fp) != 3)
		return NULL;

	dprintf("\n");

	result = calloc (1, sizeof (struct qemu_device_list));
	for (;;) {
		struct qemu_device *d;
		uint32_t features;
		enum qemu_save_section sec = getc (fp);

		if (feof (fp) || ferror (fp))
			break;
		if (sec == QEMU_VM_EOF)
			break;
		if (sec == QEMU_VM_SECTION_FOOTER) {
			footerSecId = get_be32 (fp);
			continue;
                }
		if (sec == QEMU_VM_CONFIGURATION) {
			uint32_t len = get_be32 (fp);
			get_string_len (fp, name, len);
			continue;
                }

		d = device_get (devices, result, sec, fp);
		if (!d)
			break;

		if (d != last) {
			dprintf("qemu_load: \"%s\"\n", d->vtbl->name);
			last = d;
		}

		features = d->vtbl->load (d, fp, sec);
		if (feof (fp) || ferror (fp))
			break;

		if (sec == QEMU_VM_SECTION_END || sec == QEMU_VM_SECTION_FULL)
			result->features |= features;
	}

	if (ferror (fp) ||
	    (result->features & required_features) != required_features)
		goto fail;

	return result;

fail:
	device_list_free (result);
	free (result);
	return NULL;
}

/*
 *  crash utility adaptation.
 */

#include "defs.h"

int
is_qemu_vm_file(char *filename)
{
	struct libvirt_header header;
	FILE *vmp;
	int retval;
	size_t items ATTRIBUTE_UNUSED;
	char *xml;

	if ((vmp = fopen(filename, "r")) == NULL) {
		error(INFO, "%s: %s\n", filename, strerror(errno));
		return FALSE;
	}

	retval = FALSE;
	xml = NULL;

	switch (get_be32(vmp)) 
	{
	case QEMU_VM_FILE_MAGIC:
		retval = TRUE;
		break;

	case LIBVIRT_QEMU_VM_FILE_MAGIC: 
		rewind(vmp);
		items = fread(&header.magic[0], sizeof(header), 1, vmp); 
		if (STRNEQ(header.magic, "LibvirtQemudSave")) {
			if ((xml = (char *)malloc(header.xml_length))) {
				items = fread(xml, header.xml_length, 1, vmp);
				/*
				 *  Parse here if necessary or desirable.
				 */
			} else
				fseek(vmp, header.xml_length, SEEK_CUR);

			if (get_be32(vmp) == QEMU_VM_FILE_MAGIC)
				retval = TRUE;
		}
		break;

	default:
		retval = FALSE;
	}

	if (xml)
		free(xml);

	switch (retval) 
	{
	case TRUE:
		kvm->vmp = vmp;
		kvm->vmfd = fileno(vmp);
		break;
	case FALSE:
		fclose(vmp);
		break;
	}

	return retval;
}

void
dump_qemu_header(FILE *out)
{
	int i;
	struct libvirt_header header;
	char magic[4];
	uint8_t c;
	size_t items ATTRIBUTE_UNUSED;

	rewind(kvm->vmp);
	if (get_be32(kvm->vmp) == QEMU_VM_FILE_MAGIC) {
		fprintf(out, "%s: QEMU_VM_FILE_MAGIC\n", pc->dumpfile);
		return; 
	}

	rewind(kvm->vmp);
	items = fread(&header, sizeof(header), 1, kvm->vmp);

	fprintf(out, "%s: libvirt_header:\n\n", pc->dumpfile);
	fprintf(out, "      magic: ");
	for (i = 0; i < 16; i++)
		fprintf(out, "%c", header.magic[i]);
	fprintf(out, "\n");
	fprintf(out, "      version: %d\n", header.version);
	fprintf(out, "   xml_length: %d\n", header.xml_length);
	fprintf(out, "  was_running: %d\n", header.was_running);
	fprintf(out, "      padding: (not shown)\n\n");
	for (i = 0; i < header.xml_length; i++) {
		c = getc(kvm->vmp);
		if (c)
			fprintf(out, "%c", c);
	}
	fprintf(out, "\n");
	items = fread(&magic, sizeof(char), 4, kvm->vmp);
	for (i = 0; i < 4; i++)
		fprintf(out, "%c", magic[i]);
	fprintf(out, "\n");
}

static long
device_search(const struct qemu_device_loader *devices, FILE *fp)
{
	uint sz;
	char *p1, *p2;
	long next_device_offset;
	long remaining;
	char buf[4096];
	off_t current;

	BZERO(buf, 4096);

	current = ftello(fp);
	if (fread(buf, sizeof(char), 4096, fp) != 4096) {
		fseeko(fp, current, SEEK_SET);
		return 0;
	}
	fseeko(fp, current, SEEK_SET);

        while (devices->name) {
		for (p1 = buf, remaining = 4096; 
	     	    (p2 = memchr(p1, devices->name[0], remaining));
	     	     p1 = p2+1, remaining = 4096 - (p1-buf)) {
			sz = *((unsigned char *)p2-1);
			if (STRNEQ(p2, devices->name) && 
			    (strlen(devices->name) == sz)) {
				*(p2+sz) = '\0';
				dprintf("device_search: %s\n", p2);
				next_device_offset = (p2-buf) - 6;
				return next_device_offset;
			}
		}
		devices++;
	}

	return 0;
}
