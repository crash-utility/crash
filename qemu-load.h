/*
 * Qemu save VM file description
 *
 * Copyright (C) 2009 Red Hat, Inc.
 * Written by Paolo Bonzini.
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

#ifndef QEMU_LOAD_H
#define QEMU_LOAD_H 1

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

enum qemu_save_section {
  QEMU_VM_EOF,
  QEMU_VM_SECTION_START,
  QEMU_VM_SECTION_PART,
  QEMU_VM_SECTION_END,
  QEMU_VM_SECTION_FULL,
  QEMU_VM_SUBSECTION,
  QEMU_VM_CONFIGURATION = 0x07,
  QEMU_VM_SECTION_FOOTER = 0x7e
};

enum qemu_features {
  QEMU_FEATURE_RAM = 1,
  QEMU_FEATURE_CPU = 2,
  QEMU_FEATURE_TIMER = 4,
  QEMU_FEATURE_KVM = 8
};

struct qemu_device_list {
	struct qemu_device	*head, *tail;
	uint32_t		features;
};

struct qemu_device_loader {
	const char	   *name;
	struct qemu_device *(*init_load) (struct qemu_device_list *, uint32_t,
					  uint32_t, uint32_t, bool, FILE *);
};

struct qemu_device_vtbl {
	const char	   *name;
	uint32_t	   (*load) (struct qemu_device *, FILE *,
				    enum qemu_save_section);
	void		   (*free) (struct qemu_device *,
				    struct qemu_device_list *);
};

struct qemu_device {
	struct qemu_device_vtbl *vtbl;
	struct qemu_device_list *list;
	struct qemu_device	*next;
	struct qemu_device	*prev;
	uint32_t		section_id;
	uint32_t		instance_id;
	uint32_t		version_id;
};

struct qemu_device_ram {
	struct qemu_device	dev_base;
	uint64_t		last_ram_offset;
	FILE			*fp;
	off_t			*offsets;
};

union qemu_uint128_t {
	uint32_t	i[4];
	unsigned	i128 __attribute__ ((vector_size (16)));
};

struct qemu_x86_seg {
	uint64_t	base;
	uint32_t	selector;
	uint32_t	limit;
	uint32_t	flags;
};

struct qemu_x86_sysenter {
	uint32_t	cs;
	uint64_t	esp;
	uint64_t	eip;
};

union qemu_fpu_reg {
	long double	ld;
	char		bytes[10];
	uint64_t	mmx;
};


struct qemu_x86_vmtrr {
	uint64_t		base;
	uint64_t		mask;
};

struct qemu_x86_svm {
	uint64_t		hsave;
	uint64_t		vmcb;
	uint64_t		tsc_offset;
	uint8_t			in_vmm : 1;
	uint8_t			guest_if_mask : 1;
	uint8_t			guest_intr_masking : 1;
	uint16_t		cr_read_mask;
	uint16_t		cr_write_mask;
	uint16_t		dr_read_mask;
	uint16_t		dr_write_mask;
	uint32_t		exception_intercept_mask;
	uint64_t		intercept_mask;
};

struct qemu_x86_kvm {
	uint64_t		int_bitmap[4];
	uint64_t		tsc;
	uint32_t		mp_state;
	uint32_t		exception_injected;
	uint8_t			soft_interrupt;
	uint8_t			nmi_injected;
	uint8_t			nmi_pending;
	uint8_t			has_error_code;
	uint32_t		sipi_vector;
	uint64_t		system_time_msr;
	uint64_t		wall_clock_msr;
};

struct qemu_x86_mce {
	uint64_t		mcg_cap;
	uint64_t		mcg_status;
	uint64_t		mcg_ctl;
	uint64_t		mce_banks[10 * 4];
};

struct qemu_device_x86 {
	struct qemu_device	dev_base;

	uint32_t		halted;
	uint32_t		irq;

	uint64_t		regs[16];
	uint64_t		eip;
	uint64_t		eflags;
	uint16_t		fpucw;
	uint16_t		fpusw;
	uint16_t		fpu_free;
	union qemu_fpu_reg	st[8];
	struct qemu_x86_seg	cs;
	struct qemu_x86_seg	ds;
	struct qemu_x86_seg	es;
	struct qemu_x86_seg	ss;
	struct qemu_x86_seg	fs;
	struct qemu_x86_seg	gs;
	struct qemu_x86_seg	ldt;
	struct qemu_x86_seg	tr;
	struct qemu_x86_seg	gdt;
	struct qemu_x86_seg	idt;
	struct qemu_x86_sysenter sysenter;
	uint64_t		cr0;
	uint64_t		cr2;
	uint64_t		cr3;
	uint64_t		cr4;
	uint64_t		dr[8];
	uint8_t			cr8;
	uint8_t			soft_mmu : 1;
	uint8_t			smm : 1;
	uint8_t			a20_masked : 1;
	uint8_t			global_if : 1;
	uint8_t			in_nmi : 1;
	uint32_t		mxcsr;
	union qemu_uint128_t	xmm[16];
	uint64_t		efer;
	uint64_t		star;
	uint64_t		lstar;
	uint64_t		cstar;
	uint64_t		fmask;
	uint64_t		kernel_gs_base;
	uint64_t		pat;
	uint32_t		smbase;
	struct qemu_x86_svm	svm;
	uint64_t		fixed_mtrr[11];
	uint64_t		deftype_mtrr;
	struct qemu_x86_vmtrr	variable_mtrr[8];
	struct qemu_x86_kvm	kvm;
	struct qemu_x86_mce	mce;
	uint64_t		tsc_aux;
	uint64_t		xcr0;
	uint64_t		xstate_bv;
	union qemu_uint128_t	ymmh_regs[16];
};

struct qemu_timer {
	uint64_t		cpu_ticks_offset;
	uint64_t		ticks_per_sec;
	uint64_t		cpu_clock_offset;
};

struct qemu_device *device_alloc (struct qemu_device_list *, size_t,
				  struct qemu_device_vtbl *, uint32_t,
				  uint32_t, uint32_t);
void device_free (struct qemu_device *);
void device_list_free (struct qemu_device_list *);
struct qemu_device *device_find (struct qemu_device_list *, uint32_t);
struct qemu_device *device_find_instance (struct qemu_device_list *,
					  const char *, uint32_t);

struct qemu_device_list *qemu_load (const struct qemu_device_loader *,
				    uint32_t, FILE *);

int ram_read_phys_page (struct qemu_device_ram *, void *, uint64_t);

/* For a 32-bit KVM host.  */
extern const struct qemu_device_loader devices_x86_32[];

/* For a 64-bit KVM host.  */
extern const struct qemu_device_loader devices_x86_64[];

#endif
