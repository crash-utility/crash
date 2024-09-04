/*
 * vmware_guestdump.c
 *
 * Copyright (c) 2020 VMware, Inc.
 * Copyright (c) 2024 Broadcom. All Rights Reserved. The term "Broadcom"
 * refers to Broadcom Inc. and/or its subsidiaries.
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
 * Author: Alexey Makhalov <alexey.makhalov@broadcom.com>
 */

#include "defs.h"
#include "vmware_vmss.h"

#define LOGPRX "vmw: "

/*
 * debug.guest file layout
 * 00000000: guest dump header, it includes:
 *             1. Version (4 bytes)               \
 *             2. Number of Virtual CPUs (4 bytes) } - struct guestdumpheader
 *             3. Reserved gap
 *             4. Main Memory information - struct mainmeminfo{,_old}
 *    (use get_vcpus_offset() to get total size of guestdumpheader)
 * vcpus_offset:               ---------\
 *             1. struct vcpu_state1     \
 *             2. reserved gap            } num_vcpus times
 *             3. struct vcpu_state2     /
 *             4. 4KB of reserved data  /
 *                             --------/
 *
 */
struct guestdumpheader {
	uint32_t version;
	uint32_t num_vcpus;
} __attribute__((packed)) hdr;

struct mainmeminfo {
	uint64_t last_addr;
	uint64_t memsize_in_pages;
	uint32_t reserved1;
	uint32_t mem_holes;
	struct memhole {
		uint64_t ppn;
		uint64_t pages;
	} holes[2];
} __attribute__((packed));

/* Used by version 1 only */
struct mainmeminfo_old {
	uint64_t last_addr;
	uint32_t memsize_in_pages;
	uint32_t reserved1;
	uint32_t mem_holes;
	struct memhole1 {
		uint32_t ppn;
		uint32_t pages;
	} holes[2];
	/* There are additional fields, see get_vcpus_offset() calculation. */
} __attribute__((packed));

/* First half of vcpu_state */
struct vcpu_state1 {
	uint32_t cr0;
	uint64_t cr2;
	uint64_t cr3;
	uint64_t cr4;
	uint64_t reserved1[10];
	uint64_t idt_base;
} __attribute__((packed));

/*
 * Unused fields between vcpu_state1 and vcpu_state2 swill be skipped.
 * See get_vcpu_gapsize() calculation.
 */

/* Second half of vcpu_state */
struct vcpu_state2 {
	struct x86_64_pt_regs {
		uint64_t r15;
		uint64_t r14;
		uint64_t r13;
		uint64_t r12;
		uint64_t rbp;
		uint64_t rbx;
		uint64_t r11;
		uint64_t r10;
		uint64_t r9;
		uint64_t r8;
		uint64_t rax;
		uint64_t rcx;
		uint64_t rdx;
		uint64_t rsi;
		uint64_t rdi;
		uint64_t orig_rax;
		uint64_t rip;
		uint64_t cs;
		uint64_t eflags;
		uint64_t rsp;
		uint64_t ss;
	} regs64;
	uint8_t reserved3[65];
} __attribute__((packed));

/*
 * Returns the size of the guest dump header.
 */
static inline long
get_vcpus_offset(uint32_t version, int mem_holes)
{
	switch (version) {
		case 1: /* ESXi 6.7 and older */
			return sizeof(struct guestdumpheader) + 13 + sizeof(struct mainmeminfo_old) +
				(mem_holes == -1 ? 0 : 8 * mem_holes + 4);
		case 3: /* ESXi 6.8 */
			return sizeof(struct guestdumpheader) + 14 + sizeof(struct mainmeminfo);
		case 4: /* ESXi 7.0 */
		case 5: /* ESXi 8.0 */
			return sizeof(struct guestdumpheader) + 14 + sizeof(struct mainmeminfo);
		case 6: /* ESXi 8.0u2 */
			return sizeof(struct guestdumpheader) + 15 + sizeof(struct mainmeminfo);

	}
	return 0;
}

/*
 * Returns the size of reserved (unused) fields in the middle of vcpu_state structure.
 */
static inline long
get_vcpu_gapsize(uint32_t version)
{
	if (version < 4)
		return 45;
	return 42;
}

/*
 * vmware_guestdump is an extension to the vmware_vmss with ability to debug
 * debug.guest and debug.vmem files.
 *
 * debug.guest.gz and debug.vmem.gz can be obtained using following
 * .vmx options from VM running in debug mode:
 * 	monitor.mini-suspend_on_panic = TRUE
 * 	monitor.suspend_on_triplefault = TRUE
 *
 * guestdump (debug.guest) is a simplified version of the *.vmss which does
 * not contain a full VM state, but minimal guest state, such as a memory
 * layout and CPUs state, needed for debugger. is_vmware_guestdump()
 * and vmware_guestdump_init() functions parse guestdump header and
 * populate vmss data structure (from vmware_vmss.c). In result, all
 * handlers (except mempry_dump) from vmware_vmss.c can be reused.
 *
 * debug.guest does not have a dedicated header magic or file format signature
 * To probe debug.guest we need to perform series of validations. In addition,
 * we check for the filename extension, which must be ".guest".
 */
int
is_vmware_guestdump(char *filename)
{
	struct mainmeminfo mmi;
	long vcpus_offset;
	FILE *fp;
	uint64_t filesize, expected_filesize, holes_sum = 0;
	int i;

	if (strcmp(filename + strlen(filename) - 6, ".guest"))
		return FALSE;

	if ((fp = fopen(filename, "r")) == NULL) {
		error(INFO, LOGPRX"Failed to open '%s': [Error %d] %s\n",
			filename, errno, strerror(errno));
		return FALSE;
	}

	if (fread(&hdr, sizeof(struct guestdumpheader), 1, fp) != 1) {
		error(INFO, LOGPRX"Failed to read '%s' from file '%s': [Error %d] %s\n",
			"guestdumpheader", filename, errno, strerror(errno));
		fclose(fp);
		return FALSE;
	}

	vcpus_offset = get_vcpus_offset(hdr.version, -1 /* Unknown yet, adjust it later */);

	if (!vcpus_offset) {
		if (CRASHDEBUG(1))
			error(INFO, LOGPRX"Not supported version %d\n", hdr.version);
		fclose(fp);
		return FALSE;
	}

	if (hdr.version == 1) {
		struct mainmeminfo_old tmp;
		if (fseek(fp, vcpus_offset - sizeof(struct mainmeminfo_old), SEEK_SET) == -1) {
			if (CRASHDEBUG(1))
				error(INFO, LOGPRX"Failed to fseek '%s': [Error %d] %s\n",
						filename, errno, strerror(errno));
			fclose(fp);
			return FALSE;
		}

		if (fread(&tmp, sizeof(struct mainmeminfo_old), 1, fp) != 1) {
			if (CRASHDEBUG(1))
				error(INFO, LOGPRX"Failed to read '%s' from file '%s': [Error %d] %s\n",
						"mainmeminfo_old", filename, errno, strerror(errno));
			fclose(fp);
			return FALSE;
		}
		mmi.last_addr = tmp.last_addr;
		mmi.memsize_in_pages = tmp.memsize_in_pages;
		mmi.mem_holes = tmp.mem_holes;
		mmi.holes[0].ppn = tmp.holes[0].ppn;
		mmi.holes[0].pages = tmp.holes[0].pages;
		mmi.holes[1].ppn = tmp.holes[1].ppn;
		mmi.holes[1].pages = tmp.holes[1].pages;
		/* vcpu_offset adjustment for mem_holes is required only for version 1. */
		vcpus_offset = get_vcpus_offset(hdr.version, mmi.mem_holes);
	} else {
		if (fseek(fp, vcpus_offset - sizeof(struct mainmeminfo), SEEK_SET) == -1) {
			if (CRASHDEBUG(1))
				error(INFO, LOGPRX"Failed to fseek '%s': [Error %d] %s\n",
						filename, errno, strerror(errno));
			fclose(fp);
			return FALSE;
		}

		if (fread(&mmi, sizeof(struct mainmeminfo), 1, fp) != 1) {
			if (CRASHDEBUG(1))
				error(INFO, LOGPRX"Failed to read '%s' from file '%s': [Error %d] %s\n",
						"mainmeminfo", filename, errno, strerror(errno));
			fclose(fp);
			return FALSE;
		}
	}
	if (fseek(fp, 0L, SEEK_END) == -1) {
		if (CRASHDEBUG(1))
			error(INFO, LOGPRX"Failed to fseek '%s': [Error %d] %s\n",
				filename, errno, strerror(errno));
		fclose(fp);
		return FALSE;
	}
	filesize = ftell(fp);
	fclose(fp);

	if (mmi.mem_holes > 2) {
		if (CRASHDEBUG(1))
			error(INFO, LOGPRX"Unexpected mmi.mem_holes value %d\n",
				mmi.mem_holes);
		return FALSE;
	}

	for (i = 0; i < mmi.mem_holes; i++) {
		/* hole start page */
		vmss.regions[i].startpagenum = mmi.holes[i].ppn;
		/* hole end page */
		vmss.regions[i].startppn = mmi.holes[i].ppn + mmi.holes[i].pages;
		holes_sum += mmi.holes[i].pages;
	}

	if ((mmi.last_addr + 1) != ((mmi.memsize_in_pages + holes_sum) << VMW_PAGE_SHIFT)) {
		if (CRASHDEBUG(1))
			error(INFO, LOGPRX"Memory size check failed\n");
		return FALSE;
	}

	expected_filesize = vcpus_offset + hdr.num_vcpus * (sizeof(struct vcpu_state1) +
		get_vcpu_gapsize(hdr.version) + sizeof(struct vcpu_state2) + VMW_PAGE_SIZE);
	if (filesize != expected_filesize) {
		if (CRASHDEBUG(1))
			error(INFO, LOGPRX"Incorrect file size: %d != %d\n",
				filesize, expected_filesize);
		return FALSE;
	}

	vmss.memsize = mmi.memsize_in_pages << VMW_PAGE_SHIFT;
	vmss.regionscount = mmi.mem_holes + 1;
	vmss.memoffset = 0;
	vmss.num_vcpus = hdr.num_vcpus;
	return TRUE;
}

int
vmware_guestdump_init(char *filename, FILE *ofp)
{
	FILE *fp = NULL;
	int i, result = TRUE;
	char *vmem_filename = NULL;
	struct vcpu_state1 vs1;
	struct vcpu_state2 vs2;
	char *p;

	if (!machine_type("X86") && !machine_type("X86_64")) {
		error(INFO,
		      LOGPRX"Invalid or unsupported host architecture for .vmss file: %s\n",
		      MACHINE_TYPE);
		result = FALSE;
		goto exit;
	}

	if ((fp = fopen(filename, "r")) == NULL) {
		error(INFO, LOGPRX"Failed to open '%s': [Error %d] %s\n",
		      filename, errno, strerror(errno));
		result = FALSE;
		goto exit;
	}

	if (fseek(fp, get_vcpus_offset(hdr.version, vmss.regionscount - 1), SEEK_SET) == -1) {
		error(INFO, LOGPRX"Failed to fseek '%s': [Error %d] %s\n",
		      filename, errno, strerror(errno));
		result = FALSE;
		goto exit;
	}

	vmss.vcpu_regs = malloc(vmss.num_vcpus * sizeof(uint32_t));
	vmss.regs64 = calloc(vmss.num_vcpus, sizeof(void *));
	if (!vmss.vcpu_regs || !vmss.regs64) {
		error(INFO, LOGPRX"Failed to allocate memory\n");
		result = FALSE;
		goto exit;
	}

	for (i = 0; i < vmss.num_vcpus; i++) {
		if (fread(&vs1, sizeof(struct vcpu_state1), 1, fp) != 1) {
			error(INFO, LOGPRX"Failed to read '%s' from file '%s': [Error %d] %s\n",
					"vcpu_state", filename, errno, strerror(errno));
			result = FALSE;
			goto exit;
		}
		if (fseek(fp, get_vcpu_gapsize(hdr.version), SEEK_CUR) == -1) {
			error(INFO, LOGPRX"Failed to read '%s' from file '%s': [Error %d] %s\n",
					"vcpu_state", filename, errno, strerror(errno));
			result = FALSE;
			goto exit;
		}
		if (fread(&vs2, sizeof(struct vcpu_state2), 1, fp) != 1) {
			error(INFO, LOGPRX"Failed to read '%s' from file '%s': [Error %d] %s\n",
					"vcpu_state", filename, errno, strerror(errno));
			result = FALSE;
			goto exit;
		}
		vmss.regs64[i] = calloc(1, sizeof(vmssregs64));
		if (!vmss.regs64[i]) {
			error(INFO, LOGPRX"Failed to allocate memory\n");
			result = FALSE;
			goto exit;
		}
		vmss.vcpu_regs[i] = 0;

		vmss.regs64[i]->rax = vs2.regs64.rax;
		vmss.regs64[i]->rcx = vs2.regs64.rcx;
		vmss.regs64[i]->rdx = vs2.regs64.rdx;
		vmss.regs64[i]->rbx = vs2.regs64.rbx;
		vmss.regs64[i]->rbp = vs2.regs64.rbp;
		vmss.regs64[i]->rsp = vs2.regs64.rsp;
		vmss.regs64[i]->rsi = vs2.regs64.rsi;
		vmss.regs64[i]->rdi = vs2.regs64.rdi;
		vmss.regs64[i]->r8 = vs2.regs64.r8;
		vmss.regs64[i]->r9 = vs2.regs64.r9;
		vmss.regs64[i]->r10 = vs2.regs64.r10;
		vmss.regs64[i]->r11 = vs2.regs64.r11;
		vmss.regs64[i]->r12 = vs2.regs64.r12;
		vmss.regs64[i]->r13 = vs2.regs64.r13;
		vmss.regs64[i]->r14 = vs2.regs64.r14;
		vmss.regs64[i]->r15 = vs2.regs64.r15;
		vmss.regs64[i]->idtr = vs1.idt_base;
		vmss.regs64[i]->cr[0] = vs1.cr0;
		vmss.regs64[i]->cr[2] = vs1.cr2;
		vmss.regs64[i]->cr[3] = vs1.cr3;
		vmss.regs64[i]->cr[4] = vs1.cr4;
		vmss.regs64[i]->rip = vs2.regs64.rip;
		vmss.regs64[i]->rflags = vs2.regs64.eflags;

		vmss.vcpu_regs[i] = REGS_PRESENT_ALL;
	}

	vmem_filename = strdup(filename);
	p = vmem_filename + strlen(vmem_filename) - 5;
	if (strcmp(p, "guest") != 0) {
		result = FALSE;
		goto exit;
	}
	strcpy(p, "vmem");

	fprintf(ofp, LOGPRX"Open the companion vmem file: %s\n", vmem_filename);
	if ((vmss.dfp = fopen(vmem_filename, "r")) == NULL) {
		error(INFO, LOGPRX"%s: %s\n", vmem_filename, strerror(errno));
		result = FALSE;
		goto exit;
	}
	fseek(vmss.dfp, 0L, SEEK_END);
	if (vmss.memsize != ftell(vmss.dfp)) {
		error(INFO, LOGPRX"%s: unexpected size\n", vmem_filename);
		result = FALSE;
		goto exit;
	}
	fseek(vmss.dfp, 0L, SEEK_SET);
	fprintf(ofp, LOGPRX"vmem file: %s\n\n", vmem_filename);

	if (CRASHDEBUG(1)) {
		vmware_guestdump_memory_dump(ofp);
		dump_registers_for_vmss_dump();
	}

exit:
	if (fp)
		fclose(fp);
	if (vmem_filename)
		free(vmem_filename);
	if (result == FALSE) {
		if (vmss.dfp)
			fclose(vmss.dfp);
		if (vmss.regs64) {
			for (i = 0; i < vmss.num_vcpus; i++) {
				if (vmss.regs64[i])
					free(vmss.regs64[i]);
			}
			free(vmss.regs64);
		}
		if (vmss.vcpu_regs)
			free(vmss.vcpu_regs);
	}
	return result;
}

int
vmware_guestdump_memory_dump(FILE *ofp)
{
	uint64_t holes_sum = 0;
	unsigned i;

	fprintf(ofp, "vmware_guestdump:\n");
	fprintf(ofp, "    Header: version=%d num_vcpus=%llu\n",
		hdr.version, (ulonglong)vmss.num_vcpus);
	fprintf(ofp, "Total memory: %llu\n", (ulonglong)vmss.memsize);


	fprintf(ofp, "Memory regions[%d]:\n", vmss.regionscount);
	fprintf(ofp, "    [0x%016x-", 0);
	for (i = 0; i < vmss.regionscount - 1; i++) {
		fprintf(ofp, "0x%016llx]\n", (ulonglong)vmss.regions[i].startpagenum << VMW_PAGE_SHIFT);
		fprintf(ofp, "    [0x%016llx-", (ulonglong)vmss.regions[i].startppn << VMW_PAGE_SHIFT);
		holes_sum += vmss.regions[i].startppn - vmss.regions[i].startpagenum;
	}
	fprintf(ofp, "0x%016llx]\n", (ulonglong)vmss.memsize + (holes_sum << VMW_PAGE_SHIFT));

	return TRUE;
}

