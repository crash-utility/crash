/*
 * vmware_guestdump.c
 *
 * Copyright (c) 2020 VMware, Inc.
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
 * Author: Alexey Makhalov <amakhalov@vmware.com>
 */

#include "defs.h"
#include "vmware_vmss.h"

#define LOGPRX "vmw: "

#define GUESTDUMP_VERSION 4
#define GUESTDUMP_MAGIC1 1
#define GUESTDUMP_MAGIC2 0

struct guestdumpheader {
	uint32_t version;
	uint32_t num_vcpus;
	uint8_t magic1;
	uint8_t reserved1;
	uint32_t cpu_vendor;
	uint64_t magic2;
	uint64_t last_addr;
	uint64_t memsize_in_pages;
	uint32_t reserved2;
	uint32_t mem_holes;
	struct memhole {
		uint64_t ppn;
		uint64_t pages;
	} holes[2];
} __attribute__((packed));

struct vcpu_state {
	uint32_t cr0;
	uint64_t cr2;
	uint64_t cr3;
	uint64_t cr4;
	uint64_t reserved1[10];
	uint64_t idt_base;
	uint16_t reserved2[21];
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
 * vmware_guestdump is extension to vmware_vmss with ability to debug
 * debug.guest and debug.vmem files.
 *
 * debug.guest.gz and debug.vmem.gz can be obtained using following
 * .vmx options from VM running in debug mode:
 * 	monitor.mini-suspend_on_panic = TRUE
 * 	monitor.suspend_on_triplefault = TRUE
 *
 * guestdump (debug.guest) is simplified version of *.vmss which does
 * not contain full VM state, but minimal guest state, such as memory
 * layout and CPUs state, needed for debugger. is_vmware_guestdump()
 * and vmware_guestdump_init() functions parse guestdump header and
 * populate vmss data structure (from vmware_vmss.c). As result, all
 * handlers (except mempry_dump) from vmware_vmss.c can be reused.
 *
 * debug.guest does not have dedicated header magic or signature for
 * its format. To probe debug.guest we need to perform header fields
 * and file size validity. In addition, check for the filename
 * extension, which must be ".guest".
 */

int
is_vmware_guestdump(char *filename)
{
	struct guestdumpheader hdr;
	FILE *fp;
	uint64_t filesize, holes_sum = 0;
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

	if (fseek(fp, 0L, SEEK_END) == -1) {
		error(INFO, LOGPRX"Failed to fseek '%s': [Error %d] %s\n",
		      filename, errno, strerror(errno));
		fclose(fp);
		return FALSE;
	}
	filesize = ftell(fp);
	fclose(fp);

	if (hdr.mem_holes > 2)
		goto unrecognized;

	for (i = 0; i < hdr.mem_holes; i++) {
		/* hole start page */
		vmss.regions[i].startpagenum = hdr.holes[i].ppn;
		/* hole end page */
		vmss.regions[i].startppn = hdr.holes[i].ppn + hdr.holes[i].pages;
		holes_sum += hdr.holes[i].pages;
	}

	if (hdr.version != GUESTDUMP_VERSION ||
	    hdr.magic1 != GUESTDUMP_MAGIC1 ||
	    hdr.magic2 != GUESTDUMP_MAGIC2 ||
	    (hdr.last_addr + 1) != ((hdr.memsize_in_pages + holes_sum) << VMW_PAGE_SHIFT) ||
	    filesize != sizeof(struct guestdumpheader) +
	    hdr.num_vcpus * (sizeof (struct vcpu_state) + VMW_PAGE_SIZE))
		goto unrecognized;

	vmss.memsize = hdr.memsize_in_pages << VMW_PAGE_SHIFT;
	vmss.regionscount = hdr.mem_holes + 1;
	vmss.memoffset = 0;
	vmss.num_vcpus = hdr.num_vcpus;
	return TRUE;

unrecognized:
	if (CRASHDEBUG(1))
		error(INFO, LOGPRX"Unrecognized debug.guest file.\n");
	return FALSE;
}

int
vmware_guestdump_init(char *filename, FILE *ofp)
{
	FILE *fp = NULL;
	int i, result = TRUE;
	char *vmem_filename = NULL;
	struct vcpu_state vs;
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

	if (fseek(fp, sizeof(struct guestdumpheader), SEEK_SET) == -1) {
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
		if (fread(&vs, sizeof(struct vcpu_state), 1, fp) != 1) {
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

		vmss.regs64[i]->rax = vs.regs64.rax;
		vmss.regs64[i]->rcx = vs.regs64.rcx;
		vmss.regs64[i]->rdx = vs.regs64.rdx;
		vmss.regs64[i]->rbx = vs.regs64.rbx;
		vmss.regs64[i]->rbp = vs.regs64.rbp;
		vmss.regs64[i]->rsp = vs.regs64.rsp;
		vmss.regs64[i]->rsi = vs.regs64.rsi;
		vmss.regs64[i]->rdi = vs.regs64.rdi;
		vmss.regs64[i]->r8 = vs.regs64.r8;
		vmss.regs64[i]->r9 = vs.regs64.r9;
		vmss.regs64[i]->r10 = vs.regs64.r10;
		vmss.regs64[i]->r11 = vs.regs64.r11;
		vmss.regs64[i]->r12 = vs.regs64.r12;
		vmss.regs64[i]->r13 = vs.regs64.r13;
		vmss.regs64[i]->r14 = vs.regs64.r14;
		vmss.regs64[i]->r15 = vs.regs64.r15;
		vmss.regs64[i]->idtr = vs.idt_base;
		vmss.regs64[i]->cr[0] = vs.cr0;
		vmss.regs64[i]->cr[2] = vs.cr2;
		vmss.regs64[i]->cr[3] = vs.cr3;
		vmss.regs64[i]->cr[4] = vs.cr4;
		vmss.regs64[i]->rip = vs.regs64.rip;
		vmss.regs64[i]->rflags = vs.regs64.eflags;

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
	fprintf(ofp, "vmware_guestdump:\n");
	fprintf(ofp, "    Header: version=%d num_vcpus=%llu\n",
		GUESTDUMP_VERSION, (ulonglong)vmss.num_vcpus);
	fprintf(ofp, "Total memory: %llu\n", (ulonglong)vmss.memsize);

	if (vmss.regionscount > 1) {
		uint64_t holes_sum = 0;
		unsigned i;

		fprintf(ofp, "Memory regions[%d]:\n", vmss.regionscount);
		fprintf(ofp, "    [0x%016x-", 0);
		for (i = 0; i < vmss.regionscount - 1; i++) {
			fprintf(ofp, "0x%016llx]\n", (ulonglong)vmss.regions[i].startpagenum << VMW_PAGE_SHIFT);
			fprintf(ofp, "    [0x%016llx-", (ulonglong)vmss.regions[i].startppn << VMW_PAGE_SHIFT);
			holes_sum += vmss.regions[i].startppn - vmss.regions[i].startpagenum;
		}
		fprintf(ofp, "0x%016llx]\n", (ulonglong)vmss.memsize + (holes_sum << VMW_PAGE_SHIFT));
	}

	return TRUE;
}

