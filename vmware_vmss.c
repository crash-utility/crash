/*
 * vmware_vmss.c
 *
 * Copyright (c) 2015, 2020 VMware, Inc.
 * Copyright (c) 2018 Red Hat Inc.
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
 * Authors: Dyno Hongjun Fu <hfu@vmware.com>
 *          Sergio Lopez <slp@redhat.com>
 *          Alexey Makhalov <amakhalov@vmware.com>
 */

#include "defs.h"
#include "vmware_vmss.h"

#define LOGPRX "vmw: "

vmssdata vmss = { 0 };

int
is_vmware_vmss(char *filename)
{
	struct cptdumpheader hdr;
	FILE *fp;

        if ((fp = fopen(filename, "r")) == NULL) {
		error(INFO, LOGPRX"Failed to open '%s': [Error %d] %s\n",
		      filename, errno, strerror(errno));
		return FALSE;
        }

	if (fread(&hdr, sizeof(cptdumpheader), 1, fp) != 1) {
		error(INFO, LOGPRX"Failed to read '%s' from file '%s': [Error %d] %s\n",
		      "cptdumpheader", filename, errno, strerror(errno));
		fclose(fp);
		return FALSE;
	}

	fclose(fp);

	if (hdr.id != CPTDUMP_OLD_MAGIC_NUMBER &&
	    hdr.id != CPTDUMP_MAGIC_NUMBER &&
	    hdr.id != CPTDUMP_PARTIAL_MAGIC_NUMBER &&
	    hdr.id != CPTDUMP_RESTORED_MAGIC_NUMBER &&
	    hdr.id != CPTDUMP_NORESTORE_MAGIC_NUMBER) {
		if (CRASHDEBUG(1))
			error(INFO, LOGPRX"Unrecognized .vmss file (magic %x).\n", hdr.id);
		return FALSE;
	}

	return TRUE;
}

int
vmware_vmss_init(char *filename, FILE *ofp)
{
	cptdumpheader hdr;
	cptgroupdesc *grps = NULL;
	unsigned grpsize;
	unsigned i;
	FILE *fp = NULL;
	int result = TRUE;

	if (!machine_type("X86") && !machine_type("X86_64")) {
		error(INFO,
		      LOGPRX"Invalid or unsupported host architecture for .vmss file: %s\n",
		      MACHINE_TYPE);
		result = FALSE;
		goto exit;
	}

        if ((fp = fopen(filename, "r")) == NULL) {
		error(INFO, LOGPRX"Failed to open '%s': %s [Error %d] %s\n",
		      filename, errno, strerror(errno));
		result = FALSE;
		goto exit;
        }

	if (fread(&hdr, sizeof(cptdumpheader), 1, fp) != 1) {
		error(INFO, LOGPRX"Failed to read '%s' from file '%s': [Error %d] %s\n",
		      "cptdumpheader", filename, errno, strerror(errno));
		result = FALSE;
		goto exit;
	}
	DEBUG_PARSE_PRINT((ofp, LOGPRX"Header: id=%x version=%d numgroups=%d\n",
			   hdr.id, hdr.version, hdr.numgroups));

	vmss.cpt64bit = (hdr.id != CPTDUMP_OLD_MAGIC_NUMBER);
	DEBUG_PARSE_PRINT((ofp, LOGPRX"Checkpoint is %d-bit\n", vmss.cpt64bit ? 64 : 32));
	if (!vmss.cpt64bit) {
		error(INFO, LOGPRX"Not implemented for 32-bit VMSS file!\n");
		result = FALSE;
		goto exit;
	}

	grpsize = hdr.numgroups * sizeof (cptgroupdesc);
	grps = (cptgroupdesc *) malloc(grpsize * sizeof(cptgroupdesc));
	if (grps == NULL) {
		error(INFO, LOGPRX"Failed to allocate memory! [Error %d] %s\n",
                      errno, strerror(errno));
		result = FALSE;
		goto exit;
	}

	if (fread(grps, sizeof(cptgroupdesc), grpsize, fp) != grpsize) {
		error(INFO, LOGPRX"Failed to read '%s' from file '%s': [Error %d] %s\n",
		      "cptgroupdesc", filename, errno, strerror(errno));
		result = FALSE;
		goto exit;
	}

	for (i = 0; i < hdr.numgroups; i++) {
		if (fseek(fp, grps[i].position, SEEK_SET) == -1) {
			error(INFO, LOGPRX"Bad offset of VMSS Group['%s'] in '%s' at %#llx.\n",
			      grps[i].name, filename, (ulonglong)grps[i].position);
			continue;
		}
		DEBUG_PARSE_PRINT((ofp, LOGPRX"Group: %-20s offset=%#llx size=0x%#llx.\n",
				  grps[i].name, (ulonglong)grps[i].position, (ulonglong)grps[i].size));

		if (strcmp(grps[i].name, "memory") != 0 &&
		    (strcmp(grps[i].name, "cpu") != 0 || !machine_type("X86_64"))) {
			continue;
		}

		for (;;) {
			uint16_t tag;
			char name[TAG_NAMELEN_MASK + 1];
			unsigned nameLen;
			unsigned nindx;
			int idx[3];
			unsigned j;
			int nextgroup = FALSE;

			if (fread(&tag, sizeof(tag), 1, fp) != 1) {
				error(INFO, LOGPRX"Cannot read tag.\n");
				break;
			}
			if (tag == NULL_TAG)
				break;

			nameLen = TAG_NAMELEN(tag);
			if (fread(name, nameLen, 1, fp) != 1) {
				error(INFO, LOGPRX"Cannot read tag name.\n");
				break;
			}
			name[nameLen] = 0;
			DEBUG_PARSE_PRINT((ofp, LOGPRX"\t Item %20s", name));

			nindx = TAG_NINDX(tag);
			if (nindx > 3) {
				error(INFO, LOGPRX"Too many indexes %d (> 3).\n", nindx);
				break;
			}
			idx[0] = idx[1] = idx[2] = NO_INDEX;
			for (j= 0; j < nindx; j++) {
				if (fread(&idx[j], sizeof(idx[0]), 1, fp) != 1) {
					error(INFO, LOGPRX"Cannot read index.\n");
					nextgroup = TRUE;
					break;
				}
				DEBUG_PARSE_PRINT((ofp, "[%d]", idx[j]));
			}
			if (nextgroup) {
				DEBUG_PARSE_PRINT((ofp, "\n"));
				break;
			}

			if (IS_BLOCK_TAG(tag)) {
				uint64_t nbytes;
				uint64_t blockpos;
				uint64_t nbytesinmem;
				int compressed = IS_BLOCK_COMPRESSED_TAG(tag);
				uint16_t padsize;

				if (fread(&nbytes, sizeof(nbytes), 1, fp) != 1) {
					error(INFO, LOGPRX"Cannot read block size.\n");
					break;
				}
				if (fread(&nbytesinmem, sizeof(nbytesinmem), 1, fp) != 1) {
					error(INFO, LOGPRX"Cannot read block memory size.\n");
					break;
				}
				if (fread(&padsize, sizeof(padsize), 1, fp) != 1) {
					error(INFO, LOGPRX"Cannot read block padding size.\n");
					break;
				}
				if ((blockpos = ftell(fp)) == -1) {
					error(INFO, LOGPRX"Cannot determine location within VMSS file.\n");
					break;
				}
				blockpos += padsize;

				if (strcmp(name, "Memory") == 0) {
					/* The things that we really care about...*/
					vmss.memoffset = blockpos;
					vmss.memsize = nbytesinmem;
					vmss.separate_vmem = FALSE;
					DEBUG_PARSE_PRINT((ofp, "\t=> %sBLOCK: position=%#llx size=%#llx memsize=%#llx\n",
							   compressed ? "COMPRESSED " : "",
							   (ulonglong)blockpos, (ulonglong)nbytes, (ulonglong)nbytesinmem));

					if (compressed) {
						error(INFO, LOGPRX"Cannot handle compressed memory dump yet!\n");
						result = FALSE;
						goto exit;
					}

					if (fseek(fp, blockpos + nbytes, SEEK_SET) == -1) {
						error(INFO, LOGPRX"Cannot seek past block at %#llx.\n",
						      (ulonglong)(blockpos + nbytes));
						break;
					}
				} else if (strcmp(name, "gpregs") == 0 &&
					   nbytes == VMW_GPREGS_SIZE &&
					   idx[0] < vmss.num_vcpus) {
					int cpu = idx[0];
					if (fread(vmss.regs64[cpu], VMW_GPREGS_SIZE, 1, fp) != 1) {
						error(INFO, LOGPRX"Failed to read '%s' from file '%s': [Error %d] %s\n",
						      name, filename, errno, strerror(errno));
						break;
					}
					DEBUG_PARSE_PRINT((ofp, "\n"));
					vmss.vcpu_regs[cpu] |= REGS_PRESENT_GPREGS;
				} else if (strcmp(name, "CR64") == 0 &&
					   nbytes == VMW_CR64_SIZE &&
					   idx[0] < vmss.num_vcpus) {
					int cpu = idx[0];
					DEBUG_PARSE_PRINT((ofp, "\t=> "));
					if (fread(&vmss.regs64[cpu]->cr[0], VMW_CR64_SIZE, 1, fp) != 1) {
						error(INFO, LOGPRX"Failed to read '%s' from file '%s': [Error %d] %s\n",
						      name, filename, errno, strerror(errno));
						break;
					}
					for (j = 0; j < VMW_CR64_SIZE / 8; j++)
						DEBUG_PARSE_PRINT((ofp, "%s%016llX", j ? " " : "",
								(ulonglong)vmss.regs64[cpu]->cr[j]));
					DEBUG_PARSE_PRINT((ofp, "\n"));
					vmss.vcpu_regs[cpu] |= REGS_PRESENT_CRS;
				} else if (strcmp(name, "IDTR") == 0 &&
					   nbytes == VMW_IDTR_SIZE &&
					   idx[0] < vmss.num_vcpus) {
					int cpu = idx[0];
					uint64_t idtr;
					if (fseek(fp, blockpos + 2, SEEK_SET) == -1) {
						error(INFO, LOGPRX"Cannot seek past block at %#llx.\n",
						      (ulonglong)(blockpos + 2));
						break;
					}
					if (fread(&idtr, sizeof(idtr), 1, fp) != 1) {
						error(INFO, LOGPRX"Failed to read '%s' from file '%s': [Error %d] %s\n",
						      name, filename, errno, strerror(errno));
						break;
					}
					DEBUG_PARSE_PRINT((ofp, "\n"));
					vmss.regs64[cpu]->idtr = idtr;
					vmss.vcpu_regs[cpu] |= REGS_PRESENT_IDTR;
				} else {
					if (fseek(fp, blockpos + nbytes, SEEK_SET) == -1) {
						error(INFO, LOGPRX"Cannot seek past block at %#llx.\n",
						      (ulonglong)(blockpos + nbytes));
						break;
					}
					DEBUG_PARSE_PRINT((ofp, "\n"));
				}
			} else {
				union {
					uint8_t val[TAG_VALSIZE_MASK];
					uint32_t val32;
					uint64_t val64;
				} u;
				unsigned k;
				unsigned valsize = TAG_VALSIZE(tag);
				uint64_t blockpos = ftell(fp);

				DEBUG_PARSE_PRINT((ofp, "\t=> position=%#llx size=%#x: ", (ulonglong)blockpos, valsize));
				if (fread(u.val, sizeof(u.val[0]), valsize, fp) != valsize) {
					error(INFO, LOGPRX"Cannot read item.\n");
					break;
				}
				for (k = 0; k < valsize; k++) {
					/* Assume Little Endian */
					DEBUG_PARSE_PRINT((ofp, "%02X", u.val[valsize - k - 1]));
				}

				if (strcmp(grps[i].name, "memory") == 0) {
					if (strcmp(name, "regionsCount") == 0) {
						vmss.regionscount = u.val32;
					}
				        if (strcmp(name, "regionPageNum") == 0) {
						vmss.regions[idx[0]].startpagenum = u.val32;
					}
					if (strcmp(name, "regionPPN") == 0) {
						vmss.regions[idx[0]].startppn = u.val32;
					}
					if (strcmp(name, "regionSize") == 0) {
						vmss.regions[idx[0]].size = u.val32;
					}
					if (strcmp(name, "align_mask") == 0) {
						vmss.alignmask = u.val32;
					}
				} else if (strcmp(grps[i].name, "cpu") == 0) {
					if (strcmp(name, "cpu:numVCPUs") == 0) {
						if (vmss.regs64 != NULL) {
							error(INFO, LOGPRX"Duplicated cpu:numVCPUs entry.\n");
							break;
						}

						vmss.num_vcpus = u.val32;
						vmss.regs64 = malloc(vmss.num_vcpus * sizeof(void *));
						vmss.vcpu_regs = malloc(vmss.num_vcpus * sizeof(uint32_t));

						for (k = 0; k < vmss.num_vcpus; k++) {
							vmss.regs64[k] = malloc(sizeof(vmssregs64));
							memset(vmss.regs64[k], 0, sizeof(vmssregs64));
							vmss.vcpu_regs[k] = 0;
						}
					} else if (strcmp(name, "rax") == 0) {
						int cpu = idx[0];
						vmss.regs64[cpu]->rax = u.val64;
						vmss.vcpu_regs[cpu] |= REGS_PRESENT_RAX;
					} else if (strcmp(name, "rcx") == 0) {
						int cpu = idx[0];
						vmss.regs64[cpu]->rcx = u.val64;
						vmss.vcpu_regs[cpu] |= REGS_PRESENT_RCX;
					} else if (strcmp(name, "rdx") == 0) {
						int cpu = idx[0];
						vmss.regs64[cpu]->rdx = u.val64;
						vmss.vcpu_regs[cpu] |= REGS_PRESENT_RDX;
					} else if (strcmp(name, "rbx") == 0) {
						int cpu = idx[0];
						vmss.regs64[cpu]->rbx = u.val64;
						vmss.vcpu_regs[cpu] |= REGS_PRESENT_RBX;
					} else if (strcmp(name, "rbp") == 0) {
						int cpu = idx[0];
						vmss.regs64[cpu]->rbp = u.val64;
						vmss.vcpu_regs[cpu] |= REGS_PRESENT_RBP;
					} else if (strcmp(name, "rsp") == 0) {
						int cpu = idx[0];
						vmss.regs64[cpu]->rsp = u.val64;
						vmss.vcpu_regs[cpu] |= REGS_PRESENT_RSP;
					} else if (strcmp(name, "rsi") == 0) {
						int cpu = idx[0];
						vmss.regs64[cpu]->rsi = u.val64;
						vmss.vcpu_regs[cpu] |= REGS_PRESENT_RSI;
					} else if (strcmp(name, "rdi") == 0) {
						int cpu = idx[0];
						vmss.regs64[cpu]->rdi = u.val64;
						vmss.vcpu_regs[cpu] |= REGS_PRESENT_RDI;
					} else if (strcmp(name, "r8") == 0) {
						int cpu = idx[0];
						vmss.regs64[cpu]->r8 = u.val64;
						vmss.vcpu_regs[cpu] |= REGS_PRESENT_R8;
					} else if (strcmp(name, "r9") == 0) {
						int cpu = idx[0];
						vmss.regs64[cpu]->r9 = u.val64;
						vmss.vcpu_regs[cpu] |= REGS_PRESENT_R9;
					} else if (strcmp(name, "r10") == 0) {
						int cpu = idx[0];
						vmss.regs64[cpu]->r10 = u.val64;
						vmss.vcpu_regs[cpu] |= REGS_PRESENT_R10;
					} else if (strcmp(name, "r11") == 0) {
						int cpu = idx[0];
						vmss.regs64[cpu]->r11 = u.val64;
						vmss.vcpu_regs[cpu] |= REGS_PRESENT_R11;
					} else if (strcmp(name, "r12") == 0) {
						int cpu = idx[0];
						vmss.regs64[cpu]->r12 = u.val64;
						vmss.vcpu_regs[cpu] |= REGS_PRESENT_R12;
					} else if (strcmp(name, "r13") == 0) {
						int cpu = idx[0];
						vmss.regs64[cpu]->r13 = u.val64;
						vmss.vcpu_regs[cpu] |= REGS_PRESENT_R13;
					} else if (strcmp(name, "r14") == 0) {
						int cpu = idx[0];
						vmss.regs64[cpu]->r14 = u.val64;
						vmss.vcpu_regs[cpu] |= REGS_PRESENT_R14;
					} else if (strcmp(name, "r15") == 0) {
						int cpu = idx[0];
						vmss.regs64[cpu]->r15 = u.val64;
						vmss.vcpu_regs[cpu] |= REGS_PRESENT_R15;
					} else if (strcmp(name, "CR64") == 0) {
						int cpu = idx[0];
						switch (idx[1]) {
							case 0:
								vmss.regs64[cpu]->cr[0] = u.val64;
								vmss.vcpu_regs[cpu] |= REGS_PRESENT_CR0;
								break;
							case 1:
								vmss.regs64[cpu]->cr[1] = u.val64;
								vmss.vcpu_regs[cpu] |= REGS_PRESENT_CR1;
								break;
							case 2:
								vmss.regs64[cpu]->cr[2] = u.val64;
								vmss.vcpu_regs[cpu] |= REGS_PRESENT_CR2;
								break;
							case 3:
								vmss.regs64[cpu]->cr[3] = u.val64;
								vmss.vcpu_regs[cpu] |= REGS_PRESENT_CR3;
								break;
							case 4:
								vmss.regs64[cpu]->cr[4] = u.val64;
								vmss.vcpu_regs[cpu] |= REGS_PRESENT_CR4;
								break;
						}
					} else if (strcmp(name, "IDTR") == 0) {
						int cpu = idx[0];
						if (idx[1] == 1)
							vmss.regs64[cpu]->idtr = u.val32;
						else if (idx[1] == 2) {
							vmss.regs64[cpu]->idtr |= (uint64_t) u.val32 << 32;
							vmss.vcpu_regs[cpu] |= REGS_PRESENT_IDTR;
						}
					} else if (strcmp(name, "rip") == 0) {
						int cpu = idx[0];
						vmss.regs64[cpu]->rip = u.val64;
						vmss.vcpu_regs[cpu] |= REGS_PRESENT_RIP;
					} else if (strcmp(name, "eflags") == 0) {
						int cpu = idx[0];
						vmss.regs64[cpu]->rflags |= u.val32;
						vmss.vcpu_regs[cpu] |= REGS_PRESENT_RFLAGS;
					} else if (strcmp(name, "EFLAGS") == 0) {
						int cpu = idx[0];
						vmss.regs64[cpu]->rflags |= u.val32;
						vmss.vcpu_regs[cpu] |= REGS_PRESENT_RFLAGS;
					}
				}

				DEBUG_PARSE_PRINT((ofp, "\n"));
			}
		}
	}


	if (vmss.memsize == 0) {
		char *vmem_filename, *p;

		if (!(pc->flags & SILENT))
			fprintf(ofp, LOGPRX"Memory dump is not part of this vmss file.\n");
		fclose(fp);
		fp = NULL;

		if (!(pc->flags & SILENT))
			fprintf(ofp, LOGPRX"Try to locate the companion vmem file ...\n");
		/* check the companion vmem file */
		vmem_filename = strdup(filename);
		p = vmem_filename + strlen(vmem_filename) - 4;
		if (strcmp(p, "vmss") != 0 && strcmp(p, "vmsn") != 0) {
			free(vmem_filename);
			result = FALSE;
			goto exit;
		}
		strcpy(p, "vmem");
		if ((fp = fopen(vmem_filename, "r")) == NULL) {
			error(INFO, LOGPRX"%s: %s\n", vmem_filename, strerror(errno));
			free(vmem_filename);
			result = FALSE;
			goto exit;
		}
		fseek(fp, 0L, SEEK_END);
		vmss.memsize = ftell(fp);
		fseek(fp, 0L, SEEK_SET);

		vmss.separate_vmem = TRUE;
		vmss.filename = filename;

		if (!(pc->flags & SILENT))
			fprintf(ofp, LOGPRX"vmem file: %s\n\n", vmem_filename);
		free(vmem_filename);
	}

	vmss.dfp = fp;

exit:
	if (grps)
		free(grps);

	if (!result && fp)
		fclose(fp);

	return result;
}

uint vmware_vmss_page_size(void)
{
	return VMW_PAGE_SIZE;
}

int
read_vmware_vmss(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	uint64_t pos = paddr;

	if (vmss.regionscount > 0) {
		/* Memory is divided into regions and there are holes between them. */
		uint32_t ppn = (uint32_t) (pos >> VMW_PAGE_SHIFT);
	        int i;

		for (i = 0; i < vmss.regionscount; i++) {
			uint32_t hole;

			if (ppn < vmss.regions[i].startppn)
				break;

			/* skip holes. */
			hole = vmss.regions[i].startppn - vmss.regions[i].startpagenum;
			pos -= (uint64_t)hole << VMW_PAGE_SHIFT;
		}
	}

	if (pos + cnt > vmss.memsize) {
		error(INFO, LOGPRX"Read beyond the end of file! paddr=%#lx cnt=%d\n",
		      paddr, cnt);
	}

	pos += vmss.memoffset;
        if (fseek(vmss.dfp, pos, SEEK_SET) != 0)
		return SEEK_ERROR;

	if (fread(bufptr, 1, cnt, vmss.dfp) != cnt)
		return READ_ERROR;

	return cnt;
}

int
write_vmware_vmss(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	return SEEK_ERROR;
}

void
vmware_vmss_display_regs(int cpu, FILE *ofp)
{
	if (cpu >= vmss.num_vcpus)
		return;

	if (machine_type("X86_64")) {
		fprintf(ofp,
		    "	 RIP: %016llx  RSP: %016llx  RFLAGS: %08llx\n"
		    "	 RAX: %016llx  RBX: %016llx  RCX: %016llx\n"
		    "	 RDX: %016llx  RSI: %016llx  RDI: %016llx\n"
		    "	 RBP: %016llx   R8: %016llx   R9: %016llx\n"
		    "	 R10: %016llx  R11: %016llx  R12: %016llx\n"
		    "	 R13: %016llx  R14: %016llx  R15: %016llx\n",
		    (ulonglong)vmss.regs64[cpu]->rip,
		    (ulonglong)vmss.regs64[cpu]->rsp,
		    (ulonglong)vmss.regs64[cpu]->rflags,
		    (ulonglong)vmss.regs64[cpu]->rax,
		    (ulonglong)vmss.regs64[cpu]->rbx,
		    (ulonglong)vmss.regs64[cpu]->rcx,
		    (ulonglong)vmss.regs64[cpu]->rdx,
		    (ulonglong)vmss.regs64[cpu]->rsi,
		    (ulonglong)vmss.regs64[cpu]->rdi,
		    (ulonglong)vmss.regs64[cpu]->rbp,
		    (ulonglong)vmss.regs64[cpu]->r8,
		    (ulonglong)vmss.regs64[cpu]->r9,
		    (ulonglong)vmss.regs64[cpu]->r10,
		    (ulonglong)vmss.regs64[cpu]->r11,
		    (ulonglong)vmss.regs64[cpu]->r12,
		    (ulonglong)vmss.regs64[cpu]->r13,
		    (ulonglong)vmss.regs64[cpu]->r14,
		    (ulonglong)vmss.regs64[cpu]->r15
		);
	}
}

void
get_vmware_vmss_regs(struct bt_info *bt, ulong *ipp, ulong *spp)
{
	ulong ip, sp;

	ip = sp = 0;

	if (bt->tc->processor >= vmss.num_vcpus ||
	    vmss.regs64 == NULL ||
	    vmss.vcpu_regs[bt->tc->processor] != REGS_PRESENT_ALL) {
		machdep->get_stack_frame(bt, ipp, spp);
		return;
	}

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

	ip = (ulong)vmss.regs64[bt->tc->processor]->rip;
	sp = (ulong)vmss.regs64[bt->tc->processor]->rsp;
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

int
vmware_vmss_memory_dump(FILE *ofp)
{
	cptdumpheader hdr;
	cptgroupdesc *grps = NULL;
	unsigned grpsize;
	unsigned i;
	int result = TRUE;
	FILE *fp = vmss.dfp;

	if (vmss.separate_vmem) {
	        if ((fp = fopen(vmss.filename, "r")) == NULL) {
			error(INFO, LOGPRX"Failed to open '%s': %s [Error %d] %s\n",
			      vmss.filename, errno, strerror(errno));
			return FALSE;
		}
	}

	if (fseek(fp, 0, SEEK_SET) != 0) {
		fprintf(ofp, "Error seeking to position 0.\n");
		fclose(fp);
		return FALSE;
	}

	if (fread(&hdr, sizeof(cptdumpheader), 1, fp) != 1) {
		fprintf(ofp, "Failed to read vmss file: [Error %d] %s\n",
			errno, strerror(errno));
		fclose(fp);
		return FALSE;
	}

	fprintf(ofp, "vmware_vmss:\n");
	fprintf(ofp, "    Header: id=%x version=%d numgroups=%d\n",
		hdr.id, hdr.version, hdr.numgroups);

	vmss.cpt64bit = (hdr.id != CPTDUMP_OLD_MAGIC_NUMBER);
	fprintf(ofp, "    Checkpoint is %d-bit\n", vmss.cpt64bit ? 64 : 32);

	grpsize = hdr.numgroups * sizeof (cptgroupdesc);
	grps = (cptgroupdesc *) malloc(grpsize * sizeof(cptgroupdesc));
	if (grps == NULL) {
		fprintf(ofp, "Failed to allocate memory! [Error %d] %s\n",
			errno, strerror(errno));
		fclose(fp);
		return FALSE;
	}

	if (fread(grps, sizeof(cptgroupdesc), grpsize, fp) != grpsize) {
		fprintf(ofp, "Failed to read vmss file: [Error %d] %s\n",
			errno, strerror(errno));
		result = FALSE;
		goto exit;
	}

	for (i = 0; i < hdr.numgroups; i++) {
		if (fseek(fp, grps[i].position, SEEK_SET) == -1) {
			fprintf(ofp, "Bad offset of VMSS Group['%s'] in vmss file at %#llx.\n",
				grps[i].name, (ulonglong)grps[i].position);
			continue;
		}
		fprintf(ofp, "\nGroup: %s offset=%#llx size=0x%#llx\n",
			grps[i].name, (ulonglong)grps[i].position, (ulonglong)grps[i].size);

		for (;;) {
			uint16_t tag;
			char name[TAG_NAMELEN_MASK + 1];
			unsigned nameLen;
			unsigned nindx;
			int idx[3];
			unsigned j;
			int nextgroup = FALSE;

			if (fread(&tag, sizeof(tag), 1, fp) != 1) {
				fprintf(ofp, "Cannot read tag.\n");
				break;
			}
			if (tag == NULL_TAG)
				break;

			nameLen = TAG_NAMELEN(tag);
			if (fread(name, nameLen, 1, fp) != 1) {
				fprintf(ofp, "Cannot read tag name.\n");
				break;
			}
			name[nameLen] = 0;
			fprintf(ofp, "    Item %20s", name);

			nindx = TAG_NINDX(tag);
			if (nindx > 3) {
				fprintf(ofp, "Too many indexes %d (> 3).\n", nindx);
				break;
			}
			idx[0] = idx[1] = idx[2] = NO_INDEX;
			for (j= 0; j < 3; j++) {
				if (j < nindx) {
					if (fread(&idx[j], sizeof(idx[0]), 1, fp) != 1) {
						fprintf(ofp, "Cannot read index.\n");
						nextgroup = TRUE;
						break;
					}
					fprintf(ofp, "[%d]", idx[j]);
				} else
					fprintf(ofp, "   ");
			}
		       if (nextgroup)
				break;

			if (IS_BLOCK_TAG(tag)) {
				uint64_t nbytes;
				uint64_t blockpos;
				uint64_t nbytesinmem;
				int compressed = IS_BLOCK_COMPRESSED_TAG(tag);
				uint16_t padsize;
				unsigned k, l;
				char byte;

				if (fread(&nbytes, sizeof(nbytes), 1, fp) != 1) {
					fprintf(ofp, "Cannot read block size.\n");
					break;
				}
				if (fread(&nbytesinmem, sizeof(nbytesinmem), 1, fp) != 1) {
					fprintf(ofp, "Cannot read block memory size.\n");
					break;
				}
				if (fread(&padsize, sizeof(padsize), 1, fp) != 1) {
					fprintf(ofp, "Cannot read block padding size.\n");
					break;
				}
				if ((blockpos = ftell(fp)) == -1) {
					fprintf(ofp, "Cannot determine location within VMSS file.\n");
					break;
				}
				blockpos += padsize;

				fprintf(ofp, " => %sBLOCK: position=%#llx size=%#llx memsize=%#llx\n",
					compressed ? "COMPRESSED " : "",
					(ulonglong)blockpos, (ulonglong)nbytes, (ulonglong)nbytesinmem);

				if (nbytes && nbytes <= MAX_BLOCK_DUMP && !compressed) {
					fprintf(ofp, "Hex dump: \n");
					l = 0;
					for (k = 0; k < nbytes; k++) {
						if (fread(&byte, 1, 1, fp) != 1) {
							fprintf(ofp, "Cannot read byte.\n");
							result = FALSE;
							goto exit;
						}

						fprintf(ofp, " %02hhX", byte);

						if (l++ == 15) {
							fprintf(ofp, "\n");
							l = 0;
						}
					}
					if (l)
						fprintf(ofp, "\n\n");
					else
						fprintf(ofp, "\n");
				} else {
					if (fseek(fp, blockpos + nbytes, SEEK_SET) == -1) {
						fprintf(ofp, "Cannot seek past block at %#llx.\n",
							(ulonglong)(blockpos + nbytes));
						result = FALSE;
						goto exit;
					}
				}
			} else {
				union {
					uint8_t val[TAG_VALSIZE_MASK];
					uint32_t val32;
					uint64_t val64;
				} u;
				unsigned k;
				unsigned valsize = TAG_VALSIZE(tag);
				uint64_t blockpos = ftell(fp);

				fprintf(ofp, " => position=%#llx size=%#x: ",
					(ulonglong)blockpos, valsize);

				if (fread(u.val, sizeof(u.val[0]), valsize, fp) != valsize) {
					fprintf(ofp, "Cannot read item.\n");
					break;
				}
				for (k = 0; k < valsize; k++) {
					/* Assume Little Endian */
					fprintf(ofp, "%02X", u.val[valsize - k - 1]);
				}


				fprintf(ofp, "\n");
			}
		}
	}

exit:
	if (vmss.separate_vmem)
		fclose(fp);
	if (grps)
		free(grps);

	return result;
}

void
dump_registers_for_vmss_dump(void)
{
	int i;
	vmssregs64 *regs;

	if (!machine_type("X86_64")) {
		fprintf(fp, "-r option not supported on this dumpfile type\n");
		return;
	}

	for (i = 0; i < vmss.num_vcpus; i++) {
		regs = vmss.regs64[i];

		if (i)
			fprintf(fp, "\n");

		fprintf(fp, "CPU %d:\n", i);

		if (vmss.vcpu_regs[i] != REGS_PRESENT_ALL) {
			fprintf(fp, "Missing registers for this CPU: 0x%x\n", vmss.vcpu_regs[i]);
			continue;
		}

		fprintf(fp, "  RAX: %016llx  RBX: %016llx  RCX: %016llx\n",
			(ulonglong)regs->rax, (ulonglong)regs->rbx, (ulonglong)regs->rcx);
		fprintf(fp, "  RDX: %016llx  RSI: %016llx  RDI: %016llx\n",
			(ulonglong)regs->rdx, (ulonglong)regs->rsi, (ulonglong)regs->rdi);
		fprintf(fp, "  RSP: %016llx  RBP: %016llx   R8: %016llx\n",
			(ulonglong)regs->rsp, (ulonglong)regs->rbp, (ulonglong)regs->r8);
		fprintf(fp, "   R9: %016llx  R10: %016llx  R11: %016llx\n",
			(ulonglong)regs->r9, (ulonglong)regs->r10, (ulonglong)regs->r11);
		fprintf(fp, "  R12: %016llx  R13: %016llx  R14: %016llx\n",
			(ulonglong)regs->r12, (ulonglong)regs->r13, (ulonglong)regs->r14);
		fprintf(fp, "  R15: %016llx  RIP: %016llx  RFLAGS: %08llx\n",
			(ulonglong)regs->r15, (ulonglong)regs->rip, (ulonglong)regs->rflags);
		fprintf(fp, "  IDT: base: %016llx\n",
			(ulonglong)regs->idtr);
		fprintf(fp, "  CR0: %016llx  CR1: %016llx  CR2: %016llx\n",
			(ulonglong)regs->cr[0], (ulonglong)regs->cr[1], (ulonglong)regs->cr[2]);
		fprintf(fp, "  CR3: %016llx  CR4: %016llx\n",
			(ulonglong)regs->cr[3], (ulonglong)regs->cr[4]);
	}
}

int
vmware_vmss_valid_regs(struct bt_info *bt)
{
	if (vmss.vcpu_regs[bt->tc->processor] == REGS_PRESENT_ALL)
		return TRUE;

	return FALSE;
}

int
vmware_vmss_get_nr_cpus(void)
{
	return vmss.num_vcpus;
}

int
vmware_vmss_get_cr3_cr4_idtr(int cpu, ulong *cr3, ulong *cr4, ulong *idtr)
{
	if (cpu >= vmss.num_vcpus || vmss.vcpu_regs[cpu] != REGS_PRESENT_ALL)
		return FALSE;

	*cr3 = vmss.regs64[cpu]->cr[3];
	*cr4 = vmss.regs64[cpu]->cr[4];
	*idtr = vmss.regs64[cpu]->idtr;

	return TRUE;
}

int
vmware_vmss_get_cpu_reg(int cpu, int regno, const char *name, int size,
                        void *value)
{
        if (cpu >= vmss.num_vcpus)
                return FALSE;

        /* All supported registers are 8 bytes long. */
        if (size != 8)
                return FALSE;

#define CASE(R,r) \
                case R##_REGNUM: \
                        if (!(vmss.vcpu_regs[cpu] & REGS_PRESENT_##R)) \
                                return FALSE; \
                        memcpy(value, &vmss.regs64[cpu]->r, size); \
                        break


        switch (regno) {
                CASE (RAX, rax);
                CASE (RBX, rbx);
                CASE (RCX, rcx);
                CASE (RDX, rdx);
                CASE (RSI, rsi);
                CASE (RDI, rdi);
                CASE (RBP, rbp);
                CASE (RSP, rsp);
                CASE (R8, r8);
                CASE (R9, r9);
                CASE (R10, r10);
                CASE (R11, r11);
                CASE (R12, r12);
                CASE (R13, r13);
                CASE (R14, r14);
                CASE (R15, r15);
                CASE (RIP, rip);
                case EFLAGS_REGNUM:
                        if (!(vmss.vcpu_regs[cpu] & REGS_PRESENT_RFLAGS))
                                return FALSE;
                        memcpy(value, &vmss.regs64[cpu]->rflags, size);
                        break;
                default:
                        return FALSE;
        }
        return TRUE;
}

int
vmware_vmss_phys_base(ulong *phys_base)
{
	*phys_base = vmss.phys_base;

	return TRUE;
}

int
vmware_vmss_set_phys_base(ulong phys_base)
{
	vmss.phys_base = phys_base;

	return TRUE;
}
