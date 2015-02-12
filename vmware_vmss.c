/*
 * vmware_vmss.c
 *
 * Copyright (c) 2015 VMware, Inc.
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
 * Author: Dyno Hongjun Fu <hfu@vmware.com>
 */

#include "defs.h"
#include "vmware_vmss.h"

#define LOGPRX "vmw: "

static vmssdata vmss = { 0 };

int
is_vmware_vmss(char *filename)
{
	struct cptdumpheader hdr;
	FILE *fp;

        if ((fp = fopen(filename, "r")) == NULL) {
		if (CRASHDEBUG(1))
			error(INFO, LOGPRX"%s: %s\n", filename, strerror(errno));
		return FALSE;
        }

	if (fread(&hdr, sizeof(cptdumpheader), 1, fp) != 1) {
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
	cptgroupdesc *grps;
	unsigned grpsize;
	unsigned i;
	FILE *fp;

	if (!machine_type("X86") && !machine_type("X86_64")) {
		error(FATAL,
		      LOGPRX"invalid or unsupported host architecture for .vmss file: %s\n",
		      MACHINE_TYPE);
		return FALSE;
	}

        if ((fp = fopen(filename, "r")) == NULL) {
		error(INFO, LOGPRX"%s: %s\n", filename, strerror(errno));
		return FALSE;
        }

	vmss.dfp = fp;
	vmss.ofp = ofp;

	if (fread(&hdr, sizeof(cptdumpheader), 1, vmss.dfp) != 1)
		return FALSE;
	DEBUG_PARSE_PRINT((vmss.ofp, LOGPRX"Header: id=%x version=%d numgroups=%d\n",
			   hdr.id, hdr.version, hdr.numgroups));

	vmss.cpt64bit = (hdr.id != CPTDUMP_OLD_MAGIC_NUMBER);
	DEBUG_PARSE_PRINT((vmss.ofp, LOGPRX"Checkpoint is %d-bit\n",
			   vmss.cpt64bit ? 64 : 32));
	if (!vmss.cpt64bit) {
		fprintf(vmss.ofp, LOGPRX"Not implemented for 32-bit VMSS file!\n");
		return FALSE;
	}

	grpsize = hdr.numgroups * sizeof (cptgroupdesc);
	grps = (cptgroupdesc *) malloc(grpsize * sizeof(cptgroupdesc));
	if (grps == NULL) {
		fprintf(vmss.ofp, LOGPRX"Out of memory! failed to allocate groups.\n");
		return FALSE;
	}

	if (fread(grps, sizeof(cptgroupdesc), grpsize, vmss.dfp) != grpsize) {
		fprintf(vmss.ofp, LOGPRX"Cannot read VMSS groups in %s!\n", filename);
		free(grps);
		return FALSE;
	}

	for (i = 0; i < hdr.numgroups; i++) {
		if (fseek(vmss.dfp, grps[i].position, SEEK_SET) == -1) {
			fprintf(vmss.ofp, LOGPRX"Bad offset of VMSS Group['%s'] in '%s' at %#llx.\n",
				grps[i].name, filename, (ulonglong)grps[i].position);
			continue;
		}
		DEBUG_PARSE_PRINT((vmss.ofp, LOGPRX"Group: %-20s offset=%#llx size=0x%#llx.\n",
				  grps[i].name, (ulonglong)grps[i].position, (ulonglong)grps[i].size));

		if (strcmp(grps[i].name, "memory") != 0) {
			continue;
		}

		for (;;) {
			uint16_t tag;
			char name[TAG_NAMELEN_MASK + 1];
			unsigned nameLen;
			unsigned nindx;
			int idx[3];
			unsigned j;

			if (fread(&tag, sizeof(tag), 1, vmss.dfp) != 1) {
				fprintf(vmss.ofp, LOGPRX"Cannot read tag.\n");
				break;
			}
			if (tag == NULL_TAG)
				break;

			nameLen = TAG_NAMELEN(tag);
			if (fread(name, nameLen, 1, vmss.dfp) != 1) {
				fprintf(vmss.ofp, LOGPRX"Cannot read tag name.\n");
				break;
			}
			name[nameLen] = 0;
			DEBUG_PARSE_PRINT((vmss.ofp, LOGPRX"\t Item %20s",
					   name));

			nindx = TAG_NINDX(tag);
			if (nindx > 3) {
				fprintf(vmss.ofp, LOGPRX"Cannot handle %d indexes\n", nindx);
				break;
			}
			idx[0] = idx[1] = idx[2] = NO_INDEX;
			for (j= 0; j < nindx; j++) {
				if (fread(&idx[j], sizeof(idx[0]), 1, vmss.dfp) != 1) {
					fprintf(vmss.ofp, LOGPRX"Cannot read index.\n");
					break;
				}
				DEBUG_PARSE_PRINT((vmss.ofp, "[%d]", idx[j]));
			}

			if (IS_BLOCK_TAG(tag)) {
				uint64_t nbytes;
				uint64_t blockpos;
				uint64_t nbytesinmem;
				int compressed = IS_BLOCK_COMPRESSED_TAG(tag);
				uint16_t padsize;

				if (fread(&nbytes, sizeof(nbytes), 1, vmss.dfp) != 1) {
					fprintf(vmss.ofp, LOGPRX"Cannot read block size.\n");
					break;
				}
				if (fread(&nbytesinmem, sizeof(nbytesinmem), 1, vmss.dfp) != 1) {
					fprintf(vmss.ofp, LOGPRX"Cannot read block memory size.\n");
					break;
				}
				if (fread(&padsize, sizeof(padsize), 1, vmss.dfp) != 1) {
					fprintf(vmss.ofp, LOGPRX"Cannot read block padding size.\n");
					break;
				}
				if ((blockpos = ftell(vmss.dfp)) == -1) {
					fprintf(vmss.ofp, LOGPRX"Cannot determine location within VMSS file.\n");
					break;
				}
				blockpos += padsize;

				if (fseek(vmss.dfp, blockpos + nbytes, SEEK_SET) == -1) {
					fprintf(vmss.ofp, LOGPRX"Cannot seek past block at %#llx.\n",
						(ulonglong)(blockpos + nbytes));
					break;
				}

				/* The things that we really care about...*/
				if (strcmp(grps[i].name, "memory") == 0 &&
				    strcmp(name, "Memory") == 0) {
					vmss.memoffset = blockpos;
					vmss.memsize = nbytesinmem;
				}

				DEBUG_PARSE_PRINT((vmss.ofp, "\t=> %sBLOCK: position=%#llx size=%#llx memsize=%#llx\n",
						  compressed ? "COMPRESSED " : "",
						  (ulonglong)blockpos, (ulonglong)nbytes, (ulonglong)nbytesinmem));

			} else {
				uint8_t val[TAG_VALSIZE_MASK];
				unsigned k;
				unsigned valsize = TAG_VALSIZE(tag);
				uint64_t blockpos = ftell(vmss.dfp);

				DEBUG_PARSE_PRINT((vmss.ofp, "\t=> position=%#llx size=%#x: ", (ulonglong)blockpos, valsize));
				if (fread(val, sizeof(val[0]), valsize, vmss.dfp) != valsize) {
					fprintf(vmss.ofp, LOGPRX"Cannot read item.\n");
					break;
				}
				for (k = 0; k < valsize; k++) {
					/* Assume Little Endian */
					DEBUG_PARSE_PRINT((vmss.ofp, "%02X", val[valsize - k - 1]));
				}

				if (strcmp(grps[i].name, "memory") == 0) {
					if (strcmp(name, "regionsCount") == 0) {
						vmss.regionscount = (uint32_t) *val;
						if (vmss.regionscount != 0) {
							fprintf(vmss.ofp, LOGPRX"regionsCount=%d (!= 0) NOT TESTED!",
							        vmss.regionscount);
						}
					}
					if (strcmp(name, "align_mask") == 0) {
						vmss.alignmask = (uint32_t) *val;
						if (vmss.alignmask != 0xff) {
							fprintf(vmss.ofp, LOGPRX"align_mask=%d (!= 0xff) NOT TESTED!",
							        vmss.regionscount);
						}
					}
				}

				DEBUG_PARSE_PRINT((vmss.ofp, "\n"));
			}
		}
	}

	free(grps);

	if (vmss.memsize == 0) {
		char *vmem_filename, *p;

		fprintf(vmss.ofp, LOGPRX"Memory dump is not part of this vmss file.\n");
		fclose(vmss.dfp);

		fprintf(vmss.ofp, LOGPRX"Try to locate the companion vmem file ...\n");
		/* check the companion vmem file */
		vmem_filename = strdup(filename);
		p = vmem_filename + strlen(vmem_filename) - 4;
		if (strcmp(p, "vmss") != 0 && strcmp(p, "vmsn") != 0) {
			free(vmem_filename);
			return FALSE;
		}
		strcpy(p, "vmem");
		if ((fp = fopen(vmem_filename, "r")) == NULL) {
			error(INFO, LOGPRX"%s: %s\n", vmem_filename, strerror(errno));
			free(vmem_filename);
			return FALSE;
		}
		vmss.dfp = fp;
		fseek(vmss.dfp, 0L, SEEK_END);
		vmss.memsize = ftell(vmss.dfp);
		fseek(vmss.dfp, 0L, SEEK_SET);

		fprintf(vmss.ofp, LOGPRX"vmem file: %s\n\n", vmem_filename);
		free(vmem_filename);
	}

	return TRUE;
}

uint vmware_vmss_page_size(void)
{
	return 4096;
}

int
read_vmware_vmss(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	uint64_t pos = vmss.memoffset + paddr;

	if (pos + cnt > vmss.memoffset + vmss.memsize) {
		cnt -= ((pos + cnt) - (vmss.memoffset + vmss.memsize));
		if (cnt < 0) {
			error(INFO, LOGPRX"Read beyond the end of file! paddr=%#lx\n",
			      paddr);
		}
	}

        if (fseek(vmss.dfp, pos, SEEK_SET) != 0)
		return SEEK_ERROR;

        if (fread(bufptr, 1 , cnt, vmss.dfp) != cnt)
		return READ_ERROR;

	return cnt;
}

int
write_vmware_vmss(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	return SEEK_ERROR;
}

