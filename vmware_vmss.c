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

/* VMware only supports X86/X86_64 virtual machines. */
#define VMW_PAGE_SIZE (4096)
#define VMW_PAGE_SHIFT (12)

static vmssdata vmss = { 0 };

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
		error(INFO, LOGPRX"Failed to read '%s': [Error %d] %s\n",
		      filename, errno, strerror(errno));
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
		error(INFO, LOGPRX"Failed to read '%s': %s [Error %d] %s\n",
                      filename, errno, strerror(errno));
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
		error(INFO, LOGPRX"Failed to read '%s': [Error %d] %s\n",
		      filename, errno, strerror(errno));
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
		       if (nextgroup)
				break;

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

				if (fseek(fp, blockpos + nbytes, SEEK_SET) == -1) {
					error(INFO, LOGPRX"Cannot seek past block at %#llx.\n",
					      (ulonglong)(blockpos + nbytes));
					break;
				}

				if (strcmp(name, "Memory") == 0) {
					/* The things that we really care about...*/
					vmss.memoffset = blockpos;
					vmss.memsize = nbytesinmem;
					DEBUG_PARSE_PRINT((ofp, "\t=> %sBLOCK: position=%#llx size=%#llx memsize=%#llx\n",
							   compressed ? "COMPRESSED " : "",
							   (ulonglong)blockpos, (ulonglong)nbytes, (ulonglong)nbytesinmem));

					if (compressed) {
						error(INFO, LOGPRX"Cannot handle compressed memory dump yet!\n");
						result = FALSE;
						goto exit;
					}
				}
			} else {
				union {
					uint8_t val[TAG_VALSIZE_MASK];
					uint32_t val32;
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
				}

				DEBUG_PARSE_PRINT((ofp, "\n"));
			}
		}
	}


	if (vmss.memsize == 0) {
		char *vmem_filename, *p;

		fprintf(ofp, LOGPRX"Memory dump is not part of this vmss file.\n");
		fclose(fp);
		fp = NULL;

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
			if (ppn < vmss.regions[i].startppn)
				break;

			/* skip holes. */
			pos -= ((vmss.regions[i].startppn - vmss.regions[i].startpagenum)
				<< VMW_PAGE_SHIFT);
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

