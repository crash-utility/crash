/*
 * sadump.h - core analysis suite
 *
 * Copyright (c) 2011 FUJITSU LIMITED
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
 * Author: HATAYAMA Daisuke <d.hatayama@jp.fujitsu.com>
 */

#include "defs.h"
#include "sadump.h"
#include <arpa/inet.h> /* htonl, htons */
#include <elf.h>
#include <inttypes.h>

enum {
	failed = -1
};

static struct sadump_data sadump_data = { 0 };
static struct sadump_data *sd = &sadump_data;

static int read_device(void *buf, size_t bytes, ulong *offset);
static int read_dump_header(char *file);
static int add_disk(char *file);
static int open_dump_file(char *file);
static int open_disk(char *file);
static uint64_t paddr_to_pfn(physaddr_t paddr);
static inline int is_set_bit(char *bitmap, uint64_t pfn);
static inline int page_is_ram(uint64_t nr);
static inline int page_is_dumpable(uint64_t nr);
static int lookup_diskset(uint64_t whole_offset, int *diskid, uint64_t *disk_offset);
static struct tm *efi_time_t_to_tm(const efi_time_t *e);
static char * guid_to_str(efi_guid_t *guid, char *buf, size_t buflen);
static int verify_magic_number(uint32_t magicnum[DUMP_PART_HEADER_MAGICNUM_SIZE]);
static ulong per_cpu_ptr(ulong ptr, int cpu);
static ulong early_per_cpu_ptr(char *symbol, struct syment *sym, int cpu);
static ulong legacy_per_cpu_ptr(ulong ptr, int cpu);
static int get_prstatus_from_crash_notes(int cpu, char *prstatus);
static void display_smram_cpu_state(int apicid, struct sadump_smram_cpu_state *s);
static int cpu_to_apicid(int cpu, int *apicid);
static int get_sadump_smram_cpu_state(int cpu, struct sadump_smram_cpu_state *smram);
static int block_table_init(void);
static uint64_t pfn_to_block(uint64_t pfn);
static void mask_reserved_fields(struct sadump_smram_cpu_state *smram);

struct sadump_data *
sadump_get_sadump_data(void)
{
	if (!SADUMP_VALID() || !SADUMP_DUMPFILE())
		return NULL;

	return &sadump_data;
}

int
sadump_cleanup_sadump_data(void)
{
	int i;

	if (!SADUMP_VALID() || !SADUMP_DUMPFILE())
		return FALSE;

	if (sd->flags & SADUMP_DISKSET) {
		for (i = 1; i < sd->sd_list_len; ++i) {
			if (sd->sd_list[i]->dfd)
				close(sd->sd_list[i]->dfd);
			free(sd->sd_list[i]->header);
			free(sd->sd_list[i]);
		}
	}

	close(sd->dfd);
	free(sd->header);
	free(sd->dump_header);
	free(sd->diskset_header);
	free(sd->bitmap);
	free(sd->dumpable_bitmap);
	free(sd->page_buf);
	free(sd->block_table);
	if (sd->sd_list[0])
		free(sd->sd_list[0]);
	free(sd->sd_list);

	memset(&sadump_data, 0, sizeof(sadump_data));

	pc->flags &= ~SADUMP;
	pc->dumpfile = NULL;
	pc->readmem = NULL;
	pc->writemem = NULL;

	return TRUE;
}

static int
read_device(void *buf, size_t bytes, ulong *offset)
{
	if (lseek(sd->dfd, *offset, SEEK_SET) == failed) {
		error(INFO, "sadump: cannot lseek dump device\n");
		return FALSE;
	}
	if (read(sd->dfd, buf, bytes) < bytes) {
		error(INFO, "sadump: cannot read dump device\n");
		return FALSE;
	}
	*offset += bytes;
	return TRUE;
}

static int
read_dump_header(char *file)
{
	struct sadump_part_header *sph = NULL;
	struct sadump_header *sh = NULL;
	struct sadump_disk_set_header *new, *sdh = NULL;
	struct sadump_media_header *smh = NULL;
	struct sadump_diskset_data *sd_list_len_0 = NULL;
	size_t block_size = SADUMP_DEFAULT_BLOCK_SIZE;
	ulong flags = 0;
	ulong offset = 0, sub_hdr_offset, data_offset;
	uint32_t smram_cpu_state_size = 0;
	ulong bitmap_len, dumpable_bitmap_len;
	char *bitmap = NULL, *dumpable_bitmap = NULL, *page_buf = NULL;
	char guid1[SADUMP_EFI_GUID_TEXT_REPR_LEN+1];
	char guid2[SADUMP_EFI_GUID_TEXT_REPR_LEN+1];

	sph = malloc(block_size);
	if (!sph) {
		error(INFO, "sadump: cannot allocate partition header buffer\n");
		goto err;
	}

	sdh = malloc(block_size);
	if (!sdh) {
		error(INFO, "sadump: cannot allocate disk set header buffer\n");
		goto err;
	}

	sh = malloc(block_size);
	if (!sh) {
		error(INFO, "sadump: cannot allocate dump header buffer\n");
		goto err;
	}

	smh = malloc(block_size);
	if (!smh) {
		error(INFO, "sadump: cannot allocate media header buffer\n");
		goto err;
	}

restart:
	if (!read_device(sph, block_size, &offset)) {
		error(INFO, "sadump: cannot read partition header\n");
		goto err;
	}

	if (sph->signature1 != SADUMP_SIGNATURE1 ||
	    sph->signature2 != SADUMP_SIGNATURE2) {

		flags |= SADUMP_MEDIA;

		if (CRASHDEBUG(1))
			error(INFO, "sadump: read dump device as media "
			      "format\n");

		offset = 0;

		if (!read_device(smh, block_size, &offset)) {
			error(INFO, "sadump: cannot read media header\n");
			goto err;
		}

		if (!read_device(sph, block_size, &offset)) {
			error(INFO, "sadump: cannot read partition header\n");
			goto err;
		}

		if (sph->signature1 != SADUMP_SIGNATURE1 ||
		    sph->signature2 != SADUMP_SIGNATURE2) {
			if (CRASHDEBUG(1))
				error(INFO, "sadump: does not have partition "
				      "header\n");
			goto err;
		}

	}

	if (!verify_magic_number(sph->magicnum)) {
		error(INFO, "sadump: invalid magic number\n");
		goto err;
	}

	if (!(flags & SADUMP_MEDIA) && sph->set_disk_set) {
		uint32_t header_blocks;
		size_t header_size;

		flags |= SADUMP_DISKSET;

		if (CRASHDEBUG(1))
			error(INFO, "sadump: read dump device as diskset\n");

		if (sph->set_disk_set != 1 ||
		    sph->set_disk_set > SADUMP_MAX_DISK_SET_NUM) {
			if (CRASHDEBUG(1))
				error(INFO, "sadump: invalid disk set number: "
				      "%d\n",
				      sph->set_disk_set);
			goto err;
		}

		if (!read_device(&header_blocks, sizeof(uint32_t), &offset)) {
			error(INFO, "sadump: cannot read disk set header "
			      "size\n");
			goto err;
		}

		offset -= sizeof(uint32_t);
		header_size = header_blocks * block_size;

		if (header_size > block_size) {
			new = realloc(sdh, header_size);
			if (!new) {
				error(INFO, "sadump: cannot re-allocate disk "
				      "set buffer\n");
				goto err;
			}
			sdh = new;
		}

		if (!read_device(sdh, header_size, &offset)) {
			error(INFO, "sadump: cannot read disk set header\n");
			goto err;
		}

	}

	if (!read_device(sh, block_size, &offset)) {
		error(INFO, "sadump: cannot read dump header\n");
		goto err;
	}

	sub_hdr_offset = offset;

	if (strncmp(sh->signature, SADUMP_SIGNATURE, 8) != 0) {
		if (CRASHDEBUG(1))
			error(INFO, "sadump: does not have dump header\n");
		goto err;
	}

	if (flags & SADUMP_MEDIA) {

		if (memcmp(&sph->sadump_id, &smh->sadump_id,
			   sizeof(efi_guid_t)) != 0) {
			if (CRASHDEBUG(1))
				error(INFO, "sadump: system ID mismatch\n"
				      "  partition header: %s\n"
				      "  media header: %s\n",
				      guid_to_str(&sph->sadump_id, guid1, sizeof(guid1)),
				      guid_to_str(&smh->sadump_id, guid2, sizeof(guid2)));
			goto err;
		}

		if (memcmp(&sph->disk_set_id, &smh->disk_set_id,
			   sizeof(efi_guid_t)) != 0) {
			if (CRASHDEBUG(1))
				error(INFO, "sadump: disk set ID mismatch\n"
				      "  partition header: %s\n"
				      "  media header: %s\n",
				      guid_to_str(&sph->disk_set_id, guid1, sizeof(guid1)),
				      guid_to_str(&smh->disk_set_id, guid2, sizeof(guid2)));
			goto err;
		}

		if (memcmp(&sph->time_stamp, &smh->time_stamp,
			   sizeof(efi_time_t)) != 0) {
			if (CRASHDEBUG(1)) {
				error(INFO, "sadump: time stamp mismatch\n");
				error(INFO, "sadump:   partition header: %s\n",
				      strip_linefeeds(asctime
						      (efi_time_t_to_tm
						       (&sph->time_stamp))));
				error(INFO, "sadump:   media header: %s\n",
				      strip_linefeeds(asctime
						      (efi_time_t_to_tm
						       (&smh->time_stamp))));
			}
		}

		if (smh->sequential_num != 1) {
			error(INFO, "sadump: first media file has sequential "
			      "number %d\n", smh->sequential_num);
			goto err;
		}

	}

	if (sh->block_size != block_size) {
		block_size = sh->block_size;
		offset = 0;
		goto restart;
	}

	if (CRASHDEBUG(1)) {
		if (flags & SADUMP_MEDIA)
			error(INFO, "sadump: media backup file\n");

		else if (flags & SADUMP_DISKSET)
			error(INFO, "sadump: diskset configuration with %d "
			      "disks\n", sdh->disk_num);

		else
			error(INFO, "sadump: single partition "
			      "configuration\n");
	}

	flags |= SADUMP_LOCAL;

	switch (sh->header_version) {
	case 0:
		sd->max_mapnr = (uint64_t)sh->max_mapnr;
		break;
	default:
		error(WARNING,
		      "sadump: unsupported header version: %u\n"
		      "sadump: assuming header version: 1\n",
		      sh->header_version);
	case 1:
		sd->max_mapnr = sh->max_mapnr_64;
		break;
	}

	if (sh->sub_hdr_size > 0) {
		if (!read_device(&smram_cpu_state_size, sizeof(uint32_t),
				 &offset)) {
			error(INFO,
			      "sadump: cannot read SMRAM CPU STATE size\n");
			goto err;
		}
		smram_cpu_state_size /= sh->nr_cpus;

		offset -= sizeof(uint32_t);
		offset += sh->sub_hdr_size * block_size;
	}

	if (!sh->bitmap_blocks) {
		error(INFO, "sadump: bitmap_blocks is zero\n");
		goto err;
	}
	bitmap_len = block_size * sh->bitmap_blocks;
	bitmap = calloc(bitmap_len, 1);
	if (!bitmap) {
		error(INFO, "sadump: cannot allocate memory for bitmap "
		      "buffer\n");
		goto err;
	}
	if (!read_device(bitmap, bitmap_len, &offset)) {
		error(INFO, "sadump: cannot read bitmap\n");
		goto err;
	}

	if (!sh->dumpable_bitmap_blocks) {
		error(INFO, "sadump: dumpable_bitmap_blocks is zero\n");
		goto err;
	}
	dumpable_bitmap_len = block_size * sh->dumpable_bitmap_blocks;
	dumpable_bitmap = calloc(dumpable_bitmap_len, 1);
	if (!dumpable_bitmap) {
		error(INFO, "sadump: cannot allocate memory for "
		      "dumpable_bitmap buffer\n");
		goto err;
	}
	if (!read_device(dumpable_bitmap, dumpable_bitmap_len, &offset)) {
		error(INFO, "sadump: cannot read dumpable bitmap\n");
		goto err;
	}

	data_offset = offset;

	page_buf = malloc(block_size);
	if (!page_buf) {
		error(INFO, "sadump: cannot allocate page buffer\n");
		goto err;
	}

	sd->filename = file;

	/*
	 * Switch to zero excluded mode by default on sadump-related
	 * formats because some Fujitsu troubleshooting software
	 * assumes the behavior.
	 */
	sd->flags = flags | SADUMP_ZERO_EXCLUDED;

	if (machine_type("X86"))
		sd->machine_type = EM_386;
	else if (machine_type("X86_64"))
		sd->machine_type = EM_X86_64;
	else {
		error(INFO, "sadump: unsupported machine type: %s\n",
		      MACHINE_TYPE);
		goto err;
	}

	sd->data_offset = data_offset;
	sd->block_size = block_size;
	sd->block_shift = ffs(sd->block_size) - 1;

	sd->bitmap = bitmap;
	sd->dumpable_bitmap = dumpable_bitmap;

	sd->sub_hdr_offset = sub_hdr_offset;
	sd->smram_cpu_state_size = smram_cpu_state_size;

	sd->header = sph;
	sd->dump_header = sh;
	if (flags & SADUMP_DISKSET)
		sd->diskset_header = sdh;
	if (flags & SADUMP_MEDIA)
		sd->media_header = smh;

	sd->page_buf = page_buf;

	if (flags & SADUMP_DISKSET) {

		sd_list_len_0 = malloc(sizeof(struct sadump_diskset_data));
		if (!sd_list_len_0) {
			error(INFO,
			      "sadump: cannot allocate diskset data buffer\n");
			goto err;
		}

		sd_list_len_0->filename = sd->filename;
		sd_list_len_0->dfd = sd->dfd;
		sd_list_len_0->header = sd->header;
		sd_list_len_0->data_offset = sd->data_offset;

		sd->sd_list = malloc(sizeof(struct sadump_diskset_data *));
		if (!sd->sd_list) {
			error(INFO,
			      "sadump: cannot allocate diskset list buffer\n");
			goto err;
		}

		sd->sd_list_len = 1;
		sd->sd_list[0] = sd_list_len_0;
	}

	if (!block_table_init()) {
		error(INFO, "sadump: cannot initialize block hash table\n");
		goto err;
	}

	if (!(flags & SADUMP_DISKSET))
		free(sdh);

	if (!(flags & SADUMP_MEDIA))
		free(smh);

	return TRUE;

err:
	close(sd->dfd);

	free(sph);
	free(sdh);
	free(sh);
	free(smh);
	free(bitmap);
	free(dumpable_bitmap);
	free(page_buf);
	free(sd_list_len_0);

	free(sd->sd_list);

	return FALSE;
}

static int
add_disk(char *file)
{
	struct sadump_part_header *ph;
	struct sadump_diskset_data *this_disk;
	int diskid;
	char guid1[SADUMP_EFI_GUID_TEXT_REPR_LEN+1];
	char guid2[SADUMP_EFI_GUID_TEXT_REPR_LEN+1];

	diskid = sd->sd_list_len - 1;
	this_disk = sd->sd_list[diskid];

	if (CRASHDEBUG(1))
		error(INFO, "sadump: add disk #%d\n", diskid+1);

	ph = malloc(sd->block_size);
	if (!ph) {
		error(INFO, "sadump: cannot malloc block_size buffer\n");
		return FALSE;
	}

	if (lseek(this_disk->dfd, 0, SEEK_SET) == failed) {
		error(INFO, "sadump: cannot lseek dump partition header\n");
		free(ph);
		return FALSE;
	}
	if (read(this_disk->dfd, ph, sd->block_size) < sd->block_size) {
		error(INFO, "sadump: cannot read dump partition header\n");
		free(ph);
		return FALSE;
	}

	if (ph->signature1 != SADUMP_SIGNATURE1 ||
	    ph->signature2 != SADUMP_SIGNATURE2) {
		if (CRASHDEBUG(1))
			error(INFO, "sadump: does not have partition header\n");
		free(ph);
		return FALSE;
	}

	if (memcmp(&sd->header->sadump_id, &ph->sadump_id,
		   sizeof(efi_guid_t)) != 0) {
		if (CRASHDEBUG(1))
			error(INFO, "sadump: system ID mismatch\n"
			      "  partition header on disk #1: %s\n"
			      "  partition header on disk #%d: %s\n",
			      guid_to_str(&sd->header->sadump_id, guid1,
					  sizeof(guid1)),
			      diskid+1,
			      guid_to_str(&ph->sadump_id, guid2,
					  sizeof(guid2)));
		free(ph);
		return FALSE;
	}

	if (memcmp(&sd->header->disk_set_id, &ph->disk_set_id, sizeof(efi_guid_t)) != 0) {
		if (CRASHDEBUG(1))
			error(INFO, "sadump: disk set ID mismatch\n"
			      "  partition header on disk #1: %s\n"
			      "  partition header on disk #%d: %s\n",
			      guid_to_str(&sd->header->disk_set_id, guid1,
					  sizeof(guid1)),
			      diskid+1,
			      guid_to_str(&ph->disk_set_id, guid2,
					  sizeof(guid2)));
		free(ph);
		return FALSE;
	}

	if (memcmp(&sd->diskset_header->vol_info[diskid - 1].id, &ph->vol_id,
		   sizeof(efi_guid_t)) != 0) {
		if (CRASHDEBUG(1))
			error(INFO, "sadump: volume ID mismatch\n"
			      "  disk set header on disk #1: %s\n"
			      "  partition header on disk #%d: %s\n",
			      guid_to_str(&sd->diskset_header->vol_info[diskid-1].id,
					  guid1, sizeof(guid1)),
			      diskid+1,
			      guid_to_str(&ph->vol_id, guid2, sizeof(guid2)));
		free(ph);
		return FALSE;
	}

	if (memcmp(&sd->header->time_stamp, &ph->time_stamp,
		   sizeof(efi_time_t)) != 0) {
		if (CRASHDEBUG(1)) {
			error(INFO, "sadump: time stamp mismatch\n");
			error(INFO,
			      "sadump:   partition header on disk #1: %s\n",
			      strip_linefeeds(asctime
					      (efi_time_t_to_tm
					       (&sd->header->time_stamp))));
			error(INFO,
			      "sadump:   partition header on disk #%d: %s\n",
			      diskid+1,
			      strip_linefeeds(asctime
					      (efi_time_t_to_tm
					       (&ph->time_stamp))));
		}
	}

	if (diskid != ph->set_disk_set - 1) {
		if (CRASHDEBUG(1))
			error(INFO, "sadump: wrong disk order; "
			      "#%d expected but #%d given\n",
			      diskid+1, ph->set_disk_set);
		free(ph);
		return FALSE;
	}

	this_disk->header = ph;
	this_disk->data_offset = sd->block_size;
	this_disk->filename = file;

	return TRUE;
}

static int
open_dump_file(char *file)
{
	int fd;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		error(INFO, "sadump: unable to open dump file %s", file);
		return FALSE;
	}

	sd->dfd = fd;

	return TRUE;
}

static int
open_disk(char *file)
{
	struct sadump_diskset_data *this_disk;

	sd->sd_list_len++;

	if (CRASHDEBUG(1))
		error(INFO, "sadump: open disk #%d\n", sd->sd_list_len);

	if (sd->sd_list_len > sd->diskset_header->disk_num) {
		error(INFO, "sadump: too many diskset arguments; "
		      "this diskset consists of %d disks\n",
		      sd->diskset_header->disk_num);
		return FALSE;
	}

	sd->sd_list = realloc(sd->sd_list,
			      sd->sd_list_len *
			      sizeof(struct sadump_diskset_data *));
	if (!sd->sd_list) {
		if (CRASHDEBUG(1)) {
			error(INFO, "sadump: cannot malloc diskset list buffer\n");
		}
		return FALSE;
	}

	this_disk = malloc(sizeof(struct sadump_diskset_data));
	if (!this_disk) {
		if (CRASHDEBUG(1)) {
			error(INFO, "sadump: cannot malloc diskset data buffer\n");
		}
		return FALSE;
	}
	memset(this_disk, 0, sizeof(*this_disk));
	sd->sd_list[sd->sd_list_len - 1] = this_disk;

	this_disk->dfd = open(file, O_RDONLY);
	if (!this_disk->dfd) {
		free(this_disk);
		error(INFO, "sadump: unable to open dump file %s", file);
		return FALSE;
	}

	return TRUE;
}

int is_sadump(char *file)
{
	if (SADUMP_VALID()) {

		if (!(sd->flags & SADUMP_DISKSET)) {
			if (CRASHDEBUG(1))
				error(INFO, "sadump: does not support multiple"
				      " file formats\n");
			(void) sadump_cleanup_sadump_data();
			return FALSE;
		}

		if (!open_disk(file) || !add_disk(file)) {
			(void) sadump_cleanup_sadump_data();
			return FALSE;
		}

		return TRUE;
	}

	if (!open_dump_file(file) || !read_dump_header(file))
		return FALSE;

	return TRUE;
}

int sadump_is_diskset(void)
{
	if (!SADUMP_VALID())
		return FALSE;

	return !!(sd->flags & SADUMP_DISKSET);
}

uint sadump_page_size(void)
{
	return sd->dump_header->block_size;
}

/*
 * Translate physical address in paddr to PFN number. This means normally that
 * we just shift paddr by some constant.
 */
static uint64_t
paddr_to_pfn(physaddr_t paddr)
{
	return paddr >> sd->block_shift;
}

static inline int
is_set_bit(char *bitmap, uint64_t pfn)
{
	ulong index, bit;

	index = pfn >> 3;
	bit = 7 - (pfn & 7);

	return !!(bitmap[index] & (1UL << bit));
}

static inline int
page_is_ram(uint64_t nr)
{
	return is_set_bit(sd->bitmap, nr);
}

static inline int
page_is_dumpable(uint64_t nr)
{
	return is_set_bit(sd->dumpable_bitmap, nr);
}

static int
lookup_diskset(uint64_t whole_offset, int *diskid, uint64_t *disk_offset)
{
	uint64_t offset = whole_offset;
	int i;

	for (i = 0; i < sd->sd_list_len; ++i) {
		uint64_t used_device_i, ram_size;
		ulong data_offset_i;

		used_device_i = sd->sd_list[i]->header->used_device;
		data_offset_i = sd->sd_list[i]->data_offset;

		ram_size = used_device_i - data_offset_i;

		if (offset < ram_size)
			break;
		offset -= ram_size;
	}

	if (i == sd->sd_list_len)
		return FALSE;

	*diskid = i;
	*disk_offset = offset;

	return TRUE;
}

int read_sadump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	physaddr_t curpaddr ATTRIBUTE_UNUSED;
	uint64_t pfn, whole_offset, perdisk_offset, block;
	ulong page_offset;
	int dfd;

	if (sd->flags & SADUMP_KDUMP_BACKUP &&
	    paddr >= sd->backup_src_start &&
	    paddr < sd->backup_src_start + sd->backup_src_size) {
		ulong orig_paddr;

		orig_paddr = paddr;
		paddr += sd->backup_offset - sd->backup_src_start;

		if (CRASHDEBUG(1))
			error(INFO, "sadump: kdump backup region: %#llx => %#llx\n",
			      orig_paddr, paddr);

	}

	pfn = paddr_to_pfn(paddr);

	curpaddr = paddr & ~((physaddr_t)(sd->block_size-1));
	page_offset = paddr & ((physaddr_t)(sd->block_size-1));

	if ((pfn >= sd->max_mapnr) || !page_is_ram(pfn))
		return SEEK_ERROR;
	if (!page_is_dumpable(pfn)) {
		if (!(sd->flags & SADUMP_ZERO_EXCLUDED))
			return PAGE_EXCLUDED;
		memset(bufptr, 0, cnt);
		return cnt;
	}

	block = pfn_to_block(pfn);

	whole_offset = block * sd->block_size;

	if (sd->flags & SADUMP_DISKSET) {
		int diskid;

		if (!lookup_diskset(whole_offset, &diskid, &perdisk_offset))
			return SEEK_ERROR;

		dfd = sd->sd_list[diskid]->dfd;
		perdisk_offset += sd->sd_list[diskid]->data_offset;

	} else {
		dfd = sd->dfd;
		perdisk_offset = whole_offset + sd->data_offset;

	}

	if (lseek(dfd, perdisk_offset, SEEK_SET) == failed)
		return SEEK_ERROR;

	if (read(dfd, sd->page_buf, sd->block_size) != sd->block_size)
		return READ_ERROR;

	memcpy(bufptr, sd->page_buf + page_offset, cnt);

	return cnt;
}

int write_sadump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	return 0;
}

int sadump_init(char *unused, FILE *fptr)
{
	if (!SADUMP_VALID())
		return FALSE;

	return TRUE;
}

ulong get_sadump_panic_task(void)
{
	return NO_TASK;
}

ulong get_sadump_switch_stack(ulong task)
{
	return 0;
}

static struct tm *
efi_time_t_to_tm(const efi_time_t *e)
{
	static struct tm t;
	time_t ti;

	memset(&t, 0, sizeof(t));

	t.tm_sec  = e->second;
	t.tm_min  = e->minute;
	t.tm_hour = e->hour;
	t.tm_mday = e->day;
	t.tm_mon  = e->month - 1;
	t.tm_year = e->year - 1900;

	if (e->timezone != EFI_UNSPECIFIED_TIMEZONE)
		t.tm_hour += e->timezone;

	else if (CRASHDEBUG(1))
		error(INFO, "sadump: timezone information is missing\n");

	ti = mktime(&t);
	if (ti == (time_t)-1)
		return &t;

	return localtime_r(&ti, &t);
}

static char *
guid_to_str(efi_guid_t *guid, char *buf, size_t buflen)
{
	snprintf(buf, buflen,
		 "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		 htonl(guid->data1), htons(guid->data2), htons(guid->data3),
		 guid->data4[0], guid->data4[1], guid->data4[2],
		 guid->data4[3], guid->data4[4], guid->data4[5],
		 guid->data4[6], guid->data4[7]);

	return buf;
}

static int
verify_magic_number(uint32_t magicnum[DUMP_PART_HEADER_MAGICNUM_SIZE])
{
	int i;

	for (i = 1; i < DUMP_PART_HEADER_MAGICNUM_SIZE; ++i)
		if (magicnum[i] != (magicnum[i - 1] + 7) * 11)
			return FALSE;

	return TRUE;
}

int sadump_memory_used(void)
{
	return 0;
}

int sadump_free_memory(void)
{
	return 0;
}

/*
 *  This function is dump-type independent, and could be used to dump
 *  the diskdump_data structure contents and perhaps the sadump header
 *  data.
 */
int sadump_memory_dump(FILE *fp)
{
	struct sadump_part_header *sph;
	struct sadump_disk_set_header *sdh;
	struct sadump_header *sh;
	struct sadump_media_header *smh;
	int i, others;
	char guid[SADUMP_EFI_GUID_TEXT_REPR_LEN+1];

	fprintf(fp, "sadump_data: \n");
	fprintf(fp, "          filename: %s\n", sd->filename);
	fprintf(fp, "             flags: %lx (", sd->flags);
	others = 0;
	if (sd->flags & SADUMP_LOCAL)
		fprintf(fp, "%sSADUMP_LOCAL", others++ ? "|" : "");
	if (sd->flags & SADUMP_DISKSET)
		fprintf(fp, "%sSADUMP_DISKSET", others++ ? "|" : "");
	if (sd->flags & SADUMP_MEDIA)
		fprintf(fp, "%sSADUMP_MEDIA", others++ ? "|" : "");
	if (sd->flags & SADUMP_ZERO_EXCLUDED)
		fprintf(fp, "%sSADUMP_ZERO_EXCLUDED", others++ ? "|" : "");
	if (sd->flags & SADUMP_KDUMP_BACKUP)
		fprintf(fp, "%sSADUMP_KDUMP_BACKUP", others++ ? "|" : "");
	fprintf(fp, ") \n");
        fprintf(fp, "               dfd: %d\n", sd->dfd);
        fprintf(fp, "      machine_type: %d ", sd->machine_type);
	switch (sd->machine_type)
	{
	case EM_386:
		fprintf(fp, "(EM_386)\n"); break;
	case EM_X86_64:
		fprintf(fp, "(EM_X86_64)\n"); break;
	default:
		fprintf(fp, "(unknown)\n"); break;
	}

        fprintf(fp, "\n            header: %lx\n", (ulong)sd->header);
	sph = sd->header;
	fprintf(fp, "          signature1: %x\n", sph->signature1);
	fprintf(fp, "          signature2: %x\n", sph->signature2);
	fprintf(fp, "              enable: %u\n", sph->enable);
	fprintf(fp, "              reboot: %u\n", sph->reboot);
	fprintf(fp, "            compress: %u\n", sph->compress);
	fprintf(fp, "             recycle: %u\n", sph->recycle);
	fprintf(fp, "               label: (unused)\n");
	fprintf(fp, "           sadump_id: %s\n", guid_to_str(&sph->sadump_id, guid, sizeof(guid)));
	fprintf(fp, "         disk_set_id: %s\n", guid_to_str(&sph->disk_set_id, guid, sizeof(guid)));
	fprintf(fp, "              vol_id: %s\n", guid_to_str(&sph->vol_id, guid, sizeof(guid)));
	fprintf(fp, "          time_stamp: %s\n",
		strip_linefeeds(asctime(efi_time_t_to_tm(&sph->time_stamp))));
	fprintf(fp, "        set_disk_set: %u\n", sph->set_disk_set);
	fprintf(fp, "             reserve: %u\n", sph->reserve);
	fprintf(fp, "         used_device: %llu\n", (ulonglong)sph->used_device);
	fprintf(fp, "            magicnum: %s\n",
		verify_magic_number(sph->magicnum)
		? "(valid)" : "(invalid)");

        fprintf(fp, "\n       dump header: %lx\n", (ulong)sd->dump_header);
	sh = sd->dump_header;
	fprintf(fp, "           signature: %s\n", sh->signature);
	fprintf(fp, "      header_version: %u\n", sh->header_version);
	fprintf(fp, "             reserve: %u\n", sh->reserve);
	fprintf(fp, "           timestamp: %s\n",
		strip_linefeeds(asctime(efi_time_t_to_tm(&sh->timestamp))));
	fprintf(fp, "              status: %u\n", sh->status);
	fprintf(fp, "            compress: %u\n", sh->compress);
	fprintf(fp, "          block_size: %u\n", sh->block_size);
	fprintf(fp, "      extra_hdr_size: %u\n", sh->extra_hdr_size);
	fprintf(fp, "        sub_hdr_size: %u\n", sh->sub_hdr_size);
	fprintf(fp, "       bitmap_blocks: %u\n", sh->bitmap_blocks);
	fprintf(fp, "dumpable_bitmap_blocks: %u\n", sh->dumpable_bitmap_blocks);
	fprintf(fp, "           max_mapnr: %u\n", sh->max_mapnr);
	fprintf(fp, "    total_ram_blocks: %u\n", sh->total_ram_blocks);
	fprintf(fp, "       device_blocks: %u\n", sh->device_blocks);
	fprintf(fp, "      written_blocks: %u\n", sh->written_blocks);
	fprintf(fp, "         current_cpu: %u\n", sh->current_cpu);
	fprintf(fp, "             nr_cpus: %u\n", sh->nr_cpus);
	if (sh->header_version >= 1) {
		fprintf(fp,
			"        max_mapnr_64: %" PRIu64 "\n"
			" total_ram_blocks_64: %" PRIu64 "\n"
			"    device_blocks_64: %" PRIu64 "\n"
			"   written_blocks_64: %" PRIu64 "\n",
			sh->max_mapnr_64,
			sh->total_ram_blocks_64,
			sh->device_blocks_64,
			sh->written_blocks_64);
	}

	fprintf(fp, "\n    dump sub heaer: ");
	if (sh->sub_hdr_size > 0) {
		ulong offset = sd->sub_hdr_offset;
		struct sadump_apic_state as;
		struct sadump_smram_cpu_state scs, zero;
		uint32_t size;
		uint aid;

		memset(&zero, 0, sizeof(zero));

		if (!read_device(&size, sizeof(uint32_t), &offset)) {
			error(INFO, "sadump: cannot read sub header size\n");
			return FALSE;
		}
		fprintf(fp, "\n                size: %u\n", size);
		for (aid = 0; aid < sh->nr_cpus; ++aid) {
			if (!read_device(&as, sizeof(as), &offset)) {
				error(INFO, "sadump: cannot read sub header "
				      "apic_id\n");
				return FALSE;
			}
			fprintf(fp, "          "
				"apic_id[%u]: ApicId %llu: Ldr: %llu\n",
				aid, (ulonglong)as.ApicId, (ulonglong)as.Ldr);
		}
		for (aid = 0; aid < sh->nr_cpus; ++aid) {
			if (!read_device(&scs, sizeof(scs), &offset)) {
				error(INFO, "sadump: cannot read sub header "
				      "cpu_state\n");
				return FALSE;
			}
			/*
			 * Reserved fields in SMRAM CPU states could
			 * be non-zero even if the corresponding APICs
			 * are NOT used. This breaks the assumption
			 * that SMRAM CPU state is zero cleared if and
			 * only if the APIC corresponding to the entry
			 * is NOT used.
			 */
			mask_reserved_fields(&scs);
			if (memcmp(&scs, &zero, sizeof(scs)) != 0) {
				fprintf(fp, "\n");
				display_smram_cpu_state(aid, &scs);
			}
		}
	} else
		fprintf(fp, "(n/a)\n");

        fprintf(fp, "\n   disk set header: %lx ", (ulong)sd->diskset_header);
	if ((sdh = sd->diskset_header)) {
		fprintf(fp, "\ndisk_set_header_size: %u\n", sdh->disk_set_header_size);
		fprintf(fp, "            disk_num: %u\n", sdh->disk_num);
		fprintf(fp, "       disk_set_size: %llu\n", (ulonglong)sdh->disk_set_size);
		for (i = 0; i < sdh->disk_num - 1; ++i) {
			struct sadump_volume_info *vol = &sdh->vol_info[i];

			fprintf(fp, "         vol_info[%d]: \n", i);
			fprintf(fp, "                     id: %s\n", guid_to_str(&vol->id, guid, sizeof(guid)));
			fprintf(fp, "               vol_size: %llu\n", (ulonglong)vol->vol_size);
			fprintf(fp, "                 status: %u\n", vol->status);
			fprintf(fp, "             cache_size: %u\n", vol->cache_size);
		}
	} else
		fprintf(fp, "(n/a)\n");

        fprintf(fp, "\n      media header: %lx ", (ulong)sd->media_header);
	if ((smh = sd->media_header)) {
		fprintf(fp, "\n           sadump_id: %s\n", guid_to_str(&smh->sadump_id, guid, sizeof(guid)));
		fprintf(fp, "         disk_set_id: %s\n", guid_to_str(&smh->disk_set_id, guid, sizeof(guid)));
		fprintf(fp, "          time_stamp: %s\n",
			strip_linefeeds(asctime(efi_time_t_to_tm(&smh->time_stamp))));
		fprintf(fp, "      sequential_num: %d\n", smh->sequential_num);
		fprintf(fp, "           term_cord: %d\n", smh->term_cord);
		fprintf(fp, "disk_set_header_size: %d\n", smh->disk_set_header_size);
		fprintf(fp, "        disks_in_use: %d\n", smh->disks_in_use);
		fprintf(fp, "             reserve: (not displayed) \n");
	} else
		fprintf(fp, "(n/a)\n");

        fprintf(fp, "\n            bitmap: %lx\n", (ulong)sd->bitmap);
        fprintf(fp, "   dumpable_bitmap: %lx\n", (ulong)sd->dumpable_bitmap);
        fprintf(fp, "    sub_hdr_offset: %lx\n", (ulong)sd->sub_hdr_offset);
        fprintf(fp, "smram_cpu_state_size: %lx\n", (ulong)sd->smram_cpu_state_size);
        fprintf(fp, "       data_offset: %lx\n", sd->data_offset);
        fprintf(fp, "        block_size: %d\n", sd->block_size);
        fprintf(fp, "       block_shift: %d\n", sd->block_shift);
	fprintf(fp, "          page_buf: %lx\n", (ulong)sd->page_buf);
	fprintf(fp, "       block_table: %lx\n", (ulong)sd->block_table);
	fprintf(fp, "       sd_list_len: %d\n", sd->sd_list_len);
	fprintf(fp, "           sd_list: %lx\n", (ulong)sd->sd_list);
	fprintf(fp, "  backup_src_start: %llx\n", sd->backup_src_start);
	fprintf(fp, "   backup_src_size: %lx\n", sd->backup_src_size);
	fprintf(fp, "     backup_offset: %llx\n", (ulonglong)sd->backup_src_size);

	for (i = 0; i < sd->sd_list_len; ++i) {
		struct sadump_diskset_data *sdd = sd->sd_list[i];

		fprintf(fp, "\n        sd_list[%d]: \n", i);
		fprintf(fp, "            filename: %s\n", sdd->filename);
		fprintf(fp, "                 dfd: %d\n", sdd->dfd);

		fprintf(fp, "              header: %lx\n", (ulong)sdd->header);
		sph = sdd->header;
		fprintf(fp, "            signature1: %x\n", sph->signature1);
		fprintf(fp, "            signature2: %x\n", sph->signature2);
		fprintf(fp, "                enable: %u\n", sph->enable);
		fprintf(fp, "                reboot: %u\n", sph->reboot);
		fprintf(fp, "              compress: %u\n", sph->compress);
		fprintf(fp, "               recycle: %u\n", sph->recycle);
		fprintf(fp, "                 label: (unused)\n");
		fprintf(fp, "             sadump_id: %s\n", guid_to_str(&sph->sadump_id, guid, sizeof(guid)));
		fprintf(fp, "           disk_set_id: %s\n", guid_to_str(&sph->disk_set_id, guid, sizeof(guid)));
		fprintf(fp, "                vol_id: %s\n", guid_to_str(&sph->vol_id, guid, sizeof(guid)));
		fprintf(fp, "            time_stamp: %s\n",
			strip_linefeeds(asctime(efi_time_t_to_tm(&sph->time_stamp))));
		fprintf(fp, "          set_disk_set: %u\n", sph->set_disk_set);
		fprintf(fp, "               reserve: %u\n", sph->reserve);
		fprintf(fp, "           used_device: %llu\n", (ulonglong)sph->used_device);
		fprintf(fp, "              magicnum: %s\n",
			verify_magic_number(sph->magicnum)
			? "(valid)" : "(invalid)");

		fprintf(fp, "         data_offset: %lx\n", sdd->data_offset);
	}

	return TRUE;
}

static ulong
per_cpu_ptr(ulong ptr, int cpu)
{
	if (cpu < 0 || cpu >= kt->cpus)
		return 0UL;

	if (kt->cpus == 1)
		return ptr;

	if (!(kt->flags & PER_CPU_OFF))
		return 0UL;

	if (machine_type("X86_64")) {
		ulong __per_cpu_load;

		readmem(symbol_value("__per_cpu_load"), KVADDR,
			&__per_cpu_load, sizeof(__per_cpu_load),
			"__per_cpu_load", FAULT_ON_ERROR);

		if (kt->__per_cpu_offset[cpu] == __per_cpu_load)
			return 0UL;

	} else if (machine_type("X86")) {
		if (kt->__per_cpu_offset[cpu] == 0)
			return 0UL;

	}

	return ptr + kt->__per_cpu_offset[cpu];
}

static ulong
early_per_cpu_ptr(char *symbol, struct syment *sym, int cpu)
{
	char sym_early_ptr[BUFSIZE], sym_early_map[BUFSIZE];
	ulong early_ptr;

	if (cpu < 0 || cpu >= kt->cpus)
		return 0UL;

	if (!sym && !(sym = per_cpu_symbol_search(symbol)))
		return 0UL;

	if (!(kt->flags & SMP))
		return per_cpu_ptr(sym->value, cpu);

	snprintf(sym_early_ptr, BUFSIZE, "%s_early_ptr", symbol);
	snprintf(sym_early_map, BUFSIZE, "%s_early_map", symbol);

	if (!symbol_exists(sym_early_ptr) || !symbol_exists(sym_early_map))
		return 0UL;

	readmem(symbol_value(sym_early_ptr), KVADDR, &early_ptr,
		sizeof(early_ptr), sym_early_ptr, FAULT_ON_ERROR);

	return early_ptr
		? symbol_value(sym_early_map)+cpu*sizeof(uint16_t)
		: per_cpu_ptr(sym->value, cpu);
}

static ulong
legacy_per_cpu_ptr(ulong ptr, int cpu)
{
	ulong addr;

	if (!(kt->flags & SMP))
		return ptr;

	if (cpu < 0 || cpu >= kt->cpus)
		return 0UL;

	if (!readmem(~ptr + cpu * sizeof(ulong), KVADDR, &addr, sizeof(ulong),
		     "search percpu_data", FAULT_ON_ERROR))
		return 0UL;

	return addr;
}

/**
 * Retrieve eip and esp register values from crash_notes saved by
 * kdump at crash. If register values has not been saved yet, set 0 to
 * eip and esp instead.
 */
static int
get_prstatus_from_crash_notes(int cpu, char *prstatus)
{
	ulong crash_notes, crash_notes_ptr, percpu_addr;
	char *prstatus_ptr, *note_buf, *zero_buf, *name;
	uint32_t *buf;

	if (cpu < 0 || kt->cpus <= cpu) {
		error(INFO, "sadump: given cpu is invalid: %d\n", cpu);
		return FALSE;
	}

	if (!symbol_exists("crash_notes")) {
		error(INFO, "sadump: symbol crash_notes doesn't exist\n");
		return FALSE;
	}

	crash_notes = symbol_value("crash_notes");

	readmem(crash_notes, KVADDR, &crash_notes_ptr, sizeof(ulong),
		"dereference crash_notes", FAULT_ON_ERROR);

	if (!crash_notes_ptr) {
		if (CRASHDEBUG(1))
			error(INFO,
			      "sadump: buffer for crash_notes is NULL\n");
		return FALSE;
	}

	percpu_addr = VALID_STRUCT(percpu_data)
		? legacy_per_cpu_ptr(crash_notes_ptr, cpu)
		: per_cpu_ptr(crash_notes_ptr, cpu);

	zero_buf = GETBUF(SIZE(note_buf));
	BZERO(zero_buf, SIZE(note_buf));

	note_buf = GETBUF(SIZE(note_buf));

	readmem(percpu_addr, KVADDR, note_buf, SIZE(note_buf),
		"read crash_notes", FAULT_ON_ERROR);

	if (memcmp(note_buf, zero_buf, SIZE(note_buf)) == 0)
		return FALSE;

	if (BITS64()) {
		Elf64_Nhdr *note64;

		note64 = (Elf64_Nhdr *)note_buf;
		buf = (uint32_t *)note_buf;
		name = (char *)(note64 + 1);

		if (note64->n_type != NT_PRSTATUS ||
		    note64->n_namesz != strlen("CORE") + 1 ||
		    strncmp(name, "CORE", note64->n_namesz) ||
		    note64->n_descsz != SIZE(elf_prstatus))
			return FALSE;

		prstatus_ptr = (char *)(buf + (sizeof(*note64) + 3) / 4 +
					(note64->n_namesz + 3) / 4);

	} else {
		Elf32_Nhdr *note32;

		note32 = (Elf32_Nhdr *)note_buf;
		buf = (uint32_t *)note_buf;
		name = (char *)(note32 + 1);

		if ((note32->n_type != NT_PRSTATUS) &&
		    (note32->n_namesz != strlen("CORE") + 1 ||
		     strncmp(name, "CORE", note32->n_namesz) ||
		     note32->n_descsz != SIZE(elf_prstatus)))
			return FALSE;

		prstatus_ptr = (char *)(buf + (sizeof(*note32) + 3) / 4 +
					(note32->n_namesz + 3) / 4);

	}

	memcpy(prstatus, prstatus_ptr, SIZE(elf_prstatus));

	return TRUE;
}

int
sadump_get_smram_cpu_state(int apicid,
			   struct sadump_smram_cpu_state *smram)
{
	ulong offset;

	if (!sd->sub_hdr_offset || !sd->smram_cpu_state_size ||
	    apicid >= sd->dump_header->nr_cpus)
		return FALSE;

	offset = sd->sub_hdr_offset + sizeof(uint32_t) +
		sd->dump_header->nr_cpus * sizeof(struct sadump_apic_state);

	if (lseek(sd->dfd, offset + apicid * sd->smram_cpu_state_size,
		  SEEK_SET) == failed)
		error(FATAL,
		      "sadump: cannot lseek smram cpu state in dump sub header\n");

	if (read(sd->dfd, smram, sd->smram_cpu_state_size) != sd->smram_cpu_state_size)
		error(FATAL, "sadump: cannot read smram cpu state in dump sub "
		      "header\n");

	return TRUE;
}

static void
display_smram_cpu_state(int apicid, struct sadump_smram_cpu_state *s)
{
	fprintf(fp,
		"APIC ID: %d\n"
		"    RIP: %016llx RSP: %08x%08x RBP: %08x%08x\n"
		"    RAX: %08x%08x RBX: %08x%08x RCX: %08x%08x\n"
		"    RDX: %08x%08x RSI: %08x%08x RDI: %08x%08x\n"
		"    R08: %08x%08x R09: %08x%08x R10: %08x%08x\n"
		"    R11: %08x%08x R12: %08x%08x R13: %08x%08x\n"
		"    R14: %08x%08x R15: %08x%08x\n"
		"    SMM REV: %08x SMM BASE %08x\n"
		"    CS : %08x DS: %08x SS: %08x ES: %08x FS: %08x\n"
		"    GS : %08x\n"
		"    CR0: %016llx CR3: %016llx CR4: %08x\n"
		"    GDT: %08x%08x LDT: %08x%08x IDT: %08x%08x\n"
		"    GDTlim: %08x LDTlim: %08x IDTlim: %08x\n"
		"    LDTR: %08x TR: %08x RFLAGS: %016llx\n"
		"    EPTP: %016llx EPTP_SETTING: %08x\n"
		"    DR6: %016llx DR7: %016llx\n"
		"    Ia32Efer: %016llx\n"
		"    IoMemAddr: %08x%08x IoEip: %016llx\n"
		"    IoMisc: %08x LdtInfo: %08x\n"
		"    IoInstructionRestart: %04x AutoHaltRestart: %04x\n",
		apicid,
		(ulonglong)s->Rip, s->RspUpper, s->RspLower, s->RbpUpper, s->RbpLower,
		s->RaxUpper, s->RaxLower, s->RbxUpper, s->RbxLower, s->RcxUpper, s->RcxLower,
		s->RdxUpper, s->RdxLower, s->RsiUpper, s->RsiLower, s->RdiUpper, s->RdiLower,
		s->R8Upper, s->R8Lower,	s->R9Upper, s->R9Lower,	s->R10Upper, s->R10Lower,
		s->R11Upper, s->R11Lower, s->R12Upper, s->R12Lower, s->R13Upper, s->R13Lower,
		s->R14Upper, s->R14Lower, s->R15Upper, s->R15Lower,
		s->SmmRevisionId, s->Smbase,
		s->Cs, s->Ds, s->Ss, s->Es, s->Fs, s->Gs,
		(ulonglong)s->Cr0, (ulonglong)s->Cr3, s->Cr4,
		s->GdtUpper, s->GdtLower, s->LdtUpper, s->LdtLower, s->IdtUpper, s->IdtLower,
		s->GdtLimit, s->LdtLimit, s->IdtLimit,
		s->Ldtr, s->Tr, (ulonglong)s->Rflags,
		(ulonglong)s->Eptp, s->EptpSetting,
		(ulonglong)s->Dr6, (ulonglong)s->Dr7,
		(ulonglong)s->Ia32Efer,
		s->IoMemAddrUpper, s->IoMemAddrLower, (ulonglong)s->IoEip,
		s->IoMisc, s->LdtInfo,
		s->IoInstructionRestart,
		s->AutoHaltRestart);
}

static int cpu_to_apicid(int cpu, int *apicid)
{
	struct syment *sym;

	if (symbol_exists("bios_cpu_apicid")) {
		uint8_t apicid_u8;

		readmem(symbol_value("bios_cpu_apicid") + cpu*sizeof(uint8_t),
			KVADDR, &apicid_u8, sizeof(uint8_t), "bios_cpu_apicid",
			FAULT_ON_ERROR);

		*apicid = (int)apicid_u8;

		if (CRASHDEBUG(1))
			error(INFO, "sadump: apicid %u for cpu %d from "
			      "bios_cpu_apicid\n", apicid_u8, cpu);

	} else if ((sym = per_cpu_symbol_search("x86_bios_cpu_apicid"))) {
		uint16_t apicid_u16;

		readmem(early_per_cpu_ptr("x86_bios_cpu_apicid", sym, cpu),
			KVADDR, &apicid_u16, sizeof(uint16_t),
			"x86_bios_cpu_apicid", FAULT_ON_ERROR);

		*apicid = (int)apicid_u16;

		if (CRASHDEBUG(1))
			error(INFO, "sadump: apicid %u for cpu %d from "
			      "x86_bios_cpu_apicid\n", apicid_u16, cpu);

	} else {
		if (CRASHDEBUG(1))
			error(INFO, "sadump: no symbols for access to apicid\n");

		return FALSE;
	}

	return TRUE;
}

static int
get_sadump_smram_cpu_state(int cpu, struct sadump_smram_cpu_state *smram)
{
	int apicid = 0;

	if (cpu < 0 || kt->cpus <= cpu) {
		error(INFO, "sadump: given cpu is invalid: %d\n", cpu);
		return FALSE;
	}

	if (!cpu_to_apicid(cpu, &apicid))
		return FALSE;

	sadump_get_smram_cpu_state(apicid, smram);

	return TRUE;
}

void get_sadump_regs(struct bt_info *bt, ulong *ipp, ulong *spp)
{
	ulong ip, sp;
	struct sadump_smram_cpu_state smram;
	char *prstatus;
	int cpu = bt->tc->processor;

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

	prstatus = GETBUF(SIZE(elf_prstatus));

	if (get_prstatus_from_crash_notes(cpu, prstatus)) {
		ip = ULONG(prstatus +
			   OFFSET(elf_prstatus_pr_reg) +
			   (BITS64()
			    ? OFFSET(user_regs_struct_rip)
			    : OFFSET(user_regs_struct_eip)));
		sp = ULONG(prstatus +
			   OFFSET(elf_prstatus_pr_reg) +
			   (BITS64()
			    ? OFFSET(user_regs_struct_rsp)
			    : OFFSET(user_regs_struct_eip)));
		if (ip || sp) {
			*ipp = ip;
			*spp = sp;
			return;
		}
	}

	get_sadump_smram_cpu_state(cpu, &smram);
	ip = smram.Rip;
	sp = ((uint64_t)smram.RspUpper << 32) + smram.RspLower;

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

void
sadump_display_regs(int cpu, FILE *ofp)
{
	struct sadump_smram_cpu_state smram;

	if (cpu < 0 || cpu >= kt->cpus) {
		error(INFO, "sadump: given cpu is invalid: %d\n", cpu);
		return;
	}

	get_sadump_smram_cpu_state(cpu, &smram);

	if (machine_type("X86_64")) {
		fprintf(ofp,
			"    RIP: %016llx  RSP: %016llx  RFLAGS: %08llx\n"
			"    RAX: %016llx  RBX: %016llx  RCX: %016llx\n"
			"    RDX: %016llx  RSI: %016llx  RDI: %016llx\n"
			"    RBP: %016llx   R8: %016llx   R9: %016llx\n"
			"    R10: %016llx  R11: %016llx  R12: %016llx\n"
			"    R13: %016llx  R14: %016llx  R15: %016llx\n"
			"    CS: %04x  SS: %04x\n",
			(ulonglong)(smram.Rip),
			(ulonglong)(((uint64_t)smram.RspUpper<<32)+smram.RspLower),
			(ulonglong)(smram.Rflags),
			(ulonglong)(((uint64_t)smram.RaxUpper<<32)+smram.RaxLower),
			(ulonglong)(((uint64_t)smram.RbxUpper<<32)+smram.RbxLower),
			(ulonglong)(((uint64_t)smram.RcxUpper<<32)+smram.RcxLower),
			(ulonglong)(((uint64_t)smram.RdxUpper<<32)+smram.RdxLower),
			(ulonglong)(((uint64_t)smram.RsiUpper<<32)+smram.RsiLower),
			(ulonglong)(((uint64_t)smram.RdiUpper<<32)+smram.RdiLower),
			(ulonglong)(((uint64_t)smram.RbpUpper<<32)+smram.RbpLower),
			(ulonglong)(((uint64_t)smram.R8Upper<<32)+smram.R8Lower),
			(ulonglong)(((uint64_t)smram.R9Upper<<32)+smram.R9Lower),
			(ulonglong)(((uint64_t)smram.R10Upper<<32)+smram.R10Lower),
			(ulonglong)(((uint64_t)smram.R11Upper<<32)+smram.R11Lower),
			(ulonglong)(((uint64_t)smram.R12Upper<<32)+smram.R12Lower),
			(ulonglong)(((uint64_t)smram.R13Upper<<32)+smram.R13Lower),
			(ulonglong)(((uint64_t)smram.R14Upper<<32)+smram.R14Lower),
			(ulonglong)(((uint64_t)smram.R15Upper<<32)+smram.R15Lower),
			smram.Cs,
			smram.Ss);
	}

	if (machine_type("X86")) {
		fprintf(ofp,
			"    EAX: %08llx  EBX: %08llx  ECX: %08llx  EDX: %08llx\n"
			"    DS:  %04x      ESI: %08llx  ES:  %04x      EDI: %08llx\n"
			"    SS:  %04x      ESP: %08llx  EBP: %08llx  GS:  %04x\n"
			"    CS:  %04x      EIP: %08llx  EFLAGS: %08llx\n",
			(ulonglong)smram.RaxLower,
			(ulonglong)smram.RbxLower,
			(ulonglong)smram.RcxLower,
			(ulonglong)smram.RdxLower,
			smram.Ds & 0xffff,
			(ulonglong)smram.RsiLower,
			smram.Es & 0xffff,
			(ulonglong)smram.RdiLower,
			smram.Ss,
			(ulonglong)smram.RspLower,
			(ulonglong)smram.RbpLower,
			smram.Gs,
			smram.Cs,
			(ulonglong)smram.Rip,
			(ulonglong)smram.Rflags);
	}
}

/*
 * sadump does not save phys_base; it must resort to another way.
 */
int sadump_phys_base(ulong *phys_base)
{
	if (SADUMP_VALID() && !sd->phys_base) {
		if (CRASHDEBUG(1))
			error(NOTE, "sadump: does not save phys_base.\n");
		return FALSE;
	}

	if (sd->phys_base) {
		*phys_base = sd->phys_base;
		return TRUE;
	}

	return FALSE;
}

int
sadump_set_phys_base(ulong phys_base)
{
	sd->phys_base = phys_base;

	return TRUE;
}

/*
 *  Used by "sys" command to show diskset disk names.
 */
void sadump_show_diskset(void)
{
	int i;

	for (i = 0; i < sd->sd_list_len; ++i) {
		char *filename = sd->sd_list[i]->filename;

		fprintf(fp, "%s%s", i ? "              " : "",
			filename);
		if ((i+1) < sd->sd_list_len)
			fprintf(fp, "\n");
	}
}

static int block_table_init(void)
{
	uint64_t pfn, section, max_section, *block_table;

	max_section = divideup(sd->max_mapnr, SADUMP_PF_SECTION_NUM);

	block_table = calloc(sizeof(uint64_t), max_section);
	if (!block_table) {
		error(INFO, "sadump: cannot allocate memory for block_table\n");
		return FALSE;
	}

	for (section = 0; section < max_section; ++section) {
		if (section > 0)
			block_table[section] = block_table[section-1];
		for (pfn = section * SADUMP_PF_SECTION_NUM;
		     pfn < (section + 1) * SADUMP_PF_SECTION_NUM;
		     ++pfn)
			if (page_is_dumpable(pfn))
				block_table[section]++;
	}

	sd->block_table = block_table;

	return TRUE;
}

static uint64_t pfn_to_block(uint64_t pfn)
{
	uint64_t block, section, p;

	section = pfn / SADUMP_PF_SECTION_NUM;

	if (section)
		block = sd->block_table[section - 1];
	else
		block = 0;

	for (p = section * SADUMP_PF_SECTION_NUM; p < pfn; ++p)
		if (page_is_dumpable(p))
			block++;

	return block;
}

int sadump_is_zero_excluded(void)
{
	return (sd->flags & SADUMP_ZERO_EXCLUDED) ? TRUE : FALSE;
}

void sadump_set_zero_excluded(void)
{
	sd->flags |= SADUMP_ZERO_EXCLUDED;
}

void sadump_unset_zero_excluded(void)
{
	sd->flags &= ~SADUMP_ZERO_EXCLUDED;
}

struct sadump_data *
get_sadump_data(void)
{
	return sd;
}

int
sadump_get_nr_cpus(void)
{
	/* apicids */
	return sd->dump_header->nr_cpus;
}

#ifdef X86_64
int
sadump_get_cr3_cr4_idtr(int cpu, ulong *cr3, ulong *cr4, ulong *idtr)
{
	struct sadump_smram_cpu_state scs;

	memset(&scs, 0, sizeof(scs));
	if (!sadump_get_smram_cpu_state(cpu, &scs))
		return FALSE;

	*cr3 = scs.Cr3;
	*cr4 = scs.Cr4;
	*idtr = ((uint64_t)scs.IdtUpper)<<32 | (uint64_t)scs.IdtLower;

	return TRUE;
}
#endif /* X86_64 */

static void
mask_reserved_fields(struct sadump_smram_cpu_state *smram)
{
	memset(smram->Reserved1, 0, sizeof(smram->Reserved1));
	memset(smram->Reserved2, 0, sizeof(smram->Reserved2));
	memset(smram->Reserved3, 0, sizeof(smram->Reserved3));
	memset(smram->Reserved4, 0, sizeof(smram->Reserved4));
	memset(smram->Reserved5, 0, sizeof(smram->Reserved5));
	memset(smram->Reserved6, 0, sizeof(smram->Reserved6));
	memset(smram->Reserved7, 0, sizeof(smram->Reserved7));
}
