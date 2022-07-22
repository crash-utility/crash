/* 
 * makedumpfile.c
 * 
 * This code is for reading a dumpfile ganarated by makedumpfile command.
 *
 * Copyright (C) 2011  NEC Soft, Ltd.
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
 * Author: Ken'ichi Ohmichi <oomichi mxs nes nec co jp>
 */

#define _LARGEFILE64_SOURCE 1  /* stat64() */
#include "defs.h"
#include "makedumpfile.h"
#include <byteswap.h>

static void flattened_format_get_osrelease(char *);

int flattened_format = 0;

struct flat_data {
	int64_t off_flattened;
	int64_t off_rearranged; /* offset which will be rearranged. */
	int64_t buf_size;
};

struct all_flat_data {
	unsigned long long	num_array;
	struct flat_data	*array;
	size_t			file_size;
};

struct all_flat_data afd;

struct makedumpfile_header fh_save;

static int
is_bigendian(void)
{
	int i = 0x12345678;

	if (*(char *)&i == 0x12)
		return TRUE;
	else
		return FALSE;
}

static unsigned long long
store_flat_data_array(char *file, struct flat_data **fda)
{
	int			result = FALSE, fd;
	int64_t			offset_fdh;
	int64_t			offset_report = 0;
	unsigned long long	num_allocated = 0;
	unsigned long long	num_stored    = 0;
	unsigned long long	sort_idx;
	unsigned long long	size_allocated;
	struct flat_data	*ptr = NULL, *cur, *new;
	struct makedumpfile_data_header	fdh;
	struct stat64		stat;
	ulonglong		pct, last_pct;
	char			buf[BUFSIZE];
	ssize_t			bytes_read;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		error(INFO, "unable to open dump file %s\n", file);
		return -1;
	}
	if (lseek(fd, MAX_SIZE_MDF_HEADER, SEEK_SET) < 0) {
		error(INFO, "%s: seek error (flat format)\n", file);
		close(fd);
		return -1;
	}
	if (stat64(file, &stat) < 0) {
		error(INFO, "cannot stat64 %s\n", file);
                return -1;
	}

	please_wait("sorting flat format data");
	pct = last_pct = 0;
	while (1) {
		if (num_allocated <= num_stored) {
			num_allocated += 100;
			size_allocated = sizeof(struct flat_data)
					 * num_allocated;
			new = realloc(ptr, size_allocated);
			if (new == NULL) {
				error(INFO, 
				    "unable to realloc flat_data structures\n");
				break;
			}
			ptr = new;
		}
		offset_fdh = lseek(fd, 0x0, SEEK_CUR);

		if ((bytes_read = read(fd, &fdh, sizeof(fdh))) != sizeof(fdh)) {
			if (bytes_read >= 0)
				error(INFO, 
				    "read error: %s (flat format): truncated/incomplete\n", 
					file);
			else
				error(INFO, "read error: %s (flat format)\n", file);
			break;
		}
		if (!is_bigendian()){
			fdh.offset   = bswap_64(fdh.offset);
			fdh.buf_size = bswap_64(fdh.buf_size);
		}
		if (fdh.offset == END_FLAG_FLAT_HEADER) {
			result = TRUE;
			break;
		}
		cur = ptr + num_stored;
		sort_idx = num_stored;
		while (sort_idx) {
			new = ptr + --sort_idx;
			if (new->off_rearranged >= fdh.offset) {
				cur->off_flattened = new->off_flattened;
				cur->off_rearranged = new->off_rearranged;
				cur->buf_size = new->buf_size;
				cur = new;
			} else {
				if (CRASHDEBUG(1) && sort_idx + 1 != num_stored) {
					fprintf(fp,
						"makedumpfile: Moved from %lld to %lld\n",
						num_stored, sort_idx + 1);
				}
				break;
			}
		}
		cur->off_flattened  = offset_fdh + sizeof(fdh);
		cur->off_rearranged = fdh.offset;
		cur->buf_size       = fdh.buf_size;
		num_stored++;

		pct = (offset_fdh * 100ULL) / stat.st_size; 
		if (pct > last_pct) {
			sprintf(buf, "sorting flat format data: %lld%%", (ulonglong)pct);
			please_wait(buf);
			if (CRASHDEBUG(1))
				fprintf(fp, "\n");
			last_pct = pct;
		}

		if (CRASHDEBUG(1) && (fdh.offset >> 30) > (offset_report >> 30)) {
			fprintf(fp, "makedumpfile: At %lld GiB\n",
			      (ulonglong)(fdh.offset >> 30));
			offset_report = fdh.offset;
		}

		/* seek for next makedumpfile_data_header. */
		if (lseek(fd, fdh.buf_size, SEEK_CUR) < 0) {
			error(INFO, "%s: seek error (flat format)\n", file);
			break;
		}
	}
	please_wait_done();

	close(fd);
	if (result == FALSE) {
		free(ptr);
		return -1;
	}
	*fda = ptr;

	return num_stored;
}

static int
read_all_makedumpfile_data_header(char *file)
{
	unsigned long long	num;
	struct flat_data	*fda = NULL;
	long long retval;

	retval = num = store_flat_data_array(file, &fda);
	if (retval < 0)
		return FALSE;

	afd.num_array = num;
	afd.array     = fda;

	return TRUE;
}

void
check_flattened_format(char *file)
{
	int fd, get_osrelease;
	struct stat stat;
	struct makedumpfile_header fh;

	if (pc->flags2 & GET_OSRELEASE) {
		get_osrelease = TRUE;
		pc->flags2 &= ~GET_OSRELEASE;
	} else
		get_osrelease = FALSE;

	if (flattened_format)
		goto out;

	if (file_exists(file, &stat) && S_ISCHR(stat.st_mode))
		goto out;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		error(INFO, "unable to open dump file %s\n", file);
		goto out;
	}
	if (read(fd, &fh, sizeof(fh)) < 0) {
		error(INFO, "unable to read dump file %s\n", file);
		close(fd);
		goto out;
	}
	close(fd);

	if (!is_bigendian()){
		fh.type    = bswap_64(fh.type);
		fh.version = bswap_64(fh.version);
	}
	if ((strncmp(fh.signature, MAKEDUMPFILE_SIGNATURE, sizeof(MAKEDUMPFILE_SIGNATURE)) != 0) || 
	    (fh.type != TYPE_FLAT_HEADER))
		goto out;

	if (get_osrelease) {
		flattened_format_get_osrelease(file);
		return;
	}

	if (!read_all_makedumpfile_data_header(file))
		return;

	if (CRASHDEBUG(1))
		fprintf(fp, "%s: FLAT\n\n", file);

	fh_save = fh;

	flattened_format = TRUE;
	return;

out:
	if (get_osrelease)
		pc->flags2 |= GET_OSRELEASE;
}

static int
read_raw_dump_file(int fd, off_t offset, void *buf, size_t size)
{
	if (lseek(fd, offset, SEEK_SET) < 0) {
		if (CRASHDEBUG(1))
			error(INFO, "read_raw_dump_file: lseek error (flat format)\n");
		return FALSE;
	}
	if (read(fd, buf, size) < size) {
		if (CRASHDEBUG(1))
			error(INFO, "read_raw_dump_file: read error (flat format)\n");
		return FALSE;
	}

	return TRUE;
}

int
read_flattened_format(int fd, off_t offset, void *buf, size_t size)
{
	unsigned long long	index, index_start, index_end;
	int64_t			range_start, range_end;
	size_t			read_size, remain_size;
	off_t			offset_read;
	struct flat_data	*ptr;

	index_start = 0;
	index_end   = afd.num_array;

	while (1) {
		index = (index_start + index_end) / 2;
		ptr = afd.array + index;
		range_start = ptr->off_rearranged;
		range_end   = ptr->off_rearranged + ptr->buf_size;

		if ((range_start <= offset) && (offset < range_end)) {
			/* Found a corresponding array. */
			offset_read = (offset - range_start) + ptr->off_flattened;

			if (offset + size <= range_end) {
				if (!read_raw_dump_file(fd, offset_read, buf, size))
					return FALSE;
				break;
			}

			/* Searh other array corresponding to remaining data. */
			read_size   = range_end - offset;
			remain_size = size - read_size;
			if (!read_raw_dump_file(fd, offset_read, buf, read_size))
				return FALSE;
			if (!read_flattened_format(fd, offset + read_size,
					(char *)buf + read_size, remain_size))
				return FALSE;
			break;

		} else if ((index == index_start) &&
			   (index_start + 1 == index_end)) {
			/*
			 * Try to read not-written area. That is a common case,
			 * because the area might be skipped by lseek().
			 * This area should be the data filled with zero.
			 */
			ptr = afd.array + index_end;
			if (offset + size <= ptr->off_rearranged) {
				memset(buf, 0x0, size);
			} else {
				read_size   = ptr->off_rearranged - offset;
				remain_size = size - read_size;
				memset(buf, 0x0, read_size);
				if (!read_flattened_format(fd,
						offset + read_size,
						(char *)buf + read_size,
						remain_size))
					return FALSE;
			}
			break;

		} else if (offset < ptr->off_rearranged)
			index_end   = index;
		else
			index_start = index;
	}
	return TRUE;
}

int
is_flattened_format(char *file)
{
	check_flattened_format(file);
	return flattened_format;
}

void
dump_flat_header(FILE *ofp)
{
        int i;

	fprintf(ofp, "makedumpfile header:\n");
	fprintf(ofp, "          signature: \"");
	for (i = 0; i < SIG_LEN_MDF; i++) {
		if (!fh_save.signature[i])
			break;
		fprintf(ofp, "%c", fh_save.signature[i]);
	}
	fprintf(ofp, "\"\n");
	fprintf(ofp, "               type: %llx\n", (ulonglong)fh_save.type);
	fprintf(ofp, "            version: %llx\n", (ulonglong)fh_save.version);

	fprintf(ofp, "      all_flat_data:\n");
	fprintf(ofp, "          num_array: %lld\n", (ulonglong)afd.num_array);
	fprintf(ofp, "              array: %lx\n", (ulong)afd.array);
	fprintf(ofp, "          file_size: %ld\n\n", (ulong)afd.file_size);
}

static void 
flattened_format_get_osrelease(char *file)
{
	int c;
	FILE *pipe;
	char buf[BUFSIZE], *p1, *p2;

	c = strlen("OSRELEASE=");
	sprintf(buf, "/usr/bin/strings -n %d %s", c, file);
			
	if ((pipe = popen(buf, "r")) == NULL)
		return;

        for (c = 0; (c < 100) && fgets(buf, BUFSIZE-1, pipe); c++) {
		if ((p1 = strstr(buf, "OSRELEASE="))) {
			p2 = strstr(p1, "=");
			fprintf(fp, "%s", p2+1);
			flattened_format = TRUE;
			pc->flags2 |= GET_OSRELEASE;
		}
	}

	pclose(pipe);
}
