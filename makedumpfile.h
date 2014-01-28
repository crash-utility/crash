/* 
 * makedumpfile.h
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

/*
 * makedumpfile header
 *   For re-arranging the dump data on different architecture, all the
 *   variables are defined by 64bits. The size of signature is aligned
 *   to 64bits, and change the values to big endian.
 */
#define MAKEDUMPFILE_SIGNATURE  "makedumpfile"
#define NUM_SIG_MDF             (sizeof(MAKEDUMPFILE_SIGNATURE) - 1)
#define SIZE_SIG_MDF            roundup(sizeof(char) * NUM_SIG_MDF, 8)
#define SIG_LEN_MDF             (SIZE_SIG_MDF / sizeof(char))
#define MAX_SIZE_MDF_HEADER     (4096) /* max size of makedumpfile_header */
#define TYPE_FLAT_HEADER        (1)    /* type of flattened format */
#define VERSION_FLAT_HEADER     (1)    /* current version of flattened format */
#define END_FLAG_FLAT_HEADER    (-1)

struct makedumpfile_header {
	char    signature[SIG_LEN_MDF]; /* = "makedumpfile" */
	int64_t type;
	int64_t version;
};

struct makedumpfile_data_header {
	int64_t offset;
	int64_t buf_size;
};

