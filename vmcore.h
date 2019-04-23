/*
 * vmcore.h
 *
 * Copyright (C) 2019 Chelsio Communications. All rights reserved.
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
#ifndef _VMCORE_H
#define _VMCORE_H

#include <linux/types.h>

#ifndef NT_VMCOREDD
#define NT_VMCOREDD 0x700
#endif

#define VMCOREDD_NOTE_NAME "LINUX"
#define VMCOREDD_MAX_NAME_BYTES 44

struct vmcoredd_header {
	__u32 n_namesz; /* Name size */
	__u32 n_descsz; /* Content size */
	__u32 n_type;   /* NT_VMCOREDD */
	__u8 name[8];   /* LINUX\0\0\0 */
	__u8 dump_name[VMCOREDD_MAX_NAME_BYTES]; /* Device dump's name */
};

#endif /* _VMCORE_H */
