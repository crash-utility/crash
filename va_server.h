/* va_server.h - kernel crash dump file translation library
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002, 2003, 2004, 2005 David Anderson
 * Copyright (C) 2002, 2003, 2004, 2005 Red Hat, Inc. All rights reserved.
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
 * 10/99, Dave Winchell, Initial release for kernel crash dump support.
 * 11/12/99, Dave Winchell, Add support for in memory dumps.
 */

#include "vas_crash.h"

extern int vas_page_size;
extern u_long vas_base_va;

int va_server_init(char *crash_file, u_long *start, u_long *end, u_long *stride);
int va_server_init_v1(char *crash_file, u_long *start, u_long *end, u_long *stride);
int vas_lseek(u_long position, int whence);
int vas_lseek_v1(u_long position, int whence);
size_t vas_read(void *buf_in, size_t count);
size_t vas_read_v1(void *buf_in, size_t count);
size_t vas_write(void *buf_in, size_t count);
size_t vas_write_v1(void *buf_in, size_t count);
void vas_free_data(u_long va);
void vas_free_data_v1(u_long va);


/* in-memory formats */

struct map_hdr {
     struct crash_map_entry *map;   /* array of map entries */
     int blk_size;                  /* blocksize for this map */
};



struct map_hdr_v1 {
     u_long start_va;
     u_long end_va;

     struct crash_map_entry_v1 *map;   /* array of map entries */
     int map_entries;               /* entries in array pointed to by map */
     u_long va_per_entry;           /* va covered by each map_entry */
     int blk_offset;                /* add this to start_blk in map_entry
			             * this allows relocation of compressed data
				     * while using original maps
				     */
     int blk_size;                  /* blocksize for this map */

     struct map_hdr_v1 *next;
};

extern int clean_exit(int);




