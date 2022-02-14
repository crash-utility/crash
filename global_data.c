/* global_data.c - core analysis suite
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002-2006, 2010, 2012-2013, 2018 David Anderson
 * Copyright (C) 2002-2006, 2010, 2012-2013, 2018 Red Hat, Inc. All rights reserved.
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

#include "defs.h"

/*
 *  Data output FILE pointer.  The contents of fp are changed on the fly
 *  depending upon whether the output is going to stdout, redirected to a 
 *  user-designated pipe or file, or to the "standard" scrolling pipe.
 *  Regardless of where it ends up, fprintf(fp, ...) is used throughout
 *  instead of printf().
 */

FILE *fp;   

/*
 *  The state of the program is kept in the program_context structure.
 *  Given that it's consulted so often, "pc" is globally available to
 *  quickly access the structure contents.
 */
struct program_context program_context = { 0 };
struct program_context *pc = &program_context;

/*
 *  The same thing goes for accesses to the frequently-accessed task_table,
 *  kernel_table, vm_table, symbol_table_data and machdep_table, making the 
 *  "tt", "kt", "vt", "st" and "machdep" pointers globally available.
 */
struct task_table task_table = { 0 };
struct task_table *tt = &task_table;

struct kernel_table kernel_table = { 0 };
struct kernel_table *kt = &kernel_table;

struct vm_table vm_table = { 0 };
struct vm_table *vt = &vm_table;

struct symbol_table_data symbol_table_data = { 0 };
struct symbol_table_data *st = &symbol_table_data;

struct machdep_table machdep_table = { 0 };
struct machdep_table *machdep = &machdep_table;

/*
 *  Command functions are entered with the args[] array and argcnt value 
 *  pre-set for issuance to getopt().
 */

char *args[MAXARGS];	/* argument array */
int argcnt;             /* argument count */
int argerrs;            /* argument error counter */

/*
 *  To add a new command, declare it in defs.h and enter it in this table.
 */

struct command_table_entry linux_command_table[] = {
	{"*", 	    cmd_pointer, help_pointer, 0},
	{"alias",   cmd_alias,   help_alias,   0},
        {"ascii",   cmd_ascii,   help_ascii,   0},
        {"bpf",     cmd_bpf,     help_bpf,     0},
        {"bt",      cmd_bt,      help_bt,      REFRESH_TASK_TABLE},
	{"btop",    cmd_btop,    help_btop,    0},
	{"dev",     cmd_dev,     help_dev,     0},
	{"dis",     cmd_dis,     help_dis,     MINIMAL},
	{"eval",    cmd_eval,    help_eval,    MINIMAL},
	{"exit",    cmd_quit,    help_exit,    MINIMAL},
	{"extend",  cmd_extend,  help_extend,  MINIMAL},
	{"files",   cmd_files,   help_files,   REFRESH_TASK_TABLE},
	{"foreach", cmd_foreach, help_foreach, REFRESH_TASK_TABLE},
	{"fuser",   cmd_fuser,   help_fuser,   REFRESH_TASK_TABLE},
	{"gdb",     cmd_gdb,     help_gdb,     REFRESH_TASK_TABLE},
        {"help",    cmd_help,    help_help,    MINIMAL},
	{"ipcs",    cmd_ipcs,    help_ipcs,    REFRESH_TASK_TABLE},
	{"irq",     cmd_irq,     help_irq,     0},
	{"kmem",    cmd_kmem,    help_kmem,    0},
	{"list",    cmd_list,    help__list,   REFRESH_TASK_TABLE},
	{"log",     cmd_log,     help_log,     MINIMAL},
	{"mach",    cmd_mach,    help_mach,    0},
	{"map",     cmd_map,     help_map,     HIDDEN_COMMAND},
	{"mod",     cmd_mod,     help_mod,     0},
	{"mount",   cmd_mount,   help_mount,   REFRESH_TASK_TABLE},
	{"net",	    cmd_net,	help_net,      REFRESH_TASK_TABLE},
	{"p",       cmd_p,       help_p,       0},
	{"ps",      cmd_ps,      help_ps,      REFRESH_TASK_TABLE},
	{"pte",     cmd_pte,     help_pte,     0},
	{"ptob",    cmd_ptob,    help_ptob,    0},
	{"ptov",    cmd_ptov,    help_ptov,    0},
        {"q",       cmd_quit,    help_quit,    MINIMAL},
        {"tree",    cmd_tree,    help_tree,    REFRESH_TASK_TABLE},
        {"rd",      cmd_rd,      help_rd,      MINIMAL},
	{"repeat",  cmd_repeat,  help_repeat,  0},
	{"runq",    cmd_runq,    help_runq,    REFRESH_TASK_TABLE},
	{"sbitmapq", cmd_sbitmapq, help_sbitmapq, 0},
        {"search",  cmd_search,  help_search,  0},
        {"set",     cmd_set,     help_set,     REFRESH_TASK_TABLE | MINIMAL},
        {"sig",     cmd_sig,     help_sig,     REFRESH_TASK_TABLE},
        {"struct",  cmd_struct,  help_struct,  0},
	{"swap",    cmd_swap,    help_swap,    0},
        {"sym",     cmd_sym,     help_sym,     MINIMAL},
        {"sys",     cmd_sys,     help_sys,     REFRESH_TASK_TABLE},
        {"task",    cmd_task,    help_task,    REFRESH_TASK_TABLE},
	{"test",    cmd_test,    NULL,         HIDDEN_COMMAND},
        {"timer",   cmd_timer,   help_timer,   0},
	{"union",   cmd_union,   help_union,   0},
	{"vm",      cmd_vm,      help_vm,      REFRESH_TASK_TABLE},
	{"vtop",    cmd_vtop,    help_vtop,    REFRESH_TASK_TABLE},
	{"waitq",   cmd_waitq,   help_waitq,   REFRESH_TASK_TABLE},
	{"whatis",  cmd_whatis,  help_whatis,  0},
	{"wr",      cmd_wr,      help_wr,      0},
#if defined(S390) || defined(S390X)
        {"s390dbf", cmd_s390dbf, help_s390dbf, 0},
#endif
	{(char *)NULL}
};

struct extension_table *extension_table = NULL;

/*
 *  The offset_table and size_table structure contents are referenced
 *  through several OFFSET- and SIZE-related macros.  The array_table
 *  is a shortcut used by get_array_length().
 */
struct offset_table offset_table = { 0 };
struct size_table size_table = { 0 };
struct array_table array_table = { 0 };
