/* gdb_interface.c - core analysis suite
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002-2015,2018-2019 David Anderson
 * Copyright (C) 2002-2015,2018-2019 Red Hat, Inc. All rights reserved.
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

#ifndef GDB_10_2
static void exit_after_gdb_info(void);
#endif
static int is_restricted_command(char *, ulong);
static void strip_redirection(char *);
int get_frame_offset(ulong);

int *gdb_output_format;
unsigned int *gdb_print_max;
unsigned char *gdb_prettyprint_structs;
unsigned char *gdb_prettyprint_arrays;
unsigned int *gdb_repeat_count_threshold;
unsigned char *gdb_stop_print_at_null;
unsigned int *gdb_output_radix;
static void gdb_error_debug(void);

static ulong gdb_user_print_option_address(char *);

/*
 *  Called from main() this routine sets up the call-back hook such that
 *  gdb's main() routine -- renamed gdb_main() -- will call back to
 *  our main_loop() after gdb initializes.
 */
void
gdb_main_loop(int argc, char **argv)
{
	argc = 1;

	if (pc->flags & SILENT) {
		if (pc->flags & READNOW)
			argv[argc++] = "--readnow";
		argv[argc++] = "--quiet";
		argv[argc++] = pc->namelist_debug ? 
			pc->namelist_debug : 
			(pc->debuginfo_file && (st->flags & CRC_MATCHES) ?
			pc->debuginfo_file : pc->namelist);
	} else {
		if (pc->flags & READNOW)
			argv[argc++] = "--readnow";
		argv[argc++] = pc->namelist_debug ? 
			pc->namelist_debug : 
			(pc->debuginfo_file && (st->flags & CRC_MATCHES) ?
			pc->debuginfo_file : pc->namelist);
	}

	if (CRASHDEBUG(1)) {
		int i;
		fprintf(fp, "gdb ");
		for (i = 1; i < argc; i++)
			fprintf(fp, "%s ", argv[i]);
		fprintf(fp, "\n");
	}

        optind = 0;
#ifndef GDB_10_2
#if defined(GDB_5_3) || defined(GDB_6_0) || defined(GDB_6_1)
        command_loop_hook = main_loop;
#else
	deprecated_command_loop_hook = main_loop;
#endif
#endif
        gdb_main_entry(argc, argv);
}

/*
 *  Update any hooks that gdb has set.
 */
void
update_gdb_hooks(void)
{
#if defined(GDB_6_0) || defined(GDB_6_1)
	command_loop_hook = pc->flags & VERSION_QUERY ?
        	exit_after_gdb_info : main_loop;
	target_new_objfile_hook = NULL;
#endif
#if defined(GDB_7_0) || defined(GDB_7_3_1) || defined(GDB_7_6)
	deprecated_command_loop_hook = pc->flags & VERSION_QUERY ?
		exit_after_gdb_info : main_loop;
#endif
}

void
gdb_readnow_warning(void)
{
	if ((THIS_GCC_VERSION >= GCC(3,4,0)) && (THIS_GCC_VERSION < GCC(4,0,0))
	    && !(pc->flags & READNOW)) {
		fprintf(stderr, 
 "WARNING: Because this kernel was compiled with gcc version %d.%d.%d, certain\n" 
 "         commands or command options may fail unless crash is invoked with\n"
 "         the  \"--readnow\" command line option.\n\n",
			kt->gcc_version[0],
			kt->gcc_version[1],
			kt->gcc_version[2]);
	}
}

/*
 *  Used only by the -v command line option, get gdb to initialize itself
 *  with no arguments, print its version and GPL paragraph, and then call
 *  back to exit_after_gdb_info().
 */
void
display_gdb_banner(void)
{
	optind = 0;
#ifndef GDB_10_2
#if defined(GDB_5_3) || defined(GDB_6_0) || defined(GDB_6_1)
        command_loop_hook = exit_after_gdb_info;
#else
        deprecated_command_loop_hook = exit_after_gdb_info;
#endif
#endif
	args[0] = "gdb";
	args[1] = "-version";
	gdb_main_entry(2, args);
}

#ifndef GDB_10_2
static void
exit_after_gdb_info(void)
{
        fprintf(fp, "\n");
        clean_exit(0);
}
#endif

/* 
 *  Stash a copy of the gdb version locally.  This can be called before
 *  gdb gets initialized, so bypass gdb_interface().
 */
void
get_gdb_version(void)
{
        struct gnu_request request;

	if (!pc->gdb_version) {
        	request.command = GNU_VERSION;
		gdb_command_funnel(&request);    /* bypass gdb_interface() */
		pc->gdb_version = request.buf;
	}
}

void
gdb_session_init(void)
{
	struct gnu_request *req;
	int debug_data_pulled_in;

        if (!have_partial_symbols() && !have_full_symbols())
		no_debugging_data(FATAL);

	/*
	 *  Restore the SIGINT and SIGPIPE handlers, which got temporarily
	 *  re-assigned by gdb.  The SIGINT call also initializes GDB's
         *  SIGINT sigaction.
	 */
	SIGACTION(SIGINT, restart, &pc->sigaction, &pc->gdb_sigaction);
	SIGACTION(SIGPIPE, SIG_IGN, &pc->sigaction, NULL);

	if (!(pc->flags & DROP_CORE)) 
		SIGACTION(SIGSEGV, restart, &pc->sigaction, NULL);

	/*
	 *  Set up pointers to gdb variables.
	 */
#if defined(GDB_5_3) || defined(GDB_6_0) || defined(GDB_6_1)
	gdb_output_format = &output_format;
	gdb_print_max = &print_max;
	gdb_prettyprint_structs = &prettyprint_structs;
	gdb_prettyprint_arrays = &prettyprint_arrays;
	gdb_repeat_count_threshold = &repeat_count_threshold;
	gdb_stop_print_at_null = &stop_print_at_null;
	gdb_output_radix = &output_radix;
#else
	gdb_output_format = (int *) 
		gdb_user_print_option_address("output_format");
	gdb_print_max = (unsigned int *)
		gdb_user_print_option_address("print_max");
	gdb_prettyprint_structs = (unsigned char *)
		gdb_user_print_option_address("prettyprint_structs");
	gdb_prettyprint_arrays = (unsigned char *)
		gdb_user_print_option_address("prettyprint_arrays");
	gdb_repeat_count_threshold = (unsigned int *)
		gdb_user_print_option_address("repeat_count_threshold");
	gdb_stop_print_at_null = (unsigned char *)
		gdb_user_print_option_address("stop_print_at_null");
	gdb_output_radix = (unsigned int *)
		gdb_user_print_option_address("output_radix");
#endif
	/*
         *  If the output radix is set via the --hex or --dec command line
	 *  option, then pc->output_radix will be non-zero; otherwise use 
	 *  the gdb default.  
	 */
	if (pc->output_radix) {  
		*gdb_output_radix = pc->output_radix;
		*gdb_output_format = (*gdb_output_radix == 10) ? 0 : 'x';
	}

	switch (*gdb_output_radix)
	{
	case 10:
	case 16:
		pc->output_radix = *gdb_output_radix;
		break;
	default:
		pc->output_radix = *gdb_output_radix = 10;
		*gdb_output_format = 0;
	}
		
	*gdb_prettyprint_structs = 1;
	*gdb_repeat_count_threshold = 0x7fffffff;
	*gdb_print_max = 256;
#ifdef GDB_5_3
	gdb_disassemble_from_exec = 0;
#endif

	pc->flags |= GDB_INIT;   /* set here so gdb_interface will work */

        req = (struct gnu_request *)GETBUF(sizeof(struct gnu_request));
        req->buf = GETBUF(BUFSIZE);

	/*
	 *  Make sure the namelist has symbolic data.  Later versions of
	 *  gcc may require that debug data be pulled in by printing a 
	 *  static kernel data structure.
  	 */
	debug_data_pulled_in = FALSE;
retry:
	BZERO(req->buf, BUFSIZE);
        req->command = GNU_GET_DATATYPE;
	req->name = XEN_HYPER_MODE() ? "page_info" : "task_struct";
        req->flags = GNU_RETURN_ON_ERROR;
        gdb_interface(req);

        if (req->flags & GNU_COMMAND_FAILED) {
		if (XEN_HYPER_MODE())
			no_debugging_data(WARNING);  /* just bail out */

		if (!debug_data_pulled_in) {
			if (CRASHDEBUG(1))
				error(INFO, 
           "gdb_session_init: pulling in debug data by accessing init_mm.mmap %s\n",
					symbol_exists("sysfs_mount") ?
					"and syfs_mount" : "");
			debug_data_pulled_in = TRUE;
			req->command = GNU_PASS_THROUGH;
			req->flags = GNU_RETURN_ON_ERROR|GNU_NO_READMEM;
			req->name = NULL;
			if (symbol_exists("sysfs_mount"))
				sprintf(req->buf, "print sysfs_mount, init_mm.mmap");
			else
				sprintf(req->buf, "print init_mm.mmap");
			gdb_interface(req);
        		if (!(req->flags & GNU_COMMAND_FAILED)) 
				goto retry;
		}
		no_debugging_data(WARNING);
	}

	if (pc->flags & KERNEL_DEBUG_QUERY) {
		fprintf(fp, "\n%s: %s: contains debugging data\n\n",
			pc->program_name, pc->namelist);
		if (REMOTE())
			remote_exit();
		clean_exit(0);
	}

	/*
	 *  Set up any pre-ordained gdb settings here that can't be
	 *  accessed directly.
	 */

	req->command = GNU_PASS_THROUGH;
	req->name = NULL, req->flags = 0;
	sprintf(req->buf, "set height 0");
	gdb_interface(req);

	req->command = GNU_PASS_THROUGH;
	req->name = NULL, req->flags = 0;
	sprintf(req->buf, "set width 0");
	gdb_interface(req);

#ifdef GDB_10_2
	req->command = GNU_PASS_THROUGH;
	req->name = NULL, req->flags = 0;
	sprintf(req->buf, "set max-value-size unlimited");
	gdb_interface(req);

	req->command = GNU_PASS_THROUGH;
	req->name = NULL, req->flags = 0;
	sprintf(req->buf, "set max-completions unlimited");
	gdb_interface(req);
#endif

#if 0
       /*
        *  Patch gdb's symbol values with the correct values from either
        *  the System.map or non-debug vmlinux, whichever is in effect.
        */
	if ((pc->flags & SYSMAP) || (kt->flags & (RELOC_SET|RELOC_FORCE)) || 
	    (pc->namelist_debug && !pc->debuginfo_file)) {
		req->command = GNU_PATCH_SYMBOL_VALUES;
        	req->flags = GNU_RETURN_ON_ERROR;
		gdb_interface(req);
        	if (req->flags & GNU_COMMAND_FAILED)
			error(FATAL, "patching of gdb symbol values failed\n");
	} else if (!(pc->flags & SILENT))
#else
        if (!(pc->flags & SILENT))
#endif
		fprintf(fp, "\n");


	FREEBUF(req->buf);
	FREEBUF(req);
}

/*
 *  Quickest way to gdb -- just pass a command string to pass through.
 */
int
gdb_pass_through(char *cmd, FILE *fptr, ulong flags)
{
        struct gnu_request *req;
	int retval;

	if (CRASHDEBUG(1))
  		console("gdb_pass_through: [%s]\n", cmd); 

        req = (struct gnu_request *)GETBUF(sizeof(struct gnu_request));
        req->buf = cmd;
	if (fptr)
		req->fp = fptr;
        req->command = GNU_PASS_THROUGH;
	req->flags = flags;

        gdb_interface(req);

	if ((req->flags & (GNU_RETURN_ON_ERROR|GNU_COMMAND_FAILED)) ==
	    (GNU_RETURN_ON_ERROR|GNU_COMMAND_FAILED))
		retval = FALSE;
	else
		retval = TRUE;

        FREEBUF(req);

	return retval;
}


/*
 *  General purpose routine for passing commands to gdb.  All gdb commands
 *  come through here, where they are passed to gdb_command_funnel().
 */
void 
gdb_interface(struct gnu_request *req)
{
	if (!(pc->flags & GDB_INIT)) 
		error(FATAL, "gdb_interface: gdb not initialized?\n"); 

	if (output_closed()) 
		restart(0);

	if (!req->fp) {
		req->fp = ((pc->flags & RUNTIME) || (pc->flags2 & ALLOW_FP)) ? 
			fp : CRASHDEBUG(1) ? fp : pc->nullfp;
	}

	pc->cur_req = req;
	pc->cur_gdb_cmd = req->command;

	if (CRASHDEBUG(2))
		dump_gnu_request(req, IN_GDB);

        if (!(pc->flags & DROP_CORE)) 
		SIGACTION(SIGSEGV, restart, &pc->sigaction, NULL);
        else 
		SIGACTION(SIGSEGV, SIG_DFL, &pc->sigaction, NULL);

	if (interruptible()) { 
		SIGACTION(SIGINT, pc->gdb_sigaction.sa_handler, 
			&pc->gdb_sigaction, NULL);
	} else {
		SIGACTION(SIGINT, SIG_IGN, &pc->sigaction, NULL);
		SIGACTION(SIGPIPE, SIG_IGN, &pc->sigaction, NULL);
	} 

	pc->flags |= IN_GDB;
	gdb_command_funnel(req);
	pc->flags &= ~IN_GDB;

	SIGACTION(SIGINT, restart, &pc->sigaction, NULL);
	SIGACTION(SIGSEGV, SIG_DFL, &pc->sigaction, NULL);

        if (req->flags & GNU_COMMAND_FAILED)
                gdb_error_debug();

	if (CRASHDEBUG(2))
		dump_gnu_request(req, !IN_GDB);

        pc->last_gdb_cmd = pc->cur_gdb_cmd;
        pc->cur_gdb_cmd = 0;
	pc->cur_req = NULL;
}

/*
 *  help -g output
 */
void
dump_gdb_data(void)
{
        fprintf(fp, "    prettyprint_arrays: %d\n", *gdb_prettyprint_arrays);
        fprintf(fp, "   prettyprint_structs: %d\n", *gdb_prettyprint_structs);
        fprintf(fp, "repeat_count_threshold: %x\n", *gdb_repeat_count_threshold);
	fprintf(fp, "    stop_print_at_null: %d\n", *gdb_stop_print_at_null);
	fprintf(fp, "             print_max: %d\n", *gdb_print_max);
        fprintf(fp, "          output_radix: %d\n", *gdb_output_radix);
        fprintf(fp, "         output_format: ");
        switch (*gdb_output_format)
        {
        case 'x':
                fprintf(fp, "hex\n"); break;
        case 'o':
                fprintf(fp, "octal\n"); break;
        case 0:
                fprintf(fp, "decimal\n"); break;
        }
}

void
dump_gnu_request(struct gnu_request *req, int in_gdb)
{
	int others;
	char buf[BUFSIZE];

	if (pc->flags & KERNEL_DEBUG_QUERY)
		return;

	console("%scommand: %d (%s)\n", in_gdb ? "GDB IN: " : "GDB OUT: ", 
		req->command, gdb_command_string(req->command, buf, TRUE));
        console("buf: %lx ", req->buf);
        if (req->buf && ascii_string(req->buf))
                console(" \"%s\"", req->buf);
        console("\n");
        console("fp: %lx ", req->fp);

	if (req->fp == pc->nullfp)
		console("(pc->nullfp) ");
	if (req->fp == pc->stdpipe)
		console("(pc->stdpipe) ");
	if (req->fp == pc->pipe)
		console("(pc->pipe) ");
	if (req->fp == pc->ofile)
		console("(pc->ofile) ");
	if (req->fp == pc->ifile)
		console("(pc->ifile) ");
	if (req->fp == pc->ifile_pipe)
		console("(pc->ifile_pipe) ");
	if (req->fp == pc->ifile_ofile)
		console("(pc->ifile_ofile) ");
	if (req->fp == pc->tmpfile)
		console("(pc->tmpfile) ");
	if (req->fp == pc->saved_fp)
		console("(pc->saved_fp) ");
	if (req->fp == pc->tmp_fp)
		console("(pc->tmp_fp) ");

	console("flags: %lx  (", req->flags);
	others = 0;
	if (req->flags & GNU_PRINT_LINE_NUMBERS)
		console("%sGNU_PRINT_LINE_NUMBERS", others++ ? "|" : "");
	if (req->flags & GNU_FUNCTION_ONLY)
                console("%sGNU_FUNCTION_ONLY", others++ ? "|" : "");
        if (req->flags & GNU_PRINT_ENUMERATORS)
                console("%sGNU_PRINT_ENUMERATORS", others++ ? "|" : "");
        if (req->flags & GNU_RETURN_ON_ERROR)
                console("%sGNU_RETURN_ON_ERROR", others++ ? "|" : "");
        if (req->flags & GNU_FROM_TTY_OFF)
                console("%sGNU_FROM_TTY_OFF", others++ ? "|" : "");
        if (req->flags & GNU_NO_READMEM)
                console("%sGNU_NO_READMEM", others++ ? "|" : "");
        if (req->flags & GNU_VAR_LENGTH_TYPECODE)
                console("%sGNU_VAR_LENGTH_TYPECODE", others++ ? "|" : "");
	console(")\n");

        console("addr: %lx ", req->addr);
        console("addr2: %lx ", req->addr2);
        console("count: %ld\n", req->count);

	if ((ulong)req->name > (ulong)PATCH_KERNEL_SYMBOLS_STOP) 
		console("name: \"%s\" ", req->name);
	else
		console("name: %lx ", (ulong)req->name);
	console("length: %ld ", req->length);
        console("typecode: %d\n", req->typecode);
#if defined(GDB_5_3) || defined(GDB_6_0) || defined(GDB_6_1) || defined(GDB_7_0)
	console("typename: %s\n", req->typename);
#else
	console("type_name: %s\n", req->type_name);
#endif
	console("target_typename: %s\n", req->target_typename);
	console("target_length: %ld ", req->target_length);
	console("target_typecode: %d ", req->target_typecode);
	console("is_typedef: %d ", req->is_typedef);
	console("member: \"%s\" ", req->member);
	console("member_offset: %ld\n", req->member_offset);
	console("member_length: %ld\n", req->member_length);
        console("member_typecode: %d\n", req->member_typecode);
	console("member_main_type_name: %s\n", req->member_main_type_name);
	console("member_main_type_tag_name: %s\n", req->member_main_type_tag_name);
	console("member_target_type_name: %s\n", req->member_target_type_name);
	console("member_target_type_tag_name: %s\n", req->member_target_type_tag_name);
	console("value: %lx ", req->value);
	console("tagname: \"%s\" ", req->tagname);
	console("pc: %lx  ", req->pc);
	if (is_kernel_text(req->pc))
		console("(%s)", value_to_symstr(req->pc, buf, 0));
	console("\n");
	console("sp: %lx ", req->sp);
	console("ra: %lx ", req->ra);
        console("frame: %ld ", req->frame);
	console("prevsp: %lx\n", req->prevsp);
	console("prevpc: %lx ", req->prevpc);
	console("lastsp: %lx ", req->lastsp);
        console("task: %lx ", req->task);
	console("debug: %lx\n", req->debug);
	console("\n");
}

char *
gdb_command_string(int cmd, char *buf, int live)
{
        switch (cmd)
        {
        case GNU_PASS_THROUGH:
                sprintf(buf, "GNU_PASS_THROUGH");
                break;
        case GNU_DATATYPE_INIT:
                sprintf(buf, "GNU_DATATYPE_INIT");
                break;
        case GNU_DISASSEMBLE:
                sprintf(buf, "GNU_DISASSEMBLE");
                break;
        case GNU_GET_LINE_NUMBER:
                sprintf(buf, "GNU_GET_LINE_NUMBER");
                break;
        case GNU_GET_DATATYPE:
		if (live)
                	sprintf(buf, "GNU_GET_DATATYPE[%s]", 
				pc->cur_req->name ? pc->cur_req->name : "?");
		else
			sprintf(buf, "GNU_GET_DATATYPE");
                break;
        case GNU_STACK_TRACE:
                sprintf(buf, "GNU_STACK_TRACE");
                break;
	case GNU_ALPHA_FRAME_OFFSET:
		sprintf(buf, "GNU_ALPHA_FRAME_OFFSET");
		break;
	case GNU_COMMAND_EXISTS:
                sprintf(buf, "GNU_COMMAND_EXISTS");
                break;
	case GNU_FUNCTION_NUMARGS:
                sprintf(buf, "GNU_FUNCTION_NUMARGS");
                break;
	case GNU_RESOLVE_TEXT_ADDR:
                sprintf(buf, "GNU_RESOLVE_TEXT_ADDR");
                break;
	case GNU_DEBUG_COMMAND:
                sprintf(buf, "GNU_DEBUG_COMMAND");
                break;
	case GNU_ADD_SYMBOL_FILE:
                sprintf(buf, "GNU_ADD_SYMBOL_FILE");
                break;
	case GNU_DELETE_SYMBOL_FILE:
                sprintf(buf, "GNU_DELETE_SYMBOL_FILE");
                break;
	case GNU_VERSION:
                sprintf(buf, "GNU_VERSION");
                break;
       case GNU_GET_SYMBOL_TYPE:
                sprintf(buf, "GNU_GET_SYMBOL_TYPE");
                break;
        case GNU_PATCH_SYMBOL_VALUES:
                sprintf(buf, "GNU_PATCH_SYMBOL_VALUES");
                break;
        case GNU_USER_PRINT_OPTION:
                sprintf(buf, "GNU_USER_PRINT_OPTION");
		break;
        case GNU_SET_CRASH_BLOCK:
                sprintf(buf, "GNU_SET_CRASH_BLOCK");
		break;
	case GNU_GET_FUNCTION_RANGE:
                sprintf(buf, "GNU_GET_FUNCTION_RANGE");
                break;
	case 0:
		buf[0] = NULLCHAR;
		break;
        default:
                sprintf(buf, "(?)\n");
                break;
        }

	return buf;
}

/*
 *  Restore known gdb state.
 */
void
restore_gdb_sanity(void)
{
        if (!(pc->flags & GDB_INIT))
                return;

        if (pc->output_radix) {
                *gdb_output_radix = pc->output_radix;   
                *gdb_output_format = (*gdb_output_radix == 10) ? 0 : 'x';
        }

        *gdb_prettyprint_structs = 1;   /* these may piss somebody off... */
	*gdb_repeat_count_threshold = 0x7fffffff;

	if (st->flags & ADD_SYMBOL_FILE) {
		error(INFO, 
		    "%s\n     gdb add-symbol-file command failed\n", 
			st->current->mod_namelist);
		delete_load_module(st->current->mod_base);
                st->flags &= ~ADD_SYMBOL_FILE;
	}

	if (pc->cur_gdb_cmd) {
		pc->last_gdb_cmd = pc->cur_gdb_cmd;
		pc->cur_gdb_cmd = 0;
	}
}

/*
 *  Check whether string in args[0] is a valid gdb command.
 */
int
is_gdb_command(int merge_orig_args, ulong flags)
{
        int retval;
        struct gnu_request *req;

        if (!args[0])
                return FALSE;

	if (STREQ(args[0], "Q")) {
		args[0] = "q";
		return TRUE;
	}

	if (is_restricted_command(args[0], flags))
		return FALSE;

        req = (struct gnu_request *)GETBUF(sizeof(struct gnu_request));
	req->buf = GETBUF(strlen(args[0])+1);
        req->command = GNU_COMMAND_EXISTS;
        req->name = args[0];
        req->flags = GNU_RETURN_ON_ERROR; 
	req->fp = pc->nullfp;

        gdb_interface(req);

	if (req->flags & GNU_COMMAND_FAILED) 
		retval = FALSE;
	else
        	retval = req->value;

	FREEBUF(req->buf);
        FREEBUF(req);

	if (retval && merge_orig_args) {
		int i;
		for (i = argcnt; i; i--)
			args[i] = args[i-1];
		args[0] = "gdb";
		argcnt++;
	}

        return retval;
}

/*
 *  Check whether a command is on the gdb-prohibited list.
 */
static char *prohibited_list[] = {
	"run", "r", "break", "b", "tbreak", "hbreak", "thbreak", "rbreak",
	"watch", "rwatch", "awatch", "attach", "continue", "c", "fg", "detach", 
	"finish", "handle", "interrupt", "jump", "kill", "next", "nexti", 
	"signal", "step", "s", "stepi", "target", "until", "delete", 
	"clear", "disable", "enable", "condition", "ignore", "frame", "catch",
	"tcatch", "return", "file", "exec-file", "core-file", "symbol-file",
	"load", "si", "ni", "shell", "sy",
	NULL  /* must be last */
};

static char *restricted_list[] = {
	"define", "document", "while", "if",
	NULL  /* must be last */
};

#define RESTRICTED_GDB_COMMAND \
        "restricted gdb command: %s\n%s\"%s\" may only be used in a .gdbinit file or in a command file.\n%sThe .gdbinit file is read automatically during %s initialization.\n%sOther user-defined command files may be read interactively during\n%s%s runtime by using the gdb \"source\" command.\n"

static int
is_restricted_command(char *cmd, ulong flags)
{
	int i;
	char *newline;

	for (i = 0; prohibited_list[i]; i++) {
		if (STREQ(prohibited_list[i], cmd)) {
			if (flags == RETURN_ON_ERROR)
				return TRUE;
			pc->curcmd = pc->program_name;
                	error(FATAL, "prohibited gdb command: %s\n", cmd);
		}
	}

	for (i = 0; restricted_list[i]; i++) {
		if (STREQ(restricted_list[i], cmd)) {
			if (flags == RETURN_ON_ERROR)
				return TRUE;
			newline = space(strlen(pc->program_name)+2);
			pc->curcmd = pc->program_name;
			error(FATAL, RESTRICTED_GDB_COMMAND, 
				cmd, newline, cmd,
				newline, pc->program_name,
				newline, newline, pc->program_name);
		}
	}

	return FALSE;
}

/*
 *  Remove pipe/redirection stuff from the end of the command line.
 */ 
static void
strip_redirection(char *buf)
{
	char *p1, *p2;

	p1 = strstr_rightmost(buf, args[argcnt-1]);
	p2 = p1 + strlen(args[argcnt-1]);
	console("strip_redirection: [%s]\n", p2);

	if ((p1 = strpbrk(p2, "|!>")))
		*p1 = NULLCHAR;

	strip_ending_whitespace(buf);
}

/*
 *  Command for passing strings directly to gdb.
 */
void
cmd_gdb(void)
{
	char buf[BUFSIZE];
        char **argv;

	argv = STREQ(args[0], "gdb") ? &args[1] : &args[0];

        if (*argv == NULL)
                cmd_usage(pc->curcmd, SYNOPSIS);

        if (STREQ(*argv, "set") && argv[1]) {
                /*
                 *  Intercept set commands in case something has to be done
		 *  here or elsewhere.
                 */ 
                if (STREQ(argv[1], "gdb")) {
                        cmd_set();
                        return;
                }
                if (STREQ(argv[1], "output-radix") && argv[2])
                        pc->output_radix = stol(argv[2], FAULT_ON_ERROR, NULL);
        }

	/*
	 *  If the command is not restricted, pass it on.
	 */
	if (!is_restricted_command(*argv, FAULT_ON_ERROR)) {
		if (STREQ(pc->command_line, "gdb")) {
			strcpy(buf, first_space(pc->orig_line));
			strip_beginning_whitespace(buf);
		} else
			strcpy(buf, pc->orig_line);

		if (pc->redirect & (REDIRECT_TO_FILE|REDIRECT_TO_PIPE))
			strip_redirection(buf);

		if (!gdb_pass_through(buf, NULL, GNU_RETURN_ON_ERROR))
			error(INFO, "gdb request failed: %s\n", buf);
	}
}

/*
 *  The gdb target_xfer_memory() has a hook installed to re-route
 *  all memory accesses back here; reads of 1 or 4 bytes come primarily
 *  from text disassembly requests, and are diverted to the text cache.
 */
int 
gdb_readmem_callback(ulong addr, void *buf, int len, int write)
{ 
	char locbuf[SIZEOF_32BIT], *p1;
	int memtype;
	ulong readflags;

	if (write)
		return FALSE;

	if (!(pc->cur_req)) {
		return(readmem(addr, KVADDR, buf, len, 
			"gdb_readmem_callback", RETURN_ON_ERROR));
	}

	if (pc->cur_req->flags & GNU_NO_READMEM)
		return TRUE;

	readflags = pc->curcmd_flags & PARTIAL_READ_OK ?
		RETURN_ON_ERROR|RETURN_PARTIAL : RETURN_ON_ERROR;

	if (STREQ(pc->curcmd, "bpf") && pc->curcmd_private &&
	    (addr > (ulong)pc->curcmd_private))
		readflags |= QUIET;

	if (pc->curcmd_flags & MEMTYPE_UVADDR)
		memtype = UVADDR;
	else if (pc->curcmd_flags & MEMTYPE_FILEADDR)
		memtype = FILEADDR;
	else if (!IS_KVADDR(addr)) {
		if (STREQ(pc->curcmd, "gdb") && 
		    STRNEQ(pc->cur_req->buf, "x/")) {
			memtype = UVADDR;
		} else {
			if (CRASHDEBUG(1))
			        console("gdb_readmem_callback: %lx %d FAILED\n",
					addr, len);
			return FALSE;
		}
	} else
		memtype = KVADDR;

	if (CRASHDEBUG(1))
		console("gdb_readmem_callback[%d]: %lx %d\n", 
			memtype, addr, len);

	if (memtype == FILEADDR)
		return(readmem(pc->curcmd_private, memtype, buf, len,
			"gdb_readmem_callback", readflags));
	
	switch (len)
	{
	case SIZEOF_8BIT:
		if (STREQ(pc->curcmd, "bt")) {
			if (readmem(addr, memtype, buf, SIZEOF_8BIT,
		    	    "gdb_readmem_callback", readflags)) 
				return TRUE;
		}

		p1 = (char *)buf;

		if (!readmem(addr, memtype, locbuf, SIZEOF_32BIT,
		    "gdb_readmem_callback", readflags)) 
			return FALSE;

		*p1 = locbuf[0];
		return TRUE;

	case SIZEOF_32BIT:
		if (STREQ(pc->curcmd, "bt")) {
			if (readmem(addr, memtype, buf, SIZEOF_32BIT,
		    	    "gdb_readmem_callback", readflags)) 
				return TRUE;
		}

		if (!readmem(addr, memtype, buf, SIZEOF_32BIT, 
		    "gdb_readmem callback", readflags))
			return FALSE;

		return TRUE;
	}

	return(readmem(addr, memtype, buf, len, 
		"gdb_readmem_callback", readflags));
}

/*
 *  Machine-specific line-number pc section range verifier.
 */
int
gdb_line_number_callback(ulong pc, ulong low, ulong high)
{
	if (machdep->verify_line_number)
		return machdep->verify_line_number(pc, low, high);

	return TRUE;
}

/*
 *  Prevent gdb from trying to translate and print pointers
 *  that are not kernel virtual addresses.  
 */
int
gdb_print_callback(ulong addr)
{
	if (!addr)
		return FALSE;
	else
		return IS_KVADDR(addr);
}

/*
 *  Used by gdb_interface() to catch gdb-related errors, if desired.
 */
static void
gdb_error_debug(void)
{
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	int buffers;

	if (CRASHDEBUG(2)) {
		sprintf(buf2, "\n");

		if (CRASHDEBUG(5) && (buffers = get_embedded()))
			sprintf(buf2, "(%d buffer%s in use)\n",
				buffers, buffers > 1 ? "s" : "");

		fprintf(stderr, "%s: returned via gdb_error_hook %s",
			gdb_command_string(pc->cur_gdb_cmd, buf1, TRUE), buf2);

		console("%s: returned via gdb_error_hook %s",
			gdb_command_string(pc->cur_gdb_cmd, buf1, TRUE), buf2);
	}

}


/*
 *  gdb callback to access debug mode. 
 */
int
gdb_CRASHDEBUG(ulong dval)
{
	if (CRASHDEBUG(dval)) 
		return TRUE;

	return (pc->cur_req && (pc->cur_req->debug >= dval));
}

static ulong 
gdb_user_print_option_address(char *name)
{
        struct gnu_request request;

	request.command = GNU_USER_PRINT_OPTION;
	request.name = name;
	gdb_command_funnel(&request);    
	return request.addr;
}

/*
 *  Try to set a crash scope block based upon the vaddr.   
 */
int
gdb_set_crash_scope(ulong vaddr, char *arg)
{
        struct gnu_request request, *req = &request;
	char name[BUFSIZE];
	struct load_module *lm;

	if (vaddr) {
		if (!is_kernel_text(vaddr)) {
			error(INFO, "invalid text address: %s\n", arg);
			return FALSE;
		}

		if (module_symbol(vaddr, NULL, &lm, name, 0)) {
			if (!(lm->mod_flags & MOD_LOAD_SYMS)) {
				error(INFO, "attempting to find/load \"%s\" module debuginfo\n",
					lm->mod_name);
				if (!load_module_symbols_helper(lm->mod_name)) {
					error(INFO, "cannot find/load \"%s\" module debuginfo\n",
						lm->mod_name);
					return FALSE;
				}
			}
		}
	}

	req->command = GNU_SET_CRASH_BLOCK;
	req->addr = vaddr;
	req->flags = 0;
	req->addr2 = 0;
	req->fp = pc->nullfp;
	gdb_command_funnel(req);    

	if (CRASHDEBUG(1))
		fprintf(fp, 
		    "gdb_set_crash_scope: %s  addr: %lx  block: %lx\n",
			req->flags & GNU_COMMAND_FAILED ? "FAILED" : "OK",  
			req->addr, req->addr2);

	if (req->flags & GNU_COMMAND_FAILED) {
		error(INFO, 
			"gdb cannot find text block for address: %s\n", arg);
		return FALSE;
	}

	return TRUE;
}

#ifndef ALPHA
/*
 *  Stub routine needed for resolution by non-alpha, modified gdb code.
 */
int
get_frame_offset(ulong pc)
{
	return (error(FATAL, 
	    "get_frame_offset: invalid request for non-alpha systems!\n"));
}
#endif /* !ALPHA */ 

unsigned long crash_get_kaslr_offset(void);
unsigned long crash_get_kaslr_offset(void)
{
        return kt->relocate * -1;
}

/* Callbacks for crash_target */
int crash_get_nr_cpus(void);
int crash_get_cpu_reg (int cpu, int regno, const char *regname,
                       int regsize, void *val);

int crash_get_nr_cpus(void)
{
        if (SADUMP_DUMPFILE())
                return sadump_get_nr_cpus();
        else if (DISKDUMP_DUMPFILE())
                return diskdump_get_nr_cpus();
        else if (KDUMP_DUMPFILE())
                return kdump_get_nr_cpus();
        else if (VMSS_DUMPFILE())
                return vmware_vmss_get_nr_cpus();

        /* Just CPU #0 */
        return 1;
}

int crash_get_cpu_reg (int cpu, int regno, const char *regname,
                       int regsize, void *value)
{
        if (!machdep->get_cpu_reg)
                return FALSE;
        return machdep->get_cpu_reg(cpu, regno, regname, regsize, value);
}

