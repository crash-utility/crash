/* extensions.c - core analysis suite
 *
 * Copyright (C) 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002-2013, 2018 David Anderson
 * Copyright (C) 2002-2013, 2018 Red Hat, Inc. All rights reserved.
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
#include <dlfcn.h>

static int in_extensions_library(char *, char *);
static char *get_extensions_directory(char *);
static void show_all_extensions(void);
static void show_extensions(char *);

#define DUMP_EXTENSIONS        (0)
#define LOAD_EXTENSION         (1)
#define UNLOAD_EXTENSION       (2)
#define SHOW_ALL_EXTENSIONS    (4)

/*
 *  Load, unload, or list the extension libaries.
 */
void
cmd_extend(void)
{
        int c;
	int flag;

	flag = DUMP_EXTENSIONS;

        while ((c = getopt(argcnt, args, "lus")) != EOF) {
                switch(c)
                {
		case 's':
			if (flag & UNLOAD_EXTENSION) {
				error(INFO,
					"-s and -u are mutually exclusive\n");
				argerrs++;
			}else if (flag & LOAD_EXTENSION) {
				error(INFO,
					"-s and -l are mutually exclusive\n");
				argerrs++;
			} else
				flag |= SHOW_ALL_EXTENSIONS;
			break;
		case 'l':
			if (flag & UNLOAD_EXTENSION) {
				error(INFO, 
					"-l and -u are mutually exclusive\n");
				argerrs++;
			} else if (flag & SHOW_ALL_EXTENSIONS) {
				error(INFO, 
					"-l and -s are mutually exclusive\n");
				argerrs++;
			} else
				flag |= LOAD_EXTENSION;
			break;

		case 'u':
                        if (flag & LOAD_EXTENSION) {
                                error(INFO, 
                                        "-u and -l are mutually exclusive\n");
                                argerrs++;
			} else if (flag & SHOW_ALL_EXTENSIONS) {
				error(INFO, 
					"-u and -s are mutually exclusive\n");
				argerrs++;
                        } else
                                flag |= UNLOAD_EXTENSION;
			break;

                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

	switch (flag)
	{
	case DUMP_EXTENSIONS:
		if (!args[optind]) {
			dump_extension_table(!VERBOSE);
			return;
		}
		/* FALLTHROUGH */

	case LOAD_EXTENSION:
		if (!args[optind]) { 
			error(INFO, 
		       "-l requires one or more extension library arguments\n");
			cmd_usage(pc->curcmd, SYNOPSIS);
			break;
		}

        	while (args[optind]) {
			load_extension(args[optind]);
			optind++;
		}
		break;

	case UNLOAD_EXTENSION:
		if (!args[optind]) { 
			unload_extension(NULL);
			break;
		}

        	while (args[optind]) {
			unload_extension(args[optind]);
			optind++;
		}
		break;

	case SHOW_ALL_EXTENSIONS:
		show_all_extensions();
		break;

	}
}

/*
 *  List all extension libaries and their commands in either the extend
 *  command format or for "help -e" (verbose).
 */
void 
dump_extension_table(int verbose)
{
	int i;
	struct extension_table *ext;
	struct command_table_entry *cp;
	char buf[BUFSIZE];
	int longest, others;

	if (!extension_table)
		return;

	if (verbose) {
       		for (ext = extension_table; ext; ext = ext->next) {
                        fprintf(fp, "        filename: %s\n", ext->filename);
                        fprintf(fp, "          handle: %lx\n", (ulong)ext->handle);


			fprintf(fp, "           flags: %lx (", ext->flags);
			others = 0;
			if (ext->flags & REGISTERED)
				fprintf(fp, "%sREGISTERED", others++ ?
					"|" : "");
			fprintf(fp, ")\n");
                        fprintf(fp, "            next: %lx\n", (ulong)ext->next);
                        fprintf(fp, "            prev: %lx\n", (ulong)ext->prev);

                        for (i = 0, cp = ext->command_table; cp->name; cp++, i++) {
                        	fprintf(fp, "command_table[%d]: %lx\n", i, (ulong)cp); 
				fprintf(fp, "                  name: %s\n", cp->name);
				fprintf(fp, "                  func: %lx\n", (ulong)cp->func);
				fprintf(fp, "             help_data: %lx\n", (ulong)cp->help_data); 
				fprintf(fp, "                 flags: %lx (", cp->flags);
				others = 0;
				if (cp->flags & CLEANUP)
					fprintf(fp, "%sCLEANUP", others++ ? "|" : "");
				if (cp->flags & REFRESH_TASK_TABLE)
					fprintf(fp, "%sREFRESH_TASK_TABLE", others++ ? "|" : "");
				if (cp->flags & HIDDEN_COMMAND)
					fprintf(fp, "%sHIDDEN_COMMAND", others++ ? "|" : "");
				fprintf(fp, ")\n");
			}

			if (ext->next) 
				fprintf(fp, "\n");
		}
		return;
	}


       /*
	*  Print them out in the order they were loaded.
	*/
	for (longest = 0, ext = extension_table; ext; ext = ext->next) {
		if (strlen(ext->filename) > longest)
			longest = strlen(ext->filename);
	}

	fprintf(fp, "%s  COMMANDS\n", 
		mkstring(buf, longest, LJUST, "SHARED OBJECT"));
	longest = MAX(longest, strlen("SHARED OBJECT"));

	for (ext = extension_table; ext; ext = ext->next) 
		if (ext->next == NULL)
			break;

	do {
                fprintf(fp, "%s  ", 
                        mkstring(buf, longest, LJUST, ext->filename));
                for (cp = ext->command_table; cp->name; cp++)
                        fprintf(fp, "%s ", cp->name);
		fprintf(fp, "\n");
	} while ((ext = ext->prev));
}

static void
show_extensions(char *dir) {
	DIR *dirp;
	struct dirent *dp;
	char filename[BUFSIZE*2];

        dirp = opendir(dir);
	if (!dirp)
		return;

        for (dp = readdir(dirp); dp != NULL; dp = readdir(dirp)) {
		sprintf(filename, "%s%s%s", dir,
			LASTCHAR(dir) == '/' ? "" : "/",
			dp->d_name);

		if (!is_shared_object(filename))
			continue;
		fprintf(fp, "%s\n", filename);
	}

	closedir(dirp);
}

static void
show_all_extensions(void)
{
	char *dir;

	show_extensions("./");

	if ((dir = getenv("CRASH_EXTENSIONS")))
		show_extensions(dir);

	if (BITS64())
		show_extensions("/usr/lib64/crash/extensions/");

	show_extensions("/usr/lib/crash/extensions/");
	show_extensions("./extensions/");
}

/*
 *  Load an extension library.
 */
void 
load_extension(char *lib)
{
	struct extension_table *ext, *curext;
	char buf[BUFSIZE];
	size_t size;
	char *env;
	int env_len;

	if ((env = getenv("CRASH_EXTENSIONS")))
		env_len = strlen(env)+1;
	else
		env_len = 0;	

	size = sizeof(struct extension_table) + strlen(lib) + 
		MAX(env_len, strlen("/usr/lib64/crash/extensions/")) + 1;

	if ((ext = (struct extension_table *)malloc(size)) == NULL) 
		error(FATAL, "cannot malloc extension_table space.");

	BZERO(ext, size);

	ext->filename = (char *)((ulong)ext + sizeof(struct extension_table));
	
       /*
	*  If the library is not specified by an absolute pathname, dlopen() 
        *  does not look in the current directory, so modify the filename.
	*  If it's not in the current directory, check the extensions library
	*  directory.
        */
	if ((*lib != '.') && (*lib != '/')) {
		if (file_exists(lib, NULL))
			sprintf(ext->filename, "./%s", lib);
		else if (in_extensions_library(lib, buf))
			strcpy(ext->filename, buf);
		else {
			error(INFO, "%s: %s\n", lib, strerror(ENXIO));
			free(ext);
			return;
		}
	} else 
		strcpy(ext->filename, lib);

	if (!is_shared_object(ext->filename)) {
		error(INFO, "%s: not an ELF format object file\n",
			ext->filename);
		free(ext);
		return;
	}

	for (curext = extension_table; curext; curext = curext->next) {
		if (same_file(curext->filename, ext->filename)) {
			fprintf(fp, "%s: shared object already loaded\n", 
				ext->filename);
			free(ext);
			return;
		}
	}

       /*
        *  register_extension() will be called by the shared object's
        *  _init() function before dlopen() returns below.
	*/
	pc->curext = ext;
	ext->handle = dlopen(ext->filename, RTLD_NOW|RTLD_GLOBAL); 

	if (!ext->handle) {
		strcpy(buf, dlerror());
		error(INFO, "%s\n", buf);
		if (strstr(buf, "undefined symbol: register_extension")) {
			error(INFO, "%s may be statically linked: ",
				pc->program_name);
			fprintf(fp, "recompile without the -static flag\n");
		}
		free(ext);
		return;
	}

	if (!(ext->flags & REGISTERED)) {
		dlclose(ext->handle);
		if (ext->flags & (DUPLICATE_COMMAND_NAME | NO_MINIMAL_COMMANDS))
			error(INFO, 
		         "%s: shared object unloaded\n", ext->filename);
		else
			error(INFO, 
		         "%s: no commands registered: shared object unloaded\n",
				ext->filename);
		free(ext);
		return;
	}

	fprintf(fp, "%s: shared object loaded\n", ext->filename);

	/*
	 *  Put new libraries at the head of the list.
         */
	if (extension_table) {
		extension_table->prev = ext;
		ext->next = extension_table;
	}
	extension_table = ext;

	help_init();
}

/*
 *  Check the extensions library directories.
 */
static int
in_extensions_library(char *lib, char *buf)
{
	char *env;

	if ((env = getenv("CRASH_EXTENSIONS"))) {
		sprintf(buf, "%s%s%s", env,
			LASTCHAR(env) == '/' ? "" : "/",
			lib);
		if (file_exists(buf, NULL))
			return TRUE;
	}

	if (BITS64()) {
		sprintf(buf, "/usr/lib64/crash/extensions/%s", lib);
		if (file_exists(buf, NULL))
			return TRUE;
	}

       	sprintf(buf, "/usr/lib/crash/extensions/%s", lib);
	if (file_exists(buf, NULL))
		return TRUE;
 
       	sprintf(buf, "./extensions/%s", lib);
	if (file_exists(buf, NULL))
		return TRUE;

	return FALSE;
}

/*
 * Look for an extensions directory using the proper order. 
 */
static char *
get_extensions_directory(char *dirbuf)
{
	char *env;

	if ((env = getenv("CRASH_EXTENSIONS"))) {
		if (is_directory(env)) {
			strcpy(dirbuf, env);
			return dirbuf;
		}
	}

	if (BITS64()) {
		sprintf(dirbuf, "/usr/lib64/crash/extensions");
		if (is_directory(dirbuf))
			return dirbuf;
	}

       	sprintf(dirbuf, "/usr/lib/crash/extensions");
	if (is_directory(dirbuf))
		return dirbuf;
 
       	sprintf(dirbuf, "./extensions");
	if (is_directory(dirbuf))
		return dirbuf;

	return NULL;
}


void
preload_extensions(void)
{
	DIR *dirp;
	struct dirent *dp;
	char dirbuf[BUFSIZE];
	char filename[BUFSIZE*2];
	int found;

	if (!get_extensions_directory(dirbuf))
		return;

        dirp = opendir(dirbuf);
	if (!dirp) {
		error(INFO, "%s: %s\n", dirbuf, strerror(errno));
		return;
	}

	pc->curcmd = pc->program_name;

        for (found = 0, dp = readdir(dirp); dp != NULL; dp = readdir(dirp)) {
		sprintf(filename, "%s%s%s", dirbuf, 
			LASTCHAR(dirbuf) == '/' ? "" : "/",
			dp->d_name);

		if (!is_shared_object(filename))
			continue;

		found++;

		load_extension(dp->d_name);
	}

	closedir(dirp);
	
	if (found)
		fprintf(fp, "\n");
	else
		error(NOTE, 
		    "%s: no extension modules found in directory\n\n",
			dirbuf);
}

/*
 *  Unload all, or as specified, extension libraries.
 */
void 
unload_extension(char *lib)
{
        struct extension_table *ext;
	int found;
	char buf[BUFSIZE];

	if (!lib) {
		while (extension_table) {
			ext = extension_table;
                        if (dlclose(ext->handle))
                                error(FATAL,
                                    "dlclose: %s: shared object not open\n",
                                        ext->filename);

			fprintf(fp, "%s: shared object unloaded\n", 
				ext->filename);

			extension_table = ext->next;
			free(ext);
		}

		help_init();
		return;
	}

	if ((*lib != '.') && (*lib != '/')) {
		if (!file_exists(lib, NULL) &&
		    in_extensions_library(lib, buf))
			lib = buf;
	} 

	if (!file_exists(lib, NULL)) {
		error(INFO, "%s: %s\n", lib, strerror(ENXIO));
		return;
	}

        for (ext = extension_table, found = FALSE; ext; ext = ext->next) {
                if (same_file(lib, ext->filename)) {
			found = TRUE;
			if (dlclose(ext->handle))
				error(INFO, 
				    "dlclose: %s: shared object not open\n", 
					ext->filename);
			else {
				fprintf(fp, "%s: shared object unloaded\n",
					ext->filename);

				if (extension_table == ext) {       /* first */
					extension_table = ext->next;
					if (ext->next)
						ext->next->prev = NULL;
				} else if (ext->next == NULL)       /* last */
					ext->prev->next = NULL;
				else {                              /* middle */
					ext->prev->next = ext->next;
					ext->next->prev = ext->prev;
				}

				free(ext);
				help_init();
				break;
			}
		}
		else if (STREQ(basename(lib), basename(ext->filename))) {
			error(INFO, "%s and %s are different object files\n",
				lib, ext->filename);
			found = TRUE;
		}
        }

	if (!found)
		error(INFO, "%s: not loaded\n", lib);
}

/*
 *  Register the command_table as long as there are no command namespace
 *  clashes with the currently-existing command set.  Also delete any aliases
 *  that clash, giving the registered command name priority.
 *
 *  This function is called from the shared object's _init() function
 *  before the dlopen() call returns back to load_extension() above.  
 *  The mark of approval for load_extension() is the setting of the 
 *  REGISTERED bit in the "current" extension_table structure flags.
 */ 
void 
register_extension(struct command_table_entry *command_table)
{
	struct command_table_entry *cp;

	pc->curext->flags |= NO_MINIMAL_COMMANDS;

        for (cp = command_table; cp->name; cp++) {
		if (get_command_table_entry(cp->name)) {
			error(INFO, 
                  "%s: \"%s\" is a duplicate of a currently-existing command\n",
				pc->curext->filename, cp->name);
			pc->curext->flags |= DUPLICATE_COMMAND_NAME;
			return;
		}
		if (cp->flags & MINIMAL)
			pc->curext->flags &= ~NO_MINIMAL_COMMANDS;
	}

	if ((pc->flags & MINIMAL_MODE) && (pc->curext->flags & NO_MINIMAL_COMMANDS)) {
		error(INFO, 
		      "%s: does not contain any commands which support minimal mode\n",
		      pc->curext->filename);
		return;
	}

	if (pc->flags & MINIMAL_MODE) {
		for (cp = command_table; cp->name; cp++) {
			if (!(cp->flags & MINIMAL)) {
				error(WARNING, 
				      "%s: command \"%s\" does not support minimal mode\n",
				      pc->curext->filename, cp->name);
			}
		}
	}

        for (cp = command_table; cp->name; cp++) {
		if (is_alias(cp->name)) {
			error(INFO, 
               "alias \"%s\" deleted: name clash with extension command\n",
				cp->name);
			deallocate_alias(cp->name);
		}
	}

	pc->curext->command_table = command_table;   
	pc->curext->flags |= REGISTERED;             /* Mark of approval */
}

/* 
 *  Hooks for sial.
 */
unsigned long 
get_curtask(void) 
{ 
	return CURRENT_TASK(); 
}

char *
crash_global_cmd(void) 
{ 
	return pc->curcmd;
}

struct command_table_entry *
crash_cmd_table(void) 
{ 
	return pc->cmd_table; 
}
