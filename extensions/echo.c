/* echo.c - simple example of a crash extension
 *
 * Copyright (C) 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002-2005, 2007, 2013 David Anderson
 * Copyright (C) 2002-2005, 2007, 2013 Red Hat, Inc. All rights reserved.
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

#include "defs.h"      /* From the crash source top-level directory */

static void echo_init(void);    /* constructor function */
static void echo_fini(void);    /* destructor function (optional) */

static void cmd_echo(void);     /* Declare the commands and their help data. */
static char *help_echo[];

/*
 * Please making the functions and global variables static within your
 * extension if you don't want to make them visiable to subsequently
 * loaded extensions.  Otherwise, non-static symbols within 2 extensions
 * that have the same name can cause confliction.
 */
static struct command_table_entry command_table[] = {
        { "echo", cmd_echo, help_echo, 0},          /* One or more commands, */
        { NULL },                                     /* terminated by NULL, */
};


static void __attribute__((constructor))
echo_init(void) /* Register the command set. */
{ 
        register_extension(command_table);
}
 
/* 
 *  This function is called if the shared object is unloaded. 
 *  If desired, perform any cleanups here. 
 */
static void __attribute__((destructor))
echo_fini(void) { }


/* 
 *  Arguments are passed to the command functions in the global args[argcnt]
 *  array.  See getopt(3) for info on dash arguments.  Check out defs.h and
 *  other crash commands for usage of the myriad of utility routines available
 *  to accomplish what your task.
 */
static void
cmd_echo(void)
{
        int c;

        while ((c = getopt(argcnt, args, "")) != EOF) {
                switch(c)
                {
                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

        while (args[optind]) 
                fprintf(fp, "%s ", args[optind++]);

        fprintf(fp, "\n");
}

/* 
 *  The optional help data is simply an array of strings in a defined format.
 *  For example, the "help echo" command will use the help_echo[] string
 *  array below to create a help page that looks like this:
 * 
 *    NAME
 *      echo - echoes back its arguments
 *
 *    SYNOPSIS
 *      echo arg ...
 *
 *    DESCRIPTION
 *      This command simply echoes back its arguments.
 *
 *    EXAMPLE
 *      Echo back all command arguments:
 *
 *        crash> echo hello, world
 *        hello, world
 *
 */
 
static char *help_echo[] = {
        "echo",                        /* command name */
        "echoes back its arguments",   /* short description */
        "arg ...",                     /* argument synopsis, or " " if none */
 
        "  This command simply echoes back its arguments.",
        "\nEXAMPLE",
        "  Echo back all command arguments:\n",
        "    crash> echo hello, world",
        "    hello, world",
        NULL
};


