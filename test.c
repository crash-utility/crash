/* test.c - core analysis suite
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002, 2003, 2004, 2005, 2011 David Anderson
 * Copyright (C) 2002, 2003, 2004, 2005, 2011 Red Hat, Inc. All rights reserved.
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
#include <getopt.h>

static struct option test_long_options[] = {
	{"no", no_argument, 0, 0},
        {"req", required_argument, 0, 0},
	{0, 0, 0, 0}
};

/*
 *  Test your stuff here first if you'd like.  If anything's being done
 *  below in this routine, consider it leftover trash...
 */
void
cmd_test(void)
{
	int c;
	int option_index;

        while ((c = getopt_long(argcnt, args, "", 
		test_long_options, &option_index)) != EOF) {
                switch(c)
                {
                case 0:
                        if (STREQ(test_long_options[option_index].name, "no"))
                                fprintf(fp, "no argument\n");
                        if (STREQ(test_long_options[option_index].name, "req"))
                                fprintf(fp, "required argument: %s\n", optarg);
			break;

                default:
                        argerrs++;
                        break;
		}
	}

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

        while (args[optind]) {
                ;
                optind++;
        }
}

/* 
 *  Scratch routine for testing a feature on a per-task basis by entering
 *  the "foreach test" command.  Like cmd_test(), anything that's being done
 *  below in this routine can be considered trash.
 */     
void
foreach_test(ulong task, ulong flags)
{
 
}

/*
 *  Template for building a new command.
 */
void
cmd_template(void)
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

	while (args[optind]) {
		;
		optind++;
	}
}

