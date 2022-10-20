/* configure.c - core analysis suite
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002-2013 David Anderson
 * Copyright (C) 2002-2013 Red Hat, Inc. All rights reserved.
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

/*
 *  define, clear and undef dynamically update the top-level Makefile: 
 *
 *   -b  define: TARGET, GDB, GDB_FILES, GDB_OFILES, GDB_PATCH_FILES, 
 *               TARGET_CFLAGS, LDFLAGS, GDB_CONF_FLAGS and GPL_FILES
 *       create: build_data.c
 *
 *   -d  define: TARGET, GDB, GDB_FILES, GDB_OFILES, GDB_PATCH_FILES, 
 *               TARGET_CFLAGS, LDFLAGS, GDB_CONF_FLAGS and PROGRAM (for daemon)
 *       create: build_data.c
 *
 *   -u   clear: TARGET, GDB, GDB_FILES, GDB_OFILES, VERSION, GDB_PATCH_FILES, 
 *               TARGET_CFLAGS, LDFLAGS, GDB_CONF_FLAGS and GPL_FILES
 *        undef: WARNING_ERROR, WARNING_OPTIONS
 *
 *   -r  define: GDB_FILES, VERSION, GDB_PATCH_FILES GPL_FILES
 *
 *   -w  define: WARNING_OPTIONS
 *        undef: WARNING_ERROR
 *
 *   -W  define: WARNING_ERROR, WARNING_OPTIONS
 *
 *   -n   undef: WARNING_ERROR, WARNING_OPTIONS
 *
 *   -g  define: GDB
 *
 *   -p  Create or remove .rh_rpm_package file 
 *
 *   -q  Don't print configuration
 *
 *   -s  Create crash.spec file
 *
 *   -x  Add extra libraries/flags to build
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>

struct supported_gdb_version;
void build_configure(struct supported_gdb_version *);
void release_configure(char *, struct supported_gdb_version *);
void make_rh_rpm_package(char *, int);
void unconfigure(void);
void set_warnings(int);
void show_configuration(void);
void target_rebuild_instructions(struct supported_gdb_version *, char *);
void arch_mismatch(struct supported_gdb_version *);
void get_current_configuration(struct supported_gdb_version *);
void makefile_setup(FILE **, FILE **);
void makefile_create(FILE **, FILE **);
char *strip_linefeeds(char *);
char *upper_case(char *, char *);
char *lower_case(char *, char *);
char *shift_string_left(char *, int);
char *shift_string_right(char *, int);
char *strip_beginning_whitespace(char *);
char *strip_ending_whitespace(char *);
char *strip_linefeeds(char *);
int file_exists(char *);
int count_chars(char *, char);
void make_build_data(char *);
void gdb_configure(struct supported_gdb_version *);
int parse_line(char *, char **);
struct supported_gdb_version *setup_gdb_defaults(void);
struct supported_gdb_version *store_gdb_defaults(struct supported_gdb_version *);
void make_spec_file(struct supported_gdb_version *);
void set_initial_target(struct supported_gdb_version *);
char *target_to_name(int);
int name_to_target(char *);
char *get_extra_flags(char *, char *);
void add_extra_lib(char *);

#define TRUE 1
#define FALSE 0

#undef X86
#undef ALPHA
#undef PPC
#undef IA64
#undef S390
#undef S390X
#undef PPC64
#undef X86_64
#undef ARM
#undef ARM64
#undef MIPS
#undef SPARC64
#undef MIPS64
#undef RISCV64

#define UNKNOWN 0
#define X86     1
#define ALPHA   2
#define PPC     3
#define IA64    4
#define S390    5
#define S390X   6
#define PPC64   7
#define X86_64  8
#define ARM	9
#define ARM64   10
#define MIPS    11
#define SPARC64 12
#define MIPS64  13
#define RISCV64 14

#define TARGET_X86    "TARGET=X86"
#define TARGET_ALPHA  "TARGET=ALPHA"
#define TARGET_PPC    "TARGET=PPC"
#define TARGET_IA64   "TARGET=IA64"
#define TARGET_S390   "TARGET=S390"
#define TARGET_S390X  "TARGET=S390X"
#define TARGET_PPC64  "TARGET=PPC64"
#define TARGET_X86_64 "TARGET=X86_64"
#define TARGET_ARM    "TARGET=ARM"
#define TARGET_ARM64  "TARGET=ARM64"
#define TARGET_MIPS   "TARGET=MIPS"
#define TARGET_MIPS64 "TARGET=MIPS64"
#define TARGET_SPARC64 "TARGET=SPARC64"
#define TARGET_RISCV64 "TARGET=RISCV64"

#define TARGET_CFLAGS_X86    "TARGET_CFLAGS=-D_FILE_OFFSET_BITS=64"
#define TARGET_CFLAGS_ALPHA  "TARGET_CFLAGS="
#define TARGET_CFLAGS_PPC    "TARGET_CFLAGS=-D_FILE_OFFSET_BITS=64"
#define TARGET_CFLAGS_IA64   "TARGET_CFLAGS="
#define TARGET_CFLAGS_S390   "TARGET_CFLAGS=-D_FILE_OFFSET_BITS=64"
#define TARGET_CFLAGS_S390X  "TARGET_CFLAGS="
#define TARGET_CFLAGS_PPC64  "TARGET_CFLAGS=-m64"
#define TARGET_CFLAGS_X86_64 "TARGET_CFLAGS="
#define TARGET_CFLAGS_ARM            "TARGET_CFLAGS=-D_FILE_OFFSET_BITS=64"
#define TARGET_CFLAGS_ARM_ON_X86     "TARGET_CFLAGS=-D_FILE_OFFSET_BITS=64"
#define TARGET_CFLAGS_ARM_ON_X86_64  "TARGET_CFLAGS=-m32 -D_FILE_OFFSET_BITS=64"
#define TARGET_CFLAGS_X86_ON_X86_64  "TARGET_CFLAGS=-m32 -D_FILE_OFFSET_BITS=64"
#define TARGET_CFLAGS_PPC_ON_PPC64   "TARGET_CFLAGS=-m32 -D_FILE_OFFSET_BITS=64 -fPIC"
#define TARGET_CFLAGS_ARM64            "TARGET_CFLAGS="
#define TARGET_CFLAGS_ARM64_ON_X86_64  "TARGET_CFLAGS="
#define TARGET_CFLAGS_PPC64_ON_X86_64  "TARGET_CFLAGS="
#define TARGET_CFLAGS_MIPS            "TARGET_CFLAGS=-D_FILE_OFFSET_BITS=64"
#define TARGET_CFLAGS_MIPS_ON_X86     "TARGET_CFLAGS=-D_FILE_OFFSET_BITS=64"
#define TARGET_CFLAGS_MIPS_ON_X86_64  "TARGET_CFLAGS=-m32 -D_FILE_OFFSET_BITS=64"
#define TARGET_CFLAGS_MIPS64          "TARGET_CFLAGS="
#define TARGET_CFLAGS_SPARC64         "TARGET_CFLAGS="
#define TARGET_CFLAGS_RISCV64         "TARGET_CFLAGS="
#define TARGET_CFLAGS_RISCV64_ON_X86_64	"TARGET_CFLAGS="

#define GDB_TARGET_DEFAULT        "GDB_CONF_FLAGS="
#define GDB_TARGET_ARM_ON_X86     "GDB_CONF_FLAGS=--target=arm-elf-linux"
#define GDB_TARGET_ARM_ON_X86_64  "GDB_CONF_FLAGS=--target=arm-elf-linux CFLAGS=-m32 CXXFLAGS=-m32"
#define GDB_TARGET_X86_ON_X86_64  "GDB_CONF_FLAGS=--target=i686-pc-linux-gnu CFLAGS=-m32 CXXFLAGS=-m32"
#define GDB_TARGET_PPC_ON_PPC64   "GDB_CONF_FLAGS=--target=ppc-elf-linux CFLAGS=-m32 CXXFLAGS=-m32"
#define GDB_TARGET_ARM64_ON_X86_64  "GDB_CONF_FLAGS=--target=aarch64-elf-linux"   /* TBD */
#define GDB_TARGET_PPC64_ON_X86_64  "GDB_CONF_FLAGS=--target=powerpc64le-unknown-linux-gnu"
#define GDB_TARGET_MIPS_ON_X86     "GDB_CONF_FLAGS=--target=mipsel-elf-linux"
#define GDB_TARGET_MIPS_ON_X86_64  "GDB_CONF_FLAGS=--target=mipsel-elf-linux CFLAGS=-m32 CXXFLAGS=-m32"
#define GDB_TARGET_RISCV64_ON_X86_64  "GDB_CONF_FLAGS=--target=riscv64-unknown-linux-gnu"
     
/*
 *  The original plan was to allow the use of a particular version
 *  of gdb for a given architecture.  But for practical purposes,
 *  it's a one-size-fits-all scheme, and they all use the default
 *  unless overridden.
 */

#define GDB_5_3   (0)
#define GDB_6_0   (1)
#define GDB_6_1   (2)
#define GDB_7_0   (3)
#define GDB_7_3_1 (4)
#define GDB_7_6   (5)
#define GDB_10_2   (6)
#define SUPPORTED_GDB_VERSIONS (GDB_10_2 + 1)

int default_gdb = GDB_10_2;

struct supported_gdb_version {
	char *GDB;
	char *GDB_VERSION_IN;
	char *GDB_FILES;
	char *GDB_OFILES;
	char *GDB_PATCH_FILES;
	char *GDB_FLAGS;
	char *GPL;
} supported_gdb_versions[SUPPORTED_GDB_VERSIONS] = {
	{
	    "GDB=gdb-5.3post-0.20021129.36rh",
	    "Red Hat Linux (5.3post-0.20021129.36rh)",
	    "GDB_FILES=${GDB_5.3post-0.20021129.36rh_FILES}",	   
	    "GDB_OFILES=${GDB_5.3post-0.20021129.36rh_OFILES}",
	    "GDB_PATCH_FILES=",
	    "GDB_FLAGS=-DGDB_5_3",
	    "GPLv2"
	},
	{ 
	    "GDB=gdb-6.0",
	    "6.0",
	    "GDB_FILES=${GDB_6.0_FILES}",
	    "GDB_OFILES=${GDB_6.0_OFILES}",
	    "GDB_PATCH_FILES=",
	    "GDB_FLAGS=-DGDB_6_0",
	    "GPLv2"
	},
	{
	    "GDB=gdb-6.1",
	    "6.1",
	    "GDB_FILES=${GDB_6.1_FILES}",
	    "GDB_OFILES=${GDB_6.1_OFILES}",
	    "GDB_PATCH_FILES=gdb-6.1.patch",
	    "GDB_FLAGS=-DGDB_6_1",
	    "GPLv2"
	},
	{
	    "GDB=gdb-7.0",
	    "7.0",
	    "GDB_FILES=${GDB_7.0_FILES}",
	    "GDB_OFILES=${GDB_7.0_OFILES}",
	    "GDB_PATCH_FILES=gdb-7.0.patch",
	    "GDB_FLAGS=-DGDB_7_0",
	    "GPLv3"
	},
	{
	    "GDB=gdb-7.3.1",
	    "7.3.1",
	    "GDB_FILES=${GDB_7.3.1_FILES}",
	    "GDB_OFILES=${GDB_7.3.1_OFILES}",
	    "GDB_PATCH_FILES=gdb-7.3.1.patch",
	    "GDB_FLAGS=-DGDB_7_3_1",
	    "GPLv3"
	},
	{
	    "GDB=gdb-7.6",
	    "7.6",
	    "GDB_FILES=${GDB_7.6_FILES}",
	    "GDB_OFILES=${GDB_7.6_OFILES}",
	    "GDB_PATCH_FILES=gdb-7.6.patch gdb-7.6-ppc64le-support.patch gdb-7.6-proc_service.h.patch",
	    "GDB_FLAGS=-DGDB_7_6",
	    "GPLv3"
	},
        {
            "GDB=gdb-10.2",
            "10.2",
            "GDB_FILES=${GDB_10.2_FILES}",
            "GDB_OFILES=${GDB_10.2_OFILES}",
            "GDB_PATCH_FILES=gdb-10.2.patch",
            "GDB_FLAGS=-DGDB_10_2",
            "GPLv3"
        },
};

#define DAEMON  0x1
#define QUIET   0x2

#define MAXSTRLEN 256 
#define MIN(a,b) (((a)<(b))?(a):(b))

struct target_data {
	int target;
	int host;
	int initial_gdb_target;
	int flags;
	char program[MAXSTRLEN];
	char gdb_version[MAXSTRLEN];
	char release[MAXSTRLEN];
	struct stat statbuf;
	const char *target_as_param;
} target_data = { 0 }; 

int
main(int argc, char **argv)
{
	int c;
	struct supported_gdb_version *sp;

	sp = setup_gdb_defaults();

	while ((c = getopt(argc, argv, "gsqnWwubdr:p:P:t:x:")) > 0) {
		switch (c) {
		case 'q':
			target_data.flags |= QUIET;
			break;
		case 'u':
			unconfigure();
			break;
		case 'd':
			target_data.flags |= DAEMON;
		case 'b':
			build_configure(sp);
			break;
		case 'r':
			release_configure(optarg, sp);
			break;
		case 'p':
			make_rh_rpm_package(optarg, 0);
			break;
		case 'P':
			make_rh_rpm_package(optarg, 1);
			break;
		case 'W':
		case 'w':
		case 'n':
			set_warnings(c);
			break;
		case 's':
			make_spec_file(sp);
			break;
		case 'g':
			gdb_configure(sp);
			break;
		case 't':
			target_data.target_as_param = optarg;
			break;
		case 'x':
			add_extra_lib(optarg);
			break;
		}
	}

	exit(0);
}

void
target_rebuild_instructions(struct supported_gdb_version *sp, char *target)
{
	fprintf(stderr, 
	    "\nIn order to build a crash binary for the %s architecture:\n",
		target);

	fprintf(stderr, " 1. remove the %s subdirectory\n",
		&sp->GDB[strlen("GDB=")]);
	fprintf(stderr, " 2. perform a \"make clean\"\n");
	fprintf(stderr, " 3. retry the build\n\n");
}

void
arch_mismatch(struct supported_gdb_version *sp)
{
	fprintf(stderr,
	    "\nThe initial build in this source tree was for the %s architecture.\n",
		target_to_name(target_data.initial_gdb_target));

	target_rebuild_instructions(sp, target_to_name(target_data.target));

	exit(1);
}

void
get_current_configuration(struct supported_gdb_version *sp)
{
	FILE *fp;
	static char buf[512];
	char *p;

#ifdef __alpha__
        target_data.target = ALPHA;
#endif
#ifdef __i386__
        target_data.target = X86;
#endif
#ifdef __powerpc__
        target_data.target = PPC;
#endif
#ifdef __ia64__
        target_data.target = IA64;
#endif
#ifdef __s390__
        target_data.target = S390;
#endif
#ifdef __s390x__
        target_data.target = S390X;
#endif
#ifdef __powerpc64__
        target_data.target = PPC64;
#endif
#ifdef __x86_64__
        target_data.target = X86_64;
#endif
#ifdef __arm__
        target_data.target = ARM;
#endif
#ifdef __aarch64__
        target_data.target = ARM64;
#endif
#ifdef __mips__
#ifndef __mips64
	target_data.target = MIPS;
#else
	target_data.target = MIPS64;
#endif
#endif
#ifdef __sparc_v9__
	target_data.target = SPARC64;
#endif
#if defined(__riscv) && (__riscv_xlen == 64)
	target_data.target = RISCV64;
#endif

	set_initial_target(sp);

        /* 
	 * Override target if specified on command line.
	 */
	target_data.host = target_data.target;

	if (target_data.target_as_param) {
		if ((target_data.target == X86 || target_data.target == X86_64) &&
		    (name_to_target((char *)target_data.target_as_param) == ARM)) {
			/* 
			 *  Debugging of ARM core files supported on X86, and on
			 *  X86_64 when built as a 32-bit executable.
			 */
			target_data.target = ARM;
		} else if ((target_data.target == X86 || target_data.target == X86_64) &&
			   (name_to_target((char *)target_data.target_as_param) == MIPS)) {
			/*
			 *  Debugging of MIPS little-endian core files
			 *  supported on X86, and on X86_64 when built as a
			 *  32-bit executable.
			 */
			target_data.target = MIPS;
		} else if ((target_data.target == X86_64) &&
			(name_to_target((char *)target_data.target_as_param) == X86)) {
			/*
			 *  Build an X86 crash binary on an X86_64 host.
			 */
			target_data.target = X86;
		} else if ((target_data.target == X86_64) &&
			(name_to_target((char *)target_data.target_as_param) == ARM64)) {
			/*
			 *  Build an ARM64 crash binary on an X86_64 host.
			 */
			target_data.target = ARM64;
		} else if ((target_data.target == X86_64) &&
			(name_to_target((char *)target_data.target_as_param) == PPC64)) {
			/*
			 *  Build a PPC64 little-endian crash binary on an X86_64 host.
			 */
			target_data.target = PPC64;
		} else if ((target_data.target == PPC64) &&
			(name_to_target((char *)target_data.target_as_param) == PPC)) {
			/*
			 *  Build an PPC crash binary on an PPC64 host.
			 */
			target_data.target = PPC;
		} else if (name_to_target((char *)target_data.target_as_param) ==
			target_data.host) {
			if ((target_data.initial_gdb_target != UNKNOWN) &&
			    (target_data.host != target_data.initial_gdb_target))
				arch_mismatch(sp);
		} else if ((target_data.target == X86_64) &&
			(name_to_target((char *)target_data.target_as_param) == RISCV64)) {
			/*
			 *  Build an RISCV64 crash binary on an X86_64 host.
			 */
			target_data.target = RISCV64;
		} else {
			fprintf(stderr,
			    "\ntarget=%s is not supported on the %s host architecture\n\n",
				target_data.target_as_param,
				target_to_name(target_data.host));
			exit(1);
		}
        }

	/*
	 *  Impose implied (sticky) target if an initial build has been
	 *  done in the source tree.
	 */
	if (target_data.initial_gdb_target && 
	    (target_data.target != target_data.initial_gdb_target)) {
		if ((target_data.initial_gdb_target == ARM) &&
		    (target_data.target != ARM)) {
			if ((target_data.target == X86) || 
			    (target_data.target == X86_64))
				target_data.target = ARM;
			else
				arch_mismatch(sp);
		}
		if ((target_data.target == ARM) &&
		    (target_data.initial_gdb_target != ARM))
			arch_mismatch(sp);

		if ((target_data.initial_gdb_target == MIPS) &&
		    (target_data.target != MIPS)) {
			if ((target_data.target == X86) ||
			    (target_data.target == X86_64))
				target_data.target = MIPS;
			else
				arch_mismatch(sp);
		}

		if ((target_data.initial_gdb_target == MIPS64) &&
		    (target_data.target != MIPS64))
			arch_mismatch(sp);

		if ((target_data.initial_gdb_target == RISCV64) &&
		    (target_data.target != RISCV64)) {
			if (target_data.target == X86_64)
				target_data.target = RISCV64;
			else
				arch_mismatch(sp);
		}

		if ((target_data.initial_gdb_target == X86) &&
		    (target_data.target != X86)) {
			if (target_data.target == X86_64) 
				target_data.target = X86;
			else
				arch_mismatch(sp);
		}
		if ((target_data.target == X86) &&
		    (target_data.initial_gdb_target != X86))
			arch_mismatch(sp);

		if ((target_data.initial_gdb_target == ARM64) &&
		    (target_data.target != ARM64)) {
			if (target_data.target == X86_64) 
				target_data.target = ARM64;
			else
				arch_mismatch(sp);
		}
		if ((target_data.target == ARM64) &&
		    (target_data.initial_gdb_target != ARM64))
			arch_mismatch(sp);

		if ((target_data.initial_gdb_target == PPC64) &&
		    (target_data.target != PPC64)) {
			if (target_data.target == X86_64) 
				target_data.target = PPC64;
			else
				arch_mismatch(sp);
		}
		if ((target_data.target == PPC64) &&
		    (target_data.initial_gdb_target != PPC64))
			arch_mismatch(sp);

		if ((target_data.initial_gdb_target == PPC) &&
		    (target_data.target != PPC)) {
			if (target_data.target == PPC64) 
				target_data.target = PPC;
			else
				arch_mismatch(sp);
		}
		if ((target_data.target == PPC) &&
		    (target_data.initial_gdb_target != PPC))
			arch_mismatch(sp);

		if ((target_data.target == SPARC64) &&
		    (target_data.initial_gdb_target != SPARC64))
			arch_mismatch(sp);
	}

        if ((fp = fopen("Makefile", "r")) == NULL) {
		perror("Makefile");
		goto get_release;
	}

	while (fgets(buf, 512, fp)) {
		if (strncmp(buf, "PROGRAM=", strlen("PROGRAM=")) == 0) {
			p = strstr(buf, "=") + 1;
			strip_linefeeds(p);
			upper_case(p, target_data.program);
			if (target_data.flags & DAEMON)
				strcat(target_data.program, "D");
			continue;
		}
	}

	fclose(fp);

get_release:

	target_data.release[0] = '\0';

	if (file_exists(".rh_rpm_package")) {
        	if ((fp = fopen(".rh_rpm_package", "r")) == NULL) {
			perror(".rh_rpm_package");
		} else {
			if (fgets(buf, 512, fp)) {
				strip_linefeeds(buf);
				if (strlen(buf)) {
					buf[MAXSTRLEN-1] = '\0';
					strcpy(target_data.release, buf);
				} else 
					fprintf(stderr, 
				   "WARNING: .rh_rpm_package file is empty!\n");
			} else
				fprintf(stderr, 
				   "WARNING: .rh_rpm_package file is empty!\n");
			fclose(fp);

			if (strlen(target_data.release))
				return;
		} 
	} else 
		fprintf(stderr, 
			"WARNING: .rh_rpm_package file does not exist!\n");

        if ((fp = fopen("defs.h", "r")) == NULL) {
                perror("defs.h");
		return;
        }

        while (fgets(buf, 512, fp)) {
                if (strncmp(buf, "#define BASELEVEL_REVISION", 
		    strlen("#define BASELEVEL_REVISION")) == 0) {
			p = strstr(buf, "\"") + 1;
			strip_linefeeds(p);
			p[strlen(p)-1] = '\0';
			strcpy(target_data.release, p);
			break;
		}
	}

	fclose(fp);
}

void 
show_configuration(void)
{
	int i;

	if (target_data.flags & QUIET)
		return;

	switch (target_data.target)
	{
	case X86:    
		printf("TARGET: X86\n");
		break;
	case ALPHA: 
		printf("TARGET: ALPHA\n");
		break;
	case PPC:    
		printf("TARGET: PPC\n");
		break;
	case IA64:   
		printf("TARGET: IA64\n");
		break;
	case S390:
		printf("TARGET: S390\n");
		break;
	case S390X:
		printf("TARGET: S390X\n");
		break;
	case PPC64:
		printf("TARGET: PPC64\n");
		break;
	case X86_64:
		printf("TARGET: X86_64\n");
		break;
	case ARM:
		printf("TARGET: ARM\n");
		break;
	case ARM64:
		printf("TARGET: ARM64\n");
		break;
	case MIPS:
		printf("TARGET: MIPS\n");
		break;
	case MIPS64:
		printf("TARGET: MIPS64\n");
		break;
	case SPARC64:
		printf("TARGET: SPARC64\n");
		break;
	case RISCV64:
		printf("TARGET: RISCV64\n");
		break;
	}

	if (strlen(target_data.program)) {
		for (i = 0; i < (strlen("TARGET")-strlen(target_data.program)); 
		     i++)
			printf(" ");
		printf("%s: ", target_data.program);
		if (strlen(target_data.release))
			printf("%s\n", target_data.release);
		else
			printf("???\n");
	}

	if (strlen(target_data.gdb_version)) 
		printf("   GDB: %s\n\n", &target_data.gdb_version[4]);
}

void
build_configure(struct supported_gdb_version *sp)
{
	FILE *fp1, *fp2;
	char buf[512];
	char *target;
	char *target_CFLAGS;
	char *gdb_conf_flags;
	char *ldflags;
	char *cflags;

	get_current_configuration(sp);

	target = target_CFLAGS = NULL;

	gdb_conf_flags = GDB_TARGET_DEFAULT;
	switch (target_data.target)
	{
	case X86:
		target = TARGET_X86;
		if (target_data.host == X86_64) {
                        target_CFLAGS = TARGET_CFLAGS_X86_ON_X86_64;
			gdb_conf_flags = GDB_TARGET_X86_ON_X86_64;
		} else
			target_CFLAGS = TARGET_CFLAGS_X86;
		break;
	case ALPHA:
		target = TARGET_ALPHA;
		target_CFLAGS = TARGET_CFLAGS_ALPHA;
		break;
	case PPC:
		target = TARGET_PPC;
		if (target_data.host == PPC64) {
                        target_CFLAGS = TARGET_CFLAGS_PPC_ON_PPC64;
			gdb_conf_flags = GDB_TARGET_PPC_ON_PPC64;
		} else
			target_CFLAGS = TARGET_CFLAGS_PPC;
		break;
	case IA64:
		target = TARGET_IA64;
                target_CFLAGS = TARGET_CFLAGS_IA64;
		break;
	case S390:
		target = TARGET_S390;
		target_CFLAGS = TARGET_CFLAGS_S390;
		break;
	case S390X:
		target = TARGET_S390X;
		target_CFLAGS = TARGET_CFLAGS_S390X;
		break;
	case PPC64:
                target = TARGET_PPC64;
		if (target_data.host == X86_64) {
			target_CFLAGS = TARGET_CFLAGS_PPC64_ON_X86_64;
			gdb_conf_flags = GDB_TARGET_PPC64_ON_X86_64;
		} else
			target_CFLAGS = TARGET_CFLAGS_PPC64;
                break;
	case X86_64:
                target = TARGET_X86_64;
                target_CFLAGS = TARGET_CFLAGS_X86_64;
                break;
	case ARM:
                target = TARGET_ARM;
                if (target_data.host == X86) {
                        target_CFLAGS = TARGET_CFLAGS_ARM_ON_X86;
			gdb_conf_flags = GDB_TARGET_ARM_ON_X86;
                } else if (target_data.host == X86_64) {
                        target_CFLAGS = TARGET_CFLAGS_ARM_ON_X86_64;
			gdb_conf_flags = GDB_TARGET_ARM_ON_X86_64;
		} else
                        target_CFLAGS = TARGET_CFLAGS_ARM;
                break;
	case ARM64:
		target = TARGET_ARM64;
		if (target_data.host == X86_64) {
			target_CFLAGS = TARGET_CFLAGS_ARM64_ON_X86_64;
			gdb_conf_flags = GDB_TARGET_ARM64_ON_X86_64;
		} else
			target_CFLAGS = TARGET_CFLAGS_ARM64;
		break;
	case MIPS:
                target = TARGET_MIPS;
                if (target_data.host == X86) {
                        target_CFLAGS = TARGET_CFLAGS_MIPS_ON_X86;
			gdb_conf_flags = GDB_TARGET_MIPS_ON_X86;
                } else if (target_data.host == X86_64) {
                        target_CFLAGS = TARGET_CFLAGS_MIPS_ON_X86_64;
			gdb_conf_flags = GDB_TARGET_MIPS_ON_X86_64;
		} else
                        target_CFLAGS = TARGET_CFLAGS_MIPS;
		break;
	case MIPS64:
		target = TARGET_MIPS64;
		target_CFLAGS = TARGET_CFLAGS_MIPS64;
		break;
	case SPARC64:
		target = TARGET_SPARC64;
		target_CFLAGS = TARGET_CFLAGS_SPARC64;
		break;
	case RISCV64:
		target = TARGET_RISCV64;
		if (target_data.host == X86_64) {
			target_CFLAGS = TARGET_CFLAGS_RISCV64_ON_X86_64;
			gdb_conf_flags = GDB_TARGET_RISCV64_ON_X86_64;
		} else
			target_CFLAGS = TARGET_CFLAGS_RISCV64;
		break;
	}

	ldflags = get_extra_flags("LDFLAGS.extra", NULL);
	cflags = get_extra_flags("CFLAGS.extra", NULL);
	gdb_conf_flags = get_extra_flags("GDBFLAGS.extra", gdb_conf_flags);

	makefile_setup(&fp1, &fp2);

	while (fgets(buf, 512, fp1)) {
		if (strncmp(buf, "TARGET=", strlen("TARGET=")) == 0)
			fprintf(fp2, "%s\n", target);
                else if (strncmp(buf, "TARGET_CFLAGS=",
			strlen("TARGET_CFLAGS=")) == 0)
                       	fprintf(fp2, "%s%s%s\n", target_CFLAGS,
				cflags ? " " : "", cflags ? cflags : "");
		else if (strncmp(buf, "GDB_CONF_FLAGS=",
			strlen("GDB_CONF_FLAGS=")) == 0)
			fprintf(fp2, "%s\n", gdb_conf_flags);
		else if (strncmp(buf, "GDB_FILES=",strlen("GDB_FILES=")) == 0)
			fprintf(fp2, "%s\n", sp->GDB_FILES);
		else if (strncmp(buf, "GDB_OFILES=",strlen("GDB_OFILES=")) == 0)
                        fprintf(fp2, "%s\n", sp->GDB_OFILES);
		else if (strncmp(buf, "GDB_PATCH_FILES=",strlen("GDB_PATCH_FILES=")) == 0)
                        fprintf(fp2, "%s\n", sp->GDB_PATCH_FILES);
		else if (strncmp(buf, "GDB_FLAGS=",strlen("GDB_FLAGS=")) == 0)
                        fprintf(fp2, "%s\n", sp->GDB_FLAGS);
		else if (strncmp(buf, "GPL_FILES=", strlen("GPL_FILES=")) == 0)
			fprintf(fp2, "GPL_FILES=%s\n", strcmp(sp->GPL, "GPLv2") == 0 ? 
				"COPYING" : "COPYING3");
                else if (strncmp(buf, "GDB=", strlen("GDB=")) == 0) {
                        fprintf(fp2, "%s\n", sp->GDB);
                        sprintf(target_data.gdb_version, "%s", &sp->GDB[4]);
		} else if (strncmp(buf, "LDFLAGS=", strlen("LDFLAGS=")) == 0) {
                       	fprintf(fp2, "LDFLAGS=%s\n", ldflags ? ldflags : "");
		} else
			fprintf(fp2, "%s", buf);

	}

	makefile_create(&fp1, &fp2);
	show_configuration();
	make_build_data(&target[strlen("TARGET=")]);
}

void
release_configure(char *gdb_version, struct supported_gdb_version *sp)
{
	FILE *fp1, *fp2;
	int found;
	char buf[512];
	char gdb_files[MAXSTRLEN];

	get_current_configuration(sp);

	sprintf(buf, "%s/gdb", gdb_version);
	if (!file_exists(buf)) {
		fprintf(stderr, "make release: no such directory: %s\n", buf);
		exit(1);
	}
	sprintf(gdb_files, "GDB_%s_FILES", 
		&gdb_version[strlen("gdb-")]);

	makefile_setup(&fp1, &fp2);

	found = 0;
	while (fgets(buf, 512, fp1)) {
		if (strncmp(buf, gdb_files, strlen(gdb_files)) == 0)
			found++;
		if (strncmp(buf, "GDB_FILES=", strlen("GDB_FILES=")) == 0)
			fprintf(fp2, "GDB_FILES=${%s}\n", gdb_files);
		else if (strncmp(buf, "VERSION=", strlen("VERSION=")) == 0)
                        fprintf(fp2, "VERSION=%s\n", 
				target_data.release);
		else if (strncmp(buf, "GDB_PATCH_FILES=", strlen("GDB_PATCH_FILES=")) == 0)
			fprintf(fp2, "%s\n", sp->GDB_PATCH_FILES);
		else if (strncmp(buf, "GPL_FILES=", strlen("GPL_FILES=")) == 0)
			fprintf(fp2, "GPL_FILES=%s\n", strcmp(sp->GPL, "GPLv2") == 0 ? 
				"COPYING" : "COPYING3");
		else
			fprintf(fp2, "%s", buf);

	}

        if (!found) {
                fprintf(stderr, "make release: cannot find %s\n", gdb_files);
                exit(1);
        }

	makefile_create(&fp1, &fp2);
}

/*
 *  Create an .rh_rpm_package file if the passed-in variable is set.
 */
void 
make_rh_rpm_package(char *package, int release)
{
	char *p, *cur;
	FILE *fp;
	char buf[256];

	if ((strcmp(package, "remove") == 0)) {
		if (file_exists(".rh_rpm_package")) {
			if (unlink(".rh_rpm_package")) {
				perror("unlink");
                		fprintf(stderr, 
					"cannot remove .rh_rpm_package\n");
				exit(1);
			}
		}
		return;
	}

	if (!(p = strstr(package, "=")))
		return;
	
	if (!strlen(++p))
		return;

	if (release) {
		if (!(fp = popen("./crash -v", "r"))) {
			fprintf(stderr, "cannot execute \"crash -v\"\n");
			exit(1);
		}
		cur = NULL;
		while (fgets(buf, 256, fp)) {
			if (strncmp(buf, "crash ", 6) == 0) {
				cur = &buf[6];
				break;
			} 
		}
		pclose(fp);
	
		if (!cur) {
			fprintf(stderr, "cannot get version from \"crash -v\"\n");
			exit(1);
		} 
		strip_linefeeds(cur);

		if (strcmp(cur, p) != 0) {
			fprintf(stderr, "./crash version: %s\n", cur);
			fprintf(stderr, "release version: %s\n", p);
			exit(1);
		}
	}

        if ((fp = fopen(".rh_rpm_package", "w")) == NULL) {
                perror("fopen");
                fprintf(stderr, "cannot open .rh_rpm_package\n");
                exit(1);
        }

	fprintf(fp, "%s\n", strip_linefeeds(p));

	fclose(fp);
}

void
gdb_configure(struct supported_gdb_version *sp)
{
	FILE *fp1, *fp2;
	char buf[512];

	get_current_configuration(sp);

	makefile_setup(&fp1, &fp2);

	while (fgets(buf, 512, fp1)) {
		if (strncmp(buf, "GDB=", strlen("GDB=")) == 0)
			fprintf(fp2, "%s\n", sp->GDB);
		else
			fprintf(fp2, "%s", buf);

	}

	makefile_create(&fp1, &fp2);
}

void
unconfigure(void)
{
	FILE *fp1, *fp2;
	char buf[512];

	makefile_setup(&fp1, &fp2);

	while (fgets(buf, 512, fp1)) {
                if (strncmp(buf, "TARGET=", strlen("TARGET=")) == 0)
                        fprintf(fp2, "TARGET=\n");
                else if (strncmp(buf, "TARGET_CFLAGS=",
			strlen("TARGET_CFLAGS=")) == 0)
                        fprintf(fp2, "TARGET_CFLAGS=\n");
		else if (strncmp(buf, "GDB_CONF_FLAGS=",
			strlen("GDB_CONF_FLAGS=")) == 0)
			fprintf(fp2, "GDB_CONF_FLAGS=\n");
                else if (strncmp(buf, "GDB_FILES=",strlen("GDB_FILES=")) == 0)
                        fprintf(fp2, "GDB_FILES=\n");
                else if (strncmp(buf, "GDB_OFILES=",strlen("GDB_OFILES=")) == 0)
                        fprintf(fp2, "GDB_OFILES=\n");
                else if (strncmp(buf, "GDB_PATCH_FILES=",strlen("GDB_PATCH_FILES=")) == 0)
                        fprintf(fp2, "GDB_PATCH_FILES=\n");
                else if (strncmp(buf, "GDB_FLAGS=",strlen("GDB_FLAGS=")) == 0)
                        fprintf(fp2, "GDB_FLAGS=\n");
                else if (strncmp(buf, "GDB=", strlen("GDB=")) == 0) 
                        fprintf(fp2, "GDB=\n");
                else if (strncmp(buf, "VERSION=", strlen("VERSION=")) == 0) 
                        fprintf(fp2, "VERSION=\n");
                else if (strncmp(buf, "GPL_FILES=", strlen("GPL_FILES=")) == 0) 
                        fprintf(fp2, "GPL_FILES=\n");
                else if (strncmp(buf, "LDFLAGS=", strlen("LDFLAGS=")) == 0) 
                        fprintf(fp2, "LDFLAGS=\n");
                else if (strncmp(buf, "WARNING_ERROR=", 
			strlen("WARNING_ERROR=")) == 0) {
                        shift_string_right(buf, 1);
			buf[0] = '#';
                        fprintf(fp2, "%s", buf);
		} else if (strncmp(buf, "WARNING_OPTIONS=",
                    strlen("WARNING_OPTIONS=")) == 0) {
                        shift_string_right(buf, 1);
			buf[0] = '#';
                        fprintf(fp2, "%s", buf);
		} else
                        fprintf(fp2, "%s", buf);
	}

	makefile_create(&fp1, &fp2);
}

void
set_warnings(int w)
{
        FILE *fp1, *fp2;
        char buf[512];

        makefile_setup(&fp1, &fp2);
 
        while (fgets(buf, 512, fp1)) {
		if (strncmp(buf, "#WARNING_ERROR=", 
		    strlen("#WARNING_ERROR=")) == 0) {
			switch (w)
			{
			case 'W':
				shift_string_left(buf, 1);
				break;
			case 'w':
			case 'n':
				break;
			}
		}

                if (strncmp(buf, "WARNING_ERROR=", 
		    strlen("WARNING_ERROR=")) == 0) {
			switch (w) 
			{
			case 'n':
			case 'w':
				shift_string_right(buf, 1);
				buf[0] = '#';
				break;
			case 'W':
				break;
			}
		}
		
                if (strncmp(buf, "#WARNING_OPTIONS=",
                    strlen("#WARNING_OPTIONS=")) == 0) { 
			switch (w)
			{
			case 'W':
			case 'w':
				shift_string_left(buf, 1);
				break;
			case 'n':
				break;
			}
		}

                if (strncmp(buf, "WARNING_OPTIONS=",
                    strlen("WARNING_OPTIONS=")) == 0) {
			switch (w) 
			{
			case 'w':
			case 'W':
				break;
			case 'n':
				shift_string_right(buf, 1);
				buf[0] = '#';
				break;
			}
		}

                fprintf(fp2, "%s", buf);
        }

        makefile_create(&fp1, &fp2);
}

void
makefile_setup(FILE **fp1, FILE **fp2)
{
        if (stat("Makefile", &target_data.statbuf) == -1) {
                perror("Makefile");
                exit(1);
        }

        if ((*fp1 = fopen("Makefile", "r")) == NULL) {
                perror("fopen");
                fprintf(stderr, "cannot open existing Makefile\n");
                exit(1);
        }

        unlink("Makefile.new");
        if ((*fp2 = fopen("Makefile.new", "w+")) == NULL) {
                perror("fopen");
                fprintf(stderr, "cannot create new Makefile\n");
                exit(1);
        }
}

void
makefile_create(FILE **fp1, FILE **fp2)
{
        fclose(*fp1);
        fclose(*fp2);

        if (system("mv Makefile.new Makefile") != 0) {
                fprintf(stderr, "Makefile: cannot create new Makefile\n");
                fprintf(stderr, "please copy Makefile.new to Makefile\n");
                exit(1);
        }

        if (chown("Makefile", target_data.statbuf.st_uid, 
	    target_data.statbuf.st_gid) == -1) {
                fprintf(stderr,
                    "Makefile: cannot restore original owner/group\n");
        }
}



#define LASTCHAR(s)      (s[strlen(s)-1])

char *
strip_linefeeds(char *line)
{
        char *p;

        if (line == NULL || strlen(line) == 0)
                return(line);

        p = &LASTCHAR(line);

        while (*p == '\n')
                *p = '\0';

        return(line);
}

/*      
 *  Turn a string into upper-case.
 */
char *
upper_case(char *s, char *buf)
{
        char *p1, *p2;

        p1 = s;
        p2 = buf; 
 
        while (*p1) {
                *p2 = toupper(*p1);
                p1++, p2++;
        }
                
        *p2 = '\0';
        
        return(buf);
}

/*      
 *  Turn a string into lower-case.
 */
char *
lower_case(char *s, char *buf)
{
        char *p1, *p2;
 
        p1 = s;
        p2 = buf;   
 
        while (*p1) {
                *p2 = tolower(*p1);
                p1++, p2++;
        }
  
        *p2 = '\0'; 
  
        return(buf);
}

char *
shift_string_left(char *s, int cnt)
{
        int origlen;

        if (!cnt)
                return(s);

        origlen = strlen(s);
        memmove(s, s+cnt, (origlen-cnt));
        *(s+(origlen-cnt)) = '\0';
        return(s);
}

char *
shift_string_right(char *s, int cnt)
{
        int i;
        int origlen;

        if (!cnt)
                return(s);

        origlen = strlen(s);
        memmove(s+cnt, s, origlen);
        *(s+(origlen+cnt)) = '\0';

        for (i = 0; i < cnt; i++)
                s[i] = ' ';

        return(s);
}

char *
strip_beginning_whitespace(char *line)
{
        char buf[MAXSTRLEN];
        char *p;

        if (line == NULL || strlen(line) == 0)
                return(line);

        strcpy(buf, line);
        p = &buf[0];
        while (*p == ' ' || *p == '\t')
                p++;
        strcpy(line, p);

        return(line);
}

char *
strip_ending_whitespace(char *line)
{
        char *p;

        if (line == NULL || strlen(line) == 0)
                return(line);

	p = &line[strlen(line)-1];

        while (*p == ' ' || *p == '\t') {
                *p = '\0';
                if (p == line)
                        break;
                p--;
        }

        return(line);
}

int
file_exists(char *file)
{
        struct stat sbuf;

        if (stat(file, &sbuf) == 0)
                return TRUE;

        return FALSE;
}

int
count_chars(char *s, char c)
{
        char *p;
        int count;

        if (!s)
                return 0;

        count = 0;

        for (p = s; *p; p++) {
                if (*p == c)
                        count++;
        }

        return count;
}


void
make_build_data(char *target)
{
        char *p;
        char hostname[MAXSTRLEN];
	char progname[MAXSTRLEN];
	char inbuf1[MAXSTRLEN];
	char inbuf2[MAXSTRLEN];
	char inbuf3[MAXSTRLEN];
	FILE *fp1, *fp2, *fp3, *fp4;

	unlink("build_data.c");

        fp1 = popen("date", "r");
        fp2 = popen("id", "r");
	fp3 = popen("gcc --version", "r");

	if ((fp4 = fopen("build_data.c", "w")) == NULL) {
		perror("build_data.c");
		exit(1);
	}

        if (gethostname(hostname, MAXSTRLEN) != 0)
                hostname[0] = '\0';

        p = fgets(inbuf1, 79, fp1);

        p = fgets(inbuf2, 79, fp2);
        p = strstr(inbuf2, " ");
        *p = '\0';

        p = fgets(inbuf3, 79, fp3);

	lower_case(target_data.program, progname);

	fprintf(fp4, "char *build_command = \"%s\";\n", progname);
        if (getenv("SOURCE_DATE_EPOCH"))
                fprintf(fp4, "char *build_data = \"reproducible build\";\n");
        else if (strlen(hostname))
                fprintf(fp4, "char *build_data = \"%s by %s on %s\";\n",
                        strip_linefeeds(inbuf1), inbuf2, hostname);
        else
                fprintf(fp4, "char *build_data = \"%s by %s\";\n", 
			strip_linefeeds(inbuf1), inbuf2);

        bzero(inbuf1, MAXSTRLEN);
	sprintf(inbuf1, "%s", target_data.release);

	fprintf(fp4, "char *build_target = \"%s\";\n", target);

        fprintf(fp4, "char *build_version = \"%s\";\n", inbuf1);

	fprintf(fp4, "char *compiler_version = \"%s\";\n", 
		strip_linefeeds(inbuf3));

        pclose(fp1);
        pclose(fp2);
        pclose(fp3);
	fclose(fp4);
}

void
make_spec_file(struct supported_gdb_version *sp)
{
	char *Version, *Release;
	char buf[512];

	get_current_configuration(sp);

	Release = strstr(target_data.release, "-");
	if (!Release) {
		Version = target_data.release;
		Release = "0";		
	} else {
		fprintf(stderr, 
		    "crash.spec: obsolete src.rpm build manner -- no dashes allowed: %s\n",
			target_data.release);
		return;
	}

	printf("#\n");
	printf("# crash core analysis suite\n");
	printf("#\n");
	printf("Summary: crash utility for live systems; netdump, diskdump, kdump, LKCD or mcore dumpfiles\n");
	printf("Name: %s\n", lower_case(target_data.program, buf));
	printf("Version: %s\n", Version);
	printf("Release: %s\n", Release);
	printf("License: %s\n", sp->GPL);
	printf("Group: Development/Debuggers\n");
	printf("Source: %%{name}-%%{version}.tar.gz\n");
	printf("URL: https://github.com/crash-utility\n");
	printf("Distribution: Linux 2.2 or greater\n");
	printf("Vendor: Red Hat, Inc.\n");
	printf("Packager: Dave Anderson <anderson@redhat.com>\n");
	printf("ExclusiveOS: Linux\n");
	printf("ExclusiveArch: %%{ix86} alpha ia64 ppc ppc64 ppc64pseries ppc64iseries x86_64 s390 s390x arm aarch64 ppc64le mips mipsel mips64el sparc64 riscv64\n");
	printf("Buildroot: %%{_tmppath}/%%{name}-root\n");
	printf("BuildRequires: ncurses-devel zlib-devel bison\n");
	printf("Requires: binutils\n");
	printf("# Patch0: crash-3.3-20.installfix.patch (patch example)\n");
	printf("\n");
	printf("%%description\n");
	printf("The core analysis suite is a self-contained tool that can be used to\n");
	printf("investigate either live systems, kernel core dumps created from the\n");
	printf("netdump, diskdump and kdump facilities from Red Hat Linux, the mcore kernel patch\n");
	printf("offered by Mission Critical Linux, or the LKCD kernel patch.\n");
	printf("\n");
	printf("%%package devel\n");
	printf("Requires: %%{name} = %%{version}, zlib-devel\n");
	printf("Summary: crash utility for live systems; netdump, diskdump, kdump, LKCD or mcore dumpfiles\n");
	printf("Group: Development/Debuggers\n");
	printf("\n");
	printf("%%description devel\n");
	printf("The core analysis suite is a self-contained tool that can be used to\n");
	printf("investigate either live systems, kernel core dumps created from the\n");
	printf("netdump, diskdump and kdump packages from Red Hat Linux, the mcore kernel patch\n");
	printf("offered by Mission Critical Linux, or the LKCD kernel patch.\n");
	printf("\n");
	printf("%%package extensions\n");
	printf("Summary: Additional commands for the crash dump analysis tool\n");
	printf("Group: Development/Debuggers\n");
	printf("\n");
	printf("%%description extensions\n");
	printf("The extensions package contains plugins that provide additional crash\n");
	printf("commands. The extensions can be loaded in crash via the \"extend\" command.\n");
	printf("\n");
	printf("The following extensions are provided:\n");
	printf("* eppic:  Provides C-like language for writing dump analysis scripts\n");
	printf("* dminfo: Device-mapper target analyzer\n");
	printf("* snap:   Takes a snapshot of live memory and creates a kdump dumpfile\n");
        printf("* trace:  Displays kernel tracing data and traced events that occurred prior to a panic.\n"); 
	printf("\n");
	printf("%%prep\n");
        printf("%%setup -n %%{name}-%%{version}\n"); 
	printf("# %%patch0 -p1 -b .install (patch example)\n");
	printf("\n");
	printf("%%build\n");
	printf("make RPMPKG=\"%%{version}\"\n");
	printf("# make RPMPKG=\"%%{version}-%%{release}\"\n");
	printf("make extensions\n");
     /*	printf("make crashd\n"); */
	printf("\n");
	printf("%%install\n");
	printf("rm -rf %%{buildroot}\n");
	printf("mkdir -p %%{buildroot}/usr/bin\n");
	printf("make DESTDIR=%%{buildroot} install\n");
	printf("mkdir -p %%{buildroot}%%{_mandir}/man8\n");
	printf("cp crash.8 %%{buildroot}%%{_mandir}/man8/crash.8\n");
	printf("mkdir -p %%{buildroot}%%{_includedir}/crash\n");
	printf("cp defs.h %%{buildroot}%%{_includedir}/crash\n");
	printf("mkdir -p %%{buildroot}%%{_libdir}/crash/extensions\n");
	printf("if [ -f extensions/eppic.so ]\n");
	printf("then\n");
	printf("cp extensions/eppic.so %%{buildroot}%%{_libdir}/crash/extensions\n");
	printf("fi\n");
	printf("cp extensions/dminfo.so %%{buildroot}%%{_libdir}/crash/extensions\n");
	printf("cp extensions/snap.so %%{buildroot}%%{_libdir}/crash/extensions\n");
	printf("cp extensions/trace.so %%{buildroot}%%{_libdir}/crash/extensions\n");
	printf("\n");
	printf("%%clean\n");
	printf("rm -rf %%{buildroot}\n");
	printf("\n");
	printf("%%files\n");
	printf("%%defattr(-,root,root)\n");
	printf("/usr/bin/crash\n");
	printf("%%{_mandir}/man8/crash.8*\n");
     /*	printf("/usr/bin/crashd\n"); */
	printf("%%doc README\n");
	printf("\n");
	printf("%%files devel\n");
	printf("%%defattr(-,root,root)\n");
	printf("%%{_includedir}/*\n");
	printf("\n");
	printf("%%files extensions\n");
	printf("%%defattr(-,root,root)\n");
	printf("%%{_libdir}/crash/extensions/*\n");
}

/*
 *  Use the default gdb #defines unless there's a .gdb file.
 */
struct supported_gdb_version *
setup_gdb_defaults(void)
{
	FILE *fp;
	char inbuf[512];
	char buf[512];
	struct supported_gdb_version *sp;

	/*
	 *  Use the default, allowing for an override in .gdb
	 */
        if (!file_exists(".gdb")) 
		return store_gdb_defaults(NULL);

        if ((fp = fopen(".gdb", "r")) == NULL) {
        	perror(".gdb");
		return store_gdb_defaults(NULL);
	}

        while (fgets(inbuf, 512, fp)) {
		strip_linefeeds(inbuf);
		strip_beginning_whitespace(inbuf);

		strcpy(buf, inbuf);

		/*
		 *  Simple override.
		 */
		if (strcmp(buf, "5.3") == 0) {
			fclose(fp);
			sp = &supported_gdb_versions[GDB_5_3];
			fprintf(stderr, ".gdb configuration: %s\n\n", sp->GDB_VERSION_IN);
			return store_gdb_defaults(sp);
		}
		if (strcmp(buf, "6.0") == 0) {
			fclose(fp);
			sp = &supported_gdb_versions[GDB_6_0];
			fprintf(stderr, ".gdb configuration: %s\n\n", sp->GDB_VERSION_IN);
			return store_gdb_defaults(sp);
		}
		if (strcmp(buf, "6.1") == 0) {
			fclose(fp);
			sp = &supported_gdb_versions[GDB_6_1];
			fprintf(stderr, ".gdb configuration: %s\n", sp->GDB_VERSION_IN);
			return store_gdb_defaults(sp);
		}
		if (strcmp(buf, "7.0") == 0) {
			fclose(fp);
			sp = &supported_gdb_versions[GDB_7_0];
			fprintf(stderr, ".gdb configuration: %s\n", sp->GDB_VERSION_IN);
			return store_gdb_defaults(sp);
		}
		if (strcmp(buf, "7.3.1") == 0) {
			fclose(fp);
			sp = &supported_gdb_versions[GDB_7_3_1];
			fprintf(stderr, ".gdb configuration: %s\n", sp->GDB_VERSION_IN);
			return store_gdb_defaults(sp);
		}
		if (strcmp(buf, "7.6") == 0) {
			fclose(fp);
			sp = &supported_gdb_versions[GDB_7_6];
			fprintf(stderr, ".gdb configuration: %s\n", sp->GDB_VERSION_IN);
			return store_gdb_defaults(sp);
		}
                if (strcmp(buf, "10.2") == 0) {
                        fclose(fp);
                        sp = &supported_gdb_versions[GDB_10_2];
                        fprintf(stderr, ".gdb configuration: %s\n", sp->GDB_VERSION_IN);
                        return store_gdb_defaults(sp);
                }

        }
	
	fclose(fp);

	fprintf(stderr, ".gdb: rejected -- using default gdb\n\n");
 	return store_gdb_defaults(NULL);
}

struct supported_gdb_version *
store_gdb_defaults(struct supported_gdb_version *sp)
{
	if (!sp)
		sp = &supported_gdb_versions[default_gdb];
	else
		fprintf(stderr, "WARNING: \"make clean\" may be required before rebuilding\n\n");

	return sp; 
}

void
set_initial_target(struct supported_gdb_version *sp)
{
	FILE *fp;
	char crash_target[512];
	char buf[512];

	target_data.initial_gdb_target = UNKNOWN;

	sprintf(crash_target, "%s/crash.target",
		&sp->GDB[strlen("GDB=")]);

	if (!file_exists(crash_target)) {
		if (target_data.target_as_param &&
		    file_exists(&sp->GDB[strlen("GDB=")])) {
			fprintf(stderr, 
			    "\nThe \"%s\" file does not exist.\n",
				crash_target);
			target_rebuild_instructions(sp, (char *)target_data.target_as_param);
			exit(1);
		}
		return;
	}

        if ((fp = fopen(crash_target, "r")) == NULL) {
                perror(crash_target);
                return;
        }
	
        if (!fgets(buf, 512, fp)) {
                perror(crash_target);
		fclose(fp);
                return;
	}

	fclose(fp);

	if (strncmp(buf, "X86_64", strlen("X86_64")) == 0) 
		target_data.initial_gdb_target = X86_64;
	else if (strncmp(buf, "X86", strlen("X86")) == 0) 
		target_data.initial_gdb_target = X86;
	else if (strncmp(buf, "ALPHA", strlen("ALPHA")) == 0)
		target_data.initial_gdb_target = ALPHA;
	else if (strncmp(buf, "PPC64", strlen("PPC64")) == 0)
		target_data.initial_gdb_target = PPC64;
	else if (strncmp(buf, "PPC", strlen("PPC")) == 0)
		target_data.initial_gdb_target = PPC;
	else if (strncmp(buf, "IA64", strlen("IA64")) == 0)
		target_data.initial_gdb_target = IA64;
	else if (strncmp(buf, "S390X", strlen("S390X")) == 0)
		target_data.initial_gdb_target = S390X;
	else if (strncmp(buf, "S390", strlen("S390")) == 0)
		target_data.initial_gdb_target = S390;
	else if (strncmp(buf, "ARM64", strlen("ARM64")) == 0)
		target_data.initial_gdb_target = ARM64;
	else if (strncmp(buf, "ARM", strlen("ARM")) == 0)
		target_data.initial_gdb_target = ARM;
	else if (strncmp(buf, "MIPS64", strlen("MIPS64")) == 0)
		target_data.initial_gdb_target = MIPS64;
	else if (strncmp(buf, "MIPS", strlen("MIPS")) == 0)
		target_data.initial_gdb_target = MIPS;
	else if (strncmp(buf, "SPARC64", strlen("SPARC64")) == 0)
		target_data.initial_gdb_target = SPARC64;
	else if (strncmp(buf, "RISCV64", strlen("RISCV64")) == 0)
		target_data.initial_gdb_target = RISCV64;
}

char *
target_to_name(int target)
{
	switch (target)
	{
	case X86:    return("X86");
	case ALPHA:  return("ALPHA");
	case PPC:    return("PPC");
	case IA64:   return("IA64");
	case S390:   return("S390");
	case S390X:  return("S390X");
	case PPC64:  return("PPC64");
	case X86_64: return("X86_64");
	case ARM:    return("ARM"); 
	case ARM64:  return("ARM64");
	case MIPS:   return("MIPS");
	case MIPS64: return("MIPS64");
	case SPARC64: return("SPARC64");
	case RISCV64: return("RISCV64");
	}

	return "UNKNOWN";
}

int
name_to_target(char *name)
{
	if (strncmp(name, "X86_64", strlen("X86_64")) == 0)
                return X86_64;
	else if (strncmp(name, "x86_64", strlen("x86_64")) == 0)
                return X86_64;
        else if (strncmp(name, "X86", strlen("X86")) == 0)
                return X86;
        else if (strncmp(name, "x86", strlen("x86")) == 0)
                return X86;
        else if (strncmp(name, "ALPHA", strlen("ALPHA")) == 0)
                return ALPHA;
        else if (strncmp(name, "alpha", strlen("alpha")) == 0)
                return ALPHA;
        else if (strncmp(name, "PPC64", strlen("PPC64")) == 0)
                return PPC64;
        else if (strncmp(name, "ppc64", strlen("ppc64")) == 0)
                return PPC64;
        else if (strncmp(name, "ppc64le", strlen("ppc64le")) == 0)
                return PPC64;
	else if (strncmp(name, "PPC64LE", strlen("PPC64LE")) == 0)
                return PPC64;
        else if (strncmp(name, "PPC", strlen("PPC")) == 0)
                return PPC;
        else if (strncmp(name, "ppc", strlen("ppc")) == 0)
                return PPC;
        else if (strncmp(name, "IA64", strlen("IA64")) == 0)
                return IA64;
        else if (strncmp(name, "ia64", strlen("ia64")) == 0)
                return IA64;
        else if (strncmp(name, "S390X", strlen("S390X")) == 0)
                return S390X;
        else if (strncmp(name, "s390x", strlen("s390x")) == 0)
                return S390X;
        else if (strncmp(name, "S390", strlen("S390")) == 0)
                return S390;
        else if (strncmp(name, "s390", strlen("s390")) == 0)
                return S390;
        else if (strncmp(name, "ARM64", strlen("ARM64")) == 0)
                return ARM64;
        else if (strncmp(name, "arm64", strlen("arm64")) == 0)
                return ARM64;
        else if (strncmp(name, "aarch64", strlen("aarch64")) == 0)
		return ARM64;
        else if (strncmp(name, "ARM", strlen("ARM")) == 0)
                return ARM;
        else if (strncmp(name, "arm", strlen("arm")) == 0)
                return ARM;
        else if (strncmp(name, "mips", strlen("mips")) == 0)
                return MIPS;
        else if (strncmp(name, "MIPS", strlen("MIPS")) == 0)
                return MIPS;
	else if (strncmp(name, "mips64", strlen("mips64")) == 0)
		return MIPS64;
	else if (strncmp(name, "MIPS64", strlen("MIPS64")) == 0)
		return MIPS64;
	else if (strncmp(name, "sparc64", strlen("sparc64")) == 0)
		return SPARC64;
	else if (strncmp(name, "RISCV64", strlen("RISCV64")) == 0)
		return RISCV64;
	else if (strncmp(name, "riscv64", strlen("riscv64")) == 0)
		return RISCV64;

	return UNKNOWN;
}

char *
get_extra_flags(char *filename, char *initial)
{
	FILE *fp;
	char inbuf[512];
	char buf[512];

	if (!file_exists(filename))
		return (initial ? initial : NULL);

	if ((fp = fopen(filename, "r")) == NULL) {
		perror(filename);
		return (initial ? initial : NULL);
	}

	if (initial)
		strcpy(buf, initial);
	else
		buf[0] = '\0';

	while (fgets(inbuf, 512, fp)) {
		strip_linefeeds(inbuf);
		strip_beginning_whitespace(inbuf);
		strip_ending_whitespace(inbuf);
		if (inbuf[0] == '#')
			continue;
		if (strlen(inbuf)) {
			if (strlen(buf))
				strcat(buf, " ");			
			strcat(buf, inbuf);
		}
	}

	fclose(fp);

	if (strlen(buf))
		return strdup(buf);
	else 
		return NULL;
}

/*
 *  Add extra compression libraries.  If not already there, create
 *  a CFLAGS.extra file and an LDFLAGS.extra file.

 *  For lzo: 
 *    - enter -DLZO in the CFLAGS.extra file
 *    - enter -llzo2 in the LDFLAGS.extra file
 *
 *  For snappy:
 *    - enter -DSNAPPY in the CFLAGS.extra file
 *    - enter -lsnappy in the LDFLAGS.extra file
 *
 *  For zstd:
 *    - enter -DZSTD in the CFLAGS.extra file
 *    - enter -lzstd in the LDFLAGS.extra file
 *
 *  For valgrind:
 *    - enter -DVALGRIND in the CFLAGS.extra file
 */
void
add_extra_lib(char *option)
{
	int lzo, add_DLZO, add_llzo2; 
	int snappy, add_DSNAPPY, add_lsnappy;
	int zstd, add_DZSTD, add_lzstd;
	int valgrind, add_DVALGRIND;
	char *cflags, *ldflags;
	FILE *fp_cflags, *fp_ldflags;
	char *mode;
	char inbuf[512];

	lzo = add_DLZO = add_llzo2 = 0;
	snappy = add_DSNAPPY = add_lsnappy = 0;
	zstd = add_DZSTD = add_lzstd = 0;
	valgrind = add_DVALGRIND = 0;

	ldflags = get_extra_flags("LDFLAGS.extra", NULL);
	cflags = get_extra_flags("CFLAGS.extra", NULL);

	if (strcmp(option, "lzo") == 0) {
		lzo++;
		if (!cflags || !strstr(cflags, "-DLZO"))
			add_DLZO++;
		if (!ldflags || !strstr(ldflags, "-llzo2"))
			add_llzo2++;
	}

	if (strcmp(option, "snappy") == 0) {
		snappy++;
		if (!cflags || !strstr(cflags, "-DSNAPPY"))
			add_DSNAPPY++;
		if (!ldflags || !strstr(ldflags, "-lsnappy"))
			add_lsnappy++;
	}

	if (strcmp(option, "zstd") == 0) {
		zstd++;
		if (!cflags || !strstr(cflags, "-DZSTD"))
			add_DZSTD++;
		if (!ldflags || !strstr(ldflags, "-lzstd"))
			add_lzstd++;
	}

	if (strcmp(option, "valgrind") == 0) {
		valgrind++;
		if (!cflags || !strstr(cflags, "-DVALGRIND"))
			add_DVALGRIND++;
	}

	if ((lzo || snappy || zstd) &&
	    file_exists("diskdump.o") && (unlink("diskdump.o") < 0)) {
		perror("diskdump.o");
		return;
	} 

	if (valgrind &&
	    file_exists("tools.o") && (unlink("tools.o") < 0)) {
		perror("tools.o");
		return;
	}

	mode = file_exists("CFLAGS.extra") ? "r+" : "w+";
	if ((fp_cflags = fopen("CFLAGS.extra", mode)) == NULL) {
		perror("CFLAGS.extra");
		return;
	}

	mode = file_exists("LDFLAGS.extra") ? "r+" : "w+";
	if ((fp_ldflags = fopen("LDFLAGS.extra", mode)) == NULL) {
		perror("LDFLAGS.extra");
		fclose(fp_cflags);
		return;
	}

	if (add_DLZO || add_DSNAPPY || add_DZSTD || add_DVALGRIND) {
		while (fgets(inbuf, 512, fp_cflags))
			;
		if (add_DLZO)
			fputs("-DLZO\n", fp_cflags);
		if (add_DSNAPPY)
			fputs("-DSNAPPY\n", fp_cflags);
		if (add_DZSTD)
			fputs("-DZSTD\n", fp_cflags);
		if (add_DVALGRIND)
			fputs("-DVALGRIND\n", fp_cflags);
	}

	if (add_llzo2 || add_lsnappy || add_lzstd) {
		while (fgets(inbuf, 512, fp_ldflags))
			;
		if (add_llzo2)
			fputs("-llzo2\n", fp_ldflags);
		if (add_lsnappy)
			fputs("-lsnappy\n", fp_ldflags);
		if (add_lzstd)
			fputs("-lzstd\n", fp_ldflags);
	}

	fclose(fp_cflags);
	fclose(fp_ldflags);
}
