/* defs.h - core analysis suite
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002-2020 David Anderson
 * Copyright (C) 2002-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2002 Silicon Graphics, Inc.
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

#ifndef GDB_COMMON

#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <termios.h>
#include <unistd.h>
#include <sys/mman.h>
#include <setjmp.h>
#undef basename
#if !defined(__USE_GNU)
#define __USE_GNU
#include <string.h>
#undef __USE_GNU
#else
#include <string.h>
#endif
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <assert.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <zlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <execinfo.h> /* backtrace() */
#include <regex.h>
#ifdef LZO
#include <lzo/lzo1x.h>
#endif
#ifdef SNAPPY
#include <snappy-c.h>
#endif
#ifdef ZSTD
#include <zstd.h>
#endif

#ifndef ATTRIBUTE_UNUSED
#define ATTRIBUTE_UNUSED __attribute__ ((__unused__))
#endif

#undef TRUE
#undef FALSE

#define TRUE  (1)
#define FALSE (0)
#define STR(x)	#x
#ifndef offsetof
#  define offsetof(TYPE, MEMBER) ((ulong)&((TYPE *)0)->MEMBER)
#endif

#if !defined(X86) && !defined(X86_64) && !defined(ALPHA) && !defined(PPC) && \
    !defined(IA64) && !defined(PPC64) && !defined(S390) && !defined(S390X) && \
    !defined(ARM) && !defined(ARM64) && !defined(MIPS) && !defined(MIPS64) && \
    !defined(RISCV64) && !defined(SPARC64)
#ifdef __alpha__
#define ALPHA
#endif
#ifdef __i386__
#define X86
#endif
#ifdef __powerpc64__
#define PPC64
#else
#ifdef __powerpc__
#define PPC
#endif
#endif
#ifdef __ia64__
#define IA64
#endif
#ifdef __s390__
#define S390
#endif
#ifdef __s390x__
#define S390X
#endif
#ifdef __x86_64__
#define X86_64
#endif
#ifdef __arm__
#define ARM
#endif
#ifdef __aarch64__
#define ARM64
#endif
#ifdef __mipsel__
#ifndef __mips64
#define MIPS
#else
#define MIPS64
#endif
#endif
#ifdef __sparc_v9__
#define SPARC64
#endif
#if defined(__riscv) && (__riscv_xlen == 64)
#define RISCV64
#endif
#endif

#ifdef X86
#define NR_CPUS  (256)
#endif
#ifdef X86_64
#define NR_CPUS  (8192)
#endif
#ifdef ALPHA
#define NR_CPUS  (64)
#endif
#ifdef PPC
#define NR_CPUS  (32)
#endif
#ifdef IA64
#define NR_CPUS  (4096)
#endif
#ifdef PPC64
#define NR_CPUS  (8192)
#endif
#ifdef S390
#define NR_CPUS  (512)
#endif
#ifdef S390X
#define NR_CPUS  (512)
#endif
#ifdef ARM
#define NR_CPUS  (32)
#endif
#ifdef ARM64
#define NR_CPUS  (4096)   /* TBD */
#endif
#ifdef MIPS
#define NR_CPUS  (32)
#endif
#ifdef MIPS64
#define NR_CPUS  (256)
#endif
#ifdef SPARC64
#define NR_CPUS  (4096)
#endif
#ifdef RISCV64
#define NR_CPUS  (256)
#endif

#define NR_DEVICE_DUMPS (64)

/* Some architectures require memory accesses to be aligned.  */
#if defined(SPARC64)
#define NEED_ALIGNED_MEM_ACCESS
#endif

#define BUFSIZE  (1500)
#define NULLCHAR ('\0')

#define MAXARGS    (100)   /* max number of arguments to one function */
#define MAXARGLEN  (40)   /* max length of argument */

#define HIST_BLKSIZE  (4096)

static inline int string_exists(char *s) { return (s ? TRUE : FALSE); }
#define STREQ(A, B)      (string_exists((char *)A) && string_exists((char *)B) && \
	(strcmp((char *)(A), (char *)(B)) == 0))
#define STRNEQ(A, B)     (string_exists((char *)A) && string_exists((char *)B) && \
        (strncmp((char *)(A), (char *)(B), strlen((char *)(B))) == 0))
#define BZERO(S, N)      (memset(S, NULLCHAR, N))
#define BCOPY(S, D, C)   (memcpy(D, S, C))
#define BNEG(S, N)       (memset(S, 0xff, N))
#define BEEP()           fprintf(stderr, "%c", 0x7)
#define LASTCHAR(s)      (s[strlen(s)-1])
#define FIRSTCHAR(s)     (s[0])
#define QUOTED_STRING(s) ((FIRSTCHAR(s) == '"') && (LASTCHAR(s) == '"'))
#define SINGLE_QUOTED_STRING(s) ((FIRSTCHAR(s) == '\'') && (LASTCHAR(s) == '\''))
#define PATHEQ(A, B)     ((A) && (B) && (pathcmp((char *)(A), (char *)(B)) == 0))

#ifdef roundup
#undef roundup
#endif
#define roundup(x, y)  ((((x)+((y)-1))/(y))*(y))

typedef uint64_t physaddr_t;

#define PADDR_NOT_AVAILABLE (0x1ULL)
#define KCORE_USE_VADDR      (-1ULL)

typedef unsigned long long int ulonglong;
struct number_option {
        ulong num;
        ulonglong ll_num;
	ulong retflags;
};

/*
 *  program_context flags
 */
#define LIVE_SYSTEM                 (0x1ULL)
#define TTY                         (0x2ULL)
#define RUNTIME                     (0x4ULL)
#define IN_FOREACH                  (0x8ULL)
#define MCLXCD                     (0x10ULL)
#define CMDLINE_IFILE              (0x20ULL)
#define MFD_RDWR                   (0x40ULL)
#define KVMDUMP                    (0x80ULL)
#define SILENT                    (0x100ULL)
#define SADUMP                    (0x200ULL)
#define HASH                      (0x400ULL)
#define SCROLL                    (0x800ULL)
#define NO_CONSOLE               (0x1000ULL)
#define RUNTIME_IFILE            (0x2000ULL)
#define DROP_CORE                (0x4000ULL)
#define LKCD                     (0x8000ULL)
#define GDB_INIT                (0x10000ULL)
#define IN_GDB                  (0x20000ULL)
#define RCLOCAL_IFILE           (0x40000ULL)
#define RCHOME_IFILE            (0x80000ULL)
#define VMWARE_VMSS            (0x100000ULL)
#define READLINE               (0x200000ULL) 
#define _SIGINT_               (0x400000ULL)
#define IN_RESTART             (0x800000ULL)
#define KERNEL_DEBUG_QUERY    (0x1000000ULL)
#define DEVMEM                (0x2000000ULL)
#define REM_LIVE_SYSTEM       (0x4000000ULL)
#define NAMELIST_LOCAL        (0x8000000ULL)
#define LIVE_RAMDUMP         (0x10000000ULL)
#define NAMELIST_SAVED       (0x20000000ULL)
#define DUMPFILE_SAVED       (0x40000000ULL)
#define UNLINK_NAMELIST      (0x80000000ULL) 
#define NAMELIST_UNLINKED   (0x100000000ULL)
#define REM_MCLXCD          (0x200000000ULL)
#define REM_LKCD            (0x400000000ULL)
#define NAMELIST_NO_GZIP    (0x800000000ULL)
#define UNLINK_MODULES     (0x1000000000ULL)
#define S390D              (0x2000000000ULL)
#define REM_S390D          (0x4000000000ULL)
#define SYSRQ              (0x8000000000ULL)
#define KDUMP             (0x10000000000ULL)
#define NETDUMP           (0x20000000000ULL)
#define REM_NETDUMP       (0x40000000000ULL)
#define SYSMAP            (0x80000000000ULL)
#define SYSMAP_ARG       (0x100000000000ULL)
#define MEMMOD           (0x200000000000ULL)
#define MODPRELOAD       (0x400000000000ULL)
#define DISKDUMP         (0x800000000000ULL)
#define DATADEBUG       (0x1000000000000ULL)
#define FINDKERNEL      (0x2000000000000ULL)
#define VERSION_QUERY   (0x4000000000000ULL)
#define READNOW         (0x8000000000000ULL)
#define NOCRASHRC      (0x10000000000000ULL)
#define INIT_IFILE     (0x20000000000000ULL)
#define XENDUMP        (0x40000000000000ULL)
#define XEN_HYPER      (0x80000000000000ULL)
#define XEN_CORE      (0x100000000000000ULL)
#define PLEASE_WAIT   (0x200000000000000ULL)
#define IFILE_ERROR   (0x400000000000000ULL)
#define KERNTYPES     (0x800000000000000ULL)
#define MINIMAL_MODE (0x1000000000000000ULL)
#define CRASHBUILTIN (0x2000000000000000ULL)
#define PRELOAD_EXTENSIONS \
		     (0x4000000000000000ULL)
#define PROC_KCORE   (0x8000000000000000ULL)

#define ACTIVE()            (pc->flags & LIVE_SYSTEM)
#define LOCAL_ACTIVE()      ((pc->flags & (LIVE_SYSTEM|LIVE_RAMDUMP)) == LIVE_SYSTEM)
#define DUMPFILE()          (!(pc->flags & LIVE_SYSTEM))
#define LIVE()              (pc->flags2 & LIVE_DUMP || pc->flags & LIVE_SYSTEM)
#define MEMORY_SOURCES (NETDUMP|KDUMP|MCLXCD|LKCD|DEVMEM|S390D|MEMMOD|DISKDUMP|XENDUMP|CRASHBUILTIN|KVMDUMP|PROC_KCORE|SADUMP|VMWARE_VMSS|LIVE_RAMDUMP)
#define DUMPFILE_TYPES      (DISKDUMP|NETDUMP|KDUMP|MCLXCD|LKCD|S390D|XENDUMP|KVMDUMP|SADUMP|VMWARE_VMSS|LIVE_RAMDUMP)
#define REMOTE()            (pc->flags2 & REMOTE_DAEMON)
#define REMOTE_ACTIVE()     (pc->flags & REM_LIVE_SYSTEM) 
#define REMOTE_DUMPFILE() \
	   (pc->flags & (REM_NETDUMP|REM_MCLXCD|REM_LKCD|REM_S390D))
#define REMOTE_MEMSRC()     (REMOTE_ACTIVE() || REMOTE_PAUSED() || REMOTE_DUMPFILE())
#define LKCD_DUMPFILE()     (pc->flags & (LKCD|REM_LKCD))
#define NETDUMP_DUMPFILE()  (pc->flags & (NETDUMP|REM_NETDUMP))
#define DISKDUMP_DUMPFILE() (pc->flags & DISKDUMP)
#define KDUMP_DUMPFILE()    (pc->flags & KDUMP)
#define XENDUMP_DUMPFILE()  (pc->flags & XENDUMP)
#define XEN_HYPER_MODE()    (pc->flags & XEN_HYPER)
#define SYSRQ_TASK(X)       ((pc->flags & SYSRQ) && is_task_active(X))
#define XEN_CORE_DUMPFILE() (pc->flags & XEN_CORE)
#define LKCD_KERNTYPES()    (pc->flags & KERNTYPES)
#define KVMDUMP_DUMPFILE()  (pc->flags & KVMDUMP)
#define SADUMP_DUMPFILE()  (pc->flags & SADUMP)
#define VMSS_DUMPFILE()     (pc->flags & VMWARE_VMSS)
#define QEMU_MEM_DUMP_NO_VMCOREINFO() \
	    ((pc->flags2 & (QEMU_MEM_DUMP_ELF|QEMU_MEM_DUMP_COMPRESSED)) && !(pc->flags2 & VMCOREINFO))


#define NETDUMP_LOCAL    (0x1)  /* netdump_data flags */
#define NETDUMP_REMOTE   (0x2)  
#define VMCORE_VALID()   (nd->flags & (NETDUMP_LOCAL|NETDUMP_REMOTE|KDUMP_LOCAL))
#define NETDUMP_ELF32    (0x4)
#define NETDUMP_ELF64    (0x8)
#define PARTIAL_DUMP    (0x10)  /* netdump or diskdump */
#define KDUMP_ELF32     (0x20)
#define KDUMP_ELF64     (0x40)
#define KDUMP_LOCAL     (0x80)  
#define KCORE_LOCAL    (0x100)     
#define KCORE_ELF32    (0x200)
#define KCORE_ELF64    (0x400)
#define QEMU_MEM_DUMP_KDUMP_BACKUP \
                       (0x800)
#define KVMDUMP_LOCAL    (0x1)
#define KVMDUMP_VALID()  (kvm->flags & (KVMDUMP_LOCAL))

#define DUMPFILE_FORMAT(flags) ((flags) & \
		        (NETDUMP_ELF32|NETDUMP_ELF64|KDUMP_ELF32|KDUMP_ELF64))

#define DISKDUMP_LOCAL      (0x1)
#define KDUMP_CMPRS_LOCAL   (0x2)
#define ERROR_EXCLUDED      (0x4)
#define ZERO_EXCLUDED       (0x8)
#define DUMPFILE_SPLIT      (0x10)
#define NO_ELF_NOTES        (0x20)
#define LZO_SUPPORTED       (0x40)
#define SNAPPY_SUPPORTED    (0x80)
#define ZSTD_SUPPORTED      (0x100)
#define DISKDUMP_VALID()    (dd->flags & DISKDUMP_LOCAL)
#define KDUMP_CMPRS_VALID() (dd->flags & KDUMP_CMPRS_LOCAL)
#define KDUMP_SPLIT()       (dd->flags & DUMPFILE_SPLIT)

#define XENDUMP_LOCAL    (0x1)
#define XENDUMP_VALID()  (xd->flags & XENDUMP_LOCAL)

#define SADUMP_LOCAL   (0x1)
#define SADUMP_DISKSET (0x2)
#define SADUMP_MEDIA   (0x4)
#define SADUMP_ZERO_EXCLUDED (0x8)
#define SADUMP_KDUMP_BACKUP  (0x10)
#define SADUMP_VALID() (sd->flags & SADUMP_LOCAL)

#define CRASHDEBUG(x) (pc->debug >= (x))

#define CRASHDEBUG_SUSPEND(X) { pc->debug_save = pc->debug; pc->debug = X; }
#define CRASHDEBUG_RESTORE()  { pc->debug = pc->debug_save; }

#define VERBOSE (0x1)
#define ADDRESS_SPECIFIED (0x2)

#define FAULT_ON_ERROR   (0x1)
#define RETURN_ON_ERROR  (0x2)
#define QUIET            (0x4)
#define HEX_BIAS         (0x8)
#define LONG_LONG       (0x10)
#define RETURN_PARTIAL  (0x20)
#define NO_DEVMEM_SWITCH (0x40)

#define SEEK_ERROR       (-1)
#define READ_ERROR       (-2)
#define WRITE_ERROR      (-3)
#define PAGE_EXCLUDED    (-4)
#define PAGE_INCOMPLETE  (-5)

#define RESTART()         (longjmp(pc->main_loop_env, 1))
#define RESUME_FOREACH()  (longjmp(pc->foreach_loop_env, 1))

#define INFO           (1)
#define FATAL          (2)
#define FATAL_RESTART  (3)
#define WARNING        (4)
#define NOTE           (5)
#define CONT           (6)
#define FATAL_ERROR(x) (((x) == FATAL) || ((x) == FATAL_RESTART))

#define CONSOLE_OFF(x) ((x) = console_off())
#define CONSOLE_ON(x)  (console_on(x))

#define RADIX(X)   (X)

#define NUM_HEX  (0x1)
#define NUM_DEC  (0x2)
#define NUM_EXPR (0x4)
#define NUM_ANY  (NUM_HEX|NUM_DEC|NUM_EXPR)

/*
 *  program context redirect flags 
 */
#define FROM_COMMAND_LINE        (0x1)
#define FROM_INPUT_FILE          (0x2)
#define REDIRECT_NOT_DONE        (0x4)
#define REDIRECT_TO_PIPE         (0x8)
#define REDIRECT_TO_STDPIPE     (0x10)
#define REDIRECT_TO_FILE        (0x20)
#define REDIRECT_FAILURE        (0x40)
#define REDIRECT_SHELL_ESCAPE   (0x80)
#define REDIRECT_SHELL_COMMAND (0x100)
#define REDIRECT_PID_KNOWN     (0x200)
#define REDIRECT_MULTI_PIPE    (0x400)

#define PIPE_OPTIONS (FROM_COMMAND_LINE | FROM_INPUT_FILE | REDIRECT_TO_PIPE | \
                      REDIRECT_TO_STDPIPE | REDIRECT_TO_FILE)

#define DEFAULT_REDHAT_DEBUG_LOCATION  "/usr/lib/debug/lib/modules"

#define MEMORY_DRIVER_MODULE        "crash"
#define MEMORY_DRIVER_DEVICE        "/dev/crash"
#define MEMORY_DRIVER_DEVICE_MODE   (S_IFCHR|S_IRUSR)

/*
 *  structure definitions
 */
struct program_context {
	char *program_name;             /* this program's name */
	char *program_path;             /* unadulterated argv[0] */
	char *program_version;          /* this program's version */
	char *gdb_version;              /* embedded gdb version */
	char *prompt;                   /* this program's prompt */
	unsigned long long flags;       /* flags from above */
	char *namelist;         	/* linux namelist */
	char *dumpfile;         	/* dumpfile or /dev/kmem */ 
	char *live_memsrc;              /* live memory driver */
	char *system_map;               /* get symbol values from System.map */
	char *namelist_debug;         	/* namelist containing debug data  */
	char *debuginfo_file;           /* separate debuginfo file */
	char *memory_module;            /* alternative to mem.c driver */
	char *memory_device;	        /* alternative to /dev/[k]mem device */
	char *machine_type;             /* machine's processor type */
	char *editing_mode;             /* readline vi or emacs */
	char *server;                   /* network daemon */
	char *server_memsrc;            /* memory source on server */
	char *server_namelist;          /* kernel namelist on server */
	int nfd;             		/* linux namelist fd */
	int mfd;			/* /dev/mem fd */
	int kfd;			/* /dev/kmem fd */
	int dfd;			/* dumpfile fd */
	int confd;			/* console fd */
	int sockfd;                     /* network daemon socket */
	ushort port;                    /* network daemon port */
	int rmfd;                       /* remote server memory source fd */
	int rkfd;                       /* remote server /dev/kmem fd */
	ulong program_pid;              /* program pid */
	ulong server_pid;               /* server pid */
	ulong rcvbufsize;               /* client-side receive buffer size */
	char *home;                     /* user's home directory */
	char command_line[BUFSIZE];     /* possibly parsed input command line */
	char orig_line[BUFSIZE];        /* original input line */
	char *readline;                 /* pointer to last readline() return */
	char my_tty[10];                /* real tty name (shown by ps -ef) */
	ulong debug;                    /* level of debug */
	ulong debug_save;               /* saved level for debug-suspend */
	char *console;                  /* current debug console device */
        char *redhat_debug_loc;         /* location of matching debug objects */
	int pipefd[2];                  /* output pipe file descriptors */
	FILE *nullfp;                   /* bitbucket */
	FILE *stdpipe;                  /* standard pipe for output */
	FILE *pipe;                     /* command line specified pipe */
	FILE *ofile;                    /* command line specified output file */
	FILE *ifile;                    /* command line specified input file */
	FILE *ifile_pipe;               /* output pipe specified from file */
	FILE *ifile_ofile;              /* output file specified from file */
	FILE *symfile;                  /* symbol table data file */
	FILE *symfile2;                 /* alternate access to above */
	FILE *tmpfile;                  /* tmpfile for selective data output */
	FILE *saved_fp;                 /* for printing while parsing tmpfile */
	FILE *tmp_fp;                   /* stored tmpfile pointer */
	char *input_file;               /* input file specified at invocation */
	FILE *tmpfile2;                 /* tmpfile2 does not use save_fp! */
	int eoc_index;                  /* end of redirected command index */
	int scroll_command;             /* default scroll command for output */
#define SCROLL_NONE 0
#define SCROLL_LESS 1
#define SCROLL_MORE 2
#define SCROLL_CRASHPAGER 3
	ulong redirect;			/* per-cmd origin and output flags */
	pid_t stdpipe_pid;              /* per-cmd standard output pipe's pid */
	pid_t pipe_pid;                 /* per-cmd output pipe's pid */
	pid_t pipe_shell_pid;           /* per-cmd output pipe's shell pid */
	char pipe_command[BUFSIZE];     /* pipe command line */
	struct command_table_entry *cmd_table;	/* linux/xen command table */
	char *curcmd;                   /* currently-executing command */
	char *lastcmd;                  /* previously-executed command */
	ulong cmdgencur;		/* current command generation number */
	ulong curcmd_flags;		/* general purpose per-command flag */
#define XEN_MACHINE_ADDR    (0x1)
#define REPEAT              (0x2)
#define IDLE_TASK_SHOWN     (0x4)
#define TASK_SPECIFIED      (0x8)
#define MEMTYPE_UVADDR     (0x10)
#define MEMTYPE_FILEADDR   (0x20)
#define HEADER_PRINTED     (0x40)
#define BAD_INSTRUCTION    (0x80)
#define UD2A_INSTRUCTION  (0x100)
#define IRQ_IN_USE        (0x200)
#define NO_MODIFY         (0x400)
#define IGNORE_ERRORS     (0x800)
#define FROM_RCFILE      (0x1000)
#define MEMTYPE_KVADDR   (0x2000)
#define MOD_SECTIONS     (0x4000)
#define MOD_READNOW      (0x8000)
#define MM_STRUCT_FORCE (0x10000)
#define CPUMASK         (0x20000)
#define PARTIAL_READ_OK (0x40000)
	ulonglong curcmd_private;	/* general purpose per-command info */
	int cur_gdb_cmd;                /* current gdb command */
	int last_gdb_cmd;               /* previously-executed gdb command */
	int sigint_cnt;                 /* number of ignored SIGINTs */
	struct gnu_request *cur_req;    /* current gdb gnu_request */
	struct sigaction sigaction;     /* general usage sigaction. */
	struct sigaction gdb_sigaction; /* gdb's SIGINT sigaction. */
	jmp_buf main_loop_env;          /* longjmp target default */
	jmp_buf foreach_loop_env;       /* longjmp target within foreach */
	struct termios termios_orig;    /* non-raw settings */
	struct termios termios_raw;     /* while gathering command input */
	int ncmds;                      /* number of commands in menu */
	char **cmdlist;                 /* current list of available commands */
	int cmdlistsz;                  /* space available in cmdlist */
	unsigned output_radix;          /* current gdb output_radix */
	void *sbrk;                     /* current sbrk value */
	struct extension_table *curext; /* extension being loaded */
        int (*readmem)(int, void *, int, ulong, physaddr_t); /* memory access */
        int (*writemem)(int, void *, int, ulong, physaddr_t);/* memory access */
	ulong ifile_in_progress;        /* original xxx_IFILE flags */
	off_t ifile_offset;             /* current offset into input file */
	char *runtime_ifile_cmd;        /* runtime command using input file */
	char *kvmdump_mapfile;          /* storage of physical to file offsets */
	ulonglong flags2;               /* flags overrun */
#define FLAT           (0x01ULL)
#define ELF_NOTES      (0x02ULL)
#define GET_OSRELEASE  (0x04ULL)
#define REMOTE_DAEMON  (0x08ULL)
#define ERASEINFO_DATA (0x10ULL)
#define GDB_CMD_MODE   (0x20ULL)
#define LIVE_DUMP      (0x40ULL)
#define FLAT_FORMAT() (pc->flags2 & FLAT)
#define ELF_NOTES_VALID() (pc->flags2 & ELF_NOTES)
#define RADIX_OVERRIDE (0x80ULL)
#define QEMU_MEM_DUMP_ELF (0x100ULL)
#define GET_LOG       (0x200ULL)
#define VMCOREINFO    (0x400ULL)
#define ALLOW_FP      (0x800ULL)
#define REM_PAUSED_F (0x1000ULL)
#define RAMDUMP	     (0x2000ULL)
#define REMOTE_PAUSED() (pc->flags2 & REM_PAUSED_F)
#define OFFLINE_HIDE     (0x4000ULL)
#define INCOMPLETE_DUMP  (0x8000ULL)
#define is_incomplete_dump() (pc->flags2 & INCOMPLETE_DUMP)
#define QEMU_MEM_DUMP_COMPRESSED (0x10000ULL)
#define SNAP        (0x20000ULL)
#define EXCLUDED_VMEMMAP (0x40000ULL)
#define is_excluded_vmemmap() (pc->flags2 & EXCLUDED_VMEMMAP)
#define MEMSRC_LOCAL         (0x80000ULL)
#define REDZONE             (0x100000ULL)
#define VMWARE_VMSS_GUESTDUMP (0x200000ULL)
	char *cleanup;
	char *namelist_orig;
	char *namelist_debug_orig;
	FILE *args_ifile;		/* per-command args input file */
        void (*cmd_cleanup)(void *);    /* per-command cleanup function */
	void *cmd_cleanup_arg;          /* optional cleanup function argument */
	ulong scope;			/* optional text context address */
	ulong nr_hash_queues;		/* hash queue head count */
	char *(*read_vmcoreinfo)(const char *);
	FILE *error_fp;			/* error() message direction */
	char *error_path;		/* stderr path information */
};

#define READMEM  pc->readmem

typedef void (*cmd_func_t)(void);

struct command_table_entry {               /* one for each command in menu */
	char *name;
	cmd_func_t func;
	char **help_data;
	ulong flags;
};

struct args_input_file {
	int index;
	int args_used;
	int is_gdb_cmd;
	int in_expression;
	int start;
	int resume;
	char *fileptr;
};

#define REFRESH_TASK_TABLE (0x1)           /* command_table_entry flags */
#define HIDDEN_COMMAND     (0x2)
#define CLEANUP            (0x4)           /* for extensions only */
#define MINIMAL            (0x8)

/*
 *  A linked list of extension table structures keeps track of the current
 *  set of shared library extensions.
 */
struct extension_table {
	void *handle;				    /* handle from dlopen() */
	char *filename;				    /* name of shared library */
	struct command_table_entry *command_table;  /* list of commands */
	ulong flags;                                /* registration flags */
	struct extension_table *next, *prev;        /* bookkeeping */
};

#define REGISTERED              (0x1)      /* extension_table flags */
#define DUPLICATE_COMMAND_NAME  (0x2)
#define NO_MINIMAL_COMMANDS     (0x4)

struct new_utsname {
        char sysname[65];
        char nodename[65];
        char release[65];
        char version[65];
        char machine[65];
        char domainname[65];
};

#define NO_MODULE_ACCESS (0x1)
#define TVEC_BASES_V1    (0x2)
#define GCC_3_2          (0x4)
#define GCC_3_2_3        (0x8)
#define GCC_2_96        (0x10)
#define RA_SEEK         (0x20)
#define NO_RA_SEEK      (0x40)
#define KALLSYMS_V1     (0x80)
#define NO_KALLSYMS    (0x100)
#define PER_CPU_OFF    (0x200)
#define SMP            (0x400)
#define GCC_3_3_2      (0x800)
#define KMOD_V1       (0x1000)
#define KMOD_V2       (0x2000)
#define KALLSYMS_V2   (0x2000)
#define TVEC_BASES_V2 (0x4000)
#define GCC_3_3_3     (0x8000)
#define USE_OLD_BT   (0x10000)
#define USE_OPT_BT   (0x10000)
#define ARCH_XEN     (0x20000)
#define NO_IKCONFIG  (0x40000)
#define DWARF_UNWIND (0x80000)
#define NO_DWARF_UNWIND       (0x100000)
#define DWARF_UNWIND_MEMORY   (0x200000)
#define DWARF_UNWIND_EH_FRAME (0x400000)
#define DWARF_UNWIND_CAPABLE  (DWARF_UNWIND_MEMORY|DWARF_UNWIND_EH_FRAME)
#define DWARF_UNWIND_MODULES  (0x800000)
#define BUGVERBOSE_OFF       (0x1000000)
#define RELOC_SET            (0x2000000)
#define RELOC_FORCE          (0x4000000)
#define ARCH_OPENVZ          (0x8000000)
#define ARCH_PVOPS          (0x10000000)
#define PRE_KERNEL_INIT     (0x20000000)
#define ARCH_PVOPS_XEN      (0x40000000)

#define GCC_VERSION_DEPRECATED (GCC_3_2|GCC_3_2_3|GCC_2_96|GCC_3_3_2|GCC_3_3_3)

/* flags2 */
#define RELOC_AUTO                  (0x1ULL)
#define KASLR                       (0x2ULL)
#define KASLR_CHECK                 (0x4ULL)
#define GET_TIMESTAMP               (0x8ULL)
#define TVEC_BASES_V3              (0x10ULL)
#define TIMER_BASES                (0x20ULL)
#define IRQ_DESC_TREE_RADIX        (0x40ULL)
#define IRQ_DESC_TREE_XARRAY       (0x80ULL)
#define KMOD_PAX                  (0x100ULL)

#define XEN()       (kt->flags & ARCH_XEN)
#define OPENVZ()    (kt->flags & ARCH_OPENVZ)
#define PVOPS()     (kt->flags & ARCH_PVOPS)
#define PVOPS_XEN() (kt->flags & ARCH_PVOPS_XEN)

#define PAX_MODULE_SPLIT() (kt->flags2 & KMOD_PAX)

#define XEN_MACHINE_TO_MFN(m)    ((ulonglong)(m) >> PAGESHIFT())
#define XEN_PFN_TO_PSEUDO(p)     ((ulonglong)(p) << PAGESHIFT())

#define XEN_MFN_NOT_FOUND        (~0UL)
#define XEN_PFNS_PER_PAGE        (PAGESIZE()/sizeof(ulong))
#define XEN_FOREIGN_FRAME        (1UL << (BITS()-1))

#define XEN_MACHADDR_NOT_FOUND   (~0ULL) 

#define XEN_P2M_PER_PAGE	(PAGESIZE() / sizeof(unsigned long))
#define XEN_P2M_MID_PER_PAGE	(PAGESIZE() / sizeof(unsigned long *))
#define XEN_P2M_TOP_PER_PAGE	(PAGESIZE() / sizeof(unsigned long **))

struct kernel_table {                   /* kernel data */
	ulong flags;
	ulong stext;
	ulong etext;
	ulong stext_init;
	ulong etext_init;
	ulong init_begin;
	ulong init_end;
	ulong end;
	int cpus;
	char *cpus_override;
	void (*display_bh)(void);
        ulong module_list;
        ulong kernel_module;
	int mods_installed;
	struct timespec date;
	char proc_version[BUFSIZE];
	struct new_utsname utsname;
	uint kernel_version[3];
	uint gcc_version[3];
	int runq_siblings;
	int kernel_NR_CPUS;
	long __per_cpu_offset[NR_CPUS];
	long *__rq_idx;
	long *__cpu_idx;
	ulong *cpu_flags;
#define POSSIBLE  (0x1)
#define PRESENT   (0x2)
#define ONLINE    (0x4)
#define NMI       (0x8)
#define POSSIBLE_MAP (POSSIBLE)
#define PRESENT_MAP   (PRESENT)
#define ONLINE_MAP     (ONLINE)
#define ACTIVE_MAP       (0x10)
	int BUG_bytes;
	ulong xen_flags;
#define WRITABLE_PAGE_TABLES    (0x1)
#define SHADOW_PAGE_TABLES      (0x2)
#define CANONICAL_PAGE_TABLES   (0x4)
#define XEN_SUSPEND             (0x8)
	char *m2p_page;
	ulong phys_to_machine_mapping;
	ulong p2m_table_size;
#define P2M_MAPPING_CACHE    (512)
	struct p2m_mapping_cache {
		ulong mapping;
		ulong pfn;
		ulong start;
		ulong end;
	} p2m_mapping_cache[P2M_MAPPING_CACHE];
#define P2M_MAPPING_PAGE_PFN(c) \
   (PVOPS_XEN() ? kt->p2m_mapping_cache[c].pfn : \
    (((kt->p2m_mapping_cache[c].mapping - kt->phys_to_machine_mapping)/PAGESIZE()) \
    * XEN_PFNS_PER_PAGE))
	ulong last_mapping_read;
	ulong p2m_cache_index;
	ulong p2m_pages_searched;
	ulong p2m_mfn_cache_hits;
	ulong p2m_page_cache_hits;
	ulong relocate;
	char *module_tree;
	struct pvops_xen_info {
		int p2m_top_entries;
		ulong p2m_top;
		ulong p2m_mid_missing;
		ulong p2m_missing;
	} pvops_xen;
	int highest_irq;
#define IKCONFIG_AVAIL	0x1	/* kernel contains ikconfig data */
#define IKCONFIG_LOADED	0x2	/* ikconfig data is currently loaded */
	int ikconfig_flags;
	int ikconfig_ents;
	char *hypervisor;
	struct vmcoreinfo_data {
		ulong log_buf_SYMBOL;
		ulong log_end_SYMBOL;
		ulong log_buf_len_SYMBOL;
		ulong logged_chars_SYMBOL;
		ulong log_first_idx_SYMBOL;
		ulong log_next_idx_SYMBOL;
		long log_SIZE;
		long log_ts_nsec_OFFSET;
		long log_len_OFFSET;
		long log_text_len_OFFSET;
		long log_dict_len_OFFSET;
		ulong phys_base_SYMBOL;
		ulong _stext_SYMBOL;
	} vmcoreinfo;
	ulonglong flags2;
	char *source_tree;
	struct timespec boot_date;
};

/*
 * Aid for the two versions of the kernel's module list linkage.
 */
#define NEXT_MODULE(next_module, modbuf)                             \
{                                                                    \
        switch (kt->flags & (KMOD_V1|KMOD_V2))                       \
        {                                                            \
        case KMOD_V1:                                                \
                next_module = ULONG(modbuf + OFFSET(module_next));   \
                break;                                               \
        case KMOD_V2:                                                \
                next_module = ULONG(modbuf + OFFSET(module_list));   \
                if (next_module != kt->kernel_module)                \
                        next_module -= OFFSET(module_list);          \
                break;                                               \
        }                                                            \
}

#define THIS_KERNEL_VERSION ((kt->kernel_version[0] << 16) + \
			     (kt->kernel_version[1] << 8) + \
			     (kt->kernel_version[2]))
#define LINUX(x,y,z) (((uint)(x) << 16) + ((uint)(y) << 8) + (uint)(z))

#define THIS_GCC_VERSION    ((kt->gcc_version[0] << 16) + \
                             (kt->gcc_version[1] << 8) + \
                             (kt->gcc_version[2]))
#define GCC(x,y,z) (((uint)(x) << 16) + ((uint)(y) << 8) + (uint)(z))

#define IS_KERNEL_STATIC_TEXT(x) (((ulong)(x) >= kt->stext) && \
		  	          ((ulong)(x) < kt->etext))

#define TASK_COMM_LEN 16     /* task command name length including NULL */

struct task_context {                     /* context stored for each task */
        ulong task;
	ulong thread_info;
        ulong pid;
        char comm[TASK_COMM_LEN+1];
	int processor;
	ulong ptask;
	ulong mm_struct;
	struct task_context *tc_next;
};

struct tgid_context {               /* tgid and task stored for each task */
	ulong tgid;
	ulong task;
	long rss_cache;
};

struct task_table {                      /* kernel/local task table data */
	struct task_context *current;
	struct task_context *context_array;
	void (*refresh_task_table)(void);
	ulong flags;
        ulong task_start;
	ulong task_end;
	void *task_local;
        int max_tasks;
	int nr_threads;
	ulong running_tasks;
	ulong retries;
        ulong panicmsg;
        int panic_processor;
        ulong *idle_threads;
        ulong *panic_threads;
	ulong *active_set;
	ulong *panic_ksp;
	ulong *hardirq_ctx;
	ulong *hardirq_tasks;
	ulong *softirq_ctx;
	ulong *softirq_tasks;
        ulong panic_task;
	ulong this_task;
	int pidhash_len;
	ulong pidhash_addr;
	ulong last_task_read;
	ulong last_thread_info_read;
	ulong last_mm_read;
	char *task_struct;
	char *thread_info;
	char *mm_struct;
	ulong init_pid_ns;
	struct tgid_context *tgid_array;
	struct tgid_context *last_tgid;
	ulong tgid_searches;
	ulong tgid_cache_hits;
	long filepages;
	long anonpages;
	ulong stack_end_magic;
	ulong pf_kthread;
	ulong pid_radix_tree;
	int callbacks;
	struct task_context **context_by_task; /* task_context sorted by task addr */
	ulong pid_xarray;
};

#define TASK_INIT_DONE       (0x1)
#define TASK_ARRAY_EXISTS    (0x2)
#define PANIC_TASK_NOT_FOUND (0x4)
#define TASK_REFRESH         (0x8)
#define TASK_REFRESH_OFF    (0x10)
#define PANIC_KSP           (0x20)
#define ACTIVE_SET          (0x40)
#define POPULATE_PANIC      (0x80)
#define PIDHASH            (0x100)
#define PID_HASH           (0x200)
#define THREAD_INFO        (0x400)
#define IRQSTACKS          (0x800)
#define TIMESPEC          (0x1000)
#define NO_TIMESPEC       (0x2000)
#define ACTIVE_ONLY       (0x4000)
#define START_TIME_NSECS  (0x8000)
#define THREAD_INFO_IN_TASK (0x10000)
#define PID_RADIX_TREE   (0x20000)
#define INDEXED_CONTEXTS (0x40000)
#define PID_XARRAY       (0x80000)

#define TASK_SLUSH (20)

#define NO_PROC_ID 0xFF       /* No processor magic marker (from kernel) */

/*
 *  Global "tt" points to task_table
 */
#define CURRENT_CONTEXT() (tt->current)
#define CURRENT_TASK()    (tt->current->task)
#define CURRENT_PID()     (tt->current->pid)
#define CURRENT_COMM()    (tt->current->comm)
#define RUNNING_TASKS()   (tt->running_tasks)
#define FIRST_CONTEXT()   (tt->context_array)

#define NO_PID   ((ulong)-1)
#define NO_TASK  (0)

#define IS_TASK_ADDR(X)    (machdep->is_task_addr(X))
#define GET_STACKBASE(X)   (machdep->get_stackbase(X))
#define GET_STACKTOP(X)    (machdep->get_stacktop(X))
#define STACKSIZE()        (machdep->stacksize)
#define LONGS_PER_STACK    (machdep->stacksize/sizeof(ulong))

#define INSTACK(X,BT) \
        (((ulong)(X) >= (BT)->stackbase) && ((ulong)(X) < (BT)->stacktop))

#define ALIGNED_STACK_OFFSET(task)  ((ulong)(task) & (STACKSIZE()-1))

#define BITS()		   (machdep->bits)
#define BITS32()           (machdep->bits == 32)
#define BITS64()           (machdep->bits == 64)
#define IS_KVADDR(X)       (machdep->is_kvaddr(X))
#define IS_UVADDR(X,C)     (machdep->is_uvaddr(X,C))

#define PID_ALIVE(x) (kill(x, 0) == 0)

struct kernel_list_head {
        struct kernel_list_head *next, *prev;
};

struct stack_hook {
        ulong esp;
        ulong eip;
};

struct bt_info {
        ulong task;
        ulonglong flags;
        ulong instptr;
        ulong stkptr;
	ulong bptr;
	ulong stackbase;
	ulong stacktop;
	char *stackbuf;
	struct task_context *tc;
        struct stack_hook *hp;
        struct stack_hook *textlist;
        struct reference *ref;
	ulong frameptr;
	char *call_target;
	void *machdep;
        ulong debug;
	ulong eframe_ip;
	ulong radix;
	ulong *cpumask;
};

#define STACK_OFFSET_TYPE(OFF) \
  (((ulong)(OFF) > STACKSIZE()) ? \
  (ulong)((ulong)(OFF) - (ulong)(bt->stackbase)) : (ulong)(OFF)) 

#define GET_STACK_ULONG(OFF) \
 *((ulong *)((char *)(&bt->stackbuf[(ulong)(STACK_OFFSET_TYPE(OFF))])))

#define GET_STACK_DATA(OFF, LOC, SZ) memcpy((void *)(LOC), \
    (void *)(&bt->stackbuf[(ulong)STACK_OFFSET_TYPE(OFF)]), (size_t)(SZ))

struct machine_specific;  /* uniquely defined below each machine's area */
struct xendump_data;
struct xen_kdump_data;

struct vaddr_range {
	ulong start;
	ulong end;
	ulong type;
#define KVADDR_UNITY_MAP  (1) 
#define KVADDR_VMALLOC    (2)
#define KVADDR_VMEMMAP    (3)
#define KVADDR_START_MAP  (4)
#define KVADDR_MODULES    (5)
#define MAX_KVADDR_RANGES KVADDR_MODULES
};

#define MAX_MACHDEP_ARGS 5  /* for --machdep/-m machine-specific args */

struct machdep_table {
	ulong flags;
	ulong kvbase;
	ulong identity_map_base;
	uint pagesize;
	uint pageshift;
	ulonglong pagemask;
	ulong pageoffset;
	ulong stacksize;
	uint hz;
	ulong mhz;
	int bits;
	int nr_irqs;
	uint64_t memsize;
        int (*eframe_search)(struct bt_info *);
        void (*back_trace)(struct bt_info *);
        ulong (*processor_speed)(void);
        int (*uvtop)(struct task_context *, ulong, physaddr_t *, int);
        int (*kvtop)(struct task_context *, ulong, physaddr_t *, int);
        ulong (*get_task_pgd)(ulong);
	void (*dump_irq)(int);
	void (*get_stack_frame)(struct bt_info *, ulong *, ulong *);
	ulong (*get_stackbase)(ulong);
	ulong (*get_stacktop)(ulong);
	int (*translate_pte)(ulong, void *, ulonglong);
	uint64_t (*memory_size)(void);
	ulong (*vmalloc_start)(void);
        int (*is_task_addr)(ulong);
	int (*verify_symbol)(const char *, ulong, char);
	int (*dis_filter)(ulong, char *, unsigned int);
	int (*get_smp_cpus)(void);
        int (*is_kvaddr)(ulong);
        int (*is_uvaddr)(ulong, struct task_context *);
	int (*verify_paddr)(uint64_t);
	void (*cmd_mach)(void);
	void (*init_kernel_pgd)(void);
	struct syment *(*value_to_symbol)(ulong, ulong *);
 	struct line_number_hook {
        	char *func;
        	char **file;
	} *line_number_hooks;
	ulong last_pgd_read;
	ulong last_pud_read;
	ulong last_pmd_read;
	ulong last_ptbl_read;
	char *pgd;
	char *pud;
 	char *pmd;	
	char *ptbl;
	int ptrs_per_pgd;
	char *cmdline_args[MAX_MACHDEP_ARGS];
	struct machine_specific *machspec;
	ulong section_size_bits;
	ulong max_physmem_bits;
	ulong sections_per_root;
	int (*xendump_p2m_create)(struct xendump_data *);
	ulong (*xendump_panic_task)(struct xendump_data *);
	void (*get_xendump_regs)(struct xendump_data *, struct bt_info *, ulong *, ulong *);
	void (*clear_machdep_cache)(void);
	int (*xen_kdump_p2m_create)(struct xen_kdump_data *);
	int (*in_alternate_stack)(int, ulong);
	void (*dumpfile_init)(int, void *);
	void (*process_elf_notes)(void *, unsigned long);
	int (*get_kvaddr_ranges)(struct vaddr_range *);
        int (*verify_line_number)(ulong, ulong, ulong);
        void (*get_irq_affinity)(int);
        void (*show_interrupts)(int, ulong *);
	int (*is_page_ptr)(ulong, physaddr_t *);
	int (*get_cpu_reg)(int, int, const char *, int, void *);
};

/*
 *  Processor-common flags;  processor-specific flags use the lower bits
 *  as defined in their processor-specific files below. (see KSYMS_START defs).
 */
#define HWRESET         (0x80000000)
#define OMIT_FRAME_PTR  (0x40000000)
#define FRAMESIZE_DEBUG (0x20000000)
#define MACHDEP_BT_TEXT (0x10000000)
#define DEVMEMRD         (0x8000000)
#define INIT             (0x4000000)
#define VM_4_LEVEL       (0x2000000)
#define MCA              (0x1000000)
#define PAE               (0x800000)
#define VMEMMAP           (0x400000)

extern struct machdep_table *machdep;

#ifndef HZ
#define HZ sysconf(_SC_CLK_TCK)
#endif

#define IS_LAST_PGD_READ(pgd)     ((ulong)(pgd) == machdep->last_pgd_read)
#define IS_LAST_PMD_READ(pmd)     ((ulong)(pmd) == machdep->last_pmd_read)
#define IS_LAST_PTBL_READ(ptbl)   ((ulong)(ptbl) == machdep->last_ptbl_read)
#define IS_LAST_PUD_READ(pud)     ((ulong)(pud) == machdep->last_pud_read)

#define FILL_PGD(PGD, TYPE, SIZE) 					    \
    if (!IS_LAST_PGD_READ(PGD)) {                                           \
            readmem((ulonglong)((ulong)(PGD)), TYPE, machdep->pgd,          \
                    SIZE, "pgd page", FAULT_ON_ERROR);                      \
            machdep->last_pgd_read = (ulong)(PGD);                          \
    }

#define FILL_PUD(PUD, TYPE, SIZE) 					    \
    if (!IS_LAST_PUD_READ(PUD)) {                                           \
            readmem((ulonglong)((ulong)(PUD)), TYPE, machdep->pud,          \
                    SIZE, "pud page", FAULT_ON_ERROR);                      \
            machdep->last_pud_read = (ulong)(PUD);                          \
    }

#define FILL_PMD(PMD, TYPE, SIZE)			                    \
    if (!IS_LAST_PMD_READ(PMD)) {                                           \
            readmem((ulonglong)(PMD), TYPE, machdep->pmd,                   \
	            SIZE, "pmd page", FAULT_ON_ERROR);                      \
            machdep->last_pmd_read = (ulong)(PMD);                          \
    }

#define FILL_PTBL(PTBL, TYPE, SIZE)			           	    \
    if (!IS_LAST_PTBL_READ(PTBL)) {                                         \
    	    readmem((ulonglong)(PTBL), TYPE, machdep->ptbl,                 \
	            SIZE, "page table", FAULT_ON_ERROR);                    \
            machdep->last_ptbl_read = (ulong)(PTBL); 	                    \
    }

#define SETUP_ENV  (0)
#define PRE_SYMTAB (1)
#define PRE_GDB    (2)
#define POST_GDB   (3)
#define POST_INIT  (4)
#define POST_VM    (5)
#define LOG_ONLY   (6)
#define POST_RELOC (7)

#define FOREACH_BT     (1)
#define FOREACH_VM     (2)
#define FOREACH_TASK   (3)
#define FOREACH_SET    (4)
#define FOREACH_FILES  (5)
#define FOREACH_NET    (6)
#define FOREACH_TEST   (7)
#define FOREACH_VTOP   (8)
#define FOREACH_SIG    (9)
#define FOREACH_PS    (10)

#define MAX_FOREACH_KEYWORDS (10)
#define MAX_FOREACH_TASKS    (50)
#define MAX_FOREACH_PIDS     (50)
#define MAX_FOREACH_COMMS    (50)
#define MAX_FOREACH_ARGS     (50)
#define MAX_REGEX_ARGS       (10)

#define FOREACH_CMD            (0x1)
#define FOREACH_r_FLAG         (0x2)
#define FOREACH_s_FLAG         (0x4)
#define FOREACH_S_FLAG         (0x8)
#define FOREACH_i_FLAG        (0x10)
#define FOREACH_e_FLAG        (0x20)
#define FOREACH_g_FLAG        (0x40)
#define FOREACH_l_FLAG        (0x80)
#define FOREACH_p_FLAG       (0x100)
#define FOREACH_t_FLAG       (0x200)
#define FOREACH_u_FLAG       (0x400)
#define FOREACH_m_FLAG       (0x800)
#define FOREACH_v_FLAG      (0x1000)
#define FOREACH_KERNEL      (0x2000)
#define FOREACH_USER        (0x4000)
#define FOREACH_SPECIFIED   (0x8000)
#define FOREACH_ACTIVE     (0x10000)
#define FOREACH_k_FLAG     (0x20000)
#define FOREACH_c_FLAG     (0x40000)
#define FOREACH_f_FLAG     (0x80000)
#define FOREACH_o_FLAG    (0x100000)
#define FOREACH_T_FLAG    (0x200000)
#define FOREACH_F_FLAG    (0x400000)
#define FOREACH_x_FLAG    (0x800000)
#define FOREACH_d_FLAG   (0x1000000)
#define FOREACH_STATE    (0x2000000)
#define FOREACH_a_FLAG   (0x4000000)
#define FOREACH_G_FLAG   (0x8000000)
#define FOREACH_F_FLAG2 (0x10000000)
#define FOREACH_y_FLAG  (0x20000000)
#define FOREACH_GLEADER (0x40000000)

#define FOREACH_PS_EXCLUSIVE \
  (FOREACH_g_FLAG|FOREACH_a_FLAG|FOREACH_t_FLAG|FOREACH_c_FLAG|FOREACH_p_FLAG|FOREACH_l_FLAG|FOREACH_r_FLAG|FOREACH_m_FLAG)

struct foreach_data {
	ulong flags;
        int keyword_array[MAX_FOREACH_KEYWORDS];
        ulong task_array[MAX_FOREACH_TASKS];
        char *comm_array[MAX_FOREACH_COMMS];
        ulong pid_array[MAX_FOREACH_PIDS];
	ulong arg_array[MAX_FOREACH_ARGS];
	struct regex_info {
		char *pattern;
		regex_t regex;
	} regex_info[MAX_REGEX_ARGS];
	ulong state;
	char *reference;
	int keys;
	int pids;
	int tasks;
	int comms;
	int args;
	int regexs;
	int policy;
};

struct reference {       
        char *str;       
        ulong cmdflags;  
        ulong hexval;     
        ulong decval;     
        ulong ref1;
        ulong ref2;
	void *refp;
};

struct offset_table {                    /* stash of commonly-used offsets */
	long list_head_next;             /* add new entries to end of table */
	long list_head_prev;
	long task_struct_pid;
	long task_struct_state;
	long task_struct_comm;
	long task_struct_mm;
	long task_struct_tss;
	long task_struct_thread;
	long task_struct_active_mm;
	long task_struct_tss_eip;
	long task_struct_tss_esp;
	long task_struct_tss_ksp;
	long task_struct_processor;
	long task_struct_p_pptr;
	long task_struct_parent;
	long task_struct_has_cpu;
	long task_struct_cpus_runnable;
	long task_struct_thread_eip;
	long task_struct_thread_esp;
	long task_struct_thread_ksp;
	long task_struct_next_task;
	long task_struct_files;
	long task_struct_fs;
	long task_struct_pidhash_next;
	long task_struct_next_run;
	long task_struct_flags;
	long task_struct_sig;
	long task_struct_signal;
	long task_struct_blocked;
	long task_struct_sigpending;
	long task_struct_pending;
	long task_struct_sigqueue;
	long task_struct_sighand;
	long task_struct_start_time;
	long task_struct_times;
	long task_struct_utime;
	long task_struct_stime;
	long task_struct_cpu;
	long task_struct_run_list;
        long task_struct_pgrp;
        long task_struct_tgid;
	long task_struct_namespace;
	long task_struct_pids;
	long task_struct_last_run;
	long task_struct_timestamp;
	long task_struct_thread_info;
	long task_struct_nsproxy;
	long task_struct_rlim;
	long thread_info_task;
	long thread_info_cpu;
	long thread_info_previous_esp;
	long thread_info_flags;
	long nsproxy_mnt_ns;
	long mnt_namespace_root;
	long mnt_namespace_list;
	long pid_link_pid;
	long pid_hash_chain;
	long hlist_node_next;
	long hlist_node_pprev;
	long pid_pid_chain;
	long thread_struct_eip;
	long thread_struct_esp;
	long thread_struct_ksp;
	long thread_struct_fph;
	long thread_struct_rip;
	long thread_struct_rsp;
	long thread_struct_rsp0;
	long tms_tms_utime;
	long tms_tms_stime;
	long signal_struct_count;
	long signal_struct_action;
	long signal_struct_shared_pending;
	long signal_struct_rlim;
	long k_sigaction_sa;
	long sigaction_sa_handler;
	long sigaction_sa_flags;
	long sigaction_sa_mask;
	long sigpending_head;
	long sigpending_list;
	long sigpending_signal;
	long signal_queue_next;
	long signal_queue_info;
	long sigqueue_next;
	long sigqueue_list;
	long sigqueue_info;
	long sighand_struct_action;
	long siginfo_si_signo;
	long thread_struct_cr3;
	long thread_struct_ptbr;
	long thread_struct_pg_tables;
	long switch_stack_r26;
	long switch_stack_b0;
	long switch_stack_ar_bspstore;
	long switch_stack_ar_pfs;
	long switch_stack_ar_rnat;
	long switch_stack_pr;
	long cpuinfo_ia64_proc_freq;
	long cpuinfo_ia64_unimpl_va_mask;
	long cpuinfo_ia64_unimpl_pa_mask;
	long device_node_type;
	long device_node_allnext;
	long device_node_properties;
	long property_name;
	long property_value;
	long property_next;
	long machdep_calls_setup_residual;
	long RESIDUAL_VitalProductData;
	long VPD_ProcessorHz;
	long bd_info_bi_intfreq;
	long hwrpb_struct_cycle_freq;
	long hwrpb_struct_processor_offset;
	long hwrpb_struct_processor_size;
	long percpu_struct_halt_PC;
	long percpu_struct_halt_ra;
	long percpu_struct_halt_pv;
	long mm_struct_mmap;
	long mm_struct_pgd;
	long mm_struct_rss;
	long mm_struct_anon_rss;
	long mm_struct_file_rss;
	long mm_struct_total_vm;
	long mm_struct_start_code;
	long mm_struct_arg_start;
	long mm_struct_arg_end;
	long mm_struct_env_start;
	long mm_struct_env_end;
        long vm_area_struct_vm_mm;
        long vm_area_struct_vm_next;
        long vm_area_struct_vm_end;
        long vm_area_struct_vm_start; 
	long vm_area_struct_vm_flags;
	long vm_area_struct_vm_file;
	long vm_area_struct_vm_offset;
	long vm_area_struct_vm_pgoff;
        long vm_struct_addr;
        long vm_struct_size;
        long vm_struct_next;
	long module_size_of_struct;
	long module_next;
	long module_size;
	long module_name;
	long module_nsyms;
	long module_syms;
	long module_flags;
	long module_num_syms;
	long module_list;
	long module_gpl_syms;
	long module_num_gpl_syms;
	long module_module_core;
	long module_core_size;
	long module_core_text_size;
	long module_num_symtab;
	long module_symtab;
	long module_strtab;

	long module_kallsyms_start;
	long kallsyms_header_sections;
	long kallsyms_header_section_off;
	long kallsyms_header_symbols;
	long kallsyms_header_symbol_off;
	long kallsyms_header_string_off;
	long kallsyms_symbol_section_off;
	long kallsyms_symbol_symbol_addr;
	long kallsyms_symbol_name_off;
	long kallsyms_section_start;
	long kallsyms_section_size;
	long kallsyms_section_name_off;

	long page_next;
	long page_prev;
	long page_next_hash;
	long page_list;
	long page_list_next;
	long page_list_prev;
	long page_inode;
	long page_offset;
	long page_count;
	long page_flags;
	long page_mapping;
	long page_index;
	long page_buffers;
	long page_lru;
	long page_pte;
	long swap_info_struct_swap_file;
	long swap_info_struct_swap_vfsmnt;
	long swap_info_struct_flags;
	long swap_info_struct_swap_map;
	long swap_info_struct_swap_device;
	long swap_info_struct_prio;
	long swap_info_struct_max;
	long swap_info_struct_pages;
	long swap_info_struct_old_block_size;
	long block_device_bd_inode;
	long block_device_bd_list;
	long block_device_bd_disk;
	long irq_desc_t_status;
	long irq_desc_t_handler;
	long irq_desc_t_chip;
	long irq_desc_t_action;
	long irq_desc_t_depth;
	long irqdesc_action;
	long irqdesc_ctl;
	long irqdesc_level;
	long irqaction_handler;
	long irqaction_flags;
	long irqaction_mask;
	long irqaction_name;
	long irqaction_dev_id;
	long irqaction_next;
	long hw_interrupt_type_typename;
	long hw_interrupt_type_startup;
	long hw_interrupt_type_shutdown;
	long hw_interrupt_type_handle;
	long hw_interrupt_type_enable;
	long hw_interrupt_type_disable;
	long hw_interrupt_type_ack;
	long hw_interrupt_type_end;
	long hw_interrupt_type_set_affinity;
	long irq_chip_typename;
	long irq_chip_startup;
	long irq_chip_shutdown;
	long irq_chip_enable;
	long irq_chip_disable;
	long irq_chip_ack;
	long irq_chip_end;
	long irq_chip_set_affinity;
	long irq_chip_mask;
	long irq_chip_mask_ack;
	long irq_chip_unmask;
	long irq_chip_eoi;
	long irq_chip_retrigger;
	long irq_chip_set_type;
	long irq_chip_set_wake;
	long irq_cpustat_t___softirq_active;
	long irq_cpustat_t___softirq_mask;
	long fdtable_max_fds;
	long fdtable_max_fdset;
	long fdtable_open_fds;
	long fdtable_fd;
	long files_struct_fdt;
        long files_struct_max_fds;
        long files_struct_max_fdset;
        long files_struct_open_fds;
        long files_struct_fd;
	long files_struct_open_fds_init;
        long file_f_dentry;
        long file_f_vfsmnt;
        long file_f_count;
	long file_f_path;
	long path_mnt;
	long path_dentry;
        long fs_struct_root;
        long fs_struct_pwd;
        long fs_struct_rootmnt;
        long fs_struct_pwdmnt;
        long dentry_d_inode;
        long dentry_d_parent;
        long dentry_d_name;
	long dentry_d_covers;
	long dentry_d_iname;
        long qstr_len;
        long qstr_name;
        long inode_i_mode;
        long inode_i_op;
        long inode_i_sb;
	long inode_u;
	long inode_i_flock;
	long inode_i_fop;
	long inode_i_mapping;
	long address_space_nrpages;
	long vfsmount_mnt_next;
	long vfsmount_mnt_devname;
	long vfsmount_mnt_dirname;
	long vfsmount_mnt_sb;
	long vfsmount_mnt_list;
	long vfsmount_mnt_mountpoint;
	long vfsmount_mnt_parent;
	long namespace_root;
	long namespace_list;
	long super_block_s_dirty;
	long super_block_s_type;
	long super_block_s_files;
	long file_system_type_name;
	long nlm_file_f_file;
	long file_lock_fl_owner;
	long nlm_host_h_exportent;
	long svc_client_cl_ident;
	long kmem_cache_s_c_nextp;
	long kmem_cache_s_c_name;
	long kmem_cache_s_c_num;
	long kmem_cache_s_c_org_size;
	long kmem_cache_s_c_flags;
	long kmem_cache_s_c_offset;
	long kmem_cache_s_c_firstp;
	long kmem_cache_s_c_gfporder;
	long kmem_cache_s_c_magic;
	long kmem_cache_s_num;
	long kmem_cache_s_next;
	long kmem_cache_s_name;
	long kmem_cache_s_objsize;
	long kmem_cache_s_flags;
	long kmem_cache_s_gfporder;
	long kmem_cache_s_slabs;
	long kmem_cache_s_slabs_full;
	long kmem_cache_s_slabs_partial;
	long kmem_cache_s_slabs_free;
	long kmem_cache_s_cpudata;
	long kmem_cache_s_c_align;
	long kmem_cache_s_colour_off;
	long cpucache_s_avail;
	long cpucache_s_limit;
	long kmem_cache_s_array;
	long array_cache_avail;
	long array_cache_limit;
	long kmem_cache_s_lists;
	long kmem_list3_slabs_partial;
	long kmem_list3_slabs_full;
	long kmem_list3_slabs_free;
	long kmem_list3_free_objects;
	long kmem_list3_shared;
	long kmem_slab_s_s_nextp;
	long kmem_slab_s_s_freep;
	long kmem_slab_s_s_inuse;
	long kmem_slab_s_s_mem;
	long kmem_slab_s_s_index;
	long kmem_slab_s_s_offset;
	long kmem_slab_s_s_magic;
	long slab_s_list;
	long slab_s_s_mem;
	long slab_s_inuse;
	long slab_s_free;
        long slab_list;
        long slab_s_mem;
        long slab_inuse;
        long slab_free;
	long net_device_next;
	long net_device_name;
	long net_device_type;
	long net_device_addr_len;
	long net_device_ip_ptr;
	long net_device_dev_list;
	long net_dev_base_head;
	long device_next;
	long device_name;
	long device_type;
	long device_ip_ptr;
	long device_addr_len;
	long socket_sk;
	long sock_daddr;
	long sock_rcv_saddr;
	long sock_dport;
	long sock_sport;
	long sock_num;
	long sock_type;
	long sock_family;
	long sock_common_skc_family;
	long sock_sk_type;
	long inet_sock_inet;
	long inet_opt_daddr;
	long inet_opt_rcv_saddr;
	long inet_opt_dport;
	long inet_opt_sport;
	long inet_opt_num;
	long ipv6_pinfo_rcv_saddr;
	long ipv6_pinfo_daddr;
	long timer_list_list;
	long timer_list_next;
	long timer_list_entry;
	long timer_list_expires;
	long timer_list_function;
	long timer_vec_root_vec;
	long timer_vec_vec;
	long tvec_root_s_vec;
	long tvec_s_vec;
	long tvec_t_base_s_tv1;
 	long wait_queue_task;
 	long wait_queue_next;
 	long __wait_queue_task;
	long __wait_queue_head_task_list;
 	long __wait_queue_task_list;
	long pglist_data_node_zones;
	long pglist_data_node_mem_map;
	long pglist_data_node_start_paddr;
        long pglist_data_node_start_mapnr;
        long pglist_data_node_size;
        long pglist_data_node_id;
        long pglist_data_node_next;
	long pglist_data_nr_zones;
	long pglist_data_node_start_pfn;
	long pglist_data_pgdat_next;
	long pglist_data_node_present_pages;
	long pglist_data_node_spanned_pages;
	long pglist_data_bdata;
	long page_cache_bucket_chain;
        long zone_struct_free_pages;
        long zone_struct_free_area;
        long zone_struct_zone_pgdat;
        long zone_struct_name;
        long zone_struct_size;
	long zone_struct_memsize;
	long zone_struct_zone_start_pfn;
        long zone_struct_zone_start_paddr;
        long zone_struct_zone_start_mapnr;
        long zone_struct_zone_mem_map;
	long zone_struct_inactive_clean_pages;
	long zone_struct_inactive_clean_list;
	long zone_struct_inactive_dirty_pages;
	long zone_struct_active_pages;
	long zone_struct_pages_min;
	long zone_struct_pages_low;
	long zone_struct_pages_high;
	long zone_free_pages;
	long zone_free_area;
        long zone_zone_pgdat;
	long zone_zone_mem_map;
        long zone_name;
	long zone_spanned_pages;
	long zone_zone_start_pfn;
	long zone_pages_min;
	long zone_pages_low;
	long zone_pages_high;
	long zone_vm_stat;
        long neighbour_next;
        long neighbour_primary_key;
        long neighbour_ha;
        long neighbour_dev;
        long neighbour_nud_state;
	long neigh_table_hash_buckets;
	long neigh_table_key_len;
        long in_device_ifa_list;
        long in_ifaddr_ifa_next;
        long in_ifaddr_ifa_address;
	long pci_dev_global_list;
	long pci_dev_next;
	long pci_dev_bus;
	long pci_dev_devfn;
	long pci_dev_class;
	long pci_dev_device;
	long pci_dev_vendor;
	long pci_bus_number;
        long resource_entry_t_from;
        long resource_entry_t_num;
        long resource_entry_t_name; 
        long resource_entry_t_next;
        long resource_name;
        long resource_start;
        long resource_end;
        long resource_sibling;
        long resource_child;
	long runqueue_curr;
	long runqueue_idle;
	long runqueue_active;
	long runqueue_expired;
	long runqueue_arrays;
	long runqueue_cpu;
	long cpu_s_idle;
	long cpu_s_curr;
	long prio_array_nr_active;
	long prio_array_queue;
	long user_regs_struct_ebp;
	long user_regs_struct_esp;
	long user_regs_struct_rip;
	long user_regs_struct_cs;
	long user_regs_struct_eflags;
	long user_regs_struct_rsp;
	long user_regs_struct_ss;
	long e820map_nr_map;
	long e820entry_addr;	
	long e820entry_size;	
	long e820entry_type;	
	long char_device_struct_next;
	long char_device_struct_name;
	long char_device_struct_fops;
	long char_device_struct_major;
	long gendisk_major;
	long gendisk_disk_name;
	long gendisk_fops;
	long blk_major_name_next;
	long blk_major_name_major;
	long blk_major_name_name;
	long radix_tree_root_height;
	long radix_tree_root_rnode;
	long x8664_pda_pcurrent;
	long x8664_pda_data_offset;
	long x8664_pda_kernelstack;
	long x8664_pda_irqrsp;
	long x8664_pda_irqstackptr;
	long x8664_pda_level4_pgt;
	long x8664_pda_cpunumber;
	long x8664_pda_me;
	long tss_struct_ist;
	long mem_section_section_mem_map;
	long vcpu_guest_context_user_regs;
	long cpu_user_regs_eip;
	long cpu_user_regs_esp;
	long cpu_user_regs_rip;
	long cpu_user_regs_rsp;
        long unwind_table_core;
        long unwind_table_init;
        long unwind_table_address;
        long unwind_table_size;
        long unwind_table_link;
        long unwind_table_name;
	long rq_cfs;
	long rq_rt;
	long rq_nr_running;
	long cfs_rq_rb_leftmost;
	long cfs_rq_nr_running;
	long cfs_rq_tasks_timeline;
	long task_struct_se;
	long sched_entity_run_node;
	long rt_rq_active;
	long kmem_cache_size;
	long kmem_cache_objsize;
	long kmem_cache_offset;
	long kmem_cache_order;
	long kmem_cache_local_node;
	long kmem_cache_objects;
	long kmem_cache_inuse;
	long kmem_cache_align;
	long kmem_cache_name;
	long kmem_cache_list;
	long kmem_cache_node;
	long kmem_cache_cpu_slab;
	long page_inuse;
/*	long page_offset;  use "old" page->offset */
	long page_slab;
	long page_first_page;
	long page_freelist;
	long kmem_cache_node_nr_partial;
	long kmem_cache_node_nr_slabs;
	long kmem_cache_node_partial;
	long kmem_cache_node_full;
	long pid_numbers;
	long upid_nr;
	long upid_ns;
	long upid_pid_chain;
	long pid_tasks;
        long kmem_cache_cpu_freelist;
        long kmem_cache_cpu_page;
        long kmem_cache_cpu_node;
	long kmem_cache_flags;
	long zone_nr_active;
	long zone_nr_inactive;
	long zone_all_unreclaimable;
	long zone_present_pages;
	long zone_flags;
	long zone_pages_scanned;
	long pcpu_info_vcpu;
	long pcpu_info_idle;
	long vcpu_struct_rq;
	long task_struct_sched_info;
	long sched_info_last_arrival;
	long page_objects;
	long kmem_cache_oo;
	long char_device_struct_cdev;
	long char_device_struct_baseminor;
	long cdev_ops;
	long probe_next;
	long probe_dev;
	long probe_data;
	long kobj_map_probes;
	long task_struct_prio;
	long zone_watermark;
	long module_sect_attrs;
	long module_sect_attrs_attrs;
	long module_sect_attrs_nsections;
	long module_sect_attr_mattr;
	long module_sect_attr_name;
	long module_sect_attr_address;
	long module_attribute_attr;
	long attribute_owner;
	long module_sect_attr_attr;
	long module_sections_attrs;
	long swap_info_struct_inuse_pages;
	long s390_lowcore_psw_save_area;
	long mm_struct_rss_stat;
	long mm_rss_stat_count;
	long module_module_init;
	long module_init_text_size;
	long cpu_context_save_fp;
	long cpu_context_save_sp;
	long cpu_context_save_pc;
	long elf_prstatus_pr_pid;
	long elf_prstatus_pr_reg;
	long irq_desc_t_name;
	long thread_info_cpu_context;
	long unwind_table_list;
	long unwind_table_start;
	long unwind_table_stop;
	long unwind_table_begin_addr;
	long unwind_table_end_addr;
	long unwind_idx_addr;
	long unwind_idx_insn;
	long signal_struct_nr_threads;
	long module_init_size;
	long module_percpu;
	long radix_tree_node_slots;
	long s390_stack_frame_back_chain;
	long s390_stack_frame_r14;
	long user_regs_struct_eip;
	long user_regs_struct_rax;
	long user_regs_struct_eax;
	long user_regs_struct_rbx;
	long user_regs_struct_ebx;
	long user_regs_struct_rcx;
	long user_regs_struct_ecx;
	long user_regs_struct_rdx;
	long user_regs_struct_edx;
	long user_regs_struct_rsi;
	long user_regs_struct_esi;
	long user_regs_struct_rdi;
	long user_regs_struct_edi;
	long user_regs_struct_ds;
	long user_regs_struct_es;
	long user_regs_struct_fs;
	long user_regs_struct_gs;
	long user_regs_struct_rbp;
	long user_regs_struct_r8;
	long user_regs_struct_r9;
	long user_regs_struct_r10;
	long user_regs_struct_r11;
	long user_regs_struct_r12;
	long user_regs_struct_r13;
	long user_regs_struct_r14;
	long user_regs_struct_r15;
	long sched_entity_cfs_rq;
	long sched_entity_my_q;
	long sched_entity_on_rq;
	long task_struct_on_rq;
	long cfs_rq_curr;
	long irq_desc_t_irq_data;
	long irq_desc_t_kstat_irqs;
	long irq_desc_t_affinity;
	long irq_data_chip;
	long irq_data_affinity;
	long kernel_stat_irqs;
	long socket_alloc_vfs_inode;
	long class_devices;
	long class_p;
	long class_private_devices;
	long device_knode_class;
	long device_node;
	long gendisk_dev;
	long gendisk_kobj;
	long gendisk_part0;
	long gendisk_queue;
	long hd_struct_dev;
	long klist_k_list;
	long klist_node_n_klist;
	long klist_node_n_node;
	long kobject_entry;
	long kset_list;
	long request_list_count;
	long request_queue_in_flight;
	long request_queue_rq;
	long subsys_private_klist_devices;
	long subsystem_kset;
	long mount_mnt_parent;
	long mount_mnt_mountpoint;
	long mount_mnt_list;
	long mount_mnt_devname;
	long mount_mnt;
	long task_struct_exit_state;
	long timekeeper_xtime;
	long file_f_op;
	long file_private_data;
	long hstate_order;
	long hugetlbfs_sb_info_hstate;
	long idr_layer_ary;
	long idr_layer_layer;
	long idr_layers;
	long idr_top;
	long ipc_id_ary_p;
	long ipc_ids_entries;
	long ipc_ids_max_id;
	long ipc_ids_ipcs_idr;
	long ipc_ids_in_use;
	long ipc_namespace_ids;
	long kern_ipc_perm_deleted;
	long kern_ipc_perm_key;
	long kern_ipc_perm_mode;
	long kern_ipc_perm_uid;
	long kern_ipc_perm_id;
	long kern_ipc_perm_seq;
	long nsproxy_ipc_ns;
	long shmem_inode_info_swapped;
	long shmem_inode_info_vfs_inode;
	long shm_file_data_file;
	long shmid_kernel_shm_file;
	long shmid_kernel_shm_nattch;
	long shmid_kernel_shm_perm;
	long shmid_kernel_shm_segsz;
	long shmid_kernel_id;
	long sem_array_sem_perm;
	long sem_array_sem_id;
	long sem_array_sem_nsems;
	long msg_queue_q_perm;
	long msg_queue_q_id;
	long msg_queue_q_cbytes;
	long msg_queue_q_qnum;
	long super_block_s_fs_info;
	long rq_timestamp;
	long radix_tree_node_height;
	long rb_root_rb_node;
	long rb_node_rb_left;
	long rb_node_rb_right;
	long rt_prio_array_queue;
	long task_struct_rt;
	long sched_rt_entity_run_list;
	long log_ts_nsec;
	long log_len;
	long log_text_len;
	long log_dict_len;
	long log_level;
	long log_flags_level;
	long timekeeper_xtime_sec;
	long neigh_table_hash_mask;
	long sched_rt_entity_my_q;
	long neigh_table_hash_shift;
	long neigh_table_nht_ptr;
	long task_group_parent;
	long task_group_css;
	long cgroup_subsys_state_cgroup;
	long cgroup_dentry;
	long task_group_rt_rq;
	long rt_rq_tg;
	long task_group_cfs_rq;
	long cfs_rq_tg;
	long task_group_siblings;
	long task_group_children;
	long task_group_cfs_bandwidth;
	long cfs_rq_throttled;
	long task_group_rt_bandwidth;
	long rt_rq_rt_throttled;
	long rt_rq_highest_prio;
	long rt_rq_rt_nr_running;
	long vmap_area_va_start;
	long vmap_area_va_end;
	long vmap_area_list;
	long vmap_area_flags;
	long vmap_area_vm;
	long hrtimer_cpu_base_clock_base;
	long hrtimer_clock_base_offset;
	long hrtimer_clock_base_active;
	long hrtimer_clock_base_first;
	long hrtimer_clock_base_get_time;
	long hrtimer_base_first;
	long hrtimer_base_pending;
	long hrtimer_base_get_time;
	long hrtimer_node;
	long hrtimer_list;
	long hrtimer_softexpires;
	long hrtimer_expires;
	long hrtimer_function;
	long timerqueue_head_next;
	long timerqueue_node_expires;
	long timerqueue_node_node;
	long ktime_t_tv64;
	long ktime_t_sec;
	long ktime_t_nsec;
	long module_taints;
	long module_gpgsig_ok;
	long module_license_gplok;
	long tnt_bit;
	long tnt_true;
	long tnt_false;
	long task_struct_thread_context_fp;
	long task_struct_thread_context_sp;
	long task_struct_thread_context_pc;
	long page_slab_page;
	long trace_print_flags_mask;
	long trace_print_flags_name;
	long task_struct_rss_stat;
	long task_rss_stat_count;
	long page_s_mem;
	long page_active;
	long hstate_nr_huge_pages;
	long hstate_free_huge_pages;
	long hstate_name;
	long cgroup_kn;
	long kernfs_node_name;
	long kernfs_node_parent;
	long kmem_cache_cpu_partial;
	long kmem_cache_cpu_cache;
	long nsproxy_net_ns;
	long atomic_t_counter;
	long percpu_counter_count;
	long mm_struct_mm_count;
	long task_struct_thread_reg29;
	long task_struct_thread_reg31;
	long pt_regs_regs;
	long pt_regs_cp0_badvaddr;
	long address_space_page_tree;
	long page_compound_head;
	long irq_desc_irq_data;
	long kmem_cache_node_total_objects;
	long timer_base_vectors;
	long request_queue_mq_ops;
	long request_queue_queue_ctx;
	long blk_mq_ctx_rq_dispatched;
	long blk_mq_ctx_rq_completed;
	long task_struct_stack;
	long tnt_mod;
	long radix_tree_node_shift;
	long kmem_cache_red_left_pad;
	long inactive_task_frame_ret_addr;
	long sk_buff_head_next;
	long sk_buff_head_qlen;
	long sk_buff_next;
	long sk_buff_len;
	long sk_buff_data;
	long nlmsghdr_nlmsg_type;
	long module_arch;
	long mod_arch_specific_num_orcs;
	long mod_arch_specific_orc_unwind_ip;
	long mod_arch_specific_orc_unwind;
	long task_struct_policy;
	long kmem_cache_random;
	long pid_namespace_idr;
	long idr_idr_rt;
	long bpf_prog_aux;
	long bpf_prog_type;
	long bpf_prog_tag;
	long bpf_prog_jited_len;
	long bpf_prog_bpf_func;
	long bpf_prog_len;
	long bpf_prog_insnsi;
	long bpf_prog_pages;
	long bpf_map_map_type;
	long bpf_map_map_flags;
	long bpf_map_pages;
	long bpf_map_key_size;
	long bpf_map_value_size;
	long bpf_map_max_entries;
	long bpf_map_user;
	long bpf_map_name;
	long bpf_prog_aux_used_map_cnt;
	long bpf_prog_aux_used_maps;
	long bpf_prog_aux_load_time;
	long bpf_prog_aux_user;
	long user_struct_uid;
	long idr_cur;
	long kmem_cache_memcg_params;
	long memcg_cache_params___root_caches_node;
	long memcg_cache_params_children;
	long memcg_cache_params_children_node;
	long task_struct_pid_links;
	long kernel_symbol_value;
	long pci_dev_dev;
        long pci_dev_hdr_type;
        long pci_dev_pcie_flags_reg;
        long pci_bus_node;
        long pci_bus_devices;
        long pci_bus_dev;
        long pci_bus_children;
        long pci_bus_parent;
        long pci_bus_self;
	long device_kobj;
	long kobject_name;
	long memory_block_dev;
	long memory_block_start_section_nr;
	long memory_block_end_section_nr;
	long memory_block_state;
	long memory_block_nid;
	long mem_section_pageblock_flags;
	long bus_type_p;
	long device_private_device;
	long device_private_knode_bus;
	long xarray_xa_head;
	long xa_node_slots;
	long xa_node_shift;
	long hd_struct_dkstats;
	long disk_stats_in_flight;
	long cpu_context_save_r7;
	long dentry_d_sb;
	long device_private_knode_class;
	long timerqueue_head_rb_root;
	long rb_root_cached_rb_leftmost;
	long bpf_map_memory;
	long bpf_map_memory_pages;
	long bpf_map_memory_user;
	long bpf_prog_aux_name;
	long page_private;
	long swap_info_struct_bdev;
	long zram_mempoll;
	long zram_compressor;
	long zram_table_flag;
	long zspoll_size_class;
	long size_class_size;
	long gendisk_private_data;
	long zram_table_entry;
	long module_core_size_rw;
	long module_core_size_rx;
	long module_init_size_rw;
	long module_init_size_rx;
	long module_module_core_rw;
	long module_module_core_rx;
	long module_module_init_rw;
	long module_module_init_rx;
	long super_block_s_inodes;
	long inode_i_sb_list;
	long irq_common_data_affinity;
	long irq_desc_irq_common_data;
	long uts_namespace_name;
	long printk_info_seq;
	long printk_info_ts_nsec;
	long printk_info_text_len;
	long printk_info_level;
	long printk_info_caller_id;
	long printk_info_dev_info;
	long dev_printk_info_subsystem;
	long dev_printk_info_device;
	long prb_desc_ring;
	long prb_text_data_ring;
	long prb_desc_ring_count_bits;
	long prb_desc_ring_descs;
	long prb_desc_ring_infos;
	long prb_desc_ring_head_id;
	long prb_desc_ring_tail_id;
	long prb_desc_state_var;
	long prb_desc_text_blk_lpos;
	long prb_data_blk_lpos_begin;
	long prb_data_blk_lpos_next;
	long prb_data_ring_size_bits;
	long prb_data_ring_data;
	long atomic_long_t_counter;
	long block_device_bd_device;
	long block_device_bd_stats;
	long wait_queue_entry_private;
	long wait_queue_head_head;
	long wait_queue_entry_entry;
	long printk_safe_seq_buf_len;
	long printk_safe_seq_buf_message_lost;
	long printk_safe_seq_buf_buffer;
	long sbitmap_word_depth;
	long sbitmap_word_word;
	long sbitmap_word_cleared;
	long sbitmap_depth;
	long sbitmap_shift;
	long sbitmap_map_nr;
	long sbitmap_map;
	long sbitmap_queue_sb;
	long sbitmap_queue_alloc_hint;
	long sbitmap_queue_wake_batch;
	long sbitmap_queue_wake_index;
	long sbitmap_queue_ws;
	long sbitmap_queue_ws_active;
	long sbitmap_queue_round_robin;
	long sbitmap_queue_min_shallow_depth;
	long sbq_wait_state_wait_cnt;
	long sbq_wait_state_wait;
	long sbitmap_alloc_hint;
	long sbitmap_round_robin;
	long request_cmd_flags;
	long request_q;
	long request_state;
	long request_queue_queue_hw_ctx;
	long request_queue_nr_hw_queues;
	long blk_mq_hw_ctx_tags;
	long blk_mq_tags_bitmap_tags;
	long blk_mq_tags_breserved_tags;
	long blk_mq_tags_nr_reserved_tags;
	long blk_mq_tags_rqs;
	long request_queue_hctx_table;
	long percpu_counter_counters;
	long slab_slab_list;
	long mm_struct_mm_mt;
	long maple_tree_ma_root;
	long maple_tree_ma_flags;
	long maple_node_parent;
	long maple_node_ma64;
	long maple_node_mr64;
	long maple_node_slot;
	long maple_arange_64_pivot;
	long maple_arange_64_slot;
	long maple_arange_64_gap;
	long maple_arange_64_meta;
	long maple_range_64_pivot;
	long maple_range_64_slot;
	long maple_metadata_end;
	long maple_metadata_gap;
	long sock_sk_common;
	long sock_common_skc_v6_daddr;
	long sock_common_skc_v6_rcv_saddr;
	long inactive_task_frame_bp;
};

struct size_table {         /* stash of commonly-used sizes */
	long page;
	long free_area_struct;
	long zone_struct;
	long free_area;
	long zone;
	long kmem_slab_s;
	long kmem_cache_s;
	long kmem_bufctl_t;
	long slab_s;
	long slab;
	long cpucache_s;
	long array_cache;
	long swap_info_struct;
	long mm_struct;
	long vm_area_struct;
	long pglist_data;
	long page_cache_bucket;
	long pt_regs;
	long task_struct;
	long thread_info;
	long softirq_state;
	long desc_struct;
	long umode_t;
	long dentry;
	long files_struct;
	long fdtable;
	long fs_struct;
	long file;
	long inode;
	long vfsmount;
	long super_block;
        long irqdesc;
	long module;
	long list_head;
	long hlist_node;
	long hlist_head;
	long irq_cpustat_t;
	long cpuinfo_x86;
	long cpuinfo_ia64;
	long timer_list;
	long timer_vec_root;
	long timer_vec;
	long tvec_root_s;
	long tvec_s;
	long tvec_t_base_s;
	long wait_queue;
	long __wait_queue;
	long device;
	long net_device;
	long sock;
	long signal_struct;
	long sigpending_signal;
	long signal_queue;
	long sighand_struct;
	long sigqueue;
	long k_sigaction;
	long resource_entry_t;
	long resource;
	long runqueue;
	long irq_desc_t;
	long task_union;
	long thread_union;
	long prio_array;
	long user_regs_struct;
	long switch_stack;
	long vm_area_struct_vm_flags;
	long e820map;
	long e820entry;
	long cpu_s;
	long pgd_t;
	long kallsyms_header;
	long kallsyms_symbol;
	long kallsyms_section;
	long irq_ctx;
	long block_device;
	long blk_major_name;
	long gendisk;
	long address_space;
	long char_device_struct;
	long inet_sock;
	long in6_addr;
	long socket;
	long spinlock_t;
	long radix_tree_root;
	long radix_tree_node;
	long x8664_pda;
	long ppc64_paca;
	long gate_struct;
	long tss_struct;
	long task_struct_start_time;
	long cputime_t;
	long mem_section;
	long pid_link;
	long unwind_table;
	long rlimit;
	long kmem_cache;
	long kmem_cache_node;
	long upid;
	long kmem_cache_cpu;
	long cfs_rq;
	long pcpu_info;
	long vcpu_struct;
	long cdev;
	long probe;
	long kobj_map;
	long page_flags;
	long module_sect_attr;
	long task_struct_utime;
	long task_struct_stime;
	long cpu_context_save;
	long elf_prstatus;
	long note_buf;
	long unwind_idx;
	long softirq_action;
	long irq_data;
	long s390_stack_frame;
	long percpu_data;
	long sched_entity;
	long kernel_stat;
	long subsystem;
	long class_private;
	long rq_in_flight;
	long class_private_devices;
	long mount;
	long hstate;
	long ipc_ids;
	long shmid_kernel;
	long sem_array;
	long msg_queue;
	long log;
	long log_level;
	long rt_rq;
	long task_group;
	long vmap_area;
	long hrtimer_clock_base;
	long hrtimer_base;
	long tnt;
	long trace_print_flags;
	long task_struct_flags;
	long timer_base;
	long taint_flag;
	long nlmsghdr;
	long nlmsghdr_nlmsg_type;
	long sk_buff_head_qlen;
	long sk_buff_len;
	long orc_entry;
	long task_struct_policy;
	long pid;
	long bpf_prog;
	long bpf_prog_aux;
	long bpf_map;
	long bpf_insn;
	long xarray;
	long xa_node;
	long zram_table_entry;
	long irq_common_data;
	long printk_info;
	long printk_ringbuffer;
	long prb_desc;
	long wait_queue_entry;
	long task_struct_state;
	long printk_safe_seq_buf_buffer;
	long sbitmap_word;
	long sbitmap;
	long sbitmap_queue;
	long sbq_wait_state;
	long blk_mq_tags;
	long percpu_counter;
	long maple_tree;
	long maple_node;
};

struct array_table {
	int kmem_cache_s_name;
	int kmem_cache_s_c_name;
	int kmem_cache_s_array;
	int kmem_cache_s_cpudata;
	int irq_desc;
	int irq_action;
	int log_buf;
	int timer_vec_vec;
	int timer_vec_root_vec;
	int tvec_s_vec;
	int tvec_root_s_vec;
	int page_hash_table;
	int net_device_name;
	int neigh_table_hash_buckets;
	int neighbour_ha;
	int swap_info;
        int pglist_data_node_zones;
        int zone_struct_free_area;
        int zone_free_area;
	int free_area;
	int free_area_DIMENSION;
	int prio_array_queue;
	int height_to_maxindex;
	int pid_hash;
	int kmem_cache_node;
	int kmem_cache_cpu_slab;
	int rt_prio_array_queue;
	int height_to_maxnodes;
	int task_struct_rlim;
	int signal_struct_rlim;
	int vm_numa_stat;
};

/*
 *  The following set of macros use gdb to determine structure, union,
 *  or member sizes/offsets.  They should be used only during initialization
 *  of the offset_table or size_table, or with data structures whose names
 *  or members are only known/specified during runtime.
 */
#define MEMBER_SIZE_REQUEST ((struct datatype_member *)(-1))
#define ANON_MEMBER_OFFSET_REQUEST ((struct datatype_member *)(-2))
#define MEMBER_TYPE_REQUEST ((struct datatype_member *)(-3))
#define STRUCT_SIZE_REQUEST ((struct datatype_member *)(-4))
#define MEMBER_TYPE_NAME_REQUEST ((struct datatype_member *)(-5))
#define ANON_MEMBER_SIZE_REQUEST ((struct datatype_member *)(-6))

#define STRUCT_SIZE(X)      datatype_info((X), NULL, STRUCT_SIZE_REQUEST)
#define UNION_SIZE(X)       datatype_info((X), NULL, STRUCT_SIZE_REQUEST)
#define STRUCT_EXISTS(X)    (datatype_info((X), NULL, STRUCT_SIZE_REQUEST) >= 0)
#define DATATYPE_SIZE(X)    datatype_info((X)->name, NULL, (X))
#define MEMBER_OFFSET(X,Y)  datatype_info((X), (Y), NULL)
#define MEMBER_EXISTS(X,Y)  (datatype_info((X), (Y), NULL) >= 0)
#define MEMBER_SIZE(X,Y)    datatype_info((X), (Y), MEMBER_SIZE_REQUEST)
#define MEMBER_TYPE(X,Y)    datatype_info((X), (Y), MEMBER_TYPE_REQUEST)
#define MEMBER_TYPE_NAME(X,Y)    ((char *)datatype_info((X), (Y), MEMBER_TYPE_NAME_REQUEST))
#define ANON_MEMBER_OFFSET(X,Y)    datatype_info((X), (Y), ANON_MEMBER_OFFSET_REQUEST)
#define ANON_MEMBER_SIZE(X,Y)    datatype_info((X), (Y), ANON_MEMBER_SIZE_REQUEST)

/*
 *  The following set of macros can only be used with pre-intialized fields
 *  in the offset table, size table or array_table.
 */
#define OFFSET(X)	   (OFFSET_verify(offset_table.X, (char *)__FUNCTION__, __FILE__, __LINE__, #X))
#define MODULE_OFFSET(X,Y) (PAX_MODULE_SPLIT() ? OFFSET(Y) : OFFSET(X))
#define MODULE_OFFSET2(X,T) MODULE_OFFSET(X, X##_##T)
#define SIZE(X)            (SIZE_verify(size_table.X, (char *)__FUNCTION__, __FILE__, __LINE__, #X))
#define INVALID_OFFSET     (-1)
#define INVALID_MEMBER(X)  (offset_table.X == INVALID_OFFSET)
#define INVALID_SIZE(X)    (size_table.X == -1)
#define VALID_SIZE(X)      (size_table.X >= 0)
#define VALID_STRUCT(X)    (size_table.X >= 0)
#define VALID_MEMBER(X)    (offset_table.X >= 0)
#define ARRAY_LENGTH(X)    (array_table.X)
#define ASSIGN_OFFSET(X)   (offset_table.X)
#define ASSIGN_SIZE(X)     (size_table.X)
#define OFFSET_OPTION(X,Y) (OFFSET_option(offset_table.X, offset_table.Y, (char *)__FUNCTION__, __FILE__, __LINE__, #X, #Y))
#define SIZE_OPTION(X,Y)   (SIZE_option(size_table.X, size_table.Y, (char *)__FUNCTION__, __FILE__, __LINE__, #X, #Y))

#define MEMBER_OFFSET_INIT(X, Y, Z) (ASSIGN_OFFSET(X) = MEMBER_OFFSET(Y, Z))
#define STRUCT_SIZE_INIT(X, Y) (ASSIGN_SIZE(X) = STRUCT_SIZE(Y))
#define ARRAY_LENGTH_INIT(A, B, C, D, E) ((A) = get_array_length(C, D, E))
#define ARRAY_LENGTH_INIT_ALT(A, B, C, D, E) ((A) = get_array_length_alt(B, C, D, E))
#define MEMBER_SIZE_INIT(X, Y, Z) (ASSIGN_SIZE(X) = MEMBER_SIZE(Y, Z))
#define ANON_MEMBER_OFFSET_INIT(X, Y, Z) (ASSIGN_OFFSET(X) = ANON_MEMBER_OFFSET(Y, Z))

/*
 *  For use with non-debug kernels.
 */
struct builtin_debug_table {
        char *release;
	char *machine_type;
        struct offset_table *offset_table;
        struct size_table *size_table;
        struct array_table *array_table;
};

/*
 *  Facilitators for pulling correctly-sized data out of a buffer at a
 *  known address. 
 */

#ifdef NEED_ALIGNED_MEM_ACCESS

#define DEF_LOADER(TYPE)			\
static inline TYPE				\
load_##TYPE (char *addr)			\
{						\
	TYPE ret;				\
	size_t i = sizeof(TYPE);		\
	while (i--)				\
		((char *)&ret)[i] = addr[i];	\
	return ret;				\
}

DEF_LOADER(int);
DEF_LOADER(uint);
DEF_LOADER(long);
DEF_LOADER(ulong);
DEF_LOADER(ulonglong);
DEF_LOADER(ushort);
DEF_LOADER(short);
typedef void *pointer_t;
DEF_LOADER(pointer_t);
DEF_LOADER(bool);

#define LOADER(TYPE) load_##TYPE

#define INT(ADDR)       LOADER(int) ((char *)(ADDR))
#define UINT(ADDR)      LOADER(uint) ((char *)(ADDR))
#define LONG(ADDR)      LOADER(long) ((char *)(ADDR))
#define ULONG(ADDR)     LOADER(ulong) ((char *)(ADDR))
#define ULONGLONG(ADDR) LOADER(ulonglong) ((char *)(ADDR))
#define ULONG_PTR(ADDR) ((ulong *) (LOADER(pointer_t) ((char *)(ADDR))))
#define USHORT(ADDR)    LOADER(ushort) ((char *)(ADDR))
#define SHORT(ADDR)     LOADER(short) ((char *)(ADDR))
#define UCHAR(ADDR)     *((unsigned char *)((char *)(ADDR)))
#define VOID_PTR(ADDR)  ((void *) (LOADER(pointer_t) ((char *)(ADDR))))
#define BOOL(ADDR)      LOADER(bool) ((char *)(ADDR)))

#else

#define INT(ADDR)       *((int *)((char *)(ADDR)))
#define UINT(ADDR)      *((uint *)((char *)(ADDR)))
#define LONG(ADDR)      *((long *)((char *)(ADDR)))
#define ULONG(ADDR)     *((ulong *)((char *)(ADDR)))
#define ULONGLONG(ADDR) *((ulonglong *)((char *)(ADDR)))
#define ULONG_PTR(ADDR) *((ulong **)((char *)(ADDR)))
#define USHORT(ADDR)    *((ushort *)((char *)(ADDR)))
#define SHORT(ADDR)     *((short *)((char *)(ADDR)))
#define UCHAR(ADDR)     *((unsigned char *)((char *)(ADDR)))
#define VOID_PTR(ADDR)  *((void **)((char *)(ADDR)))
#define BOOL(ADDR)      *((bool *)((char *)(ADDR)))

#endif /* NEED_ALIGNED_MEM_ACCESS */

struct node_table {
	int node_id;
	ulong pgdat;
	ulong mem_map;
	ulong size;
	ulong present;
	ulonglong start_paddr;
	ulong start_mapnr;
};

struct meminfo;
struct slab_data;

#define VMA_CACHE   (20)

struct vm_table {                /* kernel VM-related data */
	ulong flags;
	ulong kernel_pgd[NR_CPUS];
	ulong high_memory;
	ulong vmalloc_start;
	ulong mem_map;
	long total_pages;
	ulong totalram_pages;
	ulong totalhigh_pages;
	ulong num_physpages;
	ulong max_mapnr;
	ulong kmem_max_c_num;
	ulong kmem_max_limit;
	ulong kmem_max_cpus;
	ulong kmem_cache_count;
	ulong kmem_cache_len_nodes;
	ulong PG_reserved;
	ulong PG_slab;
	ulong PG_head_tail_mask;
	int kmem_cache_namelen;
	ulong page_hash_table;
	int page_hash_table_len;
	int paddr_prlen;
	int numnodes;
	int nr_zones;
	int nr_free_areas;
	struct node_table *node_table;
        void (*dump_free_pages)(struct meminfo *);
	void (*dump_kmem_cache)(struct meminfo *);
	struct slab_data *slab_data;
	uint nr_swapfiles;
	ulong last_swap_read;
	char *swap_info_struct;
        char *vma_cache;
        ulong cached_vma[VMA_CACHE];
        ulong cached_vma_hits[VMA_CACHE];
        int vma_cache_index;
        ulong vma_cache_fills;
	void *mem_sec;
	char *mem_section;
	int ZONE_HIGHMEM;
	ulong *node_online_map;
	int node_online_map_len;
	int nr_vm_stat_items;
	char **vm_stat_items;
	int cpu_slab_type;
	int nr_vm_event_items;
	char **vm_event_items;
	int nr_bad_slab_caches;
	ulong *bad_slab_caches;
	int nr_pageflags;
	struct pageflags_data {
		ulong mask;
		char *name;
	} *pageflags_data;
	ulong max_mem_section_nr;
};

#define NODES                       (0x1)
#define ZONES                       (0x2)
#define PERCPU_KMALLOC_V1           (0x4)
#define COMMON_VADDR                (0x8)
#define KMEM_CACHE_INIT            (0x10)
#define V_MEM_MAP                  (0x20)
#define PERCPU_KMALLOC_V2          (0x40)
#define KMEM_CACHE_UNAVAIL         (0x80)
#define FLATMEM			  (0x100)
#define DISCONTIGMEM		  (0x200)
#define SPARSEMEM		  (0x400)
#define SPARSEMEM_EX		  (0x800)
#define PERCPU_KMALLOC_V2_NODES  (0x1000)
#define KMEM_CACHE_DELAY         (0x2000)
#define NODES_ONLINE             (0x4000)
#define VM_STAT                  (0x8000)
#define KMALLOC_SLUB            (0x10000)
#define CONFIG_NUMA             (0x20000)
#define VM_EVENT                (0x40000)
#define PGCNT_ADJ               (0x80000)
#define VM_INIT                (0x100000)
#define SWAPINFO_V1            (0x200000)
#define SWAPINFO_V2            (0x400000)
#define NODELISTS_IS_PTR       (0x800000)
#define KMALLOC_COMMON        (0x1000000)
#define USE_VMAP_AREA         (0x2000000)
#define PAGEFLAGS             (0x4000000)
#define SLAB_OVERLOAD_PAGE    (0x8000000)
#define SLAB_CPU_CACHE       (0x10000000)
#define SLAB_ROOT_CACHES     (0x20000000)
#define FREELIST_PTR_BSWAP   (0x40000000)

#define IS_FLATMEM()		(vt->flags & FLATMEM)
#define IS_DISCONTIGMEM()	(vt->flags & DISCONTIGMEM)
#define IS_SPARSEMEM()		(vt->flags & SPARSEMEM)
#define IS_SPARSEMEM_EX()	(vt->flags & SPARSEMEM_EX)

#define COMMON_VADDR_SPACE() (vt->flags & COMMON_VADDR)
#define PADDR_PRLEN          (vt->paddr_prlen)

struct datatype_member {        /* minimal definition of a structure/union */
	char *name;             /* and possibly a member within it */
	char *member;
	ulong type;
	long size;
	long member_offset;
	long member_size;
	int member_typecode;
	ulong flags;
	const char *tagname;         /* tagname and value for enums */
	long value;
	ulong vaddr;
};

#define union_name struct_name

struct list_data {             /* generic structure used by do_list() to walk */
        ulong flags;           /* through linked lists in the kernel */
        ulong start;
        long member_offset;
	long list_head_offset;
        ulong end;
	ulong searchfor;
	char **structname;
	int structname_args;
	char *header;
	ulong *list_ptr;
	int (*callback_func)(void *, void *); 
	void *callback_data;
	long struct_list_offset;
};
#define LIST_OFFSET_ENTERED  (VERBOSE << 1)
#define LIST_START_ENTERED   (VERBOSE << 2)
#define LIST_HEAD_FORMAT     (VERBOSE << 3)
#define LIST_HEAD_POINTER    (VERBOSE << 4)
#define RETURN_ON_DUPLICATE  (VERBOSE << 5)
#define RETURN_ON_LIST_ERROR (VERBOSE << 6)
#define LIST_STRUCT_RADIX_10 (VERBOSE << 7)
#define LIST_STRUCT_RADIX_16 (VERBOSE << 8)
#define LIST_HEAD_REVERSE    (VERBOSE << 9)
#define LIST_ALLOCATE       (VERBOSE << 10)
#define LIST_CALLBACK       (VERBOSE << 11)
#define CALLBACK_RETURN     (VERBOSE << 12)
#define LIST_PARSE_MEMBER   (VERBOSE << 13)
#define LIST_READ_MEMBER    (VERBOSE << 14)
#define LIST_BRENT_ALGO     (VERBOSE << 15)
#define LIST_HEAD_OFFSET_ENTERED  (VERBOSE << 16)

struct tree_data {
	ulong flags;
	ulong start;
	long node_member_offset;
	char **structname;
	int structname_args;
	int count;
};

#define TREE_ROOT_OFFSET_ENTERED  (VERBOSE << 1)
#define TREE_NODE_OFFSET_ENTERED  (VERBOSE << 2)
#define TREE_NODE_POINTER         (VERBOSE << 3)
#define TREE_POSITION_DISPLAY     (VERBOSE << 4)
#define TREE_STRUCT_RADIX_10      (VERBOSE << 5)
#define TREE_STRUCT_RADIX_16      (VERBOSE << 6)
#define TREE_PARSE_MEMBER         (VERBOSE << 7)
#define TREE_READ_MEMBER          (VERBOSE << 8)
#define TREE_LINEAR_ORDER         (VERBOSE << 9)
#define TREE_STRUCT_VERBOSE       (VERBOSE << 10)

#define ALIAS_RUNTIME  (1)
#define ALIAS_RCLOCAL  (2)
#define ALIAS_RCHOME   (3)
#define ALIAS_BUILTIN  (4)

struct alias_data {                 /* command alias storage */
	struct alias_data *next;
	char *alias;
	int argcnt;
	int size;
	int origin;
	char *args[MAXARGS];
	char argbuf[1];
};

struct rb_node
{
        unsigned long  rb_parent_color;
#define RB_RED          0
#define RB_BLACK        1
        struct rb_node *rb_right;
        struct rb_node *rb_left;
};

struct rb_root
{
        struct rb_node *rb_node;
};

#define NUMBER_STACKFRAMES 4

#define SAVE_RETURN_ADDRESS(retaddr) \
{ 									\
	int i; 								\
	int saved_stacks; 						\
									\
	saved_stacks = backtrace((void **)retaddr, NUMBER_STACKFRAMES); \
									\
	/* explicitely zero out the invalid addresses */		\
	for (i = saved_stacks; i < NUMBER_STACKFRAMES; i++)		\
		retaddr[i] = 0;						\
}

#endif /* !GDB_COMMON */


#define SYMBOL_NAME_USED (0x1)
#define MODULE_SYMBOL    (0x2)
#define IS_MODULE_SYMBOL(SYM)  ((SYM)->flags & MODULE_SYMBOL)

struct syment {
        ulong value;
        char *name;
	struct syment *val_hash_next;
	struct syment *name_hash_next;
	char type;
	unsigned char cnt;
	unsigned char flags;
	unsigned char pad2;
};

#define NAMESPACE_INIT     (1)
#define NAMESPACE_REUSE    (2)
#define NAMESPACE_FREE     (3)
#define NAMESPACE_INSTALL  (4)
#define NAMESPACE_COMPLETE (5)

struct symbol_namespace {
	char *address;
	size_t size;
	long index;
	long cnt;
};

struct downsized {
	char *name;
	struct downsized *next;
};

#define SYMVAL_HASH (512)
#define SYMVAL_HASH_INDEX(vaddr) \
        (((vaddr) >> machdep->pageshift) % SYMVAL_HASH)

#define SYMNAME_HASH (512)

#define PATCH_KERNEL_SYMBOLS_START  ((char *)(1))
#define PATCH_KERNEL_SYMBOLS_STOP   ((char *)(2))

#ifndef GDB_COMMON

struct symbol_table_data {
	ulong flags;
#ifdef GDB_5_3
	struct _bfd *bfd;
#else
	struct bfd *bfd;
#endif
	struct sec *sections;
	struct syment *symtable;
	struct syment *symend;
	long symcnt;
	ulong syment_size;
        struct symval_hash_chain {
                struct syment *val_hash_head;
                struct syment *val_hash_last;
        } symval_hash[SYMVAL_HASH];
        double val_hash_searches;
        double val_hash_iterations;
        struct syment *symname_hash[SYMNAME_HASH];
	struct symbol_namespace kernel_namespace;
	struct syment *ext_module_symtable;
	struct syment *ext_module_symend;
	long ext_module_symcnt;
	struct symbol_namespace ext_module_namespace;
	int mods_installed;
	struct load_module *current;
	struct load_module *load_modules;
	off_t dwarf_eh_frame_file_offset;
	ulong dwarf_eh_frame_size;
	ulong first_ksymbol;
	ulong __per_cpu_start;
	ulong __per_cpu_end;
	off_t dwarf_debug_frame_file_offset;
	ulong dwarf_debug_frame_size;
	ulong first_section_start;
	ulong last_section_end;
	ulong _stext_vmlinux;
	struct downsized downsized;
	ulong divide_error_vmlinux;
	ulong idt_table_vmlinux;
	ulong saved_command_line_vmlinux;
	ulong pti_init_vmlinux;
	ulong kaiser_init_vmlinux;
	int kernel_symbol_type;
	ulong linux_banner_vmlinux;
	struct syment *mod_symname_hash[SYMNAME_HASH];
};

/* flags for st */
#define KERNEL_SYMS        (0x1)
#define MODULE_SYMS        (0x2)
#define LOAD_MODULE_SYMS   (0x4)
#define INSMOD_BUILTIN     (0x8)
#define GDB_SYMS_PATCHED  (0x10)
#define GDB_PATCHED()     (st->flags & GDB_SYMS_PATCHED)
#define NO_SEC_LOAD       (0x20)
#define NO_SEC_CONTENTS   (0x40)
#define FORCE_DEBUGINFO   (0x80)
#define CRC_MATCHES      (0x100)
#define ADD_SYMBOL_FILE  (0x200)
#define USE_OLD_ADD_SYM  (0x400)
#define PERCPU_SYMS      (0x800)
#define MODSECT_UNKNOWN (0x1000)
#define MODSECT_V1      (0x2000)
#define MODSECT_V2      (0x4000)
#define MODSECT_V3      (0x8000)
#define MODSECT_VMASK   (MODSECT_V1|MODSECT_V2|MODSECT_V3)
#define NO_STRIP       (0x10000)

#define NO_LINE_NUMBERS() ((st->flags & GDB_SYMS_PATCHED) && !(kt->flags2 & KASLR))

#endif /* !GDB_COMMON */

#define ALL_MODULES      (0)

#define MAX_MOD_NAMELIST (256)
#define MAX_MOD_NAME     (64)
#define MAX_MOD_SEC_NAME (64)

#define MOD_EXT_SYMS    (0x1)
#define MOD_LOAD_SYMS   (0x2)
#define MOD_REMOTE      (0x4)
#define MOD_KALLSYMS    (0x8)
#define MOD_INITRD     (0x10)
#define MOD_NOPATCH    (0x20)
#define MOD_INIT       (0x40)
#define MOD_DO_READNOW (0x80)

#define SEC_FOUND       (0x10000)

struct mod_section_data {
#if defined(GDB_5_3) || defined(GDB_6_0)
        struct sec *section;
#else
        struct bfd_section *section;
#endif
        char name[MAX_MOD_SEC_NAME];
        ulong offset;
        ulong size;
        int priority;
        int flags;
};

struct load_module {
        ulong mod_base;
	ulong module_struct;
        long mod_size;
        char mod_namelist[MAX_MOD_NAMELIST];
        char mod_name[MAX_MOD_NAME];
        ulong mod_flags;
	struct syment *mod_symtable;
	struct syment *mod_symend;
        long mod_ext_symcnt;
	struct syment *mod_ext_symtable;
	struct syment *mod_ext_symend;
        long mod_load_symcnt;
        struct syment *mod_load_symtable;
        struct syment *mod_load_symend;
        long mod_symalloc;
	struct symbol_namespace mod_load_namespace;
	ulong mod_size_of_struct;
        ulong mod_text_start;
	ulong mod_etext_guess;
	ulong mod_rodata_start;
        ulong mod_data_start;
	ulong mod_bss_start;
	int mod_sections;
	struct mod_section_data *mod_section_data;
        ulong mod_init_text_size;
        ulong mod_init_module_ptr;
	ulong mod_init_size;
	struct syment *mod_init_symtable;
	struct syment *mod_init_symend;
	ulong mod_percpu;
	ulong mod_percpu_size;
	struct objfile *loaded_objfile;
};

#define IN_MODULE(A,L) \
 (((ulong)(A) >= (L)->mod_base) && ((ulong)(A) < ((L)->mod_base+(L)->mod_size)))

#define IN_MODULE_INIT(A,L) \
 (((ulong)(A) >= (L)->mod_init_module_ptr) && ((ulong)(A) < ((L)->mod_init_module_ptr+(L)->mod_init_size)))

#define IN_MODULE_PERCPU(A,L) \
 (((ulong)(A) >= (L)->mod_percpu) && ((ulong)(A) < ((L)->mod_percpu+(L)->mod_percpu_size)))

#define MODULE_PERCPU_SYMS_LOADED(L) ((L)->mod_percpu && (L)->mod_percpu_size)

#ifndef GDB_COMMON

#define KVADDR             (0x1)
#define UVADDR             (0x2)
#define PHYSADDR           (0x4)
#define XENMACHADDR        (0x8)
#define FILEADDR          (0x10)
#define AMBIGUOUS          (~0)

#define USE_USER_PGD       (UVADDR << 2)

#define VERIFY_ADDR        (0x8)   /* vm_area_dump() flags -- must follow */
#define PRINT_INODES      (0x10)   /* KVADDR, UVADDR, and PHYSADDR */
#define PRINT_MM_STRUCT   (0x20)
#define PRINT_VMA_STRUCTS (0x40)
#define PRINT_SINGLE_VMA  (0x80)
#define PRINT_RADIX_10   (0x100)
#define PRINT_RADIX_16   (0x200)
#define PRINT_NRPAGES    (0x400)

#define MIN_PAGE_SIZE  (4096)

#define PTOB(X)       ((ulonglong)(X) << machdep->pageshift)
#define BTOP(X)       ((ulonglong)(X) >> machdep->pageshift)

#define PAGESIZE()    (machdep->pagesize)
#define PAGESHIFT()   (machdep->pageshift)

#define PAGEOFFSET(X) (((ulong)(X)) & machdep->pageoffset)
#define VIRTPAGEBASE(X)  (((ulong)(X)) & (ulong)machdep->pagemask)
#define PHYSPAGEBASE(X)  (((physaddr_t)(X)) & (physaddr_t)machdep->pagemask)

/* 
 * Sparse memory stuff
 *  These must follow the definitions in the kernel mmzone.h
 */
#define SECTION_SIZE_BITS()	(machdep->section_size_bits)
#define MAX_PHYSMEM_BITS()	(machdep->max_physmem_bits)
#define SECTIONS_SHIFT()	(MAX_PHYSMEM_BITS() - SECTION_SIZE_BITS())
#define PA_SECTION_SHIFT()	(SECTION_SIZE_BITS())
#define PFN_SECTION_SHIFT()	(SECTION_SIZE_BITS() - PAGESHIFT())
#define NR_MEM_SECTIONS()	(1UL << SECTIONS_SHIFT())
#define PAGES_PER_SECTION()	(1UL << PFN_SECTION_SHIFT())
#define PAGE_SECTION_MASK()	(~(PAGES_PER_SECTION()-1))

#define pfn_to_section_nr(pfn) ((pfn) >> PFN_SECTION_SHIFT())
#define section_nr_to_pfn(sec) ((sec) << PFN_SECTION_SHIFT())

#define SECTIONS_PER_ROOT()	(machdep->sections_per_root)

/* CONFIG_SPARSEMEM_EXTREME */
#define _SECTIONS_PER_ROOT_EXTREME()	(PAGESIZE() / SIZE(mem_section))
/* !CONFIG_SPARSEMEM_EXTREME */
#define _SECTIONS_PER_ROOT()	(1)

#define SECTION_NR_TO_ROOT(sec)	((sec) / SECTIONS_PER_ROOT())
#define DIV_ROUND_UP(n,d)	(((n) + (d) - 1) / (d))
#define NR_SECTION_ROOTS()	(DIV_ROUND_UP(NR_MEM_SECTIONS(), SECTIONS_PER_ROOT()))
#define SECTION_ROOT_MASK()	(SECTIONS_PER_ROOT() - 1)

struct QEMUCPUSegment {
	uint32_t selector;
	uint32_t limit;
	uint32_t flags;
	uint32_t pad;
	uint64_t base;
};

typedef struct QEMUCPUSegment QEMUCPUSegment;

struct QEMUCPUState {
	uint32_t version;
	uint32_t size;
	uint64_t rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp;
	uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
	uint64_t rip, rflags;
	QEMUCPUSegment cs, ds, es, fs, gs, ss;
	QEMUCPUSegment ldt, tr, gdt, idt;
	uint64_t cr[5];
};

typedef struct QEMUCPUState QEMUCPUState;

/*
 *  Machine specific stuff
 */

#ifdef ARM
#define _32BIT_
#define MACHINE_TYPE		"ARM"

#define PAGEBASE(X)		(((ulong)(X)) & (ulong)machdep->pagemask)

#define PTOV(X) \
	((unsigned long)(X)-(machdep->machspec->phys_base)+(machdep->kvbase))
#define VTOP(X) \
	((unsigned long)(X)-(machdep->kvbase)+(machdep->machspec->phys_base))

#define IS_VMALLOC_ADDR(X) 	arm_is_vmalloc_addr((ulong)(X))

#define DEFAULT_MODULES_VADDR	(machdep->kvbase - 16 * 1024 * 1024)
#define MODULES_VADDR   	(machdep->machspec->modules_vaddr)
#define MODULES_END     	(machdep->machspec->modules_end)
#define VMALLOC_START   	(machdep->machspec->vmalloc_start_addr)
#define VMALLOC_END     	(machdep->machspec->vmalloc_end)

#define PGDIR_SHIFT   		(21)
#define PTRS_PER_PTE		(512)
#define PTRS_PER_PGD		(2048)

#define PGD_OFFSET(vaddr)       ((vaddr) >> PGDIR_SHIFT)
#define PTE_OFFSET(vaddr)       (((vaddr) >> PAGESHIFT()) & (PTRS_PER_PTE - 1))

#define __SWP_TYPE_SHIFT	3
#define __SWP_TYPE_BITS		6
#define __SWP_TYPE_MASK		((1 << __SWP_TYPE_BITS) - 1)
#define __SWP_OFFSET_SHIFT	(__SWP_TYPE_BITS + __SWP_TYPE_SHIFT)

#define SWP_TYPE(entry)		(((entry) >> __SWP_TYPE_SHIFT) & __SWP_TYPE_MASK)
#define SWP_OFFSET(entry)	((entry) >> __SWP_OFFSET_SHIFT)

#define __swp_type(entry)	SWP_TYPE(entry)
#define __swp_offset(entry)	SWP_OFFSET(entry)

#define TIF_SIGPENDING		(THIS_KERNEL_VERSION >= LINUX(2,6,23) ? 0 : 2)

#define _SECTION_SIZE_BITS	28
#define _MAX_PHYSMEM_BITS	32

/*add for LPAE*/
typedef unsigned long long u64;
typedef signed int         s32;
typedef u64 pgd_t;
typedef u64 pmd_t;
typedef u64 pte_t;

#define PMDSIZE()		(PAGESIZE())
#define LPAE_PGDIR_SHIFT	(30)
#define LPAE_PMDIR_SHIFT	(21)

#define LPAE_PGD_OFFSET(vaddr)  ((vaddr) >> LPAE_PGDIR_SHIFT)
#define LPAE_PMD_OFFSET(vaddr)  (((vaddr) >> LPAE_PMDIR_SHIFT) & \
				((1<<(LPAE_PGDIR_SHIFT-LPAE_PMDIR_SHIFT))-1))

#define _SECTION_SIZE_BITS_LPAE	28
#define _MAX_PHYSMEM_BITS_LPAE	36

/*
 * #define PTRS_PER_PTE            512
 * #define PTRS_PER_PMD            512
 * #define PTRS_PER_PGD            4
 *
 */

#define LPAE_PGDIR_SIZE()	32
#define LPAE_PGDIR_OFFSET(X)	(((ulong)(X)) & (LPAE_PGDIR_SIZE() - 1))

#define LPAE_PMDIR_SIZE()	4096
#define LPAE_PMDIR_OFFSET(X)	(((ulong)(X)) & (LPAE_PMDIR_SIZE() - 1))

#define LPAE_PTEDIR_SIZE()	4096
#define LPAE_PTEDIR_OFFSET(X)	(((ulong)(X)) & (LPAE_PTEDIR_SIZE() - 1))

/*section size for LPAE is 2MiB*/
#define LPAE_SECTION_PAGE_MASK	(~((MEGABYTES(2))-1))

#define _PHYSICAL_MASK_LPAE         ((1ULL << _MAX_PHYSMEM_BITS_LPAE) - 1)
#define PAGE_BASE_MASK    ((u64)((s32)machdep->pagemask & _PHYSICAL_MASK_LPAE))
#define LPAE_PAGEBASE(X)                (((ulonglong)(X)) & PAGE_BASE_MASK)

#define LPAE_VTOP(X) \
	((unsigned long long)(unsigned long)(X) - \
			(machdep->kvbase) + (machdep->machspec->phys_base))

#define IS_LAST_PGD_READ_LPAE(pgd)     ((pgd) == \
					machdep->machspec->last_pgd_read_lpae)
#define IS_LAST_PMD_READ_LPAE(pmd)     ((pmd) == \
					machdep->machspec->last_pmd_read_lpae)
#define IS_LAST_PTBL_READ_LPAE(ptbl)   ((ptbl) == \
					machdep->machspec->last_ptbl_read_lpae)

#define FILL_PGD_LPAE(PGD, TYPE, SIZE)			                    \
	if (!IS_LAST_PGD_READ_LPAE(PGD)) {                                  \
		readmem((ulonglong)(PGD), TYPE, machdep->pgd,               \
			SIZE, "pmd page", FAULT_ON_ERROR);                   \
		machdep->machspec->last_pgd_read_lpae \
						= (ulonglong)(PGD);        \
	}
#define FILL_PMD_LPAE(PMD, TYPE, SIZE)			                    \
	if (!IS_LAST_PMD_READ_LPAE(PMD)) {                                  \
		readmem((ulonglong)(PMD), TYPE, machdep->pmd,               \
			SIZE, "pmd page", FAULT_ON_ERROR);                  \
		machdep->machspec->last_pmd_read_lpae \
						= (ulonglong)(PMD);        \
	}

#define FILL_PTBL_LPAE(PTBL, TYPE, SIZE)		          	    \
	if (!IS_LAST_PTBL_READ_LPAE(PTBL)) {                                \
		readmem((ulonglong)(PTBL), TYPE, machdep->ptbl,              \
			SIZE, "page table", FAULT_ON_ERROR);                 \
		machdep->machspec->last_ptbl_read_lpae \
						= (ulonglong)(PTBL); 	    \
	}
#endif  /* ARM */

#ifndef EM_AARCH64
#define EM_AARCH64              183
#endif

#ifdef ARM64
#define _64BIT_
#define MACHINE_TYPE       "ARM64"    

#define USERSPACE_TOP   (machdep->machspec->userspace_top)
#define PAGE_OFFSET     (machdep->machspec->page_offset)
#define VMALLOC_START   (machdep->machspec->vmalloc_start_addr)
#define VMALLOC_END     (machdep->machspec->vmalloc_end)
#define VMEMMAP_VADDR   (machdep->machspec->vmemmap_vaddr)
#define VMEMMAP_END     (machdep->machspec->vmemmap_end)
#define MODULES_VADDR   (machdep->machspec->modules_vaddr)
#define MODULES_END     (machdep->machspec->modules_end)

#define PTOV(X)	arm64_PTOV((ulong)(X))
#define VTOP(X)	arm64_VTOP((ulong)(X))

#define IS_VMALLOC_ADDR(X)    arm64_IS_VMALLOC_ADDR((ulong)(X))

#define PAGEBASE(X)     (((ulong)(X)) & (ulong)machdep->pagemask)

/*
 * 48-bit physical address supported. 
 */
#define PHYS_MASK_SHIFT   (48)
#define PHYS_MASK         (((1UL) << PHYS_MASK_SHIFT) - 1)

typedef signed int s32;

/*
 * 3-levels / 4K pages
 */
#define PTRS_PER_PGD_L3_4K   (512)
#define PTRS_PER_PMD_L3_4K   (512)
#define PTRS_PER_PTE_L3_4K   (512)
#define PGDIR_SHIFT_L3_4K    (30)
#define PGDIR_SIZE_L3_4K     ((1UL) << PGDIR_SHIFT_L3_4K)
#define PGDIR_MASK_L3_4K     (~(PGDIR_SIZE_L3_4K-1))
#define PMD_SHIFT_L3_4K      (21)
#define PMD_SIZE_L3_4K       (1UL << PMD_SHIFT_L3_4K)
#define PMD_MASK_L3_4K       (~(PMD_SIZE_L3_4K-1))

/*
 * 4-levels / 4K pages
 * 48-bit VA
 */
#define PTRS_PER_PGD_L4_4K   ((1UL) << (48 - 39))
#define PTRS_PER_PUD_L4_4K   (512)
#define PTRS_PER_PMD_L4_4K   (512)
#define PTRS_PER_PTE_L4_4K   (512)
#define PGDIR_SHIFT_L4_4K    (39)
#define PGDIR_SIZE_L4_4K     ((1UL) << PGDIR_SHIFT_L4_4K)
#define PGDIR_MASK_L4_4K     (~(PGDIR_SIZE_L4_4K-1))
#define PUD_SHIFT_L4_4K      (30)
#define PUD_SIZE_L4_4K       ((1UL) << PUD_SHIFT_L4_4K)
#define PUD_MASK_L4_4K       (~(PUD_SIZE_L4_4K-1))
#define PMD_SHIFT_L4_4K      (21)
#define PMD_SIZE_L4_4K       (1UL << PMD_SHIFT_L4_4K)
#define PMD_MASK_L4_4K       (~(PMD_SIZE_L4_4K-1))

#define PGDIR_SIZE_48VA      (1UL << ((48 - 39) + 3))
#define PGDIR_MASK_48VA      (~(PGDIR_SIZE_48VA - 1))
#define PGDIR_OFFSET_48VA(X) (((ulong)(X)) & (PGDIR_SIZE_48VA - 1))

/*
 * 3-levels / 64K pages
 */
#define PTRS_PER_PGD_L3_64K  (64)
#define PTRS_PER_PMD_L3_64K  (8192)
#define PTRS_PER_PTE_L3_64K  (8192)
#define PGDIR_SHIFT_L3_64K   (42)
#define PGDIR_SIZE_L3_64K    ((1UL) << PGDIR_SHIFT_L3_64K)
#define PGDIR_MASK_L3_64K    (~(PGDIR_SIZE_L3_64K-1))
#define PMD_SHIFT_L3_64K     (29)
#define PMD_SIZE_L3_64K      (1UL << PMD_SHIFT_L3_64K)
#define PMD_MASK_L3_64K      (~(PMD_SIZE_L3_64K-1))
#define PGDIR_OFFSET_L3_64K(X) (((ulong)(X)) & ((machdep->ptrs_per_pgd * 8) - 1))

/*
 * 2-levels / 64K pages
 */
#define PTRS_PER_PGD_L2_64K  (8192)
#define PTRS_PER_PTE_L2_64K  (8192)
#define PGDIR_SHIFT_L2_64K   (29)
#define PGDIR_SIZE_L2_64K    ((1UL) << PGDIR_SHIFT_L2_64K)
#define PGDIR_MASK_L2_64K    (~(PGDIR_SIZE_L2_64K-1))

/*
 * Software defined PTE bits definition.
 * (arch/arm64/include/asm/pgtable.h)
 */
#define PTE_VALID       (1UL << 0)
#define PTE_DIRTY       (1UL << 55)
#define PTE_SPECIAL     (1UL << 56)

/*
 * Level 3 descriptor (PTE).
 * (arch/arm64/include/asm/pgtable-hwdef.h)
 */
#define PTE_TYPE_MASK   (3UL << 0)
#define PTE_TYPE_FAULT  (0UL << 0)
#define PTE_TYPE_PAGE   (3UL << 0)
#define PTE_USER        (1UL << 6)         /* AP[1] */
#define PTE_RDONLY      (1UL << 7)         /* AP[2] */
#define PTE_SHARED      (3UL << 8)         /* SH[1:0], inner shareable */
#define PTE_AF          (1UL << 10)        /* Access Flag */
#define PTE_NG          (1UL << 11)        /* nG */
#define PTE_PXN         (1UL << 53)        /* Privileged XN */
#define PTE_UXN         (1UL << 54)        /* User XN */

#define __swp_type(x)     arm64_swp_type(x)
#define __swp_offset(x)   arm64_swp_offset(x)
#define SWP_TYPE(x)       __swp_type(x)
#define SWP_OFFSET(x)     __swp_offset(x)

#define KSYMS_START   (0x1)
#define PHYS_OFFSET   (0x2)
#define VM_L2_64K     (0x4)
#define VM_L3_64K     (0x8)
#define VM_L3_4K      (0x10)
#define KDUMP_ENABLED (0x20)
#define IRQ_STACKS    (0x40)
#define NEW_VMEMMAP   (0x80)
#define VM_L4_4K      (0x100)
#define UNW_4_14      (0x200)
#define FLIPPED_VM    (0x400)
#define HAS_PHYSVIRT_OFFSET (0x800)
#define OVERFLOW_STACKS     (0x1000)

/*
 * Get kimage_voffset from /dev/crash
 */
#define DEV_CRASH_ARCH_DATA _IOR('c', 1, unsigned long)

/* 
 * sources: Documentation/arm64/memory.txt 
 *          arch/arm64/include/asm/memory.h 
 *          arch/arm64/include/asm/pgtable.h
 */
#define ARM64_VA_START       ((0xffffffffffffffffUL) \
					<< machdep->machspec->VA_BITS)
#define _VA_START(va)        ((0xffffffffffffffffUL) - \
                             ((1UL) << ((va) - 1)) + 1)
#define TEXT_OFFSET_MASK     (~((MEGABYTES(2UL))-1))

#define ARM64_PAGE_OFFSET    ((0xffffffffffffffffUL) \
					<< (machdep->machspec->VA_BITS - 1))
/* kernels >= v5.4 the kernel VA space is flipped */
#define ARM64_FLIP_PAGE_OFFSET (-(1UL) << machdep->machspec->VA_BITS)

#define ARM64_USERSPACE_TOP  ((1UL) << machdep->machspec->VA_BITS)
#define ARM64_USERSPACE_TOP_ACTUAL  ((1UL) << machdep->machspec->VA_BITS_ACTUAL)

/* only used for v4.6 or later */
#define ARM64_MODULES_VSIZE     MEGABYTES(128)
#define ARM64_KASAN_SHADOW_SIZE (1UL << (machdep->machspec->VA_BITS - 3))

/*
 * The following 3 definitions are the original values, but are obsolete
 * for 3.17 and later kernels because they are now build-time calculations.
 * They all depend on the kernel's new VMEMMAP_SIZE value, which is dependent
 * upon the size of struct page.  Accordingly, arm64_calc_virtual_memory_ranges()
 * determines their values at POST_GDB time.
 */
#define ARM64_VMALLOC_END    (ARM64_PAGE_OFFSET - 0x400000000UL - KILOBYTES(64) - 1)
#define ARM64_VMEMMAP_VADDR  ((ARM64_VMALLOC_END+1) + KILOBYTES(64))
#define ARM64_VMEMMAP_END    (ARM64_VMEMMAP_VADDR + GIGABYTES(8UL) - 1)

#define ARM64_STACK_SIZE   (16384)
#define ARM64_IRQ_STACK_SIZE   ARM64_STACK_SIZE
#define ARM64_OVERFLOW_STACK_SIZE   (4096)

#define _SECTION_SIZE_BITS           30
#define _SECTION_SIZE_BITS_5_12      27
#define _SECTION_SIZE_BITS_5_12_64K  29
#define _MAX_PHYSMEM_BITS       40
#define _MAX_PHYSMEM_BITS_3_17  48
#define _MAX_PHYSMEM_BITS_52    52

typedef unsigned long long __u64;
typedef unsigned long long u64;

struct arm64_user_pt_regs {
        __u64           regs[31];
        __u64           sp;
        __u64           pc;
        __u64           pstate;
};

struct arm64_pt_regs {
        union {
                struct arm64_user_pt_regs user_regs;
                struct {
                        u64 regs[31];
                        u64 sp;
                        u64 pc;
                        u64 pstate;
                };
        };
        u64 orig_x0;
        u64 syscallno;
};

/* AArch32 CPSR bits */
#define PSR_MODE32_BIT          0x00000010

#define TIF_SIGPENDING  (0)
#define display_idt_table() \
        error(FATAL, "-d option is not applicable to ARM64 architecture\n")

struct machine_specific {
	ulong flags;
	ulong userspace_top;
	ulong page_offset;
	ulong vmalloc_start_addr;
	ulong vmalloc_end;
	ulong vmemmap_vaddr;
	ulong vmemmap_end;
	ulong modules_vaddr;
	ulong modules_end;
	ulong phys_offset;
	ulong __exception_text_start;
	ulong __exception_text_end;
	struct arm64_pt_regs *panic_task_regs;
	ulong PTE_PROT_NONE;
	ulong PTE_FILE;
	ulong VA_BITS;
	ulong __SWP_TYPE_BITS;
	ulong __SWP_TYPE_SHIFT;
	ulong __SWP_TYPE_MASK;
	ulong __SWP_OFFSET_BITS;
	ulong __SWP_OFFSET_SHIFT;
	ulong __SWP_OFFSET_MASK;
	ulong crash_kexec_start;
	ulong crash_kexec_end;
	ulong crash_save_cpu_start;
	ulong crash_save_cpu_end;
	ulong kernel_flags;
	ulong irq_stack_size;
	ulong *irq_stacks;
	char  *irq_stackbuf;
	ulong __irqentry_text_start;
	ulong __irqentry_text_end;
	ulong overflow_stack_size;
	ulong *overflow_stacks;
	char  *overflow_stackbuf;
	/* for exception vector code */
	ulong exp_entry1_start;
	ulong exp_entry1_end;
	ulong exp_entry2_start;
	ulong exp_entry2_end;
	/* only needed for v4.6 or later kernel */
	ulong kimage_voffset;
	ulong kimage_text;
	ulong kimage_end;
	ulong user_eframe_offset;
	/* for v4.14 or later */
	ulong kern_eframe_offset;
	ulong machine_kexec_start;
	ulong machine_kexec_end;
	ulong VA_BITS_ACTUAL;
	ulong CONFIG_ARM64_VA_BITS;
	ulong VA_START;
	ulong CONFIG_ARM64_KERNELPACMASK;
	ulong physvirt_offset;
	ulong struct_page_size;
};

struct arm64_stackframe {
        unsigned long fp;
        unsigned long sp;
        unsigned long pc;
};

#endif  /* ARM64 */

#ifdef MIPS
#define _32BIT_
#define MACHINE_TYPE		"MIPS"

#define PAGEBASE(X)		(((ulong)(X)) & (ulong)machdep->pagemask)

#define PTOV(X)            ((unsigned long)(X) + 0x80000000lu)
#define VTOP(X)            ((unsigned long)(X) & 0x1ffffffflu)

#define IS_VMALLOC_ADDR(X) (vt->vmalloc_start && (ulong)(X) >= vt->vmalloc_start)

#define DEFAULT_MODULES_VADDR	(machdep->kvbase - 16 * 1024 * 1024)
#define MODULES_VADDR   	(machdep->machspec->modules_vaddr)
#define MODULES_END     	(machdep->machspec->modules_end)
#define VMALLOC_START   	(machdep->machspec->vmalloc_start_addr)
#define VMALLOC_END     	(machdep->machspec->vmalloc_end)

#define __SWP_TYPE_SHIFT	3
#define __SWP_TYPE_BITS		6
#define __SWP_TYPE_MASK		((1 << __SWP_TYPE_BITS) - 1)
#define __SWP_OFFSET_SHIFT	(__SWP_TYPE_BITS + __SWP_TYPE_SHIFT)

#define SWP_TYPE(entry)		(((entry) >> __SWP_TYPE_SHIFT) & __SWP_TYPE_MASK)
#define SWP_OFFSET(entry)	((entry) >> __SWP_OFFSET_SHIFT)

#define __swp_type(entry)	SWP_TYPE(entry)
#define __swp_offset(entry)	SWP_OFFSET(entry)

#define TIF_SIGPENDING		(THIS_KERNEL_VERSION >= LINUX(2,6,23) ? 1 : 2)

#define _SECTION_SIZE_BITS	26
#define _MAX_PHYSMEM_BITS	32
#endif  /* MIPS */

#ifdef MIPS64
#define _64BIT_
#define MACHINE_TYPE		"MIPS64"

#define PAGEBASE(X)		(((ulong)(X)) & (ulong)machdep->pagemask)
#define IS_CKPHYS(X)		(((X) >= 0xffffffff80000000lu) && \
				((X) < 0xffffffffc0000000lu))
#define IS_XKPHYS(X)		(((X) >= 0x8000000000000000lu) && \
				((X) < 0xc000000000000000lu))

#define PTOV(X) 		((ulong)(X) + 0x9800000000000000lu)
#define VTOP(X) 		(IS_CKPHYS(X) ? ((ulong)(X) & 0x000000001ffffffflu) \
				: ((ulong)(X) & 0x0000fffffffffffflu))

#define IS_VMALLOC_ADDR(X) (vt->vmalloc_start && (ulong)(X) >= vt->vmalloc_start && !IS_CKPHYS(X))

#define DEFAULT_MODULES_VADDR   0xffffffffc0000000lu
#define MODULES_VADDR           (machdep->machspec->modules_vaddr)
#define MODULES_END             (machdep->machspec->modules_end)
#define VMALLOC_START           (machdep->machspec->vmalloc_start_addr)
#define VMALLOC_END             (machdep->machspec->vmalloc_end)

#define __SWP_TYPE_SHIFT        16
#define __SWP_TYPE_BITS         8
#define __SWP_TYPE_MASK         ((1 << __SWP_TYPE_BITS) - 1)
#define __SWP_OFFSET_SHIFT      (__SWP_TYPE_BITS + __SWP_TYPE_SHIFT)

#define SWP_TYPE(entry)         (((entry) >> __SWP_TYPE_SHIFT) & __SWP_TYPE_MASK)
#define SWP_OFFSET(entry)       ((entry) >> __SWP_OFFSET_SHIFT)

#define __swp_type(entry)       SWP_TYPE(entry)
#define __swp_offset(entry)     SWP_OFFSET(entry)

#define TIF_SIGPENDING          (THIS_KERNEL_VERSION >= LINUX(2,6,23) ? 1 : 2)

#define _SECTION_SIZE_BITS      28
#define _MAX_PHYSMEM_BITS       48
#endif  /* MIPS64 */

#ifndef EM_RISCV
#define EM_RISCV		243
#endif

#ifdef RISCV64
#define _64BIT_
#define MACHINE_TYPE		"RISCV64"

typedef struct { ulong pgd; } pgd_t;
typedef struct { ulong p4d; } p4d_t;
typedef struct { ulong pud; } pud_t;
typedef struct { ulong pmd; } pmd_t;
typedef struct { ulong pte; } pte_t;
typedef signed int s32;

/* arch/riscv/include/asm/pgtable-64.h */
#define PGD_SHIFT_L3		(30)
#define PGD_SHIFT_L4		(39)
#define PGD_SHIFT_L5		(48)

#define P4D_SHIFT		(39)
#define PUD_SHIFT		(30)
#define PMD_SHIFT		(21)

#define PTRS_PER_PGD		(512)
#define PTRS_PER_P4D		(512)
#define PTRS_PER_PUD		(512)
#define PTRS_PER_PMD		(512)
#define PTRS_PER_PTE		(512)

/*
 * Mask for bit 0~53(PROT and PPN) of PTE
 * 63 6261  60    54  53 10  9 8 7 6 5 4 3 2 1 0
 * N  PBMT  Reserved  P P N  RSW D A G U X W R V
 */
#define PTE_PFN_PROT_MASK	0x3FFFFFFFFFFFFF

/*
 * 3-levels / 4K pages
 *
 * sv39
 * PGD  |  PMD  |  PTE  |  OFFSET  |
 *  9   |   9   |   9   |    12    |
 */
#define pgd_index_l3_4k(addr) (((addr) >> PGD_SHIFT_L3) & (PTRS_PER_PGD - 1))
#define pmd_index_l3_4k(addr) (((addr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
#define pte_index_l3_4k(addr) (((addr) >> PAGESHIFT()) & (PTRS_PER_PTE - 1))

/*
 * 4-levels / 4K pages
 *
 * sv48
 * PGD  |  PUD  |  PMD  |   PTE   |  OFFSET  |
 *  9   |   9   |   9   |    9    |    12    |
 */
#define pgd_index_l4_4k(addr) (((addr) >> PGD_SHIFT_L4) & (PTRS_PER_PGD - 1))
#define pud_index_l4_4k(addr) (((addr) >> PUD_SHIFT) & (PTRS_PER_PUD - 1))
#define pmd_index_l4_4k(addr) (((addr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
#define pte_index_l4_4k(addr) (((addr) >> PAGESHIFT()) & (PTRS_PER_PTE - 1))

/*
 * 5-levels / 4K pages
 *
 * sv57
 * PGD  |  P4D  |  PUD  |  PMD  |   PTE   |  OFFSET  |
 *  9   |   9   |   9   |   9   |    9    |    12    |
 */
#define pgd_index_l5_4k(addr) (((addr) >> PGD_SHIFT_L5) & (PTRS_PER_PGD - 1))
#define p4d_index_l5_4k(addr) (((addr) >> P4D_SHIFT) & (PTRS_PER_P4D - 1))
#define pud_index_l5_4k(addr) (((addr) >> PUD_SHIFT) & (PTRS_PER_PUD - 1))
#define pmd_index_l5_4k(addr) (((addr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
#define pte_index_l5_4k(addr) (((addr) >> PAGESHIFT()) & (PTRS_PER_PTE - 1))

#define VM_L3_4K	(0x2)
#define VM_L3_2M	(0x4)
#define VM_L3_1G	(0x8)
#define VM_L4_4K	(0x10)
#define VM_L4_2M	(0x20)
#define VM_L4_1G	(0x40)
#define VM_L5_4K	(0x80)
#define VM_L5_2M	(0x100)
#define VM_L5_1G	(0x200)

#define VM_FLAGS	(VM_L3_4K | VM_L3_2M | VM_L3_1G | \
			 VM_L4_4K | VM_L4_2M | VM_L4_1G | \
			 VM_L5_4K | VM_L5_2M | VM_L5_1G)

/*
 * Direct memory mapping
 */
#define PTOV(X) 									\
	(((unsigned long)(X)+(machdep->kvbase)) - machdep->machspec->phys_base)
#define VTOP(X) ({									\
	ulong _X = X;									\
	(THIS_KERNEL_VERSION >= LINUX(5,13,0) &&					\
		(_X) >= machdep->machspec->kernel_link_addr) ?				\
		(((unsigned long)(_X)-(machdep->machspec->kernel_link_addr)) +		\
		 machdep->machspec->phys_base):						\
		(((unsigned long)(_X)-(machdep->kvbase)) +				\
		 machdep->machspec->phys_base);						\
	})
#define PAGEBASE(X)		(((ulong)(X)) & (ulong)machdep->pagemask)

/*
 * Stack size order
 */
#define THREAD_SIZE_ORDER	2

#define PAGE_OFFSET		(machdep->machspec->page_offset)
#define VMALLOC_START		(machdep->machspec->vmalloc_start_addr)
#define VMALLOC_END		(machdep->machspec->vmalloc_end)
#define VMEMMAP_VADDR		(machdep->machspec->vmemmap_vaddr)
#define VMEMMAP_END		(machdep->machspec->vmemmap_end)
#define MODULES_VADDR		(machdep->machspec->modules_vaddr)
#define MODULES_END		(machdep->machspec->modules_end)
#define IS_VMALLOC_ADDR(X)	riscv64_IS_VMALLOC_ADDR((ulong)(X))

/* from arch/riscv/include/asm/pgtable.h */
#define __SWP_TYPE_SHIFT	6
#define __SWP_TYPE_BITS 	5
#define __SWP_TYPE_MASK 	((1UL << __SWP_TYPE_BITS) - 1)
#define __SWP_OFFSET_SHIFT	(__SWP_TYPE_BITS + __SWP_TYPE_SHIFT)

#define MAX_SWAPFILES_CHECK()	BUILD_BUG_ON(MAX_SWAPFILES_SHIFT > __SWP_TYPE_BITS)

#define SWP_TYPE(entry) 	(((entry) >> __SWP_TYPE_SHIFT) & __SWP_TYPE_MASK)
#define SWP_OFFSET(entry)	((entry) >> __SWP_OFFSET_SHIFT)
#define __swp_type(entry)	SWP_TYPE(entry)
#define __swp_offset(entry)	SWP_OFFSET(entry)

#define TIF_SIGPENDING		(THIS_KERNEL_VERSION >= LINUX(2,6,23) ? 1 : 2)

/* from arch/riscv/include/asm/sparsemem.h */
#define _SECTION_SIZE_BITS	27
#define _MAX_PHYSMEM_BITS	56 /* 56-bit physical address supported */
#define PHYS_MASK_SHIFT 	_MAX_PHYSMEM_BITS
#define PHYS_MASK		(((1UL) << PHYS_MASK_SHIFT) - 1)

#define IS_LAST_P4D_READ(p4d)	((ulong)(p4d) == machdep->machspec->last_p4d_read)
#define FILL_P4D(P4D, TYPE, SIZE)					      \
    if (!IS_LAST_P4D_READ(P4D)) {					      \
	    readmem((ulonglong)((ulong)(P4D)), TYPE, machdep->machspec->p4d,  \
		     SIZE, "p4d page", FAULT_ON_ERROR);                       \
	    machdep->machspec->last_p4d_read = (ulong)(P4D);                  \
    }

#endif  /* RISCV64 */

#ifdef X86
#define _32BIT_
#define MACHINE_TYPE       "X86"
#define PTOV(X)            ((unsigned long)(X)+(machdep->kvbase))
#define VTOP(X)            ((unsigned long)(X)-(machdep->kvbase))
#define IS_VMALLOC_ADDR(X) (vt->vmalloc_start && (ulong)(X) >= vt->vmalloc_start)
#define KVBASE_MASK        (0x1ffffff)

#define PGDIR_SHIFT_2LEVEL   (22)
#define PTRS_PER_PTE_2LEVEL  (1024)
#define PTRS_PER_PGD_2LEVEL  (1024)

#define PGDIR_SHIFT_3LEVEL   (30)
#define PTRS_PER_PTE_3LEVEL  (512)
#define PTRS_PER_PGD_3LEVEL  (4)
#define PMD_SHIFT            (21)    /* only used by PAE translators */
#define PTRS_PER_PMD         (512)   /* only used by PAE translators */

#define _PAGE_PRESENT   0x001
#define _PAGE_RW        0x002
#define _PAGE_USER      0x004
#define _PAGE_PWT       0x008
#define _PAGE_PCD       0x010
#define _PAGE_ACCESSED  0x020
#define _PAGE_DIRTY     0x040
#define _PAGE_4M        0x080   /* 4 MB page, Pentium+, if present.. */
#define _PAGE_PSE       0x080   /* 4 MB (or 2MB) page, Pentium+, if present.. */
#define _PAGE_GLOBAL    0x100   /* Global TLB entry PPro+ */
#define _PAGE_PROTNONE  (machdep->machspec->page_protnone)
#define _PAGE_NX        (0x8000000000000000ULL)

#define NONPAE_PAGEBASE(X)   (((unsigned long)(X)) & (unsigned long)machdep->pagemask)
#define NX_BIT_MASK          (0x7fffffffffffffffULL)
#define PAE_PAGEBASE(X)      (((unsigned long long)(X)) & ((unsigned long long)machdep->pagemask) & NX_BIT_MASK)

#define SWP_TYPE(entry) (((entry) >> 1) & 0x3f)
#define SWP_OFFSET(entry) ((entry) >> 8)
#define __swp_type_PAE(entry)      (((entry) >> 32) & 0x1f)
#define __swp_type_nonPAE(entry)   (((entry) >> 1) & 0x1f)
#define __swp_offset_PAE(entry)    (((entry) >> 32) >> 5)
#define __swp_offset_nonPAE(entry) ((entry) >> 8)
#define __swp_type(entry)          (machdep->flags & PAE ? \
				    __swp_type_PAE(entry) : __swp_type_nonPAE(entry))
#define __swp_offset(entry)        (machdep->flags & PAE ? \
				    __swp_offset_PAE(entry) : __swp_offset_nonPAE(entry))

#define TIF_SIGPENDING  (2)

// CONFIG_X86_PAE 
#define _SECTION_SIZE_BITS_PAE_ORIG	30
#define _SECTION_SIZE_BITS_PAE_2_6_26	29
#define _MAX_PHYSMEM_BITS_PAE	36

// !CONFIG_X86_PAE   
#define _SECTION_SIZE_BITS	26
#define _MAX_PHYSMEM_BITS	32

#define IS_LAST_PMD_READ_PAE(pmd)     ((ulong)(pmd) == machdep->machspec->last_pmd_read_PAE)
#define IS_LAST_PTBL_READ_PAE(ptbl)   ((ulong)(ptbl) == machdep->machspec->last_ptbl_read_PAE)

#define FILL_PMD_PAE(PMD, TYPE, SIZE)			                    \
    if (!IS_LAST_PMD_READ_PAE(PMD)) {                                       \
            readmem((ulonglong)(PMD), TYPE, machdep->pmd,                   \
	            SIZE, "pmd page", FAULT_ON_ERROR);                      \
            machdep->machspec->last_pmd_read_PAE = (ulonglong)(PMD);        \
    }					                                    

#define FILL_PTBL_PAE(PTBL, TYPE, SIZE)			           	    \
    if (!IS_LAST_PTBL_READ_PAE(PTBL)) {                                     \
    	    readmem((ulonglong)(PTBL), TYPE, machdep->ptbl,                 \
	            SIZE, "page table", FAULT_ON_ERROR);                    \
            machdep->machspec->last_ptbl_read_PAE = (ulonglong)(PTBL); 	    \
    }

#endif  /* X86 */

#ifdef X86_64 
#define _64BIT_
#define MACHINE_TYPE       "X86_64"

#define USERSPACE_TOP   (machdep->machspec->userspace_top)
#define PAGE_OFFSET     (machdep->machspec->page_offset)
#define VMALLOC_START   (machdep->machspec->vmalloc_start_addr)
#define VMALLOC_END     (machdep->machspec->vmalloc_end)
#define VMEMMAP_VADDR   (machdep->machspec->vmemmap_vaddr)
#define VMEMMAP_END     (machdep->machspec->vmemmap_end)
#define MODULES_VADDR   (machdep->machspec->modules_vaddr)
#define MODULES_END     (machdep->machspec->modules_end)

#define __START_KERNEL_map    0xffffffff80000000UL
#define MODULES_LEN     (MODULES_END - MODULES_VADDR)

#define USERSPACE_TOP_ORIG         0x0000008000000000
#define PAGE_OFFSET_ORIG           0x0000010000000000
#define VMALLOC_START_ADDR_ORIG    0xffffff0000000000
#define VMALLOC_END_ORIG           0xffffff7fffffffff
#define MODULES_VADDR_ORIG         0xffffffffa0000000
#define MODULES_END_ORIG           0xffffffffafffffff
 
#define USERSPACE_TOP_2_6_11       0x0000800000000000
#define PAGE_OFFSET_2_6_11         0xffff810000000000
#define VMALLOC_START_ADDR_2_6_11  0xffffc20000000000
#define VMALLOC_END_2_6_11         0xffffe1ffffffffff
#define MODULES_VADDR_2_6_11       0xffffffff88000000
#define MODULES_END_2_6_11         0xfffffffffff00000

#define VMEMMAP_VADDR_2_6_24       0xffffe20000000000
#define VMEMMAP_END_2_6_24         0xffffe2ffffffffff

#define MODULES_VADDR_2_6_26       0xffffffffa0000000

#define PAGE_OFFSET_2_6_27         0xffff880000000000
#define MODULES_END_2_6_27         0xffffffffff000000

#define USERSPACE_TOP_XEN          0x0000800000000000
#define PAGE_OFFSET_XEN            0xffff880000000000
#define VMALLOC_START_ADDR_XEN     0xffffc20000000000
#define VMALLOC_END_XEN            0xffffe1ffffffffff
#define MODULES_VADDR_XEN          0xffffffff88000000
#define MODULES_END_XEN            0xfffffffffff00000

#define USERSPACE_TOP_XEN_RHEL4       0x0000008000000000
#define PAGE_OFFSET_XEN_RHEL4         0xffffff8000000000
#define VMALLOC_START_ADDR_XEN_RHEL4  0xffffff0000000000
#define VMALLOC_END_XEN_RHEL4         0xffffff7fffffffff
#define MODULES_VADDR_XEN_RHEL4       0xffffffffa0000000
#define MODULES_END_XEN_RHEL4         0xffffffffafffffff

#define VMALLOC_START_ADDR_2_6_31  0xffffc90000000000
#define VMALLOC_END_2_6_31         0xffffe8ffffffffff
#define VMEMMAP_VADDR_2_6_31       0xffffea0000000000
#define VMEMMAP_END_2_6_31         0xffffeaffffffffff
#define MODULES_VADDR_2_6_31       0xffffffffa0000000
#define MODULES_END_2_6_31         0xffffffffff000000

#define USERSPACE_TOP_5LEVEL       0x0100000000000000
#define PAGE_OFFSET_5LEVEL         0xff10000000000000
#define VMALLOC_START_ADDR_5LEVEL  0xffa0000000000000
#define VMALLOC_END_5LEVEL         0xffd1ffffffffffff
#define MODULES_VADDR_5LEVEL       0xffffffffa0000000
#define MODULES_END_5LEVEL         0xffffffffff5fffff
#define VMEMMAP_VADDR_5LEVEL       0xffd4000000000000
#define VMEMMAP_END_5LEVEL         0xffd5ffffffffffff

#define PAGE_OFFSET_4LEVEL_4_20    0xffff888000000000
#define PAGE_OFFSET_5LEVEL_4_20    0xff11000000000000

#define VSYSCALL_START             0xffffffffff600000
#define VSYSCALL_END               0xffffffffff601000

#define CPU_ENTRY_AREA_START       0xfffffe0000000000
#define CPU_ENTRY_AREA_END         0xfffffe7fffffffff

#define PTOV(X)               ((unsigned long)(X)+(machdep->kvbase))
#define VTOP(X)               x86_64_VTOP((ulong)(X))
#define IS_VMALLOC_ADDR(X)    x86_64_IS_VMALLOC_ADDR((ulong)(X))

/*
 * the default page table level for x86_64:
 *    4 level page tables
 */
#define PGDIR_SHIFT     39
#define PTRS_PER_PGD    512
#define PUD_SHIFT       30
#define PTRS_PER_PUD    512
#define PMD_SHIFT       21
#define PTRS_PER_PMD    512
#define PTRS_PER_PTE    512

/* 5 level page */
#define PGDIR_SHIFT_5LEVEL    48
#define PTRS_PER_PGD_5LEVEL  512
#define P4D_SHIFT             39
#define PTRS_PER_P4D         512

#define __PGDIR_SHIFT  (machdep->machspec->pgdir_shift)
#define __PTRS_PER_PGD  (machdep->machspec->ptrs_per_pgd)

#define pgd_index(address)  (((address) >> __PGDIR_SHIFT) & (__PTRS_PER_PGD-1))
#define p4d_index(address)  (((address) >> P4D_SHIFT) & (PTRS_PER_P4D - 1))
#define pud_index(address)  (((address) >> PUD_SHIFT) & (PTRS_PER_PUD - 1))
#define pmd_index(address)  (((address) >> PMD_SHIFT) & (PTRS_PER_PMD-1))
#define pte_index(address)  (((address) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1))

#define FILL_TOP_PGD() 							\
	if (!(pc->flags & RUNTIME) || ACTIVE()) { 				\
		FILL_PGD(vt->kernel_pgd[0], KVADDR, PAGESIZE());		\
	}

#define FILL_TOP_PGD_HYPER() 							\
	unsigned long idle_pg_table = symbol_exists("idle_pg_table_4") ? 	\
					symbol_value("idle_pg_table_4") : 	\
					symbol_value("idle_pg_table");		\
	FILL_PGD(idle_pg_table, KVADDR, PAGESIZE());

#define IS_LAST_P4D_READ(p4d) ((ulong)(p4d) == machdep->machspec->last_p4d_read)

#define FILL_P4D(P4D, TYPE, SIZE)                                             \
    if (!IS_LAST_P4D_READ(P4D)) {                                             \
	    readmem((ulonglong)((ulong)(P4D)), TYPE, machdep->machspec->p4d,  \
		    SIZE, "p4d page", FAULT_ON_ERROR);                        \
	    machdep->machspec->last_p4d_read = (ulong)(P4D);                  \
    }

#define MAX_POSSIBLE_PHYSMEM_BITS     52

/* 
 *  PHYSICAL_PAGE_MASK changed (enlarged) between 2.4 and 2.6, so
 *  for safety, use the 2.6 values to generate it.
 */ 
#define __PHYSICAL_MASK_SHIFT_XEN     52
#define __PHYSICAL_MASK_SHIFT_2_6     46
#define __PHYSICAL_MASK_SHIFT_5LEVEL  52
#define __PHYSICAL_MASK_SHIFT  (machdep->machspec->physical_mask_shift)
#define __PHYSICAL_MASK        ((1UL << __PHYSICAL_MASK_SHIFT) - 1)
#define __VIRTUAL_MASK_SHIFT   48
#define __VIRTUAL_MASK         ((1UL << __VIRTUAL_MASK_SHIFT) - 1)
#define PAGE_SHIFT             12
#define PAGE_SIZE              (1UL << PAGE_SHIFT)
#define PHYSICAL_PAGE_MASK    (~(PAGE_SIZE-1) & __PHYSICAL_MASK )

#define _PAGE_BIT_NX    63
#define _PAGE_PRESENT   0x001
#define _PAGE_RW        0x002
#define _PAGE_USER      0x004
#define _PAGE_PWT       0x008
#define _PAGE_PCD       0x010
#define _PAGE_ACCESSED  0x020
#define _PAGE_DIRTY     0x040
#define _PAGE_PSE       0x080   /* 2MB page */
#define _PAGE_FILE      0x040   /* set:pagecache, unset:swap */
#define _PAGE_GLOBAL    0x100   /* Global TLB entry */
#define _PAGE_PROTNONE  (machdep->machspec->page_protnone)
#define _PAGE_NX        (1UL<<_PAGE_BIT_NX)

#define SWP_TYPE(entry) (((entry) >> 1) & 0x3f)
#define SWP_OFFSET(entry) ((entry) >> 8)
#define __swp_type(entry)   x86_64_swp_type(entry)
#define __swp_offset(entry) x86_64_swp_offset(entry)

#define TIF_SIGPENDING  (2)

#define PAGEBASE(X)           (((ulong)(X)) & (ulong)machdep->pagemask)

#define _CPU_PDA_READ2(CPU, BUFFER) \
 	((readmem(symbol_value("_cpu_pda"),				\
		 KVADDR, &cpu_pda_addr, sizeof(unsigned long),		\
		 "_cpu_pda addr", RETURN_ON_ERROR)) &&			\
 	(readmem(cpu_pda_addr + ((CPU) * sizeof(void *)),		\
		 KVADDR, &cpu_pda_addr, sizeof(unsigned long),		\
		 "_cpu_pda addr", RETURN_ON_ERROR)) &&			\
	(cpu_pda_addr) &&						\
	(readmem(cpu_pda_addr, KVADDR, (BUFFER), SIZE(x8664_pda),	\
		 "cpu_pda entry", RETURN_ON_ERROR)))

#define _CPU_PDA_READ(CPU, BUFFER) \
	((STRNEQ("_cpu_pda", closest_symbol((symbol_value("_cpu_pda") +	\
	     ((CPU) * sizeof(unsigned long)))))) &&			\
 	(readmem(symbol_value("_cpu_pda") + ((CPU) * sizeof(void *)),   \
		 KVADDR, &cpu_pda_addr, sizeof(unsigned long),          \
		 "_cpu_pda addr", RETURN_ON_ERROR)) &&	   	        \
	(readmem(cpu_pda_addr, KVADDR, (BUFFER), SIZE(x8664_pda),       \
		 "cpu_pda entry", RETURN_ON_ERROR)))

#define CPU_PDA_READ(CPU, BUFFER) \
	(STRNEQ("cpu_pda", closest_symbol((symbol_value("cpu_pda") +	\
	     ((CPU) * SIZE(x8664_pda))))) &&				\
        readmem(symbol_value("cpu_pda") + ((CPU) * SIZE(x8664_pda)),	\
             KVADDR, (BUFFER), SIZE(x8664_pda), "cpu_pda entry",	\
             RETURN_ON_ERROR))

#define VALID_LEVEL4_PGT_ADDR(X) \
	(((X) == VIRTPAGEBASE(X)) && IS_KVADDR(X) && !IS_VMALLOC_ADDR(X))

#define _SECTION_SIZE_BITS	  27
#define _MAX_PHYSMEM_BITS	  40
#define _MAX_PHYSMEM_BITS_2_6_26  44
#define _MAX_PHYSMEM_BITS_2_6_31  46
#define _MAX_PHYSMEM_BITS_5LEVEL  52

#endif  /* X86_64 */

#ifdef ALPHA
#define _64BIT_
#define MACHINE_TYPE       "ALPHA"

#define PAGEBASE(X)  (((unsigned long)(X)) & (unsigned long)machdep->pagemask)

#define PTOV(X)            ((unsigned long)(X)+(machdep->kvbase))
#define VTOP(X)            ((unsigned long)(X)-(machdep->kvbase))
#define IS_VMALLOC_ADDR(X) (vt->vmalloc_start && (ulong)(X) >= vt->vmalloc_start)
#define KSEG_BASE_48_BIT   (0xffff800000000000)
#define KSEG_BASE          (0xfffffc0000000000)
#define _PFN_MASK          (0xFFFFFFFF00000000)
#define VMALLOC_START      (0xFFFFFE0000000000)
#define MIN_SYMBOL_VALUE   (KSEG_BASE_48_BIT)

#define PGDIR_SHIFT     (PAGESHIFT() + 2*(PAGESHIFT()-3))
#define PMD_SHIFT       (PAGESHIFT() + (PAGESHIFT()-3))
#define PTRS_PER_PAGE   (1024)

#define PTRS_PER_PGD    (1UL << (PAGESHIFT()-3))

/*
 * OSF/1 PAL-code-imposed page table bits
 */
#define _PAGE_VALID     0x0001
#define _PAGE_FOR       0x0002  /* used for page protection (fault on read) */
#define _PAGE_FOW       0x0004  /* used for page protection (fault on write) */
#define _PAGE_FOE       0x0008  /* used for page protection (fault on exec) */
#define _PAGE_ASM       0x0010
#define _PAGE_KRE       0x0100  /* xxx - see below on the "accessed" bit */
#define _PAGE_URE       0x0200  /* xxx */
#define _PAGE_KWE       0x1000  /* used to do the dirty bit in software */
#define _PAGE_UWE       0x2000  /* used to do the dirty bit in software */

/* .. and these are ours ... */
#define _PAGE_DIRTY     0x20000
#define _PAGE_ACCESSED  0x40000

#define SWP_TYPE(entry) (((entry) >> 32) & 0xff)
#define SWP_OFFSET(entry) ((entry) >> 40)
#define __swp_type(entry)   SWP_TYPE(entry)
#define __swp_offset(entry) SWP_OFFSET(entry)

#define TIF_SIGPENDING (2)

#endif  /* ALPHA */

#ifdef PPC
#define _32BIT_
#define MACHINE_TYPE       "PPC"

#define PAGEBASE(X) 		((X) & machdep->pagemask)

#define PTOV(X)            ((unsigned long)(X)+(machdep->kvbase))
#define VTOP(X)            ((unsigned long)(X)-(machdep->kvbase))
#define IS_VMALLOC_ADDR(X) (vt->vmalloc_start && (ulong)(X) >= vt->vmalloc_start)

/* Holds the platform specific info for page translation */
struct machine_specific {
	char *platform;

	/* page address translation bits */
	int pte_size;
	int pte_rpn_shift;

	/* page flags */
	ulong _page_present;
	ulong _page_user;
	ulong _page_rw;
	ulong _page_guarded;
	ulong _page_coherent;
	ulong _page_no_cache;
	ulong _page_writethru;
	ulong _page_dirty;
	ulong _page_accessed;
	ulong _page_hwwrite;
	ulong _page_shared;
	ulong _page_k_rw;

	/* platform special vtop */
	int (*vtop_special)(ulong vaddr, physaddr_t *paddr, int verbose);
	void *mmu_special;
};

/* machdep flags for ppc32 specific */
#define IS_PAE()		(machdep->flags & PAE)
#define IS_BOOKE()		(machdep->flags & CPU_BOOKE)
/* Page translation bits */
#define PPC_PLATFORM		(machdep->machspec->platform)
#define PTE_SIZE		(machdep->machspec->pte_size)
#define PTE_RPN_SHIFT		(machdep->machspec->pte_rpn_shift)
#define PAGE_SHIFT		(12)
#define PTE_T_LOG2		(ffs(PTE_SIZE) - 1)
#define PTE_SHIFT		(PAGE_SHIFT - PTE_T_LOG2)
#define PGDIR_SHIFT		(PAGE_SHIFT + PTE_SHIFT)
#define PTRS_PER_PGD		(1 << (32 - PGDIR_SHIFT))
#define PTRS_PER_PTE		(1 << PTE_SHIFT)
/* special vtop */
#define VTOP_SPECIAL		(machdep->machspec->vtop_special)
#define MMU_SPECIAL		(machdep->machspec->mmu_special)

/* PFN shifts */
#define BOOKE3E_PTE_RPN_SHIFT	(24)

/* PAGE flags */
#define _PAGE_PRESENT   (machdep->machspec->_page_present)	/* software: pte contains a translation */
#define _PAGE_USER      (machdep->machspec->_page_user)		/* matches one of the PP bits */
#define _PAGE_RW        (machdep->machspec->_page_rw)		/* software: user write access allowed */
#define _PAGE_GUARDED   (machdep->machspec->_page_guarded)
#define _PAGE_COHERENT  (machdep->machspec->_page_coherent	/* M: enforce memory coherence (SMP systems) */)
#define _PAGE_NO_CACHE  (machdep->machspec->_page_no_cache)	/* I: cache inhibit */
#define _PAGE_WRITETHRU (machdep->machspec->_page_writethru)	/* W: cache write-through */
#define _PAGE_DIRTY     (machdep->machspec->_page_dirty)	/* C: page changed */
#define _PAGE_ACCESSED  (machdep->machspec->_page_accessed)	/* R: page referenced */
#define _PAGE_HWWRITE   (machdep->machspec->_page_hwwrite)	/* software: _PAGE_RW & _PAGE_DIRTY */
#define _PAGE_SHARED    (machdep->machspec->_page_shared)
#define _PAGE_K_RW	(machdep->machspec->_page_k_rw)		/* privilege only write access allowed */

/* Default values for PAGE flags */
#define DEFAULT_PAGE_PRESENT   0x001
#define DEFAULT_PAGE_USER      0x002
#define DEFAULT_PAGE_RW        0x004
#define DEFAULT_PAGE_GUARDED   0x008
#define DEFAULT_PAGE_COHERENT  0x010
#define DEFAULT_PAGE_NO_CACHE  0x020
#define DEFAULT_PAGE_WRITETHRU 0x040
#define DEFAULT_PAGE_DIRTY     0x080
#define DEFAULT_PAGE_ACCESSED  0x100
#define DEFAULT_PAGE_HWWRITE   0x200
#define DEFAULT_PAGE_SHARED    0

/* PPC44x PAGE flags: Values from kernel asm/pte-44x.h */
#define PPC44x_PAGE_PRESENT	0x001
#define PPC44x_PAGE_RW		0x002
#define PPC44x_PAGE_ACCESSED	0x008
#define PPC44x_PAGE_DIRTY	0x010
#define PPC44x_PAGE_USER	0x040
#define PPC44x_PAGE_GUARDED	0x100
#define PPC44x_PAGE_COHERENT	0x200
#define PPC44x_PAGE_NO_CACHE	0x400
#define PPC44x_PAGE_WRITETHRU	0x800
#define PPC44x_PAGE_HWWRITE	0
#define PPC44x_PAGE_SHARED	0

/* BOOK3E */
#define BOOK3E_PAGE_PRESENT	0x000001
#define BOOK3E_PAGE_BAP_SR	0x000004
#define BOOK3E_PAGE_BAP_UR	0x000008 /* User Readable */
#define BOOK3E_PAGE_BAP_SW	0x000010
#define BOOK3E_PAGE_BAP_UW	0x000020 /* User Writable */
#define BOOK3E_PAGE_DIRTY	0x001000
#define BOOK3E_PAGE_ACCESSED	0x040000
#define BOOK3E_PAGE_GUARDED	0x100000
#define BOOK3E_PAGE_COHERENT	0x200000
#define BOOK3E_PAGE_NO_CACHE	0x400000
#define BOOK3E_PAGE_WRITETHRU	0x800000
#define BOOK3E_PAGE_HWWRITE	0
#define BOOK3E_PAGE_SHARED	0
#define BOOK3E_PAGE_USER	(BOOK3E_PAGE_BAP_SR | BOOK3E_PAGE_BAP_UR)
#define BOOK3E_PAGE_RW		(BOOK3E_PAGE_BAP_SW | BOOK3E_PAGE_BAP_UW)
#define BOOK3E_PAGE_KERNEL_RW	(BOOK3E_PAGE_BAP_SW | BOOK3E_PAGE_BAP_SR | BOOK3E_PAGE_DIRTY)

/* FSL BOOKE */
#define FSL_BOOKE_PAGE_PRESENT	0x00001
#define FSL_BOOKE_PAGE_USER	0x00002
#define FSL_BOOKE_PAGE_RW	0x00004
#define FSL_BOOKE_PAGE_DIRTY	0x00008
#define FSL_BOOKE_PAGE_ACCESSED	0x00020
#define FSL_BOOKE_PAGE_GUARDED	0x00080
#define FSL_BOOKE_PAGE_COHERENT	0x00100
#define FSL_BOOKE_PAGE_NO_CACHE	0x00200
#define FSL_BOOKE_PAGE_WRITETHRU	0x00400
#define FSL_BOOKE_PAGE_HWWRITE	0
#define FSL_BOOKE_PAGE_SHARED	0

#define SWP_TYPE(entry) (((entry) >> 1) & 0x7f)
#define SWP_OFFSET(entry) ((entry) >> 8)
#define __swp_type(entry)   SWP_TYPE(entry)
#define __swp_offset(entry) SWP_OFFSET(entry)

#define TIF_SIGPENDING (THIS_KERNEL_VERSION >= LINUX(2,6,23) ? 1 : 2)

#define _SECTION_SIZE_BITS	24
#define _MAX_PHYSMEM_BITS	44

#define STACK_FRAME_OVERHEAD	16
#define STACK_FRAME_LR_SAVE	(sizeof(ulong))
#define STACK_FRAME_MARKER	(2 * sizeof(ulong))
#define STACK_FRAME_REGS_MARKER	0x72656773
#define PPC_STACK_SIZE		8192

#endif  /* PPC */

#ifdef IA64
#define _64BIT_
#define MACHINE_TYPE          "IA64"

#define PAGEBASE(X)  (((unsigned long)(X)) & (unsigned long)machdep->pagemask)

#define REGION_SHIFT           (61)
#define VADDR_REGION(X)        ((ulong)(X) >> REGION_SHIFT)

#define KERNEL_CACHED_REGION   (7)
#define KERNEL_UNCACHED_REGION (6)
#define KERNEL_VMALLOC_REGION  (5)
#define USER_STACK_REGION      (4)
#define USER_DATA_REGION       (3)
#define USER_TEXT_REGION       (2)
#define USER_SHMEM_REGION      (1)
#define USER_IA32_EMUL_REGION  (0)

#define KERNEL_VMALLOC_BASE   ((ulong)KERNEL_VMALLOC_REGION << REGION_SHIFT)
#define KERNEL_UNCACHED_BASE  ((ulong)KERNEL_UNCACHED_REGION << REGION_SHIFT)
#define KERNEL_CACHED_BASE    ((ulong)KERNEL_CACHED_REGION << REGION_SHIFT)

#define _SECTION_SIZE_BITS    30
#define _MAX_PHYSMEM_BITS     50

/*
 *  As of 2.6, these are no longer straight forward.
 */
#define PTOV(X)               ia64_PTOV((ulong)(X))
#define VTOP(X)		      ia64_VTOP((ulong)(X))
#define IS_VMALLOC_ADDR(X)    ia64_IS_VMALLOC_ADDR((ulong)(X))

#define SWITCH_STACK_ADDR(X)  (ia64_get_switch_stack((ulong)(X)))

#define __IA64_UL(x)           ((unsigned long)(x))
#define IA64_MAX_PHYS_BITS  (50)  /* max # of phys address bits (architected) */

/*
 * How many pointers will a page table level hold expressed in shift 
 */
#define PTRS_PER_PTD_SHIFT	(PAGESHIFT()-3)

/*
 * Definitions for fourth level:
 */
#define PTRS_PER_PTE	(__IA64_UL(1) << (PTRS_PER_PTD_SHIFT))

/*
 * Definitions for third level:
 *
 * PMD_SHIFT determines the size of the area a third-level page table
 * can map.
 */
#define PMD_SHIFT	(PAGESHIFT() + (PTRS_PER_PTD_SHIFT))
#define PMD_SIZE	(1UL << PMD_SHIFT)
#define PMD_MASK	(~(PMD_SIZE-1))
#define PTRS_PER_PMD	(1UL << (PTRS_PER_PTD_SHIFT))

/*
 * PUD_SHIFT determines the size of the area a second-level page table
 * can map
 */
#define PUD_SHIFT	(PMD_SHIFT + (PTRS_PER_PTD_SHIFT))
#define PUD_SIZE	(1UL << PUD_SHIFT)
#define PUD_MASK	(~(PUD_SIZE-1))
#define PTRS_PER_PUD	(1UL << (PTRS_PER_PTD_SHIFT))

/*
 * Definitions for first level:
 *
 * PGDIR_SHIFT determines what a first-level page table entry can map.
 */

#define PGDIR_SHIFT_4L		(PUD_SHIFT + (PTRS_PER_PTD_SHIFT))
#define PGDIR_SHIFT_3L		(PMD_SHIFT + (PTRS_PER_PTD_SHIFT))
/* Turns out 4L & 3L PGDIR_SHIFT are the same (for now) */
#define PGDIR_SHIFT		PGDIR_SHIFT_4L
#define PGDIR_SIZE		(__IA64_UL(1) << PGDIR_SHIFT)
#define PGDIR_MASK		(~(PGDIR_SIZE-1))
#define PTRS_PER_PGD_SHIFT	PTRS_PER_PTD_SHIFT
#define PTRS_PER_PGD		(1UL << PTRS_PER_PGD_SHIFT)
#define USER_PTRS_PER_PGD	(5*PTRS_PER_PGD/8)	/* regions 0-4 are user regions */
#define FIRST_USER_ADDRESS	0

/*
 * First, define the various bits in a PTE.  Note that the PTE format
 * matches the VHPT short format, the firt doubleword of the VHPD long
 * format, and the first doubleword of the TLB insertion format.
 */
#define _PAGE_P			(1 <<  0)       /* page present bit */
#define _PAGE_MA_WB		(0x0 <<  2)	/* write back memory attribute */
#define _PAGE_MA_UC		(0x4 <<  2)	/* uncacheable memory attribute */
#define _PAGE_MA_UCE		(0x5 <<  2)	/* UC exported attribute */
#define _PAGE_MA_WC		(0x6 <<  2)	/* write coalescing memory attribute */
#define _PAGE_MA_NAT		(0x7 <<  2)	/* not-a-thing attribute */
#define _PAGE_MA_MASK		(0x7 <<  2)
#define _PAGE_PL_0		(0 <<  7)	/* privilege level 0 (kernel) */
#define _PAGE_PL_1		(1 <<  7)	/* privilege level 1 (unused) */
#define _PAGE_PL_2		(2 <<  7)	/* privilege level 2 (unused) */
#define _PAGE_PL_3		(3 <<  7)	/* privilege level 3 (user) */
#define _PAGE_PL_MASK		(3 <<  7)
#define _PAGE_AR_R		(0 <<  9)	/* read only */
#define _PAGE_AR_RX		(1 <<  9)	/* read & execute */
#define _PAGE_AR_RW		(2 <<  9)	/* read & write */
#define _PAGE_AR_RWX		(3 <<  9)	/* read, write & execute */
#define _PAGE_AR_R_RW		(4 <<  9)	/* read / read & write */
#define _PAGE_AR_RX_RWX		(5 <<  9)	/* read & exec / read, write & exec */
#define _PAGE_AR_RWX_RW		(6 <<  9)	/* read, write & exec / read & write */
#define _PAGE_AR_X_RX		(7 <<  9)	/* exec & promote / read & exec */
#define _PAGE_AR_MASK		(7 <<  9)
#define _PAGE_AR_SHIFT		9
#define _PAGE_A			(1 <<  5)	/* page accessed bit */
#define _PAGE_D			(1 <<  6)	/* page dirty bit */
#define _PAGE_PPN_MASK		(((__IA64_UL(1) << IA64_MAX_PHYS_BITS) - 1) & ~0xfffUL)
#define _PAGE_ED		(__IA64_UL(1) << 52)	/* exception deferral */
#define _PAGE_PROTNONE		(__IA64_UL(1) << 63)

#define _PFN_MASK		_PAGE_PPN_MASK
#define _PAGE_CHG_MASK		(_PFN_MASK | _PAGE_A | _PAGE_D)

#define _PAGE_SIZE_4K	12
#define _PAGE_SIZE_8K	13
#define _PAGE_SIZE_16K	14
#define _PAGE_SIZE_64K	16
#define _PAGE_SIZE_256K	18
#define _PAGE_SIZE_1M	20
#define _PAGE_SIZE_4M	22
#define _PAGE_SIZE_16M	24
#define _PAGE_SIZE_64M	26
#define _PAGE_SIZE_256M	28

#define __ACCESS_BITS		_PAGE_ED | _PAGE_A | _PAGE_P | _PAGE_MA_WB
#define __DIRTY_BITS_NO_ED	_PAGE_A | _PAGE_P | _PAGE_D | _PAGE_MA_WB
#define __DIRTY_BITS		_PAGE_ED | __DIRTY_BITS_NO_ED

#define EFI_PAGE_SHIFT  (12)

/*
 * NOTE: #include'ing <asm/efi.h> creates too many compiler problems, so
 * this stuff is hardwired here; it's probably etched in stone somewhere.
 */
struct efi_memory_desc_t {
        uint32_t type;
        uint32_t pad;
        uint64_t phys_addr;
        uint64_t virt_addr;
        uint64_t num_pages;
        uint64_t attribute;
} desc;

/* Memory types: */
#define EFI_RESERVED_TYPE                0
#define EFI_LOADER_CODE                  1
#define EFI_LOADER_DATA                  2
#define EFI_BOOT_SERVICES_CODE           3
#define EFI_BOOT_SERVICES_DATA           4
#define EFI_RUNTIME_SERVICES_CODE        5
#define EFI_RUNTIME_SERVICES_DATA        6
#define EFI_CONVENTIONAL_MEMORY          7
#define EFI_UNUSABLE_MEMORY              8
#define EFI_ACPI_RECLAIM_MEMORY          9
#define EFI_ACPI_MEMORY_NVS             10
#define EFI_MEMORY_MAPPED_IO            11
#define EFI_MEMORY_MAPPED_IO_PORT_SPACE 12
#define EFI_PAL_CODE                    13
#define EFI_MAX_MEMORY_TYPE             14

/* Attribute values: */
#define EFI_MEMORY_UC           0x0000000000000001      /* uncached */
#define EFI_MEMORY_WC           0x0000000000000002      /* write-coalescing */
#define EFI_MEMORY_WT           0x0000000000000004      /* write-through */
#define EFI_MEMORY_WB           0x0000000000000008      /* write-back */
#define EFI_MEMORY_WP           0x0000000000001000      /* write-protect */
#define EFI_MEMORY_RP           0x0000000000002000      /* read-protect */
#define EFI_MEMORY_XP           0x0000000000004000      /* execute-protect */
#define EFI_MEMORY_RUNTIME      0x8000000000000000      /* range requires runtime mapping */

#define SWP_TYPE(entry)    (((entry) >> 1) & 0xff)
#define SWP_OFFSET(entry)  ((entry) >> 9)
#define __swp_type(entry)    ((entry >> 2) & 0x7f)
#define __swp_offset(entry)  ((entry << 1) >> 10)

#define TIF_SIGPENDING (THIS_KERNEL_VERSION >= LINUX(2,6,23) ? 0 : 1)

#define KERNEL_TR_PAGE_SIZE (1 << _PAGE_SIZE_64M)
#define KERNEL_TR_PAGE_MASK (~(KERNEL_TR_PAGE_SIZE - 1))

#define UNKNOWN_PHYS_START ((ulong)(-1))
#define DEFAULT_PHYS_START (KERNEL_TR_PAGE_SIZE * 1)

#define IA64_GET_STACK_ULONG(OFF) \
        ((INSTACK(OFF,bt)) ? (GET_STACK_ULONG(OFF)) : get_init_stack_ulong((unsigned long)OFF))

#endif  /* IA64 */

#ifdef PPC64
#define _64BIT_
#define MACHINE_TYPE       "PPC64"

#define PPC64_64K_PAGE_SIZE  65536
#define PPC64_STACK_SIZE     16384

#define PAGEBASE(X)  (((ulong)(X)) & (ulong)machdep->pagemask)

#define PTOV(X)            ((unsigned long)(X)+(machdep->identity_map_base))
#define VTOP(X)            ((unsigned long)(X)-(machdep->identity_map_base))
#define BOOK3E_VMBASE 0x8000000000000000
#define IS_VMALLOC_ADDR(X) machdep->machspec->is_vmaddr(X)
#define KERNELBASE      machdep->pageoffset

#define PGDIR_SHIFT     (machdep->pageshift + (machdep->pageshift -3) + (machdep->pageshift - 2))
#define PMD_SHIFT       (machdep->pageshift + (machdep->pageshift - 3))

#define PGD_MASK        (~((1UL << PGDIR_SHIFT) - 1))
#define PMD_MASK        (~((1UL << PMD_SHIFT) - 1))

/* shift to put page number into pte */
#define PTE_RPN_SHIFT_DEFAULT 16
#define PMD_TO_PTEPAGE_SHIFT 2  /* Used for 2.6 or later */

#define PTE_INDEX_SIZE  9
#define PMD_INDEX_SIZE  10
#define PGD_INDEX_SIZE  10

#define PTRS_PER_PTE    (1 << PTE_INDEX_SIZE)
#define PTRS_PER_PMD    (1 << PMD_INDEX_SIZE)
#define PTRS_PER_PGD    (1 << PGD_INDEX_SIZE)

#define PGD_OFFSET_24(vaddr)    ((vaddr >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#define PGD_OFFSET(vaddr)       ((vaddr >> PGDIR_SHIFT) & 0x7ff)
#define PMD_OFFSET(vaddr)       ((vaddr >> PMD_SHIFT) & (PTRS_PER_PMD - 1))

/* 4-level page table support */

/* 4K pagesize */
#define PTE_INDEX_SIZE_L4_4K  9
#define PMD_INDEX_SIZE_L4_4K  7
#define PUD_INDEX_SIZE_L4_4K  7
#define PGD_INDEX_SIZE_L4_4K  9
#define PUD_INDEX_SIZE_L4_4K_3_7  9
#define PTE_INDEX_SIZE_RADIX_4K  9
#define PMD_INDEX_SIZE_RADIX_4K  9
#define PUD_INDEX_SIZE_RADIX_4K  9
#define PGD_INDEX_SIZE_RADIX_4K  13
#define PTE_RPN_SHIFT_L4_4K  17
#define PTE_RPN_SHIFT_L4_4K_4_5  18
#define PGD_MASKED_BITS_4K  0
#define PUD_MASKED_BITS_4K  0
#define PMD_MASKED_BITS_4K  0

/* 64K pagesize */
#define PTE_INDEX_SIZE_L4_64K  12
#define PMD_INDEX_SIZE_L4_64K  12
#define PUD_INDEX_SIZE_L4_64K  0
#define PGD_INDEX_SIZE_L4_64K  4
#define PTE_INDEX_SIZE_L4_64K_3_10  8
#define PMD_INDEX_SIZE_L4_64K_3_10  10
#define PGD_INDEX_SIZE_L4_64K_3_10  12
#define PMD_INDEX_SIZE_L4_64K_4_6  5
#define PUD_INDEX_SIZE_L4_64K_4_6  5
#define PMD_INDEX_SIZE_L4_64K_4_12 10
#define PUD_INDEX_SIZE_L4_64K_4_12 7
#define PGD_INDEX_SIZE_L4_64K_4_12 8
#define PUD_INDEX_SIZE_L4_64K_4_17 10
#define PTE_INDEX_SIZE_RADIX_64K  5
#define PMD_INDEX_SIZE_RADIX_64K  9
#define PUD_INDEX_SIZE_RADIX_64K  9
#define PGD_INDEX_SIZE_RADIX_64K  13
#define PTE_RPN_SHIFT_L4_64K_V1  32
#define PTE_RPN_SHIFT_L4_64K_V2  30
#define PTE_RPN_SHIFT_L4_BOOK3E_64K 28
#define PTE_RPN_SHIFT_L4_BOOK3E_4K 24
#define PGD_MASKED_BITS_64K  0
#define PUD_MASKED_BITS_64K  0x1ff
#define PMD_MASKED_BITS_64K  0x1ff
#define PMD_MASKED_BITS_64K_3_11 0xfff
#define PMD_MASKED_BITS_BOOK3E_64K_4_5 0x7ff
#define PGD_MASKED_BITS_64K_4_6  0xc0000000000000ffUL
#define PUD_MASKED_BITS_64K_4_6  0xc0000000000000ffUL
#define PMD_MASKED_BITS_64K_4_6  0xc0000000000000ffUL

#define PTE_RPN_MASK_DEFAULT  0xffffffffffffffffUL
#define PAGE_PA_MAX_L4_4_6    (THIS_KERNEL_VERSION >= LINUX(4,11,0) ? 53 : 57)
#define PTE_RPN_MASK_L4_4_6   \
	(((1UL << PAGE_PA_MAX_L4_4_6) - 1) & ~((1UL << PAGESHIFT()) - 1))
#define PTE_RPN_SHIFT_L4_4_6  PAGESHIFT()

#define PGD_MASKED_BITS_4_7  0xc0000000000000ffUL
#define PUD_MASKED_BITS_4_7  0xc0000000000000ffUL
#define PMD_MASKED_BITS_4_7  0xc0000000000000ffUL

#define PD_HUGE           0x8000000000000000
#define HUGE_PTE_MASK     0x03
#define HUGEPD_SHIFT_MASK 0x3f
#define HUGEPD_ADDR_MASK  (0x0fffffffffffffffUL & ~HUGEPD_SHIFT_MASK)

#define PGD_MASK_L4		\
	(THIS_KERNEL_VERSION >= LINUX(3,10,0) ? (machdep->ptrs_per_pgd - 1) : 0x1ff)

#define PGD_OFFSET_L4(vaddr)	\
	((vaddr >> (machdep->machspec->l4_shift)) & PGD_MASK_L4)

#define PUD_OFFSET_L4(vaddr)	\
	((vaddr >> (machdep->machspec->l3_shift)) & (machdep->machspec->ptrs_per_l3 - 1))

#define PMD_OFFSET_L4(vaddr)	\
	((vaddr >> (machdep->machspec->l2_shift)) & (machdep->machspec->ptrs_per_l2 - 1))

#define _PAGE_PTE       (machdep->machspec->_page_pte)          /* distinguishes PTEs from pointers */
#define _PAGE_PRESENT   (machdep->machspec->_page_present)      /* software: pte contains a translation */
#define _PAGE_USER      (machdep->machspec->_page_user)         /* matches one of the PP bits */
#define _PAGE_RW        (machdep->machspec->_page_rw)           /* software: user write access allowed */
#define _PAGE_GUARDED   (machdep->machspec->_page_guarded)
#define _PAGE_COHERENT  (machdep->machspec->_page_coherent      /* M: enforce memory coherence (SMP systems) */)
#define _PAGE_NO_CACHE  (machdep->machspec->_page_no_cache)     /* I: cache inhibit */
#define _PAGE_WRITETHRU (machdep->machspec->_page_writethru)    /* W: cache write-through */
#define _PAGE_DIRTY     (machdep->machspec->_page_dirty)        /* C: page changed */
#define _PAGE_ACCESSED  (machdep->machspec->_page_accessed)     /* R: page referenced */

#define PTE_RPN_MASK    (machdep->machspec->pte_rpn_mask)
#define PTE_RPN_SHIFT   (machdep->machspec->pte_rpn_shift)

#define TIF_SIGPENDING (THIS_KERNEL_VERSION >= LINUX(2,6,23) ? 1 : 2)

#define SWP_TYPE(entry) (((entry) >> 1) & 0x7f)
#define SWP_OFFSET(entry) ((entry) >> 8)
#define __swp_type(entry)   SWP_TYPE(entry)
#define __swp_offset(entry) SWP_OFFSET(entry)

#define MSR_PR_LG	14	/* Problem State / Privilege Level */
				/* Used to find the user or kernel-mode frame*/

#define STACK_FRAME_OVERHEAD            112
#define EXCP_FRAME_MARKER               0x7265677368657265

#define _SECTION_SIZE_BITS	24
#define _MAX_PHYSMEM_BITS	44
#define _MAX_PHYSMEM_BITS_3_7   46
#define _MAX_PHYSMEM_BITS_4_19  47
#define _MAX_PHYSMEM_BITS_4_20  51

#endif /* PPC64 */

#ifdef S390
#define _32BIT_
#define MACHINE_TYPE       "S390"

#define PTOV(X)            ((unsigned long)(X)+(machdep->kvbase))
#define VTOP(X)            ((unsigned long)(X)-(machdep->kvbase))
#define IS_VMALLOC_ADDR(X) (vt->vmalloc_start && (ulong)(X) >= vt->vmalloc_start)

#define PTRS_PER_PTE    1024
#define PTRS_PER_PMD    1
#define PTRS_PER_PGD    512
#define SEGMENT_TABLE_SIZE  ((sizeof(ulong)*4) * PTRS_PER_PGD)  

#define SWP_TYPE(entry) (((entry) >> 2) & 0x1f)
#define SWP_OFFSET(entry) ((((entry) >> 11) & 0xfffffffe) | \
                           (((entry) >> 7) & 0x1))
#define __swp_type(entry)   SWP_TYPE(entry)
#define __swp_offset(entry) SWP_OFFSET(entry)

#define TIF_SIGPENDING (THIS_KERNEL_VERSION >= LINUX(3,16,0) ? 1 : 2)

#define _SECTION_SIZE_BITS	25
#define _MAX_PHYSMEM_BITS	31

#endif  /* S390 */

#ifdef S390X
#define _64BIT_
#define MACHINE_TYPE       "S390X"

#define PTOV(X)            ((unsigned long)(X)+(machdep->kvbase))
#define VTOP(X)            ((unsigned long)(X)-(machdep->kvbase))
#define IS_VMALLOC_ADDR(X) (vt->vmalloc_start && (ulong)(X) >= vt->vmalloc_start)
#define PTRS_PER_PTE    512
#define PTRS_PER_PMD    1024
#define PTRS_PER_PGD    2048
#define SEGMENT_TABLE_SIZE    ((sizeof(ulong)*2) * PTRS_PER_PMD)

#define SWP_TYPE(entry)   (((entry) >> 2) & 0x1f)
#define SWP_OFFSET(entry) ((((entry) >> 11) & 0xfffffffffffffffe) | \
                           (((entry) >> 7) & 0x1)) 
#define __swp_type(entry)  SWP_TYPE(entry)
#define __swp_offset(entry) SWP_OFFSET(entry)

#define TIF_SIGPENDING (THIS_KERNEL_VERSION >= LINUX(3,16,0) ? 1 : 2)

#define _SECTION_SIZE_BITS	28
#define _MAX_PHYSMEM_BITS_OLD	42
#define _MAX_PHYSMEM_BITS_NEW	46

#endif  /* S390X */

#ifdef SPARC64
#define _64BIT_
#define MACHINE_TYPE       "SPARC64"

#define PTOV(X) \
	((unsigned long)(X) + machdep->machspec->page_offset)
#define VTOP(X) \
	((unsigned long)(X) - machdep->machspec->page_offset)

#define PAGE_OFFSET     (machdep->machspec->page_offset)

extern int sparc64_IS_VMALLOC_ADDR(ulong vaddr);
#define IS_VMALLOC_ADDR(X)    sparc64_IS_VMALLOC_ADDR((ulong)(X))
#define PAGE_SHIFT	(13)
#define PAGE_SIZE	(1UL << PAGE_SHIFT)
#define PAGE_MASK	(~(PAGE_SIZE - 1))
#define PAGEBASE(X)     (((ulong)(X)) & (ulong)machdep->pagemask)
#define THREAD_SIZE	(2 * PAGE_SIZE)

/* S3 Core
 *	Core 48-bit physical address supported.
 *	Bit 47 distinguishes memory or I/O. When set to "1" it is I/O.
 */
#define PHYS_MASK_SHIFT   (47)
#define PHYS_MASK         (((1UL) << PHYS_MASK_SHIFT) - 1)

typedef signed int s32;

/*
 * This next two defines are convenience defines for normal page table.
 */
#define PTES_PER_PAGE		(1UL << (PAGE_SHIFT - 3))
#define PTES_PER_PAGE_MASK	(PTES_PER_PAGE - 1)

/* 4-level page table */
#define PMD_SHIFT	(PAGE_SHIFT + (PAGE_SHIFT-3))
#define PMD_SIZE	(1UL << PMD_SHIFT)
#define PMD_MASK	(~(PMD_SIZE - 1))
#define PMD_BITS	(PAGE_SHIFT - 3)

#define PUD_SHIFT	(PMD_SHIFT + PMD_BITS)
#define PUD_SIZE	(1UL << PUD_SHIFT)
#define PUD_MASK	(~(PUD_SIZE - 1))
#define PUD_BITS	(PAGE_SHIFT - 3)

#define PGDIR_SHIFT	(PUD_SHIFT + PUD_BITS)
#define PGDIR_SIZE	(1UL << PGDIR_SHIFT)
#define PGDIR_MASK	(~(PGDIR_SIZE - 1))
#define PGDIR_BITS	(PAGE_SHIFT - 3)

#define PTRS_PER_PTE	(1UL << (PAGE_SHIFT - 3))
#define PTRS_PER_PMD	(1UL << PMD_BITS)
#define PTRS_PER_PUD	(1UL << PUD_BITS)
#define PTRS_PER_PGD	(1UL << PGDIR_BITS)

#define HPAGE_SHIFT		(23)
/* Down one huge page */
#define SPARC64_USERSPACE_TOP  (-(1UL << HPAGE_SHIFT))
#define PAGE_PMD_HUGE		 (0x0100000000000000UL)

/* These are for SUN4V.  */
#define _PAGE_VALID		(0x8000000000000000UL)
#define _PAGE_NFO_4V		(0x4000000000000000UL)
#define	_PAGE_MODIFIED_4V	(0x2000000000000000UL)
#define	_PAGE_ACCESSED_4V	(0x1000000000000000UL)
#define	_PAGE_READ_4V		(0x0800000000000000UL)
#define	_PAGE_WRITE_4V		(0x0400000000000000UL)
#define	_PAGE_PADDR_4V		(0x00FFFFFFFFFFE000UL)
#define _PAGE_PFN_MASK		(_PAGE_PADDR_4V)
#define	_PAGE_P_4V		(0x0000000000000100UL)
#define	_PAGE_EXEC_4V		(0x0000000000000080UL)
#define	_PAGE_W_4V		(0x0000000000000040UL)
#define _PAGE_PRESENT_4V	(0x0000000000000010UL)
#define	_PAGE_SZALL_4V		(0x0000000000000007UL)
/* There are other page sizes. Some supported. */
#define	_PAGE_SZ4MB_4V		(0x0000000000000003UL)
#define	_PAGE_SZ512K_4V		(0x0000000000000002UL)
#define	_PAGE_SZ64K_4V		(0x0000000000000001UL)
#define _PAGE_SZ8K_4V		(0x0000000000000000UL)

#define SPARC64_MODULES_VADDR	(0x0000000010000000UL)
#define SPARC64_MODULES_END	(0x00000000f0000000UL)
#define SPARC64_VMALLOC_START	(0x0000000100000000UL)

#define SPARC64_STACK_SIZE	0x4000

/* sparsemem */
#define _SECTION_SIZE_BITS	30
#define _MAX_PHYSMEM_BITS	53

#define STACK_BIAS	2047

struct machine_specific {
	ulong page_offset;
	ulong vmalloc_end;
};

#define TIF_SIGPENDING	(2)
#define SWP_OFFSET(E)	((E) >> (PAGE_SHIFT + 8UL))
#define SWP_TYPE(E)	(((E) >> PAGE_SHIFT) & 0xffUL)
#define __swp_type(E)	SWP_TYPE(E)
#define	__swp_offset(E)	SWP_OFFSET(E)
#endif /* SPARC64 */

#ifdef PLATFORM

#define SWP_TYPE(entry)   (error("PLATFORM_SWP_TYPE: TBD\n"))
#define SWP_OFFSET(entry) (error("PLATFORM_SWP_OFFSET: TBD\n"))
#define __swp_type(entry)   SWP_TYPE(entry)
#define __swp_offset(entry) SWP_OFFSET(entry)

#endif /* PLATFORM */

#define KILOBYTES(x)  ((x) * (1024))
#define MEGABYTES(x)  ((x) * (1048576))
#define GIGABYTES(x)  ((x) * (1073741824))
#define TB_SHIFT (40)
#define TERABYTES(x) ((x) * (1UL << TB_SHIFT))

#define MEGABYTE_MASK (MEGABYTES(1)-1)

#define SIZEOF_64BIT  (8)
#define SIZEOF_32BIT  (4)
#define SIZEOF_16BIT  (2)
#define SIZEOF_8BIT   (1)

#ifdef ARM
#define MAX_HEXADDR_STRLEN (8)
#define UVADDR_PRLEN       (8)
#endif
#ifdef X86
#define MAX_HEXADDR_STRLEN (8)             
#define UVADDR_PRLEN       (8)
#endif
#ifdef ALPHA
#define MAX_HEXADDR_STRLEN (16)             
#define UVADDR_PRLEN       (11)
#endif
#ifdef PPC
#define MAX_HEXADDR_STRLEN (8)             
#define UVADDR_PRLEN       (8)
#endif
#ifdef IA64
#define MAX_HEXADDR_STRLEN (16)
#define UVADDR_PRLEN       (16)
#endif
#ifdef S390
#define MAX_HEXADDR_STRLEN (8)
#define UVADDR_PRLEN       (8)
#endif
#ifdef S390X
#define MAX_HEXADDR_STRLEN (16)
#define UVADDR_PRLEN       (16)
#endif
#ifdef X86_64
#define MAX_HEXADDR_STRLEN (16)
#define UVADDR_PRLEN       (10)
#endif
#ifdef PPC64
#define MAX_HEXADDR_STRLEN (16)
#define UVADDR_PRLEN       (16)
#endif
#ifdef ARM64
#define MAX_HEXADDR_STRLEN (16)
#define UVADDR_PRLEN       (10)
#endif
#ifdef MIPS
#define MAX_HEXADDR_STRLEN (8)
#define UVADDR_PRLEN       (8)
#endif
#ifdef MIPS64
#define MAX_HEXADDR_STRLEN (16)
#define UVADDR_PRLEN       (16)
#endif
#ifdef SPARC64
#define MAX_HEXADDR_STRLEN (16)
#define UVADDR_PRLEN      (16)
#endif
#ifdef RISCV64
#define MAX_HEXADDR_STRLEN (16)
#define UVADDR_PRLEN       (16)
#endif

#define BADADDR  ((ulong)(-1))
#define BADVAL   ((ulong)(-1))
#define UNUSED   (-1)

#define UNINITIALIZED (BADVAL)

#define BITS_PER_BYTE (8)
#define BITS_PER_LONG (BITS_PER_BYTE * sizeof(long))
#define NUM_TO_BIT(x) (1UL<<((x)%BITS_PER_LONG))
#define NUM_IN_BITMAP(bitmap, x) (bitmap[(x)/BITS_PER_LONG] & NUM_TO_BIT(x))
#define SET_BIT(bitmap, x) (bitmap[(x)/BITS_PER_LONG] |= NUM_TO_BIT(x))

static inline unsigned int __const_hweight8(unsigned long w)
{
	return
		(!!((w) & (1ULL << 0))) +
		(!!((w) & (1ULL << 1))) +
		(!!((w) & (1ULL << 2))) +
		(!!((w) & (1ULL << 3))) +
		(!!((w) & (1ULL << 4))) +
		(!!((w) & (1ULL << 5))) +
		(!!((w) & (1ULL << 6))) +
		(!!((w) & (1ULL << 7)));
}

#define __const_hweight16(w) (__const_hweight8(w)  + __const_hweight8((w)  >> 8))
#define __const_hweight32(w) (__const_hweight16(w) + __const_hweight16((w) >> 16))
#define __const_hweight64(w) (__const_hweight32(w) + __const_hweight32((w) >> 32))

#define hweight32(w) __const_hweight32(w)
#define hweight64(w) __const_hweight64(w)

/*
 *  precision lengths for fprintf
 */ 
#define VADDR_PRLEN      (sizeof(char *) == 8 ? 16 : 8)
#define LONG_LONG_PRLEN  (16)
#define LONG_PRLEN       (sizeof(long) == 8 ? 16 : 8)
#define INT_PRLEN        (sizeof(int) == 8 ? 16 : 8)
#define CHAR_PRLEN       (2)
#define SHORT_PRLEN      (4)

#define MINSPACE  (-100)

#define SYNOPSIS       (0x1)
#define COMPLETE_HELP  (0x2)
#define PIPE_TO_SCROLL (0x4)
#define MUST_HELP      (0x8)

#define LEFT_JUSTIFY   (1)
#define RIGHT_JUSTIFY  (2)

#define CENTER       (0x1)
#define LJUST        (0x2)
#define RJUST        (0x4)
#define LONG_DEC     (0x8)
#define LONG_HEX     (0x10)
#define INT_DEC      (0x20)
#define INT_HEX      (0x40)
#define LONGLONG_HEX (0x80)
#define ZERO_FILL   (0x100)
#define SLONG_DEC   (0x200)

#define INIT_TIME (1)
#define RUN_TIME  (2)

/*
 * IRQ line status.
 * For kernels up to and including 2.6.17
 */
#define IRQ_INPROGRESS_2_6_17  1       /* IRQ handler active - do not enter! */
#define IRQ_DISABLED_2_6_17    2       /* IRQ disabled - do not enter! */
#define IRQ_PENDING_2_6_17     4       /* IRQ pending - replay on enable */
#define IRQ_REPLAY_2_6_17      8       /* IRQ has been replayed but not acked yet */
#define IRQ_AUTODETECT_2_6_17  16      /* IRQ is being autodetected */
#define IRQ_WAITING_2_6_17     32      /* IRQ not yet seen - for autodetection */
#define IRQ_LEVEL_2_6_17       64      /* IRQ level triggered */
#define IRQ_MASKED_2_6_17      128     /* IRQ masked - shouldn't be seen again */

/*
 * For kernel 2.6.21 and later
 */
#define IRQ_TYPE_NONE_2_6_21		0x00000000	/* Default, unspecified type */
#define IRQ_TYPE_EDGE_RISING_2_6_21	0x00000001	/* Edge rising type */
#define IRQ_TYPE_EDGE_FALLING_2_6_21	0x00000002	/* Edge falling type */
#define IRQ_TYPE_EDGE_BOTH_2_6_21 	(IRQ_TYPE_EDGE_FALLING | IRQ_TYPE_EDGE_RISING)
#define IRQ_TYPE_LEVEL_HIGH_2_6_21	0x00000004	/* Level high type */
#define IRQ_TYPE_LEVEL_LOW_2_6_21	0x00000008	/* Level low type */
#define IRQ_TYPE_SENSE_MASK_2_6_21	0x0000000f	/* Mask of the above */
#define IRQ_TYPE_PROBE_2_6_21		0x00000010	/* Probing in progress */

#define IRQ_INPROGRESS_2_6_21		0x00000100	/* IRQ handler active - do not enter! */
#define IRQ_DISABLED_2_6_21		0x00000200	/* IRQ disabled - do not enter! */
#define IRQ_PENDING_2_6_21		0x00000400	/* IRQ pending - replay on enable */
#define IRQ_REPLAY_2_6_21		0x00000800	/* IRQ has been replayed but not acked yet */
#define IRQ_AUTODETECT_2_6_21		0x00001000	/* IRQ is being autodetected */
#define IRQ_WAITING_2_6_21		0x00002000	/* IRQ not yet seen - for autodetection */
#define IRQ_LEVEL_2_6_21		0x00004000	/* IRQ level triggered */
#define IRQ_MASKED_2_6_21		0x00008000	/* IRQ masked - shouldn't be seen again */
#define IRQ_PER_CPU_2_6_21		0x00010000	/* IRQ is per CPU */
#define IRQ_NOPROBE_2_6_21		0x00020000	/* IRQ is not valid for probing */
#define IRQ_NOREQUEST_2_6_21		0x00040000	/* IRQ cannot be requested */
#define IRQ_NOAUTOEN_2_6_21		0x00080000	/* IRQ will not be enabled on request irq */
#define IRQ_WAKEUP_2_6_21		0x00100000	/* IRQ triggers system wakeup */
#define IRQ_MOVE_PENDING_2_6_21		0x00200000	/* need to re-target IRQ destination */
#define IRQ_NO_BALANCING_2_6_21		0x00400000	/* IRQ is excluded from balancing */
#define IRQ_SPURIOUS_DISABLED_2_6_21	0x00800000	/* IRQ was disabled by the spurious trap */
#define IRQ_MOVE_PCNTXT_2_6_21		0x01000000	/* IRQ migration from process context */
#define IRQ_AFFINITY_SET_2_6_21		0x02000000	/* IRQ affinity was set from userspace*/

/*
 * Select proper IRQ value depending on kernel version
 */
#define IRQ_TYPE_NONE		\
	(THIS_KERNEL_VERSION >= LINUX(2,6,21) ? IRQ_TYPE_NONE_2_6_21 : 0)
#define IRQ_TYPE_EDGE_RISING	\
	(THIS_KERNEL_VERSION >= LINUX(2,6,21) ? IRQ_TYPE_EDGE_RISING_2_6_21 : 0)
#define IRQ_TYPE_EDGE_FALLING	\
	(THIS_KERNEL_VERSION >= LINUX(2,6,21) ? IRQ_TYPE_EDGE_FALLING_2_6_21 : 0)
#define IRQ_TYPE_EDGE_BOTH	\
	(THIS_KERNEL_VERSION >= LINUX(2,6,21) ? IRQ_TYPE_EDGE_BOTH_2_6_21 : 0)
#define IRQ_TYPE_LEVEL_HIGH	\
	(THIS_KERNEL_VERSION >= LINUX(2,6,21) ? IRQ_TYPE_LEVEL_HIGH_2_6_21 : 0)
#define IRQ_TYPE_LEVEL_LOW	\
	(THIS_KERNEL_VERSION >= LINUX(2,6,21) ? IRQ_TYPE_LEVEL_LOW_2_6_21 : 0)
#define IRQ_TYPE_SENSE_MASK	\
	(THIS_KERNEL_VERSION >= LINUX(2,6,21) ? IRQ_TYPE_SENSE_MASK_2_6_21 : 0)
#define IRQ_TYPE_PROBE		\
	(THIS_KERNEL_VERSION >= LINUX(2,6,21) ? IRQ_TYPE_PROBE_2_6_21 : 0)

#define IRQ_INPROGRESS		\
	(THIS_KERNEL_VERSION >= LINUX(2,6,21) ? IRQ_INPROGRESS_2_6_21 : IRQ_INPROGRESS_2_6_17)
#define IRQ_DISABLED		\
	(THIS_KERNEL_VERSION >= LINUX(2,6,21) ? IRQ_DISABLED_2_6_21 : IRQ_DISABLED_2_6_17)
#define IRQ_PENDING		\
	(THIS_KERNEL_VERSION >= LINUX(2,6,21) ? IRQ_PENDING_2_6_21 : IRQ_PENDING_2_6_17)
#define IRQ_REPLAY		\
	(THIS_KERNEL_VERSION >= LINUX(2,6,21) ? IRQ_REPLAY_2_6_21 : IRQ_REPLAY_2_6_17)
#define IRQ_AUTODETECT		\
	(THIS_KERNEL_VERSION >= LINUX(2,6,21) ? IRQ_AUTODETECT_2_6_21 : IRQ_AUTODETECT_2_6_17)
#define IRQ_WAITING		\
	(THIS_KERNEL_VERSION >= LINUX(2,6,21) ? IRQ_WAITING_2_6_21 : IRQ_WAITING_2_6_17)
#define IRQ_LEVEL		\
	(THIS_KERNEL_VERSION >= LINUX(2,6,21) ? IRQ_LEVEL_2_6_21 : IRQ_LEVEL_2_6_17)
#define IRQ_MASKED		\
	(THIS_KERNEL_VERSION >= LINUX(2,6,21) ? IRQ_MASKED_2_6_21 : IRQ_MASKED_2_6_17)
#define IRQ_PER_CPU		\
	(THIS_KERNEL_VERSION >= LINUX(2,6,21) ? IRQ_PER_CPU_2_6_21 : 0)
#define IRQ_NOPROBE		\
	(THIS_KERNEL_VERSION >= LINUX(2,6,21) ? IRQ_NOPROBE_2_6_21 : 0)
#define IRQ_NOREQUEST		\
	(THIS_KERNEL_VERSION >= LINUX(2,6,21) ? IRQ_NOREQUEST_2_6_21 : 0)
#define IRQ_NOAUTOEN		\
	(THIS_KERNEL_VERSION >= LINUX(2,6,21) ? IRQ_NOAUTOEN_2_6_21 : 0)
#define IRQ_WAKEUP		\
	(THIS_KERNEL_VERSION >= LINUX(2,6,21) ? IRQ_WAKEUP_2_6_21 : 0)
#define IRQ_MOVE_PENDING	\
	(THIS_KERNEL_VERSION >= LINUX(2,6,21) ? IRQ_MOVE_PENDING_2_6_21 : 0)
#define IRQ_NO_BALANCING	\
	(THIS_KERNEL_VERSION >= LINUX(2,6,21) ? IRQ_NO_BALANCING_2_6_21 : 0)
#define IRQ_SPURIOUS_DISABLED	\
	(THIS_KERNEL_VERSION >= LINUX(2,6,21) ? IRQ_SPURIOUS_DISABLED_2_6_21 : 0)
#define IRQ_MOVE_PCNTXT		\
	(THIS_KERNEL_VERSION >= LINUX(2,6,21) ? IRQ_MOVE_PCNTXT_2_6_21 : 0)
#define IRQ_AFFINITY_SET	\
	(THIS_KERNEL_VERSION >= LINUX(2,6,21) ? IRQ_AFFINITY_SET_2_6_21 : 0)

#ifdef ARM
#define SA_PROBE                SA_ONESHOT
#define SA_SAMPLE_RANDOM        SA_RESTART
#define SA_SHIRQ                0x04000000
#define SA_RESTORER             0x04000000
#endif

#ifdef X86
#define SA_PROBE                SA_ONESHOT
#define SA_SAMPLE_RANDOM        SA_RESTART
#define SA_SHIRQ                0x04000000
#define SA_RESTORER             0x04000000
#endif

#ifdef X86_64
#define SA_PROBE                SA_ONESHOT
#define SA_SAMPLE_RANDOM        SA_RESTART
#define SA_SHIRQ                0x04000000
#define SA_RESTORER             0x04000000
#endif

#ifdef ALPHA
#define SA_PROBE                SA_ONESHOT
#define SA_SAMPLE_RANDOM        SA_RESTART
#define SA_SHIRQ                0x40000000
#endif

#ifdef PPC
#define SA_PROBE                SA_ONESHOT
#define SA_SAMPLE_RANDOM        SA_RESTART
#define SA_SHIRQ                0x04000000
#define SA_RESTORER             0x04000000
#endif

#ifdef PPC64
#define SA_PROBE                SA_ONESHOT
#define SA_SAMPLE_RANDOM        SA_RESTART
#define SA_SHIRQ                0x04000000
#define SA_RESTORER             0x04000000u
#endif

#ifdef IA64
#define SA_PROBE                SA_ONESHOT
#define SA_SAMPLE_RANDOM        SA_RESTART
#define SA_SHIRQ                0x04000000
#define SA_RESTORER             0x04000000
#endif

#ifdef S390
#define SA_PROBE                SA_ONESHOT
#define SA_SAMPLE_RANDOM        SA_RESTART
#define SA_SHIRQ                0x04000000
#define SA_RESTORER     	0x04000000
#endif

#ifdef S390X
#define SA_PROBE                SA_ONESHOT
#define SA_SAMPLE_RANDOM        SA_RESTART
#define SA_SHIRQ                0x04000000
#define SA_RESTORER     	0x04000000
#endif


#define ACTION_FLAGS (SA_INTERRUPT|SA_PROBE|SA_SAMPLE_RANDOM|SA_SHIRQ)


#endif /* !GDB_COMMON */

typedef enum drill_ops_s {
	EOP_MEMBER_SIZES,
	EOP_MEMBER_NAME,
	EOP_POINTER,
	EOP_TYPEDEF,
	EOP_INT,
	EOP_VALUE,
	EOP_ARRAY,
	EOP_UNION,
	EOP_ENUM,
	EOP_ENUMVAL,
	EOP_STRUCT,
	EOP_FUNCTION,
	EOP_DONE,
	EOP_OOPS
} drill_ops_t;

/*
 *  Common request structure for BFD or GDB data or commands.
 */
struct gnu_request {    
	int command;
	char *buf;
	FILE *fp;
	ulong addr;
	ulong addr2;
	ulong count;
	ulong flags;
	char *name;
	ulong length;
	int typecode;
#if defined(GDB_5_3) || defined(GDB_6_0) || defined(GDB_6_1) || defined(GDB_7_0) 
	char *typename;
#else
	char *type_name;
#endif
	char *target_typename;
	ulong target_length;
	int target_typecode;
	int is_typedef;
	char *member;
	long member_offset;
	long member_length;
	int member_typecode;
	long value;
	const char *tagname;
	ulong pc;
	ulong sp;
	ulong ra;
	int curframe;
	ulong frame;
	ulong prevsp;
	ulong prevpc;
	ulong lastsp;
	ulong task;
	ulong debug;
	struct stack_hook *hookp;
        ulong lowest;
        ulong highest;
        void (*callback) (struct gnu_request *req, void *data);
        void *callback_data;
	struct load_module *lm;
	char *member_main_type_name;
	char *member_main_type_tag_name;
	char *member_target_type_name;
	char *member_target_type_tag_name;
	char *type_tag_name;
	/* callback function for 3rd party symbol and type (EPPIC for now) */
	void *priv;
	int (*tcb)(drill_ops_t, struct gnu_request *, const void *, const void *, const void *, const void *);
};

/*
 *  GNU commands
 */
#define GNU_DATATYPE_INIT           (1)
#define GNU_DISASSEMBLE             (2)
#define GNU_GET_LINE_NUMBER         (3)
#define GNU_PASS_THROUGH            (4)
#define GNU_GET_DATATYPE            (5)
#define GNU_COMMAND_EXISTS          (6)
#define GNU_STACK_TRACE             (7)
#define GNU_ALPHA_FRAME_OFFSET      (8)
#define GNU_FUNCTION_NUMARGS        (9)
#define GNU_RESOLVE_TEXT_ADDR       (10)
#define GNU_ADD_SYMBOL_FILE         (11)
#define GNU_DELETE_SYMBOL_FILE      (12)
#define GNU_VERSION                 (13)
#define GNU_PATCH_SYMBOL_VALUES     (14)
#define GNU_GET_SYMBOL_TYPE         (15)
#define GNU_USER_PRINT_OPTION       (16)
#define GNU_SET_CRASH_BLOCK         (17)
#define GNU_GET_FUNCTION_RANGE      (18)
#define GNU_ITERATE_DATATYPES       (19)
#define GNU_LOOKUP_STRUCT_CONTENTS  (20)
#define GNU_DEBUG_COMMAND           (100)
/*
 *  GNU flags
 */
#define GNU_PRINT_LINE_NUMBERS   (0x1)
#define GNU_FUNCTION_ONLY        (0x2)
#define GNU_PRINT_ENUMERATORS    (0x4)
#define GNU_RETURN_ON_ERROR      (0x8)
#define GNU_COMMAND_FAILED      (0x10)
#define GNU_FROM_TTY_OFF        (0x20)
#define GNU_NO_READMEM          (0x40)
#define GNU_VAR_LENGTH_TYPECODE (0x80)

#undef TRUE
#undef FALSE

#define TRUE  (1)
#define FALSE (0)

#ifdef GDB_COMMON
/*
 *  function prototypes required by modified gdb source files.
 */
extern "C" int console(const char *, ...);
extern "C" int gdb_CRASHDEBUG(ulong);
int gdb_readmem_callback(ulong, void *, int, int);
void patch_load_module(struct objfile *objfile, struct minimal_symbol *msymbol);
extern "C" int patch_kernel_symbol(struct gnu_request *);
struct syment *symbol_search(char *);
int gdb_line_number_callback(ulong, ulong, ulong);
int gdb_print_callback(ulong);
char *gdb_lookup_module_symbol(ulong, ulong *);
extern "C" int same_file(char *, char *);
#endif

#ifndef GDB_COMMON
/*
 *  WARNING: the following type codes are type_code enums from gdb/gdbtypes.h
 */
enum type_code {
  TYPE_CODE_UNDEF,              /* Not used; catches errors */
  TYPE_CODE_PTR,                /* Pointer type */
  TYPE_CODE_ARRAY,              /* Array type with lower & upper bounds. */
  TYPE_CODE_STRUCT,             /* C struct or Pascal record */
  TYPE_CODE_UNION,              /* C union or Pascal variant part */
  TYPE_CODE_ENUM,               /* Enumeration type */
#if defined(GDB_5_3) || defined(GDB_6_0) || defined(GDB_6_1) || defined(GDB_7_0) || defined(GDB_7_3_1) || defined(GDB_7_6) || defined(GDB_10_2)
#if defined(GDB_7_0) || defined(GDB_7_3_1) || defined(GDB_7_6) || defined(GDB_10_2)
  TYPE_CODE_FLAGS,              /* Bit flags type */
#endif
  TYPE_CODE_FUNC,               /* Function type */
  TYPE_CODE_INT,                /* Integer type */

  /* Floating type.  This is *NOT* a complex type.  Beware, there are parts
     of GDB which bogusly assume that TYPE_CODE_FLT can mean complex.  */
  TYPE_CODE_FLT,

  /* Void type.  The length field specifies the length (probably always
     one) which is used in pointer arithmetic involving pointers to
     this type, but actually dereferencing such a pointer is invalid;
     a void type has no length and no actual representation in memory
     or registers.  A pointer to a void type is a generic pointer.  */
  TYPE_CODE_VOID,

  TYPE_CODE_SET,                /* Pascal sets */
  TYPE_CODE_RANGE,              /* Range (integers within spec'd bounds) */

  /* 
   *  NOTE: the remainder of the type codes are not list or used here...
   */
  TYPE_CODE_BOOL = 20,
#endif
};

/*
 * include/linux/sched.h
 */
#define PF_EXITING 0x00000004  /* getting shut down */
#define PF_KTHREAD 0x00200000  /* I am a kernel thread */
#define SCHED_NORMAL	0
#define SCHED_FIFO	1
#define SCHED_RR	2
#define SCHED_BATCH	3
#define SCHED_ISO	4
#define SCHED_IDLE	5
#define SCHED_DEADLINE	6

extern long _ZOMBIE_;
#define IS_ZOMBIE(task)   (task_state(task) & _ZOMBIE_)
#define IS_EXITING(task)  (task_flags(task) & PF_EXITING)
  
/*
 *  ps command options.
 */
#define PS_BY_PID         (0x1)
#define PS_BY_TASK        (0x2)
#define PS_BY_CMD         (0x4)
#define PS_SHOW_ALL       (0x8)
#define PS_PPID_LIST     (0x10)
#define PS_CHILD_LIST    (0x20)
#define PS_KERNEL        (0x40)
#define PS_USER          (0x80)
#define PS_TIMES        (0x100)
#define PS_KSTACKP      (0x200)
#define PS_LAST_RUN     (0x400)
#define PS_ARGV_ENVP    (0x800)
#define PS_TGID_LIST   (0x1000)
#define PS_RLIMIT      (0x2000)
#define PS_GROUP       (0x4000)
#define PS_BY_REGEX    (0x8000)
#define PS_NO_HEADER  (0x10000)
#define PS_MSECS      (0x20000)
#define PS_SUMMARY    (0x40000)
#define PS_POLICY     (0x80000)
#define PS_ACTIVE    (0x100000)

#define PS_EXCLUSIVE (PS_TGID_LIST|PS_ARGV_ENVP|PS_TIMES|PS_CHILD_LIST|PS_PPID_LIST|PS_LAST_RUN|PS_RLIMIT|PS_MSECS|PS_SUMMARY|PS_ACTIVE)

#define MAX_PS_ARGS    (100)   /* maximum command-line specific requests */

struct psinfo {
	int argc;
        ulong pid[MAX_PS_ARGS];
	int type[MAX_PS_ARGS];
        ulong task[MAX_PS_ARGS];
        char comm[MAX_PS_ARGS][TASK_COMM_LEN+1];
	struct regex_data {
		char *pattern;
		regex_t regex;
	} regex_data[MAX_PS_ARGS];
	int regexs;
	ulong *cpus;
	int policy;
};

#define IS_A_NUMBER(X)      (decimal(X, 0) || hexadecimal(X, 0))
#define AMBIGUOUS_NUMBER(X) (decimal(X, 0) && hexadecimal(X, 0))

#define is_mclx_compressed_dump(X)  (va_server_init((X), 0, 0, 0) == 0)

struct task_mem_usage {
        ulong rss;
        ulong total_vm;
        double pct_physmem;
        ulong mm_struct_addr;
	ulong pgd_addr;
};

/*
 *  Global data (global_data.c) 
 */
extern FILE *fp; 
extern struct program_context program_context, *pc;
extern struct task_table task_table, *tt;
extern struct kernel_table kernel_table, *kt;
extern struct command_table_entry linux_command_table[];
extern char *args[MAXARGS];      
extern int argcnt;            
extern int argerrs;
extern struct offset_table offset_table;
extern struct size_table size_table;
extern struct array_table array_table;
extern struct vm_table vm_table, *vt;
extern struct machdep_table *machdep;
extern struct symbol_table_data symbol_table_data, *st;
extern struct extension_table *extension_table;

/*
 *  Generated in build_data.c
 */
extern char *build_command;
extern char *build_data;
extern char *build_target;
extern char *build_version;
extern char *compiler_version;


/*
 *  command prototypes
 */
void cmd_quit(void);         /* main.c */
void cmd_mach(void);         /* main.c */
void cmd_help(void);         /* help.c */
void cmd_test(void);         /* test.c */
void cmd_ascii(void);        /* tools.c */
void cmd_sbitmapq(void);     /* sbitmap.c */
void cmd_bpf(void);          /* bfp.c */
void cmd_set(void);          /* tools.c */
void cmd_eval(void);         /* tools.c */
void cmd_list(void);         /* tools.c */
void cmd_tree(void);         /* tools.c */
void cmd_template(void);     /* tools.c */
void cmd_alias(void);        /* cmdline.c */
void cmd_repeat(void);       /* cmdline.c */
void cmd_rd(void);           /* memory.c */
void cmd_wr(void);           /* memory.c */
void cmd_ptov(void);         /* memory.c */
void cmd_vtop(void);         /* memory.c */
void cmd_vm(void);           /* memory.c */
void cmd_ptob(void);         /* memory.c */
void cmd_btop(void);         /* memory.c */
void cmd_kmem(void);         /* memory.c */
void cmd_search(void);       /* memory.c */
void cmd_swap(void);         /* memory.c */
void cmd_pte(void);          /* memory.c */
void cmd_ps(void);           /* task.c */
void cmd_task(void);         /* task.c */
void cmd_foreach(void);      /* task.c */
void cmd_runq(void);         /* task.c */
void cmd_sig(void);          /* task.c */
void cmd_bt(void);           /* kernel.c */
void cmd_dis(void);          /* kernel.c */
void cmd_mod(void);          /* kernel.c */
void cmd_log(void);          /* kernel.c */
void cmd_sys(void);          /* kernel.c */
void cmd_irq(void);          /* kernel.c */
void cmd_timer(void);        /* kernel.c */
void cmd_waitq(void);        /* kernel.c */
void cmd_sym(void);          /* symbols.c */
void cmd_struct(void);       /* symbols.c */
void cmd_union(void);        /* symbols.c */
void cmd_pointer(void);      /* symbols.c */
void cmd_whatis(void);       /* symbols.c */
void cmd_p(void);            /* symbols.c */
void cmd_mount(void);        /* filesys.c */
void cmd_files(void);        /* filesys.c */
void cmd_fuser(void);        /* filesys.c */
void cmd_dev(void);          /* dev.c */
void cmd_gdb(void);          /* gdb_interface.c */
void cmd_net(void);          /* net.c */
void cmd_extend(void);       /* extensions.c */
#if defined(S390) || defined(S390X)
void cmd_s390dbf(void);
#endif
void cmd_map(void);          /* kvmdump.c */
void cmd_ipcs(void);         /* ipcs.c */

/*
 *  main.c
 */
void main_loop(void);
void exec_command(void);
struct command_table_entry *get_command_table_entry(char *);
void program_usage(int);
#define LONG_FORM  (1)
#define SHORT_FORM (0)
void dump_program_context(void);
void dump_build_data(void);
#ifdef ARM
#define machdep_init(X) arm_init(X)
#endif
#ifdef ARM64
#define machdep_init(X) arm64_init(X)
#endif
#ifdef X86
#define machdep_init(X) x86_init(X)
#endif
#ifdef ALPHA
#define machdep_init(X) alpha_init(X)
#endif
#ifdef PPC
#define machdep_init(X) ppc_init(X)
#endif
#ifdef IA64 
#define machdep_init(X) ia64_init(X)
#endif
#ifdef S390
#define machdep_init(X) s390_init(X)
#endif
#ifdef S390X
#define machdep_init(X) s390x_init(X)
#endif
#ifdef X86_64
#define machdep_init(X) x86_64_init(X)
#endif
#ifdef PPC64
#define machdep_init(X) ppc64_init(X)
#endif
#ifdef MIPS
#define machdep_init(X) mips_init(X)
#endif
#ifdef MIPS64
#define machdep_init(X) mips64_init(X)
#endif
#ifdef RISCV64
#define machdep_init(X) riscv64_init(X)
#endif
#ifdef SPARC64
#define machdep_init(X) sparc64_init(X)
#endif
int clean_exit(int);
int untrusted_file(FILE *, char *);
char *readmem_function_name(void);
char *writemem_function_name(void);
char *no_vmcoreinfo(const char *);

/*
 *  cmdline.c
 */
void restart(int);
void alias_init(char *);
struct alias_data *is_alias(char *);
void deallocate_alias(char *);
void cmdline_init(void);
void set_command_prompt(char *);
void exec_input_file(void);
void process_command_line(void);
void dump_history(void);
void resolve_rc_cmd(char *, int);
void dump_alias_data(void);
int output_open(void);
#define output_closed() (!output_open())
void close_output(void);
int interruptible(void);
int received_SIGINT(void);
void debug_redirect(char *);
int CRASHPAGER_valid(void);
char *setup_scroll_command(void);
int minimal_functions(char *);
int is_args_input_file(struct command_table_entry *, struct args_input_file *);
void exec_args_input_file(struct command_table_entry *, struct args_input_file *);

/*
 *  tools.c
 */
FILE *set_error(char *);
int __error(int, char *, ...);
#define error __error               /* avoid conflict with gdb error() */
int console(const char *, ...);
void create_console_device(char *);
int console_off(void);
int console_on(int);
int console_verbatim(char *);
int whitespace(int);
int ascii(int);
int ascii_string(char *);
int printable_string(char *);
char *clean_line(char *);
char *strip_line_end(char *);
char *strip_linefeeds(char *);
char *strip_beginning_whitespace(char *);
char *strip_ending_whitespace(char *);
char *strip_ending_char(char *, char);
char *strip_beginning_char(char *, char);
char *strip_comma(char *);
char *strip_hex(char *);
char *upper_case(const char *, char *);
char *first_nonspace(char *);
char *first_space(char *);
char *replace_string(char *, char *, char);
void string_insert(char *, char *);
char *strstr_rightmost(char *, char *);
char *null_first_space(char *);
int parse_line(char *, char **);
void print_verbatim(FILE *, char *);
char *fixup_percent(char *);
int can_eval(char *);
ulong eval(char *, int, int *);
ulonglong evall(char *, int, int *);
int eval_common(char *, int, int *, struct number_option *);
ulong htol(char *, int, int *);
ulong dtol(char *, int, int *);
unsigned int dtoi(char *, int, int *);
ulong stol(char *, int, int *);
ulonglong stoll(char *, int, int *);
ulonglong htoll(char *, int, int *);
ulonglong dtoll(char *, int, int *);
int decimal(char *, int);
int hexadecimal(char *, int);
int hexadecimal_only(char *, int);
ulong convert(char *, int, int *, ulong);
void pad_line(FILE *, int, char);
#define INDENT(x)  pad_line(fp, x, ' ')
char *mkstring(char *, int, ulong, const char *);
#define MKSTR(X) ((const char *)(X))
int count_leading_spaces(char *);
int count_chars(char *, char);
long count_buffer_chars(char *, char, long);
char *space(int);
char *concat_args(char *, int, int);
char *shift_string_left(char *, int);
char *shift_string_right(char *, int);
int bracketed(char *, char *, int);
void backspace(int);
int do_list(struct list_data *);
int do_list_no_hash(struct list_data *);
struct radix_tree_ops {
	void (*entry)(ulong node, ulong slot, const char *path,
		      ulong index, void *private);
	uint radix;
	void *private;
};
int do_radix_tree_traverse(ulong ptr, int is_root, struct radix_tree_ops *ops);
struct xarray_ops {
	void (*entry)(ulong node, ulong slot, const char *path,
		      ulong index, void *private);
	uint radix;
	void *private;
};
int do_xarray_traverse(ulong ptr, int is_root, struct xarray_ops *ops);
int do_rdtree(struct tree_data *);
int do_rbtree(struct tree_data *);
int do_xatree(struct tree_data *);
int retrieve_list(ulong *, int);
long power(long, int);
long long ll_power(long long, long long);
void hq_init(void);
int hq_open(void);
int hq_close(void);
int hq_enter(ulong);
int hq_entry_exists(ulong);
int hq_is_open(void);
int hq_is_inuse(void);
long get_embedded(void);
void dump_embedded(char *);
char *ordinal(ulong, char *);
char *first_nonspace(char *);
void dump_hash_table(int);
void dump_shared_bufs(void);
void drop_core(char *);
int extract_hex(char *, ulong *, char, ulong);
int count_bits_int(int);
int count_bits_long(ulong);
int highest_bit_long(ulong);
int lowest_bit_long(ulong);
void buf_init(void);
void sym_buf_init(void);
void free_all_bufs(void);
char *getbuf(long);
void freebuf(char *);
char *resizebuf(char *, long, long);
char *strdupbuf(char *);
#define GETBUF(X)   getbuf((long)(X))
#define FREEBUF(X)  freebuf((char *)(X))
#define RESIZEBUF(X,Y,Z) (X) = (typeof(X))resizebuf((char *)(X), (long)(Y), (long)(Z));
#define STRDUPBUF(X) strdupbuf((char *)(X))
void sigsetup(int, void *, struct sigaction *, struct sigaction *);
#define SIGACTION(s, h, a, o) sigsetup(s, h, a, o)
char *convert_time(ulonglong, char *);
char *ctime_tz(time_t *);
void stall(ulong);
char *pages_to_size(ulong, char *);
int clean_arg(void);
int empty_list(ulong);
int machine_type(char *);
int machine_type_mismatch(char *, char *, char *, ulong);
void command_not_supported(void);
void option_not_supported(int);
void please_wait(char *);
void please_wait_done(void);
int pathcmp(char *, char *);
int calculate(char *, ulong *, ulonglong *, ulong);
int endian_mismatch(char *, char, ulong);
uint16_t swap16(uint16_t, int);
uint32_t swap32(uint32_t, int);
uint64_t swap64(uint64_t, int);
ulong *get_cpumask_buf(void);
int make_cpumask(char *, ulong *, int, int *);
size_t strlcpy(char *, char *, size_t);
struct rb_node *rb_first(struct rb_root *);
struct rb_node *rb_parent(struct rb_node *, struct rb_node *);
struct rb_node *rb_right(struct rb_node *, struct rb_node *);
struct rb_node *rb_left(struct rb_node *, struct rb_node *);
struct rb_node *rb_next(struct rb_node *);
struct rb_node *rb_last(struct rb_root *);
long percpu_counter_sum_positive(ulong fbc);

/* 
 *  symbols.c 
 */
void symtab_init(void);
char *check_specified_kernel_debug_file(void);
void no_debugging_data(int);
void get_text_init_space(void);
int is_kernel_text(ulong);
int is_kernel_data(ulong);
int is_init_data(ulong value); 
int is_kernel_text_offset(ulong);
int is_symbol_text(struct syment *);
int is_rodata(ulong, struct syment **);
int get_text_function_range(ulong, ulong *, ulong *);
void datatype_init(void);
struct syment *symbol_search(char *);
struct syment *value_search(ulong, ulong *);
struct syment *value_search_base_kernel(ulong, ulong *);
struct syment *value_search_module(ulong, ulong *);
struct syment *symbol_search_next(char *, struct syment *);
ulong highest_bss_symbol(void);
int in_ksymbol_range(ulong);
int module_symbol(ulong, struct syment **, 
	struct load_module **, char *, ulong);
#define IS_MODULE_VADDR(X) \
	(module_symbol((ulong)(X), NULL, NULL, NULL, *gdb_output_radix))
char *closest_symbol(ulong);
ulong closest_symbol_value(ulong);
#define SAME_FUNCTION(X,Y) (closest_symbol_value(X) == closest_symbol_value(Y))
void show_symbol(struct syment *, ulong, ulong);
#define SHOW_LINENUM  (0x1)
#define SHOW_SECTION  (0x2)
#define SHOW_HEX_OFFS (0x4)
#define SHOW_DEC_OFFS (0x8)
#define SHOW_RADIX() (*gdb_output_radix == 16 ? SHOW_HEX_OFFS : SHOW_DEC_OFFS)
#define SHOW_MODULE  (0x10)
int symbol_name_count(char *);
int symbol_query(char *, char *, struct syment **);
struct syment *next_symbol(char *, struct syment *);
struct syment *prev_symbol(char *, struct syment *);
void get_symbol_data(char *, long, void *);
int try_get_symbol_data(char *, long, void *);
char *value_to_symstr(ulong, char *, ulong);
char *value_symbol(ulong);
ulong symbol_value(char *);
ulong symbol_value_module(char *, char *);
struct syment *per_cpu_symbol_search(char *);
int symbol_exists(char *s);
int kernel_symbol_exists(char *s);
struct syment *kernel_symbol_search(char *);
ulong symbol_value_from_proc_kallsyms(char *);
int get_syment_array(char *, struct syment **, int);
void set_temporary_radix(unsigned int, unsigned int *);
void restore_current_radix(unsigned int);
void dump_struct(char *, ulong, unsigned);
void dump_struct_member(char *, ulong, unsigned);
void dump_union(char *, ulong, unsigned);
void store_module_symbols_v1(ulong, int);
void store_module_symbols_v2(ulong, int);
int is_datatype_command(void);
int is_typedef(char *);
int arg_to_datatype(char *, struct datatype_member *, ulong);
void dump_symbol_table(void);
void dump_struct_table(ulong);
void dump_offset_table(char *, ulong);
int is_elf_file(char *);
int is_kernel(char *);
int is_shared_object(char *);
int file_elf_version(char *);
int is_system_map(char *);
int is_compressed_kernel(char *, char **);
int select_namelist(char *);
int get_array_length(char *, int *, long);
int get_array_length_alt(char *, char *, int *, long);
int builtin_array_length(char *, int, int *);
char *get_line_number(ulong, char *, int);
char *get_build_directory(char *);
int datatype_exists(char *);
int get_function_numargs(ulong);
int is_module_name(char *, ulong *, struct load_module **);
int is_module_address(ulong, char *);
ulong lowest_module_address(void);
ulong highest_module_address(void);
int load_module_symbols(char *, char *, ulong);
void delete_load_module(ulong);
ulong gdb_load_module_callback(ulong, char *);
char *load_module_filter(char *, int);
#define LM_P_FILTER   (1)
#define LM_DIS_FILTER (2)
long datatype_info(char *, char *, struct datatype_member *);
int get_symbol_type(char *, char *, struct gnu_request *);
int get_symbol_length(char *);
void dump_numargs_cache(void);
int patch_kernel_symbol(struct gnu_request *);
struct syment *generic_machdep_value_to_symbol(ulong, ulong *);
long OFFSET_verify(long, char *, char *, int, char *);
long SIZE_verify(long, char *, char *, int, char *);
long OFFSET_option(long, long, char *, char *, int, char *, char *);
long SIZE_option(long, long, char *, char *, int, char *, char *);
void dump_trace(void **);
int enumerator_value(char *, long *);
int dump_enumerator_list(char *);
struct load_module *init_module_function(ulong);
struct struct_member_data {
	char *structure;
	char *member;
	long type;
	long unsigned_type;
	long length;
	long offset;
	long bitpos;
	long bitsize;
};
int fill_struct_member_data(struct struct_member_data *);
void parse_for_member_extended(struct datatype_member *, ulong);
void add_to_downsized(char *);
int is_downsized(char *);
int is_string(char *, char *);
struct syment *symbol_complete_match(const char *, struct syment *);

/*  
 *  memory.c 
 */
void mem_init(void);
void vm_init(void);
int readmem(ulonglong, int, void *, long, char *, ulong);
int writemem(ulonglong, int, void *, long, char *, ulong);
int generic_verify_paddr(uint64_t);
int read_dev_mem(int, void *, int, ulong, physaddr_t);
int read_memory_device(int, void *, int, ulong, physaddr_t);
int read_mclx_dumpfile(int, void *, int, ulong, physaddr_t);
int read_lkcd_dumpfile(int, void *, int, ulong, physaddr_t);
int read_daemon(int, void *, int, ulong, physaddr_t);
int write_dev_mem(int, void *, int, ulong, physaddr_t);
int write_memory_device(int, void *, int, ulong, physaddr_t);
int write_mclx_dumpfile(int, void *, int, ulong, physaddr_t);
int write_lkcd_dumpfile(int, void *, int, ulong, physaddr_t);
int write_daemon(int, void *, int, ulong, physaddr_t);
int kvtop(struct task_context *, ulong, physaddr_t *, int);
int uvtop(struct task_context *, ulong, physaddr_t *, int);
void do_vtop(ulong, struct task_context *, ulong);
void raw_stack_dump(ulong, ulong);
void raw_data_dump(ulong, long, int);
int accessible(ulong);
ulong vm_area_dump(ulong, ulong, ulong, struct reference *);
#define IN_TASK_VMA(TASK,VA) (vm_area_dump((TASK), UVADDR|VERIFY_ADDR, (VA), 0))
char *fill_vma_cache(ulong);
void clear_vma_cache(void);
void dump_vma_cache(ulong);
int generic_is_page_ptr(ulong, physaddr_t *);
int is_page_ptr(ulong, physaddr_t *);
void dump_vm_table(int);
int read_string(ulong, char *, int);
void get_task_mem_usage(ulong, struct task_mem_usage *);
char *get_memory_size(char *);
uint64_t generic_memory_size(void);
char *swap_location(ulonglong, char *); 
void clear_swap_info_cache(void);
uint memory_page_size(void);
void force_page_size(char *);
ulong first_vmalloc_address(void);
ulong last_vmalloc_address(void);
int in_vmlist_segment(ulong);
int phys_to_page(physaddr_t, ulong *);
int generic_get_kvaddr_ranges(struct vaddr_range *);
int l1_cache_size(void);
int dumpfile_memory(int);
#define DUMPFILE_MEM_USED    (1)
#define DUMPFILE_FREE_MEM    (2)
#define DUMPFILE_MEM_DUMP    (3)
#define DUMPFILE_ENVIRONMENT (4)
uint64_t total_node_memory(void);
int generic_is_kvaddr(ulong);
int generic_is_uvaddr(ulong, struct task_context *);
void fill_stackbuf(struct bt_info *);
void alter_stackbuf(struct bt_info *);
int vaddr_type(ulong, struct task_context *);
char *format_stack_entry(struct bt_info *bt, char *, ulong, ulong);
int in_user_stack(ulong, ulong);
int dump_inode_page(ulong);
ulong valid_section_nr(ulong);
void display_memory_from_file_offset(ulonglong, long, void *);
void swap_info_init(void);

/*
 *  filesys.c 
 */
void fd_init(void);
void vfs_init(void);
int is_a_tty(char *);
int file_exists(char *, struct stat *);
int file_readable(char *);
int is_directory(char *);
char *search_directory_tree(char *, char *, int);
void open_tmpfile(void);
void close_tmpfile(void);
void open_tmpfile2(void);
void set_tmpfile2(FILE *);
void close_tmpfile2(void);
void open_files_dump(ulong, int, struct reference *);
void get_pathname(ulong, char *, int, int, ulong);
ulong *get_mount_list(int *, struct task_context *);
char *vfsmount_devname(ulong, char *, int);
ulong file_to_dentry(ulong);
ulong file_to_vfsmnt(ulong);
int get_proc_version(void);
int file_checksum(char *, long *);
void dump_filesys_table(int);
char *fill_file_cache(ulong);
void clear_file_cache(void);
char *fill_dentry_cache(ulong);
void clear_dentry_cache(void);
char *fill_inode_cache(ulong);
void clear_inode_cache(void);
int monitor_memory(long *, long *, long *, long *);
int is_readable(char *);
struct list_pair {
	ulong index;
	void *value;
};
#define radix_tree_pair list_pair
ulong do_radix_tree(ulong, int, struct list_pair *);
#define RADIX_TREE_COUNT   (1)
#define RADIX_TREE_SEARCH  (2)
#define RADIX_TREE_DUMP    (3)
#define RADIX_TREE_GATHER  (4)
#define RADIX_TREE_DUMP_CB (5)
/*
 * from: "include/linux/radix-tree.h"
 */
#define RADIX_TREE_ENTRY_MASK           3UL
#define RADIX_TREE_EXCEPTIONAL_ENTRY    2

ulong do_xarray(ulong, int, struct list_pair *);
#define XARRAY_COUNT   (1)
#define XARRAY_SEARCH  (2)
#define XARRAY_DUMP    (3)
#define XARRAY_GATHER  (4)
#define XARRAY_DUMP_CB (5)
#define XARRAY_TAG_MASK      (3UL)
#define XARRAY_TAG_INTERNAL  (2UL)

int file_dump(ulong, ulong, ulong, int, int);
#define DUMP_FULL_NAME      0x1
#define DUMP_INODE_ONLY     0x2
#define DUMP_DENTRY_ONLY    0x4
#define DUMP_EMPTY_FILE     0x8
#define DUMP_FILE_NRPAGES  0x10
int same_file(char *, char *);
int cleanup_memory_driver(void);

void maple_init(void);
int do_mptree(struct tree_data *);
ulong do_maple_tree(ulong, int, struct list_pair *);
#define MAPLE_TREE_COUNT   (1)
#define MAPLE_TREE_SEARCH  (2)
#define MAPLE_TREE_DUMP    (3)
#define MAPLE_TREE_GATHER  (4)
#define MAPLE_TREE_DUMP_CB (5)

/*
 *  help.c 
 */
#define HELP_COLUMNS 5
#define START_OF_HELP_DATA(X)  "START_OF_HELP_DATA" X
#define END_OF_HELP_DATA       "END_OF_HELP_DATA"
void help_init(void);
void cmd_usage(char *, int);
void display_version(void);
void display_help_screen(char *);
#ifdef ARM
#define dump_machdep_table(X) arm_dump_machdep_table(X)
#endif
#ifdef ARM64
#define dump_machdep_table(X) arm64_dump_machdep_table(X)
#endif
#ifdef X86
#define dump_machdep_table(X) x86_dump_machdep_table(X)
#endif
#ifdef ALPHA
#define dump_machdep_table(X) alpha_dump_machdep_table(X)
#endif
#ifdef PPC
#define dump_machdep_table(X) ppc_dump_machdep_table(X)
#endif
#ifdef IA64
#define dump_machdep_table(X) ia64_dump_machdep_table(X)
#endif
#ifdef S390
#define dump_machdep_table(X) s390_dump_machdep_table(X)
#endif
#ifdef S390X
#define dump_machdep_table(X) s390x_dump_machdep_table(X)
#endif
#ifdef X86_64
#define dump_machdep_table(X) x86_64_dump_machdep_table(X)
#endif
#ifdef PPC64
#define dump_machdep_table(X) ppc64_dump_machdep_table(X)
#endif
#ifdef MIPS
#define dump_machdep_table(X) mips_dump_machdep_table(X)
#endif
#ifdef MIPS64
#define dump_machdep_table(X) mips64_dump_machdep_table(X)
#endif
#ifdef SPARC64
#define dump_machdep_table(X) sparc64_dump_machdep_table(X)
#endif
#ifdef RISCV64
#define dump_machdep_table(X) riscv64_dump_machdep_table(X)
#endif
extern char *help_pointer[];
extern char *help_alias[];
extern char *help_ascii[];
extern char *help_bpf[];
extern char *help_bt[];
extern char *help_btop[];
extern char *help_dev[];
extern char *help_dis[];
extern char *help_eval[];
extern char *help_exit[];
extern char *help_extend[];
extern char *help_files[];
extern char *help_foreach[];
extern char *help_fuser[];
extern char *help_gdb[];
extern char *help_help[];
extern char *help_irq[];
extern char *help_kmem[];
extern char *help__list[];
extern char *help_tree[];
extern char *help_log[];
extern char *help_mach[];
extern char *help_mod[];
extern char *help_mount[];
extern char *help_net[];
extern char *help_p[];
extern char *help_ps[];
extern char *help_pte[];
extern char *help_ptob[];
extern char *help_ptov[];
extern char *help_quit[];
extern char *help_rd[];
extern char *help_repeat[];
extern char *help_runq[];
extern char *help_ipcs[];
extern char *help_sbitmapq[];
extern char *help_search[];
extern char *help_set[];
extern char *help_sig[];
extern char *help_struct[];
extern char *help_swap[];
extern char *help_sym[];
extern char *help_sys[];
extern char *help_task[];
extern char *help_timer[];
extern char *help_union[];
extern char *help_vm[];
extern char *help_vtop[];
extern char *help_waitq[];
extern char *help_whatis[];
extern char *help_wr[];
#if defined(S390) || defined(S390X)
extern char *help_s390dbf[];
#endif
extern char *help_map[];

/*
 *  task.c
 */ 
void task_init(void);
int set_context(ulong, ulong);
void show_context(struct task_context *);
ulong pid_to_task(ulong);
ulong task_to_pid(ulong);
int task_exists(ulong);
int is_kernel_thread(ulong);
int is_idle_thread(ulong);
void get_idle_threads(ulong *, int);
char *task_state_string(ulong, char *, int);
ulong task_flags(ulong);
ulong task_state(ulong);
ulong task_mm(ulong, int);
ulong task_tgid(ulong);
ulonglong task_last_run(ulong);
ulong vaddr_in_task_struct(ulong);
int comm_exists(char *);
struct task_context *task_to_context(ulong);
struct task_context *pid_to_context(ulong);
struct task_context *tgid_to_context(ulong);
ulong stkptr_to_task(ulong);
ulong task_to_thread_info(ulong);
ulong task_to_stackbase(ulong);
int str_to_context(char *, ulong *, struct task_context **);
#define STR_PID     (0x1)
#define STR_TASK    (0x2)
#define STR_INVALID (0x4)
char *get_panicmsg(char *);
char *task_cpu(int, char *, int);
void print_task_header(FILE *, struct task_context *, int);
ulong get_active_task(int);
int is_task_active(ulong);
int is_panic_thread(ulong);
int get_panic_ksp(struct bt_info *, ulong *);
void foreach(struct foreach_data *);
int pid_exists(ulong);
#define TASKS_PER_PID(x)  pid_exists(x)
char *fill_task_struct(ulong);
#define IS_LAST_TASK_READ(task) ((ulong)(task) == tt->last_task_read)
char *fill_thread_info(ulong);
#define IS_LAST_THREAD_INFO_READ(ti) ((ulong)(ti) == tt->last_thread_info_read)
char *fill_mm_struct(ulong);
#define IS_LAST_MM_READ(mm)     ((ulong)(mm) == tt->last_mm_read)
void do_task(ulong, ulong, struct reference *, unsigned int);
void clear_task_cache(void);
int get_active_set(void);
void clear_active_set(void);
void do_sig(ulong, ulong, struct reference *);
void modify_signame(int, char *, char *);
ulong generic_get_stackbase(ulong);
ulong generic_get_stacktop(ulong);
void dump_task_table(int);
void sort_context_array(void);
void sort_tgid_array(void);
int sort_by_tgid(const void *, const void *);
int in_irq_ctx(ulonglong, int, ulong);
void check_stack_overflow(void);

/*
 *  extensions.c
 */
void register_extension(struct command_table_entry *);
void dump_extension_table(int);
void load_extension(char *);
void unload_extension(char *);
void preload_extensions(void);
/* Hooks for sial */
unsigned long get_curtask(void);
char *crash_global_cmd(void);
struct command_table_entry *crash_cmd_table(void);

/*
 *  kernel.c 
 */ 
void kernel_init(void);
void module_init(void);
void verify_version(void);
void verify_spinlock(void);
void non_matching_kernel(void);
struct load_module *modref_to_load_module(char *);
int load_module_symbols_helper(char *);
void unlink_module(struct load_module *);
int check_specified_module_tree(char *, char *);
int is_system_call(char *, ulong);
void generic_dump_irq(int);
void generic_get_irq_affinity(int);
void generic_show_interrupts(int, ulong *);
int generic_dis_filter(ulong, char *, unsigned int);
int kernel_BUG_encoding_bytes(void);
void display_sys_stats(void);
char *get_uptime(char *, ulonglong *);
void clone_bt_info(struct bt_info *, struct bt_info *, struct task_context *);
void dump_kernel_table(int);
void dump_bt_info(struct bt_info *, char *where);
void dump_log(int);
#define LOG_LEVEL(v) ((v) & 0x07)
#define SHOW_LOG_LEVEL (0x1)
#define SHOW_LOG_DICT  (0x2)
#define SHOW_LOG_TEXT  (0x4)
#define SHOW_LOG_AUDIT (0x8)
#define SHOW_LOG_CTIME (0x10)
#define SHOW_LOG_SAFE  (0x20)
void set_cpu(int);
void clear_machdep_cache(void);
struct stack_hook *gather_text_list(struct bt_info *);
int get_cpus_online(void);
int get_cpus_active(void);
int get_cpus_present(void);
int get_cpus_possible(void);
int check_offline_cpu(int);
int hide_offline_cpu(int);
int get_highest_cpu_online(void);
int get_highest_cpu_present(void);
int get_cpus_to_display(void);
void get_log_from_vmcoreinfo(char *file);
int in_cpu_map(int, int);
void paravirt_init(void);
void print_stack_text_syms(struct bt_info *, ulong, ulong);
void back_trace(struct bt_info *);
int in_alternate_stack(int, ulong);
ulong cpu_map_addr(const char *type);
#define BT_RAW                     (0x1ULL)
#define BT_SYMBOLIC_ARGS           (0x2ULL)
#define BT_FULL                    (0x4ULL)
#define BT_TEXT_SYMBOLS            (0x8ULL)
#define BT_TEXT_SYMBOLS_PRINT     (0x10ULL)
#define BT_TEXT_SYMBOLS_NOPRINT   (0x20ULL)
#define BT_USE_GDB                (0x40ULL)
#define BT_EXCEPTION_FRAME        (0x80ULL)
#define BT_LINE_NUMBERS          (0x100ULL)
#define BT_USER_EFRAME           (0x200ULL)
#define BT_INCOMPLETE_USER_EFRAME  (BT_USER_EFRAME)
#define BT_SAVE_LASTSP           (0x400ULL)
#define BT_FROM_EXCEPTION        (0x800ULL)
#define BT_FROM_CALLFRAME       (0x1000ULL)
#define BT_EFRAME_SEARCH        (0x2000ULL)
#define BT_SPECULATE            (0x4000ULL)
#define BT_FRAMESIZE_DISABLE   (BT_SPECULATE)
#define BT_RESCHEDULE           (0x8000ULL)
#define BT_SCHEDULE      (BT_RESCHEDULE)
#define BT_RET_FROM_SMP_FORK   (0x10000ULL)
#define BT_STRACE              (0x20000ULL)
#define BT_KDUMP_ADJUST         (BT_STRACE)
#define BT_KSTACKP             (0x40000ULL)
#define BT_LOOP_TRAP           (0x80000ULL)
#define BT_BUMP_FRAME_LEVEL   (0x100000ULL)
#define BT_EFRAME_COUNT       (0x200000ULL)
#define BT_CPU_IDLE           (0x400000ULL)
#define BT_WRAP_TRAP          (0x800000ULL)
#define BT_KERNEL_THREAD     (0x1000000ULL)
#define BT_ERROR_MASK  (BT_LOOP_TRAP|BT_WRAP_TRAP|BT_KERNEL_THREAD|BT_CPU_IDLE)
#define BT_UNWIND_ERROR      (0x2000000ULL)
#define BT_OLD_BACK_TRACE    (0x4000000ULL)
#define BT_OPT_BACK_TRACE    (0x4000000ULL)
#define BT_FRAMESIZE_DEBUG   (0x8000000ULL)
#define BT_CONTEXT_SWITCH   (0x10000000ULL)
#define BT_HARDIRQ          (0x20000000ULL)
#define BT_SOFTIRQ          (0x40000000ULL)
#define BT_CHECK_CALLER     (0x80000000ULL)
#define BT_NO_CHECK_CALLER (0x100000000ULL)
#define BT_EXCEPTION_STACK (0x200000000ULL)
#define BT_IRQSTACK        (0x400000000ULL)
#define BT_DUMPFILE_SEARCH (0x800000000ULL)
#define BT_EFRAME_SEARCH2 (0x1000000000ULL)
#define BT_START          (0x2000000000ULL)
#define BT_TEXT_SYMBOLS_ALL  (0x4000000000ULL)     
#define BT_XEN_STOP_THIS_CPU (0x8000000000ULL)
#define BT_THREAD_GROUP     (0x10000000000ULL)
#define BT_SAVE_EFRAME_IP   (0x20000000000ULL)
#define BT_FULL_SYM_SLAB    (0x40000000000ULL)
#define BT_KDUMP_ELF_REGS   (0x80000000000ULL)
#define BT_USER_SPACE      (0x100000000000ULL)
#define BT_KERNEL_SPACE    (0x200000000000ULL)
#define BT_FULL_SYM_SLAB2  (0x400000000000ULL)
#define BT_EFRAME_TARGET   (0x800000000000ULL)
#define BT_CPUMASK        (0x1000000000000ULL)
#define BT_SHOW_ALL_REGS  (0x2000000000000ULL)
#define BT_REGS_NOT_FOUND (0x4000000000000ULL)
#define BT_OVERFLOW_STACK (0x8000000000000ULL)
#define BT_SKIP_IDLE     (0x10000000000000ULL)
#define BT_SYMBOL_OFFSET   (BT_SYMBOLIC_ARGS)

#define BT_REF_HEXVAL         (0x1)
#define BT_REF_SYMBOL         (0x2)
#define BT_REF_FOUND          (0x4)
#define BT_REFERENCE_CHECK(X) ((X)->ref)
#define BT_REFERENCE_FOUND(X) ((X)->ref && ((X)->ref->cmdflags & BT_REF_FOUND))

#define NO_MODULES() \
	 (!kt->module_list || (kt->module_list == kt->kernel_module))

#define USER_EFRAME_ADDR(task) \
	((ulong)task + UNION_SIZE("task_union") - SIZE(pt_regs))

struct remote_file {
	char *filename;
	char *local;
	int fd;
	int flags;
	int type;
	long csum;
	off_t size;
};

#define REMOTE_VERBOSE   (O_RDWR << 1)
#define REMOTE_COPY_DONE (REMOTE_VERBOSE << 1)
#define TYPE_ELF         (REMOTE_VERBOSE << 2)
#define TYPE_DEVMEM      (REMOTE_VERBOSE << 3)
#define TYPE_MCLXCD      (REMOTE_VERBOSE << 4)
#define TYPE_LKCD        (REMOTE_VERBOSE << 5)
#define TYPE_S390D       (REMOTE_VERBOSE << 6)
#define TYPE_NETDUMP     (REMOTE_VERBOSE << 7)

ulonglong xen_m2p(ulonglong);

void read_in_kernel_config(int);

#define IKCFG_INIT   (0)
#define IKCFG_READ   (1)
#define IKCFG_SETUP  (2)
#define IKCFG_FREE   (3)

int get_kernel_config(char *, char **);
enum {
	IKCONFIG_N,
	IKCONFIG_Y,
	IKCONFIG_M,
	IKCONFIG_STR,
};

#define MAGIC_START  "IKCFG_ST"
#define MAGIC_END    "IKCFG_ED"
#define MAGIC_SIZE   (sizeof(MAGIC_START) - 1)

/*
 *  dev.c
 */
void dev_init(void);
void dump_dev_table(void);
void devdump_extract(void *, ulonglong, char *, FILE *);
void devdump_info(void *, ulonglong, FILE *);

/*
 *  ipcs.c
 */
void ipcs_init(void);
ulong idr_find(ulong, int);

/*
 * sbitmap.c
 */
/* sbitmap helpers */
struct sbitmap_context {
	unsigned depth;
	unsigned shift;
	unsigned map_nr;
	ulong map_addr;
	ulong alloc_hint;
	bool round_robin;
};

typedef bool (*sbitmap_for_each_fn)(unsigned int idx, void *p);

void sbitmap_for_each_set(const struct sbitmap_context *sc,
	sbitmap_for_each_fn fn, void *data);
void sbitmap_context_load(ulong addr, struct sbitmap_context *sc);

/* sbitmap_queue helpers */
typedef bool (*sbitmapq_for_each_fn)(unsigned int idx, ulong addr, void *p);

struct sbitmapq_ops {
	/* array params associated with the bitmap */
	ulong addr;
	ulong size;
	/* callback params */
	sbitmapq_for_each_fn fn;
	void *p;
};

void sbitmapq_init(void);
void sbitmapq_for_each_set(ulong addr, struct sbitmapq_ops *ops);

#ifdef ARM
void arm_init(int);
void arm_dump_machdep_table(ulong);
int arm_is_vmalloc_addr(ulong);
void arm_dump_backtrace_entry(struct bt_info *, int, ulong, ulong);

#define display_idt_table() \
        error(FATAL, "-d option is not applicable to ARM architecture\n")

struct arm_pt_regs {
	ulong uregs[18];
};

#define ARM_cpsr	uregs[16]
#define ARM_pc		uregs[15]
#define ARM_lr		uregs[14]
#define ARM_sp		uregs[13]
#define ARM_ip		uregs[12]
#define ARM_fp		uregs[11]
#define ARM_r10		uregs[10]
#define ARM_r9		uregs[9]
#define ARM_r8		uregs[8]
#define ARM_r7		uregs[7]
#define ARM_r6		uregs[6]
#define ARM_r5		uregs[5]
#define ARM_r4		uregs[4]
#define ARM_r3		uregs[3]
#define ARM_r2		uregs[2]
#define ARM_r1		uregs[1]
#define ARM_r0		uregs[0]
#define ARM_ORIG_r0	uregs[17]

#define KSYMS_START	(0x1)
#define PHYS_BASE	(0x2)
#define PGTABLE_V2	(0x4)
#define IDMAP_PGD	(0x8)

#define KVBASE_MASK	(0x1ffffff)

struct machine_specific {
	ulong phys_base;
	ulong vmalloc_start_addr;
	ulong modules_vaddr;
	ulong modules_end;
	ulong kernel_text_start;
	ulong kernel_text_end;
	ulong exception_text_start;
	ulong exception_text_end;
	ulonglong last_pgd_read_lpae;
	ulonglong last_pmd_read_lpae;
	ulonglong last_ptbl_read_lpae;
	struct arm_pt_regs *crash_task_regs;
	int unwind_index_prel31;
};

int init_unwind_tables(void);
void unwind_backtrace(struct bt_info *);
#endif /* ARM */

/* 
 * arm64.c 
 */
#ifdef ARM64
void arm64_init(int);
void arm64_dump_machdep_table(ulong);
ulong arm64_VTOP(ulong);
ulong arm64_PTOV(ulong);
int arm64_IS_VMALLOC_ADDR(ulong);
ulong arm64_swp_type(ulong);
ulong arm64_swp_offset(ulong);
#endif

/*
 *  alpha.c
 */
#ifdef ALPHA
void alpha_init(int);
void alpha_dump_machdep_table(ulong);
#define display_idt_table() \
        error(FATAL, "-d option is not applicable to alpha architecture\n")

#define HWRESET_TASK(X)  ((machdep->flags & HWRESET) && is_task_active(X) && \
                         (task_to_context(X)->processor == 0)) 
#endif

/*
 *  x86.c           
 */
#ifdef X86
void x86_init(int);
void x86_dump_machdep_table(ulong);
void x86_display_idt_table(void);
#define display_idt_table() x86_display_idt_table()
#define KSYMS_START    (0x1)
void x86_dump_eframe_common(struct bt_info *bt, ulong *, int);
char *x86_function_called_by(ulong);
struct syment *x86_jmp_error_code(ulong);
struct syment *x86_text_lock_jmp(ulong, ulong *);

struct machine_specific {
        ulong *idt_table;
	ulong entry_tramp_start;
	ulong entry_tramp_end;
	physaddr_t entry_tramp_start_phys;
	ulonglong last_pmd_read_PAE;
	ulonglong last_ptbl_read_PAE;
	ulong page_protnone;
	int max_numnodes;
	ulong *remap_start_vaddr;
	ulong *remap_end_vaddr;
	ulong *remap_start_pfn;
};

struct syment *x86_is_entry_tramp_address(ulong, ulong *); 
#endif

/*
 * x86_64.c
 */
#ifdef X86_64
void x86_64_init(int);
void x86_64_dump_machdep_table(ulong);
ulong x86_64_PTOV(ulong);
ulong x86_64_VTOP(ulong);
int x86_64_IS_VMALLOC_ADDR(ulong);
ulong x86_64_swp_type(ulong);
ulong x86_64_swp_offset(ulong);
void x86_64_display_idt_table(void);
#define display_idt_table() x86_64_display_idt_table()
long x86_64_exception_frame(ulong, ulong, char *, struct bt_info *, FILE *);
#define EFRAME_INIT (0)

struct x86_64_pt_regs_offsets {
        long r15;
        long r14;
        long r13;
        long r12;
        long rbp;
        long rbx;
/* arguments: non interrupts/non tracing syscalls only save upto here*/
        long r11;
        long r10;
        long r9;
        long r8;
        long rax;
        long rcx;
        long rdx;
        long rsi;
        long rdi;
        long orig_rax;
/* end of arguments */
/* cpu exception frame or undefined */
        long rip;
        long cs;
        long eflags;
        long rsp;
        long ss;
};

#define MAX_EXCEPTION_STACKS 7
#define NMI_STACK (machdep->machspec->stkinfo.NMI_stack_index)

struct x86_64_stkinfo {
	ulong ebase[NR_CPUS][MAX_EXCEPTION_STACKS];
	int esize[MAX_EXCEPTION_STACKS];
	char available[NR_CPUS][MAX_EXCEPTION_STACKS];
	ulong ibase[NR_CPUS];
	int isize;
	int NMI_stack_index;
	char *exception_stacks[MAX_EXCEPTION_STACKS];
};

typedef struct __attribute__((__packed__)) {
        signed short sp_offset;
        signed short bp_offset;
        unsigned int sp_reg:4;
        unsigned int bp_reg:4;
        unsigned int type:2;
        unsigned int end:1;
} kernel_orc_entry;

struct ORC_data {
	int module_ORC;
	uint lookup_num_blocks;
	ulong __start_orc_unwind_ip;
	ulong __stop_orc_unwind_ip;
	ulong __start_orc_unwind;
	ulong __stop_orc_unwind;
	ulong orc_lookup;
	ulong ip_entry;
	ulong orc_entry;
	kernel_orc_entry kernel_orc_entry;
};

#define ORC_TYPE_CALL                   0
#define ORC_TYPE_REGS                   1
#define ORC_TYPE_REGS_IRET              2
#define UNWIND_HINT_TYPE_SAVE           3
#define UNWIND_HINT_TYPE_RESTORE        4

#define ORC_REG_UNDEFINED               0
#define ORC_REG_PREV_SP                 1
#define ORC_REG_DX                      2
#define ORC_REG_DI                      3
#define ORC_REG_BP                      4
#define ORC_REG_SP                      5
#define ORC_REG_R10                     6
#define ORC_REG_R13                     7
#define ORC_REG_BP_INDIRECT             8
#define ORC_REG_SP_INDIRECT             9
#define ORC_REG_MAX                     15

struct machine_specific {
	ulong userspace_top;
	ulong page_offset;
	ulong vmalloc_start_addr;
	ulong vmalloc_end;
	ulong vmemmap_vaddr;
	ulong vmemmap_end;
	ulong modules_vaddr;
	ulong modules_end;
	ulong phys_base;
	char *pml4;
	char *upml;
	ulong last_upml_read;
	ulong last_pml4_read;
	char *irqstack;
	ulong irq_eframe_link;
	struct x86_64_pt_regs_offsets pto;
	struct x86_64_stkinfo stkinfo;
	ulong *current;
	ulong *crash_nmi_rsp;
	ulong vsyscall_page;
	ulong thread_return;
	ulong page_protnone;
	ulong GART_start;
	ulong GART_end;
	ulong kernel_image_size;
	ulong physical_mask_shift;
	ulong pgdir_shift;
        char *p4d;
	ulong last_p4d_read;
	struct ORC_data orc;
	ulong irq_stack_gap;
	ulong kpti_entry_stack;
	ulong kpti_entry_stack_size;
	ulong ptrs_per_pgd;
	ulong cpu_entry_area_start;
	ulong cpu_entry_area_end;
	ulong page_offset_force;
	char **exception_functions;
	ulong sme_mask;
};

#define KSYMS_START    (0x1)
#define PT_REGS_INIT   (0x2)
#define VM_ORIG        (0x4)
#define VM_2_6_11      (0x8)
#define VM_XEN        (0x10)
#define NO_TSS        (0x20)
#define SCHED_TEXT    (0x40)
#define PHYS_BASE     (0x80)
#define VM_XEN_RHEL4 (0x100)
#define FRAMEPOINTER (0x200)
#define GART_REGION  (0x400)
#define NESTED_NMI   (0x800)
#define RANDOMIZED  (0x1000)
#define VM_5LEVEL   (0x2000)
#define ORC         (0x4000)
#define KPTI        (0x8000)
#define L1TF       (0x10000)

#define VM_FLAGS (VM_ORIG|VM_2_6_11|VM_XEN|VM_XEN_RHEL4|VM_5LEVEL)

#define _2MB_PAGE_MASK (~((MEGABYTES(2))-1))
#define _1GB_PAGE_MASK (~((GIGABYTES(1))-1))

#endif

#if defined(X86) || defined(X86_64)

/*
 *  unwind_x86_32_64.c
 */
void init_unwind_table(void);
int dwarf_backtrace(struct bt_info *, int, ulong);
void dwarf_debug(struct bt_info *);
int dwarf_print_stack_entry(struct bt_info *, int);

#endif


/*
 * ppc64.c
 */

/*
 *  This structure was copied from kernel source
 *  in include/asm-ppc/ptrace.h
 */
struct ppc64_pt_regs {
        long gpr[32];
        long nip;
        long msr;
        long orig_gpr3;      /* Used for restarting system calls */
        long ctr;
        long link;
        long xer;
        long ccr;
        long mq;             /* 601 only (not used at present) */
                                /* Used on APUS to hold IPL value. */
	long trap;           /* Reason for being here */
        long dar;            /* Fault registers */
        long dsisr;
        long result;         /* Result of a system call */
};

struct ppc64_elf_siginfo {
    int si_signo;
    int si_code;
    int si_errno;
};

struct ppc64_elf_prstatus {
    struct ppc64_elf_siginfo pr_info;
    short pr_cursig;
    unsigned long pr_sigpend;
    unsigned long pr_sighold;
    pid_t pr_pid;
    pid_t pr_ppid;
    pid_t pr_pgrp;
    pid_t pr_sid;
    struct timeval pr_utime;
    struct timeval pr_stime;
    struct timeval pr_cutime;
    struct timeval pr_cstime;
    struct ppc64_pt_regs pr_reg;
    int pr_fpvalid;
};

#ifdef PPC64

enum emergency_stack_type {
	NONE_STACK		= 0,
	EMERGENCY_STACK,
	NMI_EMERGENCY_STACK,
	MC_EMERGENCY_STACK
};

struct ppc64_opal {
	uint64_t base;
	uint64_t entry;
	uint64_t size;
};

struct ppc64_vmemmap {
        unsigned long phys;
        unsigned long virt;
};

/*
 * Used to store the HW interrupt stack. It is only for 2.4.
 */
struct machine_specific {
	ulong *hwintrstack;
        char *hwstackbuf;
        uint hwstacksize;

	/* Emergency stacks */
	ulong *emergency_sp;
	ulong *nmi_emergency_sp;
	ulong *mc_emergency_sp;

	uint l4_index_size;
	uint l3_index_size;
	uint l2_index_size;
	uint l1_index_size;

	uint ptrs_per_l4;
	uint ptrs_per_l3;
	uint ptrs_per_l2;
	uint ptrs_per_l1;

	uint l4_shift;
	uint l3_shift;
	uint l2_shift;
	uint l1_shift;

	uint pte_rpn_shift;
	ulong pte_rpn_mask;
	ulong pgd_masked_bits;
	ulong pud_masked_bits;
	ulong pmd_masked_bits;

	int vmemmap_cnt;
	int vmemmap_psize;
	ulong vmemmap_base;
	struct ppc64_vmemmap *vmemmap_list;
	ulong _page_pte;
	ulong _page_present;
	ulong _page_user;
	ulong _page_rw;
	ulong _page_guarded;
	ulong _page_coherent;
	ulong _page_no_cache;
	ulong _page_writethru;
	ulong _page_dirty;
	ulong _page_accessed;
	int (*is_kvaddr)(ulong);
	int (*is_vmaddr)(ulong);
	struct ppc64_opal opal;
};

void ppc64_init(int);
void ppc64_dump_machdep_table(ulong);
#define display_idt_table() \
        error(FATAL, "-d option is not applicable to PowerPC architecture\n")
#define KSYMS_START     (0x1)
#define VM_ORIG         (0x2)
#define VMEMMAP_AWARE   (0x4)
#define BOOK3E          (0x8)
#define PHYS_ENTRY_L4   (0x10)
#define SWAP_ENTRY_L4   (0x20)
/*
 * The flag bit for radix MMU in cpu_spec.mmu_features
 * in the kernel is also 0x40.
 */
#define RADIX_MMU       (0x40)
#define OPAL_FW         (0x80)

#define REGION_SHIFT       (60UL)
#define REGION_ID(addr)    (((unsigned long)(addr)) >> REGION_SHIFT)
#define VMEMMAP_REGION_ID  (0xfUL)
#endif

/*
 *  ppc.c
 */
#ifdef PPC
void ppc_init(int);
void ppc_dump_machdep_table(ulong);
void ppc_relocate_nt_prstatus_percpu(void **, uint *);
#define display_idt_table() \
        error(FATAL, "-d option is not applicable to PowerPC architecture\n")
#define KSYMS_START (0x1)
/* This should match PPC_FEATURE_BOOKE from include/asm-powerpc/cputable.h */
#define CPU_BOOKE (0x00008000)
#else
#define ppc_relocate_nt_prstatus_percpu(X,Y) do {} while (0)
#endif

/*
 *  lkcd_fix_mem.c
 */

struct _dump_header_asm_s;
struct _dump_header_s;
ulong get_lkcd_switch_stack(ulong);
int fix_addr_v8(struct _dump_header_asm_s *);
int lkcd_dump_init_v8_arch(struct _dump_header_s *dh);
int fix_addr_v7(int);
int get_lkcd_regs_for_cpu_arch(int cpu, ulong *eip, ulong *esp);
int lkcd_get_kernel_start_v8(ulong *addr);

/*
 * lkcd_v8.c
 */
int get_lkcd_regs_for_cpu_v8(struct bt_info *bt, ulong *eip, ulong *esp);

/*
 *  ia64.c
 */
#ifdef IA64
void ia64_init(int);
void ia64_dump_machdep_table(ulong);
void ia64_dump_line_number(ulong);
ulong ia64_get_switch_stack(ulong);
void ia64_exception_frame(ulong, struct bt_info *bt);
ulong ia64_PTOV(ulong);
ulong ia64_VTOP(ulong);
int ia64_IS_VMALLOC_ADDR(ulong);
#define display_idt_table() \
	error(FATAL, "-d option TBD on ia64 architecture\n");
int ia64_in_init_stack(ulong addr);
int ia64_in_mca_stack_hyper(ulong addr, struct bt_info *bt);
physaddr_t ia64_xen_kdump_p2m(struct xen_kdump_data *xkd, physaddr_t pseudo);

#define OLD_UNWIND       (0x1)   /* CONFIG_IA64_NEW_UNWIND not turned on */
#define NEW_UNWIND       (0x2)   /* CONFIG_IA64_NEW_UNWIND turned on */
#define NEW_UNW_V1       (0x4)
#define NEW_UNW_V2       (0x8)
#define NEW_UNW_V3      (0x10)
#define UNW_OUT_OF_SYNC (0x20)   /* shared data structures out of sync */
#define UNW_READ        (0x40)   /* kernel unw has been read successfully */
#define MEM_LIMIT       (0x80)
#define UNW_PTREGS     (0x100)
#define UNW_R0	       (0x200)

#undef IA64_RBS_OFFSET
#undef IA64_STK_OFFSET
#define IA64_RBS_OFFSET   ((SIZE(task_struct) + 15) & ~15)
#define IA64_STK_OFFSET   (STACKSIZE())

struct machine_specific {
	ulong cpu_data_address;
        ulong unimpl_va_mask;
        ulong unimpl_pa_mask;
	long unw_tables_offset;
	long unw_kernel_table_offset;
	long unw_pt_regs_offsets;
	int script_index;
	struct unw_script *script_cache;
	ulong script_cache_fills;
	ulong script_cache_hits;
	void *unw;
	ulong mem_limit;
	ulong kernel_region;
	ulong kernel_start;
	ulong phys_start;
	ulong vmalloc_start;
	char *ia64_memmap;
	uint64_t efi_memmap_size; 
	uint64_t efi_memdesc_size;
	void (*unwind_init)(void);
	void (*unwind)(struct bt_info *);
	void (*dump_unwind_stats)(void);
	int (*unwind_debug)(ulong);
	int ia64_init_stack_size;
};


/*
 *  unwind.c
 */
void unwind_init_v1(void);
void unwind_v1(struct bt_info *);
void dump_unwind_stats_v1(void);
int unwind_debug_v1(ulong);

void unwind_init_v2(void);
void unwind_v2(struct bt_info *);
void dump_unwind_stats_v2(void);
int unwind_debug_v2(ulong);

void unwind_init_v3(void);
void unwind_v3(struct bt_info *);
void dump_unwind_stats_v3(void);
int unwind_debug_v3(ulong);

#endif  /* IA64 */

/*
 *  s390.c
 */
#ifdef S390 
void s390_init(int);
void s390_dump_machdep_table(ulong);
#define display_idt_table() \
        error(FATAL, "-d option is not applicable to S390 architecture\n")
#define KSYMS_START (0x1)
#endif

/*
 *  s390_dump.c
 */
int is_s390_dump(char *);
FILE* s390_dump_init(char *);
int read_s390_dumpfile(int, void *, int, ulong, physaddr_t);
int write_s390_dumpfile(int, void *, int, ulong, physaddr_t);
uint s390_page_size(void);
int s390_memory_used(void);
int s390_free_memory(void);
int s390_memory_dump(FILE *);
ulong get_s390_panic_task(void);
void get_s390_panicmsg(char *);

/*
 *  s390x.c
 */
#ifdef S390X
void s390x_init(int);
void s390x_dump_machdep_table(ulong);
#define display_idt_table() \
        error(FATAL, "-d option is not applicable to S390X architecture\n")
#define KSYMS_START (0x1)
#endif

/*
 * mips.c
 */
void mips_display_regs_from_elf_notes(int, FILE *);

#ifdef MIPS
void mips_init(int);
void mips_dump_machdep_table(ulong);

#define display_idt_table() \
        error(FATAL, "-d option is not applicable to MIPS architecture\n")

struct mips_regset {
	ulong regs[45];
};

struct mips_pt_regs_main {
        ulong regs[32];
        ulong cp0_status;
        ulong hi;
        ulong lo;
};

struct mips_pt_regs_cp0 {
        ulong cp0_badvaddr;
        ulong cp0_cause;
        ulong cp0_epc;
};

#define KSYMS_START	(0x1)
#define PHYS_BASE	(0x2)

#define KVBASE_MASK	(0x1ffffff)

struct machine_specific {
	ulong phys_base;
	ulong vmalloc_start_addr;
	ulong modules_vaddr;
	ulong modules_end;

	ulong _page_present;
	ulong _page_read;
	ulong _page_write;
	ulong _page_accessed;
	ulong _page_modified;
	ulong _page_global;
	ulong _page_valid;
	ulong _page_no_read;
	ulong _page_no_exec;
	ulong _page_dirty;

	ulong _pfn_shift;

#define _PAGE_PRESENT   (machdep->machspec->_page_present)
#define _PAGE_READ      (machdep->machspec->_page_read)
#define _PAGE_WRITE     (machdep->machspec->_page_write)
#define _PAGE_ACCESSED  (machdep->machspec->_page_accessed)
#define _PAGE_MODIFIED  (machdep->machspec->_page_modified)
#define _PAGE_GLOBAL    (machdep->machspec->_page_global)
#define _PAGE_VALID     (machdep->machspec->_page_valid)
#define _PAGE_NO_READ   (machdep->machspec->_page_no_read)
#define _PAGE_NO_EXEC   (machdep->machspec->_page_no_exec)
#define _PAGE_DIRTY     (machdep->machspec->_page_dirty)
#define _PFN_SHIFT      (machdep->machspec->_pfn_shift)

	struct mips_regset *crash_task_regs;
};
#endif /* MIPS */

/*
 * mips64.c
 */
void mips64_display_regs_from_elf_notes(int, FILE *);

#ifdef MIPS64
void mips64_init(int);
void mips64_dump_machdep_table(ulong);

#define display_idt_table() \
	error(FATAL, "-d option is not applicable to MIPS64 architecture\n")

/* from arch/mips/include/asm/ptrace.h */
struct mips64_register {
	ulong regs[45];
};

struct mips64_pt_regs_main {
	ulong regs[32];
	ulong cp0_status;
	ulong hi;
	ulong lo;
};

struct mips64_pt_regs_cp0 {
	ulong cp0_badvaddr;
	ulong cp0_cause;
	ulong cp0_epc;
};

struct mips64_unwind_frame {
	unsigned long sp;
	unsigned long pc;
	unsigned long ra;
};

#define KSYMS_START	(0x1)

struct machine_specific {
	ulong phys_base;
	ulong vmalloc_start_addr;
	ulong modules_vaddr;
	ulong modules_end;

	ulong _page_present;
	ulong _page_read;
	ulong _page_write;
	ulong _page_accessed;
	ulong _page_modified;
	ulong _page_huge;
	ulong _page_special;
	ulong _page_protnone;
	ulong _page_global;
	ulong _page_valid;
	ulong _page_no_read;
	ulong _page_no_exec;
	ulong _page_dirty;

	ulong _pfn_shift;

	struct mips64_register *crash_task_regs;
};
/* from arch/mips/include/asm/pgtable-bits.h */
#define _PAGE_PRESENT	(machdep->machspec->_page_present)
#define _PAGE_READ	(machdep->machspec->_page_read)
#define _PAGE_WRITE	(machdep->machspec->_page_write)
#define _PAGE_ACCESSED	(machdep->machspec->_page_accessed)
#define _PAGE_MODIFIED	(machdep->machspec->_page_modified)
#define _PAGE_HUGE	(machdep->machspec->_page_huge)
#define _PAGE_SPECIAL	(machdep->machspec->_page_special)
#define _PAGE_PROTNONE	(machdep->machspec->_page_protnone)
#define _PAGE_GLOBAL	(machdep->machspec->_page_global)
#define _PAGE_VALID	(machdep->machspec->_page_valid)
#define _PAGE_NO_READ	(machdep->machspec->_page_no_read)
#define _PAGE_NO_EXEC	(machdep->machspec->_page_no_exec)
#define _PAGE_DIRTY	(machdep->machspec->_page_dirty)
#define _PFN_SHIFT	(machdep->machspec->_pfn_shift)

#endif /* MIPS64 */

/*
 * riscv64.c
 */
void riscv64_display_regs_from_elf_notes(int, FILE *);

#ifdef RISCV64
void riscv64_init(int);
void riscv64_dump_machdep_table(ulong);
int riscv64_IS_VMALLOC_ADDR(ulong);

#define display_idt_table() \
	error(FATAL, "-d option is not applicable to RISCV64 architecture\n")

/* from arch/riscv/include/asm/ptrace.h */
struct riscv64_register {
	ulong regs[36];
};

struct riscv64_pt_regs {
	ulong badvaddr;
	ulong cause;
	ulong epc;
};

struct riscv64_unwind_frame {
	ulong fp;
	ulong sp;
	ulong pc;
};

#define KSYMS_START	(0x1)

struct machine_specific {
	ulong phys_base;
	ulong page_offset;
	ulong vmalloc_start_addr;
	ulong vmalloc_end;
	ulong vmemmap_vaddr;
	ulong vmemmap_end;
	ulong modules_vaddr;
	ulong modules_end;
	ulong kernel_link_addr;

	ulong _page_present;
	ulong _page_read;
	ulong _page_write;
	ulong _page_exec;
	ulong _page_user;
	ulong _page_global;
	ulong _page_accessed;
	ulong _page_dirty;
	ulong _page_soft;

	ulong _pfn_shift;
	ulong va_bits;
	char *p4d;
	ulong last_p4d_read;
	ulong struct_page_size;

	struct riscv64_register *crash_task_regs;
};
/* from arch/riscv/include/asm/pgtable-bits.h */
#define _PAGE_PRESENT	(machdep->machspec->_page_present)
#define _PAGE_READ	(machdep->machspec->_page_read)
#define _PAGE_WRITE	(machdep->machspec->_page_write)
#define _PAGE_EXEC	(machdep->machspec->_page_exec)
#define _PAGE_USER	(machdep->machspec->_page_user)
#define _PAGE_GLOBAL	(machdep->machspec->_page_global)
#define _PAGE_ACCESSED	(machdep->machspec->_page_accessed)
#define _PAGE_DIRTY	(machdep->machspec->_page_dirty)
#define _PAGE_SOFT	(machdep->machspec->_page_soft)
#define _PAGE_SEC	(machdep->machspec->_page_sec)
#define _PAGE_SHARE	(machdep->machspec->_page_share)
#define _PAGE_BUF	(machdep->machspec->_page_buf)
#define _PAGE_CACHE	(machdep->machspec->_page_cache)
#define _PAGE_SO	(machdep->machspec->_page_so)
#define _PAGE_SPECIAL	_PAGE_SOFT
#define _PAGE_TABLE	_PAGE_PRESENT
#define _PAGE_PROT_NONE _PAGE_READ
#define _PAGE_PFN_SHIFT 10

/* from 'struct pt_regs' definitions of RISC-V arch */
#define RISCV64_REGS_EPC  0
#define RISCV64_REGS_RA   1
#define RISCV64_REGS_SP   2
#define RISCV64_REGS_FP   8

#endif /* RISCV64 */

/*
 * sparc64.c
 */
#ifdef SPARC64
void sparc64_init(int);
void sparc64_dump_machdep_table(ulong);
int sparc64_vmalloc_addr(ulong);
#define display_idt_table() \
	error(FATAL, "The -d option is not applicable to sparc64.\n")
#endif

/*
 *  netdump.c 
 */
int is_netdump(char *, ulong);
uint netdump_page_size(void);
int read_netdump(int, void *, int, ulong, physaddr_t);
int write_netdump(int, void *, int, ulong, physaddr_t);
int netdump_free_memory(void);
int netdump_memory_used(void);
int netdump_init(char *, FILE *);
ulong get_netdump_panic_task(void);
ulong get_netdump_switch_stack(ulong);
FILE *set_netdump_fp(FILE *);
int netdump_memory_dump(FILE *);
void get_netdump_regs(struct bt_info *, ulong *, ulong *);
int is_partial_netdump(void);
void get_netdump_regs_x86(struct bt_info *, ulong *, ulong *);
void get_netdump_regs_x86_64(struct bt_info *, ulong *, ulong *);
void dump_registers_for_elf_dumpfiles(void);
struct vmcore_data;
struct vmcore_data *get_kdump_vmcore_data(void);
int read_kdump(int, void *, int, ulong, physaddr_t);
int write_kdump(int, void *, int, ulong, physaddr_t);
int is_kdump(char *, ulong);
int kdump_init(char *, FILE *);
ulong get_kdump_panic_task(void);
uint kdump_page_size(void);
int kdump_free_memory(void);
int kdump_memory_used(void);
int kdump_memory_dump(FILE *);
void get_kdump_regs(struct bt_info *, ulong *, ulong *);
void xen_kdump_p2m_mfn(char *);
int is_sadump_xen(void);
void set_xen_phys_start(char *);
ulong xen_phys_start(void);
int xen_major_version(void);
int xen_minor_version(void);
int get_netdump_arch(void);
int exist_regs_in_elf_notes(struct task_context *);
void *get_regs_from_elf_notes(struct task_context *);
void map_cpus_to_prstatus(void);
int kdump_phys_base(ulong *);
int kdump_set_phys_base(ulong);
int arm_kdump_phys_base(ulong *);
int arm_kdump_phys_end(ulong *);
int is_proc_kcore(char *, ulong);
int proc_kcore_init(FILE *, int);
int read_proc_kcore(int, void *, int, ulong, physaddr_t);
int write_proc_kcore(int, void *, int, ulong, physaddr_t);
int kcore_memory_dump(FILE *);
void dump_registers_for_qemu_mem_dump(void);
void kdump_backup_region_init(void);
void display_regs_from_elf_notes(int, FILE *);
void display_ELF_note(int, int, void *, FILE *);
void *netdump_get_prstatus_percpu(int);
int kdump_kaslr_check(void);
void display_vmcoredd_note(void *ptr, FILE *ofp);
int kdump_get_nr_cpus(void);
QEMUCPUState *kdump_get_qemucpustate(int);
void kdump_device_dump_info(FILE *);
void kdump_device_dump_extract(int, char *, FILE *);
#define PRSTATUS_NOTE (1)
#define QEMU_NOTE     (2)

/*
 * ramdump.c
 */
int is_ramdump(char *pattern);
char *ramdump_to_elf(void);
void ramdump_elf_output_file(char *opt);
void ramdump_cleanup(void);
int read_ramdump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr);
void show_ramdump_files(void);
void dump_ramdump_data(void);
int is_ramdump_image(void);

/*
 *  diskdump.c
 */
int is_diskdump(char *);
uint diskdump_page_size(void);
int read_diskdump(int, void *, int, ulong, physaddr_t);
int write_diskdump(int, void *, int, ulong, physaddr_t);
int diskdump_free_memory(void);
int diskdump_memory_used(void);
int diskdump_init(char *, FILE *);
ulong get_diskdump_panic_task(void);
ulong get_diskdump_switch_stack(ulong);
int diskdump_memory_dump(FILE *);
FILE *set_diskdump_fp(FILE *);
void get_diskdump_regs(struct bt_info *, ulong *, ulong *);
int diskdump_phys_base(unsigned long *);
int diskdump_set_phys_base(unsigned long);
extern ulong *diskdump_flags;
int is_partial_diskdump(void);
int get_dump_level(void);
int dumpfile_is_split(void);
void show_split_dumpfiles(void);
void x86_process_elf_notes(void *, unsigned long);
void *diskdump_get_prstatus_percpu(int);
void map_cpus_to_prstatus_kdump_cmprs(void);
void diskdump_display_regs(int, FILE *);
void process_elf32_notes(void *, ulong);
void process_elf64_notes(void *, ulong);
void dump_registers_for_compressed_kdump(void);
int diskdump_kaslr_check(void);
int diskdump_get_nr_cpus(void);
QEMUCPUState *diskdump_get_qemucpustate(int);
void diskdump_device_dump_info(FILE *);
void diskdump_device_dump_extract(int, char *, FILE *);
ulong readswap(ulonglong pte_val, char *buf, ulong len, ulonglong vaddr);
/*support for zram*/
ulong try_zram_decompress(ulonglong pte_val, unsigned char *buf, ulong len, ulonglong vaddr);
#define OBJ_TAG_BITS     1
#ifndef MAX_POSSIBLE_PHYSMEM_BITS
#define MAX_POSSIBLE_PHYSMEM_BITS (MAX_PHYSMEM_BITS())
#endif
#define _PFN_BITS        (MAX_POSSIBLE_PHYSMEM_BITS - PAGESHIFT())
#define OBJ_INDEX_BITS   (BITS_PER_LONG - _PFN_BITS - OBJ_TAG_BITS)
#define OBJ_INDEX_MASK   ((1 << OBJ_INDEX_BITS) - 1)
#define ZS_HANDLE_SIZE   (sizeof(unsigned long))
#define ZSPAGE_MAGIC     0x58
#define SWAP_ADDRESS_SPACE_SHIFT	14
#define SECTOR_SHIFT     9
#define SECTORS_PER_PAGE_SHIFT  (PAGESHIFT() - SECTOR_SHIFT)
#define SECTORS_PER_PAGE        (1 << SECTORS_PER_PAGE_SHIFT)
#define ZRAM_FLAG_SHIFT         (1<<24)
#define ZRAM_FLAG_SAME_BIT      (1<<25)
struct zspage {
    struct {
        unsigned int fullness : 2;
        unsigned int class : 9;
        unsigned int isolated : 3;
        unsigned int magic : 8;
    };
    unsigned int inuse;
    unsigned int freeobj;
};

/*
 * makedumpfile.c
 */
void check_flattened_format(char *file);
int is_flattened_format(char *file);
int read_flattened_format(int fd, off_t offset, void *buf, size_t size);
void dump_flat_header(FILE *);

/*
 * xendump.c
 */
int is_xendump(char *);
int read_xendump(int, void *, int, ulong, physaddr_t);
int write_xendump(int, void *, int, ulong, physaddr_t);
uint xendump_page_size(void);
int xendump_free_memory(void);
int xendump_memory_used(void);
int xendump_init(char *, FILE *);
int xendump_memory_dump(FILE *);
ulong get_xendump_panic_task(void);
void get_xendump_regs(struct bt_info *, ulong *, ulong *);
char *xc_core_mfn_to_page(ulong, char *);
int xc_core_mfn_to_page_index(ulong);
void xendump_panic_hook(char *);
int read_xendump_hyper(int, void *, int, ulong, physaddr_t);
struct xendump_data *get_xendump_data(void);

/*
 * kvmdump.c
 */
int is_kvmdump(char *);
int is_kvmdump_mapfile(char *);
int kvmdump_init(char *, FILE *);
int read_kvmdump(int, void *, int, ulong, physaddr_t);
int write_kvmdump(int, void *, int, ulong, physaddr_t);
int kvmdump_free_memory(void);
int kvmdump_memory_used(void);
int kvmdump_memory_dump(FILE *);
void get_kvmdump_regs(struct bt_info *, ulong *, ulong *);
ulong get_kvmdump_panic_task(void);
int kvmdump_phys_base(unsigned long *);
void kvmdump_display_regs(int, FILE *);
void set_kvmhost_type(char *);
void set_kvm_iohole(char *);
struct kvm_register_set {
	union {
		uint32_t cs;
		uint32_t ss;
		uint32_t ds;
		uint32_t es;
		uint32_t fs;
		uint32_t gs;
		uint64_t ip;
		uint64_t flags;
		uint64_t regs[16];
	} x86;
};
int get_kvm_register_set(int, struct kvm_register_set *);

/*
 * sadump.c
 */
int is_sadump(char *);
uint sadump_page_size(void);
int read_sadump(int, void *, int, ulong, physaddr_t);
int write_sadump(int, void *, int, ulong, physaddr_t);
int sadump_init(char *, FILE *);
int sadump_is_diskset(void);
ulong get_sadump_panic_task(void);
ulong get_sadump_switch_stack(ulong);
int sadump_memory_used(void);
int sadump_free_memory(void);
int sadump_memory_dump(FILE *);
FILE *set_sadump_fp(FILE *);
void get_sadump_regs(struct bt_info *bt, ulong *ipp, ulong *spp);
void sadump_display_regs(int, FILE *);
int sadump_phys_base(ulong *);
int sadump_set_phys_base(ulong);
void sadump_show_diskset(void);
int sadump_is_zero_excluded(void);
void sadump_set_zero_excluded(void);
void sadump_unset_zero_excluded(void);
struct sadump_data;
struct sadump_data *get_sadump_data(void);
int sadump_calc_kaslr_offset(ulong *);
int sadump_get_nr_cpus(void);
int sadump_get_cr3_cr4_idtr(int, ulong *, ulong *, ulong *);

/*
 * qemu.c
 */
int qemu_init(char *);

/*
 * qemu-load.c
 */
int is_qemu_vm_file(char *);
void dump_qemu_header(FILE *);

/*
 *  net.c
 */
void net_init(void);
void dump_net_table(void);
void dump_sockets_workhorse(ulong, ulong, struct reference *);

/*
 *  remote.c
 */
int is_remote_daemon(char *);
physaddr_t get_remote_phys_base(physaddr_t, physaddr_t);
physaddr_t remote_vtop(int, physaddr_t);
int get_remote_regs(struct bt_info *, ulong *, ulong *);
physaddr_t get_remote_cr3(int);
void remote_fd_init(void);
int get_remote_file(struct remote_file *);
uint remote_page_size(void);
int find_remote_module_objfile(struct load_module *lm, char *, char *);
int remote_free_memory(void);
int remote_memory_dump(int);
int remote_memory_used(void);
void remote_exit(void);
int remote_execute(void);
void remote_clear_pipeline(void);
int remote_memory_read(int, char *, int, physaddr_t, int);

/*
 * vmware_vmss.c
 */
int is_vmware_vmss(char *filename);
int vmware_vmss_init(char *filename, FILE *ofp);
uint vmware_vmss_page_size(void);
int read_vmware_vmss(int, void *, int, ulong, physaddr_t);
int write_vmware_vmss(int, void *, int, ulong, physaddr_t);
void vmware_vmss_display_regs(int, FILE *);
void get_vmware_vmss_regs(struct bt_info *, ulong *, ulong *);
int vmware_vmss_memory_dump(FILE *);
void dump_registers_for_vmss_dump(void);
int vmware_vmss_valid_regs(struct bt_info *);
int vmware_vmss_get_nr_cpus(void);
int vmware_vmss_get_cr3_cr4_idtr(int, ulong *, ulong *, ulong *);
int vmware_vmss_phys_base(ulong *phys_base);
int vmware_vmss_set_phys_base(ulong);
int vmware_vmss_get_cpu_reg(int, int, const char *, int, void *);

/*
 * vmware_guestdump.c
 */
int is_vmware_guestdump(char *filename);
int vmware_guestdump_init(char *filename, FILE *ofp);
int vmware_guestdump_memory_dump(FILE *);

/*
 * kaslr_helper.c
 */
int calc_kaslr_offset(ulong *, ulong *);

/*
 * printk.c
 */
void dump_lockless_record_log(int);

/*
 *  gnu_binutils.c
 */

/* NO LONGER IN USE */

/*
 *  test.c
 */
void cmd_template(void);
void foreach_test(ulong, ulong);

/*
 *  va_server.c
 */
int mclx_page_size(void);
int vas_memory_used(void);
int vas_memory_dump(FILE *);
int vas_free_memory(char *);
void set_vas_debug(ulong);
size_t vas_write(void *, size_t);
int va_server_init(char *, ulong *, ulong *, ulong *);
size_t vas_read(void *, size_t);
int vas_lseek(ulong, int);

/*
 *  lkcd_x86_trace.c
 */
int lkcd_x86_back_trace(struct bt_info *, int, FILE *);

/*
 * lkcd_common.c
 */
int lkcd_dump_init(FILE *, int, char *);
ulong get_lkcd_panic_task(void);
void get_lkcd_panicmsg(char *);
int is_lkcd_compressed_dump(char *);
void dump_lkcd_environment(ulong);
int lkcd_lseek(physaddr_t);
long lkcd_read(void *, long);
void set_lkcd_debug(ulong);
FILE *set_lkcd_fp(FILE *);
uint lkcd_page_size(void);
int lkcd_memory_used(void);
int lkcd_memory_dump(FILE *);
int lkcd_free_memory(void);
void lkcd_print(char *, ...);
void set_remote_lkcd_panic_data(ulong, char *);
void set_lkcd_nohash(void);
int lkcd_load_dump_page_header(void *, ulong);
void lkcd_dumpfile_complaint(uint32_t, uint32_t, int);
int set_mb_benchmark(ulong);
ulonglong fix_lkcd_address(ulonglong);
int lkcd_get_kernel_start(ulong *addr);
int get_lkcd_regs_for_cpu(struct bt_info *bt, ulong *eip, ulong *esp);

/*
 * lkcd_v1.c
 */
int lkcd_dump_init_v1(FILE *, int);
void dump_dump_page_v1(char *, void *);
void dump_lkcd_environment_v1(ulong);
uint32_t get_dp_size_v1(void);
uint32_t get_dp_flags_v1(void);
uint64_t get_dp_address_v1(void);

/*
 * lkcd_v2_v3.c
 */
int lkcd_dump_init_v2_v3(FILE *, int);
void dump_dump_page_v2_v3(char *, void *);
void dump_lkcd_environment_v2_v3(ulong);
uint32_t get_dp_size_v2_v3(void);
uint32_t get_dp_flags_v2_v3(void);
uint64_t get_dp_address_v2_v3(void);

/*
 * lkcd_v5.c
 */
int lkcd_dump_init_v5(FILE *, int);
void dump_dump_page_v5(char *, void *);
void dump_lkcd_environment_v5(ulong);
uint32_t get_dp_size_v5(void); 
uint32_t get_dp_flags_v5(void);
uint64_t get_dp_address_v5(void); 

/*
 * lkcd_v7.c
 */
int lkcd_dump_init_v7(FILE *, int, char *);
void dump_dump_page_v7(char *, void *);
void dump_lkcd_environment_v7(ulong);
uint32_t get_dp_size_v7(void); 
uint32_t get_dp_flags_v7(void);
uint64_t get_dp_address_v7(void); 

/*
 * lkcd_v8.c
 */
int lkcd_dump_init_v8(FILE *, int, char *);
void dump_dump_page_v8(char *, void *);
void dump_lkcd_environment_v8(ulong);
uint32_t get_dp_size_v8(void); 
uint32_t get_dp_flags_v8(void);
uint64_t get_dp_address_v8(void); 

#ifdef LKCD_COMMON
/*
 *  Until they differ across versions, these remain usable in the common
 *  routines in lkcd_common.c
 */
#define LKCD_DUMP_MAGIC_NUMBER        (0xa8190173618f23edULL)
#define LKCD_DUMP_MAGIC_LIVE          (0xa8190173618f23cdULL)  

#define LKCD_DUMP_V1                  (0x1)  /* DUMP_VERSION_NUMBER */ 
#define LKCD_DUMP_V2                  (0x2)  /* DUMP_VERSION_NUMBER */
#define LKCD_DUMP_V3                  (0x3)  /* DUMP_VERSION_NUMBER */
#define LKCD_DUMP_V5                  (0x5)  /* DUMP_VERSION_NUMBER */
#define LKCD_DUMP_V6                  (0x6)  /* DUMP_VERSION_NUMBER */
#define LKCD_DUMP_V7                  (0x7)  /* DUMP_VERSION_NUMBER */
#define LKCD_DUMP_V8                  (0x8)  /* DUMP_VERSION_NUMBER */
#define LKCD_DUMP_V9                  (0x9)  /* DUMP_VERSION_NUMBER */
#define LKCD_DUMP_V10                 (0xa)  /* DUMP_VERSION_NUMBER */

#define LKCD_DUMP_VERSION_NUMBER_MASK (0xf)
#define LKCD_DUMP_RAW                 (0x1)   /* DUMP_[DH_]RAW */ 
#define LKCD_DUMP_COMPRESSED          (0x2)   /* DUMP_[DH_]COMPRESSED */
#define LKCD_DUMP_END                 (0x4)   /* DUMP_[DH_]END */

#define LKCD_DUMP_COMPRESS_NONE    (0x0)      /* DUMP_COMPRESS_NONE */ 
#define LKCD_DUMP_COMPRESS_RLE     (0x1)      /* DUMP_COMPRESS_RLE */
#define LKCD_DUMP_COMPRESS_GZIP    (0x2)      /* DUMP_COMPRESS_GZIP */

#define LKCD_DUMP_MCLX_V0            (0x80000000)   /* MCLX mod of LKCD */
#define LKCD_DUMP_MCLX_V1            (0x40000000)   /* Extra page header data */
#define LKCD_OFFSET_TO_FIRST_PAGE    (65536)

#define MCLX_PAGE_HEADERS            (4096)
#define MCLX_V1_PAGE_HEADER_CACHE    ((sizeof(uint64_t)) * MCLX_PAGE_HEADERS)

/*
 *  lkcd_load_dump_page_header() return values
 */
#define LKCD_DUMPFILE_OK  (0)
#define LKCD_DUMPFILE_EOF (1)
#define LKCD_DUMPFILE_END (2)

/*
 *  Common handling of LKCD dump environment 
 */
#define LKCD_CACHED_PAGES     (16)
#define LKCD_PAGE_HASH        (32)
#define LKCD_DUMP_HEADER_ONLY (1)       /* arguments to lkcd_dump_environment */
#define LKCD_DUMP_PAGE_ONLY   (2)

#define LKCD_VALID     (0x1)      	       /* flags */
#define LKCD_REMOTE    (0x2)
#define LKCD_NOHASH    (0x4)
#define LKCD_MCLX      (0x8)
#define LKCD_BAD_DUMP (0x10)

struct page_hash_entry {
	uint32_t pg_flags;
	uint64_t pg_addr;
	off_t pg_hdr_offset;
	struct page_hash_entry *next;
};

struct page_desc {
	off_t offset; /* lseek offset in dump file */
};

struct physmem_zone {
	uint64_t start;
	struct page_desc *pages;
};

struct fix_addrs {
        ulong task;
        ulong saddr;
        ulong sw;
};


struct lkcd_environment {
        int fd;                        /* dumpfile file descriptor */
	ulong flags;                   /* flags from above */
	ulong debug;                   /* shadow of pc->debug */
	FILE *fp;		       /* abstracted fp for fprintf */
        void *dump_header;             /* header stash, v1 or v2 */
	void *dump_header_asm;         /* architecture specific header for v2 */
	void *dump_header_asm_smp;     /* architecture specific header for v7 & v8 */
        void *dump_page;               /* current page header holder */
	uint32_t version;              /* version number of this dump */
	uint32_t page_size;	       /* size of a Linux memory page */
	int page_shift;                /* byte address to page */
	int bits;                      /* processor bitsize */
	ulong panic_task;              /* panic task address */
	char *panic_string;            /* pointer to stashed panic string */
	uint32_t compression;          /* compression type */
        uint32_t (*get_dp_size)(void); /* returns current page's dp_size */
        uint32_t (*get_dp_flags)(void); /* returns current page's dp_size */
        uint64_t (*get_dp_address)(void); /* returns current page's dp_address*/
	size_t page_header_size;       /* size of version's page header */
        unsigned long curpos;          /* offset into current page */
        uint64_t curpaddr;             /* current page's physical address */
	off_t curhdroffs;              /* current page's header offset */
        char *curbufptr;               /* pointer to uncompressed page buffer */
        uint64_t kvbase;               /* physical-to-LKCD page address format*/
        char *page_cache_buf;          /* base of cached buffer pages */
        char *compressed_page;         /* copy of compressed page data */
        int evict_index;               /* next page to evict */
        ulong evictions;               /* total evictions done */
        struct page_cache_hdr {        /* header for each cached page */
		uint32_t pg_flags;
                uint64_t pg_addr;
                char *pg_bufptr;
                ulong pg_hit_count;
        } page_cache_hdr[LKCD_CACHED_PAGES];
	struct page_hash_entry *page_hash;
	ulong total_pages;
	ulong benchmark_pages;
	ulong benchmarks_done;
	off_t *mb_hdr_offsets;
	ulong total_reads;
	ulong cached_reads;
	ulong hashed_reads;
	ulong hashed;
	ulong compressed;
	ulong raw;

	/* lkcd_v7 additions */
	char    *dumpfile_index;	/* array of offsets for each page */
	int     ifd;			/* index file for dump (LKCD V7+) */
	long 	memory_pages;		/* Mamimum index of dump pages */
	off_t 	page_offset_max;	/* Offset of page with greatest offset seen so far */
	long 	page_index_max;		/* Index  of page with greatest offset seen so far */
	off_t 	*page_offsets;		/* Pointer to huge array with seek offsets */
					/* NB: There are no holes in the array */

	struct physmem_zone *zones;	/* Array of physical memory zones */
	int 	num_zones;		/* Number of zones initialized */
	int 	max_zones;		/* Size of the zones array */
	long	zoned_offsets;		/* Number of stored page offsets */
	uint64_t zone_mask;
	int	zone_shift;

	int     fix_addr_num;           /* Number of active stacks to switch to saved values */
	struct fix_addrs *fix_addr;     /* Array of active stacks to switch to saved values */                                                                                


};

#define ZONE_ALLOC 128	
#define ZONE_SIZE (MEGABYTES(512))

#define MEGABYTE_ALIGNED(vaddr)  (!((uint64_t)(vaddr) & MEGABYTE_MASK))

#define LKCD_PAGE_HASH_INDEX(paddr) \
        (((paddr) >> lkcd->page_shift) % LKCD_PAGE_HASH)
#define LKCD_PAGES_PER_MEGABYTE() (MEGABYTES(1) / lkcd->page_size)
#define LKCD_PAGE_MEGABYTE(page)  ((page) / LKCD_PAGES_PER_MEGABYTE())
#define LKCD_BENCHMARKS_DONE()  (lkcd->benchmarks_done >= lkcd->benchmark_pages)
#define LKCD_VALID_PAGE(flags) ((flags) & LKCD_VALID)

extern struct lkcd_environment *lkcd;

#define LKCD_DEBUG(x)  (lkcd->debug >= (x))
#undef BITS
#undef BITS32
#undef BITS64
#define BITS()    (lkcd->bits)
#define BITS32()  (lkcd->bits == 32)
#define BITS64()  (lkcd->bits == 64)

#endif  /* LKCD_COMMON */

/*
 *  gdb_interface.c
 */
void gdb_main_loop(int, char **);
void display_gdb_banner(void);
void get_gdb_version(void);
void gdb_session_init(void);
void gdb_interface(struct gnu_request *);
int gdb_pass_through(char *, FILE *, ulong);
int gdb_readmem_callback(ulong, void *, int, int);
int gdb_line_number_callback(ulong, ulong, ulong);
int gdb_print_callback(ulong);
char *gdb_lookup_module_symbol(ulong, ulong *);
void gdb_error_hook(void);
void restore_gdb_sanity(void);
int is_gdb_command(int, ulong);
char *gdb_command_string(int, char *, int);
void dump_gnu_request(struct gnu_request *, int);
int gdb_CRASHDEBUG(ulong);
void dump_gdb_data(void);
void update_gdb_hooks(void);
void gdb_readnow_warning(void);
int gdb_set_crash_scope(ulong, char *);
extern int *gdb_output_format;
extern unsigned int *gdb_print_max;
extern unsigned char *gdb_prettyprint_structs;
extern unsigned char *gdb_prettyprint_arrays;
extern unsigned int *gdb_repeat_count_threshold;
extern unsigned char *gdb_stop_print_at_null;
extern unsigned int *gdb_output_radix;

/*
 *  gdb/top.c
 */
extern void execute_command (char *, int);
#if defined(GDB_5_3) || defined(GDB_6_0) || defined(GDB_6_1)
extern void (*command_loop_hook)(void);
extern void (*error_hook)(void);
#else
extern void (*deprecated_command_loop_hook)(void);

/*
 *  gdb/exceptions.c
 */
extern void (*error_hook)(void);
#endif

/*
 *  gdb/symtab.c
 */
extern void gdb_command_funnel(struct gnu_request *);

/*
 *  gdb/symfile.c
 */
#if defined(GDB_6_0) || defined(GDB_6_1)
struct objfile;
extern void (*target_new_objfile_hook)(struct objfile *);
#endif

/*
 *  gdb/valprint.c
 */
extern unsigned output_radix;
#if defined(GDB_5_3) || defined(GDB_6_0) || defined(GDB_6_1)
extern int output_format;
extern int prettyprint_structs;
extern int prettyprint_arrays;
extern int repeat_count_threshold;
extern unsigned int print_max;
extern int stop_print_at_null;
#endif

#ifdef GDB_7_6
/*
 *  gdb/cleanups.c
 */
struct cleanup;
extern struct cleanup *all_cleanups(void);
extern void do_cleanups(struct cleanup *);
#else
/*
 *  gdb/utils.c
 */
extern void do_cleanups(void *);
#endif

/*
 *  gdb/version.c
 */
extern char *version;

/*
 *  gdb/disasm.c
 */
#ifdef GDB_5_3
extern int gdb_disassemble_from_exec;
#endif

/*
 *  readline/readline.c
 */
#ifdef GDB_5_3
extern char *readline(char *);
#else
extern char *readline(const char *);
#endif
extern int rl_editing_mode;

/*
 *  readline/history.c
 */
extern int history_offset;

/*
 *  external gdb routines
 */
extern int gdb_main_entry(int, char **);
#ifdef GDB_5_3
extern unsigned long calc_crc32(unsigned long, unsigned char *, size_t);
#else
extern unsigned long gnu_debuglink_crc32 (unsigned long, unsigned char *, size_t);
#endif
extern int have_partial_symbols(void); 
extern int have_full_symbols(void);

#if defined(X86) || defined(X86_64) || defined(IA64)
#define XEN_HYPERVISOR_ARCH 
#endif

/*
 * Register numbers must be in sync with gdb/features/i386/64bit-core.c
 * to make crash_target->fetch_registers() ---> machdep->get_cpu_reg()
 * working properly.
 */
enum x86_64_regnum {
        RAX_REGNUM,
        RBX_REGNUM,
        RCX_REGNUM,
        RDX_REGNUM,
        RSI_REGNUM,
        RDI_REGNUM,
        RBP_REGNUM,
        RSP_REGNUM,
        R8_REGNUM,
        R9_REGNUM,
        R10_REGNUM,
        R11_REGNUM,
        R12_REGNUM,
        R13_REGNUM,
        R14_REGNUM,
        R15_REGNUM,
        RIP_REGNUM,
        EFLAGS_REGNUM,
        CS_REGNUM,
        SS_REGNUM,
        DS_REGNUM,
        ES_REGNUM,
        FS_REGNUM,
        GS_REGNUM,
        ST0_REGNUM,
        ST1_REGNUM,
        ST2_REGNUM,
        ST3_REGNUM,
        ST4_REGNUM,
        ST5_REGNUM,
        ST6_REGNUM,
        ST7_REGNUM,
        FCTRL_REGNUM,
        FSTAT_REGNUM,
        FTAG_REGNUM,
        FISEG_REGNUM,
        FIOFF_REGNUM,
        FOSEG_REGNUM,
        FOOFF_REGNUM,
        FOP_REGNUM,
        LAST_REGNUM
};

#endif /* !GDB_COMMON */
