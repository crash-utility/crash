/*
 *    s390 debug feature command for crash
 *
 *    Copyright (C) IBM Corp. 2006
 *    Author(s): Michael Holzheu <holzheu@de.ibm.com>
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

#if defined(S390) || defined(S390X)

#include "defs.h"
#include <iconv.h>
#include <ctype.h>

/*
 * Compat layer to integrate lcrash commands into crash
 * Maps lcrash API to crash functions
 */

#define KL_NBPW sizeof(long)
#define KL_ERRORFP stderr
#define MAX_ARGS 128
#define MAX_CMDLINE 256

#define C_FALSE         0x00000001   /* Command takes no arguments */
#define C_TRUE          0x00000002   /* Command requires arguments */
#define C_ALL           0x00000004   /* All elements */
#define C_PERM          0x00000008   /* Allocate perminant blocks */
#define C_TEMP          0x00000000   /* For completeness */
#define C_FULL          0x00000010   /* Full output */
#define C_LIST          0x00000020   /* List items */
#define C_NEXT          0x00000040   /* Follow links */
#define C_WRITE         0x00000080   /* Write output to file */
#define C_NO_OPCHECK    0x00000100   /* Don't reject bad cmd line options */
#define C_ITER          0x00000200   /* set iteration threshold */

#define C_LFLG_SHFT 12

#define KL_ARCH_S390 0
#define KL_ARCH_S390X 1
#ifdef __s390x__
#define KL_ARCH KL_ARCH_S390X
#define FMTPTR "l"
#define KL_PTRSZ 8
#else
#define KL_ARCH KL_ARCH_S390
#define FMTPTR "ll"
#define KL_PTRSZ 4
#endif

/* Start TOD time of kernel in usecs for relative time stamps */
static uint64_t tod_clock_base_us;

typedef unsigned long uaddr_t;
typedef unsigned long kaddr_t;

typedef struct _syment {
	char *s_name;
	kaddr_t s_addr;
} syment_t;

typedef struct option_s {
	struct option_s	*op_next;
	char		op_char;
	char		*op_arg;
} option_t;

typedef struct command_s {
	int		flags;
	char		cmdstr[MAX_CMDLINE];
	char		*command;
	char		*cmdline;
	option_t	*options;
	int		nargs;
	char		*args[MAX_ARGS];
	char		*pipe_cmd;
	FILE		*ofp;
	FILE		*efp;
} command_t;

static inline syment_t* kl_lkup_symaddr(kaddr_t addr)
{
	static syment_t sym;
	struct syment *crash_sym;

	crash_sym = value_search(addr, &sym.s_addr);
	if (!crash_sym)
		return NULL;
	sym.s_name = crash_sym->name;
	return &sym;
}

static inline syment_t* kl_lkup_symname(char* name)
{
	static syment_t sym;
	sym.s_addr = symbol_value(name);
	sym.s_name = NULL;
	if(!sym.s_addr)
		return NULL;
	else
		return &sym;
}

static inline void GET_BLOCK(kaddr_t addr, int size, void* ptr)
{
	readmem(addr, KVADDR,ptr,size,"GET_BLOCK",FAULT_ON_ERROR);
}

static inline kaddr_t KL_VREAD_PTR(kaddr_t addr)
{
	unsigned long ptr;
	readmem(addr, KVADDR,&ptr,sizeof(ptr),"GET_BLOCK",FAULT_ON_ERROR);
	return (kaddr_t)ptr;
}

static inline uint32_t KL_GET_UINT32(void* ptr)
{
	return *((uint32_t*)ptr);
}

static inline uint64_t KL_GET_UINT64(void* ptr)
{
	return *((uint64_t*)ptr);
}

static inline kaddr_t KL_GET_PTR(void* ptr)
{
	return *((kaddr_t*)ptr);
}

static inline void* K_PTR(void* addr, char* struct_name, char* member_name)
{
	return addr+MEMBER_OFFSET(struct_name,member_name);
}

static inline unsigned long KL_ULONG(void* ptr, char* struct_name, char*
				     member_name)
{
	return ULONG(ptr+MEMBER_OFFSET(struct_name,member_name));
}

static inline uint32_t KL_VREAD_UINT32(kaddr_t addr)
{
	uint32_t rc;
	readmem(addr, KVADDR,&rc,sizeof(rc),"KL_VREAD_UINT32",FAULT_ON_ERROR);
	return rc;
}

static inline uint32_t KL_INT(void* ptr, char* struct_name, char* member_name)
{
	return UINT(ptr+MEMBER_OFFSET(struct_name,member_name));
}

static inline int set_cmd_flags(command_t *cmd, int flags, char *extraops)
{
	return 0;
}

#define USEC_PER_SEC 1000000L
/* Time of day clock value for 1970/01/01 */
#define TOD_UNIX_EPOCH (0x8126d60e46000000LL - (0x3c26700LL * 1000000 * 4096))
/* Time of day clock value for 1970/01/01 in usecs */
#define TOD_UNIX_EPOCH_US (TOD_UNIX_EPOCH >> 12)

static inline void kl_s390tod_to_timeval(uint64_t todval, struct timeval *xtime)
{
	uint64_t todval_us;

	/* Convert TOD to usec (51th bit of TOD is us) */
	todval_us = todval >> 12;
	/* Add base if we have relative time stamps */
	todval_us += tod_clock_base_us;
	/* Subtract EPOCH that we get time in usec since 1970 */
	todval_us -= TOD_UNIX_EPOCH_US;
	xtime->tv_sec  = todval_us / USEC_PER_SEC;
	xtime->tv_usec = todval_us % USEC_PER_SEC;
}

static inline int kl_struct_len(char* struct_name)
{
	return STRUCT_SIZE(struct_name);
}

static inline kaddr_t kl_funcaddr(kaddr_t addr)
{
	struct syment *crash_sym;

	crash_sym = value_search(addr, &addr);
	if (!crash_sym)
		return -1;
	else
		return crash_sym->value;
}

#define CMD_USAGE(cmd, s) \
	fprintf(cmd->ofp, "Usage: %s %s\n", cmd->command, s); \
	fprintf(cmd->ofp, "Enter \"help %s\" for details.\n",cmd->command);

/*
 * s390 debug feature implementation
 */

#ifdef DBF_DYNAMIC_VIEWS	/* views defined in shared libs */
#include <dlfcn.h>
#endif

/* Local flags
 */

#define LOAD_FLAG (1 << C_LFLG_SHFT)
#define VIEWS_FLAG (2 << C_LFLG_SHFT)
#define SAVE_DBF_FLAG (4 << C_LFLG_SHFT)

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif

/* Stuff which has to match with include/asm-s390/debug.h */

#define DBF_VERSION_V1 1
#define DBF_VERSION_V2 2
#define DBF_VERSION_V3 3
#define PAGE_SIZE 4096
#define DEBUG_MAX_VIEWS	    10 /* max number of views in proc fs */
#define DEBUG_MAX_PROCF_LEN	64 /* max length for a proc file name */
#define DEBUG_SPRINTF_MAX_ARGS 10

/* define debug-structures for lcrash */
#define DEBUG_DATA(entry) (char*)(entry + 1)

typedef struct debug_view_s debug_view_t;

/*
 * struct to hold contents of struct __debug_entry from dump
 * for DBF_VERSION_V1 and DBF_VERSION_V2
 */
typedef struct debug_entry_v1_s {
	union {
		struct {
			unsigned long long clock:52;
			unsigned long long exception:1;
			unsigned long long level:3;
			unsigned long long cpuid:8;
		} fields;

		unsigned long long stck;
	} id;
	kaddr_t caller; /* changed from void* to kaddr_t */
} __attribute__((packed)) debug_entry_v1_t;

/* for DBF_VERSION_V3 */
typedef struct debug_entry_v3_s {
	unsigned long long clock:60;
	unsigned long long exception:1;
	unsigned long long level:3;
	kaddr_t caller; /* changed from void* to kaddr_t */
	unsigned short cpuid;
} __attribute__((packed)) debug_entry_v3_t;

static unsigned int dbf_version;

/* struct is used to manage contents of structs debug_info from dump
 * in lcrash
 */
typedef struct debug_info_s {
	struct debug_info_s *next;
	struct debug_info_s *prev;
	kaddr_t next_dbi;   /* store next ptr of struct in dump */
	kaddr_t prev_dbi;   /* store prev ptr of struct in dump */
	int level;
	int nr_areas;
	int page_order;
	int buf_size;
	int entry_size;
	void **areas; /* contents of debug areas from dump */
	int active_area;
	int *active_entry; /* change to uint32_t ? */
	debug_view_t *views[DEBUG_MAX_VIEWS];
	char name[DEBUG_MAX_PROCF_LEN];
	kaddr_t addr;
	int pages_per_area_v2;
	void ***areas_v2;
} debug_info_t;


/* functions to generate dbf output
 */
typedef int (debug_header_proc_t) (debug_info_t* id, debug_view_t* view,
				   int area, void* entry,
				   char* out_buf);
typedef int (debug_format_proc_t) (debug_info_t* id, debug_view_t* view,
				   char* out_buf, const char* in_buf);
typedef int (debug_prolog_proc_t) (debug_info_t* id, debug_view_t* view,
				   char* out_buf);

struct debug_view_s {
	char name[DEBUG_MAX_PROCF_LEN];
	debug_prolog_proc_t* prolog_proc;
	debug_header_proc_t* header_proc;
	debug_format_proc_t* format_proc;
	void*		private_data;
};

#define LCRASH_DB_VIEWS 1000

static debug_info_t *debug_area_first = NULL;
static debug_info_t *debug_area_last  = NULL;
static debug_view_t *debug_views[LCRASH_DB_VIEWS];
static int initialized = 0;
static iconv_t ebcdic_ascii_conv = 0;

void s390dbf_usage(command_t * cmd);
static int add_lcrash_debug_view(debug_view_t *);
static int dbe_size = 0;

static void
EBCASC(char *inout, size_t len)
{
	iconv(ebcdic_ascii_conv, &inout, &len, &inout, &len);
}

/*
 * prints header for debug entry
 */
static int
dflt_header_fn(debug_info_t * id, debug_view_t *view,
	       int area, void *entry, char *out_buf)
{
	struct timeval time_val = { 0, 0 };
	int rc = 0;
	unsigned long long time;
	unsigned short level = 0, cpuid = 0;
	char *except_str = "-";
	kaddr_t caller = 0;
	char *caller_name;
	int name_width = 26;
	int offset;
	char caller_buf[30];
	syment_t *caller_sym;

	switch (dbf_version) {
	case DBF_VERSION_V1:
	case DBF_VERSION_V2:
		level = ((debug_entry_v1_t *) entry)->id.fields.level;
		cpuid = ((debug_entry_v1_t *) entry)->id.fields.cpuid;
		time = ((debug_entry_v1_t *) entry)->id.stck;
		if (((debug_entry_v1_t *) entry)->id.fields.exception)
			except_str = "*";
		caller = ((debug_entry_v1_t *) entry)->caller;
		kl_s390tod_to_timeval(time, &time_val);
		break;
	case DBF_VERSION_V3:
		level = ((debug_entry_v3_t *) entry)->level;
		cpuid = ((debug_entry_v3_t *) entry)->cpuid;
		time = ((debug_entry_v3_t *) entry)->clock;
		if (((debug_entry_v3_t *) entry)->exception)
			except_str = "*";
		caller = ((debug_entry_v3_t *) entry)->caller;
		time_val.tv_sec  = time / USEC_PER_SEC;
		time_val.tv_usec = time % USEC_PER_SEC;
		break;
	}

	if (KL_ARCH == KL_ARCH_S390)
		caller &= 0x7fffffff;
	caller_sym = kl_lkup_symaddr(caller);
	if (caller_sym) {
		caller_name = caller_sym->s_name;
		offset = caller - kl_funcaddr(caller);
	}
	else {
		sprintf(caller_buf, "%llx", (unsigned long long)caller);
		caller_name = caller_buf;
		offset = 0;
	}
	rc += sprintf(out_buf,
	      "%02i %011lu:%06lu %1u %1s %04i <%-*s+%04i>  ",
	      area, time_val.tv_sec, time_val.tv_usec, level,
	      except_str, cpuid,
	      name_width, caller_name, offset);

	return rc;
}

/*
 * prints debug data in hex/ascii format
 */
static int
hex_ascii_format_fn(debug_info_t * id, debug_view_t *view,
		    char *out_buf, const char *in_buf)
{
	int i, rc = 0;

	if (out_buf == NULL || in_buf == NULL) {
		rc = id->buf_size * 4 + 3;
		goto out;
	}
	for (i = 0; i < id->buf_size; i++) {
		rc += sprintf(out_buf + rc, "%02x ",
			      ((unsigned char *) in_buf)[i]);
	}
	rc += sprintf(out_buf + rc, "| ");
	for (i = 0; i < id->buf_size; i++) {
		unsigned char c = in_buf[i];
		if (isascii(c) && isprint(c))
			rc += sprintf(out_buf + rc, "%c", c);
		else
			rc += sprintf(out_buf + rc, ".");
	}
	rc += sprintf(out_buf + rc, "\n");
      out:
	return rc;
}

/*
 * prints debug data in sprintf format
 */
static int
sprintf_format_fn(debug_info_t * id, debug_view_t *view,
		  char *out_buf, const char *in_buf)
{
#define _BUFSIZE 1024
	char buf[_BUFSIZE];
	int i, k, rc = 0, num_longs = 0, num_strings = 0;
	int num_used_args ATTRIBUTE_UNUSED;
	/* use kaddr_t to store long values of 32bit and 64bit archs here */
	kaddr_t inbuf_cpy[DEBUG_SPRINTF_MAX_ARGS];
	/* store ptrs to strings to be deallocated at end of this function */
	uaddr_t to_dealloc[DEBUG_SPRINTF_MAX_ARGS];
	kaddr_t addr;

	memset(buf, 0, sizeof(buf));
	memset(inbuf_cpy, 0, sizeof(inbuf_cpy));
	memset(to_dealloc, 0, sizeof(to_dealloc));

	if (out_buf == NULL || in_buf == NULL) {
	      rc = id->buf_size * 4 + 3;
	      goto out;
	}

	/* get the format string into buf */
	addr = KL_GET_PTR((void*)in_buf);
	GET_BLOCK(addr, _BUFSIZE, buf);

	k = 0;
	for (i = 0; buf[i] && (buf[i] != '\n'); i++) {
		if (buf[i] != '%')
			continue;
		if (k == DEBUG_SPRINTF_MAX_ARGS) {
			fprintf(KL_ERRORFP,
				"\nToo much parameters in sprinf view (%i)\n"
				,k + 1);
			fprintf(KL_ERRORFP, "Format String: %s)\n", buf);
			break;
		}
		/* for sprintf we have only unsigned long values ... */
		if (buf[i+1] != 's'){
			/* we use KL_GET_PTR here to read ulong value */
			addr = KL_GET_PTR((void*) in_buf + ((k + 1)* KL_NBPW));
			inbuf_cpy[k] = addr;
		} else { /* ... or ptrs to strings in debug areas */
			inbuf_cpy[k] = (uaddr_t) malloc(_BUFSIZE);
			to_dealloc[num_strings++] = inbuf_cpy[k];
			addr = KL_GET_PTR((void*) in_buf + ((k + 1)* KL_NBPW));
			GET_BLOCK(addr, _BUFSIZE,
				  (void*)(uaddr_t)(inbuf_cpy[k]));
		}
		k++;
	}

	/* count of longs fit into one entry */
	num_longs = id->buf_size /  KL_NBPW; /* sizeof(long); */
	if(num_longs < 1)	  /* bufsize of entry too small */
		goto out;
	if(num_longs == 1) {	  /* no args, just print the format string */
		rc = sprintf(out_buf + rc, "%s", buf);
		goto out;
	}

	/* number of arguments used for sprintf (without the format string) */
	num_used_args = MIN(DEBUG_SPRINTF_MAX_ARGS, (num_longs - 1));

	rc = sprintf(out_buf + rc, buf, (uaddr_t)(inbuf_cpy[0]),
		     (uaddr_t)(inbuf_cpy[1]), (uaddr_t)(inbuf_cpy[2]),
		     (uaddr_t)(inbuf_cpy[3]), (uaddr_t)(inbuf_cpy[4]),
		     (uaddr_t)(inbuf_cpy[5]), (uaddr_t)(inbuf_cpy[6]),
		     (uaddr_t)(inbuf_cpy[7]), (uaddr_t)(inbuf_cpy[8]),
		     (uaddr_t)(inbuf_cpy[9]));
 out:
	while (num_strings--){
		free((char*)(to_dealloc[num_strings]));
	}
	return rc;
}


/***********************************
 * functions for debug-views
 ***********************************/

/*
 * prints out actual debug level
 */
static int
prolog_level_fn(debug_info_t * id,
		debug_view_t *view, char *out_buf)
{
	int rc = 0;

	if (out_buf == NULL) {
		rc = 2;
		goto out;
	}
	rc = sprintf(out_buf, "%i\n", id->level);
      out:
	return rc;
}

/*
 * prints out actual pages_per_area
 */
static int
prolog_pages_fn(debug_info_t * id,
		debug_view_t *view, char *out_buf)
{
	int rc = 0;

	if (out_buf == NULL) {
		rc = 2;
		goto out;
	}
	rc = sprintf(out_buf, "%i\n", id->pages_per_area_v2);
      out:
	return rc;
}

/*
 * prints out prolog
 */
static int
prolog_fn(debug_info_t * id,
	  debug_view_t *view, char *out_buf)
{
	int rc = 0;

	rc = sprintf(out_buf, "AREA TIME LEVEL EXCEPTION CP   CALLING FUNCTION"
		     " + OFFSET          DATA\n==============================="
		     "===========================================\n");
	return rc;
}

/*
 * prints debug data in hex format
 */
static int
hex_format_fn(debug_info_t * id, debug_view_t *view,
	      char *out_buf, const char *in_buf)
{
	int i, rc = 0;

	for (i = 0; i < id->buf_size; i++) {
		rc += sprintf(out_buf + rc, "%02x ",
			      ((unsigned char *) in_buf)[i]);
	}
	rc += sprintf(out_buf + rc, "\n");
	return rc;
}

/*
 * prints debug data in ascii format
 */
static int
ascii_format_fn(debug_info_t * id, debug_view_t *view,
		char *out_buf, const char *in_buf)
{
	int i, rc = 0;

	if (out_buf == NULL || in_buf == NULL) {
		rc = id->buf_size + 1;
		goto out;
	}
	for (i = 0; i < id->buf_size; i++) {
		unsigned char c = in_buf[i];
		if (!isprint(c))
			rc += sprintf(out_buf + rc, ".");
		else
			rc += sprintf(out_buf + rc, "%c", c);
	}
	rc += sprintf(out_buf + rc, "\n");
      out:
	return rc;
}

/*
 * prints debug data in ebcdic format
 */
static int
ebcdic_format_fn(debug_info_t * id, debug_view_t *view,
		 char *out_buf, const char *in_buf)
{
	int i, rc = 0;

	if (out_buf == NULL || in_buf == NULL) {
		rc = id->buf_size + 1;
		goto out;
	}
	for (i = 0; i < id->buf_size; i++) {
		char c = in_buf[i];
		EBCASC(&c, 1);
		if (!isprint(c))
			rc += sprintf(out_buf + rc, ".");
		else
			rc += sprintf(out_buf + rc, "%c", c);
	}
	rc += sprintf(out_buf + rc, "\n");
      out:
	return rc;
}

debug_view_t ascii_view = {
	"ascii",
	&prolog_fn,
	&dflt_header_fn,
	&ascii_format_fn,
};

debug_view_t ebcdic_view = {
	"ebcdic",
	&prolog_fn,
	&dflt_header_fn,
	&ebcdic_format_fn,
};

debug_view_t hex_view = {
	"hex",
	&prolog_fn,
	&dflt_header_fn,
	&hex_format_fn,
};

debug_view_t level_view = {
	"level",
	&prolog_level_fn,
	NULL,
	NULL,
};

debug_view_t pages_view = {
	"pages",
	&prolog_pages_fn,
	NULL,
	NULL,
};

debug_view_t hex_ascii_view = {
	"hex_ascii",
	&prolog_fn,
	&dflt_header_fn,
	&hex_ascii_format_fn,
};

debug_view_t sprintf_view = {
	"sprintf",
	&prolog_fn,
	&dflt_header_fn,
	&sprintf_format_fn,
};


static debug_entry_v1_t *
debug_find_oldest_entry(debug_entry_v1_t *entries, int num, int entry_size)
{
	debug_entry_v1_t *result, *current;
	int i;
	uint64_t clock1, clock2;

	result = entries;
	current = entries;
	for (i=0; i < num; i++) {
		if (current->id.stck == 0)
			break;
		clock1 = current->id.fields.clock;
		clock2 = result->id.fields.clock;
		clock1 = KL_GET_UINT64(&clock1);
		clock2 = KL_GET_UINT64(&clock2);
		if (clock1 < clock2)
			result = current;
		current = (debug_entry_v1_t *) ((char *) current + entry_size);
	}
	return result;
}


/*
 * debug_format_output:
 * - calls prolog, header and format functions of view to format output
 */
static int
debug_format_output_v1(debug_info_t * debug_area, debug_view_t *view, 
			FILE * ofp)
{
	int i, j, len;
	int nr_of_entries;
	debug_entry_v1_t *act_entry, *last_entry;
	char *act_entry_data;
	char buf[2048];
	size_t items ATTRIBUTE_UNUSED;

	/* print prolog */
	if (view->prolog_proc) {
		len = view->prolog_proc(debug_area, view, buf);
		items = fwrite(buf,len, 1, ofp);
		memset(buf, 0, 2048);
	}
	/* print debug records */
	if (!(view->format_proc) && !(view->header_proc))
		goto out;
	if(debug_area->entry_size <= 0){
		fprintf(ofp, "Invalid entry_size: %i\n",debug_area->entry_size);
		goto out;
	}
	nr_of_entries = (PAGE_SIZE << debug_area->page_order) / debug_area->entry_size;
	for (i = 0; i < debug_area->nr_areas; i++) {
		act_entry = debug_find_oldest_entry(debug_area->areas[i],
						    nr_of_entries,
						    debug_area->entry_size);
		last_entry = (debug_entry_v1_t *) ((char *) debug_area->areas[i] +
			     (PAGE_SIZE << debug_area->page_order) -
			     debug_area->entry_size);
		for (j = 0; j < nr_of_entries; j++) {
			act_entry_data = (char*)act_entry + dbe_size;
			if (act_entry->id.stck == 0)
				break;	/* empty entry */
			if (view->header_proc) {
				len = view->header_proc(debug_area, view, i,
						  act_entry, buf);
				items = fwrite(buf,len, 1, ofp);
				memset(buf, 0, 2048);
			}
			if (view->format_proc) {
				len = view->format_proc(debug_area, view,
						  buf, act_entry_data);
				items = fwrite(buf,len, 1, ofp);
				memset(buf, 0, 2048); 
			}
			act_entry =
			    (debug_entry_v1_t *) (((char *) act_entry) +
					       debug_area->entry_size);
			if (act_entry > last_entry)
				act_entry = debug_area->areas[i];
		}
	}
      out:
	return 1;
}

/*
 * debug_format_output_v2:
 * - calls prolog, header and format functions of view to format output
 */
static int
debug_format_output_v2(debug_info_t * debug_area,
		    debug_view_t *view, FILE * ofp)
{
	int i, j, k, len;
	void *act_entry;
	char *act_entry_data;
	char buf[2048];
	size_t items ATTRIBUTE_UNUSED;

	/* print prolog */
	if (view->prolog_proc) {
		len = view->prolog_proc(debug_area, view, buf);
		items = fwrite(buf,len, 1, ofp);
		memset(buf, 0, 2048);
	}
	/* print debug records */
	if (!(view->format_proc) && !(view->header_proc))
		goto out;
	if(debug_area->entry_size <= 0){
		fprintf(ofp, "Invalid entry_size: %i\n",debug_area->entry_size);
		goto out;
	}
	for (i = 0; i < debug_area->nr_areas; i++) {
		int nr_entries_per_page = PAGE_SIZE/debug_area->entry_size;
		for (j = 0; j < debug_area->pages_per_area_v2; j++) {
			act_entry = debug_area->areas_v2[i][j];
			for (k = 0; k < nr_entries_per_page; k++) {
				act_entry_data = (char*)act_entry + dbe_size;
				if (dbf_version == DBF_VERSION_V3 &&
				    ((debug_entry_v3_t *) act_entry)->clock == 0)
					break;	/* empty entry */
				else if (dbf_version < DBF_VERSION_V3 &&
				    ((debug_entry_v1_t *) act_entry)->id.stck == 0)
					break;	/* empty entry */
				if (view->header_proc) {
					len = view->header_proc(debug_area, 
						view, i, act_entry, buf);
					items = fwrite(buf,len, 1, ofp);
					memset(buf, 0, 2048);
				}
				if (view->format_proc) {
					len = view->format_proc(debug_area, 
						view, buf, act_entry_data);
					items = fwrite(buf,len, 1, ofp);
					memset(buf, 0, 2048); 
				}
				act_entry = ((char *) act_entry) +
					debug_area->entry_size;
			}
		}
	}
out:
	return 1;
}

static debug_info_t *
find_debug_area(const char *area_name)
{
	debug_info_t* act_debug_info = debug_area_first;
	while(act_debug_info != NULL){
		if (strcmp(act_debug_info->name, area_name) == 0)
				return act_debug_info;
		act_debug_info = act_debug_info->next;
	}
	return NULL;
}

static void tod_clock_base_init(void)
{
	if (kernel_symbol_exists("tod_clock_base")) {
		/*
		 * Kernels >= 4.14 that contain 6e2ef5e4f6cc5734 ("s390/time:
		 * add support for the TOD clock epoch extension")
		 */
		get_symbol_data("tod_clock_base", sizeof(tod_clock_base_us),
				&tod_clock_base_us);
		/* Bit for usecs is at position 59 - therefore shift 4 */
		tod_clock_base_us >>= 4;
	} else if (kernel_symbol_exists("sched_clock_base_cc") &&
		   !kernel_symbol_exists("tod_to_timeval")) {
		/*
		 * Kernels >= 4.11 that contain ea417aa8a38bc7db ("s390/debug:
		 * make debug event time stamps relative to the boot TOD clock")
		 */
		get_symbol_data("sched_clock_base_cc",
				sizeof(tod_clock_base_us), &tod_clock_base_us);
		/* Bit for usecs is at position 51 - therefore shift 12 */
		tod_clock_base_us >>= 12;
	} else {
		/* All older kernels use absolute time stamps */
		tod_clock_base_us = 0;
	}
}

static void
dbf_init(void)
{
	if (!initialized) {
		tod_clock_base_init();
		if(dbf_version >= DBF_VERSION_V2)
			add_lcrash_debug_view(&pages_view);
		add_lcrash_debug_view(&ascii_view);
		add_lcrash_debug_view(&level_view);
		add_lcrash_debug_view(&ebcdic_view);
		add_lcrash_debug_view(&hex_view);
		add_lcrash_debug_view(&hex_ascii_view);
		add_lcrash_debug_view(&sprintf_view);
		ebcdic_ascii_conv = iconv_open("ISO-8859-1", "EBCDIC-US");
		initialized = 1;
	}
}

static debug_view_t*
get_debug_view(kaddr_t addr)
{
	void* k_debug_view;
	int   k_debug_view_size;
	debug_view_t* rc;

	rc = (debug_view_t*)malloc(sizeof(debug_view_t));
	memset(rc, 0, sizeof(debug_view_t));

	k_debug_view_size = kl_struct_len("debug_view");
	k_debug_view      = malloc(k_debug_view_size);
	GET_BLOCK(addr, k_debug_view_size, k_debug_view);		
	strncpy(rc->name,K_PTR(k_debug_view,"debug_view","name"),
		DEBUG_MAX_PROCF_LEN);

	free(k_debug_view);
	return rc;
}

static void
free_debug_view(debug_view_t* view)
{
	if(view) 
		free(view);
}

static void
debug_get_areas_v1(debug_info_t* db_info, void* k_dbi)
{
	kaddr_t mem_pos;
	kaddr_t dbe_addr;
	int area_size, i;

       	/* get areas */
	/* place to hold ptrs to debug areas in lcrash */
	area_size = PAGE_SIZE << db_info->page_order;
       	db_info->areas = (void**)malloc(db_info->nr_areas * sizeof(void *));
	memset(db_info->areas, 0, db_info->nr_areas * sizeof(void *));
       	mem_pos = KL_ULONG(k_dbi,"debug_info","areas");
       	for (i = 0; i < db_info->nr_areas; i++) {
		dbe_addr = KL_VREAD_PTR(mem_pos);
		db_info->areas[i] = (debug_entry_v1_t *) malloc(area_size);
		/* read raw data for debug area */
	       	GET_BLOCK(dbe_addr, area_size, db_info->areas[i]);
		mem_pos += KL_NBPW;
	}
}

static void
debug_get_areas_v2(debug_info_t* db_info, void* k_dbi)
{
	kaddr_t area_ptr;
	kaddr_t page_array_ptr;
	kaddr_t page_ptr;
	int i,j;
       	db_info->areas_v2=(void***)malloc(db_info->nr_areas * sizeof(void **));
       	area_ptr = KL_ULONG(k_dbi,"debug_info","areas");
       	for (i = 0; i < db_info->nr_areas; i++) {
		db_info->areas_v2[i] = (void**)malloc(db_info->pages_per_area_v2
							* sizeof(void*));
		page_array_ptr = KL_VREAD_PTR(area_ptr);
		for(j=0; j < db_info->pages_per_area_v2; j++) {
			page_ptr = KL_VREAD_PTR(page_array_ptr);
			db_info->areas_v2[i][j] = (void*)malloc(PAGE_SIZE);
			/* read raw data for debug area */
	       		GET_BLOCK(page_ptr, PAGE_SIZE, db_info->areas_v2[i][j]);
			page_array_ptr += KL_NBPW;
		}
		area_ptr += KL_NBPW;
	}
}

static debug_info_t*
get_debug_info(kaddr_t addr,int get_areas)
{
	void *k_dbi;
	kaddr_t mem_pos;
	kaddr_t view_addr;
	debug_info_t* db_info;
	int i;
	int dbi_size;

	/* get sizes of kernel structures */
	if(!(dbi_size = kl_struct_len("debug_info"))){
		fprintf (KL_ERRORFP,
			 "Could not determine sizeof(struct debug_info)\n");
		return(NULL);
	}
	if(!(dbe_size = kl_struct_len("__debug_entry"))){
		fprintf(KL_ERRORFP,
			"Could not determine sizeof(struct __debug_entry)\n");
		return(NULL);
	}

	/* get kernel debug_info structure */
	k_dbi = malloc(dbi_size);
	GET_BLOCK(addr, dbi_size, k_dbi);

	db_info = (debug_info_t*)malloc(sizeof(debug_info_t));
	memset(db_info, 0, sizeof(debug_info_t));

	/* copy members */
	db_info->level	    = KL_INT(k_dbi,"debug_info","level");
	db_info->nr_areas	 = KL_INT(k_dbi,"debug_info","nr_areas");
	db_info->pages_per_area_v2= KL_INT(k_dbi,"debug_info","pages_per_area");
	db_info->page_order       = KL_INT(k_dbi,"debug_info","page_order");
	db_info->buf_size	 = KL_INT(k_dbi,"debug_info","buf_size");
	db_info->entry_size       = KL_INT(k_dbi,"debug_info","entry_size");
	db_info->next_dbi	 = KL_ULONG(k_dbi,"debug_info","next");
	db_info->prev_dbi	 = KL_ULONG(k_dbi,"debug_info","prev");
	db_info->addr	     = addr;
	strncpy(db_info->name,K_PTR(k_dbi,"debug_info","name"),
		DEBUG_MAX_PROCF_LEN);


	if(get_areas){
		if(dbf_version == DBF_VERSION_V1)
			debug_get_areas_v1(db_info,k_dbi);
		else
			debug_get_areas_v2(db_info,k_dbi);
	} else {
		db_info->areas = NULL;
	}

	/* get views */
	mem_pos = (uaddr_t) K_PTR(k_dbi,"debug_info","views");
	memset(&db_info->views, 0, DEBUG_MAX_VIEWS * sizeof(void*));
	for (i = 0; i < DEBUG_MAX_VIEWS; i++) {
		view_addr = KL_GET_PTR((void*)(uaddr_t)mem_pos);
		if(view_addr == 0){
			break;
		} else {
			db_info->views[i] = get_debug_view(view_addr);
		}
		mem_pos += KL_NBPW;
	}
	free(k_dbi);
	return db_info;
}

static void
free_debug_info_v1(debug_info_t * db_info)
{
	int i;
	if(db_info->areas){
		for (i = 0; i < db_info->nr_areas; i++) {
			free(db_info->areas[i]);
		}
	}
	for (i = 0; i < DEBUG_MAX_VIEWS; i++) {
		free_debug_view(db_info->views[i]);
	}
	free(db_info->areas);
	free(db_info);
}

static void
free_debug_info_v2(debug_info_t * db_info)
{
	int i,j;
	if(db_info->areas) {
		for (i = 0; i < db_info->nr_areas; i++) {
			for(j = 0; j < db_info->pages_per_area_v2; j++) {
				free(db_info->areas_v2[i][j]);
			}
			free(db_info->areas[i]);
		}
		free(db_info->areas);
		db_info->areas = NULL;
	}
	for (i = 0; i < DEBUG_MAX_VIEWS; i++) {
		free_debug_view(db_info->views[i]);
	}
	free(db_info);
}

static void
debug_write_output(debug_info_t *db_info, debug_view_t *db_view, FILE * fp)
{
	if (dbf_version == DBF_VERSION_V1) {
		debug_format_output_v1(db_info, db_view, fp);
		free_debug_info_v1(db_info);
	} else {
		debug_format_output_v2(db_info, db_view, fp);
		free_debug_info_v2(db_info);
	}
}

static int
get_debug_areas(void)
{
	kaddr_t act_debug_area;
	syment_t *debug_sym;
	debug_info_t *act_debug_area_cpy;

	if(!(debug_sym = kl_lkup_symname("debug_area_first"))){
		printf("Did not find debug_areas");
		return -1;
	}
	act_debug_area = KL_VREAD_PTR(debug_sym->s_addr);
	while(act_debug_area != 0){
		act_debug_area_cpy = get_debug_info(act_debug_area,0);
		act_debug_area     = act_debug_area_cpy->next_dbi;
	 	if(debug_area_first == NULL){
			debug_area_first = act_debug_area_cpy;
		} else {
			debug_area_last->next = act_debug_area_cpy;
		}
		debug_area_last = act_debug_area_cpy;
	}
	return 0;
}

static void
free_debug_areas(void)
{
	debug_info_t* next;
	debug_info_t* act_debug_info = debug_area_first;

	while(act_debug_info != NULL){
		next = act_debug_info->next;
		if(dbf_version == DBF_VERSION_V1)
			free_debug_info_v1(act_debug_info);
		else
			free_debug_info_v2(act_debug_info);
		act_debug_info = next;
	}

	debug_area_first = NULL;
	debug_area_last  = NULL;
}

static debug_view_t *
find_lcrash_debug_view(const char *name)
{
	int i;
	for (i = 0; (i < LCRASH_DB_VIEWS) && (debug_views[i] != NULL); i++) {
		if (strcmp(debug_views[i]->name, name) == 0)
			return debug_views[i];
	}
	return NULL;
}

static void
print_lcrash_debug_views(FILE * ofp)
{
	int i;
	fprintf(ofp, "REGISTERED VIEWS\n");
	fprintf(ofp, "=====================\n");
	for (i = 0; i < LCRASH_DB_VIEWS; i++) {
		if (debug_views[i] == NULL) {
			return;
		}
		fprintf(ofp, " - %s\n", debug_views[i]->name);
	}
}

static int
add_lcrash_debug_view(debug_view_t *view)
{
	int i;
	for (i = 0; i < LCRASH_DB_VIEWS; i++) {
		if (debug_views[i] == NULL) {
			debug_views[i] = view;
			return 0;
		}
		if (strcmp(debug_views[i]->name, view->name) == 0)
			return -1;
	}
	return -1;
}

static int
list_one_view(char *area_name, char *view_name, command_t * cmd)
{
	debug_info_t *db_info;
	debug_view_t *db_view;

	if ((db_info = find_debug_area(area_name)) == NULL) {
		fprintf(cmd->efp, "Debug log '%s' not found!\n", area_name);
		return -1;
	}

	db_info = get_debug_info(db_info->addr,1);

	if ((db_view = find_lcrash_debug_view(view_name)) == NULL) {
		fprintf(cmd->efp, "View '%s' not registered!\n", view_name);
		return -1;
	}
	debug_write_output(db_info, db_view, cmd->ofp);
	return 0;
}

static int
list_areas(FILE * ofp)
{
	debug_info_t* act_debug_info = debug_area_first;
	fprintf(ofp, "Debug Logs:\n");
	fprintf(ofp, "==================\n");
	while(act_debug_info != NULL){
		fprintf(ofp, " - %s\n", act_debug_info->name);
		act_debug_info = act_debug_info->next;
	}
	return 0;
}

static int
list_one_area(const char *area_name, command_t * cmd)
{
	debug_info_t *db_info;
	int i;
	if ((db_info = find_debug_area(area_name)) == NULL) {
		fprintf(cmd->efp, "Debug log '%s' not found!\n", area_name);
		return -1;
	}
	fprintf(cmd->ofp, "INSTALLED VIEWS FOR '%s':\n", area_name);
	fprintf(cmd->ofp, "================================================"
		"==============================\n");
	for (i = 0; i < DEBUG_MAX_VIEWS; i++) {
		if (db_info->views[i] != NULL) {
			fprintf(cmd->ofp, " - %s ", db_info->views[i]->name);
			if (find_lcrash_debug_view(db_info->views[i]->name))
				fprintf(cmd->ofp, "(available)\n");
			else
				fprintf(cmd->ofp, "(not available)\n");
		}
	}
	fprintf(cmd->ofp, "================================================="
		"=============================\n");
	return 0;
}

#ifdef DBF_DYNAMIC_VIEWS
static int
load_debug_view(const char *path, command_t * cmd)
{
	void *library;
	const char *error;
	debug_view_t *(*view_init_func) (void);

	library = dlopen(path, RTLD_LAZY);
	if (library == NULL) {
		fprintf(cmd->efp, "Could not open %s: %s\n", path, dlerror());
		return (1);
	}

	dlerror();

	view_init_func = dlsym(library, "debug_view_init");
	error = dlerror();

	if (error) {
		fprintf(stderr, "could not find debug_view_init(): %s\n",
			error);
		exit(1);
	}

	add_lcrash_debug_view((*view_init_func) ());

	fprintf(cmd->ofp, "view %s loaded\n", path);
	fflush(stdout);
	return 0;
}
#endif

static int
save_one_view(const char *dbf_dir_name, const char *area_name,
	      const char *view_name, command_t *cmd)
{
	char path_view[PATH_MAX];
	debug_info_t *db_info;
	debug_view_t *db_view;
	FILE *view_fh;

	db_info = find_debug_area(area_name);
	if (db_info == NULL) {
		fprintf(cmd->efp, "Debug log '%s' not found!\n", area_name);
		return -1;
	}
	db_info = get_debug_info(db_info->addr, 1);

	db_view = find_lcrash_debug_view(view_name);
	if (db_view == NULL) {
		fprintf(cmd->efp, "View '%s' not registered!\n", view_name);
		return -1;
	}
	sprintf(path_view, "%s/%s/%s", dbf_dir_name, area_name, view_name);
	view_fh = fopen(path_view, "w");
	if (view_fh == NULL) {
		fprintf(cmd->efp, "Could not create file: %s (%s)\n",
			path_view, strerror(errno));
		return -1;
	}
	debug_write_output(db_info, db_view, view_fh);
	fclose(view_fh);
	return 0;
}

static int
save_one_area(const char *dbf_dir_name, const char *area_name, command_t *cmd)
{
	char dir_name_area[PATH_MAX];
	debug_info_t *db_info;
	int i;

	db_info = find_debug_area(area_name);
	if (db_info == NULL) {
		fprintf(cmd->efp, "Debug log '%s' not found!\n", area_name);
		return -1;
	}
	sprintf(dir_name_area, "%s/%s", dbf_dir_name, area_name);
	if (mkdir(dir_name_area, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) != 0) {
		fprintf(cmd->efp, "Could not create directory: %s (%s)\n",
			dir_name_area, strerror(errno));
		return -1;
	}
	for (i = 0; i < DEBUG_MAX_VIEWS; i++) {
		if (db_info->views[i] == NULL)
			continue;
		if (!find_lcrash_debug_view(db_info->views[i]->name))
			continue;
		save_one_view(dbf_dir_name, area_name, db_info->views[i]->name,
			      cmd);
	}
	return 0;
}

static void
save_dbf(const char *dbf_dir_name, command_t *cmd)
{
	debug_info_t *act_debug_info = debug_area_first;
	FILE *ofp = cmd->ofp;

	fprintf(ofp, "Saving s390dbf to directory \"%s\"\n", dbf_dir_name);
	if (mkdir(dbf_dir_name, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) != 0) {
		fprintf(cmd->efp, "Could not create directory: %s (%s)\n",
			dbf_dir_name, strerror(errno));
		return;
	}
	while (act_debug_info != NULL) {
		save_one_area(dbf_dir_name, act_debug_info->name, cmd);
		act_debug_info = act_debug_info->next;
	}
}

/* 
 * s390dbf_cmd() -- Run the 's390dbf' command.
 */
static int
s390dbf_cmd(command_t * cmd)
{
	syment_t *dbf_version_sym;
	int rc = 0;

	/* check version */
 
	if(!(dbf_version_sym = kl_lkup_symname("debug_feature_version"))){
		fprintf(KL_ERRORFP,
			"Could not determine debug_feature_version\n");
		return -1;
	}

	dbf_version = KL_VREAD_UINT32(dbf_version_sym->s_addr);

	if ((dbf_version != DBF_VERSION_V1) &&
	    (dbf_version != DBF_VERSION_V2) &&
	    (dbf_version != DBF_VERSION_V3)) {
		fprintf(cmd->efp, "lcrash does not support the"
			" debug feature version of the dump kernel:\n");
		fprintf(cmd->efp, "DUMP: %i SUPPORTED: %i, %i and %i\n",
			dbf_version, DBF_VERSION_V1, DBF_VERSION_V2, DBF_VERSION_V3);
		return -1;
	}

	dbf_init();

	if (cmd->flags & C_ALL) {
		return (0);
	}
#ifdef DBF_DYNAMIC_VIEWS
	if (cmd->flags & LOAD_FLAG) {
		printf("loading: %s\n", cmd->args[0]);
		return (load_debug_view(cmd->args[0], cmd));
	}
#endif
	if (cmd->flags & VIEWS_FLAG) {
		print_lcrash_debug_views(cmd->ofp);
		return (0);
	}
	if (cmd->nargs > 2) {
		s390dbf_usage(cmd);
		return (1);
	}

	if(get_debug_areas() == -1) 
		return -1;

	if (cmd->flags & SAVE_DBF_FLAG) {
		if (cmd->nargs != 2) {
			fprintf(cmd->efp, "Specify directory name for -s\n");
			return 1;
		}
		save_dbf(cmd->args[1], cmd);
		return 0;
	}
	switch (cmd->nargs) {
	case 0:
		rc = list_areas(cmd->ofp);
		break;
	case 1:
		rc = list_one_area(cmd->args[0], cmd);
		break;
	case 2:
		rc = list_one_view(cmd->args[0], cmd->args[1], cmd);
		break;	
	}

	free_debug_areas();

	return rc;
}

#define _S390DBF_USAGE " [-v] [-s dirname] [debug log] [debug view]"

/*
 * s390dbf_usage() -- Print the usage string for the 's390dbf' command.
 */
void
s390dbf_usage(command_t * cmd)
{
	CMD_USAGE(cmd, _S390DBF_USAGE);
}

/*
 * s390 debug feature command for crash
 */

char *help_s390dbf[] = {
	"s390dbf",
	"s390dbf prints out debug feature logs",
	"[-v] [-s dirname] [debug log] [debug view]"
	"",
	"Display Debug logs:",
	" + If called without parameters, all active debug logs are listed.",
	" + If called with the name of a debug log, all debug-views for which",
	"   the debug-log has registered are listed. It is possible thatsome",
	"   of the debug views are not available to 'crash'.",
	" + If called with the name of a debug-log and an available viewname,",
	"   the specified view is printed.",
	" + If called with '-s dirname', the s390dbf is saved to the specified",
	"   directory",
	" + If called with '-v', all debug views which are available to",
	"   'crash' are listed",
	NULL
};

void cmd_s390dbf()
{
	int i,c;

	command_t cmd = {
		.ofp = fp,
		.efp = stderr,
		.cmdstr = "s390dbf",
		.command = "s390dbf",
	};

	cmd.nargs=argcnt - 1;
	for (i=1; i < argcnt; i++)
		cmd.args[i-1] = args[i];
	
	while ((c = getopt(argcnt, args, "vs")) != EOF) {
		switch(c) {
		case 'v':
			cmd.flags |= VIEWS_FLAG;
			break;
		case 's':
			cmd.flags |= SAVE_DBF_FLAG;
			break;
		default:
			s390dbf_usage(&cmd);
			return;
		}
	}
	s390dbf_cmd(&cmd);
}

#endif

