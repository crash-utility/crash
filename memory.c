/* memory.c - core analysis suite
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002-2019 David Anderson
 * Copyright (C) 2002-2019 Red Hat, Inc. All rights reserved.
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

#include "defs.h"
#include <sys/mman.h>
#include <ctype.h>
#include <netinet/in.h>
#include <byteswap.h>
#include "maple_tree.h"

struct meminfo {           /* general purpose memory information structure */
        ulong cache;       /* used by the various memory searching/dumping */
        ulong slab;        /* routines.  Only one of these is used per cmd */
        ulong c_flags;     /* so stuff whatever's helpful in here...       */
        ulong c_offset;
	ulong c_num;
	ulong s_mem; 
	void *s_freep; 
	ulong *s_index; 
	ulong s_inuse;
	ulong cpucached_cache;
	ulong cpucached_slab;
        ulong inuse;
	ulong order;
	ulong slabsize;
        ulong num_slabs;
	ulong objects;
        ulonglong spec_addr;
        ulong flags;
	ulong size;
	ulong objsize;
	int memtype;
	int free;
	int slab_offset;
        char *reqname;
	char *curname;
	ulong *spec_cpumask;
	ulong *addrlist;
	int *kmem_bufctl;
	ulong *cpudata[NR_CPUS];
	ulong *shared_array_cache;
	int current_cache_index;
	ulong found;
	ulong retval;
	struct struct_member_data *page_member_cache;
	ulong nr_members;
	char *ignore;
	int errors;
	int calls;
	int cpu;
	int cache_count;
	ulong get_shared;
	ulong get_totalram;
	ulong get_buffers;
	ulong get_slabs;
	char *slab_buf;
	char *cache_buf;
	ulong *cache_list;
	struct vmlist {
		ulong addr;
		ulong size;
	} *vmlist;
	ulong container;
	int *freelist;
	int freelist_index_size;
	ulong random;
	ulong list_offset;
};

/*
 * Search modes
 */

#define SEARCH_ULONG	(0)
#define SEARCH_UINT	(1)
#define SEARCH_USHORT	(2)
#define SEARCH_CHARS	(3)
#define SEARCH_DEFAULT	(SEARCH_ULONG)

/* search mode information */
struct searchinfo {
	int mode;
	int vcnt;
	int val;
	int context;
	int memtype;
	int do_task_header;
	int tasks_found;
	struct task_context *task_context;
	ulong vaddr_start;
	ulong vaddr_end;
	ulonglong paddr_start;
	ulonglong paddr_end;
	union {
		/* default ulong search */
		struct {
			ulong value[MAXARGS];
			char *opt_string[MAXARGS];
			ulong mask;
		} s_ulong;

		/* uint search */
		struct {
			uint value[MAXARGS];
			char *opt_string[MAXARGS];
			uint mask;
		} s_uint;

		/* ushort search */
		struct {
			ushort value[MAXARGS];
			char *opt_string[MAXARGS];
			ushort mask;
		} s_ushort;

		/* string (chars) search */
		struct {
			char *value[MAXARGS];
			int len[MAXARGS];
			int started_flag;  /* string search needs history */
		} s_chars;
	} s_parms;
	char buf[BUFSIZE];
};

struct handle_each_vm_area_args {
	ulong task;
	ulong flag;
	ulong vaddr;
	struct reference *ref;
	char *vma_header;
	char *buf1;
	char *buf2;
	char *buf3;
	char *buf4;
	char *buf5;
	ulong vma;
	char **vma_buf;
	struct task_mem_usage *tm;
	int *found;
	int *single_vma_found;
	unsigned int radix;
	struct task_context *tc;
	ulong *single_vma;
};

static char *memtype_string(int, int);
static char *error_handle_string(ulong);
static void collect_page_member_data(char *, struct meminfo *);
struct integer_data {
	ulong value;
	ulong bitfield_value;
	struct struct_member_data *pmd;
};
static int get_bitfield_data(struct integer_data *);
static int show_page_member_data(char *, ulong, struct meminfo *, char *);
static void dump_mem_map(struct meminfo *);
static void dump_mem_map_SPARSEMEM(struct meminfo *);
static void fill_mem_map_cache(ulong, ulong, char *);
static void page_flags_init(void);
static int page_flags_init_from_pageflag_names(void);
static int page_flags_init_from_pageflags_enum(void);
static int translate_page_flags(char *, ulong);
static void dump_free_pages(struct meminfo *);
static int dump_zone_page_usage(void);
static void dump_multidimensional_free_pages(struct meminfo *);
static void dump_free_pages_zones_v1(struct meminfo *);
static void dump_free_pages_zones_v2(struct meminfo *);
struct free_page_callback_data;
static int dump_zone_free_area(ulong, int, ulong, struct free_page_callback_data *);
static void dump_page_hash_table(struct meminfo *);
static void kmem_search(struct meminfo *);
static void kmem_cache_init(void);
static void kmem_cache_init_slub(void);
static ulong max_cpudata_limit(ulong, ulong *);
static int kmem_cache_downsize(void);
static int ignore_cache(struct meminfo *, char *);
static char *is_kmem_cache_addr(ulong, char *);
static char *is_kmem_cache_addr_common(ulong, char *);
static void kmem_cache_list(struct meminfo *);
static void dump_kmem_cache(struct meminfo *);
static void dump_kmem_cache_percpu_v1(struct meminfo *);
static void dump_kmem_cache_percpu_v2(struct meminfo *);
static void dump_kmem_cache_slub(struct meminfo *);
static void kmem_cache_list_common(struct meminfo *);
static ulong get_cpu_slab_ptr(struct meminfo *, int, ulong *);
static unsigned int oo_order(ulong);
static unsigned int oo_objects(ulong);
static char *vaddr_to_kmem_cache(ulong, char *, int);
static char *is_slab_overload_page(ulong, ulong *, char *);
static ulong vaddr_to_slab(ulong);
static void do_slab_chain(int, struct meminfo *);
static void do_slab_chain_percpu_v1(long, struct meminfo *);
static void do_slab_chain_percpu_v2(long, struct meminfo *);
static void do_slab_chain_percpu_v2_nodes(long, struct meminfo *);
static void do_slab_chain_slab_overload_page(long, struct meminfo *);
static int slab_freelist_index_size(void);
static int do_slab_slub(struct meminfo *, int);
static void do_kmem_cache_slub(struct meminfo *);
static void save_slab_data(struct meminfo *);
static int slab_data_saved(struct meminfo *);
static void dump_saved_slab_data(void);
static void dump_slab(struct meminfo *);
static void dump_slab_percpu_v1(struct meminfo *);
static void dump_slab_percpu_v2(struct meminfo *);
static void dump_slab_overload_page(struct meminfo *);
static int verify_slab_v1(struct meminfo *, ulong, int);
static int verify_slab_v2(struct meminfo *, ulong, int);
static int verify_slab_overload_page(struct meminfo *, ulong, int);
static void gather_slab_free_list(struct meminfo *);
static void gather_slab_free_list_percpu(struct meminfo *);
static void gather_slab_free_list_slab_overload_page(struct meminfo *);
static void gather_cpudata_list_v1(struct meminfo *);
static void gather_cpudata_list_v2(struct meminfo *);
static void gather_cpudata_list_v2_nodes(struct meminfo *, int);
static int check_cpudata_list(struct meminfo *, ulong);
static int check_shared_list(struct meminfo *, ulong);
static void gather_slab_cached_count(struct meminfo *);
static void dump_slab_objects(struct meminfo *);
static void dump_slab_objects_percpu(struct meminfo *);
static void dump_vmlist(struct meminfo *);
static void dump_vmap_area(struct meminfo *);
static int dump_page_lists(struct meminfo *);
static void dump_kmeminfo(void);
static int page_to_phys(ulong, physaddr_t *); 
static void display_memory(ulonglong, long, ulong, int, void *); 
static char *show_opt_string(struct searchinfo *);
static void display_with_pre_and_post(void *, ulonglong, struct searchinfo *);
static ulong search_ulong(ulong *, ulong, int, struct searchinfo *);
static ulong search_uint(ulong *, ulong, int, struct searchinfo *);
static ulong search_ushort(ulong *, ulong, int, struct searchinfo *);
static ulong search_chars(ulong *, ulong, int, struct searchinfo *);
static ulonglong search_ulong_p(ulong *, ulonglong, int, struct searchinfo *);
static ulonglong search_uint_p(ulong *, ulonglong, int, struct searchinfo *);
static ulonglong search_ushort_p(ulong *, ulonglong, int, struct searchinfo *);
static ulonglong search_chars_p(ulong *, ulonglong, int, struct searchinfo *);
static void search_virtual(struct searchinfo *);
static void search_physical(struct searchinfo *);
static int next_upage(struct task_context *, ulong, ulong *);
static int next_kpage(ulong, ulong *);
static int next_physpage(ulonglong, ulonglong *);
static int next_vmlist_vaddr(ulong, ulong *);
static int next_module_vaddr(ulong, ulong *);
static int next_identity_mapping(ulong, ulong *);
static int vm_area_page_dump(ulong, ulong, ulong, ulong, ulong,
	struct reference *);
static void rss_page_types_init(void);
static int dump_swap_info(ulong, ulong *, ulong *);
static int get_hugetlb_total_pages(ulong *, ulong *);
static char *get_swapdev(ulong, char *);
static void fill_swap_info(ulong);
static char *vma_file_offset(ulong, ulong, char *);
static ssize_t read_dev_kmem(ulong, char *, long);
static void dump_memory_nodes(int);
static void dump_zone_stats(void);
#define MEMORY_NODES_DUMP       (0)
#define MEMORY_NODES_INITIALIZE (1)
static void node_table_init(void);
static int compare_node_data(const void *, const void *);
static void do_vm_flags(ulonglong);
static ulonglong get_vm_flags(char *);
static void PG_reserved_flag_init(void);
static void PG_slab_flag_init(void);
static ulong nr_blockdev_pages(void);
static ulong nr_blockdev_pages_v2(void);
void sparse_mem_init(void);
void dump_mem_sections(int);
void dump_memory_blocks(int);
void list_mem_sections(void);
ulong sparse_decode_mem_map(ulong, ulong);
char *read_mem_section(ulong);
ulong nr_to_section(ulong);
int valid_section(ulong);
int section_has_mem_map(ulong);
ulong section_mem_map_addr(ulong, int);
ulong valid_section_nr(ulong);
ulong pfn_to_map(ulong);
static int get_nodes_online(void);
static int next_online_node(int);
static ulong next_online_pgdat(int);
static int vm_stat_init(void);
static int vm_event_state_init(void);
static int dump_vm_stat(char *, long *, ulong);
static int dump_vm_event_state(void);
static int dump_page_states(void);
static int generic_read_dumpfile(ulonglong, void *, long, char *, ulong);
static int generic_write_dumpfile(ulonglong, void *, long, char *, ulong);
static int page_to_nid(ulong);
static int get_kmem_cache_list(ulong **);
static int get_kmem_cache_root_list(ulong **);
static int get_kmem_cache_child_list(ulong **, ulong);
static int get_kmem_cache_slub_data(long, struct meminfo *);
static ulong compound_head(ulong);
static long count_partial(ulong, struct meminfo *, ulong *);
static short count_cpu_partial(struct meminfo *, int);
static ulong get_freepointer(struct meminfo *, void *);
static int count_free_objects(struct meminfo *, ulong);
char *is_slab_page(struct meminfo *, char *);
static void do_cpu_partial_slub(struct meminfo *, int);
static void do_node_lists_slub(struct meminfo *, ulong, int);
static int devmem_is_restricted(void);
static int switch_to_proc_kcore(void);
static int verify_pfn(ulong);
static void dump_per_cpu_offsets(void);
static void dump_page_flags(ulonglong);
static ulong kmem_cache_nodelists(ulong);
static void dump_hstates(void);
static void freelist_ptr_init(void);
static ulong freelist_ptr(struct meminfo *, ulong, ulong);
static ulong handle_each_vm_area(struct handle_each_vm_area_args *);

/*
 *  Memory display modes specific to this file.
 */
#define DISPLAY_8      (0x2)
#define DISPLAY_16     (0x4)
#define DISPLAY_32     (0x8)
#define DISPLAY_64     (0x10)
#define SHOW_OFFSET    (0x20)
#define SYMBOLIC       (0x40)
#define HEXADECIMAL    (0x80)
#define DECIMAL        (0x100)
#define UDECIMAL       (0x200)
#define ASCII_ENDLINE  (0x400)
#define NO_ASCII       (0x800)
#define SLAB_CACHE    (0x1000)
#define DISPLAY_ASCII (0x2000)
#define NET_ENDIAN    (0x4000)
#define DISPLAY_RAW   (0x8000)
#define NO_ERROR     (0x10000)
#define SLAB_CACHE2  (0x20000)
#define DISPLAY_TYPES (DISPLAY_RAW|DISPLAY_ASCII|DISPLAY_8|\
		       DISPLAY_16|DISPLAY_32|DISPLAY_64)

#define ASCII_UNLIMITED ((ulong)(-1) >> 1)

static ulong DISPLAY_DEFAULT;

/*
 *  Verify that the sizeof the primitive types are reasonable.
 */
void
mem_init(void)
{
        if (sizeof(char) != SIZEOF_8BIT)
                error(FATAL, "unsupported sizeof(char): %d\n", sizeof(char));
        if (sizeof(short) != SIZEOF_16BIT)
                error(FATAL, "unsupported sizeof(short): %d\n", sizeof(short));
        if ((sizeof(int) != SIZEOF_32BIT) && (sizeof(int) != SIZEOF_64BIT))
                error(FATAL, "unsupported sizeof(int): %d\n", sizeof(int));
        if ((sizeof(long) != SIZEOF_32BIT) && (sizeof(long) != SIZEOF_64BIT))
                error(FATAL, "unsupported sizeof(long): %d\n", sizeof(long));
        if (sizeof(void *) != sizeof(long))
                error(FATAL, "pointer size: %d is not sizeof(long): %d\n", sizeof(void *), sizeof(long));

        DISPLAY_DEFAULT = (sizeof(long) == 8) ? DISPLAY_64 : DISPLAY_32;
}


/*
 *  Stash a few popular offsets and some basic kernel virtual memory
 *  items used by routines in this file.
 */
void
vm_init(void)
{
	char buf[BUFSIZE];
	int i, len, dimension, nr_node_ids;
	struct syment *sp_array[2];
	ulong value1, value2;
	char *kmem_cache_node_struct, *nodelists_field;

        MEMBER_OFFSET_INIT(task_struct_mm, "task_struct", "mm");
        MEMBER_OFFSET_INIT(mm_struct_mmap, "mm_struct", "mmap");
	MEMBER_OFFSET_INIT(mm_struct_mm_mt, "mm_struct", "mm_mt");
	if (VALID_MEMBER(mm_struct_mm_mt)) {
		maple_init();
	}
        MEMBER_OFFSET_INIT(mm_struct_pgd, "mm_struct", "pgd");
	MEMBER_OFFSET_INIT(mm_struct_rss, "mm_struct", "rss");
	if (!VALID_MEMBER(mm_struct_rss))
		MEMBER_OFFSET_INIT(mm_struct_rss, "mm_struct", "_rss");
	MEMBER_OFFSET_INIT(mm_struct_anon_rss, "mm_struct", "_anon_rss");
	MEMBER_OFFSET_INIT(mm_struct_file_rss, "mm_struct", "_file_rss");
	if (!VALID_MEMBER(mm_struct_anon_rss)) {
		MEMBER_OFFSET_INIT(mm_struct_rss_stat, "mm_struct", "rss_stat");
		MEMBER_OFFSET_INIT(mm_rss_stat_count, "mm_rss_stat", "count");
	}
	MEMBER_OFFSET_INIT(mm_struct_total_vm, "mm_struct", "total_vm");
	MEMBER_OFFSET_INIT(mm_struct_start_code, "mm_struct", "start_code");
	MEMBER_OFFSET_INIT(mm_struct_mm_count, "mm_struct", "mm_count");
        MEMBER_OFFSET_INIT(vm_area_struct_vm_mm, "vm_area_struct", "vm_mm");
        MEMBER_OFFSET_INIT(vm_area_struct_vm_next, "vm_area_struct", "vm_next");
        MEMBER_OFFSET_INIT(vm_area_struct_vm_end, "vm_area_struct", "vm_end");
        MEMBER_OFFSET_INIT(vm_area_struct_vm_start, 
		"vm_area_struct", "vm_start");
        MEMBER_OFFSET_INIT(vm_area_struct_vm_flags, 
                "vm_area_struct", "vm_flags");
        MEMBER_OFFSET_INIT(vm_area_struct_vm_file, "vm_area_struct", "vm_file");
        MEMBER_OFFSET_INIT(vm_area_struct_vm_offset, 
                "vm_area_struct", "vm_offset");
        MEMBER_OFFSET_INIT(vm_area_struct_vm_pgoff, 
                "vm_area_struct", "vm_pgoff");
        MEMBER_SIZE_INIT(vm_area_struct_vm_flags, "vm_area_struct", "vm_flags");

	MEMBER_OFFSET_INIT(vm_struct_addr, "vm_struct", "addr");
	MEMBER_OFFSET_INIT(vm_struct_size, "vm_struct", "size");
	MEMBER_OFFSET_INIT(vm_struct_next, "vm_struct", "next");

	MEMBER_OFFSET_INIT(vmap_area_va_start, "vmap_area", "va_start");
	MEMBER_OFFSET_INIT(vmap_area_va_end, "vmap_area", "va_end");
	MEMBER_OFFSET_INIT(vmap_area_list, "vmap_area", "list");
	MEMBER_OFFSET_INIT(vmap_area_flags, "vmap_area", "flags");
	MEMBER_OFFSET_INIT(vmap_area_vm, "vmap_area", "vm");
	if (INVALID_MEMBER(vmap_area_vm))
		MEMBER_OFFSET_INIT(vmap_area_vm, "vmap_area", "private");
	STRUCT_SIZE_INIT(vmap_area, "vmap_area");
	if (VALID_MEMBER(vmap_area_va_start) &&
	    VALID_MEMBER(vmap_area_va_end) &&
	    VALID_MEMBER(vmap_area_list) &&
	    VALID_MEMBER(vmap_area_vm) &&
	    kernel_symbol_exists("vmap_area_list"))
		vt->flags |= USE_VMAP_AREA;

	if (kernel_symbol_exists("hstates")) {
		STRUCT_SIZE_INIT(hstate, "hstate");
		MEMBER_OFFSET_INIT(hstate_order, "hstate", "order");
		MEMBER_OFFSET_INIT(hstate_nr_huge_pages, "hstate", "nr_huge_pages");
		MEMBER_OFFSET_INIT(hstate_free_huge_pages, "hstate", "free_huge_pages");
		MEMBER_OFFSET_INIT(hstate_name, "hstate", "name");
	}

	MEMBER_OFFSET_INIT(page_next, "page", "next");
	if (VALID_MEMBER(page_next)) 
		MEMBER_OFFSET_INIT(page_prev, "page", "prev");
	if (INVALID_MEMBER(page_next))
		ANON_MEMBER_OFFSET_INIT(page_next, "page", "next");
	if (INVALID_MEMBER(page_next))
		MEMBER_OFFSET_INIT(page_next, "slab", "next");

	MEMBER_OFFSET_INIT(page_list, "page", "list");
	if (VALID_MEMBER(page_list)) {
		ASSIGN_OFFSET(page_list_next) = OFFSET(page_list) +
			OFFSET(list_head_next);
		ASSIGN_OFFSET(page_list_prev) = OFFSET(page_list) +
			OFFSET(list_head_prev);
	}

	MEMBER_OFFSET_INIT(page_next_hash, "page", "next_hash");
	MEMBER_OFFSET_INIT(page_inode, "page", "inode");
	MEMBER_OFFSET_INIT(page_offset, "page", "offset");
	MEMBER_OFFSET_INIT(page_count, "page", "count");
	if (INVALID_MEMBER(page_count)) {
		MEMBER_OFFSET_INIT(page_count, "page", "_count");
		if (INVALID_MEMBER(page_count))
			ANON_MEMBER_OFFSET_INIT(page_count, "page", "_count");
		if (INVALID_MEMBER(page_count))
			MEMBER_OFFSET_INIT(page_count, "page", "_refcount");
		if (INVALID_MEMBER(page_count))
			ANON_MEMBER_OFFSET_INIT(page_count, "page", "_refcount");
	}
	MEMBER_OFFSET_INIT(page_flags, "page", "flags");
	MEMBER_SIZE_INIT(page_flags, "page", "flags");
        MEMBER_OFFSET_INIT(page_mapping, "page", "mapping");
	if (INVALID_MEMBER(page_mapping))
		ANON_MEMBER_OFFSET_INIT(page_mapping, "page", "mapping");
	if (INVALID_MEMBER(page_mapping) && 
	    (THIS_KERNEL_VERSION < LINUX(2,6,17)) &&
	    MEMBER_EXISTS("page", "_mapcount"))
		ASSIGN_OFFSET(page_mapping) = MEMBER_OFFSET("page", "_mapcount") +
			STRUCT_SIZE("atomic_t") + sizeof(ulong);
        MEMBER_OFFSET_INIT(page_index, "page", "index");
	if (INVALID_MEMBER(page_index))
		ANON_MEMBER_OFFSET_INIT(page_index, "page", "index");
        MEMBER_OFFSET_INIT(page_buffers, "page", "buffers");
	MEMBER_OFFSET_INIT(page_lru, "page", "lru");
	if (INVALID_MEMBER(page_lru))
		ANON_MEMBER_OFFSET_INIT(page_lru, "page", "lru");
	MEMBER_OFFSET_INIT(page_pte, "page", "pte");
        MEMBER_OFFSET_INIT(page_compound_head, "page", "compound_head");
	if (INVALID_MEMBER(page_compound_head))
		ANON_MEMBER_OFFSET_INIT(page_compound_head, "page", "compound_head");
	MEMBER_OFFSET_INIT(page_private, "page", "private");
	MEMBER_OFFSET_INIT(page_freelist, "page", "freelist");

	MEMBER_OFFSET_INIT(mm_struct_pgd, "mm_struct", "pgd");

	MEMBER_OFFSET_INIT(swap_info_struct_swap_file,
        	"swap_info_struct", "swap_file");
	MEMBER_OFFSET_INIT(swap_info_struct_swap_vfsmnt, 
        	"swap_info_struct", "swap_vfsmnt");
	MEMBER_OFFSET_INIT(swap_info_struct_flags,
        	"swap_info_struct", "flags");	
	MEMBER_OFFSET_INIT(swap_info_struct_swap_map, 
        	"swap_info_struct", "swap_map");
	MEMBER_OFFSET_INIT(swap_info_struct_swap_device, 
        	"swap_info_struct", "swap_device");
	MEMBER_OFFSET_INIT(swap_info_struct_prio, "swap_info_struct", "prio");
	MEMBER_OFFSET_INIT(swap_info_struct_max, "swap_info_struct", "max");
	MEMBER_OFFSET_INIT(swap_info_struct_pages, "swap_info_struct", "pages");
	MEMBER_OFFSET_INIT(swap_info_struct_inuse_pages, "swap_info_struct", 
		"inuse_pages");
	MEMBER_OFFSET_INIT(swap_info_struct_old_block_size, 
        	"swap_info_struct", "old_block_size");
	MEMBER_OFFSET_INIT(swap_info_struct_bdev, "swap_info_struct", "bdev");

	MEMBER_OFFSET_INIT(zspoll_size_class, "zs_pool", "size_class");
	MEMBER_OFFSET_INIT(size_class_size, "size_class", "size");

	MEMBER_OFFSET_INIT(block_device_bd_inode, "block_device", "bd_inode");
	MEMBER_OFFSET_INIT(block_device_bd_list, "block_device", "bd_list");
	MEMBER_OFFSET_INIT(block_device_bd_disk, "block_device", "bd_disk");
	MEMBER_OFFSET_INIT(inode_i_mapping, "inode", "i_mapping");
	MEMBER_OFFSET_INIT(address_space_page_tree, "address_space", "page_tree");
	if (INVALID_MEMBER(address_space_page_tree))
		MEMBER_OFFSET_INIT(address_space_page_tree, "address_space", "i_pages");
	MEMBER_OFFSET_INIT(address_space_nrpages, "address_space", "nrpages");
	if (INVALID_MEMBER(address_space_nrpages))
		MEMBER_OFFSET_INIT(address_space_nrpages, "address_space", "__nrpages");

	MEMBER_OFFSET_INIT(super_block_s_inodes, "super_block", "s_inodes");
	MEMBER_OFFSET_INIT(inode_i_sb_list, "inode", "i_sb_list");

	MEMBER_OFFSET_INIT(gendisk_major, "gendisk", "major");
	MEMBER_OFFSET_INIT(gendisk_fops, "gendisk", "fops");
	MEMBER_OFFSET_INIT(gendisk_disk_name, "gendisk", "disk_name");
	MEMBER_OFFSET_INIT(gendisk_private_data, "gendisk", "private_data");

	STRUCT_SIZE_INIT(block_device, "block_device");
	STRUCT_SIZE_INIT(address_space, "address_space");
	STRUCT_SIZE_INIT(gendisk, "gendisk");

	STRUCT_SIZE_INIT(blk_major_name, "blk_major_name");
	if (VALID_STRUCT(blk_major_name)) {
		MEMBER_OFFSET_INIT(blk_major_name_next, "blk_major_name", 
			"next");
		MEMBER_OFFSET_INIT(blk_major_name_name, "blk_major_name", 
			"name");
		MEMBER_OFFSET_INIT(blk_major_name_major, "blk_major_name", 
			"major");
	}

	STRUCT_SIZE_INIT(kmem_slab_s, "kmem_slab_s");
	STRUCT_SIZE_INIT(slab_s, "slab_s");
	STRUCT_SIZE_INIT(slab, "slab");
	STRUCT_SIZE_INIT(kmem_cache_s, "kmem_cache_s");
	STRUCT_SIZE_INIT(pgd_t, "pgd_t");

	/*
	 * slab: overload struct slab over struct page 
         * https://lkml.org/lkml/2013/10/16/155
	 *
	 * commit e36ce448a08d removed kmem_cache.freelist_cache in 6.1,
	 * so use freelist_size instead.
	 */
	if (MEMBER_EXISTS("kmem_cache", "freelist_size")) {
		vt->flags |= SLAB_OVERLOAD_PAGE;
		ANON_MEMBER_OFFSET_INIT(page_s_mem, "page", "s_mem");
		ANON_MEMBER_OFFSET_INIT(page_freelist, "page", "freelist");
		ANON_MEMBER_OFFSET_INIT(page_active, "page", "active");
		/*
		 * Moved to struct slab in Linux 5.17
		 */
		if (INVALID_MEMBER(page_s_mem))
			MEMBER_OFFSET_INIT(page_s_mem, "slab", "s_mem");
		if (INVALID_MEMBER(page_freelist))
			MEMBER_OFFSET_INIT(page_freelist, "slab", "freelist");
		if (INVALID_MEMBER(page_active))
			MEMBER_OFFSET_INIT(page_active, "slab", "active");

		MEMBER_OFFSET_INIT(slab_slab_list, "slab", "slab_list");
	}

        if (!VALID_STRUCT(kmem_slab_s) && VALID_STRUCT(slab_s)) {
                vt->flags |= PERCPU_KMALLOC_V1;
		MEMBER_OFFSET_INIT(kmem_cache_s_num, "kmem_cache_s", "num");
		MEMBER_OFFSET_INIT(kmem_cache_s_next, "kmem_cache_s", "next");
		MEMBER_OFFSET_INIT(kmem_cache_s_name, "kmem_cache_s", "name");
		MEMBER_OFFSET_INIT(kmem_cache_s_objsize,  
			"kmem_cache_s", "objsize");
		MEMBER_OFFSET_INIT(kmem_cache_s_flags, "kmem_cache_s", "flags");
		MEMBER_OFFSET_INIT(kmem_cache_s_gfporder,  
			"kmem_cache_s", "gfporder");
		MEMBER_OFFSET_INIT(kmem_cache_s_slabs,  
			"kmem_cache_s", "slabs");
                MEMBER_OFFSET_INIT(kmem_cache_s_slabs_full,
			"kmem_cache_s", "slabs_full");
                MEMBER_OFFSET_INIT(kmem_cache_s_slabs_partial, 
			"kmem_cache_s", "slabs_partial");
                MEMBER_OFFSET_INIT(kmem_cache_s_slabs_free,  
			"kmem_cache_s", "slabs_free");
		MEMBER_OFFSET_INIT(kmem_cache_s_cpudata, 
			"kmem_cache_s", "cpudata");
                ARRAY_LENGTH_INIT(len, NULL, "kmem_cache_s.cpudata", NULL, 0);
		MEMBER_OFFSET_INIT(kmem_cache_s_colour_off, 
			"kmem_cache_s", "colour_off");

		MEMBER_OFFSET_INIT(slab_s_list, "slab_s", "list");
		MEMBER_OFFSET_INIT(slab_s_s_mem, "slab_s", "s_mem");
		MEMBER_OFFSET_INIT(slab_s_inuse, "slab_s", "inuse");
		MEMBER_OFFSET_INIT(slab_s_free, "slab_s", "free");

		MEMBER_OFFSET_INIT(cpucache_s_avail, "cpucache_s", "avail");
		MEMBER_OFFSET_INIT(cpucache_s_limit, "cpucache_s", "limit");

		STRUCT_SIZE_INIT(cpucache_s, "cpucache_s");

        } else if (!VALID_STRUCT(kmem_slab_s) && 
		   !VALID_STRUCT(slab_s) &&
		   !MEMBER_EXISTS("kmem_cache", "cpu_slab") &&
		   (VALID_STRUCT(slab) || (vt->flags & SLAB_OVERLOAD_PAGE))) {
                vt->flags |= PERCPU_KMALLOC_V2;

		if (VALID_STRUCT(kmem_cache_s)) {
			MEMBER_OFFSET_INIT(kmem_cache_s_num, "kmem_cache_s", "num");
			MEMBER_OFFSET_INIT(kmem_cache_s_next, "kmem_cache_s", "next");
			MEMBER_OFFSET_INIT(kmem_cache_s_name, "kmem_cache_s", "name");
			MEMBER_OFFSET_INIT(kmem_cache_s_colour_off, "kmem_cache_s", 
				"colour_off");
			MEMBER_OFFSET_INIT(kmem_cache_s_objsize,  "kmem_cache_s", 
				"objsize");
			MEMBER_OFFSET_INIT(kmem_cache_s_flags, "kmem_cache_s", "flags");
			MEMBER_OFFSET_INIT(kmem_cache_s_gfporder,  
				"kmem_cache_s", "gfporder");

			MEMBER_OFFSET_INIT(kmem_cache_s_lists, "kmem_cache_s", "lists");
			MEMBER_OFFSET_INIT(kmem_cache_s_array, "kmem_cache_s", "array");
			ARRAY_LENGTH_INIT(len, NULL, "kmem_cache_s.array", NULL, 0);
		} else {
			STRUCT_SIZE_INIT(kmem_cache_s, "kmem_cache");
			MEMBER_OFFSET_INIT(kmem_cache_s_num, "kmem_cache", "num");
			MEMBER_OFFSET_INIT(kmem_cache_s_next, "kmem_cache", "next");
			if (INVALID_MEMBER(kmem_cache_s_next)) {
				/* 
				 * slab/slub unification starting in Linux 3.6.
				 */
				MEMBER_OFFSET_INIT(kmem_cache_s_next, "kmem_cache", "list");
				MEMBER_OFFSET_INIT(kmem_cache_list, "kmem_cache", "list");
				MEMBER_OFFSET_INIT(kmem_cache_name, "kmem_cache", "name");
				MEMBER_OFFSET_INIT(kmem_cache_size, "kmem_cache", "size");
				STRUCT_SIZE_INIT(kmem_cache, "kmem_cache");
			}
			MEMBER_OFFSET_INIT(kmem_cache_s_name, "kmem_cache", "name");
			MEMBER_OFFSET_INIT(kmem_cache_s_colour_off, "kmem_cache", 
				"colour_off");
			if (MEMBER_EXISTS("kmem_cache", "objsize"))
				MEMBER_OFFSET_INIT(kmem_cache_s_objsize, "kmem_cache", 
					"objsize");
			else if (MEMBER_EXISTS("kmem_cache", "buffer_size"))
				MEMBER_OFFSET_INIT(kmem_cache_s_objsize, "kmem_cache", 
					"buffer_size");
			else if (MEMBER_EXISTS("kmem_cache", "size"))
				MEMBER_OFFSET_INIT(kmem_cache_s_objsize, "kmem_cache", 
					"size");
			MEMBER_OFFSET_INIT(kmem_cache_s_flags, "kmem_cache", "flags");
			MEMBER_OFFSET_INIT(kmem_cache_s_gfporder,  
				"kmem_cache", "gfporder");

			MEMBER_OFFSET_INIT(kmem_cache_cpu_cache, "kmem_cache", "cpu_cache");

			if (MEMBER_EXISTS("kmem_cache", "lists"))
				MEMBER_OFFSET_INIT(kmem_cache_s_lists, "kmem_cache", "lists");
			else if (MEMBER_EXISTS("kmem_cache", "nodelists") ||
					 MEMBER_EXISTS("kmem_cache", "node")) {
				nodelists_field = MEMBER_EXISTS("kmem_cache", "node") ? 
					"node" : "nodelists";
				vt->flags |= PERCPU_KMALLOC_V2_NODES;
				MEMBER_OFFSET_INIT(kmem_cache_s_lists, "kmem_cache", nodelists_field);
				if (MEMBER_TYPE("kmem_cache", nodelists_field) == TYPE_CODE_PTR) {
					/* 
					 * nodelists now a pointer to an outside array 
					 */
					vt->flags |= NODELISTS_IS_PTR;
					if (kernel_symbol_exists("nr_node_ids")) {
						get_symbol_data("nr_node_ids", sizeof(int),
							&nr_node_ids);
						vt->kmem_cache_len_nodes = nr_node_ids;
					} else
						vt->kmem_cache_len_nodes = 1;
				} else if (VALID_MEMBER(kmem_cache_cpu_cache)) {
					/*
					 * commit bf0dea23a9c094ae869a88bb694fbe966671bf6d
					 * mm/slab: use percpu allocator for cpu cache
					 */
					vt->flags |= SLAB_CPU_CACHE;
					MEMBER_OFFSET_INIT(kmem_cache_node, "kmem_cache", "node");
					if (kernel_symbol_exists("nr_node_ids")) {
						get_symbol_data("nr_node_ids", sizeof(int),
							&nr_node_ids);
						vt->kmem_cache_len_nodes = nr_node_ids;
					} else
						vt->kmem_cache_len_nodes = 1;
				} else {
					/* 
					 * This should never happen with kmem_cache.node,
					 * only with kmem_cache.nodelists
					 */
					ARRAY_LENGTH_INIT(vt->kmem_cache_len_nodes, NULL, 
						"kmem_cache.nodelists", NULL, 0);
				}
			}
			MEMBER_OFFSET_INIT(kmem_cache_s_array, "kmem_cache", "array");
			ARRAY_LENGTH_INIT(len, NULL, "kmem_cache.array", NULL, 0);
		}

		if (VALID_STRUCT(slab)) {
			MEMBER_OFFSET_INIT(slab_list, "slab", "list");
			MEMBER_OFFSET_INIT(slab_s_mem, "slab", "s_mem");
			MEMBER_OFFSET_INIT(slab_inuse, "slab", "inuse");
			MEMBER_OFFSET_INIT(slab_free, "slab", "free");
			/*
			 *  slab members were moved to an anonymous union in 2.6.39.
			 */
			if (INVALID_MEMBER(slab_list))
				ANON_MEMBER_OFFSET_INIT(slab_list, "slab", "list");
			if (INVALID_MEMBER(slab_s_mem))
				ANON_MEMBER_OFFSET_INIT(slab_s_mem, "slab", "s_mem");
			if (INVALID_MEMBER(slab_inuse))
				ANON_MEMBER_OFFSET_INIT(slab_inuse, "slab", "inuse");
			if (INVALID_MEMBER(slab_free))
				ANON_MEMBER_OFFSET_INIT(slab_free, "slab", "free");
		}

		MEMBER_OFFSET_INIT(array_cache_avail, "array_cache", "avail");
		MEMBER_OFFSET_INIT(array_cache_limit, "array_cache", "limit");
		STRUCT_SIZE_INIT(array_cache, "array_cache");

		/* 
		 * kmem_list3 renamed to kmem_cache_node in kernel 3.11-rc1
		 */
		kmem_cache_node_struct = STRUCT_EXISTS("kmem_cache_node") ? 
			"kmem_cache_node" : "kmem_list3";
		MEMBER_OFFSET_INIT(kmem_list3_slabs_partial, 
			kmem_cache_node_struct, "slabs_partial");
		MEMBER_OFFSET_INIT(kmem_list3_slabs_full, 
			kmem_cache_node_struct, "slabs_full");
		MEMBER_OFFSET_INIT(kmem_list3_slabs_free, 
			kmem_cache_node_struct, "slabs_free");
		MEMBER_OFFSET_INIT(kmem_list3_free_objects, 
			kmem_cache_node_struct, "free_objects");
		MEMBER_OFFSET_INIT(kmem_list3_shared, kmem_cache_node_struct, "shared");
		/*
		 *  Common to slab/slub
		 */
		MEMBER_OFFSET_INIT(page_slab, "page", "slab_cache");
		if (INVALID_MEMBER(page_slab))
			ANON_MEMBER_OFFSET_INIT(page_slab, "page", "slab_cache");
		MEMBER_OFFSET_INIT(page_slab_page, "page", "slab_page");
		if (INVALID_MEMBER(page_slab_page))
			ANON_MEMBER_OFFSET_INIT(page_slab_page, "page", "slab_page");
		MEMBER_OFFSET_INIT(page_first_page, "page", "first_page");
		if (INVALID_MEMBER(page_first_page))
			ANON_MEMBER_OFFSET_INIT(page_first_page, "page", "first_page");

	} else if (MEMBER_EXISTS("kmem_cache", "cpu_slab") &&
		STRUCT_EXISTS("kmem_cache_node")) {
		vt->flags |= KMALLOC_SLUB;

		STRUCT_SIZE_INIT(kmem_cache, "kmem_cache");
		MEMBER_OFFSET_INIT(kmem_cache_size, "kmem_cache", "size");
		MEMBER_OFFSET_INIT(kmem_cache_objsize, "kmem_cache", "objsize");
		if (INVALID_MEMBER(kmem_cache_objsize))
			MEMBER_OFFSET_INIT(kmem_cache_objsize, "kmem_cache", 
				"object_size");
		MEMBER_OFFSET_INIT(kmem_cache_offset, "kmem_cache", "offset");
		MEMBER_OFFSET_INIT(kmem_cache_order, "kmem_cache", "order");
		MEMBER_OFFSET_INIT(kmem_cache_local_node, "kmem_cache", "local_node");
		MEMBER_OFFSET_INIT(kmem_cache_objects, "kmem_cache", "objects");
		MEMBER_OFFSET_INIT(kmem_cache_inuse, "kmem_cache", "inuse");
		MEMBER_OFFSET_INIT(kmem_cache_align, "kmem_cache", "align");
		MEMBER_OFFSET_INIT(kmem_cache_node, "kmem_cache", "node");
		MEMBER_OFFSET_INIT(kmem_cache_cpu_slab, "kmem_cache", "cpu_slab");
		MEMBER_OFFSET_INIT(kmem_cache_list, "kmem_cache", "list");
		MEMBER_OFFSET_INIT(kmem_cache_red_left_pad, "kmem_cache", "red_left_pad");
		MEMBER_OFFSET_INIT(kmem_cache_name, "kmem_cache", "name");
		MEMBER_OFFSET_INIT(kmem_cache_flags, "kmem_cache", "flags");
		MEMBER_OFFSET_INIT(kmem_cache_random, "kmem_cache", "random");
		if (VALID_MEMBER(kmem_cache_random))
			freelist_ptr_init();
		MEMBER_OFFSET_INIT(kmem_cache_cpu_freelist, "kmem_cache_cpu", "freelist");
		MEMBER_OFFSET_INIT(kmem_cache_cpu_page, "kmem_cache_cpu", "page");
		if (INVALID_MEMBER(kmem_cache_cpu_page))
			MEMBER_OFFSET_INIT(kmem_cache_cpu_page, "kmem_cache_cpu", "slab");
		MEMBER_OFFSET_INIT(kmem_cache_cpu_node, "kmem_cache_cpu", "node");
		MEMBER_OFFSET_INIT(kmem_cache_cpu_partial, "kmem_cache_cpu", "partial");
		MEMBER_OFFSET_INIT(page_inuse, "page", "inuse");
		if (INVALID_MEMBER(page_inuse))
			ANON_MEMBER_OFFSET_INIT(page_inuse, "page", "inuse");
		if (INVALID_MEMBER(page_inuse))
			MEMBER_OFFSET_INIT(page_inuse, "slab", "inuse");
		MEMBER_OFFSET_INIT(page_offset, "page", "offset");
		if (INVALID_MEMBER(page_offset))
			ANON_MEMBER_OFFSET_INIT(page_offset, "page", "offset");
		MEMBER_OFFSET_INIT(page_slab, "page", "slab");
		if (INVALID_MEMBER(page_slab))
			ANON_MEMBER_OFFSET_INIT(page_slab, "page", "slab");
		if (INVALID_MEMBER(page_slab)) {
			MEMBER_OFFSET_INIT(page_slab, "page", "slab_cache");
			if (INVALID_MEMBER(page_slab))
				ANON_MEMBER_OFFSET_INIT(page_slab, "page", "slab_cache");
		}
		if (INVALID_MEMBER(page_slab))
			MEMBER_OFFSET_INIT(page_slab, "slab", "slab_cache");

		MEMBER_OFFSET_INIT(slab_slab_list, "slab", "slab_list");

		MEMBER_OFFSET_INIT(page_slab_page, "page", "slab_page");
		if (INVALID_MEMBER(page_slab_page))
			ANON_MEMBER_OFFSET_INIT(page_slab_page, "page", "slab_page");
		MEMBER_OFFSET_INIT(page_first_page, "page", "first_page");
		if (INVALID_MEMBER(page_first_page))
			ANON_MEMBER_OFFSET_INIT(page_first_page, "page", "first_page");
		MEMBER_OFFSET_INIT(page_freelist, "page", "freelist");
		if (INVALID_MEMBER(page_freelist))
			ANON_MEMBER_OFFSET_INIT(page_freelist, "page", "freelist");
		if (INVALID_MEMBER(page_freelist))
			MEMBER_OFFSET_INIT(page_freelist, "slab", "freelist");
		if (INVALID_MEMBER(kmem_cache_objects)) {
			MEMBER_OFFSET_INIT(kmem_cache_oo, "kmem_cache", "oo");
			/* NOTE: returns offset of containing bitfield */
			ANON_MEMBER_OFFSET_INIT(page_objects, "page", "objects");
			if (INVALID_MEMBER(page_objects))
				ANON_MEMBER_OFFSET_INIT(page_objects, "slab", "objects");
		}
		if (VALID_MEMBER(kmem_cache_node)) {
                	ARRAY_LENGTH_INIT(len, NULL, "kmem_cache.node", NULL, 0);
			vt->flags |= CONFIG_NUMA;
		}
                ARRAY_LENGTH_INIT(len, NULL, "kmem_cache.cpu_slab", NULL, 0);

		STRUCT_SIZE_INIT(kmem_cache_node, "kmem_cache_node");
		STRUCT_SIZE_INIT(kmem_cache_cpu, "kmem_cache_cpu");
		MEMBER_OFFSET_INIT(kmem_cache_node_nr_partial, 
			"kmem_cache_node", "nr_partial");
		MEMBER_OFFSET_INIT(kmem_cache_node_nr_slabs, 
			"kmem_cache_node", "nr_slabs");
		MEMBER_OFFSET_INIT(kmem_cache_node_total_objects,
			"kmem_cache_node", "total_objects");
		MEMBER_OFFSET_INIT(kmem_cache_node_partial, 
			"kmem_cache_node", "partial");
		MEMBER_OFFSET_INIT(kmem_cache_node_full, 
			"kmem_cache_node", "full");
	} else {
		MEMBER_OFFSET_INIT(kmem_cache_s_c_nextp,  
			"kmem_cache_s", "c_nextp");
		MEMBER_OFFSET_INIT(kmem_cache_s_c_name,   
			"kmem_cache_s", "c_name");
		MEMBER_OFFSET_INIT(kmem_cache_s_c_num,   
			"kmem_cache_s", "c_num");
		MEMBER_OFFSET_INIT(kmem_cache_s_c_org_size,   
			"kmem_cache_s", "c_org_size");
		MEMBER_OFFSET_INIT(kmem_cache_s_c_flags,   
			"kmem_cache_s", "c_flags");
		MEMBER_OFFSET_INIT(kmem_cache_s_c_offset,   
			"kmem_cache_s", "c_offset");
		MEMBER_OFFSET_INIT(kmem_cache_s_c_firstp,   
			"kmem_cache_s", "c_firstp");
		MEMBER_OFFSET_INIT(kmem_cache_s_c_gfporder,  
			"kmem_cache_s", "c_gfporder");
		MEMBER_OFFSET_INIT(kmem_cache_s_c_magic,  
			"kmem_cache_s", "c_magic");
		MEMBER_OFFSET_INIT(kmem_cache_s_c_align,  
			"kmem_cache_s", "c_align");
	
		MEMBER_OFFSET_INIT(kmem_slab_s_s_nextp,   
			"kmem_slab_s", "s_nextp");
		MEMBER_OFFSET_INIT(kmem_slab_s_s_freep,   
			"kmem_slab_s", "s_freep");
		MEMBER_OFFSET_INIT(kmem_slab_s_s_inuse,   
			"kmem_slab_s", "s_inuse");
		MEMBER_OFFSET_INIT(kmem_slab_s_s_mem,   
			"kmem_slab_s", "s_mem");
		MEMBER_OFFSET_INIT(kmem_slab_s_s_index,   
			"kmem_slab_s", "s_index");
		MEMBER_OFFSET_INIT(kmem_slab_s_s_offset,   
			"kmem_slab_s", "s_offset");
		MEMBER_OFFSET_INIT(kmem_slab_s_s_magic,   
			"kmem_slab_s", "s_magic");
	}

	if (kernel_symbol_exists("slab_root_caches")) {
		MEMBER_OFFSET_INIT(kmem_cache_memcg_params,
			"kmem_cache", "memcg_params");
		MEMBER_OFFSET_INIT(memcg_cache_params___root_caches_node,
			"memcg_cache_params", "__root_caches_node");
		MEMBER_OFFSET_INIT(memcg_cache_params_children,
			"memcg_cache_params", "children");
		MEMBER_OFFSET_INIT(memcg_cache_params_children_node,
			"memcg_cache_params", "children_node");

		if (VALID_MEMBER(kmem_cache_memcg_params)
		    && VALID_MEMBER(memcg_cache_params___root_caches_node)
		    && VALID_MEMBER(memcg_cache_params_children)
		    && VALID_MEMBER(memcg_cache_params_children_node))
			vt->flags |= SLAB_ROOT_CACHES;
	}

	if (!kt->kernel_NR_CPUS) {
		if (enumerator_value("WORK_CPU_UNBOUND", (long *)&value1))
			kt->kernel_NR_CPUS = (int)value1;
		else if ((i = get_array_length("__per_cpu_offset", NULL, 0)))
			kt->kernel_NR_CPUS = i;
		else if (ARRAY_LENGTH(kmem_cache_s_cpudata))
			kt->kernel_NR_CPUS = ARRAY_LENGTH(kmem_cache_s_cpudata);
		else if (ARRAY_LENGTH(kmem_cache_s_array))
			kt->kernel_NR_CPUS = ARRAY_LENGTH(kmem_cache_s_array);
		else if (ARRAY_LENGTH(kmem_cache_cpu_slab))
			kt->kernel_NR_CPUS = ARRAY_LENGTH(kmem_cache_cpu_slab);
	}

	if (CRASHDEBUG(1))
		fprintf(fp, "kernel NR_CPUS: %d %s\n", kt->kernel_NR_CPUS,
			kt->kernel_NR_CPUS ? "" : "(unknown)"); 
		
        if (kt->kernel_NR_CPUS > NR_CPUS) {
		error(WARNING, 
		    "kernel-configured NR_CPUS (%d) greater than compiled-in NR_CPUS (%d)\n",
			kt->kernel_NR_CPUS, NR_CPUS);
		error(FATAL, "recompile crash with larger NR_CPUS\n");
	}

	if (machdep->init_kernel_pgd)
		machdep->init_kernel_pgd();
	else if (symbol_exists("swapper_pg_dir")) {
		value1 = symbol_value("swapper_pg_dir");
		for (i = 0; i < NR_CPUS; i++)
			vt->kernel_pgd[i] = value1;
	} else if (symbol_exists("cpu_pgd")) {
                len = get_array_length("cpu_pgd", &dimension, 0);
		if ((len == NR_CPUS) && (dimension == machdep->ptrs_per_pgd)) {
			value1 = symbol_value("cpu_pgd");
			for (i = 0; i < NR_CPUS; i++) {
				value2 = i * 
				        (SIZE(pgd_t) * machdep->ptrs_per_pgd);
				vt->kernel_pgd[i] = value1 + value2;
			}
			error(WARNING, 
                  "no swapper_pg_dir: using first entry of cpu_pgd[%d][%d]\n\n",
				dimension, len);
		} else {
			error(WARNING, 
                            "unrecognized dimensions: cpu_pgd[%d][%d]\n",
				dimension, len);
			value1 = symbol_value("cpu_pgd");
			for (i = 0; i < NR_CPUS; i++)
				vt->kernel_pgd[i] = value1;
			error(WARNING, 
                  "no swapper_pg_dir: using first entry of cpu_pgd[%d][%d]\n\n",
				dimension, len);

		}
	} else
		error(FATAL, "no swapper_pg_dir or cpu_pgd symbols exist?\n");

	get_symbol_data("high_memory", sizeof(ulong), &vt->high_memory);

	if (kernel_symbol_exists("mem_section"))
		vt->flags |= SPARSEMEM;
	else if (kernel_symbol_exists("mem_map")) {
		get_symbol_data("mem_map", sizeof(char *), &vt->mem_map);
		vt->flags |= FLATMEM;
	} else
		vt->flags |= DISCONTIGMEM;

	sparse_mem_init();

	vt->vmalloc_start = machdep->vmalloc_start();
	if (IS_VMALLOC_ADDR(vt->mem_map))
		vt->flags |= V_MEM_MAP;
	vt->total_pages = BTOP(VTOP(vt->high_memory));

	if (symbol_exists("_totalram_pages")) {
		readmem(symbol_value("_totalram_pages") +
			OFFSET(atomic_t_counter), KVADDR,
			&vt->totalram_pages, sizeof(ulong),
			"_totalram_pages", FAULT_ON_ERROR);
	} else {
		switch (get_syment_array("totalram_pages", sp_array, 2))
		{
		case 1:
			get_symbol_data("totalram_pages", sizeof(ulong),
				&vt->totalram_pages);
			break;
		case 2:
			if (!(readmem(sp_array[0]->value, KVADDR,
			    &value1, sizeof(ulong),
			    "totalram_pages #1", RETURN_ON_ERROR)))
				break;
			if (!(readmem(sp_array[1]->value, KVADDR,
			    &value2, sizeof(ulong),
			    "totalram_pages #2", RETURN_ON_ERROR)))
				break;
			vt->totalram_pages = MAX(value1, value2);
			break;
		}
	}

	if (symbol_exists("_totalhigh_pages")) {
		readmem(symbol_value("_totalhigh_pages") +
			OFFSET(atomic_t_counter), KVADDR,
			&vt->totalhigh_pages, sizeof(ulong),
			"_totalhigh_pages", FAULT_ON_ERROR);
		vt->total_pages += vt->totalhigh_pages;
	} else if (symbol_exists("totalhigh_pages")) {
	        switch (get_syment_array("totalhigh_pages", sp_array, 2))
	        {
	        case 1:
	                get_symbol_data("totalhigh_pages", sizeof(ulong),
	                        &vt->totalhigh_pages);
	                break;
	        case 2:
	                if (!(readmem(sp_array[0]->value, KVADDR,
	                    &value1, sizeof(ulong),
	                    "totalhigh_pages #1", RETURN_ON_ERROR)))
	                        break;
	                if (!(readmem(sp_array[1]->value, KVADDR,
	                    &value2, sizeof(ulong),
	                    "totalhigh_pages #2", RETURN_ON_ERROR)))
	                        break;
	                vt->totalhigh_pages = MAX(value1, value2);
	                break;
	        }
		vt->total_pages += vt->totalhigh_pages;
	}

	if (symbol_exists("num_physpages"))
        	get_symbol_data("num_physpages", sizeof(ulong), 
			&vt->num_physpages);

	if (kernel_symbol_exists("mem_map"))
        	get_symbol_data("max_mapnr", sizeof(ulong), &vt->max_mapnr);
	if (kernel_symbol_exists("nr_swapfiles"))
		get_symbol_data("nr_swapfiles", sizeof(unsigned int), 
			&vt->nr_swapfiles);

	STRUCT_SIZE_INIT(page, "page");
	STRUCT_SIZE_INIT(free_area, "free_area");
	STRUCT_SIZE_INIT(free_area_struct, "free_area_struct");
	STRUCT_SIZE_INIT(zone, "zone");
	STRUCT_SIZE_INIT(zone_struct, "zone_struct");
	STRUCT_SIZE_INIT(kmem_bufctl_t, "kmem_bufctl_t");
	STRUCT_SIZE_INIT(swap_info_struct, "swap_info_struct");
	STRUCT_SIZE_INIT(mm_struct, "mm_struct");
	STRUCT_SIZE_INIT(vm_area_struct, "vm_area_struct");
	STRUCT_SIZE_INIT(pglist_data, "pglist_data");

	if (VALID_STRUCT(pglist_data)) {
		vt->flags |= ZONES;

		if (symbol_exists("pgdat_list") && !IS_SPARSEMEM()) 
			vt->flags |= NODES;

		/*
		 *  Determine the number of nodes the best way possible,
		 *  starting with a default of 1.
		 */
		vt->numnodes = 1;

		if (symbol_exists("numnodes"))
			get_symbol_data("numnodes", sizeof(int), &vt->numnodes);

		if (get_nodes_online())
			vt->flags |= NODES_ONLINE;

		MEMBER_OFFSET_INIT(pglist_data_node_zones, 
			"pglist_data", "node_zones");
		MEMBER_OFFSET_INIT(pglist_data_node_mem_map, 
			"pglist_data", "node_mem_map");
		MEMBER_OFFSET_INIT(pglist_data_node_start_paddr, 
			"pglist_data", "node_start_paddr");
		MEMBER_OFFSET_INIT(pglist_data_node_start_mapnr, 
			"pglist_data", "node_start_mapnr");
		MEMBER_OFFSET_INIT(pglist_data_node_size, 
			"pglist_data", "node_size");
		MEMBER_OFFSET_INIT(pglist_data_node_id, 
			"pglist_data", "node_id");
		MEMBER_OFFSET_INIT(pglist_data_node_next, 
			"pglist_data", "node_next");
		MEMBER_OFFSET_INIT(pglist_data_bdata, "pglist_data", "bdata");
		MEMBER_OFFSET_INIT(pglist_data_nr_zones, "pglist_data", 
			"nr_zones");
		MEMBER_OFFSET_INIT(pglist_data_node_start_pfn, "pglist_data", 
			"node_start_pfn");
		MEMBER_OFFSET_INIT(pglist_data_pgdat_next, "pglist_data", 
			"pgdat_next");
		MEMBER_OFFSET_INIT(pglist_data_node_present_pages, 
			"pglist_data", "node_present_pages");
		MEMBER_OFFSET_INIT(pglist_data_node_spanned_pages, 
			"pglist_data", "node_spanned_pages");
		ARRAY_LENGTH_INIT(vt->nr_zones, pglist_data_node_zones,
			"pglist_data.node_zones", NULL, 
			SIZE_OPTION(zone_struct, zone));
		vt->ZONE_HIGHMEM = vt->nr_zones - 1;

		if (VALID_STRUCT(zone_struct)) {
	                MEMBER_OFFSET_INIT(zone_struct_free_pages, 
	                        "zone_struct", "free_pages");
	                MEMBER_OFFSET_INIT(zone_struct_free_area, 
	                        "zone_struct", "free_area");
	                MEMBER_OFFSET_INIT(zone_struct_zone_pgdat, 
	                        "zone_struct", "zone_pgdat");
	                MEMBER_OFFSET_INIT(zone_struct_name, "zone_struct", 
				"name");
	                MEMBER_OFFSET_INIT(zone_struct_size, "zone_struct", 
				"size");
			if (INVALID_MEMBER(zone_struct_size))
	                	MEMBER_OFFSET_INIT(zone_struct_memsize, 
					"zone_struct", "memsize");
			MEMBER_OFFSET_INIT(zone_struct_zone_start_pfn,
				"zone_struct", "zone_start_pfn");
	                MEMBER_OFFSET_INIT(zone_struct_zone_start_paddr,  
	                        "zone_struct", "zone_start_paddr");
	                MEMBER_OFFSET_INIT(zone_struct_zone_start_mapnr, 
	                        "zone_struct", "zone_start_mapnr");
	                MEMBER_OFFSET_INIT(zone_struct_zone_mem_map, 
	                        "zone_struct", "zone_mem_map");
	                MEMBER_OFFSET_INIT(zone_struct_inactive_clean_pages, 
	                        "zone_struct", "inactive_clean_pages");
	                MEMBER_OFFSET_INIT(zone_struct_inactive_clean_list, 
	                        "zone_struct", "inactive_clean_list");
	        	ARRAY_LENGTH_INIT(vt->nr_free_areas, 
				zone_struct_free_area, "zone_struct.free_area",
				NULL, SIZE(free_area_struct));
	                MEMBER_OFFSET_INIT(zone_struct_inactive_dirty_pages,
	                        "zone_struct", "inactive_dirty_pages");
	                MEMBER_OFFSET_INIT(zone_struct_active_pages,
	                        "zone_struct", "active_pages");
	                MEMBER_OFFSET_INIT(zone_struct_pages_min,
	                        "zone_struct", "pages_min");
	                MEMBER_OFFSET_INIT(zone_struct_pages_low,
	                        "zone_struct", "pages_low");
	                MEMBER_OFFSET_INIT(zone_struct_pages_high,
	                        "zone_struct", "pages_high");
                	vt->dump_free_pages = dump_free_pages_zones_v1;

		} else if (VALID_STRUCT(zone)) {
			MEMBER_OFFSET_INIT(zone_vm_stat, "zone", "vm_stat");
			MEMBER_OFFSET_INIT(zone_free_pages, "zone", "free_pages");
			if (INVALID_MEMBER(zone_free_pages) && 
			    VALID_MEMBER(zone_vm_stat)) {
				long nr_free_pages = 0;
				if (!enumerator_value("NR_FREE_PAGES", &nr_free_pages))
					error(WARNING, 
					    "cannot determine NR_FREE_PAGES enumerator\n");
				ASSIGN_OFFSET(zone_free_pages) = OFFSET(zone_vm_stat) + 
					(nr_free_pages * sizeof(long));
			}
                        MEMBER_OFFSET_INIT(zone_free_area,
                                "zone", "free_area");
                        MEMBER_OFFSET_INIT(zone_zone_pgdat,
                                "zone", "zone_pgdat");
                        MEMBER_OFFSET_INIT(zone_name, "zone",
                                "name");
	                MEMBER_OFFSET_INIT(zone_zone_mem_map, 
	                        "zone", "zone_mem_map");
                        MEMBER_OFFSET_INIT(zone_zone_start_pfn,
                                "zone", "zone_start_pfn");
                        MEMBER_OFFSET_INIT(zone_spanned_pages,
                                "zone", "spanned_pages");
                        MEMBER_OFFSET_INIT(zone_present_pages,
                                "zone", "present_pages");
                        MEMBER_OFFSET_INIT(zone_pages_min,
                                "zone", "pages_min");
                        MEMBER_OFFSET_INIT(zone_pages_low,
                                "zone", "pages_low");
                        MEMBER_OFFSET_INIT(zone_pages_high,
                                "zone", "pages_high");
                        MEMBER_OFFSET_INIT(zone_watermark,
                                "zone", "watermark");
                        if (INVALID_MEMBER(zone_watermark))
                                MEMBER_OFFSET_INIT(zone_watermark,
                                        "zone", "_watermark");
                        MEMBER_OFFSET_INIT(zone_nr_active,
                                "zone", "nr_active");
                        MEMBER_OFFSET_INIT(zone_nr_inactive,
                                "zone", "nr_inactive");
                        MEMBER_OFFSET_INIT(zone_all_unreclaimable,
                                "zone", "all_unreclaimable");
                        MEMBER_OFFSET_INIT(zone_flags, "zone", "flags");
                        MEMBER_OFFSET_INIT(zone_pages_scanned, "zone", 
				"pages_scanned");
	        	ARRAY_LENGTH_INIT(vt->nr_free_areas, zone_free_area,
				"zone.free_area", NULL, SIZE(free_area));
                	vt->dump_free_pages = dump_free_pages_zones_v2;
		}
	} else
		vt->numnodes = 1;

	node_table_init();

	sprintf(buf, "%llx", (ulonglong) 
		MAX((uint64_t)vt->max_mapnr * PAGESIZE(), 
		machdep->memory_size()));
	vt->paddr_prlen = strlen(buf);

	if (vt->flags & PERCPU_KMALLOC_V1) 
                vt->dump_kmem_cache = dump_kmem_cache_percpu_v1;
	else if (vt->flags & PERCPU_KMALLOC_V2) 
                vt->dump_kmem_cache = dump_kmem_cache_percpu_v2;
	else if (vt->flags & KMALLOC_SLUB)
                vt->dump_kmem_cache = dump_kmem_cache_slub;
	else 
                vt->dump_kmem_cache = dump_kmem_cache;

        if (!(vt->flags & (NODES|ZONES))) {
        	get_array_length("free_area", &dimension, 0);
        	if (dimension) 
                	vt->dump_free_pages = dump_multidimensional_free_pages;
		else
                	vt->dump_free_pages = dump_free_pages;
        }

        if (!(vt->vma_cache = (char *)malloc(SIZE(vm_area_struct)*VMA_CACHE)))
                error(FATAL, "cannot malloc vm_area_struct cache\n");

        if (symbol_exists("page_hash_bits")) {
		unsigned int page_hash_bits;
               	get_symbol_data("page_hash_bits", sizeof(unsigned int),
               		&page_hash_bits);
               	len = (1 << page_hash_bits);
               	builtin_array_length("page_hash_table", len, NULL);
               	get_symbol_data("page_hash_table", sizeof(void *),
               		&vt->page_hash_table);
               	vt->page_hash_table_len = len;
		 
		STRUCT_SIZE_INIT(page_cache_bucket, "page_cache_bucket");
		if (VALID_STRUCT(page_cache_bucket))
			MEMBER_OFFSET_INIT(page_cache_bucket_chain, 
				"page_cache_bucket", "chain");
        } else if (symbol_exists("page_hash_table")) {
                vt->page_hash_table = symbol_value("page_hash_table");
                vt->page_hash_table_len = 0;
        } else if (CRASHDEBUG(1))
		error(NOTE, "page_hash_table does not exist in this kernel\n");

	kmem_cache_init();

	page_flags_init();

	rss_page_types_init();

	vt->flags |= VM_INIT;
}

/*
 *  This command displays the contents of memory, with the output formatted
 *  in several different manners.  The starting address may be entered either
 *  symbolically or by address.  The default output size is the size of a long
 *  data type, and the default output format is hexadecimal.  When hexadecimal
 *  output is used, the output will be accompanied by an ASCII translation.
 *  These are the options:
 *
 *      -p  address argument is a physical address.
 *      -u  address argument is a user virtual address.
 *      -d  display output in signed decimal format (default is hexadecimal).
 *      -D  display output in unsigned decimal format (default is hexadecimal).
 *      -s  displays output symbolically when appropriate.
 *      -8  display output in 8-bit values.
 *     -16  display output in 16-bit values.
 *     -32  display output in 32-bit values (default on 32-bit machines).
 *     -64  display output in 64-bit values (default on 64-bit machines).
 *
 *  The default number of items to display is 1, but a count argument, if any,
 *  must follow the address.
 */
void
cmd_rd(void)
{
	int c, memtype, reverse;
	ulong flag;
	long bcnt, adjust, count;
	ulonglong addr, endaddr;
	ulong offset;
	struct syment *sp;
	FILE *tmpfp;
	char *outputfile;

	flag = HEXADECIMAL|DISPLAY_DEFAULT;
	endaddr = 0;
	offset = 0;
	memtype = KVADDR;
	tmpfp = NULL;
	outputfile = NULL;
	count = -1;
	adjust = bcnt = 0;
	reverse = FALSE;

        while ((c = getopt(argcnt, args, "Raxme:r:pfudDusSNo:81:3:6:")) != EOF) {
                switch(c)
		{
		case 'R':
			reverse = TRUE;
			break;

		case 'a':
			flag &= ~DISPLAY_TYPES;
                        flag |= DISPLAY_ASCII;
			break;

		case '8':
			flag &= ~DISPLAY_TYPES;
                        flag |= DISPLAY_8;
			break;

		case '1':
			if (!STREQ(optarg, "6")) {
				error(INFO, 
				    "invalid option: %c%s\n", c, optarg);
				argerrs++;
			} else {
				flag &= ~DISPLAY_TYPES;
				flag |= DISPLAY_16;
			}
			break;

		case '3':
                        if (!STREQ(optarg, "2")) {
                                error(INFO, 
				    "invalid option: %c%s\n", c, optarg);
                                argerrs++;
                        } else {
                                flag &= ~DISPLAY_TYPES;
                                flag |= DISPLAY_32;
                        }
			break;

		case '6':
                        if (!STREQ(optarg, "4")) {
                                error(INFO, 
				    "invalid option: %c%s\n", c, optarg);
                                argerrs++;
                        } else {
                                flag &= ~DISPLAY_TYPES;
                                flag |= DISPLAY_64;
                        }
			break;

		case 'e':
			endaddr = htoll(optarg, FAULT_ON_ERROR, NULL);
			break;

		case 'r':
			flag &= ~DISPLAY_TYPES;
			flag |= DISPLAY_RAW;
			outputfile = optarg;
			if ((tmpfp = fopen(outputfile, "w")) == NULL)
				error(FATAL, "cannot open output file: %s\n",
					outputfile);
			set_tmpfile2(tmpfp);
			break;

		case 's':
		case 'S':
			if (flag & DISPLAY_DEFAULT) {
				flag |= SYMBOLIC;
				if (c == 'S') {
					if (flag & SLAB_CACHE)
						flag |= SLAB_CACHE2;
					else
						flag |= SLAB_CACHE;
				}
			} else {
				error(INFO, "-%c option"
				    " is only allowed with %d-bit display\n",
					c, DISPLAY_DEFAULT == DISPLAY_64 ?
					64 : 32);
				argerrs++;
			}
			break;

		case 'o':
			offset = stol(optarg, FAULT_ON_ERROR, NULL);
			flag |= SHOW_OFFSET;
			break;

		case 'p':
			memtype &= ~(UVADDR|KVADDR|XENMACHADDR|FILEADDR);
			memtype = PHYSADDR;
			break;

		case 'u':
			memtype &= ~(KVADDR|PHYSADDR|XENMACHADDR|FILEADDR);
			memtype = UVADDR;
			break;

		case 'd':
			flag &= ~(HEXADECIMAL|DECIMAL);
			flag |= DECIMAL;
			break;

		case 'D':
			flag &= ~(HEXADECIMAL|UDECIMAL);
                        flag |= UDECIMAL;
			break;

		case 'm':
                	if (!(kt->flags & ARCH_XEN))
                        	error(FATAL, "-m option only applies to xen architecture\n");
			memtype &= ~(UVADDR|KVADDR|FILEADDR);
			memtype = XENMACHADDR;
			break;

		case 'f':
			if (!pc->dumpfile)
				error(FATAL, 
					"-f option requires a dumpfile\n");
			memtype &= ~(KVADDR|UVADDR|PHYSADDR|XENMACHADDR);
			memtype = FILEADDR;
			break;

		case 'x':
                        flag |= NO_ASCII;
			break;

		case 'N':
			flag |= NET_ENDIAN;
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs || !args[optind])
		cmd_usage(pc->curcmd, SYNOPSIS);

        if (*args[optind] == '(') 
                addr = evall(args[optind], FAULT_ON_ERROR, NULL);
	else if (hexadecimal(args[optind], 0)) 
                addr = htoll(args[optind], FAULT_ON_ERROR, NULL);
        else if ((sp = symbol_search(args[optind])))
                addr = (ulonglong)sp->value;
        else {
		fprintf(fp, "symbol not found: %s\n", args[optind]);
                fprintf(fp, "possible alternatives:\n");
                if (!symbol_query(args[optind], "  ", NULL))
                      	fprintf(fp, "  (none found)\n");
		return;
	}

        if (flag & SHOW_OFFSET)
                addr += offset;

        if (args[++optind])
                count = stol(args[optind], FAULT_ON_ERROR, NULL);

	if (count == -1) {
		if (endaddr) {
			if (endaddr <= addr)
				error(FATAL, "invalid ending address: %llx\n",
					endaddr);

			bcnt = endaddr - addr;

        		switch (flag & (DISPLAY_TYPES))
        		{
        		case DISPLAY_64:
				count = bcnt/8;
                		break;
        		case DISPLAY_32:
				count = bcnt/4;
				break;
        		case DISPLAY_16:
				count = bcnt/2;
				break;
        		case DISPLAY_8:
        		case DISPLAY_ASCII:
			case DISPLAY_RAW:
				count = bcnt;
				break;
			}

			if (bcnt == 0)
				count = 1;
		} else {
			if ((flag & DISPLAY_TYPES) == DISPLAY_RAW)
				error(FATAL, "-r option requires either a count"
					" argument or the -e option\n");
			count = (flag & DISPLAY_ASCII) ? ASCII_UNLIMITED : 1;
		}
	} else if (endaddr)
		error(WARNING, 
		    "ending address ignored when count is specified\n");

	if ((flag & HEXADECIMAL) && !(flag & SYMBOLIC) && !(flag & NO_ASCII) &&
	    !(flag & DISPLAY_ASCII))
		flag |= ASCII_ENDLINE;

	if (memtype == KVADDR) {
		if (!COMMON_VADDR_SPACE() && !IS_KVADDR(addr))
			memtype = UVADDR;
	}

	if (reverse) {
		if (!count)
			count = 1;

		switch (flag & (DISPLAY_TYPES))
		{
		case DISPLAY_64:
			bcnt = (count * 8);
			adjust = bcnt - 8;
			break;
		case DISPLAY_32:
			bcnt = (count * 4);
			adjust = bcnt - 4;
			break;
		case DISPLAY_16:
			bcnt = (count * 2);
			adjust = bcnt - 2;
			break;
		case DISPLAY_8:
		case DISPLAY_ASCII:
		case DISPLAY_RAW:
			bcnt = count;
			adjust = bcnt - 1;
			break;
		}
		addr = (count > 1) ? addr - adjust : addr;
	}

	display_memory(addr, count, flag, memtype, outputfile);
}

/*
 *  display_memory() does the work for cmd_rd(), but can (and is) called by
 *  other routines that want to dump raw data.  Based upon the flag, the 
 *  output format is tailored to fit in an 80-character line.  Hexadecimal
 *  output is accompanied by an end-of-line ASCII translation.
 */
#define MAX_HEXCHARS_PER_LINE (32)

/* line locations where ASCII output starts */
#define ASCII_START_8   (51 + VADDR_PRLEN)
#define ASCII_START_16  (43 + VADDR_PRLEN)
#define ASCII_START_32  (39 + VADDR_PRLEN)
#define ASCII_START_64  (37 + VADDR_PRLEN)

#define ENTRIES_8   (16)         /* number of entries per line per size */
#define ENTRIES_16  (8)
#define ENTRIES_32  (4)
#define ENTRIES_64  (2)

struct memloc {                  /* common holder of read memory */
        uint8_t u8;
        uint16_t u16;
        uint32_t u32;
        uint64_t u64;
        uint64_t limit64;
};

static void
display_memory(ulonglong addr, long count, ulong flag, int memtype, void *opt)
{
	int i, a, j;
	size_t typesz, sz;
	long written;
	void *location;
	char readtype[20];
	char *addrtype;
	struct memloc mem;
	int displayed, per_line;
	int hx, lost;
	char hexchars[MAX_HEXCHARS_PER_LINE+1];
	char ch;
	int linelen;
	char buf[BUFSIZE*2];
	char slab[BUFSIZE];
	int ascii_start;
	ulong error_handle;
	char *hex_64_fmt = BITS32() ? "%.*llx " : "%.*lx ";
	char *dec_64_fmt = BITS32() ? "%12lld " : "%15ld ";
	char *dec_u64_fmt = BITS32() ? "%12llu " : "%20lu ";

	if (count <= 0) 
		error(FATAL, "invalid count request: %ld\n", count);

	switch (memtype)
	{
	case KVADDR:
		addrtype = "KVADDR";
		break;
	case UVADDR:
		addrtype = "UVADDR";
		break;
	case PHYSADDR:
		addrtype = "PHYSADDR";
		break;
	case XENMACHADDR:
		addrtype = "XENMACHADDR";
		break;
	case FILEADDR:
		addrtype = "FILEADDR";
		break;
	default:
		addrtype = NULL;
		break;
	}

	if (CRASHDEBUG(4))
		fprintf(fp, "<addr: %llx count: %ld flag: %lx (%s)>\n", 
			addr, count, flag, addrtype);

	if (flag & DISPLAY_RAW) {
		for (written = 0; written < count; written += sz) {
			sz = BUFSIZE > (count - written) ? 
				(size_t)(count - written) : (size_t)BUFSIZE;
			readmem(addr + written, memtype, buf, (long)sz,
				"raw dump to file", FAULT_ON_ERROR);
			if (fwrite(buf, 1, sz, pc->tmpfile2) != sz)
				error(FATAL, "cannot write to: %s\n",
					(char *)opt);
		}
		close_tmpfile2();

		fprintf(fp, "%ld bytes copied from 0x%llx to %s\n",
			count, addr, (char *)opt);
		return;
	}

	BZERO(&mem, sizeof(struct memloc));
	hx = lost = linelen = typesz = per_line = ascii_start = 0;
	location = NULL;

	switch (flag & (DISPLAY_TYPES))
	{
	case DISPLAY_64:
		ascii_start = ASCII_START_64; 
		typesz = SIZEOF_64BIT;
		location = &mem.u64;
		sprintf(readtype, "64-bit %s", addrtype); 
		per_line = ENTRIES_64; 
		if (machine_type("IA64"))
			mem.limit64 = kt->end;
		break;

	case DISPLAY_32:
		ascii_start = ASCII_START_32; 
		typesz = SIZEOF_32BIT;
		location = &mem.u32;
		sprintf(readtype, "32-bit %s", addrtype);
		per_line = ENTRIES_32;
		break;

	case DISPLAY_16:
		ascii_start = ASCII_START_16; 
		typesz = SIZEOF_16BIT;
		location = &mem.u16;
		sprintf(readtype, "16-bit %s", addrtype);
		per_line = ENTRIES_16;
		break;

	case DISPLAY_8:
		ascii_start = ASCII_START_8; 
		typesz = SIZEOF_8BIT;
		location = &mem.u8;
		sprintf(readtype, "8-bit %s", addrtype);
		per_line = ENTRIES_8;
		break;

	case DISPLAY_ASCII:
		typesz = SIZEOF_8BIT;
		location = &mem.u8;
		sprintf(readtype, "ascii");
		per_line = 60;
		displayed = 0;
		break;
	}

	if (flag & NO_ERROR)
		error_handle = RETURN_ON_ERROR|QUIET;
	else
		error_handle = FAULT_ON_ERROR;

	for (i = a = 0; i < count; i++) {
		if(!readmem(addr, memtype, location, typesz,
			readtype, error_handle)) {
			addr += typesz;
			lost += 1;
			continue;
		}

                if (!(flag & DISPLAY_ASCII) && (((i - lost) % per_line) == 0)) {
                        if ((i - lost)) {
				if (flag & ASCII_ENDLINE) {
					fprintf(fp, "  %s", hexchars);
				}
				fprintf(fp, "\n");
			}
			fprintf(fp, "%s:  ",
				mkstring(buf, VADDR_PRLEN, RJUST|LONGLONG_HEX,
                                MKSTR(&addr)));
			hx = 0;
			BZERO(hexchars, MAX_HEXCHARS_PER_LINE+1);
			linelen = VADDR_PRLEN + strlen(":  ");
                }

	        switch (flag & DISPLAY_TYPES)
	        {
	        case DISPLAY_64:
			if ((flag & (HEXADECIMAL|SYMBOLIC|DISPLAY_DEFAULT)) ==
			    (HEXADECIMAL|SYMBOLIC|DISPLAY_DEFAULT)) {
				if ((!mem.limit64 || (mem.u64 <= mem.limit64)) && 
				    in_ksymbol_range(mem.u64) &&
				    strlen(value_to_symstr(mem.u64, buf, 0))) {
					fprintf(fp, "%-16s ", buf);
					linelen += strlen(buf)+1;
					break;
				}
				if ((flag & SLAB_CACHE) && 
				    vaddr_to_kmem_cache(mem.u64, slab, 
				    !VERBOSE)) {
					if ((flag & SLAB_CACHE2) || CRASHDEBUG(1))
						sprintf(buf, "[%llx:%s]", 
							(ulonglong)mem.u64,
							slab);
					else
						sprintf(buf, "[%s]", slab);
					fprintf(fp, "%-16s ", buf);
					linelen += strlen(buf)+1;
					break;
				}
			} 
			if (flag & HEXADECIMAL) {
				fprintf(fp, hex_64_fmt, LONG_LONG_PRLEN, 
					mem.u64);
				linelen += (LONG_LONG_PRLEN + 1);
			}

                        else if (flag & DECIMAL)
                                fprintf(fp, dec_64_fmt, mem.u64);
                        else if (flag & UDECIMAL)
                                fprintf(fp, dec_u64_fmt, mem.u64);

	                break;

	        case DISPLAY_32:
                        if ((flag & (HEXADECIMAL|SYMBOLIC|DISPLAY_DEFAULT)) ==
                            (HEXADECIMAL|SYMBOLIC|DISPLAY_DEFAULT)) {
				if (in_ksymbol_range(mem.u32) &&
				    strlen(value_to_symstr(mem.u32, buf, 0))) {
					fprintf(fp, INT_PRLEN == 16 ? 
					    "%-16s " : "%-8s ", buf);
					linelen += strlen(buf)+1;
					break;
				}
				if ((flag & SLAB_CACHE) && 
				    vaddr_to_kmem_cache(mem.u32, slab, 
				    !VERBOSE)) {
					if ((flag & SLAB_CACHE2) || CRASHDEBUG(1))
						sprintf(buf, "[%x:%s]", 
							mem.u32, slab);
					else
						sprintf(buf, "[%s]", slab);
					fprintf(fp, INT_PRLEN == 16 ? 
					    "%-16s " : "%-8s ", buf);
					linelen += strlen(buf)+1;
					break;
				}
                        }
			if (flag & NET_ENDIAN)
				mem.u32 = htonl(mem.u32);
			if (flag & HEXADECIMAL) {
				fprintf(fp, "%.*x ", INT_PRLEN, mem.u32 );
				linelen += (INT_PRLEN + 1);
			}
                        else if (flag & DECIMAL)
                                fprintf(fp, "%12d ", mem.u32 );
                        else if (flag & UDECIMAL)
                                fprintf(fp, "%12u ", mem.u32 );
	                break;

	        case DISPLAY_16:
			if (flag & NET_ENDIAN)
				mem.u16 = htons(mem.u16);
			if (flag & HEXADECIMAL) {
				fprintf(fp, "%.*x ", SHORT_PRLEN, mem.u16);
				linelen += (SHORT_PRLEN + 1);
			}
                        else if (flag & DECIMAL)
                                fprintf(fp, "%5d ", mem.u16);
                        else if (flag & UDECIMAL)
                                fprintf(fp, "%5u ", mem.u16);
	                break;

	        case DISPLAY_8:
			if (flag & HEXADECIMAL) {
				fprintf(fp, "%.*x ", CHAR_PRLEN, mem.u8);
				linelen += (CHAR_PRLEN + 1);
			}
                        else if (flag & DECIMAL)
                                fprintf(fp, "%3d ", mem.u8); 
			else if (flag & UDECIMAL)
                                fprintf(fp, "%3u ", mem.u8);
	                break;

		case DISPLAY_ASCII:
			if (isprint(mem.u8)) {
				if ((a % per_line) == 0) {
					if (displayed && i)
						fprintf(fp, "\n");
					fprintf(fp, "%s:  ",
						mkstring(buf, VADDR_PRLEN, 
						RJUST|LONGLONG_HEX, 
						MKSTR(&addr)));
				}
				fprintf(fp, "%c", mem.u8);
				displayed++;
				a++;
			} else {
				if (count == ASCII_UNLIMITED)
					return;
				a = 0;
			}
			break;
	        }

		if (flag & HEXADECIMAL) {
			char* ptr;
	                switch (flag & DISPLAY_TYPES)
	                {
	                case DISPLAY_64:
				ptr = (char*)&mem.u64;
		                for (j = 0; j < SIZEOF_64BIT; j++) {
					ch = ptr[j];
		                        if ((ch >= 0x20) && (ch < 0x7f)) {
		                                hexchars[hx++] = ch;
		                        }
		                        else {
						hexchars[hx++] = '.';
					}
		                }
	                        break;
	
	                case DISPLAY_32:
				ptr = (char*)&mem.u32;
	                        for (j = 0; j < (SIZEOF_32BIT); j++) {
					ch = ptr[j];
	                                if ((ch >= 0x20) && (ch < 0x7f)) {
	                                        hexchars[hx++] = ch;
	                                } else {
						hexchars[hx++] = '.';
					}
	                        }
	                        break;
	
	                case DISPLAY_16:
				ptr = (char*)&mem.u16;
	                        for (j = 0; j < SIZEOF_16BIT; j++) {
					ch = ptr[j];
	                                if ((ch >= 0x20) && (ch < 0x7f)) {
	                                        hexchars[hx++] = ch;
	                                } else {
						hexchars[hx++] = '.';
					}
	                        }
	                        break;
	
	                case DISPLAY_8:
				ptr = (char*)&mem.u8;
	                        for (j = 0; j < SIZEOF_8BIT; j++) {
	                                ch = ptr[j];
	                                if ((ch >= 0x20) && (ch < 0x7f)) {
	                                        hexchars[hx++] = ch;
	                                } else {
						hexchars[hx++] = '.';
					}
	                        }
	                        break;
	                }
		}

		addr += typesz;
	}

	if ((flag & ASCII_ENDLINE) && hx) {
		pad_line(fp, ascii_start - linelen, ' ');
		fprintf(fp, "  %s", hexchars);
	}

	if (lost != count )
		fprintf(fp,"\n");
}

void
display_memory_from_file_offset(ulonglong addr, long count, void *file)
{
	if (file)
		display_memory(addr, count, DISPLAY_RAW, FILEADDR, file);
	else
		display_memory(addr, count, DISPLAY_64|ASCII_ENDLINE|HEXADECIMAL,
			FILEADDR, file);
}

/*
 *  cmd_wr() is the sister routine of cmd_rd(), used to modify the contents
 *  of memory.  Like the "rd" command, the starting address may be entered 
 *  either symbolically or by address.  The default modification size 
 *  is the size of a long data type.  Write permission must exist on the
 *  /dev/mem.  The flags are similar to those used by rd:  
 * 
 *      -p  address argument is a physical address.
 *      -u  address argument is user virtual address (only if ambiguous).
 *      -k  address argument is user virtual address (only if ambiguous).
 *      -8  write data in an 8-bit value.
 *     -16  write data in a 16-bit value.
 *     -32  write data in a 32-bit values (default on 32-bit machines).
 *     -64  write data in a 64-bit values (default on 64-bit machines).
 * 
 *  Only one value of a given datasize may be modified.
 */
void
cmd_wr(void)
{
	int c;
	ulonglong value; 
	int addr_entered, value_entered;
	int memtype;
        struct memloc mem;
	ulong addr;
	void *buf;
	long size;
	struct syment *sp;

	if (DUMPFILE()) 
		error(FATAL, "not allowed on dumpfiles\n");

	memtype = 0;
	buf = NULL;
	addr = 0;
	size = sizeof(void*);
	addr_entered = value_entered = FALSE;

        while ((c = getopt(argcnt, args, "fukp81:3:6:")) != EOF) {
                switch(c)
		{
		case '8':
			size = 1;
			break;

		case '1':
			if (!STREQ(optarg, "6")) {
				error(INFO, 
				    "invalid option: %c%s\n", c, optarg);
				argerrs++;
			} else 
				size = 2;
			break;

		case '3':
                        if (!STREQ(optarg, "2")) {
                                error(INFO, 
				    "invalid option: %c%s\n", c, optarg);
                                argerrs++;
                        } else 
                                size = 4;
			break;

		case '6':
                        if (!STREQ(optarg, "4")) {
                                error(INFO, 
				    "invalid option: %c%s\n", c, optarg);
                                argerrs++;
                        } else 
                                size = 8;
			break;

		case 'p':
			memtype &= ~(UVADDR|KVADDR|FILEADDR);
			memtype = PHYSADDR;
			break;

		case 'u':
			memtype &= ~(PHYSADDR|KVADDR|FILEADDR);
			memtype = UVADDR;
			break;

		case 'k':
			memtype &= ~(PHYSADDR|UVADDR|FILEADDR);
			memtype = KVADDR;
			break;

		case 'f':   
			/*  
			 *  Unsupported, but can be forcibly implemented
			 *  by removing the DUMPFILE() check above and
		 	 *  recompiling.
			 */
			if (!pc->dumpfile)
				error(FATAL, 
					"-f option requires a dumpfile\n");
			memtype &= ~(PHYSADDR|UVADDR|KVADDR);
			memtype = FILEADDR;
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

        if (args[optind]) {
        	if (*args[optind] == '(')
                	addr = evall(args[optind], FAULT_ON_ERROR, NULL);
		else if (hexadecimal(args[optind], 0)) 
                        addr = htoll(args[optind], FAULT_ON_ERROR, NULL);
                else if ((sp = symbol_search(args[optind])))
                        addr = sp->value;
                else {
			fprintf(fp, "symbol not found: %s\n", args[optind]);
                        fprintf(fp, "possible alternatives:\n");
                        if (!symbol_query(args[optind], "  ", NULL))
                        	fprintf(fp, "  (none found)\n");
			return;
		}
		addr_entered = TRUE;

                if (args[++optind]) {
                        value = stol(args[optind], FAULT_ON_ERROR, NULL);
			value_entered = TRUE;
        
			switch (size) 
			{
			case 1:
				mem.u8 = (uint8_t)value;
				buf = (void *)&mem.u8;
				break;
			case 2:
				mem.u16 = (uint16_t)value;
				buf = (void *)&mem.u16;
				break;
			case 4:
				mem.u32 = (uint32_t)value;
				buf = (void *)&mem.u32;
				break;
			case 8:
				mem.u64 = (uint64_t)value;
				buf = (void *)&mem.u64;
				break;
			}
		}
        }

	if (!addr_entered || !value_entered)
        	cmd_usage(pc->curcmd, SYNOPSIS);

	if (!memtype)
		memtype = vaddr_type(addr, CURRENT_CONTEXT());

	switch (memtype)
	{
	case UVADDR:
		if (!IS_UVADDR(addr, CURRENT_CONTEXT())) {
			error(INFO, "invalid user virtual address: %llx\n", 
				addr);
                	cmd_usage(pc->curcmd, SYNOPSIS);
		}
		break;

	case KVADDR:
		if (!IS_KVADDR(addr)) {
			error(INFO, "invalid kernel virtual address: %llx\n",
				addr);
               		cmd_usage(pc->curcmd, SYNOPSIS);
		}
		break;

	case PHYSADDR:
		break;

	case FILEADDR:
		break;

	case AMBIGUOUS:	
		error(INFO, 
		    "ambiguous address: %llx  (requires -p, -u or -k)\n",
			addr);
                cmd_usage(pc->curcmd, SYNOPSIS);
	}
	
	writemem(addr, memtype, buf, size, "write memory", FAULT_ON_ERROR); 
}


char *
format_stack_entry(struct bt_info *bt, char *retbuf, ulong value, ulong limit)
{
	char buf[BUFSIZE*2];
	char slab[BUFSIZE];

	if (BITS32()) {
		if ((bt->flags & BT_FULL_SYM_SLAB) && accessible(value)) {
			if ((!limit || (value <= limit)) &&
			    in_ksymbol_range(value) &&
			    strlen(value_to_symstr(value, buf, 0)))
				sprintf(retbuf, INT_PRLEN == 16 ? 
				    "%-16s" : "%-8s", buf);
			else if (vaddr_to_kmem_cache(value, slab, !VERBOSE)) {
				if ((bt->flags & BT_FULL_SYM_SLAB2) || CRASHDEBUG(1))
					sprintf(buf, "[%lx:%s]", value, slab);
				else
					sprintf(buf, "[%s]", slab);
				sprintf(retbuf, INT_PRLEN == 16 ? 
					"%-16s" : "%-8s", buf);
			} else
				sprintf(retbuf, "%08lx", value);
		} else
			sprintf(retbuf, "%08lx", value);
	} else {
		if ((bt->flags & BT_FULL_SYM_SLAB) && accessible(value)) {
			if ((!limit || (value <= limit)) && 
			    in_ksymbol_range(value) &&
			    strlen(value_to_symstr(value, buf, 0)))
				sprintf(retbuf, "%-16s", buf);
			else if (vaddr_to_kmem_cache(value, slab, !VERBOSE)) {
				if ((bt->flags & BT_FULL_SYM_SLAB2) || CRASHDEBUG(1))
					sprintf(buf, "[%lx:%s]", value, slab);
				else 
					sprintf(buf, "[%s]", slab);
				sprintf(retbuf, "%-16s", buf);
			} else
				sprintf(retbuf, "%016lx", value);
		} else
			sprintf(retbuf, "%016lx", value);
	}

	return retbuf;
}

/*
 *  For processors with "traditional" kernel/user address space distinction.
 */
int
generic_is_kvaddr(ulong addr)
{
	return (addr >= (ulong)(machdep->kvbase));
}

/*
 *  NOTE: Perhaps even this generic version should tighten up requirements
 *        by calling uvtop()?
 */
int
generic_is_uvaddr(ulong addr, struct task_context *tc)
{
	return (addr < (ulong)(machdep->kvbase));
}


/*
 *  Raw dump of a task's stack, forcing symbolic output.
 */
void
raw_stack_dump(ulong stackbase, ulong size)
{
	display_memory(stackbase, size/sizeof(ulong), 
	    	HEXADECIMAL|DISPLAY_DEFAULT|SYMBOLIC, KVADDR, NULL);
}

/*
 *  Raw data dump, with the option of symbolic output.
 */
void
raw_data_dump(ulong addr, long count, int symbolic)
{
	long wordcnt;
	ulonglong address;
	int memtype;
	ulong flags = HEXADECIMAL;

	switch (sizeof(long))
	{
	case SIZEOF_32BIT:
		wordcnt = count/SIZEOF_32BIT;
		if (count % SIZEOF_32BIT)
			wordcnt++;
		break;

	case SIZEOF_64BIT:
		wordcnt = count/SIZEOF_64BIT;
		if (count % SIZEOF_64BIT)
			wordcnt++;
		break;

	default:
		break;
	}

	switch (count)
	{
	case SIZEOF_8BIT:
		flags |= DISPLAY_8;
		break;
	case SIZEOF_16BIT:
		flags |= DISPLAY_16;
		break;
	case SIZEOF_32BIT:
		flags |= DISPLAY_32;
		break;
	default:
		flags |= DISPLAY_DEFAULT;
		break;
	}

	if (pc->curcmd_flags & MEMTYPE_FILEADDR) {
		address = pc->curcmd_private;
		memtype = FILEADDR;
	} else if (pc->curcmd_flags & MEMTYPE_UVADDR) {
		address = (ulonglong)addr;
		memtype = UVADDR;
	} else {
		address = (ulonglong)addr;
		memtype = KVADDR;
	}

	display_memory(address, wordcnt, 
		flags|(symbolic ? SYMBOLIC : ASCII_ENDLINE),
		memtype, NULL);
}

/*
 *  Quietly checks the accessibility of a memory location.
 */
int
accessible(ulong kva)
{
	ulong tmp;

	return(readmem(kva, KVADDR, &tmp, sizeof(ulong), 
	       "accessible check", RETURN_ON_ERROR|QUIET));
}

/*
 *  readmem() is by far *the* workhorse of this whole program.  It reads
 *  memory from /dev/kmem, /dev/mem the dumpfile or /proc/kcore, whichever
 *  is appropriate:
 *
 *         addr  a user, kernel or physical memory address.
 *      memtype  addr type: UVADDR, KVADDR, PHYSADDR, XENMACHADDR or FILEADDR 
 *       buffer  supplied buffer to read the data into.
 *         size  number of bytes to read.
 *         type  string describing the request -- helpful when the read fails.
 * error_handle  what to do if the read fails: FAULT_ON_ERROR kills the command
 *               immediately; RETURN_ON_ERROR returns FALSE; QUIET suppresses
 *               the error message.
 */

#define PRINT_ERROR_MESSAGE ((!(error_handle & QUIET) && !STREQ(pc->curcmd, "search")) || \
	(CRASHDEBUG(1) && !STREQ(pc->curcmd, "search")) || CRASHDEBUG(2))

#define INVALID_UVADDR   "invalid user virtual address: %llx  type: \"%s\"\n"
#define INVALID_KVADDR   "invalid kernel virtual address: %llx  type: \"%s\"\n"

#define SEEK_ERRMSG      "seek error: %s address: %llx  type: \"%s\"\n"
#define READ_ERRMSG      "read error: %s address: %llx  type: \"%s\"\n"
#define WRITE_ERRMSG     "write error: %s address: %llx  type: \"%s\"\n"
#define PAGE_EXCLUDED_ERRMSG  "page excluded: %s address: %llx  type: \"%s\"\n"
#define PAGE_INCOMPLETE_ERRMSG  "page incomplete: %s address: %llx  type: \"%s\"\n"

#define RETURN_ON_PARTIAL_READ() \
	if ((error_handle & RETURN_PARTIAL) && (size < orig_size)) {		\
		if (CRASHDEBUG(1))						\
			error(INFO, "RETURN_PARTIAL: \"%s\" read: %ld of %ld\n",\
				type, orig_size - size, orig_size);		\
		return TRUE;							\
	}

int
readmem(ulonglong addr, int memtype, void *buffer, long size,
	char *type, ulong error_handle)
{
	int fd;
	long cnt, orig_size;
	physaddr_t paddr;
	ulonglong pseudo;
	char *bufptr;

	if (CRASHDEBUG(4))
		fprintf(fp, "<readmem: %llx, %s, \"%s\", %ld, %s, %lx>\n", 
			addr, memtype_string(memtype, 1), type, size, 
			error_handle_string(error_handle), (ulong)buffer);

	bufptr = (char *)buffer;
	orig_size = size;

	if (size <= 0) {
		if (PRINT_ERROR_MESSAGE)
                       	error(INFO, "invalid size request: %ld  type: \"%s\"\n",
				size, type);
		goto readmem_error;
	}

	fd = REMOTE_MEMSRC() ? pc->sockfd : (ACTIVE() ? pc->mfd : pc->dfd); 

	/*
	 * Screen out any error conditions.
	 */
        switch (memtype)
        {
        case UVADDR:
                if (!CURRENT_CONTEXT()) {
                        if (PRINT_ERROR_MESSAGE)
                                error(INFO, "no current user process\n");
                        goto readmem_error;
                }
                if (!IS_UVADDR(addr, CURRENT_CONTEXT())) {
                        if (PRINT_ERROR_MESSAGE)
                                error(INFO, INVALID_UVADDR, addr, type);
                        goto readmem_error;
                }
                break;

        case KVADDR:
                if (LKCD_DUMPFILE())
                    	addr = fix_lkcd_address(addr);

                if (!IS_KVADDR(addr)) {
                        if (PRINT_ERROR_MESSAGE)
                                error(INFO, INVALID_KVADDR, addr, type);
                        goto readmem_error;
                }
                break;

        case PHYSADDR:
	case XENMACHADDR:
                break;

	case FILEADDR:
		return generic_read_dumpfile(addr, buffer, size, type, error_handle);
        }

        while (size > 0) {
		switch (memtype)
		{
		case UVADDR:
			if (!uvtop(CURRENT_CONTEXT(), addr, &paddr, 0)) {
				if (paddr != 0) {
					cnt = PAGESIZE() - PAGEOFFSET(addr);
					if (cnt > size)
						cnt = size;

					cnt = readswap(paddr, bufptr, cnt, addr);
					if (cnt) {
						bufptr += cnt;
						addr += cnt;
						size -= cnt;
						continue;
					}
				}
				if (PRINT_ERROR_MESSAGE)
					error(INFO, INVALID_UVADDR, addr, type);
				goto readmem_error;
			}
			break;

		case KVADDR:
                	if (!kvtop(CURRENT_CONTEXT(), addr, &paddr, 0)) {
                        	if (PRINT_ERROR_MESSAGE)
                                	error(INFO, INVALID_KVADDR, addr, type);
                        	goto readmem_error;
                	}
			break;

		case PHYSADDR:
			paddr = addr;
			break;

		case XENMACHADDR:
			pseudo = xen_m2p(addr);

                	if (pseudo == XEN_MACHADDR_NOT_FOUND) {
                        	pc->curcmd_flags |= XEN_MACHINE_ADDR;
				paddr = addr;  
                	} else
                        	paddr = pseudo | PAGEOFFSET(addr);

			break;
		}

		/* 
		 *  Compute bytes till end of page.
		 */
		cnt = PAGESIZE() - PAGEOFFSET(paddr); 

                if (cnt > size)
                        cnt = size;

		if (CRASHDEBUG(4))
			fprintf(fp, "<%s: addr: %llx paddr: %llx cnt: %ld>\n", 
				readmem_function_name(), addr, 
				(unsigned long long)paddr, cnt);

		if (memtype == KVADDR)
			pc->curcmd_flags |= MEMTYPE_KVADDR;
		else
			pc->curcmd_flags &= ~MEMTYPE_KVADDR;

		switch (READMEM(fd, bufptr, cnt, 
		    (memtype == PHYSADDR) || (memtype == XENMACHADDR) ? 0 : addr, paddr))
		{
		case SEEK_ERROR:
                        if (PRINT_ERROR_MESSAGE)
                        	error(INFO, SEEK_ERRMSG, memtype_string(memtype, 0), addr, type);
                        goto readmem_error;

		case READ_ERROR:
			if (PRINT_ERROR_MESSAGE)
				error(INFO, READ_ERRMSG, memtype_string(memtype, 0), addr, type);
			if ((pc->flags & DEVMEM) && (kt->flags & PRE_KERNEL_INIT) &&
			    !(error_handle & NO_DEVMEM_SWITCH) && devmem_is_restricted() && 
			    switch_to_proc_kcore()) {
				error_handle &= ~QUIET;
				return(readmem(addr, memtype, bufptr, size,
					type, error_handle));
			}
			goto readmem_error;

		case PAGE_EXCLUDED:
			RETURN_ON_PARTIAL_READ();
                        if (PRINT_ERROR_MESSAGE)
                        	error(INFO, PAGE_EXCLUDED_ERRMSG, memtype_string(memtype, 0), addr, type);
                        goto readmem_error;

		case PAGE_INCOMPLETE:
			RETURN_ON_PARTIAL_READ();
			if (PRINT_ERROR_MESSAGE)
				error(INFO, PAGE_INCOMPLETE_ERRMSG, memtype_string(memtype, 0), addr, type);
			goto readmem_error;

		default:
			break;
		}

		addr += cnt;
                bufptr += cnt;
                size -= cnt;
        }

        return TRUE;

readmem_error:
	
        switch (error_handle)
        {
        case (FAULT_ON_ERROR):
        case (QUIET|FAULT_ON_ERROR):
                if (pc->flags & IN_FOREACH)
                        RESUME_FOREACH();
                RESTART();

        case (RETURN_ON_ERROR):
        case (RETURN_PARTIAL|RETURN_ON_ERROR):
	case (QUIET|RETURN_ON_ERROR):
		break;
        }

	return FALSE;
}

/*
 *  Accept anything...
 */
int
generic_verify_paddr(physaddr_t paddr)
{
	return TRUE;
}

/*
 *  Read from /dev/mem.
 */
int
read_dev_mem(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr) 
{
	int readcnt;

	if (!machdep->verify_paddr(paddr)) {
		if (CRASHDEBUG(1) && !STREQ(pc->curcmd, "search"))
			error(INFO, "verify_paddr(%lx) failed\n", paddr);
		return READ_ERROR;
	}

	/*
	 *  /dev/mem disallows anything >= __pa(high_memory)
	 *
         *  However it will allow 64-bit lseeks to anywhere, and when followed
	 *  by pulling a 32-bit address from the 64-bit file position, it
	 *  quietly returns faulty data from the (wrapped-around) address.
  	 */
	if (vt->high_memory && (paddr >= (physaddr_t)(VTOP(vt->high_memory)))) {
		readcnt = 0;
		errno = 0;
		goto try_dev_kmem;
	}

	if (lseek(fd, (off_t)paddr, SEEK_SET) == -1) 
		return SEEK_ERROR;

next_read:
        errno = 0;
        readcnt = read(fd, bufptr, cnt);

	if ((readcnt != cnt) && CRASHDEBUG(4)) {
		if (errno)
			perror("/dev/mem");
		error(INFO, "read(/dev/mem, %lx, %ld): %ld (%lx)\n",
			paddr, cnt, readcnt, readcnt);	
	}

try_dev_kmem:
        /*
         *  On 32-bit intel architectures high memory can can only be accessed
	 *  via vmalloc'd addresses.  However, /dev/mem returns 0 bytes, and
	 *  non-reserved memory pages can't be mmap'd, so the only alternative
	 *  is to read it from /dev/kmem.
         */
        if ((readcnt != cnt) && BITS32() && !readcnt && !errno && 
	    IS_VMALLOC_ADDR(addr))
                readcnt = read_dev_kmem(addr, bufptr, cnt);

	/*
	 *  The 2.6 valid_phys_addr_range() can potentially shorten the 
	 *  count of a legitimate read request.  So far this has only been
	 *  seen on an ia64 where a kernel page straddles an EFI segment.
	 */
	if ((readcnt != cnt) && readcnt && (machdep->flags & DEVMEMRD) && 
	     !errno) {
		if (CRASHDEBUG(1) && !STREQ(pc->curcmd, "search"))
			error(INFO, "read(/dev/mem, %lx, %ld): %ld (%lx)\n",
				paddr, cnt, readcnt, readcnt);	
		cnt -= readcnt;
		bufptr += readcnt;
		goto next_read;
	}

        if (readcnt != cnt) 
		return READ_ERROR;

	return readcnt;
}

/*
 *  Write to /dev/mem.
 */
int
write_dev_mem(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr) 
{
	if (!machdep->verify_paddr(paddr)) {
		if (CRASHDEBUG(1))
			error(INFO, "verify_paddr(%lx) failed\n", paddr);
		return WRITE_ERROR;
	}

        if (lseek(fd, (off_t)paddr, SEEK_SET) == -1) 
		return SEEK_ERROR;

        if (write(fd, bufptr, cnt) != cnt) 
		return WRITE_ERROR;

	return cnt;
}

/*
 *  The first required reads of memory are done in kernel_init(),
 *  so if there's a fatal read error of /dev/mem, display a warning
 *  message if it appears that CONFIG_STRICT_DEVMEM is in effect.
 *  On x86 and x86_64, only the first 256 pages of physical memory
 *  are accessible:
 *
 *    #ifdef CONFIG_STRICT_DEVMEM
 *    int devmem_is_allowed(unsigned long pagenr)
 *    {
 *            if (pagenr <= 256)
 *                    return 1;
 *            if (!page_is_ram(pagenr))
 *                    return 1;
 *            return 0;
 *    }
 *    #endif
 *
 *  It would probably suffice to simply check for the existence of 
 *  devmem_is_allowed(), but on x86 and x86_64 verify pfn 256 reads OK,
 *  and 257 fails.
 *
 *  Update: a patch has been posted to LKML to fix the off-by-one error
 *  by changing "<= 256" to "< 256":
 *
 *     https://lkml.org/lkml/2012/8/28/357
 *
 *  The X86/X86_64 lower-boundary pfn check below has been changed 
 *  (preemptively) from 256 to 255.
 *
 *  In any case, if that x86/x86_64 check fails to prove CONFIG_STRICT_DEVMEM 
 *  is configured, then the function will check that "jiffies" can be read,
 *  as is done for the other architectures.
 *
 */
static int
devmem_is_restricted(void)
{
	long tmp;
	int restricted;


	/*
	 *  Check for pre-CONFIG_STRICT_DEVMEM kernels.
	 */
	if (!kernel_symbol_exists("devmem_is_allowed")) {
		if (machine_type("ARM") || machine_type("ARM64") ||
		    machine_type("X86") || machine_type("X86_64") ||
		    machine_type("PPC") || machine_type("PPC64"))
			return FALSE;
	}

	restricted = FALSE;

	if (STREQ(pc->live_memsrc, "/dev/mem")) {
	    	if (machine_type("X86") || machine_type("X86_64")) {
			if (readmem(255*PAGESIZE(), PHYSADDR, &tmp,
			    sizeof(long), "devmem_is_allowed - pfn 255",
			    QUIET|RETURN_ON_ERROR|NO_DEVMEM_SWITCH) &&
			    !(readmem(257*PAGESIZE(), PHYSADDR, &tmp,
			    sizeof(long), "devmem_is_allowed - pfn 257",
			    QUIET|RETURN_ON_ERROR|NO_DEVMEM_SWITCH)))
				restricted = TRUE;
		} 
		if (kernel_symbol_exists("jiffies") &&
		    !readmem(symbol_value("jiffies"), KVADDR, &tmp,
		    sizeof(ulong), "devmem_is_allowed - jiffies", 
		    QUIET|RETURN_ON_ERROR|NO_DEVMEM_SWITCH))
			restricted = TRUE;

		if (restricted && CRASHDEBUG(1))
			error(INFO, 
 	    		    "this kernel may be configured with CONFIG_STRICT_DEVMEM,"
			    " which\n       renders /dev/mem unusable as a live memory "
			    "source.\n");
	}

	return restricted;
}

static int
switch_to_proc_kcore(void)
{
	close(pc->mfd);

	if (file_exists("/proc/kcore", NULL)) {
		if (CRASHDEBUG(1))
			error(INFO, "trying /proc/kcore as an alternative to /dev/mem\n\n");
	} else
		return FALSE;

	if ((pc->mfd = open("/proc/kcore", O_RDONLY)) < 0) {
		error(INFO, "/proc/kcore: %s\n", strerror(errno));
		return FALSE;
	}
	if (!proc_kcore_init(fp, pc->mfd)) {
		error(INFO, "/proc/kcore: initialization failed\n");
		return FALSE;
	}

	pc->flags &= ~DEVMEM;
	pc->flags |= PROC_KCORE;
	pc->readmem = read_proc_kcore;
	pc->writemem = write_proc_kcore;
	pc->live_memsrc = "/proc/kcore";

	return TRUE;
}

/*
 *  Read from memory driver.
 */
int
read_memory_device(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	if (pc->curcmd_flags & XEN_MACHINE_ADDR)
		return READ_ERROR;

        if (!machdep->verify_paddr(paddr)) {
                if (CRASHDEBUG(1))
                        error(INFO, "verify_paddr(%lx) failed\n", paddr);
                return READ_ERROR;
        }

        lseek(fd, (loff_t)paddr, SEEK_SET); 

        if (read(fd, bufptr, cnt) != cnt) 
                return READ_ERROR;

        return cnt;
}

/*
 *  Write to memory driver.  
 */
int
write_memory_device(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	if (!(MEMORY_DRIVER_DEVICE_MODE & S_IWUSR))
        	return (error(FATAL, "cannot write to %s!\n", pc->live_memsrc));

        if (lseek(fd, (loff_t)paddr, SEEK_SET) == -1)
                return SEEK_ERROR;

        if (write(fd, bufptr, cnt) != cnt)
                return WRITE_ERROR;

        return cnt;
}

/*
 *  Read from an MCLX formatted dumpfile.
 */
int
read_mclx_dumpfile(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr) 
{
        if (vas_lseek((ulong)paddr, SEEK_SET)) 
		return SEEK_ERROR;
        
        if (vas_read((void *)bufptr, cnt) != cnt) 
		return READ_ERROR;

	return cnt;
}

/*
 *  Write to an MCLX formatted dumpfile.  This only modifies the buffered 
 *  copy only; if it gets flushed, the modification is lost.
 */
int
write_mclx_dumpfile(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
        if (vas_lseek((ulong)paddr, SEEK_SET)) 
        	return SEEK_ERROR;
                                
        if (vas_write((void *)bufptr, cnt) != cnt) 
		return WRITE_ERROR;

	return cnt;
}

/*
 *  Read from an LKCD formatted dumpfile.
 */
int
read_lkcd_dumpfile(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr) 
{
	set_lkcd_fp(fp);

        if (!lkcd_lseek(paddr)) 
		return SEEK_ERROR;
        
        if (lkcd_read((void *)bufptr, cnt) != cnt) 
		return READ_ERROR;

	return cnt;
}

/*
 *  Write to an LKCD formatted dumpfile.  (dummy routine -- not allowed)
 */
int
write_lkcd_dumpfile(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr) 
{
	return (error(FATAL, "cannot write to an LKCD compressed dump!\n"));
}


/*
 *  Read from network daemon.
 */
int
read_daemon(int fd, void *bufptr, int cnt, ulong vaddr, physaddr_t paddr) 
{
	if (remote_memory_read(pc->rmfd, bufptr, cnt, paddr, -1) == cnt)
		return cnt;

	if (!IS_VMALLOC_ADDR(vaddr) || DUMPFILE())
		return READ_ERROR;

        /*
         *  On 32-bit architectures w/memory above ~936MB,
         *  that memory can only be accessed via vmalloc'd
         *  addresses.  However, /dev/mem returns 0 bytes,
         *  and non-reserved memory pages can't be mmap'd, so
         *  the only alternative is to read it from /dev/kmem.
         */

	if (BITS32() && remote_memory_read(pc->rkfd, bufptr, cnt, vaddr, -1) == cnt)
                return cnt;

	return READ_ERROR;
}

/*
 *  Write to network daemon.
 */
int
write_daemon(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr) 
{
	return (error(FATAL, "writing to daemon not supported yet [TBD]\n"));
}

/*
 *  Turn the memtype bitmask into a string.
 */
static
char *memtype_string(int memtype, int debug)
{
	static char membuf[40];

	switch (memtype)
	{
	case UVADDR:
		sprintf(membuf, debug ? "UVADDR" : "user virtual");
		break;
	case KVADDR:
		sprintf(membuf, debug ? "KVADDR" : "kernel virtual");
		break;
	case PHYSADDR:
		sprintf(membuf, debug ? "PHYSADDR" : "physical");
		break;
	case XENMACHADDR:
		sprintf(membuf, debug ? "XENMACHADDR" : "xen machine");
		break;
	case FILEADDR:
		sprintf(membuf, debug ? "FILEADDR" : "dumpfile");
		break;
	default:
		if (debug)
			sprintf(membuf, "0x%x (?)", memtype);
		else
			sprintf(membuf, "unknown");
		break;
	}

	return membuf;
}

/*
 *  Turn the error_handle bitmask into a string,
 *  Note: FAULT_ON_ERROR == 0
 */
static
char *error_handle_string(ulong error_handle)
{
        static char ebuf[20];
	int others;

	sprintf(ebuf, "(");
	others = 0;

	if (error_handle & RETURN_ON_ERROR)
		sprintf(&ebuf[strlen(ebuf)], "%sROE", others++ ? "|" : "");
	if (error_handle & FAULT_ON_ERROR)
		sprintf(&ebuf[strlen(ebuf)], "%sFOE", others++ ? "|" : "");
	if (error_handle & QUIET)
		sprintf(&ebuf[strlen(ebuf)], "%sQ", others++ ? "|" : "");
	if (error_handle & HEX_BIAS)
		sprintf(&ebuf[strlen(ebuf)], "%sHB", others++ ? "|" : "");
	if (error_handle & RETURN_PARTIAL)
		sprintf(&ebuf[strlen(ebuf)], "%sRP", others++ ? "|" : "");
	if (error_handle & NO_DEVMEM_SWITCH)
		sprintf(&ebuf[strlen(ebuf)], "%sNDS", others++ ? "|" : "");

	strcat(ebuf, ")");

        return ebuf;
}


/*
 *  Sister routine to readmem().
 */

int
writemem(ulonglong addr, int memtype, void *buffer, long size,
	char *type, ulong error_handle)
{
	int fd;
	long cnt;
	physaddr_t paddr;
	char *bufptr;

        if (CRASHDEBUG(1))
		fprintf(fp, "writemem: %llx, %s, \"%s\", %ld, %s %lx\n", 
			addr, memtype_string(memtype, 1), type, size, 
			error_handle_string(error_handle), (ulong)buffer);

	if (size < 0) {
		if (PRINT_ERROR_MESSAGE)
                       	error(INFO, "invalid size request: %ld\n", size);
		goto writemem_error;
	}

	bufptr = (char *)buffer;

	fd = ACTIVE() ? pc->mfd : pc->dfd;

	/*
	 * Screen out any error conditions.
	 */
        switch (memtype)
        {
        case UVADDR:
                if (!CURRENT_CONTEXT()) {
                        if (PRINT_ERROR_MESSAGE)
                                error(INFO, "no current user process\n");
                        goto writemem_error;
                }
                if (!IS_UVADDR(addr, CURRENT_CONTEXT())) {
                        if (PRINT_ERROR_MESSAGE)
                                error(INFO, INVALID_UVADDR, addr, type);
                        goto writemem_error;
                }
                break;

        case KVADDR:
                if (!IS_KVADDR(addr)) {
                        if (PRINT_ERROR_MESSAGE)
                                error(INFO, INVALID_KVADDR, addr, type);
                        goto writemem_error;
                }
                break;

        case PHYSADDR:
                break;


	case FILEADDR:
		return generic_write_dumpfile(addr, buffer, size, type, error_handle);
        }

        while (size > 0) {
                switch (memtype)
                {
                case UVADDR:
                        if (!uvtop(CURRENT_CONTEXT(), addr, &paddr, 0)) {
                                if (PRINT_ERROR_MESSAGE)
                                        error(INFO, INVALID_UVADDR, addr, type);
                                goto writemem_error;
                        }
                        break;

                case KVADDR:
                        if (!kvtop(CURRENT_CONTEXT(), addr, &paddr, 0)) {
                                if (PRINT_ERROR_MESSAGE)
                                        error(INFO, INVALID_KVADDR, addr, type);
                                goto writemem_error;
                        }
                        break;

                case PHYSADDR:
                        paddr = addr;
                        break;
                }

		/* 
		 *  Compute bytes till end of page.
		 */
		cnt = PAGESIZE() - PAGEOFFSET(paddr); 

                if (cnt > size)
                        cnt = size;

		switch (pc->writemem(fd, bufptr, cnt, addr, paddr))
		{
		case SEEK_ERROR:
                        if (PRINT_ERROR_MESSAGE)
                                error(INFO, SEEK_ERRMSG, memtype_string(memtype, 0), addr, type);
                        goto writemem_error;
			
		case WRITE_ERROR:
                        if (PRINT_ERROR_MESSAGE)
                                error(INFO, WRITE_ERRMSG, memtype_string(memtype, 0), addr, type);
                        goto writemem_error;

		default:
			break;
		}

                addr += cnt;
                bufptr += cnt;
                size -= cnt;
        }

        return TRUE;

writemem_error:
	
        switch (error_handle)
        {
        case (FAULT_ON_ERROR):
        case (QUIET|FAULT_ON_ERROR):
                RESTART();

        case (RETURN_ON_ERROR):
	case (QUIET|RETURN_ON_ERROR):
		break;
        }

	return FALSE;
}

/*
 *  When /dev/mem won't allow access, try /dev/kmem.  
 */
static ssize_t
read_dev_kmem(ulong vaddr, char *bufptr, long cnt)
{
	ssize_t readcnt;

	if (pc->kfd < 0) {
		if ((pc->kfd = open("/dev/kmem", O_RDONLY)) < 0)
			return 0; 
	}

	if (lseek(pc->kfd, vaddr, SEEK_SET) == -1) 
		return 0;

	readcnt = read(pc->kfd, bufptr, cnt);
	if (readcnt != cnt)
		readcnt = 0;

	return readcnt;
}

/*
 *  Generic dumpfile read/write functions to handle FILEADDR 
 *  memtype arguments to readmem() and writemem().  These are
 *  not to be confused with pc->readmem/writemem plug-ins.
 */
static int 
generic_read_dumpfile(ulonglong addr, void *buffer, long size, char *type, 
	ulong error_handle)
{
	int fd;
	int retval;

	retval = TRUE;

	if (!pc->dumpfile)
		error(FATAL, "command requires a dumpfile\n");

	if ((fd = open(pc->dumpfile, O_RDONLY)) < 0)
		error(FATAL, "%s: %s\n", pc->dumpfile,
			strerror(errno));

	if (lseek(fd, addr, SEEK_SET) == -1) {
		if (PRINT_ERROR_MESSAGE)
                	error(INFO, SEEK_ERRMSG, 
				memtype_string(FILEADDR, 0), addr, type);
		retval = FALSE;
	} else if (read(fd, buffer, size) != size) {
		if (PRINT_ERROR_MESSAGE)
			error(INFO, READ_ERRMSG, 
				memtype_string(FILEADDR, 0), addr, type);
		retval = FALSE;
	}

	close(fd);

	return retval;
}

static int 
generic_write_dumpfile(ulonglong addr, void *buffer, long size, char *type, 
	ulong error_handle)
{
	int fd;
	int retval;

	retval = TRUE;

	if (!pc->dumpfile)
		error(FATAL, "command requires a dumpfile\n");

	if ((fd = open(pc->dumpfile, O_WRONLY)) < 0)
		error(FATAL, "%s: %s\n", pc->dumpfile,
			strerror(errno));

	if (lseek(fd, addr, SEEK_SET) == -1) {
		if (PRINT_ERROR_MESSAGE)
                	error(INFO, SEEK_ERRMSG, 
				memtype_string(FILEADDR, 0), addr, type);
		retval = FALSE;
	} else if (write(fd, buffer, size) != size) {
		if (PRINT_ERROR_MESSAGE)
			error(INFO, WRITE_ERRMSG, 
				memtype_string(FILEADDR, 0), addr, type);
		retval = FALSE;
	}

	close(fd);

	return retval;
}

/*
 *  Translates a kernel virtual address to its physical address.  cmd_vtop()
 *  sets the verbose flag so that the pte translation gets displayed; all 
 *  other callers quietly accept the translation.
 */
int
kvtop(struct task_context *tc, ulong kvaddr, physaddr_t *paddr, int verbose)
{
	physaddr_t unused;

	return (machdep->kvtop(tc ? tc : CURRENT_CONTEXT(), kvaddr, 
		paddr ? paddr : &unused, verbose));
}


/*
 *  Translates a user virtual address to its physical address.  cmd_vtop()
 *  sets the verbose flag so that the pte translation gets displayed; all 
 *  other callers quietly accept the translation.
 *
 *  This routine can also take mapped kernel virtual addresses if the -u flag
 *  was passed to cmd_vtop().  If so, it makes the translation using the
 *  kernel-memory PGD entry instead of swapper_pg_dir.
 */
int
uvtop(struct task_context *tc, ulong vaddr, physaddr_t *paddr, int verbose)
{
	return(machdep->uvtop(tc, vaddr, paddr, verbose));
}

/*
 *  The vtop command does a verbose translation of a user or kernel virtual
 *  address into it physical address.  The pte translation is shown by
 *  passing the VERBOSE flag to kvtop() or uvtop().  If it's a user virtual
 *  address, the vm_area_struct data containing the page is displayed.
 *  Lastly, the mem_map[] page data containing the address is displayed.
 */

void
cmd_vtop(void)
{
	int c;
	ulong vaddr, context;
	int others;
	ulong vtop_flags, loop_vtop_flags;
	struct task_context *tc;

	vtop_flags = loop_vtop_flags = 0;
	tc = NULL;

        while ((c = getopt(argcnt, args, "ukc:")) != EOF) {
                switch(c)
		{
		case 'c':
	                switch (str_to_context(optarg, &context, &tc))
	                {
	                case STR_PID:
	                case STR_TASK:
				vtop_flags |= USE_USER_PGD;
	                        break;
	
	                case STR_INVALID:
	                        error(FATAL, "invalid task or pid value: %s\n",
	                                optarg);
	                        break;
	                }
			break;

		case 'u':
			vtop_flags |= UVADDR;
			break;

		case 'k':
			vtop_flags |= KVADDR;
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs || !args[optind])
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (!tc && !(tc = CURRENT_CONTEXT())) 
      		error(FATAL, "no current user process\n");

	if ((vtop_flags & (UVADDR|KVADDR)) == (UVADDR|KVADDR))
		error(FATAL, "-u and -k options are mutually exclusive\n");

	others = 0;
        while (args[optind]) {
		vaddr = htol(args[optind], FAULT_ON_ERROR, NULL);

		if (!(vtop_flags & (UVADDR|KVADDR))) {
			switch (vaddr_type(vaddr, tc))
			{
                	case UVADDR:
				loop_vtop_flags = UVADDR;
                        	break;
                	case KVADDR:
				loop_vtop_flags = KVADDR;
                        	break;
                	case AMBIGUOUS:
                        	error(FATAL,
                                "ambiguous address: %lx  (requires -u or -k)\n",
                                	vaddr);
                        	break;
			}
		} else
			loop_vtop_flags = 0;
	
		if (others++)
			fprintf(fp, "\n");

		do_vtop(vaddr, tc, vtop_flags | loop_vtop_flags);

		if (REMOTE() && CRASHDEBUG(1)) {
			ulong paddr = remote_vtop(tc->processor, vaddr);

			if (paddr)
				fprintf(fp, "rvtop(%lx)=%lx\n", vaddr, paddr);
		}

		optind++;
	}
}

/*
 *  Do the work for cmd_vtop(), or less likely, foreach().
 */
void
do_vtop(ulong vaddr, struct task_context *tc, ulong vtop_flags)
{
	physaddr_t paddr; 
	ulong vma, page;
	int page_exists;
        struct meminfo meminfo;
        char buf1[BUFSIZE];
        char buf2[BUFSIZE];
	int memtype = 0;

	switch (vtop_flags & (UVADDR|KVADDR))
	{
	case UVADDR:
		memtype = UVADDR;
		break;

	case KVADDR:
		memtype = KVADDR;
		break;

	case (UVADDR|KVADDR):
		error(FATAL, "-u and -k options are mutually exclusive\n");
		break;

	default:
                switch (vaddr_type(vaddr, tc))
                {
                case UVADDR:
                        memtype = UVADDR;
                        break;
                case KVADDR:
                        memtype = KVADDR;
                        break;
                case AMBIGUOUS:
			error(FATAL,
                            "ambiguous address: %lx  (requires -u or -k)\n",
                            	vaddr);
                        break;
                }
		break;
        }

	page_exists = paddr = 0;

	switch (memtype) {
	case UVADDR: 
                fprintf(fp, "%s  %s\n",
                        mkstring(buf1, UVADDR_PRLEN, LJUST, "VIRTUAL"),
                        mkstring(buf2, VADDR_PRLEN, LJUST, "PHYSICAL"));

		if (!IN_TASK_VMA(tc->task, vaddr)) {
			fprintf(fp, "%s  (not accessible)\n\n", 
				mkstring(buf1, UVADDR_PRLEN, LJUST|LONG_HEX,
				    MKSTR(vaddr)));
			return;
		}
		if (!uvtop(tc, vaddr, &paddr, 0)) {
			fprintf(fp, "%s  %s\n\n", 
				mkstring(buf1, UVADDR_PRLEN, LJUST|LONG_HEX,
				    MKSTR(vaddr)),
				(XEN() && (paddr == PADDR_NOT_AVAILABLE)) ?
				"(page not available)" : "(not mapped)");

			page_exists = FALSE;
		} else {
			fprintf(fp, "%s  %s\n\n",
			    mkstring(buf1, UVADDR_PRLEN, LJUST|LONG_HEX, 
				MKSTR(vaddr)),
			    mkstring(buf2, VADDR_PRLEN, LJUST|LONGLONG_HEX, 
				MKSTR(&paddr)));
			page_exists = TRUE;
		}
		uvtop(tc, vaddr, &paddr, VERBOSE);
		fprintf(fp, "\n");
		vma = vm_area_dump(tc->task, UVADDR, vaddr, 0);
		if (!page_exists) { 
			if (swap_location(paddr, buf1))
                       		fprintf(fp, "\nSWAP: %s\n", buf1);
			else if (vma_file_offset(vma, vaddr, buf1))
				fprintf(fp, "\nFILE: %s\n", buf1);
		}
		break; 

	case KVADDR:
                fprintf(fp, "%s  %s\n",
                        mkstring(buf1, VADDR_PRLEN, LJUST, "VIRTUAL"),
                        mkstring(buf2, VADDR_PRLEN, LJUST, "PHYSICAL"));

		if (!IS_KVADDR(vaddr)) {
			fprintf(fp, "%-8lx  (not a kernel virtual address)\n\n",
				vaddr);
			return;
		}
		if (vtop_flags & USE_USER_PGD) {
                	if (!uvtop(tc, vaddr, &paddr, 0)) {
                        	fprintf(fp, "%s  %s\n\n", 
					mkstring(buf1, UVADDR_PRLEN,
                                        LJUST|LONG_HEX, MKSTR(vaddr)),
					(XEN() && 
					(paddr == PADDR_NOT_AVAILABLE)) ?
					"(page not available)" :
					"(not mapped)");
                        	page_exists = FALSE;
                	} else {
                         	fprintf(fp, "%s  %s\n\n", 
			     		mkstring(buf1, UVADDR_PRLEN, 
					LJUST|LONG_HEX, MKSTR(vaddr)),
                            		mkstring(buf2, VADDR_PRLEN, 
					LJUST|LONGLONG_HEX, MKSTR(&paddr)));
                         	page_exists = TRUE;
                	}
                	uvtop(tc, vaddr, &paddr, VERBOSE);
		} else {
			if (!kvtop(tc, vaddr, &paddr, 0)) {
				fprintf(fp, "%s  %s\n\n", 
					mkstring(buf1, VADDR_PRLEN,
                                        LJUST|LONG_HEX, MKSTR(vaddr)),
					(XEN() && 
					(paddr == PADDR_NOT_AVAILABLE)) ?
					"(page not available)" :
					"(not mapped)");
				page_exists = FALSE;
			} else {
				fprintf(fp, "%s  %s\n\n",
                                        mkstring(buf1, VADDR_PRLEN,
                                        LJUST|LONG_HEX, MKSTR(vaddr)),
                                        mkstring(buf2, VADDR_PRLEN,
                                        LJUST|LONGLONG_HEX, MKSTR(&paddr)));
				page_exists = TRUE;
			}
			kvtop(tc, vaddr, &paddr, VERBOSE);
		}
		break;
	}

	fprintf(fp, "\n");

	if (page_exists && phys_to_page(paddr, &page)) { 
		if ((pc->flags & DEVMEM) && (paddr >= VTOP(vt->high_memory)))
			return;
		BZERO(&meminfo, sizeof(struct meminfo));
		meminfo.flags = ADDRESS_SPECIFIED;
		meminfo.spec_addr = paddr;
		meminfo.memtype = PHYSADDR;
		dump_mem_map(&meminfo);
	}
}

/*
 *  Runs PTOV() on the physical address argument or translates
 *  a per-cpu offset and cpu specifier.
 */
void
cmd_ptov(void)
{
	int c, len, unknown;
	ulong vaddr;
	physaddr_t paddr, paddr_test;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	int others;
	char *cpuspec;
	ulong *cpus;

        while ((c = getopt(argcnt, args, "")) != EOF) {
                switch(c)
		{
		default:
			argerrs++;
			break;
		}
	}

	if (argerrs || !args[optind])
		cmd_usage(pc->curcmd, SYNOPSIS);

	others = 0;
	cpuspec = NULL;
	cpus = NULL;

        while (args[optind]) {
		cpuspec = strchr(args[optind], ':');
		if (cpuspec) {
			*cpuspec++ = NULLCHAR;
			cpus = get_cpumask_buf();
			if (STREQ(cpuspec, ""))
				SET_BIT(cpus, CURRENT_CONTEXT()->processor);
			else
				make_cpumask(cpuspec, cpus, FAULT_ON_ERROR, NULL);
		}

		paddr = htoll(args[optind], FAULT_ON_ERROR, NULL);

		if (cpuspec) {
			sprintf(buf1, "[%d]", kt->cpus-1);
			len = strlen(buf1) + 2;
	
			fprintf(fp, "%sPER-CPU OFFSET: %llx\n", 
				others++ ? "\n" : "", (ulonglong)paddr);
			fprintf(fp, "  %s  %s\n",
		    		mkstring(buf1, len, LJUST, "CPU"),
		    		mkstring(buf2, VADDR_PRLEN, LJUST, "VIRTUAL"));
			for (c = 0; c < kt->cpus; c++) {
				if (!NUM_IN_BITMAP(cpus, c))
					continue;
				vaddr = paddr + kt->__per_cpu_offset[c];
				sprintf(buf1, "[%d]", c);
				fprintf(fp, "  %s%lx",
					mkstring(buf2, len, LJUST, buf1),
					vaddr);

				if (hide_offline_cpu(c))
					fprintf(fp, " [OFFLINE]\n");
				else
					fprintf(fp, "\n");
			}
			FREEBUF(cpus);
		} else {
			vaddr = PTOV(paddr);
	
			unknown = BITS32() && (!kvtop(0, vaddr, &paddr_test, 0) || 
			    (paddr_test != paddr));
	
			fprintf(fp, "%s%s  %s\n", others++ ? "\n" : "", 
			    mkstring(buf1, VADDR_PRLEN, LJUST, "VIRTUAL"),
			    mkstring(buf2, VADDR_PRLEN, LJUST, "PHYSICAL"));
			fprintf(fp, "%s  %s\n", unknown ? 
			    mkstring(buf1, VADDR_PRLEN, LJUST, "unknown") :
			    mkstring(buf1, VADDR_PRLEN, LJUST|LONG_HEX, MKSTR(vaddr)),
			    mkstring(buf2, VADDR_PRLEN, LJUST|LONGLONG_HEX, 
				MKSTR(&paddr)));
		}

		optind++;
	}
}


/*
 *  Runs PTOB() on the page frame number to get the page address.
 */
void
cmd_ptob(void)
{
        ulonglong value;

        optind = 1;
        if (!args[optind])
                cmd_usage(pc->curcmd, SYNOPSIS);

        while (args[optind]) {
		value = stoll(args[optind], FAULT_ON_ERROR, NULL);
		fprintf(fp, "%llx: %llx\n", value, PTOB(value));
                optind++;
        }
}


/*
 *  Runs BTOP() on the address to get the page frame number.
 */
void
cmd_btop(void)
{
        ulonglong value;

        optind = 1;
        if (!args[optind])
                cmd_usage(pc->curcmd, SYNOPSIS);

        while (args[optind]) {
		value = htoll(args[optind], FAULT_ON_ERROR, NULL); 
		fprintf(fp, "%llx: %llx\n", value, BTOP(value));
                optind++;
        }
}

/*
 *  This command displays basic virtual memory information of a context,
 *  consisting of a pointer to its mm_struct, its RSS and total virtual
 *  memory size; and a list of pointers to each vm_area_struct, its starting
 *  and ending address, and vm_flags value.  The argument can be a task
 *  address or a PID number; if no args, the current context is used.
 */
void
cmd_vm(void)
{
	int c;
	ulong flag;
	ulong value;
	ulong single_vma;
	ulonglong llvalue;
	struct task_context *tc;
	struct reference reference, *ref;
	unsigned int radix;
	int subsequent;

	flag = 0;
	single_vma = 0;
	radix = 0;
	ref = NULL;
	BZERO(&reference, sizeof(struct reference));

        while ((c = getopt(argcnt, args, "f:pmvR:P:xdM:")) != EOF) {
                switch(c)
		{
		case 'M':
			pc->curcmd_private = htoll(optarg, FAULT_ON_ERROR, NULL);
			pc->curcmd_flags |= MM_STRUCT_FORCE;
			break;

		case 'f':
			if (flag) 
				argerrs++;
			else {
				llvalue = htoll(optarg, FAULT_ON_ERROR, NULL);
				do_vm_flags(llvalue);
				return;
			}
			break;

		case 'p': 
			if (flag)
				argerrs++;
			else
				flag |= PHYSADDR;
			break;
		case 'm':
			if (flag)
				argerrs++;
			else
				flag |= PRINT_MM_STRUCT;
			break;
		case 'v':
			if (flag)
				argerrs++;
			else
				flag |= PRINT_VMA_STRUCTS;
			break;

		case 'R':
			if (ref) {
				error(INFO, "only one -R option allowed\n");
				argerrs++;
			} else if (flag && !(flag & PHYSADDR))
				argerrs++;
			else {
				ref = &reference;
				ref->str = optarg;
				flag |= PHYSADDR;
			}
			break;

		case 'P':
			if (flag)
				argerrs++;
			else {
				flag |= PRINT_SINGLE_VMA;
				single_vma = htol(optarg, FAULT_ON_ERROR, NULL);
			}
			break;

		case 'x':
			if (radix == 10)
				error(FATAL,
					"-d and -x are mutually exclusive\n");
			radix = 16;
			break;

		case 'd':
			if (radix == 16)
				error(FATAL,
					"-d and -x are mutually exclusive\n");
			radix = 10;
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (radix == 10)
		flag |= PRINT_RADIX_10;
	else if (radix == 16)
		flag |= PRINT_RADIX_16;

	if (!args[optind]) {
		if (!ref)
			print_task_header(fp, CURRENT_CONTEXT(), 0);
		vm_area_dump(CURRENT_TASK(), flag, single_vma, ref);
		return;
	}

	subsequent = 0;

	while (args[optind]) {
		switch (str_to_context(args[optind], &value, &tc))
		{
		case STR_PID:
			for (tc = pid_to_context(value); tc; tc = tc->tc_next) {
                                if (!ref)
                                        print_task_header(fp, tc, subsequent++);
                                vm_area_dump(tc->task, flag, single_vma, ref);
                        }
			break;

		case STR_TASK:
			if (!ref)
                                print_task_header(fp, tc, subsequent++);
                        vm_area_dump(tc->task, flag, single_vma, ref);
			break;

		case STR_INVALID:
			error(INFO, "%sinvalid task or pid value: %s\n",
				subsequent++ ? "\n" : "", args[optind]);
			break;
		}

		optind++;
	}
}

/*
 *  Translate a vm_flags value.
 */

#define VM_READ		0x00000001ULL	/* currently active flags */
#define VM_WRITE	0x00000002ULL
#define VM_EXEC		0x00000004ULL
#define VM_SHARED	0x00000008ULL
#define VM_MAYREAD	0x00000010ULL	/* limits for mprotect() etc */
#define VM_MAYWRITE	0x00000020ULL
#define VM_MAYEXEC	0x00000040ULL
#define VM_MAYSHARE	0x00000080ULL
#define VM_GROWSDOWN	0x00000100ULL	/* general info on the segment */
#define VM_GROWSUP	0x00000200ULL
#define VM_NOHUGEPAGE   0x00000200ULL   /* MADV_NOHUGEPAGE marked this vma */
#define VM_SHM		0x00000400ULL	/* shared memory area, don't swap out */
#define VM_PFNMAP       0x00000400ULL
#define VM_DENYWRITE	0x00000800ULL	/* ETXTBSY on write attempts.. */
#define VM_EXECUTABLE	0x00001000ULL
#define VM_LOCKED	0x00002000ULL
#define VM_IO           0x00004000ULL	/* Memory mapped I/O or similar */
#define VM_SEQ_READ	0x00008000ULL	/* App will access data sequentially */
#define VM_RAND_READ	0x00010000ULL	/* App will not benefit from clustered reads */
#define VM_DONTCOPY	0x00020000ULL   /* Do not copy this vma on fork */
#define VM_DONTEXPAND   0x00040000ULL   /* Cannot expand with mremap() */
#define VM_RESERVED     0x00080000ULL   /* Don't unmap it from swap_out */

#define VM_BIGPAGE      0x00100000ULL   /* bigpage mappings, no pte's */
#define VM_BIGMAP       0x00200000ULL   /* user wants bigpage mapping */

#define VM_WRITECOMBINED 0x00100000ULL   /* Write-combined */
#define VM_NONCACHED     0x00200000ULL   /* Noncached access */
#define VM_HUGETLB       0x00400000ULL   /* Huge tlb Page*/
#define VM_ACCOUNT       0x00100000ULL   /* Memory is a vm accounted object */

#define VM_NONLINEAR     0x00800000ULL   /* Is non-linear (remap_file_pages) */

#define VM_MAPPED_COPY  0x01000000ULL    /* T if mapped copy of data (nommu mmap) */
#define VM_HUGEPAGE     0x01000000ULL    /* MADV_HUGEPAGE marked this vma */

#define VM_INSERTPAGE   0x02000000ULL    /* The vma has had "vm_insert_page()" done on it */
#define VM_ALWAYSDUMP   0x04000000ULL    /* Always include in core dumps */

#define VM_CAN_NONLINEAR 0x08000000ULL   /* Has ->fault & does nonlinear pages */
#define VM_MIXEDMAP     0x10000000ULL    /* Can contain "struct page" and pure PFN pages */
#define VM_SAO          0x20000000ULL    /* Strong Access Ordering (powerpc) */
#define VM_PFN_AT_MMAP  0x40000000ULL    /* PFNMAP vma that is fully mapped at mmap time */
#define VM_MERGEABLE    0x80000000ULL    /* KSM may merge identical pages */

static void
do_vm_flags(ulonglong flags)
{
	int others;

	others = 0;

	fprintf(fp, "%llx: (", flags);

	if (flags & VM_READ) {
		fprintf(fp, "READ");
		others++;
	}
	if (flags & VM_WRITE)
		fprintf(fp, "%sWRITE", others++ ? "|" : "");
	if (flags & VM_EXEC)
		fprintf(fp, "%sEXEC", others++ ? "|" : "");
	if (flags & VM_SHARED)
		fprintf(fp, "%sSHARED", others++ ? "|" : "");
	if (flags & VM_MAYREAD)
		fprintf(fp, "%sMAYREAD", others++ ? "|" : "");
	if (flags & VM_MAYWRITE)
		fprintf(fp, "%sMAYWRITE", others++ ? "|" : "");
	if (flags & VM_MAYEXEC)
		fprintf(fp, "%sMAYEXEC", others++ ? "|" : "");
	if (flags & VM_MAYSHARE)
		fprintf(fp, "%sMAYSHARE", others++ ? "|" : "");
	if (flags & VM_GROWSDOWN)
		fprintf(fp, "%sGROWSDOWN", others++ ? "|" : "");
	if (kernel_symbol_exists("expand_upwards")) {
	    	if (flags & VM_GROWSUP)
			fprintf(fp, "%sGROWSUP", others++ ? "|" : "");
	} else if (flags & VM_NOHUGEPAGE)
		fprintf(fp, "%sNOHUGEPAGE", others++ ? "|" : "");
	if (flags & VM_SHM) {
		if (THIS_KERNEL_VERSION > LINUX(2,6,17))
			fprintf(fp, "%sPFNMAP", others++ ? "|" : "");
		else
			fprintf(fp, "%sSHM", others++ ? "|" : "");
	}
	if (flags & VM_DENYWRITE)
		fprintf(fp, "%sDENYWRITE", others++ ? "|" : "");
	if (flags & VM_EXECUTABLE)
		fprintf(fp, "%sEXECUTABLE", others++ ? "|" : "");
	if (flags & VM_LOCKED)
		fprintf(fp, "%sLOCKED", others++ ? "|" : "");
	if (flags & VM_IO)
		fprintf(fp, "%sIO", others++ ? "|" : "");
	if (flags & VM_SEQ_READ)
		fprintf(fp, "%sSEQ_READ", others++ ? "|" : "");
	if (flags & VM_RAND_READ)
		fprintf(fp, "%sRAND_READ", others++ ? "|" : "");
	if (flags & VM_DONTCOPY)
		fprintf(fp, "%sDONTCOPY", others++ ? "|" : "");
        if (flags & VM_DONTEXPAND)
                fprintf(fp, "%sDONTEXPAND", others++ ? "|" : "");
        if (flags & VM_RESERVED)
                fprintf(fp, "%sRESERVED", others++ ? "|" : "");
	if (symbol_exists("nr_bigpages") && (THIS_KERNEL_VERSION == LINUX(2,4,9))) {
        	if (flags & VM_BIGPAGE)
                	fprintf(fp, "%sBIGPAGE", others++ ? "|" : "");
        	if (flags & VM_BIGMAP)
                	fprintf(fp, "%sBIGMAP", others++ ? "|" : "");
	} else {
		if ((THIS_KERNEL_VERSION < LINUX(2,4,21)) &&
        	    (flags & VM_WRITECOMBINED))
                	fprintf(fp, "%sWRITECOMBINED", others++ ? "|" : "");
		if ((THIS_KERNEL_VERSION < LINUX(2,4,21)) &&
        	    (flags & VM_NONCACHED))
                	fprintf(fp, "%sNONCACHED", others++ ? "|" : "");
        	if (flags & VM_HUGETLB)
                	fprintf(fp, "%sHUGETLB", others++ ? "|" : "");
        	if (flags & VM_ACCOUNT)
                	fprintf(fp, "%sACCOUNT", others++ ? "|" : "");
	}
        if (flags & VM_NONLINEAR)
                fprintf(fp, "%sNONLINEAR", others++ ? "|" : "");

	if (flags & VM_HUGEPAGE) {
		if (MEMBER_EXISTS("mm_struct", "pmd_huge_pte"))
                	fprintf(fp, "%sHUGEPAGE", others++ ? "|" : "");
		else
                	fprintf(fp, "%sMAPPED_COPY", others++ ? "|" : "");
	}

        if (flags & VM_INSERTPAGE)
                fprintf(fp, "%sINSERTPAGE", others++ ? "|" : "");
        if (flags & VM_ALWAYSDUMP)
                fprintf(fp, "%sALWAYSDUMP", others++ ? "|" : "");
        if (flags & VM_CAN_NONLINEAR)
                fprintf(fp, "%sCAN_NONLINEAR", others++ ? "|" : "");
        if (flags & VM_MIXEDMAP)
                fprintf(fp, "%sMIXEDMAP", others++ ? "|" : "");
        if (flags & VM_SAO)
                fprintf(fp, "%sSAO", others++ ? "|" : "");
        if (flags & VM_PFN_AT_MMAP)
                fprintf(fp, "%sPFN_AT_MMAP", others++ ? "|" : "");
        if (flags & VM_MERGEABLE)
                fprintf(fp, "%sMERGEABLE", others++ ? "|" : "");

	fprintf(fp, ")\n");

}

/*
 * Read whatever size vm_area_struct.vm_flags happens to be into a ulonglong.
 */
static ulonglong
get_vm_flags(char *vma_buf)
{
	ulonglong vm_flags = 0;

	if (SIZE(vm_area_struct_vm_flags) == sizeof(short))
		vm_flags = USHORT(vma_buf + OFFSET(vm_area_struct_vm_flags));
	else if (SIZE(vm_area_struct_vm_flags) == sizeof(long))
		vm_flags = ULONG(vma_buf+ OFFSET(vm_area_struct_vm_flags));
	else if (SIZE(vm_area_struct_vm_flags) == sizeof(long long))
		vm_flags = ULONGLONG(vma_buf+ OFFSET(vm_area_struct_vm_flags));
	else
		error(INFO, "questionable vm_area_struct.vm_flags size: %d\n",
			SIZE(vm_area_struct_vm_flags));

	return vm_flags;
}

static void
vm_cleanup(void *arg)
{
	struct task_context *tc;

	pc->cmd_cleanup = NULL;
	pc->cmd_cleanup_arg = NULL;

	tc = (struct task_context *)arg;
	tc->mm_struct = 0;
}

static int
is_valid_mm(ulong mm)
{
	char kbuf[BUFSIZE];
	char *p;
	int mm_count;

	if (!(p = vaddr_to_kmem_cache(mm, kbuf, VERBOSE)))
		goto bailout;

	if (!STRNEQ(p, "mm_struct"))
		goto bailout;

	readmem(mm + OFFSET(mm_struct_mm_count), KVADDR, &mm_count, sizeof(int),
		"mm_struct mm_count", FAULT_ON_ERROR);

	if (mm_count == 0)
		error(FATAL, "stale mm_struct address\n");

	return mm_count;

bailout:
	error(FATAL, "invalid mm_struct address\n");
	return 0;
}

/*
 *  vm_area_dump() primarily does the work for cmd_vm(), but is also called
 *  from IN_TASK_VMA(), do_vtop(), and foreach().  How it behaves depends
 *  upon the flag and ref arguments:
 *
 *   UVADDR               do_vtop() when dumping the VMA for a uvaddr
 *   UVADDR|VERIFY_ADDR   IN_TASK_VMA() macro checks if a uvaddr is in a VMA
 *   PHYSADDR             cmd_vm() or foreach(vm) for -p and -R options
 *   PRINT_MM_STRUCT      cmd_vm() or foreach(vm) for -m option
 *   PRINT_VMA_STRUCTS    cmd_vm() or foreach(vm) for -v option
 *   PRINT_INODES         open_files_dump() backdoors foreach(vm)
 *
 *   ref                  cmd_vm() or foreach(vm) for -R option that searches
 *                        for references -- and only then does a display      
 */

#define PRINT_VM_DATA(buf4, buf5, tm)                                    \
                {                                                        \
                fprintf(fp, "%s  %s  ",                                  \
                    mkstring(buf4, VADDR_PRLEN, CENTER|LJUST, "MM"),     \
                    mkstring(buf5, VADDR_PRLEN, CENTER|LJUST, "PGD"));   \
                fprintf(fp, "%s  %s\n",                                  \
                    mkstring(buf4, 6, CENTER|LJUST, "RSS"),              \
                    mkstring(buf5, 8, CENTER|LJUST, "TOTAL_VM"));        \
                                                                         \
                fprintf(fp, "%s  %s  ",                                  \
                    mkstring(buf4, VADDR_PRLEN, CENTER|LJUST|LONG_HEX,   \
                        MKSTR(tm->mm_struct_addr)),                      \
                    mkstring(buf5, VADDR_PRLEN, CENTER|LJUST|LONG_HEX,   \
                        MKSTR(tm->pgd_addr)));                           \
                                                                         \
                sprintf(buf4, "%ldk", (tm->rss * PAGESIZE())/1024);      \
                sprintf(buf5, "%ldk", (tm->total_vm * PAGESIZE())/1024); \
                fprintf(fp, "%s  %s\n",                                  \
                    mkstring(buf4, 6, CENTER|LJUST, NULL),               \
                    mkstring(buf5, 8, CENTER|LJUST, NULL));              \
	        }

#define PRINT_VMA_DATA(buf1, buf2, buf3, buf4, vma)                            \
	fprintf(fp, "%s%s%s%s%s %6llx%s%s\n",                                  \
                mkstring(buf4, VADDR_PRLEN, CENTER|LJUST|LONG_HEX, MKSTR(vma)),\
	        space(MINSPACE),                                               \
                mkstring(buf2, UVADDR_PRLEN, RJUST|LONG_HEX, MKSTR(vm_start)), \
                space(MINSPACE),                                               \
                mkstring(buf3, UVADDR_PRLEN, RJUST|LONG_HEX, MKSTR(vm_end)),   \
		vm_flags, space(MINSPACE), buf1); 

#define FILENAME_COMPONENT(P,C) \
        ((STREQ((P), "/") && STREQ((C), "/")) || \
        (!STREQ((C), "/") && strstr((P),(C))))

#define VM_REF_SEARCH       (0x1)
#define VM_REF_DISPLAY      (0x2)
#define VM_REF_NUMBER       (0x4)
#define VM_REF_VMA          (0x8)
#define VM_REF_PAGE        (0x10)
#define VM_REF_HEADER      (0x20)
#define DO_REF_SEARCH(X)   ((X) && ((X)->cmdflags & VM_REF_SEARCH))
#define DO_REF_DISPLAY(X)  ((X) && ((X)->cmdflags & VM_REF_DISPLAY))
#define VM_REF_CHECK_HEXVAL(X,V) \
   (DO_REF_SEARCH(X) && ((X)->cmdflags & VM_REF_NUMBER) && ((X)->hexval == (V)))
#define VM_REF_CHECK_DECVAL(X,V) \
   (DO_REF_SEARCH(X) && ((X)->cmdflags & VM_REF_NUMBER) && ((X)->decval == (V)))
#define VM_REF_CHECK_STRING(X,S) \
   (DO_REF_SEARCH(X) && (string_exists(S)) && FILENAME_COMPONENT((S),(X)->str))
#define VM_REF_FOUND(X)    ((X) && ((X)->cmdflags & VM_REF_HEADER))

static ulong handle_each_vm_area(struct handle_each_vm_area_args *args)
{
	char *dentry_buf, *file_buf;
	ulong vm_start;
	ulong vm_end;
	ulong vm_mm;
	ulonglong vm_flags;
	ulong vm_file, inode;
	ulong dentry, vfsmnt;

	if ((args->flag & PHYSADDR) && !DO_REF_SEARCH(args->ref))
		fprintf(fp, "%s", args->vma_header);

	inode = 0;
	BZERO(args->buf1, BUFSIZE);
	*(args->vma_buf) = fill_vma_cache(args->vma);

	vm_mm = ULONG(*(args->vma_buf) + OFFSET(vm_area_struct_vm_mm));
	vm_end = ULONG(*(args->vma_buf) + OFFSET(vm_area_struct_vm_end));
	vm_start = ULONG(*(args->vma_buf) + OFFSET(vm_area_struct_vm_start));
	vm_flags = get_vm_flags(*(args->vma_buf));
	vm_file = ULONG(*(args->vma_buf) + OFFSET(vm_area_struct_vm_file));

	if (args->flag & PRINT_SINGLE_VMA) {
		if (args->vma != *(args->single_vma))
			return 0;
		fprintf(fp, "%s", args->vma_header);
		*(args->single_vma_found) = TRUE;
	}

	if (args->flag & PRINT_VMA_STRUCTS) {
		dump_struct("vm_area_struct", args->vma, args->radix);
		return 0;
	}

	if (vm_file && !(args->flag & VERIFY_ADDR)) {
		file_buf = fill_file_cache(vm_file);
		dentry = ULONG(file_buf + OFFSET(file_f_dentry));
		dentry_buf = NULL;
		if (dentry) {
			dentry_buf = fill_dentry_cache(dentry);
			if (VALID_MEMBER(file_f_vfsmnt)) {
				vfsmnt = ULONG(file_buf + OFFSET(file_f_vfsmnt));
				get_pathname(dentry, args->buf1, BUFSIZE, 1, vfsmnt);
			} else
				get_pathname(dentry, args->buf1, BUFSIZE, 1, 0);
		}
		if ((args->flag & PRINT_INODES) && dentry)
			inode = ULONG(dentry_buf + OFFSET(dentry_d_inode));
	}

	if (!(args->flag & UVADDR) || ((args->flag & UVADDR) &&
	    ((args->vaddr >= vm_start) && (args->vaddr < vm_end)))) {
		*(args->found) = TRUE;

		if (args->flag & VERIFY_ADDR)
			return args->vma;

		if (DO_REF_SEARCH(args->ref)) {
			if (VM_REF_CHECK_HEXVAL(args->ref, args->vma) ||
			    VM_REF_CHECK_HEXVAL(args->ref, (ulong)vm_flags) ||
			    VM_REF_CHECK_STRING(args->ref, args->buf1)) {
				if (!(args->ref->cmdflags & VM_REF_HEADER)) {
					print_task_header(fp, args->tc, 0);
					PRINT_VM_DATA(args->buf4, args->buf5, args->tm);
					args->ref->cmdflags |= VM_REF_HEADER;
				}
				if (!(args->ref->cmdflags & VM_REF_VMA) ||
				    (args->ref->cmdflags & VM_REF_PAGE)) {
					fprintf(fp, "%s", args->vma_header);
					args->ref->cmdflags |= VM_REF_VMA;
					args->ref->cmdflags &= ~VM_REF_PAGE;
					args->ref->ref1 = args->vma;
				}
				PRINT_VMA_DATA(args->buf1, args->buf2,
						args->buf3, args->buf4, args->vma);
			}

			if (vm_area_page_dump(args->vma, args->task,
			    vm_start, vm_end, vm_mm, args->ref)) {
				if (!(args->ref->cmdflags & VM_REF_HEADER)) {
					print_task_header(fp, args->tc, 0);
					PRINT_VM_DATA(args->buf4, args->buf5, args->tm);
					args->ref->cmdflags |= VM_REF_HEADER;
				}
				if (!(args->ref->cmdflags & VM_REF_VMA) ||
				    (args->ref->ref1 != args->vma)) {
					fprintf(fp, "%s", args->vma_header);
					PRINT_VMA_DATA(args->buf1, args->buf2,
							args->buf3, args->buf4, args->vma);
					args->ref->cmdflags |= VM_REF_VMA;
					args->ref->ref1 = args->vma;
				}

				args->ref->cmdflags |= VM_REF_DISPLAY;
				vm_area_page_dump(args->vma, args->task,
					vm_start, vm_end, vm_mm, args->ref);
				args->ref->cmdflags &= ~VM_REF_DISPLAY;
			}

			return 0;
		}

		if (inode) {
			fprintf(fp, "%lx%s%s%s%s%s%6llx%s%lx %s\n",
				args->vma, space(MINSPACE),
				mkstring(args->buf2, UVADDR_PRLEN, RJUST|LONG_HEX,
				MKSTR(vm_start)), space(MINSPACE),
				mkstring(args->buf3, UVADDR_PRLEN, RJUST|LONG_HEX,
				MKSTR(vm_end)), space(MINSPACE),
				vm_flags, space(MINSPACE), inode, args->buf1);
		} else {
			PRINT_VMA_DATA(args->buf1, args->buf2,
					args->buf3, args->buf4, args->vma);

			if (args->flag & (PHYSADDR|PRINT_SINGLE_VMA))
				vm_area_page_dump(args->vma, args->task,
				    vm_start, vm_end, vm_mm, args->ref);
		}

		if (args->flag & UVADDR)
			return args->vma;
	}
	return 0;
}

ulong
vm_area_dump(ulong task, ulong flag, ulong vaddr, struct reference *ref)
{
	struct task_context *tc;
	ulong vma;
	ulong single_vma;
	unsigned int radix;
	int single_vma_found;
	int found;
	struct task_mem_usage task_mem_usage, *tm;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char buf5[BUFSIZE];
	char vma_header[BUFSIZE];
	char *vma_buf;
	int i;
	ulong mm_mt, entry_num;
	struct list_pair *entry_list;

        tc = task_to_context(task);
	tm = &task_mem_usage;
	get_task_mem_usage(task, tm);

	single_vma = 0;
	single_vma_found = FALSE;
	if (flag & PRINT_SINGLE_VMA) {
		single_vma = vaddr;
		vaddr = 0;
	}

	if (flag & PRINT_RADIX_10)
		radix = 10;
	else if (flag & PRINT_RADIX_16)
		radix = 16;
	else
		radix = 0;

	if (ref) {
		ref->cmdflags = VM_REF_SEARCH;
		if (IS_A_NUMBER(ref->str)) {
			ref->hexval = htol(ref->str, FAULT_ON_ERROR, NULL);
			if (decimal(ref->str, 0))
				ref->decval = dtol(ref->str, 
					FAULT_ON_ERROR, NULL);
			ref->cmdflags |= VM_REF_NUMBER;
		} 
	}

        if (VM_REF_CHECK_HEXVAL(ref, tm->mm_struct_addr) ||
            VM_REF_CHECK_HEXVAL(ref, tm->pgd_addr)) {
        	print_task_header(fp, tc, 0);
		PRINT_VM_DATA(buf4, buf5, tm);
		fprintf(fp, "\n");
                return (ulong)NULL;
        }

        if (!(flag & (UVADDR|PRINT_MM_STRUCT|PRINT_VMA_STRUCTS|PRINT_SINGLE_VMA)) &&
	    !DO_REF_SEARCH(ref)) 
		PRINT_VM_DATA(buf4, buf5, tm);

        if (!tm->mm_struct_addr) {
		if (pc->curcmd_flags & MM_STRUCT_FORCE) {
			if (!is_valid_mm(pc->curcmd_private))
				return (ulong)NULL;

			tc->mm_struct = tm->mm_struct_addr = pc->curcmd_private;

			/*
			 * tc->mm_struct is changed, use vm_cleanup to
			 * restore it.
			 */
			pc->cmd_cleanup_arg = (void *)tc;
			pc->cmd_cleanup = vm_cleanup;
		} else
			return (ulong)NULL;
	}

	if (flag & PRINT_MM_STRUCT) {
		dump_struct("mm_struct", tm->mm_struct_addr, radix);
                return (ulong)NULL;
	}

       	sprintf(vma_header, "%s%s%s%s%s  FLAGS%sFILE\n",
                mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "VMA"),
                space(MINSPACE),              
                mkstring(buf2, UVADDR_PRLEN, CENTER|RJUST, "START"),
                space(MINSPACE),              
                mkstring(buf3, UVADDR_PRLEN, CENTER|RJUST, "END"),
		space(MINSPACE));

	if (!(flag & (PHYSADDR|VERIFY_ADDR|PRINT_VMA_STRUCTS|PRINT_SINGLE_VMA)) && 
	    !DO_REF_SEARCH(ref)) 
		fprintf(fp, "%s", vma_header);

	found = FALSE;

	struct handle_each_vm_area_args args = {
		.task = task,		.flag = flag,	.vaddr = vaddr,
		.ref = ref,		.tc = tc,	.radix = radix,
		.tm = tm,		.buf1 = buf1,	.buf2 = buf2,
		.buf3 = buf3,		.buf4 = buf4,	.buf5 = buf5,
		.vma_header = vma_header,		.single_vma = &single_vma,
		.single_vma_found = &single_vma_found,	.found = &found,
		.vma_buf = &vma_buf,
	};

	if (INVALID_MEMBER(mm_struct_mmap) && VALID_MEMBER(mm_struct_mm_mt)) {
		mm_mt = tm->mm_struct_addr + OFFSET(mm_struct_mm_mt);
		entry_num = do_maple_tree(mm_mt, MAPLE_TREE_COUNT, NULL);
		entry_list = (struct list_pair *)GETBUF(entry_num * sizeof(struct list_pair));
		do_maple_tree(mm_mt, MAPLE_TREE_GATHER, entry_list);

		for (i = 0; i < entry_num; i++) {
			if (!!(args.vma = (ulong)entry_list[i].value) &&
			    handle_each_vm_area(&args)) {
				FREEBUF(entry_list);
				return args.vma;
			}
		}
		FREEBUF(entry_list);
	} else {
		readmem(tm->mm_struct_addr + OFFSET(mm_struct_mmap), KVADDR,
			&vma, sizeof(void *), "mm_struct mmap", FAULT_ON_ERROR);
		while (vma) {
			args.vma = vma;
			if (handle_each_vm_area(&args))
				return vma;
			vma = ULONG(vma_buf + OFFSET(vm_area_struct_vm_next));
		}
	}

	if (flag & VERIFY_ADDR)
		return (ulong)NULL;

	if ((flag & PRINT_SINGLE_VMA) && !single_vma_found)
		fprintf(fp, "(not found)\n");

	if ((flag & UVADDR) && !found) 
		fprintf(fp, "(not found)\n");

	if (VM_REF_FOUND(ref))
		fprintf(fp, "\n");

	return (ulong)NULL;
}

static int
vm_area_page_dump(ulong vma, 
		  ulong task, 
		  ulong start, 
		  ulong end, 
		  ulong mm,
		  struct reference *ref)
{
	physaddr_t paddr;
	ulong offs;
	char *p1, *p2;
	int display;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE*2];
	char buf4[BUFSIZE];

	if (mm == symbol_value("init_mm"))
		return FALSE;

	if (!ref || DO_REF_DISPLAY(ref))
		fprintf(fp, "%s  %s\n",
			mkstring(buf1, UVADDR_PRLEN, LJUST, "VIRTUAL"),
			mkstring(buf2, MAX(PADDR_PRLEN, strlen("PHYSICAL")), 
			LJUST, "PHYSICAL"));

	if (DO_REF_DISPLAY(ref)) {
		start = ref->ref2;
	}

	while (start < end) {

		display = DO_REF_SEARCH(ref) ? FALSE : TRUE;
	
		if (VM_REF_CHECK_HEXVAL(ref, start)) {
			if (DO_REF_DISPLAY(ref)) 
				display = TRUE;
			else {
				ref->cmdflags |= VM_REF_PAGE;
				ref->ref2 = start;
				return TRUE;
			}
		}

                if (uvtop(task_to_context(task), start, &paddr, 0)) {
			sprintf(buf3, "%s  %s\n",
				mkstring(buf1, UVADDR_PRLEN, LJUST|LONG_HEX,
				MKSTR(start)),
                	        mkstring(buf2, MAX(PADDR_PRLEN, 
				strlen("PHYSICAL")), RJUST|LONGLONG_HEX, 
				MKSTR(&paddr)));

			if (VM_REF_CHECK_HEXVAL(ref, paddr)) {
				if (DO_REF_DISPLAY(ref)) 
					display = TRUE;
				else {
					ref->cmdflags |= VM_REF_PAGE;
					ref->ref2 = start;
					return TRUE;
				}
			}

                } else if (paddr && swap_location(paddr, buf1)) {

			sprintf(buf3, "%s  SWAP: %s\n",
			    mkstring(buf2, UVADDR_PRLEN, LJUST|LONG_HEX,
                                MKSTR(start)), buf1);

			if (DO_REF_SEARCH(ref)) { 
				if (VM_REF_CHECK_DECVAL(ref, 
				    THIS_KERNEL_VERSION >= LINUX(2,6,0) ?
				    __swp_offset(paddr) : SWP_OFFSET(paddr))) {
					if (DO_REF_DISPLAY(ref))
						display = TRUE;
					else {
						ref->cmdflags |= VM_REF_PAGE;
						ref->ref2 = start;
						return TRUE;
					}
				}

				strcpy(buf4, buf3);
				p1 = strstr(buf4, "SWAP:") + strlen("SWAP: ");
				p2 = strstr(buf4, "  OFFSET:");
				*p2 = NULLCHAR;
				if (VM_REF_CHECK_STRING(ref, p1)) {
					if (DO_REF_DISPLAY(ref))
						display = TRUE;
					else {
						ref->cmdflags |= VM_REF_PAGE;
						ref->ref2 = start;
						return TRUE;
					}
				}
			}
                } else if (vma_file_offset(vma, start, buf1)) {

                        sprintf(buf3, "%s  FILE: %s\n", 
			    mkstring(buf2, UVADDR_PRLEN, LJUST|LONG_HEX,
                                MKSTR(start)), buf1);

			if (DO_REF_SEARCH(ref)) {
			 	extract_hex(strstr(buf3, "OFFSET:") + 
					strlen("OFFSET: "), &offs, 0, 0);

				if (VM_REF_CHECK_HEXVAL(ref, offs)) {
					if (DO_REF_DISPLAY(ref))
						display = TRUE;
					else {
						ref->cmdflags |= VM_REF_PAGE;
				        	ref->ref2 = start;
						return TRUE;
					}
				}
			}
                } else {
                        sprintf(buf3, "%s  (not mapped)\n", 
			    mkstring(buf1, UVADDR_PRLEN, LJUST|LONG_HEX,
                                MKSTR(start)));
		}

		if (display)
			fprintf(fp, "%s", buf3);

		start += PAGESIZE();
	}

	return FALSE;
}



/*
 *  Cache the passed-in vm_area_struct.
 */
char *
fill_vma_cache(ulong vma)
{
	int i;
	char *cache;

	vt->vma_cache_fills++;

        for (i = 0; i < VMA_CACHE; i++) {
                if (vt->cached_vma[i] == vma) {
			vt->cached_vma_hits[i]++;
			cache = vt->vma_cache + (SIZE(vm_area_struct)*i);
			return(cache);
		}
	}

	cache = vt->vma_cache + (SIZE(vm_area_struct)*vt->vma_cache_index);

        readmem(vma, KVADDR, cache, SIZE(vm_area_struct),
        	"fill_vma_cache", FAULT_ON_ERROR);

	vt->cached_vma[vt->vma_cache_index] = vma;

	vt->vma_cache_index = (vt->vma_cache_index+1) % VMA_CACHE;

	return(cache);
}

/*
 *  If active, clear the vm_area_struct references.
 */
void
clear_vma_cache(void)
{
	int i;

	if (DUMPFILE())
		return;

        for (i = 0; i < VMA_CACHE; i++) {
                vt->cached_vma[i] = 0;
        	vt->cached_vma_hits[i] = 0;
	}

        vt->vma_cache_fills = 0;
	vt->vma_cache_index = 0;
}

/*
 *  Check whether an address is a user stack address based
 *  upon its vm_area_struct flags.
 */
int
in_user_stack(ulong task, ulong vaddr) 
{
	ulong vma; 
	ulonglong vm_flags;
	char *vma_buf;

	if ((vma = vm_area_dump(task, UVADDR|VERIFY_ADDR, vaddr, 0))) {
		vma_buf = fill_vma_cache(vma);
		vm_flags = get_vm_flags(vma_buf);

		if (vm_flags & VM_GROWSDOWN)
			return TRUE;
		else if (kernel_symbol_exists("expand_upwards") &&
			(vm_flags & VM_GROWSUP))
			return TRUE;
		/*
		 *  per-thread stack
		 */
		if ((vm_flags & (VM_READ|VM_WRITE)) == (VM_READ|VM_WRITE))
			return TRUE;
	}
	return FALSE;
}

/*
 * Set the const value of filepages and anonpages 
 * according to MM_FILEPAGES and MM_ANONPAGES.
 */
static void 
rss_page_types_init(void)
{
	long anonpages, filepages;

	if (VALID_MEMBER(mm_struct_rss))
		return;

	if (VALID_MEMBER(mm_struct_rss_stat)) 
	{
		if (!enumerator_value("MM_FILEPAGES", &filepages) ||
		    !enumerator_value("MM_ANONPAGES", &anonpages)) 
		{
			filepages = 0;
			anonpages = 1;
		}
		tt->filepages = filepages;
		tt->anonpages = anonpages;
	}
}

static struct tgid_context *
tgid_quick_search(ulong tgid)
{
	struct tgid_context *last, *next;

	tt->tgid_searches++;

	if (!(last = tt->last_tgid))
		return NULL;

	if (tgid == last->tgid) {
		tt->tgid_cache_hits++;
		return last;
	}

	next = last + 1;
	if ((next < (tt->tgid_array + RUNNING_TASKS())) &&
 	    (tgid == next->tgid)) {
		tt->tgid_cache_hits++;
		return next;
	}

	return NULL;
}

static void
collect_page_member_data(char *optlist, struct meminfo *mi)
{
	int i;
	int members;
	char buf[BUFSIZE];
	char *memberlist[MAXARGS];
	struct struct_member_data *page_member_cache, *pmd;

	if ((count_chars(optlist, ',')+1) > MAXARGS)
		error(FATAL, "too many members in comma-separated list\n");

	if ((LASTCHAR(optlist) == ',') || (LASTCHAR(optlist) == '.'))
		error(FATAL, "invalid format: %s\n", optlist);

	strcpy(buf, optlist);
	replace_string(optlist, ",", ' ');

	if (!(members = parse_line(optlist, memberlist)))
		error(FATAL, "invalid page struct member list format: %s\n", buf);

        page_member_cache = (struct struct_member_data *)
                GETBUF(sizeof(struct struct_member_data) * members);

	for (i = 0, pmd = page_member_cache; i < members; i++, pmd++) {
		pmd->structure = "page";
		pmd->member = memberlist[i];

		if (!fill_struct_member_data(pmd))
			error(FATAL, "invalid %s struct member: %s\n",
				pmd->structure, pmd->member);

		if (CRASHDEBUG(1)) {
			fprintf(fp, "      structure: %s\n", pmd->structure);
			fprintf(fp, "         member: %s\n", pmd->member);
			fprintf(fp, "           type: %ld\n", pmd->type);
			fprintf(fp, "  unsigned_type: %ld\n", pmd->unsigned_type);
			fprintf(fp, "         length: %ld\n", pmd->length);
			fprintf(fp, "         offset: %ld\n", pmd->offset);
			fprintf(fp, "         bitpos: %ld\n", pmd->bitpos);
			fprintf(fp, "        bitsize: %ld%s", pmd->bitsize,
				members > 1 ? "\n\n" : "\n");
		}
	}

	mi->nr_members = members;
	mi->page_member_cache = page_member_cache;
}

static int
get_bitfield_data(struct integer_data *bd)
{
	int pos, size;
	uint32_t tmpvalue32;
	uint64_t tmpvalue64;
	uint32_t mask32;
	uint64_t mask64;
	struct struct_member_data *pmd;

	pmd = bd->pmd;
	pos = bd->pmd->bitpos;
	size = bd->pmd->bitsize;

	if (pos == 0 && size == 0) {
		bd->bitfield_value = bd->value;
		return TRUE;
	}

	switch (__BYTE_ORDER)
	{
	case __LITTLE_ENDIAN:
		switch (pmd->length)
		{
		case 4:
			tmpvalue32 = (uint32_t)bd->value;
			tmpvalue32 >>= pos;
			mask32 = (1 << size) - 1;
			tmpvalue32 &= mask32;
			bd->bitfield_value = (ulong)tmpvalue32;
			break;
		case 8:
			tmpvalue64 = (uint64_t)bd->value;
			tmpvalue64 >>= pos;
			mask64 = (1UL << size) - 1;
			tmpvalue64 &= mask64;
			bd->bitfield_value = tmpvalue64;
			break;
		default:
			return FALSE;
		}
		break;

	case __BIG_ENDIAN:
		switch (pmd->length)
		{
		case 4:
			tmpvalue32 = (uint32_t)bd->value;
			tmpvalue32 <<= pos;
			tmpvalue32 >>= (32-size);
			mask32 = (1 << size) - 1;
			tmpvalue32 &= mask32;
			bd->bitfield_value = (ulong)tmpvalue32;
			break;
		case 8:
			tmpvalue64 = (uint64_t)bd->value;
			tmpvalue64 <<= pos;
			tmpvalue64 >>= (64-size);
			mask64 = (1UL << size) - 1;
			tmpvalue64 &= mask64;
			bd->bitfield_value = tmpvalue64;
			break;
		default:
			return FALSE;
		}
		break;
	}

	return TRUE;
}

static int
show_page_member_data(char *pcache, ulong pp, struct meminfo *mi, char *outputbuffer)
{
	int bufferindex, i, c, cnt, radix, struct_intbuf[10];
	ulong longbuf, struct_longbuf[10];
	unsigned char boolbuf;
	void *voidptr;
	ushort shortbuf;
	struct struct_member_data *pmd;
	struct integer_data integer_data;

	bufferindex = 0;
	pmd = mi->page_member_cache;

	bufferindex += sprintf(outputbuffer + bufferindex, "%lx  ", pp);

	for (i = 0; i < mi->nr_members; pmd++, i++) {

		switch (pmd->type)
		{
		case TYPE_CODE_PTR:
			voidptr = VOID_PTR(pcache + pmd->offset);
			bufferindex += sprintf(outputbuffer + bufferindex, 
				VADDR_PRLEN == 8 ? "%08lx  " : "%016lx  ", (ulong)voidptr);
			break;

		case TYPE_CODE_INT:
			switch (pmd->length)
			{
			case 1:
				integer_data.value = UCHAR(pcache + pmd->offset);
				break;
			case 2:
				integer_data.value = USHORT(pcache + pmd->offset);
				break;
			case 4:	
				integer_data.value = UINT(pcache + pmd->offset);
				break;
			case 8:
				if (BITS32()) 
					goto unsupported;
				integer_data.value = ULONG(pcache + pmd->offset);
				break;
			default:
				goto unsupported;
			}

			integer_data.pmd = pmd;
			if (get_bitfield_data(&integer_data))
				longbuf = integer_data.bitfield_value;
			else
				goto unsupported;

			if (STREQ(pmd->member, "flags"))
				radix = 16;
			else if (STRNEQ(pmd->member, "_count") || STRNEQ(pmd->member, "_mapcount"))
				radix = 10;
			else
				radix = *gdb_output_radix;
			
			if (pmd->unsigned_type) {
				if (pmd->length == sizeof(ulonglong))
					bufferindex += sprintf(outputbuffer + bufferindex,
						radix == 10 ?  "%lu  " : "%016lx  ", longbuf);
				else if (pmd->length == sizeof(int))
					bufferindex += sprintf(outputbuffer + bufferindex,
						radix == 10 ?  "%u  " : "%08x  ", (uint)longbuf);
				else if (pmd->length == sizeof(short)) {
					bufferindex += sprintf(outputbuffer + bufferindex,
						radix == 10 ?  "%u  " : "%04x  ", (ushort)longbuf);
				}
				else if (pmd->length == sizeof(char))
					bufferindex += sprintf(outputbuffer + bufferindex,
						radix == 10 ?  "%u  " : "%02x  ", (unsigned char)longbuf);
			} else {
				if (pmd->length == sizeof(ulonglong))
					bufferindex += sprintf(outputbuffer + bufferindex,
						radix == 10 ?  "%ld  " : "%016lx", longbuf);
				else if (pmd->length == sizeof(int))
					bufferindex += sprintf(outputbuffer + bufferindex,
						radix == 10 ?  "%d  " : "%08x  ", (int)longbuf);
				else if (pmd->length == sizeof(short))
					bufferindex += sprintf(outputbuffer + bufferindex,
						radix == 10 ?  "%d  " : "%04x  ", (short)longbuf);
				else if (pmd->length == sizeof(char))
					bufferindex += sprintf(outputbuffer + bufferindex,
						radix == 10 ?  "%d  " : "%02x  ", (char)longbuf);
			}
			break;

		case TYPE_CODE_STRUCT:
			if (STRNEQ(pmd->member, "_count") || STRNEQ(pmd->member, "_mapcount")) {
				BCOPY(pcache+pmd->offset, (char *)&struct_intbuf[0], pmd->length);
				bufferindex += sprintf(outputbuffer + bufferindex,
					"%d  ", struct_intbuf[0]); 
			} else if ((pmd->length % sizeof(long)) == 0) {
				BCOPY(pcache+pmd->offset, (char *)&struct_longbuf[0], pmd->length);
				cnt = pmd->length / sizeof(long);
				for (c = 0; c < cnt; c++) {
					bufferindex += sprintf(outputbuffer + bufferindex,
						BITS32() ? "%08lx%s" : "%016lx%s", 
						struct_longbuf[c], (c+1) < cnt ? "," : "");
				}
				bufferindex += sprintf(outputbuffer + bufferindex, "  "); 
			} else if ((pmd->length % sizeof(int)) == 0) {
				BCOPY(pcache+pmd->offset, (char *)&struct_intbuf[0], pmd->length);
				cnt = pmd->length / sizeof(int);
				for (c = 0; c < cnt; c++) {
					bufferindex += sprintf(outputbuffer + bufferindex,
						"%08x%s", struct_intbuf[c], 
						(c+1) < cnt ? "," : "");
				}
			} else if (pmd->length == sizeof(short)) {
				BCOPY(pcache+pmd->offset, (char *)&shortbuf, pmd->length);
				bufferindex += sprintf(outputbuffer + bufferindex,
					"%04x  ", shortbuf); 
			} else
				goto unsupported;
			break;

		case TYPE_CODE_BOOL:
			radix = *gdb_output_radix;
			boolbuf = UCHAR(pcache + pmd->offset);
			if (boolbuf <= 1)
				bufferindex += sprintf(outputbuffer + bufferindex, "%s  ", 
					boolbuf ? "true" : "false");
			else
				bufferindex += sprintf(outputbuffer + bufferindex, 
					radix == 10 ? "%d" : "%x  ", boolbuf);
			break;

		default:
unsupported:
			error(FATAL, "unsupported page member reference: %s.%s\n",
				pmd->structure, pmd->member);
			break;
		}
	}

	return bufferindex += sprintf(outputbuffer+bufferindex, "\n");
}

/*
 *  Fill in the task_mem_usage structure with the RSS, virtual memory size,
 *  percent of physical memory being used, and the mm_struct address.
 */
void
get_task_mem_usage(ulong task, struct task_mem_usage *tm)
{
	struct task_context *tc;
	long rss = 0, rss_cache = 0;

	BZERO(tm, sizeof(struct task_mem_usage));

	if (IS_ZOMBIE(task) || IS_EXITING(task)) 
		return;

	tc = task_to_context(task);

	if (!tc || !tc->mm_struct)     /* probably a kernel thread */
		return;

	tm->mm_struct_addr = tc->mm_struct;

	if (!task_mm(task, TRUE))
		return;

	if (VALID_MEMBER(mm_struct_rss))
		/*  
		 *  mm_struct.rss or mm_struct._rss exist. 
		 */
        	tm->rss = ULONG(tt->mm_struct + OFFSET(mm_struct_rss));
	else {
		/*
		 *  Latest kernels have mm_struct.mm_rss_stat[].
		 */ 
		if (VALID_MEMBER(mm_struct_rss_stat) && VALID_MEMBER(mm_rss_stat_count)) {
			long anonpages, filepages, count;

			anonpages = tt->anonpages;
			filepages = tt->filepages;
			count = LONG(tt->mm_struct +
				OFFSET(mm_struct_rss_stat) +
				OFFSET(mm_rss_stat_count) +
				(filepages * sizeof(long)));

			/*
			 * The counter is updated in asynchronous manner
			 * and may become negative, see:
			 * include/linux/mm.h: get_mm_counter()
			 */
			if (count > 0)
				rss += count;

			count = LONG(tt->mm_struct +
				OFFSET(mm_struct_rss_stat) +
				OFFSET(mm_rss_stat_count) +
				(anonpages * sizeof(long)));
			if (count > 0)
				rss += count;

		} else if (VALID_MEMBER(mm_struct_rss_stat)) {
			/* 6.2: struct percpu_counter rss_stat[NR_MM_COUNTERS] */
			ulong fbc;

			fbc = tc->mm_struct + OFFSET(mm_struct_rss_stat) +
				(tt->filepages * SIZE(percpu_counter));
			rss += percpu_counter_sum_positive(fbc);

			fbc = tc->mm_struct + OFFSET(mm_struct_rss_stat) +
				(tt->anonpages * SIZE(percpu_counter));
			rss += percpu_counter_sum_positive(fbc);
		}

		/* Check whether SPLIT_RSS_COUNTING is enabled */
		if (VALID_MEMBER(task_struct_rss_stat)) {
			int sync_rss;
			struct tgid_context tgid, *tgid_array, *tg, *first, *last;

			tgid_array = tt->tgid_array;
			tgid.tgid = task_tgid(task);

			if (!(tg = tgid_quick_search(tgid.tgid)))
				tg = (struct tgid_context *)bsearch(&tgid, tgid_array, RUNNING_TASKS(), 
					sizeof(struct tgid_context), sort_by_tgid);

			if (tg) {
				/* find the first element which has the same tgid */
				first = tg;
				while ((first > tgid_array) && ((first - 1)->tgid == first->tgid)) 
					first--;

				/* find the last element which have same tgid */
				last = tg;
				while ((last < (tgid_array + (RUNNING_TASKS() - 1))) && 
					(last->tgid == (last + 1)->tgid))
					last++;

				/*
				 * Using rss cache for dumpfile is more beneficial than live debug
				 * because its value never changes in dumpfile.
				 */
				if (ACTIVE() || last->rss_cache == UNINITIALIZED) {
					while (first <= last)
					{
						/* count 0 -> filepages */
						if (!readmem(first->task +
							OFFSET(task_struct_rss_stat) +
							OFFSET(task_rss_stat_count), KVADDR,
							&sync_rss,
							sizeof(int),
							"task_struct rss_stat MM_FILEPAGES",
							RETURN_ON_ERROR))
								continue;

						if (sync_rss > 0)
							rss_cache += sync_rss;

						/* count 1 -> anonpages */
						if (!readmem(first->task +
							OFFSET(task_struct_rss_stat) +
							OFFSET(task_rss_stat_count) +
							sizeof(int),
							KVADDR, &sync_rss,
							sizeof(int),
							"task_struct rss_stat MM_ANONPAGES",
							RETURN_ON_ERROR))
								continue;

						if (sync_rss > 0)
							rss_cache += sync_rss;

						if (first == last)
							break;
						first++;
					}
					last->rss_cache = rss_cache;
				}

				rss += last->rss_cache;
				tt->last_tgid = last;
			}
		}

		/*  
		 *  mm_struct._anon_rss and mm_struct._file_rss should exist. 
		 */
		if (VALID_MEMBER(mm_struct_anon_rss))
			rss +=  LONG(tt->mm_struct + OFFSET(mm_struct_anon_rss));
		if (VALID_MEMBER(mm_struct_file_rss))
			rss +=  LONG(tt->mm_struct + OFFSET(mm_struct_file_rss));

		tm->rss = (unsigned long)rss;
	}
        tm->total_vm = ULONG(tt->mm_struct + OFFSET(mm_struct_total_vm));
        tm->pgd_addr = ULONG(tt->mm_struct + OFFSET(mm_struct_pgd));

	if (is_kernel_thread(task) && !tm->rss)
		return;

	tm->pct_physmem = ((double)(tm->rss*100)) /
		((double)(MIN(vt->total_pages, 
		vt->num_physpages ? vt->num_physpages : vt->total_pages)));
}


/*
 *  cmd_kmem() is designed as a multi-purpose kernel memory investigator with
 *  the flag argument sending it off in a multitude of areas.  To date, the
 *  following options are defined:
 *
 *      -f  displays the contents of the system free_area[] array headers;
 *          also verifies that the page count equals nr_free_pages
 *      -F  same as -f, but also dumps all pages linked to that header.
 *      -p  displays basic information about each page in the system 
 *          mem_map[] array.
 *      -s  displays kmalloc() slab data.
 *      -S  same as -s, but displays all kmalloc() objects.
 *      -v  displays the vmlist entries.
 *      -c  displays the number of pages in the page_hash_table.
 *      -C  displays all entries in the page_hash_table.
 *      -i  displays informational data shown by /proc/meminfo.
 *      -h  hugepage information from hstates[] array
 *
 *      -P  forces address to be defined as a physical address
 * address  when used with -f, the address can be either a page pointer
 *          or a physical address; the free_area header containing the page
 *          (if any) is displayed.
 *          When used with -p, the address can be either a page pointer or a
 *          physical address; its basic mem_map page information is displayed.
 *          When used with -c, the page_hash_table entry containing the
 *          page pointer is displayed.
 */

/*  Note: VERBOSE is 0x1, ADDRESS_SPECIFIED is 0x2 */

#define GET_TOTALRAM_PAGES     (ADDRESS_SPECIFIED << 1)
#define GET_SHARED_PAGES       (ADDRESS_SPECIFIED << 2)
#define GET_FREE_PAGES         (ADDRESS_SPECIFIED << 3)
#define GET_FREE_HIGHMEM_PAGES (ADDRESS_SPECIFIED << 4)
#define GET_ZONE_SIZES         (ADDRESS_SPECIFIED << 5)
#define GET_HIGHEST            (ADDRESS_SPECIFIED << 6)
#define GET_BUFFERS_PAGES      (ADDRESS_SPECIFIED << 7)
#define GET_SLAB_PAGES         (ADDRESS_SPECIFIED << 8)
#define GET_PHYS_TO_VMALLOC    (ADDRESS_SPECIFIED << 9)
#define GET_ACTIVE_LIST        (ADDRESS_SPECIFIED << 10)
#define GET_INACTIVE_LIST      (ADDRESS_SPECIFIED << 11)
#define GET_INACTIVE_CLEAN     (ADDRESS_SPECIFIED << 12)  /* obsolete */
#define GET_INACTIVE_DIRTY     (ADDRESS_SPECIFIED << 13)  /* obsolete */
#define SLAB_GET_COUNTS        (ADDRESS_SPECIFIED << 14)
#define SLAB_WALKTHROUGH       (ADDRESS_SPECIFIED << 15)
#define GET_VMLIST_COUNT       (ADDRESS_SPECIFIED << 16)
#define GET_VMLIST             (ADDRESS_SPECIFIED << 17)
#define SLAB_DATA_NOSAVE       (ADDRESS_SPECIFIED << 18)
#define GET_SLUB_SLABS         (ADDRESS_SPECIFIED << 19)
#define GET_SLUB_OBJECTS       (ADDRESS_SPECIFIED << 20)
#define VMLIST_VERIFY          (ADDRESS_SPECIFIED << 21)
#define SLAB_FIRST_NODE        (ADDRESS_SPECIFIED << 22)
#define CACHE_SET              (ADDRESS_SPECIFIED << 23)
#define SLAB_OVERLOAD_PAGE_PTR (ADDRESS_SPECIFIED << 24)
#define SLAB_BITFIELD          (ADDRESS_SPECIFIED << 25)
#define SLAB_GATHER_FAILURE    (ADDRESS_SPECIFIED << 26)
#define GET_SLAB_ROOT_CACHES   (ADDRESS_SPECIFIED << 27)

#define GET_ALL \
	(GET_SHARED_PAGES|GET_TOTALRAM_PAGES|GET_BUFFERS_PAGES|GET_SLAB_PAGES)

void
cmd_kmem(void)
{
	int i;
	int c;
	int sflag, Sflag, pflag, fflag, Fflag, vflag, zflag, oflag, gflag; 
	int nflag, cflag, Cflag, iflag, lflag, Lflag, Pflag, Vflag, hflag;
	int rflag;
	struct meminfo meminfo;
	ulonglong value[MAXARGS];
	char buf[BUFSIZE];
	char arg_buf[BUFSIZE];
	char *p1;
	ulong *cpus;
	int spec_addr, escape, choose_cpu;

	cpus = NULL;
	spec_addr = choose_cpu = 0;
        sflag =	Sflag = pflag = fflag = Fflag = Pflag = zflag = oflag = 0;
	vflag = Cflag = cflag = iflag = nflag = lflag = Lflag = Vflag = 0;
	gflag = hflag = rflag = 0;
	escape = FALSE;
	BZERO(&meminfo, sizeof(struct meminfo));
	BZERO(&value[0], sizeof(ulonglong)*MAXARGS);
	pc->curcmd_flags &= ~HEADER_PRINTED;

        while ((c = getopt(argcnt, args, "gI:sS::rFfm:pvczCinl:L:PVoh")) != EOF) {
                switch(c)
		{
		case 'V':
			Vflag = 1;
			break;

		case 'n':
			nflag = 1;
			break;

		case 'z':
			zflag = 1;
			break;

		case 'i': 
			iflag = 1;
			break;

		case 'h': 
			hflag = 1;
			break;

		case 'C':
			Cflag = 1, cflag = 0;;
			break;

		case 'c':
			cflag = 1, Cflag = 0;
			break;

		case 'v':
			vflag = 1;
			break;

		case 's':
			sflag = 1; Sflag = rflag = 0;
			break;

		case 'S':
			if (choose_cpu)
				error(FATAL, "only one -S option allowed\n");
			/* Use the GNU extension with getopt(3) ... */
			if (optarg) {
				if (!(vt->flags & KMALLOC_SLUB))
					error(FATAL,
						"can only use -S=cpu(s) with a kernel \n"
						"that is built with CONFIG_SLUB support.\n");
				if (optarg[0] != '=')
					error(FATAL,
						"CPU-specific slab data to be displayed "
						"must be written as expected only e.g. -S=1,45.\n");
				/* Skip = ... */
				optarg++;

				choose_cpu = 1;
				BZERO(arg_buf, BUFSIZE);
				strcpy(arg_buf, optarg);

				cpus = get_cpumask_buf();
				make_cpumask(arg_buf, cpus, FAULT_ON_ERROR, NULL);
				meminfo.spec_cpumask = cpus;
			}
			Sflag = 1; sflag = rflag = 0;
			break;

		case 'r':
			rflag = 1; sflag = Sflag = 0;
			break;

		case 'F':
			Fflag = 1; fflag = 0;
			break;;

		case 'f':
			fflag = 1; Fflag = 0;
			break;;

		case 'p':
			pflag = 1;
			break;

		case 'm':
			pflag = 1;
			collect_page_member_data(optarg, &meminfo);
			break;

		case 'I':
			meminfo.ignore = optarg;
			break;	

		case 'l':
			if (STREQ(optarg, "a")) {
				meminfo.flags |= GET_ACTIVE_LIST;
				lflag = 1; Lflag = 0;
                        } else if (STREQ(optarg, "i")) { 
                                meminfo.flags |= GET_INACTIVE_LIST;
                                lflag = 1; Lflag = 0;
			} else if (STREQ(optarg, "ic")) {
				meminfo.flags |= GET_INACTIVE_CLEAN;
				lflag = 1; Lflag = 0;
			} else if (STREQ(optarg, "id")) {
				meminfo.flags |= GET_INACTIVE_DIRTY;
				lflag = 1; Lflag = 0;
			} else
				argerrs++;
			break;

                case 'L':
                        if (STREQ(optarg, "a")) {
                                meminfo.flags |= GET_ACTIVE_LIST;
                                Lflag = 1; lflag = 0;
			} else if (STREQ(optarg, "i")) {
                                meminfo.flags |= GET_INACTIVE_LIST;
                                Lflag = 1; lflag = 0;
                        } else if (STREQ(optarg, "ic")) {
                                meminfo.flags |= GET_INACTIVE_CLEAN;
                                Lflag = 1; lflag = 0;
                        } else if (STREQ(optarg, "id")) {
                                meminfo.flags |= GET_INACTIVE_DIRTY;
                                Lflag = 1; lflag = 0;
                        } else
                                argerrs++;
                        break;

		case 'P':
			Pflag = 1;
			break;

		case 'o':
			oflag = 1;
			break;

		case 'g':
			gflag = 1;
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

        if ((sflag + Sflag + pflag + fflag + Fflag + Vflag + oflag +
            vflag + Cflag + cflag + iflag + lflag + Lflag + gflag +
            hflag + rflag) > 1) {
		error(INFO, "only one flag allowed!\n");
		cmd_usage(pc->curcmd, SYNOPSIS);
	} 

	if (sflag || Sflag || rflag || !(vt->flags & KMEM_CACHE_INIT))
		kmem_cache_init();

	while (args[optind]) {
                if (hexadecimal(args[optind], 0)) {
                        value[spec_addr++] = 
				htoll(args[optind], FAULT_ON_ERROR, NULL);
                } else {
		        if (meminfo.reqname)
                                error(FATAL,
                                  "only one kmem_cache reference is allowed\n");
                        meminfo.reqname = args[optind];
			if (args[optind][0] == '\\') {
				meminfo.reqname = &args[optind][1]; 
				escape = TRUE;
			} else
				meminfo.reqname = args[optind];
                        if (!sflag && !Sflag && !rflag)
                                cmd_usage(pc->curcmd, SYNOPSIS);
                }

		optind++;
	}

	for (i = 0; i < spec_addr; i++) {

		if (Pflag) 
			meminfo.memtype = PHYSADDR;
		else 
			meminfo.memtype = IS_KVADDR(value[i]) ? 
				KVADDR : PHYSADDR;

               	if (fflag) {
                        meminfo.spec_addr = value[i];
                        meminfo.flags = ADDRESS_SPECIFIED;
                        if (meminfo.calls++)
                                fprintf(fp, "\n");
                        vt->dump_free_pages(&meminfo);
                        fflag++;
                }

                if (pflag) {
			meminfo.spec_addr = value[i];
			meminfo.flags = ADDRESS_SPECIFIED;
                        dump_mem_map(&meminfo);
                        pflag++;
                }

                if (sflag || Sflag) {
        		if (vt->flags & KMEM_CACHE_UNAVAIL) 
                		error(FATAL, 
				   "kmem cache slab subsystem not available\n");
 
			meminfo.flags = Sflag ? VERBOSE : 0;

			if (meminfo.memtype == PHYSADDR) {
                          	if (value[i] < VTOP(vt->high_memory)) {
                        		value[i] = PTOV(value[i]);
					meminfo.memtype = KVADDR;
				} else
                			error(WARNING,
                    	   "cannot make virtual-to-physical translation: %llx\n",
                        			value[i]);
			}
			
			if ((p1 = is_kmem_cache_addr(value[i], buf))) {
				if (meminfo.reqname)
					error(FATAL, 
				  "only one kmem_cache reference is allowed\n");
				meminfo.reqname = p1;
				meminfo.cache = value[i];
				meminfo.flags |= CACHE_SET;
                        	if ((i+1) == spec_addr) { /* done? */ 
					if (meminfo.calls++)
						fprintf(fp, "\n");
                        		vt->dump_kmem_cache(&meminfo);
				}
				meminfo.flags &= ~CACHE_SET;
			} else {
                        	meminfo.spec_addr = value[i];
                        	meminfo.flags = ADDRESS_SPECIFIED;
				if (Sflag && (vt->flags & KMALLOC_SLUB))
					meminfo.flags |= VERBOSE;
				if (meminfo.calls++)
					fprintf(fp, "\n");
                        	vt->dump_kmem_cache(&meminfo);
			}

			if (sflag)
                        	sflag++;
			if (Sflag)
				Sflag++;
                }

                if (vflag) {
			meminfo.spec_addr = value[i];
			meminfo.flags = ADDRESS_SPECIFIED; 
                        dump_vmlist(&meminfo);
                        vflag++;
                }

                if (cflag) {
			meminfo.spec_addr = value[i];
			meminfo.flags = ADDRESS_SPECIFIED; 
			if (meminfo.calls++)
				fprintf(fp, "\n");
                        dump_page_hash_table(&meminfo);
                        cflag++;
                }

                if (lflag) {
                        meminfo.spec_addr = value[i];
                        meminfo.flags |= (ADDRESS_SPECIFIED|VERBOSE);
                        if (meminfo.calls++)
                                fprintf(fp, "\n");
                        dump_page_lists(&meminfo);
                        lflag++;
                }

		if (gflag) {
			if (i)
                                fprintf(fp, "\n");
			dump_page_flags(value[i]);
			gflag++;
		}

                /* 
                 * no value arguments allowed! 
                 */
                if (zflag || nflag || iflag || Fflag || Cflag || Lflag || 
		    Vflag || oflag || hflag || rflag) {
			error(INFO, 
			    "no address arguments allowed with this option\n");
                        cmd_usage(pc->curcmd, SYNOPSIS);
		}

        	if (!(sflag + Sflag + pflag + fflag + vflag + cflag + 
		      lflag + Lflag + gflag)) {
			meminfo.spec_addr = value[i];
                        meminfo.flags = ADDRESS_SPECIFIED;
                        if (meminfo.calls++)
                                fprintf(fp, "\n");
			else
				kmem_cache_init();   
                        kmem_search(&meminfo);
		}

	}

	if (iflag == 1)
		dump_kmeminfo();

	if (pflag == 1)
		dump_mem_map(&meminfo);

	if (fflag == 1)
		vt->dump_free_pages(&meminfo);

	if (Fflag == 1) {
		meminfo.flags = VERBOSE;
		vt->dump_free_pages(&meminfo);
	}

	if (hflag == 1) 
		dump_hstates();

	if (sflag == 1 || rflag == 1) {
		if (rflag) {
			if (!((vt->flags & KMALLOC_SLUB)
			    && (vt->flags & SLAB_ROOT_CACHES)))
				option_not_supported('r');
			meminfo.flags = GET_SLAB_ROOT_CACHES;
		}
		if (!escape && STREQ(meminfo.reqname, "list"))
			kmem_cache_list(&meminfo);
                else if (vt->flags & KMEM_CACHE_UNAVAIL)
                     	error(FATAL, 
			    "kmem cache slab subsystem not available\n");
		else
			vt->dump_kmem_cache(&meminfo);
	}

	if (Sflag == 1) {
		if (STREQ(meminfo.reqname, "list"))
			kmem_cache_list(&meminfo);
                else if (vt->flags & KMEM_CACHE_UNAVAIL)
                     	error(FATAL, 
			    "kmem cache slab subsystem not available\n");
		else {
			meminfo.flags = VERBOSE;
			vt->dump_kmem_cache(&meminfo);
		}
		if (choose_cpu)
			FREEBUF(cpus);
	}

	if (vflag == 1)
		dump_vmlist(&meminfo);

	if (Cflag == 1) {
		meminfo.flags = VERBOSE;
		dump_page_hash_table(&meminfo);
	}

	if (cflag == 1)
		dump_page_hash_table(&meminfo);

	if (nflag == 1)
		dump_memory_nodes(MEMORY_NODES_DUMP);

	if (zflag == 1)
		dump_zone_stats();

	if (lflag == 1) { 
		dump_page_lists(&meminfo);
	}

	if (Lflag == 1) {
		meminfo.flags |= VERBOSE;
		dump_page_lists(&meminfo);
	}

	if (Vflag == 1) {
		dump_vm_stat(NULL, NULL, 0);
		dump_page_states();
		dump_vm_event_state();
	}

	if (oflag == 1)
		dump_per_cpu_offsets();

	if (gflag == 1)
		dump_page_flags(0);

	if (!(sflag + Sflag + pflag + fflag + Fflag + vflag + 
	      Vflag + zflag + oflag + cflag + Cflag + iflag + 
	      nflag + lflag + Lflag + gflag + hflag + rflag +
	      meminfo.calls))
		cmd_usage(pc->curcmd, SYNOPSIS);

}

static void
PG_reserved_flag_init(void)
{
	ulong pageptr;
	int count;
	ulong vaddr, flags;
	char *buf;

	if (enumerator_value("PG_reserved", (long *)&flags)) {
		vt->PG_reserved = 1 << flags;
		if (CRASHDEBUG(2))
			fprintf(fp, "PG_reserved (enum): %lx\n", vt->PG_reserved);
		return;
	}

	vaddr = kt->stext;
	if (!vaddr) {
		if (kernel_symbol_exists("sys_read"))
			vaddr = symbol_value("sys_read");
		else if (kernel_symbol_exists("__x64_sys_read"))
			vaddr = symbol_value("__x64_sys_read");
	}

	if (!phys_to_page((physaddr_t)VTOP(vaddr), &pageptr))
		return;

	buf = (char *)GETBUF(SIZE(page));

	if (!readmem(pageptr, KVADDR, buf, SIZE(page),
            "reserved page", RETURN_ON_ERROR|QUIET)) {
		FREEBUF(buf);
		return;
	}

	flags = ULONG(buf + OFFSET(page_flags));
	count = INT(buf + OFFSET(page_count));

	if (count_bits_long(flags) == 1)
		vt->PG_reserved = flags;
	else
		vt->PG_reserved = 1 << (ffsl(flags)-1);

	if (count == -1)
		vt->flags |= PGCNT_ADJ;

	if (CRASHDEBUG(2))
		fprintf(fp, 
		    "PG_reserved: vaddr: %lx page: %lx flags: %lx => %lx\n",
			vaddr, pageptr, flags, vt->PG_reserved);

	FREEBUF(buf);
}

static void 
PG_slab_flag_init(void)
{
	int bit;
        ulong pageptr;
        ulong vaddr, flags, flags2;
        char buf[BUFSIZE];  /* safe for a page struct */

	/*
	 *  Set the old defaults in case all else fails.
	 */
	if (enumerator_value("PG_slab", (long *)&flags)) {
		vt->PG_slab = flags;
		if (CRASHDEBUG(2))
			fprintf(fp, "PG_slab (enum): %lx\n", vt->PG_slab);
	} else if (VALID_MEMBER(page_pte)) {
                if (THIS_KERNEL_VERSION < LINUX(2,6,0))
                        vt->PG_slab = 10;
                else if (THIS_KERNEL_VERSION >= LINUX(2,6,0))
                        vt->PG_slab = 7;
        } else if (THIS_KERNEL_VERSION >= LINUX(2,6,0)) {
		vt->PG_slab = 7;
	} else {
		if (try_get_symbol_data("vm_area_cachep", sizeof(void *), &vaddr) &&
            	    phys_to_page((physaddr_t)VTOP(vaddr), &pageptr) &&
                    readmem(pageptr, KVADDR, buf, SIZE(page),
		    "vm_area_cachep page", RETURN_ON_ERROR|QUIET)) {

			flags = ULONG(buf + OFFSET(page_flags));

			if ((bit = ffsl(flags))) {
				vt->PG_slab = bit - 1;
	
				if (CRASHDEBUG(2))
					fprintf(fp,
			"PG_slab bit: vaddr: %lx page: %lx flags: %lx => %ld\n",
					vaddr, pageptr, flags, vt->PG_slab);
			}
		}
	}

	if (VALID_MEMBER(page_compound_head)) {
		if (CRASHDEBUG(2))
			fprintf(fp, 
			    "PG_head_tail_mask: (UNUSED): page.compound_head exists!\n");
	} else if (vt->flags & KMALLOC_SLUB) {
		/* 
		 *  PG_slab and the following are hardwired for 
		 *  kernels prior to the pageflags enumerator.
		 */
#define PG_compound             14      /* Part of a compound page */
#define PG_reclaim              17      /* To be reclaimed asap */
		vt->PG_head_tail_mask = ((1L << PG_compound) | (1L << PG_reclaim));

		if (enumerator_value("PG_tail", (long *)&flags))
			vt->PG_head_tail_mask = (1L << flags);
		else if (enumerator_value("PG_compound", (long *)&flags) &&
		    	 enumerator_value("PG_reclaim", (long *)&flags2)) {
			vt->PG_head_tail_mask = ((1L << flags) | (1L << flags2));
	       		if (CRASHDEBUG(2))
				fprintf(fp, "PG_head_tail_mask: %lx\n", 
					vt->PG_head_tail_mask);
		} else if (vt->flags & PAGEFLAGS) {
			vt->PG_head_tail_mask = 0;
			error(WARNING, 
				"SLUB: cannot determine how compound pages are linked\n\n");
		}
	} else {
		if (enumerator_value("PG_tail", (long *)&flags))
			vt->PG_head_tail_mask = (1L << flags);
		else if (enumerator_value("PG_compound", (long *)&flags) &&
		    enumerator_value("PG_reclaim", (long *)&flags2)) {
			vt->PG_head_tail_mask = ((1L << flags) | (1L << flags2));
	       		if (CRASHDEBUG(2))
				fprintf(fp, "PG_head_tail_mask: %lx (PG_compound|PG_reclaim)\n", 
					vt->PG_head_tail_mask);
		} else if (vt->flags & PAGEFLAGS) 
			error(WARNING, 
				"SLAB: cannot determine how compound pages are linked\n\n");
	}

	if (!vt->PG_slab)
		error(INFO, "cannot determine PG_slab bit value\n");	
}

/*
 *  dump_mem_map() displays basic data about each entry in the mem_map[]
 *  array, or if an address is specified, just the mem_map[] entry for that
 *  address.  Specified addresses can either be physical address or page
 *  structure pointers.
 */

/* Page flag bit values */
#define v22_PG_locked                0
#define v22_PG_error                 1
#define v22_PG_referenced            2
#define v22_PG_dirty                 3
#define v22_PG_uptodate              4
#define v22_PG_free_after            5
#define v22_PG_decr_after            6
#define v22_PG_swap_unlock_after     7
#define v22_PG_DMA                   8
#define v22_PG_Slab                  9
#define v22_PG_swap_cache           10
#define v22_PG_skip                 11
#define v22_PG_reserved             31

#define v24_PG_locked                0
#define v24_PG_error                 1
#define v24_PG_referenced            2
#define v24_PG_uptodate              3
#define v24_PG_dirty                 4
#define v24_PG_decr_after            5
#define v24_PG_active                6
#define v24_PG_inactive_dirty        7
#define v24_PG_slab                  8
#define v24_PG_swap_cache            9
#define v24_PG_skip                 10
#define v24_PG_inactive_clean       11
#define v24_PG_highmem              12
#define v24_PG_checked              13      /* kill me in 2.5.<early>. */
#define v24_PG_bigpage              14
                                /* bits 21-30 unused */
#define v24_PG_arch_1               30
#define v24_PG_reserved             31

#define v26_PG_private              12

#define PGMM_CACHED (512)

static void
dump_mem_map_SPARSEMEM(struct meminfo *mi)
{
	ulong i;
	long total_pages;
	int others, page_not_mapped, phys_not_mapped, page_mapping;
	ulong pp, ppend;
	physaddr_t phys, physend;
	ulong tmp, reserved, shared, slabs;
        ulong PG_reserved_flag;
	long buffers;
	ulong inode, offset, flags, mapping, index;
	uint count;
	int print_hdr, pg_spec, phys_spec, done;
	int v22;
	char hdr[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char *page_cache;
	char *pcache;
	ulong section, section_nr, nr_mem_sections, section_size;
	long buffersize;
	char *outputbuffer;
	int bufferindex;

	buffersize = 1024 * 1024;
	outputbuffer = GETBUF(buffersize + 512);

	char style1[100];
	char style2[100];
	char style3[100];
	char style4[100];

	sprintf((char *)&style1, "%%lx%s%%%dllx%s%%%dlx%s%%8lx %%2d%s",
			space(MINSPACE),
			(int)MAX(PADDR_PRLEN, strlen("PHYSICAL")),
			space(MINSPACE),
			VADDR_PRLEN,
			space(MINSPACE),
			space(MINSPACE));
	sprintf((char *)&style2, "%%-%dlx%s%%%dllx%s%s%s%s %2s ",
			VADDR_PRLEN,
			space(MINSPACE),
			(int)MAX(PADDR_PRLEN, strlen("PHYSICAL")),
			space(MINSPACE),
			mkstring(buf3, VADDR_PRLEN, CENTER|RJUST, " "),
			space(MINSPACE),
			mkstring(buf4, 8, CENTER|RJUST, " "),
			" ");
	sprintf((char *)&style3, "%%-%dlx%s%%%dllx%s%s%s%s %%2d ",
			VADDR_PRLEN,
			space(MINSPACE),
			(int)MAX(PADDR_PRLEN, strlen("PHYSICAL")),
			space(MINSPACE),
			mkstring(buf3, VADDR_PRLEN, CENTER|RJUST, "-------"),
			space(MINSPACE),
			mkstring(buf4, 8, CENTER|RJUST, "-----"));
	sprintf((char *)&style4, "%%-%dlx%s%%%dllx%s%%%dlx%s%%8lx %%2d ",
			VADDR_PRLEN,
			space(MINSPACE),
			(int)MAX(PADDR_PRLEN, strlen("PHYSICAL")),
			space(MINSPACE),
			VADDR_PRLEN,
			space(MINSPACE));

	v22 = VALID_MEMBER(page_inode);  /* page.inode vs. page.mapping */

        if (v22) {
		sprintf(hdr, "%s%s%s%s%s%s%s%sCNT FLAGS\n",
		    mkstring(buf1, VADDR_PRLEN, CENTER, "PAGE"), 
		    space(MINSPACE),               
                    mkstring(buf2, MAX(PADDR_PRLEN, strlen("PHYSICAL")),
			RJUST, "PHYSICAL"),		    
		    space(MINSPACE),               
		    mkstring(buf3, VADDR_PRLEN, CENTER|RJUST, "INODE"), 
		    space(MINSPACE),               
		    mkstring(buf4, 8, CENTER|LJUST, "OFFSET"),
		    space(MINSPACE-1));
	} else if (mi->nr_members) {
		sprintf(hdr, "%s", mkstring(buf1, VADDR_PRLEN, CENTER, "PAGE"));
		for (i = 0; i < mi->nr_members; i++)
			sprintf(&hdr[strlen(hdr)], "  %s", 
				mi->page_member_cache[i].member);
		strcat(hdr, "\n");
	} else {
		sprintf(hdr, "%s%s%s%s%s%s%sCNT FLAGS\n",
		    mkstring(buf1, VADDR_PRLEN, CENTER, "PAGE"), 
		    space(MINSPACE),             
                    mkstring(buf2, MAX(PADDR_PRLEN, strlen("PHYSICAL")),
                        RJUST, "PHYSICAL"),
		    space(MINSPACE),             
		    mkstring(buf3, VADDR_PRLEN, CENTER|RJUST, "MAPPING"),
		    space(MINSPACE),               
		    mkstring(buf4, 8, CENTER|RJUST, "INDEX"));
        }

	mapping = index = 0;
	reserved = shared = slabs = buffers = inode = offset = 0;
	pg_spec = phys_spec = print_hdr = FALSE;

	switch (mi->flags)
	{
	case ADDRESS_SPECIFIED: 
		switch (mi->memtype)
		{
		case KVADDR:
                        if (is_page_ptr(mi->spec_addr, NULL))
                                pg_spec = TRUE;
                        else {
                                if (kvtop(NULL, mi->spec_addr, &phys, 0)) {
                                        mi->spec_addr = phys;
                                        phys_spec = TRUE;
                                }
                                else
                                        return;
                        }
			break;
		case PHYSADDR:
			phys_spec = TRUE;
			break;
		default:
			error(FATAL, "dump_mem_map: no memtype specified\n");
			break;
		}
		print_hdr = TRUE;
		break;

	case GET_ALL:
		shared = 0;
                reserved = 0;
		buffers = 0;
		slabs = 0;
		break;

	case GET_SHARED_PAGES:
		shared = 0;
		break;

	case GET_TOTALRAM_PAGES:
                reserved = 0;
		break;

	case GET_BUFFERS_PAGES:
		buffers = 0;
		break;

	case GET_SLAB_PAGES:
		slabs = 0;
		break;

	default:
		print_hdr = TRUE;
		break;
	}

	page_cache = GETBUF(SIZE(page) * PGMM_CACHED);
	done = FALSE;
	total_pages = 0;

	nr_mem_sections = NR_MEM_SECTIONS();

	bufferindex = 0;

	/* 
	 *  Iterate over all possible sections
	 */
        for (section_nr = 0; section_nr < nr_mem_sections ; section_nr++) {

		if (CRASHDEBUG(2)) 
			fprintf(fp, "section_nr = %ld\n", section_nr);

		/* 
		 *  If we are looking up a specific address, jump directly
		 *  to the section with that page 
		 */
		if (mi->flags & ADDRESS_SPECIFIED) {        
			ulong pfn;
			physaddr_t tmp;

			if (pg_spec) {
				if (!page_to_phys(mi->spec_addr, &tmp))
					return;
				pfn = tmp >> PAGESHIFT();
			} else
				pfn = mi->spec_addr >> PAGESHIFT();
			section_nr = pfn_to_section_nr(pfn);
		}

                if (!(section = valid_section_nr(section_nr))) {
#ifdef NOTDEF
                        break;    /* On a real sparsemem system we need to check
				   * every section as gaps may exist.  But this
				   * can be slow.  If we know we don't have gaps
				   * just stop validating sections when we 
				   * get to the end of the valid ones.  
				   * In the future find a way to short circuit
				   * this loop.
				   */
#endif
			if (mi->flags & ADDRESS_SPECIFIED)
				break;
			continue;
		}

		if (print_hdr) {
			if (!(pc->curcmd_flags & HEADER_PRINTED))
				fprintf(fp, "%s", hdr);
			print_hdr = FALSE;
			pc->curcmd_flags |= HEADER_PRINTED;
		}

		pp = section_mem_map_addr(section, 0);
		pp = sparse_decode_mem_map(pp, section_nr);
		phys = (physaddr_t) section_nr * PAGES_PER_SECTION() * PAGESIZE();
		section_size = PAGES_PER_SECTION();

		for (i = 0; i < section_size; 
		     i++, pp += SIZE(page), phys += PAGESIZE()) {

			if ((i % PGMM_CACHED) == 0) {

				ppend = pp + ((PGMM_CACHED-1) * SIZE(page));
				physend = phys + ((PGMM_CACHED-1) * PAGESIZE());

				if ((pg_spec && (mi->spec_addr > ppend)) ||
			            (phys_spec && 
				    (PHYSPAGEBASE(mi->spec_addr) > physend))) {
					i += (PGMM_CACHED-1);
					pp = ppend;
					phys = physend;
					continue;
				}  

				fill_mem_map_cache(pp, ppend, page_cache);
			}

			pcache = page_cache + ((i%PGMM_CACHED) * SIZE(page));

			if (received_SIGINT())
				restart(0);
	
			if ((pg_spec && (pp == mi->spec_addr)) || 
			   (phys_spec && (phys == PHYSPAGEBASE(mi->spec_addr))))
				done = TRUE;

			if (!done && (pg_spec || phys_spec))
				continue;

			if (mi->nr_members) {
				bufferindex += show_page_member_data(pcache, pp, mi, outputbuffer+bufferindex);
				goto display_members;
			}
			
			flags = ULONG(pcache + OFFSET(page_flags));
			if (SIZE(page_flags) == 4)
				flags &= 0xffffffff;
			count = UINT(pcache + OFFSET(page_count));

	                switch (mi->flags)
			{
			case GET_ALL:
			case GET_BUFFERS_PAGES:
				if (VALID_MEMBER(page_buffers)) {
					tmp = ULONG(pcache + 
						OFFSET(page_buffers));
					if (tmp)
						buffers++;
				} else if (THIS_KERNEL_VERSION >= LINUX(2,6,0)) {
	                                if ((flags >> v26_PG_private) & 1) 
						buffers++;
				} else
					error(FATAL, 
			       "cannot determine whether pages have buffers\n");

				if (mi->flags != GET_ALL)
					continue;

				/* FALLTHROUGH */

			case GET_SLAB_PAGES:
				if (v22) {
	                                if ((flags >> v22_PG_Slab) & 1) 
						slabs++;
				} else if (vt->PG_slab) {
	                                if ((flags >> vt->PG_slab) & 1) 
						slabs++;
				} else {
	                                if ((flags >> v24_PG_slab) & 1) 
						slabs++;
				}
				if (mi->flags != GET_ALL)
					continue;

				/* FALLTHROUGH */

			case GET_SHARED_PAGES:
			case GET_TOTALRAM_PAGES:
                                if (vt->PG_reserved)
					PG_reserved_flag = vt->PG_reserved;
				else
                                        PG_reserved_flag = v22 ?
                                                1 << v22_PG_reserved :
                                                1 << v24_PG_reserved;

	                        if (flags & PG_reserved_flag) {
	                                reserved++;
				} else {
					if ((int)count > 
					    (vt->flags & PGCNT_ADJ ? 0 : 1))
						shared++;
				}
	                        continue;
	                }
			page_mapping = VALID_MEMBER(page_mapping);
	
			if (v22) {
				inode = ULONG(pcache + OFFSET(page_inode));
				offset = ULONG(pcache + OFFSET(page_offset));
			} else if (page_mapping) { 
				mapping = ULONG(pcache + 
					OFFSET(page_mapping));
				index = ULONG(pcache + OFFSET(page_index));
			}
	
			page_not_mapped = phys_not_mapped = FALSE;

			if (v22) {
				bufferindex += sprintf(outputbuffer+bufferindex,
						(char *)&style1, pp, phys, inode,
						offset, count);
			} else {
				if ((vt->flags & V_MEM_MAP)) {
				    	if (!machdep->verify_paddr(phys)) 
						phys_not_mapped = TRUE;
					if (!kvtop(NULL, pp, NULL, 0))
						page_not_mapped = TRUE;
				}
				if (page_not_mapped)
					bufferindex += sprintf(outputbuffer+bufferindex,
							(char *)&style2, pp, phys);
				else if (!page_mapping)
					bufferindex += sprintf(outputbuffer+bufferindex,
							(char *)&style3, pp, phys, count);
				else
					bufferindex += sprintf(outputbuffer+bufferindex,
							(char *)&style4, pp, phys,
							mapping, index, count);
			}
	
			others = 0;
	
#define sprintflag(X) sprintf(outputbuffer + bufferindex, X, others++ ? "," : "")

			if (v22) {
		                if ((flags >> v22_PG_DMA) & 1)
					bufferindex += sprintflag("%sDMA");
				if ((flags >> v22_PG_locked) & 1)
					bufferindex += sprintflag("%slocked");
				if ((flags >> v22_PG_error) & 1)
					bufferindex += sprintflag("%serror");
				if ((flags >> v22_PG_referenced) & 1)
					bufferindex += sprintflag("%sreferenced");
				if ((flags >> v22_PG_dirty) & 1)
					bufferindex += sprintflag("%sdirty");
				if ((flags >> v22_PG_uptodate) & 1)
					bufferindex += sprintflag("%suptodate");
				if ((flags >> v22_PG_free_after) & 1)
					bufferindex += sprintflag("%sfree_after");
				if ((flags >> v22_PG_decr_after) & 1)
					bufferindex += sprintflag("%sdecr_after");
				if ((flags >> v22_PG_swap_unlock_after) & 1)
					bufferindex += sprintflag("%sswap_unlock_after");
				if ((flags >> v22_PG_Slab) & 1)
					bufferindex += sprintflag("%sslab");
				if ((flags >> v22_PG_swap_cache) & 1)
					bufferindex += sprintflag("%sswap_cache");
				if ((flags >> v22_PG_skip) & 1)
					bufferindex += sprintflag("%sskip");
	                        if ((flags >> v22_PG_reserved) & 1)
					bufferindex += sprintflag("%sreserved");
				bufferindex += sprintf(outputbuffer+bufferindex, "\n");
			} else if (THIS_KERNEL_VERSION > LINUX(2,4,9)) {
				if (vt->flags & PAGEFLAGS)
					bufferindex += translate_page_flags(outputbuffer+bufferindex, flags);
				else
					bufferindex += sprintf(outputbuffer+bufferindex, "%lx\n", flags);
			} else {
	
		                if ((flags >> v24_PG_locked) & 1)
					bufferindex += sprintflag("%slocked");
				if ((flags >> v24_PG_error) & 1)
					bufferindex += sprintflag("%serror");
				if ((flags >> v24_PG_referenced) & 1)
					bufferindex += sprintflag("%sreferenced");
				if ((flags >> v24_PG_uptodate) & 1)
					bufferindex += sprintflag("%suptodate");
                                if ((flags >> v24_PG_dirty) & 1)
					bufferindex += sprintflag("%sdirty");
				if ((flags >> v24_PG_decr_after) & 1)
					bufferindex += sprintflag("%sdecr_after");
                                if ((flags >> v24_PG_active) & 1)
					bufferindex += sprintflag("%sactive");
                                if ((flags >> v24_PG_inactive_dirty) & 1)
					bufferindex += sprintflag("%sinactive_dirty");
				if ((flags >> v24_PG_slab) & 1)
					bufferindex += sprintflag("%sslab");
				if ((flags >> v24_PG_swap_cache) & 1)
					bufferindex += sprintflag("%sswap_cache");
				if ((flags >> v24_PG_skip) & 1)
					bufferindex += sprintflag("%sskip");
				if ((flags >> v24_PG_inactive_clean) & 1)
					bufferindex += sprintflag("%sinactive_clean");
				if ((flags >> v24_PG_highmem) & 1)
					bufferindex += sprintflag("%shighmem");
				if ((flags >> v24_PG_checked) & 1)
					bufferindex += sprintflag("%schecked");
				if ((flags >> v24_PG_bigpage) & 1)
					bufferindex += sprintflag("%sbigpage");
                                if ((flags >> v24_PG_arch_1) & 1)
					bufferindex += sprintflag("%sarch_1");
				if ((flags >> v24_PG_reserved) & 1)
					bufferindex += sprintflag("%sreserved");
				if (phys_not_mapped)
					bufferindex += sprintflag("%s[NOT MAPPED]");

				bufferindex += sprintf(outputbuffer+bufferindex, "\n");
			}

display_members:
			if (bufferindex > buffersize) {
				fprintf(fp, "%s", outputbuffer);
				bufferindex = 0;
			}
	
			if (done)
				break;
		}

		if (done)
			break;
	}

	if (bufferindex > 0) {
		fprintf(fp, "%s", outputbuffer);
	}

	switch (mi->flags)
	{
	case GET_TOTALRAM_PAGES:
		mi->retval = total_pages - reserved;
		break;

	case GET_SHARED_PAGES:
		mi->retval = shared;
		break;

	case GET_BUFFERS_PAGES:
		mi->retval = buffers;
		break;

	case GET_SLAB_PAGES:
		mi->retval = slabs;
		break;

	case GET_ALL:
		mi->get_totalram = total_pages - reserved;
		mi->get_shared = shared;
		mi->get_buffers = buffers;
        	mi->get_slabs = slabs;
		break;

	case ADDRESS_SPECIFIED:
		mi->retval = done;
		break; 
	}

	if (mi->nr_members)
		FREEBUF(mi->page_member_cache);
	FREEBUF(outputbuffer);
	FREEBUF(page_cache);
}

static void
dump_mem_map(struct meminfo *mi)
{
	long i, n;
	long total_pages;
	int others, page_not_mapped, phys_not_mapped, page_mapping;
	ulong pp, ppend;
	physaddr_t phys, physend;
	ulong tmp, reserved, shared, slabs;
        ulong PG_reserved_flag;
	long buffers;
	ulong inode, offset, flags, mapping, index;
	ulong node_size;
	uint count;
	int print_hdr, pg_spec, phys_spec, done;
	int v22;
	struct node_table *nt;
	char hdr[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char *page_cache;
	char *pcache;
	long buffersize;
	char *outputbuffer;
	int bufferindex;
	char style1[100];
	char style2[100];
	char style3[100];
	char style4[100];

	if (IS_SPARSEMEM()) {
		dump_mem_map_SPARSEMEM(mi);
		return;
	}

	buffersize = 1024 * 1024;
	outputbuffer = GETBUF(buffersize + 512);

	sprintf((char *)&style1, "%%lx%s%%%dllx%s%%%dlx%s%%8lx %%2d%s",
			space(MINSPACE),
			(int)MAX(PADDR_PRLEN, strlen("PHYSICAL")),
			space(MINSPACE),
			VADDR_PRLEN,
			space(MINSPACE),
			space(MINSPACE));
	sprintf((char *)&style2, "%%-%dlx%s%%%dllx%s%s%s%s %2s ",
			VADDR_PRLEN,
			space(MINSPACE),
			(int)MAX(PADDR_PRLEN, strlen("PHYSICAL")),
			space(MINSPACE),
			mkstring(buf3, VADDR_PRLEN, CENTER|RJUST, " "),
			space(MINSPACE),
			mkstring(buf4, 8, CENTER|RJUST, " "),
			" ");
	sprintf((char *)&style3, "%%-%dlx%s%%%dllx%s%s%s%s %%2d ",
			VADDR_PRLEN,
			space(MINSPACE),
			(int)MAX(PADDR_PRLEN, strlen("PHYSICAL")),
			space(MINSPACE),
			mkstring(buf3, VADDR_PRLEN, CENTER|RJUST, "-------"),
			space(MINSPACE),
			mkstring(buf4, 8, CENTER|RJUST, "-----"));
	sprintf((char *)&style4, "%%-%dlx%s%%%dllx%s%%%dlx%s%%8lx %%2d ",
			VADDR_PRLEN,
			space(MINSPACE),
			(int)MAX(PADDR_PRLEN, strlen("PHYSICAL")),
			space(MINSPACE),
			VADDR_PRLEN,
			space(MINSPACE));

	v22 = VALID_MEMBER(page_inode);  /* page.inode vs. page.mapping */

        if (v22) {
		sprintf(hdr, "%s%s%s%s%s%s%s%sCNT FLAGS\n",
		    mkstring(buf1, VADDR_PRLEN, CENTER, "PAGE"), 
		    space(MINSPACE),               
                    mkstring(buf2, MAX(PADDR_PRLEN, strlen("PHYSICAL")),
			RJUST, "PHYSICAL"),		    
		    space(MINSPACE),               
		    mkstring(buf3, VADDR_PRLEN, CENTER|RJUST, "INODE"), 
		    space(MINSPACE),               
		    mkstring(buf4, 8, CENTER|LJUST, "OFFSET"),
		    space(MINSPACE-1));
	} else if (mi->nr_members) {
		sprintf(hdr, "%s", mkstring(buf1, VADDR_PRLEN, CENTER, "PAGE"));
		for (i = 0; i < mi->nr_members; i++)
			sprintf(&hdr[strlen(hdr)], "  %s", 
				mi->page_member_cache[i].member);
		strcat(hdr, "\n");
	} else {
		sprintf(hdr, "%s%s%s%s%s%s%sCNT FLAGS\n",
		    mkstring(buf1, VADDR_PRLEN, CENTER, "PAGE"), 
		    space(MINSPACE),             
                    mkstring(buf2, MAX(PADDR_PRLEN, strlen("PHYSICAL")),
                        RJUST, "PHYSICAL"),
		    space(MINSPACE),             
		    mkstring(buf3, VADDR_PRLEN, CENTER|RJUST, "MAPPING"),
		    space(MINSPACE),               
		    mkstring(buf4, 8, CENTER|RJUST, "INDEX"));
        }

	mapping = index = 0;
	reserved = shared = slabs = buffers = inode = offset = 0;
	pg_spec = phys_spec = print_hdr = FALSE;
	
	switch (mi->flags)
	{
	case ADDRESS_SPECIFIED: 
		switch (mi->memtype)
		{
		case KVADDR:
                        if (is_page_ptr(mi->spec_addr, NULL))
                                pg_spec = TRUE;
                        else {
                                if (kvtop(NULL, mi->spec_addr, &phys, 0)) {
                                        mi->spec_addr = phys;
                                        phys_spec = TRUE;
                                }
                                else
                                        return;
                        }
			break;
		case PHYSADDR:
			phys_spec = TRUE;
			break;
		default:
			error(FATAL, "dump_mem_map: no memtype specified\n");
			break;
		}
		print_hdr = TRUE;
		break;

	case GET_ALL:
		shared = 0;
                reserved = 0;
		buffers = 0;
		slabs = 0;
		break;

	case GET_SHARED_PAGES:
		shared = 0;
		break;

	case GET_TOTALRAM_PAGES:
                reserved = 0;
		break;

	case GET_BUFFERS_PAGES:
		buffers = 0;
		break;

	case GET_SLAB_PAGES:
		slabs = 0;
		break;

	default:
		print_hdr = TRUE;
		break;
	}

	page_cache = GETBUF(SIZE(page) * PGMM_CACHED);
	done = FALSE;
	total_pages = 0;

	bufferindex = 0;

	for (n = 0; n < vt->numnodes; n++) {
		if (print_hdr) {
			if (!(pc->curcmd_flags & HEADER_PRINTED))
				fprintf(fp, "%s%s", n ? "\n" : "", hdr);
			print_hdr = FALSE;
			pc->curcmd_flags |= HEADER_PRINTED;
		}

		nt = &vt->node_table[n];
		total_pages += nt->size;
		pp = nt->mem_map;
		phys = nt->start_paddr;
		if ((vt->flags & V_MEM_MAP) && (vt->numnodes == 1))
			node_size = vt->max_mapnr;
		else
			node_size = nt->size;

		for (i = 0; i < node_size; 
		     i++, pp += SIZE(page), phys += PAGESIZE()) {

			if ((i % PGMM_CACHED) == 0) {
				ppend = pp + ((PGMM_CACHED-1) * SIZE(page));
				physend = phys + ((PGMM_CACHED-1) * PAGESIZE());

				if ((pg_spec && (mi->spec_addr > ppend)) ||
			            (phys_spec && 
				    (PHYSPAGEBASE(mi->spec_addr) > physend))) {
					i += (PGMM_CACHED-1);
					pp = ppend;
					phys = physend;
					continue;
				}  

				fill_mem_map_cache(pp, ppend, page_cache);
			}

			pcache = page_cache + ((i%PGMM_CACHED) * SIZE(page));

			if (received_SIGINT())
				restart(0);
	
			if ((pg_spec && (pp == mi->spec_addr)) || 
			   (phys_spec && (phys == PHYSPAGEBASE(mi->spec_addr))))
				done = TRUE;

			if (!done && (pg_spec || phys_spec))
				continue;
			
			if (mi->nr_members) {
				bufferindex += show_page_member_data(pcache, pp, mi, outputbuffer+bufferindex);
				goto display_members;
			}

			flags = ULONG(pcache + OFFSET(page_flags));
			if (SIZE(page_flags) == 4)
				flags &= 0xffffffff;
			count = UINT(pcache + OFFSET(page_count));

	                switch (mi->flags)
			{
			case GET_ALL:
			case GET_BUFFERS_PAGES:
				if (VALID_MEMBER(page_buffers)) {
					tmp = ULONG(pcache + 
						OFFSET(page_buffers));
					if (tmp)
						buffers++;
				} else if (THIS_KERNEL_VERSION >= LINUX(2,6,0)) {
	                                if ((flags >> v26_PG_private) & 1) 
						buffers++;
				} else
					error(FATAL, 
			       "cannot determine whether pages have buffers\n");

				if (mi->flags != GET_ALL)
					continue;

				/* FALLTHROUGH */

			case GET_SLAB_PAGES:
				if (v22) {
	                                if ((flags >> v22_PG_Slab) & 1) 
						slabs++;
				} else if (vt->PG_slab) {
	                                if ((flags >> vt->PG_slab) & 1) 
						slabs++;
				} else {
	                                if ((flags >> v24_PG_slab) & 1) 
						slabs++;
				}
				if (mi->flags != GET_ALL)
					continue;

				/* FALLTHROUGH */

			case GET_SHARED_PAGES:
			case GET_TOTALRAM_PAGES:
                                if (vt->PG_reserved)
					PG_reserved_flag = vt->PG_reserved;
				else
                                        PG_reserved_flag = v22 ?
                                                1 << v22_PG_reserved :
                                                1 << v24_PG_reserved;

	                        if (flags & PG_reserved_flag) {
	                                reserved++;
				} else {
					if ((int)count >
					    (vt->flags & PGCNT_ADJ ? 0 : 1))
						shared++;
				}
	                        continue;
	                }
	
			page_mapping = VALID_MEMBER(page_mapping);

			if (v22) {
				inode = ULONG(pcache + OFFSET(page_inode));
				offset = ULONG(pcache + OFFSET(page_offset));
			} else if (page_mapping) {
				mapping = ULONG(pcache + 
					OFFSET(page_mapping));
				index = ULONG(pcache + OFFSET(page_index));
			}
	
			page_not_mapped = phys_not_mapped = FALSE;

			if (v22) {
				bufferindex += sprintf(outputbuffer+bufferindex,
						(char *)&style1, pp, phys, inode,
						offset, count);
			} else {
				if ((vt->flags & V_MEM_MAP)) {
				    	if (!machdep->verify_paddr(phys)) 
						phys_not_mapped = TRUE;
					if (!kvtop(NULL, pp, NULL, 0))
						page_not_mapped = TRUE;
				}
				if (page_not_mapped)
					bufferindex += sprintf(outputbuffer+bufferindex,
							(char *)&style2, pp, phys);
				else if (!page_mapping)
					bufferindex += sprintf(outputbuffer+bufferindex,
							(char *)&style3, pp, phys, count);
				else
					bufferindex += sprintf(outputbuffer+bufferindex,
							(char *)&style4, pp, phys,
							mapping, index, count);
			}
	
			others = 0;
	
#define sprintflag(X) sprintf(outputbuffer + bufferindex, X, others++ ? "," : "")

			if (v22) {
		                if ((flags >> v22_PG_DMA) & 1)
					bufferindex += sprintflag("%sDMA");
				if ((flags >> v22_PG_locked) & 1)
					bufferindex += sprintflag("%slocked");
				if ((flags >> v22_PG_error) & 1)
					bufferindex += sprintflag("%serror");
				if ((flags >> v22_PG_referenced) & 1)
					bufferindex += sprintflag("%sreferenced");
				if ((flags >> v22_PG_dirty) & 1)
					bufferindex += sprintflag("%sdirty");
				if ((flags >> v22_PG_uptodate) & 1)
					bufferindex += sprintflag("%suptodate");
				if ((flags >> v22_PG_free_after) & 1)
					bufferindex += sprintflag("%sfree_after");
				if ((flags >> v22_PG_decr_after) & 1)
					bufferindex += sprintflag("%sdecr_after");
				if ((flags >> v22_PG_swap_unlock_after) & 1)
					bufferindex += sprintflag("%sswap_unlock_after");
				if ((flags >> v22_PG_Slab) & 1)
					bufferindex += sprintflag("%sslab");
				if ((flags >> v22_PG_swap_cache) & 1)
					bufferindex += sprintflag("%sswap_cache");
				if ((flags >> v22_PG_skip) & 1)
					bufferindex += sprintflag("%sskip");
	                        if ((flags >> v22_PG_reserved) & 1)
					bufferindex += sprintflag("%sreserved");
				bufferindex += sprintf(outputbuffer+bufferindex, "\n");
			} else if (THIS_KERNEL_VERSION > LINUX(2,4,9)) {
				if (vt->flags & PAGEFLAGS)
					bufferindex += translate_page_flags(outputbuffer+bufferindex, flags);
				else
					bufferindex += sprintf(outputbuffer+bufferindex, "%lx\n", flags);
			} else {
	
		                if ((flags >> v24_PG_locked) & 1)
					bufferindex += sprintflag("%slocked");
				if ((flags >> v24_PG_error) & 1)
					bufferindex += sprintflag("%serror");
				if ((flags >> v24_PG_referenced) & 1)
					bufferindex += sprintflag("%sreferenced");
				if ((flags >> v24_PG_uptodate) & 1)
					bufferindex += sprintflag("%suptodate");
                                if ((flags >> v24_PG_dirty) & 1)
					bufferindex += sprintflag("%sdirty");
				if ((flags >> v24_PG_decr_after) & 1)
					bufferindex += sprintflag("%sdecr_after");
                                if ((flags >> v24_PG_active) & 1)
					bufferindex += sprintflag("%sactive");
                                if ((flags >> v24_PG_inactive_dirty) & 1)
					bufferindex += sprintflag("%sinactive_dirty");
				if ((flags >> v24_PG_slab) & 1)
					bufferindex += sprintflag("%sslab");
				if ((flags >> v24_PG_swap_cache) & 1)
					bufferindex += sprintflag("%sswap_cache");
				if ((flags >> v24_PG_skip) & 1)
					bufferindex += sprintflag("%sskip");
				if ((flags >> v24_PG_inactive_clean) & 1)
					bufferindex += sprintflag("%sinactive_clean");
				if ((flags >> v24_PG_highmem) & 1)
					bufferindex += sprintflag("%shighmem");
				if ((flags >> v24_PG_checked) & 1)
					bufferindex += sprintflag("%schecked");
				if ((flags >> v24_PG_bigpage) & 1)
					bufferindex += sprintflag("%sbigpage");
                                if ((flags >> v24_PG_arch_1) & 1)
					bufferindex += sprintflag("%sarch_1");
				if ((flags >> v24_PG_reserved) & 1)
					bufferindex += sprintflag("%sreserved");
				if (phys_not_mapped)
					bufferindex += sprintflag("%s[NOT MAPPED]");

				bufferindex += sprintf(outputbuffer+bufferindex, "\n");
			}
	
display_members:
			if (bufferindex > buffersize) {
				fprintf(fp, "%s", outputbuffer);
				bufferindex = 0;
			}

			if (done)
				break;
		}

		if (done)
			break;
	}

	if (bufferindex > 0) {
		fprintf(fp, "%s", outputbuffer);
	}

	switch (mi->flags)
	{
	case GET_TOTALRAM_PAGES:
		mi->retval = total_pages - reserved;
		break;

	case GET_SHARED_PAGES:
		mi->retval = shared;
		break;

	case GET_BUFFERS_PAGES:
		mi->retval = buffers;
		break;

	case GET_SLAB_PAGES:
		mi->retval = slabs;
		break;

	case GET_ALL:
		mi->get_totalram = total_pages - reserved;
		mi->get_shared = shared;
		mi->get_buffers = buffers;
        	mi->get_slabs = slabs;
		break;

	case ADDRESS_SPECIFIED:
		mi->retval = done;
		break; 
	}

	if (mi->nr_members)
		FREEBUF(mi->page_member_cache);
	FREEBUF(outputbuffer);
	FREEBUF(page_cache);
}

/*
 *  Stash a chunk of PGMM_CACHED page structures, starting at addr, into the
 *  passed-in buffer.  The mem_map array is normally guaranteed to be
 *  readable except in the case of virtual mem_map usage.  When V_MEM_MAP
 *  is in place, read all pages consumed by PGMM_CACHED page structures
 *  that are currently mapped, leaving the unmapped ones just zeroed out.
 */
static void
fill_mem_map_cache(ulong pp, ulong ppend, char *page_cache)
{
	long size, cnt;
	ulong addr;
        char *bufptr;

	/*
	 *  Try to read it in one fell swoop.
 	 */
	if (readmem(pp, KVADDR, page_cache, SIZE(page) * PGMM_CACHED,
      	    "page struct cache", RETURN_ON_ERROR|QUIET))
		return;

	/*
	 *  Break it into page-size-or-less requests, warning if it's
	 *  not a virtual mem_map.
	 */
        size = SIZE(page) * PGMM_CACHED;
        addr = pp;
        bufptr = page_cache;

        while (size > 0) {
		/* 
		 *  Compute bytes till end of page.
		 */
		cnt = PAGESIZE() - PAGEOFFSET(addr); 

                if (cnt > size)
                        cnt = size;

		if (!readmem(addr, KVADDR, bufptr, cnt,
                    "virtual page struct cache", RETURN_ON_ERROR|QUIET)) {
			BZERO(bufptr, cnt);
			if (!((vt->flags & V_MEM_MAP) || (machdep->flags & VMEMMAP)) && ((addr+cnt) < ppend))
				error(WARNING, 
		                   "mem_map[] from %lx to %lx not accessible\n",
					addr, addr+cnt);
		}

		addr += cnt;
                bufptr += cnt;
                size -= cnt;
        }
}

static void
dump_hstates()
{
	char *hstate;
	int i, len, order;
	long nr, free;
	ulong vaddr;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];

	if (!kernel_symbol_exists("hstates")) {
		error(INFO, "hstates[] array does not exist\n");
		option_not_supported('h');
	}

	if (INVALID_SIZE(hstate) ||
	    INVALID_MEMBER(hstate_order) ||
	    INVALID_MEMBER(hstate_name) ||
	    INVALID_MEMBER(hstate_nr_huge_pages) ||
	    INVALID_MEMBER(hstate_free_huge_pages)) {
		error(INFO, "hstate structure or members have changed\n");
		option_not_supported('h');
	}

	fprintf(fp, "%s", 
		mkstring(buf1, VADDR_PRLEN, CENTER, "HSTATE"));
	fprintf(fp, "   SIZE    FREE   TOTAL  NAME\n");

	len = get_array_length("hstates", NULL, 0);
	hstate = GETBUF(SIZE(hstate));

	for (i = 0; i < len; i++) {
		vaddr = symbol_value("hstates") + (SIZE(hstate) * i);
		if (!readmem(vaddr, KVADDR, hstate,
            	    SIZE(hstate), "hstate", RETURN_ON_ERROR))
			break;

		order = INT(hstate + OFFSET(hstate_order));
		if (!order)
			continue;

		fprintf(fp, "%lx  ", vaddr);

		pages_to_size(1 << order, buf1);
		shift_string_left(first_space(buf1), 1);
		fprintf(fp, "%s  ", mkstring(buf2, 5, RJUST, buf1));

		free = LONG(hstate + OFFSET(hstate_free_huge_pages));
		sprintf(buf1, "%ld", free);
		fprintf(fp, "%s  ", mkstring(buf2, 6, RJUST, buf1));

		nr = LONG(hstate + OFFSET(hstate_nr_huge_pages));
		sprintf(buf1, "%ld", nr);
		fprintf(fp, "%s  ", mkstring(buf2, 6, RJUST, buf1));

		fprintf(fp, "%s\n", hstate + OFFSET(hstate_name));
	}

	FREEBUF(hstate);
}


static void
page_flags_init(void)
{
	if (!page_flags_init_from_pageflag_names())
		page_flags_init_from_pageflags_enum();

	PG_reserved_flag_init();
	PG_slab_flag_init();
}

static int
page_flags_init_from_pageflag_names(void)
{
	int i, len;
	char *buffer, *nameptr;
	char namebuf[BUFSIZE];
	ulong mask;
	void *name;

	MEMBER_OFFSET_INIT(trace_print_flags_mask, "trace_print_flags", "mask");
	MEMBER_OFFSET_INIT(trace_print_flags_name, "trace_print_flags", "name");
	STRUCT_SIZE_INIT(trace_print_flags, "trace_print_flags");

	if (INVALID_SIZE(trace_print_flags) ||
	    INVALID_MEMBER(trace_print_flags_mask) || 
	    INVALID_MEMBER(trace_print_flags_name) ||
	    !kernel_symbol_exists("pageflag_names") ||
	    !(len = get_array_length("pageflag_names", NULL, 0)))
		return FALSE;

	buffer = GETBUF(SIZE(trace_print_flags) * len);

	if (!readmem(symbol_value("pageflag_names"), KVADDR, buffer,
	    SIZE(trace_print_flags) * len, "pageflag_names array",
	    RETURN_ON_ERROR)) {
		FREEBUF(buffer);
		return FALSE;
	}

	if (!(vt->pageflags_data = (struct pageflags_data *)
	    malloc(sizeof(struct pageflags_data) * len))) {
		error(INFO, "cannot malloc pageflags_data cache\n");
		FREEBUF(buffer);
		return FALSE;
	}

	if (CRASHDEBUG(1))
		fprintf(fp, "pageflags from pageflag_names: \n");

	for (i = 0; i < len; i++) {
		mask = ULONG(buffer + (SIZE(trace_print_flags)*i) + 
			OFFSET(trace_print_flags_mask));		
		name = VOID_PTR(buffer + (SIZE(trace_print_flags)*i) + 
			OFFSET(trace_print_flags_name));		

		if ((mask == -1UL) && !name) {   /* Linux 3.5 and earlier */
			len--;
			break;
		}

		if ((mask == 0UL) && !name) {   /* Linux 4.6 and later */
			len--;
			break;
		}

		if (!read_string((ulong)name, namebuf, BUFSIZE-1)) {
			error(INFO, "failed to read pageflag_names entry (i: %d  name: %lx  mask: %lx)\n",
				i, name, mask);
			goto pageflags_fail;
		}

		if (!(nameptr = (char *)malloc(strlen(namebuf)+1))) {
			error(INFO, "cannot malloc pageflag_names space\n");
			goto pageflags_fail;
		}
		strcpy(nameptr, namebuf);

		vt->pageflags_data[i].name = nameptr;
		vt->pageflags_data[i].mask = mask;

		if (CRASHDEBUG(1)) {
			fprintf(fp, "  %08lx %s\n", 
				vt->pageflags_data[i].mask,
				vt->pageflags_data[i].name);
		}
	}

	FREEBUF(buffer);
	vt->nr_pageflags = len;
	vt->flags |= PAGEFLAGS;
	return TRUE;

pageflags_fail:
	FREEBUF(buffer);
	free(vt->pageflags_data);
	vt->pageflags_data = NULL;
	return FALSE;
}

static int
page_flags_init_from_pageflags_enum(void)
{
	int c;
	int p, len;
	char *nameptr;
	char buf[BUFSIZE];
	char *arglist[MAXARGS];

	if (!(vt->pageflags_data = (struct pageflags_data *)
	    malloc(sizeof(struct pageflags_data) * 32))) {
		error(INFO, "cannot malloc pageflags_data cache\n");
		return FALSE;
        }

	p = 0;
	pc->flags2 |= ALLOW_FP;
	open_tmpfile();

	if (dump_enumerator_list("pageflags")) {
		rewind(pc->tmpfile);
		while (fgets(buf, BUFSIZE, pc->tmpfile)) {
			if (!strstr(buf, " = "))
				continue;

			c = parse_line(buf, arglist);

			if (strstr(arglist[0], "__NR_PAGEFLAGS")) {
				len = atoi(arglist[2]);
				if (!len || (len > 32))
					goto enum_fail;
				vt->nr_pageflags = len;
				break;
			}

			if (!(nameptr = (char *)malloc(strlen(arglist[0])))) {
				error(INFO, "cannot malloc pageflags name space\n");
				goto enum_fail;
			}
			strcpy(nameptr, arglist[0] + strlen("PG_"));
			vt->pageflags_data[p].name = nameptr;
			vt->pageflags_data[p].mask = 1 << atoi(arglist[2]); 

			p++;
		}
	} else 
		goto enum_fail;

	close_tmpfile();
	pc->flags2 &= ~ALLOW_FP;

	if (CRASHDEBUG(1)) {
		fprintf(fp, "pageflags from enum: \n");
		for (p = 0; p < vt->nr_pageflags; p++)
			fprintf(fp, "  %08lx %s\n", 
				vt->pageflags_data[p].mask,
				vt->pageflags_data[p].name);
	}

	vt->flags |= PAGEFLAGS;
	return TRUE;

enum_fail:
	close_tmpfile();
	pc->flags2 &= ~ALLOW_FP;

	for (c = 0; c < p; c++)
		free(vt->pageflags_data[c].name);
	free(vt->pageflags_data);
	vt->pageflags_data = NULL;
	vt->nr_pageflags = 0;

	return FALSE;
}

static int
translate_page_flags(char *buffer, ulong flags)
{
	char buf[BUFSIZE];
	int i, others;

	sprintf(buf, "%lx", flags);

	if (flags) {
		for (i = others = 0; i < vt->nr_pageflags; i++) {
			if (flags & vt->pageflags_data[i].mask)
				sprintf(&buf[strlen(buf)], "%s%s",
					others++ ? "," : " ",
					vt->pageflags_data[i].name);
		}
	}
	strcat(buf, "\n");
	strcpy(buffer, buf);

	return(strlen(buf));
}

/*
 *  Display the mem_map data for a single page.
 */
int
dump_inode_page(ulong page)
{
	struct meminfo meminfo;

	if (!is_page_ptr(page, NULL))
		return 0;

	BZERO(&meminfo, sizeof(struct meminfo));
	meminfo.spec_addr = page;
	meminfo.memtype = KVADDR;
	meminfo.flags = ADDRESS_SPECIFIED;
	dump_mem_map(&meminfo);

	return meminfo.retval;
}

/*
 *  dump_page_hash_table() displays the entries in each page_hash_table.
 */

#define PGHASH_CACHED (1024)

static void
dump_page_hash_table(struct meminfo *hi)
{
	int i;
	int len, entry_len;
	ulong page_hash_table, head;
	struct list_data list_data, *ld;
	struct gnu_request req;
	long total_cached;
	long page_cache_size;
	ulong this_addr, searchpage;
	int errflag, found, cnt, populated, verbose;
	uint ival;
	ulong buffer_pages;
	char buf[BUFSIZE];
	char hash_table[BUFSIZE];
	char *pcache, *pghash_cache;

	if (!vt->page_hash_table) {
		if (hi->flags & VERBOSE)
			option_not_supported('C');
		
        	if (symbol_exists("nr_pagecache")) {
			buffer_pages = nr_blockdev_pages();
                	get_symbol_data("nr_pagecache", sizeof(int), &ival);
                	page_cache_size = (ulong)ival;
			page_cache_size -= buffer_pages;
        		fprintf(fp, "page cache size: %ld\n", page_cache_size);
			if (hi->flags & ADDRESS_SPECIFIED)
				option_not_supported('c');
		} else
			option_not_supported('c');
		return;
	}

	ld = &list_data;

	if (hi->spec_addr && (hi->flags & ADDRESS_SPECIFIED)) {
		verbose = TRUE;
		searchpage = hi->spec_addr;
	} else if (hi->flags & VERBOSE) {
		verbose = TRUE;
		searchpage = 0;
	} else { 
		verbose = FALSE;
		searchpage = 0;
	}

	if (vt->page_hash_table_len == 0) 
		error(FATAL, "cannot determine size of page_hash_table\n");

	page_hash_table = vt->page_hash_table;
	len = vt->page_hash_table_len;
	entry_len = VALID_STRUCT(page_cache_bucket) ?
		SIZE(page_cache_bucket) : sizeof(void *);

	populated = 0;
	if (CRASHDEBUG(1))
		fprintf(fp, "page_hash_table length: %d\n", len);

	get_symbol_type("page_cache_size", NULL, &req);
        if (req.length == sizeof(int)) {
                get_symbol_data("page_cache_size", sizeof(int), &ival);
                page_cache_size = (long)ival;
        } else
                get_symbol_data("page_cache_size", sizeof(long),
                        &page_cache_size);

        pghash_cache = GETBUF(sizeof(void *) * PGHASH_CACHED);

	if (searchpage)
		open_tmpfile();

	hq_open();
	for (i = total_cached = 0; i < len; i++, 
	     page_hash_table += entry_len) {

                if ((i % PGHASH_CACHED) == 0) {
                	readmem(page_hash_table, KVADDR, pghash_cache,
                        	entry_len * PGHASH_CACHED,
                                "page hash cache", FAULT_ON_ERROR);
                }

                pcache = pghash_cache + ((i%PGHASH_CACHED) * entry_len);
		if (VALID_STRUCT(page_cache_bucket))
			pcache += OFFSET(page_cache_bucket_chain);
			
		head = ULONG(pcache);

		if (!head) 
			continue;

		if (verbose) 
			fprintf(fp, "page_hash_table[%d]\n", i);
		
		if (CRASHDEBUG(1))
			populated++;

                BZERO(ld, sizeof(struct list_data));
                ld->flags = verbose;
                ld->start = head;
		ld->searchfor = searchpage;
		ld->member_offset = OFFSET(page_next_hash);
                cnt = do_list(ld);
                total_cached += cnt;

		if (ld->searchfor)
			break;

		if (received_SIGINT())
			restart(0);
	}
	hq_close();

        fprintf(fp, "%spage_cache_size: %ld ", verbose ? "\n" : "",
                page_cache_size);
        if (page_cache_size != total_cached)
                fprintf(fp, "(found %ld)\n", total_cached);
        else
                fprintf(fp, "(verified)\n");

	if (CRASHDEBUG(1))
		fprintf(fp, "heads containing page(s): %d\n", populated);

	if (searchpage) {
		rewind(pc->tmpfile);
		found = FALSE;
		while (fgets(buf, BUFSIZE, pc->tmpfile)) {
			if (CRASHDEBUG(1) && STRNEQ(buf, "<readmem:"))
				continue;

			if (strstr(buf, "page_hash_table")) {
				strcpy(hash_table, buf); 
				continue;
			}
			if (strstr(buf, "page_cache_size"))
				continue;

			if (CRASHDEBUG(1) && 
			    !hexadecimal(strip_linefeeds(buf), 0))
				continue;

                	this_addr = htol(strip_linefeeds(buf),
                        	RETURN_ON_ERROR, &errflag);

			if (this_addr == searchpage) {
				found = TRUE;
				break;
			}
		}
		close_tmpfile();

		if (found) {
			fprintf(fp, "%s", hash_table);
			fprintf(fp, "%lx\n", searchpage);
			hi->retval = TRUE;
		}
	}
}

/*
 *  dump_free_pages() displays basic data about pages currently resident
 *  in the free_area[] memory lists.  If the flags contains the VERBOSE 
 *  bit, each page slab base address is dumped.  If an address is specified
 *  only the free_area[] data containing that page is displayed, along with
 *  the page slab base address.  Specified addresses can either be physical 
 *  address or page structure pointers.
 */
char *free_area_hdr1 = \
	"AREA  SIZE  FREE_AREA_STRUCT  BLOCKS   PAGES\n";
char *free_area_hdr2 = \
	"AREA  SIZE  FREE_AREA_STRUCT\n";

static void
dump_free_pages(struct meminfo *fi)
{
	int i;
	int order;
	ulong free_area;
	char *free_area_buf;
	ulong *pp;
	int nr_mem_lists;
	struct list_data list_data, *ld;
	long cnt, total_free, chunk_size;
	int nr_free_pages;
	char buf[BUFSIZE];
	char last_free[BUFSIZE];
	char last_free_hdr[BUFSIZE];
	int verbose, errflag, found;
	physaddr_t searchphys;
	ulong this_addr; 
	physaddr_t this_phys;
	int do_search;
	ulong kfp, offset;
	int flen, dimension;

        if (vt->flags & (NODES|ZONES)) 
		error(FATAL, "dump_free_pages called with (NODES|ZONES)\n");

	nr_mem_lists = ARRAY_LENGTH(free_area);
	dimension = ARRAY_LENGTH(free_area_DIMENSION);

	if (nr_mem_lists == 0)
		error(FATAL, "cannot determine size/dimensions of free_area\n");

	if (dimension) 
		error(FATAL, 
		    "dump_free_pages called with multidimensional free area\n");

	ld = &list_data;
	total_free = 0;
	searchphys = 0;
	chunk_size = 0;
	do_search = FALSE;
	get_symbol_data("nr_free_pages", sizeof(int), &nr_free_pages);
	
	switch (fi->flags)
	{
	case GET_FREE_HIGHMEM_PAGES:
                error(FATAL, "GET_FREE_HIGHMEM_PAGES invalid in this kernel\n");

	case GET_FREE_PAGES:
		fi->retval = (ulong)nr_free_pages;
		return;

	case ADDRESS_SPECIFIED:
		switch (fi->memtype)
		{
		case KVADDR:
                        if (!page_to_phys(fi->spec_addr, &searchphys)) {
                                if (!kvtop(NULL, fi->spec_addr, &searchphys, 0))
                                        return;
                        }
			break;
		case PHYSADDR:
			searchphys = fi->spec_addr;
			break;
		default:
			error(FATAL, "dump_free_pages: no memtype specified\n");
		}
		do_search = TRUE;
		break;
	} 

	verbose = (do_search || (fi->flags & VERBOSE)) ? TRUE : FALSE;

	free_area_buf = GETBUF(nr_mem_lists * SIZE(free_area_struct));
	kfp = free_area = symbol_value("free_area");
	flen = MAX(VADDR_PRLEN, strlen("FREE_AREA_STRUCT"));
	readmem(free_area, KVADDR, free_area_buf, 
		SIZE(free_area_struct) * nr_mem_lists, 
		"free_area_struct", FAULT_ON_ERROR);

	if (do_search)
		open_tmpfile();

	if (!verbose)
		fprintf(fp, "%s", free_area_hdr1);

       	hq_open();
	for (i = 0; i < nr_mem_lists; i++) {
		pp = (ulong *)(free_area_buf + (SIZE(free_area_struct)*i));

		chunk_size = power(2, i);

		if (verbose)
			fprintf(fp, "%s", free_area_hdr2);

		fprintf(fp, "%3d  ", i);
		sprintf(buf, "%ldk", (chunk_size * PAGESIZE())/1024);
		fprintf(fp, "%5s  ", buf);

		fprintf(fp, "%s  %s", 
			mkstring(buf, flen, CENTER|LONG_HEX, MKSTR(kfp)),
			verbose ? "\n" : "");

		if (is_page_ptr(*pp, NULL)) {
			BZERO(ld, sizeof(struct list_data));
			ld->flags = verbose;
			ld->start = *pp;
			ld->end = free_area;
        		cnt = do_list(ld);
			total_free += (cnt * chunk_size);
		} else 
			cnt = 0;

		if (!verbose)
			fprintf(fp, "%6ld  %6ld\n", cnt, cnt * chunk_size );

		free_area += SIZE(free_area_struct);
		kfp += SIZE(free_area_struct);
	}
       	hq_close();

	fprintf(fp, "\nnr_free_pages: %d ", nr_free_pages);
	if (total_free != nr_free_pages)
		fprintf(fp, "(found %ld)\n", total_free);
	else
		fprintf(fp, "(verified)\n");

	if (!do_search)
		return;

	found = FALSE;
        rewind(pc->tmpfile);
	order = offset = this_addr = 0;

        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
		if (CRASHDEBUG(1) && STRNEQ(buf, "<readmem"))
			continue;

		if (strstr(buf, "nr_free_pages") ||
		    STREQ(buf, "\n"))
			continue;

		if (strstr(buf, "AREA")) {
			strcpy(last_free_hdr, buf);
			continue;
		}

		if (strstr(buf, "k")) {
			strcpy(last_free, buf);
			chunk_size = power(2, order) * PAGESIZE();
			order++;
			continue;
		}

		if (CRASHDEBUG(1) && !hexadecimal(strip_linefeeds(buf), 0))
			continue;

		errflag = 0;
		this_addr = htol(strip_linefeeds(buf), 
			RETURN_ON_ERROR, &errflag);
                if (errflag) 
			continue;

		if (!page_to_phys(this_addr, &this_phys))
			continue;

		if ((searchphys >= this_phys) && 
		    (searchphys < (this_phys+chunk_size))) {
			if (searchphys > this_phys) 
				offset = (searchphys - this_phys)/PAGESIZE();
			found = TRUE;
			break;
		}
	}
        close_tmpfile();

	if (found) {
		order--;

		fprintf(fp, "%s", last_free_hdr);
		fprintf(fp, "%s", last_free);
		fprintf(fp, "%lx  ", this_addr);
		if (order) {
                	switch (fi->memtype)
                	{
                	case KVADDR:
				fprintf(fp, "(%lx is ", (ulong)fi->spec_addr);
                        	break;
                	case PHYSADDR:
				fprintf(fp, "(%llx is %s", fi->spec_addr,
				    PAGEOFFSET(fi->spec_addr) ?  "in " : "");
                        	break;
			}
			fprintf(fp, "%s of %ld pages) ",
				ordinal(offset+1, buf), power(2, order));
		}

		fi->retval = TRUE;
		fprintf(fp, "\n");
	}
}

/*
 *  Dump free pages on kernels with a multi-dimensional free_area array.
 */
char *free_area_hdr5 = \
	"  AREA    SIZE  FREE_AREA_STRUCT  BLOCKS   PAGES\n";
char *free_area_hdr6 = \
	"  AREA    SIZE  FREE_AREA_STRUCT\n";

static void
dump_multidimensional_free_pages(struct meminfo *fi)
{
	int i, j;
	struct list_data list_data, *ld;
	long cnt, total_free;
	ulong kfp, free_area;
	physaddr_t searchphys;
	int flen, errflag, verbose, nr_free_pages;
	int nr_mem_lists, dimension, order, do_search;
	ulong sum, found, offset;
	char *free_area_buf, *p;
	ulong *pp;
	long chunk_size;
        ulong this_addr; 
	physaddr_t this_phys;
	char buf[BUFSIZE];
	char last_area[BUFSIZE];
	char last_area_hdr[BUFSIZE];


        if (vt->flags & (NODES|ZONES)) 
                error(FATAL, 
		"dump_multidimensional_free_pages called with (NODES|ZONES)\n");

        ld = &list_data;
	if (SIZE(free_area_struct) % sizeof(ulong))
		error(FATAL, "free_area_struct not long-word aligned?\n");

        total_free = 0;
        searchphys = 0;
	chunk_size = 0;
	do_search = FALSE;
        get_symbol_data("nr_free_pages", sizeof(int), &nr_free_pages);

        switch (fi->flags)
        {
        case GET_FREE_HIGHMEM_PAGES:
                error(FATAL, "GET_FREE_HIGHMEM_PAGES invalid in this kernel\n");

        case GET_FREE_PAGES:
                fi->retval = (ulong)nr_free_pages;
                return;

	case ADDRESS_SPECIFIED:
		switch (fi->memtype)
                {
                case KVADDR:
                        if (!page_to_phys(fi->spec_addr, &searchphys)) {
                                if (!kvtop(NULL, fi->spec_addr, &searchphys, 0))
                                        return;
                        }
                        break;
                case PHYSADDR:
                        searchphys = fi->spec_addr;
                        break;
                default:
                        error(FATAL, 
		    "dump_multidimensional_free_pages: no memtype specified\n");
                }
		do_search = TRUE;
		break;
	}

        verbose = (do_search || (fi->flags & VERBOSE)) ? TRUE : FALSE;

	flen = MAX(VADDR_PRLEN, strlen("FREE_AREA_STRUCT"));
        nr_mem_lists = ARRAY_LENGTH(free_area);
	dimension = ARRAY_LENGTH(free_area_DIMENSION);
	if (!nr_mem_lists || !dimension)
		error(FATAL, "cannot determine free_area dimensions\n");
        free_area_buf = 
		GETBUF((nr_mem_lists * SIZE(free_area_struct)) * dimension);
        kfp = free_area = symbol_value("free_area");
        readmem(free_area, KVADDR, free_area_buf, 
		(SIZE(free_area_struct) * nr_mem_lists) * dimension,
                "free_area arrays", FAULT_ON_ERROR);

        if (do_search)
                open_tmpfile();

        hq_open();
        for (i = sum = found = 0; i < dimension; i++) {
        	if (!verbose)
                	fprintf(fp, "%s", free_area_hdr5);
               	pp = (ulong *)(free_area_buf + 
			((SIZE(free_area_struct)*nr_mem_lists)*i));
		for (j = 0; j < nr_mem_lists; j++) {
                        if (verbose)
                                fprintf(fp, "%s", free_area_hdr6);

			sprintf(buf, "[%d][%d]", i, j);
			fprintf(fp, "%7s  ", buf);

                	chunk_size = power(2, j);

                	sprintf(buf, "%ldk", (chunk_size * PAGESIZE())/1024);
                	fprintf(fp, "%5s  ", buf);

                	fprintf(fp, "%s  %s",  
			    mkstring(buf, flen, CENTER|LONG_HEX, MKSTR(kfp)),
			    verbose ? "\n" : "");

                	if (is_page_ptr(*pp, NULL)) {
                        	BZERO(ld, sizeof(struct list_data));
                        	ld->flags = verbose;
                        	ld->start = *pp;
                        	ld->end = free_area;
                        	cnt = do_list(ld);
                        	total_free += (cnt * chunk_size);
                	} else
                        	cnt = 0;

                	if (!verbose)
                        	fprintf(fp, 
					"%6ld  %6ld\n", cnt, cnt * chunk_size );

			pp += (SIZE(free_area_struct)/sizeof(ulong));
			free_area += SIZE(free_area_struct);
			kfp += SIZE(free_area_struct);
		}
		fprintf(fp, "\n");
	}
	hq_close();

        fprintf(fp, "nr_free_pages: %d ", nr_free_pages);
        if (total_free != nr_free_pages)
                fprintf(fp, "(found %ld)\n", total_free);
        else
                fprintf(fp, "(verified)\n");

        if (!do_search)
                return;

        found = FALSE;
        rewind(pc->tmpfile);
        order = offset = this_addr = 0;

        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
		if (CRASHDEBUG(1) && STRNEQ(buf, "<readmem:"))
			continue;

		if (STRNEQ(buf, "nr_free_pages:"))
			continue;

		if (strstr(buf, "AREA")) {
                        strcpy(last_area_hdr, buf);
                        p = fgets(buf, BUFSIZE, pc->tmpfile);
                        strcpy(last_area, strip_linefeeds(buf));
			p = strstr(buf, "k");
			*p = NULLCHAR;
			while (*p != ' ')
				p--;
			chunk_size = atol(p+1) * 1024;
			if (chunk_size == PAGESIZE())
				order = 0;
			else
				order++;
                        continue;
                }

                errflag = 0;
                this_addr = htol(strip_linefeeds(buf),
                        RETURN_ON_ERROR, &errflag);
                if (errflag)
                        continue;

                if (!page_to_phys(this_addr, &this_phys))
                        continue;

                if ((searchphys >= this_phys) &&
                    (searchphys < (this_phys+chunk_size))) {
                        if (searchphys > this_phys)
                                offset = (searchphys - this_phys)/PAGESIZE();
                        found = TRUE;
                        break;
                }

	}
	close_tmpfile();

	if (found) {
		fprintf(fp, "%s", last_area_hdr);
		fprintf(fp, "%s\n", last_area);
		fprintf(fp, "%lx  ", this_addr);
                if (order) {
                	switch (fi->memtype)
                	{
                	case KVADDR:
                                fprintf(fp, "(%lx is ", (ulong)fi->spec_addr);
                        	break;
                	case PHYSADDR:
                                fprintf(fp, "(%llx is %s", fi->spec_addr,
                                    PAGEOFFSET(fi->spec_addr) ?  "in " : "");
                        	break;
			}
                        fprintf(fp, "%s of %ld pages) ",
                                ordinal(offset+1, buf), power(2, order));
                }

		fi->retval = TRUE;
                fprintf(fp, "\n");
	}
}


/*
 *  Dump free pages in newer kernels that have zones.  This is a work in
 *  progress, because although the framework for memory nodes has been laid
 *  down, complete support has not been put in place.
 */
static char *zone_hdr = "ZONE  NAME        SIZE    FREE";

static void
dump_free_pages_zones_v1(struct meminfo *fi)
{
	int i, n;
	ulong node_zones;
	ulong size;
	long zone_size_offset;
	long chunk_size;
	int order, errflag, do_search;
	ulong offset, verbose, value, sum, found; 
	ulong this_addr;
	physaddr_t this_phys, searchphys;
        ulong zone_mem_map;
        ulong zone_start_paddr;
        ulong zone_start_mapnr;
	struct node_table *nt;
	char buf[BUFSIZE], *p;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char last_node[BUFSIZE];
	char last_zone[BUFSIZE];
	char last_area[BUFSIZE];
	char last_area_hdr[BUFSIZE];

       if (!(vt->flags & (NODES|ZONES)))
		error(FATAL, 
		    "dump_free_pages_zones_v1 called without (NODES|ZONES)\n");

        if (fi->flags & ADDRESS_SPECIFIED) {
                switch (fi->memtype)
                {
                case KVADDR:
                        if (!page_to_phys(fi->spec_addr, &searchphys)) {
                                if (!kvtop(NULL, fi->spec_addr, &searchphys, 0))
                                        return;
                        }
                        break;
                case PHYSADDR:
                        searchphys = fi->spec_addr;
                        break;
                default:
                        error(FATAL, 
			    "dump_free_pages_zones_v1: no memtype specified\n");
                }
		do_search = TRUE;
        } else {
                searchphys = 0;
		do_search = FALSE;
	}
        verbose = (do_search || (fi->flags & VERBOSE)) ? TRUE : FALSE;

	chunk_size = 0;
	zone_size_offset = 0;

	if (VALID_MEMBER(zone_struct_size))
		zone_size_offset =  OFFSET(zone_struct_size);
	else if (VALID_MEMBER(zone_struct_memsize))
		zone_size_offset =  OFFSET(zone_struct_memsize);
	else
		error(FATAL, 
			"zone_struct has neither size nor memsize field\n");

	if (do_search)
		open_tmpfile();

	hq_open();

	for (n = sum = found = 0; n < vt->numnodes; n++) {
                nt = &vt->node_table[n];
		node_zones = nt->pgdat + OFFSET(pglist_data_node_zones);

		for (i = 0; i < vt->nr_zones; i++) {
	
			if (fi->flags == GET_FREE_PAGES) {
	                	readmem(node_zones+
					OFFSET(zone_struct_free_pages), 
					KVADDR, &value, sizeof(ulong),
	                        	"node_zones free_pages", 
					FAULT_ON_ERROR);
				sum += value;
				node_zones += SIZE(zone_struct);
				continue;
			}
	
	                if (fi->flags == GET_FREE_HIGHMEM_PAGES) {
	                        if (i == vt->ZONE_HIGHMEM) {
	                                readmem(node_zones+
						OFFSET(zone_struct_free_pages),
						KVADDR, &value, sizeof(ulong),
	                                        "node_zones free_pages",
	                                        FAULT_ON_ERROR);
	                                sum += value;
	                        }
	                        node_zones += SIZE(zone_struct);
	                        continue;
	                }
	
			if (fi->flags == GET_ZONE_SIZES) {
	                	readmem(node_zones+zone_size_offset, 
					KVADDR, &size, sizeof(ulong),
	                        	"node_zones {mem}size", FAULT_ON_ERROR);
	                        sum += size;
	                        node_zones += SIZE(zone_struct);
	                        continue;
			}

			if ((i == 0) && (vt->flags & NODES)) {
				if (n) {
					fprintf(fp, "\n");
                                	pad_line(fp, 
						VADDR_PRLEN > 8 ? 74 : 66, '-');
                                	fprintf(fp, "\n");
				}
				fprintf(fp, "%sNODE\n %2d\n", 
					n ? "\n" : "", nt->node_id);
			}

	                fprintf(fp, "%s%s  %s  START_PADDR  START_MAPNR\n",
				i > 0 ? "\n" : "",
	                        zone_hdr,
	                        mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, 
				    "MEM_MAP"));
	
			fprintf(fp, "%3d   ", i);
	
	        	readmem(node_zones+OFFSET(zone_struct_name), KVADDR, 
				&value, sizeof(void *), 
				"node_zones name", FAULT_ON_ERROR);
	                if (read_string(value, buf, BUFSIZE-1))
	                	fprintf(fp, "%-9s ", buf);
			else
				fprintf(fp, "(unknown) ");
	
	        	readmem(node_zones+zone_size_offset, KVADDR, 
				&size, sizeof(ulong), 
				"node_zones {mem}size", FAULT_ON_ERROR);
	                fprintf(fp, "%6ld  ", size);
	
	        	readmem(node_zones+OFFSET(zone_struct_free_pages), 
				KVADDR, &value, sizeof(ulong), 
				"node_zones free_pages", FAULT_ON_ERROR);
	
	                fprintf(fp, "%6ld  ", value);
	
	                readmem(node_zones+OFFSET(zone_struct_zone_start_paddr),
	                        KVADDR, &zone_start_paddr, sizeof(ulong),
	                        "node_zones zone_start_paddr", FAULT_ON_ERROR);
	                readmem(node_zones+OFFSET(zone_struct_zone_start_mapnr),
	                        KVADDR, &zone_start_mapnr, sizeof(ulong),
	                        "node_zones zone_start_mapnr", FAULT_ON_ERROR);
	                readmem(node_zones+OFFSET(zone_struct_zone_mem_map),
	                        KVADDR, &zone_mem_map, sizeof(ulong),
	                        "node_zones zone_mem_map", FAULT_ON_ERROR);
	
	                fprintf(fp, "%s  %s  %s\n",
	                	mkstring(buf1, VADDR_PRLEN,
	                            CENTER|LONG_HEX,MKSTR(zone_mem_map)),
	                	mkstring(buf2, strlen("START_PADDR"),
	                            CENTER|LONG_HEX|RJUST,
					MKSTR(zone_start_paddr)),
	                	mkstring(buf3, strlen("START_MAPNR"),
	                            CENTER|LONG_DEC|RJUST,
					MKSTR(zone_start_mapnr)));
	
			sum += value;

			if (value)
				found += dump_zone_free_area(node_zones+
					OFFSET(zone_struct_free_area), 
					vt->nr_free_areas, verbose, NULL);

			node_zones += SIZE(zone_struct);
		}
	}

	hq_close();

        if (fi->flags & (GET_FREE_PAGES|GET_ZONE_SIZES|GET_FREE_HIGHMEM_PAGES)) {
                fi->retval = sum;
                return;
        }

	fprintf(fp, "\nnr_free_pages: %ld  ", sum);
	if (sum == found)
		fprintf(fp, "(verified)\n");
	else
		fprintf(fp, "(found %ld)\n", found);

	if (!do_search)
		return;

        found = FALSE;
        rewind(pc->tmpfile);
        order = offset = this_addr = 0;
	last_node[0] = NULLCHAR;
        last_zone[0] = NULLCHAR;
        last_area[0] = NULLCHAR;
        last_area_hdr[0] = NULLCHAR;


        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
		if (CRASHDEBUG(1) && STRNEQ(buf, "<readmem"))
			continue;

		if (STRNEQ(buf, "nr_free_pages:"))
			continue;

		if (STRNEQ(buf, "NODE")) { 
			p = fgets(buf, BUFSIZE, pc->tmpfile);
			strcpy(last_node, strip_linefeeds(buf));
			continue;
		}
		if (STRNEQ(buf, "ZONE")) {
			p = fgets(buf, BUFSIZE, pc->tmpfile);
			strcpy(last_zone, strip_linefeeds(buf));
			continue;
		}
		if (STRNEQ(buf, "AREA")) {
                        strcpy(last_area_hdr, buf);
                        p = fgets(buf, BUFSIZE, pc->tmpfile);
                        strcpy(last_area, strip_linefeeds(buf));
			p = strstr(buf, "k");
			*p = NULLCHAR;
			while (*p != ' ')
				p--;
			chunk_size = atol(p+1) * 1024;
			if (chunk_size == PAGESIZE())
				order = 0;
			else
				order++;
                        continue;
                }

                if (CRASHDEBUG(0) &&
                    !hexadecimal(strip_linefeeds(buf), 0))
                        continue;

                errflag = 0;
                this_addr = htol(strip_linefeeds(buf),
                        RETURN_ON_ERROR, &errflag);
                if (errflag)
                        continue;

                if (!page_to_phys(this_addr, &this_phys))
                        continue;

                if ((searchphys >= this_phys) &&
                    (searchphys < (this_phys+chunk_size))) {
                        if (searchphys > this_phys)
                                offset = (searchphys - this_phys)/PAGESIZE();
                        found = TRUE;
                        break;
                }

	}
	close_tmpfile();

	if (found) {
		if (strlen(last_node)) 
			fprintf(fp, "NODE\n%s\n", last_node); 
                fprintf(fp, "%s  %s  START_PADDR  START_MAPNR\n",
                        zone_hdr,
                        mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "MEM_MAP"));
		fprintf(fp, "%s\n", last_zone);
		fprintf(fp, "%s", last_area_hdr);
		fprintf(fp, "%s\n", last_area);
		fprintf(fp, "%lx  ", this_addr);
                if (order) {
                	switch (fi->memtype)
                	{
                	case KVADDR:
                                fprintf(fp, "(%lx is ", (ulong)fi->spec_addr);
                        	break;
                	case PHYSADDR:
                                fprintf(fp, "(%llx is %s", fi->spec_addr,
                                    PAGEOFFSET(fi->spec_addr) ?  "in " : "");
                        	break;
			}
                        fprintf(fp, "%s of %ld pages) ",
                                ordinal(offset+1, buf), power(2, order));
                }

		fi->retval = TRUE;
                fprintf(fp, "\n");
	}
}


/*
 *  Callback function for free-list search for a specific page.
 */
struct free_page_callback_data {
	ulong searchpage;
	long chunk_size;
	ulong page;
	int found;
};

static int
free_page_callback(void *page, void *arg)
{
	struct free_page_callback_data *cbd = arg;
	ulong first_page, last_page;

	first_page = (ulong)page;
	last_page = first_page + (cbd->chunk_size * SIZE(page));	

	if ((cbd->searchpage >= first_page) && (cbd->searchpage <= last_page)) {
		cbd->page = (ulong)page;
		cbd->found = TRUE;
		return TRUE;
	}

	return FALSE;
}


/*
 *  Same as dump_free_pages_zones_v1(), but updated for numerous 2.6 zone 
 *  and free_area related data structure changes.
 */
static void
dump_free_pages_zones_v2(struct meminfo *fi)
{
	int i, n;
	ulong node_zones;
	ulong size;
	long zone_size_offset;
	long chunk_size;
	int order, errflag, do_search;
	ulong offset, verbose, value, sum, found; 
	ulong this_addr;
	physaddr_t phys, this_phys, searchphys, end_paddr;
	ulong searchpage;
	struct free_page_callback_data callback_data;
	ulong pp;
        ulong zone_mem_map;
        ulong zone_start_paddr;
	ulong zone_start_pfn;
        ulong zone_start_mapnr;
	struct node_table *nt;
	char buf[BUFSIZE], *p;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char last_node[BUFSIZE];
	char last_zone[BUFSIZE];
	char last_area[BUFSIZE];
	char last_area_hdr[BUFSIZE];

       if (!(vt->flags & (NODES|ZONES)))
		error(FATAL, 
		    "dump_free_pages_zones_v2 called without (NODES|ZONES)\n");

        if (fi->flags & ADDRESS_SPECIFIED) {
                switch (fi->memtype)
                {
                case KVADDR:
                        if (!page_to_phys(fi->spec_addr, &searchphys)) {
                                if (!kvtop(NULL, fi->spec_addr, &searchphys, 0))
                                        return;
                        }
                        break;
                case PHYSADDR:
                        searchphys = fi->spec_addr;
                        break;
                default:
                        error(FATAL, 
			    "dump_free_pages_zones_v2: no memtype specified\n");
                }
		if (!phys_to_page(searchphys, &searchpage)) {
			error(INFO, "cannot determine page for %lx\n", fi->spec_addr);
			return;
		}
		do_search = TRUE;
		callback_data.searchpage = searchpage;
		callback_data.found = FALSE;
        } else {
                searchphys = 0;
		do_search = FALSE;
	}

        verbose = (do_search || (fi->flags & VERBOSE)) ? TRUE : FALSE;

	zone_size_offset = 0;
	chunk_size = 0;
	this_addr = 0;

	if (VALID_MEMBER(zone_spanned_pages))
		zone_size_offset =  OFFSET(zone_spanned_pages);
	else
		error(FATAL, "zone struct has no spanned_pages field\n");

	if (do_search)
		open_tmpfile();

	hq_open();

	for (n = sum = found = 0; n < vt->numnodes; n++) {
                nt = &vt->node_table[n];
		node_zones = nt->pgdat + OFFSET(pglist_data_node_zones);

		for (i = 0; i < vt->nr_zones; i++) {
			if (fi->flags == GET_FREE_PAGES) {
	                	readmem(node_zones+
					OFFSET(zone_free_pages), 
					KVADDR, &value, sizeof(ulong),
	                        	"node_zones free_pages", 
					FAULT_ON_ERROR);
				sum += value;
				node_zones += SIZE(zone);
				continue;
			}
	
	                if (fi->flags == GET_FREE_HIGHMEM_PAGES) {
				readmem(node_zones+OFFSET(zone_name), KVADDR,
					&value, sizeof(void *),
					"node_zones name", FAULT_ON_ERROR);
				if (read_string(value, buf, BUFSIZE-1) &&
				    STREQ(buf, "HighMem"))
					vt->ZONE_HIGHMEM = i;

	                        if (i == vt->ZONE_HIGHMEM) {
	                                readmem(node_zones+
						OFFSET(zone_free_pages),
						KVADDR, &value, sizeof(ulong),
	                                        "node_zones free_pages",
	                                        FAULT_ON_ERROR);
	                                sum += value;
	                        }
	                        node_zones += SIZE(zone);
	                        continue;
	                }
	
			if (fi->flags == GET_ZONE_SIZES) {
	                	readmem(node_zones+zone_size_offset, 
					KVADDR, &size, sizeof(ulong),
	                        	"node_zones size", FAULT_ON_ERROR);
	                        sum += size;
	                        node_zones += SIZE(zone);
	                        continue;
			}

			if ((i == 0) && ((vt->flags & NODES) || (vt->numnodes > 1))) {
				if (n) {
					fprintf(fp, "\n");
					pad_line(fp, 
						VADDR_PRLEN > 8 ? 74 : 66, '-');
					fprintf(fp, "\n");
				}
				fprintf(fp, "%sNODE\n %2d\n", 
					n ? "\n" : "", nt->node_id);
			}

	                fprintf(fp, "%s%s  %s  START_PADDR  START_MAPNR\n",
				i > 0 ? "\n" : "",
	                        zone_hdr,
	                        mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, 
				    "MEM_MAP"));
	
			fprintf(fp, "%3d   ", i);
	
	        	readmem(node_zones+OFFSET(zone_name), KVADDR, 
				&value, sizeof(void *), 
				"node_zones name", FAULT_ON_ERROR);
	                if (read_string(value, buf, BUFSIZE-1))
	                	fprintf(fp, "%-9s ", buf);
			else
				fprintf(fp, "(unknown) ");
	
	        	readmem(node_zones+zone_size_offset, KVADDR, 
				&size, sizeof(ulong), 
				"node_zones size", FAULT_ON_ERROR);
	                fprintf(fp, "%6ld  ", size);
	
	        	readmem(node_zones+OFFSET(zone_free_pages), 
				KVADDR, &value, sizeof(ulong), 
				"node_zones free_pages", FAULT_ON_ERROR);
	
	                fprintf(fp, "%6ld  ", value);
	
			if (VALID_MEMBER(zone_zone_mem_map)) {
                        	readmem(node_zones+OFFSET(zone_zone_mem_map),
                                	KVADDR, &zone_mem_map, sizeof(ulong),
                                	"node_zones zone_mem_map", FAULT_ON_ERROR);
			}

			readmem(node_zones+ OFFSET(zone_zone_start_pfn),
                                KVADDR, &zone_start_pfn, sizeof(ulong),
                                "node_zones zone_start_pfn", FAULT_ON_ERROR);
                        zone_start_paddr = PTOB(zone_start_pfn);

			if (!VALID_MEMBER(zone_zone_mem_map)) {
				if (IS_SPARSEMEM() || IS_DISCONTIGMEM()) {
					zone_mem_map = 0;
					if (size) {
						phys = PTOB(zone_start_pfn);
                                        	if (phys_to_page(phys, &pp))
                                                	zone_mem_map = pp;
					}
				} else if (vt->flags & FLATMEM) {
					zone_mem_map = 0;
					if (size)
						zone_mem_map = nt->mem_map +
							(zone_start_pfn * SIZE(page));
				} else
					error(FATAL, "\ncannot determine zone mem_map: TBD\n");
			}

                        if (zone_mem_map) 
                        	zone_start_mapnr = 
					(zone_mem_map - nt->mem_map) / 
						SIZE(page);
                        else
                                zone_start_mapnr = 0;
	
	                fprintf(fp, "%s  %s  %s\n",
	                	mkstring(buf1, VADDR_PRLEN,
	                            CENTER|LONG_HEX,MKSTR(zone_mem_map)),
	                	mkstring(buf2, strlen("START_PADDR"),
	                            CENTER|LONG_HEX|RJUST,
					MKSTR(zone_start_paddr)),
	                	mkstring(buf3, strlen("START_MAPNR"),
	                            CENTER|LONG_DEC|RJUST,
					MKSTR(zone_start_mapnr)));
	
			sum += value;

			if (value) {
				if (do_search) {
					end_paddr = nt->start_paddr +
						((physaddr_t)nt->size * 
						 (physaddr_t)PAGESIZE());

					if ((searchphys >= nt->start_paddr) &&
					    (searchphys < end_paddr))
						found += dump_zone_free_area(node_zones+
							OFFSET(zone_free_area), 
							vt->nr_free_areas, verbose,
							&callback_data);

					if (callback_data.found)
						goto done_search;
				} else 
					found += dump_zone_free_area(node_zones+
						OFFSET(zone_free_area), 
						vt->nr_free_areas, verbose, NULL);
			}

			node_zones += SIZE(zone);
		}
	}

done_search:
	hq_close();

        if (fi->flags & (GET_FREE_PAGES|GET_ZONE_SIZES|GET_FREE_HIGHMEM_PAGES)) {
                fi->retval = sum;
                return;
        }

	fprintf(fp, "\nnr_free_pages: %ld  ", sum);
	if (sum == found)
		fprintf(fp, "(verified)\n");
	else
		fprintf(fp, "(found %ld)\n", found);

	if (!do_search)
		return;

        found = FALSE;
        rewind(pc->tmpfile);
        order = offset = 0;
	last_node[0] = NULLCHAR;
        last_zone[0] = NULLCHAR;
        last_area[0] = NULLCHAR;
        last_area_hdr[0] = NULLCHAR;


        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
		if (CRASHDEBUG(1) && STRNEQ(buf, "<readmem"))
			continue;

		if (STRNEQ(buf, "nr_free_pages:"))
			continue;

		if (STRNEQ(buf, "NODE")) { 
			p = fgets(buf, BUFSIZE, pc->tmpfile);
			strcpy(last_node, strip_linefeeds(buf));
			continue;
		}
		if (STRNEQ(buf, "ZONE")) {
			p = fgets(buf, BUFSIZE, pc->tmpfile);
			strcpy(last_zone, strip_linefeeds(buf));
			continue;
		}
		if (STRNEQ(buf, "AREA")) {
                        strcpy(last_area_hdr, buf);
                        p = fgets(buf, BUFSIZE, pc->tmpfile);
                        strcpy(last_area, strip_linefeeds(buf));
			p = strstr(buf, "k");
			*p = NULLCHAR;
			while (*p != ' ')
				p--;
			chunk_size = atol(p+1) * 1024;
			if (chunk_size == PAGESIZE())
				order = 0;
			else
				order++;
                        continue;
                }

                if (CRASHDEBUG(0) &&
                    !hexadecimal(strip_linefeeds(buf), 0)) 
                        continue;

                errflag = 0;
                this_addr = htol(strip_linefeeds(buf),
                        RETURN_ON_ERROR, &errflag);
                if (errflag)
                        continue;

                if (!page_to_phys(this_addr, &this_phys)) 
                        continue;

                if ((searchphys >= this_phys) &&
                    (searchphys < (this_phys+chunk_size))) {
                        if (searchphys > this_phys)
                                offset = (searchphys - this_phys)/PAGESIZE();
                        found = TRUE;
                        break;
                }

	}
	close_tmpfile();

	if (found) {
		if (strlen(last_node)) 
			fprintf(fp, "NODE\n%s\n", last_node); 
                fprintf(fp, "%s  %s  START_PADDR  START_MAPNR\n",
                        zone_hdr,
                        mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "MEM_MAP"));
		fprintf(fp, "%s\n", last_zone);
		fprintf(fp, "%s", last_area_hdr);
		fprintf(fp, "%s\n", last_area);
		fprintf(fp, "%lx  ", this_addr);
                if (order) {
                	switch (fi->memtype)
                	{
                	case KVADDR:
                                fprintf(fp, "(%lx is ", (ulong)fi->spec_addr);
                        	break;
                	case PHYSADDR:
                                fprintf(fp, "(%llx is %s", fi->spec_addr,
                                    PAGEOFFSET(fi->spec_addr) ?  "in " : "");
                        	break;
			}
                        fprintf(fp, "%s of %ld pages)",
                                ordinal(offset+1, buf), chunk_size/PAGESIZE());
                }

		fi->retval = TRUE;
                fprintf(fp, "\n");
	}
}


static char *
page_usage_hdr = "ZONE  NAME        FREE   ACTIVE  INACTIVE_DIRTY  INACTIVE_CLEAN  MIN/LOW/HIGH";

/*
 *  Display info about the non-free pages in each zone.
 */
static int
dump_zone_page_usage(void)
{
	int i, n;
	ulong value, node_zones;
	struct node_table *nt;
	ulong inactive_dirty_pages, inactive_clean_pages, active_pages; 
	ulong free_pages, pages_min, pages_low, pages_high;
	char namebuf[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];

	if (!VALID_MEMBER(zone_struct_inactive_dirty_pages) ||
	    !VALID_MEMBER(zone_struct_inactive_clean_pages) ||
	    !VALID_MEMBER(zone_struct_active_pages) ||
	    !VALID_MEMBER(zone_struct_pages_min) ||
	    !VALID_MEMBER(zone_struct_pages_low) ||
	    !VALID_MEMBER(zone_struct_pages_high))
		return FALSE;

	fprintf(fp, "\n");

        for (n = 0; n < vt->numnodes; n++) {
                nt = &vt->node_table[n];
                node_zones = nt->pgdat + OFFSET(pglist_data_node_zones);
                
		if ((vt->numnodes > 1) && (vt->flags & NODES)) {
                	fprintf(fp, "%sNODE\n %2d\n",
                        	n ? "\n" : "", nt->node_id);
                }
		fprintf(fp, "%s\n", page_usage_hdr);

                for (i = 0; i < vt->nr_zones; i++) {
			readmem(node_zones+OFFSET(zone_struct_free_pages),
                                KVADDR, &free_pages, sizeof(ulong),
                                "node_zones free_pages", FAULT_ON_ERROR);
		        readmem(node_zones+
				OFFSET(zone_struct_inactive_dirty_pages),
		                KVADDR, &inactive_dirty_pages, sizeof(ulong),
		                "node_zones inactive_dirty_pages", 
				FAULT_ON_ERROR);
		        readmem(node_zones+
				OFFSET(zone_struct_inactive_clean_pages),
		                KVADDR, &inactive_clean_pages, sizeof(ulong),
		                "node_zones inactive_clean_pages", 
				FAULT_ON_ERROR);
		        readmem(node_zones+OFFSET(zone_struct_active_pages),
		                KVADDR, &active_pages, sizeof(ulong),
		                "node_zones active_pages", FAULT_ON_ERROR);
		        readmem(node_zones+OFFSET(zone_struct_pages_min),
		                KVADDR, &pages_min, sizeof(ulong),
		                "node_zones pages_min", FAULT_ON_ERROR);
		        readmem(node_zones+OFFSET(zone_struct_pages_low),
		                KVADDR, &pages_low, sizeof(ulong),
		                "node_zones pages_low", FAULT_ON_ERROR);
		        readmem(node_zones+OFFSET(zone_struct_pages_high),
		                KVADDR, &pages_high, sizeof(ulong),
		                "node_zones pages_high", FAULT_ON_ERROR);

                        readmem(node_zones+OFFSET(zone_struct_name), KVADDR,
                                &value, sizeof(void *),
                                "node_zones name", FAULT_ON_ERROR);
                        if (read_string(value, buf1, BUFSIZE-1))
                                sprintf(namebuf, "%-8s", buf1);
                        else
                                sprintf(namebuf, "(unknown)");

		        sprintf(buf2, "%ld/%ld/%ld", 
				pages_min, pages_low, pages_high);
		        fprintf(fp, "%3d   %s %7ld  %7ld %15ld %15ld  %s\n",
				i,
				namebuf,
		                free_pages,
		                active_pages,
		                inactive_dirty_pages,
		                inactive_clean_pages,
		                mkstring(buf3, strlen("MIN/LOW/HIGH"), 
				CENTER, buf2));

			node_zones += SIZE(zone_struct);
		}
	}

	return TRUE;
}


/*
 *  Dump the num "order" contents of the zone_t free_area array.
 */
char *free_area_hdr3 = "AREA    SIZE  FREE_AREA_STRUCT\n";
char *free_area_hdr4 = "AREA    SIZE  FREE_AREA_STRUCT  BLOCKS  PAGES\n";

static int
dump_zone_free_area(ulong free_area, int num, ulong verbose, 
		    struct free_page_callback_data *callback_data)
{
	int i, j;
	long chunk_size;
	int flen, total_free, cnt;
	char buf[BUFSIZE];
	ulong free_area_buf[3];
	char *free_area_buf2;
	char *free_list_buf;
	ulong free_list;
	struct list_data list_data, *ld;
	int list_count;
	ulong *free_ptr;

	list_count = 0;
	free_list_buf = free_area_buf2 = NULL;

	if (VALID_STRUCT(free_area_struct)) {
		if (SIZE(free_area_struct) != (3 * sizeof(ulong)))
			error(FATAL, 
			    "unrecognized free_area_struct size: %ld\n", 
				SIZE(free_area_struct));
		list_count = 1;
	} else if (VALID_STRUCT(free_area)) {
                if (SIZE(free_area) == (3 * sizeof(ulong)))
			list_count = 1;
		else {
			list_count = MEMBER_SIZE("free_area", 
				"free_list")/SIZE(list_head);
			free_area_buf2 = GETBUF(SIZE(free_area));
			free_list_buf = GETBUF(SIZE(list_head));
			readmem(free_area, KVADDR, free_area_buf2,
				SIZE(free_area), "free_area struct", 
				FAULT_ON_ERROR);
		}
	} else error(FATAL, 
		"neither free_area_struct or free_area structures exist\n");

	ld = &list_data;

	if (!verbose)
		fprintf(fp, "%s", free_area_hdr4);

	total_free = 0;
	flen = MAX(VADDR_PRLEN, strlen("FREE_AREA_STRUCT"));

	if (list_count > 1)
		goto multiple_lists;

	for (i = 0; i < num; i++, 
	     free_area += SIZE_OPTION(free_area_struct, free_area)) {
		if (verbose)
			fprintf(fp, "%s", free_area_hdr3);
		fprintf(fp, "%3d ", i);
		chunk_size = power(2, i);
		sprintf(buf, "%ldk", (chunk_size * PAGESIZE())/1024);
                fprintf(fp, " %7s  ", buf);

                readmem(free_area, KVADDR, free_area_buf,
                        sizeof(ulong) * 3, "free_area_struct", FAULT_ON_ERROR);

		fprintf(fp, "%s  ",
			mkstring(buf, flen, CENTER|LONG_HEX, MKSTR(free_area)));

		if (free_area_buf[0] == free_area) {
			if (verbose)
				fprintf(fp, "\n");
			else
				fprintf(fp, "%6d %6d\n", 0, 0);
			continue;
		}
	
		if (verbose)
			fprintf(fp, "\n");

                BZERO(ld, sizeof(struct list_data));
                ld->flags = verbose | RETURN_ON_DUPLICATE;
                ld->start = free_area_buf[0];
                ld->end = free_area;
		if (VALID_MEMBER(page_list_next))
			ld->list_head_offset = OFFSET(page_list);
        	else if (VALID_MEMBER(page_lru))
			ld->list_head_offset = OFFSET(page_lru)+
				OFFSET(list_head_next);
		else error(FATAL, 
			"neither page.list or page.lru exist?\n");

                cnt = do_list(ld);
		if (cnt < 0) {
			error(pc->curcmd_flags & IGNORE_ERRORS ? INFO : FATAL, 
			    "corrupted free list from free_area_struct: %lx\n", 
				free_area);
			if (pc->curcmd_flags & IGNORE_ERRORS)
				break;
		}

		if (!verbose)
			fprintf(fp, "%6d %6ld\n", cnt, cnt*chunk_size);

                total_free += (cnt * chunk_size);
	}

	return total_free;

multiple_lists:

	for (i = 0; i < num; i++, 
	     free_area += SIZE_OPTION(free_area_struct, free_area)) {

		readmem(free_area, KVADDR, free_area_buf2,
			SIZE(free_area), "free_area struct", FAULT_ON_ERROR);

		for (j = 0, free_list = free_area; j < list_count; 
		     j++, free_list += SIZE(list_head)) {

			if (verbose)
				fprintf(fp, "%s", free_area_hdr3);

			fprintf(fp, "%3d ", i);
			chunk_size = power(2, i);
			sprintf(buf, "%ldk", (chunk_size * PAGESIZE())/1024);
			fprintf(fp, " %7s  ", buf);

			readmem(free_list, KVADDR, free_list_buf,
				SIZE(list_head), "free_area free_list", 
				FAULT_ON_ERROR);
			fprintf(fp, "%s  ",
				mkstring(buf, flen, CENTER|LONG_HEX, MKSTR(free_list)));

			free_ptr = (ulong *)free_list_buf;

			if (*free_ptr == free_list) {
				if (verbose)
					fprintf(fp, "\n");
				else
					fprintf(fp, "%6d %6d\n", 0, 0);
				continue;
			}
			if (verbose)
				fprintf(fp, "\n");

			BZERO(ld, sizeof(struct list_data));
			ld->flags = verbose | RETURN_ON_DUPLICATE;
			ld->start = *free_ptr;
			ld->end = free_list;
			ld->list_head_offset = OFFSET(page_lru) + 
				OFFSET(list_head_next);
			if (callback_data) {
				ld->flags &= ~VERBOSE;
				ld->flags |= (LIST_CALLBACK|CALLBACK_RETURN);
				ld->callback_func = free_page_callback;
				ld->callback_data = (void *)callback_data;
				callback_data->chunk_size = chunk_size;
			}
			cnt = do_list(ld);
			if (cnt < 0) {
				error(pc->curcmd_flags & IGNORE_ERRORS ? INFO : FATAL, 
				    "corrupted free list %d from free_area struct: %lx\n", 
					j, free_area);
				if (pc->curcmd_flags & IGNORE_ERRORS)
					goto bailout;
			}

			if (callback_data && callback_data->found) {
				fprintf(fp, "%lx\n", callback_data->page);
				goto bailout;
			}

			if (!verbose)
				fprintf(fp, "%6d %6ld\n", cnt, cnt*chunk_size);

			total_free += (cnt * chunk_size);
		}
	}

bailout:
	FREEBUF(free_area_buf2);
	FREEBUF(free_list_buf);
	return total_free;
}

/*
 *  dump_kmeminfo displays basic memory use information typically shown 
 *  by /proc/meminfo, and then some...
 */

char *kmeminfo_hdr = "                 PAGES        TOTAL      PERCENTAGE\n";

static void
dump_kmeminfo(void)
{
	int i, len;
	ulong totalram_pages;
	ulong freeram_pages;
	ulong used_pages;
	ulong shared_pages;
	ulong buffer_pages;
	ulong subtract_buffer_pages;
	ulong totalswap_pages, totalused_pages;
        ulong totalhigh_pages;
        ulong freehighmem_pages;
        ulong totallowmem_pages;
        ulong freelowmem_pages;
	ulong allowed;
	long committed;
	ulong overcommit_kbytes = 0;
	int overcommit_ratio;
	ulong hugetlb_total_pages, hugetlb_total_free_pages = 0;
	int done_hugetlb_calc = 0; 
	long nr_file_pages, nr_slab;
	ulong swapper_space_nrpages;
	ulong pct;
	uint tmp;
	struct meminfo meminfo;
	struct gnu_request req;
	long page_cache_size;
        ulong get_totalram;
        ulong get_buffers;
        ulong get_slabs;
	char buf[BUFSIZE];


	BZERO(&meminfo, sizeof(struct meminfo));
	meminfo.flags = GET_ALL;
	dump_mem_map(&meminfo);
	get_totalram = meminfo.get_totalram;
	shared_pages = meminfo.get_shared;
	get_buffers = meminfo.get_buffers;
	get_slabs = meminfo.get_slabs;

	/*
	 *  If vm_stat array exists, override page search info.
	 */
	if (vm_stat_init()) {
		if (dump_vm_stat("NR_SLAB", &nr_slab, 0))
			get_slabs = nr_slab;
		else if (dump_vm_stat("NR_SLAB_RECLAIMABLE", &nr_slab, 0)) {
			get_slabs = nr_slab;
			if (dump_vm_stat("NR_SLAB_UNRECLAIMABLE", &nr_slab, 0))
				get_slabs += nr_slab;
		} else if (dump_vm_stat("NR_SLAB_RECLAIMABLE_B", &nr_slab, 0)) {
			/* 5.9 and later */
			get_slabs = nr_slab;
			if (dump_vm_stat("NR_SLAB_UNRECLAIMABLE_B", &nr_slab, 0))
				get_slabs += nr_slab;
		}
	}

	fprintf(fp, "%s", kmeminfo_hdr);
	/*
	 *  Get total RAM based upon how the various versions of si_meminfo()
         *  have done it, latest to earliest:
	 *
         *    Prior to 2.3.36, count all mem_map pages minus the reserved ones.
         *    From 2.3.36 onwards, use "totalram_pages" if set.
	 */
	if (symbol_exists("totalram_pages") ||
	    symbol_exists("_totalram_pages")) {
		totalram_pages = vt->totalram_pages ? 
			vt->totalram_pages : get_totalram; 
	} else 
		totalram_pages = get_totalram;

	fprintf(fp, "%13s  %7ld  %11s         ----\n", "TOTAL MEM", 
		totalram_pages, pages_to_size(totalram_pages, buf));

	/*
	 *  Get free pages from dump_free_pages() or its associates.
	 *  Used pages are a free-bee...
	 */
	meminfo.flags = GET_FREE_PAGES;
	vt->dump_free_pages(&meminfo);
	freeram_pages = meminfo.retval;
        pct = (freeram_pages * 100)/totalram_pages;
	fprintf(fp, "%13s  %7ld  %11s  %3ld%% of TOTAL MEM\n", 
		"FREE", freeram_pages, pages_to_size(freeram_pages, buf), pct);

	used_pages = totalram_pages - freeram_pages;
        pct = (used_pages * 100)/totalram_pages;
        fprintf(fp, "%13s  %7ld  %11s  %3ld%% of TOTAL MEM\n", 
		"USED", used_pages, pages_to_size(used_pages, buf), pct);

	/*
	 *  Get shared pages from dump_mem_map().  Note that this is done
         *  differently than the kernel -- it just tallies the non-reserved
         *  pages that have a count of greater than 1.
	 */
        pct = (shared_pages * 100)/totalram_pages;
        fprintf(fp, "%13s  %7ld  %11s  %3ld%% of TOTAL MEM\n", 
		"SHARED", shared_pages, pages_to_size(shared_pages, buf), pct);

	subtract_buffer_pages = 0;
	if (symbol_exists("buffermem_pages")) { 
                get_symbol_data("buffermem_pages", sizeof(int), &tmp);
		buffer_pages = (ulong)tmp;
	} else if (symbol_exists("buffermem")) {
                get_symbol_data("buffermem", sizeof(int), &tmp);
		buffer_pages = BTOP(tmp);
	} else if ((THIS_KERNEL_VERSION >= LINUX(2,6,0)) && 
		symbol_exists("nr_blockdev_pages")) {
		subtract_buffer_pages = buffer_pages = nr_blockdev_pages();
	} else
		buffer_pages = 0;

        pct = (buffer_pages * 100)/totalram_pages;
        fprintf(fp, "%13s  %7ld  %11s  %3ld%% of TOTAL MEM\n", 
		"BUFFERS", buffer_pages, pages_to_size(buffer_pages, buf), pct);

	if (CRASHDEBUG(1)) 
        	error(NOTE, "pages with buffers: %ld\n", get_buffers);

	/*
	 *  page_cache_size has evolved from a long to an atomic_t to
	 *  not existing at all.
	 */
	
	if (symbol_exists("page_cache_size")) {
		get_symbol_type("page_cache_size", NULL, &req);
        	if (req.length == sizeof(int)) {
                	get_symbol_data("page_cache_size", sizeof(int), &tmp);
                	page_cache_size = (long)tmp;
        	} else
                	get_symbol_data("page_cache_size", sizeof(long),
                        	&page_cache_size);
		page_cache_size -= subtract_buffer_pages;
	} else if (symbol_exists("nr_pagecache")) {
               	get_symbol_data("nr_pagecache", sizeof(int), &tmp);
               	page_cache_size = (long)tmp;
		page_cache_size -= subtract_buffer_pages;
	} else if (dump_vm_stat("NR_FILE_PAGES", &nr_file_pages, 0)) {
		char *swapper_space = GETBUF(SIZE(address_space));

		swapper_space_nrpages = 0;
		if (symbol_exists("nr_swapper_spaces") &&
			(len = get_array_length("nr_swapper_spaces",
				NULL, 0))) {
			char *nr_swapper_space =
				GETBUF(len * sizeof(unsigned int));
			readmem(symbol_value("nr_swapper_spaces"), KVADDR,
				nr_swapper_space,  len * sizeof(unsigned int),
				"nr_swapper_space", RETURN_ON_ERROR);
			for (i = 0; i < len; i++) {
				int j;
				unsigned long sa;
				unsigned int banks = UINT(nr_swapper_space +
					(i * sizeof(unsigned int)));

				if (!banks)
					continue;

				readmem(symbol_value("swapper_spaces") +
					(i * sizeof(void *)),KVADDR,
					&sa, sizeof(void *),
					"swapper_space", RETURN_ON_ERROR);

				if (!sa)
					continue;

				for (j = 0; j < banks; j++) {
					readmem(sa + j * SIZE(address_space),
						KVADDR, swapper_space,
						SIZE(address_space),
						"swapper_space",
						RETURN_ON_ERROR);
					swapper_space_nrpages +=
						ULONG(swapper_space +
						OFFSET(address_space_nrpages));
				}
			}
			FREEBUF(nr_swapper_space);
		} else if (symbol_exists("swapper_spaces") &&
		    (len = get_array_length("swapper_spaces", NULL, 0))) {
			for (i = 0; i < len; i++) {
		    		if (!readmem(symbol_value("swapper_spaces") + 
				    i * SIZE(address_space), KVADDR, 
		    		    swapper_space, SIZE(address_space), 
				    "swapper_space", RETURN_ON_ERROR))
					break;
				swapper_space_nrpages += ULONG(swapper_space + 
					OFFSET(address_space_nrpages));
			}
                } else if (symbol_exists("swapper_space") &&
		    readmem(symbol_value("swapper_space"), KVADDR, 
		    swapper_space, SIZE(address_space), "swapper_space", 
		    RETURN_ON_ERROR))
			swapper_space_nrpages = ULONG(swapper_space + 
				OFFSET(address_space_nrpages));

		page_cache_size = nr_file_pages - swapper_space_nrpages -
			buffer_pages;
		FREEBUF(swapper_space);
	} else
		page_cache_size = 0;


	if (page_cache_size < 0) {
		error(INFO, "page_cache_size went negative (%ld), setting to 0\n",
			page_cache_size);
		page_cache_size = 0;
	}
        pct = (page_cache_size * 100)/totalram_pages;
        fprintf(fp, "%13s  %7ld  %11s  %3ld%% of TOTAL MEM\n", 
		"CACHED", page_cache_size, 
		pages_to_size(page_cache_size, buf), pct);

	/*
 	 *  Although /proc/meminfo doesn't show it, show how much memory
	 *  the slabs take up.
	 */

        pct = (get_slabs * 100)/totalram_pages;
	fprintf(fp, "%13s  %7ld  %11s  %3ld%% of TOTAL MEM\n",
		"SLAB", get_slabs, pages_to_size(get_slabs, buf), pct);

	if (symbol_exists("totalhigh_pages") ||
	    symbol_exists("_totalhigh_pages")) {
		totalhigh_pages = vt->totalhigh_pages;

		pct = totalhigh_pages ?
			(totalhigh_pages * 100)/totalram_pages : 0;
                fprintf(fp, "\n%13s  %7ld  %11s  %3ld%% of TOTAL MEM\n", 
			"TOTAL HIGH", totalhigh_pages, 
			pages_to_size(totalhigh_pages, buf), pct);

		meminfo.flags = GET_FREE_HIGHMEM_PAGES;
                vt->dump_free_pages(&meminfo);
		freehighmem_pages = meminfo.retval;
        	pct = freehighmem_pages ?  
			(freehighmem_pages * 100)/totalhigh_pages : 0;
                fprintf(fp, "%13s  %7ld  %11s  %3ld%% of TOTAL HIGH\n", 
			"FREE HIGH", freehighmem_pages, 
			pages_to_size(freehighmem_pages, buf), pct);

                totallowmem_pages = totalram_pages - totalhigh_pages;
		pct = (totallowmem_pages * 100)/totalram_pages;
                fprintf(fp, "%13s  %7ld  %11s  %3ld%% of TOTAL MEM\n", 
			"TOTAL LOW", totallowmem_pages, 
			pages_to_size(totallowmem_pages, buf), pct);

                freelowmem_pages = freeram_pages - freehighmem_pages;
        	pct = (freelowmem_pages * 100)/totallowmem_pages;
                fprintf(fp, "%13s  %7ld  %11s  %3ld%% of TOTAL LOW\n", 
			"FREE LOW", freelowmem_pages, 
			pages_to_size(freelowmem_pages, buf), pct);
        }

	if (get_hugetlb_total_pages(&hugetlb_total_pages,
	    &hugetlb_total_free_pages)) {
		done_hugetlb_calc = 1;

		fprintf(fp, "\n%13s  %7ld  %11s         ----\n", 
			"TOTAL HUGE", hugetlb_total_pages, 
			pages_to_size(hugetlb_total_pages, buf));
		pct = hugetlb_total_free_pages ?
			(hugetlb_total_free_pages * 100) /
			hugetlb_total_pages : 0;
		fprintf(fp, "%13s  %7ld  %11s  %3ld%% of TOTAL HUGE\n", 
			"HUGE FREE",
			hugetlb_total_free_pages,
			pages_to_size(hugetlb_total_free_pages, buf), pct);
	}

        /*
         *  get swap data from dump_swap_info().
         */
	fprintf(fp, "\n");
	if (symbol_exists("swapper_space") || symbol_exists("swapper_spaces")) {
		if (dump_swap_info(RETURN_ON_ERROR, &totalswap_pages, 
		    &totalused_pages)) {
			fprintf(fp, "%13s  %7ld  %11s         ----\n", 
				"TOTAL SWAP", totalswap_pages, 
				pages_to_size(totalswap_pages, buf));
			pct = totalswap_pages ? (totalused_pages * 100) /
				totalswap_pages : 0;
			fprintf(fp, "%13s  %7ld  %11s  %3ld%% of TOTAL SWAP\n",
				"SWAP USED", totalused_pages,
				pages_to_size(totalused_pages, buf), pct);
	 		pct = totalswap_pages ? 
				((totalswap_pages - totalused_pages) *
				100) / totalswap_pages : 0;
			fprintf(fp, "%13s  %7ld  %11s  %3ld%% of TOTAL SWAP\n", 
				"SWAP FREE",
				totalswap_pages - totalused_pages,
				pages_to_size(totalswap_pages - totalused_pages, 
				buf), pct);
		} else
			error(INFO, 
			    "swap_info[%ld].swap_map at %lx is inaccessible\n",
				totalused_pages, totalswap_pages);
	}

	/*
	 * Show committed memory
	 */
	if (kernel_symbol_exists("sysctl_overcommit_memory")) {

		fprintf(fp, "\n");
		if (kernel_symbol_exists("sysctl_overcommit_kbytes"))
			get_symbol_data("sysctl_overcommit_kbytes",
				sizeof(ulong), &overcommit_kbytes);

		if (overcommit_kbytes)
			allowed = overcommit_kbytes >>
				(machdep->pageshift - 10);
		else {
			get_symbol_data("sysctl_overcommit_ratio",
				sizeof(int), &overcommit_ratio);

			if (!done_hugetlb_calc)
				goto bailout;

			allowed = ((totalram_pages - hugetlb_total_pages)
				* overcommit_ratio / 100);
		}
		if (symbol_exists("vm_committed_as")) {
			if (INVALID_MEMBER(percpu_counter_count))
				goto bailout;

			readmem(symbol_value("vm_committed_as") +
				OFFSET(percpu_counter_count),
				KVADDR, &committed, sizeof(long),
				"percpu_counter count", FAULT_ON_ERROR);

			/* Ensure always positive */
			if (committed < 0)
				committed = 0;
		} else {
			if (INVALID_MEMBER(atomic_t_counter))
				goto bailout;

			readmem(symbol_value("vm_committed_space") +
				OFFSET(atomic_t_counter), KVADDR,
				&committed, sizeof(int), 
				"atomic_t counter", FAULT_ON_ERROR);
		}
		allowed += totalswap_pages;
		fprintf(fp, "%13s  %7ld  %11s         ----\n",
			"COMMIT LIMIT", allowed,
			pages_to_size(allowed, buf));

		if (allowed) {
			pct = committed ? ((committed * 100)
				/ allowed) : 0;
			fprintf(fp, "%13s  %7ld  %11s  %3ld%% of TOTAL LIMIT\n",
				"COMMITTED", committed,
				pages_to_size(committed, buf), pct);
		} else
			fprintf(fp, "%13s  %7ld  %11s         ----\n",
				"COMMITTED", committed,
				pages_to_size(committed, buf));
	}
bailout:
	dump_zone_page_usage();
}

/*
 *  Emulate 2.6 nr_blockdev_pages() function.
 */
static ulong
nr_blockdev_pages(void)
{
        struct list_data list_data, *ld;
	int i, bdevcnt;
	ulong inode, address_space;
	ulong nrpages;
	char *block_device_buf, *inode_buf, *address_space_buf;

	if (!kernel_symbol_exists("all_bdevs"))
		return nr_blockdev_pages_v2();

        ld = &list_data;
        BZERO(ld, sizeof(struct list_data));
	get_symbol_data("all_bdevs", sizeof(void *), &ld->start);
	if (empty_list(ld->start))
		return 0;
	ld->flags |= LIST_ALLOCATE;
	ld->end = symbol_value("all_bdevs");
        ld->list_head_offset = OFFSET(block_device_bd_list);

	block_device_buf = GETBUF(SIZE(block_device));
	inode_buf = GETBUF(SIZE(inode));
	address_space_buf = GETBUF(SIZE(address_space));

        bdevcnt = do_list(ld);

	/*
	 *  go through the block_device list, emulating:
	 *
	 *      ret += bdev->bd_inode->i_mapping->nrpages;
	 */
	for (i = nrpages = 0; i < bdevcnt; i++) {
                readmem(ld->list_ptr[i], KVADDR, block_device_buf, 
			SIZE(block_device), "block_device buffer", 
			FAULT_ON_ERROR);
		inode = ULONG(block_device_buf + OFFSET(block_device_bd_inode));
                readmem(inode, KVADDR, inode_buf, SIZE(inode), "inode buffer", 
			FAULT_ON_ERROR);
		address_space = ULONG(inode_buf + OFFSET(inode_i_mapping));
                readmem(address_space, KVADDR, address_space_buf, 
			SIZE(address_space), "address_space buffer", 
			FAULT_ON_ERROR);
		nrpages += ULONG(address_space_buf + 
			OFFSET(address_space_nrpages));
	}

	FREEBUF(ld->list_ptr);
	FREEBUF(block_device_buf);
	FREEBUF(inode_buf);
	FREEBUF(address_space_buf);

	return nrpages;
} 

/*
 *  Emulate 5.9 nr_blockdev_pages() function.
 */
static ulong
nr_blockdev_pages_v2(void)
{
	struct list_data list_data, *ld;
	ulong bd_sb, address_space;
	ulong nrpages;
	int i, inode_count;
	char *inode_buf, *address_space_buf;

	ld = &list_data;
	BZERO(ld, sizeof(struct list_data));

	get_symbol_data("blockdev_superblock", sizeof(void *), &bd_sb);
	readmem(bd_sb + OFFSET(super_block_s_inodes), KVADDR, &ld->start,
		sizeof(ulong), "blockdev_superblock.s_inodes", FAULT_ON_ERROR);

	if (empty_list(ld->start))
		return 0;
	ld->flags |= LIST_ALLOCATE;
	ld->end = bd_sb + OFFSET(super_block_s_inodes);
	ld->list_head_offset = OFFSET(inode_i_sb_list);

	inode_buf = GETBUF(SIZE(inode));
	address_space_buf = GETBUF(SIZE(address_space));

	inode_count = do_list(ld);

	/*
	 *  go through the s_inodes list, emulating:
	 *
	 *      ret += inode->i_mapping->nrpages;
	 */
	for (i = nrpages = 0; i < inode_count; i++) {
		readmem(ld->list_ptr[i], KVADDR, inode_buf, SIZE(inode), "inode buffer",
			FAULT_ON_ERROR);
		address_space = ULONG(inode_buf + OFFSET(inode_i_mapping));
		readmem(address_space, KVADDR, address_space_buf, SIZE(address_space),
			"address_space buffer", FAULT_ON_ERROR);
		nrpages += ULONG(address_space_buf + OFFSET(address_space_nrpages));
	}

	FREEBUF(ld->list_ptr);
	FREEBUF(inode_buf);
	FREEBUF(address_space_buf);

	return nrpages;
}

/*
 *  dump_vmlist() displays information from the vmlist.
 */

static void
dump_vmlist(struct meminfo *vi)
{
	char buf[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	ulong vmlist;
	ulong addr, size, next, pcheck, count, verified; 
	physaddr_t paddr;
	int mod_vmlist;

	if (vt->flags & USE_VMAP_AREA) {
		dump_vmap_area(vi);
		return;
	}

	get_symbol_data("vmlist", sizeof(void *), &vmlist);
	next = vmlist;
	count = verified = 0;
	mod_vmlist = kernel_symbol_exists("mod_vmlist");

	while (next) {
		if (!(pc->curcmd_flags & HEADER_PRINTED) && (next == vmlist) && 
		    !(vi->flags & (GET_HIGHEST|GET_PHYS_TO_VMALLOC|
		      GET_VMLIST_COUNT|GET_VMLIST|VMLIST_VERIFY))) {
			fprintf(fp, "%s  ", 
			    mkstring(buf, MAX(strlen("VM_STRUCT"), VADDR_PRLEN),
			    	CENTER|LJUST, "VM_STRUCT"));
			fprintf(fp, "%s    SIZE\n",
			    mkstring(buf, (VADDR_PRLEN * 2) + strlen(" - "),
				CENTER|LJUST, "ADDRESS RANGE"));
			pc->curcmd_flags |= HEADER_PRINTED;
		}

                readmem(next+OFFSET(vm_struct_addr), KVADDR, 
			&addr, sizeof(void *),
                        "vmlist addr", FAULT_ON_ERROR);
                readmem(next+OFFSET(vm_struct_size), KVADDR, 
			&size, sizeof(ulong),
                        "vmlist size", FAULT_ON_ERROR);

		if (vi->flags & (GET_VMLIST_COUNT|GET_VMLIST)) {
			/*
			 *  Preceding GET_VMLIST_COUNT set vi->retval.
			 */
			if (vi->flags & GET_VMLIST) {
				if (count < vi->retval) {
					vi->vmlist[count].addr = addr;
					vi->vmlist[count].size = size;
				}
			}
			count++;
			goto next_entry;
		}

		if (!(vi->flags & ADDRESS_SPECIFIED) || 
		    ((vi->memtype == KVADDR) &&
		    ((vi->spec_addr >= addr) && (vi->spec_addr < (addr+size))))) {
			if (vi->flags & VMLIST_VERIFY) {
				verified++;
				break;
			}	
			fprintf(fp, "%s%s  %s - %s  %6ld\n",
				mkstring(buf,VADDR_PRLEN, LONG_HEX|CENTER|LJUST,
				MKSTR(next)), space(MINSPACE-1),
				mkstring(buf1, VADDR_PRLEN, LONG_HEX|RJUST,
				MKSTR(addr)),
				mkstring(buf2, VADDR_PRLEN, LONG_HEX|LJUST,
				MKSTR(addr+size)),
				size);
		}

		if ((vi->flags & ADDRESS_SPECIFIED) && 
		     (vi->memtype == PHYSADDR)) {
			for (pcheck = addr; pcheck < (addr+size); 
			     pcheck += PAGESIZE()) {
				if (!kvtop(NULL, pcheck, &paddr, 0))
					continue;
		    		if ((vi->spec_addr >= paddr) && 
				    (vi->spec_addr < (paddr+PAGESIZE()))) {
					if (vi->flags & GET_PHYS_TO_VMALLOC) {
						vi->retval = pcheck +
						    PAGEOFFSET(vi->spec_addr);
						return;
				        } else
						fprintf(fp,
						"%s%s  %s - %s  %6ld\n",
						mkstring(buf, VADDR_PRLEN,
						LONG_HEX|CENTER|LJUST,
						MKSTR(next)), space(MINSPACE-1),
						mkstring(buf1, VADDR_PRLEN,
						LONG_HEX|RJUST, MKSTR(addr)),
						mkstring(buf2, VADDR_PRLEN,
						LONG_HEX|LJUST,
						MKSTR(addr+size)), size);
					break;
				}
			}

		}
next_entry:
                readmem(next+OFFSET(vm_struct_next), 
			KVADDR, &next, sizeof(void *),
                        "vmlist next", FAULT_ON_ERROR);
		
		if (!next && mod_vmlist) {
			get_symbol_data("mod_vmlist", sizeof(void *), &next);
			mod_vmlist = FALSE;
		}
	}

	if (vi->flags & GET_HIGHEST)
		vi->retval = addr+size;

	if (vi->flags & GET_VMLIST_COUNT)
		vi->retval = count;

	if (vi->flags & VMLIST_VERIFY)
		vi->retval = verified;
}

static void
dump_vmap_area(struct meminfo *vi)
{
	int i, cnt;
	ulong start, end, vm_struct, flags, vm;
	struct list_data list_data, *ld;
	char *vmap_area_buf; 
	ulong size, pcheck, count, verified; 
	physaddr_t paddr;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];

#define VM_VM_AREA 0x4   /* mm/vmalloc.c */

	vmap_area_buf = GETBUF(SIZE(vmap_area));
	start = count = verified = size = 0;

	ld = &list_data;
	BZERO(ld, sizeof(struct list_data));
	ld->flags = LIST_HEAD_FORMAT|LIST_HEAD_POINTER|LIST_ALLOCATE;
	get_symbol_data("vmap_area_list", sizeof(void *), &ld->start);
	ld->list_head_offset = OFFSET(vmap_area_list);
	ld->end = symbol_value("vmap_area_list");
	cnt = do_list(ld);
	if (cnt < 0) {
		FREEBUF(vmap_area_buf);
		error(WARNING, "invalid/corrupt vmap_area_list\n"); 
		vi->retval = 0;
		return;
	}

	for (i = 0; i < cnt; i++) {
		if (!(pc->curcmd_flags & HEADER_PRINTED) && (i == 0) && 
		    !(vi->flags & (GET_HIGHEST|GET_PHYS_TO_VMALLOC|
		      GET_VMLIST_COUNT|GET_VMLIST|VMLIST_VERIFY))) {
			fprintf(fp, "%s  ", 
			    mkstring(buf1, MAX(strlen("VMAP_AREA"), VADDR_PRLEN),
			    	CENTER|LJUST, "VMAP_AREA"));
			fprintf(fp, "%s  ", 
			    mkstring(buf1, MAX(strlen("VM_STRUCT"), VADDR_PRLEN),
			    	CENTER|LJUST, "VM_STRUCT"));
			fprintf(fp, "%s     SIZE\n",
			    mkstring(buf1, (VADDR_PRLEN * 2) + strlen(" - "),
				CENTER|LJUST, "ADDRESS RANGE"));
			pc->curcmd_flags |= HEADER_PRINTED;
		}

		readmem(ld->list_ptr[i], KVADDR, vmap_area_buf,
                        SIZE(vmap_area), "vmap_area struct", FAULT_ON_ERROR); 

		if (VALID_MEMBER(vmap_area_flags)) {
			flags = ULONG(vmap_area_buf + OFFSET(vmap_area_flags));
			if (flags != VM_VM_AREA)
				continue;
		} else {
			vm = ULONG(vmap_area_buf + OFFSET(vmap_area_vm));
			if (!vm)
				continue;
		}
		start = ULONG(vmap_area_buf + OFFSET(vmap_area_va_start));
		end = ULONG(vmap_area_buf + OFFSET(vmap_area_va_end));
		vm_struct = ULONG(vmap_area_buf + OFFSET(vmap_area_vm));

		size = end - start;

		if (vi->flags & (GET_VMLIST_COUNT|GET_VMLIST)) {
			/*
			 *  Preceding GET_VMLIST_COUNT set vi->retval.
			 */
			if (vi->flags & GET_VMLIST) {
				if (count < vi->retval) {
					vi->vmlist[count].addr = start;
					vi->vmlist[count].size = size;
				}
			}
			count++;
			continue;
		}

		if (!(vi->flags & ADDRESS_SPECIFIED) || 
		    ((vi->memtype == KVADDR) &&
		    ((vi->spec_addr >= start) && (vi->spec_addr < (start+size))))) {
			if (vi->flags & VMLIST_VERIFY) {
				verified++;
				break;
			} 	
			fprintf(fp, "%s%s  %s%s  %s - %s  %7ld\n",
				mkstring(buf1,VADDR_PRLEN, LONG_HEX|CENTER|LJUST,
				MKSTR(ld->list_ptr[i])), space(MINSPACE-1),
				mkstring(buf2,VADDR_PRLEN, LONG_HEX|CENTER|LJUST,
				MKSTR(vm_struct)), space(MINSPACE-1),
				mkstring(buf3, VADDR_PRLEN, LONG_HEX|RJUST,
				MKSTR(start)),
				mkstring(buf4, VADDR_PRLEN, LONG_HEX|LJUST,
				MKSTR(start+size)),
				size);
		}

		if ((vi->flags & ADDRESS_SPECIFIED) && 
		     (vi->memtype == PHYSADDR)) {
			for (pcheck = start; pcheck < (start+size); 
			     pcheck += PAGESIZE()) {
				if (!kvtop(NULL, pcheck, &paddr, 0))
					continue;
		    		if ((vi->spec_addr >= paddr) && 
				    (vi->spec_addr < (paddr+PAGESIZE()))) {
					if (vi->flags & GET_PHYS_TO_VMALLOC) {
						vi->retval = pcheck +
						    PAGEOFFSET(vi->spec_addr);
						FREEBUF(ld->list_ptr);
						return;
				        } else
						fprintf(fp,
						"%s%s  %s%s  %s - %s  %7ld\n",
						mkstring(buf1,VADDR_PRLEN, 
						LONG_HEX|CENTER|LJUST,
						MKSTR(ld->list_ptr[i])), 
						space(MINSPACE-1),
						mkstring(buf2, VADDR_PRLEN,
						LONG_HEX|CENTER|LJUST,
						MKSTR(vm_struct)), space(MINSPACE-1),
						mkstring(buf3, VADDR_PRLEN,
						LONG_HEX|RJUST, MKSTR(start)),
						mkstring(buf4, VADDR_PRLEN,
						LONG_HEX|LJUST,
						MKSTR(start+size)), size);
					break;
				}
			}

		}
	}

	FREEBUF(vmap_area_buf);
	FREEBUF(ld->list_ptr);

	if (vi->flags & GET_HIGHEST)
		vi->retval = start+size;

	if (vi->flags & GET_VMLIST_COUNT)
		vi->retval = count;

	if (vi->flags & VMLIST_VERIFY)
		vi->retval = verified;
}


/*
 *  dump_page_lists() displays information from the active_list,
 *  inactive_dirty_list and inactive_clean_list from each zone.
 */
static int
dump_page_lists(struct meminfo *mi)
{
	int i, c, n, retval;
        ulong node_zones, pgdat;
	struct node_table *nt;
	struct list_data list_data, *ld;
	char buf[BUFSIZE];
	ulong value;
	ulong inactive_clean_pages, inactive_clean_list;
	int nr_active_pages, nr_inactive_pages;
	int nr_inactive_dirty_pages;

	ld = &list_data;

	retval = FALSE;
	nr_active_pages = nr_inactive_dirty_pages = -1;

	BZERO(ld, sizeof(struct list_data));
	ld->list_head_offset = OFFSET(page_lru);
	if (mi->flags & ADDRESS_SPECIFIED)
		ld->searchfor = mi->spec_addr;
	else if (mi->flags & VERBOSE)
		ld->flags |= VERBOSE;
	
	if (mi->flags & GET_ACTIVE_LIST) {
		if (!symbol_exists("active_list"))
			error(FATAL, 
			    "active_list does not exist in this kernel\n");

		if (symbol_exists("nr_active_pages"))
			get_symbol_data("nr_active_pages", sizeof(int), 
				&nr_active_pages);
		else
			error(FATAL, 
			    "nr_active_pages does not exist in this kernel\n");

		ld->end = symbol_value("active_list");
                readmem(ld->end, KVADDR, &ld->start, sizeof(void *),
                	"LIST_HEAD contents", FAULT_ON_ERROR);
		
		if (mi->flags & VERBOSE)
			fprintf(fp, "active_list:\n");

                if (ld->start == ld->end) {
                       c = 0;
                       ld->searchfor = 0;
                       if (mi->flags & VERBOSE)
                               fprintf(fp, "(empty)\n");
                } else {
                	hq_open();
                	c = do_list(ld);
                	hq_close();
		}

		if ((mi->flags & ADDRESS_SPECIFIED) && ld->searchfor) {
			fprintf(fp, "%lx\n", ld->searchfor);
			retval = TRUE;
                } else {
                        fprintf(fp, "%snr_active_pages: %d ", 
				mi->flags & VERBOSE ? "\n" : "",
                                nr_active_pages);
                        if (c != nr_active_pages)
                                fprintf(fp, "(found %d)\n", c);
                        else
                                fprintf(fp, "(verified)\n");
		}
	}

	if (mi->flags & GET_INACTIVE_LIST) {
		if (!symbol_exists("inactive_list"))
			error(FATAL, 
			    "inactive_list does not exist in this kernel\n");

		if (symbol_exists("nr_inactive_pages"))
			get_symbol_data("nr_inactive_pages", sizeof(int), 
				&nr_inactive_pages);
		else
			error(FATAL, 
			    "nr_active_pages does not exist in this kernel\n");

		ld->end = symbol_value("inactive_list");
                readmem(ld->end, KVADDR, &ld->start, sizeof(void *),
                	"LIST_HEAD contents", FAULT_ON_ERROR);
		
		if (mi->flags & VERBOSE)
			fprintf(fp, "inactive_list:\n");

                if (ld->start == ld->end) {
                       c = 0;
                       ld->searchfor = 0;
                       if (mi->flags & VERBOSE)
                               fprintf(fp, "(empty)\n");
                } else {
                	hq_open();
                	c = do_list(ld);
                	hq_close();
		}

		if ((mi->flags & ADDRESS_SPECIFIED) && ld->searchfor) {
			fprintf(fp, "%lx\n", ld->searchfor);
			retval = TRUE;
                } else {
                        fprintf(fp, "%snr_inactive_pages: %d ", 
				mi->flags & VERBOSE ? "\n" : "",
                                nr_inactive_pages);
                        if (c != nr_inactive_pages)
                                fprintf(fp, "(found %d)\n", c);
                        else
                                fprintf(fp, "(verified)\n");
		}
	}

        if (mi->flags & GET_INACTIVE_DIRTY) {
		if (!symbol_exists("inactive_dirty_list"))
			error(FATAL, 
		        "inactive_dirty_list does not exist in this kernel\n");

                if (symbol_exists("nr_inactive_dirty_pages"))
                        get_symbol_data("nr_inactive_dirty_pages", sizeof(int), 
                                &nr_inactive_dirty_pages);
		else
			error(FATAL,
                     "nr_inactive_dirty_pages does not exist in this kernel\n");

		ld->end = symbol_value("inactive_dirty_list");
                readmem(ld->end, KVADDR, &ld->start, sizeof(void *),
                	"LIST_HEAD contents", FAULT_ON_ERROR);

		if (mi->flags & VERBOSE)
			fprintf(fp, "%sinactive_dirty_list:\n",
				mi->flags & GET_ACTIVE_LIST ? "\n" : "");

                if (ld->start == ld->end) {
                       c = 0;
                       ld->searchfor = 0;
                       if (mi->flags & VERBOSE)
                               fprintf(fp, "(empty)\n");
                } else {
			hq_open();
        		c = do_list(ld);
        		hq_close();
		}

                if ((mi->flags & ADDRESS_SPECIFIED) && ld->searchfor) { 
                        fprintf(fp, "%lx\n", ld->searchfor);
			retval = TRUE;
		} else {
			fprintf(fp, "%snr_inactive_dirty_pages: %d ", 
				mi->flags & VERBOSE ? "\n" : "",
				nr_inactive_dirty_pages);
        		if (c != nr_inactive_dirty_pages)
                		fprintf(fp, "(found %d)\n", c);
        		else
                		fprintf(fp, "(verified)\n");
		}
        }

        if (mi->flags & GET_INACTIVE_CLEAN) {
		if (INVALID_MEMBER(zone_struct_inactive_clean_list))
			error(FATAL, 
		        "inactive_clean_list(s) do not exist in this kernel\n");

        	get_symbol_data("pgdat_list", sizeof(void *), &pgdat);

                if ((mi->flags & VERBOSE) && 
		    (mi->flags & (GET_ACTIVE_LIST|GET_INACTIVE_DIRTY)))
			fprintf(fp, "\n");

        	for (n = 0; pgdat; n++) {
                	nt = &vt->node_table[n];

                	node_zones = nt->pgdat + OFFSET(pglist_data_node_zones);

                	for (i = 0; i < vt->nr_zones; i++) {
                        	readmem(node_zones+OFFSET(zone_struct_name), 
					KVADDR, &value, sizeof(void *),
                                	"zone_struct name", FAULT_ON_ERROR);
                        	if (!read_string(value, buf, BUFSIZE-1))
                                	sprintf(buf, "(unknown) ");

                		if (mi->flags & VERBOSE) {
					if (vt->numnodes > 1)
                        			fprintf(fp, "NODE %d ", n);
                        		fprintf(fp, 
				            "\"%s\" inactive_clean_list:\n", 
						buf);
				}

				readmem(node_zones +
				    OFFSET(zone_struct_inactive_clean_pages),
                                    KVADDR, &inactive_clean_pages, 
				    sizeof(ulong), "inactive_clean_pages", 
				    FAULT_ON_ERROR);

                                readmem(node_zones +
                                    OFFSET(zone_struct_inactive_clean_list),
                                    KVADDR, &inactive_clean_list, 
                                    sizeof(ulong), "inactive_clean_list", 
                                    FAULT_ON_ERROR);

				ld->start = inactive_clean_list;
				ld->end = node_zones +
                                    OFFSET(zone_struct_inactive_clean_list);
        			if (mi->flags & ADDRESS_SPECIFIED)
                			ld->searchfor = mi->spec_addr;

				if (ld->start == ld->end) {
					c = 0;
					ld->searchfor = 0;
					if (mi->flags & VERBOSE)
						fprintf(fp, "(empty)\n");
				} else {
                			hq_open();
                			c = do_list(ld);
                			hq_close();
				}

		                if ((mi->flags & ADDRESS_SPECIFIED) && 
				    ld->searchfor) {
		                        fprintf(fp, "%lx\n", ld->searchfor);
		                        retval = TRUE;
		                } else {
					if (vt->numnodes > 1)
						fprintf(fp, "NODE %d ", n);
					fprintf(fp, "\"%s\" ", buf);
		                        fprintf(fp, 
					    "inactive_clean_pages: %ld ",
		                                inactive_clean_pages);
		                        if (c != inactive_clean_pages)
		                                fprintf(fp, "(found %d)\n", c);
		                        else
		                                fprintf(fp, "(verified)\n");
		                }

				node_zones += SIZE(zone_struct);
			}

                	readmem(pgdat + OFFSET_OPTION(pglist_data_node_next,
				pglist_data_pgdat_next), KVADDR,
                        	&pgdat, sizeof(void *), "pglist_data node_next",
                        	FAULT_ON_ERROR);
		}
        }

	return retval;
}



/*
 *  Check whether an address is a kmem_cache_t address, and if so, return
 *  a pointer to the static buffer containing its name string.  Otherwise
 *  return NULL on failure.
 */

#define PERCPU_NOT_SUPPORTED "per-cpu slab format not supported yet\n"

static char * 
is_kmem_cache_addr(ulong vaddr, char *kbuf)
{
        ulong cache, cache_cache, name;
	long next_offset, name_offset;

	if (vt->flags & KMEM_CACHE_UNAVAIL) {
		error(INFO, "kmem cache slab subsystem not available\n");
		return NULL;
	}

	if (vt->flags & KMALLOC_SLUB) 
		return is_kmem_cache_addr_common(vaddr, kbuf);

	if ((vt->flags & KMALLOC_COMMON) && !symbol_exists("cache_cache"))
		return is_kmem_cache_addr_common(vaddr, kbuf);

        name_offset = vt->flags & (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2) ?
                OFFSET(kmem_cache_s_name) : OFFSET(kmem_cache_s_c_name);
        next_offset = vt->flags & (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2) ?
                OFFSET(kmem_cache_s_next) : OFFSET(kmem_cache_s_c_nextp);

        cache = cache_cache = symbol_value("cache_cache");

        do {
		if (cache == vaddr) {
	                if (vt->kmem_cache_namelen) {
				readmem(cache+name_offset, KVADDR, kbuf, vt->kmem_cache_namelen, "name array", FAULT_ON_ERROR);
	                } else {
				readmem(cache+name_offset, KVADDR, &name, sizeof(name), "name", FAULT_ON_ERROR);
	                        if (!read_string(name, kbuf, BUFSIZE-1)) {
					if (vt->flags & 
					  (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2))
	                                	error(WARNING,
	                      "cannot read kmem_cache_s.name string at %lx\n",
	                                        	name);
					else
	                                	error(WARNING,
	                      "cannot read kmem_cache_s.c_name string at %lx\n",
	                                        	name);
					sprintf(kbuf, "(unknown)");
				}
	                }
			return kbuf;
		}

		readmem(cache+next_offset, KVADDR, &cache, sizeof(long),
			"kmem_cache_s next", FAULT_ON_ERROR);

		if (vt->flags & (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2))
			cache -= next_offset;

        } while (cache != cache_cache);

	return NULL;
}

/*
 *  Note same functionality as above, but instead it just
 *  dumps all slab cache names and their addresses.
 */
static void
kmem_cache_list(struct meminfo *mi)
{
        ulong cache, cache_cache, name;
	long next_offset, name_offset;
	char *cache_buf;
	int has_cache_chain;
	ulong cache_chain;
	char buf[BUFSIZE];

	if (vt->flags & KMEM_CACHE_UNAVAIL) {
		error(INFO, "kmem cache slab subsystem not available\n");
		return;
	}

	if (vt->flags & (KMALLOC_SLUB|KMALLOC_COMMON)) {
		kmem_cache_list_common(mi);
		return;		
	}

	if (symbol_exists("cache_chain")) {	
		has_cache_chain = TRUE;
		cache_chain = symbol_value("cache_chain");
	} else {
		has_cache_chain = FALSE;
		cache_chain = 0;
	}

        name_offset = vt->flags & (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2) ?
                OFFSET(kmem_cache_s_name) : OFFSET(kmem_cache_s_c_name);
        next_offset = vt->flags & (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2) ?
                OFFSET(kmem_cache_s_next) : OFFSET(kmem_cache_s_c_nextp);

        cache = cache_cache = symbol_value("cache_cache");

	cache_buf = GETBUF(SIZE(kmem_cache_s));

        do {
	        readmem(cache, KVADDR, cache_buf, SIZE(kmem_cache_s),
	        	"kmem_cache buffer", FAULT_ON_ERROR);

	        if (vt->kmem_cache_namelen) {
			BCOPY(cache_buf+name_offset, buf, 
				vt->kmem_cache_namelen);
	        } else {
			name = ULONG(cache_buf + name_offset);
	                if (!read_string(name, buf, BUFSIZE-1)) {
				if (vt->flags & 
				    (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2))
	                               	error(WARNING,
	                      "cannot read kmem_cache_s.name string at %lx\n",
	                                       	name);
				else
	                               	error(WARNING,
	                      "cannot read kmem_cache_s.c_name string at %lx\n",
	                                       	name);
				sprintf(buf, "(unknown)");
			}
	        }

		fprintf(fp, "%lx %s\n", cache, buf);

		cache = ULONG(cache_buf + next_offset);

		if (has_cache_chain && (cache == cache_chain))
			readmem(cache, KVADDR, &cache, sizeof(char *),
				"cache_chain", FAULT_ON_ERROR);

		if (vt->flags & (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2))
			cache -= next_offset;

        } while (cache != cache_cache);

	FREEBUF(cache_buf);
}

/*
 *  Translate an address to its physical page number, verify that the
 *  page in fact belongs to the slab subsystem, and if so, return the 
 *  name of the cache to which it belongs.
 */
static char *
vaddr_to_kmem_cache(ulong vaddr, char *buf, int verbose)
{
	physaddr_t paddr;
	ulong page, cache, page_flags;

        if (!kvtop(NULL, vaddr, &paddr, 0)) {
		if (verbose)
		 	error(WARNING, 
 		            "cannot make virtual-to-physical translation: %lx\n", 
				vaddr);
		return NULL;
	}

	if (!phys_to_page(paddr, &page)) {
		if (verbose)
			error(WARNING, 
			    "cannot find mem_map page for address: %lx\n", 
				vaddr);
		return NULL;
	}

	if (vt->PG_slab) {
		readmem(page+OFFSET(page_flags), KVADDR,
			&page_flags, sizeof(ulong), "page.flags",
			FAULT_ON_ERROR);
		if (!(page_flags & (1 << vt->PG_slab))) {
			if (((vt->flags & KMALLOC_SLUB) || VALID_MEMBER(page_compound_head)) ||
			    ((vt->flags & KMALLOC_COMMON) &&
			    VALID_MEMBER(page_slab) && VALID_MEMBER(page_first_page))) {
				readmem(compound_head(page)+OFFSET(page_flags), KVADDR,
					&page_flags, sizeof(ulong), "page.flags",
					FAULT_ON_ERROR);
				if (!(page_flags & (1 << vt->PG_slab)))
					return NULL;
			} else
				return NULL;
		}
	}

	if ((vt->flags & KMALLOC_SLUB) ||
	    ((vt->flags & KMALLOC_COMMON) && VALID_MEMBER(page_slab) && 
	    (VALID_MEMBER(page_compound_head) || VALID_MEMBER(page_first_page)))) {
                readmem(compound_head(page)+OFFSET(page_slab),
                        KVADDR, &cache, sizeof(void *),
                        "page.slab", FAULT_ON_ERROR);
	} else if (VALID_MEMBER(page_next))
                readmem(page+OFFSET(page_next),
                        KVADDR, &cache, sizeof(void *),
                        "page.next", FAULT_ON_ERROR);
	else if (VALID_MEMBER(page_list_next))
                readmem(page+OFFSET(page_list_next),
                        KVADDR, &cache, sizeof(void *),
                        "page.list.next", FAULT_ON_ERROR);
	else if (VALID_MEMBER(page_lru))
                readmem(page+OFFSET(page_lru)+OFFSET(list_head_next),
                        KVADDR, &cache, sizeof(void *),
                        "page.lru.next", FAULT_ON_ERROR);
	else
		error(FATAL, "cannot determine slab cache from page struct\n");

	return(is_kmem_cache_addr(cache, buf)); 
}


static char *
is_slab_overload_page(ulong vaddr, ulong *page_head, char *buf)
{
	ulong cache;
	char *p;

        if ((vt->flags & SLAB_OVERLOAD_PAGE) &&
	    is_page_ptr(vaddr, NULL) && VALID_MEMBER(page_slab) && 
	    (VALID_MEMBER(page_compound_head) || VALID_MEMBER(page_first_page))) {
                readmem(compound_head(vaddr)+OFFSET(page_slab),
                        KVADDR, &cache, sizeof(void *),
                        "page.slab", FAULT_ON_ERROR);
		p = is_kmem_cache_addr(cache, buf);
		if (p)
			*page_head = compound_head(vaddr);
		return p;
	}

	return NULL;
}

/*
 *  Translate an address to its physical page number, verify that the
 *  page in fact belongs to the slab subsystem, and if so, return the
 *  address of the slab to which it belongs.
 */
static ulong
vaddr_to_slab(ulong vaddr)
{
        physaddr_t paddr;
        ulong page;
        ulong slab;

        if (!kvtop(NULL, vaddr, &paddr, 0)) {
                error(WARNING,
                    "cannot make virtual-to-physical translation: %lx\n",
                        vaddr);
                return 0;
        }

        if (!phys_to_page(paddr, &page)) {
                error(WARNING, "cannot find mem_map page for address: %lx\n",
                        vaddr);
                return 0;
        }

	slab = 0;

        if ((vt->flags & KMALLOC_SLUB) || VALID_MEMBER(page_compound_head))
		slab = compound_head(page);
	else if (vt->flags & SLAB_OVERLOAD_PAGE)
		slab = compound_head(page);
        else if ((vt->flags & KMALLOC_COMMON) && VALID_MEMBER(page_slab_page))
                readmem(page+OFFSET(page_slab_page),
                        KVADDR, &slab, sizeof(void *),
                        "page.slab_page", FAULT_ON_ERROR);
        else if (VALID_MEMBER(page_prev))
                readmem(page+OFFSET(page_prev),
                        KVADDR, &slab, sizeof(void *),
                        "page.prev", FAULT_ON_ERROR);
        else if (VALID_MEMBER(page_list_prev))
                readmem(page+OFFSET(page_list_prev),
                        KVADDR, &slab, sizeof(void *),
                        "page.list.prev", FAULT_ON_ERROR);
	else if (VALID_MEMBER(page_lru))
                readmem(page+OFFSET(page_lru)+OFFSET(list_head_prev),
                        KVADDR, &slab, sizeof(void *),
                        "page.lru.prev", FAULT_ON_ERROR);
        else
                error(FATAL, "unknown definition of struct page?\n");

	return slab;
}


/*
 *  Initialize any data required for scouring the kmalloc subsystem more
 *  efficiently.
 */
char slab_hdr[100] = { 0 };
char kmem_cache_hdr[100] = { 0 };
char free_inuse_hdr[100] = { 0 };

static void
kmem_cache_init(void)
{
	ulong cache, cache_end, max_cnum, max_limit, max_cpus, tmp, tmp2;
	long cache_count, num_offset, next_offset;
	char *cache_buf;

	if (vt->flags & KMEM_CACHE_UNAVAIL)
		return;

	if ((vt->flags & KMEM_CACHE_DELAY) && !(pc->flags & RUNTIME))
		return;

	if (DUMPFILE() && (vt->flags & KMEM_CACHE_INIT))
		return; 

	please_wait("gathering kmem slab cache data");

        if (!strlen(slab_hdr)) {
		if (vt->flags & KMALLOC_SLUB) 
			sprintf(slab_hdr, 
			    "SLAB%sMEMORY%sNODE  TOTAL  ALLOCATED  FREE\n",
				space(VADDR_PRLEN > 8 ? 14 : 6),
				space(VADDR_PRLEN > 8 ? 12 : 4));
		else
			sprintf(slab_hdr, 
			    "SLAB%sMEMORY%sTOTAL  ALLOCATED  FREE\n",
				space(VADDR_PRLEN > 8 ? 14 : 6),
				space(VADDR_PRLEN > 8 ? 12 : 4));
	}

	if (!strlen(kmem_cache_hdr)) 
		sprintf(kmem_cache_hdr,
     "CACHE%s OBJSIZE  ALLOCATED     TOTAL  SLABS  SSIZE  NAME\n",
			space(VADDR_PRLEN > 8 ? 12 : 4));

	if (!strlen(free_inuse_hdr)) 
		sprintf(free_inuse_hdr, "FREE / [ALLOCATED]\n");

	if (vt->flags & KMALLOC_SLUB) {
		kmem_cache_init_slub();
		please_wait_done();
		return;
	}

	num_offset = vt->flags & (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2) ? 
		OFFSET(kmem_cache_s_num) : OFFSET(kmem_cache_s_c_num);
	next_offset = vt->flags & (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2) ?
		OFFSET(kmem_cache_s_next) : OFFSET(kmem_cache_s_c_nextp);
        max_cnum = max_limit = max_cpus = cache_count = tmp2 = 0;

	/*
	 *  Pre-2.6 versions used the "cache_cache" as the head of the
	 *  slab chain list.  2.6 uses the "cache_chain" list_head.
         *  In 3.6 SLAB and SLUB use the "slab_caches" list_head.
	 */
	if (vt->flags & PERCPU_KMALLOC_V2) {
		if (kernel_symbol_exists("cache_chain")) {
			get_symbol_data("cache_chain", sizeof(ulong), &cache);
			cache_end = symbol_value("cache_chain");
		} else if (kernel_symbol_exists("slab_caches")) {
			vt->flags |= KMALLOC_COMMON;
			get_symbol_data("slab_caches", sizeof(ulong), &cache);
			cache_end = symbol_value("slab_caches");
		} else {
			error(INFO, 
			    "unable to initialize kmem slab cache subsystem\n\n");
			return;
		}
		cache -= next_offset;
        } else
                cache = cache_end = symbol_value("cache_cache");

	if (!(pc->flags & RUNTIME)) {
		if (kmem_cache_downsize())
			add_to_downsized("kmem_cache");
	}

	cache_buf = GETBUF(SIZE(kmem_cache_s));
	hq_open();

        do {
		cache_count++;

                if (!readmem(cache, KVADDR, cache_buf, SIZE(kmem_cache_s),
                        "kmem_cache buffer", RETURN_ON_ERROR)) {
			FREEBUF(cache_buf);
			vt->flags |= KMEM_CACHE_UNAVAIL;
			error(INFO, 
		          "%sunable to initialize kmem slab cache subsystem\n\n",
				DUMPFILE() ? "\n" : "");
			hq_close();
			return;
		}

		if (!hq_enter(cache)) {
			error(WARNING, 
			    "%sduplicate kmem_cache entry in cache list: %lx\n",
				DUMPFILE() ? "\n" : "", cache);
			error(INFO, "unable to initialize kmem slab cache subsystem\n\n");
			vt->flags |= KMEM_CACHE_UNAVAIL;
			hq_close();
			return;
		}

		tmp = (ulong)(UINT(cache_buf + num_offset));
                if (tmp > max_cnum)
                        max_cnum = tmp;

		if ((tmp = max_cpudata_limit(cache, &tmp2)) > max_limit)
			max_limit = tmp;
		/*
		 *  Recognize and bail out on any max_cpudata_limit() failures.
		 */
		if (vt->flags & KMEM_CACHE_UNAVAIL) {
			FREEBUF(cache_buf);
			hq_close();
			return;
		}

		if (tmp2 > max_cpus)
			max_cpus = tmp2;

		cache = ULONG(cache_buf + next_offset);

		switch (vt->flags & (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2)) 
		{
		case PERCPU_KMALLOC_V1:
			cache -= next_offset;
			break;
		case PERCPU_KMALLOC_V2:
			if (cache != cache_end)
				cache -= next_offset;
			break;
		}

        } while (cache != cache_end);

	hq_close();
	FREEBUF(cache_buf);

	vt->kmem_max_c_num = max_cnum;
	vt->kmem_max_limit = max_limit;
	vt->kmem_max_cpus = max_cpus;
	vt->kmem_cache_count = cache_count;

	if (CRASHDEBUG(2)) {
		fprintf(fp, "kmem_cache_init:\n");
		fprintf(fp, "  kmem_max_c_num: %ld\n", vt->kmem_max_c_num);
		fprintf(fp, "  kmem_max_limit: %ld\n", vt->kmem_max_limit);
		fprintf(fp, "  kmem_max_cpus: %ld\n", vt->kmem_max_cpus);
		fprintf(fp, "  kmem_cache_count: %ld\n", vt->kmem_cache_count);
	}

	if (!(vt->flags & KMEM_CACHE_INIT)) {
		if (vt->flags & PERCPU_KMALLOC_V1)
			ARRAY_LENGTH_INIT(vt->kmem_cache_namelen,
				kmem_cache_s_name, "kmem_cache_s.name", 
				NULL, sizeof(char));
		else if (vt->flags & PERCPU_KMALLOC_V2)
			vt->kmem_cache_namelen = 0;
		else
			ARRAY_LENGTH_INIT(vt->kmem_cache_namelen,
				kmem_cache_s_c_name, "kmem_cache_s.c_name", 
				NULL, 0);
	}

	please_wait_done();

	vt->flags |= KMEM_CACHE_INIT;
}

static ulong
kmem_cache_nodelists(ulong cache)
{
	ulong nodelists = 0;

	if (vt->flags & NODELISTS_IS_PTR) {
		/* 
		 * nodelists is pointer to the array 
		 */
                if (!readmem(cache+OFFSET(kmem_cache_s_lists), KVADDR,
                    &nodelists, sizeof(ulong), "nodelists pointer",
                    RETURN_ON_ERROR))
                        error(WARNING, "cannot read kmem_cache nodelists pointer");
		return nodelists;
	} else 
		return cache+OFFSET(kmem_cache_s_lists);
}

static int
kmem_cache_downsize(void)
{
	char *cache_buf;
	ulong kmem_cache;
	uint buffer_size, object_size; 
	int nr_node_ids;
	int nr_cpu_ids;

	if (vt->flags & KMALLOC_SLUB) {
		if (kernel_symbol_exists("kmem_cache") &&
		    VALID_MEMBER(kmem_cache_objsize) &&
		    try_get_symbol_data("kmem_cache", 
		    sizeof(ulong), &kmem_cache) &&
		    readmem(kmem_cache + OFFSET(kmem_cache_objsize), 
		    KVADDR, &object_size, sizeof(int), 
		    "kmem_cache objsize/object_size", RETURN_ON_ERROR)) {
			ASSIGN_SIZE(kmem_cache) = object_size;
			if (CRASHDEBUG(1))
				fprintf(fp, "\nkmem_cache_downsize: %ld to %ld\n",
					STRUCT_SIZE("kmem_cache"), 
					SIZE(kmem_cache));
		}
		if (STRUCT_SIZE("kmem_cache") != SIZE(kmem_cache))
			return TRUE;
		else
			return FALSE;
	}

	if ((THIS_KERNEL_VERSION < LINUX(2,6,22)) ||
	    !(vt->flags & PERCPU_KMALLOC_V2_NODES) ||
	    (!kernel_symbol_exists("cache_cache") && 
	     !kernel_symbol_exists("kmem_cache_boot")) ||
	    (!MEMBER_EXISTS("kmem_cache", "buffer_size") &&
	     !MEMBER_EXISTS("kmem_cache", "size"))) {
		return FALSE;
	}

	if (vt->flags & NODELISTS_IS_PTR) {
		/* 
		 * More recent kernels have kmem_cache.array[] sized
		 * by the number of cpus plus the number of nodes.
		 */
		if (kernel_symbol_exists("kmem_cache_boot") &&
		    MEMBER_EXISTS("kmem_cache", "object_size") &&
		    readmem(symbol_value("kmem_cache_boot") +
		    MEMBER_OFFSET("kmem_cache", "object_size"), 
		    KVADDR, &object_size, sizeof(int), 
		    "kmem_cache_boot object_size", RETURN_ON_ERROR))
			ASSIGN_SIZE(kmem_cache_s) = object_size;
		else if (kernel_symbol_exists("cache_cache") &&
		    MEMBER_EXISTS("kmem_cache", "object_size") &&
		    readmem(symbol_value("cache_cache") +
		    MEMBER_OFFSET("kmem_cache", "object_size"), 
		    KVADDR, &object_size, sizeof(int), 
		    "cache_cache object_size", RETURN_ON_ERROR))
			ASSIGN_SIZE(kmem_cache_s) = object_size;
		else
			object_size = 0;

		/* 
		 * Older kernels have kmem_cache.array[] sized by 
		 * the number of cpus; real value is nr_cpu_ids, 
		 * but fallback is kt->cpus.
		 */
		if (kernel_symbol_exists("nr_cpu_ids"))
			get_symbol_data("nr_cpu_ids", sizeof(int), 
				&nr_cpu_ids);
		else 
			nr_cpu_ids = kt->cpus;
	
		ARRAY_LENGTH(kmem_cache_s_array) = nr_cpu_ids;

		if (!object_size)
			ASSIGN_SIZE(kmem_cache_s) = OFFSET(kmem_cache_s_array) +
				sizeof(ulong) * nr_cpu_ids;
		if (CRASHDEBUG(1))
			fprintf(fp, "\nkmem_cache_downsize: %ld to %ld\n",
				STRUCT_SIZE("kmem_cache"), SIZE(kmem_cache_s));

		if (STRUCT_SIZE("kmem_cache") != SIZE(kmem_cache_s))
			return TRUE;
		else
			return FALSE;
	} else if (vt->flags & SLAB_CPU_CACHE) {
                if (kernel_symbol_exists("kmem_cache_boot") &&
                    MEMBER_EXISTS("kmem_cache", "object_size") &&
                    readmem(symbol_value("kmem_cache_boot") +
                    MEMBER_OFFSET("kmem_cache", "object_size"),
                    KVADDR, &object_size, sizeof(int),
                    "kmem_cache_boot object_size", RETURN_ON_ERROR))
                        ASSIGN_SIZE(kmem_cache_s) = object_size;
		else {
			object_size = OFFSET(kmem_cache_node) +
				(sizeof(void *) * vt->kmem_cache_len_nodes);
                        ASSIGN_SIZE(kmem_cache_s) = object_size;
		}
		if (CRASHDEBUG(1))
			fprintf(fp, "\nkmem_cache_downsize: %ld to %ld\n",
				STRUCT_SIZE("kmem_cache"), SIZE(kmem_cache_s));

		if (STRUCT_SIZE("kmem_cache") != SIZE(kmem_cache_s))
			return TRUE;
		else
			return FALSE;
	}

	cache_buf = GETBUF(SIZE(kmem_cache_s));

	if (!readmem(symbol_value("cache_cache"), KVADDR, cache_buf, 
	    SIZE(kmem_cache_s), "kmem_cache buffer", RETURN_ON_ERROR)) {
		FREEBUF(cache_buf);
		return FALSE;
	}

	buffer_size = UINT(cache_buf + 
		MEMBER_OFFSET("kmem_cache", "buffer_size"));

	if (buffer_size < SIZE(kmem_cache_s)) {

		if (kernel_symbol_exists("nr_node_ids")) {
			get_symbol_data("nr_node_ids", sizeof(int),
				&nr_node_ids);
			vt->kmem_cache_len_nodes = nr_node_ids;
					
		} else
			vt->kmem_cache_len_nodes = 1;

		if (buffer_size >= (uint)(OFFSET(kmem_cache_s_lists) + 
	    	    (sizeof(void *) * vt->kmem_cache_len_nodes)))
			ASSIGN_SIZE(kmem_cache_s) = buffer_size;
		else
			error(WARNING, 
			    "questionable cache_cache.buffer_size: %d\n",
				buffer_size);

		if (CRASHDEBUG(1)) {
     			fprintf(fp, 
			    "\nkmem_cache_downsize: %ld to %d\n",
				STRUCT_SIZE("kmem_cache"), buffer_size);
			fprintf(fp,
			    "kmem_cache_downsize: nr_node_ids: %ld\n",
				vt->kmem_cache_len_nodes);
		}

		FREEBUF(cache_buf);
		if (STRUCT_SIZE("kmem_cache") != SIZE(kmem_cache_s))
			return TRUE;
		else
			return FALSE;
	}

	FREEBUF(cache_buf);
	return FALSE;
}

/*
 *  Stash a list of presumably-corrupted slab cache addresses.
 */
static void
mark_bad_slab_cache(ulong cache) 
{
	size_t sz;

	if (vt->nr_bad_slab_caches) {
		sz = sizeof(ulong) * (vt->nr_bad_slab_caches + 1);
		if (!(vt->bad_slab_caches = realloc(vt->bad_slab_caches, sz))) {
                	error(INFO, "cannot realloc bad_slab_caches array\n");
			vt->nr_bad_slab_caches = 0;
			return;
		}
	} else {
		if (!(vt->bad_slab_caches = (ulong *)malloc(sizeof(ulong)))) {
			error(INFO, "cannot malloc bad_slab_caches array\n");
			return;
		}
	}

	vt->bad_slab_caches[vt->nr_bad_slab_caches++] = cache;
}

static int
bad_slab_cache(ulong cache) 
{
	int i;

	for (i = 0; i < vt->nr_bad_slab_caches; i++) {
		if (vt->bad_slab_caches[i] == cache)
			return TRUE;
	}

       return FALSE;
}

/*
 *  Determine the largest cpudata limit for a given cache.
 */
static ulong
max_cpudata_limit(ulong cache, ulong *cpus)
{
	int i;
	ulong cpudata[NR_CPUS];
	int limit; 
	ulong max_limit;
	ulong shared, percpu_ptr;
	ulong *start_address;
	
	if (vt->flags & PERCPU_KMALLOC_V2_NODES)
		goto kmem_cache_s_array_nodes;
	
	if (vt->flags & PERCPU_KMALLOC_V2)
		goto kmem_cache_s_array;
	
	 if (INVALID_MEMBER(kmem_cache_s_cpudata)) {
		*cpus = 0;
		return 0;
	}

	if (!readmem(cache+OFFSET(kmem_cache_s_cpudata),
            KVADDR, &cpudata[0], 
	    sizeof(ulong) * ARRAY_LENGTH(kmem_cache_s_cpudata),
            "cpudata array", RETURN_ON_ERROR))
		goto bail_out;

	for (i = max_limit = 0; (i < ARRAY_LENGTH(kmem_cache_s_cpudata)) && 
	     cpudata[i]; i++) {
		if (!readmem(cpudata[i]+OFFSET(cpucache_s_limit),
        	    KVADDR, &limit, sizeof(int),
                    "cpucache limit", RETURN_ON_ERROR))
			goto bail_out;
		if (limit > max_limit)
			max_limit = limit;
	}

	*cpus = i;

	return max_limit;

kmem_cache_s_array:

	if (!readmem(cache+OFFSET(kmem_cache_s_array),
            KVADDR, &cpudata[0], 
	    sizeof(ulong) * ARRAY_LENGTH(kmem_cache_s_array),
            "array cache array", RETURN_ON_ERROR))
		goto bail_out;

	for (i = max_limit = 0; (i < ARRAY_LENGTH(kmem_cache_s_array)) && 
	     cpudata[i]; i++) {
                if (!readmem(cpudata[i]+OFFSET(array_cache_limit),
                    KVADDR, &limit, sizeof(int),
                    "array cache limit", RETURN_ON_ERROR))
			goto bail_out;
                if (limit > max_limit)
                        max_limit = limit;
        }

	/*
	 *  If the shared list can be accessed, check its size as well.
	 */
	if (VALID_MEMBER(kmem_list3_shared) &&
	    VALID_MEMBER(kmem_cache_s_lists) &&
            readmem(cache+OFFSET(kmem_cache_s_lists)+OFFSET(kmem_list3_shared),
	    KVADDR, &shared, sizeof(void *), "kmem_list3 shared", 
	    RETURN_ON_ERROR|QUIET) &&
	    readmem(shared+OFFSET(array_cache_limit), 
	    KVADDR, &limit, sizeof(int), "shared array_cache limit",
	    RETURN_ON_ERROR|QUIET)) {
		if (limit > max_limit)
			max_limit = limit;
	}
		   
	*cpus = i;
	return max_limit;

kmem_cache_s_array_nodes:

	if (CRASHDEBUG(3))
		fprintf(fp, "kmem_cache: %lx\n", cache);

	if (vt->flags & SLAB_CPU_CACHE) {
		if (!readmem(cache+OFFSET(kmem_cache_cpu_cache), KVADDR, &percpu_ptr, 
		    sizeof(void *), "kmem_cache.cpu_cache", RETURN_ON_ERROR))
			goto bail_out;

		for (i = 0; i < kt->cpus; i++)
			cpudata[i] = percpu_ptr + kt->__per_cpu_offset[i];
	} else {
		if (!readmem(cache+OFFSET(kmem_cache_s_array), KVADDR, &cpudata[0], 
		    sizeof(ulong) * MIN(NR_CPUS, ARRAY_LENGTH(kmem_cache_s_array)),
		    "array cache array", RETURN_ON_ERROR))
			goto bail_out;
	}

	for (i = max_limit = 0; i < kt->cpus; i++) {
		if (check_offline_cpu(i))
			continue;

		if (!cpudata[i])
			break;

                if (!readmem(cpudata[i]+OFFSET(array_cache_limit),
                    KVADDR, &limit, sizeof(int),
                    "array cache limit", RETURN_ON_ERROR)) {
			error(INFO, 
			    "kmem_cache: %lx: invalid array_cache pointer: %lx\n",
				cache, cpudata[i]);
			mark_bad_slab_cache(cache);
			return max_limit;
		}
		if (CRASHDEBUG(3))
			fprintf(fp, "  array limit[%d]: %d\n", i, limit);
		if ((unsigned int)limit > INT_MAX)
			error(INFO, 
			    "kmem_cache: %lx: invalid array limit[%d]: %d\n",
				cache, i, limit);
		else if (limit > max_limit)
                        max_limit = limit;
        }

	*cpus = i;

	/*
	 *  Check the shared list of all the nodes.
	 */
	start_address = (ulong *)GETBUF(sizeof(ulong) * vt->kmem_cache_len_nodes);
	
	if (VALID_MEMBER(kmem_list3_shared) && VALID_MEMBER(kmem_cache_s_lists) &&
	    readmem(kmem_cache_nodelists(cache), KVADDR, &start_address[0],
	    sizeof(ulong) * vt->kmem_cache_len_nodes, "array nodelist array",
	    RETURN_ON_ERROR)) {
		for (i = 0; i < vt->kmem_cache_len_nodes; i++) {
			if (start_address[i] == 0)
				continue;
			if (readmem(start_address[i] + OFFSET(kmem_list3_shared), 
			    KVADDR, &shared, sizeof(void *),
			    "kmem_list3 shared", RETURN_ON_ERROR|QUIET)) {
				if (!shared)
					break;
			} else
				continue;
			if (readmem(shared + OFFSET(array_cache_limit),
	       		    KVADDR, &limit, sizeof(int), "shared array_cache limit",
		            RETURN_ON_ERROR|QUIET)) {
				if (CRASHDEBUG(3))
					fprintf(fp, 
					    "  shared node limit[%d]: %d\n", 
						i, limit);
				if ((unsigned int)limit > INT_MAX)
					error(INFO, 
					    "kmem_cache: %lx: shared node limit[%d]: %d\n",
						cache, i, limit);
				else if (limit > max_limit)
					max_limit = limit;
				break;
			}
		}
	}
	FREEBUF(start_address);
	return max_limit;

bail_out:
	vt->flags |= KMEM_CACHE_UNAVAIL;
	error(INFO, "unable to initialize kmem slab cache subsystem\n\n");
	*cpus = 0;
	return 0;
}

/*
 *  Determine whether the current slab cache is contained in
 *  the comma-separated list from a "kmem -I list1,list2 ..."
 *  command entry.
 */
static int
ignore_cache(struct meminfo *si, char *name)
{
	int i, argc;
	char *p1;
	char *arglist[MAXARGS];
	char buf[BUFSIZE];

	if (!si->ignore)
		return FALSE;

	strcpy(buf, si->ignore);

	p1 = buf;
	while (*p1) {
		if (*p1 == ',')
			*p1 = ' ';
		p1++;
	}

	argc = parse_line(buf, arglist);

	for (i = 0; i < argc; i++) {
		if (STREQ(name, arglist[i]))
			return TRUE;
	}

	return FALSE;
}


/*
 *  dump_kmem_cache() displays basic information about kmalloc() slabs.
 *  At this point, only kmem_cache_s structure data for each slab is dumped.
 *
 *  TBD: Given a specified physical address, and determine which slab it came
 *  from, and whether it's in use or not.
 */

#define SLAB_C_MAGIC            0x4F17A36DUL
#define SLAB_MAGIC_ALLOC        0xA5C32F2BUL    /* slab is alive */
#define SLAB_MAGIC_DESTROYED    0xB2F23C5AUL    /* slab has been destroyed */

#define SLAB_CFLGS_BUFCTL       0x020000UL      /* bufctls in own cache */
#define SLAB_CFLGS_OBJFREELIST  0x40000000UL    /* Freelist as an object */

#define KMEM_SLAB_ADDR          (1)
#define KMEM_BUFCTL_ADDR        (2)
#define KMEM_OBJECT_ADDR_FREE   (3)
#define KMEM_OBJECT_ADDR_INUSE  (4)
#define KMEM_OBJECT_ADDR_CACHED (5)
#define KMEM_ON_SLAB            (6)
#define KMEM_OBJECT_ADDR_SHARED (7)
#define KMEM_SLAB_OVERLOAD_PAGE (8)
#define KMEM_SLAB_FREELIST      (9)

#define DUMP_KMEM_CACHE_TAG(addr, name, tag) \
	fprintf(fp, "%lx %-43s  %s\n", addr, tag, name)

#define DUMP_KMEM_CACHE_INFO()  dump_kmem_cache_info(si)

static void
dump_kmem_cache_info(struct meminfo *si)
{
	char b1[BUFSIZE];
	ulong objsize, allocated, total;

	if (si->flags & SLAB_GATHER_FAILURE)
		error(INFO, "%s: cannot gather relevant slab data\n", si->curname);

	objsize = (vt->flags & KMALLOC_SLUB) ? si->objsize : si->size;

	fprintf(fp, "%s %8ld  ",
		mkstring(b1, VADDR_PRLEN, LJUST|LONG_HEX, MKSTR(si->cache)),
		objsize);

	if (si->flags & SLAB_GATHER_FAILURE) {
		fprintf(fp, "%9s  %8s  %5s  ", "?", "?", "?");
	} else {
		allocated = (vt->flags & (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2)) ?
				si->inuse - si->cpucached_cache : si->inuse;
		total = (vt->flags & KMALLOC_SLUB) ?
				si->inuse + si->free : si->num_slabs * si->c_num;

		fprintf(fp, "%9ld  %8ld  %5ld  ",
			allocated, total, si->num_slabs);
	}

	fprintf(fp, "%4ldk  %s\n", si->slabsize/1024, si->curname);
}

#define DUMP_SLAB_INFO() \
      { \
        char b1[BUFSIZE], b2[BUFSIZE]; \
        ulong allocated, freeobjs, slab; \
	if (vt->flags & SLAB_OVERLOAD_PAGE) \
		slab = si->slab - OFFSET(page_lru); \
	else \
		slab = si->slab; \
        if (vt->flags & (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2)) { \
                allocated = si->s_inuse - si->cpucached_slab; \
                freeobjs = si->c_num - allocated - si->cpucached_slab; \
        } else { \
                allocated = si->s_inuse; \
                freeobjs = si->c_num - si->s_inuse; \
        } \
        fprintf(fp, "%s  %s  %5ld  %9ld  %4ld\n", \
                mkstring(b1, VADDR_PRLEN, LJUST|LONG_HEX, MKSTR(slab)), \
                mkstring(b2, VADDR_PRLEN, LJUST|LONG_HEX, MKSTR(si->s_mem)), \
                si->c_num, allocated, \
                vt->flags & (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2) ? \
		freeobjs + si->cpucached_slab : freeobjs); \
      }

static void
dump_kmem_cache(struct meminfo *si)
{
	char buf[BUFSIZE];
	char kbuf[BUFSIZE];
	char *reqname;
	ulong cache_cache;
	ulong name, magic;
	int cnt;
	char *p1;

	if (vt->flags & (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2)) 
		error(FATAL, 
		    "dump_kmem_cache called with PERCPU_KMALLOC_V[12] set\n");

	si->found = si->retval = 0;
	reqname = NULL;

	if ((!(si->flags & VERBOSE) || si->reqname) &&
	     !(si->flags & (ADDRESS_SPECIFIED|GET_SLAB_PAGES)))
		fprintf(fp, "%s", kmem_cache_hdr);

	si->addrlist = (ulong *)GETBUF((vt->kmem_max_c_num+1) * sizeof(ulong));
	cnt = 0;
	if (si->flags & CACHE_SET) {
		readmem(si->cache+OFFSET(kmem_cache_s_c_nextp),
			KVADDR, &cache_cache, sizeof(ulong),
			"kmem_cache next", FAULT_ON_ERROR);
	} else
		si->cache = cache_cache = symbol_value("cache_cache");

	if (si->flags & ADDRESS_SPECIFIED) {
	        if (!(p1 = vaddr_to_kmem_cache(si->spec_addr, kbuf, VERBOSE))) {
			error(INFO, 
			   "address is not allocated in slab subsystem: %lx\n",
				si->spec_addr);
			return;
		}
		
		if (si->reqname && (si->reqname != p1)) 
			error(INFO, 
			    "ignoring pre-selected %s cache for address: %lx\n",
				si->reqname, si->spec_addr, si->reqname);

		reqname = p1;
	} else
		reqname = si->reqname;

	si->cache_buf = GETBUF(SIZE(kmem_cache_s));

	do {
		if ((si->flags & VERBOSE) && !si->reqname &&
		    !(si->flags & ADDRESS_SPECIFIED))
			fprintf(fp, "%s%s", cnt++ ? "\n" : "", kmem_cache_hdr);

                readmem(si->cache, KVADDR, si->cache_buf, SIZE(kmem_cache_s),
                	"kmem_cache buffer", FAULT_ON_ERROR);

		if (vt->kmem_cache_namelen) {
			BCOPY(si->cache_buf + OFFSET(kmem_cache_s_c_name),
				buf, vt->kmem_cache_namelen);
		} else {
			name = ULONG(si->cache_buf + 
				OFFSET(kmem_cache_s_c_name));
                	if (!read_string(name, buf, BUFSIZE-1)) {
				error(WARNING, 
			      "cannot read kmem_cache_s.c_name string at %lx\n",
					name);
				sprintf(buf, "(unknown)");
			}
		}

		if (reqname && !STREQ(reqname, buf)) 
			goto next_cache;

		if (ignore_cache(si, buf)) {
			DUMP_KMEM_CACHE_TAG(si->cache, buf, "[IGNORED]");
			goto next_cache;
		}

		si->curname = buf;

		if (CRASHDEBUG(1))
			fprintf(fp, "cache: %lx %s\n", si->cache, si->curname);
		console("cache: %lx %s\n", si->cache, si->curname);

		magic = ULONG(si->cache_buf + OFFSET(kmem_cache_s_c_magic));

		if (magic == SLAB_C_MAGIC) {

			si->size = ULONG(si->cache_buf + 
				OFFSET(kmem_cache_s_c_org_size));
			if (!si->size) {
				if (STREQ(si->curname, "kmem_cache"))
					si->size = SIZE(kmem_cache_s);
				else {
					error(INFO, 
					    "\"%s\" cache: c_org_size: %ld\n",
						si->curname, si->size);
					si->errors++;
				}
			}
			si->c_flags = ULONG(si->cache_buf +
				OFFSET(kmem_cache_s_c_flags));
			si->c_offset = ULONG(si->cache_buf + 
				OFFSET(kmem_cache_s_c_offset));
			si->order = ULONG(si->cache_buf + 
				OFFSET(kmem_cache_s_c_gfporder));
			si->c_num = ULONG(si->cache_buf +
				OFFSET(kmem_cache_s_c_num));

			do_slab_chain(SLAB_GET_COUNTS, si);

			if (!(si->flags & (ADDRESS_SPECIFIED|GET_SLAB_PAGES))) 
				DUMP_KMEM_CACHE_INFO();

			if (si->flags == GET_SLAB_PAGES) 
				si->retval += (si->num_slabs * 
				    	(si->slabsize/PAGESIZE()));

			if (si->flags & (VERBOSE|ADDRESS_SPECIFIED)) {
				si->slab = (si->flags & ADDRESS_SPECIFIED) ?
					vaddr_to_slab(si->spec_addr) : 0;
			
				do_slab_chain(SLAB_WALKTHROUGH, si);

				if (si->found) {
					fprintf(fp, "%s", kmem_cache_hdr);
					DUMP_KMEM_CACHE_INFO();
					fprintf(fp, "%s", slab_hdr);
					DUMP_SLAB_INFO();

					switch (si->found)
					{
					case KMEM_BUFCTL_ADDR:
						fprintf(fp, "   %lx ", 
							(ulong)si->spec_addr);
						fprintf(fp, 
						   "(ON-SLAB kmem_bufctl_t)\n");
						break;

					case KMEM_SLAB_ADDR:
						fprintf(fp, "   %lx ", 
							(ulong)si->spec_addr);
						fprintf(fp,
					            "(ON-SLAB kmem_slab_t)\n");
						break;

					case KMEM_ON_SLAB:
						fprintf(fp, "   %lx ", 
							(ulong)si->spec_addr);
						fprintf(fp, 
						    "(unused part of slab)\n");
						break;
						
					case KMEM_OBJECT_ADDR_FREE:
                                                fprintf(fp, "%s",
							free_inuse_hdr);
						fprintf(fp, "   %lx\n", 
							si->container ? si->container :
                                                        (ulong)si->spec_addr);
						break;

                                        case KMEM_OBJECT_ADDR_INUSE:
                                                fprintf(fp, "%s",
							free_inuse_hdr);
                                                fprintf(fp, "  [%lx]\n",
							si->container ? si->container :
                                                        (ulong)si->spec_addr);
                                                break;
					}

					break;
				}
			}

		} else {
			error(INFO, "\"%s\" cache: invalid c_magic: %lx\n", 
				si->curname, magic);
			si->errors++;
		}

next_cache:
		si->cache = ULONG(si->cache_buf + OFFSET(kmem_cache_s_c_nextp));

	} while (si->cache != cache_cache);

	FREEBUF(si->cache_buf);

        if ((si->flags & ADDRESS_SPECIFIED) && !si->found)
		error(INFO, "%s: address not found in cache: %lx\n", 
			reqname, si->spec_addr);
 
	if (si->errors)
		error(INFO, "%ld error%s encountered\n", 
			si->errors, si->errors > 1 ? "s" : "");

	FREEBUF(si->addrlist);
}

/*
 *  dump_kmem_cache() adapted for newer percpu slab format.
 */

static void
dump_kmem_cache_percpu_v1(struct meminfo *si)
{
	int i;
	char buf[BUFSIZE];
	char kbuf[BUFSIZE];
	char *reqname;
	ulong cache_cache;
	ulong name;
	int cnt;
	uint tmp_val;  /* Used as temporary variable to read sizeof(int) and 
			assigned to ulong variable. We are doing this to mask
			the endian issue */
	char *p1;

        if (!(vt->flags & PERCPU_KMALLOC_V1)) 
                error(FATAL, 
                   "dump_kmem_cache_percpu called without PERCPU_KMALLOC_V1\n");

	si->found = si->retval = 0;
	reqname = NULL;

	if ((!(si->flags & VERBOSE) || si->reqname) &&
	     !(si->flags & (ADDRESS_SPECIFIED|GET_SLAB_PAGES)))
		fprintf(fp, "%s", kmem_cache_hdr);

	si->addrlist = (ulong *)GETBUF((vt->kmem_max_c_num+1) * sizeof(ulong));
	si->kmem_bufctl = (int *)GETBUF((vt->kmem_max_c_num+1) * sizeof(int));
	for (i = 0; i < vt->kmem_max_cpus; i++) 
		si->cpudata[i] = (ulong *)
			GETBUF(vt->kmem_max_limit * sizeof(ulong)); 

	cnt = 0;
	if (si->flags & CACHE_SET) {
		readmem(si->cache+OFFSET(kmem_cache_s_next), 
			KVADDR, &cache_cache, sizeof(ulong),
			"kmem_cache_s next", FAULT_ON_ERROR);
	} else
		si->cache = cache_cache = symbol_value("cache_cache");

	if (si->flags & ADDRESS_SPECIFIED) {
	        if (!(p1 = vaddr_to_kmem_cache(si->spec_addr, kbuf, VERBOSE))) {
			error(INFO, 
			   "address is not allocated in slab subsystem: %lx\n",
				si->spec_addr);
			return;
		}
		
		if (si->reqname && (si->reqname != p1)) 
			error(INFO, 
			    "ignoring pre-selected %s cache for address: %lx\n",
				si->reqname, si->spec_addr, si->reqname);
		reqname = p1;
	} else
		reqname = si->reqname;

	do {
		if ((si->flags & VERBOSE) && !si->reqname &&
		    !(si->flags & ADDRESS_SPECIFIED))
			fprintf(fp, "%s%s", cnt++ ? "\n" : "", kmem_cache_hdr);

		if (vt->kmem_cache_namelen) {
                        readmem(si->cache+OFFSET(kmem_cache_s_name), 
				KVADDR, buf, vt->kmem_cache_namelen,
                                "name array", FAULT_ON_ERROR);
		} else {
                	readmem(si->cache+OFFSET(kmem_cache_s_name), 
				KVADDR, &name, sizeof(ulong),
                        	"name", FAULT_ON_ERROR);
                	if (!read_string(name, buf, BUFSIZE-1)) {
				error(WARNING, 
			      "cannot read kmem_cache_s.name string at %lx\n",
					name);
				sprintf(buf, "(unknown)");
			}
		}

		if (reqname && !STREQ(reqname, buf)) 
			goto next_cache;

                if (ignore_cache(si, buf)) {
                        DUMP_KMEM_CACHE_TAG(si->cache, buf, "[IGNORED]");
                        goto next_cache;
                }

		si->curname = buf;

	        readmem(si->cache+OFFSET(kmem_cache_s_objsize),
	        	KVADDR, &tmp_val, sizeof(uint),
	                "objsize", FAULT_ON_ERROR);
		si->size = (ulong)tmp_val;

		if (!si->size) {
			if (STREQ(si->curname, "kmem_cache"))
				si->size = SIZE(kmem_cache_s);
			else {
				error(INFO, "\"%s\" cache: objsize: %ld\n",
					si->curname, si->size);
				si->errors++;
			}
		}

	        readmem(si->cache+OFFSET(kmem_cache_s_flags), 
			KVADDR, &tmp_val, sizeof(uint),
	                "kmem_cache_s flags", FAULT_ON_ERROR);
		si->c_flags = (ulong)tmp_val;

                readmem(si->cache+OFFSET(kmem_cache_s_gfporder),
                        KVADDR, &tmp_val, sizeof(uint),
                        "gfporder", FAULT_ON_ERROR);
		si->order = (ulong)tmp_val;

        	readmem(si->cache+OFFSET(kmem_cache_s_num),
                	KVADDR, &tmp_val, sizeof(uint),
                	"kmem_cache_s num", FAULT_ON_ERROR);
		si->c_num = (ulong)tmp_val;

		do_slab_chain_percpu_v1(SLAB_GET_COUNTS, si);

		if (!(si->flags & (ADDRESS_SPECIFIED|GET_SLAB_PAGES))) {
			DUMP_KMEM_CACHE_INFO();
			if (CRASHDEBUG(3))
				dump_struct("kmem_cache_s", si->cache, 0);
		}

		if (si->flags == GET_SLAB_PAGES) 
			si->retval += (si->num_slabs * 
				(si->slabsize/PAGESIZE()));

		if (si->flags & (VERBOSE|ADDRESS_SPECIFIED)) {

			gather_cpudata_list_v1(si);

                        si->slab = (si->flags & ADDRESS_SPECIFIED) ?
                        	vaddr_to_slab(si->spec_addr) : 0;

			do_slab_chain_percpu_v1(SLAB_WALKTHROUGH, si);

			if (si->found) {
				fprintf(fp, "%s", kmem_cache_hdr);
				DUMP_KMEM_CACHE_INFO();
				fprintf(fp, "%s", slab_hdr);
        			gather_slab_cached_count(si);
				DUMP_SLAB_INFO();

				switch (si->found)
				{
				case KMEM_BUFCTL_ADDR:
					fprintf(fp, "   %lx ", 
						(ulong)si->spec_addr);
					fprintf(fp,"(kmem_bufctl_t)\n");
					break;

				case KMEM_SLAB_ADDR:
					fprintf(fp, "   %lx ", 
						(ulong)si->spec_addr);
					fprintf(fp, "(slab_s)\n");
					break;

				case KMEM_ON_SLAB:
					fprintf(fp, "   %lx ", 
						(ulong)si->spec_addr);
					fprintf(fp, "(unused part of slab)\n");
					break;
						
				case KMEM_OBJECT_ADDR_FREE:
                                        fprintf(fp, "%s", free_inuse_hdr);
					fprintf(fp, "   %lx\n", 
						si->container ? si->container :
						(ulong)si->spec_addr);
					break;

                                case KMEM_OBJECT_ADDR_INUSE:
                                        fprintf(fp, "%s", free_inuse_hdr);
					fprintf(fp, "  [%lx]\n", 
						si->container ? si->container :
						(ulong)si->spec_addr);
                                        break;

                                case KMEM_OBJECT_ADDR_CACHED:
                                        fprintf(fp, "%s", free_inuse_hdr);
                                        fprintf(fp, 
					    "   %lx  (cpu %d cache)\n", 
						si->container ? si->container :
						(ulong)si->spec_addr, si->cpu);
                                        break;
				}

				break;
			}
		}

next_cache:
                readmem(si->cache+OFFSET(kmem_cache_s_next), 
		        KVADDR, &si->cache, sizeof(ulong),
                        "kmem_cache_s next", FAULT_ON_ERROR);

		si->cache -= OFFSET(kmem_cache_s_next);

	} while (si->cache != cache_cache);

        if ((si->flags & ADDRESS_SPECIFIED) && !si->found)
		error(INFO, "%s: address not found in cache: %lx\n", 
			reqname, si->spec_addr);
 
	if (si->errors)
		error(INFO, "%ld error%s encountered\n", 
			si->errors, si->errors > 1 ? "s" : "");

	FREEBUF(si->addrlist);
	FREEBUF(si->kmem_bufctl);
        for (i = 0; i < vt->kmem_max_cpus; i++)
                FREEBUF(si->cpudata[i]);

}


/*
 *  Updated for 2.6 slab substructure. 
 */
static void
dump_kmem_cache_percpu_v2(struct meminfo *si)
{
	int i;
	char buf[BUFSIZE];
	char kbuf[BUFSIZE];
	char *reqname;
	ulong cache_end;
	ulong name, page_head;
	int cnt;
	uint tmp_val; /* Used as temporary variable to read sizeof(int) and
			assigned to ulong variable. We are doing this to mask
			the endian issue */
	char *p1;

        if (!(vt->flags & PERCPU_KMALLOC_V2)) 
                error(FATAL, 
                   "dump_kmem_cache_percpu called without PERCPU_KMALLOC_V2\n");

	si->found = si->retval = 0;
	reqname = NULL;

	if ((!(si->flags & VERBOSE) || si->reqname) &&
	     !(si->flags & (ADDRESS_SPECIFIED|GET_SLAB_PAGES)))
		fprintf(fp, "%s", kmem_cache_hdr);

	si->addrlist = (ulong *)GETBUF((vt->kmem_max_c_num+1) * sizeof(ulong));
	si->kmem_bufctl = (int *)GETBUF((vt->kmem_max_c_num+1) * sizeof(int));
	if (vt->flags & SLAB_OVERLOAD_PAGE) {
		si->freelist = si->kmem_bufctl;
		si->freelist_index_size = slab_freelist_index_size();
		si->list_offset = VALID_MEMBER(slab_slab_list) ?
					OFFSET(slab_slab_list) : OFFSET(page_lru);
	}
	for (i = 0; i < vt->kmem_max_cpus; i++) 
		si->cpudata[i] = (ulong *)
			GETBUF(vt->kmem_max_limit * sizeof(ulong)); 
	if(vt->flags & PERCPU_KMALLOC_V2_NODES)
		si->shared_array_cache = (ulong *)
			GETBUF(vt->kmem_cache_len_nodes * 
				(vt->kmem_max_limit+1) * sizeof(ulong)); 
	else
		si->shared_array_cache = (ulong *)
			GETBUF((vt->kmem_max_limit+1) * sizeof(ulong)); 

	cnt = 0;

	if (si->flags & CACHE_SET)
		readmem(si->cache+OFFSET(kmem_cache_s_next), 
			KVADDR, &cache_end, sizeof(ulong),
			"kmem_cache_s next", FAULT_ON_ERROR);
	else {
		if (vt->flags & KMALLOC_COMMON) {
			get_symbol_data("slab_caches", sizeof(ulong), &si->cache);
			si->cache -= OFFSET(kmem_cache_s_next);
			cache_end = symbol_value("slab_caches");
		} else {
			get_symbol_data("cache_chain", sizeof(ulong), &si->cache);
			si->cache -= OFFSET(kmem_cache_s_next);
			cache_end = symbol_value("cache_chain");
		}
	}

	if (si->flags & ADDRESS_SPECIFIED) {
		if ((p1 = is_slab_overload_page(si->spec_addr, &page_head, kbuf))) {
			si->flags |= SLAB_OVERLOAD_PAGE_PTR;
			si->spec_addr = page_head;	
	        } else if (!(p1 = vaddr_to_kmem_cache(si->spec_addr, kbuf, VERBOSE))) {
			error(INFO, 
			   "address is not allocated in slab subsystem: %lx\n",
				si->spec_addr);
			return;
		}
		
		if (si->reqname && (si->reqname != p1)) 
			error(INFO, 
			    "ignoring pre-selected %s cache for address: %lx\n",
				si->reqname, si->spec_addr, si->reqname);
		reqname = p1;
	} else
		reqname = si->reqname;

	do {
		if ((si->flags & VERBOSE) && !si->reqname &&
		    !(si->flags & ADDRESS_SPECIFIED))
			fprintf(fp, "%s%s", cnt++ ? "\n" : "", kmem_cache_hdr);

		if (vt->kmem_cache_namelen) {
                        readmem(si->cache+OFFSET(kmem_cache_s_name), 
				KVADDR, buf, vt->kmem_cache_namelen,
                                "name array", FAULT_ON_ERROR);
		} else {
                	readmem(si->cache+OFFSET(kmem_cache_s_name), 
				KVADDR, &name, sizeof(ulong),
                        	"name", FAULT_ON_ERROR);
                	if (!read_string(name, buf, BUFSIZE-1)) {
				error(WARNING, 
			      "cannot read kmem_cache_s.name string at %lx\n",
					name);
				sprintf(buf, "(unknown)");
			}
		}

		if (reqname && !STREQ(reqname, buf)) 
			goto next_cache;

                if (ignore_cache(si, buf)) {
                        DUMP_KMEM_CACHE_TAG(si->cache, buf, "[IGNORED]");
                        goto next_cache;
                }

		if (bad_slab_cache(si->cache)) {
                        DUMP_KMEM_CACHE_TAG(si->cache, buf, "[INVALID/CORRUPTED]");
                        goto next_cache;
		}

		si->curname = buf;

	        readmem(si->cache+OFFSET(kmem_cache_s_objsize),
	        	KVADDR, &tmp_val, sizeof(uint),
	                "objsize", FAULT_ON_ERROR);
		si->size = (ulong)tmp_val;

		if (!si->size) {
			if (STREQ(si->curname, "kmem_cache"))
				si->size = SIZE(kmem_cache_s);
			else {
				error(INFO, "\"%s\" cache: objsize: %ld\n",
					si->curname, si->size);
				si->errors++;
			}
		}

	        readmem(si->cache+OFFSET(kmem_cache_s_flags), 
			KVADDR, &tmp_val, sizeof(uint),
	                "kmem_cache_s flags", FAULT_ON_ERROR);
		si->c_flags = (ulong)tmp_val;

                readmem(si->cache+OFFSET(kmem_cache_s_gfporder),
                        KVADDR, &tmp_val, sizeof(uint),
                        "gfporder", FAULT_ON_ERROR);
		si->order = (ulong)tmp_val;

        	readmem(si->cache+OFFSET(kmem_cache_s_num),
                	KVADDR, &tmp_val, sizeof(uint),
                	"kmem_cache_s num", FAULT_ON_ERROR);
		si->c_num = (ulong)tmp_val;

		if (vt->flags & PERCPU_KMALLOC_V2_NODES) {
			if (vt->flags & SLAB_OVERLOAD_PAGE)
				do_slab_chain_slab_overload_page(SLAB_GET_COUNTS, si);
			else
				do_slab_chain_percpu_v2_nodes(SLAB_GET_COUNTS, si);
		} else
			do_slab_chain_percpu_v2(SLAB_GET_COUNTS, si);

		if (!(si->flags & (ADDRESS_SPECIFIED|GET_SLAB_PAGES))) {
			DUMP_KMEM_CACHE_INFO();
			if (CRASHDEBUG(3))
				dump_struct("kmem_cache_s", si->cache, 0);
		}

		if (si->flags == GET_SLAB_PAGES) 
			si->retval += (si->num_slabs * 
				(si->slabsize/PAGESIZE()));

		if (si->flags & (VERBOSE|ADDRESS_SPECIFIED)) {

			if (!(vt->flags & PERCPU_KMALLOC_V2_NODES))
				gather_cpudata_list_v2(si);

                        si->slab = (si->flags & ADDRESS_SPECIFIED) ?
                        	vaddr_to_slab(si->spec_addr) : 0;

			if (vt->flags & PERCPU_KMALLOC_V2_NODES) {
				if (vt->flags & SLAB_OVERLOAD_PAGE)
					do_slab_chain_slab_overload_page(SLAB_WALKTHROUGH, si);
				else
					do_slab_chain_percpu_v2_nodes(SLAB_WALKTHROUGH, si);
			} else 
				do_slab_chain_percpu_v2(SLAB_WALKTHROUGH, si);

			if (si->found) {
				fprintf(fp, "%s", kmem_cache_hdr);
				DUMP_KMEM_CACHE_INFO();
				fprintf(fp, "%s", slab_hdr);
        			gather_slab_cached_count(si);
				DUMP_SLAB_INFO();

				switch (si->found)
				{
				case KMEM_BUFCTL_ADDR:
					fprintf(fp, "   %lx ", 
						(ulong)si->spec_addr);
					fprintf(fp,"(kmem_bufctl_t)\n");
					break;

				case KMEM_SLAB_ADDR:
					fprintf(fp, "   %lx ", 
						(ulong)si->spec_addr);
					fprintf(fp, "(slab)\n");
					break;

				case KMEM_ON_SLAB:
					fprintf(fp, "   %lx ", 
						(ulong)si->spec_addr);
					fprintf(fp, "(unused part of slab)\n");
					break;

				case KMEM_SLAB_FREELIST:
					fprintf(fp, "   %lx ", 
						(ulong)si->spec_addr);
					fprintf(fp, "(on-slab freelist)\n");
					break;

				case KMEM_SLAB_OVERLOAD_PAGE:
					si->flags &= ~ADDRESS_SPECIFIED;
					dump_slab_objects_percpu(si);
					si->flags |= ADDRESS_SPECIFIED;
					break;
						
				case KMEM_OBJECT_ADDR_FREE:
                                        fprintf(fp, "%s", free_inuse_hdr);
					fprintf(fp, "   %lx\n", 
						si->container ? si->container :
						(ulong)si->spec_addr);
					break;

                                case KMEM_OBJECT_ADDR_INUSE:
                                        fprintf(fp, "%s", free_inuse_hdr);
                                        fprintf(fp, "  [%lx]\n", 
						si->container ? si->container :
						(ulong)si->spec_addr);
                                        break;

                                case KMEM_OBJECT_ADDR_CACHED:
                                        fprintf(fp, "%s", free_inuse_hdr);
                                        fprintf(fp, 
					    "   %lx  (cpu %d cache)\n", 
						si->container ? si->container :
						(ulong)si->spec_addr, si->cpu);
                                        break;

                                case KMEM_OBJECT_ADDR_SHARED:
                                        fprintf(fp, "%s", free_inuse_hdr);
                                        fprintf(fp,
                                            "   %lx  (shared cache)\n",
						si->container ? si->container :
                                                (ulong)si->spec_addr);
                                        break;
                                }

				break;
			}
		}

next_cache:
                readmem(si->cache+OFFSET(kmem_cache_s_next), 
		        KVADDR, &si->cache, sizeof(ulong),
                        "kmem_cache_s next", FAULT_ON_ERROR);

                if (si->cache != cache_end)
			si->cache -= OFFSET(kmem_cache_s_next);

	} while (si->cache != cache_end);

        if ((si->flags & ADDRESS_SPECIFIED) && !si->found)
		error(INFO, "%s: address not found in cache: %lx\n", 
			reqname, si->spec_addr);
 
	if (si->errors)
		error(INFO, "%ld error%s encountered\n", 
			si->errors, si->errors > 1 ? "s" : "");

	FREEBUF(si->addrlist);
	FREEBUF(si->kmem_bufctl);
        for (i = 0; i < vt->kmem_max_cpus; i++)
                FREEBUF(si->cpudata[i]);
	FREEBUF(si->shared_array_cache);

}


/*
 *  Walk through the slab chain hanging off a kmem_cache_s structure,
 *  gathering basic statistics.
 *
 *  TBD: Given a specified physical address, determine whether it's in this
 *  slab chain, and whether it's in use or not.
 */

#define INSLAB(obj, si) \
  ((ulong)((ulong)(obj) & ~(si->slabsize-1)) == si->s_mem)

static void
do_slab_chain(int cmd, struct meminfo *si)
{
	ulong tmp, magic;
	ulong kmem_slab_end;
	char *kmem_slab_s_buf;

	si->slabsize = (power(2, si->order) * PAGESIZE());

	kmem_slab_end = si->cache + OFFSET(kmem_cache_s_c_offset);

	switch (cmd)
	{
	case SLAB_GET_COUNTS:
		si->slab = ULONG(si->cache_buf + OFFSET(kmem_cache_s_c_firstp));

		if (slab_data_saved(si))
			return;

		si->num_slabs = si->inuse = 0;

		if (si->slab == kmem_slab_end)
			return;

		kmem_slab_s_buf = GETBUF(SIZE(kmem_slab_s));

		do {
			if (received_SIGINT()) {
				FREEBUF(kmem_slab_s_buf);
				restart(0);
			}

			readmem(si->slab, KVADDR, kmem_slab_s_buf,
				SIZE(kmem_slab_s), "kmem_slab_s buffer",
				FAULT_ON_ERROR);

			magic = ULONG(kmem_slab_s_buf +
				OFFSET(kmem_slab_s_s_magic));

			if (magic == SLAB_MAGIC_ALLOC) {
	
				tmp = ULONG(kmem_slab_s_buf +
					OFFSET(kmem_slab_s_s_inuse));
	
				si->inuse += tmp;
				si->num_slabs++;
			} else {
				fprintf(fp, 
			   	    "\"%s\" cache: invalid s_magic: %lx\n", 
					si->curname, magic);
				si->errors++;
				FREEBUF(kmem_slab_s_buf);
				return;
			}
	
			si->slab = ULONG(kmem_slab_s_buf +
				OFFSET(kmem_slab_s_s_nextp));
	
		} while (si->slab != kmem_slab_end);
		
		FREEBUF(kmem_slab_s_buf);
		save_slab_data(si);
		break;

	case SLAB_WALKTHROUGH:
        	if (!si->slab)
			si->slab = ULONG(si->cache_buf + 
				OFFSET(kmem_cache_s_c_firstp));

		if (si->slab == kmem_slab_end)
			return;

		if (CRASHDEBUG(1)) {
			fprintf(fp, "search cache: [%s] ", si->curname);
			if (si->flags & ADDRESS_SPECIFIED) 
				fprintf(fp, "for %llx", si->spec_addr);
			fprintf(fp, "\n");
		}

		si->slab_buf = kmem_slab_s_buf = GETBUF(SIZE(kmem_slab_s));

	        do {
                        if (received_SIGINT()) {
				FREEBUF(kmem_slab_s_buf);
                                restart(0);
			}

			readmem(si->slab, KVADDR, kmem_slab_s_buf,
				SIZE(kmem_slab_s), "kmem_slab_s buffer",
				FAULT_ON_ERROR);

	                dump_slab(si);
	
	                if (si->found) {
				FREEBUF(kmem_slab_s_buf);
	                        return;
			}
	
			si->slab = ULONG(kmem_slab_s_buf +
				OFFSET(kmem_slab_s_s_nextp));
	
	        } while (si->slab != kmem_slab_end);

		FREEBUF(kmem_slab_s_buf);
		break;
	}
}


/*
 *  do_slab_chain() adapted for newer percpu slab format.
 */

#define SLAB_BASE(X) (PTOB(BTOP(X)))

#define INSLAB_PERCPU(obj, si) \
  ((ulong)((ulong)(obj) & ~(si->slabsize-1)) == SLAB_BASE(si->s_mem))

#define SLAB_CHAINS (3)

static char *slab_chain_name_v1[] = {"full", "partial", "free"};

static void
do_slab_chain_percpu_v1(long cmd, struct meminfo *si)
{
	int i, tmp, s;
	int list_borked;
	char *slab_s_buf;
	ulong specified_slab;
	ulong last;
	ulong slab_chains[SLAB_CHAINS];

	list_borked = 0;
	si->slabsize = (power(2, si->order) * PAGESIZE());
	si->cpucached_slab = 0;

	if (VALID_MEMBER(kmem_cache_s_slabs)) {
		slab_chains[0] = si->cache + OFFSET(kmem_cache_s_slabs);
		slab_chains[1] = 0;
		slab_chains[2] = 0;
	} else {
		slab_chains[0] = si->cache + OFFSET(kmem_cache_s_slabs_full);
		slab_chains[1] = si->cache + OFFSET(kmem_cache_s_slabs_partial);
		slab_chains[2] = si->cache + OFFSET(kmem_cache_s_slabs_free);
	}

	if (CRASHDEBUG(1)) {
		fprintf(fp, "[ %s: %lx ", si->curname, si->cache);
		fprintf(fp, "full: %lx partial: %lx free: %lx ]\n",
			slab_chains[0], slab_chains[1], slab_chains[2]);
	}

	switch (cmd)
	{
	case SLAB_GET_COUNTS:
		si->flags |= SLAB_GET_COUNTS;
		si->flags &= ~SLAB_WALKTHROUGH;
		si->cpucached_cache = 0;
        	si->num_slabs = si->inuse = 0;
		gather_cpudata_list_v1(si); 

		slab_s_buf = GETBUF(SIZE(slab_s));

		for (s = 0; s < SLAB_CHAINS; s++) {

			if (!slab_chains[s])
				continue;

	                if (!readmem(slab_chains[s],
	                    KVADDR, &si->slab, sizeof(ulong),
	                    "first slab", QUIET|RETURN_ON_ERROR)) {
                		error(INFO, 
				    "%s: %s list: bad slab pointer: %lx\n",
                        		si->curname, slab_chain_name_v1[s],
					slab_chains[s]);
				list_borked = 1;
				continue;
			}
	
			if (slab_data_saved(si)) {
				FREEBUF(slab_s_buf);
				return;
			}
	
			if (si->slab == slab_chains[s]) 
				continue;
	
			last = slab_chains[s];

			do {
	                        if (received_SIGINT()) {
					FREEBUF(slab_s_buf);
	                                restart(0);
				}

				if (!verify_slab_v1(si, last, s)) {
					list_borked = 1;
					continue;
				}
				last = si->slab - OFFSET(slab_s_list);
	
		                readmem(si->slab, KVADDR, slab_s_buf, 
					SIZE(slab_s), "slab_s buffer", 
					FAULT_ON_ERROR);
	
				tmp = INT(slab_s_buf + OFFSET(slab_s_inuse));
				si->inuse += tmp;
	
				if (ACTIVE())
					gather_cpudata_list_v1(si); 

				si->s_mem = ULONG(slab_s_buf + 
					OFFSET(slab_s_s_mem));
				gather_slab_cached_count(si);
	
				si->num_slabs++;
		
				si->slab = ULONG(slab_s_buf + 
					OFFSET(slab_s_list));
				si->slab -= OFFSET(slab_s_list);

				/*
				 *  Check for slab transition. (Tony Dziedzic)
				 */
				for (i = 0; i < SLAB_CHAINS; i++) {
     					if ((i != s) && 
					    (si->slab == slab_chains[i])) {
       						error(NOTE, 
	  	                      "%s: slab chain inconsistency: %s list\n",
							si->curname,
							slab_chain_name_v1[s]);
       						list_borked = 1;
     					}
				}
		
			} while (si->slab != slab_chains[s] && !list_borked);
		}

		FREEBUF(slab_s_buf);
		if (!list_borked)
			save_slab_data(si);
		break;

	case SLAB_WALKTHROUGH:
		specified_slab = si->slab;
		si->flags |= SLAB_WALKTHROUGH;
		si->flags &= ~SLAB_GET_COUNTS;

		for (s = 0; s < SLAB_CHAINS; s++) {
			if (!slab_chains[s])
				continue;

	        	if (!specified_slab) {
	                	if (!readmem(slab_chains[s],
	                            KVADDR, &si->slab, sizeof(ulong),
	                            "slabs", QUIET|RETURN_ON_ERROR)) {
                			error(INFO, 
				         "%s: %s list: bad slab pointer: %lx\n",
                        			si->curname, 
						slab_chain_name_v1[s],
						slab_chains[s]);
					list_borked = 1;
					continue;
				}
				last = slab_chains[s];
			} else
				last = 0;
	
			if (si->slab == slab_chains[s])
				continue;

			if (CRASHDEBUG(1)) {
				fprintf(fp, "search cache: [%s] ", si->curname);
				if (si->flags & ADDRESS_SPECIFIED) 
					fprintf(fp, "for %llx", si->spec_addr);
				fprintf(fp, "\n");
			}
	
		        do {
	                        if (received_SIGINT())
	                                restart(0);

				if (!verify_slab_v1(si, last, s)) {
					list_borked = 1;
					continue;
				}
				last = si->slab - OFFSET(slab_s_list);
	
		                dump_slab_percpu_v1(si);
		
		                if (si->found) {
					return;
				}
		
		                readmem(si->slab+OFFSET(slab_s_list),
		                        KVADDR, &si->slab, sizeof(ulong),
		                        "slab list", FAULT_ON_ERROR);
		
				si->slab -= OFFSET(slab_s_list);
	
		        } while (si->slab != slab_chains[s] && !list_borked);
		}

		break;
	}
}

/*
 *  Try to preclude any attempt to translate a bogus slab structure.
 */

static int
verify_slab_v1(struct meminfo *si, ulong last, int s)
{
	char slab_s_buf[BUFSIZE];
	struct kernel_list_head *list_head;
	unsigned int inuse;
	ulong s_mem;
	char *list;
	int errcnt;

	list = slab_chain_name_v1[s];

	errcnt = 0;

        if (!readmem(si->slab, KVADDR, slab_s_buf,
            SIZE(slab_s), "slab_s buffer", QUIET|RETURN_ON_ERROR)) {
                error(INFO, "%s: %s list: bad slab pointer: %lx\n",
                        si->curname, list, si->slab);
		return FALSE;
        }                        

        list_head = (struct kernel_list_head *)
		(slab_s_buf + OFFSET(slab_s_list));

	if (!IS_KVADDR((ulong)list_head->next) || 
	    !accessible((ulong)list_head->next)) {
                error(INFO, "%s: %s list: slab: %lx  bad next pointer: %lx\n",
                        si->curname, list, si->slab,
			(ulong)list_head->next);
		errcnt++;
	}

	if (last && (last != (ulong)list_head->prev)) {
                error(INFO, "%s: %s list: slab: %lx  bad prev pointer: %lx\n",
                        si->curname, list, si->slab,
                        (ulong)list_head->prev);
		errcnt++;
	}

	inuse = UINT(slab_s_buf + OFFSET(slab_s_inuse));
	if (inuse > si->c_num) {
                error(INFO, "%s: %s list: slab: %lx  bad inuse counter: %ld\n",
                        si->curname, list, si->slab, inuse);
		errcnt++;
	}

	if (!last)
		goto no_inuse_check_v1;

	switch (s) 
	{
	case 0: /* full -- but can be one singular list */
                if (VALID_MEMBER(kmem_cache_s_slabs_full) && 
		    (inuse != si->c_num)) {
                        error(INFO,
                            "%s: %s list: slab: %lx  bad inuse counter: %ld\n",
                                si->curname, list, si->slab, inuse);
                        errcnt++;
                }
		break;

	case 1: /* partial */
		if ((inuse == 0) || (inuse == si->c_num)) {
                	error(INFO, 
		 	    "%s: %s list: slab: %lx  bad inuse counter: %ld\n",
                        	si->curname,  list, si->slab, inuse);
			errcnt++;
		}
		break;

	case 2: /* free */
		if (inuse > 0) {
                	error(INFO, 
		 	    "%s: %s list: slab: %lx  bad inuse counter: %ld\n",
                        	si->curname, list, si->slab, inuse);
			errcnt++;
		}
		break;
	}

no_inuse_check_v1:
	s_mem = ULONG(slab_s_buf + OFFSET(slab_s_s_mem));
	if (!IS_KVADDR(s_mem) || !accessible(s_mem)) {
                error(INFO, "%s: %s list: slab: %lx  bad s_mem pointer: %lx\n",
                        si->curname, list, si->slab, s_mem);
		errcnt++;
	}

	si->errors += errcnt;

	return(errcnt ? FALSE : TRUE);
}

/*
 *  Updated for 2.6 slab substructure.
 */

static char *slab_chain_name_v2[] = {"partial", "full", "free"};

static void
do_slab_chain_percpu_v2(long cmd, struct meminfo *si)
{
	int i, tmp, s;
	int list_borked;
	char *slab_buf;
	ulong specified_slab;
	ulong last;
	ulong slab_chains[SLAB_CHAINS];

	list_borked = 0;
	si->slabsize = (power(2, si->order) * PAGESIZE());
	si->cpucached_slab = 0;

	slab_chains[0] = si->cache + OFFSET(kmem_cache_s_lists) +
		OFFSET(kmem_list3_slabs_partial);
	slab_chains[1] = si->cache + OFFSET(kmem_cache_s_lists) +
                OFFSET(kmem_list3_slabs_full);
        slab_chains[2] = si->cache + OFFSET(kmem_cache_s_lists) +
                OFFSET(kmem_list3_slabs_free);

        if (CRASHDEBUG(1)) {
                fprintf(fp, "[ %s: %lx ", si->curname, si->cache);
                fprintf(fp, "partial: %lx full: %lx free: %lx ]\n",
                        slab_chains[0], slab_chains[1], slab_chains[2]);
        }

	switch (cmd)
	{
	case SLAB_GET_COUNTS:
		si->flags |= SLAB_GET_COUNTS;
		si->flags &= ~SLAB_WALKTHROUGH;
		si->cpucached_cache = 0;
        	si->num_slabs = si->inuse = 0;
		gather_cpudata_list_v2(si); 

		slab_buf = GETBUF(SIZE(slab));

		for (s = 0; s < SLAB_CHAINS; s++) {
			if (!slab_chains[s])
				continue;

	                if (!readmem(slab_chains[s],
	                    KVADDR, &si->slab, sizeof(ulong),
	                    "first slab", QUIET|RETURN_ON_ERROR)) {
                                error(INFO, 
				    "%s: %s list: bad slab pointer: %lx\n",
                                        si->curname,
					slab_chain_name_v2[s],
                                        slab_chains[s]);
				list_borked = 1;
				continue;
			}
	
			if (slab_data_saved(si)) {
				FREEBUF(slab_buf);
				return;
			}
	
			if (si->slab == slab_chains[s]) 
				continue;
	
			last = slab_chains[s];

			do {
	                        if (received_SIGINT()) {
					FREEBUF(slab_buf);
	                                restart(0);
				}

				if (!verify_slab_v2(si, last, s)) {
					list_borked = 1;
					continue;
				}
				last = si->slab - OFFSET(slab_list);
	
		                readmem(si->slab, KVADDR, slab_buf, 
					SIZE(slab), "slab buffer", 
					FAULT_ON_ERROR);
	
				tmp = INT(slab_buf + OFFSET(slab_inuse));
				si->inuse += tmp;
	
				if (ACTIVE())
					gather_cpudata_list_v2(si); 

				si->s_mem = ULONG(slab_buf + 
					OFFSET(slab_s_mem));
				gather_slab_cached_count(si);
	
				si->num_slabs++;
		
				si->slab = ULONG(slab_buf + 
					OFFSET(slab_list));
				si->slab -= OFFSET(slab_list);

				/*
				 *  Check for slab transition. (Tony Dziedzic)
				 */
				for (i = 0; i < SLAB_CHAINS; i++) {
     					if ((i != s) && 
					    (si->slab == slab_chains[i])) {
       						error(NOTE, 
	  	                      "%s: slab chain inconsistency: %s list\n",
							si->curname,
							slab_chain_name_v2[s]);
       						list_borked = 1;
     					}
				}
		
			} while (si->slab != slab_chains[s] && !list_borked);
		}

		FREEBUF(slab_buf);
		if (!list_borked)
			save_slab_data(si);
		break;

	case SLAB_WALKTHROUGH:
		specified_slab = si->slab;
		si->flags |= SLAB_WALKTHROUGH;
		si->flags &= ~SLAB_GET_COUNTS;

		for (s = 0; s < SLAB_CHAINS; s++) {
			if (!slab_chains[s])
				continue;

	        	if (!specified_slab) {
	                	if (!readmem(slab_chains[s],
	                            KVADDR, &si->slab, sizeof(ulong),
	                            "slabs", QUIET|RETURN_ON_ERROR)) {
                                        error(INFO,
                                         "%s: %s list: bad slab pointer: %lx\n",
                                                si->curname,
						slab_chain_name_v2[s],
                                                slab_chains[s]);
					list_borked = 1;
					continue;
				}
				last = slab_chains[s];
			} else
				last = 0;
			
			if (si->slab == slab_chains[s])
				continue;
	
			if (CRASHDEBUG(1)) {
				fprintf(fp, "search cache: [%s] ", si->curname);
				if (si->flags & ADDRESS_SPECIFIED) 
					fprintf(fp, "for %llx", si->spec_addr);
				fprintf(fp, "\n");
			}
	
		        do {
	                        if (received_SIGINT())
	                                restart(0);
	
                                if (!verify_slab_v2(si, last, s)) {
                                        list_borked = 1;
                                        continue;
                                }
                                last = si->slab - OFFSET(slab_list);

		                dump_slab_percpu_v2(si);
		
		                if (si->found) {
					return;
				}
		
		                readmem(si->slab+OFFSET(slab_list),
		                        KVADDR, &si->slab, sizeof(ulong),
		                        "slab list", FAULT_ON_ERROR);
		
				si->slab -= OFFSET(slab_list);
	
		        } while (si->slab != slab_chains[s] && !list_borked);
		}

		break;
	}
}


/* 
* Added To  Traverse the Nodelists 
*/

static void
do_slab_chain_percpu_v2_nodes(long cmd, struct meminfo *si)
{
	int i, tmp, s, node;
	int list_borked;
	char *slab_buf;
	ulong specified_slab;
	ulong last;
	ulong slab_chains[SLAB_CHAINS];
	ulong *start_address;
	int index;

	list_borked = 0;
	slab_buf = NULL;
	si->slabsize = (power(2, si->order) * PAGESIZE());
	si->cpucached_slab = 0;
	start_address = (ulong *)GETBUF(sizeof(ulong) * vt->kmem_cache_len_nodes);

	if (!readmem(kmem_cache_nodelists(si->cache), KVADDR, 
            &start_address[0], sizeof(ulong) * vt->kmem_cache_len_nodes, 
            "array nodelist array", RETURN_ON_ERROR)) 
                    error(INFO, "cannot read kmem_cache nodelists array"); 

	switch (cmd)
	{
	case SLAB_GET_COUNTS:
		si->flags |= (SLAB_GET_COUNTS|SLAB_FIRST_NODE);
		si->flags &= ~SLAB_WALKTHROUGH;
		si->cpucached_cache = 0;
        	si->num_slabs = si->inuse = 0;
		slab_buf = GETBUF(SIZE(slab));
		for (index = 0; (index < vt->kmem_cache_len_nodes); index++)
		{ 
			if (vt->flags & NODES_ONLINE) {
				node = next_online_node(index);
				if (node < 0)
					break;
				if (node != index)
					continue;
			}
			if (start_address[index] == 0)
				continue;

			slab_chains[0] = start_address[index] + OFFSET(kmem_list3_slabs_partial);
			slab_chains[1] = start_address[index] + OFFSET(kmem_list3_slabs_full);
		        slab_chains[2] = start_address[index] + OFFSET(kmem_list3_slabs_free);
			
			gather_cpudata_list_v2_nodes(si, index); 

			si->flags &= ~SLAB_FIRST_NODE;
	
		        if (CRASHDEBUG(1)) {
                		fprintf(fp, "[ %s: %lx ", si->curname, si->cache);
	                	fprintf(fp, "partial: %lx full: %lx free: %lx ]\n",
                        		slab_chains[0], slab_chains[1], slab_chains[2]);
			}

			for (s = 0; s < SLAB_CHAINS; s++) {
				if (!slab_chains[s])
					continue;
	
		                if (!readmem(slab_chains[s],
	        	            KVADDR, &si->slab, sizeof(ulong),
	                	    "first slab", QUIET|RETURN_ON_ERROR)) {
	                                error(INFO, 
					    "%s: %s list: bad slab pointer: %lx\n",
                	                        si->curname,
						slab_chain_name_v2[s],
                                	        slab_chains[s]);
					list_borked = 1;
					continue;
				}
	
				if (slab_data_saved(si)) {
					FREEBUF(slab_buf);
					FREEBUF(start_address);
					return;
				}
			
				if (si->slab == slab_chains[s]) 
					continue;
	
				last = slab_chains[s];

				do {
	        	                if (received_SIGINT()) {
						FREEBUF(slab_buf);
						FREEBUF(start_address);
	                        	        restart(0);
					}

					if (!verify_slab_v2(si, last, s)) {
						list_borked = 1;
						continue;
					}
					last = si->slab - OFFSET(slab_list);
		
		        	        readmem(si->slab, KVADDR, slab_buf, 
						SIZE(slab), "slab buffer", 
						FAULT_ON_ERROR);
		
					tmp = INT(slab_buf + OFFSET(slab_inuse));
					si->inuse += tmp;
	
					si->s_mem = ULONG(slab_buf + 
						OFFSET(slab_s_mem));
					gather_slab_cached_count(si);
	
					si->num_slabs++;
		
					si->slab = ULONG(slab_buf + 
						OFFSET(slab_list));
					si->slab -= OFFSET(slab_list);

				/*
				 *  Check for slab transition. (Tony Dziedzic)
				 */
					for (i = 0; i < SLAB_CHAINS; i++) {
     						if ((i != s) && 
						    (si->slab == slab_chains[i])) {
       							error(NOTE, 
		  	                      "%s: slab chain inconsistency: %s list\n",
								si->curname,
								slab_chain_name_v2[s]);
       							list_borked = 1;
     						}
					}
			
				} while (si->slab != slab_chains[s] && !list_borked);
			}
		}

		if (!list_borked)
			save_slab_data(si);
		break;

	case SLAB_WALKTHROUGH:
		specified_slab = si->slab;     
		si->flags |= (SLAB_WALKTHROUGH|SLAB_FIRST_NODE);
		si->flags &= ~SLAB_GET_COUNTS;
		slab_buf = GETBUF(SIZE(slab));
		for (index = 0; (index < vt->kmem_cache_len_nodes); index++)
		{ 
			if (vt->flags & NODES_ONLINE) {
				node = next_online_node(index);
				if (node < 0)
					break;
				if (node != index)
					continue;
			}
			if (start_address[index] == 0)
				continue;

			slab_chains[0] = start_address[index] + OFFSET(kmem_list3_slabs_partial);
			slab_chains[1] = start_address[index] + OFFSET(kmem_list3_slabs_full);
		        slab_chains[2] = start_address[index] + OFFSET(kmem_list3_slabs_free);
	
			gather_cpudata_list_v2_nodes(si, index);
 
			si->flags &= ~SLAB_FIRST_NODE;

		        if (CRASHDEBUG(1)) {
                		fprintf(fp, "[ %s: %lx ", si->curname, si->cache);
	                	fprintf(fp, "partial: %lx full: %lx free: %lx ]\n",
                        		slab_chains[0], slab_chains[1], slab_chains[2]);
			}

			for (s = 0; s < SLAB_CHAINS; s++) {
				if (!slab_chains[s])
					continue;

				if (!specified_slab) {
					if (!readmem(slab_chains[s],
					    KVADDR, &si->slab, sizeof(ulong),
					    "slabs", QUIET|RETURN_ON_ERROR)) {
						error(INFO, "%s: %s list: "
						    "bad slab pointer: %lx\n",
							si->curname,
							slab_chain_name_v2[s],
							slab_chains[s]);
							list_borked = 1;
							continue;
					}
					last = slab_chains[s];
				} else
					last = 0;

				if (si->slab == slab_chains[s])
					continue;
				
				readmem(si->slab, KVADDR, slab_buf, 
						SIZE(slab), "slab buffer", 
						FAULT_ON_ERROR);
		
				si->s_mem = ULONG(slab_buf + 
						OFFSET(slab_s_mem));

				if (CRASHDEBUG(1)) {
					fprintf(fp, "search cache: [%s] ", si->curname);
					if (si->flags & ADDRESS_SPECIFIED) 
						fprintf(fp, "for %llx", si->spec_addr);
					fprintf(fp, "\n");
				}
	
			        do {
		                        if (received_SIGINT())
					{
						FREEBUF(start_address);
						FREEBUF(slab_buf);
	        	                        restart(0);
					}
	
                        	        if (!verify_slab_v2(si, last, s)) {
                                	        list_borked = 1;
                                        	continue;
	                                }
        	                        last = si->slab - OFFSET(slab_list);
	
			                dump_slab_percpu_v2(si);
					
					if (si->found) {
						FREEBUF(start_address);
						FREEBUF(slab_buf);
						return;
					}
		
			                readmem(si->slab+OFFSET(slab_list),
			                        KVADDR, &si->slab, sizeof(ulong),
			                        "slab list", FAULT_ON_ERROR);
			
					si->slab -= OFFSET(slab_list);
	
			        } while (si->slab != slab_chains[s] && !list_borked);
			}
		}

		break;
	}
	FREEBUF(slab_buf);
	FREEBUF(start_address);
}


static int
slab_freelist_index_size(void)
{
	struct datatype_member datatype, *dm;

	dm = &datatype;
	BZERO(dm, sizeof(*dm));
	dm->name = "freelist_idx_t";

	if (is_typedef(dm->name))
		return DATATYPE_SIZE(dm);

	if (CRASHDEBUG(1))
		error(INFO, "freelist_idx_t does not exist\n");

	return sizeof(int);
}

static void
do_slab_chain_slab_overload_page(long cmd, struct meminfo *si)
{
	int i, tmp, s, node;
	int list_borked;
	char *page_buf;
	ulong specified_slab;
	ulong last;
	ulong slab_chains[SLAB_CHAINS];
	ulong *start_address;
	int index;

	list_borked = 0;
	page_buf = NULL;
	si->slabsize = (power(2, si->order) * PAGESIZE());
	si->cpucached_slab = 0;
	start_address = (ulong *)GETBUF(sizeof(ulong) * vt->kmem_cache_len_nodes);

	if (!readmem(kmem_cache_nodelists(si->cache), KVADDR, 
	    &start_address[0], sizeof(ulong) * vt->kmem_cache_len_nodes, 
	    "array nodelist array", RETURN_ON_ERROR)) 
		error(INFO, "cannot read kmem_cache nodelists array"); 

	switch (cmd)
	{
	case SLAB_GET_COUNTS:
		si->flags |= (SLAB_GET_COUNTS|SLAB_FIRST_NODE);
		si->flags &= ~SLAB_WALKTHROUGH;
		si->cpucached_cache = 0;
		si->num_slabs = si->inuse = 0;
		page_buf = GETBUF(SIZE(page));
		for (index = 0; (index < vt->kmem_cache_len_nodes); index++)
		{ 
			if (vt->flags & NODES_ONLINE) {
				node = next_online_node(index);
				if (node < 0)
					break;
				if (node != index)
					continue;
			}
			if (start_address[index] == 0)
				continue;

			slab_chains[0] = start_address[index] + OFFSET(kmem_list3_slabs_partial);
			slab_chains[1] = start_address[index] + OFFSET(kmem_list3_slabs_full);
			slab_chains[2] = start_address[index] + OFFSET(kmem_list3_slabs_free);
			
			gather_cpudata_list_v2_nodes(si, index); 

			si->flags &= ~SLAB_FIRST_NODE;
	
			if (CRASHDEBUG(1)) {
				fprintf(fp, "[ %s: %lx ", si->curname, si->cache);
				fprintf(fp, "partial: %lx full: %lx free: %lx ]\n",
					slab_chains[0], slab_chains[1], slab_chains[2]);
			}

			for (s = 0; s < SLAB_CHAINS; s++) {
				if (!slab_chains[s])
					continue;
	
				if (!readmem(slab_chains[s],
				    KVADDR, &si->slab, sizeof(ulong),
				    "first slab", QUIET|RETURN_ON_ERROR)) {
					error(INFO, 
					    "%s: %s list: bad page/slab pointer: %lx\n",
						si->curname,
						slab_chain_name_v2[s],
						slab_chains[s]);
					list_borked = 1;
					continue;
				}
	
				if (slab_data_saved(si)) {
					FREEBUF(page_buf);
					FREEBUF(start_address);
					return;
				}
			
				if (si->slab == slab_chains[s]) 
					continue;
	
				last = slab_chains[s];

				do {
					if (received_SIGINT()) {
						FREEBUF(page_buf);
						FREEBUF(start_address);
						restart(0);
					}

					if (!verify_slab_overload_page(si, last, s)) {
						list_borked = 1;
						continue;
					}
					last = si->slab;
		
					readmem(si->slab - si->list_offset, KVADDR, page_buf,
						SIZE(page), "page (slab) buffer", 
						FAULT_ON_ERROR);
		
					tmp = INT(page_buf + OFFSET(page_active));
					si->inuse += tmp;
	
					si->s_mem = ULONG(page_buf + 
						OFFSET(page_s_mem));
					gather_slab_cached_count(si);
	
					si->num_slabs++;
		
					si->slab = ULONG(page_buf + si->list_offset);

					/*
				 	 *  Check for slab transition. (Tony Dziedzic)
				 	*/
					for (i = 0; i < SLAB_CHAINS; i++) {
						if ((i != s) && 
						    (si->slab == slab_chains[i])) {
							error(NOTE, 
							    "%s: slab chain inconsistency: %s list\n",
								si->curname,
								slab_chain_name_v2[s]);
							list_borked = 1;
						}
					}
			
				} while (si->slab != slab_chains[s] && !list_borked);
			}
		}

		if (!list_borked)
			save_slab_data(si);
		break;

	case SLAB_WALKTHROUGH:
		if (si->flags & SLAB_OVERLOAD_PAGE_PTR) {
			specified_slab = si->spec_addr;
			si->slab = si->spec_addr + si->list_offset;
		} else { 
			specified_slab = si->slab;    
			if (si->slab)
				si->slab += si->list_offset;
		}
		si->flags |= (SLAB_WALKTHROUGH|SLAB_FIRST_NODE);
		si->flags &= ~SLAB_GET_COUNTS;
		page_buf = GETBUF(SIZE(page));
		for (index = 0; (index < vt->kmem_cache_len_nodes); index++)
		{ 
			if (vt->flags & NODES_ONLINE) {
				node = next_online_node(index);
				if (node < 0)
					break;
				if (node != index)
					continue;
			}
			if (start_address[index] == 0)
				continue;

			slab_chains[0] = start_address[index] + OFFSET(kmem_list3_slabs_partial);
			slab_chains[1] = start_address[index] + OFFSET(kmem_list3_slabs_full);
			slab_chains[2] = start_address[index] + OFFSET(kmem_list3_slabs_free);
	
			gather_cpudata_list_v2_nodes(si, index);
 
			si->flags &= ~SLAB_FIRST_NODE;

			if (CRASHDEBUG(1)) {
				fprintf(fp, "[ %s: %lx ", si->curname, si->cache);
				fprintf(fp, "partial: %lx full: %lx free: %lx ]\n",
					slab_chains[0], slab_chains[1], slab_chains[2]);
			}

			for (s = 0; s < SLAB_CHAINS; s++) {
				if (!slab_chains[s])
					continue;

				if (!specified_slab) {
					if (!readmem(slab_chains[s],
					    KVADDR, &si->slab, sizeof(ulong),
					    "slabs", QUIET|RETURN_ON_ERROR)) {
						error(INFO, "%s: %s list: "
						    "bad page/slab pointer: %lx\n",
							si->curname,
							slab_chain_name_v2[s],
							slab_chains[s]);
							list_borked = 1;
							continue;
					}
					last = slab_chains[s];
				} else
					last = 0;

				if (si->slab == slab_chains[s])
					continue;
				
				readmem(si->slab - si->list_offset, KVADDR, page_buf,
						SIZE(page), "page (slab) buffer", 
						FAULT_ON_ERROR);
		
				si->s_mem = ULONG(page_buf + 
						OFFSET(page_s_mem));

				if (CRASHDEBUG(1)) {
					fprintf(fp, "search cache: [%s] ", si->curname);
					if (si->flags & ADDRESS_SPECIFIED) 
						fprintf(fp, "for %llx", si->spec_addr);
					fprintf(fp, "\n");
				}
	
				do {
					if (received_SIGINT())
					{
						FREEBUF(start_address);
						FREEBUF(page_buf);
						restart(0);
					}
	
					if (!verify_slab_overload_page(si, last, s)) {
						list_borked = 1;
						continue;
					}
					last = si->slab;
	
					dump_slab_overload_page(si);
					
					if (si->found) {
						FREEBUF(start_address);
						FREEBUF(page_buf);
						return;
					}
		
					readmem(si->slab, KVADDR, &si->slab, 
						sizeof(ulong), "slab list", 
						FAULT_ON_ERROR);
			
				} while (si->slab != slab_chains[s] && !list_borked);
			}
		}

		break;
	}
	FREEBUF(page_buf);
	FREEBUF(start_address);
}


/*
 *  Try to preclude any attempt to translate a bogus slab structure.
 */
static int
verify_slab_v2(struct meminfo *si, ulong last, int s)
{
	char slab_buf[BUFSIZE];
	struct kernel_list_head *list_head;
	unsigned int inuse;
	ulong s_mem;
	char *list;
	int errcnt;

	list = slab_chain_name_v2[s];

	errcnt = 0;

        if (!readmem(si->slab, KVADDR, slab_buf,
            SIZE(slab), "slab buffer", QUIET|RETURN_ON_ERROR)) {
                error(INFO, "%s: %s list: bad slab pointer: %lx\n",
                        si->curname, list, si->slab);
		return FALSE;
        }                        

        list_head = (struct kernel_list_head *)(slab_buf + OFFSET(slab_list));
	if (!IS_KVADDR((ulong)list_head->next) || 
	    !accessible((ulong)list_head->next)) {
                error(INFO, "%s: %s list: slab: %lx  bad next pointer: %lx\n",
                        si->curname, list, si->slab,
			(ulong)list_head->next);
		errcnt++;
	}

	if (last && (last != (ulong)list_head->prev)) {
                error(INFO, "%s: %s list: slab: %lx  bad prev pointer: %lx\n",
                        si->curname, list, si->slab,
                        (ulong)list_head->prev);
		errcnt++;
	}

	inuse = UINT(slab_buf + OFFSET(slab_inuse));
	if (inuse > si->c_num) {
                error(INFO, "%s: %s list: slab: %lx  bad inuse counter: %ld\n",
                        si->curname, list, si->slab, inuse);
		errcnt++;
	}

	if (!last)
		goto no_inuse_check_v2;

	switch (s) 
	{
	case 0: /* partial */
                if ((inuse == 0) || (inuse == si->c_num)) {
                	error(INFO, 
		 	    "%s: %s list: slab: %lx  bad inuse counter: %ld\n",
                        	si->curname, list, si->slab, inuse);
			errcnt++;
		}
		break;

	case 1: /* full */
		if (inuse != si->c_num) {
                	error(INFO, 
		 	    "%s: %s list: slab: %lx  bad inuse counter: %ld\n",
                        	si->curname, list, si->slab, inuse);
			errcnt++;
		}
		break;

	case 2: /* free */
		if (inuse > 0) {
                	error(INFO, 
		 	    "%s: %s list: slab: %lx  bad inuse counter: %ld\n",
                        	si->curname, list, si->slab, inuse);
			errcnt++;
		}
		break;
	}

no_inuse_check_v2:
	s_mem = ULONG(slab_buf + OFFSET(slab_s_mem));
	if (!IS_KVADDR(s_mem) || !accessible(s_mem)) {
                error(INFO, "%s: %s list: slab: %lx  bad s_mem pointer: %lx\n",
                        si->curname, list, si->slab, s_mem);
		errcnt++;
	}

	si->errors += errcnt;

	return(errcnt ? FALSE : TRUE);
}


static int
verify_slab_overload_page(struct meminfo *si, ulong last, int s)
{
	char *page_buf;
	struct kernel_list_head *list_head;
	unsigned int active;
	ulong s_mem;
	char *list;
	int errcnt;

	list = slab_chain_name_v2[s];
	page_buf = GETBUF(SIZE(page));

	errcnt = 0;

        if (!readmem(si->slab - si->list_offset, KVADDR, page_buf,
            SIZE(page), "page (slab) buffer", QUIET|RETURN_ON_ERROR)) {
                error(INFO, "%s: %s list: bad slab pointer: %lx\n",
                        si->curname, list, si->slab);
		FREEBUF(page_buf);
		return FALSE;
        }                        

        list_head = (struct kernel_list_head *)(page_buf + si->list_offset);
	if (!IS_KVADDR((ulong)list_head->next) || 
	    !accessible((ulong)list_head->next)) {
                error(INFO, "%s: %s list: page/slab: %lx  bad next pointer: %lx\n",
                        si->curname, list, si->slab,
			(ulong)list_head->next);
		errcnt++;
	}

	if (last && (last != (ulong)list_head->prev)) {
                error(INFO, "%s: %s list: page/slab: %lx  bad prev pointer: %lx\n",
                        si->curname, list, si->slab,
                        (ulong)list_head->prev);
		errcnt++;
	}

	active = UINT(page_buf + OFFSET(page_active));
	if (active > si->c_num) {
                error(INFO, "%s: %s list: page/slab: %lx  bad active counter: %ld\n",
                        si->curname, list, si->slab, active);
		errcnt++;
	}

	if (!last)
		goto no_inuse_check_v2;

	switch (s) 
	{
	case 0: /* partial */
                if ((active == 0) || (active == si->c_num)) {
                	error(INFO, 
		 	    "%s: %s list: page/slab: %lx  bad active counter: %ld\n",
                        	si->curname, list, si->slab, active);
			errcnt++;
		}
		break;

	case 1: /* full */
		if (active != si->c_num) {
                	error(INFO, 
		 	    "%s: %s list: page/slab: %lx  bad active counter: %ld\n",
                        	si->curname, list, si->slab, active);
			errcnt++;
		}
		break;

	case 2: /* free */
		if (active > 0) {
                	error(INFO, 
		 	    "%s: %s list: page/slab: %lx  bad active counter: %ld\n",
                        	si->curname, list, si->slab, active);
			errcnt++;
		}
		break;
	}

no_inuse_check_v2:
	s_mem = ULONG(page_buf + OFFSET(page_s_mem));
	if (!IS_KVADDR(s_mem) || !accessible(s_mem)) {
                error(INFO, "%s: %s list: page/slab: %lx  bad s_mem pointer: %lx\n",
                        si->curname, list, si->slab, s_mem);
		errcnt++;
	}

	si->errors += errcnt;

	FREEBUF(page_buf);

	return(errcnt ? FALSE : TRUE);
}


/*
 *  If it's a dumpfile, save the essential slab data to avoid re-reading 
 *  the whole slab chain more than once.  This may seem like overkill, but
 *  if the problem is a memory leak, or just the over-use of the buffer_head
 *  cache, it's painful to wait each time subsequent kmem -s or -i commands
 *  simply need the basic slab counts.
 */
struct slab_data {
	ulong cache_addr;
	int num_slabs;
	int inuse;
	ulong cpucached_cache;
};

#define NO_SLAB_DATA ((void *)(-1))

static void 
save_slab_data(struct meminfo *si)
{
	int i;

	if (si->flags & SLAB_DATA_NOSAVE) {
		si->flags &= ~SLAB_DATA_NOSAVE;
		return;
	}

	if (ACTIVE())
		return;

	if (vt->slab_data == NO_SLAB_DATA)
		return;

	if (!vt->slab_data) {
        	if (!(vt->slab_data = (struct slab_data *)
            	    malloc(sizeof(struct slab_data) * vt->kmem_cache_count))) {
                	error(INFO, "cannot malloc slab_data table");
			vt->slab_data = NO_SLAB_DATA;
			return;
		}
		for (i = 0; i < vt->kmem_cache_count; i++) {
			vt->slab_data[i].cache_addr = (ulong)NO_SLAB_DATA;
			vt->slab_data[i].num_slabs = 0;
			vt->slab_data[i].inuse = 0;
			vt->slab_data[i].cpucached_cache = 0;
		}
	}

	for (i = 0; i < vt->kmem_cache_count; i++) {
		if (vt->slab_data[i].cache_addr == si->cache) 
			break;

		if (vt->slab_data[i].cache_addr == (ulong)NO_SLAB_DATA) {
			vt->slab_data[i].cache_addr = si->cache; 
			vt->slab_data[i].num_slabs = si->num_slabs; 
			vt->slab_data[i].inuse = si->inuse; 
			vt->slab_data[i].cpucached_cache = si->cpucached_cache;
			break;
		}
	}
}

static int 
slab_data_saved(struct meminfo *si)
{
	int i;

	if (ACTIVE() || !vt->slab_data || (vt->slab_data == NO_SLAB_DATA)) 
		return FALSE;

	for (i = 0; i < vt->kmem_cache_count; i++) {
		if (vt->slab_data[i].cache_addr == si->cache) {
			si->inuse = vt->slab_data[i].inuse;
			si->num_slabs = vt->slab_data[i].num_slabs;
			si->cpucached_cache = vt->slab_data[i].cpucached_cache;
			return TRUE;
		}
	}

	return FALSE;
}

static void
dump_saved_slab_data(void)
{
	int i;

	if (!vt->slab_data || (vt->slab_data == NO_SLAB_DATA))
		return;

	for (i = 0; i < vt->kmem_cache_count; i++) {
		if (vt->slab_data[i].cache_addr == (ulong)NO_SLAB_DATA)
			break;

		fprintf(fp, 
             "     cache: %lx inuse: %5d num_slabs: %3d cpucached_cache: %ld\n",
			vt->slab_data[i].cache_addr,
			vt->slab_data[i].inuse,
			vt->slab_data[i].num_slabs,
			vt->slab_data[i].cpucached_cache);
	}
}

/*
 *  Dump the contents of a kmem slab.
 */

static void
dump_slab(struct meminfo *si)
{
	si->s_mem = ULONG(si->slab_buf + OFFSET(kmem_slab_s_s_mem));
	si->s_mem = PTOB(BTOP(si->s_mem));

        if (si->flags & ADDRESS_SPECIFIED)  {
                if (INSLAB(si->slab, si) && (si->spec_addr >= si->slab) &&
                    (si->spec_addr < (si->slab+SIZE(kmem_slab_s)))) {
                	si->found = KMEM_SLAB_ADDR;
                        return;
                }
		if (INSLAB(si->spec_addr, si))
			si->found = KMEM_ON_SLAB;  /* But don't return yet... */
		else
			return;
        }

	si->s_freep = VOID_PTR(si->slab_buf + OFFSET(kmem_slab_s_s_freep));
	si->s_inuse = ULONG(si->slab_buf + OFFSET(kmem_slab_s_s_inuse));
	si->s_index = ULONG_PTR(si->slab_buf + OFFSET(kmem_slab_s_s_index));

	if (!(si->flags & ADDRESS_SPECIFIED)) {
		fprintf(fp, "%s", slab_hdr);
		DUMP_SLAB_INFO();
	}

	dump_slab_objects(si);
}

/*
 *  dump_slab() adapted for newer percpu slab format.
 */

static void
dump_slab_percpu_v1(struct meminfo *si)
{
	int tmp;

        readmem(si->slab+OFFSET(slab_s_s_mem),
                KVADDR, &si->s_mem, sizeof(ulong),
                "s_mem", FAULT_ON_ERROR);

	/*
	 * Include the array of kmem_bufctl_t's appended to slab.
	 */
	tmp = SIZE(slab_s) + (SIZE(kmem_bufctl_t) * si->c_num);

        if (si->flags & ADDRESS_SPECIFIED)  {
                if (INSLAB_PERCPU(si->slab, si) && 
		    (si->spec_addr >= si->slab) &&
                    (si->spec_addr < (si->slab+tmp))) {
			if (si->spec_addr >= (si->slab + SIZE(slab_s)))
				si->found = KMEM_BUFCTL_ADDR;
			else
                		si->found = KMEM_SLAB_ADDR;
                } else if (INSLAB_PERCPU(si->spec_addr, si))
			si->found = KMEM_ON_SLAB;  /* But don't return yet... */
		else
			return;
        }

        readmem(si->slab+OFFSET(slab_s_inuse),
                KVADDR, &tmp, sizeof(int),
                "inuse", FAULT_ON_ERROR);
	si->s_inuse = tmp;

        readmem(si->slab+OFFSET(slab_s_free),
                KVADDR, &si->free, SIZE(kmem_bufctl_t),
                "kmem_bufctl_t", FAULT_ON_ERROR);

	gather_slab_free_list_percpu(si);
	gather_slab_cached_count(si);

	if (!(si->flags & ADDRESS_SPECIFIED)) {
		fprintf(fp, "%s", slab_hdr);
		DUMP_SLAB_INFO();
	}

	dump_slab_objects_percpu(si);
}


/*
 *  Updated for 2.6 slab substructure.
 */
static void
dump_slab_percpu_v2(struct meminfo *si)
{
	int tmp;

        readmem(si->slab+OFFSET(slab_s_mem),
                KVADDR, &si->s_mem, sizeof(ulong),
                "s_mem", FAULT_ON_ERROR);

	/*
	 * Include the array of kmem_bufctl_t's appended to slab.
	 */
	tmp = SIZE(slab) + (SIZE(kmem_bufctl_t) * si->c_num);

        if (si->flags & ADDRESS_SPECIFIED)  {
                if (INSLAB_PERCPU(si->slab, si) && 
		    (si->spec_addr >= si->slab) &&
                    (si->spec_addr < (si->slab+tmp))) {
			if (si->spec_addr >= (si->slab + SIZE(slab)))
				si->found = KMEM_BUFCTL_ADDR;
			else
                		si->found = KMEM_SLAB_ADDR;
                } else if (INSLAB_PERCPU(si->spec_addr, si))
			si->found = KMEM_ON_SLAB;  /* But don't return yet... */
		else
			return;
        }

        readmem(si->slab+OFFSET(slab_inuse),
                KVADDR, &tmp, sizeof(int),
                "inuse", FAULT_ON_ERROR);
	si->s_inuse = tmp;

        readmem(si->slab+OFFSET(slab_free),
                KVADDR, &si->free, SIZE(kmem_bufctl_t),
                "kmem_bufctl_t", FAULT_ON_ERROR);

	gather_slab_free_list_percpu(si);
	gather_slab_cached_count(si);

	if (!(si->flags & ADDRESS_SPECIFIED)) {
		fprintf(fp, "%s", slab_hdr);
		DUMP_SLAB_INFO();
	}

	dump_slab_objects_percpu(si);
}


static void
dump_slab_overload_page(struct meminfo *si)
{
	int tmp;
	ulong slab_overload_page, freelist;

	slab_overload_page = si->slab - si->list_offset;

        readmem(slab_overload_page + OFFSET(page_s_mem),
                KVADDR, &si->s_mem, sizeof(ulong),
                "page.s_mem", FAULT_ON_ERROR);

        readmem(slab_overload_page + OFFSET(page_freelist),
                KVADDR, &freelist, sizeof(ulong),
                "page.freelist", FAULT_ON_ERROR);

        if (si->flags & ADDRESS_SPECIFIED)  {
                if ((si->spec_addr >= slab_overload_page) &&
                    (si->spec_addr < (slab_overload_page+SIZE(page)))) {
			si->found = KMEM_SLAB_OVERLOAD_PAGE;
                } else if (INSLAB_PERCPU(si->spec_addr, si))
			si->found = KMEM_ON_SLAB;  /* But don't return yet... */
		else
			return;
        }

        readmem(slab_overload_page + OFFSET(page_active),
                KVADDR, &tmp, sizeof(int),
                "active", FAULT_ON_ERROR);
	si->s_inuse = tmp;

	gather_slab_free_list_slab_overload_page(si);
	gather_slab_cached_count(si);

	if (!(si->flags & ADDRESS_SPECIFIED)) {
		fprintf(fp, "%s", slab_hdr);
		DUMP_SLAB_INFO();
	}

	dump_slab_objects_percpu(si);
}


/*
 *  Gather the free objects in a slab into the si->addrlist, checking for
 *  specified addresses that are in-slab kmem_bufctls, and making error checks 
 *  along the way.  Object address checks are deferred to dump_slab_objects().
 */

#define INOBJECT(addr, obj) ((addr >= obj) && (addr < (obj+si->size)))

static void
gather_slab_free_list(struct meminfo *si)
{
	ulong *next, obj;
	ulong expected, cnt;

	BNEG(si->addrlist, sizeof(ulong) * (si->c_num+1));

	if (!si->s_freep)
		return;

	cnt = 0;
	expected = si->c_num - si->s_inuse;

	next = si->s_freep; 
	do {

		if (cnt == si->c_num) {
			error(INFO, 
		     "\"%s\" cache: too many objects found in slab free list\n",
				si->curname);
			si->errors++;
			return;
		}

		/*
                 *  Off-slab kmem_bufctls are contained in arrays of object 
		 *  pointers that point to:
	         *    1. next kmem_bufctl (or NULL) if the object is free.
	         *    2. to the object if it the object is in use.
                 *
	 	 *  On-slab kmem_bufctls resides just after the object itself,
	         *  and point to:
	         *    1. next kmem_bufctl (or NULL) if object is free.
	         *    2. the containing slab if the object is in use.
		 */

	        if (si->c_flags & SLAB_CFLGS_BUFCTL) 
                	obj = si->s_mem + ((next - si->s_index) * si->c_offset);
		else 
			obj = (ulong)next - si->c_offset;

		si->addrlist[cnt] = obj; 

		if (si->flags & ADDRESS_SPECIFIED) {
			if (INSLAB(next, si) && 
		            (si->spec_addr >= (ulong)next) &&
			    (si->spec_addr < (ulong)(next + 1))) {
				si->found = KMEM_BUFCTL_ADDR;
				return;
			}
		}

		cnt++;

		if (!INSLAB(obj, si)) {
			error(INFO, 
		       "\"%s\" cache: address not contained within slab: %lx\n",
				si->curname, obj);
			si->errors++;
		}

        	readmem((ulong)next, KVADDR, &next, sizeof(void *),
                	"s_freep chain entry", FAULT_ON_ERROR);
	} while (next); 

	if (cnt != expected) {
		error(INFO, 
	       "\"%s\" cache: free object mismatch: expected: %ld found: %ld\n",
			si->curname, expected, cnt); 
		si->errors++;
	}
}


/*
 *  gather_slab_free_list() adapted for newer percpu slab format.
 */

#define BUFCTL_END 0xffffFFFF

static void
gather_slab_free_list_percpu(struct meminfo *si)
{
	int i;
	ulong obj;
	ulong expected, cnt;
	int free_index;
	ulong kmembp;
	short *kbp;

	BNEG(si->addrlist, sizeof(ulong) * (si->c_num+1));

	if (CRASHDEBUG(1)) 
		fprintf(fp, "slab: %lx si->s_inuse: %ld si->c_num: %ld\n", 
			si->slab, si->s_inuse, si->c_num);

	if (si->s_inuse == si->c_num )
		return;

	kmembp = si->slab + SIZE_OPTION(slab_s, slab);
        readmem((ulong)kmembp, KVADDR, si->kmem_bufctl, 
		SIZE(kmem_bufctl_t) * si->c_num,
                "kmem_bufctl array", FAULT_ON_ERROR);

	if (CRASHDEBUG(1)) {
		for (i = 0; (SIZE(kmem_bufctl_t) == sizeof(int)) && 
		     (i < si->c_num); i++) 
			fprintf(fp, "%d ", si->kmem_bufctl[i]);

		for (kbp = (short *)&si->kmem_bufctl[0], i = 0; 
		     (SIZE(kmem_bufctl_t) == sizeof(short)) && (i < si->c_num);
		     i++) 
			fprintf(fp, "%d ", *(kbp + i));

		fprintf(fp, "\n");
	}

	cnt = 0;
	expected = si->c_num - si->s_inuse;

	if (SIZE(kmem_bufctl_t) == sizeof(int)) {
		for (free_index = si->free; free_index != BUFCTL_END;
		     free_index = si->kmem_bufctl[free_index]) {
	
	                if (cnt == si->c_num) {
	                        error(INFO,
                     "\"%s\" cache: too many objects found in slab free list\n",
	                                si->curname);
	                        si->errors++;
	                        return;
	                }
	
			obj = si->s_mem + (free_index*si->size);
			si->addrlist[cnt] = obj; 
			cnt++;
		}
	} else if (SIZE(kmem_bufctl_t) == sizeof(short)) {
		kbp = (short *)&si->kmem_bufctl[0];

                for (free_index = si->free; free_index != BUFCTL_END;
                     free_index = (int)*(kbp + free_index)) {

                        if (cnt == si->c_num) {
                                error(INFO,
                     "\"%s\" cache: too many objects found in slab free list\n",
                                        si->curname);
                                si->errors++;
                                return;
                        }

                        obj = si->s_mem + (free_index*si->size);
                        si->addrlist[cnt] = obj;
                        cnt++;
                }
	} else 
		error(FATAL, 
                "size of kmem_bufctl_t (%d) not sizeof(int) or sizeof(short)\n",
			SIZE(kmem_bufctl_t));

	if (cnt != expected) {
		error(INFO, 
	       "\"%s\" cache: free object mismatch: expected: %ld found: %ld\n",
			si->curname, expected, cnt); 
		si->errors++;
	}
}


static void
gather_slab_free_list_slab_overload_page(struct meminfo *si)
{
	int i, active, start_offset;
	ulong obj, objnr, cnt, freelist;
	unsigned char *ucharptr;
	unsigned short *ushortptr;
	unsigned int *uintptr;
	unsigned int cache_flags, overload_active;
	ulong slab_overload_page;

	if (CRASHDEBUG(1))
		fprintf(fp, "slab page: %lx active: %ld si->c_num: %ld\n", 
			si->slab - si->list_offset, si->s_inuse, si->c_num);

	if (si->s_inuse == si->c_num )
		return;

	slab_overload_page = si->slab - si->list_offset;
	readmem(slab_overload_page + OFFSET(page_freelist),
		KVADDR, &freelist, sizeof(void *), "page freelist",
		FAULT_ON_ERROR);
        readmem(freelist, KVADDR, si->freelist, 
		si->freelist_index_size * si->c_num,
                "freelist array", FAULT_ON_ERROR);
	readmem(si->cache+OFFSET(kmem_cache_s_flags),
		KVADDR, &cache_flags, sizeof(uint),
		"kmem_cache_s flags", FAULT_ON_ERROR);
        readmem(slab_overload_page + OFFSET(page_active),
                KVADDR, &overload_active, sizeof(uint),
                "active", FAULT_ON_ERROR);

	BNEG(si->addrlist, sizeof(ulong) * (si->c_num+1));
	cnt = objnr = 0;
	ucharptr = NULL;
	ushortptr = NULL;
	uintptr = NULL;
	active = si->s_inuse;

	/*
	 * On an OBJFREELIST slab, the object might have been recycled
	 * and everything before the active count can be random data.
	 */
	start_offset = 0;
	if (cache_flags & SLAB_CFLGS_OBJFREELIST)
		start_offset = overload_active;

	switch (si->freelist_index_size)
	{
	case 1: ucharptr = (unsigned char *)si->freelist + start_offset; break;
	case 2: ushortptr = (unsigned short *)si->freelist + start_offset; break;
	case 4: uintptr = (unsigned int *)si->freelist + start_offset; break;
	}

	for (i = start_offset; i < si->c_num; i++) {
		switch (si->freelist_index_size)
		{
		case 1: objnr = (ulong)*ucharptr++; break;
		case 2: objnr = (ulong)*ushortptr++; break;
		case 4: objnr = (ulong)*uintptr++; break;
		}
		if (objnr >= si->c_num) {
			error(INFO, 
			    "\"%s\" cache: invalid/corrupt freelist entry: %ld\n", 
				si->curname, objnr);
			si->errors++;
		}
		if (i >= active) {
			obj = si->s_mem + (objnr * si->size);
			si->addrlist[cnt++] = obj; 
			if (CRASHDEBUG(1))
				fprintf(fp, "%ld ", objnr);
		} else if (CRASHDEBUG(1))
			fprintf(fp, "[%ld] ", objnr);
	}

	if (CRASHDEBUG(1))
		fprintf(fp, "\n");
}


/*
 *  Dump the FREE, [ALLOCATED] and <CACHED> objects of a slab.
 */  

#define DUMP_SLAB_OBJECT() \
        for (j = on_free_list = 0; j < si->c_num; j++) {	\
                if (obj == si->addrlist[j]) {			\
                        on_free_list = TRUE;			\
                        break;					\
                }						\
        }							\
								\
        if (on_free_list) {					\
                if (!(si->flags & ADDRESS_SPECIFIED))		\
                        fprintf(fp, "   %lx\n", obj);		\
                if (si->flags & ADDRESS_SPECIFIED) {		\
                        if (INOBJECT(si->spec_addr, obj)) {	\
                                si->found =			\
                                    KMEM_OBJECT_ADDR_FREE;	\
				si->container = obj;		\
                                return;				\
                        }					\
                }						\
        } else {						\
                if (!(si->flags & ADDRESS_SPECIFIED))		\
                        fprintf(fp, "  [%lx]\n", obj);		\
                cnt++;						\
                if (si->flags & ADDRESS_SPECIFIED) {		\
                        if (INOBJECT(si->spec_addr, obj)) {	\
                                si->found =			\
                                    KMEM_OBJECT_ADDR_INUSE;	\
				si->container = obj;		\
                                return;				\
                        }					\
                }						\
        }

static void
dump_slab_objects(struct meminfo *si)
{
	int i, j;
	ulong *next;
	int on_free_list; 
	ulong cnt, expected;
	ulong bufctl, obj;

	gather_slab_free_list(si);

	if ((si->flags & ADDRESS_SPECIFIED) && (si->found & ~KMEM_ON_SLAB))
		return;

        cnt = 0;
        expected = si->s_inuse;
	si->container = 0;

        if (CRASHDEBUG(1))
                for (i = 0; i < si->c_num; i++) {
                        fprintf(fp, "si->addrlist[%d]: %lx\n", 
				i, si->addrlist[i]);
                }

        if (!(si->flags & ADDRESS_SPECIFIED)) 
		fprintf(fp, "%s", free_inuse_hdr);

        /* For on-slab bufctls, c_offset is the distance between the start of
         * an obj and its related bufctl.  For off-slab bufctls, c_offset is
         * the distance between objs in the slab.
         */

        if (si->c_flags & SLAB_CFLGS_BUFCTL) {
		for (i = 0, next = si->s_index; i < si->c_num; i++, next++) {
                	obj = si->s_mem + 
				((next - si->s_index) * si->c_offset);
			DUMP_SLAB_OBJECT();
		}
	} else {
		/*
		 *  Get the "real" s_mem, i.e., without the offset stripped off.
		 *  It contains the address of the first object.
		 */
        	readmem(si->slab+OFFSET(kmem_slab_s_s_mem),
                	KVADDR, &obj, sizeof(ulong),
                	"s_mem", FAULT_ON_ERROR);

		for (i = 0; i < si->c_num; i++) {
			DUMP_SLAB_OBJECT();

                	if (si->flags & ADDRESS_SPECIFIED) {
				bufctl = obj + si->c_offset;

                        	if ((si->spec_addr >= bufctl) &&
                                    (si->spec_addr < 
				    (bufctl + SIZE(kmem_bufctl_t)))) {
                                	si->found = KMEM_BUFCTL_ADDR;
                                	return;
                        	}
                	}

			obj += (si->c_offset + SIZE(kmem_bufctl_t));
		}
	}

        if (cnt != expected) {
                error(INFO,
              "\"%s\" cache: inuse object mismatch: expected: %ld found: %ld\n",
                        si->curname, expected, cnt);
                si->errors++;
        }

}


/*
 *  dump_slab_objects() adapted for newer percpu slab format.
 */

static void
dump_slab_objects_percpu(struct meminfo *si)
{
	int i, j;
	int on_free_list, on_cpudata_list, on_shared_list; 
	ulong cnt, expected;
	ulong obj, freelist;

	if ((si->flags & ADDRESS_SPECIFIED) && (si->found & ~KMEM_ON_SLAB))
		if (!(si->found & KMEM_SLAB_OVERLOAD_PAGE))
			return;

        cnt = 0;
        expected = si->s_inuse;
	si->container = 0;

        if (CRASHDEBUG(1))
                for (i = 0; i < si->c_num; i++) {
                        fprintf(fp, "si->addrlist[%d]: %lx\n", 
				i, si->addrlist[i]);
                }

        if (!(si->flags & ADDRESS_SPECIFIED)) 
		fprintf(fp, "%s", free_inuse_hdr);

	for (i = 0, obj = si->s_mem; i < si->c_num; i++, obj += si->size) {
		on_free_list = FALSE;
		on_cpudata_list = FALSE;
		on_shared_list = FALSE;

	        for (j = 0; j < si->c_num; j++) {        
	                if (obj == si->addrlist[j]) {                   
	                        on_free_list = TRUE;                    
	                        break;                                  
	                }                                               
	        }                                                       

		on_cpudata_list = check_cpudata_list(si, obj);
		on_shared_list = check_shared_list(si, obj);

		if (on_free_list && on_cpudata_list) {
			error(INFO, 
		    "\"%s\" cache: object %lx on both free and cpu %d lists\n",
				si->curname, obj, si->cpu);
			si->errors++;
		}
		if (on_free_list && on_shared_list) {
			error(INFO, 
		    "\"%s\" cache: object %lx on both free and shared lists\n",
				si->curname, obj);
			si->errors++;
		}
		if (on_cpudata_list && on_shared_list) {
			error(INFO, 
		    "\"%s\" cache: object %lx on both cpu %d and shared lists\n",
				si->curname, obj, si->cpu);
			si->errors++;
		}
	                                                               
	        if (on_free_list) {                                     
	                if (!(si->flags & ADDRESS_SPECIFIED))           
	                        fprintf(fp, "   %lx\n", obj);           
	                if (si->flags & ADDRESS_SPECIFIED) {            
	                        if (INOBJECT(si->spec_addr, obj)) {     
	                                si->found =                     
	                                    KMEM_OBJECT_ADDR_FREE;      
					si->container = obj;
	                                return;                         
	                        }                                       
	                }                                               
		} else if (on_cpudata_list) {
                        if (!(si->flags & ADDRESS_SPECIFIED))
                                fprintf(fp, "   %lx  (cpu %d cache)\n", obj,
					si->cpu);
                        cnt++;    
                        if (si->flags & ADDRESS_SPECIFIED) {
                                if (INOBJECT(si->spec_addr, obj)) {
                                        si->found =
                                            KMEM_OBJECT_ADDR_CACHED;
					si->container = obj;
                                        return;
                                } 
                        }
		} else if (on_shared_list) {
                        if (!(si->flags & ADDRESS_SPECIFIED))
                                fprintf(fp, "   %lx  (shared cache)\n", obj);
			cnt++;
                        if (si->flags & ADDRESS_SPECIFIED) {
                                if (INOBJECT(si->spec_addr, obj)) {
                                        si->found =
                                            KMEM_OBJECT_ADDR_SHARED;
					si->container = obj;
                                        return;
                                } 
			}
	        } else {                                                
	                if (!(si->flags & ADDRESS_SPECIFIED))           
	                        fprintf(fp, "  [%lx]\n", obj);          
	                cnt++;                                          
	                if (si->flags & ADDRESS_SPECIFIED) {            
	                        if (INOBJECT(si->spec_addr, obj)) {     
	                                si->found =                     
	                                    KMEM_OBJECT_ADDR_INUSE;     
					si->container = obj;
	                                return;                         
	                        }                                       
	                }                                               
	        }
	}

        if (cnt != expected) {
                error(INFO,
              "\"%s\" cache: inuse object mismatch: expected: %ld found: %ld\n",
                        si->curname, expected, cnt);
                si->errors++;
        }

	if ((si->flags & ADDRESS_SPECIFIED) && 
	    (vt->flags & SLAB_OVERLOAD_PAGE)) {
		readmem(si->slab - si->list_offset + OFFSET(page_freelist),
			KVADDR, &freelist, sizeof(ulong), "page.freelist", 
			FAULT_ON_ERROR);

		if ((si->spec_addr >= freelist) && (si->spec_addr < si->s_mem)) 
			si->found = KMEM_SLAB_FREELIST;
	}
}

/*
 *  Determine how many of the "inuse" slab objects are actually cached
 *  in the kmem_cache_s header.  Set the per-slab count and update the 
 *  cumulative per-cache count.  With the addition of the shared list
 *  check, the terms "cpucached_cache" and "cpucached_slab" are somewhat
 *  misleading.  But they both are types of objects that are cached
 *  in the kmem_cache_s header, just not necessarily per-cpu.
 */

static void
gather_slab_cached_count(struct meminfo *si)
{
	int i;
	ulong obj;
	int in_cpudata, in_shared;

	si->cpucached_slab = 0;

        for (i = 0, obj = si->s_mem; i < si->c_num; i++, obj += si->size) {
		in_cpudata = in_shared = 0;
		if (check_cpudata_list(si, obj)) {
			in_cpudata = TRUE;
			si->cpucached_slab++;
			if (si->flags & SLAB_GET_COUNTS) {
				si->cpucached_cache++;
			}
		}
                if (check_shared_list(si, obj)) {
			in_shared = TRUE;
			if (!in_cpudata) {
                        	si->cpucached_slab++;
                        	if (si->flags & SLAB_GET_COUNTS) {
                                	si->cpucached_cache++;
                        	}
			}
                }
		if (in_cpudata && in_shared) {
			si->flags |= SLAB_DATA_NOSAVE;
			if (!(si->flags & VERBOSE))
				error(INFO, 
		    "\"%s\" cache: object %lx on both cpu %d and shared lists\n",
				si->curname, obj, si->cpu);
		}
	}
}

/*
 *  Populate the percpu object list for a given slab.
 */

static void
gather_cpudata_list_v1(struct meminfo *si)
{
        int i, j;
	int avail;
        ulong cpudata[NR_CPUS];

        if (INVALID_MEMBER(kmem_cache_s_cpudata))
                return;

        readmem(si->cache+OFFSET(kmem_cache_s_cpudata),
                KVADDR, &cpudata[0], 
		sizeof(ulong) * ARRAY_LENGTH(kmem_cache_s_cpudata),
                "cpudata array", FAULT_ON_ERROR);

        for (i = 0; (i < ARRAY_LENGTH(kmem_cache_s_cpudata)) && 
	     cpudata[i]; i++) {
		BZERO(si->cpudata[i], sizeof(ulong) * vt->kmem_max_limit);

                readmem(cpudata[i]+OFFSET(cpucache_s_avail),
                        KVADDR, &avail, sizeof(int),
                        "cpucache avail", FAULT_ON_ERROR);

		if (!avail) 
			continue;

		if (avail > vt->kmem_max_limit) {
			error(INFO, 
	  	  "\"%s\" cache: cpucache_s.avail %d greater than limit %ld\n",
				si->curname, avail, vt->kmem_max_limit);
			si->errors++;
		}

		if (CRASHDEBUG(2))
			fprintf(fp, "%s: cpu[%d] avail: %d\n", 
				si->curname, i, avail);

                readmem(cpudata[i]+SIZE(cpucache_s),
                        KVADDR, si->cpudata[i],
			sizeof(void *) * avail,
                        "cpucache avail", FAULT_ON_ERROR);

		if (CRASHDEBUG(2))
			for (j = 0; j < avail; j++)
				fprintf(fp, "  %lx\n", si->cpudata[i][j]);
        }
}

/*
 *  Updated for 2.6 slab percpu data structure, this also gathers
 *  the shared array_cache list as well.
 */
static void
gather_cpudata_list_v2(struct meminfo *si)
{
        int i, j;
	int avail;
        ulong cpudata[NR_CPUS];
	ulong shared;

        readmem(si->cache+OFFSET(kmem_cache_s_array),
                KVADDR, &cpudata[0], 
		sizeof(ulong) * ARRAY_LENGTH(kmem_cache_s_array),
                "array_cache array", FAULT_ON_ERROR);

        for (i = 0; (i < ARRAY_LENGTH(kmem_cache_s_array)) && 
	     cpudata[i]; i++) {
		BZERO(si->cpudata[i], sizeof(ulong) * vt->kmem_max_limit);

                readmem(cpudata[i]+OFFSET(array_cache_avail),
                        KVADDR, &avail, sizeof(int),
                        "array cache avail", FAULT_ON_ERROR);

		if (!avail) 
			continue;

		if (avail > vt->kmem_max_limit) {
			error(INFO, 
	  	  "\"%s\" cache: array_cache.avail %d greater than limit %ld\n",
				si->curname, avail, vt->kmem_max_limit);
			si->errors++;
		}

		if (CRASHDEBUG(2))
			fprintf(fp, "%s: cpu[%d] avail: %d\n", 
				si->curname, i, avail);

                readmem(cpudata[i]+SIZE(array_cache),
                        KVADDR, si->cpudata[i],
			sizeof(void *) * avail,
                        "array_cache avail", FAULT_ON_ERROR);

		if (CRASHDEBUG(2))
			for (j = 0; j < avail; j++)
				fprintf(fp, "  %lx (cpu %d)\n", si->cpudata[i][j], i);
        }

        /*
         *  If the shared list contains anything, gather them as well.
         */
	BZERO(si->shared_array_cache, sizeof(ulong) * vt->kmem_max_limit);

        if (!VALID_MEMBER(kmem_list3_shared) ||
            !VALID_MEMBER(kmem_cache_s_lists) ||
            !readmem(si->cache+OFFSET(kmem_cache_s_lists)+
       	    OFFSET(kmem_list3_shared), KVADDR, &shared, sizeof(void *),
	    "kmem_list3 shared", RETURN_ON_ERROR|QUIET) ||
	    !readmem(shared+OFFSET(array_cache_avail),
            KVADDR, &avail, sizeof(int), "shared array_cache avail",
            RETURN_ON_ERROR|QUIET) || !avail)
		return;

	if (avail > vt->kmem_max_limit) {
		error(INFO, 
  	  "\"%s\" cache: shared array_cache.avail %d greater than limit %ld\n",
			si->curname, avail, vt->kmem_max_limit);
		si->errors++;
		return;
	}

	if (CRASHDEBUG(2))
		fprintf(fp, "%s: shared avail: %d\n", 
			si->curname, avail);

        readmem(shared+SIZE(array_cache), KVADDR, si->shared_array_cache,
        	sizeof(void *) * avail, "shared array_cache avail", 
		FAULT_ON_ERROR);

        if (CRASHDEBUG(2))
        	for (j = 0; j < avail; j++)
                	fprintf(fp, "  %lx (shared list)\n", si->shared_array_cache[j]);
}



/*
 *  Updated gather_cpudata_list_v2 for per-node kmem_list3's in kmem_cache 
 */
static void
gather_cpudata_list_v2_nodes(struct meminfo *si, int index)
{
        int i, j;
	int avail;
        ulong cpudata[NR_CPUS];
	ulong shared, percpu_ptr;
	ulong *start_address;

	start_address = (ulong *) GETBUF(sizeof(ulong) * vt->kmem_cache_len_nodes);

	if (vt->flags & SLAB_CPU_CACHE) {
		readmem(si->cache+OFFSET(kmem_cache_cpu_cache), KVADDR, 
			&percpu_ptr, sizeof(void *), "kmem_cache.cpu_cache", 
		    	FAULT_ON_ERROR);

		for (i = 0; i < vt->kmem_max_cpus; i++)
			cpudata[i] = percpu_ptr + kt->__per_cpu_offset[i];
	} else {
		readmem(si->cache+OFFSET(kmem_cache_s_array),
			KVADDR, &cpudata[0], 
			sizeof(ulong) * vt->kmem_max_cpus,
			"array_cache array", FAULT_ON_ERROR);
	}

        for (i = 0; (i < vt->kmem_max_cpus) && cpudata[i] && !(index); i++) {
		if (si->cpudata[i])
			BZERO(si->cpudata[i], sizeof(ulong) * vt->kmem_max_limit);
		else
			continue;

                readmem(cpudata[i]+OFFSET(array_cache_avail),
                        KVADDR, &avail, sizeof(int),
                        "array cache avail", FAULT_ON_ERROR);

		if (!avail) 
			continue;

		if (avail > vt->kmem_max_limit) {
			error(INFO, 
	  	  "\"%s\" cache: array_cache.avail %d greater than limit %ld\n",
				si->curname, avail, vt->kmem_max_limit);
			si->errors++;
			continue;
		}

		if (CRASHDEBUG(2))
			fprintf(fp, "%s: cpu[%d] avail: %d\n", 
				si->curname, i, avail);
		
                readmem(cpudata[i]+SIZE(array_cache),
                        KVADDR, si->cpudata[i],
			sizeof(void *) * avail,
                        "array_cache avail", FAULT_ON_ERROR);

		if (CRASHDEBUG(2))
			for (j = 0; j < avail; j++)
				fprintf(fp, "  %lx (cpu %d)\n", si->cpudata[i][j], i);
        }

        /*
         *  If the shared list contains anything, gather them as well.
         */
	if (si->flags & SLAB_FIRST_NODE) {
		BZERO(si->shared_array_cache, sizeof(ulong) * 
			vt->kmem_max_limit * vt->kmem_cache_len_nodes);
		si->current_cache_index = 0;
	}

	if (!readmem(kmem_cache_nodelists(si->cache), KVADDR, &start_address[0], 
	    sizeof(ulong) * vt->kmem_cache_len_nodes , "array nodelist array", 
	    RETURN_ON_ERROR) ||  
	    !readmem(start_address[index] + OFFSET(kmem_list3_shared), KVADDR, &shared,
	     sizeof(void *), "kmem_list3 shared", RETURN_ON_ERROR|QUIET) || !shared ||
	    !readmem(shared + OFFSET(array_cache_avail), KVADDR, &avail, sizeof(int), 
	    "shared array_cache avail", RETURN_ON_ERROR|QUIET) || !avail) {
		FREEBUF(start_address);
		return;
	}

	if (avail > vt->kmem_max_limit) {
		error(INFO, 
  	  "\"%s\" cache: shared array_cache.avail %d greater than limit %ld\n",
			si->curname, avail, vt->kmem_max_limit);
		si->errors++;
		FREEBUF(start_address);
		return;
	}

	if (CRASHDEBUG(2))
		fprintf(fp, "%s: shared avail: %d\n", 
			si->curname, avail);

        readmem(shared+SIZE(array_cache), KVADDR, si->shared_array_cache + si->current_cache_index,
        	sizeof(void *) * avail, "shared array_cache avail", 
		FAULT_ON_ERROR);

	if ((si->current_cache_index + avail) > 
	    (vt->kmem_max_limit * vt->kmem_cache_len_nodes)) {
		error(INFO, 
  	  "\"%s\" cache: total shared array_cache.avail %d greater than total limit %ld\n",
			si->curname, 
			si->current_cache_index + avail, 
			vt->kmem_max_limit * vt->kmem_cache_len_nodes);
		si->errors++;
		FREEBUF(start_address);
		return;
	}

        if (CRASHDEBUG(2))
        	for (j = si->current_cache_index; j < (si->current_cache_index + avail); j++)
                	fprintf(fp, "  %lx (shared list)\n", si->shared_array_cache[j]);
	
	si->current_cache_index += avail;
	FREEBUF(start_address);
}

/*
 *  Check whether a given address is contained in the previously-gathered
 *  percpu object cache.
 */

static int
check_cpudata_list(struct meminfo *si, ulong obj)
{
        int i, j;

        for (i = 0; i < vt->kmem_max_cpus; i++) {
                for (j = 0; si->cpudata[i][j]; j++)
			if (si->cpudata[i][j] == obj) {
				si->cpu = i;
				return TRUE;
			}
	}

	return FALSE;
}

/*
 *  Check whether a given address is contained in the previously-gathered
 *  shared object cache.
 */

static int
check_shared_list(struct meminfo *si, ulong obj)
{
	int i;

	if (INVALID_MEMBER(kmem_list3_shared) ||
	    !si->shared_array_cache)
		return FALSE;

        for (i = 0; si->shared_array_cache[i]; i++) {
		if (si->shared_array_cache[i] == obj)
			return TRUE;
	}

        return FALSE;
}

/*
 *  Search the various memory subsystems for instances of this address.
 *  Start with the most specific areas, ending up with at least the 
 *  mem_map page data.
 */
static void
kmem_search(struct meminfo *mi)
{
	struct syment *sp;
	struct meminfo tmp_meminfo;
	char buf[BUFSIZE];
	ulong vaddr, orig_flags;
	physaddr_t paddr;
	ulong offset;
	ulong task;
	ulong show_flags;
	struct task_context *tc;

	vaddr = 0;
	pc->curcmd_flags &= ~HEADER_PRINTED;
	pc->curcmd_flags |= IGNORE_ERRORS;

	switch (mi->memtype)
	{
	case KVADDR:
		vaddr = mi->spec_addr;
		break;

	case PHYSADDR:
		vaddr = mi->spec_addr < VTOP(vt->high_memory) ?
			PTOV(mi->spec_addr) : BADADDR;
		break;
	}

	orig_flags = mi->flags;
	mi->retval = 0;

	/*
	 *  Check first for a possible symbolic display of the virtual
	 *  address associated with mi->spec_addr or PTOV(mi->spec_addr).
	 */
	if (((vaddr >= kt->stext) && (vaddr <= kt->end)) ||
	    IS_MODULE_VADDR(mi->spec_addr)) {
		if ((sp = value_search(vaddr, &offset))) {
			show_flags = SHOW_LINENUM | SHOW_RADIX();
			if (module_symbol(sp->value, NULL, NULL, NULL, 0))
				show_flags |= SHOW_MODULE;
			show_symbol(sp, offset, show_flags);
			fprintf(fp, "\n");
		}
	}

	/*
	 *  Check for a valid mapped address.
	 */
	if ((mi->memtype == KVADDR) && IS_VMALLOC_ADDR(mi->spec_addr)) {
		if ((task = stkptr_to_task(vaddr)) && (tc = task_to_context(task))) {
			show_context(tc);
			fprintf(fp, "\n");
		}
		if (kvtop(NULL, mi->spec_addr, &paddr, 0)) {
			mi->flags = orig_flags | VMLIST_VERIFY;
			dump_vmlist(mi);
			if (mi->retval) {
				mi->flags = orig_flags;
				dump_vmlist(mi);
				fprintf(fp, "\n");
				mi->spec_addr = paddr;
				mi->memtype = PHYSADDR;
				goto mem_map;
			}
		}
	}

	/*
	 *  If the address is physical, check whether it's in vmalloc space.
	 */
	if (mi->memtype == PHYSADDR) {
		mi->flags = orig_flags;
		mi->flags |= GET_PHYS_TO_VMALLOC;
		mi->retval = 0;
        	dump_vmlist(mi);
		mi->flags &= ~GET_PHYS_TO_VMALLOC;

		if (mi->retval) {
			if ((task = stkptr_to_task(mi->retval)) && (tc = task_to_context(task))) {
				show_context(tc);
				fprintf(fp, "\n");
			}
			if ((sp = value_search(mi->retval, &offset))) {
                        	show_symbol(sp, offset, 
					SHOW_LINENUM | SHOW_RADIX());
                        	fprintf(fp, "\n");
                	}
        		dump_vmlist(mi);
			fprintf(fp, "\n");
			goto mem_map;
		}
	}

	/*
         *  Check whether the containing page belongs to the slab subsystem.
	 */
	mi->flags = orig_flags;
	mi->retval = 0;
	if ((vaddr != BADADDR) && vaddr_to_kmem_cache(vaddr, buf, VERBOSE)) {
		BZERO(&tmp_meminfo, sizeof(struct meminfo));
		tmp_meminfo.spec_addr = vaddr;
		tmp_meminfo.memtype = KVADDR;
		tmp_meminfo.flags = mi->flags;
		vt->dump_kmem_cache(&tmp_meminfo);
		fprintf(fp, "\n");
	}
	if ((vaddr != BADADDR) && is_slab_page(mi, buf)) {
		BZERO(&tmp_meminfo, sizeof(struct meminfo));
		tmp_meminfo.spec_addr = vaddr;
		tmp_meminfo.memtype = KVADDR;
		tmp_meminfo.flags = mi->flags;
		vt->dump_kmem_cache(&tmp_meminfo);
		fprintf(fp, "\n");
	}

	/*
	 *  Check free list.
	 */
	mi->flags = orig_flags;
	mi->retval = 0;
	vt->dump_free_pages(mi);
	if (mi->retval)
		fprintf(fp, "\n");

	if (vt->page_hash_table) {
		/*
		 *  Check the page cache.
		 */
		mi->flags = orig_flags;
		mi->retval = 0;
		dump_page_hash_table(mi);
		if (mi->retval)
			fprintf(fp, "\n");
	}

	/*
	 *  Check whether it's a current task or stack address.
	 */
	if ((mi->memtype & (KVADDR|PHYSADDR)) && (task = vaddr_in_task_struct(vaddr)) &&
	    (tc = task_to_context(task))) {
		show_context(tc);
		fprintf(fp, "\n");
	} else if ((mi->memtype & (KVADDR|PHYSADDR)) && (task = stkptr_to_task(vaddr)) &&
	    (tc = task_to_context(task))) {
		show_context(tc);
		fprintf(fp, "\n");
	}

mem_map:
	mi->flags = orig_flags;
	pc->curcmd_flags &= ~HEADER_PRINTED;
	if (vaddr != BADADDR)
		dump_mem_map(mi);
	else
		mi->retval = FALSE;

	if (!mi->retval)
		fprintf(fp, "%llx: %s address not found in mem map\n", 
			mi->spec_addr, memtype_string(mi->memtype, 0));
}

int
generic_is_page_ptr(ulong addr, physaddr_t *phys)
{
	return FALSE;
}

/*
 *  Determine whether an address is a page pointer from the mem_map[] array.
 *  If the caller requests it, return the associated physical address.
 */
int
is_page_ptr(ulong addr, physaddr_t *phys)
{
	int n;
        ulong ppstart, ppend;
	struct node_table *nt;
	ulong pgnum, node_size;
	ulong nr, sec_addr;
	ulong nr_mem_sections;
	ulong coded_mem_map, mem_map, end_mem_map;
	physaddr_t section_paddr;

	if (machdep->is_page_ptr(addr, phys))
		return TRUE;

	if (IS_SPARSEMEM()) {
		nr_mem_sections = vt->max_mem_section_nr+1;
	        for (nr = 0; nr < nr_mem_sections ; nr++) {
	                if ((sec_addr = valid_section_nr(nr))) {
	                        coded_mem_map = section_mem_map_addr(sec_addr, 0);
	                        mem_map = sparse_decode_mem_map(coded_mem_map, nr);
				end_mem_map = mem_map + (PAGES_PER_SECTION() * SIZE(page));

				if ((addr >= mem_map) && (addr < end_mem_map)) { 
	        			if ((addr - mem_map) % SIZE(page))
						return FALSE;
					if (phys) {
						section_paddr = PTOB(section_nr_to_pfn(nr));
						pgnum = (addr - mem_map) / SIZE(page);
						*phys = section_paddr + ((physaddr_t)pgnum * PAGESIZE());
					} 
					return TRUE;
				}
	                }
	        }
		return FALSE;
	}

	for (n = 0; n < vt->numnodes; n++) {
		nt = &vt->node_table[n];
                if ((vt->flags & V_MEM_MAP) && (vt->numnodes == 1))
	        	node_size = vt->max_mapnr;
		else
	        	node_size = nt->size;

        	ppstart = nt->mem_map;
		ppend = ppstart + (node_size * SIZE(page));

		if ((addr < ppstart) || (addr >= ppend))
                	continue;

		/*
		 *  We're in the mem_map range -- but it is a page pointer?
		 */
	        if ((addr - ppstart) % SIZE(page))
			return FALSE;

		if (phys) {
			pgnum = (addr - nt->mem_map) / SIZE(page);
			*phys = ((physaddr_t)pgnum * PAGESIZE()) + nt->start_paddr;
		}

		return TRUE;
	}

	return FALSE;

#ifdef PRE_NODES
        ppstart = vt->mem_map;
	ppend = ppstart + (vt->total_pages * vt->page_struct_len);

	if ((addr < ppstart) || (addr >= ppend)) 
		return FALSE;

	if ((addr - ppstart) % vt->page_struct_len)
		return FALSE;

	return TRUE;
#endif
}

/*
 *  Return the physical address associated with this page pointer.
 */
static int 
page_to_phys(ulong pp, physaddr_t *phys)
{
	return(is_page_ptr(pp, phys));
}


/*
 *  Return the page pointer associated with this physical address.
 */
int 
phys_to_page(physaddr_t phys, ulong *pp)
{
	int n;
        ulong pgnum;
        struct node_table *nt;
	physaddr_t pstart, pend;
	ulong node_size;

	if (IS_SPARSEMEM()) {
		ulong map;
		map = pfn_to_map(phys >> PAGESHIFT());
		if (map) {
			*pp = map;
			return TRUE;
		}
		return FALSE;
	}

        for (n = 0; n < vt->numnodes; n++) {
                nt = &vt->node_table[n];
                if ((vt->flags & V_MEM_MAP) && (vt->numnodes == 1))
                        node_size = vt->max_mapnr;
                else
                        node_size = nt->size;

                pstart = nt->start_paddr;
                pend = pstart + ((ulonglong)node_size * PAGESIZE());

                if ((phys < pstart) || (phys >= pend))
                        continue;
                /*
                 *  We're in the physical range -- calculate the page.
                 */
		pgnum = BTOP(phys - pstart);
		*pp = nt->mem_map + (pgnum * SIZE(page));

                return TRUE;
        }

	return FALSE;

#ifdef PRE_NODES
	if (phys >= (vt->total_pages * PAGESIZE()))
		return FALSE;

	pgnum = PTOB(BTOP(phys)) / PAGESIZE();
	*pp = vt->mem_map + (pgnum * vt->page_struct_len);
	
	return TRUE;
#endif
}


/*
 *  Fill the caller's buffer with up to maxlen non-NULL bytes 
 *  starting from kvaddr, returning the number of consecutive 
 *  non-NULL bytes found.  If the buffer gets filled with
 *  maxlen bytes without a NULL, then the caller is reponsible 
 *  for handling it. 
 */
int
read_string(ulong kvaddr, char *buf, int maxlen)
{
	int i;

        BZERO(buf, maxlen);

	readmem(kvaddr, KVADDR, buf, maxlen,
	    "read_string characters", QUIET|RETURN_ON_ERROR);

	for (i = 0; i < maxlen; i++) {
		if (buf[i] == NULLCHAR) {
			BZERO(&buf[i], maxlen-i);
			break;
		}
	}

	return i;
}

/*
 *  "help -v" output
 */
void
dump_vm_table(int verbose)
{
	int i;
	struct node_table *nt;
	int others;
	ulong *up;

	others = 0;
	fprintf(fp, "              flags: %lx  %s(", 
		vt->flags, count_bits_long(vt->flags) > 4 ? "\n " : "");
	if (vt->flags & NODES)
		fprintf(fp, "%sNODES", others++ ? "|" : "");
	if (vt->flags & NODES_ONLINE)
		fprintf(fp, "%sNODES_ONLINE", others++ ? "|" : "");
	if (vt->flags & ZONES)
		fprintf(fp, "%sZONES", others++ ? "|" : "");
	if (vt->flags & PERCPU_KMALLOC_V1)
		fprintf(fp, "%sPERCPU_KMALLOC_V1", others++ ? "|" : "");
	if (vt->flags & PERCPU_KMALLOC_V2)
		fprintf(fp, "%sPERCPU_KMALLOC_V2", others++ ? "|" : "");
	if (vt->flags & COMMON_VADDR)
		fprintf(fp, "%sCOMMON_VADDR", others++ ? "|" : "");
	if (vt->flags & KMEM_CACHE_INIT)
		fprintf(fp, "%sKMEM_CACHE_INIT", others++ ? "|" : "");
	if (vt->flags & V_MEM_MAP)
		fprintf(fp, "%sV_MEM_MAP", others++ ? "|" : "");
	if (vt->flags & KMEM_CACHE_UNAVAIL)
		fprintf(fp, "%sKMEM_CACHE_UNAVAIL", others++ ? "|" : "");
	if (vt->flags & DISCONTIGMEM)
		fprintf(fp, "%sDISCONTIGMEM", others++ ? "|" : "");
	if (vt->flags & FLATMEM)
		fprintf(fp, "%sFLATMEM", others++ ? "|" : "");
	if (vt->flags & SPARSEMEM)
		fprintf(fp, "%sSPARSEMEM", others++ ? "|" : "");\
	if (vt->flags & SPARSEMEM_EX)
		fprintf(fp, "%sSPARSEMEM_EX", others++ ? "|" : "");\
	if (vt->flags & KMEM_CACHE_DELAY)
		fprintf(fp, "%sKMEM_CACHE_DELAY", others++ ? "|" : "");\
	if (vt->flags & PERCPU_KMALLOC_V2_NODES)
		fprintf(fp, "%sPERCPU_KMALLOC_V2_NODES", others++ ? "|" : "");\
	if (vt->flags & VM_STAT)
		fprintf(fp, "%sVM_STAT", others++ ? "|" : "");\
	if (vt->flags & KMALLOC_SLUB)
		fprintf(fp, "%sKMALLOC_SLUB", others++ ? "|" : "");\
	if (vt->flags & KMALLOC_COMMON)
		fprintf(fp, "%sKMALLOC_COMMON", others++ ? "|" : "");\
	if (vt->flags & SLAB_OVERLOAD_PAGE)
		fprintf(fp, "%sSLAB_OVERLOAD_PAGE", others++ ? "|" : "");\
	if (vt->flags & SLAB_CPU_CACHE)
		fprintf(fp, "%sSLAB_CPU_CACHE", others++ ? "|" : "");\
	if (vt->flags & SLAB_ROOT_CACHES)
		fprintf(fp, "%sSLAB_ROOT_CACHES", others++ ? "|" : "");\
	if (vt->flags & FREELIST_PTR_BSWAP)
		fprintf(fp, "%sFREELIST_PTR_BSWAP", others++ ? "|" : "");\
	if (vt->flags & USE_VMAP_AREA)
		fprintf(fp, "%sUSE_VMAP_AREA", others++ ? "|" : "");\
	if (vt->flags & CONFIG_NUMA)
		fprintf(fp, "%sCONFIG_NUMA", others++ ? "|" : "");\
	if (vt->flags & VM_EVENT)
		fprintf(fp, "%sVM_EVENT", others++ ? "|" : "");\
	if (vt->flags & PGCNT_ADJ)
		fprintf(fp, "%sPGCNT_ADJ", others++ ? "|" : "");\
	if (vt->flags & PAGEFLAGS)
		fprintf(fp, "%sPAGEFLAGS", others++ ? "|" : "");\
	if (vt->flags & SWAPINFO_V1)
		fprintf(fp, "%sSWAPINFO_V1", others++ ? "|" : "");\
	if (vt->flags & SWAPINFO_V2)
		fprintf(fp, "%sSWAPINFO_V2", others++ ? "|" : "");\
	if (vt->flags & NODELISTS_IS_PTR)
		fprintf(fp, "%sNODELISTS_IS_PTR", others++ ? "|" : "");\
	if (vt->flags & VM_INIT)
		fprintf(fp, "%sVM_INIT", others++ ? "|" : "");\

	fprintf(fp, ")\n");
	if (vt->kernel_pgd[0] == vt->kernel_pgd[1])
       		fprintf(fp, "     kernel_pgd[NR_CPUS]: %lx ...\n", 
			vt->kernel_pgd[0]);
	else {
       		fprintf(fp, "     kernel_pgd[NR_CPUS]: ");
		for (i = 0; i < NR_CPUS; i++) {
			if ((i % 4) == 0)
				fprintf(fp, "\n     ");
			fprintf(fp, "%lx ", vt->kernel_pgd[i]);
		}
		fprintf(fp, "\n");
	}
        fprintf(fp, "        high_memory: %lx\n", vt->high_memory);
        fprintf(fp, "      vmalloc_start: %lx\n", vt->vmalloc_start);
        fprintf(fp, "            mem_map: %lx\n", vt->mem_map);
        fprintf(fp, "        total_pages: %ld\n", vt->total_pages);
        fprintf(fp, "          max_mapnr: %ld\n", vt->max_mapnr);
        fprintf(fp, "     totalram_pages: %ld\n", vt->totalram_pages);
        fprintf(fp, "    totalhigh_pages: %ld\n", vt->totalhigh_pages);
        fprintf(fp, "      num_physpages: %ld\n", vt->num_physpages);
	fprintf(fp, "    page_hash_table: %lx\n", vt->page_hash_table);
	fprintf(fp, "page_hash_table_len: %d\n", vt->page_hash_table_len);
	fprintf(fp, "     kmem_max_c_num: %ld\n", vt->kmem_max_c_num);
	fprintf(fp, "     kmem_max_limit: %ld\n", vt->kmem_max_limit);
	fprintf(fp, "      kmem_max_cpus: %ld\n", vt->kmem_max_cpus);
	fprintf(fp, "   kmem_cache_count: %ld\n", vt->kmem_cache_count);
	fprintf(fp, " kmem_cache_namelen: %d\n", vt->kmem_cache_namelen);
	fprintf(fp, "kmem_cache_len_nodes: %ld\n", vt->kmem_cache_len_nodes);
	fprintf(fp, " nr_bad_slab_caches: %d\n", vt->nr_bad_slab_caches);
	if (!vt->nr_bad_slab_caches)
		fprintf(fp, "    bad_slab_caches: (unused)\n");
	else {
		for (i = 0; i < vt->nr_bad_slab_caches; i++) {
			fprintf(fp, " bad_slab_caches[%d]: %lx\n", 
				i, vt->bad_slab_caches[i]);
		}
	}
	fprintf(fp, "        paddr_prlen: %d\n", vt->paddr_prlen);
	fprintf(fp, "           numnodes: %d\n", vt->numnodes);
	fprintf(fp, "           nr_zones: %d\n", vt->nr_zones);
	fprintf(fp, "      nr_free_areas: %d\n", vt->nr_free_areas);
	for (i = 0; i < vt->numnodes; i++) {
		nt = &vt->node_table[i];
		fprintf(fp, "      node_table[%d]: \n", i);
		fprintf(fp, "                   id: %d\n", nt->node_id);
		fprintf(fp, "                pgdat: %lx\n", nt->pgdat);
		fprintf(fp, "                 size: %ld\n", nt->size);
		fprintf(fp, "              present: %ld\n", nt->present);
		fprintf(fp, "              mem_map: %lx\n", nt->mem_map);
		fprintf(fp, "          start_paddr: %llx\n", nt->start_paddr);
		fprintf(fp, "          start_mapnr: %ld\n", nt->start_mapnr);
	}

	fprintf(fp, "    dump_free_pages: ");
	if (vt->dump_free_pages == dump_free_pages)
		fprintf(fp, "dump_free_pages()\n");
	else if (vt->dump_free_pages == dump_free_pages_zones_v1)
		fprintf(fp, "dump_free_pages_zones_v1()\n");
	else if (vt->dump_free_pages == dump_free_pages_zones_v2)
		fprintf(fp, "dump_free_pages_zones_v2()\n");
	else if (vt->dump_free_pages == dump_multidimensional_free_pages)
		fprintf(fp, "dump_multidimensional_free_pages()\n");
	else
		fprintf(fp, "%lx (unknown)\n", (ulong)vt->dump_free_pages);

	fprintf(fp, "    dump_kmem_cache: ");
	if (vt->dump_kmem_cache == dump_kmem_cache)
		fprintf(fp, "dump_kmem_cache()\n");
	else if (vt->dump_kmem_cache == dump_kmem_cache_percpu_v1)
		fprintf(fp, "dump_kmem_cache_percpu_v1()\n");
	else if (vt->dump_kmem_cache == dump_kmem_cache_percpu_v2)
		fprintf(fp, "dump_kmem_cache_percpu_v2()\n");
	else if (vt->dump_kmem_cache == dump_kmem_cache_slub)
		fprintf(fp, "dump_kmem_cache_slub()\n");
	else
		fprintf(fp, "%lx (unknown)\n", (ulong)vt->dump_kmem_cache);
	fprintf(fp, "          slab_data: %lx\n", (ulong)vt->slab_data);
	if (verbose) 
		dump_saved_slab_data();
	fprintf(fp, "      cpu_slab_type: %d\n", vt->cpu_slab_type);
	fprintf(fp, "       nr_swapfiles: %d\n", vt->nr_swapfiles);
	fprintf(fp, "     last_swap_read: %lx\n", vt->last_swap_read);
	fprintf(fp, "   swap_info_struct: %lx\n", (ulong)vt->swap_info_struct);
	fprintf(fp, "            mem_sec: %lx\n", (ulong)vt->mem_sec);
	fprintf(fp, "        mem_section: %lx\n", (ulong)vt->mem_section);
	fprintf(fp, " max_mem_section_nr: %ld\n", (ulong)vt->max_mem_section_nr);
	fprintf(fp, "       ZONE_HIGHMEM: %d\n", vt->ZONE_HIGHMEM);
	fprintf(fp, "node_online_map_len: %d\n", vt->node_online_map_len);
	if (vt->node_online_map_len) {
		fprintf(fp, "    node_online_map: ");
		up = (ulong *)vt->node_online_map;
		for (i = 0; i < vt->node_online_map_len; i++) {
			fprintf(fp, "%s%lx", i ? ", " : "[", *up);
			up++;
		}
		fprintf(fp, "]\n");
	} else {
		fprintf(fp, "    node_online_map: (unused)\n");
	}
	fprintf(fp, "   nr_vm_stat_items: %d\n", vt->nr_vm_stat_items);
	fprintf(fp, "      vm_stat_items: %s", (vt->flags & VM_STAT) ?
		"\n" : "(not used)\n");
	for (i = 0; i < vt->nr_vm_stat_items; i++)
		fprintf(fp, "        [%d] %s\n", i, vt->vm_stat_items[i]);

	fprintf(fp, "  nr_vm_event_items: %d\n", vt->nr_vm_event_items);
	fprintf(fp, "     vm_event_items: %s", (vt->flags & VM_EVENT) ?
		"\n" : "(not used)\n");
	for (i = 0; i < vt->nr_vm_event_items; i++)
		fprintf(fp, "        [%d] %s\n", i, vt->vm_event_items[i]);

        fprintf(fp, "        PG_reserved: %lx\n", vt->PG_reserved);
        fprintf(fp, "            PG_slab: %ld (%lx)\n", vt->PG_slab,
                (ulong)1 << vt->PG_slab);
        fprintf(fp, "  PG_head_tail_mask: %lx\n", vt->PG_head_tail_mask);

	fprintf(fp, "       nr_pageflags: %d\n", vt->nr_pageflags);
	fprintf(fp, "     pageflags_data: %s\n",
		vt->nr_pageflags ? "" : "(not used)");
	for (i = 0; i < vt->nr_pageflags; i++) {
		fprintf(fp, "        %s[%d] %08lx: %s\n", 
			i < 10 ? " " : "", i, 
			vt->pageflags_data[i].mask,
			vt->pageflags_data[i].name);
	}

	dump_vma_cache(VERBOSE);
}

/*
 *  Calculate the amount of memory referenced in the kernel-specific "nodes".
 */
uint64_t
total_node_memory()
{
	int i;
	struct node_table *nt;
	uint64_t total;

        for (i = total = 0; i < vt->numnodes; i++) {
                nt = &vt->node_table[i];

		if (CRASHDEBUG(1)) {
                	console("node_table[%d]: \n", i);
                	console("           id: %d\n", nt->node_id);
                	console("        pgdat: %lx\n", nt->pgdat);
                	console("         size: %ld\n", nt->size);
                	console("      present: %ld\n", nt->present);
                	console("      mem_map: %lx\n", nt->mem_map);
                	console("  start_paddr: %lx\n", nt->start_paddr);
                	console("  start_mapnr: %ld\n", nt->start_mapnr);
		}

		if (nt->present)
			total += (uint64_t)((uint64_t)nt->present * (uint64_t)PAGESIZE());
		else
			total += (uint64_t)((uint64_t)nt->size * (uint64_t)PAGESIZE());
        }

	return total;
}

/*
 *  Dump just the vm_area_struct cache table data so that it can be
 *  called from above or for debug purposes.
 */
void
dump_vma_cache(ulong verbose)
{
	int i;
        ulong vhits;

	if (!verbose)
		goto show_hits;

        for (i = 0; i < VMA_CACHE; i++)
                fprintf(fp, "     cached_vma[%2d]: %lx (%ld)\n",
                        i, vt->cached_vma[i],
                        vt->cached_vma_hits[i]);
        fprintf(fp, "          vma_cache: %lx\n", (ulong)vt->vma_cache);
        fprintf(fp, "    vma_cache_index: %d\n", vt->vma_cache_index);
        fprintf(fp, "    vma_cache_fills: %ld\n", vt->vma_cache_fills);
	fflush(fp);

show_hits:
        if (vt->vma_cache_fills) {
                for (i = vhits = 0; i < VMA_CACHE; i++)
                        vhits += vt->cached_vma_hits[i];

                fprintf(fp, "%s       vma hit rate: %2ld%% (%ld of %ld)\n",
			verbose ? "" : "  ",
                        (vhits * 100)/vt->vma_cache_fills,
                        vhits, vt->vma_cache_fills);
        }
}

/*
 *  Guess at the "real" amount of physical memory installed, formatting
 *  it in a MB or GB based string.
 */
char *
get_memory_size(char *buf)
{
	uint64_t total;
	ulong next_gig;
#ifdef OLDWAY
	ulong mbs, gbs;
#endif

	total = machdep->memory_size();

	if ((next_gig = roundup(total, GIGABYTES(1)))) {
		if ((next_gig - total) <= MEGABYTES(64))
			total = next_gig;
	}

	return (pages_to_size((ulong)(total/PAGESIZE()), buf));

#ifdef OLDWAY
	gbs = (ulong)(total/GIGABYTES(1));
	mbs = (ulong)(total/MEGABYTES(1));
	if (gbs) 
		mbs = (total % GIGABYTES(1))/MEGABYTES(1);

        if (total%MEGABYTES(1))
                mbs++;

	if (gbs) 
		sprintf(buf, mbs ? "%ld GB %ld MB" : "%ld GB", gbs, mbs);
	else 
		sprintf(buf, "%ld MB", mbs);

	return buf;
#endif
}

/*
 *  For use by architectures not having machine-specific manners for
 *  best determining physical memory size.
 */ 
uint64_t
generic_memory_size(void)
{
	if (machdep->memsize)
		return machdep->memsize;

        return (machdep->memsize = total_node_memory());
}

/*
 *  Determine whether a virtual address is user or kernel or ambiguous.
 */ 
int
vaddr_type(ulong vaddr, struct task_context *tc)
{
	int memtype, found;

	if (!tc)
		tc = CURRENT_CONTEXT();
	memtype = found = 0;

	if (machdep->is_uvaddr(vaddr, tc)) {
		memtype |= UVADDR;
		found++;
	}

	if (machdep->is_kvaddr(vaddr)) {
		memtype |= KVADDR;
		found++;
	}

	if (found == 1)
		return memtype;
	else
		return AMBIGUOUS;
}

/*
 * Determine the first valid user space address
 */
static int
address_space_start(struct task_context *tc, ulong *addr)
{
	ulong mm_mt, entry_num, i, vma = 0;
        char *vma_buf;
	struct list_pair *entry_list;

        if (!tc->mm_struct)
                return FALSE;

	if (INVALID_MEMBER(mm_struct_mmap) && VALID_MEMBER(mm_struct_mm_mt)) {
		mm_mt = tc->mm_struct + OFFSET(mm_struct_mm_mt);
		entry_num = do_maple_tree(mm_mt, MAPLE_TREE_COUNT, NULL);
		entry_list = (struct list_pair *)GETBUF(entry_num * sizeof(struct list_pair));
		do_maple_tree(mm_mt, MAPLE_TREE_GATHER, entry_list);
		for (i = 0; i < entry_num; i++) {
			if (!!(vma = (ulong)entry_list[i].value))
				break;
		}
		FREEBUF(entry_list);
	} else {
		fill_mm_struct(tc->mm_struct);
		vma = ULONG(tt->mm_struct + OFFSET(mm_struct_mmap));
	}

        if (!vma)
                return FALSE;
	vma_buf = fill_vma_cache(vma);
        *addr = ULONG(vma_buf + OFFSET(vm_area_struct_vm_start));
	
	return TRUE;
}


int
generic_get_kvaddr_ranges(struct vaddr_range *rp)
{
	int cnt;

	if (XEN_HYPER_MODE())
		return 0;

	cnt = 0;

	rp[cnt].type = KVADDR_UNITY_MAP;
	rp[cnt].start = machdep->kvbase;
	rp[cnt++].end = vt->vmalloc_start;

	rp[cnt].type = KVADDR_VMALLOC;
	rp[cnt].start = vt->vmalloc_start;
	rp[cnt++].end = (ulong)(-1);

	return cnt;
}


/*
 *  Search for a given value between a starting and ending address range,
 *  applying an optional mask for "don't care" bits.  As an alternative
 *  to entering the starting address value, -k means "start of kernel address
 *  space".  For processors with ambiguous user/kernel address spaces,
 *  -u or -k must be used (with or without -s) as a differentiator.
 */


void
cmd_search(void)
{
        int i, c, memtype, ranges, context, max;
	ulonglong start, end;
	ulong value, mask, len;
	ulong uvaddr_start, uvaddr_end;
	ulong kvaddr_start, kvaddr_end, range_end;
	int sflag, Kflag, Vflag, pflag, Tflag, tflag;
	struct searchinfo searchinfo;
	struct syment *sp;
	struct node_table *nt;
	struct vaddr_range vaddr_ranges[MAX_KVADDR_RANGES];
	struct vaddr_range *vrp;
	struct task_context *tc;

#define vaddr_overflow(ADDR)   (BITS32() && ((ADDR) > 0xffffffffULL))
#define uint_overflow(VALUE)   ((VALUE) > 0xffffffffUL) 
#define ushort_overflow(VALUE) ((VALUE) > 0xffffUL) 

	context = max = 0;
	start = end = 0;
	value = mask = sflag = pflag = Kflag = Vflag = memtype = len = Tflag = tflag = 0;
	kvaddr_start = kvaddr_end = 0;
	uvaddr_start = UNINITIALIZED;
	uvaddr_end = COMMON_VADDR_SPACE() ? (ulong)(-1) : machdep->kvbase;
	BZERO(&searchinfo, sizeof(struct searchinfo));

	vrp = &vaddr_ranges[0];
	ranges = machdep->get_kvaddr_ranges(vrp);

	if (CRASHDEBUG(1)) {
		fprintf(fp, "kvaddr ranges:\n");
		for (i = 0; i < ranges; i++) {
			fprintf(fp, "  [%d] %lx %lx ", i,
				vrp[i].start, vrp[i].end);
			switch (vrp[i].type)
			{
			case KVADDR_UNITY_MAP:
				fprintf(fp, "KVADDR_UNITY_MAP\n");
				break;
			case KVADDR_START_MAP:
				fprintf(fp, "KVADDR_START_MAP\n");
				break;
			case KVADDR_VMALLOC:
				fprintf(fp, "KVADDR_VMALLOC\n");
				break;
			case KVADDR_MODULES:
				fprintf(fp, "KVADDR_MODULES\n");
				break;
			case KVADDR_VMEMMAP:
				fprintf(fp, "KVADDR_VMEMMAP\n");
				break;
			}
		}
	}

	searchinfo.mode = SEARCH_ULONG;	/* default search */

        while ((c = getopt(argcnt, args, "Ttl:ukKVps:e:v:m:hwcx:")) != EOF) {
                switch(c)
                {
		case 'u':
			if (XEN_HYPER_MODE())
				error(FATAL, 
 			 	    "-u option is not applicable to the "
				    "Xen hypervisor\n");

			if (is_kernel_thread(CURRENT_TASK()) || 
			    !task_mm(CURRENT_TASK(), TRUE))
				error(FATAL, 
				    "current context has no user address space\n");

			if (!sflag) {
				address_space_start(CURRENT_CONTEXT(),
					&uvaddr_start);
				start = (ulonglong)uvaddr_start;
			}
			memtype = UVADDR;
			sflag++;
			break;

		case 'p':
			if (XEN_HYPER_MODE())
				error(FATAL, 
 			 	    "-p option is not applicable to the "
				    "Xen hypervisor\n");

			memtype = PHYSADDR;
			if (!sflag) {
				nt = &vt->node_table[0];
				start = nt->start_paddr;
			}
			sflag++;
			break;

		case 'V':
		case 'K':
		case 'k':
			if (XEN_HYPER_MODE())
				error(FATAL, 
 			 	    "-%c option is not applicable to the "
				    "Xen hypervisor\n", c);

			if (!sflag)
				start = vrp[0].start;	
			memtype = KVADDR;
			sflag++;
			if (c == 'K')
				Kflag++;
			else if (c == 'V')
				Vflag++;
			break;

		case 's':
			if ((sp = symbol_search(optarg)))
				start = (ulonglong)sp->value;
			else
				start = htoll(optarg, FAULT_ON_ERROR, NULL);
			sflag++;
			break;

		case 'e':
                        if ((sp = symbol_search(optarg)))
                                end = (ulonglong)sp->value;
                        else
				end = htoll(optarg, FAULT_ON_ERROR, NULL);
			if (!end)
				error(FATAL, "invalid ending address: 0\n");
                        break;

		case 'l':
			len = stol(optarg, FAULT_ON_ERROR, NULL);
			break;

		case 'm':
                        mask = htol(optarg, FAULT_ON_ERROR, NULL);
                        break;

		case 'h':
			if (searchinfo.mode != SEARCH_DEFAULT)
				error(INFO, "WARNING: overriding previously"
					" set search mode with \"h\"\n");
			searchinfo.mode = SEARCH_USHORT;
			break;

		case 'w':
			if (searchinfo.mode != SEARCH_DEFAULT)
				error(INFO, "WARNING: overriding previously"
					" set search mode with \"w\"\n");
			searchinfo.mode = SEARCH_UINT;
			break;

		case 'c':
			if (searchinfo.mode != SEARCH_DEFAULT)
				error(INFO, "WARNING: overriding previously"
					" set search type with \"c\"\n");
			searchinfo.mode = SEARCH_CHARS;
			break;

		case 'x':
			context = dtoi(optarg, FAULT_ON_ERROR, NULL);
			break;

		case 'T':
		case 't':
			if (XEN_HYPER_MODE())
				error(FATAL, 
 			 	    "-%c option is not applicable to the "
				    "Xen hypervisor\n", c);
			if (c == 'T')
				Tflag++;
			else if (c == 't')
				tflag++;
			if (tflag && Tflag)
				error(FATAL, 
				    "-t and -T options are mutually exclusive\n");
			break;

                default:
                        argerrs++;
                        break;
                }
        }

	if ((tflag || Tflag) && (memtype || start || end || len)) 
		error(FATAL, 
		    "-%c option cannot be used with other "
		    "memory-selection options\n",
		    tflag ? 't' : 'T');

	if (XEN_HYPER_MODE()) {
		memtype = KVADDR;
		if (!sflag)
			error(FATAL, 
				"the \"-s start\" option is required for"
				" the Xen hypervisor\n");
	} else if (!memtype) {
		memtype = KVADDR;
		if (!tflag && !sflag++)
			start = vrp[0].start;	
	}

        if (argerrs || (!sflag && !tflag) || !args[optind] || 
	    (len && end) || !memtype)
                cmd_usage(pc->curcmd, SYNOPSIS);

	searchinfo.memtype = memtype;

	/*
	 *  Verify starting address.
	 */
	switch (memtype)
	{
	case UVADDR:
		if (vaddr_overflow(start) ||
		    !IS_UVADDR((ulong)start, CURRENT_CONTEXT())) {
			error(INFO, "invalid user virtual address: %llx\n", 
				start);
                	cmd_usage(pc->curcmd, SYNOPSIS);
		}
		break;

	case KVADDR:
		if (tflag)
			break;
		if (vaddr_overflow(start) ||
		    !IS_KVADDR((ulong)start)) {
			error(INFO, "invalid kernel virtual address: %llx\n",
				(ulonglong)start);
               		cmd_usage(pc->curcmd, SYNOPSIS);
		}
		break;

	case AMBIGUOUS:	
		error(INFO, 
		    "ambiguous virtual address: %llx  (requires -u or -k)\n",
			(ulonglong)start);
               	cmd_usage(pc->curcmd, SYNOPSIS);
	}

	/*
	 *  Set up ending address if necessary.
	 */
	if (!end && !len && !tflag) {
		switch (memtype)
		{
		case UVADDR:
			end = (ulonglong)uvaddr_end;
			break;

		case KVADDR:
			if (XEN_HYPER_MODE())
				end = (ulong)(-1);
			else {
				range_end = 0;
				for (i = 0; i < ranges; i++) {
					if (vrp[i].end > range_end)
						range_end = vrp[i].end;	
				}
				end = (ulonglong)range_end;
			}
			break;

		case PHYSADDR:
			nt = &vt->node_table[vt->numnodes-1];
			end = nt->start_paddr + (nt->size * PAGESIZE());
			break;
		}
	} else if (len) 
		end = start + len;

	/*
	 *  Final verification and per-type start/end variable setting.
	 */
	switch (memtype)
	{
	case UVADDR:
		uvaddr_start = (ulong)start;

		if (end > (ulonglong)uvaddr_end) {
			error(INFO, 
				"ending address %lx is in kernel space: %llx\n", end);
			cmd_usage(pc->curcmd, SYNOPSIS);
		}

		if (end < (ulonglong)uvaddr_end)
			uvaddr_end = (ulong)end;

		if (uvaddr_end < uvaddr_start) {
			error(INFO, 
			   "ending address %lx is below starting address %lx\n",
				uvaddr_end, uvaddr_start);
               		cmd_usage(pc->curcmd, SYNOPSIS);
		}
		break;

	case KVADDR:
		if (tflag)
			break;
		kvaddr_start = (ulong)start;
		kvaddr_end = (ulong)end;

		if (kvaddr_end < kvaddr_start) {
			error(INFO, 
			   "ending address %lx is below starting address %lx\n",
				kvaddr_end, kvaddr_start);
               		cmd_usage(pc->curcmd, SYNOPSIS);
		}
		break;

	case PHYSADDR:
		if (end < start) {
			error(INFO, 
			   "ending address %llx is below starting address %llx\n",
				(ulonglong)end, (ulonglong)start);
               		cmd_usage(pc->curcmd, SYNOPSIS);
		}
		break;
	}

	if (mask) {
		switch (searchinfo.mode) 
		{
		case SEARCH_ULONG:
			searchinfo.s_parms.s_ulong.mask = mask;
			break;
		case SEARCH_UINT:
			searchinfo.s_parms.s_uint.mask = mask;
			break;
		case SEARCH_USHORT:
			searchinfo.s_parms.s_ushort.mask = mask;
			break;
		case SEARCH_CHARS:
			error(INFO, "mask ignored on string search\n");
			break;
		}
	}
			
	if (context) {
		switch (searchinfo.mode)
		{
		case SEARCH_ULONG:
			max = PAGESIZE()/sizeof(long);
			break;
		case SEARCH_UINT:
			max = PAGESIZE()/sizeof(int);
			break;
		case SEARCH_USHORT:
			max = PAGESIZE()/sizeof(short);
			break;
		case SEARCH_CHARS:
			error(FATAL, "-x option is not allowed with -c\n");
			break;
		}

		if (context > max)
			error(FATAL, 
			    "context value %d is too large: maximum is %d\n",
				context, max);

		searchinfo.context = context;
	}
		
	searchinfo.vcnt = 0; 
	searchinfo.val = UNUSED;

	while (args[optind]) {
		switch (searchinfo.mode) 
		{
		case SEARCH_ULONG:
			if (can_eval(args[optind])) {
				value = eval(args[optind], FAULT_ON_ERROR, NULL);
				searchinfo.s_parms.s_ulong.opt_string[searchinfo.vcnt] =
					mask ? NULL : args[optind];
			} else if (symbol_exists(args[optind])) {
				value = symbol_value(args[optind]);
				searchinfo.s_parms.s_ulong.opt_string[searchinfo.vcnt] =
					mask ? NULL : args[optind];
			} else
				value = htol(args[optind], FAULT_ON_ERROR, NULL);
			searchinfo.s_parms.s_ulong.value[searchinfo.vcnt] = value;
			searchinfo.vcnt++;
			break;

		case SEARCH_UINT:
			if (can_eval(args[optind])) {
				value = eval(args[optind], FAULT_ON_ERROR, NULL);
				searchinfo.s_parms.s_uint.opt_string[searchinfo.vcnt] =
					mask ? NULL : args[optind];
			} else if (symbol_exists(args[optind])) {
				value = symbol_value(args[optind]);
				searchinfo.s_parms.s_uint.opt_string[searchinfo.vcnt] =
					mask ? NULL : args[optind];
			} else
				value = htol(args[optind], FAULT_ON_ERROR, NULL);

			searchinfo.s_parms.s_uint.value[searchinfo.vcnt] = value;
			if (uint_overflow(value))
				error(FATAL, "value too large for -w option: %lx %s\n", 
					value, show_opt_string(&searchinfo));
			searchinfo.vcnt++;
			break;

		case SEARCH_USHORT:
			if (can_eval(args[optind])) {
				value = eval(args[optind], FAULT_ON_ERROR, NULL);
				searchinfo.s_parms.s_ushort.opt_string[searchinfo.vcnt] =
					mask ? NULL : args[optind];
			} else if (symbol_exists(args[optind])) {
				value = symbol_value(args[optind]);
				searchinfo.s_parms.s_ushort.opt_string[searchinfo.vcnt] =
					mask ? NULL : args[optind];
			} else
				value = htol(args[optind], FAULT_ON_ERROR, NULL);

			searchinfo.s_parms.s_ushort.value[searchinfo.vcnt] = value;
			if (ushort_overflow(value))
				error(FATAL, "value too large for -h option: %lx %s\n", 
					value, show_opt_string(&searchinfo));
			searchinfo.vcnt++;
			break;

		case SEARCH_CHARS:
			/* parser can deliver empty strings */
			if (strlen(args[optind])) { 
				searchinfo.s_parms.s_chars.value[searchinfo.vcnt] = 
					args[optind];
				searchinfo.s_parms.s_chars.len[searchinfo.vcnt] = 
					strlen(args[optind]);
				searchinfo.vcnt++;
			}
			break;
		}
		optind++;
	}

	if (!searchinfo.vcnt)
                cmd_usage(pc->curcmd, SYNOPSIS);
	
	switch (memtype)
	{
	case PHYSADDR:
		searchinfo.paddr_start = start;
		searchinfo.paddr_end = end;
		search_physical(&searchinfo);
		break;

	case UVADDR:
		searchinfo.vaddr_start = uvaddr_start;
		searchinfo.vaddr_end = uvaddr_end;
		search_virtual(&searchinfo);
		break;

	case KVADDR:
		if (XEN_HYPER_MODE()) {
			searchinfo.vaddr_start = kvaddr_start;
			searchinfo.vaddr_end = kvaddr_end;
			search_virtual(&searchinfo);
			break;
		}

		if (tflag || Tflag) {
			searchinfo.tasks_found = 0;
			tc = FIRST_CONTEXT();
			for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
				if (Tflag && !is_task_active(tc->task))
					continue;
				searchinfo.vaddr_start = GET_STACKBASE(tc->task); 
				searchinfo.vaddr_end = GET_STACKTOP(tc->task);
				searchinfo.task_context = tc;
				searchinfo.do_task_header = TRUE;
				search_virtual(&searchinfo);
			}
			break;
		}

		for (i = 0; i < ranges; i++) {

			if ((kvaddr_start >= vrp[i].end) ||
			    (kvaddr_end <= vrp[i].start)) 
				continue;

			switch (vrp[i].type)
			{
			case KVADDR_UNITY_MAP:
			case KVADDR_START_MAP:
				if (Vflag)
					continue;
				break;

			case KVADDR_VMALLOC:
			case KVADDR_MODULES:
			case KVADDR_VMEMMAP:
				if (Kflag)
					continue;
				break;
			}

			pc->curcmd_private = vrp[i].type;

			searchinfo.vaddr_start =
				kvaddr_start > vrp[i].start ?
				kvaddr_start : vrp[i].start;
			searchinfo.vaddr_end =
				(kvaddr_end < vrp[i].end) ?
				kvaddr_end : vrp[i].end;
			search_virtual(&searchinfo);
		}
		break;
	}
}

/*
 *  Do the work for cmd_search().
 */

static char *
show_opt_string(struct searchinfo *si)
{
	char *opt_string;
	int index;

	index = (si->val == UNUSED) ? si->vcnt : si->val;

	switch (si->mode)
	{
	case SEARCH_USHORT:
		opt_string = si->s_parms.s_ushort.opt_string[index];
		break;
	case SEARCH_UINT:
		opt_string = si->s_parms.s_uint.opt_string[index];
		break;
	case SEARCH_ULONG:
	default:
		opt_string = si->s_parms.s_ulong.opt_string[index];
		break;
	}

	if (!opt_string)
		return "";
	else if (FIRSTCHAR(opt_string) == '(')
		return opt_string;
	else {
		sprintf(si->buf, "(%s)", opt_string);
		return si->buf;
	}
}

#define SEARCHMASK(X) ((X) | mask) 

static void
display_with_pre_and_post(void *bufptr, ulonglong addr, struct searchinfo *si)
{
	int ctx, memtype, t, amount;
	ulonglong addr_d;
	ulong flag;
	char buf[BUFSIZE];

	ctx = si->context;
	memtype = si->memtype;
	flag = HEXADECIMAL|NO_ERROR|ASCII_ENDLINE;

	switch (si->mode)
	{
	case SEARCH_USHORT:
		t = sizeof(ushort);
		break;
	case SEARCH_UINT:
		t = sizeof(uint);
		break;
	case SEARCH_ULONG:
	default:
		t = sizeof(ulong);
		break;
	}

	switch (t)
	{
	case 8:
		flag |= DISPLAY_64;
		break;
	case 4:
		flag |= DISPLAY_32;
		break;
	case 2:
		flag |= DISPLAY_16;
		break;
	}

	amount = ctx * t;
	addr_d = addr - amount;

	display_memory(addr_d, ctx, flag, memtype, NULL);

	BZERO(buf, BUFSIZE);
	fprintf(fp, "%s:  ", mkstring(buf, VADDR_PRLEN,
				RJUST|LONGLONG_HEX, MKSTR(&addr)));

	switch(si->mode)
	{
	case SEARCH_ULONG:
		fprintf(fp, "%lx %s\n", *((ulong *)bufptr),
			show_opt_string(si));
		break;
	case SEARCH_UINT:
		fprintf(fp, "%x %s\n", *((uint *)bufptr),
			show_opt_string(si));
		break;
	case SEARCH_USHORT:
		fprintf(fp, "%x %s\n", *((ushort *)bufptr),
			show_opt_string(si));
		break;
	}

	addr_d = addr + t;
	display_memory(addr_d, ctx, flag, memtype, NULL);
	fprintf(fp, "\n");
}

static ulong
search_ulong(ulong *bufptr, ulong addr, int longcnt, struct searchinfo *si)
{
	int i;
	ulong mask = si->s_parms.s_ulong.mask;
	for (i = 0; i < longcnt; i++, bufptr++, addr += sizeof(long)) {
		for (si->val = 0; si->val < si->vcnt; si->val++) {
			if (SEARCHMASK(*bufptr) == 
			    SEARCHMASK(si->s_parms.s_ulong.value[si->val])) {
				if (si->do_task_header) {
					print_task_header(fp, si->task_context, 
						si->tasks_found);
					si->do_task_header = FALSE;
					si->tasks_found++;
				}
				if (si->context)
					display_with_pre_and_post(bufptr, addr, si);
				else 
					fprintf(fp, "%lx: %lx %s\n", addr, *bufptr,
						show_opt_string(si));
			}
                }
	}
	return addr;
}

/* phys search uses ulonglong address representation */
static ulonglong
search_ulong_p(ulong *bufptr, ulonglong addr, int longcnt, struct searchinfo *si)
{
	int i;
	ulong mask = si->s_parms.s_ulong.mask;
	for (i = 0; i < longcnt; i++, bufptr++, addr += sizeof(long)) {
		for (si->val = 0; si->val < si->vcnt; si->val++) {
			if (SEARCHMASK(*bufptr) == 
			    SEARCHMASK(si->s_parms.s_ulong.value[si->val])) {
				if (si->context)
					display_with_pre_and_post(bufptr, addr, si);
				else
					fprintf(fp, "%llx: %lx %s\n", addr, *bufptr,
						show_opt_string(si));
			}
                }
	}
	return addr;
}

static ulong
search_uint(ulong *bufptr, ulong addr, int longcnt, struct searchinfo *si)
{
	int i;
	int cnt = longcnt * (sizeof(long)/sizeof(int));
	uint *ptr = (uint *)bufptr;
	uint mask = si->s_parms.s_uint.mask;

	for (i = 0; i < cnt; i++, ptr++, addr += sizeof(int)) {
		for (si->val = 0; si->val < si->vcnt; si->val++) {
			if (SEARCHMASK(*ptr) == 
			    SEARCHMASK(si->s_parms.s_uint.value[si->val])) {
				if (si->do_task_header) {
					print_task_header(fp, si->task_context, 
						si->tasks_found);
					si->do_task_header = FALSE;
					si->tasks_found++;
				}
				if (si->context)
					display_with_pre_and_post(ptr, addr, si);
				else
					fprintf(fp, "%lx: %x %s\n", addr, *ptr, 
						show_opt_string(si));
			}
                }
	}
	return addr;
}

/* phys search uses ulonglong address representation */
static ulonglong
search_uint_p(ulong *bufptr, ulonglong addr, int longcnt, struct searchinfo *si)
{
	int i;
	int cnt = longcnt * (sizeof(long)/sizeof(int));
	uint *ptr = (uint *)bufptr;
	uint mask = si->s_parms.s_uint.mask;

	for (i = 0; i < cnt; i++, ptr++, addr += sizeof(int)) {
		for (si->val = 0; si->val < si->vcnt; si->val++) {
			if (SEARCHMASK(*ptr) == 
			    SEARCHMASK(si->s_parms.s_uint.value[si->val])) {
				if (si->context)
					display_with_pre_and_post(ptr, addr, si);
				else
					fprintf(fp, "%llx: %x %s\n", addr, *ptr, 
						show_opt_string(si));
			}
                }
	}
	return addr;
}

static ulong
search_ushort(ulong *bufptr, ulong addr, int longcnt, struct searchinfo *si)
{
	int i;
	int cnt = longcnt * (sizeof(long)/sizeof(short));
	ushort *ptr = (ushort *)bufptr;
	ushort mask = si->s_parms.s_ushort.mask;

	for (i = 0; i < cnt; i++, ptr++, addr += sizeof(short)) {
		for (si->val = 0; si->val < si->vcnt; si->val++) {
			if (SEARCHMASK(*ptr) == 
			    SEARCHMASK(si->s_parms.s_ushort.value[si->val])) {
				if (si->do_task_header) {
					print_task_header(fp, si->task_context, 
						si->tasks_found);
					si->do_task_header = FALSE;
					si->tasks_found++;
				}
				if (si->context)
					display_with_pre_and_post(ptr, addr, si);
				else
					fprintf(fp, "%lx: %x %s\n", addr, *ptr, 
						show_opt_string(si));
			}
                }
	}
	return addr;
}

/* phys search uses ulonglong address representation */
static ulonglong
search_ushort_p(ulong *bufptr, ulonglong addr, int longcnt, struct searchinfo *si)
{
	int i;
	int cnt = longcnt * (sizeof(long)/sizeof(short));
	ushort *ptr = (ushort *)bufptr;
	ushort mask = si->s_parms.s_ushort.mask;

	for (i = 0; i < cnt; i++, ptr++, addr += sizeof(short)) {
		for (si->val = 0; si->val < si->vcnt; si->val++) {
			if (SEARCHMASK(*ptr) == 
			    SEARCHMASK(si->s_parms.s_ushort.value[si->val])) {
				if (si->context)
					display_with_pre_and_post(ptr, addr, si);
				else
					fprintf(fp, "%llx: %x %s\n", addr, *ptr,
						show_opt_string(si));
			}
                }
	}
	return addr;
}

/*
 * String search "memory" to remember possible matches that cross
 * page (or search buffer) boundaries.
 * The cross_match zone is the last strlen-1 chars of the page for
 * each of the possible targets.
 */
struct cross_match {
	int cnt;	/* possible hits in the cross_match zone */
	ulong addr; 	/* starting addr of crossing match zone for this target */
	ulonglong addr_p; /* for physical search */
	char hit[BUFSIZE]; /* array of hit locations in the crossing match zone */
			/* This should really be the much-smaller MAXARGLEN, but
			 * no one seems to be enforcing that in the parser.
			 */
} cross[MAXARGS];

ulong cross_match_next_addr; /* the expected starting value of the next page */
ulonglong cross_match_next_addr_p; /* the expected starting value of the next physical page */
	
#define CHARS_CTX 56

static void
report_match(struct searchinfo *si, ulong addr, char *ptr1, int len1, char *ptr2, int len2)
{
	int i;

	if (si->do_task_header) {
		print_task_header(fp, si->task_context, si->tasks_found);
		si->do_task_header = FALSE;
		si->tasks_found++;
	}

	fprintf(fp, "%lx: ", addr);
	for (i = 0; i < len1; i++) {
		if (isprint(ptr1[i]))
			fprintf(fp, "%c", ptr1[i]);
		else
			fprintf(fp, ".");
	}
	for (i = 0; i < len2; i++) {
		if (isprint(ptr2[i]))
			fprintf(fp, "%c", ptr2[i]);
		else
			fprintf(fp, ".");
	}
	fprintf(fp, "\n");	
}
	
static ulong
search_chars(ulong *bufptr, ulong addr, int longcnt, struct searchinfo *si)
{
	int i, j;
	int len;
	char *target;
	int charcnt = longcnt * sizeof(long);
	char *ptr = (char *)bufptr;

	/* is this the first page of this search? */
	if (si->s_parms.s_chars.started_flag == 0) {
		for (j = 0; j < si->vcnt; j++) {
			cross[j].cnt = 0;   /* no hits */
		}
		cross_match_next_addr = (ulong)-1; /* no page match for first page */
		si->s_parms.s_chars.started_flag++;
	}

	if (cross_match_next_addr == addr) {
		for (j = 0; j < si->vcnt; j++) {
			if (cross[j].cnt) {
				target = si->s_parms.s_chars.value[j];
				len = si->s_parms.s_chars.len[j];
				for (i = 0; i < len - 1; i++) {
					if (cross[j].hit[i] &&
						!strncmp(&target[len - 1 - i], ptr, i + 1)) 
							report_match(si, cross[j].addr + i, 
									target, len,
									&ptr[i+1], 
									CHARS_CTX - len);
				}
			}
		}
	}

	/* set up for possible cross matches on this page */
	cross_match_next_addr = addr + charcnt;
	for (j = 0; j < si->vcnt; j++) {
		len = si->s_parms.s_chars.len[j];
		cross[j].cnt = 0;
		cross[j].addr = addr + longcnt * sizeof(long) - (len - 1);
		for (i = 0; i < len - 1; i++) 
			cross[j].hit[i] = 0;
	}
	
	for (i = 0; i < charcnt; i++, ptr++, addr++) {
		for (j = 0; j < si->vcnt; j++) {
			target = si->s_parms.s_chars.value[j];
			len = si->s_parms.s_chars.len[j];
			if ((i + len) > charcnt) {
				/* check for cross match */
				if (!strncmp(target, ptr, charcnt - i)) {
					cross[j].hit[len + i - charcnt - 1] = 1;
					cross[j].cnt++;
				} 
			} else {
				if (!strncmp(target, ptr, len)) {
					int slen = CHARS_CTX;
					if ((i + CHARS_CTX) > charcnt) 
						slen = charcnt - i;
					report_match(si, addr, ptr, slen, (char *)0, 0);
				}
			}
		}
	}
	return addr;
}
						

static void
report_match_p(ulonglong addr, char *ptr1, int len1, char *ptr2, int len2)
{
	int i;
	fprintf(fp, "%llx: ", addr);
	for (i = 0; i < len1; i++) {
		if (isprint(ptr1[i]))
			fprintf(fp, "%c", ptr1[i]);
		else
			fprintf(fp, ".");
	}
	for (i = 0; i < len2; i++) {
		if (isprint(ptr2[i]))
			fprintf(fp, "%c", ptr2[i]);
		else
			fprintf(fp, ".");
	}
	fprintf(fp, "\n");	
}

static ulonglong
search_chars_p(ulong *bufptr, ulonglong addr_p, int longcnt, struct searchinfo *si)
{
	int i, j;
	int len;
	char *target;
	int charcnt = longcnt * sizeof(long);
	char *ptr = (char *)bufptr;

	/* is this the first page of this search? */
	if (si->s_parms.s_chars.started_flag == 0) {
		for (j = 0; j < si->vcnt; j++) {
			cross[j].cnt = 0;   /* no hits */
		}
		cross_match_next_addr_p = (ulonglong)-1; /* no page match for first page */
		si->s_parms.s_chars.started_flag++;
	}

	if (cross_match_next_addr_p == addr_p) {
		for (j = 0; j < si->vcnt; j++) {
			if (cross[j].cnt) {
				target = si->s_parms.s_chars.value[j];
				len = si->s_parms.s_chars.len[j];
				for (i = 0; i < len - 1; i++) {
					if (cross[j].hit[i] &&
						!strncmp(&target[len - 1 - i], ptr, i + 1)) 
							report_match_p(cross[j].addr_p + i, 
									target, len,
									&ptr[i+1], 
									CHARS_CTX - len);
				}
			}
		}
	}

	/* set up for possible cross matches on this page */
	cross_match_next_addr_p = addr_p + charcnt;
	for (j = 0; j < si->vcnt; j++) {
		len = si->s_parms.s_chars.len[j];
		cross[j].cnt = 0;
		cross[j].addr_p = addr_p + longcnt * sizeof(long) - (len - 1);
		for (i = 0; i < len - 1; i++) 
			cross[j].hit[i] = 0;
	}
	
	for (i = 0; i < charcnt; i++, ptr++, addr_p++) {
		for (j = 0; j < si->vcnt; j++) {
			target = si->s_parms.s_chars.value[j];
			len = si->s_parms.s_chars.len[j];
			if ((i + len) > charcnt) {
				/* check for cross match */
				if (!strncmp(target, ptr, charcnt - i)) {
					cross[j].hit[len + i - charcnt - 1] = 1;
					cross[j].cnt++;
				} 
			} else {
				if (!strncmp(target, ptr, len)) {
					int slen = CHARS_CTX;
					if ((i + CHARS_CTX) > charcnt) 
						slen = charcnt - i;
					report_match_p(addr_p, ptr, slen, (char *)0, 0);
				}
			}
		}
	}
	return addr_p;
}

static void
search_virtual(struct searchinfo *si)
{
	ulong start, end;
	ulong pp, next, *ubp;
	int wordcnt, lastpage;
	ulong page;
	physaddr_t paddr; 
	char *pagebuf;
	ulong pct, pages_read, pages_checked;
	time_t begin, finish;

	start = si->vaddr_start;
	end = si->vaddr_end;
	pages_read = pages_checked = 0;
	begin = finish = 0;

	pagebuf = GETBUF(PAGESIZE());

	if (start & (sizeof(long)-1)) {
		start &= ~(sizeof(long)-1);
		error(INFO, "rounding down start address to: %lx\n", start);
	}

	if (CRASHDEBUG(1)) {
		begin = time(NULL);
		fprintf(fp, "search_virtual: start: %lx end: %lx\n", 
			start, end);
	}

	next = start;

	for (pp = VIRTPAGEBASE(start); next < end; next = pp) {
		pages_checked++;
		lastpage = (VIRTPAGEBASE(next) == VIRTPAGEBASE(end));
		if (LKCD_DUMPFILE())
			set_lkcd_nohash();

		/*
		 *  Keep it virtual for Xen hypervisor.
		 */
		if (XEN_HYPER_MODE()) {
                	if (!readmem(pp, KVADDR, pagebuf, PAGESIZE(),
                    	    "search page", RETURN_ON_ERROR|QUIET)) {
				if (CRASHDEBUG(1))
					fprintf(fp, 
					    "search suspended at: %lx\n", pp);
				goto done;
			}
			goto virtual;
		}

                switch (si->memtype)
                {
                case UVADDR:
                        if (!uvtop(CURRENT_CONTEXT(), pp, &paddr, 0) ||
                            !phys_to_page(paddr, &page)) { 
				if (!next_upage(CURRENT_CONTEXT(), pp, &pp)) 
					goto done;
                                continue;
			}
                        break;

                case KVADDR:
                        if (!kvtop(CURRENT_CONTEXT(), pp, &paddr, 0) ||
                            !phys_to_page(paddr, &page)) {
				if (!next_kpage(pp, &pp))
					goto done;
                                continue;
			}
                        break;
                }

                if (!readmem(paddr, PHYSADDR, pagebuf, PAGESIZE(),
                    "search page", RETURN_ON_ERROR|QUIET)) {
			pp += PAGESIZE();
			continue;
		}
virtual:
		pages_read++;

		ubp = (ulong *)&pagebuf[next - pp];
		if (lastpage) {
			if (end == (ulong)(-1))
				wordcnt = PAGESIZE()/sizeof(long);
			else
				wordcnt = (end - next)/sizeof(long);
		} else
			wordcnt = (PAGESIZE() - (next - pp))/sizeof(long);

		switch (si->mode)
		{
		case SEARCH_ULONG:
			next = search_ulong(ubp, next, wordcnt, si);
			break;
		case SEARCH_UINT:
			next = search_uint(ubp, next, wordcnt, si);
			break;
		case SEARCH_USHORT:
			next = search_ushort(ubp, next, wordcnt, si);
			break;
		case SEARCH_CHARS:
			next = search_chars(ubp, next, wordcnt, si);
			break;
		default:
			/* unimplemented search type */
			next += wordcnt * (sizeof(long));
			break;
		}

		if (CRASHDEBUG(1))
			if ((pp % (1024*1024)) == 0)
				console("%lx\n", pp);

		pp += PAGESIZE();
	}

done:
	if (CRASHDEBUG(1)) {
		finish = time(NULL);
		pct = (pages_read * 100)/pages_checked;
		fprintf(fp, 
		    "search_virtual: read %ld (%ld%%) of %ld pages checked in %ld seconds\n", 
			pages_read, pct, pages_checked, finish - begin);
	}

	FREEBUF(pagebuf);
}


static void
search_physical(struct searchinfo *si)
{
	ulonglong start_in, end_in;
	ulong *ubp;
	int wordcnt, lastpage;
	ulonglong pnext, ppp;
	char *pagebuf;
	ulong pct, pages_read, pages_checked;
	time_t begin, finish;
	ulong page;

	start_in = si->paddr_start;
	end_in = si->paddr_end;
	pages_read = pages_checked = 0;
	begin = finish = 0;

	pagebuf = GETBUF(PAGESIZE());

        if (start_in & (sizeof(ulonglong)-1)) {
                start_in &= ~(sizeof(ulonglong)-1);
                error(INFO, "rounding down start address to: %llx\n", 
			(ulonglong)start_in);
        }

	if (CRASHDEBUG(1)) {
		begin = time(NULL);
		fprintf(fp, "search_physical: start: %llx end: %llx\n", 
			start_in, end_in);
	}

        pnext = start_in;
        for (ppp = PHYSPAGEBASE(start_in); pnext < end_in; pnext = ppp) {
		pages_checked++;
                lastpage = (PHYSPAGEBASE(pnext) == PHYSPAGEBASE(end_in));
                if (LKCD_DUMPFILE())
                        set_lkcd_nohash();

                if (!phys_to_page(ppp, &page) || 
		    !readmem(ppp, PHYSADDR, pagebuf, PAGESIZE(),
                   	"search page", RETURN_ON_ERROR|QUIET)) {
			if (!next_physpage(ppp, &ppp))
				break;
			continue;
		}

		pages_read++;
                ubp = (ulong *)&pagebuf[pnext - ppp];
                if (lastpage) {
                        if (end_in == (ulonglong)(-1))
                                wordcnt = PAGESIZE()/sizeof(long);
                        else
                                wordcnt = (end_in - pnext)/sizeof(long);
                } else
                        wordcnt = (PAGESIZE() - (pnext - ppp))/sizeof(long);

		switch (si->mode)
		{
		case SEARCH_ULONG:
			pnext = search_ulong_p(ubp, pnext, wordcnt, si);
			break;
		case SEARCH_UINT:
			pnext = search_uint_p(ubp, pnext, wordcnt, si);
			break;
		case SEARCH_USHORT:
			pnext = search_ushort_p(ubp, pnext, wordcnt, si);
			break;
		case SEARCH_CHARS:
			pnext = search_chars_p(ubp, pnext, wordcnt, si);
			break;
		default:
			/* unimplemented search type */
			pnext += wordcnt * (sizeof(long));
			break;
		}

		ppp += PAGESIZE();
	}

	if (CRASHDEBUG(1)) {
		finish = time(NULL);
		pct = (pages_read * 100)/pages_checked;
		fprintf(fp, 
		    "search_physical: read %ld (%ld%%) of %ld pages checked in %ld seconds\n", 
			pages_read, pct, pages_checked, finish - begin);
	}

	FREEBUF(pagebuf);
}

static bool
check_vma(ulong vma, ulong vaddr, ulong *vm_next, ulong *nextvaddr)
{
	char *vma_buf;
	ulong vm_start, vm_end;

	vma_buf = fill_vma_cache(vma);

	vm_start = ULONG(vma_buf + OFFSET(vm_area_struct_vm_start));
	vm_end = ULONG(vma_buf + OFFSET(vm_area_struct_vm_end));
	if (vm_next)
		*vm_next = ULONG(vma_buf + OFFSET(vm_area_struct_vm_next));

	if (vaddr <= vm_start) {
		*nextvaddr = vm_start;
		return TRUE;
	}

	if ((vaddr > vm_start) && (vaddr < vm_end)) {
		*nextvaddr = vaddr;
		return TRUE;
	}
	return FALSE;
}

/*
 *  Return the next mapped user virtual address page that comes after 
 *  the passed-in address.
 */
static int
next_upage(struct task_context *tc, ulong vaddr, ulong *nextvaddr)
{
	ulong vma, total_vm;
	ulong vm_next;
	ulong mm_mt, entry_num, i;
	struct list_pair *entry_list;

        if (!tc->mm_struct)
                return FALSE;

	fill_mm_struct(tc->mm_struct);
	vaddr = VIRTPAGEBASE(vaddr) + PAGESIZE();  /* first possible page */
	total_vm = ULONG(tt->mm_struct + OFFSET(mm_struct_total_vm));
	if (!total_vm)
		return FALSE;

	if (INVALID_MEMBER(mm_struct_mmap) && VALID_MEMBER(mm_struct_mm_mt)) {
		mm_mt = tc->mm_struct + OFFSET(mm_struct_mm_mt);
		entry_num = do_maple_tree(mm_mt, MAPLE_TREE_COUNT, NULL);
		entry_list = (struct list_pair *)GETBUF(entry_num * sizeof(struct list_pair));
		do_maple_tree(mm_mt, MAPLE_TREE_GATHER, entry_list);
		for (i = 0; i < entry_num; i++) {
			if (!!(vma = (ulong)entry_list[i].value) &&
			    check_vma(vma, vaddr, NULL, nextvaddr)) {
				FREEBUF(entry_list);
				return TRUE;
			}
		}
		FREEBUF(entry_list);
	} else {
		vma = ULONG(tt->mm_struct + OFFSET(mm_struct_mmap));

		if (!vma)
			return FALSE;
		for ( ; vma; vma = vm_next) {
			if (check_vma(vma, vaddr, &vm_next, nextvaddr))
				return TRUE;
		}
	}

	return FALSE;
}

/*
 *  Return the next mapped kernel virtual address in the vmlist
 *  that is equal to or comes after the passed-in address.
 *  Prevent repeated calls to dump_vmlist() by only doing it
 *  one time for dumpfiles, or one time per (active) command.
 */
static int
next_vmlist_vaddr(ulong vaddr, ulong *nextvaddr)
{
	int i, retval;
	ulong cnt;
	struct meminfo meminfo, *mi;
	static int count = 0;
	static struct vmlist *vmlist = NULL;
	static ulong cmdgencur = BADVAL;

	/*
	 *  Search the stashed vmlist if possible.
	 */
	if (vmlist && ACTIVE()) {
		if (pc->cmdgencur != cmdgencur) {
			free(vmlist);
			vmlist = NULL;
		}
	}

	if (vmlist) {
		for (i = 0, retval = FALSE; i < count; i++) {
			if (vaddr <= vmlist[i].addr) {
				*nextvaddr = vmlist[i].addr;
				retval = TRUE;
				break;
			}
			if (vaddr < (vmlist[i].addr + vmlist[i].size)) {
				*nextvaddr = vaddr;
				retval = TRUE;
				break;
			}
		}
		return retval;
	}

	mi = &meminfo;
	BZERO(mi, sizeof(struct meminfo));
        mi->flags = GET_VMLIST_COUNT;
        dump_vmlist(mi);
	cnt = mi->retval;

	if (!cnt)
		return FALSE;

	mi->vmlist = (struct vmlist *)GETBUF(sizeof(struct vmlist)*cnt);
        mi->flags = GET_VMLIST;
        dump_vmlist(mi);

	for (i = 0, retval = FALSE; i < cnt; i++) {
		if (vaddr <= mi->vmlist[i].addr) {
			*nextvaddr = mi->vmlist[i].addr;
			retval = TRUE;
			break;
		}
		if (vaddr < (mi->vmlist[i].addr + mi->vmlist[i].size)) {
			*nextvaddr = vaddr;
			retval = TRUE;
			break;
		}
	}

	if (!vmlist) {
		vmlist = (struct vmlist *)
			malloc(sizeof(struct vmlist)*cnt);

		if (vmlist) {
			BCOPY(mi->vmlist, vmlist,
				sizeof(struct vmlist)*cnt);
			count = cnt;
			cmdgencur = pc->cmdgencur;
		}
	}

	FREEBUF(mi->vmlist);

	return retval;
}

/*
 *  Determine whether a virtual address is inside a vmlist segment.
 */
int 
in_vmlist_segment(ulong vaddr)
{
	ulong next;

	if (next_vmlist_vaddr(vaddr, &next) &&
	    (vaddr == next))
		return TRUE;

	return FALSE;
}

/*
 *  Return the next kernel module virtual address that is
 *  equal to or comes after the passed-in address.
 */
static int
next_module_vaddr(ulong vaddr, ulong *nextvaddr)
{
	int i;
	ulong start, end;
	struct load_module *lm;

	for (i = 0; i < st->mods_installed; i++) {
		lm = &st->load_modules[i];
		start = lm->mod_base;
		end = lm->mod_base + lm->mod_size;
		if (vaddr >= end)
			continue;
		/*
	 	 *  Either below or in this module.
		 */
		if (vaddr < start)
			*nextvaddr = start;
		else
			*nextvaddr = vaddr;
		return TRUE;
	}

	return FALSE;
}

/*
 *  Return the next kernel virtual address page in a designated
 *  kernel virtual address range that comes after the passed-in, 
 *  untranslatable, address.
 */
static int
next_kpage(ulong vaddr, ulong *nextvaddr)
{
        ulong vaddr_orig;

	vaddr_orig = vaddr;
	vaddr = VIRTPAGEBASE(vaddr) + PAGESIZE();  /* first possible page */

        if (vaddr < vaddr_orig)  /* wrapped back to zero? */
                return FALSE;

	switch (pc->curcmd_private)
	{
	case KVADDR_UNITY_MAP:
		return next_identity_mapping(vaddr, nextvaddr);

	case KVADDR_VMALLOC: 
		return next_vmlist_vaddr(vaddr, nextvaddr);

	case KVADDR_VMEMMAP:  
		*nextvaddr = vaddr;
		return TRUE;

	case KVADDR_START_MAP:
		*nextvaddr = vaddr;
		return TRUE;

	case KVADDR_MODULES: 
		return next_module_vaddr(vaddr, nextvaddr);
	}

	return FALSE;
}

/*
 *  Return the next physical address page that comes after
 *  the passed-in, unreadable, address.
 */
static int
next_physpage(ulonglong paddr, ulonglong *nextpaddr)
{
	int n;
	ulonglong node_start;
	ulonglong node_end;
	struct node_table *nt;

	for (n = 0; n < vt->numnodes; n++) {
		nt = &vt->node_table[n];
		node_start = nt->start_paddr;
		node_end = nt->start_paddr + (nt->size * PAGESIZE());

		if (paddr >= node_end)
			continue;

		if (paddr < node_start) {
			*nextpaddr = node_start;
			return TRUE;
		}

		if (paddr < node_end) {
			*nextpaddr = paddr + PAGESIZE();
			return TRUE;
		}
	}

	return FALSE;
}

static int
get_hugetlb_total_pages(ulong *nr_total_pages, ulong *nr_total_free_pages)
{
	ulong hstate_p, vaddr;
	int i, len;
	ulong nr_huge_pages;
	ulong free_huge_pages;
	uint horder;

	*nr_total_pages = *nr_total_free_pages = 0;
	if (kernel_symbol_exists("hstates")) {

		if (INVALID_SIZE(hstate) ||
		    INVALID_MEMBER(hstate_order) ||
		    INVALID_MEMBER(hstate_nr_huge_pages) ||
		    INVALID_MEMBER(hstate_free_huge_pages))
			return FALSE;

		len = get_array_length("hstates", NULL, 0);
		hstate_p = symbol_value("hstates");

		for (i = 0; i < len; i++) {
			vaddr = hstate_p + (SIZE(hstate) * i);

			readmem(vaddr + OFFSET(hstate_order),
				KVADDR, &horder, sizeof(uint),
				"hstate_order", FAULT_ON_ERROR);

			if (!horder)
				continue;

			readmem(vaddr + OFFSET(hstate_nr_huge_pages),
				KVADDR, &nr_huge_pages, sizeof(ulong),
				"hstate_nr_huge_pages", FAULT_ON_ERROR);

			readmem(vaddr + OFFSET(hstate_free_huge_pages),
				KVADDR, &free_huge_pages, sizeof(ulong),
				"hstate_free_huge_pages", FAULT_ON_ERROR);

			*nr_total_pages += nr_huge_pages * (1 << horder);
			*nr_total_free_pages += free_huge_pages * (1 << horder);
		}
	} else if (kernel_symbol_exists("nr_huge_pages")) {
		unsigned long hpage_shift = 21;

		if ((machine_type("X86") && !(machdep->flags & PAE)))
			hpage_shift = 22;
		get_symbol_data("nr_huge_pages",
			sizeof(ulong), &nr_huge_pages);
		get_symbol_data("free_huge_pages",
			sizeof(ulong), &free_huge_pages);
		*nr_total_pages = nr_huge_pages * ((1 << hpage_shift) /
			machdep->pagesize);
		*nr_total_free_pages = free_huge_pages *
			((1 << hpage_shift) / machdep->pagesize);
	}
	return TRUE;
}

/*
 *  Display swap statistics.
 */
void
cmd_swap(void)
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

	dump_swap_info(VERBOSE, NULL, NULL);
}

/*
 *  Do the work for cmd_swap().
 */

#define SWP_USED        1
#define SWAP_MAP_BAD    0x8000

char *swap_info_hdr = \
"SWAP_INFO_STRUCT    TYPE       SIZE       USED     PCT  PRI  FILENAME\n";

static int
dump_swap_info(ulong swapflags, ulong *totalswap_pages, ulong *totalused_pages)
{
	int i, j;
	int swap_device, prio;
	ulong pages, usedswap;
	ulong flags, swap_file, max, swap_map, pct;
	ulong vfsmnt;
	ulong swap_info, swap_info_ptr;
	ushort *smap;
	ulong inuse_pages, totalswap, totalused;
	char *devname;
	char buf[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char buf5[BUFSIZE];

	if (!symbol_exists("nr_swapfiles"))
		error(FATAL, "nr_swapfiles doesn't exist in this kernel!\n");

        if (!symbol_exists("swap_info"))
                error(FATAL, "swap_info doesn't exist in this kernel!\n");

	swap_info_init();

	swap_info = symbol_value("swap_info");

	if (swapflags & VERBOSE)
		fprintf(fp, "%s", swap_info_hdr);

	totalswap = totalused = 0;

	for (i = 0; i < vt->nr_swapfiles; i++, 
	    swap_info += (vt->flags & SWAPINFO_V1 ? 
            SIZE(swap_info_struct) : sizeof(void *))) {
		if (vt->flags & SWAPINFO_V2) {
			if (!readmem(swap_info, KVADDR, &swap_info_ptr,
			    sizeof(void *), "swap_info pointer", 
			    QUIET|RETURN_ON_ERROR))
				continue;
			if (!swap_info_ptr)
				continue;
			fill_swap_info(swap_info_ptr);
		} else
			fill_swap_info(swap_info);

		if (MEMBER_SIZE("swap_info_struct", "flags") == sizeof(uint))
			flags = UINT(vt->swap_info_struct +
				OFFSET(swap_info_struct_flags));
		else
			flags = ULONG(vt->swap_info_struct +
				OFFSET(swap_info_struct_flags));

		if (!(flags & SWP_USED))
			continue;

		swap_file = ULONG(vt->swap_info_struct + 
			OFFSET(swap_info_struct_swap_file));

                swap_device = INT(vt->swap_info_struct +
                        OFFSET_OPTION(swap_info_struct_swap_device, 
			swap_info_struct_old_block_size));

                pages = INT(vt->swap_info_struct +
                        OFFSET(swap_info_struct_pages));

		totalswap += pages;
		pages <<= (PAGESHIFT() - 10);
		inuse_pages = 0;

		if (MEMBER_SIZE("swap_info_struct", "prio") == sizeof(short))
			prio = SHORT(vt->swap_info_struct + 
				OFFSET(swap_info_struct_prio));
		else
			prio = INT(vt->swap_info_struct + 
				OFFSET(swap_info_struct_prio));

		if (MEMBER_SIZE("swap_info_struct", "max") == sizeof(int))
			max = UINT(vt->swap_info_struct +
				OFFSET(swap_info_struct_max));
		else
			max = ULONG(vt->swap_info_struct +
				OFFSET(swap_info_struct_max));

		if (VALID_MEMBER(swap_info_struct_inuse_pages)) {
			if (MEMBER_SIZE("swap_info_struct", "inuse_pages") == sizeof(int))
				inuse_pages = UINT(vt->swap_info_struct +
					OFFSET(swap_info_struct_inuse_pages));
			else
				inuse_pages = ULONG(vt->swap_info_struct +
					OFFSET(swap_info_struct_inuse_pages));
		}

		swap_map = ULONG(vt->swap_info_struct +
			OFFSET(swap_info_struct_swap_map));

		if (swap_file) {
			if (VALID_MEMBER(swap_info_struct_swap_vfsmnt)) {
                		vfsmnt = ULONG(vt->swap_info_struct +
                        		OFFSET(swap_info_struct_swap_vfsmnt));
				get_pathname(swap_file, buf, BUFSIZE, 
					1, vfsmnt);
			} else if (VALID_MEMBER
				(swap_info_struct_old_block_size)) {
				devname = vfsmount_devname(file_to_vfsmnt(swap_file), 
					buf1, BUFSIZE);
				get_pathname(file_to_dentry(swap_file), 
					buf, BUFSIZE, 1, file_to_vfsmnt(swap_file));
				if ((STREQ(devname, "devtmpfs") || STREQ(devname, "udev")) 
				    && !STRNEQ(buf, "/dev/"))
					string_insert("/dev", buf);
			} else {
				get_pathname(swap_file, buf, BUFSIZE, 1, 0);
			}
		} else
			sprintf(buf, "(unknown)");

		smap = NULL;
		if (vt->flags & SWAPINFO_V1) {
			smap = (ushort *)GETBUF(sizeof(ushort) * max);

			if (!readmem(swap_map, KVADDR, smap, 
			    sizeof(ushort) * max, "swap_info swap_map data",
			    RETURN_ON_ERROR|QUIET)) {
				if (swapflags & RETURN_ON_ERROR) {
					*totalswap_pages = swap_map;
					*totalused_pages = i;
					FREEBUF(smap);
					return FALSE;
				} else 
					error(FATAL, 
			"swap_info[%d].swap_map at %lx is inaccessible\n",
						i, swap_map);
			}
		}

		usedswap = 0;
		if (smap) {
	                for (j = 0; j < max; j++) {
	                        switch (smap[j])
	                        {
	                        case SWAP_MAP_BAD:
	                        case 0:
	                                continue;
	                        default:
	                                usedswap++;
	                        }
			}
			FREEBUF(smap);
		} else
			usedswap = inuse_pages;

		totalused += usedswap;
		usedswap <<= (PAGESHIFT() - 10);
		pct = (usedswap * 100)/pages;

		if (swapflags & VERBOSE) {
			sprintf(buf1, "%lx", (vt->flags & SWAPINFO_V2) ? 
				swap_info_ptr : swap_info);
			sprintf(buf2, "%ldk", pages); 
			sprintf(buf3, "%ldk", usedswap); 
			sprintf(buf4, "%2ld%%", pct);
			sprintf(buf5, "%d", prio);
			fprintf(fp, "%s  %s %s %s %s %s  %s\n", 
				mkstring(buf1, 
				MAX(VADDR_PRLEN, strlen("SWAP_INFO_STRUCT")),  
				CENTER|LJUST, NULL),
				swap_device ? "PARTITION" : "  FILE   ",
				mkstring(buf2, 10, CENTER|RJUST, NULL),
				mkstring(buf3, 10, CENTER|RJUST, NULL),
				mkstring(buf4, 4, CENTER|RJUST, NULL),
				mkstring(buf5, 4, RJUST, NULL), buf);
		}
	}

	if (totalswap_pages)
		*totalswap_pages = totalswap;
	if (totalused_pages)
		*totalused_pages = totalused;

	return TRUE;
}

/*
 *  Determine the swap_info_struct usage.
 */
void
swap_info_init(void)
{
	struct gnu_request *req;

	if (vt->flags & (SWAPINFO_V1|SWAPINFO_V2))
		return;

	req = (struct gnu_request *)GETBUF(sizeof(struct gnu_request));

	if ((get_symbol_type("swap_info", NULL, req) == TYPE_CODE_ARRAY) && 
	    ((req->target_typecode == TYPE_CODE_PTR) ||
	     (req->target_typecode == TYPE_CODE_STRUCT))) {
		switch (req->target_typecode)
		{
		case TYPE_CODE_STRUCT:
			vt->flags |= SWAPINFO_V1;
			break;
		case TYPE_CODE_PTR:
			vt->flags |= SWAPINFO_V2;
			break;
		}
	} else {
		if (THIS_KERNEL_VERSION >= LINUX(2,6,33))
			vt->flags |= SWAPINFO_V2;
		else
			vt->flags |= SWAPINFO_V1;
        }

	FREEBUF(req);
}

/*
 *  Translate a PTE into a swap device and offset string.
 */
char *
swap_location(ulonglong pte, char *buf)
{
	char swapdev[BUFSIZE];

        if (!pte)
                return NULL;

	if (!symbol_exists("nr_swapfiles") || !symbol_exists("swap_info"))
		return NULL;

	if (THIS_KERNEL_VERSION >= LINUX(2,6,0))
		sprintf(buf, "%s  OFFSET: %lld", 
			get_swapdev(__swp_type(pte), swapdev), (ulonglong)__swp_offset(pte));
	else
		sprintf(buf, "%s  OFFSET: %llx", 
			get_swapdev(SWP_TYPE(pte), swapdev), (ulonglong)SWP_OFFSET(pte));

        return buf;
}

/*
 *  Given the type field from a PTE, return the name of the swap device.
 */
static char *
get_swapdev(ulong type, char *buf)
{
	unsigned int i, swap_info_len;
	ulong swap_info, swap_info_ptr, swap_file;
	struct syment *sp;
	ulong vfsmnt;
	char *devname;
	char buf1[BUFSIZE];

	swap_info_init();

        swap_info = symbol_value("swap_info");

	swap_info_len = (i = ARRAY_LENGTH(swap_info)) ?
		i : get_array_length("swap_info", NULL, 0);

	/*
	 *  Even though the swap_info[] array is declared statically as:
	 *
	 *    struct swap_info_struct *swap_info[MAX_SWAPFILES];
	 *
	 *  the dimension may not be shown by the debuginfo data,
	 *  for example:
	 *
	 *    struct swap_info_struct *swap_info[28];
	 *      or
	 *    struct swap_info_struct *swap_info[];
	 *
	 *  In that case, calculate its length by checking the next
	 *  symbol's value.
	 */
	if ((swap_info_len == 0) && (vt->flags & SWAPINFO_V2) &&
	    (sp = next_symbol("swap_info", NULL)))
		swap_info_len = (sp->value - swap_info) / sizeof(void *);

        sprintf(buf, "(unknown swap location)");

	if (type >= swap_info_len)
		return buf;

	switch (vt->flags & (SWAPINFO_V1|SWAPINFO_V2))
	{
	case SWAPINFO_V1:
		swap_info += type * SIZE(swap_info_struct);
		fill_swap_info(swap_info);
		break;

	case SWAPINFO_V2:
		swap_info += type * sizeof(void *);
		if (!readmem(swap_info, KVADDR, &swap_info_ptr,
		    sizeof(void *), "swap_info pointer",
		    RETURN_ON_ERROR|QUIET))
			return buf;
		if (!swap_info_ptr)
			return buf;
		fill_swap_info(swap_info_ptr);
		break;
	}

	swap_file = ULONG(vt->swap_info_struct + 
		OFFSET(swap_info_struct_swap_file));

        if (swap_file) {
		if (VALID_MEMBER(swap_info_struct_swap_vfsmnt)) {
			vfsmnt = ULONG(vt->swap_info_struct + 
				OFFSET(swap_info_struct_swap_vfsmnt));
        		get_pathname(swap_file, buf, BUFSIZE, 1, vfsmnt);
                } else if (VALID_MEMBER (swap_info_struct_old_block_size)) {
			devname = vfsmount_devname(file_to_vfsmnt(swap_file),
				buf1, BUFSIZE);
			get_pathname(file_to_dentry(swap_file),
				buf, BUFSIZE, 1, file_to_vfsmnt(swap_file));
			if ((STREQ(devname, "devtmpfs") || STREQ(devname, "udev")) 
			    && !STRNEQ(buf, "/dev/"))
				string_insert("/dev", buf);
		} else {
        		get_pathname(swap_file, buf, BUFSIZE, 1, 0);
		}
        } 

	return buf;
}

/*
 *  If not currently stashed, cache the passed-in swap_info_struct.
 */
static void
fill_swap_info(ulong swap_info)
{
	if (vt->last_swap_read == swap_info)
		return;

	if (!vt->swap_info_struct && !(vt->swap_info_struct = (char *)
        	malloc(SIZE(swap_info_struct))))
			error(FATAL, "cannot malloc swap_info_struct space\n");
	
        readmem(swap_info, KVADDR, vt->swap_info_struct, SIZE(swap_info_struct),
                "fill_swap_info", FAULT_ON_ERROR);

	vt->last_swap_read = swap_info;
}

/*
 *  If active, clear references to the swap_info references.
 */
void
clear_swap_info_cache(void)
{
	if (ACTIVE())
		vt->last_swap_read = 0;
}


/*
 *  Translage a vm_area_struct and virtual address into a filename
 *  and offset string.
 */ 

#define PAGE_CACHE_SHIFT  (machdep->pageshift) /* This is supposed to change! */

static char *
vma_file_offset(ulong vma, ulong vaddr, char *buf)
{
	ulong vm_file, vm_start, vm_offset, vm_pgoff, dentry, offset;
	ulong vfsmnt;
	char file[BUFSIZE];
	char *vma_buf, *file_buf;

	if (!vma)
		return NULL;

        vma_buf = fill_vma_cache(vma);

        vm_file = ULONG(vma_buf + OFFSET(vm_area_struct_vm_file));

	if (!vm_file) 
		goto no_file_offset;

        file_buf = fill_file_cache(vm_file);
        dentry = ULONG(file_buf + OFFSET(file_f_dentry));

	if (!dentry) 
		goto no_file_offset;

	file[0] = NULLCHAR;
	if (VALID_MEMBER(file_f_vfsmnt)) {
        	vfsmnt = ULONG(file_buf + OFFSET(file_f_vfsmnt));
               	get_pathname(dentry, file, BUFSIZE, 1, vfsmnt);
	} else 
               	get_pathname(dentry, file, BUFSIZE, 1, 0);

	if (!strlen(file)) 
		goto no_file_offset;

        vm_start = ULONG(vma_buf + OFFSET(vm_area_struct_vm_start));

	vm_offset = vm_pgoff = 0xdeadbeef;

	if (VALID_MEMBER(vm_area_struct_vm_offset)) 
        	vm_offset = ULONG(vma_buf + 
			OFFSET(vm_area_struct_vm_offset));
	else if (VALID_MEMBER(vm_area_struct_vm_pgoff))
        	vm_pgoff = ULONG(vma_buf + 
			OFFSET(vm_area_struct_vm_pgoff));
	else 
		goto no_file_offset;

	offset = 0;
	if (vm_offset != 0xdeadbeef) 
		offset = VIRTPAGEBASE(vaddr) - vm_start + vm_offset;
	else if (vm_pgoff != 0xdeadbeef) {
		offset = ((vaddr - vm_start) >> PAGE_CACHE_SHIFT) + vm_pgoff;
		offset <<= PAGE_CACHE_SHIFT;
	}

	sprintf(buf, "%s  OFFSET: %lx", file, offset);

	return buf;

no_file_offset:
	return NULL;
}

/*
 *  Translate a PTE into its physical address and flags.
 */
void
cmd_pte(void)
{
        int c;
	ulonglong pte;

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
		pte = htoll(args[optind], FAULT_ON_ERROR, NULL);
		machdep->translate_pte((ulong)pte, NULL, pte);
		optind++;
	}

}

static char *node_zone_hdr = "ZONE  NAME         SIZE";

/*
 *  On systems supporting memory nodes, display the basic per-node data.
 */
static void
dump_memory_nodes(int initialize)
{
	int i, j;
	int n, id, node, flen, slen, badaddr;
	ulong node_mem_map;
	ulong temp_node_start_paddr;
	ulonglong node_start_paddr;
	ulong node_start_pfn;
        ulong node_start_mapnr;
	ulong node_spanned_pages, node_present_pages;
        ulong free_pages, zone_size, node_size, cum_zone_size;
	ulong zone_start_paddr, zone_start_mapnr, zone_mem_map;
	physaddr_t phys;
	ulong pp;
	ulong zone_start_pfn;
	ulong bdata;
	ulong pgdat;
	ulong node_zones;
	ulong value;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char buf5[BUFSIZE];
	struct node_table *nt;

	node = slen = 0;

	if (!(vt->flags & (NODES|NODES_ONLINE)) && initialize) {
		nt = &vt->node_table[0];
		nt->node_id = 0;
		if (symbol_exists("contig_page_data"))
			nt->pgdat = symbol_value("contig_page_data");
                else
			nt->pgdat = 0;
		nt->size = vt->total_pages;
		nt->mem_map = vt->mem_map;
		nt->start_paddr = 0;
		nt->start_mapnr = 0;
                if (CRASHDEBUG(1)) {
                        fprintf(fp, "node_table[%d]: \n", 0);
                        fprintf(fp, "             id: %d\n", nt->node_id);
                        fprintf(fp, "          pgdat: %lx\n", nt->pgdat);
                        fprintf(fp, "           size: %ld\n", nt->size);
                        fprintf(fp, "        present: %ld\n", nt->present);
                        fprintf(fp, "        mem_map: %lx\n", nt->mem_map);
                        fprintf(fp, "    start_paddr: %llx\n", nt->start_paddr);
                        fprintf(fp, "    start_mapnr: %ld\n", nt->start_mapnr);
                }
		return;
	}

	if (initialize) {
		pgdat = UNINITIALIZED;
		/*
		 *  This order may have to change based upon architecture...
		 */
		if (symbol_exists("pgdat_list") && 
		    (VALID_MEMBER(pglist_data_node_next) || 
		     VALID_MEMBER(pglist_data_pgdat_next))) {
                        get_symbol_data("pgdat_list", sizeof(void *), &pgdat);
			vt->flags &= ~NODES_ONLINE;
		} else if (vt->flags & NODES_ONLINE) {
			if ((node = next_online_node(0)) < 0) {
				error(WARNING, 
				   "cannot determine first node from node_online_map\n\n");
				return;
			} 
			if (!(pgdat = next_online_pgdat(node))) { 
				error(WARNING, 
				   "cannot determine pgdat list for this kernel/architecture\n\n");
				return;
			}
		} 
	} else
		pgdat = vt->node_table[0].pgdat;

	if (initialize && (pgdat == UNINITIALIZED)) {
		error(WARNING, "cannot initialize pgdat list\n\n");
		return;
	}

	for (n = 0, badaddr = FALSE; pgdat; n++) {
		if (n >= vt->numnodes)
			error(FATAL, "numnodes out of sync with pgdat_list?\n");

		nt = &vt->node_table[n];

		readmem(pgdat+OFFSET(pglist_data_node_id), KVADDR, &id,
			sizeof(int), "pglist node_id", FAULT_ON_ERROR);

		if (VALID_MEMBER(pglist_data_node_mem_map)) {
			readmem(pgdat+OFFSET(pglist_data_node_mem_map), KVADDR, 
				&node_mem_map, sizeof(ulong), 
				"node_mem_map", FAULT_ON_ERROR);
		} else {
			node_mem_map = BADADDR;
			badaddr = TRUE;
		}

		if (VALID_MEMBER(pglist_data_node_start_paddr)) {
			readmem(pgdat+OFFSET(pglist_data_node_start_paddr), 
				KVADDR, &temp_node_start_paddr, sizeof(ulong), 
				"pglist node_start_paddr", FAULT_ON_ERROR);
			node_start_paddr = temp_node_start_paddr;
		}
		else if (VALID_MEMBER(pglist_data_node_start_pfn)) {
			readmem(pgdat+OFFSET(pglist_data_node_start_pfn), 
				KVADDR, &node_start_pfn, sizeof(ulong), 
				"pglist node_start_pfn", FAULT_ON_ERROR);
				node_start_mapnr = node_start_pfn;
				node_start_paddr = PTOB(node_start_pfn);
			if (badaddr && IS_SPARSEMEM()) {
				if (!verify_pfn(node_start_pfn))
					error(WARNING, "questionable node_start_pfn: %lx\n",
						node_start_pfn);
				phys = PTOB(node_start_pfn);
                                if (phys_to_page(phys, &pp))
                                	node_mem_map = pp;
			}
		} else error(INFO, 
			"cannot determine zone starting physical address\n");

		if (VALID_MEMBER(pglist_data_node_start_mapnr))
			readmem(pgdat+OFFSET(pglist_data_node_start_mapnr), 
				KVADDR, &node_start_mapnr, sizeof(ulong), 
				"pglist node_start_mapnr", FAULT_ON_ERROR);

		if (VALID_MEMBER(pglist_data_node_size)) 
			readmem(pgdat+OFFSET(pglist_data_node_size), 
				KVADDR, &node_size, sizeof(ulong), 
				"pglist node_size", FAULT_ON_ERROR);
		else if (VALID_MEMBER(pglist_data_node_spanned_pages)) {
			readmem(pgdat+OFFSET(pglist_data_node_spanned_pages), 
				KVADDR, &node_spanned_pages, sizeof(ulong), 
				"pglist node_spanned_pages", FAULT_ON_ERROR);
			node_size = node_spanned_pages;
		} else error(INFO, "cannot determine zone size\n");

		if (VALID_MEMBER(pglist_data_node_present_pages))
                        readmem(pgdat+OFFSET(pglist_data_node_present_pages),
                                KVADDR, &node_present_pages, sizeof(ulong),
                                "pglist node_present_pages", FAULT_ON_ERROR);
		else
			node_present_pages = 0;

		if (VALID_MEMBER(pglist_data_bdata))
			readmem(pgdat+OFFSET(pglist_data_bdata), KVADDR, &bdata,
				sizeof(ulong), "pglist bdata", FAULT_ON_ERROR);
		else
			bdata = BADADDR;

		if (initialize) {
			nt->node_id = id;
			nt->pgdat = pgdat;
			if (VALID_MEMBER(zone_struct_memsize)) 
				nt->size = 0;  /* initialize below */
			else 
				nt->size = node_size;
			nt->present = node_present_pages;
			nt->mem_map = node_mem_map;
			nt->start_paddr = node_start_paddr;
			nt->start_mapnr = node_start_mapnr;

			if (CRASHDEBUG(1)) {
                		fprintf(fp, "node_table[%d]: \n", n);
                		fprintf(fp, "             id: %d\n", nt->node_id);
                		fprintf(fp, "          pgdat: %lx\n", nt->pgdat);
                		fprintf(fp, "           size: %ld\n", nt->size);
                		fprintf(fp, "        present: %ld\n", nt->present);
                		fprintf(fp, "        mem_map: %lx\n", nt->mem_map);
                		fprintf(fp, "    start_paddr: %llx\n", nt->start_paddr);
                		fprintf(fp, "    start_mapnr: %ld\n", nt->start_mapnr);
			}
		}

		if (!initialize) {
			if (n) {
				fprintf(fp, "\n");
				pad_line(fp, slen, '-');
			}
			flen = MAX(VADDR_PRLEN, strlen("BOOTMEM_DATA"));
			fprintf(fp, "%sNODE  %s  %s  %s  %s\n", 
			    n ? "\n\n" : "",
			    mkstring(buf1, 8, CENTER, "SIZE"),
			    mkstring(buf2, flen, CENTER|LJUST, "PGLIST_DATA"),
			    mkstring(buf3, flen, CENTER|LJUST, "BOOTMEM_DATA"),
			    mkstring(buf4, flen, CENTER|LJUST, "NODE_ZONES"));

			node_zones = pgdat + OFFSET(pglist_data_node_zones);
			sprintf(buf5, " %2d   %s  %s  %s  %s\n", id, 
			    mkstring(buf1, 8, CENTER|LJUST|LONG_DEC, 
				MKSTR(node_size)),
			    mkstring(buf2, flen, CENTER|LJUST|LONG_HEX, 
				MKSTR(pgdat)),
			    bdata == BADADDR ? 
			    mkstring(buf3, flen, CENTER, "----") :
			    mkstring(buf3, flen, CENTER|LONG_HEX, MKSTR(bdata)),
			    mkstring(buf4, flen, CENTER|LJUST|LONG_HEX,
                                MKSTR(node_zones)));
			fprintf(fp, "%s", buf5);

			j = 12 + strlen(buf1) + strlen(buf2) + strlen(buf3) +
				count_leading_spaces(buf4);
                	for (i = 1; i < vt->nr_zones; i++) {
				node_zones += SIZE_OPTION(zone_struct, zone);
				INDENT(j);
				fprintf(fp, "%lx\n", node_zones);
			}
	
			fprintf(fp, "%s     START_PADDR    START_MAPNR\n",
	                    mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, 
				"MEM_MAP"));
	                fprintf(fp, "%s  %s  %s\n",
	                    mkstring(buf1, VADDR_PRLEN,
	                        CENTER|LONG_HEX, MKSTR(node_mem_map)),
			    mkstring(buf2, strlen("   START_PADDR  "),
	                        CENTER|LONGLONG_HEX|RJUST, MKSTR(&node_start_paddr)),
	                    mkstring(buf3, strlen("START_MAPNR"),
	                        CENTER|LONG_DEC|RJUST, 
				    MKSTR(node_start_mapnr)));
	
			sprintf(buf2, "%s  %s  START_PADDR  START_MAPNR", 
				node_zone_hdr,
				mkstring(buf1, VADDR_PRLEN, CENTER|RJUST, 
				    "MEM_MAP"));
			slen = strlen(buf2);
			fprintf(fp, "\n%s\n", buf2);
		}

       		node_zones = pgdat + OFFSET(pglist_data_node_zones);
		cum_zone_size = 0;
		for (i = 0; i < vt->nr_zones; i++) {
			if (CRASHDEBUG(7))
				fprintf(fp, "zone %d at %lx\n", i, node_zones);

			if (VALID_MEMBER(zone_struct_size))
                		readmem(node_zones+OFFSET(zone_struct_size), 
				    	KVADDR, &zone_size, sizeof(ulong),
                        		"zone_struct size", FAULT_ON_ERROR);
			else if (VALID_MEMBER(zone_struct_memsize)) {
                		readmem(node_zones+OFFSET(zone_struct_memsize), 
				    	KVADDR, &zone_size, sizeof(ulong),
                        		"zone_struct memsize", FAULT_ON_ERROR);
				nt->size += zone_size;
			} else if (VALID_MEMBER(zone_spanned_pages)) {
                		readmem(node_zones+ OFFSET(zone_spanned_pages), 
				    	KVADDR, &zone_size, sizeof(ulong),
                        		"zone spanned_pages", FAULT_ON_ERROR);
			} else error(FATAL, 
			    "zone_struct has neither size nor memsize field\n");

                	readmem(node_zones+ 
				OFFSET_OPTION(zone_struct_free_pages,
				zone_free_pages), KVADDR, &free_pages, 
				sizeof(ulong), "zone[_struct] free_pages", 
				FAULT_ON_ERROR);
                	readmem(node_zones+OFFSET_OPTION(zone_struct_name,
				zone_name), KVADDR, &value, sizeof(void *),
                        	"zone[_struct] name", FAULT_ON_ERROR);
                	if (!read_string(value, buf1, BUFSIZE-1))
                        	sprintf(buf1, "(unknown) ");
			if (VALID_STRUCT(zone_struct)) {
				if (VALID_MEMBER(zone_struct_zone_start_paddr))
				{
                        		readmem(node_zones+OFFSET
					    (zone_struct_zone_start_paddr),
                                	    KVADDR, &zone_start_paddr, 
					    sizeof(ulong), 
					    "node_zones zone_start_paddr", 
					    FAULT_ON_ERROR);
				} else {
					readmem(node_zones+
					    OFFSET(zone_struct_zone_start_pfn),
					    KVADDR, &zone_start_pfn,
					    sizeof(ulong),
					    "node_zones zone_start_pfn",
					    FAULT_ON_ERROR);
					    zone_start_paddr = 
						PTOB(zone_start_pfn);
				}
                        	readmem(node_zones+
					OFFSET(zone_struct_zone_start_mapnr),
                                	KVADDR, &zone_start_mapnr, 
					sizeof(ulong), 
					"node_zones zone_start_mapnr", 
					FAULT_ON_ERROR);
			} else {
                                readmem(node_zones+
                                        OFFSET(zone_zone_start_pfn),
                                        KVADDR, &zone_start_pfn,
                                        sizeof(ulong),
                                        "node_zones zone_start_pfn",
                                        FAULT_ON_ERROR);
				zone_start_paddr = PTOB(zone_start_pfn);

				if (IS_SPARSEMEM()) {
					zone_mem_map = 0;
					zone_start_mapnr = 0;
					if (zone_size) {
						phys = PTOB(zone_start_pfn);
						zone_start_mapnr = phys/PAGESIZE();
					}

				} else if (!(vt->flags & NODES) && 
				    INVALID_MEMBER(zone_zone_mem_map)) {
					readmem(pgdat+OFFSET(pglist_data_node_mem_map),
                                    	    KVADDR, &zone_mem_map, sizeof(void *),
                                    	    "contig_page_data mem_map", FAULT_ON_ERROR);
					if (zone_size)
						zone_mem_map += cum_zone_size * SIZE(page);
				} else readmem(node_zones+
                                        OFFSET(zone_zone_mem_map),
                                        KVADDR, &zone_mem_map,
                                        sizeof(ulong),
                                        "node_zones zone_mem_map",
                                        FAULT_ON_ERROR);

				if (zone_mem_map)
					zone_start_mapnr = 
				    	    (zone_mem_map - node_mem_map) / 
					    SIZE(page);
				else if (!IS_SPARSEMEM())
					zone_start_mapnr = 0;
			}

			if (IS_SPARSEMEM()) {
				zone_mem_map = 0;
				if (zone_size) {
					phys = PTOB(zone_start_pfn);
					if (phys_to_page(phys, &pp))
						zone_mem_map = pp;
				}
			} else if (!(vt->flags & NODES) && 
			    INVALID_MEMBER(zone_struct_zone_mem_map) &&
			    INVALID_MEMBER(zone_zone_mem_map)) {
                		readmem(pgdat+OFFSET(pglist_data_node_mem_map),
				    KVADDR, &zone_mem_map, sizeof(void *), 
				    "contig_page_data mem_map", FAULT_ON_ERROR);
				if (zone_size)
					zone_mem_map += cum_zone_size * SIZE(page);
				else
					zone_mem_map = 0;
			} else 
				readmem(node_zones+
				    OFFSET_OPTION(zone_struct_zone_mem_map,
				    zone_zone_mem_map), KVADDR, &zone_mem_map, 
				    sizeof(ulong), "node_zones zone_mem_map", 
				    FAULT_ON_ERROR);

			if (!initialize) {
				fprintf(fp, " %2d   %-9s %7ld  ", 
					i, buf1, zone_size);
				cum_zone_size += zone_size;
				fprintf(fp, "%s  %s  %s\n",
	                    	    mkstring(buf1, VADDR_PRLEN,
	                        	RJUST|LONG_HEX,MKSTR(zone_mem_map)),
	                            mkstring(buf2, strlen("START_PADDR"),
	                        	LONG_HEX|RJUST,MKSTR(zone_start_paddr)),
	                    	    mkstring(buf3, strlen("START_MAPNR"),
	                        	LONG_DEC|RJUST,
					MKSTR(zone_start_mapnr)));
			}

			node_zones += SIZE_OPTION(zone_struct, zone);
		}

		if (initialize) {
			if (vt->flags & NODES_ONLINE) {
				if ((node = next_online_node(node+1)) < 0)
					pgdat = 0;
                        	else if (!(pgdat = next_online_pgdat(node))) {
                                	error(WARNING,
                   "cannot determine pgdat list for this kernel/architecture (node %d)\n\n", 
						node);
					pgdat = 0;
                        	}
			} else 
				readmem(pgdat + OFFSET_OPTION(pglist_data_node_next,
					pglist_data_pgdat_next), KVADDR,
					&pgdat, sizeof(void *), "pglist_data node_next",
					FAULT_ON_ERROR);
		} else {
			if ((n+1) < vt->numnodes)
				pgdat = vt->node_table[n+1].pgdat;
			else
				pgdat = 0;
		}
	} 

	if (n != vt->numnodes) {
		if (CRASHDEBUG(2))
			error(NOTE, "changing numnodes from %d to %d\n",
				vt->numnodes, n);
		vt->numnodes = n;
	}

	if (IS_SPARSEMEM()) {
		dump_mem_sections(initialize);
		dump_memory_blocks(initialize);
	}
}

/*
 *  At least verify that page-shifted physical address.
 */
static int
verify_pfn(ulong pfn)
{
	int i;
	physaddr_t mask;

	if (!machdep->max_physmem_bits)
		return TRUE;
	
	mask = 0;
	for (i = machdep->max_physmem_bits; i < machdep->bits; i++)
		mask |= ((physaddr_t)1 << i);
		
	if (mask & PTOB(pfn))
		return FALSE;

	return TRUE;
}

static void
dump_zone_stats(void)
{
	int i, n;
	ulong pgdat, node_zones;
	char *zonebuf;
	char buf1[BUFSIZE];
	int ivalue;
	ulong value1;
	ulong value2;
	ulong value3;
	ulong value4;
	ulong value5;
	ulong value6;
	long min, low, high;

	value1 = value2 = value3 = value4 = value5 = value6 = 0;
	min = low = high = 0;
	pgdat = vt->node_table[0].pgdat;
	zonebuf = GETBUF(SIZE_OPTION(zone_struct, zone));
	vm_stat_init();

        for (n = 0; pgdat; n++) {
                node_zones = pgdat + OFFSET(pglist_data_node_zones);

                for (i = 0; i < vt->nr_zones; i++) {

			if (!readmem(node_zones, KVADDR, zonebuf,
			    SIZE_OPTION(zone_struct, zone),
			    "zone buffer", FAULT_ON_ERROR))
				break; 

			value1 = ULONG(zonebuf + 
				OFFSET_OPTION(zone_struct_name, zone_name));

                        if (!read_string(value1, buf1, BUFSIZE-1))
                                sprintf(buf1, "(unknown) ");

			if (VALID_MEMBER(zone_struct_size))
				value1 = value6 = ULONG(zonebuf + 
					OFFSET(zone_struct_size));
			else if (VALID_MEMBER(zone_struct_memsize)) {
				value1 = value6 = ULONG(zonebuf + 
					OFFSET(zone_struct_memsize));
			} else if (VALID_MEMBER(zone_spanned_pages)) {
				value1 = ULONG(zonebuf + 
					OFFSET(zone_spanned_pages));
				value6 = ULONG(zonebuf + 
					OFFSET(zone_present_pages));
			} else error(FATAL, 
			    	"zone struct has unknown size field\n");

			if (VALID_MEMBER(zone_watermark)) {
				if (!enumerator_value("WMARK_MIN", &min) ||
				    !enumerator_value("WMARK_LOW", &low) ||
				    !enumerator_value("WMARK_HIGH", &high)) {
					min = 0;
					low = 1;
					high = 2;
				}
				value2 = ULONG(zonebuf + OFFSET(zone_watermark) +
					(sizeof(long) * min));
				value3 = ULONG(zonebuf + OFFSET(zone_watermark) +
					(sizeof(long) * low));
				value4 = ULONG(zonebuf + OFFSET(zone_watermark) +
					(sizeof(long) * high));
			} else {
				value2 = ULONG(zonebuf + OFFSET_OPTION(zone_pages_min,
					zone_struct_pages_min));
				value3 = ULONG(zonebuf + OFFSET_OPTION(zone_pages_low,
					zone_struct_pages_low));
				value4 = ULONG(zonebuf + OFFSET_OPTION(zone_pages_high,
					zone_struct_pages_high));
			}
			value5 = ULONG(zonebuf + OFFSET_OPTION(zone_free_pages,
				zone_struct_free_pages));

			fprintf(fp, 
			    "NODE: %d  ZONE: %d  ADDR: %lx  NAME: \"%s\"\n", 
				n, i, node_zones, buf1);

			if (!value1) {
				fprintf(fp, "  [unpopulated]\n");
				goto next_zone;
			}
			fprintf(fp, "  SIZE: %ld", value1);
			if (value6 < value1) 
				fprintf(fp, "  PRESENT: %ld", value6);
			fprintf(fp, "  MIN/LOW/HIGH: %ld/%ld/%ld",
				value2, value3, value4);

			if (VALID_MEMBER(zone_vm_stat)) 
			    	dump_vm_stat("NR_FREE_PAGES", (long *)&value5, 
			    		node_zones + OFFSET(zone_vm_stat));

			if (VALID_MEMBER(zone_nr_active) && 
			    VALID_MEMBER(zone_nr_inactive)) {
				value1 = ULONG(zonebuf + 
					OFFSET(zone_nr_active));
				value2 = ULONG(zonebuf + 
					OFFSET(zone_nr_inactive));
				fprintf(fp, 
			    "\n  NR_ACTIVE: %ld  NR_INACTIVE: %ld  FREE: %ld\n",
					value1, value2, value5); 
				if (VALID_MEMBER(zone_vm_stat)) {
					fprintf(fp, "  VM_STAT:\n");
					dump_vm_stat(NULL, NULL, node_zones +
						OFFSET(zone_vm_stat));
				}
			} else if (VALID_MEMBER(zone_vm_stat) &&
				dump_vm_stat("NR_ACTIVE", (long *)&value1, 
				node_zones + OFFSET(zone_vm_stat)) &&
				dump_vm_stat("NR_INACTIVE", (long *)&value2, 
				node_zones + OFFSET(zone_vm_stat))) {
				fprintf(fp, "\n  VM_STAT:\n");
				dump_vm_stat(NULL, NULL, node_zones + 
					OFFSET(zone_vm_stat));
			} else {
				if (VALID_MEMBER(zone_vm_stat)) {
					fprintf(fp, "\n  VM_STAT:\n");
					dump_vm_stat(NULL, NULL, node_zones + 
						OFFSET(zone_vm_stat));
				} else
					fprintf(fp, "  FREE: %ld\n", value5); 
			}

			if (VALID_MEMBER(zone_all_unreclaimable)) {
				ivalue = UINT(zonebuf + 
					OFFSET(zone_all_unreclaimable));
				fprintf(fp, "  ALL_UNRECLAIMABLE: %s  ", 
					ivalue ? "yes" : "no");
			} else if (VALID_MEMBER(zone_flags) &&
				enumerator_value("ZONE_ALL_UNRECLAIMABLE", 
				(long *)&value1)) {
				value2 = ULONG(zonebuf + OFFSET(zone_flags));
				value3 = value2 & (1 << value1);
				fprintf(fp, "  ALL_UNRECLAIMABLE: %s  ", 
					value3 ? "yes" : "no");
			}

			if (VALID_MEMBER(zone_pages_scanned)) {
				value1 = ULONG(zonebuf + 
					OFFSET(zone_pages_scanned));
				fprintf(fp, "PAGES_SCANNED: %lu  ", value1);
			} 
			fprintf(fp, "\n");

next_zone:
			fprintf(fp, "\n");
			node_zones += SIZE_OPTION(zone_struct, zone);
		}

		if ((n+1) < vt->numnodes)
			pgdat = vt->node_table[n+1].pgdat;
		else
			pgdat = 0;
	}

	FREEBUF(zonebuf);

}

/*
 *  Gather essential information regarding each memory node.
 */
static void
node_table_init(void)
{
	int n;
	ulong pgdat;

	/*
	 *  Override numnodes -- some kernels may leave it at 1 on a system
	 *  with multiple memory nodes.
	 */
	if ((vt->flags & NODES) && (VALID_MEMBER(pglist_data_node_next) || 
	    VALID_MEMBER(pglist_data_pgdat_next))) {

	        get_symbol_data("pgdat_list", sizeof(void *), &pgdat);
	
	        for (n = 0; pgdat; n++) {
	                readmem(pgdat + OFFSET_OPTION(pglist_data_node_next,
	                        pglist_data_pgdat_next), KVADDR,
	                        &pgdat, sizeof(void *), "pglist_data node_next",
	                        FAULT_ON_ERROR);
		}
		if (n != vt->numnodes) {
			if (CRASHDEBUG(2))
				error(NOTE, "changing numnodes from %d to %d\n",
					vt->numnodes, n);
			vt->numnodes = n;
		}
	} else
		vt->flags &= ~NODES;

       	if (!(vt->node_table = (struct node_table *)
	    malloc(sizeof(struct node_table) * vt->numnodes)))
		error(FATAL, "cannot malloc node_table %s(%d nodes)",
			vt->numnodes > 1 ? "array " : "", vt->numnodes);

	BZERO(vt->node_table, sizeof(struct node_table) * vt->numnodes);

	dump_memory_nodes(MEMORY_NODES_INITIALIZE);

        qsort((void *)vt->node_table, (size_t)vt->numnodes,
                sizeof(struct node_table), compare_node_data);

	if (CRASHDEBUG(2))
		dump_memory_nodes(MEMORY_NODES_DUMP);
}

/*
 *  The comparison function must return an integer less  than,
 *  equal  to,  or  greater than zero if the first argument is
 *  considered to be respectively  less  than,  equal  to,  or
 *  greater than the second.  If two members compare as equal,
 *  their order in the sorted array is undefined.
 */

static int
compare_node_data(const void *v1, const void *v2)
{
        struct node_table *t1, *t2;

        t1 = (struct node_table *)v1;
        t2 = (struct node_table *)v2;

        return (t1->node_id < t2->node_id ? -1 :
                t1->node_id == t2->node_id ? 0 : 1);
}


/*
 *  Depending upon the processor, and whether we're running live or on a 
 *  dumpfile, get the system page size.
 */
uint
memory_page_size(void)
{
	uint psz;

	if (machdep->pagesize)
		return machdep->pagesize;

	if (REMOTE_MEMSRC())
		return remote_page_size();

	switch (pc->flags & MEMORY_SOURCES)
	{
	case DISKDUMP:
		psz = diskdump_page_size();
		break;

        case XENDUMP:
                psz = xendump_page_size();
                break;

	case KDUMP:
		psz = kdump_page_size();
		break;

	case NETDUMP:
		psz = netdump_page_size();
		break;

	case MCLXCD:
		psz = (uint)mclx_page_size();
		break;

	case LKCD:
#if 0							/* REMIND: */
		psz = lkcd_page_size();			/* dh_dump_page_size is HW page size; should add dh_page_size */
#else
		psz = (uint)getpagesize();
#endif
		break;

	case DEVMEM:                      
	case MEMMOD:
	case CRASHBUILTIN:
	case KVMDUMP:
	case PROC_KCORE:
	case LIVE_RAMDUMP:
		psz = (uint)getpagesize();  
		break;

	case S390D:
		psz = s390_page_size();
		break;

	case SADUMP:
		psz = sadump_page_size();
		break;

	case VMWARE_VMSS:
		psz = vmware_vmss_page_size();
		break;

	default:
		psz = 0;
		error(FATAL, "memory_page_size: invalid pc->flags: %lx\n", 
			pc->flags & MEMORY_SOURCES); 
	}

	return psz;
}

/*
 *  If the page size cannot be determined by the dumpfile (like kdump),
 *  and the processor default cannot be used, allow the force-feeding
 *  of a crash command-line page size option.
 */
void
force_page_size(char *s)
{
	int k, err;
	ulong psize;

	k = 1;
	err = FALSE;
	psize = 0;

	switch (LASTCHAR(s))
	{
	case 'k':
	case 'K':
		LASTCHAR(s) = NULLCHAR;
		if (!decimal(s, 0)) {
			err = TRUE;
			break;
		}
		k = 1024;

		/* FALLTHROUGH */

	default:
        	if (decimal(s, 0))
                	psize = dtol(s, QUIET|RETURN_ON_ERROR, &err);
        	else if (hexadecimal(s, 0))
                	psize = htol(s, QUIET|RETURN_ON_ERROR, &err);
		else
			err = TRUE;
		break;
	}

	if (err) 
		error(INFO, "invalid page size: %s\n", s);
	else
		machdep->pagesize = psize * k;
}


/*
 *  Return the vmalloc address referenced by the first vm_struct
 *  on the vmlist.  This can normally be used by the machine-specific
 *  xxx_vmalloc_start() routines.
 */

ulong
first_vmalloc_address(void)
{
	static ulong vmalloc_start = 0;
        ulong vm_struct, vmap_area;

	if (DUMPFILE() && vmalloc_start)
		return vmalloc_start;

	if (vt->flags & USE_VMAP_AREA) {
		get_symbol_data("vmap_area_list", sizeof(void *), &vmap_area);
		if (!vmap_area)
			return 0;
		if (!readmem(vmap_area - OFFSET(vmap_area_list) +
		    OFFSET(vmap_area_va_start), KVADDR, &vmalloc_start, 
		    sizeof(void *), "first vmap_area va_start", RETURN_ON_ERROR)) 
			non_matching_kernel();

	} else if (kernel_symbol_exists("vmlist")) {
		get_symbol_data("vmlist", sizeof(void *), &vm_struct);
		if (!vm_struct)
			return 0;
		if (!readmem(vm_struct+OFFSET(vm_struct_addr), KVADDR, 
		    &vmalloc_start, sizeof(void *), 
		    "first vmlist addr", RETURN_ON_ERROR)) 
			non_matching_kernel();
	} 

	return vmalloc_start;
}

/*
 *  Return the highest vmalloc address in the vmlist.
 */
ulong
last_vmalloc_address(void)
{
	struct meminfo meminfo;
	static ulong vmalloc_limit = 0;

	if (!vmalloc_limit || ACTIVE()) {
		BZERO(&meminfo, sizeof(struct meminfo));
		meminfo.memtype = KVADDR;
		meminfo.spec_addr = 0;
		meminfo.flags = (ADDRESS_SPECIFIED|GET_HIGHEST);
		dump_vmlist(&meminfo);
		vmalloc_limit = meminfo.retval;
	}

	return vmalloc_limit;
}
/*
 *  Determine whether an identity-mapped virtual address
 *  refers to an existant physical page, and if not bump
 *  it up to the next node.
 */
static int
next_identity_mapping(ulong vaddr, ulong *nextvaddr)
{
	int n, retval;
        struct node_table *nt;
        ulonglong paddr, pstart, psave, pend;
	ulong node_size;

	paddr = VTOP(vaddr);
	psave = 0;
	retval = FALSE;

        for (n = 0; n < vt->numnodes; n++) {
                nt = &vt->node_table[n];
                if ((vt->flags & V_MEM_MAP) && (vt->numnodes == 1))
                        node_size = vt->max_mapnr;
                else
	                node_size = nt->size;

                pstart = nt->start_paddr;
                pend = pstart + ((ulonglong)node_size * PAGESIZE());

		/*
		 *  Check the next node.
		 */
                if (paddr >= pend)
			continue;
		/*
		 *  Bump up to the next node, but keep looking in
		 *  case of non-sequential nodes.
		 */
                if (paddr < pstart) {
			if (psave && (psave < pstart))
				continue;
			*nextvaddr = PTOV(pstart);
			psave = pstart;
			retval = TRUE;
			continue;
		}
                /*
                 *  We're in the physical range.
                 */
		*nextvaddr = vaddr;
                retval = TRUE;
		break;
        }

	return retval;
}


/*
 *  Return the L1 cache size in bytes, which can be found stored in the
 *  cache_cache.
 */

int
l1_cache_size(void)
{
	ulong cache;
	ulong c_align;
	int colour_off;
	int retval;

	retval = -1;

	if (VALID_MEMBER(kmem_cache_s_c_align)) {
        	cache = symbol_value("cache_cache");
                readmem(cache+OFFSET(kmem_cache_s_c_align),
                	KVADDR, &c_align, sizeof(ulong),
                        "c_align", FAULT_ON_ERROR);
		retval = (int)c_align;
	} else if (VALID_MEMBER(kmem_cache_s_colour_off)) {
        	cache = symbol_value("cache_cache");
                readmem(cache+OFFSET(kmem_cache_s_colour_off),
                	KVADDR, &colour_off, sizeof(int),
                        "colour_off", FAULT_ON_ERROR);
		retval = colour_off;
	}

	return retval;
}

/*
 *  Multi-purpose routine used to query/control dumpfile memory usage.
 */
int
dumpfile_memory(int cmd)
{
	int retval;

	retval = 0;

	switch (cmd)
	{
	case DUMPFILE_MEM_USED:
                if (REMOTE_DUMPFILE()) 
                        retval = remote_memory_used();
		else if (pc->flags & NETDUMP)
        		retval = netdump_memory_used();
		else if (pc->flags & KDUMP)
        		retval = kdump_memory_used();
		else if (pc->flags & XENDUMP)
        		retval = xendump_memory_used();
		else if (pc->flags & KVMDUMP)
			retval = kvmdump_memory_used();
		else if (pc->flags & DISKDUMP)
        		retval = diskdump_memory_used();
		else if (pc->flags & LKCD)
        		retval = lkcd_memory_used();
		else if (pc->flags & MCLXCD)
                        retval = vas_memory_used();
		else if (pc->flags & S390D)
			retval = s390_memory_used();
		else if (pc->flags & SADUMP)
			retval = sadump_memory_used();
		break;

	case DUMPFILE_FREE_MEM:
                if (REMOTE_DUMPFILE())
                        retval = remote_free_memory();
                else if (pc->flags & NETDUMP)
			retval = netdump_free_memory();
                else if (pc->flags & KDUMP)
			retval = kdump_free_memory();
                else if (pc->flags & XENDUMP)
			retval = xendump_free_memory();
                else if (pc->flags & KVMDUMP)
			retval = kvmdump_free_memory();
                else if (pc->flags & DISKDUMP)
			retval = diskdump_free_memory();
                else if (pc->flags & LKCD)
                        retval = lkcd_free_memory();
                else if (pc->flags & MCLXCD)
                        retval = vas_free_memory(NULL);
                else if (pc->flags & S390D)
                        retval = s390_free_memory();
		else if (pc->flags & SADUMP)
			retval = sadump_free_memory();
		break;

	case DUMPFILE_MEM_DUMP:
		if (REMOTE_DUMPFILE())
                        retval = remote_memory_dump(0);
                else if (pc->flags & NETDUMP) 
                        retval = netdump_memory_dump(fp);
                else if (pc->flags & KDUMP) 
                        retval = kdump_memory_dump(fp);
                else if (pc->flags & XENDUMP) 
                        retval = xendump_memory_dump(fp);
                else if (pc->flags & KVMDUMP) 
                        retval = kvmdump_memory_dump(fp);
                else if (pc->flags & DISKDUMP) 
                        retval = diskdump_memory_dump(fp);
                else if (pc->flags & LKCD) 
                        retval = lkcd_memory_dump(set_lkcd_fp(fp));
                else if (pc->flags & MCLXCD)
                        retval = vas_memory_dump(fp);
                else if (pc->flags & S390D)
                        retval = s390_memory_dump(fp);
                else if (pc->flags & PROC_KCORE)
                        retval = kcore_memory_dump(fp);
		else if (pc->flags & SADUMP)
			retval = sadump_memory_dump(fp);
		else if (pc->flags & VMWARE_VMSS) {
			if (pc->flags2 & VMWARE_VMSS_GUESTDUMP)
				retval = vmware_guestdump_memory_dump(fp);
			else
				retval = vmware_vmss_memory_dump(fp);
		}
		break;
	
	case DUMPFILE_ENVIRONMENT:
                if (pc->flags & LKCD) {
                        set_lkcd_fp(fp);
                        dump_lkcd_environment(0);
		} else if (pc->flags & REM_LKCD) 
                        retval = remote_memory_dump(VERBOSE);
		break;
	}

	return retval;
}

/* 
 *  Functions for sparse mem support 
 */
ulong 
sparse_decode_mem_map(ulong coded_mem_map, ulong section_nr)
{
        return coded_mem_map + 
	    (section_nr_to_pfn(section_nr) * SIZE(page));
}

void
sparse_mem_init(void)
{
	ulong addr;
	ulong mem_section_size;
	int len, dimension, mem_section_is_ptr;

	if (!IS_SPARSEMEM())
		return;

	MEMBER_OFFSET_INIT(mem_section_section_mem_map, "mem_section",
		"section_mem_map");

	if (!MAX_PHYSMEM_BITS())
		error(FATAL, 
		    "CONFIG_SPARSEMEM kernels not supported for this architecture\n");

	/*
	 *  The kernel's mem_section changed from array to pointer in this commit:
	 *
	 *   commit 83e3c48729d9ebb7af5a31a504f3fd6aff0348c4
	 *   mm/sparsemem: Allocate mem_section at runtime for CONFIG_SPARSEMEM_EXTREME=y
	 */
	mem_section_is_ptr = 
		get_symbol_type("mem_section", NULL, NULL) == TYPE_CODE_PTR ? 
			TRUE : FALSE;

	if (((len = get_array_length("mem_section", &dimension, 0)) ==
	    (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT_EXTREME())) || 
	    mem_section_is_ptr || !dimension)
		vt->flags |= SPARSEMEM_EX;

	if (IS_SPARSEMEM_EX()) {
		machdep->sections_per_root = _SECTIONS_PER_ROOT_EXTREME();
		mem_section_size = sizeof(void *) * NR_SECTION_ROOTS();
	} else {
		machdep->sections_per_root = _SECTIONS_PER_ROOT();
		mem_section_size = SIZE(mem_section) * NR_SECTION_ROOTS();
	}

	if (CRASHDEBUG(1)) {
		fprintf(fp, "PAGESIZE=%d\n",PAGESIZE());
		fprintf(fp,"mem_section_size = %ld\n", mem_section_size);
		fprintf(fp, "NR_SECTION_ROOTS = %ld\n", NR_SECTION_ROOTS());
		fprintf(fp, "NR_MEM_SECTIONS = %ld\n", NR_MEM_SECTIONS());
		fprintf(fp, "SECTIONS_PER_ROOT = %ld\n", SECTIONS_PER_ROOT() );
		fprintf(fp, "SECTION_ROOT_MASK = 0x%lx\n", SECTION_ROOT_MASK());
		fprintf(fp, "PAGES_PER_SECTION = %ld\n", PAGES_PER_SECTION());
		if (!mem_section_is_ptr && IS_SPARSEMEM_EX() && !len)
			error(WARNING, "SPARSEMEM_EX: questionable section values\n");
	}

	if (!(vt->mem_sec = (void *)malloc(mem_section_size)))
		error(FATAL, "cannot malloc mem_sec cache\n");
	if (!(vt->mem_section = (char *)malloc(SIZE(mem_section))))
		error(FATAL, "cannot malloc mem_section cache\n");

	if (mem_section_is_ptr)
		get_symbol_data("mem_section", sizeof(void *), &addr);
	else
		addr = symbol_value("mem_section");

	readmem(addr, KVADDR, vt->mem_sec, mem_section_size,
		"memory section root table", FAULT_ON_ERROR);
}

char *
read_mem_section(ulong addr)
{
	if ((addr == 0) || !IS_KVADDR(addr))
		return 0;
	
	readmem(addr, KVADDR, vt->mem_section, SIZE(mem_section),
		"memory section", FAULT_ON_ERROR);

	return vt->mem_section;
}

ulong
nr_to_section(ulong nr)
{
	ulong addr;
	ulong *mem_sec = vt->mem_sec;

	if (IS_SPARSEMEM_EX()) {
		if (SECTION_NR_TO_ROOT(nr) >= NR_SECTION_ROOTS()) {
			if (!STREQ(pc->curcmd, "rd") && 
			    !STREQ(pc->curcmd, "search") &&
			    !STREQ(pc->curcmd, "kmem"))
				error(WARNING, 
			   	    "sparsemem: invalid section number: %ld\n",
					 nr);
			return 0;
		}
	}

	if (IS_SPARSEMEM_EX()) {
		if ((mem_sec[SECTION_NR_TO_ROOT(nr)] == 0) || 
	    	    !IS_KVADDR(mem_sec[SECTION_NR_TO_ROOT(nr)]))
			return 0;
		addr = mem_sec[SECTION_NR_TO_ROOT(nr)] + 
		    (nr & SECTION_ROOT_MASK()) * SIZE(mem_section);
	} else
		addr = symbol_value("mem_section") +
		    (SECTIONS_PER_ROOT() * SECTION_NR_TO_ROOT(nr) +
			(nr & SECTION_ROOT_MASK())) * SIZE(mem_section);

	if (!IS_KVADDR(addr))
		return 0;

	return addr;
}

/*
 * We use the lower bits of the mem_map pointer to store
 * a little bit of information.  The pointer is calculated
 * as mem_map - section_nr_to_pfn(pnum).  The result is
 * aligned to the minimum alignment of the two values:
 *   1. All mem_map arrays are page-aligned.
 *   2. section_nr_to_pfn() always clears PFN_SECTION_SHIFT
 *      lowest bits.  PFN_SECTION_SHIFT is arch-specific
 *      (equal SECTION_SIZE_BITS - PAGE_SHIFT), and the
 *      worst combination is powerpc with 256k pages,
 *      which results in PFN_SECTION_SHIFT equal 6.
 * To sum it up, at least 6 bits are available.
 */
#define SECTION_MARKED_PRESENT		(1UL<<0)
#define SECTION_HAS_MEM_MAP		(1UL<<1)
#define SECTION_IS_ONLINE		(1UL<<2)
#define SECTION_IS_EARLY		(1UL<<3)
#define SECTION_TAINT_ZONE_DEVICE	(1UL<<4)
#define SECTION_MAP_LAST_BIT		(1UL<<5)
#define SECTION_MAP_MASK		(~(SECTION_MAP_LAST_BIT-1))


int 
valid_section(ulong addr)
{
	char *mem_section;

	if ((mem_section = read_mem_section(addr)))
        	return (ULONG(mem_section + 
			OFFSET(mem_section_section_mem_map))
			& SECTION_MARKED_PRESENT);
	return 0;
}

int 
section_has_mem_map(ulong addr)
{
	char *mem_section;
	ulong kernel_version_bit;

	if (THIS_KERNEL_VERSION >= LINUX(2,6,24))
		kernel_version_bit = SECTION_HAS_MEM_MAP;
	else
		kernel_version_bit = SECTION_MARKED_PRESENT;

	if ((mem_section = read_mem_section(addr)))
		return (ULONG(mem_section + 
			OFFSET(mem_section_section_mem_map))
			& kernel_version_bit);
	return 0;
}

ulong 
section_mem_map_addr(ulong addr, int raw)
{   
	char *mem_section;
	ulong map;

	if ((mem_section = read_mem_section(addr))) {
		map = ULONG(mem_section + 
			OFFSET(mem_section_section_mem_map));
		if (!raw)
			map &= SECTION_MAP_MASK;
		return map;
	}
	return 0;
}


ulong 
valid_section_nr(ulong nr)
{
	ulong addr = nr_to_section(nr);

	if (valid_section(addr))
		return addr;

	return 0;
}

ulong 
pfn_to_map(ulong pfn)
{
	ulong section, page_offset;
	ulong section_nr;
	ulong coded_mem_map, mem_map;

	section_nr = pfn_to_section_nr(pfn);
	if (!(section = valid_section_nr(section_nr))) 
		return 0;

	if (section_has_mem_map(section)) {
		page_offset = pfn - section_nr_to_pfn(section_nr);
		coded_mem_map = section_mem_map_addr(section, 0);
		mem_map = sparse_decode_mem_map(coded_mem_map, section_nr) +
			(page_offset * SIZE(page));
		return mem_map;
	}

	return 0;
}

static void
fill_mem_section_state(ulong state, char *buf)
{
	int bufidx = 0;

	memset(buf, 0, sizeof(*buf) * BUFSIZE);

	if (state & SECTION_MARKED_PRESENT)
		bufidx += sprintf(buf + bufidx, "%s", "P");
	if (state & SECTION_HAS_MEM_MAP)
		bufidx += sprintf(buf + bufidx, "%s", "M");
	if (state & SECTION_IS_ONLINE)
		bufidx += sprintf(buf + bufidx, "%s", "O");
	if (state & SECTION_IS_EARLY)
		bufidx += sprintf(buf + bufidx, "%s", "E");
	if (state & SECTION_TAINT_ZONE_DEVICE)
		bufidx += sprintf(buf + bufidx, "%s", "D");
}

void 
dump_mem_sections(int initialize)
{
	ulong nr, max, addr;
	ulong nr_mem_sections;
	ulong coded_mem_map, mem_map, pfn;
	char statebuf[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char buf5[BUFSIZE];

	nr_mem_sections = NR_MEM_SECTIONS();

	if (initialize) {
		for (nr = max = 0; nr < nr_mem_sections ; nr++) {
			if (valid_section_nr(nr))
				max = nr;
		}
		vt->max_mem_section_nr = max;
		return;
	}

	fprintf(fp, "\n");
	pad_line(fp, BITS32() ? 59 : 67, '-');
	fprintf(fp, "\n\nNR  %s  %s  %s  %s PFN\n",
                mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "SECTION"),
                mkstring(buf2, MAX(VADDR_PRLEN,strlen("CODED_MEM_MAP")), 
		CENTER|LJUST, "CODED_MEM_MAP"),
		mkstring(buf3, VADDR_PRLEN, CENTER|LJUST, "MEM_MAP"),
		mkstring(buf4, strlen("STATE"), CENTER, "STATE"));

	for (nr = 0; nr < nr_mem_sections ; nr++) {
		if ((addr = valid_section_nr(nr))) {
			coded_mem_map = section_mem_map_addr(addr, 0);
			mem_map = sparse_decode_mem_map(coded_mem_map,nr);
			pfn = section_nr_to_pfn(nr);
			fill_mem_section_state(section_mem_map_addr(addr, 1),
						statebuf);


			fprintf(fp, "%2ld  %s  %s  %s  %s %s\n",
                		nr,
                		mkstring(buf1, VADDR_PRLEN,
                        	CENTER|LONG_HEX, MKSTR(addr)),
                		mkstring(buf2, MAX(VADDR_PRLEN,
				strlen("CODED_MEM_MAP")),
                        	CENTER|LONG_HEX|RJUST, MKSTR(coded_mem_map)),
                		mkstring(buf3, VADDR_PRLEN,
                        	CENTER|LONG_HEX|RJUST, MKSTR(mem_map)),
				mkstring(buf4, strlen("STATE"), CENTER, statebuf),
				pc->output_radix == 10 ?
				mkstring(buf5, VADDR_PRLEN,
                        	LONG_DEC|LJUST, MKSTR(pfn)) :
				mkstring(buf5, VADDR_PRLEN,
                        	LONG_HEX|LJUST, MKSTR(pfn)));
		}
	}
}

#define MEM_ONLINE		(1<<0)
#define MEM_GOING_OFFLINE	(1<<1)
#define MEM_OFFLINE		(1<<2)
#define MEM_GOING_ONLINE	(1<<3)
#define MEM_CANCEL_ONLINE	(1<<4)
#define MEM_CANCEL_OFFLINE	(1<<5)

static void
fill_memory_block_state(ulong memblock, char *buf)
{
	ulong state;

	memset(buf, 0, sizeof(*buf) * BUFSIZE);

	readmem(memblock + OFFSET(memory_block_state), KVADDR, &state,
		sizeof(void *), "memory_block state", FAULT_ON_ERROR);

	switch (state) {
	case MEM_ONLINE:
		sprintf(buf, "%s", "ONLINE");
		break;
	case MEM_GOING_OFFLINE:
		sprintf(buf, "%s", "GOING_OFFLINE");
		break;
	case MEM_OFFLINE:
		sprintf(buf, "%s", "OFFLINE");
		break;
	case MEM_GOING_ONLINE:
		sprintf(buf, "%s", "GOING_ONLINE");
		break;
	case MEM_CANCEL_ONLINE:
		sprintf(buf, "%s", "CANCEL_ONLINE");
		break;
	case MEM_CANCEL_OFFLINE:
		sprintf(buf, "%s",  "CANCEL_OFFLINE");
		break;
	default:
		sprintf(buf, "%s", "UNKNOWN");
	}
}

static ulong
pfn_to_phys(ulong pfn)
{
	return pfn << PAGESHIFT();
}

static void
fill_memory_block_name(ulong memblock, char *name)
{
	ulong kobj, value;

	memset(name, 0, sizeof(*name) * BUFSIZE);

	kobj = memblock + OFFSET(memory_block_dev) + OFFSET(device_kobj);

	readmem(kobj + OFFSET(kobject_name),
		KVADDR, &value, sizeof(void *), "kobject name",
		FAULT_ON_ERROR);

	read_string(value, name, BUFSIZE-1);
}

static void
fill_memory_block_parange(ulong saddr, ulong eaddr, char *parange)
{
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];

	memset(parange, 0, sizeof(*parange) * BUFSIZE);

	if (eaddr == ULLONG_MAX)
		sprintf(parange, "%s",
			mkstring(buf1, PADDR_PRLEN*2 + 3, CENTER|LONG_HEX, MKSTR(saddr)));
	else
		sprintf(parange, "%s - %s",
			mkstring(buf1, PADDR_PRLEN, RJUST|LONG_HEX, MKSTR(saddr)),
			mkstring(buf2, PADDR_PRLEN, RJUST|LONG_HEX, MKSTR(eaddr)));
}

static void
fill_memory_block_srange(ulong start_sec, char *srange)
{
	memset(srange, 0, sizeof(*srange) * BUFSIZE);

	sprintf(srange, "%lu", start_sec);
}

static void
print_memory_block(ulong memory_block)
{
	ulong start_sec, end_sec, nid;
	ulong memblock_size, mbs, start_addr, end_addr = (ulong)ULLONG_MAX;
	char statebuf[BUFSIZE];
	char srangebuf[BUFSIZE];
	char parangebuf[BUFSIZE];
	char name[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf5[BUFSIZE];
	char buf6[BUFSIZE];
	char buf7[BUFSIZE];

	readmem(memory_block + OFFSET(memory_block_start_section_nr), KVADDR,
		&start_sec, sizeof(void *), "memory_block start_section_nr",
		FAULT_ON_ERROR);

	start_addr = pfn_to_phys(section_nr_to_pfn(start_sec));

	if (symbol_exists("memory_block_size_probed")) {
		memblock_size = symbol_value("memory_block_size_probed");
		readmem(memblock_size, KVADDR,
			&mbs, sizeof(ulong), "memory_block_size_probed",
			FAULT_ON_ERROR);
		end_addr = start_addr + mbs - 1;
	} else if (MEMBER_EXISTS("memory_block", "end_section_nr")) {
	        readmem(memory_block + OFFSET(memory_block_end_section_nr), KVADDR,
			&end_sec, sizeof(void *), "memory_block end_section_nr",
			FAULT_ON_ERROR);
		end_addr = pfn_to_phys(section_nr_to_pfn(end_sec + 1)) - 1;
	}

	fill_memory_block_state(memory_block, statebuf);
	fill_memory_block_name(memory_block, name);
	fill_memory_block_parange(start_addr, end_addr, parangebuf);
	fill_memory_block_srange(start_sec, srangebuf);

	if (MEMBER_EXISTS("memory_block", "nid")) {
		readmem(memory_block + OFFSET(memory_block_nid), KVADDR, &nid,
			sizeof(int), "memory_block nid", FAULT_ON_ERROR);
		fprintf(fp, " %s %s %s %s  %s %s\n",
			mkstring(buf1, VADDR_PRLEN, LJUST|LONG_HEX,
			MKSTR(memory_block)),
			mkstring(buf2, 12, CENTER, name),
			parangebuf,
			mkstring(buf5, strlen("NODE"), CENTER|INT_DEC,
			MKSTR(nid)),
			mkstring(buf6, strlen("OFFLINE"), LJUST,
			statebuf),
			mkstring(buf7, 12, LJUST, srangebuf));
	} else
		fprintf(fp, " %s %s %s  %s %s\n",
			mkstring(buf1, VADDR_PRLEN, LJUST|LONG_HEX,
			MKSTR(memory_block)),
			mkstring(buf2, 10, CENTER, name),
			parangebuf,
			mkstring(buf5, strlen("OFFLINE"), LJUST,
			statebuf),
			mkstring(buf6, 12, LJUST, srangebuf));
}

static void
init_memory_block_offset(void)
{
	MEMBER_OFFSET_INIT(bus_type_p, "bus_type", "p");
	if (INVALID_MEMBER(bus_type_p)) {
		MEMBER_OFFSET_INIT(kset_list, "kset", "list");
		MEMBER_OFFSET_INIT(kset_kobj, "kset", "kobj");
		MEMBER_OFFSET_INIT(kobject_name, "kobject", "name");
		MEMBER_OFFSET_INIT(kobject_entry, "kobject", "entry");
		MEMBER_OFFSET_INIT(subsys_private_subsys, "subsys_private", "subsys");
	}
	MEMBER_OFFSET_INIT(subsys_private_klist_devices,
				"subsys_private", "klist_devices");
	MEMBER_OFFSET_INIT(klist_k_list, "klist", "k_list");
	MEMBER_OFFSET_INIT(klist_node_n_node, "klist_node", "n_node");
	MEMBER_OFFSET_INIT(device_kobj, "device", "kobj");
	MEMBER_OFFSET_INIT(kobject_name, "kobject", "name");
	MEMBER_OFFSET_INIT(device_private_knode_bus,
				"device_private", "knode_bus");
	MEMBER_OFFSET_INIT(device_private_device, "device_private", "device");
	MEMBER_OFFSET_INIT(memory_block_dev, "memory_block", "dev");
	MEMBER_OFFSET_INIT(memory_block_start_section_nr,
				"memory_block", "start_section_nr");
	MEMBER_OFFSET_INIT(memory_block_end_section_nr,
				"memory_block", "end_section_nr");
	MEMBER_OFFSET_INIT(memory_block_state, "memory_block", "state");
	if (MEMBER_EXISTS("memory_block", "nid"))
		MEMBER_OFFSET_INIT(memory_block_nid, "memory_block", "nid");
}

static void
init_memory_block(int *klistcnt, ulong **klistbuf)
{
	ulong private, klist, start;
	struct list_data list_data, *ld;

	ld = &list_data;
	private = 0;

	init_memory_block_offset();

	/*
	 * v6.3-rc1
	 * d2bf38c088e0 driver core: remove private pointer from struct bus_type
	 */
	if (INVALID_MEMBER(bus_type_p)) {
		int i, cnt;
		char buf[32];
		ulong bus_kset, list, name;

		BZERO(ld, sizeof(struct list_data));

		get_symbol_data("bus_kset", sizeof(ulong), &bus_kset);
		readmem(bus_kset + OFFSET(kset_list), KVADDR, &list,
			sizeof(ulong), "bus_kset.list", FAULT_ON_ERROR);

		ld->flags |= LIST_ALLOCATE;
		ld->start = list;
		ld->end = bus_kset + OFFSET(kset_list);
		ld->list_head_offset = OFFSET(kobject_entry);

		cnt = do_list(ld);
		for (i = 0; i < cnt; i++) {
			readmem(ld->list_ptr[i] + OFFSET(kobject_name), KVADDR, &name,
				sizeof(ulong), "kobject.name", FAULT_ON_ERROR);
			read_string(name, buf, sizeof(buf)-1);
			if (CRASHDEBUG(1))
				fprintf(fp, "kobject: %lx name: %s\n", ld->list_ptr[i], buf);
			if (STREQ(buf, "memory")) {
				/* entry is subsys_private.subsys.kobj. See bus_to_subsys(). */
				private = ld->list_ptr[i] - OFFSET(kset_kobj)
						- OFFSET(subsys_private_subsys);
				break;
			}
		}
		FREEBUF(ld->list_ptr);
	} else {
		ulong memory_subsys = symbol_value("memory_subsys");
		readmem(memory_subsys + OFFSET(bus_type_p), KVADDR, &private,
			sizeof(void *), "memory_subsys.private", FAULT_ON_ERROR);
	}

	if (!private)
		error(FATAL, "cannot determine subsys_private for memory.\n");

	klist = private + OFFSET(subsys_private_klist_devices) +
					OFFSET(klist_k_list);
	BZERO(ld, sizeof(struct list_data));

	readmem(klist, KVADDR, &start,
		sizeof(void *), "klist klist", FAULT_ON_ERROR);

	ld->start = start;
	ld->end = klist;
	ld->list_head_offset = OFFSET(klist_node_n_node) +
					OFFSET(device_private_knode_bus);
	hq_open();
	*klistcnt = do_list(ld);
	*klistbuf = (ulong *)GETBUF(*klistcnt * sizeof(ulong));
	*klistcnt = retrieve_list(*klistbuf, *klistcnt);
	hq_close();
}

void
dump_memory_blocks(int initialize)
{
	ulong memory_block, device;
	ulong *klistbuf;
	int klistcnt, i;
	char mb_hdr[BUFSIZE];
	char paddr_hdr[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char buf5[BUFSIZE];
	char buf6[BUFSIZE];

	if ((!STRUCT_EXISTS("memory_block")) ||
				(!symbol_exists("memory_subsys")))
		return;

	if (initialize)
		return;

	init_memory_block(&klistcnt, &klistbuf);

	if ((symbol_exists("memory_block_size_probed")) ||
	    (MEMBER_EXISTS("memory_block", "end_section_nr")))
		sprintf(paddr_hdr, "%s", "PHYSICAL RANGE");
	else
		sprintf(paddr_hdr, "%s", "PHYSICAL START");

	if (MEMBER_EXISTS("memory_block", "nid"))
		sprintf(mb_hdr, "\n%s %s   %s   %s  %s %s\n",
			mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "MEM_BLOCK"),
			mkstring(buf2, 10, CENTER, "NAME"),
			mkstring(buf3, PADDR_PRLEN*2 + 2, CENTER, paddr_hdr),
			mkstring(buf4, strlen("NODE"), CENTER, "NODE"),
			mkstring(buf5, strlen("OFFLINE"), LJUST, "STATE"),
			mkstring(buf6, 12, LJUST, "START_SECTION_NO"));
	else
		sprintf(mb_hdr, "\n%s %s   %s    %s %s\n",
			mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "MEM_BLOCK"),
			mkstring(buf2, 10, CENTER, "NAME"),
			mkstring(buf3, PADDR_PRLEN*2, CENTER, paddr_hdr),
			mkstring(buf4, strlen("OFFLINE"), LJUST, "STATE"),
			mkstring(buf5, 12, LJUST, "START_SECTION_NO"));
	fprintf(fp, "%s", mb_hdr);

	for (i = 0; i < klistcnt; i++) {
		readmem(klistbuf[i] + OFFSET(device_private_device), KVADDR,
			&device, sizeof(void *), "device_private device",
			FAULT_ON_ERROR);
		memory_block = device - OFFSET(memory_block_dev);
		print_memory_block(memory_block);
	}
	FREEBUF(klistbuf);
}

void 
list_mem_sections(void)
{
	ulong nr,addr;
	ulong nr_mem_sections = NR_MEM_SECTIONS();
	ulong coded_mem_map;

	for (nr = 0; nr <= nr_mem_sections ; nr++) {
		if ((addr = valid_section_nr(nr))) {
			coded_mem_map = section_mem_map_addr(addr, 0);
			fprintf(fp,
			    "nr=%ld section = %lx coded_mem_map=%lx pfn=%ld mem_map=%lx\n",
				nr,
				addr,
				coded_mem_map,
				section_nr_to_pfn(nr),
				sparse_decode_mem_map(coded_mem_map,nr));
		}
	}
}

/*
 *  For kernels containing the node_online_map or node_states[], 
 *  return the number of online node bits set.
 */
static int
get_nodes_online(void)
{
	int i, len, online;
	struct gnu_request req;
	ulong *maskptr;
	long N_ONLINE;
	ulong mapaddr;

	if (!symbol_exists("node_online_map") && 
	    !symbol_exists("node_states")) 
		return 0;

	len = mapaddr = 0;

	if (symbol_exists("node_online_map")) {
		if (LKCD_KERNTYPES()) {
                	if ((len = STRUCT_SIZE("nodemask_t")) < 0)
       				error(FATAL,
					"cannot determine type nodemask_t\n");
			mapaddr = symbol_value("node_online_map");
		} else {
			len = get_symbol_type("node_online_map", NULL, &req)
			    == TYPE_CODE_UNDEF ?  sizeof(ulong) : req.length;
			mapaddr = symbol_value("node_online_map");
		}
	} else if (symbol_exists("node_states")) {
		if ((get_symbol_type("node_states", NULL, &req) != TYPE_CODE_ARRAY) ||
		    !(len = get_array_length("node_states", NULL, 0)) ||
		    !enumerator_value("N_ONLINE", &N_ONLINE))
			return 0;
		len = req.length / len;
		mapaddr = symbol_value("node_states") + (N_ONLINE * len);
	}

       	if (!(vt->node_online_map = (ulong *)malloc(len)))
       		error(FATAL, "cannot malloc node_online_map\n");

 	if (!readmem(mapaddr, KVADDR, 
	    (void *)&vt->node_online_map[0], len, "node_online_map", 
	    QUIET|RETURN_ON_ERROR))
		error(FATAL, "cannot read node_online_map/node_states\n");

	vt->node_online_map_len = len/sizeof(ulong);

	online = 0;

	maskptr = (ulong *)vt->node_online_map;
	for (i = 0; i < vt->node_online_map_len; i++, maskptr++)
		online += count_bits_long(*maskptr);

	if (CRASHDEBUG(1)) {
		fprintf(fp, "node_online_map: [");
		for (i = 0; i < vt->node_online_map_len; i++)
			fprintf(fp, "%s%lx", i ? ", " : "",  vt->node_online_map[i]);
		fprintf(fp, "] -> nodes online: %d\n", online);
	}

	if (online)
		vt->numnodes = online;

	return online;
}

/*
 *  Return the next node index, with "first" being the first acceptable node.
 */
static int
next_online_node(int first)
{
	int i, j, node;
	ulong mask, *maskptr;

	if ((first/BITS_PER_LONG) >= vt->node_online_map_len)
		return -1;

	maskptr = (ulong *)vt->node_online_map;
	for (i = node = 0; i <  vt->node_online_map_len; i++, maskptr++) {
		mask = *maskptr;
        	for (j = 0; j < BITS_PER_LONG; j++, node++) {
                	if (mask & 1) {
				if (node >= first)
					return node;
			}
               	 	mask >>= 1;
        	}
	}

	return -1;
}

/*
 *  Modify appropriately for architecture/kernel nuances.
 */
static ulong
next_online_pgdat(int node)
{
        char buf[BUFSIZE];
	ulong pgdat;

/*
 * "__node_data" is used in the mips64 architecture,
 * and "node_data" is used in other architectures.
 */
#ifndef __mips64
#define NODE_DATA_VAR "node_data"
#else
#define NODE_DATA_VAR "__node_data"
#endif

	/*
	 *  Default -- look for type:  node_data[]/__node_data[]
	 */
	if (LKCD_KERNTYPES()) {
		if (!kernel_symbol_exists(NODE_DATA_VAR))
			goto pgdat2;
		/* 
		 *  Just index into node_data[]/__node_data[] without checking that
		 *  it is an array; kerntypes have no such symbol information.
	 	 */
	} else {
		if (get_symbol_type(NODE_DATA_VAR, NULL, NULL) != TYPE_CODE_ARRAY)
			goto pgdat2;

	        open_tmpfile();
	        sprintf(buf, "whatis " NODE_DATA_VAR);
	        if (!gdb_pass_through(buf, fp, GNU_RETURN_ON_ERROR)) {
	                close_tmpfile();
			goto pgdat2;
	        }
	        rewind(pc->tmpfile);
	        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
	                if (STRNEQ(buf, "type = "))
	                        break;
	        }
	        close_tmpfile();

		if ((!strstr(buf, "struct pglist_data *") &&
		     !strstr(buf, "pg_data_t *") &&
		     !strstr(buf, "struct node_data *")) ||
		    (count_chars(buf, '[') != 1) ||
		    (count_chars(buf, ']') != 1))
			goto pgdat2;
	}

	if (!readmem(symbol_value(NODE_DATA_VAR) + (node * sizeof(void *)),
	    KVADDR, &pgdat, sizeof(void *), NODE_DATA_VAR, RETURN_ON_ERROR) ||
	    !IS_KVADDR(pgdat))
		goto pgdat2;

	return pgdat;

pgdat2:
	if (LKCD_KERNTYPES()) {
		if (!kernel_symbol_exists("pgdat_list"))
			goto pgdat3;
	} else {
		if (get_symbol_type("pgdat_list",NULL,NULL) != TYPE_CODE_ARRAY)
			goto pgdat3;

	        open_tmpfile();
	        sprintf(buf, "whatis pgdat_list");
	        if (!gdb_pass_through(buf, fp, GNU_RETURN_ON_ERROR)) {
	                close_tmpfile();
			goto pgdat3;
	        }
	        rewind(pc->tmpfile);
	        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
	                if (STRNEQ(buf, "type = "))
	                        break;
	        }
	        close_tmpfile();

		if ((!strstr(buf, "struct pglist_data *") &&
		     !strstr(buf, "pg_data_t *") &&
		     !strstr(buf, "struct node_data *")) ||
		    (count_chars(buf, '[') != 1) ||
		    (count_chars(buf, ']') != 1))
			goto pgdat3;
	}

	if (!readmem(symbol_value("pgdat_list") + (node * sizeof(void *)), 
	    KVADDR, &pgdat, sizeof(void *), "pgdat_list", RETURN_ON_ERROR) ||
	    !IS_KVADDR(pgdat))
		goto pgdat3;

	return pgdat;

pgdat3:
	if (symbol_exists("contig_page_data") && (node == 0))
		return symbol_value("contig_page_data");

	return 0;
}

/*
 *  Make the vm_stat[] array contents easily accessible.
 */
static int
vm_stat_init(void)
{
        char buf[BUFSIZE];
        char *arglist[MAXARGS];
	int i, count, stringlen, total;
	int c ATTRIBUTE_UNUSED;
        struct gnu_request *req;
	char *start;
	long enum_value, zone_cnt = -1, node_cnt = -1;
	int split_vmstat = 0, ni = 0;

	if (vt->flags & VM_STAT)
		return TRUE;

	if ((vt->nr_vm_stat_items == -1) ||
		(!symbol_exists("vm_stat") && !symbol_exists("vm_zone_stat")))
		goto bailout;

        /*
         *  look for type: type = atomic_long_t []
         */
	if (LKCD_KERNTYPES()) {
		if ((!symbol_exists("vm_stat") &&
				!symbol_exists("vm_zone_stat")))
			goto bailout;
		/* 
		 *  Just assume that vm_stat is an array; there is
		 *  no symbol info in a kerntypes file. 
		 */
	} else {
		if (symbol_exists("vm_stat") &&
		    get_symbol_type("vm_stat", NULL, NULL) == TYPE_CODE_ARRAY) {
			vt->nr_vm_stat_items =
				get_array_length("vm_stat", NULL, 0);
		} else if (symbol_exists("vm_zone_stat") &&
			get_symbol_type("vm_zone_stat",
			NULL, NULL) == TYPE_CODE_ARRAY) {
			if (symbol_exists("vm_numa_stat") &&
			    get_array_length("vm_numa_stat", NULL, 0)) {
				vt->nr_vm_stat_items =
					get_array_length("vm_zone_stat", NULL, 0)
					+ get_array_length("vm_node_stat", NULL, 0) 
					+ ARRAY_LENGTH(vm_numa_stat);
				split_vmstat = 2;
				enumerator_value("NR_VM_ZONE_STAT_ITEMS", &zone_cnt);
				enumerator_value("NR_VM_NODE_STAT_ITEMS", &node_cnt);
			} else {
				vt->nr_vm_stat_items =
					get_array_length("vm_zone_stat", NULL, 0)
					+ get_array_length("vm_node_stat", NULL, 0);
				split_vmstat = 1;
				enumerator_value("NR_VM_ZONE_STAT_ITEMS", &zone_cnt);
			}
		} else {
			goto bailout;
		}
	}

        open_tmpfile();
        req = (struct gnu_request *)GETBUF(sizeof(struct gnu_request));
        req->command = GNU_GET_DATATYPE;
        req->name = "zone_stat_item";
        req->flags = GNU_PRINT_ENUMERATORS;
        gdb_interface(req);

	if (split_vmstat >= 1) {
		req->command = GNU_GET_DATATYPE;
		req->name = "node_stat_item";
		req->flags = GNU_PRINT_ENUMERATORS;
		gdb_interface(req);
	}

	if (split_vmstat == 2) {
		req->command = GNU_GET_DATATYPE;
		req->name = "numa_stat_item";
		req->flags = GNU_PRINT_ENUMERATORS;
		gdb_interface(req);
	}

        FREEBUF(req);

	stringlen = 1;
	count = -1;

        rewind(pc->tmpfile);
        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
		if (strstr(buf, "{") || strstr(buf, "}"))
			continue;
		clean_line(buf);
		c = parse_line(buf, arglist);
		if ((!split_vmstat &&
			STREQ(arglist[0], "NR_VM_ZONE_STAT_ITEMS")) ||
			((split_vmstat == 1) &&
			STREQ(arglist[0], "NR_VM_NODE_STAT_ITEMS")) ||
			((split_vmstat == 2) &&
			STREQ(arglist[0], "NR_VM_NUMA_STAT_ITEMS"))) {
			if (LKCD_KERNTYPES())
				vt->nr_vm_stat_items = 
					MAX(atoi(arglist[2]), count);
			break;
		} else if ((split_vmstat == 1) &&
			STREQ(arglist[0], "NR_VM_ZONE_STAT_ITEMS")) {
			continue;
		} else if ((split_vmstat == 2) && 
			STREQ(arglist[0], "NR_VM_NODE_STAT_ITEMS")) {
			continue;
		} else {
			stringlen += strlen(arglist[0]) + 1;
			count++;
		}
        }

	total = stringlen + (sizeof(void *) * vt->nr_vm_stat_items);
        if (!(vt->vm_stat_items = (char **)malloc(total))) {
		close_tmpfile();
                error(FATAL, "cannot malloc vm_stat_items cache\n");
	}
	BZERO(vt->vm_stat_items, total);

	start = (char *)&vt->vm_stat_items[vt->nr_vm_stat_items];

        rewind(pc->tmpfile);
        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
                if (strstr(buf, "{") || strstr(buf, "}"))
                        continue;
		c = parse_line(buf, arglist);
		if (!enumerator_value(arglist[0], &enum_value)) {
			close_tmpfile();
			goto bailout;
		}

		i = ni + enum_value;
		if (!ni && (enum_value == zone_cnt)) {
			ni = zone_cnt;
			continue;
		} else if ((ni == zone_cnt) && (enum_value == node_cnt)) {
			ni += node_cnt;
			continue;
		}

		if (i < vt->nr_vm_stat_items) {
			vt->vm_stat_items[i] = start;
			strcpy(start, arglist[0]);
			start += strlen(arglist[0]) + 1;
		}
        }

	close_tmpfile();

	vt->flags |= VM_STAT;
	return TRUE;

bailout:
	vt->nr_vm_stat_items = -1;
	return FALSE;
}

/*
 *  Either dump all vm_stat entries, or return the value of
 *  the specified vm_stat item.  Use the global counter unless
 *  a zone-specific address is passed.
 */
static int
dump_vm_stat(char *item, long *retval, ulong zone)
{
	char *buf;
	ulong *vp;
	ulong location;
	int i, maxlen, len, node_start = -1, numa_start = 1;
	long total_cnt, zone_cnt = 0, node_cnt = 0, numa_cnt = 0;
	int split_vmstat = 0;

	if (!vm_stat_init()) {
		if (!item)
			if (CRASHDEBUG(1))
				error(INFO,
			    	    "vm_stat not available in this kernel\n");
		return FALSE;
	}

	buf = GETBUF(sizeof(ulong) * vt->nr_vm_stat_items);

	if (symbol_exists("vm_node_stat") && symbol_exists("vm_zone_stat") &&
	    symbol_exists("vm_numa_stat") && ARRAY_LENGTH(vm_numa_stat))
		split_vmstat = 2;
	else if (symbol_exists("vm_node_stat") && symbol_exists("vm_zone_stat"))
		split_vmstat = 1;
	else
		location = zone ? zone : symbol_value("vm_stat");

	if (split_vmstat == 1) {
		enumerator_value("NR_VM_ZONE_STAT_ITEMS", &zone_cnt);
		location = zone ? zone : symbol_value("vm_zone_stat");
		readmem(location, KVADDR, buf,
			sizeof(ulong) * zone_cnt,
			"vm_zone_stat", FAULT_ON_ERROR);
		if (!zone) {
			location = symbol_value("vm_node_stat");
			enumerator_value("NR_VM_NODE_STAT_ITEMS", &node_cnt);
			readmem(location, KVADDR, buf + (sizeof(ulong) * zone_cnt),
				sizeof(ulong) * node_cnt,
				"vm_node_stat", FAULT_ON_ERROR);
		}
		node_start = zone_cnt;
		total_cnt = zone_cnt + node_cnt;
	} else if (split_vmstat == 2) {
		enumerator_value("NR_VM_ZONE_STAT_ITEMS", &zone_cnt);
		location = zone ? zone : symbol_value("vm_zone_stat");
		readmem(location, KVADDR, buf,
			sizeof(ulong) * zone_cnt,
			"vm_zone_stat", FAULT_ON_ERROR);
		if (!zone) {
			location = symbol_value("vm_node_stat");
			enumerator_value("NR_VM_NODE_STAT_ITEMS", &node_cnt);
			readmem(location, KVADDR, buf + (sizeof(ulong) * zone_cnt),
				sizeof(ulong) * node_cnt,
				"vm_node_stat", FAULT_ON_ERROR);
		}
		node_start = zone_cnt;
		if (!zone) {
			location = symbol_value("vm_numa_stat");
			enumerator_value("NR_VM_NUMA_STAT_ITEMS", &numa_cnt);
			readmem(location, KVADDR, buf + (sizeof(ulong) * (zone_cnt+node_cnt)),
				sizeof(ulong) * numa_cnt,
				"vm_numa_stat", FAULT_ON_ERROR);
		}
		numa_start = zone_cnt+node_cnt;
		total_cnt = zone_cnt + node_cnt + numa_cnt;
	} else {
		readmem(location, KVADDR, buf,
			sizeof(ulong) * vt->nr_vm_stat_items,
			"vm_stat", FAULT_ON_ERROR);
		total_cnt = vt->nr_vm_stat_items;
	}

	if (!item) {
		if (!zone) {
			if (symbol_exists("vm_zone_stat"))
				fprintf(fp, "  VM_ZONE_STAT:\n");
			else
				fprintf(fp, "  VM_STAT:\n");
		}
		for (i = maxlen = 0; i < total_cnt; i++)
			if ((len = strlen(vt->vm_stat_items[i])) > maxlen)
				maxlen = len;
		vp = (ulong *)buf;
		for (i = 0; i < total_cnt; i++) {
			if (!zone) {
				if ((i == node_start) && symbol_exists("vm_node_stat")) 
					fprintf(fp, "\n  VM_NODE_STAT:\n"); 
				if ((i == numa_start) && symbol_exists("vm_numa_stat")
				    && ARRAY_LENGTH(vm_numa_stat))
					fprintf(fp, "\n  VM_NUMA_STAT:\n"); 
			}
			fprintf(fp, "%s%s: %ld\n",
				space(maxlen - strlen(vt->vm_stat_items[i])),
				 vt->vm_stat_items[i], vp[i]);
		}
		return TRUE;
	}

	vp = (ulong *)buf;
	for (i = 0; i < total_cnt; i++) {
		if (STREQ(vt->vm_stat_items[i], item)) {
			*retval = vp[i];
			return TRUE;
		}
	}

	return FALSE;
}

/*
 *  Dump the cumulative totals of the per_cpu__page_states counters.
 */
int
dump_page_states(void)
{
	struct syment *sp;
	ulong addr, value;
	int i, c, fd, len, instance, members;
	char buf[BUFSIZE];
        char *arglist[MAXARGS];
	struct entry {
		char *name;
		ulong value;
	} *entry_list;
	struct stat stat;
	char *namebuf, *nameptr;

	if (!(sp = per_cpu_symbol_search("per_cpu__page_states"))) {
		if (CRASHDEBUG(1))
			error(INFO, "per_cpu__page_states"
			    "not available in this kernel\n");
		return FALSE;
	}

	instance = members = len = 0;

        sprintf(buf, "ptype struct page_state");

	open_tmpfile();
        if (!gdb_pass_through(buf, fp, GNU_RETURN_ON_ERROR)) {
		close_tmpfile();
		return FALSE;
	}

	fflush(pc->tmpfile);
	fd = fileno(pc->tmpfile);
	fstat(fd, &stat);
	namebuf = GETBUF(stat.st_size);
	nameptr = namebuf;

	rewind(pc->tmpfile);
        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
		if (strstr(buf, "struct page_state") ||
		    strstr(buf, "}"))
			continue;
		members++;
	}

	entry_list = (struct entry *)
		GETBUF(sizeof(struct entry) * members);

	rewind(pc->tmpfile);
	i = 0;
        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
		if (strstr(buf, "struct page_state") ||
		    strstr(buf, "}"))
			continue;
		strip_ending_char(strip_linefeeds(buf), ';');
		c = parse_line(buf, arglist);
		strcpy(nameptr, arglist[c-1]);
		entry_list[i].name = nameptr;
		if (strlen(nameptr) > len)
			len = strlen(nameptr);
		nameptr += strlen(nameptr)+2;
		i++;
	}
	close_tmpfile();

	open_tmpfile();

        for (c = 0; c < kt->cpus; c++) {
                addr = sp->value + kt->__per_cpu_offset[c];
		dump_struct("page_state", addr, RADIX(16));
        }

	i = 0;
	rewind(pc->tmpfile);
        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
		if (strstr(buf, "struct page_state")) {
			instance++;
			i = 0;
			continue;
		}
		if (strstr(buf, "}"))
			continue;	
		strip_linefeeds(buf);
		extract_hex(buf, &value, ',', TRUE);
		entry_list[i].value += value;
		i++;
        }

	close_tmpfile();

	fprintf(fp, "  PAGE_STATES:\n");
	for (i = 0; i < members; i++) {
		sprintf(buf, "%s", entry_list[i].name);
		fprintf(fp, "%s", mkstring(buf, len+2, RJUST, 0));
		fprintf(fp, ": %ld\n", entry_list[i].value);
	}

	FREEBUF(namebuf);
	FREEBUF(entry_list);

	return TRUE;
}


/* 
 *  Dump the cumulative totals of the per_cpu__vm_event_state
 *  counters.
 */
static int 
dump_vm_event_state(void)
{
	int i, c, maxlen, len;
	struct syment *sp;
	ulong addr;
	ulong *events, *cumulative;

	if (!vm_event_state_init())
		return FALSE;

	events = (ulong *)GETBUF((sizeof(ulong) * vt->nr_vm_event_items) * 2);
	cumulative = &events[vt->nr_vm_event_items];

        sp = per_cpu_symbol_search("per_cpu__vm_event_states");

        for (c = 0; c < kt->cpus; c++) {
                addr = sp->value + kt->__per_cpu_offset[c];
		if (CRASHDEBUG(1)) {
			fprintf(fp, "[%d]: %lx\n", c, addr);
			dump_struct("vm_event_state", addr, RADIX(16));
		}
                readmem(addr, KVADDR, events,
                    sizeof(ulong) * vt->nr_vm_event_items, 
		    "vm_event_states buffer", FAULT_ON_ERROR);
		for (i = 0; i < vt->nr_vm_event_items; i++)
			cumulative[i] += events[i];
        }

	fprintf(fp, "\n  VM_EVENT_STATES:\n");

	for (i = maxlen = 0; i < vt->nr_vm_event_items; i++)
		if ((len = strlen(vt->vm_event_items[i])) > maxlen)
			maxlen = len; 

	for (i = 0; i < vt->nr_vm_event_items; i++)
		fprintf(fp, "%s%s: %lu\n", 
			space(maxlen - strlen(vt->vm_event_items[i])),
			vt->vm_event_items[i], cumulative[i]);

	FREEBUF(events);

	return TRUE;
}

static int
vm_event_state_init(void)
{
	int i, stringlen, total;
	int c ATTRIBUTE_UNUSED;
	long count, enum_value;
	struct gnu_request *req;
	char *arglist[MAXARGS];
	char buf[BUFSIZE];
	char *start;

	if (vt->flags & VM_EVENT)
		return TRUE;

        if ((vt->nr_vm_event_items == -1) || 
	    !per_cpu_symbol_search("per_cpu__vm_event_states"))
                goto bailout;

	if (!enumerator_value("NR_VM_EVENT_ITEMS", &count))
		return FALSE;

	vt->nr_vm_event_items = count;

        open_tmpfile();
        req = (struct gnu_request *)GETBUF(sizeof(struct gnu_request));
        req->command = GNU_GET_DATATYPE;
        req->name = "vm_event_item";
        req->flags = GNU_PRINT_ENUMERATORS;
        gdb_interface(req);
        FREEBUF(req);

	stringlen = 1;

        rewind(pc->tmpfile);
        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
		if (strstr(buf, "{") || strstr(buf, "}"))
			continue;
		clean_line(buf);
		c = parse_line(buf, arglist);
		if (STREQ(arglist[0], "NR_VM_EVENT_ITEMS"))
			break;
		else
			stringlen += strlen(arglist[0]);
        }

	total = stringlen + vt->nr_vm_event_items + 
		(sizeof(void *) * vt->nr_vm_event_items);
        if (!(vt->vm_event_items = (char **)malloc(total))) {
		close_tmpfile();
                error(FATAL, "cannot malloc vm_event_items cache\n");
	}
	BZERO(vt->vm_event_items, total);

	start = (char *)&vt->vm_event_items[vt->nr_vm_event_items];

        rewind(pc->tmpfile);
        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
                if (strstr(buf, "{") || strstr(buf, "}"))
                        continue;
		c = parse_line(buf, arglist);
		if (enumerator_value(arglist[0], &enum_value))
			i = enum_value;
		else {
			close_tmpfile();
			goto bailout;
		}
		if (i < vt->nr_vm_event_items) {
			vt->vm_event_items[i] = start;
			strcpy(start, arglist[0]);
			start += strlen(arglist[0]) + 1;
		}
        }
	close_tmpfile();

	vt->flags |= VM_EVENT;
	return TRUE;

bailout:
	vt->nr_vm_event_items = -1;
	return FALSE;
}

/*
 *  Dump the per-cpu offset values that are used to 
 *  resolve per-cpu symbol values.
 */
static void
dump_per_cpu_offsets(void)
{
	int c;
	char buf[BUFSIZE];

	fprintf(fp, "PER-CPU OFFSET VALUES:\n");

	for (c = 0; c < kt->cpus; c++) {
		sprintf(buf, "CPU %d", c);
		fprintf(fp, "%7s: %lx", buf, kt->__per_cpu_offset[c]);

		if (hide_offline_cpu(c))
			fprintf(fp, " [OFFLINE]\n");
		else
			fprintf(fp, "\n");

	}
}

/*
 *  Dump the value(s) of a page->flags bitmap.
 */
void
dump_page_flags(ulonglong flags)
{
	int c ATTRIBUTE_UNUSED;
	int sz, val, found, largest, longest, header_printed;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char header[BUFSIZE];
	char *arglist[MAXARGS];
	ulonglong tmpflag;

	found = longest = largest = header_printed = 0;

        open_tmpfile();
	if (dump_enumerator_list("pageflags")) {
		rewind(pc->tmpfile);
		while (fgets(buf1, BUFSIZE, pc->tmpfile)) {
			if (strstr(buf1, " = ")) {
				c = parse_line(buf1, arglist);
				if ((sz = strlen(arglist[0])) > longest)
					longest = sz;
				if (strstr(arglist[0], "PG_") &&
				    ((val = atoi(arglist[2])) > largest))
					largest = val;
			}
        	}
	} else
		error(FATAL, "enum pageflags does not exist in this kernel\n");

	largest = (largest+1)/4 + 1;
	sprintf(header, "%s BIT  VALUE\n",
		mkstring(buf1, longest, LJUST, "PAGE-FLAG"));

	rewind(pc->tmpfile);

	if (flags)
		fprintf(pc->saved_fp, "FLAGS: %llx\n", flags);

	fprintf(pc->saved_fp, "%s%s", flags ? "  " : "", header);

	while (fgets(buf1, BUFSIZE, pc->tmpfile)) {
		if (strstr(buf1, " = ") && strstr(buf1, "PG_")) {
			c = parse_line(buf1, arglist);
			val = atoi(arglist[2]);
			tmpflag = 1ULL << val;
			if (!flags || (flags & tmpflag)) {
				fprintf(pc->saved_fp, "%s%s  %2d  %.*lx\n", 
					flags ? "  " : "",
					mkstring(buf2, longest, LJUST, 
					arglist[0]), val,
					largest, (ulong)(1ULL << val));
				if (flags & tmpflag)
					found++;
			}

		}
	}

	if (flags && !found)
		fprintf(pc->saved_fp, "  (none found)\n");

        close_tmpfile();
}


/*
 *  Support for slub.c slab cache.
 */
static void
kmem_cache_init_slub(void)
{
	if (vt->flags & KMEM_CACHE_INIT)
		return;

	if (CRASHDEBUG(1) &&
	    !(vt->flags & CONFIG_NUMA) && (vt->numnodes > 1))
		error(WARNING, 
		    "kmem_cache_init_slub: numnodes: %d without CONFIG_NUMA\n",
			vt->numnodes);

	if (kmem_cache_downsize())
		add_to_downsized("kmem_cache");

	vt->cpu_slab_type = MEMBER_TYPE("kmem_cache", "cpu_slab");

	vt->flags |= KMEM_CACHE_INIT;
}

static void 
kmem_cache_list_common(struct meminfo *mi)
{
        int i, cnt;
        ulong *cache_list;
        ulong name;
	char buf[BUFSIZE];

	if (mi->flags & GET_SLAB_ROOT_CACHES)
		cnt = get_kmem_cache_root_list(&cache_list);
	else
		cnt = get_kmem_cache_list(&cache_list);

	for (i = 0; i < cnt; i++) {
		fprintf(fp, "%lx ", cache_list[i]);

		readmem(cache_list[i] + OFFSET(kmem_cache_name), 
			KVADDR, &name, sizeof(char *),
			"kmem_cache.name", FAULT_ON_ERROR);

		if (!read_string(name, buf, BUFSIZE-1))
			sprintf(buf, "(unknown)\n");
		
		fprintf(fp, "%s\n", buf);
	}

	FREEBUF(cache_list);
}

static void
dump_kmem_cache_slub(struct meminfo *si)
{
	int i;
	ulong name, oo;
	unsigned int size, objsize, objects, order, offset;
	char *reqname, *p1;
	char kbuf[BUFSIZE];
	char buf[BUFSIZE];

	if (INVALID_MEMBER(kmem_cache_node_nr_slabs)) {
		error(INFO, 
		    "option requires kmem_cache_node.nr_slabs member!\n"
		    "(the kernel must be built with CONFIG_SLUB_DEBUG)\n");
		return;
	}

	order = objects = 0;
	if (si->flags & GET_SLAB_ROOT_CACHES)
		si->cache_count = get_kmem_cache_root_list(&si->cache_list);
	else
		si->cache_count = get_kmem_cache_list(&si->cache_list);

	si->cache_buf = GETBUF(SIZE(kmem_cache));

	si->list_offset = VALID_MEMBER(slab_slab_list) ?
				OFFSET(slab_slab_list) : OFFSET(page_lru);

	if (VALID_MEMBER(page_objects) &&
	    OFFSET(page_objects) == OFFSET(page_inuse))
		si->flags |= SLAB_BITFIELD;

	if (!si->reqname &&
	     !(si->flags & (ADDRESS_SPECIFIED|GET_SLAB_PAGES)))
		fprintf(fp, "%s", kmem_cache_hdr);

	if (si->flags & ADDRESS_SPECIFIED) {
		if ((p1 = is_slab_page(si, kbuf))) {
			si->flags |= VERBOSE;
			si->slab = (ulong)si->spec_addr;
		} else if (!(p1 = vaddr_to_kmem_cache(si->spec_addr, kbuf, 
		    	VERBOSE))) {
			error(INFO, 
			   "address is not allocated in slab subsystem: %lx\n",
				si->spec_addr);
			goto bailout;
		}
		
		if (si->reqname && (si->reqname != p1)) 
			error(INFO, 
			    "ignoring pre-selected %s cache for address: %lx\n",
				si->reqname, si->spec_addr, si->reqname);
		reqname = p1;
	} else
		reqname = si->reqname;

	for (i = 0; i < si->cache_count; i++) {
		BZERO(si->cache_buf, SIZE(kmem_cache));
		if (!readmem(si->cache_list[i], KVADDR, si->cache_buf, 
		    SIZE(kmem_cache), "kmem_cache buffer", 
		    RETURN_ON_ERROR|RETURN_PARTIAL))
			goto next_cache;

		name = ULONG(si->cache_buf + OFFSET(kmem_cache_name)); 
		if (!read_string(name, buf, BUFSIZE-1))
			sprintf(buf, "(unknown)");
		if (reqname) {
			if (!STREQ(reqname, buf))
				continue;
			fprintf(fp, "%s", kmem_cache_hdr);
		}
		if (ignore_cache(si, buf)) {
			DUMP_KMEM_CACHE_TAG(si->cache_list[i], buf, "[IGNORED]");
			goto next_cache;
		}

		objsize = UINT(si->cache_buf + OFFSET(kmem_cache_objsize)); 
		size = UINT(si->cache_buf + OFFSET(kmem_cache_size)); 
		offset = UINT(si->cache_buf + OFFSET(kmem_cache_offset));
		if (VALID_MEMBER(kmem_cache_objects)) {
			objects = UINT(si->cache_buf + 
				OFFSET(kmem_cache_objects)); 
			order = UINT(si->cache_buf + OFFSET(kmem_cache_order)); 
		} else if (VALID_MEMBER(kmem_cache_oo)) {
			oo = ULONG(si->cache_buf + OFFSET(kmem_cache_oo));
			objects = oo_objects(oo);
			order = oo_order(oo);
		} else
			error(FATAL, "cannot determine "
			    	"kmem_cache objects/order values\n");

		si->cache = si->cache_list[i];
		si->curname = buf;
		si->objsize = objsize;
		si->size = size;
		si->objects = objects;
		si->slabsize = (PAGESIZE() << order);
		si->inuse = si->num_slabs = 0;
		si->slab_offset = offset;
		si->random = VALID_MEMBER(kmem_cache_random) ?
			ULONG(si->cache_buf + OFFSET(kmem_cache_random)) : 0;

		if (!get_kmem_cache_slub_data(GET_SLUB_SLABS, si) ||
		    !get_kmem_cache_slub_data(GET_SLUB_OBJECTS, si))
			si->flags |= SLAB_GATHER_FAILURE;

		/* accumulate children's slabinfo */
		if (si->flags & GET_SLAB_ROOT_CACHES) {
			struct meminfo *mi;
			int j;
			char buf2[BUFSIZE];

			mi = (struct meminfo *)GETBUF(sizeof(struct meminfo));
			memcpy(mi, si, sizeof(struct meminfo));

			mi->cache_count = get_kmem_cache_child_list(&mi->cache_list,
						si->cache_list[i]);

			if (!mi->cache_count)
				goto no_children;

			mi->cache_buf = GETBUF(SIZE(kmem_cache));

			for (j = 0; j < mi->cache_count; j++) {
				BZERO(mi->cache_buf, SIZE(kmem_cache));
				if (!readmem(mi->cache_list[j], KVADDR, mi->cache_buf,
				    SIZE(kmem_cache), "kmem_cache buffer",
				    RETURN_ON_ERROR|RETURN_PARTIAL))
					continue;

				name = ULONG(mi->cache_buf + OFFSET(kmem_cache_name));
				if (!read_string(name, buf2, BUFSIZE-1))
					sprintf(buf2, "(unknown)");

				objsize = UINT(mi->cache_buf + OFFSET(kmem_cache_objsize));
				size = UINT(mi->cache_buf + OFFSET(kmem_cache_size));
				offset = UINT(mi->cache_buf + OFFSET(kmem_cache_offset));
				if (VALID_MEMBER(kmem_cache_objects)) {
					objects = UINT(mi->cache_buf +
						OFFSET(kmem_cache_objects));
					order = UINT(mi->cache_buf + OFFSET(kmem_cache_order));
				} else if (VALID_MEMBER(kmem_cache_oo)) {
					oo = ULONG(mi->cache_buf + OFFSET(kmem_cache_oo));
					objects = oo_objects(oo);
					order = oo_order(oo);
				} else
					error(FATAL, "cannot determine "
						"kmem_cache objects/order values\n");

				mi->cache = mi->cache_list[j];
				mi->curname = buf2;
				mi->objsize = objsize;
				mi->size = size;
				mi->objects = objects;
				mi->slabsize = (PAGESIZE() << order);
				mi->inuse = mi->num_slabs = 0;
				mi->slab_offset = offset;
				mi->random = VALID_MEMBER(kmem_cache_random) ?
					ULONG(mi->cache_buf + OFFSET(kmem_cache_random)) : 0;

				if (!get_kmem_cache_slub_data(GET_SLUB_SLABS, mi) ||
				    !get_kmem_cache_slub_data(GET_SLUB_OBJECTS, mi)) {
					si->flags |= SLAB_GATHER_FAILURE;
					continue;
				}

				si->inuse += mi->inuse;
				si->free += mi->free;
				si->num_slabs += mi->num_slabs;

				if (CRASHDEBUG(1))
					dump_kmem_cache_info(mi);
			}
			FREEBUF(mi->cache_buf);
			FREEBUF(mi->cache_list);
no_children:
			FREEBUF(mi);
		}

		DUMP_KMEM_CACHE_INFO();

		if (si->flags & SLAB_GATHER_FAILURE) {
			si->flags &= ~SLAB_GATHER_FAILURE;
			goto next_cache;
		}

		if (si->flags & ADDRESS_SPECIFIED) {
			if (!si->slab)
                		si->slab = vaddr_to_slab(si->spec_addr);
			do_slab_slub(si, VERBOSE);
		} else if (si->flags & VERBOSE) {
			do_kmem_cache_slub(si);
			if (!reqname && ((i+1) < si->cache_count))
				fprintf(fp, "%s", kmem_cache_hdr);
		}

next_cache:
		if (reqname) 
			break;
	}

bailout:
	FREEBUF(si->cache_list);
	FREEBUF(si->cache_buf);
}

static ushort 
slub_page_objects(struct meminfo *si, ulong page)
{
	ulong objects_vaddr;
	ushort objects;

	/*
	 *  Pre-2.6.27, the object count and order were fixed in the
	 *  kmem_cache structure.  Now they may change, say if a high
	 *  order slab allocation fails, so the per-slab object count
	 *  is kept in the slab.
	 */
	if (VALID_MEMBER(page_objects)) {
		objects_vaddr = page + OFFSET(page_objects);
		if (si->flags & SLAB_BITFIELD)
			objects_vaddr += sizeof(ushort);
		if (!readmem(objects_vaddr, KVADDR, &objects,
			     sizeof(ushort), "page.objects", RETURN_ON_ERROR))
			return 0;
		/*
		 *  Strip page.frozen bit.
		 */
		if (si->flags & SLAB_BITFIELD) {
			if (__BYTE_ORDER == __LITTLE_ENDIAN) {
				objects <<= 1;
				objects >>= 1;
			}
			if (__BYTE_ORDER == __BIG_ENDIAN)
				objects >>= 1;
		}

		if (CRASHDEBUG(1) && (objects != si->objects))
			error(NOTE, "%s: slab: %lx oo objects: %ld "
			      "slab objects: %d\n",
			      si->curname, page,
			      si->objects, objects);

		if (objects == (ushort)(-1)) {
			error(INFO, "%s: slab: %lx invalid page.objects: -1\n",
			      si->curname, page);
			return 0;
		}
	} else
		objects = (ushort)si->objects;

	return objects;
}

static short 
count_cpu_partial(struct meminfo *si, int cpu)
{
	short cpu_partial_inuse, cpu_partial_objects, free_objects;
	ulong cpu_partial;

	free_objects = 0;

	if (VALID_MEMBER(kmem_cache_cpu_partial) && VALID_MEMBER(page_objects)) {
		readmem(ULONG(si->cache_buf + OFFSET(kmem_cache_cpu_slab)) +
			kt->__per_cpu_offset[cpu] + OFFSET(kmem_cache_cpu_partial),
			KVADDR, &cpu_partial, sizeof(ulong),
			"kmem_cache_cpu.partial", RETURN_ON_ERROR);

		while (cpu_partial) {
			if (!is_page_ptr(cpu_partial, NULL)) {
				error(INFO, "%s: invalid partial list slab pointer: %lx\n",
					si->curname, cpu_partial);
				return 0;
			}
			if (!readmem(cpu_partial + OFFSET(page_inuse), KVADDR, &cpu_partial_inuse,
			    sizeof(ushort), "page.inuse", RETURN_ON_ERROR))
				return 0;
			if (cpu_partial_inuse == -1)
				return 0;

			cpu_partial_objects = slub_page_objects(si,
								cpu_partial);
			if (!cpu_partial_objects)
				return 0;
			free_objects += cpu_partial_objects - cpu_partial_inuse;

			readmem(cpu_partial + OFFSET(page_next), KVADDR,
				&cpu_partial, sizeof(ulong), "page.next",
				RETURN_ON_ERROR);
		}
	}
	return free_objects;
}

/*
 *  Emulate the total count calculation done by the
 *  slab_objects() sysfs function in slub.c.
 */ 
static int 
get_kmem_cache_slub_data(long cmd, struct meminfo *si)
{
	int i, n, node;
	ulong total_objects, total_slabs, free_objects;
	ulong cpu_slab_ptr, node_ptr, cpu_freelist, orig_slab;
	ulong node_nr_partial, node_nr_slabs, node_total_objects;
	int full_slabs, objects, node_total_avail;
	long p;
	short inuse;
        ulong *nodes, *per_cpu;
	struct node_table *nt;

	/*
	 *  nodes[n] is not being used (for now)
	 *  per_cpu[n] is a count of cpu_slab pages per node.
	 */
        nodes = (ulong *)GETBUF(2 * sizeof(ulong) * vt->numnodes);
        per_cpu = nodes + vt->numnodes;

	total_slabs = total_objects = free_objects = cpu_freelist = 0;
	node_total_avail = VALID_MEMBER(kmem_cache_node_total_objects) ? TRUE : FALSE;

	for (i = 0; i < kt->cpus; i++) {
		cpu_slab_ptr = get_cpu_slab_ptr(si, i, &cpu_freelist);

		if (!cpu_slab_ptr)
			continue;

		if ((node = page_to_nid(cpu_slab_ptr)) < 0)
			goto bailout;

		switch (cmd)
		{
		case GET_SLUB_OBJECTS: {
			/* For better error report, set cur slab to si->slab. */
			orig_slab = si->slab;
			si->slab = cpu_slab_ptr;

			if (!readmem(cpu_slab_ptr + OFFSET(page_inuse), 
				     KVADDR, &inuse, sizeof(short),
				     "page inuse", RETURN_ON_ERROR)) {
				si->slab = orig_slab;
				return FALSE;
			}
			objects = slub_page_objects(si, cpu_slab_ptr);
			if (!objects) {
				si->slab = orig_slab;
				return FALSE;
			}

			free_objects += objects - inuse;
			free_objects += count_free_objects(si, cpu_freelist);
			free_objects += count_cpu_partial(si, i);

			if (!node_total_avail)
				total_objects += inuse;
			total_slabs++;

			si->slab = orig_slab;
		}
			break;

		case GET_SLUB_SLABS:
			total_slabs++;
			break;
		}
		per_cpu[node]++;
	}
	
	for (n = 0; n < vt->numnodes; n++) {
		if (vt->flags & CONFIG_NUMA) {
			nt = &vt->node_table[n];
			node_ptr = ULONG(si->cache_buf +
				OFFSET(kmem_cache_node) +
				(sizeof(void *) * nt->node_id));
		} else
			node_ptr = si->cache + 
				OFFSET(kmem_cache_local_node);

		if (!node_ptr) 
			continue; 
		
               	if (!readmem(node_ptr + OFFSET(kmem_cache_node_nr_partial), 
		    KVADDR, &node_nr_partial, sizeof(ulong), 
		    "kmem_cache_node nr_partial", RETURN_ON_ERROR))
			goto bailout;
               	if (!readmem(node_ptr + OFFSET(kmem_cache_node_nr_slabs), 
		    KVADDR, &node_nr_slabs, sizeof(ulong), 
		    "kmem_cache_node nr_slabs", RETURN_ON_ERROR))
			goto bailout;
		if (node_total_avail) {
			if (!readmem(node_ptr + OFFSET(kmem_cache_node_total_objects),
			    KVADDR, &node_total_objects, sizeof(ulong),
			    "kmem_cache_node total_objects", RETURN_ON_ERROR))
				goto bailout;
		}

		switch (cmd)
		{
		case GET_SLUB_OBJECTS:
			if ((p = count_partial(node_ptr, si, &free_objects)) < 0)
				return FALSE;
			if (!node_total_avail)
				total_objects += p;
			total_slabs += node_nr_partial;
			break;

		case GET_SLUB_SLABS:
			total_slabs += node_nr_partial;
			break;
		}

		full_slabs = node_nr_slabs - per_cpu[n] - node_nr_partial;
		objects = si->objects;

		switch (cmd)
		{
		case GET_SLUB_OBJECTS:
			if (node_total_avail)
				total_objects += node_total_objects;
			else
				total_objects += (full_slabs * objects);
			total_slabs += full_slabs;
			break;

		case GET_SLUB_SLABS:
			total_slabs += full_slabs;
			break;
		}

		if (!(vt->flags & CONFIG_NUMA))
			break;
	}

	switch (cmd)
	{
	case GET_SLUB_OBJECTS:
		if (!node_total_avail)
			si->inuse = total_objects;
		else
			si->inuse = total_objects - free_objects;
		if (VALID_MEMBER(page_objects) && node_total_avail)
			si->free = free_objects;
		else
			si->free = (total_slabs * si->objects) - si->inuse;
		break;

	case GET_SLUB_SLABS:
		si->num_slabs = total_slabs;
		break;
	}

	FREEBUF(nodes);
	return TRUE;

bailout:
	FREEBUF(nodes);
	return FALSE;
}

static void
do_cpu_partial_slub(struct meminfo *si, int cpu)
{
	ulong cpu_slab_ptr;
	void *partial;

	cpu_slab_ptr = ULONG(si->cache_buf + OFFSET(kmem_cache_cpu_slab)) +
				kt->__per_cpu_offset[cpu];
	readmem(cpu_slab_ptr + OFFSET(kmem_cache_cpu_partial), KVADDR,
		&partial, sizeof(void *), "kmem_cache_cpu.partial",
		RETURN_ON_ERROR);

	fprintf(fp, "CPU %d PARTIAL:\n%s", cpu,
		partial ? "" : "  (empty)\n");

	/*
	 * kmem_cache_cpu.partial points to the first page of per cpu partial
	 * list.
	 */ 
	while (partial) {
		si->slab = (ulong)partial;

		if (!is_page_ptr(si->slab, NULL)) {
			error(INFO, "%s: invalid partial list slab pointer: %lx\n",
				si->curname, si->slab);
			break;
		}

		if (!do_slab_slub(si, VERBOSE))
			break;

		readmem((ulong)partial + OFFSET(page_next), KVADDR, &partial,
			sizeof(void *), "page.next", RETURN_ON_ERROR);

	}
}

static void
do_kmem_cache_slub(struct meminfo *si)  
{
	int i, n;
	ulong cpu_slab_ptr, node_ptr;
	ulong node_nr_partial, node_nr_slabs;
	ulong *per_cpu;
	struct node_table *nt;

	per_cpu = (ulong *)GETBUF(sizeof(ulong) * vt->numnodes);

        for (i = 0; i < kt->cpus; i++) {
		if (si->spec_cpumask && !NUM_IN_BITMAP(si->spec_cpumask, i))
			continue;
		if (hide_offline_cpu(i)) {
			fprintf(fp, "CPU %d [OFFLINE]\n", i);
			continue;
		}

		cpu_slab_ptr = ULONG(si->cache_buf + OFFSET(kmem_cache_cpu_slab)) +
				kt->__per_cpu_offset[i];
		fprintf(fp, "CPU %d KMEM_CACHE_CPU:\n  %lx\n", i, cpu_slab_ptr);

		cpu_slab_ptr = get_cpu_slab_ptr(si, i, NULL);

		fprintf(fp, "CPU %d SLAB:\n%s", i, 
			cpu_slab_ptr ? "" : "  (empty)\n");

                if (cpu_slab_ptr) {
                	if ((n = page_to_nid(cpu_slab_ptr)) >= 0)
				per_cpu[n]++;

			si->slab = cpu_slab_ptr;
			if (!do_slab_slub(si, VERBOSE))
				continue;	
		}

		if (VALID_MEMBER(kmem_cache_cpu_partial))
			do_cpu_partial_slub(si, i);

		if (received_SIGINT())
			restart(0);
        }

        for (n = 0; n < vt->numnodes; n++) {
                if (vt->flags & CONFIG_NUMA) {
			nt = &vt->node_table[n];
                        node_ptr = ULONG(si->cache_buf +
                                OFFSET(kmem_cache_node) +
                                (sizeof(void *)* nt->node_id));
                } else
                        node_ptr = si->cache +
                                OFFSET(kmem_cache_local_node);

		if (node_ptr) { 
		 	if (!readmem(node_ptr + OFFSET(kmem_cache_node_nr_partial),
			    KVADDR, &node_nr_partial, sizeof(ulong),
			    "kmem_cache_node nr_partial", RETURN_ON_ERROR))
				break;
			if (!readmem(node_ptr + OFFSET(kmem_cache_node_nr_slabs),
			    KVADDR, &node_nr_slabs, sizeof(ulong),
			    "kmem_cache_node nr_slabs", RETURN_ON_ERROR))
				break;
		} else
			node_nr_partial = node_nr_slabs = 0;

		fprintf(fp, "KMEM_CACHE_NODE   NODE  SLABS  PARTIAL  PER-CPU\n");

		fprintf(fp, "%lx%s", node_ptr, space(VADDR_PRLEN > 8 ? 2 : 10));
		fprintf(fp, "%4d  %5ld  %7ld  %7ld\n",
			n, node_nr_slabs, node_nr_partial, per_cpu[n]);

		do_node_lists_slub(si, node_ptr, n);

		if (!(vt->flags & CONFIG_NUMA))
			break;
	}

	fprintf(fp, "\n");

	FREEBUF(per_cpu);
}

#define DUMP_SLAB_INFO_SLUB() \
      { \
        char b1[BUFSIZE], b2[BUFSIZE]; \
        fprintf(fp, "  %s  %s  %4d  %5d  %9d  %4d\n", \
                mkstring(b1, VADDR_PRLEN, LJUST|LONG_HEX, MKSTR(si->slab)), \
                mkstring(b2, VADDR_PRLEN, LJUST|LONG_HEX, MKSTR(vaddr)), \
		node, objects, inuse, objects - inuse); \
      }

static int
do_slab_slub(struct meminfo *si, int verbose)
{
	physaddr_t paddr; 
	ulong vaddr;
	ushort inuse, objects; 
	ulong freelist, cpu_freelist, cpu_slab_ptr;
	int i, free_objects, cpu_slab, is_free, node;
	ulong p, q;
#define SLAB_RED_ZONE 0x00000400UL
	ulong flags, red_left_pad;

	if (!si->slab) {
		if (CRASHDEBUG(1))
			error(INFO, "-S option not supported for CONFIG_SLUB\n");
		return FALSE;
	}

	if (!page_to_phys(si->slab, &paddr)) {
		error(INFO, 
		    "%s: invalid slab address: %lx\n",
			si->curname, si->slab);
		return FALSE;
	} 

	node = page_to_nid(si->slab);

	vaddr = PTOV(paddr);

	if (verbose)
		fprintf(fp, "  %s", slab_hdr);

	if (!readmem(si->slab + OFFSET(page_inuse), KVADDR, &inuse,
	    sizeof(ushort), "page.inuse", RETURN_ON_ERROR))
		return FALSE;
	if (!readmem(si->slab + OFFSET(page_freelist), KVADDR, &freelist,
	    sizeof(void *), "page.freelist", RETURN_ON_ERROR))
		return FALSE;

	objects = slub_page_objects(si, si->slab);
	if (!objects)
		return FALSE;

	if (!verbose) {
		DUMP_SLAB_INFO_SLUB();
		return TRUE;
	}

	cpu_freelist = 0;
	for (i = 0, cpu_slab = -1; i < kt->cpus; i++) {
		cpu_slab_ptr = get_cpu_slab_ptr(si, i, &cpu_freelist);

		if (!cpu_slab_ptr)
                        continue;
		if (cpu_slab_ptr == si->slab) {
			cpu_slab = i;
			/*
			 *  Later slub scheme uses the per-cpu freelist
			 *  so count the free objects by hand.
			 */
			if ((free_objects = count_free_objects(si, cpu_freelist)) < 0)
				return FALSE;
			/*
			 * If the object is freed on foreign cpu, the
			 * object is liked to page->freelist.
			 */
			if (freelist)
				free_objects += objects - inuse;
			inuse = objects - free_objects;
			break;
		}
	}

	DUMP_SLAB_INFO_SLUB();

	fprintf(fp, "  %s", free_inuse_hdr);

#define PAGE_MAPPING_ANON  1

	if (CRASHDEBUG(8)) {
		fprintf(fp, "< SLUB: free list START: >\n");
		i = 0;
		for (q = freelist; q; q = get_freepointer(si, (void *)q)) {
			if (q & PAGE_MAPPING_ANON) { 
				fprintf(fp, 
				    "< SLUB: free list END: %lx (%d found) >\n",
					q, i); 
				break;
			}
			fprintf(fp, "   %lx\n", q);
			i++;
		}
		if (!q) 
			fprintf(fp, "< SLUB: free list END (%d found) >\n", i);
	}

	red_left_pad = 0;
	if (VALID_MEMBER(kmem_cache_red_left_pad)) {
		flags = ULONG(si->cache_buf + OFFSET(kmem_cache_flags));
		if (flags & SLAB_RED_ZONE)
			red_left_pad = ULONG(si->cache_buf + OFFSET(kmem_cache_red_left_pad));
	}

	for (p = vaddr; p < vaddr + objects * si->size; p += si->size) {
		hq_open();
		is_free = FALSE;
		/* Search an object on both of freelist and cpu_freelist */
		ulong lists[] = { freelist, cpu_freelist, };
		for (i = 0; i < sizeof(lists) / sizeof(lists[0]); i++) {
			for (is_free = 0, q = lists[i]; q;
			     q = get_freepointer(si, (void *)q)) {

				if (q == BADADDR) {
					hq_close();
					return FALSE;
				}
				if (q & PAGE_MAPPING_ANON)
					break;
				if ((p + red_left_pad) == q) {
					is_free = TRUE;
					goto found_object;
				}
				if (!hq_enter(q)) {
					hq_close();
					error(INFO, "%s: slab: %lx duplicate freelist object: %lx\n",
					      si->curname, si->slab, q);
					return FALSE;
				}
			}
		}
	found_object:
		hq_close();

		if (si->flags & ADDRESS_SPECIFIED) {
			if ((si->spec_addr < p) ||
			    (si->spec_addr >= (p + si->size))) {
				if (!(si->flags & VERBOSE))
					continue;
			} 
		}

		fprintf(fp, "  %s%lx%s", 
			is_free ? " " : "[",
			pc->flags2 & REDZONE ? p : p + red_left_pad,
			is_free ? "  " : "]");
		if (is_free && (cpu_slab >= 0))
			fprintf(fp, "(cpu %d cache)", cpu_slab);
		fprintf(fp, "\n");

	}

	return TRUE;
}

static int
count_free_objects(struct meminfo *si, ulong freelist)
{
	int c;
	ulong q;

	hq_open();
	c = 0;
	for (q = freelist; q; q = get_freepointer(si, (void *)q)) {
                if (q & PAGE_MAPPING_ANON)
			break;
		if (!hq_enter(q)) {
			error(INFO, "%s: slab: %lx duplicate freelist object: %lx\n",
				si->curname, si->slab, q);
			break;
		}
                c++;
	}
	hq_close();
	return c;
}

/*
 * With CONFIG_SLAB_FREELIST_HARDENED, freelist_ptr's are crypted with xor's,
 * and for recent release with an additionnal bswap. Some releases prio to 5.7.0
 * may be using the additionnal bswap. The only easy and reliable way to tell is
 * to inspect assembly code (eg. "__slab_free") for a bswap instruction.
 */
static int
freelist_ptr_bswap_x86(void)
{
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char *arglist[MAXARGS];
	int found;

	sprintf(buf1, "disassemble __slab_free");
	open_tmpfile();
	if (!gdb_pass_through(buf1, pc->tmpfile, GNU_RETURN_ON_ERROR)) {
		close_tmpfile();
		return FALSE;
	}
	rewind(pc->tmpfile);
	found = FALSE;
	while (fgets(buf2, BUFSIZE, pc->tmpfile)) {
		if (parse_line(buf2, arglist) < 3)
			continue;
		if (STREQ(arglist[2], "bswap")) {
			found = TRUE;
			break;
		}
	}
	close_tmpfile();
	return found;
}

static void
freelist_ptr_init(void)
{
	if (THIS_KERNEL_VERSION >= LINUX(5,7,0) ||
	    ((machine_type("X86_64") || machine_type("X86")) && freelist_ptr_bswap_x86()))
		vt->flags |= FREELIST_PTR_BSWAP;
}

static ulong
freelist_ptr(struct meminfo *si, ulong ptr, ulong ptr_addr)
{
	if (VALID_MEMBER(kmem_cache_random)) {
		/* CONFIG_SLAB_FREELIST_HARDENED */

		if (vt->flags & FREELIST_PTR_BSWAP)
			ptr_addr = (sizeof(long) == 8) ? bswap_64(ptr_addr)
						       : bswap_32(ptr_addr);
		return (ptr ^ si->random ^ ptr_addr);
	} else
		return ptr;
}

static ulong
get_freepointer(struct meminfo *si, void *object)
{
	ulong vaddr, nextfree;
	
	vaddr = (ulong)(object + si->slab_offset);
	if (!readmem(vaddr, KVADDR, &nextfree,
           sizeof(void *), "get_freepointer", QUIET|RETURN_ON_ERROR)) {
		error(INFO, "%s: slab: %lx invalid freepointer: %lx\n", 
			si->curname, si->slab, vaddr);
		return BADADDR;
	}

	return (freelist_ptr(si, nextfree, vaddr));
}

static void
do_node_lists_slub(struct meminfo *si, ulong node_ptr, int node)
{
	ulong next, last, list_head, flags;
	int first;

	if (!node_ptr)
		return;

	list_head = node_ptr + OFFSET(kmem_cache_node_partial);
 	if (!readmem(list_head, KVADDR, &next, sizeof(ulong),
	    "kmem_cache_node partial", RETURN_ON_ERROR))
		return;

	fprintf(fp, "NODE %d PARTIAL:\n%s", node,
		next == list_head ? "  (empty)\n" : "");
	first = 0;
        while (next != list_head) {
		si->slab = last = next - si->list_offset;
		if (first++ == 0)
			fprintf(fp, "  %s", slab_hdr);

		if (!is_page_ptr(si->slab, NULL)) {
			error(INFO, 
			    "%s: invalid partial list slab pointer: %lx\n", 
				si->curname, si->slab);
			return;
		}

		if (!do_slab_slub(si, !VERBOSE))
			return;
		
		if (received_SIGINT())
			restart(0);

                if (!readmem(next, KVADDR, &next, sizeof(ulong),
                    "page.lru.next", RETURN_ON_ERROR))
                        return;

		if (!IS_KVADDR(next) || 
		    ((next != list_head) && 
		     !is_page_ptr(next - si->list_offset, NULL))) {
			error(INFO, 
			    "%s: partial list slab: %lx invalid page.lru.next: %lx\n", 
				si->curname, last, next);
			return;
		}

        }

#define SLAB_STORE_USER (0x00010000UL)
	flags = ULONG(si->cache_buf + OFFSET(kmem_cache_flags));
	
	if (INVALID_MEMBER(kmem_cache_node_full) ||
	    !(flags & SLAB_STORE_USER)) {
		fprintf(fp, "NODE %d FULL:\n  (not tracked)\n", node);
		return;
	}

	list_head = node_ptr + OFFSET(kmem_cache_node_full);
 	if (!readmem(list_head, KVADDR, &next, sizeof(ulong),
	    "kmem_cache_node full", RETURN_ON_ERROR))
		return;

	fprintf(fp, "NODE %d FULL:\n%s", node, 
		next == list_head ? "  (empty)\n" : "");
	first = 0;
        while (next != list_head) {
		si->slab = next - si->list_offset;
		if (first++ == 0)
			fprintf(fp, "  %s", slab_hdr);

		if (!is_page_ptr(si->slab, NULL)) {
			error(INFO, "%s: invalid full list slab pointer: %lx\n", 
				si->curname, si->slab);
			return;
		}
		if (!do_slab_slub(si, !VERBOSE))
			return;

		if (received_SIGINT())
			restart(0);

                if (!readmem(next, KVADDR, &next, sizeof(ulong),
                    "page.lru.next", RETURN_ON_ERROR))
                        return;

		if (!IS_KVADDR(next)) {
			error(INFO, "%s: full list slab: %lx page.lru.next: %lx\n", 
				si->curname, si->slab, next);
			return;
		}
        }
}


static char *
is_kmem_cache_addr_common(ulong vaddr, char *kbuf)
{
        int i, cnt;
        ulong *cache_list;
        ulong name;
        int found;

        cnt = get_kmem_cache_list(&cache_list);
	
        for (i = 0, found = FALSE; i < cnt; i++) {
		if (cache_list[i] != vaddr)
			continue;

		if (!readmem(cache_list[i] + OFFSET(kmem_cache_name), 
		    KVADDR, &name, sizeof(char *),
		    "kmem_cache.name", RETURN_ON_ERROR))
			break;

                if (!read_string(name, kbuf, BUFSIZE-1))
			sprintf(kbuf, "(unknown)");

		found = TRUE;
		break;
        }

        FREEBUF(cache_list);

	return (found ? kbuf : NULL);
}

/*
 *  Kernel-config-neutral page-to-node evaluator.
 */
static int 
page_to_nid(ulong page)
{
        int i;
	physaddr_t paddr;
        struct node_table *nt;
        physaddr_t end_paddr;

	if (!page_to_phys(page, &paddr)) {
		error(INFO, "page_to_nid: invalid page: %lx\n", page);
		return -1;
	}

        for (i = 0; i < vt->numnodes; i++) {
                nt = &vt->node_table[i];

		end_paddr = nt->start_paddr +
			((physaddr_t)nt->size * (physaddr_t)PAGESIZE());
	
		if ((paddr >= nt->start_paddr) && (paddr < end_paddr))
			return i;
        }

	error(INFO, "page_to_nid: cannot determine node for pages: %lx\n", 
		page);

	return -1; 
}

/*
 *  Allocate and fill the passed-in buffer with a list of
 *  the current kmem_cache structures.
 */
static int
get_kmem_cache_list(ulong **cache_buf)
{
	int cnt;
	ulong vaddr;
	struct list_data list_data, *ld;

	get_symbol_data("slab_caches", sizeof(void *), &vaddr);

	ld = &list_data;
	BZERO(ld, sizeof(struct list_data));
	ld->flags |= LIST_ALLOCATE;
	ld->start = vaddr;
	ld->list_head_offset = OFFSET(kmem_cache_list);
	ld->end = symbol_value("slab_caches");
	if (CRASHDEBUG(3))
		ld->flags |= VERBOSE;

	cnt = do_list(ld);
	*cache_buf = ld->list_ptr;

	return cnt;
}

static int
get_kmem_cache_root_list(ulong **cache_buf)
{
	int cnt;
	ulong vaddr;
	struct list_data list_data, *ld;

	get_symbol_data("slab_root_caches", sizeof(void *), &vaddr);

	ld = &list_data;
	BZERO(ld, sizeof(struct list_data));
	ld->flags |= LIST_ALLOCATE;
	ld->start = vaddr;
	ld->list_head_offset = OFFSET(kmem_cache_memcg_params)
		+ OFFSET(memcg_cache_params___root_caches_node);
	ld->end = symbol_value("slab_root_caches");
	if (CRASHDEBUG(3))
		ld->flags |= VERBOSE;

	cnt = do_list(ld);
	*cache_buf = ld->list_ptr;

	return cnt;
}

static int
get_kmem_cache_child_list(ulong **cache_buf, ulong root)
{
	int cnt;
	ulong vaddr, children;
	struct list_data list_data, *ld;

	children = root + OFFSET(kmem_cache_memcg_params)
			+ OFFSET(memcg_cache_params_children);

	readmem(children, KVADDR, &vaddr, sizeof(ulong),
		"kmem_cache.memcg_params.children",
		FAULT_ON_ERROR);

	/*
	 * When no children, since there is the difference of offset
	 * of children list between root and child, do_list returns
	 * an incorrect cache_buf[0]. So we determine wheather it has
	 * children or not with the value of list_head.next.
	 */
	if (children == vaddr)
		return 0;

	ld = &list_data;
	BZERO(ld, sizeof(struct list_data));
	ld->flags |= LIST_ALLOCATE;
	ld->start = vaddr;
	ld->list_head_offset =
		OFFSET(kmem_cache_memcg_params)
		+ OFFSET(memcg_cache_params_children_node);
	ld->end = children;
	if (CRASHDEBUG(3))
		ld->flags |= VERBOSE;

	cnt = do_list(ld);
	*cache_buf = ld->list_ptr;

	return cnt;
}

/*
 *  Get the address of the head page of a compound page.
 */
static ulong
compound_head(ulong page)
{
	ulong flags, first_page, compound_head;

	first_page = page;

	if (VALID_MEMBER(page_compound_head)) {
		if (readmem(page+OFFSET(page_compound_head), KVADDR, &compound_head, 
		    sizeof(ulong), "page.compound_head", RETURN_ON_ERROR)) {
			if (compound_head & 1)
				first_page = compound_head - 1;
		}
	} else if (readmem(page+OFFSET(page_flags), KVADDR, &flags, sizeof(ulong),
		"page.flags", RETURN_ON_ERROR)) {
		if ((flags & vt->PG_head_tail_mask) == vt->PG_head_tail_mask)
			readmem(page+OFFSET(page_first_page), KVADDR, &first_page, 
				sizeof(ulong), "page.first_page", RETURN_ON_ERROR);
	}
		
	return first_page;
}

long 
count_partial(ulong node, struct meminfo *si, ulong *free)
{
	ulong list_head, next, last;
	short inuse, objects;
	ulong total_inuse;
	ulong count = 0;

	count = 0;
	total_inuse = 0;
	list_head = node + OFFSET(kmem_cache_node_partial);
	if (!readmem(list_head, KVADDR, &next, sizeof(ulong),
	    "kmem_cache_node.partial", RETURN_ON_ERROR))
		return -1;

	hq_open();

	while (next != list_head) {
		if (!readmem(next - si->list_offset + OFFSET(page_inuse),
		    KVADDR, &inuse, sizeof(ushort), "page.inuse", RETURN_ON_ERROR)) {
			hq_close();
			return -1;
		}
		last = next - si->list_offset;

		if (inuse == -1) {
			error(INFO, 
			    "%s: partial list slab: %lx invalid page.inuse: -1\n",
				si->curname, last);
			break;
		}
		total_inuse += inuse;

		if (VALID_MEMBER(page_objects)) {
			objects = slub_page_objects(si, last);
			if (!objects) {
				hq_close();
				return -1;
			}
			*free += objects - inuse;
		}

		if (!readmem(next, KVADDR, &next, sizeof(ulong),
		    "page.lru.next", RETURN_ON_ERROR)) {
			hq_close();
			return -1;
		}
		if (!IS_KVADDR(next) ||
		    ((next != list_head) && 
		     !is_page_ptr(next - si->list_offset, NULL))) {
			error(INFO, "%s: partial list slab: %lx invalid page.lru.next: %lx\n", 
				si->curname, last, next);
			break;
		}

		/*
		 *  Keep track of the last 1000 entries, and check
		 *  whether the list has recursed back onto itself.
		 */
		if ((++count % 1000) == 0) {
			hq_close();
			hq_open();
		}
		if (!hq_enter(next)) {
			error(INFO, 
			    "%s: partial list slab: %lx duplicate slab entry: %lx\n",
				 si->curname, last, next);
			hq_close();
			return -1;
		}
	}

	hq_close();
	return total_inuse;
}

char *
is_slab_page(struct meminfo *si, char *buf)
{
	int i, cnt;
	ulong page_slab, page_flags, name;
        ulong *cache_list;
        char *retval;

	if (!(vt->flags & KMALLOC_SLUB))
		return NULL;

	if (!is_page_ptr((ulong)si->spec_addr, NULL))
		return NULL;

	if (!readmem(si->spec_addr + OFFSET(page_flags), KVADDR, 
	    &page_flags, sizeof(ulong), "page.flags", 
	    RETURN_ON_ERROR|QUIET))
		return NULL;

	if (!(page_flags & (1 << vt->PG_slab)))
		return NULL;

	if (!readmem(si->spec_addr + OFFSET(page_slab), KVADDR, 
	    &page_slab, sizeof(ulong), "page.slab", 
	    RETURN_ON_ERROR|QUIET))
		return NULL;

	retval = NULL;
        cnt = get_kmem_cache_list(&cache_list);

	for (i = 0; i < cnt; i++) {
		if (page_slab == cache_list[i]) {
			if (!readmem(cache_list[i] + OFFSET(kmem_cache_name), 
			    KVADDR, &name, sizeof(char *),
			    "kmem_cache.name", QUIET|RETURN_ON_ERROR))
				goto bailout;

			if (!read_string(name, buf, BUFSIZE-1))
				goto bailout;

			retval = buf;
			break;
		}
	} 

bailout:
	FREEBUF(cache_list);

	return retval;
}

/*
 *  Figure out which of the kmem_cache.cpu_slab declarations
 *  is used by this kernel, and return a pointer to the slab
 *  page being used.  Return the kmem_cache_cpu.freelist pointer
 *  if requested.
 */
static ulong
get_cpu_slab_ptr(struct meminfo *si, int cpu, ulong *cpu_freelist)
{
	ulong cpu_slab_ptr, page, freelist;

	if (cpu_freelist)
		*cpu_freelist = 0;

	switch (vt->cpu_slab_type)
	{
	case TYPE_CODE_STRUCT:
		cpu_slab_ptr = ULONG(si->cache_buf +
                        OFFSET(kmem_cache_cpu_slab) +
			OFFSET(kmem_cache_cpu_page));
		if (cpu_freelist && VALID_MEMBER(kmem_cache_cpu_freelist))
			*cpu_freelist = ULONG(si->cache_buf +
                        	OFFSET(kmem_cache_cpu_slab) +
                        	OFFSET(kmem_cache_cpu_freelist));
		break;

	case TYPE_CODE_ARRAY:
		cpu_slab_ptr = ULONG(si->cache_buf +
			OFFSET(kmem_cache_cpu_slab) + (sizeof(void *)*cpu));

		if (cpu_slab_ptr && cpu_freelist &&
		    VALID_MEMBER(kmem_cache_cpu_freelist)) {
			if (readmem(cpu_slab_ptr + OFFSET(kmem_cache_cpu_freelist),
			    KVADDR, &freelist, sizeof(void *),
			    "kmem_cache_cpu.freelist", RETURN_ON_ERROR))
				*cpu_freelist = freelist;
		}
	
		if (cpu_slab_ptr && VALID_MEMBER(kmem_cache_cpu_page)) {
			if (!readmem(cpu_slab_ptr + OFFSET(kmem_cache_cpu_page),
			    KVADDR, &page, sizeof(void *),
			    "kmem_cache_cpu.page", RETURN_ON_ERROR))
				cpu_slab_ptr = 0;
			else
				cpu_slab_ptr = page;
		}
		break;

	case TYPE_CODE_PTR:
		cpu_slab_ptr = ULONG(si->cache_buf + OFFSET(kmem_cache_cpu_slab)) +
			kt->__per_cpu_offset[cpu];

		if (cpu_slab_ptr && cpu_freelist &&
		    VALID_MEMBER(kmem_cache_cpu_freelist)) {
			if (readmem(cpu_slab_ptr + OFFSET(kmem_cache_cpu_freelist),
			    KVADDR, &freelist, sizeof(void *),
			    "kmem_cache_cpu.freelist", RETURN_ON_ERROR))
				*cpu_freelist = freelist;
		}
	
		if (cpu_slab_ptr && VALID_MEMBER(kmem_cache_cpu_page)) {
			if (!readmem(cpu_slab_ptr + OFFSET(kmem_cache_cpu_page),
			    KVADDR, &page, sizeof(void *),
			    "kmem_cache_cpu.page", RETURN_ON_ERROR))
				cpu_slab_ptr = 0;
			else
				cpu_slab_ptr = page;
		}
		break;

	default:
		cpu_slab_ptr = 0;
		error(FATAL, "cannot determine location of kmem_cache.cpu_slab page\n");
	}

	return cpu_slab_ptr;
}

/*
 *  In 2.6.27 kmem_cache.order and kmem_cache.objects were merged
 *  into the kmem_cache.oo, a kmem_cache_order_objects structure.  
 *  oo_order() and oo_objects() emulate the kernel functions
 *  of the same name.
 */
static unsigned int oo_order(ulong oo)
{
        return (oo >> 16);
}

static unsigned int oo_objects(ulong oo)
{
        return (oo & ((1 << 16) - 1));
}

#ifdef NOT_USED
ulong
slab_to_kmem_cache_node(struct meminfo *si, ulong slab_page)
{
	int node;
	ulong node_ptr;

	if (vt->flags & CONFIG_NUMA) {
		node = page_to_nid(slab_page);
		node_ptr = ULONG(si->cache_buf +
			OFFSET(kmem_cache_node) +
			(sizeof(void *)*node));
	} else
		node_ptr = si->cache + OFFSET(kmem_cache_local_node);

	return node_ptr;
}

ulong
get_kmem_cache_by_name(char *request)
{
        int i, cnt;
        ulong *cache_list;
        ulong name;
        char buf[BUFSIZE];
        ulong found;

        cnt = get_kmem_cache_list(&cache_list);
        cache_buf = GETBUF(SIZE(kmem_cache));
        found = 0;

        for (i = 0; i < cnt; i++) {
		readmem(cache_list[i] + OFFSET(kmem_cache_name), 
			KVADDR, &name, sizeof(char *),
			"kmem_cache.name", FAULT_ON_ERROR);

                if (!read_string(name, buf, BUFSIZE-1))
			continue;

                if (STREQ(buf, request)) {
                        found = cache_list[i];
                        break;
                }
        }

        FREEBUF(cache_list);

        return found;
}
#endif  /* NOT_USED */
