/*
 *  xen_hyper_defs.h
 *
 *  Portions Copyright (C) 2006-2007 Fujitsu Limited
 *  Portions Copyright (C) 2006-2007 VA Linux Systems Japan K.K.
 *
 *  Authors: Itsuro Oda <oda@valinux.co.jp>
 *           Fumihiko Kakuma <kakuma@valinux.co.jp>
 *
 *  This file is part of Xencrash.
 *
 *  Xencrash is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  Xencrash is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Xencrash; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA.
 */

#ifdef XEN_HYPERVISOR_ARCH

#include <sys/types.h>
#include <elf.h>

#ifdef X86
/* Xen Hypervisor address space layout */
#define IOREMAP_VIRT_END        (0UL)
#define IOREMAP_VIRT_START      (0xFFC00000UL)
#define DIRECTMAP_VIRT_END      IOREMAP_VIRT_START
#define DIRECTMAP_VIRT_START    (0xFF000000UL)
#define MAPCACHE_VIRT_END       DIRECTMAP_VIRT_START
#define MAPCACHE_VIRT_START     (0xFFC00000UL)
#define PERDOMAIN_VIRT_END      DIRECTMAP_VIRT_START
#define PERDOMAIN_VIRT_START    (0xFE800000UL)
#define SH_LINEAR_PT_VIRT_END   PERDOMAIN_VIRT_START
#define SH_LINEAR_PT_VIRT_START (0xFE400000UL)
#define SH_LINEAR_PT_VIRT_START_PAE (0xFE000000UL)
#define LINEAR_PT_VIRT_END      SH_LINEAR_PT_VIRT_START
#define LINEAR_PT_VIRT_START    (0xFE000000UL)
#define LINEAR_PT_VIRT_START_PAE    (0xFD800000UL)
#define RDWR_MPT_VIRT_END       LINEAR_PT_VIRT_START
#define RDWR_MPT_VIRT_START     (0xFDC00000UL)
#define RDWR_MPT_VIRT_START_PAE     (0xFC800000UL)
#define FRAMETABLE_VIRT_END     RDWR_MPT_VIRT_START
#define FRAMETABLE_VIRT_START   (0xFC400000UL)
#define FRAMETABLE_VIRT_START_PAE   (0xF6800000UL)
#define RO_MPT_VIRT_END         FRAMETABLE_VIRT_START
#define RO_MPT_VIRT_START       (0xFC000000UL)
#define RO_MPT_VIRT_START_PAE       (0xF5800000UL)

#define HYPERVISOR_VIRT_START   RO_MPT_VIRT_START
#define HYPERVISOR_VIRT_START_PAE   RO_MPT_VIRT_START_PAE
#endif

#ifdef X86_64
#define HYPERVISOR_VIRT_START (0xffff800000000000)
#define HYPERVISOR_VIRT_END   (0xffff880000000000)
#define DIRECTMAP_VIRT_START  (0xffff830000000000)
#define DIRECTMAP_VIRT_END    (0xffff880000000000)
#define PAGE_OFFSET_XEN_HYPER DIRECTMAP_VIRT_START
#define XEN_VIRT_START        (xht->xen_virt_start)
#define XEN_VIRT_ADDR(vaddr) \
    (((vaddr) >= XEN_VIRT_START) && ((vaddr) < DIRECTMAP_VIRT_START))
#endif

#ifdef IA64
#define HYPERVISOR_VIRT_START (0xe800000000000000)
#define HYPERVISOR_VIRT_END   (0xf800000000000000)
#define DEFAULT_SHAREDINFO_ADDR (0xf100000000000000)
#define PERCPU_PAGE_SIZE      65536
#define PERCPU_ADDR	      (DEFAULT_SHAREDINFO_ADDR - PERCPU_PAGE_SIZE)
#define DIRECTMAP_VIRT_START  (0xf000000000000000)
#define DIRECTMAP_VIRT_END    PERCPU_ADDR
#define VIRT_FRAME_TABLE_SIZE     (0x0100000000000000)

#define PERCPU_VIRT_ADDR(vaddr) \
    (((vaddr) >= PERCPU_ADDR) && ((vaddr) < PERCPU_ADDR + PERCPU_PAGE_SIZE))

#define FRAME_TABLE_VIRT_ADDR(vaddr) \
    ((vaddr) >= xhmachdep->frame_table && (vaddr) < xhmachdep->frame_table + VIRT_FRAME_TABLE_SIZE)

#undef IA64_RBS_OFFSET
#define IA64_RBS_OFFSET   ((XEN_HYPER_SIZE(vcpu) + 15) & ~15)

#endif /* IA64 */

#define DIRECTMAP_VIRT_ADDR(vaddr) \
    (((vaddr) >= DIRECTMAP_VIRT_START) && ((vaddr) < DIRECTMAP_VIRT_END))

typedef uint16_t	domid_t;
typedef uint32_t	Elf_Word;

/*
 * NOTE kakuma: The following defines are temporary version for
 * elf note format which is used only in crash.
 */
#define XEN_HYPER_ELF_NOTE_V1	1
#define XEN_HYPER_ELF_NOTE_V2	2
#define XEN_HYPER_ELF_NOTE_V3	3
#define XEN_HYPER_ELF_NOTE_V4	4

#ifdef X86
#define XEN_HYPER_ELF_NOTE_V4_NOTE_SIZE	0x100
#endif
#if defined(X86_64) || defined(IA64)
#define XEN_HYPER_ELF_NOTE_V4_NOTE_SIZE	0x200
#endif

/*
 * Xen Hyper
 */
#define XEN_HYPER_SMP (0x400)

#ifdef X86
#define XEN_HYPER_MAX_VIRT_CPUS  (32)
#define XEN_HYPER_HZ 100
#endif
#ifdef X86_64
#define XEN_HYPER_MAX_VIRT_CPUS  (32)
#define XEN_HYPER_HZ 100
#endif
#ifdef IA64
#define XEN_HYPER_MAX_VIRT_CPUS  (64)
#define XEN_HYPER_HZ 100
#endif
#ifndef XEN_HYPER_MAX_VIRT_CPUS
#define XEN_HYPER_MAX_VIRT_CPUS  (1)
#endif

#if defined(X86) || defined(X86_64)
#define xen_hyper_per_cpu(var, cpu)  \
	({ ulong __var_addr; \
	   if (xht->__per_cpu_offset) \
		__var_addr = (xht->flags & XEN_HYPER_SMP) ? \
			((ulong)(var) + xht->__per_cpu_offset[cpu]) : (ulong)(var); \
	   else \
		__var_addr = (ulong)(var) + ((ulong)(cpu) << xht->percpu_shift); \
	   __var_addr; })
#elif defined(IA64)
#define xen_hyper_per_cpu(var, cpu)  \
	((xht->flags & XEN_HYPER_SMP) ? \
		(ulong)(var) + (xht->__per_cpu_offset[cpu]) : \
		(ulong)(var))
#endif

#if defined(X86) || defined(X86_64)
#define XEN_HYPER_STACK_ORDER 2
#if 0
#define XEN_HYPER_STACK_SIZE (machdep->pagesize << XEN_HYPER_STACK_ORDER)
#endif
#define XEN_HYPER_GET_CPU_INFO(sp) \
	((sp & ~(STACKSIZE()-1)) | \
	(STACKSIZE() - XEN_HYPER_SIZE(cpu_info)))
#endif

#define XEN_HYPER_CONRING_SIZE 16384

/* system time */
#define XEN_HYPER_NANO_TO_SEC(ns)	((ulonglong)((ns) / 1000000000ULL))
#define XEN_HYPER_MICR_TO_SEC(us)	((ulonglong)((us) / 1000000ULL))
#define XEN_HYPER_MILI_TO_SEC(ms)	((ulonglong)((ms) / 1000ULL))

/*
 * Domain
 */
/* Prepared domain ID. */
#define XEN_HYPER_DOMID_IO		(0x7FF1U)
#define XEN_HYPER_DOMID_XEN		(0x7FF2U)
#define XEN_HYPER_DOMID_IDLE		(0x7FFFU)

/* Domain flags (domain_flags). */
 /* Is this domain privileged? */
#define XEN_HYPER__DOMF_privileged       0
#define XEN_HYPER_DOMF_privileged        (1UL<<XEN_HYPER__DOMF_privileged)
 /* Guest shut itself down for some reason. */
#define XEN_HYPER__DOMF_shutdown         1
#define XEN_HYPER_DOMF_shutdown          (1UL<<XEN_HYPER__DOMF_shutdown)
 /* Death rattle. */
#define XEN_HYPER__DOMF_dying            2
#define XEN_HYPER_DOMF_dying             (1UL<<XEN_HYPER__DOMF_dying)
 /* Domain is paused by controller software. */
#define XEN_HYPER__DOMF_ctrl_pause       3
#define XEN_HYPER_DOMF_ctrl_pause        (1UL<<XEN_HYPER__DOMF_ctrl_pause)
 /* Domain is being debugged by controller software. */
#define XEN_HYPER__DOMF_debugging        4
#define XEN_HYPER_DOMF_debugging         (1UL<<XEN_HYPER__DOMF_debugging)
 /* Are any VCPUs polling event channels (SCHEDOP_poll)? */
#define XEN_HYPER__DOMF_polling          5
#define XEN_HYPER_DOMF_polling           (1UL<<XEN_HYPER__DOMF_polling)
 /* Domain is paused by the hypervisor? */
#define XEN_HYPER__DOMF_paused           6
#define XEN_HYPER_DOMF_paused            (1UL<<XEN_HYPER__DOMF_paused)
 /* Domain flag error */
#define XEN_HYPER_DOMF_ERROR            ((ulong)(-1))

/* Domain status. */
 /* Is this an HVM guest? */
#define XEN_HYPER__DOMS_HVM              0
#define XEN_HYPER_DOMS_HVM               (1UL<<XEN_HYPER__DOMS_HVM)
 /* Is this guest fully privileged (aka dom0)? */
#define XEN_HYPER__DOMS_privileged       1
#define XEN_HYPER_DOMS_privileged        (1UL<<XEN_HYPER__DOMS_privileged)
 /* Is this guest being debugged by dom0? */
#define XEN_HYPER__DOMS_debugging        2
#define XEN_HYPER_DOMS_debugging         (1UL<<XEN_HYPER__DOMS_debugging)
 /* Are any VCPUs polling event channels (SCHEDOP_poll)? */
#define XEN_HYPER__DOMS_polling          3
#define XEN_HYPER_DOMS_polling           (1UL<<XEN_HYPER__DOMS_polling)
 /* Domain is paused by controller software? */
#define XEN_HYPER__DOMS_ctrl_pause       4
#define XEN_HYPER_DOMS_ctrl_pause        (1UL<<XEN_HYPER__DOMS_ctrl_pause)
 /* Is this guest dying (i.e., a zombie)? */
#define XEN_HYPER__DOMS_dying            5
#define XEN_HYPER_DOMS_dying             (1UL<<XEN_HYPER__DOMS_dying)
 /* In process of shutting down? */
#define XEN_HYPER__DOMS_shuttingdown     6
#define XEN_HYPER_DOMS_shuttingdown      (1UL<<XEN_HYPER__DOMS_shutdown)
 /* Fully shut down? */
#define XEN_HYPER__DOMS_shutdown         7
#define XEN_HYPER_DOMS_shutdown          (1UL<<XEN_HYPER__DOMS_shutdown)

/*
 * VCPU
 */
/* VCPU flags (vcpu_flags). */
 /* Has the FPU been initialised? */
#define XEN_HYPER__VCPUF_fpu_initialised 0
#define XEN_HYPER_VCPUF_fpu_initialised  (1UL<<XEN_HYPER__VCPUF_fpu_initialised)
 /* Has the FPU been used since it was last saved? */
#define XEN_HYPER__VCPUF_fpu_dirtied     1
#define XEN_HYPER_VCPUF_fpu_dirtied      (1UL<<XEN_HYPER__VCPUF_fpu_dirtied)
 /* Domain is blocked waiting for an event. */
#define XEN_HYPER__VCPUF_blocked         2
#define XEN_HYPER_VCPUF_blocked          (1UL<<XEN_HYPER__VCPUF_blocked)
 /* Currently running on a CPU? */
#define XEN_HYPER__VCPUF_running         3
#define XEN_HYPER_VCPUF_running          (1UL<<XEN_HYPER__VCPUF_running)
 /* Initialization completed. */
#define XEN_HYPER__VCPUF_initialised     4
#define XEN_HYPER_VCPUF_initialised      (1UL<<XEN_HYPER__VCPUF_initialised)
 /* VCPU is offline. */
#define XEN_HYPER__VCPUF_down            5
#define XEN_HYPER_VCPUF_down             (1UL<<XEN_HYPER__VCPUF_down)
 /* NMI callback pending for this VCPU? */
#define XEN_HYPER__VCPUF_nmi_pending     8
#define XEN_HYPER_VCPUF_nmi_pending      (1UL<<XEN_HYPER__VCPUF_nmi_pending)
 /* Avoid NMI reentry by allowing NMIs to be masked for short periods. */
#define XEN_HYPER__VCPUF_nmi_masked      9
#define XEN_HYPER_VCPUF_nmi_masked       (1UL<<XEN_HYPER__VCPUF_nmi_masked)
 /* VCPU is polling a set of event channels (SCHEDOP_poll). */
#define XEN_HYPER__VCPUF_polling         10
#define XEN_HYPER_VCPUF_polling          (1UL<<XEN_HYPER__VCPUF_polling)
 /* VCPU is paused by the hypervisor? */
#define XEN_HYPER__VCPUF_paused          11
#define XEN_HYPER_VCPUF_paused           (1UL<<XEN_HYPER__VCPUF_paused)
/* VCPU is blocked awaiting an event to be consumed by Xen. */
#define XEN_HYPER__VCPUF_blocked_in_xen  12
#define XEN_HYPER_VCPUF_blocked_in_xen   (1UL<<XEN_HYPER__VCPUF_blocked_in_xen)
 /* VCPU flag error */
#define XEN_HYPER_VCPUF_ERROR            ((ulong)(-1))

/* VCPU state (vcpu_runstate_info.state). */
/* VCPU is currently running on a physical CPU. */
#define XEN_HYPER_RUNSTATE_running  0
/* VCPU is runnable, but not currently scheduled on any physical CPU. */
#define XEN_HYPER_RUNSTATE_runnable 1
/* VCPU is blocked (a.k.a. idle). It is therefore not runnable. */
#define XEN_HYPER_RUNSTATE_blocked  2
/*
 * VCPU is not runnable, but it is not blocked.
 * This is a 'catch all' state for things like hotplug and pauses by the
 * system administrator (or for critical sections in the hypervisor).
 * RUNSTATE_blocked dominates this state (it is the preferred state).
 */
#define XEN_HYPER_RUNSTATE_offline  3
#define XEN_HYPER_RUNSTATE_ERROR        ((int)(-1))

/*
 * PCPU
 */
#define XEN_HYPER_TSS_IST_MAX	7

/*
 * Scheduler
 */
#define XEN_SCHEDULER_SEDF	4
#define XEN_SCHEDULER_CREDIT	5

#define XEN_HYPER_OPT_SCHED_SIZE 10

/*
 * Constants for function
 */
#define XEN_HYPER_CMD_BUFSIZE (1024)

#define XEN_HYPER_DOMAIN_ID_INVALID ((uint16_t)(-1))
#define XEN_HYPER_VCPU_ID_INVALID ((int)(-1))
#define XEN_HYPER_PCPU_ID_INVALID ((uint)(-1))

#define XEN_HYPER_DOMAIN_READ_DOM0 0
#define XEN_HYPER_DOMAIN_READ_INIT 1
#define XEN_HYPER_DOMAIN_READ_NEXT 2

#define XEN_HYPER_DOMAIN_FLAGS_PRIV 0
#define XEN_HYPER_DOMAIN_FLAGS_STAT 1

#define XEN_HYPER_STR_ADDR	(0x1)
#define XEN_HYPER_STR_DID	(0x11)
#define XEN_HYPER_STR_DOMAIN	(0x12)
#define XEN_HYPER_STR_VCID	(0x21)
#define XEN_HYPER_STR_VCPU	(0x22)
#define XEN_HYPER_STR_PCID	(0x31)
#define XEN_HYPER_STR_PCPU	(0x32)
#define XEN_HYPER_STR_INVALID	(-1)

#define XEN_HYPER_DOMAIN_TYPE_IO	(0x0)
#define XEN_HYPER_DOMAIN_TYPE_XEN	(0x1)
#define XEN_HYPER_DOMAIN_TYPE_IDLE	(0x2)
#define XEN_HYPER_DOMAIN_TYPE_DOM0	(0x3)
#define XEN_HYPER_DOMAIN_TYPE_GUEST	(0x4)
#define XEN_HYPER_DOMAIN_TYPE_INVALID	(-1)

#define XEN_HYPER_ELF_NOTE_FILL_T_NOTE		(0)
#define XEN_HYPER_ELF_NOTE_FILL_T_CORE		(1)
#define XEN_HYPER_ELF_NOTE_FILL_T_XEN_CORE	(2)
#define XEN_HYPER_ELF_NOTE_FILL_T_XEN_CORE_M	(3)
#define XEN_HYPER_ELF_NOTE_FILL_T_PRS		(4)
#define XEN_HYPER_ELF_NOTE_FILL_T_XEN_REGS	(5)

/*
 * Command interface structs
 */
#define XEN_HYPER_MAX_ARGS 100

struct xen_hyper_cmd_args {
	int cnt;
	ulong value[XEN_HYPER_MAX_ARGS];
	int type[XEN_HYPER_MAX_ARGS];
	ulong addr[XEN_HYPER_MAX_ARGS];
	void *context[XEN_HYPER_MAX_ARGS];
};

/*
 * dump information command
 */
/* options */
#define XEN_HYPER_DUMPINFO_TIME (0x1)
#define XEN_HYPER_DUMPINFO_REGS (0x2)

/*
 * Domain command
 */
#define XEN_HYPER_MAX_DOMS_ARGS XEN_HYPER_MAX_ARGS

/*
 * Physical cpu command
 */
#define XEN_HYPER_MAX_PCPUS_ARGS XEN_HYPER_MAX_ARGS
#define XEN_HYPER_PCPUS_1STCALL (0x1)
#define XEN_HYPER_PCPUS_REGS (0x2)
#define XEN_HYPER_PCPUS_TSS (0x4)

/*
 * Schedule command
 */
#define XEN_HYPER_MAX_SCHED_ARGS XEN_HYPER_MAX_ARGS
#define XEN_HYPER_SCHED_1STCALL (0x1)
#define XEN_HYPER_SCHED_VERBOSE (0x2)

/*
 * Virtual cpu command
 */
#define XEN_HYPER_MAX_VCPUS_ARGS XEN_HYPER_MAX_ARGS
#define XEN_HYPER_VCPUS_ID (0x1)


/*
 * table structs
 */
struct xen_hyper_machdep_table {
	void (*pcpu_init)(void);
#ifdef IA64
	long frame_table;
#endif
};

struct xen_hyper_table {
	ulong flags;
	ulong stext;
	ulong etext;
	ulong cpu_data_address;
	struct new_utsname utsname;
	uint cpu_curr;
	uint max_cpus;			/* max cpu in system */
	int cores;			/* number of cpu core */
	int pcpus;			/* number of physical cpu */
	int vcpus;			/* number of virtual cpu */
	int domains;			/* number of domain */
	ulong sys_pages;
	int crashing_cpu;
	struct xen_hyper_vcpu_context *crashing_vcc;
	ulong max_page;
	ulong total_pages;
	ulong *cpumask;
	uint *cpu_idxs;
	ulong *__per_cpu_offset;
	int percpu_shift;
	int idle_vcpu_size;
	ulong *idle_vcpu_array;
#ifdef X86_64
	ulong xen_virt_start;
#endif
};

struct xen_hyper_dumpinfo_context {
	ulong note;			/* per_cpu__crash_notes address */
	uint pcpu_id;
	char *ELF_Prstatus_ptr;		/* pointer to ELF_Prstatus buf */
	char *pr_reg_ptr;		/* pointer to pr_reg buf */
};

struct xen_hyper_dumpinfo_context_xen_core {
	ulong note;			/* per_cpu__crash_notes v3:xen_regs address */
	uint pcpu_id;
	char *crash_xen_core_ptr;	/* pointer to crash_xen_core_t buf */
};

struct xen_hyper_dumpinfo_context_xen_info {
	ulong note;			/* per_cpu__crash_notes v2:xen, v3:xen_info address */
	uint pcpu_id;
	char *crash_xen_info_ptr;	/* pointer to v2:xen_crash_xen_regs_t, v3:crash_xen_info_t buf */
};

struct xen_hyper_dumpinfo_table {
	uint note_ver;
	struct xen_hyper_dumpinfo_context *context_array;
	struct xen_hyper_dumpinfo_context_xen_core *context_xen_core_array;
	struct xen_hyper_dumpinfo_context_xen_info context_xen_info;
	char *crash_note_core_array;
	char *crash_note_xen_core_array;
	char *crash_note_xen_info_ptr;
	uint xen_info_cpu;
	Elf_Word note_size;
	Elf_Word core_offset;
	Elf_Word core_size;
	Elf_Word xen_core_offset;
	Elf_Word xen_core_size;
	Elf_Word xen_info_offset;
	Elf_Word xen_info_size;
};

/* domain */
struct xen_hyper_domain_context {
	ulong domain;			/* domain address */
	domid_t domain_id;
	uint tot_pages;
	uint max_pages;
	uint xenheap_pages;
	ulong shared_info;
	ulong sched_priv;
	ulong next_in_list;
	ulong domain_flags;
	ulong evtchn;
	int vcpu_cnt;
	ulong *vcpu;
	struct xen_hyper_vcpu_context_array *vcpu_context_array;
};

struct xen_hyper_domain_table {
	uint32_t flags;
	struct xen_hyper_domain_context *context_array;
	int context_array_cnt;
	ulong running_domains;
	struct xen_hyper_domain_context *dom_io;
	struct xen_hyper_domain_context *dom_xen;
	struct xen_hyper_domain_context *dom0;
	struct xen_hyper_domain_context *idle_domain;
	struct xen_hyper_domain_context *curr_domain;
	struct xen_hyper_domain_context *last;
	char *domain_struct;
	char *domain_struct_verify;
};

/* vcpu */
struct xen_hyper_vcpu_context {
	ulong vcpu;			/* vcpu address */
	int vcpu_id;
	int processor;
	ulong vcpu_info;
	ulong domain;
	ulong next_in_list;
	ulong sleep_tick;
	ulong sched_priv;
	int state;
	uint64_t state_entry_time;
	ulong runstate_guest;
	ulong vcpu_flags;
};

struct xen_hyper_vcpu_context_array {
	struct xen_hyper_vcpu_context *context_array;
	int context_array_cnt;
	int context_array_valid;
};

struct xen_hyper_vcpu_table {
	uint32_t flags;
	struct xen_hyper_vcpu_context_array *vcpu_context_arrays;
	int vcpu_context_arrays_cnt;
	ulong idle_vcpu;
	struct xen_hyper_vcpu_context_array *idle_vcpu_context_array;
	struct xen_hyper_vcpu_context *last;
	char *vcpu_struct;
	char *vcpu_struct_verify;
};

/* pcpu */
struct xen_hyper_pcpu_context {
	/* pcpu info */
	ulong pcpu;			/* pcpu address */
	uint processor_id;
	ulong guest_cpu_user_regs;
	ulong current_vcpu;
	/* tss_struct info */
	ulong init_tss;
	union {
		uint32_t esp0;
		uint64_t rsp0;	
	} sp;
	uint64_t ist[XEN_HYPER_TSS_IST_MAX];	/* This is valid on x86_64 */
};

struct xen_hyper_pcpu_table {
	struct xen_hyper_pcpu_context *context_array;
	struct xen_hyper_pcpu_context *last;
	char *pcpu_struct;
};

/* scheduler */
struct xen_hyper_sched_context {
	uint cpu_id;
	ulong schedule_data;
	ulong curr;
	ulong idle;
	ulong sched_priv;
	ulong tick;
};

struct xen_hyper_sched_table {
	char *name;
	char opt_sched[XEN_HYPER_OPT_SCHED_SIZE];
	uint sched_id;
	ulong scheduler;
	char *scheduler_struct;
	struct xen_hyper_sched_context *sched_context_array;
};

struct syment;

struct xen_hyper_symbol_table_data {
	struct syment *symtable;
};

struct xen_hyper_size_table {
	long ELF_Prstatus;			/* elf note v1,v2,v3,v4 */
	long ELF_Signifo;
	long ELF_Gregset;
	long ELF_Timeval;
	long arch_domain;
	long arch_shared_info;
	long cpu_info;
	long cpu_time;
	long cpu_user_regs;
	long cpumask_t;
	long cpuinfo_ia64;
	long cpuinfo_x86;
	long crash_note_t;			/* elf note v2, v3 */
	long crash_note_core_t;			/* elf note v2, v3 */
	long crash_note_xen_t;			/* elf note v2 */
	long crash_note_xen_core_t;		/* elf note v3 */
	long crash_note_xen_info_t;		/* elf note v3 */
	long crash_xen_core_t;			/* elf note v3,v4 */
	long crash_xen_info_t;			/* elf note v3,v4 */
	long domain;
	long domain_vcpu;
#ifdef IA64
	long mm_struct;
#endif
	long note_buf_t;			/* elf note v1 */
	long schedule_data;
	long scheduler;
	long shared_info;
	long timer;
	long tss;
	long vcpu;
	long vcpu_runstate_info;
	long xen_crash_xen_regs_t;		/* elf note v2 */
};

struct xen_hyper_offset_table {
	/* ELF */
	long ELF_Prstatus_pr_info;
	long ELF_Prstatus_pr_cursig;
	long ELF_Prstatus_pr_sigpend;
	long ELF_Prstatus_pr_sighold;
	long ELF_Prstatus_pr_pid;
	long ELF_Prstatus_pr_ppid;
	long ELF_Prstatus_pr_pgrp;
	long ELF_Prstatus_pr_sid;
	long ELF_Prstatus_pr_utime;
	long ELF_Prstatus_pr_stime;
	long ELF_Prstatus_pr_cutime;
	long ELF_Prstatus_pr_cstime;
	long ELF_Prstatus_pr_reg;
	long ELF_Prstatus_pr_fpvalid;
	long ELF_Timeval_tv_sec;
	long ELF_Timeval_tv_usec;
	/* arch_domain */
#ifdef IA64
	long arch_domain_mm;
#endif
	/* arch_shared_info */
	long arch_shared_info_max_pfn;
	long arch_shared_info_pfn_to_mfn_frame_list_list;
	long arch_shared_info_nmi_reason;
	/* cpu_info */
	long cpu_info_guest_cpu_user_regs;
	long cpu_info_processor_id;
	long cpu_info_current_vcpu;
	/* cpu_time */
	long cpu_time_local_tsc_stamp;
	long cpu_time_stime_local_stamp;
	long cpu_time_stime_master_stamp;
	long cpu_time_tsc_scale;
	long cpu_time_calibration_timer;
	/* cpuinfo_ia64 */
	long cpuinfo_ia64_proc_freq;
	long cpuinfo_ia64_vendor;
	/* crash_note_t */
	long crash_note_t_core;			/* elf note v2, v3 */
	long crash_note_t_xen;			/* elf note v2 */
	long crash_note_t_xen_regs;		/* elf note v3 */
	long crash_note_t_xen_info;		/* elf note v3 */
	/* crash_note_core_t elf note v2, v3 */
	long crash_note_core_t_note;
	long crash_note_core_t_desc;
	/* crash_note_xen_t elf note v2 */
	long crash_note_xen_t_note;
	long crash_note_xen_t_desc;
	/* crash_note_xen_core_t elf note v3 */
	long crash_note_xen_core_t_note;
	long crash_note_xen_core_t_desc;
	/* crash_note_xen_info_t elf note v3 */
	long crash_note_xen_info_t_note;
	long crash_note_xen_info_t_desc;
	/* domain */
	long domain_page_list;
	long domain_xenpage_list;
	long domain_domain_id;
	long domain_tot_pages;
	long domain_max_pages;
	long domain_xenheap_pages;
	long domain_shared_info;
	long domain_sched_priv;
	long domain_next_in_list;
	long domain_domain_flags;
	long domain_evtchn;
	long domain_is_hvm;
	long domain_guest_type;
	long domain_is_privileged;
	long domain_debugger_attached;
	long domain_is_polling;
	long domain_is_dying;
	/*
	 * This changed from xen-4.2.5 to domain_controller_pause_count.
	 * See below!
	 */
	long domain_is_paused_by_controller;
	long domain_is_shutting_down;
	long domain_is_shut_down;
	long domain_vcpu;
	long domain_max_vcpus;
	long domain_arch;
#ifdef IA64
	/* mm_struct */
	long mm_struct_pgd;
#endif
	/* schedule_data */
	long schedule_data_schedule_lock;
	long schedule_data_curr;
	long schedule_data_idle;
	long schedule_data_sched_priv;
	long schedule_data_s_timer;
	long schedule_data_tick;
	/* scheduler */
	long scheduler_name;
	long scheduler_opt_name;
	long scheduler_sched_id;
	long scheduler_init;
	long scheduler_tick;
	long scheduler_init_vcpu;
	long scheduler_destroy_domain;
	long scheduler_sleep;
	long scheduler_wake;
	long scheduler_set_affinity;
	long scheduler_do_schedule;
	long scheduler_adjust;
	long scheduler_dump_settings;
	long scheduler_dump_cpu_state;
	/* shared_info */
	long shared_info_vcpu_info;
	long shared_info_evtchn_pending;
	long shared_info_evtchn_mask;
	long shared_info_arch;
	/* timer */
	long timer_expires;
	long timer_cpu;
	long timer_function;
	long timer_data;
	long timer_heap_offset;
	long timer_killed;
	/* tss */
	long tss_rsp0;
	long tss_esp0;
	long tss_ist;
	/* vcpu */
	long vcpu_vcpu_id;
	long vcpu_processor;
	long vcpu_vcpu_info;
	long vcpu_domain;
	long vcpu_next_in_list;
	long vcpu_timer;
	long vcpu_sleep_tick;
	long vcpu_poll_timer;
	long vcpu_sched_priv;
	long vcpu_runstate;
	long vcpu_runstate_guest;
	long vcpu_vcpu_flags;
	long vcpu_pause_count;
	long vcpu_virq_to_evtchn;
	long vcpu_cpu_affinity;
	long vcpu_nmi_addr;
	long vcpu_vcpu_dirty_cpumask;
	long vcpu_arch;
#ifdef IA64
	long vcpu_thread_ksp;
#endif
	/* vcpu_runstate_info */
	long vcpu_runstate_info_state;
	long vcpu_runstate_info_state_entry_time;
	long vcpu_runstate_info_time;
	/* domain - changed item see domain_is_paused_by_controller */
	long domain_controller_pause_count;
};

/*
 * offset, size
 */
#define XEN_HYPER_SIZE(X)		(SIZE_verify(xen_hyper_size_table.X, (char *)__FUNCTION__, __FILE__, __LINE__, #X))
#define XEN_HYPER_OFFSET(X)		(OFFSET_verify(xen_hyper_offset_table.X, (char *)__FUNCTION__, __FILE__, __LINE__, #X))
#define XEN_HYPER_INVALID_MEMBER(X)	(xen_hyper_offset_table.X == INVALID_OFFSET)
#define XEN_HYPER_INVALID_SIZE(X)	(xen_hyper_size_table.X == -1)
#define XEN_HYPER_VALID_SIZE(X)		(xen_hyper_size_table.X >= 0)
#define XEN_HYPER_VALID_STRUCT(X)	(xen_hyper_size_table.X >= 0)
#define XEN_HYPER_VALID_MEMBER(X)	(xen_hyper_offset_table.X >= 0)

#define XEN_HYPER_ASSIGN_SIZE(X)	(xen_hyper_size_table.X)
#define XEN_HYPER_ASSIGN_OFFSET(X)	(xen_hyper_offset_table.X)

#define XEN_HYPER_STRUCT_SIZE_INIT(X, Y) (XEN_HYPER_ASSIGN_SIZE(X) = STRUCT_SIZE(Y))
#define XEN_HYPER_MEMBER_SIZE_INIT(X, Y, Z) (XEN_HYPER_ASSIGN_SIZE(X) = MEMBER_SIZE(Y, Z))
#define XEN_HYPER_MEMBER_OFFSET_INIT(X, Y, Z) (XEN_HYPER_ASSIGN_OFFSET(X) = MEMBER_OFFSET(Y, Z))

/*
 * System
 */
#define XEN_HYPER_MAX_CPUS() (xht->max_cpus)
#define XEN_HYPER_CRASHING_CPU() (xht->crashing_cpu)

/*
 * Dump information
 */
#define XEN_HYPER_X86_NOTE_EIP(regs) (regs[12])
#define XEN_HYPER_X86_NOTE_ESP(regs) (regs[15])
#define XEN_HYPER_X86_64_NOTE_RIP(regs) (regs[16])
#define XEN_HYPER_X86_64_NOTE_RSP(regs) (regs[19])

/*
 * Domain
 */
#define XEN_HYPER_DOMAIN_F_INIT 0x1

#define XEN_HYPER_NR_DOMAINS() (xht->domains)
#define XEN_HYPER_RUNNING_DOMAINS() (xhdt->running_domains)

/*
 * Phisycal CPU
 */
#define XEN_HYPER_NR_PCPUS() (xht->pcpus)
#define for_cpu_indexes(i, cpuid)		\
	for (i = 0, cpuid = xht->cpu_idxs[i];	\
	i < XEN_HYPER_NR_PCPUS();		\
	cpuid = xht->cpu_idxs[++i])
#define XEN_HYPER_CURR_VCPU(pcpuid) \
	(xen_hyper_get_active_vcpu_from_pcpuid(pcpuid))

/*
 * VCPU
 */
#define XEN_HYPER_VCPU_F_INIT 0x1

#define XEN_HYPER_NR_VCPUS_IN_DOM(domain_context) (domain_context->vcpu_cnt)
#define XEN_HYPER_VCPU_LAST_CONTEXT()	(xhvct->last)

/*
 * tools
 */
#define XEN_HYPER_PRI(fp, len, str, buf, flag, args)	\
	sprintf args;				\
	xen_hyper_fpr_indent(fp, len, str, buf, flag);
#define XEN_HYPER_PRI_CONST(fp, len, str, flag)	\
	xen_hyper_fpr_indent(fp, len, str, NULL, flag);

#define XEN_HYPER_PRI_L		(0x0)
#define XEN_HYPER_PRI_R		(0x1)
#define XEN_HYPER_PRI_LF	(0x2)

/*
 * Global data
 */
extern struct xen_hyper_machdep_table *xhmachdep;
extern struct xen_hyper_table *xht;
extern struct xen_hyper_dumpinfo_table *xhdit;
extern struct xen_hyper_domain_table *xhdt;
extern struct xen_hyper_vcpu_table *xhvct;
extern struct xen_hyper_pcpu_table *xhpct;
extern struct xen_hyper_sched_table *xhscht;
extern struct xen_hyper_symbol_table_data *xhsymt;

extern struct xen_hyper_offset_table xen_hyper_offset_table;
extern struct xen_hyper_size_table xen_hyper_size_table;

extern struct command_table_entry xen_hyper_command_table[];
extern struct task_context fake_tc;

/*
 * Xen Hyper command help
 */
extern char *xen_hyper_help_domain[];
extern char *xen_hyper_help_doms[];
extern char *xen_hyper_help_dumpinfo[];
extern char *xen_hyper_help_log[];
extern char *xen_hyper_help_pcpus[];
extern char *xen_hyper_help_sched[];
extern char *xen_hyper_help_sys[];
extern char *xen_hyper_help_vcpu[];
extern char *xen_hyper_help_vcpus[];

/*
 * Prototype
 */
ulonglong xen_hyper_get_uptime_hyper(void);

/*
 * x86
 */
int xen_hyper_x86_get_smp_cpus(void);
uint64_t xen_hyper_x86_memory_size(void);

/*
 * IA64
 */
int xen_hyper_ia64_get_smp_cpus(void);
uint64_t xen_hyper_ia64_memory_size(void);
ulong xen_hyper_ia64_processor_speed(void);

/*
 * Xen Hyper
 */
void xen_hyper_init(void);
void xen_hyper_domain_init(void);
void xen_hyper_vcpu_init(void);
void xen_hyper_dumpinfo_init(void);
void xen_hyper_misc_init(void);
void xen_hyper_post_init(void);
struct xen_hyper_dumpinfo_context *xen_hyper_id_to_dumpinfo_context(uint id);
struct xen_hyper_dumpinfo_context *xen_hyper_note_to_dumpinfo_context(ulong note);
char *xen_hyper_fill_elf_notes(ulong note, char *note_buf, int type);

/* domain */
void xen_hyper_refresh_domain_context_space(void);
int xen_hyper_get_domains(void);
char *xen_hyper_get_domain_next(int mod, ulong *next);
domid_t xen_hyper_domain_to_id(ulong domain);
char *xen_hyper_id_to_domain_struct(domid_t id);
struct xen_hyper_domain_context *
xen_hyper_domain_to_domain_context(ulong domain);
struct xen_hyper_domain_context *
xen_hyper_id_to_domain_context(domid_t id);
struct xen_hyper_domain_context *
xen_hyper_store_domain_context(struct xen_hyper_domain_context *dc,
		ulong domain, char *dp);
char *xen_hyper_read_domain_from_context(struct xen_hyper_domain_context *dc);
char *xen_hyper_read_domain(ulong domain);
char *xen_hyper_read_domain_verify(ulong domain);
char *xen_hyper_fill_domain_struct(ulong domain, char *domain_struct);
void xen_hyper_alloc_domain_context_space(int domains);
ulong xen_hyper_domain_state(struct xen_hyper_domain_context *dc);

/* vcpu */
void xen_hyper_refresh_vcpu_context_space(void);
struct xen_hyper_vcpu_context *
xen_hyper_vcpu_to_vcpu_context(ulong vcpu);
struct xen_hyper_vcpu_context *
xen_hyper_id_to_vcpu_context(ulong domain, domid_t did, int vcid);
struct xen_hyper_vcpu_context_array *
xen_hyper_domain_to_vcpu_context_array(ulong domain);
struct xen_hyper_vcpu_context_array *
xen_hyper_domid_to_vcpu_context_array(domid_t id);
struct xen_hyper_vcpu_context *
xen_hyper_store_vcpu_context(struct xen_hyper_vcpu_context *vcc,
	ulong vcpu, char *vcp);
char *
xen_hyper_read_vcpu_from_context(struct xen_hyper_vcpu_context *vcc);
char *xen_hyper_read_vcpu(ulong vcpu);
char *xen_hyper_read_vcpu_verify(ulong vcpu);
char *xen_hyper_fill_vcpu_struct(ulong vcpu, char *vcpu_struct);
void xen_hyper_alloc_vcpu_context_arrays_space(int domains);
void xen_hyper_alloc_vcpu_context_space(struct xen_hyper_vcpu_context_array *vcca, int vcpus);
int xen_hyper_vcpu_state(struct xen_hyper_vcpu_context *vcc);

/* pcpu */
#if defined(X86) || defined(X86_64)
void xen_hyper_x86_pcpu_init(void);
#elif defined(IA64)
void xen_hyper_ia64_pcpu_init(void);
#endif
struct xen_hyper_pcpu_context *xen_hyper_id_to_pcpu_context(uint id);
struct xen_hyper_pcpu_context *xen_hyper_pcpu_to_pcpu_context(ulong pcpu);
struct xen_hyper_pcpu_context *xen_hyper_store_pcpu_context(struct xen_hyper_pcpu_context *pcc,
	ulong pcpu, char *pcp);
struct xen_hyper_pcpu_context *xen_hyper_store_pcpu_context_tss(struct xen_hyper_pcpu_context *pcc,
	ulong init_tss, char *tss);
char *xen_hyper_read_pcpu(ulong pcpu);
char *xen_hyper_fill_pcpu_struct(ulong pcpu, char *pcpu_struct);
void xen_hyper_alloc_pcpu_context_space(int pcpus);

/* others */
char *xen_hyper_x86_fill_cpu_data(int idx, char *cpuinfo_x86);
char *xen_hyper_ia64_fill_cpu_data(int idx, char *cpuinfo_ia64);
int xen_hyper_is_vcpu_crash(struct xen_hyper_vcpu_context *vcc);
void xen_hyper_print_bt_header(FILE *out, ulong pcpu, int newline);
ulong xen_hyper_get_active_vcpu_from_pcpuid(ulong pcpu);
ulong xen_hyper_pcpu_to_active_vcpu(ulong pcpu);
void xen_hyper_get_cpu_info(void);
int xen_hyper_test_pcpu_id(uint pcpu_id);

/*
 * Xen Hyper command
 */
void xen_hyper_cmd_help(void);
void xen_hyper_cmd_domain(void);
void xen_hyper_cmd_doms(void);
void xen_hyper_cmd_dumpinfo(void);
void xen_hyper_cmd_log(void);
void xen_hyper_dump_log(void);
void xen_hyper_cmd_pcpus(void);
void xen_hyper_cmd_sched(void);
void xen_hyper_cmd_sys(void);
void xen_hyper_cmd_vcpu(void);
void xen_hyper_cmd_vcpus(void);
void xen_hyper_display_sys_stats(void);

void xen_hyper_show_vcpu_context(struct xen_hyper_vcpu_context *vcc);
char *xen_hyper_domain_state_string(struct xen_hyper_domain_context *dc,
	char *buf, int verbose);
char *xen_hyper_vcpu_state_string(struct xen_hyper_vcpu_context *vcc,
	char *buf, int verbose);

/* tools */
void xen_hyper_fpr_indent(FILE *fp, int len, char *str1, char *str2, int flag);

#else

#define XEN_HYPERVISOR_NOT_SUPPORTED \
    "Xen hypervisor mode not supported on this architecture\n"

#endif
