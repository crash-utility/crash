/*
 *  xen_hyper_global_data.c
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

#include "defs.h"

#ifdef XEN_HYPERVISOR_ARCH
#include "xen_hyper_defs.h"

/*
 * Global data for Xen hypervisor.
 */

struct xen_hyper_machdep_table xen_hyper_machdep_table = { 0 };
struct xen_hyper_machdep_table *xhmachdep = &xen_hyper_machdep_table;

struct xen_hyper_table xen_hyper_table = { 0 };
struct xen_hyper_table *xht = &xen_hyper_table;

struct xen_hyper_dumpinfo_table xen_hyper_dumpinfo_table = { 0 };
struct xen_hyper_dumpinfo_table *xhdit = &xen_hyper_dumpinfo_table;

struct xen_hyper_domain_table xen_hyper_domain_table = { 0 };
struct xen_hyper_domain_table *xhdt = &xen_hyper_domain_table;

struct xen_hyper_vcpu_table xen_hyper_vcpu_table = { 0 };
struct xen_hyper_vcpu_table *xhvct = &xen_hyper_vcpu_table;

struct xen_hyper_pcpu_table xen_hyper_pcpu_table = { 0 };
struct xen_hyper_pcpu_table *xhpct = &xen_hyper_pcpu_table;

struct xen_hyper_sched_table xen_hyper_sched_table = { 0 };
struct xen_hyper_sched_table *xhscht = &xen_hyper_sched_table;

struct xen_hyper_symbol_table_data xen_hyper_symbol_table_data = { 0 };
struct xen_hyper_symbol_table_data *xhsymt = &xen_hyper_symbol_table_data;

/*
 * The following commands are for Xen hypervisor.
 */

struct command_table_entry xen_hyper_command_table[] = {
	{"*", 	    cmd_pointer, help_pointer, 0},
	{"alias",   cmd_alias,   help_alias,   0},
        {"ascii",   cmd_ascii,   help_ascii,   0},
        {"bt",      cmd_bt,      help_bt,      0},
	{"dis",     cmd_dis,     help_dis,     0},
	{"domain",  xen_hyper_cmd_domain,   xen_hyper_help_domain,  REFRESH_TASK_TABLE},
	{"doms",    xen_hyper_cmd_doms,     xen_hyper_help_doms,    REFRESH_TASK_TABLE},
#if defined(X86) || defined(X86_64)
	{"dumpinfo",xen_hyper_cmd_dumpinfo, xen_hyper_help_dumpinfo,0},
#endif
	{"eval",    cmd_eval,    help_eval,    0},
	{"exit",    cmd_quit,    help_exit,    0},
	{"extend",  cmd_extend,  help_extend,  0},
	{"gdb",     cmd_gdb,     help_gdb,     0},
        {"help",    xen_hyper_cmd_help,     help_help,              0},
	{"list",    cmd_list,    help__list,   0},
	{"log",     xen_hyper_cmd_log,      xen_hyper_help_log,     0},
	{"p",       cmd_p,       help_p,       0},
	{"pcpus",   xen_hyper_cmd_pcpus,    xen_hyper_help_pcpus,   0},
        {"pte",     cmd_pte,     help_pte,     0},
        {"q",       cmd_quit,    help_quit,    0},
        {"rd",      cmd_rd,      help_rd,      0},
	{"repeat",  cmd_repeat,  help_repeat,  0},
	{"sched",   xen_hyper_cmd_sched,    xen_hyper_help_sched,   0},
        {"search",  cmd_search,  help_search,  0},
        {"set",     cmd_set,     help_set,     0},
        {"struct",  cmd_struct,  help_struct,  0},
        {"sym",     cmd_sym,     help_sym,     0},
        {"sys",     xen_hyper_cmd_sys,      xen_hyper_help_sys,     0},
	{"test",    cmd_test,    NULL,         HIDDEN_COMMAND},
	{"union",   cmd_union,   help_union,   0},
	{"vcpu",    xen_hyper_cmd_vcpu,     xen_hyper_help_vcpu,    REFRESH_TASK_TABLE},
	{"vcpus",   xen_hyper_cmd_vcpus,    xen_hyper_help_vcpus,   REFRESH_TASK_TABLE},
	{"whatis",  cmd_whatis,  help_whatis,  0},
	{"wr",      cmd_wr,      help_wr,      0},
	{(char *)NULL}
};

/*
 *
 */
struct xen_hyper_offset_table xen_hyper_offset_table = { 0 };
struct xen_hyper_size_table xen_hyper_size_table = { 0 };

/*
 * help data
 */

char *xen_hyper_help_domain[] = {
"domain",
"display contents of domain struct",
"[domain-id | domainp] ...",
"  This command displays contents of domain struct for selected, or all, domains",
"     domain-id  a domain id.",
"       domainp  a domain pointer.",
NULL               
};

char *xen_hyper_help_doms[] = {
"doms",
"display domain status information",
"[domain-id | domainp] ...",
"  This command displays domain status for selected, or all, domains" ,
"     domain-id  a domain id.",
"       domainp  a domain pointer.",
" ",
"    1. the DOMAIN-ID.",
"    2. the struct domain pointer.",
"    3. the domain state",
"       (SF:fully shut down, SH:shutting down, DY:dying,",
"        CP:pause by controller software, PO:polling event channels,",
"        PA:pause by the hypervisor, RU:running).",
"    4. the TYPE of domain",
"       (O:dom_io, X:dom_xen, I:idle domain, 0:domain 0, U:domain U).",
"    5. displays max_pages member of domain.",
"    6. displays tot_pages member of domain.",
"    7. a number of vcpu that domain is assigned.",
"    8. the shared_info pointer of domain.",
"    9. frame containing list of mfns containing list of mfns" ,
"       containing p2m.",
" ",
"  The active domain on each CPU will be highlighted by an angle ",
"  bracket (\">\") preceding its information.",
"  The crashing domain on each CPU will be highlighted by an aster ",
"  (\"*\") preceding its information.",
"\nEXAMPLES",
"  Show the domain status of all:\n",
"    %s> doms",
"       DID   DOMAIN  ST T  MAXPAGE  TOTPAGE VCPU SHARED_I  P2M_MFN",
"      32753 ffbf8080 RU O     0        0      0      0      ----",
"      32754 ffbfa080 RU X     0        0      0      0      ----",
"      32767 ffbfc080 RU I     0        0      2      0      ----",
"    >*    0 ff198080 RU 0 ffffffff   32900    2  ff194000   18d0",
"          4 ffbee080 RU U   4000     4000     2  ff18d000   3eb92",
"          5 ff186080 RU U   4000     4000     2  ff184000   298d3",
"    %s>",
NULL               
};

char *xen_hyper_help_dumpinfo[] = {
"dumpinfo",
"display Xen dump information",
"[-t | -r] [pcpu-id | enotep] ...",
"  This command displays Xen dump information for selected, or all, cpus" ,
"       pcpu-id  a physical cpu id.",
"        enotep  a ELF Note pointer.",
"            -t  display time information.",
"            -r  display register information.",
NULL               
};

char *xen_hyper_help_log[] = {
"log",
"dump system message buffer",
" ",
"  This command dumps the xen conring contents in chronological order." ,
"  ",
"EXAMPLES",
"  Dump the Xen message buffer:\n",
"    %s> log",
"     __  __            _____  ___                     _        _     _",
"     \\ \\/ /___ _ __   |___ / / _ \\    _   _ _ __  ___| |_ __ _| |__ | | ___",
"      \\  // _ \\ '_ \\    |_ \\| | | |__| | | | '_ \\/ __| __/ _` | '_ \\| |/ _ \\",
"      /  \\  __/ | | |  ___) | |_| |__| |_| | | | \\__ \\ || (_| | |_) | |  __/",
"     /_/\\_\\___|_| |_| |____(_)___/    \\__,_|_| |_|___/\\__\\__,_|_.__/|_|\\___|",
"    ",
"     http://www.cl.cam.ac.uk/netos/xen",
"     University of Cambridge Computer Laboratory",
"    ",
"     Xen version 3.0-unstable (damm@) (gcc version 3.4.6 (Gentoo 3.4.6-r1, ssp-3.4.5-1.0,",
"     pie-8.7.9)) Wed Dec  6 17:34:32 JST 2006",
"     Latest ChangeSet: unavailable",
"    ",
"    (XEN) Console output is synchronous.",
"    (XEN) Command line: 12733-i386-pae/xen.gz console=com1 sync_console conswitch=bb com1",
"    =115200,8n1,0x3f8 dom0_mem=480000 crashkernel=64M@32M",
"    (XEN) Physical RAM map:",
"    (XEN)  0000000000000000 - 0000000000098000 (usable)",
"    (XEN)  0000000000098000 - 00000000000a0000 (reserved)",
"    (XEN)  00000000000f0000 - 0000000000100000 (reserved)",
"    (XEN)  0000000000100000 - 000000003f7f0000 (usable)",
"    (XEN)  000000003f7f0000 - 000000003f7f3000 (ACPI NVS)",
"    (XEN)  000000003f7f3000 - 000000003f800000 (ACPI data)",
"    (XEN)  00000000e0000000 - 00000000f0000000 (reserved)",
"    (XEN)  00000000fec00000 - 0000000100000000 (reserved)",
"    (XEN) Kdump: 64MB (65536kB) at 0x2000000",
"    (XEN) System RAM: 1015MB (1039904kB)",
"    (XEN) ACPI: RSDP (v000 XPC                                   ) @ 0x000f9250",
"    ...",
NULL               
};

char *xen_hyper_help_pcpus[] = {
"pcpus",
"display physical cpu information",
"[-r][-t] [pcpu-id | pcpup] ...",
"  This command displays physical cpu information for selected, or all, cpus" ,
"       pcpu-id  a physical cpu id.",
"         pcpup  a physical cpu pointer.",
"      cur-vcpu  a current virtual cpu pointer.",
"            -r  display register information.",
"            -t  display init_tss information.",
" ",
"  The crashing physical cpu will be highlighted by an aster ",
"  (\"*\") preceding its information.",
"\nEXAMPLES",
"  Show the physical cpu status of all:\n",
"    %s> pcpus",
"       PCID   PCPU   CUR-VCPU",
"          0 ff1a3fb4 ffbf9080",
"     *    1 ff1dbfb4 ffbf8080",
"    %s>",
" ",
"  Show the physical cpu status of all with register information:\n",
"    %s> pcpus -r",
"       PCID   PCPU   CUR-VCPU",
"     *    0 ff1b7fb4 ffbef080",
"    Register information:",
"    struct cpu_user_regs {",
"      ebx = 0x0,",
"      ecx = 0xdcf4bed8,",
"      edx = 0xc0326887,",
"      esi = 0x63,",
"      edi = 0x0,",
"      ebp = 0xdcf4bee0,",
"      eax = 0x25,",
"      error_code = 0x6,",
"      entry_vector = 0xe,",
"      eip = 0xc01014a7,",
"      cs = 0x61,",
"      saved_upcall_mask = 0x0,",
"      _pad0 = 0x0,",
"      eflags = 0x202,",
"      esp = 0xdcf4bed0,",
"      ss = 0x69,",
"      _pad1 = 0x0,",
"      es = 0x7b,",
"      _pad2 = 0x0,",
"      ds = 0x7b,",
"      _pad3 = 0x0,",
"      fs = 0x0,",
"      _pad4 = 0x0,",
"      gs = 0x0,",
"      _pad5 = 0x0",
"    }",
" ",
"  Show the physical cpu status of all with init_tss information:\n",
"    %s> pcpus -t",
"       PCID   PCPU   CUR-VCPU",
"     *    0 ff1b7fb4 ffbef080",
"    init_tss information:",
"    struct tss_struct {",
"      back_link = 0x0,",
"      __blh = 0x0,",
"      esp0 = 0xff1b7fe8,",
"      ss0 = 0xe010,",
"      __ss0h = 0x0,",
"      esp1 = 0xdcf4bff8,",
"      ss1 = 0x69,",
"      __ss1h = 0x0,",
"      esp2 = 0x0,",
"      ss2 = 0x0,",
"      __ss2h = 0x0,",
"      __cr3 = 0x0,",
"      eip = 0x0,",
"      eflags = 0x0,",
"      eax = 0x0,",
"      ecx = 0x0,",
"      edx = 0x0,",
"      ebx = 0x0,",
"      esp = 0x0,",
"      ebp = 0x0,",
"      esi = 0x0,",
"      edi = 0x0,",
"      es = 0x0,",
"      __esh = 0x0,",
"      cs = 0x0,",
"      __csh = 0x0,",
"      ss = 0x0,",
"      __ssh = 0x0,",
"      ds = 0x0,",
"      __dsh = 0x0,",
"      fs = 0x0,",
"      __fsh = 0x0,",
"      gs = 0x0,",
"      __gsh = 0x0,",
"      ldt = 0x0,",
"      __ldth = 0x0,",
"      trace = 0x0,",
"      bitmap = 0x8000,",
"      __cacheline_filler = \"\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\"",
"    }",
NULL               
};

char *xen_hyper_help_sched[] = {
"pcpus",
"display scheduler information",
"[-v] [pcpu-id] ...",
"  This command displays scheduler information for selected, or all, cpus" ,
"       pcpu-id  a physical cpu id.",
"            -v  display verbosely scheduler information.",
" ",
NULL               
};

char *xen_hyper_help_sys[] = {
"sys",
"system data",
"[-c [name|number]] config",
"  This command displays system-specific data.  If no arguments are entered,\n"
"  the same system data shown during %s invocation is shown.\n",
"\nEXAMPLES",
"  Display essential system information:\n",
"    %s> sys",
"      DEBUG KERNEL: xen-syms",
"          DUMPFILE: vmcore",
"              CPUS: 2",
"           DOMAINS: 2",
"           MACHINE: Pentium III (Coppermine)  (866 Mhz)",
"            MEMORY: 2 GB",
"    %s>",
NULL               
};

char *xen_hyper_help_vcpu[] = {
"vcpu",
"display contents of vcpu struct",
"[vcpup] ...",
"  This command displays contents of vcpu struct for selected, or all, vcpus",
"       vcpu-id  a virtual cpu id.",
"         vcpup  a virtual cpu pointer.",
NULL               
};

char *xen_hyper_help_vcpus[] = {
"vcpus",
"display vcpu status information",
"[-i domain-id vcpu-id | vcpup] ...",
"  This command displays vcpu status for selected, or all, vcpus" ,
"     domain-id  a domain id.",
"       vcpu-id  a VCPU-ID.",
"         vcpup  a hexadecimal struct vcpu pointer.",
"            -i  specify vcpu id as an argument.",
" ",
"    1. the VCPU-ID.",
"    2. the physical CPU-ID.",
"    3. the struct vcpu pointer.",
"    4. the vcpu state (RU, BL, OF).",
"    5. the TYPE of domain that vcpu is assigned(I, 0, G).",
"    6. the DOMAIN-ID of domain that vcpu is assigned.",
"    7. the struct domain pointer of domain that vcpu is assigned.",
" ",
"  The active vcpu on each CPU will be highlighted by an angle ",
"  bracket (\">\") preceding its information.",
"  The crashing vcpu on each CPU will be highlighted by an aster ",
"  (\"*\") preceding its information.",
"\nEXAMPLES",
"  Show the vcpu status of all:\n",
"    %s> vcpus",
"       VCID  PCID   VCPU   ST T DOMID  DOMAIN",
"          0     0 ffbfe080 RU I 32767 ffbfc080",
"          1     1 ff1df080 RU I 32767 ffbfc080",
"    >*    0     0 ff195180 RU 0     0 ff198080",
"    >     1     1 ff190080 BL 0     0 ff198080",
"          0     1 ff18a080 BL G     4 ffbee080",
"          1     0 ff189080 BL G     4 ffbee080",
"          0     1 ff1f3080 BL G     5 ff186080",
"          1     0 ff1f2080 BL G     5 ff186080",
"    %s>",
NULL               
};

struct task_context fake_tc = { 0 };

#endif
