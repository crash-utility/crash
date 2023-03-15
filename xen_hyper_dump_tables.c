/*
 *  xen_hyper_dump_tables.c
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

static void xen_hyper_dump_xen_hyper_table(int verbose);
static void xen_hyper_dump_xen_hyper_dumpinfo_table(int verbose);
static void xen_hyper_dump_xen_hyper_domain_table(int verbose);
static void xen_hyper_dump_xen_hyper_vcpu_table(int verbose);
static void xen_hyper_dump_xen_hyper_pcpu_table(int verbose);
static void xen_hyper_dump_xen_hyper_sched_table(int verbose);
static void xen_hyper_dump_xen_hyper_size_table(char *spec, ulong makestruct);
static void xen_hyper_dump_xen_hyper_offset_table(char *spec, ulong makestruct);

static void xen_hyper_dump_mem(void *mem, ulong len, int dsz);

/*
 *  Get help for a command, to dump an internal table, or the GNU public
 *  license copying/warranty information.
 */
void
xen_hyper_cmd_help(void)
{
	int c;
	int oflag;

	oflag = 0;

        while ((c = getopt(argcnt, args, 
	        "aBbcDgHhM:mnOopszX:")) != EOF) {
                switch(c)
                {
		case 'a':
			dump_alias_data();
			return;
		case 'b':
			dump_shared_bufs();
			return;
		case 'B':
			dump_build_data();
			return;
		case 'c':
			dump_numargs_cache();
			return;
		case 'n':
		case 'D':
			dumpfile_memory(DUMPFILE_MEM_DUMP);
			return;
		case 'g':
			dump_gdb_data();
			return;
		case 'H':
			dump_hash_table(VERBOSE);
			return;
		case 'h':
			dump_hash_table(!VERBOSE);
 			return;
		case 'M':
			dump_machdep_table(stol(optarg, FAULT_ON_ERROR, NULL));
			return;
		case 'm':
			dump_machdep_table(0);
			return;
		case 'O':
			dump_offset_table(NULL, TRUE);
			return;
		case 'o':
			oflag = TRUE;
			break;
		case 'p':
			dump_program_context();
			return;
		case 's':
			dump_symbol_table();
			return;
		case 'X':
			if (strlen(optarg) != 3) {
				argerrs++;
				break;
			}
			if (!strncmp("Xen", optarg, strlen(optarg)))
				xen_hyper_dump_xen_hyper_table(VERBOSE);
			else if (!strncmp("xen", optarg, strlen(optarg)))
				xen_hyper_dump_xen_hyper_table(!VERBOSE);
			else if (!strncmp("Dmp", optarg, strlen(optarg)))
				xen_hyper_dump_xen_hyper_dumpinfo_table(VERBOSE);
			else if (!strncmp("dmp", optarg, strlen(optarg)))
				xen_hyper_dump_xen_hyper_dumpinfo_table(!VERBOSE);
			else if (!strncmp("Dom", optarg, strlen(optarg)))
				xen_hyper_dump_xen_hyper_domain_table(VERBOSE);
			else if (!strncmp("dom", optarg, strlen(optarg)))
				xen_hyper_dump_xen_hyper_domain_table(!VERBOSE);
			else if (!strncmp("Vcp", optarg, strlen(optarg)))
				xen_hyper_dump_xen_hyper_vcpu_table(VERBOSE);
			else if (!strncmp("vcp", optarg, strlen(optarg)))
				xen_hyper_dump_xen_hyper_vcpu_table(!VERBOSE);
			else if (!strncmp("Pcp", optarg, strlen(optarg)))
				xen_hyper_dump_xen_hyper_pcpu_table(VERBOSE);
			else if (!strncmp("pcp", optarg, strlen(optarg)))
				xen_hyper_dump_xen_hyper_pcpu_table(!VERBOSE);
			else if (!strncmp("Sch", optarg, strlen(optarg)))
				xen_hyper_dump_xen_hyper_sched_table(VERBOSE);
			else if (!strncmp("sch", optarg, strlen(optarg)))
				xen_hyper_dump_xen_hyper_sched_table(!VERBOSE);
			else if (!strncmp("siz", optarg, strlen(optarg)))
				xen_hyper_dump_xen_hyper_size_table(NULL, TRUE);
			else if (!strncmp("ofs", optarg, strlen(optarg)))
				xen_hyper_dump_xen_hyper_offset_table(NULL, TRUE);
			else {
				argerrs++;
				break;
			}
 			return;
		case 'z':
			fprintf(fp, "help options:\n");
			fprintf(fp, " -a - alias data\n");
			fprintf(fp, " -b - shared buffer data\n");
			fprintf(fp, " -B - build data\n");
			fprintf(fp, " -c - numargs cache\n");
			fprintf(fp, " -M <num> machine specific\n");
			fprintf(fp, " -m - machdep_table\n");
			fprintf(fp, " -s - symbol table data\n");
			fprintf(fp, " -o - offset_table and size_table\n");
			fprintf(fp, " -p - program_context\n");
			fprintf(fp, " -h - hash_table data\n");
			fprintf(fp, " -H - hash_table data (verbose)\n");
			fprintf(fp, " -X Xen - xen table data (verbose)\n");
			fprintf(fp, " -X xen - xen table data\n");
			fprintf(fp, " -X Dmp - dumpinfo table data (verbose)\n");
			fprintf(fp, " -X dmp - dumpinfo table data\n");
			fprintf(fp, " -X Dom - domain table data (verbose)\n");
			fprintf(fp, " -X dom - domain table data\n");
			fprintf(fp, " -X Vcp - vcpu table data (verbose)\n");
			fprintf(fp, " -X vcp - vcpu table data\n");
			fprintf(fp, " -X Pcp - pcpu table data (verbose)\n");
			fprintf(fp, " -X pcp - pcpu table data\n");
			fprintf(fp, " -X Sch - schedule table data (verbose)\n");
			fprintf(fp, " -X sch - schedule table data\n");
			fprintf(fp, " -X siz - size table data\n");
			fprintf(fp, " -X ofs - offset table data\n");
			return;
                default:  
			argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, COMPLETE_HELP);

	if (!args[optind]) {
		if (oflag) 
			dump_offset_table(NULL, FALSE);
		else 
			display_help_screen("");
		return;
	}

        do {
		if (oflag) 
			dump_offset_table(args[optind], FALSE);
		else	
        		cmd_usage(args[optind], COMPLETE_HELP);
		optind++;
        } while (args[optind]);
}

/*
 * "help -x xen" output
 */
static void
xen_hyper_dump_xen_hyper_table(int verbose)
{
	char buf[XEN_HYPER_CMD_BUFSIZE];
	uint cpuid;
	int len, flag, i;

	len = 14;
	flag = XEN_HYPER_PRI_R;

	XEN_HYPER_PRI(fp, len, "cpu_data_address: ", buf, flag,
		(buf, "%lu\n", xht->cpu_data_address));
	XEN_HYPER_PRI(fp, len, "cpu_curr: ", buf, flag,
		(buf, "%u\n", xht->cpu_curr));
	XEN_HYPER_PRI(fp, len, "max_cpus: ", buf, flag,
		(buf, "%u\n", xht->max_cpus));
	XEN_HYPER_PRI(fp, len, "cores: ", buf, flag,
		(buf, "%d\n", xht->cores));
	XEN_HYPER_PRI(fp, len, "pcpus: ", buf, flag,
		(buf, "%d\n", xht->pcpus));
	XEN_HYPER_PRI(fp, len, "vcpus: ", buf, flag,
		(buf, "%d\n", xht->vcpus));
	XEN_HYPER_PRI(fp, len, "domains: ", buf, flag,
		(buf, "%d\n", xht->domains));
	XEN_HYPER_PRI(fp, len, "sys_pages: ", buf, flag,
		(buf, "%lu\n", xht->sys_pages));
	XEN_HYPER_PRI(fp, len, "crashing_cpu: ", buf, flag,
		(buf, "%d\n", xht->crashing_cpu));
	XEN_HYPER_PRI(fp, len, "crashing_vcc: ", buf, flag,
		(buf, "%p\n", xht->crashing_vcc));
	XEN_HYPER_PRI(fp, len, "max_page: ", buf, flag,
		(buf, "%lu\n", xht->max_page));
	XEN_HYPER_PRI(fp, len, "total_pages: ", buf, flag,
		(buf, "%lu\n", xht->total_pages));
	XEN_HYPER_PRI(fp, len, "cpumask: ", buf, flag,
		(buf, "%p\n", xht->cpumask));
	if (verbose && xht->cpumask) {
		xen_hyper_dump_mem(xht->cpumask,
				XEN_HYPER_SIZE(cpumask_t), sizeof(long));
	}
	XEN_HYPER_PRI(fp, len, "cpu_idxs: ", buf, flag,
		(buf, "%p\n", xht->cpu_idxs));
	if (verbose) {
		for_cpu_indexes(i, cpuid)
			fprintf(fp, "%03d : %d\n", i, cpuid);
	}
}

/*
 * "help -x dmp" output
 */
static void
xen_hyper_dump_xen_hyper_dumpinfo_table(int verbose)
{
	char buf[XEN_HYPER_CMD_BUFSIZE];
	int len, flag;

	len = 25;
	flag = XEN_HYPER_PRI_R;

	XEN_HYPER_PRI(fp, len, "note_ver: ", buf, flag,
		(buf, "%u\n", xhdit->note_ver));
	XEN_HYPER_PRI(fp, len, "context_array: ", buf, flag,
		(buf, "%p\n", xhdit->context_array));
	if (verbose && xhdit->context_array) {
		xen_hyper_dump_mem((long *)xhdit->context_array,
				sizeof(struct xen_hyper_dumpinfo_context) *
				XEN_HYPER_MAX_CPUS(), sizeof(long));
	}
	XEN_HYPER_PRI(fp, len, "context_xen_core_array: ", buf, flag,
		(buf, "%p\n", xhdit->context_xen_core_array));
	if (verbose && xhdit->context_xen_core_array) {
		xen_hyper_dump_mem((long *)xhdit->context_xen_core_array,
				sizeof(struct xen_hyper_dumpinfo_context_xen_core) *
				XEN_HYPER_MAX_CPUS(), sizeof(long));
	}
	XEN_HYPER_PRI_CONST(fp, len, "context_xen_info: ", flag|XEN_HYPER_PRI_LF);
	XEN_HYPER_PRI(fp, len, "note: ", buf, flag,
		(buf, "%lx\n", xhdit->context_xen_info.note));
	XEN_HYPER_PRI(fp, len, "pcpu_id: ", buf, flag,
		(buf, "%u\n", xhdit->context_xen_info.pcpu_id));
	XEN_HYPER_PRI(fp, len, "crash_xen_info_ptr: ", buf, flag,
		(buf, "%p\n", xhdit->context_xen_info.crash_xen_info_ptr));
	XEN_HYPER_PRI(fp, len, "crash_note_core_array: ", buf, flag,
		(buf, "%p\n", xhdit->crash_note_core_array));
	if (verbose && xhdit->crash_note_core_array) {
		xen_hyper_dump_mem((long *)xhdit->crash_note_core_array,
				xhdit->core_size * XEN_HYPER_NR_PCPUS(),
				sizeof(long));
	}
	XEN_HYPER_PRI(fp, len, "crash_note_xen_core_array: ", buf, flag,
		(buf, "%p\n", xhdit->crash_note_xen_core_array));
	if (verbose && xhdit->crash_note_xen_core_array) {
		xen_hyper_dump_mem(
				xhdit->crash_note_xen_core_array,
				xhdit->xen_core_size * XEN_HYPER_NR_PCPUS(),
				sizeof(long));
	}
	XEN_HYPER_PRI(fp, len, "crash_note_xen_info_ptr: ", buf, flag,
		(buf, "%p\n", xhdit->crash_note_xen_info_ptr));
	if (verbose && xhdit->crash_note_xen_info_ptr) {
		xen_hyper_dump_mem(
				xhdit->crash_note_xen_info_ptr,
				xhdit->xen_info_size, sizeof(long));
	}
	XEN_HYPER_PRI(fp, len, "xen_info_cpu: ", buf, flag,
		(buf, "%u\n", xhdit->xen_info_cpu));
	XEN_HYPER_PRI(fp, len, "note_size: ", buf, flag,
		(buf, "%u\n", xhdit->note_size));
	XEN_HYPER_PRI(fp, len, "core_offset: ", buf, flag,
		(buf, "%u\n", xhdit->core_offset));
	XEN_HYPER_PRI(fp, len, "core_size: ", buf, flag,
		(buf, "%u\n", xhdit->core_size));
	XEN_HYPER_PRI(fp, len, "xen_core_offset: ", buf, flag,
		(buf, "%u\n", xhdit->xen_core_offset));
	XEN_HYPER_PRI(fp, len, "xen_core_size: ", buf, flag,
		(buf, "%u\n", xhdit->xen_core_size));
	XEN_HYPER_PRI(fp, len, "xen_info_offset: ", buf, flag,
		(buf, "%u\n", xhdit->xen_info_offset));
	XEN_HYPER_PRI(fp, len, "xen_info_size: ", buf, flag,
		(buf, "%u\n", xhdit->xen_info_size));
}

/*
 * "help -x dom" output
 */
static void
xen_hyper_dump_xen_hyper_domain_table(int verbose)
{
	char buf[XEN_HYPER_CMD_BUFSIZE];
	struct xen_hyper_domain_context *dcca;
	int len, flag, i;

	len = 22;
	flag = XEN_HYPER_PRI_R;

	XEN_HYPER_PRI(fp, len, "context_array: ", buf, flag,
		(buf, "%p\n", xhdt->context_array));
	if (verbose) {
		char buf1[XEN_HYPER_CMD_BUFSIZE];
		int j;
		for (i = 0, dcca = xhdt->context_array;
		i < xhdt->context_array_cnt; i++, dcca++) {
			snprintf(buf, XEN_HYPER_CMD_BUFSIZE, "context_array[%d]: ", i);
			XEN_HYPER_PRI_CONST(fp, len, buf, flag|XEN_HYPER_PRI_LF);
			XEN_HYPER_PRI(fp, len, "domain: ", buf, flag,
				(buf, "%lx\n", dcca->domain));
			XEN_HYPER_PRI(fp, len, "domain_id: ", buf, flag,
				(buf, "%d\n", dcca->domain_id));
			XEN_HYPER_PRI(fp, len, "tot_pages: ", buf, flag,
				(buf, "%x\n", dcca->tot_pages));
			XEN_HYPER_PRI(fp, len, "max_pages: ", buf, flag,
				(buf, "%x\n", dcca->max_pages));
			XEN_HYPER_PRI(fp, len, "xenheap_pages: ", buf, flag,
				(buf, "%x\n", dcca->xenheap_pages));
			XEN_HYPER_PRI(fp, len, "shared_info: ", buf, flag,
				(buf, "%lx\n", dcca->shared_info));
			XEN_HYPER_PRI(fp, len, "sched_priv: ", buf, flag,
				(buf, "%lx\n", dcca->sched_priv));
			XEN_HYPER_PRI(fp, len, "next_in_list: ", buf, flag,
				(buf, "%lx\n", dcca->next_in_list));
			XEN_HYPER_PRI(fp, len, "domain_flags: ", buf, flag,
				(buf, "%lx\n", dcca->domain_flags));
			XEN_HYPER_PRI(fp, len, "evtchn: ", buf, flag,
				(buf, "%lx\n", dcca->evtchn));
			XEN_HYPER_PRI(fp, len, "vcpu_cnt: ", buf, flag,
				(buf, "%d\n", dcca->vcpu_cnt));
			for (j = 0; j < XEN_HYPER_MAX_VIRT_CPUS; j++) {
				snprintf(buf1, XEN_HYPER_CMD_BUFSIZE, "vcpu[%d]: ", j);
				XEN_HYPER_PRI(fp, len, buf1, buf, flag,
					(buf, "%lx\n", dcca->vcpu[j]));
			}
			XEN_HYPER_PRI(fp, len, "vcpu_context_array: ", buf, flag,
				(buf, "%p\n", dcca->vcpu_context_array));
		}
	}
	XEN_HYPER_PRI(fp, len, "context_array_cnt: ", buf, flag,
		(buf, "%d\n", xhdt->context_array_cnt));
	XEN_HYPER_PRI(fp, len, "running_domains: ", buf, flag,
		(buf, "%lu\n", xhdt->running_domains));
	XEN_HYPER_PRI(fp, len, "dom_io: ", buf, flag,
		(buf, "%p\n", xhdt->dom_io));
	XEN_HYPER_PRI(fp, len, "dom_xen: ", buf, flag,
		(buf, "%p\n", xhdt->dom_xen));
	XEN_HYPER_PRI(fp, len, "dom0: ", buf, flag,
		(buf, "%p\n", xhdt->dom0));
	XEN_HYPER_PRI(fp, len, "idle_domain: ", buf, flag,
		(buf, "%p\n", xhdt->idle_domain));
	XEN_HYPER_PRI(fp, len, "curr_domain: ", buf, flag,
		(buf, "%p\n", xhdt->curr_domain));
	XEN_HYPER_PRI(fp, len, "last: ", buf, flag,
		(buf, "%p\n", xhdt->last));
	XEN_HYPER_PRI(fp, len, "domain_struct: ", buf, flag,
		(buf, "%p\n", xhdt->domain_struct));
	XEN_HYPER_PRI(fp, len, "domain_struct_verify: ", buf, flag,
		(buf, "%p\n", xhdt->domain_struct_verify));
}

/*
 * "help -x vcp" output
 */
static void
xen_hyper_dump_xen_hyper_vcpu_table(int verbose)
{
	char buf[XEN_HYPER_CMD_BUFSIZE];
	int len, flag;

	len = 25;
	flag = XEN_HYPER_PRI_R;

	XEN_HYPER_PRI(fp, len, "vcpu_context_arrays: ", buf, flag,
		(buf, "%p\n", xhvct->vcpu_context_arrays));
	XEN_HYPER_PRI(fp, len, "vcpu_context_arrays_cnt: ", buf, flag,
		(buf, "%d\n", xhvct->vcpu_context_arrays_cnt));
	if (verbose) {
		struct xen_hyper_vcpu_context_array *vcca;
		struct xen_hyper_vcpu_context *vca;
		int i, j;

		for (i = 0, vcca = xhvct->vcpu_context_arrays;
		i < xhvct->vcpu_context_arrays_cnt; i++, vcca++) {
			snprintf(buf, XEN_HYPER_CMD_BUFSIZE, "vcpu_context_arrays[%d]: ", i);
			XEN_HYPER_PRI_CONST(fp, len, buf, flag|XEN_HYPER_PRI_LF);
			if (vcca->context_array) {
				XEN_HYPER_PRI(fp, len, "context_array: ", buf, flag,
					(buf, "%p\n", vcca->context_array));
			} else {
				XEN_HYPER_PRI(fp, len, "context_array: ", buf, flag,
					(buf, "NULL\n"));
			}
			XEN_HYPER_PRI(fp, len, "context_array_cnt: ", buf, flag,
				(buf, "%d\n", vcca->context_array_cnt));
			XEN_HYPER_PRI(fp, len, "context_array_valid: ", buf, flag,
				(buf, "%d\n", vcca->context_array_valid));
			for (j = 0, vca = vcca->context_array;
			j < vcca->context_array_cnt; j++, vca++) {
				snprintf(buf, XEN_HYPER_CMD_BUFSIZE, "context_array[%d]: ", j);
				XEN_HYPER_PRI_CONST(fp, len, buf, flag|XEN_HYPER_PRI_LF);
				XEN_HYPER_PRI(fp, len, "vcpu: ", buf, flag,
					(buf, "%lx\n", vca->vcpu));
				XEN_HYPER_PRI(fp, len, "vcpu_id: ", buf, flag,
					(buf, "%d\n", vca->vcpu_id));
				XEN_HYPER_PRI(fp, len, "processor: ", buf, flag,
					(buf, "%d\n", vca->processor));
				XEN_HYPER_PRI(fp, len, "vcpu_info: ", buf, flag,
					(buf, "%lx\n", vca->vcpu_info));
				XEN_HYPER_PRI(fp, len, "domain: ", buf, flag,
					(buf, "%lx\n", vca->domain));
				XEN_HYPER_PRI(fp, len, "next_in_list: ", buf, flag,
					(buf, "%lx\n", vca->next_in_list));
				XEN_HYPER_PRI(fp, len, "sleep_tick: ", buf, flag,
					(buf, "%lx\n", vca->sleep_tick));
				XEN_HYPER_PRI(fp, len, "sched_priv: ", buf, flag,
					(buf, "%lx\n", vca->sched_priv));
				XEN_HYPER_PRI(fp, len, "state: ", buf, flag,
					(buf, "%d\n", vca->state));
				XEN_HYPER_PRI(fp, len, "state_entry_time: ", buf, flag,
					(buf, "%llux\n", (unsigned long long)(vca->state_entry_time)));
				XEN_HYPER_PRI(fp, len, "runstate_guest: ", buf, flag,
					(buf, "%lx\n", vca->runstate_guest));
				XEN_HYPER_PRI(fp, len, "vcpu_flags: ", buf, flag,
					(buf, "%lx\n", vca->vcpu_flags));
			}
		}
	}
	XEN_HYPER_PRI(fp, len, "idle_vcpu: ", buf, flag,
		(buf, "%lx\n", xhvct->idle_vcpu));
	XEN_HYPER_PRI(fp, len, "idle_vcpu_context_array: ", buf, flag,
		(buf, "%p\n", xhvct->idle_vcpu_context_array));
	XEN_HYPER_PRI(fp, len, "last: ", buf, flag,
		(buf, "%p\n", xhvct->last));
	XEN_HYPER_PRI(fp, len, "vcpu_struct: ", buf, flag,
		(buf, "%p\n", xhvct->vcpu_struct));
	XEN_HYPER_PRI(fp, len, "vcpu_struct_verify: ", buf, flag,
		(buf, "%p\n", xhvct->vcpu_struct_verify));
}

/*
 * "help -x pcp" output
 */
static void
xen_hyper_dump_xen_hyper_pcpu_table(int verbose)
{
	char buf[XEN_HYPER_CMD_BUFSIZE];
	struct xen_hyper_pcpu_context *pcca;
	int len, flag, i;
#ifdef X86_64
	uint64_t *ist_p;
	int j;
#endif

	len = 21;
	flag = XEN_HYPER_PRI_R;

	XEN_HYPER_PRI(fp, len, "context_array: ", buf, flag,
		(buf, "%p\n", xhpct->context_array));
	if (verbose) {
		for (i = 0, pcca = xhpct->context_array;
		i < XEN_HYPER_MAX_CPUS(); i++, pcca++) {
			snprintf(buf, XEN_HYPER_CMD_BUFSIZE, "context_array %d: ", i);
			XEN_HYPER_PRI_CONST(fp, len, buf, flag|XEN_HYPER_PRI_LF);
			XEN_HYPER_PRI(fp, len, "pcpu: ", buf, flag,
				(buf, "%lx\n", pcca->pcpu));
			XEN_HYPER_PRI(fp, len, "processor_id: ", buf, flag,
				(buf, "%u\n", pcca->processor_id));
			XEN_HYPER_PRI(fp, len, "guest_cpu_user_regs: ", buf, flag,
				(buf, "%lx\n", pcca->guest_cpu_user_regs));
			XEN_HYPER_PRI(fp, len, "current_vcpu: ", buf, flag,
				(buf, "%lx\n", pcca->current_vcpu));
			XEN_HYPER_PRI(fp, len, "init_tss: ", buf, flag,
				(buf, "%lx\n", pcca->init_tss));
#ifdef X86
			XEN_HYPER_PRI(fp, len, "sp.esp0: ", buf, flag,
				(buf, "%x\n", pcca->sp.esp0));
#endif
#ifdef X86_64
			XEN_HYPER_PRI(fp, len, "sp.rsp0: ", buf, flag,
				(buf, "%lx\n", pcca->sp.rsp0));
			for (j = 0, ist_p = pcca->ist;
			j < XEN_HYPER_TSS_IST_MAX; j++, ist_p++) {
				XEN_HYPER_PRI(fp, len, "ist: ", buf, flag,
					(buf, "%lx\n", *ist_p));
			}
#endif
		}
	}
	XEN_HYPER_PRI(fp, len, "last: ", buf, flag,
		(buf, "%p\n", xhpct->last));
	XEN_HYPER_PRI(fp, len, "pcpu_struct: ", buf, flag,
		(buf, "%p\n", xhpct->pcpu_struct));
}

/*
 * "help -x sch" output
 */
static void
xen_hyper_dump_xen_hyper_sched_table(int verbose)
{
	struct xen_hyper_sched_context *schc;
	char buf[XEN_HYPER_CMD_BUFSIZE];
	int len, flag, i;

	len = 21;
	flag = XEN_HYPER_PRI_R;

	XEN_HYPER_PRI(fp, len, "name: ", buf, flag,
		(buf, "%s\n", xhscht->name));
	XEN_HYPER_PRI(fp, len, "opt_sched: ", buf, flag,
		(buf, "%s\n", xhscht->opt_sched));
	XEN_HYPER_PRI(fp, len, "sched_id: ", buf, flag,
		(buf, "%d\n", xhscht->sched_id));
	XEN_HYPER_PRI(fp, len, "scheduler: ", buf, flag,
		(buf, "%lx\n", xhscht->scheduler));
	XEN_HYPER_PRI(fp, len, "scheduler_struct: ", buf, flag,
		(buf, "%p\n", xhscht->scheduler_struct));
	XEN_HYPER_PRI(fp, len, "sched_context_array: ", buf, flag,
		(buf, "%p\n", xhscht->sched_context_array));
	if (verbose) {
		for (i = 0, schc = xhscht->sched_context_array;
		i < xht->pcpus; i++, schc++) {
			XEN_HYPER_PRI(fp, len, "sched_context_array[", buf,
				flag, (buf, "%d]\n", i));
			XEN_HYPER_PRI(fp, len, "schedule_data: ", buf, flag,
				(buf, "%lx\n", schc->schedule_data));
			XEN_HYPER_PRI(fp, len, "sched_resource: ", buf, flag,
				(buf, "%lx\n", schc->sched_resource));
			XEN_HYPER_PRI(fp, len, "curr: ", buf, flag,
				(buf, "%lx\n", schc->curr));
			XEN_HYPER_PRI(fp, len, "idle: ", buf, flag,
				(buf, "%lx\n", schc->idle));
			XEN_HYPER_PRI(fp, len, "sched_priv: ", buf, flag,
				(buf, "%lx\n", schc->sched_priv));
			XEN_HYPER_PRI(fp, len, "tick: ", buf, flag,
				(buf, "%lx\n", schc->tick));
		}
	}
}

/*
 * "help -x siz" output
 */
static void
xen_hyper_dump_xen_hyper_size_table(char *spec, ulong makestruct)
{
	char buf[XEN_HYPER_CMD_BUFSIZE];
	int len, flag;

	len = 23;
	flag = XEN_HYPER_PRI_R;

	XEN_HYPER_PRI(fp, len, "ELF_Prstatus: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.ELF_Prstatus));
	XEN_HYPER_PRI(fp, len, "ELF_Signifo: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.ELF_Signifo));
	XEN_HYPER_PRI(fp, len, "ELF_Gregset: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.ELF_Gregset));
	XEN_HYPER_PRI(fp, len, "ELF_Timeval: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.ELF_Timeval));
	XEN_HYPER_PRI(fp, len, "arch_domain: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.arch_domain));
	XEN_HYPER_PRI(fp, len, "arch_shared_info: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.arch_shared_info));
	XEN_HYPER_PRI(fp, len, "cpu_info: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.cpu_info));
	XEN_HYPER_PRI(fp, len, "cpu_time: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.cpu_time));
	XEN_HYPER_PRI(fp, len, "cpu_user_regs: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.cpu_user_regs));
	XEN_HYPER_PRI(fp, len, "cpumask_t: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.cpumask_t));
	XEN_HYPER_PRI(fp, len, "cpuinfo_ia64: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.cpuinfo_ia64));
	XEN_HYPER_PRI(fp, len, "cpuinfo_x86: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.cpuinfo_x86));
	XEN_HYPER_PRI(fp, len, "crash_note_t: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.crash_note_t));
	XEN_HYPER_PRI(fp, len, "crash_note_core_t: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.crash_note_core_t));
	XEN_HYPER_PRI(fp, len, "crash_note_xen_t: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.crash_note_xen_t));
	XEN_HYPER_PRI(fp, len, "crash_note_xen_core_t: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.crash_note_xen_core_t));
	XEN_HYPER_PRI(fp, len, "crash_note_xen_info_t: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.crash_note_xen_info_t));
	XEN_HYPER_PRI(fp, len, "crash_xen_core_t: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.crash_xen_core_t));
	XEN_HYPER_PRI(fp, len, "crash_xen_info_t: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.crash_xen_info_t));
	XEN_HYPER_PRI(fp, len, "domain: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.domain));
#ifdef IA64
	XEN_HYPER_PRI(fp, len, "mm_struct: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.mm_struct));
#endif
	XEN_HYPER_PRI(fp, len, "note_buf_t: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.note_buf_t));
	XEN_HYPER_PRI(fp, len, "schedule_data: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.schedule_data));
	XEN_HYPER_PRI(fp, len, "sched_resource: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.sched_resource));
	XEN_HYPER_PRI(fp, len, "scheduler: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.scheduler));
	XEN_HYPER_PRI(fp, len, "shared_info: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.shared_info));
	XEN_HYPER_PRI(fp, len, "timer: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.timer));
	XEN_HYPER_PRI(fp, len, "tss: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.tss));
	XEN_HYPER_PRI(fp, len, "vcpu: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.vcpu));
	XEN_HYPER_PRI(fp, len, "vcpu_runstate_info: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.vcpu_runstate_info));
	XEN_HYPER_PRI(fp, len, "xen_crash_xen_regs_t: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.xen_crash_xen_regs_t));
}

/*
 * "help -x ofs" output
 */
static void
xen_hyper_dump_xen_hyper_offset_table(char *spec, ulong makestruct)
{
	char buf[XEN_HYPER_CMD_BUFSIZE];
	int len, flag;

	len = 45;
	flag = XEN_HYPER_PRI_R;

	XEN_HYPER_PRI(fp, len, "ELF_Prstatus_pr_info: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Prstatus_pr_info));
	XEN_HYPER_PRI(fp, len, "ELF_Prstatus_pr_cursig: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Prstatus_pr_cursig));
	XEN_HYPER_PRI(fp, len, "ELF_Prstatus_pr_sigpend: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Prstatus_pr_sigpend));
	XEN_HYPER_PRI(fp, len, "ELF_Prstatus_pr_sighold: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Prstatus_pr_sighold));
	XEN_HYPER_PRI(fp, len, "ELF_Prstatus_pr_pid: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Prstatus_pr_pid));
	XEN_HYPER_PRI(fp, len, "ELF_Prstatus_pr_ppid: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Prstatus_pr_ppid));
	XEN_HYPER_PRI(fp, len, "ELF_Prstatus_pr_pgrp: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Prstatus_pr_pgrp));
	XEN_HYPER_PRI(fp, len, "ELF_Prstatus_pr_sid: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Prstatus_pr_sid));
	XEN_HYPER_PRI(fp, len, "ELF_Prstatus_pr_stime: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Prstatus_pr_stime));
	XEN_HYPER_PRI(fp, len, "ELF_Prstatus_pr_cutime: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Prstatus_pr_cutime));
	XEN_HYPER_PRI(fp, len, "ELF_Prstatus_pr_cstime: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Prstatus_pr_cstime));
	XEN_HYPER_PRI(fp, len, "ELF_Prstatus_pr_reg: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Prstatus_pr_reg));
	XEN_HYPER_PRI(fp, len, "ELF_Prstatus_pr_fpvalid: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Prstatus_pr_fpvalid));
	XEN_HYPER_PRI(fp, len, "ELF_Timeval_tv_sec: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Timeval_tv_sec));
	XEN_HYPER_PRI(fp, len, "ELF_Timeval_tv_usec: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Timeval_tv_usec));

#ifdef IA64
	XEN_HYPER_PRI(fp, len, "arch_domain_mm: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.arch_domain_mm));
#endif

	XEN_HYPER_PRI(fp, len, "arch_shared_info_max_pfn: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.arch_shared_info_max_pfn));
	XEN_HYPER_PRI(fp, len, "arch_shared_info_pfn_to_mfn_frame_list_list: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.arch_shared_info_pfn_to_mfn_frame_list_list));
	XEN_HYPER_PRI(fp, len, "arch_shared_info_nmi_reason: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.arch_shared_info_nmi_reason));

	XEN_HYPER_PRI(fp, len, "cpu_info_guest_cpu_user_regs: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.cpu_info_guest_cpu_user_regs));
	XEN_HYPER_PRI(fp, len, "cpu_info_processor_id: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.cpu_info_processor_id));
	XEN_HYPER_PRI(fp, len, "cpu_info_current_vcpu: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.cpu_info_current_vcpu));

	XEN_HYPER_PRI(fp, len, "cpu_time_local_tsc_stamp: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.cpu_time_local_tsc_stamp));
	XEN_HYPER_PRI(fp, len, "cpu_time_stime_local_stamp: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.cpu_time_stime_local_stamp));
	XEN_HYPER_PRI(fp, len, "cpu_time_stime_master_stamp: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.cpu_time_stime_master_stamp));
	XEN_HYPER_PRI(fp, len, "cpu_time_tsc_scale: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.cpu_time_tsc_scale));
	XEN_HYPER_PRI(fp, len, "cpu_time_calibration_timer: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.cpu_time_calibration_timer));

	XEN_HYPER_PRI(fp, len, "crash_note_t_core: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.crash_note_t_core));
	XEN_HYPER_PRI(fp, len, "crash_note_t_xen: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.crash_note_t_xen));
	XEN_HYPER_PRI(fp, len, "crash_note_t_xen_regs: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.crash_note_t_xen_regs));
	XEN_HYPER_PRI(fp, len, "crash_note_t_xen_info: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.crash_note_t_xen_info));

	XEN_HYPER_PRI(fp, len, "crash_note_core_t_note: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.crash_note_core_t_note));
	XEN_HYPER_PRI(fp, len, "crash_note_core_t_desc: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.crash_note_core_t_desc));

	XEN_HYPER_PRI(fp, len, "crash_note_xen_t_note: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.crash_note_xen_t_note));
	XEN_HYPER_PRI(fp, len, "crash_note_xen_t_desc: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.crash_note_xen_t_desc));

	XEN_HYPER_PRI(fp, len, "crash_note_xen_core_t_note: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.crash_note_xen_core_t_note));
	XEN_HYPER_PRI(fp, len, "crash_note_xen_core_t_desc: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.crash_note_xen_core_t_desc));

	XEN_HYPER_PRI(fp, len, "crash_note_xen_info_t_note: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.crash_note_xen_info_t_note));
	XEN_HYPER_PRI(fp, len, "crash_note_xen_info_t_desc: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.crash_note_xen_info_t_desc));

	XEN_HYPER_PRI(fp, len, "domain_page_list: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_page_list));
	XEN_HYPER_PRI(fp, len, "domain_xenpage_list: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_xenpage_list));
	XEN_HYPER_PRI(fp, len, "domain_domain_id: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_domain_id));
	XEN_HYPER_PRI(fp, len, "domain_tot_pages: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_tot_pages));
	XEN_HYPER_PRI(fp, len, "domain_max_pages: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_max_pages));
	XEN_HYPER_PRI(fp, len, "domain_xenheap_pages: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_xenheap_pages));
	XEN_HYPER_PRI(fp, len, "domain_shared_info: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_shared_info));
	XEN_HYPER_PRI(fp, len, "domain_sched_priv: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_sched_priv));
	XEN_HYPER_PRI(fp, len, "domain_next_in_list: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_next_in_list));
	XEN_HYPER_PRI(fp, len, "domain_domain_flags: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_domain_flags));
	XEN_HYPER_PRI(fp, len, "domain_evtchn: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_evtchn));
	XEN_HYPER_PRI(fp, len, "domain_is_hvm: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_is_hvm));
	XEN_HYPER_PRI(fp, len, "domain_guest_type: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_guest_type));
	XEN_HYPER_PRI(fp, len, "domain_is_privileged: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_is_privileged));
	XEN_HYPER_PRI(fp, len, "domain_debugger_attached: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_debugger_attached));
	if (XEN_HYPER_VALID_MEMBER(domain_is_polling)) {
		XEN_HYPER_PRI(fp, len, "domain_is_polling: ", buf, flag,
			(buf, "%ld\n", xen_hyper_offset_table.domain_is_polling));
	}
	XEN_HYPER_PRI(fp, len, "domain_is_dying: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_is_dying));
	/* Only one of next both exists but print both, ones value is -1. */
	XEN_HYPER_PRI(fp, len, "domain_is_paused_by_controller: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_is_paused_by_controller));
	XEN_HYPER_PRI(fp, len, "domain_controller_pause_count: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_controller_pause_count));
	XEN_HYPER_PRI(fp, len, "domain_is_shutting_down: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_is_shutting_down));
	XEN_HYPER_PRI(fp, len, "domain_is_shut_down: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_is_shut_down));
	XEN_HYPER_PRI(fp, len, "domain_vcpu: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_vcpu));
	XEN_HYPER_PRI(fp, len, "domain_arch: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_arch));

#ifdef IA64
	XEN_HYPER_PRI(fp, len, "mm_struct_pgd: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.mm_struct_pgd));
#endif

	XEN_HYPER_PRI(fp, len, "schedule_data_schedule_lock: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.schedule_data_schedule_lock));
	XEN_HYPER_PRI(fp, len, "schedule_data_curr: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.schedule_data_curr));
	XEN_HYPER_PRI(fp, len, "schedule_data_idle: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.schedule_data_idle));
	XEN_HYPER_PRI(fp, len, "schedule_data_sched_priv: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.schedule_data_sched_priv));
	XEN_HYPER_PRI(fp, len, "schedule_data_s_timer: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.schedule_data_s_timer));
	XEN_HYPER_PRI(fp, len, "schedule_data_tick: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.schedule_data_tick));

	XEN_HYPER_PRI(fp, len, "scheduler_name: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.scheduler_name));
	XEN_HYPER_PRI(fp, len, "scheduler_opt_name: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.scheduler_opt_name));
	XEN_HYPER_PRI(fp, len, "scheduler_sched_id: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.scheduler_sched_id));
	XEN_HYPER_PRI(fp, len, "scheduler_init: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.scheduler_init));
	XEN_HYPER_PRI(fp, len, "scheduler_tick: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.scheduler_tick));
	XEN_HYPER_PRI(fp, len, "scheduler_init_vcpu: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.scheduler_init_vcpu));
	XEN_HYPER_PRI(fp, len, "scheduler_destroy_domain: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.scheduler_destroy_domain));
	XEN_HYPER_PRI(fp, len, "scheduler_sleep: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.scheduler_sleep));
	XEN_HYPER_PRI(fp, len, "scheduler_wake: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.scheduler_wake));
	XEN_HYPER_PRI(fp, len, "scheduler_set_affinity: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.scheduler_set_affinity));
	XEN_HYPER_PRI(fp, len, "scheduler_do_schedule: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.scheduler_do_schedule));
	XEN_HYPER_PRI(fp, len, "scheduler_adjust: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.scheduler_adjust));
	XEN_HYPER_PRI(fp, len, "scheduler_dump_settings: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.scheduler_dump_settings));
	XEN_HYPER_PRI(fp, len, "scheduler_dump_cpu_state: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.scheduler_dump_cpu_state));

	XEN_HYPER_PRI(fp, len, "shared_info_vcpu_info: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.shared_info_vcpu_info));
	XEN_HYPER_PRI(fp, len, "shared_info_evtchn_pending: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.shared_info_evtchn_pending));
	XEN_HYPER_PRI(fp, len, "shared_info_evtchn_mask: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.shared_info_evtchn_mask));
	XEN_HYPER_PRI(fp, len, "shared_info_arch: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.shared_info_arch));

	XEN_HYPER_PRI(fp, len, "timer_expires: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.timer_expires));
	XEN_HYPER_PRI(fp, len, "timer_cpu: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.timer_cpu));
	XEN_HYPER_PRI(fp, len, "timer_function: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.timer_function));
	XEN_HYPER_PRI(fp, len, "timer_data: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.timer_data));
	XEN_HYPER_PRI(fp, len, "timer_heap_offset: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.timer_heap_offset));
	XEN_HYPER_PRI(fp, len, "timer_killed: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.timer_killed));

	XEN_HYPER_PRI(fp, len, "tss_struct_rsp0: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.tss_rsp0));
	XEN_HYPER_PRI(fp, len, "tss_struct_esp0: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.tss_esp0));

	XEN_HYPER_PRI(fp, len, "vcpu_vcpu_id: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_vcpu_id));
	XEN_HYPER_PRI(fp, len, "vcpu_processor: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_processor));
	XEN_HYPER_PRI(fp, len, "vcpu_vcpu_info: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_vcpu_info));
	XEN_HYPER_PRI(fp, len, "vcpu_domain: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_domain));
	XEN_HYPER_PRI(fp, len, "vcpu_next_in_list: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_next_in_list));
	XEN_HYPER_PRI(fp, len, "vcpu_timer: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_timer));
	XEN_HYPER_PRI(fp, len, "vcpu_sleep_tick: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_sleep_tick));
	XEN_HYPER_PRI(fp, len, "vcpu_poll_timer: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_poll_timer));
	XEN_HYPER_PRI(fp, len, "vcpu_sched_priv: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_sched_priv));
	XEN_HYPER_PRI(fp, len, "vcpu_runstate: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_runstate));
	XEN_HYPER_PRI(fp, len, "vcpu_runstate_guest: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_runstate_guest));
	XEN_HYPER_PRI(fp, len, "vcpu_vcpu_flags: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_vcpu_flags));
	XEN_HYPER_PRI(fp, len, "vcpu_pause_count: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_pause_count));
	XEN_HYPER_PRI(fp, len, "vcpu_virq_to_evtchn: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_virq_to_evtchn));
	XEN_HYPER_PRI(fp, len, "vcpu_cpu_affinity: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_cpu_affinity));
	XEN_HYPER_PRI(fp, len, "vcpu_nmi_addr: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_nmi_addr));
	XEN_HYPER_PRI(fp, len, "vcpu_vcpu_dirty_cpumask: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_vcpu_dirty_cpumask));
	XEN_HYPER_PRI(fp, len, "vcpu_arch: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_arch));
	XEN_HYPER_PRI(fp, len, "vcpu_runstate_info_state: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_runstate_info_state));
	XEN_HYPER_PRI(fp, len, "vcpu_runstate_info_state_entry_time: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_runstate_info_state_entry_time));
	XEN_HYPER_PRI(fp, len, "vcpu_runstate_info_time: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_runstate_info_time));
#ifdef IA64
	XEN_HYPER_PRI(fp, len, "vcpu_thread_ksp: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_thread_ksp));
#endif
}

/*
 * dump specified memory with specified size.
 */
#define DSP_BYTE_SIZE 16

static void
xen_hyper_dump_mem(void *mem, ulong len, int dsz)
{
	long i, max;
	void *mem_w = mem;

	if (!len || 
	(dsz != SIZEOF_8BIT && dsz != SIZEOF_16BIT &&
	 dsz != SIZEOF_32BIT && dsz != SIZEOF_64BIT))
		return;
	max = len / dsz + (len % dsz ? 1 : 0);
	for (i = 0; i <  max; i++) {
		if (i != 0 && !(i % (DSP_BYTE_SIZE / dsz)))
			fprintf(fp, "\n");
		if (i == 0 || !(i % (DSP_BYTE_SIZE / dsz)))
			fprintf(fp, "%p : ", mem_w);
		if (dsz == SIZEOF_8BIT)
			fprintf(fp, "%02x ", *(uint8_t *)mem_w);
		else if (dsz == SIZEOF_16BIT)
			fprintf(fp, "%04x ", *(uint16_t *)mem_w);
		else if (dsz == SIZEOF_32BIT)
			fprintf(fp, "%08x ", *(uint32_t *)mem_w);
		else if (dsz == SIZEOF_64BIT)
			fprintf(fp, "%016llx ", *(unsigned long long *)mem_w);
		mem_w = (char *)mem_w + dsz;
	}
	fprintf(fp, "\n");
}
#endif
