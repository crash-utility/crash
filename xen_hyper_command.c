/*
 *  xen_hyper_command.c
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

#ifdef X86
char *xhregt[] = {
	"ebx", "ecx", "edx", "esi", "edi", "ebp", "eax", "ds", "es",
	"fs", "gs", "orig_eax", "eip", "cs", "eflags", "esp", "ss",
	NULL
};
#endif

#ifdef X86_64
char *xhregt[] = {
	"r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8",
	"rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags",
	"rsp", "ss", "fs", "gs", "ds", "es", "fs", "gs",
	NULL
};
#endif

#ifdef IA64
char *xhregt[] = {
	"aaa", "bbb",
	NULL
};
#endif

static void xen_hyper_do_domain(struct xen_hyper_cmd_args *da);
static void xen_hyper_do_doms(struct xen_hyper_cmd_args *da);
static void xen_hyper_show_doms(struct xen_hyper_domain_context *dc);
static void xen_hyper_do_dumpinfo(ulong flag, struct xen_hyper_cmd_args *dia);
static void xen_hyper_show_dumpinfo(ulong flag,
	struct xen_hyper_dumpinfo_context *dic);
static void xen_hyper_do_pcpus(ulong flag, struct xen_hyper_cmd_args *pca);
static void xen_hyper_show_pcpus(ulong flag, struct xen_hyper_pcpu_context *pcc);
static void xen_hyper_do_sched(ulong flag, struct xen_hyper_cmd_args *scha);
static void xen_hyper_show_sched(ulong flag, struct xen_hyper_sched_context *schc);
static void xen_hyper_do_vcpu(struct xen_hyper_cmd_args *vca);
static void xen_hyper_do_vcpus(struct xen_hyper_cmd_args *vca);
static void xen_hyper_show_vcpus(struct xen_hyper_vcpu_context *vcc);
static char *xen_hyper_domain_to_type(ulong domain, int *type, char *buf, int verbose);
static char *xen_hyper_domain_context_to_type(
	struct xen_hyper_domain_context *dc, int *type, char *buf, int verbose);
static int xen_hyper_str_to_domain_context(char *string, ulong *value,
	struct xen_hyper_domain_context **dcp);
static int xen_hyper_str_to_dumpinfo_context(char *string, ulong *value, struct xen_hyper_dumpinfo_context **dicp);
static int xen_hyper_strvcpu_to_vcpu_context(char *string, ulong *value,
	struct xen_hyper_vcpu_context **vccp);
static int
xen_hyper_strid_to_vcpu_context(char *strdom, char *strvc, ulong *valdom,
	ulong *valvc, struct xen_hyper_vcpu_context **vccp);
static int xen_hyper_str_to_pcpu_context(char *string, ulong *value,
	struct xen_hyper_pcpu_context **pccp);

/*
 *  Display domain struct.
 */
void
xen_hyper_cmd_domain(void)
{
	struct xen_hyper_cmd_args da;
	struct xen_hyper_domain_context *dc;
	ulong val;
        int c, cnt, type, bogus;

	BZERO(&da, sizeof(struct xen_hyper_cmd_args));
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

	cnt = bogus = 0;
        while (args[optind]) {
		if (IS_A_NUMBER(args[optind])) {
			type = xen_hyper_str_to_domain_context(args[optind], &val, &dc);
			switch (type) {
			case XEN_HYPER_STR_DID:
			case XEN_HYPER_STR_DOMAIN:
				da.value[cnt] = val;
				da.type[cnt] = type;
				da.addr[cnt] = dc->domain;
				da.context[cnt] = dc;
				cnt++;
				break;
			case XEN_HYPER_STR_INVALID:
				error(INFO, "invalid domain or id value: %s\n\n",
					args[optind]);
				bogus++;
			}
		} else {
			error(FATAL, "invalid address: %s\n",
				args[optind]);
		}
		optind++;
	}
	da.cnt = cnt;
	if (bogus && !cnt) {
		return;
	}
	
	xen_hyper_do_domain(&da);
}

/*
 *  Do the work requested by xen_hyper_cmd_dom().
 */
static void
xen_hyper_do_domain(struct xen_hyper_cmd_args *da)
{
	int i;

	if (da->cnt) {
		if (da->cnt == 1) {
			xhdt->last = da->context[0];
		}
		for (i = 0; i < da->cnt; i++) {
			dump_struct("domain", da->addr[i], 0);
		}
	} else {
		dump_struct("domain", xhdt->last->domain, 0);
	}
}

/*
 *  Display domain status.
 */
void
xen_hyper_cmd_doms(void)
{
	struct xen_hyper_cmd_args da;
	struct xen_hyper_domain_context *dc;
	ulong val;
        int c, cnt, type, bogus;

	BZERO(&da, sizeof(struct xen_hyper_cmd_args));
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

	cnt = bogus = 0;
        while (args[optind]) {
		if (IS_A_NUMBER(args[optind])) {
			type = xen_hyper_str_to_domain_context(args[optind], &val, &dc);
			switch (type) {
			case XEN_HYPER_STR_DID:
			case XEN_HYPER_STR_DOMAIN:
				da.value[cnt] = val;
				da.type[cnt] = type;
				da.addr[cnt] = dc->domain;
				da.context[cnt] = dc;
				cnt++;
				break;
			case XEN_HYPER_STR_INVALID:
				error(INFO, "invalid domain or id value: %s\n\n",
					args[optind]);
				bogus++;
			}
		} else {
			error(FATAL, "invalid address: %s\n",
				args[optind]);
		}
		optind++;
	}
	da.cnt = cnt;
	if (bogus && !cnt) {
		return;
	}
	
	xen_hyper_do_doms(&da);
}

/*
 *  Do the work requested by xen_hyper_cmd_doms().
 */
static void
xen_hyper_do_doms(struct xen_hyper_cmd_args *da)
{
	struct xen_hyper_domain_context *dca;
	char buf1[XEN_HYPER_CMD_BUFSIZE];
	char buf2[XEN_HYPER_CMD_BUFSIZE];
	int i;

	sprintf(buf1, "   DID  %s ST T ",
		mkstring(buf2, VADDR_PRLEN, CENTER|RJUST, "DOMAIN"));
	mkstring(&buf1[strlen(buf1)], INT_PRLEN, CENTER|RJUST, "MAXPAGE");
	strncat(buf1, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf1)-1);
	mkstring(&buf1[strlen(buf1)], INT_PRLEN, CENTER|RJUST, "TOTPAGE");
	strncat(buf1, " VCPU ", XEN_HYPER_CMD_BUFSIZE-strlen(buf1)-1);
	mkstring(&buf1[strlen(buf1)], VADDR_PRLEN, CENTER|RJUST, "SHARED_I");
	strncat(buf1, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf1)-1);
	mkstring(&buf1[strlen(buf1)], LONG_PRLEN, CENTER|RJUST, "P2M_MFN");
	fprintf(fp, "%s\n", buf1);
	if (da->cnt) {
		for (i = 0; i < da->cnt; i++) {
			xen_hyper_show_doms(da->context[i]);
		}
	} else {
		for (i = 0, dca=xhdt->context_array; i < XEN_HYPER_NR_DOMAINS();
			i++, dca++) {
			xen_hyper_show_doms(dca);
		}
	}
}

static void
xen_hyper_show_doms(struct xen_hyper_domain_context *dc)
{
	char *act, *crash;
	uint cpuid;
	int type, i, j;
	struct xen_hyper_pcpu_context *pcc;
#if defined(X86) || defined(X86_64)
	char *shared_info;
#elif defined(IA64)
	char *domain_struct;
	ulong pgd;
#endif
	char buf1[XEN_HYPER_CMD_BUFSIZE];
	char buf2[XEN_HYPER_CMD_BUFSIZE];

	if (!(dc->domain)) {
		return;
	}

#if defined(X86) || defined(X86_64)
	shared_info = GETBUF(XEN_HYPER_SIZE(shared_info));
	if (dc->shared_info) {
		if (!readmem(dc->shared_info, KVADDR, shared_info,
			XEN_HYPER_SIZE(shared_info), "fill_shared_info_struct",
			ACTIVE() ? (RETURN_ON_ERROR|QUIET) : RETURN_ON_ERROR)) {
			error(WARNING, "cannot fill shared_info struct.\n");
			BZERO(shared_info, XEN_HYPER_SIZE(shared_info));
		}
	}
#elif defined(IA64)
	if ((domain_struct = xen_hyper_read_domain(dc->domain)) == NULL) {
		error(FATAL, "cannot read domain.\n");
	}
#endif
	act = NULL;
	for_cpu_indexes(i, cpuid)
	{
		pcc = xen_hyper_id_to_pcpu_context(cpuid);
		for (j = 0; j < dc->vcpu_cnt; j++) {
			if (pcc->current_vcpu == dc->vcpu[j]) {
				act = ">";
				break;
			}
		}
		if (act)	break;
	}
	if (act == NULL)	act = " ";
	if (xht->crashing_vcc && dc->domain == xht->crashing_vcc->domain) {
		crash = "*";
	} else {
		crash = " ";
	}
	sprintf(buf1, "%s%s%5d ", act, crash, dc->domain_id);
	mkstring(&buf1[strlen(buf1)], VADDR_PRLEN, CENTER|LONG_HEX|RJUST, (char *)(dc->domain));
	strncat(buf1, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf1)-1);
	sprintf(&buf1[strlen(buf1)], "%s ",
		xen_hyper_domain_state_string(dc, buf2, !VERBOSE));
	sprintf(&buf1[strlen(buf1)], "%s ",
		xen_hyper_domain_context_to_type(dc, &type, buf2, !VERBOSE));
	mkstring(&buf1[strlen(buf1)], INT_PRLEN, CENTER|INT_HEX|RJUST,
		MKSTR((long)(dc->max_pages)));
	strncat(buf1, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf1)-1);
	mkstring(&buf1[strlen(buf1)], INT_PRLEN, CENTER|INT_HEX|RJUST,
		MKSTR((long)(dc->tot_pages)));
	sprintf(&buf1[strlen(buf1)], " %3d  ", dc->vcpu_cnt);
	mkstring(&buf1[strlen(buf1)], VADDR_PRLEN, CENTER|LONG_HEX|RJUST,
		MKSTR(dc->shared_info));
	strncat(buf1, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf1)-1);
#if defined(X86) || defined(X86_64)
	if (dc->shared_info) {
		mkstring(&buf1[strlen(buf1)], LONG_PRLEN, CENTER|LONG_HEX|RJUST,
			MKSTR(ULONG(shared_info +
				XEN_HYPER_OFFSET(shared_info_arch) +
				XEN_HYPER_OFFSET(arch_shared_info_pfn_to_mfn_frame_list_list)))
		);
	} else {
		mkstring(&buf1[strlen(buf1)], LONG_PRLEN, CENTER|RJUST, "----");
	}
	FREEBUF(shared_info);
#elif defined(IA64)
	pgd = ULONG(domain_struct + XEN_HYPER_OFFSET(domain_arch) +
		XEN_HYPER_OFFSET(arch_domain_mm) +
		XEN_HYPER_OFFSET(mm_struct_pgd));
	if (pgd) {
		mkstring(&buf1[strlen(buf1)], LONG_PRLEN,
			CENTER|LONG_HEX|RJUST,
			MKSTR((pgd - DIRECTMAP_VIRT_START) >> machdep->pageshift));
	} else {
		mkstring(&buf1[strlen(buf1)], LONG_PRLEN, CENTER|RJUST, "----");
	}
#endif

	fprintf(fp, "%s\n", buf1);
}

/*
 * Display ELF Notes information.
 */
void
xen_hyper_cmd_dumpinfo(void)
{
	struct xen_hyper_cmd_args dia;
	ulong flag;
	ulong val;
	struct xen_hyper_dumpinfo_context *dic;
	int c, cnt, type, bogus;

	BZERO(&dia, sizeof(struct xen_hyper_cmd_args));
	flag = val =0;
	dic = NULL;
        while ((c = getopt(argcnt, args, "rt")) != EOF) {
                switch(c)
                {
		case 't':
			flag |= XEN_HYPER_DUMPINFO_TIME;
                        break;
		case 'r':
			flag |= XEN_HYPER_DUMPINFO_REGS;
                        break;
                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

	cnt = bogus = 0;
        while (args[optind]) {
		if (IS_A_NUMBER(args[optind])) {
			type = xen_hyper_str_to_dumpinfo_context(args[optind], &val, &dic);
			switch (type)
			{
			case XEN_HYPER_STR_PCID:
			case XEN_HYPER_STR_ADDR:
				dia.value[cnt] = val;
				dia.type[cnt] = type;
				dia.context[cnt] = dic;
				cnt++;
				break;

			case XEN_HYPER_STR_INVALID:
				error(INFO, "invalid note address or id "
					"value: %s\n\n", args[optind]);
				bogus++;
				break;
			}
		} else {
			error(INFO, "invalid note address or id "
				"value: %s\n\n", args[optind]);
		}
		optind++;
	}
	dia.cnt = cnt;
	if (!cnt && bogus) {
		return;
	}
	
	xen_hyper_do_dumpinfo(flag, &dia);
}

/*
 * Do the work requested by xen_hyper_cmd_dumpinfo().
 */
static void
xen_hyper_do_dumpinfo(ulong flag, struct xen_hyper_cmd_args *dia)
{
	struct xen_hyper_dumpinfo_context *dic;
	char buf[XEN_HYPER_CMD_BUFSIZE];
	int i, cnt;

	if (dia->cnt) {
		cnt = dia->cnt;
	} else {
		cnt = XEN_HYPER_NR_PCPUS();
	}
	for (i = 0; i < cnt; i++) {
		if (i == 0 || flag & XEN_HYPER_DUMPINFO_REGS ||
			flag & XEN_HYPER_DUMPINFO_TIME) {
			if (i) {
				fprintf(fp, "\n");
			}
			sprintf(buf, " PCID ");
			mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|RJUST, "ENOTE");
//			sprintf(&buf[strlen(buf)], "  PID   PPID  PGRP  SID");
			strncat(buf, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf)-1);
			mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|RJUST, "CORE");
			if (xhdit->note_ver >= XEN_HYPER_ELF_NOTE_V2) {
				strncat(buf, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf)-1);
				mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|RJUST, "XEN_CORE");
			}
			if (xhdit->note_ver >= XEN_HYPER_ELF_NOTE_V3) {
				strncat(buf, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf)-1);
				mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|RJUST, "XEN_INFO");
			}
			fprintf(fp, "%s\n", buf);
		}
		if (dia->cnt) {
			dic = dia->context[i];
		} else {
			dic = xen_hyper_id_to_dumpinfo_context(xht->cpu_idxs[i]);
		}
		xen_hyper_show_dumpinfo(flag, dic);
	}
}

static void
xen_hyper_show_dumpinfo(ulong flag, struct xen_hyper_dumpinfo_context *dic)
{
	char buf[XEN_HYPER_CMD_BUFSIZE];
	char *note_buf;
	ulong addr;
	ulong *regs;
	long tv_sec, tv_usec;
	int i, regcnt;

	if (!dic || !dic->note) {
		return;
	}

	note_buf = dic->ELF_Prstatus_ptr;
	sprintf(buf, "%5d ", dic->pcpu_id);
	mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|LONG_HEX|RJUST,
		MKSTR(dic->note));

#if 0
	pid = INT(note_buf + XEN_HYPER_OFFSET(ELF_Prstatus_pr_pid));
	sprintf(&buf[strlen(buf)], " %5d ", pid);
	pid = INT(note_buf + XEN_HYPER_OFFSET(ELF_Prstatus_pr_ppid));
	sprintf(&buf[strlen(buf)], "%5d ", pid);
	pid = INT(note_buf + XEN_HYPER_OFFSET(ELF_Prstatus_pr_pgrp));
	sprintf(&buf[strlen(buf)], "%5d ", pid);
	pid = INT(note_buf + XEN_HYPER_OFFSET(ELF_Prstatus_pr_sid));
	sprintf(&buf[strlen(buf)], "%5d", pid);
#endif
	strncat(buf, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf)-1);
	mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|LONG_HEX|RJUST,
		MKSTR(dic->note));
	if (xhdit->note_ver >= XEN_HYPER_ELF_NOTE_V2) {
		strncat(buf, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf)-1);
		mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|LONG_HEX|RJUST,
		MKSTR(dic->note + xhdit->core_size));
	}
	if (xhdit->note_ver >= XEN_HYPER_ELF_NOTE_V3) {
		strncat(buf, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf)-1);
		if (xhdit->xen_info_cpu == dic->pcpu_id)
			mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|LONG_HEX|RJUST,
			MKSTR(dic->note + xhdit->core_size + xhdit->xen_core_size));
		else
			mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|RJUST, "--");

	}

	fprintf(fp, "%s\n", buf);

	if (flag & XEN_HYPER_DUMPINFO_TIME) {
		sprintf(buf, "             ");
		mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|RJUST, "tv_sec");
		strncat(buf, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf)-1);
		mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|RJUST, "tv_usec");
		fprintf(fp, "%s\n", buf);

		addr = (ulong)note_buf +
			XEN_HYPER_OFFSET(ELF_Prstatus_pr_utime);
		for (i = 0; i < 4; i++, addr += XEN_HYPER_SIZE(ELF_Timeval)) {
			switch (i)
			{
			case 0: 
				sprintf(buf, "  pr_utime   ");
				break;
			case 1: 
				sprintf(buf, "  pr_stime   ");
				break;
			case 2: 
				sprintf(buf, "  pr_cutime  ");
				break;
			case 3: 
				sprintf(buf, "  pr_cstime  ");
				break;
			}
			tv_sec = LONG(addr +
				XEN_HYPER_OFFSET(ELF_Timeval_tv_sec));
			tv_usec = LONG(addr +
				XEN_HYPER_OFFSET(ELF_Timeval_tv_sec) +
				XEN_HYPER_OFFSET(ELF_Timeval_tv_usec));
			mkstring(&buf[strlen(buf)], LONG_PRLEN, CENTER|LONG_HEX|RJUST,
				MKSTR(tv_sec));
			strncat(buf, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf)-1);
			mkstring(&buf[strlen(buf)], LONG_PRLEN, CENTER|LONG_HEX|RJUST,
				MKSTR(tv_usec));
			fprintf(fp, "%s\n", buf);
		}
	}

	if (flag & XEN_HYPER_DUMPINFO_REGS) {
		regcnt = XEN_HYPER_SIZE(ELF_Gregset) / sizeof(long);
		addr = (ulong)note_buf +
			XEN_HYPER_OFFSET(ELF_Prstatus_pr_reg);
		regs = (ulong *)addr;
		fprintf(fp, "Register information(%lx):\n",
			dic->note + xhdit->core_offset + XEN_HYPER_OFFSET(ELF_Prstatus_pr_reg));
		for (i = 0; i < regcnt; i++, regs++) {
			if (xhregt[i] == NULL) {
				break;
			}
			fprintf(fp, "  %s = ", xhregt[i]);
			fprintf(fp, "0x%s\n",
				mkstring(buf, LONG_PRLEN, LONG_HEX|LJUST, MKSTR(*regs)));
		}
	}
}

/*
 * Dump the Xen conring in chronological order.
 */
void
xen_hyper_cmd_log(void)
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
	
	xen_hyper_dump_log();
}

void
xen_hyper_dump_log(void)
{
	uint conringp, warp, len, idx, i;
	ulong conring;
	char *buf;
	char last = 0;
	uint32_t conring_size;

	if (get_symbol_type("conring", NULL, NULL) == TYPE_CODE_ARRAY)
		conring = symbol_value("conring");
	else
		get_symbol_data("conring", sizeof(ulong), &conring);

	get_symbol_data("conringp", sizeof(uint), &conringp);

	if (symbol_exists("conring_size"))
		get_symbol_data("conring_size", sizeof(uint32_t), &conring_size);
	else
		conring_size = XEN_HYPER_CONRING_SIZE;

	if (conringp >= conring_size) {
		idx = conringp & (conring_size - 1);
		len = conring_size;
		warp = TRUE;
	} else {
		idx = 0;
		len = conringp;
		warp = FALSE;
	}

	buf = GETBUF(conring_size);
	readmem(conring, KVADDR, buf, conring_size,
		"conring contents", FAULT_ON_ERROR);

wrap_around:
	for (i = idx; i < len; i++) {
		if (buf[i]) {
			fputc(ascii(buf[i]) ? buf[i] : '.', fp);
			last = buf[i];
		}
	}
	if (warp) {
		len = idx;
		idx = 0;
		warp = FALSE;
		goto wrap_around;
	}
	if (last != '\n') {
		fprintf(fp, "\n");
	}
	FREEBUF(buf);
}

/*
 *  Display physical cpu information.
 */
void
xen_hyper_cmd_pcpus(void)
{
	struct xen_hyper_cmd_args pca;
	struct xen_hyper_pcpu_context *pcc;
	ulong flag;
	ulong val;
        int c, cnt, type, bogus;

	BZERO(&pca, sizeof(struct xen_hyper_cmd_args));
	flag= 0;
        while ((c = getopt(argcnt, args, "rt")) != EOF) {
                switch(c)
                {
		case 'r':
			flag |= XEN_HYPER_PCPUS_REGS;
			break;
		case 't':
			flag |= XEN_HYPER_PCPUS_TSS;
			break;
                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

	cnt = bogus = 0;
        while (args[optind]) {
		if (IS_A_NUMBER(args[optind])) {
			type = xen_hyper_str_to_pcpu_context(args[optind], &val, &pcc);
			switch (type) {
			case XEN_HYPER_STR_PCID:
			case XEN_HYPER_STR_PCPU:
				pca.value[cnt] = val;
				pca.type[cnt] = type;
				pca.addr[cnt] = pcc->pcpu;
				pca.context[cnt] = pcc;
				cnt++;
				break;
			case XEN_HYPER_STR_INVALID:
				error(INFO, "invalid pcpu or id value: %s\n\n",
					args[optind]);
				bogus++;
			}
		} else {
			error(FATAL, "invalid address: %s\n",
				args[optind]);
		}
		optind++;
	}
	pca.cnt = cnt;
	if (bogus && !cnt) {
		return;
	}
	
	xen_hyper_do_pcpus(flag, &pca);
}

/*
 *  Do the work requested by xen_hyper_cmd_pcpu().
 */
static void
xen_hyper_do_pcpus(ulong flag, struct xen_hyper_cmd_args *pca)
{
	struct xen_hyper_pcpu_context *pcc;
	uint cpuid;
	int i;

	if (pca->cnt) {
		for (i = 0; i < pca->cnt; i++) {
			xen_hyper_show_pcpus(flag, pca->context[i]);
			flag |= XEN_HYPER_PCPUS_1STCALL;
		}
	} else {
		for_cpu_indexes(i, cpuid)
		{
			pcc = xen_hyper_id_to_pcpu_context(cpuid);
			xen_hyper_show_pcpus(flag, pcc);
			flag |= XEN_HYPER_PCPUS_1STCALL;
		}
	}
}

static void
xen_hyper_show_pcpus(ulong flag, struct xen_hyper_pcpu_context *pcc)
{
	char *act = "  ";
	char buf[XEN_HYPER_CMD_BUFSIZE];

	if (!(pcc->pcpu)) {
		return;
	}
	if (XEN_HYPER_CRASHING_CPU() == pcc->processor_id) {
		act = " *";
	}
	if ((flag & XEN_HYPER_PCPUS_REGS) || (flag & XEN_HYPER_PCPUS_TSS) ||
	!(flag & XEN_HYPER_PCPUS_1STCALL)) {
		if (((flag & XEN_HYPER_PCPUS_REGS) || (flag & XEN_HYPER_PCPUS_TSS)) &&
		(flag & XEN_HYPER_PCPUS_1STCALL)) {
			fprintf(fp, "\n");
		}
		sprintf(buf, "   PCID ");
		mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|RJUST, "PCPU");
		strncat(buf, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf)-1);
		mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|RJUST, "CUR-VCPU");
		strncat(buf, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf)-1);
		mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|RJUST, "TSS");
		fprintf(fp, "%s\n", buf);
	}

	sprintf(buf, "%s%5d ", act, pcc->processor_id);
	mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|LONG_HEX|RJUST, MKSTR(pcc->pcpu));
	strncat(buf, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf)-1);
	mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|LONG_HEX|RJUST,
		MKSTR(pcc->current_vcpu));
	strncat(buf, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf)-1);
	mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|LONG_HEX|RJUST,
		MKSTR(pcc->init_tss));
	fprintf(fp, "%s\n", buf);
	if (flag & XEN_HYPER_PCPUS_REGS) {
		fprintf(fp, "Register information:\n");
		dump_struct("cpu_user_regs", pcc->guest_cpu_user_regs, 0);
	}
	if (flag & XEN_HYPER_PCPUS_TSS) {
		fprintf(fp, "init_tss information:\n");
		dump_struct("tss_struct", pcc->init_tss, 0);
	}
}

/*
 *  Display schedule info.
 */
void
xen_hyper_cmd_sched(void)
{
	struct xen_hyper_cmd_args scha;
	struct xen_hyper_pcpu_context *pcc;
	ulong flag;
	ulong val;
        int c, cnt, type, bogus;

	BZERO(&scha, sizeof(struct xen_hyper_cmd_args));
	flag = 0;
        while ((c = getopt(argcnt, args, "v")) != EOF) {
                switch(c)
                {
		case 'v':
			flag |= XEN_HYPER_SCHED_VERBOSE;
			break;

                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

	cnt = bogus = 0;
        while (args[optind]) {
		if (IS_A_NUMBER(args[optind])) {
			type = xen_hyper_str_to_pcpu_context(args[optind], &val, &pcc);
			switch (type) {
			case XEN_HYPER_STR_PCID:
				scha.value[cnt] = val;
				scha.type[cnt] = type;
				scha.context[cnt] = &xhscht->sched_context_array[val];
				cnt++;
				break;
			case XEN_HYPER_STR_PCPU:
			case XEN_HYPER_STR_INVALID:
				error(INFO, "invalid pcpu id value: %s\n\n",
					args[optind]);
				bogus++;
			}
		} else {
			error(FATAL, "invalid address: %s\n",
				args[optind]);
		}
		optind++;
	}
	scha.cnt = cnt;
	if (bogus && !cnt) {
		return;
	}
	
	xen_hyper_do_sched(flag, &scha);
}

/*
 *  Do the work requested by xen_hyper_cmd_pcpu().
 */
static void
xen_hyper_do_sched(ulong flag, struct xen_hyper_cmd_args *scha)
{
	struct xen_hyper_sched_context *schc;
	uint cpuid;
	int i;

	fprintf(fp, "Scheduler name : %s\n\n", xhscht->name);

	if (scha->cnt) {
		for (i = 0; i < scha->cnt; i++) {
			xen_hyper_show_sched(flag, scha->context[i]);
			flag |= XEN_HYPER_SCHED_1STCALL;
		}
	} else {
		for_cpu_indexes(i, cpuid)
		{
			schc = &xhscht->sched_context_array[cpuid];
			xen_hyper_show_sched(flag, schc);
			flag |= XEN_HYPER_SCHED_1STCALL;
		}
	}
}

static void
xen_hyper_show_sched(ulong flag, struct xen_hyper_sched_context *schc)
{
	char buf[XEN_HYPER_CMD_BUFSIZE];

	if (!(schc->schedule_data)) {
		return;
	}
	if ((flag & XEN_HYPER_SCHED_VERBOSE) ||
	!(flag & XEN_HYPER_SCHED_1STCALL)) {
		if ((flag & XEN_HYPER_SCHED_1STCALL) &&
		(flag & XEN_HYPER_SCHED_VERBOSE)) {
			fprintf(fp, "\n");
		}
		sprintf(buf, "  CPU  ");
		mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|RJUST, "SCH-DATA");
		strncat(buf, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf)-1);
		mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|RJUST, "SCH-PRIV");
		strncat(buf, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf)-1);
		mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|RJUST, "CUR-VCPU");
		strncat(buf, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf)-1);
		mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|RJUST, "IDL-VCPU");
		if (XEN_HYPER_VALID_MEMBER(schedule_data_tick)) {
			strncat(buf, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf)-1);
			mkstring(&buf[strlen(buf)], LONG_PRLEN, CENTER|RJUST, "TICK");
		}
		fprintf(fp, "%s\n", buf);
	}

	sprintf(buf, "%5d  ", schc->cpu_id);
	mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|LONG_HEX|RJUST,
		MKSTR(schc->schedule_data));
	strncat(buf, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf)-1);
	mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|LONG_HEX|RJUST,
		MKSTR(schc->sched_priv));
	strncat(buf, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf)-1);
	mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|LONG_HEX|RJUST,
		MKSTR(schc->curr));
	strncat(buf, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf)-1);
	mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|LONG_HEX|RJUST,
		MKSTR(schc->idle));
	if (XEN_HYPER_VALID_MEMBER(schedule_data_tick)) {
		strncat(buf, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf)-1);
		mkstring(&buf[strlen(buf)], LONG_PRLEN, CENTER|LONG_HEX|RJUST,
			MKSTR(schc->tick));
	}
	fprintf(fp, "%s\n", buf);
	if (flag & XEN_HYPER_SCHED_VERBOSE) {
		;
	}
}

/*
 *  Display general system info.
 */
void
xen_hyper_cmd_sys(void)
{
        int c;
	ulong sflag;

	sflag = FALSE;

        while ((c = getopt(argcnt, args, "c")) != EOF) {
                switch(c)
                {
		case 'c':
			sflag = TRUE;
			break;

                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

        if (!args[optind]) {
		if (sflag)
			fprintf(fp, "No support argument\n");
			/* display config info here. */
		else
			xen_hyper_display_sys_stats();
		return;
	}
}

/*
 *  Display system stats at init-time or for the sys command.
 */
void
xen_hyper_display_sys_stats(void)
{
        struct new_utsname *uts;
        char buf1[XEN_HYPER_CMD_BUFSIZE];
        char buf2[XEN_HYPER_CMD_BUFSIZE];
	ulong mhz;
	int len, flag;

	uts = &xht->utsname;
	len = 11;
	flag = XEN_HYPER_PRI_R;

        /*
         *  It's now safe to unlink the remote namelist.
         */
        if (pc->flags & UNLINK_NAMELIST) {
                unlink(pc->namelist);
                pc->flags &= ~UNLINK_NAMELIST;
                pc->flags |= NAMELIST_UNLINKED;
        }

	if (REMOTE()) {
		switch (pc->flags & 
			(NAMELIST_LOCAL|NAMELIST_UNLINKED|NAMELIST_SAVED))
		{
		case NAMELIST_UNLINKED:
			XEN_HYPER_PRI(fp, len, "KERNEL: ", buf1, flag,
				(buf1, "%s  (temporary)\n", pc->namelist));
			break;

		case (NAMELIST_UNLINKED|NAMELIST_SAVED):
		case NAMELIST_LOCAL:
			XEN_HYPER_PRI(fp, len, "KERNEL: ", buf1, flag,
				(buf1, "%s\n", pc->namelist));
			break;

		}
	} else {
        	if (pc->system_map) {
			XEN_HYPER_PRI(fp, len, "SYSTEM MAP: ", buf1, flag,
				(buf1, "%s\n", pc->system_map));
			XEN_HYPER_PRI(fp, len, "DEBUG KERNEL: ", buf1, flag,
				(buf1, "%s\n", pc->namelist));
		} else {
			XEN_HYPER_PRI(fp, len, "KERNEL: ", buf1, flag,
				(buf1, "%s\n", pc->namelist));
		}
	}

	if (pc->debuginfo_file) {
		XEN_HYPER_PRI(fp, len, "DEBUGINFO: ", buf1, flag,
			(buf1, "%s\n", pc->debuginfo_file));
	} else if (pc->namelist_debug) {
		XEN_HYPER_PRI(fp, len, "DEBUG KERNEL: ", buf1, flag,
			(buf1, "%s\n", pc->namelist_debug));
	}

	XEN_HYPER_PRI_CONST(fp, len, "DUMPFILE: ", flag);
        if (ACTIVE()) {
		if (REMOTE_ACTIVE()) 
			fprintf(fp, "%s@%s  (remote live system)\n",
			    	pc->server_memsrc, pc->server);
		else
                	fprintf(fp, "%s\n", pc->live_memsrc);
	} else {
		if (REMOTE_DUMPFILE())
                	fprintf(fp, "%s@%s  (remote dumpfile)", 
				pc->server_memsrc, pc->server);
		else
                	fprintf(fp, "%s", pc->dumpfile);

		fprintf(fp, "\n");
	}

	XEN_HYPER_PRI(fp, len, "CPUS: ", buf1, flag,
		(buf1, "%d\n", XEN_HYPER_NR_PCPUS()));
	XEN_HYPER_PRI(fp, len, "DOMAINS: ", buf1, flag,
		(buf1, "%d\n", XEN_HYPER_NR_DOMAINS()));
	/* !!!Display a date here if it can be found. */
	XEN_HYPER_PRI(fp, len, "UPTIME: ", buf1, flag,
		(buf1, "%s\n", (xen_hyper_get_uptime_hyper() ? 
		 convert_time(xen_hyper_get_uptime_hyper(), buf2) : "--:--:--")));
	/* !!!Display a version here if it can be found. */
	XEN_HYPER_PRI_CONST(fp, len, "MACHINE: ", flag);
	if (strlen(uts->machine)) {
		fprintf(fp, "%s  ", uts->machine);
	} else {
		fprintf(fp, "unknown  ");
	}
	if ((mhz = machdep->processor_speed()))
		fprintf(fp, "(%ld Mhz)\n", mhz);
	else
		fprintf(fp, "(unknown Mhz)\n");
	XEN_HYPER_PRI(fp, len, "MEMORY: ", buf1, flag,
		(buf1, "%s\n", get_memory_size(buf2)));
	if (XENDUMP_DUMPFILE() && (kt->xen_flags & XEN_SUSPEND))
		return;
}

/*
 *  Display vcpu struct.
 */
void
xen_hyper_cmd_vcpu(void)
{
	struct xen_hyper_cmd_args vca;
	struct xen_hyper_vcpu_context *vcc;
	ulong flag;
	ulong valvc, valdom;
        int c, cnt, type, bogus;

	BZERO(&vca, sizeof(struct xen_hyper_cmd_args));
	flag = 0;
        while ((c = getopt(argcnt, args, "i")) != EOF) {
                switch(c)
                {
		case 'i':
			flag |= XEN_HYPER_VCPUS_ID;
                        break;
                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

	cnt = bogus = 0;
        while (args[optind]) {
		if (IS_A_NUMBER(args[optind])) {
			if (flag & XEN_HYPER_VCPUS_ID) {
				type = xen_hyper_strid_to_vcpu_context(
					args[optind], args[optind+1],
					&valdom, &valvc, &vcc);
			} else {
				type = xen_hyper_strvcpu_to_vcpu_context(
					args[optind], &valvc, &vcc);
			}
			switch (type) {
			case XEN_HYPER_STR_VCID:
			case XEN_HYPER_STR_VCPU:
				vca.value[cnt] = valvc;
				vca.type[cnt] = type;
				vca.addr[cnt] = vcc->vcpu;
				vca.context[cnt] = vcc;
				cnt++;
				break;
			case XEN_HYPER_STR_INVALID:
				error(INFO, "invalid vcpu or id value: %s\n\n",
					args[optind]);
				bogus++;
			}
		} else {
			error(FATAL, "invalid address: %s\n",
				args[optind]);
		}
		optind++;
		if (flag & XEN_HYPER_VCPUS_ID) optind++;
	}
	vca.cnt = cnt;
	if (bogus && !cnt) {
		return;
	}
	
	xen_hyper_do_vcpu(&vca);
}

/*
 *  Do the work requested by xen_hyper_cmd_vcpu().
 */
static void
xen_hyper_do_vcpu(struct xen_hyper_cmd_args *vca)
{
	int i;

	if (vca->cnt) {
		if (vca->cnt == 1) {
			xhvct->last = vca->context[0];
		}
		for (i = 0; i < vca->cnt; i++) {
			dump_struct("vcpu", vca->addr[i], 0);
		}
	} else {
		dump_struct("vcpu", xhvct->last->vcpu, 0);
	}
}

/*
 *  Display vcpu status.
 */
void
xen_hyper_cmd_vcpus(void)
{
	struct xen_hyper_cmd_args vca;
	struct xen_hyper_vcpu_context *vcc;
	ulong flag;
	ulong valvc, valdom;
        int c, cnt, type, bogus;

	BZERO(&vca, sizeof(struct xen_hyper_cmd_args));
	flag = 0;
        while ((c = getopt(argcnt, args, "i")) != EOF) {
                switch(c)
                {
		case 'i':
			flag |= XEN_HYPER_VCPUS_ID;
                        break;
                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

	cnt = bogus = 0;
        while (args[optind]) {
		if (IS_A_NUMBER(args[optind])) {
			if (flag & XEN_HYPER_VCPUS_ID) {
				type = xen_hyper_strid_to_vcpu_context(
					args[optind], args[optind+1],
					&valdom, &valvc, &vcc);
			} else {
				type = xen_hyper_strvcpu_to_vcpu_context(
					args[optind], &valvc, &vcc);
			}
			switch (type) {
			case XEN_HYPER_STR_VCID:
			case XEN_HYPER_STR_VCPU:
				vca.value[cnt] = valvc;
				vca.type[cnt] = type;
				vca.addr[cnt] = vcc->vcpu;
				vca.context[cnt] = vcc;
				cnt++;
				break;
			case XEN_HYPER_STR_INVALID:
				error(INFO, "invalid vcpu or id value: %s\n\n",
					args[optind]);
				bogus++;
			}
		} else {
			error(FATAL, "invalid address: %s\n",
				args[optind]);
		}
		optind++;
	}
	vca.cnt = cnt;
	if (bogus && !cnt) {
		return;
	}
	
	xen_hyper_do_vcpus(&vca);
}

/*
 *  Do the work requested by xen_hyper_cmd_vcpus().
 */
static void
xen_hyper_do_vcpus(struct xen_hyper_cmd_args *vca)
{
	struct xen_hyper_vcpu_context_array *vcca;
	struct xen_hyper_vcpu_context *vcc;
	char buf1[XEN_HYPER_CMD_BUFSIZE];
	char buf2[XEN_HYPER_CMD_BUFSIZE];
	int i, j;

	fprintf(fp, "   VCID  PCID %s ST T DOMID %s\n",
		mkstring(buf1, VADDR_PRLEN, CENTER|RJUST, "VCPU"),
		mkstring(buf2, VADDR_PRLEN, CENTER|RJUST, "DOMAIN"));
	if (vca->cnt) {
		for (i = 0; i < vca->cnt; i++) {
			xen_hyper_show_vcpus(vca->context[i]);
		}
	} else {
		for (i = 0, vcca = xhvct->vcpu_context_arrays;
			i < XEN_HYPER_NR_DOMAINS(); i++, vcca++) {
			for (j = 0, vcc = vcca->context_array;
				j < vcca->context_array_valid; j++, vcc++) {
				xen_hyper_show_vcpus(vcc);
			}
		}
	}
}

static void
xen_hyper_show_vcpus(struct xen_hyper_vcpu_context *vcc)
{
	int type;
	char *act, *crash;
	char buf[XEN_HYPER_CMD_BUFSIZE];
	struct xen_hyper_pcpu_context *pcc;
	domid_t domid;

	if (!(vcc->vcpu)) {
		return;
	}
	if((pcc = xen_hyper_id_to_pcpu_context(vcc->processor))) {
		if (pcc->current_vcpu == vcc->vcpu) {
			act = ">";
		} else {
			act = " ";
		}
	} else {
		act = " ";
	}
	if (xht->crashing_vcc && vcc->vcpu == xht->crashing_vcc->vcpu) {
		crash = "*";
	} else {
		crash = " ";
	}
	sprintf(buf, "%s%s%5d %5d ", act, crash, vcc->vcpu_id, vcc->processor);
	mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|LONG_HEX|RJUST,
		MKSTR(vcc->vcpu));
	strncat(buf, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf)-1);
	xen_hyper_vcpu_state_string(vcc, &buf[strlen(buf)], !VERBOSE);
	strncat(buf, " ", XEN_HYPER_CMD_BUFSIZE-strlen(buf)-1);
	xen_hyper_domain_to_type(vcc->domain, &type, &buf[strlen(buf)], !VERBOSE);
	if ((domid = xen_hyper_domain_to_id(vcc->domain)) == XEN_HYPER_DOMAIN_ID_INVALID) {
		sprintf(&buf[strlen(buf)], " ????? ");
	} else {
		sprintf(&buf[strlen(buf)], " %5d ", domid);
	}
	mkstring(&buf[strlen(buf)], VADDR_PRLEN, CENTER|LONG_HEX|RJUST,
		MKSTR(vcc->domain));
	fprintf(fp, "%s\n", buf);
}



/*
 *  Get string for domain status.
 *  - This may need some data in domain struct.
 */
char *
xen_hyper_domain_state_string(struct xen_hyper_domain_context *dc,
	char *buf, int verbose)
{
	ulong stat;

	stat = xen_hyper_domain_state(dc);

	if (stat == XEN_HYPER_DOMF_ERROR) {
		sprintf(buf, verbose ? "(unknown)" : "??");
	} else if (XEN_HYPER_VALID_MEMBER(domain_domain_flags)) {
		if (stat & XEN_HYPER_DOMF_shutdown) {
			sprintf(buf, verbose ? "DOMAIN_SHUTDOWN" : "SF");
		} else if (stat & XEN_HYPER_DOMF_dying) {
			sprintf(buf, verbose ? "DOMAIN_DYING" : "DY");
		} else if (stat & XEN_HYPER_DOMF_ctrl_pause) {
			sprintf(buf, verbose ? "DOMAIN_CTRL_PAUSE" : "CP");
		} else if (stat & XEN_HYPER_DOMF_polling) {
			sprintf(buf, verbose ? "DOMAIN_POLLING" : "PO");
		} else if (stat & XEN_HYPER_DOMF_paused) {
			sprintf(buf, verbose ? "DOMAIN_PAUSED" : "PA");
		} else {
			sprintf(buf, verbose ? "DOMAIN_RUNNING" : "RU");
		}
	} else {
		if (stat & XEN_HYPER_DOMS_shutdown) {
			sprintf(buf, verbose ? "DOMAIN_SHUTDOWN" : "SF");
		} else if (stat & XEN_HYPER_DOMS_shuttingdown) {
			sprintf(buf, verbose ? "DOMAIN_SHUTTINGDOWN" : "SH");
		} else if (stat & XEN_HYPER_DOMS_dying) {
			sprintf(buf, verbose ? "DOMAIN_DYING" : "DY");
		} else if (stat & XEN_HYPER_DOMS_ctrl_pause) {
			sprintf(buf, verbose ? "DOMAIN_CTRL_PAUSE" : "CP");
		} else if (stat & XEN_HYPER_DOMS_polling) {
			sprintf(buf, verbose ? "DOMAIN_POLLING" : "PO");
		} else {
			sprintf(buf, verbose ? "DOMAIN_RUNNING" : "RU");
		}
	}

	return buf;
}

/*
 *  Get string for vcpu status.
 *  - This may need some data in vcpu struct.
 */
char *
xen_hyper_vcpu_state_string(struct xen_hyper_vcpu_context *vcc,
	char *buf, int verbose)
{
	int stat;

	stat = xen_hyper_vcpu_state(vcc);

	if (stat == XEN_HYPER_RUNSTATE_ERROR) {
		sprintf(buf, verbose ? "(unknown)" : "??");
	} else if (stat == XEN_HYPER_RUNSTATE_running ||
		stat == XEN_HYPER_RUNSTATE_runnable) {
		sprintf(buf, verbose ? "VCPU_RUNNING" : "RU");
	} else if (stat == XEN_HYPER_RUNSTATE_blocked) {
		sprintf(buf, verbose ? "VCPU_BLOCKED" : "BL");
	} else if (stat == XEN_HYPER_RUNSTATE_offline) {
		sprintf(buf, verbose ? "VCPU_OFFLINE" : "OF");
	} else {
		sprintf(buf, verbose ? "(unknown)" : "??");
	}

	return buf;
}

/*
 *  Get domain type from domain address.
 */
static char *
xen_hyper_domain_to_type(ulong domain, int *type, char *buf, int verbose)
{
	struct xen_hyper_domain_context *dc;

	if ((dc = xen_hyper_domain_to_domain_context(domain)) == NULL) {
		error(WARNING, "cannot get context from domain address.\n");
		return NULL;
	}
	return xen_hyper_domain_context_to_type(dc, type, buf, verbose);
}

/*
 *  Get domain type from domain context.
 */
static char *
xen_hyper_domain_context_to_type(struct xen_hyper_domain_context *dc, int *type,
	char *buf, int verbose)
{
	if (!dc) {
		*type = XEN_HYPER_DOMAIN_TYPE_INVALID;
		return NULL;
	} else if (dc->domain_id == XEN_HYPER_DOMID_IO) {
		*type = XEN_HYPER_DOMAIN_TYPE_IO;
		sprintf(buf, verbose ? "dom_io" : "O");
	} else if (dc->domain_id == XEN_HYPER_DOMID_XEN) {
		*type = XEN_HYPER_DOMAIN_TYPE_XEN;
		sprintf(buf, verbose ? "dom_xen" : "X");
	} else if (dc->domain_id == XEN_HYPER_DOMID_IDLE) {
		*type = XEN_HYPER_DOMAIN_TYPE_IDLE;
		sprintf(buf, verbose ? "idle domain" : "I");
	} else if (dc == xhdt->dom0) {
		*type = XEN_HYPER_DOMAIN_TYPE_DOM0;
		sprintf(buf, verbose ? "domain 0" : "0");
	} else {
		*type = XEN_HYPER_DOMAIN_TYPE_GUEST;
		sprintf(buf, verbose ? "domain U" : "U");
	}
	return buf;
}

/*
 * Check a type for value. And return domain context.
 */
static int
xen_hyper_str_to_domain_context(char *string, ulong *value,
	struct xen_hyper_domain_context **dcp)
{
	ulong dvalue, hvalue;
	int found, type;
	char *s;
	struct xen_hyper_domain_context *dc_did, *dc_ddc, *dc_hid, *dc_hdc;

	if (string == NULL) {
		error(INFO, "received NULL string\n");
		return STR_INVALID;
	}

	s = string;
        dvalue = hvalue = BADADDR;

        if (decimal(s, 0))
                dvalue = dtol(s, RETURN_ON_ERROR, NULL);

        if (hexadecimal(s, 0)) {
        	if (STRNEQ(s, "0x") || STRNEQ(s, "0X"))
                	s += 2;
		if (strlen(s) <= MAX_HEXADDR_STRLEN) 
                	hvalue = htol(s, RETURN_ON_ERROR, NULL);
	}

        found = 0;
        dc_did = dc_ddc = dc_hid = dc_hdc = NULL;
	type = XEN_HYPER_STR_INVALID;

	if (dvalue != BADADDR) {
		if ((dc_did = xen_hyper_id_to_domain_context(dvalue)))
			found++;
	        if ((dc_ddc = xen_hyper_domain_to_domain_context(dvalue)))
			found++;
	}

	if ((hvalue != BADADDR) && (dvalue != hvalue)) {
	        if ((dc_hid = xen_hyper_id_to_domain_context(hvalue)))
			found++;
	        if ((dc_hdc = xen_hyper_domain_to_domain_context(hvalue)))
			found++;
	}

	switch (found) 
	{
	case 2: 
		if (dc_did && dc_hid) {      
                	*dcp = dc_did;      
                	*value = dvalue;   
                	type = STR_PID;
		}
		break;

	case 1: 
		if (dc_did) {
			*dcp = dc_did;
			*value = dvalue;
			type = XEN_HYPER_STR_DID;
		}

		if (dc_ddc) {
			*dcp = dc_ddc;
			*value = dvalue;
			type = XEN_HYPER_STR_DOMAIN;
		}

		if (dc_hid) {
			*dcp = dc_hid;
			*value = hvalue;
			type = XEN_HYPER_STR_DID;
		}

		if (dc_hdc) {
			*dcp = dc_hdc;
			*value = hvalue;
			type = XEN_HYPER_STR_DOMAIN;
		}
		break;
	}

	return type;
}



/*
 *  Display a vcpu context.
 */
void
xen_hyper_show_vcpu_context(struct xen_hyper_vcpu_context *vcc)
{
	char buf[XEN_HYPER_CMD_BUFSIZE];
	struct xen_hyper_pcpu_context *pcc;
	struct xen_hyper_domain_context *dc;
	int len, flag;

	len = 6;
	len += pc->flags & RUNTIME ? 0 : 5;
	flag = XEN_HYPER_PRI_R;

	if (!(pcc = xen_hyper_id_to_pcpu_context(vcc->processor))) {
		error(WARNING, "cannot get pcpu context vcpu belongs.\n");
		return;
	}
	if (!(dc = xen_hyper_domain_to_domain_context(vcc->domain))) {
		error(WARNING, "cannot get domain context vcpu belongs.\n");
		return;
	}
	XEN_HYPER_PRI(fp, len, "PCPU-ID: ", buf, flag,
		(buf, "%d\n", vcc->processor));
	XEN_HYPER_PRI(fp, len, "PCPU: ", buf, flag,
		(buf, "%lx\n", pcc->pcpu));
	XEN_HYPER_PRI(fp, len, "VCPU-ID: ", buf, flag,
		(buf, "%d\n", vcc->vcpu_id));
	XEN_HYPER_PRI(fp, len, "VCPU: ", buf, flag,
		(buf, "%lx  ", vcc->vcpu));
	fprintf(fp, "(%s)\n", xen_hyper_vcpu_state_string(vcc, buf, VERBOSE));
	XEN_HYPER_PRI(fp, len, "DOMAIN-ID: ", buf, flag,
		(buf, "%d\n", dc->domain_id));
	XEN_HYPER_PRI(fp, len, "DOMAIN: ", buf, flag,
		(buf, "%lx  ", vcc->domain));
	fprintf(fp, "(%s)\n", xen_hyper_domain_state_string(dc, buf, VERBOSE));
	XEN_HYPER_PRI_CONST(fp, len, "STATE: ", flag);
	if (machdep->flags & HWRESET) {
		fprintf(fp, "HARDWARE RESET");
	} else if (machdep->flags & INIT) {
		fprintf(fp, "INIT");
	} else if (xen_hyper_is_vcpu_crash(vcc)) {
		fprintf(fp, "CRASH");
	} else {
		fprintf(fp, "ACTIVE");
	}

	fprintf(fp, "\n");
}

/*
 * Check a type for value. And return dump information context address.
 */
static int
xen_hyper_str_to_dumpinfo_context(char *string, ulong *value,
	struct xen_hyper_dumpinfo_context **dicp)
{
	ulong dvalue, hvalue;
	struct xen_hyper_dumpinfo_context *note_did, *note_hid;
	struct xen_hyper_dumpinfo_context *note_dad, *note_had;
	int found, type;
	char *s;

	if (string == NULL) {
		error(INFO, "received NULL string\n");
		return STR_INVALID;
	}

	s = string;
	dvalue = hvalue = BADADDR;

	if (decimal(s, 0))
		dvalue = dtol(s, RETURN_ON_ERROR, NULL);
	if (hexadecimal(s, 0)) {
		if (STRNEQ(s, "0x") || STRNEQ(s, "0X"))
			s += 2;
		if (strlen(s) <= MAX_HEXADDR_STRLEN)
			hvalue = htol(s, RETURN_ON_ERROR, NULL);
	}

	found = 0;
	note_did = note_hid = note_dad = note_had = 0;
	type = XEN_HYPER_STR_INVALID;

	if (dvalue != BADADDR) {
		if (dvalue > XEN_HYPER_MAX_CPUS()) {
			note_dad = xen_hyper_note_to_dumpinfo_context(dvalue);
		} else {
			note_did = xen_hyper_id_to_dumpinfo_context(dvalue);
		}
		found++;
	}
	if ((hvalue != BADADDR)) {
		if (hvalue > XEN_HYPER_MAX_CPUS()) {
			note_had = xen_hyper_note_to_dumpinfo_context(hvalue);
		} else {
			note_hid = xen_hyper_id_to_dumpinfo_context(hvalue);
		}
		found++;
	}

	switch (found)
	{
	case 2:
		if (note_did && note_hid) {
			*value = dvalue;
			*dicp = note_did;
			type = XEN_HYPER_STR_PCID;
		}
		break;
	case 1:
		if (note_did) {
			*value = dvalue;
			*dicp = note_did;
			type = XEN_HYPER_STR_PCID;
		}

		if (note_hid) {
			*value = hvalue;
			*dicp = note_hid;
			type = XEN_HYPER_STR_PCID;
		}

		if (note_dad) {
			*value = dvalue;
			*dicp = note_dad;
			type = XEN_HYPER_STR_ADDR;
		}

		if (note_had) {
			*value = hvalue;
			*dicp = note_had;
			type = XEN_HYPER_STR_ADDR;
		}
		break;
	}

	return type;
}

/*
 * Check a type for value. And return vcpu context.
 */
static int
xen_hyper_strvcpu_to_vcpu_context(char *string, ulong *value,
	struct xen_hyper_vcpu_context **vccp)
{
	ulong dvalue, hvalue;
	int found, type;
	char *s;
	struct xen_hyper_vcpu_context *vcc_dvc, *vcc_hvc;

	if (string == NULL) {
		error(INFO, "received NULL string\n");
		return STR_INVALID;
	}

	s = string;
        dvalue = hvalue = BADADDR;

        if (decimal(s, 0))
                dvalue = dtol(s, RETURN_ON_ERROR, NULL);

        if (hexadecimal(s, 0)) {
        	if (STRNEQ(s, "0x") || STRNEQ(s, "0X"))
                	s += 2;
		if (strlen(s) <= MAX_HEXADDR_STRLEN) 
                	hvalue = htol(s, RETURN_ON_ERROR, NULL);
	}

        found = 0;
        vcc_dvc = vcc_hvc = NULL;
	type = XEN_HYPER_STR_INVALID;

	if (dvalue != BADADDR) {
	        if ((vcc_dvc = xen_hyper_vcpu_to_vcpu_context(dvalue)))
			found++;
	}

	if ((hvalue != BADADDR) && (dvalue != hvalue)) {
	        if ((vcc_hvc = xen_hyper_vcpu_to_vcpu_context(hvalue)))
			found++;
	}

	switch (found) 
	{
	case 1: 
		if (vcc_dvc) {
			*vccp = vcc_dvc;
			*value = dvalue;
			type = XEN_HYPER_STR_VCPU;
		}

		if (vcc_hvc) {
			*vccp = vcc_hvc;
			*value = hvalue;
			type = XEN_HYPER_STR_VCPU;
		}
		break;
	}

	return type;
}

/*
 * Check a type for id value. And return vcpu context.
 */
static int
xen_hyper_strid_to_vcpu_context(char *strdom, char *strvc, ulong *valdom,
	ulong *valvc, struct xen_hyper_vcpu_context **vccp)
{
	ulong dvalue, hvalue;
	int found, type;
	char *s;
	struct xen_hyper_vcpu_context *vcc_did, *vcc_hid;
	struct xen_hyper_domain_context *dc;

	if (strdom == NULL || strvc == NULL) {
		error(INFO, "received NULL string\n");
		return STR_INVALID;
	}

	if (xen_hyper_str_to_domain_context(strdom, valdom, &dc) ==
	XEN_HYPER_STR_INVALID) {
		error(INFO, "invalid domain id string.\n");
		return STR_INVALID;
	}

	s = strvc;
        dvalue = hvalue = BADADDR;
        if (decimal(s, 0))
                dvalue = dtol(s, RETURN_ON_ERROR, NULL);

        if (hexadecimal(s, 0)) {
        	if (STRNEQ(s, "0x") || STRNEQ(s, "0X"))
                	s += 2;
		if (strlen(s) <= MAX_HEXADDR_STRLEN) 
                	hvalue = htol(s, RETURN_ON_ERROR, NULL);
	}

        found = 0;
        vcc_did = vcc_hid = NULL;
	type = XEN_HYPER_STR_INVALID;

	if (dvalue != BADADDR) {
	        if ((vcc_did = xen_hyper_id_to_vcpu_context(dc->domain,
		XEN_HYPER_DOMAIN_ID_INVALID, dvalue)))
			found++;
	}

	if ((hvalue != BADADDR) && (dvalue != hvalue)) {
	        if ((vcc_hid = xen_hyper_id_to_vcpu_context(dc->domain,
		XEN_HYPER_DOMAIN_ID_INVALID, hvalue)))
			found++;
	}

	switch (found) 
	{
	case 2:
		if (vcc_did && vcc_hid) {
			*vccp = vcc_did;
			*valvc = dvalue;
			type = XEN_HYPER_STR_VCID;
		}
		break;
	case 1: 
		if (vcc_did) {
			*vccp = vcc_did;
			*valvc = dvalue;
			type = XEN_HYPER_STR_VCID;
		}

		if (vcc_hid) {
			*vccp = vcc_hid;
			*valvc = hvalue;
			type = XEN_HYPER_STR_VCID;
		}
		break;
	}

	return type;
}

/*
 * Check a type for value. And return pcpu context.
 */
static int
xen_hyper_str_to_pcpu_context(char *string, ulong *value,
	struct xen_hyper_pcpu_context **pccp)
{
	ulong dvalue, hvalue;
	int found, type;
	char *s;
	struct xen_hyper_pcpu_context *pcc_did, *pcc_dpc, *pcc_hid, *pcc_hpc;

	if (string == NULL) {
		error(INFO, "received NULL string\n");
		return STR_INVALID;
	}

	s = string;
        dvalue = hvalue = BADADDR;

        if (decimal(s, 0))
                dvalue = dtol(s, RETURN_ON_ERROR, NULL);

        if (hexadecimal(s, 0)) {
        	if (STRNEQ(s, "0x") || STRNEQ(s, "0X"))
                	s += 2;
		if (strlen(s) <= MAX_HEXADDR_STRLEN) 
                	hvalue = htol(s, RETURN_ON_ERROR, NULL);
	}

        found = 0;
        pcc_did = pcc_dpc = pcc_hid = pcc_hpc = NULL;
	type = XEN_HYPER_STR_INVALID;

	if (dvalue != BADADDR) {
		if ((pcc_did = xen_hyper_id_to_pcpu_context(dvalue)))
			found++;
	        if ((pcc_dpc = xen_hyper_pcpu_to_pcpu_context(dvalue)))
			found++;
	}

	if ((hvalue != BADADDR) && (dvalue != hvalue)) {
	        if ((pcc_hid = xen_hyper_id_to_pcpu_context(hvalue)))
			found++;
	        if ((pcc_hpc = xen_hyper_pcpu_to_pcpu_context(hvalue)))
			found++;
	}

	switch (found) 
	{
	case 2: 
		if (pcc_did && pcc_hid) {      
                	*pccp = pcc_did;      
                	*value = dvalue;   
                	type = STR_PID;
		}
		break;

	case 1: 
		if (pcc_did) {
			*pccp = pcc_did;
			*value = dvalue;
			type = XEN_HYPER_STR_PCID;
		}

		if (pcc_dpc) {
			*pccp = pcc_dpc;
			*value = dvalue;
			type = XEN_HYPER_STR_PCPU;
		}

		if (pcc_hid) {
			*pccp = pcc_hid;
			*value = hvalue;
			type = XEN_HYPER_STR_PCID;
		}

		if (pcc_hpc) {
			*pccp = pcc_hpc;
			*value = hvalue;
			type = XEN_HYPER_STR_PCPU;
		}
		break;
	}

	return type;
}

#endif
