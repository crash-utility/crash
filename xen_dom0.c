/* xen_dom0.c
 *
 * Copyright (C) 2015 David Anderson
 * Copyright (C) 2015 Red Hat, Inc. All rights reserved.
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
 *
 * Author: David Anderson
 */

#include "defs.h"
#include "xen_dom0.h"

static struct xen_kdump_data xen_kdump_data = { 0 };

struct xen_kdump_data *xkd = &xen_kdump_data;

void
dump_xen_kdump_data(FILE *fp)
{
	int i, others;

	fprintf(fp, "         xen_kdump_data: %s\n",
		XEN_CORE_DUMPFILE() ? " " : "(unused)");
	if (!XEN_CORE_DUMPFILE())
		return;
	fprintf(fp, "                    flags: %lx (", xkd->flags);
	others = 0;
	if (xkd->flags & KDUMP_P2M_INIT)
		fprintf(fp, "%sKDUMP_P2M_INIT", others++ ? "|" : "");
	if (xkd->flags & KDUMP_CR3)
		fprintf(fp, "%sKDUMP_CR3", others++ ? "|" : "");
	if (xkd->flags & KDUMP_MFN_LIST)
		fprintf(fp, "%sKDUMP_MFN_LIST", others++ ? "|" : "");
	fprintf(fp, ")\n");
	fprintf(fp, "                  p2m_mfn: %lx\n",
		xkd->p2m_mfn);
	fprintf(fp, "                      cr3: %lx\n",
		xkd->cr3);
	fprintf(fp, "            last_mfn_read: %lx\n",
		xkd->last_mfn_read);
	fprintf(fp, "            last_pmd_read: %lx\n",
		xkd->last_pmd_read);
	fprintf(fp, "                     page: %lx\n",
		(ulong)xkd->page);
	fprintf(fp, "                 accesses: %ld\n",
		xkd->accesses);
	fprintf(fp, "               cache_hits: %ld ",
		xkd->cache_hits);
	if (xkd->accesses)
		fprintf(fp, "(%ld%%)",
			xkd->cache_hits * 100 / xkd->accesses);
	fprintf(fp, "\n               p2m_frames: %d\n",
		xkd->p2m_frames);
	fprintf(fp, "           xen_phys_start: %lx\n",
		xkd->xen_phys_start);
	fprintf(fp, "        xen_major_version: %d\n",
		xkd->xen_major_version);
	fprintf(fp, "        xen_minor_version: %d\n",
		xkd->xen_minor_version);
	fprintf(fp, "       p2m_mfn_frame_list: %lx\n",
		(ulong)xkd->p2m_mfn_frame_list);
	for (i = 0; i < xkd->p2m_frames; i++)
		fprintf(fp, "%lx ", xkd->p2m_mfn_frame_list[i]);
	if (i) fprintf(fp, "\n");
}

void
process_xen_note(ulong type, void *data, size_t sz)
{
	ulong *up = (ulong*) data;
	unsigned words = sz / sizeof(ulong);

	pc->flags |= XEN_CORE;
	xkd->last_mfn_read = UNINITIALIZED;
	xkd->last_pmd_read = UNINITIALIZED;

	if (type == NT_XEN_KDUMP_CR3)
		error(WARNING,
		      "obsolete Xen n_type: %lx (NT_XEN_KDUMP_CR3)\n\n",
		      type);

	if (type == NT_XEN_KDUMP_CR3 && words == 1) {
		xkd->flags |= KDUMP_CR3;
		/*
		 *  Use the first cr3 found.
		 */
		if (!xkd->cr3)
			xkd->cr3 = *up;
	} else {
		xkd->flags |= KDUMP_MFN_LIST;
		/*
		 *  If already set, overridden with --pfm_mfn
		 */
		if (!xkd->p2m_mfn)
			xkd->p2m_mfn = up[words-1];
		if (words > 9 && !xkd->xen_phys_start)
			xkd->xen_phys_start = up[words-2];
		xkd->xen_major_version = up[0];
		xkd->xen_minor_version = up[1];
	}
}

/*
 *  Override the dom0 p2m mfn in the XEN_ELFNOTE_CRASH_INFO note
 *  in order to initiate a crash session of a guest kernel.
 */
void
xen_kdump_p2m_mfn(char *arg)
{
	ulong value;
	int errflag;

	errflag = 0;
	value = htol(arg, RETURN_ON_ERROR|QUIET, &errflag);
	if (!errflag) {
		xen_kdump_data.p2m_mfn = value;
		if (CRASHDEBUG(1))
			error(INFO,
			    "xen_kdump_data.p2m_mfn override: %lx\n",
				value);
	} else
		error(WARNING, "invalid p2m_mfn argument: %s\n", arg);
}

/*
 *  Fujitsu dom0/HV sadump-generated dumpfile, which requires
 *  the --p2m_mfn command line argument.
 */
int
is_sadump_xen(void)
{
	if (xen_kdump_data.p2m_mfn) {
		if (!XEN_CORE_DUMPFILE()) {
			pc->flags |= XEN_CORE;
			xkd->last_mfn_read = UNINITIALIZED;
			xkd->last_pmd_read = UNINITIALIZED;
			xkd->flags |= KDUMP_MFN_LIST;
		}
		return TRUE;
	}

	return FALSE;
}

void
set_xen_phys_start(char *arg)
{
	ulong value;
	int errflag = 0;

	value = htol(arg, RETURN_ON_ERROR|QUIET, &errflag);
	if (!errflag)
		xen_kdump_data.xen_phys_start = value;
	else
		error(WARNING, "invalid xen_phys_start argument: %s\n", arg);
}

ulong
xen_phys_start(void)
{
	return xkd->xen_phys_start;
}

int
xen_major_version(void)
{
	return xkd->xen_major_version;
}

int
xen_minor_version(void)
{
	return xkd->xen_minor_version;
}

struct xen_kdump_data *
get_xen_kdump_data(void)
{
	return xkd;
}

/*
 *  Translate a xen domain's pseudo-physical address into the
 *  xen machine address.  Since there's no compression involved,
 *  just the last phys_to_machine_mapping[] page read is cached,
 *  which essentially caches 1024 p2m translations.
 */
physaddr_t
xen_kdump_p2m(physaddr_t pseudo)
{
	ulong pfn, mfn_frame;
	ulong *mfnptr;
	ulong mfn_idx, frame_idx;
	physaddr_t paddr;

	if (pc->curcmd_flags & XEN_MACHINE_ADDR)
		return pseudo;

	if (!(xkd->flags & KDUMP_P2M_INIT)) {
		if (!machdep->xen_kdump_p2m_create)
			error(FATAL,
			      "xen kdump dumpfiles not supported on this architecture\n");

		if ((xkd->page =
		     (char *)malloc(PAGESIZE())) == NULL)
			error(FATAL,
			      "cannot malloc xen kdump data page\n");

		if (!machdep->xen_kdump_p2m_create(xkd))
			error(FATAL,
			      "cannot create xen kdump pfn-to-mfn mapping\n");

		xkd->flags |= KDUMP_P2M_INIT;
	}

#ifdef IA64
	return ia64_xen_kdump_p2m(xkd, pseudo);
#endif

	xkd->accesses++;

	pfn = (ulong)BTOP(pseudo);
	mfn_idx = pfn / (PAGESIZE()/sizeof(ulong));
	frame_idx = pfn % (PAGESIZE()/sizeof(ulong));
	if (mfn_idx >= xkd->p2m_frames) {
		if (CRASHDEBUG(8))
			fprintf(fp, "xen_kdump_p2m: paddr/pfn: %llx/%lx: "
			    "mfn_idx nonexistent\n",
				(ulonglong)pseudo, pfn);
		return P2M_FAILURE;
	}
	mfn_frame = xkd->p2m_mfn_frame_list[mfn_idx];

	if (mfn_frame == xkd->last_mfn_read)
		xkd->cache_hits++;
	else {
		int res;

		if (CRASHDEBUG(8))
			fprintf(fp, "xen_kdump_p2m: paddr/pfn: %llx/%lx: "
			    "read mfn_frame: %llx\n",
				(ulonglong)pseudo, pfn, PTOB(mfn_frame));

		pc->curcmd_flags |= XEN_MACHINE_ADDR;
		res = readmem((physaddr_t)PTOB(mfn_frame), PHYSADDR,
			      xkd->page, PAGESIZE(),
			      "xen_kdump_p2m mfn frame", RETURN_ON_ERROR);
		pc->curcmd_flags &= ~XEN_MACHINE_ADDR;

		if (!res)
			return P2M_FAILURE;
	}

	xkd->last_mfn_read = mfn_frame;

	mfnptr = ((ulong *)(xkd->page)) + frame_idx;
	paddr = (physaddr_t)PTOB((ulonglong)(*mfnptr));
	paddr |= PAGEOFFSET(pseudo);

	if (CRASHDEBUG(7))
		fprintf(fp,
		    "xen_kdump_p2m(%llx): mfn_idx: %ld frame_idx: %ld"
		    " mfn_frame: %lx mfn: %lx => %llx\n",
			(ulonglong)pseudo, mfn_idx, frame_idx,
			mfn_frame, *mfnptr, (ulonglong)paddr);

	return paddr;
}
