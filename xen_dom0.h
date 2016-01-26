/* xen_dom0.h
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

/*
 *  ELF note types for Xen dom0/hypervisor kdumps.
 *  The comments below are from xen/include/public/elfnote.h.
 */

/*
 * System information exported through crash notes.
 *
 * The kexec / kdump code will create one XEN_ELFNOTE_CRASH_INFO
 * note in case of a system crash. This note will contain various
 * information about the system, see xen/include/xen/elfcore.h.
 */
#define XEN_ELFNOTE_CRASH_INFO 0x1000001

/*
 * System registers exported through crash notes.
 *
 * The kexec / kdump code will create one XEN_ELFNOTE_CRASH_REGS
 * note per cpu in case of a system crash. This note is architecture
 * specific and will contain registers not saved in the "CORE" note.
 * See xen/include/xen/elfcore.h for more information.
 */
#define XEN_ELFNOTE_CRASH_REGS 0x1000002


/*
 * For (temporary) backwards compatibility.
 */
#define NT_XEN_KDUMP_CR3 0x10000001

struct xen_kdump_data {
	ulong flags;
	ulong cr3;
	ulong p2m_mfn;
	char *page;
	ulong last_mfn_read;
	ulong last_pmd_read;
	ulong cache_hits;
	ulong accesses;
	int p2m_frames;
        ulong *p2m_mfn_frame_list;
	ulong xen_phys_start;
	int xen_major_version;
	int xen_minor_version;
};

#define KDUMP_P2M_INIT  (0x1)
#define KDUMP_CR3       (0x2)
#define KDUMP_MFN_LIST  (0x4)

#define P2M_FAILURE ((physaddr_t)(0xffffffffffffffffLL))

extern struct xen_kdump_data *xkd;

void dump_xen_kdump_data(FILE *);
struct xen_kdump_data *get_xen_kdump_data(void);

void process_xen_note(ulong, void *, size_t);
physaddr_t xen_kdump_p2m(physaddr_t);
