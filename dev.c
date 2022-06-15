/* dev.c - core analysis suite 
 *
 * Copyright (C) 2001, 2002 Mission Critical Linux, Inc.
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

#include "defs.h"
#include "vmcore.h"

static void dump_blkdevs(ulong);
static void dump_chrdevs(ulong);
static void dump_blkdevs_v2(ulong);
static void dump_blkdevs_v3(ulong);
static ulong search_cdev_map_probes(char *, int, int, ulong *);
static ulong search_bdev_map_probes(char *, int, int, ulong *);
static ulong search_blockdev_inodes(int, ulong *);
static void do_pci(void); 
static void do_pci2(void);
static void do_io(void);
static void do_resource_list(ulong, char *, int);

static const char *pci_strclass (uint, char *); 
static const char *pci_strvendor(uint, char *); 
static const char *pci_strdev(uint, uint, char *); 

static void diskio_option(ulong flags);
 
static struct dev_table {
        ulong flags;
} dev_table = { 0 };

struct dev_table *dt = &dev_table;

#define DEV_INIT    0x1
#define DISKIO_INIT 0x2

#define DIOF_ALL	1 << 0
#define DIOF_NONZERO	1 << 1

void
dev_init(void)
{
        MEMBER_OFFSET_INIT(pci_dev_global_list, "pci_dev", "global_list");
        MEMBER_OFFSET_INIT(pci_dev_next, "pci_dev", "next");
        MEMBER_OFFSET_INIT(pci_dev_bus, "pci_dev", "bus");
	MEMBER_OFFSET_INIT(pci_dev_dev, "pci_dev", "dev");
        MEMBER_OFFSET_INIT(pci_dev_devfn, "pci_dev", "devfn");
        MEMBER_OFFSET_INIT(pci_dev_class, "pci_dev", "class");
        MEMBER_OFFSET_INIT(pci_dev_device, "pci_dev", "device");
	MEMBER_OFFSET_INIT(pci_dev_hdr_type, "pci_dev", "hdr_type");
	MEMBER_OFFSET_INIT(pci_dev_pcie_flags_reg, "pci_dev", "pcie_flags_reg");
        MEMBER_OFFSET_INIT(pci_dev_vendor, "pci_dev", "vendor");
	MEMBER_OFFSET_INIT(pci_bus_number, "pci_bus", "number");
	MEMBER_OFFSET_INIT(pci_bus_node, "pci_bus", "node");
	MEMBER_OFFSET_INIT(pci_bus_devices, "pci_bus", "devices");
	MEMBER_OFFSET_INIT(pci_bus_dev, "pci_bus", "dev");
	MEMBER_OFFSET_INIT(pci_bus_children, "pci_bus", "children");
	MEMBER_OFFSET_INIT(pci_bus_parent, "pci_bus", "parent");
	MEMBER_OFFSET_INIT(pci_bus_self, "pci_bus", "self");

	MEMBER_OFFSET_INIT(device_kobj, "device", "kobj");
	MEMBER_OFFSET_INIT(kobject_name, "kobject", "name");

        STRUCT_SIZE_INIT(resource, "resource");
	if ((VALID_STRUCT(resource) && symbol_exists("do_resource_list")) ||
	    (VALID_STRUCT(resource) &&
             symbol_exists("iomem_resource") &&
             symbol_exists("ioport_resource"))) {
        	MEMBER_OFFSET_INIT(resource_name, "resource", "name");
        	MEMBER_OFFSET_INIT(resource_start, "resource", "start");
        	MEMBER_OFFSET_INIT(resource_end, "resource", "end");
        	MEMBER_OFFSET_INIT(resource_sibling, "resource", "sibling");
        	MEMBER_OFFSET_INIT(resource_child, "resource", "child");
	} else {
		STRUCT_SIZE_INIT(resource_entry_t, "resource_entry_t");
		if (VALID_SIZE(resource_entry_t)) {
			MEMBER_OFFSET_INIT(resource_entry_t_from, 
				"resource_entry_t", "from");
			MEMBER_OFFSET_INIT(resource_entry_t_num, 
				"resource_entry_t", "num");
			MEMBER_OFFSET_INIT(resource_entry_t_name, 
				"resource_entry_t", "name");
			MEMBER_OFFSET_INIT(resource_entry_t_next, 
				"resource_entry_t", "next");
		}
	}

	dt->flags |= DEV_INIT;
}


/*
 *  Generic command for character and block device data.
 */
void
cmd_dev(void)
{
	int c;
	int dd_index = -1;
	char *outputfile = NULL;
	ulong flags;

	flags = 0;

	while ((c = getopt(argcnt, args, "dDpiVv:")) != EOF) {
                switch(c)
                {
		case 'd':
			diskio_option(DIOF_ALL);
			return;

		case 'D':
			diskio_option(DIOF_NONZERO);
			return;

		case 'i':
			if (machine_type("S390X"))
				option_not_supported(c);
			do_io();
			return;

		case 'p':
			if (machine_type("S390X"))
				option_not_supported(c);
			if (symbol_exists("pci_devices"))
				do_pci();
			else if (symbol_exists("pci_root_buses"))
				do_pci2();
			else
				option_not_supported(c);
			return;

		case 'V':
			if (KDUMP_DUMPFILE())
				kdump_device_dump_info(fp);
			else if (DISKDUMP_DUMPFILE())
				diskdump_device_dump_info(fp);
			else if (ACTIVE())
				error(INFO, "-V option not supported on a live system\n");
			else
				error(INFO, "-V option not supported on this dumpfile type\n");
			return;

		case 'v':
			dd_index = atoi(optarg);
			break;

                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

        while (args[optind]) {
		if (dd_index >= 0) {
			if (!outputfile) 
				outputfile = args[optind];
			else
				cmd_usage(pc->curcmd, SYNOPSIS);
		} else
			cmd_usage(pc->curcmd, SYNOPSIS);
		optind++;
	}

	if (dd_index >= 0) {
		if (KDUMP_DUMPFILE())
			kdump_device_dump_extract(dd_index, outputfile, fp);
		else if (DISKDUMP_DUMPFILE())
			diskdump_device_dump_extract(dd_index, outputfile, fp);
		else if (ACTIVE())
			error(INFO, "-v option not supported on a live system\n");
		else
			error(INFO, "-v option not supported on this dumpfile type\n");
		return;
	}

	dump_chrdevs(flags);
	fprintf(fp, "\n");
	dump_blkdevs(flags);
}

#define MAX_DEV (255)

#define MINORBITS       20
#define MINORMASK       ((1U << MINORBITS) - 1)

#define MAJOR(dev)      ((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)      ((unsigned int) ((dev) & MINORMASK))

char *chrdev_hdr = "CHRDEV    NAME         ";
char *blkdev_hdr = "BLKDEV    NAME         ";

/*
 *  Dump the character device data.
 */
static void
dump_chrdevs(ulong flags)
{
	int i;
	ulong addr, size;
	char buf[BUFSIZE];
	char buf2[BUFSIZE];
	struct chrdevs {
		ulong name;
		ulong ops;
	} chrdevs[MAX_DEV], *cp;
	ulong *cdp;
	char *char_device_struct_buf;
	ulong next, savenext, name, fops, cdev; 
	int major, minor;
	int name_typecode;
	size_t name_size;

	if (!symbol_exists("chrdevs"))
		error(FATAL, "chrdevs: symbol does not exist\n");

	addr = symbol_value("chrdevs");
	size = VALID_STRUCT(char_device_struct) ? 
		sizeof(void *) : sizeof(struct chrdevs);

        readmem(addr, KVADDR, &chrdevs[0], size * MAX_DEV,
        	"chrdevs array", FAULT_ON_ERROR);

	fprintf(fp, "%s  %s", chrdev_hdr, VADDR_PRLEN == 8 ? " " : "");
	fprintf(fp, "%s  ", mkstring(buf, VADDR_PRLEN, CENTER, "CDEV"));
	fprintf(fp, "%s\n", mkstring(buf, VADDR_PRLEN, LJUST, "OPERATIONS"));

	if (VALID_STRUCT(char_device_struct))
		goto char_device_struct;

	for (i = 0, cp = &chrdevs[0]; i < MAX_DEV; i++, cp++) {
		if (!cp->ops)
			continue;

		fprintf(fp, " %3d      ", i);
		if (cp->name) {
                	if (read_string(cp->name, buf, BUFSIZE-1))
                        	fprintf(fp, "%-11s ", buf);
                	else
                        	fprintf(fp, "%-11s ", "(unknown)");
			
		} else
                      	fprintf(fp, "%-11s ", "(unknown)");

		sprintf(buf, "%s%%%dlx  ", 
			strlen("OPERATIONS") < VADDR_PRLEN ? " " : "  ",
			VADDR_PRLEN);
		fprintf(fp, buf, cp->ops);
		value_to_symstr(cp->ops, buf, 0);
		if (strlen(buf))
			fprintf(fp, "<%s>", buf);

		fprintf(fp, "\n");
	}
	return;

char_device_struct:

	char_device_struct_buf = GETBUF(SIZE(char_device_struct));
	cdp = (ulong *)&chrdevs[0];
	name_typecode = MEMBER_TYPE("char_device_struct", "name");
	name_size = (size_t)MEMBER_SIZE("char_device_struct", "name"); 

	for (i = 0; i < MAX_DEV; i++, cdp++) {
		if (!(*cdp))
			continue;

       		readmem(*cdp, KVADDR, char_device_struct_buf, 
			SIZE(char_device_struct),
                	"char_device_struct", FAULT_ON_ERROR);

		next = ULONG(char_device_struct_buf + 
			OFFSET(char_device_struct_next));
		name = ULONG(char_device_struct_buf + 
			OFFSET(char_device_struct_name));
		switch (name_typecode)
		{
		case TYPE_CODE_ARRAY:
			snprintf(buf, name_size, "%s",
				 char_device_struct_buf +
				 OFFSET(char_device_struct_name));
			break;
		case TYPE_CODE_PTR:
		default:
			if (!name || !read_string(name, buf, BUFSIZE-1))
				break;
		}

		major = INT(char_device_struct_buf + 
			OFFSET(char_device_struct_major));
		minor = INT(char_device_struct_buf + 
			OFFSET(char_device_struct_baseminor));

		cdev = fops = 0;
		if (VALID_MEMBER(char_device_struct_cdev) &&
				VALID_STRUCT(cdev)) {
			cdev = ULONG(char_device_struct_buf + 
				OFFSET(char_device_struct_cdev));
			if (cdev) {
				addr = cdev + OFFSET(cdev_ops);
				readmem(addr, KVADDR, &fops, 
					sizeof(void *),
					"cdev ops", FAULT_ON_ERROR);
			}
		} else {
			fops = ULONG(char_device_struct_buf + 
				OFFSET(char_device_struct_fops));
		}

		if (!fops)
			fops = search_cdev_map_probes(buf, major, minor, &cdev);

		if (!fops) { 
			fprintf(fp, " %3d      ", major);
			fprintf(fp, "%-13s ", buf);
			fprintf(fp, "%s%s\n", VADDR_PRLEN == 8 ? "  " : " ",
				mkstring(buf, VADDR_PRLEN, CENTER, "(none)"));
		} else {
			fprintf(fp, " %3d      ", major);
			fprintf(fp, "%-13s ", buf);
			sprintf(buf2, "%s%%%dlx  ",
				strlen("OPERATIONS") < VADDR_PRLEN ? " " : "  ",
				VADDR_PRLEN);
			fprintf(fp, buf2, cdev);
			value_to_symstr(fops, buf2, 0);
			if (strlen(buf2))
				fprintf(fp, "%s", buf2);
			else
				fprintf(fp, "%lx", fops);
			fprintf(fp, "\n");
		}

		if (CRASHDEBUG(1))
			fprintf(fp, 
		    	    "%lx: major: %d minor: %d name: %s next: %lx cdev: %lx fops: %lx\n",
				*cdp, major, minor, buf, next, cdev, fops);

		while (next) {
       			readmem(savenext = next, KVADDR, char_device_struct_buf,
				SIZE(char_device_struct),
                		"char_device_struct", FAULT_ON_ERROR);

	                next = ULONG(char_device_struct_buf +
	                        OFFSET(char_device_struct_next));
	                name = ULONG(char_device_struct_buf +
	                        OFFSET(char_device_struct_name));
			switch (name_typecode)
			{
			case TYPE_CODE_ARRAY:
				snprintf(buf, name_size, "%s",
					 char_device_struct_buf +
					 OFFSET(char_device_struct_name));
				break;
			case TYPE_CODE_PTR:
			default:
				if (!name || !read_string(name, buf, BUFSIZE-1))
					sprintf(buf, "(unknown)");
				break;
			}

	                major = INT(char_device_struct_buf +
	                        OFFSET(char_device_struct_major));
	                minor = INT(char_device_struct_buf +
	                        OFFSET(char_device_struct_baseminor));

			fops = cdev = 0;
			if (VALID_MEMBER(char_device_struct_cdev) &&
					VALID_STRUCT(cdev)) {
				cdev = ULONG(char_device_struct_buf + 
					OFFSET(char_device_struct_cdev));
				if (cdev) {
					addr = cdev + OFFSET(cdev_ops);
					readmem(addr, KVADDR, &fops,
						sizeof(void *),
						"cdev ops", FAULT_ON_ERROR);
				}
			} else {
				fops = ULONG(char_device_struct_buf + 
					OFFSET(char_device_struct_fops));
			}
 
			if (!fops)
				fops = search_cdev_map_probes(buf, major, minor, &cdev);

			if (!fops) {
				fprintf(fp, " %3d      ", major);
				fprintf(fp, "%-13s ", buf);
				fprintf(fp, "%s%s\n", VADDR_PRLEN == 8 ? "  " : " ",
					mkstring(buf, VADDR_PRLEN, CENTER, "(none)"));
			} else { 
				fprintf(fp, " %3d      ", major);
				fprintf(fp, "%-13s ", buf);
				sprintf(buf2, "%s%%%dlx  ",
					strlen("OPERATIONS") < VADDR_PRLEN ? 
					" " : "  ", VADDR_PRLEN);
				fprintf(fp, buf2, cdev);
				value_to_symstr(fops, buf2, 0);
				if (strlen(buf2))
					fprintf(fp, "%s", buf2);
				else
					fprintf(fp, "%lx", fops);
				fprintf(fp, "\n");
			}
	
			if (CRASHDEBUG(1))
	                	fprintf(fp,
	                        "%lx: major: %d minor: %d name: %s next: %lx cdev: %lx fops: %lx\n",
	                        	savenext, major, minor, buf, next, cdev, fops);
		}
	}

	FREEBUF(char_device_struct_buf);
}

/*
 *  Search for a major/minor match by following the list headed
 *  by the kobj_map.probes[major] array entry.  The "data" member
 *  points to a cdev structure containing the file_operations
 *  pointer.
 */
static ulong 
search_cdev_map_probes(char *name, int major, int minor, ulong *cdev)
{
	char *probe_buf;
	ulong probes[MAX_DEV];
	ulong cdev_map, addr, next, ops, probe_data;
	uint probe_dev;

	if (kernel_symbol_exists("cdev_map"))
		get_symbol_data("cdev_map", sizeof(ulong), &cdev_map);
	else
		return 0;

	addr = cdev_map + OFFSET(kobj_map_probes);
	if (!readmem(addr, KVADDR, &probes[0], sizeof(void *) * MAX_DEV,
	    "cdev_map.probes[]", QUIET|RETURN_ON_ERROR))
		return 0;

	ops = 0;
	probe_buf = GETBUF(SIZE(probe));
	next = probes[major];

	while (next) {
		if (!readmem(next, KVADDR, probe_buf, SIZE(probe),
		    "struct probe", QUIET|RETURN_ON_ERROR))
			break;

		probe_dev = UINT(probe_buf + OFFSET(probe_dev));

		if ((MAJOR(probe_dev) == major) && 
		    (MINOR(probe_dev) == minor)) {
			probe_data = ULONG(probe_buf + OFFSET(probe_data));
			addr = probe_data + OFFSET(cdev_ops);
			if (!readmem(addr, KVADDR, &ops, sizeof(void *),
	    		    "cdev ops", QUIET|RETURN_ON_ERROR))
				ops = 0;
			else 
				*cdev = probe_data;
			break;
		}

		next = ULONG(probe_buf + OFFSET(probe_next));
	}

	FREEBUF(probe_buf);
	return ops;
}

/*
 *  Dump the block device data.
 */
static void
dump_blkdevs(ulong flags)
{
	int i;
	ulong addr;
	char buf[BUFSIZE];
        struct blkdevs {
                ulong name;
                ulong ops;
        } blkdevs[MAX_DEV], *bp;

	if (kernel_symbol_exists("major_names") &&
	    (kernel_symbol_exists("bdev_map") ||
	     kernel_symbol_exists("blockdev_superblock"))) {
		dump_blkdevs_v3(flags);
		return;
	}

        if (symbol_exists("all_bdevs")) {
                dump_blkdevs_v2(flags);
                return;
        }

	if (!symbol_exists("blkdevs"))
		error(FATAL, "blkdevs or all_bdevs: symbols do not exist\n");

	addr = symbol_value("blkdevs");
        readmem(addr, KVADDR, &blkdevs[0], sizeof(struct blkdevs) * MAX_DEV,
                "blkdevs array", FAULT_ON_ERROR);

	fprintf(fp, "%s%s\n", blkdev_hdr, 
		mkstring(buf, VADDR_PRLEN, CENTER, "OPERATIONS"));

	for (i = 0, bp = &blkdevs[0]; i < MAX_DEV; i++, bp++) {
		if (!bp->ops)
			continue;

		fprintf(fp, " %3d      ", i);
                if (bp->name) {
                        if (read_string(bp->name, buf, BUFSIZE-1))
                                fprintf(fp, "%-11s ", buf);
                        else
                                fprintf(fp, "%-11s ", "(unknown)");

                } else 
                        fprintf(fp, "%-11s ", "(unknown)");

		sprintf(buf, "%s%%%dlx  ", 
			strlen("OPERATIONS") < VADDR_PRLEN ? " " : "  ",
			VADDR_PRLEN);
		fprintf(fp, buf, bp->ops);

		value_to_symstr(bp->ops, buf, 0);
		if (strlen(buf))
			fprintf(fp, "<%s>", buf);

		fprintf(fp, "\n");
	}
}

/*
 *  block device dump for 2.6 
 */
static void
dump_blkdevs_v2(ulong flags)
{
        struct list_data list_data, *ld;
	ulong *major_fops, *bdevlist, *gendisklist, *majorlist;
	int i, j, bdevcnt, len;
	char *block_device_buf, *gendisk_buf, *blk_major_name_buf;
	ulong next, savenext, fops; 
	int major, total;
	char buf[BUFSIZE];

	if (!symbol_exists("major_names")) 
		error(FATAL, 
			"major_names[] array doesn't exist in this kernel\n");

	len = get_array_length("major_names", NULL, 0);

	block_device_buf = GETBUF(SIZE(block_device));
	gendisk_buf = GETBUF(SIZE(gendisk));

        ld = &list_data;
        BZERO(ld, sizeof(struct list_data));

	get_symbol_data("all_bdevs", sizeof(void *), &ld->start);
	ld->end = symbol_value("all_bdevs");
        ld->list_head_offset = OFFSET(block_device_bd_list);

        hq_open();
        bdevcnt = do_list(ld);
        bdevlist = (ulong *)GETBUF(bdevcnt * sizeof(ulong));
        gendisklist = (ulong *)GETBUF(bdevcnt * sizeof(ulong));
        bdevcnt = retrieve_list(bdevlist, bdevcnt);
        hq_close();

	total = MAX(len, bdevcnt);
	major_fops = (ulong *)GETBUF(sizeof(void *) * total);

	/*
	 *  go through the block_device list, emulating:
	 *
	 *      ret += bdev->bd_inode->i_mapping->nrpages;
	 */
	for (i = 0; i < bdevcnt; i++) {
                readmem(bdevlist[i], KVADDR, block_device_buf, 
			SIZE(block_device), "block_device buffer", 
			FAULT_ON_ERROR);
		gendisklist[i] = ULONG(block_device_buf + 
			OFFSET(block_device_bd_disk));
		if (CRASHDEBUG(1))
			fprintf(fp, "[%d] %lx -> %lx\n", 
				i, bdevlist[i], gendisklist[i]);
	}

	for (i = 1; i < bdevcnt; i++) {
		for (j = 0; j < i; j++) {
			if (gendisklist[i] == gendisklist[j]) 
				gendisklist[i] = 0;
		}
	}

	for (i = 0; i < bdevcnt; i++) {
		if (!gendisklist[i]) 
			continue;
                readmem(gendisklist[i], KVADDR, gendisk_buf, 
			SIZE(gendisk), "gendisk buffer", 
			FAULT_ON_ERROR);
		fops = ULONG(gendisk_buf + OFFSET(gendisk_fops));
		major = UINT(gendisk_buf + OFFSET(gendisk_major));
		strncpy(buf, gendisk_buf + OFFSET(gendisk_disk_name), 32);
		if (CRASHDEBUG(1))
			fprintf(fp, "%lx: name: [%s] major: %d fops: %lx\n", 
				gendisklist[i], buf, major, fops);	

		if (fops && (major < total))
			major_fops[major] = fops;
	}

	FREEBUF(bdevlist);
	FREEBUF(gendisklist);
	FREEBUF(block_device_buf);
	FREEBUF(gendisk_buf);

	if (CRASHDEBUG(1))
		fprintf(fp, "major_names[%d]\n", len);
	majorlist = (ulong *)GETBUF(len * sizeof(void *));
	blk_major_name_buf = GETBUF(SIZE(blk_major_name));
	readmem(symbol_value("major_names"), KVADDR, &majorlist[0], 
		sizeof(void *) * len, "major_names array", FAULT_ON_ERROR);

	fprintf(fp, "%s%s\n", blkdev_hdr, 
		mkstring(buf, VADDR_PRLEN, CENTER, "OPERATIONS"));

	for (i = 0; i < len; i++) {
		if (!majorlist[i])
			continue;

                readmem(majorlist[i], KVADDR, blk_major_name_buf, 
			SIZE(blk_major_name), "blk_major_name buffer", 
			FAULT_ON_ERROR);
		
		major = UINT(blk_major_name_buf + 
			OFFSET(blk_major_name_major));
		buf[0] = NULLCHAR;
		strncpy(buf, blk_major_name_buf + 
			OFFSET(blk_major_name_name), 16);
		next = ULONG(blk_major_name_buf +
                        OFFSET(blk_major_name_next));
		if (CRASHDEBUG(1))
			fprintf(fp, 
		    	    "[%d] %lx major: %d name: %s next: %lx fops: %lx\n",
				i, majorlist[i], major, buf, next, 
				major_fops[major]);

                fprintf(fp, " %3d      ", major);
                fprintf(fp, "%-12s ", strlen(buf) ? buf : "(unknown)");
		if (major_fops[major]) {
                	sprintf(buf, "%s%%%dlx  ",
                        	strlen("OPERATIONS") < VADDR_PRLEN ? " " : "  ",
                        	VADDR_PRLEN);
                	fprintf(fp, buf, major_fops[major]);
                	value_to_symstr(major_fops[major], buf, 0);
                	if (strlen(buf))
                        	fprintf(fp, "<%s>", buf);
		} else 
			fprintf(fp, " (unknown)");
                fprintf(fp, "\n");

		while (next) {
                	readmem(savenext = next, KVADDR, blk_major_name_buf, 
				SIZE(blk_major_name), "blk_major_name buffer", 
				FAULT_ON_ERROR);
                	major = UINT(blk_major_name_buf +
                        	OFFSET(blk_major_name_major));
                	strncpy(buf, blk_major_name_buf +
                        	OFFSET(blk_major_name_name), 16);
                	next = ULONG(blk_major_name_buf +
                        	OFFSET(blk_major_name_next));
			if (CRASHDEBUG(1))
                		fprintf(fp, 
			    "[%d] %lx major: %d name: %s next: %lx fops: %lx\n",
                        		i, savenext, major, buf, next, 
					major_fops[major]);

                	fprintf(fp, " %3d      ", major);
                	fprintf(fp, "%-12s ", strlen(buf) ? buf : "(unknown)");
                	if (major_fops[major]) {
                        	sprintf(buf, "%s%%%dlx  ",
                                	strlen("OPERATIONS") < VADDR_PRLEN ? 
						" " : "  ", VADDR_PRLEN);
                        	fprintf(fp, buf, major_fops[major]);
                        	value_to_symstr(major_fops[major], buf, 0);
                        	if (strlen(buf))
                                	fprintf(fp, "<%s>", buf);
                	} else
                        	fprintf(fp, " (unknown)");
			fprintf(fp, "\n");
		}
	}
	
	FREEBUF(majorlist);
	FREEBUF(major_fops);
	FREEBUF(blk_major_name_buf);
}

static void
dump_blkdevs_v3(ulong flags)
{
	int i, len;
	ulong blk_major_name;
	char *blk_major_name_buf;
	char buf[BUFSIZE];
	uint major;
	ulong gendisk, addr, fops;
	int use_bdev_map = kernel_symbol_exists("bdev_map");
	
	if (!(len = get_array_length("major_names", NULL, 0)))
		len = MAX_DEV;

	fprintf(fp, "%s  %s", blkdev_hdr, VADDR_PRLEN == 8 ? " " : "");
	fprintf(fp, "%s  ", mkstring(buf, VADDR_PRLEN, CENTER|RJUST, "GENDISK"));
	fprintf(fp, "%s\n", mkstring(buf, VADDR_PRLEN, LJUST, "OPERATIONS"));

	blk_major_name_buf = GETBUF(SIZE(blk_major_name));
	gendisk = 0;

	for (i = 0; i < len; i++) {
		addr = symbol_value("major_names") + (i * sizeof(void *));
		readmem(addr, KVADDR, &blk_major_name, sizeof(void *),
			"major_names[] entry", FAULT_ON_ERROR);

		if (!blk_major_name)
			continue;

		readmem(blk_major_name, KVADDR, blk_major_name_buf,
			SIZE(blk_major_name), "blk_major_name", FAULT_ON_ERROR);

		major = UINT(blk_major_name_buf + 
			OFFSET(blk_major_name_major));
		buf[0] = NULLCHAR;
		strncpy(buf, blk_major_name_buf +  
			OFFSET(blk_major_name_name), 16);

		if (use_bdev_map)
			fops = search_bdev_map_probes(buf, major == i ? major : i,
				UNUSED, &gendisk);
		else /* v5.11 and later */
			fops = search_blockdev_inodes(major, &gendisk);

		if (CRASHDEBUG(1))
			fprintf(fp, "blk_major_name: %lx block major: %d name: %s gendisk: %lx fops: %lx\n", 
				blk_major_name, major, buf, gendisk, fops);

		if (!fops) {
			fprintf(fp, " %3d      ", major);
			fprintf(fp, "%-13s ", 
				strlen(buf) ? buf : "(unknown)");
			fprintf(fp, "%s%s\n", VADDR_PRLEN == 8 ? "  " : " ",
				mkstring(buf, VADDR_PRLEN, CENTER, "(none)"));
			continue;
		}

		fprintf(fp, " %3d      ", major);
		fprintf(fp, "%-13s ", strlen(buf) ? buf : "(unknown)");
		sprintf(buf, "%s%%%dlx  ",
			strlen("OPERATIONS") < VADDR_PRLEN ? " " : "  ",
			VADDR_PRLEN);
		fprintf(fp, buf, gendisk);
		value_to_symstr(fops, buf, 0);
		if (strlen(buf))
			fprintf(fp, "%s", buf);
		else
			fprintf(fp, "%lx", fops);
		fprintf(fp, "\n");
	}
}

static ulong 
search_bdev_map_probes(char *name, int major, int minor, ulong *gendisk)
{
	char *probe_buf, *gendisk_buf;
	ulong probes[MAX_DEV];
	ulong bdev_map, addr, next, probe_data, fops;
	uint probe_dev;

	get_symbol_data("bdev_map", sizeof(ulong), &bdev_map);

	addr = bdev_map + OFFSET(kobj_map_probes);
	if (!readmem(addr, KVADDR, &probes[0], sizeof(void *) * MAX_DEV,
	    "bdev_map.probes[]", QUIET|RETURN_ON_ERROR))
		return 0;

	probe_buf = GETBUF(SIZE(probe));
	gendisk_buf = GETBUF(SIZE(gendisk));

	fops = 0;

	for (next = probes[major]; next; 
	     next = ULONG(probe_buf + OFFSET(probe_next))) {

		if (!readmem(next, KVADDR, probe_buf, SIZE(probe),
		    "struct probe", QUIET|RETURN_ON_ERROR))
			break;

		probe_data = ULONG(probe_buf + OFFSET(probe_data));
		if (!probe_data)
			continue;

		probe_dev = UINT(probe_buf + OFFSET(probe_dev));
		if (MAJOR(probe_dev) != major)
			continue;

		if (!readmem(probe_data, KVADDR, gendisk_buf,
		    SIZE(gendisk), "gendisk buffer",
		    QUIET|RETURN_ON_ERROR))
			break;

		fops = ULONG(gendisk_buf + OFFSET(gendisk_fops));

		if (fops) {
			*gendisk = probe_data;
			break;
		}
	}

	FREEBUF(probe_buf);
	FREEBUF(gendisk_buf);
	return fops;
}

/* For bdev_inode.  See block/bdev.c */
#define I_BDEV(inode) (inode - SIZE(block_device))

static ulong
search_blockdev_inodes(int major, ulong *gendisk)
{
	struct list_data list_data, *ld;
	ulong addr, bd_sb, disk, fops = 0;
	int i, inode_count, gendisk_major;
	char *gendisk_buf;

	ld = &list_data;
	BZERO(ld, sizeof(struct list_data));

	get_symbol_data("blockdev_superblock", sizeof(void *), &bd_sb);

	addr = bd_sb + OFFSET(super_block_s_inodes);
	if (!readmem(addr, KVADDR, &ld->start, sizeof(ulong),
	    "blockdev_superblock.s_inodes", QUIET|RETURN_ON_ERROR))
		return 0;

	if (empty_list(ld->start))
		return 0;

	ld->flags |= LIST_ALLOCATE;
	ld->end = bd_sb + OFFSET(super_block_s_inodes);
	ld->list_head_offset = OFFSET(inode_i_sb_list);

	inode_count = do_list(ld);

	gendisk_buf = GETBUF(SIZE(gendisk));

	for (i = 0; i < inode_count; i++) {
		addr = I_BDEV(ld->list_ptr[i]) + OFFSET(block_device_bd_disk);
		if (!readmem(addr, KVADDR, &disk, sizeof(ulong),
		    "block_device.bd_disk", QUIET|RETURN_ON_ERROR))
			continue;

		if (!disk)
			continue;

		if (!readmem(disk, KVADDR, gendisk_buf, SIZE(gendisk),
		    "gendisk buffer", QUIET|RETURN_ON_ERROR))
			continue;

		gendisk_major = INT(gendisk_buf + OFFSET(gendisk_major));
		if (gendisk_major != major)
			continue;

		fops = ULONG(gendisk_buf + OFFSET(gendisk_fops));
		if (fops) {
			*gendisk = disk;
			break;
		}
	}

	FREEBUF(ld->list_ptr);
	FREEBUF(gendisk_buf);
	return fops;
}

void
dump_dev_table(void)
{
	struct dev_table *dt;
	int others;

	dt = &dev_table;
	others = 0;

	fprintf(fp, "        flags: %lx (", dt->flags);
	if (dt->flags & DEV_INIT)
		fprintf(fp, "%sDEV_INIT", others++ ? "|" : "");
	if (dt->flags & DISKIO_INIT)
		fprintf(fp, "%sDISKIO_INIT", others++ ? "|" : "");
	fprintf(fp, ")\n");
}

/*
 *  Dump the I/O ports.
 */

static void
do_io(void)
{
	int i, c, len, wrap, cnt, size;
	ulong *resource_list, name, start, end;
	char *resource_buf, *p1;
	struct list_data list_data, *ld;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];

	if (symbol_exists("get_ioport_list"))   /* linux 2.2 */
		goto ioport_list;
	if (symbol_exists("do_resource_list"))  /* linux 2.4 */
		goto resource_list;
	if (symbol_exists("iomem_resource") && symbol_exists("ioport_resource"))
		goto resource_list;
	return;

ioport_list:
	/*
	 * ioport
	 */
	fprintf(fp, "%s  %s  NAME\n",
		mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "RESOURCE"),
		mkstring(buf2, 9, CENTER|LJUST, "RANGE"));

	wrap = VADDR_PRLEN + 2 + 9 + 2;

        resource_buf = GETBUF(SIZE(resource_entry_t));
	ld = &list_data;
        BZERO(ld, sizeof(struct list_data));
        ld->start = 0xc026cf20;
	readmem(symbol_value("iolist") + OFFSET(resource_entry_t_next),
		KVADDR, &ld->start, sizeof(void *), "iolist.next",
		FAULT_ON_ERROR);
        ld->member_offset = OFFSET(resource_entry_t_next);

        hq_open();
        cnt = do_list(ld);
        if (!cnt)
            	return;
        resource_list = (ulong *)GETBUF(cnt * sizeof(ulong));
        cnt = retrieve_list(resource_list, cnt);
        hq_close();

	for (i = 0; i < cnt; i++) {
		fprintf(fp, "%lx  ", resource_list[i]);
		readmem(resource_list[i], KVADDR, resource_buf,
			SIZE(resource_entry_t), "resource_entry_t",
			FAULT_ON_ERROR); 
		start = ULONG(resource_buf + OFFSET(resource_entry_t_from));
		end = ULONG(resource_buf + OFFSET(resource_entry_t_num));
		end += start;
		fprintf(fp, "%04lx-%04lx  ", start, end);
		name = ULONG(resource_buf + OFFSET(resource_entry_t_name));
                if (!read_string(name, buf1, BUFSIZE-1))
                        sprintf(buf1, "(unknown)");

		if (wrap + strlen(buf1) <= 80)
			fprintf(fp, "%s\n", buf1);
                else {
                        len = wrap + strlen(buf1) - 80;
                        for (c = 0, p1 = &buf1[strlen(buf1)-1];
                             p1 > buf1; p1--, c++) {
                                if (*p1 != ' ')
                                        continue;
                                if (c >= len) {
                                        *p1 = NULLCHAR;
                                        break;
                                }
                        }
                        fprintf(fp, "%s\n", buf1);
                        if (*p1 == NULLCHAR) {
                                pad_line(fp, wrap, ' ');
                                fprintf(fp, "%s\n", p1+1);
                        }
                }
	}

	return;

resource_list:
        resource_buf = GETBUF(SIZE(resource));
	/* 
	 * ioport 
	 */
        readmem(symbol_value("ioport_resource") + OFFSET(resource_end),
                KVADDR, &end, sizeof(long), "ioport_resource.end",
                FAULT_ON_ERROR);

	size = (end > 0xffff) ? 8 : 4;

        fprintf(fp, "%s  %s  NAME\n",
                mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "RESOURCE"),
                mkstring(buf2, (size*2) + 1, 
		CENTER|LJUST, "RANGE"));
	do_resource_list(symbol_value("ioport_resource"), resource_buf, size);

	/* 
	 * iomem 
	 */
        readmem(symbol_value("iomem_resource") + OFFSET(resource_end),
                KVADDR, &end, sizeof(long), "iomem_resource.end",
                FAULT_ON_ERROR);
	size = (end > 0xffff) ? 8 : 4;
        fprintf(fp, "\n%s  %s  NAME\n",
                mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "RESOURCE"),
                mkstring(buf2, (size*2) + 1,
                CENTER|LJUST, "RANGE"));
	do_resource_list(symbol_value("iomem_resource"), resource_buf, size);

	return;
}

static void
do_resource_list(ulong first_entry, char *resource_buf, int size)
{
	ulong entry, name, start, end, child, sibling;
	int c, wrap, len;
	char buf1[BUFSIZE];
	char *fmt, *p1;

	fmt = NULL;

	switch (size)
	{
	case 4:
		fmt = "%8lx  %04lx-%04lx";
		break;
	case 8:
		fmt = "%8lx  %08lx-%08lx";
		break;
	}
	wrap = VADDR_PRLEN + 2 + ((size*2)+1) + 2;

	entry = first_entry;

        while (entry) {
                readmem(entry, KVADDR, resource_buf,
                        SIZE(resource), "resource", FAULT_ON_ERROR);

                start = ULONG(resource_buf + OFFSET(resource_start));
                end = ULONG(resource_buf + OFFSET(resource_end));
                name = ULONG(resource_buf + OFFSET(resource_name));
                child = ULONG(resource_buf + OFFSET(resource_child));
                sibling = ULONG(resource_buf + OFFSET(resource_sibling));

                if (!read_string(name, buf1, BUFSIZE-1))
			sprintf(buf1, "(unknown)");

		fprintf(fp, fmt, entry, start, end);
		if (wrap + strlen(buf1) <= 80)
			fprintf(fp, "  %s\n", buf1);
		else {
			len = wrap + strlen(buf1) - 80;
			for (c = 0, p1 = &buf1[strlen(buf1)-1]; 
			     p1 > buf1; p1--, c++) {
				if (*p1 != ' ')
					continue;
				if (c >= len) {
					*p1 = NULLCHAR;
					break;
				}
			}
			fprintf(fp, "  %s\n", buf1);
			if (*p1 == NULLCHAR) {
				pad_line(fp, wrap, ' ');
				fprintf(fp, "%s\n", p1+1);
			}
		}

		if (child && (child != entry)) 
			do_resource_list(child, resource_buf, size);

                entry = sibling;
        }
}


/*
 *  PCI defines taken from 2.2.17 version of pci.h 
 */

#define USE_2_2_17_PCI_H

#ifdef USE_2_2_17_PCI_H
/*
 *	PCI defines and function prototypes
 *	Copyright 1994, Drew Eckhardt
 *	Copyright 1997--1999 Martin Mares <mj@atrey.karlin.mff.cuni.cz>
 *
 *	For more information, please consult the following manuals (look at
 *	http://www.pcisig.com/ for how to get them):
 *
 *	PCI BIOS Specification
 *	PCI Local Bus Specification
 *	PCI to PCI Bridge Specification
 *	PCI System Design Guide
 */

/*
 * Under PCI, each device has 256 bytes of configuration address space,
 * of which the first 64 bytes are standardized as follows:
 */
#define PCI_VENDOR_ID		0x00	/* 16 bits */
#define PCI_DEVICE_ID		0x02	/* 16 bits */
#define PCI_COMMAND		0x04	/* 16 bits */
#define  PCI_COMMAND_IO		0x1	/* Enable response in I/O space */
#define  PCI_COMMAND_MEMORY	0x2	/* Enable response in Memory space */
#define  PCI_COMMAND_MASTER	0x4	/* Enable bus mastering */
#define  PCI_COMMAND_SPECIAL	0x8	/* Enable response to special cycles */
#define  PCI_COMMAND_INVALIDATE	0x10	/* Use memory write and invalidate */
#define  PCI_COMMAND_VGA_PALETTE 0x20	/* Enable palette snooping */
#define  PCI_COMMAND_PARITY	0x40	/* Enable parity checking */
#define  PCI_COMMAND_WAIT 	0x80	/* Enable address/data stepping */
#define  PCI_COMMAND_SERR	0x100	/* Enable SERR */
#define  PCI_COMMAND_FAST_BACK	0x200	/* Enable back-to-back writes */

#define PCI_STATUS		0x06	/* 16 bits */
#define  PCI_STATUS_CAP_LIST	0x10	/* Support Capability List */
#define  PCI_STATUS_66MHZ	0x20	/* Support 66 Mhz PCI 2.1 bus */
#define  PCI_STATUS_UDF		0x40	/* Support User Definable Features */
#define  PCI_STATUS_FAST_BACK	0x80	/* Accept fast-back to back */
#define  PCI_STATUS_PARITY	0x100	/* Detected parity error */
#define  PCI_STATUS_DEVSEL_MASK	0x600	/* DEVSEL timing */
#define  PCI_STATUS_DEVSEL_FAST	0x000	
#define  PCI_STATUS_DEVSEL_MEDIUM 0x200
#define  PCI_STATUS_DEVSEL_SLOW 0x400
#define  PCI_STATUS_SIG_TARGET_ABORT 0x800 /* Set on target abort */
#define  PCI_STATUS_REC_TARGET_ABORT 0x1000 /* Master ack of " */
#define  PCI_STATUS_REC_MASTER_ABORT 0x2000 /* Set on master abort */
#define  PCI_STATUS_SIG_SYSTEM_ERROR 0x4000 /* Set when we drive SERR */
#define  PCI_STATUS_DETECTED_PARITY 0x8000 /* Set on parity error */

#define PCI_CLASS_REVISION	0x08	/* High 24 bits are class, low 8
					   revision */
#define PCI_REVISION_ID         0x08    /* Revision ID */
#define PCI_CLASS_PROG          0x09    /* Reg. Level Programming Interface */
#define PCI_CLASS_DEVICE        0x0a    /* Device class */

#define PCI_CACHE_LINE_SIZE	0x0c	/* 8 bits */
#define PCI_LATENCY_TIMER	0x0d	/* 8 bits */
#define PCI_HEADER_TYPE		0x0e	/* 8 bits */
#define  PCI_HEADER_TYPE_NORMAL	0
#define  PCI_HEADER_TYPE_BRIDGE 1
#define  PCI_HEADER_TYPE_CARDBUS 2

#define PCI_BIST		0x0f	/* 8 bits */
#define PCI_BIST_CODE_MASK	0x0f	/* Return result */
#define PCI_BIST_START		0x40	/* 1 to start BIST, 2 secs or less */
#define PCI_BIST_CAPABLE	0x80	/* 1 if BIST capable */

/*
 * Base addresses specify locations in memory or I/O space.
 * Decoded size can be determined by writing a value of 
 * 0xffffffff to the register, and reading it back.  Only 
 * 1 bits are decoded.
 */
#define PCI_BASE_ADDRESS_0	0x10	/* 32 bits */
#define PCI_BASE_ADDRESS_1	0x14	/* 32 bits [htype 0,1 only] */
#define PCI_BASE_ADDRESS_2	0x18	/* 32 bits [htype 0 only] */
#define PCI_BASE_ADDRESS_3	0x1c	/* 32 bits */
#define PCI_BASE_ADDRESS_4	0x20	/* 32 bits */
#define PCI_BASE_ADDRESS_5	0x24	/* 32 bits */
#define  PCI_BASE_ADDRESS_SPACE	0x01	/* 0 = memory, 1 = I/O */
#define  PCI_BASE_ADDRESS_SPACE_IO 0x01
#define  PCI_BASE_ADDRESS_SPACE_MEMORY 0x00
#define  PCI_BASE_ADDRESS_MEM_TYPE_MASK 0x06
#define  PCI_BASE_ADDRESS_MEM_TYPE_32	0x00	/* 32 bit address */
#define  PCI_BASE_ADDRESS_MEM_TYPE_1M	0x02	/* Below 1M */
#define  PCI_BASE_ADDRESS_MEM_TYPE_64	0x04	/* 64 bit address */
#define  PCI_BASE_ADDRESS_MEM_PREFETCH	0x08	/* prefetchable? */
#define  PCI_BASE_ADDRESS_MEM_MASK	(~0x0fUL)
#define  PCI_BASE_ADDRESS_IO_MASK	(~0x03UL)
/* bit 1 is reserved if address_space = 1 */

/* Header type 0 (normal devices) */
#define PCI_CARDBUS_CIS		0x28
#define PCI_SUBSYSTEM_VENDOR_ID	0x2c
#define PCI_SUBSYSTEM_ID	0x2e  
#define PCI_ROM_ADDRESS		0x30	/* Bits 31..11 are address, 10..1 reserved */
#define  PCI_ROM_ADDRESS_ENABLE	0x01
#define PCI_ROM_ADDRESS_MASK	(~0x7ffUL)

#define PCI_CAPABILITY_LIST	0x34	/* Offset of first capability list entry */

/* 0x35-0x3b are reserved */
#define PCI_INTERRUPT_LINE	0x3c	/* 8 bits */
#define PCI_INTERRUPT_PIN	0x3d	/* 8 bits */
#define PCI_MIN_GNT		0x3e	/* 8 bits */
#define PCI_MAX_LAT		0x3f	/* 8 bits */

/* Header type 1 (PCI-to-PCI bridges) */
#define PCI_PRIMARY_BUS		0x18	/* Primary bus number */
#define PCI_SECONDARY_BUS	0x19	/* Secondary bus number */
#define PCI_SUBORDINATE_BUS	0x1a	/* Highest bus number behind the bridge */
#define PCI_SEC_LATENCY_TIMER	0x1b	/* Latency timer for secondary interface */
#define PCI_IO_BASE		0x1c	/* I/O range behind the bridge */
#define PCI_IO_LIMIT		0x1d
#define  PCI_IO_RANGE_TYPE_MASK	0x0f	/* I/O bridging type */
#define  PCI_IO_RANGE_TYPE_16	0x00
#define  PCI_IO_RANGE_TYPE_32	0x01
#define  PCI_IO_RANGE_MASK	~0x0f
#define PCI_SEC_STATUS		0x1e	/* Secondary status register, only bit 14 used */
#define PCI_MEMORY_BASE		0x20	/* Memory range behind */
#define PCI_MEMORY_LIMIT	0x22
#define  PCI_MEMORY_RANGE_TYPE_MASK 0x0f
#define  PCI_MEMORY_RANGE_MASK	~0x0f
#define PCI_PREF_MEMORY_BASE	0x24	/* Prefetchable memory range behind */
#define PCI_PREF_MEMORY_LIMIT	0x26
#define  PCI_PREF_RANGE_TYPE_MASK 0x0f
#define  PCI_PREF_RANGE_TYPE_32	0x00
#define  PCI_PREF_RANGE_TYPE_64	0x01
#define  PCI_PREF_RANGE_MASK	~0x0f
#define PCI_PREF_BASE_UPPER32	0x28	/* Upper half of prefetchable memory range */
#define PCI_PREF_LIMIT_UPPER32	0x2c
#define PCI_IO_BASE_UPPER16	0x30	/* Upper half of I/O addresses */
#define PCI_IO_LIMIT_UPPER16	0x32
/* 0x34-0x3b is reserved */
#define PCI_ROM_ADDRESS1	0x38	/* Same as PCI_ROM_ADDRESS, but for htype 1 */
/* 0x3c-0x3d are same as for htype 0 */
#define PCI_BRIDGE_CONTROL	0x3e
#define  PCI_BRIDGE_CTL_PARITY	0x01	/* Enable parity detection on secondary interface */
#define  PCI_BRIDGE_CTL_SERR	0x02	/* The same for SERR forwarding */
#define  PCI_BRIDGE_CTL_NO_ISA	0x04	/* Disable bridging of ISA ports */
#define  PCI_BRIDGE_CTL_VGA	0x08	/* Forward VGA addresses */
#define  PCI_BRIDGE_CTL_MASTER_ABORT 0x20  /* Report master aborts */
#define  PCI_BRIDGE_CTL_BUS_RESET 0x40	/* Secondary bus reset */
#define  PCI_BRIDGE_CTL_FAST_BACK 0x80	/* Fast Back2Back enabled on secondary interface */

/* Header type 2 (CardBus bridges) */
/* 0x14-0x15 reserved */
#define PCI_CB_SEC_STATUS	0x16	/* Secondary status */
#define PCI_CB_PRIMARY_BUS	0x18	/* PCI bus number */
#define PCI_CB_CARD_BUS		0x19	/* CardBus bus number */
#define PCI_CB_SUBORDINATE_BUS	0x1a	/* Subordinate bus number */
#define PCI_CB_LATENCY_TIMER	0x1b	/* CardBus latency timer */
#define PCI_CB_MEMORY_BASE_0	0x1c
#define PCI_CB_MEMORY_LIMIT_0	0x20
#define PCI_CB_MEMORY_BASE_1	0x24
#define PCI_CB_MEMORY_LIMIT_1	0x28
#define PCI_CB_IO_BASE_0	0x2c
#define PCI_CB_IO_BASE_0_HI	0x2e
#define PCI_CB_IO_LIMIT_0	0x30
#define PCI_CB_IO_LIMIT_0_HI	0x32
#define PCI_CB_IO_BASE_1	0x34
#define PCI_CB_IO_BASE_1_HI	0x36
#define PCI_CB_IO_LIMIT_1	0x38
#define PCI_CB_IO_LIMIT_1_HI	0x3a
#define  PCI_CB_IO_RANGE_MASK	~0x03
/* 0x3c-0x3d are same as for htype 0 */
#define PCI_CB_BRIDGE_CONTROL	0x3e
#define  PCI_CB_BRIDGE_CTL_PARITY	0x01	/* Similar to standard bridge control register */
#define  PCI_CB_BRIDGE_CTL_SERR		0x02
#define  PCI_CB_BRIDGE_CTL_ISA		0x04
#define  PCI_CB_BRIDGE_CTL_VGA		0x08
#define  PCI_CB_BRIDGE_CTL_MASTER_ABORT	0x20
#define  PCI_CB_BRIDGE_CTL_CB_RESET	0x40	/* CardBus reset */
#define  PCI_CB_BRIDGE_CTL_16BIT_INT	0x80	/* Enable interrupt for 16-bit cards */
#define  PCI_CB_BRIDGE_CTL_PREFETCH_MEM0 0x100	/* Prefetch enable for both memory regions */
#define  PCI_CB_BRIDGE_CTL_PREFETCH_MEM1 0x200
#define  PCI_CB_BRIDGE_CTL_POST_WRITES	0x400
#define PCI_CB_SUBSYSTEM_VENDOR_ID 0x40
#define PCI_CB_SUBSYSTEM_ID	0x42
#define PCI_CB_LEGACY_MODE_BASE	0x44	/* 16-bit PC Card legacy mode base address (ExCa) */
/* 0x48-0x7f reserved */

/* Capability lists */
#define PCI_CAP_LIST_ID		0	/* Capability ID */
#define  PCI_CAP_ID_PM		0x01	/* Power Management */
#define  PCI_CAP_ID_AGP		0x02	/* Accelerated Graphics Port */
#define PCI_CAP_LIST_NEXT	1	/* Next capability in the list */

/* Device classes and subclasses */

#define PCI_CLASS_NOT_DEFINED		0x0000
#define PCI_CLASS_NOT_DEFINED_VGA	0x0001

#define PCI_BASE_CLASS_STORAGE		0x01
#define PCI_CLASS_STORAGE_SCSI		0x0100
#define PCI_CLASS_STORAGE_IDE		0x0101
#define PCI_CLASS_STORAGE_FLOPPY	0x0102
#define PCI_CLASS_STORAGE_IPI		0x0103
#define PCI_CLASS_STORAGE_RAID		0x0104
#define PCI_CLASS_STORAGE_OTHER		0x0180

#define PCI_BASE_CLASS_NETWORK		0x02
#define PCI_CLASS_NETWORK_ETHERNET	0x0200
#define PCI_CLASS_NETWORK_TOKEN_RING	0x0201
#define PCI_CLASS_NETWORK_FDDI		0x0202
#define PCI_CLASS_NETWORK_ATM		0x0203
#define PCI_CLASS_NETWORK_OTHER		0x0280

#define PCI_BASE_CLASS_DISPLAY		0x03
#define PCI_CLASS_DISPLAY_VGA		0x0300
#define PCI_CLASS_DISPLAY_XGA		0x0301
#define PCI_CLASS_DISPLAY_OTHER		0x0380

#define PCI_BASE_CLASS_MULTIMEDIA	0x04
#define PCI_CLASS_MULTIMEDIA_VIDEO	0x0400
#define PCI_CLASS_MULTIMEDIA_AUDIO	0x0401
#define PCI_CLASS_MULTIMEDIA_OTHER	0x0480

#define PCI_BASE_CLASS_MEMORY		0x05
#define  PCI_CLASS_MEMORY_RAM		0x0500
#define  PCI_CLASS_MEMORY_FLASH		0x0501
#define  PCI_CLASS_MEMORY_OTHER		0x0580

#define PCI_BASE_CLASS_BRIDGE		0x06
#define  PCI_CLASS_BRIDGE_HOST		0x0600
#define  PCI_CLASS_BRIDGE_ISA		0x0601
#define  PCI_CLASS_BRIDGE_EISA		0x0602
#define  PCI_CLASS_BRIDGE_MC		0x0603
#define  PCI_CLASS_BRIDGE_PCI		0x0604
#define  PCI_CLASS_BRIDGE_PCMCIA	0x0605
#define  PCI_CLASS_BRIDGE_NUBUS		0x0606
#define  PCI_CLASS_BRIDGE_CARDBUS	0x0607
#define  PCI_CLASS_BRIDGE_OTHER		0x0680

#define PCI_BASE_CLASS_COMMUNICATION	0x07
#define PCI_CLASS_COMMUNICATION_SERIAL	0x0700
#define PCI_CLASS_COMMUNICATION_PARALLEL 0x0701
#define PCI_CLASS_COMMUNICATION_OTHER	0x0780

#define PCI_BASE_CLASS_SYSTEM		0x08
#define PCI_CLASS_SYSTEM_PIC		0x0800
#define PCI_CLASS_SYSTEM_DMA		0x0801
#define PCI_CLASS_SYSTEM_TIMER		0x0802
#define PCI_CLASS_SYSTEM_RTC		0x0803
#define PCI_CLASS_SYSTEM_OTHER		0x0880

#define PCI_BASE_CLASS_INPUT		0x09
#define PCI_CLASS_INPUT_KEYBOARD	0x0900
#define PCI_CLASS_INPUT_PEN		0x0901
#define PCI_CLASS_INPUT_MOUSE		0x0902
#define PCI_CLASS_INPUT_OTHER		0x0980

#define PCI_BASE_CLASS_DOCKING		0x0a
#define PCI_CLASS_DOCKING_GENERIC	0x0a00
#define PCI_CLASS_DOCKING_OTHER		0x0a01

#define PCI_BASE_CLASS_PROCESSOR	0x0b
#define PCI_CLASS_PROCESSOR_386		0x0b00
#define PCI_CLASS_PROCESSOR_486		0x0b01
#define PCI_CLASS_PROCESSOR_PENTIUM	0x0b02
#define PCI_CLASS_PROCESSOR_ALPHA	0x0b10
#define PCI_CLASS_PROCESSOR_POWERPC	0x0b20
#define PCI_CLASS_PROCESSOR_CO		0x0b40

#define PCI_BASE_CLASS_SERIAL		0x0c
#define PCI_CLASS_SERIAL_FIREWIRE	0x0c00
#define PCI_CLASS_SERIAL_ACCESS		0x0c01
#define PCI_CLASS_SERIAL_SSA		0x0c02
#define PCI_CLASS_SERIAL_USB		0x0c03
#define PCI_CLASS_SERIAL_FIBER		0x0c04
#define PCI_CLASS_SERIAL_SMBUS		0x0c05

#define PCI_BASE_CLASS_INTELLIGENT      0x0e
#define PCI_CLASS_INTELLIGENT_I2O       0x0e00

#define PCI_CLASS_HOT_SWAP_CONTROLLER	0xff00

#define PCI_CLASS_OTHERS		0xff

/*
 * Vendor and card ID's: sort these numerically according to vendor
 * (and according to card ID within vendor). Send all updates to
 * <linux-pcisupport@cck.uni-kl.de>.
 */
#define PCI_VENDOR_ID_COMPAQ		0x0e11
#define PCI_DEVICE_ID_COMPAQ_TOKENRING	0x0508
#define PCI_DEVICE_ID_COMPAQ_1280	0x3033
#define PCI_DEVICE_ID_COMPAQ_TRIFLEX	0x4000
#define PCI_DEVICE_ID_COMPAQ_6010	0x6010
#define PCI_DEVICE_ID_COMPAQ_SMART2P	0xae10
#define PCI_DEVICE_ID_COMPAQ_NETEL100	0xae32
#define PCI_DEVICE_ID_COMPAQ_NETEL10	0xae34
#define PCI_DEVICE_ID_COMPAQ_NETFLEX3I	0xae35
#define PCI_DEVICE_ID_COMPAQ_NETEL100D	0xae40
#define PCI_DEVICE_ID_COMPAQ_NETEL100PI	0xae43
#define PCI_DEVICE_ID_COMPAQ_NETEL100I	0xb011
#define PCI_DEVICE_ID_COMPAQ_THUNDER	0xf130
#define PCI_DEVICE_ID_COMPAQ_NETFLEX3B	0xf150

#define PCI_VENDOR_ID_NCR		0x1000
#define PCI_DEVICE_ID_NCR_53C810	0x0001
#define PCI_DEVICE_ID_NCR_53C820	0x0002
#define PCI_DEVICE_ID_NCR_53C825	0x0003
#define PCI_DEVICE_ID_NCR_53C815	0x0004
#define PCI_DEVICE_ID_NCR_53C860	0x0006
#define PCI_DEVICE_ID_NCR_53C1510D	0x000a
#define PCI_DEVICE_ID_NCR_53C896	0x000b
#define PCI_DEVICE_ID_NCR_53C895	0x000c
#define PCI_DEVICE_ID_NCR_53C885	0x000d
#define PCI_DEVICE_ID_NCR_53C875	0x000f
#define PCI_DEVICE_ID_NCR_53C1510	0x0010
#define PCI_DEVICE_ID_NCR_53C875J	0x008f

#define PCI_VENDOR_ID_ATI		0x1002
#define PCI_DEVICE_ID_ATI_68800		0x4158
#define PCI_DEVICE_ID_ATI_215CT222	0x4354
#define PCI_DEVICE_ID_ATI_210888CX	0x4358
#define PCI_DEVICE_ID_ATI_215GB		0x4742
#define PCI_DEVICE_ID_ATI_215GD		0x4744
#define PCI_DEVICE_ID_ATI_215GI		0x4749
#define PCI_DEVICE_ID_ATI_215GP		0x4750
#define PCI_DEVICE_ID_ATI_215GQ		0x4751
#define PCI_DEVICE_ID_ATI_215GT		0x4754
#define PCI_DEVICE_ID_ATI_215GTB	0x4755
#define PCI_DEVICE_ID_ATI_210888GX	0x4758
#define PCI_DEVICE_ID_ATI_RAGE128_LE	0x4c45
#define PCI_DEVICE_ID_ATI_RAGE128_LF	0x4c46
#define PCI_DEVICE_ID_ATI_215LG		0x4c47
#define PCI_DEVICE_ID_ATI_264LT		0x4c54
#define PCI_DEVICE_ID_ATI_RAGE128_PF	0x5046
#define PCI_DEVICE_ID_ATI_RAGE128_PR	0x5052
#define PCI_DEVICE_ID_ATI_RAGE128_RE	0x5245
#define PCI_DEVICE_ID_ATI_RAGE128_RF	0x5246
#define PCI_DEVICE_ID_ATI_RAGE128_RK	0x524b
#define PCI_DEVICE_ID_ATI_RAGE128_RL	0x524c
#define PCI_DEVICE_ID_ATI_264VT		0x5654

#define PCI_VENDOR_ID_VLSI		0x1004
#define PCI_DEVICE_ID_VLSI_82C592	0x0005
#define PCI_DEVICE_ID_VLSI_82C593	0x0006
#define PCI_DEVICE_ID_VLSI_82C594	0x0007
#define PCI_DEVICE_ID_VLSI_82C597	0x0009
#define PCI_DEVICE_ID_VLSI_82C541	0x000c
#define PCI_DEVICE_ID_VLSI_82C543	0x000d
#define PCI_DEVICE_ID_VLSI_82C532	0x0101
#define PCI_DEVICE_ID_VLSI_82C534	0x0102
#define PCI_DEVICE_ID_VLSI_82C535	0x0104
#define PCI_DEVICE_ID_VLSI_82C147	0x0105
#define PCI_DEVICE_ID_VLSI_VAS96011	0x0702

#define PCI_VENDOR_ID_ADL		0x1005
#define PCI_DEVICE_ID_ADL_2301		0x2301

#define PCI_VENDOR_ID_NS		0x100b
#define PCI_DEVICE_ID_NS_87415		0x0002
#define PCI_DEVICE_ID_NS_87410		0xd001

#define PCI_VENDOR_ID_TSENG		0x100c
#define PCI_DEVICE_ID_TSENG_W32P_2	0x3202
#define PCI_DEVICE_ID_TSENG_W32P_b	0x3205
#define PCI_DEVICE_ID_TSENG_W32P_c	0x3206
#define PCI_DEVICE_ID_TSENG_W32P_d	0x3207
#define PCI_DEVICE_ID_TSENG_ET6000	0x3208

#define PCI_VENDOR_ID_WEITEK		0x100e
#define PCI_DEVICE_ID_WEITEK_P9000	0x9001
#define PCI_DEVICE_ID_WEITEK_P9100	0x9100

#define PCI_VENDOR_ID_DEC		0x1011
#define PCI_DEVICE_ID_DEC_BRD		0x0001
#define PCI_DEVICE_ID_DEC_TULIP		0x0002
#define PCI_DEVICE_ID_DEC_TGA		0x0004
#define PCI_DEVICE_ID_DEC_TULIP_FAST	0x0009
#define PCI_DEVICE_ID_DEC_TGA2		0x000D
#define PCI_DEVICE_ID_DEC_FDDI		0x000F
#define PCI_DEVICE_ID_DEC_TULIP_PLUS	0x0014
#define PCI_DEVICE_ID_DEC_21142		0x0019
#define PCI_DEVICE_ID_DEC_21052		0x0021
#define PCI_DEVICE_ID_DEC_21150		0x0022
#define PCI_DEVICE_ID_DEC_21152		0x0024
#define PCI_DEVICE_ID_DEC_21153		0x0025
#define PCI_DEVICE_ID_DEC_21154		0x0026
#define PCI_DEVICE_ID_DEC_21285		0x1065
#define PCI_DEVICE_ID_DEC_21554		0x0046
#define PCI_DEVICE_ID_COMPAQ_42XX	0x0046

#define PCI_VENDOR_ID_CIRRUS		0x1013
#define PCI_DEVICE_ID_CIRRUS_7548	0x0038
#define PCI_DEVICE_ID_CIRRUS_5430	0x00a0
#define PCI_DEVICE_ID_CIRRUS_5434_4	0x00a4
#define PCI_DEVICE_ID_CIRRUS_5434_8	0x00a8
#define PCI_DEVICE_ID_CIRRUS_5436	0x00ac
#define PCI_DEVICE_ID_CIRRUS_5446	0x00b8
#define PCI_DEVICE_ID_CIRRUS_5480	0x00bc
#define PCI_DEVICE_ID_CIRRUS_5464	0x00d4
#define PCI_DEVICE_ID_CIRRUS_5465	0x00d6
#define PCI_DEVICE_ID_CIRRUS_6729	0x1100
#define PCI_DEVICE_ID_CIRRUS_6832	0x1110
#define PCI_DEVICE_ID_CIRRUS_7542	0x1200
#define PCI_DEVICE_ID_CIRRUS_7543	0x1202
#define PCI_DEVICE_ID_CIRRUS_7541	0x1204

#define PCI_VENDOR_ID_IBM		0x1014
#define PCI_DEVICE_ID_IBM_FIRE_CORAL	0x000a
#define PCI_DEVICE_ID_IBM_TR		0x0018
#define PCI_DEVICE_ID_IBM_82G2675	0x001d
#define PCI_DEVICE_ID_IBM_MCA		0x0020
#define PCI_DEVICE_ID_IBM_82351		0x0022
#define PCI_DEVICE_ID_IBM_PYTHON	0x002d
#define PCI_DEVICE_ID_IBM_SERVERAID	0x002e
#define PCI_DEVICE_ID_IBM_TR_WAKE	0x003e
#define PCI_DEVICE_ID_IBM_MPIC		0x0046
#define PCI_DEVICE_ID_IBM_3780IDSP	0x007d
#define PCI_DEVICE_ID_IBM_MPIC_2	0xffff

#define PCI_VENDOR_ID_WD		0x101c
#define PCI_DEVICE_ID_WD_7197		0x3296

#define PCI_VENDOR_ID_AMD		0x1022
#define PCI_DEVICE_ID_AMD_LANCE		0x2000
#define PCI_DEVICE_ID_AMD_LANCE_HOME	0x2001
#define PCI_DEVICE_ID_AMD_SCSI		0x2020

#define PCI_VENDOR_ID_TRIDENT		0x1023
#define PCI_DEVICE_ID_TRIDENT_9397	0x9397
#define PCI_DEVICE_ID_TRIDENT_9420	0x9420
#define PCI_DEVICE_ID_TRIDENT_9440	0x9440
#define PCI_DEVICE_ID_TRIDENT_9660	0x9660
#define PCI_DEVICE_ID_TRIDENT_9750	0x9750

#define PCI_VENDOR_ID_AI		0x1025
#define PCI_DEVICE_ID_AI_M1435		0x1435

#define PCI_VENDOR_ID_MATROX		0x102B
#define PCI_DEVICE_ID_MATROX_MGA_2	0x0518
#define PCI_DEVICE_ID_MATROX_MIL	0x0519
#define PCI_DEVICE_ID_MATROX_MYS	0x051A
#define PCI_DEVICE_ID_MATROX_MIL_2	0x051b
#define PCI_DEVICE_ID_MATROX_MIL_2_AGP	0x051f
#define PCI_DEVICE_ID_MATROX_G200_PCI   0x0520
#define PCI_DEVICE_ID_MATROX_G200_AGP   0x0521
#define PCI_DEVICE_ID_MATROX_MGA_IMP	0x0d10
#define PCI_DEVICE_ID_MATROX_G100_MM    0x1000
#define PCI_DEVICE_ID_MATROX_G100_AGP   0x1001

#define PCI_VENDOR_ID_CT		0x102c
#define PCI_DEVICE_ID_CT_65545		0x00d8
#define PCI_DEVICE_ID_CT_65548		0x00dc
#define PCI_DEVICE_ID_CT_65550		0x00e0
#define PCI_DEVICE_ID_CT_65554		0x00e4
#define PCI_DEVICE_ID_CT_65555		0x00e5

#define PCI_VENDOR_ID_MIRO		0x1031
#define PCI_DEVICE_ID_MIRO_36050	0x5601

#define PCI_VENDOR_ID_NEC		0x1033
#define PCI_DEVICE_ID_NEC_PCX2		0x0046

#define PCI_VENDOR_ID_FD		0x1036
#define PCI_DEVICE_ID_FD_36C70		0x0000

#define PCI_VENDOR_ID_SI		0x1039
#define PCI_DEVICE_ID_SI_5591_AGP	0x0001
#define PCI_DEVICE_ID_SI_6202		0x0002
#define PCI_DEVICE_ID_SI_503		0x0008
#define PCI_DEVICE_ID_SI_ACPI		0x0009
#define PCI_DEVICE_ID_SI_5597_VGA	0x0200
#define PCI_DEVICE_ID_SI_6205		0x0205
#define PCI_DEVICE_ID_SI_501		0x0406
#define PCI_DEVICE_ID_SI_496		0x0496
#define PCI_DEVICE_ID_SI_601		0x0601
#define PCI_DEVICE_ID_SI_5107		0x5107
#define PCI_DEVICE_ID_SI_5511		0x5511
#define PCI_DEVICE_ID_SI_5513		0x5513
#define PCI_DEVICE_ID_SI_5571		0x5571
#define PCI_DEVICE_ID_SI_5591		0x5591
#define PCI_DEVICE_ID_SI_5597		0x5597
#define PCI_DEVICE_ID_SI_7001		0x7001

#define PCI_VENDOR_ID_HP		0x103c
#define PCI_DEVICE_ID_HP_J2585A		0x1030
#define PCI_DEVICE_ID_HP_J2585B		0x1031

#define PCI_VENDOR_ID_PCTECH		0x1042
#define PCI_DEVICE_ID_PCTECH_RZ1000	0x1000
#define PCI_DEVICE_ID_PCTECH_RZ1001	0x1001
#define PCI_DEVICE_ID_PCTECH_SAMURAI_0	0x3000
#define PCI_DEVICE_ID_PCTECH_SAMURAI_1	0x3010
#define PCI_DEVICE_ID_PCTECH_SAMURAI_IDE 0x3020

#define PCI_VENDOR_ID_DPT               0x1044   
#define PCI_DEVICE_ID_DPT               0xa400  

#define PCI_VENDOR_ID_OPTI		0x1045
#define PCI_DEVICE_ID_OPTI_92C178	0xc178
#define PCI_DEVICE_ID_OPTI_82C557	0xc557
#define PCI_DEVICE_ID_OPTI_82C558	0xc558
#define PCI_DEVICE_ID_OPTI_82C621	0xc621
#define PCI_DEVICE_ID_OPTI_82C700	0xc700
#define PCI_DEVICE_ID_OPTI_82C701	0xc701
#define PCI_DEVICE_ID_OPTI_82C814	0xc814
#define PCI_DEVICE_ID_OPTI_82C822	0xc822
#define PCI_DEVICE_ID_OPTI_82C861	0xc861
#define PCI_DEVICE_ID_OPTI_82C825	0xd568

#define PCI_VENDOR_ID_SGS		0x104a
#define PCI_DEVICE_ID_SGS_2000		0x0008
#define PCI_DEVICE_ID_SGS_1764		0x0009

#define PCI_VENDOR_ID_BUSLOGIC		      0x104B
#define PCI_DEVICE_ID_BUSLOGIC_MULTIMASTER_NC 0x0140
#define PCI_DEVICE_ID_BUSLOGIC_MULTIMASTER    0x1040
#define PCI_DEVICE_ID_BUSLOGIC_FLASHPOINT     0x8130

#define PCI_VENDOR_ID_TI		0x104c
#define PCI_DEVICE_ID_TI_TVP4010	0x3d04
#define PCI_DEVICE_ID_TI_TVP4020	0x3d07
#define PCI_DEVICE_ID_TI_PCI1130	0xac12
#define PCI_DEVICE_ID_TI_PCI1031	0xac13
#define PCI_DEVICE_ID_TI_PCI1131	0xac15
#define PCI_DEVICE_ID_TI_PCI1250	0xac16
#define PCI_DEVICE_ID_TI_PCI1220	0xac17

#define PCI_VENDOR_ID_OAK		0x104e
#define PCI_DEVICE_ID_OAK_OTI107	0x0107

/* Winbond have two vendor IDs! See 0x10ad as well */
#define PCI_VENDOR_ID_WINBOND2		0x1050
#define PCI_DEVICE_ID_WINBOND2_89C940	0x0940

#define PCI_VENDOR_ID_MOTOROLA		0x1057
#define PCI_VENDOR_ID_MOTOROLA_OOPS	0x1507
#define PCI_DEVICE_ID_MOTOROLA_MPC105	0x0001
#define PCI_DEVICE_ID_MOTOROLA_MPC106	0x0002
#define PCI_DEVICE_ID_MOTOROLA_RAVEN	0x4801
#define PCI_DEVICE_ID_MOTOROLA_FALCON	0x4802
#define PCI_DEVICE_ID_MOTOROLA_CPX8216	0x4806

#define PCI_VENDOR_ID_PROMISE		0x105a
#define PCI_DEVICE_ID_PROMISE_20246	0x4d33
#define PCI_DEVICE_ID_PROMISE_5300	0x5300

#define PCI_VENDOR_ID_N9		0x105d
#define PCI_DEVICE_ID_N9_I128		0x2309
#define PCI_DEVICE_ID_N9_I128_2		0x2339
#define PCI_DEVICE_ID_N9_I128_T2R	0x493d

#define PCI_VENDOR_ID_UMC		0x1060
#define PCI_DEVICE_ID_UMC_UM8673F	0x0101
#define PCI_DEVICE_ID_UMC_UM8891A	0x0891
#define PCI_DEVICE_ID_UMC_UM8886BF	0x673a
#define PCI_DEVICE_ID_UMC_UM8886A	0x886a
#define PCI_DEVICE_ID_UMC_UM8881F	0x8881
#define PCI_DEVICE_ID_UMC_UM8886F	0x8886
#define PCI_DEVICE_ID_UMC_UM9017F	0x9017
#define PCI_DEVICE_ID_UMC_UM8886N	0xe886
#define PCI_DEVICE_ID_UMC_UM8891N	0xe891

#define PCI_VENDOR_ID_X			0x1061
#define PCI_DEVICE_ID_X_AGX016		0x0001

#define PCI_VENDOR_ID_PICOP		0x1066
#define PCI_DEVICE_ID_PICOP_PT86C52X	0x0001
#define PCI_DEVICE_ID_PICOP_PT80C524	0x8002

#define PCI_VENDOR_ID_MYLEX		0x1069
#define PCI_DEVICE_ID_MYLEX_DAC960_P	0x0001
#define PCI_DEVICE_ID_MYLEX_DAC960_PD	0x0002
#define PCI_DEVICE_ID_MYLEX_DAC960_PG	0x0010
#define PCI_DEVICE_ID_MYLEX_DAC960_LA	0x0020
#define PCI_DEVICE_ID_MYLEX_DAC960_LP	0x0050
#define PCI_DEVICE_ID_MYLEX_DAC960_BA	0xBA56

#define PCI_VENDOR_ID_APPLE		0x106b
#define PCI_DEVICE_ID_APPLE_BANDIT	0x0001
#define PCI_DEVICE_ID_APPLE_GC		0x0002
#define PCI_DEVICE_ID_APPLE_HYDRA	0x000e

#define PCI_VENDOR_ID_NEXGEN		0x1074
#define PCI_DEVICE_ID_NEXGEN_82C501	0x4e78

#define PCI_VENDOR_ID_QLOGIC		0x1077
#define PCI_DEVICE_ID_QLOGIC_ISP1020	0x1020
#define PCI_DEVICE_ID_QLOGIC_ISP1022	0x1022
#define PCI_DEVICE_ID_QLOGIC_ISP2100	0x2100
#define PCI_DEVICE_ID_QLOGIC_ISP2200	0x2200

#define PCI_VENDOR_ID_CYRIX		0x1078
#define PCI_DEVICE_ID_CYRIX_5510	0x0000
#define PCI_DEVICE_ID_CYRIX_PCI_MASTER	0x0001
#define PCI_DEVICE_ID_CYRIX_5520	0x0002
#define PCI_DEVICE_ID_CYRIX_5530_LEGACY	0x0100
#define PCI_DEVICE_ID_CYRIX_5530_SMI	0x0101
#define PCI_DEVICE_ID_CYRIX_5530_IDE	0x0102
#define PCI_DEVICE_ID_CYRIX_5530_AUDIO	0x0103
#define PCI_DEVICE_ID_CYRIX_5530_VIDEO	0x0104

#define PCI_VENDOR_ID_LEADTEK		0x107d
#define PCI_DEVICE_ID_LEADTEK_805	0x0000

#define PCI_VENDOR_ID_CONTAQ		0x1080
#define PCI_DEVICE_ID_CONTAQ_82C599	0x0600
#define PCI_DEVICE_ID_CONTAQ_82C693	0xc693

#define PCI_VENDOR_ID_FOREX		0x1083

#define PCI_VENDOR_ID_OLICOM		0x108d
#define PCI_DEVICE_ID_OLICOM_OC3136	0x0001
#define PCI_DEVICE_ID_OLICOM_OC2315	0x0011
#define PCI_DEVICE_ID_OLICOM_OC2325	0x0012
#define PCI_DEVICE_ID_OLICOM_OC2183	0x0013
#define PCI_DEVICE_ID_OLICOM_OC2326	0x0014
#define PCI_DEVICE_ID_OLICOM_OC6151	0x0021

#define PCI_VENDOR_ID_SUN		0x108e
#define PCI_DEVICE_ID_SUN_EBUS		0x1000
#define PCI_DEVICE_ID_SUN_HAPPYMEAL	0x1001
#define PCI_DEVICE_ID_SUN_SIMBA		0x5000
#define PCI_DEVICE_ID_SUN_PBM		0x8000
#define PCI_DEVICE_ID_SUN_SABRE		0xa000

#define PCI_VENDOR_ID_CMD		0x1095
#define PCI_DEVICE_ID_CMD_640		0x0640
#define PCI_DEVICE_ID_CMD_643		0x0643
#define PCI_DEVICE_ID_CMD_646		0x0646
#define PCI_DEVICE_ID_CMD_647		0x0647
#define PCI_DEVICE_ID_CMD_670		0x0670

#define PCI_VENDOR_ID_VISION		0x1098
#define PCI_DEVICE_ID_VISION_QD8500	0x0001
#define PCI_DEVICE_ID_VISION_QD8580	0x0002

#define PCI_VENDOR_ID_BROOKTREE		0x109e
#define PCI_DEVICE_ID_BROOKTREE_848	0x0350
#define PCI_DEVICE_ID_BROOKTREE_849A	0x0351
#define PCI_DEVICE_ID_BROOKTREE_878_1   0x036e
#define PCI_DEVICE_ID_BROOKTREE_878     0x0878
#define PCI_DEVICE_ID_BROOKTREE_8474	0x8474

#define PCI_VENDOR_ID_SIERRA		0x10a8
#define PCI_DEVICE_ID_SIERRA_STB	0x0000

#define PCI_VENDOR_ID_ACC		0x10aa
#define PCI_DEVICE_ID_ACC_2056		0x0000

#define PCI_VENDOR_ID_WINBOND		0x10ad
#define PCI_DEVICE_ID_WINBOND_83769	0x0001
#define PCI_DEVICE_ID_WINBOND_82C105	0x0105
#define PCI_DEVICE_ID_WINBOND_83C553	0x0565

#define PCI_VENDOR_ID_DATABOOK		0x10b3
#define PCI_DEVICE_ID_DATABOOK_87144	0xb106

#define PCI_VENDOR_ID_PLX		0x10b5
#define PCI_DEVICE_ID_PLX_9050		0x9050
#define PCI_DEVICE_ID_PLX_9060		0x9060
#define PCI_DEVICE_ID_PLX_9060ES	0x906E
#define PCI_DEVICE_ID_PLX_9060SD	0x906D
#define PCI_DEVICE_ID_PLX_9080		0x9080

#define PCI_VENDOR_ID_MADGE		0x10b6
#define PCI_DEVICE_ID_MADGE_MK2		0x0002
#define PCI_DEVICE_ID_MADGE_C155S	0x1001

#define PCI_VENDOR_ID_3COM		0x10b7
#define PCI_DEVICE_ID_3COM_3C985	0x0001
#define PCI_DEVICE_ID_3COM_3C339	0x3390
#define PCI_DEVICE_ID_3COM_3C590	0x5900
#define PCI_DEVICE_ID_3COM_3C595TX	0x5950
#define PCI_DEVICE_ID_3COM_3C595T4	0x5951
#define PCI_DEVICE_ID_3COM_3C595MII	0x5952
#define PCI_DEVICE_ID_3COM_3C900TPO	0x9000
#define PCI_DEVICE_ID_3COM_3C900COMBO	0x9001
#define PCI_DEVICE_ID_3COM_3C905TX	0x9050
#define PCI_DEVICE_ID_3COM_3C905T4	0x9051
#define PCI_DEVICE_ID_3COM_3C905B_TX	0x9055

#define PCI_VENDOR_ID_SMC		0x10b8
#define PCI_DEVICE_ID_SMC_EPIC100	0x0005

#define PCI_VENDOR_ID_AL		0x10b9
#define PCI_DEVICE_ID_AL_M1445		0x1445
#define PCI_DEVICE_ID_AL_M1449		0x1449
#define PCI_DEVICE_ID_AL_M1451		0x1451
#define PCI_DEVICE_ID_AL_M1461		0x1461
#define PCI_DEVICE_ID_AL_M1489		0x1489
#define PCI_DEVICE_ID_AL_M1511		0x1511
#define PCI_DEVICE_ID_AL_M1513		0x1513
#define PCI_DEVICE_ID_AL_M1521		0x1521
#define PCI_DEVICE_ID_AL_M1523		0x1523
#define PCI_DEVICE_ID_AL_M1531		0x1531
#define PCI_DEVICE_ID_AL_M1533		0x1533
#define PCI_DEVICE_ID_AL_M3307		0x3307
#define PCI_DEVICE_ID_AL_M4803		0x5215
#define PCI_DEVICE_ID_AL_M5219		0x5219
#define PCI_DEVICE_ID_AL_M5229		0x5229
#define PCI_DEVICE_ID_AL_M5237		0x5237
#define PCI_DEVICE_ID_AL_M7101		0x7101

#define PCI_VENDOR_ID_MITSUBISHI	0x10ba

#define PCI_VENDOR_ID_SURECOM		0x10bd
#define PCI_DEVICE_ID_SURECOM_NE34	0x0e34

#define PCI_VENDOR_ID_NEOMAGIC          0x10c8
#define PCI_DEVICE_ID_NEOMAGIC_MAGICGRAPH_NM2070 0x0001
#define PCI_DEVICE_ID_NEOMAGIC_MAGICGRAPH_128V 0x0002
#define PCI_DEVICE_ID_NEOMAGIC_MAGICGRAPH_128ZV 0x0003
#define PCI_DEVICE_ID_NEOMAGIC_MAGICGRAPH_NM2160 0x0004
#define PCI_DEVICE_ID_NEOMAGIC_MAGICMEDIA_256AV       0x0005
#define PCI_DEVICE_ID_NEOMAGIC_MAGICGRAPH_128ZVPLUS   0x0083

#define PCI_VENDOR_ID_ASP		0x10cd
#define PCI_DEVICE_ID_ASP_ABP940	0x1200
#define PCI_DEVICE_ID_ASP_ABP940U	0x1300
#define PCI_DEVICE_ID_ASP_ABP940UW	0x2300

#define PCI_VENDOR_ID_MACRONIX		0x10d9
#define PCI_DEVICE_ID_MACRONIX_MX98713	0x0512
#define PCI_DEVICE_ID_MACRONIX_MX987x5	0x0531

#define PCI_VENDOR_ID_CERN		0x10dc
#define PCI_DEVICE_ID_CERN_SPSB_PMC	0x0001
#define PCI_DEVICE_ID_CERN_SPSB_PCI	0x0002
#define PCI_DEVICE_ID_CERN_HIPPI_DST	0x0021
#define PCI_DEVICE_ID_CERN_HIPPI_SRC	0x0022

#define PCI_VENDOR_ID_NVIDIA		0x10de

#define PCI_VENDOR_ID_IMS		0x10e0
#define PCI_DEVICE_ID_IMS_8849		0x8849

#define PCI_VENDOR_ID_TEKRAM2		0x10e1
#define PCI_DEVICE_ID_TEKRAM2_690c	0x690c

#define PCI_VENDOR_ID_TUNDRA		0x10e3
#define PCI_DEVICE_ID_TUNDRA_CA91C042	0x0000

#define PCI_VENDOR_ID_AMCC		0x10e8
#define PCI_DEVICE_ID_AMCC_MYRINET	0x8043
#define PCI_DEVICE_ID_AMCC_PARASTATION	0x8062
#define PCI_DEVICE_ID_AMCC_S5933	0x807d
#define PCI_DEVICE_ID_AMCC_S5933_HEPC3	0x809c

#define PCI_VENDOR_ID_INTERG		0x10ea
#define PCI_DEVICE_ID_INTERG_1680	0x1680
#define PCI_DEVICE_ID_INTERG_1682	0x1682

#define PCI_VENDOR_ID_REALTEK		0x10ec
#define PCI_DEVICE_ID_REALTEK_8029	0x8029
#define PCI_DEVICE_ID_REALTEK_8129	0x8129
#define PCI_DEVICE_ID_REALTEK_8139	0x8139

#define PCI_VENDOR_ID_TRUEVISION	0x10fa
#define PCI_DEVICE_ID_TRUEVISION_T1000	0x000c

#define PCI_VENDOR_ID_INIT		0x1101
#define PCI_DEVICE_ID_INIT_320P		0x9100
#define PCI_DEVICE_ID_INIT_360P		0x9500

#define PCI_VENDOR_ID_TTI		0x1103
#define PCI_DEVICE_ID_TTI_HPT343	0x0003

#define PCI_VENDOR_ID_VIA		0x1106
#define PCI_DEVICE_ID_VIA_82C505	0x0505
#define PCI_DEVICE_ID_VIA_82C561	0x0561
#define PCI_DEVICE_ID_VIA_82C586_1	0x0571
#define PCI_DEVICE_ID_VIA_82C576	0x0576
#define PCI_DEVICE_ID_VIA_82C585	0x0585
#define PCI_DEVICE_ID_VIA_82C586_0	0x0586
#define PCI_DEVICE_ID_VIA_82C595	0x0595
#define PCI_DEVICE_ID_VIA_82C596_0	0x0596
#define PCI_DEVICE_ID_VIA_82C597_0	0x0597
#define PCI_DEVICE_ID_VIA_82C598_0      0x0598
#define PCI_DEVICE_ID_VIA_82C926	0x0926
#define PCI_DEVICE_ID_VIA_82C416	0x1571
#define PCI_DEVICE_ID_VIA_82C595_97	0x1595
#define PCI_DEVICE_ID_VIA_82C586_2	0x3038
#define PCI_DEVICE_ID_VIA_82C586_3	0x3040
#define PCI_DEVICE_ID_VIA_82C686_5	0x3058
#define PCI_DEVICE_ID_VIA_86C100A	0x6100
#define PCI_DEVICE_ID_VIA_82C597_1	0x8597
#define PCI_DEVICE_ID_VIA_82C598_1      0x8598

#define PCI_VENDOR_ID_SMC2             0x1113
#define PCI_DEVICE_ID_SMC2_1211TX      0x1211

#define PCI_VENDOR_ID_VORTEX		0x1119
#define PCI_DEVICE_ID_VORTEX_GDT60x0	0x0000
#define PCI_DEVICE_ID_VORTEX_GDT6000B	0x0001
#define PCI_DEVICE_ID_VORTEX_GDT6x10	0x0002
#define PCI_DEVICE_ID_VORTEX_GDT6x20	0x0003
#define PCI_DEVICE_ID_VORTEX_GDT6530	0x0004
#define PCI_DEVICE_ID_VORTEX_GDT6550	0x0005
#define PCI_DEVICE_ID_VORTEX_GDT6x17	0x0006
#define PCI_DEVICE_ID_VORTEX_GDT6x27	0x0007
#define PCI_DEVICE_ID_VORTEX_GDT6537	0x0008
#define PCI_DEVICE_ID_VORTEX_GDT6557	0x0009
#define PCI_DEVICE_ID_VORTEX_GDT6x15	0x000a
#define PCI_DEVICE_ID_VORTEX_GDT6x25	0x000b
#define PCI_DEVICE_ID_VORTEX_GDT6535	0x000c
#define PCI_DEVICE_ID_VORTEX_GDT6555	0x000d
#define PCI_DEVICE_ID_VORTEX_GDT6x17RP	0x0100
#define PCI_DEVICE_ID_VORTEX_GDT6x27RP	0x0101
#define PCI_DEVICE_ID_VORTEX_GDT6537RP	0x0102
#define PCI_DEVICE_ID_VORTEX_GDT6557RP	0x0103
#define PCI_DEVICE_ID_VORTEX_GDT6x11RP	0x0104
#define PCI_DEVICE_ID_VORTEX_GDT6x21RP	0x0105
#define PCI_DEVICE_ID_VORTEX_GDT6x17RP1	0x0110
#define PCI_DEVICE_ID_VORTEX_GDT6x27RP1	0x0111
#define PCI_DEVICE_ID_VORTEX_GDT6537RP1	0x0112
#define PCI_DEVICE_ID_VORTEX_GDT6557RP1	0x0113
#define PCI_DEVICE_ID_VORTEX_GDT6x11RP1	0x0114
#define PCI_DEVICE_ID_VORTEX_GDT6x21RP1	0x0115
#define PCI_DEVICE_ID_VORTEX_GDT6x17RP2	0x0120
#define PCI_DEVICE_ID_VORTEX_GDT6x27RP2	0x0121
#define PCI_DEVICE_ID_VORTEX_GDT6537RP2	0x0122
#define PCI_DEVICE_ID_VORTEX_GDT6557RP2	0x0123
#define PCI_DEVICE_ID_VORTEX_GDT6x11RP2	0x0124
#define PCI_DEVICE_ID_VORTEX_GDT6x21RP2	0x0125

#define PCI_VENDOR_ID_EF		0x111a
#define PCI_DEVICE_ID_EF_ATM_FPGA	0x0000
#define PCI_DEVICE_ID_EF_ATM_ASIC	0x0002

#define PCI_VENDOR_ID_FORE		0x1127
#define PCI_DEVICE_ID_FORE_PCA200PC	0x0210
#define PCI_DEVICE_ID_FORE_PCA200E	0x0300

#define PCI_VENDOR_ID_IMAGINGTECH	0x112f
#define PCI_DEVICE_ID_IMAGINGTECH_ICPCI	0x0000

#define PCI_VENDOR_ID_PHILIPS		0x1131
#define PCI_DEVICE_ID_PHILIPS_SAA7145	0x7145
#define PCI_DEVICE_ID_PHILIPS_SAA7146	0x7146

#define PCI_VENDOR_ID_CYCLONE		0x113c
#define PCI_DEVICE_ID_CYCLONE_SDK	0x0001

#define PCI_VENDOR_ID_ALLIANCE		0x1142
#define PCI_DEVICE_ID_ALLIANCE_PROMOTIO	0x3210
#define PCI_DEVICE_ID_ALLIANCE_PROVIDEO	0x6422
#define PCI_DEVICE_ID_ALLIANCE_AT24	0x6424
#define PCI_DEVICE_ID_ALLIANCE_AT3D	0x643d

#define PCI_VENDOR_ID_SYSKONNECT	0x1148
#define PCI_DEVICE_ID_SYSKONNECT_FP	0x4000
#define PCI_DEVICE_ID_SYSKONNECT_TR	0x4200
#define PCI_DEVICE_ID_SYSKONNECT_GE	0x4300

#define PCI_VENDOR_ID_VMIC		0x114a
#define PCI_DEVICE_ID_VMIC_VME		0x7587

#define PCI_VENDOR_ID_DIGI		0x114f
#define PCI_DEVICE_ID_DIGI_EPC		0x0002
#define PCI_DEVICE_ID_DIGI_RIGHTSWITCH	0x0003
#define PCI_DEVICE_ID_DIGI_XEM		0x0004
#define PCI_DEVICE_ID_DIGI_XR		0x0005
#define PCI_DEVICE_ID_DIGI_CX		0x0006
#define PCI_DEVICE_ID_DIGI_XRJ		0x0009
#define PCI_DEVICE_ID_DIGI_EPCJ		0x000a
#define PCI_DEVICE_ID_DIGI_XR_920	0x0027

#define PCI_VENDOR_ID_MUTECH		0x1159
#define PCI_DEVICE_ID_MUTECH_MV1000	0x0001

#define PCI_VENDOR_ID_RENDITION		0x1163
#define PCI_DEVICE_ID_RENDITION_VERITE	0x0001
#define PCI_DEVICE_ID_RENDITION_VERITE2100 0x2000

#define PCI_VENDOR_ID_SERVERWORKS	0x1166
#define PCI_DEVICE_ID_SERVERWORKS_HE	0x0008
#define PCI_DEVICE_ID_SERVERWORKS_LE	0x0009
#define PCI_DEVICE_ID_SERVERWORKS_CIOB30   0x0010
#define PCI_DEVICE_ID_SERVERWORKS_CMIC_HE  0x0011
#define PCI_DEVICE_ID_SERVERWORKS_CSB5	    0x0201

#define PCI_VENDOR_ID_SBE		0x1176
#define PCI_DEVICE_ID_SBE_WANXL100	0x0301
#define PCI_DEVICE_ID_SBE_WANXL200	0x0302
#define PCI_DEVICE_ID_SBE_WANXL400	0x0104

#define PCI_VENDOR_ID_TOSHIBA		0x1179
#define PCI_DEVICE_ID_TOSHIBA_601	0x0601
#define PCI_DEVICE_ID_TOSHIBA_TOPIC95	0x060a
#define PCI_DEVICE_ID_TOSHIBA_TOPIC97	0x060f

#define PCI_VENDOR_ID_RICOH		0x1180
#define PCI_DEVICE_ID_RICOH_RL5C465	0x0465
#define PCI_DEVICE_ID_RICOH_RL5C466	0x0466
#define PCI_DEVICE_ID_RICOH_RL5C475	0x0475
#define PCI_DEVICE_ID_RICOH_RL5C478	0x0478

#define PCI_VENDOR_ID_ARTOP		0x1191
#define PCI_DEVICE_ID_ARTOP_ATP8400	0x0004
#define PCI_DEVICE_ID_ARTOP_ATP850UF	0x0005

#define PCI_VENDOR_ID_ZEITNET		0x1193
#define PCI_DEVICE_ID_ZEITNET_1221	0x0001
#define PCI_DEVICE_ID_ZEITNET_1225	0x0002

#define PCI_VENDOR_ID_OMEGA		0x119b
#define PCI_DEVICE_ID_OMEGA_82C092G	0x1221

#define PCI_VENDOR_ID_GALILEO		0x11ab
#define PCI_DEVICE_ID_GALILEO_GT64011	0x4146

#define PCI_VENDOR_ID_LITEON		0x11ad
#define PCI_DEVICE_ID_LITEON_LNE100TX	0x0002

#define PCI_VENDOR_ID_NP		0x11bc
#define PCI_DEVICE_ID_NP_PCI_FDDI	0x0001

#define PCI_VENDOR_ID_ATT		0x11c1
#define PCI_DEVICE_ID_ATT_L56XMF	0x0440
#define PCI_DEVICE_ID_ATT_L56DVP	0x0480

#define PCI_VENDOR_ID_SPECIALIX		0x11cb
#define PCI_DEVICE_ID_SPECIALIX_IO8	0x2000
#define PCI_DEVICE_ID_SPECIALIX_XIO	0x4000
#define PCI_DEVICE_ID_SPECIALIX_RIO	0x8000

#define PCI_VENDOR_ID_AURAVISION	0x11d1
#define PCI_DEVICE_ID_AURAVISION_VXP524	0x01f7

#define PCI_VENDOR_ID_IKON		0x11d5
#define PCI_DEVICE_ID_IKON_10115	0x0115
#define PCI_DEVICE_ID_IKON_10117	0x0117

#define PCI_VENDOR_ID_ZORAN		0x11de
#define PCI_DEVICE_ID_ZORAN_36057	0x6057
#define PCI_DEVICE_ID_ZORAN_36120	0x6120

#define PCI_VENDOR_ID_KINETIC		0x11f4
#define PCI_DEVICE_ID_KINETIC_2915	0x2915

#define PCI_VENDOR_ID_COMPEX		0x11f6
#define PCI_DEVICE_ID_COMPEX_ENET100VG4	0x0112
#define PCI_DEVICE_ID_COMPEX_RL2000	0x1401

#define PCI_VENDOR_ID_RP               0x11fe
#define PCI_DEVICE_ID_RP32INTF         0x0001
#define PCI_DEVICE_ID_RP8INTF          0x0002
#define PCI_DEVICE_ID_RP16INTF         0x0003
#define PCI_DEVICE_ID_RP4QUAD	       0x0004
#define PCI_DEVICE_ID_RP8OCTA          0x0005
#define PCI_DEVICE_ID_RP8J	       0x0006
#define PCI_DEVICE_ID_RPP4	       0x000A
#define PCI_DEVICE_ID_RPP8	       0x000B
#define PCI_DEVICE_ID_RP8M	       0x000C

#define PCI_VENDOR_ID_CYCLADES		0x120e
#define PCI_DEVICE_ID_CYCLOM_Y_Lo	0x0100
#define PCI_DEVICE_ID_CYCLOM_Y_Hi	0x0101
#define PCI_DEVICE_ID_CYCLOM_4Y_Lo	0x0102
#define PCI_DEVICE_ID_CYCLOM_4Y_Hi	0x0103
#define PCI_DEVICE_ID_CYCLOM_8Y_Lo	0x0104
#define PCI_DEVICE_ID_CYCLOM_8Y_Hi	0x0105
#define PCI_DEVICE_ID_CYCLOM_Z_Lo	0x0200
#define PCI_DEVICE_ID_CYCLOM_Z_Hi	0x0201
#define PCI_DEVICE_ID_PC300_RX_2	0x0300
#define PCI_DEVICE_ID_PC300_RX_1	0x0301
#define PCI_DEVICE_ID_PC300_TE_2	0x0310
#define PCI_DEVICE_ID_PC300_TE_1	0x0311

#define PCI_VENDOR_ID_ESSENTIAL		0x120f
#define PCI_DEVICE_ID_ESSENTIAL_ROADRUNNER	0x0001

#define PCI_VENDOR_ID_O2		0x1217
#define PCI_DEVICE_ID_O2_6729		0x6729
#define PCI_DEVICE_ID_O2_6730		0x673a
#define PCI_DEVICE_ID_O2_6832		0x6832
#define PCI_DEVICE_ID_O2_6836		0x6836

#define PCI_VENDOR_ID_3DFX		0x121a
#define PCI_DEVICE_ID_3DFX_VOODOO	0x0001
#define PCI_DEVICE_ID_3DFX_VOODOO2	0x0002
#define PCI_DEVICE_ID_3DFX_BANSHEE      0x0003

#define PCI_VENDOR_ID_SIGMADES		0x1236
#define PCI_DEVICE_ID_SIGMADES_6425	0x6401

#define PCI_VENDOR_ID_CCUBE		0x123f

#define PCI_VENDOR_ID_AVM		0x1244
#define PCI_DEVICE_ID_AVM_A1		0x0a00

#define PCI_VENDOR_ID_DIPIX		0x1246

#define PCI_VENDOR_ID_STALLION		0x124d
#define PCI_DEVICE_ID_STALLION_ECHPCI832 0x0000
#define PCI_DEVICE_ID_STALLION_ECHPCI864 0x0002
#define PCI_DEVICE_ID_STALLION_EIOPCI	0x0003

#define PCI_VENDOR_ID_OPTIBASE		0x1255
#define PCI_DEVICE_ID_OPTIBASE_FORGE	0x1110
#define PCI_DEVICE_ID_OPTIBASE_FUSION	0x1210
#define PCI_DEVICE_ID_OPTIBASE_VPLEX	0x2110
#define PCI_DEVICE_ID_OPTIBASE_VPLEXCC	0x2120
#define PCI_DEVICE_ID_OPTIBASE_VQUEST	0x2130

#define PCI_VENDOR_ID_SATSAGEM		0x1267
#define PCI_DEVICE_ID_SATSAGEM_PCR2101	0x5352
#define PCI_DEVICE_ID_SATSAGEM_TELSATTURBO 0x5a4b

#define PCI_VENDOR_ID_HUGHES		0x1273
#define PCI_DEVICE_ID_HUGHES_DIRECPC	0x0002

#define PCI_VENDOR_ID_ENSONIQ		0x1274
#define PCI_DEVICE_ID_ENSONIQ_AUDIOPCI	0x5000
#define PCI_DEVICE_ID_ENSONIQ_ES1371    0x1371

#define PCI_VENDOR_ID_ALTEON		0x12ae
#define PCI_DEVICE_ID_ALTEON_ACENIC	0x0001

#define PCI_VENDOR_ID_PICTUREL		0x12c5
#define PCI_DEVICE_ID_PICTUREL_PCIVST	0x0081

#define PCI_VENDOR_ID_NVIDIA_SGS	0x12d2
#define PCI_DEVICE_ID_NVIDIA_SGS_RIVA128 0x0018

#define PCI_VENDOR_ID_CBOARDS		0x1307
#define PCI_DEVICE_ID_CBOARDS_DAS1602_16 0x0001

#define PCI_VENDOR_ID_SIIG		0x131f
#define PCI_DEVICE_ID_SIIG_1S1P_10x_550	0x1010
#define PCI_DEVICE_ID_SIIG_1S1P_10x_650	0x1011
#define PCI_DEVICE_ID_SIIG_1S1P_10x_850	0x1012
#define PCI_DEVICE_ID_SIIG_1P_10x	0x1020
#define PCI_DEVICE_ID_SIIG_2P_10x	0x1021
#define PCI_DEVICE_ID_SIIG_2S1P_10x_550	0x1034
#define PCI_DEVICE_ID_SIIG_2S1P_10x_650	0x1035
#define PCI_DEVICE_ID_SIIG_2S1P_10x_850	0x1036
#define PCI_DEVICE_ID_SIIG_1P_20x	0x2020
#define PCI_DEVICE_ID_SIIG_2P_20x	0x2021
#define PCI_DEVICE_ID_SIIG_2P1S_20x_550	0x2040
#define PCI_DEVICE_ID_SIIG_2P1S_20x_650	0x2041
#define PCI_DEVICE_ID_SIIG_2P1S_20x_850	0x2042
#define PCI_DEVICE_ID_SIIG_1S1P_20x_550	0x2010
#define PCI_DEVICE_ID_SIIG_1S1P_20x_650	0x2011
#define PCI_DEVICE_ID_SIIG_1S1P_20x_850	0x2012
#define PCI_DEVICE_ID_SIIG_2S1P_20x_550	0x2060
#define PCI_DEVICE_ID_SIIG_2S1P_20x_650	0x2061
#define PCI_DEVICE_ID_SIIG_2S1P_20x_850	0x2062

#define PCI_VENDOR_ID_NETGEAR		0x1385
#define PCI_DEVICE_ID_NETGEAR_GA620	0x620a

#define PCI_VENDOR_ID_LAVA		0x1407
#define PCI_DEVICE_ID_LAVA_PARALLEL	0x8000
#define PCI_DEVICE_ID_LAVA_DUAL_PAR_A	0x8002 /* The Lava Dual Parallel is */
#define PCI_DEVICE_ID_LAVA_DUAL_PAR_B	0x8003 /* two PCI devices on a card */

#define PCI_VENDOR_ID_TIMEDIA		0x1409
#define PCI_DEVICE_ID_TIMEDIA_1889	0x7168
#define PCI_DEVICE_ID_TIMEDIA_4008A	0x7268

#define PCI_VENDOR_ID_AFAVLAB		0x14db
#define PCI_DEVICE_ID_AFAVLAB_TK9902	0x2120

#define PCI_VENDOR_ID_SYMPHONY		0x1c1c
#define PCI_DEVICE_ID_SYMPHONY_101	0x0001

#define PCI_VENDOR_ID_TEKRAM		0x1de1
#define PCI_DEVICE_ID_TEKRAM_DC290	0xdc29

#define PCI_VENDOR_ID_3DLABS		0x3d3d
#define PCI_DEVICE_ID_3DLABS_300SX	0x0001
#define PCI_DEVICE_ID_3DLABS_500TX	0x0002
#define PCI_DEVICE_ID_3DLABS_DELTA	0x0003
#define PCI_DEVICE_ID_3DLABS_PERMEDIA	0x0004
#define PCI_DEVICE_ID_3DLABS_MX		0x0006
#define PCI_DEVICE_ID_3DLABS_PERMEDIA2	0x0007
#define PCI_DEVICE_ID_3DLABS_GAMMA	0x0008
#define PCI_DEVICE_ID_3DLABS_PERMEDIA2V	0x0009

#define PCI_VENDOR_ID_AVANCE		0x4005
#define PCI_DEVICE_ID_AVANCE_ALG2064	0x2064
#define PCI_DEVICE_ID_AVANCE_2302	0x2302

#define PCI_VENDOR_ID_NETVIN		0x4a14
#define PCI_DEVICE_ID_NETVIN_NV5000SC	0x5000

#define PCI_VENDOR_ID_S3		0x5333
#define PCI_DEVICE_ID_S3_PLATO_PXS	0x0551
#define PCI_DEVICE_ID_S3_ViRGE		0x5631
#define PCI_DEVICE_ID_S3_TRIO		0x8811
#define PCI_DEVICE_ID_S3_AURORA64VP	0x8812
#define PCI_DEVICE_ID_S3_TRIO64UVP	0x8814
#define PCI_DEVICE_ID_S3_ViRGE_VX	0x883d
#define PCI_DEVICE_ID_S3_868		0x8880
#define PCI_DEVICE_ID_S3_928		0x88b0
#define PCI_DEVICE_ID_S3_864_1		0x88c0
#define PCI_DEVICE_ID_S3_864_2		0x88c1
#define PCI_DEVICE_ID_S3_964_1		0x88d0
#define PCI_DEVICE_ID_S3_964_2		0x88d1
#define PCI_DEVICE_ID_S3_968		0x88f0
#define PCI_DEVICE_ID_S3_TRIO64V2	0x8901
#define PCI_DEVICE_ID_S3_PLATO_PXG	0x8902
#define PCI_DEVICE_ID_S3_ViRGE_DXGX	0x8a01
#define PCI_DEVICE_ID_S3_ViRGE_GX2	0x8a10
#define PCI_DEVICE_ID_S3_ViRGE_MX	0x8c01
#define PCI_DEVICE_ID_S3_ViRGE_MXP	0x8c02
#define PCI_DEVICE_ID_S3_ViRGE_MXPMV	0x8c03
#define PCI_DEVICE_ID_S3_SONICVIBES	0xca00

#define PCI_VENDOR_ID_DCI       0x6666
#define PCI_DEVICE_ID_DCI_PCCOM4    0x0001

#define PCI_VENDOR_ID_GENROCO		0x5555
#define PCI_DEVICE_ID_GENROCO_HFP832	0x0003

#define PCI_VENDOR_ID_INTEL		0x8086
#define PCI_DEVICE_ID_INTEL_21145	0x0039
#define PCI_DEVICE_ID_INTEL_82375	0x0482
#define PCI_DEVICE_ID_INTEL_82424	0x0483
#define PCI_DEVICE_ID_INTEL_82378	0x0484
#define PCI_DEVICE_ID_INTEL_82430	0x0486
#define PCI_DEVICE_ID_INTEL_82434	0x04a3
#define PCI_DEVICE_ID_INTEL_I960	0x0960
#define PCI_DEVICE_ID_INTEL_I960RN	0x0964
#define PCI_DEVICE_ID_INTEL_82559ER	0x1209
#define PCI_DEVICE_ID_INTEL_82092AA_0	0x1221
#define PCI_DEVICE_ID_INTEL_82092AA_1	0x1222
#define PCI_DEVICE_ID_INTEL_7116	0x1223
#define PCI_DEVICE_ID_INTEL_82596	0x1226
#define PCI_DEVICE_ID_INTEL_82865	0x1227
#define PCI_DEVICE_ID_INTEL_82557	0x1229
#define PCI_DEVICE_ID_INTEL_82437	0x122d
#define PCI_DEVICE_ID_INTEL_82371FB_0	0x122e
#define PCI_DEVICE_ID_INTEL_82371FB_1	0x1230
#define PCI_DEVICE_ID_INTEL_82371MX	0x1234
#define PCI_DEVICE_ID_INTEL_82437MX	0x1235
#define PCI_DEVICE_ID_INTEL_82441	0x1237
#define PCI_DEVICE_ID_INTEL_82380FB	0x124b
#define PCI_DEVICE_ID_INTEL_82439	0x1250
#define PCI_DEVICE_ID_INTEL_MEGARAID	0x1960
#define PCI_DEVICE_ID_INTEL_82371SB_0	0x7000
#define PCI_DEVICE_ID_INTEL_82371SB_1	0x7010
#define PCI_DEVICE_ID_INTEL_82371SB_2	0x7020
#define PCI_DEVICE_ID_INTEL_82437VX	0x7030
#define PCI_DEVICE_ID_INTEL_82439TX	0x7100
#define PCI_DEVICE_ID_INTEL_82371AB_0	0x7110
#define PCI_DEVICE_ID_INTEL_82371AB	0x7111
#define PCI_DEVICE_ID_INTEL_82371AB_2	0x7112
#define PCI_DEVICE_ID_INTEL_82371AB_3	0x7113
#define PCI_DEVICE_ID_INTEL_82443LX_0	0x7180
#define PCI_DEVICE_ID_INTEL_82443LX_1	0x7181
#define PCI_DEVICE_ID_INTEL_82443BX_0	0x7190
#define PCI_DEVICE_ID_INTEL_82443BX_1	0x7191
#define PCI_DEVICE_ID_INTEL_82443BX_2	0x7192
#define PCI_DEVICE_ID_INTEL_P6		0x84c4
#define PCI_DEVICE_ID_INTEL_82450GX	0x84c4
#define PCI_DEVICE_ID_INTEL_82453GX	0x84c5
#define PCI_DEVICE_ID_INTEL_82451NX	0x84ca
#define PCI_DEVICE_ID_INTEL_82454NX	0x84cb

#define PCI_VENDOR_ID_COMPUTONE		0x8e0e
#define PCI_DEVICE_ID_COMPUTONE_IP2EX	0x0291

#define PCI_VENDOR_ID_KTI		0x8e2e
#define PCI_DEVICE_ID_KTI_ET32P2	0x3000

#define PCI_VENDOR_ID_ADAPTEC		0x9004
#define PCI_DEVICE_ID_ADAPTEC_7810	0x1078
#define PCI_DEVICE_ID_ADAPTEC_7821	0x2178
#define PCI_DEVICE_ID_ADAPTEC_38602	0x3860
#define PCI_DEVICE_ID_ADAPTEC_7850	0x5078
#define PCI_DEVICE_ID_ADAPTEC_7855	0x5578
#define PCI_DEVICE_ID_ADAPTEC_5800	0x5800
#define PCI_DEVICE_ID_ADAPTEC_3860	0x6038
#define PCI_DEVICE_ID_ADAPTEC_1480A	0x6075
#define PCI_DEVICE_ID_ADAPTEC_7860	0x6078
#define PCI_DEVICE_ID_ADAPTEC_7861	0x6178
#define PCI_DEVICE_ID_ADAPTEC_7870	0x7078
#define PCI_DEVICE_ID_ADAPTEC_7871	0x7178
#define PCI_DEVICE_ID_ADAPTEC_7872	0x7278
#define PCI_DEVICE_ID_ADAPTEC_7873	0x7378
#define PCI_DEVICE_ID_ADAPTEC_7874	0x7478
#define PCI_DEVICE_ID_ADAPTEC_7895	0x7895
#define PCI_DEVICE_ID_ADAPTEC_7880	0x8078
#define PCI_DEVICE_ID_ADAPTEC_7881	0x8178
#define PCI_DEVICE_ID_ADAPTEC_7882	0x8278
#define PCI_DEVICE_ID_ADAPTEC_7883	0x8378
#define PCI_DEVICE_ID_ADAPTEC_7884	0x8478
#define PCI_DEVICE_ID_ADAPTEC_7885	0x8578
#define PCI_DEVICE_ID_ADAPTEC_7886	0x8678
#define PCI_DEVICE_ID_ADAPTEC_7887	0x8778
#define PCI_DEVICE_ID_ADAPTEC_7888	0x8878
#define PCI_DEVICE_ID_ADAPTEC_1030	0x8b78

#define PCI_VENDOR_ID_ADAPTEC2		0x9005
#define PCI_DEVICE_ID_ADAPTEC2_2940U2	0x0010
#define PCI_DEVICE_ID_ADAPTEC2_2930U2	0x0011
#define PCI_DEVICE_ID_ADAPTEC2_7890B	0x0013
#define PCI_DEVICE_ID_ADAPTEC2_7890	0x001f
#define PCI_DEVICE_ID_ADAPTEC2_3940U2	0x0050
#define PCI_DEVICE_ID_ADAPTEC2_3950U2D	0x0051
#define PCI_DEVICE_ID_ADAPTEC2_7896	0x005f
#define PCI_DEVICE_ID_ADAPTEC2_7892A	0x0080
#define PCI_DEVICE_ID_ADAPTEC2_7892B	0x0081
#define PCI_DEVICE_ID_ADAPTEC2_7892D	0x0083
#define PCI_DEVICE_ID_ADAPTEC2_7892P	0x008f
#define PCI_DEVICE_ID_ADAPTEC2_7899A	0x00c0
#define PCI_DEVICE_ID_ADAPTEC2_7899B	0x00c1
#define PCI_DEVICE_ID_ADAPTEC2_7899D	0x00c3
#define PCI_DEVICE_ID_ADAPTEC2_7899P	0x00cf

#define PCI_VENDOR_ID_ATRONICS		0x907f
#define PCI_DEVICE_ID_ATRONICS_2015	0x2015

#define PCI_VENDOR_ID_HOLTEK		0x9412
#define PCI_DEVICE_ID_HOLTEK_6565	0x6565

#define PCI_VENDOR_ID_TIGERJET		0xe159
#define PCI_DEVICE_ID_TIGERJET_300	0x0001

#define PCI_VENDOR_ID_ARK		0xedd8
#define PCI_DEVICE_ID_ARK_STING		0xa091
#define PCI_DEVICE_ID_ARK_STINGARK	0xa099
#define PCI_DEVICE_ID_ARK_2000MT	0xa0a1

#define PCI_VENDOR_ID_INTERPHASE		0x107e
#define PCI_DEVICE_ID_INTERPHASE_5526	0x0004
#define PCI_DEVICE_ID_INTERPHASE_55x6	0x0005

/*
 * The PCI interface treats multi-function devices as independent
 * devices.  The slot/function address of each device is encoded
 * in a single byte as follows:
 *
 *	7:3 = slot
 *	2:0 = function
 */
#define PCI_DEVFN(slot,func)	((((slot) & 0x1f) << 3) | ((func) & 0x07))
#define PCI_SLOT(devfn)		(((devfn) >> 3) & 0x1f)
#define PCI_FUNC(devfn)		((devfn) & 0x07)

#endif /* USE_2_2_17_PCI_H */

#define PCI_EXP_FLAGS_TYPE      0x00f0  /* Device/Port type */
#define  PCI_EXP_TYPE_ENDPOINT  0x0     /* Express Endpoint */
#define  PCI_EXP_TYPE_LEG_END   0x1     /* Legacy Endpoint */
#define  PCI_EXP_TYPE_ROOT_PORT 0x4     /* Root Port */
#define  PCI_EXP_TYPE_UPSTREAM  0x5     /* Upstream Port */
#define  PCI_EXP_TYPE_DOWNSTREAM 0x6    /* Downstream Port */
#define  PCI_EXP_TYPE_PCI_BRIDGE 0x7    /* PCIe to PCI/PCI-X Bridge */
#define  PCI_EXP_TYPE_PCIE_BRIDGE 0x8   /* PCI/PCI-X to PCIe Bridge */
#define  PCI_EXP_TYPE_RC_END    0x9     /* Root Complex Integrated Endpoint */
#define  PCI_EXP_TYPE_RC_EC     0xa     /* Root Complex Event Collector */

static void
fill_dev_name(ulong pci_dev, char *name)
{
	ulong kobj, value;

	memset(name, 0, sizeof(*name) * BUFSIZE);

	kobj = pci_dev + OFFSET(pci_dev_dev) + OFFSET(device_kobj);

	readmem(kobj + OFFSET(kobject_name),
		KVADDR, &value, sizeof(void *), "kobject name",
		FAULT_ON_ERROR);

	read_string(value, name, BUFSIZE-1);
}

static void
fill_bus_name(ulong pci_bus, char *name)
{
	ulong kobj, value;

	memset(name, 0, sizeof(*name) * BUFSIZE);

	kobj = pci_bus + OFFSET(pci_bus_dev) + OFFSET(device_kobj);

	readmem(kobj + OFFSET(kobject_name),
		KVADDR, &value, sizeof(void *), "kobject name",
		FAULT_ON_ERROR);

	read_string(value, name, BUFSIZE-1);
}

static void
fill_dev_id(ulong pci_dev, char *id)
{
	unsigned short device, vendor;

	memset(id, 0, sizeof(*id) * BUFSIZE);

	readmem(pci_dev + OFFSET(pci_dev_device),
		KVADDR, &device, sizeof(short), "pci dev device",
		FAULT_ON_ERROR);
	readmem(pci_dev + OFFSET(pci_dev_vendor), KVADDR,
		&vendor, sizeof(short), "pci dev vendor", FAULT_ON_ERROR);

	sprintf(id, "%x:%x", vendor, device);
}

static void
fill_dev_class(ulong pci_dev, char *c)
{
	unsigned int class;

	memset(c, 0, sizeof(*c) * BUFSIZE);
	readmem(pci_dev + OFFSET(pci_dev_class), KVADDR,
		&class, sizeof(int), "pci class", FAULT_ON_ERROR);

	class >>= 8;

	sprintf(c, "%04x", class);
}

static int
pci_pcie_type(ulong cap)
{
	return (cap & PCI_EXP_FLAGS_TYPE) >> 4;
}

static int
pci_is_bridge(unsigned char hdr_type)
{
	return hdr_type == PCI_HEADER_TYPE_BRIDGE ||
		hdr_type == PCI_HEADER_TYPE_CARDBUS;
}

static void
fill_pcie_type(ulong pcidev, char *t)
{
	int type, bufidx = 0;
	unsigned short pciecap;
	unsigned char hdr_type;

	memset(t, 0, sizeof(*t) * BUFSIZE);

	readmem(pcidev + OFFSET(pci_dev_hdr_type), KVADDR, &hdr_type,
		sizeof(char), "pci dev hdr_type", FAULT_ON_ERROR);

	if (!VALID_MEMBER(pci_dev_pcie_flags_reg))
		goto bridge_chk;

	readmem(pcidev + OFFSET(pci_dev_pcie_flags_reg), KVADDR, &pciecap,
		sizeof(unsigned short), "pci dev pcie_flags_reg", FAULT_ON_ERROR);

	type = pci_pcie_type(pciecap);

	if (type == PCI_EXP_TYPE_ENDPOINT)
		bufidx = sprintf(t, "ENDPOINT");
	else if (type == PCI_EXP_TYPE_LEG_END)
		bufidx = sprintf(t, "LEG_END");
	else if (type == PCI_EXP_TYPE_ROOT_PORT)
		bufidx = sprintf(t, "ROOT_PORT");
	else if (type == PCI_EXP_TYPE_UPSTREAM)
		bufidx = sprintf(t, "UPSTREAM");
	else if (type == PCI_EXP_TYPE_DOWNSTREAM)
		bufidx = sprintf(t, "DOWNSTREAM");
	else if (type == PCI_EXP_TYPE_PCI_BRIDGE)
		bufidx = sprintf(t, "PCI_BRIDGE");
	else if (type == PCI_EXP_TYPE_PCIE_BRIDGE)
		bufidx = sprintf(t, "PCIE_BRIDGE");
	else if (type == PCI_EXP_TYPE_RC_END)
		bufidx = sprintf(t, "RC_END");
	else if (type == PCI_EXP_TYPE_RC_EC)
		bufidx = sprintf(t, "RC_EC");

bridge_chk:
	if (pci_is_bridge(hdr_type))
		sprintf(t + bufidx, " [BRIDGE]");
}

static void
walk_devices(ulong pci_bus)
{
	struct list_data list_data, *ld;
	int devcnt, i;
	ulong *devlist, self;
	char name[BUFSIZE], class[BUFSIZE], id[BUFSIZE], type[BUFSIZE];
	char pcidev_hdr[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char buf5[BUFSIZE];

	ld = &list_data;

	BZERO(ld, sizeof(struct list_data));

	readmem(pci_bus + OFFSET(pci_bus_devices), KVADDR,
		&ld->start, sizeof(void *), "pci bus devices",
		FAULT_ON_ERROR);

	if (VALID_MEMBER(pci_dev_pcie_flags_reg))
		snprintf(pcidev_hdr, sizeof(pcidev_hdr), "%s %s %s %s %s\n",
			mkstring(buf1, VADDR_PRLEN, CENTER, "PCI DEV"),
			mkstring(buf2, strlen("0000:00:00.0"), CENTER, "DO:BU:SL.FN"),
			mkstring(buf3, strlen("0000") + 2, CENTER, "CLASS"),
			mkstring(buf4, strlen("0000:0000"), CENTER, "PCI_ID"),
			mkstring(buf5, 10, CENTER, "TYPE"));
	else
		snprintf(pcidev_hdr, sizeof(pcidev_hdr), "%s %s %s %s\n",
			mkstring(buf1, VADDR_PRLEN, CENTER, "PCI DEV"),
			mkstring(buf2, strlen("0000:00:00.0"), CENTER, "DO:BU:SL.FN"),
			mkstring(buf3, strlen("0000") + 2, CENTER, "CLASS"),
			mkstring(buf4, strlen("0000:0000"), CENTER, "PCI_ID"));

	fprintf(fp, "  %s", pcidev_hdr);

	readmem(pci_bus + OFFSET(pci_bus_self), KVADDR, &self,
		sizeof(void *), "pci bus self", FAULT_ON_ERROR);
	if (self) {
		fill_dev_name(self, name);
		fill_dev_class(self, class);
		fill_dev_id(self, id);
		fill_pcie_type(self, type);
		fprintf(fp, "  %s %s %s %s %s\n",
			mkstring(buf1, VADDR_PRLEN, LJUST|LONG_HEX,
			MKSTR(self)),
			mkstring(buf2, strlen("0000:00:00.0"), CENTER, name),
			mkstring(buf3, strlen("0000") + 2, CENTER, class),
			mkstring(buf4, strlen("0000:0000"), CENTER, id),
			mkstring(buf5, 10, CENTER, type));
	}

	if (ld->start == (pci_bus + OFFSET(pci_bus_devices)))
		return;

	ld->end = pci_bus + OFFSET(pci_bus_devices);
	hq_open();
	devcnt = do_list(ld);
	devlist = (ulong *)GETBUF(devcnt * sizeof(ulong));
	devcnt = retrieve_list(devlist, devcnt);
	hq_close();

	for (i = 0; i < devcnt; i++) {
		fill_dev_name(devlist[i], name);
		fill_dev_class(devlist[i], class);
		fill_dev_id(devlist[i], id);
		fill_pcie_type(devlist[i], type);
		fprintf(fp, "  %s %s %s %s %s\n",
			mkstring(buf1, VADDR_PRLEN, LJUST|LONG_HEX,
			MKSTR(devlist[i])),
			mkstring(buf2, strlen("0000:00:00.0"), CENTER, name),
			mkstring(buf3, strlen("0000") + 2, CENTER, class),
			mkstring(buf4, strlen("0000:0000"), CENTER, id),
			mkstring(buf5, 10, CENTER, type));
	}
	FREEBUF(devlist);
}

static void
walk_buses(ulong pci_bus)
{
	struct list_data list_data, *ld;
	int buscnt, i;
	ulong *buslist, parent;
	char pcibus_hdr[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];

	ld = &list_data;

	BZERO(ld, sizeof(struct list_data));

	readmem(pci_bus + OFFSET(pci_bus_children), KVADDR,
		&ld->start, sizeof(void *), "pci bus children",
		FAULT_ON_ERROR);

	if (ld->start == (pci_bus + OFFSET(pci_bus_children)))
		return;

	ld->end = pci_bus + OFFSET(pci_bus_children);
	hq_open();
	buscnt = do_list(ld);
	buslist = (ulong *)GETBUF(buscnt * sizeof(ulong));
	buscnt = retrieve_list(buslist, buscnt);
	hq_close();

	snprintf(pcibus_hdr, sizeof(pcibus_hdr), "%s %s\n",
		mkstring(buf1, VADDR_PRLEN, CENTER, "PCI BUS"),
		mkstring(buf2, VADDR_PRLEN, CENTER, "PARENT BUS"));

	for (i = 0; i < buscnt; i++) {
		readmem(buslist[i] + OFFSET(pci_bus_parent), KVADDR, &parent,
			sizeof(void *), "pci bus parent", FAULT_ON_ERROR);

		fprintf(fp, "  %s", pcibus_hdr);

		fprintf(fp, "  %s %s\n",
			mkstring(buf1, VADDR_PRLEN, LJUST|LONG_HEX,
			MKSTR(buslist[i])),
			mkstring(buf2, VADDR_PRLEN, LJUST|LONG_HEX,
			MKSTR(parent)));
		walk_devices(buslist[i]);
		fprintf(fp, "\n");
		walk_buses(buslist[i]);
	}
	FREEBUF(buslist);
}

static void
do_pci2(void)
{
	struct list_data list_data, *ld;
	int rootbuscnt, i;
	ulong *rootbuslist;
	unsigned long pci_root_bus_addr = symbol_value("pci_root_buses");
	char name[BUFSIZE];
	char pcirootbus_hdr[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];

	ld = &list_data;
	BZERO(ld, sizeof(struct list_data));

	get_symbol_data("pci_root_buses", sizeof(void *), &ld->start);

	if (ld->start == pci_root_bus_addr)
		error(FATAL, "no PCI devices found on this system.\n");

	ld->end = pci_root_bus_addr;

	hq_open();
	rootbuscnt = do_list(ld);
	rootbuslist = (ulong *)GETBUF(rootbuscnt * sizeof(ulong));
	rootbuscnt = retrieve_list(rootbuslist, rootbuscnt);
	hq_close();

	snprintf(pcirootbus_hdr, sizeof(pcirootbus_hdr), "%s %s\n",
			mkstring(buf1, VADDR_PRLEN, CENTER, "ROOT BUS"),
			mkstring(buf2, strlen("0000:00"), CENTER, "BUSNAME"));

	for (i = 0; i < rootbuscnt; i++) {
		fprintf(fp, "%s", pcirootbus_hdr);
		fill_bus_name(rootbuslist[i], name);
		fprintf(fp, "%s %s\n",
			mkstring(buf1, VADDR_PRLEN, LJUST|LONG_HEX,
			MKSTR(rootbuslist[i])),
			mkstring(buf2, strlen("0000:00"), CENTER, name));
		 walk_devices(rootbuslist[i]);
		 walk_buses(rootbuslist[i]);

		fprintf(fp, "\n");
	}
	FREEBUF(rootbuslist);
}

static void
do_pci(void)
{
	struct list_data  pcilist_data;
	int               devcnt, i;
	unsigned int      class;
	unsigned short    device, vendor;
	unsigned char     busno;
	ulong             *devlist, bus, devfn, prev, next;
	char 		  buf1[BUFSIZE];
	char 		  buf2[BUFSIZE];
	char 		  buf3[BUFSIZE];

	BZERO(&pcilist_data, sizeof(struct list_data));

	if (VALID_MEMBER(pci_dev_global_list)) {
                get_symbol_data("pci_devices", sizeof(void *), &pcilist_data.start);
                pcilist_data.end = symbol_value("pci_devices");
                pcilist_data.list_head_offset = OFFSET(pci_dev_global_list);
		readmem(symbol_value("pci_devices") + OFFSET(list_head_prev),
			KVADDR, &prev, sizeof(void *), "list head prev",
			FAULT_ON_ERROR);
                /*
		 * Check if this system does not have any PCI devices.
		 */
		if ((pcilist_data.start == pcilist_data.end) &&
 		   (prev == pcilist_data.end))
			error(FATAL, "no PCI devices found on this system.\n");

	} else if (VALID_MEMBER(pci_dev_next)) {
		get_symbol_data("pci_devices", sizeof(void *),
				&pcilist_data.start);
		pcilist_data.member_offset = OFFSET(pci_dev_next);
                /*
		 * Check if this system does not have any PCI devices.
		 */
		readmem(pcilist_data.start + pcilist_data.member_offset,
			KVADDR, &next, sizeof(void *), "pci dev next",
			FAULT_ON_ERROR);
		if (!next)
			error(FATAL, "no PCI devices found on this system.\n");
	} else
		option_not_supported('p');

	hq_open();
	devcnt = do_list(&pcilist_data);
	devlist = (ulong *)GETBUF(devcnt * sizeof(ulong));
	devcnt = retrieve_list(devlist, devcnt);
	hq_close();

	fprintf(fp, "%s BU:SL.FN CLASS: VENDOR-DEVICE\n",
		mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "PCI_DEV"));

	for (i = 0; i < devcnt; i++) {

		/*
		 * Get the pci bus number
		 */
		readmem(devlist[i] + OFFSET(pci_dev_bus), KVADDR, &bus, 
			sizeof(void *), "pci bus", FAULT_ON_ERROR);
		readmem(bus + OFFSET(pci_bus_number), KVADDR, &busno, 
			sizeof(char), "pci bus number", FAULT_ON_ERROR);
		readmem(devlist[i] + OFFSET(pci_dev_devfn), KVADDR,
			&devfn, sizeof(ulong), "pci devfn", FAULT_ON_ERROR);

		fprintf(fp, "%lx %02x:%02lx.%lx  ", devlist[i], 
			busno, PCI_SLOT(devfn), PCI_FUNC(devfn));

		/*
		 * Now read in the class, device, and vendor.
		 */
		readmem(devlist[i] + OFFSET(pci_dev_class), KVADDR,
			&class, sizeof(int), "pci class", FAULT_ON_ERROR);
		readmem(devlist[i] + OFFSET(pci_dev_device),
			KVADDR, &device, sizeof(short), "pci device", 
			FAULT_ON_ERROR);
		readmem(devlist[i] + OFFSET(pci_dev_vendor),KVADDR,
			&vendor, sizeof(short), "pci vendor", FAULT_ON_ERROR);

		fprintf(fp, "%s: %s %s", 
			pci_strclass(class, buf1),
			pci_strvendor(vendor, buf2), 
			pci_strdev(vendor, device, buf3));

		fprintf(fp, "\n");
	}

	FREEBUF(devlist);
}



/*
 * Taken from drivers/pci/oldproc.c, kernel ver 2.2.17
 */
struct pci_dev_info {
        unsigned short  vendor;         /* vendor id */
        unsigned short  device;         /* device id */

        const char      *name;          /* device name */
};


#define DEVICE(vid,did,name) \
  {PCI_VENDOR_ID_##vid, PCI_DEVICE_ID_##did, (name)}

/*
 * Sorted in ascending order by vendor and device.
 * Use binary search for lookup. If you add a device make sure
 * it is sequential by both vendor and device id.
 */
struct pci_dev_info dev_info[] = {
	DEVICE( COMPAQ,		COMPAQ_1280,	"QVision 1280/p"),
	DEVICE(	COMPAQ,		COMPAQ_6010,	"Hot Plug PCI Bridge"),
	DEVICE( COMPAQ,		COMPAQ_SMART2P,	"Smart-2/P RAID Controller"),
	DEVICE( COMPAQ,		COMPAQ_NETEL100,"Netelligent 10/100"),
	DEVICE( COMPAQ,		COMPAQ_NETEL10,	"Netelligent 10"),
	DEVICE( COMPAQ,		COMPAQ_NETFLEX3I,"NetFlex 3"),
	DEVICE( COMPAQ,		COMPAQ_NETEL100D,"Netelligent 10/100 Dual"),
	DEVICE( COMPAQ,		COMPAQ_NETEL100PI,"Netelligent 10/100 ProLiant"),
	DEVICE( COMPAQ,		COMPAQ_NETEL100I,"Netelligent 10/100 Integrated"),
	DEVICE( COMPAQ,		COMPAQ_THUNDER,	"ThunderLAN"),
	DEVICE( COMPAQ,		COMPAQ_NETFLEX3B,"NetFlex 3 BNC"),
	DEVICE( NCR,		NCR_53C810,	"53c810"),
	DEVICE( NCR,		NCR_53C820,	"53c820"),
	DEVICE( NCR,		NCR_53C825,	"53c825"),
	DEVICE( NCR,		NCR_53C815,	"53c815"),
	DEVICE( NCR,		NCR_53C860,	"53c860"),
	DEVICE( NCR,		NCR_53C896,	"53c896"),
	DEVICE( NCR,		NCR_53C895,	"53c895"),
	DEVICE( NCR,		NCR_53C885,	"53c885"),
	DEVICE( NCR,		NCR_53C875,	"53c875"),
	DEVICE( NCR,		NCR_53C875J,	"53c875J"),
	DEVICE( ATI,		ATI_68800,      "68800AX"),
	DEVICE( ATI,		ATI_215CT222,   "215CT222"),
	DEVICE( ATI,		ATI_210888CX,   "210888CX"),
	DEVICE( ATI,		ATI_215GB,	"Mach64 GB"),
	DEVICE( ATI,		ATI_215GD,	"Mach64 GD (Rage Pro)"),
	DEVICE( ATI,		ATI_215GI,	"Mach64 GI (Rage Pro)"),
	DEVICE( ATI,		ATI_215GP,	"Mach64 GP (Rage Pro)"),
	DEVICE( ATI,		ATI_215GQ,	"Mach64 GQ (Rage Pro)"),
	DEVICE( ATI,		ATI_215GT,	"Mach64 GT (Rage II)"),
	DEVICE( ATI,		ATI_215GTB,	"Mach64 GT (Rage II)"),
	DEVICE( ATI,		ATI_210888GX,   "210888GX"),
	DEVICE( ATI,		ATI_215LG,	"Mach64 LG (Rage Pro)"),
	DEVICE( ATI,		ATI_264LT,	"Mach64 LT"),
	DEVICE( ATI,		ATI_264VT,	"Mach64 VT"),
	DEVICE( VLSI,		VLSI_82C592,	"82C592-FC1"),
	DEVICE( VLSI,		VLSI_82C593,	"82C593-FC1"),
	DEVICE( VLSI,		VLSI_82C594,	"82C594-AFC2"),
	DEVICE( VLSI,		VLSI_82C597,	"82C597-AFC2"),
	DEVICE( VLSI,		VLSI_82C541,	"82C541 Lynx"),
	DEVICE( VLSI,		VLSI_82C543,	"82C543 Lynx ISA"),
	DEVICE( VLSI,		VLSI_82C532,	"82C532"),
	DEVICE( VLSI,		VLSI_82C534,	"82C534"),
	DEVICE( VLSI,		VLSI_82C535,	"82C535"),
	DEVICE( VLSI,		VLSI_82C147,	"82C147"),
	DEVICE( VLSI,		VLSI_VAS96011,	"VAS96011 (Golden Gate II)"),
	DEVICE( ADL,		ADL_2301,	"2301"),
	DEVICE( NS,		NS_87415,	"87415"),
	DEVICE( NS,		NS_87410,	"87410"),
	DEVICE( TSENG,		TSENG_W32P_2,	"ET4000W32P"),
	DEVICE( TSENG,		TSENG_W32P_b,	"ET4000W32P rev B"),
	DEVICE( TSENG,		TSENG_W32P_c,	"ET4000W32P rev C"),
	DEVICE( TSENG,		TSENG_W32P_d,	"ET4000W32P rev D"),
	DEVICE( TSENG,		TSENG_ET6000,	"ET6000"),
	DEVICE( WEITEK,		WEITEK_P9000,	"P9000"),
	DEVICE( WEITEK,		WEITEK_P9100,	"P9100"),
	DEVICE( DEC,		DEC_BRD,	"DC21050"),
	DEVICE( DEC,		DEC_TULIP,	"DC21040"),
	DEVICE( DEC,		DEC_TGA,	"TGA"),
	DEVICE( DEC,		DEC_TULIP_FAST,	"DC21140"),
	DEVICE( DEC,		DEC_TGA2,	"TGA2"),
	DEVICE( DEC,		DEC_FDDI,	"DEFPA"),
	DEVICE( DEC,		DEC_TULIP_PLUS,	"DC21041"),
	DEVICE( DEC,		DEC_21142,	"DC21142"),
	DEVICE( DEC,		DEC_21052,	"DC21052"),
	DEVICE( DEC,		DEC_21150,	"DC21150"),
	DEVICE( DEC,		DEC_21152,	"DC21152"),
	DEVICE( DEC,		DEC_21153,	"DC21153"),
	DEVICE( DEC,		DEC_21154,	"DC21154"),
	DEVICE( DEC,		DEC_21285,	"DC21285 Footbridge"),
	DEVICE( DEC,		DEC_21554,	"DC21554 DrawBridge"),
	DEVICE( CIRRUS,		CIRRUS_7548,	"GD 7548"),
	DEVICE( CIRRUS,		CIRRUS_5430,	"GD 5430"),
	DEVICE( CIRRUS,		CIRRUS_5434_4,	"GD 5434"),
	DEVICE( CIRRUS,		CIRRUS_5434_8,	"GD 5434"),
	DEVICE( CIRRUS,		CIRRUS_5436,	"GD 5436"),
	DEVICE( CIRRUS,		CIRRUS_5446,	"GD 5446"),
	DEVICE( CIRRUS,		CIRRUS_5480,	"GD 5480"),
	DEVICE( CIRRUS,		CIRRUS_5464,	"GD 5464"),
	DEVICE( CIRRUS,		CIRRUS_5465,	"GD 5465"),
	DEVICE( CIRRUS,		CIRRUS_6729,	"CL 6729"),
	DEVICE( CIRRUS,		CIRRUS_6832,	"PD 6832"),
	DEVICE( CIRRUS,		CIRRUS_7542,	"CL 7542"),
	DEVICE( CIRRUS,		CIRRUS_7543,	"CL 7543"),
	DEVICE( CIRRUS,		CIRRUS_7541,	"CL 7541"),
	DEVICE( IBM,		IBM_FIRE_CORAL,	"Fire Coral"),
	DEVICE( IBM,		IBM_TR,		"Token Ring"),
	DEVICE( IBM,		IBM_82G2675,	"82G2675"),
	DEVICE( IBM,		IBM_MCA,	"MicroChannel"),
	DEVICE( IBM,		IBM_82351,	"82351"),
	DEVICE( IBM,		IBM_PYTHON,	"Python"),
	DEVICE( IBM,		IBM_SERVERAID,	"ServeRAID"),
	DEVICE( IBM,		IBM_TR_WAKE,	"Wake On LAN Token Ring"),
	DEVICE( IBM,		IBM_MPIC,	"MPIC-2 Interrupt Controller"),
	DEVICE( IBM,		IBM_3780IDSP,	"MWave DSP"),
	DEVICE( IBM,		IBM_MPIC_2,	"MPIC-2 ASIC Interrupt Controller"),
	DEVICE( WD,		WD_7197,	"WD 7197"),
	DEVICE( AMD,		AMD_LANCE,	"79C970"),
	DEVICE( AMD,		AMD_SCSI,	"53C974"),
	DEVICE( TRIDENT,	TRIDENT_9397,	"Cyber9397"),
	DEVICE( TRIDENT,	TRIDENT_9420,	"TG 9420"),
	DEVICE( TRIDENT,	TRIDENT_9440,	"TG 9440"),
	DEVICE( TRIDENT,	TRIDENT_9660,	"TG 9660 / Cyber9385"),
	DEVICE( TRIDENT,	TRIDENT_9750,	"Image 975"),
	DEVICE( AI,		AI_M1435,	"M1435"),
	DEVICE( MATROX,		MATROX_MGA_2,	"Atlas PX2085"),
	DEVICE( MATROX,		MATROX_MIL,	"Millennium"),
	DEVICE( MATROX,		MATROX_MYS,	"Mystique"),
	DEVICE( MATROX,		MATROX_MIL_2,	"Millennium II"),
	DEVICE( MATROX,		MATROX_MIL_2_AGP,"Millennium II AGP"),
	DEVICE( MATROX,         MATROX_G200_PCI,"Matrox G200 PCI"),
	DEVICE( MATROX,         MATROX_G200_AGP,"Matrox G200 AGP"),
	DEVICE( MATROX,		MATROX_MGA_IMP,	"MGA Impression"),
	DEVICE( MATROX,         MATROX_G100_MM, "Matrox G100 multi monitor"),
	DEVICE( MATROX,         MATROX_G100_AGP,"Matrox G100 AGP"),
	DEVICE( CT,		CT_65545,	"65545"),
	DEVICE( CT,		CT_65548,	"65548"),
	DEVICE(	CT,		CT_65550,	"65550"),
	DEVICE( CT,		CT_65554,	"65554"),
	DEVICE( CT,		CT_65555,	"65555"),
	DEVICE( MIRO,		MIRO_36050,	"ZR36050"),
	DEVICE( NEC,		NEC_PCX2,	"PowerVR PCX2"),
	DEVICE( FD,		FD_36C70,	"TMC-18C30"),
	DEVICE( SI,		SI_5591_AGP,	"5591/5592 AGP"),
	DEVICE( SI,		SI_6202,	"6202"),
	DEVICE( SI,		SI_503,		"85C503"),
	DEVICE( SI,		SI_ACPI,	"ACPI"),
	DEVICE( SI,		SI_5597_VGA,	"5597/5598 VGA"),
	DEVICE( SI,		SI_6205,	"6205"),
	DEVICE( SI,		SI_501,		"85C501"),
	DEVICE( SI,		SI_496,		"85C496"),
	DEVICE( SI,		SI_601,		"85C601"),
	DEVICE( SI,		SI_5107,	"5107"),
	DEVICE( SI,		SI_5511,       	"85C5511"),
	DEVICE( SI,		SI_5513,	"85C5513"),
	DEVICE( SI,		SI_5571,	"5571"),
	DEVICE( SI,		SI_5591,	"5591/5592 Host"),
	DEVICE( SI,		SI_5597,	"5597/5598 Host"),
	DEVICE( SI,		SI_7001,	"7001 USB"),
	DEVICE( HP,		HP_J2585A,	"J2585A"),
	DEVICE( HP,		HP_J2585B,	"J2585B (Lassen)"),
	DEVICE( PCTECH,		PCTECH_RZ1000,  "RZ1000 (buggy)"),
	DEVICE( PCTECH,		PCTECH_RZ1001,  "RZ1001 (buggy?)"),
	DEVICE( PCTECH,		PCTECH_SAMURAI_0,"Samurai 0"),
	DEVICE( PCTECH,		PCTECH_SAMURAI_1,"Samurai 1"),
	DEVICE( PCTECH,		PCTECH_SAMURAI_IDE,"Samurai IDE"),
	DEVICE( DPT,		DPT,		"SmartCache/Raid"),
	DEVICE( OPTI,		OPTI_92C178,	"92C178"),
	DEVICE( OPTI,		OPTI_82C557,	"82C557 Viper-M"),
	DEVICE( OPTI,		OPTI_82C558,	"82C558 Viper-M ISA+IDE"),
	DEVICE( OPTI,		OPTI_82C621,	"82C621"),
	DEVICE( OPTI,		OPTI_82C700,	"82C700"),
	DEVICE( OPTI,		OPTI_82C701,	"82C701 FireStar Plus"),
	DEVICE( OPTI,		OPTI_82C814,	"82C814 Firebridge 1"),
	DEVICE( OPTI,		OPTI_82C822,	"82C822"),
	DEVICE( OPTI,		OPTI_82C825,	"82C825 Firebridge 2"),
	DEVICE( SGS,		SGS_2000,	"STG 2000X"),
	DEVICE( SGS,		SGS_1764,	"STG 1764X"),
	DEVICE( BUSLOGIC,	BUSLOGIC_MULTIMASTER_NC, "MultiMaster NC"),
	DEVICE( BUSLOGIC,	BUSLOGIC_MULTIMASTER,    "MultiMaster"),
	DEVICE( BUSLOGIC,	BUSLOGIC_FLASHPOINT,     "FlashPoint"),
	DEVICE( TI,		TI_TVP4010,	"TVP4010 Permedia"),
	DEVICE( TI,		TI_TVP4020,	"TVP4020 Permedia 2"),
	DEVICE( TI,		TI_PCI1130,	"PCI1130"),
	DEVICE( TI,		TI_PCI1131,	"PCI1131"),
	DEVICE( TI,		TI_PCI1250,	"PCI1250"),
	DEVICE( OAK,		OAK_OTI107,	"OTI107"),
	DEVICE( WINBOND2,	WINBOND2_89C940,"NE2000-PCI"),
	DEVICE( MOTOROLA,	MOTOROLA_MPC105,"MPC105 Eagle"),
	DEVICE( MOTOROLA,	MOTOROLA_MPC106,"MPC106 Grackle"),
	DEVICE( MOTOROLA,	MOTOROLA_RAVEN,	"Raven"),
	DEVICE( MOTOROLA,	MOTOROLA_FALCON,"Falcon"),
	DEVICE( MOTOROLA,	MOTOROLA_CPX8216,"CPX8216"),
	DEVICE( PROMISE,        PROMISE_20246,	"IDE UltraDMA/33"),
	DEVICE( PROMISE,	PROMISE_5300,	"DC5030"),
	DEVICE( N9,		N9_I128,	"Imagine 128"),
	DEVICE( N9,		N9_I128_2,	"Imagine 128v2"),
	DEVICE( N9,		N9_I128_T2R,	"Revolution 3D"),
	DEVICE( UMC,		UMC_UM8673F,	"UM8673F"),
	DEVICE( UMC,		UMC_UM8891A,	"UM8891A"),
	DEVICE( UMC,		UMC_UM8886BF,	"UM8886BF"),
	DEVICE( UMC,		UMC_UM8886A,	"UM8886A"),
	DEVICE( UMC,		UMC_UM8881F,	"UM8881F"),
	DEVICE( UMC,		UMC_UM8886F,	"UM8886F"),
	DEVICE( UMC,		UMC_UM9017F,	"UM9017F"),
	DEVICE( UMC,		UMC_UM8886N,	"UM8886N"),
	DEVICE( UMC,		UMC_UM8891N,	"UM8891N"),
	DEVICE( X,		X_AGX016,	"ITT AGX016"),
	DEVICE( PICOP,		PICOP_PT86C52X,	"PT86C52x Vesuvius"),
	DEVICE( PICOP,		PICOP_PT80C524,	"PT80C524 Nile"),
	DEVICE( MYLEX,		MYLEX_DAC960_P, "DAC960 P Series"),
	DEVICE( MYLEX,		MYLEX_DAC960_PD,"DAC960 PD Series"),
	DEVICE( MYLEX,		MYLEX_DAC960_PG,"DAC960 PG Series"),
	DEVICE( MYLEX,		MYLEX_DAC960_LP,"DAC960 LP Series"),
	DEVICE( MYLEX,		MYLEX_DAC960_BA,"DAC960 BA Series"),
	DEVICE( APPLE,		APPLE_BANDIT,	"Bandit"),
	DEVICE( APPLE,		APPLE_GC,	"Grand Central"),
	DEVICE( APPLE,		APPLE_HYDRA,	"Hydra"),
	DEVICE( NEXGEN,		NEXGEN_82C501,	"82C501"),
	DEVICE( QLOGIC,		QLOGIC_ISP1020,	"ISP1020"),
	DEVICE( QLOGIC,		QLOGIC_ISP1022,	"ISP1022"),
	DEVICE( CYRIX,		CYRIX_5510,	"5510"),
	DEVICE( CYRIX,		CYRIX_PCI_MASTER,"PCI Master"),
	DEVICE( CYRIX,		CYRIX_5520,	"5520"),
	DEVICE( CYRIX,		CYRIX_5530_LEGACY,"5530 Kahlua Legacy"),
	DEVICE( CYRIX,		CYRIX_5530_SMI,	"5530 Kahlua SMI"),
	DEVICE( CYRIX,		CYRIX_5530_IDE,	"5530 Kahlua IDE"),
	DEVICE( CYRIX,		CYRIX_5530_AUDIO,"5530 Kahlua Audio"),
	DEVICE( CYRIX,		CYRIX_5530_VIDEO,"5530 Kahlua Video"),
	DEVICE( LEADTEK,	LEADTEK_805,	"S3 805"),
	DEVICE( CONTAQ,		CONTAQ_82C599,	"82C599"),
	DEVICE( CONTAQ,		CONTAQ_82C693,	"82C693"),
	DEVICE( OLICOM,		OLICOM_OC3136,	"OC-3136/3137"),
	DEVICE( OLICOM,		OLICOM_OC2315,	"OC-2315"),
	DEVICE( OLICOM,		OLICOM_OC2325,	"OC-2325"),
	DEVICE( OLICOM,		OLICOM_OC2183,	"OC-2183/2185"),
	DEVICE( OLICOM,		OLICOM_OC2326,	"OC-2326"),
	DEVICE( OLICOM,		OLICOM_OC6151,	"OC-6151/6152"),
	DEVICE( SUN,		SUN_EBUS,	"PCI-EBus Bridge"),
	DEVICE( SUN,		SUN_HAPPYMEAL,	"Happy Meal Ethernet"),
	DEVICE( SUN,		SUN_SIMBA,	"Advanced PCI Bridge"),
	DEVICE( SUN,		SUN_PBM,	"PCI Bus Module"),
	DEVICE( SUN,		SUN_SABRE,	"Ultra IIi PCI"),
	DEVICE( CMD,		CMD_640,	"640 (buggy)"),
	DEVICE( CMD,		CMD_643,	"643"),
	DEVICE( CMD,		CMD_646,	"646"),
	DEVICE( CMD,		CMD_670,	"670"),
	DEVICE( VISION,		VISION_QD8500,	"QD-8500"),
	DEVICE( VISION,		VISION_QD8580,	"QD-8580"),
	DEVICE( BROOKTREE,	BROOKTREE_848,	"Bt848"),
	DEVICE( BROOKTREE,	BROOKTREE_849A,	"Bt849"),
	DEVICE( BROOKTREE,      BROOKTREE_878_1,"Bt878 2nd Contr. (?)"),
	DEVICE( BROOKTREE,      BROOKTREE_878,  "Bt878"),
	DEVICE( BROOKTREE,	BROOKTREE_8474,	"Bt8474"),
	DEVICE( SIERRA,		SIERRA_STB,	"STB Horizon 64"),
	DEVICE( ACC,		ACC_2056,	"2056"),
	DEVICE( WINBOND,	WINBOND_83769,	"W83769F"),
	DEVICE( WINBOND,	WINBOND_82C105,	"SL82C105"),
	DEVICE( WINBOND,	WINBOND_83C553,	"W83C553"),
	DEVICE( DATABOOK,      	DATABOOK_87144,	"DB87144"),
	DEVICE(	PLX,		PLX_9050,	"PCI9050 I2O"),
	DEVICE( PLX,		PLX_9080,	"PCI9080 I2O"),
	DEVICE( MADGE,		MADGE_MK2,	"Smart 16/4 BM Mk2 Ringnode"),
	DEVICE( MADGE,		MADGE_C155S,	"Collage 155 Server"),
	DEVICE( 3COM,		3COM_3C339,	"3C339 TokenRing"),
	DEVICE( 3COM,		3COM_3C590,	"3C590 10bT"),
	DEVICE( 3COM,		3COM_3C595TX,	"3C595 100bTX"),
	DEVICE( 3COM,		3COM_3C595T4,	"3C595 100bT4"),
	DEVICE( 3COM,		3COM_3C595MII,	"3C595 100b-MII"),
	DEVICE( 3COM,		3COM_3C900TPO,	"3C900 10bTPO"),
	DEVICE( 3COM,		3COM_3C900COMBO,"3C900 10b Combo"),
	DEVICE( 3COM,		3COM_3C905TX,	"3C905 100bTX"),
	DEVICE( 3COM,		3COM_3C905T4,	"3C905 100bT4"),
	DEVICE( 3COM,		3COM_3C905B_TX,	"3C905B 100bTX"),
	DEVICE( SMC,		SMC_EPIC100,	"9432 TX"),
	DEVICE( AL,		AL_M1445,	"M1445"),
	DEVICE( AL,		AL_M1449,	"M1449"),
	DEVICE( AL,		AL_M1451,	"M1451"),
	DEVICE( AL,		AL_M1461,	"M1461"),
	DEVICE( AL,		AL_M1489,	"M1489"),
	DEVICE( AL,		AL_M1511,	"M1511"),
	DEVICE( AL,		AL_M1513,	"M1513"),
	DEVICE( AL,		AL_M1521,	"M1521"),
	DEVICE( AL,		AL_M1523,	"M1523"),
	DEVICE( AL,		AL_M1531,	"M1531 Aladdin IV"),
	DEVICE( AL,		AL_M1533,	"M1533 Aladdin IV"),
	DEVICE( AL,		AL_M3307,	"M3307 MPEG-1 decoder"),
	DEVICE( AL,		AL_M4803,	"M4803"),
	DEVICE( AL,		AL_M5219,	"M5219"),
	DEVICE( AL,		AL_M5229,	"M5229 TXpro"),
	DEVICE( AL,		AL_M5237,	"M5237 USB"),
	DEVICE( SURECOM,	SURECOM_NE34,	"NE-34PCI LAN"),
	DEVICE( NEOMAGIC,       NEOMAGIC_MAGICGRAPH_NM2070,     "Magicgraph NM2070"),
	DEVICE( NEOMAGIC,	NEOMAGIC_MAGICGRAPH_128V, "MagicGraph 128V"),
	DEVICE( NEOMAGIC,	NEOMAGIC_MAGICGRAPH_128ZV, "MagicGraph 128ZV"),
	DEVICE( NEOMAGIC,	NEOMAGIC_MAGICGRAPH_NM2160, "MagicGraph NM2160"),
	DEVICE( NEOMAGIC,	NEOMAGIC_MAGICGRAPH_128ZVPLUS, "MagicGraph 128ZV+"),
	DEVICE( ASP,		ASP_ABP940,	"ABP940"),
	DEVICE( ASP,		ASP_ABP940U,	"ABP940U"),
	DEVICE( ASP,		ASP_ABP940UW,	"ABP940UW"),
	DEVICE( MACRONIX,	MACRONIX_MX98713,"MX98713"),
	DEVICE( MACRONIX,	MACRONIX_MX987x5,"MX98715 / MX98725"),
	DEVICE( CERN,		CERN_SPSB_PMC,	"STAR/RD24 SCI-PCI (PMC)"),
	DEVICE( CERN,		CERN_SPSB_PCI,	"STAR/RD24 SCI-PCI (PMC)"),
	DEVICE( CERN,		CERN_HIPPI_DST,	"HIPPI destination"),
	DEVICE( CERN,		CERN_HIPPI_SRC,	"HIPPI source"),
	DEVICE( IMS,		IMS_8849,	"8849"),
	DEVICE( TEKRAM2,	TEKRAM2_690c,	"DC690c"),
	DEVICE( TUNDRA,		TUNDRA_CA91C042,"CA91C042 Universe"),
	DEVICE( AMCC,		AMCC_MYRINET,	"Myrinet PCI (M2-PCI-32)"),
	DEVICE( AMCC,		AMCC_PARASTATION,"ParaStation Interface"),
	DEVICE( AMCC,		AMCC_S5933,	"S5933 PCI44"),
	DEVICE( AMCC,		AMCC_S5933_HEPC3,"S5933 Traquair HEPC3"),
	DEVICE( INTERG,		INTERG_1680,	"IGA-1680"),
	DEVICE( INTERG,         INTERG_1682,    "IGA-1682"),
	DEVICE( REALTEK,	REALTEK_8029,	"8029"),
	DEVICE( REALTEK,	REALTEK_8129,	"8129"),
	DEVICE( REALTEK,	REALTEK_8139,	"8139"),
	DEVICE( TRUEVISION,	TRUEVISION_T1000,"TARGA 1000"),
	DEVICE( INIT,		INIT_320P,	"320 P"),
	DEVICE( INIT,		INIT_360P,	"360 P"),
	DEVICE(	TTI,		TTI_HPT343,	"HPT343"),
	DEVICE( VIA,		VIA_82C505,	"VT 82C505"),
	DEVICE( VIA,		VIA_82C561,	"VT 82C561"),
	DEVICE( VIA,		VIA_82C586_1,	"VT 82C586 Apollo IDE"),
	DEVICE( VIA,		VIA_82C576,	"VT 82C576 3V"),
	DEVICE( VIA,		VIA_82C585,	"VT 82C585 Apollo VP1/VPX"),
	DEVICE( VIA,		VIA_82C586_0,	"VT 82C586 Apollo ISA"),
	DEVICE( VIA,		VIA_82C595,	"VT 82C595 Apollo VP2"),
	DEVICE( VIA,		VIA_82C596_0,	"VT 82C596 Apollo Pro"),
	DEVICE( VIA,		VIA_82C597_0,	"VT 82C597 Apollo VP3"),
	DEVICE( VIA,		VIA_82C598_0,	"VT 82C598 Apollo MVP3"),
	DEVICE( VIA,		VIA_82C926,	"VT 82C926 Amazon"),
	DEVICE( VIA,		VIA_82C416,	"VT 82C416MV"),
	DEVICE( VIA,		VIA_82C595_97,	"VT 82C595 Apollo VP2/97"),
	DEVICE( VIA,		VIA_82C586_2,	"VT 82C586 Apollo USB"),
	DEVICE( VIA,		VIA_82C586_3,	"VT 82C586B Apollo ACPI"),
	DEVICE( VIA,		VIA_86C100A,	"VT 86C100A"),
	DEVICE( VIA,		VIA_82C597_1,	"VT 82C597 Apollo VP3 AGP"),
	DEVICE( VIA,		VIA_82C598_1,	"VT 82C598 Apollo MVP3 AGP"),
	DEVICE( SMC2,		SMC2_1211TX,	"1211 TX"),
	DEVICE( VORTEX,		VORTEX_GDT60x0,	"GDT 60x0"),
	DEVICE( VORTEX,		VORTEX_GDT6000B,"GDT 6000b"),
	DEVICE( VORTEX,		VORTEX_GDT6x10,	"GDT 6110/6510"),
	DEVICE( VORTEX,		VORTEX_GDT6x20,	"GDT 6120/6520"),
	DEVICE( VORTEX,		VORTEX_GDT6530,	"GDT 6530"),
	DEVICE( VORTEX,		VORTEX_GDT6550,	"GDT 6550"),
	DEVICE( VORTEX,		VORTEX_GDT6x17,	"GDT 6117/6517"),
	DEVICE( VORTEX,		VORTEX_GDT6x27,	"GDT 6127/6527"),
	DEVICE( VORTEX,		VORTEX_GDT6537,	"GDT 6537"),
	DEVICE( VORTEX,		VORTEX_GDT6557,	"GDT 6557"),
	DEVICE( VORTEX,		VORTEX_GDT6x15,	"GDT 6115/6515"),
	DEVICE( VORTEX,		VORTEX_GDT6x25,	"GDT 6125/6525"),
	DEVICE( VORTEX,		VORTEX_GDT6535,	"GDT 6535"),
	DEVICE( VORTEX,		VORTEX_GDT6555,	"GDT 6555"),
	DEVICE( VORTEX,		VORTEX_GDT6x17RP,"GDT 6117RP/6517RP"),
	DEVICE( VORTEX,		VORTEX_GDT6x27RP,"GDT 6127RP/6527RP"),
	DEVICE( VORTEX,		VORTEX_GDT6537RP,"GDT 6537RP"),
	DEVICE( VORTEX,		VORTEX_GDT6557RP,"GDT 6557RP"),
	DEVICE( VORTEX,		VORTEX_GDT6x11RP,"GDT 6111RP/6511RP"),
	DEVICE( VORTEX,		VORTEX_GDT6x21RP,"GDT 6121RP/6521RP"),
	DEVICE( VORTEX,		VORTEX_GDT6x17RP1,"GDT 6117RP1/6517RP1"),
	DEVICE( VORTEX,		VORTEX_GDT6x27RP1,"GDT 6127RP1/6527RP1"),
	DEVICE( VORTEX,		VORTEX_GDT6537RP1,"GDT 6537RP1"),
	DEVICE( VORTEX,		VORTEX_GDT6557RP1,"GDT 6557RP1"),
	DEVICE( VORTEX,		VORTEX_GDT6x11RP1,"GDT 6111RP1/6511RP1"),
	DEVICE( VORTEX,		VORTEX_GDT6x21RP1,"GDT 6121RP1/6521RP1"),
	DEVICE( VORTEX,		VORTEX_GDT6x17RP2,"GDT 6117RP2/6517RP2"),
	DEVICE( VORTEX,		VORTEX_GDT6x27RP2,"GDT 6127RP2/6527RP2"),
	DEVICE( VORTEX,		VORTEX_GDT6537RP2,"GDT 6537RP2"),
	DEVICE( VORTEX,		VORTEX_GDT6557RP2,"GDT 6557RP2"),
	DEVICE( VORTEX,		VORTEX_GDT6x11RP2,"GDT 6111RP2/6511RP2"),
	DEVICE( VORTEX,		VORTEX_GDT6x21RP2,"GDT 6121RP2/6521RP2"),
	DEVICE( EF,		EF_ATM_FPGA,   	"155P-MF1 (FPGA)"),
	DEVICE( EF,		EF_ATM_ASIC,    "155P-MF1 (ASIC)"),
	DEVICE( FORE,		FORE_PCA200PC,  "PCA-200PC"),
	DEVICE( FORE,		FORE_PCA200E,	 "PCA-200E"),
	DEVICE( IMAGINGTECH,	IMAGINGTECH_ICPCI, "MVC IC-PCI"),
	DEVICE( PHILIPS,	PHILIPS_SAA7145,"SAA7145"),
	DEVICE( PHILIPS,	PHILIPS_SAA7146,"SAA7146"),
	DEVICE( CYCLONE,	CYCLONE_SDK,	"SDK"),
	DEVICE( ALLIANCE,	ALLIANCE_PROMOTIO, "Promotion-6410"),
	DEVICE( ALLIANCE,	ALLIANCE_PROVIDEO, "Provideo"),
	DEVICE( ALLIANCE,	ALLIANCE_AT24,	"AT24"),
	DEVICE( ALLIANCE,	ALLIANCE_AT3D,	"AT3D"),
	DEVICE( SYSKONNECT,	SYSKONNECT_FP,	"SK-FDDI-PCI"),
	DEVICE( SYSKONNECT,	SYSKONNECT_TR,	"SK-TR-PCI"),
	DEVICE( SYSKONNECT,	SYSKONNECT_GE,	"SK-98xx"),
	DEVICE( VMIC,		VMIC_VME,	"VMIVME-7587"),
	DEVICE( DIGI,		DIGI_EPC,	"AccelPort EPC"),
 	DEVICE( DIGI,		DIGI_RIGHTSWITCH, "RightSwitch SE-6"),
	DEVICE( DIGI,		DIGI_XEM,	"AccelPort Xem"),
	DEVICE( DIGI,		DIGI_XR,	"AccelPort Xr"),
	DEVICE( DIGI,		DIGI_CX,	"AccelPort C/X"),
	DEVICE( DIGI,		DIGI_XRJ,	"AccelPort Xr/J"),
	DEVICE( DIGI,		DIGI_EPCJ,	"AccelPort EPC/J"),
	DEVICE( DIGI,		DIGI_XR_920,	"AccelPort Xr 920"),
	DEVICE( MUTECH,		MUTECH_MV1000,	"MV-1000"),
	DEVICE( RENDITION,	RENDITION_VERITE,"Verite 1000"),
	DEVICE( RENDITION,	RENDITION_VERITE2100,"Verite 2100"),
	DEVICE(	SERVERWORKS,	SERVERWORKS_HE,	"CNB20HE PCI Bridge"),
	DEVICE(	SERVERWORKS,	SERVERWORKS_LE,	"CNB30LE PCI Bridge"),
	DEVICE(	SERVERWORKS,	SERVERWORKS_CMIC_HE,	"CMIC-HE PCI Bridge"),
	DEVICE(	SERVERWORKS,	SERVERWORKS_CIOB30,	"CIOB30 I/O Bridge"),
	DEVICE(	SERVERWORKS,	SERVERWORKS_CSB5,	"CSB5 PCI Bridge"),
	DEVICE( TOSHIBA,	TOSHIBA_601,	"Laptop"),
	DEVICE( TOSHIBA,	TOSHIBA_TOPIC95,"ToPIC95"),
	DEVICE( TOSHIBA,	TOSHIBA_TOPIC97,"ToPIC97"),
	DEVICE( RICOH,		RICOH_RL5C466,	"RL5C466"),
	DEVICE(	ARTOP,		ARTOP_ATP8400,	"ATP8400"),
	DEVICE( ARTOP,		ARTOP_ATP850UF,	"ATP850UF"),
	DEVICE( ZEITNET,	ZEITNET_1221,	"1221"),
	DEVICE( ZEITNET,	ZEITNET_1225,	"1225"),
	DEVICE( OMEGA,		OMEGA_82C092G,	"82C092G"),
	DEVICE( LITEON,		LITEON_LNE100TX,"LNE100TX"),
	DEVICE( NP,		NP_PCI_FDDI,	"NP-PCI"),       
	DEVICE( ATT,		ATT_L56XMF,	"L56xMF"),
	DEVICE( ATT,		ATT_L56DVP,	"L56DV+P"),
	DEVICE( SPECIALIX,	SPECIALIX_IO8,	"IO8+/PCI"),
	DEVICE( SPECIALIX,	SPECIALIX_XIO,	"XIO/SIO host"),
	DEVICE( SPECIALIX,	SPECIALIX_RIO,	"RIO host"),
	DEVICE( AURAVISION,	AURAVISION_VXP524,"VXP524"),
	DEVICE( IKON,		IKON_10115,	"10115 Greensheet"),
	DEVICE( IKON,		IKON_10117,	"10117 Greensheet"),
	DEVICE( ZORAN,		ZORAN_36057,	"ZR36057"),
	DEVICE( ZORAN,		ZORAN_36120,	"ZR36120"),
	DEVICE( KINETIC,	KINETIC_2915,	"2915 CAMAC"),
	DEVICE( COMPEX,		COMPEX_ENET100VG4, "Readylink ENET100-VG4"),
	DEVICE( COMPEX,		COMPEX_RL2000,	"ReadyLink 2000"),
	DEVICE( RP,             RP32INTF,       "RocketPort 32 Intf"),
	DEVICE( RP,             RP8INTF,        "RocketPort 8 Intf"),
	DEVICE( RP,             RP16INTF,       "RocketPort 16 Intf"),
	DEVICE( RP, 		RP4QUAD,	"Rocketport 4 Quad"),
	DEVICE( RP,             RP8OCTA,        "RocketPort 8 Oct"),
	DEVICE( RP,             RP8J,	        "RocketPort 8 J"),
	DEVICE( RP,             RPP4,	        "RocketPort Plus 4 Quad"),
	DEVICE( RP,             RPP8,	        "RocketPort Plus 8 Oct"),
	DEVICE( RP,             RP8M,	        "RocketModem 8 J"),
	DEVICE( CYCLADES,	CYCLOM_Y_Lo,	"Cyclom-Y below 1Mbyte"),
	DEVICE( CYCLADES,	CYCLOM_Y_Hi,	"Cyclom-Y above 1Mbyte"),
	DEVICE( CYCLADES,	CYCLOM_4Y_Lo,	"Cyclom-4Y below 1Mbyte"),
	DEVICE( CYCLADES,	CYCLOM_4Y_Hi,	"Cyclom-4Y above 1Mbyte"),
	DEVICE( CYCLADES,	CYCLOM_8Y_Lo,	"Cyclom-8Y below 1Mbyte"),
	DEVICE( CYCLADES,	CYCLOM_8Y_Hi,	"Cyclom-8Y above 1Mbyte"),
	DEVICE( CYCLADES,	CYCLOM_Z_Lo,	"Cyclades-Z below 1Mbyte"),
	DEVICE( CYCLADES,	CYCLOM_Z_Hi,	"Cyclades-Z above 1Mbyte"),
	DEVICE( CYCLADES,	PC300_RX_2,	"PC300/RSV or /X21 (2 ports)"),
	DEVICE( CYCLADES,	PC300_RX_1,	"PC300/RSV or /X21 (1 port)"),
	DEVICE( CYCLADES,	PC300_TE_2,	"PC300/TE (2 ports)"),
	DEVICE( CYCLADES,	PC300_TE_1,	"PC300/TE (1 port)"),
	DEVICE( ESSENTIAL,	ESSENTIAL_ROADRUNNER,"Roadrunner serial HIPPI"),
	DEVICE( O2,		O2_6832,	"6832"),
	DEVICE( 3DFX,		3DFX_VOODOO,	"Voodoo"),
	DEVICE( 3DFX,		3DFX_VOODOO2,	"Voodoo2"),
	DEVICE( 3DFX,           3DFX_BANSHEE,   "Banshee"),
	DEVICE( SIGMADES,	SIGMADES_6425,	"REALmagic64/GX"),
	DEVICE( AVM,		AVM_A1,		"A1 (Fritz)"),
	DEVICE( STALLION,	STALLION_ECHPCI832,"EasyConnection 8/32"),
	DEVICE( STALLION,	STALLION_ECHPCI864,"EasyConnection 8/64"),
	DEVICE( STALLION,	STALLION_EIOPCI,"EasyIO"),
	DEVICE( OPTIBASE,	OPTIBASE_FORGE,	"MPEG Forge"),
	DEVICE( OPTIBASE,	OPTIBASE_FUSION,"MPEG Fusion"),
	DEVICE( OPTIBASE,	OPTIBASE_VPLEX,	"VideoPlex"),
	DEVICE( OPTIBASE,	OPTIBASE_VPLEXCC,"VideoPlex CC"),
	DEVICE( OPTIBASE,	OPTIBASE_VQUEST,"VideoQuest"),
	DEVICE( SATSAGEM,	SATSAGEM_PCR2101,"PCR2101 DVB receiver"),
	DEVICE( SATSAGEM,	SATSAGEM_TELSATTURBO,"Telsat Turbo DVB"),
	DEVICE( HUGHES,		HUGHES_DIRECPC,	"DirecPC"),
	DEVICE( ENSONIQ,	ENSONIQ_ES1371,	"ES1371"),
	DEVICE( ENSONIQ,	ENSONIQ_AUDIOPCI,"AudioPCI"),
	DEVICE( ALTEON,		ALTEON_ACENIC,  "AceNIC"),
	DEVICE( PICTUREL,	PICTUREL_PCIVST,"PCIVST"),
	DEVICE( NVIDIA_SGS,	NVIDIA_SGS_RIVA128,	"Riva 128"),
	DEVICE( CBOARDS,	CBOARDS_DAS1602_16,"DAS1602/16"),
	DEVICE( MOTOROLA_OOPS,	MOTOROLA_FALCON,"Falcon"),
	DEVICE( TIMEDIA,	TIMEDIA_4008A, "Noname 4008A"),
	DEVICE( SYMPHONY,	SYMPHONY_101,	"82C101"),
	DEVICE( TEKRAM,		TEKRAM_DC290,	"DC-290"),
	DEVICE( 3DLABS,		3DLABS_300SX,	"GLINT 300SX"),
	DEVICE( 3DLABS,		3DLABS_500TX,	"GLINT 500TX"),
	DEVICE( 3DLABS,		3DLABS_DELTA,	"GLINT Delta"),
	DEVICE( 3DLABS,		3DLABS_PERMEDIA,"PERMEDIA"),
	DEVICE( 3DLABS,		3DLABS_MX,	"GLINT MX"),
	DEVICE( AVANCE,		AVANCE_ALG2064,	"ALG2064i"),
	DEVICE( AVANCE,		AVANCE_2302,	"ALG-2302"),
	DEVICE( NETVIN,		NETVIN_NV5000SC,"NV5000"),
	DEVICE( S3,		S3_PLATO_PXS,	"PLATO/PX (system)"),
	DEVICE( S3,		S3_ViRGE,	"ViRGE"),
	DEVICE( S3,		S3_TRIO,	"Trio32/Trio64"),
	DEVICE( S3,		S3_AURORA64VP,	"Aurora64V+"),
	DEVICE( S3,		S3_TRIO64UVP,	"Trio64UV+"),
	DEVICE( S3,		S3_ViRGE_VX,	"ViRGE/VX"),
	DEVICE( S3,		S3_868,	        "Vision 868"),
	DEVICE( S3,		S3_928,		"Vision 928-P"),
	DEVICE( S3,		S3_864_1,	"Vision 864-P"),
	DEVICE( S3,		S3_864_2,	"Vision 864-P"),
	DEVICE( S3,		S3_964_1,	"Vision 964-P"),
	DEVICE( S3,		S3_964_2,	"Vision 964-P"),
	DEVICE( S3,		S3_968,		"Vision 968"),
	DEVICE( S3,		S3_TRIO64V2,	"Trio64V2/DX or /GX"),
	DEVICE( S3,		S3_PLATO_PXG,	"PLATO/PX (graphics)"),
	DEVICE( S3,		S3_ViRGE_DXGX,	"ViRGE/DX or /GX"),
	DEVICE( S3,		S3_ViRGE_GX2,	"ViRGE/GX2"),
	DEVICE( S3,		S3_ViRGE_MX,	"ViRGE/MX"),
	DEVICE( S3,		S3_ViRGE_MXP,	"ViRGE/MX+"),
	DEVICE( S3,		S3_ViRGE_MXPMV,	"ViRGE/MX+MV"),
	DEVICE( S3,		S3_SONICVIBES,	"SonicVibes"),
	DEVICE( DCI,		DCI_PCCOM4,	"PC COM PCI Bus 4 port serial Adapter"),
	DEVICE( GENROCO,	GENROCO_HFP832,	"TURBOstor HFP832"),
	DEVICE( INTEL,		INTEL_82375,	"82375EB"),
	DEVICE( INTEL,		INTEL_82424,	"82424ZX Saturn"),
	DEVICE( INTEL,		INTEL_82378,	"82378IB"),
	DEVICE( INTEL,		INTEL_82430,	"82430ZX Aries"),
	DEVICE( INTEL,		INTEL_82434,	"82434LX Mercury/Neptune"),
	DEVICE( INTEL,		INTEL_I960,	"i960"),
	DEVICE( INTEL,		INTEL_I960RN,	"i960 RN"),
	DEVICE( INTEL,		INTEL_82559ER,	"82559ER"),
	DEVICE( INTEL,		INTEL_82092AA_0,"82092AA PCMCIA bridge"),
	DEVICE( INTEL,		INTEL_82092AA_1,"82092AA EIDE"),
	DEVICE( INTEL,		INTEL_7116,	"SAA7116"),
	DEVICE( INTEL,		INTEL_82596,	"82596"),
	DEVICE( INTEL,		INTEL_82865,	"82865"),
	DEVICE( INTEL,		INTEL_82557,	"82557"),
	DEVICE( INTEL,		INTEL_82437,	"82437"),
	DEVICE( INTEL,		INTEL_82371FB_0,"82371FB PIIX ISA"),
	DEVICE( INTEL,		INTEL_82371FB_1,"82371FB PIIX IDE"),
	DEVICE( INTEL,		INTEL_82371MX,	"430MX - 82371MX MPIIX"),
	DEVICE( INTEL,		INTEL_82437MX,	"430MX - 82437MX MTSC"),
	DEVICE( INTEL,		INTEL_82441,	"82441FX Natoma"),
	DEVICE( INTEL,		INTEL_82380FB,	"82380FB Mobile"),
	DEVICE( INTEL,		INTEL_82439,	"82439HX Triton II"),
	DEVICE(	INTEL,		INTEL_MEGARAID,	"OEM MegaRAID Controller"),
	DEVICE(	INTEL,		INTEL_82371SB_0,"82371SB PIIX3 ISA"),
	DEVICE(	INTEL,		INTEL_82371SB_1,"82371SB PIIX3 IDE"),
	DEVICE( INTEL,		INTEL_82371SB_2,"82371SB PIIX3 USB"),
	DEVICE( INTEL,		INTEL_82437VX,	"82437VX Triton II"),
	DEVICE( INTEL,		INTEL_82439TX,	"82439TX"),
	DEVICE( INTEL,		INTEL_82371AB_0,"82371AB PIIX4 ISA"),
	DEVICE( INTEL,		INTEL_82371AB,	"82371AB PIIX4 IDE"),
	DEVICE( INTEL,		INTEL_82371AB_2,"82371AB PIIX4 USB"),
	DEVICE( INTEL,		INTEL_82371AB_3,"82371AB PIIX4 ACPI"),
	DEVICE( INTEL,		INTEL_82443LX_0,"440LX - 82443LX PAC Host"),
	DEVICE( INTEL,		INTEL_82443LX_1,"440LX - 82443LX PAC AGP"),
	DEVICE( INTEL,		INTEL_82443BX_0,"440BX - 82443BX Host"),
	DEVICE( INTEL,		INTEL_82443BX_1,"440BX - 82443BX AGP"),
	DEVICE( INTEL,		INTEL_82443BX_2,"440BX - 82443BX Host (no AGP)"),
	DEVICE( INTEL,		INTEL_P6,	"Orion P6"),
 	DEVICE( INTEL,		INTEL_82450GX,	"450KX/GX [Orion] - 82454KX/GX PCI Bridge"),
 	DEVICE( INTEL,		INTEL_82453GX,	"450KX/GX [Orion] - 82453KX/GX Memory Controller"),
 	DEVICE( INTEL,		INTEL_82451NX,	"450NX - 82451NX Memory & I/O Controller"),
 	DEVICE( INTEL,		INTEL_82454NX,	"450NX - 82454NX PCI Expander Bridge"),
	DEVICE( COMPUTONE,	COMPUTONE_IP2EX, "Computone IntelliPort Plus"),
	DEVICE(	KTI,		KTI_ET32P2,	"ET32P2"),
	DEVICE( ADAPTEC,	ADAPTEC_7810,	"AIC-7810 RAID"),
	DEVICE( ADAPTEC,	ADAPTEC_7821,	"AIC-7860"),
	DEVICE( ADAPTEC,	ADAPTEC_38602,	"AIC-7860"),
	DEVICE( ADAPTEC,	ADAPTEC_7850,	"AIC-7850"),
	DEVICE( ADAPTEC,	ADAPTEC_7855,	"AIC-7855"),
	DEVICE( ADAPTEC,	ADAPTEC_5800,	"AIC-5800"),
	DEVICE( ADAPTEC,	ADAPTEC_3860,	"AIC-7860"),
	DEVICE( ADAPTEC,	ADAPTEC_7860,	"AIC-7860"),
	DEVICE( ADAPTEC,	ADAPTEC_7861,	"AIC-7861"),
	DEVICE( ADAPTEC,	ADAPTEC_7870,	"AIC-7870"),
	DEVICE( ADAPTEC,	ADAPTEC_7871,	"AIC-7871"),
	DEVICE( ADAPTEC,	ADAPTEC_7872,	"AIC-7872"),
	DEVICE( ADAPTEC,	ADAPTEC_7873,	"AIC-7873"),
	DEVICE( ADAPTEC,	ADAPTEC_7874,	"AIC-7874"),
	DEVICE( ADAPTEC,	ADAPTEC_7895,	"AIC-7895U"),
	DEVICE( ADAPTEC,	ADAPTEC_7880,	"AIC-7880U"),
	DEVICE( ADAPTEC,	ADAPTEC_7881,	"AIC-7881U"),
	DEVICE( ADAPTEC,	ADAPTEC_7882,	"AIC-7882U"),
	DEVICE( ADAPTEC,	ADAPTEC_7883,	"AIC-7883U"),
	DEVICE( ADAPTEC,	ADAPTEC_7884,	"AIC-7884U"),
	DEVICE( ADAPTEC,	ADAPTEC_7885,	"AIC-7885U"),
	DEVICE( ADAPTEC,	ADAPTEC_7886,	"AIC-7886U"),
	DEVICE( ADAPTEC,	ADAPTEC_7887,	"AIC-7887U"),
	DEVICE( ADAPTEC,	ADAPTEC_7888,	"AIC-7888U"),
	DEVICE( ADAPTEC,	ADAPTEC_1030,	"ABA-1030 DVB receiver"),
	DEVICE( ADAPTEC2,	ADAPTEC2_2940U2,"AHA-2940U2"),
	DEVICE( ADAPTEC2,	ADAPTEC2_2930U2,"AHA-2930U2"),
	DEVICE( ADAPTEC2,	ADAPTEC2_7890B,	"AIC-7890/1"),
	DEVICE( ADAPTEC2,	ADAPTEC2_7890,	"AIC-7890/1"),
	DEVICE( ADAPTEC2,	ADAPTEC2_3940U2,"AHA-3940U2"),
	DEVICE( ADAPTEC2,	ADAPTEC2_3950U2D,"AHA-3950U2D"),
	DEVICE( ADAPTEC2,	ADAPTEC2_7896,	"AIC-7896/7"),
	DEVICE( ADAPTEC2,	ADAPTEC2_7892A,	"AIC-7892"),
	DEVICE( ADAPTEC2,	ADAPTEC2_7892B,	"AIC-7892"),
	DEVICE( ADAPTEC2,	ADAPTEC2_7892D,	"AIC-7892"),
	DEVICE( ADAPTEC2,	ADAPTEC2_7892P,	"AIC-7892"),
	DEVICE( ADAPTEC2,	ADAPTEC2_7899A,	"AIC-7899"),
	DEVICE( ADAPTEC2,	ADAPTEC2_7899B,	"AIC-7899"),
	DEVICE( ADAPTEC2,	ADAPTEC2_7899D,	"AIC-7899"),
	DEVICE( ADAPTEC2,	ADAPTEC2_7899P,	"AIC-7899"),
  	DEVICE( ATRONICS,	ATRONICS_2015,	"IDE-2015PL"),
	DEVICE( TIGERJET,	TIGERJET_300,	"Tiger300 ISDN"),
	DEVICE( ARK,		ARK_STING,	"Stingray"),
	DEVICE( ARK,		ARK_STINGARK,	"Stingray ARK 2000PV"),
	DEVICE( ARK,		ARK_2000MT,	"2000MT")
};


/*
 * device_info[] is sorted so we can use binary search
 */
static struct pci_dev_info *
pci_lookup_dev(unsigned int vendor, unsigned int dev)
{
	int min = 0,
	    max = sizeof(dev_info)/sizeof(dev_info[0]) - 1;

	for ( ; ; )
	{
	    int i = (min + max) >> 1;
	    long order;

	    order = dev_info[i].vendor - (long) vendor;
	    if (!order)
		order = dev_info[i].device - (long) dev;
	
	    if (order < 0)
	    {
		    min = i + 1;
		    if ( min > max )
		       return 0;
		    continue;
	    }

	    if (order > 0)
	    {
		    max = i - 1;
		    if ( min > max )
		       return 0;
		    continue;
	    }
  	   
	    return & dev_info[ i ];
	}
}


static const char *
pci_strclass (unsigned int class, char *buf)
{
	char *s;

	switch (class >> 8) {
	case PCI_CLASS_NOT_DEFINED:
		s = "Non-VGA device"; 
		break;
	case PCI_CLASS_NOT_DEFINED_VGA:
		s = "VGA compatible device"; 
		break;
	case PCI_CLASS_STORAGE_SCSI:
		s = "SCSI storage controller"; 
		break;
	case PCI_CLASS_STORAGE_IDE:
		s = "IDE interface"; 
		break;
	case PCI_CLASS_STORAGE_FLOPPY:
		s = "Floppy disk controller"; 
		break;
	case PCI_CLASS_STORAGE_IPI:
		s = "IPI storage controller"; 
		break;
	case PCI_CLASS_STORAGE_RAID:
		s = "RAID storage controller"; 
		break;
	case PCI_CLASS_STORAGE_OTHER:
		s = "Unknown mass storage controller"; 
		break;

	case PCI_CLASS_NETWORK_ETHERNET:
		s = "Ethernet controller"; 
		break;
	case PCI_CLASS_NETWORK_TOKEN_RING:
		s = "Token ring network controller"; 
		break;
	case PCI_CLASS_NETWORK_FDDI:
		s = "FDDI network controller"; 
		break;
	case PCI_CLASS_NETWORK_ATM:
		s = "ATM network controller"; 
		break;
	case PCI_CLASS_NETWORK_OTHER:
		s = "Network controller"; 
		break;

	case PCI_CLASS_DISPLAY_VGA:
		s = "VGA compatible controller"; 
		break;
	case PCI_CLASS_DISPLAY_XGA:
		s = "XGA compatible controller"; 
		break;
	case PCI_CLASS_DISPLAY_OTHER:
		s = "Display controller"; 
		break;

	case PCI_CLASS_MULTIMEDIA_VIDEO:
		s = "Multimedia video controller"; 
		break;
	case PCI_CLASS_MULTIMEDIA_AUDIO:
		s = "Multimedia audio controller"; 
		break;
	case PCI_CLASS_MULTIMEDIA_OTHER:
		s = "Multimedia controller"; 
		break;

	case PCI_CLASS_MEMORY_RAM:
		s = "RAM memory"; 
		break;
	case PCI_CLASS_MEMORY_FLASH:
		s = "FLASH memory"; 
		break;
	case PCI_CLASS_MEMORY_OTHER:
		s = "Memory"; 
		break;

	case PCI_CLASS_BRIDGE_HOST:
		s = "Host bridge"; 
		break;
	case PCI_CLASS_BRIDGE_ISA:
		s = "ISA bridge"; 
		break;
	case PCI_CLASS_BRIDGE_EISA:
		s = "EISA bridge"; 
		break;
	case PCI_CLASS_BRIDGE_MC:
		s = "MicroChannel bridge"; 
		break;
	case PCI_CLASS_BRIDGE_PCI:
		s = "PCI bridge"; 
		break;
	case PCI_CLASS_BRIDGE_PCMCIA:
		s = "PCMCIA bridge"; 
		break;
	case PCI_CLASS_BRIDGE_NUBUS:
		s = "NuBus bridge"; 
		break;
	case PCI_CLASS_BRIDGE_CARDBUS:
		s = "CardBus bridge"; 
		break;
	case PCI_CLASS_BRIDGE_OTHER:
		s = "Bridge"; 
		break;

	case PCI_CLASS_COMMUNICATION_SERIAL:
		s = "Serial controller"; 
		break;
	case PCI_CLASS_COMMUNICATION_PARALLEL:
		s = "Parallel controller"; 
		break;
	case PCI_CLASS_COMMUNICATION_OTHER:
		s = "Communication controller"; 
		break;

	case PCI_CLASS_SYSTEM_PIC:
		s = "PIC"; 
		break;
	case PCI_CLASS_SYSTEM_DMA:
		s = "DMA controller"; 
		break;
	case PCI_CLASS_SYSTEM_TIMER:
		s = "Timer"; 
		break;
	case PCI_CLASS_SYSTEM_RTC:
		s = "RTC"; 
		break;
	case PCI_CLASS_SYSTEM_OTHER:
		s = "System peripheral"; 
		break;

	case PCI_CLASS_INPUT_KEYBOARD:
		s = "Keyboard controller"; 
		break;
	case PCI_CLASS_INPUT_PEN:
		s = "Digitizer Pen"; 
		break;
	case PCI_CLASS_INPUT_MOUSE:
		s = "Mouse controller"; 
		break;
	case PCI_CLASS_INPUT_OTHER:
		s = "Input device controller"; 
		break;

	case PCI_CLASS_DOCKING_GENERIC:
		s = "Generic Docking Station"; 
		break;
	case PCI_CLASS_DOCKING_OTHER:
		s = "Docking Station"; 
		break;

	case PCI_CLASS_PROCESSOR_386:
		s = "386"; 
		break;
	case PCI_CLASS_PROCESSOR_486:
		s = "486"; 
		break;
	case PCI_CLASS_PROCESSOR_PENTIUM:
		s = "Pentium"; 
		break;
	case PCI_CLASS_PROCESSOR_ALPHA:
		s = "Alpha"; 
		break;
	case PCI_CLASS_PROCESSOR_POWERPC:
		s = "Power PC"; 
		break;
	case PCI_CLASS_PROCESSOR_CO:
		s = "Co-processor"; 
		break;

	case PCI_CLASS_SERIAL_FIREWIRE:
		s = "FireWire (IEEE 1394)"; 
		break;
	case PCI_CLASS_SERIAL_ACCESS:
		s = "ACCESS Bus"; 
		break;
	case PCI_CLASS_SERIAL_SSA:
		s = "SSA"; 
		break;
	case PCI_CLASS_SERIAL_USB:
		s = "USB Controller"; 
		break;
	case PCI_CLASS_SERIAL_FIBER:
		s = "Fiber Channel"; 
		break;
	case PCI_CLASS_SERIAL_SMBUS:
		s = "SM Bus"; 
		break;

	case PCI_CLASS_HOT_SWAP_CONTROLLER:
		s = "Hot Swap Controller"; 
		break;

	default:					
		sprintf(buf, "[PCI_CLASS %x]", class);
		s = buf;
		break;
	}

	return s;
}


static const char *
pci_strvendor(unsigned int vendor, char *buf)
{
	char *s;

	switch (vendor) {
	case PCI_VENDOR_ID_COMPAQ:	
		s = "Compaq"; 
		break;
	case PCI_VENDOR_ID_NCR:		
		s = "NCR"; 
		break;
	case PCI_VENDOR_ID_ATI:		
		s = "ATI"; 
		break;
	case PCI_VENDOR_ID_VLSI:		
		s = "VLSI"; 
		break;
	case PCI_VENDOR_ID_ADL:		
		s = "Avance Logic"; 
		break;
	case PCI_VENDOR_ID_NS:		
		s = "NS"; 
		break;
	case PCI_VENDOR_ID_TSENG:		
		s = "Tseng'Lab"; 
		break;
	case PCI_VENDOR_ID_WEITEK:	
		s = "Weitek"; 
		break;
	case PCI_VENDOR_ID_DEC:		
		s = "DEC"; 
		break;
	case PCI_VENDOR_ID_CIRRUS:	
		s = "Cirrus Logic"; 
		break;
	case PCI_VENDOR_ID_IBM:		
		s = "IBM"; 
		break;
	case PCI_VENDOR_ID_WD:		
		s = "Western Digital"; 
		break;
	case PCI_VENDOR_ID_AMD:		
		s = "AMD"; 
		break;
	case PCI_VENDOR_ID_TRIDENT:	
		s = "Trident"; 
		break;
	case PCI_VENDOR_ID_AI:		
		s = "Acer Incorporated"; 
		break;
	case PCI_VENDOR_ID_MATROX:	
		s = "Matrox"; 
		break;
	case PCI_VENDOR_ID_CT:		
		s = "Chips & Technologies"; 
		break;
	case PCI_VENDOR_ID_MIRO:		
		s = "Miro"; 
		break;
	case PCI_VENDOR_ID_NEC:		
		s = "NEC"; 
		break;
	case PCI_VENDOR_ID_FD:		
		s = "Future Domain"; 
		break;
	case PCI_VENDOR_ID_SI:		
		s = "Silicon Integrated Systems"; 
		break;
	case PCI_VENDOR_ID_HP:		
		s = "Hewlett Packard"; 
		break;
	case PCI_VENDOR_ID_PCTECH:	
		s = "PCTECH"; 
		break;
	case PCI_VENDOR_ID_DPT:		
		s = "DPT"; 
		break;
	case PCI_VENDOR_ID_OPTI:		
		s = "OPTi"; 
		break;
	case PCI_VENDOR_ID_SGS:		
		s = "SGS Thomson"; 
		break;
	case PCI_VENDOR_ID_BUSLOGIC:	
		s = "BusLogic"; 
		break;
	case PCI_VENDOR_ID_TI:		
		s = "Texas Instruments"; 
		break;
	case PCI_VENDOR_ID_OAK: 		
		s = "OAK"; 
		break;
	case PCI_VENDOR_ID_WINBOND2:	
		s = "Winbond"; 
		break;
	case PCI_VENDOR_ID_MOTOROLA:	
		s = "Motorola"; 
		break;
	case PCI_VENDOR_ID_MOTOROLA_OOPS:	
		s = "Motorola"; 
		break;
	case PCI_VENDOR_ID_PROMISE:	
		s = "Promise Technology"; 
		break;
	case PCI_VENDOR_ID_N9:		
		s = "Number Nine"; 
		break;
	case PCI_VENDOR_ID_UMC:		
		s = "UMC"; 
		break;
	case PCI_VENDOR_ID_X:		
		s = "X TECHNOLOGY"; 
		break;
	case PCI_VENDOR_ID_MYLEX:		
		s = "Mylex"; 
		break;
	case PCI_VENDOR_ID_PICOP:		
		s = "PicoPower"; 
		break;
	case PCI_VENDOR_ID_APPLE:		
		s = "Apple"; 
		break;
	case PCI_VENDOR_ID_NEXGEN:	
		s = "Nexgen"; 
		break;
	case PCI_VENDOR_ID_QLOGIC:	
		s = "Q Logic"; 
		break;
	case PCI_VENDOR_ID_CYRIX:		
		s = "Cyrix"; 
		break;
	case PCI_VENDOR_ID_LEADTEK:	
		s = "Leadtek Research"; 
		break;
	case PCI_VENDOR_ID_CONTAQ:	
		s = "Contaq"; 
		break;
	case PCI_VENDOR_ID_FOREX:		
		s = "Forex"; 
		break;
	case PCI_VENDOR_ID_OLICOM:	
		s = "Olicom"; 
		break;
	case PCI_VENDOR_ID_SUN:		
		s = "Sun Microsystems"; 
		break;
	case PCI_VENDOR_ID_CMD:		
		s = "CMD"; 
		break;
	case PCI_VENDOR_ID_VISION:	
		s = "Vision"; 
		break;
	case PCI_VENDOR_ID_BROOKTREE:	
		s = "Brooktree"; 
		break;
	case PCI_VENDOR_ID_SIERRA:	
		s = "Sierra"; 
		break;
	case PCI_VENDOR_ID_ACC:		
		s = "ACC MICROELECTRONICS"; 
		break;
	case PCI_VENDOR_ID_WINBOND:	
		s = "Winbond"; 
		break;
	case PCI_VENDOR_ID_DATABOOK:	
		s = "Databook"; 
		break;
	case PCI_VENDOR_ID_PLX:		
		s = "PLX"; 
		break;
	case PCI_VENDOR_ID_MADGE:		
		s = "Madge Networks"; 
		break;
	case PCI_VENDOR_ID_3COM:		
		s = "3Com"; 
		break;
	case PCI_VENDOR_ID_SMC:		
		s = "SMC"; 
		break;
	case PCI_VENDOR_ID_AL:		
		s = "Acer Labs"; 
		break;
	case PCI_VENDOR_ID_MITSUBISHI:	
		s = "Mitsubishi"; 
		break;
	case PCI_VENDOR_ID_SURECOM:	
		s = "Surecom"; 
		break;
	case PCI_VENDOR_ID_NEOMAGIC:	
		s = "Neomagic"; 
		break;
	case PCI_VENDOR_ID_ASP:		
		s = "Advanced System Products"; 
		break;
	case PCI_VENDOR_ID_MACRONIX:	
		s = "Macronix"; 
		break;
	case PCI_VENDOR_ID_CERN:		
		s = "CERN"; 
		break;
	case PCI_VENDOR_ID_NVIDIA:	
		s = "NVidia"; 
		break;
	case PCI_VENDOR_ID_IMS:		
		s = "IMS"; 
		break;
	case PCI_VENDOR_ID_TEKRAM2:	
		s = "Tekram"; 
		break;
	case PCI_VENDOR_ID_TUNDRA:	
		s = "Tundra"; 
		break;
	case PCI_VENDOR_ID_AMCC:		
		s = "AMCC"; 
		break;
	case PCI_VENDOR_ID_INTERG:	
		s = "Intergraphics"; 
		break;
	case PCI_VENDOR_ID_REALTEK:	
		s = "Realtek"; 
		break;
	case PCI_VENDOR_ID_TRUEVISION:	
		s = "Truevision"; 
		break;
	case PCI_VENDOR_ID_INIT:		
		s = "Initio Corp"; 
		break;
	case PCI_VENDOR_ID_TTI:		
		s = "Triones Technologies, Inc."; 
		break;
	case PCI_VENDOR_ID_VIA:		
		s = "VIA Technologies"; 
		break;
	case PCI_VENDOR_ID_SMC2:		
		s = "SMC"; 
		break;
	case PCI_VENDOR_ID_VORTEX:	
		s = "VORTEX"; 
		break;
	case PCI_VENDOR_ID_EF:		
		s = "Efficient Networks"; 
		break;
	case PCI_VENDOR_ID_FORE:		
		s = "Fore Systems"; 
		break;
	case PCI_VENDOR_ID_IMAGINGTECH:	
		s = "Imaging Technology"; 
		break;
	case PCI_VENDOR_ID_PHILIPS:	
		s = "Philips"; 
		break;
	case PCI_VENDOR_ID_CYCLONE:	
		s = "Cyclone"; 
		break;
	case PCI_VENDOR_ID_ALLIANCE:	
		s = "Alliance"; 
		break;
	case PCI_VENDOR_ID_VMIC:		
		s = "VMIC"; 
		break;
	case PCI_VENDOR_ID_DIGI:		
		s = "Digi Intl."; 
		break;
	case PCI_VENDOR_ID_MUTECH:	
		s = "Mutech"; 
		break;
	case PCI_VENDOR_ID_RENDITION:	
		s = "Rendition"; 
		break;
	case PCI_VENDOR_ID_TOSHIBA:	
		s = "Toshiba"; 
		break;
	case PCI_VENDOR_ID_RICOH:		
		s = "Ricoh"; 
		break;
	case PCI_VENDOR_ID_ARTOP:		
		s = "Artop Electronics"; 
		break;
	case PCI_VENDOR_ID_ZEITNET:	
		s = "ZeitNet"; 
		break;
	case PCI_VENDOR_ID_OMEGA:		
		s = "Omega Micro"; 
		break;
	case PCI_VENDOR_ID_LITEON:	
		s = "LiteOn"; 
		break;
	case PCI_VENDOR_ID_NP:		
		s = "Network Peripherals"; 
		break;
	case PCI_VENDOR_ID_ATT:		
		s = "Lucent (ex-AT&T) Microelectronics"; 
		break;
	case PCI_VENDOR_ID_SPECIALIX:	
		s = "Specialix"; 
		break;
	case PCI_VENDOR_ID_AURAVISION:	
		s = "Auravision"; 
		break;
	case PCI_VENDOR_ID_IKON:		
		s = "Ikon"; 
		break;
	case PCI_VENDOR_ID_ZORAN:		
		s = "Zoran"; 
		break;
	case PCI_VENDOR_ID_KINETIC:	
		s = "Kinetic"; 
		break;
	case PCI_VENDOR_ID_COMPEX:	
		s = "Compex"; 
		break;
	case PCI_VENDOR_ID_RP:		
		s = "Comtrol"; 
		break;
	case PCI_VENDOR_ID_CYCLADES:	
		s = "Cyclades"; 
		break;
	case PCI_VENDOR_ID_ESSENTIAL:	
		s = "Essential Communications"; 
		break;
	case PCI_VENDOR_ID_O2:		
		s = "O2 Micro"; 
		break;
	case PCI_VENDOR_ID_3DFX:		
		s = "3Dfx"; 
		break;
	case PCI_VENDOR_ID_SIGMADES:	
		s = "Sigma Designs"; 
		break;
	case PCI_VENDOR_ID_AVM:		
		s = "AVM"; 
		break;
	case PCI_VENDOR_ID_CCUBE:		
		s = "C-Cube"; 
		break;
	case PCI_VENDOR_ID_DIPIX:		
		s = "Dipix"; 
		break;
	case PCI_VENDOR_ID_STALLION:	
		s = "Stallion Technologies"; 
		break;
	case PCI_VENDOR_ID_OPTIBASE:	
		s = "Optibase"; 
		break;
	case PCI_VENDOR_ID_SATSAGEM:	
		s = "SatSagem"; 
		break;
	case PCI_VENDOR_ID_HUGHES:	
		s = "Hughes"; 
		break;
	case PCI_VENDOR_ID_ENSONIQ:	
		s = "Ensoniq"; 
		break;
	case PCI_VENDOR_ID_ALTEON:	
		s = "Alteon"; 
		break;
	case PCI_VENDOR_ID_PICTUREL:	
		s = "Picture Elements"; 
		break;
	case PCI_VENDOR_ID_NVIDIA_SGS:	
		s = "NVidia/SGS Thomson"; 
		break;
	case PCI_VENDOR_ID_CBOARDS:	
		s = "ComputerBoards"; 
		break;
	case PCI_VENDOR_ID_TIMEDIA:	
		s = "Timedia Technology"; 
		break;
	case PCI_VENDOR_ID_SYMPHONY:	
		s = "Symphony"; 
		break;
	case PCI_VENDOR_ID_COMPUTONE:	
		s = "Computone Corporation"; 
		break;
	case PCI_VENDOR_ID_TEKRAM:	
		s = "Tekram"; 
		break;
	case PCI_VENDOR_ID_3DLABS:	
		s = "3Dlabs"; 
		break;
	case PCI_VENDOR_ID_AVANCE:	
		s = "Avance"; 
		break;
	case PCI_VENDOR_ID_NETVIN:	
		s = "NetVin"; 
		break;
	case PCI_VENDOR_ID_S3:		
		s = "S3 Inc."; 
		break;
	case PCI_VENDOR_ID_DCI:		
		s = "Decision Computer Int."; 
		break;
	case PCI_VENDOR_ID_GENROCO:	
		s = "Genroco"; 
		break;
	case PCI_VENDOR_ID_INTEL:		
		s = "Intel"; 
		break;
	case PCI_VENDOR_ID_KTI:		
		s = "KTI"; 
		break;
	case PCI_VENDOR_ID_ADAPTEC:	
		s = "Adaptec"; 
		break;
	case PCI_VENDOR_ID_ADAPTEC2:	
		s = "Adaptec"; 
		break;
	case PCI_VENDOR_ID_ATRONICS:	
		s = "Atronics"; 
		break;
	case PCI_VENDOR_ID_TIGERJET:	
		s = "TigerJet"; 
		break;
	case PCI_VENDOR_ID_ARK:		
		s = "ARK Logic"; 
		break;
	case PCI_VENDOR_ID_SYSKONNECT:	
		s = "SysKonnect"; 
		break;

        default:				
		sprintf(buf, "[PCI_VENDOR %x]", vendor); 
		s = buf;
		break;
	}

	return s;
}


static const char *
pci_strdev(unsigned int vendor, unsigned int device, char *buf)
{
	struct pci_dev_info *info;

	if ((info = pci_lookup_dev(vendor, device)))
		return info->name;
	else {
		sprintf(buf, "[PCI_DEVICE %x]", device);
		return buf;
	}
}

/*
 * If the disk's name is started with these strings, we will skip it and do not
 * display its statistics.
 */
static char *skipped_disk_name[] = {
	"ram",
	"loop",
	NULL
};

static int 
is_skipped_disk(char *name)
{
	char **p = skipped_disk_name;

	while (*p) {
		if (strncmp(name, *p, strlen(*p)) == 0)
			return TRUE;
		p++;
	}

	return FALSE;
}

struct diskio {
    int read;
    int write;
};

struct iter {
	/* If the kernel uses klist, the address should be klist.k_list */
	long head_address;
	long current_address;
	long type_address; /* the address of symbol "disk_type" */

	/*
	 * If it is true, it means request_list.count[2] contains async/sync
	 * requests.
	 */
	int sync_count;
	int diskname_len;

	unsigned long (*next_disk)(struct iter *);

	/*
	 * The argument is the address of request_queue, and the function
	 * returns the total requests in the driver(not ended)
	 */
	unsigned int (*get_in_flight)(unsigned long);

	/*
	 * this function reads request_list.count[2], and the first argument
	 * is the address of request_queue.
	 */
	void (*get_diskio)(unsigned long , unsigned long, struct diskio *);

	/*
	 * check if device.type == &disk_type
	 *
	 * old kernel(version <= 2.6.24) does not have the symbol "disk_type",
	 * and this callback should be null.
	 */
	int (*match)(struct iter *, unsigned long);

	/*
	 * If the kernel uses list, the argument is the address of list_head,
	 * otherwise, the argument is the address of klist_node.
	 */
	unsigned long (*get_gendisk)(unsigned long);
};

/* kernel version <= 2.6.24 */
static unsigned long 
get_gendisk_1(unsigned long entry)
{
	return entry - OFFSET(kobject_entry) - OFFSET(gendisk_kobj);
}

/* 2.6.24 < kernel version <= 2.6.27 */
static unsigned long 
get_gendisk_2(unsigned long entry)
{
	return entry - OFFSET(device_node) - OFFSET(gendisk_dev);
}

/* kernel version > 2.6.27 && struct gendisk contains dev/__dev */
static unsigned long 
get_gendisk_3(unsigned long entry)
{
	return entry - OFFSET(device_knode_class) - OFFSET(gendisk_dev);
}

/* kernel version > 2.6.27 && struct gendisk does not contain dev/__dev */
static unsigned long 
get_gendisk_4(unsigned long entry)
{
	return entry - OFFSET(device_knode_class) - OFFSET(hd_struct_dev) -
		OFFSET(gendisk_part0);
}

/* kernel version >= 5.1 */
static unsigned long
get_gendisk_5(unsigned long entry)
{
	unsigned long device_address;
	unsigned long device_private_address;
	unsigned long gendisk;

	device_private_address = entry - OFFSET(device_private_knode_class);
	readmem(device_private_address + OFFSET(device_private_device),
		KVADDR, &device_address, sizeof(device_address),
		"device_private.device", FAULT_ON_ERROR);

	if (VALID_MEMBER(hd_struct_dev))
		return device_address - OFFSET(hd_struct_dev) - OFFSET(gendisk_part0);

	/* kernel version >= 5.11 */
	readmem(device_address - OFFSET(block_device_bd_device) +
		OFFSET(block_device_bd_disk), KVADDR, &gendisk,
		sizeof(ulong), "block_device.bd_disk", FAULT_ON_ERROR);

	return gendisk;
}

/* 2.6.24 < kernel version <= 2.6.27 */
static int 
match_list(struct iter *i, unsigned long entry)
{
	unsigned long device_address;
	unsigned long device_type;

	device_address = entry - OFFSET(device_node);
	readmem(device_address + OFFSET(device_type), KVADDR, &device_type,
		sizeof(device_type), "device.type", FAULT_ON_ERROR);
	if (device_type != i->type_address)
		return FALSE;

	return TRUE;
}

/* kernel version > 2.6.27 */
static int 
match_klist(struct iter *i, unsigned long entry)
{
	unsigned long device_address;
	unsigned long device_type;
	unsigned long device_private_address;

	if (VALID_MEMBER(device_knode_class))
		device_address = entry - OFFSET(device_knode_class);
	else {
		/* kernel version >= 5.1 */
		device_private_address = entry -
			OFFSET(device_private_knode_class);
		readmem(device_private_address + OFFSET(device_private_device),
			KVADDR, &device_address, sizeof(device_address),
			"device_private.device", FAULT_ON_ERROR);
	}
	readmem(device_address + OFFSET(device_type), KVADDR, &device_type,
		sizeof(device_type), "device.type", FAULT_ON_ERROR);
	if (device_type != i->type_address)
		return FALSE;

	return TRUE;
}

/* old kernel(version <= 2.6.27): list */
static unsigned long 
next_disk_list(struct iter *i)
{
	unsigned long list_head_address, next_address;

	if (i->current_address) {
		list_head_address = i->current_address;
	} else {
		list_head_address = i->head_address;
	}

again:
	/* read list_head.next */
	readmem(list_head_address + OFFSET(list_head_next), KVADDR,
		&next_address, sizeof(next_address), "list_head.next",
		FAULT_ON_ERROR);

	if (next_address == i->head_address)
		return 0;

	if (i->match && !i->match(i, next_address)) {
		list_head_address = next_address;
		goto again;
	}

	i->current_address = next_address;
	return i->get_gendisk(next_address);
}

/* new kernel(version > 2.6.27): klist */
static unsigned long 
next_disk_klist(struct iter* i)
{
	unsigned long klist_node_address, list_head_address, next_address;
	unsigned long n_klist;

	if (i->current_address) {
		list_head_address = i->current_address;
	} else {
		list_head_address = i->head_address;
	}

again:
	/* read list_head.next */
	readmem(list_head_address + OFFSET(list_head_next), KVADDR,
		&next_address, sizeof(next_address), "list_head.next",
		FAULT_ON_ERROR);

	/* skip dead klist_node */
	while(next_address != i->head_address) {
		klist_node_address = next_address - OFFSET(klist_node_n_node);
		readmem(klist_node_address + OFFSET(klist_node_n_klist), KVADDR,
			&n_klist, sizeof(n_klist), "klist_node.n_klist",
			FAULT_ON_ERROR);
		if (!(n_klist & 1))
			break;

		/* the klist_node is dead, skip to next klist_node */
		readmem(next_address + OFFSET(list_head_next), KVADDR,
			&next_address, sizeof(next_address), "list_head.next",
			FAULT_ON_ERROR);
	}

	if (next_address == i->head_address)
		return 0;

	if (i->match && !i->match(i, klist_node_address)) {
		list_head_address = next_address;
		goto again;
	}

	i->current_address = next_address;
	return i->get_gendisk(klist_node_address);
}

static int
use_mq_interface(unsigned long q)
{
	unsigned long mq_ops;

	if (!VALID_MEMBER(request_queue_mq_ops))
		return 0;

	readmem(q + OFFSET(request_queue_mq_ops), KVADDR, &mq_ops,
		sizeof(ulong), "request_queue.mq_ops", FAULT_ON_ERROR);

	if (mq_ops == 0)
		return 0;
	else
		return 1;
}

static void
get_one_mctx_diskio(unsigned long mctx, struct diskio *io)
{
	unsigned long dispatch[2];
	unsigned long comp[2];

	readmem(mctx + OFFSET(blk_mq_ctx_rq_dispatched),
		KVADDR, dispatch, sizeof(ulong) * 2, "blk_mq_ctx.rq_dispatched",
		FAULT_ON_ERROR);

	readmem(mctx + OFFSET(blk_mq_ctx_rq_completed),
		KVADDR, comp, sizeof(ulong) * 2, "blk_mq_ctx.rq_completed",
		FAULT_ON_ERROR);

	io->read = (dispatch[0] - comp[0]);
	io->write = (dispatch[1] - comp[1]);
}

typedef bool (busy_tag_iter_fn)(ulong rq, void *data);

struct mq_inflight {
	ulong q;
	struct diskio *dio;
};

struct bt_iter_data {
	ulong tags;
	uint reserved;
	uint nr_reserved_tags;
	busy_tag_iter_fn *fn;
	void *data;
};

/*
 * See the include/linux/blk_types.h and include/linux/blk-mq.h
 */
#define MQ_RQ_IN_FLIGHT 1
#define REQ_OP_BITS     8
#define REQ_OP_MASK     ((1 << REQ_OP_BITS) - 1)

static uint op_is_write(uint op)
{
	return (op & REQ_OP_MASK) & 1;
}

static bool mq_check_inflight(ulong rq, void *data)
{
	uint cmd_flags = 0, state = 0;
	ulong addr = 0, queue = 0;
	struct mq_inflight *mi = data;

	if (!IS_KVADDR(rq))
		return TRUE;

	addr = rq + OFFSET(request_q);
	if (!readmem(addr, KVADDR, &queue, sizeof(ulong), "request.q", RETURN_ON_ERROR))
		return FALSE;

	addr = rq + OFFSET(request_cmd_flags);
	if (!readmem(addr, KVADDR, &cmd_flags, sizeof(uint), "request.cmd_flags", RETURN_ON_ERROR))
		return FALSE;

	addr = rq + OFFSET(request_state);
	if (!readmem(addr, KVADDR, &state, sizeof(uint), "request.state", RETURN_ON_ERROR))
		return FALSE;

	if (queue == mi->q && state == MQ_RQ_IN_FLIGHT) {
		if (op_is_write(cmd_flags))
			mi->dio->write++;
		else
			mi->dio->read++;
	}

	return TRUE;
}

static bool bt_iter(uint bitnr, void *data)
{
	ulong addr = 0, rqs_addr = 0, rq = 0;
	struct bt_iter_data *iter_data = data;
	ulong tag = iter_data->tags;

	if (!iter_data->reserved)
		bitnr += iter_data->nr_reserved_tags;

	/* rqs */
	addr = tag + OFFSET(blk_mq_tags_rqs);
	if (!readmem(addr, KVADDR, &rqs_addr, sizeof(void *), "blk_mq_tags.rqs", RETURN_ON_ERROR))
		return FALSE;

	addr = rqs_addr + bitnr * sizeof(ulong); /* rqs[bitnr] */
	if (!readmem(addr, KVADDR, &rq, sizeof(ulong), "blk_mq_tags.rqs[]", RETURN_ON_ERROR))
		return FALSE;

	return iter_data->fn(rq, iter_data->data);
}

static void bt_for_each(ulong q, ulong tags, ulong sbq, uint reserved, uint nr_resvd_tags, struct diskio *dio)
{
	struct sbitmap_context sc = {0};
	struct mq_inflight mi = {
		.q = q,
		.dio = dio,
	};
	struct bt_iter_data iter_data = {
		.tags = tags,
		.reserved = reserved,
		.nr_reserved_tags = nr_resvd_tags,
		.fn = mq_check_inflight,
		.data = &mi,
	};

	sbitmap_context_load(sbq + OFFSET(sbitmap_queue_sb), &sc);
	sbitmap_for_each_set(&sc, bt_iter, &iter_data);
}

static void queue_for_each_hw_ctx(ulong q, ulong *hctx, uint cnt, struct diskio *dio)
{
	uint i;
	int bitmap_tags_is_ptr = 0;

	if (MEMBER_TYPE("blk_mq_tags", "bitmap_tags") == TYPE_CODE_PTR)
		bitmap_tags_is_ptr = 1;

	for (i = 0; i < cnt; i++) {
		ulong addr = 0, tags = 0;
		uint nr_reserved_tags = 0;

		/* Tags owned by the block driver */
		addr = hctx[i] + OFFSET(blk_mq_hw_ctx_tags);
		if (!readmem(addr, KVADDR, &tags, sizeof(ulong),
				"blk_mq_hw_ctx.tags", RETURN_ON_ERROR))
			break;

		addr = tags + OFFSET(blk_mq_tags_nr_reserved_tags);
		if (!readmem(addr, KVADDR, &nr_reserved_tags, sizeof(uint),
				"blk_mq_tags_nr_reserved_tags", RETURN_ON_ERROR))
			break;

		if (nr_reserved_tags) {
			addr = tags + OFFSET(blk_mq_tags_breserved_tags);
			if (bitmap_tags_is_ptr &&
			    !readmem(addr, KVADDR, &addr, sizeof(ulong),
					"blk_mq_tags.bitmap_tags", RETURN_ON_ERROR))
				break;
			bt_for_each(q, tags, addr, 1, nr_reserved_tags, dio);
		}
		addr = tags + OFFSET(blk_mq_tags_bitmap_tags);
		if (bitmap_tags_is_ptr &&
		    !readmem(addr, KVADDR, &addr, sizeof(ulong),
				"blk_mq_tags.bitmap_tags", RETURN_ON_ERROR))
			break;
		bt_for_each(q, tags, addr, 0, nr_reserved_tags, dio);
	}
}

static void get_mq_diskio_from_hw_queues(ulong q, struct diskio *dio)
{
	uint cnt = 0;
	ulong addr = 0, hctx_addr = 0;
	ulong *hctx_array = NULL;
	struct list_pair *lp = NULL;

	if (VALID_MEMBER(request_queue_hctx_table)) {
		addr = q + OFFSET(request_queue_hctx_table);
		cnt = do_xarray(addr, XARRAY_COUNT, NULL);
		lp = (struct list_pair *)GETBUF(sizeof(struct list_pair) * (cnt + 1));
		if (!lp)
			error(FATAL, "fail to get memory for list_pair.\n");
		lp[0].index = cnt;
		cnt = do_xarray(addr, XARRAY_GATHER, lp);
	} else {
		addr = q + OFFSET(request_queue_nr_hw_queues);
		readmem(addr, KVADDR, &cnt, sizeof(uint),
			"request_queue.nr_hw_queues", FAULT_ON_ERROR);

		addr = q + OFFSET(request_queue_queue_hw_ctx);
		readmem(addr, KVADDR, &hctx_addr, sizeof(void *),
			"request_queue.queue_hw_ctx", FAULT_ON_ERROR);
	}

	hctx_array = (ulong *)GETBUF(sizeof(void *) * cnt);
	if (!hctx_array) {
		if (lp)
			FREEBUF(lp);
		error(FATAL, "fail to get memory for the hctx_array\n");
	}

	if (lp && hctx_array) {
		uint i;

		/* copy it from list_pair to hctx_array */
		for (i = 0; i < cnt; i++)
			hctx_array[i] = (ulong)lp[i].value;

		FREEBUF(lp);
	} else if (!readmem(hctx_addr, KVADDR, hctx_array, sizeof(void *) * cnt,
			"request_queue.queue_hw_ctx[]", RETURN_ON_ERROR)) {
		FREEBUF(hctx_array);
		return;
	}

	queue_for_each_hw_ctx(q, hctx_array, cnt, dio);

	FREEBUF(hctx_array);
}

static void
get_mq_diskio(unsigned long q, unsigned long *mq_count)
{
	int cpu;
	unsigned long queue_ctx;
	unsigned long mctx_addr;
	struct diskio tmp = {0};

	/*
	 * Currently this function does not support old blk-mq implementation
	 * before 12f5b9314545 ("blk-mq: Remove generation seqeunce"), so
	 * filter them out.
	 */
	if (VALID_MEMBER(request_state)) {
		if (CRASHDEBUG(1))
			fprintf(fp, "mq: using sbitmap\n");
		get_mq_diskio_from_hw_queues(q, &tmp);
		mq_count[0] = tmp.read;
		mq_count[1] = tmp.write;
		return;
	}

	if (CRASHDEBUG(1))
		fprintf(fp, "mq: using blk_mq_ctx.rq_{completed,dispatched} counters\n");

	readmem(q + OFFSET(request_queue_queue_ctx), KVADDR, &queue_ctx,
		sizeof(ulong), "request_queue.queue_ctx",
		FAULT_ON_ERROR);

	for (cpu = 0; cpu < kt->cpus; cpu++) {
		if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF)) {
			mctx_addr = queue_ctx + kt->__per_cpu_offset[cpu];
			get_one_mctx_diskio(mctx_addr, &tmp);
			mq_count[0] += tmp.read;
			mq_count[1] += tmp.write;
		}
	}
}

static void
get_one_diskio_from_dkstats(unsigned long dkstats, unsigned long *count)
{
	int cpu;
	unsigned long dkstats_addr;
	unsigned long in_flight[2];

	for (cpu = 0; cpu < kt->cpus; cpu++) {
		if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF)) {
			dkstats_addr = dkstats + kt->__per_cpu_offset[cpu];
			readmem(dkstats_addr + OFFSET(disk_stats_in_flight),
				KVADDR, in_flight, sizeof(long) * 2,
				"disk_stats.in_flight", FAULT_ON_ERROR);
			count[0] += in_flight[0];
			count[1] += in_flight[1];
		}
	}
}


/* read request_queue.rq.count[2] */
static void 
get_diskio_1(unsigned long rq, unsigned long gendisk, struct diskio *io)
{
	int count[2];
	unsigned long io_counts[2] = { 0 };
	unsigned long dkstats;

	if (!use_mq_interface(rq)) {
		if (VALID_MEMBER(request_queue_rq)) {
			readmem(rq + OFFSET(request_queue_rq) +
				OFFSET(request_list_count), KVADDR, count,
				sizeof(int) * 2, "request_list.count", FAULT_ON_ERROR);

			io->read = count[0];
			io->write = count[1];
		} else {
			if (VALID_MEMBER(hd_struct_dkstats))
				readmem(gendisk + OFFSET(gendisk_part0) +
					OFFSET(hd_struct_dkstats), KVADDR, &dkstats,
					sizeof(ulong), "gendisk.part0.dkstats", FAULT_ON_ERROR);
			else { /* kernel version >= 5.11 */
				ulong block_device;
				readmem(gendisk + OFFSET(gendisk_part0), KVADDR, &block_device,
					sizeof(ulong), "gendisk.part0", FAULT_ON_ERROR);
				readmem(block_device + OFFSET(block_device_bd_stats), KVADDR,
					&dkstats, sizeof(ulong), "block_device.bd_stats",
					FAULT_ON_ERROR);
			}

			get_one_diskio_from_dkstats(dkstats, io_counts);

			io->read = io_counts[0];
			io->write = io_counts[1];
		}
	} else {
		get_mq_diskio(rq, io_counts);
		io->read = io_counts[0];
		io->write = io_counts[1];
	}
}

/* request_queue.in_flight contains total requests */
static unsigned int 
get_in_flight_1(unsigned long rq)
{
	unsigned int in_flight;

	readmem(rq+ OFFSET(request_queue_in_flight), KVADDR, &in_flight,
		sizeof(uint), "request_queue.in_flight", FAULT_ON_ERROR);
	return in_flight;
}

/* request_queue.in_flight[2] contains read/write requests */
static unsigned int 
get_in_flight_2(unsigned long rq)
{
	unsigned int in_flight[2];

	readmem(rq+ OFFSET(request_queue_in_flight), KVADDR, in_flight,
		sizeof(uint) * 2, "request_queue.in_flight", FAULT_ON_ERROR);
	return in_flight[0] + in_flight[1];
}

static void 
init_iter(struct iter *i)
{
	ARRAY_LENGTH_INIT(i->diskname_len, gendisk.disk_name,
		"gendisk.disk_name", NULL, sizeof(char));
	if (i->diskname_len < 0 || i->diskname_len > BUFSIZE) {
		option_not_supported('d');
		return;
	}

	i->current_address = 0;

	/* check whether BLK_RW_SYNC exists */
	i->sync_count =
		get_symbol_type("BLK_RW_SYNC", NULL, NULL) == TYPE_CODE_ENUM;

	if (SIZE(rq_in_flight) == sizeof(int)) {
		i->get_in_flight = get_in_flight_1;
	} else if (SIZE(rq_in_flight) == sizeof(int) * 2) {
		i->get_in_flight = get_in_flight_2;
	}
	i->get_diskio = get_diskio_1;

	if (symbol_exists("block_subsys") || symbol_exists("block_kset")) {
		/* kernel version <= 2.6.24 */
		unsigned long block_subsys_addr;

		if (symbol_exists("block_subsys"))
			block_subsys_addr = symbol_value("block_subsys");
		else
			block_subsys_addr = symbol_value("block_kset");
		if (VALID_STRUCT(subsystem))
			i->head_address = block_subsys_addr +
				OFFSET(subsystem_kset) + OFFSET(kset_list);
		else
			i->head_address = block_subsys_addr + OFFSET(kset_list);
		i->type_address = 0;
		i->next_disk = next_disk_list;
		i->match = NULL;
		i->get_gendisk = get_gendisk_1;
	} else if (symbol_exists("block_class")) {
		unsigned long block_class_addr = symbol_value("block_class");

		i->type_address = symbol_value("disk_type");
		if (VALID_MEMBER(class_devices) ||
		   (VALID_MEMBER(class_private_devices) &&
		      SIZE(class_private_devices) == SIZE(list_head))) {
			/* 2.6.24 < kernel version <= 2.6.27, list */
			if (!VALID_STRUCT(class_private)) {
				/* 2.6.24 < kernel version <= 2.6.26 */
				i->head_address = block_class_addr +
					OFFSET(class_devices);
			} else {
				/* kernel version is 2.6.27 */
				unsigned long class_private_addr;

				readmem(block_class_addr + OFFSET(class_p),
					KVADDR, &class_private_addr,
					sizeof(class_private_addr), "class.p",
					FAULT_ON_ERROR);
				i->head_address = class_private_addr +
					OFFSET(class_private_devices);
			}
			i->next_disk = next_disk_list;
			i->match = match_list;
			i->get_gendisk = get_gendisk_2;
		} else {
			/* kernel version > 2.6.27, klist */
			unsigned long class_private_addr;
			readmem(block_class_addr + OFFSET(class_p), KVADDR,
				&class_private_addr, sizeof(class_private_addr),
				"class.p", FAULT_ON_ERROR);

			if (VALID_STRUCT(class_private)) {
				/* 2.6.27 < kernel version <= 2.6.37-rc2 */
				i->head_address = class_private_addr +
					OFFSET(class_private_devices);
			} else {
				/* kernel version > 2.6.37-rc2 */
				i->head_address = class_private_addr +
					OFFSET(subsys_private_klist_devices);
			}
			i->head_address += OFFSET(klist_k_list);
			i->next_disk = next_disk_klist;
			i->match = match_klist;
			if (VALID_MEMBER(gendisk_dev))
				i->get_gendisk = get_gendisk_3;
			else if (VALID_MEMBER(device_knode_class))
				i->get_gendisk = get_gendisk_4;
			else
				i->get_gendisk = get_gendisk_5;
		}
	} else {
		option_not_supported('d');
		return;
	}
}

static void 
display_one_diskio(struct iter *i, unsigned long gendisk, ulong flags)
{
	char disk_name[BUFSIZE + 1];
	char buf0[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char buf5[BUFSIZE];
	int major;
	unsigned long queue_addr;
	unsigned int in_flight;
	struct diskio io;

	memset(disk_name, 0, BUFSIZE + 1);
	readmem(gendisk + OFFSET(gendisk_disk_name), KVADDR, disk_name,
		i->diskname_len, "gen_disk.disk_name", FAULT_ON_ERROR);
	if (is_skipped_disk(disk_name))
		return;

	readmem(gendisk + OFFSET(gendisk_queue), KVADDR, &queue_addr,
		sizeof(ulong), "gen_disk.queue", FAULT_ON_ERROR);
	readmem(gendisk + OFFSET(gendisk_major), KVADDR, &major, sizeof(int),
		"gen_disk.major", FAULT_ON_ERROR);
	i->get_diskio(queue_addr, gendisk, &io);

	if ((flags & DIOF_NONZERO)
		&& (io.read + io.write == 0))
		return;

	fprintf(fp, "%s%s%s  %s%s%s%s  %s%5d%s%s%s%s%s",
		mkstring(buf0, 5, RJUST|INT_DEC, (char *)(unsigned long)major),
		space(MINSPACE),
		mkstring(buf1, VADDR_PRLEN, LJUST|LONG_HEX, (char *)gendisk),
		space(MINSPACE),
		mkstring(buf2, 10, LJUST, disk_name),
		space(MINSPACE),
		mkstring(buf3, VADDR_PRLEN <= 11 ? 11 : VADDR_PRLEN,
			 LJUST|LONG_HEX, (char *)queue_addr),
		space(MINSPACE),
		io.read + io.write,
		space(MINSPACE),
		mkstring(buf4, 5, RJUST|INT_DEC,
			(char *)(unsigned long)io.read),
		space(MINSPACE),
		mkstring(buf5, 5, RJUST|INT_DEC,
			(char *)(unsigned long)io.write),
		space(MINSPACE));

	if (VALID_MEMBER(request_queue_in_flight)) {
		if (!use_mq_interface(queue_addr)) {
			in_flight = i->get_in_flight(queue_addr);
			fprintf(fp, "%5u\n", in_flight);
		} else
			fprintf(fp, "%s\n", "N/A(MQ)");
	} else
		fprintf(fp, "\n");
}

static void 
display_all_diskio(ulong flags)
{
	struct iter i;
	unsigned long gendisk;
	char buf0[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char buf5[BUFSIZE];

	init_iter(&i);

	fprintf(fp, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
		"MAJOR",
		space(MINSPACE),
		mkstring(buf0, VADDR_PRLEN + 2, LJUST, "GENDISK"),
		space(MINSPACE),
		"NAME      ",
		space(MINSPACE),
		mkstring(buf1, VADDR_PRLEN <= 11 ? 13 : VADDR_PRLEN + 2, LJUST,
			"REQUEST_QUEUE"),
		space(MINSPACE),
		mkstring(buf2, 5, RJUST, "TOTAL"),
		space(MINSPACE),
		i.sync_count ? mkstring(buf3, 5, RJUST, "ASYNC") :
			mkstring(buf3, 5, RJUST, "READ"),
		space(MINSPACE),
		i.sync_count ? mkstring(buf4, 5, RJUST, "SYNC") :
			mkstring(buf4, 5, RJUST, "WRITE"),
		space(MINSPACE),
		VALID_MEMBER(request_queue_in_flight) ? mkstring(buf5, 5, RJUST, "DRV") : "");

	while ((gendisk = i.next_disk(&i)) != 0)
		display_one_diskio(&i, gendisk, flags);
}

static 
void diskio_init(void)
{
	if (dt->flags & DISKIO_INIT)
		return;

	MEMBER_OFFSET_INIT(class_devices, "class", "class_devices");
	if (INVALID_MEMBER(class_devices))
		MEMBER_OFFSET_INIT(class_devices, "class", "devices");
	MEMBER_OFFSET_INIT(class_p, "class", "p");
	MEMBER_OFFSET_INIT(class_private_devices, "class_private",
		"class_devices");
	MEMBER_OFFSET_INIT(device_knode_class, "device", "knode_class");
	MEMBER_OFFSET_INIT(device_node, "device", "node");
	MEMBER_OFFSET_INIT(device_type, "device", "type");
	MEMBER_OFFSET_INIT(device_private_device, "device_private", "device");
	MEMBER_OFFSET_INIT(device_private_knode_class, "device_private",
		"knode_class");
	MEMBER_OFFSET_INIT(gendisk_dev, "gendisk", "dev");
	if (INVALID_MEMBER(gendisk_dev))
		MEMBER_OFFSET_INIT(gendisk_dev, "gendisk", "__dev");
	MEMBER_OFFSET_INIT(gendisk_kobj, "gendisk", "kobj");
	MEMBER_OFFSET_INIT(gendisk_part0, "gendisk", "part0");
	MEMBER_OFFSET_INIT(gendisk_queue, "gendisk", "queue");
	MEMBER_OFFSET_INIT(hd_struct_dev, "hd_struct", "__dev");
	MEMBER_OFFSET_INIT(hd_struct_dkstats, "hd_struct", "dkstats");
	MEMBER_OFFSET_INIT(block_device_bd_device, "block_device", "bd_device");
	MEMBER_OFFSET_INIT(block_device_bd_stats, "block_device", "bd_stats");
	MEMBER_OFFSET_INIT(klist_k_list, "klist", "k_list");
	MEMBER_OFFSET_INIT(klist_node_n_klist, "klist_node", "n_klist");
	MEMBER_OFFSET_INIT(klist_node_n_node, "klist_node", "n_node");
	MEMBER_OFFSET_INIT(kobject_entry, "kobject", "entry");
	MEMBER_OFFSET_INIT(kset_list, "kset", "list");
	MEMBER_OFFSET_INIT(request_list_count, "request_list", "count");
	MEMBER_OFFSET_INIT(request_cmd_flags, "request", "cmd_flags");
	MEMBER_OFFSET_INIT(request_q, "request", "q");
	MEMBER_OFFSET_INIT(request_state, "request", "state");
	MEMBER_OFFSET_INIT(request_queue_in_flight, "request_queue",
		"in_flight");
	if (MEMBER_EXISTS("request_queue", "rq"))
		MEMBER_OFFSET_INIT(request_queue_rq, "request_queue", "rq");
	else
		MEMBER_OFFSET_INIT(request_queue_rq, "request_queue", "root_rl");
	if (MEMBER_EXISTS("request_queue", "mq_ops")) {
		MEMBER_OFFSET_INIT(request_queue_mq_ops, "request_queue",
			"mq_ops");
		ANON_MEMBER_OFFSET_INIT(request_queue_queue_ctx,
			"request_queue", "queue_ctx");
		MEMBER_OFFSET_INIT(request_queue_queue_hw_ctx,
			"request_queue", "queue_hw_ctx");
		MEMBER_OFFSET_INIT(request_queue_nr_hw_queues,
			"request_queue", "nr_hw_queues");
		MEMBER_OFFSET_INIT(request_queue_hctx_table,
			"request_queue", "hctx_table");
		MEMBER_OFFSET_INIT(blk_mq_ctx_rq_dispatched, "blk_mq_ctx",
			"rq_dispatched");
		MEMBER_OFFSET_INIT(blk_mq_ctx_rq_completed, "blk_mq_ctx",
			"rq_completed");
		MEMBER_OFFSET_INIT(blk_mq_hw_ctx_tags, "blk_mq_hw_ctx", "tags");
		MEMBER_OFFSET_INIT(blk_mq_tags_bitmap_tags, "blk_mq_tags",
			"bitmap_tags");
		MEMBER_OFFSET_INIT(blk_mq_tags_breserved_tags, "blk_mq_tags",
			"breserved_tags");
		MEMBER_OFFSET_INIT(blk_mq_tags_nr_reserved_tags, "blk_mq_tags",
			"nr_reserved_tags");
		MEMBER_OFFSET_INIT(blk_mq_tags_rqs, "blk_mq_tags", "rqs");
		STRUCT_SIZE_INIT(blk_mq_tags, "blk_mq_tags");
		STRUCT_SIZE_INIT(sbitmap, "sbitmap");
		STRUCT_SIZE_INIT(sbitmap_word, "sbitmap_word");
		MEMBER_OFFSET_INIT(sbitmap_word_word, "sbitmap_word", "word");
		MEMBER_OFFSET_INIT(sbitmap_word_cleared, "sbitmap_word", "cleared");
		MEMBER_OFFSET_INIT(sbitmap_depth, "sbitmap", "depth");
		MEMBER_OFFSET_INIT(sbitmap_shift, "sbitmap", "shift");
		MEMBER_OFFSET_INIT(sbitmap_map_nr, "sbitmap", "map_nr");
		MEMBER_OFFSET_INIT(sbitmap_map, "sbitmap", "map");
		MEMBER_OFFSET_INIT(sbitmap_queue_sb, "sbitmap_queue", "sb");

	}
	MEMBER_OFFSET_INIT(subsys_private_klist_devices, "subsys_private",
		"klist_devices");
	MEMBER_OFFSET_INIT(subsystem_kset, "subsystem", "kset");
	STRUCT_SIZE_INIT(subsystem, "subsystem");
	STRUCT_SIZE_INIT(class_private, "class_private");
	MEMBER_SIZE_INIT(rq_in_flight, "request_queue", "in_flight");
	MEMBER_SIZE_INIT(class_private_devices, "class_private",
		"class_devices");
	MEMBER_OFFSET_INIT(disk_stats_in_flight, "disk_stats", "in_flight");

	dt->flags |= DISKIO_INIT;
}

static void 
diskio_option(ulong flags)
{
	diskio_init();
	display_all_diskio(flags);
}

void
devdump_extract(void *_note, ulonglong offset, char *dump_file, FILE *ofp)
{
	struct vmcoredd_header *vh = (struct vmcoredd_header *)_note;
	ulong dump_size, count;
	FILE *tmpfp;

	if (vh->n_type != NT_VMCOREDD)
		error(FATAL, "unsupported note type: 0x%x", vh->n_type);

	dump_size = vh->n_descsz - VMCOREDD_MAX_NAME_BYTES;

	if (dump_file) {
		tmpfp = fopen(dump_file, "w");
		if (!tmpfp) {
			error(FATAL, "cannot open output file: %s\n",
			      dump_file);
			return;
		}
		set_tmpfile2(tmpfp);
	}
	fprintf(ofp, "DEVICE: %s\n", vh->dump_name);
	
	if (dump_file)
		count = dump_size;
	else 
		count = dump_size/sizeof(uint64_t) +
			(dump_size % sizeof(uint64_t) ? 1 : 0);
	
	display_memory_from_file_offset(offset + sizeof(struct vmcoredd_header),
		count, dump_file);
}

void 
devdump_info(void *_note, ulonglong offset, FILE *ofp)
{
	struct vmcoredd_header *vh = (struct vmcoredd_header *)_note;
	char buf[BUFSIZE];
	ulong dump_size;

	if (vh->n_type != NT_VMCOREDD)
		return;

	dump_size = vh->n_descsz - VMCOREDD_MAX_NAME_BYTES;
	offset += sizeof(struct vmcoredd_header);

	fprintf(ofp, "0x%s ", mkstring(buf, LONG_LONG_PRLEN, LJUST | LONGLONG_HEX,
		MKSTR(&offset)));
	fprintf(ofp, "%s ", mkstring(buf, LONG_PRLEN, LJUST | LONG_DEC,
		MKSTR(dump_size)));
	fprintf(ofp, "%s\n", vh->dump_name);
}
