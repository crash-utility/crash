/* filesys.c - core analysis suite
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002-2019 David Anderson
 * Copyright (C) 2002-2019 Red Hat, Inc. All rights reserved.
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
#include <sys/sysmacros.h>
#include <linux/major.h>
#include <regex.h>
#include <sys/utsname.h>

static void show_mounts(ulong, int, struct task_context *);
static int find_booted_kernel(void);
static int find_booted_system_map(void);
static int verify_utsname(char *);
static char **build_searchdirs(int, int *);
static int build_kernel_directory(char *);
static int redhat_kernel_directory_v1(char *);
static int redhat_kernel_directory_v2(char *);
static int redhat_debug_directory(char *);
static ulong *create_dentry_array(ulong, int *);
static ulong *create_dentry_array_percpu(ulong, int *);
static void show_fuser(char *, char *);
static int mount_point(char *);
static int open_file_reference(struct reference *);
static void memory_source_init(void);
static int get_pathname_component(ulong, ulong, int, char *, char *);
char *inode_type(char *, char *);
static void match_proc_version(void);
static void get_live_memory_source(void);
static int memory_driver_module_loaded(int *);
static int insmod_memory_driver_module(void);
static int get_memory_driver_dev(dev_t *);
static int memory_driver_init(void);
static int create_memory_device(dev_t);
static int match_file_string(char *, char *, char *);
static ulong get_root_vfsmount(char *);
static void check_live_arch_mismatch(void);
static long get_inode_nrpages(ulong);
static void dump_inode_page_cache_info(ulong);

#define DENTRY_CACHE (20)
#define INODE_CACHE  (20)
#define FILE_CACHE   (20)

static struct filesys_table {
        char *dentry_cache;
	ulong cached_dentry[DENTRY_CACHE];
	ulong cached_dentry_hits[DENTRY_CACHE];
	int dentry_cache_index;
	ulong dentry_cache_fills;

        char *inode_cache;
        ulong cached_inode[INODE_CACHE];
        ulong cached_inode_hits[INODE_CACHE];
        int inode_cache_index;
        ulong inode_cache_fills;

        char *file_cache;
        ulong cached_file[FILE_CACHE];
        ulong cached_file_hits[FILE_CACHE];
        int file_cache_index;
        ulong file_cache_fills;

} filesys_table = { 0 };


static struct filesys_table *ft = &filesys_table;

/*
 *  Open the namelist, dumpfile and output devices.
 */
void
fd_init(void)
{
	pc->nfd = pc->kfd = pc->mfd = pc->dfd = -1;

        if ((pc->nullfp = fopen("/dev/null", "w+")) == NULL)
                error(INFO, "cannot open /dev/null (for extraneous output)");

	if (REMOTE()) 
		remote_fd_init();
	else {
		if (pc->namelist && pc->namelist_debug && pc->system_map) {
			error(INFO, 
                "too many namelist options:\n       %s\n       %s\n       %s\n",
				pc->namelist, pc->namelist_debug, 
				pc->system_map);
			program_usage(SHORT_FORM);
		}

		if (pc->namelist) {
			if (XEN_HYPER_MODE() && !pc->dumpfile)
				error(FATAL, 
				    "Xen hypervisor mode requires a dumpfile\n");

			if (!pc->dumpfile && !get_proc_version())
	                	error(INFO, "/proc/version: %s\n", 
					strerror(errno));
		} else {
			if (pc->dumpfile) {
				error(INFO, "namelist argument required\n");
				program_usage(SHORT_FORM);
			}
			if (!pc->dumpfile)
				check_live_arch_mismatch();
			if (!find_booted_kernel())
	                	program_usage(SHORT_FORM);
		}
	
		if (!pc->dumpfile) {
			pc->flags |= LIVE_SYSTEM;
			get_live_memory_source();
		}
	
		if ((pc->nfd = open(pc->namelist, O_RDONLY)) < 0) 
			error(FATAL, "%s: %s\n", pc->namelist, strerror(errno));
		else {
			close(pc->nfd);
			pc->nfd = -1;
		}

		if (LOCAL_ACTIVE() && !(pc->namelist_debug || pc->system_map)) {
			memory_source_init();
			match_proc_version();
		}
	
	}

	memory_source_init();

	if (ACTIVE())
		proc_kcore_init(fp, UNUSED);

	if (CRASHDEBUG(1)) {
		fprintf(fp, "readmem: %s() ", readmem_function_name());
		if (ACTIVE()) {
			fprintf(fp, "-> %s ", pc->live_memsrc);
			if (pc->flags & MEMMOD)
				fprintf(fp, "(module)");
			else if (pc->flags & CRASHBUILTIN)
				fprintf(fp, "(built-in)");
		}
		fprintf(fp, "\n");
	}
}

/*
 *  Do whatever's necessary to handle the memory source.
 */
static void
memory_source_init(void)
{
	if (REMOTE() && !(pc->flags2 & MEMSRC_LOCAL))
		return;

	if (pc->flags & KERNEL_DEBUG_QUERY)
		return;

        if (LOCAL_ACTIVE()) {
		if (pc->mfd != -1)  /* already been here */
			return;

		if (!STREQ(pc->live_memsrc, "/dev/mem") &&
		     STREQ(pc->live_memsrc, pc->memory_device)) {
			if (memory_driver_init())
				return;

			error(INFO, "cannot initialize crash memory driver\n");
			error(INFO, "using /dev/mem\n\n");
			pc->flags &= ~MEMMOD;
			pc->flags |= DEVMEM;
			pc->readmem = read_dev_mem;
			pc->writemem = write_dev_mem;
			pc->live_memsrc = "/dev/mem";
		} 

		if (STREQ(pc->live_memsrc, "/dev/mem")) {
	                if ((pc->mfd = open("/dev/mem", O_RDWR)) < 0) {
	                        if ((pc->mfd = open("/dev/mem", O_RDONLY)) < 0)
	                                error(FATAL, "/dev/mem: %s\n",
	                                        strerror(errno));
	                } else
	                        pc->flags |= MFD_RDWR;
		} else if (STREQ(pc->live_memsrc, "/proc/kcore")) {
			if ((pc->mfd = open("/proc/kcore", O_RDONLY)) < 0)
				error(FATAL, "/proc/kcore: %s\n", 
					strerror(errno));
			if (!proc_kcore_init(fp, pc->mfd))
				error(FATAL, 
				    "/proc/kcore: initialization failed\n");
		} else {
			if (!pc->live_memsrc)
				error(FATAL, "cannot find a live memory device\n");
			else
				error(FATAL, "unknown memory device: %s\n",
					pc->live_memsrc);
		}

		return;
        } 

	if (pc->dumpfile) {
	        if (!file_exists(pc->dumpfile, NULL))
	        	error(FATAL, "%s: %s\n", pc->dumpfile, 
				strerror(ENOENT));
	
		if (!(pc->flags & DUMPFILE_TYPES)) 
			error(FATAL, "%s: dump format not supported!\n",
				pc->dumpfile);
	
                if (pc->flags & NETDUMP) {
                        if (!netdump_init(pc->dumpfile, fp))
                                error(FATAL, "%s: initialization failed\n",
                                        pc->dumpfile);
		} else if (pc->flags & KDUMP) {
                        if (!kdump_init(pc->dumpfile, fp))
                                error(FATAL, "%s: initialization failed\n",
                                        pc->dumpfile);
		} else if (pc->flags & XENDUMP) {
                        if (!xendump_init(pc->dumpfile, fp))
                                error(FATAL, "%s: initialization failed\n",
                                        pc->dumpfile);
		} else if (pc->flags & KVMDUMP) {
                        if (!kvmdump_init(pc->dumpfile, fp))
                                error(FATAL, "%s: initialization failed\n",
                                        pc->dumpfile);
		} else if (pc->flags & DISKDUMP) {
                        if (!diskdump_init(pc->dumpfile, fp))
                                error(FATAL, "%s: initialization failed\n",
                                        pc->dumpfile);
                } else if (pc->flags & LKCD) {
	        	if ((pc->dfd = open(pc->dumpfile, O_RDONLY)) < 0)
	                	error(FATAL, "%s: %s\n", pc->dumpfile, 
					strerror(errno));
			if (!lkcd_dump_init(fp, pc->dfd, pc->dumpfile))
	                	error(FATAL, "%s: initialization failed\n", 
					pc->dumpfile);
		} else if (pc->flags & S390D) { 
			if (!s390_dump_init(pc->dumpfile))
				error(FATAL, "%s: initialization failed\n",
                                        pc->dumpfile);
		} else if (pc->flags & VMWARE_VMSS) {
			if (pc->flags2 & VMWARE_VMSS_GUESTDUMP) {
				if (!vmware_guestdump_init(pc->dumpfile, fp))
					error(FATAL, "%s: initialization failed\n",
						pc->dumpfile);
			} else {
				if (!vmware_vmss_init(pc->dumpfile, fp))
					error(FATAL, "%s: initialization failed\n",
						pc->dumpfile);
			}
		}
	}
}

/*
 *  If only a namelist argument is entered for a live system, and the
 *  version string doesn't match /proc/version, try to avert a failure
 *  by assigning it to a matching System.map.
 */
static void
match_proc_version(void)
{
	char buffer[BUFSIZE], *p1, *p2;

	if (pc->flags & KERNEL_DEBUG_QUERY)
		return;

	if (!strlen(kt->proc_version)) 
		return;

	if (match_file_string(pc->namelist, kt->proc_version, buffer)) {
                if (CRASHDEBUG(1)) {
			fprintf(fp, "/proc/version:\n%s\n", kt->proc_version);
			fprintf(fp, "%s:\n%s", pc->namelist, buffer);
		}
		return;
	}

	error(WARNING, "%s%sand /proc/version do not match!\n\n", 
		pc->namelist, 
		strlen(pc->namelist) > 39 ? "\n         " : " ");

	/*
	 *  find_booted_system_map() requires VTOP(), which used to be a 
	 *  hardwired masking of the kernel address.  But some architectures 
	 *  may not know what their physical base address is at this point, 
	 *  and others may have different machdep->kvbase values, so for all
	 *  but the 0-based kernel virtual address architectures, bail out
	 *  here with a relevant error message.
	 */
	if (!machine_type("S390") && !machine_type("S390X")) {
		p1 = &kt->proc_version[strlen("Linux version ")];
		p2 = strstr(p1, " ");
		*p2 = NULLCHAR;
		error(WARNING, "/proc/version indicates kernel version: %s\n", p1);
		error(FATAL, "please use the vmlinux file for that kernel version, or try using\n"
			"       the System.map for that kernel version as an additional argument.\n", p1);
		clean_exit(1);
	}

	if (find_booted_system_map())
                pc->flags |= SYSMAP;
}


#define CREATE  1
#define DESTROY 0
#define DEFAULT_SEARCHDIRS 6
#define EXTRA_SEARCHDIRS 5

static char **
build_searchdirs(int create, int *preferred)
{
	int i;
	int cnt, start;
	DIR *dirp;
        struct dirent *dp;
	char dirbuf[BUFSIZE];
	static char **searchdirs = { 0 };
	static char *default_searchdirs[DEFAULT_SEARCHDIRS+1] = {
        	"/usr/src/linux/",
        	"/boot/",
	        "/boot/efi/redhat",
		"/boot/efi/EFI/redhat",
		"/usr/lib/debug/boot/",
        	"/",
        	NULL
	};

	if (!create) {
		if (searchdirs) {
			for (i = DEFAULT_SEARCHDIRS; searchdirs[i]; i++) 
				free(searchdirs[i]);
			free(searchdirs);
		}
		return NULL;
	}

	if (preferred)
		*preferred = 0;

	/*
	 *  Allow, at a minimum, the defaults plus an extra four directories: 
	 *
	 *    /lib/modules
	 *    /usr/src/redhat/BUILD/kernel-<version>/linux
	 *    /usr/src/redhat/BUILD/kernel-<version>/linux-<version>
	 *    /usr/lib/debug/lib/modules
	 *
	 */  
	cnt = DEFAULT_SEARCHDIRS + EXTRA_SEARCHDIRS;  

        if ((dirp = opendir("/usr/src"))) {
                for (dp = readdir(dirp); dp != NULL; dp = readdir(dirp)) 
			cnt++;

		if ((searchdirs = calloc(cnt, sizeof(char *))) == NULL) {
			error(INFO, "/usr/src/ directory list malloc: %s\n",
                                strerror(errno));
			closedir(dirp);
			return default_searchdirs;
		} 

		for (i = 0; i < DEFAULT_SEARCHDIRS; i++) 
			searchdirs[i] = default_searchdirs[i];
		cnt = DEFAULT_SEARCHDIRS;

		rewinddir(dirp);

        	for (dp = readdir(dirp); dp != NULL; dp = readdir(dirp)) {
			if (STREQ(dp->d_name, "linux") ||
			    STREQ(dp->d_name, "redhat") ||
			    STREQ(dp->d_name, ".") ||
			    STREQ(dp->d_name, ".."))
				continue;

			sprintf(dirbuf, "/usr/src/%s", dp->d_name);
			if (mount_point(dirbuf))
				continue;
			if (!is_directory(dirbuf))
				continue;

			if ((searchdirs[cnt] = (char *)
			    malloc(strlen(dirbuf)+2)) == NULL) {
				error(INFO,
				    "/usr/src/ directory entry malloc: %s\n",
                                	strerror(errno));
				break;
			}
			sprintf(searchdirs[cnt], "%s/", dirbuf); 
			cnt++;
		}

		closedir(dirp);

		searchdirs[cnt] = NULL;
	} else {
		if ((searchdirs = calloc(cnt, sizeof(char *))) == NULL) {
			error(INFO, "search directory list malloc: %s\n",
                                strerror(errno));
			return default_searchdirs;
		} 
		for (i = 0; i < DEFAULT_SEARCHDIRS; i++) 
			searchdirs[i] = default_searchdirs[i];
		cnt = DEFAULT_SEARCHDIRS;
	}

	if (build_kernel_directory(dirbuf)) {
		if ((searchdirs[cnt] = (char *)
		    malloc(strlen(dirbuf)+2)) == NULL) {
			error(INFO,
			    "/lib/modules/ directory entry malloc: %s\n",
				strerror(errno));
		} else {
			sprintf(searchdirs[cnt], "%s/", dirbuf);
			cnt++;
		}
	}

        if (redhat_kernel_directory_v1(dirbuf)) {
                if ((searchdirs[cnt] = (char *) 
		    malloc(strlen(dirbuf)+2)) == NULL) {
                        error(INFO, 
			    "/usr/src/redhat directory entry malloc: %s\n",
                        	strerror(errno));
                } else {
                        sprintf(searchdirs[cnt], "%s/", dirbuf);
                        cnt++;
                }
        }

        if (redhat_kernel_directory_v2(dirbuf)) {
                if ((searchdirs[cnt] = (char *)
                    malloc(strlen(dirbuf)+2)) == NULL) {
                        error(INFO,
                            "/usr/src/redhat directory entry malloc: %s\n",
                                strerror(errno));
                } else {
                        sprintf(searchdirs[cnt], "%s/", dirbuf);
                        cnt++;
                }
        }

        if (redhat_debug_directory(dirbuf)) {
                if ((searchdirs[cnt] = (char *)
                     malloc(strlen(dirbuf)+2)) == NULL) {
                         error(INFO, "%s directory entry malloc: %s\n",
                                 dirbuf, strerror(errno));
                } else {
                         sprintf(searchdirs[cnt], "%s/", dirbuf);
			if (preferred)
				*preferred = cnt;
                         cnt++;
                }
        }

	searchdirs[cnt] = NULL;
 
	if (CRASHDEBUG(1)) {
		i = start = preferred ? *preferred : 0;
		do {
			fprintf(fp, "searchdirs[%d]: %s\n", 
				i, searchdirs[i]);
			if (++i == cnt) {
				if (start != 0)
					i = 0;
				else
					break;
			}
		} while (i != start);
	}

	return searchdirs;
}

static int
build_kernel_directory(char *buf)
{
	char *p1, *p2;

	if (!strstr(kt->proc_version, "Linux version "))
		return FALSE;

	BZERO(buf, BUFSIZE);
	sprintf(buf, "/lib/modules/");

	p1 = &kt->proc_version[strlen("Linux version ")];
	p2 = &buf[strlen(buf)];

	while (*p1 != ' ')
		*p2++ = *p1++;

	strcat(buf, "/build");
	return TRUE;
}

static int
redhat_kernel_directory_v1(char *buf)
{
	char *p1, *p2;

	if (!strstr(kt->proc_version, "Linux version "))
		return FALSE;

	BZERO(buf, BUFSIZE);
	sprintf(buf, "/usr/src/redhat/BUILD/kernel-");

	p1 = &kt->proc_version[strlen("Linux version ")];
	p2 = &buf[strlen(buf)];

	while (((*p1 >= '0') && (*p1 <= '9')) || (*p1 == '.'))
		*p2++ = *p1++;	

	strcat(buf, "/linux");
	return TRUE;
}

static int
redhat_kernel_directory_v2(char *buf)
{
        char *p1, *p2;

        if (!strstr(kt->proc_version, "Linux version "))
                return FALSE;

        BZERO(buf, BUFSIZE);
        sprintf(buf, "/usr/src/redhat/BUILD/kernel-");

        p1 = &kt->proc_version[strlen("Linux version ")];
        p2 = &buf[strlen(buf)];

        while (((*p1 >= '0') && (*p1 <= '9')) || (*p1 == '.'))
                *p2++ = *p1++;

        strcat(buf, "/linux-");

        p1 = &kt->proc_version[strlen("Linux version ")];
        p2 = &buf[strlen(buf)];

        while (((*p1 >= '0') && (*p1 <= '9')) || (*p1 == '.'))
                *p2++ = *p1++;

        return TRUE;
}


static int
redhat_debug_directory(char *buf)
{
        char *p1, *p2;

        if (!strstr(kt->proc_version, "Linux version "))
                return FALSE;

        BZERO(buf, BUFSIZE);
        sprintf(buf, "%s/", pc->redhat_debug_loc);

        p1 = &kt->proc_version[strlen("Linux version ")];
        p2 = &buf[strlen(buf)];

        while (*p1 != ' ')
                *p2++ = *p1++;

        return TRUE;
}

/*
 *  If a namelist was not entered, presume we're using the currently-running
 *  kernel.  Read its version string from /proc/version, and then look in
 *  the search directories for a kernel with the same version string embedded
 *  in it.
 */
static int
find_booted_kernel(void)
{
	char kernel[BUFSIZE];
	char buffer[BUFSIZE];
	char **searchdirs;
	int i, preferred, wrapped;
        DIR *dirp;
        struct dirent *dp;
	int found;

	pc->flags |= FINDKERNEL;

	fflush(fp);

	if (!file_exists("/proc/version", NULL)) {
		error(INFO, 
		    "/proc/version: %s: cannot determine booted kernel\n",
			strerror(ENOENT));
		return FALSE;
	}

	if (!get_proc_version()) {
                error(INFO, "/proc/version: %s\n", strerror(errno));
                return FALSE;
	}

        if (CRASHDEBUG(1))
                fprintf(fp, "\nfind_booted_kernel: search for [%s]\n", 
			kt->proc_version);

        searchdirs = build_searchdirs(CREATE, &preferred);

	for (i = preferred, wrapped = found = FALSE; !found; i++) { 
		if (!searchdirs[i]) {
			if (preferred && !wrapped) {
				wrapped = TRUE;
				i = 0;
			} else
				break;
		} else if (wrapped && (preferred == i))
			break;
	
	        dirp = opendir(searchdirs[i]);
		if (!dirp)
			continue;
	        for (dp = readdir(dirp); dp != NULL; dp = readdir(dirp)) {
			if (dp->d_name[0] == '.')
				continue;

			sprintf(kernel, "%s%s", searchdirs[i], dp->d_name);

			if (mount_point(kernel) ||
			    !file_readable(kernel) || 
                            !is_kernel(kernel))
				continue;

			if (CRASHDEBUG(1)) 
				fprintf(fp, "find_booted_kernel: check: %s\n", 
					kernel);

			found = match_file_string(kernel, kt->proc_version, buffer);
	
			if (found)
				break;
	        }
		closedir(dirp);
	}

	mount_point(DESTROY);
	build_searchdirs(DESTROY, NULL);

	if (found) {
                if ((pc->namelist = (char *)malloc
		    (strlen(kernel)+1)) == NULL) 
			error(FATAL, "booted kernel name malloc: %s\n",
				strerror(errno));
                else {
                        strcpy(pc->namelist, kernel);
			if (CRASHDEBUG(1))
				fprintf(fp, "find_booted_kernel: found: %s\n", 
					pc->namelist);
                        return TRUE;
                }
	}

	error(INFO, 
             "cannot find booted kernel -- please enter namelist argument\n\n");
	return FALSE;
}

/*
 *  Determine whether a file is a mount point, without the benefit of stat().
 *  This horrendous kludge is necessary to avoid uninterruptible stat() or 
 *  fstat() calls on nfs mount-points where the remote directory is no longer 
 *  available.
 */
static int
mount_point(char *name)
{
	int i;
	static int mount_points_gathered = -1;
	static char **mount_points;
        char *arglist[MAXARGS];
	char buf[BUFSIZE];
	char mntfile[BUFSIZE];
	int argc, found;
        FILE *mp;

	/*
	 *  The first time through, stash a list of mount points.
	 */

	if (mount_points_gathered < 0) {
		found = mount_points_gathered = 0; 

        	if (file_exists("/proc/mounts", NULL))
			sprintf(mntfile, "/proc/mounts");
		else if (file_exists("/etc/mtab", NULL))
			sprintf(mntfile, "/etc/mtab");
		else
                	return FALSE;

        	if ((mp = fopen(mntfile, "r")) == NULL)
                	return FALSE;

		while (fgets(buf, BUFSIZE, mp)) {
        		argc = parse_line(buf, arglist);
			if (argc < 2)
				continue;
			found++;
		}
		fclose(mp);

		if (!(mount_points = (char **)malloc(sizeof(char *) * found)))
			return FALSE;

                if ((mp = fopen(mntfile, "r")) == NULL) 
                        return FALSE;

		i = 0;
                while (fgets(buf, BUFSIZE, mp) && 
		       (mount_points_gathered < found)) {
                        argc = parse_line(buf, arglist);
                        if (argc < 2)
                                continue;
			if ((mount_points[i] = (char *)
			     malloc(strlen(arglist[1])*2))) { 
				strcpy(mount_points[i], arglist[1]);
                        	mount_points_gathered++, i++;
			}
                }
		fclose(mp);

		if (CRASHDEBUG(2))
			for (i = 0; i < mount_points_gathered; i++)
				fprintf(fp, "mount_points[%d]: %s (%lx)\n", 
					i, mount_points[i], 
					(ulong)mount_points[i]);
		
	}

	/*
	 *  A null name string means we're done with this routine forever,
	 *  so the malloc'd memory can be freed.
	 */
        if (!name) {   
                for (i = 0; i < mount_points_gathered; i++) 
                        free(mount_points[i]);
                free(mount_points);
                return FALSE;
        }


	for (i = 0; i < mount_points_gathered; i++) {
		if (STREQ(name, mount_points[i]))
			return TRUE;
	}


        return FALSE;
}


/*
 *  If /proc/version exists, get it for verification purposes later.
 */
int
get_proc_version(void)
{
        FILE *version;

	if (strlen(kt->proc_version))  /* been here, done that... */
		return TRUE;

        if (!file_exists("/proc/version", NULL)) 
                return FALSE;

        if ((version = fopen("/proc/version", "r")) == NULL) 
                return FALSE;

        if (fread(&kt->proc_version, sizeof(char), 
	    	BUFSIZE-1, version) <= 0) {
		fclose(version);
                return FALSE;
	}
        
        fclose(version);

	strip_linefeeds(kt->proc_version);

	return TRUE;
}


/*
 *  Given a non-matching kernel namelist, try to find a System.map file
 *  that has a system_utsname whose contents match /proc/version.
 */
static int
find_booted_system_map(void)
{
	char system_map[BUFSIZE];
	char **searchdirs;
	int i;
        DIR *dirp;
        struct dirent *dp;
	int found;

	fflush(fp);

	if (!file_exists("/proc/version", NULL)) {
		error(INFO, 
		    "/proc/version: %s: cannot determine booted System.map\n",
			strerror(ENOENT));
		return FALSE;
	}

	if (!get_proc_version()) {
                error(INFO, "/proc/version: %s\n", strerror(errno));
                return FALSE;
	}

	found = FALSE;

	/*
	 *  To avoid a search, try the obvious first.
	 */
	sprintf(system_map, "/boot/System.map");
	if (file_readable(system_map) && verify_utsname(system_map)) {
		found = TRUE;
	} else {
	        searchdirs = build_searchdirs(CREATE, NULL);
	
		for (i = 0; !found && searchdirs[i]; i++) { 
		        dirp = opendir(searchdirs[i]);
			if (!dirp)
				continue;
		        for (dp = readdir(dirp); dp != NULL; 
			     dp = readdir(dirp)) {
				if (!strstr(dp->d_name, "System.map"))
					continue;
	
				sprintf(system_map, "%s%s", searchdirs[i], 
					dp->d_name);
	
				if (mount_point(system_map) ||
				    !file_readable(system_map) || 
	                            !is_system_map(system_map))
					continue;
	
				if (verify_utsname(system_map)) {
					found = TRUE;
					break;
				}
		        }
			closedir(dirp);
		}

		mount_point(DESTROY);
		build_searchdirs(DESTROY, NULL);
	}

	if (found) {
                if ((pc->system_map = (char *)malloc
		    (strlen(system_map)+1)) == NULL) 
			error(FATAL, "booted system map name malloc: %s\n",
				strerror(errno));
                strcpy(pc->system_map, system_map);
		if (CRASHDEBUG(1))
			fprintf(fp, "find_booted_system_map: found: %s\n", 
				pc->system_map);
                return TRUE;
	}

	error(INFO, 
 "cannot find booted system map -- please enter namelist or system map\n\n");
	return FALSE;
}

/*
 *  Read the system_utsname from /dev/mem, based upon the address found
 *  in the passed-in System.map file, and compare it to /proc/version.
 */
static int
verify_utsname(char *system_map)
{
	char buffer[BUFSIZE];
	ulong value;
	struct new_utsname new_utsname;

	if (CRASHDEBUG(1)) 
		fprintf(fp, "verify_utsname: check: %s\n", system_map);

	if (!match_file_string(system_map, "D system_utsname", buffer))
		return FALSE;
	
	if (extract_hex(buffer, &value, NULLCHAR, TRUE) &&
	    (READMEM(pc->mfd, &new_utsname, 
	     sizeof(struct new_utsname), value, 
	     VTOP(value)) > 0) && 
	    ascii_string(new_utsname.release) &&
	    ascii_string(new_utsname.version) &&
	    STRNEQ(new_utsname.release, "2.") &&
	    (strlen(new_utsname.release) > 4) &&
	    (strlen(new_utsname.version) > 27)) {
		if (CRASHDEBUG(1)) {
			fprintf(fp, "release: [%s]\n", new_utsname.release);
			fprintf(fp, "version: [%s]\n", new_utsname.version);
		}
		if (strstr(kt->proc_version, new_utsname.release) &&
		    strstr(kt->proc_version, new_utsname.version)) {
			return TRUE;
		}
	}

	return FALSE;
}

/*
 *  Determine whether a file exists, using the caller's stat structure if
 *  one was passed in.
 */
int
file_exists(char *file, struct stat *sp)
{
        struct stat sbuf;

        if (stat(file, sp ? sp : &sbuf) == 0)
                return TRUE;

        return FALSE;
}

/*
 *  Determine whether a file exists, and if so, if it's readable.
 */
int 
file_readable(char *file)
{
	char tmp;
	int fd;

	if (!file_exists(file, NULL))
		return FALSE;

	if ((fd = open(file, O_RDONLY)) < 0) 
		return FALSE;

	if (read(fd, &tmp, sizeof(tmp)) != sizeof(tmp)) {
		close(fd);
		return FALSE;
	}
	close(fd);

	return TRUE;
}

/*
 *  Quick file checksummer.
 */
int 
file_checksum(char *file, long *retsum)
{
	int i;
	int fd;
	ssize_t cnt;
	char buf[MIN_PAGE_SIZE];
	long csum;


	if ((fd = open(file, O_RDONLY)) < 0)
		return FALSE;

	csum = 0;
	BZERO(buf, MIN_PAGE_SIZE);
	while ((cnt = read(fd, buf, MIN_PAGE_SIZE)) > 0) {
		for (i = 0; i < cnt; i++)
			csum += buf[i];
		BZERO(buf, MIN_PAGE_SIZE);
	}
	close(fd);

	*retsum = csum;

	return TRUE;
}

int
is_directory(char *file)
{
    struct stat sbuf;
 
    if (!file || !strlen(file))
        return(FALSE);

    if (stat(file, &sbuf) == -1)
        return(FALSE);                         /* This file doesn't exist. */
            
    return((sbuf.st_mode & S_IFMT) == S_IFDIR ? TRUE : FALSE);
}


/*
 *  Search a directory tree for filename, and if found, return a temporarily
 *  allocated buffer containing the full pathname.   The "done" business is
 *  protection against fgets() prematurely returning NULL before the find
 *  command completes.  (I thought this was impossible until I saw it happen...)
 *  When time permits, rewrite this doing the search by hand.
 */
char *
search_directory_tree(char *directory, char *file, int follow_links)
{
	char command[BUFSIZE];
	char buf[BUFSIZE];
	char *retbuf, *start, *end, *module;
	FILE *pipe;
	regex_t regex;
	int regex_used, done;

	if (!file_exists("/usr/bin/find", NULL) || 
	    !file_exists("/bin/echo", NULL) ||
	    !is_directory(directory) ||
	    (*file == '(')) 
		return NULL;

	sprintf(command, 
            "/usr/bin/find %s %s -name %s -print; /bin/echo search done",
		follow_links ? "-L" : "", directory, file);

        if ((pipe = popen(command, "r")) == NULL) {
                error(INFO, "%s: %s\n", command, strerror(errno));
                return NULL;
        }

	done = FALSE;
	retbuf = NULL;
	regex_used = ((start = strstr(file, "[")) && 
		(end = strstr(file, "]")) && (start < end) &&
		(regcomp(&regex, file, 0) == 0));

        while (fgets(buf, BUFSIZE-1, pipe) || !done) {
                if (STREQ(buf, "search done\n")) {
                        done = TRUE;
                        break;
                }
                if (!retbuf && !regex_used &&
                    STREQ((char *)basename(strip_linefeeds(buf)), file)) {
                        retbuf = GETBUF(strlen(buf)+1);
                        strcpy(retbuf, buf);
                }
		if (!retbuf && regex_used) {
			module = basename(strip_linefeeds(buf));
			if (regexec(&regex, module, 0, NULL, 0) == 0) {
				retbuf = GETBUF(strlen(buf)+1);
				strcpy(retbuf, buf);
			}
		}
        }

	if (regex_used)
		regfree(&regex);

        pclose(pipe);

	return retbuf;
}
 
/*
 *  Determine whether a file exists, and if so, if it's a tty.
 */
int
is_a_tty(char *filename)
{
        int fd;

        if ((fd = open(filename, O_RDONLY)) < 0)
                return FALSE;

        if (isatty(fd)) {
                close(fd);
                return TRUE;
        }

        close(fd);
        return FALSE;
}

/*
 *  Open a tmpfile for command output.  fp is stashed in pc->saved_fp, and
 *  temporarily set to the new FILE pointer.  This allows a command to still
 *  print to the original output while the tmpfile is still open.
 */

#define OPEN_ONLY_ONCE 

#ifdef OPEN_ONLY_ONCE
void
open_tmpfile(void)
{
	int ret ATTRIBUTE_UNUSED;

        if (pc->tmpfile)
                error(FATAL, "recursive temporary file usage\n");

	if (!pc->tmp_fp) {
        	if ((pc->tmp_fp = tmpfile()) == NULL) 
                	error(FATAL, "cannot open temporary file\n");
	}

	fflush(pc->tmpfile);
	ret = ftruncate(fileno(pc->tmp_fp), 0);
	rewind(pc->tmp_fp);

	pc->tmpfile = pc->tmp_fp;
	pc->saved_fp = fp;
	fp = pc->tmpfile;
}
#else
void
open_tmpfile(void)
{
        if (pc->tmpfile)
                error(FATAL, "recursive temporary file usage\n");

        if ((pc->tmpfile = tmpfile()) == NULL) {
                error(FATAL, "cannot open temporary file\n");
        } else {
                pc->saved_fp = fp;
                fp = pc->tmpfile;
        }
}
#endif

/*
 *  Destroy the reference to the tmpfile, and restore fp to the state
 *  it had when open_tmpfile() was called.
 */
#ifdef OPEN_ONLY_ONCE
void
close_tmpfile(void)
{
	int ret ATTRIBUTE_UNUSED;

	if (pc->tmpfile) {
		fflush(pc->tmpfile);
		ret = ftruncate(fileno(pc->tmpfile), 0);
		rewind(pc->tmpfile);
		pc->tmpfile = NULL;
		fp = pc->saved_fp;
	} else 
		error(FATAL, "trying to close an unopened temporary file\n");
}
#else
void
close_tmpfile(void)
{
        if (pc->tmpfile) {
                fp = pc->saved_fp;
                fclose(pc->tmpfile);
                pc->tmpfile = NULL;
        } else
                error(FATAL, "trying to close an unopened temporary file\n");

}
#endif

/*
 *  open_tmpfile2(), set_tmpfile2() and close_tmpfile2() do not use a 
 *  permanent tmpfile, and do NOT modify the global fp pointer or pc->saved_fp.
 *  That being the case, all wrapped functions must be aware of it, or the 
 *  global fp pointer has to explicitly manipulated by the calling function.  
 *  The secondary tmpfile should only be used by common functions that might 
 *  be called by a higher-level function using the primary permanent tmpfile,
 *  or alternatively a caller may pass in a FILE pointer to set_tmpfile2().
 */
void 
open_tmpfile2(void)
{
        if (pc->tmpfile2)
                error(FATAL, "recursive secondary temporary file usage\n");
                
        if ((pc->tmpfile2 = tmpfile()) == NULL)
                error(FATAL, "cannot open secondary temporary file\n");
        
        rewind(pc->tmpfile2);
}

void
close_tmpfile2(void)
{
	if (pc->tmpfile2) {
		fflush(pc->tmpfile2);
		fclose(pc->tmpfile2);
        	pc->tmpfile2 = NULL;
	}
}

void
set_tmpfile2(FILE *fptr)
{
        if (pc->tmpfile2)
                error(FATAL, "secondary temporary file already in use\n");

	pc->tmpfile2 = fptr;
}


#define MOUNT_PRINT_INODES  0x1
#define MOUNT_PRINT_FILES   0x2

/*
 *  Display basic information about the currently mounted filesystems.
 *  The -f option lists the open files for the filesystem(s).
 *  The -i option dumps the dirty inodes of the filesystem(s).
 *  If an inode address, mount, vfsmount, superblock, device name or 
 *  directory name is also entered, just show the data for the 
 *  filesystem indicated by the argument.
 */

static char mount_hdr[BUFSIZE] = { 0 };

void
cmd_mount(void)
{
	int i;
	int c, found;
	struct task_context *tc, *namespace_context;
	ulong value1, value2;
	char *spec_string;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char *arglist[MAXARGS*2];
	ulong vfsmount = 0;
	int flags = 0;
	int save_next;
	ulong pid;

	/* find a context */
	pid = 1;
	while ((namespace_context = pid_to_context(pid)) == NULL)
		pid++;

	while ((c = getopt(argcnt, args, "ifn:")) != EOF) {
		switch(c)
		{
		case 'i':
			if (INVALID_MEMBER(super_block_s_dirty)) {
				error(INFO, 
				    "the super_block.s_dirty linked list does "
				    "not exist in this kernel\n");
				option_not_supported(c);
			}
			flags |= MOUNT_PRINT_INODES;
			break;

		case 'f':
			flags |= MOUNT_PRINT_FILES;
			break;

		case 'n':
			switch (str_to_context(optarg, &value1, &tc)) {
			case STR_PID:
			case STR_TASK:
				namespace_context = tc;
				break;
			case STR_INVALID:
				error(FATAL, "invalid task or pid value: %s\n",
					optarg);
				break;
			}
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (args[optind] == 0) {
		show_mounts(0, flags, namespace_context);
		return;
	}

	/*
	 *  Dump everything into a tmpfile, and then walk
	 *  through it for each search argument entered.
	 */
	open_tmpfile();
	show_mounts(0, MOUNT_PRINT_FILES | 
		(VALID_MEMBER(super_block_s_dirty) ? MOUNT_PRINT_INODES : 0), 
		namespace_context);

	pc->curcmd_flags &= ~HEADER_PRINTED;

	do {
		spec_string = args[optind];
		if (STRNEQ(spec_string, "0x") && 
		    hexadecimal(spec_string, 0))
			shift_string_left(spec_string, 2);

		found = FALSE;
		rewind(pc->tmpfile);
		save_next = 0;

		while (fgets(buf1, BUFSIZE, pc->tmpfile)) {
			if (STRNEQ(buf1, mount_hdr)) {
				save_next = TRUE;
				continue;
			}
			if (save_next) {
				strcpy(buf2, buf1);
				save_next = FALSE;
			}

			if (!(c = parse_line(buf1, arglist)))
				continue;

			for (i = 0; i < c; i++) {
				if (PATHEQ(arglist[i], spec_string))
					found = TRUE;
				/*
				 *  Check for a vfsmount address
				 *  embedded in a struct mount.
				 */
				if ((i == 0) && (c == 5) &&
				    VALID_MEMBER(mount_mnt) &&
				    hexadecimal(spec_string, 0) &&
				    hexadecimal(arglist[i], 0)) {
					value1 = htol(spec_string, 
						FAULT_ON_ERROR, NULL);
					value2 = htol(arglist[i], 
						FAULT_ON_ERROR, NULL) + 
						OFFSET(mount_mnt);
					if (value1 == value2)
						found = TRUE;
				}
			}
			if (found) {
				fp = pc->saved_fp;
				if (flags) {
					sscanf(buf2,"%lx", &vfsmount);
					show_mounts(vfsmount, flags, 
						namespace_context);
				} else {
					if (!(pc->curcmd_flags & HEADER_PRINTED)) {
						fprintf(fp, "%s", mount_hdr);
						pc->curcmd_flags |= HEADER_PRINTED;
					}
					fprintf(fp, "%s", buf2);
				}
				found = FALSE;
				fp = pc->tmpfile;
			}
		}
	} while (args[++optind]);

	close_tmpfile();
}

/*
 *  Do the work for cmd_mount();
 */

static void
show_mounts(ulong one_vfsmount, int flags, struct task_context *namespace_context)
{
	ulong one_vfsmount_list;
	long sb_s_files;
	long s_dirty;
	ulong devp, dirp, sbp, dirty, type, name;
	struct list_data list_data, *ld;
	char buf1[BUFSIZE*2];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE/2];
	ulong *dentry_list, *dp, *mntlist;
	ulong *vfsmnt;
	char *vfsmount_buf, *super_block_buf, *mount_buf;
	ulong dentry, inode, inode_sb, mnt_parent;
	char *dentry_buf, *inode_buf;
	int cnt, i, m, files_header_printed;
	int mount_cnt; 
	int devlen;
	char mount_files_header[BUFSIZE];
	long per_cpu_s_files;

        sprintf(mount_files_header, "%s%s%s%sTYPE%sPATH\n",
                mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "DENTRY"),
                space(MINSPACE),
                mkstring(buf2, VADDR_PRLEN, CENTER|LJUST, "INODE"),
                space(MINSPACE),
		space(MINSPACE));
		
	dirp = dentry = mnt_parent = sb_s_files = s_dirty = 0;

	if (VALID_MEMBER(super_block_s_dirty))
		s_dirty = OFFSET(super_block_s_dirty);

	per_cpu_s_files = MEMBER_EXISTS("file", "f_sb_list_cpu");

	dentry_list = NULL;
	mntlist = 0;
	ld = &list_data;

	if (one_vfsmount) {
		one_vfsmount_list = one_vfsmount;
		mount_cnt = 1;
		mntlist = &one_vfsmount_list;
	} else 
		mntlist = get_mount_list(&mount_cnt, namespace_context); 

	devlen = strlen("DEVNAME")+2;

	if (!strlen(mount_hdr)) {
		snprintf(mount_hdr, sizeof(mount_hdr), "%s %s %s %s DIRNAME\n",
                	mkstring(buf1, VADDR_PRLEN, CENTER, 
				VALID_STRUCT(mount) ?  "MOUNT" : "VFSMOUNT"),
                	mkstring(buf2, VADDR_PRLEN, CENTER, "SUPERBLK"),
                	mkstring(buf3, strlen("rootfs"), LJUST, "TYPE"),
			mkstring(buf4, devlen, LJUST, "DEVNAME"));
	}

	if (flags == 0)
		fprintf(fp, "%s", mount_hdr);

	sb_s_files = VALID_MEMBER(super_block_s_files) ?
		OFFSET(super_block_s_files) : INVALID_OFFSET;

	if ((flags & MOUNT_PRINT_FILES) && (sb_s_files == INVALID_OFFSET)) {
		/*
		 *  super_block.s_files deprecated
		 */
		if (!kernel_symbol_exists("inuse_filps")) {
			error(INFO, "the super_block.s_files linked list does "
                                    "not exist in this kernel\n");
			option_not_supported('f');
		}
		/*
	  	 * No open files list in super_block (2.2).  
	  	 * Use inuse_filps list instead.
	  	 */
		dentry_list = create_dentry_array(symbol_value("inuse_filps"), 
			&cnt);
	}

	if (VALID_STRUCT(mount)) {
		mount_buf = GETBUF(SIZE(mount));
		vfsmount_buf = mount_buf + OFFSET(mount_mnt);
	} else {
		mount_buf = NULL;
		vfsmount_buf = GETBUF(SIZE(vfsmount));
	}
	super_block_buf = GETBUF(SIZE(super_block));

	for (m = 0, vfsmnt = mntlist; m < mount_cnt; m++, vfsmnt++) {
		if (VALID_STRUCT(mount)) {
			readmem(*vfsmnt, KVADDR, mount_buf, SIZE(mount),
				"mount buffer", FAULT_ON_ERROR);
			devp = ULONG(mount_buf +  OFFSET(mount_mnt_devname));
		} else {
			readmem(*vfsmnt, KVADDR, vfsmount_buf, SIZE(vfsmount),
				"vfsmount buffer", FAULT_ON_ERROR);
			devp = ULONG(vfsmount_buf +  OFFSET(vfsmount_mnt_devname));
		}

		if (VALID_MEMBER(vfsmount_mnt_dirname)) {
			dirp = ULONG(vfsmount_buf +  
				OFFSET(vfsmount_mnt_dirname)); 
		} else {
			if (VALID_STRUCT(mount)) {
				mnt_parent = ULONG(mount_buf + 
					OFFSET(mount_mnt_parent));
				dentry = ULONG(mount_buf +  
					OFFSET(mount_mnt_mountpoint));
			} else {
				mnt_parent = ULONG(vfsmount_buf + 
					OFFSET(vfsmount_mnt_parent));
				dentry = ULONG(vfsmount_buf +  
					OFFSET(vfsmount_mnt_mountpoint));
			}
		}

		sbp = ULONG(vfsmount_buf + OFFSET(vfsmount_mnt_sb)); 
		if (!IS_KVADDR(sbp)) {
			error(WARNING, "cannot get super_block from vfsmnt: 0x%lx\n", *vfsmnt);
			continue;
		}

		if (flags)
			fprintf(fp, "%s", mount_hdr);
                fprintf(fp, "%s %s ",
			mkstring(buf1, VADDR_PRLEN, RJUST|LONG_HEX, 
			MKSTR(*vfsmnt)),
			mkstring(buf2, VADDR_PRLEN, RJUST|LONG_HEX, 
			MKSTR(sbp)));

                readmem(sbp, KVADDR, super_block_buf, SIZE(super_block),
                        "super_block buffer", FAULT_ON_ERROR);
		type = ULONG(super_block_buf + OFFSET(super_block_s_type)); 
                readmem(type + OFFSET(file_system_type_name),
                        KVADDR, &name, sizeof(void *),
                        "file_system_type name", FAULT_ON_ERROR);

                if (read_string(name, buf4, (BUFSIZE/2)-1))
			sprintf(buf3, "%-6s ", buf4);
                else
			sprintf(buf3, "unknown ");

		if (read_string(devp, buf1, BUFSIZE-1))
			sprintf(buf4, "%s ", 
				mkstring(buf2, devlen, LJUST, buf1));
		else
			sprintf(buf4, "%s ", 
				mkstring(buf2, devlen, LJUST, "(unknown)"));

		sprintf(buf1, "%s%s", buf3, buf4);
		while ((strlen(buf1) > 17) && (buf1[strlen(buf1)-2] == ' '))
			strip_ending_char(buf1, ' ');
		fprintf(fp, "%s", buf1);

		if (VALID_MEMBER(vfsmount_mnt_dirname)) {
                	if (read_string(dirp, buf1, BUFSIZE-1))
                        	fprintf(fp, "%-10s\n", buf1);
                	else
                        	fprintf(fp, "%-10s\n", "(unknown)");
		} else {
			get_pathname(dentry, buf1, BUFSIZE, 1, VALID_STRUCT(mount) ?
				mnt_parent + OFFSET(mount_mnt) : mnt_parent);
                       	fprintf(fp, "%-10s\n", buf1);
		}

		if (flags & MOUNT_PRINT_FILES) {
			if (sb_s_files != INVALID_OFFSET) {
				dentry_list = per_cpu_s_files ?
					create_dentry_array_percpu(sbp+
					    sb_s_files, &cnt) :
					create_dentry_array(sbp+sb_s_files, 
					    &cnt);
			}
			files_header_printed = 0;
			for (i=0, dp = dentry_list; i<cnt; i++, dp++) {
				dentry_buf = fill_dentry_cache(*dp);
				inode = ULONG(dentry_buf +
					OFFSET(dentry_d_inode));
				if (!inode)
					continue;
				inode_buf = fill_inode_cache(inode);
				inode_sb = ULONG(inode_buf + 
					OFFSET(inode_i_sb));
				if (inode_sb != sbp)
					continue;
				if (files_header_printed == 0) {
					fprintf(fp, "%s\n",
                                            mkstring(buf2, VADDR_PRLEN,
                                                CENTER, "OPEN FILES"));
					fprintf(fp, "%s", mount_files_header);
					files_header_printed = 1;
				}
				file_dump(0, *dp, inode, 0, DUMP_DENTRY_ONLY);
			}
			if (files_header_printed == 0) {
				fprintf(fp, "%s\nNo open files found\n",
					mkstring(buf2, VADDR_PRLEN,
                                            CENTER, "OPEN FILES"));
			} 
		}

		if (flags & MOUNT_PRINT_INODES) {
			dirty = ULONG(super_block_buf + s_dirty); 

			if (dirty != (sbp+s_dirty)) {
				BZERO(ld, sizeof(struct list_data));
                        	ld->flags = VERBOSE;
                        	ld->start = dirty;
                        	ld->end = (sbp+s_dirty);
				ld->header = "DIRTY INODES\n";
				hq_open();
                        	do_list(ld);
				hq_close();
			} else {
				fprintf(fp, 
				    "DIRTY INODES\nNo dirty inodes found\n");
			}
		}

		if (flags && !one_vfsmount)
			fprintf(fp, "\n");

	}

	if (!one_vfsmount)
		FREEBUF(mntlist); 
	if (VALID_STRUCT(mount))
		FREEBUF(mount_buf);
	else
		FREEBUF(vfsmount_buf);
	FREEBUF(super_block_buf);
}

/*
 *  Allocate and fill a list of the currently-mounted vfsmount pointers.
 */
ulong *
get_mount_list(int *cntptr, struct task_context *namespace_context)
{
	struct list_data list_data, *ld;
	ulong namespace, root, nsproxy, mnt_ns;
	struct task_context *tc;
	
        ld = &list_data;
        BZERO(ld, sizeof(struct list_data));
	ld->flags |= LIST_ALLOCATE;

	if (symbol_exists("vfsmntlist")) {
        	get_symbol_data("vfsmntlist", sizeof(void *), &ld->start);
               	ld->end = symbol_value("vfsmntlist");
	} else if (VALID_MEMBER(task_struct_nsproxy)) {
 		tc = namespace_context;

        	readmem(tc->task + OFFSET(task_struct_nsproxy), KVADDR, 
			&nsproxy, sizeof(void *), "task nsproxy", 
			FAULT_ON_ERROR);
        	if (!readmem(nsproxy + OFFSET(nsproxy_mnt_ns), KVADDR, 
			&mnt_ns, sizeof(void *), "nsproxy mnt_ns", 
			RETURN_ON_ERROR|QUIET))
			error(FATAL, "cannot determine mount list location!\n");
        	if (!readmem(mnt_ns + OFFSET(mnt_namespace_root), KVADDR, 
			&root, sizeof(void *), "mnt_namespace root", 
			RETURN_ON_ERROR|QUIET))
			error(FATAL, "cannot determine mount list location!\n");

		ld->start = root + OFFSET_OPTION(vfsmount_mnt_list, mount_mnt_list);
        	ld->end = mnt_ns + OFFSET(mnt_namespace_list);

	} else if (VALID_MEMBER(namespace_root)) {
 		tc = namespace_context;

        	readmem(tc->task + OFFSET(task_struct_namespace), KVADDR, 
			&namespace, sizeof(void *), "task namespace", 
			FAULT_ON_ERROR);
        	if (!readmem(namespace + OFFSET(namespace_root), KVADDR, 
			&root, sizeof(void *), "namespace root", 
			RETURN_ON_ERROR|QUIET))
			error(FATAL, "cannot determine mount list location!\n");

		if (CRASHDEBUG(1))
			console("namespace: %lx => root: %lx\n", 
				namespace, root);

		ld->start = root + OFFSET_OPTION(vfsmount_mnt_list, mount_mnt_list);
        	ld->end = namespace + OFFSET(namespace_list);
	} else
		error(FATAL, "cannot determine mount list location!\n");
	
        if (VALID_MEMBER(vfsmount_mnt_list)) 
                ld->list_head_offset = OFFSET(vfsmount_mnt_list);
	else if (VALID_STRUCT(mount))
		ld->list_head_offset = OFFSET(mount_mnt_list);
	else
                ld->member_offset = OFFSET(vfsmount_mnt_next);
        
        *cntptr = do_list(ld);
        return(ld->list_ptr);
}


/*
 *  Given a dentry, display its address, inode, super_block, pathname.
 */
static void
display_dentry_info(ulong dentry)
{
	int m, found;
        char *dentry_buf, *inode_buf, *vfsmount_buf, *mount_buf;
        ulong inode, superblock, sb, vfs;
	ulong *mntlist, *vfsmnt;
	char pathname[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	int mount_cnt;

        fprintf(fp, "%s%s%s%s%s%sTYPE%sPATH\n",
                mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "DENTRY"),
                space(MINSPACE),
                mkstring(buf2, VADDR_PRLEN, CENTER|LJUST, "INODE"),
                space(MINSPACE),
                mkstring(buf3, VADDR_PRLEN, CENTER|LJUST, "SUPERBLK"),
                space(MINSPACE),
		space(MINSPACE));

        dentry_buf = fill_dentry_cache(dentry);
        inode = ULONG(dentry_buf + OFFSET(dentry_d_inode));
	pathname[0] = NULLCHAR;

        if (inode) {
                inode_buf = fill_inode_cache(inode);
                superblock = ULONG(inode_buf + OFFSET(inode_i_sb));
	} else {
		inode_buf = NULL;
		superblock = ULONG(dentry_buf + OFFSET(dentry_d_sb));
	}

	if (!superblock)
		goto nopath;

        if (VALID_MEMBER(file_f_vfsmnt)) {
		mntlist = get_mount_list(&mount_cnt, pid_to_context(1));
		if (VALID_STRUCT(mount)) {
			mount_buf = GETBUF(SIZE(mount));
			vfsmount_buf = mount_buf + OFFSET(mount_mnt);
		} else {
			mount_buf = NULL;
			vfsmount_buf = GETBUF(SIZE(vfsmount));
		}

        	for (m = found = 0, vfsmnt = mntlist; 
		     m < mount_cnt; m++, vfsmnt++) {
			if (VALID_STRUCT(mount))
				readmem(*vfsmnt, KVADDR, mount_buf, SIZE(mount),
					"mount buffer", FAULT_ON_ERROR);
			else
				readmem(*vfsmnt, KVADDR, vfsmount_buf, SIZE(vfsmount),
					"vfsmount buffer", FAULT_ON_ERROR);
                	sb = ULONG(vfsmount_buf + OFFSET(vfsmount_mnt_sb));
			if (superblock && (sb == superblock)) {
                		get_pathname(dentry, pathname, BUFSIZE, 1,
					VALID_STRUCT(mount) ?
					*vfsmnt+OFFSET(mount_mnt) : *vfsmnt);
				found = TRUE;
			}
		}

		if (!found && symbol_exists("pipe_mnt")) {
			get_symbol_data("pipe_mnt", sizeof(long), &vfs);
			if (VALID_STRUCT(mount))
				readmem(vfs - OFFSET(mount_mnt), KVADDR, mount_buf, SIZE(mount),
					"mount buffer", FAULT_ON_ERROR);
			else
				readmem(vfs, KVADDR, vfsmount_buf, SIZE(vfsmount),
					"vfsmount buffer", FAULT_ON_ERROR);
                        sb = ULONG(vfsmount_buf + OFFSET(vfsmount_mnt_sb));
                        if (superblock && (sb == superblock)) {
                                get_pathname(dentry, pathname, BUFSIZE, 1, vfs);
                                found = TRUE;
                        }
		}
		if (!found && symbol_exists("sock_mnt")) {
			get_symbol_data("sock_mnt", sizeof(long), &vfs);
			if (VALID_STRUCT(mount))
				readmem(vfs - OFFSET(mount_mnt), KVADDR, mount_buf, SIZE(mount),
					"mount buffer", FAULT_ON_ERROR);
			else
				readmem(vfs, KVADDR, vfsmount_buf, SIZE(vfsmount),
					"vfsmount buffer", FAULT_ON_ERROR);
                        sb = ULONG(vfsmount_buf + OFFSET(vfsmount_mnt_sb));
                        if (superblock && (sb == superblock)) {
                                get_pathname(dentry, pathname, BUFSIZE, 1, vfs);
                                found = TRUE;
                        }
		}
        } else {
		mntlist = 0;
        	get_pathname(dentry, pathname, BUFSIZE, 1, 0);
	}

	if (mntlist) {
		FREEBUF(mntlist);
		if (VALID_STRUCT(mount))
			FREEBUF(mount_buf);
		else
			FREEBUF(vfsmount_buf);
	}

nopath:
	fprintf(fp, "%s%s%s%s%s%s%s%s%s\n",
		mkstring(buf1, VADDR_PRLEN, RJUST|LONG_HEX, MKSTR(dentry)),
		space(MINSPACE), 
		mkstring(buf2, VADDR_PRLEN, RJUST|LONG_HEX, MKSTR(inode)),
		space(MINSPACE),
		mkstring(buf3, VADDR_PRLEN, CENTER|LONG_HEX, MKSTR(superblock)),
		space(MINSPACE), 
		inode ? inode_type(inode_buf, pathname) : "N/A",
		space(MINSPACE), pathname);
}

/*
 *  Return a 4-character type string of an inode, modifying a previously
 *  gathered pathname if necessary.
 */
char *
inode_type(char *inode_buf, char *pathname)
{
	char *type;
        uint32_t umode32;
        uint16_t umode16;
        uint mode;
        ulong inode_i_op;
        ulong inode_i_fop;
	long i_fop_off;

        mode = umode16 = umode32 = 0;

        switch (SIZE(umode_t))
        {
        case SIZEOF_32BIT:
                umode32 = UINT(inode_buf + OFFSET(inode_i_mode));
		mode = umode32;
                break;

        case SIZEOF_16BIT:
                umode16 = USHORT(inode_buf + OFFSET(inode_i_mode));
		mode = (uint)umode16;
                break;
        }

	type = "UNKN";
	if (S_ISREG(mode))
		type = "REG ";
	if (S_ISLNK(mode))
		type = "LNK ";
	if (S_ISDIR(mode))
		type = "DIR ";
	if (S_ISCHR(mode))
		type = "CHR ";
	if (S_ISBLK(mode))
		type = "BLK ";
	if (S_ISFIFO(mode)) {
		type = "FIFO";
		if (symbol_exists("pipe_inode_operations")) {
			inode_i_op = ULONG(inode_buf + OFFSET(inode_i_op));
			if (inode_i_op == 
			    symbol_value("pipe_inode_operations")) {
				type = "PIPE";
				pathname[0] = NULLCHAR;
			}
		} else {
			if (symbol_exists("rdwr_pipe_fops") && 
			    (i_fop_off = OFFSET(inode_i_fop)) > 0) {
				 inode_i_fop = ULONG(inode_buf + i_fop_off);
				 if (inode_i_fop == 
				     symbol_value("rdwr_pipe_fops")) { 
					type = "PIPE";
					pathname[0] = NULLCHAR;
				 }
			}
		}
	}
	if (S_ISSOCK(mode)) {
		type = "SOCK";
		if (STREQ(pathname, "/"))
			pathname[0] = NULLCHAR;
	}

	return type;
}


/*
 *  Walk an open file list and return an array of open dentries.
 */
static ulong *
create_dentry_array(ulong list_addr, int *count)
{ 
	struct list_data list_data, *ld;
	ulong *file, *files_list, *dentry_list;
	ulong dentry, inode;
	char *file_buf, *dentry_buf;
	int cnt, f_count, i;
	int dentry_cnt = 0;

	ld = &list_data;
	BZERO(ld, sizeof(struct list_data));
	readmem(list_addr, KVADDR, &ld->start, sizeof(void *), "file list head",
		FAULT_ON_ERROR);

	if (list_addr == ld->start) {  /* empty list? */
		*count = 0;
		return NULL;
	}

	ld->end = list_addr;
	hq_open();
	cnt = do_list(ld);
	if (cnt == 0) {
		hq_close();
		*count = 0;
		return NULL;
	}
	files_list = (ulong *)GETBUF(cnt * sizeof(ulong));
	cnt = retrieve_list(files_list, cnt);
	hq_close();
	hq_open();

	for (i=0, file = files_list; i<cnt; i++, file++) {
		file_buf = fill_file_cache(*file);

		f_count = INT(file_buf + OFFSET(file_f_count));
		if (!f_count)
			continue;

		dentry = ULONG(file_buf + OFFSET(file_f_dentry));
		if (!dentry)
			continue;

		dentry_buf = fill_dentry_cache(dentry);
		inode = ULONG(dentry_buf + OFFSET(dentry_d_inode));

		if (!inode)
			continue;
		if (hq_enter(dentry))
			dentry_cnt++;
	}
	if (dentry_cnt) {
		dentry_list = (ulong *)GETBUF(dentry_cnt * sizeof(ulong));
		*count = retrieve_list(dentry_list, dentry_cnt);
	} else {
		*count = 0;
		dentry_list = NULL;
	}
	hq_close();
	FREEBUF(files_list);
	return dentry_list;
}

/*
 *  Walk each per-cpu open file list and return an array of open dentries.
 */
static ulong *
create_dentry_array_percpu(ulong percpu_list_addr, int *count)
{
	int i, j, c, total;
	int cpu; 
	ulong percpu_list_offset, list_addr;
	ulong *dentry_list;
	struct percpu_list {
		ulong *dentry_list;
		int count;
	} *percpu_list;

	if ((cpu = get_highest_cpu_online()) < 0)
		error(FATAL, "cannot determine highest cpu online\n");

	percpu_list = (struct percpu_list *)
		GETBUF(sizeof(struct percpu_list) * (cpu+1));

        readmem(percpu_list_addr, KVADDR, &percpu_list_offset, sizeof(void *), 
	    "percpu file list head offset", FAULT_ON_ERROR);

	for (c = total = 0; c < (cpu+1); c++) {
		list_addr = percpu_list_offset + kt->__per_cpu_offset[c];
		percpu_list[c].dentry_list = create_dentry_array(list_addr, 
			&percpu_list[c].count);
		total += percpu_list[c].count;
	}

	if (total) {
		dentry_list = (ulong *)GETBUF(total * sizeof(ulong));

		for (c = i = 0; c < (cpu+1); c++) {
			if (percpu_list[c].count == 0)
				continue;
			for (j = 0; j < percpu_list[c].count; j++)
				dentry_list[i++] = 
					percpu_list[c].dentry_list[j];
			FREEBUF(percpu_list[c].dentry_list);
		}
	} else 
		dentry_list = NULL;

	FREEBUF(percpu_list);
	*count = total;
	return dentry_list;
}

/*
 *  Stash vfs structure offsets
 */
void
vfs_init(void)
{ 
        MEMBER_OFFSET_INIT(nlm_file_f_file, "nlm_file", "f_file");
	MEMBER_OFFSET_INIT(task_struct_files, "task_struct", "files");
	MEMBER_OFFSET_INIT(task_struct_fs, "task_struct", "fs");
	MEMBER_OFFSET_INIT(fs_struct_root, "fs_struct", "root");
	MEMBER_OFFSET_INIT(fs_struct_pwd, "fs_struct", "pwd");
	MEMBER_OFFSET_INIT(fs_struct_rootmnt, "fs_struct", "rootmnt");
	MEMBER_OFFSET_INIT(fs_struct_pwdmnt, "fs_struct", "pwdmnt");
	MEMBER_OFFSET_INIT(files_struct_open_fds_init,  
		"files_struct", "open_fds_init");
	MEMBER_OFFSET_INIT(files_struct_fdt, "files_struct", "fdt");
	if (VALID_MEMBER(files_struct_fdt)) {
		MEMBER_OFFSET_INIT(fdtable_max_fds, "fdtable", "max_fds");
		MEMBER_OFFSET_INIT(fdtable_max_fdset, "fdtable", "max_fdset");
		MEMBER_OFFSET_INIT(fdtable_open_fds, "fdtable", "open_fds");
		MEMBER_OFFSET_INIT(fdtable_fd, "fdtable", "fd");
	} else {
		MEMBER_OFFSET_INIT(files_struct_max_fds, "files_struct", "max_fds");
		MEMBER_OFFSET_INIT(files_struct_max_fdset, "files_struct", "max_fdset");
		MEMBER_OFFSET_INIT(files_struct_open_fds, "files_struct", "open_fds");
		MEMBER_OFFSET_INIT(files_struct_fd, "files_struct", "fd");
	}
	MEMBER_OFFSET_INIT(file_f_dentry, "file", "f_dentry");
	MEMBER_OFFSET_INIT(file_f_vfsmnt, "file", "f_vfsmnt");
	MEMBER_OFFSET_INIT(file_f_count, "file", "f_count");
	MEMBER_OFFSET_INIT(path_mnt, "path", "mnt");
	MEMBER_OFFSET_INIT(path_dentry, "path", "dentry");
	if (INVALID_MEMBER(file_f_dentry)) {
		MEMBER_OFFSET_INIT(file_f_path, "file", "f_path");
		ASSIGN_OFFSET(file_f_dentry) = OFFSET(file_f_path) + OFFSET(path_dentry);
		ASSIGN_OFFSET(file_f_vfsmnt) = OFFSET(file_f_path) + OFFSET(path_mnt);
	}
	MEMBER_OFFSET_INIT(dentry_d_inode, "dentry", "d_inode");
	MEMBER_OFFSET_INIT(dentry_d_parent, "dentry", "d_parent");
	MEMBER_OFFSET_INIT(dentry_d_covers, "dentry", "d_covers");
	MEMBER_OFFSET_INIT(dentry_d_name, "dentry", "d_name");
	MEMBER_OFFSET_INIT(dentry_d_iname, "dentry", "d_iname");
	MEMBER_OFFSET_INIT(dentry_d_sb, "dentry", "d_sb");
	MEMBER_OFFSET_INIT(inode_i_mode, "inode", "i_mode");
	MEMBER_OFFSET_INIT(inode_i_op, "inode", "i_op");
	MEMBER_OFFSET_INIT(inode_i_sb, "inode", "i_sb");
	MEMBER_OFFSET_INIT(inode_u, "inode", "u");
	MEMBER_OFFSET_INIT(qstr_name, "qstr", "name");
	MEMBER_OFFSET_INIT(qstr_len, "qstr", "len");
	if (INVALID_MEMBER(qstr_len))
		ANON_MEMBER_OFFSET_INIT(qstr_len, "qstr", "len");

	MEMBER_OFFSET_INIT(vfsmount_mnt_next, "vfsmount", "mnt_next");
        MEMBER_OFFSET_INIT(vfsmount_mnt_devname, "vfsmount", "mnt_devname");
	if (INVALID_MEMBER(vfsmount_mnt_devname))
		MEMBER_OFFSET_INIT(mount_mnt_devname, "mount", "mnt_devname");
        MEMBER_OFFSET_INIT(vfsmount_mnt_dirname, "vfsmount", "mnt_dirname");
        MEMBER_OFFSET_INIT(vfsmount_mnt_sb, "vfsmount", "mnt_sb");
        MEMBER_OFFSET_INIT(vfsmount_mnt_list, "vfsmount", "mnt_list");
	if (INVALID_MEMBER(vfsmount_mnt_devname))
		MEMBER_OFFSET_INIT(mount_mnt_list, "mount", "mnt_list");
        MEMBER_OFFSET_INIT(vfsmount_mnt_parent, "vfsmount", "mnt_parent");
	if (INVALID_MEMBER(vfsmount_mnt_devname))
		MEMBER_OFFSET_INIT(mount_mnt_parent, "mount", "mnt_parent");
        MEMBER_OFFSET_INIT(vfsmount_mnt_mountpoint, 
		"vfsmount", "mnt_mountpoint");
	if (INVALID_MEMBER(vfsmount_mnt_devname))
		MEMBER_OFFSET_INIT(mount_mnt_mountpoint,
			"mount", "mnt_mountpoint");
	MEMBER_OFFSET_INIT(mount_mnt, "mount", "mnt");
	MEMBER_OFFSET_INIT(namespace_root, "namespace", "root");
	MEMBER_OFFSET_INIT(task_struct_nsproxy, "task_struct", "nsproxy");
	if (VALID_MEMBER(namespace_root)) {
		MEMBER_OFFSET_INIT(namespace_list, "namespace", "list");
		MEMBER_OFFSET_INIT(task_struct_namespace, 
			"task_struct", "namespace");
	} else if (VALID_MEMBER(task_struct_nsproxy)) {
		MEMBER_OFFSET_INIT(nsproxy_mnt_ns, "nsproxy", "mnt_ns");
        	MEMBER_OFFSET_INIT(mnt_namespace_root, "mnt_namespace", "root");
        	MEMBER_OFFSET_INIT(mnt_namespace_list, "mnt_namespace", "list");
	} else if (THIS_KERNEL_VERSION >= LINUX(2,4,20)) {
		if (CRASHDEBUG(2))
			fprintf(fp, "hardwiring namespace stuff\n");
		ASSIGN_OFFSET(task_struct_namespace) = OFFSET(task_struct_files) +
			sizeof(void *);
		ASSIGN_OFFSET(namespace_root) = sizeof(void *);
		ASSIGN_OFFSET(namespace_list) = sizeof(void *) * 2;
	}

        MEMBER_OFFSET_INIT(super_block_s_dirty, "super_block", "s_dirty");
        MEMBER_OFFSET_INIT(super_block_s_type, "super_block", "s_type");
        MEMBER_OFFSET_INIT(file_system_type_name, "file_system_type", "name");
	MEMBER_OFFSET_INIT(super_block_s_files, "super_block", "s_files");
        MEMBER_OFFSET_INIT(inode_i_flock, "inode", "i_flock");
        MEMBER_OFFSET_INIT(file_lock_fl_owner, "file_lock", "fl_owner");
        MEMBER_OFFSET_INIT(nlm_host_h_exportent, "nlm_host", "h_exportent");
        MEMBER_OFFSET_INIT(svc_client_cl_ident, "svc_client", "cl_ident");
	MEMBER_OFFSET_INIT(inode_i_fop, "inode","i_fop");

	STRUCT_SIZE_INIT(umode_t, "umode_t");
	STRUCT_SIZE_INIT(dentry, "dentry");
	STRUCT_SIZE_INIT(files_struct, "files_struct");
	if (VALID_MEMBER(files_struct_fdt))
		STRUCT_SIZE_INIT(fdtable, "fdtable");
	STRUCT_SIZE_INIT(file, "file");
	STRUCT_SIZE_INIT(inode, "inode");
	STRUCT_SIZE_INIT(mount, "mount");
	STRUCT_SIZE_INIT(vfsmount, "vfsmount");
	STRUCT_SIZE_INIT(fs_struct, "fs_struct");
	STRUCT_SIZE_INIT(super_block, "super_block");

	if (!(ft->file_cache = (char *)malloc(SIZE(file)*FILE_CACHE)))
		error(FATAL, "cannot malloc file cache\n");
	if (!(ft->dentry_cache = (char *)malloc(SIZE(dentry)*DENTRY_CACHE)))
		error(FATAL, "cannot malloc dentry cache\n");
	if (!(ft->inode_cache = (char *)malloc(SIZE(inode)*INODE_CACHE)))
		error(FATAL, "cannot malloc inode cache\n");

	MEMBER_OFFSET_INIT(rb_root_rb_node, 
		"rb_root","rb_node");
	MEMBER_OFFSET_INIT(rb_node_rb_left, 
		"rb_node","rb_left");
	MEMBER_OFFSET_INIT(rb_node_rb_right, 
		"rb_node","rb_right");
}

void
dump_filesys_table(int verbose)
{
	int i;
	ulong fhits, dhits, ihits;

	if (!verbose)
		goto show_hit_rates;

        for (i = 0; i < FILE_CACHE; i++)
                fprintf(fp, "   cached_file[%2d]: %lx (%ld)\n",
                        i, ft->cached_file[i],
                        ft->cached_file_hits[i]);
        fprintf(fp, "        file_cache: %lx\n", (ulong)ft->file_cache);
        fprintf(fp, "  file_cache_index: %d\n", ft->file_cache_index);
        fprintf(fp, "  file_cache_fills: %ld\n", ft->file_cache_fills);

	for (i = 0; i < DENTRY_CACHE; i++)
		fprintf(fp, "  cached_dentry[%2d]: %lx (%ld)\n", 
			i, ft->cached_dentry[i],
			ft->cached_dentry_hits[i]);
	fprintf(fp, "      dentry_cache: %lx\n", (ulong)ft->dentry_cache);
	fprintf(fp, "dentry_cache_index: %d\n", ft->dentry_cache_index);
	fprintf(fp, "dentry_cache_fills: %ld\n", ft->dentry_cache_fills);

        for (i = 0; i < INODE_CACHE; i++)
                fprintf(fp, "  cached_inode[%2d]: %lx (%ld)\n",
                        i, ft->cached_inode[i],
                        ft->cached_inode_hits[i]);
        fprintf(fp, "       inode_cache: %lx\n", (ulong)ft->inode_cache);
        fprintf(fp, " inode_cache_index: %d\n", ft->inode_cache_index);
        fprintf(fp, " inode_cache_fills: %ld\n", ft->inode_cache_fills);

show_hit_rates:
        if (ft->file_cache_fills) {
                for (i = fhits = 0; i < FILE_CACHE; i++)
                        fhits += ft->cached_file_hits[i];

                fprintf(fp, "     file hit rate: %2ld%% (%ld of %ld)\n",
                        (fhits * 100)/ft->file_cache_fills,
                        fhits, ft->file_cache_fills);
	} 

        if (ft->dentry_cache_fills) {
                for (i = dhits = 0; i < DENTRY_CACHE; i++)
                        dhits += ft->cached_dentry_hits[i];

		fprintf(fp, "   dentry hit rate: %2ld%% (%ld of %ld)\n",
			(dhits * 100)/ft->dentry_cache_fills,
			dhits, ft->dentry_cache_fills);
	}

        if (ft->inode_cache_fills) {
                for (i = ihits = 0; i < INODE_CACHE; i++)
                        ihits += ft->cached_inode_hits[i];

		fprintf(fp, "    inode hit rate: %2ld%% (%ld of %ld)\n",
                        (ihits * 100)/ft->inode_cache_fills,
                        ihits, ft->inode_cache_fills);
	}
}

/*
 * Get the page count for the specific mapping
 */
static long
get_inode_nrpages(ulong i_mapping)
{
	char *address_space_buf;
	ulong nrpages;

	address_space_buf = GETBUF(SIZE(address_space));

	readmem(i_mapping, KVADDR, address_space_buf,
	    SIZE(address_space), "address_space buffer",
	    FAULT_ON_ERROR);
	nrpages = ULONG(address_space_buf + OFFSET(address_space_nrpages));

	FREEBUF(address_space_buf);

	return nrpages;
}

static void
dump_inode_page_cache_info(ulong inode)
{
	char *inode_buf;
	ulong i_mapping, nrpages, root_rnode, xarray, count;
	struct list_pair lp;
	char header[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];

	inode_buf = GETBUF(SIZE(inode));
	readmem(inode, KVADDR, inode_buf, SIZE(inode), "inode buffer",
	    FAULT_ON_ERROR);

	i_mapping = ULONG(inode_buf + OFFSET(inode_i_mapping));
	nrpages = get_inode_nrpages(i_mapping);

	sprintf(header, "%s  NRPAGES\n",
		mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "INODE"));
	fprintf(fp, "%s", header);

	fprintf(fp, "%s  %s\n\n",
		mkstring(buf1, VADDR_PRLEN,
		CENTER|RJUST|LONG_HEX,
		MKSTR(inode)),
		mkstring(buf2, strlen("NRPAGES"),
		RJUST|LONG_DEC,
		MKSTR(nrpages)));

	FREEBUF(inode_buf);

	if (!nrpages)
		return;

	xarray = root_rnode = count = 0;
	if (MEMBER_EXISTS("address_space", "i_pages") &&
	    (STREQ(MEMBER_TYPE_NAME("address_space", "i_pages"), "xarray") ||
	    (STREQ(MEMBER_TYPE_NAME("address_space", "i_pages"), "radix_tree_root") &&
	     MEMBER_EXISTS("radix_tree_root", "xa_head"))))
		xarray = i_mapping + OFFSET(address_space_page_tree);
	else 
		root_rnode = i_mapping + OFFSET(address_space_page_tree);

	lp.index = 0;
	lp.value = (void *)&dump_inode_page;

	if (root_rnode)
		count = do_radix_tree(root_rnode, RADIX_TREE_DUMP_CB, &lp);
	else if (xarray)
		count = do_xarray(xarray, XARRAY_DUMP_CB, &lp);

	if (count != nrpages)
		error(INFO, "%s page count: %ld  nrpages: %ld\n",
			root_rnode ? "radix tree" : "xarray",
			count, nrpages);

	return;
}

/*
 *  This command displays information about the open files of a context.
 *  For each open file descriptor the file descriptor number, a pointer
 *  to the file struct, pointer to the dentry struct, pointer to the inode 
 *  struct, indication of file type and pathname are printed.
 *  The argument can be a task address or a PID number; if no args, the 
 *  current context is used.
 *  If the flag -l is passed, any files held open in the kernel by the
 *  lockd server on behalf of an NFS client are displayed.
 */

void
cmd_files(void)
{
	int c;
	ulong value;
	struct task_context *tc;
	int subsequent;
	struct reference reference, *ref;
	char *refarg;
	int open_flags = 0;

        ref = NULL;
        refarg = NULL;

        while ((c = getopt(argcnt, args, "d:R:p:c")) != EOF) {
                switch(c)
		{
		case 'R':
			if (ref) {
				error(INFO, "only one -R option allowed\n");
				argerrs++;
			} else {
				ref = &reference;
        			BZERO(ref, sizeof(struct reference));
				ref->str = refarg = optarg;
			}
			break;

		case 'd':
			value = htol(optarg, FAULT_ON_ERROR, NULL);
			display_dentry_info(value);
			return;

		case 'p':
			if (VALID_MEMBER(address_space_page_tree) &&
			    VALID_MEMBER(inode_i_mapping)) {
				value = htol(optarg, FAULT_ON_ERROR, NULL);
				dump_inode_page_cache_info(value);
			} else
				option_not_supported('p');
			return;

		case 'c':
			if (VALID_MEMBER(address_space_nrpages) &&
			    VALID_MEMBER(inode_i_mapping))
				open_flags |= PRINT_NRPAGES;
			else
				option_not_supported('c');
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (!args[optind]) {
		if (!ref)
			print_task_header(fp, CURRENT_CONTEXT(), 0);

		open_files_dump(CURRENT_TASK(), open_flags, ref);

		return;
	}

	subsequent = 0;

	while (args[optind]) {

		if (ref && subsequent) {
                        BZERO(ref, sizeof(struct reference));
                        ref->str = refarg;
                }

                switch (str_to_context(args[optind], &value, &tc))
                {
                case STR_PID:
                        for (tc = pid_to_context(value); tc; tc = tc->tc_next) {
                                if (!ref)
                                        print_task_header(fp, tc, subsequent);
                                open_files_dump(tc->task, open_flags, ref);
                                fprintf(fp, "\n");
                        }
                        break;

                case STR_TASK:
                        if (!ref)
                                print_task_header(fp, tc, subsequent);
                        open_files_dump(tc->task, open_flags, ref);
                        break;

                case STR_INVALID:
                        error(INFO, "invalid task or pid value: %s\n",
                                args[optind]);
                        break;
                }

		subsequent++;
		optind++;
	}
}

#define FILES_REF_HEXNUM (0x1)
#define FILES_REF_DECNUM (0x2)
#define FILES_REF_FOUND  (0x4)

#define PRINT_FILE_REFERENCE()                  \
	if (!root_pwd_printed) {                \
        	print_task_header(fp, tc, 0);   \
                fprintf(fp, "%s", root_pwd);    \
		root_pwd_printed = TRUE;        \
	}                                       \
	if (!header_printed) {                  \
		fprintf(fp, "%s", files_header);\
                header_printed = TRUE;          \
	}                                       \
	fprintf(fp, "%s", buf4);                \
	ref->cmdflags |= FILES_REF_FOUND;

#define FILENAME_COMPONENT(P,C) \
        ((STREQ((P), "/") && STREQ((C), "/")) || \
	(!STREQ((C), "/") && strstr((P),(C))))  



/*
 *  open_files_dump() does the work for cmd_files().
 */

void
open_files_dump(ulong task, int flags, struct reference *ref)
{
        struct task_context *tc;
	ulong files_struct_addr; 
	ulong fdtable_addr = 0;
	char *files_struct_buf, *fdtable_buf = NULL;
	ulong fs_struct_addr;
	char *dentry_buf, *fs_struct_buf;
	char *ret ATTRIBUTE_UNUSED;
	ulong root_dentry, pwd_dentry;
	ulong root_inode, pwd_inode;
	ulong vfsmnt;
	int max_fdset = 0;
	int max_fds = 0;
	ulong open_fds_addr;
	int open_fds_size;
	ulong *open_fds;
	ulong fd;
	ulong file;
	ulong value;
	int i, j, use_path;
	int header_printed = 0;
	char root_pathname[BUFSIZE];
	char pwd_pathname[BUFSIZE];
	char files_header[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char root_pwd[BUFSIZE*4];
	int root_pwd_printed = 0;
	int file_dump_flags = 0;

	BZERO(root_pathname, BUFSIZE);
	BZERO(pwd_pathname, BUFSIZE);
	files_struct_buf = GETBUF(SIZE(files_struct));
	if (VALID_STRUCT(fdtable))
		fdtable_buf = GETBUF(SIZE(fdtable));
	fill_task_struct(task);

	if (flags & PRINT_NRPAGES) {
		sprintf(files_header, " FD%s%s%s%s%sNRPAGES%sTYPE%sPATH\n",
			space(MINSPACE),
			mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "INODE"),
			space(MINSPACE),
			mkstring(buf2, MAX(VADDR_PRLEN, strlen("I_MAPPING")),
			BITS32() ? (CENTER|RJUST) : (CENTER|LJUST), "I_MAPPING"),
			space(MINSPACE),
			space(MINSPACE),
			space(MINSPACE));
	} else {
		sprintf(files_header, " FD%s%s%s%s%s%s%sTYPE%sPATH\n",
			space(MINSPACE),
			mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "FILE"),
			space(MINSPACE),
			mkstring(buf2, VADDR_PRLEN, CENTER|LJUST, "DENTRY"),
			space(MINSPACE),
			mkstring(buf3, VADDR_PRLEN, CENTER|LJUST, "INODE"),
			space(MINSPACE),
			space(MINSPACE));
	}

	tc = task_to_context(task);

	if (ref) 
		ref->cmdflags = 0;

	fs_struct_addr = ULONG(tt->task_struct + OFFSET(task_struct_fs));

        if (fs_struct_addr) {
		fs_struct_buf = GETBUF(SIZE(fs_struct));
                readmem(fs_struct_addr, KVADDR, fs_struct_buf, SIZE(fs_struct), 
			"fs_struct buffer", FAULT_ON_ERROR);

		use_path = (MEMBER_TYPE("fs_struct", "root") == TYPE_CODE_STRUCT);
		if (use_path)
			root_dentry = ULONG(fs_struct_buf + OFFSET(fs_struct_root) +
				OFFSET(path_dentry));
		else
			root_dentry = ULONG(fs_struct_buf + OFFSET(fs_struct_root));

		if (root_dentry) {
			if (VALID_MEMBER(fs_struct_rootmnt)) {
                		vfsmnt = ULONG(fs_struct_buf +
                        		OFFSET(fs_struct_rootmnt));
				get_pathname(root_dentry, root_pathname, 
					BUFSIZE, 1, vfsmnt);
			} else if (use_path) {
				vfsmnt = ULONG(fs_struct_buf +
					OFFSET(fs_struct_root) +
					OFFSET(path_mnt));
				get_pathname(root_dentry, root_pathname, 
					BUFSIZE, 1, vfsmnt);
			} else {
				get_pathname(root_dentry, root_pathname, 
					BUFSIZE, 1, 0);
			}
		}

		if (use_path)
			pwd_dentry = ULONG(fs_struct_buf + OFFSET(fs_struct_pwd) +
				OFFSET(path_dentry));
		else
			pwd_dentry = ULONG(fs_struct_buf + OFFSET(fs_struct_pwd));

		if (pwd_dentry) {
			if (VALID_MEMBER(fs_struct_pwdmnt)) {
                		vfsmnt = ULONG(fs_struct_buf +
                        		OFFSET(fs_struct_pwdmnt));
				get_pathname(pwd_dentry, pwd_pathname, 
					BUFSIZE, 1, vfsmnt);
			} else if (use_path) {
				vfsmnt = ULONG(fs_struct_buf +
					OFFSET(fs_struct_pwd) +
					OFFSET(path_mnt));
				get_pathname(pwd_dentry, pwd_pathname, 
					BUFSIZE, 1, vfsmnt);

			} else {
				get_pathname(pwd_dentry, pwd_pathname, 
					BUFSIZE, 1, 0);
			}
		}

		if ((flags & PRINT_INODES) && root_dentry && pwd_dentry) {
			dentry_buf = fill_dentry_cache(root_dentry);
			root_inode = ULONG(dentry_buf + OFFSET(dentry_d_inode));
			dentry_buf = fill_dentry_cache(pwd_dentry);
			pwd_inode = ULONG(dentry_buf + OFFSET(dentry_d_inode));
			fprintf(fp, "ROOT: %lx %s    CWD: %lx %s\n", 
				root_inode, root_pathname, pwd_inode,
				pwd_pathname);
		} else if (ref) {
			snprintf(root_pwd, sizeof(root_pwd),
			     	"ROOT: %s    CWD: %s \n", 
				root_pathname, pwd_pathname);
			if (FILENAME_COMPONENT(root_pathname, ref->str) ||
			    FILENAME_COMPONENT(pwd_pathname, ref->str)) {
				print_task_header(fp, tc, 0);
				fprintf(fp, "%s", root_pwd); 
				root_pwd_printed = TRUE;
				ref->cmdflags |= FILES_REF_FOUND;
			}
		} else
			fprintf(fp, "ROOT: %s    CWD: %s\n", 
				root_pathname, pwd_pathname);

		FREEBUF(fs_struct_buf);
	}

	files_struct_addr = ULONG(tt->task_struct + OFFSET(task_struct_files));

	if (files_struct_addr) {
		readmem(files_struct_addr, KVADDR, files_struct_buf,
			SIZE(files_struct), "files_struct buffer",
			FAULT_ON_ERROR);
	
		if (VALID_MEMBER(files_struct_max_fdset)) {
			max_fdset = INT(files_struct_buf +
			OFFSET(files_struct_max_fdset));

			max_fds = INT(files_struct_buf +
			OFFSET(files_struct_max_fds));
		}
	}

	if (VALID_MEMBER(files_struct_fdt)) {
		fdtable_addr = ULONG(files_struct_buf + OFFSET(files_struct_fdt));

		if (fdtable_addr) {
			readmem(fdtable_addr, KVADDR, fdtable_buf,
	 			SIZE(fdtable), "fdtable buffer", FAULT_ON_ERROR); 
			if (VALID_MEMBER(fdtable_max_fdset))
				max_fdset = INT(fdtable_buf +
					OFFSET(fdtable_max_fdset));
			else
				max_fdset = -1;
			max_fds = INT(fdtable_buf +
        	                OFFSET(fdtable_max_fds));
		}
	}

	if ((VALID_MEMBER(files_struct_fdt) && !fdtable_addr) || 
	    !files_struct_addr || max_fdset == 0 || max_fds == 0) {
		if (ref) {
			if (ref->cmdflags & FILES_REF_FOUND)
				fprintf(fp, "\n");
		} else
			fprintf(fp, "No open files\n");
		if (fdtable_buf)
			FREEBUF(fdtable_buf);
		FREEBUF(files_struct_buf);
		return;
	}

        if (ref && IS_A_NUMBER(ref->str)) { 
                if (hexadecimal_only(ref->str, 0)) {
                        ref->hexval = htol(ref->str, FAULT_ON_ERROR, NULL);
                        ref->cmdflags |= FILES_REF_HEXNUM;
                } else {
			value = dtol(ref->str, FAULT_ON_ERROR, NULL);
			if (value <= MAX(max_fdset, max_fds)) {
                              	ref->decval = value;
                               	ref->cmdflags |= FILES_REF_DECNUM;
			} else {
                             	ref->hexval = htol(ref->str, 
					FAULT_ON_ERROR, NULL);
                                ref->cmdflags |= FILES_REF_HEXNUM;
			}
		}
        }

	if (VALID_MEMBER(fdtable_open_fds))
		open_fds_addr = ULONG(fdtable_buf +
			OFFSET(fdtable_open_fds));
	else
		open_fds_addr = ULONG(files_struct_buf +
			OFFSET(files_struct_open_fds));

	open_fds_size = MAX(max_fdset, max_fds) / BITS_PER_BYTE;	
	open_fds = (ulong *)GETBUF(open_fds_size);
	if (!open_fds) {
		if (fdtable_buf)
			FREEBUF(fdtable_buf);
		FREEBUF(files_struct_buf);
		return;
	}

	if (open_fds_addr) {
		if (VALID_MEMBER(files_struct_open_fds_init) && 
		    (open_fds_addr == (files_struct_addr + 
		    OFFSET(files_struct_open_fds_init)))) 
			BCOPY(files_struct_buf + 
			        OFFSET(files_struct_open_fds_init),
				open_fds, open_fds_size);
		else
			readmem(open_fds_addr, KVADDR, open_fds,
				open_fds_size, "fdtable open_fds",
				FAULT_ON_ERROR);
	} 

	if (VALID_MEMBER(fdtable_fd))
		fd = ULONG(fdtable_buf + OFFSET(fdtable_fd));
	else
		fd = ULONG(files_struct_buf + OFFSET(files_struct_fd));

	if (!open_fds_addr || !fd) {
                if (ref && (ref->cmdflags & FILES_REF_FOUND))
                	fprintf(fp, "\n");
		if (fdtable_buf)
			FREEBUF(fdtable_buf);
		FREEBUF(files_struct_buf);
		FREEBUF(open_fds);
		return;
	}

	file_dump_flags = DUMP_FULL_NAME | DUMP_EMPTY_FILE;
	if (flags & PRINT_NRPAGES)
		file_dump_flags |= DUMP_FILE_NRPAGES;

	j = 0;
	for (;;) {
		unsigned long set;
		i = j * BITS_PER_LONG;
		if (((max_fdset >= 0) && (i >= max_fdset)) || 
		    (i >= max_fds))
			 break;
		set = open_fds[j++];
		while (set) {
			if (set & 1) {
        			readmem(fd + i*sizeof(struct file *), KVADDR, 
					&file, sizeof(struct file *), 
					"fd file", FAULT_ON_ERROR);

				if (ref && file) {
					open_tmpfile();
                                        if (file_dump(file, 0, 0, i, file_dump_flags)) {
						BZERO(buf4, BUFSIZE);
						rewind(pc->tmpfile);
						ret = fgets(buf4, BUFSIZE, 
							pc->tmpfile);
						close_tmpfile();
						ref->refp = buf4;
						if (open_file_reference(ref)) { 
							PRINT_FILE_REFERENCE();
						}
					} else
						close_tmpfile();
				}
				else if (file) {
					if (!header_printed) {
						fprintf(fp, "%s", files_header);
						header_printed = 1;
					}
					file_dump(file, 0, 0, i, file_dump_flags);
				}
			}
			i++;
			set >>= 1;
		}
	}

	if (!header_printed && !ref)
		fprintf(fp, "No open files\n");

	if (ref && (ref->cmdflags & FILES_REF_FOUND))
		fprintf(fp, "\n");

	if (fdtable_buf)
		FREEBUF(fdtable_buf);
	FREEBUF(files_struct_buf);
	FREEBUF(open_fds);
}

/*
 *  Check an open file string for references.  
 */
static int
open_file_reference(struct reference *ref)
{
	char buf[BUFSIZE];
	char *arglist[MAXARGS];
	int i, fd, argcnt;
	ulong vaddr;

	strcpy(buf, ref->refp);
	if ((argcnt = parse_line(buf, arglist)) < 5)
		return FALSE;

	if (ref->cmdflags & (FILES_REF_HEXNUM|FILES_REF_DECNUM)) {
		fd = dtol(arglist[0], FAULT_ON_ERROR, NULL);
		if (((ref->cmdflags & FILES_REF_HEXNUM) && 
		    (fd == ref->hexval)) || 
                    ((ref->cmdflags & FILES_REF_DECNUM) &&
		    (fd == ref->decval))) {
			return TRUE;
		}

        	for (i = 1; i < 4; i++) {
			if (STREQ(arglist[i], "?"))
				continue;
        		vaddr = htol(arglist[i], FAULT_ON_ERROR, NULL);
        		if (vaddr == ref->hexval) 
        			return TRUE;
        	}
	}

	if (STREQ(ref->str, arglist[4])) {
		return TRUE;
	}

	if ((argcnt == 6) && FILENAME_COMPONENT(arglist[5], ref->str)) {
		return TRUE;
	}
	
	return FALSE;
}

#ifdef DEPRECATED
/*
 * nlm_files_dump() prints files held open by lockd server on behalf
 * of NFS clients
 */

#define FILE_NRHASH 32

char nlm_files_header[BUFSIZE] = { 0 };
char *nlm_header = \
"Files open by lockd for client discretionary file locks:\n";

void
nlm_files_dump(void)
{
	int header_printed = 0;
	int i, j, cnt;
	ulong nlmsvc_ops, nlm_files;
	struct syment *nsp;
	ulong nlm_files_array[FILE_NRHASH];
	struct list_data list_data, *ld;
	ulong *file, *files_list;
	ulong dentry, inode, flock, host, client;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];

        if (!strlen(nlm_files_header)) {
                sprintf(nlm_files_header,
                    "CLIENT               %s %s%sTYPE%sPATH\n",
                        mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "NLM_FILE"),
                        mkstring(buf2, VADDR_PRLEN, CENTER|LJUST, "INODE"),
                        space(MINSPACE),
                        space(MINSPACE));
        }

	if (!symbol_exists("nlm_files") || !symbol_exists("nlmsvc_ops")
	    || !symbol_exists("nfsd_nlm_ops")) {
		goto out;
	}
	get_symbol_data("nlmsvc_ops", sizeof(void *), &nlmsvc_ops);
	if (nlmsvc_ops != symbol_value("nfsd_nlm_ops")) {
		goto out;
	}
	if ((nsp = next_symbol("nlm_files", NULL)) == NULL) {
		error(WARNING, "cannot find next symbol after nlm_files\n");
		goto out;
	}
	nlm_files = symbol_value("nlm_files");
	if (((nsp->value - nlm_files) / sizeof(void *)) != FILE_NRHASH ) {
		error(WARNING, "FILE_NRHASH has changed from %d\n", 
		      FILE_NRHASH);
		if (((nsp->value - nlm_files) / sizeof(void *)) < 
		    FILE_NRHASH )
			goto out;
	}

	readmem(nlm_files, KVADDR, nlm_files_array, 
		sizeof(ulong) * FILE_NRHASH, "nlm_files array",
		FAULT_ON_ERROR);
	for (i = 0; i < FILE_NRHASH; i++) {
		if (nlm_files_array[i] == 0) {
			continue;
		}
		ld = &list_data;
		BZERO(ld, sizeof(struct list_data));	
		ld->start = nlm_files_array[i];
		hq_open();
		cnt = do_list(ld);
		files_list = (ulong *)GETBUF(cnt * sizeof(ulong));
		cnt = retrieve_list(files_list, cnt);
		hq_close();
		for (j=0, file = files_list; j<cnt; j++, file++) {
			readmem(*file + OFFSET(nlm_file_f_file) + 
				OFFSET(file_f_dentry), KVADDR, &dentry,
				sizeof(void *), "nlm_file dentry", 
				FAULT_ON_ERROR);
			if (!dentry)
				continue;
			readmem(dentry + OFFSET(dentry_d_inode), KVADDR, 
				&inode, sizeof(void *), "dentry d_inode",
				FAULT_ON_ERROR);
			if (!inode)
				continue;
			readmem(inode + OFFSET(inode_i_flock), KVADDR,
				&flock, sizeof(void *), "inode i_flock",
				FAULT_ON_ERROR);
			if (!flock)
				continue;
			readmem(flock + OFFSET(file_lock_fl_owner), KVADDR,
				&host, sizeof(void *), 
				"file_lock fl_owner", FAULT_ON_ERROR);
			if (!host)
				continue;
			readmem(host + OFFSET(nlm_host_h_exportent), KVADDR,
				&client, sizeof(void *), 
				"nlm_host h_exportent", FAULT_ON_ERROR);
			if (!client)
				continue;
			if (!read_string(client + OFFSET(svc_client_cl_ident), 
			    buf1, BUFSIZE-1))
				continue;
			if (!header_printed) {
				fprintf(fp, nlm_header);
				fprintf(fp, nlm_files_header);
				header_printed = 1;
			}

			fprintf(fp, "%-20s %8lx ", buf1, *file);
			file_dump(*file, dentry, inode, 0, 
				  DUMP_INODE_ONLY | DUMP_FULL_NAME);
		}
	}
out:
	if (!header_printed)
		fprintf(fp, "No lockd server files open for NFS clients\n");
}
#endif
	    
/*
 * file_dump() prints info for an open file descriptor
 */

int
file_dump(ulong file, ulong dentry, ulong inode, int fd, int flags)
{
	ulong vfsmnt;
	char *dentry_buf, *file_buf, *inode_buf, *type;
	char pathname[BUFSIZE];
	char *printpath;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	ulong i_mapping = 0;
	ulong nrpages = 0;

	file_buf = NULL;

	if (!dentry && file) {
		file_buf = fill_file_cache(file);		
		dentry = ULONG(file_buf + OFFSET(file_f_dentry));
	}

	if (!dentry) {
		if (flags & DUMP_EMPTY_FILE) {
			fprintf(fp, "%3d%s%s%s%s%s%s%s%s%s%s\n",
				fd,
				space(MINSPACE),
				mkstring(buf1, VADDR_PRLEN, 
				CENTER|RJUST|LONG_HEX, 
				MKSTR(file)),
				space(MINSPACE),
				mkstring(buf2, VADDR_PRLEN, 
				CENTER|LONG_HEX|ZERO_FILL, 
				MKSTR(dentry)),
				space(MINSPACE),
				mkstring(buf3, VADDR_PRLEN, 
				CENTER, 
				"?"),
				space(MINSPACE),
				"?   ",
				space(MINSPACE),
				"?");
			return TRUE;
		}
		return FALSE;
	}

	if (!inode) {
		dentry_buf = fill_dentry_cache(dentry);
		inode = ULONG(dentry_buf + OFFSET(dentry_d_inode));
	}

	if (!inode) { 
		if (flags & DUMP_EMPTY_FILE) {
			fprintf(fp, "%3d%s%s%s%s%s%s%s%s%s%s\n",
				fd,
				space(MINSPACE),
				mkstring(buf1, VADDR_PRLEN, 
				CENTER|RJUST|LONG_HEX, 
				MKSTR(file)),
				space(MINSPACE),
				mkstring(buf2, VADDR_PRLEN, 
				CENTER|RJUST|LONG_HEX, 
				MKSTR(dentry)),
				space(MINSPACE),
				mkstring(buf3, VADDR_PRLEN, 
				CENTER|LONG_HEX|ZERO_FILL, 
				MKSTR(inode)),
				space(MINSPACE),
				"?   ",
				space(MINSPACE),
				"?");
			return TRUE;
		}
		return FALSE;
	}

	inode_buf = fill_inode_cache(inode);

	if (flags & DUMP_FULL_NAME) {
		if (VALID_MEMBER(file_f_vfsmnt)) {
			vfsmnt = get_root_vfsmount(file_buf);
			get_pathname(dentry, pathname, BUFSIZE, 1, vfsmnt);
			if (STRNEQ(pathname, "/pts/") &&
			    STREQ(vfsmount_devname(vfsmnt, buf1, BUFSIZE),
			    "devpts"))
				string_insert("/dev", pathname);
		} else {
			get_pathname(dentry, pathname, BUFSIZE, 1, 0);
		}
	} else
		get_pathname(dentry, pathname, BUFSIZE, 0, 0);

	type = inode_type(inode_buf, pathname);

	if (flags & DUMP_FULL_NAME)
		printpath = pathname;
	else
		printpath = pathname+1;

	if (flags & DUMP_INODE_ONLY) {
		fprintf(fp, "%s%s%s%s%s\n",
			mkstring(buf1, VADDR_PRLEN, 
			CENTER|RJUST|LONG_HEX, 
			MKSTR(inode)),
			space(MINSPACE),
			type, 
			space(MINSPACE),
			printpath);
	} else {
		if (flags & DUMP_DENTRY_ONLY) {
			fprintf(fp, "%s%s%s%s%s%s%s\n",
				mkstring(buf1, VADDR_PRLEN, 
				CENTER|RJUST|LONG_HEX, 
				MKSTR(dentry)),
				space(MINSPACE),
				mkstring(buf2, VADDR_PRLEN, 
				CENTER|RJUST|LONG_HEX, 
				MKSTR(inode)),
				space(MINSPACE),
				type, 
				space(MINSPACE),
				pathname+1);
		} else if (flags & DUMP_FILE_NRPAGES) {
			i_mapping = ULONG(inode_buf + OFFSET(inode_i_mapping));
			nrpages = get_inode_nrpages(i_mapping);

			fprintf(fp, "%3d%s%s%s%s%s%s%s%s%s%s\n",
				fd,
				space(MINSPACE),
				mkstring(buf1, VADDR_PRLEN,
				CENTER|RJUST|LONG_HEX,
				MKSTR(inode)),
				space(MINSPACE),
				mkstring(buf2, MAX(VADDR_PRLEN, strlen("I_MAPPING")),
				CENTER|RJUST|LONG_HEX,
				MKSTR(i_mapping)),
				space(MINSPACE),
				mkstring(buf3, strlen("NRPAGES"),
				RJUST|LONG_DEC,
				MKSTR(nrpages)),
				space(MINSPACE),
				type,
				space(MINSPACE),
				pathname);
		} else {
                        fprintf(fp, "%3d%s%s%s%s%s%s%s%s%s%s\n",
                                fd,
                                space(MINSPACE),
				mkstring(buf1, VADDR_PRLEN, 
				CENTER|RJUST|LONG_HEX, 
				MKSTR(file)),
                                space(MINSPACE),
				mkstring(buf2, VADDR_PRLEN, 
				CENTER|RJUST|LONG_HEX, 
				MKSTR(dentry)),
                                space(MINSPACE),
				mkstring(buf3, VADDR_PRLEN, 
				CENTER|RJUST|LONG_HEX, 
				MKSTR(inode)),
                                space(MINSPACE),
                                type,
                                space(MINSPACE),
                                pathname);
		}
	}

	return TRUE;
}

/*
 *  Get the dentry associated with a file.
 */
ulong
file_to_dentry(ulong file)
{
        char *file_buf;
	ulong dentry;

        file_buf = fill_file_cache(file);
        dentry = ULONG(file_buf + OFFSET(file_f_dentry));
        return dentry;
}

/*
 *  Get the vfsmnt associated with a file.
 */
ulong
file_to_vfsmnt(ulong file)
{
	char *file_buf;
	ulong vfsmnt;

	file_buf = fill_file_cache(file);
	vfsmnt = ULONG(file_buf + OFFSET(file_f_vfsmnt));
	return vfsmnt;
}

/*
 * get_pathname() fills in a pathname string for an ending dentry
 * See __d_path() in the kernel for help fixing problems.
 */
void
get_pathname(ulong dentry, char *pathname, int length, int full, ulong vfsmnt)
{
	char buf[BUFSIZE];
	char tmpname[BUFSIZE];
	ulong tmp_dentry, parent;
	int d_name_len = 0;
	ulong d_name_name;
	ulong tmp_vfsmnt, mnt_parent;
	char *dentry_buf, *vfsmnt_buf, *mnt_buf;

	BZERO(buf, BUFSIZE);
	BZERO(tmpname, BUFSIZE);
	BZERO(pathname, length);
	if (VALID_STRUCT(mount)) {
		if (VALID_MEMBER(mount_mnt_mountpoint)) {
			mnt_buf = GETBUF(SIZE(mount));
			vfsmnt_buf = mnt_buf + OFFSET(mount_mnt);
		} else {
			mnt_buf = NULL;
			vfsmnt_buf = NULL;
		}
	} else {
		mnt_buf = NULL;
		vfsmnt_buf = VALID_MEMBER(vfsmount_mnt_mountpoint) ? 
			GETBUF(SIZE(vfsmount)) : NULL;
	}

	parent = dentry;
	tmp_vfsmnt = vfsmnt;

	do {
		tmp_dentry = parent;

		dentry_buf = fill_dentry_cache(tmp_dentry);

		d_name_len = INT(dentry_buf +
			OFFSET(dentry_d_name) + OFFSET(qstr_len));

		if (!d_name_len) 
			break;

		d_name_name = ULONG(dentry_buf + OFFSET(dentry_d_name) 
			+ OFFSET(qstr_name));

		if (!d_name_name)
			break;

		if (!get_pathname_component(tmp_dentry, d_name_name, d_name_len,
		     dentry_buf, buf))
			break;

		if (tmp_dentry != dentry) {
			strncpy(tmpname, pathname, BUFSIZE-1);
			if (strlen(tmpname) + d_name_len < BUFSIZE) {
				if ((d_name_len > 1 || !STREQ(buf, "/")) &&
				    !STRNEQ(tmpname, "/")) {
					sprintf(pathname, "%s%s%s", buf, 
						"/", tmpname);
				} else {
					sprintf(pathname, 
						"%s%s", buf, tmpname);
				}
			}
		} else {
			strncpy(pathname, buf, BUFSIZE);
		}

		parent = ULONG(dentry_buf + OFFSET(dentry_d_parent)); 
			
		if (tmp_dentry == parent && full) {
			if (VALID_MEMBER(vfsmount_mnt_mountpoint)) {
				if (tmp_vfsmnt) {
					if (strncmp(pathname, "//", 2) == 0)
						shift_string_left(pathname, 1);
                                        readmem(tmp_vfsmnt, KVADDR, vfsmnt_buf,
						SIZE(vfsmount), 
						"vfsmount buffer", 
						FAULT_ON_ERROR);
        				parent = ULONG(vfsmnt_buf + 
					    OFFSET(vfsmount_mnt_mountpoint));
        				mnt_parent = ULONG(vfsmnt_buf + 
					    OFFSET(vfsmount_mnt_parent));
					if (tmp_vfsmnt == mnt_parent)
						break;
					else
						tmp_vfsmnt = mnt_parent;
				}
			} else if (VALID_STRUCT(mount)) {
				if (tmp_vfsmnt) {
					if (strncmp(pathname, "//", 2) == 0)
						shift_string_left(pathname, 1);
                                        readmem(tmp_vfsmnt - OFFSET(mount_mnt),
						KVADDR, mnt_buf,
						SIZE(mount), 
						"mount buffer", 
						FAULT_ON_ERROR);
        				parent = ULONG(mnt_buf + 
					    OFFSET(mount_mnt_mountpoint));
        				mnt_parent = ULONG(mnt_buf + 
					    OFFSET(mount_mnt_parent));
					if ((tmp_vfsmnt - OFFSET(mount_mnt)) == mnt_parent)
						break;
					else
						tmp_vfsmnt = mnt_parent + OFFSET(mount_mnt);
				}
			}
			else {
				parent = ULONG(dentry_buf + 
					OFFSET(dentry_d_covers)); 
			}
		}
						
	} while (tmp_dentry != parent && parent);

	if (mnt_buf)
		FREEBUF(mnt_buf);
	else if (vfsmnt_buf)
		FREEBUF(vfsmnt_buf);
}

/*
 *  If the pathname component, which may be internal or external to the 
 *  dentry, has string length equal to what's expected, copy it into the
 *  passed-in buffer, and return its length.  If it doesn't match, return 0.
 */
static int
get_pathname_component(ulong dentry, 
		       ulong d_name_name,
		       int d_name_len,
		       char *dentry_buf, 
		       char *pathbuf)
{
	int len = d_name_len;   /* presume success */

        if (d_name_name == (dentry + OFFSET(dentry_d_iname))) {
                if (strlen(dentry_buf + OFFSET(dentry_d_iname)) == d_name_len)
                	strcpy(pathbuf, dentry_buf + OFFSET(dentry_d_iname));
                else
                        len = 0;
        } else if ((read_string(d_name_name, pathbuf, BUFSIZE)) != d_name_len)
                len = 0;

	return len;
}

/*
 *  Cache the passed-in file structure.
 */
char *
fill_file_cache(ulong file)
{
        int i;
        char *cache;

        ft->file_cache_fills++;

        for (i = 0; i < DENTRY_CACHE; i++) {
                if (ft->cached_file[i] == file) {
                        ft->cached_file_hits[i]++;
                        cache = ft->file_cache + (SIZE(file)*i);
                        return(cache);
                }
        }

        cache = ft->file_cache + (SIZE(file)*ft->file_cache_index);

        readmem(file, KVADDR, cache, SIZE(file),
                "fill_file_cache", FAULT_ON_ERROR);

        ft->cached_file[ft->file_cache_index] = file;

        ft->file_cache_index = (ft->file_cache_index+1) % DENTRY_CACHE;

        return(cache);
}

/*
 *  If active, clear the file references.
 */
void
clear_file_cache(void)
{
        int i;

        if (DUMPFILE())
                return;

        for (i = 0; i < DENTRY_CACHE; i++) {
                ft->cached_file[i] = 0;
                ft->cached_file_hits[i] = 0;
        }

        ft->file_cache_fills = 0;
        ft->file_cache_index = 0;
}



/*
 *  Cache the passed-in dentry structure.
 */
char *
fill_dentry_cache(ulong dentry)
{
	int i;
	char *cache;

	ft->dentry_cache_fills++;

        for (i = 0; i < DENTRY_CACHE; i++) {
                if (ft->cached_dentry[i] == dentry) {
			ft->cached_dentry_hits[i]++;
			cache = ft->dentry_cache + (SIZE(dentry)*i);
			return(cache);
		}
	}

	cache = ft->dentry_cache + (SIZE(dentry)*ft->dentry_cache_index);

        readmem(dentry, KVADDR, cache, SIZE(dentry),
        	"fill_dentry_cache", FAULT_ON_ERROR);

	ft->cached_dentry[ft->dentry_cache_index] = dentry;

	ft->dentry_cache_index = (ft->dentry_cache_index+1) % DENTRY_CACHE;

	return(cache);
}

/*
 *  If active, clear the dentry references.
 */
void
clear_dentry_cache(void)
{
	int i;

	if (DUMPFILE())
		return;

        for (i = 0; i < DENTRY_CACHE; i++) {
                ft->cached_dentry[i] = 0;
        	ft->cached_dentry_hits[i] = 0;
	}

        ft->dentry_cache_fills = 0;
	ft->dentry_cache_index = 0;
}

/*
 *  Cache the passed-in inode structure.
 */
char *
fill_inode_cache(ulong inode)
{
        int i;
        char *cache;

        ft->inode_cache_fills++;

        for (i = 0; i < INODE_CACHE; i++) {
                if (ft->cached_inode[i] == inode) {
                        ft->cached_inode_hits[i]++;
                        cache = ft->inode_cache + (SIZE(inode)*i);
                        return(cache);
                }
        }

        cache = ft->inode_cache + (SIZE(inode)*ft->inode_cache_index);

        readmem(inode, KVADDR, cache, SIZE(inode),
                "fill_inode_cache", FAULT_ON_ERROR);

        ft->cached_inode[ft->inode_cache_index] = inode;

        ft->inode_cache_index = (ft->inode_cache_index+1) % INODE_CACHE;

        return(cache);
}

/*      
 *  If active, clear the inode references.
 */
void
clear_inode_cache(void)
{
        int i; 
 
        if (DUMPFILE())
                return;
 
        for (i = 0; i < DENTRY_CACHE; i++) {
                ft->cached_inode[i] = 0;
                ft->cached_inode_hits[i] = 0;
        }

        ft->inode_cache_fills = 0;
        ft->inode_cache_index = 0;
}


/*
 *  This command displays the tasks using specified files or sockets.
 *  Tasks will be listed that reference the file as the current working
 *  directory, root directory, an open file descriptor, or that mmap the
 *  file.
 *  The argument can be a full pathname without symbolic links, or inode 
 *  address.
 */

void
cmd_fuser(void)
{
	int c;
	char *spec_string, *tmp;
	struct foreach_data foreach_data, *fd;
	char task_buf[BUFSIZE];
	char buf[BUFSIZE];
	char uses[20];
	char fuser_header[BUFSIZE];
	int doing_fds, doing_mmap, len;
	int fuser_header_printed, lockd_header_printed;

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

	if (!args[optind]) {
		cmd_usage(pc->curcmd, SYNOPSIS);
		return;
	}

	sprintf(fuser_header, " PID   %s  COMM             USAGE\n",
		mkstring(buf, VADDR_PRLEN, CENTER, "TASK"));

	doing_fds = doing_mmap = 0;
	while (args[optind]) {
                spec_string = args[optind];
		if (STRNEQ(spec_string, "0x") && hexadecimal(spec_string, 0))
			shift_string_left(spec_string, 2);
		len = strlen(spec_string);
		fuser_header_printed = 0;
		lockd_header_printed = 0;
		open_tmpfile();
		BZERO(&foreach_data, sizeof(struct foreach_data));
		fd = &foreach_data;
		fd->keyword_array[0] = FOREACH_FILES;
		fd->keyword_array[1] = FOREACH_VM;
		fd->keys = 2;
		fd->flags |= FOREACH_i_FLAG;
		foreach(fd);
		rewind(pc->tmpfile);
		BZERO(uses, 20);
		while (fgets(buf, BUFSIZE, pc->tmpfile)) {
			if (STRNEQ(buf, "PID:")) {
				if (!STREQ(uses, "")) {
					if (!fuser_header_printed) {
						fprintf(pc->saved_fp,
							"%s", fuser_header);
						fuser_header_printed = 1;
					}
					show_fuser(task_buf, uses);
					BZERO(uses, 20);
				}
				BZERO(task_buf, BUFSIZE);
				strcpy(task_buf, buf);
				doing_fds = doing_mmap = 0;
				continue;
			}
			if (STRNEQ(buf, "ROOT:")) {
				if ((tmp = strstr(buf, spec_string)) &&
				    (tmp[len] == ' ' || tmp[len] == '\n')) {
					if (strstr(tmp, "CWD:")) {
						strcat(uses, "root ");
						if ((tmp = strstr(tmp+len,
						    spec_string)) &&
						    (tmp[len] == ' ' || 
						     tmp[len] == '\n')) {
							strcat(uses, "cwd ");
						}
					} else {
						strcat(uses, "cwd ");
					}
				}
				continue;
			}
			if (strstr(buf, "DENTRY")) {
				doing_fds = 1;
				continue;
			}
			if (strstr(buf, "TOTAL_VM")) {
				doing_fds = 0;
				continue;
			}
			if (strstr(buf, " VMA ")) {
				doing_mmap = 1;
				doing_fds = 0;
				continue;
			}
			if ((tmp = strstr(buf, spec_string)) &&
			    (tmp[len] == ' ' || tmp[len] == '\n')) {
				if (doing_fds) {
					strcat(uses, "fd ");
					doing_fds = 0;
				}
				if (doing_mmap) {
					strcat(uses, "mmap ");
					doing_mmap = 0;
				}
			}

		}
		if (!STREQ(uses, "")) {
			if (!fuser_header_printed) {
				fprintf(pc->saved_fp, "%s", fuser_header);
				fuser_header_printed = 1;
			}
			show_fuser(task_buf, uses);
			BZERO(uses, 20);
		}
		close_tmpfile();
		optind++;
		if (!fuser_header_printed && !lockd_header_printed) {
			fprintf(fp, "No users of %s found\n", spec_string);
		}
	}
}

static void
show_fuser(char *buf, char *uses)
{
	char pid[10];
	char task[20];
	char command[20];
	char *p;
	int i;

	BZERO(pid, 10);
	BZERO(task, 20);
	BZERO(command, 20);
	p = strstr(buf, "PID: ") + strlen("PID: ");
	i = 0;
	while (*p != ' ' && i < 10) {
		pid[i++] = *p++;
	}
	pid[i] = NULLCHAR;

	p = strstr(buf, "TASK: ") + strlen("TASK: ");
	while (*p == ' ')
		p++;
	i = 0;
	while (*p != ' ' && i < 20) {
		task[i++] = *p++;
	}
	task[i] = NULLCHAR;
	mkstring(task, VADDR_PRLEN, RJUST, task);

	p = strstr(buf, "COMMAND: ") + strlen("COMMAND: ");
	strncpy(command, p, 16);
	i = strlen(command) - 1;
	while (i < 16) {
		command[i++] = ' ';
	}
	command[16] = NULLCHAR;

        fprintf(pc->saved_fp, "%5s  %s  %s %s\n",
                pid, task, command, uses);
}


/*
 *  Gather some host memory/swap statistics, passing back whatever the
 *  caller requires.
 */

int
monitor_memory(long *freemem_pages, 
	       long *freeswap_pages, 
	       long *mem_usage,
	       long *swap_usage)
{
	FILE *mp;
	char buf[BUFSIZE];
        char *arglist[MAXARGS];
        int argc ATTRIBUTE_UNUSED;
        int params;
	ulong freemem, memtotal, freeswap, swaptotal;

	if (!file_exists("/proc/meminfo", NULL))
		return FALSE;

	if ((mp = fopen("/proc/meminfo", "r")) == NULL)
		return FALSE;

	params = 0;
	freemem = memtotal = freeswap = swaptotal = 0;

	while (fgets(buf, BUFSIZE, mp)) {
		if (strstr(buf, "SwapFree")) {
			params++;
			argc = parse_line(buf, arglist);
			if (decimal(arglist[1], 0)) 
				freeswap = (atol(arglist[1]) * 1024)/PAGESIZE();
		}
		
		if (strstr(buf, "MemFree")) {
			params++;
                        argc = parse_line(buf, arglist);
                        if (decimal(arglist[1], 0)) 
                                freemem = (atol(arglist[1]) * 1024)/PAGESIZE();
                }

                if (strstr(buf, "MemTotal")) {
			params++;
                        argc = parse_line(buf, arglist);
                        if (decimal(arglist[1], 0))
                                memtotal = (atol(arglist[1]) * 1024)/PAGESIZE();
                }

                if (strstr(buf, "SwapTotal")) {
                        params++;
                        argc = parse_line(buf, arglist);
                        if (decimal(arglist[1], 0))
                               swaptotal = (atol(arglist[1]) * 1024)/PAGESIZE();
                }

	}

	fclose(mp);

	if (params != 4)
		return FALSE;

	if (freemem_pages)
		*freemem_pages = freemem;
	if (freeswap_pages)
        	*freeswap_pages = freeswap;
	if (mem_usage)
		*mem_usage = ((memtotal-freemem)*100) / memtotal; 
	if (swap_usage)
		*swap_usage = ((swaptotal-freeswap)*100) / swaptotal;

	return TRUE;
}

/*
 *  Determine whether two filenames reference the same file.
 */
int
same_file(char *f1, char *f2)
{
	struct stat stat1, stat2;

	if ((stat(f1, &stat1) != 0) || (stat(f2, &stat2) != 0))
		return FALSE;

	if ((stat1.st_dev == stat2.st_dev) &&
	    (stat1.st_ino == stat2.st_ino))
		return TRUE;

	return FALSE;
}


/*
 *  Determine which live memory source to use.
 */

#define MODPROBE_CMD "/sbin/modprobe -l --type drivers/char 2>&1"

static void 
get_live_memory_source(void)
{
	FILE *pipe;
	char buf[BUFSIZE];
	char modname1[BUFSIZE/2];
	char modname2[BUFSIZE/2];
	char *name;
	int use_module, crashbuiltin;
	struct stat stat1, stat2;
	struct utsname utsname;

	if (!(pc->flags & PROC_KCORE))
		pc->flags |= DEVMEM;
	if (pc->live_memsrc)
		goto live_report;

	if (file_readable("/dev/mem"))
		pc->live_memsrc = "/dev/mem";
	else if (file_exists("/proc/kcore", NULL)) {
		pc->flags &= ~DEVMEM;
		pc->flags |= PROC_KCORE;
		pc->live_memsrc = "/proc/kcore";
	}
	use_module = crashbuiltin = FALSE;

	if (file_exists("/dev/mem", &stat1) &&
	    file_exists(pc->memory_device, &stat2) &&
	    S_ISCHR(stat1.st_mode) && S_ISCHR(stat2.st_mode) &&
	    (stat1.st_rdev == stat2.st_rdev)) { 
		if (!STREQ(pc->memory_device, "/dev/mem"))
			error(INFO, "%s: same device as /dev/mem\n%s", 
				pc->memory_device, 
				pc->memory_module ? "" : "\n");
		if (pc->memory_module)
			error(INFO, "ignoring --memory_module %s request\n\n", 
				pc->memory_module);
	} else if (pc->memory_module && memory_driver_module_loaded(NULL)) {
		error(INFO, "using pre-loaded \"%s\" module\n\n", 
			pc->memory_module);
		pc->flags |= MODPRELOAD;
		use_module = TRUE;
	} else {
		pc->memory_module = MEMORY_DRIVER_MODULE;

        	if ((pipe = popen(MODPROBE_CMD, "r")) == NULL) {
			error(INFO, "%s: %s\n", MODPROBE_CMD, strerror(errno));
                	return;
		}

		sprintf(modname1, "%s.o", pc->memory_module);
                sprintf(modname2, "%s.ko", pc->memory_module);
	        while (fgets(buf, BUFSIZE, pipe)) {
			if (strstr(buf, "invalid option") && 
			    (uname(&utsname) == 0)) {
				sprintf(buf, 
				    "/lib/modules/%s/kernel/drivers/char/%s", 
					utsname.release, modname2);
				if (file_exists(buf, &stat1))
					use_module = TRUE;
				else {
					strcat(buf, ".xz");
					if (file_exists(buf, &stat1))
						use_module = TRUE;
				}
				break;
			}
			name = basename(strip_linefeeds(buf));
			if (STREQ(name, modname1) || STREQ(name, modname2)) {
				use_module = TRUE;
				break;
			}
		}

		pclose(pipe);

		if (!use_module && file_exists("/dev/crash", &stat1) && 
		    S_ISCHR(stat1.st_mode))
			crashbuiltin = TRUE;
	}

	if (use_module) {
		pc->flags &= ~(DEVMEM|PROC_KCORE);
		pc->flags |= MEMMOD;
		pc->readmem = read_memory_device;
		pc->writemem = write_memory_device;
		pc->live_memsrc = pc->memory_device;
	}

	if (crashbuiltin) {
		pc->flags &= ~(DEVMEM|PROC_KCORE);
		pc->flags |= CRASHBUILTIN;
		pc->readmem = read_memory_device;
		pc->writemem = write_memory_device;
		pc->live_memsrc = pc->memory_device;
		pc->memory_module = NULL;
	}

live_report:
	if (CRASHDEBUG(1)) 
		fprintf(fp, "get_live_memory_source: %s\n", pc->live_memsrc);
}

/*
 *  Read /proc/modules to determine whether the crash driver module
 *  has been loaded.
 */
static int
memory_driver_module_loaded(int *count)
{
        FILE *modules;
        int argcnt, module_loaded;
        char *arglist[MAXARGS];
	char buf[BUFSIZE];

        if ((modules = fopen("/proc/modules", "r")) == NULL) {
                error(INFO, "/proc/modules: %s\n", strerror(errno));
                return FALSE;
        }

        module_loaded = FALSE;
        while (fgets(buf, BUFSIZE, modules)) {
		console("%s", buf);
                argcnt = parse_line(buf, arglist);
                if (argcnt < 3) 
                        continue;
                if (STREQ(arglist[0], pc->memory_module)) {
                        module_loaded = TRUE;
                        if (CRASHDEBUG(1))
                                fprintf(stderr, 
				    "\"%s\" module loaded: [%s][%s][%s]\n", 
					arglist[0], arglist[0],
					arglist[1], arglist[2]);
			if (count) 
				*count = atoi(arglist[2]);
                        break;
                }
        }

        fclose(modules);
	
	return module_loaded;
}

/*
 *  Insmod the memory driver module.
 */
static int
insmod_memory_driver_module(void)
{
        FILE *pipe;
	char buf[BUFSIZE];
	char command[BUFSIZE];

	sprintf(command, "/sbin/modprobe %s", pc->memory_module);
	if (CRASHDEBUG(1))
		fprintf(fp, "%s\n", command);

        if ((pipe = popen(command, "r")) == NULL) {
		error(INFO, "%s: %s", command, strerror(errno));
		return FALSE;
	}

        while (fgets(buf, BUFSIZE, pipe))
        	fprintf(fp, "%s\n", buf);
        pclose(pipe);

	if (!memory_driver_module_loaded(NULL)) {
		error(INFO, "cannot insmod \"%s\" module\n", pc->memory_module);
		return FALSE;
	}

	return TRUE;
}

/*
 *  Return the dev_t for the memory device driver.  The major number will
 *  be that of the kernel's misc driver; the minor is dynamically created
 *  when the module at inmod time, and found in /proc/misc.
 */
static int
get_memory_driver_dev(dev_t *devp)
{
	char buf[BUFSIZE];
        char *arglist[MAXARGS];
        int argcnt;
	FILE *misc;
	int minor;
	dev_t dev;

	dev = 0;

        if ((misc = fopen("/proc/misc", "r")) == NULL) { 
		error(INFO, "/proc/misc: %s", strerror(errno));
        } else {
        	while (fgets(buf, BUFSIZE, misc)) {
                	argcnt = parse_line(buf, arglist);
			if ((argcnt == 2) && 
			    STREQ(arglist[1], pc->memory_module)) {
				minor = atoi(arglist[0]);
				dev = makedev(MISC_MAJOR, minor);
				if (CRASHDEBUG(1))
					fprintf(fp, 
					    "/proc/misc: %s %s => %d/%d\n",
						arglist[0], arglist[1], 
						major(dev), minor(dev));
				break;
			}
		}
		fclose(misc);
	}

	if (!dev) {
		error(INFO, "cannot determine minor number of %s driver\n",
			pc->memory_module); 
		return FALSE;
	}

	*devp = dev;
	return TRUE;
}

/*
 *  Deal with the creation or verification of the memory device file:
 *
 *   1. If the device exists, and has the correct major/minor device numbers,
 *      nothing needs to be done.
 *   2. If the filename exists, but it's not a device file, has the wrong
 *      major/minor device numbers, or the wrong permissions, advise the
 *      user to delete it.
 *   3. Otherwise, create it.
 */
static int 
create_memory_device(dev_t dev)
{
	struct stat stat;

	if (file_exists(pc->live_memsrc, &stat)) {
		/*
		 *  It already exists -- just use it.
		 */
		if ((stat.st_mode == MEMORY_DRIVER_DEVICE_MODE) && 
		    (stat.st_rdev == dev))
			return TRUE;

		/*
		 *  Either it's not a device special file, or it's got
		 *  the wrong major/minor numbers, or the wrong permissions.
		 *  Unlink the file -- it shouldn't be there.
		 */
		if (!S_ISCHR(stat.st_mode)) 
			error(FATAL, 
			    "%s: not a character device -- please delete it!\n",
				pc->live_memsrc);
		else if (dev != stat.st_rdev) 
			error(FATAL, 
			    "%s: invalid device: %d/%d  -- please delete it!\n",
				pc->live_memsrc, major(stat.st_rdev), 
				minor(stat.st_rdev));
		else 
			unlink(pc->live_memsrc);
	} 

	/* 
	 *  Either it doesn't exist or it was just unlinked.
	 *  In either case, try to create it.
	 */
	if (mknod(pc->live_memsrc, MEMORY_DRIVER_DEVICE_MODE, dev)) {
		error(INFO, "%s: mknod: %s\n", pc->live_memsrc,
			strerror(errno));
		return FALSE;
	}

	return TRUE;
}

/*
 *  If we're here, the memory driver module is being requested:
 *
 *   1. If /dev/crash is built into the kernel, just open it.
 *   2. If the module is not already loaded, insmod it.
 *   3. Determine the misc driver minor device number that it was assigned.
 *   4. Create (or verify) the device file.
 *   5. Then just open it.
 */ 

static int 
memory_driver_init(void)
{
	dev_t dev;

	if (pc->flags & CRASHBUILTIN)
		goto open_device;

	if (!memory_driver_module_loaded(NULL)) {
	    	if (!insmod_memory_driver_module()) 
			return FALSE;
	} else
		pc->flags |= MODPRELOAD;

	if (!get_memory_driver_dev(&dev)) 
		return FALSE;

	if (!create_memory_device(dev)) 
		return FALSE;

open_device:
	if ((pc->mfd = open(pc->memory_device, O_RDONLY)) < 0) { 
		error(INFO, "%s: open: %s\n", pc->memory_device, 
			strerror(errno));
		return FALSE;
	}

	return TRUE;
}

/*
 *  Remove the memory driver module and associated file.
 */
int
cleanup_memory_driver(void)
{
	int errors, count;
        char command[BUFSIZE];

	count = errors = 0;

	if (pc->flags & KERNEL_DEBUG_QUERY)
		return TRUE;

	close(pc->mfd);
	if (file_exists(pc->memory_device, NULL) &&
	    unlink(pc->memory_device)) {
                error(INFO, "%s: %s\n", pc->memory_device, strerror(errno));
		errors++;
	}

	if (!(pc->flags & MODPRELOAD) && 
	    memory_driver_module_loaded(&count) && !count) {
	        sprintf(command, "/sbin/rmmod %s", pc->memory_module);
		if (CRASHDEBUG(1))
			fprintf(fp, "%s\n", command);
		errors += system(command);
	}

	if (errors)
		error(NOTE, "cleanup_memory_driver failed\n");

	return errors ? FALSE : TRUE;
}

struct do_radix_tree_info {
	ulong maxcount;
	ulong count;
	void *data;
};
static void do_radix_tree_count(ulong node, ulong slot, const char *path,
				ulong index, void *private)
{
	struct do_radix_tree_info *info = private;
	info->count++;
}
static void do_radix_tree_search(ulong node, ulong slot, const char *path,
				 ulong index, void *private)
{
	struct do_radix_tree_info *info = private;
	struct list_pair *rtp = info->data;

	if (rtp->index == index) {
		rtp->value = (void *)slot;
		info->count = 1;
	}
}
static void do_radix_tree_dump(ulong node, ulong slot, const char *path,
			       ulong index, void *private)
{
	struct do_radix_tree_info *info = private;
	fprintf(fp, "[%ld] %lx\n", index, slot);
	info->count++;
}
static void do_radix_tree_gather(ulong node, ulong slot, const char *path,
				 ulong index, void *private)
{
	struct do_radix_tree_info *info = private;
	struct list_pair *rtp = info->data;

	if (info->maxcount) {
		rtp[info->count].index = index;
		rtp[info->count].value = (void *)slot;

		info->count++;
		info->maxcount--;
	}
}
static void do_radix_tree_dump_cb(ulong node, ulong slot, const char *path,
				  ulong index, void *private)
{
	struct do_radix_tree_info *info = private;
	struct list_pair *rtp = info->data;
	int (*cb)(ulong) = rtp->value;

	/* Caller defined operation */
	if (!cb(slot)) {
		if ((slot & RADIX_TREE_ENTRY_MASK) == RADIX_TREE_EXCEPTIONAL_ENTRY) {
			if (CRASHDEBUG(1))
				error(INFO, "RADIX_TREE_EXCEPTIONAL_ENTRY: %lx\n", slot); 
			return;
		}
		error(FATAL, "do_radix_tree: callback "
		      "operation failed: entry: %ld  item: %lx\n",
		      info->count, slot);
	}
	info->count++;
}

/*
 *  do_radix_tree argument usage: 
 *
 *    root: Address of a radix_tree_root structure
 *
 *    flag: RADIX_TREE_COUNT - Return the number of entries in the tree.   
 *          RADIX_TREE_SEARCH - Search for an entry at rtp->index; if found,
 *            store the entry in rtp->value and return a count of 1; otherwise
 *            return a count of 0. 
 *          RADIX_TREE_DUMP - Dump all existing index/value pairs.    
 *          RADIX_TREE_GATHER - Store all existing index/value pairs in the 
 *            passed-in array of list_pair structs starting at rtp, 
 *            returning the count of entries stored; the caller can/should 
 *            limit the number of returned entries by putting the array size
 *            (max count) in the rtp->index field of the first structure 
 *            in the passed-in array.
 *          RADIX_TREE_DUMP_CB - Similar with RADIX_TREE_DUMP, but for each
 *            radix tree entry, a user defined callback at rtp->value will
 *            be invoked.
 *
 *     rtp: Unused by RADIX_TREE_COUNT and RADIX_TREE_DUMP. 
 *          A pointer to a list_pair structure for RADIX_TREE_SEARCH.
 *          A pointer to an array of list_pair structures for
 *          RADIX_TREE_GATHER; the dimension (max count) of the array may
 *          be stored in the index field of the first structure to avoid
 *          any chance of an overrun.
 *          For RADIX_TREE_DUMP_CB, the rtp->value must be initialized as a
 *          callback function.  The callback prototype must be: int (*)(ulong);
 */
ulong
do_radix_tree(ulong root, int flag, struct list_pair *rtp)
{
	struct do_radix_tree_info info = {
		.count		= 0,
		.data		= rtp,
	};
	struct radix_tree_ops ops = {
		.radix		= 16,
		.private	= &info,
	};

	switch (flag)
	{
	case RADIX_TREE_COUNT:
		ops.entry = do_radix_tree_count;
		break;

	case RADIX_TREE_SEARCH:
		/*
		 * FIXME: do_radix_tree_traverse() traverses whole
		 * radix tree, not binary search. So this search is
		 * not efficient.
		 */
		ops.entry = do_radix_tree_search;
		break;

	case RADIX_TREE_DUMP:
		ops.entry = do_radix_tree_dump;
		break;

	case RADIX_TREE_GATHER:
		if (!(info.maxcount = rtp->index))
			info.maxcount = (ulong)(-1);   /* caller beware */

		ops.entry = do_radix_tree_gather;
		break;

	case RADIX_TREE_DUMP_CB:
		if (rtp->value == NULL) {
			error(FATAL, "do_radix_tree: need set callback function");
			return -EINVAL;
		}
		ops.entry = do_radix_tree_dump_cb;
		break;

	default:
		error(FATAL, "do_radix_tree: invalid flag: %lx\n", flag);
	}

	do_radix_tree_traverse(root, 1, &ops);
	return info.count;
}


struct do_xarray_info {
	ulong maxcount;
	ulong count;
	void *data;
};
static void do_xarray_count(ulong node, ulong slot, const char *path,
				ulong index, void *private)
{
	struct do_xarray_info *info = private;
	info->count++;
}
static void do_xarray_search(ulong node, ulong slot, const char *path,
				 ulong index, void *private)
{
	struct do_xarray_info *info = private;
	struct list_pair *xp = info->data;

	if (xp->index == index) {
		xp->value = (void *)slot;
		info->count = 1;
	}
}
static void do_xarray_dump(ulong node, ulong slot, const char *path,
			       ulong index, void *private)
{
	struct do_xarray_info *info = private;
	fprintf(fp, "[%ld] %lx\n", index, slot);
	info->count++;
}
static void do_xarray_gather(ulong node, ulong slot, const char *path,
				 ulong index, void *private)
{
	struct do_xarray_info *info = private;
	struct list_pair *xp = info->data;

	if (info->maxcount) {
		xp[info->count].index = index;
		xp[info->count].value = (void *)slot;

		info->count++;
		info->maxcount--;
	}
}
static void do_xarray_dump_cb(ulong node, ulong slot, const char *path,
				  ulong index, void *private)
{
	struct do_xarray_info *info = private;
	struct list_pair *xp = info->data;
	int (*cb)(ulong) = xp->value;

	/* Caller defined operation */
	if (!cb(slot)) {
		if (slot & XARRAY_TAG_MASK) {
			if (CRASHDEBUG(1))
				error(INFO, "entry has XARRAY_TAG_MASK bits set: %lx\n", slot); 
			return;
		}
		error(FATAL, "do_xarray: callback "
		      "operation failed: entry: %ld  item: %lx\n",
		      info->count, slot);
	}
	info->count++;
}

/*
 *  do_xarray argument usage: 
 *
 *    root: Address of a xarray structure
 *
 *    flag: XARRAY_COUNT - Return the number of entries in the tree.   
 *          XARRAY_SEARCH - Search for an entry at xp->index; if found,
 *            store the entry in xp->value and return a count of 1; otherwise
 *            return a count of 0. 
 *          XARRY_DUMP - Dump all existing index/value pairs.    
 *          XARRAY_GATHER - Store all existing index/value pairs in the 
 *            passed-in array of list_pair structs starting at xp, 
 *            returning the count of entries stored; the caller can/should 
 *            limit the number of returned entries by putting the array size
 *            (max count) in the xp->index field of the first structure 
 *            in the passed-in array.
 *          XARRAY_DUMP_CB - Similar with XARRAY_DUMP, but for each
 *            xarray entry, a user defined callback at xp->value will
 *            be invoked.
 *
 *      xp: Unused by XARRAY_COUNT and XARRAY_DUMP. 
 *          A pointer to a list_pair structure for XARRAY_SEARCH.
 *          A pointer to an array of list_pair structures for
 *          XARRAY_GATHER; the dimension (max count) of the array may
 *          be stored in the index field of the first structure to avoid
 *          any chance of an overrun.
 *          For XARRAY_DUMP_CB, the rtp->value must be initialized as a
 *          callback function.  The callback prototype must be: int (*)(ulong);
 */
ulong
do_xarray(ulong root, int flag, struct list_pair *xp)
{
	struct do_xarray_info info = {
		.count		= 0,
		.data		= xp,
	};
	struct xarray_ops ops = {
		.radix		= 16,
		.private	= &info,
	};

	switch (flag)
	{
	case XARRAY_COUNT:
		ops.entry = do_xarray_count;
		break;

	case XARRAY_SEARCH:
		ops.entry = do_xarray_search;
		break;

	case XARRAY_DUMP:
		ops.entry = do_xarray_dump;
		break;

	case XARRAY_GATHER:
		if (!(info.maxcount = xp->index))
			info.maxcount = (ulong)(-1);   /* caller beware */

		ops.entry = do_xarray_gather;
		break;

	case XARRAY_DUMP_CB:
		if (xp->value == NULL) {
			error(FATAL, "do_xarray: no callback function specified");
			return -EINVAL;
		}
		ops.entry = do_xarray_dump_cb;
		break;

	default:
		error(FATAL, "do_xarray: invalid flag: %lx\n", flag);
	}

	do_xarray_traverse(root, 1, &ops);
	return info.count;
}

int
is_readable(char *filename)
{
	int fd;

        if ((fd = open(filename, O_RDONLY)) < 0) {
		error(INFO, "%s: %s\n", filename, strerror(errno));
		return FALSE;
	} else
		close(fd);

	return TRUE;
}

static int
match_file_string(char *filename, char *string, char *buffer)
{
	int found;
	char command[BUFSIZE];
	FILE *pipe;


	sprintf(command, "/usr/bin/strings %s", filename);
        if ((pipe = popen(command, "r")) == NULL) {
                error(INFO, "%s: %s\n", filename, strerror(errno));
                return FALSE;
        }

        found = FALSE;
        while (fgets(buffer, BUFSIZE-1, pipe)) {
                if (strstr(buffer, string)) {
                        found = TRUE;
                        break;
                }
        }
        pclose(pipe);

	return found;
}

char *
vfsmount_devname(ulong vfsmnt, char *buf, int maxlen)
{
	ulong devp;

	BZERO(buf, maxlen);

	if (VALID_STRUCT(mount)) {
		if (!readmem(vfsmnt - OFFSET(mount_mnt) + OFFSET(mount_mnt_devname),
		    KVADDR, &devp, sizeof(void *), "mount mnt_devname", 
		    QUIET|RETURN_ON_ERROR))
			return buf;
	} else {
		if (!readmem(vfsmnt + OFFSET(vfsmount_mnt_devname),
		    KVADDR, &devp, sizeof(void *), "vfsmount mnt_devname", 
		    QUIET|RETURN_ON_ERROR))
			return buf;
	}

	if (read_string(devp, buf, BUFSIZE-1))
		return buf;

	return buf;
}

static ulong
get_root_vfsmount(char *file_buf)
{
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	ulong vfsmnt;
	ulong mnt_parent;

	vfsmnt = ULONG(file_buf + OFFSET(file_f_vfsmnt));

	if (!strlen(vfsmount_devname(vfsmnt, buf1, BUFSIZE)))
		return vfsmnt;

	if (STREQ(buf1, "udev") || STREQ(buf1, "devtmpfs")) {
		if (VALID_STRUCT(mount)) {
			if (!readmem(vfsmnt - OFFSET(mount_mnt) + OFFSET(mount_mnt_parent), KVADDR, 
			    &mnt_parent, sizeof(void *), "mount mnt_parent", 
			    QUIET|RETURN_ON_ERROR))
				return vfsmnt;
		} else {
			if (!readmem(vfsmnt + OFFSET(vfsmount_mnt_parent), KVADDR, 
			    &mnt_parent, sizeof(void *), "vfsmount mnt_parent", 
			    QUIET|RETURN_ON_ERROR))
				return vfsmnt;
		}

		if (!strlen(vfsmount_devname(mnt_parent, buf2, BUFSIZE)))
			return vfsmnt;

		if (STREQ(buf1, "udev") && STREQ(buf2, "udev"))
			return mnt_parent;
		if (STREQ(buf1, "devtmpfs") && STREQ(buf2, "devtmpfs"))
			return mnt_parent;
	}

	return vfsmnt;
}

void
check_live_arch_mismatch(void)
{
	struct utsname utsname;

	if (machine_type("X86") && (uname(&utsname) == 0) &&
	    STRNEQ(utsname.machine, "x86_64"))
                error(FATAL, "compiled for the X86 architecture\n");

#if defined(__i386__) || defined(__x86_64__) 
	if (machine_type("ARM"))
		error(FATAL, "compiled for the ARM architecture\n");
#endif
#ifdef __x86_64__
	if (machine_type("ARM64"))
		error(FATAL, "compiled for the ARM64 architecture\n");
#endif
#ifdef __x86_64__ 
	if (machine_type("PPC64"))
		error(FATAL, "compiled for the PPC64 architecture\n");
#endif
#ifdef __powerpc64__
	if (machine_type("PPC"))
		error(FATAL, "compiled for the PPC architecture\n");
#endif
}
