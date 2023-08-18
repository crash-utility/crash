/* main.c - core analysis suite
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
#include "xen_hyper_defs.h"
#include <curses.h>
#include <getopt.h>
#include <sys/prctl.h>

static void setup_environment(int, char **);
static int is_external_command(void);
static int is_builtin_command(void);
static int is_input_file(void);
static void check_xen_hyper(void);
static void show_untrusted_files(void);
static void get_osrelease(char *);
static void get_log(char *);

static struct option long_options[] = {
        {"memory_module", required_argument, 0, 0},
        {"memory_device", required_argument, 0, 0},
        {"no_kallsyms", 0, 0, 0},
        {"no_modules", 0, 0, 0},
        {"help", optional_argument, 0, 'h'},
	{"no_data_debug", 0, 0, 0},
	{"no_crashrc", 0, 0, 0},
	{"no_kmem_cache", 0, 0, 0},
	{"kmem_cache_delay", 0, 0, 0},
	{"readnow", 0, 0, 0},
	{"smp", 0, 0, 0},
	{"machdep", required_argument, 0, 0},
	{"version", 0, 0, 0},
	{"buildinfo", 0, 0, 0},
        {"cpus", required_argument, 0, 0},
        {"no_ikconfig", 0, 0, 0},
        {"hyper", 0, 0, 0},
	{"p2m_mfn", required_argument, 0, 0},
	{"xen_phys_start", required_argument, 0, 0},
	{"zero_excluded", 0, 0, 0},
	{"no_panic", 0, 0, 0},
        {"more", 0, 0, 0},
        {"less", 0, 0, 0},
        {"CRASHPAGER", 0, 0, 0},
        {"no_scroll", 0, 0, 0},
        {"reloc", required_argument, 0, 0},
	{"kaslr", required_argument, 0, 0},
	{"active", 0, 0, 0},
	{"minimal", 0, 0, 0},
	{"mod", required_argument, 0, 0},
	{"kvmhost", required_argument, 0, 0},
	{"kvmio", required_argument, 0, 0},
	{"no_elf_notes", 0, 0, 0},
	{"osrelease", required_argument, 0, 0},
	{"log", required_argument, 0, 0},
	{"hex", 0, 0, 0},
	{"dec", 0, 0, 0},
	{"no_strip", 0, 0, 0},
	{"hash", required_argument, 0, 0},
	{"offline", required_argument, 0, 0},
	{"src", required_argument, 0, 0},
        {0, 0, 0, 0}
};

int
main(int argc, char **argv)
{
	int i, c, option_index;
	char *tmpname;

	setup_environment(argc, argv);

	/* 
	 *  Get and verify command line options.
	 */
	opterr = 0;
	optind = 0;
	while((c = getopt_long(argc, argv, "Lkgh::e:i:sSvc:d:tfp:m:xo:",
       		long_options, &option_index)) != -1) {
		switch (c)
		{
		case 0:
		        if (STREQ(long_options[option_index].name, 
			    "memory_module")) 
				pc->memory_module = optarg;

		        else if (STREQ(long_options[option_index].name, 
			    "memory_device")) 
				pc->memory_device = optarg;

		        else if (STREQ(long_options[option_index].name, 
			    "no_kallsyms")) 
				kt->flags |= NO_KALLSYMS;

		        else if (STREQ(long_options[option_index].name, 
			    "no_modules")) 
				kt->flags |= NO_MODULE_ACCESS;

		        else if (STREQ(long_options[option_index].name, 
			    "no_ikconfig")) 
				kt->flags |= NO_IKCONFIG;

		        else if (STREQ(long_options[option_index].name, 
			    "no_data_debug")) 
				pc->flags &= ~DATADEBUG;

		        else if (STREQ(long_options[option_index].name, 
			    "no_kmem_cache")) 
				vt->flags |= KMEM_CACHE_UNAVAIL;

		        else if (STREQ(long_options[option_index].name, 
			    "kmem_cache_delay")) 
				vt->flags |= KMEM_CACHE_DELAY;

		        else if (STREQ(long_options[option_index].name, 
			    "readnow")) 
				pc->flags |= READNOW;

		        else if (STREQ(long_options[option_index].name, 
			    "smp")) 
				kt->flags |= SMP;

		        else if (STREQ(long_options[option_index].name, 
			    "machdep")) {
				for (i = 0; i < MAX_MACHDEP_ARGS; i++) {
					if (machdep->cmdline_args[i])
						continue;
					machdep->cmdline_args[i] = optarg;
					break;
				}
				if (i == MAX_MACHDEP_ARGS)
					error(INFO, "option ignored: %s\n",
						optarg);
			}

		        else if (STREQ(long_options[option_index].name, 
			    "version")) { 
				pc->flags |= VERSION_QUERY;
                        	display_version();
                        	display_gdb_banner();
                        	clean_exit(0);
			}

		        else if (STREQ(long_options[option_index].name, 
			    "buildinfo")) {
				dump_build_data();
				clean_exit(0);
			}

		        else if (STREQ(long_options[option_index].name, "cpus")) 
				kt->cpus_override = optarg;

			else if (STREQ(long_options[option_index].name, "hyper"))
				pc->flags |= XEN_HYPER;

		        else if (STREQ(long_options[option_index].name, "p2m_mfn")) 
				xen_kdump_p2m_mfn(optarg);

		        else if (STREQ(long_options[option_index].name, "xen_phys_start")) 
				set_xen_phys_start(optarg);

		        else if (STREQ(long_options[option_index].name, "zero_excluded")) 
				*diskdump_flags |= ZERO_EXCLUDED;

			else if (STREQ(long_options[option_index].name, "no_elf_notes")) {
				if (machine_type("X86") || machine_type("X86_64"))
					*diskdump_flags |= NO_ELF_NOTES;
				else
					error(INFO,
					      "--no_elf_notes is only applicable to "
					      "the X86 and X86_64 architectures.\n");
			}

		        else if (STREQ(long_options[option_index].name, "no_panic")) 
				tt->flags |= PANIC_TASK_NOT_FOUND;

		        else if (STREQ(long_options[option_index].name, "no_strip")) 
				st->flags |= NO_STRIP;

		        else if (STREQ(long_options[option_index].name, "more")) {
				if ((pc->scroll_command != SCROLL_NONE) &&
				    file_exists("/bin/more", NULL))
					pc->scroll_command = SCROLL_MORE;
			}

		        else if (STREQ(long_options[option_index].name, "less")) {
				if ((pc->scroll_command != SCROLL_NONE) &&
				    file_exists("/usr/bin/less", NULL))
					pc->scroll_command = SCROLL_LESS;
			}

		        else if (STREQ(long_options[option_index].name, "CRASHPAGER")) {
				if ((pc->scroll_command != SCROLL_NONE) && 
				    CRASHPAGER_valid())
					pc->scroll_command = SCROLL_CRASHPAGER;
			}

		        else if (STREQ(long_options[option_index].name, "no_scroll"))
				 pc->flags &= ~SCROLL;

		        else if (STREQ(long_options[option_index].name, "no_crashrc"))
				pc->flags |= NOCRASHRC;

		        else if (STREQ(long_options[option_index].name, "active"))
				tt->flags |= ACTIVE_ONLY;

		        else if (STREQ(long_options[option_index].name, "mod"))
				kt->module_tree = optarg;

		        else if (STREQ(long_options[option_index].name, "hash")) {
				if (!calculate(optarg, &pc->nr_hash_queues, NULL, 0)) {
					error(INFO, "invalid --hash argument: %s\n",
						optarg);
				}
			} else if (STREQ(long_options[option_index].name, "kaslr")) {
				if (!machine_type("X86_64") &&
				    !machine_type("ARM64") && !machine_type("X86") &&
				    !machine_type("S390X") && !machine_type("RISCV64"))
					error(INFO, "--kaslr not valid "
						"with this machine type.\n");
				else if (STREQ(optarg, "auto"))
					kt->flags2 |= (RELOC_AUTO|KASLR);
				else {
					if (!calculate(optarg, &kt->relocate,
							NULL, 0)) {
						error(INFO,
						    "invalid --kaslr argument: %s\n",
						    optarg);
						program_usage(SHORT_FORM);
					}
					kt->relocate *= -1;
					kt->flags |= RELOC_SET;
					kt->flags2 |= KASLR;
					st->_stext_vmlinux = UNINITIALIZED;
				}

			} else if (STREQ(long_options[option_index].name, "reloc")) {
				if (!calculate(optarg, &kt->relocate, NULL, 0)) {
					error(INFO, "invalid --reloc argument: %s\n",
						optarg);
					program_usage(SHORT_FORM);
				}
				kt->flags |= RELOC_SET;
			}

			else if (STREQ(long_options[option_index].name, "minimal")) 
				pc->flags |= MINIMAL_MODE;

		        else if (STREQ(long_options[option_index].name, "kvmhost"))
				set_kvmhost_type(optarg);

		        else if (STREQ(long_options[option_index].name, "kvmio"))
				set_kvm_iohole(optarg);

		        else if (STREQ(long_options[option_index].name, "osrelease")) {
				pc->flags2 |= GET_OSRELEASE;
				get_osrelease(optarg);
			}

		        else if (STREQ(long_options[option_index].name, "log")) {
				pc->flags2 |= GET_LOG;
				get_log(optarg);
			}

			else if (STREQ(long_options[option_index].name, "hex")) {
				pc->flags2 |= RADIX_OVERRIDE;
				pc->output_radix = 16;
			}

			else if (STREQ(long_options[option_index].name, "dec")) {
				pc->flags2 |= RADIX_OVERRIDE;
				pc->output_radix = 10;
			}

			else if (STREQ(long_options[option_index].name, "offline")) {
				if (STREQ(optarg, "show"))
					pc->flags2 &= ~OFFLINE_HIDE;
				else if (STREQ(optarg, "hide"))
					pc->flags2 |= OFFLINE_HIDE;
				else {
					error(INFO, "invalid --offline argument: %s\n", optarg);
					program_usage(SHORT_FORM);
				}
			}

			else if (STREQ(long_options[option_index].name, "src"))
				kt->source_tree = optarg;

			else {
				error(INFO, "internal error: option %s unhandled\n",
					long_options[option_index].name);
				program_usage(SHORT_FORM);
			}
			break;

		case 'f':
			st->flags |= FORCE_DEBUGINFO;
			break;

		case 'g':
			pc->flags |= KERNEL_DEBUG_QUERY;
			break;

		case 'h':
			/* note: long_getopt's handling of optional arguments is weak.
			 * To it, an optional argument must be part of the same argument
			 * as the flag itself (eg. --help=commands or -hcommands).
			 * We want to accept "--help commands" or "-h commands".
			 * So we must do that part ourselves.
			 */
			if (optarg != NULL)
				cmd_usage(optarg, COMPLETE_HELP|PIPE_TO_SCROLL|MUST_HELP);
			else if (argv[optind] != NULL && argv[optind][0] != '-')
				cmd_usage(argv[optind++], COMPLETE_HELP|PIPE_TO_SCROLL|MUST_HELP);
			else
				program_usage(LONG_FORM);
			clean_exit(0);
			
		case 'k':
			pc->flags |= KERNTYPES;
			break;

		case 'e':
			if (STREQ(optarg, "vi"))
				pc->editing_mode = "vi";
			else if (STREQ(optarg, "emacs"))
				pc->editing_mode = "emacs";
			else
				fprintf(fp, "invalid edit mode: %s\n", optarg);	
			break;

		case 't':
			kt->flags2 |= GET_TIMESTAMP;
			break;

		case 'i':
			pc->input_file = optarg;
			pc->flags |= CMDLINE_IFILE;
			break;

		case 'v':
			pc->flags |= VERSION_QUERY;
			display_version();
			display_gdb_banner();
			clean_exit(0);

		case 's':
			pc->flags |= SILENT;
			pc->flags &= ~SCROLL;
//   			pc->scroll_command = SCROLL_NONE;   (why?)
			break;

		case 'L':
			if (mlockall(MCL_CURRENT|MCL_FUTURE) == -1)
				perror("mlockall");
			break;

		case 'S':
			if (is_system_map("/boot/System.map")) {
                                pc->system_map = "/boot/System.map";
                                pc->flags |= (SYSMAP|SYSMAP_ARG);
			}
			break;	

		case 'c':
			create_console_device(optarg);
			break;

		case 'd': 
			pc->debug = atol(optarg);
			set_lkcd_debug(pc->debug);
			set_vas_debug(pc->debug);
			break;

		case 'p':
			force_page_size(optarg);
			break;

		case 'm':
			for (i = 0; i < MAX_MACHDEP_ARGS; i++) {
				if (machdep->cmdline_args[i])
					continue;
				machdep->cmdline_args[i] = optarg;
				break;
			}
			if (i == MAX_MACHDEP_ARGS)
				error(INFO, "option ignored: %s\n",
					optarg);
			break;

		case 'x':
			pc->flags |= PRELOAD_EXTENSIONS;
			break;

		case 'o':
			ramdump_elf_output_file(optarg);
			break;

		default:
			error(INFO, "invalid option: %s\n",
				argv[optind-1]);
			program_usage(SHORT_FORM);
		}
	}
	opterr = 1;

	display_version();

	/*
	 *  Take the kernel and dumpfile arguments in either order.
	 */
	while (argv[optind]) {

		if (is_ramdump(argv[optind])) {
			if (pc->flags & MEMORY_SOURCES) {
				error(INFO,
					"too many dumpfile arguments\n");
					program_usage(SHORT_FORM);
			}

			if (ACTIVE()) {
				pc->flags |= LIVE_RAMDUMP;
				pc->readmem = read_ramdump;
				pc->writemem = NULL;
				optind++;
				continue;
			}

			pc->dumpfile = ramdump_to_elf();
			if (is_kdump(pc->dumpfile, KDUMP_LOCAL)) {
				pc->flags |= KDUMP;
				if (is_ramdump_image())
					pc->readmem = read_ramdump;
				else
					pc->readmem = read_kdump;
				pc->writemem = NULL;
			} else {
				error(INFO, "malformed ELF file: %s\n",
					pc->dumpfile);
				program_usage(SHORT_FORM);
			}
			optind++;
			continue;
		}

		if (is_remote_daemon(argv[optind])) {
                	if (pc->flags & DUMPFILE_TYPES) {
				error(INFO, 
				      "too many dumpfile/memory arguments\n");
				program_usage(SHORT_FORM);
			}
			pc->flags2 |= REMOTE_DAEMON;
			optind++;
			continue;
		}

		if (STREQ(argv[optind], "/dev/crash")) {
			pc->memory_device = argv[optind];
			optind++;
			continue;
		}

		if (!file_exists(argv[optind], NULL)) {
			error(INFO, "%s: %s\n", argv[optind], strerror(ENOENT));
			program_usage(SHORT_FORM);
		} else if (is_directory(argv[optind])) {
			error(INFO, "%s: not a supported file format\n", 
				argv[optind]);
			program_usage(SHORT_FORM);
		} else if (!is_readable(argv[optind])) 
			program_usage(SHORT_FORM);

		if (is_kernel(argv[optind])) {
			if (pc->namelist || pc->server_namelist) {
				if (!select_namelist(argv[optind])) {
                               		error(INFO, 
					    "too many namelist arguments\n");
                               		program_usage(SHORT_FORM);
				}
			} else
				pc->namelist = argv[optind];

		} else if (is_compressed_kernel(argv[optind], &tmpname)) {
			if (pc->namelist) {
				if (!select_namelist(tmpname)) {
					error(INFO, 
					    "too many namelist arguments\n");
					program_usage(SHORT_FORM);
				}
				if (pc->namelist_debug == tmpname) {
					pc->namelist_debug_orig = argv[optind];
				} else {
					pc->namelist_debug_orig = pc->namelist_orig;
					pc->namelist_orig = argv[optind];
				}
			} else {
				pc->namelist = tmpname;
				pc->namelist_orig = argv[optind];
			}
			pc->cleanup = NULL;

		} else if (!(pc->flags & KERNEL_DEBUG_QUERY)) {

			if (is_flattened_format(argv[optind]))
				pc->flags2 |= FLAT;

			if (STREQ(argv[optind], "/dev/mem")) {
                        	if (pc->flags & MEMORY_SOURCES) {
                                	error(INFO, 
                                            "too many dumpfile arguments\n");
                                	program_usage(SHORT_FORM);
                        	}
				pc->flags |= DEVMEM;
				pc->dumpfile = NULL;
				pc->readmem = read_dev_mem;
				pc->writemem = write_dev_mem;
				pc->live_memsrc = argv[optind];

			} else if (is_proc_kcore(argv[optind], KCORE_LOCAL)) {
				if (pc->flags & MEMORY_SOURCES) {
					error(INFO, 
					    "too many dumpfile arguments\n");
					program_usage(SHORT_FORM);
				}
				pc->flags |= PROC_KCORE;
				pc->dumpfile = NULL;
				pc->readmem = read_proc_kcore;
				pc->writemem = write_proc_kcore;
				pc->live_memsrc = argv[optind];

			} else if (is_netdump(argv[optind], NETDUMP_LOCAL)) {
                                if (pc->flags & MEMORY_SOURCES) {
                                        error(INFO,
                                            "too many dumpfile arguments\n");
                                        program_usage(SHORT_FORM);
                                }
                                pc->flags |= NETDUMP;
                                pc->dumpfile = argv[optind];

				if (is_sadump_xen()) {
					pc->readmem = read_kdump;
					pc->writemem = write_kdump;
				} else {
					pc->readmem = read_netdump;
					pc->writemem = write_netdump;
				}

                        } else if (is_kdump(argv[optind], KDUMP_LOCAL)) {
                                if (pc->flags & MEMORY_SOURCES) {
                                        error(INFO,
                                            "too many dumpfile arguments\n");
                                        program_usage(SHORT_FORM);
                                }
                                pc->flags |= KDUMP;
                                pc->dumpfile = argv[optind];
                                pc->readmem = read_kdump;
                                pc->writemem = write_kdump;

                        } else if (is_kvmdump(argv[optind])) {
                                if (pc->flags & MEMORY_SOURCES) {
                                        error(INFO,
                                            "too many dumpfile arguments\n");
                                        program_usage(SHORT_FORM);
                                }
                                pc->flags |= KVMDUMP;
                                pc->dumpfile = argv[optind];
                                pc->readmem = read_kvmdump;
                                pc->writemem = write_kvmdump;

			} else if (is_kvmdump_mapfile(argv[optind])) {
				if (pc->kvmdump_mapfile) {
                                        error(INFO,
                                            "too many KVM map file arguments\n");
                                        program_usage(SHORT_FORM);
				}
				pc->kvmdump_mapfile = argv[optind];
                                
                        } else if (is_xendump(argv[optind])) {
                                if (pc->flags & MEMORY_SOURCES) {
                                        error(INFO,
                                            "too many dumpfile arguments\n");
                                        program_usage(SHORT_FORM);
                                }
                                pc->flags |= XENDUMP;
                                pc->dumpfile = argv[optind];
                                pc->readmem = read_xendump;
                                pc->writemem = write_xendump;

                        } else if (is_system_map(argv[optind])) {
                                pc->system_map = argv[optind];
                                pc->flags |= (SYSMAP|SYSMAP_ARG);

			} else if (is_diskdump(argv[optind])) {
                                if ((pc->flags & MEMORY_SOURCES) &&
                                    (!dumpfile_is_split())) {
                                        error(INFO,
                                            "too many dumpfile arguments\n");
                                        program_usage(SHORT_FORM);
                                }
                                pc->flags |= DISKDUMP;
                                pc->dumpfile = argv[optind];
                                pc->readmem = read_diskdump;
                                pc->writemem = write_diskdump;

			} else if (is_lkcd_compressed_dump(argv[optind])) {
				if (pc->flags & MEMORY_SOURCES) {
                                        error(INFO,
                                            "too many dumpfile arguments\n");
                                        program_usage(SHORT_FORM);
                                }
                                pc->flags |= LKCD;
                                pc->dumpfile = argv[optind];
				pc->readmem = read_lkcd_dumpfile;
				pc->writemem = write_lkcd_dumpfile;

			} else if (is_mclx_compressed_dump(argv[optind])) {
				if (pc->flags & MEMORY_SOURCES) {
					error(INFO,
                                            "too many dumpfile arguments\n");
                                        program_usage(SHORT_FORM);
                                }
				pc->flags |= MCLXCD;
				pc->dumpfile = argv[optind];
				pc->readmem = read_mclx_dumpfile;
				pc->writemem = write_mclx_dumpfile;

                        } else if (is_s390_dump(argv[optind])) {
                                if (pc->flags & MEMORY_SOURCES) {
                                        error(INFO,
                                            "too many dumpfile arguments\n");
                                        program_usage(SHORT_FORM);
                                }
                                pc->flags |= S390D;
                                pc->dumpfile = argv[optind];
                                pc->readmem = read_s390_dumpfile;
                                pc->writemem = write_s390_dumpfile;

			} else if (is_sadump(argv[optind])) {
				if ((pc->flags & MEMORY_SOURCES) &&
				    !sadump_is_diskset()) {
                                        error(INFO,
                                            "too many dumpfile arguments\n");
                                        program_usage(SHORT_FORM);
				}
				pc->flags |= SADUMP;
				pc->dumpfile = argv[optind];
				pc->readmem = read_sadump;
				pc->writemem = write_sadump;

			} else if (is_vmware_vmss(argv[optind])) {
                                if (pc->flags & MEMORY_SOURCES) {
                                        error(INFO,
                                            "too many dumpfile arguments\n");
                                        program_usage(SHORT_FORM);
                                }
				pc->flags |= VMWARE_VMSS;
				pc->dumpfile = argv[optind];
				pc->readmem = read_vmware_vmss;
				pc->writemem = write_vmware_vmss;

			} else if (is_vmware_guestdump(argv[optind])) {
                                if (pc->flags & MEMORY_SOURCES) {
                                        error(INFO,
                                            "too many dumpfile arguments\n");
                                        program_usage(SHORT_FORM);
                                }
				pc->flags |= VMWARE_VMSS;
				pc->flags2 |= VMWARE_VMSS_GUESTDUMP;
				pc->dumpfile = argv[optind];
				pc->readmem = read_vmware_vmss;
				pc->writemem = write_vmware_vmss;

			} else { 
				error(INFO, 
				    "%s: not a supported file format\n",
					argv[optind]);
				program_usage(SHORT_FORM);
			}
		}
		optind++;
	}
	
	check_xen_hyper();

        if (setjmp(pc->main_loop_env))
                clean_exit(1);

	/*
	 *  Initialize various subsystems.
	 */
	fd_init();
	buf_init();
        cmdline_init();
        mem_init();
       	hq_init();
	machdep_init(PRE_SYMTAB);
        symtab_init();
	paravirt_init();
	machdep_init(PRE_GDB);
        datatype_init();

	/*
	 *  gdb_main_loop() modifies "command_loop_hook" to point to the 
         *  main_loop() function below, and then calls gdb's main() function.
         *  After gdb initializes itself, it calls back to main_loop().
	 */
	gdb_main_loop(argc, argv);   

	clean_exit(0);
	exit(0); 
}

/*
 *  This routine is called from above, but also will be re-entered
 *  as part of gdb's SIGINT handling.  Since GDB_INIT and RUNTIME 
 *  will be set on re-entrancy, the initialization routines won't 
 *  be called.  This can be avoided by always making gdb ignore SIGINT.
 */
void
main_loop(void)
{
	if (pc->flags2 & ERASEINFO_DATA)
		error(WARNING, "\n%s:\n         "
		    "Kernel data has been erased from this dumpfile.  This may "
		    "cause\n         the crash session to fail entirely, may "
                    "cause commands to fail,\n         or may result in "
		    "unpredictable\n         runtime behavior.\n",
			pc->dumpfile);

	if (pc->flags2 & INCOMPLETE_DUMP) {
		error(WARNING, "\n%s:\n         "
		    "This dumpfile is incomplete.  This may cause the crash session"
		    "\n         to fail entirely, may cause commands to fail, or may"
		    " result in\n         unpredictable runtime behavior.\n",
			pc->dumpfile);
		if (!(*diskdump_flags & ZERO_EXCLUDED))
			fprintf(fp,
			    "   NOTE: This dumpfile may be analyzed with the --zero_excluded command\n"
			    "         line option, in which case any read requests from missing pages\n"
			    "         will return zero-filled memory.\n");
	}

	if (pc->flags2 & EXCLUDED_VMEMMAP) {
		error(WARNING, "\n%s:\n         "
		    "This dumpfile is incomplete because the page structures associated\n"
                    "         with excluded pages may also be excluded.  This may cause the crash\n"
		    "         session to fail entirely, may cause commands to fail (most notably\n"
		    "         the \"kmem\" command), or may result in unpredictable runtime behavior.\n",
			pc->dumpfile);

	}

        if (!(pc->flags & GDB_INIT)) {
		gdb_session_init();
		machdep_init(POST_RELOC);
		show_untrusted_files();
		kdump_backup_region_init();
		if (XEN_HYPER_MODE()) {
#ifdef XEN_HYPERVISOR_ARCH
			machdep_init(POST_GDB);
			xen_hyper_init();
			machdep_init(POST_INIT);
#else
        		error(FATAL, XEN_HYPERVISOR_NOT_SUPPORTED);
#endif
		} else if (!(pc->flags & MINIMAL_MODE)) {
			read_in_kernel_config(IKCFG_INIT);
			kernel_init();
			machdep_init(POST_GDB);
        		vm_init();
			machdep_init(POST_VM);
        		module_init();
        		help_init();
        		task_init();
        		vfs_init();
			net_init();
			dev_init();
			machdep_init(POST_INIT);
		}
	} else
		SIGACTION(SIGINT, restart, &pc->sigaction, NULL);

        /*
         *  Display system statistics and current context.
         */
        if (!(pc->flags & SILENT) && !(pc->flags & RUNTIME)) {
		if (XEN_HYPER_MODE()) {
#ifdef XEN_HYPERVISOR_ARCH
			xen_hyper_display_sys_stats();
			xen_hyper_show_vcpu_context(XEN_HYPER_VCPU_LAST_CONTEXT());
                	fprintf(fp, "\n");
#else
        		error(FATAL, XEN_HYPERVISOR_NOT_SUPPORTED);
#endif
		} else if (!(pc->flags & MINIMAL_MODE)) {
			display_sys_stats();
			show_context(CURRENT_CONTEXT());
                	fprintf(fp, "\n");
		}
        }

	if (pc->flags & MINIMAL_MODE)
            error(NOTE, 
		"minimal mode commands: log, dis, rd, sym, eval, set, extend and exit\n\n");

        pc->flags |= RUNTIME;

	if (pc->flags & PRELOAD_EXTENSIONS)
		preload_extensions();

	/*
	 *  Return here if a non-recoverable error occurs
	 *  during command execution.
	 */
	if (setjmp(pc->main_loop_env)) {
		;
	}

	/*
	 *  process_command_line() reads, parses and stores input command lines
	 *  in the global args[] array.  exec_command() figures out what to 
         *  do with the parsed line.
	 */
	while (TRUE) {
		process_command_line();
		exec_command();
	}
}

/*
 *  Most of the time args[0] simply contains the name string of a command
 *  found in the global command_table[].  Special consideration is done for 
 *  dealing with input files, "known" external commands, and built-in commands.
 *  If none of the above apply, the args[0] string is checked against the
 *  known list of structure, union and typedef names, and if found, passed
 *  on to cmd_struct(), cmd_union() or cmd_whatis().
 */
void
exec_command(void)
{
	struct command_table_entry *ct;
	struct args_input_file args_ifile;

        if (args[0] && (args[0][0] == '\\') && args[0][1]) {
		shift_string_left(args[0], 1);
                shift_string_left(pc->orig_line, 1);
		pc->curcmd_flags |= NO_MODIFY;
	}

reattempt:
	if (!args[0])
		return;

	optind = argerrs = 0;

	if ((ct = get_command_table_entry(args[0]))) {
                if (ct->flags & REFRESH_TASK_TABLE) {
			if (XEN_HYPER_MODE()) {
#ifdef XEN_HYPERVISOR_ARCH
				xen_hyper_refresh_domain_context_space();
				xen_hyper_refresh_vcpu_context_space();
#else
        			error(FATAL, XEN_HYPERVISOR_NOT_SUPPORTED);
#endif
			} else if (!(pc->flags & MINIMAL_MODE)) {
				tt->refresh_task_table();
				sort_context_array();
				sort_tgid_array();	
			}
		}
                if (!STREQ(pc->curcmd, pc->program_name))
                        pc->lastcmd = pc->curcmd;
                pc->curcmd = ct->name;
		pc->cmdgencur++;

		if (is_args_input_file(ct, &args_ifile))
			exec_args_input_file(ct, &args_ifile);
		else
			(*ct->func)();

                pc->lastcmd = pc->curcmd;
                pc->curcmd = pc->program_name;
                return;
	}

	if (is_input_file())
		return;

	if (is_external_command())
		return;

	if (is_builtin_command())
		return;

        if (is_datatype_command()) 
                goto reattempt;

	if (STRNEQ(args[0], "#") || STRNEQ(args[0], "//"))
		return;

	if (!(pc->flags & MINIMAL_MODE) &&
	    is_gdb_command(TRUE, FAULT_ON_ERROR)) 
		goto reattempt;

	if (REMOTE() && remote_execute())
		return;

	pc->curcmd = pc->program_name;

	if (pc->flags & MINIMAL_MODE)
		error(INFO, 
		    "%s: command not available in minimal mode\n"
		    "NOTE: minimal mode commands: log, dis, rd, sym, eval, set, extend and exit\n",
			args[0]);
	else
		error(INFO, "command not found: %s\n", args[0]);

	if (pc->curcmd_flags & REPEAT)
		pc->curcmd_flags &= ~REPEAT;
}


/*
 *  Find the command_table structure associated with a command name.
 */
struct command_table_entry *
get_command_table_entry(char *name)
{       
	int i;
        struct command_table_entry *cp;
        struct extension_table *ext;

	if (pc->flags2 & GDB_CMD_MODE) {
		if (STREQ(name, "crash")) {
			if (argcnt == 1)
				error(FATAL, 
				    "a crash command must follow "
				    "the \"crash\" directive\n");
			for (i = 1; i <= argcnt; i++)
				args[i-1] = args[i];
			argcnt--;
			name = args[0];
		} else
			name = "gdb";
	}
	
	for (cp = pc->cmd_table; cp->name; cp++) {
                if (STREQ(cp->name, name)) {
			if (!(pc->flags & MINIMAL_MODE) || (cp->flags & MINIMAL))
				return cp;
			else
				return NULL;
		}
        }
                
        for (ext = extension_table; ext; ext = ext->next) {
                for (cp = ext->command_table; cp->name; cp++) {
                        if (STREQ(cp->name, name)) {
				if (!(pc->flags & MINIMAL_MODE) || (cp->flags & MINIMAL))
					return cp;
				else
					return NULL;
			}
                }
        }       

        return NULL;
}


static int
is_input_file(void)
{
        if (STREQ(args[0], "<")) {
                exec_input_file();
                return TRUE;
        }

	return FALSE;
}

static int
is_builtin_command(void)
{
	int i;
	struct remote_file remote_file, *rfp;

	/*
	 *  cmd_test() is used strictly for debugging -- but not advertised
	 *  in the help menu.
	 */ 
        if (STREQ(args[0], "test")) {
		pc->curcmd = "test";
                cmd_test();
                return TRUE;
        }

        if (STREQ(args[0], "save")) {
		pc->curcmd = "save";
		rfp = &remote_file;
		BZERO(rfp, sizeof(struct remote_file));
		rfp->flags |= REMOTE_VERBOSE;
		for (i = 1; i < argcnt; i++) {
			rfp->filename = args[i];
			get_remote_file(rfp); 
		}
		return TRUE;
	}

	return FALSE;
}

/*
 *  Pure laziness -- to avoid having to type the exclamation point at the
 *  beginning of the line.
 */
static int
is_external_command(void)
{
	int i;
	char *cmd;
	char command[BUFSIZE];

	cmd = args[0];

        if (STREQ(cmd, "vi") ||
            STREQ(cmd, "pwd") ||
            STREQ(cmd, "grep") ||
            STREQ(cmd, "cat") ||
            STREQ(cmd, "more") ||
            STREQ(cmd, "less") ||
	    STREQ(cmd, "echo") ||
            STREQ(cmd, "ls")) {
                sprintf(command, "%s", cmd);
                for (i = 1; i < argcnt; i++) {
                        strcat(command, " ");
			if (strstr(args[i], " ")) {
				strcat(command, "\"");
                        	strcat(command, args[i]);
				strcat(command, "\"");
			}
			else
                        	strcat(command, args[i]);
                }
                if (system(command) == -1)
			perror(command);
                return TRUE;
        }

	return FALSE;
}

void
cmd_quit(void)
{
	if (REMOTE())
		remote_exit();

	clean_exit(0);
}

void
cmd_mach(void)
{
	machdep->cmd_mach();
}


static void
setup_environment(int argc, char **argv)
{
	int i;
	char *p1;
	char buf[BUFSIZE];
	char homerc[BUFSIZE];
	char localrc[BUFSIZE];
	FILE *afp;
	char *program;

	program = argv[0];

	/*
	 *  Program output typically goes via "fprintf(fp, ...)", but the 
	 *  contents of fp are modified on the fly to handle redirection
	 *  to pipes or output files.
	 */
	fp = stdout;

	if (!set_error("default")) {
		fprintf(stderr, "crash: cannot malloc error() path string\n");
		clean_exit(1);
	}

	/*
	 *  Start populating the program_context structure.  It's used so
	 *  frequently that "pc" has been declared globally to point to the
	 *  "program_context" structure.
	 */
        pc->program_name = (char *)basename(program);
	pc->program_path = program;
        pc->program_version = build_version;
	pc->program_pid = (ulong)getpid();
        pc->curcmd = pc->program_name;
        pc->flags = (HASH|SCROLL);
	pc->flags |= DATADEBUG;          /* default until unnecessary */
	pc->flags2 |= REDZONE;
	pc->confd = -2;
	pc->machine_type = MACHINE_TYPE;
	if (file_readable("/dev/mem")) {     /* defaults until argv[] is parsed */
		pc->readmem = read_dev_mem;
		pc->writemem = write_dev_mem;
	} else if (file_exists("/proc/kcore", NULL)) {
		pc->readmem = read_proc_kcore;
		pc->writemem = write_proc_kcore;
	}
	pc->read_vmcoreinfo = no_vmcoreinfo;
	pc->memory_module = NULL;
	pc->memory_device = MEMORY_DRIVER_DEVICE;
	machdep->bits = sizeof(long) * 8;
	machdep->verify_paddr = generic_verify_paddr;
	machdep->get_kvaddr_ranges = generic_get_kvaddr_ranges;
	machdep->is_page_ptr = generic_is_page_ptr;
	pc->redhat_debug_loc = DEFAULT_REDHAT_DEBUG_LOCATION;
	pc->cmdgencur = 0;
	pc->cmd_table = linux_command_table;
	kt->BUG_bytes = -1;
	kt->flags |= PRE_KERNEL_INIT;

	/*
	 *  Set up to perform a clean_exit() upon parent death.
	 */
	SIGACTION(SIGUSR2, restart, &pc->sigaction, NULL);
	prctl(PR_SET_PDEATHSIG, SIGUSR2);

	/*
	 *  Get gdb version before initializing it since this might be one 
         *  of the short-hand commands that need it without running gdb.
	 */
	get_gdb_version();

	/* 
	 *  Set up the default scrolling behavior for terminal output.
	 */
	if (isatty(fileno(stdout))) {
		if (CRASHPAGER_valid()) {
			pc->flags |= SCROLL;
			pc->scroll_command = SCROLL_CRASHPAGER;
		} else if (file_exists("/usr/bin/less", NULL)) {
			pc->flags |= SCROLL;
			pc->scroll_command = SCROLL_LESS;
		} else if (file_exists("/bin/more", NULL)) {
			pc->flags |= SCROLL;
			pc->scroll_command = SCROLL_MORE;
		} else {
                	pc->scroll_command = SCROLL_NONE;
                	pc->flags &= ~SCROLL;
        	}
	} 

	/*
	 *  Setup the readline command line editing mode based upon the 
	 *  following order:
	 *
	 *   (1) EDITOR environment variable
         *   (2) overridden by any .crashrc entry: "set vi" or "set emacs"
         *   (3) RL_VI_MODE if not set anywhere else
	 */

	pc->flags |= READLINE;
	pc->editing_mode = "no_mode";

	if ((p1 = getenv("EDITOR"))) {
		if (strstr(p1, "vi"))
			pc->editing_mode = "vi";
		if (strstr(p1, "emacs"))
			pc->editing_mode = "emacs";
	}

	/*
	 *  Resolve $HOME .rc file first, then the one in the local directory.
         *  Note that only "set" and "alias" commands are done at this time.
	 */
	for (i = 1; i < argc; i++)
		if (STREQ(argv[i], "--no_crashrc"))
			pc->flags |= NOCRASHRC; 

	alias_init(NULL);

	if ((p1 = getenv("HOME"))) {
		if ((pc->home = (char *)malloc(strlen(p1)+1)) == NULL) {
                        error(INFO, "home directory malloc: %s\n",
                                strerror(errno));
			pc->home = "(unknown)";
		} else
			strcpy(pc->home, p1);
	        sprintf(homerc, "%s/.%src", pc->home, pc->program_name);
	        if (!(pc->flags & NOCRASHRC) && file_exists(homerc, NULL)) {
	                if ((afp = fopen(homerc, "r")) == NULL)
	                        error(INFO, "cannot open %s: %s\n",
	                                homerc, strerror(errno));
			else if (untrusted_file(afp, homerc))
				fclose(afp);
	                else {
	                        while (fgets(buf, BUFSIZE, afp))
	                                resolve_rc_cmd(buf, ALIAS_RCHOME);
	                        fclose(afp);
	                }
	        }
	}

        sprintf(localrc, ".%src", pc->program_name);
	if (!same_file(homerc, localrc) && 
	    !(pc->flags & NOCRASHRC) && file_exists(localrc, NULL)) {
		if ((afp = fopen(localrc, "r")) == NULL)
                        error(INFO, "cannot open %s: %s\n",
				localrc, strerror(errno));
		else if (untrusted_file(afp, localrc))
			fclose(afp);
		else {
			while (fgets(buf, BUFSIZE, afp)) 
				resolve_rc_cmd(buf, ALIAS_RCLOCAL);
			fclose(afp);
		}
	}

	if (STREQ(pc->editing_mode, "no_mode"))
		pc->editing_mode = "vi";

	machdep_init(SETUP_ENV);
}


/*
 *  "help -p" output
 */
void
dump_program_context(void)
{
	int i;
	int others = 0;
	char *p1;
	char buf[BUFSIZE];
	char buf2[BUFSIZE];

	fprintf(fp, "     program_name: %s\n", pc->program_name);
	fprintf(fp, "     program_path: %s\n", pc->program_path);
	fprintf(fp, "  program_version: %s\n", pc->program_version);
	fprintf(fp, "      gdb_version: %s\n", pc->gdb_version);
	fprintf(fp, "      program_pid: %ld\n", pc->program_pid);
	fprintf(fp, "           prompt: \"%s\"\n", pc->prompt);
	fprintf(fp, "            flags: %llx ", pc->flags);

	if (pc->flags)
		sprintf(buf, "(");
	if (pc->flags & RUNTIME)
		sprintf(&buf[strlen(buf)], "%sRUNTIME", others++ ? "|" : "");
	if (pc->flags & LIVE_SYSTEM)
		sprintf(&buf[strlen(buf)], "%sLIVE_SYSTEM", 
			others++ ? "|" : "");
	if (pc->flags & TTY)
		sprintf(&buf[strlen(buf)], "%sTTY", others++ ? "|" : "");
        if (pc->flags & IN_FOREACH)
                sprintf(&buf[strlen(buf)], "%sIN_FOREACH", others++ ? "|" : "");
        if (pc->flags & MFD_RDWR)
                sprintf(&buf[strlen(buf)], "%sMFD_RDWR", others++ ? "|" : "");
        if (pc->flags & KVMDUMP)
                sprintf(&buf[strlen(buf)], "%sKVMDUMP", others++ ? "|" : "");
        if (pc->flags & SILENT)
                sprintf(&buf[strlen(buf)], "%sSILENT", others++ ? "|" : "");
        if (pc->flags & HASH)
                sprintf(&buf[strlen(buf)], "%sHASH", others++ ? "|" : "");
        if (pc->flags & SCROLL)
                sprintf(&buf[strlen(buf)], "%sSCROLL", others++ ? "|" : "");
        if (pc->flags & NO_CONSOLE)
                sprintf(&buf[strlen(buf)], "%sNO_CONSOLE", others++ ? "|" : "");
        if (pc->flags & MCLXCD)
                sprintf(&buf[strlen(buf)], "%sMCLXCD", others++ ? "|" : "");
        if (pc->flags & RUNTIME_IFILE)
                sprintf(&buf[strlen(buf)], "%sRUNTIME_IFILE", 
			others++ ? "|" : "");
        if (pc->flags & CMDLINE_IFILE)
                sprintf(&buf[strlen(buf)], "%sCMDLINE_IFILE", 
			others++ ? "|" : "");
        if (pc->flags & DROP_CORE)
                sprintf(&buf[strlen(buf)], "%sDROP_CORE", others++ ? "|" : "");
        if (pc->flags & LKCD)
                sprintf(&buf[strlen(buf)], "%sLKCD", others++ ? "|" : "");
        if (pc->flags & GDB_INIT)
                sprintf(&buf[strlen(buf)], "%sGDB_INIT", others++ ? "|" : "");
        if (pc->flags & IN_GDB)
                sprintf(&buf[strlen(buf)], "%sIN_GDB", others++ ? "|" : "");
	if (pc->flags & RCHOME_IFILE)
                sprintf(&buf[strlen(buf)], "%sRCHOME_IFILE", 
			others++ ? "|" : "");
	if (pc->flags & RCLOCAL_IFILE)
                sprintf(&buf[strlen(buf)], "%sRCLOCAL_IFILE", 
			others++ ? "|" : "");
	if (pc->flags & READLINE)
                sprintf(&buf[strlen(buf)], "%sREADLINE", others++ ? "|" : "");
        if (pc->flags & _SIGINT_)
                sprintf(&buf[strlen(buf)], 
			"%s_SIGINT_", others++ ? "|" : "");
        if (pc->flags & IN_RESTART)
                sprintf(&buf[strlen(buf)], "%sIN_RESTART", others++ ? "|" : "");
        if (pc->flags & KERNEL_DEBUG_QUERY)
                sprintf(&buf[strlen(buf)], 
			"%sKERNEL_DEBUG_QUERY", others++ ? "|" : "");
        if (pc->flags & DEVMEM)
                sprintf(&buf[strlen(buf)], 
			"%sDEVMEM", others++ ? "|" : "");
        if (pc->flags & MEMMOD)
                sprintf(&buf[strlen(buf)], 
			"%sMEMMOD", others++ ? "|" : "");
        if (pc->flags & MODPRELOAD)
                sprintf(&buf[strlen(buf)], 
			"%sMODPRELOAD", others++ ? "|" : "");
        if (pc->flags & REM_LIVE_SYSTEM)
                sprintf(&buf[strlen(buf)],
                        "%sREM_LIVE_SYSTEM", others++ ? "|" : "");
        if (pc->flags & NAMELIST_LOCAL)
                sprintf(&buf[strlen(buf)],
                        "%sNAMELIST_LOCAL", others++ ? "|" : "");
        if (pc->flags & DUMPFILE_SAVED)
                sprintf(&buf[strlen(buf)],
                        "%sDUMPFILE_SAVED", others++ ? "|" : "");
        if (pc->flags & NAMELIST_SAVED)
                sprintf(&buf[strlen(buf)],
                        "%sNAMELIST_SAVED", others++ ? "|" : "");
        if (pc->flags & UNLINK_NAMELIST)
                sprintf(&buf[strlen(buf)],
                        "%sUNLINK_NAMELIST", others++ ? "|" : "");
        if (pc->flags & NAMELIST_UNLINKED)
                sprintf(&buf[strlen(buf)],
                        "%sNAMELIST_UNLINKED", others++ ? "|" : "");
        if (pc->flags & REM_MCLXCD)
                sprintf(&buf[strlen(buf)],
                        "%sREM_MCLXCD", others++ ? "|" : "");
        if (pc->flags & REM_LKCD)
                sprintf(&buf[strlen(buf)],
                        "%sREM_LKCD", others++ ? "|" : "");
        if (pc->flags & NAMELIST_NO_GZIP)
                sprintf(&buf[strlen(buf)],
                        "%sNAMELIST_NO_GZIP", others++ ? "|" : "");
        if (pc->flags & UNLINK_MODULES)
                sprintf(&buf[strlen(buf)],
                        "%sUNLINK_MODULES", others++ ? "|" : "");
        if (pc->flags & S390D)
                sprintf(&buf[strlen(buf)],
                        "%sS390D", others++ ? "|" : "");
        if (pc->flags & REM_S390D)
                sprintf(&buf[strlen(buf)],
                        "%sREM_S390D", others++ ? "|" : "");
        if (pc->flags & NETDUMP)
                sprintf(&buf[strlen(buf)],
                        "%sNETDUMP", others++ ? "|" : "");
        if (pc->flags & XENDUMP)
                sprintf(&buf[strlen(buf)],
                        "%sXENDUMP", others++ ? "|" : "");
        if (pc->flags & KDUMP)
                sprintf(&buf[strlen(buf)],
                        "%sKDUMP", others++ ? "|" : "");
        if (pc->flags & SADUMP)
                sprintf(&buf[strlen(buf)],
                        "%sSADUMP", others++ ? "|" : "");
        if (pc->flags & SYSRQ)
                sprintf(&buf[strlen(buf)],
                        "%sSYSRQ", others++ ? "|" : "");
        if (pc->flags & REM_NETDUMP)
                sprintf(&buf[strlen(buf)],
                        "%sREM_NETDUMP", others++ ? "|" : "");
        if (pc->flags & DISKDUMP)
                sprintf(&buf[strlen(buf)],
                        "%sDISKDUMP", others++ ? "|" : "");
        if (pc->flags & VMWARE_VMSS)
                sprintf(&buf[strlen(buf)],
                        "%sVMWARE_VMSS", others++ ? "|" : "");
        if (pc->flags & SYSMAP)
                sprintf(&buf[strlen(buf)],
                        "%sSYSMAP", others++ ? "|" : "");
        if (pc->flags & SYSMAP_ARG)
                sprintf(&buf[strlen(buf)],
                        "%sSYSMAP_ARG", others++ ? "|" : "");
        if (pc->flags & DATADEBUG)
                sprintf(&buf[strlen(buf)],
                        "%sDATADEBUG", others++ ? "|" : "");
	if (pc->flags & FINDKERNEL)
                sprintf(&buf[strlen(buf)],
                        "%sFINDKERNEL", others++ ? "|" : "");
        if (pc->flags & VERSION_QUERY)
                sprintf(&buf[strlen(buf)],
                        "%sVERSION_QUERY", others++ ? "|" : "");
        if (pc->flags & READNOW)
                sprintf(&buf[strlen(buf)],
                        "%sREADNOW", others++ ? "|" : "");
        if (pc->flags & NOCRASHRC)
                sprintf(&buf[strlen(buf)],
                        "%sNOCRASHRC", others++ ? "|" : "");
        if (pc->flags & INIT_IFILE)
                sprintf(&buf[strlen(buf)],
                        "%sINIT_IFILE", others++ ? "|" : "");
        if (pc->flags & XEN_HYPER)
                sprintf(&buf[strlen(buf)],
                        "%sXEN_HYPER", others++ ? "|" : "");
        if (pc->flags & XEN_CORE)
                sprintf(&buf[strlen(buf)],
                        "%sXEN_CORE", others++ ? "|" : "");
        if (pc->flags & PLEASE_WAIT)
                sprintf(&buf[strlen(buf)],
                        "%sPLEASE_WAIT", others++ ? "|" : "");
        if (pc->flags & IFILE_ERROR)
                sprintf(&buf[strlen(buf)],
                        "%sIFILE_ERROR", others++ ? "|" : "");
        if (pc->flags & MINIMAL_MODE)
                sprintf(&buf[strlen(buf)],
                        "%sMINIMAL_MODE", others++ ? "|" : "");
        if (pc->flags & CRASHBUILTIN)
                sprintf(&buf[strlen(buf)], 
			"%sCRASHBUILTIN", others++ ? "|" : "");
        if (pc->flags & PRELOAD_EXTENSIONS)
                sprintf(&buf[strlen(buf)], 
			"%sPRELOAD_EXTENSIONS", others++ ? "|" : "");
        if (pc->flags & PROC_KCORE)
                sprintf(&buf[strlen(buf)], 
			"%sPROC_KCORE", others++ ? "|" : "");

	if (pc->flags)
		strcat(buf, ")");

	if (strlen(buf)) {
		if (strlen(buf) > 46) {
			sprintf(buf2, "\n%s\n", 
				mkstring(buf, 80, CENTER|LJUST, NULL));
			if (strlen(buf2) <= 82) 
				fprintf(fp, "%s", buf2);
			else {
				for (i = strlen(buf2)-1; i; i--) {
					if ((buf2[i] == '|') && (i < 80))
						break;
				}

				strcpy(buf, buf2);
				buf[i+1] = NULLCHAR;
				fprintf(fp, "%s\n %s", buf, &buf2[i+1]);
			}
		}
		else
			fprintf(fp, "%s\n", buf);
	}

	others = 0;
	fprintf(fp, "           flags2: %llx (", pc->flags2);
	if (pc->flags2 & FLAT)
		fprintf(fp, "%sFLAT", others++ ? "|" : "");
	if (pc->flags2 & ELF_NOTES)
		fprintf(fp, "%sELF_NOTES", others++ ? "|" : "");
	if (pc->flags2 & GET_OSRELEASE)
		fprintf(fp, "%sGET_OSRELEASE", others++ ? "|" : "");
	if (pc->flags2 & REMOTE_DAEMON)
		fprintf(fp, "%sREMOTE_DAEMON", others++ ? "|" : "");
	if (pc->flags2 & LIVE_DUMP)
		fprintf(fp, "%sLIVE_DUMP", others++ ? "|" : "");
	if (pc->flags2 & RADIX_OVERRIDE)
		fprintf(fp, "%sRADIX_OVERRIDE", others++ ? "|" : "");
	if (pc->flags2 & QEMU_MEM_DUMP_ELF)
		fprintf(fp, "%sQEMU_MEM_DUMP_ELF", others++ ? "|" : "");
	if (pc->flags2 & QEMU_MEM_DUMP_COMPRESSED)
		fprintf(fp, "%sQEMU_MEM_DUMP_COMPRESSED", others++ ? "|" : "");
	if (pc->flags2 & GET_LOG)
		fprintf(fp, "%sGET_LOG", others++ ? "|" : "");
	if (pc->flags2 & VMCOREINFO)
		fprintf(fp, "%sVMCOREINFO", others++ ? "|" : "");
	if (pc->flags2 & ALLOW_FP)
		fprintf(fp, "%sALLOW_FP", others++ ? "|" : "");
	if (pc->flags2 & RAMDUMP)
		fprintf(fp, "%sRAMDUMP", others++ ? "|" : "");
	if (pc->flags2 & OFFLINE_HIDE)
		fprintf(fp, "%sOFFLINE_HIDE", others++ ? "|" : "");
	if (pc->flags2 & INCOMPLETE_DUMP)
		fprintf(fp, "%sINCOMPLETE_DUMP", others++ ? "|" : "");
	if (pc->flags2 & SNAP)
		fprintf(fp, "%sSNAP", others++ ? "|" : "");
	if (pc->flags2 & EXCLUDED_VMEMMAP)
		fprintf(fp, "%sEXCLUDED_VMEMMAP", others++ ? "|" : "");
        if (pc->flags2 & MEMSRC_LOCAL)
		fprintf(fp, "%sMEMSRC_LOCAL", others++ ? "|" : "");
	if (pc->flags2 & REDZONE)
		fprintf(fp, "%sREDZONE", others++ ? "|" : "");
	if (pc->flags2 & VMWARE_VMSS_GUESTDUMP)
		fprintf(fp, "%sVMWARE_VMSS_GUESTDUMP", others++ ? "|" : "");
	fprintf(fp, ")\n");

	fprintf(fp, "         namelist: %s\n", pc->namelist);
	fprintf(fp, "         dumpfile: %s\n", pc->dumpfile);
	fprintf(fp, "      live_memsrc: %s\n", pc->live_memsrc);
	fprintf(fp, "       system_map: %s\n", pc->system_map);
	fprintf(fp, "   namelist_debug: %s\n", pc->namelist_debug);
	fprintf(fp, "   debuginfo_file: %s\n", pc->debuginfo_file);
	fprintf(fp, "    namelist_orig: %s\n", pc->namelist_orig);
	fprintf(fp, "namelist_dbg_orig: %s\n", pc->namelist_debug_orig);
	fprintf(fp, "  kvmdump_mapfile: %s\n", pc->kvmdump_mapfile);
	fprintf(fp, "    memory_module: %s\n", pc->memory_module);
	fprintf(fp, "    memory_device: %s\n", pc->memory_device);
	fprintf(fp, "     machine_type: %s\n", pc->machine_type);
	fprintf(fp, "     editing_mode: %s\n", pc->editing_mode);
	fprintf(fp, "              nfd: %d\n", pc->nfd);
	fprintf(fp, "              mfd: %d\n", pc->mfd);
	fprintf(fp, "              kfd: %d\n", pc->kfd);
	fprintf(fp, "              dfd: %d\n", pc->dfd);
	fprintf(fp, "            confd: %d\n", pc->confd);
	fprintf(fp, "             home: %s\n", pc->home);
	fprintf(fp, "     command_line: ");
	if (STRNEQ(pc->command_line, args[0]))
		fprintf(fp, "%s\n", concat_args(buf, 0, FALSE));
	else
		fprintf(fp, "%s\n", pc->command_line);
	fprintf(fp, "        orig_line: %s\n", pc->orig_line);
	fprintf(fp, "        eoc_index: %d\n", pc->eoc_index);
	fprintf(fp, "         readline: %lx\n", (ulong)pc->readline);
	fprintf(fp, "           my_tty: %s\n", pc->my_tty);
	fprintf(fp, "            debug: %ld\n", pc->debug);
	fprintf(fp, "       debug_save: %ld\n", pc->debug_save);
	fprintf(fp, "          console: %s\n", pc->console);
	fprintf(fp, " redhat_debug_loc: %s\n", pc->redhat_debug_loc);
	fprintf(fp, "        pipefd[2]: %d,%d\n", pc->pipefd[0], pc->pipefd[1]);
	fprintf(fp, "           nullfp: %lx\n", (ulong)pc->nullfp);
	fprintf(fp, "          stdpipe: %lx\n", (ulong)pc->stdpipe);
	fprintf(fp, "             pipe: %lx\n", (ulong)pc->pipe);
	fprintf(fp, "            ifile: %lx\n", (ulong)pc->ifile);
	fprintf(fp, "            ofile: %lx\n", (ulong)pc->ofile);
	fprintf(fp, "       ifile_pipe: %lx\n", (ulong)pc->ifile_pipe);
	fprintf(fp, "      ifile_ofile: %lx\n", (ulong)pc->ifile_ofile);
	fprintf(fp, "       args_ifile: %lx\n", (ulong)pc->args_ifile);
	fprintf(fp, "       input_file: %s\n", pc->input_file);
	fprintf(fp, "ifile_in_progress: %lx (", pc->ifile_in_progress);
	others = 0;
	if (pc->ifile_in_progress & RCHOME_IFILE)
		fprintf(fp, "%sRCHOME_IFILE", others++ ? "|" : "");
	if (pc->ifile_in_progress & RCLOCAL_IFILE)
		fprintf(fp, "%sRCLOCAL_IFILE", others++ ? "|" : "");
	if (pc->ifile_in_progress & CMDLINE_IFILE)
		fprintf(fp, "%sCMDLINE_IFILE", others++ ? "|" : "");
	if (pc->ifile_in_progress & RUNTIME_IFILE)
		fprintf(fp, "%sRUNTIME_IFILE", others++ ? "|" : "");
	fprintf(fp, ")\n");
	fprintf(fp, "     ifile_offset: %lld\n", (ulonglong)pc->ifile_offset);
	fprintf(fp, "runtime_ifile_cmd: %s\n", pc->runtime_ifile_cmd ?
                pc->runtime_ifile_cmd : "(unused)");
	fprintf(fp, "   scroll_command: ");
	switch (pc->scroll_command) 
	{
	case SCROLL_NONE:
		fprintf(fp, "SCROLL_NONE\n");
		break;
	case SCROLL_LESS:
		fprintf(fp, "SCROLL_LESS\n");
		break;
	case SCROLL_MORE:
		fprintf(fp, "SCROLL_MORE\n");
		break;
	case SCROLL_CRASHPAGER:
		fprintf(fp, "SCROLL_CRASHPAGER (%s)\n", getenv("CRASHPAGER"));
		break;
	}

	buf[0] = NULLCHAR;
	fprintf(fp, "         redirect: %lx ", pc->redirect);
	if (pc->redirect)
		sprintf(buf, "(");
	others = 0;
	if (pc->redirect & FROM_COMMAND_LINE)
		sprintf(&buf[strlen(buf)], 
			"%sFROM_COMMAND_LINE", others++ ? "|" : "");
	if (pc->redirect & FROM_INPUT_FILE)
		sprintf(&buf[strlen(buf)], 
			"%sFROM_INPUT_FILE", others++ ? "|" : "");
	if (pc->redirect & REDIRECT_NOT_DONE)
		sprintf(&buf[strlen(buf)], 
			"%sREDIRECT_NOT_DONE", others++ ? "|" : "");
	if (pc->redirect & REDIRECT_TO_PIPE)
		sprintf(&buf[strlen(buf)], 
			"%sREDIRECT_TO_PIPE", others++ ? "|" : "");
	if (pc->redirect & REDIRECT_TO_STDPIPE)
		sprintf(&buf[strlen(buf)], 
			"%sREDIRECT_TO_STDPIPE", others++ ? "|" : "");
	if (pc->redirect & REDIRECT_TO_FILE)
		sprintf(&buf[strlen(buf)], 
			"%sREDIRECT_TO_FILE", others++ ? "|" : "");
	if (pc->redirect & REDIRECT_FAILURE)
		sprintf(&buf[strlen(buf)], 
			"%sREDIRECT_FAILURE", others++ ? "|" : "");
	if (pc->redirect & REDIRECT_SHELL_ESCAPE)
		sprintf(&buf[strlen(buf)], 
			"%sREDIRECT_SHELL_ESCAPE", others++ ? "|" : "");
	if (pc->redirect & REDIRECT_SHELL_COMMAND)
		sprintf(&buf[strlen(buf)], 
			"%sREDIRECT_SHELL_COMMAND", others++ ? "|" : "");
	if (pc->redirect & REDIRECT_PID_KNOWN)
		sprintf(&buf[strlen(buf)], 
			"%sREDIRECT_PID_KNOWN", others++ ? "|" : "");
	if (pc->redirect & REDIRECT_MULTI_PIPE)
		sprintf(&buf[strlen(buf)], 
			"%sREDIRECT_MULTI_PIPE", others++ ? "|" : "");
	if (pc->redirect)
		strcat(buf, ")");

        if (strlen(buf)) {
                if (strlen(buf) > 54)
                        fprintf(fp, "\n%s\n",
                                mkstring(buf, 80, CENTER|LJUST, NULL));
                else
                        fprintf(fp, "%s\n", buf);
        }

	if (!pc->redirect)
		fprintf(fp, "\n");

	fprintf(fp, "      stdpipe_pid: %d\n", pc->stdpipe_pid);
	fprintf(fp, "         pipe_pid: %d\n", pc->pipe_pid);
	fprintf(fp, "   pipe_shell_pid: %d\n", pc->pipe_shell_pid);
	fprintf(fp, "     pipe_command: %s\n", pc->pipe_command);
	if (pc->symfile && pc->symfile2) {
		fprintf(fp, "          symfile: %lx  (%ld)\n", 
			(ulong)pc->symfile, (ulong)ftell(pc->symfile));
		fprintf(fp, "         symfile2: %lx  (%ld)\n", 
			(ulong)pc->symfile2, (ulong)ftell(pc->symfile2));
	} else {
		fprintf(fp, "          symfile: %lx \n", (ulong)pc->symfile);
		fprintf(fp, "         symfile2: %lx \n", (ulong)pc->symfile2);
	}
	fprintf(fp, "          tmpfile: %lx\n", (ulong)pc->tmpfile);
	fprintf(fp, "         saved_fp: %lx\n", (ulong)pc->saved_fp);
	fprintf(fp, "           tmp_fp: %lx\n", (ulong)pc->tmp_fp);
	fprintf(fp, "         tmpfile2: %lx\n", (ulong)pc->tmpfile2);

	fprintf(fp, "        cmd_table: %s\n", XEN_HYPER_MODE() ?
		"xen_hyper_command_table" : "linux_command_table");
	fprintf(fp, "           curcmd: %s\n", pc->curcmd);
	fprintf(fp, "          lastcmd: %s\n", pc->lastcmd);
	fprintf(fp, "      cur_gdb_cmd: %d  %s\n", pc->cur_gdb_cmd,
		gdb_command_string(pc->cur_gdb_cmd, buf, FALSE));
	fprintf(fp, "     last_gdb_cmd: %d  %s\n", pc->last_gdb_cmd,
		gdb_command_string(pc->last_gdb_cmd, buf, FALSE));
	fprintf(fp, "          cur_req: %lx\n", (ulong)pc->cur_req);
	fprintf(fp, "        cmdgencur: %ld\n", pc->cmdgencur); 
	fprintf(fp, "     curcmd_flags: %lx (", pc->curcmd_flags);
	others = 0;
        if (pc->curcmd_flags & XEN_MACHINE_ADDR)
		fprintf(fp, "%sXEN_MACHINE_ADDR", others ? "|" : "");
        if (pc->curcmd_flags & REPEAT)
		fprintf(fp, "%sREPEAT", others ? "|" : "");
        if (pc->curcmd_flags & IDLE_TASK_SHOWN)
		fprintf(fp, "%sIDLE_TASK_SHOWN", others ? "|" : "");
        if (pc->curcmd_flags & TASK_SPECIFIED)
		fprintf(fp, "%sTASK_SPECIFIED", others ? "|" : "");
        if (pc->curcmd_flags & MEMTYPE_UVADDR)
		fprintf(fp, "%sMEMTYPE_UVADDR", others ? "|" : "");
        if (pc->curcmd_flags & MEMTYPE_FILEADDR)
		fprintf(fp, "%sMEMTYPE_FILEADDR", others ? "|" : "");
        if (pc->curcmd_flags & HEADER_PRINTED)
		fprintf(fp, "%sHEADER_PRINTED", others ? "|" : "");
        if (pc->curcmd_flags & BAD_INSTRUCTION)
		fprintf(fp, "%sBAD_INSTRUCTION", others ? "|" : "");
        if (pc->curcmd_flags & UD2A_INSTRUCTION)
		fprintf(fp, "%sUD2A_INSTRUCTION", others ? "|" : "");
        if (pc->curcmd_flags & IRQ_IN_USE)
		fprintf(fp, "%sIRQ_IN_USE", others ? "|" : "");
        if (pc->curcmd_flags & IGNORE_ERRORS)
		fprintf(fp, "%sIGNORE_ERRORS", others ? "|" : "");
        if (pc->curcmd_flags & FROM_RCFILE)
		fprintf(fp, "%sFROM_RCFILE", others ? "|" : "");
        if (pc->curcmd_flags & MEMTYPE_KVADDR)
		fprintf(fp, "%sMEMTYPE_KVADDR", others ? "|" : "");
        if (pc->curcmd_flags & NO_MODIFY)
		fprintf(fp, "%sNO_MODIFY", others ? "|" : "");
        if (pc->curcmd_flags & MOD_SECTIONS)
		fprintf(fp, "%sMOD_SECTIONS", others ? "|" : "");
        if (pc->curcmd_flags & MOD_READNOW)
		fprintf(fp, "%sMOD_READNOW", others ? "|" : "");
        if (pc->curcmd_flags & MM_STRUCT_FORCE)
		fprintf(fp, "%sMM_STRUCT_FORCE", others ? "|" : "");
        if (pc->curcmd_flags & CPUMASK)
		fprintf(fp, "%sCPUMASK", others ? "|" : "");
        if (pc->curcmd_flags & PARTIAL_READ_OK)
		fprintf(fp, "%sPARTIAL_READ_OK", others ? "|" : "");
	fprintf(fp, ")\n");
	fprintf(fp, "   curcmd_private: %llx\n", pc->curcmd_private); 
	fprintf(fp, "      cmd_cleanup: %lx\n", (ulong)pc->cmd_cleanup);
	fprintf(fp, "  cmd_cleanup_arg: %lx\n", (ulong)pc->cmd_cleanup_arg);
	fprintf(fp, "       sigint_cnt: %d\n", pc->sigint_cnt);
	fprintf(fp, "        sigaction: %lx\n", (ulong)&pc->sigaction);
	fprintf(fp, "    gdb_sigaction: %lx\n", (ulong)&pc->gdb_sigaction);
	fprintf(fp, "    main_loop_env: %lx\n", (ulong)&pc->main_loop_env);
	fprintf(fp, " foreach_loop_env: %lx\n", (ulong)&pc->foreach_loop_env);
	fprintf(fp, "     termios_orig: %lx\n", (ulong)&pc->termios_orig);
	fprintf(fp, "      termios_raw: %lx\n", (ulong)&pc->termios_raw);
	fprintf(fp, "            ncmds: %d\n", pc->ncmds);
	fprintf(fp, "          cmdlist: %lx\n", (ulong)pc->cmdlist);
	fprintf(fp, "        cmdlistsz: %d\n", pc->cmdlistsz);
	fprintf(fp, "     output_radix: %d (%s)\n", pc->output_radix,
		pc->output_radix == 16 ? 
		"hex" : ((pc->output_radix == 10) ? "decimal" : "???"));

	fprintf(fp, "           server: %s\n", pc->server);
	fprintf(fp, "       server_pid: %ld\n", pc->server_pid);
	fprintf(fp, "             port: %d\n", pc->port);
	fprintf(fp, "           sockfd: %d\n", pc->sockfd);
	fprintf(fp, "    server_memsrc: %s\n", pc->server_memsrc);
	fprintf(fp, "  server_namelist: %s\n", pc->server_namelist);
	fprintf(fp, "             rmfd: %d\n", pc->rmfd);
	fprintf(fp, "             rkfd: %d\n", pc->rkfd);
	fprintf(fp, "       rcvbufsize: %ld\n", pc->rcvbufsize);

	fprintf(fp, "          readmem: ");
	if ((p1 = readmem_function_name()))
		fprintf(fp, "%s()\n", p1);
	else
		fprintf(fp, "%lx\n", (ulong)pc->readmem);

	fprintf(fp, "         writemem: ");
	if ((p1 = writemem_function_name()))
		fprintf(fp, "%s()\n", p1);
	else
		fprintf(fp, "%lx\n", (ulong)pc->writemem);

	fprintf(fp, "  dumpfile memory: %d\n", 
		dumpfile_memory(DUMPFILE_MEM_USED)); 
	fprintf(fp, "           curext: %lx\n", (ulong)pc->curext); 
	fprintf(fp, "             sbrk: %lx\n", (ulong)pc->sbrk); 
	fprintf(fp, "          cleanup: %s\n", pc->cleanup);
	fprintf(fp, "            scope: %lx %s\n", pc->scope,
		pc->scope ? "" : "(not set)");
	fprintf(fp, "   nr_hash_queues: %ld\n", pc->nr_hash_queues);
	fprintf(fp, "  read_vmcoreinfo: %lx\n", (ulong)pc->read_vmcoreinfo);
	fprintf(fp, "         error_fp: %lx\n", (ulong)pc->error_fp);
	fprintf(fp, "       error_path: %s\n", pc->error_path);
}

char *
readmem_function_name(void)
{
	if (pc->readmem == read_dev_mem)
		return("read_dev_mem");
	else if (pc->readmem == read_mclx_dumpfile)
		return("read_mclx_dumpfile");
	else if (pc->readmem == read_lkcd_dumpfile)
		return("read_lkcd_dumpfile");
	else if (pc->readmem == read_daemon)
		return("read_daemon");
	else if (pc->readmem == read_netdump)
		return("read_netdump");
	else if (pc->readmem == read_xendump)
		return("read_xendump");
	else if (pc->readmem == read_kdump)
		return("read_kdump");
	else if (pc->readmem == read_memory_device)
		return("read_memory_device");
	else if (pc->readmem == read_xendump_hyper)
		return("read_xendump_hyper");
	else if (pc->readmem == read_diskdump)
		return("read_diskdump");
	else if (pc->readmem == read_proc_kcore)
		return("read_proc_kcore");
	else if (pc->readmem == read_sadump)
		return("read_sadump");
	else if (pc->readmem == read_s390_dumpfile)
		return("read_s390_dumpfile");
	else if (pc->readmem == read_ramdump)
		return("read_ramdump");
	else if (pc->readmem == read_vmware_vmss)
		return("read_vmware_vmss");
	else
		return NULL;
}

char *
writemem_function_name(void)
{
	if (pc->writemem == write_dev_mem)
		return("write_dev_mem");
	else if (pc->writemem == write_mclx_dumpfile)
		return("write_mclx_dumpfile");
	else if (pc->writemem == write_lkcd_dumpfile)
		return("write_lkcd_dumpfile");
	else if (pc->writemem == write_daemon)
		return("write_daemon");
	else if (pc->writemem == write_netdump)
		return("write_netdump");
	else if (pc->writemem == write_xendump)
		return("write_xendump");
	else if (pc->writemem == write_kdump)
		return("write_kdump");
	else if (pc->writemem == write_memory_device)
		return("write_memory_device");
//	else if (pc->writemem == write_xendump_hyper)
//		return("write_xendump_hyper");
	else if (pc->writemem == write_diskdump)
		return("write_diskdump");
	else if (pc->writemem == write_proc_kcore)
		return("write_proc_kcore");
	else if (pc->writemem == write_sadump)
		return("write_sadump");
	else if (pc->writemem == write_s390_dumpfile)
		return("write_s390_dumpfile");
	else if (pc->writemem == write_vmware_vmss)
		return("write_vmware_vmss");
	else
		return NULL;
}

/*
 *  "help -B" output
 */
void
dump_build_data(void)
{
        fprintf(fp, "   build_command: %s\n", build_command);
        fprintf(fp, "      build_data: %s\n", build_data);
        fprintf(fp, "    build_target: %s\n", build_target);
        fprintf(fp, "   build_version: %s\n", build_version);
        fprintf(fp, "compiler version: %s\n", compiler_version);
}

/*
 *  Perform any cleanup activity here.
 */
int 
clean_exit(int status)
{
	if (pc->flags & MEMMOD)
		cleanup_memory_driver();

	if ((pc->namelist_orig) && file_exists(pc->namelist, NULL))
		unlink(pc->namelist);
	if ((pc->namelist_debug_orig) && file_exists(pc->namelist_debug, NULL))
		unlink(pc->namelist_debug);
	if (pc->cleanup && file_exists(pc->cleanup, NULL))
		unlink(pc->cleanup);

	ramdump_cleanup();
	exit(status);
}

/*
 *  Check whether this session is for xen hypervisor analysis.
 */
static void
check_xen_hyper(void)
{
	if (!pc->namelist)
		return;

	if (!XEN_HYPER_MODE()) {
		if (STRNEQ(basename(pc->namelist), "xen-syms"))
			pc->flags |= XEN_HYPER;
		else
			return;
	}

#ifdef XEN_HYPERVISOR_ARCH
	pc->cmd_table = xen_hyper_command_table;
	if (pc->flags & XENDUMP)
		pc->readmem = read_xendump_hyper;
#else
	error(FATAL, XEN_HYPERVISOR_NOT_SUPPORTED);
#endif
}

/*
 *  Reject untrusted .crashrc, $HOME/.crashrc, 
 *  .gdbinit, and $HOME/.gdbinit files.
 */
static char *untrusted_file_list[4] = { 0 };

int
untrusted_file(FILE *filep, char *filename)
{
	struct stat sbuf;
	int i;

	if (filep && (fstat(fileno(filep), &sbuf) == 0) &&
	    (sbuf.st_uid == getuid()) && !(sbuf.st_mode & S_IWOTH))
		return FALSE;
	
	for (i = 0; i < 4; i++) {
		if (!untrusted_file_list[i]) {
			untrusted_file_list[i] = strdup(filename);
			break;
		}
	}

	return TRUE;
}

static void
show_untrusted_files(void)
{
	int i, cnt;

	for (i = cnt = 0; i < 4; i++) {
		if (untrusted_file_list[i]) {
			error(WARNING, "not using untrusted file: \"%s\"\n", 
				untrusted_file_list[i]);
			free(untrusted_file_list[i]);
			cnt++;
		}
	}
	if (cnt)
		fprintf(fp, "\n");
}

/*
 *  If GET_OSRELEASE is still set, the OS release has been
 *  found and displayed.
 */
static void
get_osrelease(char *dumpfile)
{
	int retval = 1;

	if (is_flattened_format(dumpfile)) {
		if (pc->flags2 & GET_OSRELEASE)
			retval = 0;
	} else if (is_diskdump(dumpfile)) {
		if (pc->flags2 & GET_OSRELEASE)
			retval = 0;
	} else if (is_kdump(dumpfile, KDUMP_LOCAL)) {
		if (pc->flags2 & GET_OSRELEASE)
			retval = 0;
	}
	
	if (retval)
		fprintf(fp, "unknown\n");

	clean_exit(retval);
}

static void
get_log(char *dumpfile)
{

	int retval = 1;

	if (is_flattened_format(dumpfile))
		pc->flags2 |= FLAT;
	
	if (is_diskdump(dumpfile)) {
		if (pc->flags2 & GET_LOG)
			retval = 0;
	} else if (is_kdump(dumpfile, KDUMP_LOCAL)) {
		if (pc->flags2 & GET_LOG)
			retval = 0;
	}

	if (retval)
		fprintf(fp, "%s: no VMCOREINFO data\n", dumpfile);

	clean_exit(retval);
}


char *
no_vmcoreinfo(const char *unused)
{
	return NULL;
}
