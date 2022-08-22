# Makefile for core analysis suite
#
# Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
#       www.missioncriticallinux.com, info@missioncriticallinux.com
#
# Copyright (C) 2002-2016 David Anderson
# Copyright (C) 2002-2016 Red Hat, Inc. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#

MAKEFLAGS += --no-print-directory
PROGRAM=crash

#
# Supported targets: X86 ALPHA PPC IA64 PPC64 SPARC64
# TARGET and GDB_CONF_FLAGS will be configured automatically by configure
#
TARGET=
GDB_CONF_FLAGS=

ARCH := $(shell uname -m | sed -e s/i.86/i386/ -e s/sun4u/sparc64/ -e s/arm.*/arm/ -e s/sa110/arm/)
ifeq (${ARCH}, ppc64)
CONF_FLAGS = -m64
endif

#
# GDB, GDB_FILES, GDB_OFILES and GDB_PATCH_FILES will be configured automatically by configure 
#
GDB=
GDB_FILES=
GDB_OFILES=
GDB_PATCH_FILES=

#
# Default installation directory
#
INSTALLDIR=${DESTDIR}/usr/bin

# LDFLAGS will be configured automatically by configure
LDFLAGS=

GENERIC_HFILES=defs.h xen_hyper_defs.h xen_dom0.h
MCORE_HFILES=va_server.h vas_crash.h
REDHAT_HFILES=netdump.h diskdump.h makedumpfile.h xendump.h kvmdump.h qemu-load.h vmcore.h
LKCD_DUMP_HFILES=lkcd_vmdump_v1.h lkcd_vmdump_v2_v3.h lkcd_dump_v5.h \
        lkcd_dump_v7.h lkcd_dump_v8.h
LKCD_OBSOLETE_HFILES=lkcd_fix_mem.h
LKCD_TRACE_HFILES=lkcd_x86_trace.h
IBM_HFILES=ibm_common.h
SADUMP_HFILES=sadump.h
UNWIND_HFILES=unwind.h unwind_i.h rse.h unwind_x86.h unwind_x86_64.h
VMWARE_HFILES=vmware_vmss.h

CFILES=main.c tools.c global_data.c memory.c filesys.c help.c task.c \
	kernel.c test.c gdb_interface.c configure.c net.c dev.c bpf.c \
	printk.c \
	alpha.c x86.c ppc.c ia64.c s390.c s390x.c s390dbf.c ppc64.c x86_64.c \
	arm.c arm64.c mips.c mips64.c sparc64.c \
	extensions.c remote.c va_server.c va_server_v1.c symbols.c cmdline.c \
	lkcd_common.c lkcd_v1.c lkcd_v2_v3.c lkcd_v5.c lkcd_v7.c lkcd_v8.c\
	lkcd_fix_mem.c s390_dump.c lkcd_x86_trace.c \
	netdump.c diskdump.c makedumpfile.c xendump.c unwind.c unwind_decoder.c \
	unwind_x86_32_64.c unwind_arm.c \
	xen_hyper.c xen_hyper_command.c xen_hyper_global_data.c \
	xen_hyper_dump_tables.c kvmdump.c qemu.c qemu-load.c sadump.c ipcs.c \
	ramdump.c vmware_vmss.c vmware_guestdump.c \
	xen_dom0.c kaslr_helper.c sbitmap.c

SOURCE_FILES=${CFILES} ${GENERIC_HFILES} ${MCORE_HFILES} \
	${REDHAT_CFILES} ${REDHAT_HFILES} ${UNWIND_HFILES} \
	${LKCD_DUMP_HFILES} ${LKCD_TRACE_HFILES} ${LKCD_OBSOLETE_HFILES}\
	${IBM_HFILES} ${SADUMP_HFILES} ${VMWARE_HFILES}

OBJECT_FILES=main.o tools.o global_data.o memory.o filesys.o help.o task.o \
	build_data.o kernel.o test.o gdb_interface.o net.o dev.o bpf.o \
	printk.o \
	alpha.o x86.o ppc.o ia64.o s390.o s390x.o s390dbf.o ppc64.o x86_64.o \
	arm.o arm64.o mips.o mips64.o sparc64.o \
	extensions.o remote.o va_server.o va_server_v1.o symbols.o cmdline.o \
	lkcd_common.o lkcd_v1.o lkcd_v2_v3.o lkcd_v5.o lkcd_v7.o lkcd_v8.o \
	lkcd_fix_mem.o s390_dump.o netdump.o diskdump.o makedumpfile.o xendump.o \
	lkcd_x86_trace.o unwind_v1.o unwind_v2.o unwind_v3.o \
	unwind_x86_32_64.o unwind_arm.o \
	xen_hyper.o xen_hyper_command.o xen_hyper_global_data.o \
	xen_hyper_dump_tables.o kvmdump.o qemu.o qemu-load.o sadump.o ipcs.o \
	ramdump.o vmware_vmss.o vmware_guestdump.o \
	xen_dom0.o kaslr_helper.o sbitmap.o

MEMORY_DRIVER_FILES=memory_driver/Makefile memory_driver/crash.c memory_driver/README

# These are the current set of crash extensions sources.  They are not built
# by default unless the third command line of the "all:" stanza is uncommented.
# Alternatively, they can be built by entering "make extensions" from this
# directory.

EXTENSIONS=extensions
EXTENSION_SOURCE_FILES=${EXTENSIONS}/Makefile ${EXTENSIONS}/echo.c ${EXTENSIONS}/dminfo.c \
	${EXTENSIONS}/snap.c ${EXTENSIONS}/snap.mk ${EXTENSIONS}/trace.c \
	${EXTENSIONS}/eppic.c ${EXTENSIONS}/eppic.mk

DAEMON_OBJECT_FILES=remote_daemon.o va_server.o va_server_v1.o \
	lkcd_common.o lkcd_v1.o lkcd_v2_v3.o lkcd_v5.o lkcd_v7.o lkcd_v8.o \
	s390_dump.o netdump_daemon.o

GDB_5.0_FILES=${GDB}/gdb/Makefile.in \
	  ${GDB}/gdb/main.c ${GDB}/gdb/symtab.c ${GDB}/gdb/target.c \
	  ${GDB}/gdb/blockframe.c ${GDB}/gdb/alpha-tdep.c \
	  ${GDB}/gdb/symfile.c ${GDB}/gdb/elfread.c \
	  ${GDB}/gdb/ui-file.c ${GDB}/gdb/utils.c ${GDB}/gdb/gnu-regex.c \
	  ${GDB}/gdb/ppc-linux-nat.c
GDB_5.0_OFILES=${GDB}/gdb/main.o ${GDB}/gdb/symtab.o ${GDB}/gdb/target.o \
          ${GDB}/gdb/blockframe.o ${GDB}/gdb/alpha-tdep.o \
          ${GDB}/gdb/symfile.o ${GDB}/gdb/elfread.o \
          ${GDB}/gdb/ui-file.o ${GDB}/gdb/utils.o ${GDB}/gdb/gnu-regex.o \
          ${GDB}/gdb/ppc-linux-nat.o

GDB_5.1_FILES=${GDB}/gdb/Makefile.in \
	  ${GDB}/gdb/main.c ${GDB}/gdb/symtab.c ${GDB}/gdb/target.c \
	  ${GDB}/gdb/blockframe.c ${GDB}/gdb/alpha-tdep.c \
	  ${GDB}/gdb/symfile.c ${GDB}/gdb/elfread.c \
	  ${GDB}/gdb/ui-file.c ${GDB}/gdb/utils.c  ${GDB}/gdb/gnu-regex.c
GDB_5.1_OFILES=${GDB}/gdb/main.o ${GDB}/gdb/symtab.o ${GDB}/gdb/target.o \
          ${GDB}/gdb/blockframe.o ${GDB}/gdb/alpha-tdep.o \
          ${GDB}/gdb/symfile.o ${GDB}/gdb/elfread.o \
          ${GDB}/gdb/ui-file.o ${GDB}/gdb/utils.o ${GDB}/gdb/gnu-regex.o

GDB_5.2.1_FILES=${GDB}/gdb/Makefile.in \
          ${GDB}/gdb/main.c ${GDB}/gdb/symtab.c ${GDB}/gdb/target.c \
          ${GDB}/gdb/blockframe.c ${GDB}/gdb/alpha-tdep.c \
          ${GDB}/gdb/symfile.c ${GDB}/gdb/elfread.c \
          ${GDB}/gdb/ui-file.c ${GDB}/gdb/utils.c
GDB_5.2.1_OFILES=${GDB}/gdb/main.o ${GDB}/gdb/symtab.o ${GDB}/gdb/target.o \
          ${GDB}/gdb/blockframe.o ${GDB}/gdb/alpha-tdep.o \
          ${GDB}/gdb/symfile.o ${GDB}/gdb/elfread.o \
          ${GDB}/gdb/ui-file.o ${GDB}/gdb/utils.o 

GDB_5.3post-0.20021129.36rh_FILES=${GDB}/gdb/Makefile.in \
          ${GDB}/gdb/main.c ${GDB}/gdb/symtab.c ${GDB}/gdb/target.c \
          ${GDB}/gdb/frame.c ${GDB}/gdb/alpha-tdep.c \
          ${GDB}/gdb/symfile.c ${GDB}/gdb/elfread.c \
          ${GDB}/gdb/ui-file.c ${GDB}/gdb/utils.c ${GDB}/gdb/dwarf2read.c
GDB_5.3post-0.20021129.36rh_OFILES=${GDB}/gdb/main.o ${GDB}/gdb/symtab.o \
          ${GDB}/gdb/target.o ${GDB}/gdb/frame.o ${GDB}/gdb/alpha-tdep.o \
          ${GDB}/gdb/symfile.o ${GDB}/gdb/elfread.o ${GDB}/gdb/ui-file.o \
          ${GDB}/gdb/utils.o ${GDB}/gdb/dwarf2read.o

GDB_6.0_FILES=${GDB}/gdb/Makefile.in ${GDB}/Makefile.in \
          ${GDB}/gdb/main.c ${GDB}/gdb/symtab.c ${GDB}/gdb/target.c \
          ${GDB}/gdb/symfile.c ${GDB}/gdb/elfread.c \
          ${GDB}/gdb/ui-file.c ${GDB}/gdb/utils.c \
	  ${GDB}/gdb/ppc-linux-tdep.c ${GDB}/sim/ppc/ppc-instructions \
	  ${GDB}/bfd/simple.c ${GDB}/include/obstack.h
GDB_6.0_OFILES=${GDB}/gdb/main.o ${GDB}/gdb/symtab.o \
          ${GDB}/gdb/target.o ${GDB}/gdb/symfile.o ${GDB}/gdb/elfread.o \
          ${GDB}/gdb/ui-file.o ${GDB}/gdb/utils.o \
	  ${GDB}/gdb/ppc-linux-tdep.o ${GDB}/bfd/simple.o

GDB_6.1_FILES=${GDB}/gdb/Makefile.in ${GDB}/Makefile.in \
          ${GDB}/gdb/main.c ${GDB}/gdb/symtab.c ${GDB}/gdb/target.c \
          ${GDB}/gdb/symfile.c ${GDB}/gdb/elfread.c \
          ${GDB}/gdb/ui-file.c ${GDB}/gdb/utils.c ${GDB}/gdb/dwarf2read.c \
          ${GDB}/include/obstack.h ${GDB}/gdb/ppc-linux-tdep.c
GDB_6.1_OFILES=${GDB}/gdb/main.o ${GDB}/gdb/symtab.o \
          ${GDB}/gdb/target.o ${GDB}/gdb/symfile.o ${GDB}/gdb/elfread.o \
          ${GDB}/gdb/ui-file.o ${GDB}/gdb/utils.o ${GDB}/gdb/dwarf2read.o \
          ${GDB}/gdb/ppc-linux-tdep.o

GDB_7.0_FILES=
GDB_7.0_OFILES=${GDB}/gdb/symtab.o

GDB_7.3.1_FILES=
GDB_7.3.1_OFILES=${GDB}/gdb/symtab.o

GDB_7.6_FILES=
GDB_7.6_OFILES=${GDB}/gdb/symtab.o

GDB_10.2_FILES=
GDB_10.2_OFILES=${GDB}/gdb/symtab.o crash_target.o

# 
# GDB_FLAGS is passed up from the gdb Makefile.
#
GDB_FLAGS=

#
# WARNING_OPTIONS and WARNING_ERROR are both applied on a per-file basis. 
# WARNING_ERROR is NOT used on files including "dirty" gdb headers so that 
# successful compilations can be achieved with acceptable warnings; its 
# usefulness is also dependent upon the processor's compiler -- your mileage
# may vary.
#
#WARNING_OPTIONS=-Wall -O2 -Wstrict-prototypes -Wmissing-prototypes -fstack-protector -Wformat-security
#WARNING_ERROR=-Werror

# TARGET_CFLAGS will be configured automatically by configure
TARGET_CFLAGS=

CRASH_CFLAGS=-g -D${TARGET} ${TARGET_CFLAGS} ${GDB_FLAGS} ${CFLAGS}

GPL_FILES=
TAR_FILES=${SOURCE_FILES} Makefile ${GPL_FILES} README .rh_rpm_package crash.8 \
	${EXTENSION_SOURCE_FILES} ${MEMORY_DRIVER_FILES}
CSCOPE_FILES=${SOURCE_FILES}

READLINE_DIRECTORY=./${GDB}/readline/readline
BFD_DIRECTORY=./${GDB}/bfd
GDB_INCLUDE_DIRECTORY=./${GDB}/include

REDHATFLAGS=-DREDHAT

# target could be set on command line when invoking make. Like: make target=ARM
# otherwise target will be the same as the host
ifneq ($(target),)
CONF_TARGET_FLAG="-t$(target)"
endif

ifeq ($(findstring warn,$(MAKECMDGOALS)),warn)
CONF_TARGET_FLAG += -w
endif
ifeq ($(findstring Warn,$(MAKECMDGOALS)),Warn)
CONF_TARGET_FLAG += -W
endif
ifeq ($(findstring nowarn,$(MAKECMDGOALS)),nowarn)
CONF_TARGET_FLAG += -n
endif
ifeq ($(findstring lzo,$(MAKECMDGOALS)),lzo)
CONF_TARGET_FLAG += -x lzo
endif
ifeq ($(findstring snappy,$(MAKECMDGOALS)),snappy)
CONF_TARGET_FLAG += -x snappy
endif
ifeq ($(findstring zstd,$(MAKECMDGOALS)),zstd)
CONF_TARGET_FLAG += -x zstd
endif
ifeq ($(findstring valgrind,$(MAKECMDGOALS)),valgrind)
CONF_TARGET_FLAG += -x valgrind
endif

# To build the extensions library by default, uncomment the third command
# line below.  Otherwise they can be built by entering "make extensions".

all: make_configure
	@./configure ${CONF_TARGET_FLAG} -p "RPMPKG=${RPMPKG}" -b
	@$(MAKE) gdb_merge
#	@$(MAKE) extensions

gdb_merge: force
	@if [ ! -f ${GDB}/README ]; then \
	  $(MAKE) gdb_unzip; fi
	@echo "${LDFLAGS} -lz -ldl -rdynamic" > ${GDB}/gdb/mergelibs
	@echo "../../${PROGRAM} ../../${PROGRAM}lib.a" > ${GDB}/gdb/mergeobj
	@rm -f ${PROGRAM}
	@if [ ! -f ${GDB}/config.status ]; then \
	  (cd ${GDB}; ./configure ${GDB_CONF_FLAGS} --with-separate-debug-dir=/usr/lib/debug \
	    --with-bugurl="" --with-expat=no --with-python=no --disable-sim; \
	  $(MAKE) CRASH_TARGET=${TARGET}; echo ${TARGET} > crash.target) \
	else $(MAKE) rebuild; fi
	@if [ ! -f ${PROGRAM} ]; then \
	  echo; echo "${PROGRAM} build failed"; \
	  echo; exit 1; fi

rebuild:
	@if [ ! -f ${GDB}/${GDB}.patch ]; then \
	  touch ${GDB}/${GDB}.patch; fi
	@if [ -f ${GDB}.patch ] && [ -s ${GDB}.patch ] && \
	  [ "`md5sum < ${GDB}.patch`" != "`md5sum < ${GDB}/${GDB}.patch`" ]; then \
	  (sh -x ${GDB}.patch ${TARGET}; patch -N -p0 -r- --fuzz=0 < ${GDB}.patch; cp ${GDB}.patch ${GDB}; cd ${GDB}; \
	  $(MAKE) CRASH_TARGET=${TARGET}) \
	else (cd ${GDB}/gdb; $(MAKE) CRASH_TARGET=${TARGET}); fi

gdb_unzip:
	@rm -f gdb.files
	@for FILE in ${GDB_FILES} dummy; do\
	  echo $$FILE >> gdb.files; done
	@if [ ! -f ${GDB}.tar.gz ] && [ ! -f /usr/bin/wget ]; then \
	  echo /usr/bin/wget is required to download ${GDB}.tar.gz; echo; exit 1; fi
	@if [ ! -f ${GDB}.tar.gz ] && [ -f /usr/bin/wget ]; then \
	  [ ! -t 2 ] && WGET_OPTS="--progress=dot:mega"; \
	  wget $$WGET_OPTS http://ftp.gnu.org/gnu/gdb/${GDB}.tar.gz; fi
	@tar --exclude-from gdb.files -xzmf ${GDB}.tar.gz
	@$(MAKE) gdb_patch

gdb_patch:
	if [ -f ${GDB}.patch ] && [ -s ${GDB}.patch ]; then \
		patch -p0 < ${GDB}.patch; cp ${GDB}.patch ${GDB}; fi

library: ${OBJECT_FILES}
	ar -rs ${PROGRAM}lib.a ${OBJECT_FILES}

gdb: force
	rm -f ${GDB_OFILES}
	@$(MAKE) all

force:
	

make_configure: force
	@rm -f configure
	@${CC} ${CONF_FLAGS} -o configure configure.c ${WARNING_ERROR} ${WARNING_OPTIONS}

clean: make_configure
	@./configure ${CONF_TARGET_FLAG} -q -b
	@$(MAKE) do_clean

do_clean:
	rm -f ${OBJECT_FILES} ${DAEMON_OBJECT_FILES} ${PROGRAM} ${PROGRAM}lib.a ${GDB_OFILES}
	@$(MAKE) -C extensions -i clean
	@$(MAKE) -C memory_driver -i clean

build_data.o: force
	${CC} -c ${CRASH_CFLAGS} build_data.c ${WARNING_OPTIONS} ${WARNING_ERROR}

install:
	/usr/bin/install -d ${INSTALLDIR}
	/usr/bin/install ${PROGRAM} ${INSTALLDIR}
#	/usr/bin/install ${PROGRAM}d ${INSTALLDIR}

unconfig: make_configure
	@./configure -u

warn Warn nowarn lzo snappy zstd valgrind: all
	@true  #dummy

main.o: ${GENERIC_HFILES} main.c
	${CC} -c ${CRASH_CFLAGS} main.c ${WARNING_OPTIONS} ${WARNING_ERROR} 

cmdline.o: ${GENERIC_HFILES} cmdline.c
	${CC} -c ${CRASH_CFLAGS} cmdline.c -I${READLINE_DIRECTORY} ${WARNING_OPTIONS} ${WARNING_ERROR}

tools.o: ${GENERIC_HFILES} tools.c
	${CC} -c ${CRASH_CFLAGS} tools.c ${WARNING_OPTIONS} ${WARNING_ERROR}

sbitmap.o: ${GENERIC_HFILES} sbitmap.c
	${CC} -c ${CRASH_CFLAGS} sbitmap.c ${WARNING_OPTIONS} ${WARNING_ERROR}

global_data.o: ${GENERIC_HFILES} global_data.c
	${CC} -c ${CRASH_CFLAGS} global_data.c ${WARNING_OPTIONS} ${WARNING_ERROR}

symbols.o: ${GENERIC_HFILES} symbols.c
	${CC} -c ${CRASH_CFLAGS} symbols.c -I${BFD_DIRECTORY} -I${GDB_INCLUDE_DIRECTORY} ${WARNING_OPTIONS} ${WARNING_ERROR}

filesys.o: ${GENERIC_HFILES} filesys.c
	${CC} -c ${CRASH_CFLAGS} filesys.c ${WARNING_OPTIONS} ${WARNING_ERROR}

help.o: ${GENERIC_HFILES} help.c
	${CC} -c ${CRASH_CFLAGS} help.c ${WARNING_OPTIONS} ${WARNING_ERROR}

memory.o: ${GENERIC_HFILES} memory.c
	${CC} -c ${CRASH_CFLAGS} memory.c ${WARNING_OPTIONS} ${WARNING_ERROR}

test.o: ${GENERIC_HFILES} test.c
	${CC} -c ${CRASH_CFLAGS} test.c ${WARNING_OPTIONS} ${WARNING_ERROR}

task.o: ${GENERIC_HFILES} task.c
	${CC} -c ${CRASH_CFLAGS} task.c ${WARNING_OPTIONS} ${WARNING_ERROR}

kernel.o: ${GENERIC_HFILES} kernel.c
	${CC} -c ${CRASH_CFLAGS} kernel.c -I${BFD_DIRECTORY} -I${GDB_INCLUDE_DIRECTORY} ${WARNING_OPTIONS} ${WARNING_ERROR}

printk.o: ${GENERIC_HFILES} printk.c
	${CC} -c ${CRASH_CFLAGS} printk.c ${WARNING_OPTIONS} ${WARNING_ERROR}

gdb_interface.o: ${GENERIC_HFILES} gdb_interface.c
	${CC} -c ${CRASH_CFLAGS} gdb_interface.c ${WARNING_OPTIONS} ${WARNING_ERROR}

va_server.o: ${MCORE_HFILES} va_server.c
	${CC} -c ${CRASH_CFLAGS} va_server.c ${WARNING_OPTIONS} ${WARNING_ERROR}

va_server_v1.o: ${MCORE_HFILES} va_server_v1.c
	${CC} -c ${CRASH_CFLAGS} va_server_v1.c ${WARNING_OPTIONS} ${WARNING_ERROR}

lkcd_common.o: ${GENERIC_HFILES} ${LKCD_DUMP_HFILES} lkcd_common.c
	${CC} -c ${CRASH_CFLAGS} lkcd_common.c ${WARNING_OPTIONS} ${WARNING_ERROR}

lkcd_v1.o: ${GENERIC_HFILES} ${LKCD_DUMP_HFILES} lkcd_v1.c
	${CC} -c ${CRASH_CFLAGS} lkcd_v1.c -DMCLX ${WARNING_OPTIONS} ${WARNING_ERROR}

lkcd_v2_v3.o: ${GENERIC_HFILES} ${LKCD_DUMP_HFILES} lkcd_v2_v3.c
	${CC} -c ${CRASH_CFLAGS} lkcd_v2_v3.c -DMCLX ${WARNING_OPTIONS} ${WARNING_ERROR}

lkcd_v5.o: ${GENERIC_HFILES} ${LKCD_DUMP_HFILES} lkcd_v5.c
	${CC} -c ${CRASH_CFLAGS} lkcd_v5.c -DMCLX ${WARNING_OPTIONS} ${WARNING_ERROR}

lkcd_v7.o: ${GENERIC_HFILES} ${LKCD_DUMP_HFILES} lkcd_v7.c
	${CC} -c ${CRASH_CFLAGS} lkcd_v7.c -DMCLX ${WARNING_OPTIONS} ${WARNING_ERROR}

lkcd_v8.o: ${GENERIC_HFILES} ${LKCD_DUMP_HFILES} lkcd_v8.c
	${CC} -c ${CRASH_CFLAGS} lkcd_v8.c -DMCLX ${WARNING_OPTIONS} ${WARNING_ERROR}

net.o: ${GENERIC_HFILES} net.c
	${CC} -c ${CRASH_CFLAGS} net.c ${WARNING_OPTIONS} ${WARNING_ERROR}

dev.o: ${GENERIC_HFILES} ${REDHAT_HFILES} dev.c
	${CC} -c ${CRASH_CFLAGS} dev.c ${WARNING_OPTIONS} ${WARNING_ERROR}

# remote.c functionality has been deprecated
remote.o: ${GENERIC_HFILES} remote.c
	@${CC} -c ${CRASH_CFLAGS} remote.c ${WARNING_OPTIONS} ${WARNING_ERROR}
remote_daemon.o: ${GENERIC_HFILES} remote.c
	${CC} -c ${CRASH_CFLAGS} -DDAEMON remote.c -o remote_daemon.o ${WARNING_OPTIONS} ${WARNING_ERROR}

x86.o: ${GENERIC_HFILES} ${REDHAT_HFILES} x86.c
	${CC} -c ${CRASH_CFLAGS} x86.c -DMCLX ${WARNING_OPTIONS} ${WARNING_ERROR}

alpha.o: ${GENERIC_HFILES} alpha.c
	${CC} -c ${CRASH_CFLAGS} alpha.c ${WARNING_OPTIONS} ${WARNING_ERROR}

ppc.o: ${GENERIC_HFILES} ppc.c
	${CC} -c ${CRASH_CFLAGS} ppc.c ${WARNING_OPTIONS} ${WARNING_ERROR}

ia64.o: ${GENERIC_HFILES} ${REDHAT_HFILES} ia64.c
	${CC} -c ${CRASH_CFLAGS} ia64.c ${WARNING_OPTIONS} ${WARNING_ERROR}

ppc64.o: ${GENERIC_HFILES} ppc64.c
	${CC} -c ${CRASH_CFLAGS} ppc64.c ${WARNING_OPTIONS} ${WARNING_ERROR}

x86_64.o: ${GENERIC_HFILES} ${REDHAT_HFILES} x86_64.c
	${CC} -c ${CRASH_CFLAGS} x86_64.c ${WARNING_OPTIONS} ${WARNING_ERROR}

arm.o: ${GENERIC_HFILES} ${REDHAT_HFILES} arm.c
	${CC} -c ${CRASH_CFLAGS} arm.c ${WARNING_OPTIONS} ${WARNING_ERROR}

arm64.o: ${GENERIC_HFILES} ${REDHAT_HFILES} arm64.c
	${CC} -c ${CRASH_CFLAGS} arm64.c ${WARNING_OPTIONS} ${WARNING_ERROR}

mips.o: ${GENERIC_HFILES} ${REDHAT_HFILES} mips.c
	${CC} -c ${CRASH_CFLAGS} mips.c ${WARNING_OPTIONS} ${WARNING_ERROR}

mips64.o: ${GENERIC_HFILES} ${REDHAT_HFILES} mips64.c
	${CC} -c ${CRASH_CFLAGS} mips64.c ${WARNING_OPTIONS} ${WARNING_ERROR}

sparc64.o: ${GENERIC_HFILES} ${REDHAT_HFILES} sparc64.c
	${CC} -c ${CRASH_CFLAGS} sparc64.c ${WARNING_OPTIONS} ${WARNING_ERROR}

s390.o: ${GENERIC_HFILES} ${IBM_HFILES} s390.c
	${CC} -c ${CRASH_CFLAGS} s390.c ${WARNING_OPTIONS} ${WARNING_ERROR}

s390x.o: ${GENERIC_HFILES} ${IBM_HFILES} s390x.c
	${CC} -c ${CRASH_CFLAGS} s390x.c ${WARNING_OPTIONS} ${WARNING_ERROR}

s390dbf.o: ${GENERIC_HFILES} ${IBM_HFILES} s390dbf.c
	${CC} -c ${CRASH_CFLAGS} s390dbf.c ${WARNING_OPTIONS} ${WARNING_ERROR}

s390_dump.o: ${GENERIC_HFILES} ${IBM_HFILES} s390_dump.c
	${CC} -c ${CRASH_CFLAGS} s390_dump.c ${WARNING_OPTIONS} ${WARNING_ERROR}

netdump.o: ${GENERIC_HFILES} ${REDHAT_HFILES} ${SADUMP_HFILES} netdump.c
	${CC} -c ${CRASH_CFLAGS} netdump.c ${WARNING_OPTIONS} ${WARNING_ERROR}
netdump_daemon.o: ${GENERIC_HFILES} ${REDHAT_HFILES} netdump.c
	${CC} -c ${CRASH_CFLAGS} -DDAEMON netdump.c -o netdump_daemon.o ${WARNING_OPTIONS} ${WARNING_ERROR}

diskdump.o: ${GENERIC_HFILES} ${REDHAT_HFILES} diskdump.c
	${CC} -c ${CRASH_CFLAGS} diskdump.c ${WARNING_OPTIONS} ${WARNING_ERROR}

makedumpfile.o: ${GENERIC_HFILES} ${REDHAT_HFILES} makedumpfile.c
	${CC} -c ${CRASH_CFLAGS} makedumpfile.c ${WARNING_OPTIONS} ${WARNING_ERROR}

xendump.o: ${GENERIC_HFILES} ${REDHAT_HFILES} xendump.c
	${CC} -c ${CRASH_CFLAGS} xendump.c ${WARNING_OPTIONS} ${WARNING_ERROR}

kvmdump.o: ${GENERIC_HFILES} ${REDHAT_HFILES} kvmdump.c
	${CC} -c ${CRASH_CFLAGS} kvmdump.c ${WARNING_OPTIONS} ${WARNING_ERROR}

qemu.o: ${GENERIC_HFILES} ${REDHAT_HFILES} qemu.c
	${CC} -c ${CRASH_CFLAGS} qemu.c ${WARNING_OPTIONS} ${WARNING_ERROR}

qemu-load.o: ${GENERIC_HFILES} ${REDHAT_HFILES} qemu-load.c
	${CC} -c ${CRASH_CFLAGS} qemu-load.c ${WARNING_OPTIONS} ${WARNING_ERROR}

sadump.o: ${GENERIC_HFILES} ${SADUMP_HFILES} sadump.c
	${CC} -c ${CRASH_CFLAGS} sadump.c ${WARNING_OPTIONS} ${WARNING_ERROR}

ipcs.o: ${GENERIC_HFILES} ipcs.c
	${CC} -c ${CRASH_CFLAGS} ipcs.c ${WARNING_OPTIONS} ${WARNING_ERROR}

extensions.o: ${GENERIC_HFILES} extensions.c
	${CC} -c ${CRASH_CFLAGS} extensions.c ${WARNING_OPTIONS} ${WARNING_ERROR}

lkcd_x86_trace.o: ${GENERIC_HFILES} ${LKCD_TRACE_HFILES} lkcd_x86_trace.c 
	${CC} -c ${CRASH_CFLAGS} lkcd_x86_trace.c -DREDHAT ${WARNING_OPTIONS} ${WARNING_ERROR}

unwind_x86_32_64.o: ${GENERIC_HFILES} ${UNWIND_HFILES} unwind_x86_32_64.c
	${CC} -c ${CRASH_CFLAGS} unwind_x86_32_64.c -o unwind_x86_32_64.o ${WARNING_OPTIONS} ${WARNING_ERROR}

unwind_arm.o: ${GENERIC_HFILES} ${UNWIND_HFILES} unwind_arm.c
	${CC} -c ${CRASH_CFLAGS} unwind_arm.c -o unwind_arm.o ${WARNING_OPTIONS} ${WARNING_ERROR}

unwind_v1.o: ${GENERIC_HFILES} ${UNWIND_HFILES} unwind.c unwind_decoder.c
	${CC} -c ${CRASH_CFLAGS} unwind.c -DREDHAT -DUNWIND_V1 -o unwind_v1.o ${WARNING_OPTIONS} ${WARNING_ERROR}

unwind_v2.o: ${GENERIC_HFILES} ${UNWIND_HFILES} unwind.c unwind_decoder.c
	${CC} -c ${CRASH_CFLAGS} unwind.c -DREDHAT -DUNWIND_V2 -o unwind_v2.o ${WARNING_OPTIONS} ${WARNING_ERROR}

unwind_v3.o: ${GENERIC_HFILES} ${UNWIND_HFILES} unwind.c unwind_decoder.c
	${CC} -c ${CRASH_CFLAGS} unwind.c -DREDHAT -DUNWIND_V3 -o unwind_v3.o ${WARNING_OPTIONS} ${WARNING_ERROR}

lkcd_fix_mem.o: ${GENERIC_HFILES} ${LKCD_HFILES} lkcd_fix_mem.c
	${CC} -c ${CRASH_CFLAGS} lkcd_fix_mem.c -DMCLX ${WARNING_OPTIONS} ${WARNING_ERROR}

xen_hyper.o: ${GENERIC_HFILES} xen_hyper.c
	${CC} -c ${CRASH_CFLAGS} xen_hyper.c ${WARNING_OPTIONS} ${WARNING_ERROR}

xen_hyper_command.o: ${GENERIC_HFILES} xen_hyper_command.c
	${CC} -c ${CRASH_CFLAGS} xen_hyper_command.c ${WARNING_OPTIONS} ${WARNING_ERROR}

xen_hyper_global_data.o: ${GENERIC_HFILES} xen_hyper_global_data.c
	${CC} -c ${CRASH_CFLAGS} xen_hyper_global_data.c ${WARNING_OPTIONS} ${WARNING_ERROR}

xen_hyper_dump_tables.o: ${GENERIC_HFILES} xen_hyper_dump_tables.c
	${CC} -c ${CRASH_CFLAGS} xen_hyper_dump_tables.c ${WARNING_OPTIONS} ${WARNING_ERROR}

xen_dom0.o: ${GENERIC_HFILES} xen_dom0.c
	${CC} -c ${CRASH_CFLAGS} xen_dom0.c ${WARNING_OPTIONS} ${WARNING_ERROR}

ramdump.o: ${GENERIC_HFILES} ${REDHAT_HFILES} ramdump.c
	${CC} -c ${CRASH_CFLAGS} ramdump.c ${WARNING_OPTIONS} ${WARNING_ERROR}

vmware_vmss.o: ${GENERIC_HFILES} ${VMWARE_HFILES} vmware_vmss.c
	${CC} -c ${CRASH_CFLAGS} vmware_vmss.c ${WARNING_OPTIONS} ${WARNING_ERROR}

vmware_guestdump.o: ${GENERIC_HFILES} ${VMWARE_HFILES} vmware_guestdump.c
	${CC} -c ${CRASH_CFLAGS} vmware_guestdump.c ${WARNING_OPTIONS} ${WARNING_ERROR}

kaslr_helper.o: ${GENERIC_HFILES} kaslr_helper.c
	${CC} -c ${CRASH_CFLAGS} kaslr_helper.c ${WARNING_OPTIONS} ${WARNING_ERROR}

bpf.o: ${GENERIC_HFILES} bpf.c
	${CC} -c ${CRASH_CFLAGS} bpf.c ${WARNING_OPTIONS} ${WARNING_ERROR}

${PROGRAM}: force
	@$(MAKE) all

# Remote daemon functionality has been deprecated.
daemon_deprecated: force
	@echo "WARNING: remote daemon functionality has been deprecated"
	@echo 

${PROGRAM}d: daemon_deprecated make_configure
	@./configure -d
	@$(MAKE) build_data.o
	@$(MAKE) daemon

daemon: ${DAEMON_OBJECT_FILES}
	${CC} ${LDFLAGS} -o ${PROGRAM}d ${DAEMON_OBJECT_FILES} build_data.o -lz 

files: make_configure
	@./configure -q -b
	@$(MAKE) show_files

gdb_files: make_configure
	@./configure -q -b
	@echo ${GDB_FILES} ${GDB_PATCH_FILES}

show_files:
	@if [ -f ${PROGRAM}  ]; then \
		./${PROGRAM} --no_scroll --no_crashrc -h README > README; fi
	@echo ${SOURCE_FILES} Makefile ${GDB_FILES} ${GDB_PATCH_FILES} ${GPL_FILES} README \
	.rh_rpm_package crash.8 ${EXTENSION_SOURCE_FILES} ${MEMORY_DRIVER_FILES}

ctags:
	ctags ${SOURCE_FILES}

tar: make_configure
	@./configure -q -b
	@$(MAKE) do_tar

do_tar:
	@if [ -f ${PROGRAM}  ]; then \
		./${PROGRAM} --no_scroll --no_crashrc -h README > README; fi
	tar cvzf ${PROGRAM}.tar.gz ${TAR_FILES} ${GDB_FILES} ${GDB_PATCH_FILES}
	@echo; ls -l ${PROGRAM}.tar.gz

VERSION=
RELEASE=0

release: make_configure
	@if [ "`id --user`" != "0" ]; then \
		echo "make release: must be super-user"; exit 1; fi
	@./configure -P "RPMPKG=${RPMPKG}" -u -g
	@$(MAKE) release_configure
	@echo 
	@echo "cvs tag this release if necessary"

release_configure: make_configure
	@if [ "${GDB}" = "" ] ; then \
		echo "make release: GDB not defined: append GDB=gdb-x.x to make command line"; echo; exit 1; fi 
	@./configure -r ${GDB}
	@$(MAKE) do_release

do_release:
	@echo "CRASH VERSION: ${VERSION}  GDB VERSION: ${GDB}"
	@if [ ! -f .rh_rpm_package  ]; then \
		echo "no .rh_rpm_package exists!"; exit 1; fi
	@chmod 666 .rh_rpm_package
	@rm -rf ./RELDIR; mkdir ./RELDIR; mkdir ./RELDIR/${PROGRAM}-${VERSION}
	@rm -f ${PROGRAM}-${VERSION}.tar.gz 
	@rm -f ${PROGRAM}-${VERSION}-${RELEASE}.src.rpm
	@chown root ./RELDIR/${PROGRAM}-${VERSION}
	@tar cf - ${SOURCE_FILES} Makefile ${GDB_FILES} ${GDB_PATCH_FILES} ${GPL_FILES} \
	.rh_rpm_package crash.8 ${EXTENSION_SOURCE_FILES} ${MEMORY_DRIVER_FILES} | \
	(cd ./RELDIR/${PROGRAM}-${VERSION}; tar xf -)
	@cp ${GDB}.tar.gz ./RELDIR/${PROGRAM}-${VERSION}
	@./${PROGRAM} --no_scroll --no_crashrc -h README > README
	@cp README ./RELDIR/${PROGRAM}-${VERSION}/README
	@(cd ./RELDIR; find . -exec chown root {} ";")
	@(cd ./RELDIR; find . -exec chgrp root {} ";")
	@(cd ./RELDIR; find . -exec touch {} ";")
	@(cd ./RELDIR; \
		tar czvf ../${PROGRAM}-${VERSION}.tar.gz ${PROGRAM}-${VERSION})
	@chgrp root ${PROGRAM}-${VERSION}.tar.gz
	@rm -rf ./RELDIR
	@echo
	@ls -l ${PROGRAM}-${VERSION}.tar.gz
	@./configure -s -u > ${PROGRAM}.spec
	@if [ -s ${PROGRAM}.spec ]; then \
	  rm -rf ./RPMBUILD; \
	  mkdir -p ./RPMBUILD/SOURCES ./RPMBUILD/SPECS ./RPMBUILD/SRPMS; \
	  cp ${PROGRAM}-${VERSION}.tar.gz ./RPMBUILD/SOURCES; \
	  cp ${PROGRAM}.spec ./RPMBUILD/SPECS; \
	  rpmbuild --define "_sourcedir ./RPMBUILD/SOURCES" \
	    --define "_srcrpmdir ./RPMBUILD/SRPMS" \
	    --define "_specdir ./RPMBUILD/SPECS" \
	    --nodeps -bs ./RPMBUILD/SPECS/${PROGRAM}.spec > /dev/null; \
	   mv ./RPMBUILD/SRPMS/${PROGRAM}-${VERSION}-${RELEASE}.src.rpm . ; \
	   rm -rf ./RPMBUILD; \
	   ls -l ${PROGRAM}-${VERSION}-${RELEASE}.src.rpm; \
	fi

ref:
	$(MAKE) ctags cscope

cscope:
	rm -f cscope.files cscope.out
	for FILE in ${SOURCE_FILES}; do \
	echo $$FILE >> cscope.files; done
	cscope -b -f cscope.out

glink: make_configure
	@./configure -q -b
	rm -f gdb
	ln -s ${GDB}/gdb gdb
	(cd ${GDB}/gdb; rm -f ${PROGRAM}; ln -s ../../${PROGRAM} ${PROGRAM})

name:
	@echo ${PROGRAM}

dis:
	objdump --disassemble --line-numbers ${PROGRAM} > ${PROGRAM}.dis

extensions: make_configure
	@./configure ${CONF_TARGET_FLAG} -q -b
	@$(MAKE) do_extensions

do_extensions:
	@$(MAKE) -C extensions -i TARGET=$(TARGET) TARGET_CFLAGS="$(TARGET_CFLAGS)" GDB=$(GDB) GDB_FLAGS=$(GDB_FLAGS)

memory_driver: make_configure 
	@$(MAKE) -C memory_driver -i
