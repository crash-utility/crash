Crash Utility Maintenance Guide
===============================

Dave Anderson

Copyright © 2020 by Red Hat, Inc. Copyright © 2021 by NEC Corporation

Permission is granted to copy, distribute and/or modify this document under
the terms of the GNU Free Documentation License, Version 1.2 or any later
version published by the Free Software Foundation; with no Invariant Sections,
no Front-Cover Texts, and no Back-Cover Texts. A copy of the license is
included in the section entitled "GNU Free Documentation License".

.. _contents:

Contents
--------

- :ref:`Introduction <intro>`

- :ref:`Files <source>`

  - :ref:`Github Repository <github_sources>`
  - :ref:`RHEL Distribution <rhel_sources>`
  - :ref:`Fedora Distribution <fedora_sources>`
  - :ref:`Source Files <file_contents>`
  - :ref:`Other Files <other_files>`

- :ref:`Configuration <configuration>`

- :ref:`Build Process <build>`

  - :ref:`Top-Level Source Files <toplevel>`
  - :ref:`Linkage with GDB <linkage>`

- :ref:`Global Data <global>`

- :ref:`Initialization Sequence <initialization>`

  - :ref:`Command Line Options <options>`
  - :ref:`setup_environment() <setup_environment>`
  - :ref:`main() <main>`
  - :ref:`GDB Initialization <GDB_init>`
  - :ref:`main_loop() <main_loop>`
  - :ref:`Post Initialization Backtrace <init_backtrace>`

- :ref:`Runtime Control Flow <runtime>`

  - :ref:`process_command_line() <process_command_line>`
  - :ref:`exec_command() <exec_command>`

- :ref:`Command Execution <commandexec>`

  - :ref:`Arguments <arguments>`
  - :ref:`Memory Allocation <memalloc>`
  - :ref:`Utility Functions <utilityfunc>`
  - :ref:`Error Handling <errorhandling>`

- :ref:`GDB Interface <GDB_interface>`

- :ref:`Debugging <debugging>`

  - :ref:`CRASHDEBUG() <crashdebug>`
  - :ref:`console() <console>`
  - :ref:`cmd_test() <test_cmd>`

- :ref:`Extension Modules <extension>`

  - :ref:`Package Samples <samples_ext>`
  - :ref:`Upstream <upstream_ext>`
  - :ref:`RHEL Packages <rhel_ext>`

- :ref:`Testing <testing>`

- :ref:`Package Maintenance <pkgmaint>`

  - :ref:`Github <github>`
  - :ref:`Fedora <fedora>`
  - :ref:`RHEL <rhel>`
  - :ref:`CentOS Stream <centos>`
  - :ref:`people.redhat.com <people>`
  - :ref:`https://crash-utility.github.io <github_io>`
  - :ref:`CVS <cvs>`

- :ref:`Crash Utility Mailing List <mailing>`

- :ref:`Monitoring Upstream Kernel Development <upstream>`

- :ref:`Frequently Asked Questions <FAQ>`

- :ref:`Further Information <further>`

- :ref:`GNU Free Documentation License <GNU>`

.. _intro:

Introduction
------------

This document contains several sections regarding the design and maintenance
of the crash utility. It is intended to be a "live" document, to be updated
with additional information, better examples, and additional :ref:`Frequently
Asked Questions <FAQ>`.

.. _source:

Files
-----

- :ref:`Other Files <other_files>`

.. _github_sources:

Github Repository
~~~~~~~~~~~~~~~~~

The crash utility sources consist of the following:

   ::

      $ git clone git://github.com/crash-utility/crash.git
      Cloning into 'crash'...
      remote: Enumerating objects: 12, done.
      remote: Counting objects: 100% (12/12), done.
      remote: Compressing objects: 100% (9/9), done.
      remote: Total 2897 (delta 5), reused 10 (delta 3), pack-reused 2885
      Receiving objects: 100% (2897/2897), 5.43 MiB | 1.41 MiB/s, done.
      Resolving deltas: 100% (1952/1952), done.
      $ cd crash
      $ ls
      alpha.c                        lkcd_fix_mem.h       sadump.c
      arm64.c                        lkcd_v1.c            sadump.h
      arm.c                          lkcd_v2_v3.c         sparc64.c
      bpf.c                          lkcd_v5.c            symbols.c
      cmdline.c                      lkcd_v7.c            task.c
      configure.c                    lkcd_v8.c            test.c
      COPYING3                       lkcd_vmdump_v1.h     tools.c
      crash.8                        lkcd_vmdump_v2_v3.h  unwind_arm.c
      defs.h                         lkcd_x86_trace.c     unwind.c
      dev.c                          lkcd_x86_trace.h     unwind_decoder.c
      diskdump.c                     main.c               unwind.h
      diskdump.h                     makedumpfile.c       unwind_i.h
      extensions/                    makedumpfile.h       unwind_x86_32_64.c
      extensions.c                   Makefile             unwind_x86_64.h
      filesys.c                      memory.c             unwind_x86.h
      gdb-7.6.patch                  memory_driver/       vas_crash.h
      gdb-7.6-ppc64le-support.patch  mips.c               va_server.c
      gdb-7.6-proc_service.h.patch   net.c                va_server.h
      gdb_interface.c                netdump.c            va_server_v1.c
      global_data.c                  netdump.h            vmcore.h
      help.c                         ppc64.c              vmware_vmss.c
      ia64.c                         ppc.c                vmware_vmss.h
      ibm_common.h                   qemu.c               x86_64.c
      ipcs.c                         qemu-load.c          x86.c
      kaslr_helper.c                 qemu-load.h          xen_dom0.c
      kernel.c                       ramdump.c            xen_dom0.h
      kvmdump.c                      README               xendump.c
      kvmdump.h                      remote.c             xendump.h
      lkcd_common.c                  rse.h                xen_hyper.c
      lkcd_dump_v5.h                 s390.c               xen_hyper_command.c
      lkcd_dump_v7.h                 s390dbf.c            xen_hyper_defs.h
      lkcd_dump_v8.h                 s390_dump.c          xen_hyper_dump_tables.c
      lkcd_fix_mem.c                 s390x.c              xen_hyper_global_data.c
      $

Note that the GDB sources are not included in the
`github <https://github.com/crash-utility/crash>`__ repository. There are 3
GDB patch files:

The ``extensions`` subdirectory contains a small set of ***sample*** extension
modules. New extension modules should not be added to this directory:

   ::

      $ ls extensions
      dminfo.c  echo.c  eppic.c  eppic.mk  Makefile  snap.c  snap.mk	trace.c
      $

The ``memory_driver`` subdirectory contains a sample kernel driver that is
similar to the old */dev/crash* driver. Given that /proc/kcore has been
stabilized for use on live systems, the sample driver is pretty much obsolete:

   ::

      $ ls memory_driver
      crash.c  Makefile  README
      $

Lastly, unshown above is the hidden ``.rh_rpm_package`` file, which contains
the package version number.

.. _rhel_sources:

RHEL Distribution
~~~~~~~~~~~~~~~~~

The RHEL sources, at a minimum, consist of the following:

::

     $ rpm -qpl crash-7.2.6-1.el8.src.rpm
     crash-7.2.6.tar.gz
     crash.spec
     lzo_snappy.patch
     rhel8_build.patch
     $

The ``crash-7.2.6.tar.gz`` file contains all of the
`github <https://github.com/crash-utility/crash>`__ sources **plus** the GDB
source files. The GDB sources were downloaded from the FSF web site, where
currently ``gdb-7.6.tar.gz`` is being used:

::

     $ tar tvzmf crash-7.2.6.tar.gz | grep tar.gz
     -rw-r--r-- root/root  31437633 2019-09-20 10:36 crash-7.2.7/gdb-7.6.tar.gz
     $

The ``lzo_snappy.patch`` file causes the LZO and snappy compression libraries
to be built into the crash binary. RHEL8 requires the ``rhel8_build.patch``,
which causes the crash sources to be compiled with -fPIE, the crash binary to
linked with "-Wl,-z,now -fpie", and the host build system's LDFLAGS contents
to be utilized.

If/when the release numbers get bumped from -1 and beyond, additional patches
may be added to the lists above. See the :ref:`RHEL Package Maintenance
<rhel>` section for details.

.. _fedora_sources:

Fedora Distribution
~~~~~~~~~~~~~~~~~~~

The Fedora sources, at a minimum, consist of the following:

::

     $ rpm -qpl crash-7.2.6-1.fc31.src.rpm
     crash-7.2.6.tar.gz
     crash.spec
     lzo_snappy.patch
     use_system_readline_v3.patch
     $

The ``crash-7.2.6.tar.gz`` file contains all of the
`github <https://github.com/crash-utility/crash>`__ sources **plus** the GDB
source files. The GDB sources were downloaded from the FSF web site, where
currently ``gdb-7.6.tar.gz`` is being used:

::

     $ tar tvzmf crash-7.2.6.tar.gz | grep tar.gz
     -rw-r--r-- root/root  31437633 2019-09-20 10:36 crash-7.2.6/gdb-7.6.tar.gz
     $

The ``lzo_snappy.patch`` file causes the LZO and snappy compression libraries
to be built into the crash binary. Fedora requires the
``use_system_readline_v3.patch``, which causes the build to utilize the host
system's ``readline`` library instead of the ``readline`` library that is
bundled in the GDB sources.

If/when the release numbers get bumped from -1 and beyond, additional patches
may be added to the lists above. See the :ref:`Fedora Package Maintenance
<fedora>` section for details.

.. _file_contents:

Source Files
~~~~~~~~~~~~

The build is configured by the interaction of these two files. See the
:ref:`Configuration <configuration>` and :ref:`Build Process <build>` sections
for details:

.. _other_files:

Other Files
~~~~~~~~~~~

There are several files that are not part of the original source tree. Most
importantly, is the current version of GDB, which gets downloaded from the
Free Software Foundation
`http://ftp.gnu.org/gnu/gdb <http://ftp.gnu.org/gnu/gdb>`__ website during the
initial build; the file is bundled with RHEL and Fedora
``crash-`` <*version*>.src.rpm file:

.. _configuration:

Configuration
-------------

The primary configuration requirements the determination of the target
kernel's architecture, the host machine's architecture if it is different than
the target's, the version of GDB that is to be used, and the target
architecture used for configuring the embedded GDB module.

When performing the initial configuration and subsequent build, the generic
``Makefile`` gets modified on the fly to reflect several configuration values.
For example, here is a newly-downloaded source tree, and a subsequent build.
Note that the ``Makefile`` becomes modified:

::

     $ git clone git://github.com/crash-utility/crash.git
     Cloning into 'crash'...
     remote: Enumerating objects: 31, done.
     remote: Counting objects: 100% (31/31), done.
     remote: Compressing objects: 100% (23/23), done.
     remote: Total 2916 (delta 12), reused 21 (delta 6), pack-reused 2885
     Receiving objects: 100% (2916/2916), 5.55 MiB | 213.00 KiB/s, done.
     Resolving deltas: 100% (1959/1959), done.
     $ cd crash
     $ git status
     # On branch master
     nothing to commit, working directory clean
     $ make
     TARGET: X86_64
      CRASH: 7.2.8
        GDB: 7.6

     --2020-02-19 11:56:34--  http://ftp.gnu.org/gnu/gdb/gdb-7.6.tar.gz
     Resolving ftp.gnu.org (ftp.gnu.org)... 2001:470:142:3::b, 209.51.188.20
     Connecting to ftp.gnu.org (ftp.gnu.org)|2001:470:142:3::b|:80... failed: No route to host.
     Connecting to ftp.gnu.org (ftp.gnu.org)|209.51.188.20|:80... connected.
     HTTP request sent, awaiting response... 200 OK
     Length: 31437633 (30M) [application/x-gzip]
     Saving to: ‘gdb-7.6.tar.gz’

... (*build log not shown*) ...

::

     $ git status
     # On branch master
     # Changes not staged for commit:
     #   (use "git add ..." to update what will be committed)
     #   (use "git checkout -- ..." to discard changes in working directory)
     #
     #	modified:   Makefile
     #
     no changes added to commit (use "git add" and/or "git commit -a")
     $

::

     $ git diff
     diff --git a/Makefile b/Makefile
     index 7455410..a82b6f8 100644
     --- a/Makefile
     +++ b/Makefile
     @@ -23,7 +23,7 @@ PROGRAM=crash
      # Supported targets: X86 ALPHA PPC IA64 PPC64 SPARC64
      # TARGET and GDB_CONF_FLAGS will be configured automatically by configure
      #
     -TARGET=
     +TARGET=X86_64
      GDB_CONF_FLAGS=

      ARCH := $(shell uname -m | sed -e s/i.86/i386/ -e s/sun4u/sparc64/ -e s/arm.*/arm/ -e s/sa110/arm/)
     @@ -34,10 +34,10 @@ endif
      #
      # GDB, GDB_FILES, GDB_OFILES and GDB_PATCH_FILES will be configured automatically by configure
      #
     -GDB=
     -GDB_FILES=
     -GDB_OFILES=
     -GDB_PATCH_FILES=
     +GDB=gdb-7.6
     +GDB_FILES=${GDB_7.6_FILES}
     +GDB_OFILES=${GDB_7.6_OFILES}
     +GDB_PATCH_FILES=gdb-7.6.patch gdb-7.6-ppc64le-support.patch gdb-7.6-proc_service.h.patch

      #
      # Default installation directory
     @@ -183,7 +183,7 @@ GDB_7.6_OFILES=${GDB}/gdb/symtab.o
      #
      # GDB_FLAGS is passed up from the gdb Makefile.
      #
     -GDB_FLAGS=
     +GDB_FLAGS=-DGDB_7_6

      #
      # WARNING_OPTIONS and WARNING_ERROR are both applied on a per-file basis.
     @@ -200,7 +200,7 @@ TARGET_CFLAGS=

      CRASH_CFLAGS=-g -D${TARGET} ${TARGET_CFLAGS} ${GDB_FLAGS} ${CFLAGS}

     -GPL_FILES=
     +GPL_FILES=COPYING3
      TAR_FILES=${SOURCE_FILES} Makefile ${GPL_FILES} README .rh_rpm_package crash.8 \
             ${EXTENSION_SOURCE_FILES} ${MEMORY_DRIVER_FILES}
      CSCOPE_FILES=${SOURCE_FILES}
     $

All of the modified values above were done by calls to the ``configure``
command, which is the first C file to be compiled. By default, the TARGET
definition is that of the architecture that the crash utility binary supports,
i.e., the architecture of the ``vmlinux`` and ``vmcore`` pair. The TARGET is
also the architecture that is used to configure the embedded GDB module. The
configuration data is always displayed at the top of the build log:

::

     $ make
       TARGET: X86_64
        CRASH: 7.2.8
          GDB: 7.6
     ...

By default the TARGET architecture reflects the host machine architecture.
However, it is possible to build certain configurations where the target
architecture may be different than the host machine's architecture. For
example, an x86_64 crash binary may be built that can be used to analyze arm64
``vmlinux`` and ``vmcore`` files while running on an x86_64 host like so:

::

     $ make TARGET=ARM64

When ``TARGET=<ARCH>`` is specified, GDB_CONF_FLAGS is also modified from its
empty default value to an argument that is passed to the build of the embedded
GDB module. Here are the possible architecture and host configurations:

::

     $ grep GDB_TARGET configure.c
     #define GDB_TARGET_DEFAULT        "GDB_CONF_FLAGS="
     #define GDB_TARGET_ARM_ON_X86     "GDB_CONF_FLAGS=--target=arm-elf-linux"
     #define GDB_TARGET_ARM_ON_X86_64  "GDB_CONF_FLAGS=--target=arm-elf-linux CFLAGS=-m32"
     #define GDB_TARGET_X86_ON_X86_64  "GDB_CONF_FLAGS=--target=i686-pc-linux-gnu CFLAGS=-m32"
     #define GDB_TARGET_PPC_ON_PPC64   "GDB_CONF_FLAGS=--target=ppc-elf-linux CFLAGS=-m32"
     #define GDB_TARGET_ARM64_ON_X86_64  "GDB_CONF_FLAGS=--target=aarch64-elf-linux"   /* TBD */
     #define GDB_TARGET_PPC64_ON_X86_64  "GDB_CONF_FLAGS=--target=powerpc64le-unknown-linux-gnu"
     #define GDB_TARGET_MIPS_ON_X86     "GDB_CONF_FLAGS=--target=mipsel-elf-linux"
     #define GDB_TARGET_MIPS_ON_X86_64  "GDB_CONF_FLAGS=--target=mipsel-elf-linux CFLAGS=-m32"
     	gdb_conf_flags = GDB_TARGET_DEFAULT;
     			gdb_conf_flags = GDB_TARGET_X86_ON_X86_64;
     			gdb_conf_flags = GDB_TARGET_PPC_ON_PPC64;
     			gdb_conf_flags = GDB_TARGET_PPC64_ON_X86_64;
     			gdb_conf_flags = GDB_TARGET_ARM_ON_X86;
     			gdb_conf_flags = GDB_TARGET_ARM_ON_X86_64;
     			gdb_conf_flags = GDB_TARGET_ARM64_ON_X86_64;
     			gdb_conf_flags = GDB_TARGET_MIPS_ON_X86;
     			gdb_conf_flags = GDB_TARGET_MIPS_ON_X86_64;
     $

.. _target_arch:

These are the possible configurations where the host machine and TARGET
architectures may differ:

   .. list-table::
      :widths: 40 40

      * - Host architecture
        - TARGET architecture

      * - x86_64 x86_64 x86_64 x86_64 x86_64 x86 x86 ppc64
        - x86 arm arm64 ppc64 mips arm mips ppc

While the version of GDB was historically configurable from a list of versions
that had been ported in the past, the latest/default version should always be
used, and is hard-coded in ``configure.c``:

::

     #define GDB_5_3   (0)
     #define GDB_6_0   (1)
     #define GDB_6_1   (2)
     #define GDB_7_0   (3)
     #define GDB_7_3_1 (4)
     #define GDB_7_6   (5)
     #define SUPPORTED_GDB_VERSIONS (GDB_7_6 + 1)

     int default_gdb = GDB_7_6;

The version number of the crash utility binary is based upon the contents of
the ``.rh_rpm_package`` file. For example:

::

     $ cat .rh_rpm_package
     7.2.8
     $

The ``.rh_rpm_package`` file may be modified manually, or by passing its new
value to ``make RPMPKG=`` <*version*>. For example:

::

     $ make RPMPKG=7.2.8-test
       TARGET: X86_64
        CRASH: 7.2.8-test
          GDB: 7.6
     ...

The modified ``Makefile`` can be restored to its pristine condition by
"unconfiguring" it like so:

::

     $ git status
     # On branch master
     # Changes not staged for commit:
     #   (use "git add ..." to update what will be committed)
     #   (use "git checkout -- ..." to discard changes in working directory)
     #
     #	modified:   Makefile
     #
     no changes added to commit (use "git add" and/or "git commit -a")
     $ make unconfig
     $ git status
     # On branch master
     nothing to commit, working directory clean
     $

.. _build:

Build Process
-------------

- :ref:`Linkage with GDB <linkage>`

.. _toplevel:

Top-Level Source Files
~~~~~~~~~~~~~~~~~~~~~~

The most recent crash utility source files can be downloaded from the
`github <https://github.com/crash-utility/crash>`__ repository:

::

     $ git clone git://github.com/crash-utility/crash.git

or if you wish to be able to push changes back upstream:

::

     $ git clone https://github.com/crash-utility/crash.git

The crash utility build tree layout consists of a top-level directory
containing a set of ``crash``-specific files. A compressed tar image
containing the full, unmodified, ``gdb-7.6.tar.gz`` source file is downloaded
from `http://ftp.gnu.org/gnu/gdb <http://ftp.gnu.org/gnu/gdb>`__ for the first
and subsequent builds. Distributions may optionally bundle the
``gdb-7.6.tar.gz`` file in their ``.src.rpm`` packages, making the download
step unnecessary.

The build proceeds as follows:

1. The unmodified GDB source files are extracted into a subdirectory of the
   top-level crash source file directory.
2. The GDB sources are patched as required.
3. The libraries and files in the GDB source tree are built first, creating the
   ``libbfd.a, libreadline.a, libopcodes.a, libiberty.a`` and ``libgdb.a``
   libraries.
4. the crash sources files in the top-level directory are then compiled and
   archived into a ``crashlib.a`` library.
5. the objects are all linked into the ``crash`` executable, located in the
   top-level directory.

The host machine machine must contain a few libraries for the build to
succeed. At a minimum, the following packages must be installed:

``ncurses-devel````zlib-devel````bison`` In order to read dumpfiles created
with LZO or snappy compression libraries, these packages must be installed:
``lzo-devel````snappy-devel`` After the source files have been downloaded, the
``crash`` binary can be built simply by entering ``make``. If the
``gdb-7.6.tar.gz`` source file does not exist, it will be downloaded: $
**make** TARGET: X86_64 CRASH: 7.2.8 GDB: 7.6 --2020-02-19 11:56:34--
http://ftp.gnu.org/gnu/gdb/gdb-7.6.tar.gz Resolving ftp.gnu.org
(ftp.gnu.org)... 2001:470:142:3::b, 209.51.188.20 Connecting to ftp.gnu.org
(ftp.gnu.org)\|2001:470:142:3::b\|:80... failed: No route to host. Connecting
to ftp.gnu.org (ftp.gnu.org)\|209.51.188.20\|:80... connected. HTTP request
sent, awaiting response... 200 OK Length: 31437633 (30M) [application/x-gzip]
Saving to: ‘gdb-7.6.tar.gz’ ... (*build log not shown*) ... $ By default the
crash binary can only read ``vmcore`` files compressed with the ``zlib``
format. In order to read ``vmcore`` files compressed with the ``LZO`` or
``snappy`` formats, their libraries must be explicitly linked in. This can be
accomplished by supplying ``Makefile`` targets like so: $ **make lzo** $
**make snappy** The two commands above may be supplied at any time, i.e.,
either during the initial build, or after a build has been completed. The
``lzo`` and ``snappy`` targets invoke the ``configure -x`` option, which
creates ``CFLAGS.extra`` and ``LDFLAGS.extra`` files, and rebuilds the binary:
$ **cat CFLAGS.extra** -DLZO -DSNAPPY $ **cat LDFLAGS.extra** -llzo2 -lsnappy
$ The ``make`` command initially invokes this stanza in the ``Makefile``: all:
make_configure @./configure ${CONF_TARGET_FLAG} -p "RPMPKG=${RPMPKG}" -b @make
--no-print-directory gdb_merge The ``make_configure`` dependency re-compiles
``configure.c`` every time. Then ``configure`` is called, optionally passing
the CONF_TARGET_FLAG if it had been invoked with
``make TARGET=<``*architecture>*, and the RPMPKG release string if it was
invoked with ``make RPMPKG=`` <*version*>, and most importantly, the ``-b``
argument. ``configure -b`` creates a copy of the ``Makefile``, where it
modifies the original in order to set the
``TARGET, GDB, GDB_FILES, GDB_OFILES, GDB_PATCH_FILES, TARGET_CFLAGS, LDFLAGS, GDB_CONF_FLAGS``
and ``GPL_FILES`` variables, as well as creating the ``build_data.c`` file.
The new version of the ``Makefile`` is copied to the original, over-writing
its contents with the new configuration data. From this point on, the build
procedure utilizes the modifed ``Makefile``, for example, when the
``gdb_merge`` main stanza is invoked: gdb_merge: force @if [ ! -f
${GDB}/README ]; then \\ make --no-print-directory gdb_unzip; fi @echo
"${LDFLAGS} -lz -ldl -rdynamic" > ${GDB}/gdb/mergelibs @echo "../../${PROGRAM}
../../${PROGRAM}lib.a" > ${GDB}/gdb/mergeobj @rm -f ${PROGRAM} @if [ ! -f
${GDB}/config.status ]; then \\ (cd ${GDB}; ./configure ${GDB_CONF_FLAGS}
--with-separate-debug-dir=/usr/lib/debug \\ --with-bugurl="" --with-expat=no
--with-python=no --disable-sim; \\ make --no-print-directory
CRASH_TARGET=${TARGET}; echo ${TARGET} > crash.target) \\ else make
--no-print-directory rebuild; fi @if [ ! -f ${PROGRAM} ]; then \\ echo; echo
"${PROGRAM} build failed"; \\ echo; exit 1; fi The first thing that needs to
be done is to create the GDB source tree if it does not exist, and then apply
the requisite patches to merge the top-level crash utility sources with the
GDB sources into a single binary: gdb_merge: force @if [ ! -f ${GDB}/README ];
then \\ **make --no-print-directory gdb_unzip; fi** ... Here the ``gdb_unzip``
stanza checks for the existence of the ``gdb-`` <*version*>``.tar.gz`` file; if
it does not exist, it downloads it with ``wget``, and extracts the GDB source
tree with ``tar``: gdb_unzip: @rm -f gdb.files @for FILE in ${GDB_FILES}
dummy; do\\ echo $$FILE >> gdb.files; done @if [ ! -f ${GDB}.tar.gz ] && [ !
-f /usr/bin/wget ]; then \\ echo /usr/bin/wget is required to download
${GDB}.tar.gz; echo; exit 1; fi @if [ ! -f ${GDB}.tar.gz ] && [ -f
/usr/bin/wget ]; then \\ **wget http://ftp.gnu.org/gnu/gdb/${GDB}.tar.gz;** fi
@**tar --exclude-from gdb.files -xvzmf ${GDB}.tar.gz** @make
--no-print-directory gdb_patch It then applies the requisite patches to the
GDB source tree:

::

     gdb_patch:
             if [ -f ${GDB}.patch ] && [ -s ${GDB}.patch ]; then \
                     patch -p0 < ${GDB}.patch; cp ${GDB}.patch ${GDB}; fi
             if [ "${ARCH}" = "ppc64le" ] && [ -f ${GDB}-ppc64le-support.patch ]; then \
                     patch -d ${GDB} -p1 -F0 < ${GDB}-ppc64le-support.patch ; \
             fi
             if [ "${ARCH}" = "x86_64" ] && [ "${TARGET}" = "PPC64" ] && [ -f ${GDB}-ppc64le-support.patch ]; then \
                     patch -d ${GDB} -p1 -F0 < ${GDB}-ppc64le-support.patch ; \
             fi
             if [ -f /usr/include/proc_service.h ]; then \
                     grep 'extern ps_err_e ps_get_thread_area (struct' /usr/include/proc_service.h; \
                     if [ $$? -eq 0 ]; then \
                             patch -p0 < ${GDB}-proc_service.h.patch; \
                     fi; \
             fi

Back in the top-level ``gdb_merge`` stanza, the ``mergelibs`` and ``meregobj``
files are created in the GDB source directory for use by the final program
linkage:

::

     gdb_merge: force
             @if [ ! -f ${GDB}/README ]; then \
               make --no-print-directory gdb_unzip; fi
             @echo "${LDFLAGS} -lz -ldl -rdynamic" > ${GDB}/gdb/mergelibs
             @echo "../../${PROGRAM} ../../${PROGRAM}lib.a" > ${GDB}/gdb/mergeobj
             ...

If this is the first build since the GDB source tree was extracted, the
``config.status`` file will not exist. In that case, the embedded GDB module
is configured and built:

::

     gdb_merge: force
             @if [ ! -f ${GDB}/README ]; then \
               make --no-print-directory gdb_unzip; fi
             @echo "${LDFLAGS} -lz -ldl -rdynamic" > ${GDB}/gdb/mergelibs
             @echo "../../${PROGRAM} ../../${PROGRAM}lib.a" > ${GDB}/gdb/mergeobj
             @rm -f ${PROGRAM}
             @if [ ! -f ${GDB}/config.status ]; then \
               (cd ${GDB}; ./configure ${GDB_CONF_FLAGS} --with-separate-debug-dir=/usr/lib/debug \
                 --with-bugurl="" --with-expat=no --with-python=no --disable-sim; \
               make --no-print-directory CRASH_TARGET=${TARGET}; echo ${TARGET} > crash.target) \
             else make --no-print-directory rebuild; fi
             ...

Upon subsequent builds, the ``rebuild`` stanza is invoked:

::

     gdb_merge: force
             @if [ ! -f ${GDB}/README ]; then \
               make --no-print-directory gdb_unzip; fi
             @echo "${LDFLAGS} -lz -ldl -rdynamic" > ${GDB}/gdb/mergelibs
             @echo "../../${PROGRAM} ../../${PROGRAM}lib.a" > ${GDB}/gdb/mergeobj
             @rm -f ${PROGRAM}
             @if [ ! -f ${GDB}/config.status ]; then \
               (cd ${GDB}; ./configure ${GDB_CONF_FLAGS} --with-separate-debug-dir=/usr/lib/debug \
                 --with-bugurl="" --with-expat=no --with-python=no --disable-sim; \
               make --no-print-directory CRASH_TARGET=${TARGET}; echo ${TARGET} > crash.target) \
             else make --no-print-directory rebuild; fi
             ...

The ``rebuild`` stanza checks whether the ``gdb-`` <*version*>``.patch`` has
been modified since the initial build, and if so, it applies just the new
changes with the ``patch -N`` option. Lastly the embedded GDB module is
rebuilt, recompiling any files that were changed in the updated
``gdb-`` <*version*>``.patch``:

::

     rebuild:
             @if [ ! -f ${GDB}/${GDB}.patch ]; then \
               touch ${GDB}/${GDB}.patch; fi
             @if [ -f ${GDB}.patch ] && [ -s ${GDB}.patch ] && \
               [ "`sum ${GDB}.patch`" != "`sum ${GDB}/${GDB}.patch`" ]; then \
               (sh -x ${GDB}.patch ${TARGET}; patch -N -p0 -r- --fuzz=0 < ${GDB}.patch; cp ${GDB}.patch ${GDB}; cd ${GDB}; \
               make --no-print-directory CRASH_TARGET=${TARGET}) \
             else (cd ${GDB}/gdb; make --no-print-directory CRASH_TARGET=${TARGET}); fi

The initial build takes several minutes to compile the embedded GDB module and
its bundled libraries. When the GDB portion of the build is complete, the
``crash``-specific files in the top-level directory are compiled, archived
into a ``crashlib.a`` file, and ultimately linked into the ``crash`` binary:

::

     $ make
     ... (build log not shown) ...
     ar -rs crashlib.a main.o tools.o global_data.o memory.o filesys.o help.o task.o build_data.o
     kernel.o test.o gdb_interface.o net.o dev.o bpf.o alpha.o x86.o ppc.o ia64.o s390.o s390x.o
     s390dbf.o ppc64.o x86_64.o arm.o arm64.o mips.o sparc64.o extensions.o remote.o va_server.o
     va_server_v1.o symbols.o cmdline.o lkcd_common.o lkcd_v1.o lkcd_v2_v3.o lkcd_v5.o lkcd_v7.o
     lkcd_v8.o lkcd_fix_mem.o s390_dump.o netdump.o diskdump.o makedumpfile.o xendump.o
     lkcd_x86_trace.o unwind_v1.o unwind_v2.o unwind_v3.o unwind_x86_32_64.o unwind_arm.o
     xen_hyper.o xen_hyper_command.o xen_hyper_global_data.o xen_hyper_dump_tables.o kvmdump.o
     qemu.o qemu-load.o sadump.o ipcs.o ramdump.o vmware_vmss.o xen_dom0.o kaslr_helper.o
     ...

Details of how that is accomplished can be found in the :ref:`Linkage with GDB
<linkage>` section.

The default compilation of the top-level source files utilizes a minimum of
flags by default; only the ``-g`` option is supplied. To compile with -Wall,
along with the
``-O2, -Wstrict-prototypes, -Wmissing-prototypes, -fstack-protector`` and
``-Wformat-security`` ``gcc`` options, build with:

::

     $ make warn

To force the compile to fail instead of just issuing warnings, this build
option will append ``-Werror`` to the options above:

::

     $ make Warn

The compilation directives are "sticky", and will remain in effect until
cleared with:

::

     $ make nowarn

Prior to accepting a new patch, it is advisable to do a full build with
``warn`` or ``Warn``:

::

     $ make clean
     ...
     $ make warn

.. _linkage:

Linkage with GDB
~~~~~~~~~~~~~~~~

After extracting the GDB source tree, and prior to invoking its build
procedure, a number of files in the tree must be patched. The primary patch
file is named after the version of GDB. At the time of this writing, the
``gdb-7.6.patch`` file patched these files:

::

     $ lsdiff gdb-7.6.patch
     gdb-7.6/libiberty/Makefile.in
     gdb-7.6/opcodes/i386-dis.c
     gdb-7.6/gdb/dwarf2read.c
     gdb-7.6/gdb/amd64-linux-nat.c
     gdb-7.6/gdb/symfile.c
     gdb-7.6/gdb/cli/cli-cmds.c
     gdb-7.6/gdb/psymtab.c
     gdb-7.6/gdb/symtab.c
     gdb-7.6/gdb/c-typeprint.c
     gdb-7.6/gdb/xml-syscall.c
     gdb-7.6/gdb/exceptions.c
     gdb-7.6/gdb/valprint.h
     gdb-7.6/gdb/target.c
     gdb-7.6/gdb/printcmd.c
     gdb-7.6/gdb/ui-file.c
     gdb-7.6/gdb/main.c
     gdb-7.6/gdb/valprint.c
     gdb-7.6/gdb/Makefile.in
     gdb-7.6/gdb/c-lang.c
     gdb-7.6/readline/rltypedefs.h
     gdb-7.6/readline/readline.h
     gdb-7.6/readline/misc.c
     gdb-7.6/Makefile.in
     gdb-7.6/gdb/defs.h
     gdb-7.6/bfd/elflink.c
     gdb-7.6/gdb/s390-nat.c
     gdb-7.6/gdb/printcmd.c
     gdb-7.6/bfd/bfd-in.h
     gdb-7.6/bfd/bfd-in2.h
     gdb-7.6/gdb/symtab.c
     gdb-7.6/gdb/aarch64-linux-nat.c
     gdb-7.6/sim/igen/Makefile.in
     gdb-7.6/sim/mips/cp1.c
     gdb-7.6/sim/mips/sim-main.h
     gdb-7.6/readline/util.c
     gdb-7.6/gdb/symtab.c
     gdb-7.6/gdb/symtab.c
     gdb-7.6/opcodes/i386-dis.c
     gdb-7.6/bfd/coff-i386.c
     gdb-7.6/bfd/coff-x86_64.c
     gdb-7.6/opcodes/arm-dis.c
     gdb-7.6/bfd/elf64-ppc.c
     gdb-7.6/include/opcode/ppc.h
     gdb-7.6/opcodes/mips-dis.c
     gdb-7.6/gdb/ada-lang.c
     gdb-7.6/gdb/linux-record.c
     gdb-7.6/gdb/inflow.c
     gdb-7.6/gdb/printcmd.c
     gdb-7.6/gdb/c-typeprint.c
     gdb-7.6/gdb/symtab.c
     gdb-7.6/bfd/elf64-s390.c
     gdb-7.6/gdb/symtab.c
     gdb-7.6/bfd/configure
     gdb-7.6/opcodes/configure
     gdb-7.6/gdb/symtab.c
     gdb-7.6/gdb/symtab.c
     gdb-7.6/gdb/symtab.c
     gdb-7.6/gdb/common/linux-ptrace.c
     gdb-7.6/gdb/features/aarch64.c
     gdb-7.6/gdb/aarch64-linux-nat.c
     gdb-7.6/gdb/aarch64-tdep.c
     $

The ppc64le architecture was unknown by ``gdb-7.6``, and therefore a large
``gdb-7.6-ppc64le-support.patch`` was added for its support. Currently it is
only applied when building on ppc64le host, or if building on an x86_64 host
for the ppc64 target architecture:

::

     $ lsdiff gdb-7.6-ppc64le-support.patch
     a/gdb/ChangeLog
     a/gdb/ppc-sysv-tdep.c
     a/gdb/ChangeLog
     a/gdb/ada-tasks.c
     a/gdb/amd64-windows-tdep.c
     a/gdb/arm-tdep.c
     a/gdb/arm-wince-tdep.c
     a/gdb/block.c
     a/gdb/blockframe.c
     a/gdb/breakpoint.c
     a/gdb/btrace.c
     a/gdb/c-valprint.c
     a/gdb/coff-pe-read.c
     a/gdb/dwarf2loc.c
     a/gdb/elfread.c
     a/gdb/frame.c
     a/gdb/frv-tdep.c
     a/gdb/glibc-tdep.c
     a/gdb/gnu-v2-abi.c
     a/gdb/gnu-v3-abi.c
     a/gdb/hppa-hpux-tdep.c
     a/gdb/i386-tdep.c
     a/gdb/ia64-tdep.c
     a/gdb/infcall.c
     a/gdb/infcmd.c
     a/gdb/jit.c
     a/gdb/linux-fork.c
     a/gdb/m32c-tdep.c
     a/gdb/m68hc11-tdep.c
     a/gdb/maint.c
     a/gdb/minsyms.c
     a/gdb/minsyms.h
     a/gdb/mips-tdep.c
     a/gdb/p-valprint.c
     a/gdb/parse.c
     a/gdb/ppc-linux-tdep.c
     a/gdb/ppc-sysv-tdep.c
     a/gdb/printcmd.c
     a/gdb/rs6000-tdep.c
     a/gdb/sh64-tdep.c
     a/gdb/stack.c
     a/gdb/symtab.c
     a/gdb/tui/tui-disasm.c
     a/bfd/ChangeLog
     a/bfd/config.bfd
     a/ChangeLog
     a/config.guess
     a/config.sub
     a/gdb/ChangeLog
     a/gdb/ppc-linux-tdep.c
     a/gdb/ppc-tdep.h
     a/gdb/ppc64-tdep.c
     a/gdb/rs6000-tdep.c
     a/include/ChangeLog
     a/include/dwarf2.def
     a/include/floatformat.h
     a/libiberty/ChangeLog
     a/libiberty/floatformat.c
     a/gdb/ChangeLog
     a/gdb/ppc64-tdep.c
     a/gdb/rs6000-tdep.c
     a/ChangeLog
     a/config.guess
     a/config.sub
     a/gdb/ppc64-tdep.c
     a/gdb/rs6000-tdep.c
     a/gdb/auxv.c
     a/gdb/configure.host
     a/gdb/configure.tgt
     a/gdb/doublest.c
     a/gdb/gdbarch.c
     a/gdb/gdbarch.h
     a/gdb/gdbarch.sh
     a/gdb/gdbtypes.c
     a/gdb/infrun.c
     a/gdb/ppc-linux-tdep.c
     a/gdb/ppc-sysv-tdep.c
     a/gdb/ppc-tdep.h
     a/gdb/symtab.c
     a/gdb/testsuite/gdb.arch/altivec-regs.exp
     a/gdb/testsuite/gdb.arch/powerpc-d128-regs.exp
     a/gdb/testsuite/gdb.arch/vsx-regs.exp
     a/gdb/testsuite/gdb.base/sigbpt.exp
     a/gdb/testsuite/gdb.base/step-bt.exp
     a/include/elf/common.h
     a/include/elf/ppc64.h
     $

The third GDB patch file, ``gdb-7.6-proc_service.h.patch`` was required for a
compilation error that started happening if ``glibc-2.25`` or later has been
installed on the host build machine, which modified the
``/usr/include/proc_service.h`` file:

::

     $ lsdiff gdb-7.6-proc_service.h.patch
     gdb-7.6/gdb/gdb_proc_service.h
     gdb-7.6/gdb/amd64-linux-nat.c
     gdb-7.6/gdb/aarch64-linux-nat.c
     gdb-7.6/gdb/arm-linux-nat.c
     gdb-7.6/gdb/i386-linux-nat.c
     gdb-7.6/gdb/mips-linux-nat.c
     $

It should be noted here that when updating the ``gdb-7.6.patch`` file, care
must be taken to prevent and/or address any conflicts that may occur when
patching a GDB file that is also patched by the
``gdb-7.6-ppc64le-support.patch`` file. In that case, it may be necessary to:

1. add the new patch to the end of ``gdb-7.6.patch``,
2. revert the new patch at the top of ``gdb-7.6-ppc64le-support.patch``, and
3. re-work the new patch so that it can be applied successfully at the end of
   ``gdb-7.6-ppc64le-support.patch``

When GDB is built, its default "target" architecture is the same as the host
machine. So, for example, when the crash utility is built on an x86_64 host by
entering ``make``, the GDB target architecture will also be x86_64, as shown
by the initialization banner:

::

     $ crash

     crash 7.2.8
     Copyright (C) 2002-2020  Red Hat, Inc.
     Copyright (C) 2004, 2005, 2006, 2010  IBM Corporation
     Copyright (C) 1999-2006  Hewlett-Packard Co
     Copyright (C) 2005, 2006, 2011, 2012  Fujitsu Limited
     Copyright (C) 2006, 2007  VA Linux Systems Japan K.K.
     Copyright (C) 2005, 2011  NEC Corporation
     Copyright (C) 1999, 2002, 2007  Silicon Graphics, Inc.
     Copyright (C) 1999, 2000, 2001, 2002  Mission Critical Linux, Inc.
     This program is free software, covered by the GNU General Public License,
     and you are welcome to change it and/or distribute copies of it under
     certain conditions.  Enter "help copying" to see the conditions.
     This program has absolutely no warranty.  Enter "help warranty" for details.

     GNU gdb (GDB) 7.6
     Copyright (C) 2013 Free Software Foundation, Inc.
     License GPLv3+: GNU GPL version 3 or later
     This is free software: you are free to change and redistribute it.
     There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
     and "show warranty" for details.
     This GDB was configured as "x86_64-unknown-linux-gnu"...

     ...

However, GDB can be configured such that it runs on the host architecture, but
can analyze the binary executable and core file of a different architecture.
The crash utility itself can be built to target a different architecture by
invoking it with ``make TARGET=<``*architecture>*, subject to the restrictions
shown in this :ref:`table <target_arch>`. So, for example, this crash utility
binary was built on an x86_64 host by invoking ``make TARGET=ARM64``; note
that it shows both ``--host`` and ``--target`` values:

::

     $ crash vmlinux vmcore

     crash 7.2.8
     Copyright (C) 2002-2020  Red Hat, Inc.
     Copyright (C) 2004, 2005, 2006, 2010  IBM Corporation
     Copyright (C) 1999-2006  Hewlett-Packard Co
     Copyright (C) 2005, 2006, 2011, 2012  Fujitsu Limited
     Copyright (C) 2006, 2007  VA Linux Systems Japan K.K.
     Copyright (C) 2005, 2011  NEC Corporation
     Copyright (C) 1999, 2002, 2007  Silicon Graphics, Inc.
     Copyright (C) 1999, 2000, 2001, 2002  Mission Critical Linux, Inc.
     This program is free software, covered by the GNU General Public License,
     and you are welcome to change it and/or distribute copies of it under
     certain conditions.  Enter "help copying" to see the conditions.
     This program has absolutely no warranty.  Enter "help warranty" for details.

     GNU gdb (GDB) 7.6
     Copyright (C) 2013 Free Software Foundation, Inc.
     License GPLv3+: GNU GPL version 3 or later
     This is free software: you are free to change and redistribute it.
     There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
     and "show warranty" for details.
     This GDB was configured as "--host=x86_64-unknown-linux-gnu --target=aarch64-elf-linux"...

     ...

This is accomplished during the initial build of the GDB module, which first
requires that the GDB ``configure`` script be invoked, as is done here by the
top-level ``Makefile``, where the ``--target=aarch64-elf-linux`` string gets
passed in the GDB_CONF_FLAGS variable:

::

     gdb_merge: force
             @if [ ! -f ${GDB}/README ]; then \
               make --no-print-directory gdb_unzip; fi
             @echo "${LDFLAGS} -lz -ldl -rdynamic" > ${GDB}/gdb/mergelibs
             @echo "../../${PROGRAM} ../../${PROGRAM}lib.a" > ${GDB}/gdb/mergeobj
             @rm -f ${PROGRAM}
             @if [ ! -f ${GDB}/config.status ]; then \
               (cd ${GDB}; ./configure ${GDB_CONF_FLAGS} --with-separate-debug-dir=/usr/lib/debug \
                 --with-bugurl="" --with-expat=no --with-python=no --disable-sim; \
               make --no-print-directory CRASH_TARGET=${TARGET}; echo ${TARGET} > crash.target) \
             else make --no-print-directory rebuild; fi
             ...

After the GDB source has been patched, and GDB has been configured, the
initial build in a source tree is kicked off here:

::

     gdb_merge: force
             @if [ ! -f ${GDB}/README ]; then \
               make --no-print-directory gdb_unzip; fi
             @echo "${LDFLAGS} -lz -ldl -rdynamic" > ${GDB}/gdb/mergelibs
             @echo "../../${PROGRAM} ../../${PROGRAM}lib.a" > ${GDB}/gdb/mergeobj
             @rm -f ${PROGRAM}
             @if [ ! -f ${GDB}/config.status ]; then \
               (cd ${GDB}; ./configure ${GDB_CONF_FLAGS} --with-separate-debug-dir=/usr/lib/debug \
                 --with-bugurl="" --with-expat=no --with-python=no --disable-sim; \
               make --no-print-directory CRASH_TARGET=${TARGET}; echo ${TARGET} > crash.target) \
             else make --no-print-directory rebuild; fi
             ...

Subsequent builds in a source tree go though the ``rebuild`` stanza, where the
``gdb-`` <*version*>``.tar.gz`` may need to be re-applied if it has changed:

::

     rebuild:
             @if [ ! -f ${GDB}/${GDB}.patch ]; then \
               touch ${GDB}/${GDB}.patch; fi
             @if [ -f ${GDB}.patch ] && [ -s ${GDB}.patch ] && \
               [ "`sum ${GDB}.patch`" != "`sum ${GDB}/${GDB}.patch`" ]; then \
               (sh -x ${GDB}.patch ${TARGET}; patch -N -p0 -r- --fuzz=0 < ${GDB}.patch; cp ${GDB}.patch ${GDB}; cd ${GDB}; \
               make --no-print-directory CRASH_TARGET=${TARGET}) \
             else (cd ${GDB}/gdb; make --no-print-directory CRASH_TARGET=${TARGET}); fi

As a result of the build procedure, two files are stored in the
``gdb-`` <*version*> directory:

1. the TARGET architecture is stored in the ``crash.target`` file. This file is
   used to make the TARGET architecture "sticky" across subsequent builds, and
   will also prevent an attempt to invoke ``make TARGET=<``*architecture>* on a
   previously built tree that has a different TARGET architecture.
2. a copy of the ``gdb-`` <*version*>.``patch`` file; this file is used to
   recognize whether the top-level version of the file has changed, and therefore
   has to be re-applied in an existing source tree.

The GDB build is a rather lengthy and time-consuming build. First, several
libraries that bundled with the GDB sources are built:

.. _global:

Global Data
-----------

There are several global data variables that are utilized by the top-level C
files. They are collected in ``global_data.c``.

The most commonly-used variable is used for data output:

::

     FILE *fp;

The content of the ``fp`` pointer is changed on the fly depending upon whether
the output data is going:

1. to the "standard" scrolling pipe command (``/usr/bin/less`` by default)
2. to be redirected to a user-designated pipe or file
3. to be redirected to a temporary file created by ``tmpfile()``
4. to ``stdout``
5. to ``/dev/null``

Regardless of the output destination, ``fprintf(fp, ...)`` is used throughout
the crash utility sources; the ``printf()`` function should never be used.

The current state of the crash utility session is kept in the
``program_context`` structure, which is referenced by the ``pc`` pointer:

::

     struct program_context program_context = { 0 };
     struct program_context *pc = &program_context;

Two very commonly-used fields are the ``->flags`` and ``->flags2`` members,
which are referenced directory or via macros. Other commonly used items are
file pointers and pipe descriptors, memory source data, command line storage,
current command information, input/output data, and several function pointers.
The contents of the structure can be viewed during runtime by entering
``help -p``.

Other global tables, and their quick-reference pointers, are:

::

     struct task_table task_table = { 0 };
     struct task_table *tt = &task_table;

     struct kernel_table kernel_table = { 0 };
     struct kernel_table *kt = &kernel_table;

     struct vm_table vm_table = { 0 };
     struct vm_table *vt = &vm_table;

     struct symbol_table_data symbol_table_data = { 0 };
     struct symbol_table_data *st = &symbol_table_data;

     struct machdep_table machdep_table = { 0 };
     struct machdep_table *machdep = &machdep_table;

The tables above contain more specific subsystem content:

1. The ``task_table`` contains information regarding the running tasks of a crash
   session, and the current task context.
2. The ``kernel_table`` contains a collection kernel-specific data, such as
   per-cpu information, module data, and kernel version information.
3. The ``vm_table`` contains memory related data, such as physical and virtual
   memory statistics, the kernel slab cache, and page structure data.
4. The ``machdep_table`` contains architecture-specific data, mostly
   memory-specific information required for address translation, and a number of
   function pointers that get plugged in by the architecture-specific files
   during initialization.

The tables can be viewed during runtime by entering ``help -t``, ``help -k``,
``help -v``, ``help -s`` and ``help -m`` respectively. They all contain
``->flags`` members, which are commonly referenced directly or via macros.

Each crash command is passed its arguments in the typical manner that can be
parsed by ``getopt()``:

::

     char *args[MAXARGS];	  /* argument array */
     int argcnt;             /* argument count */
     int argerrs;            /* argument error counter */

The full set of crash commands are collected in the ``linux_command_table[]``
array:

.. _hidden_test:

::

     struct command_table_entry linux_command_table[] = {
           {"*",       cmd_pointer, help_pointer, 0},
           {"alias",   cmd_alias,   help_alias,   0},
           {"ascii",   cmd_ascii,   help_ascii,   0},
           {"bpf",     cmd_bpf,     help_bpf,     0},
           {"bt",      cmd_bt,      help_bt,      REFRESH_TASK_TABLE},
           {"btop",    cmd_btop,    help_btop,    0},
           {"dev",     cmd_dev,     help_dev,     0},
           {"dis",     cmd_dis,     help_dis,     MINIMAL},
           {"eval",    cmd_eval,    help_eval,    MINIMAL},
           {"exit",    cmd_quit,    help_exit,    MINIMAL},
           {"extend",  cmd_extend,  help_extend,  MINIMAL},
           {"files",   cmd_files,   help_files,   REFRESH_TASK_TABLE},
           {"foreach", cmd_foreach, help_foreach, REFRESH_TASK_TABLE},
           {"fuser",   cmd_fuser,   help_fuser,   REFRESH_TASK_TABLE},
           {"gdb",     cmd_gdb,     help_gdb,     REFRESH_TASK_TABLE},
           {"help",    cmd_help,    help_help,    MINIMAL},
           {"ipcs",    cmd_ipcs,    help_ipcs,    REFRESH_TASK_TABLE},
           {"irq",     cmd_irq,     help_irq,     0},
           {"kmem",    cmd_kmem,    help_kmem,    0},
           {"list",    cmd_list,    help__list,   REFRESH_TASK_TABLE},
           {"log",     cmd_log,     help_log,     MINIMAL},
           {"mach",    cmd_mach,    help_mach,    0},
           {"map",     cmd_map,     help_map,     HIDDEN_COMMAND},
           {"mod",     cmd_mod,     help_mod,     0},
           {"mount",   cmd_mount,   help_mount,   0},
           {"net",     cmd_net,     help_net,     REFRESH_TASK_TABLE},
           {"p",       cmd_p,       help_p,       0},
           {"ps",      cmd_ps,      help_ps,      REFRESH_TASK_TABLE},
           {"pte",     cmd_pte,     help_pte,     0},
           {"ptob",    cmd_ptob,    help_ptob,    0},
           {"ptov",    cmd_ptov,    help_ptov,    0},
           {"q",       cmd_quit,    help_quit,    MINIMAL},
           {"tree",    cmd_tree,    help_tree,    REFRESH_TASK_TABLE},
           {"rd",      cmd_rd,      help_rd,      MINIMAL},
           {"repeat",  cmd_repeat,  help_repeat,  0},
           {"runq",    cmd_runq,    help_runq,    REFRESH_TASK_TABLE},
           {"search",  cmd_search,  help_search,  0},
           {"set",     cmd_set,     help_set,     REFRESH_TASK_TABLE | MINIMAL},
           {"sig",     cmd_sig,     help_sig,     REFRESH_TASK_TABLE},
           {"struct",  cmd_struct,  help_struct,  0},
           {"swap",    cmd_swap,    help_swap,    0},
           {"sym",     cmd_sym,     help_sym,     MINIMAL},
           {"sys",     cmd_sys,     help_sys,     REFRESH_TASK_TABLE},
           {"task",    cmd_task,    help_task,    REFRESH_TASK_TABLE},
           {"test",    cmd_test,    NULL,         HIDDEN_COMMAND},
           {"timer",   cmd_timer,   help_timer,   0},
           {"union",   cmd_union,   help_union,   0},
           {"vm",      cmd_vm,      help_vm,      REFRESH_TASK_TABLE},
           {"vtop",    cmd_vtop,    help_vtop,    REFRESH_TASK_TABLE},
           {"waitq",   cmd_waitq,   help_waitq,   REFRESH_TASK_TABLE},
           {"whatis",  cmd_whatis,  help_whatis,  0},
           {"wr",      cmd_wr,      help_wr,      0},
     #if defined(S390) || defined(S390X)
             {"s390dbf", cmd_s390dbf, help_s390dbf, 0},
     #endif
           {(char *)NULL}
     };

When an extension module loads a new command, it gets linked onto this data
structure, which serves as the head of a list of one or more command(s):

::

     struct extension_table *extension_table = NULL;

Commonly used data structure sizes, data structure member offsets, and array
sizes are initialized and kept in these tables, which are referenced through
various OFFSET- and SIZE-related macros defined in ``defs.h``:

::

     struct offset_table offset_table = { 0 };
     struct size_table size_table = { 0 };
     struct array_table array_table = { 0 };

.. _initialization:

Initialization Sequence
-----------------------

- :ref:`Post Initialization Backtrace <init_backtrace>`

.. _options:

Command Line Options
~~~~~~~~~~~~~~~~~~~~

The crash utility initialization sequence originates in ``main.c``. The
program can be invoked with numerous options and filename arguments. The
self-contained documentation displays the ``man`` page, which shows all
options and arguments. It can be viewed like so:

::

        $ crash -h

        USAGE:

          crash [OPTION]... NAMELIST MEMORY-IMAGE[@ADDRESS]	(dumpfile form)
          crash [OPTION]... [NAMELIST]             		(live system form)

        OPTIONS:

          NAMELIST
            This is a pathname to an uncompressed kernel image (a vmlinux
            file), or a Xen hypervisor image (a xen-syms file) which has
            been compiled with the "-g" option.  If using the dumpfile form,
            a vmlinux file may be compressed in either gzip or bzip2 formats.

          MEMORY-IMAGE
            A kernel core dump file created by the netdump, diskdump, LKCD
            kdump, xendump or kvmdump facilities.

            If a MEMORY-IMAGE argument is not entered, the session will be
            invoked on the live system, which typically requires root privileges
            because of the device file used to access system RAM.  By default,
            /dev/crash will be used if it exists.  If it does not exist, then
            /dev/mem will be used; but if the kernel has been configured with
            CONFIG_STRICT_DEVMEM, then /proc/kcore will be used.  It is permissible
            to explicitly enter /dev/crash, /dev/mem or /proc/kcore.

            An @ADDRESS value must be appended to the MEMORY-IMAGE if the dumpfile
            is a raw RAM dumpfile that has no header information describing the file
            contents.  Multiple MEMORY-IMAGE@ADDRESS ordered pairs may be entered,
            with each dumpfile containing a contiguous block of RAM, where the ADDRESS
            value is the physical start address of the block expressed in hexadecimal.
            The physical address value(s) will be used to create a temporary ELF header
            in /var/tmp, which will only exist during the crash session.  If a raw RAM
            dumpile represents a live memory source, such as that specified by the QEMU
            mem-path argument of a memory-backend-file object, then "live:" must be
            prepended to the MEMORY-IMAGE name.

          mapfile
            If the NAMELIST file is not the same kernel that is running
            (live system form), or the kernel that was running when the system
            crashed (dumpfile form), then the System.map file of the original
            kernel should be entered on the command line.

          -h [option]
          --help [option]
            Without an option argument, display a crash usage help message.
            If the option argument is a crash command name, the help page
            for that command is displayed.  If it is the string "input", a
            page describing the various crash command line input options is
            displayed.  If it is the string "output", a page describing command
            line output options is displayed.  If it is the string "all", then
            all of the possible help messages are displayed.  After the help
            message is displayed, crash exits.

          -s
            Silently proceed directly to the "crash>" prompt without displaying
            any version, GPL, or crash initialization data during startup, and by
            default, runtime command output is not passed to any scrolling command.

          -i file
            Execute the command(s) contained in "file" prior to displaying
            the "crash>" prompt for interactive user input.

          -d num
            Set the internal debug level.  The higher the number, the more
            debugging data will be printed when crash initializes and runs.

          -S
            Use /boot/System.map as the mapfile.

          -e  vi | emacs
            Set the readline(3) command  line editing mode to "vi" or "emacs".
            The default editing mode is "vi".

          -f
            Force the usage of a compressed vmlinux file if its original
            name does not start with "vmlinux".

          -k
            Indicate that the NAMELIST file is an LKCD "Kerntypes" debuginfo file.

          -g [namelist]
            Determine if a vmlinux or xen-syms namelist file contains debugging data.

          -t
            Display the system-crash timestamp and exit.

          -L
            Attempt to lock all of its virtual address space into memory by
            calling mlockall(MCL_CURRENT|MCL_FUTURE) during initialization.
            If the system call fails, an error message will be displayed,
            but the session continues.

          -c tty-device
            Open the tty-device as the console used for debug messages.

          -p page-size
            If a processor's page size cannot be determined by the dumpfile,
            and the processor default cannot be used, use page-size.

          -o filename
            Only used with the MEMORY-IMAGE@ADDRESS format for raw RAM dumpfiles,
            specifies a filename of a new ELF vmcore that will be created and used
            as the dumpfile.  It will be saved to allow future use as a standalone
            vmcore, replacing the original raw RAM dumpfile.

          -m option=value
          --machdep option=value
            Pass an option and value pair to machine-dependent code.  These
            architecture-specific option/pairs should only be required in
            very rare circumstances:

            X86_64:
              phys_base=
              irq_eframe_link=
              irq_stack_gap=
              max_physmem_bits=
              kernel_image_size=
              vm=orig       (pre-2.6.11 virtual memory address ranges)
              vm=2.6.11     (2.6.11 and later virtual memory address ranges)
              vm=xen        (Xen kernel virtual memory address ranges)
              vm=xen-rhel4  (RHEL4 Xen kernel virtual address ranges)
              vm=5level     (5-level page tables)
              page_offset=
            PPC64:
              vm=orig
              vm=2.6.14     (4-level page tables)
            IA64:
              phys_start=
              init_stack_size=
              vm=4l         (4-level page tables)
            ARM:
              phys_base=
            ARM64:
              phys_offset=
              kimage_voffset=
              max_physmem_bits=
            X86:
              page_offset=

          -x
            Automatically load extension modules from a particular directory.
            The directory is determined by the following order of precedence:

            (1) the directory specified in the CRASH_EXTENSIONS shell
                environment variable
            (2) /usr/lib64/crash/extensions  (64-bit  architectures)
            (3) /usr/lib/crash/extensions  (32-bit architectures)
            (4) the ./extensions subdirectory of the current directory

          --active
            Track only the active task on each cpu.

          --buildinfo
            Display the crash binary's build date, the user ID of the builder,
            the hostname of the machine where the build was done, the target
            architecture, the version number, and the compiler version.

          --memory_module modname
            Use the modname as an alternative kernel module to the crash.ko
            module that creates the /dev/crash device.

          --memory_device device
            Use device as an alternative device to the /dev/crash, /dev/mem
            or /proc/kcore devices.

          --log dumpfile
            Dump the contents of the kernel log buffer.  A kernel namelist
            argument is not necessary, but the dumpfile must contain the
            VMCOREINFO data taken from the original /proc/vmcore ELF header.

          --no_kallsyms
            Do not use kallsyms-generated symbol information contained within
            kernel module object files.

          --no_modules
            Do not access or display any kernel module related information.

          --no_ikconfig
            Do not attempt to read configuration data that was built into
            kernels configured with CONFIG_IKCONFIG.

          --no_data_debug
            Do not verify the validity of all structure member offsets and
            structure sizes that it uses.

          --no_kmem_cache
            Do not initialize the kernel's slab cache infrastructure, and
            commands that use kmem_cache-related data will not work.

          --no_elf_notes
            Do not use the registers from the ELF NT_PRSTATUS notes saved
            in a compressed kdump header for backtraces.

          --kmem_cache_delay
            Delay the initialization of the kernel's slab cache infrastructure
            until it is required by a run-time command.

          --readnow
            Pass this flag to the embedded gdb module, which will override
            the two-stage strategy that it uses for reading symbol tables
            from the NAMELIST.  If module symbol tables are loaded during
            runtime with the "mod" command, the same override will occur.

          --smp
            Specify that the system being analyzed is an SMP kernel.

          -v
          --version
            Display the version of the crash utility, the version of the
            embedded gdb module, GPL information, and copyright notices.

          --cpus number
            Specify the number of cpus in the SMP system being analyzed.

          --osrelease dumpfile
            Display the OSRELEASE vmcoreinfo string from a kdump dumpfile
            header.

          --hyper
            Force the session to be that of a Xen hypervisor.

          --p2m_mfn pfn
            When a Xen Hypervisor or its dom0 kernel crashes, the dumpfile
            is typically analyzed with either the Xen hypervisor or the dom0
            kernel.  It is also possible to analyze any of the guest domU
            kernels if the pfn_to_mfn_list_list pfn value of the guest kernel
            is passed on the command line along with its NAMELIST and the
            dumpfile.

          --xen_phys_start physical-address
            Supply the base physical address of the Xen hypervisor's text
            and static data for older xendump dumpfiles that did not pass
            that information in the dumpfile header.

          --zero_excluded
            If the makedumpfile(8) facility has filtered a compressed kdump
            dumpfile to exclude various types of non-essential pages, or has
            marked a compressed or ELF kdump dumpfile as incomplete due to
            an ENOSPC or other error during its creation, any attempt to
            read missing pages will fail.  With this flag, reads from any
            of those pages will return zero-filled memory.

          --no_panic
            Do not attempt to find the task that was running when the kernel
            crashed.  Set the initial context to that of the "swapper"  task
            on cpu 0.

          --more
            Use /bin/more as the command output scroller, overriding the
            default of /usr/bin/less and any settings in either ./.crashrc
            or $HOME/.crashrc.

          --less
            Use /usr/bin/less as the command output scroller, overriding any
            settings in either ./.crashrc or $HOME/.crashrc.

          --CRASHPAGER
            Use the output paging command defined in the CRASHPAGER shell
            environment variable, overriding any settings in either ./.crashrc
            or $HOME/.crashrc.

          --no_scroll
            Do not pass run-time command output to any scrolling command.

          --no_strip
            Do not strip cloned kernel text symbol names.

          --no_crashrc
            Do not execute the commands in either $HOME/.crashrc or ./.crashrc.

          --mod directory
            When loading the debuginfo data of kernel modules with the "mod -S"
            command, search for their object files in directory instead of in
            the standard location.

          --src directory
            Search for the kernel source code in directory instead of in the
            standard location that is compiled into the debuginfo data.

          --reloc size
            When analyzing live x86 kernels configured with a CONFIG_PHYSICAL_START
            value that is larger than its CONFIG_PHYSICAL_ALIGN value, then it will
            be necessary to enter a relocation size equal to the difference between
            the two values.

          --hash count
            Set the number of internal hash queue heads used for list gathering
            and verification.  The default count is 32768.

          --kaslr offset | auto
            If x86, x86_64 or s390x kernel was configured with CONFIG_RANDOMIZE_BASE,
            the offset value is equal to the difference between the symbol values
            compiled into the vmlinux file and their relocated KASLR value.  If
            set to auto, the KASLR offset value will be automatically calculated.

          --minimal
            Bring up a session that is restricted to the log, dis, rd, sym,
            eval, set and exit commands.  This option may provide a way to
            extract some minimal/quick information from a corrupted or truncated
            dumpfile, or in situations where one of the several kernel subsystem
            initialization routines would abort the crash session.

          --kvmhost [32|64]
            When examining an x86 KVM guest dumpfile, this option specifies
            that the KVM host that created the dumpfile was an x86 (32-bit)
            or an x86_64 (64-bit) machine, overriding the automatically
            determined value.

          --kvmio
            override the automatically-calculated KVM guest I/O hole size.

          --offline [show|hide]
            Show or hide command output that is associated with offline cpus,
            overriding any settings in either ./.crashrc or $HOME/.crashrc.

        FILES:

          .crashrc
            Initialization commands.  The file can be located in the user's
            HOME directory and/or the current directory.  Commands found in
            the .crashrc file in the HOME directory are executed before
            those in the current directory's .crashrc file.

        ENVIRONMENT VARIABLES:

          EDITOR
            Command input is read using readline(3).  If EDITOR is set to
            emacs or vi then suitable keybindings are used.  If EDITOR is
            not set, then vi is used.  This can be overridden by "set vi" or
            "set emacs" commands located in a .crashrc file, or by entering
            "-e emacs" on the crash command line.

          CRASHPAGER
            If CRASHPAGER is set, its value is used as the name of the program
            to which command output will be sent.  If not, then command output
            output is sent to "/usr/bin/less -E -X" by default.

          CRASH_MODULE_PATH
            Specifies an alternative directory tree to search for kernel
            module object files.

          CRASH_EXTENSIONS
            Specifies a directory containing extension modules that will be
            loaded automatically if the -x command line option is used.

        $

This is the long options table:

::

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

The parsing of the long options shown above, the single-character options, and
filename arguments is discussed below in the :ref:`main() <main>` section. But
first, the program environment must be initialized by
:ref:`setup_environment() <setup_environment>`.

.. _setup_environment:

setup_environment()
~~~~~~~~~~~~~~~~~~~

Before the traditional parsing of input arguments by ``getopt_long()``, the
``setup_environment()`` function is called:

::

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
                ...

Here is the ``setup_environment()`` function. Its primary purpose is to
initialize the global data, some of which needs to be in place before command
line arguments are parsed. Comments are interspersed in the code segment
below:

::

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

The global ``fp`` file pointer is initialized here, but it will be modified
during runtime as appropriate:

::

                /*
                 *  Program output typically goes via "fprintf(fp, ...)", but the
                 *  contents of fp are modified on the fly to handle redirection
                 *  to pipes or output files.
                 */
                fp = stdout;

The destination of error messages is pre-configurable by a ``.crashrc``
setting later on in this function, or during runtime by the ``set`` command.
Normally it just uses the "default" value:

1. *default*: error messages are always displayed on the console; if the output
   of a command is piped to an external command or redirected to a file, the
   error messages are also sent to the pipe or file.
2. *redirect*: if the output of a command is piped to an external command or
   redirected to a file, error messages are only sent to the pipe or file;
   otherwise they are displayed on the console.
3. *filename*: error messages are only sent to the specified filename; they are
   not displayed on the console and are not sent to a pipe or file.

::

                if (!set_error("default")) {
                        fprintf(stderr, "crash: cannot malloc error() path string\n");
                        clean_exit(1);
                }

Here several members of the global ``program_context`` structure are
initialized, some permanent, and others with default values:

::

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
                if (file_exists("/dev/mem", NULL)) {     /* defaults until argv[] is parsed */
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

Crash utility command output is typically passed to a scrolling program. It
can be pre-configured if the CRASHPAGER environment variable is set, but
normally ``/usr/bin/less`` will be used:

::

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

The command line editing mode may be pre-configured by the EDITOR environment
variable, or by an entry in a ``.crashrc`` file. If neither of those
configurations exist, the "no_mode" will be replaced by the default of "vi" at
the bottom of this function:

::

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

Here is where the resolution of ``set`` commands found in the
``$HOME/.crashrc`` and ``./.crashrc`` files is accomplished:

::

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

.. _main:

main()
~~~~~~

After ``setup_environment()`` has completed, the ``main()`` function
continues. Comments are interspersed in the code segment below:

::

        int
        main(int argc, char **argv)
        {
                int i, c, option_index;
                char *tmpname;

                setup_environment(argc, argv);

First the long and short command line options are resolved:

::

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
                                            !machine_type("S390X"))
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
        //                           pc->scroll_command = SCROLL_NONE;   (why?)
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

After the long and short options are consumed, what remains are one or more
filename arguments, which can by entered in any order. Each argument is
verified, typically by sending it to a function that determines what type of
file it is:

::

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

Here is where the filename argument is checked to see whether it is a kernel
file or a compressed kernel file. If it's the only one supplied on the command
line, the ``pc->namelist`` pointer is initialized:

::

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

Most of the supported dumpfile types verification functions are here. If it is
a dumpfile, the type is marked in ``pc->flags`` and the ``pc->readmem()``
function pointer is initialized:

::

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

The compressed kdump format created by the ``makedumpfile(8)`` facility is the
most common dumpfile type; its format is an extension of the old diskdump
format:

::

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

                                } else {
                                        error(INFO,
                                            "%s: not a supported file format\n",
                                                argv[optind]);
                                        program_usage(SHORT_FORM);
                                }
                        }
                        optind++;
                }

If the kernel file is named ``xen-syms``, then this session is switched to
analyse from the perspective of the Xen Hypervisor instead of a Linux kernel.
If so, the ``XEN_HYPER`` bit in ``pc->flags`` is set, and the command table is
switched from the ``linux_command_table`` to the ``xen_hyper_command_table``:

::

                check_xen_hyper();

If an unrecoverable error is encountered during the next set of initialization
functions, the ``RESTART()`` macro may be invoked, which calls ``longjmp()``
back to here. Since there is no way to continue, we exit:

::

                if (setjmp(pc->main_loop_env))
                        clean_exit(1);

Here we get into the initialization of major subsystems. Among the most
notable are:

::

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

Here is where the embedded GDB module is kicked off, which is discussed in the
:ref:`GDB Initialization <gdb_init>` section. The ``gdb_main_loop()`` function
below should never return here, but rather GDB will eventually call back into
the :ref:`main_loop() <main_loop>`, which is discussed below:

::

                /*
                 *  gdb_main_loop() modifies "command_loop_hook" to point to the
                 *  main_loop() function below, and then calls gdb's main() function.
                 *  After gdb initializes itself, it calls back to main_loop().
                 */
                gdb_main_loop(argc, argv);

                clean_exit(0);
                exit(0);
        }

.. _gdb_init:

GDB Initialization
~~~~~~~~~~~~~~~~~~

The GDB initialization sequence gets kicked off at the end of ``main()``
above. First, the global ``argc`` and ``argv[]`` variables are re-written such
that GDB is invoked with the kernel namelist argument, and possibly with
``--readnow`` and/or ``--quiet`` arguments. Note that GDB has no notion of any
dumpfile, but rather it is strictly utilized for the kernel's debuginfo data:

::

        /*
         *  Called from main() this routine sets up the call-back hook such that
         *  gdb's main() routine -- renamed gdb_main() -- will call back to
         *  our main_loop() after gdb initializes.
         */
        void
        gdb_main_loop(int argc, char **argv)
        {
                argc = 1;

                if (pc->flags & SILENT) {
                        if (pc->flags & READNOW)
                                argv[argc++] = "--readnow";
                        argv[argc++] = "--quiet";
                        argv[argc++] = pc->namelist_debug ?
                                pc->namelist_debug :
                                (pc->debuginfo_file && (st->flags & CRC_MATCHES) ?
                                pc->debuginfo_file : pc->namelist);
                } else {
                        if (pc->flags & READNOW)
                                argv[argc++] = "--readnow";
                        argv[argc++] = pc->namelist_debug ?
                                pc->namelist_debug :
                                (pc->debuginfo_file && (st->flags & CRC_MATCHES) ?
                                pc->debuginfo_file : pc->namelist);
                }

                if (CRASHDEBUG(1)) {
                        int i;
                        fprintf(fp, "gdb ");
                        for (i = 1; i < argc; i++)
                                fprintf(fp, "%s ", argv[i]);
                        fprintf(fp, "\n");
                }

                optind = 0;

The older versions of GDB are still supported, although practically speaking
only the most recent one is used. The older versions of GDB used to have a
``command_loop_hook`` function pointer plug-in, which allowed a developer to
insert a custom command-gathering loop function. That feature has been
technically deprecated in later versions of GDB, but they renamed it to
``deprecated_command_loop_hook``, and it can still be utilized in the same
way. The crash utility plugs in its own :ref:`main_loop() <main_loop>`
function, which never returns back to GDB: subdirectory:

::

        #if defined(GDB_5_3) || defined(GDB_6_0) || defined(GDB_6_1)
                command_loop_hook = main_loop;
        #else
                deprecated_command_loop_hook = main_loop;
        #endif
                gdb_main_entry(argc, argv);
        }

The ``gdb_main_loop()`` function above calls into the GDB source tree, located
in the ``gdb-`` <*version*>``/gdb`` subdirectory, where it takes a convoluted
path through patched GDB code before finally making it back to the crash
utility's :ref:`main_loop() <main_loop>`. The ``gdb_main_entry()`` function
sets up GDB's ``captured_main_args`` structure, and calls into ``gdb_main()``:

::

        #ifdef CRASH_MERGE
        /*
         *  NOTE: adapted from gdb.c, which is no longer built in; changed name of
         *        original main() to gdb_main_entry() for use as crash entry point
         */
        int
        gdb_main_entry (int argc, char **argv)
        {
          struct captured_main_args args;
          memset (&args, 0, sizeof args);
          args.argc = argc;
          args.argv = argv;
          args.use_windows = 0;
          args.interpreter_p = INTERP_CONSOLE;
          return gdb_main (&args);
        }
        #endif

``gdb_main()`` indirectly invokes a call to ``captured_main()``, passing the
``captured_main_args`` structure:

::

        int
        gdb_main (struct captured_main_args *args)
        {
          use_windows = args->use_windows;
          catch_errors (captured_main, args, "", RETURN_MASK_ALL);
          /* The only way to end up here is by an error (normal exit is
             handled by quit_force()), hence always return an error status.  */
          return 1;
        }

``captured_main()`` is a huge function that essentially does all the
initialization of GDB, e.g., setting up many global variables used throughout
GDB, parsing arguments and options, setting up its buffer handling and error
handling mechanisms, handling and ``.gdbinit`` files, printing the GDB banner,
and so on. At the end of the function, it ultimately invokes the
``captured_command_loop()`` function:

::

        static int
        captured_main (void *data)
        {

... *(initialization of GDB not shown)* ...

::

          while (1)
            {
              catch_errors (captured_command_loop, 0, "", RETURN_MASK_ALL);
        #ifdef CRASH_MERGE
              {
                int console(char *, ...);
                console("\n");
              }
        #endif
            }
          /* No exit -- exit is through quit_command.  */
        }

``captured_command_loop()`` calls ``current_interp_command_loop()``, which
should never return:

::

        static int
        captured_command_loop (void *data)
        {
          /* Top-level execution commands can be run on the background from
             here on.  */
          interpreter_async = 1;

          current_interp_command_loop ();
          ...

Finally it gets around to checking whether the
``deprecated_command_loop_hook`` has been set, and if so, calls the plug-in
function. In the case of the crash utility, it calls back into
:ref:`main_loop() <main_loop>`, which should never return:

::

        /* Run the current command interpreter's main loop.  */
        void
        current_interp_command_loop (void)
        {
          /* Somewhat messy.  For the moment prop up all the old ways of
             selecting the command loop.  `deprecated_command_loop_hook'
             should be deprecated.  */
          if (deprecated_command_loop_hook != NULL)
            deprecated_command_loop_hook ();
          else if (current_interpreter != NULL
                   && current_interpreter->procs->command_loop_proc != NULL)
            current_interpreter->procs->command_loop_proc (current_interpreter->data);
          else
            cli_command_loop ();
        }

.. _main_loop:

main_loop()
~~~~~~~~~~~

We have arrived here from a GDB callback from the
``deprecated_command_loop_hook()`` call above. The comments below are not
valid with respect to later versions of GDB, as SIGINT signals are ignored.
After a few potential WARNING messages, the initialization sequence continues.

::

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

Here we continue the initialization of major subsystems, taking two separate
paths depending upon whether this is running against a Xen hypervisor or
against a Linux kernel when not running in minimal mode. Among the most
notable are:

::

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

The system statistics and the current task context information get displayed
here:

::

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

The ``setjmp()`` call here is important point to note with respect to runtime
:ref:`error handling <errorhandling>`. Whenever a fatal error is encountered
from this point on, control will be transferred here, and the subsequent
``while (TRUE)`` loop is re-entered:

::

                /*
                 *  Return here if a non-recoverable error occurs
                 *  during command execution.
                 */
                if (setjmp(pc->main_loop_env)) {
                        ;
                }

Here we finally arrive at the crash utility's runtime command loop, where
command line input is parsed, the destination the command output is
determined, and the command is executed. The :ref:`runtime control flow
<runtime>` is discussed in the next section:

::

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

.. _init_backtrace:

Post Initialization Backtrace
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When debugging a crash utility session, the backtrace may appear confusing at
first. But considering the initialization path as detailed in the :ref:`main()
<main>`, :ref:`GDB Initialization <GDB_init>` and :ref:`main_loop()
<main_loop>` sections above, it becomes clear. If a crash session is attached
with GDB while it is sitting at the ``crash>`` prompt, the backtrace looks
like this:

::

        (gdb) bt
        #0  0x00007fc0a0df40f0 in __read_nocancel () from /lib64/libc.so.6
        #1  0x00000000007a6e79 in rl_getc (stream=0x7fc0a10cc640 <_IO_2_1_stdin_>) at input.c:471
        #2  0x00000000007a75ff in rl_read_key () at input.c:448
        #3  0x0000000000793e33 in readline_internal_char () at readline.c:517
        #4  0x0000000000794485 in readline_internal_charloop () at readline.c:579
        #5  readline_internal () at readline.c:593
        #6  readline (prompt=) at readline.c:342
        #7  0x00000000005559b3 in process_command_line () at cmdline.c:120
        #8  0x0000000000468515 in main_loop () at main.c:825
        #9  0x00000000006af443 in captured_command_loop (data=data@entry=0x0) at main.c:258
        #10 0x00000000006ae16a in catch_errors (func=func@entry=0x6af430 , func_args=func_args@entry=0x0,
            errstring=errstring@entry=0x90277f "", mask=mask@entry=6) at exceptions.c:557
        #11 0x00000000006b03d6 in captured_main (data=data@entry=0x7ffe1de14fa0) at main.c:1064
        #12 0x00000000006ae16a in catch_errors (func=func@entry=0x6af710 , func_args=func_args@entry=0x7ffe1de14fa0,
            errstring=errstring@entry=0x90277f "", mask=mask@entry=6) at exceptions.c:557
        #13 0x00000000006b0737 in gdb_main (args=0x7ffe1de14fa0) at main.c:1079
        #14 gdb_main_entry (argc=, argv=argv@entry=0x7ffe1de15108) at main.c:1099
        #15 0x00000000004f66a4 in gdb_main_loop (argc=, argc@entry=3, argv=argv@entry=0x7ffe1de15108) at gdb_interface.c:76
        #16 0x0000000000466855 in main (argc=3, argv=0x7ffe1de15108) at main.c:707
        (gdb)

Most likely a problem may occur while executing a command. For example,
putting a breakpoint in ``show_ps()``, which is called by the ``cmd_ps()``
function to execute the crash utility's ``ps`` command, shows the backtrace
going though ``exec_command()``:

::

        (gdb) bt
        #0  show_ps (flag=flag@entry=8, psi=psi@entry=0xd4a9c0 ) at task.c:3807
        #1  0x00000000004cdea2 in cmd_ps () at task.c:3590
        #2  0x000000000046828c in exec_command () at main.c:879
        #3  0x000000000046851a in main_loop () at main.c:826
        #4  0x00000000006af443 in captured_command_loop (data=data@entry=0x0) at main.c:258
        #5  0x00000000006ae16a in catch_errors (func=func@entry=0x6af430 , func_args=func_args@entry=0x0,
            errstring=errstring@entry=0x90277f "", mask=mask@entry=6) at exceptions.c:557
        #6  0x00000000006b03d6 in captured_main (data=data@entry=0x7ffe1de14fa0) at main.c:1064
        #7  0x00000000006ae16a in catch_errors (func=func@entry=0x6af710 , func_args=func_args@entry=0x7ffe1de14fa0,
            errstring=errstring@entry=0x90277f "", mask=mask@entry=6) at exceptions.c:557
        #8  0x00000000006b0737 in gdb_main (args=0x7ffe1de14fa0) at main.c:1079
        #9  gdb_main_entry (argc=, argv=argv@entry=0x7ffe1de15108) at main.c:1099
        #10 0x00000000004f66a4 in gdb_main_loop (argc=, argc@entry=3, argv=argv@entry=0x7ffe1de15108) at gdb_interface.c:76
        #11 0x0000000000466855 in main (argc=3, argv=0x7ffe1de15108) at main.c:707
        (gdb)

The ``process_command_line()`` and ``exec_command()`` functions are discussed
in the following :ref:`Runtime Control Flow <runtime>` section.

.. _runtime:

Runtime Control Flow
--------------------

- :ref:`exec_command() <exec_command>`

After all initialization functions have completed, the crash utility runs in
this loop:

::

                while (TRUE) {
                        process_command_line();
                        exec_command();
                }

.. _process_command_line:

process_command_line()
~~~~~~~~~~~~~~~~~~~~~~

Command line input may come from several sources:

1. a ``.crashrc`` file located in the user's HOME directory
2. a ``.crashrc`` file located in the current directory
3. an input file specified by the ``-i`` *filename* command line option
4. ``stdin`` from a terminal
5. a pipe, if ``stdin`` is a pipe instead of a terminal
6. an input file using the standard command line syntax: `` <`` *input-file*

Comments are interspersed below:

.. _restore_sanity:

::

        void
        process_command_line(void)
        {

Before any command is executed, ``restore_sanity()`` is called to restore the
initial environment, such as:

1. closing all files and pipes used by the previous command
2. cleaning up after commands that have designated a cleanup function
3. restore GDB to a known state
4. frees all internal buffers allocated by the previous command that were not
   explicitly freed
5. clears all data structure caches
6. reset the internal hash queue

The global ``fp`` FILE pointer is reset to ``stdout``, and the globally
accessible ``pc->command_line`` string is cleared:

::

        	/*
        	 *  Restore normal environment, clearing out any excess baggage
        	 *  piled up by the previous command.
        	 */
        	restore_sanity();
        	fp = stdout;
        	BZERO(pc->command_line, BUFSIZE);

Display the ``crash>`` prompt if appropriate:

::

        	if (!(pc->flags &
        	    (READLINE|SILENT|CMDLINE_IFILE|RCHOME_IFILE|RCLOCAL_IFILE)))
        		fprintf(fp, "%s", pc->prompt);
        	fflush(fp);

If the input source is from a file, set up the command line in the `` <``
*input-file* syntax. This format will be recognized later in
``exec_command()``:

::

        	/*
        	 *  Input can come from five possible sources:
        	 *
        	 *    1. an .rc file located in the user's HOME directory.
            *    2. an .rc file located in the current directory.
        	 *    3. an input file that was designated by the -i flag at
        	 *       program invocation.
        	 *    4. from a terminal.
        	 *    5. from a pipe, if stdin is a pipe rather than a terminal.
        	 *
        	 *  But first, handle the interruption of an input file caused
        	 *  by a FATAL error in one of its commands.
        	 *
        	 */
        	if (pc->ifile_in_progress) {
        		switch (pc->ifile_in_progress)
        		{
        		case RCHOME_IFILE:
        			pc->flags |= INIT_IFILE|RCHOME_IFILE;
        			sprintf(pc->command_line, "< %s/.%src",
        				pc->home, pc->program_name);
        			break;
        		case RCLOCAL_IFILE:
        			sprintf(pc->command_line, "< .%src", pc->program_name);
        			pc->flags |= INIT_IFILE|RCLOCAL_IFILE;
        			break;
        		case CMDLINE_IFILE:
        			sprintf(pc->command_line, "< %s", pc->input_file);
        			pc->flags |= INIT_IFILE|CMDLINE_IFILE;
        			break;
        		case RUNTIME_IFILE:
        			sprintf(pc->command_line, "%s", pc->runtime_ifile_cmd);
        			pc->flags |= IFILE_ERROR;
        			break;
        		default:
        			error(FATAL, "invalid input file\n");
        		}
        	} else if (pc->flags & RCHOME_IFILE) {
                   sprintf(pc->command_line, "< %s/.%src",
        			pc->home, pc->program_name);
        		pc->flags |= INIT_IFILE;
        	} else if (pc->flags & RCLOCAL_IFILE) {
                   sprintf(pc->command_line, "< .%src", pc->program_name);
       		pc->flags |= INIT_IFILE;
        	} else if (pc->flags & CMDLINE_IFILE) {
        		sprintf(pc->command_line, "< %s", pc->input_file);
        		pc->flags |= INIT_IFILE;
        	} else if (pc->flags & TTY) {

This is where normal command line input from a terminal is handled, via the
GNU ``readline`` library, which implements a command line history mechanism,
and a command line editing mode:

::

        		if (!(pc->readline = readline(pc->prompt))) {
        			args[0] = NULL;
        			fprintf(fp, "\n");
        			return;
        		}
        		if (strlen(pc->readline) >= BUFSIZE)
        			error(FATAL, "input line exceeds maximum of 1500 bytes\n");
        		else
        			strcpy(pc->command_line, pc->readline);
        		free(pc->readline);

        		clean_line(pc->command_line);

The command line may be modified by ``pseudo_command()``, which handles
commands such as ``h`` (history) and ``r`` (re-run). The command line,
possibly modified, is stored in the ``readline`` history:

::

        		pseudo_command(pc->command_line);
        		strcpy(pc->orig_line, pc->command_line);

        		if (strlen(pc->command_line) && !iscntrl(pc->command_line[0]))
        			add_history(pc->command_line);

        		check_special_handling(pc->command_line);
           } else {

If ``stdin`` is a pipe, the input is handled here:

::

                	if (fgets(pc->command_line, BUFSIZE-1, stdin) == NULL)
        			clean_exit(1);
        		clean_line(pc->command_line);
        		strcpy(pc->orig_line, pc->command_line);
           }

        	/*
        	 *  First clean out all linefeeds and leading/trailing spaces.
        	 *  Then substitute aliases for the real thing they represent.
        	 */
        	clean_line(pc->command_line);

If the command entered is an alias, make the substitution for the actual
command here:

::

        	resolve_aliases();

        	/*
        	 *  Setup output redirection based upon the command line itself or
        	 *  based upon the default scrolling behavior, if any.
        	 */

If a command line specifies redirection to a file or pipe,
``setup_redirect()`` will set up the destination of the command output, and
strip off the redirection part of the command line:

::

        	switch (setup_redirect(FROM_COMMAND_LINE))
        	{
        	case REDIRECT_NOT_DONE:
        	case REDIRECT_TO_STDPIPE:
        	case REDIRECT_TO_PIPE:
        	case REDIRECT_TO_FILE:
        		break;

        	case REDIRECT_SHELL_ESCAPE:
        	case REDIRECT_SHELL_COMMAND:
        	case REDIRECT_FAILURE:
        		RESTART();
        		break;
        	}

Finally, the command line is broken up into substrings, referenced by the
global ``argcnt`` and ``args[]`` array:

::

        	/*
        	 *  Setup the global argcnt and args[] array for use by everybody
        	 *  during the life of this command.
        	 */
        	argcnt = parse_line(pc->command_line, args);
        }

At this point, ``args[0]`` points to a command, is followed by zero or more
argument strings, and is ready for handling by :ref:`exec_command()
<exec_command>`

.. _exec_command:

exec_command()
~~~~~~~~~~~~~~

The ``exec_command()`` function accesses the global command table to determine
whether the first argument in the command string is a standard command, with
several other special cases handled here as well. Comments are interspersed
below:

::

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

If the command line string contains a command from the global command table,
the per-command REFRESH_TASK_TABLE flag is checked to determine whether the
task table of currenlt should be refreshed. This is only necessary on a live
system:

::

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

If the command line has used the *< inputfile* format to feed a set of
arguments to an individual command, the request is shipped off to the
``exec_args_input_file()`` file, which cycles through each line of the
*inputfile*, re-constructs the command line with the unique argument inserted,
and executes the command:

::

                        if (is_args_input_file(ct, &args_ifile))
                                exec_args_input_file(ct, &args_ifile);
                        else

Otherwise, the command is issued here:

::

                                (*ct->func)();

                        pc->lastcmd = pc->curcmd;
                        pc->curcmd = pc->program_name;
                        return;
                }

If the first token in the command line is < followed by a filename, then the
request is to run a set of one or more commands from the specified file. In
that case, the ``exec_input_file()`` function is called to issue each command
in the file individually:

::

                if (is_input_file())
                        return;

                if (is_external_command())
                        return;

                if (is_builtin_command())
                        return;

The ``is_datatype_command`` function checks the first token in the command
line to see whether it's the name of a variable, structure, union, enum or
typedef. If so, ``args[0]`` is changed to the appropriate command, i.e., to
"p", "struct", "union", or "whatis", the original args are all shifted into
the next higer ``args[]`` location, and the command reattempted:

::

                if (is_datatype_command())
                        goto reattempt;

                if (STRNEQ(args[0], "#") || STRNEQ(args[0], "//"))
                        return;

The ``is_gdb_command()`` function checks the first token in the command line
to see whether it's an acceptable GDB command. If so, ``args[0]`` is changed
to "gdb", the original args are all shifted into the next higer ``args[]``
location, and the command is reattempted:

::

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

.. _commandexec:

Command Execution
-----------------

- :ref:`Error Handling <errorhandling>`

.. _arguments:

Arguments
~~~~~~~~~

Recall from the :ref:`process_command_line() <process_command_line>` section,
that the following three :ref:`Global Data <global>` variables are set up for
use by the ``getopt()`` facility in the per-command functions:

::

        char *args[MAXARGS];    /* argument array */
        int argcnt;             /* argument count */
        int argerrs;            /* argument error counter */

The following sample command template shows the typical usage of the variables
above in conjunction with the ``optarg`` and ``optind`` variables associated
with the ``getopt()`` facility. Note that the ``cmd_usage()`` function does
not return when passed the ``SYNOPSIS`` flag:

::

        void
        cmd_sample(void)
        {
                int c;
                char *argptr1, *argptr2;
                int aflag = 0;

                while ((c = getopt(argcnt, args, "ab:")) != EOF) {
                        switch(c)
                        {
                        case 'a':
                                aflag++;
                                break;

                        case 'b':
                                argptr1 = optarg;
                                break;

                        default:
                                argerrs++;
                }

                if (argerrs)
                         cmd_usage(pc->curcmd, SYNOPSIS);

                while (args[optind]) {
                        argptr2 = args[optind];
                        optind++;
                }

... (*execute command*) ...

.. _memalloc:

Memory Allocation
~~~~~~~~~~~~~~~~~

The ``malloc()`` function should *only* be used for buffers that are permanent
to the crash session. After session initialization is complete, ``malloc()``
should *never* be used for buffers required for the execution of individual
commands. Instead, the built-in buffer management facility should be used,
which prevents the possibility of memory leaks. There are 4 memory allocation
functions available, which should be accessed by their associated macros:

::

        char *getbuf(long);
        void freebuf(char *);
        char *resizebuf(char *, long, long);
        char *strdupbuf(char *);
        #define GETBUF(X)   getbuf((long)(X))
        #define FREEBUF(X)  freebuf((char *)(X))
        #define RESIZEBUF(X,Y,Z) (X) = (typeof(X))resizebuf((char *)(X), (long)(Y), (long)(Z));
        #define STRDUPBUF(X) strdupbuf((char *)(X))

The buffer returned by ``GETBUF()`` is always zeroed-out. While it is always
good practice to call ``FREEBUF()`` when a buffer is no longer required, it is
not absolutely necessary. That is because the the next call to
:ref:`process_command_line() <process_command_line>` results in a call to
``restore_sanity()``, which in turn calls ``free_all_bufs()``.

.. _utilityfunc:

Utility Functions
~~~~~~~~~~~~~~~~~

The primary utility functions required to perform a crash command are those
that are related to:

1. kernel symbols
2. kernel data structures

::

        struct syment {
                ulong value;
                char *name;
                struct syment *val_hash_next;
                struct syment *name_hash_next;
                char type;
                unsigned char cnt;
                unsigned char flags;
                unsigned char pad2;
        };

Given the shear number of kernel symbols, the ``syment`` structures of base
kernel symbols on the ordered list are also linked onto two hash tables for
quick look-up, one hashed by address value (using ``val_hash_next``), and the
other by symbol name (using ``name_hash_next``). The ``type`` field is the
character type, i.e., 't', 'd', 'b', etc., and ``cnt`` indicates whether there
are more than one symbol with the same name.

The externally-available symbol-related utility functions are found in
``symbols.c``, and are listed together in ``defs.h``. Several utility
functions are specific to base kernel symbols, some for both kernel and module
symbols, and others specific to module symbols. For example, among the
most-commonly used functions are those listed below:

::

     int symbol_exists(char *name);

   Check whether a kernel or module symbol name exists. This is often used when
   executing a command that has multiple resolution options that depend upon the
   age/version of the kernel being analyzed.

::

     ulong symbol_value(char *name);

   Return the address value of a symbol name; in the case of multiple symbols
   with the same name, the lowest virtual address symbol value is returned.

::

     struct syment *symbol_search(char *name);

   Return a pointer to the ``syment`` of a kernel or module symbol name.

::

     struct syment *kernel_symbol_search(char *name);

   Return a pointer to the ``syment`` of a kernel symbol name.

::

     struct syment *value_search(ulong value, ulong *offset);

   Return a pointer to the ``syment`` of the symbol closest to a value, along
   with a pointer to the offset from the symbol value if requested.

::

     int module_symbol(ulong value, struct syment **spp, struct load_module **lmp,
                       char *name, ulong radix)

   Multi-purpose function that confirms whether the ``value`` is in a module's
   address space, and optionally returns a pointer to a ``syment`` of the closest
   symbol, a pointer the module's ``load_module`` structure, fills a name string
   consisting of the symbol name plus any offset expressed in the radix
   specified.

Here is the section of ``defs.h`` that lists the externally available
functions from ``symbols.c``:

::

        /*
         *  symbols.c
         */
        void symtab_init(void);
        char *check_specified_kernel_debug_file(void);
        void no_debugging_data(int);
        void get_text_init_space(void);
        int is_kernel_text(ulong);
        int is_kernel_data(ulong);
        int is_init_data(ulong value);
        int is_kernel_text_offset(ulong);
        int is_symbol_text(struct syment *);
        int is_rodata(ulong, struct syment **);
        int get_text_function_range(ulong, ulong *, ulong *);
        void datatype_init(void);
        struct syment *symbol_search(char *);
        struct syment *value_search(ulong, ulong *);
        struct syment *value_search_base_kernel(ulong, ulong *);
        struct syment *value_search_module(ulong, ulong *);
        struct syment *symbol_search_next(char *, struct syment *);
        ulong highest_bss_symbol(void);
        int in_ksymbol_range(ulong);
        int module_symbol(ulong, struct syment **,
        	struct load_module **, char *, ulong);
        #define IS_MODULE_VADDR(X) \
        	(module_symbol((ulong)(X), NULL, NULL, NULL, *gdb_output_radix))
        char *closest_symbol(ulong);
        ulong closest_symbol_value(ulong);
        #define SAME_FUNCTION(X,Y) (closest_symbol_value(X) == closest_symbol_value(Y))
        void show_symbol(struct syment *, ulong, ulong);
        #define SHOW_LINENUM  (0x1)
        #define SHOW_SECTION  (0x2)
        #define SHOW_HEX_OFFS (0x4)
        #define SHOW_DEC_OFFS (0x8)
        #define SHOW_RADIX() (*gdb_output_radix == 16 ? SHOW_HEX_OFFS : SHOW_DEC_OFFS)
        #define SHOW_MODULE  (0x10)
        int symbol_name_count(char *);
        int symbol_query(char *, char *, struct syment **);
        struct syment *next_symbol(char *, struct syment *);
        struct syment *prev_symbol(char *, struct syment *);
        void get_symbol_data(char *, long, void *);
        int try_get_symbol_data(char *, long, void *);
        char *value_to_symstr(ulong, char *, ulong);
        char *value_symbol(ulong);
        ulong symbol_value(char *);
        ulong symbol_value_module(char *, char *);
        struct syment *per_cpu_symbol_search(char *);
        int symbol_exists(char *s);
        int kernel_symbol_exists(char *s);
        struct syment *kernel_symbol_search(char *);
        ulong symbol_value_from_proc_kallsyms(char *);
        int get_syment_array(char *, struct syment **, int);
        void set_temporary_radix(unsigned int, unsigned int *);
        void restore_current_radix(unsigned int);
        void dump_struct(char *, ulong, unsigned);
        void dump_struct_member(char *, ulong, unsigned);
        void dump_union(char *, ulong, unsigned);
        void store_module_symbols_v1(ulong, int);
        void store_module_symbols_v2(ulong, int);
        int is_datatype_command(void);
        int is_typedef(char *);
        int arg_to_datatype(char *, struct datatype_member *, ulong);
        void dump_symbol_table(void);
        void dump_struct_table(ulong);
        void dump_offset_table(char *, ulong);
        int is_elf_file(char *);
        int is_kernel(char *);
        int is_shared_object(char *);
        int file_elf_version(char *);
        int is_system_map(char *);
        int is_compressed_kernel(char *, char **);
        int select_namelist(char *);
        int get_array_length(char *, int *, long);
        int get_array_length_alt(char *, char *, int *, long);
        int builtin_array_length(char *, int, int *);
        char *get_line_number(ulong, char *, int);
        char *get_build_directory(char *);
        int datatype_exists(char *);
        int get_function_numargs(ulong);
        int is_module_name(char *, ulong *, struct load_module **);
        int is_module_address(ulong, char *);
        ulong lowest_module_address(void);
        ulong highest_module_address(void);
        int load_module_symbols(char *, char *, ulong);
        void delete_load_module(ulong);
        ulong gdb_load_module_callback(ulong, char *);
        char *load_module_filter(char *, int);
        #define LM_P_FILTER   (1)
        #define LM_DIS_FILTER (2)
        long datatype_info(char *, char *, struct datatype_member *);
        int get_symbol_type(char *, char *, struct gnu_request *);
        int get_symbol_length(char *);
        int text_value_cache(ulong, uint32_t, uint32_t *);
        int text_value_cache_byte(ulong, unsigned char *);
        void dump_text_value_cache(int);
        void clear_text_value_cache(void);
        void dump_numargs_cache(void);
        int patch_kernel_symbol(struct gnu_request *);
        struct syment *generic_machdep_value_to_symbol(ulong, ulong *);
        long OFFSET_verify(long, char *, char *, int, char *);
        long SIZE_verify(long, char *, char *, int, char *);
        long OFFSET_option(long, long, char *, char *, int, char *, char *);
        long SIZE_option(long, long, char *, char *, int, char *, char *);
        void dump_trace(void **);
        int enumerator_value(char *, long *);
        int dump_enumerator_list(char *);
        struct load_module *init_module_function(ulong);
        struct struct_member_data {
        	char *structure;
        	char *member;
        	long type;
        	long unsigned_type;
        	long length;
        	long offset;
        	long bitpos;
        	long bitsize;
        };
        int fill_struct_member_data(struct struct_member_data *);
        void parse_for_member_extended(struct datatype_member *, ulong);
        void add_to_downsized(char *);
        int is_downsized(char *);
        int is_string(char *, char *);
        struct syment *symbol_complete_match(const char *, struct syment *);

::

        struct offset_table {                    /* stash of commonly-used offsets */
                long list_head_next;             /* add new entries to end of table */
                long list_head_prev;
                long task_struct_pid;
                long task_struct_state;
                long task_struct_comm;
                long task_struct_mm;
                long task_struct_tss;
                long task_struct_thread;
                long task_struct_active_mm;

... (*complete contents not shown*) ...

::

                long dentry_d_sb;
                long device_private_knode_class;
                long timerqueue_head_rb_root;
                long rb_root_cached_rb_leftmost;
                long bpf_map_memory;
                long bpf_map_memory_pages;
                long bpf_map_memory_user;
                long bpf_prog_aux_name;
        };

Similarly, the ``size_table`` structure contains the sizes of commonly-used
structures or structure members, all of which are initialized to invalid size
values of -1:

::

        struct size_table {         /* stash of commonly-used sizes */
                long page;
                long free_area_struct;
                long zone_struct;
                long free_area;
                long zone;
                long kmem_slab_s;
                long kmem_cache_s;
                long kmem_bufctl_t;
                long slab_s;
                long slab;
                long cpucache_s;
                long array_cache;
                long swap_info_struct;

... (*complete contents not shown*) ...

.. _datatype_info:

::

                long pid;
                long bpf_prog;
                long bpf_prog_aux;
                long bpf_map;
                long bpf_insn;
                long xarray;
                long xa_node;
        };

In ``symbols.c`` there is a multipurpose function called ``datatype_info()``,
which requires a pointer to structure ``name``, and accepts optional pointers
to a structure ``member`` name and to a ``struct datatype_member``. At a
minimum, it returns a size value, or -1 if it fails. Optionally it fills in a
passed-in ``datatype_member`` structure:

::

     long
     datatype_info(char *name, char *member, struct datatype_member *dm)

The ``datatype_member`` structure looks like this:

::

     struct datatype_member {        /* minimal definition of a structure/union */
             char *name;             /* and possibly a member within it */
             char *member;
             ulong type;
             long size;
             long member_offset;
             long member_size;
             int member_typecode;
             ulong flags;
             char *tagname;         /* tagname and value for enums */
             long value;
             ulong vaddr;
     };

The ``dm`` pointer argument may also be a coded value:

::

     #define MEMBER_SIZE_REQUEST ((struct datatype_member *)(-1))
     #define ANON_MEMBER_OFFSET_REQUEST ((struct datatype_member *)(-2))
     #define MEMBER_TYPE_REQUEST ((struct datatype_member *)(-3))
     #define STRUCT_SIZE_REQUEST ((struct datatype_member *)(-4))
     #define MEMBER_TYPE_NAME_REQUEST ((struct datatype_member *)(-5))
     #define ANON_MEMBER_SIZE_REQUEST ((struct datatype_member *)(-6))

The ``datatype_info()`` function is not meant to be called directly, but
rather it gets accessed via a set of macros. For example, to determine the
size of a data structure, this macro should be used:

::

     #define STRUCT_SIZE(X)  datatype_info((X), NULL, STRUCT_SIZE_REQUEST)

To determine the offset of a structure member, use this macro:

::

     #define MEMBER_OFFSET(X,Y)  datatype_info((X), (Y), NULL)

Data structure sizes and member offset values that are used repeatedly are
typically stored in the ``offset_table`` and ``size_table`` :ref:`global data
<global>` structures using these macros:

::

     #define ASSIGN_OFFSET(X)   (offset_table.X)
     #define ASSIGN_SIZE(X)     (size_table.X)

     #define MEMBER_OFFSET_INIT(X, Y, Z) (ASSIGN_OFFSET(X) = MEMBER_OFFSET(Y, Z))
     #define STRUCT_SIZE_INIT(X, Y) (ASSIGN_SIZE(X) = STRUCT_SIZE(Y))

Once stored in the ``offset_table`` and ``size_table``, the offset or size
values can then be accessed like so:

::

     #define OFFSET(X)  (OFFSET_verify(offset_table.X, (char *)__FUNCTION__, __FILE__, __LINE__, #X))
     #define SIZE(X)  (SIZE_verify(size_table.X, (char *)__FUNCTION__, __FILE__, __LINE__, #X))

The ``OFFSET_verify()`` and ``SIZE_verify()`` functions verify that the table
entry is valid (not -1), and if so, simply returns the stored value. If the
entry in invalid, a fatal error message including the the file and line number
of the call site is displayed, and the command is aborted. This is a good
thing -- as the kernel changes, the data structure or member may no longer
exist or may have been renamed, and therefore a fix must be applied.

To avoid a command abort, there are macros that check the validity of sizes or
members:

::

     #define STRUCT_EXISTS(X)    (datatype_info((X), NULL, STRUCT_SIZE_REQUEST) >= 0)
     #define MEMBER_EXISTS(X,Y)  (datatype_info((X), (Y), NULL) >= 0)

or if the ``offset_table`` and ``size_table`` entries are valid:

::

     #define VALID_STRUCT(X)    (size_table.X >= 0)
     #define VALID_MEMBER(X)    (offset_table.X >= 0)

There are similar functions for the global ``array_table``, and macros for use
when accessing structure members that are contains within embedded anonymous
structures. Here is the section of ``defs.h`` that contains all of the size
and offset macros:

::

        /*
         *  The following set of macros use gdb to determine structure, union,
         *  or member sizes/offsets.  They should be used only during initialization
         *  of the offset_table or size_table, or with data structures whose names
         *  or members are only known/specified during runtime.
         */
        #define MEMBER_SIZE_REQUEST ((struct datatype_member *)(-1))
        #define ANON_MEMBER_OFFSET_REQUEST ((struct datatype_member *)(-2))
        #define MEMBER_TYPE_REQUEST ((struct datatype_member *)(-3))
        #define STRUCT_SIZE_REQUEST ((struct datatype_member *)(-4))
        #define MEMBER_TYPE_NAME_REQUEST ((struct datatype_member *)(-5))
        #define ANON_MEMBER_SIZE_REQUEST ((struct datatype_member *)(-6))

        #define STRUCT_SIZE(X)      datatype_info((X), NULL, STRUCT_SIZE_REQUEST)
        #define UNION_SIZE(X)       datatype_info((X), NULL, STRUCT_SIZE_REQUEST)
        #define STRUCT_EXISTS(X)    (datatype_info((X), NULL, STRUCT_SIZE_REQUEST) >= 0)
        #define DATATYPE_SIZE(X)    datatype_info((X)->name, NULL, (X))
        #define MEMBER_OFFSET(X,Y)  datatype_info((X), (Y), NULL)
        #define MEMBER_EXISTS(X,Y)  (datatype_info((X), (Y), NULL) >= 0)
        #define MEMBER_SIZE(X,Y)    datatype_info((X), (Y), MEMBER_SIZE_REQUEST)
        #define MEMBER_TYPE(X,Y)    datatype_info((X), (Y), MEMBER_TYPE_REQUEST)
        #define MEMBER_TYPE_NAME(X,Y)    ((char *)datatype_info((X), (Y), MEMBER_TYPE_NAME_REQUEST))
        #define ANON_MEMBER_OFFSET(X,Y)    datatype_info((X), (Y), ANON_MEMBER_OFFSET_REQUEST)
        #define ANON_MEMBER_SIZE(X,Y)    datatype_info((X), (Y), ANON_MEMBER_SIZE_REQUEST)

        /*
         *  The following set of macros can only be used with pre-intialized fields
         *  in the offset table, size table or array_table.
         */
        #define OFFSET(X)          (OFFSET_verify(offset_table.X, (char *)__FUNCTION__, __FILE__, __LINE__, #X))
        #define SIZE(X)            (SIZE_verify(size_table.X, (char *)__FUNCTION__, __FILE__, __LINE__, #X))
        #define INVALID_OFFSET     (-1)
        #define INVALID_MEMBER(X)  (offset_table.X == INVALID_OFFSET)
        #define INVALID_SIZE(X)    (size_table.X == -1)
        #define VALID_SIZE(X)      (size_table.X >= 0)
        #define VALID_STRUCT(X)    (size_table.X >= 0)
        #define VALID_MEMBER(X)    (offset_table.X >= 0)
        #define ARRAY_LENGTH(X)    (array_table.X)
        #define ASSIGN_OFFSET(X)   (offset_table.X)
        #define ASSIGN_SIZE(X)     (size_table.X)
        #define OFFSET_OPTION(X,Y) (OFFSET_option(offset_table.X, offset_table.Y, (char *)__FUNCTION__, __FILE__, __LINE__, #X, #Y))
        #define SIZE_OPTION(X,Y)   (SIZE_option(size_table.X, size_table.Y, (char *)__FUNCTION__, __FILE__, __LINE__, #X, #Y))

        #define MEMBER_OFFSET_INIT(X, Y, Z) (ASSIGN_OFFSET(X) = MEMBER_OFFSET(Y, Z))
        #define STRUCT_SIZE_INIT(X, Y) (ASSIGN_SIZE(X) = STRUCT_SIZE(Y))
        #define ARRAY_LENGTH_INIT(A, B, C, D, E) ((A) = get_array_length(C, D, E))
        #define ARRAY_LENGTH_INIT_ALT(A, B, C, D, E) ((A) = get_array_length_alt(B, C, D, E))
        #define MEMBER_SIZE_INIT(X, Y, Z) (ASSIGN_SIZE(X) = MEMBER_SIZE(Y, Z))
        #define ANON_MEMBER_OFFSET_INIT(X, Y, Z) (ASSIGN_OFFSET(X) = ANON_MEMBER_OFFSET(Y, Z))

The contents of the 3 global tables can be viewed during runtime like so:

::

     crash> help -o
                       offset_table:
                     list_head_next: 0
                     list_head_prev: 8
                    task_struct_pid: 1188
                  task_struct_state: 0
             task_struct_exit_state: 1160
                   task_struct_comm: 1656
                     task_struct_mm: 1128
                    task_struct_tss: -1
                 task_struct_thread: 1688
              task_struct_active_mm: 1136
                task_struct_tss_eip: -1
                task_struct_tss_esp: -1

... (*complete contents not shown*) ...

::

                         size_table:
                               page: 64
                         page_flags: 8
                  trace_print_flags: 16
                   free_area_struct: -1
                          free_area: 104
                        zone_struct: -1
                              zone: 2048

... (*complete contents not shown*) ...

::

                        array_table:
                  kmem_cache_s_name: 0
                kmem_cache_s_c_name: 0
                 kmem_cache_s_array: 0
               kmem_cache_s_cpudata: 0
                            log_buf: 0
                           irq_desc: 0
                         irq_action: 0
                      timer_vec_vec: 0
                 timer_vec_root_vec: 0
                    tvec_root_s_vec: 0
                         tvec_s_vec: 0
                    page_hash_table: 0
                    net_device_name: 16
           neigh_table_hash_buckets: 0
                       neighbour_ha: 32
                          swap_info: 27
             pglist_data_node_zones: 4
              zone_struct_free_area: 0
                     zone_free_area: 11

To restrict the lengthy output to items of interest, a string fragment may be
added to the command. For example:

::

     crash> help -o vm_area
                       offset_table:
               vm_area_struct_vm_mm: 64
             vm_area_struct_vm_next: 16
            vm_area_struct_vm_start: 0
              vm_area_struct_vm_end: 8
            vm_area_struct_vm_flags: 80
             vm_area_struct_vm_file: 160
           vm_area_struct_vm_offset: -1
            vm_area_struct_vm_pgoff: 152

                         size_table:
                     vm_area_struct: 216
            vm_area_struct_vm_flags: 8
     crash>

The initialization of items in the 3 global tables is typically accomplished
during the various subsystem initialization functions during the start up of a
crash session. But for lesser-used items, the initialization can be done on a
one-time basis if/when a particular command is called. The existence of data
structures or members is often used for determining code paths to take when
the resolution of a command differs for various versions of the kernel.

.. _errorhandling:

Error Handling
~~~~~~~~~~~~~~

The handling of initialization-time and runtime errors is generally
accomplished by calling ``error()``, which is defined here in ``defs.h``

::

     #define error __error               /* avoid conflict with gdb error() */

The ``__error()`` function accepts a varying number of arguments by using the
C library's ``va_start(3)`` facility:

::

     int
     __error(int type, char *fmt, ...)

In addition, the ``type`` argument above directs the function to:

1. display the error message and return
2. display the error message and abort the current command
3. display the error message and abort the crash session during initialization

The ``type`` arguments are these:

::

     #define INFO           (1)
     #define FATAL          (2)
     #define FATAL_RESTART  (3)
     #define WARNING        (4)
     #define NOTE           (5)
     #define CONT           (6)

.. _GDB_interface:

GDB Interface
-------------

After the :ref:`GDB initialization <GDB_init>` sequence has completed, all
runtime access to the GDB source code is essentially funneled through one
function, which is located in ``gdb-`` <*version*>``/gdb/symtab.c``

::

     void
     gdb_command_funnel(struct gnu_request *req)

It takes a pointer to a ``gnu_request`` structure, which is a multi-purpose
structure that is used for interfacing with the embedded GDB code. Based upon
the ``command`` and ``flags`` members, only the relevant fields need to be
initialized:

::

     /*
      *  Common request structure for BFD or GDB data or commands.
      */
     struct gnu_request {
     	int command;
     	char *buf;
     	FILE *fp;
     	ulong addr;
     	ulong addr2;
     	ulong count;
     	ulong flags;
     	char *name;
     	ulong length;
     	int typecode;
     #if defined(GDB_5_3) || defined(GDB_6_0) || defined(GDB_6_1) || defined(GDB_7_0)
     	char *typename;
     #else
     	char *type_name;
     #endif
     	char *target_typename;
     	ulong target_length;
     	int target_typecode;
     	int is_typedef;
     	char *member;
     	long member_offset;
     	long member_length;
     	int member_typecode;
     	long value;
     	char *tagname;
     	ulong pc;
     	ulong sp;
     	ulong ra;
     	int curframe;
     	ulong frame;
     	ulong prevsp;
     	ulong prevpc;
     	ulong lastsp;
     	ulong task;
     	ulong debug;
     	struct stack_hook *hookp;
     	struct global_iterator {
         		int finished;
     		int block_index;
         		struct symtab *symtab;
         		struct symbol *sym;
         		struct objfile *obj;
       	} global_iterator;
     	struct load_module *lm;
     	char *member_main_type_name;
     	char *member_main_type_tag_name;
     	char *member_target_type_name;
     	char *member_target_type_tag_name;
     	char *type_tag_name;
     };

These are the possible ``command`` and ``flags`` values:

::

     /*
      *  GNU commands
      */
     #define GNU_DATATYPE_INIT           (1)
     #define GNU_DISASSEMBLE             (2)
     #define GNU_GET_LINE_NUMBER         (3)
     #define GNU_PASS_THROUGH            (4)
     #define GNU_GET_DATATYPE            (5)
     #define GNU_COMMAND_EXISTS          (6)
     #define GNU_STACK_TRACE             (7)
     #define GNU_ALPHA_FRAME_OFFSET      (8)
     #define GNU_FUNCTION_NUMARGS        (9)
     #define GNU_RESOLVE_TEXT_ADDR       (10)
     #define GNU_ADD_SYMBOL_FILE         (11)
     #define GNU_DELETE_SYMBOL_FILE      (12)
     #define GNU_VERSION                 (13)
     #define GNU_PATCH_SYMBOL_VALUES     (14)
     #define GNU_GET_SYMBOL_TYPE         (15)
     #define GNU_USER_PRINT_OPTION       (16)
     #define GNU_SET_CRASH_BLOCK         (17)
     #define GNU_GET_FUNCTION_RANGE      (18)
     #define GNU_GET_NEXT_DATATYPE       (19)
     #define GNU_LOOKUP_STRUCT_CONTENTS  (20)
     #define GNU_DEBUG_COMMAND           (100)
     /*
      *  GNU flags
      */
     #define GNU_PRINT_LINE_NUMBERS   (0x1)
     #define GNU_FUNCTION_ONLY        (0x2)
     #define GNU_PRINT_ENUMERATORS    (0x4)
     #define GNU_RETURN_ON_ERROR      (0x8)
     #define GNU_COMMAND_FAILED      (0x10)
     #define GNU_FROM_TTY_OFF        (0x20)
     #define GNU_NO_READMEM          (0x40)
     #define GNU_VAR_LENGTH_TYPECODE (0x80)

The success or failure of the GDB command is reflected in the ``flags`` field
if the GNU_COMMAND_FAILED flag is set upon return to the caller.

For the most part, ``gdb_command_funnel()`` is not called directly from the
top-level source code, but typically is called by one of these two functions:

::

     void
     gdb_interface(struct gnu_request *req)

This function requires the set-up of a ``gnu_request`` structure.

Alternatively, a GDB command line string may be passed directly into the
embedded GDB module without having to set up a ``gnu_request`` structure:

::

     int
     gdb_pass_through(char *cmd, FILE *fptr, ulong flags)

The ``gdb_pass_through()`` function is a simpler manner of accessing GDB; it
sets up a ``gnu_request`` structure and calls ``gdb_interface()``. The
``fptr`` FILE pointer argument allows the overriding of the default output
destination, and the ``flags`` argument is copied to the ``gnu_request.flags``
member.

The ``gdb_command_funnel()`` function is basically a large switch statement.
Based upon the command, one of several support functions are called to perform
the request. Several of the support functions (named with a ``gdb_`` prefix)
are also grafted onto ``symtab.c``, while others are existing GDB functions:

::

     /*
      *  All commands from above come through here.
      */
     void
     gdb_command_funnel(struct gnu_request *req)
     {
             struct symbol *sym;

             if (req->command != GNU_VERSION) {
                   replace_ui_file_FILE(gdb_stdout, req->fp);
                   replace_ui_file_FILE(gdb_stderr, req->fp);
             	do_cleanups(all_cleanups());
             }

             switch (req->command)
             {
             case GNU_VERSION:
             	req->buf = (char *)version;
             	break;

The commonly-used ``gdb_pass_through()`` function, which passes a native GDB
command string, goes through here:

::

             case GNU_PASS_THROUGH:
                   execute_command(req->buf,
             		req->flags & GNU_FROM_TTY_OFF ? FALSE : TRUE);
             	break;

             case GNU_USER_PRINT_OPTION:
             	get_user_print_option_address(req);
             	break;

             case GNU_RESOLVE_TEXT_ADDR:
                   sym = find_pc_function(req->addr);
                   if (!sym || TYPE_CODE(sym->type) != TYPE_CODE_FUNC)
                             req->flags |= GNU_COMMAND_FAILED;
             	break;

The crash utility's ``dis`` command goes through here:

::

             case GNU_DISASSEMBLE:
             	if (req->addr2)
                             sprintf(req->buf, "disassemble 0x%lx 0x%lx",
             			req->addr, req->addr2);
             	else
                             sprintf(req->buf, "disassemble 0x%lx", req->addr);
                   execute_command(req->buf, TRUE);
                   break;

The crash utility's ``mod -[sS]`` command loads module debuginfo data here:

::

             case GNU_ADD_SYMBOL_FILE:
             	gdb_add_symbol_file(req);
             	break;

             case GNU_DELETE_SYMBOL_FILE:
             	gdb_delete_symbol_file(req);
             	break;

             case GNU_GET_LINE_NUMBER:
             	gdb_get_line_number(req);
             	break;

This is the most-common GDB request, with :ref:`datatype_info()
<datatype_info>` being the most likely caller:

::

             case GNU_GET_DATATYPE:
             	gdb_get_datatype(req);
             	break;

             case GNU_GET_SYMBOL_TYPE:
             	gdb_get_symbol_type(req);
             	break;

             case GNU_COMMAND_EXISTS:
             	gdb_command_exists(req);
             	break;

             case GNU_ALPHA_FRAME_OFFSET:
             	req->value = 0;
             	break;

             case GNU_FUNCTION_NUMARGS:
             	gdb_function_numargs(req);
             	break;

             case GNU_DEBUG_COMMAND:
             	gdb_debug_command(req);
             	break;

When the symbol values in a ``vmlinux`` do not match their actual values, such
as when KASLR is in effect, here is where the internal GDB ``minimal_symbol``
values get patched during session initialization:

::

             case GNU_PATCH_SYMBOL_VALUES:
             	gdb_patch_symbol_values(req);
             	break;

             case GNU_SET_CRASH_BLOCK:
             	gdb_set_crash_block(req);
             	break;

             case GNU_GET_FUNCTION_RANGE:
             	sym = lookup_symbol(req->name, 0, VAR_DOMAIN, 0);
             	if (!find_pc_partial_function(req->pc, NULL, &req->addr, &req->addr2))
             		req->flags |= GNU_COMMAND_FAILED;
             	break;

             case GNU_LOOKUP_STRUCT_CONTENTS:
             	req->value = lookup_struct_contents(req);
             	break;

             case GNU_GET_NEXT_DATATYPE:
             	iterate_datatypes(req);
             	break;

             default:
             	req->flags |= GNU_COMMAND_FAILED;
             	break;
             }
     }

.. _debugging:

Debugging
---------

- :ref:`test_cmd() <test_cmd>`

.. _crashdebug:

CRASHDEBUG()
~~~~~~~~~~~~

The crash utility contains several hundred permanent debug print statements
that are only seen when the ``pc->debug`` value is non-zero:

::

     define CRASHDEBUG(x) (pc->debug >= (x))

It can be set to any value, although the current crash code utilizes values
between 1 and 8. So for example, if CRASHDEBUG(2) is called, its associated
debug print statement(s) are displayed only if the current ``pc->debug``
setting is 1 or 2, and code gated by higher CRASHDEBUG() values will be
ignored. By setting ``pc->debug`` to 8, all possible debug print statements
will be displayed.

To view debug statements during initialization, a debug number may be passed
on the command line, e.g.:

::

     $ crash -d2 vmlinux vmcore
     ...

During runtime, the number be set or cleared with the ``set`` command:

::

     crash> set debug 1
     debug: 1
     crash>

By convention, the higher the CRASHDEBUG() argument, the more verbose the
output will be. Care should be taken to utilize CRASHDEBUG() arguments to
prevent over-saturation of debug output. For example, when doing a memory read
initiated from the ``rd`` command, several CRASHDEBUG(4) code segments are
encountered. First in ``cmd_rd()``:

::

           if (CRASHDEBUG(4))
                   fprintf(fp, "<addr: %llx count: %ld flag: %lx (%s)>\n",
                           addr, count, flag, addrtype);

Then in ``readmem()``:

::

           if (CRASHDEBUG(4))
                   fprintf(fp, "\n",
                           addr, memtype_string(memtype, 1), type, size,
                           error_handle_string(error_handle), (ulong)buffer);

and:

::

                   if (CRASHDEBUG(4))
                           fprintf(fp, "<%s: addr: %llx paddr: %llx cnt: %ld>\n",
                                   readmem_function_name(), addr,
                                   (unsigned long long)paddr, cnt);

Accordingly, to see those debug statements, the debug value must be at least
4:

::

     crash> rd ffff9567db05c740
     ffff9567db05c740:  0000000080000080                    ........
     crash> set debug 3
     debug: 3
     crash> rd ffff9567db05c740
     ffff9567db05c740:  0000000080000080                    ........
     crash> set debug 4
     debug: 4
     crash> rd ffff9567db05c740
     <addr: ffff9567db05c740 count: 1 flag: 490 (KVADDR)>
     <readmem: ffff9567db05c740, KVADDR, "64-bit KVADDR", 8, (FOE), 7fff5a6eec78>
     <read_diskdump: addr: ffff9567db05c740 paddr: 1db05c740 cnt: 8>
     ffff9567db05c740:  0000000080000080                    ........
     crash>

Generally speaking, when a debug statement is important to see, it should be
gated by a lower CRASHDEBUG() argument.

.. _console:

console()
~~~~~~~~~

A problem with CRASHDEBUG() debug statements is that they often called with
``fprint(fp, ...)`` or ``error(...)``, and therefore are intermingled with
command output. This can get messy, and so it is sometimes preferable if the
debug statements can be displayed on a different terminal. To do so, the
``console`` function can be utilized, which accepts a varying number of
arguments by using the C library's va_start(3) facility:

::

     int
     console(char *fmt, ...)

This function is a no-op unless the ``pc->console`` pointer has been pre-set
by one these options:

1. by a ``set`` command in a ``.crashrc`` file:

   ::

        $ cat .crashrc
        set console /dev/pts/4
        $

2. by a runtime ``set`` command:

   ::

        crash> set console /dev/pts/4

3. on the crash command line.

   ::

        $ crash -c /dev/pts/4 vmlinux vmcore

There are several hundred ``console()`` calls existing in the current crash
source code.

.. _test_cmd:

cmd_test()
~~~~~~~~~~

Often it is helpful to debug an issue, or to develop a new command, by
modifying the hidden :ref:`test <hidden_test>` command. As written,
``cmd_test()`` does nothing:

::

     crash> test
     crash>

But it serves as a template for a regular command, accepting arguments in the
normal manner:

::

     static struct option test_long_options[] = {
             {"no", no_argument, 0, 0},
             {"req", required_argument, 0, 0},
             {0, 0, 0, 0}
     };

     /*
      *  Test your stuff here first if you'd like.  If anything's being done
      *  below in this routine, consider it leftover trash...
      */
     void
     cmd_test(void)
     {
             int c;
             int option_index;

Add any single-letter options to the empty string argument to
``getopt_long()``, and add ``case`` statements as desired. Although no other
command currently uses long options, they can be added to the
``test_long_options[]`` array above and handled here:

::

             while ((c = getopt_long(argcnt, args, "",
                     test_long_options, &option_index)) != EOF) {
                     switch(c)
                     {
                     case 0:
                             if (STREQ(test_long_options[option_index].name, "no"))
                                     fprintf(fp, "no argument\n");
                             if (STREQ(test_long_options[option_index].name, "req"))
                                     fprintf(fp, "required argument: %s\n", optarg);
                             break;

                     default:
                             argerrs++;
                             break;
                     }
             }

             if (argerrs)
                     cmd_usage(pc->curcmd, SYNOPSIS);

And cycle though one or more standalone arguments here:

::

             while (args[optind]) {
                     ;
                     optind++;
             }
     }

In addition, ``test`` can be used as a argument to the ``foreach`` command.
This empty function can be modified to run debug code on a per-task basis:

::

     void
     foreach_test(ulong task, ulong flags)
     {

     }

For example, to run the default do-nothing ``foreach_test()`` function on all
user tasks:

::

     crash> foreach user test
     PID: 1      TASK: ffff92a13a1e8000  CPU: 0   COMMAND: "systemd"

     PID: 1083   TASK: ffff92a407482080  CPU: 3   COMMAND: "systemd-journal"

     PID: 1097   TASK: ffff92a41e6b4100  CPU: 3   COMMAND: "lvmetad"

     PID: 1121   TASK: ffff92a407480000  CPU: 2   COMMAND: "systemd-udevd"

     PID: 1564   TASK: ffff92a40c170000  CPU: 3   COMMAND: "auditd"

     PID: 1565   TASK: ffff92a40749a080  CPU: 4   COMMAND: "auditd"

     PID: 1566   TASK: ffff92a40749c100  CPU: 4   COMMAND: "audispd"

     PID: 1568   TASK: ffff92a41e07b0c0  CPU: 3   COMMAND: "sedispatch"

     ...

.. _extension:

Extension Modules
-----------------

- :ref:`RHEL Packages <rhel_ext>`

.. _samples_ext:

Package Samples
~~~~~~~~~~~~~~~

The crash utility source tree contains an ``extensions`` subdirectory that
contains a handful of sample extension modules. After the crash binary has
been built, the sample extension modules may be built like so:

::

     $ ls extensions
     dminfo.c  echo.c  eppic.c  eppic.mk  Makefile  snap.c  snap.mk  trace.c
     $ make extensions
     gcc -Wall -g -shared -rdynamic -o echo.so echo.c -fPIC -DX86_64  -DGDB_7_6
     Cloning into 'eppic'...
     remote: Enumerating objects: 221, done.
     remote: Total 221 (delta 0), reused 0 (delta 0), pack-reused 221
     Receiving objects: 100% (221/221), 196.51 KiB | 221.00 KiB/s, done.
     Resolving deltas: 100% (89/89), done.
     cd eppic/libeppic && make
     bison -peppic -v -t -d eppic.y
     eppic.y: warning: 253 shift/reduce conflicts [-Wconflicts-sr]
     eppic.y: warning: 20 reduce/reduce conflicts [-Wconflicts-rr]
     cc -g -fno-omit-frame-pointer -fPIC   -c -o eppic_util.o eppic_util.c
     cc -g -fno-omit-frame-pointer -fPIC   -c -o eppic_node.o eppic_node.c
     cc -g -fno-omit-frame-pointer -fPIC   -c -o eppic_var.o eppic_var.c
     cc -g -fno-omit-frame-pointer -fPIC   -c -o eppic_func.o eppic_func.c
     cc -g -fno-omit-frame-pointer -fPIC   -c -o eppic_str.o eppic_str.c
     cc -g -fno-omit-frame-pointer -fPIC   -c -o eppic_op.o eppic_op.c
     cc -g -fno-omit-frame-pointer -fPIC   -c -o eppic_num.o eppic_num.c
     cc -g -fno-omit-frame-pointer -fPIC   -c -o eppic_stat.o eppic_stat.c
     cc -g -fno-omit-frame-pointer -fPIC   -c -o eppic_builtin.o eppic_builtin.c
     cc -g -fno-omit-frame-pointer -fPIC   -c -o eppic_type.o eppic_type.c
     cc -g -fno-omit-frame-pointer -fPIC   -c -o eppic_case.o eppic_case.c
     cc -g -fno-omit-frame-pointer -fPIC   -c -o eppic_api.o eppic_api.c
     cc -g -fno-omit-frame-pointer -fPIC   -c -o eppic_member.o eppic_member.c
     cc -g -fno-omit-frame-pointer -fPIC   -c -o eppic_alloc.o eppic_alloc.c
     cc -g -fno-omit-frame-pointer -fPIC   -c -o eppic_define.o eppic_define.c
     cc -g -fno-omit-frame-pointer -fPIC   -c -o eppic_input.o eppic_input.c
     cc -g -fno-omit-frame-pointer -fPIC   -c -o eppic_print.o eppic_print.c
     bison -peppicpp -v -t -d eppicpp.y
     eppicpp.y: warning: 23 shift/reduce conflicts [-Wconflicts-sr]
     cc -g -fno-omit-frame-pointer -fPIC -c eppicpp.tab.c
     cc -g -fno-omit-frame-pointer -fPIC -c eppic.tab.c
     flex -L -Peppic -t eppic.l > lex.eppic.c
     cc -g -fno-omit-frame-pointer -fPIC -c lex.eppic.c
     flex -Peppicpp -t eppicpp.l  > lex.eppicpp.c
     cc -g -fno-omit-frame-pointer -fPIC -c lex.eppicpp.c
     cc -g -fno-omit-frame-pointer -fPIC -o mkbaseop mkbaseop.c
     ./mkbaseop > baseops.c
     cc -g -fno-omit-frame-pointer -fPIC -c baseops.c
     ar ccurl libeppic.a eppic_util.o eppic_node.o eppic_var.o eppic_func.o eppic_str.o eppic_op.o
     eppic_num.o eppic_stat.o eppic_builtin.o eppic_type.o eppic_case.o eppic_api.o eppic_member.o
     eppic_alloc.o eppic_define.o eppic_input.o eppic_print.o eppicpp.tab.o eppic.tab.o lex.eppic.o
     lex.eppicpp.o baseops.o
     gcc -g -Ieppic/libeppic -I../gdb-7.6/gdb -I../gdb-7.6/bfd -I../gdb-7.6/include -I../gdb-7.6/gdb/config
     -I../gdb-7.6/gdb/common -I../gdb-7.6 -nostartfiles -shared -rdynamic -o eppic.so eppic/applications/crash/eppic.c
     -fPIC -DX86_64 -DGDB_7_6 -Leppic/libeppic -leppic
     gcc -Wall -g -shared -rdynamic -o trace.so trace.c -fPIC -DX86_64  -DGDB_7_6
     gcc -Wall -g -shared -rdynamic -o dminfo.so dminfo.c -fPIC -DX86_64  -DGDB_7_6
     gcc -Wall -g -I. -shared -rdynamic -o snap.so snap.c -fPIC -DX86_64  -DGDB_7_6
     $

Contributors often post patches that add a new extension module into the
samples directory. However, adding a new extension module there implies future
support, which is typically not advisable. It is suggested to post them them
on the upstream
`crash extension modules <https://crash-utility.github.io/extensions.html>`__
page, and let the author support them in the future.

.. _upstream_ext:

Upstream
~~~~~~~~

As a convenience to the greater crash utility user community, extension
modules are given "upstream" presence on the
`crash extension modules <https://crash-utility.github.io/extensions.html>`__
page. It contains information regarding:

The maintenance of the page is primarily concerned with the update of the
information of existing extension modules, or adding new extension module
entries. The page uses a simple static HTML format that can be easily
modified, or used as a template for new modules.

.. _rhel_ext:

RHEL Packages
~~~~~~~~~~~~~

There are 4 crash extension modules that have been made into RHEL packages as
requested by Red Hat OEM partners:

1. ``crash-gcore-command`` (Fujitsu)

   Creates an ELF core file from a user-space task that was running in a kernel
   dumpfile. The dumpfile must contain user-space pages for it to be effective.

2. ``crash-ptdump-command`` (Fujitsu)

   Retrieve and decode the log buffer generated by the Intel Processor Trace
   facility.

3. ``crash-trace-command`` (Fujitsu)

   Displays kernel tracing data and traced events that occurred prior to a panic.

4. ``crash-spu-commands`` (IBM)

   Analyzes SPU specific data for Power Cell/B.E. processor. This package was
   discontinued after RHEL7.

When bugs arise that are not trivial to fix, the associated bugzilla should
have its "Partner" field set appropriately, and a fix requested from them.

.. _testing:

Testing
-------

Typically an input file is fed to the crash session, and the results reviewed.
Because of the sheer number of command options, as well as the verbosity of
the output of certain commands, it can be difficult to:

1. automate the review of test output, or
2. manually review the test output.

Complicating things is the need to test the various architectures, and whether
to base the testing strategy from an upstream perspective, or from a
distribution perspective. Accordingly, the manner of testing is to be left up
to the maintainers.

.. _pkgmaint:

Package Maintenance
-------------------

- :ref:`CVS <cvs>`

.. _github:

Github
~~~~~~

The most recent releases are available from
`github <https://github.com/crash-utility/crash/releases>`__ here:

::

     https://github.com/crash-utility/crash/releases

which offers both ``crash-<version >.tar.gz`` and
``crash-<<version>``.zip file formats:

::

     $ tar xvzmf crash-<version>.tar.gz
     $ unzip crash-<version>.zip

This differs from the Red Hat `people <http://people.redhat.com/anderson>`__
web page here:

::

     http://people.redhat.com/anderson

which offers both ``crash-<version >.tar.gz`` and
``crash-<version >.src.rpm`` file formats:

::

     $ tar xvzmf crash-<version>.tar.gz
     $ rpm -ivh crash-<version>.src.rpm

The only difference between the
`github <https://github.com/crash-utility/crash/releases>`__ and Red Hat
`people <http://people.redhat.com/anderson>`__ offerings is that the Red Hat
release packages are bundled with the ``gdb-7.6.tar.gz`` file. This may be
subject to change when the :ref:`Fedora <fedora>` and :ref:`RHEL <rhel>`
package ``crash.spec`` files are updated to reference the
`github <https://github.com/crash-utility/crash/releases>`__
``crash-<<version>````.tar.gz`` file as their source.

The `crash github account <https://github.com/crash-utility>`__ contains 3
repositories:

1. crash
2. crash-extensions
3. crash-utility.github.io

In order to be able to update the repositories, they should be cloned with
HTTPS URLs:

::

     $ git clone https://github.com/crash-utility/crash.git
     $ git clone https://github.com/crash-utility/crash-extensions.git
     $ git clone https://github.com/crash-utility/crash-utility.github.io.git

Files may be added, and existing files updated, like so:

::

     $ git add <filename>
     $ git commit -a
     $ git push origin

Because the repository was cloned with HTTPS URLs, Git will ask for your
GitHub username and password.

It is recommended that when working with the
`crash <https://github.com/crash-utility/crash>`__ repository, that builds are
performed in a separate cloned directory tree, primarily because the act of
performing a build may modify these 3 files:

1. **``Makefile``**
2. **``README``**
3. **``.rh_rpm_package``**

While applying patches to files in the directory tree will be done as a normal
course of events, care should be taken to not inadvertently check in the 3
files above when any changes to them were made as a result of a build
procedure.

.. _fedora:

Fedora
~~~~~~

The maintenance of the Fedora package essentially consists of the following
steps:

1. Upload the newly-released ``crash-`` <*version*>``.tar.gz`` file to the
   lookaside cache
2. Add any newly-required patch files
3. Modify the ``crash.spec`` file accordingly
4. Commit and push any new patch files and the ``crash.spec`` file
5. Build the package

The master branch is used for new releases. A typical sequence would be:

::

     $ fedpkg clone crash
     $ fedpkg switch-branch master
     $ git pull
     $ fedpkg new-sources crash-<version>.tar.gz
     $ git add <patch-file>
     $ vi crash.spec
     $ fedpkg commit -p
     $ fedpkg build

****crash.spec modifications for Fedora****In the following sample Fedora ``crash.spec`` file, descriptions of required/suggested changes are interspersed: # # crash core analysis suite # Summary: Kernel analysis utility for live systems, netdump, diskdump, kdump, LKCD or mcore dumpfiles Name: crash The ``Version`` number should reflect the upstream version number. The ``Release`` number typically starts with 1 if nothing has changed from the upstream version, and bumped up as required for patches that are subsequently applied to a given upstream release: **Version:
7.2.8** **Release:
2%{?dist}** License: GPLv3 The ``Source`` needs to be changed to: **``https://github.com/crash-utility/crash/archive/%{version}.tar.gz``**. However, because the github release file does not contain the ``gdb-7.6.tar.gz`` file, 1 of 3 possible solutions are suggested: The ``gdb-7.6.tar.gz`` file can be added to the crash github repository. It was not done originally because github imposed a 25MB file size limit at the time, and it is a 30MB file. Adding it the github repository will increase the time to do a ``git clone``, or the time to download a release file. The ``gdb-7.6.tar.gz`` file can be added as a second ``Source`` file, and uploaded to the lookaside buffer with the ``fedpkg new-sources`` command: ``Source0: https://github.com/crash-utility/crash/archive/%{version}.tar.gz Source1: http://ftp.gnu.org/gnu/gdb/gdb-7.6.tar.gz`` When creating a github release, a binary file can be uploaded and displayed along with the tar.gz and zip files. Therefore, a ``crash-<version>.tar.gz`` file can be created in a local git repository with ``sudo make release``, and uploaded. Then that file, which contains ``gdb-7.6.tar.gz``, can be referenced as the single ``Source`` file. **Source:
http://people.redhat.com/anderson/crash-%{version}.tar.gz** The URL should be changed to: ``https://crash-utility.github.io`` **URL:
http://people.redhat.com/anderson** ExclusiveOS: Linux ExclusiveArch: %{ix86} ia64 x86_64 ppc ppc64 s390 s390x %{arm} aarch64 ppc64le BuildRequires: ncurses-devel zlib-devel lzo-devel snappy-devel bison readline-devel BuildRequires: gcc gcc-c++ Requires: binutils Provides: bundled(libiberty) Provides: bundled(gdb) = 7.6 When a new release is performed, there are two default patches that are required for the Fedora release: The ``lzo_snappy.patch`` is added so that the LZO and snappy compression libraries are built into the crash binary by default. The ``use_system_readline_v3.patch`` is required because Fedora does not allow the use of the built-in static ``readline`` library that comes with GDB, and requires the use of the host system's ``readline`` library. Any other patches, such as ``aarch64_gcc10_fno-common.patch`` below, can be removed upon the next release, because its contents should be included in the new release. **Patch0:
lzo_snappy.patch** **Patch1:
use_system_readline_v3.patch** Patch2: aarch64_gcc10_fno-common.patch %description The core analysis suite is a self-contained tool that can be used to investigate either live systems, kernel core dumps created from the netdump, diskdump and kdump packages from Red Hat Linux, the mcore kernel patch offered by Mission Critical Linux, or the LKCD kernel patch. %package devel Requires: %{name} = %{version}, zlib-devel Summary: kernel crash analysis utility for live systems, netdump, diskdump, kdump, LKCD or mcore dumpfiles %description devel The core analysis suite is a self-contained tool that can be used to investigate either live systems, kernel core dumps created from the netdump, diskdump and kdump packages from Red Hat Linux, the mcore kernel patch offered by Mission Critical Linux, or the LKCD kernel patch. %prep %setup -n %{name}-%{version} -q See the ``Patch0`` and ``Patch1`` discussion above: **%patch0
-p1 -b lzo_snappy.patch** **%patch1 -p1 -b
use_system_readline_v3.patch** %patch2 -p1 -b aarch64_gcc10_fno-common.patch %build make RPMPKG="%{version}-%{release}" CFLAGS="%{optflags}" LDFLAGS="%{build_ldflags}" %install rm -rf %{buildroot} mkdir -p %{buildroot}%{_bindir} make DESTDIR=%{buildroot} install mkdir -p %{buildroot}%{_mandir}/man8 cp -p crash.8 %{buildroot}%{_mandir}/man8/crash.8 mkdir -p %{buildroot}%{_includedir}/crash chmod 0644 defs.h cp -p defs.h %{buildroot}%{_includedir}/crash %files %{_bindir}/crash %{_mandir}/man8/crash.8\*
%doc README COPYING3 %files devel
%{_includedir}/\* Typically there are a sequence of *<release>*-1 entries for each unmodified upstream release, with an occasional bump of the release for a release-specific patch, or when Fedora Release Engineering performs a mass rebuilds: %changelog \*
Fri Jan 31 2020 Dave Anderson - 7.2.8-2 - Update to latest upstream release -
Fix aarch64 build for gcc-10 -fno-common
\* Tue Jan 28 2020 Fedora Release Engineering - 7.2.7-2 - Rebuilt for https://fedoraproject.org/wiki/Fedora_32_Mass_Rebuild \*
Mon Sep 23 2019 Dave Anderson - 7.2.7-1 - Update to latest upstream release
\* Wed Jul 24 2019 Fedora Release Engineering - 7.2.6-2 - Rebuilt for https://fedoraproject.org/wiki/Fedora_31_Mass_Rebuild \*
Mon May 6 2019 Dave Anderson - 7.2.6-1 - Update to latest upstream release
\* Sun Feb 17 2019 Igor Gnatenko - 7.2.5-3 - Rebuild for readline 8.0 \* Thu
Jan 31 2019 Fedora Release Engineering - 7.2.5-2 - Rebuilt for
https://fedoraproject.org/wiki/Fedora_30_Mass_Rebuild
\* Fri Jan 11 2019 Dave Anderson - 7.2.5-1 - Update to latest upstream release \*
Mon Sep 24 2018 Dave Anderson - 7.2.4-1 - Update to latest upstream release
\* Thu Jul 12 2018 Fedora Release Engineering - 7.2.3-2 - Rebuilt for https://fedoraproject.org/wiki/Fedora_29_Mass_Rebuild \*
Fri May 18 2018 Dave Anderson - 7.2.3-1 - Update to latest upstream release
``...``*(remainder of changelog not shown)*

.. _rhel:

RHEL
~~~~

The maintenance of the RHEL8 package essentially consists of the following
steps:

1. Upload the newly-released ``crash-`` <*version*>``.tar.gz`` file to the
   lookaside cache
2. Add any newly-required patch files
3. Modify the ``crash.spec`` file accordingly
4. Commit and push any new patch files and the ``crash.spec`` file
5. Build the package

The most recent ``rhel8-x.y.z`` branch is used for new releases. A typical
sequence would be:

::

     $ rhpkg clone crash
     $ rhpkg switch-branch rhel8-x.y.z
     $ git pull
     $ rhpkg new-sources crash-<version>.tar.gz
     $ git add <patch-file>
     $ vi crash.spec
     $ rhpkg commit -p
     $ rhpkg build

****crash.spec modifications for RHEL8****In the following sample RHEL8 ``crash.spec`` file, descriptions of required/suggested changes are interspersed: # # crash core analysis suite # Summary: Kernel analysis utility for live systems, netdump, diskdump, kdump, LKCD or mcore dumpfiles Name: crash The ``Version`` number should reflect the upstream version number. The ``Release`` number typically starts with 1 if nothing has changed from the upstream version, and bumped up as required for patches that are subsequently applied to a given upstream release: **Version:
7.2.7** **Release:
3%{?dist}** License: GPLv3 Group: Development/Debuggers The ``Source`` needs to be changed to: **``https://github.com/crash-utility/crash/archive/%{version}.tar.gz``**. However, because the github release file does not contain the ``gdb-7.6.tar.gz`` file, 1 of 3 possible solutions are suggested: The ``gdb-7.6.tar.gz`` file can be added to the crash github repository. It was not done originally because github imposed a 25MB file size limit at the time, and it is a 30MB file. Adding it the github repository will increase the time to do a ``git clone``, or the time to download a release file. The ``gdb-7.6.tar.gz`` file can be added as a second ``Source`` file, and uploaded to the lookaside buffer with the ``rhpkg new-sources`` command: ``Source0: https://github.com/crash-utility/crash/archive/%{version}.tar.gz Source1: http://ftp.gnu.org/gnu/gdb/gdb-7.6.tar.gz`` When creating a github release, a binary file can be uploaded and displayed along with the tar.gz and zip files. Therefore, a ``crash-<version>.tar.gz`` file can be created in a local git repository with ``sudo make release``, and uploaded. Then that file, which contains ``gdb-7.6.tar.gz``, can be referenced as the single ``Source`` file. **Source:
http://people.redhat.com/anderson/crash-%{version}.tar.gz** The URL should be changed to: ``https://crash-utility.github.io`` **URL:
http://people.redhat.com/anderson** ExclusiveOS: Linux ExclusiveArch: %{ix86} ia64 x86_64 ppc ppc64 s390 s390x %{arm} aarch64 ppc64le Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot-%(%{__id_u} -n) BuildRequires: ncurses-devel zlib-devel lzo-devel bison snappy-devel Requires: binutils When a new release is performed, there are two default patches that are required for the RHEL8 release: The ``lzo_snappy.patch`` is added so that the LZO and snappy compression libraries are built into the crash binary by default. The ``rhel8_build.patch`` is required to address this distribution bugzilla: `Bug 1624101 - Review annocheck distro flag failures in crash <https://bugzilla.redhat.com/show_bug.cgi?id=1624101>`__ Any other patches can be removed upon the next release, because their contents should be included in the new release. **Patch0:
lzo_snappy.patch** **Patch1:
rhel8_build.patch** Patch2: github_105a3e13_to_b5c2359f.patch Patch3: github_5cbb2fd8_to_6c1c8ac6.patch %description The core analysis suite is a self-contained tool that can be used to investigate either live systems, kernel core dumps created from the netdump, diskdump and kdump packages from Red Hat Linux, the mcore kernel patch offered by Mission Critical Linux, or the LKCD kernel patch. %package devel Requires: %{name} = %{version}, zlib-devel lzo-devel snappy-devel Summary: kernel crash analysis utility for live systems, netdump, diskdump, kdump, LKCD or mcore dumpfiles Group: Development/Debuggers %description devel The core analysis suite is a self-contained tool that can be used to investigate either live systems, kernel core dumps created from the netdump, diskdump and kdump packages from Red Hat Linux, the mcore kernel patch offered by Mission Critical Linux, or the LKCD kernel patch. %prep %setup -n %{name}-%{version} -q See the ``Patch0`` and ``Patch1`` discussion above: **%patch0
-p1 -b lzo_snappy.patch** **%patch1 -p1 -b
rhel8_build.patch** %patch2 -p1 -b github_105a3e13_to_b5c2359f.patch %patch3 -p1 -b github_5cbb2fd8_to_6c1c8ac6.patch %build make RPMPKG="%{version}-%{release}" CFLAGS="%{optflags}" %install rm -rf %{buildroot} mkdir -p %{buildroot}%{_bindir} make DESTDIR=%{buildroot} install mkdir -p %{buildroot}%{_mandir}/man8 cp -p crash.8 %{buildroot}%{_mandir}/man8/crash.8 mkdir -p %{buildroot}%{_includedir}/crash chmod 0644 defs.h cp -p defs.h %{buildroot}%{_includedir}/crash %clean rm -rf %{buildroot} %files %defattr(-,root,root,-) %{_bindir}/crash %{_mandir}/man8/crash.8\*
%doc README COPYING3 %files devel %defattr(-,root,root,-)
%{_includedir}/\* Typically there are a sequence of *<release>*-1 entries for each unmodified upstream release, with an occasional bump of the release for a release-specific patch. The ``Resolves: rhbz#<number>`` line is required for the commit to be approved: %changelog \*
Mon Feb 3 2020 Dave Anderson - 7.2.7-3 - Rebase to github commit 6c1c8ac6
Resolves: rhbz#1738619 - Fix "log -a" option Resolves: rhbz#1785537 - Fix for
ELF kdump vmcores form s390x KASLR kernels Resolves: rhbz#1786996
\* Mon Nov 11 2019 Dave Anderson - 7.2.7-2 - Rebase to latest upstream sources Resolves: rhbz#1738619 - Support for KASLR on s390x Resolves: rhbz# 1753172 \*
Mon Jun 10 2019 Dave Anderson - 7.2.6-2 - Fix "p" command regression Resolves:
rhbz#1718417 - Fix arm64 debug kernel read error message during initialization
Resolves: rhbz#1718736
\* Mon May 6 2019 Dave Anderson - 7.2.6-1 - Rebase to latest upstream sources Resolves: rhbz#1686560 - Utilize the VMCOREINFO PT_NOTE in /proc/kcore header Resolves: rhbz#1627528 - Support extraction of CONFIG_PROC_VMCORE_DEVICE_DUMP data from dumpfile header Resolves: rhbz#1702535 ``...``*(remainder
of changelog not shown)*

.. _centos:

CentOS Stream
~~~~~~~~~~~~~

*(to be determined)*

.. _people:

people.redhat.com
~~~~~~~~~~~~~~~~~

The original upstream web site of crash utility and several crash extension
modules will be decommissioned. It has been replaced by
`https://crash-utility.github.io <https://crash-utility.github.io>`__. It
should be noted that the ``Documentation//admin-guide/kdump/kdump.rst`` file
in the kernel source tree has this reference, which needs to be patched:

::

     You can also use the Crash utility to analyze dump files in Kdump
     format. Crash is available on Dave Anderson's site at the following URL:

        http://people.redhat.com/~anderson/

.. _github_io:

https://crash-utility.github.io
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is the new upstream web site for the crash utility, as well as several
crash extension modules. The extension modules are located
`https://crash-utility.github.io/extensions.html <https://crash-utility.github.io/extensions.html>`__,
which is also linked from the main page.

.. _cvs:

CVS
~~~

The crash utility sources have been handled by CVS since 2002, which was when
it first became a Red Hat product. While github started being utilized since
2014, CVS has also been utilized at the same time. Whether there is any need
to continue using CVS is debatable. However, if desired, the CVS repository
can be mounted on a local system. For example, it was mounted on a
``/var/CVS/cvsroot`` directory as shown in this ``/etc/fstab``:

::

       $ cat /etc/fstab

       #
       # /etc/fstab
       # Created by anaconda on Wed Feb 27 16:38:39 2019
       #
       # Accessible filesystems, by reference, are maintained under '/dev/disk'
       # See man pages fstab(5), findfs(8), mount(8) and/or blkid(8) for more info
       #
       /dev/mapper/RHEL7CSB-Root /                       ext4    defaults,x-systemd.device-timeout=0 1 1
       UUID=71e604a8-643d-4a96-8bc5-f3c80ccbe87d /boot                   ext4    defaults        1 2
       /dev/mapper/RHEL7CSB-Home /home                   ext4    defaults,x-systemd.device-timeout=0 1 2
       /dev/mapper/RHEL7CSB-Swap swap                    swap    defaults,x-systemd.device-timeout=0 0 0
       ntap-bos-c01-prod01-nfs01a.storage.bos.redhat.com:/common_data_nfs/home/bos /mnt/NFS_home nfs vers=3,rw,rsize=8192,wsize=8192,hard,intr 0 0
       ntap-bos-c01-prod01-nfs01a.storage.bos.redhat.com:/common_data_nfs/share/projects/cvs /var/CVS/cvsroot nfs vers=3,rw,rsize=8192,wsize=8192,hard,intr 0 0

Given the existence of ``/var/CVS/cvsroot``, two shell variables must be
exported:

::

     $ env | grep -e CVSROOT -e CVS_RSH
     CVSROOT=/var/CVS/cvsroot
     CVS_RSH=ssh
     $

   After that is done, the CVS tree can be checked out:

   $ cvs co crash
   ...

.. _mailing:

Crash Utility Mailing List
--------------------------

The crash utility mailing list at
`https://www.redhat.com/mailman/listinfo/crash-utility <https://www.redhat.com/mailman/listinfo/crash-utility>`__
is a moderated mailing list. This prevents unsolicited spam email, but it also
prevents legitimate posts from initially being accepted from non-members.

When one or more posts come from non-members, they are grouped together and an
email is sent to the list moderator. If all messages are spam, click on the
"Submit All Data" button, and they will be discarded. However, if a message
comes from a legitimate source, click on the "Accept" button to accept the
message, and either:

1. Under the "Add to one of these sender files:" click on the "Accepts" button.
   Then the submitter can converse on the list in the future without moderator
   approval and without forcing them to subscribe.
2. Send the submitter an invitation to join the list, by going to the moderator
   page at
   `https://www.redhat.com/mailman/admin/crash-utility/members/add <https://www.redhat.com/mailman/admin/crash-utility/members/add>`__.

.. _upstream:

Monitoring Kernel Upstream Development
--------------------------------------

To stay on top of upcoming kernel developments that may impact the crash
utility, it is helpful to watch for changes to key source files in a kernel
git repository.

For example, the following ``check_repo`` script can be put in the top-level
directory of a kernel git tree. It should be run after a ``git pull`` is done,
and will check for changes to any files that are listed after ``CHECK_FILES``
marker:

::

        $ cat check_repo

        THISFILE=`pwd`/check_repo

        START=`grep -n CHECK_FILES $THISFILE | grep -v grep | cut -d: -f1`
        START=`expr $START + 1`

        cat $THISFILE | sed -n -e "$START,\$p" > .junk1
        > .junk2
        for FILE in `cat .junk1 | awk '{print $2}'`
        do
          /usr/bin/md5sum $FILE >> .junk2
        done

        diff .junk1 .junk2
        RETURN=$?

        exit $RETURN

        CHECK_FILES
        c0653da9a48901f6c2518e67896a0318  Documentation/admin-guide/kdump/vmcoreinfo.rst
        d8f6f29df3acb9cba0ec74248bed40af  arch/arm64/include/asm/memory.h
        6916c8ba13c94dac62a0de6cf80ca7ea  arch/arm64/include/asm/irq.h
        421f31af4cade562bb56d5d38aa6ca75  arch/arm64/include/asm/pgtable.h
        f1a84fb85f32dea4efd7fe25384632b1  arch/arm64/include/asm/pgtable-hwdef.h
        093c5f801e3e968fa725a8173c635509  arch/arm64/kernel/smp.c
        0b06513ea2451da64cf558673b3804d5  arch/arm64/kernel/stacktrace.c
        11384aa4e1cb4fb79eb08fce8f599d21  arch/arm64/kernel/syscall.c
        5aeb0faa1595c039dc1525e824770482  arch/x86/include/asm/orc_lookup.h
        c4a58313de3250117d05d2f08c139a3f  arch/x86/include/asm/orc_types.h
        9349fc55451ba673d4a9e1e6dbbde92d  arch/x86/include/asm/page_64_types.h
        fed3acc43437eeb8cc60d19d92d58abe  arch/x86/include/asm/processor.h
        54800669a2a8b8bf20c4bd1f0bed814b  arch/x86/include/asm/unwind.h
        b889f631cde1a6d6860463ba8921e452  arch/x86/kernel/cpu/common.c
        94c89e2a14da36de3ee07bff254585aa  arch/x86/kernel/dumpstack_64.c
        589605f9082e4b490b669f6080262498  arch/x86/kernel/head64.c
        45d8a283f09f53df8397bc331b4023ba  arch/x86/kernel/machine_kexec_64.c
        8702f9bcf42bcca14110a866c22c6580  arch/x86/kernel/relocate_kernel_64.S
        8e25b56a5ffef581d7ce9522208a53a0  arch/x86/kernel/setup.c
        7628cb78708afd3dfc407587ffa2c38a  arch/x86/kernel/unwind_frame.c
        1f40da8535b5989dd0932a7e11c978c7  arch/x86/mm/dump_pagetables.c
        1c6b873a7814e6e16364f5b70fcb6985  arch/x86/mm/fault.c
        735a1fc2eae25e5a659ffbdb377bc4e0  arch/x86/mm/ident_map.c
        292dc16d39a9ed45cef293cef79e73bf  Documentation/x86/x86_64/mm.rst
        75b952b28b91780457598880d0b3aa0c  fs/proc/kcore.c
        971e7c011d9a6899354e233598fb8862  include/linux/bpf.h
        5543676e36ea27c5f8f21f9014a5801f  include/linux/mm_types.h
        e16ddeecb7177b909e60e82c001951ab  include/linux/mmzone.h
        131bd933a987314ad4cebc669c8fe250  include/linux/page-flags.h
        fd6b0558d9e383427a709ee054eb730b  include/linux/pid.h
        7cd079fbf1eded8a0c9b3b6eca4fcd16  include/linux/sched.h
        08d377ef93777a512d1e29745f762a94  include/linux/vmalloc.h
        2e8b2701138a6779081e627f7e9c2f5a  kernel/configs.c
        28f55e61621c8b08cb0ae2196ede6233  kernel/crash_core.c
        866f4b7a09cd4c44d4f48b1768ffd47d  kernel/pid.c
        aaca59af6b11b0bfa83603ddda4d9e36  kernel/printk/printk.c
        d6b4efb488edfdd8d577c4eb99cb4e49  kernel/resource.c
        0b6a29ca135f4272d6e21a5de44a3d2c  kernel/time/timer.c
        76e856430eba7fe9a4fe259ba7bba644  mm/slab_common.c
        c843eb1990d0118bcc07d8c060ca2b12  mm/slab.c
        023202c806e138be47f9a451f781b37a  mm/slub.c
        $

It is also helpful to monitor the Linux Kernel Mailing List for proposed
patches that may affect the crash utility. For example, at the time of this
writing, these patches look to be impactful:

::

       Function Granular KASLR:

            [PATCH v2 0/9] Function Granular KASLR
            https://lkml.org/lkml/2020/5/21/742

       Thomas Gleixner's consolidation of x86 entry code:

            [patch 00/10] x86/entry: Consolidation - Part I
            https://lkml.org/lkml/2020/2/25/1153

            [patch 0/8] x86/entry: Consolidation - Part II
            https://lkml.org/lkml/2020/2/25/1154

            [patch 00/24] x86/entry: Consolidation - Part III
            https://lkml.org/lkml/2020/2/25/1143

            [patch 00/16] x86/entry: Consolidation - Part IV
            https://lkml.org/lkml/2020/2/25/1120

            [patch 00/15] x86/entry: Consolidation - Part V
            https://lkml.org/lkml/2020/2/25/1099

            [patch V6 00/37] x86/entry: Rework leftovers and merge plan
            https://lkml.org/lkml/2020/5/15/1271

       KASLR on ppc64:

            [PATCH v4 0/6] implement KASLR for powerpc/fsl_booke/64
            https://lkml.org/lkml/2020/3/6/42

       Kernel stack offset randomization:

            [PATCH v2 0/5] Optionally randomize kernel stack offset each syscall
            https://lkml.org/lkml/2020/3/24/1620

.. _errors:

Errors
------

- Runtime Errors

Invocation Errors

yada yada yada

Runtime Errors

yada yada yada

.. _FAQ:

Frequently Asked Questions
--------------------------

1. Do I have to install the relevant kernel debuginfo package on the host
machine where I'm running the crash session? No. At a minimum, only the
vmlinux file is required, and it can be extracted from the kernel debuginfo
package. For example, the vmlinux file can be extracted from a kernel
debuginfo rpm file, and copied to /tmp like so: # rpm2cpio
kernel-debuginfo-2.6.18-122.el5.x86_64.rpm | \ cpio -id --rename
./usr/lib/debug/lib/modules/2.6.18-122.el5/vmlinux rename
./usr/lib/debug/lib/modules/2.6.18-122.el5/vmlinux -> /tmp/vmlinux # The same
thing applies for kernel modules, which are also contained in the kernel
debuginfo package. However, the <module-name>.ko.debug files found in the
kernel debuginfo package are not a standalone kernel module binaries, but
rather just the debuginfo part of the stripped binary module that was
installed. And to load the debuginfo data of the module into the crash
utility, the stripped binary <module-name>.ko binary module file is also
required. See the Debugging Modules section for details.

2. When do I need to use a System.map file on the command line? Almost never.
The only reason for a System.map command line argument is if the vmlinux file
does not match the kernel being analyzed, i.e., the kernel that crashed, or if
running on a live system, the kernel that is running. So the question really
is: why wouldn't they match? One reason is that perhaps the vmlinux of the
kernel that crashed (or is running live) was built without the -g switch, and
therefore has no debuginfo data. In that case, it may be possible to rebuild
the same kernel after-the-fact with the -g switch, and thereby generating a
new vmlinux file with debuginfo data. However, when that is done, there are
subtle changes that may cause the re-built kernel's symbols to not "match up"
with the original. So what the crash utility can do is to take the debuginfo
data from the rebuilt vmlinux file, but update the embedded GDB module's list
of kernel symbol values with the correct symbol values from the System.map
file. So when a System.map file is used on the command line, and where the
vmlinux.debuginfo file is the rebuilt kernel, you will see the crash utility
patching GDB's internal "minimal_symbol" list like so: # crash
vmlinux.debuginfo vmcore System.map-2.6.18-92.el5 crash 4.0-7.4 Copyright (C)
2002, 2003, 2004, 2005, 2006, 2007, 2008 Red Hat, Inc. Copyright (C) 2004,
2005, 2006 IBM Corporation Copyright (C) 1999-2006 Hewlett-Packard Co
Copyright (C) 2005, 2006 Fujitsu Limited Copyright (C) 2006, 2007 VA Linux
Systems Japan K.K. Copyright (C) 2005 NEC Corporation Copyright (C) 1999,
2002, 2007 Silicon Graphics, Inc. Copyright (C) 1999, 2000, 2001, 2002 Mission
Critical Linux, Inc. This program is free software, covered by the GNU General
Public License, and you are welcome to change it and/or distribute copies of
it under certain conditions. Enter "help copying" to see the conditions. This
program has absolutely no warranty. Enter "help warranty" for details. GNU gdb
6.1 Copyright 2004 Free Software Foundation, Inc. GDB is free software,
covered by the GNU General Public License, and you are welcome to change it
and/or distribute copies of it under certain conditions. Type "show copying"
to see the conditions. There is absolutely no warranty for GDB. Type "show
warranty" for details. This GDB was configured as
"x86_64-unknown-linux-gnu"... please wait... (patching 27826 gdb
minimal_symbol values) SYSTEM MAP: System.map-2.6.18-92.el5 DEBUG KERNEL:
vmlinux.debug (2.6.18-92.el5) DUMPFILE: vmcore CPUS: 2 DATE: Thu Dec 13
06:24:24 2007 UPTIME: 00:12:36 LOAD AVERAGE: 0.01, 0.07, 0.10 TASKS: 107
NODENAME: dhcp83-53.boston.redhat.com RELEASE: 2.6.18-92.el5 VERSION: #1 SMP
Tue Nov 27 17:15:58 EST 2007 MACHINE: x86_64 (2793 Mhz) MEMORY: 818.5 MB
PANIC: "SysRq : Trigger a crashdump" PID: 2677 COMMAND: "bash" TASK:
ffff880032e107e0 [THREAD_INFO: ffff880024278000] CPU: 1 STATE: TASK_RUNNING
(SYSRQ) crash> Another reason for a mis-match could be that the target kernel
was a "one-off" debug kernel that was built without -g. In that case, it may
be possible to use a debuginfo vmlinux from the original kernel that it was
based upon, along with the System.map of the target kernel. As long as there
are no changes to any critical data structures that the crash utility depends
upon, that would probably work as well. It should also be noted that the
vmlinux file that was built without -g may also be used in the same way as a
System.map file, i.e., as the source of correct symbol values. In that case,
the crash session could be invoked like so: # crash vmlinux.debuginfo vmcore
vmlinux where the debuginfo data would be taken from the vmlinux.debuginfo
file, and the correct symbol values taken from the vmlinux file and
back-patched into the embedded GDB module.

3. How do I do that? yowza yowza

N. Question template? yowza yowza

.. _further:

Further Information
-------------------

*(to be determined)*

.. _GNU:

GNU Free Documentation License
------------------------------

::

                   GNU Free Documentation License
                     Version 1.2, November 2002

    Copyright (C) 2000,2001,2002  Free Software Foundation, Inc.
        51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
    Everyone is permitted to copy and distribute verbatim copies
    of this license document, but changing it is not allowed.

   0. PREAMBLE

   The purpose of this License is to make a manual, textbook, or other
   functional and useful document "free" in the sense of freedom: to
   assure everyone the effective freedom to copy and redistribute it,
   with or without modifying it, either commercially or noncommercially.
   Secondarily, this License preserves for the author and publisher a way
   to get credit for their work, while not being considered responsible
   for modifications made by others.

   This License is a kind of "copyleft", which means that derivative
   works of the document must themselves be free in the same sense.  It
   complements the GNU General Public License, which is a copyleft
   license designed for free software.

   We have designed this License in order to use it for manuals for free
   software, because free software needs free documentation: a free
   program should come with manuals providing the same freedoms that the
   software does.  But this License is not limited to software manuals;
   it can be used for any textual work, regardless of subject matter or
   whether it is published as a printed book.  We recommend this License
   principally for works whose purpose is instruction or reference.

   1. APPLICABILITY AND DEFINITIONS

   This License applies to any manual or other work, in any medium, that
   contains a notice placed by the copyright holder saying it can be
   distributed under the terms of this License.  Such a notice grants a
   world-wide, royalty-free license, unlimited in duration, to use that
   work under the conditions stated herein.  The "Document", below,
   refers to any such manual or work.  Any member of the public is a
   licensee, and is addressed as "you".  You accept the license if you
   copy, modify or distribute the work in a way requiring permission
   under copyright law.

   A "Modified Version" of the Document means any work containing the
   Document or a portion of it, either copied verbatim, or with
   modifications and/or translated into another language.

   A "Secondary Section" is a named appendix or a front-matter section of
   the Document that deals exclusively with the relationship of the
   publishers or authors of the Document to the Document's overall subject
   (or to related matters) and contains nothing that could fall directly
   within that overall subject.  (Thus, if the Document is in part a
   textbook of mathematics, a Secondary Section may not explain any
   mathematics.)  The relationship could be a matter of historical
   connection with the subject or with related matters, or of legal,
   commercial, philosophical, ethical or political position regarding
   them.

   The "Invariant Sections" are certain Secondary Sections whose titles
   are designated, as being those of Invariant Sections, in the notice
   that says that the Document is released under this License.  If a
   section does not fit the above definition of Secondary then it is not
   allowed to be designated as Invariant.  The Document may contain zero
   Invariant Sections.  If the Document does not identify any Invariant
   Sections then there are none.

   The "Cover Texts" are certain short passages of text that are listed,
   as Front-Cover Texts or Back-Cover Texts, in the notice that says that
   the Document is released under this License.  A Front-Cover Text may
   be at most 5 words, and a Back-Cover Text may be at most 25 words.

   A "Transparent" copy of the Document means a machine-readable copy,
   represented in a format whose specification is available to the
   general public, that is suitable for revising the document
   straightforwardly with generic text editors or (for images composed of
   pixels) generic paint programs or (for drawings) some widely available
   drawing editor, and that is suitable for input to text formatters or
   for automatic translation to a variety of formats suitable for input
   to text formatters.  A copy made in an otherwise Transparent file
   format whose markup, or absence of markup, has been arranged to thwart
   or discourage subsequent modification by readers is not Transparent.
   An image format is not Transparent if used for any substantial amount
   of text.  A copy that is not "Transparent" is called "Opaque".

   Examples of suitable formats for Transparent copies include plain
   ASCII without markup, Texinfo input format, LaTeX input format, SGML
   or XML using a publicly available DTD, and standard-conforming simple
   HTML, PostScript or PDF designed for human modification.  Examples of
   transparent image formats include PNG, XCF and JPG.  Opaque formats
   include proprietary formats that can be read and edited only by
   proprietary word processors, SGML or XML for which the DTD and/or
   processing tools are not generally available, and the
   machine-generated HTML, PostScript or PDF produced by some word
   processors for output purposes only.

   The "Title Page" means, for a printed book, the title page itself,
   plus such following pages as are needed to hold, legibly, the material
   this License requires to appear in the title page.  For works in
   formats which do not have any title page as such, "Title Page" means
   the text near the most prominent appearance of the work's title,
   preceding the beginning of the body of the text.

   A section "Entitled XYZ" means a named subunit of the Document whose
   title either is precisely XYZ or contains XYZ in parentheses following
   text that translates XYZ in another language.  (Here XYZ stands for a
   specific section name mentioned below, such as "Acknowledgements",
   "Dedications", "Endorsements", or "History".)  To "Preserve the Title"
   of such a section when you modify the Document means that it remains a
   section "Entitled XYZ" according to this definition.

   The Document may include Warranty Disclaimers next to the notice which
   states that this License applies to the Document.  These Warranty
   Disclaimers are considered to be included by reference in this
   License, but only as regards disclaiming warranties: any other
   implication that these Warranty Disclaimers may have is void and has
   no effect on the meaning of this License.

   2. VERBATIM COPYING

   You may copy and distribute the Document in any medium, either
   commercially or noncommercially, provided that this License, the
   copyright notices, and the license notice saying this License applies
   to the Document are reproduced in all copies, and that you add no other
   conditions whatsoever to those of this License.  You may not use
   technical measures to obstruct or control the reading or further
   copying of the copies you make or distribute.  However, you may accept
   compensation in exchange for copies.  If you distribute a large enough
   number of copies you must also follow the conditions in section 3.

   You may also lend copies, under the same conditions stated above, and
   you may publicly display copies.

   3. COPYING IN QUANTITY

   If you publish printed copies (or copies in media that commonly have
   printed covers) of the Document, numbering more than 100, and the
   Document's license notice requires Cover Texts, you must enclose the
   copies in covers that carry, clearly and legibly, all these Cover
   Texts: Front-Cover Texts on the front cover, and Back-Cover Texts on
   the back cover.  Both covers must also clearly and legibly identify
   you as the publisher of these copies.  The front cover must present
   the full title with all words of the title equally prominent and
   visible.  You may add other material on the covers in addition.
   Copying with changes limited to the covers, as long as they preserve
   the title of the Document and satisfy these conditions, can be treated
   as verbatim copying in other respects.

   If the required texts for either cover are too voluminous to fit
   legibly, you should put the first ones listed (as many as fit
   reasonably) on the actual cover, and continue the rest onto adjacent
   pages.

   If you publish or distribute Opaque copies of the Document numbering
   more than 100, you must either include a machine-readable Transparent
   copy along with each Opaque copy, or state in or with each Opaque copy
   a computer-network location from which the general network-using
   public has access to download using public-standard network protocols
   a complete Transparent copy of the Document, free of added material.
   If you use the latter option, you must take reasonably prudent steps,
   when you begin distribution of Opaque copies in quantity, to ensure
   that this Transparent copy will remain thus accessible at the stated
   location until at least one year after the last time you distribute an
   Opaque copy (directly or through your agents or retailers) of that
   edition to the public.

   It is requested, but not required, that you contact the authors of the
   Document well before redistributing any large number of copies, to give
   them a chance to provide you with an updated version of the Document.

   4. MODIFICATIONS

   You may copy and distribute a Modified Version of the Document under
   the conditions of sections 2 and 3 above, provided that you release
   the Modified Version under precisely this License, with the Modified
   Version filling the role of the Document, thus licensing distribution
   and modification of the Modified Version to whoever possesses a copy
   of it.  In addition, you must do these things in the Modified Version:

   A. Use in the Title Page (and on the covers, if any) a title distinct
      from that of the Document, and from those of previous versions
      (which should, if there were any, be listed in the History section
      of the Document).  You may use the same title as a previous version
      if the original publisher of that version gives permission.
   B. List on the Title Page, as authors, one or more persons or entities
      responsible for authorship of the modifications in the Modified
      Version, together with at least five of the principal authors of the
      Document (all of its principal authors, if it has fewer than five),
      unless they release you from this requirement.
   C. State on the Title page the name of the publisher of the
      Modified Version, as the publisher.
   D. Preserve all the copyright notices of the Document.
   E. Add an appropriate copyright notice for your modifications
      adjacent to the other copyright notices.
   F. Include, immediately after the copyright notices, a license notice
      giving the public permission to use the Modified Version under the
      terms of this License, in the form shown in the Addendum below.
   G. Preserve in that license notice the full lists of Invariant Sections
      and required Cover Texts given in the Document's license notice.
   H. Include an unaltered copy of this License.
   I. Preserve the section Entitled "History", Preserve its Title, and add
      to it an item stating at least the title, year, new authors, and
      publisher of the Modified Version as given on the Title Page.  If
      there is no section Entitled "History" in the Document, create one
      stating the title, year, authors, and publisher of the Document as
      given on its Title Page, then add an item describing the Modified
      Version as stated in the previous sentence.
   J. Preserve the network location, if any, given in the Document for
      public access to a Transparent copy of the Document, and likewise
      the network locations given in the Document for previous versions
      it was based on.  These may be placed in the "History" section.
      You may omit a network location for a work that was published at
      least four years before the Document itself, or if the original
      publisher of the version it refers to gives permission.
   K. For any section Entitled "Acknowledgements" or "Dedications",
      Preserve the Title of the section, and preserve in the section all
      the substance and tone of each of the contributor acknowledgements
      and/or dedications given therein.
   L. Preserve all the Invariant Sections of the Document,
      unaltered in their text and in their titles.  Section numbers
      or the equivalent are not considered part of the section titles.
   M. Delete any section Entitled "Endorsements".  Such a section
      may not be included in the Modified Version.
   N. Do not retitle any existing section to be Entitled "Endorsements"
      or to conflict in title with any Invariant Section.
   O. Preserve any Warranty Disclaimers.

   If the Modified Version includes new front-matter sections or
   appendices that qualify as Secondary Sections and contain no material
   copied from the Document, you may at your option designate some or all
   of these sections as invariant.  To do this, add their titles to the
   list of Invariant Sections in the Modified Version's license notice.
   These titles must be distinct from any other section titles.

   You may add a section Entitled "Endorsements", provided it contains
   nothing but endorsements of your Modified Version by various
   parties--for example, statements of peer review or that the text has
   been approved by an organization as the authoritative definition of a
   standard.

   You may add a passage of up to five words as a Front-Cover Text, and a
   passage of up to 25 words as a Back-Cover Text, to the end of the list
   of Cover Texts in the Modified Version.  Only one passage of
   Front-Cover Text and one of Back-Cover Text may be added by (or
   through arrangements made by) any one entity.  If the Document already
   includes a cover text for the same cover, previously added by you or
   by arrangement made by the same entity you are acting on behalf of,
   you may not add another; but you may replace the old one, on explicit
   permission from the previous publisher that added the old one.

   The author(s) and publisher(s) of the Document do not by this License
   give permission to use their names for publicity for or to assert or
   imply endorsement of any Modified Version.

   5. COMBINING DOCUMENTS

   You may combine the Document with other documents released under this
   License, under the terms defined in section 4 above for modified
   versions, provided that you include in the combination all of the
   Invariant Sections of all of the original documents, unmodified, and
   list them all as Invariant Sections of your combined work in its
   license notice, and that you preserve all their Warranty Disclaimers.

   The combined work need only contain one copy of this License, and
   multiple identical Invariant Sections may be replaced with a single
   copy.  If there are multiple Invariant Sections with the same name but
   different contents, make the title of each such section unique by
   adding at the end of it, in parentheses, the name of the original
   author or publisher of that section if known, or else a unique number.
   Make the same adjustment to the section titles in the list of
   Invariant Sections in the license notice of the combined work.

   In the combination, you must combine any sections Entitled "History"
   in the various original documents, forming one section Entitled
   "History"; likewise combine any sections Entitled "Acknowledgements",
   and any sections Entitled "Dedications".  You must delete all sections
   Entitled "Endorsements".

   6. COLLECTIONS OF DOCUMENTS

   You may make a collection consisting of the Document and other documents
   released under this License, and replace the individual copies of this
   License in the various documents with a single copy that is included in
   the collection, provided that you follow the rules of this License for
   verbatim copying of each of the documents in all other respects.

   You may extract a single document from such a collection, and distribute
   it individually under this License, provided you insert a copy of this
   License into the extracted document, and follow this License in all
   other respects regarding verbatim copying of that document.

   7. AGGREGATION WITH INDEPENDENT WORKS

   A compilation of the Document or its derivatives with other separate
   and independent documents or works, in or on a volume of a storage or
   distribution medium, is called an "aggregate" if the copyright
   resulting from the compilation is not used to limit the legal rights
   of the compilation's users beyond what the individual works permit.
   When the Document is included in an aggregate, this License does not
   apply to the other works in the aggregate which are not themselves
   derivative works of the Document.

   If the Cover Text requirement of section 3 is applicable to these
   copies of the Document, then if the Document is less than one half of
   the entire aggregate, the Document's Cover Texts may be placed on
   covers that bracket the Document within the aggregate, or the
   electronic equivalent of covers if the Document is in electronic form.
   Otherwise they must appear on printed covers that bracket the whole
   aggregate.

   8. TRANSLATION

   Translation is considered a kind of modification, so you may
   distribute translations of the Document under the terms of section 4.
   Replacing Invariant Sections with translations requires special
   permission from their copyright holders, but you may include
   translations of some or all Invariant Sections in addition to the
   original versions of these Invariant Sections.  You may include a
   translation of this License, and all the license notices in the
   Document, and any Warranty Disclaimers, provided that you also include
   the original English version of this License and the original versions
   of those notices and disclaimers.  In case of a disagreement between
   the translation and the original version of this License or a notice
   or disclaimer, the original version will prevail.

   If a section in the Document is Entitled "Acknowledgements",
   "Dedications", or "History", the requirement (section 4) to Preserve
   its Title (section 1) will typically require changing the actual
   title.

   9. TERMINATION

   You may not copy, modify, sublicense, or distribute the Document except
   as expressly provided for under this License.  Any other attempt to
   copy, modify, sublicense or distribute the Document is void, and will
   automatically terminate your rights under this License.  However,
   parties who have received copies, or rights, from you under this
   License will not have their licenses terminated so long as such
   parties remain in full compliance.

   10. FUTURE REVISIONS OF THIS LICENSE

   The Free Software Foundation may publish new, revised versions
   of the GNU Free Documentation License from time to time.  Such new
   versions will be similar in spirit to the present version, but may
   differ in detail to address new problems or concerns.  See
   http://www.gnu.org/copyleft/.

   Each version of the License is given a distinguishing version number.
   If the Document specifies that a particular numbered version of this
   License "or any later version" applies to it, you have the option of
   following the terms and conditions either of that specified version or
   of any later version that has been published (not as a draft) by the
   Free Software Foundation.  If the Document does not specify a version
   number of this License, you may choose any version ever published (not
   as a draft) by the Free Software Foundation.
