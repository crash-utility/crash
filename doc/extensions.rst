Crash extension modules
=======================

The ``echo.c`` extension module can be used as a simple template for creating
an extension module to implement a new command.

Crash extension modules are required to ``#include`` the
`defs.h <https://github.com/crash-utility/crash/blob/master/defs.h>`__ file
from the top-level directory of crash source tree. There are three suggested
manners for building a module:

1. Hand-compile the module's ``.so`` shared object file like this:

   ``$ gcc -shared -rdynamic -o <module>.so <module>.c -fPIC -D<machine-type> $(TARGET_CFLAGS)``

   where <*machine-type*> is ``X86, X86_64, IA64, PPC64, ARM, S390 or S390X``,
   and where ``$(TARGET_CFLAGS)`` is ``-D_FILE_OFFSET_BITS=64`` on 32-bit
   architectures, and ``-m64`` on ppc64.

   If the extension module contains the obsolete ``_init()`` and ``_fini()``
   functions, then the ``-nostartfiles`` compiler option is also required.
   However it is recommended that constructor and destructor functions be used as
   recommended by the ``dlopen(3)`` man page.

   As a convenience, the crash utility's *crash-<version>.src.rpm* package builds
   a *crash-devel* sub-package, which installs
   `defs.h <https://github.com/crash-utility/crash/blob/master/defs.h>`__ into
   */usr/include/crash/defs.h*.

2. Alternatively, copy the module's ``.c`` source file to the
   *crash-<version>/extensions* subdirectory. Then, from the top-level
   *crash-<version>* directory, enter:

   ``$ make extensions``

   If the default compile line does not suffice, create an accompanying ``.mk``
   makefile with the same prefix as the ``.c`` file, copy it to the
   *crash-<version>/extensions* subdirectory, and enter the same
   ``make extensions`` command as above.

3. Lastly, some extension modules that do have both *<module>.c* and
   *<module>.mk* files may be built without the crash source tree if the
   `defs.h <https://github.com/crash-utility/crash/blob/master/defs.h>`__ file is
   located in the current directory or in the */usr/include/crash* directory:

   ``$ make -f <module>.mk``

To add the module's command(s) to a running crash session, enter:

``crash> extend <path-to>/<module>.so``

The command(s) registered by the extension module will appear in the crash
`help <help_pages/help.html>`__ menu. The module can be installed
automatically if the ``extend`` command above is entered in either
*./.crashrc* or *$HOME/.crashrc*.

If the *crash-<version>.src.rpm* file is used to build the crash package, a
*crash-extensions-<version>.rpm* subpackage containing a subset of the
extension modules below is built. If the subpackage is installed, the
extension modules will be located in */usr/lib/crash/extensions* or
*/usr/lib64/crash/extensions*, whichever is appropriate.

Lastly, there is a ``crash -x`` command line option that will load extension
modules automatically from a particular directory. The search for the
extension module directory will be done in the following order, and the first
one (if any) that exists will be selected as the target directory:

1. the directory specified in the ``CRASH_EXTENSIONS`` shell environment variable
2. */usr/lib64/crash/extensions* (64-bit architectures)
3. */usr/lib/crash/extensions*
4. *./extensions*

All extension modules that are found in the target directory will be loaded
automatically.

.. list-table::
   :header-rows: 1
   :widths: 22 18 60

   * - ``echo.c``
     - ``echo``
     - - Provided primarily as a template for writing new extension modules.
       - To build the module from the top-level *crash-<version>* directory, enter:
         ``$ make extensions``
       - This module's source file is contained within the *crash-<version>.src.rpm*
         and *crash-<version>.tar.gz* files, and the compiled module is included in the
         *crash-extensions-<version>.rpm* subpackage when *crash-<version>.src.rpm* is
         used to build the crash package.
       - Author: Dave Anderson <anderson@redhat.com>

   * - ``snap.c`` ``snap.mk``
     - ``snap``
     - - Takes a snapshot of physical memory and creates an ELF vmcore. The default
         vmcore is a kdump-style dumpfile, but a netdump-style may be optionally
         created. It supports the X86, X86_64, IA64, ARM64 and PPC64 architectures
         only. All caveats regarding the taking of a "live" memory snapshot apply, such
         as the constantly-changing state of the kernel's slab subsystem or active
         process set while the dump is taking place.

       - To build the module from the top-level *crash-<version>* directory, enter:
         ``$ make extensions``

       - The module also serves as an example of an extension module that can be built
         in all three manners:

         1. Copy ``snap.c`` to the *crash-<version>/extensions* subdirectory, and from the
            top-level *crash-<version>* directory, enter: ``$ make extensions``
         2. Copy both ``snap.c`` and ``snap.mk`` to the *crash-<version>/extensions*
            subdirectory, and from the top-level *crash-<version>* directory, enter:
            ``$ make extensions``
         3. Copy ``snap.c``, ``snap.mk``, and
            `defs.h <https://github.com/crash-utility/crash/blob/master/defs.h>`__ into
            any directory. The
            `defs.h <https://github.com/crash-utility/crash/blob/master/defs.h>`__ file
            may also be located in the */usr/include/crash* directory, as would be the
            case if the *crash-devel* sub-package had been installed. Then enter:
            ``$ make -f snap.mk``

       - This module's source file and makefile are contained within the
         *crash-<version>.src.rpm* and *crash-<version>.tar.gz* files, and the compiled
         module is included in the *crash-extensions-<version>.rpm* subpackage when
         *crash-<version>.src.rpm* is used to build the crash package.

       - Author: Dave Anderson <anderson@redhat.com>

   * - ``eppic.c`` ``eppic.mk``
     - ``load`` ``unload`` ``edit`` ``sclass`` ``sdebug`` ``sname``
     - - This module is a prerequisite for the loading of EPPIC (Embeddable
         Pre-Processor and Interpreter for C) scripts.
       - To build the module from the top-level *crash-<version>* directory, enter:
         ``$ make extensions``
       - Upon installing the ``eppic.so`` object file with ``extend``, any EPPIC
         scripts located in the */usr/share/eppic/crash* or *$HOME/.eppic* directories
         will be loaded automatically.
       - This module's source files are downloaded automatically from their git tree
         located at
         `https://github.com/lucchouina/eppic <https://github.com/lucchouina/eppic>`__,
         and the compiled extension module is included in the
         *crash-extensions-<version>.rpm* subpackage when *crash-<version>.src.rpm* is
         used to build the crash package.
       - Author: Luc Chouinard <lucchouina@gmail.com>

   * - ``dminfo.c``
     - ``dminfo``
     - - Device Mapper information.
       - To build the module from the top-level *crash-<version>* directory, enter:
         ``$ make extensions``
       - This module's source file is contained within the *crash-<version>.src.rpm*
         and *crash-<version>.tar.gz* files, and the compiled module is included in the
         *crash-extensions-<version>.rpm* subpackage when *crash-<version>.src.rpm* is
         used to build the crash package.
       - Author: NEC Japan

   * - ``crash-trace``
     - ``trace``
     - - Displays kernel tracing data and traced events that occurred prior to a panic.
       - To build the module from the top-level *crash-<version>* directory, enter:
         ``$ tar xzf crash-trace-command-<version>.tar.gz``
         ``$ mv crash-trace-command-<version>/trace.c extensions``
         ``$ make extensions``
       - Package website:
         `https://github.com/fujitsu/crash-trace <https://github.com/fujitsu/crash-trace>`__
       - Author: Lai Jiangshan <laijs@cn.fujitsu.com>
       - Maintainer: Daisuke Hatayama <d.hatayama@fujitsu.com>
       - NOTE: This module moved from extensions/trace.c in the crash repository to the
         separate crash-trace repository above.

   * - ``crash-gcore``
     - ``gcore``
     - - Create a core dump file of a user-space task that was running in a kernel
         dumpfile. The module supports the X86, X86_64, ARM, ARM64, MIPS and PPC64
         architectures.
       - If */usr/include/crash/defs.h* exists, the module may be built like so:
         ``$ tar xzf crash-gcore-command-<version>.tar.gz``
         ``$ cd crash-gcore-command-<version>`` ``$ make -f gcore.mk``
       - Alternatively, ``defs.h`` may be copied to the current directory:
         ``$ tar xzf crash-gcore-command-<version>.tar.gz``
         ``$ cd crash-gcore-command-<version>`` ``$ cp <path-to>/defs.h .``
         ``$ make -f gcore.mk``
       - To build the module from the top-level *crash-<version>* directory, enter:
         ``$ tar xzf crash-gcore-command-<version>.tar.gz``
         ``$ mv crash-gcore-command-<version>/* extensions`` ``$ make extensions``
       - This module's source files are self-contained in
         ``crash-gcore-command-<version>.tar.gz``.
       - `Changelog <https://crash-utility.github.io/extensions/gcore.changelog.html>`__
       - Package website:
         `https://github.com/fujitsu/crash-gcore <https://github.com/fujitsu/crash-gcore>`__
       - Author: Daisuke Hatayama <d.hatayama@fujitsu.com>

   * - ``spu.c``
     - ``spuctx`` ``spus`` ``spurq``
     - - Commands for viewing Cell/B.E. SPU's data
       - Requires kernel version >= 2.6.23-rc1
       - To build it, copy ``spu.c`` to the *crash-<version>/extensions* subdirectory,
         and from the top-level *crash-<version>* directory, enter:
         ``$ make extensions``
       - Prior to installing it, it is necessary to load the debuginfo symbols of the
         ``spufs`` kernel module: ``crash> mod -s spufs``
       - This module is part of IBM Software Development Kit (SDK) for Multicore
         Acceleration since Version 3.0.
       - Author: Lucio Correia <luciojhc@br.ibm.com>

   * - ``pykdump``
     - ``epython`` ``crashinfo`` ``xportshow``
     - - Execute Python scripts in crash environment
       - Gather basic data
       - View networking information
       - See `Project page <http://sourceforge.net/projects/pykdump>`__ for more
         details
       - Author: Alex Sidorenko <asid@hp.com>

   * - ``qemu-vtop.c``
     - ``qemu-vtop``
     - - Translate a KVM guest physical address into the virtual and physical addresses
         of its KVM host.
       - To build the module from the top-level *crash-<version>* directory, enter:
         ``$ cp <path-to>/qemu-vtop.c extensions`` ``$ make extensions``
       - Prior to executing the command, it is necessary to load the debuginfo symbols
         of the ``kvm`` kernel module: ``crash> mod -s kvm``
       - Author: Qiao Nuohan <qiaonuohan@cn.fujitsu.com>

   * - ``ipcs.c``
     - ``ipcs``
     - - Provide information about the System V IPCS facilities.
       - An updated version of this command was built into crash version 6.0.7.
       - To build the module from the top-level *crash-<version>* directory, enter:
         ``$ cp <path-to>/ipcs.c extensions`` ``$ make extensions``
       - Author: Qiao Nuohan <qiaonuohan@cn.fujitsu.com>

   * - ``pstruct.c``
     - ``pstruct``
     - - Print structure member data in a single line.
       - Requires crash utility version >= 6.0.7.
       - To build the module from the top-level *crash-<version>* directory, enter:
         ``$ cp <path-to>/pstruct.c extensions`` ``$ make extensions``
       - Author: Qiao Nuohan <qiaonuohan@cn.fujitsu.com>

   * - ``lscgroup.c``
     - ``lscgroup``
     - - Display active cgroups
       - To build the module from the top-level *crash-<version>* directory, enter:
         ``$ cp <path-to>/lscgroup.c extensions`` ``$ make extensions``
       - Author: Yongming Yu <yuym.fnst@cn.fujitsu.com>

   * - ``cgget.c``
     - ``cgget``
     - - Display cgroup parameters
       - To build the module from the top-level *crash-<version>* directory, enter:
         ``$ cp <path-to>/cgget.c extensions`` ``$ make extensions``
       - Author: Zhang Xiaohe <zhangxh@cn.fujitsu.com>

   * - ``swap_usage.c``
     - ``pswap``
     - - Display the swap consumption of a user process
       - To build the module from the top-level *crash-<version>* directory, enter:
         ``$ cp <path-to>/swap_usage.c extensions`` ``$ make extensions``
       - Author: Aaron Tomlin <atomlin@redhat.com>

   * - ``memutils.c``
     - ``memutils``
     - - Displays memory information
       - To build the module from the top-level *crash-<version>* directory, enter:
         ``$ cp <path-to>/memutils.c extensions`` ``$ make extensions``
       - Author: Vinayak Menon <vinayakm.list@gmail.com>

   * - ``ksm.c``
     - ``ksm``
     - - Display kernel samepage merging (KSM) information
       - To build the module from the top-level *crash-<version>* directory, enter:
         ``$ cp <path-to>/ksm.c extensions`` ``$ make extensions``
       - Author: Zhang Yanfei <zhangyanfei@cn.fujitsu.com>
       - Maintainer: Qiao Nuohan <qiaonuohan@cn.fujitsu.com>

   * - ``sockq.c``
     - ``sockq``
     - - Retrieve socket receive queue into a file
       - To build the module from the top-level *crash-<version>* directory, enter:
         ``$ cp <path-to>/sockq.c extensions`` ``$ make extensions``
       - Author: Qiao Nuohan <qiaonuohan@cn.fujitsu.com>

   * - ``fp.c`` ``fp.mk``
     - ``fp``
     - - Obtain function parameters from stack frames (x86_64 only)
       - To build the module from the top-level *crash-<version>* directory, enter:
         ``$ wget https://raw.github.com/hziSot/crash-stack-parser/master/crash-parse-stack-7.0.1-ext.patch``
         ``$ patch -p1 < crash-parse-stack-7.0.1-ext.patch`` ``$ make extensions``
       - Author: Alexandr Terekhov <Alexandr_Terekhov@epam.com>

   * - ``vz.c``
     - ``vzlist`` ``vzps`` ``ctid``
     - - OpenVZ specific commands
       - To build the module from the top-level *crash-<version>* directory, enter:
         ``$ cp <path-to>/vz.c extensions`` ``$ make extensions``

   * - ``ptdump-1.0.7.tar.gz``
     - ``ptdump``
     - - Retrieve and decode the log buffer generated by the Intel Processor Trace
         facility
       - To build the module from the top-level *crash-<version>* directory, enter:
         ``$ tar xvf ptdump-1.0.7.tar.gz`` ``$ mv ptdump-1.0.7/* extensions``
         ``$ make extensions``

   * - ``proccgroup.c``
     - ``showcg``
     - - Show which cgroups a process is a member of
       - To build the module from the top-level *crash-<version>* directory, enter:
         ``$ cp <path-to>/proccgroup.c extensions`` ``$ make extensions``

   * - ``cacheutils.c``
     - ``ccat`` ``cls`` ``cfind``
     - - Page cache utilities
       - To build the module from the top-level *crash-<version>* directory, enter:
         ``$ cp <path-to>/cacheutils.c extensions`` ``$ make extensions``
       - Package website:
         `https://github.com/k-hagio/crash-cacheutils <https://github.com/k-hagio/crash-cacheutils>`__

   * - ``page_owner.c``
     - ``owner``
     - - Display
         `page owner <https://www.kernel.org/doc/html/latest/mm/page_owner.html>`__
         information
       - To build the module from the top-level *crash-<version>* directory, enter:
         ``$ cp <path-to>/page_owner.c extensions`` ``$ make extensions``
       - Package website:
         `https://github.com/k-hagio/crash-pageowner <https://github.com/k-hagio/crash-pageowner>`__
       - As of April 2024, tested/supported only on RHEL8/RHEL9 and not sure which
         upstream kernel is supported. For the latest information, see the package
         website above.

   * - ``scsi.c``
     - ``sdinfo``
     - - Displays Linux kernel's SCSI disk information, including devices, hosts,
         targets, and associated I/O requests and SCSI commands. Support for NVMe
         devices is currently under development and will be added in upcoming releases.
       - To build the module from the top-level *crash-<version>* directory, enter:
         ``$ cp <path-to>/scsi.c scsi.mk extensions`` ``$ make extensions``
       - Package website:
         `https://github.com/briston-dev/crash-diskutils <https://github.com/briston-dev/crash-diskutils>`__
       - Tested in rhel8, not work for kernel>=v6.4. For the latest information, see
         the package website above.

   * - ``crash-plugins``
     - 
     - - This extension provides a comprehensive collection of crash-utility plugins
         for analyzing Linux kernel crash dumps, covering both kernel space and user
         space debugging. These plugins significantly enhance debugging efficiency.
       - Package website:
         `https://github.com/quic/crash-plugins <https://github.com/quic/crash-plugins>`__
       - Commands: This module includes over 40 commands, covering a diverse range of
         functionalities: 1.Memory Management:
         ``slub, buddy, cma, memblock, vmalloc, reserved, zram, swap, dmabuf, pageowner, pagecache, meminfo``
         2.Process & Scheduling: ``procrank, sched, binder`` 3.Device & Drivers:
         ``dd, dts, regulator, icc, ccf, thermal, cpu, watchdog`` 4.Debugging &
         Logging: ``rtb, pstore, qlog, ipc, dbi(uwind stack), ftrace, systemd``
         5.Utilities: ``workqueue, coredump, env, t32, lockdep, iommu`` 6.Android
         Userspace: ``property, logcat, surfaceflinger``
       - Supported architectures: ARM64, ARM32 Tested kernel versions: 5.4 to 6.6
         Android versions: 11 (API 30) to 14 (API 34) For the latest information, see
         the package website above.

crash EPPIC scripts
-------------------

EPPIC scripts require no compilation, but they do require that the eppic.so
extension module be pre-loaded with ``extend``, because eppic.so provides the
``load`` command required to load EPPIC scripts. To add the module to a
running crash session, enter:

``crash> extend <path-to>/eppic.so``

The module can be installed automatically if the ``extend`` command above is
entered in either *./.crashrc* or *$HOME/.crashrc*.

EPPIC scripts may be located anywhere. However, upon loading the eppic.so
module, EPPIC scripts located in the */usr/share/eppic/crash* or
*$HOME/.eppic* directories will be loaded automatically. The command(s)
contained in loaded EPPIC script(s) will appear in the crash
`help <https://crash-utility.github.io/extensions/help_help.html>`__ menu.

The EPPIC `README <https://github.com/lucchouina/eppic/wiki>`__ and
`README.code <https://github.com/lucchouina/eppic/blob/master/applications/crash/README.code>`__
files contain information regarding the format of eppic scripts.

The EPPIC sources contain a sample ``ipcs2`` command, similar in nature to the
built-in ``ipcs`` command. The ``ipcs2`` script files will be located in the
*extensions/eppic/applications/crash/code* directory, and the directory's
contents should be copied to either */usr/share/eppic/crash* or
*$HOME/.eppic*. For example:

``$ make extensions ... $ cp -r extensions/eppic/applications/crash/code/* /usr/share/eppic/crash``

Having done the above, upon loading the eppic.so module, the ``ipcs2`` EPPIC
command will be automatically loaded.

The EPPIC package website is here:

`https://github.com/lucchouina/eppic <https://github.com/lucchouina/eppic>`__

Author: Luc Chouinard <lucchouina@gmail.com>

crashdc: Crash Dump Data Collector
----------------------------------

The crashdc data collector is a script that can be used in conjunction with
the crash utility to automatically generate a text file containing major
information about a newly generated crash dump. The package website is here:

`http://crashdc.sourceforge.net <http://crashdc.sourceforge.net>`__

Author: Louis Bouchard <louis.bouchard@canonical.com>

Python scripts
--------------

Author: Alexey Dobriyan <adobriyan@gmail.com>

This an example of how to run crash utility commands from a Python script:

::

   #!/usr/bin/python2
   import hashlib
   import os
   import subprocess
   import tempfile

   # create "vmlinux" and "core" symlinks before running
   #CRASH='/usr/bin/crash'
   CRASH=os.path.join(os.path.expanduser('~'), 'bin', 'crash')

   # split() without empty strings
   def xsplit(s, c):
       i = 0
       while True:
           j = s.find(c, i)
           if j == -1:
               if i == len(s):
                   return
               yield s[i:]
               return
           elif i == j:
               i = i + 1
               continue
           else:
               yield s[i:j]
               i = j + 1

   _CRASH_CACHE_DIR='.crash'
   def crash(cmd):
       idx = cmd.find('\n')
       if idx >= 0:
           print 'CRASH "%s" ...' % cmd[:idx]
       else:
           print 'CRASH "%s"' % cmd

       try:
           os.mkdir(_CRASH_CACHE_DIR)
       except OSError:
           pass

       cache_filename = os.path.join(_CRASH_CACHE_DIR, hashlib.sha1(cmd).hexdigest())
       if os.path.isfile(cache_filename):
           with open(cache_filename, 'r') as f:
               return f.read()

       fd, filename = tempfile.mkstemp()
       f = os.fdopen(fd, 'w')
       f.write(cmd)
       if cmd[-1] != '\n':
           f.write('\n')
       f.write('q\n')
       f.close()

       with open(filename, 'r') as f:
           x = subprocess.check_output([CRASH, '-s', 'vmlinux', 'core'], stdin=f)
       os.unlink(filename)

       with open(cache_filename, 'w+') as f:
           f.write(x)
       return x

   def make_cmd(fmt, it):
       return '\n'.join(map(lambda x: fmt % x, it))

   #def struct_inode():
   #    cmd = 'list -H super_blocks super_block.s_list'
   #    x = crash(cmd)
   #    list_sb = map(lambda x: int(x, 16), xsplit(x, '\n'))
   #
   #    cmd = 'struct super_block.s_inodes'
   #    x = crash(cmd)
   #    s = [line for line in xsplit(x, '\n')]
   #    OFFSETOF_STRUCT_INODE_S_INODES = int(s[1].split()[0][1:-1])
   #
   ##    set_inode = set()
   ##    for sb in list_sb:
   ##        cmd = 'list -H %x inode.i_sb_list' % (sb + OFFSETOF_STRUCT_INODE_S_INODES)
   ##        x = crash(cmd)
   ##        set_inode.update(map(lambda x: int(x, 16), xsplit(x, '\n')))
   ##    print len(set_inode)
   #
   #    set_inode = set()
   #    cmd = make_cmd('list -H %x inode.i_sb_list', map(lambda x: x + OFFSETOF_STRUCT_INODE_S_INODES, list_sb))
   #    x = crash(cmd)
   #    set_inode = set(map(lambda x: int(x, 16), xsplit(x, '\n')))
   #    print len(set_inode)
   #
   #struct_inode()

Pykdump scripts
---------------

Pykdump scripts require no Python installed, but they do require the
`mpykdump.so <http://sourceforge.net/projects/pykdump>`__ extension module
pre-loaded with ``extend``. mpykdump.so provides built-in Python interpreter
and needed pure Python libraries as well as Python bindings to crash. Loading
the extension registers 'epython' command which can be used to execute Python
programs.

To minimize the extension size, only parts of Python standard library are
included in the extension file. If you need anything extra (e.g. XML/RPC)
please contact the author.

The mpykdump.so extension file is a shared library with ZIP-archive appended
at the end of it. You can use standard ZIP command to view the contents of it
and add your own Python programs. In addition to generic *epython* command,
two useful programs are included in the extension (see Wiki documentation on
SF site for more details).

The package website is here:

`http://pykdump.sourceforge.net <http://pykdump.sourceforge.net>`__

Author: Alex Sidorenko <asid@hp.com>

.. list-table::
   :widths: 25 75

   * - ``crashinfo``
     - - Print a brief summary of the dump running some tests
       - Using additional options, do other things (Swiss Army Knife approach - instead
         of many separate programs, use one with many options)
       - Author: Alex Sidorenko <asid@hp.com>

   * - ``xportshow``
     - - Print networking connections, routing tables etc. - similar to *netstat*
       - Author: Alex Sidorenko <asid@hp.com>

crash-extscript
---------------

***crash-extscript*** is an extension module command that can communicate with
external scripts.

At times it may be necessary to execute a series of crash commands to arrive
at a result. For example, the output of a crash command may be parsed for a
particular element, which is then used in a subsequent command, and so on.
There are cases when this may take several steps, and this utility can be used
to automate those steps. Another use can be to execute a series of pre-defined
crash commands, parse the output to get relevant information, and generate a
bug report.

These are the components in contained in this package:

1. A crash utility extension module called *extscript.so* that provides a crash
   command called *extscript*.
2. A example perl script called *perlfc.pl*, which can talk to the *extscript*
   extension module command. This script can be used as an example to write
   similar utilities that can talk to *extscript*.
3. A protocol definition for communication between *extscript* and the external
   script.

The external script is not executed as-is, but rather it is invoked by running
the *extscript* command from the crash prompt. The external script is
essentially run as a "server" by the crash utility when the *extscript*
command is issued; the external script serves the crash utility by issuing
crash commands.

To build the extension module from the top-level *crash-<version>* directory,
enter:

``$ cp extscript.c extensions`` ``$ make extensions`` ``$ cp perlfc.pl .``

Then from the crash prompt:

``crash> extend extensions/extscript.so``
``crash> extscript -f perl -a perl -a ./perlfc.pl``
``crash> extscript -b vmallocinfo``

The first command loads the *extscript.so* module, which adds the *extscript*
command to crash utility. The second command sets up the execution format
similar to how arguments are passed to *execlp()*, passing the executable
command's filename and the command arguments. The third command is the
"bypass" command, which executes the specified command that is encoded in the
*perlfc.pl* script. In this case *vmallocinfo* is one of the commands that is
defined in *perlfc.pl*; its output will be similar to */proc/vmallocinfo*,
displayed on crash console.

The *help* command shows all the commands supported by the script and its
usage:

``crash> extscript -b help``

The *perlfc.pl* script is an example of how to write quick automation scripts
to use the *extscript* extension of crash utility.

More details can be found in the
`README <https://github.com/vinayakmenon/crash-extscript/blob/master/README.md>`__
of the package

The package website is here:

`https://github.com/vinayakmenon/crash-extscript <https://github.com/vinayakmenon/crash-extscript>`__

Author: Vinayak Menon <vinayakm.list@gmail.com>
