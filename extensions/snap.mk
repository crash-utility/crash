#
# Copyright (C) 2009, 2011, 2013 David Anderson
# Copyright (C) 2009, 2011, 2013 Red Hat, Inc. All rights reserved.
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

ifeq ($(shell arch), i686)
  TARGET=X86
  TARGET_CFLAGS=-D_FILE_OFFSET_BITS=64
endif
ifeq ($(shell arch), ppc64)
  TARGET=PPC64
  TARGET_CFLAGS=-m64
endif
ifeq ($(shell arch), ppc64le)
  TARGET=PPC64
  TARGET_CFLAGS=-m64
endif
ifeq ($(shell arch), ia64)
  TARGET=IA64
  TARGET_CFLAGS=
endif
ifeq ($(shell arch), x86_64)
  TARGET=X86_64
  TARGET_CFLAGS=
endif

ifeq ($(shell /bin/ls /usr/include/crash/defs.h 2>/dev/null), /usr/include/crash/defs.h)
  INCDIR=/usr/include/crash
endif
ifeq ($(shell /bin/ls ../defs.h 2> /dev/null), ../defs.h)
  INCDIR=..
endif
ifeq ($(shell /bin/ls ./defs.h 2> /dev/null), ./defs.h)
  INCDIR=.
endif

all: snap.so
	
snap.so: $(INCDIR)/defs.h snap.c 
	gcc -Wall -g -I$(INCDIR) -shared -rdynamic -o snap.so snap.c -fPIC -D$(TARGET) $(TARGET_CFLAGS) $(GDB_FLAGS)
