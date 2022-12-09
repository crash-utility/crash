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

TARGET_FLAGS = -D$(TARGET)
ifeq ($(TARGET), PPC64)
	TARGET_FLAGS += -m64
endif
ifeq ($(TARGET), ARM)
	TARGET_FLAGS += -m32
endif
ifeq ($(TARGET), MIPS)
	TARGET_FLAGS += -m32
endif
ifeq ($(TARGET), X86)
	TARGET_FLAGS += -m32
endif

APPFILE=eppic/applications/crash/eppic.c
GIT := $(shell which git 2> /dev/null)
# crash 8 with gdb 10 uses new third party callback (tcb) API
EPPIC_BRANCH=v5.0

all:
	@if [ -f /usr/bin/flex ] && [ -f /usr/bin/bison ]; \
	then \
		if [ -f ../$(GDB)/crash.target ]; \
		then \
			if  [ ! -f $(APPFILE) ]; \
			then \
				if [ -f "$(GIT)" ]; \
				then \
					if [ -n "$(EPPIC_GIT_URL)" ]; \
					then \
						git clone $(EPPIC_GIT_OPTIONS) $(EPPIC_GIT_URL) eppic; \
					else \
						if ping -c 1 -W 5 github.com >/dev/null ; then \
							git clone -b $(EPPIC_BRANCH) $(EPPIC_GIT_OPTIONS) https://github.com/lucchouina/eppic.git eppic; \
						fi; \
					fi; \
				else \
					if [ ! -f "$(GIT)" ]; then \
						echo "eppic.so: git command is needed for pulling eppic extension code"; \
					fi; \
				fi; \
			fi; \
			if  [ -f $(APPFILE) ]; \
			then \
				make -f eppic.mk eppic.so; \
			else \
				echo "eppic.so: failed to pull eppic code from git repo"; \
			fi; \
		else \
			echo "eppic.so: build failed: requires the crash $(GDB) module"; \
		fi ;\
	else \
		echo "eppic.so: build failed: requires /usr/bin/flex and /usr/bin/bison"; \
	fi

lib-eppic: 
	cd eppic/libeppic && make

eppic.so: ../defs.h $(APPFILE) lib-eppic
	gcc -g -O0 -Ieppic/libeppic -I.. -nostartfiles -shared -rdynamic -o eppic.so $(APPFILE) -fPIC $(TARGET_FLAGS) $(GDB_FLAGS) -Leppic/libeppic -leppic

clean:
	if  [ -d eppic/libeppic ]; \
	then \
		cd eppic/libeppic && make -i clean; \
	fi
	rm -f eppic.so
