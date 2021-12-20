#
# Makefile for building crash shared object extensions
#
# Copyright (C) 2005, 2007, 2009, 2011, 2013 David Anderson
# Copyright (C) 2005, 2007, 2009, 2011, 2013 Red Hat, Inc. All rights reserved.
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
# To build the extension shared objects in this directory, run 
# "make extensions" from the top-level directory.
#
# To add a new extension object, simply copy your module's .c file
# to this directory, and it will be built automatically using
# the "standard" compile line.  If that compile line does not 
# suffice, create a .mk file with the same prefix as the .c file,
# and that makefile will be invoked. 
# 

CONTRIB_SO := $(patsubst %.c,%.so,$(wildcard *.c))

all: link_defs $(CONTRIB_SO)
	
link_defs:
	@rm -f defs.h
	@ln ../defs.h 

$(CONTRIB_SO): %.so: %.c defs.h
	@if [ -f $*.mk ]; then \
		$(MAKE) -f $*.mk; \
	else \
		grep '((constructor))' $*.c > .constructor; \
		if [ -s .constructor ]; then \
			echo "gcc -Wall -g -shared -rdynamic -o $@ $*.c -fPIC -D$(TARGET) $(TARGET_CFLAGS) $(GDB_FLAGS)"; \
			gcc -Wall -g -shared -rdynamic -o $@ $*.c -fPIC -D$(TARGET) $(TARGET_CFLAGS) $(GDB_FLAGS); \
		fi; \
		if [ ! -s .constructor ]; then \
			echo "gcc -Wall -g -nostartfiles -shared -rdynamic -o $@ $*.c -fPIC -D$(TARGET) $(TARGET_CFLAGS) $(GDB_FLAGS)"; \
			gcc -Wall -g -nostartfiles -shared -rdynamic -o $@ $*.c -fPIC -D$(TARGET) $(TARGET_CFLAGS) $(GDB_FLAGS); \
		fi; \
		rm -f .constructor; \
	fi

clean:
	rm -f $(CONTRIB_SO)
	@for MAKEFILE in `grep -sl "^clean:" *.mk`; \
	  do $(MAKE) -f $$MAKEFILE clean; \
	done
