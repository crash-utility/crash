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
ifneq ($(KERNELRELEASE),)
obj-m := crash.o
else
PWD := $(shell pwd)
KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/${KVER}/build
all:
	${MAKE} -C ${KDIR} M=${PWD} SUBDIRS=${PWD} modules
clean:
	test -e ${KDIR}/Makefile && ${MAKE} -C ${KDIR} M=${PWD} SUBDIRS=${PWD} clean || ${RM} *.mod.c *.ko *.o Module.*
endif
