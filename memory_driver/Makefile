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
obj-m := crash.o
all:
	make -C /lib/modules/`uname -r`/build M=${PWD} SUBDIRS=${PWD} modules
clean:
	rm -f *.mod.c *.ko *.o Module.*
