LUASRC = $(wildcard src/lua/*.lua)
LUAOBJ = $(LUASRC:.lua=.o)
CSRC   = $(wildcard src/c/*.c)
COBJ   = $(CSRC:.c=.o)
PREFIX = /usr/local

LUAJIT_CFLAGS := -include $(CURDIR)/gcc-preinclude.h -lpthread

all: $(LUAJIT) $(SYSCALL) $(PFLUA)
#       LuaJIT
	@(cd lib/luajit && \
	 $(MAKE) PREFIX=`pwd`/usr/local \
	         CFLAGS="$(LUAJIT_CFLAGS)" && \
	 $(MAKE) DESTDIR=`pwd` install)
	(cd lib/luajit/usr/local/bin; ln -fs luajit-2.1.0-beta3 luajit)
#       effil
	@(if [ ! -d lib/effil/build ]; then \
		mkdir -p lib/effil/build && \
		cd lib/effil/build && \
		cmake -D LUA_INCLUDE_DIR=$(CURDIR)/lib/luajit/usr/local/include/luajit-2.1 .. ; \
	fi)
	@(cd lib/effil/build && $(MAKE))
	@cp -p lib/effil/build/libeffil.so $(CURDIR)/lib/luajit/usr/local/lib/lua/5.1
	@cp -p lib/effil/src/lua/effil.lua src/
#       ljsyscall
	@mkdir -p src/syscall/linux
	@cp -p lib/ljsyscall/syscall.lua   src/
	@cp -p lib/ljsyscall/syscall/*.lua src/syscall/
	@cp -p  lib/ljsyscall/syscall/linux/*.lua src/syscall/linux/
	@cp -pr lib/ljsyscall/syscall/linux/x64   src/syscall/linux/
	@cp -pr lib/ljsyscall/syscall/shared      src/syscall/
#       ljndpi
	@mkdir -p src/ndpi
	@cp -p lib/ljndpi/ndpi.lua src/
	@cp -p lib/ljndpi/ndpi/*.lua src/ndpi/
	cd src && $(MAKE)

install: all
	install -D src/snabb ${DESTDIR}${PREFIX}/bin/snabb

clean:
	(cd lib/luajit && $(MAKE) clean)
	(rm -rf lib/effil/build)
	(cd src; $(MAKE) clean; rm -rf syscall.lua syscall effil.lua libeffil.so)

PACKAGE:=snabbswitch
DIST_BINARY:=snabb
BUILDDIR:=$(shell pwd)

dist: DISTDIR:=$(BUILDDIR)/$(PACKAGE)-$(shell git describe --tags)
dist: all
	mkdir "$(DISTDIR)"
	git clone "$(BUILDDIR)" "$(DISTDIR)/snabbswitch"
	rm -rf "$(DISTDIR)/snabbswitch/.git"
	cp "$(BUILDDIR)/src/snabb" "$(DISTDIR)/"
	if test "$(DIST_BINARY)" != "snabb"; then ln -s "snabb" "$(DISTDIR)/$(DIST_BINARY)"; fi
	cd "$(DISTDIR)/.." && tar cJvf "`basename '$(DISTDIR)'`.tar.xz" "`basename '$(DISTDIR)'`"
	rm -rf "$(DISTDIR)"

.SERIAL: all
