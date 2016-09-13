CROSS_COMPILE ?=
DESTDIR ?=

CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar

OBJS = dce.o \
       dce-fd-frc.o \
       dce-scf-compression.o \
       dce-scf-decompression.o \
       dpdcei-drv.o \
       dce-userspace.o

CFLAGS = -Iinclude \
	 -pthread \
	 ${EXTRA_CFLAGS} \
	 -Wall \
	 -Wextra -Wformat \
	 -std=gnu99 \
	 -Wmissing-prototypes \
	 -Wpointer-arith \
	 -Winline \
	 -Wundef \
	 -fmax-errors=1 \
	 -Wstrict-prototypes
	 #-Werror

LDFLAGS = -static -Wl,--hash-style=gnu ${EXTRA_CFLAGS}

PREFIX = $(DESTDIR)/sbin
EXEC_PREFIX = $(DESTDIR)/usr/sbin

HEADER_DEPENDENCIES = $(subst .o,.d,$(OBJS))

all: dce_test

dce_test: tests/dce_test.o libdce.a
	$(CC) $(CFLAGS) $^ -o $@

libdce.a: $(OBJS)
	$(AR) rcs $@ $(OBJS)

install:
	install -d $(PREFIX) $(EXEC_PREFIX)
	install -m 755 restool $(PREFIX)
	cp -d scripts/* $(EXEC_PREFIX)
	chmod 755 $(EXEC_PREFIX)/ls-main

clean:
	rm -f $(OBJS) \
	      $(HEADER_DEPENDENCIES) \
	      dce_test

%.d: %.c
	@($(CC) $(CFLAGS) -M $< | \
	  sed 's,\($(notdir $*)\.o\) *:,$(dir $@)\1 $@: ,' > $@.tmp); \
	 mv $@.tmp $@

-include $(HEADER_DEPENDENCIES)



