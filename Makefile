CROSS_COMPILE ?=
DESTDIR ?=

CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar

OBJS = dce.o \
       dce-fd-frc.o \
       dce-fd.o \
       dce-fcr.o \
       lib/fsl_mc_sys.o \
       lib/dprc.o \
       lib/dpio.o \
       lib/dpdcei.o \
       lib/vfio_utils.o \
       lib/allocator.o \
       lib/qbman_debug.o \
       lib/qbman_portal.o \
       lib/dpio_service.o \
       dce-scf-compression.o \
       dce-scf-decompression.o \
       dpdcei-drv.o \
       basic_dce.o

CFLAGS = -Iinclude \
	 -g3 \
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

all: basic_dce_test basic_dce_perf basic_dce_sanity

basic_dce_test: tests/basic_dce_test.o libdce.a
	$(CC) $(CFLAGS) $^ -o $@

basic_dce_perf: tests/basic_dce_perf.o libdce.a
	$(CC) $(CFLAGS) $^ -o $@

basic_dce_sanity: tests/basic_dce_sanity.o libdce.a
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
	      basic_dce_test basic_dce_perf basic_dce_sanity \
	      tests/*.o

%.d: %.c
	@($(CC) $(CFLAGS) -M $< | \
	  sed 's,\($(notdir $*)\.o\) *:,$(dir $@)\1 $@: ,' > $@.tmp); \
	 mv $@.tmp $@

-include $(HEADER_DEPENDENCIES)



