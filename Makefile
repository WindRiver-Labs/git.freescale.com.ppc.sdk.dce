CROSS_COMPILE ?=
DESTDIR ?=

CC = $(CROSS_COMPILE)gcc

OBJS = restool.o \
       dprc_commands.o \
       dpio_commands.o \
       dpbp_commands.o \
       dpdcei_commands.o \
       dprc.o \
       dpmng.o \
       dpbp.o \
       dpio.o \
       dpdcei.o \
       fsl_mc_sys.o \
       dce.o \
       dce-fd-frc.o \
       dce-scf-compression.o \
       dce-scf-decompression.o \
       #dpdcei-drv.o

CFLAGS = ${EXTRA_CFLAGS} \
	  -Iinclude \
	  -Wall \
          -Wstrict-prototypes \
          -Wextra -Wformat \
          -std=gnu99 \
          -Wmissing-prototypes \
          -Wpointer-arith \
          -Winline \
          -Werror \
          -Wundef \
	  -fmax-errors=10

LDFLAGS = -static -Wl,--hash-style=gnu ${EXTRA_CFLAGS}

PREFIX = $(DESTDIR)/sbin
EXEC_PREFIX = $(DESTDIR)/usr/sbin

HEADER_DEPENDENCIES = $(subst .o,.d,$(OBJS))

all: libdce.a

libdce.a: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) -lm
	file $@

install:
	install -d $(PREFIX) $(EXEC_PREFIX)
	install -m 755 restool $(PREFIX)
	cp -d scripts/* $(EXEC_PREFIX)
	chmod 755 $(EXEC_PREFIX)/ls-main

clean:
	rm -f $(OBJS) \
	      $(HEADER_DEPENDENCIES) \
	      restool

%.d: %.c
	@($(CC) $(CFLAGS) -M $< | \
	  sed 's,\($(notdir $*)\.o\) *:,$(dir $@)\1 $@: ,' > $@.tmp); \
	 mv $@.tmp $@

-include $(HEADER_DEPENDENCIES)



