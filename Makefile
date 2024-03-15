CFILES=iprd.c checksum.c
BINFILE=iprd
WITH_PERL=1
#WITH_PERL56=1
#STATIC=1

.ifdef WITH_PERL
CFILES+=perlhook.c
LDFLAGS+=-Wl,-R/usr/lib -Wl,-E -lperl -lm  /usr/libdata/perl/5.00503/mach/auto/DynaLoader/DynaLoader.a -L/usr/libdata/perl/5.00503/mach/CORE -lperl -lm -lc -lcrypt -lperl -lm
CCFLAGS+=-I/usr/libdata/perl/5.00503/mach/CORE 
CDEFS+=-DWITH_PERL
.endif

.ifdef STATIC
LDFLAGS+=-static
.endif

all:	$(CFILES)
	gcc $(CDEFS) -o $(BINFILE) $(CFILES) $(CCFLAGS) $(LDFLAGS)

clean:
	rm *.o $(BINFILE)