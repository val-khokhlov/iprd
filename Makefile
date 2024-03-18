CFILES=iprd.c checksum.c
BINFILE=iprd
WITH_PERL=1
WITH_PERL56=1
#STATIC=1

.ifdef WITH_PERL
CFILES+=perlhook.c
LDFLAGS_PERL!=perl -MExtUtils::Embed -e ldopts
CCFLAGS_PERL!=perl -MExtUtils::Embed -e ccopts
CCFLAGS+=$(CCFLAGS_PERL)
LDFLAGS+=$(LDFLAGS_PERL)
CDEFS+=-DWITH_PERL
.endif

.ifdef WITH_PERL56
CDEFS+=-DWITH_PERL56
.endif

.ifdef STATIC
LDFLAGS+=-static
.endif

all:	$(CFILES)
	gcc $(CDEFS) -o $(BINFILE) $(CFILES) $(CCFLAGS) $(LDFLAGS)

clean:
	rm *.o $(BINFILE)