ifndef SIBYL
include ../Makefile.inc
endif

default: libs

libs: bsd-base64.o
	$(CC) $(CFLAGS) $(DEBUG) -fPIC -c bsd-base64.c -o bsd-base64.o

clean:
	@find . \( -iname "*.o" -or -iname "*~" -or -iname "sibyl_srv" \) -exec rm -f '{}' \;

