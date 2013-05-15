# put common definitions in here
CC	  = gcc
CFLAGS    = -Wall -fno-stack-protector # -DDEBUG -g (ubuntu stack...)
INC       = -I../lib # will be in other dirs
LDFLAGS   = 
LIBS      = -lpam -lcrypt
LIBDIR    = "../lib"
SIBYL   = 1
# .SILENT :default: libs

libs: bsd-base64.o
	$(CC) $(CFLAGS) -fPIC -c bsd-base64.c -o bsd-base64.o

debug:
	$(CC) $(CFLAGS) -g -DDEBUG -fPIC -c bsd-base64.c -o bsd-base64.o

clean:
	@find . \( -iname "*.o" -or -iname "*~" -or -iname "sibyl_srv" \) -exec rm -f '{}' \;

