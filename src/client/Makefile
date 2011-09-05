# put common definitions in here
CC	  = gcc
CFLAGS    = -Wall # -DDEBUG -g
INC       = -I../lib # will be in other dirs
LD	  = ld
LDFLAGS   = 
LIBS      = -lpam -lcrypt
LIBDIR    = "../lib"
SIBYL   = 1
# .SILENT :


default: pam_sibyl

pam_sibyl:
	$(CC) $(CFLAGS) $(INC) -fPIC -c sibyl_support.c -o sibyl_support.o
	$(CC) $(CFLAGS) $(INC) -fPIC -c pam_sibyl.c -o pam_sibyl.o
	ld -x --shared -o pam_sibyl.so pam_sibyl.o sibyl_support.o $(LIBDIR)/bsd-base64.o $(LIBS)

debug:
	$(CC) $(CFLAGS) -DDEBUG -g $(INC) -fPIC -c sibyl_support.c -o sibyl_support.o
	$(CC) $(CFLAGS) -DDEBUG -g $(INC) -fPIC -c pam_sibyl.c -o pam_sibyl.o
	ld -x --shared -o pam_sibyl.so pam_sibyl.o sibyl_support.o $(LIBDIR)/bsd-base64.o $(LIBS)

clean:
	@find . \( -iname "*.o" -or -iname "*~" -or -iname "*.so" \) -exec rm -f '{}' \;
