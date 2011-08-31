ifndef SIBYL
include ../Makefile.inc
endif
LIBDIR = "../lib"

default: pam_sibyl-osx

pam_sibyl-osx: INC    += -I/Developer/SDKs/MacOSX10.6.sdk/usr/include/
pam_sibyl-osx: LIBS   += -lcrypto
pam_sibyl-osx:
	$(CC) $(CFLAGS) $(DEBUG) $(INC) -fPIC -c sibyl_support.c -o sibyl_support.o
	$(CC) $(CFLAGS) $(DEBUG) $(INC) -fPIC -c pam_sibyl.c -o pam_sibyl.o
	gcc -dynamiclib -o pam_sibyl.so pam_sibyl.o sibyl_support.o $(LIBDIR)/bsd-base64.o $(LIBS)

pam_sibyl-linux:
	@echo libs is $(LIBS)
	$(CC) $(INC) -fPIC -c sibyl_support.c -o sibyl_support.o
	$(CC) $(INC) -fPIC -c pam_sibyl.c -o pam_sibyl.o
	ld -x --shared -o pam_sibyl.so pam_sibyl.o sibyl_support.o $(LIBDIR)/bsd-base64.o $(LIBS)

pam_exec:
	@echo generando pam_exec
	$(CC) $(INC) -g pam_exec.c -o pam $(LIBDIR)/bsd-base64.o $(LIBS)

clean:
	@find . \( -iname "*.o" -or -iname "*~" -or -iname "sibyl_srv" \) -exec rm -f '{}' \;
