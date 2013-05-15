# put common definitions in here
CC	  = gcc
CFLAGS    = -Wall -fno-stack-protector # -DDEBUG -g (Ubuntu stack...)
INC       = -I../lib # will be in other dirs
INC_OSX   = -I../lib -I/opt/local/include
LIBD_OSX  = -L/opt/local/lib -L../lib
LD	  = ld
LDFLAGS   = 
LIBS      = -lpam -lcrypto
LIBDIR    = "../lib"
SIBYL   = 1
# .SILENT :


default: pam_sibyl

libs:
	cd ../lib && $(MAKE) $(MFLAGS)

pam_sibyl: libs
	$(CC) $(CFLAGS) $(INC) -fPIC -c sibyl_support.c -o sibyl_support.o
	$(CC) $(CFLAGS) $(INC) -fPIC -c pam_sibyl.c -o pam_sibyl.o
	ld -x --shared -o pam_sibyl.so pam_sibyl.o sibyl_support.o $(LIBDIR)/bsd-base64.o $(LIBS)

debug: libs
	$(CC) $(CFLAGS) -DDEBUG -g $(INC) -fPIC -c sibyl_support.c -o sibyl_support.o
	$(CC) $(CFLAGS) -DDEBUG -g $(INC) -fPIC -c pam_sibyl.c -o pam_sibyl.o
	ld -x --shared -o pam_sibyl.so pam_sibyl.o sibyl_support.o $(LIBDIR)/bsd-base64.o $(LIBS)

pam_sibyl-osx: libs
	$(CC) $(CFLAGS) $(INC_OSX) -fPIC -c sibyl_support.c -o sibyl_support.o
	$(CC) $(CFLAGS) $(INC_OSX) -fPIC -c pam_sibyl.c -o pam_sibyl.o
	gcc -dynamiclib -o pam_sibyl.so pam_sibyl.o sibyl_support.o $(LIBD_OSX) $(LIBDIR)/bsd-base64.o $(LIBS)
#	ld -x -o pam_sibyl.so pam_sibyl.o sibyl_support.o $(LIBD_OSX) $(LIBDIR)/bsd-base64.o $(LIBS)

debug-osx: libs
	$(CC) $(CFLAGS) -DDEBUG -g $(INC_OSX) -fPIC -c sibyl_support.c -o sibyl_support.o
	$(CC) $(CFLAGS) -DDEBUG -g $(INC_OSX) -fPIC -c pam_sibyl.c -o pam_sibyl.o
	gcc -dynamiclib -o pam_sibyl.so pam_sibyl.o sibyl_support.o $(LIBD_OSX) $(LIBDIR)/bsd-base64.o $(LIBS)
#	ld -x -o pam_sibyl.so pam_sibyl.o sibyl_support.o $(LIBD_OSX) $(LIBDIR)/bsd-base64.o $(LIBS)



clean:
	@find . \( -iname "*.o" -or -iname "*~" -or -iname "*.so" \) -exec rm -f '{}' \;
