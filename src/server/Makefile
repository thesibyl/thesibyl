# put common definitions in here
CC	  = gcc
CFLAGS    = -Wall  -DDEBUG -g 
INC       = -I../lib # will be in other dirs
INC_OSX   = -I../lib -I/opt/local/include
LIBD_OSX  = -L/opt/local/lib -L../lib
LD	  = ld
LDFLAGS   = 
LIBS      = -lcrypto
LIBDIR    = "../lib"
SIBYL   = 1
# .SILENT :

default: srv

libs:
	cd ../lib && $(MAKE) $(MFLAGS)

srv: libs
	$(CC) $(CFLAGS) $(INC) -fPIC -c sibyl_srv_support.c -o sibyl_srv_support.o 
	$(CC) $(CFLAGS) $(INC) sibyl_srv.c -o sibyl_srv sibyl_srv_support.o $(LIBDIR)/bsd-base64.o $(LIBS)

debug: libs
	$(CC) $(CFLAGS) -DDEBUG -g $(INC) -fPIC -c sibyl_srv_support.c -o sibyl_srv_support.o
	$(CC) $(CFLAGS) -DDEBUG -g $(INC) sibyl_srv.c -o sibyl_srv sibyl_srv_support.o $(LIBDIR)/bsd-base64.o $(LIBS)

clean:
	@find . \( -iname "*.o" -or -iname "*~" -or -iname "sibyl_srv" \) -exec rm -f '{}' \;

srv-osx: libs
	$(CC) $(CFLAGS) $(INC_OSX) -fPIC -c sibyl_srv_support.c -o sibyl_srv_support.o
	$(CC) $(CFLAGS) $(INC_OSX) sibyl_srv.c -o sibyl_srv sibyl_srv_support.o $(LIBDIR)/bsd-base64.o $(LIBD_OSX) $(LIBS)

debug-osx: libs
	$(CC) $(CFLAGS) -DDEBUG -g $(INC_OSX) -fPIC -c sibyl_srv_support.c -o sibyl_srv_support.o
	$(CC) $(CFLAGS) -DDEBUG -g $(INC_OSX) sibyl_srv.c -o sibyl_srv sibyl_srv_support.o $(LIBDIR)/bsd-base64.o $(LIBD_OSX) $(LIBS)
