include ../Makefile.inc
LIBDIR = "../lib"
LIBS = -lcrypto -lcrypt

default: srv

libs:
	cd ../lib && $(MAKE) $(MFLAGS)

debug: CFLAGS += -DDEBUG -g

srv: libs
	@echo generando sibyl_srv 
	$(CC) $(INC) -g sibyl_srv.c -o sibyl_srv $(LIBDIR)/bsd-base64.o $(LIBS)

clean:
	@find . \( -iname "*.o" -or -iname "*~" -or -iname "sibyl_srv" \) -exec rm -f '{}' \;

