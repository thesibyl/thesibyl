include ../Makefile.inc
LIBDIR = "../lib"
LIBS = -lcrypto -lcrypt

default: srv

libs:
	cd ../lib && $(MAKE) $(MFLAGS)

srv: libs
	@echo generando sibyl_srv 
	$(CC) $(INC) -g sibyl_srv.c -o sibyl_srv $(LIBDIR)/bsd-base64.o $(LIBS)

clean:
	@rm *{.o,.so,~} || true
