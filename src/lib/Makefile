include ../Makefile.inc

default: libs

libs: bsd-base64.o
	$(CC) -fPIC -c bsd-base64.c -o bsd-base64.o

clean:
	rm -f *{.o,~} || true

