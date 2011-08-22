include ../Makefile.inc
LIBDIR = "../lib"

default: pam_sibyl-osx

pam_sibyl-osx:
	@echo libs is $(LIBS)
	@echo inc is $(INC)
	@echo jajajaj
	$(CC) $(INC) -fPIC -c sibyl_support.c -o sibyl_support.o
	$(CC) $(INC) -fPIC -c pam_sibyl.c -o pam_sibyl.o
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
	@rm *{.o,.so,~} || true
