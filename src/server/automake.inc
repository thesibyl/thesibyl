bin_PROGRAMS += sibyl_srv
sibyl_srv_SOURCES = server/sibyl_srv.c \
		  server/sibyl_srv_support.c \
		  server/sibyl_srv_support.h \
		  lib/sibyl.h \
		  lib/bsd-base64.c \
		  lib/bsd-base64.h
AM_CFLAGS = -I$(top_srcdir)/lib
