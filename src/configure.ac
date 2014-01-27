#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([thesibyl], [0.1], [todo@todo.com])
AM_INIT_AUTOMAKE

AC_CONFIG_SRCDIR([lib/bsd-base64.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_CHECK_PROG(OPENSSL, openssl, [openssl], [openssl not found], [])

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lcrypt':
# AC_CHECK_LIB([crypt], [main])
AC_CHECK_LIB([crypto], [RSA_size])
# FIXME: Replace `main' with a function in `-lpam':
# AC_CHECK_LIB([pam], [main])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h limits.h netdb.h netinet/in.h stdlib.h string.h sys/param.h sys/socket.h sys/time.h syslog.h termios.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([memset socket strchr])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
