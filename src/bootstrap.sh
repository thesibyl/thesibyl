#! /usr/local/bin/bash

# Bootstrap script for the sibyl #

touch ./NEWS
touch ./README
touch ./AUTHORS
touch ./ChangeLog


aclocal
autoheader
autoconf
automake --add-missing

mkdir build && cd build
../configure
make
