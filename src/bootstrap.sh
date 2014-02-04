#! /usr/bin/env bash

# Bootstrap script for the sibyl #

BUILD_DIR=build

touch ./NEWS
touch ./README
touch ./AUTHORS
touch ./ChangeLog


aclocal
autoheader
autoconf
automake --add-missing

if ! test -d $BUILD_DIR; then
	mkdir $BUILD_DIR
fi

cd build
../configure
make
