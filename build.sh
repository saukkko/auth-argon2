#!/bin/bash
set -e

WRK=/home/sauli/auth-argon2
CFLAGS_DEBUG="-Og -g -pipe -march=x86-64 -mtune=generic -Iinclude"
CFLAGS="-O2 -pipe -march=native -Iinclude"
LDFLAGS_DEBUG="-Wl,-Og -Wl,-g -largon2"
LDFLAGS="-Wl,-O1 -Wl,-s -largon2"

mkdir -pv $WRK/{obj,bin}
rm -fv $WRK/{obj,bin}/*

if [[ $1 == "release" ]]; then
	set -x
	cd $WRK/obj
	/usr/bin/gcc -Wall -E ../src/main.c | /usr/bin/gcc -Wall $CFLAGS -x c -S -o main.s -
	/usr/bin/gcc -Wall $CFLAGS -c main.s -o main.o
	/usr/bin/gcc -Wall $LDFLAGS main.o -o ../bin/main
	cd $WRK/bin
	strip --strip-unneeded main
else
	set -x
	cd $WRK/obj
	/usr/bin/gcc -Wall -E ../src/main.c -DDEV | /usr/bin/gcc -Wall $CFLAGS_DEBUG -x c -S -o main.s -
        /usr/bin/gcc -Wall $CFLAGS_DEBUG -c main.s -o main.o
	/usr/bin/gcc -Wall $LDFLAGS_DEBUG main.o -o ../bin/main
fi

