#!/bin/sh -e
if test -z "$1"
then
  printf "Need file as argument\n"
  exit 1
fi

stty -echo
printf "Enter passwowrd (will not echo): "
read -r PW

printf "$PW" | /usr/bin/argon2 "$(dd if=/dev/random bs=1 count=64 2>/dev/null)" -i -t 12 -p 4 -m 16 -l 64 -e >> "$1"
PW=";)"
stty echo
printf "\n"

