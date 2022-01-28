#!/bin/sh -e
if [ -z "$1" ]
then
  printf "Need file as argument\n"
  exit 1
fi

stty -echo
printf "Enter password (will not echo): "
read -r PW
printf "\n"
printf "Re-enter to verify: "
read -r PW2

if [ "$PW" != "$PW2" ]
then
  stty echo
  printf "Passwords don't match\n"
  exit 1
fi
# yes, the password will be briefly visible in processes
printf "$PW" | /usr/bin/argon2 "$(dd if=/dev/random bs=1 count=64 2>/dev/null)" -i -t 12 -p 4 -m 16 -l 64 -e >> "$1"
PW=""
PW2=""
stty echo
printf "\n"
