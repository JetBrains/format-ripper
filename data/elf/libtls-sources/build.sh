#!/bin/sh
# Note: ../libtls.lld-x86_64 was built by clang and ld.lld 15.0.3 from the JetBrains.clang-llvm 15.0.3.1 package and
# ../libtls.bfd-m68k by GNU Binutils 2.47 from the m68k-elf-binutils Homebrew package, other versions produce different files
set -e
cd "$(dirname "$0")"
CLANG=${CLANG:-clang}
LLD=${LLD:-ld.lld}
M68K_PREFIX=${M68K_PREFIX:-m68k-elf-}
"$CLANG" -target x86_64-linux-gnu -O1 -fPIC -shared -nostdlib --ld-path="$LLD" -Wl,--hash-style=both -o ../libtls.lld-x86_64 tls.c
trap 'rm -f tls.m68k.o' EXIT
"${M68K_PREFIX}as" -o tls.m68k.o tls.m68k.s
"${M68K_PREFIX}ld" -shared --hash-style=both -o ../libtls.bfd-m68k tls.m68k.o
