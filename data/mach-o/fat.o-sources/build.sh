#!/bin/sh
# Note: ../fat.o was built by Apple clang 17.0.0 (clang-1700.6.4.2) and lipo from Xcode 26.3, other versions produce different files
set -e
cd "$(dirname "$0")"
CLANG=${CLANG:-clang}
LIPO=${LIPO:-lipo}
trap 'rm -f object.x86_64.o object.arm64.o object.i386.o' EXIT
# Note: the empty sysroot keeps the SDK version out of LC_BUILD_VERSION and LC_VERSION_MIN_MACOSX
for target in x86_64-apple-macos10.13 arm64-apple-macos11 i386-apple-macos10.13; do
  "$CLANG" -target "$target" -isysroot /var/empty -O1 -fcommon -c -o "object.${target%%-*}.o" object.c
done
"$LIPO" -create -output ../fat.o object.x86_64.o object.arm64.o object.i386.o
