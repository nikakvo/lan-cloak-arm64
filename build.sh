#!/bin/sh
# build.sh - builds bin/lanc-bpf (static arm64) with the DHCP cleaner embedded.
# Needs: clang (with the bpf target), llvm-objcopy, llvm-readelf, zig 0.16.0.
#   ZIG="zig" by default; e.g. ZIG="python3 -m ziglang" for the pip package.
set -e
cd "$(dirname "$0")"
ZIG=${ZIG:-zig}
CLANG=${CLANG:-clang}
INC=${BPF_INC:-}
[ -z "$INC" ] && [ -d /usr/include/x86_64-linux-gnu ] && INC=-I/usr/include/x86_64-linux-gnu
$CLANG -O2 -g0 -target bpfel $INC -Wall -c src/dhcp_clean.bpf.c -o src/dhcp_clean.bpf.o
sh tools/mkhdr.sh src/dhcp_clean.bpf.o src/dhcp_clean.h
mkdir -p bin
$ZIG cc -target aarch64-linux-musl -O2 -static -s -Wall -Wextra -o bin/lanc-bpf src/lanc-bpf.c
rm -f src/dhcp_clean.bpf.o
sha256sum bin/lanc-bpf
