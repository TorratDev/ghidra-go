#!/usr/bin/env bash
# Builds the comparison corpus. Output binaries are committed so results do
# not drift with the local toolchain; rerun only when sources change.
set -euo pipefail
cd "$(dirname "$0")"
SRC=src
OUT=binaries
mkdir -p "$OUT"

build() { # name cmd...
    local name=$1; shift
    if "$@" -o "$OUT/$name" 2>"$OUT/$name.log"; then
        rm -f "$OUT/$name.log"
        echo "built $name"
    else
        echo "SKIP $name (see $OUT/$name.log)"
    fi
}

for cc in gcc clang; do
    for opt in O0 O2; do
        build basic-x86_64-$cc-$opt $cc -$opt -g0 -fno-stack-protector $SRC/basic.c
        build basic-x86_64-$cc-$opt-stripped $cc -$opt -g0 -s -fno-stack-protector $SRC/basic.c
    done
done
build objects-x86_64-gxx-O2 g++ -O2 -g0 $SRC/objects.cpp
build objects-x86_64-gxx-O2-stripped g++ -O2 -g0 -s $SRC/objects.cpp
build basic-x86_64-gcc-O2-static-stripped gcc -O2 -g0 -s -static $SRC/basic.c

FS="-ffreestanding -fno-builtin -nostdlib -fno-stack-protector -fno-pic -fuse-ld=lld -g0"
build freestanding-i386-clang-O2 clang --target=i386-linux-gnu -O2 $FS -static $SRC/freestanding.c
build freestanding-aarch64-clang-O2 clang --target=aarch64-linux-gnu -O2 $FS -static $SRC/freestanding.c
build freestanding-aarch64-clang-O0 clang --target=aarch64-linux-gnu -O0 $FS -static $SRC/freestanding.c
build freestanding-x86_64-clang-O2 clang --target=x86_64-linux-gnu -O2 $FS -static $SRC/freestanding.c
build freestanding-x86_64-pe-clang-O2.exe clang --target=x86_64-pc-windows-msvc -O2 -ffreestanding -fno-builtin \
    -nostdlib -fuse-ld=lld -Wl,/entry:_start -Wl,/subsystem:console -Wl,/Brepro $SRC/freestanding.c
build freestanding-i386-pe-clang-O2.exe clang --target=i686-pc-windows-msvc -O2 -ffreestanding -fno-builtin \
    -nostdlib -fuse-ld=lld -Wl,/entry:_start -Wl,/subsystem:console -Wl,/Brepro $SRC/freestanding.c
# Mach-O. The macOS 11 target adds LC_BUILD_VERSION and __DATA_CONST; the
# default darwin triple does not, and lld's output is deterministic, so no UUID
# pinning. Reproduced with clang 14 and lld 14 in debian:bookworm-slim.
build freestanding-x86_64-macho-clang-O2 clang --target=x86_64-apple-macos11 -O2 -ffreestanding -fno-builtin \
    -nostdlib -fuse-ld=lld -Wl,-e,__start $SRC/freestanding.c

# Rust (no_std, no libc). rustc defaults to v0 mangling; legacy mangling is
# behind -Z, enabled on stable via RUSTC_BOOTSTRAP for this corpus build only.
RF="-C panic=abort -C opt-level=1 -C relocation-model=static -C link-arg=-nostartfiles -C link-arg=-nostdlib -C link-arg=-static --edition 2021"
build rust-x86_64-v0 rustc $RF -C symbol-mangling-version=v0 $SRC/rustlib.rs
build rust-x86_64-legacy env RUSTC_BOOTSTRAP=1 rustc $RF -Z unstable-options -C symbol-mangling-version=legacy $SRC/rustlib.rs

# MSVC-ABI C++ DLLs (no CRT) with MSVC-mangled exports.
MF="-O1 -shared -nostdlib -fno-exceptions -fno-rtti -fuse-ld=lld -Wl,/noentry -Wl,/Brepro"
build cxx-msvc-x86_64.dll clang --target=x86_64-pc-windows-msvc $MF $SRC/msvc.cpp
build cxx-msvc-i386.dll clang --target=i686-pc-windows-msvc $MF $SRC/msvc.cpp

# Import libraries are a side effect of the DLL links.
rm -f "$OUT"/*.lib
