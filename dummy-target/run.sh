#!/bin/bash

set -e

rm -rf out
mkdir -p out

../../AFL/afl-clang-fast++ -fsanitize=dataflow -O1 -g target.cpp -o target
cargo build # --release
clear
RUST_BACKTRACE=1 ../target/debug/sim-fuzzer -o out "$@" ./target @@
