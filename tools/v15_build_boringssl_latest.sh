#!/usr/bin/env bash
# Build a fresh, isolated BoringSSL control binary. It never changes the historical checkout.
set -euo pipefail

OUT=/root/pq-hybrid-phase2/boringssl-latest
test ! -e "$OUT"
git clone --depth 1 https://boringssl.googlesource.com/boringssl "$OUT"
cmake -S "$OUT" -B "$OUT/build" -GNinja -DCMAKE_BUILD_TYPE=Release
ninja -C "$OUT/build" bssl
git -C "$OUT" rev-parse HEAD
sha256sum "$OUT/build/bssl"
"$OUT/build/bssl" server -help 2>&1 | head -80
