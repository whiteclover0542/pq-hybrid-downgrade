#!/usr/bin/env bash
# Complete an interrupted v1.8 s2n build by adding the required official AWS-LC prefix.
set -euo pipefail

OUT=/root/pq-hybrid-phase2/v18
SRC="$OUT/s2n-tls"
test -d "$SRC/.git"
export DEBIAN_FRONTEND=noninteractive
apt-get install -y clang ninja-build
"$SRC/codebuild/bin/install_awslc.sh" "$OUT/awslc-build" "$OUT/awslc-install"
cmake -S "$SRC" -B "$SRC/build-awslc" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON \
  -DS2N_INTERN_LIBCRYPTO=ON -DCMAKE_PREFIX_PATH="$OUT/awslc-install"
cmake --build "$SRC/build-awslc" --target s2nc -j 2
printf '\n== provenance ==\n'
git -C "$SRC" rev-parse HEAD
"$SRC/build-awslc/bin/s2nc" --help | head -n 3
sha256sum "$SRC/build-awslc/bin/s2nc"
