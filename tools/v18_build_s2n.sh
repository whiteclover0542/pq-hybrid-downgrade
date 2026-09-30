#!/usr/bin/env bash
# Build current official s2n-tls with its isolated AWS-LC dependency, required for its PQ groups.
set -euo pipefail

OUT=/root/pq-hybrid-phase2/v18
SRC="$OUT/s2n-tls"
mkdir -p "$OUT"
if [[ -e "$SRC" ]]; then
  echo "refusing to overwrite existing source: $SRC" >&2
  exit 2
fi
git clone --depth 1 https://github.com/aws/s2n-tls.git "$SRC"
apt-get install -y clang ninja-build
"$SRC/codebuild/bin/install_awslc.sh" "$OUT/awslc-build" "$OUT/awslc-install"
# s2nc is a testing utility and is conditionally defined under BUILD_TESTING;
# build that target only rather than running the test suite.
cmake -S "$SRC" -B "$SRC/build" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON \
  -DS2N_INTERN_LIBCRYPTO=ON -DCMAKE_PREFIX_PATH="$OUT/awslc-install"
cmake --build "$SRC/build" --target s2nc -j 2
printf '\n== provenance ==\n'
git -C "$SRC" rev-parse HEAD
git -C "$SRC" status --short
find "$SRC/build" -type f -name s2nc -printf '%p\n'
