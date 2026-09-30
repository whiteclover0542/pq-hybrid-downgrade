#!/usr/bin/env bash
# Build the v1.8 loopback client probes from Ubuntu packages; preserve all output in v1.8-setup.log.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=/root/pq-hybrid-phase2/v18
LOG="$OUT/setup.log"
mkdir -p "$OUT"
exec > >(tee "$LOG") 2>&1

export DEBIAN_FRONTEND=noninteractive
apt-get install -y gnutls-bin libwolfssl-dev botan libbotan-3-dev default-jdk nodejs libmbedtls-dev
cc -O2 -Wall "$REPO_ROOT/tools/v18/wolfssl_client.c" -lwolfssl -o "$OUT/wolfssl_client"
cc -O2 -Wall "$REPO_ROOT/tools/v18/mbedtls_client.c" -lmbedtls -lmbedx509 -lmbedcrypto -o "$OUT/mbedtls_client"
javac -d "$OUT" "$REPO_ROOT/tools/v18/JavaTlsClient.java"
cp "$REPO_ROOT/tools/v18/node_tls_client.js" "$REPO_ROOT/tools/v18/python_tls_client.py" "$OUT/"

printf '\n== versions ==\n'
gnutls-cli --version | head -n 1
botan version
java -version
node --version
python3 -c 'import ssl; print(ssl.OPENSSL_VERSION)'
sha256sum "$OUT/wolfssl_client" "$OUT/mbedtls_client" "$OUT/JavaTlsClient.class" \
  "$OUT/node_tls_client.js" "$OUT/python_tls_client.py"
