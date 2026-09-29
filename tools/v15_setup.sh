#!/bin/bash
# v1.5 negotiation-function comparison: build the Go and rustls servers and the NSS cert DB
# outside the repository (under /root/pq-hybrid-phase2/v15). Prints versions for the evidence ledger.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
OUT=/root/pq-hybrid-phase2/v15
PEM=/root/pq-hybrid-phase2/openssl/apps/server.pem
mkdir -p "$OUT"

echo "=== go server"
go version
( cd "$REPO/tools/v15/goserver" && [ -f go.mod ] || go mod init v15goserver >/dev/null 2>&1; \
  cd "$REPO/tools/v15/goserver" && CGO_ENABLED=0 go build -o "$OUT/goserver" . )
sha256sum "$OUT/goserver"

echo "=== rustls server"
if ! command -v cargo >/dev/null; then
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null 2>&1
fi
. "$HOME/.cargo/env"
cargo --version
( cd "$REPO/tools/v15/rustserver" && CARGO_TARGET_DIR="$OUT/rust-target" cargo build --release -q )
cp "$OUT/rust-target/release/v15-rustls-server" "$OUT/rustserver"
grep -A1 '^name = "rustls"$' "$REPO/tools/v15/rustserver/Cargo.lock" | tail -1
sha256sum "$OUT/rustserver"

echo "=== nss"
dpkg -l libnss3 libnss3-tools | awk '/^ii/ {print $2, $3}'
rm -rf "$OUT/nssdb" && mkdir -p "$OUT/nssdb"
certutil -N -d "sql:$OUT/nssdb" --empty-password
openssl pkcs12 -export -in "$PEM" -inkey "$PEM" -name server -passout pass: -out "$OUT/server.p12" 2>/dev/null
pk12util -i "$OUT/server.p12" -d "sql:$OUT/nssdb" -W "" >/dev/null
certutil -L -d "sql:$OUT/nssdb"
echo "=== done"
