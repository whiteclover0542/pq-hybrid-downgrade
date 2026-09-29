#!/bin/bash
# v1.6: client default key-share survey and real server software (nginx, Caddy) with default settings.
# Builds the Go/rustls default clients and writes nginx/Caddy configs outside the repository.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
V15=/root/pq-hybrid-phase2/v15
OUT=/root/pq-hybrid-phase2/v16
PEM=/root/pq-hybrid-phase2/openssl/apps/server.pem
mkdir -p "$OUT/caddy-data" "$OUT/caddy-config"

echo "=== packages"
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx caddy >/dev/null 2>&1
systemctl disable --now nginx caddy >/dev/null 2>&1 || true
pkill -x nginx || true; pkill -x caddy || true
dpkg -l nginx caddy openssl 'libssl3*' curl libnss3 | awk '/^ii/ {print $2, $3}'
nginx -v 2>&1; caddy version

echo "=== go client"
( cd "$REPO/tools/v15/goclient" && { [ -f go.mod ] || go mod init v15goclient >/dev/null 2>&1; } && CGO_ENABLED=0 go build -o "$V15/goclient" . )
sha256sum "$V15/goclient"

echo "=== rustls client"
. "$HOME/.cargo/env"
( cd "$REPO/tools/v15/rustserver" && CARGO_TARGET_DIR="$V15/rust-target" cargo build --release -q )
cp "$V15/rust-target/release/client" "$V15/rustclient"
sha256sum "$V15/rustclient"

echo "=== nginx config (defaults except listen/cert/protocol)"
cat > "$OUT/nginx.conf" <<EOF
worker_processes 1;
pid $OUT/nginx.pid;
error_log $OUT/nginx-error.log;
events {}
http {
    access_log off;
    server {
        listen 127.0.0.1:8545 ssl;
        ssl_certificate $PEM;
        ssl_certificate_key $PEM;
        ssl_protocols TLSv1.3;
        location / { return 200 "ok\n"; }
    }
}
EOF
nginx -t -c "$OUT/nginx.conf" 2>&1 | tail -1

echo "=== Caddyfile (defaults except listen/cert)"
cat > "$OUT/Caddyfile" <<EOF
{
    admin off
    auto_https disable_redirects
}
https://127.0.0.1:8545 {
    tls $PEM $PEM
    respond "ok"
}
EOF
XDG_DATA_HOME=$OUT/caddy-data XDG_CONFIG_HOME=$OUT/caddy-config caddy validate --config "$OUT/Caddyfile" --adapter caddyfile 2>&1 | tail -1
echo "=== done"
