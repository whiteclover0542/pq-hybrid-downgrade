#!/bin/bash
# A-0 native-only probe: one handshake per server group setting, fixed 3.5.5 client.
# Usage: bash tools/v12_a0_smoke.sh <server-prefix>   (e.g. /root/pq-hybrid-phase2/install/openssl-3.5.6)
set -u
SERVER_PREFIX=${1:?server install prefix required}
CLIENT_PREFIX=/root/pq-hybrid-phase2/install/openssl
CERT=/root/pq-hybrid-phase2/openssl/apps/server.pem
PORT=8599

SERVER=(env LD_LIBRARY_PATH=$SERVER_PREFIX/lib64 OPENSSL_CONF=/dev/null "$SERVER_PREFIX/bin/openssl")
CLIENT=(env LD_LIBRARY_PATH=$CLIENT_PREFIX/lib64 OPENSSL_CONF=/dev/null "$CLIENT_PREFIX/bin/openssl")
unset OPENSSL_MODULES

echo "== server version"; "${SERVER[@]}" version -a | head -3
echo "== client version"; "${CLIENT[@]}" version
echo "== server providers"; "${SERVER[@]}" list -providers -provider default
echo "== server tls groups (mlkem/x25519)"; "${SERVER[@]}" list -tls-groups -tls1_3 | tr ':' '\n' | grep -i -E 'mlkem|^ *x25519$'

for g in "X25519MLKEM768:X25519" "X25519MLKEM768/X25519" "DEFAULT" "OMIT"; do
  if [ "$g" = OMIT ]; then gargs=(); else gargs=(-groups "$g"); fi
  timeout 3 "${SERVER[@]}" s_server -tls1_3 -www -provider default -accept $PORT -cert "$CERT" "${gargs[@]}" \
    >/tmp/v12a0-srv.log 2>&1 &
  sleep 0.7
  timeout 3 "${CLIENT[@]}" s_client -tls1_3 -state -msg -provider default -connect 127.0.0.1:$PORT \
    -groups X25519:X25519MLKEM768 </dev/null >/tmp/v12a0-cli.log 2>&1
  echo "== server $g: ServerHello-lines=$(grep -c 'ServerHello' /tmp/v12a0-cli.log)" \
       "hrr-random-lines=$(grep -c '03 03 cf 21 ad 74 e5 9a 61 11' /tmp/v12a0-cli.log)" \
       "$(grep -m1 -E 'Negotiated TLS1.3 group|Peer Temp Key' /tmp/v12a0-cli.log)"
  wait
done
