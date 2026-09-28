#!/bin/bash
# Read-only survey: can a BoringSSL server be told to HRR for a preferred group the client did not share?
cd /root/pq-hybrid-phase2/boringssl
echo "HEAD=$(git rev-parse HEAD)"
grep -n -i -E "hello_retry|HelloRetryRequest|needs_psk_binder|ssl_setup_key_shares|tls1_get_shared_group|ssl_nego|group_id" ssl/extensions.cc | head -60
grep -n -i -E "SSL_CTX_set1_groups|SSL_CTX_set1_group_ids|SSL_CTX_set1_curves|prefer|server_preference" include/openssl/ssl.h | head -40
/root/pq-hybrid-phase2/build/boringssl/tool/bssl server 2>&1 | head -80
