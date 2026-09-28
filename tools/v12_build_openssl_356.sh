#!/bin/bash
# Build OpenSSL 3.5.6 into its own prefix after proving the CVE-2026-2673 fix commit is an ancestor.
set -eu
FIX=85977e013f32ceb96aa034c0e741adddc1a05e34
SRC=/root/pq-hybrid-phase2/openssl-3.5.6
PREFIX=/root/pq-hybrid-phase2/install/openssl-3.5.6

cd /root/pq-hybrid-phase2/openssl
git fetch --tags origin
echo "tag-commit=$(git rev-parse 'openssl-3.5.6^{commit}')"
[ -d "$SRC" ] || git worktree add "$SRC" openssl-3.5.6
cd "$SRC"
echo "HEAD=$(git rev-parse HEAD)"
git show --no-patch --format='fix-commit=%H %ad %s' "$FIX"
if git merge-base --is-ancestor "$FIX" HEAD; then echo "fix-ancestor=yes"; else echo "fix-ancestor=no"; exit 2; fi

./Configure linux-x86_64 --prefix="$PREFIX" --openssldir="$PREFIX/ssl" no-tests 2>&1 | tail -3
make -j2 >/tmp/v12-356-make.log 2>&1
make install_sw >/tmp/v12-356-install.log 2>&1
echo "compiler=$(gcc --version | head -1)"
sha256sum "$PREFIX/bin/openssl" /root/pq-hybrid-phase2/install/openssl/bin/openssl
ls "$PREFIX/lib64/libssl.so.3"
