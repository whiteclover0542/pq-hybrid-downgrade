#!/bin/bash
# v1.3 causal-isolation builds. Each variant gets its own worktree and install prefix;
# the existing 3.5.5 / 3.5.6 installs are never touched.
#   3.5.5-cherrypick : openssl-3.5.5 + only the ssl/t1_lib.c change of fix 85977e0
#   3.5.6-revert     : openssl-3.5.6 - only the ssl/t1_lib.c change of fix 85977e0
#   3.6.1 / 3.6.2    : release tags (3.6 fix 2157c9d is in 3.6.2, not in 3.6.1)
# Usage: bash tools/v13_build_variants.sh [variant ...]   (default: all four)
set -eu
ROOT=/root/pq-hybrid-phase2
SRC=$ROOT/openssl
FIX35=85977e013f32ceb96aa034c0e741adddc1a05e34
FIX36=2157c9d81f7b0bd7dfa25b960e928ec28e8dd63f

build() {  # build <variant> <tag> <patch-mode: none|apply|revert> <fix commit>
  local variant=$1 tag=$2 mode=$3 fix=$4
  local tree=$ROOT/openssl-$variant prefix=$ROOT/install/openssl-$variant
  echo "=== $variant (tag $tag, mode $mode)"
  [ -d "$tree" ] || git -C "$SRC" worktree add --detach "$tree" "$tag" >/dev/null
  cd "$tree"
  git checkout -q --detach "$tag" && git checkout -q -- . && git clean -qfdx
  echo "tag-commit=$(git rev-parse HEAD)"
  if git merge-base --is-ancestor "$fix" HEAD; then echo "fix-ancestor=yes"; else echo "fix-ancestor=no"; fi
  case $mode in
    apply)  git diff "$fix^" "$fix" -- ssl/t1_lib.c | git apply --index ;;
    revert) git diff "$fix" "$fix^" -- ssl/t1_lib.c | git apply --index ;;
  esac
  if [ "$mode" != none ]; then
    echo "patched-files=$(git diff --cached --name-only | tr '\n' ' ')"
    echo "patch-sha256=$(git diff --cached | sha256sum | cut -d' ' -f1)"
  fi
  ./Configure linux-x86_64 --prefix="$prefix" --openssldir="$prefix/ssl" no-tests >/tmp/v13-$variant-configure.log 2>&1
  make -j8 >/tmp/v13-$variant-make.log 2>&1
  make install_sw >/tmp/v13-$variant-install.log 2>&1
  echo "binary-sha256=$(sha256sum "$prefix/bin/openssl" | cut -d' ' -f1)"
  echo "version=$(LD_LIBRARY_PATH=$prefix/lib64 OPENSSL_CONF=/dev/null "$prefix/bin/openssl" version)"
}

git -C "$SRC" fetch --tags origin >/dev/null 2>&1
variants=${*:-3.5.5-cherrypick 3.5.6-revert 3.6.1 3.6.2}
for v in $variants; do
  case $v in
    3.5.5-cherrypick) build "$v" openssl-3.5.5 apply  "$FIX35" ;;
    3.5.6-revert)     build "$v" openssl-3.5.6 revert "$FIX35" ;;
    3.6.1)            build "$v" openssl-3.6.1 none   "$FIX36" ;;
    3.6.2)            build "$v" openssl-3.6.2 none   "$FIX36" ;;
    *) echo "unknown variant $v"; exit 2 ;;
  esac
done
echo "=== done"
