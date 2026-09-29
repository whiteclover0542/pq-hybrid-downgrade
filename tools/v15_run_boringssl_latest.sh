#!/usr/bin/env bash
set -euo pipefail
REPO=/mnt/d/IT/git/PERSONAL/pq-hybrid-downgrade/pq-hybrid-downgrade
OUT=${1:-"$REPO/docs/research/baselines/raw/v1.5-boringssl-latest"}
BSSL=/root/pq-hybrid-phase2/boringssl-latest/build/bssl
test -x "$BSSL"
mkdir -p "$OUT"
if compgen -G "$OUT/*.json" >/dev/null; then
  echo "refusing non-empty output directory: $OUT" >&2
  exit 2
fi
exec >"$OUT/v1.5-boringssl-latest.stdout.log" 2>"$OUT/v1.5-boringssl-latest.stderr.log"
cd "$REPO/tools"
exec env PYTHONIOENCODING=utf-8 FAULTINJECT_V15_BSSL="$BSSL" python3 -m faultinject.v15 --repeat 3 --servers boringssl --output-dir "$OUT"
