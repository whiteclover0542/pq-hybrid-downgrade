#!/usr/bin/env bash
# Run the isolated v1.6 direct-default matrix without touching the committed v1.6 E9a/E9b data.
set -euo pipefail

REPO=/mnt/d/IT/git/PERSONAL/pq-hybrid-downgrade/pq-hybrid-downgrade
OUT=${1:-"$REPO/docs/research/baselines/raw/v1.6-direct"}

mkdir -p "$OUT"
if compgen -G "$OUT/*.json" >/dev/null; then
  echo "refusing non-empty output directory: $OUT" >&2
  exit 2
fi

exec >"$OUT/v1.6-direct.stdout.log" 2>"$OUT/v1.6-direct.stderr.log"
cd "$REPO/tools"
exec env PYTHONIOENCODING=utf-8 python3 -m faultinject.v16 --direct-repeat 3 --output-dir "$OUT"
