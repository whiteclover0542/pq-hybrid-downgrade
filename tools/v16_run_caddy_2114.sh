#!/usr/bin/env bash
# Compare the verified official Caddy 2.11.4 binary with the unchanged nginx control.
set -euo pipefail

REPO=/mnt/d/IT/git/PERSONAL/pq-hybrid-downgrade/pq-hybrid-downgrade
OUT=${1:-"$REPO/docs/research/baselines/raw/v1.6-caddy-2.11.4"}
CADDY=/root/pq-hybrid-phase2/v16/caddy-2.11.4/caddy

test -x "$CADDY"
mkdir -p "$OUT"
if compgen -G "$OUT/*.json" >/dev/null; then
  echo "refusing non-empty output directory: $OUT" >&2
  exit 2
fi

exec >"$OUT/v1.6-caddy-2.11.4.stdout.log" 2>"$OUT/v1.6-caddy-2.11.4.stderr.log"
cd "$REPO/tools"
exec env PYTHONIOENCODING=utf-8 FAULTINJECT_V16_CADDY="$CADDY" python3 -m faultinject.v16 --repeat 3 --output-dir "$OUT"
