#!/usr/bin/env bash
# Run the fixed v1.8 7-client × 3-repetition survey in a fresh output directory.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_DIR" >&2
  exit 2
fi
OUT=$1
if [[ -e "$OUT" ]] && find "$OUT" -type f -name '*.json' -print -quit | grep -q .; then
  echo "refusing to reuse output directory containing JSON: $OUT" >&2
  exit 2
fi
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO_ROOT/tools"
python3 -m faultinject.v18 --repeat 3 --output-dir "$OUT"
