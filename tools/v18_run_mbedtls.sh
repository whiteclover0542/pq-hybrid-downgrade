#!/usr/bin/env bash
# Replace only the separated RNG-initialization diagnostic records with a fresh mbedTLS survey.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_DIR" >&2
  exit 2
fi
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO_ROOT/tools"
python3 -m faultinject.v18 --repeat 3 --clients mbedtls --output-dir "$1"
