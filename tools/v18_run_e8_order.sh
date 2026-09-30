#!/usr/bin/env bash
# Add the missing client-order and server-order controls for Botan's observed C3 default.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_DIR" >&2
  exit 2
fi
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO_ROOT/tools"
python3 -m faultinject.v18 --e8-repeat 3 --servers boringssl go --output-dir "$1"
