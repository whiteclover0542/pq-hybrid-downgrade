#!/usr/bin/env bash
# Survey the current official AWS-LC-backed s2n-tls client with its default policy.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_DIR" >&2
  exit 2
fi
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO_ROOT/tools"
python3 -m faultinject.v18 --repeat 3 --clients s2n-tls --output-dir "$1"
