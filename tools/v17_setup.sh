#!/bin/bash
# v1.7: install headless Chrome (Chrome for Testing, chrome-headless-shell) and Firefox (official release)
# outside the repository, for the browser ClientHello survey. Prints versions and SHA-256 for provenance.
set -euo pipefail
OUT=/root/pq-hybrid-phase2/v17
mkdir -p "$OUT"
cd "$OUT"

echo "=== runtime libraries"
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unzip xz-utils bzip2 libnss3 libatk1.0-0t64 libatk-bridge2.0-0t64 \
  libcups2t64 libxkbcommon0 libxcomposite1 libxdamage1 libxrandr2 libgbm1 libpango-1.0-0 libasound2t64 \
  libgtk-3-0t64 libdbus-glib-1-2 libx11-xcb1 >/dev/null 2>&1 || echo "warning: some packages failed to install"

echo "=== chrome-headless-shell (Chrome for Testing, Stable)"
JSON=https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json
URL=$(curl -sf "$JSON" | python3 -c "import json,sys; d=json.load(sys.stdin)['channels']['Stable']; print(d['version']); print([x['url'] for x in d['downloads']['chrome-headless-shell'] if x['platform']=='linux64'][0])")
echo "$URL"
curl -sfL -o chrome-headless-shell.zip "$(echo "$URL" | tail -1)"
sha256sum chrome-headless-shell.zip
rm -rf chrome-headless-shell-linux64 && unzip -q chrome-headless-shell.zip
CHROME=$OUT/chrome-headless-shell-linux64/chrome-headless-shell
"$CHROME" --version
ldd "$CHROME" | grep "not found" || echo "chrome libs ok"

echo "=== firefox (official latest release)"
curl -sfL -o firefox.tar "https://download.mozilla.org/?product=firefox-latest-ssl&os=linux64&lang=en-US"
sha256sum firefox.tar
rm -rf firefox && tar -xf firefox.tar
"$OUT/firefox/firefox" --version
ldd "$OUT/firefox/libxul.so" | grep "not found" || echo "firefox libs ok"
mkdir -p "$OUT/ffprofile"
echo "=== done"
