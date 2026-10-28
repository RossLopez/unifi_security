#!/usr/bin/env bash
# Build the Splunk app package into dist/ (gitignored).
# Usage: scripts/package.sh
set -euo pipefail
cd "$(dirname "$0")/.."
app=unifi_security
cmp -s LICENSE "$app/LICENSE" || { echo "LICENSE and $app/LICENSE differ" >&2; exit 1; }
ver=$(awk -F' *= *' '/^\[launcher\]/{f=1;next} /^\[/{f=0} f&&$1=="version"{print $2}' "$app/default/app.conf")
mkdir -p dist
out="dist/${app}-${ver}.spl"
COPYFILE_DISABLE=1 tar --exclude='.DS_Store' --exclude='local' --exclude='local.meta' --exclude='*.pyc' \
  -czf "$out" "$app"
echo "built $out"
