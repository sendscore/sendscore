#!/usr/bin/env bash
# Installs the npm package and the wheel for this machine from a -local build
# into clean projects, and runs conformance through them, with no SENDSCORE_BIN
# and no CLI on PATH, so the only binary to find is the bundled one.
#
#   (cd packages/sdk && npm ci && npm run build)
#   bash scripts/test-bundled.sh
set -euo pipefail

repo=$(pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
unset SENDSCORE_BIN

go run ./scripts/buildpackages -local -out "$tmp/packages"

mkdir "$tmp/tgz" "$tmp/npm"
for dir in "$tmp"/packages/npm/*; do
  (cd "$tmp/tgz" && npm pack "$dir" --silent >/dev/null)
done
platform=$(node -p 'process.platform + "-" + process.arch')
(
  cd "$tmp/npm"
  npm init -y >/dev/null
  npm install --no-audit --no-fund "$tmp/tgz/sendscore-cli-$platform-"*.tgz "$(ls "$tmp"/tgz/sendscore-[0-9]*.tgz)"
  cat > found.mjs <<'JS'
import { binary } from "sendscore";
const path = await binary();
if (!path.replaceAll("\\", "/").includes("/node_modules/@sendscore/cli-")) throw new Error(`used ${path}`);
console.log(`npm uses ${path}`);
JS
  node found.mjs
  node -e 'console.log(require("url").pathToFileURL("node_modules/sendscore/dist/index.js").href)' > url.txt
)
SENDSCORE_PACKAGE=$(cat "$tmp/npm/url.txt") node --test packages/sdk/test/conformance.test.mjs

python=$(command -v python3 || command -v python)
"$python" -m venv "$tmp/venv"
venv_python="$tmp/venv/bin/python"
[ -x "$venv_python" ] || venv_python="$tmp/venv/Scripts/python.exe"
"$venv_python" -m pip install --quiet --no-index --find-links "$tmp/packages/python" sendscore
cd "$tmp"
"$venv_python" -c '
from pathlib import Path
from sendscore._binary import find_binary
path = Path(find_binary())
if path.parent.name != "_bin":
    raise SystemExit(f"used {path}")
print(f"Python uses {path}")'
cd "$repo/packages/python/tests"
"$venv_python" -m unittest test_conformance
