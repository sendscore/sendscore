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

# expect CODE COMMAND...: the command must exit with exactly CODE.
expect() {
  local want=$1 got=0
  shift
  "$@" >/dev/null 2>&1 || got=$?
  if [ "$got" != "$want" ]; then
    echo "$* exited $got, want $want" >&2
    exit 1
  fi
}

# The sendscore command must hand over its arguments, streams, and exit code.
command_checks() {
  local run=("$@")
  expect 0 "${run[@]}" --version
  expect 0 "${run[@]}" diff "$repo/testdata/sample.eml" "$repo/testdata/sample.eml"
  expect 1 "${run[@]}" check --offline "$repo/conformance/messages/signed.eml"
  expect 2 "${run[@]}" check --offline "$repo/testdata/sample.eml"
  expect 64 "${run[@]}" check
  expect 70 env SENDSCORE_LAUNCHED=1 "${run[@]}" --version
  got=$("${run[@]}" check --offline --json - < "$repo/testdata/sample.eml") || true
  want=$("${run[@]}" check --offline --json "$repo/testdata/sample.eml") || true
  if [ -z "$got" ] || [ "$got" != "$want" ]; then
    echo "stdin gave a different report" >&2
    exit 1
  fi
}

cd "$tmp/npm"
command_checks npx --no-install sendscore
cd "$repo"

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
venv_command="$tmp/venv/bin/sendscore"
[ -x "$venv_command" ] || venv_command="$tmp/venv/Scripts/sendscore.exe"
command_checks "$venv_command"
cd "$repo/packages/python/tests"
"$venv_python" -m unittest test_conformance
