#!/usr/bin/env bash
# 已有 aotopsy 可执行文件时，安装脚本要把 ida/ghidra 脚本放到它旁边和 SEEP_AOTOPSY_HOME。
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/android/bin" "$TMP/home"
printf '#!/bin/sh\nexit 0\n' > "$TMP/android/bin/aotopsy"
chmod +x "$TMP/android/bin/aotopsy"

SEEP_ANDROID_TOOLBOX="$TMP/android" \
SEEP_AOTOPSY_HOME="$TMP/home" \
bash "$SCRIPT_DIR/install-capabilities.sh" --only aotopsy >/dev/null

fail() { echo "FAIL: $*" >&2; exit 1; }
for f in \
    "$TMP/android/bin/ida_scripts/aotopsy_apply.py" \
    "$TMP/android/bin/ghidra_scripts/aotopsy_apply.py" \
    "$TMP/android/bin/ghidra_scripts/aotopsy_prescript.py" \
    "$TMP/android/bin/ghidra_scripts/AARCH64_dart.cspec" \
    "$TMP/home/ida_scripts/aotopsy_apply.py" \
    "$TMP/home/ghidra_scripts/aotopsy_prescript.py"
do
    [ -s "$f" ] || fail "缺少 $f"
done
cmp -s "$ROOT/Tool/aotopsy/ida_scripts/aotopsy_apply.py" "$TMP/android/bin/ida_scripts/aotopsy_apply.py" \
    || fail "ida 脚本与仓库不一致"

echo "ok"
