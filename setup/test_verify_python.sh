#!/usr/bin/env bash
# verify.sh 必须先用 seep-venv，不能被 PATH 上能 import sys 但没有 mcp 的 python3 截走。
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/path" "$TMP/agent/seep-venv/bin"
cat > "$TMP/path/python3" << 'EOF'
#!/usr/bin/env bash
if [[ "$*" == *"import mcp"* ]]; then
    echo "system python has no mcp" >&2
    exit 1
fi
exit 0
EOF
cat > "$TMP/agent/seep-venv/bin/python" << 'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$TMP/path/python3" "$TMP/agent/seep-venv/bin/python"

fail() { echo "FAIL: $*" >&2; exit 1; }

chosen="$( {
    SEEP_AGENT_DIR="$TMP/agent" \
    VERIFY_PRINT_PY=1 \
    PATH="$TMP/path:/usr/bin:/bin" \
    bash "$SCRIPT_DIR/verify.sh"
} | tail -n 1 )" || fail "打印解释器失败"
[ "$chosen" = "$TMP/agent/seep-venv/bin/python" ] || fail "选中了 $chosen，不是 seep-venv"

rm -rf "$TMP/agent"
fallback="$( {
    SEEP_AGENT_DIR="$TMP/agent" \
    VERIFY_PRINT_PY=1 \
    PATH="$TMP/path:/usr/bin:/bin" \
    bash "$SCRIPT_DIR/verify.sh"
} | tail -n 1 )" || fail "没有 venv 时打印失败"
[ "$fallback" = "$TMP/path/python3" ] || fail "没有 venv 时选中了 $fallback"

echo "ok"
