#!/usr/bin/env bash
# macOS 自带 bash 3.2：update.sh 不得把「正常更新」当成命令，
# 也不得在空代理数组上因 set -u 退出。pull 失败必须停在拉取，不能接着装。
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

LOG="$TMP/git.log"
cat > "$TMP/git" << 'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${FAKE_GIT_LOG:?}"
joined=" $* "
if [[ "$joined" == *" ls-remote "* ]]; then
    if [ "${FAKE_GIT_LS_REMOTE:-ok}" = "empty" ]; then
        exit 0
    fi
    echo "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa refs/heads/main"
    exit 0
fi
if [[ "$joined" == *" rev-parse "* ]]; then
    echo "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    exit 0
fi
if [[ "$joined" == *" status "* ]]; then
    exit 0
fi
if [[ "$joined" == *" pull "* ]]; then
    echo "simulated network failure" >&2
    exit 23
fi
exit 0
EOF
chmod +x "$TMP/git"

cat > "$TMP/curl" << 'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${FAKE_GIT_LOG:?}"
exit 1
EOF
chmod +x "$TMP/curl"

export FAKE_GIT_LOG="$LOG"
export PATH="$TMP:$PATH"
export SEEP_AGENT_DIR="$TMP/agent"
export SEEP_UPDATE_NO_PROXY=1
mkdir -p "$SEEP_AGENT_DIR"

fail() {
    echo "FAIL: $*" >&2
    echo "---- stdout ----" >&2
    cat "$TMP/out" >&2 || true
    echo "---- stderr ----" >&2
    cat "$TMP/err" >&2 || true
    exit 1
}

bash -n "$SCRIPT_DIR/update.sh" || fail "bash -n"

: > "$LOG"
bash "$SCRIPT_DIR/update.sh" --dry-run >"$TMP/out" 2>"$TMP/err"
rc=$?
[ "$rc" -eq 0 ] || fail "dry-run exit $rc"
grep -F "DRY RUN（不修改任何文件）" "$TMP/out" >/dev/null || fail "dry-run 没有印出 DRY RUN"
grep -F "command not found" "$TMP/out" "$TMP/err" && fail "dry-run 把模式字符串当成了命令"
grep -F "unbound variable" "$TMP/out" "$TMP/err" && fail "dry-run 触发 unbound"
grep -F "pull" "$LOG" && fail "dry-run 不该执行 git pull"

: > "$LOG"
bash "$SCRIPT_DIR/update.sh" >"$TMP/out" 2>"$TMP/err"
rc=$?
[ "$rc" -eq 1 ] || fail "模拟 pull 失败时期望退出码 1，实际 $rc"
grep -F "正常更新" "$TMP/out" >/dev/null || fail "运行模式没有印出正常更新"
grep -F "command not found" "$TMP/out" "$TMP/err" && fail "正常更新被当成命令"
grep -F "unbound variable" "$TMP/out" "$TMP/err" && fail "空 PROXY_ARGS 仍然 unbound"
grep -F "git pull 失败" "$TMP/out" >/dev/null || fail "pull 失败被管道吞掉了"
grep -F "增量同步" "$TMP/out" && fail "pull 失败后仍继续安装"
grep -F "pull --rebase origin main" "$LOG" >/dev/null || fail "没有真正调用 git pull"

: > "$LOG"
bash "$SCRIPT_DIR/update.sh" --check >"$TMP/out" 2>"$TMP/err"
rc=$?
[ "$rc" -eq 0 ] || fail "--check exit $rc"
grep -F "已是最新版本" "$TMP/out" >/dev/null || fail "--check 没有得出版本结论"
grep -F "unbound variable" "$TMP/out" "$TMP/err" && fail "--check 的空 GIT_PROXY unbound"
grep -F "ls-remote origin refs/heads/main" "$LOG" >/dev/null || fail "--check 没有调用 ls-remote"
grep -F "http.proxy" "$LOG" && fail "--check 在无代理时仍塞了代理参数"

: > "$LOG"
FAKE_GIT_LS_REMOTE=empty bash -c 'export FAKE_GIT_LS_REMOTE; exec bash "$0" --check' "$SCRIPT_DIR/update.sh" >"$TMP/out" 2>"$TMP/err"
rc=$?
[ "$rc" -eq 0 ] || fail "--check 无远程输出时 exit $rc"
grep -F "unbound variable" "$TMP/out" "$TMP/err" && fail "空 CURL_PROXY unbound"
grep -F -- "--max-time" "$LOG" >/dev/null || fail "没有落到 curl 探测 VERSION"

echo "ok"
