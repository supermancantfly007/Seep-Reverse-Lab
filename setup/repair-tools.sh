#!/usr/bin/env bash
# ==============================================================================
# Seep Lab —— 工具修复器（macOS / Linux）
# ==============================================================================
# 与 setup/repair-tools.ps1 对齐：工具已内置在 Tool/mcp/Tool/safe/，
# 只有损坏或缺失时才重新下载。可重复执行；已就绪的文件默认不覆盖。
#
# 本脚本会修（官方源优先，失败再试 ghproxy.net / gh-proxy.com）：
#   · jadx          上游 zip 含 Unix 启动脚本，解压到 <safe>/jadx/
#   · apktool       下载 apktool.jar，并写 POSIX 启动脚本 apktool
#                   （java -jar）。不写 Windows 的 apktool.bat
#   · playwright-mcp  目录里还没有可用包时，npm install @playwright/mcp
#   · js-reverse-mcp  与 ps1 相同：不下载，只确认 npm/npx 可用（走 npx）
#   · ida-pro-mcp   目录缺失时 pip install ida-pro-mcp（只装桥接包）
#
# 本脚本明确不修（跳过并说明，不会报成已修好）：
#   · radare2       ps1 下载的是 Windows 资产 radare2-*-w64.zip（PE）。
#                   在 macOS/Linux 上不能运行。不下载、不覆盖仓库里那份
#                   Windows 构建。请用系统包管理器自行安装，解析器走 PATH。
#   · 用户 PATH     ps1 用 [Environment]::SetEnvironmentVariable 写 Windows
#                   用户环境变量。Unix 没有单一对等位置；本脚本不改
#                   ~/.zshrc、~/.bashrc、~/.profile，也不改 ~/.pi。
#   · IDA Pro 本体  商业软件，只提示，不安装。
#   · aotopsy 等    不在 repair-tools.ps1 里，这里也不碰。
#
# 用法：
#   ./setup/repair-tools.sh
#   ./setup/repair-tools.sh --only jadx,apktool
#   ./setup/repair-tools.sh --only jadx --force
#   ./setup/repair-tools.sh --dest /tmp/seep-safe     # 写到别的目录（测试用）
#   SEEP_TOOLS_DIR=/tmp/seep-safe ./setup/repair-tools.sh
#
# 退出码：0 没有失败项；1 有下载/安装失败；2 参数错误，或 --only 点名的项
# 全部只是跳过（一件都没修好，也不假装成功）。
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

GREEN="\033[1;32m"; RED="\033[1;31m"; YELLOW="\033[1;33m"
CYAN="\033[1;36m"; WHITE="\033[1;37m"; GRAY="\033[0;37m"; RESET="\033[0m"

ONLY=""
FORCE=0
DEST="${SEEP_TOOLS_DIR:-}"

usage() {
    sed -n '2,35p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --only)
            [ $# -ge 2 ] || { echo "缺少 --only 的参数" >&2; exit 2; }
            ONLY="$ONLY $2"
            shift 2
            ;;
        --only=*)
            ONLY="$ONLY ${1#*=}"
            shift
            ;;
        --force) FORCE=1; shift ;;
        --dest)
            [ $# -ge 2 ] || { echo "缺少 --dest 的参数" >&2; exit 2; }
            DEST="$2"
            shift 2
            ;;
        --dest=*) DEST="${1#*=}"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "未知参数: $1" >&2; usage >&2; exit 2 ;;
    esac
done

ONLY="$(printf '%s' "$ONLY" | tr ',' ' ')"

ok()   { echo -e "    ${GREEN}[OK]${RESET} $1"; }
warn() { echo -e "    ${YELLOW}[!!]${RESET} $1"; }
info() { echo -e "    ${GRAY}[..]${RESET} $1"; }
fail() { echo -e "    ${RED}[FAIL]${RESET} $1"; }

os="$(uname -s)"
case "$os" in
    Darwin|Linux) ;;
    *)
        echo "本脚本只用于 macOS / Linux（当前: ${os}）。Windows 请运行 setup/repair-tools.ps1。" >&2
        exit 2
        ;;
esac

for name in $ONLY; do
    case "$name" in
        jadx|radare2|apktool|playwright-mcp|js-reverse-mcp|ida-pro-mcp) ;;
        "") ;;
        *) echo "未知工具: ${name}（可选 jadx / radare2 / apktool / playwright-mcp / js-reverse-mcp / ida-pro-mcp）" >&2; exit 2 ;;
    esac
done

if [ -n "$DEST" ]; then
    mkdir -p "$DEST" || { echo "无法创建目录: $DEST" >&2; exit 1; }
    TOOLS_DIR="$(cd "$DEST" && pwd)" || { echo "无法进入目录: $DEST" >&2; exit 1; }
else
    TOOLS_DIR="$ROOT/Tool/mcp/Tool/safe"
    mkdir -p "$TOOLS_DIR"
fi

RESULTS="$(mktemp)"
trap 'rm -f "$RESULTS"' EXIT

should_run() {
    [ -z "$(printf '%s' "$ONLY" | tr -d '[:space:]')" ] && return 0
    case " $ONLY " in
        *" $1 "*) return 0 ;;
        *) return 1 ;;
    esac
}

mark() {
    # $1 = OK|FAIL|SKIP  $2 = 工具名
    printf '%s %s\n' "$1" "$2" >> "$RESULTS"
}

file_bytes() {
    if [ ! -f "$1" ]; then
        echo 0
        return
    fi
    wc -c < "$1" | tr -d ' '
}

# 带镜像回退的下载。成功时目标文件 > 1024 字节。
download_url() {
    local url="$1" out="$2"
    local mirrors="" m u tag
    case "$url" in
        https://github.com/*|http://github.com/*)
            mirrors=" https://ghproxy.net/ https://gh-proxy.com/"
            ;;
    esac
    for m in "" $mirrors; do
        if [ -z "$m" ]; then
            u="$url"
            tag="official"
        else
            u="${m}${url}"
            tag="${m%/}"
        fi
        info "尝试 $tag ..."
        rm -f "$out"
        if curl -fsSL --retry 2 --connect-timeout 20 --max-time 300 \
                -A "seep-setup" -o "$out" "$u"; then
            if [ "$(file_bytes "$out")" -gt 1024 ]; then
                ok "下载成功 ($tag)"
                return 0
            fi
            info "失败: 文件过小"
        else
            info "失败: curl 退出 $?"
        fi
        rm -f "$out"
    done
    return 1
}

# 打印三行：url、文件名、tag。失败返回非 0。
github_asset() {
    local repo="$1" pattern="$2" body
    body="$(curl -fsSL --connect-timeout 20 --max-time 60 \
        -A "seep-setup" -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/$repo/releases/latest" 2>/dev/null)" || {
        warn "GitHub API 失败 ($repo)"
        return 1
    }
    printf '%s' "$body" | python3 -c '
import json, sys, re
raw = sys.stdin.read()
try:
    rel = json.loads(raw)
except Exception:
    sys.exit(1)
pat = re.compile(sys.argv[1])
for asset in rel.get("assets") or []:
    name = asset.get("name") or ""
    if pat.search(name):
        url = asset.get("browser_download_url") or ""
        if not url:
            sys.exit(1)
        sys.stdout.write(url + "\n" + name + "\n" + (rel.get("tag_name") or "") + "\n")
        sys.exit(0)
sys.exit(1)
' "$pattern"
}

flatten_single_root() {
    local dest="$1" count only tmp
    count="$(find "$dest" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')"
    [ "$count" = "1" ] || return 0
    only="$(find "$dest" -mindepth 1 -maxdepth 1)"
    [ -d "$only" ] || return 0
    tmp="$(mktemp -d)"
    find "$only" -mindepth 1 -maxdepth 1 -exec mv {} "$tmp"/ \;
    rm -rf "$only"
    find "$tmp" -mindepth 1 -maxdepth 1 -exec mv {} "$dest"/ \;
    rmdir "$tmp" 2>/dev/null || rm -rf "$tmp"
}

extract_zip() {
    local zip="$1" dest="$2"
    rm -rf "$dest"
    mkdir -p "$dest"
    if command -v unzip >/dev/null 2>&1; then
        unzip -q "$zip" -d "$dest" || return 1
    else
        python3 -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' \
            "$zip" "$dest" || return 1
    fi
    flatten_single_root "$dest"
}

have() { command -v "$1" >/dev/null 2>&1; }

find_python() {
    if [ -n "${SEEP_PYTHON:-}" ] && [ -x "${SEEP_PYTHON}" ]; then
        printf '%s\n' "$SEEP_PYTHON"
        return 0
    fi
    if have python3; then
        command -v python3
        return 0
    fi
    if have python; then
        command -v python
        return 0
    fi
    return 1
}

write_apktool_launcher() {
    local dst="$1"
    cat > "$dst/apktool" <<'EOF'
#!/bin/sh
# POSIX 启动器。Windows 修复脚本写的是 apktool.bat，这里不写 .bat。
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then
    JAVA="$JAVA_HOME/bin/java"
else
    JAVA=java
fi
exec "$JAVA" -jar -Duser.language=en "$here/apktool.jar" "$@"
EOF
    chmod +x "$dst/apktool"
}

# ---------------------------------------------------------------- jadx
if should_run jadx; then
    echo -e "\n${CYAN}  [1/6] jadx (Java 反编译)${RESET}"
    dst="$TOOLS_DIR/jadx"
    if [ "$FORCE" -eq 0 ] && [ -f "$dst/bin/jadx" ] && [ "$(file_bytes "$dst/bin/jadx")" -gt 0 ]; then
        chmod +x "$dst/bin/jadx" 2>/dev/null || true
        ok "已存在，跳过"
        mark OK jadx
    else
        if ! have curl || ! have python3; then
            fail "需要 curl 和 python3 才能下载 jadx"
            mark FAIL jadx
        else
            asset="$(github_asset skylot/jadx '^jadx-[\d.]+\.zip$')" || asset=""
            if [ -z "$asset" ]; then
                warn "jadx: 无法获取 release 信息"
                mark FAIL jadx
            else
                url="$(printf '%s\n' "$asset" | sed -n '1p')"
                name="$(printf '%s\n' "$asset" | sed -n '2p')"
                tag="$(printf '%s\n' "$asset" | sed -n '3p')"
                zip="$(mktemp "${TMPDIR:-/tmp}/jadx.XXXXXX")"
                if download_url "$url" "$zip"; then
                    if extract_zip "$zip" "$dst" && [ -f "$dst/bin/jadx" ]; then
                        chmod +x "$dst/bin/jadx" "$dst/bin/jadx-gui" 2>/dev/null || true
                        rm -f "$zip"
                        ok "jadx ${tag:-$name} -> $dst"
                        mark OK jadx
                    else
                        rm -f "$zip"
                        warn "jadx 解压后没有 bin/jadx（压缩包布局不符）"
                        mark FAIL jadx
                    fi
                else
                    rm -f "$zip"
                    warn "jadx 下载失败"
                    mark FAIL jadx
                fi
            fi
        fi
    fi
fi

# ---------------------------------------------------------------- radare2
if should_run radare2; then
    echo -e "\n${CYAN}  [2/6] radare2 (二进制逆向)${RESET}"
    warn "跳过：repair-tools.ps1 下载的是 Windows 资产 radare2-*-w64.zip（PE），在 macOS/Linux 上不能运行。"
    info "不下载该包，也不覆盖 $TOOLS_DIR/radare2（仓库里那份是给 Windows 用的）。"
    if have radare2 || have r2; then
        native="$(command -v radare2 2>/dev/null || command -v r2)"
        info "系统 PATH 上已有原生程序: $native （本脚本没有安装它）"
    else
        info "当前 PATH 没有 radare2 / r2。请自行安装后再开终端："
        echo "        macOS          : brew install radare2"
        echo "        Debian/Ubuntu  : sudo apt-get install -y radare2"
        echo "        Fedora         : sudo dnf install -y radare2"
        echo "        Arch           : sudo pacman -S radare2"
    fi
    info "解析器在 Unix 上会忽略 .exe/.bat，只认原生 radare2 或 PATH。"
    mark SKIP radare2
fi

# ---------------------------------------------------------------- apktool
if should_run apktool; then
    echo -e "\n${CYAN}  [3/6] apktool (APK 解包/重打包)${RESET}"
    dst="$TOOLS_DIR/apktool"
    if [ "$FORCE" -eq 0 ] && [ -f "$dst/apktool.jar" ] && [ "$(file_bytes "$dst/apktool.jar")" -gt 1024 ]; then
        if [ ! -x "$dst/apktool" ]; then
            write_apktool_launcher "$dst"
            ok "jar 已在，补写了 Unix 启动脚本（未写 apktool.bat）"
        else
            ok "已存在，跳过"
        fi
        mark OK apktool
    else
        if ! have curl || ! have python3; then
            fail "需要 curl 和 python3 才能下载 apktool"
            mark FAIL apktool
        else
            mkdir -p "$dst"
            asset="$(github_asset iBotPeaches/Apktool '^apktool_[\d.]+\.jar$')" || asset=""
            if [ -z "$asset" ]; then
                warn "apktool: 无法获取 release 信息"
                mark FAIL apktool
            else
                url="$(printf '%s\n' "$asset" | sed -n '1p')"
                tag="$(printf '%s\n' "$asset" | sed -n '3p')"
                jar="$dst/apktool.jar"
                tmpjar="$(mktemp "${TMPDIR:-/tmp}/apktool.XXXXXX")"
                if download_url "$url" "$tmpjar"; then
                    mv -f "$tmpjar" "$jar"
                    write_apktool_launcher "$dst"
                    ok "apktool ${tag} -> $dst （jar + Unix 启动脚本，没有写 .bat）"
                    mark OK apktool
                else
                    rm -f "$tmpjar"
                    warn "apktool 下载失败"
                    mark FAIL apktool
                fi
            fi
        fi
    fi
fi

# ---------------------------------------------------------------- playwright-mcp
playwright_ready() {
    local dst="$1"
    [ -f "$dst/node_modules.zip" ] && return 0
    [ -d "$dst/node_modules/@playwright/mcp" ] && return 0
    [ -f "$dst/package.json" ] || return 1
    python3 -c 'import json,sys
try:
    name=json.load(open(sys.argv[1],encoding="utf-8")).get("name")
except Exception:
    sys.exit(1)
sys.exit(0 if name=="@playwright/mcp" else 1)' "$dst/package.json"
}

if should_run playwright-mcp; then
    echo -e "\n${CYAN}  [4/6] playwright-mcp (浏览器自动化)${RESET}"
    dst="$TOOLS_DIR/playwright-mcp"
    if [ "$FORCE" -eq 0 ] && [ -d "$dst" ] && playwright_ready "$dst"; then
        ok "已存在，跳过（重复执行不会改这个目录里的 package.json）"
        mark OK playwright-mcp
    elif ! have npm; then
        warn "未找到 npm，跳过"
        mark FAIL playwright-mcp
    else
        mkdir -p "$dst"
        if [ ! -f "$dst/package.json" ]; then
            printf '%s\n' '{ "name": "playwright-mcp-local", "private": true }' > "$dst/package.json"
        fi
        info "npm install @playwright/mcp ..."
        if ( cd "$dst" && npm install @playwright/mcp --no-audit --no-fund ); then
            ok "playwright-mcp -> $dst"
            mark OK playwright-mcp
        else
            warn "npm install 失败（可改用 npx @playwright/mcp）"
            mark FAIL playwright-mcp
        fi
    fi
fi

# ---------------------------------------------------------------- js-reverse-mcp
if should_run js-reverse-mcp; then
    echo -e "\n${CYAN}  [5/6] js-reverse-mcp (JS 逆向)${RESET}"
    if ! have npm && ! have npx; then
        warn "未找到 npm/npx，跳过（js-reverse-mcp 依赖 npx）"
        mark FAIL js-reverse-mcp
    else
        info "js-reverse-mcp 采用官方推荐的 npx 方式（无需本地下载）"
        info "注册方式：mcp.json 中 command=npx, args=[\"js-reverse-mcp\"]"
        info "可选本地安装：git clone https://github.com/zhizhuodemao/js-reverse-mcp && npm i && npm run build"
        ok "js-reverse-mcp -> 走 npx（已在 mcp.json.template 中预置）"
        mark OK js-reverse-mcp
    fi
fi

# ---------------------------------------------------------------- ida-pro-mcp
if should_run ida-pro-mcp; then
    echo -e "\n${CYAN}  [6/6] ida-pro-mcp (IDA 桥接)${RESET}"
    dst="$TOOLS_DIR/ida-pro-mcp"
    if [ "$FORCE" -eq 0 ] && [ -d "$dst" ]; then
        ok "已存在，跳过"
        info "（IDA 本体需你自备，见 MANUAL/IDA-PRO.md；本脚本不装它）"
        mark OK ida-pro-mcp
    else
        py="$(find_python)" || py=""
        if [ -z "$py" ]; then
            warn "未找到 Python，无法 pip install ida-pro-mcp"
            mark FAIL ida-pro-mcp
        else
            info "pip install ida-pro-mcp （解释器: ${py}）..."
            if "$py" -m pip install --quiet ida-pro-mcp; then
                mkdir -p "$dst"
                ok "ida-pro-mcp 已装入该 Python 环境"
                info "（IDA 本体需你自备，见 MANUAL/IDA-PRO.md）"
                mark OK ida-pro-mcp
            else
                warn "ida-pro-mcp 安装失败（未改动解释器以外的配置）"
                mark FAIL ida-pro-mcp
            fi
        fi
    fi
fi

# ---------------------------------------------------------------- PATH
echo -e "\n${CYAN}  [PATH] 用户 PATH${RESET}"
warn "跳过：不修改用户 PATH。"
info "Windows 版写入的是用户环境变量；Unix 没有对等的单一注册位置。"
info "本脚本不改 ~/.zshrc、~/.bashrc、~/.profile，也不改 ~/.pi。"
usable=""
if [ -f "$TOOLS_DIR/jadx/bin/jadx" ]; then
    usable="$usable $TOOLS_DIR/jadx/bin"
fi
if [ -x "$TOOLS_DIR/apktool/apktool" ] || [ -f "$TOOLS_DIR/apktool/apktool.jar" ]; then
    usable="$usable $TOOLS_DIR/apktool"
fi
if [ -x "$TOOLS_DIR/radare2/bin/radare2" ] || [ -x "$TOOLS_DIR/radare2/bin/r2" ]; then
    usable="$usable $TOOLS_DIR/radare2/bin"
fi
if [ -n "$(printf '%s' "$usable" | tr -d '[:space:]')" ]; then
    info "若要在当前 shell 临时使用，可自行执行（本脚本没有执行）："
    echo "        export PATH=\"$(printf '%s' "$usable" | sed 's/^ *//; s/  */:/g'):\$PATH\""
else
    info "没有发现可加入 PATH 的 Unix 可执行文件（.exe / .bat 不算）。"
fi

# ---------------------------------------------------------------- 汇总
echo -e "\n${WHITE}  ---------- 工具修复汇总 ----------${RESET}"
ok_n=0
fail_n=0
skip_n=0
if [ -s "$RESULTS" ]; then
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        st="${line%% *}"
        nm="${line#* }"
        case "$st" in
            OK)   echo "    [OK]   $nm"; ok_n=$((ok_n + 1)) ;;
            FAIL) echo "    [FAIL] $nm"; fail_n=$((fail_n + 1)) ;;
            SKIP) echo "    [SKIP] $nm"; skip_n=$((skip_n + 1)) ;;
            *)    echo "    [??]   $line" ;;
        esac
    done < "$RESULTS"
else
    warn "没有匹配的工具"
fi

if [ "$skip_n" -gt 0 ]; then
    echo -e "    ${YELLOW}跳过项没有被修，也没有被记成成功。${RESET}"
fi

if [ "$fail_n" -gt 0 ]; then
    echo -e "\n    ${YELLOW}失败项可重跑本脚本，或按 MANUAL/PREREQUISITES.md 手动处理。${RESET}"
    exit 1
fi

if [ -n "$(printf '%s' "$ONLY" | tr -d '[:space:]')" ] && [ "$ok_n" -eq 0 ]; then
    echo -e "\n    ${YELLOW}--only 点名的项目全部跳过，没有修成任何一件。${RESET}"
    exit 2
fi

exit 0
