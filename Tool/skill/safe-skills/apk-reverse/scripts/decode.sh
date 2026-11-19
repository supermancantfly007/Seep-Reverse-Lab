#!/usr/bin/env bash
# decode.sh — 与 decode.ps1 同一套参数和摘要。macOS/Linux 用本脚本；Windows 继续用 decode.ps1。
# jadx 调本机二进制；apktool 用 java -jar，不走 apktool 包装脚本。
#
# 用法:
#   bash decode.sh --apk-path app.apk [--name demo] [--out-root dir]
#                  [--skip-jadx] [--skip-apktool] [--clean]
#   bash decode.sh app.apk [同上可选参数]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# scripts -> apk-reverse -> safe-skills -> skill -> Tool
TOOL_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
SAFE_DIR="$TOOL_DIR/mcp/Tool/safe"
SKILL_TOOL_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

die() {
    echo "$*" >&2
    exit 1
}

need_value() {
    local opt="$1"
    local value="${2:-}"
    if [[ -z "$value" || "$value" == -* ]]; then
        die "缺少参数值: $opt"
    fi
}

resolve_java() {
    if [[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME}/bin/java" ]]; then
        echo "${JAVA_HOME}/bin/java"
        return 0
    fi
    if command -v java >/dev/null 2>&1; then
        command -v java
        return 0
    fi
    die "Missing required CLI tool: java"
}

resolve_jadx() {
    if command -v jadx >/dev/null 2>&1; then
        command -v jadx
        return 0
    fi
    local cand
    for cand in \
        "$SAFE_DIR/jadx/bin/jadx" \
        "$SKILL_TOOL_ROOT/jadx/bin/jadx" \
        "$TOOL_DIR/jadx/bin/jadx"
    do
        if [[ -f "$cand" ]]; then
            echo "$cand"
            return 0
        fi
    done
    die "Missing required CLI tool: jadx"
}

resolve_apktool_jar() {
    local cand wrapper dir
    for cand in \
        "$SAFE_DIR/apktool/apktool.jar" \
        "$SKILL_TOOL_ROOT/apktool/apktool.jar" \
        "$TOOL_DIR/apktool/apktool.jar"
    do
        if [[ -f "$cand" ]]; then
            echo "$cand"
            return 0
        fi
    done
    wrapper="$(command -v apktool 2>/dev/null || true)"
    if [[ -n "$wrapper" ]]; then
        dir="$(cd "$(dirname "$wrapper")" && pwd)"
        if [[ -f "$dir/apktool.jar" ]]; then
            echo "$dir/apktool.jar"
            return 0
        fi
    fi
    die "Missing apktool.jar (call java -jar; looked under $SAFE_DIR/apktool and PATH)"
}

safe_name() {
    local raw
    raw="$(basename "$1")"
    raw="${raw%.*}"
    if [[ -z "$raw" ]]; then
        raw="apk"
    fi
    printf '%s\n' "$raw" | sed 's/[^A-Za-z0-9._-]/_/g'
}

count_files() {
    local dir="$1"
    local pattern="$2"
    if [[ ! -d "$dir" ]]; then
        echo 0
        return 0
    fi
    find "$dir" -type f -name "$pattern" | wc -l | tr -d ' '
}

count_smali_dirs() {
    local dir="$1"
    if [[ ! -d "$dir" ]]; then
        echo 0
        return 0
    fi
    find "$dir" -maxdepth 1 -mindepth 1 -type d -name 'smali*' | wc -l | tr -d ' '
}

manifest_package() {
    local manifest="$1"
    local py=""
    if [[ ! -f "$manifest" ]]; then
        echo ""
        return 0
    fi
    if command -v python3 >/dev/null 2>&1; then
        py="$(command -v python3)"
    elif command -v python >/dev/null 2>&1; then
        py="$(command -v python)"
    fi
    if [[ -n "$py" ]]; then
        "$py" -c 'import sys, xml.etree.ElementTree as ET
try:
    print(ET.parse(sys.argv[1]).getroot().attrib.get("package", ""))
except Exception:
    print("")' "$manifest"
        return 0
    fi
    sed -n 's/.*package="\([^"]*\)".*/\1/p' "$manifest" | head -n 1 || true
}

APK_PATH=""
NAME=""
OUT_ROOT=""
SKIP_JADX=0
SKIP_APKTOOL=0
CLEAN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --apk-path)
            need_value "$1" "${2:-}"
            APK_PATH="$2"
            shift 2
            ;;
        --name)
            need_value "$1" "${2:-}"
            NAME="$2"
            shift 2
            ;;
        --out-root)
            need_value "$1" "${2:-}"
            OUT_ROOT="$2"
            shift 2
            ;;
        --skip-jadx) SKIP_JADX=1; shift ;;
        --skip-apktool) SKIP_APKTOOL=1; shift ;;
        --clean) CLEAN=1; shift ;;
        -*)
            die "未知选项: $1"
            ;;
        *)
            if [[ -z "$APK_PATH" ]]; then
                APK_PATH="$1"
                shift
            else
                die "未知参数: $1"
            fi
            ;;
    esac
done

if [[ -z "$APK_PATH" ]]; then
    die "用法: $0 --apk-path <apk> [--name <name>] [--out-root <dir>] [--skip-jadx] [--skip-apktool] [--clean]"
fi
if [[ ! -f "$APK_PATH" ]]; then
    die "APK not found: $APK_PATH"
fi

JADX_BIN=""
APKTOOL_JAR=""
JAVA_BIN=""
if [[ "$SKIP_JADX" -eq 0 ]]; then
    JADX_BIN="$(resolve_jadx)"
fi
if [[ "$SKIP_APKTOOL" -eq 0 ]]; then
    APKTOOL_JAR="$(resolve_apktool_jar)"
    JAVA_BIN="$(resolve_java)"
fi

if [[ -z "$NAME" ]]; then
    NAME="$(safe_name "$APK_PATH")"
fi
if [[ -z "$OUT_ROOT" ]]; then
    OUT_ROOT="$(dirname "$APK_PATH")"
    if [[ -z "$OUT_ROOT" || "$OUT_ROOT" == "." ]]; then
        if [[ "$APK_PATH" != */* ]]; then
            OUT_ROOT="$(pwd)"
        fi
    fi
fi

TASK_ROOT="$OUT_ROOT/$NAME"
JADX_OUT="$TASK_ROOT/jadx"
APKTOOL_OUT="$TASK_ROOT/apktool"

mkdir -p "$OUT_ROOT"
if [[ "$CLEAN" -eq 1 && -d "$TASK_ROOT" ]]; then
    rm -rf "$TASK_ROOT"
fi
mkdir -p "$TASK_ROOT"

JADX_EXIT=""
if [[ "$SKIP_JADX" -eq 0 ]]; then
    rm -rf "$JADX_OUT"
    set +e
    "$JADX_BIN" -d "$JADX_OUT" "$APK_PATH"
    JADX_EXIT=$?
    set -e
fi

APKTOOL_EXIT=""
if [[ "$SKIP_APKTOOL" -eq 0 ]]; then
    rm -rf "$APKTOOL_OUT"
    set +e
    "$JAVA_BIN" -jar "$APKTOOL_JAR" d "$APK_PATH" -o "$APKTOOL_OUT" -f
    APKTOOL_EXIT=$?
    set -e
fi

PACKAGE=""
if [[ "$SKIP_APKTOOL" -eq 0 ]]; then
    PACKAGE="$(manifest_package "$APKTOOL_OUT/AndroidManifest.xml")"
fi
JAVA_COUNT="$(count_files "$JADX_OUT" '*.java')"
SMALI_DIRS="$(count_smali_dirs "$APKTOOL_OUT")"
SO_COUNT="$(count_files "$APKTOOL_OUT" '*.so')"
XML_COUNT="$(count_files "$APKTOOL_OUT" '*.xml')"

echo "task_root=$TASK_ROOT"
echo "jadx_out=$JADX_OUT"
echo "apktool_out=$APKTOOL_OUT"
echo "package=$PACKAGE"
echo "jadx_exit_code=$JADX_EXIT"
echo "apktool_exit_code=$APKTOOL_EXIT"
echo "java_files=$JAVA_COUNT"
echo "smali_dirs=$SMALI_DIRS"
echo "so_files=$SO_COUNT"
echo "xml_files=$XML_COUNT"

if [[ -n "$JADX_EXIT" && "$JADX_EXIT" != "0" ]]; then
    echo "warning=jadx returned non-zero exit code; inspect output but treat exported sources as usable if present"
fi
