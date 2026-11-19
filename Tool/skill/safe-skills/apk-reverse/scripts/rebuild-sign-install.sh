#!/usr/bin/env bash
# rebuild-sign-install.sh — 与 rebuild-sign-install.ps1 同一套参数和产物名。
# macOS/Linux 用本脚本；Windows 继续用 rebuild-sign-install.ps1。
# apktool 用 java -jar；zipalign / apksigner / keytool / adb 用本机工具。
#
# 用法:
#   bash rebuild-sign-install.sh --project-dir apktool_out [--out-dir dir] [--base-name name]
#       [--keystore path] [--key-alias androiddebugkey] [--store-pass android] [--key-pass android]
#       [--device-serial SERIAL] [--install] [--reinstall] [--clean]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
SAFE_DIR="$TOOL_DIR/mcp/Tool/safe"
SKILL_TOOL_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
DEFAULT_KEYSTORE="$SCRIPT_DIR/../debug.keystore"

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

latest_build_tool() {
    local name="$1"
    local sdk bt cand
    local sdks=()
    [[ -n "${ANDROID_HOME:-}" ]] && sdks+=("$ANDROID_HOME")
    [[ -n "${ANDROID_SDK_ROOT:-}" ]] && sdks+=("$ANDROID_SDK_ROOT")
    sdks+=("${HOME}/Library/Android/sdk" "${HOME}/Android/Sdk")
    for sdk in "${sdks[@]}"; do
        [[ -d "$sdk/build-tools" ]] || continue
        bt="$(find "$sdk/build-tools" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -r | head -n 1 || true)"
        [[ -n "$bt" ]] || continue
        cand="$bt/$name"
        if [[ -f "$cand" ]]; then
            echo "$cand"
            return 0
        fi
    done
    return 1
}

resolve_tool() {
    local name="$1"
    local cand
    if command -v "$name" >/dev/null 2>&1; then
        command -v "$name"
        return 0
    fi
    case "$name" in
        keytool)
            if [[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME}/bin/keytool" ]]; then
                echo "${JAVA_HOME}/bin/keytool"
                return 0
            fi
            ;;
        adb)
            for cand in \
                "${ANDROID_HOME:-}/platform-tools/adb" \
                "${ANDROID_SDK_ROOT:-}/platform-tools/adb" \
                "${HOME}/Library/Android/sdk/platform-tools/adb" \
                "${HOME}/Android/Sdk/platform-tools/adb" \
                "${HOME}/.seep/android/platform-tools/adb"
            do
                if [[ -n "$cand" && -f "$cand" ]]; then
                    echo "$cand"
                    return 0
                fi
            done
            ;;
        zipalign|apksigner)
            if cand="$(latest_build_tool "$name")"; then
                echo "$cand"
                return 0
            fi
            ;;
    esac
    die "Missing required CLI tool: $name"
}

ensure_debug_keystore() {
    local path="$1"
    local keytool="$2"
    local alias="$3"
    local store_pass="$4"
    local key_pass="$5"
    if [[ -f "$path" ]]; then
        return 0
    fi
    mkdir -p "$(dirname "$path")"
    "$keytool" -genkeypair -v \
        -keystore "$path" \
        -storepass "$store_pass" \
        -keypass "$key_pass" \
        -alias "$alias" \
        -keyalg RSA -keysize 2048 -validity 10000 \
        -dname "CN=Android Debug,O=OpenCode,C=CN"
}

PROJECT_DIR=""
OUT_DIR=""
BASE_NAME=""
KEYSTORE="$DEFAULT_KEYSTORE"
KEY_ALIAS="androiddebugkey"
STORE_PASS="android"
KEY_PASS="android"
DEVICE_SERIAL=""
DO_INSTALL=0
REINSTALL=0
CLEAN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project-dir)
            need_value "$1" "${2:-}"
            PROJECT_DIR="$2"
            shift 2
            ;;
        --out-dir)
            need_value "$1" "${2:-}"
            OUT_DIR="$2"
            shift 2
            ;;
        --base-name)
            need_value "$1" "${2:-}"
            BASE_NAME="$2"
            shift 2
            ;;
        --keystore)
            need_value "$1" "${2:-}"
            KEYSTORE="$2"
            shift 2
            ;;
        --key-alias)
            need_value "$1" "${2:-}"
            KEY_ALIAS="$2"
            shift 2
            ;;
        --store-pass)
            need_value "$1" "${2:-}"
            STORE_PASS="$2"
            shift 2
            ;;
        --key-pass)
            need_value "$1" "${2:-}"
            KEY_PASS="$2"
            shift 2
            ;;
        --device-serial)
            need_value "$1" "${2:-}"
            DEVICE_SERIAL="$2"
            shift 2
            ;;
        --install) DO_INSTALL=1; shift ;;
        --reinstall) REINSTALL=1; shift ;;
        --clean) CLEAN=1; shift ;;
        -*)
            die "未知选项: $1"
            ;;
        *)
            if [[ -z "$PROJECT_DIR" ]]; then
                PROJECT_DIR="$1"
                shift
            else
                die "未知参数: $1"
            fi
            ;;
    esac
done

PROJECT_DIR="${PROJECT_DIR%/}"
if [[ -z "$PROJECT_DIR" || ! -d "$PROJECT_DIR" ]]; then
    die "Project directory not found: $PROJECT_DIR"
fi

if [[ -z "$OUT_DIR" ]]; then
    OUT_DIR="$(dirname "$PROJECT_DIR")"
    if [[ -z "$OUT_DIR" || "$OUT_DIR" == "." ]]; then
        if [[ "$PROJECT_DIR" != */* ]]; then
            OUT_DIR="$(pwd)"
        fi
    fi
fi

JAVA_BIN="$(resolve_java)"
APKTOOL_JAR="$(resolve_apktool_jar)"
ZIPALIGN="$(resolve_tool zipalign)"
APKSIGNER="$(resolve_tool apksigner)"
KEYTOOL="$(resolve_tool keytool)"
ADB=""
if [[ "$DO_INSTALL" -eq 1 ]]; then
    ADB="$(resolve_tool adb)"
fi

ensure_debug_keystore "$KEYSTORE" "$KEYTOOL" "$KEY_ALIAS" "$STORE_PASS" "$KEY_PASS"
mkdir -p "$OUT_DIR"

if [[ -z "$BASE_NAME" ]]; then
    BASE_NAME="$(basename "$PROJECT_DIR")"
fi
UNSIGNED_APK="$OUT_DIR/${BASE_NAME}-unsigned.apk"
ALIGNED_APK="$OUT_DIR/${BASE_NAME}-aligned.apk"
SIGNED_APK="$OUT_DIR/${BASE_NAME}-signed.apk"

if [[ "$CLEAN" -eq 1 ]]; then
    rm -f "$UNSIGNED_APK" "$ALIGNED_APK" "$SIGNED_APK"
fi

"$JAVA_BIN" -jar "$APKTOOL_JAR" b "$PROJECT_DIR" -o "$UNSIGNED_APK" || die "apktool build failed."
"$ZIPALIGN" -f -p 4 "$UNSIGNED_APK" "$ALIGNED_APK" || die "zipalign failed."
cp -f "$ALIGNED_APK" "$SIGNED_APK"
"$APKSIGNER" sign --ks "$KEYSTORE" --ks-key-alias "$KEY_ALIAS" \
    --ks-pass "pass:$STORE_PASS" --key-pass "pass:$KEY_PASS" \
    --out "$SIGNED_APK" "$ALIGNED_APK" || die "apksigner sign failed."
"$APKSIGNER" verify --print-certs "$SIGNED_APK" || die "apksigner verify failed."

echo "unsigned_apk=$UNSIGNED_APK"
echo "aligned_apk=$ALIGNED_APK"
echo "signed_apk=$SIGNED_APK"
echo "keystore=$KEYSTORE"

if [[ "$DO_INSTALL" -eq 1 ]]; then
    ADB_ARGS=()
    if [[ -n "$DEVICE_SERIAL" ]]; then
        ADB_ARGS+=("-s" "$DEVICE_SERIAL")
    fi
    ADB_ARGS+=("install")
    if [[ "$REINSTALL" -eq 1 ]]; then
        ADB_ARGS+=("-r")
    fi
    ADB_ARGS+=("$SIGNED_APK")
    "$ADB" "${ADB_ARGS[@]}" || die "adb install failed."
    echo "install_device=$DEVICE_SERIAL"
fi
