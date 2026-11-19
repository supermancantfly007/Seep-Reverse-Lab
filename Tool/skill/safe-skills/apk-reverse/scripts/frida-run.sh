#!/usr/bin/env bash
# frida-run.sh — 与 frida-run.ps1 同一套参数。macOS/Linux 用本脚本；Windows 继续用 frida-run.ps1。
# 列设备/进程走本机 python 的 frida 模块；注入走本机 frida CLI。
#
# 用法:
#   bash frida-run.sh --list-devices
#   bash frida-run.sh --usb --list-processes
#   bash frida-run.sh --usb --spawn --package com.example.app --script-path hook.js
#   bash frida-run.sh --process name --script-path hook.js [--remote-host 127.0.0.1:27042] [--pause]

set -euo pipefail

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

resolve_python() {
    if command -v python3 >/dev/null 2>&1; then
        command -v python3
        return 0
    fi
    if command -v python >/dev/null 2>&1; then
        command -v python
        return 0
    fi
    die "Missing required CLI tool: python"
}

resolve_frida() {
    if command -v frida >/dev/null 2>&1; then
        command -v frida
        return 0
    fi
    local cand
    for cand in \
        "${HOME}/.seep/android/frida-env/bin/frida" \
        "${HOME}/.seep/android/bin/frida"
    do
        if [[ -f "$cand" ]]; then
            echo "$cand"
            return 0
        fi
    done
    die "Missing required CLI tool: frida (install frida-tools: pip install frida-tools)"
}

PACKAGE=""
PROCESS=""
REMOTE_HOST="127.0.0.1:27042"
SCRIPT_PATH=""
USB=0
SPAWN=0
PAUSE=0
LIST_DEVICES=0
LIST_PROCESSES=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --package)
            need_value "$1" "${2:-}"
            PACKAGE="$2"
            shift 2
            ;;
        --process)
            need_value "$1" "${2:-}"
            PROCESS="$2"
            shift 2
            ;;
        --remote-host)
            need_value "$1" "${2:-}"
            REMOTE_HOST="$2"
            shift 2
            ;;
        --script-path)
            need_value "$1" "${2:-}"
            SCRIPT_PATH="$2"
            shift 2
            ;;
        --usb) USB=1; shift ;;
        --spawn) SPAWN=1; shift ;;
        --pause) PAUSE=1; shift ;;
        --list-devices) LIST_DEVICES=1; shift ;;
        --list-processes) LIST_PROCESSES=1; shift ;;
        -*)
            die "未知选项: $1"
            ;;
        *)
            die "未知参数: $1"
            ;;
    esac
done

PYTHON_BIN="$(resolve_python)"
FRIDA_BIN="$(resolve_frida)"

if [[ "$LIST_DEVICES" -eq 1 ]]; then
    "$PYTHON_BIN" -c 'import frida
for d in frida.enumerate_devices():
    print("%s\t%s\t%s" % (d.id, d.type, d.name))'
    exit $?
fi

TARGET="$PACKAGE"
if [[ -z "$TARGET" ]]; then
    TARGET="$PROCESS"
fi
if [[ -z "$TARGET" && "$LIST_PROCESSES" -eq 0 ]]; then
    die "Provide --package or --process, or use --list-processes."
fi

if [[ "$LIST_PROCESSES" -eq 1 ]]; then
    if [[ "$USB" -eq 1 ]]; then
        SEEP_FRIDA_MODE="usb"
    else
        SEEP_FRIDA_MODE="remote-host"
    fi
    SEEP_FRIDA_HOST="$REMOTE_HOST" SEEP_FRIDA_MODE="$SEEP_FRIDA_MODE" "$PYTHON_BIN" -c 'import os, frida
mode = os.environ.get("SEEP_FRIDA_MODE", "")
host = os.environ.get("SEEP_FRIDA_HOST", "")
manager = frida.get_device_manager()
device = frida.get_usb_device() if mode == "usb" else manager.add_remote_device(host)
for p in device.enumerate_processes():
    print("%s\t%s" % (p.pid, p.name))'
    exit $?
fi

if [[ ! -f "$SCRIPT_PATH" ]]; then
    die "Frida script not found: $SCRIPT_PATH"
fi

ARGS=()
if [[ "$USB" -eq 1 ]]; then
    ARGS+=("-U")
else
    ARGS+=("-H" "$REMOTE_HOST")
fi
if [[ "$SPAWN" -eq 1 ]]; then
    ARGS+=("-f")
else
    ARGS+=("-n")
fi
ARGS+=("$TARGET" "-l" "$SCRIPT_PATH")
if [[ "$PAUSE" -eq 0 ]]; then
    ARGS+=("--no-pause")
fi

"$FRIDA_BIN" "${ARGS[@]}"
exit $?
