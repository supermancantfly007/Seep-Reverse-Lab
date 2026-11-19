#!/usr/bin/env bash
# manifest-summary.sh — 与 manifest-summary.ps1 同一套输出。macOS/Linux 用本脚本；Windows 继续用 .ps1。
#
# 用法:
#   bash manifest-summary.sh --manifest-path apktool_out/AndroidManifest.xml

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

MANIFEST=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --manifest-path)
            need_value "$1" "${2:-}"
            MANIFEST="$2"
            shift 2
            ;;
        -*)
            die "未知选项: $1"
            ;;
        *)
            if [[ -z "$MANIFEST" ]]; then
                MANIFEST="$1"
                shift
            else
                die "未知参数: $1"
            fi
            ;;
    esac
done

if [[ -z "$MANIFEST" || ! -f "$MANIFEST" ]]; then
    die "Manifest not found: $MANIFEST"
fi

PY=""
if command -v python3 >/dev/null 2>&1; then
    PY="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
    PY="$(command -v python)"
else
    die "Missing required CLI tool: python"
fi

"$PY" - "$MANIFEST" <<'PY'
import sys
import xml.etree.ElementTree as ET

NS = "http://schemas.android.com/apk/res/android"
path = sys.argv[1]

def attr(node, name):
    return node.attrib.get("{%s}%s" % (NS, name), "") or ""

def children(parent, tag):
    if parent is None:
        return []
    return [el for el in list(parent) if el.tag == tag]

try:
    manifest = ET.parse(path).getroot()
except ET.ParseError as exc:
    sys.stderr.write("Manifest parse failed: %s\n" % exc)
    sys.exit(1)

print("package=%s" % manifest.attrib.get("package", ""))

perms = children(manifest, "uses-permission")
print("permission_count=%d" % len(perms))
for perm in perms:
    name = attr(perm, "name")
    if name:
        print("permission=%s" % name)

app = None
for el in list(manifest):
    if el.tag == "application":
        app = el
        break

for label in ("activity", "service", "receiver", "provider"):
    nodes = children(app, label)
    print("%s_count=%d" % (label, len(nodes)))
    for node in nodes:
        print("%s=%s\t%s\t%s" % (label, attr(node, "name"), attr(node, "exported"), attr(node, "enabled")))

mains = []
for activity in children(app, "activity"):
    for filt in children(activity, "intent-filter"):
        has_main = any(attr(node, "name") == "android.intent.action.MAIN" for node in children(filt, "action"))
        has_launcher = any(attr(node, "name") == "android.intent.category.LAUNCHER" for node in children(filt, "category"))
        if has_main and has_launcher:
            mains.append(attr(activity, "name"))

seen = []
for entry in mains:
    if entry not in seen:
        seen.append(entry)
        print("main_activity=%s" % entry)
PY
