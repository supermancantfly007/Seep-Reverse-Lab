"""TVBox / CatVod spider 入口与硬编码线索提取。"""
from __future__ import annotations

import os
import re
from datetime import datetime
from typing import Any, Dict, List
from urllib.parse import urlparse

from .common import (
    ensure_dir, flag, intval, now_iso, resolve_tool, run_tool, work_root, write_evidence,
)

ENTRIES = {
    "homeContent": r"homeContent\s*\(",
    "categoryContent": r"categoryContent\s*\(",
    "detailContent": r"detailContent\s*\(",
    "playerContent": r"playerContent\s*\(",
    "searchContent": r"searchContent\s*\(",
    "homeVideoContent": r"homeVideoContent\s*\(",
}


def _jadx() -> str:
    hit = resolve_tool("jadx")
    if hit:
        return hit
    here = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "mcp", "Tool", "safe", "jadx", "bin", "jadx"))
    if os.path.isfile(here):
        return here
    raise SystemExit("未找到 jadx。确认 Tool/mcp/Tool/safe/jadx 或 PATH 里有 jadx。")


def _scan(files: List[str], src_dir: str, pattern: str, limit: int, ignore_case: bool = False) -> List[Dict[str, Any]]:
    flags = re.IGNORECASE if ignore_case else 0
    rx = re.compile(pattern, flags)
    hits = []
    for path in files:
        if len(hits) >= limit:
            break
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        rel = os.path.relpath(path, src_dir)
        for m in rx.finditer(text):
            if len(hits) >= limit:
                break
            line = text.count("\n", 0, m.start()) + 1
            hits.append({"File": rel, "Match": m.group(0).strip(), "Line": line})
    return hits


def run(args: Dict[str, Any]) -> None:
    target = args.get("Path") or ""
    if not target or not os.path.exists(target):
        raise SystemExit("目标不存在: %s" % target)
    target = os.path.abspath(target)
    base = os.path.splitext(os.path.basename(target))[0]
    out_dir = args.get("OutDir") or os.path.join(
        work_root(), "spider-%s-%s" % (base, datetime.now().strftime("%Y%m%d-%H%M%S"))
    )
    ensure_dir(out_dir)
    src_dir = os.path.join(out_dir, "src")
    skip = flag(args, "SkipDecompile")
    max_snippets = intval(args, "MaxSnippets", 3)
    jadx_cmd = "skipped"

    if not skip:
        jadx_cmd = _jadx()
        if not os.path.isdir(src_dir):
            log = run_tool(jadx_cmd, ["-d", src_dir, "--no-res", "--show-bad-code", target], timeout=intval(args, "TimeoutSec", 600))
            if not os.path.isdir(src_dir):
                if "No classes" in log:
                    os.makedirs(src_dir, exist_ok=True)
                else:
                    tail = log[-1200:]
                    raise SystemExit("jadx 反编译失败（未生成输出目录）。日志尾部：\n%s" % tail)
    elif not os.path.isdir(src_dir):
        raise SystemExit("指定了 -SkipDecompile，但 %s 不存在" % src_dir)

    java_files = []
    for root, _dirs, names in os.walk(src_dir):
        for name in names:
            if name.endswith((".java", ".kt")):
                java_files.append(os.path.join(root, name))
    if not java_files:
        raise SystemExit("反编译目录里没有源码文件: %s" % src_dir)

    entries = []
    for key, pattern in ENTRIES.items():
        hits = _scan(java_files, src_dir, pattern, 6)
        files = sorted({h["File"] for h in hits})
        entries.append({"Entry": key, "Found": bool(hits), "Files": files})

    base_spider = _scan(java_files, src_dir, r"extends\s+(com\.github\.catvod\.crawler\.)?Spider", 10)
    urls = _scan(java_files, src_dir, r"https?://[A-Za-z0-9.\-:]+[^\s\"')\\]*", 200, True)
    domains = []
    for hit in urls:
        try:
            host = urlparse(hit["Match"]).hostname
        except Exception:
            host = ""
        if host and host not in domains:
            domains.append(host)
    domains.sort()
    paths = _scan(
        java_files, src_dir,
        r'(?i)("[^"]*?/(api|vod|json|php)[^"]*"|[?&]ac=(list|videolist|detail)|/[A-Za-z0-9_\-]+\?[A-Za-z0-9_\-]+=)',
        80,
    )
    secrets = _scan(
        java_files, src_dir,
        r'(?i)(api[_-]?key|secret|token|appid|appkey|access[_-]?key|password|passwd)\s*[=:]\s*"[^"]{4,}"',
        40,
    )
    header_sets = _scan(
        java_files, src_dir,
        r'(?i)\.put\(\s*"(Referer|User-Agent|Origin|Cookie|X-[A-Za-z\-]+)"\s*,\s*"[^"]*"',
        40,
    )
    crypto_calls = _scan(java_files, src_dir, r"(Base64\.decode|Base64\.encode|Cipher\.getInstance|MessageDigest\.getInstance|AES/|DES/)", 40)
    kinds = []
    for hit in crypto_calls:
        m = hit["Match"]
        if "Base64" in m:
            kind = "Base64"
        elif "MessageDigest" in m:
            kind = "MessageDigest(摘要)"
        elif "Cipher" in m:
            kind = "Cipher(对称加密)"
        else:
            kind = m
        if kind not in kinds:
            kinds.append(kind)
    short = 0
    for path in java_files:
        stem = os.path.splitext(os.path.basename(path))[0]
        if re.fullmatch(r"[A-Za-z]{1,2}", stem):
            short += 1
    ratio = round(100.0 * short / len(java_files), 1) if java_files else 0

    found = [e["Entry"] for e in entries if e["Found"]]
    missing = [e["Entry"] for e in entries if not e["Found"]]
    if not found:
        verdict, level = "🔴 未定位到任何 Spider 入口 —— 可能不是 CatVod spider，或方法被字符串反射调用", "FAIL"
    elif "detailContent" in found and "playerContent" in found:
        verdict, level = "🟢 已定位取流链路：%s" % " / ".join(found), "OK"
    else:
        verdict, level = "🟡 部分入口命中：%s（缺 %s）" % (" / ".join(found), ", ".join(missing)), "P1"

    risks = []
    if secrets:
        risks.append("硬编码凭据 %s 处（源码里直接可见，属 CWE-798）" % len(secrets))
    if header_sets:
        risks.append("代码内硬编码请求头 %s 处（防盗链绕过逻辑所在）" % len(header_sets))
    if crypto_calls:
        risks.append("加密/编码调用：%s（可能有字符串保护，需跟进）" % ", ".join(kinds))
    if ratio >= 30:
        risks.append("混淆程度较高（单字母类名占比 %s%%），疑似 ProGuard/Allatori" % ratio)
    if len(domains) > 6:
        risks.append("硬编码域名 %s 个，源站可能多套切换" % len(domains))

    evidence = {
        "Schema": "seep.spider.extract/1",
        "GeneratedAt": now_iso(),
        "Target": target,
        "Jadx": jadx_cmd,
        "SourceFiles": len(java_files),
        "Entries": entries,
        "BaseSpider": base_spider,
        "Domains": domains,
        "Urls": urls[:40],
        "ApiPaths": paths[:40],
        "Secrets": secrets[:max_snippets],
        "HeaderSets": header_sets[:20],
        "CryptoKinds": kinds,
        "Obfuscation": {"ShortClassNames": short, "Ratio": ratio},
        "Verdict": {"Level": level, "Text": verdict, "Risks": risks},
        "OutDir": out_dir,
    }
    md = ["# Spider 提取报告", "", "- 源码文件: %s" % len(java_files), "- 结论: **%s**" % verdict, "", "## 入口", ""]
    for e in entries:
        md.append("- %s %s" % ("✅" if e["Found"] else "—", e["Entry"]))
    write_evidence(out_dir, evidence, "\n".join(md) + "\n")
    return evidence
