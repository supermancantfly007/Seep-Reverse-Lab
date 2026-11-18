"""HTTP 头变体矩阵重放。JSON 契约与 http-replay.ps1 一致（seep.http.replay/1）。"""
from __future__ import annotations

import os
import time
from typing import Any, Dict, List

from .common import (
    body_hash, body_sketch, curl_method_body, default_out, fetch, finish, flag,
    header_table, intval, now_iso, url_from_curl, write_evidence,
)

MOBILE_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
)


def run(args: Dict[str, Any]) -> None:
    headers = header_table(args)
    url = args.get("Url") or ""
    curl = args.get("Curl") or ""
    if curl and not url:
        url = url_from_curl(curl)
    method = (args.get("Method") or "GET").upper()
    body = args.get("Body") or ""
    if curl:
        curl_method, curl_body = curl_method_body(curl)
        if method == "GET" and curl_method:
            method = curl_method
        if not body and curl_body:
            body = curl_body
    if not url:
        raise SystemExit("必须提供 -Url 或 -Curl")

    out_dir = args.get("OutDir") or default_out("replay")
    os.makedirs(out_dir, exist_ok=True)
    timeout = intval(args, "TimeoutSec", 30)
    content_type = args.get("ContentType") or ""

    ua = headers.get("User-Agent", "")
    ref = headers.get("Referer", "")
    org = headers.get("Origin", "")
    ck = headers.get("Cookie", "")
    matrix: List[Dict[str, Any]] = [
        {"Name": "full", "Desc": "全头（基准）", "Headers": dict(headers)},
        {"Name": "no-headers", "Desc": "去掉全部头", "Headers": {}},
    ]
    if ua:
        matrix.append({"Name": "ua-only", "Desc": "只留 UA", "Headers": {"User-Agent": ua}})
    if ref:
        matrix.append({"Name": "referer-only", "Desc": "只留 Referer", "Headers": {"Referer": ref}})
    if org:
        matrix.append({"Name": "origin-only", "Desc": "只留 Origin", "Headers": {"Origin": org}})
    if ck:
        matrix.append({"Name": "cookie-only", "Desc": "只留 Cookie", "Headers": {"Cookie": ck}})
    if len(headers) > 1:
        for key in list(headers.keys()):
            kept = {k: v for k, v in headers.items() if k != key}
            matrix.append({"Name": "minus-%s" % key, "Desc": "剔除 %s" % key, "Headers": kept})
    if ua:
        swapped = dict(headers)
        swapped["User-Agent"] = MOBILE_UA
        matrix.append({"Name": "mobile-ua", "Desc": "换成移动端 UA", "Headers": swapped})

    results = []
    body_dir = os.path.join(out_dir, "bodies")
    if flag(args, "SaveBodies"):
        os.makedirs(body_dir, exist_ok=True)
    for variant in matrix:
        resp = fetch(url, headers=variant["Headers"], method=method, body=body,
                     content_type=content_type, timeout=timeout)
        if flag(args, "SaveBodies") and resp.get("Body"):
            safe = "".join(ch if ch not in '\\/:*?"<>|' else "_" for ch in variant["Name"])
            with open(os.path.join(body_dir, safe + ".txt"), "w", encoding="utf-8") as fh:
                fh.write(resp["Body"])
        results.append({
            "Variant": variant["Name"],
            "Desc": variant["Desc"],
            "Status": resp["Status"],
            "Length": resp["Length"],
            "ContentType": resp["ContentType"],
            "Msn": resp["Msn"],
            "BodyHash": body_hash(resp.get("Body") or ""),
            "Sketch": body_sketch(resp.get("Body") or ""),
            "Error": resp.get("Error") or "",
        })

    rate_results = []
    rate_n = intval(args, "RateTest", 0)
    interval = intval(args, "RateIntervalMs", 200) / 1000.0
    for i in range(1, rate_n + 1):
        resp = fetch(url, headers=headers, method=method, body=body,
                     content_type=content_type, timeout=timeout)
        rate_results.append({"Round": i, "Status": resp["Status"], "Length": resp["Length"], "Msn": resp["Msn"]})
        if interval > 0 and i < rate_n:
            time.sleep(interval)

    base = next((r for r in results if r["Variant"] == "full"), None)
    base_ok = bool(base and 200 <= base["Status"] < 400)
    key_headers: List[str] = []
    wrong_headers: List[str] = []
    if base_ok and base:
        for row in results:
            if row["Variant"] == "full":
                continue
            if row["Status"] < 200 or row["Status"] >= 400:
                key_headers.append(row["Variant"])
            elif row["BodyHash"] != base["BodyHash"] and row["Length"] > 0:
                wrong_headers.append(row["Variant"])

    if not base_ok:
        if base and base["Status"] == 0:
            verdict, level = "⚪ 全头请求直接失败 —— 网络层问题（DNS/TLS/超时），先排除环境", "INVALID"
        else:
            status = base["Status"] if base else 0
            verdict, level = "🟠 全头请求仍失败（HTTP %s）—— 需要额外凭据：登录态 Cookie / 有效签名 / 设备指纹 / IP 白名单" % status, "P1"
    elif not key_headers:
        verdict, level = "🟡 头不是门槛 —— 所有变体都能过，鉴权在别处（时间戳签名 / token 参数 / IP / 频率）", "P1"
    else:
        verdict, level = "🟢 定位到门槛头：%s —— 缺了就失败" % ", ".join(key_headers), "OK"

    rate_verdict = ""
    if rate_results:
        codes = sorted({r["Status"] for r in rate_results})
        blocked = [r for r in rate_results if r["Status"] in (429, 403, 503)]
        if blocked:
            blocked_codes = sorted({r["Status"] for r in blocked})
            rate_verdict = "🟠 触发频控：%s/%s 次被拒（状态 %s）" % (len(blocked), len(rate_results), ",".join(map(str, blocked_codes)))
        else:
            rate_verdict = "🟢 %s 次连续请求未被拦截（状态集合 %s）" % (rate_n, ",".join(map(str, codes)))

    evidence = {
        "Schema": "seep.http.replay/1",
        "GeneratedAt": now_iso(),
        "Request": {"Url": url, "Method": method, "HasBody": bool(body), "Headers": list(headers.keys())},
        "Results": results,
        "RateTest": rate_results,
        "Verdict": {
            "Level": level,
            "Text": verdict,
            "GateHeaders": key_headers,
            "SemanticDiff": wrong_headers,
            "Rate": rate_verdict,
        },
        "OutDir": out_dir,
    }
    lines = [
        "# HTTP 重放举证报告", "",
        "- 生成: %s" % evidence["GeneratedAt"],
        "- 请求: `%s %s`" % (method, url),
        "- 结论: **%s**" % verdict,
    ]
    if rate_verdict:
        lines.append("- 频控: %s" % rate_verdict)
    lines += ["", "| 变体 | 状态 | 长度 | 指纹 |", "| :--- | ---: | ---: | :--- |"]
    for row in results:
        lines.append("| `%s` | %s | %s | `%s` |" % (row["Variant"], row["Status"], row["Length"], row["BodyHash"]))
    if key_headers:
        lines += ["", "**门槛头**: %s" % ", ".join(key_headers)]
    write_evidence(out_dir, evidence, "\n".join(lines) + "\n")
    return evidence
