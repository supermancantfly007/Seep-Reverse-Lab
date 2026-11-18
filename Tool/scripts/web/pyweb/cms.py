"""影视站 CMS / 暴露面指纹。只发 GET，路径表固定，默认 400ms 间隔。"""
from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Optional
from .common import (
    default_out, fetch, flag, header_table, intval, now_iso,
    origin_of, write_evidence,
)

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
CMS_PATTERNS = (
    ("苹果CMS (maccms10)", r"Powered by\s*<a[^>]*>?Maccms|maccms\.com|/template/default/html/|mac_\w+\.js|maccms", 3),
    ("苹果CMS (v10 特征路径)", r"application/admin|extend/base\.php|think\\", 2),
    ("海洋CMS (seacms)", r"seacms|海洋影视|/template/default/|mytemplate|seacms\.com", 3),
    ("织梦 (DedeCMS)", r"/dede/|DedeCMS|Power by DedeCms", 2),
    ("WordPress", r"/wp-content/|wp-includes|WordPress", 2),
    ("织梦/帝国/其他国内 CMS", r"帝国CMS|EmpireCMS|phpcms|ThinkPHP", 1),
)
PLAYERS = (
    ("MacPlayer", r"MacPlayer|player_aaaa|mac_player"),
    ("DPlayer", r"DPlayer"),
    ("video.js", r"video-js|videojs"),
    ("hls.js", r"hls\.js|Hls\.js"),
    ("ckplayer", r"ckplayer"),
    ("aliplayer", r"Aliplayer|aliplayer"),
    ("jwplayer", r"jwplayer"),
    ("artplayer", r"artplayer"),
)


def _sleep(ms: int) -> None:
    if ms > 0:
        time.sleep(ms / 1000.0)


def run(args: Dict[str, Any]) -> None:
    url = (args.get("Url") or "").strip()
    if not url:
        raise SystemExit("必须提供 -Url")
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    base = url.rstrip("/")
    headers = header_table(args)
    headers.setdefault("User-Agent", DEFAULT_UA)
    out_dir = args.get("OutDir") or default_out("cms")
    os.makedirs(out_dir, exist_ok=True)
    timeout = intval(args, "TimeoutSec", 15)
    delay = intval(args, "DelayMs", 400)
    deep = flag(args, "Deep")

    evidence: List[Dict[str, str]] = []

    def add(kind: str, value: str, source: str, note: str = "") -> None:
        evidence.append({"Kind": kind, "Value": value, "Source": source, "Note": note})

    root = fetch(base, headers=headers, timeout=timeout, max_body=1_048_576)
    add("http", "HTTP %s" % root["Status"], "GET /", "长度 %s，耗时 %sms" % (root["Length"], root["Msn"]))
    if root["Status"] == 0:
        payload = {
            "Schema": "seep.cms.fingerprint/1",
            "GeneratedAt": now_iso(),
            "Target": base,
            "Error": root["Error"],
            "Verdict": {"Level": "FAIL", "Text": "⚪ 站点不可达：%s" % root["Error"]},
            "OutDir": out_dir,
        }
        write_evidence(out_dir, payload, "# 站点不可达\n\n%s\n" % root["Error"])
        return payload

    html = root.get("Body") or ""
    rh = {k.lower(): v for k, v in (root.get("Headers") or {}).items()}
    # 保留原始大小写键用于展示，匹配用小写
    raw_headers = root.get("Headers") or {}
    server = ""
    powered = ""
    cookie = ""
    for k, v in raw_headers.items():
        lk = k.lower()
        if lk == "server":
            server = v
        elif lk == "x-powered-by":
            powered = v
        elif lk == "set-cookie":
            cookie = v
    if server:
        add("server", server, "Server 头")
    if powered:
        add("server", powered, "X-Powered-By")

    cdn: List[str] = []
    keys_l = {k.lower() for k in raw_headers}
    if "cf-ray" in keys_l or re.search(r"cloudflare", server, re.I):
        cdn.append("Cloudflare")
    if re.search(r"jsl_clearlocalstorage|__jsluid", cookie):
        cdn.append("加速乐(Jiasule)")
    if keys_l & {"x-via", "x-cache"}:
        cdn.append("CDN(X-Via/X-Cache)")
    if re.search(r"acw_sc__v2|acw_tc", cookie):
        cdn.append("阿里云WAF")
    if re.search(r"""document\.cookie\s*=\s*["']__jsl""", html):
        cdn.append("加速乐(JS挑战)")
    cdn = list(dict.fromkeys(cdn))
    for c in cdn:
        add("cdn", c, "响应头/HTML")

    cms_hits = []
    for name, rx, weight in CMS_PATTERNS:
        if re.search(rx, html, re.I):
            cms_hits.append({"Name": name, "Signal": "HTML 命中 /%s/" % rx, "Weight": weight})

    players = [name for name, rx in PLAYERS if re.search(rx, html)]
    for p in players:
        add("player", p, "HTML")
    m3u8_n = len(re.findall(r"https?://[^\"'\s]+\.m3u8[^\"'\s]*", html))
    if m3u8_n:
        add("stream", "HTML 内直出 %s 个 m3u8 地址" % m3u8_n, "HTML", "说明播放链路未做二次解析")

    origin = origin_of(base)
    api_result = None
    for api_url in (
        origin + "/api.php/provide/vod/?ac=list",
        origin + "/api.php/provide/vod/at/xml/?ac=list",
        origin + "/api.php/provide/vod/?ac=list&pg=1",
    ):
        resp = fetch(api_url, headers=headers, timeout=timeout, max_body=262144)
        _sleep(delay)
        is_json = "json" in (resp.get("ContentType") or "").lower() or re.match(r"^\s*[\{\[]", resp.get("Body") or "")
        looks = bool(re.search(r'"code"\s*:', resp.get("Body") or "") and re.search(r'"list"\s*:|"data"\s*:|vod_', resp.get("Body") or ""))
        if resp["Ok"] and is_json and looks:
            api_result = {
                "Url": api_url,
                "Status": resp["Status"],
                "Length": resp["Length"],
                "Sketch": (resp.get("Body") or "")[:200],
            }
            add("api", "采集接口可用", api_url, "HTTP %s，%s 字节" % (resp["Status"], resp["Length"]))
            if "provide/vod" in (resp.get("Body") or ""):
                cms_hits.append({"Name": "苹果CMS 采集接口", "Signal": "api.php/provide/vod 响应有效 JSON", "Weight": 4})
            break
        if resp["Status"] in (200, 301, 302, 403):
            add("api", "探测 %s" % resp["Status"], api_url, "存在但未返回有效采集 JSON")

    tvbox = None
    for tu in (origin + "/tvbox/config.json", origin + "/config.json", origin + "/tvbox.json"):
        resp = fetch(tu, headers=headers, timeout=timeout, max_body=262144)
        _sleep(delay)
        if resp["Ok"] and re.search(r'"sites"\s*:', resp.get("Body") or ""):
            tvbox = {"Url": tu, "Status": resp["Status"], "Length": resp["Length"]}
            add("tvbox", "TVBox 源配置可访问", tu, "含 sites 数组，%s 字节" % resp["Length"])
            break

    probes = [
        {"P": "/admin.php", "K": "后台入口", "Lv": "info"},
        {"P": "/admin/", "K": "后台目录", "Lv": "info"},
        {"P": "/admin/login.php", "K": "后台登录", "Lv": "info"},
    ]
    if deep:
        probes += [
            {"P": "/.env", "K": "配置泄露", "Lv": "high"},
            {"P": "/.git/config", "K": "源码仓库泄露", "Lv": "high"},
            {"P": "/install/", "K": "安装向导残留", "Lv": "high"},
            {"P": "/phpinfo.php", "K": "phpinfo 泄露", "Lv": "high"},
            {"P": "/backup.zip", "K": "备份文件", "Lv": "high"},
            {"P": "/www.zip", "K": "备份文件", "Lv": "high"},
            {"P": "/data/", "K": "数据目录", "Lv": "medium"},
            {"P": "/runtime/", "K": "运行时目录", "Lv": "medium"},
        ]
    exposures = []
    for item in probes:
        u = origin + item["P"]
        resp = fetch(u, headers=headers, timeout=timeout, max_body=65536)
        _sleep(delay)
        hit = False
        desc = ""
        body = resp.get("Body") or ""
        if resp["Status"] == 200 and resp["Length"] > 0:
            if item["P"] == "/.env" and re.search(r"(?m)^\s*[A-Z_]+=", body):
                hit, desc = True, ".env 内容可读"
            elif item["P"] == "/.git/config" and "[core]" in body:
                hit, desc = True, ".git/config 可读"
            elif item["K"] == "备份文件" and "html" not in (resp.get("ContentType") or "").lower():
                hit, desc = True, "备份文件可下载（%s）" % resp.get("ContentType")
            elif item["K"] == "phpinfo 泄露" and re.search(r"PHP Version|phpinfo\(\)", body):
                hit, desc = True, "phpinfo 页面可读"
            elif "后台" in item["K"] and re.search(r"(?i)login|password|登录|管理", body):
                hit, desc = True, "后台入口可访问（HTTP %s）" % resp["Status"]
            elif "目录" in item["K"] and re.search(r"(?i)Index of /|Directory listing", body):
                hit, desc = True, "目录可列出"
        elif resp["Status"] in (401, 403):
            hit, desc = True, "存在但被拒（HTTP %s）" % resp["Status"]
        if hit:
            exposures.append({
                "Path": item["P"], "Kind": item["K"], "Level": item["Lv"],
                "Status": resp["Status"], "Length": resp["Length"], "Desc": desc,
            })
            add("exposure", "%s：%s" % (item["K"], desc), u)

    cms_hits.sort(key=lambda h: h["Weight"], reverse=True)
    confidence = min(100, sum(h["Weight"] for h in cms_hits) * 20)
    top = cms_hits[0] if cms_hits else None
    if top and confidence >= 60:
        verdict, level = "🟢 识别为：%s（置信度 %s%%）" % (top["Name"], confidence), "OK"
    elif top:
        verdict, level = "🟡 疑似：%s（置信度 %s%%，证据偏少）" % (top["Name"], confidence), "P1"
    else:
        verdict, level = "⚪ 未能识别 CMS 家族 —— 可能是自建站 / 全静态 / 有强 WAF 拦截", "UNKNOWN"

    advice = []
    if api_result:
        advice.append("采集接口直连可用（%s）→ 可直接跑 hls-analyze / http-replay 验证取流链路" % api_result["Url"])
    else:
        advice.append("采集接口未直连成功 → 用 ffuf 枚举路径，或用 js-reverse 抓前端实际请求的接口")
    if cdn:
        advice.append("存在 CDN/WAF（%s）→ 先过 js-reverse 拿真实 Cookie，再重放" % ", ".join(cdn))
    if players:
        advice.append("播放器：%s → 取 m3u8 后交 hls-analyze 判定加密/防盗链" % ", ".join(players))
    high = [e for e in exposures if e["Level"] == "high"]
    if high:
        advice.append("高危暴露 %s 项：%s" % (len(high), ", ".join(e["Path"] for e in high)))
    if tvbox:
        advice.append("TVBox 源配置可读（%s）→ 这是源站的聚合配置，比单站更有价值" % tvbox["Url"])

    payload = {
        "Schema": "seep.cms.fingerprint/1",
        "GeneratedAt": now_iso(),
        "Target": base,
        "Http": {"Status": root["Status"], "Length": root["Length"], "Msn": root["Msn"], "Server": server, "PoweredBy": powered},
        "Cdn": cdn,
        "Cms": cms_hits[:5],
        "Confidence": confidence,
        "Players": players,
        "M3u8InHtml": m3u8_n,
        "Api": api_result,
        "TvBox": tvbox,
        "Exposures": exposures,
        "Evidence": evidence,
        "Verdict": {"Level": level, "Text": verdict, "Advice": advice},
        "OutDir": out_dir,
    }
    md = ["# 影视站 CMS / 源站指纹报告", "", "- 目标: `%s`" % base, "- 结论: **%s**" % verdict, ""]
    for a in advice:
        md.append("- %s" % a)
    write_evidence(out_dir, payload, "\n".join(md) + "\n")
    return payload
