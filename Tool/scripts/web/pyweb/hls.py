"""HLS / m3u8 取证。JSON 契约与 hls-analyze.ps1 一致（seep.hls.evidence/1）。"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from .common import (
    default_out, dump_json, fetch, finish, flag, header_table, intval,
    now_iso, resolve_tool, resolve_uri, run_tool, url_from_curl, write_evidence,
)

DRM_IDS = (
    ("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed", "Widevine"),
    ("94ce86fb-07ff-4f43-adb8-93d2fa968ca2", "FairPlay"),
    ("9a04f079-9840-4286-ab92-e65be0885f95", "PlayReady"),
)
TOKEN_NAME = re.compile(r"(?i)sign|token|auth|expire|secret|key|e$|st$|t$|wssecret|txsecret")


def _attrs(line: str) -> Dict[str, str]:
    out = {}
    for m in re.finditer(r'([A-Z0-9\-]+)=("[^"]*"|[^,]*)', line):
        out[m.group(1)] = m.group(2).strip('"')
    return out


def _drm_kind(attrs: Dict[str, str]) -> str:
    kf = attrs.get("KEYFORMAT", "")
    method = attrs.get("METHOD", "")
    low = kf.lower()
    for needle, name in DRM_IDS:
        if needle in low:
            return name
    if "streamingkeydelivery" in low:
        return "FairPlay"
    if "playready" in low:
        return "PlayReady"
    if "clearkey" in low:
        return "ClearKey"
    if method == "SAMPLE-AES-CTR":
        return "SAMPLE-AES-CTR"
    if method == "SAMPLE-AES":
        return "SAMPLE-AES"
    return ""


def _parse_media(text: str, base: str) -> Dict[str, Any]:
    lines = [ln.strip() for ln in re.split(r"\r?\n", text) if ln.strip()]
    segments: List[str] = []
    keys: List[Dict[str, Any]] = []
    maps: List[Dict[str, Any]] = []
    dur = 0.0
    version = ""
    target = 0.0
    seq = 0
    disc = 0
    for ln in lines:
        m = re.match(r"^#EXT-X-VERSION:(.+)$", ln)
        if m:
            version = m.group(1).strip()
            continue
        m = re.match(r"^#EXT-X-TARGETDURATION:(.+)$", ln)
        if m:
            target = float(m.group(1).strip())
            continue
        m = re.match(r"^#EXT-X-MEDIA-SEQUENCE:(.+)$", ln)
        if m:
            seq = int(float(m.group(1).strip()))
            continue
        if re.match(r"^#EXT-X-DISCONTINUITY\s*$", ln):
            disc += 1
            continue
        m = re.match(r"^#EXT-X-KEY:(.+)$", ln)
        if m:
            a = _attrs(m.group(1))
            raw = a.get("URI", "")
            keys.append({
                "Method": a.get("METHOD", ""),
                "Uri": resolve_uri(base, raw),
                "UriRaw": raw,
                "Iv": a.get("IV", ""),
                "KeyFormat": a.get("KEYFORMAT", "identity"),
                "DrmKind": _drm_kind(a),
            })
            continue
        m = re.match(r"^#EXT-X-MAP:(.+)$", ln)
        if m:
            a = _attrs(m.group(1))
            raw = a.get("URI", "")
            maps.append({"Uri": resolve_uri(base, raw), "UriRaw": raw})
            continue
        m = re.match(r"^#EXTINF:([0-9.]+)", ln)
        if m:
            dur += float(m.group(1))
            continue
        if not ln.startswith("#"):
            segments.append(resolve_uri(base, ln))
    return {
        "IsMaster": False,
        "Version": version,
        "TargetDuration": target,
        "MediaSequence": seq,
        "Segments": segments,
        "Keys": keys,
        "Maps": maps,
        "Discontinuities": disc,
        "EndList": "#EXT-X-ENDLIST" in text,
        "TotalDuration": round(dur, 2),
    }


def _parse_variants(text: str, base: str) -> List[Dict[str, Any]]:
    lines = [ln.strip() for ln in re.split(r"\r?\n", text) if ln.strip()]
    variants = []
    for i, ln in enumerate(lines):
        if not ln.startswith("#EXT-X-STREAM-INF"):
            continue
        attrs = _attrs(ln.split(":", 1)[-1])
        uri = ""
        for nxt in lines[i + 1:]:
            if not nxt.startswith("#"):
                uri = nxt
                break
        if not uri:
            continue
        bw = attrs.get("BANDWIDTH") or "0"
        try:
            bandwidth = int(bw)
        except ValueError:
            bandwidth = 0
        variants.append({
            "Bandwidth": bandwidth,
            "Resolution": attrs.get("RESOLUTION", ""),
            "Codecs": attrs.get("CODECS", ""),
            "Uri": resolve_uri(base, uri),
            "Raw": uri,
        })
    return variants


def _diag(code: str, level: str, detail: str, advice: str) -> Dict[str, str]:
    return {"Code": code, "Level": level, "Detail": detail, "Advice": advice}


def run(args: Dict[str, Any]) -> None:
    headers = header_table(args)
    url = args.get("Url") or ""
    playlist = args.get("Playlist") or ""
    if args.get("Curl") and not url:
        url = url_from_curl(args["Curl"])
    if not url and not playlist:
        raise SystemExit("必须提供 -Url 或 -Playlist（或 -Curl）")

    out_dir = args.get("OutDir") or default_out("hls")
    os.makedirs(out_dir, exist_ok=True)
    timeout = intval(args, "TimeoutSec", 30)
    variant = args.get("Variant") or "best"
    verify_seconds = intval(args, "VerifySeconds", 15)

    if playlist:
        if not os.path.isfile(playlist):
            raise SystemExit("Playlist 文件不存在: %s" % playlist)
        with open(playlist, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        base = args.get("BaseUrl") or ""
        fetch_info = {"Ok": True, "Status": 200, "Length": len(text), "ContentType": "local", "Error": "", "Body": text, "Msn": 0}
    else:
        fetched = fetch(url, headers=headers, timeout=timeout)
        text = fetched.get("Body") or ""
        base = url
        fetch_info = fetched

    looks = "#EXTM3U" in (text or "")
    diagnosis: List[Dict[str, str]] = []
    if not looks:
        diagnosis.append(_diag(
            "NOT_A_PLAYLIST", "P0",
            "返回内容不是 m3u8（HTTP %s，%s 字节，CT=%s）。" % (
                fetch_info.get("Status"), fetch_info.get("Length"), fetch_info.get("ContentType")),
            "站点可能返回了 HTML 错误页 / 登录页 / 风控页。先看 evidence.json 的 fetch.head，再补 Referer / Cookie / UA。",
        ))

    variants: List[Dict[str, Any]] = []
    media = None
    if looks:
        is_master = "#EXT-X-STREAM-INF" in text
        if is_master:
            variants = _parse_variants(text, base)
        media = {
            "IsMaster": is_master,
            "Version": "",
            "TargetDuration": 0,
            "MediaSequence": 0,
            "Segments": [],
            "Keys": [],
            "Maps": [],
            "Discontinuities": 0,
            "EndList": "#EXT-X-ENDLIST" in text,
            "TotalDuration": 0.0,
        }
        if not is_master:
            media = _parse_media(text, base)
            media["IsMaster"] = False

    chosen_uri = url
    target_media = media
    if looks and media and media.get("IsMaster") and variants:
        if variant == "all":
            chosen = variants
        elif re.fullmatch(r"\d+", variant or ""):
            idx = int(variant)
            chosen = [variants[idx]] if idx < len(variants) else [variants[0]]
        else:
            chosen = [sorted(variants, key=lambda v: v["Bandwidth"], reverse=True)[0]]
        if chosen:
            chosen_uri = chosen[0]["Uri"]
            sub = fetch(chosen_uri, headers=headers, timeout=timeout)
            if "#EXTM3U" not in (sub.get("Body") or ""):
                target_media = None
                diagnosis.append(_diag(
                    "VARIANT_NOT_PLAYLIST", "P0",
                    "子播放列表 %s 返回的不是 m3u8（HTTP %s）。" % (chosen_uri, sub.get("Status")),
                    "子 playlist 也受防盗链保护；确认头是否对子域名同样有效。",
                ))
            else:
                target_media = _parse_media(sub["Body"], chosen_uri)

    seg_pattern = ""
    seg_hosts: List[str] = []
    token_params: List[str] = []
    segs = (target_media or {}).get("Segments") or []
    if segs:
        seg_pattern = re.sub(r"\d{3,}", "{n}", segs[0])
        hosts = []
        names = []
        for s in segs[:20]:
            try:
                u = urlparse(s)
                hosts.append(u.hostname or "")
                if u.query:
                    for pair in u.query.split("&"):
                        k = pair.split("=", 1)[0]
                        if k and TOKEN_NAME.search(k):
                            names.append(k)
            except Exception:
                continue
        seg_hosts = sorted({h for h in hosts if h})
        token_params = sorted(set(names))

    key_probes = []
    if not flag(args, "NoKeyProbe") and target_media:
        seen = set()
        for key in target_media.get("Keys") or []:
            if key.get("Method") == "NONE" or not key.get("Uri") or key["Uri"] in seen:
                continue
            seen.add(key["Uri"])
            with_h = fetch(key["Uri"], headers=headers, timeout=timeout, max_body=256)
            bare = fetch(key["Uri"], headers={}, timeout=timeout, max_body=256)
            if with_h["Ok"] and with_h["Length"] == 16:
                verdict, note = "KEY_OK", "返回 16 字节，标准 AES-128 key，可直接解密"
            elif with_h["Ok"] and with_h["Length"] > 0 and with_h["Length"] != 16:
                verdict, note = "KEY_SUSPECT", "返回 %s 字节，非标准 16 字节 key（可能是 DRM 许可证响应或错误页）" % with_h["Length"]
            elif with_h["Status"] in (401, 403):
                verdict, note = "KEY_DENIED", "带头仍被拒（HTTP %s），key 需要登录态 / 一次性 token / 设备指纹" % with_h["Status"]
            elif with_h["Status"] == 0:
                verdict, note = "KEY_ERROR", with_h.get("Error") or ""
            else:
                verdict, note = "KEY_UNEXPECTED", "HTTP %s，%s 字节" % (with_h["Status"], with_h["Length"])
            delta = ""
            if bare["Status"] != with_h["Status"]:
                delta = "去头后 HTTP %s（带头 %s）→ 头是关键" % (bare["Status"], with_h["Status"])
            elif bare["Status"] == with_h["Status"] == 200:
                delta = "去头后仍 200 → key 无鉴权"
            key_probes.append({
                "Uri": key["Uri"],
                "Method": key.get("Method"),
                "WithHeadersStatus": with_h["Status"],
                "WithHeadersLength": with_h["Length"],
                "BareStatus": bare["Status"],
                "Verdict": verdict,
                "Note": note,
                "HeaderDelta": delta,
            })

    drm_kinds = []
    if target_media:
        drm_kinds = sorted({k.get("DrmKind") for k in target_media.get("Keys") or [] if k.get("DrmKind")})
    sample = [k for k in (target_media or {}).get("Keys") or [] if str(k.get("Method", "")).startswith("SAMPLE-AES")]
    decrypt = {
        "Possible": False,
        "Scheme": "NONE",
        "Reason": "",
        "Drm": ",".join(drm_kinds),
        "Fmp4": bool(target_media and target_media.get("Maps")),
        "NeedsHeaders": bool(headers),
    }
    if drm_kinds:
        decrypt["Scheme"] = "DRM"
        decrypt["Possible"] = False
        decrypt["Reason"] = "检测到 DRM（%s）—— 受版权保护体系约束，密钥由许可证服务器下发，不属于可逆向范围。" % ", ".join(drm_kinds)
        diagnosis.append(_diag(
            "DRM_PROTECTED", "STOP", decrypt["Reason"],
            "按 G-Auth 边界终止取证：写「受 DRM 保护、不可逆向、需版权方授权」，不要继续探测许可证服务器。",
        ))
    elif sample:
        decrypt["Scheme"] = "SAMPLE-AES"
        decrypt["Reason"] = "SAMPLE-AES 只加密部分 NAL / 音频帧，ffmpeg 无法直接 -c copy 还原，需按样本特点定制解封装。"
        diagnosis.append(_diag("SAMPLE_AES", "P1", decrypt["Reason"], "先确认是否同时在 key 上有 DRM KEYFORMAT。"))
    elif target_media and any(k.get("Method") == "AES-128" for k in target_media.get("Keys") or []):
        decrypt["Scheme"] = "AES-128"
        denied = [k for k in key_probes if k["Verdict"] == "KEY_DENIED"]
        if denied:
            decrypt["Reason"] = "AES-128 加密，但 key URI 在带头情况下仍被拒绝 → 需要登录态或一次性 token。"
        else:
            decrypt["Possible"] = True
            decrypt["Reason"] = "AES-128 加密，key 可获取（ffmpeg -headers 可直接解密），取证闭环可做。"
    elif target_media:
        decrypt["Scheme"] = "CLEAR"
        decrypt["Possible"] = True
        decrypt["Reason"] = "未加密（METHOD=NONE 或无 EXT-X-KEY），可直接取流。"

    if target_media and not target_media.get("Segments") and looks:
        diagnosis.append(_diag(
            "NO_SEGMENTS", "P1",
            "playlist 里没有任何分片（可能是 live 未开始的空窗口，或 EXT-X-ENDLIST 已过期）。",
            "确认是否 live 流；点播流出现空分片通常意味着源已下架。",
        ))

    verify = {"Attempted": False, "Ok": False, "Seconds": 0, "File": "", "Ffprobe": "", "Error": "", "Skipped": ""}
    ffmpeg = resolve_tool("ffmpeg")
    ffprobe = resolve_tool("ffprobe")
    if flag(args, "NoVerify"):
        verify["Skipped"] = "NoVerify"
    elif not decrypt["Possible"]:
        verify["Skipped"] = "解密不可行（%s）" % decrypt["Scheme"]
    elif not ffmpeg:
        verify["Skipped"] = "ffmpeg 未安装（brew install ffmpeg 或 ./setup/install-capabilities.sh --only web）"
    elif not chosen_uri or not re.match(r"^https?://", chosen_uri or ""):
        verify["Skipped"] = "无可用目标 URI（本地 playlist 且未给 BaseUrl）"
    else:
        verify["Attempted"] = True
        out_file = os.path.join(out_dir, "probe.ts")
        hdr_lines = "".join("%s: %s\r\n" % (k, v) for k, v in headers.items())
        cmd = ["-hide_banner", "-nostdin", "-loglevel", "error", "-y"]
        if hdr_lines:
            cmd += ["-headers", hdr_lines]
        if headers.get("User-Agent"):
            cmd += ["-user_agent", headers["User-Agent"]]
        if headers.get("Referer"):
            cmd += ["-referer", headers["Referer"]]
        cmd += ["-protocol_whitelist", "file,http,https,tcp,tls,crypto", "-i", chosen_uri,
                "-t", str(verify_seconds), "-c", "copy", "-f", "mpegts", out_file]
        log = run_tool(ffmpeg, cmd, timeout=max(60, verify_seconds * 8))
        if os.path.isfile(out_file) and os.path.getsize(out_file) > 1024:
            verify["Ok"] = True
            verify["File"] = out_file
            verify["Seconds"] = round(os.path.getsize(out_file) / (1024 * 1024), 2)
            if ffprobe:
                verify["Ffprobe"] = run_tool(ffprobe, [
                    "-hide_banner", "-v", "error",
                    "-show_entries", "stream=index,codec_name,codec_type,width,height,bit_rate",
                    "-show_entries", "format=duration,bit_rate,format_name",
                    "-of", "json", out_file,
                ])
        else:
            verify["Error"] = log or "ffmpeg 未产生输出（无错误信息）"
            diagnosis.append(_diag(
                "DECRYPT_FAILED", "P0",
                "按判定应该可解，但 ffmpeg 实解失败。",
                "常见原因：key 有一次性有效期、分片需单独 Referer、或 base64 变体 key。",
            ))

    if not looks:
        verdict_text, verdict_level = "⚪ 目标不是有效 m3u8 —— 404 / 被拦截 / 返了登录页", "INVALID"
    elif drm_kinds:
        verdict_text, verdict_level = "🔴 DRM 保护 —— 取证终止（写\"不可逆向，需版权方授权\"）", "STOP"
    elif decrypt["Scheme"] == "SAMPLE-AES":
        verdict_text, verdict_level = "🟠 SAMPLE-AES —— 需专用解封装，不能直接 -c copy", "P1"
    elif verify["Ok"]:
        verdict_text, verdict_level = "🟢 可取证闭环 —— playlist 可解、分片可播（物证 probe.ts）", "OK"
    elif decrypt["Possible"] and not verify["Attempted"]:
        verdict_text, verdict_level = "🟡 静态判定可解（已跳过实解验证）—— 去掉 -NoVerify 出物证", "P1"
    elif decrypt["Possible"] and verify["Attempted"]:
        verdict_text, verdict_level = "🟡 逻辑可解但实解失败 —— 查 token 有效期 / 分片级头", "P1"
    elif not decrypt["Possible"]:
        verdict_text, verdict_level = "🟠 key 受鉴权保护 —— 需登录态或一次性 token", "P1"
    else:
        verdict_text, verdict_level = "⚪ 未完成判定 —— 检查输入与网络", "UNKNOWN"

    head = (fetch_info.get("Body") or "")[:400]
    evidence = {
        "Schema": "seep.hls.evidence/1",
        "GeneratedAt": now_iso(),
        "Input": {"Url": url, "Playlist": playlist, "Variant": variant, "Headers": list(headers.keys())},
        "Fetch": {
            "Status": fetch_info.get("Status"),
            "Length": fetch_info.get("Length"),
            "ContentType": fetch_info.get("ContentType"),
            "Msn": fetch_info.get("Msn"),
            "IsPlaylist": looks,
            "Error": fetch_info.get("Error") or "",
            "Head": head,
        },
        "Variants": variants,
        "Chosen": chosen_uri,
        "Media": None if not target_media else {
            "Version": target_media.get("Version"),
            "TargetDuration": target_media.get("TargetDuration"),
            "MediaSequence": target_media.get("MediaSequence"),
            "SegmentCount": len(target_media.get("Segments") or []),
            "TotalDuration": target_media.get("TotalDuration"),
            "Discontinuities": target_media.get("Discontinuities"),
            "EndList": target_media.get("EndList"),
            "FirstSegments": (target_media.get("Segments") or [])[:3],
            "Keys": target_media.get("Keys"),
            "Maps": target_media.get("Maps"),
            "SegmentPattern": seg_pattern,
            "SegmentHosts": seg_hosts,
            "TokenParams": token_params,
        },
        "KeyProbes": key_probes,
        "Decrypt": decrypt,
        "Verify": verify,
        "Diagnosis": diagnosis,
        "Verdict": {"Level": verdict_level, "Text": verdict_text},
        "OutDir": out_dir,
    }
    md = [
        "# HLS 取证报告", "",
        "- 生成时间: %s" % evidence["GeneratedAt"],
        "- 目标: `%s`" % (url or playlist),
        "- 结论: **%s**" % verdict_text, "",
        "## 1. 加密与密钥", "",
        "- 方案: %s" % decrypt["Scheme"],
        "- 可解密: %s" % decrypt["Possible"],
        "- 依据: %s" % decrypt["Reason"], "",
        "## 2. 诊断", "",
    ]
    if not diagnosis:
        md.append("- 无异常")
    else:
        for d in diagnosis:
            md += ["**[%s] %s** — %s" % (d["Level"], d["Code"], d["Detail"]), "", "> 处置: %s" % d["Advice"], ""]
    write_evidence(out_dir, evidence, "\n".join(md) + "\n")
    return evidence
