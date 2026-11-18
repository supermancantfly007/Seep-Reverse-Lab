"""取证脚本的公共底座：HTTP、请求头、工作目录、JSON 落盘。只依赖标准库。"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

SWITCHES = {
    "Json", "NoVerify", "Deep", "Authorized", "Nuclei", "Ffuf", "Hls",
    "SkipDecompile", "Force", "SaveBodies", "NoKeyProbe",
}
REPEATABLE = {"Header"}


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def parse_ps(argv: List[str]) -> Dict[str, Any]:
    """解析 PowerShell 风格参数（-Url x -Header a -Header b -Json）。MCP 已经按这套拼参数。"""
    out: Dict[str, Any] = {"Header": []}
    i = 0
    while i < len(argv):
        token = argv[i]
        if not token.startswith("-") or token == "-":
            i += 1
            continue
        key = token[1:]
        if key in SWITCHES:
            out[key] = True
            i += 1
            continue
        if i + 1 >= len(argv):
            raise SystemExit("缺少参数值: %s" % token)
        val = argv[i + 1]
        i += 2
        if key in REPEATABLE:
            out.setdefault(key, []).append(val)
        else:
            out[key] = val
    return out


def flag(args: Dict[str, Any], name: str) -> bool:
    return bool(args.get(name))


def intval(args: Dict[str, Any], name: str, default: int) -> int:
    raw = args.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def web_toolbox_root() -> str:
    env = os.environ.get("SEEP_WEB_TOOLBOX", "").strip()
    if env:
        return env
    if sys.platform == "win32":
        return r"D:\Tool\Web"
    return os.path.join(os.path.expanduser("~"), ".seep", "web")


def work_root() -> str:
    path = os.path.join(web_toolbox_root(), "work")
    os.makedirs(path, exist_ok=True)
    return path


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def default_out(prefix: str) -> str:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return ensure_dir(os.path.join(work_root(), "%s-%s" % (prefix, stamp)))


def resolve_tool(name: str) -> Optional[str]:
    root = web_toolbox_root()
    candidates = [
        os.path.join(root, "ffmpeg", "bin", name),
        os.path.join(root, "bin", name),
        os.path.join(root, name, "bin", name),
        os.path.join(root, "ffmpeg", "bin", name + ".exe"),
        os.path.join(root, "bin", name + ".exe"),
        os.path.join(root, name + ".exe"),
    ]
    for c in candidates:
        if os.path.isfile(c) and (sys.platform == "win32" or os.access(c, os.X_OK) or c.lower().endswith(".exe") is False):
            if sys.platform != "win32" and c.lower().endswith((".exe", ".bat", ".cmd")):
                continue
            return c
    return shutil.which(name)


def run_tool(exe: str, args: List[str], timeout: int = 120) -> str:
    try:
        proc = subprocess.run(
            [exe] + args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return "[timeout %ss]" % timeout
    except OSError as exc:
        return str(exc)
    return ((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")).strip()


def header_table(args: Dict[str, Any]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    raw_json = args.get("HeaderJson") or ""
    if raw_json:
        try:
            obj = json.loads(raw_json)
            if isinstance(obj, dict):
                for k, v in obj.items():
                    headers[str(k)] = str(v)
        except json.JSONDecodeError:
            pass
    for line in args.get("Header") or []:
        m = re.match(r"^\s*([^:=]+?)\s*[:=]\s*(.*)$", line or "")
        if m:
            headers[m.group(1).strip()] = m.group(2)
    curl = args.get("Curl") or ""
    if curl:
        for rx in (
            r"-H\s+'([^:]+):\s*([^']*)'",
            r'-H\s+"([^:]+):\s*([^"]*)"',
            r"--header\s+([^:]+):\s*(\S+)",
        ):
            for m in re.finditer(rx, curl):
                headers[m.group(1).strip()] = m.group(2).strip()
    if args.get("Referer"):
        headers["Referer"] = args["Referer"]
    if args.get("UserAgent"):
        headers["User-Agent"] = args["UserAgent"]
    if args.get("Cookie"):
        headers["Cookie"] = args["Cookie"]
    return headers


def url_from_curl(curl: str) -> str:
    m = re.search(r"curl\s+(?:[^'\"\s]+\s+)*['\"](https?://[^'\"]+)['\"]", curl)
    if m:
        return m.group(1)
    m = re.search(r"(https?://[^\s'\"]+)", curl)
    return m.group(1) if m else ""


def curl_method_body(curl: str) -> tuple:
    method = ""
    body = ""
    m = re.search(r"-X\s+(POST|PUT|PATCH|DELETE)", curl, re.I)
    if m:
        method = m.group(1).upper()
    m = re.search(r"--data(?:-raw|-binary|-urlencode)?\s+['\"](.+?)['\"]", curl)
    if m:
        body = m.group(1)
        if not method:
            method = "POST"
    return method, body


def fetch(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    method: str = "GET",
    body: str = "",
    content_type: str = "",
    timeout: int = 30,
    max_body: int = 2_097_152,
) -> Dict[str, Any]:
    """永不抛异常。字段与 Invoke-WebFetch 对齐：Ok/Status/Length/ContentType/Body/Headers/Error/Msn。"""
    hdrs = {k: v for k, v in (headers or {}).items() if v}
    data = None
    if body:
        data = body.encode("utf-8")
        hdrs.setdefault("Content-Type", content_type or "application/json")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method or "GET")
    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(max_body)
            status = int(getattr(resp, "status", 200) or 200)
            resp_headers = {k: v for k, v in resp.headers.items()}
            ctype = resp.headers.get("Content-Type", "")
            length = resp.headers.get("Content-Length")
            nbytes = int(length) if (length and length.isdigit()) else len(raw)
            text = raw.decode("utf-8", errors="replace")
            return {
                "Ok": 200 <= status < 400,
                "Status": status,
                "Length": nbytes,
                "ContentType": ctype,
                "Body": text,
                "Headers": resp_headers,
                "Error": "",
                "Msn": int((time.time() - started) * 1000),
            }
    except urllib.error.HTTPError as exc:
        raw = exc.read(max_body) if exc.fp else b""
        ctype = exc.headers.get("Content-Type", "") if exc.headers else ""
        length = exc.headers.get("Content-Length") if exc.headers else None
        nbytes = int(length) if (length and str(length).isdigit()) else len(raw)
        resp_headers = {k: v for k, v in exc.headers.items()} if exc.headers else {}
        return {
            "Ok": False,
            "Status": int(exc.code),
            "Length": nbytes,
            "ContentType": ctype,
            "Body": raw.decode("utf-8", errors="replace"),
            "Headers": resp_headers,
            "Error": "HTTP %s" % exc.code,
            "Msn": int((time.time() - started) * 1000),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "Ok": False,
            "Status": 0,
            "Length": 0,
            "ContentType": "",
            "Body": "",
            "Headers": {},
            "Error": str(exc),
            "Msn": int((time.time() - started) * 1000),
        }


def body_hash(text: str) -> str:
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def body_sketch(text: str) -> str:
    if not text:
        return ""
    t = text.strip()
    if t.startswith("{") or t.startswith("["):
        for kw in ('"code"', '"msg"', '"message"', '"success"', '"data"'):
            i = t.find(kw)
            if i >= 0:
                return t[i:i + 120]
        return t[:120]
    m = re.search(r"(?i)<title>(.*?)</title>", t)
    if m:
        return "HTML title: %s" % m.group(1)
    m = re.search(r"(?i)(登录|验证|forbidden|denied|blocked|权限)", t)
    if m:
        return "文本命中: %s" % m.group(0)
    return t[:120]


def resolve_uri(base: str, rel: str) -> str:
    if not rel:
        return ""
    if re.match(r"^https?://", rel, re.I):
        return rel
    if not base:
        return rel
    try:
        return urljoin(base, rel)
    except Exception:
        return rel


def origin_of(url: str) -> str:
    u = urlparse(url)
    if not u.scheme or not u.netloc:
        return url.rstrip("/")
    return "%s://%s" % (u.scheme, u.netloc)


def dump_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2)


def write_evidence(out_dir: str, payload: Dict[str, Any], report_md: str) -> None:
    ensure_dir(out_dir)
    with open(os.path.join(out_dir, "evidence.json"), "w", encoding="utf-8") as fh:
        fh.write(dump_json(payload))
    with open(os.path.join(out_dir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(report_md)


def emit(payload: Dict[str, Any], as_json: bool) -> None:
    if as_json:
        sys.stdout.write(dump_json(payload))
        sys.stdout.write("\n")
    else:
        text = (payload.get("Verdict") or {}).get("Text") or payload.get("status") or ""
        sys.stdout.write(str(text) + "\n")
        if payload.get("OutDir"):
            sys.stdout.write(payload["OutDir"] + "\n")


def finish(payload: Dict[str, Any], as_json: bool, code: int = 0) -> None:
    emit(payload, as_json)
    raise SystemExit(code)
