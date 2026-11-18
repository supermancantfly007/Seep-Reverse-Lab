"""授权 → 指纹 → 举证 → 可选 nuclei/ffuf → 复测 → 报告。每步过 gate。"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List

from . import cms, gate, report
from .common import ensure_dir, fetch, intval, now_iso, resolve_tool, run_tool, work_root

UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


def _step(steps: List[Dict[str, str]], name: str, status: str, note: str = "") -> None:
    steps.append({"step": name, "status": status, "note": note})


def _case_dir(url: str, given: str) -> str:
    if given:
        ensure_dir(given)
        return given
    safe = re.sub(r"^https?://", "", url)
    safe = re.sub(r"[^\w.\-]", "_", safe)[:40]
    stamp = now_iso().replace(":", "").replace("+", "")
    path = os.path.join(work_root(), "webcase-%s-%s" % (safe, stamp))
    ensure_dir(path)
    return path


def _exploitable(kind: str, resp: Dict[str, Any]) -> Dict[str, Any]:
    body = resp.get("Body") or ""
    ctype = resp.get("ContentType") or ""
    ok = False
    why = ""
    if "配置泄露" in kind:
        if re.search(r"(?m)^\s*[A-Z][A-Z0-9_]*\s*=", body):
            ok, why = True, ".env 键值对可读"
        else:
            why = "返回 200 但内容不含键值对"
    elif "源码仓库" in kind:
        if "[core]" in body:
            ok, why = True, ".git/config 含 [core] 段"
        else:
            why = "不含 [core]"
    elif "备份" in kind:
        if "html" not in ctype.lower() and resp.get("Length", 0) > 32:
            ok, why = True, "可下载（%s, %s B）" % (ctype, resp.get("Length"))
        else:
            why = "内容不像有效备份"
    elif "phpinfo" in kind:
        if re.search(r"PHP Version|phpinfo\(\)", body):
            ok, why = True, "phpinfo 页面内容可读"
        else:
            why = "不含 phpinfo 标记"
    elif "目录" in kind:
        if re.search(r"(?i)Index of /|Directory listing", body):
            ok, why = True, "目录可列举"
        else:
            why = "未开启目录列举"
    elif "后台" in kind:
        why = "入口可访问（仅暴露入口，不等于可越权，故不计为可利用）" if resp.get("Status") == 200 else "HTTP %s" % resp.get("Status")
    else:
        if resp.get("Status") == 200 and resp.get("Length", 0) > 0:
            ok, why = True, "HTTP 200 / %s B" % resp.get("Length")
        else:
            why = "HTTP %s" % resp.get("Status")
    return {"Exploitable": ok, "Why": why}


def _fail(steps, name, note, out_dir, base):
    _step(steps, name, "FAIL", note)
    return {
        "status": "FAIL",
        "target": base,
        "caseDir": out_dir,
        "steps": steps,
        "error": note,
    }, 3


def run(args: Dict[str, Any]):
    url = (args.get("Url") or "").strip()
    if not url:
        raise SystemExit("必须提供 -Url")
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    base = url.rstrip("/")
    scope = args.get("Scope") or ""
    steps: List[Dict[str, str]] = []
    if not args.get("Authorized") or not scope:
        _step(steps, "gate-0", "BLOCK", "未提供 -Authorized / -Scope")
        return {
            "status": "BLOCK",
            "stage": 0,
            "name": "AUTHORIZE",
            "action": "G-Auth 门未过：传 authorized=true 与 scope='<授权依据>'",
            "steps": steps,
        }, 2

    out_dir = _case_dir(base, args.get("OutDir") or "")
    delay = intval(args, "DelayMs", 300)
    timeout = intval(args, "TimeoutSec", 15)
    stop_after = intval(args, "StopAfter", 4)
    try:
        gate.run({"Action": "init", "Target": base, "Dir": out_dir})
        gate.run({
            "Action": "authorize", "Dir": out_dir, "Scope": scope,
            "Operator": args.get("Operator") or "未填写",
        })
        _step(steps, "gate-0", "PASS", "授权已登记：%s" % scope)
    except SystemExit as exc:
        return _fail(steps, "gate-0", str(exc), out_dir, base)

    if stop_after < 1:
        return {"status": "OK", "target": base, "caseDir": out_dir, "steps": steps}

    raw_dir = ensure_dir(os.path.join(out_dir, "raw"))
    try:
        gate.run({"Action": "check", "Dir": out_dir, "Stage": "1"})
        fp = cms.run({
            "Url": base, "Deep": True, "DelayMs": str(delay),
            "TimeoutSec": str(timeout), "OutDir": raw_dir,
        })
        evidence_path = os.path.join(raw_dir, "evidence.json")
        if not os.path.isfile(evidence_path):
            raise SystemExit("指纹脚本未产出 evidence.json")
        gate.run({"Action": "record", "Dir": out_dir, "Stage": "1", "Source": evidence_path})
        names = ",".join(c.get("Name", "") for c in (fp.get("Cms") or []))
        high_n = sum(1 for e in (fp.get("Exposures") or []) if e.get("Level") == "high")
        _step(steps, "stage-1", "PASS", "CMS=%s 暴露面=%s(high %s) 采集接口=%s" % (
            names, len(fp.get("Exposures") or []), high_n, "有" if fp.get("Api") else "无"))
    except SystemExit as exc:
        return _fail(steps, "stage-1", str(exc), out_dir, base)

    if stop_after < 2:
        return {"status": "OK", "target": base, "caseDir": out_dir, "steps": steps, "report": ""}

    headers = {"User-Agent": UA}
    proof_items: List[Dict[str, Any]] = []
    exposures = [e for e in (fp.get("Exposures") or []) if e.get("Level") != "info"]
    exposures = exposures[: intval(args, "MaxExposures", 20)]
    for exp in exposures:
        u = base + exp["Path"]
        resp = fetch(u, headers=headers, timeout=timeout, max_body=262144)
        if delay:
            time.sleep(delay / 1000.0)
        judged = _exploitable(exp.get("Kind") or "", resp)
        proof_items.append({
            "path": exp["Path"],
            "kind": exp.get("Kind"),
            "level": exp.get("Level"),
            "status": resp["Status"],
            "length": resp["Length"],
            "exploitable": bool(judged["Exploitable"]),
            "evidence": "GET %s → HTTP %s, %s B, %s；判定：%s" % (
                u, resp["Status"], resp["Length"], resp.get("ContentType"), judged["Why"]),
        })
    if fp.get("Api"):
        api_url = fp["Api"]["Url"] if isinstance(fp["Api"], dict) else str(fp["Api"])
        resp = fetch(api_url, headers=headers, timeout=timeout, max_body=65536)
        is_open = bool(resp["Ok"] and re.search(r'"list"|"data"', resp.get("Body") or ""))
        proof_items.append({
            "path": "/api.php/provide/vod/",
            "kind": "采集接口",
            "level": "high" if is_open else "info",
            "status": resp["Status"],
            "length": resp["Length"],
            "exploitable": is_open,
            "evidence": "GET %s → HTTP %s, %s B；判定：%s" % (
                api_url, resp["Status"], resp["Length"],
                "无鉴权即可取列表" if is_open else "未返回有效采集数据"),
        })

    if args.get("Nuclei"):
        nuc = resolve_tool("nuclei")
        if not nuc:
            _step(steps, "nuclei", "SKIP", "未安装")
        else:
            nuc_out = os.path.join(raw_dir, "nuclei.jsonl")
            run_tool(nuc, [
                "-u", base, "-tags", "cms,exposure,tech", "-severity", "medium,high,critical",
                "-silent", "-jsonl", "-o", nuc_out, "-timeout", "10", "-retries", "1", "-no-color",
            ], timeout=180)
            n = 0
            if os.path.isfile(nuc_out):
                with open(nuc_out, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            row = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        sev = ((row.get("info") or {}).get("severity") or "")
                        lvl = "high" if sev in ("critical", "high") else ("medium" if sev == "medium" else "info")
                        proof_items.append({
                            "path": row.get("matched-at") or "",
                            "kind": "nuclei:" + ((row.get("info") or {}).get("name") or ""),
                            "level": lvl,
                            "status": 200,
                            "length": 0,
                            "exploitable": lvl == "high",
                            "evidence": "模板 %s [%s]" % (row.get("template-id") or row.get("templateID"), sev),
                        })
                        n += 1
            _step(steps, "nuclei", "PASS", "%s 条命中" % n)

    if args.get("Ffuf"):
        ff = resolve_tool("ffuf")
        wl = os.path.join(web_toolbox_root_wordlist())
        if not ff:
            _step(steps, "ffuf", "SKIP", "未安装")
        elif not os.path.isfile(wl):
            _step(steps, "ffuf", "SKIP", "缺字典 %s" % wl)
        else:
            ff_out = os.path.join(raw_dir, "ffuf.json")
            run_tool(ff, [
                "-u", base + "/FUZZ", "-w", wl, "-mc", "200,301,302,403",
                "-of", "json", "-o", ff_out, "-s", "-t", "5", "-rate", "20",
            ], timeout=180)
            n = 0
            if os.path.isfile(ff_out):
                try:
                    with open(ff_out, "r", encoding="utf-8") as fh:
                        doc = json.load(fh)
                    for res in doc.get("results") or []:
                        fuzz = ((res.get("input") or {}).get("FUZZ") or "")
                        proof_items.append({
                            "path": "/" + fuzz,
                            "kind": "ffuf:目录发现",
                            "level": "info",
                            "status": res.get("status"),
                            "length": res.get("length"),
                            "exploitable": False,
                            "evidence": "ffuf: /%s → HTTP %s" % (fuzz, res.get("status")),
                        })
                        n += 1
                except (OSError, json.JSONDecodeError):
                    pass
            _step(steps, "ffuf", "PASS", "%s 条路径" % n)

    proof_file = os.path.join(out_dir, "proof-input.json")
    with open(proof_file, "w", encoding="utf-8") as fh:
        json.dump({"items": proof_items}, fh, ensure_ascii=False, indent=2)
    try:
        recorded = gate.run({"Action": "record", "Dir": out_dir, "Stage": "2", "Source": proof_file})
        if isinstance(recorded, tuple) and recorded[1] != 0:
            return _fail(steps, "stage-2", (recorded[0] or {}).get("action") or "举证门未过", out_dir, base)
        proven = sum(1 for p in proof_items if p["exploitable"])
        _step(steps, "stage-2", "PASS", "举证 %s 条，其中可利用 %s 条" % (len(proof_items), proven))
    except SystemExit as exc:
        return _fail(steps, "stage-2", str(exc), out_dir, base)

    if stop_after < 3:
        return {"status": "OK", "target": base, "caseDir": out_dir, "steps": steps}

    retest_items = []
    for item in proof_items:
        path = item.get("path") or ""
        if not path.startswith("/") or item.get("level") == "info":
            continue
        resp = fetch(base + path, headers=headers, timeout=timeout, max_body=65536)
        if delay:
            time.sleep(delay / 1000.0)
        judged = _exploitable(item.get("kind") or "", resp)
        retest_items.append({
            "path": path,
            "fixed": not judged["Exploitable"],
            "status": resp["Status"],
            "note": judged["Why"],
        })
    retest_file = os.path.join(out_dir, "retest-input.json")
    with open(retest_file, "w", encoding="utf-8") as fh:
        json.dump({"items": retest_items}, fh, ensure_ascii=False, indent=2)
    try:
        recorded = gate.run({"Action": "record", "Dir": out_dir, "Stage": "3", "Source": retest_file})
        if isinstance(recorded, tuple) and recorded[1] != 0:
            return _fail(steps, "stage-3", (recorded[0] or {}).get("action") or "复测门未过", out_dir, base)
        still = sum(1 for r in retest_items if not r["fixed"])
        _step(steps, "stage-3", "PASS", "复测 %s 条，仍存在 %s 条" % (len(retest_items), still))
    except SystemExit as exc:
        return _fail(steps, "stage-3", str(exc), out_dir, base)

    if stop_after < 4:
        return {"status": "OK", "target": base, "caseDir": out_dir, "steps": steps}

    try:
        rep = report.run({"Dir": out_dir, "Json": True})
        if isinstance(rep, tuple):
            rep_obj, code = rep
            if code != 0:
                return _fail(steps, "stage-4", rep_obj.get("message") or "报告被拒绝", out_dir, base)
        else:
            rep_obj = rep
        _step(steps, "stage-4", "PASS", "报告已生成（定级 %s）" % rep_obj.get("grade"))
    except SystemExit as exc:
        return _fail(steps, "stage-4", str(exc), out_dir, base)

    proven = sum(1 for p in proof_items if p["exploitable"])
    high = sum(1 for p in proof_items if p.get("level") == "high")
    return {
        "status": "OK",
        "target": base,
        "caseDir": out_dir,
        "report": os.path.join(out_dir, "report.md"),
        "steps": steps,
        "exposures": len(exposures),
        "proof": len(proof_items),
        "proven": proven,
        "high": high,
    }


def web_toolbox_root_wordlist() -> str:
    from .common import web_toolbox_root
    return os.path.join(web_toolbox_root(), "wordlists", "web-common.txt")
