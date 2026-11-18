"""Web 审计硬阶段门。阶段不可跳：0 授权 → 1 指纹 → 2 举证 → 3 复测 → 4 报告。"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

from .common import dump_json, intval, now_iso, work_root

STAGE_NAMES = {0: "AUTHORIZE", 1: "FINGERPRINT", 2: "PROOF", 3: "RETEST", 4: "REPORT"}
STAGE_FILES = {
    0: "stage0-authorization.json",
    1: "stage1-fingerprint.json",
    2: "stage2-proof.json",
    3: "stage3-retest.json",
}


def _read_json(path: str) -> Optional[Dict[str, Any]]:
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def _history(case_dir: str, status: str, stage: int, note: str) -> None:
    if not case_dir or not os.path.isdir(case_dir):
        return
    line = json.dumps({
        "at": now_iso(),
        "stage": stage,
        "name": STAGE_NAMES.get(stage, ""),
        "status": status,
        "note": note,
    }, ensure_ascii=False)
    with open(os.path.join(case_dir, ".gate-history.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def _stage_path(case_dir: str, n: int) -> str:
    return os.path.join(case_dir, STAGE_FILES[n])


def _read_stage(case_dir: str, n: int) -> Optional[Dict[str, Any]]:
    return _read_json(_stage_path(case_dir, n))


def _write_stage(case_dir: str, n: int, data: Dict[str, Any]) -> str:
    path = _stage_path(case_dir, n)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(dump_json(data))
    return path


def _result(args: Dict[str, Any], status: str, stage: int, missing: List[str], message: str):
    case_dir = args.get("Dir") or ""
    payload = {
        "status": status,
        "stage": stage,
        "name": STAGE_NAMES.get(stage, ""),
        "dir": case_dir,
        "missing": missing,
        "action": message,
        "at": now_iso(),
    }
    return payload, (0 if status == "PASS" else 1)


def run(args: Dict[str, Any]) -> None:
    action = (args.get("Action") or "").strip()
    case_dir = args.get("Dir") or ""
    if action == "init":
        target = args.get("Target") or ""
        if not target:
            raise SystemExit("-Action init 需要 -Target")
        if not case_dir:
            safe = re.sub(r"^https?://", "", target)
            safe = re.sub(r"[^\w.\-]", "_", safe)[:40]
            case_dir = os.path.join(work_root(), "webcase-%s-%s" % (safe, now_iso().replace(":", "").replace("+", "")))
            args["Dir"] = case_dir
        os.makedirs(os.path.join(case_dir, "raw"), exist_ok=True)
        meta = {"schemaversion": 1, "target": target, "created": now_iso(), "toolbox": "python"}
        with open(os.path.join(case_dir, "case.json"), "w", encoding="utf-8") as fh:
            fh.write(dump_json(meta))
        _history(case_dir, "INIT", 0, "case created for %s" % target)
        return meta

    if not case_dir:
        raise SystemExit("该动作需要 -Dir <案件目录>")
    if not os.path.isdir(case_dir):
        raise SystemExit("案件目录不存在: %s" % case_dir)

    if action == "authorize":
        scope = args.get("Scope") or ""
        if not scope:
            raise SystemExit("-Action authorize 需要 -Scope（授权依据）")
        case = _read_json(os.path.join(case_dir, "case.json")) or {}
        data = {
            "stage": 0,
            "name": "AUTHORIZE",
            "authorized": True,
            "target": case.get("target") or args.get("Target") or "",
            "scope": scope,
            "operator": args.get("Operator") or "未填写",
            "at": now_iso(),
            "gAuth": "satisfied",
        }
        _write_stage(case_dir, 0, data)
        _history(case_dir, "PASS", 0, "authorized: %s" % scope)
        return data

    if action == "status":
        rows = []
        for n in range(4):
            data = _read_stage(case_dir, n)
            rows.append({"stage": n, "name": STAGE_NAMES[n], "done": bool(data), "at": (data or {}).get("at", "")})
        rows.append({"stage": 4, "name": STAGE_NAMES[4], "done": os.path.isfile(os.path.join(case_dir, "report.md")), "at": ""})
        hist = os.path.join(case_dir, ".gate-history.jsonl")
        count = 0
        if os.path.isfile(hist):
            with open(hist, "r", encoding="utf-8") as fh:
                count = sum(1 for line in fh if line.strip())
        return {"dir": case_dir, "stages": rows, "historyLines": count}

    stage = intval(args, "Stage", -1)
    if action == "record":
        if stage < 1 or stage > 3:
            raise SystemExit("-Action record 只支持 -Stage 1..3")
        source = args.get("Source") or ""
        if not source or not os.path.isfile(source):
            raise SystemExit("Source 不存在: %s" % source)
        prev = _read_stage(case_dir, stage - 1)
        if not prev:
            _history(case_dir, "BLOCK", stage, "record rejected: stage %s missing" % (stage - 1))
            return _result(args, "BLOCK", stage, ["缺少前置 stage %s (%s)，禁止先斩后奏" % (stage - 1, STAGE_NAMES[stage - 1])], "先完成 stage %s" % (stage - 1))
        raw = _read_json(source) or {}
        if stage == 1:
            exposures = []
            for e in raw.get("Exposures") or []:
                if not e:
                    continue
                exposures.append({
                    "path": e.get("Path"), "kind": e.get("Kind"), "level": e.get("Level"),
                    "status": e.get("Status"), "length": e.get("Length"), "desc": e.get("Desc"),
                })
            cms_names = [c.get("Name") for c in (raw.get("Cms") or []) if c and c.get("Name")]
            normalized = {
                "stage": 1, "name": "FINGERPRINT", "target": raw.get("Target"),
                "verdict": (raw.get("Verdict") or {}).get("Text", ""),
                "level": (raw.get("Verdict") or {}).get("Level", ""),
                "confidence": raw.get("Confidence"),
                "cms": cms_names,
                "api": (raw.get("Api") or {}).get("Url", "") if isinstance(raw.get("Api"), dict) else (raw.get("Api") or ""),
                "tvbox": (raw.get("TvBox") or {}).get("Url", "") if isinstance(raw.get("TvBox"), dict) else (raw.get("TvBox") or ""),
                "players": raw.get("Players") or [],
                "exposures": exposures,
                "highCount": sum(1 for e in exposures if e.get("level") == "high"),
                "source": os.path.abspath(source),
                "at": now_iso(),
            }
        elif stage == 2:
            items = []
            if raw.get("items"):
                for item in raw["items"]:
                    items.append({
                        "path": item.get("path"),
                        "level": item.get("level") or "high",
                        "exploitable": bool(item.get("exploitable")),
                        "evidence": item.get("evidence") or "",
                    })
            elif raw.get("Results") is not None:
                gate = ((raw.get("Verdict") or {}).get("GateHeaders") or [])
                items.append({
                    "path": (raw.get("Request") or {}).get("Url", ""),
                    "level": "info",
                    "exploitable": bool(gate),
                    "evidence": "http-replay: gate=[%s] verdict=%s" % (",".join(gate), (raw.get("Verdict") or {}).get("Text")),
                })
            if not items:
                _history(case_dir, "BLOCK", 2, "record rejected: empty proof items")
                return _result(args, "BLOCK", 2, ["stage 2 举证为空 —— 未从 Source 中解析出任何 items/Results"], "举证必须带至少 1 条可核验的请求-响应证据")
            normalized = {
                "stage": 2, "name": "PROOF", "items": items,
                "proven": sum(1 for i in items if i["exploitable"]),
                "denied": sum(1 for i in items if not i["exploitable"]),
                "source": os.path.abspath(source),
                "at": now_iso(),
            }
        else:
            items = raw.get("items") or []
            normalized = {
                "stage": 3, "name": "RETEST", "items": items,
                "fixed": sum(1 for i in items if i.get("fixed")),
                "open": sum(1 for i in items if not i.get("fixed")),
                "source": os.path.abspath(source),
                "at": now_iso(),
            }
        _write_stage(case_dir, stage, normalized)
        _history(case_dir, "PASS", stage, "recorded from %s" % os.path.basename(source))
        return normalized

    if action == "check":
        if stage < 1 or stage > 4:
            raise SystemExit("-Action check 需要 -Stage 1..4")
        missing: List[str] = []
        s0 = _read_stage(case_dir, 0)
        if not s0:
            missing.append('stage 0 AUTHORIZE 未登记 —— 先跑 -Action authorize -Scope "<授权依据>"')
        elif not s0.get("authorized"):
            missing.append("stage 0 存在但 authorized=false")
        for n in range(1, stage):
            data = _read_stage(case_dir, n)
            if not data:
                missing.append("缺少 stage %s (%s) 产物 —— 跑到阶段 %s 并 -Action record 收纳" % (n, STAGE_NAMES[n], n))
                continue
            if n == 1 and not data.get("exposures") and not data.get("api") and not data.get("cms") and not data.get("tvbox"):
                missing.append("stage 1 指纹全空（无 CMS / 无采集接口 / 无暴露面）—— 换 -Deep 或补 Cookie 重跑")
            if n == 2 and data.get("proven") == 0 and not (data.get("items") or []):
                missing.append("stage 2 举证为空 —— 无证据不得进入下一阶段")
        if stage == 4:
            s1 = _read_stage(case_dir, 1)
            s2 = _read_stage(case_dir, 2)
            if s1 and (s1.get("highCount") or 0) > 0:
                if not s2 or not (s2.get("items") or []):
                    missing.append("stage 1 发现 %s 条高危暴露，但 stage 2 无任何举证 —— 不允许直接出报告" % s1.get("highCount"))
            if not os.path.isfile(os.path.join(case_dir, "report.md")):
                missing.append("report.md 未生成 —— 先跑 web-report")
        if missing:
            _history(case_dir, "BLOCK", stage, " | ".join(missing))
            return _result(args, "BLOCK", stage, missing, "按提示补齐；不允许跳过前置阶段直接下结论")
        _history(case_dir, "PASS", stage, "gate satisfied")
        return _result(args, "PASS", stage, [], "允许进入该阶段")

    raise SystemExit("未知 Action: %s" % action)
