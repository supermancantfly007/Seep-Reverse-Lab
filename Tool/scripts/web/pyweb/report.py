"""从案件目录生成 Web 源与暴露面报告。不重新发包。"""
from __future__ import annotations

import json
import os
import shutil
from typing import Any, Dict, List, Optional

from .common import finish, flag, now_iso

FIX = {
    "配置泄露": [
        "立即从 Web 根目录移除该文件，或在 Nginx/Apache 加 deny 规则（`.env` / `.env.*`）；",
        "轮换文件中出现的全部密钥（APP_KEY / DB 密码 / 第三方 Token），视为已泄露；",
        "审计访问日志，确认是否有外部 IP 拉取过；",
        "在部署脚本中加检查，禁止把 `.env` 放进发布包。",
    ],
    "源码仓库泄露": [
        "删除 Web 根下的 `.git` 目录，并加 deny 规则；",
        "确认源码是否含硬编码凭据，若有则全部轮换；",
        "审计日志确认是否被拉取过；",
        "改用构建产物发布，服务器上不保留版本库。",
    ],
    "备份文件": [
        "立即删除；备份文件不得放在 Web 可访问目录；",
        "备份内通常含数据库导出与源码，按全部密钥与用户数据已泄露处置；",
        "审计日志确认下载记录；",
        "备份改存对象存储私有桶，加鉴权与过期策略。",
    ],
    "安装向导残留": [
        "删除或重命名 `install/` 目录；",
        "确认安装锁文件存在且不可覆盖；",
        "若曾暴露，检查是否被重置过管理员账号。",
    ],
    "phpinfo 泄露": [
        "删除 `phpinfo.php`；",
        "生产环境设置 `expose_php = Off`，`display_errors = Off`；",
        "检查是否泄露了绝对路径、扩展版本、环境变量。",
    ],
    "后台入口": [
        "后台路径改名，或加 IP 白名单 / 双因素；",
        "限制登录尝试频率，记录失败来源 IP；",
        "确认默认口令已改。",
    ],
    "后台目录": [
        "关闭目录列举（`autoindex off` / `Options -Indexes`）；",
        "对后台目录加访问控制。",
    ],
    "后台登录": [
        "后台登录入口加 IP 白名单或双因素；",
        "限制登录失败次数。",
    ],
}
IMPACT = {
    "配置泄露": "数据库凭据与签名密钥泄露，可能导致数据被拖库、会话被伪造。",
    "源码仓库泄露": "完整源码与提交历史泄露，攻击者可定向挖掘未公开问题，并拿到历史硬编码凭据。",
    "备份文件": "数据库或源码备份可下载，用户数据与管理员凭据整体泄露。",
    "安装向导残留": "可能被重新执行安装流程覆盖配置，导致站点被接管。",
    "phpinfo 泄露": "泄露绝对路径、PHP 版本与扩展，为后续针对性利用提供情报。",
    "后台入口": "后台暴露于公网，可被撞库；口令策略弱则直接失守。",
    "后台登录": "后台暴露于公网，可被撞库；口令策略弱则直接失守。",
    "后台目录": "后台目录暴露，便于发现登录入口。",
    "数据目录": "数据目录可访问，可能列出备份与临时文件。",
    "运行时目录": "运行时目录可访问，可能泄露日志与缓存。",
}


def _read(path: str) -> Optional[Dict[str, Any]]:
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def _advice(kind: str, path: str) -> List[str]:
    for key, lines in FIX.items():
        if key in (kind or ""):
            return lines
    return ["对 `%s` 加访问控制或移除暴露面，并审计相关访问日志。" % path]


def _impact(kind: str, level: str) -> str:
    for key, text in IMPACT.items():
        if key in (kind or ""):
            return text
    if level == "high":
        return "可作为进一步攻击的跳板，需按高危处置。"
    return "情报价值为主，单独利用难度较高。"


def run(args: Dict[str, Any]):
    case_dir = args.get("Dir") or ""
    if not os.path.isdir(case_dir):
        raise SystemExit("案件目录不存在: %s" % case_dir)
    s0 = _read(os.path.join(case_dir, "stage0-authorization.json"))
    s1 = _read(os.path.join(case_dir, "stage1-fingerprint.json"))
    s2 = _read(os.path.join(case_dir, "stage2-proof.json"))
    s3 = _read(os.path.join(case_dir, "stage3-retest.json"))
    blocked = []
    if not s0:
        blocked.append("stage 0 AUTHORIZE")
    if not s1:
        blocked.append("stage 1 FINGERPRINT")
    if blocked:
        return {
            "status": "BLOCK",
            "missing": blocked,
            "message": "证据链不完整，拒绝出报告（缺 %s）" % " 与 ".join(blocked),
        }, 1

    exposures = list(s1.get("exposures") or [])
    proof = list((s2 or {}).get("items") or [])
    retest = list((s3 or {}).get("items") or [])
    high = sum(1 for e in exposures if e.get("level") == "high")
    med = sum(1 for e in exposures if e.get("level") == "medium")
    proven = sum(1 for p in proof if p.get("exploitable"))
    if high > 0 and proven > 0:
        grade = "严重"
    elif high > 0:
        grade = "高"
    elif med > 0 or s1.get("api") or s1.get("tvbox"):
        grade = "中"
    else:
        grade = "低"

    summary = []
    if high > 0 and proven > 0:
        summary.append("发现 **%s 项高危暴露面**，其中 **%s 项已完成可利用性举证**。" % (high, proven))
    elif high > 0:
        summary.append("发现 **%s 项高危暴露面**，尚未完成可利用性举证（结论降级为「疑似」）。" % high)
    if s1.get("api"):
        summary.append("采集接口可直接调用（`%s`）。" % s1["api"])
    if s1.get("tvbox"):
        summary.append("TVBox 源配置公开可读（`%s`）。" % s1["tvbox"])
    if not summary:
        summary.append("未发现高危暴露面；采集接口与源配置均未直接暴露。")

    cms = "、".join(s1.get("cms") or []) or "未识别"
    players = "、".join(s1.get("players") or []) or "未识别"
    md: List[str] = [
        "# Web 源与暴露面安全评估报告", "",
        "| 项 | 值 |", "| :--- | :--- |",
        "| 目标资产 | `%s` |" % (s1.get("target") or ""),
        "| 评估类型 | 外部无侵入取证（CMS 指纹 / 暴露面 / 可利用性举证 / 复测） |",
        "| 授权依据 | %s |" % (s0.get("scope") or ""),
        "| 授权人 | %s |" % (s0.get("operator") or ""),
        "| 评估时间 | %s |" % (s1.get("at") or ""),
        "| 综合定级 | **%s** |" % grade,
        "| 案件目录 | `%s` |" % case_dir, "",
        "---", "", "## 0. 结论摘要", "",
    ]
    md += ["- %s" % line for line in summary]
    md += [
        "", "## 1. 资产画像", "",
        "| 项 | 结果 |", "| :--- | :--- |",
        "| CMS 家族 | %s（置信度 %s%%） |" % (cms, s1.get("confidence") or 0),
        "| 采集接口 | %s |" % (("`%s`" % s1["api"]) if s1.get("api") else "未直连成功"),
        "| TVBox 源配置 | %s |" % (("`%s`" % s1["tvbox"]) if s1.get("tvbox") else "未发现"),
        "| 播放器 | %s |" % players, "",
        "## 2. 暴露面清单", "",
    ]
    if not exposures:
        md.append("未发现可访问的暴露面（`-Deep` 探测范围内）。")
    else:
        md += ["| # | 路径 | 类型 | 等级 | HTTP | 证据 |", "| ---: | :--- | :--- | :--- | ---: | :--- |"]
        for i, e in enumerate(exposures, 1):
            md.append("| %s | `%s` | %s | %s | %s | %s |" % (i, e.get("path"), e.get("kind"), e.get("level"), e.get("status"), e.get("desc")))
    md += ["", "## 3. 可利用性举证", ""]
    if not proof:
        md.append("> 本节为空。第 2 节只能算「疑似暴露」，不得直接当结论对外。")
    else:
        md += ["| 路径 | 判定 | 证据 |", "| :--- | :--- | :--- |"]
        for p in proof:
            mark = "可利用" if p.get("exploitable") else "不成立"
            ev = (p.get("evidence") or "").replace("\n", " ")
            if len(ev) > 160:
                ev = ev[:160] + "…"
            md.append("| `%s` | %s | %s |" % (p.get("path"), mark, ev))
    md += ["", "## 4. 影响分析", ""]
    if not exposures:
        md.append("- 无")
    else:
        for e in exposures:
            md.append("**%s（%s / %s）** — %s" % (e.get("path"), e.get("kind"), e.get("level"), _impact(e.get("kind") or "", e.get("level") or "")))
            md.append("")
    md += ["## 5. 修复建议", ""]
    seen = set()
    if not exposures:
        md.append("- 无（保持现状并定期复测）")
    else:
        n = 0
        for e in exposures:
            kind = e.get("kind") or ""
            if kind in seen:
                continue
            seen.add(kind)
            n += 1
            md.append("### 5.%s %s" % (n, kind))
            md.append("")
            for line in _advice(kind, e.get("path") or ""):
                md.append("- %s" % line)
            md.append("")
    md += ["## 6. 复测步骤", "", "```bash"]
    target = (s1.get("target") or "").rstrip("/")
    for e in exposures:
        if e.get("level") == "info":
            continue
        md.append("curl -sS -o /dev/null -w '%%{http_code}\\n' '%s%s'" % (target, e.get("path") or ""))
    md += ["```", ""]
    if retest:
        md += ["### 6.1 已执行复测", "", "| 路径 | 状态 |", "| :--- | :--- |"]
        for r in retest:
            md.append("| `%s` | %s |" % (r.get("path"), "已修复" if r.get("fixed") else "仍存在"))
        md.append("")

    out_file = args.get("OutFile") or os.path.join(case_dir, "report.md")
    if os.path.isfile(out_file) and not flag(args, "Force"):
        shutil.copyfile(out_file, out_file + ".bak")
    with open(out_file, "w", encoding="utf-8") as fh:
        fh.write("\n".join(md) + "\n")
    hist = os.path.join(case_dir, ".gate-history.jsonl")
    with open(hist, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "at": now_iso(), "stage": 4, "name": "REPORT", "status": "PASS",
            "note": "report generated: %s" % out_file,
        }, ensure_ascii=False) + "\n")
    return {
        "status": "OK",
        "grade": grade,
        "report": out_file,
        "exposures": len(exposures),
        "high": high,
        "proven": proven,
        "hasProof": bool(proof),
        "hasRetest": bool(retest),
        "summary": summary,
    }
