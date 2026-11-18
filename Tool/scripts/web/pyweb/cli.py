"""把 *.ps1 的名字映射到 Python 实现，参数仍是 MCP 已经在用的 -Url / -Json 风格。"""
from __future__ import annotations

import sys
from typing import Any, Dict

from . import cms, gate, hls, pipeline, replay, report, spider
from .common import finish, flag, parse_ps

DISPATCH = {
    "hls-analyze.ps1": hls.run,
    "http-replay.ps1": replay.run,
    "spider-extract.ps1": spider.run,
    "cms-fingerprint.ps1": cms.run,
    "web-pipeline.ps1": pipeline.run,
    "web-gate.ps1": gate.run,
    "web-report.ps1": report.run,
}


def main(argv=None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        sys.stderr.write("用法: python web.py <脚本名.ps1> [-Json] [-Url ...] ...\n")
        sys.stderr.write("可用: %s\n" % ", ".join(sorted(DISPATCH)))
        raise SystemExit(2)
    name = argv[0]
    fn = DISPATCH.get(name)
    if fn is None:
        sys.stderr.write("未知脚本: %s\n" % name)
        raise SystemExit(2)
    args: Dict[str, Any] = parse_ps(argv[1:])
    result = fn(args)
    code = 0
    if isinstance(result, tuple):
        result, code = result
    finish(result, flag(args, "Json") or True, code)


if __name__ == "__main__":
    main()
