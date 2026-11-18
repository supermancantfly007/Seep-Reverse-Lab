#!/usr/bin/env python3
"""Web / HLS 取证入口。MCP 调用本文件，不再依赖 PowerShell。"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from pyweb.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
