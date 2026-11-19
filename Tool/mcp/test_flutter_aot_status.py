#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""flutter_aot 不得再把 Unix 写成不支持；文档不得再要求 PowerShell 7 或把 13337 当故障。"""

import json
import os
import stat
import tempfile

import seep_mcp_server as srv


def _isolate(tmp: str):
    old_root = srv.ANDROID_TOOLBOX_DIR
    old_which = srv.shutil.which
    srv.ANDROID_TOOLBOX_DIR = tmp
    srv.shutil.which = lambda _name: None
    return old_root, old_which


def _restore(saved) -> None:
    srv.ANDROID_TOOLBOX_DIR, srv.shutil.which = saved


def _touch(path: str, executable: bool) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("")
    mode = os.stat(path).st_mode
    if executable:
        os.chmod(path, mode | stat.S_IEXEC)
    else:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def test_missing_binary_is_not_installed() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        saved = _isolate(tmp)
        try:
            unix = srv._flutter_aot_boundary()
            windows = srv._flutter_aot_boundary(platform="win32")
        finally:
            _restore(saved)
    assert unix["status"] == "not-installed", unix
    assert unix["path"] is None
    assert "未安装" in unix["note"]
    assert "go.mod" in unix["note"]
    assert "apktool" not in unix["note"]
    assert "windows-only" not in json.dumps(unix)
    assert windows["status"] == "not-installed", windows
    assert "install-android-toolbox.ps1" in windows["note"]


def test_executable_is_ready_and_pe_payload_is_not() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        saved = _isolate(tmp)
        try:
            pe = os.path.join(tmp, "aotopsy", "aotopsy.exe")
            _touch(pe, executable=True)
            skipped = srv._flutter_aot_boundary()
            binary = os.path.join(tmp, "bin", "aotopsy")
            _touch(binary, executable=True)
            ready = srv._flutter_aot_boundary()
            _touch(binary, executable=False)
            plain = srv._flutter_aot_boundary()
        finally:
            _restore(saved)
    assert skipped["status"] == "not-installed", skipped
    assert ready["status"] == "ready", ready
    assert ready["path"] == binary
    assert plain["status"] == "not-installed", plain


def test_seep_status_uses_the_same_boundary() -> None:
    data = json.loads(srv.seep_status())
    reported = data["platform_boundaries"]["flutter_aot"]
    expected = srv._flutter_aot_boundary()
    assert reported["status"] == expected["status"], reported
    assert reported["status"] in ("ready", "not-installed")
    assert "apktool" not in reported["note"]


def test_docs_no_longer_hardcode_the_old_limits() -> None:
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    def text(rel: str) -> str:
        with open(os.path.join(root, rel), encoding="utf-8") as handle:
            return handle.read()

    readme = text("README.md")
    chinese = text("README.zh.md")
    checklist = text("MANUAL/DEPLOYMENT-CHECKLIST.md")
    server = text("Tool/mcp/seep_mcp_server.py")
    updater = text("setup/update.sh")
    assert "Windows-only" not in readme
    assert "PowerShell 7" not in readme
    assert "web.py" in readme
    assert "Windows-only" not in chinese
    assert "PowerShell 7" not in chinese
    assert "web.py" in chinese
    assert "13337 端口自动唤醒" not in checklist
    assert "Unix 不适用" not in checklist
    assert "13337 关闭不是故障" in checklist
    assert "windows-only" not in server
    assert "Windows-only" not in updater
    assert "set -uo pipefail" in updater


if __name__ == "__main__":
    test_missing_binary_is_not_installed()
    test_executable_is_ready_and_pe_payload_is_not()
    test_seep_status_uses_the_same_boundary()
    test_docs_no_longer_hardcode_the_old_limits()
    print("ok")
