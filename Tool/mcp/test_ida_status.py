#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""seep_ida_status 不得把「13337 没监听」当成 IDA 不可用。"""

import json
import os
import stat
import tempfile

from seep_mcp_server import _collect_ida_status


def _touch(path: str, executable: bool = False) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("")
    if executable:
        mode = os.stat(path).st_mode
        os.chmod(path, mode | stat.S_IEXEC)


def _write_mcp(path: str, entry: dict) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"mcpServers": {"ida": entry}}, handle)


def test_idalib_stdio_is_online_when_legacy_port_is_closed() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        command = os.path.join(tmp, "idalib-mcp")
        idadir = os.path.join(tmp, "IDA", "Contents", "MacOS")
        _touch(command, executable=True)
        _touch(os.path.join(idadir, "ida"), executable=True)
        _touch(os.path.join(idadir, "libidalib.dylib"))
        mcp = os.path.join(tmp, "mcp.json")
        _write_mcp(mcp, {
            "command": command,
            "args": ["--stdio"],
            "env": {"IDADIR": idadir},
            "transport": "stdio",
        })
        result = _collect_ida_status(config_paths=[mcp], legacy_listening=False)
        assert result["status"] == "Online", result
        assert result["usable"] is True
        assert result["transport"] == "idalib-stdio"
        assert result["legacy_port_13337"] == "closed"
        assert "不要因此判定 IDA 不可用" in result["message"]


def test_missing_command_is_degraded_not_silently_online() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        mcp = os.path.join(tmp, "mcp.json")
        _write_mcp(mcp, {
            "command": os.path.join(tmp, "missing-idalib-mcp"),
            "args": ["--stdio"],
            "transport": "stdio",
        })
        result = _collect_ida_status(config_paths=[mcp], legacy_listening=False)
        assert result["status"] == "Degraded", result
        assert result["usable"] is False


def test_no_config_and_closed_port_stays_offline() -> None:
    result = _collect_ida_status(config_paths=[], legacy_listening=False)
    assert result["status"] == "Offline / Unreachable", result
    assert result["usable"] is False


def test_legacy_port_alone_is_still_online() -> None:
    result = _collect_ida_status(config_paths=[], legacy_listening=True)
    assert result["status"] == "Online", result
    assert result["usable"] is True
    assert result["transport"] == "gui-plugin-13337"


if __name__ == "__main__":
    test_idalib_stdio_is_online_when_legacy_port_is_closed()
    test_missing_command_is_degraded_not_silently_online()
    test_no_config_and_closed_port_stays_offline()
    test_legacy_port_alone_is_still_online()
    print("ok")
