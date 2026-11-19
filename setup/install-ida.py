#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Seep Lab — macOS / Linux 上把 IDA 增量写入 ~/.pi/agent/mcp.json。

与 setup/install-ida.ps1、setup/mcp-merge.py 同一条合并契约：
只动 mcpServers.ida，其它 MCP 条目原样保留。找不到 IDA、或 idalib-mcp
装不上时退出码为 0，只打印警告，不写一个不存在的 command，也不写 13337。

探测顺序：--ida-root → SEEP_IDA_ROOT → setup/tool-registry.json 里
id 为 ida 的 candidates。

IDADIR：
  macOS  .app 包的 Contents/MacOS（内有 ida 或 idat，以及 libidalib.dylib）
  Linux  同一目录里有 ida 或 idat，以及 libidalib.so

命令：优先已存在的 <agent>/ida-mcp-venv/bin/idalib-mcp，其次 PATH 上的
idalib-mcp。都没有且 IDA 本体已找到时，才在该 venv 里 pip install ida-pro-mcp。

已有 ida 条目时：command 仍然存在就保留用户改过的 command，只补缺失的
env.IDADIR；command 丢了才换成下面的 stdio 条目。

    command = <idalib-mcp>
    args    = ["--stdio"]
    env     = PYTHONIOENCODING=utf-8, IDADIR=<IDADIR>
    transport = stdio
    lifecycle = lazy
    requestTimeoutMs = 180000

SEEP_AGENT_DIR 或 --agent-dir 覆盖 agent 目录。写盘为 UTF-8 无 BOM。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

BIN_NAMES = ("ida", "idat")


def warn(msg: str) -> None:
    print("    [!!] %s" % msg)


def ok(msg: str) -> None:
    print("    [OK] %s" % msg)


def info(msg: str) -> None:
    print("    [..] %s" % msg)


def default_agent_dir() -> str:
    override = os.environ.get("SEEP_AGENT_DIR")
    if override and override.strip():
        return os.path.abspath(os.path.expanduser(override.strip()))
    return os.path.join(os.path.expanduser("~"), ".pi", "agent")


def required_libs() -> tuple[str, ...]:
    if sys.platform == "darwin":
        return ("libidalib.dylib",)
    if sys.platform.startswith("linux"):
        return ("libidalib.so",)
    return ("libidalib.dylib", "libidalib.so")


def is_idadir(path: str) -> bool:
    if not path or not os.path.isdir(path):
        return False
    has_bin = any(os.path.isfile(os.path.join(path, name)) for name in BIN_NAMES)
    has_lib = any(os.path.isfile(os.path.join(path, name)) for name in required_libs())
    return has_bin and has_lib


def resolve_idadir(raw: str | None) -> str | None:
    """把 .app、安装根或 ida/idat 本体归一化成 IDADIR。不合格返回 None。"""
    if raw is None:
        return None
    text = str(raw).strip().strip('"').strip("'")
    if not text:
        return None
    path = os.path.abspath(os.path.expanduser(text))
    if os.path.isfile(path):
        path = os.path.dirname(path)
    if not os.path.isdir(path):
        return None
    macos = os.path.join(path, "Contents", "MacOS")
    ordered = []
    if path.endswith(".app") or os.path.isdir(macos):
        ordered.append(macos)
    ordered.append(path)
    seen = set()
    for cand in ordered:
        if cand in seen:
            continue
        seen.add(cand)
        if is_idadir(cand):
            return cand
    return None


def expand_candidate(pattern: str) -> str:
    """展开 %VAR% / {env:VAR} / ~。未设置的变量换成空串，调用方再判断路径在不在。"""

    def repl(match: re.Match) -> str:
        return os.environ.get(match.group(1), "")

    text = re.sub(r"%([^%]+)%", repl, pattern)
    text = re.sub(r"\{env:([A-Za-z0-9_]+)\}", repl, text)
    if text.startswith("~"):
        text = os.path.expanduser(text)
    return text


def load_ida_candidates(registry_path: str) -> list[str]:
    if not os.path.isfile(registry_path):
        warn("工具注册表不存在，跳过候选路径: %s" % registry_path)
        return []
    try:
        with open(registry_path, "r", encoding="utf-8-sig", errors="replace") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        warn("工具注册表无法读取，跳过候选路径: %s" % exc)
        return []
    tools = data.get("tools") if isinstance(data, dict) else None
    if not isinstance(tools, list):
        warn("工具注册表缺少 tools 数组，跳过候选路径")
        return []
    for tool in tools:
        if isinstance(tool, dict) and tool.get("id") == "ida":
            raw = tool.get("candidates") or []
            return [item for item in raw if isinstance(item, str) and item.strip()]
    warn("工具注册表里没有 id=ida 的条目，跳过候选路径")
    return []


def probe_idadir(cli_root: str | None, registry_path: str) -> str | None:
    """参数 → SEEP_IDA_ROOT → 注册表候选。命中即停。"""
    if cli_root is not None and str(cli_root).strip():
        hit = resolve_idadir(cli_root)
        if hit:
            info("从 --ida-root 找到 IDADIR: %s" % hit)
            return hit
        warn("--ida-root 不是有效的 IDA 目录，继续探测: %s" % cli_root)

    env_root = os.environ.get("SEEP_IDA_ROOT")
    if env_root and env_root.strip():
        hit = resolve_idadir(env_root)
        if hit:
            info("从 SEEP_IDA_ROOT 找到 IDADIR: %s" % hit)
            return hit
        warn("SEEP_IDA_ROOT 不是有效的 IDA 目录，继续扫描候选路径: %s" % env_root)

    for pattern in load_ida_candidates(registry_path):
        expanded = expand_candidate(pattern)
        if not expanded or not os.path.exists(expanded):
            continue
        hit = resolve_idadir(expanded)
        if hit:
            info("从候选路径找到 IDADIR: %s" % hit)
            return hit
    return None


def command_exists(command: object) -> bool:
    if not isinstance(command, str):
        return False
    text = command.strip()
    if not text:
        return False
    if os.path.isabs(text) or "/" in text or "\\" in text:
        return os.path.isfile(os.path.expanduser(text))
    return shutil.which(text) is not None


def find_idalib_mcp(agent_dir: str) -> str | None:
    venv_bin = os.path.join(agent_dir, "ida-mcp-venv", "bin", "idalib-mcp")
    if os.path.isfile(venv_bin):
        return os.path.abspath(venv_bin)
    found = shutil.which("idalib-mcp")
    if found:
        return os.path.abspath(found)
    return None


def install_idalib_mcp(agent_dir: str) -> str | None:
    """只在 IDA 已找到、且现成命令不存在时调用。失败返回 None，不写 command。"""
    venv = os.path.join(agent_dir, "ida-mcp-venv")
    py = os.path.join(venv, "bin", "python")
    if not os.path.isfile(py):
        info("创建 IDA MCP venv: %s" % venv)
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "venv", venv],
                capture_output=True, text=True,
            )
        except OSError as exc:
            warn("创建 venv 失败: %s" % exc)
            return None
        if proc.returncode != 0 or not os.path.isfile(py):
            warn("创建 venv 失败，未写入 ida command")
            tail = (proc.stderr or proc.stdout or "").strip().splitlines()
            if tail:
                warn(tail[-1])
            return None
    info("在 venv 中安装 ida-pro-mcp ...")
    try:
        proc = subprocess.run(
            [py, "-m", "pip", "install", "--disable-pip-version-check", "--quiet", "ida-pro-mcp"],
            capture_output=True, text=True,
        )
    except OSError as exc:
        warn("pip 安装 ida-pro-mcp 失败: %s" % exc)
        return None
    bin_path = os.path.join(venv, "bin", "idalib-mcp")
    if proc.returncode != 0 or not os.path.isfile(bin_path):
        warn("ida-pro-mcp 安装失败，未写入 ida command")
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()
        if tail:
            warn(tail[-1])
        return None
    ok("idalib-mcp 已安装: %s" % bin_path)
    return os.path.abspath(bin_path)


def canonical_entry(command: str, idadir: str) -> dict:
    return {
        "command": command,
        "args": ["--stdio"],
        "env": {
            "PYTHONIOENCODING": "utf-8",
            "IDADIR": idadir,
        },
        "transport": "stdio",
        "lifecycle": "lazy",
        "requestTimeoutMs": 180000,
    }


def idadir_missing(env: dict) -> bool:
    if "IDADIR" not in env:
        return True
    value = env.get("IDADIR")
    return isinstance(value, str) and value.strip() == ""


def fill_missing_idadir(entry: dict, idadir: str) -> bool:
    """只补缺失的 IDADIR，不动 command / args / 其它 env。"""
    env = entry.get("env")
    if not isinstance(env, dict):
        entry["env"] = {"IDADIR": idadir}
        return True
    if idadir_missing(env):
        env["IDADIR"] = idadir
        return True
    return False


def read_mcp(path: str):
    """返回 (data, error)。文件不存在时 data 是空的 mcpServers，不算错误。"""
    if not os.path.exists(path):
        return {"mcpServers": {}}, None
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            raw = handle.read()
    except OSError as exc:
        return None, "无法读取 mcp.json: %s" % exc
    if not raw.strip():
        return {"mcpServers": {}}, None
    try:
        data = json.loads(raw)
    except ValueError as exc:
        return None, "现有 mcp.json 语法异常，为避免覆盖其它 MCP 已停止写入: %s" % exc
    if not isinstance(data, dict):
        return None, "现有 mcp.json 顶层不是对象，已停止写入"
    return data, None


def write_json(path: str, data: dict) -> None:
    """UTF-8 无 BOM、LF、无结尾换行，与 mcp-merge.py 对齐。先写临时文件再替换。"""
    text = json.dumps(data, indent=2, ensure_ascii=False)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def ensure_servers(data: dict) -> dict:
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        data["mcpServers"] = {}
        return data["mcpServers"]
    return servers


def not_found_message() -> int:
    warn("未检测到 IDA Pro 安装路径")
    info("IDA Pro 为商业软件，未安装不影响工作台，核心链路继续使用 Radare2。")
    info("若已安装但路径特殊，可执行：")
    info('    python3 setup/install-ida.py --ida-root "/Applications/IDA Professional 9.x.app"')
    info("    或设置 SEEP_IDA_ROOT 后重跑本脚本 / ./setup/install.sh")
    return 0


def main(argv: list[str] | None = None) -> int:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description="把 IDA 增量写入 mcp.json（找不到则退出码 0）")
    parser.add_argument("--ida-root", default=None, help="IDA 安装根、.app 或 ida/idat 路径；优先于 SEEP_IDA_ROOT")
    parser.add_argument("--agent-dir", default=None, help="agent 目录，默认 SEEP_AGENT_DIR 或 ~/.pi/agent")
    parser.add_argument("--registry", default=None, help="默认 setup/tool-registry.json")
    parser.add_argument("--skip-pip", action="store_true", help="不要自动 pip install ida-pro-mcp")
    args = parser.parse_args(argv)

    agent_dir = os.path.abspath(os.path.expanduser(args.agent_dir)) if args.agent_dir else default_agent_dir()
    registry_path = args.registry or os.path.join(script_dir, "tool-registry.json")
    mcp_path = os.path.join(agent_dir, "mcp.json")

    print("  === IDA Pro 探测与配置 (Unix) ===")
    idadir = probe_idadir(args.ida_root, registry_path)
    if not idadir:
        return not_found_message()
    ok("已定位 IDADIR: %s" % idadir)

    data, error = read_mcp(mcp_path)
    if data is None:
        warn(error or "mcp.json 无法安全读取")
        return 0

    servers = ensure_servers(data)
    current = servers.get("ida")
    if isinstance(current, dict) and command_exists(current.get("command")):
        if fill_missing_idadir(current, idadir):
            try:
                write_json(mcp_path, data)
            except OSError as exc:
                warn("写入 mcp.json 失败: %s" % exc)
                return 1
            ok("已保留现有 ida command，只补上缺失的 IDADIR")
            info("  command = %s" % current.get("command"))
            info("  IDADIR  = %s" % idadir)
        else:
            ok("ida 条目的 command 仍在且 IDADIR 已设置，未改动 mcp.json")
        return 0

    command = find_idalib_mcp(agent_dir)
    if command:
        info("使用已有 idalib-mcp: %s" % command)
    elif args.skip_pip:
        warn("未找到 idalib-mcp，且指定了 --skip-pip，未写入 ida command")
        return 0
    else:
        command = install_idalib_mcp(agent_dir)
        if not command:
            warn("没有可用的 idalib-mcp，未写入 ida 条目（避免写入无效 command）")
            return 0

    new_entry = canonical_entry(command, idadir)
    if servers.get("ida") == new_entry:
        ok("ida 条目已是 stdio 配置，未改动 mcp.json")
        return 0
    servers["ida"] = new_entry
    try:
        write_json(mcp_path, data)
    except OSError as exc:
        warn("写入 mcp.json 失败: %s" % exc)
        return 1
    ok("mcp.json 已增量更新 ida（stdio，其它 MCP 未改动）")
    info("  command = %s" % command)
    info("  IDADIR  = %s" % idadir)
    info("  重启 Pi Agent 或 DSH 后生效。13337 未监听是正常状态。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
