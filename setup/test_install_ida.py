#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""setup/install-ida.py 契约测试。全部使用临时目录，不写真实 ~/.pi/agent/mcp.json。

用法:
    python3 setup/test_install_ida.py
退出码: 0 通过 / 1 失败
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "install-ida.py")
REAL_REGISTRY = os.path.join(HERE, "tool-registry.json")
REAL_MCP = os.path.join(os.path.expanduser("~"), ".pi", "agent", "mcp.json")

FAILS = []


def check(cond, name, detail=""):
    if cond:
        print("  [PASS] %s" % name)
    else:
        print("  [FAIL] %s%s" % (name, ("  -> " + detail) if detail else ""))
        FAILS.append(name)


def lib_name():
    if sys.platform == "darwin":
        return "libidalib.dylib"
    return "libidalib.so"


def snapshot(path):
    if not os.path.exists(path):
        return None
    with open(path, "rb") as handle:
        blob = handle.read()
    st = os.stat(path)
    return (st.st_mtime_ns, st.st_size, hashlib.sha256(blob).hexdigest())


def write_bytes(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = text.encode("utf-8")
    with open(path, "wb") as handle:
        handle.write(data)


def read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()


def touch(path, executable=False):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(b"")
    if executable:
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)


def make_bundle(parent):
    idadir = os.path.join(parent, "IDA Professional 9.0.app", "Contents", "MacOS")
    os.makedirs(idadir, exist_ok=True)
    touch(os.path.join(idadir, "ida"), executable=True)
    touch(os.path.join(idadir, lib_name()))
    return idadir


def make_flat(parent):
    idadir = os.path.join(parent, "ida-flat")
    os.makedirs(idadir, exist_ok=True)
    touch(os.path.join(idadir, "idat"), executable=True)
    touch(os.path.join(idadir, lib_name()))
    return idadir


def make_mcp_bin(agent):
    path = os.path.join(agent, "ida-mcp-venv", "bin", "idalib-mcp")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("#!/bin/sh\nexit 0\n")
    os.chmod(path, 0o755)
    return path


def write_registry(path, candidates):
    payload = {"tools": [{"id": "ida", "candidates": candidates}]}
    write_bytes(path, json.dumps(payload))
    return path


def run(agent, extra=None, env_extra=None):
    env = os.environ.copy()
    env["SEEP_AGENT_DIR"] = agent
    env.pop("SEEP_IDA_ROOT", None)
    env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
    if env_extra:
        env.update(env_extra)
    cmd = [sys.executable, SCRIPT, "--agent-dir", agent]
    if extra:
        cmd.extend(extra)
    return subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env,
    )


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def main() -> int:
    if not os.path.isfile(SCRIPT):
        print("[SKIP] 找不到 setup/install-ida.py")
        return 0

    print("=== install-ida 契约测试 ===")
    real_before = snapshot(REAL_MCP)

    with open(REAL_REGISTRY, "r", encoding="utf-8") as handle:
        registry = json.load(handle)
    ida_tools = [item for item in registry.get("tools", []) if item.get("id") == "ida"]
    candidates = ida_tools[0].get("candidates", []) if ida_tools else []
    check(
        "/Applications/IDA Professional 9.0.app" in candidates
        and any(item.startswith("/Applications/IDA Professional 9.") for item in candidates),
        "注册表 id=ida 含 /Applications/IDA Professional 9.x.app",
        str(candidates[-6:]),
    )

    with tempfile.TemporaryDirectory(prefix="seep-install-ida-") as tmp:
        # ---- 1. 假 .app + 假 idalib-mcp：写入 stdio，保留其它 server
        agent = os.path.join(tmp, "agent-write")
        os.makedirs(agent, exist_ok=True)
        idadir = make_bundle(os.path.join(tmp, "bundles"))
        app_root = os.path.dirname(os.path.dirname(idadir))
        mcp_bin = make_mcp_bin(agent)
        mcp_path = os.path.join(agent, "mcp.json")
        seed = {
            "note": "keep-me",
            "mcpServers": {
                "x64dbg": {"command": "x64dbg-mcp"},
                "playwright": {"env": {"PLAYWRIGHT_MCP_EXTENSION_TOKEN": "user-real-token"}},
            },
        }
        write_bytes(mcp_path, json.dumps(seed, indent=4, ensure_ascii=False))
        empty_reg = write_registry(os.path.join(tmp, "empty-reg.json"), ["/no/such/ida-pro"])
        proc = run(agent, ["--ida-root", app_root, "--registry", empty_reg])
        check(proc.returncode == 0, "有 IDA 时退出码为 0", "rc=%s stderr=%s" % (proc.returncode, proc.stderr[-300:]))
        written = load_json(mcp_path)
        servers = written.get("mcpServers", {})
        ida = servers.get("ida", {})
        check(written.get("note") == "keep-me", "顶层非 mcpServers 字段保留")
        check(servers.get("x64dbg") == {"command": "x64dbg-mcp"}, "已有 x64dbg 不丢")
        check(
            servers.get("playwright", {}).get("env", {}).get("PLAYWRIGHT_MCP_EXTENSION_TOKEN") == "user-real-token",
            "已有 playwright token 不丢",
            str(servers.get("playwright")),
        )
        check(ida.get("command") == os.path.abspath(mcp_bin), "command 指向 venv 里的 idalib-mcp", str(ida.get("command")))
        check(ida.get("args") == ["--stdio"], "args 只有 --stdio", str(ida.get("args")))
        check(ida.get("env", {}).get("PYTHONIOENCODING") == "utf-8", "env.PYTHONIOENCODING=utf-8")
        check(ida.get("env", {}).get("IDADIR") == idadir, "IDADIR 是 Contents/MacOS", str(ida.get("env")))
        check(ida.get("transport") == "stdio", "transport=stdio")
        check(ida.get("lifecycle") == "lazy", "lifecycle=lazy")
        check(ida.get("requestTimeoutMs") == 180000, "requestTimeoutMs=180000", str(ida.get("requestTimeoutMs")))
        blob = read_bytes(mcp_path)
        check(not blob.startswith(b"\xef\xbb\xbf"), "UTF-8 无 BOM")
        check(b"\r\n" not in blob, "写盘使用 LF")
        check(b"13337" not in blob, "不写入 13337")

        # ---- 2. 没有 IDA：退出 0，且已有 mcp 一个字节都不改
        agent_miss = os.path.join(tmp, "agent-miss")
        os.makedirs(agent_miss, exist_ok=True)
        miss_mcp = os.path.join(agent_miss, "mcp.json")
        original = '{\n  "mcpServers": {\n    "x64dbg": {"command": "keep-me"}\n  }\n}\n'
        write_bytes(miss_mcp, original)
        before = read_bytes(miss_mcp)
        proc_miss = run(
            agent_miss,
            ["--registry", empty_reg],
            {"SEEP_IDA_ROOT": ""},
        )
        check(proc_miss.returncode == 0, "没有 IDA 时退出码为 0", "rc=%s" % proc_miss.returncode)
        check("未检测到 IDA" in (proc_miss.stdout or ""), "没有 IDA 时打印警告", proc_miss.stdout[-400:])
        check(read_bytes(miss_mcp) == before, "没有 IDA 时不改已有 mcp.json")
        absent_agent = os.path.join(tmp, "agent-absent")
        proc_absent = run(absent_agent, ["--registry", empty_reg])
        check(proc_absent.returncode == 0, "mcp 不存在且没有 IDA 时仍退出 0", "rc=%s" % proc_absent.returncode)
        check(not os.path.exists(os.path.join(absent_agent, "mcp.json")), "没有 IDA 且 mcp 不存在时不创建文件")

        # ---- 3. 候选路径：跳过无效目录，.app 解析为 Contents/MacOS；其它 server 仍在
        agent_cand = os.path.join(tmp, "agent-cand")
        os.makedirs(agent_cand, exist_ok=True)
        make_mcp_bin(agent_cand)
        bad = os.path.join(tmp, "bad-only-bin")
        os.makedirs(bad, exist_ok=True)
        touch(os.path.join(bad, "ida"), executable=True)
        good_dir = make_bundle(os.path.join(tmp, "cand-bundle"))
        good_app = os.path.dirname(os.path.dirname(good_dir))
        cand_reg = write_registry(
            os.path.join(tmp, "cand-reg.json"),
            ["/definitely/missing/IDA Pro", bad, good_app],
        )
        cand_mcp = os.path.join(agent_cand, "mcp.json")
        write_bytes(cand_mcp, json.dumps({"mcpServers": {"custom": {"command": "mine"}}}))
        proc_cand = run(agent_cand, ["--registry", cand_reg])
        check(proc_cand.returncode == 0, "只靠候选路径时退出码为 0", proc_cand.stderr[-200:])
        cand_ida = load_json(cand_mcp).get("mcpServers", {}).get("ida", {})
        check(cand_ida.get("env", {}).get("IDADIR") == good_dir, "候选 .app 的 IDADIR 为 Contents/MacOS", str(cand_ida.get("env")))
        check(load_json(cand_mcp)["mcpServers"].get("custom") == {"command": "mine"}, "候选路径写入时不丢其它 server")

        # ---- 4. SEEP_IDA_ROOT 优先于候选；--ida-root 再优先于环境变量
        flat = make_flat(tmp)
        agent_env = os.path.join(tmp, "agent-env")
        os.makedirs(agent_env, exist_ok=True)
        make_mcp_bin(agent_env)
        proc_env = run(agent_env, ["--registry", cand_reg], {"SEEP_IDA_ROOT": flat})
        env_ida = load_json(os.path.join(agent_env, "mcp.json")).get("mcpServers", {}).get("ida", {})
        check(env_ida.get("env", {}).get("IDADIR") == flat, "SEEP_IDA_ROOT 优先于候选路径", str(env_ida.get("env")))

        agent_cli = os.path.join(tmp, "agent-cli")
        os.makedirs(agent_cli, exist_ok=True)
        cli_bin = make_mcp_bin(agent_cli)
        decoy_dir = os.path.join(tmp, "decoy-path")
        decoy = os.path.join(decoy_dir, "idalib-mcp")
        touch(decoy, executable=True)
        proc_cli = run(
            agent_cli,
            ["--ida-root", app_root, "--registry", cand_reg],
            {
                "SEEP_IDA_ROOT": flat,
                "PATH": decoy_dir + os.pathsep + "/usr/bin:/bin",
            },
        )
        cli_ida = load_json(os.path.join(agent_cli, "mcp.json")).get("mcpServers", {}).get("ida", {})
        check(proc_cli.returncode == 0, "--ida-root 探测退出码为 0", "rc=%s" % proc_cli.returncode)
        check(cli_ida.get("env", {}).get("IDADIR") == idadir, "--ida-root 优先于 SEEP_IDA_ROOT", str(cli_ida.get("env")))
        check(os.path.basename(cli_ida.get("command") or "") == "idalib-mcp", "command 是 idalib-mcp")
        check(
            cli_ida.get("command") == os.path.abspath(cli_bin),
            "venv 里的 idalib-mcp 优先于 PATH",
            str(cli_ida.get("command")),
        )

        # PATH 上的 idalib-mcp：venv 里没有时采用它
        agent_path = os.path.join(tmp, "agent-path")
        os.makedirs(agent_path, exist_ok=True)
        path_dir = os.path.join(tmp, "path-bin")
        path_bin = os.path.join(path_dir, "idalib-mcp")
        touch(path_bin, executable=True)
        proc_path = run(
            agent_path,
            ["--ida-root", flat],
            {"PATH": path_dir + os.pathsep + "/usr/bin:/bin"},
        )
        path_ida = load_json(os.path.join(agent_path, "mcp.json")).get("mcpServers", {}).get("ida", {})
        check(proc_path.returncode == 0, "PATH 上的 idalib-mcp 可用时退出码为 0")
        check(path_ida.get("command") == os.path.abspath(path_bin), "没有 venv 命令时使用 PATH 上的 idalib-mcp", str(path_ida.get("command")))
        check(path_ida.get("args") == ["--stdio"], "PATH 命令同样写 --stdio")

        # ---- 5. 已有 command 仍在：保留用户 command，只补 IDADIR
        agent_keep = os.path.join(tmp, "agent-keep")
        os.makedirs(agent_keep, exist_ok=True)
        custom = os.path.join(agent_keep, "custom-mcp")
        touch(custom, executable=True)
        keep_mcp = os.path.join(agent_keep, "mcp.json")
        keep_seed = {
            "mcpServers": {
                "x64dbg": {"command": "still-here"},
                "ida": {
                    "command": custom,
                    "args": ["--user"],
                    "env": {"PYTHONIOENCODING": "utf-8", "OTHER": "1"},
                    "transport": "stdio",
                    "lifecycle": "eager",
                    "requestTimeoutMs": 1,
                },
            }
        }
        write_bytes(keep_mcp, json.dumps(keep_seed))
        proc_keep = run(agent_keep, ["--ida-root", flat])
        kept = load_json(keep_mcp)
        kept_ida = kept["mcpServers"]["ida"]
        check(proc_keep.returncode == 0, "保留用户 command 时退出码为 0")
        check(kept_ida.get("command") == custom, "command 仍在时不替换", str(kept_ida.get("command")))
        check(kept_ida.get("args") == ["--user"], "不改用户 args")
        check(kept_ida.get("lifecycle") == "eager", "不改用户 lifecycle")
        check(kept_ida.get("requestTimeoutMs") == 1, "不改用户 timeout")
        check(kept_ida.get("env", {}).get("OTHER") == "1", "不丢用户已有 env")
        check(kept_ida.get("env", {}).get("PYTHONIOENCODING") == "utf-8", "保留已有 PYTHONIOENCODING")
        check(kept_ida.get("env", {}).get("IDADIR") == flat, "只补缺失的 IDADIR", str(kept_ida.get("env")))
        check(kept["mcpServers"].get("x64dbg") == {"command": "still-here"}, "补 IDADIR 时不丢其它 server")

        # IDADIR 已在且 command 仍在：文件字节不变
        untouched = read_bytes(keep_mcp)
        proc_again = run(agent_keep, ["--ida-root", flat])
        check(proc_again.returncode == 0, "已完整的 ida 条目再跑退出码为 0")
        check(read_bytes(keep_mcp) == untouched, "command 仍在且 IDADIR 已有时不改写文件")

        # ---- 6. command 丢了才替换；不把 13337 留在新条目里
        agent_dead = os.path.join(tmp, "agent-dead")
        os.makedirs(agent_dead, exist_ok=True)
        dead_bin = make_mcp_bin(agent_dead)
        dead_mcp = os.path.join(agent_dead, "mcp.json")
        dead_seed = {
            "mcpServers": {
                "x64dbg": {"command": "keep"},
                "ida": {
                    "command": os.path.join(tmp, "gone", "idalib-mcp"),
                    "args": ["--host", "127.0.0.1", "--port", "13337"],
                    "transport": "http",
                },
            }
        }
        write_bytes(dead_mcp, json.dumps(dead_seed))
        proc_dead = run(agent_dead, ["--ida-root", flat])
        dead = load_json(dead_mcp)
        dead_ida = dead["mcpServers"]["ida"]
        check(proc_dead.returncode == 0, "command 丢失时退出码为 0")
        check(dead_ida.get("command") == os.path.abspath(dead_bin), "command 丢失后改用 idalib-mcp", str(dead_ida.get("command")))
        check(dead_ida.get("args") == ["--stdio"], "替换后 args 为 --stdio，不再是 13337", str(dead_ida.get("args")))
        check(dead_ida.get("transport") == "stdio", "替换后 transport=stdio")
        check(dead_ida.get("lifecycle") == "lazy", "替换后 lifecycle=lazy")
        check("13337" not in json.dumps(dead_ida), "新 ida 条目不含 13337")
        check(dead["mcpServers"].get("x64dbg") == {"command": "keep"}, "替换 ida 时不丢其它 server")

        # ---- 7. 没有命令且 --skip-pip：退出 0，不写坏 command，不改文件
        agent_skip = os.path.join(tmp, "agent-skip")
        os.makedirs(agent_skip, exist_ok=True)
        skip_mcp = os.path.join(agent_skip, "mcp.json")
        skip_text = '{"mcpServers":{"x64dbg":{"command":"keep"}}}\n'
        write_bytes(skip_mcp, skip_text)
        proc_skip = run(agent_skip, ["--ida-root", flat, "--skip-pip"])
        check(proc_skip.returncode == 0, "没有 idalib-mcp 且跳过 pip 时退出码为 0", proc_skip.stderr[-200:])
        check(read_bytes(skip_mcp) == skip_text.encode("utf-8"), "安装未执行时不写入无效 command")
        check("未写入" in (proc_skip.stdout or ""), "安装未执行时打印警告", proc_skip.stdout[-400:])

        # ---- 8. 损坏的 mcp.json 不覆盖
        agent_bad = os.path.join(tmp, "agent-bad")
        os.makedirs(agent_bad, exist_ok=True)
        make_mcp_bin(agent_bad)
        bad_mcp = os.path.join(agent_bad, "mcp.json")
        broken = "{ this is not json, keep x64dbg\n"
        write_bytes(bad_mcp, broken)
        proc_bad = run(agent_bad, ["--ida-root", flat])
        check(proc_bad.returncode == 0, "mcp.json 损坏时不让安装失败", "rc=%s" % proc_bad.returncode)
        check(read_bytes(bad_mcp) == broken.encode("utf-8"), "mcp.json 损坏时不覆盖原文件")

    real_after = snapshot(REAL_MCP)
    check(real_before == real_after, "测试没有改写真实 ~/.pi/agent/mcp.json", "before=%s after=%s" % (real_before, real_after))

    sh_path = os.path.join(HERE, "install.sh")
    with open(sh_path, "r", encoding="utf-8") as handle:
        sh = handle.read()
    marker = 'ida_py="$SCRIPT_DIR/install-ida.py"'
    start = sh.find(marker)
    block = sh[start:start + 800] if start >= 0 else ""
    check(start > 0, "install.sh 调用 install-ida.py")
    check("FAILED+=" not in block, "install.sh 的 IDA 步骤不计入 FAILED", block)
    merge_at = sh.find("mcp-merge.py")
    check(merge_at >= 0 and start > merge_at, "install-ida.py 在 mcp.json 合并之后调用")

    print("")
    if FAILS:
        print("INSTALL-IDA TESTS FAILED (%d)" % len(FAILS))
        return 1
    print("INSTALL-IDA OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
