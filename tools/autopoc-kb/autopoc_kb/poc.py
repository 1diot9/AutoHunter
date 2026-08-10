"""解析 PoC argparse 并同步执行 Python 脚本（标准库，无代理池）。"""

from __future__ import annotations

import ast
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

_IS_WIN = sys.platform == "win32"
_POC_SKIP_DIRS = frozenset({"logs", "__pycache__", ".git", "node_modules"})


def list_python_pocs(poc_root: Path) -> list[Path]:
    if not poc_root.is_dir():
        return []
    root = poc_root.resolve()
    out: list[Path] = []
    for p in sorted(root.rglob("*.py")):
        if not p.is_file():
            continue
        rel_parts = p.relative_to(root).parts
        if any(part in _POC_SKIP_DIRS for part in rel_parts):
            continue
        if p.name.startswith("."):
            continue
        out.append(p)
    return out


def resolve_poc_script(poc_root: Path, script: str) -> Path:
    root = poc_root.resolve()
    rel = script.lstrip("/").replace("\\", "/")
    if not rel or ".." in Path(rel).parts:
        raise ValueError("非法脚本路径")
    target = (root / rel).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise ValueError("脚本路径越界") from exc
    if target.suffix.lower() != ".py" or not target.is_file():
        raise ValueError("脚本不存在或不是 Python 文件")
    allowed = {p.resolve() for p in list_python_pocs(root)}
    if target not in allowed:
        raise ValueError("脚本不在可运行列表中")
    return target


def _literal(node: ast.AST | None) -> Any:
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except Exception:  # noqa: BLE001
        if isinstance(node, ast.Name):
            if node.id == "True":
                return True
            if node.id == "False":
                return False
            if node.id == "None":
                return None
        return None


def _type_name(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _dest_from_flags(flags: list[str], dest: str | None) -> str:
    if dest:
        return dest
    for flag in flags:
        if flag.startswith("--"):
            return flag[2:].replace("-", "_")
    for flag in flags:
        if flag.startswith("-") and not flag.startswith("--"):
            return flag.lstrip("-").replace("-", "_")
    return flags[0].lstrip("-").replace("-", "_") if flags else "arg"


def _parse_add_argument(call: ast.Call) -> dict[str, Any] | None:
    flags: list[str] = []
    for arg in call.args:
        val = _literal(arg)
        if isinstance(val, str):
            flags.append(val)
    if not flags:
        return None

    kwargs: dict[str, Any] = {}
    for kw in call.keywords:
        if not kw.arg:
            continue
        if kw.arg == "type":
            kwargs["type"] = _type_name(kw.value)
        elif kw.arg == "choices":
            choices = _literal(kw.value)
            if isinstance(choices, (list, tuple)):
                kwargs["choices"] = [str(c) for c in choices]
        else:
            kwargs[kw.arg] = _literal(kw.value)

    positional = not any(f.startswith("-") for f in flags)
    action = kwargs.get("action")
    arg_type = "str"
    if action in ("store_true", "store_false"):
        arg_type = "bool"
    else:
        t = kwargs.get("type")
        if t in ("int", "float", "str"):
            arg_type = t

    required = bool(kwargs.get("required", False))
    if positional:
        required = kwargs.get("nargs") not in ("?", "*", "+") and "default" not in kwargs

    default = kwargs.get("default")
    if arg_type == "bool":
        if action == "store_true":
            default = False if default is None else bool(default)
        elif action == "store_false":
            default = True if default is None else bool(default)

    name = _dest_from_flags(flags, kwargs.get("dest") if isinstance(kwargs.get("dest"), str) else None)
    help_text = kwargs.get("help")
    if help_text is not None:
        help_text = str(help_text)

    return {
        "name": name,
        "flags": flags,
        "positional": positional,
        "required": required,
        "arg_type": arg_type,
        "default": default,
        "help": help_text,
        "choices": kwargs.get("choices"),
        "action": action,
    }


def parse_argparse_script(path: Path) -> tuple[str | None, list[dict[str, Any]], bool]:
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(path))
    except Exception:  # noqa: BLE001
        return None, [], False

    description: str | None = None
    args: list[dict[str, Any]] = []
    seen: set[str] = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        is_parser = False
        if isinstance(func, ast.Attribute) and func.attr == "ArgumentParser":
            is_parser = True
        elif isinstance(func, ast.Name) and func.id == "ArgumentParser":
            is_parser = True
        if is_parser and description is None:
            for kw in node.keywords:
                if kw.arg == "description":
                    val = _literal(kw.value)
                    if isinstance(val, str):
                        description = val
            continue

        if isinstance(func, ast.Attribute) and func.attr == "add_argument":
            parsed = _parse_add_argument(node)
            if not parsed:
                continue
            if parsed["name"] in seen:
                continue
            seen.add(parsed["name"])
            args.append(parsed)

    return description, args, True


def prefer_cli_flag(flags: list[str]) -> str | None:
    opts = [f for f in flags if isinstance(f, str) and f.startswith("-")]
    if not opts:
        return None
    for f in opts:
        if f.startswith("--"):
            return f
    return opts[0]


def flag_args_to_argv(flag_args: dict[str, Any] | None) -> list[str]:
    if not flag_args:
        return []
    out: list[str] = []
    for key, raw in flag_args.items():
        flag = str(key).strip()
        if not flag.startswith("-"):
            raise ValueError(f"参数键必须是 CLI flag（以 - 开头）: {key!r}")
        if raw is False or raw is None or raw == "":
            continue
        if raw is True:
            out.append(flag)
            continue
        out.extend([flag, str(raw)])
    return out


def _subprocess_group_kwargs() -> dict[str, Any]:
    if _IS_WIN:
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}  # type: ignore[attr-defined]
    return {"start_new_session": True}


def _kill_process_tree(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    pid = proc.pid
    if _IS_WIN:
        try:
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except OSError:
            try:
                proc.terminate()
            except Exception:  # noqa: BLE001
                pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass
        return
    try:
        os.killpg(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.terminate()
        except Exception:  # noqa: BLE001
            pass
    try:
        proc.wait(timeout=3)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def run_poc_script(
    poc_root: Path,
    script: str,
    *,
    extra_args: list[str] | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    """同步执行 PoC，返回 command / stdout / stderr / exit_code / timed_out。"""
    root = poc_root.resolve()
    target = resolve_poc_script(root, script)
    rel = str(target.relative_to(root)).replace("\\", "/")
    command = [sys.executable or "python3", rel, *(str(a) for a in (extra_args or []) if str(a).strip())]

    env = {**os.environ, "PYTHONUNBUFFERED": "1", "PYTHONIOENCODING": "utf-8"}
    started = time.monotonic()
    timed_out = False
    proc = subprocess.Popen(
        command,
        cwd=str(root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        **_subprocess_group_kwargs(),
    )
    try:
        stdout, stderr = proc.communicate(timeout=max(1, int(timeout)))
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_process_tree(proc)
        stdout, stderr = proc.communicate(timeout=5)
    exit_code = proc.returncode
    if timed_out and exit_code is None:
        exit_code = -1
    return {
        "script": rel,
        "command": command,
        "stdout": stdout or "",
        "stderr": stderr or "",
        "exit_code": exit_code,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "timed_out": timed_out,
    }
