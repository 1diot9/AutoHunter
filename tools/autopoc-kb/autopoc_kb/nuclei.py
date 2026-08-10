"""Nuclei 模板扫描（标准库）。"""

from __future__ import annotations

import json
import os
import select
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Iterator


class NucleiRunnerError(Exception):
    def __init__(self, message: str, *, code: str = "error") -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def find_nuclei() -> str:
    n = shutil.which("nuclei")
    if not n:
        raise NucleiRunnerError(
            "nuclei 未安装，请先运行 "
            "`go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`",
            code="not_found",
        )
    return n


def list_nuclei_templates(nuclei_root: Path | str | None) -> list[Path]:
    if not nuclei_root:
        return []
    base = Path(nuclei_root)
    if not base.is_dir():
        return []
    return sorted(
        p
        for p in base.glob("*.y*ml")
        if p.is_file() and not p.name.startswith(".")
    )


def split_extra_flags(extra_flags: str | None) -> list[str]:
    if not extra_flags or not str(extra_flags).strip():
        return []
    return [f for f in str(extra_flags).split() if f]


def _is_code_protocol_template(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if line[:1] not in (" ", "\t") and stripped.startswith("code:"):
            return True
    return False


def templates_need_code_flag(templates: list[Path]) -> bool:
    return any(_is_code_protocol_template(t) for t in templates)


def _with_code_flag_if_needed(extra: list[str], templates: list[Path]) -> list[str]:
    out = list(extra)
    if not templates_need_code_flag(templates):
        return out
    lowered = {f.lower() for f in out}
    if "-code" in lowered or "-enable-code" in lowered:
        return out
    out.append("-code")
    return out


def _build_cmd(
    nuclei_bin: str,
    templates: list[Path],
    targets_file: str,
    extra: list[str],
) -> list[str]:
    if not templates:
        raise NucleiRunnerError("no nuclei templates", code="bad_request")
    cmd = [nuclei_bin]
    parents = {t.parent.resolve() for t in templates}
    if len(parents) == 1 and len(templates) == len(list(templates[0].parent.glob("*.y*ml"))):
        cmd.extend(["-t", str(templates[0].parent)])
    else:
        for t in templates:
            cmd.extend(["-t", str(t)])
    cmd.extend(
        [
            "-l",
            targets_file,
            "-j",
            "-silent",
            "-no-color",
            "-no-stdin",
            "-duc",
        ]
    )
    cmd.extend(_with_code_flag_if_needed(extra, templates))
    return cmd


def _kill_proc(proc: subprocess.Popen[bytes]) -> None:
    try:
        proc.kill()
    except OSError:
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def iter_nuclei_events(
    targets: list[str],
    templates: list[Path],
    *,
    extra_flags: list[str] | None = None,
    timeout: int | None = None,
    nuclei_bin: str | None = None,
) -> Iterator[dict[str, Any]]:
    if not targets:
        raise NucleiRunnerError("至少需要一个目标 URL", code="bad_request")
    if not templates:
        raise NucleiRunnerError("no nuclei templates", code="bad_request")

    bin_path = nuclei_bin or find_nuclei()
    extra = list(extra_flags or [])
    tf_path: str | None = None
    started = time.monotonic()
    hit = False
    output_lines: list[str] = []
    matches: list[Any] = []
    exit_code: int | None = None
    timed_out = False
    cmd: list[str] = []

    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(targets))
            tf_path = tf.name

        cmd = _build_cmd(bin_path, templates, tf_path, extra)
        yield {"type": "start", "command": cmd, "templates": [str(t) for t in templates]}

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=False,
        )
        try:
            assert proc.stdout is not None
            deadline = (started + timeout) if timeout and timeout > 0 else None
            buf = b""
            while True:
                if deadline is not None and time.monotonic() > deadline:
                    timed_out = True
                    _kill_proc(proc)
                    exit_code = -1
                    yield {"type": "error", "error": f"timed out after {timeout}s"}
                    break

                wait = 0.5
                if deadline is not None:
                    wait = max(0.05, min(wait, deadline - time.monotonic()))
                ready, _, _ = select.select([proc.stdout], [], [], wait)
                if not ready:
                    if proc.poll() is not None:
                        rest = proc.stdout.read() or b""
                        buf += rest
                        break
                    continue

                chunk = proc.stdout.read(65536)
                if not chunk:
                    if proc.poll() is not None:
                        break
                    continue
                buf += chunk

                while True:
                    nl = buf.find(b"\n")
                    if nl < 0:
                        break
                    raw = buf[:nl]
                    buf = buf[nl + 1 :]
                    line = raw.decode("utf-8", errors="replace").rstrip()
                    if not line:
                        continue
                    output_lines.append(line)
                    try:
                        parsed = json.loads(line)
                        hit = True
                        matches.append(parsed)
                        yield {"type": "result", "matched": True, "data": parsed}
                    except json.JSONDecodeError:
                        yield {"type": "output", "line": line}

            if buf and exit_code is None:
                line = buf.decode("utf-8", errors="replace").rstrip()
                if line:
                    output_lines.append(line)
                    try:
                        parsed = json.loads(line)
                        hit = True
                        matches.append(parsed)
                        yield {"type": "result", "matched": True, "data": parsed}
                    except json.JSONDecodeError:
                        yield {"type": "output", "line": line}

            if exit_code is None:
                proc.wait()
                exit_code = proc.returncode
        except Exception as exc:  # noqa: BLE001
            exit_code = -1
            yield {"type": "error", "error": str(exc)}
            _kill_proc(proc)
    finally:
        if tf_path:
            try:
                os.unlink(tf_path)
            except OSError:
                pass

    duration_ms = int((time.monotonic() - started) * 1000)
    yield {
        "type": "done",
        "hit": hit,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "output": "\n".join(output_lines[-50:]),
        "output_lines": output_lines,
        "matches": matches,
        "command": cmd,
        "duration_ms": duration_ms,
        "templates": [str(t) for t in templates],
    }


def run_nuclei_on_templates(
    targets: list[str],
    templates: list[Path],
    *,
    extra_flags: list[str] | None = None,
    timeout: int | None = None,
    nuclei_bin: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "hit": False,
        "exit_code": None,
        "timed_out": False,
        "output": "",
        "matches": [],
        "command": [],
        "duration_ms": 0,
        "templates": [str(t) for t in templates],
        "error": None,
    }
    for ev in iter_nuclei_events(
        targets,
        templates,
        extra_flags=extra_flags,
        timeout=timeout,
        nuclei_bin=nuclei_bin,
    ):
        if ev.get("type") == "error" and result["error"] is None:
            result["error"] = ev.get("error")
        if ev.get("type") == "done":
            result.update(
                {
                    "hit": bool(ev.get("hit")),
                    "exit_code": ev.get("exit_code"),
                    "timed_out": bool(ev.get("timed_out")),
                    "output": ev.get("output") or "",
                    "matches": ev.get("matches") or [],
                    "command": ev.get("command") or [],
                    "duration_ms": ev.get("duration_ms") or 0,
                    "templates": ev.get("templates") or result["templates"],
                }
            )
    return result
