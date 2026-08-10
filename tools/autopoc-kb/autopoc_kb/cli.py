"""AutoPoc kb-only CLI：检索 / 读产物 / Nuclei / PoC（对齐 MCP autopoc-vuln-kb）。

用法：

  ./autopoc-kb.sh list-components                 # 列出全部组件
  ./autopoc-kb.sh list-components -q spring       # 模糊搜组件
  ./autopoc-kb.sh search-vulns --component confluence   # 默认 --kb-dir ./kb
  ./autopoc-kb.sh --kb-dir /path/to/kb get-vuln --id CVE-2024-21683
  export AUTOPOC_KB_DIR=/path/to/kb
  python3 -m autopoc_kb get-vuln --id CVE-2024-21683

重要：run-poc / run-nuclei 只后台启动任务并立刻返回 job_id，
不会自动打印最终结果；须再调用 get-poc-result / get-nuclei-result 轮询。
可选 --wait 在本进程内阻塞到结束。输出默认 JSON（stdout）。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any

from . import store
from .errors import MAX_NUCLEI_VULNS, SEARCH_SEVERITIES, VulnKbError
from .poc import flag_args_to_argv

DEFAULT_POLL_INTERVAL = 1.0


class _HelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Omit suppressed actions; hide the redundant commands metavar line."""

    def _format_action(self, action: argparse.Action) -> str:
        if action.help is argparse.SUPPRESS:
            return ""
        parts = super()._format_action(action)
        if getattr(action, "nargs", None) == argparse.PARSER:
            lines = parts.splitlines(keepends=True)
            return "".join(lines[1:]) if len(lines) > 1 else parts
        return parts


def _json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)


def _emit(data: Any) -> None:
    print(_json(data), flush=True)


def _err(exc: VulnKbError) -> int:
    _emit({"error": True, "code": exc.code, "message": exc.message})
    return 1


def _parse_id_keys(raw: str) -> list[str]:
    parts = [p.strip() for p in str(raw).replace(" ", ",").split(",") if p.strip()]
    if not parts:
        raise argparse.ArgumentTypeError("至少需要一个 vuln id / identifier / slug")
    return parts


def _as_vuln_id(raw: str) -> str:
    s = str(raw).strip()
    if not s:
        raise VulnKbError("vuln id is required", code="bad_request")
    return s


def _parse_args_json(raw: str | None) -> dict[str, Any]:
    if raw is None or not str(raw).strip():
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"--args-json 不是合法 JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit('--args-json 须为 JSON object，如 {"--url":"http://x"}')
    return data


def _argv_to_flag_args(argv: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    i = 0
    while i < len(argv):
        tok = argv[i]
        if not tok.startswith("-"):
            raise SystemExit(f"PoC 参数须以 - 开头的 flag：{tok!r}")
        if "=" in tok and not tok.startswith("-="):
            flag, _, val = tok.partition("=")
            out[flag] = val
            i += 1
            continue
        nxt = argv[i + 1] if i + 1 < len(argv) else None
        if nxt is None or nxt.startswith("-"):
            out[tok] = True
            i += 1
            continue
        out[tok] = nxt
        i += 2
    return out


def _wait_poc(job_id: str, *, poll_interval: float) -> dict[str, Any]:
    while True:
        result = store.get_poc_result(job_id=job_id)
        status = str(result.get("status") or "")
        if status not in ("pending", "running"):
            return result
        time.sleep(max(0.1, poll_interval))


def _wait_nuclei(job_id: str, *, poll_interval: float) -> dict[str, Any]:
    while True:
        result = store.get_nuclei_result(job_id=job_id)
        status = str(result.get("status") or "")
        if status not in ("pending", "running"):
            return result
        time.sleep(max(0.1, poll_interval))


def cmd_list_components(ns: argparse.Namespace) -> int:
    try:
        _emit(store.list_components(q=ns.q, limit=ns.limit))
        return 0
    except VulnKbError as exc:
        return _err(exc)


def cmd_search_vulns(ns: argparse.Namespace) -> int:
    try:
        _emit(
            store.search_vulns(
                component=ns.component,
                severity=ns.severity,
                limit=ns.limit,
            )
        )
        return 0
    except VulnKbError as exc:
        return _err(exc)


def cmd_get_vuln(ns: argparse.Namespace) -> int:
    try:
        _emit(store.get_vuln(vuln_id=_as_vuln_id(ns.id)))
        return 0
    except VulnKbError as exc:
        return _err(exc)


def cmd_get_artifact(ns: argparse.Namespace) -> int:
    try:
        data = store.get_artifact(
            vuln_id=_as_vuln_id(ns.id),
            path=ns.path,
            offset=ns.offset,
            max_chars=ns.max_chars,
            full=ns.full,
        )
        if ns.raw:
            sys.stdout.write(str(data.get("content") or ""))
            if not str(data.get("content") or "").endswith("\n"):
                sys.stdout.write("\n")
            sys.stdout.flush()
            if data.get("truncated"):
                meta = {
                    "truncated": True,
                    "next_offset": data.get("next_offset"),
                    "total_chars": data.get("total_chars"),
                }
                print(_json(meta), file=sys.stderr, flush=True)
            return 0
        _emit(data)
        return 0
    except VulnKbError as exc:
        return _err(exc)


def cmd_get_poc_meta(ns: argparse.Namespace) -> int:
    try:
        _emit(store.get_poc_meta_mcp(vuln_id=_as_vuln_id(ns.id)))
        return 0
    except VulnKbError as exc:
        return _err(exc)


def cmd_run_poc(ns: argparse.Namespace) -> int:
    flag_args = _parse_args_json(ns.args_json)
    if ns.poc_argv:
        flag_args = {**flag_args, **_argv_to_flag_args(list(ns.poc_argv))}
    if not flag_args:
        print(
            "run-poc 需要 PoC 参数：在 -- 后传 flag，或用 --args-json。"
            "例：run-poc --id CVE-xxx -- --url http://127.0.0.1:8080",
            file=sys.stderr,
        )
        return 2
    try:
        flag_args_to_argv(flag_args)
    except ValueError as exc:
        _emit({"error": True, "code": "bad_request", "message": str(exc)})
        return 1

    try:
        started = store.run_poc_mcp(
            vuln_id=_as_vuln_id(ns.id),
            args=flag_args,
            script=ns.script,
            timeout=ns.timeout,
        )
        if not ns.wait:
            _emit(started)
            return 0
        job_id = str(started.get("job_id") or "")
        if not job_id:
            _emit(started)
            return 1
        result = _wait_poc(job_id, poll_interval=ns.poll_interval)
        _emit(result)
        status = str(result.get("status") or "")
        if status == "failed":
            return 1
        if status == "done" and result.get("exit_code") not in (0, None):
            return 1
        return 0
    except VulnKbError as exc:
        return _err(exc)


def cmd_get_poc_result(ns: argparse.Namespace) -> int:
    try:
        result = store.get_poc_result(job_id=ns.job_id)
        _emit(result)
        return 0 if str(result.get("status") or "") != "failed" else 1
    except VulnKbError as exc:
        return _err(exc)


def cmd_run_nuclei(ns: argparse.Namespace) -> int:
    try:
        ids: list[str] = [_as_vuln_id(x) for x in ns.ids]
        started = store.run_nuclei(
            vuln_ids=ids,
            target=ns.target,
            extra_flags=ns.extra_flags,
            timeout=ns.timeout,
        )
        if not ns.wait:
            _emit(started)
            return 0
        job_id = str(started.get("job_id") or "")
        if not job_id:
            _emit(started)
            return 1
        result = _wait_nuclei(job_id, poll_interval=ns.poll_interval)
        _emit(result)
        return 0 if str(result.get("status") or "") != "failed" else 1
    except VulnKbError as exc:
        return _err(exc)


def cmd_get_nuclei_result(ns: argparse.Namespace) -> int:
    try:
        result = store.get_nuclei_result(job_id=ns.job_id)
        _emit(result)
        return 0 if str(result.get("status") or "") != "failed" else 1
    except VulnKbError as exc:
        return _err(exc)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="autopoc-kb",
        description=(
            "漏洞库 CLI：检索 → Nuclei / PoC（默认 kb: ./kb；仅授权目标）。"
            "run-poc / run-nuclei 只返回 job_id，须手动 get-*-result 取结果。"
        ),
        epilog=(
            "示例:\n"
            "  autopoc-kb list-components\n"
            "  autopoc-kb list-components -q spring\n"
            "  autopoc-kb search-vulns -c confluence\n"
            "  autopoc-kb get-vuln --id CVE-2024-21683\n"
            "  autopoc-kb run-poc --id CVE-xxx -- --url http://127.0.0.1:8080\n"
            "  autopoc-kb get-poc-result --job-id <job_id>   # 须手动轮询\n"
            "  autopoc-kb run-nuclei --ids CVE-xxx --target http://127.0.0.1:8090\n"
            "  autopoc-kb get-nuclei-result --job-id <job_id>  # 须手动轮询\n"
            "  autopoc-kb run-poc -h"
        ),
        formatter_class=_HelpFormatter,
    )
    p.add_argument(
        "--kb-dir",
        default=os.environ.get("AUTOPOC_KB_DIR") or "./kb",
        help="知识库目录（默认 ./kb）",
    )
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND", title="commands")

    def _add(name: str, **kwargs: Any) -> argparse.ArgumentParser:
        return sub.add_parser(name, **kwargs)

    id_help = "漏洞 id / identifier / slug"

    sp = _add("list-components", help="列出 / 模糊搜组件")
    sp.add_argument("-q", "--q", default=None, help="组件名模糊关键词（省略则列出全部）")
    sp.add_argument(
        "-n",
        "--limit",
        type=int,
        default=0,
        help="返回条数上限；0 表示不截断（默认）",
    )
    sp.set_defaults(func=cmd_list_components)

    sp = _add("search-vulns", help="检索漏洞")
    sp.add_argument("-c", "--component", default=None, help="组件（模糊）")
    sp.add_argument(
        "-s",
        "--severity",
        default="critical",
        metavar="{" + ",".join(SEARCH_SEVERITIES) + "}",
        help="严重度，可逗号组合，默认 critical",
    )
    sp.add_argument("-n", "--limit", type=int, default=10, help="条数上限，默认 10")
    sp.set_defaults(func=cmd_search_vulns)

    sp = _add("get-vuln", help="漏洞元数据")
    sp.add_argument("--id", required=True, help=id_help)
    sp.set_defaults(func=cmd_get_vuln)

    sp = _add("get-artifact", help="读产物")
    sp.add_argument("--id", required=True, help=id_help)
    sp.add_argument("--path", required=True, help="相对路径，如 report.md")
    sp.add_argument("--offset", type=int, default=0, help="字符偏移")
    sp.add_argument("--max-chars", type=int, default=30000, help="最多返回字符数")
    sp.add_argument("--full", action="store_true", help="更大分块")
    sp.add_argument("--raw", action="store_true", help="仅输出 content")
    sp.set_defaults(func=cmd_get_artifact)

    sp = _add("get-poc-meta", help="PoC 参数说明")
    sp.add_argument("--id", required=True, help=id_help)
    sp.set_defaults(func=cmd_get_poc_meta)

    sp = _add(
        "run-poc",
        help="后台启动 PoC（立刻返回 job_id；须再 get-poc-result 取结果）",
        description=(
            "后台启动 PoC，立刻打印含 job_id 的 JSON，不会自动等待结束。"
            "必须再用 get-poc-result --job-id … 轮询最终结果。"
            "若要本进程阻塞到结束，加 --wait。"
        ),
    )
    sp.add_argument("--id", required=True, help=id_help)
    sp.add_argument("--script", default=None, help="相对 poc/ 的 .py")
    sp.add_argument("--timeout", type=int, default=None, help="超时秒数")
    sp.add_argument("--args-json", default=None, help='JSON 参数，如 {"--url":"http://x"}')
    sp.add_argument(
        "--wait",
        action="store_true",
        help="可选：本进程内轮询到结束再打印结果（默认不自动取结果，须手动 get-poc-result）",
    )
    sp.add_argument(
        "--poll-interval",
        type=float,
        default=DEFAULT_POLL_INTERVAL,
        help="仅 --wait 时生效：轮询间隔秒数（默认 1）",
    )
    sp.add_argument(
        "poc_argv",
        nargs=argparse.REMAINDER,
        help="PoC 参数：写在 -- 之后",
    )
    sp.set_defaults(func=cmd_run_poc)

    sp = _add(
        "get-poc-result",
        help="【必调】轮询 PoC 结果（run-poc 返回 job_id 后）",
        description=(
            "按 job_id 查询 PoC 执行结果。run-poc 默认只启动任务，"
            "不会自动回调；须反复调用本命令直到 status 为 done/failed。"
        ),
    )
    sp.add_argument("--job-id", required=True, help="run-poc 返回的 job_id")
    sp.set_defaults(func=cmd_get_poc_result)

    sp = _add(
        "run-nuclei",
        help="后台启动 Nuclei（立刻返回 job_id；须再 get-nuclei-result 取结果）",
        description=(
            "后台启动 Nuclei，立刻打印含 job_id 的 JSON，不会自动等待结束。"
            "必须再用 get-nuclei-result --job-id … 轮询最终结果。"
            "若要本进程阻塞到结束，加 --wait。"
        ),
    )
    sp.add_argument(
        "--ids",
        type=_parse_id_keys,
        required=True,
        help=f"id/identifier/slug，逗号分隔，最多 {MAX_NUCLEI_VULNS} 条",
    )
    sp.add_argument("--target", required=True, help="目标 URL/host")
    sp.add_argument("--extra-flags", default=None, help="附加 nuclei 参数")
    sp.add_argument("--timeout", type=int, default=None, help="超时秒数")
    sp.add_argument(
        "--wait",
        action="store_true",
        help="可选：本进程内轮询到结束再打印结果（默认不自动取结果，须手动 get-nuclei-result）",
    )
    sp.add_argument(
        "--poll-interval",
        type=float,
        default=DEFAULT_POLL_INTERVAL,
        help="仅 --wait 时生效：轮询间隔秒数（默认 1）",
    )
    sp.set_defaults(func=cmd_run_nuclei)

    sp = _add(
        "get-nuclei-result",
        help="【必调】轮询 Nuclei 结果（run-nuclei 返回 job_id 后）",
        description=(
            "按 job_id 查询 Nuclei 扫描结果。run-nuclei 默认只启动任务，"
            "不会自动回调；须反复调用本命令直到 status 为 done/failed。"
        ),
    )
    sp.add_argument("--job-id", required=True, help="run-nuclei 返回的 job_id")
    sp.set_defaults(func=cmd_get_nuclei_result)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    ns = parser.parse_args(argv)
    if getattr(ns, "poc_argv", None):
        if ns.poc_argv and ns.poc_argv[0] == "--":
            ns.poc_argv = ns.poc_argv[1:]

    kb_dir = (getattr(ns, "kb_dir", None) or "").strip() or None
    if not kb_dir:
        _emit(
            {
                "error": True,
                "code": "bad_request",
                "message": "需要 --kb-dir PATH 或环境变量 AUTOPOC_KB_DIR",
            }
        )
        return 2
    try:
        store.bind(kb_dir)
    except VulnKbError as exc:
        return _err(exc)

    return int(ns.func(ns))


if __name__ == "__main__":
    raise SystemExit(main())
