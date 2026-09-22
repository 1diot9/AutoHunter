"""工具执行器：worker 真实挖洞的底层能力。

提供给 LLM 通过 function calling 调用：
- run_shell: 受控执行任意命令（带超时、输出截断、自毁防护、工作目录隔离）
- http_request: 发原始 HTTP 请求，返回完整请求包+响应包（取证用）
"""
from __future__ import annotations

import os
import selectors
import shlex
import signal
import sqlite3
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qsl, urlparse

import httpx

from app.agents.prefilter import capped_resolution
from app.config import worker_config
from app.http_defaults import BROWSER_UA
from app.memory import drop_file_cache, drop_tree_cache, trim_process_memory
from app.tools import autopoc_bridge
from app.tools.decoder import decode_transform as _decode_transform
from app.tools.guard import CommandBlocked, NeedsConfirm, check_command, check_http_request
from app.tools.js_analyzer import analyze_javascript as analyze_js_text
from app.tools.js_analyzer import analyze_url as analyze_js_url
from app.tools.waf_advisor import suggest_waf_bypass as _suggest_waf_bypass

# 只读测绘查询硬上限：worker 用它确认归属/探攻击面，不是全量测绘，给小额度即可。
_FOFA_LOOKUP_MAX_SIZE = 30
# 企业 session cookie jar 上限，防异常站点塞爆内存。
_SESSION_MAX_COOKIES = 50
_SESSION_MAX_HEADERS = 30
# 用户 cookie 跟随跳转时最多再走几跳，避免开放重定向把凭据送到一长串外站。
_REDIRECT_HOST_HOPS = 4
# 代理服务器被标记为不健康后的冷却时间（秒）。冷却结束后重新纳入轮询候选。
# 轮询策略：每次请求后轮转到下一台健康代理，分散流量降低单 IP 被目标 WAF 封禁概率。
_PROXY_UNHEALTHY_COOLDOWN = int(os.environ.get("PROXY_UNHEALTHY_COOLDOWN", "60"))
# 连续失败多少次才标记不健康（避免单次网络抖动误杀）。
_PROXY_FAIL_THRESHOLD = 2

# 单目标工作目录落地日志体积上限（字节）。24x7 防撞盘：超限后停止写新日志文件，
# 仍把截断输出回传给 LLM，不影响挖掘，只是不再落地完整证据。
_WORKDIR_MAX_BYTES = int(os.environ.get("WORKER_WORKDIR_MAX_BYTES", str(50 * 1024 * 1024)))
# 每写这么多次日志做一次真实全目录体积校准（捕获 shell 子进程 curl -o/wget/重定向直落的顶层文件；
# _dir_size 用非递归 glob，只数顶层文件，git clone 落的子目录树不在统计内）。
_WORKDIR_RESCAN_EVERY = 32
_SHELL_CAPTURE_MAX_BYTES = int(os.environ.get("WORKER_SHELL_CAPTURE_MAX_BYTES", str(512 * 1024)))
_HTTP_MAX_BYTES = int(os.environ.get("WORKER_HTTP_MAX_BYTES", str(1024 * 1024)))
_REFLECT_GUIDANCE = (
    "本次未执行。请先反思：会不会删库、清缓存、覆盖已有文件导致改不回？"
    "能改成 SRC_TEST_ 哨兵、ROLLBACK、或只证明接口存在就不要做破坏。"
    "若确认是无害验证，再次调用并设 confirm_destructive=true，confirm_reason 写明原因。"
)


def _confirm_pause(exc: NeedsConfirm) -> dict[str, Any]:
    return {
        "ok": False,
        "needs_confirm": True,
        "error": f"疑似不可逆操作，先停一下：{exc.reason}",
        "guidance": _REFLECT_GUIDANCE,
    }


def _truncate(text: str, limit: Optional[int] = None) -> str:
    if limit is None:
        limit = worker_config.output_truncate
        if worker_config.llm_tool_output_truncate > 0:
            limit = min(limit, worker_config.llm_tool_output_truncate)
    else:
        limit = int(limit)
    if len(text) <= limit:
        return text
    head = text[: limit // 2]
    tail = text[-limit // 4 :]
    return f"{head}\n\n...[输出过长已截断，完整内容已写入工作目录文件]...\n\n{tail}"


def _normalize_headers(headers: Any) -> dict[str, str]:
    """把 LLM 可能乱传的 headers 统一成 {str: str}，容错非 dict 形态，绝不抛异常。

    支持：
      - dict            → 原样（值转字符串）
      - list["K: V"]    → 逐行按第一个冒号切分
      - "K: V\\nK2: V2"  → 按行切分
      - None / 其它      → {}
    """
    if not headers:
        return {}
    if isinstance(headers, dict):
        return {str(k): str(v) for k, v in headers.items()}
    lines: list[str] = []
    if isinstance(headers, str):
        lines = headers.splitlines()
    elif isinstance(headers, (list, tuple)):
        for item in headers:
            if isinstance(item, dict):
                # list[{"name":..,"value":..}] 或 list[{"K":"V"}]
                if "name" in item and "value" in item:
                    lines.append(f"{item['name']}: {item['value']}")
                else:
                    lines.extend(f"{k}: {v}" for k, v in item.items())
            else:
                lines.append(str(item))
    else:
        return {}
    out: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip()
        if k:
            out[k] = v.strip()
    return out


def _host_from_url(url: str) -> str:
    raw = url or ""
    if "://" not in raw:
        raw = "http://" + raw
    try:
        return (urlparse(raw).hostname or "").lower()
    except Exception:
        return ""


def _cookie_host_ok(domain: str, host: str) -> bool:
    d = (domain or "").lstrip(".").lower()
    h = (host or "").lower()
    if not h:
        return False
    if not d:
        return True
    return h == d or h.endswith("." + d)


def _redirect_hop(url: str, cookies: dict[str, str]) -> tuple[int, str]:
    """只读一跳 Location，不把响应 Set-Cookie 写进会话。"""
    headers = {"User-Agent": BROWSER_UA}
    if cookies:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    with httpx.Client(verify=False, timeout=12, follow_redirects=False, trust_env=False) as client:
        resp = client.get(url, headers=headers)
    return int(resp.status_code or 0), str(resp.headers.get("location") or "")


def _parse_cookie_header(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in (raw or "").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, _, v = part.partition("=")
        k, v = k.strip(), v.strip()
        if k:
            out[k] = v
    return out


def _split_set_cookie(raw: str) -> tuple[str, str, str, str] | None:
    """Parse a Set-Cookie value into (name, value, domain, path)."""
    parts = [p.strip() for p in (raw or "").split(";") if p.strip()]
    if not parts or "=" not in parts[0]:
        return None
    name, _, value = parts[0].partition("=")
    name, value = name.strip(), value.strip()
    if not name:
        return None
    domain = ""
    path = "/"
    for attr in parts[1:]:
        if "=" not in attr:
            continue
        ak, _, av = attr.partition("=")
        akl = ak.strip().lower()
        if akl == "domain":
            domain = av.strip()
        elif akl == "path":
            path = av.strip() or "/"
    return name, value, domain, path


def _pop_header(headers: dict[str, str], name: str) -> str:
    for k in list(headers.keys()):
        if k.lower() == name.lower():
            return str(headers.pop(k) or "")
    return ""


def _normalize_files(files: Any, work_dir: Path) -> dict[str, Any] | None:
    if not files or not isinstance(files, dict):
        return None
    root = work_dir.resolve()
    out: dict[str, Any] = {}
    for field, spec in files.items():
        name = str(field)
        if isinstance(spec, (bytes, bytearray)):
            out[name] = (name, bytes(spec))
            continue
        if isinstance(spec, str):
            if spec.startswith("@") or spec.startswith("file:"):
                rel = spec[1:] if spec.startswith("@") else spec[5:]
                data = _read_work_file(rel, root)
                if data is None:
                    continue
                out[name] = (Path(rel).name or name, data)
            else:
                out[name] = (name, spec.encode("utf-8"))
            continue
        if isinstance(spec, dict):
            filename = str(spec.get("filename") or spec.get("name") or name)
            ctype = str(spec.get("content_type") or spec.get("contentType") or "application/octet-stream")
            path = spec.get("path") or spec.get("file")
            content = spec.get("content")
            if content is None:
                content = spec.get("data")
            if content is None:
                content = spec.get("value")
            if path:
                data = _read_work_file(str(path), root)
                if data is None:
                    continue
                filename = str(spec.get("filename") or Path(str(path)).name or filename)
                out[name] = (filename, data, ctype)
            elif isinstance(content, (bytes, bytearray)):
                out[name] = (filename, bytes(content), ctype)
            elif content is not None:
                out[name] = (filename, str(content).encode("utf-8"), ctype)
            continue
        if isinstance(spec, (list, tuple)) and spec:
            filename = str(spec[0] or name)
            raw = spec[1] if len(spec) > 1 else ""
            ctype = str(spec[2]) if len(spec) > 2 else "application/octet-stream"
            if isinstance(raw, (bytes, bytearray)):
                out[name] = (filename, bytes(raw), ctype)
            else:
                out[name] = (filename, str(raw).encode("utf-8"), ctype)
    return out or None


def _read_work_file(path: str, root: Path) -> bytes | None:
    p = Path(path)
    if not p.is_absolute():
        p = root / path
    try:
        resolved = p.resolve()
        resolved.relative_to(root)
    except Exception:
        return None
    if not resolved.is_file():
        return None
    try:
        return resolved.read_bytes()[: 2 * 1024 * 1024]
    except Exception:
        return None


class ToolExecutor:
    def __init__(
        self,
        target: str,
        work_dir: Optional[str] = None,
        cancel_event: Optional[threading.Event] = None,
        enterprise: bool = False,
        fofa_key: str = "",
        fofa_base_url: str = "",
        engine: str = "fofa",
        task_id: str = "",
    ):
        self.target = target
        self.task_id = task_id or ""
        self.cancel_event = cancel_event or threading.Event()
        # 企业模式：对目标生产环境的破坏性命令做额外硬拦截。
        self.enterprise = enterprise
        # 资产测绘引擎：fofa_lookup 走任务选定的引擎（FOFA / Quake / Hunter / …），
        # key/base_url 由编排层按 resolve_engine_config 注入；base_url 空则用引擎默认端点。
        self.engine = engine or "fofa"
        self.fofa_key = fofa_key or ""
        self.fofa_base_url = (fofa_base_url or "").rstrip("/")
        # 每个目标独立工作目录
        safe_name = "".join(c if c.isalnum() else "_" for c in target)[:60]
        self.work_dir = Path(work_dir or worker_config.work_root) / safe_name
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self._log_seq = 0
        self._active_procs: set[subprocess.Popen] = set()
        # 会话态：worker 登录/拿到 token 后自动携带到后续 http_request，
        # 解决"明明登进去了，深挖请求却忘带凭证导致越权失败"的断链问题。
        # 每个 target 独立 executor 实例、session jar 相互隔离，不会串号。
        # 全模式启用（edu 用泄露凭证/用户凭证登录后同样必须带登录态深入）。
        self._session_cookies: dict[str, str] = {}
        self._cookie_jar: list[dict[str, str]] = []
        self._session_headers: dict[str, str] = {}
        # 工作笔记：worker 用 update_notes 工具维护，每轮注入回 messages，
        # 解决"历史压缩后忘了自己发现过什么"的连续性断裂问题。
        self._worker_notes: str = ""
        # HTTP 会话复用：持久 httpx.Client（惰性创建），避免同 host 大量请求每次重做 TCP+TLS 握手。
        self._client: Optional[httpx.Client] = None
        # 工作目录体积：增量估算 + 周期性全目录校准（见 _write_log），避免每次写日志都全目录扫描。
        self._workdir_bytes: int = self._dir_size()
        self._writes_since_scan: int = 0
        self._over_cap: bool = False   # 一旦确认超上限即置位：work_dir 只增不删，此后直接短路不再全扫
        self._cookie_hub: Any = None
        self._relogin_retrying = False
        # 用户注入的 cookie 额外绑定到这些主机（目标主机 + 跳转到达的主机）。
        self._cookie_alias_hosts: list[str] = []
        self._user_cookie_names: set[str] = set()

        # 代理模式：本地 IP 被目标 WAF 封禁后，http_request 透明改走 SSH 代理，
        # 保留同一 worker 的上下文与会话态（cookie jar 原地延续），无需重派。
        self.proxy_mode = False
        self._proxy_config = None
        self._proxy_server_idx = 0
        # 代理服务器健康表：{server: {"failures": int, "last_fail": float, "healthy": bool}}
        # 轮询时跳过不健康的服务器（冷却期过后自动恢复），分散流量降低封禁概率。
        self._proxy_health: dict[str, dict] = {}
    def cancel_running(self) -> None:
        """协作取消：置取消信号 + 杀子进程。仅用于控制面真取消（pause/stop/超时）。

        注意：会 set cancel_event，worker 据此判定"被取消、结果丢弃"。所以
        【正常完成后的清理】绝不能调这个（否则正常结果会被误判成取消而丢弃，
        历史事故根因：每个 worker 完成都被丢弃、findings/done 永远为 0）。
        正常完成清理请用 kill_processes()。
        """
        self.cancel_event.set()
        self.kill_processes()

    def kill_processes(self) -> None:
        """只杀掉当前 executor 启动的所有子进程组，不触碰 cancel_event。

        用于 worker 正常完成后的资源清理（杀残留子进程），不污染取消信号。
        """
        for proc in list(self._active_procs):
            self._kill_process_group(proc)
        self.close_http_client()
        drop_tree_cache(self.work_dir, cap=80)
        trim_process_memory()

    # ---- run_shell ----
    def run_shell(
        self,
        command: str,
        timeout: Optional[int] = None,
        confirm_destructive: Any = False,
        confirm_reason: str = "",
    ) -> dict[str, Any]:
        try:
            timeout = int(timeout) if timeout else worker_config.shell_timeout
        except (TypeError, ValueError):
            timeout = worker_config.shell_timeout
        # 硬上限 + 下限：防 LLM 传超大/非法 timeout 长期占用 worker 槽位（DoS）。
        timeout = max(1, min(timeout, worker_config.shell_timeout_max))
        try:
            check_command(
                command,
                enterprise=self.enterprise,
                confirm_destructive=confirm_destructive,
                confirm_reason=confirm_reason,
            )
        except NeedsConfirm as e:
            return _confirm_pause(e)
        except CommandBlocked as e:
            return {"ok": False, "blocked": True, "error": str(e)}

        start = time.time()
        proc: subprocess.Popen | None = None
        timed_out = False
        cancelled = False
        omitted_bytes = 0
        chunks: list[bytes] = []
        try:
            proc = subprocess.Popen(
                command,
                shell=True,
                cwd=str(self.work_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,  # 独立进程组，便于超时整组 kill
            )
            self._active_procs.add(proc)
            deadline = start + timeout
            if proc.stdout is None:
                rc = proc.wait(timeout=timeout)
            else:
                selector = selectors.DefaultSelector()
                selector.register(proc.stdout, selectors.EVENT_READ)
                try:
                    while True:
                        if self.cancel_event.is_set():
                            cancelled = True
                            self._kill_process_group(proc)
                        elif time.time() >= deadline:
                            timed_out = True
                            self._kill_process_group(proc)

                        for key, _ in selector.select(timeout=0.2):
                            data = key.fileobj.read1(8192)
                            if not data:
                                continue
                            room = max(0, _SHELL_CAPTURE_MAX_BYTES - sum(len(c) for c in chunks))
                            if room:
                                chunks.append(data[:room])
                            if len(data) > room:
                                omitted_bytes += len(data) - room

                        rc = proc.poll()
                        if rc is not None:
                            # 进程退出后再 drain 一次，保证 wait/reap 前尽量拿到尾部输出。
                            while True:
                                data = proc.stdout.read1(8192)
                                if not data:
                                    break
                                room = max(0, _SHELL_CAPTURE_MAX_BYTES - sum(len(c) for c in chunks))
                                if room:
                                    chunks.append(data[:room])
                                if len(data) > room:
                                    omitted_bytes += len(data) - room
                            break
                    rc = proc.wait(timeout=3)
                finally:
                    selector.close()
            cancelled = cancelled or self.cancel_event.is_set()
        except Exception as e:
            return {"ok": False, "error": f"命令执行异常: {e}"}
        finally:
            if proc is not None:
                self._active_procs.discard(proc)
                if proc.poll() is None:
                    self._kill_process_group(proc)
                    try:
                        proc.wait(timeout=3)
                    except Exception:
                        pass

        elapsed = round(time.time() - start, 2)
        full_out = b"".join(chunks).decode("utf-8", "replace")
        if omitted_bytes:
            full_out += f"\n\n...[输出超过 {_SHELL_CAPTURE_MAX_BYTES} 字节，已丢弃约 {omitted_bytes} 字节以保护内存]..."
        # 完整输出落地，避免截断丢证据（带体积上限，防 24x7 撞盘）
        log_file = self._write_log(f"$ {command}\n\n{full_out}")

        return {
            "ok": rc == 0 and not timed_out and not cancelled,
            "return_code": rc,
            "timed_out": timed_out,
            "cancelled": cancelled,
            "elapsed_sec": elapsed,
            "output": _truncate(full_out),
            "output_file": str(log_file) if log_file else "",
        }

    @staticmethod
    def _kill_process_group(proc: subprocess.Popen) -> None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def _dir_size(self) -> int:
        try:
            return sum(f.stat().st_size for f in self.work_dir.glob("*") if f.is_file())
        except Exception:
            return 0

    def _write_log(self, content: str) -> Optional[Path]:
        """落地日志文件；工作目录超体积上限则跳过（返回 None），不再写盘。

        体积用增量计数 self._workdir_bytes 估算，避免每次写日志都全目录扫描（聚合 O(files²)）；
        每 _WORKDIR_RESCAN_EVERY 次写入做一次真实全目录扫描校准——因为 run_shell 的子进程
        （curl -o / wget / 输出重定向等直落顶层文件）会绕过本函数，纯计数器会漏统计、弱化
        _WORKDIR_MAX_BYTES 的防撞盘保护。估算值一旦达上限即置 _over_cap 终态、停止写盘且不再全扫。
        """
        # 超上限是终态（work_dir 只增不删）：直接短路，绝不再触发全目录扫描。
        if self._over_cap:
            return None
        data = content.encode("utf-8")
        # 仅按“写入次数”周期性校准，不再因“已达上限”而每次全扫（否则撞盘后退化成每写必扫）。
        if self._writes_since_scan >= _WORKDIR_RESCAN_EVERY:
            self._workdir_bytes = self._dir_size()
            self._writes_since_scan = 0
        if self._workdir_bytes >= _WORKDIR_MAX_BYTES:
            self._over_cap = True
            return None
        self._log_seq += 1
        log_file = self.work_dir / f"shell_{self._log_seq}.log"
        try:
            log_file.write_bytes(data)  # 与 write_text(encoding="utf-8") 字节数一致，便于精确计数
            drop_file_cache(log_file)
        except Exception:
            return None
        self._workdir_bytes += len(data)
        self._writes_since_scan += 1
        return log_file

    def _get_http_client(self) -> httpx.Client:
        """惰性复用的持久 HTTP client（连接池），避免同 host 大量请求重复 TCP+TLS 握手。

        per-request 的 timeout/follow_redirects 在 build_request/send 时逐次覆盖；cookie 每次
        请求前清空再从 self._session_cookies 重灌，保证会话态唯一真值来源、jar 不跨 host 累积。
        """
        if self._client is None or self._client.is_closed:
            self._client = httpx.Client(
                verify=False,
                timeout=20,
                follow_redirects=False,
                headers={"User-Agent": BROWSER_UA},
                limits=httpx.Limits(
                    max_keepalive_connections=8, max_connections=32, keepalive_expiry=30.0
                ),
            )
        return self._client

    def close_http_client(self) -> None:
        # 经 kill_processes 调用。正常完成时无 in-flight 请求；取消路径（cancel_running →
        # kill_processes）下 worker 线程可能正在 send/iter，此时 close 会让该请求抛异常并被
        # http_request 的 except 兜成 {ok:false}——这正是取消语义（放弃在途请求），有意为之。
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    # ---- http_request ----
    def http_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[dict[str, str]] = None,
        data: Optional[str] = None,
        json_body: Optional[Any] = None,
        files: Optional[Any] = None,
        follow_redirects: bool = False,
        timeout: int = 20,
        confirm_destructive: Any = False,
        confirm_reason: str = "",
    ) -> dict[str, Any]:
        if self.proxy_mode:
            return self._http_request_via_proxy(
                url=url, method=method, headers=headers, data=data,
                json_body=json_body, follow_redirects=follow_redirects, timeout=timeout,
            )
        # LLM 可能把 headers 传成非 dict 形态（list["K: V"] / "K: V\nK2: V2" / None），
        # 直接喂给 dict()/httpx 会抛 "dictionary update sequence element..." 崩掉整个 agent。
        # 这里统一规范化成 dict，容错所有 agent 的 http_request 调用。
        headers = _normalize_headers(headers)
        incoming_cookie = _pop_header(headers, "Cookie")
        overlay = _parse_cookie_header(incoming_cookie)
        files_norm = _normalize_files(files, self.work_dir)
        hub = self._cookie_hub
        if hub is not None and not self._relogin_retrying:
            try:
                hub.pull(self)
            except Exception:
                pass
        try:
            check_http_request(
                method, url, data=data, json_body=json_body, files=files_norm,
                confirm_destructive=confirm_destructive,
                confirm_reason=confirm_reason,
            )
        except NeedsConfirm as e:
            return {**_confirm_pause(e), "url": url}
        except CommandBlocked as e:
            return {"ok": False, "blocked": True, "error": str(e), "url": url}
        merged_headers, session_applied = self._apply_session(headers, url, overlay)
        pinned_cookies = self._pinned_user_cookies(_host_from_url(url) or self._target_host())

        req: httpx.Request | None = None
        try:
            client = self._get_http_client()
            host = _host_from_url(url) or self._target_host()
            try:
                client.cookies.clear()
            except Exception:
                pass
            self._fill_client_cookies(client, host, overlay)
            send_kwargs: dict[str, Any] = {"headers": merged_headers, "timeout": timeout}
            if files_norm:
                form_data = None
                if isinstance(data, str) and data and "=" in data:
                    form_data = dict(parse_qsl(data, keep_blank_values=True))
                send_kwargs["data"] = form_data
                send_kwargs["files"] = files_norm
            elif json_body is not None:
                send_kwargs["json"] = json_body
            else:
                send_kwargs["content"] = data
            req = client.build_request(method.upper(), url, **send_kwargs)
            with capped_resolution():
                resp = client.send(req, stream=True, follow_redirects=follow_redirects)
            from app.tools.netguard import LOOPBACK_BLOCK_ERROR, is_loopback_target
            final_url = str(getattr(resp, "url", "") or url)
            if is_loopback_target(final_url):
                try:
                    resp.close()
                except Exception:
                    pass
                return {
                    "ok": False,
                    "blocked": True,
                    "error": LOOPBACK_BLOCK_ERROR,
                    "url": url,
                }
            body, truncated = self._read_limited_response(resp)
            # 吸收整条重定向链（resp.history 里每个中间 302 + 最终响应）的 Set-Cookie，
            # 而不是只读最终 resp.cookies；再兜底吸收 client.cookies jar 里的全部。
            session_updated = self._absorb_redirect_chain(resp, client)
            self._bind_pinned_locations(pinned_cookies, resp)
        except Exception as e:
            return {"ok": False, "error": f"HTTP 请求异常: {e}", "url": url}

        # 原始请求行（取证/格式参考）。响应报文不再单独回传：状态码 + response_headers +
        # body 已结构化提供，raw_response 会与它们 100% 重复，是当轮就纯冗余的双份大文本。
        # 模型 submit_finding 时按 prompt 规范从 body 自行裁剪取证，不依赖这份 raw_response。
        # multipart/files 是流式 body，send 后不能再 req.content；dump 失败也不能把已成功的请求打成工具异常。
        try:
            raw_req = self._raw_request(req, data, json_body, files_norm)
        except Exception:
            raw_req = f"{method.upper()} {url}"

        result = {
            "ok": True,
            "status_code": resp.status_code,
            "url": str(resp.url),
            "response_headers": dict(resp.headers),
            "body": _truncate(body),
            "body_len": len(body),
            "body_truncated": truncated,
            "raw_request": _truncate(raw_req, 1536),
        }
        # 跟随重定向时给出跳转链摘要，方便 agent 看清 CAS/SSO 登录流程走到哪、最终落在哪。
        try:
            hist = list(getattr(resp, "history", []) or [])
            if hist:
                chain = [f"{h.status_code} {h.request.method} {str(h.url)}" for h in hist]
                chain.append(f"{resp.status_code} {resp.request.method} {str(resp.url)}")
                result["redirect_chain"] = chain[:12]
                result["final_url"] = str(resp.url)
        except Exception:
            pass
        if session_applied:
            result["session_applied"] = session_applied
        if session_updated:
            result["session_cookies_updated"] = session_updated
        if hub is not None:
            try:
                hub.push(self)
            except Exception:
                pass
            if not self._relogin_retrying:
                try:
                    if hub.maybe_relogin(self, result):
                        self._relogin_retrying = True
                        try:
                            return self.http_request(
                                url, method=method, headers=headers, data=data,
                                json_body=json_body, files=files,
                                follow_redirects=follow_redirects, timeout=timeout,
                                confirm_destructive=confirm_destructive,
                                confirm_reason=confirm_reason,
                            )
                        finally:
                            self._relogin_retrying = False
                except Exception:
                    self._relogin_retrying = False
        return result

    # ---- 代理模式（IP 封禁时透明走 SSH 代理）----
    def enable_proxy_mode(self) -> dict[str, Any]:
        """切换为代理模式：后续 http_request 自动经 SSH 代理发送。

        worker 交叉验证确认本地 IP 被目标 WAF 封禁后调用。切换后 http_request
        透明走代理，LLM 无需改用 run_shell+ssh curl，上下文与会话态原地保留。
        """
        from app.settings_service import resolve_proxy_config
        cfg = resolve_proxy_config()
        if not cfg.available:
            return {
                "ok": False,
                "error": "无可用代理服务器，无法切换代理模式",
                "guidance": "未配置 SSH 代理。调用 finish(verdict=ip_banned) 将目标标记为 IP 封禁，等待后续重测。",
            }
        self._proxy_config = cfg
        self.proxy_mode = True
        return {
            "ok": True,
            "message": "已切换到代理模式，后续 http_request 将自动通过 SSH 代理发送。"
                        "多台代理自动轮询分发，降低单 IP 被封概率。"
                        "继续用 http_request 正常测试即可，无需手动 ssh curl。",
            "proxy_servers": cfg.server_list,
            "guidance": "现在所有 http_request 自动走代理。继续正常挖掘；"
                        "若代理请求也持续失败（所有代理服务器不可达），再调用 finish(verdict=ip_banned)。",
        }

    def _http_request_via_proxy(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[dict[str, str]] = None,
        data: Optional[str] = None,
        json_body: Optional[Any] = None,
        follow_redirects: bool = False,
        timeout: int = 20,
    ) -> dict[str, Any]:
        """通过 SSH 代理发送 HTTP 请求，返回与 http_request 一致的结果结构。

        用 curl -D /dev/stderr -o /dev/stdout -w 把响应头(body 前的 stderr)和
        响应体(stdout)分离，尾部追加状态码标记。多台代理服务器按轮询+健康度策略
        自动分发：每次请求后轮转到下一台健康代理（分散流量降低单 IP 被封概率），
        某台连续失败则标记不健康并冷却跳过，全部不可达才报失败。
        """
        cfg = self._proxy_config
        if not cfg or not cfg.available:
            return {"ok": False, "error": "代理模式未启用或无可用代理", "url": url}

        headers = _normalize_headers(headers)
        merged_headers, session_applied = self._apply_session(headers, url)

        # 请求体序列化
        body_data: Optional[str] = None
        if data is not None:
            body_data = str(data)
        elif json_body is not None:
            import json as _json
            body_data = _json.dumps(json_body, ensure_ascii=False)
            if not any(k.lower() == "content-type" for k in merged_headers):
                merged_headers["Content-Type"] = "application/json"

        method_up = method.upper()
        servers = list(cfg.server_list)
        key_path = cfg.ssh_key_path
        last_error = ""

        # 轮询+健康度：_pick_proxy_servers 返回健康代理优先的轮序，
        # 每次成功后轮转到下一台，分散流量；连续失败的自动冷却跳过。
        for srv in self._pick_proxy_servers(servers):
            if ":" in srv.split("@")[-1]:
                user_host, port = srv.rsplit(":", 1)
            else:
                user_host, port = srv, "22"

            # 构造远程 curl 命令：头→stderr，体+状态码标记→stdout
            curl_parts = ["curl", "-s", "-S", "-k", "--connect-timeout", "8"]
            if follow_redirects:
                curl_parts.append("-L")
            curl_parts += [
                "--max-time", str(int(timeout)),
                "-D", "/dev/stderr", "-o", "/dev/stdout",
                "-w", r"\n<<<HTTP_STATUS:%{http_code}>>>",
                "-X", method_up,
            ]
            for k, v in merged_headers.items():
                curl_parts += ["-H", f"{k}: {v}"]
            if body_data is not None:
                curl_parts += ["-d", body_data]
            curl_parts.append(url)

            remote_cmd = " ".join(shlex.quote(p) for p in curl_parts)
            ssh_cmd = [
                "ssh", "-i", key_path,
                "-o", "StrictHostKeyChecking=no",
                "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=5",
                "-p", port, user_host,
                remote_cmd,
            ]

            try:
                result = subprocess.run(
                    ssh_cmd, capture_output=True, timeout=timeout + 15,
                )
            except subprocess.TimeoutExpired:
                last_error = f"代理 {srv} 超时"
                self._mark_proxy_unhealthy(srv)
                continue
            except Exception as e:
                last_error = f"代理 {srv} 异常: {e}"
                self._mark_proxy_unhealthy(srv)
                continue

            out = (result.stdout or b"").decode("utf-8", "replace")
            err = (result.stderr or b"").decode("utf-8", "replace")

            # 解析状态码标记
            marker = "<<<HTTP_STATUS:"
            pos = out.rfind(marker)
            status_code = 0
            body_text = out
            if pos >= 0:
                end = out.find(">>>", pos)
                if end > pos:
                    code_str = out[pos + len(marker):end].strip()
                    if code_str.isdigit():
                        status_code = int(code_str)
                    body_text = out[:pos].rstrip("\n")

            if status_code == 0:
                # 连接失败（curl 未拿到任何 HTTP 响应）→ 换下一台代理
                last_error = f"代理 {srv} 连接失败: {err[:200]}"
                self._mark_proxy_unhealthy(srv)
                continue

            # 成功：标记健康 + 轮转到下一台代理（分散流量，降低单 IP 被封概率）
            self._mark_proxy_healthy(srv)
            self._proxy_server_idx = (servers.index(srv) + 1) % len(servers)

            try:
                resp_headers, redirect_chain, session_updated = self._parse_proxy_headers(err, url)
            except Exception:
                resp_headers, redirect_chain, session_updated = {}, [], []

            # 截断响应体（与本地 http_request 一致的上限）
            truncated = False
            if len(body_text) > _HTTP_MAX_BYTES:
                body_text = (
                    body_text[:_HTTP_MAX_BYTES]
                    + f"\n\n...[响应超过 {_HTTP_MAX_BYTES} 字节，已截断以保护内存]..."
                )
                truncated = True
            body_out = _truncate(body_text)

            # 构造取证用原始请求行
            raw_req_lines = [f"{method_up} {url} HTTP/1.1"]
            for k, v in merged_headers.items():
                raw_req_lines.append(f"{k}: {v}")
            if body_data is not None:
                raw_req_lines.append("")
                raw_req_lines.append(body_data[:512])
            raw_req = "\n".join(raw_req_lines)

            result_dict: dict[str, Any] = {
                "ok": True,
                "status_code": status_code,
                "url": url,
                "response_headers": resp_headers,
                "body": body_out,
                "body_len": len(body_text),
                "body_truncated": truncated,
                "raw_request": _truncate(raw_req, 1536),
                "via_proxy": True,
                "proxy_server": srv,
            }
            if redirect_chain:
                result_dict["redirect_chain"] = redirect_chain
            if session_applied:
                result_dict["session_applied"] = session_applied
            if session_updated:
                result_dict["session_cookies_updated"] = session_updated
            return result_dict

        # 所有代理服务器都不可达
        return {
            "ok": False,
            "error": f"所有代理服务器均不可达: {last_error}",
            "url": url,
            "via_proxy": True,
            "guidance": "所有代理服务器都无法连接目标。若目标本身存活（探活服务器可达），"
                        "调用 finish(verdict=ip_banned) 等待后续重测。",
        }

    def _pick_proxy_servers(self, servers: list[str]) -> list[str]:
        """返回按轮询+健康度排序的代理服务器候选列表。

        健康的服务器优先、按当前轮转索引排列；不健康的排后（冷却期过后自动恢复）。
        全部不健康时返回全部（兜底：仍然尝试，成功则恢复健康）。
        """
        now = time.time()
        healthy: list[str] = []
        unhealthy: list[str] = []
        n = len(servers)
        for offset in range(n):
            idx = (self._proxy_server_idx + offset) % n
            srv = servers[idx]
            h = self._proxy_health.get(srv)
            if h and not h.get("healthy", True):
                # 冷却期结束 → 恢复健康
                if (now - h.get("last_fail", 0)) >= _PROXY_UNHEALTHY_COOLDOWN:
                    h["healthy"] = True
                    h["failures"] = 0
            if self._proxy_health.get(srv, {}).get("healthy", True):
                healthy.append(srv)
            else:
                unhealthy.append(srv)
        # 健康优先；全不健康时兜底尝试全部
        return healthy + unhealthy

    def _mark_proxy_healthy(self, server: str) -> None:
        """代理请求成功：重置失败计数，标记健康。"""
        h = self._proxy_health.get(server)
        if h:
            h["failures"] = 0
            h["healthy"] = True

    def _mark_proxy_unhealthy(self, server: str) -> None:
        """代理请求失败：累计失败次数，超过阈值则标记不健康（冷却期内跳过）。"""
        h = self._proxy_health.setdefault(
            server, {"failures": 0, "last_fail": 0, "healthy": True}
        )
        h["failures"] = h.get("failures", 0) + 1
        h["last_fail"] = time.time()
        if h["failures"] >= _PROXY_FAIL_THRESHOLD:
            h["healthy"] = False

    def _parse_proxy_headers(self, raw: str, url: str = "") -> tuple[dict[str, str], list[str], list[str]]:
        """解析 curl -D 输出的响应头流，返回 (最终响应头, 重定向状态码链, 更新的cookie名)。

        curl -D /dev/stderr 把每个响应（含重定向中间跳）的头块依次写入 stderr，
        块间以空行分隔。取最后一个块作为最终响应头；遍历所有块的 Set-Cookie 吸收进 session。
        """
        resp_headers: dict[str, str] = {}
        redirect_chain: list[str] = []
        updated: list[str] = []
        fallback_host = _host_from_url(url) or self._target_host()
        norm = raw.replace("\r\n", "\n").replace("\r", "\n")
        blocks = [b for b in norm.split("\n\n") if b.strip()]
        for block in blocks:
            lines = block.strip().split("\n")
            if not lines:
                continue
            # 状态行 HTTP/x.y CODE TEXT
            first = lines[0]
            parts = first.split(" ", 2)
            if len(parts) >= 2 and parts[0].upper().startswith("HTTP"):
                redirect_chain.append(parts[1])
            hdrs: dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    k = k.strip()
                    v = v.strip()
                    if not k:
                        continue
                    hdrs[k] = v
                    if k.lower() == "set-cookie":
                        parsed = _split_set_cookie(v)
                        if parsed:
                            cn, cval, domain, path = parsed
                            try:
                                self._put_cookie_entry(
                                    cn, cval,
                                    domain=domain or fallback_host,
                                    path=path,
                                    updated=updated,
                                )
                            except Exception:
                                pass
            if hdrs:
                resp_headers = hdrs
        return resp_headers, redirect_chain, updated

    # ---- 会话状态管理（全模式）----
    def _target_host(self) -> str:
        return _host_from_url(self.target)

    def _rebuild_cookie_map(self) -> None:
        mapped: dict[str, str] = {}
        for e in self._cookie_jar:
            mapped[e["name"]] = e["value"]
        self._session_cookies = mapped

    def _put_cookie_entry(
        self,
        name: str,
        value: str,
        domain: str = "",
        path: str = "/",
        updated: Optional[list[str]] = None,
    ) -> None:
        name = str(name or "").strip()
        if not name:
            return
        value = str(value)[:4096]
        domain = (domain or "").lstrip(".").lower()
        path = path or "/"
        for e in self._cookie_jar:
            if e["name"] == name and (e.get("domain") or "") == domain:
                e["value"] = value
                e["path"] = path
                if updated is not None and name not in updated:
                    updated.append(name)
                self._rebuild_cookie_map()
                return
        if len(self._cookie_jar) >= _SESSION_MAX_COOKIES:
            self._rebuild_cookie_map()
            return
        self._cookie_jar.append({"name": name, "value": value, "domain": domain, "path": path})
        if updated is not None and name not in updated:
            updated.append(name)
        self._rebuild_cookie_map()

    def _cookies_for_host(self, host: str, overlay: Optional[dict[str, str]] = None) -> dict[str, str]:
        picked: dict[str, tuple[int, str]] = {}
        for e in self._cookie_jar:
            if not _cookie_host_ok(e.get("domain") or "", host):
                continue
            spec = len(e.get("domain") or "")
            prev = picked.get(e["name"])
            if prev is None or spec >= prev[0]:
                picked[e["name"]] = (spec, e["value"])
        out = {k: v[1] for k, v in picked.items()}
        if overlay:
            out.update(overlay)
        return out

    def _fill_client_cookies(
        self,
        client: httpx.Client,
        host: str,
        overlay: Optional[dict[str, str]] = None,
    ) -> None:
        for e in self._cookie_jar:
            d = e.get("domain") or host
            try:
                client.cookies.set(
                    e["name"], e["value"],
                    domain=d,
                    path=e.get("path") or "/",
                )
            except Exception:
                pass
        if overlay:
            for k, v in overlay.items():
                try:
                    client.cookies.set(k, v, domain=host, path="/")
                except Exception:
                    pass

    def _apply_session(
        self,
        headers: Optional[dict[str, str]],
        url: str = "",
        overlay: Optional[dict[str, str]] = None,
    ) -> tuple[dict[str, str], list[str]]:
        try:
            merged: dict[str, str] = {}
            applied: list[str] = []
            for k, v in self._session_headers.items():
                merged[k] = v
            if headers:
                for k, v in headers.items():
                    if k.lower() == "cookie":
                        continue
                    merged[k] = v
            host = _host_from_url(url) or self._target_host()
            jar_cookies = self._cookies_for_host(host, overlay)
            if jar_cookies:
                merged["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar_cookies.items())
                applied.append(f"Cookie({len(jar_cookies)})")
            if self._session_headers:
                applied.append(f"headers({len(self._session_headers)})")
            if not any(k.lower() == "user-agent" for k in merged):
                merged["User-Agent"] = BROWSER_UA
            return merged, applied
        except Exception:
            fallback = dict(headers) if headers else {}
            if not any(k.lower() == "user-agent" for k in fallback):
                fallback["User-Agent"] = BROWSER_UA
            return fallback, []

    def _absorb_cookie_obj(self, ck: Any, fallback_host: str, updated: list[str]) -> None:
        name = getattr(ck, "name", "") or ""
        value = getattr(ck, "value", "") or ""
        if not name:
            return
        domain = (getattr(ck, "domain", None) or fallback_host or "").lstrip(".")
        path = getattr(ck, "path", None) or "/"
        self._put_cookie_entry(name, value, domain=domain, path=path, updated=updated)

    def _absorb_redirect_chain(self, resp: httpx.Response, client: "httpx.Client") -> list[str]:
        updated: list[str] = []
        try:
            for hist in list(getattr(resp, "history", []) or []):
                host = _host_from_url(str(getattr(hist, "url", "") or ""))
                try:
                    for ck in hist.cookies.jar:
                        self._absorb_cookie_obj(ck, host, updated)
                except Exception:
                    try:
                        for name, value in hist.cookies.items():
                            self._put_cookie_entry(name, value, domain=host, path="/", updated=updated)
                    except Exception:
                        pass
            host = _host_from_url(str(getattr(resp, "url", "") or ""))
            try:
                for ck in resp.cookies.jar:
                    self._absorb_cookie_obj(ck, host, updated)
            except Exception:
                try:
                    for name, value in resp.cookies.items():
                        self._put_cookie_entry(name, value, domain=host, path="/", updated=updated)
                except Exception:
                    pass
            try:
                for ck in client.cookies.jar:
                    fb = (getattr(ck, "domain", None) or host or "").lstrip(".")
                    self._absorb_cookie_obj(ck, fb, updated)
            except Exception:
                pass
        except Exception:
            pass
        return updated

    def _session_cookie_hosts(self) -> list[str]:
        """用户注入 cookie 要写入的主机：目标主机，以及跳转链上记下的主机。"""
        hosts: list[str] = []
        target = self._target_host()
        if target:
            hosts.append(target)
        for raw in self._cookie_alias_hosts:
            host = str(raw or "").strip().lower().lstrip(".")
            if host and host not in hosts:
                hosts.append(host)
        return hosts or [target]

    def _bind_cookie_values(self, values: dict[str, str], host: str) -> None:
        host = (host or "").strip().lower().lstrip(".")
        if not host:
            return
        if host not in self._cookie_alias_hosts:
            self._cookie_alias_hosts.append(host)
        for name, value in values.items():
            if not name:
                continue
            self._put_cookie_entry(name, value, domain=host, path="/")

    def spread_cookies_to_redirect_hosts(self, names: list[str]) -> list[str]:
        """把指定 cookie 的当前值复制到目标 URL 的跳转主机上。

        任务 URL 经常 301 到另一个域名（mibi.xiaomi.com → mibi.wali.com）。
        只绑在入口主机上时，业务站请求不会带上登录 cookie。
        """
        from urllib.parse import urljoin

        from app.tools.netguard import is_loopback_target

        wanted = [str(n) for n in (names or []) if str(n or "").strip()]
        origin = self._target_host()
        current = self._cookies_for_host(origin) if origin else {}
        values = {name: current[name] for name in wanted if name in current}
        if origin:
            self._bind_cookie_values(values, origin)
        if not values:
            return list(self._session_cookie_hosts())

        fetch = self._redirect_hop if callable(getattr(self, "_redirect_hop", None)) else _redirect_hop
        url = (self.target or "").strip()
        seen: set[str] = set()
        for _ in range(_REDIRECT_HOST_HOPS):
            if not url or url in seen:
                break
            seen.add(url)
            hop_host = _host_from_url(url)
            if not hop_host or is_loopback_target(hop_host):
                break
            self._bind_cookie_values(values, hop_host)
            try:
                status, location = fetch(url, values)
            except Exception:
                break
            try:
                status_i = int(status or 0)
            except (TypeError, ValueError):
                break
            loc = str(location or "").strip()
            if status_i not in (301, 302, 303, 307, 308) or not loc:
                break
            nxt = urljoin(url, loc)
            if not (nxt.startswith("http://") or nxt.startswith("https://")):
                break
            url = nxt
        return list(self._session_cookie_hosts())

    def _pinned_user_cookies(self, host: str) -> dict[str, str]:
        if not self._user_cookie_names:
            return {}
        current = self._cookies_for_host(host)
        return {name: current[name] for name in self._user_cookie_names if name in current}

    def _bind_pinned_locations(self, pinned: dict[str, str], resp: Any) -> None:
        """跳转目标主机也带上请求前的用户 cookie，避免 Set-Cookie 清场覆盖后再复制。"""
        if not pinned or resp is None:
            return
        from app.tools.netguard import is_loopback_target

        locs: list[str] = []
        try:
            loc = resp.headers.get("location") or resp.headers.get("Location") or ""
        except Exception:
            loc = ""
        if loc:
            locs.append(str(loc))
        try:
            for hist in list(getattr(resp, "history", []) or []):
                hloc = ""
                try:
                    hloc = hist.headers.get("location") or ""
                except Exception:
                    hloc = ""
                if hloc:
                    locs.append(str(hloc))
        except Exception:
            pass
        base = str(getattr(resp, "url", "") or "")
        from urllib.parse import urljoin
        for loc in locs:
            nxt = urljoin(base, loc) if base else loc
            host = _host_from_url(nxt)
            if not host or is_loopback_target(host):
                continue
            self._bind_cookie_values(pinned, host)

    def session_set(
        self,
        cookies: Optional[dict[str, str]] = None,
        headers: Optional[dict[str, str]] = None,
        clear: bool = False,
    ) -> dict[str, Any]:
        try:
            if clear:
                self._session_cookies.clear()
                self._cookie_jar.clear()
                self._session_headers.clear()
                self._cookie_alias_hosts.clear()
                self._user_cookie_names.clear()
            hosts = self._session_cookie_hosts()
            if isinstance(cookies, dict):
                self._user_cookie_names.update(k for k in cookies if isinstance(k, str) and k)
                for k, v in cookies.items():
                    if not isinstance(k, str):
                        continue
                    for host in hosts:
                        self._put_cookie_entry(k, str(v)[:4096], domain=host, path="/")
            if isinstance(headers, dict):
                for k, v in headers.items():
                    if not isinstance(k, str):
                        continue
                    if k.lower() == "cookie":
                        parsed = _parse_cookie_header(str(v))
                        self._user_cookie_names.update(parsed)
                        for ck, cv in parsed.items():
                            for host in hosts:
                                self._put_cookie_entry(ck, cv, domain=host, path="/")
                        continue
                    if k in self._session_headers or len(self._session_headers) < _SESSION_MAX_HEADERS:
                        self._session_headers[k] = str(v)[:4096]
            out = {
                "ok": True,
                "active_cookies": sorted(self._session_cookies.keys()),
                "active_headers": sorted(self._session_headers.keys()),
                "guidance": "已更新会话态，后续 http_request 会自动携带；继续以此据点深挖受限接口。",
            }
            hub = self._cookie_hub
            if hub is not None and not clear and (self._session_cookies or self._session_headers):
                try:
                    hub.push(self)
                except Exception:
                    pass
            return out
        except Exception as e:
            return {"ok": False, "error": f"session_set 异常: {type(e).__name__}: {e}"}

    # ---- 工作笔记（跨轮持久记忆）----
    def update_notes(self, notes: str = "") -> dict[str, Any]:
        """worker 更新工作笔记。笔记每轮注入回 messages，不受历史压缩影响。"""
        self._worker_notes = (notes or "").strip()[:4000]
        return {"ok": True, "notes_len": len(self._worker_notes)}

    def session_status_block(self) -> str:
        """生成当前会话态 + 工作笔记的摘要块，供 worker 每轮注入 messages。

        这是连续性的核心：即使历史被压缩成摘要、即使过了 30 轮，worker 仍能
        '看到'自己当前持有哪些 cookie/header（登录态不断）、以及自己记录的关键
        进度（端点/凭据/已试方向/下一步计划），不会重复扫同一条路。
        """
        lines = ["# 当前状态（跨轮持久，每轮自动注入）"]
        # 会话态
        cookies = sorted(self._session_cookies.keys()) if self._session_cookies else []
        headers = sorted(self._session_headers.keys()) if self._session_headers else []
        if cookies or headers:
            lines.append(f"- 会话态：持有 cookie {cookies}，鉴权头 {headers}（http_request 自动携带）")
        else:
            lines.append("- 会话态：暂无登录态（拿到凭证后用 session_set 登记）")
        # 工作笔记
        if self._worker_notes:
            lines.append("- 工作笔记：")
            lines.append(self._worker_notes)
        else:
            lines.append("- 工作笔记：（暂无。发现端点/凭据/token/突破口后用 update_notes 记录，否则跨轮会忘）")
        return "\n".join(lines) + "\n\n"

    def export_resume_state(self) -> dict[str, Any]:
        """导出可跨 worker 续挖的进度快照（笔记 + 会话态）。"""
        return {
            "worker_notes": self._worker_notes or "",
            "session_cookies": dict(self._session_cookies or {}),
            "session_cookie_jar": [dict(e) for e in self._cookie_jar],
            "session_headers": dict(self._session_headers or {}),
        }

    def restore_resume_state(
        self,
        *,
        worker_notes: str = "",
        session_cookies: dict | None = None,
        session_headers: dict | None = None,
        session_cookie_jar: list | None = None,
    ) -> None:
        if worker_notes:
            self._worker_notes = str(worker_notes).strip()[:4000]
        if isinstance(session_cookie_jar, list) and session_cookie_jar:
            self._cookie_jar = []
            for raw in session_cookie_jar:
                if not isinstance(raw, dict) or not raw.get("name"):
                    continue
                self._put_cookie_entry(
                    str(raw.get("name")),
                    str(raw.get("value") or "")[:4096],
                    domain=str(raw.get("domain") or ""),
                    path=str(raw.get("path") or "/"),
                )
            self._rebuild_cookie_map()
        cookies = session_cookies if isinstance(session_cookies, dict) else {}
        headers = session_headers if isinstance(session_headers, dict) else {}
        if cookies or headers:
            if not (isinstance(session_cookie_jar, list) and session_cookie_jar):
                self.session_set(cookies=cookies or None, headers=headers or None)
            elif headers:
                self.session_set(headers=headers)

    # ---- decode_transform ----
    def decode_transform(self, value: str = "", mode: str = "auto") -> dict[str, Any]:
        """编码/解码/哈希分析（纯内存，无外部副作用）。详见 tools/decoder.py。"""
        return _decode_transform(value, mode)

    # ---- fofa_lookup（只读资产测绘，确认归属 + 探攻击面）----
    def fofa_lookup(self, query: str = "", size: int = 10) -> dict[str, Any]:
        """对任务选定的测绘引擎发一次只读查询，返回命中规模和样本
        （host/ip/port/title/domain/org）。

        用途：① 确认目标归属（org/备案/证书）填准 owner；② 看同 IP/同域还开了
        哪些端口/服务，发现隐藏攻击面。查询统一按 FOFA 语法书写，非 FOFA 引擎
        （Quake / Hunter / …）在请求前自动翻译。只读查询，不对目标产生任何请求。
        """
        from app.engines.sync import engine_display_name, engine_search_sync, result_rows_to_dicts

        engine_name = self.engine or "fofa"
        disp = engine_display_name(engine_name)
        if not self.fofa_key:
            return {"ok": False, "error": f"未配置 {disp} key，无法查询。",
                    "guidance": "跳过测绘，直接用 http_request 验证归属（看证书/页脚/备案）。"}
        q = (query or "").strip()
        if not q:
            return {"ok": False, "kind": "arg_error", "error": "query 不能为空",
                    "guidance": f'传 {disp} 查询语法，如 ip="1.2.3.4" 或 host="example.com"。'}
        safe_size = max(1, min(int(size or 10), _FOFA_LOOKUP_MAX_SIZE))
        try:
            res = engine_search_sync(
                engine_name, self.fofa_key, q,
                page=1, page_size=safe_size, base_url=self.fofa_base_url or None,
            )
            from app.engines.meter import record_engine_search
            record_engine_search(self.task_id, "worker", q, engine_name)
        except Exception as e:
            return {"ok": False, "error": f"{disp} 调用失败: {type(e).__name__}: {e}"[:300],
                    "guidance": f"{disp} 不可用，改用 http_request 直接验证归属。"}

        sample = []
        for r in result_rows_to_dicts(res, limit=safe_size):
            sample.append({
                "host": r.get("host", ""),
                "ip": r.get("ip", ""),
                "port": r.get("port", ""),
                "title": (r.get("title", "") or "")[:120],
                "domain": r.get("domain", ""),
                "org": r.get("org", ""),
                "protocol": r.get("protocol", ""),
            })
        return {
            "ok": True,
            "query": q,
            "engine": engine_name,
            "size": res.size,
            "sample": sample,
            "guidance": "据此核实 owner 归属、发现同 IP/同域其它端口与服务；测绘只读，验证仍需 http_request 实证。",
        }

    @staticmethod
    def _read_limited_response(resp: httpx.Response) -> tuple[str, bool]:
        chunks: list[bytes] = []
        total = 0
        truncated = False
        try:
            for chunk in resp.iter_bytes():
                if not chunk:
                    continue
                if total + len(chunk) > _HTTP_MAX_BYTES:
                    room = max(0, _HTTP_MAX_BYTES - total)
                    if room:
                        chunks.append(chunk[:room])
                    truncated = True
                    break
                chunks.append(chunk)
                total += len(chunk)
        finally:
            resp.close()
        body = b"".join(chunks).decode(resp.encoding or "utf-8", "replace")
        if truncated:
            body += f"\n\n...[响应超过 {_HTTP_MAX_BYTES} 字节，已截断以保护内存]..."
        return body, truncated

    @staticmethod
    def _request_body_text(
        req: httpx.Request,
        data: Optional[str],
        json_body: Any,
        files: Any = None,
    ) -> str:
        """取证预览请求体。multipart 等流式 body 不能读 req.content（RequestNotRead）。"""
        try:
            content = req.content
        except Exception:
            content = None
        if content:
            try:
                return content.decode("utf-8", "replace")
            except Exception:
                return "<binary>"
        if json_body is not None:
            try:
                import json as _json
                return _json.dumps(json_body, ensure_ascii=False)
            except Exception:
                return str(json_body)
        if data:
            return str(data)
        if files:
            if isinstance(files, dict):
                names = ", ".join(str(k) for k in files)
                return f"<multipart: {names}>" if names else "<multipart>"
            return "<multipart>"
        return ""

    @staticmethod
    def _raw_request(
        req: httpx.Request,
        data: Optional[str],
        json_body: Any,
        files: Any = None,
    ) -> str:
        lines = [f"{req.method} {req.url.raw_path.decode('latin-1')} HTTP/1.1"]
        lines.append(f"Host: {req.url.host}")
        for k, v in req.headers.items():
            if k.lower() == "host":
                continue
            lines.append(f"{k}: {v}")
        body = ToolExecutor._request_body_text(req, data, json_body, files)
        return "\n".join(lines) + "\n\n" + body

    # ---- analyze_javascript（条件开放给 worker）----
    def analyze_javascript(
        self,
        url: str = "",
        text: str = "",
        max_depth: int = 2,
        max_assets: int = 80,
    ) -> dict[str, Any]:
        """分析入口 URL 或 JS 文本，返回高价值链路和统一接口清单。"""
        try:
            safe_depth = max(0, min(int(max_depth or 2), 4))
            safe_assets = max(1, min(int(max_assets or 80), 150))
            if url:
                result = analyze_js_url(url, max_depth=safe_depth, max_assets=safe_assets)
            elif text:
                result = analyze_js_text(text[:800_000], base_url=self.target, source="worker_text")
            else:
                return {
                    "ok": False,
                    "kind": "arg_error",
                    "error": "analyze_javascript 需要 url 或 text",
                    "guidance": "传入口 URL 或已抓到的 JS 文本；不要空调用。",
                }
            return {
                "ok": True,
                "summary": result.get("summary", {}),
                "chains": result.get("chains", [])[:8],
                "endpoint_inventory": result.get("endpoint_inventory", [])[:80],
                "assets": result.get("assets", [])[:30],
                "fetch_errors": result.get("fetch_errors", [])[:20],
                "guidance": self._js_analyze_guidance(result),
            }
        except Exception as e:
            return {"ok": False, "error": f"JS 分析异常: {type(e).__name__}: {e}"}

    @staticmethod
    def _js_analyze_guidance(result: dict[str, Any]) -> str:
        chains = result.get("chains") or []
        kinds = {c.get("kind") for c in chains if isinstance(c, dict)}
        base = (
            "这些只是 JS 静态线索。优先按 chains 里的 probes 用 http_request/run_shell 做真实验证；"
            "没有实证危害不要 submit_finding。"
        )
        if "client_signed_encrypted_api" in kinds:
            return (
                base
                + " 已命中「客户端签名+AES 加密请求体」链路：立刻提取 ClientAppID/ClientAppSecret/AES 口令，"
                "按前端算法构造请求。用 eval_javascript 跑登录页加密函数得到密文再 POST；"
                "只发现密钥不算洞。"
            )
        if "frontend_secret_followup" in kinds:
            return base + " 发现高价值 secret：继续搜索签名/加密函数并伪造一次受限调用。"
        return base

    def eval_javascript(self, code: str = "", timeout: int = 8) -> dict[str, Any]:
        src = (code or "").strip()
        if not src:
            return {"ok": False, "kind": "arg_error", "error": "code 为空"}
        if len(src) > 120_000:
            src = src[:120_000]
        t = max(1, min(int(timeout or 8), 20))
        p = None
        for bin_name in ("node", "nodejs"):
            try:
                p = subprocess.run(
                    [bin_name, "-e", src],
                    capture_output=True,
                    timeout=t,
                    cwd=str(self.work_dir),
                    env={**os.environ, "NODE_PATH": str(self.work_dir)},
                )
                break
            except FileNotFoundError:
                continue
            except subprocess.TimeoutExpired:
                return {"ok": False, "timed_out": True, "error": "eval_javascript 超时"}
            except Exception as e:
                return {"ok": False, "error": f"eval_javascript 异常: {type(e).__name__}: {e}"}
        if p is None:
            return {
                "ok": False,
                "error": "容器内无 node。用 run_shell 把加密改写成 python 计算，或 session_set 注入已有 Cookie。",
            }
        out = (p.stdout or b"").decode("utf-8", "replace")
        err = (p.stderr or b"").decode("utf-8", "replace")
        return {
            "ok": p.returncode == 0,
            "output": _truncate(out),
            "stderr": _truncate(err, 1500),
            "return_code": p.returncode,
            "guidance": "把 stdout 的密文/签名填进 http_request 的 data/json_body；这不是浏览器，DOM/window 不可用。",
        }

    # ---- suggest_waf_bypass（纯本地，不发网络）----
    def suggest_waf_bypass(
        self,
        payload: str,
        status_code: int | None = None,
        response_headers: Optional[dict[str, Any]] = None,
        response_body: str = "",
        context: str = "generic",
    ) -> dict[str, Any]:
        try:
            return _suggest_waf_bypass(
                payload=payload,
                status_code=status_code,
                response_headers=response_headers,
                response_body=response_body,
                context=context,
            )
        except Exception as e:
            return {"ok": False, "error": f"WAF 建议生成异常: {type(e).__name__}: {e}"}

    # ---- knowledge_lookup（人工知识库查阅，渐进式披露）----
    def knowledge_lookup(
        self,
        doc_id: str = "",
        vuln_found: bool = False,
        vuln_type: str = "",
    ) -> dict[str, Any]:
        """查阅人工知识库技巧文档。

        两步渐进式披露：
        - 传 doc_id → 返回该文档完整原文（第二步）
        - 不传 doc_id → 按是否发现漏洞筛选，返回标题+摘要列表（第一步）

        使用同步 sqlite3 直查（executor 运行在线程池中，WAL 模式并发安全）。
        """
        db_path = os.environ.get(
            "DB_PATH",
            str(Path(__file__).resolve().parent.parent.parent / "data" / "autohunter.db"),
        )
        try:
            conn = sqlite3.connect(db_path, timeout=5)
            conn.row_factory = sqlite3.Row

            # 第二步：获取完整原文
            if doc_id:
                row = conn.execute(
                    "SELECT id, title, summary, content, doc_type, tags, hit_count "
                    "FROM knowledge_docs WHERE id = ? AND enabled = 1",
                    (doc_id,),
                ).fetchone()
                conn.close()
                if not row:
                    return {"ok": False, "error": "文档不存在或未启用"}
                # 增加引用计数（best-effort，失败不影响读取）
                try:
                    conn2 = sqlite3.connect(db_path, timeout=5)
                    conn2.execute(
                        "UPDATE knowledge_docs SET hit_count = hit_count + 1 WHERE id = ?",
                        (doc_id,),
                    )
                    conn2.commit()
                    conn2.close()
                except Exception:
                    pass
                import json as _json
                return {
                    "ok": True,
                    "doc_id": row["id"],
                    "title": row["title"],
                    "summary": row["summary"],
                    "content": row["content"][:8000],  # 截断防 context 爆炸
                    "doc_type": row["doc_type"],
                    "tags": _json.loads(row["tags"]) if row["tags"] else [],
                    "hit_count": row["hit_count"],
                    "guidance": "这是辅助参考技巧，请结合目标实际情况独立判断，不要盲目照搬。",
                }

            # 第一步：返回筛选后的标题+摘要列表
            # vuln_found=false → 只返回 pre_vuln 文档
            # vuln_found=true  → 返回 pre_vuln + post_vuln 文档，按 vuln_type 标签匹配优先排序
            if vuln_found:
                query = (
                    "SELECT id, title, summary, doc_type, tags, hit_count "
                    "FROM knowledge_docs WHERE enabled = 1 "
                    "ORDER BY hit_count DESC LIMIT 30"
                )
            else:
                query = (
                    "SELECT id, title, summary, doc_type, tags, hit_count "
                    "FROM knowledge_docs WHERE enabled = 1 AND doc_type = 'pre_vuln' "
                    "ORDER BY hit_count DESC LIMIT 30"
                )
            rows = conn.execute(query).fetchall()
            conn.close()

            import json as _json
            docs = []
            for r in rows:
                tags = _json.loads(r["tags"]) if r["tags"] else []
                docs.append({
                    "doc_id": r["id"],
                    "title": r["title"],
                    "summary": r["summary"],
                    "doc_type": r["doc_type"],
                    "tags": tags,
                    "hit_count": r["hit_count"],
                })

            # 如果有 vuln_type，按标签匹配度排序（匹配的排前面）
            if vuln_type and docs:
                vt_lower = vuln_type.lower()
                docs.sort(
                    key=lambda d: (
                        0 if any(vt_lower in str(t).lower() for t in d.get("tags", [])) else 1,
                        -d.get("hit_count", 0),
                    )
                )

            # 收集所有可用标签（去重排序），供AI参考
            all_tags = sorted({str(t) for d in docs for t in d.get("tags", [])})

            return {
                "ok": True,
                "total": len(docs),
                "docs": docs,
                "available_tags": all_tags,
                "guidance": (
                    "以上是知识库中匹配的技巧文档摘要。选择你需要的文档，用 doc_id 参数获取完整原文。"
                    "available_tags 是当前知识库中所有可用标签，可用于判断文档覆盖范围。"
                    "知识库仅作辅助参考，请结合目标实际情况独立判断。"
                ),
            }
        except Exception as e:
            return {"ok": False, "error": f"知识库查询异常: {type(e).__name__}: {e}"}

    # ---- AutoPoc 漏洞知识库（search / read / run）----
    def autopoc_search(
        self,
        action: str = "search",
        component: str = "",
        q: str = "",
        severity: str = "critical",
        limit: int = 10,
    ) -> dict[str, Any]:
        return autopoc_bridge.autopoc_search(
            action=action,
            component=component,
            q=q,
            severity=severity,
            limit=limit,
        )

    def autopoc_read(
        self,
        action: str = "get",
        vuln_id: str = "",
        path: str = "",
        offset: int = 0,
        max_chars: int = 6000,
    ) -> dict[str, Any]:
        return autopoc_bridge.autopoc_read(
            action=action,
            vuln_id=vuln_id,
            path=path,
            offset=offset,
            max_chars=max_chars,
        )

    def autopoc_run(
        self,
        action: str = "nuclei",
        target: str = "",
        vuln_id: str = "",
        vuln_ids: Any = None,
        args: Any = None,
        script: str = "",
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        return autopoc_bridge.autopoc_run(
            action=action,
            target=target,
            vuln_id=vuln_id,
            vuln_ids=vuln_ids,
            args=args,
            script=script,
            timeout=timeout,
        )
