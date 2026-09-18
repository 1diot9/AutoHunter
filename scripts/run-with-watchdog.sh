#!/bin/sh
set -eu

# ============================================================================
#  AutoHunter  ·  Powered By StanleyNull  ·  CC BY-NC 4.0
# ============================================================================

# Windows Docker 把 ~/.ssh 私钥挂成 0777，OpenSSH 会直接拒绝。
# 从 /run/host-ssh 复制到 /root/.ssh 并 chmod 600，应用侧仍读默认路径。
prepare_ssh_keys() {
  mkdir -p /root/.ssh
  chmod 700 /root/.ssh 2>/dev/null || true
  installed=0
  for name in id_ed25519 id_rsa id_ecdsa id_ed25519_sk; do
    src="/run/host-ssh/$name"
    dest="/root/.ssh/$name"
    if [ -f "$src" ] && [ -s "$src" ]; then
      cp "$src" "$dest"
      chmod 600 "$dest"
      installed=$((installed + 1))
    fi
  done
  if [ "$installed" -gt 0 ]; then
    echo "[watchdog] staged $installed SSH private key(s) into /root/.ssh" >&2
  elif [ -d /run/host-ssh ]; then
    echo "[watchdog] no host SSH private key found under /run/host-ssh" >&2
  fi
}

prepare_ssh_keys

HOST="${AUTOHUNTER_HOST:-0.0.0.0}"
PORT="${AUTOHUNTER_PORT:-18800}"
INTERVAL="${AUTOHUNTER_WATCHDOG_INTERVAL:-20}"
TIMEOUT="${AUTOHUNTER_WATCHDOG_TIMEOUT:-20}"
MAX_FAILURES="${AUTOHUNTER_WATCHDOG_MAX_FAILURES:-3}"
MAX_LAG_FAILURES="${AUTOHUNTER_WATCHDOG_MAX_LAG_FAILURES:-12}"
START_GRACE="${AUTOHUNTER_WATCHDOG_START_GRACE:-20}"
DIAG_SIGNAL="${AUTOHUNTER_WATCHDOG_DIAG_SIGNAL:-USR1}"
DIAG_GRACE="${AUTOHUNTER_WATCHDOG_DIAG_GRACE:-3}"
HEARTBEAT_PATH="${AUTOHUNTER_HEARTBEAT_PATH:-/tmp/autohunter.heartbeat}"
HEARTBEAT_STALE="${AUTOHUNTER_WATCHDOG_HEARTBEAT_STALE:-45}"

dump_proc_file() {
  file="$1"
  if [ -r "$file" ]; then
    echo "----- $file -----" >&2
    cat "$file" >&2 || true
  else
    echo "----- $file (unavailable) -----" >&2
  fi
}

dump_native_diagnostics() {
  if ! kill -0 "$UVICORN_PID" 2>/dev/null; then
    return 0
  fi

  echo "[watchdog] native diagnostics begin pid=$UVICORN_PID" >&2
  dump_proc_file "/proc/$UVICORN_PID/status"
  dump_proc_file "/proc/$UVICORN_PID/wchan"
  dump_proc_file "/proc/$UVICORN_PID/sched"

  if [ -d "/proc/$UVICORN_PID/fd" ]; then
    echo "----- /proc/$UVICORN_PID/fd -----" >&2
    ls -l "/proc/$UVICORN_PID/fd" >&2 || true
  fi

  if [ -d "/proc/$UVICORN_PID/task" ]; then
    echo "----- /proc/$UVICORN_PID/task -----" >&2
    for task_dir in /proc/"$UVICORN_PID"/task/*; do
      tid="${task_dir##*/}"
      echo "[watchdog] thread tid=$tid" >&2
      dump_proc_file "$task_dir/comm"
      dump_proc_file "$task_dir/status"
      dump_proc_file "$task_dir/wchan"
      dump_proc_file "$task_dir/sched"
      dump_proc_file "$task_dir/stack"
    done
  fi
  echo "[watchdog] native diagnostics end pid=$UVICORN_PID" >&2
}

# ============================================================================
#  启动前安全检查：websockets 主版本必须 >=13。
#  pyppeteer/selenium/undetected-chromedriver 等包会把 websockets 降级到 <13，
#  导致 uvicorn 报 ImportError: cannot import name 'ServerProtocol'。
#  只在被降级到 <13 时才自动修复；高版本（>=15）uvicorn 通常向后兼容，
#  不强制降级（避免在受限网络里 pip 反复失败拖慢启动）。
# ============================================================================
WS_MAJOR=$(python3 -c "import websockets; print(websockets.__version__.split('.')[0])" 2>/dev/null || echo "0")
if [ "$WS_MAJOR" -lt 13 ] 2>/dev/null; then
  echo "[watchdog] websockets major=$WS_MAJOR < 13, auto-repairing..." >&2
  pip3 install --quiet 'websockets>=13.0' 2>&1 || pip install --quiet 'websockets>=13.0' 2>&1 || true
  WS_MAJOR=$(python3 -c "import websockets; print(websockets.__version__.split('.')[0])" 2>/dev/null || echo "0")
  echo "[watchdog] websockets repaired, new major=$WS_MAJOR" >&2
fi

uvicorn app.main:app --host "$HOST" --port "$PORT" &
UVICORN_PID="$!"

terminate() {
  if kill -0 "$UVICORN_PID" 2>/dev/null; then
    kill -TERM "$UVICORN_PID" 2>/dev/null || true
    sleep 5
    kill -KILL "$UVICORN_PID" 2>/dev/null || true
  fi
}

trap 'terminate; exit 143' INT TERM

heartbeat_age() {
  if [ ! -f "$HEARTBEAT_PATH" ]; then
    echo 99999
    return 0
  fi
  now=$(date +%s)
  mtime=$(stat -c %Y "$HEARTBEAT_PATH" 2>/dev/null || stat -f %m "$HEARTBEAT_PATH" 2>/dev/null || echo 0)
  age=$((now - mtime))
  if [ "$age" -lt 0 ]; then
    age=0
  fi
  echo "$age"
}

dump_and_kill() {
  reason="$1"
  echo "[watchdog] dumping runtime diagnostics via SIG${DIAG_SIGNAL}" >&2
  kill "-${DIAG_SIGNAL}" "$UVICORN_PID" 2>/dev/null || true
  sleep "$DIAG_GRACE" || true
  dump_native_diagnostics
  echo "[watchdog] ${reason}; terminating container for Docker restart" >&2
  terminate
  exit 70
}

sleep "$START_GRACE" || true
failures=0
lag_failures=0
dumped_lag=0

while kill -0 "$UVICORN_PID" 2>/dev/null; do
  if curl -fsS --max-time "$TIMEOUT" "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
    failures=0
    lag_failures=0
    dumped_lag=0
  else
    age=$(heartbeat_age)
    if [ "$age" -lt "$HEARTBEAT_STALE" ]; then
      # 进程心跳仍在跳：只是事件循环卡住，多半是 SQLite/大 JSON，不应立刻杀容器。
      lag_failures=$((lag_failures + 1))
      failures=0
      echo "[watchdog] /health lagged but thread heartbeat is fresh (${age}s); event-loop stall ${lag_failures}/${MAX_LAG_FAILURES}" >&2
      if [ "$dumped_lag" -eq 0 ]; then
        echo "[watchdog] dumping runtime diagnostics via SIG${DIAG_SIGNAL}" >&2
        kill "-${DIAG_SIGNAL}" "$UVICORN_PID" 2>/dev/null || true
        dumped_lag=1
      fi
      if [ "$lag_failures" -ge "$MAX_LAG_FAILURES" ]; then
        dump_and_kill "event loop stalled too long while process heartbeat stayed fresh"
      fi
    else
      failures=$((failures + 1))
      echo "[watchdog] health check failed and heartbeat stale (${age}s) ${failures}/${MAX_FAILURES}" >&2
      if [ "$failures" -ge "$MAX_FAILURES" ]; then
        dump_and_kill "uvicorn appears hung"
      fi
    fi
  fi
  sleep "$INTERVAL" || true
done

wait "$UVICORN_PID"
