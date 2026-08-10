# AutoPoc kb-only CLI

可单独拷贝的漏洞知识库 CLI：只读可移植 `kb/`，功能对齐 MCP `autopoc-vuln-kb`。
**零第三方依赖**（Python 3 标准库；跑 Nuclei 需本机安装 `nuclei`）。

## 在 AutoHunter 中的用法

本目录已 vendored 到 AutoHunter 的 `tools/autopoc-kb/`。Worker 通过
`autopoc_search` / `autopoc_read` / `autopoc_run` 三个工具调用（见 `app/tools/autopoc_bridge.py`），
不经过 Cursor MCP。

1. 把知识库导出放到 `data/autopoc-kb/`（或设 `AUTOPOC_KB_DIR`），布局为 `{slug}/meta.json` + 产物。
2. 重启/热更容器后，Worker 在轮数门控通过且目录非空时自动挂载上述工具。
3. 也可直接用本 CLI 调试：

```bash
./autopoc-kb.sh --kb-dir ../../data/autopoc-kb list-components
```

## 迁移到其他项目

拷贝本目录 + 知识库即可：

```text
your-project/
├── tools/autopoc-kb/     # 本目录整体（或任意目录名）
│   ├── autopoc_kb/
│   ├── autopoc-kb.sh
│   ├── autopoc-kb.cmd
│   └── autopoc-kb.ps1
└── kb/                   # 或任意路径的 kb 导出
    └── {slug}/meta.json + report.md + poc/ + nuclei/ + …
```

## 用法

`--kb-dir` 默认 `./kb`（也可设 `AUTOPOC_KB_DIR`）：

```bash
# 当前目录下有 ./kb 时可省略 --kb-dir
./autopoc-kb.sh -h
./autopoc-kb.sh list-components
./autopoc-kb.sh list-components -q spring
./autopoc-kb.sh search-vulns -c confluence
./autopoc-kb.sh get-vuln --id CVE-2024-21683
./autopoc-kb.sh get-artifact --id cve-2024-21683 --path report.md
./autopoc-kb.sh get-poc-meta --id CVE-2024-21683

# run-* 只启动任务并返回 job_id；必须再 get-*-result 取结果
./autopoc-kb.sh run-poc --id CVE-2024-21683 -- --target http://127.0.0.1:8090
./autopoc-kb.sh get-poc-result --job-id <job_id>
./autopoc-kb.sh run-nuclei --ids CVE-2024-21683 --target http://127.0.0.1:8090
./autopoc-kb.sh get-nuclei-result --job-id <job_id>

# 其他路径
./autopoc-kb.sh --kb-dir /path/to/kb search-vulns -c confluence
```

也可：

```bash
export PYTHONPATH=/path/to/tools/autopoc-kb
python3 -m autopoc_kb search-vulns -c confluence
```

`--id` / `--ids` 可用数字稳定 id、CVE identifier 或目录 slug。
**仅对已授权目标**使用 `run-poc` / `run-nuclei`。

## 重要：`run-poc` / `run-nuclei` 须手动取结果

与 MCP 一致：**启动与取结果是两步**。

| 步骤 | PoC | Nuclei |
|------|-----|--------|
| 1. 启动 | `run-poc` → 立刻返回 `job_id` | `run-nuclei` → 立刻返回 `job_id` |
| 2. 取结果（必调） | `get-poc-result --job-id …` | `get-nuclei-result --job-id …` |

- `run-poc` / `run-nuclei` **不会**自动打印最终 stdout / hit 结果。
- 须反复调用对应的 `get-*-result`，直到 `status` 为 `done` 或 `failed`。
- 可选：`--wait` 让本进程内阻塞轮询到结束（仍建议 Agent / 脚本走手动两步）。

```bash
# 推荐（手动回调）
./autopoc-kb.sh run-nuclei --ids CVE-2024-21683 --target http://127.0.0.1:8090
# → {"job_id":"…","status":"running",…}
./autopoc-kb.sh get-nuclei-result --job-id <job_id>

./autopoc-kb.sh run-poc --id CVE-2024-21683 -- --target http://127.0.0.1:8090
./autopoc-kb.sh get-poc-result --job-id <job_id>

# 可选：本进程等结束
./autopoc-kb.sh run-poc --wait --id CVE-2024-21683 -- --target http://127.0.0.1:8090
```

子命令帮助里也写了同样约定：`./autopoc-kb.sh run-poc -h`、`./autopoc-kb.sh run-nuclei -h`。

## 子命令（对齐 MCP）

| CLI | MCP |
|-----|-----|
| `list-components` | `list_components` |
| `search-vulns` | `search_vulns` |
| `get-vuln` | `get_vuln` |
| `get-artifact` | `get_artifact` |
| `get-poc-meta` | `get_poc_meta` |
| `run-poc` | `run_poc`（返回 `job_id`） |
| `get-poc-result` | `get_poc_result`（**手动轮询**） |
| `run-nuclei` | `run_nuclei`（返回 `job_id`） |
| `get-nuclei-result` | `get_nuclei_result`（**手动轮询**） |
