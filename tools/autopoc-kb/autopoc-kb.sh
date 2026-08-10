#!/usr/bin/env bash
# AutoPoc kb-only CLI（标准库 + python3，无需 backend / venv）
# 示例：
#   ./autopoc-kb.sh --kb-dir /path/to/kb search-vulns -c confluence
#   ./autopoc-kb.sh --kb-dir ./kb get-vuln --id CVE-2024-21683
#   ./autopoc-kb.sh --kb-dir ./kb run-poc --id CVE-xxx -- --url http://127.0.0.1:8080
#   ./autopoc-kb.sh get-poc-result --job-id <job_id>   # run-poc / run-nuclei 须手动取结果
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
export PYTHONPATH="${HERE}${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m autopoc_kb "$@"
