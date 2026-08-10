"""业务异常与共享常量。"""

from __future__ import annotations


class VulnKbError(Exception):
    """可映射为工具错误信息的业务异常。"""

    def __init__(self, message: str, *, code: str = "error") -> None:
        super().__init__(message)
        self.code = code
        self.message = message


DEFAULT_MAX_CHARS = 30_000
HARD_CHUNK_MAX = 100_000
DEFAULT_SEARCH_LIMIT = 10
MAX_SEARCH_LIMIT = 50
SEARCH_SEVERITIES = ("critical", "high", "medium", "low")
DEFAULT_SEARCH_SEVERITIES = ("critical",)
DEFAULT_POC_OUTPUT_CHARS = 50_000
HARD_POC_OUTPUT_MAX = 200_000
DEFAULT_NUCLEI_OUTPUT_CHARS = 50_000
HARD_NUCLEI_OUTPUT_MAX = 200_000
MAX_NUCLEI_VULNS = 10
DEFAULT_NUCLEI_TIMEOUT = 300
DEFAULT_POC_TIMEOUT = 120
NUCLEI_JOB_TTL_S = 3600
POC_JOB_TTL_S = 3600
_POC_SCRIPT_PREFERENCE = ("exploit.py", "poc.py", "detect.py", "main.py")
