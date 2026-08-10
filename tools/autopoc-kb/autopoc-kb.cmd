@echo off
REM AutoPoc kb-only CLI（标准库 + Python 3，无需 backend / venv）
REM 示例：
REM   autopoc-kb.cmd --kb-dir C:\path\to\kb search-vulns -c confluence
setlocal EnableExtensions
set "HERE=%~dp0"
set "PYTHONPATH=%HERE%;%PYTHONPATH%"
where python >nul 2>&1
if not errorlevel 1 (
  python -m autopoc_kb %*
  exit /b %ERRORLEVEL%
)
py -3 -m autopoc_kb %*
exit /b %ERRORLEVEL%
