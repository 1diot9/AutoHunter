# AutoPoc kb-only CLI（标准库 + Python 3，无需 backend / venv）
# 示例：
#   .\autopoc-kb.ps1 --kb-dir C:\path\to\kb search-vulns -c confluence
$ErrorActionPreference = 'Stop'
$Here = $PSScriptRoot
$env:PYTHONPATH = if ($env:PYTHONPATH) { "$Here;$env:PYTHONPATH" } else { $Here }

$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command py -ErrorAction SilentlyContinue }
if (-not $py) { throw 'Python 3 not found. Install Python 3 and retry.' }

if ($py.Name -eq 'py.exe') {
    & py -3 -m autopoc_kb @args
} else {
    & python -m autopoc_kb @args
}
exit $LASTEXITCODE
