# Pre-release security check (CLAUDE.md 7.11): linters, security scanners and every test suite.
# Run from the project root:   powershell -ExecutionPolicy Bypass -File scripts\security-check.ps1
# Needs the backend and agent .venv folders and frontend\node_modules (see README.md), and the
# local MongoDB service for the backend tests. Add -SkipTests for the scanners only.
#
# pip-audit lists the known findings that are accepted in docs/known-limitations.md
# (dnspython, Pillow, filelock); anything new in its output needs a fix or a written reason.

param([switch]$SkipTests)

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
$env:PYTHONIOENCODING = "utf-8"   # bandit's report has non-ASCII characters
$failed = New-Object System.Collections.Generic.List[string]

function Step([string]$name, [string]$dir, [scriptblock]$command) {
    Write-Host ""
    Write-Host "== $name" -ForegroundColor Cyan
    Push-Location (Join-Path $root $dir)
    try {
        & $command
        if ($LASTEXITCODE -ne 0) { $failed.Add($name) }
    } finally {
        Pop-Location
    }
}

$py = ".venv\Scripts\python.exe"

Step "backend: ruff"       "backend"  { & $py -m ruff check . }
Step "backend: bandit"     "backend"  { & $py -m bandit -q -r app scripts }
Step "backend: pip-audit"  "backend"  { & $py -m pip_audit -r requirements.txt }
Step "agent: ruff"         "agent"    { & $py -m ruff check . }
Step "agent: bandit"       "agent"    { & $py -m bandit -q -r netmap_agent simulation }
Step "agent: pip-audit"    "agent"    { & $py -m pip_audit -r requirements.txt }
Step "frontend: npm audit" "frontend" { npm audit --omit=dev }

if (-not $SkipTests) {
    Step "backend: pytest"  "backend"  { & $py -m pytest -q -p no:warnings }
    Step "agent: pytest"    "agent"    { & $py -m pytest -q -p no:warnings }
    Step "frontend: vitest" "frontend" { npx vitest run }
    Step "frontend: build"  "frontend" { npm run build }
}

Write-Host ""
if ($failed.Count -eq 0) {
    Write-Host "All checks passed." -ForegroundColor Green
    exit 0
}
Write-Host "Failed or reported findings:" -ForegroundColor Yellow
$failed | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
Write-Host "pip-audit findings already accepted in docs/known-limitations.md can be ignored."
exit 1
