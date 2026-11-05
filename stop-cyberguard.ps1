<#
.SYNOPSIS
    Safely stops the CyberGuard AI backend/frontend processes started by
    start-cyberguard.ps1, and stops (not removes) the Redis/Redpanda
    containers.

.DESCRIPTION
    - Only stops processes whose PIDs were recorded by start-cyberguard.ps1
      in .cyberguard-pids.json, and only after sanity-checking the process
      name. Never kills a process merely because it occupies port 8000 or
      5173.
    - Never stops PostgreSQL.
    - Uses 'docker compose stop redis redpanda' only - never 'down',
      'down -v', 'rm', or any volume/image command.

.NOTES
    Run with:  .\stop-cyberguard.ps1
    Or, if local scripts are blocked by policy:
      powershell -ExecutionPolicy Bypass -File .\stop-cyberguard.ps1
#>

$ProjectRoot  = $PSScriptRoot
Set-Location $ProjectRoot
$PidStateFile = Join-Path $ProjectRoot '.cyberguard-pids.json'

function Write-Section($title) {
    Write-Host ''
    Write-Host "== $title ==" -ForegroundColor Cyan
}
function Write-Ok($msg)   { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "  [FAIL] $msg" -ForegroundColor Red }

function Stop-TrackedProcess {
    param(
        [string]$Label,
        [Nullable[int]]$ProcessId,
        [string[]]$ExpectedNames
    )

    if (-not $ProcessId) {
        Write-Warn "No tracked PID recorded for $Label (nothing to stop)."
        return
    }

    $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if (-not $proc) {
        Write-Warn "$Label PID $ProcessId is not running (already stopped or stale record)."
        return
    }

    if ($ExpectedNames -notcontains $proc.ProcessName) {
        Write-Warn "$Label PID $ProcessId is now '$($proc.ProcessName)', not one of [$($ExpectedNames -join ', ')]. Refusing to stop it - this PID likely belongs to a different, unrelated process now. Stop it manually if you're sure."
        return
    }

    try {
        Stop-Process -Id $ProcessId -ErrorAction Stop
        Start-Sleep -Seconds 2
        if (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue) {
            Write-Host "  $Label did not exit gracefully, forcing..." -ForegroundColor DarkYellow
            Stop-Process -Id $ProcessId -Force -ErrorAction Stop
        }
        Write-Ok "$Label stopped (was PID $ProcessId)."
    } catch {
        Write-Fail "Could not stop $Label (PID $ProcessId): $($_.Exception.Message)"
    }
}

Write-Host '=====================================================' -ForegroundColor Magenta
Write-Host '  CyberGuard AI - Stop' -ForegroundColor Magenta
Write-Host '=====================================================' -ForegroundColor Magenta

Write-Section 'Backend / Frontend'
if (-not (Test-Path $PidStateFile)) {
    Write-Warn "No .cyberguard-pids.json found - nothing was tracked as started by start-cyberguard.ps1."
    Write-Host "    If a backend/frontend is running, it was not launched by this script system (or its tracking file was removed)." -ForegroundColor DarkYellow
    Write-Host "    Stop it manually, or identify its PID with: Get-NetTCPConnection -LocalPort 8000,5173" -ForegroundColor DarkYellow
} else {
    $state = Get-Content $PidStateFile -Raw | ConvertFrom-Json
    Stop-TrackedProcess -Label 'Backend'  -ProcessId $state.backendPid  -ExpectedNames @('python', 'powershell', 'pwsh')
    Stop-TrackedProcess -Label 'Frontend' -ProcessId $state.frontendPid -ExpectedNames @('node', 'powershell', 'pwsh')

    Remove-Item -Path $PidStateFile -ErrorAction SilentlyContinue
    Write-Ok "Cleared .cyberguard-pids.json."
}

Write-Section 'Redis + Redpanda (Docker)'
Push-Location $ProjectRoot
try {
    docker compose stop redis redpanda 2>&1 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "Redis and Redpanda containers stopped (not removed; volumes intact)."
    } else {
        Write-Fail "'docker compose stop redis redpanda' returned a non-zero exit code."
    }
} finally {
    Pop-Location
}

Write-Section 'PostgreSQL'
Write-Warn "PostgreSQL service was left untouched (not stopped automatically, as required)."

Write-Host ''
Write-Host 'Done.' -ForegroundColor Green
