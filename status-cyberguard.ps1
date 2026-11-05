<#
.SYNOPSIS
    Reports the status of every CyberGuard AI service component.

.DESCRIPTION
    Read-only. Does not start, stop, or modify anything. Uses the actual
    health/readiness endpoints exposed by the backend
    (app/api/v1/health.py) and the real container names from
    docker-compose.yml.

.NOTES
    Run with:  .\status-cyberguard.ps1
    Or, if local scripts are blocked by policy:
      powershell -ExecutionPolicy Bypass -File .\status-cyberguard.ps1
#>

$ProjectRoot  = $PSScriptRoot
Set-Location $ProjectRoot
$PidStateFile = Join-Path $ProjectRoot '.cyberguard-pids.json'

$PgServiceName = 'postgresql-x64-18'
$BackendPort   = 8000
$FrontendPort  = 5173

$script:AllGood = $true

function Write-Section($title) {
    Write-Host ''
    Write-Host "== $title ==" -ForegroundColor Cyan
}
function Write-Ok($msg)   { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow; $script:AllGood = $false }
function Write-Fail($msg) { Write-Host "  [FAIL] $msg" -ForegroundColor Red; $script:AllGood = $false }

function Test-TcpPort([string]$ComputerName, [int]$Port) {
    try {
        return [bool](Test-NetConnection -ComputerName $ComputerName -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue)
    } catch {
        return $false
    }
}

function Get-ContainerHealth([string]$ContainerName) {
    try {
        $status = docker inspect --format '{{.State.Health.Status}}' $ContainerName 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        return $status.Trim()
    } catch {
        return $null
    }
}

Write-Host '=====================================================' -ForegroundColor Magenta
Write-Host '  CyberGuard AI - Status' -ForegroundColor Magenta
Write-Host '=====================================================' -ForegroundColor Magenta

# ---------------------------------------------------------------------------
# PostgreSQL
# ---------------------------------------------------------------------------
Write-Section 'PostgreSQL'
$pgService = Get-Service -Name $PgServiceName -ErrorAction SilentlyContinue
if (-not $pgService) {
    Write-Fail "Service '$PgServiceName' not found."
} elseif ($pgService.Status -ne 'Running') {
    Write-Fail "Service '$PgServiceName' status: $($pgService.Status)"
} else {
    Write-Ok "Service '$PgServiceName' is Running."
    if (Test-TcpPort -ComputerName 'localhost' -Port 5432) {
        Write-Ok "Accepting connections on port 5432."
    } else {
        Write-Fail "Service is Running but port 5432 is not accepting connections."
    }
}

# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------
Write-Section 'Redis (Docker)'
$redisHealth = Get-ContainerHealth 'cyberguard-redis'
if ($null -eq $redisHealth) {
    Write-Fail "Container 'cyberguard-redis' not found. Is it created? (docker compose up -d redis)"
} elseif ($redisHealth -eq 'healthy') {
    Write-Ok "Container healthy."
    if (Test-TcpPort -ComputerName 'localhost' -Port 6379) {
        Write-Ok "Port 6379 reachable."
    } else {
        Write-Fail "Container reports healthy but port 6379 is not reachable."
    }
} else {
    Write-Fail "Container health status: $redisHealth"
}

# ---------------------------------------------------------------------------
# Redpanda
# ---------------------------------------------------------------------------
Write-Section 'Redpanda (Docker)'
$redpandaHealth = Get-ContainerHealth 'cyberguard-redpanda'
if ($null -eq $redpandaHealth) {
    Write-Fail "Container 'cyberguard-redpanda' not found. Is it created? (docker compose up -d redpanda)"
} elseif ($redpandaHealth -eq 'healthy') {
    Write-Ok "Container healthy."
    if (Test-TcpPort -ComputerName 'localhost' -Port 9092) {
        Write-Ok "Port 9092 reachable."
    } else {
        Write-Fail "Container reports healthy but port 9092 is not reachable."
    }
} else {
    Write-Fail "Container health status: $redpandaHealth"
}

# ---------------------------------------------------------------------------
# Backend process + health endpoints
# ---------------------------------------------------------------------------
Write-Section 'Backend (FastAPI)'

$trackedBackendPid = $null
if (Test-Path $PidStateFile) {
    $state = Get-Content $PidStateFile -Raw | ConvertFrom-Json
    $trackedBackendPid = $state.backendPid
}
if ($trackedBackendPid -and (Get-Process -Id $trackedBackendPid -ErrorAction SilentlyContinue)) {
    Write-Ok "Tracked backend process PID $trackedBackendPid is running."
} elseif ($trackedBackendPid) {
    Write-Warn "Tracked backend PID $trackedBackendPid is no longer running."
} else {
    Write-Warn "No backend PID tracked in .cyberguard-pids.json."
}

try {
    $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$BackendPort/api/v1/health" -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
    Write-Ok "GET /api/v1/health -> HTTP $($resp.StatusCode)"
} catch {
    Write-Fail "GET /api/v1/health failed: $($_.Exception.Message)"
}

try {
    $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$BackendPort/api/v1/health/ready" -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
    $body = $resp.Content | ConvertFrom-Json
    Write-Ok "GET /api/v1/health/ready -> HTTP $($resp.StatusCode), checks: $($body.checks | ConvertTo-Json -Compress)"
} catch {
    if ($_.Exception.Response) {
        $code = [int]$_.Exception.Response.StatusCode
        Write-Warn "GET /api/v1/health/ready -> HTTP $code (not ready - see backend logs for which check failed)"
    } else {
        Write-Fail "GET /api/v1/health/ready failed: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# Frontend
# ---------------------------------------------------------------------------
Write-Section 'Frontend (Vite)'

$trackedFrontendPid = $null
if (Test-Path $PidStateFile) {
    $state = Get-Content $PidStateFile -Raw | ConvertFrom-Json
    $trackedFrontendPid = $state.frontendPid
}
if ($trackedFrontendPid -and (Get-Process -Id $trackedFrontendPid -ErrorAction SilentlyContinue)) {
    Write-Ok "Tracked frontend process PID $trackedFrontendPid is running."
} elseif ($trackedFrontendPid) {
    Write-Warn "Tracked frontend PID $trackedFrontendPid is no longer running."
} else {
    Write-Warn "No frontend PID tracked in .cyberguard-pids.json."
}

try {
    $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$FrontendPort/" -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
    Write-Ok "GET http://127.0.0.1:$FrontendPort/ -> HTTP $($resp.StatusCode)"
} catch {
    Write-Fail "Frontend not responding on port ${FrontendPort}: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# Rollup
# ---------------------------------------------------------------------------
Write-Section 'Overall'
if ($script:AllGood) {
    Write-Host "  CyberGuard AI is fully operational." -ForegroundColor Green
    exit 0
} else {
    Write-Host "  CyberGuard AI is only partially running. See [FAIL]/[WARN] items above." -ForegroundColor Red
    exit 1
}
