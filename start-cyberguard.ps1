<#
.SYNOPSIS
    Starts all CyberGuard AI services in the required hybrid layout:
    PostgreSQL (native Windows service), Redis + Redpanda (Docker),
    FastAPI backend (native venv), React/Vite frontend (native).

.DESCRIPTION
    - Does NOT start backend/frontend/PostgreSQL as Docker containers.
    - Does NOT start any Compose service other than redis/redpanda.
    - Does NOT auto-restart an already-running backend/frontend; reports
      the existing PID/port instead.
    - Does NOT change the machine's PowerShell execution policy.

.NOTES
    Run with:  .\start-cyberguard.ps1
    Or, if local scripts are blocked by policy:
      powershell -ExecutionPolicy Bypass -File .\start-cyberguard.ps1
#>

$ProjectRoot = $PSScriptRoot
Set-Location $ProjectRoot

$BackendDir   = Join-Path $ProjectRoot 'backend'
$FrontendDir  = Join-Path $ProjectRoot 'frontend'
$PythonExe    = Join-Path $BackendDir 'venv\Scripts\python.exe'
$PidStateFile = Join-Path $ProjectRoot '.cyberguard-pids.json'

$PgServiceName = 'postgresql-x64-18'
$BackendPort   = 8000
$FrontendPort  = 5173

$script:HadFailure = $false

function Write-Section($title) {
    Write-Host ''
    Write-Host "== $title ==" -ForegroundColor Cyan
}

function Write-Ok($msg)   { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function Write-Fail($msg) {
    Write-Host "  [FAIL] $msg" -ForegroundColor Red
    $script:HadFailure = $true
}

function Get-ListeningProcessId([int]$Port) {
    $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($conn) { return $conn.OwningProcess }
    return $null
}

function Test-TcpPort([string]$ComputerName, [int]$Port, [int]$TimeoutSeconds = 1) {
    try {
        $result = Test-NetConnection -ComputerName $ComputerName -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue
        return [bool]$result
    } catch {
        return $false
    }
}

function Wait-ForCondition {
    param(
        [scriptblock]$Condition,
        [int]$TimeoutSeconds = 30,
        [int]$IntervalSeconds = 2
    )
    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        if (& $Condition) { return $true }
        Start-Sleep -Seconds $IntervalSeconds
        $elapsed += $IntervalSeconds
    }
    return $false
}

function Get-ContainerHealth([string]$ContainerName) {
    try {
        $status = docker inspect --format '{{.State.Health.Status}}' $ContainerName 2>$null
        if ($LASTEXITCODE -ne 0) { return 'missing' }
        return $status.Trim()
    } catch {
        return 'missing'
    }
}

Write-Host '=====================================================' -ForegroundColor Magenta
Write-Host '  CyberGuard AI - Startup' -ForegroundColor Magenta
Write-Host '=====================================================' -ForegroundColor Magenta

# ---------------------------------------------------------------------------
# 1. Working directory
# ---------------------------------------------------------------------------
Write-Section 'Project Root'
Write-Ok "Working directory: $ProjectRoot"

# ---------------------------------------------------------------------------
# 2. Docker Desktop check
# ---------------------------------------------------------------------------
Write-Section 'Docker Desktop'
$dockerInfo = docker info 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Fail "Docker Desktop does not appear to be running."
    Write-Host "    Diagnose: run 'docker info' manually and check Docker Desktop is started." -ForegroundColor DarkYellow
} else {
    Write-Ok "Docker Desktop is running."
}

# ---------------------------------------------------------------------------
# 3. PostgreSQL native Windows service
# ---------------------------------------------------------------------------
Write-Section 'PostgreSQL Service'
$pgOk = $false
$pgService = Get-Service -Name $PgServiceName -ErrorAction SilentlyContinue
if (-not $pgService) {
    Write-Fail "Windows service '$PgServiceName' was not found."
    Write-Host "    Diagnose: run 'Get-Service postgresql*' to find the correct service name." -ForegroundColor DarkYellow
} else {
    if ($pgService.Status -ne 'Running') {
        Write-Host "  PostgreSQL service is '$($pgService.Status)'. Starting it..." -ForegroundColor DarkCyan
        try {
            Start-Service -Name $PgServiceName -ErrorAction Stop
        } catch {
            Write-Fail "Could not start service '$PgServiceName': $($_.Exception.Message)"
            Write-Host "    Diagnose: try 'Start-Service $PgServiceName' from an elevated PowerShell." -ForegroundColor DarkYellow
        }
    } else {
        Write-Ok "PostgreSQL service already running."
    }

    # Confirm it is actually accepting TCP connections, not just "Running".
    $pgReady = Wait-ForCondition -Condition { Test-TcpPort -ComputerName 'localhost' -Port 5432 } -TimeoutSeconds 20 -IntervalSeconds 2
    if ($pgReady) {
        Write-Ok "PostgreSQL is accepting connections on port 5432."
        $pgOk = $true
    } else {
        Write-Fail "PostgreSQL service is not accepting connections on port 5432 within timeout."
        Write-Host "    Diagnose: check 'services.msc' for '$PgServiceName', or inspect its logs under the PostgreSQL data directory." -ForegroundColor DarkYellow
    }
}

# ---------------------------------------------------------------------------
# 4. Redis + Redpanda via Docker Compose (only these two services)
# ---------------------------------------------------------------------------
Write-Section 'Redis + Redpanda (Docker)'
$redisOk = $false
$redpandaOk = $false

if ($LASTEXITCODE -eq 0 -or $true) {
    Push-Location $ProjectRoot
    try {
        docker compose up -d redis redpanda 2>&1 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "'docker compose up -d redis redpanda' returned a non-zero exit code."
            Write-Host "    Diagnose: run 'docker compose logs redis redpanda' for details." -ForegroundColor DarkYellow
        } else {
            $redisHealthy = Wait-ForCondition -Condition { (Get-ContainerHealth 'cyberguard-redis') -eq 'healthy' } -TimeoutSeconds 30 -IntervalSeconds 2
            if ($redisHealthy) {
                Write-Ok "Redis container (cyberguard-redis) is healthy."
                $redisOk = $true
            } else {
                $state = Get-ContainerHealth 'cyberguard-redis'
                Write-Fail "Redis container did not become healthy (status: $state)."
                Write-Host "    Diagnose: run 'docker compose logs redis'." -ForegroundColor DarkYellow
            }

            $redpandaHealthy = Wait-ForCondition -Condition { (Get-ContainerHealth 'cyberguard-redpanda') -eq 'healthy' } -TimeoutSeconds 60 -IntervalSeconds 3
            if ($redpandaHealthy) {
                Write-Ok "Redpanda container (cyberguard-redpanda) is healthy."
                $redpandaOk = $true
            } else {
                $state = Get-ContainerHealth 'cyberguard-redpanda'
                Write-Fail "Redpanda container did not become healthy (status: $state)."
                Write-Host "    Diagnose: run 'docker compose logs redpanda'." -ForegroundColor DarkYellow
            }
        }
    } finally {
        Pop-Location
    }
}

# ---------------------------------------------------------------------------
# 5. Backend (FastAPI, native venv, run_windows.py)
# ---------------------------------------------------------------------------
Write-Section 'Backend (FastAPI)'
$backendPid = $null
$existingBackendPid = Get-ListeningProcessId -Port $BackendPort

if ($existingBackendPid) {
    $proc = Get-Process -Id $existingBackendPid -ErrorAction SilentlyContinue
    $procName = if ($proc) { $proc.ProcessName } else { 'unknown' }
    Write-Warn "Port $BackendPort is already in use by PID $existingBackendPid ($procName). Not starting a duplicate backend."
    $backendPid = $existingBackendPid
} else {
    if (-not (Test-Path $PythonExe)) {
        Write-Fail "Backend virtual environment python.exe not found at: $PythonExe"
        Write-Host "    Diagnose: create the venv first (python -m venv backend\venv) and install requirements." -ForegroundColor DarkYellow
    } else {
        Write-Host "  Launching backend via run_windows.py (preserves Selector event-loop fix)..." -ForegroundColor DarkCyan
        $proc = Start-Process -FilePath 'powershell' `
            -ArgumentList @('-NoExit', '-Command', "Set-Location '$BackendDir'; & '$PythonExe' run_windows.py") `
            -WindowStyle Normal `
            -PassThru
        $backendPid = $proc.Id
        Write-Ok "Backend window launched (PID $backendPid)."
    }
}

$backendReady = $false
if ($backendPid) {
    Write-Host "  Waiting for backend readiness endpoint..." -ForegroundColor DarkCyan
    $backendReady = Wait-ForCondition -Condition {
        try {
            $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$BackendPort/api/v1/health/ready" -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
            return $resp.StatusCode -eq 200
        } catch {
            # /ready may legitimately return 503 while still starting; treat
            # non-200 as "not ready yet" and keep polling, but also accept
            # the basic liveness endpoint once it responds at all.
            try {
                $resp2 = Invoke-WebRequest -Uri "http://127.0.0.1:$BackendPort/api/v1/health" -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
                return $resp2.StatusCode -eq 200
            } catch {
                return $false
            }
        }
    } -TimeoutSeconds 45 -IntervalSeconds 3

    if ($backendReady) {
        Write-Ok "Backend is responding on port $BackendPort."
    } else {
        Write-Fail "Backend did not respond on http://127.0.0.1:$BackendPort within timeout."
        Write-Host "    Diagnose: check the backend PowerShell window for a traceback, or run 'python run_windows.py' manually from backend\." -ForegroundColor DarkYellow
    }
}

# ---------------------------------------------------------------------------
# 6. Frontend (Vite dev server, native)
# ---------------------------------------------------------------------------
Write-Section 'Frontend (Vite)'
$frontendPid = $null
$existingFrontendPid = Get-ListeningProcessId -Port $FrontendPort

if ($existingFrontendPid) {
    $proc = Get-Process -Id $existingFrontendPid -ErrorAction SilentlyContinue
    $procName = if ($proc) { $proc.ProcessName } else { 'unknown' }
    Write-Warn "Port $FrontendPort is already in use by PID $existingFrontendPid ($procName). Not starting a duplicate frontend."
    $frontendPid = $existingFrontendPid
} else {
    if (-not (Test-Path (Join-Path $FrontendDir 'package.json'))) {
        Write-Fail "frontend\package.json not found at: $FrontendDir"
    } else {
        Write-Host "  Launching Vite dev server..." -ForegroundColor DarkCyan
        $devCmd = "Set-Location '$FrontendDir'; npm run dev -- --host=127.0.0.1 --port=$FrontendPort --strictPort"
        $proc = Start-Process -FilePath 'powershell' `
            -ArgumentList @('-NoExit', '-Command', $devCmd) `
            -WindowStyle Normal `
            -PassThru
        $frontendPid = $proc.Id
        Write-Ok "Frontend window launched (PID $frontendPid)."
    }
}

$frontendReady = $false
if ($frontendPid) {
    Write-Host "  Waiting for frontend dev server to respond..." -ForegroundColor DarkCyan
    $frontendReady = Wait-ForCondition -Condition {
        Test-TcpPort -ComputerName '127.0.0.1' -Port $FrontendPort
    } -TimeoutSeconds 30 -IntervalSeconds 2

    if ($frontendReady) {
        Write-Ok "Frontend is responding on port $FrontendPort."
    } else {
        Write-Fail "Frontend did not respond on http://127.0.0.1:$FrontendPort within timeout."
        Write-Host "    Diagnose: check the frontend PowerShell window for errors, or run 'npm run dev' manually from frontend\." -ForegroundColor DarkYellow
    }
}

# ---------------------------------------------------------------------------
# 7. Persist PIDs for stop-cyberguard.ps1
# ---------------------------------------------------------------------------
$state = @{
    backendPid  = $backendPid
    frontendPid = $frontendPid
    startedAt   = (Get-Date).ToString('o')
}
$state | ConvertTo-Json | Set-Content -Path $PidStateFile -Encoding UTF8

# ---------------------------------------------------------------------------
# 8. Summary
# ---------------------------------------------------------------------------
Write-Section 'Summary'
Write-Host "  PostgreSQL : $(if ($pgOk) { 'OK' } else { 'FAILED' })" -ForegroundColor $(if ($pgOk) { 'Green' } else { 'Red' })
Write-Host "  Redis      : $(if ($redisOk) { 'OK' } else { 'FAILED' })" -ForegroundColor $(if ($redisOk) { 'Green' } else { 'Red' })
Write-Host "  Redpanda   : $(if ($redpandaOk) { 'OK' } else { 'FAILED' })" -ForegroundColor $(if ($redpandaOk) { 'Green' } else { 'Red' })
Write-Host "  Backend    : $(if ($backendReady) { 'OK' } else { 'FAILED' })" -ForegroundColor $(if ($backendReady) { 'Green' } else { 'Red' })
Write-Host "  Frontend   : $(if ($frontendReady) { 'OK' } else { 'FAILED' })" -ForegroundColor $(if ($frontendReady) { 'Green' } else { 'Red' })
Write-Host ''

if ($script:HadFailure -or -not ($pgOk -and $redisOk -and $redpandaOk -and $backendReady -and $frontendReady)) {
    Write-Host "CyberGuard AI did NOT start cleanly. Review the [FAIL] messages above." -ForegroundColor Red
    exit 1
} else {
    Write-Host "CyberGuard AI is up." -ForegroundColor Green
    Write-Host "  Frontend : http://localhost:5173" -ForegroundColor Green
    Write-Host "  Backend  : http://127.0.0.1:8000/docs" -ForegroundColor Green
    exit 0
}
