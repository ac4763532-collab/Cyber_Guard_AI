<#
.SYNOPSIS
    CyberGuard AI Windows Collector — Service Installer

.DESCRIPTION
    Installs, uninstalls, and manages the CyberGuard Windows Collector
    as a Windows Service. Handles:
        - Admin elevation check
        - ACL setup on %PROGRAMDATA%\CyberGuard (SYSTEM + Admins only)
        - pip dependency install (pywin32)
        - Service install as LocalSystem (required for Security log access)
        - Auto-start at boot
        - Automatic restart on failure
        - Status / start / stop / restart commands

.PARAMETER Action
    The action to perform:
        Install      Install the service (default)
        Uninstall    Stop and remove the service
        Start        Start an installed service
        Stop         Stop a running service
        Restart      Stop and start
        Status       Show current status
        Enroll       Enroll the collector (prompts for token)

.PARAMETER EnrollmentToken
    Optional. If provided with -Action Install, the collector is
    enrolled non-interactively after service installation.
    If omitted, the operator runs `main.py enroll <token>` manually.

.PARAMETER PythonPath
    Optional. Path to python.exe. Defaults to "python" on PATH.

.EXAMPLE
    # Install the service (requires Administrator):
    .\install_service.ps1 -Action Install

.EXAMPLE
    # Install and enroll in one step:
    .\install_service.ps1 -Action Install -EnrollmentToken "cgc_abc123..."

.EXAMPLE
    # Check status:
    .\install_service.ps1 -Action Status

.EXAMPLE
    # Uninstall:
    .\install_service.ps1 -Action Uninstall

.NOTES
    Requires: Administrator elevation, Python 3.10+ on PATH, pywin32.
    The script installs pywin32 automatically if missing.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Install", "Uninstall", "Start", "Stop", "Restart", "Status", "Enroll")]
    [string]$Action = "Install",

    [Parameter(Mandatory = $false)]
    [string]$EnrollmentToken = "",

    [Parameter(Mandatory = $false)]
    [string]$PythonPath = "python"
)


# ============================================================================
# CONFIGURATION
# ============================================================================

$ServiceName       = "CyberGuardCollector"
$ServiceDisplayName = "CyberGuard AI Collector"
$ProgramDataDir    = Join-Path $env:PROGRAMDATA "CyberGuard"
$ScriptDir         = Split-Path -Parent $MyInvocation.MyCommand.Path
$MainScript        = Join-Path $ScriptDir "main.py"
$ServiceScript     = Join-Path $ScriptDir "service.py"

# Retry policy: restart 3 times on failure, spaced 60 seconds apart,
# reset the failure counter after 24 hours of clean running.
$RecoveryResetSeconds = 86400
$RecoveryActions      = "restart/60000/restart/60000/restart/60000"


# ============================================================================
# HELPERS
# ============================================================================

function Write-Banner {
    param([string]$Message)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $Message" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Message)
    Write-Host "  → $Message" -ForegroundColor White
}

function Write-Ok {
    param([string]$Message)
    Write-Host "  ✓ $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "  ⚠ $Message" -ForegroundColor Yellow
}

function Write-Fail {
    param([string]$Message)
    Write-Host "  ✗ $Message" -ForegroundColor Red
}

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Admin {
    if (-not (Test-Admin)) {
        Write-Host ""
        Write-Fail "This script must be run as Administrator."
        Write-Host ""
        Write-Host "  Right-click PowerShell → 'Run as administrator', then:"
        Write-Host "    cd `"$ScriptDir`""
        Write-Host "    .\install_service.ps1 -Action $Action"
        Write-Host ""
        exit 1
    }
}

function Test-Python {
    try {
        $version = & $PythonPath --version 2>&1
        if ($LASTEXITCODE -ne 0) {
            return $null
        }
        return $version
    } catch {
        return $null
    }
}

function Ensure-Pywin32 {
    Write-Step "Checking pywin32..."
    try {
        $null = & $PythonPath -c "import win32serviceutil" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "pywin32 is installed"
            return $true
        }
    } catch { }

    Write-Warn "pywin32 not found — installing..."
    & $PythonPath -m pip install --upgrade pywin32 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "pip install pywin32 failed"
        return $false
    }

    # pywin32 post-install registers the service DLLs — needed on some
    # Python versions to make win32service importable
    $postinstall = Join-Path (Split-Path -Parent (Split-Path -Parent $PythonPath)) "Scripts\pywin32_postinstall.py"
    if (Test-Path $postinstall) {
        Write-Step "Running pywin32 post-install..."
        & $PythonPath $postinstall -install 2>&1 | Out-Null
    }

    Write-Ok "pywin32 installed"
    return $true
}

function Set-ProgramDataAcls {
    Write-Step "Setting ACLs on $ProgramDataDir..."

    if (-not (Test-Path $ProgramDataDir)) {
        New-Item -ItemType Directory -Path $ProgramDataDir -Force | Out-Null
    }

    # Disable inheritance; remove all existing ACEs; then grant only
    # SYSTEM + Administrators. This prevents non-admin users from
    # reading the DPAPI-encrypted credential blob or tampering with
    # the config.
    try {
        $acl = Get-Acl $ProgramDataDir
        $acl.SetAccessRuleProtection($true, $false)   # protected, no inheritance

        # Clear existing rules
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

        # SYSTEM — full control
        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "NT AUTHORITY\SYSTEM",
            "FullControl",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )
        $acl.AddAccessRule($systemRule)

        # Administrators — full control
        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "BUILTIN\Administrators",
            "FullControl",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )
        $acl.AddAccessRule($adminRule)

        Set-Acl -Path $ProgramDataDir -AclObject $acl
        Write-Ok "ACLs set: SYSTEM + Administrators only"
    } catch {
        Write-Warn "ACL setup failed (service will still run, but directory is more permissive): $_"
    }
}

function Install-Service {
    Write-Banner "Installing CyberGuard AI Collector Service"

    Assert-Admin

    # ── Python check
    Write-Step "Checking Python..."
    $pyversion = Test-Python
    if (-not $pyversion) {
        Write-Fail "Python not found at '$PythonPath'"
        Write-Host "  Install Python 3.10+ and ensure 'python' is on PATH."
        exit 1
    }
    Write-Ok "$pyversion"

    # ── Script presence
    if (-not (Test-Path $MainScript)) {
        Write-Fail "main.py not found at $MainScript"
        exit 1
    }
    if (-not (Test-Path $ServiceScript)) {
        Write-Fail "service.py not found at $ServiceScript"
        exit 1
    }
    Write-Ok "Collector scripts found"

    # ── pywin32
    if (-not (Ensure-Pywin32)) {
        exit 1
    }

    # ── ProgramData directory + ACLs
    Set-ProgramDataAcls

    # ── Existing service check
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Warn "Service '$ServiceName' already exists"
        $answer = Read-Host "  Reinstall it? [y/N]"
        if ($answer -notmatch '^[yY]') {
            Write-Host "  Cancelled."
            exit 0
        }
        Write-Step "Stopping and removing existing service..."
        & $PythonPath $ServiceScript stop 2>&1 | Out-Null
        & $PythonPath $ServiceScript remove 2>&1 | Out-Null
        Start-Sleep -Seconds 2
    }

    # ── Install the service
    Write-Step "Installing service via pywin32..."
    & $PythonPath $ServiceScript --startup auto install 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Service install failed"
        exit 1
    }
    Write-Ok "Service installed"

    # ── Configure recovery (auto-restart on failure)
    Write-Step "Configuring failure recovery..."
    & sc.exe failure $ServiceName reset= $RecoveryResetSeconds actions= $RecoveryActions 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "Recovery configured: restart on failure (3 attempts, 60s intervals)"
    } else {
        Write-Warn "Could not configure failure recovery"
    }

    # ── Optional enrollment
    if ($EnrollmentToken -ne "") {
        Write-Step "Enrolling collector with provided token..."
        & $PythonPath $MainScript enroll $EnrollmentToken 2>&1 | Out-Host
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "Enrollment failed — run manually: python main.py enroll <token>"
            exit 1
        }
        Write-Ok "Enrolled successfully"
    } else {
        Write-Warn "No enrollment token provided."
        Write-Host "  Enroll manually after install:"
        Write-Host "    $PythonPath `"$MainScript`" enroll <token>"
    }

    # ── Start the service
    Write-Step "Starting service..."
    & $PythonPath $ServiceScript start 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Service start failed — check logs at $ProgramDataDir\logs\collector.log"
        exit 1
    }
    Start-Sleep -Seconds 2

    # ── Final status
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Host ""
        Write-Host "  ┌────────────────────────────────────────────────────┐" -ForegroundColor Green
        Write-Host "  │  Installation complete — service is RUNNING       │" -ForegroundColor Green
        Write-Host "  └────────────────────────────────────────────────────┘" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Service name:     $ServiceName"
        Write-Host "  Display name:     $ServiceDisplayName"
        Write-Host "  Status:           $($svc.Status)"
        Write-Host "  Config:           $ProgramDataDir\config.json"
        Write-Host "  Logs:             $ProgramDataDir\logs\collector.log"
        Write-Host ""
        Write-Host "  Manage with:"
        Write-Host "    .\install_service.ps1 -Action Status"
        Write-Host "    .\install_service.ps1 -Action Stop"
        Write-Host "    .\install_service.ps1 -Action Restart"
        Write-Host "    .\install_service.ps1 -Action Uninstall"
        Write-Host ""
    } else {
        Write-Fail "Service installed but not running"
        Write-Host "  Check Event Viewer or:"
        Write-Host "    Get-EventLog -LogName Application -Source $ServiceName -Newest 20"
        exit 1
    }
}


function Uninstall-Service {
    Write-Banner "Uninstalling CyberGuard AI Collector Service"
    Assert-Admin

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Warn "Service '$ServiceName' is not installed"
        return
    }

    Write-Step "Stopping service..."
    & $PythonPath $ServiceScript stop 2>&1 | Out-Null
    Start-Sleep -Seconds 2

    Write-Step "Removing service..."
    & $PythonPath $ServiceScript remove 2>&1 | Out-Host

    Start-Sleep -Seconds 1
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Fail "Service still present after remove — check permissions"
    } else {
        Write-Ok "Service removed"
    }

    Write-Host ""
    Write-Warn "Config and queue data preserved at: $ProgramDataDir"
    Write-Host "  To remove all data: Remove-Item -Recurse -Force `"$ProgramDataDir`""
    Write-Host ""
}


function Get-Status {
    Write-Banner "CyberGuard AI Collector — Status"

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Warn "Service is NOT installed"
        Write-Host "  Install with: .\install_service.ps1 -Action Install"
        return
    }

    Write-Host "  Service:  $($svc.Name)"
    Write-Host "  Display:  $($svc.DisplayName)"
    Write-Host "  Status:   $($svc.Status)"
    Write-Host "  StartType: $($svc.StartType)"
    Write-Host ""

    # Show config summary if possible
    if (Test-Path $ProgramDataDir) {
        Write-Host "  Data directory:  $ProgramDataDir"
        $configFile = Join-Path $ProgramDataDir "config.json"
        $logFile = Join-Path $ProgramDataDir "logs\collector.log"

        if (Test-Path $configFile) {
            Write-Host "  Config:          $configFile (exists)"
        } else {
            Write-Warn "Config not yet created (collector not enrolled)"
        }

        if (Test-Path $logFile) {
            $size = (Get-Item $logFile).Length
            Write-Host "  Log:             $logFile ($([math]::Round($size/1KB,1)) KB)"
            Write-Host ""
            Write-Host "  Last 5 log lines:"
            Get-Content $logFile -Tail 5 | ForEach-Object {
                Write-Host "    $_" -ForegroundColor DarkGray
            }
        }
    }
    Write-Host ""
}


function Start-Service {
    Write-Banner "Starting CyberGuard Collector Service"
    Assert-Admin
    & $PythonPath $ServiceScript start 2>&1 | Out-Host
    Start-Sleep -Seconds 2
    Get-Status
}


function Stop-Service {
    Write-Banner "Stopping CyberGuard Collector Service"
    Assert-Admin
    & $PythonPath $ServiceScript stop 2>&1 | Out-Host
    Start-Sleep -Seconds 2
    Get-Status
}


function Restart-Service {
    Write-Banner "Restarting CyberGuard Collector Service"
    Assert-Admin
    & $PythonPath $ServiceScript restart 2>&1 | Out-Host
    Start-Sleep -Seconds 2
    Get-Status
}


function Invoke-Enroll {
    Write-Banner "Enrolling CyberGuard Collector"
    Assert-Admin
    if ($EnrollmentToken -eq "") {
        $EnrollmentToken = Read-Host "  Paste enrollment token (cgc_...)"
    }
    if ($EnrollmentToken -eq "") {
        Write-Fail "No token provided"
        exit 1
    }
    & $PythonPath $MainScript enroll $EnrollmentToken 2>&1 | Out-Host
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "Enrolled successfully"
    } else {
        Write-Fail "Enrollment failed"
        exit 1
    }
}


# ============================================================================
# DISPATCH
# ============================================================================

try {
    switch ($Action) {
        "Install"   { Install-Service }
        "Uninstall" { Uninstall-Service }
        "Start"     { Start-Service }
        "Stop"      { Stop-Service }
        "Restart"   { Restart-Service }
        "Status"    { Get-Status }
        "Enroll"    { Invoke-Enroll }
    }
} catch {
    Write-Host ""
    Write-Fail "Unhandled error: $_"
    Write-Host ""
    Write-Host "  Full stack trace:"
    Write-Host "    $($_.ScriptStackTrace)" -ForegroundColor DarkGray
    exit 1
}