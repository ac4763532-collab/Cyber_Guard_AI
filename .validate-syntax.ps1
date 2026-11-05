$files = @('start-cyberguard.ps1', 'stop-cyberguard.ps1', 'status-cyberguard.ps1')
$allOk = $true
foreach ($f in $files) {
    $path = Join-Path $PSScriptRoot $f
    try {
        $null = [scriptblock]::Create((Get-Content -Raw $path))
        Write-Host "OK: $f" -ForegroundColor Green
    } catch {
        Write-Host "SYNTAX ERROR in ${f}: $($_.Exception.Message)" -ForegroundColor Red
        $allOk = $false
    }
}
if (-not $allOk) { exit 1 }
exit 0
