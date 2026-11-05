Write-Host "Listeners on 5173:"
Get-NetTCPConnection -LocalPort 5173 -ErrorAction SilentlyContinue | Format-Table LocalAddress, LocalPort, State, OwningProcess

try {
    $r = Invoke-WebRequest -Uri 'http://127.0.0.1:5173/' -UseBasicParsing -TimeoutSec 5
    Write-Host "127.0.0.1 OK: $($r.StatusCode)"
} catch {
    Write-Host "127.0.0.1 FAILED: $($_.Exception.Message)"
}

try {
    $r = Invoke-WebRequest -Uri 'http://localhost:5173/' -UseBasicParsing -TimeoutSec 5
    Write-Host "localhost OK: $($r.StatusCode)"
} catch {
    Write-Host "localhost FAILED: $($_.Exception.Message)"
}
