$node = Get-CimInstance Win32_Process -Filter "Name='node.exe'"
foreach ($p in $node) {
    Write-Host "PID $($p.ProcessId) parent $($p.ParentProcessId):"
    Write-Host "  $($p.CommandLine)"
}
Write-Host "---vite version---"
Set-Location "E:\CyberGuard_AI\frontend"
npx vite --version
