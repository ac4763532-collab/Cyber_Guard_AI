& "$env:WINDIR\System32\whoami.exe" /groups | Select-String -Pattern 'Event Log|BUILTIN|Administrators'
Write-Host '---user---'
& "$env:WINDIR\System32\whoami.exe"
