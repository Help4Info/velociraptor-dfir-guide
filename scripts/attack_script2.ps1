# Attack Simulation Script - Educational Purpose
# MITRE ATT&CK Techniques Demonstrated

# T1105 - Ingress Tool Transfer
$downloads = @(
    "https://live.sysinternals.com/PsExec64.exe",
    "https://live.sysinternals.com/procdump64.exe",
    "https://live.sysinternals.com/sdelete64.exe"
)

foreach ($url in $downloads){
    $file = Split-Path $Url -Leaf
    $dest = "C:\PerfLogs\" + $file
    
    # Simulate Zone.Identifier (marks file as downloaded from internet)
    $ads = "[ZoneTransfer]`r`nZoneId=3`r`nReferrerUrl=https://malicious-site.com/`r`nHostUrl=https://malicious-site.com/" + $file
    
    Remove-Item -Path $dest -Force -ErrorAction SilentlyContinue
    Invoke-WebRequest -Uri $Url -OutFile $dest -UseBasicParsing
    Set-Content -Path ($dest + ":Zone.Identifier") $ads
}

# Create suspicious PowerShell script
echo "Write-Host 'Malicious payload executed'" > C:\PerfLogs\payload.ps1

# T1036 - Masquerading via 8.3 filename
fsutil file setshortname C:\PerfLogs\psexec64.exe FAKE.EXE

# T1003.001 - Process memory dump
calc.exe
Start-Sleep -Seconds 3
C:\PerfLogs\procdump64.exe -accepteula -ma Calculator C:\PerfLogs\calc.dmp
Stop-Process -Name Calculator -ErrorAction SilentlyContinue

# T1560 - Data staged for exfiltration
Compress-Archive -Path C:\PerfLogs\* -DestinationPath C:\PerfLogs\exfil.zip -CompressionLevel Fastest -Force

# T1070.004 - Indicator removal
Remove-Item -Path C:\PerfLogs\*.zip, C:\PerfLogs\*.dmp, C:\PerfLogs\*.ps1 -ErrorAction SilentlyContinue

Write-Host "Attack simulation completed"
