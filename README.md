# 🦖 Velociraptor DFIR - Practical Guide

A comprehensive guide for deploying Velociraptor and conducting digital forensics investigations on Windows endpoints.

![Velociraptor](https://img.shields.io/badge/Velociraptor-DFIR-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Installation](#installation)
- [Attack Simulation](#attack-simulation)
- [Investigation Guide](#investigation-guide)
- [VQL Queries](#vql-queries)
- [Resources](#resources)

## 🎯 Overview

This project demonstrates how to:
- Deploy a Velociraptor server and client infrastructure
- Simulate realistic attack scenarios (MITRE ATT&CK techniques)
- Investigate and detect malicious activities using VQL
- Recover deleted files and analyze forensic artifacts

## 🏗️ Architecture

```
┌─────────────────────┐         ┌─────────────────────┐
│  Velociraptor       │         │  Windows 11         │
│  Server             │◄───────►│  Client             │
│  (Ubuntu 24.04)     │  :8000  │  (Endpoint)         │
│  192.168.1.48       │         │  192.168.1.49       │
└─────────────────────┘         └─────────────────────┘
        │
        │ :8889 (GUI)
        ▼
   Web Console
```

| Component | OS | IP | Port |
|-----------|----|----|------|
| Server | Ubuntu 24.04 | 192.168.1.48 | 8000 (frontend), 8889 (GUI) |
| Client | Windows 11 | 192.168.1.49 | - |

## 🚀 Installation

### Server (Ubuntu)

```bash
# Download Velociraptor
wget https://github.com/Velocidex/velociraptor/releases/download/v0.7.1/velociraptor-v0.7.1-linux-amd64
chmod +x velociraptor-v0.7.1-linux-amd64
mv velociraptor-v0.7.1-linux-amd64 /usr/local/bin/velociraptor

# Generate configuration
velociraptor config generate -i

# Create admin user
velociraptor --config server.config.yaml user add admin --role administrator

# Start server
velociraptor --config server.config.yaml frontend -v
```

### Client (Windows)

```powershell
# Copy files to Windows
# - velociraptor.exe
# - client.config.yaml

# Install as service
velociraptor.exe --config client.config.yaml service install

# Start service
net start Velociraptor
```

## ⚔️ Attack Simulation

### Script 1: Basic Attack (BAT)

Simulates initial compromise techniques:

```batch
@echo off
:: T1562.001 - Disable Windows Defender
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"

:: T1105 - Simulated file download
echo Simulated download > %TEMP%\update.txt

:: T1003 - Credential harvesting
echo Login: admin > %APPDATA%\credentials.txt
echo Password: 123456 >> %APPDATA%\credentials.txt

:: T1070.004 - File deletion
del /Q "C:\Users\%USERNAME%\Documents\notes.txt"
```

### Script 2: Advanced Attack (PowerShell)

Simulates sophisticated attack techniques:

```powershell
# T1105 - Download offensive tools
$downloads = @(
    "https://live.sysinternals.com/PsExec64.exe",
    "https://live.sysinternals.com/procdump64.exe",
    "https://live.sysinternals.com/sdelete64.exe"
)

foreach ($url in $downloads){
    $file = Split-Path $Url -Leaf
    $dest = "C:\PerfLogs\" + $file
    Invoke-WebRequest -Uri $Url -OutFile $dest
    
    # Add Zone.Identifier ADS
    $ads = "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://malicious.com/"
    Set-Content -Path ($dest + ":Zone.Identifier") $ads
}

# T1036 - Masquerading (8.3 name obfuscation)
fsutil file setshortname C:\PerfLogs\psexec64.exe FAKE.EXE

# T1560 - Archive for exfiltration
Compress-Archive -Path C:\PerfLogs\* -DestinationPath C:\PerfLogs\exfil.zip

# T1070.004 - Cleanup
Remove-Item -Path C:\PerfLogs\*.zip, C:\PerfLogs\*.dmp, C:\PerfLogs\*.ps1
```

## 🔍 Investigation Guide

### Accessing the Console

1. Open browser: `https://192.168.1.48:8889`
2. Login with admin credentials
3. Search for client: `DESKTOP-7IE75MQ`

### Key Artifacts to Collect

| Artifact | Purpose |
|----------|---------|
| `Generic.Client.Info` | System information |
| `Windows.EventLogs.PowershellScriptblock` | PowerShell logs |
| `Windows.Forensics.FilenameSearch` | File search |
| `Windows.NTFS.MFT` | Deleted files recovery |
| `Windows.NTFS.ADS` | Alternate Data Streams |
| `Windows.Registry.Run` | Persistence mechanisms |

## 📝 VQL Queries

### System Information
```sql
SELECT OS, Hostname, Fqdn, Architecture FROM info()
```

### Search for Credentials File
```sql
SELECT FullPath, Size, Mtime 
FROM glob(globs="C:/Users/**/credentials.txt")
```

### Find Deleted Files (MFT)
```sql
SELECT FileName, FullPath, InUse, Created, Modified
FROM parse_mft(filename="C:/$MFT")
WHERE FileName =~ "notes.txt"
```

### Detect Defender Disabled
```sql
SELECT TimeCreated, EventID, Message
FROM parse_evtx(filename="C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx")
WHERE Message =~ "DisableRealtimeMonitoring"
```

### Files in Temp (Recent)
```sql
SELECT Name, Size, Mtime
FROM glob(globs="C:/Users/*/AppData/Local/Temp/*")
ORDER BY Mtime DESC LIMIT 10
```

### Execute Remote Command
```sql
SELECT * FROM execve(argv=["ping", "-n", "2", "192.168.1.48"])
```

### Registry Run Keys
```sql
SELECT Name, FullPath, Data
FROM glob(globs="HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/Run/*")
```

### Zone.Identifier (Downloaded Files)
```sql
SELECT FullPath, Data
FROM Artifact.Windows.NTFS.ADS()
WHERE Name = "Zone.Identifier"
```

## 📚 Resources

### Official Documentation
- [Velociraptor Docs](https://docs.velociraptor.app/)
- [VQL Reference](https://docs.velociraptor.app/vql_reference/)

### GitHub Repositories
- [Velociraptor](https://github.com/Velocidex/velociraptor)
- [Volatility3](https://github.com/volatilityfoundation/volatility3)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- [KAPE Files](https://github.com/EricZimmerman/KapeFiles)

### MITRE ATT&CK Techniques Used
| ID | Technique |
|----|-----------|
| T1562.001 | Impair Defenses: Disable or Modify Tools |
| T1105 | Ingress Tool Transfer |
| T1003 | Credential Dumping |
| T1036 | Masquerading |
| T1560 | Archive Collected Data |
| T1070.004 | File Deletion |

## 📄 License

MIT License - Feel free to use and modify for your own projects.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

**Author:** Security Professional  
**Tools:** Velociraptor, VQL, Windows Forensics
