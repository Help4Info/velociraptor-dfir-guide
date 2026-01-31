# VQL Queries Reference

A collection of useful VQL (Velociraptor Query Language) queries for DFIR investigations.

## System Information

```sql
-- Basic system info
SELECT OS, Hostname, Fqdn, Architecture FROM info()

-- Detailed system info
SELECT * FROM info()
```

## File Search

```sql
-- Search for specific file
SELECT FullPath, Size, Mtime 
FROM glob(globs="C:/Users/**/credentials.txt")

-- Search by pattern
SELECT FullPath, Size, Mtime 
FROM glob(globs="C:/Users/**/*.txt")
WHERE Name =~ "password|credential|secret"

-- Recent files in Temp
SELECT Name, Size, Mtime
FROM glob(globs="C:/Users/*/AppData/Local/Temp/*")
ORDER BY Mtime DESC LIMIT 20
```

## Deleted Files Recovery (MFT Analysis)

```sql
-- Find deleted files
SELECT FileName, FullPath, InUse, Created, Modified, Size
FROM parse_mft(filename="C:/$MFT")
WHERE FileName =~ "notes|secret|password"
AND NOT InUse

-- All deleted files in specific folder
SELECT FileName, FullPath, Created, Modified
FROM parse_mft(filename="C:/$MFT")
WHERE FullPath =~ "Documents"
AND NOT InUse
```

## PowerShell Logs

```sql
-- PowerShell ScriptBlock logs
SELECT TimeCreated, EventID, Message
FROM parse_evtx(filename="C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx")
WHERE EventID = 4104

-- Search for specific command
SELECT TimeCreated, Message
FROM parse_evtx(filename="C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx")
WHERE Message =~ "DisableRealtimeMonitoring|Invoke-WebRequest|DownloadString"
```

## Process Analysis

```sql
-- List all processes
SELECT Name, Pid, PPid, Username, CommandLine, CreateTime
FROM pslist()

-- Suspicious processes
SELECT Name, Pid, CommandLine
FROM pslist()
WHERE CommandLine =~ "powershell|cmd|wscript|cscript"
```

## Network Connections

```sql
-- Active connections
SELECT Pid, Name, LocalAddress, RemoteAddress, Status
FROM netstat()

-- External connections only
SELECT Pid, Name, LocalAddress, RemoteAddress, Status
FROM netstat()
WHERE NOT RemoteAddress =~ "^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)"
```

## Registry Analysis

```sql
-- Run keys (persistence)
SELECT Name, FullPath, Data
FROM glob(globs="HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/Run/*")

-- User Run keys
SELECT Name, FullPath, Data
FROM glob(globs="HKEY_USERS/*/SOFTWARE/Microsoft/Windows/CurrentVersion/Run/*")

-- Services
SELECT Name, FullPath
FROM glob(globs="HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/*")
LIMIT 50
```

## Zone.Identifier (Downloaded Files)

```sql
-- Files with Zone.Identifier ADS
SELECT FullPath, Data
FROM Artifact.Windows.NTFS.ADS()
WHERE Name = "Zone.Identifier"

-- Specific folder
SELECT FullPath, Data
FROM Artifact.Windows.NTFS.ADS()
WHERE Name = "Zone.Identifier"
AND FullPath =~ "PerfLogs|Downloads|Temp"
```

## Remote Command Execution

```sql
-- Ping
SELECT * FROM execve(argv=["ping", "-n", "2", "192.168.1.1"])

-- ipconfig
SELECT * FROM execve(argv=["ipconfig", "/all"])

-- whoami
SELECT * FROM execve(argv=["whoami", "/all"])

-- List directory
SELECT * FROM execve(argv=["cmd", "/c", "dir", "C:\\Users"])
```

## Scheduled Tasks

```sql
-- List scheduled tasks
SELECT * FROM Artifact.Windows.System.TaskScheduler()

-- Suspicious tasks
SELECT Name, Path, Command, Arguments
FROM Artifact.Windows.System.TaskScheduler()
WHERE Command =~ "powershell|cmd|wscript"
```

## Browser History

```sql
-- Chrome history
SELECT * FROM Artifact.Windows.Applications.Chrome.History()

-- Edge history  
SELECT * FROM Artifact.Windows.Applications.Edge.History()
```
