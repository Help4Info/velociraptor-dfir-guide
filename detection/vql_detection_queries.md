# VQL Detection Queries - Malware Simulation

Requêtes VQL pour détecter les artefacts de simulation de malware.

## 1. Détecter les fichiers marqueurs de simulation

```sql
SELECT FullPath, Name, Size, Mtime,
       read_file(filename=FullPath, length=500) AS Content
FROM glob(globs="C:/Users/*/AppData/Local/Temp/*malware*simulation*.txt")
```

## 2. Détecter les scripts PowerShell suspects

```sql
SELECT TimeCreated, EventID, Message
FROM parse_evtx(
  filename="C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx"
)
WHERE Message =~ "SIMULATION|DisableRealtimeMonitoring|Invoke-WebRequest"
ORDER BY TimeCreated DESC
LIMIT 20
```

## 3. Détecter les outils Sysinternals (potentiellement malveillants)

```sql
SELECT FullPath, Name, Size, Mtime,
       hash(path=FullPath, hashselect="SHA256") AS SHA256
FROM glob(globs="C:/PerfLogs/*.exe")
WHERE Name =~ "psexec|procdump|sdelete"
```

## 4. Détecter les fichiers téléchargés depuis Internet (Zone.Identifier)

```sql
SELECT FullPath,
       parse_string_with_regex(
         string=read_file(filename=FullPath + ":Zone.Identifier", length=500),
         regex="ZoneId=(?P<ZoneId>\\d+)"
       ).ZoneId AS ZoneId,
       parse_string_with_regex(
         string=read_file(filename=FullPath + ":Zone.Identifier", length=500),
         regex="HostUrl=(?P<HostUrl>[^\\r\\n]+)"
       ).HostUrl AS SourceURL
FROM glob(globs="C:/PerfLogs/*.exe")
WHERE read_file(filename=FullPath + ":Zone.Identifier", length=10) != ""
```

## 5. Détecter la désactivation de Windows Defender

```sql
SELECT TimeCreated, Message
FROM parse_evtx(
  filename="C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx"
)
WHERE Message =~ "Set-MpPreference.*Disable"
ORDER BY TimeCreated DESC
```

## 6. Détecter les fichiers supprimés (MFT Analysis)

```sql
SELECT FileName, FullPath, InUse, Created, Modified, Size
FROM parse_mft(filename="C:/$MFT")
WHERE NOT InUse
AND FileName =~ "\\.(txt|ps1|bat|exe|zip|dmp)$"
AND Modified > timestamp(epoch=now() - 86400)
ORDER BY Modified DESC
LIMIT 50
```

## 7. Détecter les processus suspects

```sql
SELECT Name, Pid, PPid, Username, CommandLine, CreateTime
FROM pslist()
WHERE CommandLine =~ "powershell.*-enc|-ExecutionPolicy Bypass|cmd.*/c"
```

## 8. Hunt - Recherche globale d'IOCs

```sql
LET IOCs = ("psexec", "procdump", "mimikatz", "credentials.txt", "malware_simulation")

SELECT FullPath, Name, Size, Mtime
FROM glob(globs="C:/Users/**/*")
WHERE Name =~ join(array=IOCs, sep="|")
```
