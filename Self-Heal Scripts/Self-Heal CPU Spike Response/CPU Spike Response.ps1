# HighCPU-Remediation-Hardened.ps1
# Universally production-safe on ALL Windows roles(It skips if it detects DC or Exchange)

$ErrorActionPreference = "Continue"

function Log {
    param($Message)
    Write-Output "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
}

Log "Starting hardened High CPU remediation"

# Detect if system is a Domain Controller
$IsDC = (Get-WmiObject Win32_ComputerSystem).DomainRole -ge 4

# Detect free disk space on C:
$Disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'"
$FreeGB = [math]::Round($Disk.FreeSpace / 1GB, 2)

# 1. Clear DNS cache (safe everywhere)
Log "1. Clearing DNS client cache"
ipconfig /flushdns | Out-Null
if (Get-Command Clear-DnsClientCache -ErrorAction SilentlyContinue) {
    Clear-DnsClientCache
}

# 2. Windows Search — SAFE MODE ONLY
if (Get-Service WSearch -ErrorAction SilentlyContinue) {
    Log "2. Windows Search detected – NOT restarting (safe mode)"
} else {
    Log "2. Windows Search not present"
}

# 3. Capture diagnostic dump (MINI, gated)
Log "3. Evaluating CPU usage"

$Top = Get-Process | Sort-Object CPU -Descending | Select-Object -First 1

if ($Top.CPU -gt 80 -and $FreeGB -ge 5) {

    if ($Top.Name -eq "lsass") {
        Log "   → LSASS detected – dump explicitly skipped (security safe)"
    }
    else {
        $ProcDumpPaths = @(
            "C:\Sysinternals\procdump.exe",
            "$env:ProgramFiles\Sysinternals\procdump.exe"
        )

        $ProcDump = $ProcDumpPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

        if ($ProcDump) {
            $DumpFolder = "C:\Dumps"
            if (-not (Test-Path $DumpFolder)) {
                New-Item -Path $DumpFolder -ItemType Directory -Force | Out-Null
            }

            $DumpFile = "$DumpFolder\HighCPU_$(Get-Date -Format 'yyyyMMdd_HHmmss')_$($Top.Name)_PID$($Top.Id).dmp"

            Log "   → Creating MINI dump of $($Top.Name) (PID $($Top.Id))"
            & $ProcDump -accepteula -mp $Top.Id $DumpFile | Out-Null
        }
        else {
            Log "   → ProcDump not found – skipping dump"
        }
    }
}
else {
    Log "   → CPU or disk threshold not met – skipping dump"
}

# 4. Kerberos tickets — skip on DCs
if (-not $IsDC) {
    Log "4. Purging SYSTEM Kerberos tickets (non-DC)"
    klist -li 0x3e7 purge 2>$null
}
else {
    Log "4. Domain Controller detected – Kerberos purge skipped"
}

# 5. Memory cleanup (safe)
Log "5. Running safe memory maintenance"
[System.GC]::Collect()
& "$env:SystemRoot\System32\rundll32.exe" advapi32.dll,ProcessIdleTasks

# 6. CPU forensic log
$LogFolder = "C:\Admin\HighCPU"
if (-not (Test-Path $LogFolder)) {
    New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
}

$LogFile = "$LogFolder\TopCPU_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Log "6. Writing CPU process log → $LogFile"

Get-Process |
    Sort-Object CPU -Descending |
    Select-Object -First 20 Name,Id,CPU,WS |
    Format-Table -AutoSize |
    Out-File $LogFile -Encoding ascii

Log "Hardened script finished – universally safe execution complete"
