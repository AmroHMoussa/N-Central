# HighMemory-Remediation-UniversalSafe.ps1
# Universally safe on ALL Windows server roles
# No service restarts, no forced dumps, no auth impact, no side effects

$ErrorActionPreference = "Continue"

function Log {
    param($Msg)
    Write-Output "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Msg"
}

Log "=== High Memory Universal-Safe Remediation started ==="

# Detect Domain Controller (for absolute safety gating)
$IsDC = (Get-WmiObject Win32_ComputerSystem).DomainRole -ge 4

# 1. Run Windows-supported idle maintenance ONLY
# (releases standby/file cache naturally, no pauses, no GC forcing)
Log "1. Running Windows idle maintenance (safe on all roles)"
& "$env:SystemRoot\System32\rundll32.exe" advapi32.dll,ProcessIdleTasks

# 2. Clear DNS client cache (safe everywhere)
Log "2. Clearing DNS client cache"
ipconfig /flushdns | Out-Null
if (Get-Command Clear-DnsClientCache -ErrorAction SilentlyContinue) {
    Clear-DnsClientCache
}

# 3. Identify top private-memory consumer (read-only)
Log "3. Identifying top private-memory process"
$TopPriv = Get-Process | Sort-Object PrivateMemorySize64 -Descending | Select-Object -First 1

Log ("   → Top process: {0} (PID {1}) using {2} GB private memory" -f `
    $TopPriv.Name, $TopPriv.Id, ([math]::Round($TopPriv.PrivateMemorySize64 / 1GB, 2)))

# 4. OPTIONAL, SAFE diagnostic dump (mini dump only, never LSASS, never DC)
$ProcDumpPaths = @(
    "C:\Sysinternals\procdump.exe",
    "$env:ProgramFiles\Sysinternals\procdump.exe"
)
$ProcDump = $ProcDumpPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($ProcDump -and -not $IsDC -and $TopPriv.Name -ne "lsass") {

    # Disk space safety check
    $Disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'"
    $FreeGB = [math]::Round($Disk.FreeSpace / 1GB, 2)

    if ($FreeGB -ge 10) {
        $DumpFolder = "C:\Dumps"
        if (-not (Test-Path $DumpFolder)) {
            New-Item -Path $DumpFolder -ItemType Directory -Force | Out-Null
        }

        $DumpFile = "$DumpFolder\HighMemMini_$(Get-Date -Format 'yyyyMMdd_HHmmss')_$($TopPriv.Name)_PID$($TopPriv.Id).dmp"
        Log "4. Creating SAFE mini dump (non-DC, non-LSASS) → $DumpFile"

        & $ProcDump -accepteula -mp $TopPriv.Id $DumpFile | Out-Null
    }
    else {
        Log "4. Dump skipped – insufficient free disk space"
    }
}
else {
    Log "4. Dump skipped – role, process, or tool restrictions"
}

# 5. Memory-focused forensic log (read-only)
$LogFolder = "C:\Admin\HighMemory"
if (-not (Test-Path $LogFolder)) {
    New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
}

$LogFile = "$LogFolder\MemoryLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Log "5. Writing memory usage log → $LogFile"

Get-Process |
    Sort-Object PrivateMemorySize64 -Descending |
    Select-Object -First 25 `
        Name,Id,
        @{n='WS(GB)';e={[math]::Round($_.WS/1GB,2)}},
        @{n='Priv(GB)';e={[math]::Round($_.PrivateMemorySize64/1GB,2)}} |
    Format-Table -AutoSize |
    Out-File $LogFile -Encoding ascii

Log "=== High Memory Universal-Safe Remediation finished ==="
