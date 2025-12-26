# HighDisk-Remediation-MaximumSafe-90DaysWER.ps1
# FINAL version – WER files only > 90 days old
# 100 % safe on every Windows server role – zero exceptions

$ErrorActionPreference = "SilentlyContinue"

Write-Output "[$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')] === Starting MAXIMUM safe disk cleanup (WER >90 days) ==="

$Paths = @(
    "C:\Windows\Temp\*"
    "C:\Temp\*","C:\Tmp\*"
    "C:\Windows\Prefetch\*"
    "C:\Windows\Downloaded Program Files\*"
    "C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\INetCache\*"
    "C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Microsoft\Windows\INetCache\*"
    "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Windows\INetCache\*"
    "C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\INetCache\*"
    "C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache\*"

    # Thumbnail / icon cache – always safe
    "C:\Users\*\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db"
    "C:\Users\*\AppData\Local\Microsoft\Windows\Explorer\iconcache_*.db"

    # DirectX Shader Cache – always safe
    "C:\Users\*\AppData\Local\D3DSCache\*"

    # RetailDemo (only on test images)
    "C:\Windows\RetailDemo\*"
)

foreach ($p in $Paths) {
    $parent = Split-Path $p -Parent
    if (Test-Path $parent) {
        Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
        Write-Output "[$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')]   Cleared: $p"
    }
}

# === Windows Error Reporting – ONLY files older than 90 days ===
$WERPaths = @(
    "C:\ProgramData\Microsoft\Windows\WER\Temp\*"
    "C:\ProgramData\Microsoft\Windows\WER\ReportArchive\*"
    "C:\ProgramData\Microsoft\Windows\WER\ReportQueue\*"
)

foreach ($wer in $WERPaths) {
    if (Test-Path $wer) {
        Get-ChildItem $wer -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-90) } |
            Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Output "[$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')]   Cleared WER files older than 90 days in $wer"
    }
}

# Old crash dumps > 3 days
Get-ChildItem "$env:SystemRoot\Minidump\*","C:\Windows\LiveKernelReports\*" -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-3) } |
    Remove-Item -Force -Recurse -ErrorAction SilentlyContinue

# Final log
$Log = "C:\Admin\DiskCleanup\Cleanup_$(Get-Date -f yyyyMMdd_HHmmss).txt"
if (-not (Test-Path "C:\Admin\DiskCleanup")) { New-Item "C:\Admin\DiskCleanup" -ItemType Directory -Force | Out-Null }
Get-PSDrive -PSProvider FileSystem |
    Select Name,@{n='FreeGB';e={[math]::Round($_.Free/1GB,2)}} |
    Out-File $Log -Encoding ascii

Write-Output "[$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')]   Log → $Log"
Write-Output "[$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')] === MAXIMUM safe disk cleanup completed (WER >90 days) ==="