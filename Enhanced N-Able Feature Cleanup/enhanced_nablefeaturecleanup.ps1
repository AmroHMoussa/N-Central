Param (
    [string]$verbose = "Y"
)

# List of features to clean up
$featuresToClean = @(
    'PME',
    'Take Control',
    'AVD',
    'N-central Windows Agent',
    'Advanced Monitoring Agent'
)

function setupLogging() {
    $script:logFilePath = "C:\ProgramData\MspPlatform\Tech Tribes\N-able Feature Cleanup\debug.log"
    
    $script:logFolder = Split-Path $logFilePath
    $script:logFile = Split-Path $logFilePath -Leaf

    $logFolderExists = Test-Path $logFolder
    $logFileExists = Test-Path $logFilePath

    If ($logFolderExists -eq $false) {
        New-Item -ItemType "directory" -Path $logFolder | Out-Null
    }
    
    If ($logFileExists -eq $true) {
        Remove-Item $logFilePath -ErrorAction SilentlyContinue
        Start-Sleep 2
        New-Item -ItemType "file" -Path $logFolder -Name $logFile | Out-Null
    } Else {
        New-Item -ItemType "file" -Path $logFolder -Name $logFile | Out-Null
    }
    
    If (($logFolder -match '.+?\\$') -eq $false) {
        $script:logFolder = $logFolder + "\"
    }

    [float]$script:currentVersion = 1.06
    writeToLog I "Started processing N-ableFeatureCleanup.ps1."
    writeToLog I "Running script version: $currentVersion"
}

function validateUserInput() {
# Ensures the provided input from user is valid
    If ($verbose.ToLower() -eq "y") {
        $script:verboseMode = $true
        writeToLog V "You have defined to have the script output the verbose log entries."
    } Else {
        $script:verboseMode = $false
        writeToLog I "Will output logs in regular mode."
    }

    If (($null -eq $featureName) -or ($featureName -eq "")) {
        writeToLog F "No value has been given for the 'featureName' variable."
        writeToLog F "Failing script."
        Exit 1001
    }

    writeToLog V "Input Parameters have been successfully validated."
    writeToLog V ("Completed running {0} function." -f $MyInvocation.MyCommand)
}

function initialSetup() {
    writeToLog V ("Started running {0} function." -f $MyInvocation.MyCommand)

    $osVersion = (Get-WmiObject Win32_OperatingSystem).Caption
    If (($null -eq $osVersion) -or ($OSVersion -like "*OS - Alias not found*")) {
        $osVersion = (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue('ProductName')
    }
    writeToLog I "Detected Operating System:`r`n`t$OSVersion"
    
    $osArch = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
    writeToLog I "Detected Operating System Architecture: $osArch"

    $psVersion = $PSVersionTable.PSVersion
    writeToLog I "Detected PowerShell Version:`r`n`t$psVersion"

    $dotNetVersion = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name version -EA 0 | Where-Object { $_.PSChildName -Match '^(?!S)\p{L}'} | Select-Object PSChildName, version

    foreach ($i in $dotNetVersion) {
        writeToLog I ".NET Version: $($i.PSChildName) = $($i.Version)"
    }

    writeToLog I "Setting TLS to allow version 1.2."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]'Tls12'

    $tlsValue = [Net.ServicePointManager]::SecurityProtocol
    writeToLog V "Confirming TLS Value set:`r`n`t$tlsValue"
    
    writeToLog V ("Completed running {0} function." -f $MyInvocation.MyCommand)
}

function downloadScript() {
    writeToLog V ("Started running {0} function." -f $MyInvocation.MyCommand)

    switch -regex -Wildcard ($featureName) {
        "PME" {
            $featureToCleanup = "PME"
            $script:scriptName = "PMECleanup.ps1"
        }
        "Take Control" {
            $featureToCleanup = "Take Control"
            $script:scriptName = "TakeControlCleanup.ps1"
        }
        "AVD"  {
            $featureToCleanup = "AVD"
            $script:scriptName = "avdCleanup.ps1"
        }
        "N-central Windows Agent"  {
            $featureToCleanup = "NCAgent"
            $script:scriptName = "WindowsAgentCleanup.ps1"
        }
        "Advanced Monitoring Agent"  {
            $featureToCleanup = "N-sightRMM"
            $script:scriptName = "N-sightRMMCleanup.ps1"
        }
        Default {
            $featureToCleanup = $null
        }
    }

    writeToLog I "Feature Selected:`r`n`t$featureToCleanup"

    If ($null -eq $featureToCleanup) {
        writeToLog F "Given feature is not supported for removal - '$featureName'"
        Exit 1001
    }

    $script:scriptLocation = $logFolder + $scriptName

    If (!(Test-Path $scriptLocation)) {
        writeToLog W "The cleanup utility for $featureName was not found on the device. Skipping."
        return $false
    }

    writeToLog V ("Completed running {0} function." -f $MyInvocation.MyCommand)
    return $true
}

function triggerCleanup() {
    writeToLog V ("Started running {0} function." -f $MyInvocation.MyCommand)
    Invoke-Expression "& ""$scriptLocation"""
    writeToLog V ("Completed running {0} function." -f $MyInvocation.MyCommand)
}

function postRuntime() {
    try { Remove-Item "$logFolder*.ps1" -Force -ErrorAction SilentlyContinue } catch {}
}

function writeToLog($state, $message) {
    $script:timestamp = "[{0:dd/MM/yy} {0:HH:mm:ss}]" -f (Get-Date)

    switch -regex -Wildcard ($state) {
        "I" { $state="INFO"; $colour="Cyan" }
        "E" { $state="ERROR"; $colour="Red" }
        "W" { $state="WARNING"; $colour="Yellow" }
        "F" { $state="FAILURE"; $colour="Red" }
        "C" { $state="COMPLETE"; $colour="Green" }
        "V" { if ($verboseMode) { $state="VERBOSE"; $colour="Magenta" } else { return } }
        default { $state="INFO" }
    }

    Write-Host "$($timeStamp) - [$state]: $message" -ForegroundColor $colour
    Write-Output "$($timeStamp) - [$state]: $message" | Out-file $logFilePath -Append -ErrorAction SilentlyContinue
}

function main() {
    setupLogging

    foreach ($feature in $featuresToClean) {
        writeToLog I "Starting cleanup for feature: $feature"
        $script:featureName = $feature
        try {
            validateUserInput
            initialSetup
            $scriptExists = downloadScript

            if ($scriptExists) {
                triggerCleanup
                writeToLog C "Completed cleanup for feature: $feature"
            }
            postRuntime
        }
        catch {
            writeToLog E "Error occurred while processing feature: $feature"
            writeToLog E $_.Exception.Message
        }
    }

    writeToLog C "All features processed."
}

main
