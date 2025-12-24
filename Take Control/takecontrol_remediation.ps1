Set-ExecutionPolicy RemoteSigned
# Take Control Recovery Script
# N-able Technologies 2025
# Version: 4.4
#
# This script checks for the installation of the Take Control agent, verifies its signature, and re-installs it if necessary.
# The script is designed to be run with administrator privileges and can be forced to re-install the agent using command line arguments.

# Parameters:
# -Force: Forces the re-installation of the Take Control agent without changing it's configuration..
# -CleanInstall: Forces a clean installation of the Take Control agent, removing any existing installations and registry keys.
# -TargetVersion: Install the specified version of the Take Control N-central agent.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Re-installs the Take Control agent without changing it's configuration.")]
    [switch]$Force,    
    [Parameter(Mandatory = $false, HelpMessage = "Performs a clean install of the Take Control agent.")]
    [switch]$CleanInstall,
    [Parameter(Mandatory = $false, HelpMessage = "Checks the Take Control agent state without re-installing it.")]
    [switch]$CheckOnly,
    [Parameter(Mandatory = $false, HelpMessage = "Checks the Take Control agent state and re-installs it if necessary.")]
    [switch]$CheckAndReInstall,
    [Parameter(Mandatory = $false, HelpMessage = "Runs the script in silent mode without user interaction.")]
    [switch]$Silent,
    [Parameter(Mandatory = $false, HelpMessage = "Install the specified version of the Take Control N-central agent.")]
    [string]$TargetVersion
)

$ScriptVersion = "4.4"

$agentInstallPath = Join-Path -Path ${Env:ProgramFiles(x86)} -ChildPath "Beanywhere Support Express\GetSupportService_N-central"
$agentIniPath = Join-Path -Path ${Env:ProgramData} -ChildPath "GetSupportService_N-Central\BASupSrvc.ini"
$agentRegPath = "HKLM:\SOFTWARE\WOW6432Node\Multiplicar Negocios\BACE_N-Central\Settings"
$ncentralAgentBinaryPath = Join-Path -Path ${Env:ProgramFiles(x86)} -ChildPath "N-able Technologies\Windows Agent\bin"
$ncentralAgentConfigPath = Join-Path -Path ${Env:ProgramFiles(x86)} -ChildPath "N-able Technologies\Windows Agent\config\RCConfig.xml"

if ($env:PROCESSOR_ARCHITECTURE -eq "x86") {
    $agentInstallPath = Join-Path ${Env:ProgramFiles} "Beanywhere Support Express\GetSupportService_N-central"
    $agentRegPath = "HKLM:\SOFTWARE\Multiplicar Negocios\BACE_N-Central\Settings"
    $ncentralAgentBinaryPath = Join-Path ${Env:ProgramFiles} "N-able Technologies\Windows Agent\bin"
    $ncentralAgentConfigPath = Join-Path -Path ${Env:ProgramFiles} -ChildPath "N-able Technologies\Windows Agent\config\RCConfig.xml"
}

$AgentBinaryPath = Join-Path $agentInstallPath "BASupSrvc.exe"
$UpdaterBinaryPath = Join-Path $agentInstallPath "BASupSrvcUpdater.exe"
$AgentUninstallerPath = Join-Path $agentInstallPath "UnInstall.exe" 
$IncorrectServiceName = "BASupportExpressStandaloneService"
$AgentServiceName = "BASupportExpressStandaloneService_N_Central"
$UpdaterServiceName = "BASupportExpressSrvcUpdater_N_Central"
$InstallLockFilePath = Join-Path $agentInstallPath "__installing.lock"
$UnInstallLockFilePath = Join-Path $agentInstallPath "__uninstalling.lock"
$NCentralAgentRemoteControlDLLPath = Join-Path $ncentralAgentBinaryPath "RemoteControl.dll"

$RemoteJsonUrl = "https://swi-rc.cdn-sw.net/n-central/updates/json/TakeControlCheckAndReInstall.json"

if ($TargetVersion -and ($TargetVersion -notmatch '^\d+\.\d+\.[a-zA-Z0-9-_]+$')) {
    Write-Host "Invalid TargetVersion format. Please use X.Y.Z format."
    exit 1
}

if ($TargetVersion -ne "") {
    $RemoteJsonUrl = "https://swi-rc.cdn-sw.net/n-central/updates/json/TakeControlCheckAndReInstall_$TargetVersion.json"
}

$ExpectedSignedSubject = "CN=N-ABLE TECHNOLOGIES LTD, O=N-ABLE TECHNOLOGIES LTD, L=Dundee, C=GB"

$serviceNotRunningGuardInterval = 10
$lockFileAgeThresholdMinutes = 10

$LogFilePath = Join-Path $env:TEMP "TakeControlCheckAndReInstall.log"

function WriteLog {
    param (
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet("", "INFO", "WARN", "ERROR")]
        [string]$Level = "INFO",
        [Parameter(Mandatory = $false)]
        [string]$ForegroundColor = "White",
        [Parameter(Mandatory = $false)]
        [bool]$LogToConsole = !$Silent
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp][$Level] $Message"

    if ($LogToConsole) {
        
        # Write to console
        switch ($Level) {
            "INFO" { Write-Host $logEntry -ForegroundColor $ForegroundColor }
            "WARN" { Write-Host $logEntry -ForegroundColor DarkYellow }
            "ERROR" { Write-Host $logEntry -ForegroundColor DarkRed }
        }

    }

    # Write to log file
    try {
        Add-Content -Path $LogFilePath -Value $logEntry
    }
    catch {
        Write-Host "Failed to write to log file: $LogFilePath"
    }
}

function CheckFileSignature {
    param (
        [string]$FilePath
    )

    $result = $false

    try {

        $signature = Get-AuthenticodeSignature -FilePath $FilePath

        if ($signature.Status -eq "Valid") {

            if ($signature.SignerCertificate.Subject -eq $ExpectedSignedSubject) {
                $result = $true
            }
            else {
                WriteLog -Level "ERROR" -Message  "The file has a valid signature but is not signed by N-able."
            }

        }
        else {
            WriteLog -Level "ERROR" -Message  "The file does not have a valid signature."
        }

    }
    catch {
        WriteLog -Level "ERROR" -Message  "Error: Unable to retrieve signature information for the file."
    }

    return $result

}

function FetchTakeControlAgent {

    $validRequest = $false

    try {

        WriteLog -Message  "Fetching latest Take Control agent information..."
        $ProgressPreference = 'SilentlyContinue'
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        $jsonContent = Invoke-RestMethod -Uri $RemoteJsonUrl
        $validRequest = $true

    }
    catch {
        WriteLog -Level "ERROR" -Message  "Exception occurred while retrieving the remote json file. $_"
    }

    if ($validRequest) { 
      
        try {

            $Url = $jsonContent.url;
            $ExpectedHash = $jsonContent.expected_hash
            $ExpectedSize = $jsonContent.expected_size

        }
        catch {
            WriteLog -Level "ERROR" -Message  "Exception occurred while parsing the remote json file. $_"
            $validRequest = $false
        }
 
        if (($Url -ne "") -and ($ExpectedHash -ne "") -and ($validRequest)) {

            $uniqueId = [System.Guid]::NewGuid().ToString()

            $FilePath = Join-Path $env:TEMP "MSPA4NCentralInstaller-$uniqueId.exe"

            Remove-Item -Path $FilePath -ErrorAction SilentlyContinue

            WriteLog -Message  "Fetching Take Control agent binary from '$Url' to '$FilePath'."
            Invoke-WebRequest -Uri $Url -OutFile $FilePath

            WriteLog -Message  "Verifying the hash of the downloaded file."
            $ActualHash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash

            $ActualSize = (Get-Item -Path $FilePath).Length

            if ($ExpectedSize -ne $ActualSize) {
                WriteLog -Level "ERROR" -Message  "The file size does not match the expected size. Exiting..."
                return $null
            } 
            elseif ($ExpectedHash -ne $ActualHash) {
                WriteLog -Level "ERROR" -Message  "The file hash does not match the expected hash. Exiting..."
                return $null
            }
            elseif (-not (CheckFileSignature($FilePath))) {
                WriteLog -Level "ERROR" -Message  "The file signature is not valid. Exiting..."   
                return $null
            }
            else {
                WriteLog -Message  "The file size and hash match the expected values and the signature is correct."

                return $FilePath
            }

        }
        else {
            WriteLog -Level "ERROR" -Message  "Empty URL or expected_hash."
        }

    }
    else {
        WriteLog -Level "ERROR" -Message  "Unable to retrieve the remote json file. $_"
    }

    return $null

}

function ExecuteBinary {
    param (
        [string] $FileName,
        [string] $Parameters,
        [bool] $RemoveFile = $true
    )

    $exitCode = -1

    try {

        $proc = Start-Process -FilePath $FileName -ArgumentList $Parameters -Wait -PassThru -NoNewWindow -ErrorAction Stop
        $exitCode = $proc.ExitCode

    }
    catch {
        WriteLog -Level "ERROR" -Message  "Error executing file `$FileName: $_"
        $exitCode = 1
    }

    if ($RemoveFile) {
       
        try {
            if (Test-Path -Path $FileName) {
                WriteLog -Message  "Deleting file:`t$FileName"
                Remove-Item -Path $FileName
            }
        }
        catch {
            WriteLog -Level "WARN" -Message  "Error deleting file `$FileName`: $_"
        }  
    
    }

    return $exitCode

}

function RemoveAgentIniAndRegKeyIfPresent {

    if (Test-Path -Path $agentIniPath) {
        try {
            Remove-Item -Path $agentIniPath -Force -ErrorAction Stop
            WriteLog -Message  "Successfully deleted file:`t$agentIniPath"
        }
        catch {
            WriteLog -Level "WARN" -Message  "Error deleting file `$agentIniPath`: $_"
        }
    }

    if (Test-Path -Path $agentRegPath) {
        try {
            Remove-Item -Path $agentRegPath -Recurse -Force -ErrorAction Stop
            WriteLog -Message  "Successfully deleted registry key:`t$agentRegPath"
        }
        catch {
            WriteLog -Level "WARN" -Message  "Error deleting registry key `t$agentRegPath`: $_"
        }
    }

}

function Get-IniContent {
    param(
        [Parameter(Mandatory)][string]$Path
    )

    if (-not (Test-Path $Path)) {
        return $null
    }

    $ini = @{}
    $currentSection = ''

    foreach ($rawLine in Get-Content $Path) {
        $line = $rawLine.Trim()
        if ($line -match '^\s*;') {
            # skip comments
            continue
        }
        elseif ($line -match '^\[(.+)\]$') {
            # section header
            $currentSection = $Matches[1]
            if (-not $ini.ContainsKey($currentSection)) {
                $ini[$currentSection] = @{}
            }
        }
        elseif ($line -match '^(.*?)=(.*)$') {
            # key = value
            $key = $Matches[1].Trim()
            $value = $Matches[2].Trim()
            if ($currentSection) {
                $ini[$currentSection][$key] = $value
            }
            else {
                # keys before any section go at top level
                $ini[$key] = $value
            }
        }
    }

    return $ini
}

function IsLockFilePresent {
    param (
        [Parameter(Mandatory = $true)]
        [string]$LockFilePath,
        [Parameter(Mandatory = $false)]
        [int]$lockFileAgeThresholdMinutes = 10
    )

    $lockExists = $false

    if (Test-Path -Path $LockFilePath) {
        $installLockFileCreationTime = (Get-Item -Path $LockFilePath).CreationTime
        $ageMinutes = (Get-Date) - $installLockFileCreationTime
        if ($ageMinutes.TotalMinutes -lt $lockFileAgeThresholdMinutes) {
            WriteLog -Message  "The lock file '$LockFilePath' is newer than $lockFileAgeThresholdMinutes minutes. Exiting..."
            $lockExists = $true
        }
        else {
            WriteLog -Message  "The lock file '$LockFilePath' is older than $lockFileAgeThresholdMinutes minutes."
        }
    }

    return $lockExists

}

function WaitForLockFile {
    param (
        [Parameter(Mandatory = $true)]
        [string]$LockFilePath,
        [Parameter(Mandatory = $false)]
        [int]$WaitTimeInSeconds = 30
    )

    $endTime = (Get-Date).AddSeconds($WaitTimeInSeconds)

    while ((Get-Date) -lt $endTime) {
        if (IsLockFilePresent -LockFilePath $LockFilePath) {
            return $true
        }

        Start-Sleep -Seconds 5
    }

    return $false
}

function TerminateProcessList {
    param (
        [Parameter(Mandatory = $true)]
        [array]$ProcessList
    )

    foreach ($process in $ProcessList) {
        try {
            Get-Process -Name $process.Name -ErrorAction SilentlyContinue | Where-Object { $_.Path -ieq $process.Path } | Stop-Process -Force -ErrorAction SilentlyContinue
        }
        catch {
            WriteLog -Level "WARN" -Message  "Error terminating process '$($process.Name)': $_"
        }
    }

}

function CheckNCentralRemoteControlDLLVersion {
    param (
        [Parameter(Mandatory = $false)]
        [string]$NCentralAgentRemoteControlDLLPath = $NCentralAgentRemoteControlDLLPath
    )

    if (Test-Path -Path $NCentralAgentRemoteControlDLLPath) {
        $dllVersion = (Get-Item -Path $NCentralAgentRemoteControlDLLPath).VersionInfo.FileVersion
        WriteLog -Message  "N-central Agent Remote Control DLL version: $dllVersion"

        $minAffectedVersion = [Version]"2024.6.0.0"
        $maxAffectedVersion = [Version]"2024.6.0.22"

        if ($dllVersion -ge $minAffectedVersion -and $dllVersion -le $maxAffectedVersion) {
            WriteLog -Level "WARN" -Message  "The detected RemoteControl.DLL of the N-central Agent is known to be affected by a documented issue. Please refer to N-central's documentation to update it to the latest version."
        }

    }
    else {
        WriteLog -Level "WARN" -Message  "N-central Remote Control DLL not found at path: $NCentralAgentRemoteControlDLLPath"
    }

}

function IsNcentralRCConfigValid {

    if (Test-Path -Path $ncentralAgentConfigPath) {

        try {

            $xmlContent = [xml](Get-Content -Path $ncentralAgentConfigPath)

            if (($null -ne $xmlContent.RCConfig.mspa_server_unique_id) -and ($null -ne $xmlContent.RCConfig.mspa_secret_key) -and ($xmlContent.RCConfig.mspa_server_unique_id -ne "") -and ($xmlContent.RCConfig.mspa_secret_key -ne "") ) {
                return $true
            }
            else {
                WriteLog -Level "ERROR" -Message  "N-central Remote Control configuration not found or incomplete."
                return $false
            }

        }
        catch {
            WriteLog -Level "ERROR" -Message  "Error reading N-central Remote Control configuration file: $($_.Exception.Message)"
        }

    }
    else {
        WriteLog -Level "ERROR" -Message  "N-central Remote Control configuration file not found at path: $ncentralAgentConfigPath"
    }

    return $true

}


function  TestGatewayTCPConnection {
    param (
        [Parameter(Mandatory = $false)]
        [string]$GwTCPHost = "gw-tcp-test.global.mspa.n-able.com",
        [Parameter(Mandatory = $false)]
        [int]$GwTCPPort = 443,
        [Parameter(Mandatory = $false)]
        [int]$Timeout = 5000  # 5 seconds
    )

    $connectionSuccess = $false
    $command = "PING"

    try {

        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($GwTCPHost, $GwTCPPort)
        $networkStream = $tcpClient.GetStream()

        $networkStream.ReadTimeout = $Timeout
        $networkStream.WriteTimeout = $Timeout

        $reader = New-Object System.IO.StreamReader($networkStream)
        $writer = New-Object System.IO.StreamWriter($networkStream)
        $writer.AutoFlush = $true

        try {

            $writer.WriteLine($command)

            $response = $reader.ReadLine()

            if ($response -match "200 OK") {
                WriteLog -Message  "Take Control GW_TCP_$GwTCPPort is reachable. `t[200 - OK]" -ForegroundColor DarkGreen
                $connectionSuccess = $true
            }
            else {
                WriteLog -Level "WARN" -Message  "Take Control GW_TCP_$GwTCPPort is reachable with errors. `t[$response - UNEXPECTED RESPONSE]"
            }

        }
        catch {
            WriteLog -Level "WARN" -Message  "Take Control GW_TCP_$GwTCPPort is NOT reachable. `t[ERROR] - $($_.Exception.Message)"            
        }
        finally {
            $reader.Close()
            $writer.Close()
            $tcpClient.Close()
        }

    }
    catch {
        WriteLog -Level "WARN" -Message  "Take Control GW_TCP_$GwTCPPort is NOT reachable. `t[ERROR] - $($_.Exception.Message)"            
    }   

    return $connectionSuccess
    
}

function  TestGatewayTLSConnection {
    param (
        [Parameter(Mandatory = $false)]
        [string]$GwTLSHost = "gw-tls-test.global.mspa.n-able.com",
        [Parameter(Mandatory = $false)]
        [int]$GwTLSPort = 443,
        [Parameter(Mandatory = $false)]
        [int]$Timeout = 5000  # 5 seconds
    )

    $connectionSuccess = $false
    $command = "PING"

    try {

        $tcpClient = New-Object System.Net.Sockets.TcpClient($GwTLSHost, $GwTLSPort)
        $networkStream = $tcpClient.GetStream()

        $sslStream = New-Object System.Net.Security.SslStream($networkStream, $false, { $true })
        $sslStream.AuthenticateAsClient($GwTLSHost, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)

        $sslStream.ReadTimeout = $Timeout
        $sslStream.WriteTimeout = $Timeout

        $reader = New-Object System.IO.StreamReader($sslStream)
        $writer = New-Object System.IO.StreamWriter($sslStream)
        $writer.AutoFlush = $true

        try {
            
            $writer.WriteLine($command)

            $response = $reader.ReadLine()

            if ($response -match "200 OK") {
                WriteLog -Message  "Take Control GW_TLS_443 is reachable. `t[200 - OK]" -ForegroundColor DarkGreen
                $connectionSuccess = $true
            }
            else {
                WriteLog -Level "WARN" -Message  "Take Control GW_TLS_443 is reachable with errors. `t[$response - UNEXPECTED RESPONSE]"
            }

        }
        catch {
            WriteLog -Level "WARN" -Message  "Take Control GW_TLS_443 is NOT reachable. `t[ERROR] - $($_.Exception.Message)"            
        }
        finally {
            $reader.Close()
            $writer.Close()
            $sslStream.Close()
            $tcpClient.Close()
        }

    }
    catch {
        WriteLog -Level "WARN" -Message  "Take Control GW_TLS is NOT reachable. `t[ERROR] - $($_.Exception.Message)"            
    }

    return $connectionSuccess

}

function TestTakeControlInfrastructureConnection {

    $HTTPQueryList = @(
        @{ Region = "GLB"; URL = "https://comserver.global.mspa.n-able.com/comserver/echo.php?magicid=query_global"; ExpectedValue = "<response><echo>query_global</echo></response>" },
        @{ Region = "US1"; URL = "https://comserver.us1.mspa.n-able.com/comserver/echo.php?magicid=query_us1"; ExpectedValue = "<response><echo>query_us1</echo></response>" },
        @{ Region = "US2"; URL = "https://comserver.us2.mspa.n-able.com/comserver/echo.php?magicid=query_us2"; ExpectedValue = "<response><echo>query_us2</echo></response>" },
        @{ Region = "EU1"; URL = "https://comserver.eu1.mspa.n-able.com/comserver/echo.php?magicid=query_eu1"; ExpectedValue = "<response><echo>query_eu1</echo></response>" },
        @{ Region = "CDN"; URL = "https://swi-rc.cdn-sw.net/n-central/scripts/echo.xml"; ExpectedValue = "<response><echo>query_cdn</echo></response>" }
    )

    $connectionError = $false

    foreach ($httpQuery in $HTTPQueryList) {

        try {

            $ProgressPreference = 'SilentlyContinue'           
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $response = Invoke-WebRequest -Uri $httpQuery.URL -UseBasicParsing -ErrorAction Stop

            if ($response.Content -eq $httpQuery.expectedValue) {
                WriteLog -Message  "Take Control $($httpQuery.Region) is reachable. `t`t[$($response.StatusCode) - OK]" -ForegroundColor DarkGreen
            }
            else {
                WriteLog -Level "WARN" -Message  "Take Control $($httpQuery.Region) is reachable with errors. `t`t[$($response.StatusCode) - UNEXPECTED RESPONSE]"
            }

        }
        catch {
            WriteLog -Level "WARN" -Message  "Take Control $($httpQuery.Region) is NOT reachable. `t`t[ERROR] - $($_.Exception.Message)"            
            $connectionError = $true
        }

    }

    $gwTCPResult = TestGatewayTCPConnection
    $gwTCPResult3377 = TestGatewayTCPConnection -GwTCPPort 3377
    $gwTLSResult = TestGatewayTLSConnection

    if ((-not $gwTCPResult) -and (-not $gwTCPResult3377) -and (-not $gwTLSResult)) {
        $connectionError = $true
    }
    
    if ($connectionError -eq $true) {
        WriteLog -Level "WARN" -Message  "`nTake Control infrastructure may not be reachable. Please check this device's internet connection and firewall settings and make sure connections to the Take Control infrastructure are not being blocked. Please refer to the Take Control documentation for more information.`n"
    }
    
}

function CheckLockFileAndReInstall {
    param (
        [Parameter(Mandatory = $false)]
        [bool]$CleanInstall = $false
    )

    $lockExists = IsLockFilePresent -LockFilePath $InstallLockFilePath -lockFileAgeThresholdMinutes $lockFileAgeThresholdMinutes
    if ($lockExists -eq $true) {
        WriteLog -Message  "Installation lock file is present. Exiting..."
        Exit
    }

    $lockExists = IsLockFilePresent -LockFilePath $UnInstallLockFilePath -lockFileAgeThresholdMinutes $lockFileAgeThresholdMinutes
    if ($lockExists -eq $true) {
        WriteLog -Message  "Uninstallation lock file is present. Exiting..."
        Exit
    }

    WriteLog -Message  "Fetching Take Control agent location..."
    $agentFile = FetchTakeControlAgent
    $mspID = $null

    if ($null -ne $agentFile) {

        if ($CleanInstall -eq $true) {

            WriteLog -Message  "Reading ini file content..."
            $iniContent = Get-IniContent -Path $agentIniPath

            if ($null -eq $iniContent) {
                WriteLog -Message  "No ini file found..."
            }
            else {
                if ($iniContent.ContainsKey("Main") -and $iniContent["Main"].ContainsKey("MSPID")) {                 
                    $mspID = $iniContent["Main"]["MSPID"]
                    WriteLog -Message  "MSPID: $mspID"
                }
                else {
                    WriteLog -Level "WARN" -Message  "No MSPID found in ini file..."
                }
            }

            # Remove Take Control service with incorrect name if present
            if (ServiceExists -ServiceName $IncorrectServiceName) {

                if (CheckServiceExecutablePath -ServiceName $IncorrectServiceName -ExpectedPath $AgentBinaryPath) {

                    WriteLog -Message  "Found TC N-central agent with incorrect service name $IncorrectServiceName..."
                    $serviceStopped = StopService -ServiceName $IncorrectServiceName -WaitTimeInMinutes 3

                    if (-not $serviceStopped) {
                        WriteLog -Level "WARN" -Message  "Take Control service $IncorrectServiceName did not stop within the expected time."
                    } else {

                        WriteLog -Message  "Removing incorrect Take Control service $IncorrectServiceName..."
                        if (DeleteService -ServiceName $IncorrectServiceName) {
                            WriteLog -Message  "Successfully removed incorrect Take Control service $IncorrectServiceName."
                        }
                        else {
                            WriteLog -Level "WARN" -Message  "Error removing incorrect Take Control service $IncorrectServiceName."
                        }

                    }

                }
               
            }

            if (Test-Path $AgentUninstallerPath) {

                $lockExists = IsLockFilePresent -LockFilePath $UnInstallLockFilePath -lockFileAgeThresholdMinutes $lockFileAgeThresholdMinutes
                if ($lockExists -eq $true) {
                    WriteLog -Message  "Uninstallation lock file is present. Uninstallation is in progress... Exiting..."
                    Exit
                }

                WriteLog -Message  "Uninstalling previous agent..."

                $uninstallerArguments = "/S"
                $exitCode = ExecuteBinary -FileName $AgentUninstallerPath -Parameters $uninstallerArguments
                WriteLog -Message "Uninstaller finished with exit code $exitCode"

            }
            else {
                WriteLog -Level "WARN" -Message  "Take Control agent uninstaller not found..."
            }

            WriteLog -Message  "Making sure the Take Control agent is not running..."
            if (ServiceExists -ServiceName $AgentServiceName) {
                WriteLog -Message  "Stopping Take Control service  $AgentServiceName..."
                StopService -ServiceName $AgentServiceName -WaitTimeInMinutes 3
            }

            if (ServiceExists -ServiceName $UpdaterServiceName) {
                WriteLog -Message  "Stopping Take Control service  $UpdaterServiceName..."
                StopService -ServiceName $UpdaterServiceName -WaitTimeInMinutes 3
            }

            $processList = @(
                @{ Name = "BASupSrvc"; Path = $AgentBinaryPath },
                @{ Name = "BASupSrvcUpdater"; Path = $UpdaterBinaryPath }
            )

            WriteLog -Message  "Terminating any running services..."
            TerminateProcessList -ProcessList $processList

            WriteLog -Message  "Cleaning up previous installation..."
            RemoveAgentIniAndRegKeyIfPresent

        }
            
        $parameters = "/S /R /L"
        if (($null -ne $mspID) -and ($mspID -ne "")) {
            $parameters += " /MSPID $mspID"
        }

        WriteLog -Message  "Checking for the presence of install lock file..."
        $lockExists = WaitForLockFile -LockFilePath $InstallLockFilePath -WaitTimeInSeconds 45
        if ($lockExists -eq $true) {
            WriteLog -Message  "Installation lock file is present. Installation is already in progress... Exiting..."
            Exit
        }

        WriteLog -Message  "Starting Take Control agent installer"
        $exitCode = ExecuteBinary -FileName $agentFile -Parameters $parameters
        WriteLog -Message "Installer finished with exit code $exitCode"

    }
    else {
        WriteLog -Level "ERROR" -Message ("Unable to download Take Control agent file...")  
    }

    Exit

}

function ServiceExists {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )

    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if ($null -eq $service) {
        return $false
    } 

    return $true

}

function WaitForServiceState {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedState,

        [Parameter(Mandatory = $true)]
        [int]$WaitTimeInMinutes,

        [Parameter(Mandatory = $false)]
        [int]$ServicePollIntervalSeconds = 5
    )

    $endTime = (Get-Date).AddMinutes($WaitTimeInMinutes)

    while ((Get-Date) -lt $endTime) {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

        if (($null -ne $service) -and ($service.Status -eq $ExpectedState)) {
            WriteLog -Message  "Service '$ServiceName' is in the '$ExpectedState' state."
            return $true
        }

        Start-Sleep -Seconds $servicePollIntervalSeconds
    }

    WriteLog -Message  "Service '$ServiceName' did not reach the '$ExpectedState' state within the specified wait time."
    return $false

}

function WaitForServiceToStart {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,

        [Parameter(Mandatory = $true)]
        [int]$WaitTimeInMinutes
    )

    WaitForServiceState -ServiceName $ServiceName -ExpectedState "Running" -WaitTimeInMinutes $WaitTimeInMinutes

}

function StopService {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,

        [Parameter(Mandatory = $true)]
        [int]$WaitTimeInMinutes
    )

    if (-not (ServiceExists -ServiceName $ServiceName)) {
        WriteLog -Level "WARN" -Message  "Service '$ServiceName' does not exist."
        return $false
    }

    try {

        Stop-Service -Name $ServiceName -ErrorAction Stop

    }
    catch {
        WriteLog -Level "WARN" -Message  "Error stopping service '$ServiceName': $_"
        return $false
    }

    $retVal = WaitForServiceState -ServiceName $ServiceName -ExpectedState "Stopped" -WaitTimeInMinutes $WaitTimeInMinutes

    return $retVal
}

function DeleteService {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )

    if (-not (ServiceExists -ServiceName $ServiceName)) {
        WriteLog -Level "WARN" -Message  "Service '$ServiceName' does not exist."
        return $false
    }

    try {

        sc.exe delete $ServiceName | Out-Null

    }
    catch {
        WriteLog -Level "WARN" -Message  "Error deleting service '$ServiceName': $_"
        return $false
    }

    return $true

}

function CheckServiceExecutablePath {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedPath
    )

    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if ($null -eq $service) {
        return $false
    }

    try {

        $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
        $actualPath = $wmiService.PathName.Trim('"')

        if ($actualPath -ieq $ExpectedPath) {
            WriteLog -Message  "The service '$ServiceName' executable path matches the expected path."
            return $true
        }
        else {
            WriteLog -Level "ERROR" -Message  "The service '$ServiceName' executable path does not match the expected path."
            return $false
        }

    }
    catch {
        WriteLog -Level "ERROR" -Message  "Error retrieving service information for '$ServiceName': $_"
        return $false
    }

}

function CheckNCentralRCConfig {
    param (
        [Parameter(Mandatory = $false)]
        [string]$NCentralAgentRemoteControlDLLPath = $NCentralAgentRemoteControlDLLPath
    )

    if (Test-Path -Path $NCentralAgentRemoteControlDLLPath) {
        $iniContent = Get-IniContent -Path $NCentralAgentRemoteControlDLLPath

        if ($iniContent -and $iniContent.ContainsKey("RemoteControl")) {
            WriteLog -Message  "N-central Remote Control configuration found."
            return $true
        }
        else {
            WriteLog -Level "ERROR" -Message  "N-central Remote Control configuration not found."
            return $false
        }
    }
    else {
        WriteLog -Level "ERROR" -Message  "N-central Remote Control DLL not found at path: $NCentralAgentRemoteControlDLLPath"
        return $false
    }
}

## Perform Take Control agent state checks | return $true if the agent is in a good state, otherwise return $false
function IsTakeControlAgentInGoodState {
    param (
        [Parameter(Mandatory = $false)]
        [bool]$RestartServiceIfStopped = $false
    )

    WriteLog -Message "Checking Take Control agent state..."
    if ((-not (Test-Path -Path $AgentBinaryPath)) -or (-not (Test-Path -Path $UpdaterBinaryPath))) {

        WriteLog -Level ERROR -Message "Take Control agent binaries were not found..."
        return $false

    }
    else {

        WriteLog -Message "Take Control agent binaries were found..." -ForegroundColor DarkGreen

    }

    WriteLog -Message "Checking Take Control agent signatures..."
    if (-not (CheckFileSignature -FilePath $AgentBinaryPath)) {
        WriteLog -Level "ERROR" -Message  "Take Control agent binary signature is invalid."
        return $false
    }
    else {
        WriteLog -Message "Take Control agent binary signature is valid." -ForegroundColor DarkGreen
    }

    if (-not (CheckFileSignature -FilePath $UpdaterBinaryPath)) {
        WriteLog -Level "ERROR" -Message  "Take Control updater binary signature is invalid."
        return $false
    }
    else {
        WriteLog -Message "Take Control updater binary signature is valid." -ForegroundColor DarkGreen
    }

    $agentService = Get-Service -Name $AgentServiceName -ErrorAction SilentlyContinue
    if (-not $agentService) {

        WriteLog -Level ERROR -Message "The service '$AgentServiceName' is not registered..."
        return $false

    }
    else {

        WriteLog -Message "The service '$AgentServiceName' is registered..." -ForegroundColor DarkGreen

    }

    $updaterService = Get-Service -Name $UpdaterServiceName -ErrorAction SilentlyContinue
    if (-not $updaterService) {

        WriteLog -Level ERROR -Message "The service '$UpdaterServiceName' is not registered."
        return $false

    }
    else {

        WriteLog -Message  "The service '$UpdaterServiceName' is registered..." -ForegroundColor DarkGreen

    }

    if ($agentService.Status -ne "Running") {

        if ($RestartServiceIfStopped) {

            WriteLog -Message  "The service '$AgentServiceName' is not running... Waiting..."
            $agentServiceStarted = WaitForServiceToStart -ServiceName $AgentServiceName -WaitTimeInMinutes $serviceNotRunningGuardInterval
            if ($agentServiceStarted -eq $false) {
                WriteLog -Level ERROR -Message "The service '$AgentServiceName' is still not running... Re-Installing..."
                return $false
            }
            else {
                WriteLog -Message  "The service '$UpdaterServiceName' started... Skipping re-installation..."
            }

        }
        else {

            WriteLog -Level ERROR -Message  "The service '$AgentServiceName' is not running..."
            return $false

        }

    }
    else {

        WriteLog -Message  "The service '$AgentServiceName' is running..." -ForegroundColor DarkGreen

    }

    if ($updaterService.Status -ne "Running") {  

        if ($RestartServiceIfStopped) {

            WriteLog -Message  "The service '$UpdaterServiceName' is not running... Waiting..."
            $updaterServiceStarted = WaitForServiceToStart -ServiceName $UpdaterServiceName -WaitTimeInMinutes $serviceNotRunningGuardInterval
            if ($updaterServiceStarted -eq $false) {
                WriteLog -Message  "The service '$UpdaterServiceName' is still not running... Re-Installing..."
                return $false
            }
            else {
                WriteLog -Message  "The service '$UpdaterServiceName' started... Skipping re-installation..."
            }

        }
        else {

            WriteLog -Message  "The service '$UpdaterServiceName' is not running..."
            return $false

        }
 
    }
    else {

        WriteLog -Message  "The service '$UpdaterServiceName' is running..." -ForegroundColor DarkGreen

    }

    return $true

}

## Main Script Execution
WriteLog -Message  "Take Control Check and Re-Install Script v'$ScriptVersion'" -ForegroundColor DarkCyan
WriteLog -Message  "N-able Technologies 2025" -ForegroundColor DarkMagenta
WriteLog -Message  "------------------------------------------------------------"

if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    WriteLog -Message  "This script must be run with Administrator privileges."
    Exit
} 

WriteLog -Message  "Testing Take Control infrastructure connection..."
TestTakeControlInfrastructureConnection

WriteLog -Message  "Checking N-Central agent RemoteControl.dll version..."
CheckNCentralRemoteControlDLLVersion

if ($Force) {

    WriteLog -Message  "Forcing re-installation of Take Control..."
    CheckLockFileAndReInstall -CleanInstall $false    

}

if ($CleanInstall) {

    WriteLog -Message  "Performing clean installation of Take Control..."  
    CheckLockFileAndReInstall -CleanInstall $true

}

if ($CheckOnly) {

    WriteLog -Message  "Checking Take Control agent state without re-installing..."
    $isInGoodState = IsTakeControlAgentInGoodState -RestartServiceIfStopped $false
    if ($isInGoodState) {
        WriteLog -Message  "Take Control agent is in a good state."
        $isRCConfigValid = IsNcentralRCConfigValid
        if (-not $isRCConfigValid) {
            WriteLog -Level "ERROR" -Message  "N-central Remote Control configuration is not found or incomplete. Re-installing..."
            Exit 1
        }
        else {
            WriteLog -Message  "N-central Remote Control configuration is complete."
            Exit 0
        }
    }
    else {
        WriteLog -Level "ERROR" -Message  "Take Control agent is not in a good state. Please check the logs for more details."
        Exit 1
    }

}

if ($CheckAndReInstall) {

    WriteLog -Message  "Checking Take Control agent state and re-installing if necessary..."
    $agentInGoodState = IsTakeControlAgentInGoodState -RestartServiceIfStopped $false
    if (-not $agentInGoodState) {
        WriteLog -Level ERROR -Message  "Take Control agent is not in a good state. Re-installing..."
        CheckLockFileAndReInstall -CleanInstall $true
    }
    else {

        $isRCConfigValid = IsNcentralRCConfigValid
        if (-not $isRCConfigValid) {
            WriteLog -Level "ERROR" -Message  "N-central Remote Control configuration is not found or incomplete. Re-installing..."
            CheckLockFileAndReInstall -CleanInstall $true
        }
        else {
            WriteLog -Message  "N-central Remote Control configuration is found and complete."
        }

        WriteLog -Message  "Take Control agent is in a good state. No re-installation needed."
    }

    Exit 0

}
else {

    WriteLog -Message  "Checking Take Control agent state and installing if necessary..."

    $agentInGoodState = IsTakeControlAgentInGoodState -RestartServiceIfStopped $true
    if (-not $agentInGoodState) {

        WriteLog -Level ERROR -Message  "Take Control agent is not in a good state. Installing..."
        CheckLockFileAndReInstall -CleanInstall $false

    }
    else {

        $isRCConfigValid = IsNcentralRCConfigValid
        if (-not $isRCConfigValid) {
            WriteLog -Level "ERROR" -Message  "N-central Remote Control configuration is not found or incomplete. Re-installing..."
            CheckLockFileAndReInstall -CleanInstall $true
        }
        else {
            WriteLog -Message  "N-central Remote Control configuration is found and complete."
        }

        WriteLog -Message  "Take Control agent is in a good state. No re-installation needed."

    }
    
}

# SIG # Begin signature block
# MIIooQYJKoZIhvcNAQcCoIIokjCCKI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCClx8wSPA3BT90g
# Lv8SuUrwlI3PRHn5tmqtrF7o1kBS86CCIUwwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggawMIIEmKADAgECAhAIrUCyYNKcTJ9ezam9k67ZMA0GCSqG
# SIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0zNjA0MjgyMzU5NTlaMGkx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEzODQg
# MjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDVtC9C0Cit
# eLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0JAfhS0/TeEP0F9ce2vnS
# 1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJrQ5qZ8sU7H/Lvy0daE6ZM
# swEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhFLqGfLOEYwhrMxe6TSXBC
# Mo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+FLEikVoQ11vkunKoAFdE3
# /hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh3K3kGKDYwSNHR7OhD26j
# q22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJwZPt4bRc4G/rJvmM1bL5
# OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQayg9Rc9hUZTO1i4F4z8ujo
# 7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbIYViY9XwCFjyDKK05huzU
# tw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchApQfDVxW0mdmgRQRNYmtwm
# KwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRroOBl8ZhzNeDhFMJlP/2NP
# TLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IBWTCCAVUwEgYDVR0TAQH/
# BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+YXsIiGX0TkIwHwYDVR0j
# BBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8E
# PDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAEDMAgGBmeBDAEEATANBgkq
# hkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql+Eg08yy25nRm95RysQDK
# r2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFFUP2cvbaF4HZ+N3HLIvda
# qpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1hmYFW9snjdufE5BtfQ/g+
# lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3RywYFzzDaju4ImhvTnhOE7a
# brs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5UbdldAhQfQDN8A+KVssIhdXNS
# y0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw8MzK7/0pNVwfiThV9zeK
# iwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnPLqR0kq3bPKSchh/jwVYb
# KyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatEQOON8BUozu3xGFYHKi8Q
# xAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bnKD+sEq6lLyJsQfmCXBVm
# zGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQjiWQ1tygVQK+pKHJ6l/aCn
# HwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbqyK+p/pQd52MbOoZWeE4w
# gga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIx
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
# dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBH
# NDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVT
# MRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1
# c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0Zo
# dLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi
# 6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNg
# xVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiF
# cMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJ
# m/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvS
# GmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1
# ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9
# MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7
# Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bG
# RinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6
# X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAd
# BgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJx
# XWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUF
# BwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGln
# aWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJo
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNy
# bDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQEL
# BQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxj
# aaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0
# hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0
# F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnT
# mpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKf
# ZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzE
# wlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbh
# OhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOX
# gpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EO
# LLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wG
# WqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWg
# AwIBAgIQCoDvGEuN8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0
# IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0Ex
# MB4XDTI1MDYwNDAwMDAwMFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEy
# NTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3
# zBlCMGMyqJnfFNZx+wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8Tch
# TySA2R4QKpVD7dvNZh6wW2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWj
# FDYOzDi8SOhPUWlLnh00Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2Uo
# yrN0ijtUDVHRXdmncOOMA3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjP
# KHW5KqCvpSduSwhwUmotuQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KS
# uNLoZLc1Hf2JNMVL4Q1OpbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7w
# JNdoRORVbPR1VVnDuSeHVZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vW
# doUoHLWnqWU3dCCyFG1roSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOg
# rY7rlRyTlaCCfw7aSUROwnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K
# 096V1hE0yZIXe+giAwW00aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCf
# gPf8+3mnAgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zy
# Me39/dfzkXFjGVBDz2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezL
# TjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsG
# AQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5j
# b20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNy
# dDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGln
# aUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5j
# cmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEB
# CwUAA4ICAQBlKq3xHCcEua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZ
# D9gBq9fNaNmFj6Eh8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/
# ML9lFfim8/9yJmZSe2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu
# +WUqW4daIqToXFE/JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4o
# bEMnxYOX8VBRKe1uNnzQVTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2h
# ECZpqyU1d0IbX6Wq8/gVutDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasn
# M9AWcIQfVjnzrvwiCZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol
# /DJgddJ35XTxfUlQ+8Hggt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgY
# xQbV1S3CrWqZzBt1R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3oc
# CVccAvlKV9jEnstrniLvUxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcB
# ZU8atufk+EMF/cWuiC7POGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzCCB1owggVC
# oAMCAQICEA5Z6qrtsYFW9Bd58NpoF5owDQYJKoZIhvcNAQELBQAwaTELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2Vy
# dCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENB
# MTAeFw0yNDA0MTUwMDAwMDBaFw0yNzA0MTMyMzU5NTlaMGIxCzAJBgNVBAYTAkdC
# MQ8wDQYDVQQHEwZEdW5kZWUxIDAeBgNVBAoTF04tQUJMRSBURUNITk9MT0dJRVMg
# TFREMSAwHgYDVQQDExdOLUFCTEUgVEVDSE5PTE9HSUVTIExURDCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBANkCgchl3TyjsJqQ9KIALQmMrlfUkt1f4drA
# wPB3GgJDi/5W1QhUjP7XhDur+AZwpX6C5q5zaXc/f867V+OirVQq0EsoOE2Oc28F
# yw/CrZ8kutqXr6+XvjW6a5xrzIwtAAmrhRPbRSGqDsc0BydHY2gnPuynCWzsKuIC
# JHVkfslAhbPf2Y+NrrW1A8PFxBJ1z22fTrjvBs2BliEZ4EC/pwm6ctGu1Poltvu9
# JravomTzrz6DCicwL07kXZbB/iwIAp+hh7C/vrrSiKtx4OyvOcZdyDHFYB3OHfga
# QFcc6+hyRn5B4prtH1B9leEkw1Uj3h/vXlVsd/61hUQOM0O+JAzxw9rdfg1+pkpE
# +40d+yj2ts4hGNj2xnmSHmV3bsNlKIjV+koKW0OuVVoEtU3lgbCBk2jPnhwNLTkp
# ms0esPZsOvRn1m0hTv/H3Bi4Tye7feZ8ilvfhetWfAbBp/v2+fNaVxhkWHuvesHb
# xVgLavxStrsfBEs8Ce72p8A3wKJ51A3/sxpEprG+ChcTUYG1vfsyb4mbhTxKD2WN
# AQvI/vv2Dr6uIHuL+O+x7a2GYX/GktoBkfXGFZGbW3YfBHGu2kZCF9VUve6cWSbE
# 8VHEQgeLhIhpDZi2MQnUPk1iwr5mnfG4MZrV894S2VI5vFTwLHFjTibKGFXlk7Z9
# 5wrAWn/VAgMBAAGjggIDMIIB/zAfBgNVHSMEGDAWgBRoN+Drtjv4XxGG+/5hewiI
# ZfROQjAdBgNVHQ4EFgQUvBwz+I/zpwmiS1CFCA++Gvaej7owPgYDVR0gBDcwNTAz
# BgZngQwBBAEwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20v
# Q1BTMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzCBtQYDVR0f
# BIGtMIGqMFOgUaBPhk1odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNybDBToFGg
# T4ZNaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29k
# ZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcmwwgZQGCCsGAQUFBwEBBIGH
# MIGEMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXAYIKwYB
# BQUHMAKGUGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3J0MAkGA1UdEwQC
# MAAwDQYJKoZIhvcNAQELBQADggIBAAXejDEqFzr5NXtC5oCbJeUrSzsq+EmBdJnD
# r6t5fIHICw+ad34qFO4xb7H+Z4CgQIxo3mp0Cy9yWIVEsSwxLAyrCZdd2Cy4GZ9E
# uH/c/E7ZAIticRyDqh2Flghq9YHBXNhszcVfuLAkfWugrs3kZ8gxpQw/P0tCt5B5
# hzqulJXqyjTJJqv++sxSafvFCxnCrk/C174eaWnPwofZAzsbSPqhcNQ8yL/WNvDT
# xbcJVEgvG04LTYzCY8dR7DGxZ8Zaz3DkC65mdyIrP5lx4JKcXX1I2G15Mgk4HnCm
# 9b3uF5Z0yFUoebPkzqP/Fo5pPuyJj1SIu85hiXmD6Hkwu/UGCWpLxNtuw74/yBu5
# DKNACAFRNMLlveN7KHGW91WTO7yG8WkIr9vMYrrHLwIYcmsg8Jhjg+b06MUGztFh
# n7FSlVp90HZabnjzE+I6fqLHS4TFcVSRDkmDyvLzSDGQhIgqDPxdiYYHY9zkLA6Z
# OgzKO+N0WjM33IC/I8DdNixUXr7i/SehTOxlNBXlF1TWPZXNTNLHxAGL5K0wHcF1
# T4/KHredj+dgbIxu6O03X89cjqW0B1HNgGE6z5K0Fvl1oVkcdtudzB7fQZsc4ZaO
# SruSmoH4FeXL5VpLlxlDr1avk60YFtS/iyHPLOGT4FoQNRPv41UDfXv6YwraX8Js
# 3pb/5sxsMYIGqzCCBqcCAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgQ29kZSBT
# aWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExAhAOWeqq7bGBVvQXefDaaBea
# MA0GCWCGSAFlAwQCAQUAoIHWMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwG
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCEuhaO
# ZicN5AEgifS4O7DKFQRT78Ua/Jy7mNQ5LO1rbjBqBgorBgEEAYI3AgEMMVwwWqAo
# gCYATgAtAGEAYgBsAGUAIABUAGEAawBlACAAQwBvAG4AdAByAG8AbKEugCxodHRw
# czovL3d3dy5uLWFibGUuY29tL3Byb2R1Y3RzL3Rha2UtY29udHJvbDANBgkqhkiG
# 9w0BAQEFAASCAgB9c6lG1Z8ghzC6czBtLUR8fll040snPq48/381eT4NRsKXi+cv
# bI1Jju7ekFvhcFJFAYkK6bJKWc2KZtRVfhPBU07df7pn6MBGrnvXcZ/tYKcQMimJ
# 3QESifGML7enuQpNIJgh1IljCAG8nHJhXI+3PgK5/tB6r0LbdiKALdm1jRNTmMbn
# hTLLdmDoKdxu88icBHVZUtx9MYSEcOWjNWbBVhuYJ7xDWg3xI8lRDBVS55UNcWXe
# 1VRdyoCHQgBl4KRtNiImRc6TAknv6D7CKifABnaO0qSif/XEIF9PnjuV8dBP0aMA
# /KWCaef5x0T/+mSQPAcGd/IJL9fNSLMoNHKsJdxon6PIw0aj8Wk1Mc3kl9EqICyY
# bVeyQo3tT1Gx+TGHYICKDmRdb55X/lMYi8T8XVSMKk+37oREOgvSWM8BPr9WXUUM
# JuIX6EJUrCkGFom7gq48HJ01Ritxu+f03kbcYZQx+e79glGYuaBJYGLRC/O7LoiS
# o9uduQJQ+D9AS0VDi3pRK66RJM1YKOmhyHOrhw30eovy+HArjgaHK3i2oVtZZHA4
# O36BHg5c7ltvnNenkZvuqeMMbuF9ocXAqRIWAabFXq5MYVCk6R2/JCgapZ+3DobE
# o6SiEiOoZ476zyEVjxh243K1hKPKZ0Nwa3U4RxFgMJgRbNAmBff3DgtLxqGCAyYw
# ggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yNTExMzAxNTQ5MDRaMC8GCSqGSIb3DQEJBDEi
# BCBmRolmrmbusJD0I4tOV8HvpZaLjA7qQuTiCYfGkPRtITANBgkqhkiG9w0BAQEF
# AASCAgBg00BGy5OynD2TZ29maLo4MvCi3D8kmb8wgzmnJsu8jgBLCTZ+4m54MhFK
# wSmyHHigEe1pxgkBq8104KZcahTqG1zWDbgM5WWsA2owSbVXC+jkGx4D9Nm7pi3d
# akWkgkkFzC8WTHR6zJ1JivOsbkVUUSagU72QH94mRqqeyL2ZNJnnSHn9lPL7i3IR
# A6WK3R08YtE4c6CU5i6BO3cJZM4S1Fo8cz85bdehhYYxWweuflB43k/FB3gnumAX
# 8s/IwascDVw2MOjYTaDONJpEJivfM81dlciuIPtwt8K7iHM9p5r0GNrQLYBKQZEB
# 6R1muE1E2gGVYRXp33UFvVuNqY8EjOyCmCVDLU5FEghqii89kqAJuLpHNiop3t2m
# cpIGMO83laZEsOs5jumRoE8rkpZ1W2Wy1rEZMrRdvz8VeiyHZp6LIQQf5HW3S6JW
# 4fj2NJunR4aDqkK2kopM6iZprgIhfqjUiIbK/vqATSYHF+9c43zMzDyJCSpvKKH/
# Od7xEsgqKTj0OfP8aMazY1PAxICkdV5xLWgGoPoHpvPVHE/WIs2ykvJFezUNqVzO
# n8jlKVeRFU6kwySZcr78JILz7+gbYLR+zXm4Viqa65RRc0wUWvfAYJYI/7QG9OaH
# OxbPGIVRNae05Qji0NfMFgaxHRrqdx7VxRZOgWeQlEwjoixiog==
# SIG # End signature block
