# Script takes in 1 parameter "-install_arg"
# Values can be either "install" or "uninstall"
Param (
    [Parameter(Position=0, Mandatory=$true)]
    [string] $install_arg,
    [Parameter(Position=1, Mandatory=$false)]
    [string] $defender
)

# Clear N-Able Cache (only if NcentralAssetTool.exe is present, otherwise it will throw an error)
function ClearChache {
    $cache = Start-Process "C:\Program Files (x86)\N-able Technologies\Windows Agent\bin\NcentralAssetTool.exe" -ArgumentList "-t" -Wait -PassThru -WindowStyle Hidden;
    
    # If Start-Process returns 0 - action was successful
    if ($cache.ExitCode -eq 0){
        Write-Output "N-Able Cache was cleaned successfully";
    } else {
        Write-Output "ERROR: There was an issue clearing N-Able cache";
    }
}

# Install N-Able Agent
function Install_Nable {
    [CmdletBinding()]
    param ()

    try {
        if (-not (Test-Path "C:\temp")) {
            New-Item -ItemType Directory -Path "C:\temp"
        }

        $setupFile = "C:\temp\WindowsAgentSetup.exe";
        if ($defender){
            Write-Output "Using installer file from Defender folder."
            $setupFile = '"C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\WindowsAgentSetup.exe"';
        } else {
            Write-Output "Downloading N-able Windows Agent setup."
            $ProgressPreference = 'SilentlyContinue'
            
            Invoke-WebRequest -Uri https://xxx/download/current/winnt/N-central/WindowsAgentSetup.exe -OutFile $setupFile #Replace 'xxx' with the server address
            Write-Output "Download complete."
        }
        
        Write-Output "Running N-able Windows Agent setup."
        $arguments = @(
            '/s',
            '/v"',
            '/qn',
            'CUSTOMERID=xxx',#Replace with the customer ID
            'CUSTOMERSPECIFIC=1',
            'REGISTRATION_TOKEN=xxx', #Replace with the registration token
            'SERVERPROTOCOL=HTTPS',
            'SERVERADDRESS=xxx', #Replace with the server address
            'SERVERPORT=xxx"' #Replace with the port
        )

        Start-Process $setupFile -ArgumentList $arguments -Wait -WindowStyle Hidden
        Write-Output "Installation complete."

        if ($defender){
            Remove-Item -Path $setupFile;
            Write-Output "WindowsAgentSetup.exe installer file removed";
        }
    } catch {
        Write-Output "An error occurred while installing N-able Windows Agent: $_"
    }
}

# Uninstall N-Able Agent
function Uninstall_Nable {
    # Clear N-Able cache
    ClearChache;

    Write-Output "Uninstalling N-Able...";
    $uninstall_process = Uninstall-Package -ProviderName msi -Name "Windows Agent";

    # If uninstall_process is not null - action completed successfully
    if ($uninstall_process){
        Write-Output "N-Able uninstalled successfully";
    } else {
        Write-Output "ERROR: There was an issue uninstalling N-Able";
    }
}

# Check script flag
if ($install_arg -eq "uninstall"){
    Uninstall_Nable;
} else {
    Install_Nable;
}