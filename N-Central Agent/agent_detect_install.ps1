﻿#This Script is used to detect if the CMS Agent is already installed on the target computer, and installs it if not detected. It runs silently.

#Declaring Variables
$setupFile = '"C:\Temp\WindowsCMSAgentSetup.exe"';
$filePath = "C:\Program Files (x86)\N-able Technologies\Windows Agent\bin\agent.exe"
$downloadPath = "C:\Temp"
$fileExists = (Test-Path -Path $filePath -ErrorAction SilentlyContinue)

#Installation Arguments
 $arguments = @(
            '/s',
            '/v"',
            '/qn',
            'CUSTOMERID=xxx', #Replace with the customer's ID number
            'CUSTOMERSPECIFIC=1',
            'REGISTRATION_TOKEN=xxx', #Replace with the registration token
            'SERVERPROTOCOL=HTTPS',
            'SERVERADDRESS=xxx', #Replace with the server address
            'SERVERPORT=xxx"' #Replace with the server port
        )

#Check if the Agent has already been installed
if ($fileExists) {
    Write-Host "Checking for CMS Agent..."
    Write-Host "'$filePath' exists on this computer. CMS Agent Already installed."
    Exit 0
}

#If not already installed, downloads agent from GenieAll Server and installs it on local computer
Else {
    Write-Host "Checking for CMS Agent..."
    Write-Host "'$filePath' does not exist on this computer, installing CMS Agent."
    #Checks if 'C:\Temp' exists and creates it if it does not
    try {
        if (-not (Test-Path $downloadPath)) {
            New-Item -ItemType Directory -Path $downloadPath
        }
    #Downloads CMS Agent to the 'C:\Temp' folder
    Write-Output "Downloading N-able Windows Agent setup."
    Invoke-WebRequest -Uri https://xxx/download/current/winnt/N-central/WindowsAgentSetup.exe -OutFile $setupFile #Replace xxx with your server address
    #Installs CMS Agent
    Start-Process $setupFile -ArgumentList $arguments -Wait -WindowStyle Hidden
    Write-Output "Installation complete."
    }

#Error detection
    catch {
            Write-Output "An error occurred while installing the CMS Agent: $_"
        }

}