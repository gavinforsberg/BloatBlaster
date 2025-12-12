#Requires -Version 5.1

[CmdletBinding()]
param (
    [Parameter()]
    [String]$AppsToRemove = "Amazon.com.Amazon, AmazonVideo.PrimeVideo, Clipchamp.Clipchamp, Disney.37853FC22B2CE, DropboxInc.Dropbox, Facebook.Facebook, Facebook.InstagramBeta, king.com.BubbleWitch3Saga, king.com.CandyCrushSaga, king.com.CandyCrushSodaSaga, LinkedInforWindows, 5A894077.McAfeeSecurity, 4DF9E0F8.Netflix, SpotifyAB.SpotifyMusic, BytedancePte.Ltd.TikTok, 5319275A.WhatsAppDesktop, Microsoft.XboxApp, Microsoft.XboxGameOverlay, Microsoft.XboxGamingOverlay, Microsoft.XboxSpeechToTextOverlay, Microsoft.Xbox.TCUI, Microsoft.XboxIdentityProvider",
    [Parameter()]
    [String]$OverrideWithCustomField
)

$global:ExitCode = 0
$AppList  = New-Object System.Collections.Generic.List[string]

# Tests if the user is running with elevated/admin privileges
function Test-IsElevated 
{
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Assert-Admin 
{
    if (-not (Test-IsElevated)) 
    {
        Write-Error "Access Denied. Please run with Administrator privileges."
        exit 1
    }
}

# Prompts the user and sets timezone to CST
function setTimeZone 
{
    # Prompt for time zone change 
    $response = Read-Host "Do you want to set the time zone to Central Standard Time (Y/N)?"

    if ($response -match '^[Yy]') 
    {
        # Sets time zone to Central
        Set-TimeZone -Id "Central Standard Time"
    } 
    else { Write-Warning "Timezone wasn't changed." }
}

# Copilot staying enabled but everything else seemed to work 
function Disable-NonMicrosoftStartupApps {
    Write-Host "`nDisabling non-Microsoft startup apps..."

    $startupKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )

    foreach ($key in $startupKeys) {
        if (Test-Path $key) {
            Get-ItemProperty -Path $key | ForEach-Object {
                foreach ($property in $_.PSObject.Properties) {
                    $name = $property.Name
                    $command = $property.Value

                    if ($command -and $command -notmatch "Microsoft|Defender|SecurityHealth") {
                        Write-Host "Disabling startup item: $name"

                        # Disable in StartupApproved (so it looks disabled in Task Manager)
                        $approvedKey = $key.Replace("Run","Explorer\StartupApproved\Run")
                        if (-not (Test-Path $approvedKey)) { New-Item -Path $approvedKey -Force | Out-Null }
                        $disabledValue = [byte[]](0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
                        Set-ItemProperty -Path $approvedKey -Name $name -Value $disabledValue

                        # Optional: actually remove the Run entry
                        # Remove-ItemProperty -Path $key -Name $name -ErrorAction SilentlyContinue
                    }
                }
            }
        }
    }

    # Startup folder cleanup
    $startupPaths = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )

    foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -Filter *.lnk | ForEach-Object {
                if ($_.Name -notmatch "Microsoft|Defender|SecurityHealth") {
                    Write-Host "Removing startup shortcut: $($_.Name)"
                    Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}

# Function to reset taskbar pins to only File Explorer and Firefox
function Reset-TaskbarPins 
{
    Write-Host "`nResetting taskbar..."

    # Kill Explorer
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue

    # Remove pinned items (shortcuts + registry state)
    $taskbarPath = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
    if (Test-Path $taskbarPath) 
    {
        Remove-Item "$taskbarPath\*" -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Recurse -ErrorAction SilentlyContinue

    # Restart Explorer
    Start-Process explorer.exe
    Start-Sleep -Seconds 5
}

# This doesn't seem to be doing anything when ran - NEEDS FIXING
# Function to remove bloatware apps
function Remove-Bloatware 
{
    foreach ($App in $AppList) 
    {
        $AppxPackage = Get-AppxPackage -AllUsers | Where-Object { $_.Name -Like "*$App*" } | Sort-Object Name -Unique
        $Provisioned = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*$App*" } | Sort-Object DisplayName -Unique

        if (-not $AppxPackage -and -not $Provisioned) 
        {
            Write-Warning "$App is not installed."
            continue
        }

        try 
        {
            if ($Provisioned) {
                Write-Verbose "Removing provisioned package $($Provisioned.DisplayName)..."
                $Provisioned | Remove-AppxProvisionedPackage -Online -AllUsers | Out-Null
            }
            if ($AppxPackage) {
                Write-Verbose "Removing app package $($AppxPackage.Name)..."
                $AppxPackage | Remove-AppxPackage -AllUsers | Out-Null
            }
            Write-Host "Removed: $App"
        }
        catch 
        {
            Write-Error "Failed to remove ${App}: $($_.Exception.Message)"
            $global:ExitCode = 1
        }
    }
}

# Function to install Firefox, Chrome, and Adobe Acrobat Reader using winget
function installApps 
{
    Write-Host "`n--- FULL WINGET SOURCE RESET ---" -ForegroundColor Cyan

    # Stop anything possibly locking the database
    taskkill /IM WinGet.exe /F 2>$null
    taskkill /IM AppInstaller.exe /F 2>$null

    # Remove corrupted WinGet database + indexes
    Remove-Item "$env:LOCALAPPDATA\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\*" -Recurse -Force -ErrorAction SilentlyContinue

    # Remove legacy WinGet sqlite DB (causes 100% of hash mismatch cases)
    Remove-Item "$env:LOCALAPPDATA\Microsoft\WinGet" -Recurse -Force -ErrorAction SilentlyContinue

    # Re-register App Installer (repairs WinGet integration)
    Add-AppxPackage -Register "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*\AppxManifest.xml" -DisableDevelopmentMode -ErrorAction SilentlyContinue

    # Reset winget sources
    winget source reset --force
    winget source update

    Write-Host "--- Winget source reset complete ---`n" -ForegroundColor Green


    Write-Host "`nStarting software installations via winget..."

    # Required apps (always installed)
    $AppsToInstall = @(
        @{ Name = "Google Chrome"; Id = "Google.Chrome" },
        @{ Name = "Mozilla Firefox"; Id = "Mozilla.Firefox" },
        @{ Name = "Adobe Acrobat Reader DC"; Id = "Adobe.Acrobat.Reader.64-bit" }
    )

    # Optional user-choice apps
    $OptionalSoftware = @(
        @{ Name = "7-Zip"; Id = "7zip.7zip" },
        @{ Name = "VLC Media Player"; Id = "VideoLAN.VLC" },
        @{ Name = "Webex"; Id = "Cisco.Webex" },
        @{ Name = "Zoom"; Id = "Zoom.Zoom" }
    )

    foreach ($app in $AppsToInstall) {
        Write-Host "`nInstalling REQUIRED app: $($app.Name)..."

        $result = Install-WingetPackage -PackageId $app.Id -DisplayName $app.Name

        # Special fallback for Chrome only
        if ($app.Id -eq "Google.Chrome" -and -not $result) {
            Install-ChromeFallback
        }
    }

    foreach ($opt in $OptionalSoftware) 
    {
        $answer = Read-Host "`nDo you want to install $($opt.Name) (Y/N)?"

        while($answer -notmatch '^(Y|y|N|n)$') 
        {
            Write-Host "Invalid response. Please enter Y or N."
            $answer = Read-Host "`nDo you want to install $($opt.Name) (Y/N)?"
            
            if ($answer -match '^(Y|y)$') 
            {
                Write-Host "`nInstalling optional app: $($opt.Name)..."
                Install-WingetPackage -PackageId $opt.Id -DisplayName $opt.Name | Out-Null
            }
            else { Write-Host "Skipping $($opt.Name)." }
        }
    }
}

function Install-WingetPackage 
{
    param
    (
        [string]$PackageId,
        [string]$DisplayName,
        [int]$MaxRetries = 5
    )

    Write-Host "`nInstalling $DisplayName..."

    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) 
    {

        Write-Host "Attempt $attempt of $MaxRetries..." -ForegroundColor Cyan

        $output = winget install `
            --id $PackageId `
            --source winget `
            --accept-package-agreements `
            --accept-source-agreements `
            --force `
            --disable-interactivity 2>&1

        $exitCode = $LASTEXITCODE

        # Detect HASH MISMATCH
        if ($output -match "Installer hash does not match") 
        {
            Write-Warning "HASH MISMATCH detected for $DisplayName."
            Write-Host "Waiting 5s before retry..."
            Start-Sleep 5
            continue
        }

        # Normal install success
        if ($exitCode -eq 0 -and $output -notmatch "No applicable installer") 
        {
            Write-Host "$DisplayName installed successfully." -ForegroundColor Green
            return $true
        }

        Write-Warning "Install attempt failed (ExitCode=$exitCode)"
        Write-Host "Output: $output"

        Start-Sleep 3
    }

    Write-Host "FAILED: $DisplayName could not be installed after $MaxRetries attempts." -ForegroundColor Red
    return $false
}

function Install-ChromeFallback 
{
    Write-Warning "Winget Chrome install repeatedly failed — using fallback direct MSI."

    $url = "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi"
    $path = "$env:TEMP\chrome.msi"

    Invoke-WebRequest -Uri $url -OutFile $path -UseBasicParsing

    Start-Process msiexec.exe -ArgumentList "/i `"$path`" /qn" -Wait

    Write-Host "Chrome installed via fallback."
}




# Function to clean up disk and create a restore point
function cleanRestore 
{
    # Run Disk Cleanup silently and wait
    Write-Host "Running Disk Cleanup (silent) and waiting for it to finish..."
    Start-Process cleanmgr.exe -ArgumentList "/sagerun:1" -Wait
    Write-Host "Disk Cleanup completed."

    # Create a System Restore Point
    Write-Host "Creating System Restore Point: 'Initial Setup'..."
    try 
    {
        # Enables system protection
        $drive = "C:"
        Enable-ComputerRestore -Drive $drive
        Start-Sleep -Seconds 5  # Gives it time to initialize 

        # Set sahdow storage size to 5% of total disk space 
        $psDrive = Get-PSDrive -Name $drive.TrimEnd(':')
        $totalSpace = $psDrive.Used + $psDrive.Free
        $maxSizeBytes = [math]::Round($totalSpace * 0.05)
        $maxSizeMB = [math]::Round($maxSizeBytes / 1MB)

        # Resize shadow storage
        vssadmin Resize ShadowStorage /For=$drive /On=$drive /MaxSize=${maxSizeMB}MB | Out-Null
        Start-Sleep -Seconds 5

        # Confirm if System Restore is active
        $restorePointList = Get-ComputerRestorePoint -ErrorAction SilentlyContinue

        if ($restorePointList) 
        {
            # Create a restore point
            Checkpoint-Computer -Description "Initial Setup" -RestorePointType "MODIFY_SETTINGS"
            Write-Host "System Restore Point 'Initial Setup' created successfully."
        } else 
        {
            Write-Warning "System Restore is not enabled or supported. Restore point not created."
        }
    }
    catch 
    {
        Write-Error "An error occurred while creating the restore point: $_"

    }

    # Run the restore point again to ensure it's created
    Checkpoint-Computer -Description "Initial Setup" -RestorePointType "MODIFY_SETTINGS"
}

# Function to set power plan to High Performance and adjust settings
function setPowerPlan
{
    # Sets power plan to high performance, disables Fast Startup, disables sleep, lock screen after 30 minutes
    # Attempts to set lid/power button/sleep button actions to "do nothing", but this funciton is not working as intended. 
    Write-Output "Switching to High performance power plan..."

    # Set High performance as active
    $activePlan = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
    powercfg.exe -setactive $activePlan

    # 1. Set Sleep to Never
    Write-Output "Disabling sleep..."
    powercfg.exe /change standby-timeout-ac 0
    powercfg.exe /change standby-timeout-dc 0

    # 2. Set Lock Screen after 30 minutes (1800 seconds)
    Write-Output "Set display shutoff to 30 minutes..."
    powercfg -change -monitor-timeout-ac 30
    powercfg -change -monitor-timeout-dc 30

    # 3. Disable Fast Startup
    Write-Output "Disabling Fast Startup..."
    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
    Set-ItemProperty -Path $regPath -Name "HiberbootEnabled" -Value 0

    # Apply the updated plan
    powercfg /setactive $activePlan
    Write-Output "Power configuration complete under High Performance plan."

    # Set lid close/button actions (Not working) 
    $do_nothing = 0
    powercfg /SETACVALUEINDEX $activePlan SUB_BUTTONS LIDACTION $do_nothing
    powercfg /SETDCVALUEINDEX $activePlan SUB_BUTTONS LIDACTION $do_nothing
    powercfg /SETACVALUEINDEX $activePlan SUB_BUTTONS PBUTTONACTION $do_nothing
    powercfg /SETDCVALUEINDEX $activePlan SUB_BUTTONS PBUTTONACTION $do_nothing
    powercfg /SETACVALUEINDEX $activePlan SUB_BUTTONS SBUTTONACTION $do_nothing
    powercfg /SETDCVALUEINDEX $activePlan SUB_BUTTONS SBUTTONACTION $do_nothing

    # Apply the updated plan
    powercfg /setactive $activePlan
    Write-Output "Power plan updated successfully."
}

function installOffice 
{
    # Prompt for Office 365 download and install
    $response = Read-Host "Do you want to install Microsoft 365 (Y/N)?"

    while($response -notmatch '^(Y|y|N|n)$') 
    {
        Write-Host "Invalid response. Please enter Y or N."
        $response = Read-Host "Do you want to install Microsoft 365 (Y/N)?"
        
        if($response -match '^(N|n)') 
        {
            Write-Host "Installation cancelled by user."
            return
        }
    }
    
    Write-Host "`nStarting Microsoft 365 download and installation..."

    # Path where Office Deployment Tool and XML live
    $officePath = "C:\Installs\Office 365 Business Premium - Offline"
    $setupExe   = Join-Path $officePath "setup.exe"
    $xmlFile    = Join-Path $officePath "General M365 Business.xml"

    $officePath = "C:\Installs\Office 365 Business Premium - Offline"
    Set-Location $officePath

        # Validate paths
    if (!(Test-Path $setupExe)) {
        Write-Error "setup.exe NOT FOUND at: $setupExe"
        return
    }
    if (!(Test-Path $xmlFile)) {
        Write-Error "XML NOT FOUND at: $xmlFile"
        return
    }

    Write-Host "Using XML:`n$xmlFile"

    # Step 1 – Download Office
    Start-Process -FilePath $setupExe `
        -ArgumentList "/download `"$xmlFile`"" `
        -Wait -NoNewWindow

    Write-Host "`nDownload complete."

    # Step 2 – Install Office
    Start-Process -FilePath $setupExe `
        -ArgumentList "/configure `"$xmlFile`"" `
        -Wait -NoNewWindow

    Write-Host "`nOffice installation completed." 
}


# Main script execution
Assert-Admin 
installApps
Remove-Bloatware
Disable-NonMicrosoftStartupApps
Reset-TaskbarPins
cleanRestore
setPowerPlan
setTimeZone
installOffice  
exit $global:ExitCode
