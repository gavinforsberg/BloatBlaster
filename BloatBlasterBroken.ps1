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

# SYNTAX ISSUES IDENTIFIED - NEEDS FIXING
# Function to reset taskbar pins to only File Explorer and Firefox
function Reset-TaskbarPins 
{
    Write-Host "`nResetting taskbar to only include File Explorer and Firefox..."

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

    # Re-pin File Explorer
    $explorerPath = "C:\Windows\explorer.exe"
    $shell = New-Object -ComObject Shell.Application
    $folder = $shell.Namespace((Split-Path $explorerPath))
    $item = $folder.ParseName((Split-Path $explorerPath -Leaf))
    $item.InvokeVerb("Pin to Taskbar")
    Write-Host "Pinned File Explorer."

    # Locate Firefox dynamically
    $firefoxPath = (Get-Command firefox.exe -ErrorAction SilentlyContinue).Source
    if ($firefoxPath) 
    {
        $folder = $shell.Namespace((Split-Path $firefoxPath))
        $item = $folder.ParseName((Split-Path $firefoxPath -Leaf))
        $item.InvokeVerb("Pin to Taskbar")
        Write-Host "Pinned Firefox."
    }
    else 
    {
        Write-Warning "Firefox not found — skipping pin."
    }

    # Proactively unpin Teams/Edge if they sneak in
    Start-Sleep -Seconds 5
    $unwantedPins = @("Teams.lnk","Microsoft Edge.lnk")
    foreach ($pin in $unwantedPins) 
    {
        $shortcut = Join-Path $taskbarPath $pin
        if (Test-Path $shortcut) 
        {
            Remove-Item $shortcut -Force -ErrorAction SilentlyContinue
            Write-Host "Removed unwanted pin: $pin"
        }
    }
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
    # Install common applications using winget
    Write-Host "`nStarting software installations via winget..."

    $AppsToInstall = @(
        @{ Name = "Google Chrome"; Id = "Google.Chrome" },
        @{ Name = "Mozilla Firefox"; Id = "Mozilla.Firefox" },
        @{ Name = "Adobe Acrobat Reader DC"; Id = "Adobe.Acrobat.Reader.64-bit" }
    )

    foreach ($app in $AppsToInstall) {
        Write-Host "`nAttempting to install $($app.Name)..."
        try {
            winget install --id $($app.Id) --silent --accept-package-agreements --accept-source-agreements
            Write-Host "Successfully installed $($app.Name)."
        }
        catch {
            Write-Error "Failed to install $($app.Name): $($_.Exception.Message)"
            $global:ExitCode = 1
        }
    }
}

# Function to clean up disk and create a restore point
function cleanRestore 
{
    #Runs Disk Cleanup and Creates a Restore Point
    # Step 1: Set all cleanup options
    #Function: Set all Disk Cleanup options for sageset:1
    #function Set-DiskCleanupOptions 

    # Step 2: Run Disk Cleanup silently and wait
    Write-Host "Running Disk Cleanup (silent) and waiting for it to finish..."
    Start-Process cleanmgr.exe -ArgumentList "/sagerun:1" -Wait
    Write-Host "Disk Cleanup completed."

    # Step 3: Create a System Restore Point

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

    if ($response -match '^[Yy]') 
    {
        Write-Host "Starting Microsoft 365 download and installation..."

        $officePath = "C:\Installs\Office 365 Business Premium - Offline"
        Set-Location $officePath

        # Step 1: Download Office
        Start-Process -FilePath ".\setup.exe" -ArgumentList @('/download', 'General M365 Business.xml') -Wait
        Write-Host "Download complete."

        # Step 2: Install Office
        Start-Process -FilePath ".\setup.exe" -ArgumentList @('/configure', 'General M365 Business.xml') -Wait
        Write-Host "Office installation completed."

        
        # if (!(Test-Path "$officePath\Office")) 
        # {
        #     Write-Warning "Office files not found. The download might have failed."
        #     exit 1
        # }
    
    }
    else 
    {
        Write-Host 'Installation cancelled by user.'
    }
}


# Main script execution
Assert-Admin 
installApps
Remove-Bloatware
Disable-NonMicrosoftStartupApps
Reset-TaskbarPins
cleanRestore
setTimeZone
installOffice  
exit $global:ExitCode
