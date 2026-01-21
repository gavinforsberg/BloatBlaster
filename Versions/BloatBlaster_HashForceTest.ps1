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

# Function to install Chrome using Winget or MSI fallback
function Install-Chrome
{
    # Winget attempt
    $ChromeWinget = Start-Process -FilePath "winget" `
        -ArgumentList "install --exact --id Google.Chrome --silent --accept-source-agreements --accept-package-agreements" `
        -NoNewWindow -PassThru -Wait

    # Winget exit codes Chrome uses incorrectly but still means "Chrome is installed"
    $ChromeOkExitCodes = @(
        0,                # success
        -1978335189,      # Chrome "already installed" bug
        -1978335159,      # Chrome "already installed but no upgrade" bug
        -1978335192       # Chrome "no applicable installer" bug
    )

    if ($ChromeOkExitCodes -contains $ChromeWinget.ExitCode)
    {
        if (Test-ChromeInstalled) 
        {
            Write-Host "Chrome installed or already present. Winget considered successful." -ForegroundColor Green
            return
        }
    }

    # If winget *really* failed, detect hash mismatch
    Write-Warning "Winget exited with code $($ChromeWinget.ExitCode). Checking output..."

    $LastWingetOutput = winget install --exact --id Google.Chrome --silent --accept-source-agreements --accept-package-agreements 2>&1

    if ($LastWingetOutput -match "hash does not match") 
    {
        Write-Warning "`nHash mismatch detected. Ignoring the hash mismatch and trying again...`n"
        winget settings --enable InstallerHashOverride 
        winget install --exact --id Google.Chrome --silent --accept-source-agreements --accept-package-agreements --ignore-security-hash --force
    }
    else { Write-Error "Winget failed, but no hash mismatch detected." }

    winget settings --disable InstallerHashOverride 
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

    # Install common applications using winget
    Write-Host "`nStarting software installations via winget..."

    $AppsToInstall = @(
        @{ Name = "Mozilla Firefox"; Id = "Mozilla.Firefox" },
        @{ Name = "Adobe Acrobat Reader DC"; Id = "Adobe.Acrobat.Reader.64-bit" }
    )

    $OptionalSoftware = @(
        @{ Name = "Lenovo System Update"; Id = "Lenovo.SystemUpdate" },
        @{ Name = "7-Zip"; Id = "7zip.7zip" },
        @{ Name = "Webex"; Id = "Cisco.Webex" },
        @{ Name = "VLC Media Player"; Id = "VideoLAN.VLC" },
        @{ Name = "Webex"; Id = "Cisco.Webex" },
        @{ Name = "Zoom"; Id = "Zoom.Zoom" }
    )

    # Install Chrome (Winget Ignoring Security Hash)
    Install-Chrome

    foreach ($app in $AppsToInstall) 
    {
        Write-Host "`nAttempting to install $($app.Name)..."
        try 
        {
            winget install --exact --id $($app.Id) --silent --accept-package-agreements --accept-source-agreements
            Write-Host "Successfully installed $($app.Name)."
        }
        catch 
        {
            Write-Error "Failed to install $($app.Name): $($_.Exception.Message)"
            $global:ExitCode = 1
        }
    }

    foreach ($opt in $OptionalSoftware) 
    {
        $answer = Read-Host "`nDo you want to install $($opt.Name) (Y/N)?"

        # Validate input
        while($answer -notmatch '^[YyNn]$') 
        {
            Write-Host "Invalid response. Please enter Y or N." -ForegroundColor Red
            $answer = Read-Host "`nDo you want to install $($opt.Name) (Y/N)?"
        }

        # Process valid input
        if ($answer -match '^[Yy]$') 
        {
            try 
            {
                winget install --exact --id $($opt.Id) --silent --accept-package-agreements --accept-source-agreements
                Write-Host "$($opt.Name)." -ForegroundColor Green
            }
            catch 
            {
                Write-Error "Failed to install $($opt.Name): $($_.Exception.Message)"
                $global:ExitCode = 1
            }
        }
        else { Write-Host "Skipping $($opt.Name)." -ForegroundColor Gray }
    }
}

function installOffice 
{
    # Prompt for Office 365 download and install
    $response = Read-Host "`nDo you want to install Microsoft 365 (Y/N)?"

    while($response -notmatch '^(Y|y|N|n)$') 
    {
        Write-Host "Invalid response. Please enter Y or N."
        $response = Read-Host "`nDo you want to install Microsoft 365 (Y/N)?"
    }

    if($response -match '^(N|n)') 
    {
        Write-Host "Installation cancelled by user.`n"
        return
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

    Write-Host "`nOffice installation completed.`n"
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
            if ($Provisioned) 
            {
                Write-Verbose "Removing provisioned package $($Provisioned.DisplayName)..."
                $Provisioned | Remove-AppxProvisionedPackage -Online -AllUsers | Out-Null
            }
            if ($AppxPackage) 
            {
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

# Prompts the user and sets timezone to CST
function setTimeZone 
{
    # Prompt for time zone change 
    $response = Read-Host "`nDo you want to set the time zone to Central Standard Time (Y/N)?"

    while($response -notmatch '^(Y|y|N|n)$') 
    {
        Write-Host "Invalid response. Please enter Y or N."
        $response = Read-Host "`nDo you want to set the time zone to Central Standard Time (Y/N)?"
    }

    if($response -match '^(Y|y)') 
    {
        Write-Host "Setting timezone to Central Standard Time..."
        Set-TimeZone -Id "Central Standard Time"
        return
    }
    else { Write-Warning "Timezone wasn't changed." }
}

# Function to clean up disk and create a restore point
function cleanRestore 
{
    # Run Disk Cleanup silently and wait
    Write-Host "`nRunning Disk Cleanup (silent) and waiting for it to finish..."
    Start-Process cleanmgr.exe -ArgumentList "/sagerun:1" -Wait -NoNewWindow
    Write-Host "Disk Cleanup completed."

    # Create a System Restore Point
    Write-Host "`nSystem Restore Point: 'Initial Setup'..."
    try 
    {
        # Enables system protection
        $drive = "C:"
        Enable-ComputerRestore -Drive $drive
        Start-Sleep -Seconds 5  # Gives it time to initialize 

        # # Set shadow storage size to 5% of total disk space 
        # $psDrive = Get-PSDrive -Name $drive.TrimEnd(':')
        # $totalSpace = $psDrive.Used + $psDrive.Free
        # $maxSizeBytes = [math]::Round($totalSpace * 0.05)
        # $maxSizeMB = [math]::Round($maxSizeBytes / 1MB)

        # # Resize shadow storage
        # vssadmin Resize ShadowStorage /For=$drive /On=$drive /MaxSize=${maxSizeMB}MB | Out-Null
        # Start-Sleep -Seconds 5

        # Confirm if System Restore is active
        $restorePointList = Get-ComputerRestorePoint -ErrorAction SilentlyContinue

        if ($restorePointList) 
        {
            # Create a restore point
            Checkpoint-Computer -Description "Initial Setup" -RestorePointType "MODIFY_SETTINGS"
            Write-Host "System Restore Point 'Initial Setup' created successfully."
        } else 
        {
            # Write-Warning "System Restore is not enabled or supported. Restore point not created."
            Write-Warning "System Restore was not enabled. Trying again..."

            $drive = "C:"
            Enable-ComputerRestore -Drive $drive
            Start-Sleep -Seconds 5
        }

        $restorePointList = Get-ComputerRestorePoint -ErrorAction SilentlyContinue

                
        if ($restorePointList) 
        {
            # Create a restore point
            Checkpoint-Computer -Description "Initial Setup" -RestorePointType "MODIFY_SETTINGS"
            Write-Host "System Restore Point 'Initial Setup' created successfully."
        } else 
        {
            Write-Warning "System Restore failed again. Skipping restore point creation."
        }
    }
    catch 
    {
        Write-Error "An unexpected error occurred while creating the restore point: $_"

    }
}

# Function to set power plan to High Performance and adjust settings
function setPowerPlan
{
    # Sets power plan to high performance, disables Fast Startup, disables sleep, lock screen after 30 minutes
    # Attempts to set lid/power button/sleep button actions to "do nothing", but this funciton is not working as intended. 
    Write-Output "`nSwitching to High performance power plan..."

    # Set High performance as active
    $activePlan = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
    powercfg.exe -setactive $activePlan

    # 1. Set Sleep to Never
    Write-Output "Setting battery sleep to 30 minutes, AC sleep to never..."
    powercfg.exe /change standby-timeout-ac 0
    powercfg.exe /change standby-timeout-dc 30

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

    # Modern Standby breaks this:  
    # Button GUIDs
    $SUB_BUTTONS   = "4f971e89-eebd-4455-a8de-9e59040e7347"
    $LIDACTION     = "5ca83367-6e45-459f-a27b-476b1d01c936"
    $PBUTTONACTION = "7648efa3-dd9c-4e3e-b566-50f929386280"
    $SBUTTONACTION = "96996bc0-ad50-47ec-923b-6f41874dd9eb"

    $doNothing = 0

    # Lid
    powercfg /SETACVALUEINDEX $activePlan $SUB_BUTTONS $LIDACTION $doNothing
    powercfg /SETDCVALUEINDEX $activePlan $SUB_BUTTONS $LIDACTION $doNothing

    # Power button
    powercfg /SETACVALUEINDEX $activePlan $SUB_BUTTONS $PBUTTONACTION $doNothing
    powercfg /SETDCVALUEINDEX $activePlan $SUB_BUTTONS $PBUTTONACTION $doNothing

    # Sleep button (FIXED)
    powercfg /SETACVALUEINDEX $activePlan $SUB_BUTTONS $SBUTTONACTION $doNothing
    powercfg /SETDCVALUEINDEX $activePlan $SUB_BUTTONS $SBUTTONACTION $doNothing

    # Apply
    powercfg /SETACTIVE $activePlan

    # Safe verification
    # powercfg /QUERY $activePlan

    # Apply the updated plan
    powercfg /setactive $activePlan
    Write-Output "Power plan updated successfully."
}

# Disable specific startup apps: Teams, Edge, OneDrive, Webex, Copilot
function Disable-StartupApps 
{
    Write-Host "`nDisabling specific startup apps (Teams, Edge, OneDrive, Webex, Copilot)..." -ForegroundColor Cyan
    
    $appsToDisable = @(
        @{ Name = "Teams"; Patterns = @("Teams", "ms-teams", "msteams") },
        @{ Name = "Microsoft Edge"; Patterns = @("MicrosoftEdge", "msedge") },
        @{ Name = "OneDrive"; Patterns = @("OneDrive") },
        @{ Name = "Webex"; Patterns = @("Webex", "CiscoWebex") },
        @{ Name = "Copilot"; Patterns = @("Copilot", "Microsoft.Copilot") }
    )
    
    # Registry locations for startup items
    $startupKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )
    
    foreach ($app in $appsToDisable) {
        $foundAndDisabled = $false
        Write-Host "`n  Processing: $($app.Name)" -ForegroundColor Yellow
        
        # Check and REMOVE (not just disable) from registry Run keys
        foreach ($key in $startupKeys) {
            if (Test-Path $key) {
                $properties = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                if ($properties) {
                    foreach ($property in $properties.PSObject.Properties) {
                        $propName = $property.Name
                        $propValue = $property.Value
                        
                        # Skip system properties
                        if ($propName -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) {
                            continue
                        }
                        
                        # Check if this property matches any of our patterns
                        foreach ($pattern in $app.Patterns) {
                            if ($propName -like "*$pattern*" -or $propValue -like "*$pattern*") {
                                Write-Host "    Found in registry: $propName at $key" -ForegroundColor Magenta
                                
                                # First, disable in StartupApproved
                                $approvedKey = $key.Replace("Run", "Explorer\StartupApproved\Run")
                                if (-not (Test-Path $approvedKey)) {
                                    New-Item -Path $approvedKey -Force | Out-Null
                                }
                                
                                try {
                                    $disabledValue = [byte[]](0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
                                    Set-ItemProperty -Path $approvedKey -Name $propName -Value $disabledValue -ErrorAction Stop
                                    
                                    # Then REMOVE the entry entirely
                                    Remove-ItemProperty -Path $key -Name $propName -ErrorAction Stop
                                    Write-Host "    Removed: $propName" -ForegroundColor Green
                                    $foundAndDisabled = $true
                                }
                                catch {
                                    Write-Warning "    Could not remove ($propName): $($_.Exception.Message)"
                                }
                                
                                break
                            }
                        }
                    }
                }
            }
        }
        
        # Check and remove from startup folders
        $startupPaths = @(
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
        )
        
        foreach ($path in $startupPaths) {
            if (Test-Path $path) {
                Get-ChildItem -Path $path -Filter *.lnk -ErrorAction SilentlyContinue | ForEach-Object {
                    foreach ($pattern in $app.Patterns) {
                        if ($_.Name -like "*$pattern*") {
                            Write-Host "    Found shortcut: $($_.Name)" -ForegroundColor Magenta
                            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                            Write-Host "    Removed: $($_.Name)" -ForegroundColor Green
                            $foundAndDisabled = $true
                            Write-Host $foundAndDisabled
                        }
                    }
                }
            }
        }
        
        # Disable using Task Scheduler (common for OneDrive, Teams)
        foreach ($pattern in $app.Patterns) {
            try {
                $tasks = Get-ScheduledTask -TaskName "*$pattern*" -ErrorAction SilentlyContinue
                foreach ($task in $tasks) {
                    if ($task.State -ne "Disabled") {
                        Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop | Out-Null
                        Write-Host "    Disabled scheduled task: $($task.TaskName)" -ForegroundColor Green
                        $foundAndDisabled = $true
                    }
                }
            }
            catch {
                # Silently continue if no tasks found
            }
        }
        
        if (-not $foundAndDisabled) {
            Write-Host "Not found or already disabled" -ForegroundColor Gray
        }
    }
    
    # ===== TEAMS SPECIFIC =====
    Write-Host "`n  Applying comprehensive Teams restrictions..." -ForegroundColor Yellow
    
    # Disable Teams auto-start for current user
    $teamsConfigPath = "$env:APPDATA\Microsoft\Teams\desktop-config.json"
    if (Test-Path $teamsConfigPath) {
        try {
            $teamsConfig = Get-Content $teamsConfigPath -Raw | ConvertFrom-Json
            $teamsConfig.appPreferenceSettings.openAtLogin = $false
            $teamsConfig.appPreferenceSettings.runningOnClose = $false
            $teamsConfig | ConvertTo-Json -Depth 10 | Set-Content $teamsConfigPath
            Write-Host "    Teams auto-start disabled in config" -ForegroundColor Green
        }
        catch {
            Write-Warning "    Could not modify Teams config: $($_.Exception.Message)"
        }
    }
    
    # Remove all Teams startup registry entries (check multiple locations)
    $teamsStartupLocations = @(
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"; Name = "com.squirrel.Teams.Teams" },
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"; Name = "Teams" },
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"; Name = "com.squirrel.Teams.Teams" },
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"; Name = "Teams" }
    )
    
    foreach ($location in $teamsStartupLocations) {
        if (Test-Path $location.Path) {
            if (Get-ItemProperty -Path $location.Path -Name $location.Name -ErrorAction SilentlyContinue) {
                Remove-ItemProperty -Path $location.Path -Name $location.Name -ErrorAction SilentlyContinue
                Write-Host "    Removed Teams from: $($location.Path)\$($location.Name)" -ForegroundColor Green
            }
        }
    }
    
    # Disable Teams via Group Policy registry
    $teamsPolicyKey = "HKCU:\Software\Policies\Microsoft\Office\16.0\common\officeupdate"
    if (-not (Test-Path $teamsPolicyKey)) {
        New-Item -Path $teamsPolicyKey -Force | Out-Null
    }
    Set-ItemProperty -Path $teamsPolicyKey -Name "preventteamsinstall" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Write-Host "    Teams prevented via policy registry" -ForegroundColor Green
    
    # ===== COPILOT SPECIFIC =====
    Write-Host "`n  Applying comprehensive Copilot restrictions..." -ForegroundColor Yellow
    
    # Disable Copilot via multiple registry locations
    $copilotKeys = @(
        @{ Path = "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot"; Name = "TurnOffWindowsCopilot"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"; Name = "TurnOffWindowsCopilot"; Value = 1 },
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "ShowCopilotButton"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "CopilotPageContext"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "HubsSidebarEnabled"; Value = 0 }
    )
    
    foreach ($key in $copilotKeys) {
        try {
            if (-not (Test-Path $key.Path)) {
                New-Item -Path $key.Path -Force | Out-Null
            }
            Set-ItemProperty -Path $key.Path -Name $key.Name -Value $key.Value -Type DWord -ErrorAction Stop
            Write-Host "    Set $($key.Path)\$($key.Name) = $($key.Value)" -ForegroundColor Green
        }
        catch {
            Write-Warning "    Could not set $($key.Path)\$($key.Name): $($_.Exception.Message)"
        }
    }
    
    # Remove Copilot from startup
    $copilotStartupLocations = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    )
    
    foreach ($loc in $copilotStartupLocations) {
        if (Test-Path $loc) {
            Get-ItemProperty -Path $loc -ErrorAction SilentlyContinue | 
                ForEach-Object {
                    $_.PSObject.Properties | Where-Object { 
                        $_.Name -notmatch "^PS" -and $_.Value -match "Copilot" 
                    } | ForEach-Object {
                        Remove-ItemProperty -Path $loc -Name $_.Name -ErrorAction SilentlyContinue
                        Write-Host "    Removed Copilot from: $loc\$($_.Name)" -ForegroundColor Green
                    }
                }
        }
    }
    
    # ===== ONEDRIVE =====
    Write-Host "`n  Applying additional OneDrive restrictions..." -ForegroundColor Yellow
    try {
        # Remove OneDrive from Run keys
        $oneDriveRunKeys = @(
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
        )
        
        foreach ($key in $oneDriveRunKeys) {
            if (Test-Path $key) {
                if (Get-ItemProperty -Path $key -Name "OneDrive" -ErrorAction SilentlyContinue) {
                    Remove-ItemProperty -Path $key -Name "OneDrive" -ErrorAction SilentlyContinue
                    Write-Host "    Removed OneDrive from: $key" -ForegroundColor Green
                }
            }
        }
    }
    catch {
        Write-Warning "    Could not disable OneDrive via registry: $($_.Exception.Message)"
    }
    
    # ===== EDGE =====
    Write-Host "`n  Preventing Microsoft Edge background processes..." -ForegroundColor Yellow
    try {
        $edgeKeys = @(
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "BackgroundModeEnabled"; Value = 0 },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "StartupBoostEnabled"; Value = 0 },
            @{ Path = "HKCU:\Software\Policies\Microsoft\Edge"; Name = "BackgroundModeEnabled"; Value = 0 },
            @{ Path = "HKCU:\Software\Policies\Microsoft\Edge"; Name = "StartupBoostEnabled"; Value = 0 }
        )
        
        foreach ($key in $edgeKeys) {
            if (-not (Test-Path $key.Path)) {
                New-Item -Path $key.Path -Force | Out-Null
            }
            Set-ItemProperty -Path $key.Path -Name $key.Name -Value $key.Value -Type DWord -ErrorAction Stop
        }
        Write-Host "    Edge background mode disabled" -ForegroundColor Green
    }
    catch {
        Write-Warning "    Could not disable Edge background mode: $($_.Exception.Message)"
    }
    
    Write-Host "`nSpecific startup apps disabled successfully." -ForegroundColor Green
}
function Test-AgentsInstalled 
{
    param([string]$MsiPath)

    $productCode = (Get-WmiObject Win32_Product |
        Where-Object { $_.LocalPackage -eq $MsiPath }).IdentifyingNumber

    return [bool]$productCode
}

function InstallAgents
{
    if(Test-AgentsInstalled) 
    {
        Write-Output "Management agents already installed. Skipping installation."
        return
    }
    else
    {
        Write-Output "Installing management agents..."

        $scriptRoot = if ($PSScriptRoot) {
            $PSScriptRoot
        } else {
            Get-Location 
        }

        $agentsPath = Join-Path $scriptRoot "agents"

        if (-not (Test-Path $agentsPath)) {
            Write-Warning "Agents folder not found at $agentsPath. Skipping agent installation."
            return
        }

        $msiFiles = Get-ChildItem -Path $agentsPath -Filter *.msi -File

        if ($msiFiles.Count -eq 0) {
            Write-Warning "No MSI files found in agents folder."
            return
        }

        foreach ($msi in $msiFiles) {
            Write-Output "Installing agent: $($msi.Name)"
            Start-Process msiexec.exe `
                -ArgumentList "/i `"$($msi.FullName)`" /qn /norestart" `
                -Wait
        }
        Write-Output "Management agents installation completed."
    }
}

function windowsUpdate
{
    Write-Output "Triggering Windows Update scan..."

    # Force Windows Update to scan, download, and install
    Start-Process -FilePath "UsoClient.exe" -ArgumentList "StartScan" -NoNewWindow
    Start-Sleep -Seconds 5

    Start-Process -FilePath "UsoClient.exe" -ArgumentList "StartDownload" -NoNewWindow
    Start-Sleep -Seconds 5

    Start-Process -FilePath "UsoClient.exe" -ArgumentList "StartInstall" -NoNewWindow

    Write-Output "Windows Update initiated in background.`n"
}


# Main script execution
Assert-Admin
InstallAgents
windowsUpdate
installApps
Remove-Bloatware
setPowerPlan
Disable-StartupApps 
Reset-TaskbarPins
setTimeZone
cleanRestore
installOffice  

Write-Warning "Windows Updates may require a reboot to complete.`n`n"

exit $global:ExitCode
