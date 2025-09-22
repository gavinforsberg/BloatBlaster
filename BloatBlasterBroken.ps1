#Requires -Version 5.1

[CmdletBinding()]
param (
    [Parameter()]
    [String]$AppsToRemove = "Amazon.com.Amazon, AmazonVideo.PrimeVideo, Clipchamp.Clipchamp, Disney.37853FC22B2CE, DropboxInc.Dropbox, Facebook.Facebook, Facebook.InstagramBeta, king.com.BubbleWitch3Saga, king.com.CandyCrushSaga, king.com.CandyCrushSodaSaga, 5A894077.McAfeeSecurity, 4DF9E0F8.Netflix, SpotifyAB.SpotifyMusic, BytedancePte.Ltd.TikTok, 5319275A.WhatsAppDesktop, Microsoft.XboxApp, Microsoft.XboxGameOverlay, Microsoft.XboxGamingOverlay, Microsoft.XboxSpeechToTextOverlay, Microsoft.Xbox.TCUI, Microsoft.XboxIdentityProvider",
    [Parameter()]
    [String]$OverrideWithCustomField
)

$global:ExitCode = 0

function Disable-NonMicrosoftStartupApps {
    # # --- REMOVE UNNECESSARY STARTUP APPS ---
#     Write-Host "`nDisabling non-Microsoft startup applications..."
#     try {
#         Get-CimInstance -ClassName Win32_StartupCommand | Where-Object {
#             $_.Command -notmatch "Microsoft|Windows Defender|SecurityHealth"
#         } | ForEach-Object {
#             Write-Host "Disabling: $($_.Name)"
#             $null = Disable-ScheduledTask -TaskName $_.Name -ErrorAction SilentlyContinue
#         }
#     } catch {
#         Write-Host "[Warning] Could not disable all startup tasks: $($_.Exception.Message)"
#     }


    Write-Host "`nDisabling non-Microsoft startup apps..."

    # Registry locations
    $runKeys = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"

    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            Get-ItemProperty -Path $key | ForEach-Object {
                foreach ($property in $_.PSObject.Properties) {
                    $name = $property.Name
                    $command = $property.Value
                    if ($command -notmatch "Microsoft|Defender|SecurityHealth") {
                        Write-Host "Removing registry startup item: $name"
                        Remove-ItemProperty -Path $key -Name $name -ErrorAction SilentlyContinue
                    }
                }
            }
        }
    }

    # Startup folder paths
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

    function Reset-TaskbarPins 
{
    Write-Host "`nResetting taskbar to only include File Explorer and Firefox..."

    # Kill Explorer
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue

    # Remove pinned items
    $taskbarPath = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
    if (Test-Path $taskbarPath) 
    {
        Remove-Item "$taskbarPath\*" -Force -ErrorAction SilentlyContinue
    }

    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Recurse -ErrorAction SilentlyContinue

    # Restart Explorer
    Start-Process explorer.exe
    Start-Sleep -Seconds 5

    # Pin File Explorer
    $explorerPath = "C:\Windows\explorer.exe"
    $shell = New-Object -ComObject Shell.Application
    $folder = $shell.Namespace((Split-Path $explorerPath))
    $item = $folder.ParseName((Split-Path $explorerPath -Leaf))
    $item.InvokeVerb("Pin to Tas&kbar")
    Write-Host "Pinned File Explorer."

    # Pin Firefox
    $firefoxPath = "${env:ProgramFiles}\Mozilla Firefox\firefox.exe"
    if (Test-Path $firefoxPath) 
    {
        $folder = $shell.Namespace((Split-Path $firefoxPath))
        $item = $folder.ParseName((Split-Path $firefoxPath -Leaf))
        $item.InvokeVerb("Pin to Tas&kbar")
        Write-Host "Pinned Firefox."
    } 
    else 
    {
        Write-Warning "Firefox is not installed at the expected path."
    }

    # Unpin Teams specifically after File Explorer restarts 
    Start-Sleep -Seconds 10  # Give Explorer time to fully restart
    $teamsShortcut = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Teams.lnk"

    if (Test-Path $teamsShortcut) 
    {
        Remove-Item $teamsShortcut -Force -ErrorAction SilentlyContinue
        Write-Host "Teams was pinned — removing shortcut."
    }

        
    try 
    {
        $TaskBarPath = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
        if (Test-Path $TaskBarPath) 
        {
            Remove-Item "$TaskBarPath\*" -Force -ErrorAction SilentlyContinue
            Write-Host "Pinned taskbar items removed. Restart Explorer for full effect."
        }
    } 
    catch 
    {
        Write-Host "[Warning] Could not clear pinned taskbar icons: $($_.Exception.Message)"
    }
}

function beginning {
    # Replace parameters with dynamic script variables.
    if ($env:appsToRemove -and $env:appsToRemove -notlike "null") { $AppsToRemove = $env:appsToRemove }
    if ($env:overrideWithCustomFieldName -and $env:overrideWithCustomFieldName -notlike "null") { $OverrideWithCustomField = $env:overrideWithCustomFieldName }

    $AppList = New-Object System.Collections.Generic.List[string]

    function Get-NinjaProperty {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
            [String]$Name
        )
    
        # We'll redirect error output to the success stream to make it easier to error out if nothing was found or something else went wrong.
        $NinjaPropertyValue = Ninja-Property-Get -Name $Name 2>&1
    
        # If we received some sort of error it should have an exception property and we'll exit the function with that error information.
        if ($NinjaPropertyValue.Exception) { throw $NinjaPropertyValue }
    
        if (-not $NinjaPropertyValue) {
            throw [System.NullReferenceException]::New("The Custom Field '$Name' is empty!")
        }
    
        $NinjaPropertyValue
    }

    if ($OverrideWithCustomField) 
    {
        Write-Host "Attempting to retrieve uninstall list from '$OverrideWithCustomField'."
        try 
        {
            $AppsToRemove = Get-NinjaProperty -Name $OverrideWithCustomField -ErrorAction Stop
        }
        catch 
        {
            # If we ran into some sort of error we'll output it here.
            Write-Host "Error $($_.Exception.Message)"
            exit 1
        }
    }

    # Check if apps to remove are specified; otherwise, list all Appx packages and exit
    if (!$AppsToRemove) 
    {
        Write-Host "Error Nothing given to remove? Please specify one of the below packages."
        Get-AppxPackage -AllUsers | Select-Object Name | Sort-Object Name | Out-String | Write-Host
        exit 1
    }

    # Regex to detect invalid characters in Appx package names
    $InvalidCharacters = '[#!@&$)(<>?|:;\/{}^%`"\]+'

    # Process each app name after splitting the input string
    if ($AppsToRemove -match ",") 
    {
        $AppsToRemove -split ',' | ForEach-Object 
        {
            $App = $_.Trim()
            if ($App -match '^[-.]' -or $App -match '\.\.|--' -or $App -match '[-.]$' -or $App -match "\s" -or $App -match $InvalidCharacters) 
            {
                Write-Host "[Error] Invalid character in '$App'. Appx package names cannot contain '$InvalidCharcters', start with '.-', contain a space, or have consecutive '.' or '-' characters."
                $global:ExitCode = 1
                return
            }

            if ($App.Length -ge 50) {
                Write-Host "[Error] Appx package name of '$App' is invalid Appx package names must be less than 50 characters."
                $global:ExitCode = 1
                return
            }

            $AppList.Add($App)
        }
    }
    else {
        $AppsToRemove = $AppsToRemove.Trim()
        if ($AppsToRemove -match '^[-.]' -or $AppsToRemove -match '\.\.|--' -or $AppsToRemove -match '[-.]$' -or $AppsToRemove -match "\s" -or $AppsToRemove -match $InvalidCharacters) {
            Write-Host "[Error] Invalid character in '$AppsToRemove'. AppxPackage names cannot contain '#!@&$)(<>?|:;\/{}^%`"', start with '.-', contain a space, or have consecutive '.' or '-' characters."
            Get-AppxPackage -AllUsers | Select-Object Name | Sort-Object Name | Out-String | Write-Host
            exit 1
        }

        if ($AppsToRemove.Length -ge 50) {
            Write-Host "[Error] Appx package name of '$AppsToRemove' is invalid Appx package names must be less than 50 characters."
            Get-AppxPackage -AllUsers | Select-Object Name | Sort-Object Name | Out-String | Write-Host
            exit 1
        }

        $AppList.Add($AppsToRemove)
    }

    # Exit if no valid apps to remove
    if ($AppList.Count -eq 0) {
        Write-Host "[Error] No valid apps to remove!"
        Get-AppxPackage -AllUsers | Select-Object Name | Sort-Object Name | Out-String | Write-Host
        exit 1
    }

    # Function to check if the script is running with Administrator privileges
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    if (!$global:ExitCode) {
        $global:ExitCode = 0
    }
}

function isAdmin {
        # Check for Administrator privileges before attempting to remove any packages
        if (!(Test-IsElevated)) {
            Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
            exit 1
        }
}

function removeBloat 
{
    # Attempt to remove each specified app
    foreach ($App in $AppList) 
    {
        $AppxPackage = Get-AppxPackage -AllUsers | Where-Object { $_.Name -Like "*$App*" } | Sort-Object Name -Unique
        $ProvisionedPackage = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*$App*" } | Sort-Object DisplayName -Unique
        
        # Warn if the app is not installed
        if (!$AppxPackage -and !$ProvisionedPackage) {
            Write-Host "`n[Warn] $App is not installed!"
            continue
        }

        # Output an error if too many apps were selected for uninstall
        if ($AppxPackage.Count -gt 1) {
            Write-Host "[Error] Too many Apps were found with the name '$App'. Please re-run with a more specific name."
            Write-Host ($AppxPackage | Select-Object Name | Sort-Object Name | Out-String)
            $global:ExitCode = 1
            continue
        }
        if ($ProvisionedPackage.Count -gt 1) {
            Write-Host "[Error] Too many Apps were found with the name '$App'. Please re-run with a more specific name."
            Write-Host ($ProvisionedPackage | Select-Object DisplayName | Sort-Object DisplayName | Out-String)
            $global:ExitCode = 1
            continue
        }

        # Output an error if two different packages got selected.
        if ($ProvisionedPackage -and $AppxPackage -and $AppxPackage.Name -ne $ProvisionedPackage.DisplayName) {
            Write-Host "[Error] Too many Apps were found with the name '$App'. Please re-run with a more specific name."
            Write-Host ($ProvisionedPackage | Select-Object DisplayName | Sort-Object DisplayName | Out-String)
            $global:ExitCode = 1
            continue
        }

        try 
        {
            # Remove the provisioning package first.
            if ($ProvisionedPackage) 
            {
                Write-Host "`nAttempting to remove provisioning package $($ProvisionedPackage.DisplayName)..."
                Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*$App*" } | Remove-AppxProvisionedPackage -Online -AllUsers | Out-Null
                Write-Host "Successfully removed provisioning package $($ProvisionedPackage.DisplayName)."
            }

            # Remove the installed instances.
            if ($AppxPackage) 
            {
                Write-Host "`nAttempting to remove $($AppxPackage.Name)..."
                Get-AppxPackage -AllUsers | Where-Object { $_.Name -Like "*$App*" } | Remove-AppxPackage -AllUsers
                Write-Host "Successfully removed $($AppxPackage.Name)."
            }
        }
        catch 
        {
            if ($AppxPackage.Count -gt 1) 
            {
                Write-Host "[Error] Too many Apps were found with the name '$App'. Please re-run with a more specific name."

                foreach ($pkg in $AppxPackage) 
                {
                    Write-Host " - $($pkg.Name)"
                }

                $ExitCode = 1
                continue
            }

            if ($ProvisionedPackage.Count -gt 1) 
            {
                Write-Host "[Error] Too many Provisioned Apps were found with the name '$App'. Please re-run with a more specific name."

                foreach ($pkg in $ProvisionedPackage) 
                {
                    Write-Host " - $($pkg.DisplayName)"
                }

                $ExitCode = 1
                continue
            }
        }
    }
}

function installApps {
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
            Write-Host "[Error] Failed to install $($app.Name): $($_.Exception.Message)"
            $global:ExitCode = 1
        }
    }
}

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
    # Sets time zone to Central 
    Set-TimeZone -Id "Central Standard Time"


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
        Start-Process -FilePath ".\setup.exe" -ArgumentList '/download "General M365 Business.xml" -Wait'
        Write-Host "Download complete."

        if (!(Test-Path "$officePath\Office")) 
        {
            Write-Warning "Office files not found. The download might have failed."
            exit 1
        }

        # Step 2: Install Office
        Start-Process -FilePath ".\setup.exe" -ArgumentList '/configure "General M365 Business.xml" -Wait'
        Write-Host "Office installation completed."
    } 
    else 
    {
        Write-Host "Installation cancelled by user."
    }
}

beginning
isAdmin
installApps
removeBloat
Disable-NonMicrosoftStartupApps
Reset-TaskbarPins
cleanRestore
installOffice
