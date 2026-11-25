#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    BloatBlaster (MSP) - new PC setup.

.DESCRIPTION
    Verifies/repairs WinGet, runs Windows Update, removes bloatware, installs standard and
    optional apps, applies power / startup / taskbar / time zone settings, runs Disk Cleanup,
    creates a restore point, installs management agents and (optionally) Microsoft 365.

    All questions are asked up front, so the rest of the run is unattended.

    Run in 64-bit Windows PowerShell 5.1 as an elevated technician or end-user account
    (not SYSTEM). Per-user settings (taskbar pins, startup apps, Copilot button) apply to
    the account running the script, so run it as the end user's account where possible.

    A transcript is written to C:\Installs (see -LogFolder).

.EXAMPLE
    .\BloatBlaster_MSP.ps1
#>
[CmdletBinding()]
param (
    # Exact AppX package names (no wildcards)
    [string[]]$AppsToRemove = @(
        '4DF9E0F8.Netflix',
        '5319275A.WhatsAppDesktop',
        '5A894077.McAfeeSecurity',
        '7EE7776C.LinkedInforWindows',
        'Amazon.com.Amazon',
        'AmazonVideo.PrimeVideo',
        'BytedancePte.Ltd.TikTok',
        'Clipchamp.Clipchamp',
        'Disney.37853FC22B2CE',
        'DropboxInc.Dropbox',
        'DropboxInc.DropboxOEM',
        'Facebook.Facebook',
        'Facebook.InstagramBeta',
        'king.com.BubbleWitch3Saga',
        'king.com.CandyCrushSaga',
        'king.com.CandyCrushSodaSaga',
        'Microsoft.BingNews',
        'Microsoft.BingWeather',
        'Microsoft.Copilot',
        'Microsoft.GamingApp',
        'Microsoft.Xbox.TCUI',
        'Microsoft.XboxApp',
        'Microsoft.XboxGameOverlay',
        'Microsoft.XboxGamingOverlay',
        'Microsoft.XboxIdentityProvider',
        'Microsoft.XboxSpeechToTextOverlay',
        'SpotifyAB.SpotifyMusic'
    ),

    # Transcript and MSI logs go here
    [string]$LogFolder = 'C:\Installs',

    # Office Deployment Tool folder (setup.exe + config XML)
    [string]$OfficeFolder = 'C:\Installs\Office 365 Business Premium - Offline',
    [string]$OfficeConfigFile = 'General M365 Business.xml',

    # Folder of agent MSIs. Defaults to .\agents next to the script.
    [string]$AgentsFolder,

    [ValidateRange(1, 10)]
    [int]$MaxUpdateCycles = 5
)

$script:ExitCode       = 0
$script:RebootRequired = $false
$script:WinGetPath     = $null
$ProgressPreference    = 'SilentlyContinue'   # Appx cmdlets run much faster without progress bars

# winget exit codes that are not real failures
$WINGET_ALREADY_INSTALLED = -1978335135   # 0x8A150061
$WINGET_NO_UPGRADE        = -1978335189   # 0x8A15002B

#region ---------- Software lists ----------

$RequiredApps = @(
    @{ Name = 'Google Chrome';           Id = 'Google.Chrome'; Force = $true }   # --force works around frequent hash mismatches
    @{ Name = 'Mozilla Firefox';         Id = 'Mozilla.Firefox' }
    @{ Name = 'Adobe Acrobat Reader DC'; Id = 'Adobe.Acrobat.Reader.64-bit' }
)

$OptionalSoftware = @(
    @{ Name = '7-Zip';                Id = '7zip.7zip' }
    @{ Name = 'Acrobat Pro';          Id = 'Adobe.Acrobat.Pro' }
    @{ Name = 'Advanced IP Scanner';  Id = 'Famatech.AdvancedIPScanner' }
    @{ Name = 'Bluebeam Revu 20';     Id = 'Bluebeam.Revu.20' }   # Confirm this version matches the client's license
    @{ Name = 'Canva';                Id = 'Canva.Canva' }
    @{ Name = 'CopyTrans';            Id = 'CopyTrans.Studio' }
    @{ Name = 'Creative Cloud';       Id = 'Adobe.CreativeCloud' }
    @{ Name = 'CrystalDiskInfo';      Id = 'CrystalDewWorld.CrystalDiskInfo.KureiKeiEdition' }
    @{ Name = 'Dell Command Update';      Id = 'Dell.CommandUpdate' }
    @{ Name = 'Dropbox';              Id = 'Dropbox.Dropbox' }
    @{ Name = 'Eraser';               Id = 'Eraser.Eraser' }
    @{ Name = 'Git';                  Id = 'Git.Git' }
    @{ Name = 'Google Earth Pro';     Id = 'Google.EarthPro' }
    @{ Name = 'GoTo';                 Id = 'GoTo.GoTo' }
    @{ Name = 'HP Image Assistant';   Id = 'HP.ImageAssistant' }
    @{ Name = 'iTunes';               Id = 'Apple.iTunes' }
    @{ Name = 'Lenovo System Update'; Id = 'Lenovo.SystemUpdate' }
    @{ Name = 'Nano Text Editor';     Id = 'GNU.Nano' }
    @{ Name = 'Nmap';                 Id = 'Insecure.Nmap' }
    @{ Name = 'OpenVPN Connect';      Id = 'OpenVPNTechnologies.OpenVPNConnect' }
    @{ Name = 'PDFgear';              Id = 'PDFgear.PDFgear' }
    @{ Name = 'PowerPanel Personal';  Id = 'CyberPowerSystemsInc.PowerPanelPersonal' }
    @{ Name = 'PuTTY';                Id = 'PuTTY.PuTTY' }
    @{ Name = 'Python 3.14';          Id = 'Python.Python.3.14' }
    @{ Name = 'Revo Uninstaller';     Id = 'RevoUninstaller.RevoUninstaller' }
    @{ Name = 'Rufus';                Id = 'Rufus.Rufus' }
    @{ Name = 'ShareX';               Id = 'ShareX.ShareX' }
    @{ Name = 'Splashtop Business';   Id = 'Splashtop.SplashtopBusiness' }
    @{ Name = 'Spotify';              Id = 'Spotify.Spotify' }
    @{ Name = 'TeraCopy';             Id = 'CodeSector.TeraCopy' }
    @{ Name = 'TreeSize Free';        Id = 'JAMSoftware.TreeSize.Free' }
    @{ Name = 'VirtualBox';           Id = 'Oracle.VirtualBox' }
    @{ Name = 'Visual Studio Code';   Id = 'Microsoft.VisualStudioCode' }
    @{ Name = 'VLC Media Player';     Id = 'VideoLAN.VLC' }
    @{ Name = 'Cloudflare WARP';      Id = 'Cloudflare.Warp' }
    @{ Name = 'Waterfox';             Id = 'Waterfox.Waterfox' }
    @{ Name = 'Webex';                Id = 'Cisco.Webex' }
    @{ Name = 'Wireshark';            Id = 'WiresharkFoundation.Wireshark' }
    @{ Name = 'Zoom';                 Id = 'Zoom.Zoom' }
)

#endregion

#region ---------- General helpers ----------

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host "=== $Title ===" -ForegroundColor Cyan
}

# Logs a warning and marks the run as failed
function Set-Failure {
    param([string]$Message)
    Write-Warning $Message
    $script:ExitCode = 1
}

function Read-YesNo {
    param([string]$Prompt)
    while ($true) {
        $answer = (Read-Host "$Prompt (Y/N)").Trim()
        if ($answer -match '^(y|yes)$') { return $true }
        if ($answer -match '^(n|no)$')  { return $false }
        Write-Host 'Please enter Y or N.' -ForegroundColor Yellow
    }
}

# Creates the key only if missing. (New-Item -Force on an existing registry key wipes its values.)
function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$Type = 'DWord'
    )
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

# Stops the script if it isn't running in a supported context
function Assert-SupportedContext {
    if (-not [Environment]::Is64BitProcess) {
        Write-Error 'Run this script in 64-bit Windows PowerShell 5.1.'
        exit 1
    }
    if ([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
        Write-Error 'This interactive script cannot run as SYSTEM. Run it elevated from a user session.'
        exit 1
    }
}

# Warns when the script runs as a different account than the signed-in user
function Test-RunningAsConsoleUser {
    $me      = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $console = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).UserName
    if ($console -and $console -ne $me) {
        Write-Warning "Running as '$me' but '$console' is signed in. Taskbar and startup-app changes will apply to '$me' only."
    }
}

function Select-OptionalSoftware {
    param([object[]]$Catalog)

    Write-Host "`nOptional software:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $Catalog.Count; $i++) {
        Write-Host ('[{0,2}] {1}' -f ($i + 1), $Catalog[$i].Name)
    }
    Write-Host '[ 0] None'

    while ($true) {
        $raw = Read-Host "`nEnter numbers (comma-separated, e.g. 1,3,5) or 0 for none"
        if ([string]::IsNullOrWhiteSpace($raw) -or $raw.Trim() -eq '0') { return @() }

        $tokens  = $raw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        $invalid = @($tokens | Where-Object { $_ -notmatch '^\d+$' -or [int]$_ -lt 1 -or [int]$_ -gt $Catalog.Count })

        if ($invalid.Count -gt 0) {
            Write-Host "Invalid selection: $($invalid -join ', '). Try again." -ForegroundColor Yellow
            continue
        }

        $indexes = $tokens | ForEach-Object { [int]$_ - 1 } | Sort-Object -Unique
        return @($indexes | ForEach-Object { $Catalog[$_] })
    }
}

#endregion

#region ---------- WinGet ----------

# Runs the exact winget.exe verified by Initialize-WinGet (no reliance on PATH or the alias)
function Invoke-WinGet {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    if (-not $script:WinGetPath) { throw 'WinGet has not been verified.' }
    & $script:WinGetPath @Arguments
}

function Invoke-WinGetPreflightCommand {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    Write-Host "  Verifying: winget $($Arguments -join ' ')" -ForegroundColor Cyan
    Invoke-WinGet -Arguments $Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "WinGet check failed (exit $LASTEXITCODE): $($Arguments -join ' ')" }
}

# Deploys the latest stable App Installer/WinGet and its dependencies using Microsoft's
# supported repair cmdlet, without deleting source databases or app data.
# Returns $true when winget is verified and usable.
# https://learn.microsoft.com/windows/package-manager/winget/
function Initialize-WinGet {
    Write-Section 'Updating App Installer and verifying WinGet'

    $previousTls = [Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::SecurityProtocol = $previousTls -bor [Net.SecurityProtocolType]::Tls12

        $before = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction Stop |
            Sort-Object Version -Descending | Select-Object -First 1
        if ($before) { Write-Host "  App Installer before: $($before.Version)" }
        else         { Write-Host '  App Installer is missing for this account; installing it.' }

        Write-Host '  Checking PowerShell Gallery and NuGet prerequisites...'
        if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue |
                Where-Object { [version]$_.Version -ge [version]'2.8.5.201' })) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force -ErrorAction Stop | Out-Null
        }

        $gallery = Get-PSRepository -Name PSGallery -ErrorAction Stop
        if ($gallery.SourceLocation.TrimEnd('/') -ne 'https://www.powershellgallery.com/api/v2') {
            throw 'PSGallery does not point to the official PowerShell Gallery.'
        }

        $latest    = Find-Module -Name Microsoft.WinGet.Client -Repository PSGallery -ErrorAction Stop
        $available = Get-Module -Name Microsoft.WinGet.Client -ListAvailable |
            Sort-Object Version -Descending | Select-Object -First 1
        if (-not $available -or $available.Version -lt [version]$latest.Version) {
            Write-Host "  Installing Microsoft.WinGet.Client $($latest.Version)..."
            Install-Module -Name Microsoft.WinGet.Client -RequiredVersion $latest.Version -Repository PSGallery -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        }
        Import-Module Microsoft.WinGet.Client -MinimumVersion $latest.Version -Force -ErrorAction Stop

        Write-Host '  Installing/repairing the latest stable App Installer and dependencies...'
        $repairResult = @(Repair-WinGetPackageManager -AllUsers -Latest -Force -ErrorAction Stop)
        $repairResult | Out-Host
        foreach ($result in $repairResult) {
            if (($result -is [int] -or $result -is [long]) -and $result -ne 0) {
                throw "App Installer repair returned exit code $result."
            }
        }

        $package = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction Stop |
            Sort-Object Version -Descending | Select-Object -First 1
        if (-not $package -or $package.Status -ne 'Ok') {
            throw 'App Installer is not registered in a healthy state for the current account.'
        }
        Write-Host "  App Installer after: $($package.Version)" -ForegroundColor Green

        foreach ($dependency in $package.Dependencies) {
            Write-Host "  Dependency: $($dependency.Name) $($dependency.Version) [$($dependency.Status)]"
            if ($dependency.Status -ne 'Ok') { throw "Dependency is unhealthy: $($dependency.Name)" }
        }

        $exe = Join-Path $package.InstallLocation 'winget.exe'
        if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
            throw 'The registered App Installer package does not contain winget.exe.'
        }
        $script:WinGetPath = $exe

        Invoke-WinGetPreflightCommand -Arguments @('--version')
        Invoke-WinGetPreflightCommand -Arguments @('source', 'update', '--name', 'winget', '--disable-interactivity')
        # A real repository query verifies more than just launching the executable
        Invoke-WinGetPreflightCommand -Arguments @('show', '--id', 'Microsoft.PowerShell', '--exact', '--source', 'winget', '--accept-source-agreements', '--disable-interactivity')

        Write-Host '  WinGet executable and community source verified.' -ForegroundColor Green
        return $true
    }
    catch {
        $script:WinGetPath = $null
        Set-Failure "WinGet check failed: $($_.Exception.Message)"
        Write-Warning 'App installs and upgrades will be skipped. The rest of setup will continue.'
        return $false
    }
    finally {
        [Net.ServicePointManager]::SecurityProtocol = $previousTls
    }
}

function Test-WingetInstalled {
    param([string]$PackageId)
    $null = Invoke-WinGet -Arguments @('list', '--id', $PackageId, '--exact', '--accept-source-agreements', '--disable-interactivity')
    return ($LASTEXITCODE -eq 0)
}

function Install-WingetPackage {
    param(
        [string]$Name,
        [string]$Id,
        [switch]$Force
    )

    Write-Host "`n$Name ($Id)" -ForegroundColor Cyan

    if (Test-WingetInstalled -PackageId $Id) {
        Write-Host '  Already installed - skipping.' -ForegroundColor DarkGray
        return
    }

    $wingetArgs = @(
        'install', '--id', $Id, '--exact', '--source', 'winget', '--silent',
        '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity'
    )
    if ($Force) { $wingetArgs += '--force' }

    Invoke-WinGet -Arguments $wingetArgs | Out-Host

    switch ($LASTEXITCODE) {
        0                         { Write-Host "  Installed $Name." -ForegroundColor Green }
        $WINGET_ALREADY_INSTALLED { Write-Host '  Already installed.' -ForegroundColor DarkGray }
        default                   { Set-Failure "$Name install returned exit code $LASTEXITCODE." }
    }
}

function Install-Application {
    param(
        [object[]]$Required,
        [object[]]$Optional
    )

    Write-Section 'Application installs (winget)'

    if (-not $script:WinGetPath) {
        Write-Warning 'WinGet is not available. Skipping application installs and upgrades.'
        return
    }

    foreach ($app in @($Required) + @($Optional)) {
        if (-not $app) { continue }
        Install-WingetPackage -Name $app.Name -Id $app.Id -Force:([bool]$app.Force)
    }

    Write-Host "`nUpgrading installed applications..." -ForegroundColor Cyan
    Invoke-WinGet -Arguments @('upgrade', '--all', '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity') | Out-Host

    if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq $WINGET_NO_UPGRADE) {
        Write-Host 'Application updates complete.' -ForegroundColor Green
    }
    else {
        Write-Warning "winget upgrade returned exit code $LASTEXITCODE (one or more upgrades failed)."
    }
}

#endregion

#region ---------- Windows Update ----------

function Invoke-WindowsUpdate {
    param([int]$MaxCycles = 5)

    Write-Section 'Windows Update'

    $service = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    if (-not $service) { Set-Failure 'Windows Update service not found. Skipping updates.'; return }
    if ($service.StartType -eq 'Disabled') { Set-Service -Name wuauserv -StartupType Manual }
    if ($service.Status -ne 'Running')     { Start-Service -Name wuauserv -ErrorAction SilentlyContinue }

    $session  = New-Object -ComObject Microsoft.Update.Session
    $session.ClientApplicationID = 'BloatBlaster'
    $searcher = $session.CreateUpdateSearcher()
    $upToDate = $false

    for ($cycle = 1; $cycle -le $MaxCycles; $cycle++) {
        Write-Host "`n--- Update cycle $cycle of $MaxCycles ---"
        Write-Host 'Searching for updates...'

        try {
            $result = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
        }
        catch {
            Set-Failure "Unable to query Windows Update: $($_.Exception.Message)"
            return
        }

        # Build the list of updates that can install unattended
        $toInstall = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($update in $result.Updates) {
            if ($update.InstallationBehavior.CanRequestUserInput) {
                Write-Host "  Skipping (needs user input): $($update.Title)" -ForegroundColor Yellow
                continue
            }
            if (-not $update.EulaAccepted) { $update.AcceptEula() }
            Write-Host "  - $($update.Title)"
            [void]$toInstall.Add($update)
        }

        if ($toInstall.Count -eq 0) { $upToDate = $true; break }

        Write-Host "Downloading $($toInstall.Count) update(s)..."
        try {
            $downloader = $session.CreateUpdateDownloader()
            $downloader.Updates = $toInstall
            [void]$downloader.Download()
        }
        catch {
            Write-Warning "Some updates could not be downloaded: $($_.Exception.Message)"
        }

        $ready = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($update in $toInstall) {
            if ($update.IsDownloaded) { [void]$ready.Add($update) }
        }
        if ($ready.Count -eq 0) { Set-Failure 'No updates downloaded successfully.'; return }

        Write-Host "Installing $($ready.Count) update(s)..."
        try {
            $installer = $session.CreateUpdateInstaller()
            $installer.Updates = $ready
            $install = $installer.Install()
        }
        catch {
            Set-Failure "Update installation error: $($_.Exception.Message)"
            return
        }

        # 2 = Succeeded, 3 = Succeeded with errors, 4 = Failed, 5 = Aborted
        switch ($install.ResultCode) {
            2       { Write-Host 'Updates installed successfully.' -ForegroundColor Green }
            3       { Write-Warning 'Updates installed with some errors.' }
            default { Set-Failure "Update installation result code: $($install.ResultCode)" }
        }

        if ($install.RebootRequired) {
            $script:RebootRequired = $true
            Write-Warning 'A reboot is required before more updates can install. Continuing setup; run this again after rebooting to finish updates.'
            return
        }
    }

    if ($upToDate) {
        Write-Host 'Windows Update is current.' -ForegroundColor Green
    }
    else {
        Write-Warning "Stopped after $MaxCycles update cycles. Run Windows Update again after rebooting."
    }
}

#endregion

#region ---------- Bloatware ----------

# Targeted removal by exact package name. The package manager owns WindowsApps and per-user
# package data cleanup: never take ownership of or recursively delete profile/app folders.
# References: learn.microsoft.com/powershell/module/appx/remove-appxpackage
#             learn.microsoft.com/powershell/module/dism/remove-appxprovisionedpackage
function Remove-Bloatware {
    param([string[]]$Apps)

    Write-Section 'Targeted application removal'

    # Validate names: exact package names only, no wildcards
    $targets = foreach ($name in $Apps) {
        $name = $name.Trim()
        if (-not $name) { continue }
        if ($name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]+$') {
            Set-Failure "Rejected invalid package name: $name"
            continue
        }
        $name
    }
    $targets = @($targets | Sort-Object -Unique)

    # Enumerate once (Get-AppxProvisionedPackage is slow)
    try {
        $installedAll   = @(Get-AppxPackage -AllUsers -PackageTypeFilter Main, Bundle -ErrorAction Stop)
        $provisionedAll = @(Get-AppxProvisionedPackage -Online -ErrorAction Stop)
    }
    catch {
        Set-Failure "Could not list installed apps: $($_.Exception.Message)"
        return
    }

    $results   = New-Object System.Collections.Generic.List[object]
    $attempted = New-Object System.Collections.Generic.List[string]

    foreach ($name in $targets) {
        $installed   = @($installedAll   | Where-Object { $_.Name -eq $name })
        $provisioned = @($provisionedAll | Where-Object { $_.DisplayName -eq $name })

        if ($installed.Count -eq 0 -and $provisioned.Count -eq 0) {
            $results.Add([pscustomobject]@{ App = $name; Status = 'Not present' })
            continue
        }

        Write-Host "`n$name" -ForegroundColor Cyan
        $failed = $false

        # Provisioned first so the app isn't reinstalled for new user profiles
        foreach ($package in $provisioned) {
            try {
                Write-Host "  Removing provisioning: $($package.PackageName)"
                $r = Remove-AppxProvisionedPackage -Online -AllUsers -PackageName $package.PackageName -ErrorAction Stop
                if ($r.RestartNeeded) { $script:RebootRequired = $true; Write-Warning '  Reboot required to finish removal.' }
            }
            catch {
                $failed = $true
                Write-Warning "  Provisioning removal failed: $($_.Exception.Message)"
            }
        }

        # Bundles must be removed via their parent, not each child package
        $bundles = @($installed | Where-Object { $_.IsBundle })
        if ($bundles.Count -gt 0) { $installed = $bundles }

        foreach ($package in ($installed | Sort-Object PackageFullName -Unique)) {
            try {
                if ($package.NonRemovable -or $package.IsFramework) {
                    throw 'Windows marks this package protected or shared; leaving it intact.'
                }
                Write-Host "  Removing for all users: $($package.PackageFullName)"
                Remove-AppxPackage -Package $package.PackageFullName -AllUsers -ErrorAction Stop
            }
            catch {
                $failed = $true
                Write-Warning "  Installed-package removal failed: $($_.Exception.Message)"
            }
        }

        if ($failed) {
            $script:ExitCode = 1
            $results.Add([pscustomobject]@{ App = $name; Status = 'Failed - needs review' })
        }
        else {
            $attempted.Add($name)
        }
    }

    # Verify once for everything that was removed without errors
    if ($attempted.Count -gt 0) {
        try {
            $installedNow   = @(Get-AppxPackage -AllUsers -PackageTypeFilter Main, Bundle -ErrorAction Stop)
            $provisionedNow = @(Get-AppxProvisionedPackage -Online -ErrorAction Stop)

            foreach ($name in $attempted) {
                if ($provisionedNow | Where-Object { $_.DisplayName -eq $name }) {
                    Set-Failure "$name is still provisioned."
                    $results.Add([pscustomobject]@{ App = $name; Status = 'Still provisioned - needs review' })
                }
                elseif ($installedNow | Where-Object { $_.Name -eq $name }) {
                    # Removal for other profiles can stay pending until they sign in or the PC reboots
                    $results.Add([pscustomobject]@{ App = $name; Status = 'Removed - pending for some users until reboot/sign-in' })
                }
                else {
                    $results.Add([pscustomobject]@{ App = $name; Status = 'Removed and verified' })
                }
            }
        }
        catch {
            Write-Warning "Could not verify removals: $($_.Exception.Message)"
            foreach ($name in $attempted) { $results.Add([pscustomobject]@{ App = $name; Status = 'Removed (not verified)' }) }
        }
    }

    Remove-DropboxPromotion

    Write-Host "`nApplication removal summary" -ForegroundColor Cyan
    $results | Sort-Object App | Format-Table -AutoSize | Out-Host
    Write-Host 'Shared Gaming Services, Widgets/Web Experience, Office Copilot, Dropbox sync data and browser profiles are preserved.'
}

function Remove-DropboxPromotion {
    Write-Host "`nChecking native Dropbox promotions..." -ForegroundColor Cyan

    $promoNames = @('Dropbox Promotion', 'Dropbox OEM', 'Dropbox 25 GB', 'Get Dropbox')
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $found = $false

    foreach ($key in $keys) {
        if (-not (Test-Path -LiteralPath $key)) { continue }
        try {
            $entries = @(Get-ChildItem -LiteralPath $key -ErrorAction Stop |
                Get-ItemProperty -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -in $promoNames })

            foreach ($entry in $entries) {
                $found = $true
                try {
                    Write-Host "  Found: $($entry.DisplayName)"
                    # Only run a recognized MSI uninstall or a Dropbox-signed OEM uninstaller.
                    # Never run arbitrary uninstall commands from the registry.
                    if ($entry.WindowsInstaller -eq 1 -and $entry.PSChildName -match '^\{[0-9A-Fa-f-]{36}\}$') {
                        $process = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList @('/x', $entry.PSChildName, '/qn', '/norestart') -Wait -PassThru -ErrorAction Stop
                        if ($process.ExitCode -notin @(0, 1605, 1614, 3010)) { throw "MSI exit code $($process.ExitCode)" }
                        if ($process.ExitCode -eq 3010) { $script:RebootRequired = $true; Write-Warning '  Promotion removal requires reboot.' }
                        if (Test-Path -LiteralPath $entry.PSPath) { throw 'Promotion registration remains; review after reboot.' }
                        Write-Host '  Native promotion removal verified.' -ForegroundColor Green
                    }
                    elseif ($entry.UninstallString -match '^"([^"\r\n]+\\DropboxOEM\.exe)"\s+/(?:uninstall|remove)\s*$') {
                        $exe      = $Matches[1]
                        $argument = ($entry.UninstallString -replace '^"[^"\r\n]+"\s+', '')
                        if (-not [IO.Path]::IsPathRooted($exe) -or -not (Test-Path -LiteralPath $exe -PathType Leaf)) {
                            throw 'OEM uninstaller path is unavailable.'
                        }
                        $signature = Get-AuthenticodeSignature -LiteralPath $exe -ErrorAction Stop
                        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '(?:^|,\s*)O="?Dropbox(?:,? Inc\.?)?"?(?:,|$)') {
                            throw 'OEM uninstaller does not have a valid Dropbox publisher signature.'
                        }
                        $process = Start-Process -FilePath $exe -ArgumentList $argument -Wait -PassThru -ErrorAction Stop
                        if ($process.ExitCode -notin @(0, 3010)) { throw "OEM exit code $($process.ExitCode)" }
                        if ($process.ExitCode -eq 3010) { $script:RebootRequired = $true; Write-Warning '  OEM removal requires reboot.' }
                        if (Test-Path -LiteralPath $entry.PSPath) { throw 'OEM registration remains; review after reboot.' }
                        Write-Host '  Native OEM promotion removal verified.' -ForegroundColor Green
                    }
                    else {
                        throw 'Unrecognized uninstaller; remove this promotion through Installed apps. No command was run.'
                    }
                }
                catch {
                    Set-Failure "  $($entry.DisplayName): $($_.Exception.Message)"
                }
            }
        }
        catch {
            Set-Failure "  Could not inspect ${key}: $($_.Exception.Message)"
        }
    }
    if (-not $found) { Write-Host '  No registered Dropbox promotion found.' -ForegroundColor DarkGray }

    # Only exact promotional shortcut names that point at DropboxOEM.exe. Never touch Dropbox folders or sync shortcuts.
    $roots = @(
        "$env:PUBLIC\Desktop",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs",
        [Environment]::GetFolderPath('Desktop')
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

    $shell = $null
    try {
        foreach ($root in $roots) {
            foreach ($leaf in @('Dropbox 25 GB.lnk', 'Get Dropbox.lnk', 'Dropbox Promotion.lnk')) {
                $path = Join-Path $root $leaf
                if (-not (Test-Path -LiteralPath $path)) { continue }
                try {
                    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
                    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse point skipped.' }
                    if (-not $shell) { $shell = New-Object -ComObject WScript.Shell }
                    $link = $shell.CreateShortcut($path)
                    if ([IO.Path]::GetFileName($link.TargetPath) -ne 'DropboxOEM.exe') {
                        Write-Warning "  Unconfirmed promotional shortcut preserved: $path"
                        continue
                    }
                    Remove-Item -LiteralPath $path -Force -ErrorAction Stop
                    Write-Host "  Removed promotional shortcut: $path" -ForegroundColor Green
                }
                catch {
                    Set-Failure "  Shortcut cleanup failed for ${path}: $($_.Exception.Message)"
                }
            }
        }
    }
    finally {
        if ($shell) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell) }
    }
}

#endregion

#region ---------- Power ----------

function Invoke-Powercfg {
    param([string[]]$Arguments)
    & powercfg.exe @Arguments
    if ($LASTEXITCODE -ne 0) { Write-Warning "powercfg $($Arguments -join ' ') failed ($LASTEXITCODE)." }
}

function Set-PowerSetting {
    Write-Section 'Power settings'

    # High performance plan if this device has it (Modern Standby devices often only have Balanced)
    $highPerf = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
    if ((powercfg.exe /list | Out-String) -match $highPerf) {
        Invoke-Powercfg '/setactive', $highPerf
    }
    else {
        $dup = powercfg.exe /duplicatescheme $highPerf 2>$null | Out-String
        if ($LASTEXITCODE -eq 0 -and $dup -match '[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}') {
            Invoke-Powercfg '/setactive', $Matches[0]
        }
        else {
            Write-Warning 'High performance plan is not available on this device. Applying settings to the current plan.'
        }
    }
    powercfg.exe /getactivescheme | Out-Host

    # Sleep and display: never on AC, 30 minutes on battery
    Write-Host 'Sleep and display off: Never on AC, 30 minutes on battery.'
    Invoke-Powercfg '/change', 'standby-timeout-ac', '0'
    Invoke-Powercfg '/change', 'standby-timeout-dc', '30'
    Invoke-Powercfg '/change', 'monitor-timeout-ac', '0'
    Invoke-Powercfg '/change', 'monitor-timeout-dc', '30'

    # Lid and buttons: 0 = Do nothing, 1 = Sleep, 3 = Shut down
    # Lid closed on battery still sleeps so laptops don't overheat in a bag.
    Write-Host 'Lid: Do nothing on AC, Sleep on battery. Power button: Shut down. Sleep button: Do nothing on AC, Sleep on battery.'
    $buttons = @(
        @{ Setting = 'LIDACTION';     AC = 0; DC = 1 }
        @{ Setting = 'PBUTTONACTION'; AC = 3; DC = 3 }
        @{ Setting = 'SBUTTONACTION'; AC = 0; DC = 1 }
    )
    foreach ($b in $buttons) {
        Invoke-Powercfg '/setacvalueindex', 'SCHEME_CURRENT', 'SUB_BUTTONS', $b.Setting, $b.AC
        Invoke-Powercfg '/setdcvalueindex', 'SCHEME_CURRENT', 'SUB_BUTTONS', $b.Setting, $b.DC
    }
    Invoke-Powercfg '/setactive', 'SCHEME_CURRENT'

    Write-Host 'Disabling Fast Startup...'
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled' -Value 0

    Write-Host 'Power settings applied.' -ForegroundColor Green
}

#endregion

#region ---------- Startup apps ----------

# Marks a startup entry as disabled, the same way Task Manager does (reversible)
function Disable-StartupEntry {
    param(
        [string]$ApprovedKey,
        [string]$Name
    )
    $disabled = [byte[]](0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    Set-RegistryValue -Path $ApprovedKey -Name $Name -Value $disabled -Type Binary
}

function Disable-StartupApp {
    Write-Section 'Disabling startup apps (Teams, Edge, OneDrive, Webex, Copilot)'

    $approvedRoot = 'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved'

    $targets = @(
        @{ Name = 'Teams';          Pattern = 'ms-?teams|com\.squirrel\.Teams|\\Teams\\' }
        @{ Name = 'Microsoft Edge'; Pattern = 'MicrosoftEdgeAutoLaunch|msedge\.exe' }
        @{ Name = 'OneDrive';       Pattern = 'OneDrive' }
        @{ Name = 'Webex';          Pattern = 'webex' }
        @{ Name = 'Copilot';        Pattern = 'copilot' }
    )

    $runSources = @(
        @{ Run = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run';             Approved = "HKCU:\$approvedRoot\Run" }
        @{ Run = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';             Approved = "HKLM:\$approvedRoot\Run" }
        @{ Run = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Approved = "HKLM:\$approvedRoot\Run32" }
    )

    $folderSources = @(
        @{ Folder = [Environment]::GetFolderPath('Startup');       Approved = "HKCU:\$approvedRoot\StartupFolder" }
        @{ Folder = [Environment]::GetFolderPath('CommonStartup'); Approved = "HKLM:\$approvedRoot\StartupFolder" }
    )

    foreach ($target in $targets) {
        Write-Host "`n  $($target.Name)" -ForegroundColor Yellow
        $hits = 0

        # Registry Run keys
        foreach ($src in $runSources) {
            $key = Get-Item -Path $src.Run -ErrorAction SilentlyContinue
            if (-not $key) { continue }

            foreach ($name in $key.GetValueNames()) {
                if (-not $name) { continue }
                $value = [string]$key.GetValue($name)
                if ($name -match $target.Pattern -or $value -match $target.Pattern) {
                    try {
                        Disable-StartupEntry -ApprovedKey $src.Approved -Name $name
                        Write-Host "    Disabled: $name ($($src.Run))" -ForegroundColor Green
                        $hits++
                    }
                    catch {
                        Write-Warning "    Could not disable ${name}: $($_.Exception.Message)"
                    }
                }
            }
        }

        # Startup folder shortcuts
        foreach ($src in $folderSources) {
            if (-not $src.Folder -or -not (Test-Path $src.Folder)) { continue }

            Get-ChildItem -Path $src.Folder -Filter *.lnk -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match $target.Pattern } |
                ForEach-Object {
                    try {
                        Disable-StartupEntry -ApprovedKey $src.Approved -Name $_.Name
                        Write-Host "    Disabled shortcut: $($_.Name)" -ForegroundColor Green
                        $hits++
                    }
                    catch {
                        Write-Warning "    Could not disable $($_.Name): $($_.Exception.Message)"
                    }
                }
        }

        if ($hits -eq 0) { Write-Host '    Not found or already disabled' -ForegroundColor DarkGray }
    }

    # New Teams starts via an app startup task, not a Run key (State 1 = disabled by user)
    Write-Host "`n  Teams / Copilot / Edge policies" -ForegroundColor Yellow
    $settings = @(
        @{ Path = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MSTeams_8wekyb3d8bbwe\TeamsTfwStartupTask'; Name = 'State'; Value = 1 }
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\common\officeupdate'; Name = 'preventteamsinstall';   Value = 1 }
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot';          Name = 'TurnOffWindowsCopilot'; Value = 1 }
        @{ Path = 'HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot';          Name = 'TurnOffWindowsCopilot'; Value = 1 }
        @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name = 'ShowCopilotButton';     Value = 0 }
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge';                            Name = 'CopilotPageContext';    Value = 0 }
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge';                            Name = 'HubsSidebarEnabled';    Value = 0 }
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge';                            Name = 'BackgroundModeEnabled'; Value = 0 }
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge';                            Name = 'StartupBoostEnabled';   Value = 0 }
    )

    foreach ($s in $settings) {
        try {
            Set-RegistryValue -Path $s.Path -Name $s.Name -Value $s.Value
            Write-Host "    $($s.Name) = $($s.Value)" -ForegroundColor Green
        }
        catch {
            Write-Warning "    Could not set $($s.Path)\$($s.Name): $($_.Exception.Message)"
        }
    }

    Write-Host "`nStartup apps disabled." -ForegroundColor Green
}

#endregion

#region ---------- Taskbar / time zone ----------

# Clears all taskbar pins for the current user. Windows restores its default pins.
function Reset-TaskbarPin {
    Write-Section 'Resetting taskbar pins'

    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue

    $pinFolder = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
    if (Test-Path $pinFolder) { Remove-Item "$pinFolder\*" -Force -ErrorAction SilentlyContinue }
    Remove-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband' -Recurse -ErrorAction SilentlyContinue

    Start-Sleep -Seconds 2
    if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) { Start-Process explorer.exe }
    Start-Sleep -Seconds 3

    Write-Host 'Taskbar reset.' -ForegroundColor Green
}

function Set-CentralTimeZone {
    Write-Section 'Time zone'

    Set-TimeZone -Id 'Central Standard Time'
    Write-Host 'Time zone set to Central Standard Time.' -ForegroundColor Green

    Write-Host 'Syncing time...'
    Set-Service -Name w32time -StartupType Automatic
    Start-Service -Name w32time -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    w32tm /resync /force | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Warning 'Time sync failed. Retrying...'
        Start-Sleep -Seconds 3
        w32tm /resync /force | Out-Host
        if ($LASTEXITCODE -ne 0) { Write-Warning 'Time sync failed again.' }
    }

    w32tm /query /status | Out-Host
}

#endregion

#region ---------- Disk Cleanup / restore point ----------

function Invoke-DiskCleanup {
    Write-Section 'Disk Cleanup'

    # /sagerun:1 only cleans categories flagged with StateFlags0001, so set them here.
    # DownloadsFolder is skipped so user downloads are never deleted.
    $caches = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'
    Get-ChildItem -Path $caches -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -ne 'DownloadsFolder' } |
        ForEach-Object {
            New-ItemProperty -Path $_.PSPath -Name 'StateFlags0001' -Value 2 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        }

    Write-Host 'Running Disk Cleanup (up to 30 minutes)...'
    $proc = Start-Process cleanmgr.exe -ArgumentList '/sagerun:1' -PassThru
    if ($proc.WaitForExit(30 * 60 * 1000)) {
        Write-Host 'Disk Cleanup complete.' -ForegroundColor Green
    }
    else {
        Write-Warning 'Disk Cleanup is still running after 30 minutes. Continuing without waiting.'
    }
}

function New-SetupRestorePoint {
    Write-Section 'System Restore point'

    $srKey    = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
    $freqName = 'SystemRestorePointCreationFrequency'
    $previous = (Get-ItemProperty -Path $srKey -Name $freqName -ErrorAction SilentlyContinue).$freqName

    try {
        Enable-ComputerRestore -Drive 'C:\' -ErrorAction Stop

        vssadmin Resize ShadowStorage /For=C: /On=C: /MaxSize=5% | Out-Host
        if ($LASTEXITCODE -ne 0) { Write-Warning 'Could not resize shadow storage. Using the Windows default.' }

        # Windows skips restore points made within 24 hours of the last one unless this is 0
        Set-RegistryValue -Path $srKey -Name $freqName -Value 0

        Checkpoint-Computer -Description 'Initial Setup' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        Write-Host "Restore point 'Initial Setup' created." -ForegroundColor Green
    }
    catch {
        Set-Failure "Restore point not created: $($_.Exception.Message)"
    }
    finally {
        if ($null -ne $previous) {
            Set-RegistryValue -Path $srKey -Name $freqName -Value $previous
        }
        else {
            Remove-ItemProperty -Path $srKey -Name $freqName -ErrorAction SilentlyContinue
        }
    }
}

#endregion

#region ---------- Management agents ----------

# Reads the ProductCode from an MSI without installing it
function Get-MsiProductCode {
    param([string]$Path)

    $installer = $database = $view = $record = $null
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $database  = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($Path, 0))
        $view      = $database.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $database, @("SELECT Value FROM Property WHERE Property='ProductCode'"))
        $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
        $record    = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
        $code      = $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, @(1))
        $view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null) | Out-Null
        return $code
    }
    catch {
        Write-Warning "Could not read ProductCode from ${Path}: $($_.Exception.Message)"
        return $null
    }
    finally {
        # Release COM handles so the MSI file isn't left locked
        foreach ($obj in $record, $view, $database, $installer) {
            if ($obj) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($obj) }
        }
        [GC]::Collect()
    }
}

function Test-MsiProductInstalled {
    param([string]$ProductCode)
    $uninstallKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($key in $uninstallKeys) {
        if (Test-Path (Join-Path $key $ProductCode)) { return $true }
    }
    return $false
}

function Install-Agent {
    param([string]$Folder)

    Write-Section 'Management agents'

    if (-not (Test-Path $Folder)) {
        Write-Warning "Agents folder not found at $Folder. Skipping agent installation."
        return
    }

    $msiFiles = @(Get-ChildItem -Path $Folder -Filter *.msi -File)
    if ($msiFiles.Count -eq 0) {
        Write-Warning "No MSI files found in $Folder."
        return
    }

    foreach ($msi in $msiFiles) {
        $code = Get-MsiProductCode -Path $msi.FullName
        if ($code -and (Test-MsiProductInstalled -ProductCode $code)) {
            Write-Host "  $($msi.Name) is already installed. Skipping." -ForegroundColor DarkGray
            continue
        }

        $msiLog = Join-Path $LogFolder ("Agent_{0}.log" -f $msi.BaseName)
        Write-Host "  Installing $($msi.Name)..."

        $proc = Start-Process msiexec.exe -Wait -PassThru `
            -ArgumentList "/i `"$($msi.FullName)`" /qn /norestart /l*v `"$msiLog`""

        switch ($proc.ExitCode) {
            0                       { Write-Host "  Installed $($msi.Name)." -ForegroundColor Green }
            { $_ -in 1641, 3010 }   { Write-Host "  Installed $($msi.Name) (reboot required)." -ForegroundColor Green; $script:RebootRequired = $true }
            default                 { Set-Failure "$($msi.Name) failed with exit code $($proc.ExitCode). See $msiLog" }
        }
    }
}

#endregion

#region ---------- Microsoft 365 ----------

function Install-Office {
    param(
        [string]$Folder,
        [string]$ConfigFile
    )

    Write-Section 'Microsoft 365'

    $setupExe = Join-Path $Folder 'setup.exe'
    $xmlFile  = Join-Path $Folder $ConfigFile

    foreach ($file in $setupExe, $xmlFile) {
        if (-not (Test-Path $file)) { Set-Failure "Not found: $file. Skipping Microsoft 365."; return }
    }

    Write-Host "Using config: $xmlFile"

    # A separate download step is only needed when the XML installs from a local SourcePath
    $config = [xml](Get-Content -Path $xmlFile -Raw)
    if ($config.Configuration.Add.SourcePath) {
        Write-Host 'Downloading Office source files...'
        $proc = Start-Process -FilePath $setupExe -ArgumentList "/download `"$xmlFile`"" -WorkingDirectory $Folder -Wait -PassThru -NoNewWindow
        if ($proc.ExitCode -ne 0) { Set-Failure "Office download failed with exit code $($proc.ExitCode)."; return }
    }

    Write-Host 'Installing Microsoft 365...'
    $proc = Start-Process -FilePath $setupExe -ArgumentList "/configure `"$xmlFile`"" -WorkingDirectory $Folder -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -eq 0) {
        Write-Host 'Microsoft 365 installed.' -ForegroundColor Green
    }
    else {
        Set-Failure "Office install failed with exit code $($proc.ExitCode)."
    }
}

#endregion

#region ---------- Main ----------

Assert-SupportedContext

if (-not $AgentsFolder) {
    $base = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $AgentsFolder = Join-Path $base 'agents'
}

if (-not (Test-Path $LogFolder)) { New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null }
$logFile = Join-Path $LogFolder ('BloatBlaster_{0}_{1:yyyyMMdd_HHmmss}.log' -f $env:COMPUTERNAME, (Get-Date))
Start-Transcript -Path $logFile | Out-Null

try {
    Test-RunningAsConsoleUser

    # Ask everything up front so the rest runs unattended
    Write-Section 'Setup questions'
    $selectedOptional = @(Select-OptionalSoftware -Catalog $OptionalSoftware)
    $doTaskbar        = Read-YesNo "`nReset the taskbar pins?"
    $doTimeZone       = Read-YesNo 'Set the time zone to Central Standard Time?'
    $doOffice         = Read-YesNo 'Install Microsoft 365?'

    Write-Host "`nOptional apps:  $(if ($selectedOptional.Count) { ($selectedOptional | ForEach-Object { $_.Name }) -join ', ' } else { 'None' })"
    Write-Host "Reset taskbar:  $doTaskbar"
    Write-Host "Set time zone:  $doTimeZone"
    Write-Host "Install M365:   $doOffice"
    Write-Host "`nAll questions answered. The rest of setup runs unattended." -ForegroundColor Green

    [void](Initialize-WinGet)
    Invoke-WindowsUpdate -MaxCycles $MaxUpdateCycles
    Remove-Bloatware -Apps $AppsToRemove
    Install-Application -Required $RequiredApps -Optional $selectedOptional
    Set-PowerSetting
    Disable-StartupApp

    if ($doTaskbar)  { Reset-TaskbarPin }    else { Write-Host "`nTaskbar not reset." }
    if ($doTimeZone) { Set-CentralTimeZone } else { Write-Host "`nTime zone not changed." }

    Invoke-DiskCleanup
    New-SetupRestorePoint
    Install-Agent -Folder $AgentsFolder

    if ($doOffice) { Install-Office -Folder $OfficeFolder -ConfigFile $OfficeConfigFile }
    else           { Write-Host "`nMicrosoft 365 not installed." }
}
catch {
    Set-Failure "Unexpected error: $($_.Exception.Message)"
}
finally {
    Write-Section 'Summary'
    if ($script:RebootRequired) {
        Write-Warning 'A reboot is required. Run Windows Update again afterward to pick up any remaining updates.'
    }
    if ($script:ExitCode -eq 0) {
        Write-Host 'Setup finished with no errors.' -ForegroundColor Green
    }
    else {
        Write-Warning 'Setup finished with errors. Review the warnings above.'
    }
    Write-Host "Log: $logFile"
    Stop-Transcript | Out-Null
}

exit $script:ExitCode

#endregion
