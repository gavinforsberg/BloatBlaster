#Requires -Version 5.1
<#
.SYNOPSIS
    BloatBlaster GUI - a front end for the BloatBlaster new-PC setup script.

.DESCRIPTION
    Lets a technician pick steps, optional apps and bloatware to remove, then runs the
    BloatBlaster script unattended (-Unattended) and streams its output live.

    The app lists (optional software, required apps, bloatware) are read straight from the
    BloatBlaster script, so editing the lists in the script is all that's needed.

    Put this file next to BloatBlaster_Refactor.ps1 (or BloatBlaster_MSP.ps1) and launch it
    with BloatBlaster_GUI.cmd, or:
        powershell.exe -ExecutionPolicy Bypass -File .\BloatBlaster_GUI.ps1
    It re-launches itself elevated if needed.

.PARAMETER ScriptPath
    Path to the BloatBlaster script. Defaults to the first BloatBlaster script found next to this file.

.PARAMETER NoElevate
    Open without elevating (preview only; Run is disabled).
#>
[CmdletBinding()]
param(
    [string]$ScriptPath,
    [switch]$NoElevate
)

$ErrorActionPreference = 'Stop'

#region ---------- Elevation / STA ----------

$psExe = if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    "$env:SystemRoot\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
} else {
    "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
$isSta = [Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'

if ((-not $isAdmin -and -not $NoElevate) -or -not $isSta) {
    $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-WindowStyle', 'Hidden', '-File', "`"$PSCommandPath`"")
    if ($ScriptPath) { $relaunch += @('-ScriptPath', "`"$ScriptPath`"") }
    if ($NoElevate)  { $relaunch += '-NoElevate' }
    try {
        if ($isAdmin -or $NoElevate) { Start-Process -FilePath $psExe -ArgumentList $relaunch }
        else                         { Start-Process -FilePath $psExe -ArgumentList $relaunch -Verb RunAs }
    }
    catch {
        Add-Type -AssemblyName PresentationFramework
        [void][System.Windows.MessageBox]::Show("BloatBlaster needs administrator rights.`n`n$($_.Exception.Message)", 'BloatBlaster', 'OK', 'Error')
    }
    exit
}

#endregion

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

#region ---------- Helper types ----------

if (-not ('BloatBlasterGui.Runner' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Text;

namespace BloatBlasterGui {
    public abstract class Notify : INotifyPropertyChanged {
        public event PropertyChangedEventHandler PropertyChanged;
        protected void Raise(string name) {
            var h = PropertyChanged;
            if (h != null) h(this, new PropertyChangedEventArgs(name));
        }
    }

    public class CheckItem : Notify {
        public string Name { get; set; }
        public string Id { get; set; }
        bool _checked;
        public bool IsChecked { get { return _checked; } set { _checked = value; Raise("IsChecked"); } }
    }

    public class LogLine {
        public string Text { get; set; }
        public string Color { get; set; }
        public string Weight { get; set; }
    }

    public class StepItem : Notify {
        public string Key { get; set; }
        public string Name { get; set; }
        public int Warnings;
        string _state = "pending";
        public string State {
            get { return _state; }
            set { _state = value; Raise("State"); Raise("Glyph"); Raise("Fore"); Raise("Back"); Raise("Tip"); }
        }
        public void Touch() { Raise("Tip"); }
        public string Glyph { get {
            switch (_state) {
                case "running": return "\u25B6";
                case "done":    return "\u2714";
                case "warn":    return "\u26A0";
                case "stopped": return "\u25A0";
                default:        return "\u25CB";
            } } }
        public string Fore { get {
            switch (_state) {
                case "running": return "#1D4ED8";
                case "done":    return "#047857";
                case "warn":    return "#B45309";
                case "stopped": return "#B91C1C";
                default:        return "#6B7280";
            } } }
        public string Back { get {
            switch (_state) {
                case "running": return "#DBEAFE";
                case "done":    return "#D1FAE5";
                case "warn":    return "#FEF3C7";
                case "stopped": return "#FEE2E2";
                default:        return "#F3F4F6";
            } } }
        public string Tip { get {
            return Name + ": " + _state + (Warnings > 0 ? " (" + Warnings + " warning" + (Warnings == 1 ? "" : "s") + ")" : "");
        } }
    }

    // Runs a process and queues its output lines; the UI drains the queue on a timer.
    public class Runner {
        public ConcurrentQueue<string> Lines = new ConcurrentQueue<string>();
        public Process Proc;

        public void Start(string exe, string args, string workDir) {
            var psi = new ProcessStartInfo(exe, args);
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.RedirectStandardInput = true;
            psi.CreateNoWindow = true;
            psi.WorkingDirectory = workDir;
            psi.StandardOutputEncoding = Encoding.UTF8;
            psi.StandardErrorEncoding = Encoding.UTF8;
            Proc = new Process();
            Proc.StartInfo = psi;
            Proc.OutputDataReceived += (s, e) => { if (e.Data != null) Lines.Enqueue(e.Data); };
            Proc.ErrorDataReceived  += (s, e) => { if (e.Data != null) Lines.Enqueue("ERROR: " + e.Data); };
            Proc.Start();
            Proc.StandardInput.Close();   // nothing should ever prompt; EOF instead of hanging
            Proc.BeginOutputReadLine();
            Proc.BeginErrorReadLine();
        }

        // Kills the script and everything it started (winget, msiexec, cleanmgr...)
        public void KillTree() {
            if (Proc == null || Proc.HasExited) return;
            var k = Process.Start(new ProcessStartInfo("taskkill.exe", "/T /F /PID " + Proc.Id) { CreateNoWindow = true, UseShellExecute = false });
            k.WaitForExit(15000);
        }
    }
}
'@
}

#endregion

#region ---------- Script discovery and parsing ----------

function Find-BloatBlasterScript {
    $here = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    foreach ($name in 'BloatBlaster_Refactor.ps1', 'BloatBlaster_MSP.ps1', 'BloatBlaster_STABLE.ps1', 'BloatBlaster.ps1') {
        $p = Join-Path $here $name
        if (Test-Path -LiteralPath $p) { return $p }
    }
    $any = Get-ChildItem -Path $here -Filter 'BloatBlaster*.ps1' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notlike '*GUI*' } | Select-Object -First 1
    if ($any) { return $any.FullName }
    return $null
}

# Reads the app lists and parameter defaults from the script without running it
function Read-BloatBlasterScript {
    param([string]$Path)

    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "The script has syntax errors: $($errors[0].Message) (line $($errors[0].Extent.StartLineNumber))" }
    if (-not $ast.ParamBlock) { throw 'The script has no param() block.' }

    $params = @{}
    foreach ($p in $ast.ParamBlock.Parameters) { $params[$p.Name.VariablePath.UserPath] = $p }

    $getDefault = {
        param($name)
        $p = $params[$name]
        if (-not $p -or -not $p.DefaultValue) { return $null }
        try { return $p.DefaultValue.SafeGetValue() } catch { return $null }
    }

    $getHashtables = {
        param($varName)
        $assign = $ast.Find({
                param($n)
                $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
                $n.Left.VariablePath.UserPath -eq $varName
            }, $true)
        if (-not $assign) { return @() }
        @($assign.Right.FindAll({ param($n) $n -is [System.Management.Automation.Language.HashtableAst] }, $true) |
            ForEach-Object { $_.SafeGetValue() })
    }

    $bloat = @()
    if ($params['AppsToRemove'] -and $params['AppsToRemove'].DefaultValue) {
        $bloat = @($params['AppsToRemove'].DefaultValue.FindAll({
                    param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true) |
                ForEach-Object { $_.Value })
    }

    [pscustomobject]@{
        Path             = $Path
        SupportsGui      = $params.ContainsKey('Unattended') -and $params.ContainsKey('SkipStep')
        SupportsSac      = $params.ContainsKey('DisableSmartAppControl')
        Required         = @(& $getHashtables 'RequiredApps')
        Optional         = @(& $getHashtables 'OptionalSoftware')
        Bloatware        = $bloat
        LogFolder        = & $getDefault 'LogFolder'
        OfficeFolder     = & $getDefault 'OfficeFolder'
        OfficeConfigFile = & $getDefault 'OfficeConfigFile'
        MaxUpdateCycles  = & $getDefault 'MaxUpdateCycles'
    }
}

function ConvertTo-PSLiteral {
    param([string]$Value)
    "'" + $Value.Replace("'", "''") + "'"
}

function ConvertTo-PSArrayLiteral {
    param([string[]]$Values)
    if (-not $Values -or $Values.Count -eq 0) { return '@()' }
    '@(' + (($Values | ForEach-Object { ConvertTo-PSLiteral $_ }) -join ', ') + ')'
}

#endregion

#region ---------- Step definitions (in run order) ----------

# Section = the Write-Section title the script prints when the step starts
$StepDefs = @(
    @{ Key = 'WinGet';        Name = 'WinGet';          Section = 'Updating App Installer and verifying WinGet'; Box = 'StepWinGet' }
    @{ Key = 'WindowsUpdate'; Name = 'Windows Update';  Section = 'Windows Update';                Box = 'StepWindowsUpdate' }
    @{ Key = 'Bloatware';     Name = 'Bloatware';       Section = 'Targeted application removal'; Box = 'StepBloatware' }
    @{ Key = 'SmartAppControl'; Name = 'Smart App Control'; Section = 'Smart App Control';         Box = 'OptSmartApp' }
    @{ Key = 'Apps';          Name = 'Apps';            Section = 'Application installs*';        Box = 'StepApps' }
    @{ Key = 'Power';         Name = 'Power';           Section = 'Power settings';                Box = 'StepPower' }
    @{ Key = 'Startup';       Name = 'Startup apps';    Section = 'Disabling startup apps*';      Box = 'StepStartup' }
    @{ Key = 'Taskbar';       Name = 'Taskbar';         Section = 'Resetting taskbar pins';        Box = 'OptTaskbar' }
    @{ Key = 'TimeZone';      Name = 'Time zone';       Section = 'Time zone';                     Box = 'OptTimeZone' }
    @{ Key = 'DiskCleanup';   Name = 'Disk Cleanup';    Section = 'Disk Cleanup';                  Box = 'StepDiskCleanup' }
    @{ Key = 'RestorePoint';  Name = 'Restore point';   Section = 'System Restore point';          Box = 'StepRestorePoint' }
    @{ Key = 'Agents';        Name = 'Agents';          Section = 'Management agents';             Box = 'StepAgents' }
    @{ Key = 'Office';        Name = 'Microsoft 365';   Section = 'Microsoft 365';                 Box = 'OptOffice' }
)
# Steps the script can skip via -SkipStep (the rest are opt-in switches)
$SkippableSteps = 'WinGet', 'WindowsUpdate', 'Bloatware', 'Apps', 'Power', 'Startup', 'DiskCleanup', 'RestorePoint', 'Agents'

#endregion

#region ---------- XAML ----------

[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="BloatBlaster" Width="1240" Height="820" MinWidth="1000" MinHeight="640"
        WindowStartupLocation="CenterScreen" Background="#F3F4F6"
        FontFamily="Segoe UI" FontSize="13" UseLayoutRounding="True">
  <Window.Resources>
    <Style x:Key="Btn" TargetType="Button">
      <Setter Property="Background" Value="White"/>
      <Setter Property="Foreground" Value="#111827"/>
      <Setter Property="BorderBrush" Value="#D1D5DB"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="14,7"/>
      <Setter Property="Margin" Value="8,0,0,0"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="b" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="6" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Opacity" Value="0.85"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter TargetName="b" Property="Opacity" Value="0.4"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="Primary" TargetType="Button" BasedOn="{StaticResource Btn}">
      <Setter Property="Background" Value="#2563EB"/>
      <Setter Property="BorderBrush" Value="#2563EB"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Padding" Value="22,8"/>
    </Style>
    <Style x:Key="Danger" TargetType="Button" BasedOn="{StaticResource Btn}">
      <Setter Property="Background" Value="#DC2626"/>
      <Setter Property="BorderBrush" Value="#DC2626"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
    <Style x:Key="Small" TargetType="Button" BasedOn="{StaticResource Btn}">
      <Setter Property="Padding" Value="10,4"/>
      <Setter Property="FontSize" Value="12"/>
    </Style>
    <Style x:Key="Section" TargetType="TextBlock">
      <Setter Property="FontSize" Value="11"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Foreground" Value="#6B7280"/>
      <Setter Property="Margin" Value="0,14,0,6"/>
    </Style>
    <Style x:Key="Hint" TargetType="TextBlock">
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="Foreground" Value="#6B7280"/>
      <Setter Property="TextWrapping" Value="Wrap"/>
    </Style>
    <Style x:Key="StepBox" TargetType="CheckBox">
      <Setter Property="Margin" Value="0,5"/>
      <Setter Property="VerticalContentAlignment" Value="Top"/>
      <Setter Property="Cursor" Value="Hand"/>
    </Style>
    <Style TargetType="TextBox">
      <Setter Property="Padding" Value="6,5"/>
      <Setter Property="BorderBrush" Value="#D1D5DB"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
    </Style>
    <Style TargetType="TabItem">
      <Setter Property="Padding" Value="12,6"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
    <Style x:Key="ListRow" TargetType="ListBoxItem">
      <Setter Property="Padding" Value="6,4"/>
      <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
      <Setter Property="Focusable" Value="False"/>
    </Style>
  </Window.Resources>

  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- Header -->
    <Border Grid.Row="0" Background="#111827" Padding="20,14">
      <DockPanel>
        <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
          <TextBlock x:Name="HostInfo" Foreground="#9CA3AF" VerticalAlignment="Center"/>
          <Border x:Name="AdminBadge" CornerRadius="10" Padding="9,2" Margin="12,0,0,0" Background="#065F46">
            <TextBlock x:Name="AdminText" Foreground="#D1FAE5" FontSize="11" FontWeight="SemiBold" Text="ADMINISTRATOR"/>
          </Border>
        </StackPanel>
        <StackPanel Orientation="Horizontal">
          <TextBlock Text="BloatBlaster" Foreground="White" FontSize="21" FontWeight="Bold"/>
          <TextBlock Text="New PC setup" Foreground="#9CA3AF" FontSize="13" Margin="12,0,0,3" VerticalAlignment="Bottom"/>
        </StackPanel>
      </DockPanel>
    </Border>

    <!-- Warning banner -->
    <Border x:Name="Banner" Grid.Row="1" Background="#FEF3C7" BorderBrush="#F59E0B" BorderThickness="0,0,0,1" Padding="20,9" Visibility="Collapsed">
      <TextBlock x:Name="BannerText" Foreground="#92400E" TextWrapping="Wrap"/>
    </Border>

    <!-- Body -->
    <Grid Grid.Row="2" Margin="16,16,16,0">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="450"/>
        <ColumnDefinition Width="16"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>

      <!-- Configuration -->
      <Border x:Name="ConfigPanel" Grid.Column="0" Background="White" CornerRadius="8" BorderBrush="#E5E7EB" BorderThickness="1">
        <TabControl x:Name="Tabs" BorderThickness="0,1,0,0" BorderBrush="#E5E7EB" Margin="8" Background="White">

          <TabItem Header="Steps">
            <ScrollViewer VerticalScrollBarVisibility="Auto">
              <StackPanel Margin="12,0,12,12">
                <TextBlock Style="{StaticResource Section}" Text="SETUP STEPS"/>

                <CheckBox x:Name="StepWinGet" Style="{StaticResource StepBox}" IsChecked="True">
                  <StackPanel Margin="4,0,0,0"><TextBlock Text="Verify / repair WinGet" FontWeight="SemiBold"/>
                    <TextBlock Style="{StaticResource Hint}" Text="Updates App Installer. Required for app installs."/></StackPanel>
                </CheckBox>
                <DockPanel>
                  <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Top" Margin="0,5,0,0">
                    <TextBlock Text="max cycles" Style="{StaticResource Hint}" VerticalAlignment="Center" Margin="0,0,6,0"/>
                    <ComboBox x:Name="UpdateCycles" Width="54"/>
                  </StackPanel>
                  <CheckBox x:Name="StepWindowsUpdate" Style="{StaticResource StepBox}" IsChecked="True">
                    <StackPanel Margin="4,0,0,0"><TextBlock Text="Windows Update" FontWeight="SemiBold"/>
                      <TextBlock Style="{StaticResource Hint}" Text="Installs updates until current or a reboot is needed."/></StackPanel>
                  </CheckBox>
                </DockPanel>
                <CheckBox x:Name="StepBloatware" Style="{StaticResource StepBox}" IsChecked="True">
                  <StackPanel Margin="4,0,0,0"><TextBlock Text="Remove bloatware" FontWeight="SemiBold"/>
                    <TextBlock x:Name="BloatHint" Style="{StaticResource Hint}" Text="Apps checked on the Bloatware tab, plus Dropbox promotions."/></StackPanel>
                </CheckBox>
                <CheckBox x:Name="StepApps" Style="{StaticResource StepBox}" IsChecked="True">
                  <StackPanel Margin="4,0,0,0"><TextBlock Text="Install and upgrade apps" FontWeight="SemiBold"/>
                    <TextBlock x:Name="AppsHint" Style="{StaticResource Hint}" Text="Required apps plus anything picked on the Optional apps tab."/></StackPanel>
                </CheckBox>
                <CheckBox x:Name="StepPower" Style="{StaticResource StepBox}" IsChecked="True">
                  <StackPanel Margin="4,0,0,0"><TextBlock Text="Power settings" FontWeight="SemiBold"/>
                    <TextBlock Style="{StaticResource Hint}" Text="High performance, no sleep on AC, lid/buttons, Fast Startup off."/></StackPanel>
                </CheckBox>
                <CheckBox x:Name="StepStartup" Style="{StaticResource StepBox}" IsChecked="True">
                  <StackPanel Margin="4,0,0,0"><TextBlock Text="Disable startup apps" FontWeight="SemiBold"/>
                    <TextBlock Style="{StaticResource Hint}" Text="Teams, Edge, OneDrive, Webex, Copilot + Copilot/Edge policies."/></StackPanel>
                </CheckBox>
                <CheckBox x:Name="StepDiskCleanup" Style="{StaticResource StepBox}" IsChecked="True">
                  <StackPanel Margin="4,0,0,0"><TextBlock Text="Disk Cleanup" FontWeight="SemiBold"/>
                    <TextBlock Style="{StaticResource Hint}" Text="All categories except Downloads. Up to 30 minutes."/></StackPanel>
                </CheckBox>
                <CheckBox x:Name="StepRestorePoint" Style="{StaticResource StepBox}" IsChecked="True">
                  <StackPanel Margin="4,0,0,0"><TextBlock Text="Create restore point" FontWeight="SemiBold"/>
                    <TextBlock Style="{StaticResource Hint}" Text="Enables System Restore on C: and saves 'Initial Setup'."/></StackPanel>
                </CheckBox>
                <CheckBox x:Name="StepAgents" Style="{StaticResource StepBox}" IsChecked="True">
                  <StackPanel Margin="4,0,0,0"><TextBlock Text="Install management agents" FontWeight="SemiBold"/>
                    <TextBlock x:Name="AgentsHint" Style="{StaticResource Hint}" Text="Every MSI in the agents folder."/></StackPanel>
                </CheckBox>

                <TextBlock Style="{StaticResource Section}" Text="OPTIONAL (THE SCRIPT USED TO ASK THESE)"/>
                <CheckBox x:Name="OptTaskbar" Style="{StaticResource StepBox}">
                  <StackPanel Margin="4,0,0,0"><TextBlock Text="Reset taskbar pins" FontWeight="SemiBold"/>
                    <TextBlock Style="{StaticResource Hint}" Text="Restarts Explorer for the account running setup."/></StackPanel>
                </CheckBox>
                <CheckBox x:Name="OptTimeZone" Style="{StaticResource StepBox}">
                  <StackPanel Margin="4,0,0,0"><TextBlock Text="Set time zone to Central" FontWeight="SemiBold"/>
                    <TextBlock Style="{StaticResource Hint}" Text="Central Standard Time and a forced time sync."/></StackPanel>
                </CheckBox>
                <CheckBox x:Name="OptOffice" Style="{StaticResource StepBox}">
                  <StackPanel Margin="4,0,0,0"><TextBlock Text="Install Microsoft 365" FontWeight="SemiBold"/>
                    <TextBlock x:Name="OfficeHint" Style="{StaticResource Hint}" Text="Office Deployment Tool from the Paths tab."/></StackPanel>
                </CheckBox>
                <CheckBox x:Name="OptSmartApp" Style="{StaticResource StepBox}">
                  <StackPanel Margin="4,0,0,0"><TextBlock Text="Turn off Smart App Control" FontWeight="SemiBold"/>
                    <TextBlock x:Name="SacHint" Style="{StaticResource Hint}" Text="Checking..."/></StackPanel>
                </CheckBox>

                <StackPanel Orientation="Horizontal" Margin="0,14,0,0">
                  <Button x:Name="StepsAll" Style="{StaticResource Small}" Margin="0" Content="Select all"/>
                  <Button x:Name="StepsNone" Style="{StaticResource Small}" Content="Clear all"/>
                </StackPanel>
              </StackPanel>
            </ScrollViewer>
          </TabItem>

          <TabItem x:Name="OptionalTab" Header="Optional apps">
            <DockPanel Margin="12,10,12,12">
              <Border DockPanel.Dock="Top" Background="#F9FAFB" BorderBrush="#E5E7EB" BorderThickness="1" CornerRadius="6" Padding="10,8" Margin="0,0,0,10">
                <TextBlock x:Name="RequiredText" Style="{StaticResource Hint}" Foreground="#374151"/>
              </Border>
              <DockPanel DockPanel.Dock="Top" Margin="0,0,0,8">
                <Button x:Name="OptClear" DockPanel.Dock="Right" Style="{StaticResource Small}" Content="Clear"/>
                <Grid>
                  <TextBox x:Name="OptSearch"/>
                  <TextBlock x:Name="OptSearchHint" Text="Search apps..." Foreground="#9CA3AF" Margin="9,0,0,0" VerticalAlignment="Center" IsHitTestVisible="False"/>
                </Grid>
              </DockPanel>
              <TextBlock x:Name="OptCount" DockPanel.Dock="Bottom" Style="{StaticResource Hint}" Margin="0,8,0,0"/>
              <ListBox x:Name="OptList" BorderBrush="#E5E7EB" ItemContainerStyle="{StaticResource ListRow}"
                       ScrollViewer.HorizontalScrollBarVisibility="Disabled">
                <ListBox.ItemTemplate>
                  <DataTemplate>
                    <CheckBox IsChecked="{Binding IsChecked, Mode=TwoWay}" Cursor="Hand">
                      <StackPanel Orientation="Horizontal" Margin="4,0,0,0">
                        <TextBlock Text="{Binding Name}"/>
                        <TextBlock Text="{Binding Id}" Foreground="#9CA3AF" FontSize="11" Margin="8,1,0,0"/>
                      </StackPanel>
                    </CheckBox>
                  </DataTemplate>
                </ListBox.ItemTemplate>
              </ListBox>
            </DockPanel>
          </TabItem>

          <TabItem x:Name="BloatTab" Header="Bloatware">
            <DockPanel Margin="12,10,12,12">
              <TextBlock DockPanel.Dock="Top" Style="{StaticResource Hint}" Margin="0,0,0,8"
                         Text="AppX packages removed for all users and from the image. Uncheck anything this client wants to keep."/>
              <DockPanel DockPanel.Dock="Top" Margin="0,0,0,8">
                <TextBlock x:Name="BloatCount" Style="{StaticResource Hint}" VerticalAlignment="Center"/>
                <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
                  <Button x:Name="BloatAll" Style="{StaticResource Small}" Content="All"/>
                  <Button x:Name="BloatNone" Style="{StaticResource Small}" Content="None"/>
                </StackPanel>
              </DockPanel>
              <ListBox x:Name="BloatList" BorderBrush="#E5E7EB" ItemContainerStyle="{StaticResource ListRow}"
                       ScrollViewer.HorizontalScrollBarVisibility="Disabled">
                <ListBox.ItemTemplate>
                  <DataTemplate>
                    <CheckBox IsChecked="{Binding IsChecked, Mode=TwoWay}" Cursor="Hand">
                      <TextBlock Text="{Binding Name}" Margin="4,0,0,0" FontFamily="Cascadia Mono, Consolas" FontSize="12"/>
                    </CheckBox>
                  </DataTemplate>
                </ListBox.ItemTemplate>
              </ListBox>
            </DockPanel>
          </TabItem>

          <TabItem Header="Paths">
            <ScrollViewer VerticalScrollBarVisibility="Auto">
              <StackPanel Margin="12,0,12,12">
                <TextBlock Style="{StaticResource Section}" Text="BLOATBLASTER SCRIPT"/>
                <DockPanel>
                  <Button x:Name="ScriptReload" DockPanel.Dock="Right" Style="{StaticResource Small}" Content="Reload"/>
                  <Button x:Name="ScriptBrowse" DockPanel.Dock="Right" Style="{StaticResource Small}" Content="Browse"/>
                  <TextBox x:Name="ScriptBox"/>
                </DockPanel>
                <TextBlock x:Name="ScriptStatus" Style="{StaticResource Hint}" Margin="2,4,0,0"/>

                <TextBlock Style="{StaticResource Section}" Text="LOG FOLDER"/>
                <DockPanel>
                  <Button x:Name="LogBrowse" DockPanel.Dock="Right" Style="{StaticResource Small}" Content="Browse"/>
                  <TextBox x:Name="LogBox"/>
                </DockPanel>
                <TextBlock Style="{StaticResource Hint}" Margin="2,4,0,0" Text="Transcript and MSI logs. Created if missing."/>

                <TextBlock Style="{StaticResource Section}" Text="AGENTS FOLDER"/>
                <DockPanel>
                  <Button x:Name="AgentsBrowse" DockPanel.Dock="Right" Style="{StaticResource Small}" Content="Browse"/>
                  <TextBox x:Name="AgentsBox"/>
                </DockPanel>
                <TextBlock x:Name="AgentsStatus" Style="{StaticResource Hint}" Margin="2,4,0,0"/>

                <TextBlock Style="{StaticResource Section}" Text="MICROSOFT 365 (OFFICE DEPLOYMENT TOOL)"/>
                <DockPanel>
                  <Button x:Name="OfficeBrowse" DockPanel.Dock="Right" Style="{StaticResource Small}" Content="Browse"/>
                  <TextBox x:Name="OfficeBox"/>
                </DockPanel>
                <TextBlock Style="{StaticResource Hint}" Margin="2,8,0,4" Text="Config XML (file name in that folder)"/>
                <DockPanel>
                  <Button x:Name="OfficeXmlBrowse" DockPanel.Dock="Right" Style="{StaticResource Small}" Content="Browse"/>
                  <TextBox x:Name="OfficeXmlBox"/>
                </DockPanel>
                <TextBlock x:Name="OfficeStatus" Style="{StaticResource Hint}" Margin="2,4,0,0"/>
              </StackPanel>
            </ScrollViewer>
          </TabItem>
        </TabControl>
      </Border>

      <!-- Run panel -->
      <Border Grid.Column="2" Background="White" CornerRadius="8" BorderBrush="#E5E7EB" BorderThickness="1">
        <DockPanel Margin="16,14,16,16">
          <StackPanel DockPanel.Dock="Top">
            <DockPanel>
              <TextBlock x:Name="Elapsed" DockPanel.Dock="Right" Foreground="#6B7280" VerticalAlignment="Center" FontFamily="Cascadia Mono, Consolas"/>
              <TextBlock x:Name="StatusTitle" Text="Ready" FontSize="17" FontWeight="SemiBold" Foreground="#111827"/>
            </DockPanel>
            <TextBlock x:Name="StatusDetail" Style="{StaticResource Hint}" Margin="0,2,0,0" Text="Choose steps on the left, then Run setup."/>
            <ProgressBar x:Name="Progress" Height="6" Margin="0,10,0,12" Foreground="#2563EB" Background="#E5E7EB" BorderThickness="0"/>
            <ItemsControl x:Name="StepChips">
              <ItemsControl.ItemsPanel>
                <ItemsPanelTemplate><WrapPanel/></ItemsPanelTemplate>
              </ItemsControl.ItemsPanel>
              <ItemsControl.ItemTemplate>
                <DataTemplate>
                  <Border CornerRadius="11" Padding="9,3" Margin="0,0,6,6" Background="{Binding Back}" ToolTip="{Binding Tip}">
                    <StackPanel Orientation="Horizontal">
                      <TextBlock Text="{Binding Glyph}" Foreground="{Binding Fore}" FontFamily="Segoe UI Symbol" Margin="0,0,5,0"/>
                      <TextBlock Text="{Binding Name}" Foreground="{Binding Fore}" FontSize="12" FontWeight="SemiBold"/>
                    </StackPanel>
                  </Border>
                </DataTemplate>
              </ItemsControl.ItemTemplate>
            </ItemsControl>
          </StackPanel>
          <Border CornerRadius="6" Background="#0B1220" Padding="4" Margin="0,6,0,0">
            <ListBox x:Name="Console" Background="Transparent" BorderThickness="0"
                     FontFamily="Cascadia Mono, Consolas" FontSize="12" SelectionMode="Extended"
                     VirtualizingPanel.IsVirtualizing="True" VirtualizingPanel.VirtualizationMode="Recycling"
                     ScrollViewer.HorizontalScrollBarVisibility="Auto">
              <ListBox.ItemContainerStyle>
                <Style TargetType="ListBoxItem">
                  <Setter Property="Padding" Value="6,0"/>
                </Style>
              </ListBox.ItemContainerStyle>
              <ListBox.ItemTemplate>
                <DataTemplate>
                  <TextBlock Text="{Binding Text}" Foreground="{Binding Color}" FontWeight="{Binding Weight}"/>
                </DataTemplate>
              </ListBox.ItemTemplate>
            </ListBox>
          </Border>
        </DockPanel>
      </Border>
    </Grid>

    <!-- Footer -->
    <Border Grid.Row="3" Padding="16,14">
      <DockPanel>
        <StackPanel DockPanel.Dock="Right" Orientation="Horizontal">
          <Button x:Name="OpenLogs" Style="{StaticResource Btn}" Content="Open logs"/>
          <Button x:Name="CopyOutput" Style="{StaticResource Btn}" Content="Copy output"/>
          <Button x:Name="StopBtn" Style="{StaticResource Danger}" Content="Stop" IsEnabled="False"/>
          <Button x:Name="RunBtn" Style="{StaticResource Primary}" Content="Run setup"/>
        </StackPanel>
        <TextBlock x:Name="FooterText" Foreground="#6B7280" VerticalAlignment="Center"/>
      </DockPanel>
    </Border>
  </Grid>
</Window>
'@

#endregion

#region ---------- Build window ----------

$window = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xaml))
$ui = @{}
$xaml.SelectNodes('//*[@*[local-name()="Name"]]') | ForEach-Object {
    $name = $_.Attributes | Where-Object { $_.LocalName -eq 'Name' } | Select-Object -First 1 -ExpandProperty Value
    $ui[$name] = $window.FindName($name)
}

$optItems   = New-Object 'System.Collections.ObjectModel.ObservableCollection[BloatBlasterGui.CheckItem]'
$bloatItems = New-Object 'System.Collections.ObjectModel.ObservableCollection[BloatBlasterGui.CheckItem]'
$stepItems  = New-Object 'System.Collections.ObjectModel.ObservableCollection[BloatBlasterGui.StepItem]'
$logItems   = New-Object 'System.Collections.ObjectModel.ObservableCollection[BloatBlasterGui.LogLine]'
$ui.OptList.ItemsSource   = $optItems
$ui.BloatList.ItemsSource = $bloatItems
$ui.StepChips.ItemsSource = $stepItems
$ui.Console.ItemsSource   = $logItems
foreach ($n in 1..10) { [void]$ui.UpdateCycles.Items.Add([int]$n) }

$state = @{
    Script      = $null      # parsed script info
    Runner      = $null
    Running     = $false
    ExitSeen    = $false
    Stopped     = $false
    Current     = $null      # running StepItem
    DoneCount   = 0
    WarnCount   = 0
    Reboot      = $false
    LogFile     = $null
    LastBlank   = $false
    Launcher    = $null
    Clock       = New-Object System.Diagnostics.Stopwatch
}

$ui.HostInfo.Text = "$([Environment]::MachineName)  |  $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
if (-not $isAdmin) {
    $ui.AdminBadge.Background = '#7F1D1D'
    $ui.AdminText.Foreground  = '#FEE2E2'
    $ui.AdminText.Text        = 'NOT ELEVATED'
}

#endregion

#region ---------- UI helpers ----------

function Confirm-Action {
    param([string]$Message, [string]$Title, [string]$Icon = 'Question')
    ([System.Windows.MessageBox]::Show($window, $Message, $Title, 'YesNo', $Icon)) -eq 'Yes'
}

function Show-Banner {
    param([string]$Text)
    if ($Text) { $ui.BannerText.Text = $Text; $ui.Banner.Visibility = 'Visible' }
    else       { $ui.Banner.Visibility = 'Collapsed' }
}

function Get-StepEnabled {
    param([string]$Key)
    $def = $StepDefs | Where-Object { $_.Key -eq $Key }
    [bool]$ui[$def.Box].IsChecked
}

function Update-Summary {
    $optSel   = @($optItems   | Where-Object IsChecked).Count
    $bloatSel = @($bloatItems | Where-Object IsChecked).Count
    $ui.OptCount.Text    = "$optSel of $($optItems.Count) selected"
    $ui.BloatCount.Text  = "$bloatSel of $($bloatItems.Count) will be removed"
    $ui.OptionalTab.Header = if ($optSel) { "Optional apps ($optSel)" } else { 'Optional apps' }
    $ui.BloatTab.Header    = "Bloatware ($bloatSel)"

    $steps = @($StepDefs | Where-Object { Get-StepEnabled $_.Key })
    $ui.FooterText.Text = '{0} step{1}  |  {2} optional app{3}  |  {4} bloatware app{5}' -f `
        $steps.Count, $(if ($steps.Count -eq 1) { '' } else { 's' }),
        $optSel,      $(if ($optSel -eq 1) { '' } else { 's' }),
        $bloatSel,    $(if ($bloatSel -eq 1) { '' } else { 's' })

    $ui.RunBtn.IsEnabled = (-not $state.Running) -and $isAdmin -and $state.Script -and $state.Script.SupportsGui -and $steps.Count -gt 0
}

# Same logic as Get-SmartAppControlState in the script: On, Evaluation, Off or NotAvailable
function Get-SmartAppControlState {
    try {
        switch ((Get-MpComputerStatus -ErrorAction Stop).SmartAppControlState) {
            'On'   { return 'On' }
            'Eval' { return 'Evaluation' }
            'Off'  { return 'Off' }
        }
    }
    catch { }
    $value = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name 'VerifiedAndReputablePolicyState' -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState
    switch ($value) { 0 { 'Off' } 1 { 'On' } 2 { 'Evaluation' } default { 'NotAvailable' } }
}

# Enables the Smart App Control option only when this PC has it on and the script supports it
function Update-SacOption {
    if (-not $state.SacState) { $state.SacState = Get-SmartAppControlState }
    $sac = $state.SacState
    $box = $ui.OptSmartApp

    if (-not ($state.Script -and $state.Script.SupportsSac)) {
        $box.IsChecked = $false; $box.IsEnabled = $false
        $ui.SacHint.Text = "This version of the script doesn't support it."
    }
    elseif ($sac -in 'On', 'Evaluation') {
        $box.IsEnabled = $true
        $ui.SacHint.Text = "Currently '$sac' on this PC. Can block some installers. Usually can't be turned back on without reinstalling Windows."
    }
    else {
        $box.IsChecked = $false; $box.IsEnabled = $false
        $ui.SacHint.Text = if ($sac -eq 'Off') { 'Already off on this PC.' } else { 'Not available on this PC.' }
    }
}

# Rebuilds the step chips as "pending" from the current checkboxes (not during or right after a run)
function Reset-StepChips {
    if ($state.Running) { return }
    $stepItems.Clear()
    foreach ($d in ($StepDefs | Where-Object { Get-StepEnabled $_.Key })) {
        $stepItems.Add((New-Object BloatBlasterGui.StepItem -Property @{ Key = $d.Key; Name = $d.Name }))
    }
    $ui.Progress.Maximum = [Math]::Max(1, $stepItems.Count)
    $ui.Progress.Value   = 0
}

# Called when the step selection changes
function Update-StepSelection {
    Reset-StepChips
    Update-Summary
}

function Update-PathStatus {
    $agents = $ui.AgentsBox.Text.Trim()
    if ($agents -and (Test-Path -LiteralPath $agents -PathType Container)) {
        $msis = @(Get-ChildItem -LiteralPath $agents -Filter *.msi -File -ErrorAction SilentlyContinue)
        $ui.AgentsStatus.Text       = if ($msis.Count) { "$([char]0x2714) $($msis.Count) MSI(s): $(($msis.Name) -join ', ')" } else { "$([char]0x26A0) Folder exists but has no MSI files." }
        $ui.AgentsStatus.Foreground = if ($msis.Count) { '#047857' } else { '#B45309' }
        $ui.AgentsHint.Text         = if ($msis.Count) { "$($msis.Count) MSI(s) in the agents folder." } else { 'The agents folder has no MSI files; this step will be skipped.' }
    }
    else {
        $ui.AgentsStatus.Text       = "$([char]0x26A0) Folder not found. The agents step will be skipped."
        $ui.AgentsStatus.Foreground = '#B45309'
        $ui.AgentsHint.Text         = 'Agents folder not found (see Paths); this step will be skipped.'
    }

    $office = $ui.OfficeBox.Text.Trim()
    $xml    = $ui.OfficeXmlBox.Text.Trim()
    $setupOk = $office -and (Test-Path -LiteralPath (Join-Path $office 'setup.exe') -PathType Leaf)
    $xmlOk   = $office -and $xml -and (Test-Path -LiteralPath (Join-Path $office $xml) -PathType Leaf)
    if ($setupOk -and $xmlOk) {
        $ui.OfficeStatus.Text = "$([char]0x2714) setup.exe and config found."; $ui.OfficeStatus.Foreground = '#047857'
        $ui.OfficeHint.Text   = "Uses $xml."
    }
    else {
        $missing = @(); if (-not $setupOk) { $missing += 'setup.exe' }; if (-not $xmlOk) { $missing += 'config XML' }
        $ui.OfficeStatus.Text = "$([char]0x26A0) Missing: $($missing -join ', '). Microsoft 365 install will fail."; $ui.OfficeStatus.Foreground = '#B45309'
        $ui.OfficeHint.Text   = 'Office files not found (see Paths).'
    }
}

function Import-ScriptInfo {
    param([string]$Path)

    $optItems.Clear(); $bloatItems.Clear()
    $state.Script = $null
    $ui.ScriptBox.Text = $Path

    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        $ui.ScriptStatus.Text = "$([char]0x26A0) Script not found."; $ui.ScriptStatus.Foreground = '#B91C1C'
        Show-Banner 'BloatBlaster script not found. Put this GUI next to BloatBlaster_Refactor.ps1, or pick the script on the Paths tab.'
        Update-Summary; return
    }

    try { $info = Read-BloatBlasterScript -Path $Path }
    catch {
        $ui.ScriptStatus.Text = "$([char]0x26A0) $($_.Exception.Message)"; $ui.ScriptStatus.Foreground = '#B91C1C'
        Show-Banner "Couldn't read the script: $($_.Exception.Message)"
        Update-Summary; return
    }
    $state.Script = $info

    foreach ($a in ($info.Optional | Sort-Object { $_.Name })) {
        $optItems.Add((New-Object BloatBlasterGui.CheckItem -Property @{ Name = $a.Name; Id = $a.Id; IsChecked = $false }))
    }
    foreach ($b in $info.Bloatware) {
        $bloatItems.Add((New-Object BloatBlasterGui.CheckItem -Property @{ Name = $b; Id = $b; IsChecked = $true }))
    }

    $req = ($info.Required | ForEach-Object { $_.Name }) -join ', '
    $ui.RequiredText.Text = if ($req) { "Always installed: $req" } else { 'No required apps defined.' }

    if ($info.LogFolder)        { $ui.LogBox.Text       = $info.LogFolder }
    if ($info.OfficeFolder)     { $ui.OfficeBox.Text    = $info.OfficeFolder }
    if ($info.OfficeConfigFile) { $ui.OfficeXmlBox.Text = $info.OfficeConfigFile }
    $ui.AgentsBox.Text = Join-Path (Split-Path -Parent $Path) 'agents'
    $ui.UpdateCycles.SelectedItem = if ($info.MaxUpdateCycles) { [int]$info.MaxUpdateCycles } else { 5 }

    $ui.ScriptStatus.Text = "$([char]0x2714) $($info.Optional.Count) optional apps, $($info.Required.Count) required, $($info.Bloatware.Count) bloatware entries."
    $ui.ScriptStatus.Foreground = '#047857'

    if (-not $info.SupportsGui) {
        Show-Banner "This version of $(Split-Path -Leaf $Path) has no -Unattended / -SkipStep parameters, so the GUI can't drive it. Use the updated BloatBlaster_Refactor.ps1."
    }
    elseif (-not $isAdmin) {
        Show-Banner 'Preview mode: not running as administrator, so Run setup is disabled.'
    }
    else { Show-Banner $null }

    Update-SacOption
    Update-PathStatus
    Update-StepSelection
}

function Select-Folder {
    param([string]$Start)
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($Start -and (Test-Path -LiteralPath $Start)) { $dlg.SelectedPath = $Start }
    if ($dlg.ShowDialog() -eq 'OK') { return $dlg.SelectedPath }
    return $null
}

function Select-File {
    param([string]$Filter, [string]$StartDir)
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Filter = $Filter
    if ($StartDir -and (Test-Path -LiteralPath $StartDir)) { $dlg.InitialDirectory = $StartDir }
    if ($dlg.ShowDialog($window)) { return $dlg.FileName }
    return $null
}

#endregion

#region ---------- Output handling ----------

function Complete-CurrentStep {
    param([string]$As)
    $cur = $state.Current
    if (-not $cur) { return }
    if (-not $As) { $As = if ($cur.Warnings -gt 0) { 'warn' } else { 'done' } }
    $cur.State = $As
    if ($As -ne 'stopped') { $state.DoneCount++ }
    $ui.Progress.Value = $state.DoneCount
    $state.Current = $null
}

function Enter-Section {
    param([string]$Title)

    if ($Title -eq 'Summary') {
        Complete-CurrentStep
        $ui.StatusTitle.Text = 'Wrapping up...'
        return
    }
    $def = $StepDefs | Where-Object { $Title -like $_.Section } | Select-Object -First 1
    if (-not $def) { return }

    Complete-CurrentStep
    $step = $stepItems | Where-Object { $_.Key -eq $def.Key } | Select-Object -First 1
    if (-not $step) { return }
    $step.State = 'running'
    $state.Current = $step
    $idx = $stepItems.IndexOf($step) + 1
    $ui.StatusTitle.Text  = "Running: $($step.Name)"
    $ui.StatusDetail.Text = "Step $idx of $($stepItems.Count)"
}

function Add-LogLine {
    param([string]$Text)

    # Drop winget spinner / progress bar noise
    if ($Text -match '^\s*[-\\|/]\s*$' -or $Text -match "[$([char]0x2588)$([char]0x2592)]") { return }
    if ([string]::IsNullOrWhiteSpace($Text)) {
        if ($state.LastBlank) { return }
        $state.LastBlank = $true
    }
    else { $state.LastBlank = $false }

    $color = '#CBD5E1'; $weight = 'Normal'
    if ($Text -match '^=== (.+) ===$') {
        $color = '#60A5FA'; $weight = 'Bold'
        Enter-Section $Matches[1]
    }
    elseif ($Text -match '^WARNING:') {
        $color = '#FBBF24'
        $state.WarnCount++
        if ($state.Current) { $state.Current.Warnings++; $state.Current.Touch() }
    }
    elseif ($Text -match '^ERROR:') {
        $color = '#F87171'
        if ($state.Current) { $state.Current.Warnings++; $state.Current.Touch() }
    }
    elseif ($Text -match '(?i)(already installed|skipping|not present|not found or already disabled|not reset\.|not changed\.|not installed\.|No registered Dropbox)') {
        $color = '#64748B'
    }
    elseif ($Text -match '(?i)(^\s*(installed|removed|disabled)\b|complete\.?$|verified\.?$|successfully|applied\.?$|created\.?$|is current\.?$|with no errors)') {
        $color = '#34D399'
    }

    if ($Text -match 'A reboot is required') { $state.Reboot = $true }
    if ($Text -match '^Log: (.+)$') { $state.LogFile = $Matches[1].Trim() }

    $logItems.Add((New-Object BloatBlasterGui.LogLine -Property @{ Text = $Text; Color = $color; Weight = $weight }))
}

function Set-RunningUi {
    param([bool]$Running)
    $state.Running = $Running
    $ui.ConfigPanel.IsEnabled = -not $Running
    $ui.StopBtn.IsEnabled     = $Running
    $ui.RunBtn.Content        = if ($Running) { 'Running...' } else { 'Run setup' }
    Update-Summary
}

function Complete-Run {
    $timer.Stop()
    $state.Clock.Stop()
    $code = try { $state.Runner.Proc.ExitCode } catch { -1 }

    if ($state.Stopped) {
        Complete-CurrentStep -As 'stopped'
        $ui.StatusTitle.Text = 'Stopped'
        $ui.StatusTitle.Foreground = '#B91C1C'
        $ui.StatusDetail.Text = 'Setup was stopped before it finished. Check the log, and re-run what is left.'
    }
    else {
        Complete-CurrentStep
        $ui.Progress.Value = $ui.Progress.Maximum
        if ($code -eq 0) {
            $ui.StatusTitle.Text = 'Finished with no errors'
            $ui.StatusTitle.Foreground = '#047857'
        }
        else {
            $ui.StatusTitle.Text = "Finished with errors (exit $code)"
            $ui.StatusTitle.Foreground = '#B45309'
        }
        $detail = @()
        if ($state.WarnCount) { $detail += "$($state.WarnCount) warning(s); review the amber lines." }
        if ($state.Reboot)    { $detail += 'Reboot required, then run Windows Update again.' }
        if ($state.LogFile)   { $detail += "Log: $($state.LogFile)" }
        $ui.StatusDetail.Text = if ($detail) { $detail -join '  ' } else { 'All done.' }
    }

    if ($state.Launcher) { Remove-Item -LiteralPath $state.Launcher -Force -ErrorAction SilentlyContinue }
    Set-RunningUi $false
    if ($logItems.Count) { $ui.Console.ScrollIntoView($logItems[$logItems.Count - 1]) }
}

$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromMilliseconds(150)
$timer.Add_Tick({
    $runner = $state.Runner
    if (-not $runner) { return }

    $line = $null; $added = 0
    while ($added -lt 1500 -and $runner.Lines.TryDequeue([ref]$line)) { Add-LogLine $line; $added++ }
    if ($added -and $logItems.Count) { $ui.Console.ScrollIntoView($logItems[$logItems.Count - 1]) }
    while ($logItems.Count -gt 30000) { $logItems.RemoveAt(0) }

    $ui.Elapsed.Text = $state.Clock.Elapsed.ToString('hh\:mm\:ss')

    if ($runner.Proc.HasExited) {
        if (-not $state.ExitSeen) { $runner.Proc.WaitForExit(); $state.ExitSeen = $true; return }   # flush output streams
        if ($runner.Lines.IsEmpty) { Complete-Run }
    }
})

#endregion

#region ---------- Run / stop ----------

function Start-Setup {
    $info = $state.Script
    $steps    = @($StepDefs | Where-Object { Get-StepEnabled $_.Key })
    $skip     = @($SkippableSteps | Where-Object { -not (Get-StepEnabled $_) })
    $optIds   = @($optItems   | Where-Object IsChecked | ForEach-Object Id)
    $optNames = @($optItems   | Where-Object IsChecked | ForEach-Object Name)
    $bloat    = @($bloatItems | Where-Object IsChecked | ForEach-Object Name)

    # Confirm
    $msg = "Run BloatBlaster on $([Environment]::MachineName)?`n`n" +
           "Steps: $(($steps | ForEach-Object Name) -join ', ')`n`n" +
           "Optional apps: $(if ($optNames) { $optNames -join ', ' } else { 'none' })`n" +
           "Bloatware to remove: $($bloat.Count) app(s)`n`n"
    if ((Get-StepEnabled 'Office') -and $ui.OfficeStatus.Text -like "$([char]0x26A0)*") { $msg += "Note: Microsoft 365 files are missing, so that step will fail.`n" }
    if ((Get-StepEnabled 'Taskbar')) { $msg += "Note: Explorer will restart to reset the taskbar.`n" }
    if ((Get-StepEnabled 'SmartAppControl')) { $msg += "Note: Smart App Control will be turned off. It usually can't be turned back on without reinstalling Windows.`n" }
    $msg += "`nThis changes system settings and can take an hour or more."
    if (-not (Confirm-Action $msg 'Run setup?' 'Question')) { return }

    # Build the unattended command
    $parts = @(
        '& ' + (ConvertTo-PSLiteral $info.Path),
        '-Unattended',
        '-OptionalAppIds ' + (ConvertTo-PSArrayLiteral $optIds),
        '-AppsToRemove '   + (ConvertTo-PSArrayLiteral $bloat),
        '-SkipStep '       + (ConvertTo-PSArrayLiteral $skip),
        '-MaxUpdateCycles ' + [int]$ui.UpdateCycles.SelectedItem
    )
    if ($ui.LogBox.Text.Trim())       { $parts += '-LogFolder '        + (ConvertTo-PSLiteral $ui.LogBox.Text.Trim()) }
    if ($ui.AgentsBox.Text.Trim())    { $parts += '-AgentsFolder '     + (ConvertTo-PSLiteral $ui.AgentsBox.Text.Trim()) }
    if ($ui.OfficeBox.Text.Trim())    { $parts += '-OfficeFolder '     + (ConvertTo-PSLiteral $ui.OfficeBox.Text.Trim()) }
    if ($ui.OfficeXmlBox.Text.Trim()) { $parts += '-OfficeConfigFile ' + (ConvertTo-PSLiteral $ui.OfficeXmlBox.Text.Trim()) }
    if (Get-StepEnabled 'Taskbar')    { $parts += '-ResetTaskbar' }
    if (Get-StepEnabled 'TimeZone')   { $parts += '-SetTimeZone' }
    if (Get-StepEnabled 'Office')     { $parts += '-InstallOffice' }
    if (Get-StepEnabled 'SmartAppControl') { $parts += '-DisableSmartAppControl' }

    $launcher = Join-Path $env:TEMP ("BloatBlaster_GUI_{0:yyyyMMdd_HHmmss}.ps1" -f (Get-Date))
    $body = @(
        '[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false'
        ($parts -join ' ')
        'exit $LASTEXITCODE'
    ) -join "`r`n"
    Set-Content -LiteralPath $launcher -Value $body -Encoding UTF8
    $state.Launcher = $launcher

    # Reset run state
    $logItems.Clear()
    $state.ExitSeen = $false; $state.Stopped = $false; $state.Current = $null
    $state.DoneCount = 0; $state.WarnCount = 0; $state.Reboot = $false; $state.LogFile = $null
    Reset-StepChips
    $ui.StatusTitle.Foreground = '#111827'
    $ui.StatusTitle.Text  = 'Starting...'
    $ui.StatusDetail.Text = "Step 0 of $($stepItems.Count)"
    Set-RunningUi $true

    $runner = New-Object BloatBlasterGui.Runner
    $state.Runner = $runner
    try {
        $runner.Start($psExe, "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$launcher`"", (Split-Path -Parent $info.Path))
    }
    catch {
        Set-RunningUi $false
        [void][System.Windows.MessageBox]::Show($window, "Couldn't start the script: $($_.Exception.Message)", 'BloatBlaster', 'OK', 'Error')
        return
    }
    $state.Clock.Restart()
    $timer.Start()
}

function Stop-Setup {
    param([switch]$NoConfirm)
    if (-not $state.Running) { return $true }
    if (-not $NoConfirm) {
        $ok = Confirm-Action "Stop setup now?`n`nStopping in the middle of Windows Update or an install can leave it half-finished. You can run setup again afterwards." 'Stop setup?' 'Warning'
        if (-not $ok) { return $false }
    }
    $state.Stopped = $true
    $ui.StatusTitle.Text = 'Stopping...'
    try { $state.Runner.KillTree() } catch { }
    return $true
}

#endregion

#region ---------- Events ----------

$ui.RunBtn.Add_Click({ Start-Setup })
$ui.StopBtn.Add_Click({ [void](Stop-Setup) })

$window.Add_Closing({
    param($s, $e)
    if ($state.Running) {
        if (-not (Stop-Setup)) { $e.Cancel = $true; return }
        $state.Runner.Proc.WaitForExit(10000) | Out-Null
    }
    $timer.Stop()
    if ($state.Launcher) { Remove-Item -LiteralPath $state.Launcher -Force -ErrorAction SilentlyContinue }
})

# Any step checkbox
$stepBoxes = $StepDefs | ForEach-Object { $_.Box }
foreach ($b in $stepBoxes) { $ui[$b].Add_Click({ Update-StepSelection }) }

# App installs need WinGet (these run before the generic handler above, then it refreshes)
$ui.StepApps.Add_Click({ if ($ui.StepApps.IsChecked) { $ui.StepWinGet.IsChecked = $true }; Update-StepSelection })
$ui.StepWinGet.Add_Click({ if (-not $ui.StepWinGet.IsChecked) { $ui.StepApps.IsChecked = $false }; Update-StepSelection })

$ui.StepsAll.Add_Click({  foreach ($b in $stepBoxes) { $ui[$b].IsChecked = $true };  Update-StepSelection })
$ui.StepsNone.Add_Click({ foreach ($b in $stepBoxes) { $ui[$b].IsChecked = $false }; Update-StepSelection })

# Checklist clicks bubble up from the item checkboxes
$listClick = [System.Windows.RoutedEventHandler]{ Update-Summary }
$ui.OptList.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, $listClick)
$ui.BloatList.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, $listClick)

$ui.OptClear.Add_Click({  foreach ($i in $optItems)   { $i.IsChecked = $false }; Update-Summary })
$ui.BloatAll.Add_Click({  foreach ($i in $bloatItems) { $i.IsChecked = $true };  Update-Summary })
$ui.BloatNone.Add_Click({ foreach ($i in $bloatItems) { $i.IsChecked = $false }; Update-Summary })

# Search filter for optional apps
$optView = [System.Windows.Data.CollectionViewSource]::GetDefaultView($optItems)
$ui.OptSearch.Add_TextChanged({
    $q = $ui.OptSearch.Text.Trim()
    $ui.OptSearchHint.Visibility = if ($q) { 'Hidden' } else { 'Visible' }
    if ($q) {
        $optView.Filter = [Predicate[object]]{ param($o) $o.Name -like "*$q*" -or $o.Id -like "*$q*" }.GetNewClosure()
    }
    else { $optView.Filter = $null }
})

# Paths
$ui.ScriptBrowse.Add_Click({
    $f = Select-File -Filter 'PowerShell scripts (*.ps1)|*.ps1' -StartDir (Split-Path -Parent $ui.ScriptBox.Text)
    if ($f) { Import-ScriptInfo $f }
})
$ui.ScriptReload.Add_Click({ Import-ScriptInfo $ui.ScriptBox.Text.Trim() })
$ui.LogBrowse.Add_Click({ $f = Select-Folder $ui.LogBox.Text; if ($f) { $ui.LogBox.Text = $f } })
$ui.AgentsBrowse.Add_Click({ $f = Select-Folder $ui.AgentsBox.Text; if ($f) { $ui.AgentsBox.Text = $f } })
$ui.OfficeBrowse.Add_Click({ $f = Select-Folder $ui.OfficeBox.Text; if ($f) { $ui.OfficeBox.Text = $f } })
$ui.OfficeXmlBrowse.Add_Click({
    $f = Select-File -Filter 'Office config (*.xml)|*.xml' -StartDir $ui.OfficeBox.Text
    if ($f) { $ui.OfficeBox.Text = Split-Path -Parent $f; $ui.OfficeXmlBox.Text = Split-Path -Leaf $f }
})
foreach ($tb in 'AgentsBox', 'OfficeBox', 'OfficeXmlBox') { $ui[$tb].Add_TextChanged({ Update-PathStatus }) }

# Footer
$ui.OpenLogs.Add_Click({
    if ($state.LogFile -and (Test-Path -LiteralPath $state.LogFile)) { Start-Process notepad.exe -ArgumentList "`"$($state.LogFile)`""; return }
    $dir = $ui.LogBox.Text.Trim()
    if ($dir -and (Test-Path -LiteralPath $dir)) { Start-Process explorer.exe -ArgumentList "`"$dir`"" }
    else { [void][System.Windows.MessageBox]::Show($window, "Log folder not found yet: $dir", 'BloatBlaster') }
})
$ui.CopyOutput.Add_Click({
    if ($logItems.Count) { [System.Windows.Clipboard]::SetText((($logItems | ForEach-Object Text) -join "`r`n")) }
})

#endregion

#region ---------- Start ----------

try {
    if (-not $ScriptPath) { $ScriptPath = Find-BloatBlasterScript }
    Import-ScriptInfo $ScriptPath
    if ($env:BLOATBLASTER_GUI_NOSHOW) { return }   # used by tests to load the window without showing it
    [void]$window.ShowDialog()
}
catch {
    [void][System.Windows.MessageBox]::Show("BloatBlaster GUI error:`n`n$($_.Exception.Message)", 'BloatBlaster', 'OK', 'Error')
}

#endregion
