<#
Copyright 2026 Julien Bombled

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
#>

[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$DemandStart,
    [switch]$NoStart,
    [string[]]$AllowSid = @(),
    [switch]$AllowCurrentUser,
    [string]$BinaryPath = (Join-Path $PSScriptRoot 'routeward.exe'),
    # Admin-only location the LocalSystem service binary is copied to (never run from the extraction folder).
    [string]$InstallDir = (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'RouteWard')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator privileges are required to manage the RouteWard Windows Service.'
}

if (-not (Test-Path -LiteralPath $BinaryPath)) {
    throw "RouteWard CLI binary not found: $BinaryPath"
}

function Invoke-RouteWardServiceCli {
    param(
        [string[]]$CliArgs,
        [switch]$IgnoreFailure,
        [switch]$Quiet
    )

    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        # PowerShell 5.1 turns native stderr (human status lines) into a terminating error
        # when $ErrorActionPreference is 'Stop', even when the command exits 0.
        $rawRecords = & $BinaryPath @CliArgs 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $prevPref
    }

    $stdoutLines = [System.Collections.Generic.List[string]]::new()
    $stderrLines = [System.Collections.Generic.List[string]]::new()
    foreach ($rec in @($rawRecords)) {
        if ($rec -is [System.Management.Automation.ErrorRecord]) {
            $stderrLines.Add($rec.ToString())
        }
        elseif ($null -ne $rec) {
            $stdoutLines.Add($rec.ToString())
        }
    }

    if (-not $Quiet -and $stdoutLines.Count -gt 0) {
        $stdoutLines | Write-Output
    }
    if (-not $IgnoreFailure -and $exitCode -ne 0) {
        $cmdLine = $CliArgs -join ' '
        $errDetail = ($stderrLines -join ' ').Trim()
        if ([string]::IsNullOrWhiteSpace($errDetail)) {
            $errDetail = ($stdoutLines -join ' ').Trim()
        }
        if ([string]::IsNullOrWhiteSpace($errDetail)) {
            throw "RouteWard command '$cmdLine' failed with exit code $exitCode"
        }
        throw "RouteWard command '$cmdLine' failed with exit code ${exitCode}: $errDetail"
    }
}

if ($Uninstall) {
    Invoke-RouteWardServiceCli -CliArgs @('service', 'stop') -IgnoreFailure -Quiet
    Invoke-RouteWardServiceCli -CliArgs @('service', 'uninstall')
    exit 0
}

# The service runs as LocalSystem: its binary must live in a directory only administrators can write to.
# Copy the bundle out of the (user-writable) extraction folder and register the installed copy.
function Copy-RouteWardBundle {
    param([string]$SourceExe, [string]$DestDir)

    $sourceDir = Split-Path -Parent (Resolve-Path -LiteralPath $SourceExe).Path
    $destFull = [System.IO.Path]::GetFullPath($DestDir).TrimEnd('\')
    if ([string]::Equals($sourceDir.TrimEnd('\'), $destFull, [StringComparison]::OrdinalIgnoreCase)) {
        return (Join-Path $destFull (Split-Path -Leaf $SourceExe))
    }

    try {
        # A running service keeps its executable locked: stop it before replacing the files.
        Invoke-RouteWardServiceCli -CliArgs @('service', 'stop') -IgnoreFailure -Quiet
        New-Item -ItemType Directory -Path $destFull -Force | Out-Null
        Copy-Item -LiteralPath $SourceExe -Destination (Join-Path $destFull 'routeward.exe') -Force
        $desktopExe = Join-Path $sourceDir 'routeward-desktop.exe'
        if (Test-Path -LiteralPath $desktopExe) {
            Copy-Item -LiteralPath $desktopExe -Destination (Join-Path $destFull 'routeward-desktop.exe') -Force
        }
        $windivertSource = Join-Path $sourceDir 'third_party\windivert\bin'
        if (Test-Path -LiteralPath $windivertSource) {
            $windivertDest = Join-Path $destFull 'third_party\windivert\bin'
            New-Item -ItemType Directory -Path $windivertDest -Force | Out-Null
            Copy-Item -Path (Join-Path $windivertSource '*') -Destination $windivertDest -Recurse -Force
        }
        # The first windivertDllPaths entry is a WinDivert.dll sitting next to routeward.exe:
        # copy that root-level pair too (the driver is loaded from the same directory).
        foreach ($rootFile in @('WinDivert.dll', 'WinDivert64.sys')) {
            $rootSource = Join-Path $sourceDir $rootFile
            if (Test-Path -LiteralPath $rootSource) {
                Copy-Item -LiteralPath $rootSource -Destination (Join-Path $destFull $rootFile) -Force
            }
        }
    }
    catch {
        throw "Failed to copy RouteWard files to '$destFull': $($_.Exception.Message)"
    }
    return (Join-Path $destFull 'routeward.exe')
}

$BinaryPath = Copy-RouteWardBundle -SourceExe $BinaryPath -DestDir $InstallDir
Write-Output "RouteWard service binary: $BinaryPath"

$installArgs = [System.Collections.Generic.List[string]]::new()
$installArgs.Add('service')
$installArgs.Add('install')
$installArgs.Add('--bin-path')
$installArgs.Add($BinaryPath)

if ($AllowCurrentUser -or $AllowSid.Count -eq 0) {
    $installArgs.Add('--allow-current-user')
}
foreach ($sid in $AllowSid) {
    if (-not [string]::IsNullOrWhiteSpace($sid)) {
        $installArgs.Add('--allow-sid')
        $installArgs.Add($sid.Trim())
    }
}
if ($DemandStart) {
    $installArgs.Add('--demand-start')
}

Invoke-RouteWardServiceCli -CliArgs ($installArgs.ToArray()) | Out-Null

if (-not $NoStart) {
    Invoke-RouteWardServiceCli -CliArgs @('service', 'start') | Out-Null
}
