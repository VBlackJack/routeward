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
    [string]$BinaryPath = (Join-Path $PSScriptRoot 'routeward.exe')
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
