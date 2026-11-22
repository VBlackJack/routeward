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

<#
.SYNOPSIS
  Checks the InstallExecuteSequence of a built RouteWard MSI for the upgrade protection ordering.

.DESCRIPTION
  Opens the MSI read-only through the WindowsInstaller.Installer COM object and fails unless:
    - InstallInitialize < each capture SetProperty and capture action < RemoveExistingProducts
    - RemoveExistingProducts > InstallInitialize
    - MigrateUpgradeState and its SetProperty < InstallFinalize
  The SetProperty rows are the sequence entries whose name ends with the name of the action they
  feed (WiX prefixes the generated action name).

.PARAMETER MsiPath
  Path of the built .msi file.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$MsiPath
)

$ErrorActionPreference = 'Stop'

$CaptureActions = @('CaptureOldProtectionStatus', 'CaptureOldProtectionStatusNoSlash')
$DecideAction = 'MigrateUpgradeState'
$SequenceQuery = 'SELECT Action, Sequence FROM InstallExecuteSequence'
$OpenDatabaseReadOnly = 0

function Invoke-Com($Target, [string]$Member, [string]$Kind, $Arguments) {
    return $Target.GetType().InvokeMember($Member, $Kind, $null, $Target, $Arguments)
}

$resolved = (Resolve-Path -LiteralPath $MsiPath).Path
$installer = New-Object -ComObject WindowsInstaller.Installer
$database = Invoke-Com $installer 'OpenDatabase' 'InvokeMethod' @($resolved, $OpenDatabaseReadOnly)
$view = Invoke-Com $database 'OpenView' 'InvokeMethod' @($SequenceQuery)
Invoke-Com $view 'Execute' 'InvokeMethod' $null | Out-Null

$sequence = @{}
while ($true) {
    $record = Invoke-Com $view 'Fetch' 'InvokeMethod' $null
    if ($null -eq $record) { break }
    $name = Invoke-Com $record 'StringData' 'GetProperty' @(1)
    $number = Invoke-Com $record 'IntegerData' 'GetProperty' @(2)
    $sequence[$name] = [int]$number
}
Invoke-Com $view 'Close' 'InvokeMethod' $null | Out-Null

$failures = New-Object System.Collections.Generic.List[string]

function Assert-Present([string]$Name) {
    if (-not $sequence.ContainsKey($Name)) {
        $failures.Add("missing from InstallExecuteSequence: $Name")
        return $false
    }
    return $true
}

function Assert-Before([string]$Left, [string]$Right) {
    if (-not (Assert-Present $Left)) { return }
    if (-not (Assert-Present $Right)) { return }
    if (-not ($sequence[$Left] -lt $sequence[$Right])) {
        $failures.Add("$Left ($($sequence[$Left])) must run before $Right ($($sequence[$Right]))")
    }
}

function Get-SetPropertyActions([string]$Action) {
    return @($sequence.Keys | Where-Object { $_ -ne $Action -and $_.EndsWith($Action) })
}

Assert-Before 'InstallInitialize' 'RemoveExistingProducts'

foreach ($action in $CaptureActions) {
    Assert-Before 'InstallInitialize' $action
    Assert-Before $action 'RemoveExistingProducts'
    $setters = Get-SetPropertyActions $action
    if ($setters.Count -eq 0) { $failures.Add("no SetProperty action found for $action") }
    foreach ($setter in $setters) {
        Assert-Before 'InstallInitialize' $setter
        Assert-Before $setter 'RemoveExistingProducts'
    }
}

Assert-Before $DecideAction 'InstallFinalize'
$decideSetters = Get-SetPropertyActions $DecideAction
if ($decideSetters.Count -eq 0) { $failures.Add("no SetProperty action found for $DecideAction") }
foreach ($setter in $decideSetters) {
    Assert-Before $setter 'InstallFinalize'
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) { Write-Host "ERROR: $failure" }
    exit 1
}
Write-Host "MSI InstallExecuteSequence ordering is correct: $resolved"
