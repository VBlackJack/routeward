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
  Checks the install sequence and custom actions of a built RouteWard MSI for the upgrade protection design.

.DESCRIPTION
  Opens the MSI read-only through the WindowsInstaller.Installer COM object and fails unless:
    - InstallValidate < RemoveExistingProducts < InstallInitialize (default MajorUpgrade schedule)
    - FindRelatedProducts, AppSearch, CostFinalize < the RouteWardOldCli setters
      < the capture command line setter < the capture action < InstallValidate
    - the MigrateUpgradeState setter < MigrateUpgradeState < InstallFinalize
    - the capture is an immediate impersonated action that continues on failure (type has 0x40, no 0x400)
    - MigrateUpgradeState is a deferred-class commit action without impersonation that continues on
      failure (type has 0x400, 0x200, 0x800 and 0x40)
    - the capture command line setter writes the fixed property WixQuietExecCmdLine
    - no deferred custom action is sequenced before InstallInitialize (it would make Windows Installer
      fail the upgrade with error 2613)
  Any missing row fails the check.

.PARAMETER MsiPath
  Path of the built .msi file.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$MsiPath
)

$ErrorActionPreference = 'Stop'

$CaptureAction = 'CaptureOldProtectionStatus'
$CaptureCmdLineSetter = 'SetRouteWardCaptureCmdLine'
$OldCliSetters = @('SetRouteWardOldCliWithSlash', 'SetRouteWardOldCliNoSlash')
$DecideAction = 'MigrateUpgradeState'
$CmdLineProperty = 'WixQuietExecCmdLine'
$SequenceQuery = 'SELECT Action, Sequence FROM InstallExecuteSequence'
$CustomActionQuery = 'SELECT Action, Type, Source, Target FROM CustomAction'
$OpenDatabaseReadOnly = 0
$NullInteger = [int]::MinValue
$TypeInScript = 0x400
$TypeCommit = 0x200
$TypeNoImpersonate = 0x800
$TypeContinue = 0x40

function Invoke-Com($Target, [string]$Member, [string]$Kind, $Arguments) {
    return $Target.GetType().InvokeMember($Member, $Kind, $null, $Target, $Arguments)
}

function Read-Rows($Database, [string]$Query, [scriptblock]$Convert) {
    $view = Invoke-Com $Database 'OpenView' 'InvokeMethod' @($Query)
    Invoke-Com $view 'Execute' 'InvokeMethod' $null | Out-Null
    $rows = @()
    while ($true) {
        $record = Invoke-Com $view 'Fetch' 'InvokeMethod' $null
        if ($null -eq $record) { break }
        $rows += & $Convert $record
    }
    Invoke-Com $view 'Close' 'InvokeMethod' $null | Out-Null
    return $rows
}

function Get-RecordString($Record, [int]$Field) {
    return [string](Invoke-Com $Record 'StringData' 'GetProperty' @($Field))
}

function Get-RecordInteger($Record, [int]$Field) {
    return [int](Invoke-Com $Record 'IntegerData' 'GetProperty' @($Field))
}

$resolved = (Resolve-Path -LiteralPath $MsiPath).Path
$installer = New-Object -ComObject WindowsInstaller.Installer
$database = Invoke-Com $installer 'OpenDatabase' 'InvokeMethod' @($resolved, $OpenDatabaseReadOnly)

$sequence = @{}
foreach ($row in (Read-Rows $database $SequenceQuery {
            param($record)
            [pscustomobject]@{
                Action   = (Get-RecordString $record 1)
                Sequence = (Get-RecordInteger $record 2)
            }
        })) {
    $sequence[$row.Action] = $row.Sequence
}

$customActions = @{}
foreach ($row in (Read-Rows $database $CustomActionQuery {
            param($record)
            [pscustomobject]@{
                Action = (Get-RecordString $record 1)
                Type   = (Get-RecordInteger $record 2)
                Source = (Get-RecordString $record 3)
                Target = (Get-RecordString $record 4)
            }
        })) {
    $customActions[$row.Action] = $row
}

$failures = New-Object System.Collections.Generic.List[string]

function Assert-Present([string]$Name) {
    if (-not $sequence.ContainsKey($Name)) {
        $message = "missing from InstallExecuteSequence: $Name"
        if (-not $failures.Contains($message)) { $failures.Add($message) }
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

function Get-CustomAction([string]$Name) {
    if (-not $customActions.ContainsKey($Name)) {
        $failures.Add("missing from CustomAction: $Name")
        return $null
    }
    return $customActions[$Name]
}

function Assert-TypeFlags([string]$Name, [int[]]$Required, [int[]]$Forbidden) {
    $action = Get-CustomAction $Name
    if ($null -eq $action) { return }
    foreach ($flag in $Required) {
        if (($action.Type -band $flag) -ne $flag) {
            $failures.Add("$Name type $($action.Type) lacks flag 0x$($flag.ToString('X'))")
        }
    }
    foreach ($flag in $Forbidden) {
        if (($action.Type -band $flag) -ne 0) {
            $failures.Add("$Name type $($action.Type) must not have flag 0x$($flag.ToString('X'))")
        }
    }
}

# The default MajorUpgrade schedule: the old product is removed after InstallValidate, in its own transaction.
Assert-Before 'InstallValidate' 'RemoveExistingProducts'
Assert-Before 'RemoveExistingProducts' 'InstallInitialize'

# The capture and the setters that feed it run once the old product is detected, before InstallValidate.
Assert-Before $CaptureCmdLineSetter $CaptureAction
Assert-Before $CaptureAction 'InstallValidate'
foreach ($setter in $OldCliSetters) {
    foreach ($earlier in @('FindRelatedProducts', 'AppSearch', 'CostFinalize')) {
        Assert-Before $earlier $setter
    }
    Assert-Before $setter $CaptureCmdLineSetter
}

# The decision runs in the commit phase, with its own setter before it.
$decideSetters = @($sequence.Keys | Where-Object { $_ -ne $DecideAction -and $_.EndsWith($DecideAction) })
if ($decideSetters.Count -eq 0) { $failures.Add("no SetProperty action found for $DecideAction") }
foreach ($setter in $decideSetters) { Assert-Before $setter $DecideAction }
Assert-Before $DecideAction 'InstallFinalize'

Assert-TypeFlags $CaptureAction @($TypeContinue) @($TypeInScript)
Assert-TypeFlags $DecideAction @($TypeInScript, $TypeCommit, $TypeNoImpersonate, $TypeContinue) @()

$cmdLineSetter = Get-CustomAction $CaptureCmdLineSetter
if ($null -ne $cmdLineSetter -and $cmdLineSetter.Source -ne $CmdLineProperty) {
    $failures.Add("$CaptureCmdLineSetter must set $CmdLineProperty, it sets '$($cmdLineSetter.Source)'")
}

# A deferred action generated before InstallInitialize makes the upgrade fail with error 2613.
if (Assert-Present 'InstallInitialize') {
    foreach ($name in $sequence.Keys) {
        if ($sequence[$name] -eq $NullInteger -or $sequence[$name] -ge $sequence['InstallInitialize']) { continue }
        if ($customActions.ContainsKey($name) -and (($customActions[$name].Type -band $TypeInScript) -ne 0)) {
            $failures.Add("deferred custom action $name ($($sequence[$name])) is sequenced before InstallInitialize")
        }
    }
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) { Write-Host "ERROR: $failure" }
    exit 1
}
Write-Host "MSI upgrade sequence and custom actions are correct: $resolved"
