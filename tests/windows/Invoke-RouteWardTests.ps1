<#
 * Copyright 2026 Julien Bombled
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$ConfirmTestMachine,

    [Parameter(Mandatory = $false)]
    [string]$BinDir = (Get-Location).Path,

    [Parameter(Mandatory = $false)]
    [string]$SystemConstantsJsonPath = "",

    [Parameter(Mandatory = $false)]
    [string]$DefaultProfileJsonPath = "",

    [Parameter(Mandatory = $false)]
    [string]$RouteWardExeName = "routeward.exe",

    [Parameter(Mandatory = $false)]
    [string]$DesktopExeName = "routeward-desktop.exe",

    [Parameter(Mandatory = $false)]
    [string[]]$WinDivertFileNames = @("WinDivert.dll", "WinDivert64.sys"),

    [Parameter(Mandatory = $false)]
    [string]$WinDivertSubDir = "third_party\windivert\bin",

    [Parameter(Mandatory = $false)]
    [string]$CurlExePath = (Join-Path $env:SystemRoot "System32\curl.exe"),

    [Parameter(Mandatory = $false)]
    [string]$Socks5Host = "127.0.0.1",

    [Parameter(Mandatory = $false)]
    [int]$Socks5Port = 1080,

    [Parameter(Mandatory = $false)]
    [string]$PipeName = "\\.\pipe\routeward-daemon",

    [Parameter(Mandatory = $false)]
    [int]$TransparentRelayPort = 10810,

    [Parameter(Mandatory = $false)]
    [string]$FirewallRulePrefix = "RouteWard_TransparentRelay_",

    [Parameter(Mandatory = $false)]
    [string]$FirewallRuleName = "",

    [Parameter(Mandatory = $false)]
    [string]$ExpectedProxyRuleName = "CLI Tools via SOCKS5 Proxy",

    [Parameter(Mandatory = $false)]
    [string]$TempBlockRuleId = "rule-win-regression-block-curl",

    [Parameter(Mandatory = $false)]
    [string]$TempBlockRuleName = "Temporary Windows Regression Block Curl",

    [Parameter(Mandatory = $false)]
    [string]$TestUrl = "http://example.com",

    [Parameter(Mandatory = $false)]
    [string]$ExpectedHttpStatus = "200",

    [Parameter(Mandatory = $false)]
    [string]$AppDataFolderName = "RouteWard",

    [Parameter(Mandatory = $false)]
    [string]$ProfileFileName = "active_profile.json",

    [Parameter(Mandatory = $false)]
    [string]$LogsFolderName = "logs",

    [Parameter(Mandatory = $false)]
    [string]$LogFilePrefix = "RouteWard",

    [Parameter(Mandatory = $false)]
    [string]$ExpectedCleanupLogText = "Removed scoped inbound firewall rule",

    [Parameter(Mandatory = $false)]
    [string[]]$AllowedProfileSids = @("S-1-5-18", "S-1-5-32-544"),

    [Parameter(Mandatory = $false)]
    [string[]]$ForbiddenPipeTrustees = @("WD", "BU", "AU", "S-1-1-0", "S-1-5-32-545", "S-1-5-11"),

    [Parameter(Mandatory = $false)]
    [int]$PipeReadyTimeoutMs = 10000,

    [Parameter(Mandatory = $false)]
    [int]$PollIntervalMs = 200,

    [Parameter(Mandatory = $false)]
    [int]$TcpConnectTimeoutMs = 3000,

    [Parameter(Mandatory = $false)]
    [int]$CurlTimeoutSec = 15,

    [Parameter(Mandatory = $false)]
    [int]$LogFlushWaitMs = 700,

    [Parameter(Mandatory = $false)]
    [int]$ReportLogTailLines = 30,

    [Parameter(Mandatory = $false)]
    [string]$ReportFilePrefix = "RouteWard_TestReport_"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Guardrail 1: Refuse execution without explicit -ConfirmTestMachine switch
# ---------------------------------------------------------------------------
if (-not $ConfirmTestMachine.IsPresent) {
    Write-Host "[ABORT] Refusing to run without the explicit -ConfirmTestMachine switch." -ForegroundColor Yellow
    Write-Host "This script starts WinDivert packet interception and controls the RouteWard daemon."
    Write-Host "Launch inside the dedicated Windows test VM with:"
    Write-Host "  .\Invoke-RouteWardTests.ps1 -ConfirmTestMachine"
    exit 2
}

# ---------------------------------------------------------------------------
# Load defaults from configs/ when present (zero hardcoding)
# ---------------------------------------------------------------------------
$repoRootCandidate = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ([string]::IsNullOrWhiteSpace($SystemConstantsJsonPath)) {
    $candidateConsts = Join-Path $repoRootCandidate "configs\system_constants.json"
    if (Test-Path -LiteralPath $candidateConsts) {
        $SystemConstantsJsonPath = $candidateConsts
    }
}
if (-not [string]::IsNullOrWhiteSpace($SystemConstantsJsonPath) -and (Test-Path -LiteralPath $SystemConstantsJsonPath)) {
    $sysConsts = Get-Content -LiteralPath $SystemConstantsJsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $PSBoundParameters.ContainsKey("PipeName") -and $sysConsts.ipc.windowsPipeName) {
        $PipeName = [string]$sysConsts.ipc.windowsPipeName
    }
    if (-not $PSBoundParameters.ContainsKey("TransparentRelayPort") -and $sysConsts.network.defaultTransparentTcpPort) {
        $TransparentRelayPort = [int]$sysConsts.network.defaultTransparentTcpPort
    }
    if (-not $PSBoundParameters.ContainsKey("LogsFolderName") -and $sysConsts.telemetry.logDirectory) {
        $LogsFolderName = [string]$sysConsts.telemetry.logDirectory
    }
    if (-not $PSBoundParameters.ContainsKey("LogFilePrefix") -and $sysConsts.telemetry.logAppName) {
        $LogFilePrefix = [string]$sysConsts.telemetry.logAppName
    }
}

if ([string]::IsNullOrWhiteSpace($DefaultProfileJsonPath)) {
    $candidateProf = Join-Path $repoRootCandidate "configs\default_profile.json"
    if (Test-Path -LiteralPath $candidateProf) {
        $DefaultProfileJsonPath = $candidateProf
    }
}
if (-not [string]::IsNullOrWhiteSpace($DefaultProfileJsonPath) -and (Test-Path -LiteralPath $DefaultProfileJsonPath)) {
    $defProf = Get-Content -LiteralPath $DefaultProfileJsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $defProxies = @($defProf.proxies)
    if (-not $PSBoundParameters.ContainsKey("Socks5Host") -and $defProxies.Count -gt 0) {
        $Socks5Host = [string]$defProxies[0].host
    }
    if (-not $PSBoundParameters.ContainsKey("Socks5Port") -and $defProxies.Count -gt 0) {
        $Socks5Port = [int]$defProxies[0].port
    }
}

if ([string]::IsNullOrWhiteSpace($FirewallRuleName)) {
    $FirewallRuleName = "${FirewallRulePrefix}${TransparentRelayPort}"
}

$programDataRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$localAppDataRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
$programDataAppDir = Join-Path $programDataRoot $AppDataFolderName
$activeProfilePath = Join-Path $programDataAppDir $ProfileFileName
$daemonLogsDir = Join-Path $programDataAppDir $LogsFolderName
$userLogsDir = Join-Path (Join-Path $localAppDataRoot $AppDataFolderName) $LogsFolderName
$logWildcard = "${LogFilePrefix}_*.log"

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-TcpEndpoint {
    param(
        [string]$TargetHost,
        [int]$Port,
        [int]$TimeoutMs
    )
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    try {
        $asyncResult = $tcpClient.BeginConnect($TargetHost, $Port, $null, $null)
        if (-not $asyncResult.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            return $false
        }
        $tcpClient.EndConnect($asyncResult)
        return $true
    } catch {
        return $false
    } finally {
        $tcpClient.Close()
    }
}

function Test-NamedPipeExists {
    param([string]$FullPipePath)
    $leafName = $FullPipePath -replace '^\\\\\.\\pipe\\', ''
    try {
        $matchesFound = [System.IO.Directory]::GetFiles("\\.\pipe\", $leafName)
        return ($null -ne $matchesFound -and $matchesFound.Length -gt 0)
    } catch {
        return (Test-Path -LiteralPath $FullPipePath)
    }
}

function Wait-ForNamedPipe {
    param(
        [string]$FullPipePath,
        [int]$TimeoutMs,
        [int]$IntervalMs
    )
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($stopwatch.ElapsedMilliseconds -lt $TimeoutMs) {
        if (Test-NamedPipeExists -FullPipePath $FullPipePath) {
            return $true
        }
        Start-Sleep -Milliseconds $IntervalMs
    }
    return (Test-NamedPipeExists -FullPipePath $FullPipePath)
}

function Test-FirewallRulePresent {
    param([string]$RuleName)
    $null = & netsh.exe advfirewall firewall show rule name="$RuleName" 2>&1
    return ($LASTEXITCODE -eq 0)
}

function Remove-SensitiveText {
    param([string]$InputText)
    if ([string]::IsNullOrEmpty($InputText)) {
        return ""
    }
    $redacted = $InputText -replace '("password"\s*:\s*)"[^"]*"', '$1"[REDACTED]"'
    $redacted = $redacted -replace '(password\s*=\s*)[^\s,;"]+', '$1[REDACTED]'
    return $redacted
}

$script:RawCtlCapture = New-Object System.Collections.Generic.List[string]

function Invoke-RouteWardCtl {
    param(
        [string]$ExePath,
        [string[]]$CtlArgs,
        [string]$Label
    )
    $argList = @("ctl") + $CtlArgs
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $outputLines = & $ExePath @argList 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevEap
    }
    $rawText = ($outputLines | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
    $sanitized = Remove-SensitiveText -InputText $rawText
    $script:RawCtlCapture.Add("--- [$Label] routeward $($argList -join ' ') (exit=$exitCode) ---`r`n$sanitized")
    return [PSCustomObject]@{
        ExitCode = $exitCode
        RawText  = $rawText
    }
}

function Invoke-UnproxiedCurl {
    param(
        [string]$CurlBin,
        [string]$Url,
        [int]$TimeoutSec
    )
    $proxyVars = @("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy")
    $savedVars = @{}
    foreach ($v in $proxyVars) {
        $savedVars[$v] = [Environment]::GetEnvironmentVariable($v, "Process")
        [Environment]::SetEnvironmentVariable($v, $null, "Process")
    }
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $out = & $CurlBin --noproxy "" -s -S -o NUL -w "%{http_code}" --max-time $TimeoutSec $Url 2>&1
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevEap
        foreach ($v in $proxyVars) {
            [Environment]::SetEnvironmentVariable($v, $savedVars[$v], "Process")
        }
    }
    $raw = ($out | ForEach-Object { $_.ToString() }) -join ""
    return [PSCustomObject]@{
        ExitCode = $code
        HttpCode = $raw.Trim()
    }
}

function Start-DaemonBackground {
    param(
        [string]$ExePath,
        [string]$WorkDir
    )
    $proc = Start-Process -FilePath $ExePath -ArgumentList @("daemon") -WorkingDirectory $WorkDir -WindowStyle Hidden -PassThru
    return $proc
}

function Stop-DaemonProcess {
    param([System.Diagnostics.Process]$ProcessObj)
    if ($null -ne $ProcessObj) {
        try {
            if (-not $ProcessObj.HasExited) {
                Stop-Process -Id $ProcessObj.Id -Force -ErrorAction SilentlyContinue
                $null = $ProcessObj.WaitForExit(3000)
            }
        } catch {
            # Ignore if process already exited
        }
    }
}

# ---------------------------------------------------------------------------
# Guardrail 2: Pre-flight validation (before touching anything)
# ---------------------------------------------------------------------------
if (-not (Test-IsAdministrator)) {
    Write-Host "[ABORT] Pre-flight check failed: PowerShell session must run as Administrator." -ForegroundColor Red
    exit 2
}

$resolvedBinDir = $BinDir
if (-not (Test-Path -LiteralPath (Join-Path $resolvedBinDir $RouteWardExeName))) {
    $releaseCandidate = Join-Path $repoRootCandidate "target\release"
    if (Test-Path -LiteralPath (Join-Path $PSScriptRoot $RouteWardExeName)) {
        $resolvedBinDir = $PSScriptRoot
    } elseif (Test-Path -LiteralPath (Join-Path $releaseCandidate $RouteWardExeName)) {
        $resolvedBinDir = $releaseCandidate
    }
}

$routeWardExePath = Join-Path $resolvedBinDir $RouteWardExeName
$desktopExePath = Join-Path $resolvedBinDir $DesktopExeName

if (-not (Test-Path -LiteralPath $routeWardExePath)) {
    Write-Host "[ABORT] Pre-flight check failed: Missing CLI binary at '$routeWardExePath'." -ForegroundColor Red
    exit 2
}
if (-not (Test-Path -LiteralPath $desktopExePath)) {
    Write-Host "[ABORT] Pre-flight check failed: Missing desktop binary at '$desktopExePath'." -ForegroundColor Red
    exit 2
}
if (-not (Test-Path -LiteralPath $CurlExePath)) {
    Write-Host "[ABORT] Pre-flight check failed: Missing curl binary at '$CurlExePath'." -ForegroundColor Red
    exit 2
}

$resolvedWinDivertFiles = New-Object System.Collections.Generic.List[string]
foreach ($wdFile in $WinDivertFileNames) {
    $directCandidate = Join-Path $resolvedBinDir $wdFile
    $subDirCandidate = Join-Path (Join-Path $resolvedBinDir $WinDivertSubDir) $wdFile
    if (Test-Path -LiteralPath $directCandidate) {
        $resolvedWinDivertFiles.Add($directCandidate)
    } elseif (Test-Path -LiteralPath $subDirCandidate) {
        $resolvedWinDivertFiles.Add($subDirCandidate)
    } else {
        Write-Host "[ABORT] Pre-flight check failed: Missing WinDivert file '$wdFile' in '$resolvedBinDir' or '$subDirCandidate'." -ForegroundColor Red
        exit 2
    }
}

$runningRouteWard = @(Get-Process -Name "routeward", "routeward-desktop" -ErrorAction SilentlyContinue)
if ($runningRouteWard.Count -gt 0) {
    $runningList = ($runningRouteWard | ForEach-Object { "$($_.ProcessName) (PID $($_.Id))" }) -join ", "
    Write-Host "[ABORT] Pre-flight check failed: RouteWard process already running ($runningList)." -ForegroundColor Red
    exit 2
}

if (-not (Test-TcpEndpoint -TargetHost $Socks5Host -Port $Socks5Port -TimeoutMs $TcpConnectTimeoutMs)) {
    Write-Host "[ABORT] Pre-flight check failed: Upstream SOCKS5 proxy at ${Socks5Host}:${Socks5Port} is not reachable." -ForegroundColor Red
    exit 2
}

# ---------------------------------------------------------------------------
# State tracking and profile backup for try/finally restoration
# ---------------------------------------------------------------------------
$scriptStartTime = Get-Date
$cwdPath = (Get-Location).Path
$cwdLogsDir = Join-Path $cwdPath $LogsFolderName
$cwdLogsExistedBefore = Test-Path -LiteralPath $cwdLogsDir

$profileExistedAtStart = Test-Path -LiteralPath $activeProfilePath
$initialProfileBytes = $null
if ($profileExistedAtStart) {
    $initialProfileBytes = [System.IO.File]::ReadAllBytes($activeProfilePath)
}
$profileCapturedAfterDaemonInit = $false
$profileModifiedByScript = $false

$script:DaemonProcess = $null
$scenarioResults = New-Object System.Collections.Generic.List[PSCustomObject]
$auditNotes = New-Object System.Collections.Generic.List[string]

function Record-ScenarioResult {
    param(
        [string]$Id,
        [ValidateSet("PASS", "FAIL", "SKIP")]
        [string]$Status,
        [string]$Title,
        [string]$Detail
    )
    $line = "[$Status] Scenario ($Id) $Title - $Detail"
    switch ($Status) {
        "PASS" { Write-Host $line -ForegroundColor Green }
        "FAIL" { Write-Host $line -ForegroundColor Red }
        "SKIP" { Write-Host $line -ForegroundColor Yellow }
    }
    $scenarioResults.Add([PSCustomObject]@{
        Id     = $Id
        Status = $Status
        Title  = $Title
        Detail = $Detail
        Line   = $line
    })
}

# ---------------------------------------------------------------------------
# Main Scenario Execution (Protected by try/finally)
# ---------------------------------------------------------------------------
try {
    # -----------------------------------------------------------------------
    # Scenario (a): Start daemon in background; Named Pipe appears
    # -----------------------------------------------------------------------
    try {
        $script:DaemonProcess = Start-DaemonBackground -ExePath $routeWardExePath -WorkDir $resolvedBinDir
        $pipeReady = Wait-ForNamedPipe -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs
        if ($pipeReady -and (-not $script:DaemonProcess.HasExited)) {
            if (-not $profileExistedAtStart -and (Test-Path -LiteralPath $activeProfilePath)) {
                $initialProfileBytes = [System.IO.File]::ReadAllBytes($activeProfilePath)
                $profileCapturedAfterDaemonInit = $true
            }
            Record-ScenarioResult -Id "a" -Status "PASS" -Title "Daemon background startup" -Detail "Daemon PID=$($script:DaemonProcess.Id) listening on $PipeName"
        } else {
            Record-ScenarioResult -Id "a" -Status "FAIL" -Title "Daemon background startup" -Detail "Pipe '$PipeName' did not appear within ${PipeReadyTimeoutMs}ms or daemon exited early"
        }
    } catch {
        Record-ScenarioResult -Id "a" -Status "FAIL" -Title "Daemon background startup" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (b): ACL checks on ProgramData\RouteWard, active_profile.json, and Named Pipe SDDL
    # -----------------------------------------------------------------------
    try {
        $aclErrors = New-Object System.Collections.Generic.List[string]
        foreach ($targetItem in @(
            @{ Label = "Directory"; Path = $programDataAppDir },
            @{ Label = "ProfileFile"; Path = $activeProfilePath }
        )) {
            $itemPath = $targetItem.Path
            $itemLabel = $targetItem.Label
            if (-not (Test-Path -LiteralPath $itemPath)) {
                $aclErrors.Add("$itemLabel '$itemPath' does not exist")
                continue
            }
            $acl = Get-Acl -LiteralPath $itemPath
            if (-not $acl.AreAccessRulesProtected) {
                $aclErrors.Add("$itemLabel '$itemPath' DACL is not protected (inheritance enabled)")
            }
            $seenSids = New-Object System.Collections.Generic.HashSet[string]
            foreach ($ace in $acl.Access) {
                $sidValue = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                $null = $seenSids.Add($sidValue)
                if ($AllowedProfileSids -notcontains $sidValue) {
                    $aclErrors.Add("$itemLabel '$itemPath' grants access to unauthorized principal $($ace.IdentityReference) ($sidValue)")
                }
            }
            foreach ($reqSid in $AllowedProfileSids) {
                if (-not $seenSids.Contains($reqSid)) {
                    $aclErrors.Add("$itemLabel '$itemPath' is missing required ACE for SID $reqSid")
                }
            }
        }

        $pipeSecurity = [System.IO.Directory]::GetAccessControl($PipeName)
        $pipeSddl = $pipeSecurity.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
        $auditNotes.Add("Named Pipe SDDL ($PipeName): $pipeSddl")

        if (-not $pipeSddl.StartsWith("D:P")) {
            $aclErrors.Add("Named Pipe SDDL '$pipeSddl' does not have a protected DACL (D:P)")
        }

        $aceMatches = [regex]::Matches($pipeSddl, "\(([^)]+)\)")
        foreach ($m in $aceMatches) {
            $aceBody = $m.Groups[1].Value
            $fields = $aceBody -split ";"
            if ($fields.Count -ge 6) {
                $trustee = $fields[5].Trim()
                if ($ForbiddenPipeTrustees -contains $trustee) {
                    $aclErrors.Add("Named Pipe SDDL '$pipeSddl' contains forbidden trustee '$trustee'")
                }
            }
        }

        if ($aclErrors.Count -eq 0) {
            Record-ScenarioResult -Id "b" -Status "PASS" -Title "Profile & Named Pipe ACLs" -Detail "ProgramData dir/profile restricted to SYSTEM+Administrators (D:P); pipe SDDL=$pipeSddl"
        } else {
            Record-ScenarioResult -Id "b" -Status "FAIL" -Title "Profile & Named Pipe ACLs" -Detail ($aclErrors -join "; ")
        }
    } catch {
        Record-ScenarioResult -Id "b" -Status "FAIL" -Title "Profile & Named Pipe ACLs" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (c): ctl status (daemon reachable, elevated, interception stopped)
    # -----------------------------------------------------------------------
    try {
        $statusRes = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("status") -Label "Scenario-c-status"
        if ($statusRes.ExitCode -ne 0) {
            Record-ScenarioResult -Id "c" -Status "FAIL" -Title "ctl status initial state" -Detail "ctl status exited with code $($statusRes.ExitCode)"
        } else {
            $parsed = $statusRes.RawText | ConvertFrom-Json
            $diag = $parsed.data
            if ($parsed.ok -eq $true -and $diag.daemonConnected -eq $true -and $diag.elevatedPrivileges -eq $true -and $diag.running -eq $false) {
                Record-ScenarioResult -Id "c" -Status "PASS" -Title "ctl status initial state" -Detail "daemonConnected=true, elevatedPrivileges=true, running=false"
            } else {
                Record-ScenarioResult -Id "c" -Status "FAIL" -Title "ctl status initial state" -Detail "Unexpected status payload: ok=$($parsed.ok), daemonConnected=$($diag.daemonConnected), elevated=$($diag.elevatedPrivileges), running=$($diag.running)"
            }
        }
    } catch {
        Record-ScenarioResult -Id "c" -Status "FAIL" -Title "ctl status initial state" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (d): ctl start then curl.exe (HTTP 200, ctl connections shows curl.exe, expected rule, rxBytes > 0)
    # -----------------------------------------------------------------------
    try {
        $startRes = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("start") -Label "Scenario-d-start"
        $startJson = $startRes.RawText | ConvertFrom-Json
        if ($startRes.ExitCode -ne 0 -or $startJson.ok -ne $true -or $startJson.data.running -ne $true) {
            Record-ScenarioResult -Id "d" -Status "FAIL" -Title "ctl start and SOCKS5 routing" -Detail "ctl start failed or running!=true"
        } else {
            $curlRes = Invoke-UnproxiedCurl -CurlBin $CurlExePath -Url $TestUrl -TimeoutSec $CurlTimeoutSec
            Start-Sleep -Milliseconds $PollIntervalMs
            $connsRes = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("connections") -Label "Scenario-d-connections"
            $connsJson = $connsRes.RawText | ConvertFrom-Json

            $matchingConn = $null
            if ($null -ne $connsJson.data) {
                foreach ($c in $connsJson.data) {
                    if ($c.processName -ieq "curl.exe" -and $c.matchedRule -eq $ExpectedProxyRuleName -and ([int64]$c.rxBytes) -gt 0) {
                        $matchingConn = $c
                        break
                    }
                }
            }

            if ($curlRes.ExitCode -eq 0 -and $curlRes.HttpCode -eq $ExpectedHttpStatus -and $null -ne $matchingConn) {
                Record-ScenarioResult -Id "d" -Status "PASS" -Title "ctl start and SOCKS5 routing" -Detail "curl HTTP $($curlRes.HttpCode), PID=$($matchingConn.pid), rule='$($matchingConn.matchedRule)', rxBytes=$($matchingConn.rxBytes)"
            } else {
                Record-ScenarioResult -Id "d" -Status "FAIL" -Title "ctl start and SOCKS5 routing" -Detail "curl exit=$($curlRes.ExitCode) http=$($curlRes.HttpCode), matching curl.exe connection found=$($null -ne $matchingConn)"
            }
        }
    } catch {
        Record-ScenarioResult -Id "d" -Status "FAIL" -Title "ctl start and SOCKS5 routing" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (e): Temporary Block rule for curl.exe (SKIP if ctl cannot both add and remove rules)
    # -----------------------------------------------------------------------
    try {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            $ctlHelpOut = (& $routeWardExePath ctl --help 2>&1 | ForEach-Object { $_.ToString() }) -join "`n"
        } finally {
            $ErrorActionPreference = $prevEap
        }
        $hasUpsertRule = $ctlHelpOut -match "\bupsert-rule\b"
        $hasRemoveRule = $ctlHelpOut -match "\b(remove-rule|delete-rule)\b"

        if (-not ($hasUpsertRule -and $hasRemoveRule)) {
            Record-ScenarioResult -Id "e" -Status "SKIP" -Title "Temporary Block rule via ctl" -Detail "routeward ctl exposes 'upsert-rule' but does not expose a 'remove-rule' subcommand to delete temporary test rules"
        } else {
            $removeCmd = $Matches[1]
            $blockRuleObj = @{
                id              = $TempBlockRuleId
                name            = $TempBlockRuleName
                enabled         = $true
                priority        = 1
                processPatterns = @("curl.exe")
                domainPatterns  = @()
                ipCidrs         = @()
                portRanges      = @()
                protocol        = "tcp"
                action          = @{ type = "block" }
            }
            $blockRuleJson = $blockRuleObj | ConvertTo-Json -Compress -Depth 5
            $profileModifiedByScript = $true
            $upsertRes = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("upsert-rule", "--json", $blockRuleJson) -Label "Scenario-e-upsert-block"
            $curlBlocked = Invoke-UnproxiedCurl -CurlBin $CurlExePath -Url $TestUrl -TimeoutSec 5
            Start-Sleep -Milliseconds $PollIntervalMs
            $connsBlockedRes = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("connections") -Label "Scenario-e-connections"
            $connsBlockedJson = $connsBlockedRes.RawText | ConvertFrom-Json
            $remRes = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @($removeCmd, "--id", $TempBlockRuleId) -Label "Scenario-e-remove-block"

            $sawBlockedConn = $false
            if ($null -ne $connsBlockedJson.data) {
                foreach ($c in $connsBlockedJson.data) {
                    if ($c.processName -ieq "curl.exe" -and $c.status -eq "blocked") {
                        $sawBlockedConn = $true
                        break
                    }
                }
            }

            if ($upsertRes.ExitCode -eq 0 -and $curlBlocked.ExitCode -ne 0 -and $sawBlockedConn -and $remRes.ExitCode -eq 0) {
                Record-ScenarioResult -Id "e" -Status "PASS" -Title "Temporary Block rule via ctl" -Detail "curl failed as expected (exit=$($curlBlocked.ExitCode)), connection marked blocked, and temporary rule removed"
            } else {
                Record-ScenarioResult -Id "e" -Status "FAIL" -Title "Temporary Block rule via ctl" -Detail "upsertExit=$($upsertRes.ExitCode), curlExit=$($curlBlocked.ExitCode), sawBlocked=$sawBlockedConn, removeExit=$($remRes.ExitCode)"
            }
        }
    } catch {
        Record-ScenarioResult -Id "e" -Status "FAIL" -Title "Temporary Block rule via ctl" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (f): ctl stop removes firewall rule and curl returns HTTP 200 directly
    # -----------------------------------------------------------------------
    try {
        $stopRes = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("stop") -Label "Scenario-f-stop"
        $stopJson = $stopRes.RawText | ConvertFrom-Json
        Start-Sleep -Milliseconds $PollIntervalMs
        $fwStillPresent = Test-FirewallRulePresent -RuleName $FirewallRuleName
        $curlDirect = Invoke-UnproxiedCurl -CurlBin $CurlExePath -Url $TestUrl -TimeoutSec $CurlTimeoutSec

        if ($stopRes.ExitCode -eq 0 -and $stopJson.ok -eq $true -and $stopJson.data.running -eq $false -and (-not $fwStillPresent) -and $curlDirect.ExitCode -eq 0 -and $curlDirect.HttpCode -eq $ExpectedHttpStatus) {
            Record-ScenarioResult -Id "f" -Status "PASS" -Title "ctl stop and direct pass-through" -Detail "Firewall rule '$FirewallRuleName' removed and direct curl returned HTTP $($curlDirect.HttpCode)"
        } else {
            Record-ScenarioResult -Id "f" -Status "FAIL" -Title "ctl stop and direct pass-through" -Detail "stopOk=$($stopJson.ok), running=$($stopJson.data.running), fwPresent=$fwStillPresent, curlHttp=$($curlDirect.HttpCode)"
        }
    } catch {
        Record-ScenarioResult -Id "f" -Status "FAIL" -Title "ctl stop and direct pass-through" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (g): Crash test (ctl start, Stop-Process -Force on daemon, fail-open curl 200, orphaned firewall rule present)
    # -----------------------------------------------------------------------
    try {
        $reStartRes = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("start") -Label "Scenario-g-start"
        $reStartJson = $reStartRes.RawText | ConvertFrom-Json
        Start-Sleep -Milliseconds $PollIntervalMs
        $fwBeforeCrash = Test-FirewallRulePresent -RuleName $FirewallRuleName

        if ($reStartRes.ExitCode -ne 0 -or $reStartJson.data.running -ne $true -or (-not $fwBeforeCrash)) {
            Record-ScenarioResult -Id "g" -Status "FAIL" -Title "Daemon crash fail-open & orphaned rule" -Detail "Failed to start interception or create firewall rule before crash test"
        } else {
            $killedPid = $script:DaemonProcess.Id
            Stop-DaemonProcess -ProcessObj $script:DaemonProcess
            $script:DaemonProcess = $null
            Start-Sleep -Milliseconds $PollIntervalMs

            # Query ctl status while daemon is down so CLI records user-side disconnection log
            $null = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("status") -Label "Scenario-g-status-while-down"

            $curlAfterCrash = Invoke-UnproxiedCurl -CurlBin $CurlExePath -Url $TestUrl -TimeoutSec $CurlTimeoutSec
            $fwOrphanPresent = Test-FirewallRulePresent -RuleName $FirewallRuleName

            if ($curlAfterCrash.ExitCode -eq 0 -and $curlAfterCrash.HttpCode -eq $ExpectedHttpStatus -and $fwOrphanPresent) {
                Record-ScenarioResult -Id "g" -Status "PASS" -Title "Daemon crash fail-open & orphaned rule" -Detail "Force-killed daemon PID=$killedPid; curl returned HTTP $($curlAfterCrash.HttpCode) (fail-open) and orphaned rule '$FirewallRuleName' remained present"
            } else {
                Record-ScenarioResult -Id "g" -Status "FAIL" -Title "Daemon crash fail-open & orphaned rule" -Detail "curlExit=$($curlAfterCrash.ExitCode) http=$($curlAfterCrash.HttpCode), orphanRulePresent=$fwOrphanPresent"
            }
        }
    } catch {
        Record-ScenarioResult -Id "g" -Status "FAIL" -Title "Daemon crash fail-open & orphaned rule" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (h): Daemon restart automatically removes orphaned firewall rule and logs it
    # -----------------------------------------------------------------------
    try {
        $daemonLogBeforeLines = 0
        $existingDaemonLogs = @(Get-ChildItem -Path $daemonLogsDir -Filter $logWildcard -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
        if ($existingDaemonLogs.Count -gt 0) {
            $daemonLogBeforeLines = @(Get-Content -LiteralPath $existingDaemonLogs[0].FullName -Encoding UTF8).Count
        }

        $script:DaemonProcess = Start-DaemonBackground -ExePath $routeWardExePath -WorkDir $resolvedBinDir
        $pipeReadyAfterCrash = Wait-ForNamedPipe -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs
        Start-Sleep -Milliseconds $LogFlushWaitMs

        $fwAfterRestart = Test-FirewallRulePresent -RuleName $FirewallRuleName
        $sawCleanupInLog = $false
        $latestDaemonLogs = @(Get-ChildItem -Path $daemonLogsDir -Filter $logWildcard -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
        if ($latestDaemonLogs.Count -gt 0) {
            $allLines = @(Get-Content -LiteralPath $latestDaemonLogs[0].FullName -Encoding UTF8)
            $newLines = if ($allLines.Count -gt $daemonLogBeforeLines) {
                $allLines[$daemonLogBeforeLines..($allLines.Count - 1)]
            } else {
                $allLines
            }
            foreach ($ln in $newLines) {
                if ($ln.Contains($ExpectedCleanupLogText) -and $ln.Contains($FirewallRuleName)) {
                    $sawCleanupInLog = $true
                    break
                }
            }
        }

        if ($pipeReadyAfterCrash -and (-not $fwAfterRestart) -and $sawCleanupInLog) {
            Record-ScenarioResult -Id "h" -Status "PASS" -Title "Automatic orphan cleanup on daemon restart" -Detail "Orphaned rule '$FirewallRuleName' removed at startup and logged in daemon log"
        } else {
            Record-ScenarioResult -Id "h" -Status "FAIL" -Title "Automatic orphan cleanup on daemon restart" -Detail "pipeReady=$pipeReadyAfterCrash, fwStillPresent=$fwAfterRestart, cleanupLogged=$sawCleanupInLog"
        }
    } catch {
        Record-ScenarioResult -Id "h" -Status "FAIL" -Title "Automatic orphan cleanup on daemon restart" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (i): Daemon and user logs modified during test, no CWD 'logs' directory created
    # -----------------------------------------------------------------------
    try {
        Start-Sleep -Milliseconds $LogFlushWaitMs
        $daemonLogFiles = @(Get-ChildItem -Path $daemonLogsDir -Filter $logWildcard -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
        $userLogFiles = @(Get-ChildItem -Path $userLogsDir -Filter $logWildcard -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)

        $daemonLogModified = ($daemonLogFiles.Count -gt 0) -and ($daemonLogFiles[0].LastWriteTime -ge $scriptStartTime.AddSeconds(-2))
        $userLogModified = ($userLogFiles.Count -gt 0) -and ($userLogFiles[0].LastWriteTime -ge $scriptStartTime.AddSeconds(-2))
        $cwdLogsCreatedDuringTest = (-not $cwdLogsExistedBefore) -and (Test-Path -LiteralPath $cwdLogsDir)

        if ($daemonLogModified -and $userLogModified -and (-not $cwdLogsCreatedDuringTest)) {
            Record-ScenarioResult -Id "i" -Status "PASS" -Title "Daemon & user log paths and CWD cleanliness" -Detail "Daemon log ($($daemonLogFiles[0].FullName)) and user log ($($userLogFiles[0].FullName)) updated; no CWD '$LogsFolderName' created"
        } else {
            Record-ScenarioResult -Id "i" -Status "FAIL" -Title "Daemon & user log paths and CWD cleanliness" -Detail "daemonLogModified=$daemonLogModified ($daemonLogsDir), userLogModified=$userLogModified ($userLogsDir), cwdLogsCreated=$cwdLogsCreatedDuringTest ($cwdLogsDir)"
        }
    } catch {
        Record-ScenarioResult -Id "i" -Status "FAIL" -Title "Daemon & user log paths and CWD cleanliness" -Detail $_.Exception.Message
    }
} finally {
    # -----------------------------------------------------------------------
    # Guardrail 4: Always stop daemon, run routeward cleanup, and restore profile if modified
    # -----------------------------------------------------------------------
    Stop-DaemonProcess -ProcessObj $script:DaemonProcess
    $script:DaemonProcess = $null

    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $cleanupOut = & $routeWardExePath cleanup 2>&1
        $cleanupExit = $LASTEXITCODE
        $cleanupStr = ($cleanupOut | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
        $script:RawCtlCapture.Add("--- [Finally-Cleanup] routeward cleanup (exit=$cleanupExit) ---`r`n$cleanupStr")
    } catch {
        $script:RawCtlCapture.Add("--- [Finally-Cleanup] routeward cleanup error: $($_.Exception.Message) ---")
    } finally {
        $ErrorActionPreference = $prevEap
    }

    if ($profileModifiedByScript -and $null -ne $initialProfileBytes -and (Test-Path -LiteralPath $programDataAppDir)) {
        try {
            [System.IO.File]::WriteAllBytes($activeProfilePath, $initialProfileBytes)
            $auditNotes.Add("Restored original profile bytes to '$activeProfilePath' (profileCapturedAfterDaemonInit=$profileCapturedAfterDaemonInit).")
        } catch {
            $auditNotes.Add("WARNING: Failed to restore original profile at '$activeProfilePath': $($_.Exception.Message)")
        }
    }
}

# ---------------------------------------------------------------------------
# Summary & Timestamped Report Generation
# ---------------------------------------------------------------------------
$passCount = @($scenarioResults | Where-Object { $_.Status -eq "PASS" }).Count
$failCount = @($scenarioResults | Where-Object { $_.Status -eq "FAIL" }).Count
$skipCount = @($scenarioResults | Where-Object { $_.Status -eq "SKIP" }).Count
$summaryBanner = "$passCount PASS / $failCount FAIL / $skipCount SKIP"

Write-Host ""
Write-Host "=== RouteWard Windows Regression Summary: $summaryBanner ===" -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Red" })

$reportTimestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$reportPath = Join-Path $PSScriptRoot "${ReportFilePrefix}${reportTimestamp}.txt"

$reportLines = New-Object System.Collections.Generic.List[string]
$reportLines.Add("================================================================================")
$reportLines.Add("RouteWard Windows Non-Regression Test Report")
$reportLines.Add("Started At : $($scriptStartTime.ToString('yyyy-MM-dd HH:mm:ss zzz'))")
$reportLines.Add("Finished At: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))")
$reportLines.Add("Host / OS  : $([Environment]::MachineName) - $([Environment]::OSVersion.VersionString)")
$reportLines.Add("PS Version : $($PSVersionTable.PSVersion.ToString())")
$reportLines.Add("Summary    : $summaryBanner")
$reportLines.Add("================================================================================")
$reportLines.Add("")
$reportLines.Add("## 1. Scenario Results")
foreach ($r in $scenarioResults) {
    $reportLines.Add($r.Line)
}

$reportLines.Add("")
$reportLines.Add("## 2. Binary & Driver Inventory")
$binaryTargets = @($routeWardExePath, $desktopExePath) + $resolvedWinDivertFiles
foreach ($binPath in $binaryTargets) {
    if (Test-Path -LiteralPath $binPath) {
        $item = Get-Item -LiteralPath $binPath
        $verInfo = $item.VersionInfo.ProductVersion
        if ([string]::IsNullOrWhiteSpace($verInfo)) {
            $verInfo = $item.VersionInfo.FileVersion
        }
        if ([string]::IsNullOrWhiteSpace($verInfo)) {
            $verInfo = "n/a"
        }
        $reportLines.Add("- $($item.Name): path='$($item.FullName)', size=$($item.Length) bytes, version='$verInfo'")
    }
}
$prevEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    $cliVer = (& $routeWardExePath --version 2>&1 | ForEach-Object { $_.ToString() }) -join " "
    $reportLines.Add("- routeward --version: $($cliVer.Trim())")
} finally {
    $ErrorActionPreference = $prevEap
}

if ($auditNotes.Count -gt 0) {
    $reportLines.Add("")
    $reportLines.Add("## 3. Audit Notes")
    foreach ($note in $auditNotes) {
        $reportLines.Add("- $(Remove-SensitiveText -InputText $note)")
    }
}

$reportLines.Add("")
$reportLines.Add("## 4. Raw CTL & Cleanup Outputs (Passwords Redacted)")
foreach ($entry in $script:RawCtlCapture) {
    $reportLines.Add($entry)
    $reportLines.Add("")
}

$reportLines.Add("## 5. Log Tails (Last $ReportLogTailLines Lines, Passwords Redacted)")
foreach ($logGroup in @(
    @{ Title = "Daemon Log ($daemonLogsDir)"; Dir = $daemonLogsDir },
    @{ Title = "User Log ($userLogsDir)"; Dir = $userLogsDir }
)) {
    $reportLines.Add("--- $($logGroup.Title) ---")
    $latestLogs = @(Get-ChildItem -Path $logGroup.Dir -Filter $logWildcard -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    if ($latestLogs.Count -eq 0) {
        $reportLines.Add("(No log file found)")
    } else {
        $targetLog = $latestLogs[0].FullName
        $reportLines.Add("File: $targetLog")
        $tailLines = @(Get-Content -LiteralPath $targetLog -Tail $ReportLogTailLines -Encoding UTF8 -ErrorAction SilentlyContinue)
        foreach ($tl in $tailLines) {
            $reportLines.Add((Remove-SensitiveText -InputText $tl))
        }
    }
    $reportLines.Add("")
}

Set-Content -LiteralPath $reportPath -Value ($reportLines -join [Environment]::NewLine) -Encoding UTF8
Write-Host "Report written to: $reportPath"

if ($failCount -gt 0) {
    exit 1
}
exit 0
