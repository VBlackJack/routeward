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
    [switch]$DryRun,

    [Parameter(Mandatory = $false)]
    [string]$SampleResponsesJsonPath = "",

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
    [string]$ReportFilePrefix = "RouteWard_TestReport_",

    [Parameter(Mandatory = $false)]
    [string]$ExternalDnsServer = "9.9.9.9",

    [Parameter(Mandatory = $false)]
    [string]$FakeIpCidr = "198.18.0.0/15",

    [Parameter(Mandatory = $false)]
    [string]$PublicDnsTestDomain = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Guardrail 1: Refuse execution without explicit -ConfirmTestMachine or -DryRun
# ---------------------------------------------------------------------------
if (-not $ConfirmTestMachine.IsPresent -and -not $DryRun.IsPresent) {
    Write-Host "[ABORT] Refusing to run without the explicit -ConfirmTestMachine switch (or -DryRun)." -ForegroundColor Yellow
    Write-Host "This script starts WinDivert packet interception and controls the RouteWard daemon."
    Write-Host "Launch inside the dedicated Windows test VM with:"
    Write-Host "  .\Invoke-RouteWardTests.ps1 -ConfirmTestMachine"
    exit 2
}

# ---------------------------------------------------------------------------
# Safe out-of-repository path resolution & config loading (Bug 1 fix)
# ---------------------------------------------------------------------------
function Resolve-OptionalRepoRoot {
    param([string]$StartDir)
    if ([string]::IsNullOrWhiteSpace($StartDir)) {
        return ""
    }
    $parent1 = Split-Path -Parent $StartDir
    if ([string]::IsNullOrWhiteSpace($parent1)) {
        return ""
    }
    $parent2 = Split-Path -Parent $parent1
    if ([string]::IsNullOrWhiteSpace($parent2)) {
        return ""
    }
    return $parent2
}

$repoRootCandidate = Resolve-OptionalRepoRoot -StartDir $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($SystemConstantsJsonPath) -and (-not [string]::IsNullOrWhiteSpace($repoRootCandidate))) {
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
    if (-not $PSBoundParameters.ContainsKey("FakeIpCidr") -and $sysConsts.dns.fakeIpCidr) {
        $FakeIpCidr = [string]$sysConsts.dns.fakeIpCidr
    }
    if (-not $PSBoundParameters.ContainsKey("ExternalDnsServer") -and $sysConsts.dns.upstreamDnsServer) {
        $rawUpstreamDns = [string]$sysConsts.dns.upstreamDnsServer
        $ExternalDnsServer = ($rawUpstreamDns -replace ':\d+$', '')
    }
}

if ([string]::IsNullOrWhiteSpace($PublicDnsTestDomain)) {
    try {
        $parsedTestUri = [System.Uri]$TestUrl
        if (-not [string]::IsNullOrWhiteSpace($parsedTestUri.Host)) {
            $PublicDnsTestDomain = $parsedTestUri.Host
        } else {
            $PublicDnsTestDomain = "example.com"
        }
    } catch {
        $PublicDnsTestDomain = "example.com"
    }
}

if ([string]::IsNullOrWhiteSpace($DefaultProfileJsonPath) -and (-not [string]::IsNullOrWhiteSpace($repoRootCandidate))) {
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
# Strict IPC Response Parser (Bug 2 fix: validates {"id":...,"ok":true,"result":...})
# ---------------------------------------------------------------------------
function ConvertFrom-CtlResponseJson {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$RawJson,

        [Parameter(Mandatory = $true)]
        [string]$Context,

        [Parameter(Mandatory = $false)]
        [string[]]$RequiredResultProperties = @(),

        [Parameter(Mandatory = $false)]
        [switch]$ExpectResultArray,

        [Parameter(Mandatory = $false)]
        [string[]]$RequiredArrayElementProperties = @()
    )

    if ([string]::IsNullOrWhiteSpace($RawJson)) {
        throw "ctl [$Context] returned empty output instead of JSON IpcResponse."
    }

    try {
        $parsed = $RawJson | ConvertFrom-Json
    } catch {
        throw "ctl [$Context] output is not valid JSON: $($_.Exception.Message)"
    }

    if ($null -eq $parsed) {
        throw "ctl [$Context] JSON deserialized to null."
    }

    $topProps = @($parsed.PSObject.Properties | ForEach-Object { $_.Name })
    if ($topProps -notcontains "ok") {
        throw "ctl [$Context] response schema mismatch: missing top-level 'ok' field (found properties: $($topProps -join ', '))."
    }

    if ($parsed.ok -ne $true) {
        $errDetail = if ($topProps -contains "error" -and $null -ne $parsed.error) { [string]$parsed.error } else { "unknown error" }
        throw "ctl [$Context] returned ok=false: $errDetail"
    }

    if ($topProps -notcontains "result") {
        throw "ctl [$Context] response schema mismatch: missing top-level 'result' field on ok=true IpcResponse (found properties: $($topProps -join ', '))."
    }

    $resVal = $parsed.result
    if ($null -eq $resVal) {
        throw "ctl [$Context] response schema mismatch: 'result' field is null."
    }

    if ($ExpectResultArray.IsPresent) {
        $items = @($resVal)
        if ($RequiredArrayElementProperties.Count -gt 0 -and $items.Count -gt 0) {
            $firstElemProps = @($items[0].PSObject.Properties | ForEach-Object { $_.Name })
            foreach ($reqElemProp in $RequiredArrayElementProperties) {
                if ($firstElemProps -notcontains $reqElemProp) {
                    throw "ctl [$Context] array element schema mismatch: missing property '$reqElemProp' (found: $($firstElemProps -join ', '))."
                }
            }
        }
        return ,$items
    }

    if ($RequiredResultProperties.Count -gt 0) {
        $resProps = @($resVal.PSObject.Properties | ForEach-Object { $_.Name })
        foreach ($reqProp in $RequiredResultProperties) {
            if ($resProps -notcontains $reqProp) {
                throw "ctl [$Context] result schema mismatch: missing property 'result.$reqProp' (found: $($resProps -join ', '))."
            }
        }
    }

    return $resVal
}

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

function Wait-ForNamedPipeAbsent {
    param(
        [string]$FullPipePath,
        [int]$TimeoutMs,
        [int]$IntervalMs
    )
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($stopwatch.ElapsedMilliseconds -lt $TimeoutMs) {
        if (-not (Test-NamedPipeExists -FullPipePath $FullPipePath)) {
            return $true
        }
        Start-Sleep -Milliseconds $IntervalMs
    }
    return (-not (Test-NamedPipeExists -FullPipePath $FullPipePath))
}

function Test-FirewallRulePresent {
    param([string]$RuleName)
    $null = & netsh.exe advfirewall firewall show rule name="$RuleName" 2>&1
    return ($LASTEXITCODE -eq 0)
}

function Ensure-SyntheticFirewallRulePresent {
    param(
        [string]$RuleName,
        [string]$ProgramPath,
        [int]$Port
    )
    if (-not (Test-FirewallRulePresent -RuleName $RuleName)) {
        $null = & netsh.exe advfirewall firewall add rule name="$RuleName" dir=in action=allow program="$ProgramPath" enable=yes profile=any protocol=TCP localport=$Port 2>&1
    }
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

function Build-CurlArguments {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSec
    )
    # Note: Never pass an empty string "" to --noproxy in Windows PowerShell 5.1,
    # as PowerShell 5.1 strips "" when invoking native binaries, causing --noproxy to consume -s.
    return @(
        "-s",
        "-o",
        "NUL",
        "-w",
        "%{http_code}",
        "--noproxy",
        "*",
        "--max-time",
        "$TimeoutSec",
        $Url
    )
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
    $curlArgs = Build-CurlArguments -Url $Url -TimeoutSec $TimeoutSec
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        # Capture standard output only; discard standard error so progress/diagnostics never mix with %{http_code}
        $stdoutLines = & $CurlBin @curlArgs 2>$null
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevEap
        foreach ($v in $proxyVars) {
            [Environment]::SetEnvironmentVariable($v, $savedVars[$v], "Process")
        }
    }
    $httpCodeOnly = (($stdoutLines | ForEach-Object { $_.ToString() }) -join "").Trim()
    return [PSCustomObject]@{
        ExitCode = $code
        HttpCode = $httpCodeOnly
    }
}

function Write-Utf8NoBomJsonTempFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$JsonText
    )
    $tempDir = [System.IO.Path]::GetTempPath()
    $tempFileName = "routeward_rule_$([guid]::NewGuid().ToString('N')).json"
    $tempFilePath = Join-Path $tempDir $tempFileName
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($tempFilePath, $JsonText, $utf8NoBom)
    return $tempFilePath
}

function Split-ProcessCommandLineArgs {
    param(
        [string]$ExecutablePath,
        [string]$CommandLine
    )
    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return ""
    }
    $trimmed = $CommandLine.Trim()
    if (-not [string]::IsNullOrWhiteSpace($ExecutablePath)) {
        $quotedExe = "`"$ExecutablePath`""
        if ($trimmed.StartsWith($quotedExe, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $trimmed.Substring($quotedExe.Length).Trim()
        }
        if ($trimmed.StartsWith($ExecutablePath, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $trimmed.Substring($ExecutablePath.Length).Trim()
        }
    }
    if ($trimmed.StartsWith('"')) {
        $endQuote = $trimmed.IndexOf('"', 1)
        if ($endQuote -gt 0) {
            return $trimmed.Substring($endQuote + 1).Trim()
        }
    } else {
        $firstSpace = $trimmed.IndexOf(' ')
        if ($firstSpace -gt 0) {
            return $trimmed.Substring($firstSpace + 1).Trim()
        }
    }
    return ""
}

function Get-LocalPortListenerProcessInfo {
    param([int]$Port)
    $listeners = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
    foreach ($l in $listeners) {
        $ownerPid = [int]$l.OwningProcess
        if ($ownerPid -gt 0) {
            $wmiProc = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $ownerPid" -ErrorAction SilentlyContinue
            $exePath = if ($null -ne $wmiProc -and $wmiProc.ExecutablePath) { [string]$wmiProc.ExecutablePath } else { "" }
            $cmdLine = if ($null -ne $wmiProc -and $wmiProc.CommandLine) { [string]$wmiProc.CommandLine } else { "" }
            return [PSCustomObject]@{
                Pid            = $ownerPid
                ExecutablePath = $exePath
                CommandLine    = $cmdLine
            }
        }
    }
    return $null
}

function Test-IpInFakePool {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$IpAddressString,

        [Parameter(Mandatory = $false)]
        [string]$PoolCidr = "198.18.0.0/15"
    )
    if ([string]::IsNullOrWhiteSpace($IpAddressString)) {
        return $false
    }
    $ipObj = $null
    if (-not [System.Net.IPAddress]::TryParse($IpAddressString.Trim(), [ref]$ipObj)) {
        return $false
    }
    if ($ipObj.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        return $false
    }
    $ipBytes = $ipObj.GetAddressBytes()
    $ipU32 = ([uint32]$ipBytes[0] -shl 24) -bor ([uint32]$ipBytes[1] -shl 16) -bor ([uint32]$ipBytes[2] -shl 8) -bor ([uint32]$ipBytes[3])

    $cidrParts = $PoolCidr -split '/'
    $netIpObj = $null
    if ($cidrParts.Count -ne 2 -or (-not [System.Net.IPAddress]::TryParse($cidrParts[0].Trim(), [ref]$netIpObj))) {
        return (($ipBytes[0] -eq 198) -and (($ipBytes[1] -band 0xFE) -eq 18))
    }
    $prefixLen = [int]$cidrParts[1]
    $netBytes = $netIpObj.GetAddressBytes()
    $netU32 = ([uint32]$netBytes[0] -shl 24) -bor ([uint32]$netBytes[1] -shl 16) -bor ([uint32]$netBytes[2] -shl 8) -bor ([uint32]$netBytes[3])
    $maskU32 = if ($prefixLen -le 0) { [uint32]0 } elseif ($prefixLen -ge 32) { [uint32]::MaxValue } else { ([uint32]::MaxValue -shl (32 - $prefixLen)) }
    return (($ipU32 -band $maskU32) -eq ($netU32 -band $maskU32))
}

function Get-MachineActiveDirectoryOrPrimaryDnsSuffix {
    $candidates = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($env:USERDNSDOMAIN)) {
        $candidates.Add($env:USERDNSDOMAIN.Trim().Trim('.'))
    }
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($null -ne $cs -and $cs.PartOfDomain -and (-not [string]::IsNullOrWhiteSpace($cs.Domain))) {
            $candidates.Add(([string]$cs.Domain).Trim().Trim('.'))
        }
    } catch {
        # Ignore WMI error
    }
    try {
        $tcpParams = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ErrorAction SilentlyContinue
        if ($null -ne $tcpParams) {
            foreach ($propName in @("Domain", "NV Domain")) {
                $val = $tcpParams.$propName
                if (-not [string]::IsNullOrWhiteSpace($val)) {
                    $candidates.Add(([string]$val).Trim().Trim('.'))
                }
            }
        }
    } catch {
        # Ignore registry error
    }
    foreach ($c in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($c) -and $c.Contains(".")) {
            return $c
        }
    }
    return ""
}

function Clear-AllWindowsDnsCaches {
    $notes = New-Object System.Collections.Generic.List[string]
    try {
        if (Get-Command -Name "Clear-DnsClientCache" -ErrorAction SilentlyContinue) {
            Clear-DnsClientCache -ErrorAction SilentlyContinue
            $notes.Add("Cleared Windows DNS Client cache via Clear-DnsClientCache.")
        } else {
            $null = & ipconfig.exe /flushdns 2>&1
            $notes.Add("Cleared Windows DNS Client cache via ipconfig /flushdns.")
        }
    } catch {
        $notes.Add("WARNING: Failed to clear DNS Client cache: $($_.Exception.Message)")
    }

    try {
        $dnsSvc = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
        if ($null -ne $dnsSvc -and $dnsSvc.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {
            if (Get-Command -Name "Clear-DnsServerCache" -ErrorAction SilentlyContinue) {
                Clear-DnsServerCache -Force -ErrorAction SilentlyContinue
                $notes.Add("Cleared Windows DNS Server cache (service 'DNS' running) via Clear-DnsServerCache -Force.")
            } elseif (Get-Command -Name "dnscmd.exe" -ErrorAction SilentlyContinue) {
                $null = & dnscmd.exe /clearcache 2>&1
                $notes.Add("Cleared Windows DNS Server cache (service 'DNS' running) via dnscmd /clearcache.")
            }
        }
    } catch {
        $notes.Add("WARNING: Failed to clear Windows DNS Server cache: $($_.Exception.Message)")
    }
    return ,$notes.ToArray()
}

# ---------------------------------------------------------------------------
# DryRun Mode: Validate out-of-repo path resolution, curl command construction,
#              --json-file UTF-8 no-BOM temp file flow, and IPC response parser
# ---------------------------------------------------------------------------
if ($DryRun.IsPresent) {
    Write-Host "=== RouteWard Windows Test Suite - DRY RUN MODE (No daemon / No WinDivert) ===" -ForegroundColor Cyan

    # 1. Verify out-of-repo path resolution (e.g., C:\RouteWard where second Split-Path is empty)
    $simulatedStandaloneRoot = Resolve-OptionalRepoRoot -StartDir "C:\RouteWard"
    if ($simulatedStandaloneRoot -ne "") {
        throw "DryRun failed: expected empty repo root for 'C:\RouteWard', got '$simulatedStandaloneRoot'"
    }
    Write-Host "[DRYRUN-PASS] Out-of-repo path resolution ('C:\RouteWard') succeeded without Join-Path error." -ForegroundColor Green

    # 2. Verify curl argument construction and stdout-only HTTP code capture
    $sampleCurlArgs = Build-CurlArguments -Url $TestUrl -TimeoutSec $CurlTimeoutSec
    if ($sampleCurlArgs[0] -ne "-s" -or $sampleCurlArgs[1] -ne "-o" -or $sampleCurlArgs[2] -ne "NUL" -or $sampleCurlArgs[3] -ne "-w" -or $sampleCurlArgs[4] -ne "%{http_code}") {
        throw "DryRun failed: unexpected curl argument order: $($sampleCurlArgs -join ' ')"
    }
    foreach ($argItem in $sampleCurlArgs) {
        if ([string]::IsNullOrEmpty($argItem)) {
            throw "DryRun failed: curl arguments must not contain empty strings in PowerShell 5.1."
        }
    }
    if (Test-Path -LiteralPath $CurlExePath) {
        $closedPortCurl = Invoke-UnproxiedCurl -CurlBin $CurlExePath -Url "http://127.0.0.1:1" -TimeoutSec 1
        if ($closedPortCurl.ExitCode -eq 0 -or $closedPortCurl.HttpCode -notmatch '^\d{3}$') {
            throw "DryRun failed: expected clean 3-digit HTTP code and non-zero exit from closed port curl, got HttpCode='$($closedPortCurl.HttpCode)' ExitCode=$($closedPortCurl.ExitCode)"
        }
    }
    Write-Host "[DRYRUN-PASS] Verified curl command construction (-s -o NUL -w '%{http_code}') and stdout-only HTTP code capture." -ForegroundColor Green

    # 3. Verify --json-file temporary UTF-8 no-BOM file creation and cleanup in %TEMP%
    $dryRunRuleObj = @{
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
    $dryRunRuleJson = $dryRunRuleObj | ConvertTo-Json -Compress -Depth 5
    $dryRunTempFile = Write-Utf8NoBomJsonTempFile -JsonText $dryRunRuleJson
    try {
        if (-not (Test-Path -LiteralPath $dryRunTempFile)) {
            throw "DryRun failed: temporary JSON file was not created at '$dryRunTempFile'."
        }
        $rawBytes = [System.IO.File]::ReadAllBytes($dryRunTempFile)
        if ($rawBytes.Length -ge 3 -and $rawBytes[0] -eq 0xEF -and $rawBytes[1] -eq 0xBB -and $rawBytes[2] -eq 0xBF) {
            throw "DryRun failed: temporary JSON file '$dryRunTempFile' contains a UTF-8 BOM."
        }
        $reloadedRule = Get-Content -LiteralPath $dryRunTempFile -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($reloadedRule.id -ne $TempBlockRuleId -or $reloadedRule.protocol -ne "tcp" -or $reloadedRule.action.type -ne "block") {
            throw "DryRun failed: reloaded JSON from '$dryRunTempFile' did not preserve rule fields."
        }
        $ctlUpsertArgs = @("upsert-rule", "--json-file", $dryRunTempFile)
        if ($ctlUpsertArgs[1] -ne "--json-file" -or $ctlUpsertArgs[2] -ne $dryRunTempFile) {
            throw "DryRun failed: unexpected --json-file argument list."
        }
    } finally {
        if (Test-Path -LiteralPath $dryRunTempFile) {
            Remove-Item -LiteralPath $dryRunTempFile -Force -ErrorAction SilentlyContinue
        }
    }
    if (Test-Path -LiteralPath $dryRunTempFile) {
        throw "DryRun failed: temporary JSON file '$dryRunTempFile' was not removed in finally block."
    }
    Write-Host "[DRYRUN-PASS] Verified --json-file UTF-8 (no BOM) temporary file creation, JSON integrity, and cleanup under %TEMP%." -ForegroundColor Green

    # 4. Load sample ctl responses fixture and verify strict parser
    if ([string]::IsNullOrWhiteSpace($SampleResponsesJsonPath)) {
        $SampleResponsesJsonPath = Join-Path $PSScriptRoot "fixtures\sample_ctl_responses.json"
    }
    if (-not (Test-Path -LiteralPath $SampleResponsesJsonPath)) {
        throw "DryRun failed: missing sample responses fixture at '$SampleResponsesJsonPath'."
    }

    $fixtures = Get-Content -LiteralPath $SampleResponsesJsonPath -Raw -Encoding UTF8 | ConvertFrom-Json

    $diagStopped = ConvertFrom-CtlResponseJson `
        -RawJson ($fixtures.statusStopped | ConvertTo-Json -Depth 6) `
        -Context "DryRun-statusStopped" `
        -RequiredResultProperties @("daemonConnected", "elevatedPrivileges", "running")
    if ($diagStopped.daemonConnected -ne $true -or $diagStopped.elevatedPrivileges -ne $true -or $diagStopped.running -ne $false) {
        throw "DryRun failed: unexpected values in statusStopped fixture."
    }
    Write-Host "[DRYRUN-PASS] Parsed 'ctl status' (stopped) IpcResponse.result schema." -ForegroundColor Green

    $diagRunning = ConvertFrom-CtlResponseJson `
        -RawJson ($fixtures.startRunning | ConvertTo-Json -Depth 6) `
        -Context "DryRun-startRunning" `
        -RequiredResultProperties @("daemonConnected", "elevatedPrivileges", "running")
    if ($diagRunning.running -ne $true) {
        throw "DryRun failed: expected running=true in startRunning fixture."
    }
    Write-Host "[DRYRUN-PASS] Parsed 'ctl start' (running) IpcResponse.result schema." -ForegroundColor Green

    $connsProxied = ConvertFrom-CtlResponseJson `
        -RawJson ($fixtures.connectionsProxied | ConvertTo-Json -Depth 6) `
        -Context "DryRun-connectionsProxied" `
        -ExpectResultArray `
        -RequiredArrayElementProperties @("processName", "matchedRule", "rxBytes", "status")
    if ($connsProxied.Count -ne 1 -or $connsProxied[0].processName -ne "curl.exe" -or $connsProxied[0].rxBytes -le 0) {
        throw "DryRun failed: unexpected connectionsProxied payload."
    }
    Write-Host "[DRYRUN-PASS] Parsed 'ctl connections' (proxied curl.exe, rxBytes=$($connsProxied[0].rxBytes)) array schema." -ForegroundColor Green

    $connsBlocked = ConvertFrom-CtlResponseJson `
        -RawJson ($fixtures.connectionsBlocked | ConvertTo-Json -Depth 6) `
        -Context "DryRun-connectionsBlocked" `
        -ExpectResultArray `
        -RequiredArrayElementProperties @("processName", "matchedRule", "rxBytes", "status")
    if ($connsBlocked.Count -ne 1 -or $connsBlocked[0].status -ne "blocked") {
        throw "DryRun failed: unexpected connectionsBlocked payload."
    }
    Write-Host "[DRYRUN-PASS] Parsed 'ctl connections' (blocked curl.exe) array schema." -ForegroundColor Green

    $connsKillSwitch = ConvertFrom-CtlResponseJson `
        -RawJson ($fixtures.connectionsKillSwitchBlocked | ConvertTo-Json -Depth 6) `
        -Context "DryRun-connectionsKillSwitchBlocked" `
        -ExpectResultArray `
        -RequiredArrayElementProperties @("processName", "matchedRule", "routeLabel", "status")
    if ($connsKillSwitch.Count -ne 1 -or $connsKillSwitch[0].status -ne "blocked" -or $connsKillSwitch[0].routeLabel -ne "BLOCKED" -or $connsKillSwitch[0].matchedRule -ne $ExpectedProxyRuleName) {
        throw "DryRun failed: unexpected connectionsKillSwitchBlocked payload."
    }
    $logsKillSwitch = ConvertFrom-CtlResponseJson `
        -RawJson ($fixtures.logsKillSwitchBlocked | ConvertTo-Json -Depth 6) `
        -Context "DryRun-logsKillSwitchBlocked" `
        -ExpectResultArray `
        -RequiredArrayElementProperties @("level", "component", "message")
    if ($logsKillSwitch.Count -ne 1 -or $logsKillSwitch[0].level -ne "WARN" -or $logsKillSwitch[0].message -notmatch "Kill-Switch blocked connection") {
        throw "DryRun failed: unexpected logsKillSwitchBlocked payload."
    }
    $parsedSshArgs = Split-ProcessCommandLineArgs `
        -ExecutablePath "C:\Windows\System32\OpenSSH\ssh.exe" `
        -CommandLine "`"C:\Windows\System32\OpenSSH\ssh.exe`" -N -D 127.0.0.1:1080 user@10.0.2.2"
    if ($parsedSshArgs -ne "-N -D 127.0.0.1:1080 user@10.0.2.2") {
        throw "DryRun failed: Split-ProcessCommandLineArgs returned '$parsedSshArgs'."
    }
    Write-Host "[DRYRUN-PASS] Parsed Scenario (j) Kill-Switch connections/logs fixtures and SOCKS5 restart command-line parser." -ForegroundColor Green

    if (-not (Test-IpInFakePool -IpAddressString "198.18.0.10" -PoolCidr $FakeIpCidr) -or (-not (Test-IpInFakePool -IpAddressString "198.19.255.254" -PoolCidr $FakeIpCidr))) {
        throw "DryRun failed: Test-IpInFakePool returned false for address inside $FakeIpCidr."
    }
    if ((Test-IpInFakePool -IpAddressString "93.184.216.34" -PoolCidr $FakeIpCidr) -or (Test-IpInFakePool -IpAddressString "10.0.0.1" -PoolCidr $FakeIpCidr)) {
        throw "DryRun failed: Test-IpInFakePool returned true for address outside $FakeIpCidr."
    }
    $fakeIpsDryRun = ConvertFrom-CtlResponseJson `
        -RawJson ($fixtures.fakeIpsSample | ConvertTo-Json -Depth 6) `
        -Context "DryRun-fakeIpsSample" `
        -ExpectResultArray `
        -RequiredArrayElementProperties @("fakeIp", "domain", "ttlRemainingSeconds")
    if ($fakeIpsDryRun.Count -ne 1 -or $fakeIpsDryRun[0].domain -ne "example.com" -or (-not (Test-IpInFakePool -IpAddressString ([string]$fakeIpsDryRun[0].fakeIp) -PoolCidr $FakeIpCidr))) {
        throw "DryRun failed: unexpected fakeIpsSample payload."
    }
    $connsFakeIpProxied = ConvertFrom-CtlResponseJson `
        -RawJson ($fixtures.connectionsFakeIpProxied | ConvertTo-Json -Depth 6) `
        -Context "DryRun-connectionsFakeIpProxied" `
        -ExpectResultArray `
        -RequiredArrayElementProperties @("processName", "targetHost", "resolvedDomain", "matchedRule", "rxBytes")
    if ($connsFakeIpProxied.Count -ne 1 -or $connsFakeIpProxied[0].resolvedDomain -ne "example.com") {
        throw "DryRun failed: unexpected connectionsFakeIpProxied payload."
    }
    $logsDnsFlushDryRun = ConvertFrom-CtlResponseJson `
        -RawJson ($fixtures.logsDnsCacheFlushed | ConvertTo-Json -Depth 6) `
        -Context "DryRun-logsDnsCacheFlushed" `
        -ExpectResultArray `
        -RequiredArrayElementProperties @("level", "component", "message")
    if ($logsDnsFlushDryRun.Count -ne 1 -or $logsDnsFlushDryRun[0].component -ne "FakeIpDNS" -or $logsDnsFlushDryRun[0].message -notmatch "startup via (dnsapi\.dll!DnsFlushResolverCache|ipconfig /flushdns)") {
        throw "DryRun failed: unexpected logsDnsCacheFlushed payload."
    }
    Write-Host "[DRYRUN-PASS] Verified Fake-IP CIDR pool helper, 'ctl fake-ips', domain-routed connection, and OS DNS cache flush fixtures for Scenarios (k)-(n)." -ForegroundColor Green

    $upsertAck = ConvertFrom-CtlResponseJson `
        -RawJson ($fixtures.upsertRuleOk | ConvertTo-Json -Depth 6) `
        -Context "DryRun-upsertRuleOk" `
        -RequiredResultProperties @("ok")
    $removeAck = ConvertFrom-CtlResponseJson `
        -RawJson ($fixtures.removeRuleOk | ConvertTo-Json -Depth 6) `
        -Context "DryRun-removeRuleOk" `
        -RequiredResultProperties @("ok")
    if ($upsertAck.ok -ne $true -or $removeAck.ok -ne $true) {
        throw "DryRun failed: unexpected upsert/remove rule response."
    }
    Write-Host "[DRYRUN-PASS] Parsed 'ctl upsert-rule' and 'ctl remove-rule' responses." -ForegroundColor Green

    $stateObj = ConvertFrom-CtlResponseJson `
        -RawJson ($fixtures.stateSample | ConvertTo-Json -Depth 8) `
        -Context "DryRun-stateSample" `
        -RequiredResultProperties @("diagnostics", "profile")
    if (@($stateObj.profile.rules).Count -ne 1) {
        throw "DryRun failed: unexpected rules count in stateSample."
    }
    Write-Host "[DRYRUN-PASS] Parsed 'ctl state' full daemon state response." -ForegroundColor Green

    # Verify legacy 'data' field is rejected with a clear schema mismatch message
    $rejectedLegacy = $false
    try {
        $null = ConvertFrom-CtlResponseJson `
            -RawJson ($fixtures.legacyMalformedDataField | ConvertTo-Json -Depth 6) `
            -Context "DryRun-legacyMalformedDataField" `
            -RequiredResultProperties @("running")
    } catch {
        if ($_.Exception.Message -match "missing top-level 'result' field") {
            $rejectedLegacy = $true
        } else {
            throw "DryRun failed: unexpected error message for malformed response: $($_.Exception.Message)"
        }
    }
    if (-not $rejectedLegacy) {
        throw "DryRun failed: legacy 'data' field response was not rejected."
    }
    Write-Host "[DRYRUN-PASS] Rejected malformed 'data' field response with explicit schema error." -ForegroundColor Green
    Write-Host "=== DRY RUN COMPLETED SUCCESSFULLY (0 errors) ===" -ForegroundColor Green
    exit 0
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
    if (Test-Path -LiteralPath (Join-Path $PSScriptRoot $RouteWardExeName)) {
        $resolvedBinDir = $PSScriptRoot
    } elseif (-not [string]::IsNullOrWhiteSpace($repoRootCandidate)) {
        $releaseCandidate = Join-Path $repoRootCandidate "target\release"
        if (Test-Path -LiteralPath (Join-Path $releaseCandidate $RouteWardExeName)) {
            $resolvedBinDir = $releaseCandidate
        }
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
# Process & CTL Management (Bugs 3 & 4 fix: track all daemon PIDs and isolate scenarios)
# ---------------------------------------------------------------------------
$script:RawCtlCapture = New-Object System.Collections.Generic.List[string]
$script:StartedDaemonPids = New-Object System.Collections.Generic.HashSet[int]
$script:CurrentDaemonProc = $null

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

function Start-TrackedDaemon {
    param(
        [string]$ExePath,
        [string]$WorkDir
    )
    $proc = Start-Process -FilePath $ExePath -ArgumentList @("daemon") -WorkingDirectory $WorkDir -WindowStyle Hidden -PassThru
    $null = $script:StartedDaemonPids.Add([int]$proc.Id)
    $script:CurrentDaemonProc = $proc
    return $proc
}

function Stop-AllTrackedDaemons {
    param(
        [string]$ExePath,
        [string]$FullPipePath,
        [switch]$ForceKillOnly
    )
    # 1. If graceful stop is allowed and the pipe is present, ask the daemon to stop interception first
    if (-not $ForceKillOnly.IsPresent -and (Test-NamedPipeExists -FullPipePath $FullPipePath)) {
        try {
            $null = Invoke-RouteWardCtl -ExePath $ExePath -CtlArgs @("stop") -Label "Cleanup-GracefulStop"
            Start-Sleep -Milliseconds 150
        } catch {
            # Continue to PID termination
        }
    }

    # 2. Terminate every tracked daemon PID
    foreach ($trackedPid in @($script:StartedDaemonPids)) {
        $p = Get-Process -Id $trackedPid -ErrorAction SilentlyContinue
        if ($null -ne $p) {
            Stop-Process -Id $trackedPid -Force -ErrorAction SilentlyContinue
            Wait-Process -Id $trackedPid -Timeout 5 -ErrorAction SilentlyContinue
        }
    }

    # 3. Ensure no stray routeward daemon process survives
    $strayProcs = @(Get-Process -Name "routeward" -ErrorAction SilentlyContinue)
    foreach ($sp in $strayProcs) {
        Stop-Process -Id $sp.Id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $sp.Id -Timeout 5 -ErrorAction SilentlyContinue
    }

    $script:CurrentDaemonProc = $null
    $null = Wait-ForNamedPipeAbsent -FullPipePath $FullPipePath -TimeoutMs 3000 -IntervalMs 100
}

function Ensure-ScenarioDaemonState {
    param(
        [string]$ExePath,
        [string]$WorkDir,
        [string]$FullPipePath,
        [int]$TimeoutMs,
        [int]$IntervalMs,
        [bool]$RequireInterceptionRunning
    )
    $needStart = $true
    if ($null -ne $script:CurrentDaemonProc -and (-not $script:CurrentDaemonProc.HasExited) -and (Test-NamedPipeExists -FullPipePath $FullPipePath)) {
        $needStart = $false
    }

    if ($needStart) {
        Stop-AllTrackedDaemons -ExePath $ExePath -FullPipePath $FullPipePath -ForceKillOnly
        $null = Start-TrackedDaemon -ExePath $ExePath -WorkDir $WorkDir
        if (-not (Wait-ForNamedPipe -FullPipePath $FullPipePath -TimeoutMs $TimeoutMs -IntervalMs $IntervalMs)) {
            throw "Failed to start daemon or bind pipe '$FullPipePath' within ${TimeoutMs}ms."
        }
    }

    $statusRaw = Invoke-RouteWardCtl -ExePath $ExePath -CtlArgs @("status") -Label "EnsureState-status"
    $diag = ConvertFrom-CtlResponseJson `
        -RawJson $statusRaw.RawText `
        -Context "EnsureState-status" `
        -RequiredResultProperties @("daemonConnected", "elevatedPrivileges", "running")

    if ($RequireInterceptionRunning -and (-not $diag.running)) {
        $startRaw = Invoke-RouteWardCtl -ExePath $ExePath -CtlArgs @("start") -Label "EnsureState-start"
        $startDiag = ConvertFrom-CtlResponseJson `
            -RawJson $startRaw.RawText `
            -Context "EnsureState-start" `
            -RequiredResultProperties @("running")
        if (-not $startDiag.running) {
            throw "Ensure-ScenarioDaemonState failed to start interception."
        }
    } elseif ((-not $RequireInterceptionRunning) -and $diag.running) {
        $stopRaw = Invoke-RouteWardCtl -ExePath $ExePath -CtlArgs @("stop") -Label "EnsureState-stop"
        $stopDiag = ConvertFrom-CtlResponseJson `
            -RawJson $stopRaw.RawText `
            -Context "EnsureState-stop" `
            -RequiredResultProperties @("running")
        if ($stopDiag.running) {
            throw "Ensure-ScenarioDaemonState failed to stop interception."
        }
    }
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

$scenarioResults = New-Object System.Collections.Generic.List[PSCustomObject]
$auditNotes = New-Object System.Collections.Generic.List[string]
$postCleanupCurlStatus = "Not executed"

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
        Stop-AllTrackedDaemons -ExePath $routeWardExePath -FullPipePath $PipeName -ForceKillOnly
        $procA = Start-TrackedDaemon -ExePath $routeWardExePath -WorkDir $resolvedBinDir
        $pipeReady = Wait-ForNamedPipe -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs
        if ($pipeReady -and (-not $procA.HasExited)) {
            if ($null -eq $initialProfileBytes -and (Test-Path -LiteralPath $activeProfilePath)) {
                $initialProfileBytes = [System.IO.File]::ReadAllBytes($activeProfilePath)
                $profileCapturedAfterDaemonInit = $true
            }
            Record-ScenarioResult -Id "a" -Status "PASS" -Title "Daemon background startup" -Detail "Daemon PID=$($procA.Id) listening on $PipeName"
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
        Ensure-ScenarioDaemonState -ExePath $routeWardExePath -WorkDir $resolvedBinDir -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs -RequireInterceptionRunning $false

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
        Ensure-ScenarioDaemonState -ExePath $routeWardExePath -WorkDir $resolvedBinDir -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs -RequireInterceptionRunning $false

        $statusRes = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("status") -Label "Scenario-c-status"
        if ($statusRes.ExitCode -ne 0) {
            Record-ScenarioResult -Id "c" -Status "FAIL" -Title "ctl status initial state" -Detail "ctl status exited with code $($statusRes.ExitCode)"
        } else {
            $diag = ConvertFrom-CtlResponseJson `
                -RawJson $statusRes.RawText `
                -Context "Scenario-c-status" `
                -RequiredResultProperties @("daemonConnected", "elevatedPrivileges", "running")
            if ($diag.daemonConnected -eq $true -and $diag.elevatedPrivileges -eq $true -and $diag.running -eq $false) {
                Record-ScenarioResult -Id "c" -Status "PASS" -Title "ctl status initial state" -Detail "daemonConnected=true, elevatedPrivileges=true, running=false"
            } else {
                Record-ScenarioResult -Id "c" -Status "FAIL" -Title "ctl status initial state" -Detail "Unexpected status values: daemonConnected=$($diag.daemonConnected), elevated=$($diag.elevatedPrivileges), running=$($diag.running)"
            }
        }
    } catch {
        Record-ScenarioResult -Id "c" -Status "FAIL" -Title "ctl status initial state" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (d): ctl start then curl.exe (HTTP 200, ctl connections shows curl.exe, expected rule, rxBytes > 0)
    # -----------------------------------------------------------------------
    try {
        Ensure-ScenarioDaemonState -ExePath $routeWardExePath -WorkDir $resolvedBinDir -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs -RequireInterceptionRunning $false

        $startRes = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("start") -Label "Scenario-d-start"
        $startDiag = ConvertFrom-CtlResponseJson `
            -RawJson $startRes.RawText `
            -Context "Scenario-d-start" `
            -RequiredResultProperties @("running")

        if ($startRes.ExitCode -ne 0 -or $startDiag.running -ne $true) {
            Record-ScenarioResult -Id "d" -Status "FAIL" -Title "ctl start and SOCKS5 routing" -Detail "ctl start failed or result.running!=true"
        } else {
            $curlRes = Invoke-UnproxiedCurl -CurlBin $CurlExePath -Url $TestUrl -TimeoutSec $CurlTimeoutSec
            Start-Sleep -Milliseconds $PollIntervalMs
            $connsRes = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("connections") -Label "Scenario-d-connections"
            $connsList = ConvertFrom-CtlResponseJson `
                -RawJson $connsRes.RawText `
                -Context "Scenario-d-connections" `
                -ExpectResultArray `
                -RequiredArrayElementProperties @("processName", "matchedRule", "rxBytes", "status")

            $matchingConn = $null
            foreach ($c in $connsList) {
                if ($c.processName -ieq "curl.exe" -and $c.matchedRule -eq $ExpectedProxyRuleName -and ([int64]$c.rxBytes) -gt 0) {
                    $matchingConn = $c
                    break
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
    # Scenario (e): Temporary Block rule for curl.exe via ctl upsert-rule / remove-rule
    # -----------------------------------------------------------------------
    try {
        Ensure-ScenarioDaemonState -ExePath $routeWardExePath -WorkDir $resolvedBinDir -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs -RequireInterceptionRunning $true

        $stateBeforeRaw = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("state") -Label "Scenario-e-state-before"
        $stateBefore = ConvertFrom-CtlResponseJson `
            -RawJson $stateBeforeRaw.RawText `
            -Context "Scenario-e-state-before" `
            -RequiredResultProperties @("profile")
        $rulesBeforeJson = ($stateBefore.profile.rules | ConvertTo-Json -Compress -Depth 8)

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

        $tempRuleFile = Write-Utf8NoBomJsonTempFile -JsonText $blockRuleJson
        try {
            $upsertRes = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("upsert-rule", "--json-file", $tempRuleFile) -Label "Scenario-e-upsert-block"
            $null = ConvertFrom-CtlResponseJson -RawJson $upsertRes.RawText -Context "Scenario-e-upsert-block" -RequiredResultProperties @("ok")
        } finally {
            if (Test-Path -LiteralPath $tempRuleFile) {
                Remove-Item -LiteralPath $tempRuleFile -Force -ErrorAction SilentlyContinue
            }
        }

        try {
            $curlBlocked = Invoke-UnproxiedCurl -CurlBin $CurlExePath -Url $TestUrl -TimeoutSec 5
            Start-Sleep -Milliseconds $PollIntervalMs
            $connsBlockedRes = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("connections") -Label "Scenario-e-connections"
            $connsBlockedList = ConvertFrom-CtlResponseJson `
                -RawJson $connsBlockedRes.RawText `
                -Context "Scenario-e-connections" `
                -ExpectResultArray `
                -RequiredArrayElementProperties @("processName", "matchedRule", "status")
        } finally {
            $remRes = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("remove-rule", "--id", $TempBlockRuleId) -Label "Scenario-e-remove-block"
            $null = ConvertFrom-CtlResponseJson -RawJson $remRes.RawText -Context "Scenario-e-remove-block" -RequiredResultProperties @("ok")
        }

        $stateAfterRaw = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("state") -Label "Scenario-e-state-after"
        $stateAfter = ConvertFrom-CtlResponseJson `
            -RawJson $stateAfterRaw.RawText `
            -Context "Scenario-e-state-after" `
            -RequiredResultProperties @("profile")
        $rulesAfterJson = ($stateAfter.profile.rules | ConvertTo-Json -Compress -Depth 8)
        $profileRestoredIdentical = ($rulesBeforeJson -eq $rulesAfterJson)
        if ($profileRestoredIdentical) {
            $profileModifiedByScript = $false
        }

        $sawBlockedConn = $false
        foreach ($c in $connsBlockedList) {
            if ($c.processName -ieq "curl.exe" -and $c.status -eq "blocked") {
                $sawBlockedConn = $true
                break
            }
        }

        if ($curlBlocked.ExitCode -ne 0 -and $sawBlockedConn -and $profileRestoredIdentical) {
            Record-ScenarioResult -Id "e" -Status "PASS" -Title "Temporary Block rule via ctl" -Detail "curl failed as expected (exit=$($curlBlocked.ExitCode)), connection marked blocked, rule removed and profile verified identical"
        } else {
            Record-ScenarioResult -Id "e" -Status "FAIL" -Title "Temporary Block rule via ctl" -Detail "curlExit=$($curlBlocked.ExitCode), sawBlocked=$sawBlockedConn, profileRestoredIdentical=$profileRestoredIdentical"
        }
    } catch {
        Record-ScenarioResult -Id "e" -Status "FAIL" -Title "Temporary Block rule via ctl" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (f): ctl stop removes firewall rule and curl returns HTTP 200 directly
    # -----------------------------------------------------------------------
    try {
        Ensure-ScenarioDaemonState -ExePath $routeWardExePath -WorkDir $resolvedBinDir -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs -RequireInterceptionRunning $true

        $stopRes = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("stop") -Label "Scenario-f-stop"
        $stopDiag = ConvertFrom-CtlResponseJson `
            -RawJson $stopRes.RawText `
            -Context "Scenario-f-stop" `
            -RequiredResultProperties @("running")
        Start-Sleep -Milliseconds $PollIntervalMs
        $fwStillPresent = Test-FirewallRulePresent -RuleName $FirewallRuleName
        $curlDirect = Invoke-UnproxiedCurl -CurlBin $CurlExePath -Url $TestUrl -TimeoutSec $CurlTimeoutSec

        if ($stopRes.ExitCode -eq 0 -and $stopDiag.running -eq $false -and (-not $fwStillPresent) -and $curlDirect.ExitCode -eq 0 -and $curlDirect.HttpCode -eq $ExpectedHttpStatus) {
            Record-ScenarioResult -Id "f" -Status "PASS" -Title "ctl stop and direct pass-through" -Detail "Firewall rule '$FirewallRuleName' removed and direct curl returned HTTP $($curlDirect.HttpCode)"
        } else {
            Record-ScenarioResult -Id "f" -Status "FAIL" -Title "ctl stop and direct pass-through" -Detail "running=$($stopDiag.running), fwPresent=$fwStillPresent, curlHttp=$($curlDirect.HttpCode)"
        }
    } catch {
        Record-ScenarioResult -Id "f" -Status "FAIL" -Title "ctl stop and direct pass-through" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (g): Crash test (ctl start, Stop-Process -Force on daemon, fail-open curl 200, orphaned firewall rule present)
    # -----------------------------------------------------------------------
    try {
        Ensure-ScenarioDaemonState -ExePath $routeWardExePath -WorkDir $resolvedBinDir -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs -RequireInterceptionRunning $true
        Start-Sleep -Milliseconds $PollIntervalMs
        $fwBeforeCrash = Test-FirewallRulePresent -RuleName $FirewallRuleName

        if (-not $fwBeforeCrash) {
            Record-ScenarioResult -Id "g" -Status "FAIL" -Title "Daemon crash fail-open & orphaned rule" -Detail "Firewall rule '$FirewallRuleName' was not present after ctl start"
        } else {
            $killedPid = $script:CurrentDaemonProc.Id
            Stop-AllTrackedDaemons -ExePath $routeWardExePath -FullPipePath $PipeName -ForceKillOnly
            Start-Sleep -Milliseconds $PollIntervalMs

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
    #               (Self-contained: ensures daemon is stopped and orphaned rule exists first)
    # -----------------------------------------------------------------------
    try {
        Stop-AllTrackedDaemons -ExePath $routeWardExePath -FullPipePath $PipeName -ForceKillOnly
        Ensure-SyntheticFirewallRulePresent -RuleName $FirewallRuleName -ProgramPath $routeWardExePath -Port $TransparentRelayPort

        $daemonLogBeforeLines = 0
        $existingDaemonLogs = @(Get-ChildItem -Path $daemonLogsDir -Filter $logWildcard -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
        if ($existingDaemonLogs.Count -gt 0) {
            $daemonLogBeforeLines = @(Get-Content -LiteralPath $existingDaemonLogs[0].FullName -Encoding UTF8).Count
        }

        $null = Start-TrackedDaemon -ExePath $routeWardExePath -WorkDir $resolvedBinDir
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
        Ensure-ScenarioDaemonState -ExePath $routeWardExePath -WorkDir $resolvedBinDir -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs -RequireInterceptionRunning $false
        $null = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("status") -Label "Scenario-i-status-log-check"
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

    # -----------------------------------------------------------------------
    # Scenario (j): Kill-Switch (killSwitchEnabled=true) — SOCKS5 proxy stopped
    #               during test, curl.exe matched by Proxy rule fails without
    #               falling back to Direct, and ctl connections reports Blocked
    # -----------------------------------------------------------------------
    try {
        Ensure-ScenarioDaemonState -ExePath $routeWardExePath -WorkDir $resolvedBinDir -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs -RequireInterceptionRunning $true

        $socksListenerInfo = Get-LocalPortListenerProcessInfo -Port $Socks5Port
        $socksStoppedByScript = $false

        try {
            if ($null -ne $socksListenerInfo -and $socksListenerInfo.Pid -gt 0) {
                Stop-Process -Id $socksListenerInfo.Pid -Force -ErrorAction SilentlyContinue
                Wait-Process -Id $socksListenerInfo.Pid -Timeout 5 -ErrorAction SilentlyContinue
                $socksStoppedByScript = $true
            }

            $stopWaitSw = [System.Diagnostics.Stopwatch]::StartNew()
            while ($stopWaitSw.ElapsedMilliseconds -lt 3000) {
                if (-not (Test-TcpEndpoint -TargetHost $Socks5Host -Port $Socks5Port -TimeoutMs 250)) {
                    break
                }
                Start-Sleep -Milliseconds 100
            }

            $socksStillUp = Test-TcpEndpoint -TargetHost $Socks5Host -Port $Socks5Port -TimeoutMs 300
            if ($socksStillUp) {
                Record-ScenarioResult -Id "j" -Status "FAIL" -Title "Kill-Switch blocks curl when SOCKS5 proxy is stopped" -Detail "Could not stop SOCKS5 listener on ${Socks5Host}:${Socks5Port}"
            } else {
                $curlKillSwitch = Invoke-UnproxiedCurl -CurlBin $CurlExePath -Url $TestUrl -TimeoutSec 5
                Start-Sleep -Milliseconds $PollIntervalMs

                $connsKsRes = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("connections") -Label "Scenario-j-connections"
                $connsKsList = ConvertFrom-CtlResponseJson `
                    -RawJson $connsKsRes.RawText `
                    -Context "Scenario-j-connections" `
                    -ExpectResultArray `
                    -RequiredArrayElementProperties @("processName", "matchedRule", "routeLabel", "status")

                $logsKsRes = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("logs") -Label "Scenario-j-logs"
                $logsKsList = ConvertFrom-CtlResponseJson `
                    -RawJson $logsKsRes.RawText `
                    -Context "Scenario-j-logs" `
                    -ExpectResultArray `
                    -RequiredArrayElementProperties @("level", "component", "message")

                $sawKillSwitchBlockedConn = $false
                foreach ($c in $connsKsList) {
                    if ($c.processName -ieq "curl.exe" -and $c.matchedRule -eq $ExpectedProxyRuleName -and $c.status -eq "blocked" -and $c.routeLabel -eq "BLOCKED") {
                        $sawKillSwitchBlockedConn = $true
                        break
                    }
                }

                $sawKillSwitchWarnLog = $false
                foreach ($l in $logsKsList) {
                    if ($l.level -eq "WARN" -and ([string]$l.message).Contains("Kill-Switch blocked connection")) {
                        $sawKillSwitchWarnLog = $true
                        break
                    }
                }

                if ($curlKillSwitch.ExitCode -ne 0 -and $curlKillSwitch.HttpCode -ne $ExpectedHttpStatus -and $sawKillSwitchBlockedConn -and $sawKillSwitchWarnLog) {
                    Record-ScenarioResult -Id "j" -Status "PASS" -Title "Kill-Switch blocks curl when SOCKS5 proxy is stopped" -Detail "curl failed as expected (exit=$($curlKillSwitch.ExitCode) http=$($curlKillSwitch.HttpCode), no Direct leak), connection recorded with status=blocked/routeLabel=BLOCKED, WARN logged"
                } else {
                    Record-ScenarioResult -Id "j" -Status "FAIL" -Title "Kill-Switch blocks curl when SOCKS5 proxy is stopped" -Detail "curlExit=$($curlKillSwitch.ExitCode) http=$($curlKillSwitch.HttpCode), sawBlockedConn=$sawKillSwitchBlockedConn, sawWarnLog=$sawKillSwitchWarnLog"
                }
            }
        } finally {
            if ($socksStoppedByScript) {
                $restartedOk = $false
                if ($null -ne $socksListenerInfo -and (-not [string]::IsNullOrWhiteSpace($socksListenerInfo.ExecutablePath)) -and (Test-Path -LiteralPath $socksListenerInfo.ExecutablePath)) {
                    try {
                        $restartArgs = Split-ProcessCommandLineArgs -ExecutablePath $socksListenerInfo.ExecutablePath -CommandLine $socksListenerInfo.CommandLine
                        $restartedProc = if ([string]::IsNullOrWhiteSpace($restartArgs)) {
                            Start-Process -FilePath $socksListenerInfo.ExecutablePath -WindowStyle Hidden -PassThru
                        } else {
                            Start-Process -FilePath $socksListenerInfo.ExecutablePath -ArgumentList $restartArgs -WindowStyle Hidden -PassThru
                        }
                        $restartSw = [System.Diagnostics.Stopwatch]::StartNew()
                        while ($restartSw.ElapsedMilliseconds -lt 3000) {
                            if (Test-TcpEndpoint -TargetHost $Socks5Host -Port $Socks5Port -TimeoutMs 250) {
                                $restartedOk = $true
                                break
                            }
                            Start-Sleep -Milliseconds 150
                        }
                        if ($restartedOk) {
                            $msg = "SOCKS5 listener on ${Socks5Host}:${Socks5Port} was automatically restarted after Scenario (j) (PID=$($restartedProc.Id))."
                            $auditNotes.Add($msg)
                            Write-Host "[INFO] $msg" -ForegroundColor Cyan
                        } elseif ($null -ne $restartedProc -and (-not $restartedProc.HasExited)) {
                            Stop-Process -Id $restartedProc.Id -Force -ErrorAction SilentlyContinue
                        }
                    } catch {
                        # Will report manual restart notice below
                    }
                }
                if (-not $restartedOk) {
                    $noticeMsg = "SOCKS5 listener on ${Socks5Host}:${Socks5Port} (original PID=$($socksListenerInfo.Pid)) was stopped for Scenario (j) and requires manual restart before the next test run."
                    $auditNotes.Add("NOTICE: $noticeMsg")
                    Write-Host "[NOTICE] $noticeMsg" -ForegroundColor Yellow
                }
            }
        }
    } catch {
        Record-ScenarioResult -Id "j" -Status "FAIL" -Title "Kill-Switch blocks curl when SOCKS5 proxy is stopped" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (k): Resolve-DnsName on a public domain toward an explicit external
    #               resolver returns a Fake-IP (198.18.0.0/15), and curl.exe to
    #               that domain is routed via the SOCKS5 proxy with its domain name
    # -----------------------------------------------------------------------
    try {
        Ensure-ScenarioDaemonState -ExePath $routeWardExePath -WorkDir $resolvedBinDir -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs -RequireInterceptionRunning $true
        $null = Clear-AllWindowsDnsCaches

        $dnsResK = @(Resolve-DnsName -Name $PublicDnsTestDomain -Type A -Server $ExternalDnsServer -DnsOnly -NoHostsFile -ErrorAction Stop | Where-Object { $null -ne $_.IPAddress })
        $resolvedIpK = if ($dnsResK.Count -gt 0) { [string]$dnsResK[0].IPAddress } else { "" }
        $isFakeIpK = Test-IpInFakePool -IpAddressString $resolvedIpK -PoolCidr $FakeIpCidr

        $fakeIpsResK = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("fake-ips") -Label "Scenario-k-fake-ips"
        $fakeIpsListK = ConvertFrom-CtlResponseJson `
            -RawJson $fakeIpsResK.RawText `
            -Context "Scenario-k-fake-ips" `
            -ExpectResultArray `
            -RequiredArrayElementProperties @("fakeIp", "domain", "ttlRemainingSeconds")

        $sawFakeIpEntryK = $false
        foreach ($entry in $fakeIpsListK) {
            if ($entry.domain -ieq $PublicDnsTestDomain -and (Test-IpInFakePool -IpAddressString ([string]$entry.fakeIp) -PoolCidr $FakeIpCidr)) {
                $sawFakeIpEntryK = $true
                break
            }
        }

        $curlResK = Invoke-UnproxiedCurl -CurlBin $CurlExePath -Url $TestUrl -TimeoutSec $CurlTimeoutSec
        Start-Sleep -Milliseconds $PollIntervalMs

        $connsResK = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("connections") -Label "Scenario-k-connections"
        $connsListK = ConvertFrom-CtlResponseJson `
            -RawJson $connsResK.RawText `
            -Context "Scenario-k-connections" `
            -ExpectResultArray `
            -RequiredArrayElementProperties @("processName", "targetHost", "matchedRule", "rxBytes", "status")

        $matchingDomainConnK = $null
        foreach ($c in $connsListK) {
            $domMatch = ($c.targetHost -ieq $PublicDnsTestDomain) -or ($null -ne $c.resolvedDomain -and $c.resolvedDomain -ieq $PublicDnsTestDomain)
            if ($c.processName -ieq "curl.exe" -and $domMatch -and $c.matchedRule -eq $ExpectedProxyRuleName -and ([int64]$c.rxBytes) -gt 0) {
                $matchingDomainConnK = $c
                break
            }
        }

        if ($isFakeIpK -and $sawFakeIpEntryK -and $curlResK.ExitCode -eq 0 -and $curlResK.HttpCode -eq $ExpectedHttpStatus -and $null -ne $matchingDomainConnK) {
            Record-ScenarioResult -Id "k" -Status "PASS" -Title "Fake-IP DNS interception & domain routing via SOCKS5" -Detail "$PublicDnsTestDomain -> $resolvedIpK (in $FakeIpCidr), curl HTTP $($curlResK.HttpCode) routed with domain '$($matchingDomainConnK.targetHost)'"
        } else {
            Record-ScenarioResult -Id "k" -Status "FAIL" -Title "Fake-IP DNS interception & domain routing via SOCKS5" -Detail "resolvedIp='$resolvedIpK' (isFakeIp=$isFakeIpK), inCtlTable=$sawFakeIpEntryK, curlHttp=$($curlResK.HttpCode), domainConnFound=$($null -ne $matchingDomainConnK)"
        }
    } catch {
        Record-ScenarioResult -Id "k" -Status "FAIL" -Title "Fake-IP DNS interception & domain routing via SOCKS5" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (l): Resolve-DnsName on the VM's Active Directory / primary DNS
    #               suffix continues to resolve normally and directly (outside Fake-IP)
    # -----------------------------------------------------------------------
    try {
        Ensure-ScenarioDaemonState -ExePath $routeWardExePath -WorkDir $resolvedBinDir -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs -RequireInterceptionRunning $true
        $adDomain = Get-MachineActiveDirectoryOrPrimaryDnsSuffix
        if ([string]::IsNullOrWhiteSpace($adDomain)) {
            Record-ScenarioResult -Id "l" -Status "SKIP" -Title "Active Directory domain direct DNS bypass" -Detail "No Active Directory domain or primary DNS suffix configured on this machine"
        } else {
            $adRecords = @(Resolve-DnsName -Name $adDomain -Type A -DnsOnly -NoHostsFile -ErrorAction Stop | Where-Object { $null -ne $_.IPAddress })
            $adIps = @($adRecords | ForEach-Object { [string]$_.IPAddress })
            $anyInFakePool = $false
            foreach ($ipStr in $adIps) {
                if (Test-IpInFakePool -IpAddressString $ipStr -PoolCidr $FakeIpCidr) {
                    $anyInFakePool = $true
                    break
                }
            }
            if ($adIps.Count -gt 0 -and (-not $anyInFakePool)) {
                Record-ScenarioResult -Id "l" -Status "PASS" -Title "Active Directory domain direct DNS bypass" -Detail "AD domain '$adDomain' resolved directly to $($adIps -join ', ') (outside $FakeIpCidr)"
            } else {
                Record-ScenarioResult -Id "l" -Status "FAIL" -Title "Active Directory domain direct DNS bypass" -Detail "AD domain '$adDomain' returned IPs=[$($adIps -join ', ')], anyInFakePool=$anyInFakePool"
            }
        }
    } catch {
        Record-ScenarioResult -Id "l" -Status "FAIL" -Title "Active Directory domain direct DNS bypass" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (m): After ctl stop and Clear-DnsClientCache, normal DNS resolution
    #               returns a real IP outside the Fake-IP pool
    # -----------------------------------------------------------------------
    try {
        Ensure-ScenarioDaemonState -ExePath $routeWardExePath -WorkDir $resolvedBinDir -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs -RequireInterceptionRunning $true
        $stopResM = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("stop") -Label "Scenario-m-stop"
        $stopDiagM = ConvertFrom-CtlResponseJson `
            -RawJson $stopResM.RawText `
            -Context "Scenario-m-stop" `
            -RequiredResultProperties @("running")
        $null = Clear-AllWindowsDnsCaches

        $dnsResM = @(Resolve-DnsName -Name $PublicDnsTestDomain -Type A -Server $ExternalDnsServer -DnsOnly -NoHostsFile -ErrorAction Stop | Where-Object { $null -ne $_.IPAddress })
        $resolvedIpM = if ($dnsResM.Count -gt 0) { [string]$dnsResM[0].IPAddress } else { "" }
        $isFakeIpM = Test-IpInFakePool -IpAddressString $resolvedIpM -PoolCidr $FakeIpCidr

        if ($stopResM.ExitCode -eq 0 -and $stopDiagM.running -eq $false -and (-not [string]::IsNullOrWhiteSpace($resolvedIpM)) -and (-not $isFakeIpM)) {
            Record-ScenarioResult -Id "m" -Status "PASS" -Title "Post-stop direct DNS resolution outside Fake-IP pool" -Detail "After ctl stop + cache flush, $PublicDnsTestDomain resolved to real IP $resolvedIpM (outside $FakeIpCidr)"
        } else {
            Record-ScenarioResult -Id "m" -Status "FAIL" -Title "Post-stop direct DNS resolution outside Fake-IP pool" -Detail "running=$($stopDiagM.running), resolvedIp='$resolvedIpM', isFakeIp=$isFakeIpM"
        }
    } catch {
        Record-ScenarioResult -Id "m" -Status "FAIL" -Title "Post-stop direct DNS resolution outside Fake-IP pool" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (n): Starting the engine automatically flushes the OS DNS
    #               resolver cache (DnsFlushResolverCache / ipconfig /flushdns)
    # -----------------------------------------------------------------------
    try {
        Ensure-ScenarioDaemonState -ExePath $routeWardExePath -WorkDir $resolvedBinDir -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs -RequireInterceptionRunning $false

        # Pre-seed the Windows DNS Client cache while interception is stopped
        $null = Resolve-DnsName -Name $PublicDnsTestDomain -Type A -ErrorAction SilentlyContinue

        $startResN = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("start") -Label "Scenario-n-start"
        $startDiagN = ConvertFrom-CtlResponseJson `
            -RawJson $startResN.RawText `
            -Context "Scenario-n-start" `
            -RequiredResultProperties @("running")

        $cachedAfterStart = @()
        if (Get-Command -Name "Get-DnsClientCache" -ErrorAction SilentlyContinue) {
            $cachedAfterStart = @(Get-DnsClientCache -Entry $PublicDnsTestDomain -ErrorAction SilentlyContinue)
        }

        $logsResN = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("logs") -Label "Scenario-n-logs"
        $logsListN = ConvertFrom-CtlResponseJson `
            -RawJson $logsResN.RawText `
            -Context "Scenario-n-logs" `
            -ExpectResultArray `
            -RequiredArrayElementProperties @("level", "component", "message")

        $sawStartupFlushLog = $false
        $flushDetail = ""
        foreach ($l in $logsListN) {
            if ($l.component -eq "FakeIpDNS" -and ([string]$l.message) -match "startup via (dnsapi\.dll!DnsFlushResolverCache|ipconfig /flushdns)") {
                $sawStartupFlushLog = $true
                $flushDetail = [string]$l.message
                break
            }
        }

        if ($startResN.ExitCode -eq 0 -and $startDiagN.running -eq $true -and $sawStartupFlushLog -and $cachedAfterStart.Count -eq 0) {
            Record-ScenarioResult -Id "n" -Status "PASS" -Title "OS DNS cache flushed on engine startup" -Detail "$flushDetail; Get-DnsClientCache entries for $PublicDnsTestDomain after start = $($cachedAfterStart.Count)"
        } else {
            Record-ScenarioResult -Id "n" -Status "FAIL" -Title "OS DNS cache flushed on engine startup" -Detail "running=$($startDiagN.running), sawStartupFlushLog=$sawStartupFlushLog, cachedAfterStartCount=$($cachedAfterStart.Count)"
        }
    } catch {
        Record-ScenarioResult -Id "n" -Status "FAIL" -Title "OS DNS cache flushed on engine startup" -Detail $_.Exception.Message
    }
} finally {
    # -----------------------------------------------------------------------
    # Guardrail 4 (Bug 4 fix):
    # 1. Stop interception via ctl stop, then terminate all tracked daemon PIDs
    # 2. Verify zero routeward daemon processes remain alive
    # 3. Run routeward cleanup only after all daemon processes have exited
    # 4. Restore profile if modified
    # 5. Verify outbound curl connectivity and record it in the report
    # -----------------------------------------------------------------------
    Stop-AllTrackedDaemons -ExePath $routeWardExePath -FullPipePath $PipeName

    $survivingProcs = @(Get-Process -Name "routeward" -ErrorAction SilentlyContinue)
    if ($survivingProcs.Count -gt 0) {
        $survivingIds = ($survivingProcs | ForEach-Object { $_.Id }) -join ", "
        $auditNotes.Add("WARNING: Surviving routeward processes detected before cleanup (PIDs: $survivingIds); forcing termination.")
        foreach ($sp in $survivingProcs) {
            Stop-Process -Id $sp.Id -Force -ErrorAction SilentlyContinue
            Wait-Process -Id $sp.Id -Timeout 5 -ErrorAction SilentlyContinue
        }
    } else {
        $auditNotes.Add("Verified 0 surviving routeward processes prior to running 'routeward cleanup'.")
    }

    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $cleanupOut = & $routeWardExePath cleanup 2>&1
        $cleanupExit = $LASTEXITCODE
        $cleanupStr = ($cleanupOut | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
        $script:RawCtlCapture.Add("--- [Finally-Cleanup] routeward cleanup (exit=$cleanupExit) ---`r`n$cleanupStr")
        if ($cleanupExit -ne 0) {
            $forceOut = & $routeWardExePath cleanup --force 2>&1
            $forceExit = $LASTEXITCODE
            $forceStr = ($forceOut | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
            $script:RawCtlCapture.Add("--- [Finally-Cleanup-Force] routeward cleanup --force (exit=$forceExit) ---`r`n$forceStr")
        }
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

    $dnsFlushNotes = Clear-AllWindowsDnsCaches
    foreach ($fn in $dnsFlushNotes) {
        $auditNotes.Add($fn)
    }

    try {
        $finalCurl = Invoke-UnproxiedCurl -CurlBin $CurlExePath -Url $TestUrl -TimeoutSec $CurlTimeoutSec
        $postCleanupCurlStatus = "HTTP $($finalCurl.HttpCode) (curl exit=$($finalCurl.ExitCode), target=$TestUrl)"
        $auditNotes.Add("Post-cleanup outbound connectivity check: $postCleanupCurlStatus")
        Write-Host "Post-cleanup outbound connectivity check: $postCleanupCurlStatus"
    } catch {
        $postCleanupCurlStatus = "ERROR: $($_.Exception.Message)"
        $auditNotes.Add("Post-cleanup outbound connectivity check failed: $postCleanupCurlStatus")
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
$reportLines.Add("Post-Cleanup Connectivity: $postCleanupCurlStatus")
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
    $reportLines.Add("## 3. Audit Notes & Cleanup Verification")
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
