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

    # Name of the proxy rule this script provisions for curl.exe (the default profile ships no proxy and no rule).
    [Parameter(Mandatory = $false)]
    [string]$ExpectedProxyRuleName = "CLI Tools via SOCKS5 Proxy",

    [Parameter(Mandatory = $false)]
    [string]$ProvisionedProxyId = "proxy-win-regression-socks5",

    [Parameter(Mandatory = $false)]
    [string]$ProvisionedProxyName = "Windows Regression SOCKS5 Proxy",

    [Parameter(Mandatory = $false)]
    [string]$ProvisionedRuleId = "rule-win-regression-cli-socks5",

    [Parameter(Mandatory = $false)]
    [int]$ProvisionedRulePriority = 30,

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

    # A blocked TCP connection must be refused (curl exit 7 or 56) in less than this many milliseconds.
    [Parameter(Mandatory = $false)]
    [int]$BlockFastRejectMaxMs = 5000,

    # A blocked UDP probe must receive its ICMP rejection in less than this many milliseconds.
    [Parameter(Mandatory = $false)]
    [int]$UdpFastRejectMaxMs = 500,

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
    [string]$PublicDnsTestDomain = "",

    [Parameter(Mandatory = $false)]
    [string]$UdpTestServerExeName = "socks5_udp_test_server.exe",

    [Parameter(Mandatory = $false)]
    [int]$UdpTestProxyPort = 1082,

    [Parameter(Mandatory = $false)]
    [int]$UdpRefuseTestProxyPort = 1083,

    [Parameter(Mandatory = $false)]
    [string]$PublicNtpServer = "time.cloudflare.com",

    [Parameter(Mandatory = $false)]
    [int]$NtpPort = 123,

    [Parameter(Mandatory = $false)]
    [int]$Ipv6TestProxyPort = 1084,

    [Parameter(Mandatory = $false)]
    [int]$Ipv6TestHttpPort = 18080,

    [Parameter(Mandatory = $false)]
    [int]$Ipv6TestUdpPort = 18123
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding($false)
try {
    [Console]::InputEncoding = $script:Utf8NoBomEncoding
    [Console]::OutputEncoding = $script:Utf8NoBomEncoding
} catch {
    # Ignore if host does not attach a console handle
}
$OutputEncoding = $script:Utf8NoBomEncoding

$script:ScenarioExecutionPlan = @(
    [PSCustomObject]@{ ExecutionOrder = 1;  Id = "a"; RequiresSocks5 = $false; StopsSocks5 = $false; Title = "Daemon background startup" },
    [PSCustomObject]@{ ExecutionOrder = 2;  Id = "b"; RequiresSocks5 = $false; StopsSocks5 = $false; Title = "Profile & Named Pipe ACLs" },
    [PSCustomObject]@{ ExecutionOrder = 3;  Id = "c"; RequiresSocks5 = $false; StopsSocks5 = $false; Title = "ctl status initial state" },
    [PSCustomObject]@{ ExecutionOrder = 4;  Id = "d"; RequiresSocks5 = $true;  StopsSocks5 = $false; Title = "ctl start and SOCKS5 routing" },
    [PSCustomObject]@{ ExecutionOrder = 5;  Id = "e"; RequiresSocks5 = $false; StopsSocks5 = $false; Title = "Temporary Block rule via ctl" },
    [PSCustomObject]@{ ExecutionOrder = 6;  Id = "f"; RequiresSocks5 = $false; StopsSocks5 = $false; Title = "ctl stop and direct pass-through" },
    [PSCustomObject]@{ ExecutionOrder = 7;  Id = "g"; RequiresSocks5 = $false; StopsSocks5 = $false; Title = "Daemon crash fail-open & orphaned rule" },
    [PSCustomObject]@{ ExecutionOrder = 8;  Id = "h"; RequiresSocks5 = $false; StopsSocks5 = $false; Title = "Automatic orphan cleanup on daemon restart" },
    [PSCustomObject]@{ ExecutionOrder = 9;  Id = "i"; RequiresSocks5 = $false; StopsSocks5 = $false; Title = "Daemon & user log paths and CWD cleanliness" },
    [PSCustomObject]@{ ExecutionOrder = 10; Id = "k"; RequiresSocks5 = $true;  StopsSocks5 = $false; Title = "Fake-IP DNS interception & domain routing via SOCKS5" },
    [PSCustomObject]@{ ExecutionOrder = 11; Id = "l"; RequiresSocks5 = $false; StopsSocks5 = $false; Title = "Active Directory domain direct DNS bypass" },
    [PSCustomObject]@{ ExecutionOrder = 12; Id = "m"; RequiresSocks5 = $false; StopsSocks5 = $false; Title = "Post-stop direct DNS resolution outside Fake-IP pool" },
    [PSCustomObject]@{ ExecutionOrder = 13; Id = "n"; RequiresSocks5 = $false; StopsSocks5 = $false; Title = "OS DNS cache flushed on engine startup" },
    [PSCustomObject]@{ ExecutionOrder = 14; Id = "o"; RequiresSocks5 = $false; StopsSocks5 = $false; Title = "QUIC (UDP 443) rejected with ICMP Port Unreachable" },
    [PSCustomObject]@{ ExecutionOrder = 15; Id = "p"; RequiresSocks5 = $false; StopsSocks5 = $false; Title = "LLMNR (UDP 5355) blocks public FQDNs and allows local names" },
    [PSCustomObject]@{ ExecutionOrder = 16; Id = "q"; RequiresSocks5 = $false; StopsSocks5 = $false; Title = "Transparent UDP proxy routing (NTP UDP 123) & profile restoration" },
    [PSCustomObject]@{ ExecutionOrder = 17; Id = "r"; RequiresSocks5 = $false; StopsSocks5 = $false; Title = "Transparent UDP with proxy refusing UDP ASSOCIATE + Kill-Switch" },
    [PSCustomObject]@{ ExecutionOrder = 18; Id = "s"; RequiresSocks5 = $false; StopsSocks5 = $false; Title = "Transparent Direct UDP with process attribution" },
    [PSCustomObject]@{ ExecutionOrder = 19; Id = "t"; RequiresSocks5 = $false; StopsSocks5 = $false; Title = "IPv6 TCP interception & SOCKS5 ATYP=0x04 routing via WinDivert" },
    [PSCustomObject]@{ ExecutionOrder = 20; Id = "u"; RequiresSocks5 = $false; StopsSocks5 = $false; Title = "IPv6 UDP interception & SOCKS5 UDP ASSOCIATE ATYP=0x04 via WinDivert" },
    [PSCustomObject]@{ ExecutionOrder = 21; Id = "v"; RequiresSocks5 = $false; StopsSocks5 = $false; Title = "IPv6 DNS (port 53 UDP/TCP Fake-IP) & gated IPv6 DoT (port 853)" },
    [PSCustomObject]@{ ExecutionOrder = 22; Id = "w"; RequiresSocks5 = $false; StopsSocks5 = $false; Title = "IPv6 QUIC (UDP 443) rejected with ICMPv6 Port Unreachable" },
    [PSCustomObject]@{ ExecutionOrder = 23; Id = "x"; RequiresSocks5 = $false; StopsSocks5 = $false; Title = "Direct IPv6 UDP flow attributed to process in ctl connections" },
    [PSCustomObject]@{ ExecutionOrder = 24; Id = "y"; RequiresSocks5 = $false; StopsSocks5 = $false; Title = "Windows SCM service status & routeward-desktop --smoke-ipc" },
    [PSCustomObject]@{ ExecutionOrder = 25; Id = "z"; RequiresSocks5 = $false; StopsSocks5 = $false; Title = "DNS server processes get real DNS answers instead of Fake-IP" },
    [PSCustomObject]@{ ExecutionOrder = 26; Id = "j"; RequiresSocks5 = $true;  StopsSocks5 = $true;  Title = "Kill-Switch blocks curl when SOCKS5 proxy is stopped" }
)

$script:CurrentPowerShellHostExe = ([System.Diagnostics.Process]::GetCurrentProcess().ProcessName + ".exe")
$script:ExpectedUdpHostProcesses = @("powershell.exe", "pwsh.exe", $script:CurrentPowerShellHostExe) | Select-Object -Unique

function Get-ScenarioPlanEntry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id
    )
    foreach ($entry in $script:ScenarioExecutionPlan) {
        if ($entry.Id -eq $Id) {
            return $entry
        }
    }
    throw "Unknown scenario Id '$Id' in ScenarioExecutionPlan."
}

function Get-StartupDnsFlushMethodFromLogs {
    param(
        [Parameter(Mandatory = $false)]
        [object[]]$CtlLogItems = @(),

        [Parameter(Mandatory = $false)]
        [string]$DaemonLogDirectory = "",

        [Parameter(Mandatory = $false)]
        [string]$DaemonLogFilter = "RouteWard_*.log"
    )
    foreach ($l in @($CtlLogItems)) {
        if ($null -ne $l -and $l.component -eq "FakeIpDNS" -and ([string]$l.message) -match "startup via (?<method>dnsapi\.dll!DnsFlushResolverCache|ipconfig /flushdns)") {
            return [string]$Matches["method"]
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($DaemonLogDirectory) -and (Test-Path -LiteralPath $DaemonLogDirectory)) {
        $latestLogs = @(Get-ChildItem -Path $DaemonLogDirectory -Filter $DaemonLogFilter -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
        if ($latestLogs.Count -gt 0) {
            $linesUtf8 = @(Get-Content -LiteralPath $latestLogs[0].FullName -Encoding UTF8 -ErrorAction SilentlyContinue)
            for ($idx = $linesUtf8.Count - 1; $idx -ge 0; $idx--) {
                $ln = [string]$linesUtf8[$idx]
                if ($ln.Contains("[FakeIpDNS]") -and ($ln -match "startup via (?<method>dnsapi\.dll!DnsFlushResolverCache|ipconfig /flushdns)")) {
                    return [string]$Matches["method"]
                }
            }
        }
    }
    return ""
}

function New-DnsWireQueryPacket {
    param(
        [Parameter(Mandatory = $true)]
        [string]$QueryName,

        [Parameter(Mandatory = $false)]
        [uint16]$TransactionId = 0x5355,

        [Parameter(Mandatory = $false)]
        [uint16]$QType = 1
    )
    $bytes = New-Object System.Collections.Generic.List[byte]
    # Header: ID, Flags=0x0000, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    $bytes.Add([byte](($TransactionId -shr 8) -band 0xFF))
    $bytes.Add([byte]($TransactionId -band 0xFF))
    $bytes.AddRange([byte[]]@(0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))

    $trimmed = $QueryName.Trim().TrimEnd('.')
    foreach ($label in ($trimmed -split '\.')) {
        if (-not [string]::IsNullOrEmpty($label)) {
            $labelBytes = [System.Text.Encoding]::ASCII.GetBytes($label)
            $bytes.Add([byte]$labelBytes.Length)
            $bytes.AddRange($labelBytes)
        }
    }
    $bytes.Add([byte]0x00)
    # QTYPE (1=A, 28=AAAA), QCLASS=1 (IN)
    $bytes.AddRange([byte[]]@([byte](($QType -shr 8) -band 0xFF), [byte]($QType -band 0xFF), 0x00, 0x01))
    return ,$bytes.ToArray()
}

function New-NtpClientRequestPacket {
    $pkt = New-Object byte[] 48
    # LI = 0 (no warning), VN = 4 (NTPv4), Mode = 3 (Client) -> 0x23
    $pkt[0] = 0x23
    return ,$pkt
}

function Invoke-UdpNtpExchange {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetHost,

        [Parameter(Mandatory = $false)]
        [int]$Port = 123,

        [Parameter(Mandatory = $false)]
        [int]$ReceiveTimeoutMs = 3000
    )
    $udp = New-Object System.Net.Sockets.UdpClient
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $udp.Client.ReceiveTimeout = $ReceiveTimeoutMs
        $reqPkt = New-NtpClientRequestPacket
        $null = $udp.Send($reqPkt, $reqPkt.Length, $TargetHost, $Port)
        $remoteEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        try {
            $respBytes = $udp.Receive([ref]$remoteEp)
            $sw.Stop()
            $replyLen = if ($null -ne $respBytes) { [int]$respBytes.Length } else { 0 }
            $mode = if ($replyLen -ge 48) { [int]($respBytes[0] -band 0x07) } else { 0 }
            $remoteIpStr = if ($null -ne $remoteEp -and $null -ne $remoteEp.Address) { $remoteEp.Address.ToString() } else { $TargetHost }
            $validReply = ($replyLen -ge 48 -and ($mode -eq 4 -or $mode -eq 5))
            $errMsg = if ($validReply) { "" } else { "invalid NTP reply payload ($replyLen bytes, mode=$mode) within $ReceiveTimeoutMs ms" }
            return [PSCustomObject]@{
                ReplyReceived   = $validReply
                ReplyLength     = $replyLen
                ReplyLen        = $replyLen
                ServerMode      = $mode
                TargetIp        = $remoteIpStr
                RemoteAddress   = $remoteIpStr
                SocketErrorCode = "None"
                DelayMs         = [Math]::Round($sw.Elapsed.TotalMilliseconds, 2)
                ErrorMessage    = $errMsg
            }
        } catch [System.Net.Sockets.SocketException] {
            $sw.Stop()
            $sockCode = $_.Exception.SocketErrorCode.ToString()
            return [PSCustomObject]@{
                ReplyReceived   = $false
                ReplyLength     = 0
                ReplyLen        = 0
                ServerMode      = 0
                TargetIp        = $TargetHost
                RemoteAddress   = ""
                SocketErrorCode = $sockCode
                DelayMs         = [Math]::Round($sw.Elapsed.TotalMilliseconds, 2)
                ErrorMessage    = "no UDP reply within $ReceiveTimeoutMs ms (socketError=$sockCode)"
            }
        }
    } catch {
        $sw.Stop()
        return [PSCustomObject]@{
            ReplyReceived   = $false
            ReplyLength     = 0
            ReplyLen        = 0
            ServerMode      = 0
            TargetIp        = $TargetHost
            RemoteAddress   = ""
            SocketErrorCode = "SendError"
            DelayMs         = [Math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            ErrorMessage    = "no UDP reply within $ReceiveTimeoutMs ms ($($_.Exception.Message))"
        }
    } finally {
        $udp.Close()
    }
}

function Get-RoutedUdpLogLines {
    param(
        [Parameter(Mandatory = $false)]
        [object[]]$CtlLogItems = @()
    )
    $lines = New-Object System.Collections.Generic.List[string]
    if ($null -eq $CtlLogItems) {
        return $lines.ToArray()
    }
    foreach ($item in $CtlLogItems) {
        if ($null -eq $item) {
            continue
        }
        $msg = [string]$item.message
        if ($msg.Contains("Routed UDP") -or $msg.Contains("Kill-Switch blocked") -or $msg.Contains("Fake-IP egress guard")) {
            $lines.Add("[$($item.level)][$($item.component)] $msg")
        }
    }
    return $lines.ToArray()
}

function Get-FastRejectionNote {
    param(
        [Parameter(Mandatory = $true)]
        $Probe
    )
    # Fast means the ICMP rejection reached the client within $UdpFastRejectMaxMs. A blocked but not fast
    # probe stays a PASS until the VM confirms the injected ICMP is not dropped by the host firewall.
    $isFast = ($Probe.FastRejection -eq $true) -and ([double]$Probe.DelayMs -lt $UdpFastRejectMaxMs)
    if ($isFast) {
        return "fastRejection=True (under $UdpFastRejectMaxMs ms)"
    }
    return "fastRejection=False (NOT fast: no ICMP rejection under $UdpFastRejectMaxMs ms, check that the firewall does not drop the injected ICMP)"
}

function Invoke-QuicUdp443Probe {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetIp,

        [Parameter(Mandatory = $false)]
        [int]$Port = 443,

        [Parameter(Mandatory = $false)]
        [int]$ReceiveTimeoutMs = 1500,

        [Parameter(Mandatory = $false)]
        [string]$LocalIp = ""
    )
    $parsedIp = [System.Net.IPAddress]::Loopback
    $isV6 = [System.Net.IPAddress]::TryParse($TargetIp, [ref]$parsedIp) -and ($parsedIp.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6)
    $udp = if (-not [string]::IsNullOrWhiteSpace($LocalIp)) {
        $localEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($LocalIp), 0)
        New-Object System.Net.Sockets.UdpClient($localEp)
    } elseif ($isV6) {
        New-Object System.Net.Sockets.UdpClient([System.Net.Sockets.AddressFamily]::InterNetworkV6)
    } else {
        New-Object System.Net.Sockets.UdpClient
    }
    try {
        $udp.Client.ReceiveTimeout = $ReceiveTimeoutMs
        try {
            # Arm Winsock SIO_UDP_CONNRESET (-1744830452) so inbound ICMP Port Unreachable surfaces WSAECONNRESET
            $null = $udp.Client.IOControl(-1744830452, [byte[]]@(1, 0, 0, 0), $null)
        } catch {
            # Ignore if IOControl is unsupported on the socket
        }
        $udp.Connect($TargetIp, $Port)
        $payload = [System.Text.Encoding]::ASCII.GetBytes("QUIC_INITIAL_PROBE_42A")
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $null = $udp.Send($payload, $payload.Length)
        $anyAddr = if ($isV6) { [System.Net.IPAddress]::IPv6Any } else { [System.Net.IPAddress]::Any }
        $remoteEp = New-Object System.Net.IPEndPoint($anyAddr, 0)
        try {
            $null = $udp.Receive([ref]$remoteEp)
            $sw.Stop()
            return [PSCustomObject]@{
                UnexpectedReplyReceived = $true
                FastRejection           = $false
                ClientErrorReceived     = $false
                SocketErrorCode         = "None"
                DelayMs                 = [Math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            }
        } catch [System.Net.Sockets.SocketException] {
            $sw.Stop()
            $sockErr = $_.Exception.SocketErrorCode.ToString()
            $isIcmpReject = ($sockErr -eq "ConnectionReset" -or $sockErr -eq "ConnectionRefused")
            return [PSCustomObject]@{
                UnexpectedReplyReceived = $false
                FastRejection           = $isIcmpReject
                ClientErrorReceived     = $isIcmpReject
                SocketErrorCode         = $sockErr
                DelayMs                 = [Math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            }
        }
    } finally {
        $udp.Close()
    }
}

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

# Polls a condition until it returns true or the timeout elapses. Returns $true/$false and never throws
# on timeout; exceptions raised by the condition count as "not yet". Condition variable names must not
# collide with this function's own locals (waitSw, waitOk, Condition, TimeoutMs, IntervalMs, Description).
function Wait-Until {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Condition,
        [int]$TimeoutMs = 5000,
        [int]$IntervalMs = 0,
        [string]$Description = "condition"
    )
    if ($IntervalMs -le 0) {
        $IntervalMs = $PollIntervalMs
    }
    if ($IntervalMs -lt 50) {
        $IntervalMs = 50
    }
    $waitSw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        $waitOk = $false
        try {
            $waitOk = [bool](& $Condition)
        } catch {
            $waitOk = $false
        }
        if ($waitOk) {
            return $true
        }
        if ($waitSw.ElapsedMilliseconds -ge $TimeoutMs) {
            break
        }
        Start-Sleep -Milliseconds $IntervalMs
    }
    Write-Host "[WARN] Timed out after ${TimeoutMs}ms waiting for: $Description" -ForegroundColor Yellow
    return $false
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
        [int]$TimeoutSec,

        # When greater than zero, adds --connect-timeout so a missing refusal shows as a timeout (exit 28).
        [int]$ConnectTimeoutSec = 0
    )
    # Note: Never pass an empty string "" to --noproxy in Windows PowerShell 5.1,
    # as PowerShell 5.1 strips "" when invoking native binaries, causing --noproxy to consume -s.
    $curlCliArgs = @(
        "-s",
        "-o",
        "NUL",
        "-w",
        "%{http_code}",
        "--noproxy",
        "*",
        "--max-time",
        "$TimeoutSec"
    )
    if ($ConnectTimeoutSec -gt 0) {
        $curlCliArgs += @("--connect-timeout", "$ConnectTimeoutSec")
    }
    $curlCliArgs += $Url
    return $curlCliArgs
}

function Invoke-UnproxiedCurl {
    param(
        [string]$CurlBin,
        [string]$Url,
        [int]$TimeoutSec,
        [int]$ConnectTimeoutSec = 0
    )
    $proxyVars = @("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy")
    $savedVars = @{}
    foreach ($v in $proxyVars) {
        $savedVars[$v] = [Environment]::GetEnvironmentVariable($v, "Process")
        [Environment]::SetEnvironmentVariable($v, $null, "Process")
    }
    $curlArgs = Build-CurlArguments -Url $Url -TimeoutSec $TimeoutSec -ConnectTimeoutSec $ConnectTimeoutSec
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $curlStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        # Capture standard output only; discard standard error so progress/diagnostics never mix with %{http_code}
        $stdoutLines = & $CurlBin @curlArgs 2>$null
        $code = $LASTEXITCODE
        $curlStopwatch.Stop()
    } finally {
        $ErrorActionPreference = $prevEap
        foreach ($v in $proxyVars) {
            [Environment]::SetEnvironmentVariable($v, $savedVars[$v], "Process")
        }
    }
    $httpCodeOnly = (($stdoutLines | ForEach-Object { $_.ToString() }) -join "").Trim()
    return [PSCustomObject]@{
        ExitCode  = $code
        HttpCode  = $httpCodeOnly
        ElapsedMs = [int][Math]::Round($curlStopwatch.Elapsed.TotalMilliseconds)
    }
}

function New-RegressionProxyObject {
    return [ordered]@{
        id            = $ProvisionedProxyId
        name          = $ProvisionedProxyName
        protocol      = "socks5"
        host          = $Socks5Host
        port          = $Socks5Port
        auth          = $null
        udpEnabled    = $true
        tls           = $false
        sni           = $null
        enabled       = $true
        lastLatencyMs = $null
        exitIp        = $null
    }
}

function New-RegressionRuleObject {
    return [ordered]@{
        id              = $ProvisionedRuleId
        name            = $ExpectedProxyRuleName
        enabled         = $true
        priority        = $ProvisionedRulePriority
        processPatterns = @("curl.exe", "curl")
        domainPatterns  = @()
        ipCidrs         = @()
        portRanges      = @()
        protocol        = "tcp"
        action          = [ordered]@{
            type     = "proxy"
            targetId = $ProvisionedProxyId
        }
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

function Get-NslookupAnswerAddresses {
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$OutputText = ""
    )
    # The answer section starts at the "Name:" line; the resolver banner before it also carries an
    # address (the server asked) and must not be mistaken for an answer.
    $nameMatch = [regex]::Match($OutputText, '(?m)^\s*Name:')
    if (-not $nameMatch.Success) {
        return @()
    }
    $answerText = $OutputText.Substring($nameMatch.Index)
    $found = New-Object System.Collections.Generic.List[string]
    foreach ($m in [regex]::Matches($answerText, '\b(?:\d{1,3}\.){3}\d{1,3}\b')) {
        $found.Add($m.Value)
    }
    return @($found)
}

function Get-MachineConfiguredIpv4DnsServer {
    $candidates = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        ForEach-Object { $_.ServerAddresses } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $_ -notlike "127.*" -and $_ -notlike "169.254.*" })
    if ($candidates.Count -gt 0) {
        return [string]$candidates[0]
    }
    return ""
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
    $sampleConnectArgs = Build-CurlArguments -Url $TestUrl -TimeoutSec $CurlTimeoutSec -ConnectTimeoutSec 10
    if (($sampleConnectArgs -join ' ') -notmatch '--connect-timeout 10 ') {
        throw "DryRun failed: --connect-timeout missing from curl arguments: $($sampleConnectArgs -join ' ')"
    }
    $fastNote = Get-FastRejectionNote -Probe ([PSCustomObject]@{ FastRejection = $true; DelayMs = 12 })
    $slowNote = Get-FastRejectionNote -Probe ([PSCustomObject]@{ FastRejection = $true; DelayMs = $UdpFastRejectMaxMs + 1 })
    if ($fastNote -notmatch 'fastRejection=True' -or $slowNote -notmatch 'fastRejection=False') {
        throw "DryRun failed: unexpected fast rejection notes '$fastNote' / '$slowNote'"
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

    $dryRunFixtureProxy = (New-RegressionProxyObject | ConvertTo-Json -Depth 5 -Compress) | ConvertFrom-Json
    $dryRunFixtureRule = (New-RegressionRuleObject | ConvertTo-Json -Depth 6 -Compress) | ConvertFrom-Json
    if ($dryRunFixtureProxy.protocol -ne "socks5" -or $dryRunFixtureProxy.host -ne $Socks5Host -or [int]$dryRunFixtureProxy.port -ne $Socks5Port) {
        throw "DryRun failed: regression proxy fixture does not target $($Socks5Host):$($Socks5Port)."
    }
    if ($dryRunFixtureRule.name -ne $ExpectedProxyRuleName -or $dryRunFixtureRule.action.type -ne "proxy" -or $dryRunFixtureRule.action.targetId -ne $dryRunFixtureProxy.id) {
        throw "DryRun failed: regression rule fixture does not reference the regression proxy."
    }
    Write-Host "[DRYRUN-PASS] Built regression SOCKS5 proxy and curl.exe rule fixtures (no dependency on default profile proxies)." -ForegroundColor Green

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
    $dryRunFlushMethod = Get-StartupDnsFlushMethodFromLogs -CtlLogItems $logsDnsFlushDryRun
    if ($logsDnsFlushDryRun.Count -ne 1 -or $logsDnsFlushDryRun[0].component -ne "FakeIpDNS" -or [string]::IsNullOrWhiteSpace($dryRunFlushMethod)) {
        throw "DryRun failed: unexpected logsDnsCacheFlushed payload or empty flush method."
    }
    $frSampleLog = @([PSCustomObject]@{
        level     = "INFO"
        component = "FakeIpDNS"
        message   = "Cache DNS de l'OS vide (startup via dnsapi.dll!DnsFlushResolverCache)"
    })
    $frExtractedMethod = Get-StartupDnsFlushMethodFromLogs -CtlLogItems $frSampleLog
    if ($frExtractedMethod -ne "dnsapi.dll!DnsFlushResolverCache") {
        throw "DryRun failed: expected invariant English method from localized log, got '$frExtractedMethod'."
    }
    if ($script:ScenarioExecutionPlan.Count -ne 26) {
        throw "DryRun failed: expected 26 scenarios in ScenarioExecutionPlan, got $($script:ScenarioExecutionPlan.Count)."
    }
    $lastScenario = $script:ScenarioExecutionPlan[$script:ScenarioExecutionPlan.Count - 1]
    if ($lastScenario.Id -ne "j" -or $lastScenario.ExecutionOrder -ne 26 -or (-not $lastScenario.StopsSocks5)) {
        throw "DryRun failed: Scenario (j) must execute last (ExecutionOrder=26, StopsSocks5=true)."
    }
    $nslookupSample = "Server:  dns.example.test`r`nAddress:  192.0.2.53`r`n`r`nNon-authoritative answer:`r`nName:    example.com`r`nAddresses:  2606:2800:220:1:248:1893:25c8:1946`r`n          93.184.216.34`r`n"
    $nslookupAnswers = @(Get-NslookupAnswerAddresses -OutputText $nslookupSample)
    if ($nslookupAnswers.Count -ne 1 -or $nslookupAnswers[0] -ne "93.184.216.34") {
        throw "DryRun failed: Get-NslookupAnswerAddresses must ignore the server banner and keep only answer IPv4 addresses, got '$($nslookupAnswers -join ',')'."
    }
    if (@(Get-NslookupAnswerAddresses -OutputText "Server:  dns.example.test`r`nAddress:  192.0.2.53`r`n*** dns.example.test can't find nx.invalid: Non-existent domain").Count -ne 0) {
        throw "DryRun failed: Get-NslookupAnswerAddresses must return nothing when nslookup reports no answer."
    }
    foreach ($planItem in $script:ScenarioExecutionPlan) {
        if ($planItem.RequiresSocks5 -and $planItem.Id -ne "j" -and $planItem.ExecutionOrder -ge $lastScenario.ExecutionOrder) {
            throw "DryRun failed: Scenario ($($planItem.Id)) requires SOCKS5 and must run before Scenario (j)."
        }
    }
    $llmnrTestPkt = New-DnsWireQueryPacket -QueryName "public-leak.routeward.test" -TransactionId 0x5355
    if ($llmnrTestPkt.Length -le 20 -or $llmnrTestPkt[0] -ne 0x53 -or $llmnrTestPkt[1] -ne 0x55) {
        throw "DryRun failed: New-DnsWireQueryPacket produced unexpected wire bytes."
    }
    $aaaaTestPkt = New-DnsWireQueryPacket -QueryName "example.com" -TransactionId 0x5356 -QType 28
    if ($aaaaTestPkt.Length -le 20 -or $aaaaTestPkt[$aaaaTestPkt.Length - 4] -ne 0x00 -or $aaaaTestPkt[$aaaaTestPkt.Length - 3] -ne 0x1C) {
        throw "DryRun failed: New-DnsWireQueryPacket QType=28 did not encode AAAA QTYPE."
    }
    $ntpTestPkt = New-NtpClientRequestPacket
    if ($ntpTestPkt.Length -ne 48 -or $ntpTestPkt[0] -ne 0x23) {
        throw "DryRun failed: New-NtpClientRequestPacket produced unexpected wire bytes."
    }
    $dryRunUdpTimeout = Invoke-UdpNtpExchange -TargetHost "127.0.0.1" -Port 1 -ReceiveTimeoutMs 100
    if ($dryRunUdpTimeout.ReplyReceived -ne $false -or $dryRunUdpTimeout.ReplyLength -ne 0 -or $dryRunUdpTimeout.TargetIp -ne "127.0.0.1" -or $dryRunUdpTimeout.ErrorMessage -notmatch '^no UDP reply within 100 ms') {
        throw "DryRun failed: Invoke-UdpNtpExchange timeout returned unexpected fields: $($dryRunUdpTimeout | ConvertTo-Json -Compress)"
    }
    $sampleUdpLogs = @(
        [PSCustomObject]@{
            level     = "INFO"
            component = "TransparentRelay"
            message   = 'Routed UDP PID=4016 process="powershell.exe" exe="powershell.exe" -> 198.18.0.2:123 (domain=Some("time.cloudflare.com"), realIp=162.159.200.1) via DIRECT [rule="Default Profile Policy"]'
        }
    )
    $extractedUdpLogLines = @(Get-RoutedUdpLogLines -CtlLogItems $sampleUdpLogs)
    if ($extractedUdpLogLines.Count -ne 1 -or -not ($extractedUdpLogLines[0] -is [string]) -or $extractedUdpLogLines[0] -notmatch 'realIp=162\.159\.200\.1') {
        throw "DryRun failed: Get-RoutedUdpLogLines did not extract expected Routed UDP line."
    }
    if (@(Get-RoutedUdpLogLines -CtlLogItems @()).Count -ne 0) {
        throw "DryRun failed: Get-RoutedUdpLogLines should return empty collection for empty input."
    }
    $connsQuicLlmnrDryRun = ConvertFrom-CtlResponseJson `
        -RawJson ($fixtures.connectionsQuicAndLlmnrBlocked | ConvertTo-Json -Depth 6) `
        -Context "DryRun-connectionsQuicAndLlmnrBlocked" `
        -ExpectResultArray `
        -RequiredArrayElementProperties @("processName", "targetPort", "protocol", "matchedRule", "status")
    $logsQuicLlmnrDryRun = ConvertFrom-CtlResponseJson `
        -RawJson ($fixtures.logsQuicAndLlmnrBlocked | ConvertTo-Json -Depth 6) `
        -Context "DryRun-logsQuicAndLlmnrBlocked" `
        -ExpectResultArray `
        -RequiredArrayElementProperties @("level", "component", "message")
    if ($connsQuicLlmnrDryRun.Count -ne 2 -or $logsQuicLlmnrDryRun.Count -ne 2) {
        throw "DryRun failed: unexpected connectionsQuicAndLlmnrBlocked or logsQuicLlmnrBlocked count."
    }
    $upsertProxyAck = ConvertFrom-CtlResponseJson `
        -RawJson ($fixtures.upsertProxyOk | ConvertTo-Json -Depth 6) `
        -Context "DryRun-upsertProxyOk" `
        -RequiredResultProperties @("ok")
    $removeProxyAck = ConvertFrom-CtlResponseJson `
        -RawJson ($fixtures.removeProxyOk | ConvertTo-Json -Depth 6) `
        -Context "DryRun-removeProxyOk" `
        -RequiredResultProperties @("ok")
    if ($upsertProxyAck.ok -ne $true -or $removeProxyAck.ok -ne $true) {
        throw "DryRun failed: unexpected upsert/remove proxy response."
    }
    $connsUdpNtpProxiedDryRun = ConvertFrom-CtlResponseJson `
        -RawJson ($fixtures.connectionsUdpNtpProxied | ConvertTo-Json -Depth 6) `
        -Context "DryRun-connectionsUdpNtpProxied" `
        -ExpectResultArray `
        -RequiredArrayElementProperties @("processName", "targetPort", "protocol", "matchedRule", "routeLabel", "status")
    $connsUdpRefusedDryRun = ConvertFrom-CtlResponseJson `
        -RawJson ($fixtures.connectionsUdpRefusedBlocked | ConvertTo-Json -Depth 6) `
        -Context "DryRun-connectionsUdpRefusedBlocked" `
        -ExpectResultArray `
        -RequiredArrayElementProperties @("processName", "targetPort", "protocol", "matchedRule", "routeLabel", "status")
    $connsUdpDirectDryRun = ConvertFrom-CtlResponseJson `
        -RawJson ($fixtures.connectionsUdpDirectAttributed | ConvertTo-Json -Depth 6) `
        -Context "DryRun-connectionsUdpDirectAttributed" `
        -ExpectResultArray `
        -RequiredArrayElementProperties @("processName", "targetPort", "protocol", "matchedRule", "routeLabel", "status")
    if ($connsUdpNtpProxiedDryRun.Count -ne 1 -or $connsUdpRefusedDryRun.Count -ne 1 -or $connsUdpDirectDryRun.Count -ne 1) {
        throw "DryRun failed: unexpected 4.2.b UDP fixture counts."
    }
    $orderChain = ($script:ScenarioExecutionPlan | ForEach-Object { "{0:D2}:({1})" -f $_.ExecutionOrder, $_.Id }) -join " -> "
    Write-Host "[DRYRUN-PASS] Verified Fake-IP CIDR pool helper, 'ctl fake-ips', QUIC/LLMNR/UDP-4.2.b fixtures, English-only OS DNS cache flush parser, and explicit execution order ($orderChain)." -ForegroundColor Green

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

$udpTestServerExePath = $null
$udpTestCandidates = @(
    (Join-Path $resolvedBinDir $UdpTestServerExeName),
    (Join-Path (Join-Path $resolvedBinDir "examples") $UdpTestServerExeName),
    (Join-Path $PSScriptRoot $UdpTestServerExeName)
)
if (-not [string]::IsNullOrWhiteSpace($repoRootCandidate)) {
    $udpTestCandidates += (Join-Path $repoRootCandidate "target\release\examples\$UdpTestServerExeName")
}
foreach ($udpCand in $udpTestCandidates) {
    if (Test-Path -LiteralPath $udpCand) {
        $udpTestServerExePath = $udpCand
        break
    }
}
if ([string]::IsNullOrWhiteSpace($udpTestServerExePath)) {
    Write-Host "[ABORT] Pre-flight check failed: Missing SOCKS5 UDP test server binary '$UdpTestServerExeName' in '$resolvedBinDir' or '$resolvedBinDir\examples'." -ForegroundColor Red
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

$script:RawCtlCapture = New-Object System.Collections.Generic.List[string]
$script:StartedDaemonPids = New-Object System.Collections.Generic.HashSet[int]
$script:StartedUdpTestServerPids = New-Object System.Collections.Generic.HashSet[int]
$script:CurrentDaemonProc = $null
$script:PrimarySocks5Pid = 0
$script:AutoStartedPrimarySocks5 = $false

$existingSocksListener = Get-LocalPortListenerProcessInfo -Port $Socks5Port
if ($null -ne $existingSocksListener -and $existingSocksListener.Pid -gt 0) {
    $script:PrimarySocks5Pid = [int]$existingSocksListener.Pid
} elseif ($Socks5Host -in @("127.0.0.1", "localhost", "::1") -and (-not [string]::IsNullOrWhiteSpace($udpTestServerExePath))) {
    Write-Host "[INFO] Pre-flight check: No upstream SOCKS5 listener on ${Socks5Host}:${Socks5Port}; auto-starting local socks5_udp_test_server.exe." -ForegroundColor Cyan
    $autoProc = Start-Process -FilePath $udpTestServerExePath -ArgumentList @("--bind", "127.0.0.1:$Socks5Port") -WindowStyle Hidden -PassThru
    $autoReadySw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($autoReadySw.ElapsedMilliseconds -lt 3000) {
        if (Test-TcpEndpoint -TargetHost $Socks5Host -Port $Socks5Port -TimeoutMs 250) {
            break
        }
        Start-Sleep -Milliseconds 100
    }
    if ($null -ne $autoProc -and (-not $autoProc.HasExited) -and (Test-TcpEndpoint -TargetHost $Socks5Host -Port $Socks5Port -TimeoutMs 250)) {
        $script:PrimarySocks5Pid = [int]$autoProc.Id
        $script:AutoStartedPrimarySocks5 = $true
        $null = $script:StartedUdpTestServerPids.Add($script:PrimarySocks5Pid)
    } elseif ($null -ne $autoProc -and (-not $autoProc.HasExited)) {
        Stop-Process -Id $autoProc.Id -Force -ErrorAction SilentlyContinue
    }
}

if (-not (Test-TcpEndpoint -TargetHost $Socks5Host -Port $Socks5Port -TimeoutMs $TcpConnectTimeoutMs)) {
    Write-Host "[WARN] Pre-flight check: Upstream SOCKS5 proxy at ${Socks5Host}:${Socks5Port} is not reachable. Scenarios requiring SOCKS5 will be marked SKIP (upstream SOCKS5 unreachable)." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Process & CTL Management (Bugs 3 & 4 fix: track all daemon PIDs and isolate scenarios)
# ---------------------------------------------------------------------------

function Start-TrackedUdpTestServer {
    param(
        [string]$ExePath,
        [int]$Port,
        [string]$StatsFilePath,
        [switch]$DisableUdpAssociate,
        [string[]]$ExtraArgs = @()
    )
    if (Test-Path -LiteralPath $StatsFilePath) {
        Remove-Item -LiteralPath $StatsFilePath -Force -ErrorAction SilentlyContinue
    }
    $argsList = @("--bind", "127.0.0.1:$Port", "--stats-file", $StatsFilePath)
    if ($DisableUdpAssociate.IsPresent) {
        $argsList += "--disable-udp-associate"
    }
    if ($null -ne $ExtraArgs -and $ExtraArgs.Count -gt 0) {
        $argsList += $ExtraArgs
    }
    $proc = Start-Process -FilePath $ExePath -ArgumentList $argsList -WindowStyle Hidden -PassThru
    $null = $script:StartedUdpTestServerPids.Add([int]$proc.Id)
    $readySw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($readySw.ElapsedMilliseconds -lt 3000) {
        if (Test-TcpEndpoint -TargetHost "127.0.0.1" -Port $Port -TimeoutMs 250) {
            return $proc
        }
        Start-Sleep -Milliseconds 100
    }
    throw "Timed out waiting for socks5_udp_test_server on 127.0.0.1:$Port"
}

function Stop-AllTrackedUdpTestServers {
    param(
        [switch]$IncludePrimarySocks5
    )
    foreach ($udpPid in @($script:StartedUdpTestServerPids)) {
        if ((-not $IncludePrimarySocks5.IsPresent) -and $script:PrimarySocks5Pid -gt 0 -and $udpPid -eq $script:PrimarySocks5Pid) {
            continue
        }
        $up = Get-Process -Id $udpPid -ErrorAction SilentlyContinue
        if ($null -ne $up) {
            Stop-Process -Id $udpPid -Force -ErrorAction SilentlyContinue
            Wait-Process -Id $udpPid -Timeout 5 -ErrorAction SilentlyContinue
        }
    }
    $strayUdpServers = @(Get-Process -Name "socks5_udp_test_server" -ErrorAction SilentlyContinue)
    foreach ($su in $strayUdpServers) {
        if ((-not $IncludePrimarySocks5.IsPresent) -and $script:PrimarySocks5Pid -gt 0 -and [int]$su.Id -eq $script:PrimarySocks5Pid) {
            continue
        }
        if ((-not $IncludePrimarySocks5.IsPresent) -and (-not $script:AutoStartedPrimarySocks5)) {
            $portOwner = Get-LocalPortListenerProcessInfo -Port $Socks5Port
            if ($null -ne $portOwner -and [int]$portOwner.Pid -eq [int]$su.Id) {
                continue
            }
        }
        Stop-Process -Id $su.Id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $su.Id -Timeout 5 -ErrorAction SilentlyContinue
    }
    if ($IncludePrimarySocks5.IsPresent -and $script:AutoStartedPrimarySocks5) {
        $portOwnerAfter = Get-LocalPortListenerProcessInfo -Port $Socks5Port
        if ($null -ne $portOwnerAfter -and $portOwnerAfter.Pid -gt 0) {
            $ownerProc = Get-Process -Id $portOwnerAfter.Pid -ErrorAction SilentlyContinue
            if ($null -ne $ownerProc -and $ownerProc.ProcessName -ieq "socks5_udp_test_server") {
                Stop-Process -Id $ownerProc.Id -Force -ErrorAction SilentlyContinue
                Wait-Process -Id $ownerProc.Id -Timeout 5 -ErrorAction SilentlyContinue
            }
        }
    }
}

function Initialize-TransientWinDivertIpv6Route {
    param(
        [string]$LocalUlaIp = "fd00:7277:2026::10",
        [int]$PrefixLength = 64,
        [string]$NextHopIp = "fd00:7277:2026::1",
        [string]$TargetRemoteIp = "2001:db8:7277::10",
        [string]$NeighborMac = "02-00-5e-72-77-01"
    )
    $iface = Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object { $_.ConnectionState -eq "Connected" -and $_.InterfaceAlias -notmatch "Loopback" } |
        Sort-Object InterfaceMetric |
        Select-Object -First 1
    if ($null -eq $iface) {
        return $null
    }
    $ifIdx = [int]$iface.InterfaceIndex
    $ctx = [PSCustomObject]@{
        InterfaceIndex = $ifIdx
        InterfaceAlias = [string]$iface.InterfaceAlias
        LocalUlaIp     = $LocalUlaIp
        PrefixLength   = $PrefixLength
        NextHopIp      = $NextHopIp
        TargetPrefix   = "$TargetRemoteIp/128"
        AddedIp        = $false
        AddedRoute     = $false
        AddedNeighbor  = $false
    }
    try {
        $existingIp = Get-NetIPAddress -InterfaceIndex $ifIdx -IPAddress $LocalUlaIp -AddressFamily IPv6 -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -eq $existingIp) {
            $null = New-NetIPAddress -InterfaceIndex $ifIdx -IPAddress $LocalUlaIp -PrefixLength $PrefixLength -AddressFamily IPv6 -SkipAsSource $false -PolicyStore ActiveStore -ErrorAction Stop
            $ctx.AddedIp = $true
        }
        $existingNeighbor = Get-NetNeighbor -InterfaceIndex $ifIdx -IPAddress $NextHopIp -AddressFamily IPv6 -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -eq $existingNeighbor -or ([string]$existingNeighbor.State -ne "Permanent") -or ([string]$existingNeighbor.LinkLayerAddress -ine $NeighborMac)) {
            if ($null -ne $existingNeighbor -and ([string]$existingNeighbor.State -eq "Permanent")) {
                Remove-NetNeighbor -InterfaceIndex $ifIdx -IPAddress $NextHopIp -AddressFamily IPv6 -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue
            }
            $null = New-NetNeighbor -InterfaceIndex $ifIdx -IPAddress $NextHopIp -LinkLayerAddress $NeighborMac -PolicyStore ActiveStore -State Permanent -ErrorAction Stop
            $ctx.AddedNeighbor = $true
        }
        $existingRoute = Get-NetRoute -InterfaceIndex $ifIdx -DestinationPrefix $ctx.TargetPrefix -NextHop $NextHopIp -AddressFamily IPv6 -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -eq $existingRoute) {
            $null = New-NetRoute -DestinationPrefix $ctx.TargetPrefix -InterfaceIndex $ifIdx -NextHop $NextHopIp -PolicyStore ActiveStore -ErrorAction Stop
            $ctx.AddedRoute = $true
        }
        $dadSw = [System.Diagnostics.Stopwatch]::StartNew()
        $addrState = ""
        while ($dadSw.ElapsedMilliseconds -lt 6000) {
            $addrState = [string](Get-NetIPAddress -InterfaceIndex $ifIdx -IPAddress $LocalUlaIp -AddressFamily IPv6 -ErrorAction SilentlyContinue | Select-Object -First 1).AddressState
            if ($addrState -eq "Preferred") {
                break
            }
            Start-Sleep -Milliseconds 100
        }
        if ($addrState -ne "Preferred") {
            throw "Transient IPv6 ULA '$LocalUlaIp' did not reach Preferred state (current='$addrState')"
        }
        return $ctx
    } catch {
        Remove-TransientWinDivertIpv6Route -Context $ctx
        throw
    }
}

function Remove-TransientWinDivertIpv6Route {
    param(
        [object]$Context
    )
    if ($null -eq $Context) {
        return
    }
    if ($Context.AddedRoute) {
        Remove-NetRoute -InterfaceIndex $Context.InterfaceIndex -DestinationPrefix $Context.TargetPrefix -NextHop $Context.NextHopIp -AddressFamily IPv6 -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ($Context.AddedNeighbor) {
        Remove-NetNeighbor -InterfaceIndex $Context.InterfaceIndex -IPAddress $Context.NextHopIp -AddressFamily IPv6 -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ($Context.AddedIp) {
        Remove-NetIPAddress -InterfaceIndex $Context.InterfaceIndex -IPAddress $Context.LocalUlaIp -AddressFamily IPv6 -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Start-LocalIpv6HttpTestListener {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port
    )
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::IPv6Loopback, $Port)
    $listener.Start()
    $ps = [powershell]::Create()
    $null = $ps.AddScript({
        param($TcpListener)
        try {
            $deadline = [DateTime]::UtcNow.AddSeconds(15)
            while ([DateTime]::UtcNow -lt $deadline) {
                if ($TcpListener.Pending()) {
                    $client = $TcpListener.AcceptTcpClient()
                    try {
                        $client.ReceiveTimeout = 2000
                        $stream = $client.GetStream()
                        $buf = New-Object byte[] 4096
                        try { $null = $stream.Read($buf, 0, $buf.Length) } catch {}
                        $body = "IPV6_OK_200"
                        $resp = "HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n$body"
                        $respBytes = [System.Text.Encoding]::ASCII.GetBytes($resp)
                        $stream.Write($respBytes, 0, $respBytes.Length)
                        $stream.Flush()
                    } finally {
                        $client.Close()
                    }
                    break
                }
                Start-Sleep -Milliseconds 25
            }
        } catch {
            # Ignore listener shutdown
        }
    }).AddArgument($listener)
    $asyncResult = $ps.BeginInvoke()
    return [PSCustomObject]@{
        Listener    = $listener
        PowerShell  = $ps
        AsyncResult = $asyncResult
    }
}

function Stop-LocalIpv6HttpTestListener {
    param([object]$Handle)
    if ($null -eq $Handle) {
        return
    }
    try { $Handle.Listener.Stop() } catch {}
    try { $Handle.PowerShell.Stop() } catch {}
    try { $Handle.PowerShell.Dispose() } catch {}
}

function Invoke-Ipv6UdpNtpExchange {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetIp,

        [Parameter(Mandatory = $true)]
        [int]$Port,

        [Parameter(Mandatory = $false)]
        [int]$ReceiveTimeoutMs = 4000,

        [Parameter(Mandatory = $false)]
        [string]$LocalIp = ""
    )
    $udp = if (-not [string]::IsNullOrWhiteSpace($LocalIp)) {
        $localEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($LocalIp), 0)
        New-Object System.Net.Sockets.UdpClient($localEp)
    } else {
        New-Object System.Net.Sockets.UdpClient([System.Net.Sockets.AddressFamily]::InterNetworkV6)
    }
    try {
        $udp.Client.ReceiveTimeout = $ReceiveTimeoutMs
        $ipObj = [System.Net.IPAddress]::Parse($TargetIp)
        $udp.Connect($ipObj, $Port)
        $reqBytes = New-NtpClientRequestPacket
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $null = $udp.Send($reqBytes, $reqBytes.Length)
        $remoteEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::IPv6Any, 0)
        try {
            $respBytes = $udp.Receive([ref]$remoteEp)
            $sw.Stop()
            return [PSCustomObject]@{
                ReplyReceived = ($null -ne $respBytes -and $respBytes.Length -ge 48)
                ReplyLength   = if ($null -ne $respBytes) { $respBytes.Length } else { 0 }
                RemoteIp      = $remoteEp.Address.ToString()
                DelayMs       = [Math]::Round($sw.Elapsed.TotalMilliseconds, 2)
                ErrorMessage  = ""
            }
        } catch {
            $sw.Stop()
            return [PSCustomObject]@{
                ReplyReceived = $false
                ReplyLength   = 0
                RemoteIp      = ""
                DelayMs       = [Math]::Round($sw.Elapsed.TotalMilliseconds, 2)
                ErrorMessage  = $_.Exception.Message
            }
        }
    } finally {
        $udp.Close()
    }
}

function Invoke-Ipv6DnsWireQuery {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetIp,

        [Parameter(Mandatory = $true)]
        [string]$QueryName,

        [Parameter(Mandatory = $false)]
        [int]$Port = 53,

        [Parameter(Mandatory = $false)]
        [ValidateSet("udp", "tcp")]
        [string]$Protocol = "udp",

        [Parameter(Mandatory = $false)]
        [uint16]$QType = 1,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutMs = 4000,

        [Parameter(Mandatory = $false)]
        [string]$LocalIp = ""
    )
    $txId = [uint16](Get-Random -Minimum 1000 -Maximum 65000)
    $queryPkt = New-DnsWireQueryPacket -QueryName $QueryName -TransactionId $txId -QType $QType
    $respBytes = $null
    $errMsg = ""
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        if ($Protocol -eq "udp") {
            $udp = if (-not [string]::IsNullOrWhiteSpace($LocalIp)) {
                $localEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($LocalIp), 0)
                New-Object System.Net.Sockets.UdpClient($localEp)
            } else {
                New-Object System.Net.Sockets.UdpClient([System.Net.Sockets.AddressFamily]::InterNetworkV6)
            }
            try {
                $udp.Client.ReceiveTimeout = $TimeoutMs
                $udp.Connect([System.Net.IPAddress]::Parse($TargetIp), $Port)
                $null = $udp.Send($queryPkt, $queryPkt.Length)
                $remoteEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::IPv6Any, 0)
                $respBytes = $udp.Receive([ref]$remoteEp)
            } finally {
                $udp.Close()
            }
        } else {
            $tcp = if (-not [string]::IsNullOrWhiteSpace($LocalIp)) {
                $localEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($LocalIp), 0)
                New-Object System.Net.Sockets.TcpClient($localEp)
            } else {
                New-Object System.Net.Sockets.TcpClient([System.Net.Sockets.AddressFamily]::InterNetworkV6)
            }
            try {
                $tcp.ReceiveTimeout = $TimeoutMs
                $tcp.SendTimeout = $TimeoutMs
                $connectTask = $tcp.ConnectAsync([System.Net.IPAddress]::Parse($TargetIp), $Port)
                if (-not $connectTask.Wait($TimeoutMs)) {
                    throw "TCP connect timed out after $TimeoutMs ms"
                }
                if ($connectTask.IsFaulted) {
                    throw $connectTask.Exception.InnerException
                }
                $stream = $tcp.GetStream()
                $stream.ReadTimeout = $TimeoutMs
                $stream.WriteTimeout = $TimeoutMs
                $lenPrefix = [byte[]]@([byte](($queryPkt.Length -shr 8) -band 0xFF), [byte]($queryPkt.Length -band 0xFF))
                $stream.Write($lenPrefix, 0, 2)
                $stream.Write($queryPkt, 0, $queryPkt.Length)
                $stream.Flush()

                $lenBuf = New-Object byte[] 2
                $got = 0
                while ($got -lt 2) {
                    $n = $stream.Read($lenBuf, $got, 2 - $got)
                    if ($n -le 0) {
                        throw "Unexpected EOF reading TCP DNS length prefix"
                    }
                    $got += $n
                }
                $msgLen = (([int]$lenBuf[0]) -shl 8) -bor [int]$lenBuf[1]
                $respBytes = New-Object byte[] $msgLen
                $got = 0
                while ($got -lt $msgLen) {
                    $n = $stream.Read($respBytes, $got, $msgLen - $got)
                    if ($n -le 0) {
                        throw "Unexpected EOF reading TCP DNS payload"
                    }
                    $got += $n
                }
            } finally {
                $tcp.Close()
            }
        }
    } catch {
        $errMsg = $_.Exception.Message
    } finally {
        $sw.Stop()
    }

    if ($null -eq $respBytes -or $respBytes.Length -lt 12) {
        return [PSCustomObject]@{
            ReplyReceived = $false
            RCode         = -1
            AnswerCount   = 0
            AnswerIps     = @()
            DelayMs       = [Math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            ErrorMessage  = $errMsg
        }
    }

    $rcode = [int]($respBytes[3] -band 0x0F)
    $qdCount = (([int]$respBytes[4]) -shl 8) -bor [int]$respBytes[5]
    $anCount = (([int]$respBytes[6]) -shl 8) -bor [int]$respBytes[7]
    $answerIps = New-Object System.Collections.Generic.List[string]

    try {
        $pos = 12
        for ($q = 0; $q -lt $qdCount -and $pos -lt $respBytes.Length; $q++) {
            while ($pos -lt $respBytes.Length) {
                $labelLen = [int]$respBytes[$pos]
                if ($labelLen -eq 0) {
                    $pos += 1
                    break
                }
                if (($labelLen -band 0xC0) -eq 0xC0) {
                    $pos += 2
                    break
                }
                $pos += (1 + $labelLen)
            }
            $pos += 4
        }
        for ($a = 0; $a -lt $anCount -and ($pos + 10) -le $respBytes.Length; $a++) {
            while ($pos -lt $respBytes.Length) {
                $labelLen = [int]$respBytes[$pos]
                if ($labelLen -eq 0) {
                    $pos += 1
                    break
                }
                if (($labelLen -band 0xC0) -eq 0xC0) {
                    $pos += 2
                    break
                }
                $pos += (1 + $labelLen)
            }
            if (($pos + 10) -gt $respBytes.Length) { break }
            $rrType = (([int]$respBytes[$pos]) -shl 8) -bor [int]$respBytes[$pos + 1]
            $rdLen = (([int]$respBytes[$pos + 8]) -shl 8) -bor [int]$respBytes[$pos + 9]
            $pos += 10
            if (($pos + $rdLen) -gt $respBytes.Length) { break }
            if ($rrType -eq 1 -and $rdLen -eq 4) {
                $answerIps.Add("$($respBytes[$pos]).$($respBytes[$pos + 1]).$($respBytes[$pos + 2]).$($respBytes[$pos + 3])")
            }
            $pos += $rdLen
        }
    } catch {
        # Best-effort RR walk
    }

    return [PSCustomObject]@{
        ReplyReceived = $true
        RCode         = $rcode
        AnswerCount   = $anCount
        AnswerIps     = @($answerIps)
        DelayMs       = [Math]::Round($sw.Elapsed.TotalMilliseconds, 2)
        ErrorMessage  = $errMsg
    }
}

function Get-NormalizedProfileSnapshotJson {
    param(
        [string]$ExePath,
        [string]$Label
    )
    $stateRes = Invoke-RouteWardCtl -ExePath $ExePath -CtlArgs @("state") -Label $Label
    $stateObj = ConvertFrom-CtlResponseJson `
        -RawJson $stateRes.RawText `
        -Context $Label `
        -RequiredResultProperties @("diagnostics", "profile")
    return ($stateObj.profile | ConvertTo-Json -Depth 10 -Compress)
}

function Invoke-RouteWardCtl {
    param(
        [string]$ExePath,
        [string[]]$CtlArgs,
        [string]$Label,
        [switch]$SkipCapture
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
    if (-not $SkipCapture.IsPresent) {
        $script:RawCtlCapture.Add("--- [$Label] routeward $($argList -join ' ') (exit=$exitCode) ---`r`n$sanitized")
    }
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
            $null = Wait-Until -TimeoutMs 5000 -Description "firewall rule absent after graceful stop" -Condition { -not (Test-FirewallRulePresent -RuleName $FirewallRuleName) }
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

# Polls "ctl connections" or "ctl logs" until one entry satisfies the Match predicate (param($c) -> bool).
# Polling reads are not added to the raw ctl capture. Returns $true/$false, never throws on timeout.
function Wait-ForCtlEntry {
    param(
        [string]$ExePath,
        [ValidateSet("connections", "logs")]
        [string]$CtlCommand,
        [scriptblock]$Match,
        [string]$Description,
        [int]$TimeoutMs = 5000
    )
    $entryLabel = "Wait-$CtlCommand"
    $entryMatch = $Match
    return (Wait-Until -TimeoutMs $TimeoutMs -Description $Description -Condition {
        $entryRes = Invoke-RouteWardCtl -ExePath $ExePath -CtlArgs @($CtlCommand) -Label $entryLabel -SkipCapture
        $entryItems = ConvertFrom-CtlResponseJson -RawJson $entryRes.RawText -Context $entryLabel -ExpectResultArray
        foreach ($entryItem in @($entryItems)) {
            if (& $entryMatch $entryItem) {
                return $true
            }
        }
        return $false
    })
}

# Returns the daemon log lines appended after the first SkipLines lines of the newest matching log file.
function Get-NewDaemonLogLines {
    param(
        [string]$LogsDir,
        [string]$Filter,
        [int]$SkipLines
    )
    $logFiles = @(Get-ChildItem -Path $LogsDir -Filter $Filter -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    if ($logFiles.Count -eq 0) {
        return @()
    }
    $logLines = @(Get-Content -LiteralPath $logFiles[0].FullName -Encoding UTF8)
    if ($logLines.Count -gt $SkipLines) {
        return @($logLines[$SkipLines..($logLines.Count - 1)])
    }
    return @($logLines)
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
$fixtureProxyAdded = $false
$fixtureRuleAdded = $false

$scenarioResults = New-Object System.Collections.Generic.List[PSCustomObject]
$auditNotes = New-Object System.Collections.Generic.List[string]
$postCleanupCurlStatus = "Not executed"

function Record-ScenarioResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [ValidateSet("PASS", "FAIL", "SKIP")]
        [string]$Status,

        [Parameter(Mandatory = $false)]
        [string]$Title = "",

        [Parameter(Mandatory = $true)]
        [string]$Detail
    )
    $planEntry = Get-ScenarioPlanEntry -Id $Id
    $effectiveTitle = if (-not [string]::IsNullOrWhiteSpace($Title)) { $Title } else { $planEntry.Title }
    $totalScenarios = $script:ScenarioExecutionPlan.Count
    $orderTag = ("{0:D2}/{1:D2}" -f $planEntry.ExecutionOrder, $totalScenarios)
    $line = "[$Status] [Order $orderTag] Scenario ($Id) $effectiveTitle - $Detail"
    switch ($Status) {
        "PASS" { Write-Host $line -ForegroundColor Green }
        "FAIL" { Write-Host $line -ForegroundColor Red }
        "SKIP" { Write-Host $line -ForegroundColor Yellow }
    }
    $scenarioResults.Add([PSCustomObject]@{
        ExecutionOrder = $planEntry.ExecutionOrder
        Id             = $Id
        Status         = $Status
        Title          = $effectiveTitle
        Detail         = $Detail
        Line           = $line
    })
}

function Test-ScenarioSocks5Prerequisite {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id
    )
    $planEntry = Get-ScenarioPlanEntry -Id $Id
    if (-not $planEntry.RequiresSocks5) {
        return $true
    }
    if (Test-TcpEndpoint -TargetHost $Socks5Host -Port $Socks5Port -TimeoutMs $TcpConnectTimeoutMs) {
        return $true
    }
    Record-ScenarioResult -Id $Id -Status "SKIP" -Title $planEntry.Title -Detail "upstream SOCKS5 unreachable"
    return $false
}

$executionOrderSummary = ($script:ScenarioExecutionPlan | ForEach-Object { "{0:D2}:({1})" -f $_.ExecutionOrder, $_.Id }) -join " -> "
Write-Host "Scenario Execution Order: $executionOrderSummary" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Main Scenario Execution (Protected by try/finally)
# ---------------------------------------------------------------------------
try {
    # -----------------------------------------------------------------------
    # Scenario (a): Start daemon in background; Named Pipe appears
    # -----------------------------------------------------------------------
    try {
        Stop-AllTrackedUdpTestServers
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
    # Fixture setup (not a scenario): the default profile ships no proxy node and no proxy
    # rule, so provision the SOCKS5 node (Socks5Host:Socks5Port parameters) and the curl.exe
    # proxy rule used by scenarios (d), (k), and (j). Removed again in the finally block;
    # the original profile bytes are restored as a second safety net.
    # -----------------------------------------------------------------------
    try {
        $fixtureProxyFile = Write-Utf8NoBomJsonTempFile -JsonText ((New-RegressionProxyObject) | ConvertTo-Json -Depth 5 -Compress)
        $fixtureRuleFile = Write-Utf8NoBomJsonTempFile -JsonText ((New-RegressionRuleObject) | ConvertTo-Json -Depth 6 -Compress)
        try {
            $fixtureProxyRes = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("upsert-proxy", "--json-file", $fixtureProxyFile) -Label "Fixture-upsert-proxy"
            $fixtureProxyObj = ConvertFrom-CtlResponseJson -RawJson $fixtureProxyRes.RawText -Context "Fixture-upsert-proxy" -RequiredResultProperties @("ok")
            if (-not $fixtureProxyObj.ok) {
                throw "Failed to upsert regression SOCKS5 proxy '$ProvisionedProxyId'"
            }
            $fixtureProxyAdded = $true
            $profileModifiedByScript = $true

            $fixtureRuleRes = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("upsert-rule", "--json-file", $fixtureRuleFile) -Label "Fixture-upsert-rule"
            $fixtureRuleObj = ConvertFrom-CtlResponseJson -RawJson $fixtureRuleRes.RawText -Context "Fixture-upsert-rule" -RequiredResultProperties @("ok")
            if (-not $fixtureRuleObj.ok) {
                throw "Failed to upsert regression proxy rule '$ProvisionedRuleId'"
            }
            $fixtureRuleAdded = $true
            $auditNotes.Add("Provisioned regression SOCKS5 proxy '$ProvisionedProxyId' ($($Socks5Host):$($Socks5Port)) and rule '$ExpectedProxyRuleName' ('$ProvisionedRuleId').")
        } finally {
            foreach ($fixtureTmp in @($fixtureProxyFile, $fixtureRuleFile)) {
                if (-not [string]::IsNullOrWhiteSpace($fixtureTmp) -and (Test-Path -LiteralPath $fixtureTmp)) {
                    Remove-Item -LiteralPath $fixtureTmp -Force -ErrorAction SilentlyContinue
                }
            }
        }
    } catch {
        $auditNotes.Add("WARNING: Fixture setup failed (scenarios needing the proxy rule will fail): $($_.Exception.Message)")
    }

    # -----------------------------------------------------------------------
    # Scenario (d) [Order 04/14]: ctl start then curl.exe (HTTP 200, ctl connections shows curl.exe, expected rule, rxBytes > 0)
    # -----------------------------------------------------------------------
    try {
        if (Test-ScenarioSocks5Prerequisite -Id "d") {
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
                $null = Wait-ForCtlEntry -ExePath $routeWardExePath -CtlCommand "connections" -Description "curl.exe connection routed by '$ExpectedProxyRuleName' with rxBytes > 0" -Match {
                    param($c)
                    $c.processName -ieq "curl.exe" -and $c.matchedRule -eq $ExpectedProxyRuleName -and ([int64]$c.rxBytes) -gt 0
                }
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
            $curlBlocked = Invoke-UnproxiedCurl -CurlBin $CurlExePath -Url $TestUrl -TimeoutSec 15 -ConnectTimeoutSec 10
            $null = Wait-ForCtlEntry -ExePath $routeWardExePath -CtlCommand "connections" -Description "blocked curl.exe connection" -Match {
                param($c)
                $c.processName -ieq "curl.exe" -and $c.status -eq "blocked"
            }
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

        # A refused connection (injected TCP RST) ends with curl exit 7 (or 56) well before the connect timeout.
        $blockedRefusedFast = (($curlBlocked.ExitCode -eq 7) -or ($curlBlocked.ExitCode -eq 56)) -and ($curlBlocked.ElapsedMs -lt $BlockFastRejectMaxMs)
        if ($blockedRefusedFast -and $sawBlockedConn -and $profileRestoredIdentical) {
            Record-ScenarioResult -Id "e" -Status "PASS" -Title "Temporary Block rule via ctl" -Detail "curl refused as expected (exit=$($curlBlocked.ExitCode), elapsed=$($curlBlocked.ElapsedMs) ms < $BlockFastRejectMaxMs ms), connection marked blocked, rule removed and profile verified identical"
        } else {
            Record-ScenarioResult -Id "e" -Status "FAIL" -Title "Temporary Block rule via ctl" -Detail "curlExit=$($curlBlocked.ExitCode) (expected 7 or 56), elapsedMs=$($curlBlocked.ElapsedMs) (expected < $BlockFastRejectMaxMs), sawBlocked=$sawBlockedConn, profileRestoredIdentical=$profileRestoredIdentical"
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
        $null = Wait-Until -TimeoutMs 5000 -Description "firewall rule '$FirewallRuleName' removed after ctl stop" -Condition { -not (Test-FirewallRulePresent -RuleName $FirewallRuleName) }
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
        $null = Wait-Until -TimeoutMs 5000 -Description "firewall rule '$FirewallRuleName' present after ctl start" -Condition { Test-FirewallRulePresent -RuleName $FirewallRuleName }
        $fwBeforeCrash = Test-FirewallRulePresent -RuleName $FirewallRuleName

        if (-not $fwBeforeCrash) {
            Record-ScenarioResult -Id "g" -Status "FAIL" -Title "Daemon crash fail-open & orphaned rule" -Detail "Firewall rule '$FirewallRuleName' was not present after ctl start"
        } else {
            $killedPid = $script:CurrentDaemonProc.Id
            Stop-AllTrackedUdpTestServers
    Stop-AllTrackedDaemons -ExePath $routeWardExePath -FullPipePath $PipeName -ForceKillOnly
            $null = Wait-Until -TimeoutMs 5000 -Description "killed daemon PID=$killedPid to exit" -Condition { $null -eq (Get-Process -Id $killedPid -ErrorAction SilentlyContinue) }

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
        Stop-AllTrackedUdpTestServers
    Stop-AllTrackedDaemons -ExePath $routeWardExePath -FullPipePath $PipeName -ForceKillOnly
        Ensure-SyntheticFirewallRulePresent -RuleName $FirewallRuleName -ProgramPath $routeWardExePath -Port $TransparentRelayPort

        $daemonLogBeforeLines = 0
        $existingDaemonLogs = @(Get-ChildItem -Path $daemonLogsDir -Filter $logWildcard -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
        if ($existingDaemonLogs.Count -gt 0) {
            $daemonLogBeforeLines = @(Get-Content -LiteralPath $existingDaemonLogs[0].FullName -Encoding UTF8).Count
        }

        $null = Start-TrackedDaemon -ExePath $routeWardExePath -WorkDir $resolvedBinDir
        $pipeReadyAfterCrash = Wait-ForNamedPipe -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs
        $null = Wait-Until -TimeoutMs ([Math]::Max(5000, 3 * $LogFlushWaitMs)) -Description "orphan cleanup line in daemon log" -Condition {
            $cleanupLines = @(Get-NewDaemonLogLines -LogsDir $daemonLogsDir -Filter $logWildcard -SkipLines $daemonLogBeforeLines)
            $cleanupHits = @($cleanupLines | Where-Object { $_.Contains($ExpectedCleanupLogText) -and $_.Contains($FirewallRuleName) })
            $cleanupHits.Count -gt 0
        }

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
        $null = Wait-Until -TimeoutMs ([Math]::Max(5000, 3 * $LogFlushWaitMs)) -Description "daemon and user logs written since script start" -Condition {
            $pollDaemonLogs = @(Get-ChildItem -Path $daemonLogsDir -Filter $logWildcard -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
            $pollUserLogs = @(Get-ChildItem -Path $userLogsDir -Filter $logWildcard -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
            ($pollDaemonLogs.Count -gt 0) -and ($pollDaemonLogs[0].LastWriteTime -ge $scriptStartTime.AddSeconds(-2)) -and ($pollUserLogs.Count -gt 0) -and ($pollUserLogs[0].LastWriteTime -ge $scriptStartTime.AddSeconds(-2))
        }

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
    # Scenario (k) [Order 10/14]: Resolve-DnsName on a public domain toward an explicit external
    #               resolver returns a Fake-IP (198.18.0.0/15), and curl.exe to
    #               that domain is routed via the SOCKS5 proxy with its domain name
    # -----------------------------------------------------------------------
    try {
        if (Test-ScenarioSocks5Prerequisite -Id "k") {
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
            $null = Wait-ForCtlEntry -ExePath $routeWardExePath -CtlCommand "connections" -Description "curl.exe connection to '$PublicDnsTestDomain' routed by '$ExpectedProxyRuleName'" -Match {
                param($c)
                $domMatchPoll = ($c.targetHost -ieq $PublicDnsTestDomain) -or ($null -ne $c.resolvedDomain -and $c.resolvedDomain -ieq $PublicDnsTestDomain)
                $c.processName -ieq "curl.exe" -and $domMatchPoll -and $c.matchedRule -eq $ExpectedProxyRuleName -and ([int64]$c.rxBytes) -gt 0
            }

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
                Record-ScenarioResult -Id "k" -Status "PASS" -Title "Fake-IP DNS interception & domain routing via SOCKS5" -Detail "$PublicDnsTestDomain -> $resolvedIpK (in $FakeIpCidr), curl HTTP $($curlResK.HttpCode) routed with domain '$($matchingDomainConnK.resolvedDomain)' (target $($matchingDomainConnK.targetHost))"
            } else {
                Record-ScenarioResult -Id "k" -Status "FAIL" -Title "Fake-IP DNS interception & domain routing via SOCKS5" -Detail "resolvedIp='$resolvedIpK' (isFakeIp=$isFakeIpK), inCtlTable=$sawFakeIpEntryK, curlHttp=$($curlResK.HttpCode), domainConnFound=$($null -ne $matchingDomainConnK)"
            }
        }
    } catch {
        Record-ScenarioResult -Id "k" -Status "FAIL" -Title "Fake-IP DNS interception & domain routing via SOCKS5" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (l) [Order 11/14]: Resolve-DnsName on the VM's Active Directory / primary DNS
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
    # Scenario (m) [Order 12/14]: After ctl stop and Clear-DnsClientCache, normal DNS resolution
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
    # Scenario (n) [Order 13/14]: Starting the engine automatically flushes the OS DNS
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

        $flushMethod = Get-StartupDnsFlushMethodFromLogs `
            -CtlLogItems $logsListN `
            -DaemonLogDirectory $daemonLogsDir `
            -DaemonLogFilter $logWildcard
        $sawStartupFlushLog = (-not [string]::IsNullOrWhiteSpace($flushMethod))

        if ($startResN.ExitCode -eq 0 -and $startDiagN.running -eq $true -and $sawStartupFlushLog -and $cachedAfterStart.Count -eq 0) {
            Record-ScenarioResult -Id "n" -Status "PASS" -Title "OS DNS cache flushed on engine startup" -Detail "OS DNS cache flushed at startup via $flushMethod; Get-DnsClientCache entries for $PublicDnsTestDomain after start = $($cachedAfterStart.Count)"
        } else {
            Record-ScenarioResult -Id "n" -Status "FAIL" -Title "OS DNS cache flushed on engine startup" -Detail "running=$($startDiagN.running), sawStartupFlushLog=$sawStartupFlushLog, cachedAfterStartCount=$($cachedAfterStart.Count)"
        }
    } catch {
        Record-ScenarioResult -Id "n" -Status "FAIL" -Title "OS DNS cache flushed on engine startup" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (o) [Order 14/16]: QUIC (UDP 443) rejected with inbound ICMPv4
    #               Port Unreachable (Type 3, Code 3), client error delay measured
    # -----------------------------------------------------------------------
    try {
        Ensure-ScenarioDaemonState -ExePath $routeWardExePath -WorkDir $resolvedBinDir -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs -RequireInterceptionRunning $true

        $quicProbe = Invoke-QuicUdp443Probe -TargetIp $ExternalDnsServer -Port 443 -ReceiveTimeoutMs 1500
        $null = Wait-ForCtlEntry -ExePath $routeWardExePath -CtlCommand "connections" -Description "blocked QUIC UDP 443 connection" -Match {
            param($c)
            [int]$c.targetPort -eq 443 -and $c.protocol -eq "udp" -and $c.matchedRule -eq "SecurityPolicy:blockQuicUdp443" -and $c.status -eq "blocked"
        }
        $null = Wait-ForCtlEntry -ExePath $routeWardExePath -CtlCommand "logs" -Description "QUIC rejection WARN log" -Match {
            param($l)
            $l.level -eq "WARN" -and ([string]$l.message).Contains("Rejected QUIC (UDP port 443) with ICMP Port Unreachable")
        }

        $connsResO = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("connections") -Label "Scenario-o-connections"
        $connsListO = ConvertFrom-CtlResponseJson `
            -RawJson $connsResO.RawText `
            -Context "Scenario-o-connections" `
            -ExpectResultArray `
            -RequiredArrayElementProperties @("targetHost", "targetPort", "protocol", "matchedRule", "status")

        $logsResO = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("logs") -Label "Scenario-o-logs"
        $logsListO = ConvertFrom-CtlResponseJson `
            -RawJson $logsResO.RawText `
            -Context "Scenario-o-logs" `
            -ExpectResultArray `
            -RequiredArrayElementProperties @("level", "component", "message")

        $sawQuicBlockedConn = $false
        foreach ($c in $connsListO) {
            if ([int]$c.targetPort -eq 443 -and $c.protocol -eq "udp" -and $c.matchedRule -eq "SecurityPolicy:blockQuicUdp443" -and $c.status -eq "blocked") {
                $sawQuicBlockedConn = $true
                break
            }
        }

        $sawQuicWarnLog = $false
        foreach ($l in $logsListO) {
            if ($l.level -eq "WARN" -and ([string]$l.message).Contains("Rejected QUIC (UDP port 443) with ICMP Port Unreachable")) {
                $sawQuicWarnLog = $true
                break
            }
        }

        if ($sawQuicBlockedConn -and $sawQuicWarnLog -and (-not $quicProbe.UnexpectedReplyReceived)) {
            Record-ScenarioResult -Id "o" -Status "PASS" -Title "QUIC (UDP 443) rejected with ICMP Port Unreachable" -Detail "UDP 443 toward ${ExternalDnsServer}:443 blocked=true, $(Get-FastRejectionNote -Probe $quicProbe) (clientError=$($quicProbe.SocketErrorCode), measuredDelay=$($quicProbe.DelayMs) ms, matchedRule=SecurityPolicy:blockQuicUdp443, status=blocked)"
        } else {
            Record-ScenarioResult -Id "o" -Status "FAIL" -Title "QUIC (UDP 443) rejected with ICMP Port Unreachable" -Detail "blocked=$sawQuicBlockedConn, sawWarnLog=$sawQuicWarnLog, unexpectedReply=$($quicProbe.UnexpectedReplyReceived), fastRejection=$($quicProbe.FastRejection), clientError=$($quicProbe.SocketErrorCode), delayMs=$($quicProbe.DelayMs)"
        }
    } catch {
        Record-ScenarioResult -Id "o" -Status "FAIL" -Title "QUIC (UDP 443) rejected with ICMP Port Unreachable" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (p) [Order 15/16]: LLMNR (UDP 5355) blocks public FQDNs with
    #               rate-limited WARN and allows local single-label names
    # -----------------------------------------------------------------------
    try {
        Ensure-ScenarioDaemonState -ExePath $routeWardExePath -WorkDir $resolvedBinDir -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs -RequireInterceptionRunning $true

        $publicLlmnrFqdn = "public-leak.routeward.test"
        $localLlmnrName = "fileserver"
        $publicPkt = New-DnsWireQueryPacket -QueryName $publicLlmnrFqdn -TransactionId 0x5355
        $localPkt = New-DnsWireQueryPacket -QueryName $localLlmnrName -TransactionId 0x5356

        $llmnrSock = New-Object System.Net.Sockets.UdpClient
        try {
            $null = $llmnrSock.Send($publicPkt, $publicPkt.Length, $ExternalDnsServer, 5355)
            $null = $llmnrSock.Send($localPkt, $localPkt.Length, $ExternalDnsServer, 5355)
        } finally {
            $llmnrSock.Close()
        }
        $null = Wait-ForCtlEntry -ExePath $routeWardExePath -CtlCommand "connections" -Description "LLMNR public FQDN blocked connection" -Match {
            param($c)
            [int]$c.targetPort -eq 5355 -and $c.protocol -eq "udp" -and $c.matchedRule -eq "LocalNameGuard:LLMNR" -and $c.status -eq "blocked" -and $c.resolvedDomain -ieq $publicLlmnrFqdn
        }
        $null = Wait-ForCtlEntry -ExePath $routeWardExePath -CtlCommand "logs" -Description "LLMNR WARN log" -Match {
            param($l)
            $l.level -eq "WARN" -and ([string]$l.message).Contains("Blocked public FQDN `"$publicLlmnrFqdn`" over LLMNR")
        }

        $connsResP = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("connections") -Label "Scenario-p-connections"
        $connsListP = ConvertFrom-CtlResponseJson `
            -RawJson $connsResP.RawText `
            -Context "Scenario-p-connections" `
            -ExpectResultArray `
            -RequiredArrayElementProperties @("targetPort", "protocol", "matchedRule", "status")

        $logsResP = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("logs") -Label "Scenario-p-logs"
        $logsListP = ConvertFrom-CtlResponseJson `
            -RawJson $logsResP.RawText `
            -Context "Scenario-p-logs" `
            -ExpectResultArray `
            -RequiredArrayElementProperties @("level", "component", "message")

        $sawPublicFqdnBlocked = $false
        $sawLocalNameBlocked = $false
        foreach ($c in $connsListP) {
            if ([int]$c.targetPort -eq 5355 -and $c.protocol -eq "udp" -and $c.matchedRule -eq "LocalNameGuard:LLMNR" -and $c.status -eq "blocked") {
                if ($c.resolvedDomain -ieq $publicLlmnrFqdn) {
                    $sawPublicFqdnBlocked = $true
                }
                if ($c.resolvedDomain -ieq $localLlmnrName) {
                    $sawLocalNameBlocked = $true
                }
            }
        }

        $sawLlmnrWarnLog = $false
        foreach ($l in $logsListP) {
            if ($l.level -eq "WARN" -and ([string]$l.message).Contains("Blocked public FQDN `"$publicLlmnrFqdn`" over LLMNR")) {
                $sawLlmnrWarnLog = $true
                break
            }
        }

        if ($sawPublicFqdnBlocked -and (-not $sawLocalNameBlocked) -and $sawLlmnrWarnLog) {
            Record-ScenarioResult -Id "p" -Status "PASS" -Title "LLMNR (UDP 5355) blocks public FQDNs and allows local names" -Detail "Public FQDN '$publicLlmnrFqdn' blocked (LocalNameGuard:LLMNR, WARN logged); local name '$localLlmnrName' allowed directly"
        } else {
            Record-ScenarioResult -Id "p" -Status "FAIL" -Title "LLMNR (UDP 5355) blocks public FQDNs and allows local names" -Detail "sawPublicFqdnBlocked=$sawPublicFqdnBlocked, sawLocalNameBlocked=$sawLocalNameBlocked, sawLlmnrWarnLog=$sawLlmnrWarnLog"
        }
    } catch {
        Record-ScenarioResult -Id "p" -Status "FAIL" -Title "LLMNR (UDP 5355) blocks public FQDNs and allows local names" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (q) [Order 16/19]: UDP routed through SOCKS5 UDP ASSOCIATE
    #               (time.cloudflare.com:123 via socks5_udp_test_server.exe)
    # -----------------------------------------------------------------------
    try {
        Ensure-ScenarioDaemonState -ExePath $routeWardExePath -WorkDir $resolvedBinDir -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs -RequireInterceptionRunning $true

        $profileBeforeQ = Get-NormalizedProfileSnapshotJson -ExePath $routeWardExePath -Label "Scenario-q-state-before"
        $statsFileQ = Join-Path ([System.IO.Path]::GetTempPath()) "routeward_udp_test_q_$PID.json"
        $tempProxyFileQ = Join-Path ([System.IO.Path]::GetTempPath()) "routeward_temp_proxy_q_$PID.json"
        $tempRuleFileQ = Join-Path ([System.IO.Path]::GetTempPath()) "routeward_temp_rule_q_$PID.json"
        $tempProxyIdQ = "socks-win-udp-test-$UdpTestProxyPort"
        $tempRuleIdQ = "rule-win-udp-ntp-proxy"
        $tempRuleNameQ = "WinTest UDP NTP Proxy"
        $udpServerProcQ = $null
        $proxyAddedQ = $false
        $ruleAddedQ = $false

        try {
            $udpServerProcQ = Start-TrackedUdpTestServer -ExePath $udpTestServerExePath -Port $UdpTestProxyPort -StatsFilePath $statsFileQ

            $proxyObjQ = [ordered]@{
                id            = $tempProxyIdQ
                name          = "UDP Test SOCKS5 $UdpTestProxyPort"
                protocol      = "socks5"
                host          = "127.0.0.1"
                port          = $UdpTestProxyPort
                auth          = $null
                udpEnabled    = $true
                tls           = $false
                sni           = $null
                enabled       = $true
                lastLatencyMs = $null
                exitIp        = $null
            }
            $tempProxyFileQ = Write-Utf8NoBomJsonTempFile -JsonText ($proxyObjQ | ConvertTo-Json -Depth 5 -Compress)
            $upProxyResQ = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("upsert-proxy", "--json-file", $tempProxyFileQ) -Label "Scenario-q-upsert-proxy"
            $upProxyObjQ = ConvertFrom-CtlResponseJson -RawJson $upProxyResQ.RawText -Context "Scenario-q-upsert-proxy" -RequiredResultProperties @("ok")
            if (-not $upProxyObjQ.ok) {
                throw "Failed to upsert temporary UDP test proxy '$tempProxyIdQ'"
            }
            $proxyAddedQ = $true
            $profileModifiedByScript = $true

            $ruleObjQ = [ordered]@{
                id              = $tempRuleIdQ
                name            = $tempRuleNameQ
                enabled         = $true
                priority        = 1
                processPatterns = @($script:ExpectedUdpHostProcesses)
                domainPatterns  = @()
                ipCidrs         = @()
                portRanges      = @(@{ start = $NtpPort; end = $NtpPort })
                protocol        = "udp"
                action          = [ordered]@{
                    type     = "proxy"
                    targetId = $tempProxyIdQ
                }
            }
            $tempRuleFileQ = Write-Utf8NoBomJsonTempFile -JsonText ($ruleObjQ | ConvertTo-Json -Depth 6 -Compress)
            $upRuleResQ = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("upsert-rule", "--json-file", $tempRuleFileQ) -Label "Scenario-q-upsert-rule"
            $upRuleObjQ = ConvertFrom-CtlResponseJson -RawJson $upRuleResQ.RawText -Context "Scenario-q-upsert-rule" -RequiredResultProperties @("ok")
            if (-not $upRuleObjQ.ok) {
                throw "Failed to upsert temporary UDP test rule '$tempRuleIdQ'"
            }
            $ruleAddedQ = $true

            # Intentional fixed wait: no observable signal that the engine has applied the new rule to its filter set.
            Start-Sleep -Milliseconds 250
            $ntpExchQ = Invoke-UdpNtpExchange -TargetHost $PublicNtpServer -Port $NtpPort -ReceiveTimeoutMs 4000
            $null = Wait-ForCtlEntry -ExePath $routeWardExePath -CtlCommand "connections" -Description "proxied UDP NTP connection for rule '$tempRuleNameQ'" -Match {
                param($c)
                [int]$c.targetPort -eq $NtpPort -and $c.protocol -eq "udp" -and $c.matchedRule -eq $tempRuleNameQ -and $c.status -ne "blocked"
            }

            $connsResQ = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("connections") -Label "Scenario-q-connections"
            $connsListQ = ConvertFrom-CtlResponseJson `
                -RawJson $connsResQ.RawText `
                -Context "Scenario-q-connections" `
                -ExpectResultArray `
                -RequiredArrayElementProperties @("processName", "targetPort", "protocol", "matchedRule", "routeLabel", "status")

            $logsResQ = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("logs") -Label "Scenario-q-logs"
            $logsListQ = ConvertFrom-CtlResponseJson `
                -RawJson $logsResQ.RawText `
                -Context "Scenario-q-logs" `
                -ExpectResultArray `
                -RequiredArrayElementProperties @("level", "component", "message")
            $routedUdpLogsQ = @(Get-RoutedUdpLogLines -CtlLogItems $logsListQ)
            $routedUdpLogSummaryQ = if ($routedUdpLogsQ.Count -gt 0) { $routedUdpLogsQ -join " | " } else { "none" }

            $sawProxiedNtpConn = $false
            foreach ($c in $connsListQ) {
                if ([int]$c.targetPort -eq $NtpPort -and $c.protocol -eq "udp" -and $c.matchedRule -eq $tempRuleNameQ -and $c.status -ne "blocked") {
                    $sawProxiedNtpConn = $true
                    break
                }
            }

            $statsObjQ = $null
            if (Test-Path -LiteralPath $statsFileQ) {
                $statsObjQ = Get-Content -LiteralPath $statsFileQ -Raw -Encoding UTF8 | ConvertFrom-Json
            }
            $assocReqsQ = if ($null -ne $statsObjQ) { [int]$statsObjQ.udp_associate_requests } else { 0 }
            $dgramsRelayedQ = if ($null -ne $statsObjQ) { [int]$statsObjQ.udp_datagrams_relayed } else { 0 }
            $repliesRelayedQ = if ($null -ne $statsObjQ -and $statsObjQ.PSObject.Properties.Match("udp_replies_relayed").Count -gt 0) { [int]$statsObjQ.udp_replies_relayed } else { 0 }
            $assocRefusedQ = if ($null -ne $statsObjQ -and $statsObjQ.PSObject.Properties.Match("udp_associate_refused").Count -gt 0) { [int]$statsObjQ.udp_associate_refused } else { 0 }
            $statsSummaryQ = "stats-file(udp_associate_requests=$assocReqsQ, udp_datagrams_relayed=$dgramsRelayedQ, udp_replies_relayed=$repliesRelayedQ, udp_associate_refused=$assocRefusedQ)"
            $auditNotes.Add("Scenario (q) diagnostics: $statsSummaryQ; daemon Routed UDP logs: [$routedUdpLogSummaryQ]")

            if ($ntpExchQ.ReplyReceived -and $ntpExchQ.ReplyLength -ge 48 -and $sawProxiedNtpConn -and $assocReqsQ -ge 1 -and $dgramsRelayedQ -ge 1 -and $repliesRelayedQ -ge 1) {
                Record-ScenarioResult -Id "q" -Status "PASS" -Title "UDP routed through SOCKS5 UDP ASSOCIATE (NTP via test server)" -Detail "NTP reply received ($($ntpExchQ.ReplyLength) bytes in $($ntpExchQ.DelayMs) ms via Fake-IP/Target $($ntpExchQ.TargetIp)); $statsSummaryQ; routedUdpLogs=[$routedUdpLogSummaryQ]"
            } else {
                $failPrefixQ = if (-not [string]::IsNullOrWhiteSpace($ntpExchQ.ErrorMessage)) { "$($ntpExchQ.ErrorMessage); " } else { "" }
                Record-ScenarioResult -Id "q" -Status "FAIL" -Title "UDP routed through SOCKS5 UDP ASSOCIATE (NTP via test server)" -Detail "${failPrefixQ}replyReceived=$($ntpExchQ.ReplyReceived) len=$($ntpExchQ.ReplyLength), sawConn=$sawProxiedNtpConn, $statsSummaryQ, routedUdpLogs=[$routedUdpLogSummaryQ]"
            }
        } finally {
            if ($ruleAddedQ) {
                $null = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("remove-rule", "--id", $tempRuleIdQ) -Label "Scenario-q-remove-rule"
            }
            if ($proxyAddedQ) {
                $null = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("remove-proxy", "--id", $tempProxyIdQ) -Label "Scenario-q-remove-proxy"
            }
            if ($null -ne $udpServerProcQ -and (-not $udpServerProcQ.HasExited)) {
                Stop-Process -Id $udpServerProcQ.Id -Force -ErrorAction SilentlyContinue
                Wait-Process -Id $udpServerProcQ.Id -Timeout 5 -ErrorAction SilentlyContinue
            }
            Remove-Item -LiteralPath $tempProxyFileQ, $tempRuleFileQ, $statsFileQ -Force -ErrorAction SilentlyContinue
            $profileAfterQ = Get-NormalizedProfileSnapshotJson -ExePath $routeWardExePath -Label "Scenario-q-state-after"
            if ($profileBeforeQ -ne $profileAfterQ) {
                throw "Scenario (q) cleanup check failed: profile state after cleanup does not match profile state before Scenario (q)."
            }
        }
    } catch {
        Record-ScenarioResult -Id "q" -Status "FAIL" -Title "UDP routed through SOCKS5 UDP ASSOCIATE (NTP via test server)" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (r) [Order 17/19]: Proxy refusing UDP ASSOCIATE (--disable-udp-associate)
    #               blocks UDP with Kill-Switch and never leaks Direct
    # -----------------------------------------------------------------------
    try {
        Ensure-ScenarioDaemonState -ExePath $routeWardExePath -WorkDir $resolvedBinDir -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs -RequireInterceptionRunning $true

        $profileBeforeR = Get-NormalizedProfileSnapshotJson -ExePath $routeWardExePath -Label "Scenario-r-state-before"
        $statsFileR = Join-Path ([System.IO.Path]::GetTempPath()) "routeward_udp_test_r_$PID.json"
        $tempProxyFileR = Join-Path ([System.IO.Path]::GetTempPath()) "routeward_temp_proxy_r_$PID.json"
        $tempRuleFileR = Join-Path ([System.IO.Path]::GetTempPath()) "routeward_temp_rule_r_$PID.json"
        $tempProxyIdR = "socks-win-udp-refuse-$UdpRefuseTestProxyPort"
        $tempRuleIdR = "rule-win-udp-ntp-refuse"
        $tempRuleNameR = "WinTest UDP NTP Refuse"
        $udpServerProcR = $null
        $proxyAddedR = $false
        $ruleAddedR = $false

        try {
            $udpServerProcR = Start-TrackedUdpTestServer -ExePath $udpTestServerExePath -Port $UdpRefuseTestProxyPort -StatsFilePath $statsFileR -DisableUdpAssociate

            $proxyObjR = [ordered]@{
                id            = $tempProxyIdR
                name          = "UDP Refuse SOCKS5 $UdpRefuseTestProxyPort"
                protocol      = "socks5"
                host          = "127.0.0.1"
                port          = $UdpRefuseTestProxyPort
                auth          = $null
                udpEnabled    = $true
                tls           = $false
                sni           = $null
                enabled       = $true
                lastLatencyMs = $null
                exitIp        = $null
            }
            $tempProxyFileR = Write-Utf8NoBomJsonTempFile -JsonText ($proxyObjR | ConvertTo-Json -Depth 5 -Compress)
            $upProxyResR = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("upsert-proxy", "--json-file", $tempProxyFileR) -Label "Scenario-r-upsert-proxy"
            $upProxyObjR = ConvertFrom-CtlResponseJson -RawJson $upProxyResR.RawText -Context "Scenario-r-upsert-proxy" -RequiredResultProperties @("ok")
            if (-not $upProxyObjR.ok) {
                throw "Failed to upsert temporary UDP refuse proxy '$tempProxyIdR'"
            }
            $proxyAddedR = $true
            $profileModifiedByScript = $true

            $ruleObjR = [ordered]@{
                id              = $tempRuleIdR
                name            = $tempRuleNameR
                enabled         = $true
                priority        = 1
                processPatterns = @($script:ExpectedUdpHostProcesses)
                domainPatterns  = @()
                ipCidrs         = @()
                portRanges      = @(@{ start = $NtpPort; end = $NtpPort })
                protocol        = "udp"
                action          = [ordered]@{
                    type     = "proxy"
                    targetId = $tempProxyIdR
                }
            }
            $tempRuleFileR = Write-Utf8NoBomJsonTempFile -JsonText ($ruleObjR | ConvertTo-Json -Depth 6 -Compress)
            $upRuleResR = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("upsert-rule", "--json-file", $tempRuleFileR) -Label "Scenario-r-upsert-rule"
            $upRuleObjR = ConvertFrom-CtlResponseJson -RawJson $upRuleResR.RawText -Context "Scenario-r-upsert-rule" -RequiredResultProperties @("ok")
            if (-not $upRuleObjR.ok) {
                throw "Failed to upsert temporary UDP refuse rule '$tempRuleIdR'"
            }
            $ruleAddedR = $true

            # Intentional fixed wait: no observable signal that the engine has applied the new rule to its filter set.
            Start-Sleep -Milliseconds 250
            $ntpExchR = Invoke-UdpNtpExchange -TargetHost $PublicNtpServer -Port $NtpPort -ReceiveTimeoutMs 2000
            $null = Wait-ForCtlEntry -ExePath $routeWardExePath -CtlCommand "connections" -Description "blocked UDP NTP connection for rule '$tempRuleNameR'" -Match {
                param($c)
                [int]$c.targetPort -eq $NtpPort -and $c.protocol -eq "udp" -and $c.matchedRule -eq $tempRuleNameR -and $c.status -eq "blocked" -and $c.routeLabel -eq "BLOCKED"
            }

            $connsResR = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("connections") -Label "Scenario-r-connections"
            $connsListR = ConvertFrom-CtlResponseJson `
                -RawJson $connsResR.RawText `
                -Context "Scenario-r-connections" `
                -ExpectResultArray `
                -RequiredArrayElementProperties @("processName", "targetPort", "protocol", "matchedRule", "routeLabel", "status")

            $sawBlockedRefuseConn = $false
            foreach ($c in $connsListR) {
                if ([int]$c.targetPort -eq $NtpPort -and $c.protocol -eq "udp" -and $c.matchedRule -eq $tempRuleNameR -and $c.status -eq "blocked" -and $c.routeLabel -eq "BLOCKED") {
                    $sawBlockedRefuseConn = $true
                    break
                }
            }

            $statsObjR = $null
            if (Test-Path -LiteralPath $statsFileR) {
                $statsObjR = Get-Content -LiteralPath $statsFileR -Raw -Encoding UTF8 | ConvertFrom-Json
            }
            $assocRefusedR = if ($null -ne $statsObjR) { [int]$statsObjR.udp_associate_refused } else { 0 }

            if ((-not $ntpExchR.ReplyReceived) -and $sawBlockedRefuseConn -and $assocRefusedR -ge 1) {
                Record-ScenarioResult -Id "r" -Status "PASS" -Title "Proxy refusing UDP ASSOCIATE blocks UDP with Kill-Switch" -Detail "UDP ASSOCIATE refused with REP=0x07 (udp_associate_refused=$assocRefusedR); no Direct leak (replyReceived=false); connection recorded as status=blocked/routeLabel=BLOCKED"
            } else {
                Record-ScenarioResult -Id "r" -Status "FAIL" -Title "Proxy refusing UDP ASSOCIATE blocks UDP with Kill-Switch" -Detail "replyReceived=$($ntpExchR.ReplyReceived), sawBlockedConn=$sawBlockedRefuseConn, udp_associate_refused=$assocRefusedR"
            }
        } finally {
            if ($ruleAddedR) {
                $null = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("remove-rule", "--id", $tempRuleIdR) -Label "Scenario-r-remove-rule"
            }
            if ($proxyAddedR) {
                $null = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("remove-proxy", "--id", $tempProxyIdR) -Label "Scenario-r-remove-proxy"
            }
            if ($null -ne $udpServerProcR -and (-not $udpServerProcR.HasExited)) {
                Stop-Process -Id $udpServerProcR.Id -Force -ErrorAction SilentlyContinue
                Wait-Process -Id $udpServerProcR.Id -Timeout 5 -ErrorAction SilentlyContinue
            }
            Remove-Item -LiteralPath $tempProxyFileR, $tempRuleFileR, $statsFileR -Force -ErrorAction SilentlyContinue
            $profileAfterR = Get-NormalizedProfileSnapshotJson -ExePath $routeWardExePath -Label "Scenario-r-state-after"
            if ($profileBeforeR -ne $profileAfterR) {
                throw "Scenario (r) cleanup check failed: profile state after cleanup does not match profile state before Scenario (r)."
            }
        }
    } catch {
        Record-ScenarioResult -Id "r" -Status "FAIL" -Title "Proxy refusing UDP ASSOCIATE blocks UDP with Kill-Switch" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (s) [Order 18/19]: Direct UDP flow attributed to process in
    #               ctl connections / ctl logs
    # -----------------------------------------------------------------------
    try {
        Ensure-ScenarioDaemonState -ExePath $routeWardExePath -WorkDir $resolvedBinDir -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs -RequireInterceptionRunning $true

        $ntpExchS = Invoke-UdpNtpExchange -TargetHost $PublicNtpServer -Port $NtpPort -ReceiveTimeoutMs 4000
        $null = Wait-ForCtlEntry -ExePath $routeWardExePath -CtlCommand "connections" -Description "direct UDP NTP connection attributed to a process" -Match {
            param($c)
            [int]$c.targetPort -eq $NtpPort -and $c.protocol -eq "udp" -and $c.routeLabel -eq "DIRECT" -and ($script:ExpectedUdpHostProcesses -contains $c.processName)
        }
        $null = Wait-ForCtlEntry -ExePath $routeWardExePath -CtlCommand "logs" -Description "direct UDP Routed log line" -Match {
            param($l)
            $msgPoll = [string]$l.message
            $msgPoll.Contains("Routed UDP") -and $msgPoll.Contains(":$NtpPort") -and $msgPoll.Contains("DIRECT")
        }

        $connsResS = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("connections") -Label "Scenario-s-connections"
        $connsListS = ConvertFrom-CtlResponseJson `
            -RawJson $connsResS.RawText `
            -Context "Scenario-s-connections" `
            -ExpectResultArray `
            -RequiredArrayElementProperties @("processName", "targetPort", "protocol", "matchedRule", "routeLabel", "status")

        $logsResS = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("logs") -Label "Scenario-s-logs"
        $logsListS = ConvertFrom-CtlResponseJson `
            -RawJson $logsResS.RawText `
            -Context "Scenario-s-logs" `
            -ExpectResultArray `
            -RequiredArrayElementProperties @("level", "component", "message")

        $matchedDirectUdpConn = $null
        foreach ($c in $connsListS) {
            if ([int]$c.targetPort -eq $NtpPort -and $c.protocol -eq "udp" -and $c.routeLabel -eq "DIRECT" -and ($script:ExpectedUdpHostProcesses -contains $c.processName)) {
                $matchedDirectUdpConn = $c
                break
            }
        }

        $sawDirectUdpLog = $false
        foreach ($l in $logsListS) {
            $msgS = [string]$l.message
            if (($l.component -eq "TransparentRelay" -or $l.component -eq "WinDivert" -or $l.component -eq "Interceptor") -and $msgS.Contains("Routed UDP") -and $msgS.Contains(":$NtpPort") -and $msgS.Contains("DIRECT")) {
                foreach ($procCand in $script:ExpectedUdpHostProcesses) {
                    if ($msgS.Contains($procCand)) {
                        $sawDirectUdpLog = $true
                        break
                    }
                }
                if ($sawDirectUdpLog) {
                    break
                }
            }
        }
        $routedUdpLogsS = @(Get-RoutedUdpLogLines -CtlLogItems $logsListS)
        $routedUdpLogSummaryS = if ($routedUdpLogsS.Count -gt 0) { $routedUdpLogsS -join " | " } else { "none" }
        $statsSummaryS = "stats-file=none(direct-udp)"
        $auditNotes.Add("Scenario (s) diagnostics: $statsSummaryS; daemon Routed UDP logs: [$routedUdpLogSummaryS]")

        if ($ntpExchS.ReplyReceived -and $ntpExchS.ReplyLength -ge 48 -and $null -ne $matchedDirectUdpConn -and $sawDirectUdpLog) {
            Record-ScenarioResult -Id "s" -Status "PASS" -Title "Direct UDP flow attributed to process in ctl connections" -Detail "Direct NTP reply received ($($ntpExchS.ReplyLength) bytes in $($ntpExchS.DelayMs) ms from $($ntpExchS.TargetIp)); attributed to processName=$($matchedDirectUdpConn.processName), protocol=udp, routeLabel=DIRECT, matchedRule=$($matchedDirectUdpConn.matchedRule); $statsSummaryS; routedUdpLogs=[$routedUdpLogSummaryS]"
        } else {
            $failPrefixS = if (-not [string]::IsNullOrWhiteSpace($ntpExchS.ErrorMessage)) { "$($ntpExchS.ErrorMessage); " } else { "" }
            Record-ScenarioResult -Id "s" -Status "FAIL" -Title "Direct UDP flow attributed to process in ctl connections" -Detail "${failPrefixS}replyReceived=$($ntpExchS.ReplyReceived) len=$($ntpExchS.ReplyLength), hasAttributedConn=$($null -ne $matchedDirectUdpConn), sawDirectUdpLog=$sawDirectUdpLog, $statsSummaryS, routedUdpLogs=[$routedUdpLogSummaryS]"
        }
    } catch {
        Record-ScenarioResult -Id "s" -Status "FAIL" -Title "Direct UDP flow attributed to process in ctl connections" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (t) [Order 19/26]: Real Windows WinDivert IPv6 TCP interception
    #               -> [::]:10810 transparent reflect -> SOCKS5 ATYP=0x04
    #               -> curl.exe -6 HTTP 200 (temporary ULA + route cleaned up)
    # -----------------------------------------------------------------------
    try {
        Ensure-ScenarioDaemonState -ExePath $routeWardExePath -WorkDir $resolvedBinDir -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs -RequireInterceptionRunning $true

        $profileBeforeT = Get-NormalizedProfileSnapshotJson -ExePath $routeWardExePath -Label "Scenario-t-state-before"
        $ipv6TargetIpT = "2001:db8:7277::10"
        $statsFileT = Join-Path ([System.IO.Path]::GetTempPath()) "routeward_ipv6_test_t_$PID.json"
        $tempProxyFileT = Join-Path ([System.IO.Path]::GetTempPath()) "routeward_temp_proxy_t_$PID.json"
        $tempRuleFileT = Join-Path ([System.IO.Path]::GetTempPath()) "routeward_temp_rule_t_$PID.json"
        $tempProxyIdT = "socks-win-ipv6-test-$Ipv6TestProxyPort"
        $tempRuleIdT = "rule-win-ipv6-tcp-proxy"
        $tempRuleNameT = "WinTest IPv6 TCP Proxy"
        $ipv6RouteCtxT = $null
        $ipv6HttpHandleT = $null
        $socksProcT = $null
        $proxyAddedT = $false
        $ruleAddedT = $false

        try {
            $ipv6RouteCtxT = Initialize-TransientWinDivertIpv6Route -TargetRemoteIp $ipv6TargetIpT
            if ($null -eq $ipv6RouteCtxT) {
                Record-ScenarioResult -Id "t" -Status "SKIP" -Title "IPv6 TCP interception & SOCKS5 ATYP=0x04 routing via WinDivert" -Detail "No connected non-loopback network adapter found for transient IPv6 route"
            } else {
                $ipv6HttpHandleT = Start-LocalIpv6HttpTestListener -Port $Ipv6TestHttpPort
                $socksProcT = Start-TrackedUdpTestServer `
                    -ExePath $udpTestServerExePath `
                    -Port $Ipv6TestProxyPort `
                    -StatsFilePath $statsFileT `
                    -ExtraArgs @("--map-target", "${ipv6TargetIpT}=::1")

                $proxyObjT = [ordered]@{
                    id            = $tempProxyIdT
                    name          = "IPv6 Test SOCKS5 $Ipv6TestProxyPort"
                    protocol      = "socks5"
                    host          = "127.0.0.1"
                    port          = $Ipv6TestProxyPort
                    auth          = $null
                    udpEnabled    = $true
                    tls           = $false
                    sni           = $null
                    enabled       = $true
                    lastLatencyMs = $null
                    exitIp        = $null
                }
                $tempProxyFileT = Write-Utf8NoBomJsonTempFile -JsonText ($proxyObjT | ConvertTo-Json -Depth 5 -Compress)
                $upProxyResT = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("upsert-proxy", "--json-file", $tempProxyFileT) -Label "Scenario-t-upsert-proxy"
                $upProxyObjT = ConvertFrom-CtlResponseJson -RawJson $upProxyResT.RawText -Context "Scenario-t-upsert-proxy" -RequiredResultProperties @("ok")
                if (-not $upProxyObjT.ok) {
                    throw "Failed to upsert temporary IPv6 test proxy '$tempProxyIdT'"
                }
                $proxyAddedT = $true
                $profileModifiedByScript = $true

                $ruleObjT = [ordered]@{
                    id              = $tempRuleIdT
                    name            = $tempRuleNameT
                    enabled         = $true
                    priority        = 1
                    processPatterns = @("curl.exe")
                    domainPatterns  = @()
                    ipCidrs         = @("$ipv6TargetIpT/128")
                    portRanges      = @(@{ start = $Ipv6TestHttpPort; end = $Ipv6TestHttpPort })
                    protocol        = "tcp"
                    action          = [ordered]@{
                        type     = "proxy"
                        targetId = $tempProxyIdT
                    }
                }
                $tempRuleFileT = Write-Utf8NoBomJsonTempFile -JsonText ($ruleObjT | ConvertTo-Json -Depth 6 -Compress)
                $upRuleResT = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("upsert-rule", "--json-file", $tempRuleFileT) -Label "Scenario-t-upsert-rule"
                $upRuleObjT = ConvertFrom-CtlResponseJson -RawJson $upRuleResT.RawText -Context "Scenario-t-upsert-rule" -RequiredResultProperties @("ok")
                if (-not $upRuleObjT.ok) {
                    throw "Failed to upsert temporary IPv6 TCP rule '$tempRuleIdT'"
                }
                $ruleAddedT = $true

                # Intentional fixed wait: no observable signal that the engine has applied the new rule to its filter set.
                Start-Sleep -Milliseconds 250
                $ipv6UrlT = "http://[${ipv6TargetIpT}]:${Ipv6TestHttpPort}/"
                $curlResT = Invoke-UnproxiedCurl -CurlBin $CurlExePath -Url $ipv6UrlT -TimeoutSec 8
                $null = Wait-ForCtlEntry -ExePath $routeWardExePath -CtlCommand "connections" -Description "IPv6 curl.exe connection routed by '$tempRuleNameT'" -Match {
                    param($c)
                    $c.processName -ieq "curl.exe" -and $c.targetHost -ieq $ipv6TargetIpT -and [int]$c.targetPort -eq $Ipv6TestHttpPort -and $c.matchedRule -eq $tempRuleNameT -and ([int64]$c.rxBytes) -gt 0
                }

                $connsResT = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("connections") -Label "Scenario-t-connections"
                $connsListT = ConvertFrom-CtlResponseJson `
                    -RawJson $connsResT.RawText `
                    -Context "Scenario-t-connections" `
                    -ExpectResultArray `
                    -RequiredArrayElementProperties @("processName", "targetHost", "targetPort", "matchedRule", "rxBytes", "status")

                $matchedConnT = $null
                foreach ($c in $connsListT) {
                    if ($c.processName -ieq "curl.exe" -and $c.targetHost -ieq $ipv6TargetIpT -and [int]$c.targetPort -eq $Ipv6TestHttpPort -and $c.matchedRule -eq $tempRuleNameT -and ([int64]$c.rxBytes) -gt 0) {
                        $matchedConnT = $c
                        break
                    }
                }

                $statsObjT = $null
                if (Test-Path -LiteralPath $statsFileT) {
                    $statsObjT = Get-Content -LiteralPath $statsFileT -Raw -Encoding UTF8 | ConvertFrom-Json
                }
                $tcpConnectReqsT = if ($null -ne $statsObjT) { [int]$statsObjT.tcp_connect_requests } else { 0 }

                if ($curlResT.ExitCode -eq 0 -and $curlResT.HttpCode -eq $ExpectedHttpStatus -and $null -ne $matchedConnT -and $tcpConnectReqsT -ge 1) {
                    Record-ScenarioResult -Id "t" -Status "PASS" -Title "IPv6 TCP interception & SOCKS5 ATYP=0x04 routing via WinDivert" -Detail "curl -6 HTTP $($curlResT.HttpCode) to [${ipv6TargetIpT}]:${Ipv6TestHttpPort} via $($ipv6RouteCtxT.InterfaceAlias), rxBytes=$($matchedConnT.rxBytes), tcp_connect_requests=$tcpConnectReqsT"
                } else {
                    Record-ScenarioResult -Id "t" -Status "FAIL" -Title "IPv6 TCP interception & SOCKS5 ATYP=0x04 routing via WinDivert" -Detail "curlExit=$($curlResT.ExitCode) http=$($curlResT.HttpCode), connFound=$($null -ne $matchedConnT), tcp_connect_requests=$tcpConnectReqsT"
                }
            }
        } finally {
            if ($ruleAddedT) {
                $null = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("remove-rule", "--id", $tempRuleIdT) -Label "Scenario-t-remove-rule"
            }
            if ($proxyAddedT) {
                $null = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("remove-proxy", "--id", $tempProxyIdT) -Label "Scenario-t-remove-proxy"
            }
            Stop-LocalIpv6HttpTestListener -Handle $ipv6HttpHandleT
            if ($null -ne $socksProcT -and (-not $socksProcT.HasExited)) {
                Stop-Process -Id $socksProcT.Id -Force -ErrorAction SilentlyContinue
                Wait-Process -Id $socksProcT.Id -Timeout 5 -ErrorAction SilentlyContinue
            }
            Remove-TransientWinDivertIpv6Route -Context $ipv6RouteCtxT
            Remove-Item -LiteralPath $tempProxyFileT, $tempRuleFileT, $statsFileT -Force -ErrorAction SilentlyContinue
            $profileAfterT = Get-NormalizedProfileSnapshotJson -ExePath $routeWardExePath -Label "Scenario-t-state-after"
            if ($profileBeforeT -ne $profileAfterT) {
                throw "Scenario (t) cleanup check failed: profile state after cleanup does not match profile state before Scenario (t)."
            }
        }
    } catch {
        Record-ScenarioResult -Id "t" -Status "FAIL" -Title "IPv6 TCP interception & SOCKS5 ATYP=0x04 routing via WinDivert" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (u) [Order 20/26]: Real Windows WinDivert IPv6 UDP interception
    #               -> SOCKS5 UDP ASSOCIATE (ATYP=0x04) -> forged IPv6 UDP reply
    # -----------------------------------------------------------------------
    try {
        Ensure-ScenarioDaemonState -ExePath $routeWardExePath -WorkDir $resolvedBinDir -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs -RequireInterceptionRunning $true

        $profileBeforeU = Get-NormalizedProfileSnapshotJson -ExePath $routeWardExePath -Label "Scenario-u-state-before"
        $ipv6LocalUlaU = "fd00:7277:2026::11"
        $ipv6NextHopU = "fd00:7277:2026::2"
        $ipv6TargetIpU = "2001:db8:7277::11"
        $statsFileU = Join-Path ([System.IO.Path]::GetTempPath()) "routeward_ipv6_test_u_$PID.json"
        $tempProxyFileU = Join-Path ([System.IO.Path]::GetTempPath()) "routeward_temp_proxy_u_$PID.json"
        $tempRuleFileU = Join-Path ([System.IO.Path]::GetTempPath()) "routeward_temp_rule_u_$PID.json"
        $tempProxyIdU = "socks-win-ipv6-udp-test-$Ipv6TestProxyPort"
        $tempRuleIdU = "rule-win-ipv6-udp-proxy"
        $tempRuleNameU = "WinTest IPv6 UDP Proxy"
        $ipv6RouteCtxU = $null
        $socksProcU = $null
        $proxyAddedU = $false
        $ruleAddedU = $false

        try {
            $ipv6RouteCtxU = Initialize-TransientWinDivertIpv6Route -LocalUlaIp $ipv6LocalUlaU -NextHopIp $ipv6NextHopU -TargetRemoteIp $ipv6TargetIpU -NeighborMac "02-00-5e-72-77-02"
            if ($null -eq $ipv6RouteCtxU) {
                Record-ScenarioResult -Id "u" -Status "SKIP" -Title "IPv6 UDP interception & SOCKS5 UDP ASSOCIATE ATYP=0x04 via WinDivert" -Detail "No connected non-loopback network adapter found for transient IPv6 route"
            } else {
                $socksProcU = Start-TrackedUdpTestServer `
                    -ExePath $udpTestServerExePath `
                    -Port $Ipv6TestProxyPort `
                    -StatsFilePath $statsFileU `
                    -ExtraArgs @("--udp-echo-bind", "[::1]:$Ipv6TestUdpPort", "--map-target", "${ipv6TargetIpU}=::1")

                $proxyObjU = [ordered]@{
                    id            = $tempProxyIdU
                    name          = "IPv6 UDP Test SOCKS5 $Ipv6TestProxyPort"
                    protocol      = "socks5"
                    host          = "127.0.0.1"
                    port          = $Ipv6TestProxyPort
                    auth          = $null
                    udpEnabled    = $true
                    tls           = $false
                    sni           = $null
                    enabled       = $true
                    lastLatencyMs = $null
                    exitIp        = $null
                }
                $tempProxyFileU = Write-Utf8NoBomJsonTempFile -JsonText ($proxyObjU | ConvertTo-Json -Depth 5 -Compress)
                $upProxyResU = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("upsert-proxy", "--json-file", $tempProxyFileU) -Label "Scenario-u-upsert-proxy"
                $upProxyObjU = ConvertFrom-CtlResponseJson -RawJson $upProxyResU.RawText -Context "Scenario-u-upsert-proxy" -RequiredResultProperties @("ok")
                if (-not $upProxyObjU.ok) {
                    throw "Failed to upsert temporary IPv6 UDP proxy '$tempProxyIdU'"
                }
                $proxyAddedU = $true
                $profileModifiedByScript = $true

                $ruleObjU = [ordered]@{
                    id              = $tempRuleIdU
                    name            = $tempRuleNameU
                    enabled         = $true
                    priority        = 1
                    processPatterns = @($script:ExpectedUdpHostProcesses)
                    domainPatterns  = @()
                    ipCidrs         = @("$ipv6TargetIpU/128")
                    portRanges      = @(@{ start = $Ipv6TestUdpPort; end = $Ipv6TestUdpPort })
                    protocol        = "udp"
                    action          = [ordered]@{
                        type     = "proxy"
                        targetId = $tempProxyIdU
                    }
                }
                $tempRuleFileU = Write-Utf8NoBomJsonTempFile -JsonText ($ruleObjU | ConvertTo-Json -Depth 6 -Compress)
                $upRuleResU = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("upsert-rule", "--json-file", $tempRuleFileU) -Label "Scenario-u-upsert-rule"
                $upRuleObjU = ConvertFrom-CtlResponseJson -RawJson $upRuleResU.RawText -Context "Scenario-u-upsert-rule" -RequiredResultProperties @("ok")
                if (-not $upRuleObjU.ok) {
                    throw "Failed to upsert temporary IPv6 UDP rule '$tempRuleIdU'"
                }
                $ruleAddedU = $true

                # Intentional fixed wait: no observable signal that the engine has applied the new rule to its filter set.
                Start-Sleep -Milliseconds 250
                $udpExchU = Invoke-Ipv6UdpNtpExchange -TargetIp $ipv6TargetIpU -Port $Ipv6TestUdpPort -ReceiveTimeoutMs 4000 -LocalIp $ipv6LocalUlaU
                $null = Wait-ForCtlEntry -ExePath $routeWardExePath -CtlCommand "connections" -Description "IPv6 UDP connection routed by '$tempRuleNameU'" -Match {
                    param($c)
                    [int]$c.targetPort -eq $Ipv6TestUdpPort -and $c.protocol -eq "udp" -and $c.targetHost -ieq $ipv6TargetIpU -and $c.matchedRule -eq $tempRuleNameU -and $c.status -ne "blocked"
                }

                $connsResU = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("connections") -Label "Scenario-u-connections"
                $connsListU = ConvertFrom-CtlResponseJson `
                    -RawJson $connsResU.RawText `
                    -Context "Scenario-u-connections" `
                    -ExpectResultArray `
                    -RequiredArrayElementProperties @("processName", "targetHost", "targetPort", "protocol", "matchedRule", "status")

                $matchedUdpConnU = $null
                foreach ($c in $connsListU) {
                    if ([int]$c.targetPort -eq $Ipv6TestUdpPort -and $c.protocol -eq "udp" -and $c.targetHost -ieq $ipv6TargetIpU -and $c.matchedRule -eq $tempRuleNameU -and $c.status -ne "blocked") {
                        $matchedUdpConnU = $c
                        break
                    }
                }

                $statsObjU = $null
                if (Test-Path -LiteralPath $statsFileU) {
                    $statsObjU = Get-Content -LiteralPath $statsFileU -Raw -Encoding UTF8 | ConvertFrom-Json
                }
                $assocReqsU = if ($null -ne $statsObjU) { [int]$statsObjU.udp_associate_requests } else { 0 }
                $dgramsRelayedU = if ($null -ne $statsObjU) { [int]$statsObjU.udp_datagrams_relayed } else { 0 }
                $repliesRelayedU = if ($null -ne $statsObjU) { [int]$statsObjU.udp_replies_relayed } else { 0 }
                $lastTargetU = if ($null -ne $statsObjU) { [string]$statsObjU.last_udp_target } else { "" }

                if ($udpExchU.ReplyReceived -and $udpExchU.ReplyLength -ge 48 -and $null -ne $matchedUdpConnU -and $assocReqsU -ge 1 -and $dgramsRelayedU -ge 1 -and $repliesRelayedU -ge 1) {
                    Record-ScenarioResult -Id "u" -Status "PASS" -Title "IPv6 UDP interception & SOCKS5 UDP ASSOCIATE ATYP=0x04 via WinDivert" -Detail "IPv6 UDP reply ($($udpExchU.ReplyLength) bytes in $($udpExchU.DelayMs) ms from $($udpExchU.RemoteIp)), process=$($matchedUdpConnU.processName), last_udp_target=$lastTargetU, udp_datagrams_relayed=$dgramsRelayedU, udp_replies_relayed=$repliesRelayedU"
                } else {
                    $failPrefixU = if (-not [string]::IsNullOrWhiteSpace($udpExchU.ErrorMessage)) { "$($udpExchU.ErrorMessage); " } else { "" }
                    Record-ScenarioResult -Id "u" -Status "FAIL" -Title "IPv6 UDP interception & SOCKS5 UDP ASSOCIATE ATYP=0x04 via WinDivert" -Detail "${failPrefixU}replyReceived=$($udpExchU.ReplyReceived) len=$($udpExchU.ReplyLength), connFound=$($null -ne $matchedUdpConnU), assoc=$assocReqsU, relayed=$dgramsRelayedU, replies=$repliesRelayedU"
                }
            }
        } finally {
            if ($ruleAddedU) {
                $null = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("remove-rule", "--id", $tempRuleIdU) -Label "Scenario-u-remove-rule"
            }
            if ($proxyAddedU) {
                $null = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("remove-proxy", "--id", $tempProxyIdU) -Label "Scenario-u-remove-proxy"
            }
            if ($null -ne $socksProcU -and (-not $socksProcU.HasExited)) {
                Stop-Process -Id $socksProcU.Id -Force -ErrorAction SilentlyContinue
                Wait-Process -Id $socksProcU.Id -Timeout 5 -ErrorAction SilentlyContinue
            }
            Remove-TransientWinDivertIpv6Route -Context $ipv6RouteCtxU
            Remove-Item -LiteralPath $tempProxyFileU, $tempRuleFileU, $statsFileU -Force -ErrorAction SilentlyContinue
            $profileAfterU = Get-NormalizedProfileSnapshotJson -ExePath $routeWardExePath -Label "Scenario-u-state-after"
            if ($profileBeforeU -ne $profileAfterU) {
                throw "Scenario (u) cleanup check failed: profile state after cleanup does not match profile state before Scenario (u)."
            }
        }
    } catch {
        Record-ScenarioResult -Id "u" -Status "FAIL" -Title "IPv6 UDP interception & SOCKS5 UDP ASSOCIATE ATYP=0x04 via WinDivert" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (v) [Order 21/26]: IPv6 DNS (port 53 UDP/TCP Fake-IP A & AAAA NODATA)
    #               and gated IPv6 DoT (port 853) SecurityPolicy check
    # -----------------------------------------------------------------------
    try {
        Ensure-ScenarioDaemonState -ExePath $routeWardExePath -WorkDir $resolvedBinDir -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs -RequireInterceptionRunning $true

        $ipv6LocalUlaV = "fd00:7277:2026::10"
        $ipv6TargetIpV = "2001:db8:7277::10"
        $ipv6RouteCtxV = $null
        try {
            $ipv6RouteCtxV = Initialize-TransientWinDivertIpv6Route -LocalUlaIp $ipv6LocalUlaV -TargetRemoteIp $ipv6TargetIpV
            if ($null -eq $ipv6RouteCtxV) {
                throw "No connected non-loopback network adapter found to attach transient IPv6 route for Scenario (v)."
            }

            # Intentional fixed wait: lets the transient IPv6 route and neighbor entry settle (no observable signal beyond the Preferred address state already awaited).
            Start-Sleep -Milliseconds 200
            $dnsV6UdpA = Invoke-Ipv6DnsWireQuery -TargetIp $ipv6TargetIpV -QueryName "example.com" -Port 53 -Protocol "udp" -QType 1 -TimeoutMs 3500 -LocalIp $ipv6LocalUlaV
            $dnsV6UdpAaaa = Invoke-Ipv6DnsWireQuery -TargetIp $ipv6TargetIpV -QueryName "example.com" -Port 53 -Protocol "udp" -QType 28 -TimeoutMs 3500 -LocalIp $ipv6LocalUlaV
            $dnsV6TcpA = Invoke-Ipv6DnsWireQuery -TargetIp $ipv6TargetIpV -QueryName "example.com" -Port 53 -Protocol "tcp" -QType 1 -TimeoutMs 4000 -LocalIp $ipv6LocalUlaV

            # Probe IPv6 DoT port 853 while blockEncryptedDnsBypass is active (default profile policy)
            $dotProbeUdp = New-Object System.Net.Sockets.UdpClient((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($ipv6LocalUlaV), 0)))
            try {
                $dotBytes = [System.Text.Encoding]::ASCII.GetBytes("DOT_BYPASS_PROBE")
                $null = $dotProbeUdp.Send($dotBytes, $dotBytes.Length, $ipv6TargetIpV, 853)
            } finally {
                $dotProbeUdp.Close()
            }
            $null = Wait-ForCtlEntry -ExePath $routeWardExePath -CtlCommand "connections" -Description "blocked IPv6 DoT 853 connection" -Match {
                param($c)
                [int]$c.targetPort -eq 853 -and $c.targetHost -ieq $ipv6TargetIpV -and $c.matchedRule -eq "SecurityPolicy:blockEncryptedDnsBypass" -and $c.status -eq "blocked"
            }

            $connsResV = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("connections") -Label "Scenario-v-connections"
            $connsListV = ConvertFrom-CtlResponseJson `
                -RawJson $connsResV.RawText `
                -Context "Scenario-v-connections" `
                -ExpectResultArray `
                -RequiredArrayElementProperties @("targetHost", "targetPort", "protocol", "matchedRule", "status")

            $sawDotV6Blocked = $false
            foreach ($c in $connsListV) {
                if ([int]$c.targetPort -eq 853 -and $c.targetHost -ieq $ipv6TargetIpV -and $c.matchedRule -eq "SecurityPolicy:blockEncryptedDnsBypass" -and $c.status -eq "blocked") {
                    $sawDotV6Blocked = $true
                    break
                }
            }

            $udpAFakeIp = if ($dnsV6UdpA.AnswerIps.Count -ge 1) { [string]$dnsV6UdpA.AnswerIps[0] } else { "" }
            $tcpAFakeIp = if ($dnsV6TcpA.AnswerIps.Count -ge 1) { [string]$dnsV6TcpA.AnswerIps[0] } else { "" }
            $udpAValid = $dnsV6UdpA.ReplyReceived -and $dnsV6UdpA.RCode -eq 0 -and (Test-IpInFakePool -IpAddressString $udpAFakeIp -PoolCidr $FakeIpCidr)
            $udpAaaaValid = $dnsV6UdpAaaa.ReplyReceived -and $dnsV6UdpAaaa.RCode -eq 0 -and $dnsV6UdpAaaa.AnswerCount -eq 0
            $tcpAValid = $dnsV6TcpA.ReplyReceived -and $dnsV6TcpA.RCode -eq 0 -and (Test-IpInFakePool -IpAddressString $tcpAFakeIp -PoolCidr $FakeIpCidr)

            if ($udpAValid -and $udpAaaaValid -and $tcpAValid -and $sawDotV6Blocked) {
                Record-ScenarioResult -Id "v" -Status "PASS" -Title "IPv6 DNS (port 53 UDP/TCP Fake-IP) & gated IPv6 DoT (port 853)" -Detail "IPv6 UDP 53 A->$udpAFakeIp, UDP 53 AAAA->NODATA (rcode=0, ancount=0), TCP 53 A->$tcpAFakeIp, IPv6 DoT 853 blocked=true (SecurityPolicy:blockEncryptedDnsBypass)"
            } else {
                Record-ScenarioResult -Id "v" -Status "FAIL" -Title "IPv6 DNS (port 53 UDP/TCP Fake-IP) & gated IPv6 DoT (port 853)" -Detail "udpA=$udpAValid ('$udpAFakeIp', err=$($dnsV6UdpA.ErrorMessage)), udpAAAA=$udpAaaaValid (rcode=$($dnsV6UdpAaaa.RCode), an=$($dnsV6UdpAaaa.AnswerCount), err=$($dnsV6UdpAaaa.ErrorMessage)), tcpA=$tcpAValid ('$tcpAFakeIp', err=$($dnsV6TcpA.ErrorMessage)), dot853Blocked=$sawDotV6Blocked"
            }
        } finally {
            Remove-TransientWinDivertIpv6Route -Context $ipv6RouteCtxV
        }
    } catch {
        Record-ScenarioResult -Id "v" -Status "FAIL" -Title "IPv6 DNS (port 53 UDP/TCP Fake-IP) & gated IPv6 DoT (port 853)" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (w) [Order 22/26]: IPv6 QUIC (UDP 443) rejected with inbound
    #               ICMPv6 Port Unreachable (Type 1, Code 4) via WinDivert
    # -----------------------------------------------------------------------
    try {
        Ensure-ScenarioDaemonState -ExePath $routeWardExePath -WorkDir $resolvedBinDir -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs -RequireInterceptionRunning $true

        $ipv6LocalUlaW = "fd00:7277:2026::10"
        $ipv6TargetIpW = "2001:db8:7277::10"
        $ipv6RouteCtxW = $null
        try {
            $ipv6RouteCtxW = Initialize-TransientWinDivertIpv6Route -LocalUlaIp $ipv6LocalUlaW -TargetRemoteIp $ipv6TargetIpW
            if ($null -eq $ipv6RouteCtxW) {
                throw "No connected non-loopback network adapter found to attach transient IPv6 route for Scenario (w)."
            }

            # Intentional fixed wait: lets the transient IPv6 route and neighbor entry settle (no observable signal beyond the Preferred address state already awaited).
            Start-Sleep -Milliseconds 150
            $quicProbeV6 = Invoke-QuicUdp443Probe -TargetIp $ipv6TargetIpW -Port 443 -ReceiveTimeoutMs 1500 -LocalIp $ipv6LocalUlaW
            $null = Wait-ForCtlEntry -ExePath $routeWardExePath -CtlCommand "connections" -Description "blocked IPv6 QUIC UDP 443 connection" -Match {
                param($c)
                [int]$c.targetPort -eq 443 -and $c.protocol -eq "udp" -and $c.targetHost -ieq $ipv6TargetIpW -and $c.matchedRule -eq "SecurityPolicy:blockQuicUdp443" -and $c.status -eq "blocked"
            }
            $null = Wait-ForCtlEntry -ExePath $routeWardExePath -CtlCommand "logs" -Description "IPv6 QUIC rejection WARN log" -Match {
                param($l)
                $l.level -eq "WARN" -and ([string]$l.message).Contains("Rejected QUIC (UDP port 443) with ICMPv6 Port Unreachable") -and ([string]$l.message).Contains($ipv6TargetIpW)
            }

            $connsResW = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("connections") -Label "Scenario-w-connections"
            $connsListW = ConvertFrom-CtlResponseJson `
                -RawJson $connsResW.RawText `
                -Context "Scenario-w-connections" `
                -ExpectResultArray `
                -RequiredArrayElementProperties @("targetHost", "targetPort", "protocol", "matchedRule", "status")

            $logsResW = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("logs") -Label "Scenario-w-logs"
            $logsListW = ConvertFrom-CtlResponseJson `
                -RawJson $logsResW.RawText `
                -Context "Scenario-w-logs" `
                -ExpectResultArray `
                -RequiredArrayElementProperties @("level", "component", "message")

            $sawQuicV6BlockedConn = $false
            foreach ($c in $connsListW) {
                if ([int]$c.targetPort -eq 443 -and $c.protocol -eq "udp" -and $c.targetHost -ieq $ipv6TargetIpW -and $c.matchedRule -eq "SecurityPolicy:blockQuicUdp443" -and $c.status -eq "blocked") {
                    $sawQuicV6BlockedConn = $true
                    break
                }
            }

            $sawQuicV6WarnLog = $false
            foreach ($l in $logsListW) {
                $msgW = [string]$l.message
                if ($l.level -eq "WARN" -and $msgW.Contains("Rejected QUIC (UDP port 443) with ICMPv6 Port Unreachable") -and $msgW.Contains($ipv6TargetIpW)) {
                    $sawQuicV6WarnLog = $true
                    break
                }
            }

            if ($sawQuicV6BlockedConn -and $sawQuicV6WarnLog -and (-not $quicProbeV6.UnexpectedReplyReceived)) {
                Record-ScenarioResult -Id "w" -Status "PASS" -Title "IPv6 QUIC (UDP 443) rejected with ICMPv6 Port Unreachable" -Detail "IPv6 UDP 443 toward [${ipv6TargetIpW}]:443 blocked=true, $(Get-FastRejectionNote -Probe $quicProbeV6) (clientError=$($quicProbeV6.SocketErrorCode), measuredDelay=$($quicProbeV6.DelayMs) ms, matchedRule=SecurityPolicy:blockQuicUdp443, status=blocked)"
            } else {
                Record-ScenarioResult -Id "w" -Status "FAIL" -Title "IPv6 QUIC (UDP 443) rejected with ICMPv6 Port Unreachable" -Detail "blocked=$sawQuicV6BlockedConn, sawWarnLog=$sawQuicV6WarnLog, unexpectedReply=$($quicProbeV6.UnexpectedReplyReceived), fastRejection=$($quicProbeV6.FastRejection), clientError=$($quicProbeV6.SocketErrorCode), delayMs=$($quicProbeV6.DelayMs)"
            }
        } finally {
            Remove-TransientWinDivertIpv6Route -Context $ipv6RouteCtxW
        }
    } catch {
        Record-ScenarioResult -Id "w" -Status "FAIL" -Title "IPv6 QUIC (UDP 443) rejected with ICMPv6 Port Unreachable" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (x) [Order 23/26]: Direct IPv6 UDP flow attributed to process in
    #               ctl connections / ctl logs
    # -----------------------------------------------------------------------
    try {
        Ensure-ScenarioDaemonState -ExePath $routeWardExePath -WorkDir $resolvedBinDir -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs -RequireInterceptionRunning $true

        $ipv6LocalUlaX = "fd00:7277:2026::10"
        $ipv6TargetIpX = "2001:db8:7277::10"
        $ipv6DirectPortX = $NtpPort
        $ipv6RouteCtxX = $null
        try {
            $ipv6RouteCtxX = Initialize-TransientWinDivertIpv6Route -LocalUlaIp $ipv6LocalUlaX -TargetRemoteIp $ipv6TargetIpX
            if ($null -eq $ipv6RouteCtxX) {
                throw "No connected non-loopback network adapter found to attach transient IPv6 route for Scenario (x)."
            }

            # Intentional fixed wait: lets the transient IPv6 route and neighbor entry settle (no observable signal beyond the Preferred address state already awaited).
            Start-Sleep -Milliseconds 150
            $null = Invoke-Ipv6UdpNtpExchange -TargetIp $ipv6TargetIpX -Port $ipv6DirectPortX -ReceiveTimeoutMs 400 -LocalIp $ipv6LocalUlaX

            $matchedDirectV6Conn = $null
            $sawDirectV6Log = $false
            $pollSwX = [System.Diagnostics.Stopwatch]::StartNew()
            while ($pollSwX.ElapsedMilliseconds -lt 3000) {
                Start-Sleep -Milliseconds 300
                $connsResX = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("connections") -Label "Scenario-x-connections"
                $connsListX = ConvertFrom-CtlResponseJson `
                    -RawJson $connsResX.RawText `
                    -Context "Scenario-x-connections" `
                    -ExpectResultArray `
                    -RequiredArrayElementProperties @("processName", "targetHost", "targetPort", "protocol", "matchedRule", "routeLabel", "status")

                foreach ($c in $connsListX) {
                    if ([int]$c.targetPort -eq $ipv6DirectPortX -and $c.protocol -eq "udp" -and $c.targetHost -ieq $ipv6TargetIpX -and $c.routeLabel -eq "DIRECT" -and ($script:ExpectedUdpHostProcesses -contains $c.processName)) {
                        $matchedDirectV6Conn = $c
                        break
                    }
                }

                $logsResX = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("logs") -Label "Scenario-x-logs"
                $logsListX = ConvertFrom-CtlResponseJson `
                    -RawJson $logsResX.RawText `
                    -Context "Scenario-x-logs" `
                    -ExpectResultArray `
                    -RequiredArrayElementProperties @("level", "component", "message")

                foreach ($l in $logsListX) {
                    $msgX = [string]$l.message
                    if (($l.component -eq "TransparentRelay" -or $l.component -eq "WinDivert" -or $l.component -eq "Interceptor") -and ($msgX.Contains("Routed UDP") -or $msgX.Contains("Routed IPv6 UDP")) -and $msgX.Contains($ipv6TargetIpX) -and $msgX.Contains("DIRECT")) {
                        $sawDirectV6Log = $true
                        break
                    }
                }
                if ($null -ne $matchedDirectV6Conn -and $sawDirectV6Log) {
                    break
                }
            }

            if ($null -ne $matchedDirectV6Conn -and $sawDirectV6Log) {
                Record-ScenarioResult -Id "x" -Status "PASS" -Title "Direct IPv6 UDP flow attributed to process in ctl connections" -Detail "Attributed IPv6 DIRECT UDP flow toward [${ipv6TargetIpX}]:$ipv6DirectPortX to processName=$($matchedDirectV6Conn.processName), routeLabel=DIRECT, matchedRule=$($matchedDirectV6Conn.matchedRule)"
            } else {
                Record-ScenarioResult -Id "x" -Status "FAIL" -Title "Direct IPv6 UDP flow attributed to process in ctl connections" -Detail "hasAttributedConn=$($null -ne $matchedDirectV6Conn), sawDirectV6Log=$sawDirectV6Log for [${ipv6TargetIpX}]:$ipv6DirectPortX"
            }
        } finally {
            Remove-TransientWinDivertIpv6Route -Context $ipv6RouteCtxX
        }
    } catch {
        Record-ScenarioResult -Id "x" -Status "FAIL" -Title "Direct IPv6 UDP flow attributed to process in ctl connections" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (y) [Order 24/26]: Windows SCM service status command &
    #               routeward-desktop.exe --smoke-ipc against live daemon
    # -----------------------------------------------------------------------
    try {
        Ensure-ScenarioDaemonState -ExePath $routeWardExePath -WorkDir $resolvedBinDir -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs -RequireInterceptionRunning $true

        $svcStatusOutput = & $routeWardExePath "service" "status" 2>&1
        $svcExitCode = $LASTEXITCODE
        $svcRaw = ($svcStatusOutput | Out-String).Trim()
        if ($svcExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($svcRaw)) {
            throw "routeward service status failed (exit=$svcExitCode): $svcRaw"
        }
        $svcObj = $svcRaw | ConvertFrom-Json
        if ($svcObj.serviceName -ne "RouteWard" -or [string]::IsNullOrWhiteSpace([string]$svcObj.state)) {
            throw "Unexpected routeward service status payload: $svcRaw"
        }

        $desktopExePath = Join-Path $resolvedBinDir "routeward-desktop.exe"
        if (-not (Test-Path -LiteralPath $desktopExePath)) {
            throw "Missing routeward-desktop.exe in '$resolvedBinDir' for --smoke-ipc check."
        }
        $smokeId = [Guid]::NewGuid().ToString("N")
        $smokeOutFile = Join-Path ([System.IO.Path]::GetTempPath()) "routeward_smoke_${smokeId}_out.txt"
        $smokeErrFile = Join-Path ([System.IO.Path]::GetTempPath()) "routeward_smoke_${smokeId}_err.txt"
        try {
            $smokeProc = Start-Process -FilePath $desktopExePath -ArgumentList "--smoke-ipc" -Wait -PassThru -RedirectStandardOutput $smokeOutFile -RedirectStandardError $smokeErrFile
            $smokeExitCode = $smokeProc.ExitCode
            $smokeRawStdout = if (Test-Path -LiteralPath $smokeOutFile) { Get-Content -LiteralPath $smokeOutFile -Raw -Encoding UTF8 } else { $null }
            $smokeRawStderr = if (Test-Path -LiteralPath $smokeErrFile) { Get-Content -LiteralPath $smokeErrFile -Raw -Encoding UTF8 } else { $null }
            $smokeStdout = if ($null -ne $smokeRawStdout) { $smokeRawStdout.Trim() } else { "" }
            $smokeStderr = if ($null -ne $smokeRawStderr) { $smokeRawStderr.Trim() } else { "" }
            if ($smokeExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($smokeStdout)) {
                throw "routeward-desktop.exe --smoke-ipc failed (exit=$smokeExitCode): stdout='$smokeStdout' stderr='$smokeStderr'"
            }
            $smokeObj = $smokeStdout | ConvertFrom-Json
            if ($smokeObj.daemonConnected -ne $true -or $smokeObj.elevatedPrivileges -ne $true) {
                throw "Unexpected --smoke-ipc JSON payload: $smokeStdout"
            }
        } finally {
            Remove-Item -LiteralPath $smokeOutFile, $smokeErrFile -Force -ErrorAction SilentlyContinue
        }

        Record-ScenarioResult -Id "y" -Status "PASS" -Title "Windows SCM service status & routeward-desktop --smoke-ipc" -Detail "serviceName=$($svcObj.serviceName) state=$($svcObj.state); routeward-desktop --smoke-ipc daemonConnected=true, running=$($smokeObj.running), elevated=$($smokeObj.elevatedPrivileges)"
    } catch {
        Record-ScenarioResult -Id "y" -Status "FAIL" -Title "Windows SCM service status & routeward-desktop --smoke-ipc" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (z) [Order 25/26]: A process listed in dnsConfig.dnsServerProcesses
    #               (nslookup.exe here, standing in for a DNS server) gets a real DNS answer
    #               instead of a Fake-IP one; an optional check on the Windows DNS Server
    #               service (dns.exe) runs when that service is Running.
    # -----------------------------------------------------------------------
    $profileBeforeZ = $null
    $profileOriginalJsonZ = $null
    $profileReplacedZ = $false
    $tempProfileFileZ = $null
    try {
        Ensure-ScenarioDaemonState -ExePath $routeWardExePath -WorkDir $resolvedBinDir -FullPipePath $PipeName -TimeoutMs $PipeReadyTimeoutMs -IntervalMs $PollIntervalMs -RequireInterceptionRunning $true
        $dnsServerZ = Get-MachineConfiguredIpv4DnsServer
        if ([string]::IsNullOrWhiteSpace($dnsServerZ)) {
            $dnsServerZ = $ExternalDnsServer
        }
        $nslookupPathZ = Join-Path $env:SystemRoot "System32\nslookup.exe"
        if (-not (Test-Path -LiteralPath $nslookupPathZ)) {
            Record-ScenarioResult -Id "z" -Status "SKIP" -Title "DNS server processes get real DNS answers instead of Fake-IP" -Detail "nslookup.exe not found at '$nslookupPathZ'"
        } else {
            $profileBeforeZ = Get-NormalizedProfileSnapshotJson -ExePath $routeWardExePath -Label "Scenario-z-state-before"
            $stateResZ = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("state") -Label "Scenario-z-state"
            $stateObjZ = ConvertFrom-CtlResponseJson `
                -RawJson $stateResZ.RawText `
                -Context "Scenario-z-state" `
                -RequiredResultProperties @("diagnostics", "profile")
            $profileOriginalJsonZ = ($stateObjZ.profile | ConvertTo-Json -Depth 10 -Compress)
            try {
                $profileZ = $profileOriginalJsonZ | ConvertFrom-Json
                # A typed string[] property serializes as a JSON array on Windows PowerShell 5.1 and
                # PowerShell 7 alike; the JSON text is checked because a bare string would be refused
                # by the daemon.
                $profileZ.dnsConfig | Add-Member -NotePropertyName "dnsServerProcesses" -NotePropertyValue ([string[]]@($nslookupPathZ)) -Force
                $profileJsonZ = $profileZ | ConvertTo-Json -Depth 10 -Compress
                if ($profileJsonZ -notmatch '"dnsServerProcesses"\s*:\s*\[') {
                    throw "Scenario (z) fixture error: dnsServerProcesses was not serialized as a JSON array."
                }
                $tempProfileFileZ = Write-Utf8NoBomJsonTempFile -JsonText $profileJsonZ
                $replaceResZ = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("replace-profile", "--json-file", $tempProfileFileZ) -Label "Scenario-z-replace-profile"
                if ($replaceResZ.ExitCode -ne 0) {
                    throw "ctl replace-profile with dnsServerProcesses failed (exit=$($replaceResZ.ExitCode)): $($replaceResZ.RawText)"
                }
                $profileReplacedZ = $true
                # Intentional fixed wait: the profile apply has no observable completion signal; the bounded retry loop below absorbs any remaining lag.
                Start-Sleep -Milliseconds $PollIntervalMs

                # The exemption is applied by a helper thread that may trail the first query: retry
                # while the answer is missing or still inside the Fake-IP pool, a bounded number of
                # times with a short wait.
                $maxAttemptsZ = 5
                $retryWaitMsZ = 1000
                $nslookupIpsZ = @()
                $nslookupTextZ = ""
                $anyFakeZ = $false
                for ($attemptZ = 1; $attemptZ -le $maxAttemptsZ; $attemptZ++) {
                    $prevEapZ = $ErrorActionPreference
                    $ErrorActionPreference = "Continue"
                    try {
                        $nslookupTextZ = (& $nslookupPathZ "-type=A" "-timeout=5" $PublicDnsTestDomain $dnsServerZ 2>&1 | ForEach-Object { $_.ToString() } | Out-String)
                    } finally {
                        $ErrorActionPreference = $prevEapZ
                    }
                    $nslookupIpsZ = @(Get-NslookupAnswerAddresses -OutputText $nslookupTextZ)
                    $anyFakeZ = $false
                    foreach ($ipZ in $nslookupIpsZ) {
                        if (Test-IpInFakePool -IpAddressString $ipZ -PoolCidr $FakeIpCidr) {
                            $anyFakeZ = $true
                        }
                    }
                    if ($nslookupIpsZ.Count -gt 0 -and (-not $anyFakeZ)) {
                        break
                    }
                    if ($attemptZ -lt $maxAttemptsZ) {
                        Start-Sleep -Milliseconds $retryWaitMsZ
                    }
                }

                $logsResZ = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("logs") -Label "Scenario-z-logs"
                $logsListZ = ConvertFrom-CtlResponseJson `
                    -RawJson $logsResZ.RawText `
                    -Context "Scenario-z-logs" `
                    -ExpectResultArray `
                    -RequiredArrayElementProperties @("level", "component", "message")
                $sawExemptionLogZ = $false
                foreach ($logZ in $logsListZ) {
                    if ([string]$logZ.message -match 'Exempting DNS server process nslookup\.exe \(PID \d+\) from Fake-IP') {
                        $sawExemptionLogZ = $true
                        break
                    }
                }

                # Optional: the Windows DNS Server role (dns.exe) recursing for a public name.
                $dnsExeDetailZ = "dns.exe check skipped (DNS Server service not running)"
                $dnsExeFailZ = $false
                $dnsServiceZ = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
                if ($null -ne $dnsServiceZ -and $dnsServiceZ.Status -eq "Running" -and -not (Get-Command -Name "Clear-DnsServerCache" -ErrorAction SilentlyContinue)) {
                    $dnsExeDetailZ = "dns.exe check SKIP (Clear-DnsServerCache cmdlet not available)"
                } elseif ($null -ne $dnsServiceZ -and $dnsServiceZ.Status -eq "Running") {
                    $null = Clear-DnsServerCache -Force -ErrorAction Stop
                    $dnsExeRecordsZ = @(Resolve-DnsName -Name $PublicDnsTestDomain -Type A -Server "127.0.0.1" -DnsOnly -NoHostsFile -ErrorAction Stop | Where-Object { $null -ne $_.IPAddress })
                    $dnsExeIpsZ = @($dnsExeRecordsZ | ForEach-Object { [string]$_.IPAddress })
                    $dnsExeFakeZ = $false
                    foreach ($ipZ in $dnsExeIpsZ) {
                        if (Test-IpInFakePool -IpAddressString $ipZ -PoolCidr $FakeIpCidr) {
                            $dnsExeFakeZ = $true
                        }
                    }
                    $dnsExeFailZ = ($dnsExeIpsZ.Count -eq 0) -or $dnsExeFakeZ
                    $dnsExeDetailZ = "dns.exe resolved $PublicDnsTestDomain to [$($dnsExeIpsZ -join ', ')] (inFakePool=$dnsExeFakeZ)"
                }

                if ($nslookupIpsZ.Count -gt 0 -and (-not $anyFakeZ) -and $sawExemptionLogZ -and (-not $dnsExeFailZ)) {
                    Record-ScenarioResult -Id "z" -Status "PASS" -Title "DNS server processes get real DNS answers instead of Fake-IP" -Detail "nslookup.exe asked $dnsServerZ for $PublicDnsTestDomain and got [$($nslookupIpsZ -join ', ')] (outside $FakeIpCidr), exemption logged; $dnsExeDetailZ"
                } else {
                    Record-ScenarioResult -Id "z" -Status "FAIL" -Title "DNS server processes get real DNS answers instead of Fake-IP" -Detail "nslookupIps=[$($nslookupIpsZ -join ', ')], anyInFakePool=$anyFakeZ, exemptionLogged=$sawExemptionLogZ; $dnsExeDetailZ; nslookup output: $($nslookupTextZ.Trim())"
                }
            } finally {
                if ($profileReplacedZ) {
                    $restoreFileZ = Write-Utf8NoBomJsonTempFile -JsonText $profileOriginalJsonZ
                    try {
                        $null = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @("replace-profile", "--json-file", $restoreFileZ) -Label "Scenario-z-restore-profile"
                    } finally {
                        Remove-Item -LiteralPath $restoreFileZ -Force -ErrorAction SilentlyContinue
                    }
                }
                if ($null -ne $tempProfileFileZ) {
                    Remove-Item -LiteralPath $tempProfileFileZ -Force -ErrorAction SilentlyContinue
                }
                $profileAfterZ = Get-NormalizedProfileSnapshotJson -ExePath $routeWardExePath -Label "Scenario-z-state-after"
                if ($profileBeforeZ -ne $profileAfterZ) {
                    throw "Scenario (z) cleanup check failed: profile state after cleanup does not match profile state before Scenario (z)."
                }
            }
        }
    } catch {
        Record-ScenarioResult -Id "z" -Status "FAIL" -Title "DNS server processes get real DNS answers instead of Fake-IP" -Detail $_.Exception.Message
    }

    # -----------------------------------------------------------------------
    # Scenario (j) [Order 26/26 - Executed LAST]: Kill-Switch (killSwitchEnabled=true) -
    #               SOCKS5 proxy stopped during test, curl.exe matched by Proxy rule
    #               fails without falling back to Direct, and ctl connections reports Blocked
    # -----------------------------------------------------------------------
    try {
        if (Test-ScenarioSocks5Prerequisite -Id "j") {
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
                    $null = Wait-ForCtlEntry -ExePath $routeWardExePath -CtlCommand "connections" -Description "Kill-Switch blocked curl.exe connection" -Match {
                        param($c)
                        $c.processName -ieq "curl.exe" -and $c.matchedRule -eq $ExpectedProxyRuleName -and $c.status -eq "blocked" -and $c.routeLabel -eq "BLOCKED"
                    }
                    $null = Wait-ForCtlEntry -ExePath $routeWardExePath -CtlCommand "logs" -Description "Kill-Switch WARN log" -Match {
                        param($l)
                        $l.level -eq "WARN" -and ([string]$l.message).Contains("Kill-Switch blocked connection")
                    }

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
                        $noticeMsg = "SOCKS5 listener on ${Socks5Host}:${Socks5Port} (original PID=$($socksListenerInfo.Pid)) was stopped for Scenario (j) (executed last) and requires manual restart before the next test run."
                        $auditNotes.Add("NOTICE: $noticeMsg")
                        Write-Host "[NOTICE] $noticeMsg" -ForegroundColor Yellow
                    }
                }
            }
        }
    } catch {
        Record-ScenarioResult -Id "j" -Status "FAIL" -Title "Kill-Switch blocks curl when SOCKS5 proxy is stopped" -Detail $_.Exception.Message
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
    # Teardown of the provisioned proxy fixture while the daemon may still be reachable.
    foreach ($fixtureTeardown in @(
            @{ Added = $fixtureRuleAdded; Cmd = "remove-rule"; Id = $ProvisionedRuleId; Label = "Fixture-remove-rule" },
            @{ Added = $fixtureProxyAdded; Cmd = "remove-proxy"; Id = $ProvisionedProxyId; Label = "Fixture-remove-proxy" })) {
        if ($fixtureTeardown.Added) {
            try {
                $null = Invoke-RouteWardCtl -ExePath $routeWardExePath -CtlArgs @($fixtureTeardown.Cmd, "--id", $fixtureTeardown.Id) -Label $fixtureTeardown.Label
            } catch {
                $auditNotes.Add("WARNING: $($fixtureTeardown.Label) failed: $($_.Exception.Message)")
            }
        }
    }

    Stop-AllTrackedUdpTestServers -IncludePrimarySocks5
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
$reportLines.Add("Exec Order : $executionOrderSummary")
$reportLines.Add("Post-Cleanup Connectivity: $postCleanupCurlStatus")
$reportLines.Add("================================================================================")
$reportLines.Add("")
$reportLines.Add("## 1. Scenario Results")
foreach ($r in $scenarioResults) {
    $reportLines.Add($r.Line)
}

$reportLines.Add("")
$reportLines.Add("## 2. Binary & Driver Inventory")
$binaryTargets = @($routeWardExePath, $desktopExePath, $udpTestServerExePath) + $resolvedWinDivertFiles
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
