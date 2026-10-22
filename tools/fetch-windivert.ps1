<#
.SYNOPSIS
    Downloads, verifies (SHA-256), and extracts the official WinDivert 2.2.2-A runtime binaries.
.DESCRIPTION
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
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$DownloadUrl = 'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$ExpectedSha256 = '63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15',

    [Parameter(Mandatory = $false)]
    [string]$OutputDirectory = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $leafName = Split-Path -Path $PSScriptRoot -Leaf
    if ($leafName -ieq 'tools') {
        $OutputDirectory = Join-Path -Path $PSScriptRoot -ChildPath '..\third_party\windivert\bin'
    } else {
        $OutputDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'third_party\windivert\bin'
    }
}

$resolvedOutputDir = [System.IO.Path]::GetFullPath($OutputDirectory)
$tempZipPath = Join-Path -Path $resolvedOutputDir -ChildPath 'WinDivert-2.2.2-A.zip'
$tempExtractDir = Join-Path -Path $resolvedOutputDir -ChildPath '_extract_tmp'

if ($PSCmdlet.ShouldProcess($resolvedOutputDir, "Download WinDivert 2.2.2-A from $DownloadUrl and extract x64 binaries")) {
    if (-not (Test-Path -LiteralPath $resolvedOutputDir)) {
        New-Item -ItemType Directory -Path $resolvedOutputDir -Force | Out-Null
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    Write-Output "Downloading WinDivert archive from $DownloadUrl ..."
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $tempZipPath -UseBasicParsing

    $hashResult = Get-FileHash -Path $tempZipPath -Algorithm SHA256
    $actualHash = $hashResult.Hash.ToLowerInvariant()
    $expectedHashNormalized = $ExpectedSha256.ToLowerInvariant()

    if ($actualHash -ne $expectedHashNormalized) {
        Remove-Item -LiteralPath $tempZipPath -Force -ErrorAction SilentlyContinue
        throw "SHA-256 verification failed for $tempZipPath. Expected: $expectedHashNormalized, Actual: $actualHash"
    }

    Write-Output "SHA-256 verified ($actualHash)."

    if (Test-Path -LiteralPath $tempExtractDir) {
        Remove-Item -LiteralPath $tempExtractDir -Recurse -Force
    }

    Expand-Archive -LiteralPath $tempZipPath -DestinationPath $tempExtractDir -Force

    $archSubdir = Join-Path -Path $tempExtractDir -ChildPath 'WinDivert-2.2.2-A\x64'
    $dllSource = Join-Path -Path $archSubdir -ChildPath 'WinDivert.dll'
    $sysSource = Join-Path -Path $archSubdir -ChildPath 'WinDivert64.sys'

    if (-not (Test-Path -LiteralPath $dllSource) -or -not (Test-Path -LiteralPath $sysSource)) {
        throw "Expected x64 binaries (WinDivert.dll, WinDivert64.sys) were not found in archive structure."
    }

    Copy-Item -LiteralPath $dllSource -Destination (Join-Path -Path $resolvedOutputDir -ChildPath 'WinDivert.dll') -Force
    Copy-Item -LiteralPath $sysSource -Destination (Join-Path -Path $resolvedOutputDir -ChildPath 'WinDivert64.sys') -Force

    Remove-Item -LiteralPath $tempZipPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tempExtractDir -Recurse -Force -ErrorAction SilentlyContinue

    Write-Output "Extracted WinDivert.dll and WinDivert64.sys to $resolvedOutputDir"
}
