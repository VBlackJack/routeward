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
    [string]$TargetDir = 'target/release',
    [string]$OutDir = 'dist',
    [string]$Version = '',
    [string]$Arch = 'x64',
    [switch]$SkipDesktop,
    [switch]$IncludeWinDivert,
    [string]$WinDivertDir = 'third_party/windivert/bin'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$resolvedTargetDir = if ([System.IO.Path]::IsPathRooted($TargetDir)) {
    $TargetDir
} else {
    Join-Path $repoRoot $TargetDir
}
$resolvedOutDir = if ([System.IO.Path]::IsPathRooted($OutDir)) {
    $OutDir
} else {
    Join-Path $repoRoot $OutDir
}
$resolvedWinDivertDir = if ([System.IO.Path]::IsPathRooted($WinDivertDir)) {
    $WinDivertDir
} else {
    Join-Path $repoRoot $WinDivertDir
}

if ([string]::IsNullOrWhiteSpace($Version)) {
    $cargoToml = Get-Content -LiteralPath (Join-Path $repoRoot 'Cargo.toml') -Raw
    if ($cargoToml -match '(?m)^version\s*=\s*"([^"]+)"') {
        $Version = $Matches[1]
    }
}
if ([string]::IsNullOrWhiteSpace($Version)) {
    throw 'Failed to determine package version from Cargo.toml.'
}

$cliExe = Join-Path $resolvedTargetDir 'routeward.exe'
if (-not (Test-Path -LiteralPath $cliExe)) {
    throw "Missing CLI binary: $cliExe"
}

$desktopExe = Join-Path $resolvedTargetDir 'routeward-desktop.exe'
if (-not $SkipDesktop -and -not (Test-Path -LiteralPath $desktopExe)) {
    throw "Missing Desktop binary: $desktopExe"
}

New-Item -ItemType Directory -Path $resolvedOutDir -Force | Out-Null
$stageParent = Join-Path ([System.IO.Path]::GetTempPath()) ("routeward-pkg-" + [Guid]::NewGuid().ToString('N'))
$bundleName = "routeward-${Version}-windows-${Arch}"
$stageDir = Join-Path $stageParent $bundleName
New-Item -ItemType Directory -Path $stageDir -Force | Out-Null

try {
    Copy-Item -LiteralPath $cliExe -Destination (Join-Path $stageDir 'routeward.exe')
    if (-not $SkipDesktop -and (Test-Path -LiteralPath $desktopExe)) {
        Copy-Item -LiteralPath $desktopExe -Destination (Join-Path $stageDir 'routeward-desktop.exe')
    }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'install-service.ps1') -Destination (Join-Path $stageDir 'install-service.ps1')
    # Next to the binaries, the script extracts WinDivert into third_party\windivert\bin, a folder
    # routeward.exe and install-service.ps1 both look in: a ZIP built without WinDivert stays usable.
    Copy-Item -LiteralPath (Join-Path $repoRoot 'tools\fetch-windivert.ps1') -Destination (Join-Path $stageDir 'fetch-windivert.ps1')

    foreach ($docName in @('LICENSE', 'NOTICE')) {
        $docPath = Join-Path $repoRoot $docName
        if (Test-Path -LiteralPath $docPath) {
            Copy-Item -LiteralPath $docPath -Destination (Join-Path $stageDir $docName)
        }
    }

    if ($IncludeWinDivert) {
        # tools/fetch-windivert.ps1 only extracts the x64 binaries; there is no x86 or arm64 driver to embed.
        if ($Arch -ne 'x64') {
            throw "-IncludeWinDivert is only supported for -Arch x64 (requested: $Arch): tools/fetch-windivert.ps1 extracts the x64 WinDivert binaries only."
        }
        # Same unmodified files and notices as the MSI (LGPLv3; source archive attached to each release).
        foreach ($wdFile in @('WinDivert.dll', 'WinDivert64.sys', 'WinDivert-LICENSE.txt', 'WinDivert-README.txt')) {
            $wdSource = Join-Path $resolvedWinDivertDir $wdFile
            if (-not (Test-Path -LiteralPath $wdSource)) {
                throw "WinDivert file '$wdFile' not found in: $resolvedWinDivertDir (run tools/fetch-windivert.ps1)"
            }
            Copy-Item -LiteralPath $wdSource -Destination (Join-Path $stageDir $wdFile)
        }
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'THIRD_PARTY_NOTICES.txt') -Destination (Join-Path $stageDir 'THIRD_PARTY_NOTICES.txt')
    }

    $zipName = "${bundleName}.zip"
    $zipPath = Join-Path $resolvedOutDir $zipName
    if (Test-Path -LiteralPath $zipPath) {
        Remove-Item -LiteralPath $zipPath -Force
    }
    Compress-Archive -Path (Join-Path $stageDir '*') -DestinationPath $zipPath -CompressionLevel Optimal

    $hash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    # LF line ending so `sha256sum -c` accepts the sidecar on every platform.
    [System.IO.File]::WriteAllText("${zipPath}.sha256", "$hash  $zipName`n", [System.Text.Encoding]::ASCII)
    Write-Output "Built $zipPath"
}
finally {
    if (Test-Path -LiteralPath $stageParent) {
        Remove-Item -LiteralPath $stageParent -Recurse -Force -ErrorAction SilentlyContinue
    }
}
