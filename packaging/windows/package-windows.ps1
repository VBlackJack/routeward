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
    [switch]$SkipDesktop
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

    foreach ($docName in @('LICENSE', 'NOTICE')) {
        $docPath = Join-Path $repoRoot $docName
        if (Test-Path -LiteralPath $docPath) {
            Copy-Item -LiteralPath $docPath -Destination (Join-Path $stageDir $docName)
        }
    }

    $zipName = "${bundleName}.zip"
    $zipPath = Join-Path $resolvedOutDir $zipName
    if (Test-Path -LiteralPath $zipPath) {
        Remove-Item -LiteralPath $zipPath -Force
    }
    Compress-Archive -Path (Join-Path $stageDir '*') -DestinationPath $zipPath -CompressionLevel Optimal

    $hash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath "${zipPath}.sha256" -Value "$hash  $zipName" -Encoding ascii
    Write-Output "Built $zipPath"
}
finally {
    if (Test-Path -LiteralPath $stageParent) {
        Remove-Item -LiteralPath $stageParent -Recurse -Force -ErrorAction SilentlyContinue
    }
}
