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
    [ValidateSet('x64', 'arm64', 'x86')]
    [string]$Arch = 'x64',
    [switch]$IncludeWinDivert,
    [string]$WinDivertDir = 'third_party/windivert/bin',
    [string]$WixPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-WixExecutable {
    param([string]$ExplicitPath)

    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        if (-not (Test-Path -LiteralPath $ExplicitPath)) {
            throw "WiX executable not found at: $ExplicitPath"
        }
        return (Resolve-Path -LiteralPath $ExplicitPath).Path
    }

    $cmd = Get-Command -Name 'wix' -ErrorAction SilentlyContinue
    if ($null -ne $cmd) {
        return $cmd.Source
    }

    $dotnetTool = Join-Path $env:USERPROFILE '.dotnet\tools\wix.exe'
    if (Test-Path -LiteralPath $dotnetTool) {
        return $dotnetTool
    }

    throw 'WiX Toolset CLI (wix.exe) was not found in PATH or %USERPROFILE%\.dotnet\tools.'
}

function ConvertTo-MsiVersion {
    param([string]$DisplayVersion)

    $core = ($DisplayVersion -split '[-+]', 2)[0]
    $parts = $core -split '\.'
    if ($parts.Count -lt 2 -or $parts.Count -gt 4) {
        throw "Unsupported version format for MSI conversion: '$DisplayVersion'"
    }

    $nums = foreach ($part in $parts) {
        $parsed = 0
        if (-not [int]::TryParse($part, [ref]$parsed) -or $parsed -lt 0) {
            throw "Non-numeric version segment '$part' in '$DisplayVersion'"
        }
        $parsed
    }

    # MSI ProductVersion allows Major<=255, Minor<=255, Build<=65535.
    # Map CalVer YYYY.MMDD.PATCH -> (YYYY - 2000).MM.(DD * 100 + PATCH).
    $major = $nums[0]
    $minor = $nums[1]
    $build = if ($nums.Count -ge 3) { $nums[2] } else { 0 }

    if ($major -ge 2000 -and $minor -ge 101 -and $minor -le 1231) {
        $calMajor = $major - 2000
        $calMonth = [int][math]::Floor($minor / 100)
        $calDay = $minor % 100
        $calBuild = ($calDay * 100) + $build
        if ($calMajor -le 255 -and $calMonth -ge 1 -and $calMonth -le 12 -and $calBuild -le 65535) {
            return "$calMajor.$calMonth.$calBuild"
        }
    }

    if ($major -le 255 -and $minor -le 255 -and $build -le 65535) {
        return "$major.$minor.$build"
    }

    throw "Version '$DisplayVersion' exceeds MSI bounds (Major<=255, Minor<=255, Build<=65535)."
}

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

$msiVersion = ConvertTo-MsiVersion -DisplayVersion $Version
$wixExe = Resolve-WixExecutable -ExplicitPath $WixPath

$cliExe = Join-Path $resolvedTargetDir 'routeward.exe'
$desktopExe = Join-Path $resolvedTargetDir 'routeward-desktop.exe'
$iconPath = Join-Path $repoRoot 'assets\branding\routeward.ico'
$wxsPath = Join-Path $PSScriptRoot 'RouteWard.wxs'

foreach ($required in @($cliExe, $desktopExe, $iconPath, $wxsPath)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Required build input not found: $required"
    }
}

New-Item -ItemType Directory -Path $resolvedOutDir -Force | Out-Null
$stageDir = Join-Path ([System.IO.Path]::GetTempPath()) ("routeward-msi-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stageDir -Force | Out-Null

try {
    Copy-Item -LiteralPath $cliExe -Destination (Join-Path $stageDir 'routeward.exe')
    Copy-Item -LiteralPath $desktopExe -Destination (Join-Path $stageDir 'routeward-desktop.exe')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'install-service.ps1') -Destination (Join-Path $stageDir 'install-service.ps1')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'tools\fetch-windivert.ps1') -Destination (Join-Path $stageDir 'fetch-windivert.ps1')

    foreach ($docName in @('LICENSE', 'NOTICE')) {
        $docPath = Join-Path $repoRoot $docName
        if (Test-Path -LiteralPath $docPath) {
            Copy-Item -LiteralPath $docPath -Destination (Join-Path $stageDir $docName)
        }
    }

    $includeWinDivertFlag = 'no'
    $winDivertSysName = if ($Arch -eq 'x86') { 'WinDivert32.sys' } else { 'WinDivert64.sys' }
    if ($IncludeWinDivert) {
        $wdDll = Join-Path $resolvedWinDivertDir 'WinDivert.dll'
        $wdSys = Join-Path $resolvedWinDivertDir $winDivertSysName
        if (-not (Test-Path -LiteralPath $wdDll) -or -not (Test-Path -LiteralPath $wdSys)) {
            throw "WinDivert binaries ($winDivertSysName) not found in: $resolvedWinDivertDir"
        }
        Copy-Item -LiteralPath $wdDll -Destination (Join-Path $stageDir 'WinDivert.dll')
        Copy-Item -LiteralPath $wdSys -Destination (Join-Path $stageDir $winDivertSysName)
        $includeWinDivertFlag = 'yes'
    }

    $msiName = "routeward-${Version}-windows-${Arch}.msi"
    $msiPath = Join-Path $resolvedOutDir $msiName
    if (Test-Path -LiteralPath $msiPath) {
        Remove-Item -LiteralPath $msiPath -Force
    }

    $wixArgs = @(
        'build',
        $wxsPath,
        '-arch', $Arch,
        '-d', "MsiVersion=$msiVersion",
        '-d', "DisplayVersion=$Version",
        '-d', "StageDir=$stageDir",
        '-d', "IconPath=$iconPath",
        '-d', "IncludeWinDivert=$includeWinDivertFlag",
        '-d', "WinDivertSysName=$winDivertSysName",
        '-pdbtype', 'none',
        '-o', $msiPath
    )

    & $wixExe @wixArgs
    if ($LASTEXITCODE -ne 0) {
        throw "WiX MSI build failed with exit code $LASTEXITCODE"
    }

    $hash = (Get-FileHash -LiteralPath $msiPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath "${msiPath}.sha256" -Value "$hash  $msiName" -Encoding ascii
    Write-Output "Built $msiPath (MSI ProductVersion $msiVersion)"
}
finally {
    if (Test-Path -LiteralPath $stageDir) {
        Remove-Item -LiteralPath $stageDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
