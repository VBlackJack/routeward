# Copyright 2026 Julien Bombled
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$BrandingDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Drawing

$PNG_SIZES = @(16, 20, 24, 32, 40, 48, 64, 128, 256, 512)
$ICO_SIZES = @(16, 20, 24, 32, 40, 48, 64, 256)
$RGBA_SIZES = @(32, 256)
$ICO_HEADER_BYTES = 6
$ICO_DIR_ENTRY_BYTES = 16
$ICO_TYPE_ICON = 1
$ICO_PLANES = 1
$ICO_BIT_COUNT = 32
$ICO_MAX_DIM_BYTE = 256
$EDGE_TIMEOUT_MS = 30000

if ([string]::IsNullOrWhiteSpace($BrandingDir)) {
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $BrandingDir = Join-Path $repoRoot "assets\branding"
}

$svgPath = Join-Path $BrandingDir "routeward-icon.svg"
if (-not (Test-Path -LiteralPath $svgPath)) {
    throw "Source SVG not found at '$svgPath'."
}

function Find-EdgeExecutable {
    $candidates = @(
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe"
    )
    foreach ($candidate in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate)) {
            return $candidate
        }
    }
    throw "Microsoft Edge executable (msedge.exe) not found in standard installation paths."
}

function Convert-SvgToPngViaHeadlessEdge {
    param(
        [Parameter(Mandatory = $true)][string]$EdgeExe,
        [Parameter(Mandatory = $true)][string]$SourceSvgPath,
        [Parameter(Mandatory = $true)][int[]]$Sizes,
        [Parameter(Mandatory = $true)][string]$OutputDirectory
    )

    $svgBytes = [System.IO.File]::ReadAllBytes($SourceSvgPath)
    $svgBase64 = [Convert]::ToBase64String($svgBytes)
    $sizesJson = ($Sizes | ForEach-Object { $_.ToString() }) -join ","

    $tempWorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ("routeward_icon_build_" + [Guid]::NewGuid().ToString("N"))
    $tempProfileDir = Join-Path $tempWorkDir "edge_profile"
    $null = New-Item -ItemType Directory -Path $tempProfileDir -Force
    $tempHtmlPath = Join-Path $tempWorkDir "rasterize.html"

    try {
        $htmlContent = @"
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body>
<img id="src-svg" src="data:image/svg+xml;base64,$svgBase64" />
<pre id="raster-payload"></pre>
<script>
window.addEventListener('load', function () {
  var img = document.getElementById('src-svg');
  var sizes = [$sizesJson];
  var results = {};
  for (var i = 0; i < sizes.length; i++) {
    var sz = sizes[i];
    var canvas = document.createElement('canvas');
    canvas.width = sz;
    canvas.height = sz;
    var ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, sz, sz);
    ctx.drawImage(img, 0, 0, sz, sz);
    results[sz] = canvas.toDataURL('image/png');
  }
  document.getElementById('raster-payload').textContent = 'BEGIN_RASTER_JSON:' + JSON.stringify(results) + ':END_RASTER_JSON';
});
</script>
</body>
</html>
"@
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($tempHtmlPath, $htmlContent, $utf8NoBom)

        $fileUri = ([System.Uri]$tempHtmlPath).AbsoluteUri
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $EdgeExe
        $psi.Arguments = "--headless --disable-gpu --no-first-run --no-default-browser-check --user-data-dir=`"$tempProfileDir`" --dump-dom `"$fileUri`""
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true

        $proc = [System.Diagnostics.Process]::Start($psi)
        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()
        if (-not $proc.WaitForExit($EDGE_TIMEOUT_MS)) {
            $proc.Kill()
            throw "Headless Edge timed out after $EDGE_TIMEOUT_MS ms."
        }

        if ($stdout -notmatch 'BEGIN_RASTER_JSON:(\{.*?\}):END_RASTER_JSON') {
            throw "Headless Edge did not produce expected raster payload. ExitCode=$($proc.ExitCode) Stderr=$stderr"
        }

        $jsonPayload = $Matches[1]
        $parsedMap = ConvertFrom-Json -InputObject $jsonPayload

        foreach ($size in $Sizes) {
            $propName = $size.ToString()
            $dataUrl = $parsedMap.$propName
            if ([string]::IsNullOrWhiteSpace($dataUrl) -or (-not $dataUrl.StartsWith("data:image/png;base64,"))) {
                throw "Missing or invalid PNG data URL for size ${size}px."
            }
            $b64 = $dataUrl.Substring("data:image/png;base64,".Length)
            $pngBytes = [Convert]::FromBase64String($b64)
            $outPngPath = Join-Path $OutputDirectory "routeward-$size.png"
            [System.IO.File]::WriteAllBytes($outPngPath, $pngBytes)

            $bmp = New-Object System.Drawing.Bitmap($outPngPath)
            try {
                if ($bmp.Width -ne $size -or $bmp.Height -ne $size) {
                    throw "Generated PNG '$outPngPath' has dimensions $($bmp.Width)x$($bmp.Height), expected ${size}x${size}."
                }
            } finally {
                $bmp.Dispose()
            }
        }
    } finally {
        if (Test-Path -LiteralPath $tempWorkDir) {
            Remove-Item -LiteralPath $tempWorkDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Write-MultiSizeIco {
    param(
        [Parameter(Mandatory = $true)][int[]]$Sizes,
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$OutputIcoPath
    )

    $pngBuffers = New-Object System.Collections.Generic.List[byte[]]
    foreach ($size in $Sizes) {
        $pngPath = Join-Path $Directory "routeward-$size.png"
        if (-not (Test-Path -LiteralPath $pngPath)) {
            throw "Required PNG '$pngPath' not found for .ico assembly."
        }
        $bytes = [System.IO.File]::ReadAllBytes($pngPath)
        $pngBuffers.Add($bytes)
    }

    $ms = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter($ms)
    try {
        # ICONDIR header (6 bytes)
        $bw.Write([uint16]0)
        $bw.Write([uint16]$ICO_TYPE_ICON)
        $bw.Write([uint16]$Sizes.Count)

        $currentOffset = [uint32]($ICO_HEADER_BYTES + ($Sizes.Count * $ICO_DIR_ENTRY_BYTES))

        for ($i = 0; $i -lt $Sizes.Count; $i++) {
            $dim = $Sizes[$i]
            $dimByte = if ($dim -ge $ICO_MAX_DIM_BYTE) { [byte]0 } else { [byte]$dim }
            $payload = $pngBuffers[$i]

            $bw.Write([byte]$dimByte)
            $bw.Write([byte]$dimByte)
            $bw.Write([byte]0)
            $bw.Write([byte]0)
            $bw.Write([uint16]$ICO_PLANES)
            $bw.Write([uint16]$ICO_BIT_COUNT)
            $bw.Write([uint32]$payload.Length)
            $bw.Write([uint32]$currentOffset)

            $currentOffset += [uint32]$payload.Length
        }

        for ($i = 0; $i -lt $Sizes.Count; $i++) {
            $bw.Write($pngBuffers[$i])
        }

        $bw.Flush()
        [System.IO.File]::WriteAllBytes($OutputIcoPath, $ms.ToArray())
    } finally {
        $bw.Dispose()
        $ms.Dispose()
    }
}

function Export-RawRgbaFromPng {
    param(
        [Parameter(Mandatory = $true)][int]$Size,
        [Parameter(Mandatory = $true)][string]$Directory
    )

    $pngPath = Join-Path $Directory "routeward-$Size.png"
    $rgbaPath = Join-Path $Directory "routeward-$Size.rgba"

    $bmp = New-Object System.Drawing.Bitmap($pngPath)
    try {
        if ($bmp.Width -ne $Size -or $bmp.Height -ne $Size) {
            throw "PNG '$pngPath' dimensions $($bmp.Width)x$($bmp.Height) do not match expected ${Size}x${Size}."
        }

        $rect = New-Object System.Drawing.Rectangle(0, 0, $Size, $Size)
        $lockData = $bmp.LockBits(
            $rect,
            [System.Drawing.Imaging.ImageLockMode]::ReadOnly,
            [System.Drawing.Imaging.PixelFormat]::Format32bppArgb
        )
        try {
            $byteCount = $Size * $Size * 4
            $bgraBytes = New-Object byte[] $byteCount
            [System.Runtime.InteropServices.Marshal]::Copy($lockData.Scan0, $bgraBytes, 0, $byteCount)

            # Convert little-endian ARGB ([B, G, R, A]) to straight [R, G, B, A]
            for ($offset = 0; $offset -lt $byteCount; $offset += 4) {
                $blue = $bgraBytes[$offset]
                $red = $bgraBytes[$offset + 2]
                $bgraBytes[$offset] = $red
                $bgraBytes[$offset + 2] = $blue
            }

            [System.IO.File]::WriteAllBytes($rgbaPath, $bgraBytes)
        } finally {
            $bmp.UnlockBits($lockData)
        }
    } finally {
        $bmp.Dispose()
    }
}

$edgePath = Find-EdgeExecutable
Write-Host "Using Microsoft Edge: $edgePath"

Convert-SvgToPngViaHeadlessEdge `
    -EdgeExe $edgePath `
    -SourceSvgPath $svgPath `
    -Sizes $PNG_SIZES `
    -OutputDirectory $BrandingDir

$icoOutput = Join-Path $BrandingDir "routeward.ico"
Write-MultiSizeIco `
    -Sizes $ICO_SIZES `
    -Directory $BrandingDir `
    -OutputIcoPath $icoOutput

foreach ($rgbaSize in $RGBA_SIZES) {
    Export-RawRgbaFromPng -Size $rgbaSize -Directory $BrandingDir
}

$repoRootCandidate = Split-Path -Parent (Split-Path -Parent $BrandingDir)
$uiPublicDir = Join-Path $repoRootCandidate "ui\public"
if (Test-Path -LiteralPath $uiPublicDir) {
    Copy-Item -LiteralPath (Join-Path $BrandingDir "routeward-icon.svg") -Destination (Join-Path $uiPublicDir "routeward-icon.svg") -Force
    Copy-Item -LiteralPath (Join-Path $BrandingDir "routeward-glyph.svg") -Destination (Join-Path $uiPublicDir "routeward-glyph.svg") -Force
}

Write-Host "Successfully generated PNGs ($($PNG_SIZES -join ', ') px), routeward.ico, and raw RGBA buffers ($($RGBA_SIZES -join ', ') px) in '$BrandingDir'."
