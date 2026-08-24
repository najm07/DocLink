# Build the per-user DocLink installer (dist\DocLink-setup.msi).
#
# First run downloads WiX3 binaries into tools\wix311 (~35 MB, cached).
# Prereqs: cargo (release build is produced here), Windows 10+.
#
# Usage:  .\msi.ps1

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

# --- version from the workspace manifest ---
$version = ((Select-String -Path "$root\Cargo.toml" -Pattern '^\s*version\s*=\s*"([^"]+)"' |
    Select-Object -First 1).Matches[0].Groups[1].Value)
Write-Host "DocLink v$version"

# --- release build ---
cargo build --release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# --- WiX toolset ---
$wix = "$root\tools\wix311"
if (-not (Test-Path "$wix\candle.exe")) {
    Write-Host "Downloading WiX3 toolset..."
    New-Item -ItemType Directory -Force $wix | Out-Null
    $zip = "$env:TEMP\wix311-binaries.zip"
    Invoke-WebRequest -Uri "https://github.com/wixtoolset/wix3/releases/download/wix3112rtm/wix311-binaries.zip" `
        -OutFile $zip
    Expand-Archive -Path $zip -DestinationPath $wix -Force
    Remove-Item $zip
}

# --- compile & link ---
New-Item -ItemType Directory -Force "$root\target\wix" | Out-Null
& "$wix\candle.exe" -arch x64 `
    "-dSrc=$root\target\release" `
    "-dVersion=$version" `
    -ext "$wix\WixUtilExtension.dll" `
    -out "$root\target\wix\main.wixobj" `
    "$root\wix\main.wxs"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

New-Item -ItemType Directory -Force "$root\dist" | Out-Null
& "$wix\light.exe" `
    -ext "$wix\WixUtilExtension.dll" `
    -out "$root\dist\DocLink-setup.msi" `
    "$root\target\wix\main.wixobj"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "Installer ready: dist\DocLink-setup.msi"
Write-Host "Silent install: msiexec /i dist\DocLink-setup.msi /qn"
