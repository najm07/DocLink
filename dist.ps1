# Build a portable test package: doclink-win.exe + doclinkd.exe in one zip.
# Run from the repo root:  .\dist.ps1

cargo build --release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$dist = "dist/doclink"
New-Item -ItemType Directory -Force $dist | Out-Null
Copy-Item target/release/doclinkd.exe $dist
Copy-Item target/release/doclink-win.exe $dist
Compress-Archive -Force "$dist/*" "dist/doclink-portable.zip"

Write-Host ""
Write-Host "Package ready: dist/doclink-portable.zip"
Write-Host "Per test PC: unzip anywhere, run doclink-win.exe, approve the firewall prompt."
