# DocLink LAN-test helper (run on ONE of the two test PCs).
# Automates the local side of docs/lan-test.md: firewall check, daemon
# health, own identity, and a live watch over the pairing outcome.
#
# Usage:
#   .\lan-test.ps1              # status + wait for the peer to appear
#   .\lan-test.ps1 -PeerId <16hex>   # additionally poll that contact

param(
    [string]$PeerId = "",
    [int]$AdminPort = 0
)

$ErrorActionPreference = "Stop"

function Get-AdminPort {
    if ($script:AdminPort -gt 0) { return $script:AdminPort }
    $exe = if ($IsWindows -or $env:OS -eq "Windows_NT") {
        Join-Path (Split-Path (Get-Process doclinkd -ErrorAction SilentlyContinue |
            Select-Object -First 1 -ExpandProperty Path -ErrorAction SilentlyContinue) -ErrorAction SilentlyContinue) "doclink-admin.port"
    } else { $null }
    $local = Join-Path (Get-Location) "doclink-admin.port"
    foreach ($f in @($local, $exe)) {
        if ($f -and (Test-Path $f)) { return [int](Get-Content $f | Select-Object -First 1) }
    }
    return 37656
}

$port = Get-AdminPort
$base = "http://127.0.0.1:$port"

Write-Host "== Firewall rules =="
foreach ($rule in @("DocLink mDNS (UDP 5353)", "DocLink data (TCP 37655)")) {
    $hit = netsh advfirewall firewall show rule name="$rule" 2>$null
    Write-Host ("{0} : {1}" -f $rule, $(if ($hit -match "Rule Name:") { "present" } else { "MISSING (run doclink-win once as admin)" }))
}

Write-Host "`n== Daemon =="
if (-not (Test-NetConnection 127.0.0.1 -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue)) {
    Write-Host "admin plane not reachable on port $port - start doclink-win.exe here first."
    exit 1
}
$info = Invoke-RestMethod "$base/v1/admin/info"
Write-Host ("node      : {0} ({1})" -f $info.name, $env:COMPUTERNAME)
Write-Host ("DocLink ID: {0}" -f $info.node_id)
Write-Host ("fingerprint: {0}" -f ($info.fingerprint -replace '(.{4})(?=.)/', '$1-'))
Write-Host "protocol version: $($info.version)"

if ($PeerId) {
    Write-Host "`n== Waiting for peer $PeerId =="
    while ($true) {
        try {
            $c = Invoke-RestMethod "$base/v1/admin/contacts" |
                Where-Object { $_.node_id -eq $PeerId } | Select-Object -First 1
            if ($c) {
                Write-Host ("status: {0} online: {1}" -f $c.status, $c.online)
                if ($c.status -eq "approved") { break }
            }
        } catch { }
        Start-Sleep -Seconds 3
    }
    Write-Host "`n== Smoke: browse + download =="
    $list = Invoke-RestMethod "$base/v1/admin/browse/$PeerId/list?path="
    $list.entries | ForEach-Object { Write-Host ("{0}`t{1}`t{2}" -f $_.kind, $_.path, $_.size) }
}

Write-Host "`nDone. Full procedure: docs/lan-test.md"
