# Testing DocLink on office PCs

## Prerequisite: WebView2

`doclink-win` uses the WebView2 runtime (Chromium Edge engine). It is
preinstalled on Windows 11 and on most up-to-date Windows 10 machines.
If a window opens blank or fails to start, install the Evergreen
Bootstrapper from Microsoft once per PC.

## Build the portable package

```powershell
.\dist.ps1
```

Produces `dist/doclink-portable.zip` containing exactly two files:

- `doclinkd.exe` — the node daemon (share server, discovery, pairing).
  The web UI is embedded; no other files are needed.
- `doclink-win.exe` — the window. Starts the daemon automatically if it
  isn't running.

## Per-PC setup

1. Unzip anywhere (e.g. `C:\DocLink`).
2. Run `doclink-win.exe`.
3. Approve the Windows Firewall prompt (private networks) — this covers
   the beacon port (37654/udp) and the data plane (37655/tcp).
4. The daemon creates next to the exe: `doclink-identity.key`,
   `doclink-grants.json`, `doclink-contacts.json`, and `shared/`.
   Drop files into `shared/` to publish them.
5. Note the PC's DocLink ID in the window header (click to copy).

The daemon keeps running after you close the window — sharing stays up.
To stop it, close its console window or kill `doclinkd.exe`.

## Pairing two PCs

1. On PC-B: copy its DocLink ID from the window header.
2. On PC-A: paste the ID, set a name ("PC-B"), pick a duration, Add PC.
   The daemon waits a few seconds for the peer's beacon if it has just
   started — no host:port needed on a normal LAN.
3. On PC-B: the request appears under Incoming requests — approve with
   a granting period.
4. On PC-A: click PC-B in My PCs and browse its `shared/` folder.

If PCs sit on different subnets (broadcast beacons filtered), the
host:port field remains as a fallback, e.g. `192.168.2.40:37655`.

## Testing two instances on one PC

Discovery now shares its port gracefully (SO_REUSEADDR), but each
instance still needs its own data-plane port and its own folder (the
identity key and stores live next to the exe):

1. Copy the two exes into a second folder, e.g. `C:\DocLink-B`.
2. In that folder run: `doclinkd.exe --port 37665`
   (its admin plane lands on 37666).
3. Open the first instance with `doclink-win.exe` (port 37656) and the
   second at `http://127.0.0.1:37666` in a browser.
4. Each folder generates its own identity, so the two instances have
   different DocLink IDs and can pair with each other exactly like two
   real PCs.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Window blank / never loads | daemon didn't start — run `doclinkd.exe` manually and read its console |
| Peer never appears online | firewall blocking 37654/udp, or different subnet (use host:port) |
| "that's this PC's own DocLink ID" | you pasted the local ID — copy the ID from the OTHER PC's window header |
| Add PC fails with 403/401 | clock skew > 5 min between PCs — sync clocks |
| Browse fails with 403 | grant expired or revoked — re-add the PC |
