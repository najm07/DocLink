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
  isn't running, with no extra console window. Daemon logs go to
  `doclinkd.log` next to the exe.

## Per-PC setup

1. Unzip anywhere (e.g. `C:\DocLink`).
2. Run `doclink-win.exe`. You should see only the DocLink window.
3. Approve the Windows Firewall prompt (private networks) — this covers
   the beacon port (37654/udp) and the data plane (37655/tcp).
4. The daemon creates next to the exe: `doclink-identity.key`,
   `doclink-grants.json`, `doclink-contacts.json`, `shared/`, and
   `doclinkd.log`. Drop files into `shared/` to publish them.
5. Note the PC's DocLink ID in the window header (click to copy).

The daemon keeps running after you close the window — sharing stays up.
To stop it, kill `doclinkd.exe` in Task Manager.

If an old console window is still on screen from a previous build, close
it (or kill `doclinkd.exe`) and start `doclink-win.exe` again.

## Pairing two PCs

1. On PC-B: copy its DocLink ID from the window header.
2. On PC-A: click +, paste the ID, set a name ("PC-B"), pick a duration.
   The daemon waits a few seconds for the peer's beacon if it has just
   started — no host:port needed on a normal LAN.
3. On PC-B: the request appears under Incoming — approve with a granting
   period.
4. On PC-A: click PC-B in the list and browse its `shared/` folder.

If PCs sit on different subnets (broadcast beacons filtered), open
Advanced in the Add PC dialog and enter `host:port`, e.g.
`192.168.2.40:37655`.

## Testing two instances on one PC

Discovery now shares its port gracefully (SO_REUSEADDR), but each
instance still needs its own data-plane port and its own folder (the
identity key and stores live next to the exe):

1. Copy the two exes into a second folder, e.g. `C:\DocLink-B`.
2. In that folder run: `doclinkd.exe --port 37665`
   (its admin plane lands on 37666). This one *will* show a console —
   that is only when you launch the daemon yourself.
3. Open the first instance with `doclink-win.exe` (port 37656) and the
   second at `http://127.0.0.1:37666` in a browser.
4. Each folder generates its own identity, so the two instances have
   different DocLink IDs and can pair with each other exactly like two
   real PCs.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Extra black terminal | old daemon still running — kill `doclinkd.exe` and relaunch `doclink-win.exe` |
| Window blank / never loads | daemon didn't start — open `doclinkd.log` next to the exe |
| Peer never appears online | firewall blocking 37654/udp, or different subnet (use Advanced host:port) |
| "that's this PC's own DocLink ID" | you pasted the local ID — copy the ID from the OTHER PC's window header |
| Add PC fails with 403/401 | clock skew > 5 min between PCs — sync clocks |
| Browse fails with 403 | grant expired or revoked — re-add the PC |
