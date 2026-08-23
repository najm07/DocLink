# Two-PC LAN test (v0.3 / TLS)

Manual verification with real hardware. Budget ~20 minutes for two PCs
on the same subnet. Windows 10/11 with the WebView2 runtime.

## 0. Prerequisites

- `dist/doclink-portable.zip` freshly built (`.\dist.ps1`)
- Both PCs on the same LAN, private network profile
- Clocks roughly in sync (±15 min tolerance)

## 1. Deploy

1. Copy the zip to both PCs, unzip anywhere (e.g. `C:\DocLink`).
2. Run `doclink-win.exe`. Approve **one** UAC prompt per PC — it adds:
   - `DocLink mDNS (UDP 5353)` inbound allow
   - `DocLink data (TCP 37655)` inbound allow

   Verify afterwards:

   ```powershell
   netsh advfirewall firewall show rule name="DocLink mDNS (UDP 5353)"
   netsh advfirewall firewall show rule name="DocLink data (TCP 37655)"
   ```

3. Each daemon creates next to the exe: `doclink-identity.key`
   (ACL-restricted to the current user), `doclink-grants.json`,
   `doclink-contacts.json`, `shared/`, `doclink-admin.port`,
   `doclinkd.log`.

## 2. Pair (fingerprint UX under test)

1. PC-B: copy its DocLink ID from the window header.
2. PC-A: press **+**, paste the ID, name it, choose a duration, press
   **Next**. The dialog resolves the peer over the LAN and shows a full
   64-hex fingerprint.
3. Compare: PC-B's own Add-PC dialog shows its fingerprint under
   "This PC shows". The two must match character-for-character.
   - Match → tick the confirmation box, **Add PC**.
   - Mismatch → STOP: something is impersonating the ID (capture logs).
4. PC-B approves the incoming request with a granting period.
5. PC-A's sidebar flips to *approved* within seconds (decision push);
   worst case ~30 s (catch-up poller).

## 3. Data plane checks (now TLS)

- Browse PC-B's share from PC-A; drop a file into B's `shared/`, refresh,
  download it.
- Optional deep check of the pinned channel from PC-A:

  ```powershell
  $id = (irm http://127.0.0.1:37656/v1/admin/contacts)[0].node_id
  irm "http://127.0.0.1:37656/v1/admin/browse/$id/list?path="
  ```

  Every peer connection is rustls TLS 1.3; the certificate must hash to
  the contact's fingerprint or DocLink refuses the call.

> NOTE: external tools that use Schannel (Windows `curl.exe`,
> `Invoke-WebRequest`) cannot handshake with an Ed25519-only certificate
> and will fail with connection errors. That is a tool limitation, not a
> DocLink fault — verify through the app UI or the localhost admin API.

## 4. Negative tests

| Action | Expected |
|---|---|
| Paste PC-A's own ID into Add | `that's this PC's own DocLink ID` |
| Deny request on PC-B | PC-A row shows *denied* |
| Revoke grant on PC-B while A is browsing | next list/download fails 403 |
| Block UDP 5353 on one PC (temporarily) | discovery falls back to host:port override |
| Close PC-A's window | share stays up (tray); tray Quit stops it gracefully |

## 5. Pass criteria

- [ ] Fingerprint compare shown on both sides; mismatch path blocks Add
- [ ] One UAC prompt per PC; both firewall rules present after
- [ ] Pairing completes; browse + download works over TLS
- [ ] Revocation takes effect immediately
- [ ] Tray Quit exits cleanly (no orphaned doclinkd.exe)
