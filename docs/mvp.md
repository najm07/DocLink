# DocLink MVP roadmap

Guiding constraint: **read-only shares in v1 for peers**. No upload, no
delete, no rename over the network — a node can only publish its own
folder and read others'. (The owner manages their own share locally.)

Trust model (v0.2): AnyDesk-style pairing. PCs are added by DocLink ID,
approved once by the sharing PC with a granting period, and revocable at
any time. Grants can be scoped to specific files/folders.

## M0 — Scaffold (done)

- [x] Cargo workspace: `doclink-core` + `doclinkd`
- [x] Protocol types, ed25519 identity, UDP discovery skeleton
- [x] axum share server with path-traversal-safe read-only share root
- [x] Web UI placeholder served by the daemon
- [x] First `cargo build` green

## M1 — Local end-to-end (done)

- [x] Run daemon, browse own share in the web UI, download a file
- [x] `doclink.toml` config loading verified on Windows
- [x] Unit tests: `ShareRoot::resolve` rejects `..`, absolute paths, symlinks
- [x] Unit tests: grant scoping (`can_list` / `can_read_file` / `entry_visible`)

## M2 — Pairing and trust (v0.2) (done)

- [x] DocLink ID displayed in the window (grouped hex, click to copy)
- [x] Add PC by ID + alias (+ manual host:port fallback for filtered subnets)
- [x] Signed pair requests; approval queue on the sharing PC
- [x] Granting periods (1d / 7d / 30d / until revoked) + auto-expiry sweep
- [x] Revocation, enforced on every request
- [x] Signature-authenticated data plane; admin plane on localhost only
- [x] Daemon-side browse proxy (browser talks only to localhost)
- [x] Discovery waits for late beacons on Add PC (no manual host needed)
- [x] socket2 SO_REUSEADDR/REUSEPORT: several nodes can share one machine
- [x] Loopback beacons: same-machine instances discover each other
- [x] `--port` flag for a second same-PC instance
- [x] Scoped grants: share one file or subfolder with specific PCs only
- [x] mDNS discovery (Zeroconf) like PrintLink, with active probing fallback
- [x] Pairing decision push + requester polling (contact status updates immediately)
- [ ] Two-node verification on the office LAN (firewall rules for 37654/37655)

## M3 — Actions and polish

- [x] `doclink-win` WebView2 window shell (auto-starts the daemon, no console)
- [x] Web UI embedded into doclinkd.exe (single-file daemon)
- [x] `dist.ps1` portable test package (two exes in a zip)
- [x] VS Code-style workbench chrome (frameless window, activity bar, status bar)
- [x] My Share view: browse/manage own share, delete items, reveal in Explorer
- [x] Share… panel per item; Access editor per grant (Everything / selected items)
- [ ] Streaming downloads + `Range` support (no whole-file buffering)
- [ ] Print button: download to temp, then Windows shell `print` verb via windows-rs (`ShellExecuteEx`)
- [ ] Toast notifications (pair request received, grant expiring soon)
- [ ] Graceful shutdown (Ctrl-C / service stop)
- [ ] Contact status refresh (re-poll pair/status, surface expiry)
- [ ] Tray icon so the daemon is visible/manageable without the window

## M4 — Encryption and packaging

- [ ] TLS with pinned peer certificates (protocol v0.3)
- [ ] Identity key file permissions hardening
- [ ] Proper installer (MSI via cargo-wix, mirror Printlink's approach)
- [ ] Autostart on login (registry Run key or Scheduled Task)

## M5 — Discovery mode (network PC browser)

- [ ] New **Network** view that lists all PCs on the LAN currently running DocLink (from beacons)
- [ ] One-click **Add** from the discovery list (no need to paste the ID)
- [ ] Settings toggle **Hide this PC from discovery** (beacon suppression) so a PC can stay invisible while still adding others
- [ ] Respect the hide setting in `doclink.toml` / UI

### Post-v1 ideas

- [ ] Print-on-host through PrintLink interop
- [ ] WebDAV facade (mount a peer's share as a drive letter)
- [ ] Search across all granted peers
- [ ] `Inbox/` write support (upload into a peer's drop folder)
