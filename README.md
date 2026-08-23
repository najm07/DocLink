# DocLink

Peer-to-peer LAN file sharing for Windows — read-only shares, no upload, no central server.

## What it does

- Every PC publishes its own `shared/` folder (read-only to peers)
- You browse other PCs' shares and download files
- Trust is explicit: you add a PC by its **DocLink ID**, the sharing PC approves once, and you can revoke at any time
- Grants can be scoped: share one file or subfolder with specific PCs only

## Quick start

1. Build the daemon: `cargo build --release`
2. Run `doclinkd.exe` (or `doclink-win.exe` for the WebView2 window)
3. Drop files into the `shared/` folder next to the exe
4. On another PC, open the DocLink window, press **+**, paste the other PC's DocLink ID, give it an alias, and click **Add**
5. Browse that PC's share in the main grid; download files with **Download**

> On first run, `doclink-win` prompts once (UAC) to open Windows Firewall for
> UDP 5353 (mDNS discovery) and the data port (TCP 37655) — required for peers
> to find and reach each other on the LAN.

## Protocol

See [`docs/protocol.md`](docs/protocol.md) for the wire specification (v0.2).

## Roadmap

### M0 — Scaffold (done)

- [x] Cargo workspace: `doclink-core` + `doclinkd`
- [x] Protocol types, ed25519 identity, UDP discovery skeleton
- [x] axum share server with path-traversal-safe read-only share root
- [x] Web UI placeholder served by the daemon
- [x] First `cargo build` green

### M1 — Local end-to-end (done)

- [x] Run daemon, browse own share in the web UI, download a file
- [x] `doclink.toml` config loading verified on Windows
- [x] Unit tests: `ShareRoot::resolve` rejects `..`, absolute paths, symlinks
- [x] Unit tests: grant scoping (`can_list` / `can_read_file` / `entry_visible`)

### M2 — Pairing and trust (v0.2) (done)

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
- [x] Two-node verification on the office LAN (automatic firewall rules for UDP 5353 + TCP data port)

### M3 — Actions and polish

- [x] `doclink-win` WebView2 window shell (auto-starts the daemon, no console)
- [x] Web UI embedded into doclinkd.exe (single-file daemon)
- [x] `dist.ps1` portable test package (two exes in a zip)
- [x] VS Code-style workbench chrome (frameless window, activity bar, status bar)
- [x] My Share view: browse/manage own share, delete items, reveal in Explorer
- [x] Share… panel per item; Access editor per grant (Everything / selected items)
- [x] Streaming downloads + `Range` support (no whole-file buffering)
- [ ] Print button: download to temp, then Windows shell `print` verb via windows-rs (`ShellExecuteEx`)
- [ ] Toast notifications (pair request received, grant expiring soon)
- [x] Graceful shutdown (tray Quit / Ctrl-C; admin stop endpoint)
- [x] Contact status refresh: pending contacts re-poll the grantor's `/v1/pair/status`, and peers stay live via TCP keepalive (mDNS re-announcements alone don't refresh liveness)
- [x] Tray icon so the daemon is visible/manageable without the window (Open / Quit)

### M4 — Encryption and packaging

- [ ] TLS with pinned peer certificates (protocol v0.3)
- [x] Identity key file permissions hardening (icacls/chmod 600 on load + creation)
- [ ] Proper installer (MSI via cargo-wix, mirror Printlink's approach)
- [ ] Autostart on login (registry Run key or Scheduled Task)

### M5 — Discovery mode (network PC browser)

- [x] Add dialog lists PCs currently on the LAN running DocLink — click a row to fill the ID (no pasting)
- [ ] Standalone **Network** view that lists all live PCs at a glance
- [ ] Settings toggle **Hide this PC from discovery** (beacon suppression) so a PC can stay invisible while still adding others
- [x] Respect the hide setting in `doclink.toml` / UI (`advertise = false`)

### Post-v1 ideas

- [ ] Print-on-host through PrintLink interop
- [ ] WebDAV facade (mount a peer's share as a drive letter)
- [ ] Search across all granted peers
- [ ] `Inbox/` write support (upload into a peer's drop folder)
