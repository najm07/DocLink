# DocLink MVP roadmap

Guiding constraint: **read-only shares in v1**. No upload, no delete, no
rename — a node can only publish its own folder and read others'.

Trust model (v0.2): AnyDesk-style pairing. PCs are added by DocLink ID,
approved once by the sharing PC with a granting period, and revocable at
any time.

## M0 — Scaffold

- [x] Cargo workspace: `doclink-core` + `doclinkd`
- [x] Protocol types, ed25519 identity, UDP discovery skeleton
- [x] axum share server with path-traversal-safe read-only share root
- [x] Web UI placeholder served by the daemon
- [x] First `cargo build` green (ed25519 rand_core feature, PeerRegistry::new)

## M1 — Local end-to-end

- [ ] Run daemon, browse own share in the web UI, download a file
- [ ] `doclink.toml` config loading verified on Windows
- [ ] Unit tests: `ShareRoot::resolve` rejects `..`, absolute paths, symlinks

## M2 — Pairing and trust (v0.2)

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
- [ ] Two-node verification on the office LAN (firewall rules for 37654/37655)

## M3 — Actions and polish

- [x] `doclink-win` WebView2 window shell (auto-starts the daemon)
- [x] Web UI embedded into doclinkd.exe (single-file daemon)
- [x] `dist.ps1` portable test package (two exes in a zip)
- [ ] Streaming downloads + `Range` support (no whole-file buffering)
- [ ] Print button: download to temp, then Windows shell `print` verb
      via windows-rs (`ShellExecuteEx`)
- [ ] Toast notifications (pair request received, grant expiring soon)
- [ ] Graceful shutdown (Ctrl-C / service stop)
- [ ] Contact status refresh (re-poll pair/status, surface expiry)
- [ ] Tray icon so the daemon is visible/manageable without the window

## M4 — Encryption and packaging

- [ ] TLS with pinned peer certificates (protocol v0.3)
- [ ] Identity key file permissions hardening
- [ ] Proper installer (MSI via cargo-wix, mirror Printlink's approach)
- [ ] Autostart on login (registry Run key or Scheduled Task)

## Post-v1 ideas

- Print-on-host through PrintLink interop
- WebDAV facade (mount a peer's share as a drive letter)
- Search across all granted peers
- `Inbox/` write support (upload into a peer's drop folder)
