# DocLink MVP roadmap

Guiding constraint: **read-only shares in v1**. No upload, no delete, no
rename — a node can only publish its own folder and read others'.

## M0 — Scaffold (this commit)

- [x] Cargo workspace: `doclink-core` + `doclinkd`
- [x] Protocol types, ed25519 identity, UDP discovery skeleton
- [x] axum share server: `/v1/info`, `/v1/list`, `/v1/file`, `/v1/peers`
- [x] Path-traversal-safe read-only share root
- [x] Web UI placeholder served by the daemon
- [ ] `cargo update`, first `cargo build`, fix drift from baseline versions

## M1 — Local end-to-end

- [ ] Run daemon, browse own share in the web UI, download a file
- [ ] `doclink.toml` config loading verified on Windows
- [ ] Unit tests: `ShareRoot::resolve` rejects `..`, absolute paths, symlinks

## M2 — Real peer browsing

- [ ] Two nodes discover each other (verify beacons on the office LAN)
- [ ] socket2 + SO_REUSEADDR so two dev instances can share one machine
- [ ] Daemon-side proxy: `/v1/peers/{id}/list`, `/v1/peers/{id}/file`
- [ ] Web UI: click a peer → browse its tree through the local daemon

## M3 — Actions and polish

- [ ] Streaming downloads + `Range` support (no whole-file buffering)
- [ ] Print button: download to temp, then Windows shell `print` verb
      via windows-rs (`ShellExecuteEx`)
- [ ] Toast notification on download/print completion
- [ ] Graceful shutdown (Ctrl-C / service stop)

## M4 — Trust and packaging

- [ ] Pairing flow + fingerprint allowlist (protocol §5 v0.2)
- [ ] TLS with pinned peer certs (protocol §5 v0.3)
- [ ] Single-file release build; MSI via cargo-wix (mirror Printlink's
      installer approach)
- [ ] Autostart on login (registry Run key or Scheduled Task)

## Post-v1 ideas

- Print-on-host through PrintLink interop
- WebDAV facade (mount a peer's share as a drive letter)
- Search across all online peers
- `Inbox/` write support (upload into a peer's drop folder)
