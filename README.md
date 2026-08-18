# DocLink

Peer-to-peer document sharing for office PCs. Every machine publishes one
folder to the LAN; from any machine you open a window, browse every online
PC's shared files, and download or print what you need. No central server,
no cloud, no SMB configuration.

Sibling project to [Printlink](https://github.com/najm07/Printlink) — same
philosophy (serverless, LAN-native), different payload: PrintLink moves
print jobs, DocLink publishes files.

## How it works

Each PC runs one small daemon (`doclinkd`) with three roles:

- **Publisher** — serves a designated local folder (read-only) over HTTP:
  directory listing, metadata, file content.
- **Directory** — UDP broadcast beacons keep a live list of which peers
  are online right now.
- **Browser** — serves the web UI on localhost; the window shows all
  online PCs, their folder trees, and actions (download, print).

```
 PC-A (Compta)                PC-B (Direction)
 ┌──────────────────────┐     ┌──────────────────────┐
 │ doclinkd             │     │ doclinkd             │
 │  share: ./shared ────┼─────┼──► GET /v1/list      │
 │  discovery beacons ◄─┼─────┼─── beacons           │
 │  web UI :37655       │     │  web UI :37655       │
 └──────────────────────┘     └──────────────────────┘
```

## Quickstart

```sh
cargo update          # refresh dependency baselines
cargo run -p doclinkd # first run generates a node identity + ./shared
# open http://localhost:37655
```

Drop files into `./shared` to publish them. Run the same binary on a
second PC (or a second port on the same PC) and they will find each
other within a few seconds.

Optional `doclink.toml` next to the binary:

```toml
node_name    = "PC-Comptabilite"
share_root   = "./shared"
http_port    = 37655
identity_key = "./doclink-identity.key"
```

## Repository layout

| Path | Purpose |
|---|---|
| `crates/doclink-core` | Protocol types, ed25519 node identity, UDP discovery |
| `crates/doclinkd` | Node daemon: config, read-only share server (axum), web UI host |
| `docs/protocol.md` | Wire protocol specification (v0.1 draft) |
| `docs/mvp.md` | Milestone breakdown M0–M4 |
| `webui` | Browser UI: peer list + folder tree + download/print actions |

## Status

M0 scaffold. Shares are read-only in v1 by design. See `docs/mvp.md`
for the roadmap (peer proxy browsing, streaming downloads, print via
shell verb, pairing + TLS, packaging).

## License

MIT — see LICENSE.
