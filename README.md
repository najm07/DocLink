# DocLink

Peer-to-peer document sharing for office PCs, with AnyDesk-style trust.
Every machine publishes one folder to the LAN; from any machine you open a
window, browse the PCs you've been granted access to, and download or print
what you need. No central server, no cloud, no SMB configuration.

Sibling project to [Printlink](https://github.com/najm07/Printlink) — same
philosophy (serverless, LAN-native), different payload: PrintLink moves
print jobs, DocLink publishes files.

## How it works

Each PC runs one small daemon (`doclinkd`):

- **Publisher** — serves a designated local folder (read-only) to paired
  PCs only. Every request is signature-authenticated against a grant list.
- **Directory** — UDP beacons resolve DocLink IDs to current IPs and show
  who is online (an address book, not a trust decision).
- **Browser** — a localhost-only window: add PCs by ID, approve incoming
  requests, manage grants, browse shares, download, print.

### Trust model (AnyDesk-style)

1. Every PC has a persistent **DocLink ID** (16 hex chars, shown in the
   window header — click to copy).
2. To browse a PC, you **add it by ID** and give it a local name
   ("PC-Compta"). A signed pair request is sent.
3. The sharing PC **approves once**, choosing a granting period:
   1 day, 7 days, 30 days, or until revoked.
4. The sharing PC can **revoke** any grant at any time; grants also
   expire automatically. Both are enforced on every request.

```
 PC-A (Compta)                 PC-B (Direction)
 ┌──────────────────────┐      ┌──────────────────────┐
 │ doclinkd             │      │ doclinkd             │
 │  data  :37655 ◄──────┼──────┼── signed GET /v1/list│
 │  admin :37656 (local)│      │  admin :37656 (local)│
 │  beacons ◄───────────┼──────┼─── beacons           │
 └──────────────────────┘      └──────────────────────┘
```

| Port | Plane | Reachable from |
|---|---|---|
| 37655 | data (peer API) | LAN, authenticated |
| 37656 | admin (window UI) | localhost only |
| 37654/udp | discovery beacons | LAN |

## Quickstart

```sh
cargo update          # refresh dependency baselines
cargo run -p doclinkd # first run generates identity, ./shared, stores
# open http://localhost:37656
```

1. Note your DocLink ID in the window header; share it with a colleague.
2. They add you: ID + a name + requested duration → you approve in the
   Incoming requests panel.
3. Drop files into `./shared` — granted PCs can now browse and download.

Optional `doclink.toml` next to the binary:

```toml
node_name     = "PC-Comptabilite"
share_root    = "./shared"
http_port     = 37655   # admin plane = port + 1
identity_key  = "./doclink-identity.key"
grants_file   = "./doclink-grants.json"
contacts_file = "./doclink-contacts.json"
```

## Repository layout

| Path | Purpose |
|---|---|
| `crates/doclink-core` | Protocol types, ed25519 identity, UDP discovery |
| `crates/doclinkd` | Daemon: data plane (auth + pairing), admin plane, browse proxy, stores |
| `docs/protocol.md` | Wire protocol specification (v0.2) |
| `docs/mvp.md` | Milestone breakdown M0–M4 |
| `webui` | Window UI: contacts, requests, grants, folder browser |

## Status

M2 — pairing and trust implemented; see `docs/mvp.md`. Shares are
read-only in v1 by design. Traffic is authenticated but not yet encrypted
(TLS lands in M4) — use on a trusted office LAN.

## License

MIT — see LICENSE.
