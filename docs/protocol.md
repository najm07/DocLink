# DocLink wire protocol — v0.1 (draft)

This document is the language-neutral specification. `doclink-core` is the
reference implementation; any future client (C#, PrintLink interop) conforms
to this document.

## 1. Overview

Every node is simultaneously a **publisher** (serves its own shared folder,
read-only) and a **browser** (enumerates peers, reads their shares). There
is no central server and no push: files are only ever pulled by the reader.

Two planes:

- **Discovery plane** — UDP broadcast beacons, best-effort, unauthenticated.
- **Data plane** — HTTP over TCP per node, carrying listings and file bytes.

## 2. Discovery

- Destination: `255.255.255.255:37654/udp`, every 5 s.
- A peer is online until silent for 20 s.
- Payload: JSON `Beacon`.

```json
{
  "magic": "DOCLINK_BEACON",
  "version": "0.1",
  "node_id": "9f2c1ab07e44d310",
  "name": "PC-Comptabilite",
  "http_port": 37655,
  "fingerprint": "<64 hex chars = sha256(ed25519 pubkey)>"
}
```

Receivers MUST ignore beacons with a wrong `magic` and SHOULD ignore their
own `node_id`. Discovery is unauthenticated: the data plane re-verifies
identity (see §5).

> **Interop TODO:** align field names with PrintLink's discovery format
> (`agent/discovery.py` in the Printlink repo) so a mixed network segment
> works and print-on-host becomes possible.

## 3. Data plane endpoints

Base: `http://<peer-ip>:<http_port>`. All paths are relative to the share
root, forward-slash separated, `""` = root.

| Endpoint | Response |
|---|---|
| `GET /v1/info` | `NodeInfo` — node_id, name, version, fingerprint |
| `GET /v1/list?path=<rel>` | `ListResponse` — entries with name, path, kind, size, modified_unix |
| `GET /v1/file?path=<rel>` | file bytes, `Content-Disposition: attachment` |
| `GET /v1/peers` | `Peer[]` — the queried node's own discovery view |

Planned (M2): `GET /v1/peers/{node_id}/list|file?path=...` — daemon-side
proxy so the browser UI only ever talks to its local daemon.

### Path rules (publisher MUST enforce)

- Reject absolute paths, drive prefixes, and any `..` component → `403`.
- Canonicalize and verify the result stays under the share root
  (symlink-safe) → otherwise `403`.
- Missing paths → `404`. Errors carry `{ "error": "<message>" }`.

## 4. Identity

Each node owns a persistent ed25519 keypair (`doclink-identity.key`).
`fingerprint` = hex(sha256(public key)); `node_id` = first 16 hex chars.
The fingerprint in `/v1/info` MUST match the fingerprint in that node's
beacons — clients treat a mismatch as a different (or spoofed) node.

## 5. Security phases

| Phase | Guarantees |
|---|---|
| v0.1 (M0–M3) | Trusted-LAN posture: read-only shares, path-traversal protection, fingerprints displayed for manual verification |
| v0.2 (M4) | Pairing: nodes exchange fingerprints out-of-band once; unknown peers cannot list or read (allowlist enforced in the data plane) |
| v0.3 (M4) | Transport encryption: TLS via rustls with pinned peer certificates, or Noise (snow) — decision recorded here before implementation |

## 6. Future extensions (reserved)

- `Range` request support on `/v1/file` (M3) for resume and large files.
- Print action: client downloads to temp, then OS shell print verb (M3).
- Print-on-host via PrintLink wire compatibility (post-v1).
- WebDAV facade so shares can be mounted as Windows drive letters.
- Write support (upload into a peer's `Inbox/` subfolder) — explicitly
  out of scope for v1.
