# DocLink wire protocol — v0.5

This document is the language-neutral specification. `doclink-core` is the
reference implementation; any future client (C#, PrintLink interop) conforms
to this document.

## 1. Overview

Every node is simultaneously a **publisher** (serves its own shared folder,
read-only) and a **browser** (reads other nodes' shares). There is no
central server and no push: files are only ever pulled by the reader.

v0.2 introduces the **pairing trust model** (AnyDesk/TeamViewer style):

- Every node has a persistent **DocLink ID** (16 hex chars, derived from its
  ed25519 identity key). The ID is the address book key — you add a PC by
  its ID, not by its IP.
- Adding a PC sends a signed **pair request**. The sharing PC must approve
  it once, choosing a **granting period** (1 day / 7 days / 30 days /
  until revoked). Approvals persist; expiry and revocation are enforced
  on every request.
- All peer traffic after pairing is **signature-authenticated**.
- Grants may be **scoped**: full access, or an explicit list of files and
  folders the grantee can see.

v0.5 adds **printing on a peer's default printer** via the local PrintLink agent. A peer with `allow_print` may `POST /v1/print` raw bytes; the receiving DocLink forwards them to `https://127.0.0.1:9100` via PrintLink's HMAC+AES-GCM wire (the PrintLink hop is always localhost on the printer host). The UI's **Print on…** sends any file to any approved peer's default printer.

v0.4 adds one write path: **inbox drops**. An approved peer may upload a
single file into the owner's **inbox** drop folder (`POST /v1/upload`).
The owner reviews it and either **accepts** (moves it into `shared/`) or
**discards** it. The share itself stays read-only — a peer can never plant
content into your shared folder unvetted.

Two HTTP planes per node:

| Plane | Bind | Purpose |
|---|---|---|
| Data | `tls://0.0.0.0:37655` | Peer-facing, TLS 1.3 with pinned identity certs: info, pairing, authenticated list/file |
| Admin | `127.0.0.1:37656` | Localhost-only: window UI, contacts, approvals, revocation, scoping, own-share management, browse proxy |

Management operations are unreachable from the LAN by construction.

## 2. Identity

Each node owns a persistent ed25519 keypair (`doclink-identity.key`).
`fingerprint` = hex(sha256(public key)); `node_id` = first 16 hex chars of
the fingerprint, displayed grouped (`9f2c-1ab0-7e44-d310`). Any node_id
presented anywhere MUST hash-match its accompanying public key.

## 3. Discovery

mDNS (Zeroconf) service advertisement and resolution, exactly like
PrintLink:

- Service type: `_doclink._tcp.local.`
- Instance name: `doclink-<node_id>._doclink._tcp.local.`
- Properties: `node_id` (hex), `http_port` (decimal)

Clients browse `_doclink._tcp.local.` and resolve a DocLink ID to
`(ip, port)` from the cache. This is multicast, not broadcast, so it
survives virtual adapters and mixed networks. A contact may carry a
manual `host:port` fallback for peers on another subnet or when mDNS
is blocked.

Discovery is only an **address book** — it resolves a DocLink ID to a
current IP and shows online/offline. It grants no trust.

## 4. Authentication

Authenticated data-plane requests carry five headers:

```
x-doclink-node:  <node_id>
x-doclink-pub:   <ed25519 public key, hex>
x-doclink-ts:    <unix seconds>
x-doclink-nonce: <random hex, unique per request>
x-doclink-sig:   <hex ed25519 signature>
```

Signature input (UTF-8, `\n`-joined, trailing newline after nonce):

```
<METHOD>
<PATH>?<QUERY>
<TS>
<NONCE>
<BODY>
```

The nonce makes every signature unique even when two requests land in
the same second — required for the anti-replay cache to coexist with
fast successive calls to the same path. Senders MUST generate a fresh
random nonce per request.

For requests with a body (`POST /v1/upload`), `<BODY>` is the request
bytes rendered as lossy UTF-8 — the same bytes the receiver must read
before writing anything, so an upload is only trusted after it verifies.

Verification rules (publisher MUST enforce):

1. Timestamp within ±900 s of now → else `401`. (Generous on purpose:
   LAN PCs drift; see `auth.rs`.)
2. A live grant exists for `x-doclink-node` (not expired, not revoked)
   → else `403`.
3. hex(sha256(`x-doclink-pub`)) == grant.fingerprint → else `403`.
4. Signature verifies under `x-doclink-pub` → else `401`.
5. The signature has not already been accepted within the current
   window → else `401` (anti-replay; in-memory cache, per node).

## 5. Pairing workflow

1. Requester resolves the target ID (discovery or manual host), fetches
   `GET /v1/info`, and verifies node_id and fingerprint. The requester's
   UI shows the target's full 64-hex fingerprint and gates Add on an
   explicit human confirmation that it matches the peer's own display —
   the 16-hex ID alone is a 64-bit hash and must not be trusted blindly.
2. Requester sends `POST /v1/pair/request`:

```json
{
  "node_id": "...", "name": "PC-Direction",
  "pubkey_hex": "...", "requested_duration_secs": 604800,
  "signature": "<hex over doclink-pair-v1\nnode_id\nname\npubkey_hex\nduration>"
}
```

3. Grantor verifies the signature, checks node_id ↔ pubkey consistency,
   and queues the request for human approval. If a live grant already
   exists for that fingerprint, the response is immediately `approved`
   (idempotent re-pair).
4. A human approves (choosing the granting period) or denies via the
   grantor's admin plane. The grant is persisted to `doclink-grants.json`.
5. The grantor notifies the requester with `POST /v1/pair/decision`
   (signed over `doclink-decision-v1\n...`); the requester can also poll
   `GET /v1/pair/status?node_id=<id>` → `pending|approved|denied|unknown`.

## 6. Data endpoints (data plane)

| Endpoint | Auth | Response |
|---|---|---|
| `GET /v1/info` | none | `NodeInfo` (needed to verify pairing targets) |
| `GET /v1/list?path=<rel>` | required | `ListResponse`, scope-filtered |
| `GET /v1/search?q=<term>` | required | `SearchResponse`: case-insensitive filename matches across the caller's granted scope (recursive, visit-budget 20k, max 200 hits, `truncated` flag) |
| `GET /v1/file?path=<rel>` | required | file bytes, streamed; single `Range` supported (`206` + `Content-Range`, `416` when unsatisfiable), `Content-Disposition: attachment` |
| `POST /v1/upload?name=<file>` | required, **body signed** | drop one file into the owner's inbox → `UploadResult { name, size }`. `<file>` is a single component (no `/`, `\`, `:`, etc. — see inbox rules below). Collisions are renamed `name (1).ext`. Oversized (`> inbox_max_size`) → `413` |
| `POST /v1/print?name=<file>` | required, **body signed**, `allow_print` | print raw bytes on the peer's default printer via its local PrintLink (`127.0.0.1:9100`, HMAC+AES-GCM). Empty body → `400`, `>100 MiB` → `413`, `allow_print` missing → `403`, PrintLink offline → `503`, token rejected → `401` |
| `POST /v1/pair/request` | self-signed body | `PairStatusResponse` |
| `POST /v1/pair/decision` | self-signed body **from a known grantor** | `204`; decisions from unpaired keys are rejected (`403`) |
| `GET /v1/pair/status?node_id=<id>` | signed poll — caller must authenticate as the queried node (pubkey must hash to it) | `PairStatusResponse` |

Pairing endpoints are additionally rate-limited per source IP; pending
requests expire after 10 minutes and the pending queue is capped.

Path rules: no absolute paths, no `..`, no drive prefixes; canonicalized
paths must stay under the share root (`403`), missing paths `404`.
Errors carry `{ "error": "<message>" }`; authenticated data-plane
errors additionally carry a stable `"code"` so peers can localize:
`pending` (pair request not yet approved) · `denied` · `expired` ·
`unknown-node` (no pairing exists). Messages are end-user ready.

### Grant scoping and permissions

Each grant carries `paths: []` plus two orthogonal permissions:

- `allow_files` (default `true`): may browse/download/search/upload. When false, `paths` is ignored and every file endpoint returns `403`.
- `allow_print` (default `false`): may `POST /v1/print` (printing is separate from file access).

`paths` meaning:

- **Empty** — full access to the whole share (when `allow_files` true).
- **Non-empty** — the grantee sees only the listed files/folders.
  Listing a directory is allowed when it is inside a granted path or
  contains one (entries are then filtered to visible items). Downloading
  a file is allowed only when the file equals or lies inside a granted
  path. Anything else → `403`.

At least one of `allow_files` / `allow_print` must be true — a grant with neither is rejected. Existing `doclink-grants.json` files without these fields load as `allow_files=true, allow_print=false` (files-only, backward compatible).

### Inbox (`/v1/upload`, v0.4)

Approved peers can upload; the owner's pubkey/identity is already
authenticated by the normal header scheme. The receiving node MUST buffer
the whole request body before writing so it can verify the signature
(which covers the body bytes lossily) — the `inbox_max_size` cap bounds
the buffered memory and storage a stiffed peer can force. Enforcement:

- `<file>` must be a **single path component**: no `/`, `\`, `:`, `*`,
  `?`, `"`, `<`, `>`, `|`, control chars, dot-prefixed names, trailing
  dots/spaces, and the `.doclink.json` suffix is reserved for metadata.
  Anything else → `400`.
- Files land in `<inbox_root>` (default `inbox/`), never in `shared/`.
  Colliding names get `stem (1).ext`, `stem (2).ext`, ….
- The receiver writes `<name>.doclink.json` beside each upload recording
  the sender (`{ from, from_node_id, received_unix }`); these sidecars are
  hidden from listings. Files dropped directly on disk simply lack them.
- Receiver actions: **accept** moves the file into the share root (deduped
  there too), **discard** deletes it — both are owner-only admin operations.

## 7. Admin endpoints (admin plane, localhost only)

| Endpoint | Purpose |
|---|---|
| `GET /v1/admin/info` | This node (ID shown in the window header) |
| `GET/POST /v1/admin/contacts` | List / add-by-ID (sends the pair request) |
| `GET /v1/admin/contact-fingerprint` | Resolve an ID to its full fingerprint — shown for verification BEFORE any pair request |
| `DELETE /v1/admin/contacts/{id}` | Remove a contact |
| `GET /v1/admin/requests` | Incoming pending pair requests |
| `POST /v1/admin/requests/{id}/decision` | Approve (with duration) or deny |
| `GET /v1/admin/grants` | Grants this node has issued (with scopes) |
| `PUT /v1/admin/grants/{fingerprint}` | Set a grant's scope (`{ "paths": [...] }`, empty = full) |
| `DELETE /v1/admin/grants/{fingerprint}` | Revoke a grant |
| `POST /v1/admin/share-item` | Add/remove one path across grants (`{ path, fingerprints }`) |
| `GET /v1/admin/myshare/list?path=` | List my own share (owner view) |
| `DELETE /v1/admin/myshare?path=` | Delete a file/folder from my share |
| `POST /v1/admin/myshare/reveal` | Open the share folder in Explorer |
| `POST /v1/admin/shutdown` | Graceful daemon stop (used by the window shell) |
| `GET /v1/admin/events?since=<id>` | Notification feed (new pair requests, grants entering their final 24 h) — consumed by the shell's toast poller |
| `GET/PUT /v1/admin/settings` | Effective settings; PUT `{ advertise }` toggles LAN visibility **live** (mDNS goodbye/register) and persists to doclink.toml |
| `GET /v1/admin/browse/{id}/list\|file` | Signed proxy to a contact's share |
| `GET /v1/admin/browse/{id}/raw?path=` | Same, but inline + extension MIME for in-app preview. Hardened: `CSP: default-src 'none'; sandbox` and `nosniff`, so peer-supplied SVG/HTML cannot script |
| `GET /v1/admin/inbox` | List inbox entries (`InboxEntry[]`, newest first, with sender metadata) |
| `GET /v1/admin/inbox/{name}/file` | Download an inbox file |
| `POST /v1/admin/inbox/{name}/accept` | Move the file into `shared/` (deduped) → `{ name }` |
| `DELETE /v1/admin/inbox/{name}` | Discard (delete) the file |
| `POST /v1/admin/send` | Send one of my own shared files: `{ contact, path }` → daemon uploads it into the contact's inbox (`_upload` body-signed by me, size-capped) |
| `POST /v1/admin/print-on/{node_id}` | Print a file on a peer's default printer: `{ path, source_node_id }` (`source` is `mine` or a peer id where the file lives). Resolves bytes locally or via the browse proxy, then `POST /v1/print` to the target (requires `allow_print` on the target). `>100 MiB` → `413`, target offline / PrintLink missing → `502`, printer offline → `503` |

Every admin request must carry a local Host header
(`127.0.0.1:<port>` / `localhost:<port>`) and any Origin/Referer must
match it; violations get `404`. This closes DNS-rebinding and cross-site
request paths against the management plane.

## 8. Grants

Grants are keyed by the requester's fingerprint, carry `granted_unix`,
optional `expires_unix` (`null` = until revoked), `paths` (scope), and
`allow_files` / `allow_print` (permissions). They are re-checked on every
authenticated request. Expired grants are swept every 60 s. Revocation
and permission/scope changes are immediate: the next request from that
node reflects them.

## 9. Security notes

- v0.3 encrypts: the data plane speaks TLS 1.3 only. Each node presents
  a self-signed certificate whose subjectPublicKey IS its ed25519
  identity key, so sha256(SPKI) == fingerprint. Peers pin that hash —
  there is no CA and no second trust anchor; the number a human verified
  during pairing guards both signatures and transport. Connections whose
  certificate does not hash to the expected fingerprint are refused
  before any payload is trusted. The admin plane remains plain HTTP on
  localhost.
- Uploads (`POST /v1/upload`) are buffered and **signature-verified
  before any file is created**, and capped at `inbox_max_size`. The
  inbox write path refuses symlinks and multi-component names, so a
  hostile peer cannot reach outside the drop folder; the share itself
  stays read-only to peers.
- The admin plane trusts localhost. On shared machines, any local user can
  manage the node — acceptable for single-user office PCs, revisited in M4.
  Cross-process web attacks (DNS rebinding, CSRF) are mitigated by the
  Host/Origin guard on every admin route.
- Discovery (mDNS) is only an address book; pairing requires the human to
  verify the full 64-hex fingerprint out of band (Add PC flow gates on it).
  The 16-hex DocLink ID alone is only a 64-bit hash and MUST NOT be the
  sole trust anchor.
- Identity keys are ACL-restricted to the current user at creation (and
  re-hardened on load).

## 10. Local printing and PrintLink (v0.5)

- **Local print** (`POST /v1/admin/print/{node_id}?path=`): download a peer's file via the signed proxy and hand it to Windows' `print` verb (shell `printto`). No PrintLink involved — the file is printed on *this* PC.

- **Print on a peer** (`POST /v1/admin/print-on/{node_id}` → `POST /v1/print`): the requester resolves the file (own share or peer share via the browse proxy, capped at 100 MiB) and forwards the raw bytes to the target peer's data plane. The target verifies `allow_print`, then forwards to its **local** PrintLink agent at `https://127.0.0.1:9100` (or `19100` fallback in tests, overridable via `DOCLINK_PRINTLINK_PORT`).

Local PrintLink wire (PrintLink v1.0, frozen spec <https://github.com/najm07/Printlink>):

- Host API: `GET /printers` (unauthenticated alias list), `GET /auth-challenge?sender_id=` (9-digit persona, 120 s nonce), `POST /request-share` (tray dialog, returns `token` + `tls_fp`), `POST /print` (multipart `file` + `X-Sender-ID/Hint/Nonce/Signature`, AES-GCM `[12B nonce][ct+tag]`), `POST /revoke-grant`.
- Persona: `persona_id = format!("{:09}", u64::from_be_bytes(sha256(fingerprint)[24..32]) % 1e9)`.
- Crypto: `key=sha256(hex_decode(token) fallback utf8)`, `hint=sha256(token)[0..16]`, `sig=HMAC-SHA256(key, nonce)`, `encrypt=AES-256-GCM`.
- TLS pin: `sha256(DER cert)` TOFU on first `request-share`, re-verified on every `auth-challenge`/`print`. Token stored in `doclink-local-print.json` (100 MiB cap, `503` when the printer is offline, `401` on token rejection).
- DocLink's `local_print.rs` unit tests include vectors from the real Python agent (cryptography 46.0.5) and the full `A→B→local PrintLink` E2E (two DocLink nodes + a stub PrintLink reporting offline) proves the encrypted path.

Caveat — reference agent WSGI bug (now fixed upstream in PrintLink PR #1): `agent/server.py`'s `_TLSWSGIHandler._wsgi_env` omitted `HTTP_*` header forwarding, so `POST /print`/`revoke-grant` always saw `missing credentials` over the real network (Flask `request.headers` reads `HTTP_X_*`). E2E in this repo patched the local test copy to forward headers per WSGI spec; real hosts need that fix.

## 11. Future extensions (reserved)

- WebDAV facade (post-v1).
