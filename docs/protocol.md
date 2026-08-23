# DocLink wire protocol — v0.3

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
| `GET /v1/file?path=<rel>` | required | file bytes, streamed; single `Range` supported (`206` + `Content-Range`, `416` when unsatisfiable), `Content-Disposition: attachment` |
| `POST /v1/pair/request` | self-signed body | `PairStatusResponse` |
| `POST /v1/pair/decision` | self-signed body **from a known grantor** | `204`; decisions from unpaired keys are rejected (`403`) |
| `GET /v1/pair/status?node_id=<id>` | signed poll — caller must authenticate as the queried node (pubkey must hash to it) | `PairStatusResponse` |

Pairing endpoints are additionally rate-limited per source IP; pending
requests expire after 10 minutes and the pending queue is capped.

Path rules: no absolute paths, no `..`, no drive prefixes; canonicalized
paths must stay under the share root (`403`), missing paths `404`.
Errors carry `{ "error": "<message>" }`.

### Grant scoping

Each grant carries `paths: []`:

- **Empty** — full access to the whole share.
- **Non-empty** — the grantee sees only the listed files/folders.
  Listing a directory is allowed when it is inside a granted path or
  contains one (entries are then filtered to visible items). Downloading
  a file is allowed only when the file equals or lies inside a granted
  path. Anything else → `403`.

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
| `GET /v1/admin/browse/{id}/list\|file` | Signed proxy to a contact's share |

Every admin request must carry a local Host header
(`127.0.0.1:<port>` / `localhost:<port>`) and any Origin/Referer must
match it; violations get `404`. This closes DNS-rebinding and cross-site
request paths against the management plane.

## 8. Grants

Grants are keyed by the requester's fingerprint, carry `granted_unix`,
optional `expires_unix` (`null` = until revoked), and `paths` (scope).
They are re-checked on every authenticated request. Expired grants are
swept every 60 s. Revocation and scope changes are immediate: the next
request from that node reflects them.

## 9. Security notes

- v0.3 encrypts: the data plane speaks TLS 1.3 only. Each node presents
  a self-signed certificate whose subjectPublicKey IS its ed25519
  identity key, so sha256(SPKI) == fingerprint. Peers pin that hash —
  there is no CA and no second trust anchor; the number a human verified
  during pairing guards both signatures and transport. Connections whose
  certificate does not hash to the expected fingerprint are refused
  before any payload is trusted. The admin plane remains plain HTTP on
  localhost.
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

## 10. Future extensions (reserved)

- `Range` support on `/v1/file` (M3).
- Print action: download to temp, then OS shell print verb (M3).
- Print-on-host via PrintLink wire compatibility (post-v1).
- WebDAV facade; cross-peer search; `Inbox/` write support (post-v1).
