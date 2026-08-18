# DocLink wire protocol — v0.2

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

Two HTTP planes per node:

| Plane | Bind | Purpose |
|---|---|---|
| Data | `0.0.0.0:37655` | Peer-facing: info, pairing, authenticated list/file |
| Admin | `127.0.0.1:37656` | Localhost-only: window UI, contacts, approvals, revocation, browse proxy |

Management operations are unreachable from the LAN by construction.

## 2. Identity

Each node owns a persistent ed25519 keypair (`doclink-identity.key`).
`fingerprint` = hex(sha256(public key)); `node_id` = first 16 hex chars of
the fingerprint, displayed grouped (`9f2c-1ab0-7e44-d310`). Any node_id
presented anywhere MUST hash-match its accompanying public key.

## 3. Discovery

Unchanged from v0.1: JSON `Beacon` via UDP broadcast to port 37654 every
5 s, TTL 20 s. Discovery is only an **address book** — it resolves a
DocLink ID to a current IP and shows online/offline. It grants no trust.
A contact may carry a manual `host:port` fallback for peers beacons
cannot reach (different subnet, broadcast filtered).

## 4. Authentication

Authenticated data-plane requests carry four headers:

```
x-doclink-node: <node_id>
x-doclink-pub:  <ed25519 public key, hex>
x-doclink-ts:   <unix seconds>
x-doclink-sig:  <hex ed25519 signature>
```

Signature input (UTF-8, `\n`-joined, trailing newline after ts):

```
<METHOD>
<PATH>?<QUERY>
<TS>
<BODY>
```

Verification rules (publisher MUST enforce):

1. Timestamp within ±300 s of now → else `401`.
2. A live grant exists for `x-doclink-node` (not expired, not revoked)
   → else `403`.
3. hex(sha256(`x-doclink-pub`)) == grant.fingerprint → else `403`.
4. Signature verifies under `x-doclink-pub` → else `401`.

## 5. Pairing workflow

1. Requester resolves the target ID (discovery or manual host), fetches
   `GET /v1/info`, and verifies node_id and fingerprint.
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
| `GET /v1/list?path=<rel>` | required | `ListResponse` |
| `GET /v1/file?path=<rel>` | required | file bytes, `Content-Disposition: attachment` |
| `POST /v1/pair/request` | self-signed body | `PairStatusResponse` |
| `POST /v1/pair/decision` | self-signed body | `204` |
| `GET /v1/pair/status` | none | `PairStatusResponse` |

Path rules are unchanged from v0.1: no absolute paths, no `..`, no drive
prefixes; canonicalized paths must stay under the share root (`403`),
missing paths `404`. Errors carry `{ "error": "<message>" }`.

## 7. Admin endpoints (admin plane, localhost only)

| Endpoint | Purpose |
|---|---|
| `GET /v1/admin/info` | This node (ID shown in the window header) |
| `GET/POST /v1/admin/contacts` | List / add-by-ID (sends the pair request) |
| `DELETE /v1/admin/contacts/{id}` | Remove a contact |
| `GET /v1/admin/requests` | Incoming pending pair requests |
| `POST /v1/admin/requests/{id}/decision` | Approve (with duration) or deny |
| `GET /v1/admin/grants` | Grants this node has issued |
| `DELETE /v1/admin/grants/{fingerprint}` | Revoke a grant |
| `GET /v1/admin/browse/{id}/list\|file` | Signed proxy to a contact's share |

## 8. Grants

Grants are keyed by the requester's fingerprint, carry `granted_unix` and
optional `expires_unix` (`null` = until revoked), and are re-checked on
every authenticated request. Expired grants are swept every 60 s.
Revocation is immediate: the next request from that node fails with `403`.

## 9. Security notes

- v0.2 authenticates but does not encrypt: traffic is plain HTTP on the
  LAN. v0.3 (M4) adds TLS with pinned peer certificates.
- The admin plane trusts localhost. On shared machines, any local user can
  manage the node — acceptable for single-user office PCs, revisited in M4.
- Discovery beacons are spoofable by design; pairing decisions never rely
  on beacon data alone (fingerprint cross-check in §5 step 1).

## 10. Future extensions (reserved)

- `Range` support on `/v1/file` (M3).
- Print action: download to temp, then OS shell print verb (M3).
- Print-on-host via PrintLink wire compatibility (post-v1).
- WebDAV facade; cross-peer search; `Inbox/` write support (post-v1).
