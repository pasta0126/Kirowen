# Kirowen: HTTP API (v0)

**Status:** Draft v0, alpha. **Date:** 2026-11-18.
**Base URL:** `https://kirowen-api.northernarchive.com`
**Public log:** `https://kirowen.northernarchive.com/log/v0/` (static C2SP tiles, no API needed to read or verify it)

---

## 1. Model

- **Self-service registration.** Anyone can register a source. Registration needs no account and no operator action, and happens only through the API.
- **Token per source.** Registration returns a bearer token, shown once. The registry stores only its SHA-256.
  - **Required** to write (objects, events) and to read private data (envelopes, object histories, sequence numbers).
  - **Optional** elsewhere. Without a token, a caller is anonymous and sees only public data.
- **The token is not the proof of origin.** Every event is still an envelope signed with the source's Ed25519 key (`docs/envelope-v0.md`). The token says who is calling (quotas, ownership); the signature proves who made the statement. The operator holds tokens' hashes but never source keys, so it cannot forge events.
- **Key registrations are logged.** Registering a source appends a system-source event whose digest is the hash of a key statement (`docs/envelope-v0.md` §6). The statement is public at `GET /v0/keys/{key_id}`.

Header: `Authorization: Bearer kw_…`. Errors are JSON: `{"error": "…"}`, sometimes with extra fields.

CORS is open (`Access-Control-Allow-Origin: *`): any web page may call the API. This is safe because the token travels in a header, never in a cookie, so a page can only act with a token it already holds. The website (`web/`, served at `https://kirowen.northernarchive.com/`) offers browser registration and an interactive console (`/docs/`, Swagger UI over `web/openapi.yaml`).

## 2. Endpoints

| Method and path | Token | Purpose |
|---|---|---|
| `GET /v0/` | no | Origin, log URL, system key id, limits |
| `POST /v0/sources` | no | Register a source (§3) |
| `GET /v0/sources/me` | yes | Source id, keys with their next `kseq`, object count |
| `POST /v0/objects` | yes | Create an object; returns a registry-assigned `object_id` |
| `GET /v0/objects/{object_id}` | yes, owner | Head (`next_oseq`, `last_hash`) and history (`oseq`, `envelope_hash`, `leaf_index`) |
| `POST /v0/events` | yes | Submit an envelope (body: COSE_Sign1 bytes, ≤ 1 KiB). Returns the confirmation |
| `GET /v0/events/{envelope_hash}` | no | Confirmation (leaf index, tree head, inclusion proof) for a known hash |
| `GET /v0/leaves/{index}` | no | Any leaf (event or checkpoint) by position, with a tree head and inclusion proof (`docs/explorer-v0.md` §4) |
| `GET /v0/envelopes/{envelope_hash}` | yes, owner | The envelope bytes |
| `GET /v0/keys/{key_id}` | no | Key statement; `next_kseq` only for the owner |

Ids and hashes are hex in paths and JSON. Byte strings (keys, statements, proofs) are base64 in JSON.

## 3. Registration

```
POST /v0/sources
{"public_key": "<base64 Ed25519 public key>", "proof": "<base64 signature>"}
```

`proof` is the key's signature over:

```
kirowen register v0\n<origin>\n<hex public key>\n
```

The origin (from `GET /v0/`) binds the proof to this log. Response `201`:

```json
{"source_id": "…", "key_id": "…", "token": "kw_…", "registration": { confirmation }}
```

## 4. Submitting events

The client reads the heads, signs and submits:

1. `GET /v0/objects/{id}` → `next_oseq`, `last_hash` (becomes `prev`).
2. `GET /v0/sources/me` → the key's `next_kseq`.
3. Sign the envelope and `POST /v0/events`.

Responses:
- `200` with the confirmation, once the event is covered by a signed tree head (about 1 s).
- `409` if a head moved (`next_oseq`/`last_hash` or `next_kseq` in the body): re-read and re-sign.
- `403` if the envelope's `src` is not the token's source, the key is not the source's, or the object belongs to another source.
- `429` on quota or rate limits.

**Idempotency:** resending identical bytes returns the original confirmation.

## 5. Limits (initial)

| Limit | Value |
|---|---|
| Events per source | 10/s sustained, burst 100, 100,000 per UTC day |
| Objects per source | 1,000,000 |
| Registrations | 5 per IP per hour, 200 per day overall |
| Envelope size | 1 KiB |

## 6. Not yet

- Key rotation and revocation, token rotation.
- Retention choice per source (the 5-year maximum is not yet enforced by a deletion job).
- Search tags (`docs/envelope-v0.md` §8).
