# Kirowen: latest leaves and log explorer (v0)

**Status:** Draft v0, alpha. **Date:** 2026-11-21.

This document specifies two read-only views of the public log on the website, and the one API endpoint they need:

1. **Latest leaves:** a strip on the landing page with the last 5 leaves of the log.
2. **Explorer:** a page at `/explorer/` that shows one leaf, looked up by position or by envelope hash, and verifies it in the browser.
3. **`GET /v0/leaves/{index}`:** a public endpoint that returns any leaf with an inclusion proof.

Nothing here changes the log, the leaf format or what is public. Both views show only data that is already public in the tiles (`docs/envelope-v0.md` §4).

---

## 1. What is shown, and what is not

| Shown (public) | Not shown (private by design) |
|---|---|
| Leaf position, type (`event` or `checkpoint`) | Source, object, `oseq`, `kseq`, `prev` |
| Event leaf: `envelope_hash` | Declared time, content type, content digest |
| Checkpoint leaf: `size`, `root`, `prev_size`, `prev_root`, the signed note and its signers | The envelope (owner only, `GET /v0/envelopes/{hash}`) |
| The leaf hash, the tree head and the inclusion proof | The content (never held by the registry) |

Leaves carry no timestamp. The only time-like data is the order of leaves. The explorer must not show a time for an event or suggest that one is known.

The explorer states this on the page: an event leaf proves that *some* signed envelope with this hash was logged at this position; only the source can show what it says.

## 2. Latest leaves (landing page)

- **Placement:** under the "Live log" bar in the hero.
- **Data source:** the public tiles only, no API call. On each checkpoint refresh (every 15 s, as today) the page reads `size` from `/log/v0/checkpoint` and fetches the entry bundle(s) that hold leaves `[max(0, size−5), size)`, at most two bundles.
- **Card per leaf, newest first:** position, a type chip (event / checkpoint), and either the short `envelope_hash` (event) or `certifies size N` (checkpoint). Each card links to `/explorer/?leaf=<position>`.
- **Motion:** when the size grows, new cards slide in from the left and old ones drop off the right. With `prefers-reduced-motion`, cards are replaced without animation.
- **Empty or failed:** if the log is empty, the strip says so. If a fetch fails, the strip is hidden, like the live bar.
- **No claim of verification** on the landing page: it only displays. Verification happens in the explorer.

## 3. Explorer (`/explorer/`)

### 3.1 Lookup

- A single search field takes either a **position** (decimal) or an **envelope hash** (64 hex digits).
- URL parameters: `?leaf=<position>` or `?hash=<hex>`, so that a view can be linked. With no parameter, the explorer shows the latest leaf.
- Navigation: *previous*, *next* and *latest*.
- Lookup by hash calls `GET /v0/events/{hash}` (exists, public) to get the position, then continues as a lookup by position.

### 3.2 Data flow for a leaf at position `i`

1. Read the current checkpoint from `/log/v0/checkpoint`. If `i ≥ size`, show "no such leaf yet".
2. Read the leaf bytes from the public entry bundle (tiles). **This is the copy that is verified.**
3. Call `GET /v0/leaves/{i}` (§4) for a tree head and an inclusion proof.
4. Verify (§3.3) and render.

The API is not trusted: everything it returns is checked against the tiles and the pinned log key.

### 3.3 Checks shown to the user

Each check is listed with ✓, ✗ or "not checked" and a one-line reason.

| # | Check | How |
|---|---|---|
| 1 | Tree head signature | The tree head is a C2SP signed note. Its signature line for the log origin verifies with the **pinned** log key (`keys-public/`, embedded in the page script) using WebCrypto Ed25519. If the browser lacks Ed25519, the check is "not checked". |
| 2 | Tree head origin | First line equals `kirowen.northernarchive.com/log/v0`. |
| 3 | Same leaf | The leaf bytes returned by the API equal the bytes in the tiles. |
| 4 | Inclusion | `SHA-256(0x00 ‖ leaf)` and the proof reproduce the tree head root (RFC 9162 §2.1.3.2). |
| 5 | Leaf format | The leaf decodes as `[1, type, body]` (`docs/envelope-v0.md` §4) with a valid body. |
| 6 | Checkpoint leaf only | `body.size == i`; the embedded note has the log origin, the same size and root as the body, and a valid log signature. Cosignatures from other keys are listed as "unknown signer", not verified. |

Not checked in v0: consistency between the tree head from the API and the checkpoint the page read in step 1 (they may differ in size), and witness cosignatures. The CLI (`kirowen verify`, `kirowen audit`) remains the way to check those.

### 3.4 Rendering

- **Event leaf:** position, `envelope_hash`, leaf hash, the checks, and the note from §1. If the envelope hash is the subject of a known key statement, linking it is out of scope for v0.
- **Checkpoint leaf:** position, the certified `size` and `root`, a link to the previous checkpoint leaf (`?leaf=<prev_size>`, absent for the first), the note text, its signers, and the checks.
- The tree head used for the proof is shown with its size and root, and the proof as a list of hashes (collapsed by default).

### 3.5 Honesty about the trust model

The page says, near the checks, that the verification runs in code served by the operator, so it is only as independent as that code. Independent verification means running the open-source CLI, or a copy of this page, with the published log key. This follows the rule of stating trust assumptions (`AGENTS.md`).

## 4. API: `GET /v0/leaves/{index}`

Public, no token.

**Request:** `index` is a decimal leaf position.

**Response `200`:**

```json
{
  "leaf_index": 1234,
  "leaf": "<base64 leaf bytes>",
  "tree_head": "<signed C2SP checkpoint, as text>",
  "inclusion_proof": ["<base64>", "..."]
}
```

The tree head is the latest published one that covers the leaf; it is the same one `GET /v0/events/{hash}` would return.

**Errors:** `400` if `index` is not a decimal integer; `404` if `index ≥` the integrated tree size.

It returns only public data (the leaf is in the tiles; the proof can be rebuilt from them). It exists so that browsers do not have to rebuild proofs from hash tiles, and it serves checkpoint leaves, which have no envelope hash and so cannot be looked up through `GET /v0/events/{hash}`.

`web/openapi.yaml`, `docs/api-v0.md` and the Postman collection list the new endpoint.

## 5. Implementation notes

- **Shared script** `web/assets/log.js`: checkpoint parsing, signed-note verification, tile paths, entry bundle parsing, a minimal deterministic CBOR decoder (uint, bstr, tstr, array, map), SHA-256 and inclusion verification. Used by the landing page and the explorer.
- **Tile paths** follow C2SP tlog-tiles: the bundle index `n = ⌊i / 256⌋` is written in 3-digit groups, all but the last prefixed with `x` (e.g. `x001/x234/067`). A bundle that is not full is at `tile/entries/<n>.p/<w>`, with `w = size − 256·n`. A bundle is a sequence of entries, each a 2-byte big-endian length and the leaf bytes.
- **Big numbers:** positions and sizes are handled as `BigInt` in proof verification, because JavaScript bit operations are 32-bit.
- **No new origins:** the CSP already allows `'self'` and the API. No external libraries.
- **Registry:** a `Leaf(ctx, index)` method returns the raw leaf bytes and a confirmation, reusing `Prove`.

## 6. Out of scope (v0)

- Listing or searching events by source, object or time (no such public data exists).
- Labelling key-registration events from the system source.
- Consistency proofs and witness cosignature checks in the browser.
- Pagination beyond previous/next.
