# Kirowen: envelope, leaf and checkpoint format (v0)

**Status:** Draft v0, for the proof of concept. It may change before v1.
**Date:** 2026-11-17
**Context:** `docs/technical-analysis.md`. The decisions summarized here are recorded there (§16).

---

## 1. Design choices

| Choice | Decision | Why |
|---|---|---|
| Serialization | **Deterministic CBOR** (RFC 8949 §4.2.1, core deterministic encoding) | Compact, binary-safe and byte-for-byte reproducible, so signatures and hashes are stable. It is the format used by SCITT (RFC 9943). |
| Signature container | **COSE_Sign1** (RFC 9052) | Standard and close to SCITT signed statements. Go libraries exist (`fxamacker/cbor`, `veraison/go-cose`). Full SCITT conformance is evaluated later and not claimed. |
| Signature algorithm | **Ed25519** (COSE `alg` = -8, EdDSA) | Fast, small (64-byte signatures), deterministic and widely supported. |
| Hash function | **SHA-256** | Required for compatibility with RFC 6962/9162 and C2SP. |
| Tree | RFC 6962 Merkle tree, via **Trillian Tessera** | Leaf hash = `SHA-256(0x00 ‖ leaf_bytes)`, interior node = `SHA-256(0x01 ‖ left ‖ right)`. |
| Signed tree heads | **C2SP `tlog-checkpoint`** over **`signed-note`** | Understood by existing witnesses and tooling. |
| Algorithm agility | Every digest and signature carries an algorithm identifier | Allows migration (e.g. post-quantum) without breaking history. |

---

## 2. Identifiers

| Identifier | Format | Assigned by |
|---|---|---|
| `source_id` | 16 random bytes | Registry, at source registration |
| `object_id` | 16 random bytes | Registry, through an explicit "create object" call. Random rather than time-based (UUIDv7), to avoid leaking creation times. |
| `key_id` | `SHA-256(public_key)`, 32 bytes | Derived |
| `envelope_hash` | `SHA-256(COSE_Sign1 bytes)`, 32 bytes | Derived. It is the canonical identifier of an event before it is sequenced. |
| `leaf_index` | uint64 position in the log | Sequencer |

The system source (key registrations, rotations and revocations) uses the reserved `source_id` of 16 zero bytes.

---

## 3. Envelope

An envelope is a **COSE_Sign1** structure signed by the source.

### 3.1 Protected header

| Label | Name | Value |
|---|---|---|
| 1 | `alg` | -8 (EdDSA / Ed25519) |
| 3 | `content type` | `"application/vnd.kirowen.envelope+cbor"` |
| 4 | `kid` | `key_id` (32 bytes) |

### 3.2 Payload

A CBOR map with integer keys, encoded deterministically:

| Key | Name | Type | Required | Meaning |
|---|---|---|---|---|
| 1 | `v` | uint | yes | Envelope version. Always `1` for now. |
| 2 | `src` | bstr (16) | yes | `source_id`. Must match the source that owns `kid`. |
| 3 | `obj` | bstr (16) | yes | `object_id`. It must belong to `src`. |
| 4 | `oseq` | uint | yes | Per-object sequence number. `0` for the object's first event; each later event adds exactly 1. |
| 5 | `prev` | bstr (32) | if `oseq > 0` | `envelope_hash` of the object's previous event. |
| 6 | `kseq` | uint | yes | Per-key sequence number. Starts at `0` and increases by exactly 1 with every envelope signed by that key. |
| 7 | `time` | int | no | Time declared by the source, in milliseconds since the Unix epoch. Never validated by the registry. |
| 8 | `digest` | [int, bstr] | yes | `[alg, value]`. `alg` is a COSE hash algorithm id (-16 = SHA-256), and `value` must have that algorithm's exact length (32 bytes for SHA-256). |
| 9 | `refs` | [bstr (32)] | no | Up to 8 `envelope_hash` values of related events, e.g. the event being corrected. |

The payload deliberately carries **no plain data**. No event type, no labels and no content: anything meaningful goes inside the hashed content, which only the source keeps.

### 3.3 Acceptance rules

The registry accepts an envelope only if **all** of the following hold:

1. It decodes as deterministic CBOR and is at most **1 KiB**.
2. The signature verifies with the key `kid`, and that key is active for `src` at the current tree size (§6).
3. `obj` exists and belongs to `src`.
4. `oseq` equals the object's last `oseq` plus 1 (or `0` for a new object), and `prev` equals the `envelope_hash` of that last event.
5. `kseq` equals the key's last `kseq` plus 1.
6. `digest.value` has the exact length required by `digest.alg`, and `alg` is supported.
7. Every hash in `refs` is an envelope already in the log. In v0, references are limited to the same source.
8. The source is within its quota.

**Idempotency:** a retried envelope has identical bytes and therefore an identical `envelope_hash`. The registry returns the original confirmation, so no separate idempotency key is needed.

**Concurrency on one object:** rules 4 and 5 give optimistic concurrency. If two writers race on the same object, one wins and the other gets a conflict error, re-reads the object head and re-signs.

A source with several independent writers should give each writer its own key, so `kseq` never has to be coordinated between them.

### 3.4 Encoding details

These points were fixed while implementing the proof of concept (`envelope/`):

- The envelope is a **tagged** COSE_Sign1 message (CBOR tag 18). Untagged messages are rejected.
- The **unprotected header must be an empty map**, so every header value is covered by the signature.
- **Detached payloads are not allowed.** `external_aad` is empty.
- **Strict decoding:** every layer (the message, the protected header and the payload) is accepted only if re-encoding the decoded value reproduces the input byte for byte. This rejects unsorted keys, non-shortest integers, indefinite lengths, unknown keys, missing required keys and trailing bytes.
- Optional fields are **absent**, never empty. For example, `refs` with zero entries is rejected, and `prev` must be absent when `oseq = 0`.
- Test vectors (fixed Ed25519 seeds, so they are reproducible): `envelope/testdata/vectors.json`.

### 3.5 Content digest (client side)

The recommended construction, applied by the client library:

```
digest = SHA-256( salt ‖ canonical(content) )
salt   = 32 random bytes, kept by the source together with the content
```

- `canonical(content)` is the RFC 8785 canonical JSON form if the content is JSON. Otherwise it is the exact bytes as the source stores them.
- The registry never sees `salt` or `content` and cannot distinguish a salted digest from an unsalted one. Salting is the source's responsibility.

---

## 4. Leaves

Each leaf is a deterministic CBOR array:

```
leaf = [ 1, type, body ]          ; 1 = leaf format version
```

| `type` | Name | `body` | Counts as ordinary? |
|---|---|---|---|
| 1 | `event` | `envelope_hash` (32 bytes) | **Yes** |
| 2 | `checkpoint` | checkpoint map (§5.1) | **No** |

Key events from the system source are `event` leaves and count as ordinary.

The leaf hash is computed by the tree as `SHA-256(0x00 ‖ leaf_bytes)`.

Public leaves reveal only that an event with a given `envelope_hash` exists. They reveal neither source, object nor content.

---

## 5. Checkpoints

### 5.1 Internal checkpoint leaf (every 1,000 ordinary events)

After every 1,000 ordinary leaves, the sequencer appends a `checkpoint` leaf. Its body is:

| Key | Name | Type | Meaning |
|---|---|---|---|
| 1 | `size` | uint | Tree size `N` being certified, i.e. every leaf before this one. |
| 2 | `root` | bstr (32) | Root hash of the tree of size `N`. |
| 3 | `prev_size` | uint | `size` of the previous checkpoint leaf (`0` for the first). |
| 4 | `prev_root` | bstr (32) | `root` of the previous checkpoint leaf (absent for the first). |
| 5 | `note` | bstr | The signed C2SP checkpoint for size `N`, as sent to witnesses, with any cosignatures already collected. |

Validation: `root` and `prev_root` are 32 bytes, `size > prev_size`, `prev_root` is present exactly when `prev_size > 0`, and `note` is not empty.

Implementation note: before it can append the checkpoint leaf at position `N`, the sequencer must have integrated exactly `N` leaves. It therefore pauses intake for one batch every 1,000 ordinary events. The cost is negligible.

### 5.2 Published tree heads (external)

- Format: C2SP `tlog-checkpoint` signed by the registry key (`signed-note`). The origin line is `<domain>/log/v0`; the domain depends on the final name.
- **No-self-validation rule:** a new tree head is published only if at least one ordinary leaf has been added since the last published one.
- A tree head is published every `T` seconds (§7) and sent to witnesses using C2SP `tlog-witness`.

---

## 6. Source keys

- **Registration:** the registry creates the source, then appends a system-source event registering its first public key. That event's `digest` is the hash of a key statement `{source_id, public_key, alg, action: "add"}`, and the registry publishes the statement so anyone can check the digest.
- **Rotation and revocation:** the source signs a key statement with a currently active key. The registry appends it as a system-source event.
- **Key validity:** a key is valid for `src` from the leaf that registers it until the leaf that revokes it. This makes "which key was valid at tree size `N`" verifiable.

---

## 7. Initial parameters

All values are configurable. These are the defaults for the proof of concept.

| Parameter | Value | Notes |
|---|---|---|
| Batch window | 1 s or 1,024 entries, whichever comes first | Gives ~1 s confirmation latency. |
| Confirmation | Synchronous: returned once the event is in a registry-signed tree head | Witness cosignature follows within `T`. |
| Internal checkpoint | Every 1,000 ordinary leaves | Concept decision 11. |
| Tree head publication `T` | 60 s, only if new ordinary leaves exist | |
| Witness policy | 1 of `n` trusted witnesses (`k` = 1) | Raise `k` as more witnesses join. |
| Max envelope size | 1 KiB | A typical envelope is around 250 bytes. |
| Max `refs` per envelope | 8 | |
| Default quota per source | 10 events/s sustained, burst of 100, 100,000 events/day | Can be raised on request. |
| Max objects per source | 1,000,000 | Can be raised on request. |
| Search tags per object | Up to 16 tags; key ≤ 32 bytes, value ≤ 128 bytes | Outside the envelope (§8). |
| Envelope retention | The source chooses, up to **5 years** (default 5) | §9. |

---

## 8. Search metadata (tags)

- **Tags are not part of the envelope.** They live in a mutable per-object index, outside the tree and outside any signed structure.
- That allows them to be changed or deleted at any time without affecting verification, which matters for the GDPR.
- Only the owning source can read and search them.
- **The client library blind-indexes them by default:** each key and value is replaced by `HMAC-SHA-256(source_tag_key, x)` truncated to 16 bytes. The registry stores and matches opaque values and never sees the real tag. Only exact-match search is possible.

---

## 9. Retention

- **Tree (leaves, checkpoints, tiles): kept forever.** It is tiny (about 40 bytes per event) and is what makes the history verifiable.
- **Envelopes:** the source chooses a retention period, up to **5 years**. When it expires, the registry deletes the envelope, and the leaf (and so the proof of existence) remains.
- **Tags:** deleted on request, or with the object.
- **Self-sufficient proofs:** every confirmation returns the envelope, its leaf index, the signed tree head and the inclusion proof. If the source archives that bundle, it can prove the event to anyone forever, even after the registry has deleted the envelope.
- **Why 5 years and not forever:** the maximum can always be raised later, even to "forever", but it cannot be lowered without breaking a promise. Cost is not the reason: envelopes are about 250 bytes each.

---

## 10. Confirmation bundle

The registry's response to an accepted envelope:

| Field | Content |
|---|---|
| `envelope_hash` | 32 bytes |
| `leaf_index` | uint64 |
| `tree_head` | Signed C2SP checkpoint that includes the leaf |
| `inclusion_proof` | List of sibling hashes |

The source should store this bundle together with the envelope, its content and its salt.
