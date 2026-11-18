# Kirowen: technical analysis of the concept

**Version:** 0.1
**Date:** 2026-11-17
**Based on:** Concept document "Universal Immutable Event Registry", v0.1 (`docs/concept-v0.1.md`)
**Status:** Proposal for discussion. Unless marked **Accepted**, nothing recommended here has been decided.

---

## 0. Executive summary

1. **The model is coherent and viable.** It has no fundamental contradictions. It does have specific tensions (privacy vs. immutability, a global chain vs. isolation, free service vs. abuse), and each one has a known solution.

2. **No blockchain is needed.** The problem described matches almost exactly the one solved by **transparency logs**: Certificate Transparency (RFC 6962 / RFC 9162), Sigstore Rekor, the Go Checksum Database and Sigsum. These have run in production for years, at a scale of billions of entries and at low cost.

3. **Core proposal:** an append-only log built on a **Merkle tree**, with a single sequencer and these parts:
   - **signed checkpoints**;
   - logarithmic-size **inclusion and consistency proofs**;
   - **external witnesses** that cosign checkpoints;
   - **events signed by their sources**;
   - **content stored outside the log**, which holds only cryptographic commitments.

4. **Protection against a malicious administrator (scenario 6) cannot come from the system itself.** It requires something the operator does not control: witnesses, public anchoring, or verifiers that keep checkpoints. This is the most important part of the design, and one of the cheapest.

5. **A linear hash chain is necessary but not sufficient.** A Merkle tree serves the same purpose and also provides compact proofs, true incremental verification and privacy-preserving verification.

6. **Main risks:**
   - the operator omitting or censoring events;
   - split view (showing different histories to different clients);
   - GDPR compliance;
   - metadata leaking through the global chain;
   - abuse of a free service;
   - an unprotected window between checkpoints when traffic is low.

---

## 1. Coherence of the model

### 1.1 What holds without changes

| Principle | Assessment |
|---|---|
| Append-only; corrections are new events | Correct and standard. |
| Content-agnostic registry | Correct, and it greatly simplifies the system. |
| Single global sequence | Viable with a single logical sequencer, which is what every transparency log does. |
| Declared time vs. acceptance time | Essential and well framed. |
| Integrity, truthfulness, availability and durability kept separate | The right distinction. Many projects fail by mixing them up. |
| Registry truth vs. real-world truth | Correct. It avoids promising the impossible. |
| Decentralization is not a goal in itself | Correct. It lets us choose the cheapest solution that delivers the guarantees. |

### 1.2 Tensions the design must resolve

**T1. Global chain vs. isolation between participants (concept §6, §13).**
If every link contains the full event, verifying the chain means seeing everyone's events. The fix is for log leaves to contain **commitments** (salted hashes) instead of content. Global verification then works on hashes, and only authorized parties see the content. See §7.

**T2. Immutability vs. legal erasure obligations (concept §13, §15).**
The GDPR (Art. 17) may require personal data to be erased. An immutable log holding personal data in clear text would be incompatible with that. The fix is the same separation: content lives outside the tree and can be deleted or crypto-shredded, while the leaf keeps the commitment. The history stays verifiable ("an event with this hash existed here") even when the content is gone. This needs legal review, because a hash of personal data may still count as pseudonymized data.

**T3. Per-object linkage vs. metadata privacy (concept §6, §13).**
Linking an object's events publicly reveals patterns to anyone who can see the log: how many events a shipment has, how often they arrive, when they stop. If the log is public, the per-object linkage must be opaque to unauthorized parties (§6.3).

**T4. One checkpoint per 1,000 events vs. low traffic (concept §8).**
The decision is sound at high volume. At low volume (say, 50 events a day) a checkpoint takes 20 days to appear, and recent events stay unanchored externally the whole time. This analysis does not propose changing the decision, but **complementing** it with periodic publication of signed tree heads to witnesses (§5.4, **accepted**).

**T5. Free service vs. abuse (concept §17).**
A service that accepts writes for free and keeps them forever is a natural target for spam and free-storage abuse. Without quotas, source authentication and size limits, cost is unbounded. This is the most serious economic risk.

### 1.3 Assumptions worth correcting or tightening

- **"Producing a valid-looking version requires recomputing all later references" (concept §5).** Recomputation takes milliseconds, so it is no barrier. The only real barrier is that someone outside kept the earlier state. The concept already says so in its "acknowledged limitation", but recomputation should not be presented as an obstacle in its own right.

- **"The source must be authenticated" (concept §10).** Authentication, such as an API token, only proves to the server who is calling. It does not stop the operator from **forging** events in a source's name. For "registry truth" (concept §12) not to depend on the operator, **the source must sign every event** with its own key.

- **"A checkpoint represents the accumulated state" (concept §8).** With a Merkle tree, the root at any size already represents that state. A checkpoint is not extra computation; it is **signing and publishing** that root. Its value depends on where the signature ends up, not on computing it.

- **"Verify without walking the history" (concept §8, scenario 7).** With a linear chain plus checkpoints, proving that a given event is included still means walking the segment. With a Merkle tree the proof is about `log₂(n)` hashes (around 30 hashes for a billion events), and nothing has to be walked.

---

## 2. Threat model

A guarantee only means something against a specific adversary.

| Actor | Capability | What it might attempt |
|---|---|---|
| **Registry operator** (including a malicious or compromised admin) | Full control of servers, database and service keys | Modify or delete events; rewrite the whole history; forge events; omit events; show different histories to different clients; delay acceptance; leak content |
| **Source** | Its own key and API access | Register false statements; deny having registered something; flood the service; retry and cause duplicates |
| **Another source** | Its legitimate access | Read or infer others' data; impersonate another source |
| **External attacker** | Network access; possibly stolen credentials | Impersonate sources; tamper with messages in transit; compromise the server (and so gain the operator's capabilities) |
| **Consumer / verifier** | Whatever it is given; checkpoints it has stored | The potential victim: it must detect tampering without trusting the operator |

**Minimal trust assumptions of the proposal:**
- The hash functions and signature schemes used are secure.
- Only each source holds its own private key.
- **At least one** of the external witnesses the verifier accepts is honest and available.
- The verifier stores, or can obtain, cosigned checkpoints.

If the third assumption fails (there are no witnesses, or they all collude with the operator), scenario 6 **cannot** be guaranteed. No design can prevent that.

---

## 3. Real vs. apparent guarantees

| Claim | Real? | Condition |
|---|---|---|
| "Modifying an event breaks the chain" | **Real**, against anyone holding a checkpoint later than the event. | Without an external checkpoint, the operator can recompute everything. |
| "History cannot be rewritten" | **Apparent** with chaining alone. **Real** (as detection, not impossibility) with witnesses or external anchoring. | Honest witnesses and verifiers that cross-check. |
| "Source X registered this event" | **Apparent** with token authentication. **Real** if the source signs the event. | Source key not compromised; verifiable key registry. |
| "The content is correct" | **Not guaranteed**, as the concept acknowledges (§12). | — |
| "The registry holds all of the source's events" | **Not guaranteed** by default. The operator can silently drop events. | Mitigated with signed receipts and per-source sequence numbers (§5.6). |
| "This object's history is complete" | **Partial.** Back-links prove there are no gaps, not that the latest event was returned. | Strong completeness needs a verifiable map (§6.2). |
| "Everyone sees the same history" | **Apparent** without witnesses. This is the split-view attack. | Witnesses or checkpoint gossip. |
| "The event happened at time T" | **Not guaranteed.** It is the source's claim. | — |
| "The registry accepted the event before time T" | **Real** if the checkpoint that includes it is anchored to an external time source (timestamping witness, RFC 3161 or OpenTimestamps). | Trustworthy time source. |
| "The data will always be available" | **Not guaranteed.** Integrity does not imply availability. | Replicas, mirrors and a retention policy. |
| "Verifying reveals nothing about others" | **Real** if leaves are salted commitments. | Correct leaf design (§7). |

---

## 4. Technology alternatives

### 4.1 Options evaluated

**A. Conventional database + linear hash chain.**
An append-only table in which each row includes the hash of the previous one.
- Pros: trivial to build and cheap.
- Cons: no guarantees against the operator; inclusion proofs are linear; no compact consistency proofs.
- Verdict: insufficient on its own. It works as underlying storage, not as a trust mechanism.

**B. Merkle-tree transparency log (RFC 6962/9162, C2SP ecosystem).**
An append-only Merkle tree with signed checkpoints, inclusion and consistency proofs, and witnesses.
- Pros:
  - Designed for exactly this case: the operator is not trusted, but tampering must be detectable.
  - Built on open specifications (C2SP: `signed-note`, `tlog-checkpoint`, `tlog-tiles`, `tlog-witness`, `tlog-cosignature`) and mature libraries (Trillian Tessera in Go, Sigsum).
  - Can be served as **static files** (tiles) from object storage or a CDN, which is very cheap.
  - Logarithmic proofs.
- Cons:
  - Does not solve per-object history or privacy by itself; those must be designed on top.
  - Existing public witnesses target logs with a particular profile. We need to confirm whether they would accept this log, or whether we would have to run our own witnesses together with third parties.
- Verdict: **recommended** as the core.

**C. Immutable / verifiable database (e.g. immudb).**
A database with an internal Merkle tree and proofs.
- Pros: fewer custom components; database-style queries.
- Cons:
  - Ties the project to a specific product, and independent verification depends on that product's format.
  - External witnesses are not a first-class concept.
  - Amazon QLDB, the commercial reference in this category, was discontinued in 2025, which shows the risk of depending on a product.
- Verdict: viable, but B gives the same guarantees with open standards and no lock-in.

**D. Permissioned blockchain (e.g. Hyperledger Fabric).**
- Pros: replication across organizations.
- Cons: high operational complexity, high cost, and it requires cross-organization governance. If the same operator controls every node, it adds nothing over B.
- Verdict: not justified at this stage. It only makes sense if several organizations want to co-administer the registry, and even then B's witnesses are usually enough.

**E. Public blockchain as event storage.**
- Cons:
  - Every write has a transaction fee, contradicting concept §17 and §18.
  - It is slow.
  - Everything is public, contradicting §13.
  - Nothing can be erased, contradicting the GDPR.
- Verdict: rejected.

**F. Public blockchain only as a checkpoint anchor.**
Periodically publish a checkpoint hash to a public chain, e.g. via OpenTimestamps, which is free and aggregates many hashes into a single Bitcoin transaction.
- Pros: a proof of existence in time that is very hard to forge; near-zero cost; no data exposed.
- Cons: slow confirmation (hours); depends on an aggregator service and on the chain.
- Verdict: **recommended complement** to B, as an additional witness mechanism. There is no token involved, and the system does not depend on it to operate.

### 4.2 Comparison

| Criterion | A | **B** | C | D | E | **F** (complement) |
|---|---|---|---|---|---|---|
| Detects rewrites by the operator | No | **Yes** (with witnesses) | Partial | Partial | Yes | **Yes** |
| Compact proofs | No | **Yes** | Yes | Varies | Varies | — |
| Content privacy | Custom design | **Custom design** (compatible) | Custom design | Yes | No | **Yes** |
| GDPR-compatible | Yes | **Yes** (content kept separate) | Yes | Complex | No | **Yes** |
| Operating cost | Very low | **Low** | Low–medium | High | Very high | **Near zero** |
| Complexity | Very low | **Medium** | Medium | High | Medium | **Low** |
| Open standards | — | **Yes** | Partial | Yes | Yes | **Yes** |
| No token / crypto | Yes | **Yes** | Yes | Yes | No | **Yes** (no token to handle) |

---

## 5. Independent verifiability mechanisms

### 5.1 Append-only Merkle tree

Every accepted event becomes a **leaf** of the tree, at the position the sequencer assigns. The root of a tree of size `N` cryptographically summarizes its first `N` leaves.

- **Inclusion proof:** shows that leaf `i` is in the tree of size `N` with root `R`. It takes about `log₂(N)` hashes.
- **Consistency proof:** shows that the tree of size `N₂` with root `R₂` **extends** the tree of size `N₁` with root `R₁`, i.e. nothing earlier was modified. It also takes about `log₂(N₂)` hashes.

With these two proofs, a verifier that stored `(N₁, R₁)` can check any later state without downloading the history. That is exactly scenario 7.

**On chaining (concept decision 4):** a Merkle tree fulfils the purpose of cryptographic chaining with better properties. Every state depends on all previous ones, and altering any event changes every later root. Each leaf could also carry the previous leaf's hash so the linear chain is literal, but that adds a field without adding any guarantee. **This analysis proposes Merkle without an explicit linear link**, but that is the team's decision.

### 5.2 Signed checkpoints

A checkpoint is a statement signed by the registry: "the tree has size `N` and root `R`". Suggested format: C2SP `tlog-checkpoint` over `signed-note`. It is plain text, existing libraries can verify it, and witnesses understand it.

**Fit with concept decision 11 (one checkpoint per 1,000 ordinary events):**
- After every 1,000 ordinary events, the system appends a **checkpoint leaf** containing the signed checkpoint of the tree at that size. The leaf takes its own position in the sequence and does not count toward the 1,000.
- A checkpoint leaf at position `N+1` certifies the tree of size `N`. It cannot certify itself, and that is fine.
- Each checkpoint references the previous one (size and root), which provides the "verifiable continuity between checkpoints" that concept §8 requires. A consistency proof between the two makes it checkable.

**Important:** a checkpoint leaf inside the log **adds no trust on its own**, as concept §8 already warns. Trust comes from the copy of that checkpoint that witnesses **cosigned and that is stored outside**.

### 5.3 External witnesses

A witness is an independent service with these rules:
1. It receives a new checkpoint plus a consistency proof against the last checkpoint it cosigned for that log.
2. It cosigns only if the proof is valid, i.e. the log has rewritten nothing.
3. It stores the last checkpoint it cosigned and never cosigns an incompatible history.

A verifier accepts only checkpoints with at least `k` cosignatures from witnesses it trusts. As a result:
- An operator that rewrites history cannot get cosignatures for the new version, so verifiers reject it (**scenario 6**).
- An operator that shows different histories to different clients (split view) would need witnesses to cosign both versions, which they will not do.

Suggested specs: C2SP `tlog-witness` and `tlog-cosignature`. Ways to obtain witnesses, from most to least preferable:
1. Public witness networks in the C2SP/Sigsum ecosystem, if they accept this log. **To be confirmed.**
2. Participating organizations running a witness, which is a very lightweight process.
3. Witnesses run by sympathetic third parties (universities, foundations).
4. At a minimum, anchoring in OpenTimestamps (§4.1 F) and publishing the checkpoint to a public repository with history (e.g. a git repository mirrored across several hosting platforms).

### 5.4 Periodic publication of signed tree heads — **Accepted (2026-11-17)**

To close the unanchored window at low volume (T4) **without modifying decision 11**, the design separates two concepts:
- **Checkpoint (internal leaf):** one per 1,000 ordinary events, as decided.
- **Published tree head (external):** a signed checkpoint of the tree's current size, sent to witnesses every `T` seconds (e.g. `T` = 60 s). It is not inserted into the log.

No ordinary event then remains uncosigned for more than `T` seconds, and the sequence of internal checkpoints keeps following the agreed rule.

**No-self-validation rule — Accepted (2026-11-17).** Only ordinary events trigger a validation; a validation event never triggers another one. Concretely:

- **Tree head:** published only if there is **at least one new ordinary event** since the last published tree head. If the only thing appended since then is a checkpoint leaf, nothing is published.
- **Internal checkpoint:** counts only ordinary events (decision 11), so a checkpoint can never trigger another.
- **Consequence:** the system never produces an infinite chain of records validating one another. If no ordinary events arrive, the log stays idle: it does not grow and consumes no resources.

**Caveat:** a checkpoint leaf that lands at the very end of a burst stays uncosigned until the next ordinary event arrives and a new tree head is published. This is harmless. That leaf contains no source data, only the checkpoint of the previous tree. That checkpoint already went to the witnesses as a tree head, and any verifier can check the leaf against it.

### 5.5 Monitors

A monitor is a verifier that follows the entire log: it downloads every public leaf, recomputes the tree and checks consistency. It catches problems such as malformed leaves or incorrect internal checkpoints. Because leaves contain only commitments (§7), a monitor never sees private content. Anyone can run one, and the tool should be part of the project.

### 5.6 Receipts and protection against omission

Problem: the operator can accept an event and then never incorporate it.

Mitigations:
1. **Signed receipt.** On acceptance, the registry returns a signed receipt with the leaf hash, the assigned position and the acceptance time, plus a promise to incorporate the event within a maximum delay. This is the equivalent of a Certificate Transparency SCT. If the event does not appear in a cosigned checkpoint in time, the receipt is **public proof of misbehavior**.
2. **Per-source sequence number.** The source includes a monotonic counter in every signed event. A gap in the sequence signals an omission, and the source can detect it by checking its own events.
3. **Simpler variant:** synchronous incorporation. An event is confirmed only once it is already in a checkpoint. This is slower, but it removes the "accepted but pending" state entirely. With batch sequencing every 1 s, the latency is acceptable for most use cases.

Recommendation: start with variant 3 plus the per-source counter, and add receipts if latency becomes a problem.

---

## 6. Per-object history

### 6.1 Identification

An object is identified by the pair `(source, object_id)`. Two sources can use the same `object_id` without colliding, as required by concept §6 and §10.

### 6.2 Options for per-object linkage

**Option 1: back-link inside the event.**
Each source-signed event includes `object_seq` (a per-object counter) and `prev_object`, the position or hash of the object's previous event.
- Proves there are no gaps between the events returned.
- **Does not prove** that the latest event was returned. An operator could hide the most recent ones.
- Cost: two fields per event. The source computes them, since it knows its own object best.

**Option 2: verifiable map (sparse Merkle tree).**
Alongside the log, a cryptographically committed map `object → latest event` is maintained, and its root goes into every checkpoint.
- Proves completeness: "at checkpoint `N`, the object's latest event was at position `p`".
- Cost: significant complexity (verifiable log-backed maps are less mature) and more storage.

**Proposal:** option 1 in the first version. Option 2 only if a use case needs to prove completeness to third parties. For the source itself, the per-object counter is enough, because it knows how many events it emitted.

### 6.3 Privacy of the linkage

If leaves are public, `prev_object` and the object identifier must not appear in clear in the leaf. They go inside the **event envelope** (§7), and only the envelope's hash goes into the leaf. The registry maintains the `object → positions` index to serve authorized queries, and that index is not part of the public data.

---

## 7. Privacy and isolation

### 7.1 Three-layer structure

```
┌──────────────────────────────────────────────────────────┐
│ LOG LEAF (public, immutable)                             │
│   type · hash(envelope)                                  │
├──────────────────────────────────────────────────────────┤
│ EVENT ENVELOPE (signed by the source; restricted access; │
│ immutable except for crypto-shredding)                   │
│   source · object_id · object_seq · prev_object ·        │
│   source_seq · declared_time · content_type ·            │
│   hash(content + salt) · references · signature          │
│   + acceptance metadata added by the registry            │
├──────────────────────────────────────────────────────────┤
│ CONTENT (opaque; restricted access; erasable)            │
│   arbitrary bytes, encrypted at rest                     │
└──────────────────────────────────────────────────────────┘
```

The fields are indicative. The final format is still open (concept §20).

### 7.2 Resulting properties

- **Global verification without data:** witnesses and monitors handle only envelope hashes.
- **Inclusion proofs leak nothing:** the proof for one source's event contains only sibling-node hashes and reveals nothing about other sources (**scenario 8**).
- **Mandatory salt:** without one, content like `"23.0 °C"` or `"delivered"` can be brute-forced from its hash. The source generates the salt, and the salt travels with the content.
- **Erasure:** deleting the content (and the envelope if needed) leaves the leaf intact. The tree stays verifiable, and the event becomes "it existed, but its content is no longer available". Alternatively, each content item is encrypted with a per-object or per-source key, and the key is destroyed.
- **Metadata:** even with content hidden, the public log reveals how many events are accepted and at what rate. If that is sensitive for a source, there are two mitigations: aggregate into batches (the public granularity becomes the batch), or publish only checkpoints and not leaves. This is a product decision.

### 7.3 Access control

Four things need to be kept apart:
- **existence** (public: the leaf);
- **identification** (restricted: the envelope);
- **content** (restricted);
- **the right to query** (per-source policy).

Suggested initial model: each source owns its objects and grants read access through credentials, and the registry enforces the policy. End-to-end encryption (the source encrypts, and the registry never sees content in clear) can be added later. It is compatible with everything above, because the registry only needs the hash.

---

## 8. Identity, signatures and keys

- **Event signatures:** Ed25519 by default (fast, small signatures, widely supported). The hash function is SHA-256, for compatibility with RFC 6962 and C2SP.
- **Source key registry inside the log itself:** registration, rotation and revocation of each source's keys are recorded as events of a special system source. Which key was valid for a source at position `N` therefore becomes verifiable too, and the operator cannot swap keys silently.
- **Canonical encoding:** signatures and hashes must be reproducible, so the envelope needs a deterministic serialization. Candidates are deterministic CBOR (RFC 8949 §4.2) and canonical JSON (RFC 8785). To be decided.
- **Registry key:** signs checkpoints and receipts, and should live in hardware or a KMS. If it were compromised, an attacker could sign false checkpoints, but witnesses would still detect them, because they never cosign an inconsistent history.
- **Algorithm agility:** every structure carries an algorithm identifier, so the system can migrate (e.g. to post-quantum signatures) without breaking history.

---

## 9. Concurrency, ordering and failures

- **Single logical sequencer.** Concurrent requests enter a queue. The sequencer assigns strictly monotonic positions in batches (e.g. every 1 s or every `M` events), computes the new tree and publishes. This guarantees that two confirmed events never share a position (concept §14).
- **Expected throughput:** current implementations of this pattern handle thousands of events per second on a single modest machine. This should be confirmed with our own benchmark.
- **Idempotency and retries:** each event carries an idempotency key assigned by the source. If `(source, idempotency_key)` is retried, the registry returns the original confirmation instead of creating a duplicate.
- **Three timestamps (concept §14):**
  - `declared_time`: signed by the source; not verifiable.
  - `received_time`: recorded by the server; limited trust.
  - `accepted_time`: the batch's time; bounded externally by the witness cosignature or the anchor.
- **Sequencer failure:** the state is the log itself and sits in durable storage, so recovery means resuming from the last persisted batch. Anything not in a persisted batch was never confirmed, and the source retries.
- **Write high availability:** in the first version, a single active sequencer with fast recovery. Running several sequencers with consensus (e.g. Raft) adds complexity that is only justified if very high write availability is required.

---

## 10. Availability, durability and recovery

- **Log as static files (tiles, C2SP `tlog-tiles`).** The tree and leaves are published as immutable files in object storage. Reads scale through a CDN at very low cost, and **anyone can mirror the log** by copying files. That provides durability independent of the operator.
- **Separate storage for public and private data:**
  - Public log (leaves and tree): freely replicable.
  - Envelopes: controlled replicas with at least two providers or regions (content is never stored, see hash-only).
- **What is lost if the operator disappears:** private content, unless the sources keep their own copy, which they should. The public proofs survive in mirrors and witnesses.
- **Retention:** an explicit policy is needed, e.g. content kept for `X` years and then deleted, leaves kept indefinitely because they are tiny. **Decided:** leaves forever, envelopes up to 5 years (`docs/envelope-v0.md` §9).

---

## 11. Costs

These are order-of-magnitude estimates to validate with a prototype. Provider prices change.

**Size per event:**
- Leaf: about 40 bytes (type plus hash).
- Envelope: about 300–500 bytes (metadata plus signature).
- Content: variable. **It must have a size limit.** For large documents, only their hash is registered (concept §11).

**Scenario: 1 million events per day, with average content of 500 bytes:**
- About 1 GB per day, or about 365 GB per year in total.
- Leaves and the public tree account for under 10% of that.
- Compute: one small VM is enough for the sequencer and the API.
- Object storage: tens of euros per month after one year.
- Total: likely **tens of euros per month**. Storing content is the dominant cost, not the cryptography.

**What can make costs explode:**
- Abuse of the free service (T5): source registration, per-source quotas, size limits and rate limiting are needed from day one.
- Retaining content indefinitely.
- High-availability requirements for writes.
- Running our own witnesses. This is cheap, but it needs **independent** operators, which is an organizational problem more than a financial one.

**Practically free:** external witnesses (if we can get them), OpenTimestamps anchoring, and serving the public log through a CDN.

---

## 12. Proposed architecture

### 12.1 Components

```
           Sources (sign events)
                    │
                    ▼
       ┌─────────────────────────┐
       │ Ingestion API           │ auth · quotas · signature check
       │                         │ · idempotency
       └────────────┬────────────┘
                    ▼
       ┌─────────────────────────┐      ┌──────────────────────┐
       │ Sequencer               │─────▶│ Envelope & content   │
       │ (batches, positions,    │      │ store                │
       │ tree, checkpoint every  │      │ (private, encrypted, │
       │ 1,000)                  │      │ erasable)            │
       └────────────┬────────────┘      └──────────▲───────────┘
                    ▼                              │
       ┌─────────────────────────┐      ┌──────────┴───────────┐
       │ Public log (tiles)      │      │ Per-object index     │
       │ object storage + CDN    │      │ (source,id) →        │
       │                         │      │ positions            │
       └──┬──────────────────┬───┘      └──────────▲───────────┘
          │                  │                     │
          ▼                  ▼                     │
  ┌──────────────┐   ┌──────────────┐   ┌──────────┴───────────┐
  │ External     │   │ Mirrors /    │   │ Query API            │
  │ witnesses    │   │ monitors     │   │ (history, proofs,    │
  │ (cosign)     │   │              │   │ checkpoints)         │
  └──────┬───────┘   └──────────────┘   └──────────────────────┘
         ▼
  Cosigned checkpoints ──▶ verifiers (open library/CLI)
         └──▶ optional anchoring (OpenTimestamps / public repo)
```

### 12.2 Main flows

**Registering an event:**
1. The source builds the envelope, computes `hash(content + salt)`, signs it and sends it along with the content.
2. The API checks the signature against the source's registered key, applies quotas and checks idempotency.
3. The sequencer includes the event in the next batch, assigns it a position, updates the tree, persists and publishes.
4. The source receives confirmation: position, leaf hash, checkpoint and inclusion proof.
5. The checkpoint is sent to the witnesses, which cosign it. A source that wants the full guarantee can wait for the cosignatures.

**Querying an object's history:**
The API returns the object's envelopes and content, with their inclusion proofs, to authorized callers. The client checks the signatures, the inclusion proofs and the continuity of `object_seq` and `prev_object`.

**Verifying (any third party):**
1. Fetch the latest checkpoint cosigned by at least `k` trusted witnesses.
2. Check its consistency with the last checkpoint stored locally.
3. For a specific event, check its inclusion in that checkpoint and the source's signature.

**Deriving state:**
Not the registry's job. The application does it, or an optional client library, by replaying the events (concept §7, §22).

### 12.3 What the registry does and does not do

| Does | Does not |
|---|---|
| Order, retain, prove inclusion and consistency | Interpret content or business rules |
| Verify the source's signature | Validate whether statements are true |
| Enforce access control and quotas | Derive state (except via an optional client library) |
| Publish checkpoints and collect cosignatures | Guarantee perpetual availability of content |

---

## 13. Meeting the success criteria (concept §21)

| Scenario | How it is met | Condition |
|---|---|---|
| 1. Multiple sources | Single sequencer with a queue and monotonic positions | — |
| 2. Individual history | Index by `(source, object_id)` plus access control | Authorization |
| 3. Update | Append-only; there is no update operation | — |
| 4. Correction | New event with `references` to the corrected one | Application convention |
| 5. Fraudulent modification | The leaf hash changes, so the inclusion proof fails against the stored checkpoint | Verifier holds a later checkpoint |
| 6. Fraudulent reconstruction | The consistency proof fails, and witnesses refuse to cosign the new history | **At least one honest witness** |
| 7. Incremental validation | Consistency proof between checkpoints; logarithmic inclusion | — |
| 8. Privacy | Leaves are salted commitments; proofs reveal nothing about others | Design from §7 |

---

## 14. Risks

| # | Risk | Impact | Mitigation |
|---|---|---|---|
| R1 | No independent witnesses can be found | Scenario 6 is not met | Start with OpenTimestamps plus a public repo; recruit witnesses among participants and the C2SP community |
| R2 | Operator omits events | Incomplete history goes unnoticed | Synchronous confirmation, per-source counter, receipts |
| R3 | Split view | Clients see different histories | Witnesses; clients accept only cosigned checkpoints |
| R4 | GDPR non-compliance | Legal exposure | Content outside the tree and erasable; legal review |
| R5 | Metadata leakage | Usage patterns exposed | Non-public envelopes; batch aggregation |
| R6 | Abuse of the free service | Unbounded cost | Source registration, quotas and size limits from v1 |
| R7 | Source key compromise | Forged events in its name | Rotation and revocation recorded in the log; detection via counter |
| R8 | Registry key compromise | False checkpoints | Witnesses refuse to cosign inconsistencies; KMS/HSM |
| R9 | Home-grown crypto bugs | False guarantees | Use existing specs and libraries; do not invent structures |
| R10 | Unanchored window at low volume | Recent events could be rewritten | Periodic tree heads (§5.4, accepted) |
| R11 | Loss of the operator | Private content becomes inaccessible | Public log mirrors; sources keep their own copy; replicas |
| R12 | Users misreading "immutable" | False expectations ("it can't be changed") | Document precisely: detection, not impossibility (concept §9) |

---

## 15. Proposed decisions

These are **proposals** that need confirmation unless marked **Accepted**.

1. Core built on a **Merkle transparency log** (RFC 6962/9162, C2SP); no blockchain.
2. SHA-256 and Ed25519 by default, with algorithm identifiers.
3. **Events are signed by the source**, and source keys are registered in the log itself.
4. **Leaves are commitments.** Envelopes live outside the tree, and content never reaches the registry (hash-only, see "Content and pricing" in §16). **Accepted.**
5. Internal checkpoints every 1,000 ordinary events (decision 11) **and** periodic tree heads to witnesses, only when there are new ordinary events (no-self-validation rule, §5.4). **Accepted.**
6. **External witnesses** following C2SP `tlog-witness`, rolled out in phases (§16, Q6). **Accepted.**
7. Per-object history via `object_seq` and `prev_object` in the envelope; the verifiable map is deferred.
8. Synchronous batched confirmation in v1 (~1 s); asynchronous receipts only if latency requires them. **Accepted.**
9. Public log served as static tiles from object storage. **Accepted** (leaves are public).
10. Quotas and source registration mandatory from day one. **Accepted.**

## 16. Questions for the team

Status as of 2026-11-17.

1. **Public leaves or only checkpoints?** → **Decided: leaves are public.** Anyone can mirror and monitor the log. Leaves contain only envelope hashes, never content.
2. **Explicit linear link to the previous leaf?** → **Decided: Merkle tree only.** Decision 4 (cryptographic chaining) is fulfilled by the Merkle tree (§5.1).
3. **Confirmation latency?** → **Decided: ~1 s**, synchronous, batched (§5.6, variant 3).
4. **Content mode and size?** → **Superseded (2026-11-17) by hash-only** (see "Content and pricing" below). The original two-mode decision and the discussion that followed are kept for reference only.

   *Original decision (superseded): the source chooses, per event, between two modes:*
   - **Plain content:** the source sends the content in any format (JSON, YAML, plain text, bytes). The registry stores it, and the envelope commits to its hash.
   - **Hash only:** the source sends only a hash of its content. **The registry never receives or stores salts or the original content.** The source is solely responsible for keeping the content and the salt, and for using a salt when the content is guessable (§7.2).

   *Still open:* maximum size of plain content (64 KB suggested), and who may read plain content (public, or restricted to the source and the readers it authorizes, §7.3).

   **Update (2026-11-17), leaning, not final:** to minimize GDPR exposure, the team leans toward the registry **not storing plain content at all**. It would store only:
   - **envelopes** (hash-only mode), and possibly
   - **content encrypted by the source**, with a key the registry never holds.

   The source keeps its salt (and key). Points to take into account:
   - **Encrypted or hashed personal data can still count as personal data** under the GDPR (pseudonymized, not anonymized). Never holding salts or keys greatly reduces exposure, but does not eliminate it. A legal opinion is still needed.
   - **The envelope itself may contain personal data:** `object_id` (e.g. an email address used as an identifier) and source account details. Mitigation: the source sends a **pseudonymous `object_id`**, e.g. an HMAC of its internal identifier under a key it keeps. The registry indexes by that value and never sees the real identifier.
   - **Encrypted storage brings back storage cost and the size-limit question.** Hash-only mode avoids both. Suggested path: hash-only in v1, encrypted storage as a later option.
   - **If a source loses its content, salt or key,** the registry can still prove that an event with that hash existed, but nobody can recover what it said.

   **Superseded (2026-11-17): the two-tier idea below is shelved.** It is kept for reference only.

   **Earlier proposal: two service tiers.**
   - **Free tier = certification (hash only).** The registry stores only envelopes. The source keeps its content and salt. This is the default and covers the core purpose: proving that a statement existed unaltered at a given point in the sequence.
   - **Paid tier = optional encrypted storage.** The source may also store its content with us, **encrypted client-side** with a key the registry never holds. We store opaque ciphertext outside the tree; it is never part of a leaf.
   - **Why this split works:**
     - Storage is the dominant cost (§11), so the paid tier pays for exactly what costs money, and the free tier stays near-zero cost.
     - It fits concept §17, which excludes tokens and per-transaction fees, not optional paid storage.
   - **Sequencing:** v1 ships hash-only. The envelope keeps an optional `content_ref` field so encrypted storage can be added later without changing the event format. Because the leaf commits to `hash(salt + content)` and not to the ciphertext, a source can upload the ciphertext for an **already registered** event at any time, so adding storage later loses nothing.
   - **Implications of the paid tier:**
     - billing and a legal entity;
     - a data-processing agreement (GDPR processor) with paying sources;
     - availability and durability commitments for stored content;
     - clear terms that **a lost key means lost data**, because we cannot decrypt or recover it.
5. **Content retention?** → **Decided: retention period chosen per source**, with a service-wide maximum (value open). It does not affect the tree: only content outside the tree expires, while leaves and proofs are kept forever (§7.2, §10). Indefinite retention is ruled out. Envelope retention: decided, up to 5 years (`docs/envelope-v0.md` §9).
6. **Who runs witnesses?** → **Decided: phased combination.**
   - From day one: public anchoring (OpenTimestamps plus a public repository), plus a witness of our own **for protocol testing only**. It gives no independent guarantee.
   - As soon as possible: apply to the public witness network (witness-network.org / OmniWitness / ArmoredWitness, §18). One independent witness is enough to meet scenario 6.
   - As the project grows: an easy-to-deploy witness for participants, plus sympathetic third parties.
7. **Anonymous sources?** → **Decided: registration is mandatory.** Self-service sign-up is still possible.
8. **Is completeness of an object's history provable to third parties (verifiable map)?** → **Deferred (2026-11-18).** Back-links (`object_seq`, `prev_object`) already prove there are no gaps in a returned history. Only a verifiable map can also prove that the latest event was returned (§6.2). This matters only when third parties rely on object histories, which does not happen while there is a single source. Revisit in phase 3.

**Object identifiers and searchable metadata — Accepted (2026-11-17):**
- **The registry assigns its own opaque object identifier** (e.g. UUIDv7) when an object is first used. Sources never need to use emails or other real-world identifiers as object ids. This refines §6.1: `(source, object_id)` becomes `(source, registry-assigned object_id)`.
- **The source may attach metadata (tags)** so it can search its own objects by its own criteria.
- **Metadata is the one place where plain data reaches the registry, so it must be limited.** Proposed limits:
  - a maximum number of tags and a maximum size per tag;
  - visible and searchable **only by the owning source** by default;
  - optionally, **blind indexing**: the source sends `HMAC(source_key, value)` instead of the value. It can still search by exact match, and the registry never sees the real value.
- **The event value is a fixed-length digest with an algorithm identifier** (e.g. exactly 32 bytes for SHA-256), not a free-form field. Otherwise sources could put plain content in it and bypass hash-only mode.
- **The registry is agnostic to what the hashed content means.** It does not know whether a hash represents a sensor reading or anything else.
9. **Is end-to-end encryption a requirement?** → **Decided (2026-11-18): no.** The registry never receives content (hash-only), so there is nothing to encrypt end to end.
10. **Implementation language?** → **Decided (2026-11-17): Go.** It has the most mature ecosystem: Trillian Tessera, Sigsum, the C2SP reference libraries and OmniWitness are all written in Go. Use **Tessera**, not Trillian v1, which is in maintenance mode.

**Envelope format, parameters and retention — Decided (2026-11-17):** see `docs/envelope-v0.md`.
- **Format:** deterministic CBOR + COSE_Sign1, Ed25519, SHA-256.
- **Leaves:** `[1, type, body]`.
- **Initial parameters:** 1 s batches, `T` = 60 s, `k` = 1, 1 KiB envelopes, default quotas.
- **Retention:** the tree is kept forever. Envelopes are kept for a period the source chooses, up to 5 years (can be raised later, never lowered). Tags live outside the envelope and can be deleted.
- **Proposals 2, 3 and 7 of §15 are now part of this spec:** algorithms, source-signed events with keys registered in the log, and `object_seq`/`prev_object`.

**Content and pricing — Decided (2026-11-17):**
- **Hash-only.** The registry stores envelopes, never content. The source keeps its content and salt.
- **Free for everyone from the start**, with the intention of keeping it that way.
- **Encrypted content storage is shelved indefinitely.** It may never be built. It can be added later without changing existing events if it is ever revisited (see the shelved proposal under Q4).
- **External anchoring: only free mechanisms. Paid anchoring (Ethereum or any other chain with per-transaction fees) is ruled out.**
  - **OpenTimestamps** is free for us because public calendar servers aggregate many hashes into one Bitcoin transaction and pay its fee themselves.
  - It depends on those calendars staying available, so we should submit to several of them.
  - Only checkpoints are anchored, never individual events.

**Operator and deployment — Decided (2026-11-18):**
- **Operator:** the project lead, personally. There is no organization.
- **Hosting:** self-hosted on the operator's own Raspberry Pi.
- **Sources:** initially a single source (the operator). Registration and quotas still apply, so opening to more sources later needs no design change.
- **Storage (for now):** Tessera's POSIX driver on the Pi's local disk. A production backend and replication stay open until there are other users.
- **Funding:** none; self-funded. The running cost is the Pi's electricity.
- **Points to keep in mind:**
  - **Durability:** a single disk on a single machine is a single point of failure. SD cards wear out. An SSD and an off-site copy of the tiles are recommended. Leaves and tiles are public, so copying them anywhere is safe.
  - **Witnesses (phase 1):** external witnesses and the public witness network must be able to reach the log's checkpoints over the internet. Exposing a home Pi needs a decision (port forwarding, a tunnel, or pushing tiles and checkpoints to free static hosting).
  - **Trust:** a single operator does not weaken the model. Scenario 6 always depended on independent witnesses, never on the operator.

## 17. Phased plan

**Phase 0: proof of concept (verifiable end to end).** *Status (2026-11-18): core implemented; see `AGENTS.md` for the code map and the phase 0 limits. Covered by tests: scenario 5 (a modified envelope or file fails verification), scenario 6 against a verifier that kept a tree head (`TestRebuildDetected`; witnesses come in phase 1), scenario 7 (consistency proofs) and the checkpoint leaf every 1,000 events (`TestDefaultCheckpointEvery`). Scenario 3 holds by construction (there is no update operation). Not yet: scenario 2 needs the per-object index (phase 2); scenario 4's `refs` are carried but not yet checked by the registry.*
- Sequencer, Merkle tree, internal checkpoints every 1,000 events, tiles on disk.
- Source-signed envelopes, separate content.
- Verification CLI: inclusion, consistency and signatures.
- Demonstrates scenarios 1–5 and 7.

**Phase 1: external trust.**
- Reference witness (one of our own plus at least one run by a third party).
- Periodic tree heads and OpenTimestamps anchoring.
- Demonstrates scenarios 6 and 8.

**Phase 2: service.**
- Ingestion and query API with authentication, quotas and access control.
- Per-object index, idempotency, source key registry.
- Cloud storage and CDN; monitor and mirror.

**Phase 3: hardening.**
- Retention and erasure policy; legal review.
- KMS/HSM, replicas, high availability if justified.
- Verifiable map if justified.

---

## 18. Existing products and standards (survey, 2026-11)

This survey answers the question of whether something equal or similar already exists. It is based on public web sources and should be re-checked before any decision depends on it.

| Product / standard | What it is | Similarity | Key differences |
|---|---|---|---|
| **IETF SCITT** (RFC 9943, 2026) | Standard architecture for a *Transparency Service* that registers signed statements in an append-only ledger and returns receipts (COSE Receipts, RFC 9942) | **Very high in concept.** It is essentially the standard for what Kirowen does | A standard, not a service. Examples are scoped to software supply chains. No per-object history model. CBOR/COSE formats |
| **DataTrails** (formerly RKVST) | Commercial SaaS for "who did what when" over any data; Merkle log (Forestrie); SCITT API (preview) | **High.** Generic provenance for arbitrary events | Commercial, operated by one company; free tier but paid plans; trust relies on the vendor plus its proofs |
| **Azure Confidential Ledger** | Managed tamper-evident ledger running in TEEs (CCF), with receipts | **High** functionally | One ledger per customer, not a shared universal log; paid (~$3/day per instance); trust in Microsoft and in TEE hardware; no external witnesses |
| **immudb / immudb Vault** | Open-source immutable database with Merkle proofs; hosted Vault with a free tier (10,000 documents / 250 MB at its 2023 launch) | **Medium–high** | Per-customer database; the client must store state to detect tampering; no witness ecosystem |
| **Sigstore Rekor** (public good instance) | Free public transparency log | **Medium.** Free, public, Merkle, witnesses | Only software signatures and attestations (`hashedrekord`, `dsse`); size limits; no object model; not intended for IoT or business events |
| **Sigsum** | Minimal public transparency log for signed checksums, with witness cosigning | **Medium** | Only signed checksums; no content and no object history. A good reference design and a possible source of witnesses |
| **Hedera Consensus Service** | Public network that orders and timestamps messages in "topics" for unrelated applications | **High** functionally: a shared ordered log for independent systems | It is a blockchain with a token (HBAR), contradicting concept §18. Pays per message (USD 0.0008 from January 2026, so 1M events/day ≈ USD 800/day) |
| **Amazon QLDB** | Managed ledger database | Medium | Discontinued (2025) |
| **OpenTimestamps** | Free timestamp anchoring in Bitcoin | Low (only one component) | Timestamping only. Useful as an anchor (§4.1 F) |
| **Trillian Tessera, C2SP specs, OmniWitness / ArmoredWitness** | Building blocks: tile-based log library, open formats, public witness network | — | Components, not a product. Kirowen would build on them |

**Conclusions:**

1. **No identical product exists.** None of the services found combines all of the following:
   - a single universal log shared by unrelated sources;
   - free use;
   - open source and open standards;
   - independent witnesses;
   - a per-object history model;
   - no token.
2. **The concept is not new, and its building blocks already exist.** SCITT standardizes the idea, Tessera, C2SP and the witness network provide the cryptographic core, and DataTrails and Azure Confidential Ledger sell similar services. Kirowen's value would be **the combination plus free use plus openness**, not a new mechanism.
3. **Interoperability with SCITT is worth evaluating.** Being able to issue SCITT-compatible receipts would give credibility and interoperability at a moderate cost.
4. **"Public service for everyone" is an operational decision, not an architectural one.** The architecture in §12 is the same whether Kirowen serves only its authors or anyone. What changes is legal exposure (storing third parties' plain content makes us a data processor under the GDPR), abuse control, support and cost.

---

## References

- RFC 6962: *Certificate Transparency*.
- RFC 9943: *An Architecture for Trustworthy and Transparent Digital Supply Chains* (SCITT). https://www.rfc-editor.org/rfc/rfc9943.html
- Trillian Tessera: https://github.com/transparency-dev/tessera
- Witness network: https://blog.transparency.dev/can-i-get-a-witness-network, https://github.com/transparency-dev/armored-witness
- DataTrails SCITT: https://docs.datatrails.ai/developers/developer-patterns/scitt-api/
- Azure Confidential Ledger: https://learn.microsoft.com/azure/confidential-ledger
- immudb Vault: https://codenotary.com/blog/welcome-immudb-vault-the-fully-managed-immutable-cloud-database
- Rekor v2: https://blog.sigstore.dev/rekor-v2-ga/
- Hedera HCS pricing: https://hedera.com/blog/price-update-to-consensussubmitmessage-in-consensus-service-january-2026/
- RFC 9162: *Certificate Transparency Version 2.0*.
- C2SP (Community Cryptography Specification Project): `signed-note`, `tlog-checkpoint`, `tlog-tiles`, `tlog-witness`, `tlog-cosignature`.
- Trillian Tessera: Go library for tile-based transparency logs.
- Sigsum: minimalist transparency log with witnesses.
- Sigstore Rekor: transparency log for software signatures.
- OpenTimestamps: Bitcoin timestamp anchoring at no cost to the user.
- RFC 3161: *Time-Stamp Protocol*.
- RFC 8949 §4.2: deterministic CBOR. RFC 8785: JSON Canonicalization Scheme.
- Crosby & Wallach (2009): *Efficient Data Structures for Tamper-Evident Logging*.

*References to external projects and services reflect their known status as of this document's date. Confirm their availability and status before adopting them.*
