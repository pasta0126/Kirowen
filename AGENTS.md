# AGENTS.md

Guidelines for agents (Claude, Codex, etc.) working in this repository.

## What Kirowen is

Kirowen is a universal **immutable event registry**. It receives events from independent systems, orders them into a single global sequence, and cryptographically guarantees that the history cannot be modified or deleted **without detection**.

Core principle: **events are appended, never overwritten. The past remains verifiable, and changes produce new events.**

It is not a cryptocurrency, a token, an NFT system or a financial platform.

## Current status

**Analysis and design phase. There is no code yet.**

- `docs/concept-v0.1.md` is the concept document and the source of the requirements.
- `docs/envelope-v0.md` is the draft wire format (envelope, leaves, checkpoints) and the initial parameters.
- `docs/governance-and-operations.md` covers non-technical topics: legal, sustainability, governance and naming.
- `docs/technical-analysis.md` is the technical analysis of the concept. It covers real vs. apparent guarantees, alternatives, a proposed architecture, risks and open questions.

## Decisions taken (do not relitigate)

1. A universal, content-agnostic infrastructure for independent sources.
2. A single logical global sequence of confirmed events.
3. Events are cryptographically chained and append-only. Corrections are new events.
4. Every object has a reconstructible individual history. Objects are scoped by their source.
5. Automatic checkpoints: **one per 1,000 ordinary events**. Checkpoints do not count toward those 1,000 and occupy their own positions in the sequence.
6. Independent cryptographic verifiability: a rebuild by an administrator must be detectable by verifiers that hold proofs.
7. Integrity, truthfulness, availability and durability are kept separate.
8. Signed tree heads are published to external witnesses every `T` seconds, as a complement to checkpoints (`docs/technical-analysis.md` §5.4).
9. **No-self-validation rule:** only ordinary events trigger validations. If no new ordinary events have arrived since the last validation, no new one is produced. An infinite chain of records validating themselves must never form.
10. Merkle transparency log as the core, with public leaves (hashes only), ~1 s synchronous batched confirmation, and mandatory source registration with quotas.
11. **Hash-only, free for everyone:** the registry stores envelopes only, never content and never salts. The source keeps both. Encrypted storage is shelved indefinitely.
12. **Accepted:** the registry assigns opaque object ids. Sources may attach limited search metadata, private to the source and optionally blind-indexed. The event value is a fixed-length digest. See `docs/technical-analysis.md` §16.
13. Retention: tree leaves are kept forever. Envelopes are kept for a period the source chooses, **up to 5 years**. Tags are outside the envelope and can be deleted.
14. Envelope, leaf and checkpoint formats and the initial parameters follow `docs/envelope-v0.md` (deterministic CBOR + COSE_Sign1, Ed25519, SHA-256).
15. Witnesses are rolled out in phases: public anchoring and a test-only witness of our own, then the public witness network, then participants and third parties.
16. Implementation language: **Go**, building on Trillian Tessera and the C2SP libraries.
17. Only free external anchoring (e.g. OpenTimestamps). No Ethereum or any anchoring that charges per entry or per transaction.
18. No cryptocurrency or token. Operating cost is kept minimal, with the aspiration of offering a free service.
19. **Name: Kirowen** is kept (decided 2026-11-18), accepting the known similarity to Amazon's Kiro (`docs/governance-and-operations.md` §6).

## Open decisions (do not assume)

Storage backend for production, replication, operating entity and jurisdiction, governance and funding.

`docs/technical-analysis.md` §15 contains **proposals**, not decisions, except items marked **Accepted**. Do not treat the others as requirements until the user confirms them.

## Working rules

- **Language:** this repository is public, so **everything in it is written in English**: docs, code, comments and commit messages. The conversation with the user may be in Spanish.
- **Be precise about guarantees:** never claim something is "impossible to modify". The system guarantees **detection** under explicit trust assumptions, and those assumptions must always be stated.
- **Do not invent cryptography:** use existing specs and libraries (RFC 6962/9162, C2SP) instead of home-grown structures.
- **Simplicity:** a technology or component is justified only if it provides a guarantee that cannot be achieved more simply and cheaply.
- **The registry does not interpret business logic:** the rules for interpreting events belong to applications, not to the registry.
- **Design changes:** when a proposal affects a decision already taken, point out the tension and let the user decide.
