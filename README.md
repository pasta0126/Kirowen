# Kirowen

*Everything remains.*

Kirowen is an open, free registry of immutable events. Independent systems (sensors, apps, businesses) send it events about their own objects. Kirowen puts every event into a single global sequence and gives anyone cryptographic proof that the history has not been changed.

- **Append-only:** events are never updated or deleted. A correction is a new event.
- **Tamper-evident:** the history is a Merkle-tree transparency log. External witnesses cosign its checkpoints, so a rewritten history is detected even if the operator itself does the rewriting.
- **Hash-only:** sources send a signed envelope carrying a hash of their data, never the data itself. The source keeps its content. The registry does not know or care what the content is.
- **Per-object history:** each object's events can be retrieved and verified on their own.
- **No blockchain, no token, free:** verification relies on open standards ([C2SP](https://c2sp.org), RFC 9162) and free external anchoring.

Kirowen guarantees that a source made a statement and that the statement has not been altered since. It does not guarantee that the statement is true.

## Status

Phase 0 (proof of concept) has started. The implementation is in Go, on top of [Trillian Tessera](https://github.com/transparency-dev/tessera). So far: the envelope and leaf formats, with test vectors.

```
go test ./...
```

- [Concept](docs/concept-v0.1.md): goals and requirements.
- [Technical analysis](docs/technical-analysis.md): threat model, architecture and decisions.
- [Envelope format v0](docs/envelope-v0.md): wire format and initial parameters.
- [Governance and operations](docs/governance-and-operations.md): legal, sustainability and naming.

## License

[Apache License 2.0](LICENSE).
