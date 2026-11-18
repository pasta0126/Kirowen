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

Phase 0 (proof of concept). The implementation is in Go, on top of [Trillian Tessera](https://github.com/transparency-dev/tessera). It runs end to end on a local directory; there is no network API yet.

```sh
go test ./...
go build ./cmd/kirowen

./kirowen keygen-log -origin example.com/log/v0 -out log   # registry key
./kirowen keygen -out sensor                               # source key
./kirowen add -data data -log-key log.key -key sensor.key reading.txt
./kirowen verify -log data/log -log-pub log.pub -pub sensor.pub reading.txt.receipt.json reading.txt
./kirowen audit -log data/log -log-pub log.pub
```

`add` writes `reading.txt.receipt.json` (envelope, salt, leaf index, signed tree head and inclusion proof). With it and the file, anyone holding the two public keys can verify the event. `data/log` is the public log (C2SP tiles); it can be served as static files, and `-log` also accepts an `https://` URL.

- [Concept](docs/concept-v0.1.md): goals and requirements.
- [Technical analysis](docs/technical-analysis.md): threat model, architecture and decisions.
- [Envelope format v0](docs/envelope-v0.md): wire format and initial parameters.
- [Governance and operations](docs/governance-and-operations.md): legal, sustainability and naming.

## Public log

The phase 0 log runs at **https://kirowen.northernarchive.com/log/v0/** (origin `kirowen.northernarchive.com/log/v0`). It is an alpha: it may be reset.

Its verifier key is published here, out of band from the log itself: [`keys-public/kirowen.northernarchive.com-log-v0.pub`](keys-public/kirowen.northernarchive.com-log-v0.pub)

```
kirowen.northernarchive.com/log/v0+17c4e654+AaDWeAoySrOyLKK4lZEvGxHMe/WpGWvb4ECEtqIjR+qj
```

```sh
./kirowen audit -log https://kirowen.northernarchive.com/log/v0/ -log-pub keys-public/kirowen.northernarchive.com-log-v0.pub
```

## License

[Apache License 2.0](LICENSE).
