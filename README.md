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

Alpha. The implementation is in Go, on top of [Trillian Tessera](https://github.com/transparency-dev/tessera). The registry runs with a public HTTP API ([docs/api-v0.md](docs/api-v0.md)) and anyone can register, from the CLI or from the website: **https://kirowen.northernarchive.com** (registration in the browser and an interactive API console at [`/docs/`](https://kirowen.northernarchive.com/docs/)).

```sh
go build ./cmd/kirowen

./kirowen keygen -out me                 # your source key, kept locally
./kirowen register -key me.key           # self-service sign-up; writes me.cred.json (token)
./kirowen add -key me.key reading.txt    # writes reading.txt.receipt.json
./kirowen verify -log https://kirowen.northernarchive.com/log/v0/ \
    -log-pub keys-public/kirowen.northernarchive.com-log-v0.pub -pub me.pub \
    reading.txt.receipt.json reading.txt
```

The receipt holds the envelope, the salt, the leaf index, the signed tree head and the inclusion proof. With it and the file, anyone holding the two public keys can verify the event. Your content never leaves your machine: only its salted hash is sent.

Step-by-step guide, including keys downloaded from the website: [docs/cli.md](docs/cli.md).

Development: `go test ./...`.

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
