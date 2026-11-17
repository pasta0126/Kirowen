# Contributing to Kirowen

Thanks for your interest in Kirowen. The project is in its **design phase**: there is no code yet, and discussion of the design documents in `docs/` is the most useful contribution right now.

## Ground rules

- **Language:** everything in the repository is written in English: code, comments, docs, commit messages, issues and pull requests.
- **Code of conduct:** by participating you agree to follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- **Security issues:** never report them publicly. See [SECURITY.md](SECURITY.md).

## Design principles

Read [AGENTS.md](AGENTS.md) and [docs/technical-analysis.md](docs/technical-analysis.md) before proposing changes. In short:

- **Precise guarantees.** Kirowen makes tampering *detectable* under stated trust assumptions. It does not make it impossible. Never claim more than that.
- **No home-grown cryptography.** Use existing specifications and libraries (RFC 6962/9162, C2SP, COSE).
- **Simplicity first.** A component is justified only if it provides a guarantee that cannot be achieved more simply.
- **The registry does not interpret content.** It only stores signed envelopes carrying hashes.
- **Decided items** in `AGENTS.md` should not be reopened without a strong, new reason.

## How to contribute

1. Open an issue to discuss significant changes before writing them.
2. Fork the repository and create a branch.
3. Keep changes focused, with clear commit messages.
4. Sign off every commit (see below).
5. Open a pull request that describes what changed and why.

## Developer Certificate of Origin (DCO)

Kirowen uses the [Developer Certificate of Origin 1.1](https://developercertificate.org/) instead of a CLA. By signing off a commit, you certify that you wrote the change, or otherwise have the right to submit it under the project's license ([Apache-2.0](LICENSE)).

Add a `Signed-off-by` line to every commit:

```
Signed-off-by: Your Name <your.email@example.com>
```

Git adds it automatically with `git commit -s`. Pull requests with unsigned commits cannot be merged.

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
