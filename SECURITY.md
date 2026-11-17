# Security policy

Kirowen is security infrastructure: its value depends on its cryptographic guarantees holding. We take reports seriously and appreciate them.

## Reporting a vulnerability

**Do not open a public issue for security problems.**

Report vulnerabilities privately through GitHub's **[private vulnerability reporting](https://github.com/pasta0126/Kirowen/security/advisories/new)**: in the repository, go to *Security → Report a vulnerability*.

Please include:

- a description of the issue and its impact;
- the steps or a proof of concept needed to reproduce it;
- the affected version or commit;
- any suggested fix, if you have one.

## What to expect

- Acknowledgement within **7 days**.
- An initial assessment within **30 days**.
- Coordinated disclosure. We aim to publish a fix and an advisory within **90 days** of the report, and will credit you unless you prefer otherwise.

## Scope

In scope:

- Anything that lets someone modify, remove, reorder or forge history without detection.
- Bypassing signature, inclusion or consistency verification.
- Split-view attacks, i.e. showing different histories to different clients.
- Leakage of non-public data: envelopes, tags, or a link between a leaf and its source.
- Flaws in the specifications in `docs/`, not only in the code.

Out of scope:

- Statements that are false but correctly recorded. Kirowen certifies that a statement is unaltered, not that it is true.
- Denial of service through volume alone, unless it bypasses quotas.

## Status

The project is in its design phase and there is no released code yet. Reports about the design documents are welcome.
