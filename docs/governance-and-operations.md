# Kirowen: governance, legal and operations (non-technical topics)

**Status:** Draft for discussion. **Date:** 2026-11-17.
**Disclaimer:** this is not legal advice. Points marked ⚖️ should be confirmed with a lawyer before a public service opens.

---

## 1. Who operates Kirowen

| Option | Pros | Cons |
|---|---|---|
| **Personal project (now)** | No overhead | Personal liability once there is a public service; harder to get grants or sponsorship |
| **Non-profit association** | Cheap to set up; can receive grants and donations; limits personal liability; neutral image | Paperwork, accounts, at least a few founding members |
| **Foundation** | Strongest neutrality and continuity | Expensive and slow to set up; minimum endowment |
| **Company** | Familiar structure | Conflicts with the "free, neutral infrastructure" image |

**Recommendation:** stay a personal open-source project while there is only code and no public service. Create a **non-profit association** before opening a public service to third parties. ⚖️

**Jurisdiction — Decided (2026-11-17): Spain (EU).** This implies:
- **GDPR plus Spain's LOPDGDD**, with the AEPD as supervisory authority.
- **LSSI (Ley 34/2002):** a public web service needs a legal notice ("aviso legal").
- **The EU Digital Services Act.**
- **Association law of the region where it is registered.** ⚖️

## 2. Legal and compliance

### 2.1 GDPR

Hash-only mode removes most of the exposure. What remains:

| Data | Our role | Measures |
|---|---|---|
| Source account details (email, name of the organization) | Controller | Privacy policy; minimal data; deletion on account closure |
| Search tags | Processor on the source's behalf (if they contain personal data) | Short data-processing terms in the terms of service; blind indexing by default; deletion on request |
| Envelopes (opaque ids, hashes, declared times) | Probably pseudonymized data, at most ⚖️ | Retention limit (5 years max); no plain fields |
| Server logs (IP addresses) | Controller | Short retention (e.g. 14 days) |
| Public leaves (hashes only) | Very likely not personal data ⚖️ | Leaves never contain identifiers |

### 2.2 Content and the Digital Services Act (EU)

- **Hashes are not content.** We cannot know what a hash represents and do not try. The terms of service should say so explicitly.
- **Tags are the only stored user content.** They are tiny and private to their source, but they make us a hosting service under the DSA. ⚖️ Likely obligations: a point of contact, a notice-and-action procedure, and a statement of reasons when we remove something.
- **Requests from authorities:** we can only hand over account details, envelopes and (blind-indexed) tags. We should publish a policy on how such requests are handled and, ideally, a periodic transparency report.

### 2.3 Terms of service (minimum content)

- Kirowen certifies that a source made a statement and that it is unaltered. **It does not certify that the statement is true.**
- No availability guarantee (no SLA) for the free service.
- Sources are responsible for keeping their content, salts and confirmation bundles. **Lost content cannot be recovered.**
- Acceptable use: quotas, no abuse of metadata, and grounds for suspending a source.
- Limitation of liability.

### 2.4 Cryptography export rules

Publicly available open-source cryptographic software is generally exempt from EU and US export controls. ⚖️ This should be confirmed once, but it is unlikely to require action.

## 3. Sustainability

The decision is **free for everyone, with the intention of keeping it that way**. Expected costs are low (§11 of the technical analysis: tens of euros per month at 1 million events per day).

Funding options that keep the service free:

| Option | Notes |
|---|---|
| **Grants for open internet infrastructure** | The NLnet Foundation (NGI Zero programs) and the Sovereign Tech Agency fund this kind of project. **Decided (2026-11-17): not pursued for now.** |
| **Donations** | GitHub Sponsors or Open Collective, with transparent accounting |
| **Sponsored infrastructure** | Cloud and CDN providers run programs for open-source projects (credits or free CDN) |
| **Participants** | Organizations that rely on Kirowen may sponsor it voluntarily, or contribute by running a witness |

**Continuity / shutdown policy (publish it from day one):** if the service ever has to stop:
1. Announce the date well in advance and stop accepting events.
2. Publish a final checkpoint, cosigned by the witnesses.
3. Keep the static tiles readable for as long as possible, and hand them to mirrors.
4. Sources already hold their envelopes and proofs, so every event stays verifiable.

Committing to this publicly is itself a trust signal.

## 4. Governance

- **Now:** the project lead decides, with decisions recorded in the repository (`docs/technical-analysis.md` §16, `AGENTS.md`).
- **Later:** if there are several maintainers or relying organizations, a small steering group with a public decision process.
- **Operator transparency, which is part of the trust model:**
  - publish the registry's public keys and how they are generated and stored;
  - publish operational policies (quotas, retention, suspension);
  - publish incident reports;
  - the operator must **never run all the witnesses** a verifier relies on.

## 5. Community and repository hygiene

| File | Purpose | Recommendation |
|---|---|---|
| `SECURITY.md` | How to report vulnerabilities privately | **Done:** GitHub private vulnerability reporting |
| `CONTRIBUTING.md` | How to contribute | **Done:** DCO (`Signed-off-by` line) rather than a CLA |
| `CODE_OF_CONDUCT.md` | Community rules | **Done:** Contributor Covenant 2.1 |
| Issue / PR templates | Consistency | When there is code |

## 6. Name and trademark (checked 2026-11-17)

- **No trademark, company or product called "Kirowen" was found.** Searches were not exhaustive. ⚖️ Search EUIPO eSearch, TMview and the USPTO before investing in branding.
- **Domains:** `kirowen.com` and `kirowen.io` appear unregistered. `.dev`, `.org` and `.eu` could not be confirmed by WHOIS and should be checked with a registrar.
- **Risk of confusion:** "Kirowen" is close to **Kiro**, Amazon's AI IDE, which has a trademark application in classes 9 and 42 (software). It is even closer to **Kiroween**, Kiro's annual hackathon. Both are in the same field (software and developers). This is a moderate risk of confusion, both legally ⚖️ and for search visibility.
- **Options:**
  1. Keep "Kirowen" after a professional trademark check.
  2. Rename now, while the cost is close to zero: no code, no users, no domain.
- **If renaming:** the new name should be short, pronounceable in English and Spanish, have a free `.dev` or `.org` domain, and be clear of trademarks in classes 9 and 42. Candidates with an "inscription / record / witness" meaning (e.g. Latin words like *tabularium* or *sigillum*) are mostly taken as `.com` and `.io`, so a coined word is more practical.

## 7. Witness recruitment

1. Read the public witness network's requirements (witness-network.org) and adapt the log to them: C2SP checkpoint format, a stable origin and a public key.
2. Apply once the proof of concept runs publicly.
3. Offer participants a one-command witness deployment.
4. Approach sympathetic third parties (universities, digital-rights foundations).

## 8. Open questions

1. Who operates Kirowen when the public service opens: you personally, or an association?
2. ~~Jurisdiction~~ → Spain (EU).
3. ~~Grants~~ → not for now.
4. Keep "Kirowen" or rename now? (pending)
5. ~~Community files~~ → added.
