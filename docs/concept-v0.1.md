# Project: Universal Immutable Event Registry

**Concept document and initial functional definition**

**Version:** 0.1
**Status:** Concept defined. Technical analysis and design pending.
**Audience:** Claude (and other agents), as initial context for studying and developing the project.

*Translated from the original Spanish document.*

---

## 1. Overview

We want to build a universal infrastructure for recording immutable events. It receives information from many completely independent systems, stores it sequentially, and cryptographically guarantees the integrity of its history.

The system is not intended to handle cryptocurrencies, NFTs, financial transactions or digital assets.

The initial inspiration comes from blockchains and their ability to link records cryptographically, but there is no requirement to use a conventional blockchain.

What we actually care about is its fundamental principle: **once information is recorded, it must not be possible to modify or delete it silently without compromising the verifiable integrity of the history.**

Any change, update or correction must produce a new event.

The goal is a reusable infrastructure that gives other applications a verifiable history of their data, whatever its nature or purpose.

### Core principle

**Events are appended, never overwritten. The past remains verifiable, and changes produce new events.**

---

## 2. The problem we want to solve

Many applications hold information that changes all the time. For example:

- A sensor records temperature values.
- A delivery company updates the status of its shipments.
- An application records user-related events.
- A business system records operations or changes to information.
- An IoT device reports state changes.

These applications usually rely on conventional databases, where values can be updated and overwritten.

Event Sourcing architectures do keep event histories. However, Event Sourcing alone does not guarantee that someone with access to the infrastructure cannot modify, delete or rebuild earlier records.

We want to add a layer of trust. Our system must not depend solely on the application behaving correctly, or on an administrator choosing not to modify information. The integrity of the history must be cryptographically checkable.

---

## 3. Independence of participating systems

Systems with no relationship to one another must be able to use the registry at the same time. They do not need to share:

- Owners.
- Users.
- Data models.
- Data structures.
- Goals.
- Business rules.
- Technologies.
- Infrastructure.

The registry acts as shared infrastructure. Each system sends events about its own objects and keeps its functional independence.

### Example A: home sensors

A home has two temperature sensors.

**Living-room sensor.** It periodically records the living room's conditions. Its history might contain:

- 12:00 — Temperature: 23.0 °C.
- 12:05 — Temperature: 23.2 °C.
- 12:10 — Temperature: 23.1 °C.

**Bedroom sensor.** It records the conditions of another room:

- 12:00 — Temperature: 20.0 °C.
- 12:05 — Temperature: 20.1 °C.
- 12:10 — Temperature: 20.3 °C.

Each sensor has its own object and its own history. No reading replaces an earlier one; every reading is a new event.

The home application can look up the latest value, reconstruct how the temperature evolved, or analyze historical values.

### Example B: delivery company

A company uses the same registry to document the events of its shipments. Shipment `5842` might generate:

1. Order received.
2. Order confirmed.
3. Order being prepared.
4. Order ready.
5. Courier assigned.
6. Order picked up.
7. Out for delivery.
8. Delivered.

All of these events relate to the same reference, shipment `5842`, and the company can reconstruct its full history.

If a delivery is wrongly reported, the original event remains. The correction produces a new event that references it.

### Independence of both examples

The sensors and the delivery company have no relationship and know nothing of each other's objects, structures or rules. Yet all their events can go into the same universal registry.

---

## 4. Single, sequential global registry

The system maintains a global sequence of events. Different systems may send events at the same time. The registry must accept that concurrency, but every confirmed event occupies a unique position in a global sequence. For example:

| Sequence | Source | Object | Event |
|---|---|---|---|
| 1 | Home | Living-room sensor | 23.0 °C |
| 2 | Delivery | Shipment 5842 | Order received |
| 3 | Home | Bedroom sensor | 20.0 °C |
| 4 | Delivery | Shipment 5842 | Being prepared |
| 5 | Home | Living-room sensor | 23.2 °C |
| 6 | Delivery | Shipment 5842 | Courier assigned |
| 7 | Home | Bedroom sensor | 20.1 °C |

The global sequence is independent of where events come from. **All events are part of a single shared logical history.**

A position in the registry indicates the order in which events were definitively incorporated, not necessarily the order in which they actually happened. The time declared by the source must be kept distinct from the time the registry accepts the event.

---

## 5. Cryptographic chaining

Each entry must include a cryptographic reference to the previous state of the chain, so that events are linked. Conceptually:

**Event 1 → Event 2 → Event 3 → Event 4 → Event 5**

Each event depends cryptographically on the previous one. If someone alters the content of Event 2, its cryptographic fingerprint changes and no longer matches the reference stored in Event 3, so the integrity of the chain is compromised.

Building a seemingly valid version would require recomputing the cryptographic references from the altered event to the end of the chain. This behavior is one of the project's fundamental principles.

### Acknowledged limitation

A person with full control of the infrastructure could try to modify an event and recompute all later references. Cryptographic chaining alone therefore does not make modification impossible.

We need additional mechanisms that can show which history was authentic, even when someone tries to replace it with another. This need is addressed through validation points and independent proofs.

---

## 6. Independent per-object histories

Although there is a single global sequence, each object must be able to reconstruct its own history. For example:

- **Global history:** Event 1 → Event 2 → Event 3 → Event 4 → Event 5 → Event 6
- **Living-room sensor history:** Event 1 → Event 5
- **Shipment 5842 history:** Event 2 → Event 4 → Event 6
- **Bedroom sensor history:** Event 3

The relationship between events of the same object must be identifiable without ambiguity. Each object belongs to a given scope or source system, which avoids collisions between identical identifiers used by different applications.

### Two kinds of relationship

Conceptually, we intend to maintain:

- **Global relationship:** each event is linked to the immediately preceding event in the universal sequence.
- **Per-object relationship:** each event can be linked to the previous event of the same object.

Together, the system then offers:

- A verifiable global chronology.
- An individual history per object.
- The ability to reconstruct states.
- Full traceability of changes and events.

How both relationships are implemented technically is still open.

---

## 7. Immutability and the evolution of information

No confirmed event may be modified through any ordinary system operation. There must be no functional update or delete operations on historical content. When information changes, a new event is generated. For example:

- **Event 100:** shipment 5842 has status `out_for_delivery`.
- **Event 108:** shipment 5842 has status `delivered`.
- **Event 115:** the previous status is found to have been recorded by mistake.
- **Event 116:** a correction is recorded, stating the correct status and referencing the relevant event.

The earlier events remain. The current state is an interpretation of the recorded events, not a retroactive modification of them.

### Event vs. state

The registry stores historical events, and consuming applications interpret them to determine current states.

The registry does not need to understand the meaning of a state such as `delivered`, `cancelled` or `23 °C`. It must preserve the content, identify where it came from and keep it traceable.

---

## 8. Automatic validation checkpoints

There is a periodic validation mechanism made of special events generated by the system itself, provisionally called **checkpoints**.

### Agreed initial frequency

**One checkpoint is generated for every 1,000 accepted ordinary events.**

Checkpoints are internal events and do not count toward those 1,000 ordinary events. No time-based frequency is set for now.

### How it works conceptually

1. The system incorporates 1,000 events from various sources.
2. It then automatically generates a checkpoint that cryptographically represents the accumulated state of the history up to that point.
3. It continues incorporating events.
4. After another 1,000 ordinary events, it generates the next checkpoint, and so on.

Example:

- Ordinary events 1–1,000.
- Checkpoint A.
- Ordinary events 1,001–2,000.
- Checkpoint B.
- Ordinary events 2,001–3,000.
- Checkpoint C.

Checkpoints are part of the global sequence and have their own positions.

### Purpose

Checkpoints keep incremental integrity checks from having to walk the entire history from the beginning every time. With a checkpoint that was previously authenticated and is considered reliable, the segment after that point can be verified on its own. Older historical checks remain possible when needed.

### Key condition

A checkpoint generated by the system itself is not, on its own, independent proof of integrity. An administrator able to modify the entire chain and all its checkpoints could try to replace the whole history.

We therefore need mechanisms so that the state attested by checkpoints can be stored or verified outside the system's exclusive control. How this will be done is not decided yet.

### Checkpoint requirements

Checkpoints must:

- Identify the segment of events they certify.
- Cryptographically represent the state of the history.
- Maintain verifiable continuity with earlier checkpoints.
- Enable incremental verification.
- Be independently verifiable through appropriate proofs.
- Not replace or remove the original events.
- Make it easier to detect reconstructions that are incompatible with previously attested states.

---

## 9. Independent verifiability

One of the most important goals is that trust must not depend solely on the infrastructure's administrators. We want a third party to be able to check that a given piece of information:

1. Is part of the recorded history.
2. Retains exactly its original content.
3. Belongs to a cryptographically consistent sequence.
4. Is consistent with a previously attested historical state.

Verification should be possible independently of the service that displays the data. It is not enough for our application to answer that an event is valid; there must be a proof that can be checked by independent means.

### The guarantee we pursue

If someone modifies or rebuilds historical information, they should not be able to present that version as authentic to verifiers who hold valid proofs of the earlier history.

We do not claim that altering a server's files is physically impossible. The goal is that tampering cannot go unnoticed when checked against independent proofs.

---

## 10. Sources, objects and events

The conceptual model distinguishes three elements.

### Source

The system, application, organization or device that produces information. Examples:

- A home system.
- An IoT device.
- A delivery platform.
- A business service.

The source must be identifiable and authenticated.

### Object

The entity whose history we want to keep. Examples:

- Living-room sensor.
- Bedroom sensor.
- Shipment 5842.
- Order 872.
- Device 431.

Two different sources may use the same identifiers without their objects being confused.

### Event

A statement or occurrence related to an object. Its content can vary widely.

The system must not impose a universal business model. It only needs a minimal set of information that identifies the origin, the object, the content and its incorporation into the history. The concrete structures are still to be designed.

---

## 11. Nature of the recorded information

The infrastructure must be agnostic to what the data means. It is not specialized in sensors, logistics, e-commerce or any other activity. Conceptually, events could include:

- Numeric values.
- Text.
- States.
- Data structures.
- References to documents.
- Cryptographic fingerprints of files.
- Relationships with other events.
- Events generated by other systems.

We have not yet decided which formats, sizes or storage modes will be supported. The purpose is a universal mechanism for recording and traceability.

---

## 12. Source of truth: scope and meaning

We want each system to be able to use the registry as the historical source of reference for its events. But two concepts must be kept apart:

- **Registry truth:** proving that a given source recorded a specific statement, and that it has not been altered without leaving detectable evidence.
- **Real-world truth:** proving that the statement reflects something that actually happened.

Our system primarily guarantees the first.

For example, if a faulty sensor reports 35 °C when the real temperature is 23 °C, the registry faithfully keeps the sensor's statement. It does not automatically make the reading correct.

Likewise, if a company records an order as delivered before it has arrived, the system keeps the statement and allows a later correction to be recorded.

Validating real-world content is the job of the sources or of other external mechanisms.

---

## 13. Isolation between participants

Sharing a global chain does not mean sharing private information, and participating systems remain independent. The infrastructure must let events be recorded in a common structure without automatically granting access to other participants' data.

It is necessary to distinguish between:

- The verifiable existence of a record.
- Its identifying information.
- Its content.
- The right to query it.

The possibility of public verification must not necessarily mean that all data is public. We must study how to preserve global integrity without revealing other sources' private information.

Privacy, access control and legal obligations will be part of the later analysis.

---

## 14. Concurrency and event ordering

Systems must be able to emit events simultaneously. The incorporation mechanism must establish a coherent, unique global sequence for confirmed events; two confirmed events must never share the same global position.

We must also distinguish between:

- The moment an event happens.
- The moment its source reports it.
- The moment the registry definitively accepts it.

The global sequence represents the order of confirmed incorporation. It is not necessarily proof of the real temporal order between events that happened in different systems.

The technical design will have to resolve concurrency, definitive acceptance and failure behavior.

---

## 15. Retention, availability and recovery

Cryptographic integrity does not automatically mean the data will be available forever. The project must consider three distinct properties:

- **Integrity:** records cannot be altered without the tampering being detectable, under the defined trust conditions.
- **Availability:** records can be queried when needed.
- **Durability:** records and the necessary proofs are preserved over time.

The loss of a server should not necessarily destroy the history. However, we have not yet defined replication, retention, recovery or storage mechanisms; those decisions belong to the technical design. No guarantee of perpetual retention has been established either.

---

## 16. Access to and use of the service

We envision infrastructure that other applications can integrate relatively easily. Conceptually, it should allow the following:

- **Register an event:** a source asks to incorporate a new event associated with an object.
- **Confirm incorporation:** the system returns a confirmation that unambiguously identifies the accepted record and allows the corresponding proofs to be obtained.
- **Query an object's history:** an application retrieves all events related to a given reference, provided it is authorized.
- **Query derived state:** an application reconstructs an object's state from its events. The rules for interpreting events normally belong to the originating application, not to the ledger.
- **Verify integrity:** an authorized consumer cryptographically checks the validity and inclusion of information and its consistency with previously attested states.
- **Query checkpoints:** the system exposes its validation points and the proofs needed to check them.

These are conceptual capabilities, not decisions about endpoints, protocols or concrete interfaces.

---

## 17. Economic goal

We want to explore building this infrastructure and offering it for free. We do not intend to create a cryptocurrency or fund operations through tokens, mining or transaction fees. The initial priority is to minimize operating costs. The following will be favored:

- Open technologies.
- Operational simplicity.
- Storage efficiency.
- Low resource consumption.
- Deployability on inexpensive infrastructure.
- Ability to grow progressively.

This does not mean assuming the infrastructure can run indefinitely at no cost. Free use is an initial aspiration, not a proven economic guarantee. The sustainability model is still open.

---

## 18. What we do not intend to build

It is important to set the project's boundaries. We do not want:

- A cryptocurrency.
- A token.
- An NFT platform.
- An asset exchange system.
- A marketplace.
- A financial platform.
- Event Sourcing specialized for one specific application.
- A system that interprets the business rules of every participating application.
- A conventional database with a simple history field.
- A complex blockchain just for the sake of using the word blockchain.

Nor have we decided to build a decentralized network. Decentralization could be a tool for achieving certain guarantees, but it is not a goal in itself.

---

## 19. Conceptual decisions taken

These decisions are part of the project's current definition.

1. The project will be a universal event-recording infrastructure.
2. It will accept independent sources and applications.
3. There will be a single logical global sequence of confirmed events.
4. Events will be cryptographically chained.
5. Confirmed events will be functionally append-only.
6. Updates and corrections will generate new events.
7. Each object will have a reconstructible individual history.
8. Participating systems will not need to share data models.
9. The registry will be agnostic to event content.
10. The system itself will generate automatic checkpoints.
11. **The initial frequency will be 1 checkpoint per 1,000 ordinary events.**
12. Checkpoints will enable incremental verification from previously attested states.
13. Independent cryptographic verifiability will be pursued.
14. We will try to prevent historical tampering from going unnoticed by verifiers that hold authentic proofs.
15. The architecture must separate data integrity, truthfulness of statements, availability and durability.
16. There will be no associated cryptocurrency or token.
17. The choice of blockchain, cryptographic database or another solution remains open.
18. Operating cost must be kept as low as possible, with the aspiration of offering a free service.

---

## 20. Open questions

We have not decided:

- Project name.
- Programming language(s).
- Storage technologies.
- Software architecture.
- Final use or rejection of blockchain.
- Specific cryptographic systems.
- Hash algorithms.
- Signature and identity mechanisms.
- Strategy for external verifiers or witnesses.
- Methods for publishing and safekeeping checkpoints.
- Communication protocols.
- Authentication and authorization models.
- Final event formats.
- Size and volume limits.
- Duplicate and retry handling.
- Scalability strategy.
- Replication and recovery.
- Privacy and retention policy.
- Availability guarantees.
- Governance model.
- Economic operating model.

All of these decisions must be studied later. We do not want to constrain them prematurely.

---

## 21. Conceptual success criteria

The system should be considered satisfactory if it can demonstrate the following behaviors:

1. **Multiple sources.** Two sensors and a company record events simultaneously without interfering with one another, and all of them are incorporated into a coherent global sequence.
2. **Individual history.** It is possible to retrieve only the events related to a shipment, without getting other sensors' events.
3. **Update.** A source reports a new value. The previous value remains in the history and is not overwritten.
4. **Correction.** An application detects a historical error. The correction is recorded as a new event related to the earlier one.
5. **Fraudulent modification.** Someone alters the content of an old event. The cryptographic check detects that the stored history is no longer consistent with the authentic proofs held elsewhere.
6. **Fraudulent reconstruction.** An administrator tries to alter an event and rebuild the later cryptographic references. A verifier holding independent historical proofs detects that the rebuilt history is incompatible.
7. **Incremental validation.** After several thousand events, the system uses a previously attested checkpoint to verify the later segment without walking the earlier history again.
8. **Privacy.** A participant can verify the guarantees that concern it without gaining unauthorized access to other participants' content.

---

## 22. Project philosophy

The main philosophy is a radical separation of two responsibilities:

- **Applications are responsible for the information they produce and for interpreting it.**
- **The registry is responsible for preserving statements, maintaining their sequence and providing verifiable proofs of their historical integrity.**

The infrastructure must not become a monolithic application that knows every rule of the systems that use it. Its role must be simple, universal and reusable.

We want a technically rigorous solution without artificial complexity. A blockchain, a distributed network or any specific technology is justified only if it provides real guarantees that simpler, cheaper mechanisms cannot.

---

## 23. Next phase of work with Claude

This document is neither a technical specification nor a request for immediate implementation. Its purpose is to establish context and conceptual decisions. The next phase is to study possible technical solutions. Claude should:

- Analyze whether the model is coherent and viable.
- Identify risks, contradictions or incorrect assumptions.
- Clearly distinguish real guarantees from apparent ones.
- Evaluate technology alternatives without assuming we need a blockchain.
- Consider operating and maintenance costs.
- Study the mechanisms needed for independent verifiability.
- Propose an architecture that respects the agreed principles.

Pending decisions must not be interpreted as established requirements.

**The ultimate goal is a universal, efficient and verifiable registry infrastructure, in which the history of events cannot be silently modified and each system can reliably reconstruct how its own objects evolved.**

---

*End of concept document — version 0.1.*
