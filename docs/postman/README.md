# Postman collection

`kirowen-api-v0.postman_collection.json` holds requests for the Kirowen API (`docs/api-v0.md`) and the public log. Import it in Postman (v11 or later) with **Import**.

## Before you start

- **Writes to production are permanent.** Registering a source adds a leaf to the public log, and it is never removed. You can register at most 5 sources per IP per hour. To experiment freely, set `baseUrl` to a local `kirowend` (for example `http://localhost:8080`).
- **You rarely type values by hand.** Each request saves what the next one needs in collection variables. Run them in order the first time: *Info*, *Register a source*, *Me*, *Create object*, *Get object*.
- **Keep secrets out of exports.** `token` and `sourceSeed` are secret. Do not share or commit a collection exported with their current values.

## Variables

| Variable | What it is | Example | Who sets it |
|---|---|---|---|
| `baseUrl` | API address | `https://kirowen-api.northernarchive.com` | Preset |
| `logUrl` | Public log address (ends with `/`) | `https://kirowen.northernarchive.com/log/v0/` | Preset, updated by *Info* |
| `origin` | Log name, used in the registration proof | `kirowen.northernarchive.com/log/v0` | *Info* |
| `sourceSeed` | Your private key seed: 64 hex characters | `db62c40f…dc463` | *Register* creates one if empty, or you paste `ed25519_seed` from a CLI key file |
| `token` | Your access token, starts with `kw_` | `kw_3f9a…` | *Register*, or paste it from your `.cred.json` |
| `sourceId` | Your source id: 32 hex characters | `9c1e…` | *Register* |
| `keyId` | Your key id: 64 hex characters | `a41d…` | *Register*, *Me* |
| `objectId` | An object id: 32 hex characters | `5b07…` | *Create object* |
| `envelopeHash` | An event hash: 64 hex characters | `e3b0…` | *Register*, *Get object*, *Submit event* |

Ids and hashes are always lowercase hex.

## API endpoints

| Request | What it does | What you need |
|---|---|---|
| **Info** `GET /v0/` | Shows the log name, the log address, the system key and the limits. | Nothing. |
| **Register a source** `POST /v0/sources` | Creates your source and returns your token. The token is shown **only once**. The console also prints the key and credentials in the CLI file format. | Nothing: the script signs the proof for you. To register another source, clear `sourceSeed`. |
| **Me** `GET /v0/sources/me` | Shows your source, your keys (with the next key sequence number, `next_kseq`) and how many objects you have. | `token` |
| **Create object** `POST /v0/objects` | Creates a new object (an item whose history you will record). The registry picks its id. | `token` |
| **Get object** `GET /v0/objects/{objectId}` | Shows the object's history and its head: `next_oseq` (the number of the next event) and `last_hash` (the last event). Only the owner can see it. | `token`, `objectId` |
| **Submit event** `POST /v0/events` | Records an event. Answers with a confirmation (position in the log and proof) in about 1 second. Sending the same file again returns the same confirmation. | `token` and a signed envelope file (≤ 1 KiB, see below). In **Body → binary**, pick the file. |
| **Get event confirmation** `GET /v0/events/{envelopeHash}` | Gives the proof that an event is in the log: its position, the signed tree head and the inclusion proof. Anyone can ask. | `envelopeHash` |
| **Get leaf** `GET /v0/leaves/0` | Gives any leaf by position (an event or a checkpoint), with the signed tree head and the inclusion proof. Anyone can ask. | Nothing. |
| **Get envelope** `GET /v0/envelopes/{envelopeHash}` | Downloads the signed envelope of one of your events. Use **Save response → Save to a file** to keep it. | `token`, `envelopeHash` of **your own** event (the registration hash gives 404 because that event belongs to the system) |
| **Get own key** `GET /v0/keys/{keyId}` | Shows your public key and its registration. With your token it also shows `next_kseq`. | `keyId` (`token` optional) |
| **Get system key** `GET /v0/keys/{systemKeyId}` | Shows the registry's own key, which signs the key registrations. | Nothing (set by *Info*). |

### About events

Postman cannot create a signed envelope (COSE_Sign1). You can:

- Send events with the CLI: `kirowen add -key source.key …`. To use the same source as Postman, save the key and credentials that *Register* prints to the console as `source.key` and `source.cred.json`.
- Download one of your envelopes with *Get envelope* and send it again with *Submit event*. You get the same confirmation back (idempotency).

Common answers: `200` OK, `409` someone moved the head (read *Get object* and *Me* again and re-sign), `403` the object or key is not yours, `429` too many requests.

## Error checks

These requests are expected to fail. They check that the API rejects bad input.

| Request | Expected |
|---|---|
| Me without token | `401` |
| Unknown token | `401` |
| Register with a bad proof | `4xx` |
| Submit a non-envelope | `4xx` |
| Unknown object | `404` |
| Unknown key | `404` |

## Public log

These requests read the log directly. They need no token and no API.

| Request | What it does | What you need |
|---|---|---|
| **Checkpoint** | Gets the signed tree head: log name, number of leaves and root hash. It also works out the path of the first tile. | Nothing. |
| **First hash tile** | Gets the first block of leaf hashes. | Run *Checkpoint* first. |
| **First entry bundle** | Gets the first block of leaves. | Run *Checkpoint* first. |
