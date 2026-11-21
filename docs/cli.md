# Kirowen CLI: recording your first event

The `kirowen` command line client signs events with your source key, sends them to the API and keeps a receipt for each one. It runs on demand: nothing stays running in the background.

## 1. Build it

You need Go (see `go.mod` for the version).

```sh
git clone https://github.com/pasta0126/Kirowen.git ~/kirowen
cd ~/kirowen
go build -o bin/kirowen ./cmd/kirowen     # bin/ is ignored by git
```

Optional, so that `kirowen` works from any folder (zsh):

```sh
echo 'alias kirowen="$HOME/kirowen/bin/kirowen"' >> ~/.zshrc
source ~/.zshrc
kirowen          # prints the usage
```

After a `git pull`, run the `go build` line again.

## 2. Get credentials

A source has three files with the same base name:

| File | What it is | Secret? |
|---|---|---|
| `NAME.key` | Your Ed25519 key. It signs your events. | **Yes** |
| `NAME.cred.json` | The API URL, your `source_id` and your token. | **Yes** |
| `NAME.pub` | Your public key, so others can verify your events. | No |

The CLI finds `NAME.cred.json` next to `NAME.key`, so keep them side by side and do not rename one without the other.

**Option A: from the website.** Register at https://kirowen.northernarchive.com/#register and download the three files (`kirowen-XXXXXXXX.*`).

**Option B: from the CLI.**

```sh
kirowen keygen -out me             # writes me.key and me.pub
kirowen register -key me.key       # writes me.cred.json
```

Either way, keep them outside any git repository and readable only by you:

```sh
mkdir -p ~/.kirowen
mv ~/Downloads/kirowen-XXXXXXXX.{key,cred.json,pub} ~/.kirowen/
chmod 600 ~/.kirowen/*.key ~/.kirowen/*.cred.json
export KW=~/.kirowen/kirowen-XXXXXXXX.key   # optional shortcut, used below
```

## 3. Record an event

An event says "this source declares this content for this object". Without `-object`, `add` creates a new object first:

```sh
$ kirowen add -key $KW contract.pdf
new object 3f9a0c…
contract.pdf  object 3f9a0c…  leaf 7  receipt contract.pdf.receipt.json
```

- Only a salted hash of `contract.pdf` and your signature are sent. The file never leaves your machine.
- **Keep `contract.pdf.receipt.json` with the file.** It holds the signed envelope, the salt, the leaf index, the signed tree head and the inclusion proof. Without the salt you cannot show that this file is the one recorded. The CLI does not keep a copy.
- **Write down the object id.** The CLI does not remember it.

See it in the explorer: `https://kirowen.northernarchive.com/explorer/?leaf=7`.

## 4. Add more events to the same object

Each object has its own chained history (a new version, a correction, a status change). Pass its id:

```sh
kirowen add -key $KW -object 3f9a0c… contract-v2.pdf
kirowen add -key $KW -object 3f9a0c… scans/*.jpg     # one event and one receipt per file
```

To create an empty object and print its id:

```sh
kirowen object -key $KW
```

## 5. Verify

Anyone with your `.pub`, the receipt and the file can check the event, without a token:

```sh
$ kirowen verify -log https://kirowen.northernarchive.com/log/v0/ \
    -log-pub ~/kirowen/keys-public/kirowen.northernarchive.com-log-v0.pub \
    -pub ~/.kirowen/kirowen-XXXXXXXX.pub \
    contract.pdf.receipt.json contract.pdf
OK  envelope signed by key …
OK  included at leaf 7 of tree size …
OK  contract.pdf matches the recorded digest
OK  current tree head (size …) is consistent with the receipt's
```

To check the whole public log and its checkpoints:

```sh
kirowen audit -log https://kirowen.northernarchive.com/log/v0/ \
  -log-pub ~/kirowen/keys-public/kirowen.northernarchive.com-log-v0.pub
```

## What it proves

That your key signed a statement about this content's hash, and that the statement sits at this position in the log and has not been changed since. Detection of tampering relies on verifiers holding receipts and on the log being watched. It does not prove that the statement is true.

## Limits and caveats

- 10 events per second (burst 100) and 100,000 per day per source; envelopes up to 1 KiB.
- If you lose `NAME.key` you cannot sign events as this source. If you lose `NAME.cred.json` you cannot call the API as this source. Neither can be recovered or rotated yet.
- Alpha: the public log may be reset.
