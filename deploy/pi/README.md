# Deployment on a single host

Two containers behind Traefik:

- `kirowen-api` runs `kirowend` (registry + HTTP API) on `kirowen-api.northernarchive.com`. It is the only writer of `data/`.
- `kirowen-log` (nginx) serves, read-only, on `kirowen.northernarchive.com`: the website (`web/`: landing, browser registration, API console at `/docs/`) and the public log at `/log/v0/`.

Layout on the host:

```
kirowen/
  bin/kirowend           linux/arm64 build of ./cmd/kirowend
  keys/log.key           registry signing key (secret, never leaves the host)
  keys/log.pub           registry verifier key (public)
  keys/system.key        system source key, signs key registrations (secret)
  data/log/              public log (served at /log/v0/)
  data/envelopes/        envelopes (not served)
  data/state.db          SQLite state (not served)
  web/                   copy of the repository's web/ (served at /)
  docker-compose.yml, nginx.conf
```

Build:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o kirowend ./cmd/kirowend
```

Keys, once, on the host (with a locally built `kirowen` CLI):

```sh
kirowen keygen-log -origin kirowen.northernarchive.com/log/v0 -out keys/log
kirowen keygen -out keys/system
```

Copy the website from the repository: `rsync -a --delete web/ <host>:kirowen/web/`.

Start: `docker compose up -d`. The container runs as uid 1001, which must own `data/` and be able to read `keys/`.

Everything else (registration, objects, events) goes through the API. The host is not used to write.

Back up `keys/` and `data/` off the host when it matters. The log is public and safe to copy anywhere; the keys and `state.db` are not.
