# Deployment on a single host (phase 0)

The public log is served as static files by nginx behind Traefik. The
registry itself is the `kirowen` CLI run on the host: there is no write
API until phase 2.

Layout on the host:

```
kirowen/
  bin/kirowen            linux/arm64 build of ./cmd/kirowen
  keys/log.key           registry signing key (secret, mode 600, never leaves the host)
  keys/log.pub           registry verifier key (public)
  data/log/              public log (served at /log/v0/)
  data/envelopes/        envelopes (not served)
  docker-compose.yml     this directory's file
  nginx.conf             this directory's file
```

Build and copy:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o kirowen-linux-arm64 ./cmd/kirowen
```

Create the registry key on the host, once:

```sh
bin/kirowen keygen-log -origin kirowen.northernarchive.com/log/v0 -out keys/log
```

Create the empty log, then start the web container:

```sh
bin/kirowen init -data data -log-key keys/log.key
docker compose up -d
```

Check from anywhere:

```sh
kirowen audit -log https://kirowen.northernarchive.com/log/v0/ -log-pub log.pub
```

Back up `keys/` and `data/` off the host. The log is public and safe to copy
anywhere; `keys/log.key` is not.
