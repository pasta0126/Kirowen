#!/usr/bin/env bash
# Deploys the current checkout to the reference host over SSH.
#
#   deploy/pi/deploy.sh <ssh-host>            build, check, upload, restart, smoke test
#   deploy/pi/deploy.sh <ssh-host> rollback   restore the previous deploy and restart
#
# Environment:
#   KIROWEN_DIR     remote directory (default: kirowen, relative to the remote home)
#   SKIP_TESTS=1    skip gofmt, go vet and go test
#   ALLOW_DIRTY=1   deploy with uncommitted changes
#
# What it touches on the host: bin/kirowend, web/, nginx.conf and
# docker-compose.yml. It never touches keys/ or data/. Each of the four is
# kept as *.prev for one rollback.
set -euo pipefail

HOST="${1:-}"
ACTION="${2:-deploy}"
DIR="${KIROWEN_DIR:-kirowen}"
SITE="https://kirowen.northernarchive.com"
API="https://kirowen-api.northernarchive.com"

if [[ -z "$HOST" ]]; then
  sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi

cd "$(git rev-parse --show-toplevel)"
say() { printf '\n== %s\n' "$*"; }
remote() { ssh -o BatchMode=yes "$HOST" "cd $DIR && $*"; }

restart() {
  say "Restarting containers"
  remote 'docker compose up -d --force-recreate 2>&1 | tail -n 4'
}

smoke() {
  say "Smoke test"
  local fail=0 code
  for url in "$SITE/" "$SITE/docs/" "$SITE/openapi.yaml" "$SITE/log/v0/checkpoint" "$API/v0/"; do
    code=$(curl -s -o /dev/null -w '%{http_code}' --retry 5 --retry-delay 2 --retry-all-errors "$url" || true)
    printf '%s %s\n' "$code" "$url"
    [[ "$code" == 200 ]] || fail=1
  done
  code=$(curl -s -o /dev/null -w '%{http_code}' -X OPTIONS \
    -H "Origin: $SITE" -H 'Access-Control-Request-Method: POST' "$API/v0/objects" || true)
  printf '%s CORS preflight\n' "$code"
  [[ "$code" == 204 ]] || fail=1
  if ! curl -s "$SITE/log/v0/checkpoint" | head -n 1 | grep -qx 'kirowen.northernarchive.com/log/v0'; then
    echo "checkpoint origin mismatch"; fail=1
  fi
  return $fail
}

if [[ "$ACTION" == rollback ]]; then
  say "Rolling back on $HOST:$DIR"
  remote 'for f in bin/kirowend nginx.conf docker-compose.yml; do [ -e "$f.prev" ] && cp -p "$f.prev" "$f"; done
          if [ -d web.prev ]; then rm -rf web && cp -a web.prev web; fi'
  restart
  smoke
  exit
fi
[[ "$ACTION" == deploy ]] || { echo "unknown action: $ACTION" >&2; exit 2; }

if [[ -n "$(git status --porcelain)" && "${ALLOW_DIRTY:-}" != 1 ]]; then
  echo "Uncommitted changes. Commit first, or set ALLOW_DIRTY=1." >&2
  exit 1
fi
REV=$(git rev-parse --short HEAD)

if [[ "${SKIP_TESTS:-}" != 1 ]]; then
  say "Checks"
  [[ -z "$(gofmt -l .)" ]] || { gofmt -l .; echo "gofmt needed" >&2; exit 1; }
  go vet ./...
  go test ./... >/dev/null
  echo "ok"
fi

say "Building kirowend $REV for linux/arm64"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o "$TMP/kirowend" ./cmd/kirowend

say "Uploading to $HOST:$DIR"
remote 'for f in bin/kirowend nginx.conf docker-compose.yml; do [ -e "$f" ] && cp -p "$f" "$f.prev"; done
        if [ -d web ]; then rm -rf web.prev && cp -a web web.prev; fi
        mkdir -p staging'
scp -q "$TMP/kirowend" deploy/pi/nginx.conf deploy/pi/docker-compose.yml "$HOST:$DIR/staging/"
rsync -a --delete --chmod=Da+rx,Fa+r web/ "$HOST:$DIR/staging/web/"

say "Validating on the host"
remote 'docker run --rm -v "$PWD/staging/nginx.conf:/etc/nginx/conf.d/default.conf:ro" \
          -v "$PWD/staging/web:/srv/web:ro" nginx:1.29-alpine nginx -t 2>&1 | tail -n 1
        docker compose -f staging/docker-compose.yml config -q && echo "compose ok"'

say "Installing"
remote 'install -m 755 staging/kirowend bin/kirowend
        cp staging/nginx.conf staging/docker-compose.yml .
        rm -rf web && mv staging/web web && rm -rf staging'
restart

if smoke; then
  say "Deployed $REV"
else
  say "Smoke test FAILED. Roll back with: $0 $HOST rollback"
  exit 1
fi
