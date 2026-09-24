#!/bin/sh
# Deploy flow per CLAUDE.md §10. Run on the server.
set -eu

VERSION="$(git describe --always --dirty)"

git pull --ff-only
go test ./...
go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
  -o /opt/zruvix-cdn/zruvix-cdn.new ./cmd/cdn
mv /opt/zruvix-cdn/zruvix-cdn.new /opt/zruvix-cdn/zruvix-cdn
sudo systemctl restart zruvix-cdn
curl -fsS http://127.0.0.1:8080/healthz
