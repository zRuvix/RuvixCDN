# zruvix-cdn

Single Go binary serving the admin dashboard and the public CDN for
`https://cdn.zruvix.com`. See `CLAUDE.md` for the full architecture.

## Local dev

```
cp .env.example .env
# fill in ADMIN_PASS_HASH via:
go run ./cmd/hashpw
# fill in SESSION_SECRET via:
openssl rand -base64 32
make run
```

Open `http://localhost:8080/dash/login`. The dashboard has login,
overview (`/dash/`), and file management (`/dash/manage` with upload,
mkdir, delete).

## Layout

```
cmd/cdn            entrypoint
cmd/hashpw         bcrypt hash helper for ADMIN_PASS_HASH
internal/config    env parsing + validation (fail-closed)
internal/server    router + HTTP timeouts
internal/middleware recover, realip, logging, secure headers
internal/storage   path validation, save/delete/list/stats (security critical)
internal/cdn       public read-only file handler
internal/auth      session cookie, CSRF, login rate limit
internal/dash      dashboard pages (overview/manage) + upload/mkdir/delete APIs
web/               embedded templates/static (dashboard)
deploy/            systemd unit, deploy script, NPM notes
```

## Commands

```
make run      # go run ./cmd/cdn with .env
make build    # static binary into bin/
make test     # go test -race ./...
make lint     # go vet ./... && staticcheck ./... (if installed)
make hashpw   # go run ./cmd/hashpw
make deploy   # ssh + deploy.sh
```
