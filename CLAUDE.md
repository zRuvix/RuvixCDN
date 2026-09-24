# CLAUDE.md — cdn.zruvix.com

Single Go binary that serves **both** the admin dashboard and the public CDN
for `https://cdn.zruvix.com`. Stack: Go (stdlib-first), plain HTML/CSS/vanilla JS,
Nginx Proxy Manager (NPM) in front, hosted on Oracle Cloud, Git for version control.

Read this file fully before changing anything. Keep it updated when architecture changes.

---

## 1. What this project does

- **Public CDN:** `GET https://cdn.zruvix.com/{dir}/{file}` serves files from disk
  (e.g. `/logos/img.png`, `/blog/2026/hero.webp`).
- **Dashboard:** password-protected UI under `/dash/` to log in, see stats, and
  upload / browse / delete / organise files.
- No database in v1. **The filesystem is the source of truth.**

## 2. Routes

| Method | Path                     | Auth | Purpose                                  |
|--------|--------------------------|------|------------------------------------------|
| GET    | `/dash/login`            | no   | Login page                               |
| POST   | `/dash/login`            | no   | Verify credentials, set session cookie   |
| POST   | `/dash/logout`           | yes  | Clear session                            |
| GET    | `/dash/`                 | yes  | Overview: file count, total size, recent |
| GET    | `/dash/manage`           | yes  | Browse dirs/files, upload, delete        |
| POST   | `/dash/api/upload`       | yes  | Multipart upload into a dir              |
| POST   | `/dash/api/delete`       | yes  | Delete a file or empty dir               |
| POST   | `/dash/api/mkdir`        | yes  | Create a directory                       |
| POST   | `/dash/api/rename`       | yes  | (later) rename/move                      |
| GET    | `/dash/static/*`         | no   | Dashboard CSS/JS (embedded)              |
| GET    | `/healthz`               | no   | Liveness check for NPM / monitoring      |
| GET/HEAD | `/{dir}/{path...}`     | no   | **Public CDN file serving**              |

Rules:
- `dash` is a **reserved top-level name**. Everything else at the root is a CDN dir.
  Also reserved: `healthz`, `favicon.ico`, `robots.txt`, and any name starting with `_` or `.`.
- All mutations are `POST` and require a valid session **and** a CSRF token.
- Unauthenticated requests to `/dash/*` (except login/static) → `302 /dash/login`.
- `/` itself returns a minimal 404 or a tiny landing text. Never list directories publicly.
- Directory URLs (`/logos/`) return `404`. No autoindex, ever.

Routing implementation: Go 1.22+ `http.ServeMux`. Register `/dash/` and the CDN
catch-all `/`; the more specific `/dash/` wins. Add a test that proves `/dash/manage`
never reaches the CDN handler.

## 3. Architecture

```
Internet
   │  HTTPS (Let's Encrypt, HTTP/2)
   ▼
┌────────────────────────────┐
│ Nginx Proxy Manager (Docker)│  TLS, force-SSL, upload size limit, optional edge cache
└─────────────┬──────────────┘
              │ HTTP  (private, X-Forwarded-For / X-Forwarded-Proto)
              ▼
┌────────────────────────────────────────────────────┐
│ zruvix-cdn  (single Go binary, systemd)  :8080       │
│                                                      │
│  middleware: recover → realip → log → sec-headers    │
│     ├─ /dash/*  → dashboard (html/template, embed)   │
│     │              └─ auth (signed cookie + CSRF)    │
│     └─ /*       → CDN handler (read-only, GET/HEAD)  │
│                        │                             │
│                 storage pkg (safe FS layer)          │
└────────────────────────┬───────────────────────────┘
                         ▼
              /var/lib/zruvix-cdn/files/{dir}/{file}
```

Design principles:
1. **stdlib first.** Allowed deps: `golang.org/x/crypto` (bcrypt). Ask before adding anything else.
2. **One binary.** Templates and static assets via `//go:embed`. No runtime file dependencies except the data dir.
3. **All filesystem access goes through `internal/storage`.** Handlers never call `os.*` on user-supplied paths.
4. **The CDN path is hot and boring.** No sessions, no cookies, no templates, no allocations you can avoid.
5. Fail closed: if config is missing or invalid at startup, exit non-zero with a clear message.

## 4. Repository layout

```
zruvix-cdn/
├── CLAUDE.md
├── README.md
├── go.mod                      # module zruvix-cdn, go 1.23
├── Makefile
├── .env.example
├── .gitignore
├── cmd/
│   ├── cdn/main.go             # entrypoint: load config, build server, graceful shutdown
│   └── hashpw/main.go          # prints a bcrypt hash for ADMIN_PASS_HASH
├── internal/
│   ├── config/                 # env parsing + validation
│   ├── server/                 # router + middleware wiring
│   ├── middleware/             # recover, realip, logging, secure headers, ratelimit
│   ├── auth/                   # session cookie sign/verify, bcrypt check, CSRF
│   ├── cdn/                    # public file handler
│   ├── dash/                   # dashboard handlers (pages + api)
│   └── storage/                # path validation, list, save, delete, stats
├── web/
│   ├── embed.go                # //go:embed templates static
│   ├── templates/              # layout.html, login.html, overview.html, manage.html
│   └── static/
│       ├── css/dash.css
│       └── js/manage.js
├── deploy/
│   ├── zruvix-cdn.service      # systemd unit
│   ├── deploy.sh               # pull, build, restart
│   └── npm-notes.md            # NPM proxy host settings + custom nginx snippets
└── docs/
```

Do not create new top-level directories without a reason. Keep packages small and single-purpose.

## 5. Configuration (env vars)

Loaded from `/etc/zruvix-cdn/env` in production (systemd `EnvironmentFile`), `.env` locally.
**Never commit real values.** `.env.example` documents every variable.

| Variable            | Example / default                   | Notes                                         |
|---------------------|-------------------------------------|-----------------------------------------------|
| `LISTEN_ADDR`       | `127.0.0.1:8080`                    | See §10 on reaching it from NPM               |
| `DATA_DIR`          | `/var/lib/zruvix-cdn/files`         | Root of all CDN files                         |
| `PUBLIC_URL`        | `https://cdn.zruvix.com`            | Used to display copyable file URLs            |
| `ADMIN_USER`        | `admin`                             |                                               |
| `ADMIN_PASS_HASH`   | bcrypt hash                         | Generate with `go run ./cmd/hashpw`           |
| `SESSION_SECRET`    | 32+ random bytes, base64            | HMAC key for session cookies                  |
| `SESSION_TTL`       | `12h`                               |                                               |
| `MAX_UPLOAD_MB`     | `50`                                | Must be ≤ NPM `client_max_body_size`          |
| `CACHE_MAX_AGE`     | `86400`                             | Seconds, public files                         |
| `TRUSTED_PROXIES`   | `172.16.0.0/12,127.0.0.1/32`        | Only trust `X-Forwarded-*` from these         |
| `LOG_LEVEL`         | `info`                              |                                               |

## 6. Public CDN handler (`internal/cdn`)

Behaviour:
- Methods: `GET`, `HEAD` only. Anything else → `405`.
- Resolve `{dir}/{path...}` via `storage.Open`. Reject on any failure with a plain `404` (never leak why).
- Serve with `http.ServeContent` so `Range`, `If-Modified-Since`, `If-None-Match`, and `HEAD` work.
- Compute a weak ETag from `modtime-size` (no hashing on the hot path).
- Response headers:
  - `Cache-Control: public, max-age=<CACHE_MAX_AGE>`
  - `X-Content-Type-Options: nosniff`
  - `Access-Control-Allow-Origin: *`
  - `Cross-Origin-Resource-Policy: cross-origin`
  - **No `Set-Cookie`, ever.**
- SVG (if allowed) additionally gets `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox`.
- Content-Type comes from a fixed extension map in code, not from the OS mime database.
- Support `?v=anything` as a cache-buster (ignored by the handler).

## 7. Dashboard (`internal/dash`, `web/`)

- Server-rendered `html/template` with one `layout.html`. Vanilla JS only where needed
  (`manage.js`: drag-drop upload with progress, delete confirm, copy-URL button).
- Plain hand-written CSS, one file, CSS variables for theme, dark mode via `prefers-color-scheme`.
  No CSS frameworks, no JS frameworks, no CDN-loaded assets (the dashboard must work offline from its own binary).
- **`/dash/`** overview: total files, total size, number of dirs, 10 most recent uploads.
- **`/dash/manage`**: dir sidebar/breadcrumb, file grid or table with image thumbnails
  (served from the public URL), size, modified time, copy-URL, delete. Upload form/dropzone
  targets the currently selected dir. "New folder" button.
- **`/dash/login`**: username + password. Generic error message. Rate-limited.
- Every template receives `{CSRFToken, PublicURL, Flash}`. Every form includes the CSRF token.
- Use `SameSite=Lax` cookies and POST-only mutations; still verify CSRF token.

## 8. Auth (`internal/auth`)

- Single admin account in v1 (`ADMIN_USER` + `ADMIN_PASS_HASH`, bcrypt cost ≥ 12).
- **Stateless session cookie**: `base64(payload).base64(HMAC-SHA256)` with `{user, exp, csrf}`; constant-time compare.
- Cookie flags: `HttpOnly; Secure; SameSite=Lax; Path=/dash`.
  `Path=/dash` means the cookie is **never sent on CDN asset requests** (better caching, smaller requests, less exposure).
- Login rate limit: in-memory token bucket per client IP (e.g. 5 attempts / 10 min), plus a fixed small delay on failure.
- Always run bcrypt compare even for unknown usernames (avoid user enumeration by timing).
- Logout clears the cookie. (Server-side revocation is out of scope for v1; rotate `SESSION_SECRET` to invalidate all sessions.)
- If multi-user or API keys are needed later, introduce SQLite (`modernc.org/sqlite`, pure Go, no CGO). Not before.

## 9. Storage layer (`internal/storage`) — security critical

Everything user-controlled (dir names, file names, paths) passes through here.

- **Dir name** regex: `^[a-z0-9][a-z0-9_-]{0,62}$` (lowercase). Nested dirs allowed to a max depth of 4, each segment validated the same way.
- **File name** regex: `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`. Uploads are sanitised: spaces → `-`, unicode stripped, lowercased extension.
- Reject: empty segments, `.`/`..`, leading dots, backslashes, NUL bytes, absolute paths, reserved top-level names.
- Path resolution: `filepath.Join(root, clean)` → verify result has `root + separator` as prefix → `EvalSymlinks` and re-verify. Never follow symlinks out of root.
- Extension allowlist (configurable in code): `png jpg jpeg gif webp avif ico svg css js(*) woff woff2 ttf mp4 webm mp3 pdf json txt`
  - **(\*) `.js`, `.html`, `.htm`, `.xhtml`, `.xml` are NOT allowed by default.** See threat note below.
- On upload also sniff the first 512 bytes (`http.DetectContentType`) and make sure it is consistent with the extension.
- Enforce `http.MaxBytesReader` with `MAX_UPLOAD_MB`.
- Writes are atomic: write to `*.tmp` in the same dir, `fsync`, `rename`. Never overwrite silently — the API takes an explicit `overwrite=true`.
- Deleting a non-empty dir is refused in v1.
- File perms `0644`, dir perms `0755`, owned by the service user.

**Threat note — same origin.** The dashboard and the CDN share one origin. A hostile
HTML/JS/SVG file uploaded and opened on `cdn.zruvix.com` could run script in the
dashboard's origin and act as the logged-in admin. Therefore: no HTML/JS/XML uploads by default,
SVG is served with a sandboxing CSP, and the session cookie is scoped to `/dash`. If you need
to host JS/CSS bundles for other sites, discuss moving the dashboard to a separate host first.

## 10. Deployment (Oracle Cloud + NPM)

**Server:** OCI compute VM (Ubuntu). If it is an Always Free Ampere instance, build with `GOARCH=arm64`.

**Service:** systemd unit `zruvix-cdn.service`, runs as an unprivileged user `zruvix`,
`EnvironmentFile=/etc/zruvix-cdn/env`, `Restart=on-failure`, hardening flags
(`NoNewPrivileges=true`, `ProtectSystem=strict`, `ReadWritePaths=/var/lib/zruvix-cdn`, `PrivateTmp=true`).

**Layout on the server:**
```
/opt/zruvix-cdn/zruvix-cdn        # binary
/etc/zruvix-cdn/env               # secrets, chmod 600
/var/lib/zruvix-cdn/files/        # CDN data (back this up)
```

**NPM proxy host:**
- Domain: `cdn.zruvix.com` → scheme `http`, forward to the Go app (see reachability below).
- SSL tab: request Let's Encrypt cert, enable **Force SSL** and **HTTP/2**.
- Websockets: off. Block Common Exploits: on.
- Advanced tab: `client_max_body_size 60m;` (≥ `MAX_UPLOAD_MB`). Make sure `X-Forwarded-For` and `X-Forwarded-Proto` are passed (NPM does by default).
- Optional edge cache (verify against your NPM version's custom-config docs): define `proxy_cache_path` in NPM's custom `http_top.conf`, enable caching for everything **except** `location /dash/` (must never be cached).

**Reachability (NPM runs in Docker):** the app must be reachable from the NPM container.
Either bind `LISTEN_ADDR` to the Docker bridge gateway / `0.0.0.0` **and** block port 8080 from the internet,
or run the Go app in the same Docker network. Do **not** expose 8080 publicly. Only 80/443 (and 81 restricted to your IP for the NPM admin UI) should be open.

**Oracle firewall gotcha:** open ports in *both* the OCI VCN security list/NSG **and** the instance's own
`iptables`/`netfilter-persistent` rules (Oracle Ubuntu images ship with restrictive defaults).

**Deploy flow (`deploy/deploy.sh`):**
```
git pull --ff-only
go test ./...
go build -trimpath -ldflags "-s -w -X main.version=$(git describe --always --dirty)" -o /opt/zruvix-cdn/zruvix-cdn.new ./cmd/cdn
mv zruvix-cdn.new zruvix-cdn && sudo systemctl restart zruvix-cdn
curl -fsS http://127.0.0.1:8080/healthz
```

**Backups:** nightly `tar`/`rclone` of `/var/lib/zruvix-cdn/files` to OCI Object Storage. Files are not in Git.

## 11. Git workflow

- Branches: `main` (always deployable), feature branches `feat/…`, `fix/…`, merge via PR or squash.
- Commit style: Conventional Commits (`feat(cdn): add range support`, `fix(storage): reject symlink escape`).
- Tag releases `vMAJOR.MINOR.PATCH`.
- `.gitignore` must include: `.env`, `*.env`, `bin/`, `dist/`, `data/`, `files/`, `*.tmp`, `*.log`.
- **Never commit** secrets, password hashes, uploaded files, or the server env file.

## 12. Commands

```
make run        # go run ./cmd/cdn with .env
make build      # static binary into bin/
make test       # go test -race ./...
make lint       # go vet ./... && staticcheck ./...   (if installed)
make hashpw     # go run ./cmd/hashpw
make deploy     # ssh + deploy.sh (optional)
```

Local dev: `cp .env.example .env`, set `DATA_DIR=./data/files`, generate a hash with `make hashpw`, run `make run`,
open `http://localhost:8080/dash/login`. (`Secure` cookies: allow `COOKIE_INSECURE=true` in dev only, refuse in production.)

## 13. Coding conventions

- Go 1.23+, `gofmt` clean, `go vet` clean, tests with `-race`.
- Errors wrapped with `%w`; log once at the boundary, not at every layer.
- `log/slog` structured logging to stdout (systemd → journald). Log: method, path, status, bytes, duration, client IP. **Never log passwords, cookies, or CSRF tokens.**
- `context.Context` first param for anything that can block. No globals except `version`.
- HTTP server timeouts are mandatory: `ReadHeaderTimeout 5s`, `ReadTimeout 30s`, `WriteTimeout` generous for large downloads (or use per-handler `ResponseController`), `IdleTimeout 120s`. Graceful shutdown on SIGTERM.
- Handlers return early, keep them thin; logic lives in `storage` / `auth`.
- Table-driven tests. **`storage` must have traversal tests** (`../`, `..%2f`, encoded slashes, symlink escape, NUL, backslashes, very long names, reserved names).
- Templates: always `html/template`, never `text/template`, never mark user data as `template.HTML`.

## 14. Working agreements for Claude

- Prefer small, reviewable changes. Explain the *why* in commit messages.
- Do not add dependencies, frameworks, or a database without asking.
- Do not weaken a security rule in §8/§9 to make something convenient. Propose an alternative instead.
- When adding a route, update the table in §2 and add a test.
- When adding an env var, update `.env.example` and §5.
- Anything that touches path handling or auth needs tests in the same change.
- If a request conflicts with this file, say so and ask before proceeding.

## 15. Roadmap

1. **v0.1** — config, server skeleton, `/healthz`, storage layer + traversal tests, CDN handler.
2. **v0.2** — auth (login/logout, session, CSRF, rate limit), `/dash/login`.
3. **v0.3** — `/dash/` overview and `/dash/manage` with upload, mkdir, delete.
4. **v0.4** — systemd unit, deploy script, NPM setup, backups.
5. **Later** — rename/move, bulk upload, image thumbnails/resizing (`?w=400`), per-dir usage stats, multi-user/API keys (SQLite), separate dashboard host.

## 16. Open decisions

- Max total storage quota / per-dir quota?
- Should filenames be preserved or content-hashed (`img.a1b2c3.png`) to allow `immutable` caching?
- Do you need to host JS/CSS/HTML for other sites? (Changes the same-origin threat model, see §9.)
- Single admin forever, or multiple users?