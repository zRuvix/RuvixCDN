# NPM notes — cdn.zruvix.com (stub, full wiring verified in v0.4)

- Domain `cdn.zruvix.com` → scheme `http`, forward host to the Go app
  (`LISTEN_ADDR`, reachable from the NPM container — see CLAUDE.md §10).
- SSL tab: Let's Encrypt cert, Force SSL, HTTP/2.
- Websockets: off. Block Common Exploits: on.
- Advanced: `client_max_body_size 60m;` (≥ `MAX_UPLOAD_MB`).
- `X-Forwarded-For` / `X-Forwarded-Proto` are passed by NPM by default;
  the app only trusts them from `TRUSTED_PROXIES`.
- Optional edge cache (v0.4): cache everything **except** `location /dash/`.
