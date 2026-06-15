# CLAUDE.md — Restricted-Area Website (Rust / Axum)

## Project Overview

A minimal, content-first website with a **restricted area** protected by a robust authentication system. The admin issues credentials (a generated username + generated password) via the admin panel. Each credential pair is valid for exactly **3 logins**. After the third login the credential is permanently expired. The system has no email functionality — the admin copies the generated credentials and delivers them to the user out-of-band.

---

## Technology Stack

| Layer | Choice |
|---|---|
| Language | Rust (stable, latest) |
| Web framework | Axum |
| Database | PostgreSQL |
| Sessions | Server-side, cookie-based (stored in PostgreSQL) |
| Frontend | Plain HTML + CSS (static files, no JS framework, no templating engine) |
| Password hashing | `argon2` crate |
| Random generation | `rand` crate with `OsRng` |
| Migrations | `sqlx` with compile-time checked queries (`sqlx migrate`) |
| Config | `.env` file loaded via `dotenvy` |
| Deployment | Ubuntu bare metal, NGINX reverse proxy, `systemd` service |

No email/SMTP dependency anywhere in the project.

---

## Project Structure

```
project-root/
├── CLAUDE.md
├── Cargo.toml
├── .env.example
├── migrations/
│   ├── 0001_create_users.sql
│   ├── 0002_create_sessions.sql
│   └── 0003_create_access_log.sql
├── static/
│   ├── css/
│   │   └── style.css
│   ├── index.html              # Public landing page
│   ├── login.html              # Login page
│   └── restricted/
│       └── index.html          # Restricted content (never served directly by NGINX)
├── src/
│   ├── main.rs
│   ├── config.rs
│   ├── db.rs
│   ├── auth/
│   │   ├── mod.rs
│   │   ├── handlers.rs         # login, logout route handlers
│   │   ├── middleware.rs       # session validation extractor
│   │   └── credentials.rs     # username generation, password generation, hashing, verification
│   ├── admin/
│   │   ├── mod.rs
│   │   └── handlers.rs         # issue credentials, list users, revoke, reset
│   ├── restricted/
│   │   ├── mod.rs
│   │   └── handlers.rs         # serve restricted static content + inject access banner
│   └── error.rs                # Unified error type
└── deploy/
    ├── nginx.conf
    └── systemd.service
```

---

## Database Schema

### `users` table
```sql
CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username      TEXT NOT NULL UNIQUE,           -- generated two-word username e.g. "marble-epoch"
    password_hash TEXT NOT NULL,
    max_uses      INTEGER NOT NULL DEFAULT 3,     -- always 3, kept as column for future flexibility
    use_count     INTEGER NOT NULL DEFAULT 0,
    active        BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### `sessions` table
```sql
CREATE TABLE sessions (
    id          TEXT PRIMARY KEY,                 -- SHA-256 hash of the raw token
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL              -- NOW() + SESSION_DURATION_SECS
);
```

### `access_log` table
```sql
CREATE TABLE access_log (
    id           BIGSERIAL PRIMARY KEY,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    username     TEXT NOT NULL,                   -- denormalised for easy admin reading
    accessed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address   TEXT
);
```

---

## Credential Generation

### Username — two random words
- Maintain two embedded word lists in `src/auth/credentials.rs`: one adjective list (~200 words) and one noun list (~200 words).
- Pick one word from each list using `OsRng`.
- Join with a hyphen: `silent-harbor`, `marble-epoch`, `amber-ridge`.
- Words must be lowercase, plain ASCII, no ambiguous characters.
- Before inserting, verify the generated username does not already exist in the DB. Retry up to 10 times if collision.

### Password — random string
- Character set: uppercase A-Z, lowercase a-z, digits 0-9, symbols `!@#$%^&*`.
- Length: 14 characters.
- Generated with `OsRng` — cryptographically random.
- Never stored in plaintext. Hashed immediately with Argon2id before any DB write.
- The plaintext password is returned **once** in the `POST /admin/issue` response and never recoverable again.

---

## Authentication Flow

### Login (`POST /login`)
1. Receive `username` + `password` from HTML form (POST body, `application/x-www-form-urlencoded`).
2. Look up user by `username`. If not found, run a dummy Argon2 verify (constant-time) and return generic error — never reveal whether the username exists.
3. Check `active = TRUE` and `use_count < max_uses`. If either fails → return generic "Access denied" error (same response shape as wrong password).
4. Verify submitted password against `password_hash` using Argon2id.
5. If valid:
   - Increment `use_count` atomically (`UPDATE ... SET use_count = use_count + 1 WHERE id = $1 RETURNING use_count`).
   - If new `use_count >= max_uses`: set `active = FALSE` in the same transaction.
   - Insert a new row in `sessions` (generate 256-bit raw token, store SHA-256 hash, set `expires_at = NOW() + SESSION_DURATION_SECS`).
   - Set `Set-Cookie: session=<raw_token>; HttpOnly; Secure; SameSite=Strict; Path=/`.
   - Store `use_count` and `max_uses` in the session row (or re-read from users) so the restricted handler can display the access banner.
   - Redirect to `/restricted/`.
6. Insert a row in `access_log`.

### Session Validation (Axum extractor — `AuthUser`)
Applied to every request under `/restricted/*`:
- Read `session` cookie value (raw token).
- Compute `SHA-256(raw_token)` and query `sessions` WHERE `id = hash AND expires_at > NOW()`.
- Join with `users`: `active = TRUE` (active may be FALSE if this is the last allowed session — see note below).
- If valid → attach `AuthUser { user_id, username, use_count, max_uses }` extension to request.
- If missing/invalid/expired → clear cookie, redirect to `/login`.

> **Note on last-session access:** When `active` is set to `FALSE` on login (use_count reached max), the session created during that same login is still valid and must grant access for its duration. The middleware must check session validity independently from `active`. The `active` flag only blocks *new logins*, not existing valid sessions.

### Logout (`POST /logout`)
- Delete session row from `sessions` (matched by hashed token from cookie).
- Clear the cookie (`Set-Cookie: session=; Max-Age=0; Path=/`).
- Redirect to `/`.

---

## Access Count Banner

The restricted area must display a contextual banner at the top of every page informing the user of their access status. This is injected server-side by the `restricted::handlers` module — it reads `use_count` and `max_uses` from the `AuthUser` extractor and prepends a banner HTML snippet to the static file response.

### Banner messages

| Condition | Message |
|---|---|
| `use_count == 1` | `Welcome. This is your first access. You have 2 remaining sessions.` |
| `use_count == 2` | `This is your second access. You have 1 remaining session.` |
| `use_count == max_uses` | `This is your last access. When you log out, this credential will be permanently expired. To request new access, contact the administrator.` |

### Implementation
- The static `restricted/index.html` file contains a placeholder comment `<!-- BANNER -->`.
- The Axum handler reads the file bytes, replaces `<!-- BANNER -->` with the appropriate `<div class="access-banner">...</div>` HTML, and serves the modified bytes with `Content-Type: text/html`.
- The banner style is defined in `style.css` — minimal, fits the site aesthetic.

---

## Admin Interface

### Authentication
Protected by a single `ADMIN_SECRET` environment variable sent as:
- HTTP header: `Authorization: Bearer <ADMIN_SECRET>`, **or**
- Form field: `admin_secret=<ADMIN_SECRET>` in POST body.

Use `constant_time_eq` crate for comparison — no timing leaks. Reject immediately with `403` if wrong or missing. No login page for admin.

### Routes

| Method | Path | Description |
|---|---|---|
| `POST` | `/admin/issue` | Generate and issue a new username + password pair |
| `GET` | `/admin/users` | List all users, use counts, and active status |
| `POST` | `/admin/revoke` | Revoke access for a username (`active = FALSE`) |
| `POST` | `/admin/reset` | Reset use count and reactivate a username |

### `POST /admin/issue`

**Request:** no body required. The server generates everything.

**Process:**
1. Generate a two-word username (with collision retry).
2. Generate a 14-character random password.
3. Hash the password with Argon2id.
4. Insert into `users` (`use_count = 0`, `active = TRUE`, `max_uses = 3`).
5. Return JSON:

```json
{
  "username": "marble-epoch",
  "password": "Xk9!mQr2vL#nPw",
  "max_uses": 3,
  "message": "Copy these credentials now. The password cannot be recovered."
}
```

### `GET /admin/users`

Returns JSON array of all users:
```json
[
  {
    "username": "marble-epoch",
    "use_count": 2,
    "max_uses": 3,
    "active": true,
    "created_at": "2025-01-15T10:30:00Z"
  }
]
```

### `POST /admin/revoke`
Body: `{ "username": "marble-epoch" }`
Sets `active = FALSE` immediately. Any existing sessions remain until they expire naturally, but new logins are blocked.

### `POST /admin/reset`
Body: `{ "username": "marble-epoch" }`
Sets `use_count = 0`, `active = TRUE`. Does **not** change the password. Admin must call `/admin/issue` again if a new password is also needed (which will overwrite the user record — see upsert note).

> **Upsert behaviour on `/admin/issue`:** If a username collision somehow slips through (extremely unlikely), the retry loop handles it. There is no upsert by username — each call always creates a new user with a new generated username.

---

## Environment Variables (`.env`)

```
DATABASE_URL=postgres://user:password@localhost:5432/restricted_site
ADMIN_SECRET=your-very-long-random-admin-secret
SESSION_DURATION_SECS=3600
SERVER_ADDR=127.0.0.1:3000
```

No SMTP or email variables.

---

## Design Reference

Follow the aesthetic of https://blog.sheerluck.dev/:
- Clean, minimal, content-first layout.
- System font stack (`-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`).
- Generous line-height (1.7), comfortable reading width (`max-width: 680px`, centered).
- No heavy frameworks, no animations, no JavaScript.
- Neutral color palette (off-white background, near-black text, subtle `#e5e5e5` borders).
- The login page: centered card, `username` field, `password` field, submit button. Fits the same minimal aesthetic.

### Access banner style
```css
.access-banner {
  background: #f9f5e7;
  border-left: 3px solid #c8a84b;
  padding: 0.75rem 1rem;
  margin-bottom: 1.5rem;
  font-size: 0.9rem;
  color: #555;
}
.access-banner.final {
  background: #fdf0f0;
  border-left-color: #c0392b;
  color: #7a1a1a;
}
```

The restricted area content (`static/restricted/index.html`) is initially a static placeholder — a short paragraph stating this is a restricted area for authorized users, followed by the eventual content area. This will be expanded later; the auth system is the priority.

---

## Security Requirements (Non-Negotiable)

- [ ] Passwords hashed with **Argon2id** (`argon2` crate, default parameters — do not weaken).
- [ ] Session tokens: **256-bit random** raw token in cookie; only the **SHA-256 hash** stored in DB. A stolen DB dump cannot be used to forge sessions.
- [ ] All cookies: `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`.
- [ ] Login: **constant-time** password comparison (Argon2 handles this internally).
- [ ] Login: run dummy Argon2 verify even when username not found — prevents timing-based username enumeration.
- [ ] Admin routes: `constant_time_eq` for `ADMIN_SECRET` comparison.
- [ ] No internal error details exposed to the browser. Log with `tracing`, return generic HTTP errors.
- [ ] All DB queries via `sqlx` parameterized statements — no string interpolation.
- [ ] `use_count` increment is atomic (`UPDATE ... RETURNING use_count`) — no TOCTOU race.
- [ ] Rate-limit `/login`: max 5 attempts per IP per minute. Use `tower_governor` crate.
- [ ] NGINX: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin`.
- [ ] The `static/restricted/` directory is **not** a NGINX `root` or `alias` target. All `/restricted/*` traffic proxies to Axum exclusively.

---

## Axum Route Map

```
GET  /                      → serve static/index.html
GET  /login                 → serve static/login.html
POST /login                 → auth::handlers::login
POST /logout                → auth::handlers::logout     [clears session]

GET  /restricted/           → restricted::handlers::index   [AuthUser extractor]
GET  /restricted/*path      → restricted::handlers::asset   [AuthUser extractor]

POST /admin/issue           → admin::handlers::issue        [ADMIN_SECRET]
GET  /admin/users           → admin::handlers::list_users   [ADMIN_SECRET]
POST /admin/revoke          → admin::handlers::revoke       [ADMIN_SECRET]
POST /admin/reset           → admin::handlers::reset        [ADMIN_SECRET]
```

---

## Deployment (Ubuntu + NGINX)

### NGINX config
```nginx
server {
    listen 443 ssl;
    server_name yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    add_header X-Frame-Options "DENY";
    add_header X-Content-Type-Options "nosniff";
    add_header Referrer-Policy "strict-origin";

    # IMPORTANT: no alias or root pointing at static/restricted/
    # All /restricted/* traffic must go through Axum

    location / {
        proxy_pass         http://127.0.0.1:3000;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$host$request_uri;
}
```

### systemd service
```ini
[Unit]
Description=Restricted Site (Axum)
After=network.target postgresql.service

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/restricted-site
EnvironmentFile=/opt/restricted-site/.env
ExecStart=/opt/restricted-site/restricted-site
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Build & deploy steps
```bash
cargo build --release
cp target/release/restricted-site /opt/restricted-site/
cp -r static /opt/restricted-site/
sqlx migrate run
systemctl daemon-reload
systemctl enable --now restricted-site
```

---

## Development Order (Suggested for Claude Code)

1. `Cargo.toml` — all dependencies (`axum`, `sqlx`, `argon2`, `rand`, `tower_governor`, `constant_time_eq`, `sha2`, `hex`, `dotenvy`, `tokio`, `tracing`, `tracing-subscriber`, `serde`, `uuid`).
2. `.env.example`.
3. Database migrations (`migrations/0001`, `0002`, `0003`).
4. `src/config.rs` — typed `Config` struct from env vars.
5. `src/db.rs` — `PgPool` init, run migrations on startup.
6. `src/error.rs` — `AppError` implementing `IntoResponse`.
7. `src/auth/credentials.rs` — word lists, username generator, password generator, Argon2 hash/verify helpers.
8. `src/admin/handlers.rs` — `issue`, `list_users`, `revoke`, `reset`.
9. `src/auth/handlers.rs` — `login` (with rate limiting hook), `logout`.
10. `src/auth/middleware.rs` — `AuthUser` extractor (cookie → SHA-256 → DB lookup).
11. `src/restricted/handlers.rs` — file reader with `<!-- BANNER -->` injection.
12. `src/main.rs` — router, shared `AppState`, middleware layers.
13. `static/` — `index.html`, `login.html`, `restricted/index.html`, `css/style.css`.
14. `deploy/` — `nginx.conf`, `systemd.service`.
15. Manual end-to-end test checklist:
    - [ ] `POST /admin/issue` returns username + password JSON.
    - [ ] Login with those credentials succeeds; banner shows "1st access, 2 remaining".
    - [ ] Second login: banner shows "2nd access, 1 remaining".
    - [ ] Third login: banner shows "last access" warning; `active` set to FALSE.
    - [ ] Fourth login attempt: rejected with "Access denied".
    - [ ] `GET /admin/users` shows `use_count: 3`, `active: false`.
    - [ ] `POST /admin/reset` reactivates; login works again from count 0.
    - [ ] Direct `GET /restricted/index.html` via NGINX (bypassing Axum) is not possible.
    - [ ] Session cookie missing → redirect to `/login`.
    - [ ] Expired session → redirect to `/login`.
