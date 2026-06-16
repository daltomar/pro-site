# pro-site

A minimal, content-first website with a credential-gated restricted area, built with Rust and Axum.

## Overview

The public side is a static site. The restricted area is protected by a simple credential system: the admin generates a username/password pair through a private API; each pair is valid for a fixed number of logins, after which it expires automatically. There is no self-registration and no email flow — credentials are issued and delivered out-of-band.

## Stack

- **Language:** Rust (stable)
- **Web framework:** Axum
- **Database:** PostgreSQL (sessions and credentials)
- **Frontend:** Plain HTML + CSS, no JavaScript framework
- **Deployment:** Ubuntu, NGINX reverse proxy, systemd

## Security highlights

- Passwords hashed with Argon2id
- Session tokens are 256-bit random values; only their SHA-256 hash is stored in the database
- Cookies are `HttpOnly`, `Secure`, `SameSite=Strict`
- Login endpoint is rate-limited per IP
- Admin API protected with a constant-time secret comparison
- No internal error details exposed to the client

## License

Private.
