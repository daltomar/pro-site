# Server Setup Guide

Complete setup instructions for a fresh Ubuntu 22.04/24.04 server.

---

## 1. Install PostgreSQL

```bash
sudo apt update
sudo apt install -y postgresql postgresql-contrib
sudo systemctl enable --now postgresql
```

Verify it is running:
```bash
sudo systemctl status postgresql
```

---

## 2. Create the database and user

```bash
sudo -u postgres psql <<'SQL'
CREATE USER restricted_site WITH PASSWORD 'choose-a-strong-password-here';
CREATE DATABASE restricted_site OWNER restricted_site;
\q
SQL
```

Test the connection:
```bash
psql "postgres://restricted_site:choose-a-strong-password-here@localhost:5432/restricted_site" -c '\l'
```

---

## 3. Install Rust (on the server, for building)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup update stable
```

Or cross-compile on your development machine and copy the binary. Cross-compilation is recommended for production.

---

## 4. Install sqlx-cli (to run migrations)

```bash
cargo install sqlx-cli --no-default-features --features rustls,postgres
```

---

## 5. Clone or copy the project

```bash
git clone <your-repo> /opt/restricted-site-src
cd /opt/restricted-site-src
```

---

## 6. Configure the environment

```bash
cp .env.example .env
nano .env
```

Fill in all values:

```
DATABASE_URL=postgres://restricted_site:your-password@localhost:5432/restricted_site
ADMIN_SECRET=generate-with: openssl rand -hex 32
SESSION_DURATION_SECS=3600
SERVER_ADDR=127.0.0.1:3000
RUST_LOG=info
```

Generate a strong admin secret:
```bash
openssl rand -hex 32
```

---

## 7. Run database migrations

```bash
DATABASE_URL="postgres://restricted_site:your-password@localhost:5432/restricted_site" \
  sqlx migrate run
```

---

## 8. Build the binary

```bash
cargo build --release
```

---

## 9. Deploy the binary and static files

```bash
sudo mkdir -p /opt/restricted-site
sudo cp target/release/restricted-site /opt/restricted-site/
sudo cp -r static /opt/restricted-site/
sudo cp .env /opt/restricted-site/.env
sudo chmod 600 /opt/restricted-site/.env
sudo chown -R www-data:www-data /opt/restricted-site
```

---

## 10. Install the systemd service

```bash
sudo cp deploy/systemd.service /etc/systemd/system/restricted-site.service
sudo systemctl daemon-reload
sudo systemctl enable --now restricted-site
sudo systemctl status restricted-site
```

Check logs:
```bash
sudo journalctl -u restricted-site -f
```

---

## 11. Install NGINX

```bash
sudo apt install -y nginx
```

---

## 12. Obtain a TLS certificate (Let's Encrypt)

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com
```

---

## 13. Configure NGINX

```bash
sudo cp deploy/nginx.conf /etc/nginx/sites-available/restricted-site
# Edit the file and replace yourdomain.com with your actual domain
sudo nano /etc/nginx/sites-available/restricted-site

sudo ln -s /etc/nginx/sites-available/restricted-site /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## 14. Verify the deployment

### Issue credentials
```bash
curl -X POST https://yourdomain.com/admin/issue \
  -H "Authorization: Bearer YOUR_ADMIN_SECRET"
```

### List users
```bash
curl https://yourdomain.com/admin/users \
  -H "Authorization: Bearer YOUR_ADMIN_SECRET"
```

### Revoke a user
```bash
curl -X POST https://yourdomain.com/admin/revoke \
  -H "Authorization: Bearer YOUR_ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"username": "example-user"}'
```

### Reset a user
```bash
curl -X POST https://yourdomain.com/admin/reset \
  -H "Authorization: Bearer YOUR_ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"username": "example-user"}'
```

---

## Updating the binary

```bash
# Rebuild
cargo build --release

# Stop service, replace binary, restart
sudo systemctl stop restricted-site
sudo cp target/release/restricted-site /opt/restricted-site/
sudo systemctl start restricted-site
```

If there are new migrations:
```bash
DATABASE_URL="..." sqlx migrate run
```
before restarting the service. The server also runs migrations automatically on startup.

---

## Firewall (ufw)

```bash
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```
