# SEC360 — On-Premises Deployment Guide

## Requirements

| Requirement | Minimum | Recommended |
|---|---|---|
| OS | Ubuntu 22.04 / Debian 12 / RHEL 9 | Ubuntu 22.04 LTS |
| CPU | 2 cores | 4 cores |
| RAM | 4 GB | 8 GB |
| Disk | 20 GB | 50 GB |
| Docker | 24+ | latest |
| Docker Compose | v2 plugin | latest |
| Ports | 80, 443 open | — |

---

## Quick Start

### 1. Copy the project to your server

```bash
# Option A — from this machine (replace <SERVER> with your server's IP/hostname)
scp -r /opt/sec360 user@<SERVER>:/opt/sec360

# Option B — from Git (if you have a repo)
git clone https://your-repo/sec360.git /opt/sec360
```

### 2. Run the setup script

```bash
cd /opt/sec360
chmod +x setup.sh
./setup.sh
```

The script will:
- Verify Docker and Docker Compose are installed
- Create `.env` with auto-generated secrets
- Generate a self-signed TLS certificate (prompts for your hostname/IP)
- Build both Docker images
- Start all services
- Print the URL and default credentials

### 3. Log in

Open `https://<your-server>` in a browser.

| Field | Value |
|---|---|
| Email | `admin@sec360.local` |
| Password | `Admin123!` |

**Change this password immediately** (Settings → Users → click your account).

---

## Manual Setup (if you prefer not to use the script)

### Step 1 — Environment file

```bash
cd /opt/sec360
cp .env.example .env
```

Edit `.env` and set:

```bash
# Required — generate with: python3 -c "import secrets; print(secrets.token_hex(32))"
JWT_SECRET=<64-char random hex>

# Required — pick a strong password
POSTGRES_PASSWORD=<strong password>

# Required — your server's actual hostname or IP
CORS_ORIGINS=["https://sec360.yourcompany.com"]
```

### Step 2 — TLS certificate

**Option A: Self-signed** (dev / internal)

```bash
mkdir -p ssl
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout ssl/server.key \
  -out    ssl/server.crt \
  -subj   "/CN=sec360.yourcompany.com/O=YourCo" \
  -addext "subjectAltName=DNS:sec360.yourcompany.com,IP:127.0.0.1"
chmod 600 ssl/server.key
```

**Option B: Let's Encrypt** (public DNS)

```bash
# Install certbot, then:
certbot certonly --standalone -d sec360.yourcompany.com
cp /etc/letsencrypt/live/sec360.yourcompany.com/fullchain.pem ssl/server.crt
cp /etc/letsencrypt/live/sec360.yourcompany.com/privkey.pem   ssl/server.key
```

**Option C: Corporate CA / existing cert**

```bash
cp /path/to/your.crt ssl/server.crt
cp /path/to/your.key ssl/server.key
chmod 600 ssl/server.key
```

### Step 3 — Build and start

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

### Step 4 — Verify

```bash
# All three containers should be "healthy" or "Up"
docker compose -f docker-compose.prod.yml ps

# Check backend health
curl -k https://localhost/api/health
```

---

## Configuration Reference

All settings live in `.env`. The most important ones:

| Variable | Required | Description |
|---|---|---|
| `POSTGRES_PASSWORD` | ✓ | Database password |
| `JWT_SECRET` | ✓ | Token signing key — keep secret, changing it logs everyone out |
| `CORS_ORIGINS` | ✓ | JSON array of allowed origins — must include your URL |
| `COLLECTOR_INTERVAL_MINUTES` | — | How often integrations sync (default: 15) |
| `JWT_EXPIRE_HOURS` | — | Session length (default: 8) |
| `HTTP_PORT` / `HTTPS_PORT` | — | Override ports (default: 80 / 443) |

Integration credentials (JumpCloud, SentinelOne, etc.) are managed through the **Integrations** page in the UI — you don't need to set them in `.env`.

---

## Data Persistence

PostgreSQL data is stored in a named Docker volume `sec360_postgres_data`. It survives container restarts and upgrades.

### Backup

```bash
# Dump to a file
docker compose -f docker-compose.prod.yml exec postgres \
  pg_dump -U sec360 sec360 > backup-$(date +%Y%m%d).sql

# Restore
docker compose -f docker-compose.prod.yml exec -T postgres \
  psql -U sec360 sec360 < backup-20260101.sql
```

### Scheduled backups (cron)

```bash
# Add to crontab (runs daily at 02:00)
0 2 * * * cd /opt/sec360 && docker compose -f docker-compose.prod.yml exec -T postgres \
  pg_dump -U sec360 sec360 > /backups/sec360-$(date +\%Y\%m\%d).sql
```

---

## Updating

When new code is available:

```bash
cd /opt/sec360
git pull   # or copy updated files

# Rebuild and restart (zero-downtime for postgres data)
docker compose -f docker-compose.prod.yml build
docker compose -f docker-compose.prod.yml up -d
```

---

## Running Behind a Reverse Proxy (nginx / HAProxy / Traefik)

If you already have a reverse proxy handling TLS termination, you can skip the built-in HTTPS and expose only the backend:

1. In `docker-compose.prod.yml`, change the frontend ports to internal only:
   ```yaml
   frontend:
     expose:
       - "80"     # no external ports
     ports: []
   ```

2. Add a `proxy` network so your external proxy can reach the frontend container.

3. Point your proxy to `http://sec360_frontend_1:80`.

The nginx inside the frontend container will still proxy `/api/` to the backend.

---

## Firewall

Only two ports need to be externally reachable:

| Port | Purpose |
|---|---|
| 443/TCP | HTTPS — main UI and API |
| 80/TCP | HTTP → redirects to 443 |

PostgreSQL (5432) and the backend API (8000) are on an internal Docker network — **do not expose them**.

---

## Roles

| Role | Access |
|---|---|
| `viewer` | Read-only: dashboard, endpoints, users, compliance, activity |
| `analyst` | Viewer + reports |
| `admin` | Full access: all pages, settings, integrations, user management |

Invite users from **Settings → Users → Invite User**.

---

## Troubleshooting

```bash
# View live logs from all services
docker compose -f docker-compose.prod.yml logs -f

# View logs for a specific service
docker compose -f docker-compose.prod.yml logs -f backend

# Restart a single service
docker compose -f docker-compose.prod.yml restart backend

# Shell into the backend
docker compose -f docker-compose.prod.yml exec backend bash

# Check database directly
docker compose -f docker-compose.prod.yml exec postgres psql -U sec360 sec360
```

| Symptom | Likely cause |
|---|---|
| `502 Bad Gateway` | Backend hasn't started yet — wait 30s or check backend logs |
| Login fails with valid credentials | Wrong `CORS_ORIGINS` or mismatched `JWT_SECRET` after config change |
| Integrations won't sync | Check backend logs for collector errors; verify credentials in the Integrations page |
| Browser shows certificate warning | Expected with self-signed cert — proceed or install a CA-signed cert |
| Container exits immediately | Check logs; usually a missing required env variable |
