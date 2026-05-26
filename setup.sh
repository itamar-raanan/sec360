#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# SEC360 — On-Premises Setup Script
# Tested on Ubuntu 22.04 / Debian 12 / RHEL 9
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET} $*"; }
success() { echo -e "${GREEN}[OK]${RESET}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET} $*"; }
fatal()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
echo "  ███████╗███████╗ ██████╗ ██████╗  ██████╗  ██████╗"
echo "  ██╔════╝██╔════╝██╔════╝╚════██╗██╔════╝ ██╔═████╗"
echo "  ███████╗█████╗  ██║      █████╔╝███████╗ ██║██╔██║"
echo "  ╚════██║██╔══╝  ██║     ██╔═══╝ ██╔═══██╗████╔╝██║"
echo "  ███████║███████╗╚██████╗███████╗╚██████╔╝╚██████╔╝"
echo "  ╚══════╝╚══════╝ ╚═════╝╚══════╝ ╚═════╝  ╚═════╝"
echo -e "${RESET}"
echo -e "${BOLD}  Security Visibility Platform — On-Premises Setup${RESET}"
echo "  ──────────────────────────────────────────────────"
echo ""

# ── 1. Check prerequisites ────────────────────────────────────────────────────
info "Checking prerequisites..."

if ! command -v docker &>/dev/null; then
  fatal "Docker is not installed. Install it from https://docs.docker.com/engine/install/"
fi

# Support both 'docker compose' (v2 plugin) and 'docker-compose' (v1)
if docker compose version &>/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v docker-compose &>/dev/null; then
  COMPOSE="docker-compose"
else
  fatal "Docker Compose is not installed. Install it: https://docs.docker.com/compose/install/"
fi

DOCKER_VER=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "unknown")
COMPOSE_VER=$($COMPOSE version --short 2>/dev/null || echo "unknown")
success "Docker $DOCKER_VER  |  Compose $COMPOSE_VER"

if ! command -v openssl &>/dev/null; then
  warn "openssl not found — skipping SSL certificate generation."
  warn "You must manually place server.crt and server.key in ./ssl/"
  SKIP_SSL=true
else
  SKIP_SSL=false
fi

echo ""

# ── 2. Environment file ───────────────────────────────────────────────────────
info "Setting up environment..."

if [[ -f ".env" ]]; then
  warn ".env already exists — skipping creation. Edit it manually if needed."
else
  if [[ ! -f ".env.example" ]]; then
    fatal ".env.example not found. Are you running this from the project root?"
  fi
  cp .env.example .env

  # Generate secrets automatically
  if command -v python3 &>/dev/null; then
    JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    DB_PASS=$(python3 -c "import secrets; print('sec360_' + secrets.token_hex(12))")
  else
    JWT_SECRET=$(openssl rand -hex 32 2>/dev/null || echo "CHANGE_ME_$(date +%s)")
    DB_PASS="sec360_$(openssl rand -hex 12 2>/dev/null || echo 'changeme')"
  fi

  # Patch .env with generated values
  sed -i "s|CHANGE_ME_generate_a_64_char_random_hex_string|${JWT_SECRET}|" .env
  sed -i "s|CHANGE_ME_strong_password_here|${DB_PASS}|" .env

  success ".env created with generated secrets."
  warn "Review .env and update CORS_ORIGINS with your actual hostname before going live."
fi

echo ""

# ── 3. SSL certificates ───────────────────────────────────────────────────────
mkdir -p ssl

if [[ "${SKIP_SSL}" == "false" ]]; then
  if [[ -f "ssl/server.crt" && -f "ssl/server.key" ]]; then
    success "SSL certificates already present in ./ssl/"
  else
    info "Generating self-signed TLS certificate..."
    echo ""
    read -rp "  Enter your server's hostname or IP (e.g. sec360.company.com or 192.168.1.100): " SERVER_HOST
    SERVER_HOST="${SERVER_HOST:-localhost}"

    # Build a SAN that works for both hostname and IP
    if [[ "$SERVER_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      SAN="IP:${SERVER_HOST},IP:127.0.0.1"
    else
      SAN="DNS:${SERVER_HOST},DNS:localhost,IP:127.0.0.1"
    fi

    openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
      -keyout ssl/server.key \
      -out    ssl/server.crt \
      -subj   "/CN=${SERVER_HOST}/O=SEC360/OU=Security" \
      -addext "subjectAltName=${SAN}" \
      -addext "keyUsage=digitalSignature,keyEncipherment" \
      -addext "extendedKeyUsage=serverAuth" \
      2>/dev/null

    chmod 600 ssl/server.key
    success "Self-signed certificate created for ${SERVER_HOST} (valid 10 years)."
    warn "For production, replace ssl/server.crt + ssl/server.key with a CA-signed certificate."
    echo "  To use Let's Encrypt: https://certbot.eff.org/"
  fi
else
  if [[ ! -f "ssl/server.crt" || ! -f "ssl/server.key" ]]; then
    fatal "ssl/server.crt and ssl/server.key are missing. Place your TLS certificate files there."
  fi
fi

echo ""

# ── 4. Build images ───────────────────────────────────────────────────────────
info "Building Docker images (this may take 3–5 minutes on first run)..."
echo ""
$COMPOSE -f docker-compose.prod.yml build --no-cache 2>&1 | grep -E "^(Step|#[0-9]|WARN|ERROR|---)" | head -80 || true
echo ""
success "Images built."
echo ""

# ── 5. Start services ─────────────────────────────────────────────────────────
info "Starting services..."
$COMPOSE -f docker-compose.prod.yml up -d
echo ""

# Wait for postgres
info "Waiting for database to be ready..."
MAX_WAIT=60
COUNT=0
while ! $COMPOSE -f docker-compose.prod.yml exec -T postgres \
    pg_isready -U "$(grep POSTGRES_USER .env | cut -d= -f2 || echo sec360)" &>/dev/null; do
  COUNT=$((COUNT+1))
  if [[ $COUNT -ge $MAX_WAIT ]]; then
    fatal "PostgreSQL did not become healthy after ${MAX_WAIT}s. Check: $COMPOSE -f docker-compose.prod.yml logs postgres"
  fi
  sleep 1
done
success "Database ready."

# Wait for backend API
info "Waiting for API to start..."
COUNT=0
until $COMPOSE -f docker-compose.prod.yml exec -T backend \
    curl -sf http://localhost:8000/health &>/dev/null; do
  COUNT=$((COUNT+1))
  if [[ $COUNT -ge 60 ]]; then
    warn "Backend health check timed out — check logs: $COMPOSE -f docker-compose.prod.yml logs backend"
    break
  fi
  sleep 2
done
if [[ $COUNT -lt 60 ]]; then
  success "Backend API is healthy."
fi

echo ""

# ── 6. Print summary ──────────────────────────────────────────────────────────
SERVER_HOST="${SERVER_HOST:-$(hostname -I | awk '{print $1}')}"
HTTP_PORT=$(grep '^HTTP_PORT' .env 2>/dev/null | cut -d= -f2 || echo "80")
HTTPS_PORT=$(grep '^HTTPS_PORT' .env 2>/dev/null | cut -d= -f2 || echo "443")

echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  SEC360 is running!${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  🌐 URL:       ${CYAN}https://${SERVER_HOST}:${HTTPS_PORT}${RESET}"
echo -e "  🌐 HTTP:      ${CYAN}http://${SERVER_HOST}:${HTTP_PORT}${RESET}  (redirects to HTTPS)"
echo ""
echo -e "  ${BOLD}Default admin credentials:${RESET}"
echo -e "  👤 Email:     ${YELLOW}admin@sec360.local${RESET}"
echo -e "  🔑 Password:  ${YELLOW}Admin123!${RESET}"
echo ""
echo -e "  ${RED}${BOLD}⚠  Change the admin password immediately after first login!${RESET}"
echo ""
echo -e "  ${BOLD}Useful commands:${RESET}"
echo "  View logs:     $COMPOSE -f docker-compose.prod.yml logs -f"
echo "  Stop:          $COMPOSE -f docker-compose.prod.yml down"
echo "  Update & restart:"
echo "                 $COMPOSE -f docker-compose.prod.yml build && \\"
echo "                 $COMPOSE -f docker-compose.prod.yml up -d"
echo ""
echo -e "  ${BOLD}Next steps:${RESET}"
echo "  1. Log in and change the admin password (Settings → Users)"
echo "  2. Invite your team (Settings → Users → Invite)"
echo "  3. Connect your integrations (Integrations page)"
echo "  4. Replace ssl/server.crt with a CA-signed certificate"
echo "     if this is a production deployment"
echo ""
