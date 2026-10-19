# SEC360

SEC360 is a self-hosted security visibility and posture-management platform. It combines identity, endpoint, security-agent, activity, vulnerability, and DLP data in one analyst interface. The platform correlates records from multiple systems, evaluates endpoint compliance, calculates risk, records security-relevant changes, and can forward audit and change events to a SIEM.

This document describes the current implementation: its components, features, integrations, security controls, deployment model, configuration, and operational workflows.

## Contents

- [System architecture](#system-architecture)
- [Components](#components)
- [Features](#features)
- [Integrations](#integrations)
- [Data collection and processing](#data-collection-and-processing)
- [Authentication and authorization](#authentication-and-authorization)
- [Change logging, auditing, and SIEM](#change-logging-auditing-and-siem)
- [Deployment](#deployment)
- [Initial configuration](#initial-configuration)
- [Environment configuration](#environment-configuration)
- [Operations](#operations)
- [Development](#development)
- [API overview](#api-overview)
- [Repository structure](#repository-structure)
- [Important behavior and limitations](#important-behavior-and-limitations)

## System architecture

```mermaid
flowchart LR
    Sources["Security and identity systems"] --> Collectors["Collectors and scheduled jobs"]
    Collectors --> DB[(PostgreSQL)]
    DB --> Engines["Correlation, compliance, risk, and change engines"]
    Engines --> DB
    Browser["Analyst browser"] --> Nginx["Nginx / React application"]
    Nginx --> API["FastAPI backend"]
    API --> DB
    API --> Redis[(Redis login throttling)]
    API --> Sources
    DB --> Outbox["Durable SIEM outbox"]
    Outbox --> SIEM["HTTP(S) SIEM endpoint"]
```

The production deployment consists of five Docker Compose services:

| Component | Technology | Responsibility |
| --- | --- | --- |
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, Nginx | Web interface, TLS termination, static assets, and `/api` reverse proxy |
| Backend | Python 3.12, FastAPI, async SQLAlchemy | API, authentication, integrations, business logic, schedulers, and background work |
| Database | PostgreSQL 16 | Application state, collected data, settings, encrypted credentials, logs, and job state |
| Rate-limit store | Redis 7.4 | Shared, persistent login-failure counters in production |
| Certificate initializer | Alpine Linux one-shot container | Seeds the persistent TLS certificate volume on first deployment |

Only Nginx publishes ports in production. PostgreSQL, Redis, and the backend remain on the internal Docker network.

## Components

### Web application

The single-page application provides role-aware navigation and feature-aware routes. Pages appear only when the signed-in user has the required role and, where applicable, the supporting integration is connected.

The frontend uses:

- React Query for server-state fetching and cache invalidation.
- Zustand for client-side application state.
- Recharts for dashboard visualizations and a pinned, vendored Three.js runtime for Network Map geometry.
- Tailwind CSS and Lucide icons for the interface.
- A shared API client using `/api` by default.

### Backend API

The FastAPI service owns:

- Authentication, sessions, MFA, invitations, SAML, and RADIUS.
- Integration configuration, connection testing, and synchronization.
- Endpoint and user inventory APIs.
- Correlation, compliance, and risk evaluation.
- Reports and scheduled email delivery.
- DLP policy search and DLP change tracking.
- Puppet Facts and SentinelOne application-vulnerability views.
- Optional Network Map collection, correlation, and topology APIs.
- Audit logs, change events, SIEM delivery, and system settings.

Interactive OpenAPI documentation is available at `/docs` on the backend service. In development it is reachable at `http://localhost:8000/docs`. The production Nginx configuration exposes the application API under `/api` but does not publish the backend's `/docs` route.

### PostgreSQL data store

PostgreSQL stores the canonical inventory and operational state, including:

- Users, authentication users, sessions, and invitations.
- Endpoints, agents, source identifiers, and correlated ownership.
- Compliance results, compliance exclusions, and risk scores.
- Activity events and retained raw activity data.
- Integration definitions and encrypted credentials.
- DLP search and policy-tracking state.
- Puppet nodes, facts, favorites, and saved views.
- Application vulnerabilities.
- Network Map connections, floors, infrastructure placement, collection runs, and retained observations.
- Reports, system settings, analyst notes, audit logs, change events, and SIEM deliveries.

Database tables are created on application startup, and startup code applies idempotent compatibility patches required by the current release. Back up PostgreSQL before upgrading an existing installation.

### Collection scheduler

APScheduler runs inside the backend. A normal collection cycle is deliberately ordered to prevent concurrent collectors from overwriting correlated endpoint state:

1. JumpCloud, Active Directory, Puppet, SentinelOne, and Symantec DLP run sequentially.
2. Google Workspace and ADFS run in parallel.
3. Correlation runs, followed by compliance evaluation and risk calculation.

Other scheduled jobs handle report delivery, data retention, and SIEM retries. The default full collection interval is 15 minutes and is configurable.

When Network Map is enabled, a separate feature-owned scheduled job collects its enabled connections on the same configurable interval. Disabling Network Map immediately stops operational collection without deleting connection configuration or retained observations.

### Correlation engine

The correlation engine builds a canonical inventory from overlapping source records. It normalizes hostnames, usernames, serial numbers, and identifiers, and matches records using source IDs, serial numbers, normalized hostnames, and user relationships. Obvious placeholder or invalid serial values are ignored.

JumpCloud records normally act as the canonical base when present, while agents and details from other sources are attached to the same endpoint. Active Directory CSV imports can also associate directory computers and users with existing records.

### Compliance engine

Compliance requirements are derived from products that are enabled and successfully connected. A product that is not in the active product scope is not treated as missing.

Supported checks include:

- SentinelOne installed and at or above the configured minimum version.
- Symantec DLP installed and at or above the configured minimum version.
- WSS installed and at or above the configured minimum version.
- Generic required-agent presence.
- SentinelOne disk-encryption and device-control status when those fields are available.

An endpoint is `compliant` when all applicable checks pass, `non_compliant` when none pass, and `partial` when only some pass. An empty minimum-version setting disables that version check. Versions that cannot be parsed are not automatically penalized.

Analysts can exclude an entire endpoint or an individual agent from compliance. An exclusion requires a reason, affects compliance and risk, and is recorded in both the audit and change logs.

### Risk engine

Risk scores range from 0 to 100:

| Level | Score |
| --- | ---: |
| Low | 0–25 |
| Medium | >25–50 |
| High | >50–75 |
| Critical | >75–100 |

User risk signals are:

| Signal | Score contribution |
| --- | ---: |
| Impossible travel | +30 |
| More than three countries with more than five login events | +20 |
| Associated non-compliant device | +25 |
| MFA not enabled | +15 |
| Inactive for more than 30 days | +10 |

Endpoint risk weights are configurable in System Settings. Their defaults are:

| Signal | Default contribution |
| --- | ---: |
| SentinelOne missing | +30 |
| SentinelOne outdated | +20 |
| DLP missing | +25 |
| DLP outdated | +15 |
| WSS missing | +15 |
| WSS outdated | +10 |
| No associated user | +10 |

An endpoint with no compliance data receives an additional risk contribution. Scores are capped at 100. Authorized users can also set an endpoint risk override.

### Background and retention services

The backend also runs these recurring tasks:

- Scheduled-report scan every 30 minutes.
- SIEM outbox delivery every minute.
- Google activity and raw-data retention cleanup.
- Audit-log and delivered-SIEM-record cleanup.

Current defaults retain Google activity/raw records for 7 days, audit logs for 90 days, and successfully delivered SIEM queue records for 30 days.

## Features

### Dashboard

The dashboard presents the current security posture at a glance:

- User and endpoint counts.
- Compliance distribution.
- Risk distribution and high-risk entities.
- Security-agent and product coverage.
- Recent suspicious activity.
- Drill-down links into the underlying inventory.

### Endpoints

The Endpoints page is the primary device inventory. It shows:

- Hostname, operating system, IP address, assigned user, source, and last-seen data.
- Installed security products and agent versions.
- Compliance status and risk score.
- Analyst notes and endpoint detail.
- Product-presence filters such as “Has DLP” and “Missing DLP”.
- Bulk actions and lifecycle/cleanup controls.

Product filters are created from the currently connected product scope. For example, SentinelOne filters appear only when SentinelOne is enabled and connected.

SEC360 does **not** hide endpoints based on a 60-day or other last-seen window. All active inventory records remain visible so analysts can identify old devices and clean them from their source systems. Records intentionally retired from SEC360 are excluded from the current inventory.

### Users

The Users page provides:

- Identity details, department, manager, employment status, and MFA state.
- Risk score and risk indicators.
- Associated endpoints.
- Login and activity timeline.
- Correlated identities from connected directories.
- Filters for department, employment status, and risk.

User detail views expose the source-to-canonical identity mapping used by correlation.

### Compliance

The Compliance page and endpoint product filters use the same current endpoint inventory and active-product scope. The page includes:

- Overall compliance summary and distribution.
- Per-endpoint and per-agent checks.
- Filters for status, issue, agent, operating system, scope, and search text.
- Worst-offender analysis.
- Endpoint-level and agent-level exclusions with reasons.
- On-demand re-evaluation.

Compliance counts should therefore represent the same active inventory shown on Endpoints; the views differ only when an explicit page filter or compliance exclusion changes the selected population.

### Activity

Activity is available when Google Workspace, ADFS, or Active Directory supplies relevant data. It provides:

- Login and security activity timelines.
- Event-type, date, user, and suspicious-event filtering.
- Suspicious activity highlighting.
- Impossible-travel and related behavioral signals used by risk scoring.

### Application vulnerabilities

When a SentinelOne **cloud** integration supports application inventory, analysts can review:

- Vulnerability, application, and affected-endpoint totals.
- Severity, status, mitigation, exploit-evidence, and operating-system filters.
- CVE and affected-application detail.
- Raw source detail for investigation.
- CSV export with spreadsheet-formula injection protection.

SentinelOne on-premises deployments do not expose this feature because the required cloud application-vulnerability API is unavailable.

### Puppet Facts

When Puppet is connected, analysts can explore PuppetDB data:

- Node and fact summaries.
- Fact-name, certname, environment, report-status, and value-type filters.
- Full-text fact-value search.
- Per-user favorites.
- Saved and default views.
- Sorting, pagination, and CSV export.

### Network Map

Network Map is an optional, administrator-controlled topology workspace. Enable it under **Settings → Platform → Network Map**. When disabled, its navigation, operational API, and scheduled collection remain unavailable; administrators can still prepare and test connections at **Network Map → Connections**.

The feature owns its connections instead of placing them in the Integration Store:

- One Cisco WLC SSH connection for access points, wireless clients, WLAN IDs, and SSIDs.
- One FortiGate HTTPS API connection for DHCP lease enrichment.
- Any number of MikroTik SwOS HTTP Digest connections for switch host tables, ports, and VLANs.

Saved secrets are encrypted and never returned to the browser. **Test connection** is separate from **Save**: it validates the current form without silently saving, enabling, or scheduling it. A successful complete collection replaces only that connection's current snapshot. A failed or malformed collection leaves the previous snapshot intact and exposes the source error and collection age.

The workspace provides eight independently configurable floors using one shared schematic geometry. Administrators assign discovered access points and switches to a floor, save stable X/Z placement, and may override the served floor and role of individual switch ports. The 3D view supports orbit, pan, zoom, floor expansion, dashed Wi-Fi links, solid Ethernet links, endpoint/equipment selection, search, and an accessible list fallback when WebGL is unavailable.

Endpoint identity is resolved only by normalized MAC addresses found in existing Puppet facts. Hostname and IP address may enrich a matched record, but never create the match. Multiple Puppet matches remain explicitly ambiguous; no Puppet match is labeled **No current Puppet match** rather than incorrectly classifying the device as unmanaged. Wireless attachment takes precedence over a simultaneous wired observation unless that switch port is explicitly configured as an endpoint-facing port.

### DLP user policy search

The DLP policy search connects to the configured Symantec DLP Enforce Oracle database and searches policy conditions for user-related exclusions and patterns such as users, email addresses, domains, IP addresses, and personal-email rules. Agent collection supports the integration's configured database mode, but the live User Policy Search specifically requires Oracle credentials.

Searches also refresh the DLP policy snapshot used by the change tracker. On the first observation SEC360 creates a baseline; subsequent observations record patterns that were added, removed, or changed.

### Reports

Analysts can preview and export these report types:

- Compliance.
- Risk.
- Users.
- Endpoints.
- Activity.

Exports are CSV with Excel-compatible UTF-8 encoding and a maximum of 10,000 rows. Reports may be scheduled daily, weekly, or monthly and emailed to one or more recipients. SMTP must be configured for email delivery.

### Notes and global search

Authorized users can attach notes to supported records. Global search allows fast navigation across indexed entities without opening each feature page individually.

### Integration Store

Administrators use the Integration Store to:

- View supported integrations and their connection state.
- Save or replace credentials.
- Enable or disable an integration.
- Test connectivity.
- Run an immediate synchronization.
- Review the latest synchronization status and error.
- Create and remove supported custom integration definitions.

### Security

The administrator-only Security page contains:

- **Change Log** — selected operational changes with before/after differences.
- **Audit Log** — security and administrative actions with actor and request context.
- **SIEM** — destination, format, authentication, TLS verification, test, and delivery controls.

### Settings

Settings includes:

- Login-user provisioning, invitations, roles, account state, and MFA reset.
- Current-account password and TOTP MFA management.
- Required endpoint product tags.
- Minimum SentinelOne, DLP, and WSS versions.
- Endpoint risk weights.
- Global MFA enforcement.
- SAML and RADIUS configuration, including RADIUS connection testing.
- TLS certificate replacement.
- System settings that immediately trigger derived compliance/risk recalculation where necessary.
- Network Map activation and a direct link to its feature-owned connection and floor configuration.

## Integrations

### Inventory and identity integrations

| Integration | Main data | Notes |
| --- | --- | --- |
| JumpCloud | Users, managed endpoints, MFA | Normally supplies canonical user and endpoint records |
| Active Directory | LDAP users, computers, and departments | Supports LDAPS and a manual CSV import workflow |
| Google Workspace | Users and login/OAuth activity | Requires an appropriately delegated service account |
| ADFS | Federation metadata and service availability | Also enables activity visibility when events are available |
| Puppet | Nodes, operating-system inventory, report state, and facts | Enables the Puppet Facts workspace |
| SentinelOne | Endpoints, agents, threats, and application vulnerabilities | Cloud and on-premises modes have different capabilities |
| Symantec DLP | DLP agents, WSS/product evidence, exclusions, and policy search | Connects to the Enforce database |

HiBob and CloudSOC are retired integrations and are not presented as active catalog choices.

Cisco WLC, FortiGate, and MikroTik SwOS are Network Map sources, not Integration Store products. Configure them from **Network Map → Connections**. Puppet remains the existing source of managed-endpoint identity used by Network Map correlation; the feature does not create a second Puppet connector.

## Data collection and processing

### Integration lifecycle

An integration normally moves through this workflow:

1. An administrator enters credentials.
2. SEC360 encrypts the secret fields before storing them.
3. The administrator runs **Test**.
4. The integration is enabled.
5. A manual or scheduled sync collects source records.
6. Correlation merges overlapping users/endpoints.
7. Compliance and risk are recalculated.
8. Relevant state transitions are written to the Change Log and queued for SIEM delivery.

A transient health-check or synchronization error does not immediately remove that integration's product from compliance scope. This prevents temporary source failures from making every endpoint appear to be missing a product.

### Endpoint lifecycle

Last-seen age does not remove an endpoint from inventory. An endpoint remains current while it is active and its lifecycle state is `active`. This is intentional: stale source records remain visible until an analyst cleans them in the upstream system or deliberately retires them in SEC360.

### Network Map lifecycle

Network Map configuration, collection, and visualization are separate stages:

1. An administrator configures and tests feature-owned connections.
2. The administrator enables Network Map in System Settings.
3. Manual or scheduled collection records a scoped snapshot for each enabled connection.
4. Infrastructure is discovered into an explicit unassigned state until an administrator places it on a floor.
5. Current wireless and wired observations are correlated to existing Puppet-managed endpoints by normalized MAC address.
6. FortiGate leases enrich those observations with current IP and hostname data by the same MAC.
7. Complete snapshots retire only earlier observations from the same connection; failures retain the last useful topology.

### Credentials

Integration credentials are encrypted at rest with Fernet using `CREDENTIALS_ENCRYPTION_KEY`. Secret values are treated as write-only by the API and are not sent back to the browser after storage.

Do not change `CREDENTIALS_ENCRYPTION_KEY` on an existing installation without first migrating the encrypted values. Changing it makes previously stored credentials unreadable.

## Authentication and authorization

### Login methods

SEC360 supports three login-user types:

- **Local** — email and password stored by SEC360.
- **RADIUS** — the normal sign-in form validates the user against the configured RADIUS server. RADIUS users do not require invitations.
- **SSO** — SAML authentication through the configured identity provider, with optional SEC360 TOTP enforcement after SSO.

Administrators can provision the user type and role from Settings. Invitation acceptance is used for invited local users, not RADIUS users.

### Roles

Permissions are hierarchical:

| Role | Access |
| --- | --- |
| Viewer | Dashboards and read-only inventory/detail features |
| Analyst | Viewer permissions plus investigations, reports, compliance actions, DLP search, Puppet Facts, and related analyst workflows |
| Admin | Full access, including integrations, Security, system configuration, authentication, and user administration |

Backend authorization is enforced independently of whether a page is visible in the frontend.

### Sessions and cookies

- Access tokens are issued in the `sec360_token` cookie.
- Refresh tokens use a separate cookie scoped to `/api/auth/refresh`.
- Sessions are persisted in the database and can be revoked on logout.
- Bearer authentication is supported for API clients; when both are supplied, the application cookie takes precedence.
- Production cookies must be secure and are intended for HTTPS.

### Security controls

- Password hashing and forced bootstrap-password replacement.
- Optional or globally enforced TOTP MFA.
- Persistent login throttling: 10 failures in 15 minutes by default.
- Redis-backed, fail-closed throttling in the production Compose deployment.
- Encrypted integration, RADIUS, and SIEM credentials.
- Server-side role checks on protected endpoints.
- SAML audience/signature/configuration validation.
- Outbound-target validation to reduce SSRF risk.
- CSV formula-injection protection in security exports.
- TLS 1.2/1.3 and security headers at Nginx.
- A 25 MB request-body limit at the reverse proxy.

## Change logging, auditing, and SIEM

### Change Log

The Change Log intentionally focuses on high-signal changes:

- Endpoint security product added.
- Endpoint security product missing after previously being present.
- User enabled.
- User disabled.
- DLP or related compliance exclusion added, changed, or removed.
- DLP policy pattern added, changed, or removed.

Each event shows the meaningful before/after difference rather than dumping the complete source object. DLP pattern changes contain the exact changed fields and values. The policy actor is included when the source database supplies `modified_by`.

SEC360 persists entity snapshots, so the first collected baseline does not generate false “new missing product” events. Changes are emitted only after a previously known state actually transitions.

### Audit Log

The Audit Log records administrative and security-relevant actions, including the actor, action, resource, request IP/context, result, and timestamp where applicable. Examples include login-related operations, user and settings changes, integration actions, compliance exclusions, and SIEM configuration tests.

### SIEM delivery

Audit and change events can be forwarded in ECS 8.11-compatible form to an HTTP or HTTPS receiver. Supported payload modes are:

- ECS JSON.
- Elastic Bulk API NDJSON.

Supported authentication modes are none, bearer token, API key, and basic authentication. TLS certificate verification can be controlled in the SIEM settings.

Delivery uses a durable PostgreSQL outbox and exponential retry. A temporary SIEM outage does not discard queued events. The administrator can send a test event from **Security → SIEM**.

SEC360 sends SIEM events over HTTP(S); it does **not** emit UDP/TCP syslog directly to port 514. If Elastic Agent listens only on syslog port 514, configure an HTTP input or an HTTP-to-syslog relay and point SEC360 at that HTTP endpoint.

## Deployment

### Requirements

- A Linux host with Docker Engine and the Docker Compose plugin.
- Git.
- Ports 80 and 443 available, or alternative values configured in `.env`.
- DNS and network access from the backend container to each configured integration.
- A server name and trusted TLS certificate for production use.

Recommended production sizing depends on inventory size and collector volume. The included Compose limits allocate up to 1 GiB each to PostgreSQL and the backend, 256 MiB to the frontend, and 128 MiB to Redis; larger installations should tune these values and monitor PostgreSQL growth.

### Guided production setup

From the repository root:

```bash
./setup.sh
```

The setup script prepares `.env`, generates missing secrets, prepares TLS material, builds the production images, starts the services, waits for health, and bootstraps the initial administrator when the authentication database is empty.

Open the configured `APP_URL` or `https://<server-address>`. On first login, the bootstrap administrator must replace the temporary password before normal application access.

### Manual production setup

```bash
cp .env.example .env
# Edit .env and replace every CHANGE_ME value.
docker compose -f docker-compose.prod.yml up -d --build
```

At minimum, set strong unique values for:

- `POSTGRES_PASSWORD`
- `JWT_SECRET`
- `BOOTSTRAP_ADMIN_PASSWORD`
- `CREDENTIALS_ENCRYPTION_KEY`
- `APP_URL`
- `CORS_ORIGINS`

Production startup rejects known-unsafe JWT secrets, insecure cookies, an invalid credentials-encryption key, or missing required Redis configuration.

### Development Compose deployment

```bash
cp .env.example .env
# Use development-safe local values and set ENVIRONMENT=development.
docker compose up --build
```

The development Compose file publishes:

- Application: `https://localhost` (ports 80 and 443).
- Backend and OpenAPI: `http://localhost:8000` and `http://localhost:8000/docs`.
- PostgreSQL: `localhost:5432`.

It mounts backend source code and runs Uvicorn with reload. It is not a production configuration.

## Initial configuration

After the first administrator login:

1. Replace the bootstrap password when prompted.
2. Enable TOTP MFA for the administrator; optionally enforce MFA globally.
3. Install a trusted certificate under Settings if the deployment started with a temporary certificate.
4. Configure SMTP if invitations or scheduled reports will be used.
5. Open Integration Store, enter one source's credentials, run its connection test, enable it, and sync it.
6. Configure minimum product versions, required product tags, and risk weights.
7. Provision local, RADIUS, or SSO users and assign least-privilege roles.
8. Configure and test the SIEM destination on the Security page.
9. Validate the resulting endpoint, user, compliance, and risk populations before enabling operational alerts.

## Environment configuration

The complete template is [`.env.example`](.env.example). Important variables are summarized below.

### Application and security

| Variable | Purpose | Default/example |
| --- | --- | --- |
| `ENVIRONMENT` | Enables production validation and behavior | `production` |
| `DEBUG` | Backend debug behavior | `false` |
| `APP_URL` | Canonical browser origin for invitations and SAML redirects | `https://sec360.company.com` |
| `CORS_ORIGINS` | JSON list of permitted browser origins | `[...]` |
| `JWT_SECRET` | Signs access and refresh tokens | Required; generate a random 32-byte or larger secret |
| `JWT_EXPIRE_MINUTES` | Access-token lifetime | `480` |
| `JWT_REFRESH_EXPIRE_HOURS` | Refresh-token lifetime | `168` |
| `COOKIE_SECURE` | Restricts auth cookies to HTTPS | `true` in production |
| `CREDENTIALS_ENCRYPTION_KEY` | Fernet key for stored secrets | Required and stable for the life of the installation |

### Database and administrator

| Variable | Purpose |
| --- | --- |
| `POSTGRES_DB` | PostgreSQL database name |
| `POSTGRES_USER` | PostgreSQL application user |
| `POSTGRES_PASSWORD` | PostgreSQL password |
| `BOOTSTRAP_ADMIN_EMAIL` | Initial administrator created only when no auth users exist |
| `BOOTSTRAP_ADMIN_PASSWORD` | Temporary initial password; must be at least 12 characters and changed after login |

Changing bootstrap values does not reset an existing administrator. They are only consulted when the authentication-user table is empty.

### Network and scheduling

| Variable | Purpose | Default |
| --- | --- | --- |
| `HTTP_PORT` | Published HTTP port | `80` |
| `HTTPS_PORT` | Published HTTPS port | `443` |
| `HOST_DNS` | Optional DNS server for private on-premises zones | Empty; Docker-managed DNS |
| `COLLECTOR_INTERVAL_MINUTES` | Full integration collection interval | `15` |

Leave `HOST_DNS` empty for normal cloud integrations. Set it only when containers must resolve a private corporate hostname. The resolver must be reachable from Docker.

### Integration values

Most integration credentials should be entered in the UI, where they are encrypted in PostgreSQL. `.env.example` also exposes selected integration variables for initial or legacy configuration, including JumpCloud, SentinelOne, Symantec DLP, Puppet, Active Directory, Google Workspace, and SAML.

Values supplied through the environment take precedence where the corresponding collector supports an environment override.

## Operations

Run these commands from the repository root.

### Service status and health

```bash
docker compose -f docker-compose.prod.yml ps
docker compose -f docker-compose.prod.yml exec backend \
  python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/health').read().decode())"
```

The health response reports the application version plus database and scheduler state. Overall status is `ok` only when both checks pass.

### Logs

```bash
docker compose -f docker-compose.prod.yml logs --tail=200 backend
docker compose -f docker-compose.prod.yml logs --tail=200 frontend
docker compose -f docker-compose.prod.yml logs -f backend
```

Production Docker log rotation is configured for the backend and frontend. Application audit/change logs remain separate database records visible in the Security page.

### Manual integration checks

Use **Integration Store → Test** to validate network access and credentials without waiting for a scheduled collection. Use **Sync** to run that integration immediately.

For Network Map sources, use **Network Map → Connections → Test connection**. Cisco WLC host-key verification is strict by default; allow an unknown host key only when that tradeoff is intentional. FortiGate requires HTTPS. MikroTik SwOS may use HTTP Digest on a trusted management network because many SwOS deployments do not provide HTTPS; keep that traffic isolated and prefer HTTPS where the device supports it.

For container-level DNS troubleshooting:

```bash
docker compose -f docker-compose.prod.yml exec backend \
  getent hosts example.integration.host
```

If a private on-premises hostname needs corporate DNS, set `HOST_DNS` and recreate the backend container. Do not set a private resolver for cloud integrations unless that resolver can also resolve public DNS.

### Backup

Create a logical PostgreSQL backup before upgrades or major configuration changes:

```bash
docker compose -f docker-compose.prod.yml exec -T postgres \
  pg_dump -U sec360 -d sec360 -Fc > sec360-backup.dump
```

If `POSTGRES_USER` or `POSTGRES_DB` differs from the defaults, use the configured values. Store `.env`, the database backup, and the TLS certificate/key securely. The database contains encrypted secrets, but the encryption key in `.env` is required to use them.

### Upgrade

```bash
git pull --ff-only
docker compose -f docker-compose.prod.yml up -d --build
docker compose -f docker-compose.prod.yml ps
```

Review release changes, back up PostgreSQL first, and verify `/health` and the critical integrations after the upgrade. Do not run `docker compose down -v` during a normal upgrade because `-v` deletes persistent database, Redis, and TLS volumes.

### TLS certificates

TLS terminates at Nginx. Certificates live in the persistent `tls_data` volume. An administrator can replace the certificate and private key from Settings; the frontend container watches for changes and reloads Nginx after the updated files are installed.

### SMTP

SMTP is required for actual delivery of invitations and scheduled reports. When SMTP is not configured, SEC360 records that delivery was skipped without logging the invitation token or message body. Configure the SMTP host, port, sender, credentials, TLS mode, and public `APP_URL` before testing those workflows.

## Development

### Backend

The supported container runtime is Python 3.12. For local development:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export DB_URL='postgresql+asyncpg://sec360:sec360pass@localhost:5432/sec360'
export JWT_SECRET='development-only-random-secret'
export CREDENTIALS_ENCRYPTION_KEY='a-valid-fernet-key'
uvicorn app.main:app --reload
```

The easiest way to provide PostgreSQL during backend development is to start the Compose `postgres` service.

### Frontend

The frontend development server listens on port 3000:

```bash
cd frontend
npm ci
SEC360_API_PROXY=http://localhost:8000 npm run dev
```

Open `http://localhost:3000`. Requests under `/api` are proxied to the configured backend. Alternatively, set `VITE_API_URL` when the browser should call a different API base directly.

### Tests and validation

```bash
cd backend
pytest -q

cd ../frontend
npm run lint
npm run build
```

Before submitting a change, run the focused backend tests for the affected feature plus the frontend lint/build checks when UI code changed.

## API overview

All application APIs are mounted under `/api` except the backend health endpoint.

| Prefix | Responsibility |
| --- | --- |
| `/api/auth` | Local/RADIUS/SAML login, refresh, logout, invitation acceptance, current user, and SSO MFA |
| `/api/endpoints` | Endpoint inventory, detail, agents, bulk operations, and risk overrides |
| `/api/users` | User inventory, detail, timelines, devices, anomalies, identity mapping, and correlation |
| `/api/compliance` | Dashboard, summary, endpoint results, exclusions, and evaluation |
| `/api/risk` | User, endpoint, and overall risk data |
| `/api/activity` | Activity events and suspicious activity |
| `/api/integrations` | Catalog, credentials, enable/test/sync, AD CSV import, and custom definitions |
| `/api/settings` | Users, account security, product/risk settings, SAML, RADIUS, TLS, audit, change events, and SIEM |
| `/api/reports` | Report preview, CSV export, schedules, toggles, and send-now actions |
| `/api/dlp-policy-search` | Live Symantec DLP policy search |
| `/api/application-vulnerabilities` | SentinelOne vulnerability summaries, facets, records, detail, and CSV |
| `/api/puppet-facts` | Puppet summaries, facts, favorites, saved views, and export |
| `/api/network-map` | Feature status, operational topology, connections, tests, collection, floors, infrastructure placement, and port overrides |
| `/api/search` | Global application search |
| `/api/notes` | Analyst notes |
| `/health` | Direct backend database/scheduler health check |

Use the OpenAPI schema as the authoritative request/response contract for API integrations.

## Repository structure

```text
sec360/
├── backend/
│   ├── app/
│   │   ├── api/             # FastAPI dependencies, schemas, and route modules
│   │   ├── collectors/      # Scheduled source collectors and scheduler
│   │   ├── core/            # Configuration, database, encryption, and security
│   │   ├── integrations/    # Integration catalog and adapters
│   │   ├── models/          # SQLAlchemy persistence models
│   │   └── services/        # Correlation, compliance, risk, SIEM, reports, etc.
│   ├── alembic/             # Database migration scaffolding
│   ├── tests/               # Backend tests
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── api/             # Typed API client and feature calls
│   │   ├── components/      # Shared interface components
│   │   ├── pages/           # Route-level feature pages
│   │   └── store/           # Client-side state
│   ├── nginx.conf           # Production TLS and reverse-proxy configuration
│   ├── Dockerfile
│   └── package.json
├── docker-compose.yml       # Development-oriented Compose stack
├── docker-compose.prod.yml  # Hardened production Compose stack
├── setup.sh                 # Guided deployment/bootstrap script
└── .env.example             # Environment template
```

## Important behavior and limitations

- Inventory is not limited to recently seen endpoints. Retire or remove stale records deliberately.
- Compliance requirements follow connected product scope; a disabled or never-connected integration is not automatically treated as missing everywhere.
- SentinelOne application vulnerabilities require a supported cloud deployment and are unavailable for on-premises SentinelOne.
- The first entity or DLP policy observation creates a baseline and should not create a change event.
- SIEM transport is HTTP(S), not native syslog on port 514.
- RADIUS users can sign in through the standard form and do not need invitation acceptance.
- Bootstrap administrator settings do not modify existing users after initial database creation.
- Stored credentials depend on the original `CREDENTIALS_ENCRYPTION_KEY`; protect and back up that key.
- Production is designed for HTTPS. Disabling secure cookies or bypassing the reverse proxy is unsupported and unsafe.
