# Personal read-only API keys

SEC360 personal API keys let scripts, dashboards, and external reporting tools fetch data from the same protected API used by the web interface. Every active user can create their own keys. A key always acts as its owner and is intentionally read-only.

## Capabilities at a glance

- Authenticate with a standard `Authorization: Bearer` header.
- Read every API resource the owner is currently authorized to view.
- Use list, detail, summary, search, filter, pagination, and supported CSV export endpoints.
- Inherit the owner's live `viewer`, `analyst`, or `admin` role on every request.
- Respect integration connection requirements and platform feature switches.
- Set an expiration of 1–365 days, or create a key without an expiration.
- Track created, last-used, expiration, revocation, and status metadata.
- Revoke a key immediately from the web interface.
- Create up to 10 active keys per user.

Personal API keys cannot create, update, delete, upload, synchronize, test, trigger, exclude, configure, or otherwise mutate data. They also cannot manage API keys or initiate MFA setup.

## Create a key

1. Sign in to SEC360 in a browser.
2. Open **Settings → My Account**.
3. In **Personal API keys**, enter a descriptive name such as `SIEM inventory reader`.
4. Select an expiration: 30, 90, or 365 days, or no expiration.
5. Select **Create API key**.
6. Copy the complete key immediately and store it in a secrets manager.

The complete secret is displayed only once. SEC360 cannot recover it later. If it is lost, revoke it and create a replacement.

The interface lists each key's safe public prefix, creation time, last-used time, expiration, and status. Revoked and expired keys remain visible for lifecycle history but cannot authenticate.

## Authenticate a request

Pass the complete key in the bearer header:

```bash
export SEC360_URL="https://sec360.example.com"
export SEC360_API_KEY="sec360_PUBLICID_SECRET"

curl --fail-with-body \
  --header "Authorization: Bearer ${SEC360_API_KEY}" \
  "${SEC360_URL}/api/endpoints?limit=100&offset=0"
```

Do not place the key in a URL or query parameter. URLs are commonly stored in browser history, proxies, and server access logs.

### Python example

```python
import os
import requests

base_url = os.environ["SEC360_URL"].rstrip("/")
api_key = os.environ["SEC360_API_KEY"]

response = requests.get(
    f"{base_url}/api/users",
    headers={"Authorization": f"Bearer {api_key}"},
    params={"risk_level": "high", "limit": 100},
    timeout=30,
)
response.raise_for_status()
users = response.json()
```

### Download a CSV export

```bash
curl --fail-with-body \
  --header "Authorization: Bearer ${SEC360_API_KEY}" \
  --output application-vulnerabilities.csv \
  "${SEC360_URL}/api/application-vulnerabilities/export.csv?severity=CRITICAL"
```

The SentinelOne integration must be connected and application-vulnerability support must be available for that deployment.

## Available read capabilities

The following table describes the API families that a personal key can read. Individual endpoints still enforce their normal role, connected-integration, feature-enable, and deployment-capability checks.

| API family | Data available through supported `GET` endpoints | Typical minimum role or requirement |
| --- | --- | --- |
| `/api/auth` | Current authenticated user through `/api/auth/me` | Active user |
| `/api/endpoints` | Current endpoint inventory, filters, endpoint detail, linked owner, compliance state, security agents, and agent detail | Viewer |
| `/api/users` | User inventory, risk filters, anomalies, user detail, activity timeline, devices, and correlated identity | Viewer |
| `/api/compliance` | Dashboard, summary, endpoint results, filters, and endpoint compliance detail | Viewer |
| `/api/risk` | User risk, endpoint risk, and overall risk summary | Viewer |
| `/api/activity` | Activity and suspicious-activity records with source, user, country, type, and date filters | Viewer; ADFS, AD, or Google Workspace connected |
| `/api/search` | Global user and endpoint search | Viewer |
| `/api/application-vulnerabilities` | Summary, facets, filtered findings, finding detail, and CSV export | Viewer; supported SentinelOne deployment connected |
| `/api/dlp-policy-search` | Live Symantec DLP sender/recipient exclusions and policy correlation | Analyst; Symantec DLP with Oracle connected |
| `/api/puppet-facts` | Summary, facets, facts, favorites, saved-view definitions, and CSV export | Analyst; Puppet connected |
| `/api/linux-audits` | Feature status, report summary, filtered report inventory, report detail, and—where permitted—ingest-token metadata | Feature enabled; viewer for reports, admin for token metadata |
| `/api/proxy-audit` | Feature status, redacted connection status, revision summary, filtered policy changes, and full diff detail | Feature enabled; viewer |
| `/api/network-map` | Feature status and the topology, connections, floors, infrastructure, equipment, or collector status permitted by the owner's role | Feature enabled; most operational views require admin |
| `/api/reports` | Generated report data, CSV export, and scheduled-report definitions | Analyst |
| `/api/integrations` | Integration catalog and configuration status permitted by the owner's role | Catalog is authenticated; configured integrations require admin |
| `/api/settings` | The owner's account plus administrator-only platform, authentication, audit, security, change-log, SIEM, and feature status views | Current account or admin, depending on endpoint |

`POST`, `PUT`, `PATCH`, and `DELETE` endpoints in these families are not API-key capabilities. For example, a key may read Puppet favorites and saved views, but it cannot add a favorite or save a view. It may read scheduled reports, but it cannot create a schedule or send a report.

The backend OpenAPI schema is the authoritative contract for exact paths, query parameters, and response bodies. In development it is available at `http://localhost:8000/docs` and `http://localhost:8000/openapi.json`. Production exposure depends on the reverse-proxy configuration.

## Common queries

### Filter endpoint inventory

```bash
curl --get --fail-with-body \
  --header "Authorization: Bearer ${SEC360_API_KEY}" \
  --data-urlencode "search=server" \
  --data-urlencode "os_filter=linux" \
  --data-urlencode "has_s1=false" \
  --data-urlencode "limit=100" \
  --data-urlencode "offset=0" \
  "${SEC360_URL}/api/endpoints"
```

Endpoint filters include compliance status, operating system, search text, owner assignment, and configured agent-presence filters such as SentinelOne, DLP, and WSS.

### Filter users by risk

```bash
curl --get --fail-with-body \
  --header "Authorization: Bearer ${SEC360_API_KEY}" \
  --data-urlencode "risk_level=critical" \
  --data-urlencode "limit=100" \
  "${SEC360_URL}/api/users"
```

### Read suspicious activity in a time range

```bash
curl --get --fail-with-body \
  --header "Authorization: Bearer ${SEC360_API_KEY}" \
  --data-urlencode "date_from=2026-11-01T00:00:00Z" \
  --data-urlencode "date_to=2026-11-04T23:59:59Z" \
  --data-urlencode "limit=200" \
  "${SEC360_URL}/api/activity/suspicious"
```

### Search SEC360

```bash
curl --get --fail-with-body \
  --header "Authorization: Bearer ${SEC360_API_KEY}" \
  --data-urlencode "q=alice@example.com" \
  "${SEC360_URL}/api/search"
```

The global search query must contain at least three characters.

## Pagination and response handling

Most inventory endpoints accept `limit` and `offset`. Their maximum page sizes differ, so clients should use the endpoint's OpenAPI definition instead of assuming one global maximum. Paginated list endpoints commonly return the full matching count in the `X-Total-Count` response header.

Example pagination loop:

```python
import os
import requests

base_url = os.environ["SEC360_URL"].rstrip("/")
headers = {"Authorization": f"Bearer {os.environ['SEC360_API_KEY']}"}
offset = 0
page_size = 500
records = []

while True:
    response = requests.get(
        f"{base_url}/api/endpoints",
        headers=headers,
        params={"limit": page_size, "offset": offset},
        timeout=30,
    )
    response.raise_for_status()
    page = response.json()
    records.extend(page)
    if len(page) < page_size:
        break
    offset += len(page)
```

Treat response schemas as versioned application contracts. Clients should tolerate additional JSON fields and should not depend on object key order.

## Authorization behavior

An API key does not contain a permanent copy of a role. SEC360 loads the owning user for every request and applies that user's current role and active state:

- Promoting or demoting the owner changes the key's access immediately.
- Disabling the owner invalidates all of their keys immediately.
- Role-protected endpoints still return `403 Forbidden` when the owner lacks the required role.
- Integration-owned pages still return `409 Conflict` until the required integration is connected.
- Feature-owned pages still return `409 Conflict` until the feature is enabled.
- Deployment-specific checks still apply, such as SentinelOne on-premises installations that do not expose application vulnerabilities.
- Mandatory password-change or MFA-enrollment policy still applies to the owner.

When both a SEC360 session cookie and a bearer key are sent, the application session cookie takes precedence. API clients should avoid sending browser cookies.

## Read-only enforcement

SEC360 accepts personal API keys only for `GET`, `HEAD`, and `OPTIONS`. All other HTTP methods return:

```json
{
  "detail": "Personal API keys are read-only"
}
```

with status `403 Forbidden`, before the target operation is allowed to run.

Read-only describes the caller's business capability. SEC360 still performs internal security bookkeeping, including updating the key's last-used timestamp at most once every five minutes and writing normal request logs. Some live read features, such as DLP policy search, may also refresh internal comparison/audit evidence while fetching source data; the caller still cannot submit a mutation.

## Key lifecycle and storage

Personal keys use the format `sec360_<public-id>_<secret>`. SEC360 stores:

- a non-secret public prefix used to locate and identify the key;
- an HMAC-SHA256 digest of the complete key;
- its owner and descriptive name;
- creation, last-used, expiration, and revocation timestamps.

The raw secret is never stored and cannot be retrieved. Authentication uses a constant-time digest comparison.

The HMAC uses `JWT_SECRET` as server-side key material. Changing `JWT_SECRET` invalidates all existing personal API keys, in addition to its effects on normal authentication. Treat such a change as a planned credential rotation.

Expired keys stop working automatically. Revocation is immediate and irreversible; create a new key if access is needed again. The active-key limit counts only unrevoked, unexpired keys.

## Audit, SIEM, and request logs

Creating and revoking a personal API key produces a SEC360 audit event. Those events also enter the SIEM outbox when SIEM forwarding is enabled. The event includes safe metadata such as the key name and public prefix, never the raw key.

Every HTTP request is present in the backend request log with its method, path, status, duration, and request ID. Successful API reads do not each create a separate audit-log or SIEM event. The `X-Request-ID` response header can be used to correlate a client error with backend logs.

## Error reference

| Status | Meaning | Common causes |
| --- | --- | --- |
| `400 Bad Request` | Invalid request | Malformed or unsupported query input |
| `401 Unauthorized` | Credential not accepted | Missing, malformed, expired, revoked, or unknown key; inactive owner |
| `403 Forbidden` | Authenticated but not allowed | Write method, insufficient role, required password change/MFA, or interactive-session-only operation |
| `404 Not Found` | Resource not present or not visible | Incorrect ID or path |
| `409 Conflict` | Required capability is unavailable | Feature disabled, integration disconnected, unsupported integration deployment, or active-key limit reached during browser-based creation |
| `422 Unprocessable Entity` | Parameter validation failed | Missing query value, invalid type, or value outside endpoint bounds |
| `502 Bad Gateway` | An upstream live query failed | For example, Symantec DLP database connectivity or permissions |

To troubleshoot a request:

1. Confirm the header uses `Bearer` and contains the complete key.
2. Check the key status and expiration in **Settings → My Account**.
3. Confirm the owner is active, has completed required password/MFA setup, and has the necessary role.
4. Confirm the relevant feature is enabled and integration is connected.
5. Capture the response body and `X-Request-ID` header.
6. Search the backend container logs for that request ID.

```bash
docker compose -f docker-compose.prod.yml logs --since=10m backend
```

## Security recommendations

- Use HTTPS only. Never send a key to a plain-HTTP SEC360 endpoint.
- Store keys in a secrets manager or protected environment variable, not source code or shell history.
- Give each automation its own clearly named key so it can be revoked independently.
- Use the lowest-role owner that provides the required data.
- Prefer finite expiration and rotate before expiry.
- Never commit a `.env` file containing a key.
- Never include keys in tickets, chat messages, screenshots, URLs, or application logs.
- Revoke a key immediately if it may have been exposed.
- Validate TLS certificates in clients. Do not use `curl -k` or disable certificate verification in production.

## Management API reference

The web interface uses these endpoints through an interactive authenticated session:

| Method and path | Purpose |
| --- | --- |
| `GET /api/settings/me/api-keys` | List the signed-in user's key metadata |
| `POST /api/settings/me/api-keys` | Create a key and return the raw secret once |
| `DELETE /api/settings/me/api-keys/{key_id}` | Revoke one of the signed-in user's keys |

These endpoints deliberately reject personal API-key authentication. This prevents a stolen read-only key from minting replacement credentials or changing its own lifecycle.

Example creation body used by the browser:

```json
{
  "name": "SIEM inventory reader",
  "expires_in_days": 90
}
```

`expires_in_days` accepts `1` through `365`; `null` means no expiration. Key creation and revocation should normally be performed in **Settings → My Account** so the one-time secret and warnings are presented safely.

## Current limitations

- Permissions are inherited from the owner; there are no per-key endpoint scopes yet.
- Keys are read-only and cannot trigger synchronization or report delivery.
- Keys cannot impersonate another user or bypass an integration/feature requirement.
- The raw secret cannot be recovered after creation.
- There is no automatic rotation handshake; create a replacement, update the client, verify it, then revoke the old key.
- Request rate limiting is endpoint- and deployment-dependent; clients should use pagination, timeouts, bounded retries, and exponential backoff.

## Use the API with an AI client

SEC360 includes a standalone [read-only MCP server](../mcp-server/README.md) that maps the API to purpose-built tools for MCP-compatible AI clients. It uses the same personal key, role checks, feature flags, and connected-integration requirements described in this guide. The MCP adapter never connects directly to the SEC360 database and implements no REST mutation method.
