# SEC360 MCP server

The SEC360 MCP server lets MCP-compatible AI clients investigate SEC360 through a personal read-only API key. It is a separate adapter: it does not connect directly to PostgreSQL, store integration credentials, or bypass SEC360 authorization.

## Exposed tools

| Domain | MCP tools |
| --- | --- |
| Platform | `sec360_health`, `get_current_user`, `get_integration_status`, `search_sec360` |
| Endpoints | `list_endpoints`, `get_endpoint` |
| Users | `list_users`, `get_user`, `get_user_anomalies` |
| Compliance | `get_compliance_overview`, `list_compliance_endpoints` |
| Risk | `get_risk_overview` |
| Activity | `list_activity` |
| Application vulnerabilities | `get_application_vulnerability_overview`, `list_application_vulnerabilities`, `get_application_vulnerability` |
| Symantec DLP | `search_dlp_policy_exclusions` |
| Puppet | `get_puppet_facts_overview`, `query_puppet_facts` |
| Linux Audit | `get_linux_audit_overview`, `list_linux_audits`, `get_linux_audit` |
| Proxy Audit | `get_proxy_audit_overview`, `list_proxy_audit_events`, `get_proxy_audit_event` |
| Network Map | `get_network_map` |
| Notes and reports | `list_entity_notes`, `generate_report`, `list_scheduled_reports` |
| Security logs | `list_security_audit_events`, `list_security_change_events` |

It also exposes the `sec360://capabilities` MCP resource.

Every outbound SEC360 request is `GET`. The client rejects paths outside `/api/` and `/health`, does not follow redirects, bounds result sizes, verifies TLS by default, and never exposes the configured key as tool output.

## Requirements

- Python 3.11 or later
- A reachable SEC360 HTTPS URL
- A personal key from **Settings → My Account**
- An owner role with access to the data the MCP client needs

Feature flags and connected-integration requirements still apply. For example, DLP tools need an analyst key and a connected Symantec DLP integration.

## Local installation

```bash
cd mcp-server
python3 -m venv .venv
. .venv/bin/activate
pip install .
```

Set the required environment variables:

```bash
export SEC360_URL="https://sec360.example.com"
export SEC360_API_KEY="sec360_PUBLICID_SECRET"
```

The default transport is stdio:

```bash
sec360-mcp
```

This process is normally launched by an MCP host, not used interactively.

## MCP host configuration

Use an absolute executable path and pass the secret through the process environment:

```json
{
  "mcpServers": {
    "sec360": {
      "command": "/opt/sec360/mcp-server/.venv/bin/sec360-mcp",
      "env": {
        "SEC360_URL": "https://sec360.example.com",
        "SEC360_API_KEY": "sec360_PUBLICID_SECRET"
      }
    }
  }
}
```

Restart the MCP host after changing its configuration. The exact configuration filename and location depend on the host product.

### OpenCode

Install the package with `pipx`, then run `command -v sec360-mcp` to find the absolute executable path. Add the following to your OpenCode configuration, replacing the three placeholder values:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "sec360": {
      "type": "local",
      "command": [
        "/home/YOUR_USER/.local/bin/sec360-mcp"
      ],
      "enabled": true,
      "timeout": 120000,
      "environment": {
        "SEC360_URL": "https://YOUR-SEC360-SERVER",
        "SEC360_API_KEY": "sec360_YOUR_API_KEY",
        "SEC360_TIMEOUT_SECONDS": "120"
      }
    }
  }
}
```

Restart OpenCode after saving the configuration.

## Private certificate authorities

TLS verification is enabled by default. For an internal CA:

```bash
export SEC360_CA_BUNDLE="/etc/company-ca/sec360-ca.crt"
```

For temporary testing only, verification can be disabled with `SEC360_VERIFY_SSL=false`. Do not use that setting in production.

## Streamable HTTP

For a centrally hosted MCP endpoint:

```bash
export SEC360_MCP_TRANSPORT="streamable-http"
export SEC360_MCP_HOST="127.0.0.1"
export SEC360_MCP_PORT="9000"
sec360-mcp
```

Clients connect to `http://127.0.0.1:9000/mcp`.

The MCP HTTP endpoint does not add a second authentication layer. Anyone who can reach it can invoke tools using its configured SEC360 identity. Keep it on loopback or a private network and place authenticated TLS termination in front of it before remote exposure. For isolated per-user authorization, prefer stdio with each user's own key.

## Docker

```bash
docker build -t sec360-mcp ./mcp-server

docker run --rm \
  --name sec360-mcp \
  --publish 127.0.0.1:9000:9000 \
  --env SEC360_URL="https://sec360.example.com" \
  --env SEC360_API_KEY="sec360_PUBLICID_SECRET" \
  sec360-mcp
```

Do not put the key in the image or commit it to Compose files. Use a Docker secret or protected environment file in production.

## Configuration

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `SEC360_URL` | Yes | — | SEC360 public base URL |
| `SEC360_API_KEY` | Yes | — | Personal read-only key |
| `SEC360_CA_BUNDLE` | No | — | CA certificate used for TLS verification |
| `SEC360_VERIFY_SSL` | No | `true` | TLS verification when no CA bundle is set |
| `SEC360_TIMEOUT_SECONDS` | No | `30` | SEC360 timeout, from 5 to 120 seconds |
| `SEC360_MCP_TRANSPORT` | No | `stdio` | `stdio` or `streamable-http` |
| `SEC360_MCP_HOST` | No | `127.0.0.1` | HTTP bind address |
| `SEC360_MCP_PORT` | No | `9000` | HTTP listen port |

## Example questions

- “Show endpoints missing SentinelOne and group them by operating system.”
- “Which critical application vulnerabilities have a known exploit?”
- “Summarize compliance coverage and show the 20 worst endpoints.”
- “Find suspicious activity for this user during the last seven days.”
- “Which DLP policies exclude `alice@example.com`, and who last edited them?”
- “Show failed CIS controls from the latest Linux audit for this server.”
- “Explain what changed in the latest proxy policy revision.”
- “Compare Puppet facts for these two hosts.”

## Development and tests

```bash
cd mcp-server
pip install -e '.[dev]'
pytest -q
```

Test with the official MCP development tooling:

```bash
pip install 'mcp[cli]>=2.2,<3'
mcp dev sec360_mcp/server.py
```

Never use a production key in automated tests.

## Security model and limitations

- Tools inherit the key owner's current SEC360 role.
- Disabled owners and expired or revoked keys stop working immediately.
- The server has no write tools and its REST client contains no mutation method.
- Some reads perform normal SEC360 bookkeeping, such as last-used timestamps and DLP comparison evidence.
- Results may contain sensitive security and identity data. Apply SEC360-equivalent access and retention controls.
- A centrally deployed instance represents one configured SEC360 user. It does not exchange end-user identity for separate SEC360 credentials.
