# SEC360 MCP server

## Install

```bash
pipx install "git+https://github.com/itamar-raanan/sec360.git@main#subdirectory=mcp-server"
```

Get the installed executable path:

```bash
command -v sec360-mcp
```

## MCP host configuration

Add the following to your OpenCode configuration. Replace the executable path, SEC360 URL, and API key with your values.

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

### Optional environment variables

For an on-premises SEC360 server that uses a private or self-signed certificate,
the preferred option is to provide the absolute path to the trusted CA certificate:

```json
"SEC360_CA_BUNDLE": "/absolute/path/to/company-ca.pem"
```

If a trusted CA certificate is not available, TLS certificate verification can be
disabled temporarily:

```json
"SEC360_VERIFY_SSL": "false"
```

Disabling certificate verification reduces connection security. Use
`SEC360_CA_BUNDLE` whenever possible.

The API request timeout can also be changed. The supported range is 5–120 seconds:

```json
"SEC360_TIMEOUT_SECONDS": "120"
```

Add optional values inside the existing `environment` object. OpenCode's local MCP
configuration uses the default `stdio` transport, so `SEC360_MCP_TRANSPORT`,
`SEC360_MCP_HOST`, and `SEC360_MCP_PORT` are not required.
