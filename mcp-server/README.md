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
