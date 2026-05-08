<div align="center">

# Credential Manager MCP

**MCP server for credential manager mcp operations**

[![PyPI](https://img.shields.io/pypi/v/meok-credential-manager-mcp)](https://pypi.org/project/meok-credential-manager-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Credential Manager MCP provides AI-powered tools via the Model Context Protocol (MCP).

## Tools

| Tool | Description |
|------|-------------|
| `issue_credential` | Issue a verifiable credential with claims, signature, and expiry. Claims should  |
| `verify_credential` | Verify a credential's validity — checks existence, signature, expiry, and revoca |
| `revoke_credential` | Revoke a credential. Adds to revocation list and marks as inactive. |
| `list_credentials` | List credentials with optional filters by subject and type. |
| `audit_credential_usage` | Get audit statistics on credential issuance, verification, and revocation. |

## Installation

```bash
pip install meok-credential-manager-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "credential-manager": {
      "command": "python",
      "args": ["-m", "meok_credential_manager_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 5 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)
