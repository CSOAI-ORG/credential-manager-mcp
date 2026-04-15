# Credential Manager MCP Server

> By [MEOK AI Labs](https://meok.ai) — Verifiable credential issuance, verification, and revocation with cryptographic integrity

## Installation

```bash
pip install credential-manager-mcp
```

## Usage

```bash
python server.py
```

## Tools

### `issue_credential`
Issue a verifiable credential with claims, HMAC-SHA256 signature, and expiry.

**Parameters:**
- `subject` (str): Credential subject
- `credential_type` (str): Credential type
- `claims` (str): Claims as JSON string
- `issuer` (str): Issuer name (default 'MEOK AI Labs')
- `expires_days` (int): Expiry in days (default 365)

### `verify_credential`
Verify a credential's validity — checks existence, signature, expiry, and revocation status.

**Parameters:**
- `credential_id` (str): Credential identifier

### `revoke_credential`
Revoke a credential. Adds to revocation list and marks as inactive.

**Parameters:**
- `credential_id` (str): Credential identifier
- `reason` (str): Revocation reason

### `list_credentials`
List credentials with optional filters by subject and type.

**Parameters:**
- `subject` (str): Filter by subject
- `credential_type` (str): Filter by type
- `include_revoked` (bool): Include revoked credentials

### `audit_credential_usage`
Get audit statistics on credential issuance, verification, and revocation.

## Authentication

Free tier: 15 calls/day. Upgrade at [meok.ai/pricing](https://meok.ai/pricing) for unlimited access.

## License

MIT — MEOK AI Labs
