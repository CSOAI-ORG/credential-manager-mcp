#!/usr/bin/env python3

import sys, os
sys.path.insert(0, os.path.expanduser('~/clawd/meok-labs-engine/shared'))
from auth_middleware import check_access

import json, hashlib, time
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("credential-manager-mcp")
_CREDS: dict = {}
@mcp.tool(name="issue_credential")
async def issue_credential(subject: str, credential_type: str, claims: dict, api_key: str = "") -> str:
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    cid = hashlib.sha256(f"{subject}{credential_type}{time.time()}".encode()).hexdigest()[:16]
    _CREDS[cid] = {"subject": subject, "type": credential_type, "claims": claims, "issued_at": time.time()}
    return {"credential_id": cid, "status": "issued"}
@mcp.tool(name="verify_credential")
async def verify_credential(credential_id: str, api_key: str = "") -> str:
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    c = _CREDS.get(credential_id)
    return {"valid": c is not None, "credential": c}
@mcp.tool(name="revoke_credential")
async def revoke_credential(credential_id: str, api_key: str = "") -> str:
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    if credential_id in _CREDS:
        _CREDS[credential_id]["revoked"] = True
    return {"revoked": credential_id in _CREDS}
if __name__ == "__main__":
    mcp.run()
