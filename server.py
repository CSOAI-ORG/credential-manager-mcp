#!/usr/bin/env python3
import json, hashlib, time
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("credential-manager-mcp")
_CREDS: dict = {}
@mcp.tool(name="issue_credential")
async def issue_credential(subject: str, credential_type: str, claims: dict) -> str:
    cid = hashlib.sha256(f"{subject}{credential_type}{time.time()}".encode()).hexdigest()[:16]
    _CREDS[cid] = {"subject": subject, "type": credential_type, "claims": claims, "issued_at": time.time()}
    return json.dumps({"credential_id": cid, "status": "issued"})
@mcp.tool(name="verify_credential")
async def verify_credential(credential_id: str) -> str:
    c = _CREDS.get(credential_id)
    return json.dumps({"valid": c is not None, "credential": c})
@mcp.tool(name="revoke_credential")
async def revoke_credential(credential_id: str) -> str:
    if credential_id in _CREDS:
        _CREDS[credential_id]["revoked"] = True
    return json.dumps({"revoked": credential_id in _CREDS})
if __name__ == "__main__":
    mcp.run()
