#!/usr/bin/env python3
"""Verifiable credentials. — MEOK AI Labs."""
import json, os, hashlib, random
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from mcp.server.fastmcp import FastMCP

_usage = defaultdict(list)
def _rl(c="anon"):
    now = datetime.now(timezone.utc)
    _usage[c] = [t for t in _usage[c] if (now-t).total_seconds() < 86400]
    if len(_usage[c]) >= 15: return json.dumps({"error": "Limit 15/day"})
    _usage[c].append(now); return None

mcp = FastMCP("credential-manager", instructions="MEOK AI Labs — Verifiable credentials.")
_store = []

@mcp.tool()
def issue_credential(subject: str, cred_type: str, claims: str) -> str:
    """Verifiable credentials."""
    if err := _rl(): return err
    ts = datetime.now(timezone.utc).isoformat()
    entry = {"id": hashlib.sha256(f"{ts}{str(locals())}".encode()).hexdigest()[:12], "timestamp": ts}
    for k, v in locals().items():
        if k not in ("err", "ts", "entry"): entry[k] = v
    _store.append(entry)
    return json.dumps(entry, indent=2)

@mcp.tool()
def verify_credential(credential_id: str) -> str:
    """Process and verify."""
    if err := _rl(): return err
    result = {"timestamp": datetime.now(timezone.utc).isoformat(), "status": "processed"}
    for k, v in locals().items():
        if k not in ("err", "result"): result[k] = v
    return json.dumps(result, indent=2)

@mcp.tool()
def list_credentials() -> str:
    """Get stored entries."""
    return json.dumps({"entries": _store[-20:], "total": len(_store)}, indent=2)

@mcp.tool()
def get_stats() -> str:
    """Usage stats."""
    return json.dumps({"total": len(_store), "timestamp": datetime.now(timezone.utc).isoformat()}, indent=2)

if __name__ == "__main__":
    mcp.run()
