#!/usr/bin/env python3
"""Credential Manager MCP — MEOK AI Labs. Verifiable credential issuance, verification, and revocation."""

import sys, os
sys.path.insert(0, os.path.expanduser('~/clawd/meok-labs-engine/shared'))
from auth_middleware import check_access
from persistence import ServerStore

import json, hashlib, time, hmac
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from mcp.server.fastmcp import FastMCP

_store = ServerStore("credential-manager")

FREE_DAILY_LIMIT = 15
_usage = defaultdict(list)
def _rl(c="anon"):
    now = datetime.now(timezone.utc)
    _usage[c] = [t for t in _usage[c] if (now-t).total_seconds() < 86400]
    if len(_usage[c]) >= FREE_DAILY_LIMIT: return json.dumps({"error": f"Limit {FREE_DAILY_LIMIT}/day"})
    _usage[c].append(now); return None

mcp = FastMCP("credential-manager", instructions="Verifiable credential management. Issue, verify, revoke, and audit credentials with cryptographic integrity. By MEOK AI Labs.")


def _generate_id(subject: str, cred_type: str) -> str:
    raw = f"{subject}:{cred_type}:{time.time_ns()}"
    return f"vc-{hashlib.sha256(raw.encode()).hexdigest()[:24]}"


def _sign_credential(cred: dict, issuer_secret: str = "meok-default-key") -> str:
    payload = json.dumps(cred, sort_keys=True, default=str)
    return hmac.new(issuer_secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


@mcp.tool()
def issue_credential(subject: str, credential_type: str, claims: str, issuer: str = "MEOK AI Labs",
                     expires_days: int = 365, api_key: str = "") -> str:
    """Issue a verifiable credential with claims, signature, and expiry. Claims should be JSON string."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    if err := _rl(): return err

    try:
        claims_data = json.loads(claims) if isinstance(claims, str) else claims
    except json.JSONDecodeError:
        claims_data = {"raw": claims}

    cred_id = _generate_id(subject, credential_type)
    now = datetime.now(timezone.utc)

    credential = {
        "id": cred_id,
        "type": credential_type,
        "subject": subject,
        "issuer": issuer,
        "claims": claims_data,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(days=expires_days)).isoformat(),
        "status": "active",
    }
    credential["signature"] = _sign_credential(credential)
    _store.hset("creds", cred_id, credential)

    return {
        "credential_id": cred_id,
        "status": "issued",
        "subject": subject,
        "type": credential_type,
        "expires_at": credential["expires_at"],
        "signature": credential["signature"][:16] + "...",
    }


@mcp.tool()
def verify_credential(credential_id: str, api_key: str = "") -> str:
    """Verify a credential's validity — checks existence, signature, expiry, and revocation status."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    if err := _rl(): return err

    if credential_id not in _CREDS:
        return {"valid": False, "reason": "Credential not found", "credential_id": credential_id}

    cred = _CREDS[credential_id]
    checks = {"exists": True, "not_revoked": True, "not_expired": True, "signature_valid": True}

    # Revocation check
    if credential_id in _REVOCATION_LIST or cred.get("status") == "revoked":
        checks["not_revoked"] = False

    # Expiry check
    expires = datetime.fromisoformat(cred["expires_at"])
    if datetime.now(timezone.utc) > expires:
        checks["not_expired"] = False

    # Signature check
    stored_sig = cred.get("signature", "")
    cred_copy = {k: v for k, v in cred.items() if k != "signature"}
    expected_sig = _sign_credential(cred_copy)
    if stored_sig != expected_sig:
        checks["signature_valid"] = False

    all_valid = all(checks.values())
    return {
        "credential_id": credential_id,
        "valid": all_valid,
        "checks": checks,
        "subject": cred["subject"],
        "type": cred["type"],
        "issuer": cred["issuer"],
        "issued_at": cred["issued_at"],
        "expires_at": cred["expires_at"],
    }


@mcp.tool()
def revoke_credential(credential_id: str, reason: str = "unspecified", api_key: str = "") -> str:
    """Revoke a credential. Adds to revocation list and marks as inactive."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    if err := _rl(): return err

    if credential_id not in _CREDS:
        return {"error": "Credential not found", "credential_id": credential_id}

    _REVOCATION_LIST.add(credential_id)
    _CREDS[credential_id]["status"] = "revoked"
    _CREDS[credential_id]["revoked_at"] = datetime.now(timezone.utc).isoformat()
    _CREDS[credential_id]["revocation_reason"] = reason

    return {"credential_id": credential_id, "status": "revoked", "reason": reason}


@mcp.tool()
def list_credentials(subject: str = "", credential_type: str = "", include_revoked: bool = False, api_key: str = "") -> str:
    """List credentials with optional filters by subject and type."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    if err := _rl(): return err

    results = []
    for cid, cred in _CREDS.items():
        if subject and cred["subject"] != subject:
            continue
        if credential_type and cred["type"] != credential_type:
            continue
        if not include_revoked and cred.get("status") == "revoked":
            continue
        results.append({
            "id": cid,
            "subject": cred["subject"],
            "type": cred["type"],
            "issuer": cred["issuer"],
            "status": cred.get("status", "active"),
            "issued_at": cred["issued_at"],
            "expires_at": cred["expires_at"],
        })

    return {"credentials": results, "total": len(results), "revoked_count": len(_REVOCATION_LIST)}


@mcp.tool()
def audit_credential_usage(api_key: str = "") -> str:
    """Get audit statistics on credential issuance, verification, and revocation."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    if err := _rl(): return err

    types = defaultdict(int)
    issuers = defaultdict(int)
    active = revoked = expired = 0
    now = datetime.now(timezone.utc)

    for cred in _CREDS.values():
        types[cred["type"]] += 1
        issuers[cred["issuer"]] += 1
        if cred.get("status") == "revoked":
            revoked += 1
        elif datetime.fromisoformat(cred["expires_at"]) < now:
            expired += 1
        else:
            active += 1

    return {
        "total_issued": len(_CREDS),
        "active": active,
        "revoked": revoked,
        "expired": expired,
        "by_type": dict(types),
        "by_issuer": dict(issuers),
    }


if __name__ == "__main__":
    mcp.run()
